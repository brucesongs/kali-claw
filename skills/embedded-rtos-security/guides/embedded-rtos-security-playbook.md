# Embedded RTOS Security Playbook — End-to-End Red Team Workflow Guide

> Deep-dive companion to `skills/embedded-rtos-security/SKILL.md`.
>
> Audience: red teamers and security engineers who already know what binwalk, OpenOCD, and Ghidra are, and want a battle-tested playbook for taking an RTOS-based embedded device from physical/hardware access through firmware extraction, RTOS identification, debug-agent exploitation, network-stack RCE, and secure-boot bypass — across all the major RTOS families used in safety-critical and IoT deployments.

---

## Introduction

A Real-Time Operating System (RTOS) is the operating system layer between the silicon and a deterministic application. Unlike a general-purpose OS (Linux, Windows), an RTOS prioritizes **guaranteed worst-case latency**, **predictable scheduling**, and **minimal interrupt jitter** over fairness, throughput, and isolation. That mandate produces a fundamentally different attack surface: tasks often share a single address space, debug agents are routinely shipped in production, the network stack runs in kernel mode, and the hardware debug interfaces (JTAG, SWD, UART) are the primary engagement entry point.

This playbook walks the full RTOS engagement lifecycle:

1. **Architecture understanding** — what kind of RTOS are you looking at, and what does that mean for your attack chain?
2. **Attack surface mapping** — debug agents, network stacks, IPC, scheduler, MMU/MPU, hardware.
3. **Real-world CVE deep dives** — the VxWorks Urgent/11 (JSOF 2019), FreeRTOS+TCP (Zimperium 2018), and Zephyr Bluetooth (2019-2023) disclosures as worked examples.
4. **Hardware lab setup** — JTAGulator, Shikra, J-Link, ST-Link, Black Magic Probe, OpenOCD, Bus Pirate, GreatFET.
5. **Glitching rig** — ChipWhisperer, NewAE, voltage/clock glitching, power analysis.
6. **Emulation** — Renode, QEMU system, angr symbolic execution.
7. **Defensive guidance** — MPU/MMU enablement, stack canaries, ASLR-on-MCUs, secure boot.

The methodology is hardware-and-software combined: the firmware extraction feeds the static analysis, the static analysis feeds the dynamic analysis, the dynamic analysis informs the exploit chain, and the exploit chain lands you in the RTOS kernel where every layer of defense is theoretically bypassed by the architectural fact that "user mode" doesn't exist.

---

## RTOS Architecture Comparison

There are three architectural families of RTOS you will encounter in modern embedded systems.

### 1. Flat-Address-Space (Monolithic) RTOS

**Examples**: FreeRTOS (default build), MicroC/OS-II, older VxWorks (5.x, 6.x), ThreadX (default build), NuttX (some configs), RIOT.

**Properties**:
- All tasks share a single virtual address space (often identical to physical memory).
- No MMU enforcement; MPU optional and frequently disabled.
- The "kernel" is a library linked into the application; the scheduler runs in the same privilege mode as the tasks.
- A buffer overflow in any task can corrupt the kernel data structures (TCB list, scheduler queues) directly.

**Attack implications**:
- A single task compromise = full device compromise.
- The "kernel-mode" boundary does not exist; there is no privilege escalation to perform because the attacker is already in supervisor mode.
- The exploit chain is short: find the bug, get RCE.

### 2. Microkernel RTOS

**Examples**: QNX Neutrino, seL4, INTEGRITY-178B, PikeOS, LynxOS-178, VxWorks 653 (ARINC-653 partitions).

**Properties**:
- The kernel runs in supervisor mode and contains only the minimum: scheduling, IPC, interrupt dispatch.
- All other services (file systems, network, drivers) run as user-space processes communicating via synchronous message passing.
- Each process has its own address space (MMU-enforced).
- Process compromise does NOT directly give kernel access; the attacker must escalate via IPC, kernel-driver bugs, or credential theft.

**Attack implications**:
- The exploit chain is longer: process compromise -> privilege escalation -> kernel compromise.
- The methodology is closer to Linux kernel exploitation (procfs, capabilities, IPC abuse) than to flat-RTOS exploitation.
- QNX Neutrino is the most commonly encountered microkernel in commercial RTOS engagements.

### 3. Real-Time Executive (Hybrid)

**Examples**: TI-RTOS (SYS/BIOS), VxWorks 7 (with virtual memory context enabled), Azure RTOS ThreadX (with MMU support), Zephyr (with CONFIG_USERSPACE).

**Properties**:
- Some isolation via MPU regions or limited MMU contexts.
- Often a half-measure: kernel tasks run in supervisor mode, user tasks in restricted mode, but the boundary is configurable and frequently misconfigured.
- The MPU region set is small (typically 8-16 regions on Cortex-M), so the protection granularity is coarse.

**Attack implications**:
- The exploit chain depends on whether MPU is actually enforced.
- Many "real-time executive" deployments claim MPU protection but ship with `configUSE_MPU_WRAPPERS=1` while still creating all tasks via `xTaskCreate` (instead of `xTaskCreateRestricted`) — effectively running in flat-address-space mode.
- Verify the MPU enforcement, don't trust the configuration documentation.

### Architecture Decision Tree

```
Is the target a microkernel (QNX, seL4, INTEGRITY)?
├── Yes → Apply Linux-style methodology (procfs, IPC, capabilities).
│         Focus on qconn, Qnet, io-pkt, Photon, /proc/<pid>/as.
└── No → Is MPU/MMU enforced?
    ├── Yes (verified) → Find an MPU region misconfiguration or
    │                    escalate via kernel API abuse.
    └── No (or unverifiable) → Treat as flat-address-space.
                               Focus on heap, scheduler, IP stack, WDB.
```

---

## RTOS Attack Surface Map

The full attack surface of an RTOS-based device spans five layers. A thorough engagement considers each.

### Layer 1: Debug Agents

The debug agent is the most consistently exploitable RTOS attack surface. Every major RTOS ships a debug agent intended for development, and OEM shipping profiles routinely leave them enabled.

| RTOS | Debug Agent | Default Port | Authentication |
|------|-------------|--------------|----------------|
| VxWorks | WDB (Wind Debug Agent) | UDP 17185 | `WDB_MODE_ANY` (none) on VxWorks <= 6.9.3 |
| QNX Neutrino | qconn | TCP 8000 | Often disabled on dev images |
| FreeRTOS | GDB stub | TCP 3333 / 2331 | None (when enabled) |
| ThreadX | NetX Debug Agent, TraceX | TCP 44900 | None |
| TI-RTOS | ROV (Runtime Object Viewer) | UART / TCP 18100 | None |
| Zephyr | GDB stub (OpenOCD) | JTAG/SWD only | Hardware-dependent |

**Engagement pattern**:
1. Scan for the debug agent's port (`nmap -sU -p 17185`, `nmap -sV -p 8000`).
2. Fingerprint via the agent's protocol (WDB RPC TGT_PING, qconn JSON list).
3. If the agent responds with NULL auth, escalate to memory read / task spawn.
4. Document as CRITICAL — unauthenticated remote RCE.

### Layer 2: Network Stacks

The network stack is the kernel on most flat-address-space RTOSes. A buffer overflow in the IP stack is a kernel-mode RCE.

| RTOS | Stack | Notable CVEs |
|------|-------|--------------|
| VxWorks | WIND IP stack | Urgent/11 (CVE-2019-12256 et al., 11 CVEs) |
| FreeRTOS | FreeRTOS+TCP | Zimperium 2018 (CVE-2018-16525/16528/16529/16603) |
| ThreadX / Azure RTOS | NetX DUO | CVE-2021-2924 (HTTP), CVE-2023-34622 (DNS) |
| Zephyr | Zephyr networking (CoAP, LwM2M, DNS) | CVE-2020-13663 (DoS) |
| TI-RTOS | NDK (BSD-derived) | BSD-inherited issues |
| NuttX | NuttNet (BSD-derived) | BSD-inherited issues |
| RIOT | GNRC | CVE-2019-16525/16526 (IPv6 ND) |
| Contiki-NG | uIP | CVE-2018-16536/16537 (RPL, ICMPv6) |

**Engagement pattern**:
1. Identify the stack via strings in firmware (`FreeRTOS+TCP`, `NetX DUO`, etc.).
2. Cross-reference version against published CVE catalog.
3. Craft a PoC packet (ICMP, DHCP, L2CAP, DNS) sized to trigger the overflow.
4. Send against a bench device; observe crash via JTAG.
5. Develop the exploit chain (heap feng shui, ROP) for reliable RCE.

### Layer 3: IPC (Inter-Process Communication)

IPC is the second most exploitable surface on microkernel RTOSes (QNX Neutrino especially).

| RTOS | IPC mechanism | Attack pattern |
|------|---------------|----------------|
| QNX Neutrino | MsgSend/MsgReceive (synchronous) | Malformed message triggers kernel parsing bug |
| QNX Neutrino | Qnet (TCP/UDP 4000) | Cross-machine IPC without auth |
| VxWorks | Message queues (msgQSend/msgQReceive) | Queue overflow |
| ThreadX | tx_queue_send / tx_queue_receive | Queue pointer corruption |
| FreeRTOS | xQueueSendToBack / xQueueReceive | Heap corruption via queue item |

### Layer 4: Scheduler

The RTOS scheduler is a less-commonly-exploited but powerful attack target.

- **Priority inversion DoS**: a low-priority task holding a binary semaphore (no inheritance) can be exploited to starve a high-priority task indefinitely.
- **Scheduler corruption**: overwriting the ready-queue list head gives the attacker control over which task runs next.
- **Watchdog bypass**: identifying the watchdog task and either corrupting it or feeding it from the exploit code.

### Layer 5: MMU/MPU

The MMU/MPU is a defensive layer, but misconfiguration turns it into an attack vector.

- **MPU region reconfiguration**: if a privileged task can call `mpu_region_set()`, it can grant itself access to other regions (uVisor bypass).
- **MPU region overlap**: a misconfigured MPU region set may leave gaps where tasks have unintended access.
- **MPU disabled in production**: many OEMs disable MPU entirely in release builds to save the per-task context-switch overhead.

---

## Real CVE Deep Dives

### Case Study 1: VxWorks Urgent/11 (JSOF, 2019)

**Background**: In July 2019, the Israeli security firm JSOF disclosed a set of 11 vulnerabilities in Wind River VxWorks, collectively branded "Urgent/11". The vulnerabilities span the WDB RPC parser, the WIND IP stack's TCP state machine, the DHCPv4 client, the DHCPv6 server, the IGMPv3 handler, and the memory pool allocator. Affects VxWorks 6.5 through 6.9.x (pre-6.9.4.1) and VxWorks 7 (pre-SR0600).

**Estimated impact**: 200 million devices across industrial control (Schneider Modicon PLCs, ABB RTUs), medical (patient monitors, MRI consoles), aerospace (multiple certified platforms), enterprise networking (printers, routers), and critical infrastructure.

**Key CVEs**:

- **CVE-2019-12256**: Stack-based buffer overflow in `wdbDbgArchLib.c` when handling a malformed WDB RPC payload. The vulnerable code path is reached BEFORE the WDB auth check, meaning the bug is triggerable even with WDB disabled on some builds.
- **CVE-2019-12258**: Memory pool allocator overflow in `memPartAlloc`. Triggered by an oversized string passed to a network service that calls `memPartAlloc` (DNS resolver, DHCP client, TFTP client).
- **CVE-2019-12260**: DHCPv4 client buffer overflow in `dhcpClientOptionGet`. Triggered by a malicious DHCP OFFER with an oversized option 119 (domain search list).
- **CVE-2019-12261**: IGMPv3 ready message overflow. Triggered by a malformed IGMPv3 packet.
- **CVE-2019-12264**: TCP urgent pointer (OOB data) handling flaw. Triggered by a TCP segment with the URG flag set and an urgent pointer exceeding the segment boundary.

**Exploitation notes**:

- The WDB RPC parser overflow (CVE-2019-12256) is the highest-impact issue: it provides unauthenticated, single-packet RCE on devices with WDB enabled. Even with WDB disabled, the parser runs (briefly) before the disable check, so a precise timing attack can still trigger the overflow.
- The DHCPv4 client overflow (CVE-2019-12260) is the easiest to trigger remotely: respond to the target's DHCP DISCOVER with a malicious OFFER containing an oversized option 119. Works against any VxWorks device that uses DHCP, no auth required.
- The TCP urgent pointer flaw (CVE-2019-12264) is exploitable by anyone who can establish a TCP connection to any VxWorks service (Telnet, FTP, HTTP).

**Disclosure timeline**:

- March 2019: JSOF reports the vulnerabilities to Wind River.
- July 29, 2019: Wind River releases patches (VxWorks 6.9.4.1, SR0600 for VxWorks 7).
- August 2019: Schneider, ABB, and other OEMs begin releasing advisories.
- Many devices remained unpatched into 2024 — field deployment cycles in industrial and aerospace contexts are measured in years, not weeks.

**Lessons**:

- The WDB agent's "MODE_ANY" default is the root cause. Production deployments MUST set `INCLUDE_WDB = FALSE` in the kernel configuration.
- The IP stack running in kernel mode amplifies the impact of every buffer overflow.
- Industrial and aerospace devices have patch cycles that dwarf typical IT — assume a 5-year tail on any RTOS vulnerability.

### Case Study 2: FreeRTOS+TCP (Zimperium, 2018)

**Background**: In October 2018, Zimperium zLabs disclosed a set of vulnerabilities in FreeRTOS+TCP, the TCP/IP stack component of FreeRTOS. Affects FreeRTOS versions before 10.3.1. Estimated 4 billion devices affected (FreeRTOS is the most-deployed RTOS in the world).

**Key CVEs**:

- **CVE-2018-16525**: Use-after-free in IP fragment reassembly. Triggered by two IP fragments with overlapping offsets that conflict.
- **CVE-2018-16528**: Heap-based buffer overflow in the ICMP echo reply handler. Triggered by an oversized ICMP ECHO REQUEST (payload >1500 bytes).
- **CVE-2018-16529**: Memory leak via oversized DF-flagged IPv4 packets. Causes heap exhaustion.
- **CVE-2018-16603**: TCP SYN queue exhaustion DoS. Unlike Linux, FreeRTOS+TCP has no SYN cookie fallback.

**Exploitation notes**:

- The ICMP heap overflow (CVE-2018-16528) is the highest-impact issue: single-packet, unauthenticated, kernel-mode RCE.
- The default ICMP reply buffer is sized to the MTU (~1500 bytes); a payload >1500 bytes overflows into adjacent heap blocks.
- The overflow is reliable: heap feng shui on FreeRTOS heap_4.c is well-documented.
- Post-exploitation: the IP-task runs with kernel-equivalent privileges, so the attacker has full device control.

**Remediation**:

- Upgrade to FreeRTOS 10.3.1 or later (patches the Zimperium CVEs).
- For deployments stuck on older versions: disable ICMP echo replies (`FreeRTOS_SetPingReplyOption(NULL, pdFALSE)`), use heap_5.c with multiple memory regions for better isolation.

### Case Study 3: Zephyr Bluetooth Host Stack (2019-2023)

**Background**: The Zephyr Project's Bluetooth host stack is a from-scratch implementation (not BlueZ). Since Zephyr's first Bluetooth releases in 2017, the host stack has accumulated a steady stream of CVEs, primarily in the L2CAP and GATT layers.

**Key CVEs**:

- **CVE-2019-17500**: L2CAP heap overflow in `l2cap_chan_recv`. Triggered by an oversized L2CAP information payload.
- **CVE-2020-10018**: L2CAP heap overflow in `l2cap_recv`.
- **CVE-2020-10019**: GATT handler use-after-free in `bt_gatt_discover`.
- **CVE-2020-10024**: Bluetooth Mesh provisioning heap overflow.
- **CVE-2021-3329**: L2CAP signal heap overflow in `bt_l2cap_recv`.
- **CVE-2022-3821**: HCI ACL buffer overflow in `bt_buf_get_rx`.
- **CVE-2023-3353**: L2CAP config overflow in `l2cap_parse_conf_req`.

**Pattern**: The recurring theme is "L2CAP payload size not validated before copying into a fixed-size buffer." Each CVE patched one occurrence; the next CVE was the same bug in a different code path.

**Exploitation notes**:

- Bluetooth LE is unauthenticated by design (pairling is optional and often skipped in beacon mode).
- A BLE device in advertising mode accepts connections from any BLE scanner.
- The attack range is ~10 meters (Class 2 BLE) or up to 100 meters (Class 1 with external amplifier).
- The exploit chain is: scan for the target -> connect -> send malformed L2CAP packet -> heap overflow in the BT host -> ROP -> code execution in kernel mode.

**Remediation**:

- Upgrade to Zephyr 3.5 or later (patches the known Bluetooth CVEs).
- Disable Bluetooth if not needed (`CONFIG_BT=n`).
- Enable Bluetooth Secure Connections (`CONFIG_BT_SMP=y`) for authenticated connections.

---

## Hardware Lab Setup

A real RTOS engagement requires a hardware lab. The minimum viable setup is:

### Tier 1: $100 Lab (Entry-Level)

- **CH341A SPI programmer** ($5) — reads/writes SPI flash via USB
- **Bus Pirate v4** ($40) — multi-protocol UART/SPI/I2C/JTAG
- **ST-Link v2 clone** ($10) — SWD for STM32 targets
- **Logic analyzer (8-channel, 24 MHz)** ($15) — sigrok-compatible
- **Total**: ~$70

Capabilities: SPI flash dump, UART console access, basic SWD attach to STM32. Sufficient for consumer IoT devices (smart bulbs, sensors, wearables).

### Tier 2: $1000 Lab (Intermediate)

- **J-Link BASE** ($600) — commercial JTAG/SWD with RTOS awareness
- **Black Magic Probe** ($80) — native GDB server, open-source
- **JTAGulator** ($180) — JTAG/UART pin enumeration
- **Shikra** ($100) — multi-protocol JTAG/UART/SPI/I2C
- **GreatFET One** ($120) — scriptable multi-protocol
- **Total**: ~$1080

Capabilities: All Tier 1 + JTAG pin discovery on unknown PCBAs, RTOS-aware debugging (FreeRTOS, ThreadX, Zephyr), multi-target support.

### Tier 3: $5000+ Lab (Advanced)

- **ChipWhisperer-Lite** ($300) — voltage/clock glitching, SCA
- **ChipWhisperer-Husky** ($1500) — faster FPGA, more I/O
- **NewAE CW308 UFO board** ($300) — target platform
- **Dediprog SF600** ($600) — commercial SPI programmer
- **Saleae Logic Pro 16** ($500) — high-speed logic analyzer
- **Rigol DS1054Z oscilloscope** ($400) — glitch characterization
- **Total**: ~$3600

Capabilities: All Tier 2 + glitch attacks (secure boot bypass), power analysis (key extraction), high-speed signal capture.

### Tier 4: $20,000+ Lab (Professional)

- **ChipWhisperer-Pro** ($3000) — professional SCA
- **ChipSHOUTER** ($2000) — EM fault injection
- **Tektronix MDO3000** ($6000) — mixed-domain oscilloscope
- **Riscure Inspector** ($10,000 license) — professional SCA tooling
- **Total**: ~$20,000+

Capabilities: All Tier 3 + EMFI, professional-grade analysis, automated SCA campaigns.

### Lab Setup Best Practices

1. **Separate physical network**: RTOS network stack exploits can affect adjacent devices. Place all DUTs on an isolated VLAN or air-gapped switch.
2. **Faraday cage** for Bluetooth/wireless tests: prevents accidental interference with adjacent devices.
3. **Anti-static workspace**: ESD damage is a leading cause of false-positive hardware failures.
4. **Documented inventory**: track every target device's serial number, source, and acquisition date.
5. **Spare devices**: glitch attacks and destructive testing require spares.

---

## Glitching Rig Setup

### ChipWhisperer-Lite Setup

```text
Hardware:
- ChipWhisperer-Lite (CW1173) — the main capture/glitch board
- CW308 UFO target board — interchangeable target platform
- Target chip (STM32F4, nRF52840, etc.) on a CW308 board
- USB cable to host

Software (host):
- Python 3
- chipwhisperer Python module: pip install chipwhisperer
- Optional: chipwhisperer analyzer (CPA attack)

Setup:
1. Plug CW1173 into host USB
2. Plug CW308 target into CW1173
3. Power on CW1173 (USB-powered)
4. Verify chipwhisperer Python module recognizes the device:
   import chipwhisperer as cw
   scope = cw.scope()
   print(scope)  # should print CWLite instance
```

### Voltage Glitching Workflow

```text
1. Capture power traces of the target's vulnerable routine
   (e.g., secure boot signature verification)
2. Identify the cycle(s) where the verification branch occurs
   (look for the signature-compare MOV + BNE pattern in power trace)
3. Configure the glitch:
   - clk_src = 'clkgen' (internal clock generator, synchronized to target)
   - width = 5.5 ns (typical Cortex-M; varies by chip)
   - offset = -7.2 ns (just before the clock edge)
   - repeat = 3 (3 clock cycles of glitch)
   - trigger_src = 'ext_trigger' (triggered by an event on TIO1)
4. Sweep parameters: for each (width, offset) in a grid:
   - Reset target
   - Arm scope
   - Send a trigger event (e.g., send a UART byte the target prints at boot)
   - Wait for glitch
   - Observe target behavior: did it skip the verification branch?
5. Document successful (width, offset) combinations
6. Iterate to refine the glitch window
```

### Power Analysis (CPA) Workflow

```text
1. Build the target with a known AES key
2. Capture N traces (N >= 1000) of the AES encryption
3. For each key byte hypothesis (0-255):
   - Compute the hypothetical power model
     (Hamming weight of the SBox output)
   - Correlate against the measured traces
   - The correct key byte has the highest correlation peak
4. Recover the full AES key (16 bytes) in 16 separate CPA campaigns

Tools:
- chipwhisperer analyzer (Python)
- Optional: Riscure Inspector (commercial)

Time:
- ~5 minutes per key byte on CW-Lite
- ~80 minutes for full AES-128 key recovery
```

---

## Emulation Setup

### Renode

Renode is the canonical RTOS emulator. Unlike QEMU, Renode was designed for embedded multi-node emulation.

```text
Strengths:
- First-class ARM Cortex-M0/M0+/M3/M4/M7/M23/M33 support
- Multi-node: emulate the SoC + external flash + debug probe + console simultaneously
- Built-in RTOS awareness (FreeRTOS, Zephyr, ThreadX, NuttX)
- Peripheral emulation (UART, SPI, I2C, networking via TAP)
- Anti-anti-debugging (resistant to debug-detection in target firmware)

Weaknesses:
- Less mature than QEMU for ARM Cortex-A
- No support for some obscure SoCs (TI-RTOS SYS/BIOS on C2000, etc.)
- Steeper learning curve for custom peripheral emulation
```

### QEMU system

QEMU is the fallback for targets Renode doesn't support.

```bash
# Bare-metal RTOS on QEMU Cortex-M3 (lm3s6965evb)
qemu-system-arm -M lm3s6965evb -kernel nuttx.bin -nographic -serial mon:stdio

# With networking (TAP interface)
qemu-system-arm -M lm3s6965evb -kernel nuttx.bin -nographic \
    -netdev tap,id=net0,ifname=tap0,script=no,downscript=no \
    -device stellaris_enet,netdev=net0
```

### angr (Symbolic Execution)

angr is the canonical symbolic execution framework. Useful for finding input-to-crash paths in WDB RPC parser, FreeRTOS DHCP option handler, etc.

```python
import angr

proj = angr.Project('firmware.elf')
parser_addr = 0x08001000  # WDB RPC parser entry

symbolic_input = angr.claripy.BVS('input', 4096 * 8)
state = proj.factory.blank_state(addr=parser_addr)
state.regs.r0 = 0x20000000  # input buffer address
state.memory.store(0x20000000, symbolic_input)

simgr = proj.factory.simgr(state)
simgr.explore(find=0x08002000, avoid=[0x08003000])

if simgr.found:
    crash_input = simgr.found[0].solver.eval(symbolic_input, cast_to=bytes)
    print(f'Crash input: {crash_input[:64].hex()}')
```

**When to use angr**:

- When you have a binary function with complex input parsing and you want to find an input that reaches a specific code path.
- For WDB RPC parser: find an input that reaches the `wdbTaskSpawn` function (to demonstrate RCE).
- For FreeRTOS DHCP option handler: find an input that overflows the option buffer.

**When NOT to use angr**:

- For whole-binary analysis (too slow).
- For non-deterministic targets (interrupts, DMA).
- For targets with hardware-crypto acceleration (angr can't model the crypto unit).

---

## Defensive Guidance

### 1. Disable Debug Agents in Production

| RTOS | Configuration |
|------|---------------|
| VxWorks | `INCLUDE_WDB = FALSE` in kernel config |
| QNX Neutrino | Remove `qconn` from startup scripts (`io-pkt -d qconn` removed) |
| FreeRTOS | `-DCONFIG_DEBUG_STUB=n` in build flags |
| ThreadX | Avoid `tx_trace_buffer_pool_create()` in release |
| TI-RTOS | Disable ROV over Ethernet; keep UART-only |
| Zephyr | Don't enable GDB stub in production builds |

### 2. Enforce MPU/MMU

**FreeRTOS**:
- Set `configUSE_MPU_WRAPPERS=1` in `FreeRTOSConfig.h`.
- Create ALL tasks with `xTaskCreateRestricted` (not `xTaskCreate`).
- Define MPU regions per task via `TaskParameters_t.xRegions[]`.

**Zephyr**:
- `CONFIG_USERSPACE=y` (thread privilege separation)
- `CONFIG_MPU_STACK_GUARD=y` (separate MPU stack guard region)
- `CONFIG_HW_STACK_PROTECTION=y` (hardware stack guard)
- `CONFIG_EXECUTE_XOR_TEXT=y` (W^X enforcement)

**QNX Neutrino**:
- Rely on microkernel isolation.
- Audit CAP_SYS_ADMIN-equivalent credentials; do not grant to untrusted processes.
- Use QNX Secure Boot for code-signing enforcement.

**VxWorks**:
- Enable VxVMI (Virtual Memory Interface) for per-task memory partitions.
- Use VxWorks Security Profile (CSP) for hardening.

### 3. Stack Canaries

- Compile with `-fstack-protector-strong` (GCC/Clang).
- Set `configCHECK_FOR_STACK_OVERFLOW=2` in FreeRTOS.
- Enable `CONFIG_HW_STACK_PROTECTION=y` in Zephyr.
- For Cortex-M targets, use the MPU stack guard (a 32-byte MPU region at the bottom of each task's stack, set to no-access; stack overflow triggers a MemManage fault).

### 4. ASLR-on-MCUs

True ASLR requires an MMU (rare on bare-metal MCUs). The closest equivalent:

- **Compile-time randomization**: use a build script that randomizes function order and adds random stack offsets.
- **Link-time randomization**: with LLD (LLVM linker) or GNU ld, use `--randomize-section-padding` to add random padding between sections.
- **Runtime stack randomization**: in FreeRTOS, `configSTACK_RAND_BYTES=16` adds a 16-byte random offset to each task's stack base.
- **Runtime code randomization**: only available on higher-end Cortex-A targets with full MMU.

### 5. Secure Boot

The secure boot chain on a typical Cortex-M device:

1. **Boot ROM (mask ROM, fused)**: validates the first-stage bootloader's signature using a public key fused into the chip.
2. **First-stage bootloader**: validates the second-stage (RTOS) signature using either the same fused key or a key stored in the first-stage bootloader.
3. **Second-stage (RTOS)**: optionally validates application images.

**Verification checklist**:

- [ ] Boot ROM uses a hardware root of trust (fused key, not flash-stored key).
- [ ] All stages verify signatures, not just checksums.
- [ ] Signature verification uses a modern algorithm (Ed25519, ECDSA-P256, RSA-3072+).
- [ ] Anti-rollback protection prevents downgrade to vulnerable versions.
- [ ] Hardware debug disable (DHCSR DAM fuse) is set after manufacturing.
- [ ] Key revocation mechanism exists for compromised keys.

**Anti-glitching defenses**:

- Use a glitch-resistant secure boot (NXP LPC55S69, STM32H5, Microchip SAM L11 with anti-glitch circuits).
- Add power-monitoring circuits that reset the chip on voltage anomaly.
- Add clock-monitoring circuits that detect clock glitching.
- Use multiple signature verifications with redundant checks.

### 6. OTA Update Integrity

- Sign all OTA images with a hardware-backed key (HSM, secure element).
- Verify signatures before applying updates.
- Implement anti-rollback (reject older versions than the current).
- Use delta updates carefully (verify the patched result, not just the delta).
- Reject unsigned diffs.
- Implement a recovery mode (factory image fallback) for failed updates.

### 7. Defense-in-Depth Summary

For a real-time device in a safety-critical context, the recommended defense-in-depth stack:

1. **Secure boot** (fused key, anti-glitch)
2. **Hardware debug disable** (DAM fuse after manufacturing)
3. **MPU/MMU enforcement** (per-task isolation)
4. **Stack canaries + hardware stack guard**
5. **ASLR-on-MCU** (where supported)
6. **Disabled debug agents** in production
7. **Patched RTOS** (latest VxWorks SR, FreeRTOS 10.4+, Zephyr 3.5+)
8. **TLS on all remote services** (mbedTLS, wolfSSL)
9. **Signed OTA updates** with anti-rollback
10. **Anomaly detection** (CAN-IDS-style for task behavior)

No single layer stops a determined attacker. The layers buy time and increase the cost of attack. The Urgent/11, FreeRTOS+TCP, and Zephyr Bluetooth disclosures all demonstrated that defense-in-depth is necessary because no single layer is sufficient.

---

## Engagement Workflow Summary

A typical RTOS engagement follows this workflow:

1. **Scoping**: identify the target device, the firmware version, the engagement scope, and the authorization boundaries.
2. **Hardware access**: obtain a bench device; perform JTAG/UART enumeration (TC-RT-002).
3. **Firmware extraction**: dump the external flash via OpenOCD (TC-RT-001) or flashrom.
4. **Firmware analysis**: extract with binwalk (firmware-reverse skill); identify the RTOS via strings.
5. **Static analysis**: load into Ghidra; recover symbols (TC-RT-011); identify the WDB agent / IP stack / debug functions.
6. **Network fingerprinting**: scan for debug agents (TC-RT-003, TC-RT-005); identify exposed services.
7. **Vulnerability identification**: cross-reference version against CVE catalogs; identify known issues.
8. **Exploitation**: develop PoC for the highest-impact vulnerability (TC-RT-004, TC-RT-006, TC-RT-007, TC-RT-008).
9. **Hardware fault injection**: if software exploitation is blocked by secure boot, attempt glitch attacks (TC-RT-009).
10. **Dynamic analysis**: use Renode (TC-RT-012) or OpenOCD (TC-RT-010) for in-depth runtime analysis.
11. **Documentation**: record all findings with severity ratings, CVE references, and remediation guidance.
12. **Disclosure**: follow the vendor's coordinated disclosure process (typically 90 days).

The methodology spans multiple kali-claw skills: `firmware-reverse` (extraction), `hardware-security` (debug interfaces), `binary-reverse` (disassembly), `exploit-development` (exploit chain), and this skill (`embedded-rtos-security`) for the RTOS-specific exploitation.

---

## References

- **JSOF Urgent/11 advisory**: https://www.jsof-tech.com/urgent11/
- **Zimperium FreeRTOS+TCP analysis**: https://www.zimperium.com/freertos-tcp-vulnerabilities/
- **Wind River PSIRT**: https://www.windriver.com/psirt
- **BlackBerry QNX PSIRT**: https://www.blackberry.com/us/en/services/blackberry-product-security-incident-response-team
- **Zephyr security advisories**: https://docs.zephyrproject.org/latest/security/vulnerabilities.html
- **ARM Cortex-M security guidelines** (ARM AN-1221, ARMv8-M Security Extension)
- **OWASP Embedded Systems Security Testing Guide**: https://owasp.org/www-project-embedded-systems-security-testing/
- **Renode documentation**: https://renode.readthedocs.io/
- **ChipWhisperer documentation**: https://chipwhisperer.readthedocs.io/
- **OpenOCD documentation**: https://openocd.org/doc/html/

---

End of embedded-rtos-security-playbook.md. See `SKILL.md` for the skill overview, `payloads.md` for the complete command catalogue, and `test-cases.md` for the structured test cases.
