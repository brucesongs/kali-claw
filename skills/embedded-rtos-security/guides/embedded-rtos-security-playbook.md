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

## RTOS MITRE ATT&CK for Cloud + ICS Mapping

The MITRE ATT&CK framework has two extensions relevant to RTOS targets: ATT&CK for Cloud (techniques used against cloud-managed IoT fleets) and ATT&CK for ICS (techniques used against industrial control devices). RTOS devices sit at the intersection — they are often cloud-managed (AWS IoT, Azure IoT Hub, Pelion) AND operate in industrial contexts (PLC controllers, smart-grid RTUs). The mapping below cross-references each RTOS-specific technique against both matrices.

### Cloud-Matrix Techniques Observed on RTOS Devices

| ATT&CK for Cloud Technique | RTOS Manifestation | Example |
|---------------------------|---------------------|---------|
| **T1613 Container and Resource Discovery** | RTOS device enumerates peer cloud-managed devices via MQTT retained messages | A compromised FreeRTOS MQTT client subscribes to the wildcard topic `#` and observes all peer device traffic |
| **T1619 Cloud Storage Object Discovery** | RTOS firmware pulls OTA images from cloud storage (S3, Azure Blob, GCS) without verifying the source bucket's authenticity | A compromised OTA path fetches attacker-controlled firmware from a look-alike bucket |
| **T1530 Data from Cloud Storage Object** | RTOS device stores telemetry in cloud storage with overly-broad IAM permissions | An attacker enumerates the storage bucket and exfiltrates telemetry from all deployed devices |
| **T1602 Data from Configuration Repository** | RTOS device pulls its configuration from a cloud-hosted Git repository at boot | Compromising the repo allows injection of malicious configuration into all devices |
| **T1525 Implant Internal Image** | RTOS OTA image is replaced with attacker-controlled image that includes a backdoor | A ThreadX device's OTA image is replaced in the cloud storage bucket, then auto-installed by all deployed devices |
| **T1578 Modify Cloud Compute Infrastructure** | Compromised cloud orchestrator (AWS IoT Core, Azure IoT Hub) is used to push malicious firmware to the entire fleet | The fleet enrollment certificate is used to push a malicious firmware update to all devices |
| **T1136 Create Account** | Attacker creates a new device enrollment certificate in the cloud IoT Hub | The new certificate allows a rogue device to enroll in the fleet and receive configuration |

### ICS-Matrix Techniques Observed on RTOS Devices

| ATT&CK for ICS Technique | RTOS Manifestation | Example |
|--------------------------|---------------------|---------|
| **T0817 Drive-by Compromise** | RTOS device browses to a malicious URL (rare; only relevant for HMI-class devices) | A QNX-based HMI runs a Chromium-based browser that visits a malicious URL |
| **T0859 Valid Accounts** | RTOS device uses default credentials to authenticate to an upstream SCADA gateway | A VxWorks RTU connects to a Schneider ClearSCADA gateway with default credentials |
| **T0866 Exploitation of Remote Services** | RTOS WDB agent, qconn, or GDB stub is exploited remotely | Urgent/11 exploitation of VxWorks WDB on UDP 17185 (see deep-dive guide) |
| **T0883 Connection Proxy** | Compromised RTOS device acts as a SOCKS proxy for further lateral movement | A FreeRTOS device with two NICs bridges the IT and OT networks after compromise |
| **T0887 Secure Socket Layer (CA) Compromise** | RTOS device trusts a compromised CA for OTA image verification | A rogue CA is used to sign attacker-controlled firmware |
| **T0890 Exploitation for Privilege Escalation** | RTOS task-privilege escalation via MPU region misconfiguration | A non-privileged task exploits an MPU region overlap to gain access to the kernel TCB |
| **T0806 Brute Force** | RTOS Telnet/SSH credentials are brute-forced | QNX qconn authentication is brute-forced over TCP 8000 |
| **T0848 Network Denial of Service** | RTOS IP-stack DoS via TCP SYN flood (CVE-2018-16603) or IGMP flood | FreeRTOS+TCP SYN queue exhaustion |
| **T0830 Integrity Control** | Modbus register writes from a compromised RTOS device | A compromised VxWorks PLC writes malicious setpoints to downstream Modbus slaves |
| **T0859 Control Device Identification** | RTOS device is fingerprinted via banner, DHCP option 60, or Bluetooth HCI response | VxWorks WDB banner enumeration on UDP 17185 |

### RTOS-Specific ATT&CK Mapping (Proposed Extension)

The standard ATT&CK matrices do not capture several techniques unique to RTOS exploitation. The proposed extension below is kali-claw's working set for engagement reporting.

| Technique ID | Technique Name | Description |
|--------------|----------------|-------------|
| **R0001** | RTOS Debug Agent Exploitation | Use of a debug agent (WDB, qconn, GDB stub, ROV) for unauthenticated memory access or task spawn |
| **R0002** | RTOS IP Stack Overflow | Buffer overflow in the IP-task (kernel-mode) network stack |
| **R0003** | RTOS Heap Feng Shui | Grooming the RTOS-specific heap (heap_4.c, tx_byte_pool, tx_block_pool) for controlled overflow |
| **R0004** | RTOS Scheduler Manipulation | Priority inversion, ready-queue corruption, or watchdog bypass |
| **R0005** | RTOS MPU Region Misconfiguration | Exploiting a misconfigured MPU region set to access out-of-scope memory |
| **R0006** | RTOS Secure Boot Glitch | Voltage/clock/EM glitching to bypass secure boot signature verification |
| **R0007** | RTOS Firmware OTA Hook | Modifying the OTA update mechanism to deliver attacker-controlled firmware |
| **R0008** | RTOS Bluetooth Host Stack Exploit | Exploitation of BLE host stack (Zephyr, ThreadX BLE) for kernel-mode RCE |
| **R0009** | RTOS IPC Channel Abuse | QNX MsgSend/MsgReceive abuse, VxWorks message queue corruption, FreeRTOS queue item spray |
| **R0010** | RTOS Side-Channel Key Extraction | CPA/DPA on RTOS-resident crypto (mbedTLS, wolfSSL, micro-ecc) |

### Reporting Implications

When writing the engagement report, map each finding to BOTH the standard ATT&CK matrix (for enterprise SOC consumption) AND the RTOS-specific extension (for embedded engineering team consumption). Example finding:

```
Finding: VxWorks WDB Agent Exposed on UDP 17185 (Unauthenticated RCE)
  CVSS: 9.8 (CRITICAL)
  ATT&CK for Cloud: T1613 (Container and Resource Discovery) — if the device
    is cloud-managed, the attacker can enumerate peer devices after compromise.
  ATT&CK for ICS: T0866 (Exploitation of Remote Services) — the WDB agent is
    a remote service exploitable for unauthenticated RCE.
  RTOS Extension: R0001 (RTOS Debug Agent Exploitation), R0002 (RTOS IP Stack
    Overflow via CVE-2019-12256).
  Remediation: Set INCLUDE_WDB=FALSE in kernel config; firewall UDP 17185 at
    the network edge; upgrade to VxWorks 6.9.4.1 or later.
```

This dual-mapping makes the report useful to multiple stakeholders and positions the RTOS findings in the broader enterprise/industrial security context.

---

## RTOS Secure Boot and Trusted Execution Environment Analysis

Secure boot and Trusted Execution Environment (TEE) are the two hardware-backed defenses that, when correctly implemented, raise the cost of RTOS exploitation significantly. This section covers the analysis methodology: how to assess whether secure boot is correctly implemented, how to identify TEE-backed key storage, and how to bypass both when engaged to do so.

### Secure Boot Chain Analysis

A correctly implemented secure boot chain on a Cortex-M device has these stages:

1. **Boot ROM (mask ROM, fused at manufacturing)**:
   - Reads the first-stage bootloader from internal flash at a fixed address (e.g., `0x08000000` on STM32).
   - Validates the first-stage bootloader's signature using a public key fused into the chip.
   - If validation fails, enters a recovery mode (typically USB DFU or UART boot).

2. **First-stage bootloader**:
   - Initializes the main clock tree, external memory controllers, and the crypto accelerator.
   - Reads the second-stage image (typically the RTOS kernel) from external SPI flash or eMMC.
   - Validates the second-stage signature using either the same fused key or a key stored in the first-stage bootloader's protected flash region.
   - Jumps to the second-stage entry point.

3. **Second-stage (RTOS kernel)**:
   - Optionally validates application images before launching them.
   - On VxWorks 7 and Zephyr with MCUboot, this stage runs the MCUboot serial bootloader.

4. **Application / OTA stage**:
   - Receives OTA updates via MQTT, HTTPS, or LwM2M.
   - Validates the update signature against an OTA signing key.
   - Writes the update to a secondary flash partition.
   - Triggers MCUboot to swap partitions and reboot.

### Verification Checklist

For each stage, verify:

| Check | Pass Criteria | Common Failure |
|-------|---------------|----------------|
| Hardware root of trust | Public key is in fused mask ROM, not in external SPI flash | Key stored in flash, readable via JTAG |
| All stages verify signatures, not checksums | Use of RSA-3072, ECDSA-P256, or Ed25519 | Use of CRC32 or SHA-256 hash without signature |
| Anti-rollback protection | A fused monotonic counter rejects older versions | Counter stored in flash, resettable |
| Hardware debug disable (DHCSR DAM fuse) | DAM fuse set after manufacturing | DAM fuse never set; JTAG always enabled |
| Key revocation mechanism | Compromised keys can be revoked via a revocation list in fused ROM | No revocation mechanism; compromised keys require chip recall |
| Image encryption | OTA images are encrypted in transit and at rest | OTA images are signed but not encrypted |
| Side-channel hardening | Crypto operations run constant-time, with random delays | Naive RSA/ECDSA implementations, leak key material via CPA |
| Glitch detection | Voltage and clock anomaly detectors reset the chip on glitch | No glitch detection; vulnerable to ChipWhisperer attacks |

### Secure Boot Bypass Techniques

When engaged to bypass secure boot, the techniques in order of preference:

#### 1. Voltage Glitching (ChipWhisperer)

Target the signature verification branch in the boot ROM. The branch is typically:

```
loop:
    ldrb r1, [r0], #1   ; load next signature byte
    cmp r1, r2           ; compare with computed value
    bne fail             ; branch to fail if mismatch
    ...
fail:
    b reset              ; reboot on signature mismatch
```

A voltage glitch at the precise cycle of the `bne fail` branch can corrupt the comparison result, causing the branch to NOT be taken even on mismatch. The result: the boot ROM accepts an attacker-controlled image.

Workflow:
1. Capture power traces of the boot ROM signature verification.
2. Identify the cycle window where the `bne` branch occurs (look for the `MOV; BNE` pattern in the power trace).
3. Configure the ChipWhisperer glitch parameters: width 5-15 ns, offset -7 ns, repeat 3 cycles.
4. Sweep the glitch offset across the verification cycle window.
5. Successful glitch: the boot ROM jumps to the attacker-controlled image.

#### 2. Clock Glitching

Similar to voltage glitching but injects a clock glitch (a shortened or extra clock cycle) at the verification cycle. More precise than voltage glitching on some chips; less precise on others.

#### 3. EM Fault Injection (ChipSHOUTER)

A high-voltage EM pulse induces a transient fault in the target's CPU. More expensive than voltage/clock glitching but works against chips with built-in voltage and clock glitch detectors.

#### 4. Laser Fault Injection

A pulsed laser through the chip package induces a fault in a specific transistor. Used by professional labs against secure-element chips (NXP SmartMX, Infineon SLC52). Out of reach for most red teams.

#### 5. Boot ROM Vulnerabilities

Many boot ROMs have their own vulnerabilities. Notable examples:
- **Samsung eMMC firmware injection** (2014): a boot ROM bug allowed booting unsigned code from a malicious eMMC firmware.
- **AMLogic bootloader downgrade** (2020): a boot ROM bug allowed rolling back the bootloader to a vulnerable version.
- **Raspberry Pi boot ROM**: historical bugs in the SD card boot path.

Identify boot ROM bugs by reverse engineering the mask ROM (requires decapping the chip and imaging with an electron microscope — professional lab territory).

### Trusted Execution Environment Analysis

A TEE provides an isolated execution environment alongside the main RTOS. The TEE runs at a higher privilege level than the RTOS kernel; even a full kernel compromise does not directly compromise the TEE.

#### Common TEE Implementations on RTOS Targets

| TEE | Architecture | Vendor Usage |
|-----|--------------|--------------|
| **ARM TrustZone for Cortex-A** | Separates "Secure World" from "Normal World" via the monitor mode | Used on higher-end RTOS targets (QNX on Snapdragon, VxWorks on Cortex-A) |
| **ARMv8-M Security Extension (TZ-M)** | TrustZone for Cortex-M (M23, M33, M55) | Used on modern IoT (LPC55S69, STM32L5, SAM L11) |
| **uVisor** | Software-isolated enclaves within the RTOS | Mbed OS (deprecated 2024 but still in field devices) |
| **OpenAMP TTY/IPC** | Async IPC between RTOS and a separate Linux partition on the same SoC | Xilinx Zynq UltraScale+, NXP i.MX 8 |

#### TEE Attack Surface

The TEE attack surface includes:

1. **Normal-to-Secure World transitions**: The `SMC` (Secure Monitor Call) instruction transitions from Normal World to Secure World. Bugs in the SMC dispatcher allow Normal World code to execute arbitrary Secure World operations.

2. **Shared memory**: The Normal and Secure Worlds communicate via shared memory regions. A bug in the Secure World's shared memory parser allows the Normal World to corrupt Secure World state.

3. **Trusted Applications (TAs)**: Code running inside the TEE (TAs) may have their own vulnerabilities. A compromised TA gives the attacker code execution inside the Secure World.

4. **Hardware attacks**: Voltage/clock/EM glitching applies equally to the TEE. The TEE is only as secure as the silicon it runs on.

5. **Side channels**: The TEE's crypto operations may leak via power analysis (CPA/DPA) or timing analysis, just like any other code.

#### TEE Bypass Methodology

1. **Identify the TEE implementation**: ARM TrustZone for Cortex-A is exposed via the `smc` instruction. TrustZone-M is exposed via the `sg` (Secure Gateway) instruction. uVisor has its own syscall ABI.
2. **Enumerate TAs**: Each TA has a UUID. On GlobalPlatform-compliant TEEs, query the TA manager via `TA_OpenSessionEntryPoint`.
3. **Reverse engineer the TAs**: TAs are typically ARM binaries; load into Ghidra. The TA may use the same crypto as the RTOS but with separate key material.
4. **Identify the shared-memory protocol**: Look for shared-memory descriptors in the device tree or in the monitor-mode vector table.
5. **Fuzz the shared-memory protocol**: Write an AFL harness that exercises the shared-memory parser with malformed inputs.
6. **Side-channel the TA's crypto**: Capture power traces of the TA's signature verification; apply CPA to recover the key.

#### Lab Setup for TEE Analysis

```bash
# QEMU supports TrustZone for Cortex-A targets
qemu-system-arm -M vexpress-a9 -cpu cortex-a9 \
    -secure -bios trusted-firmware.bin \
    -serial mon:stdio -nographic

# The vexpress-a9 with -secure runs the BL31 (Secure Monitor) at EL3
# A non-secure RTOS (VxWorks, FreeRTOS) runs at EL1
# Communication between them is via SMC

# For Cortex-M TrustZone (M33):
qemu-system-arm -M lm3s6965evb -cpu cortex-m33 \
    -kernel freertos_m33.bin -nographic

# TrustZone-M requires hardware with the Security Extension
# QEMU support for TZ-M is incomplete as of 2024 — physical hardware (LPC55S69,
# STM32L5) is required for full analysis
```

### Defense-in-Depth for Secure Boot + TEE

When the secure boot and TEE are correctly implemented AND verified, the attacker must combine:
- Hardware glitching to bypass secure boot (Section above).
- TEE exploitation to compromise the Secure World.
- Persistence to maintain access across reboots.

This raises the cost of attack significantly. For a Tier-1 OEM shipping correctly-implemented secure boot and TEE on a modern Cortex-M33, the attack cost is on the order of $50,000 (lab equipment + skilled analyst time) — high enough to deter most attackers, low enough to remain within reach of nation-state adversaries.

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
