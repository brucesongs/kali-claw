---
name: embedded-rtos-security
description: RTOS penetration testing — VxWorks WDB debug agent (Urgent/11), QNX microkernel, FreeRTOS+TCP CVEs, ThreadX/Azure RTOS, Zephyr, Mbed OS, TI-RTOS, MicroC/OS, NuttX, RIOT, Contiki
origin: kali-claw
version: 1.0
compatibility: Claude Code, Claude Sonnet 4.5+
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
metadata:
  domain: embedded-rtos-security
  category: rtos
  tool_count: 13
  guide_count: 1
  mitre: T1548-Abuse Elevation Control Mechanism
  keywords:
    - RTOS
    - VxWorks
    - QNX
    - FreeRTOS
    - Zephyr
    - embedded
    - microkernel
---

# Skill: Embedded RTOS Security

> **Supplementary Files**:
> - `payloads.md` — Command catalogue for VxWorks WDB RPC/Wind debug agent exploitation (Urgent/11 CVEs CVE-2019-12256/12258/12260, IPstack flaws), QNX Neutrino Qnet/qconn/procfs exploitation, FreeRTOS+TCP CVE-2018-16528 stack attacks, ThreadX/Azure RTOS bug matrix, Zephyr Kconfig/Bluetooth host CVEs, Mbed OS uVisor/Pelion, TI-RTOS/BIOS, MicroC/OS-II/III, NuttX, RIOT, Contiki-NG, plus hardware attack surfaces (JTAG/UART/SWD enumeration via JTAGulator/Shikra/J-Link/Black Magic Probe, OpenOCD target control, voltage/clock glitching via ChipWhisperer/NewAE, side-channel analysis with GreatFET/HydraBus/Bus Pirate) — 11 sections, 60+ code blocks.
> - `test-cases.md` — Structured test cases (lab bring-up, JTAG/UART enumeration, OpenOCD target attach, VxWorks WDB RPC fingerprint/exploit, FreeRTOS+TCP CVE PoC, QNX qconn/procfs enumeration, Zephyr Bluetooth host stack fuzz, ChipWhisperer voltage glitch on secure boot, RTOS binary static analysis with Ghidra/IDA, scheduler priority inversion, Renode system emulation, MPU bypass via heap corruption) — 12 cases across 6 categories.
> - `guides/embedded-rtos-security-playbook.md` — End-to-end RTOS red team playbook covering architecture comparison (monolithic kernel vs microkernel vs real-time executive), the full RTOS attack surface map (debug agent, network stack, IPC, scheduler, MMU/MPU), real CVE deep dives (VxWorks Urgent/11 by JSOF 2019, FreeRTOS+TCP by Zimperium 2018, Zephyr Bluetooth 2019-2023), hardware lab setup (JTAGulator, Shikra, J-Link, ST-Link, Black Magic Probe, OpenOCD, Bus Pirate, GreatFET), glitching rig (ChipWhisperer, NewAE, GlitchIP), emulation (Renode, QEMU system, angr symbolic execution), and defensive guidance (MPU/MMU enablement, stack canaries, ASLR-on-MCUs, secure boot).

## Summary

Real-Time Operating System (RTOS) security covers the exploitation of deterministic operating systems used in safety-critical and embedded devices — VxWorks, QNX Neutrino, FreeRTOS (+ FreeRTOS+TCP), ThreadX/Azure RTOS, Zephyr, Arm Mbed OS, TI-RTOS/SYS/BIOS, MicroC/OS-II and III, NuttX, RIOT OS, and Contiki-NG. These operating systems are the runtime for avionics (ARINC-653 partitions on VxWorks 653 and LynxOS-178), automotive ECUs (QNX on multiple IVI platforms, AUTOSAR OS on OSEK derivatives), industrial controllers (VxWorks, MicroC/OS on PLCs, RTU/IED firmware), medical devices (ThreadX on infusion pumps, QNX on MRI consoles), IoT networking gear (FreeRTOS on consumer routers and Zigbee radios, Zephyr on 802.15.4 sensors), and aerospace/military systems (VxWorks, INTEGRITY-178B, Deos). Unlike a general-purpose OS, an RTOS sacrifices isolation for determinism: a single memory corruption, debug-agent exposure, or scheduler flaw often gives the attacker direct code execution in the highest-privilege supervisor/handler mode on the device.

**Tools**: IDA Pro, Ghidra, Binary Ninja, radare2/r2macho, OpenOCD, J-Link/ST-Link/Black Magic Probe/JTAGulator/Shikra, binwalk/firmwalker/FACT, QEMU system/Renode, angr, ChipWhisperer (NewAE), GreatFET/HydraBus/Bus Pirate, flashrom, strace/ltrace/perf.

**Domain**: embedded-rtos-security

**MITRE ATT&CK**: T1548-Abuse Elevation Control Mechanism (MPU bypass, debug agent escalation), T1068-Exploitation for Privilege Escalation (scheduler, kernel), T1055-Proccess Injection (task corruption, heap spray), T1049-System Network Connections (WDB RPC, qconn discovery), T1210-Exploitation of Remote Services (RTOS network stack), T1499-Endpoint Denial of Service (priority inversion, RTO deadlock)

## Description

An RTOS is the OS layer between the silicon and a deterministic application: where a general-purpose OS optimizes for fairness, throughput, and isolation, an RTOS optimizes for guaranteed worst-case latency, predictable scheduling, and minimal interrupt jitter. That mandate produces four architectural properties that shape every attack in this domain:

1. **Determinism over isolation.** The kernel reserves CPU time slices via fixed-priority preemptive scheduling (rate-monotonic in VxWorks, EDF in some MicroC/OS-III deployments, priority inheritance for bound priority inversion in POSIX/QNX). Tasks share the same flat address space more often than not — MicroC/OS-II has no MMU support, FreeRTOS is MMU-optional until V10.3+, and even QNX's microkernel pays a per-message context-switch tax that many IoT deployments trade away by running everything in kernel mode. A single task compromise is, in many RTOS deployments, a full-device compromise.

2. **Debug agents as the standard remote attack surface.** Every major RTOS ships a debug agent intended for development: VxWorks has **WDB (Wind River Debug Agent)** exposed over UDP port 17185 speaking the Wind River Debug RPC protocol; QNX has **qconn** on TCP 8000 used by Momentics and the QNX System Information Viewer; FreeRTOS Plus has **TCP-only GDB stubs** enabled by default in vendor SDKs; ThreadX has **NetX Debug Agent** and Azure RTOS adds the **ThreadX TraceX server**; TI-RTOS ships **ROV (Runtime Object Viewer)** accessible over UART/Ethernet. These agents were never intended for production, but OEM shipping profiles routinely leave them listening on the WAN interface. The 2019 **Urgent/11** vulnerabilities (JSOF, CVE-2019-12256 stack overflow in the WBD RPC parser, CVE-2019-12258 Memory Pool Allocator overflow, CVE-2019-12260 DHCPv4 client overflow) demonstrated that the WDB agent and the WIND IP stack together expose unauthenticated, remote-code-execution attack surface on over 200 million devices — including Schneider Electric Modicon PLCs, OTN systems in healthcare, and multiple aerospace platforms.

3. **The network stack is the kernel.** On VxWorks the WIND IP stack runs in kernel context. On FreeRTOS the `FreeRTOS+TCP` stack (`FreeRTOS_IP.c`, `FreeRTOS_Sockets.c`, `FreeRTOS_DHCP.c`) runs in a single "IP-task" with kernel-equivalent privileges. On Zephyr the networking subsystem lives in the kernel's `net_core` context. A buffer overflow in any of these is a kernel-mode RCE — there is no userland boundary to fall back to. The 2018 Zimperium disclosures (`CVE-2018-16528` `FreeRTOS_SendPing` heap overflow, `CVE-2018-16529` `FreeRTOS_recvfrom` do-not-fragment handling, `CVE-2018-16525` IP fragmentation UAF, `CVE-2018-16603` TCP SYN queue overflow) demonstrated unauthenticated, single-packet RCE across an estimated 4 billion FreeRTOS+TCP-enabled devices.

4. **The hardware is part of the threat model.** Real-time devices ship with JTAG/SWD/ETM debug interfaces, UART consoles, and unprotected external flash because they are mandatory for factory programming and field debug. Even when secure boot closes the "flash via JTAG" path, the underlying silicon primitives — ARM's Debug Authentication Mode (DAM), the JTAG-DP DPIDR access port, the Cortex-M TPIU trace port — are themselves a battle frontier. Voltage glitching (ChipWhisperer), clock glitching, and EM fault injection bypass secure boot, attestation, and key extraction on a daily basis in modern labs.

The combination is what makes RTOS security its own discipline: you do not get to choose between software exploitation and hardware exploitation — a real RTOS engagement requires both, because the network stack exploit lands you in kernel mode and the secure-boot bypass is what got you the firmware to begin with. The VxWorks Urgent/11 disclosure, the FreeRTOS+TCP Zimperium report, the multiple Zephyr Bluetooth host CVEs (CVE-2019-17500, CVE-2020-10019, CVE-2021-3329, CVE-2022-3821), and the ongoing stream of ThreadX NetX DUO CVEs (CVE-2021-2924, CVE-2023-34625) all share the same shape: a remote or local attacker exploits the IP/Bluetooth stack or debug agent to gain supervisor privileges on a device that has no separation kernel, no MPU enforcement on the compromised task, and no ASLR to randomize the target address.

**Difference from `firmware-reverse`**: Firmware-reverse covers generic firmware image acquisition (binwalk signature scan, sasquatch/jefferson filesystem extraction, FACT and firmwalker scanning) and generic full-system emulation (firmadyne, qemu-system). Embedded-rtos-security assumes the firmware image is already extracted and goes one layer deeper: identifying the RTOS, fingerprinting version via debug agent banner, exploiting RTOS-specific components (WDB RPC protocol, qconn, FreeRTOS IP-task, ThreadX NetX, Zephyr Bluetooth host), and leveraging RTOS-specific hardware attacks (priority inversion, MPU bypass, scheduler abuse). The boundary: binwalk/unblob extraction → firmware-reverse; once you know the image contains VxWorks 6.9 and you're targeting the WDB agent on UDP 17185, you're in embedded-rtos-security.

**Difference from `iot-pentest`**: IoT-pentest covers the application-layer IoT protocols (MQTT, CoAP, AMQP, LwM2M, AWS IoT Device SDK, OCF) and the cloud back-end. Embedded-rtos-security covers the RTOS that sits underneath those protocols — the FreeRTOS TCP/IP stack that carries the MQTT traffic, the ThreadX NetX DUO stack that carries the LwM2M traffic, the Zephyr networking subsystem that carries CoAP. IoT-pentest is "what the device says over MQTT"; embedded-rtos-security is "the IP stack underneath the MQTT client that has its own 4 CVEs."

**Difference from `hardware-security`**: Hardware-security covers generic chip-level debug interfaces (JTAG/UART/SWD enumeration), glitching (voltage, clock, EM), and side-channel (power analysis via ChipWhisperer, Riscure Inspector). Embedded-rtos-security applies those techniques to RTOS-specific targets — JTAG access to dump FreeRTOS task control blocks, glitch attacks to bypass the QNX kernel boot signature, power analysis to recover ThreadX NetX crypto keys. The overlap is the lab gear; the difference is the target.

**Difference from `binary-reverse`**: Binary-reverse covers general disassembly and decompilation methodology across architectures (ARM, MIPS, x86, RISC-V). Embedded-rtos-security applies binary analysis to RTOS-specific artifacts — VxWorks VxWorks symbol table (`vxworks.sym`), QNX `qnx_bootstrap` ELF segments, FreeRTOS linker map for task stack layout, ThreadX `_tx_block_pool` heap structures, Zephyr Kconfig build artifacts. The same Ghidra session produces different findings depending on whether the analyst knows they're looking at a microkernel vs a flat-address-space RTOS.

**Difference from `scada-ics-security`**: SCADA covers industrial control protocols (Modbus, DNP3, S7comm, OPC UA, IEC 61850, GOOSE). Many SCADA devices run on VxWorks or MicroC/OS, but the SCADA layer is the application; embedded-rtos-security is the OS underneath. The overlap is Schneider Modicon PLCs running VxWorks (Urgent/11); embedded-rtos-security owns the WDB agent exploit, scada-ics-security owns the Modbus function code exploitation.

## Use Cases

- **VxWorks WDB debug agent exploitation**: Identify a device running VxWorks (banner UDP 17185, TCP 17185, broadcast fingerprint), map the WIND IP stack version, exploit the Urgent/11 chain (`CVE-2019-12256` stack overflow in `wdbDbgArchLib.c`, `CVE-2019-12258` memory pool allocator overflow, `CVE-2019-12260` DHCP client `dhcpClientOptionGet` overflow) for unauthenticated remote code execution on a Schneider Modicon PLC or an ABB RTU.
- **FreeRTOS+TCP stack exploitation**: Identify a device running FreeRTOS+TCP (often via DHCP option 60 strings, banner signatures in TCP/IP response timing, or filesystem strings indicating FreeRTOS), exploit the Zimperium chain (`CVE-2018-16528` `SendPing` heap overflow, `CVE-2018-16603` TCP SYN flood exhaustion, `CVE-2018-16525` IP fragment reassembly UAF) for kernel-mode RCE in the IP-task.
- **QNX Neutrino microkernel exploitation**: Identify QNX Neutrino (procnto-smp-instr on boot, qconn on 8000, the Qnet protocol on TCP/UDP 4000), exploit qconn weak authentication, abuse procfs (`/proc/<pid>/as` for arbitrary process memory access given CAP_SYS_ADMIN-equivalent credentials), or compromise a QNX Momentics IDE-launched binary via the Slinger/jqconn trusted channel.
- **ThreadX / Azure RTOS exploitation**: Identify ThreadX (filesystem strings, banner), exploit NetX DUO CVEs (`CVE-2021-2924` HTTP server overflow, `CVE-2023-34625` IPv6 ND prefix corruption), abuse the ThreadX block-pool allocator for heap-style attacks, or compromise Azure RTOS's HTTPS/REST server features added by the OpenAMP migration.
- **Zephyr RTOS exploitation**: Identify Zephyr (Kconfig build artifacts in the firmware filesystem, Bluetooth HCI vendor strings), exploit Bluetooth host-stack CVEs (`CVE-2019-17500` L2CAP heap overflow, `CVE-2020-10019` GATT handler UAF, `CVE-2022-3821` HCI ACL buffer overflow), or attack the Zephyr networking subsystem (CoAP server, LwM2M client).
- **Mbed OS exploitation**: Identify Mbed OS (Pelion Device Management strings, uVisor traces), exploit uVisor enclave bypass, attack the Pelion Cloud client (HTTPS over mbedTLS with the FSF certificate chain), or compromise mbed-cli build artifacts.
- **TI-RTOS / SYS/BIOS exploitation**: Identify TI-RTOS (BIOS task scheduler signatures, XDC tools artifacts, the C6000/C2000 boot signature), exploit the NDK TCP/IP stack, abuse ROV (Runtime Object Viewer) debug exposure over UART/Ethernet.
- **MicroC/OS-II / III exploitation**: Identify MicroC/OS (heap signature, OSTaskCreate runtime strings), exploit the absence of MMU/MPU enforcement (the OS does not enforce task isolation), abuse the lack of address randomization for trivial ROP on a task stack.
- **NuttX / RIOT / Contiki-NG exploitation**: Identify these smaller RTOSes (often on 6LoWPAN / 802.15.4 sensors), exploit their TCP/IP stacks (NuttX BSD-derivative, RIOT GNRC, Contiki uIP), attack the 6LoWPAN mesh layer.
- **Hardware-assisted exploitation**: Enumerate JTAG/SWD/ETM via JTAGulator or Shikra, attach via OpenOCD + J-Link/ST-Link/Black Magic Probe, dump FreeRTOS task control blocks, patch the secure boot fuse via voltage glitching with ChipWhisperer, or perform power-analysis key extraction on an mbedTLS AES implementation.
- **RTOS firmware static analysis**: Use Ghidra/IDA Pro with RTOS-specific loader scripts (VxWorks symbol recovery, FreeRTOS linker map import, ThreadX heap layout reconstruction) to identify memory corruption primitives, locate the WDB agent or qconn binary, and build the exploit chain.
- **RTOS emulation and symbolic execution**: Use Renode (which has first-class VexRiscv / LiteX support and is the canonical multi-RTOS emulator) or qemu-system to boot the RTOS in an emulated environment for repeatable dynamic analysis, then use angr to symbolically explore the WDB agent RPC parser or the FreeRTOS DHCP option handler for input-to-crash paths.

## Core Tools

### Disassembly and Static Analysis

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **IDA Pro** (Hex-Rays) | Commercial disassembler with ARM/MIPS/RISC-V/PowerPC support and decompiler; standard for VxWorks symbol table recovery | `idat64 -A -B vxworks_image.bin` |
| **Ghidra** (NSA) | Free, scriptable decompiler with RTOS-specific loaders (VxWorks, FreeRTOS linker maps, ELF QNX bootstrap); preferred for collaborative analysis | `ghidraRun` then `File > Import File` |
| **Binary Ninja** (Vector 35) | Modern API-first decompiler with strong IL; preferred for scripting RTOS heap analysis | `binaryninja vxworks.bin` |
| **radare2 / r2macho** | Open-source CLI reverse engineering; r2macho adds Mach-O for Apple platforms; preferred for embedded ARM Cortex-M | `r2 -A -a arm -b 32 vxworks.bin` |

### Hardware Attack

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **OpenOCD** | Open On-Chip Debugger; speaks JTAG/SWD to ARM Cortex-M/R/A, MIPS, RISC-V; controls target via GDB | `openocd -f interface/jlink.cfg -f target/stm32f4x.cfg` |
| **J-Link** (Segger) | Commercial JTAG/SWD probe; first-class RTOS awareness (FreeRTOS, ThreadX, Zephyr) | `JLinkExe -device STM32F407VG -if SWD -speed 4000` |
| **ST-Link** (STMicro) | Vendor JTAG/SWD probe, native to STM32 ecosystem | `st-flash --reset read image.bin 0x08000000 0x100000` |
| **Black Magic Probe** | Open-source JTAG/SWD probe with built-in GDB server; preferred for FreeRTOS-aware debugging on Cortex-M | `arm-none-eabi-gdb -ex 'target extended-remote /dev/ttyACM0'` |
| **JTAGulator** (Joe Grand) | One-shot JTAG/UART pin enumeration from an unknown PCBA; recovers TCK/TMS/TDI/TDO and TX/RX/GND from any of up to 24 pins | `jtagulator` (interactive) |
| **Shikra** (Xipiter) | Multi-protocol tool: JTAG, UART, SPI, I2C, CAN; primary lab tool for unknown embedded devices | `shikra --jtag-scan` |

### Firmware Extraction and Analysis

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **binwalk** | Signature scanning for embedded images (identifies VxWorks bootrom, RTOS compression layers) | `binwalk -Me firmware.bin` |
| **firmwalker** | Filesystem vulnerability scanner (locates VxWorks `target/config`, FreeRTOS `FreeRTOSConfig.h`, ThreadX `tx_api.h` strings) | `bash firmwalker.sh /tmp/squashfs-root/ report.txt` |
| **FACT** (Firmware Analysis and Comparison Tool) | Web-UI-driven firmware analysis framework; identifies RTOS by heuristic and runs CVE matching | `fact_start` |

### Emulation and Dynamic Analysis

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **QEMU system** | Full-system emulation of ARM, MIPS, PowerPC, RISC-V; boot an RTOS image in `qemu-system-arm -M versatilepb` | `qemu-system-arm -M lm3s6965evb -kernel nuttx.bin -nographic` |
| **Renode** (Antmicro) | Multi-node emulation designed for embedded; first-class support for VexRiscv, LiteX, STM32, NXP, TI Tiva; preferred for RTOS multi-core emulation | `renode path/to/zephyr.resc` |
| **angr** | Symbolic execution framework; explores WDB agent RPC parsers and FreeRTOS DHCP option handlers for input-to-crash paths | `python3 -m angr explore_wdb.py` |

### Fault Injection and Side-Channel

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **ChipWhisperer** (NewAE) | Open-source voltage/clock glitching and power analysis platform; the canonical SCA tool for Cortex-M secure-boot bypass | `cw.run(cw.glitch.Glitcher, 'power_trace')` |
| **GreatFET** (Great Scott Gadgets) | USB multi-tool for SWD/JTAG/SPI/I2C; companion to HackRF for embedded interop | `greatfet fw -r dump.bin` |
| **HydraBus / Bus Pirate** | Open-source multi-protocol bridges for UART/SPI/I2C/1-Wire enumeration | `hydrabus` (interactive) |

### Flash and Trace

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **flashrom** | SPI NOR/NAND/eMMC programmer; reads external flash via hardware programmers (CH341A, dediprog, Bus Pirate) | `flashrom -p ch341a_spi -r flash_dump.bin` |
| **strace / ltrace / perf** | Userspace tracing on Linux-based RTOS (NuttX POSIX, QNX Neutrino, RT-Linux) | `strace -f -e trace=network -p $(pidof qconn)` |

---

## Methodology

### RTOS Attack Chain

```
Fingerprinting            Debug Agent Exploit          Kernel/Task Compromise        Persistence
(Banner/Behavior)   (WDB RPC, qconn, GDB stub)   (RCE in IP-task, MPU bypass)   (Patch image / OTA)
       |                       |                              |                              |
       v                       v                              v                              v
  UDP 17185 banner       WDB_MODE_ANY exploit            Heap overflow in IP-task      Modify vxWorks image
  qconn TCP 8000         Urgent/11 chain                 Task TCB overwrite            Patch secure boot
  DHCP option 60         FreeRTOS DHCPv4 RCE             Scheduler priority inversion  Hook OTA update flow
  Bluetooth HCI banner   Zephyr GATT UAF                 MPU region re-configure       Survive factory reset
```

**Phase Details**:

1. **Fingerprinting**: Identify the RTOS via network banner (VxWorks WDB banner on UDP 17185, qconn banner on TCP 8000), DHCP option 60 vendor class identifier, filesystem strings in extracted firmware, Bluetooth HCI vendor/version response, or symbol recovery via binwalk + VxWorks loader. Determine version (VxWorks 5.5/6.x/7, FreeRTOS 8/9/10/11, ThreadX 5.x/6.x). Cross-reference against published CVE catalog (Urgent/11, Zimperium 2018, Azure RTOS advisories 2023).

2. **Debug Agent Exploit**: If WDB is exposed (default VxWorks `< 6.9.4` ships with `WDB_MODE_ANY` allowing unauthenticated read/write/execute), use the WDB RPC protocol directly to call `tgtPing`, read arbitrary memory via `wdbCtxRead`, write memory via `wdbCtxWrite`, or spawn a task with `wdbTaskSpawn`. QNX qconn supports the QConnect protocol with optional authentication that OEMs routinely disable; exploitation includes `posix_spawn` of a root shell. FreeRTOS GDB stubs (when enabled) accept `monitor` commands for memory access without authentication.

3. **Kernel/Task Compromise**: When no debug agent is exposed, attack the IP stack directly. Urgent/11 stack overflow in `wdbDbgArchLib.c` (CVE-2019-12256) is triggered by a malformed WDB RPC packet even with WDB disabled in some builds. FreeRTOS+TCP `SendPing` heap overflow (CVE-2018-16528) is triggered by an ICMP echo with a malicious payload length. Zephyr L2CAP heap overflow (CVE-2019-17500) is triggered by an L2CAP signal packet with oversized information payload. After RCE, escalate privileges within the flat RTOS address space: all FreeRTOS tasks share the same address space (no MMU by default), so userland is already kernel-mode. On QNX microkernel, abuse procfs after obtaining any process credentials to read arbitrary process memory via `/proc/<pid>/as`.

4. **Persistence**: Modify the firmware image on the external SPI flash (after gaining write access via flashrom-on-target or a vendor-supplied update mechanism). Patch the WDB agent to require authentication. Hook the OTA update mechanism to deliver attacker-controlled firmware. On VxWorks, hook `usrAppInit` to spawn an attacker task at boot. On Zephyr, abuse the MCUboot serialized update flow.

### Debug Agent vs Network Stack Workflow

```
DEBUG AGENT PATH                                  NETWORK STACK PATH
(preferred — fewer prerequisites)                 (when debug agent is closed)

1. nmap UDP 17185 / TCP 8000 / TCP 3333           1. Identify IP/Bluetooth stack (vendor strings)
2. WDB RPC tgtPing                                2. Craft single-packet PoC (ICMP, L2CAP, IPv6 ND)
3. wdbCtxRead target_nv_params                    3. Trigger heap overflow → ROP → task spawn
4. wdbTaskSpawn revshell_task                     4. Pivot to other network services
5. Dump full RAM via WDB                          5. Leverage for lateral movement in plant
```

---

## Practical Steps

> **For detailed commands and payloads see `payloads.md`, and for the complete test checklist see `test-cases.md`.** Below is a summary of core operations for each phase.

### 1. VxWorks WDB Fingerprint

```bash
# UDP 17185 is the default WDB port
nmap -sU -p 17185 --script=vxworks-wdb <target-ip>
# Confirm with the WDB banner echo
python3 payloads/wdb_probe.py --target <target-ip> --port 17185
```

### 2. FreeRTOS+TCP Stack Detection

```bash
# DHCP option 60 vendor class often contains "FreeRTOS"
dhcpig -i eth0 --target <target-ip>
# Network stack fingerprint via timing
nmap -sV -p 80,23 --version-intensity=5 <target-ip>
```

### 3. OpenOCD + J-Link Hardware Attach

```bash
# Identify the SWD interface
openocd -f interface/jlink.cfg -f target/stm32f4x.cfg -c init -c targets
# Dump full flash via GDB
arm-none-eabi-gdb -ex 'target extended-remote :3333' \
  -ex 'monitor reset halt' \
  -ex 'dump binary memory flash.bin 0x08000000 0x08100000'
```

### 4. ChipWhisperer Glitch Attack

```python
import chipwhisperer as cw
scope = cw.scope()
target = cw.target(scope)
scope.glitch.width = 5.5
scope.glitch.offset = -7.2
scope.glitch.repeat = 3
scope.glitch.trigger_src = 'manual'
# Fire glitch at target's secure boot validation routine
scope.glitch.manual_trigger()
```

### 5. Renode RTOS Emulation

```
# Zephyr .resc script
:mmio_init
include @zephyr/memmap.repl
:set loglevel 3
emulation TimeLimit 30
showAnalyzer uart0
sysbus LoadELF @zephyr.elf
cpu SetRegister PC 0x08000000
```

---

## Defense Perspective

| Vulnerability Category | RTOS Manifestation | Detection Method |
|------------------------|------------------|------------------|
| **Debug Agent Exposure** | VxWorks WDB on UDP 17185 in production; QNX qconn on TCP 8000 with auth disabled; FreeRTOS GDB stub on TCP 3333 | Network scan (`nmap -sU -p 17185`), firmware filesystem grep for `wdbConfig`, `qConnStart` |
| **Memory Corruption in IP Stack** | VxWorks WIND IP stack Urgent/11; FreeRTOS+TCP heap overflow; ThreadX NetX DUO HTTP overflow; Zephyr CoAP UAF | Static analysis with Ghidra (look for `memcpy` without length checks in `dhcp*`, `icmp*`, `tcp*`), dynamic fuzzing with boofuzz on the network surface |
| **MPU/MMU Not Enforced** | FreeRTOS default build has no MPU region configuration; MicroC/OS-II has no MMU support; tasks share supervisor mode | Static review of `FreeRTOSConfig.h` for `configUSE_MPU_WRAPPERS=0`; binary review for absence of `vTaskAllocateMPURegions` calls |
| **Heap Corruption** | ThreadX block pool byte-level allocator; FreeRTOS `pvPortMalloc` wrapper; VxWorks `memPartAlloc` first-fit | Heap overflow fuzzing, use-after-free detection via canary placement (`-fstack-protector-all` port) |
| **Scheduler Priority Inversion** | FreeRTOS without `configUSE_MUTEXES` uses basic semaphores with no priority inheritance; VxWorks `semMCompute` has bounded inversion | Code review for `xSemaphoreCreateBinary` (no inheritance) vs `xSemaphoreCreateMutex` (inheritance) |
| **Insecure OTA Update** | VxWorks `bootLoad` over TFTP without signature; FreeRTOS AWS OTA with weak CA pinning; ThreadX Azure IoT with misconfigured x509 | Firmware update script analysis, MITM of OTA flow |
| **No Address Randomization** | No ASLR on bare-metal Cortex-M; fixed load addresses from linker map | ROP gadget analysis shows trivially small gadget offset in `pop {r0-r3,pc}` chains |
| **Weak Default Credentials** | QNX `root` no password by default in development images; VxWorks `tgtPassword` empty by default | Login probe, configuration review of `qconn.cfg`, `usrAppInit.c` |

---

## Hacker Laws

| Law | Manifestation in Embedded RTOS Security |
|-----|-----------------------------------------|
| **First Principles** | Understand the RTOS architecture before exploitation. A flat address space RTOS (FreeRTOS, MicroC/OS, older ThreadX) gives a task-compromise RCE by definition; a microkernel (QNX Neutrino, seL4) requires IPC exploitation. The VxWorks WDB RPC protocol (UDP 17185, `WDB_MODE_ANY` = no auth) is published and stable; reading the WDB specification is a 30-minute investment that pays off on every VxWorks engagement for the rest of your career. |
| **Divergent Thinking First** | When the network stack is closed, attack the debug agent. When both are closed, attack the hardware (JTAG, glitch). When the hardware is locked down, attack the supply chain (firmware build at OEM, Tier-1 SDK backdoor). The VxWorks 6.9.4 patch for Urgent/11 closed the WDB RPC parser flaw but left three other Urgent/11 CVEs unpatched in some OEM shipping profiles for 18 months — divergent thinking means re-scanning the same target across time. |
| **Trust but Verify** | The OEM claims secure boot, MPU enforcement, and WDB disabled. Verify all three independently: scan UDP 17185 with nmap, dump the firmware via JTAG and grep for `wdbMode`, inspect the linker map for MPU region allocation. Trust the silicon, not the documentation. |
| **Skill Over Credentials** | RTOS exploitation requires combining software exploitation (heap layout, scheduler behavior, IP stack internals) with hardware exploitation (JTAG TAP enumeration, glitch parameters, side-channel alignment). The OSCP does not teach this; the OSEE/OSCE try to. The most effective RTOS analysts combine embedded engineering backgrounds with binary exploitation expertise. |
| **Defense in Depth** | Secure boot + MPU enforcement + WDB disabled + stack canaries + ASLR-on-MCU (where supported) + signature-verified OTA + CAN-IDS-style anomaly detection on task behavior. No single layer stops the attacker; the layers buy time. The VxWorks Urgent/11 patch closed 11 CVEs but the underlying architecture (IP stack in kernel mode, debug agent shipped in production) remains unchanged. |
| **Assume Breach** | Design RTOS deployments assuming one task (the Bluetooth stack, the IP-task, the HTTPS server) has already been compromised. Enforce MPU regions so a task compromise cannot read crypto keys from another task. Use secure-element-backed attestation so a kernel compromise is detectable by the cloud backend. The FreeRTOS+TCP CVEs of 2018 should have been the wake-up call; many devices still ship with those versions. |
| **Least Privilege** | A FreeRTOS task running the HTTP server should not have read access to the mbedTLS key material. A QNX process running an untrusted parser should not have CAP_SYS_ADMIN-equivalent credentials. Every unnecessary permission (MPU region grant, QNX capability, VxWorks memory partition share) is an escalation vector. |
| **Minimize Attack Surface** | Disable WDB (`INCLUDE_WDB = FALSE`), qconn (`io-pkt -d qconn` removed from startup), GDB stubs (`-DCONFIG_DEBUG_STUB=n`), Bluetooth (`-DCONFIG_BT=n`) when not used. Every disabled feature is one fewer CVE waiting to be discovered. The Urgent/11 disclosure affected devices that shipped WDB in production "for diagnostics" — the same diagnostics available over JTAG at the factory. |
| **Supply Chain Trust** | The RTOS itself (VxWorks, FreeRTOS, Zephyr) is generally trusted because the source is auditable. The Tier-1 vendor modifications (a custom DHCP option parser, a proprietary Bluetooth GATT service) are where the bugs hide. The Azure RTOS acquisition of ThreadX in 2019, the Eclipse Foundation adoption of ThreadX as OpenAMP/ThreadX in 2024, and the Mbed OS deprecation in 2024 all shifted responsibility without re-auditing the underlying code. |
| **Weakest Link Is Human** | Most RTOS compromises start with an OEM who left `WDB_MODE_ANY` enabled because the field service techs needed it, a Tier-1 who reused a known-vulnerable ThreadX version because the BOM was frozen, or a developer who left a `#define DEBUG` enabled in the release build. The technical vulnerability is downstream of the organizational one. |

---

## Common Pitfalls

1. **Treating an RTOS like a general-purpose OS.** RTOS task stacks are tiny (often 256-1024 bytes); a stack overflow that would corrupt a Linux thread's adjacent guard page will corrupt the next task's TCB on FreeRTOS. RTOS schedulers do not have time-slice fairness — a high-priority task will starve everything below it forever. RTOS memory allocators (ThreadX block pool, MicroC/OS `OSMemPut`) are simple first-fit and have no `free()` semantics to exploit but have predictable layouts for overflow.

2. **Assuming WDB is disabled in production.** The VxWorks WDB agent has been found in production devices as late as 2024 — including devices that shipped after the 2019 Urgent/11 disclosure. The reason is always the same: the field service organization needs remote diagnostics, and `WDB_MODE_ANY` (no authentication) is the path of least resistance. Always scan UDP 17185 even if the OEM claims it's disabled.

3. **Confusing `configUSE_MPU_WRAPPERS=1` with MPU enforcement.** Setting `configUSE_MPU_WRAPPERS=1` in `FreeRTOSConfig.h` enables the MPU-aware API (`xTaskCreateRestricted`), but does NOT enforce MPU on existing tasks created with `xTaskCreate`. Every task must be created with `xTaskCreateRestricted` and a populated `TaskParameters_t.xRegions[]` for MPU to apply. Many OEMs enable the wrapper, leave `xTaskCreate` calls unchanged, and ship "MPU-protected" FreeRTOS that is in fact flat-address-space.

4. **Ignoring RTOS-specific heap layouts.** ThreadX's byte pool allocator (`tx_byte_pool`) places metadata inline with the allocation in a way that makes classic heap exploitation unreliable. But ThreadX's block pool (`tx_block_pool`) is a pure singly-linked free list with predictable layout — `tx_block_release` is a textbook unlink exploit. Know which allocator your target uses.

5. **Treating Zephyr like Linux.** Zephyr is POSIX-ish but its networking stack is custom, its Bluetooth host stack is a from-scratch implementation, and its scheduler is preemptive fixed-priority with cooperative time slicing only on `k_yield`. Tools like `strace`, `ltrace`, `valgrind`, and even GDB Python scripts written for Linux will not work out of the box. Use Zephyr's native `shell`, `kernel` shell, and the `west` build tool.

6. **Trusting secure boot without verifying the chain.** A device may have a fused secure-boot ROM that verifies the first-stage bootloader, but a buggy first-stage bootloader may load a second-stage image from an unverified offset. The TI-RTOS SYS/BIOS boot path, the VxWorks `bootrom` -> `usrAppInit` path, and the Zephyr MCUboot path all have multi-stage verification logic that must be reviewed end-to-end. Verify the chain, not the fuse.

7. **Glitching without reconnaissance.** Voltage glitching on a Cortex-M secure boot requires knowing the exact cycle window where the signature verification branch occurs. Reconnaissance with ChipWhisperer's power-trace capture (10k+ traces aligned by the boot clock edge) is mandatory before any glitch attempt. Glitching blind is a way to brick a $200 dev board and learn nothing.

8. **Forgetting that QNX Neutrino has a real microkernel.** Unlike VxWorks or FreeRTOS, QNX Neutrino enforces process isolation — a process compromise does not directly give kernel access. The escalation path is via procfs (`/proc/<pid>/as`), the qconn trusted channel, or kernel-driver IPC messages. Treating QNX like a flat RTOS wastes time; the methodology is closer to Linux kernel exploitation.

---

## Cross-Skill Integration

- **`firmware-reverse`** — Provides the extracted firmware image (binwalk + sasquatch + jefferson) that embedded-rtos-security then dissects for RTOS-specific components (WDB agent binary, FreeRTOSConfig.h, ThreadX `tx_api.h`). Embedded-rtos-security assumes firmware-reverse has run.
- **`hardware-security`** — Provides JTAG/UART/SWD enumeration (JTAGulator, Shikra), flashrom dumps, and the physical lab setup that embedded-rtos-security uses to access RTOS task state via OpenOCD. Embedded-rtos-security owns the RTOS-specific exploitation of those hardware primitives.
- **`binary-reverse`** — Provides Ghidra/IDA Pro methodology that embedded-rtos-security specializes for RTOS loaders (VxWorks symbol table recovery, FreeRTOS linker map import, ThreadX heap layout reconstruction).
- **`exploit-development`** — Takes RTOS vulnerabilities (Urgent/11, FreeRTOS+TCP, Zephyr Bluetooth) and develops reliable exploit code with ROP chains, heap feng shui, and shellcode targeting the specific RTOS task model.
- **`iot-pentest`** — Covers the application-layer IoT protocols (MQTT, CoAP, LwM2M) that ride on top of the RTOS networking stack. Embedded-rtos-security owns the FreeRTOS+TCP stack that carries the MQTT broker; iot-pentest owns the MQTT broker itself.
- **`scada-ics-security`** — Owns the SCADA application protocols (Modbus, DNP3, S7comm) that run on top of VxWorks or MicroC/OS in industrial controllers. Embedded-rtos-security owns the VxWorks WDB agent underneath; scada-ics-security owns the Modbus function code surface.
- **`automotive-vehicle-security`** — Owns the CAN bus, UDS, and OBD-II layer. The overlap is QNX Neutrino running on the IVI — automotive owns the IVI-as-vehicle-component; embedded-rtos-security owns the QNX microkernel underneath.
- **`sdr-rf-attack`** — Provides the RF layer for Bluetooth (Zephyr BLE), Zigbee (THREAD/ThreadX), and sub-GHz IoT protocols. Embedded-rtos-security owns the Bluetooth host stack on Zephyr; sdr-rf-attack owns the PHY/MAC layer.
- **`bluetooth-rfid-nfc`** — Provides BLE/NFC exploitation methodology that embedded-rtos-security applies to Zephyr's Bluetooth host stack and ThreadX's BLE profile stack.

---

## Learning Resources

**Supplementary files for this skill**:
- `payloads.md` — Complete command collection (11 sections, 60+ code blocks covering all major RTOS families and hardware attack surfaces)
- `test-cases.md` — Structured test cases (12 case templates, TC-RT-001 through TC-RT-012, with prerequisites, expected results, and severity ratings)

**Extended learning materials (guides/)**:
- `guides/embedded-rtos-security-playbook.md` — End-to-end red team playbook: RTOS architecture comparison, attack surface map, real CVE deep dives (Urgent/11, FreeRTOS+TCP, Zephyr Bluetooth), hardware lab setup, glitching rig, emulation, and defensive guidance.

**Reference repositories**:
- [FreeRTOS/FreeRTOS](https://github.com/FreeRTOS/FreeRTOS) — FreeRTOS kernel and FreeRTOS+TCP source
- [eclipse-threadx/threadx](https://github.com/eclipse-threadx/threadx) — ThreadX/Azure RTOS (now Eclipse Foundation)
- [zephyrproject-rtos/zephyr](https://github.com/zephyrproject-rtos/zephyr) — Zephyr RTOS source
- [RIOT-OS/RIOT](https://github.com/RIOT-OS/RIOT) — RIOT OS source
- [apache/nuttx](https://github.com/apache/nuttx) — Apache NuttX
- [contiki-ng/contiki-ng](https://github.com/contiki-ng/contiki-ng) — Contiki-NG
- [renode/renode](https://github.com/renode/renode) — Antmicro Renode emulator
- [chipwhisperer/chipwhisperer](https://github.com/newaetech/chipwhisperer) — NewAE ChipWhisperer
- [openocd-org/openocd](https://github.com/openocd-org/openocd) — OpenOCD source

**External resources**:
- [JSOF Urgent/11 disclosure (2019)](https://www.jsof-tech.com/urgent11/) — The 11 VxWorks CVEs (CVE-2019-12256 et al.)
- [Zimperium FreeRTOS+TCP analysis (2018)](https://www.zimperium.com/freertos-tcp-vulnerabilities/) — CVE-2018-16525/16528/16529/16603
- [Wind River VxWorks security advisories](https://www.windriver.com/psirt) — Vendor PSIRT
- [BlackBerry QNX security advisories](https://www.blackberry.com/us/en/services/blackberry-product-security-incident-response-team) — Vendor PSIRT
- [Zephyr Project security advisories](https://docs.zephyrproject.org/latest/security/vulnerabilities.html) — Vendor PSIRT
- ARM Cortex-M security guidelines (AN-1221, ARMv8-M Security Extension)
- [OWASP Embedded Systems Security Testing Guide](https://owasp.org/www-project-embedded-systems-security-testing/)
- [Attacking Network Protocols (James Forshaw)](https://nostarch.com/networkprotocols) — relevant for WDB RPC and qconn analysis

**Related skills**:
- `skills/firmware-reverse/SKILL.md` — Generic firmware extraction and analysis
- `skills/hardware-security/SKILL.md` — JTAG/UART/SWD/glitching methodology
- `skills/binary-reverse/SKILL.md` — Generic disassembly and decompilation
- `skills/exploit-development/SKILL.md` — Exploit development methodology
- `skills/iot-pentest/SKILL.md` — Application-layer IoT protocols
- `skills/scada-ics-security/SKILL.md` — Industrial control protocols
- `skills/automotive-vehicle-security/SKILL.md` — Vehicle attack surface (QNX IVI overlap)
