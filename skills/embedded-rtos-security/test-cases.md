# Embedded RTOS Security Test Cases

> Companion to `SKILL.md`, containing structured test cases organized by category with severity ratings.
> All commands assume an authorized engagement scope, a bench RTOS device / emulator / closed-environment target, or a Renode/QEMU emulated environment. Never run active exploitation against a production safety-critical device (avionics, medical, automotive, industrial) without explicit written authorization covering the specific device serial number, the specific firmware version, and the specific test scope.

## Prerequisites

Before executing any test case in this catalogue, verify the following pre-conditions are met:

1. **Authorization**: Written authorization from the device manufacturer AND the device operator covering the specific device serial number, the specific firmware version, and the specific test scope. For safety-critical targets (avionics DO-178C, automotive ISO 26262, medical IEC 62304, industrial IEC 62443), additional certifications or regulatory filings may be required.
2. **Hardware**: The appropriate debug probe (J-Link, ST-Link, Black Magic Probe), JTAGulator for pin enumeration, ChipWhisperer for fault injection, and a bench/spare target device (production hardware may be irreversibly damaged by glitch attacks or flash desoldering).
3. **Software**: `openocd`, `arm-none-eabi-gdb`, `radare2`, Ghidra, IDA Pro (or Binary Ninja), `binwalk`, `flashrom`, Renode, QEMU, `angr`, `chipwhisperer` (Python module), `scapy` with Bluetooth layers (see `payloads.md` §1 for install commands).
4. **Lab environment**: A separate physical network for any device under test (DUT) — RTOS network stack exploits can affect adjacent devices (DHCP OFFER overflow, broadcast ICMP). RF-shielded enclosure for any Bluetooth/gnss tests. Oscilloscope (>100 MHz) for glitch characterization.
5. **Recovery plan**: A documented plan for restoring the DUT to a known-good state after each test (JTAG reflash, factory reset, external SPI flash re-programming via flashrom).

---

## Verification Checklist

After executing each test case, verify the following pass criteria before marking the test complete:

- [ ] **Captured evidence**: PCAP/ASC trace saved with timestamp; OpenOCD logs; JTAGulator output; ChipWhisperer traces; Ghidra project archive.
- [ ] **Reproducibility**: The test was run at least twice with consistent results; documented any intermittent failures (e.g., glitch successes are typically < 5% — record attempts vs. successes).
- [ ] **Scope compliance**: No exploitation attempted against devices outside the engagement scope; no network traffic observed outside the lab segment.
- [ ] **Post-test cleanup**: DUT restored to known-good firmware; any modified configuration reverted; debug interfaces restored to OEM state.
- [ ] **Documentation**: Finding documented with severity, MITRE ATT&CK mapping, tool list, CVE references (where applicable), and remediation guidance.
- [ ] **Safety check**: For targets in safety-critical contexts (avionics, automotive, medical), confirm no unintended physical effect occurred and the DUT passed post-test functional verification.

---

## Statistics

| Category | Count | Severity Range |
|------|------|-----------|
| A. Lab Setup & Hardware Enumeration | 2 | INFO - LOW |
| B. Debug Agent Exploitation (WDB, qconn, GDB stub) | 2 | MEDIUM - CRITICAL |
| C. Network Stack Exploitation (FreeRTOS+TCP, Zephyr BT, NetX DUO) | 2 | HIGH - CRITICAL |
| D. Hardware Fault Injection (Glitching, SCA) | 2 | MEDIUM - CRITICAL |
| E. Static & Dynamic Binary Analysis | 2 | MEDIUM - HIGH |
| F. Emulation & Symbolic Execution | 2 | LOW - HIGH |
| **Total** | **12** | **INFO - CRITICAL** |

---

## A. Lab Setup & Hardware Enumeration

### TC-RT-001: OpenOCD + J-Link Lab Bring-up (VxWorks/FreeRTOS/Zephyr)

| Field | Value |
|------|-----|
| **ID** | TC-RT-001 |
| **Title** | OpenOCD + J-Link Lab Bring-up for ARM Cortex-M RTOS Targets |
| **Objective** | Stand up a working OpenOCD + J-Link environment on Kali Linux to attach to an ARM Cortex-M target running an RTOS (VxWorks/FreeRTOS/Zephyr), dump the full flash, and verify RTOS-aware GDB access (task list, per-task stack inspection). |
| **Steps** | 1. Install toolchain: `sudo apt-get install -y openocd gdb-multiarch arm-none-eabi-gcc`.<br>2. Write OpenOCD config: `cat > /tmp/swd_jlink.cfg` with `adapter driver jlink`, `transport select swd`, `swd newdap target cpu -irlen 2 -expected-id 0x2BA01477`, `target create target.cpu cortex_m -dap dap.dap -rtos FreeRTOS`.<br>3. Start OpenOCD: `openocd -f /tmp/swd_jlink.cfg`. Verify log shows `cortex_m reset_event_handler` and `target.cpu state: halted`.<br>4. Attach GDB: `arm-none-eabi-gdb -ex 'target extended-remote :3333' -ex 'monitor reset halt'`.<br>5. Read DHCSR: `(gdb) monitor mww 0xE000EDF0 0xA05F0003; monitor mdw 0xE000EDF0` — if returns `0x00030003`, debug is open; if `0x00000000`, debug is locked (proceed to TC-RT-007 for glitch attack).<br>6. Dump flash: `(gdb) dump binary memory /tmp/flash.bin 0x08000000 0x08100000`. Verify `0x100000` bytes written.<br>7. Load symbols (if .elf available): `(gdb) symbol-file firmware.elf`.<br>8. List tasks: `(gdb) info threads` — should show IDLE, IP-task, etc., if RTOS-aware.<br>9. Detach cleanly: `(gdb) monitor reset; detach; quit`. |
| **Expected Result** | OpenOCD attaches successfully; DHCSR returns `0x00030003` (open debug) or `0x00000000` (locked); full flash dumped to `/tmp/flash.bin` (size matches expected flash size); `info threads` shows RTOS task list (when RTOS awareness is active). The dumped flash can be loaded into Ghidra for static analysis (TC-RT-009). |
| **Tools** | OpenOCD, arm-none-eabi-gdb, J-Link probe (or ST-Link / Black Magic Probe), ARM Cortex-M target (STM32F4 / nRF52 / CC26xx) |
| **MITRE** | T1212-Exploitation for Credential Access (DHCSR test); T1052-Exfiltration Over Physical Medium (flash dump) |
| **Difficulty** | 2 - Beginner-Intermediate |
| **Tags** | lab, openocd, jlink, swd, cortex-m, flash-dump |

### TC-RT-002: JTAGulator Pin Enumeration on Unknown PCBA

| Field | Value |
|------|-----|
| **ID** | TC-RT-002 |
| **Title** | JTAGulator Pin Enumeration for Unknown RTOS PCBA |
| **Objective** | Use the JTAGulator hardware tool to enumerate the JTAG and UART pinout of an unknown printed circuit board assembly (PCBA) running an RTOS, recovering TCK/TMS/TDI/TDO/TRST and TX/RX/GND from a set of candidate test pads. |
| **Steps** | 1. Power off the target device. Identify candidate debug pins (typically a row of unpopulated through-hole pads near the SoC; look for 4-10 pads labeled TP1, TP2, etc., or unmarked).<br>2. Connect JTAGulator to the candidate pins: hook up to 4-8 candidate pins to channels 0-7 on JTAGulator; connect JTAGulator GND to a known GND test point.<br>3. Connect JTAGulator to host: `picocom -b 115200 /dev/ttyUSB0`.<br>4. Power on the target.<br>5. At the JTAGulator prompt: `j` (JTAG enumeration), `24` (scan 24 channels — the maximum), `0` (starting channel).<br>6. Wait for the scan to complete (typically 5-15 minutes for a 24-channel scan).<br>7. Document results: JTAGulator prints the discovered TCK/TMS/TDI/TDO mapping and the device IDCODE (if any).<br>8. Decode IDCODE: use the JEDEC JEP-106 lookup (e.g., `0x4BA00477` = ARM Cortex-M4F with SW-DP, `0x0B99A02F` = TI CC26xx).<br>9. Switch to UART enumeration: at the prompt, `u` (UART discovery), scan the same channels. JTAGulator finds the TX pin (active during boot) and the RX pin (silent).<br>10. Document pinout in the engagement notes for future OpenOCD use (TC-RT-001). |
| **Expected Result** | JTAGulator discovers a working JTAG interface (or reports "No JTAG found" — indicating JTAG is fused off or unpopulated); IDCODE decoded to a manufacturer/CPU. UART enumeration finds the boot-log-emitting TX pin. The resulting pinout enables subsequent OpenOCD attachment. |
| **Tools** | JTAGulator hardware, picocom, target PCBA, JEDEC JEP-106 lookup table (https://www.jedec.org) |
| **MITRE** | T1592-Gather Victim Host Information (hardware recon) |
| **Difficulty** | 3 - Intermediate |
| **Tags** | lab, jtagulator, jtag-enumeration, uart-discovery, pinout |

---

## B. Debug Agent Exploitation (WDB, qconn, GDB stub)

### TC-RT-003: VxWorks WDB RPC Fingerprinting

| Field | Value |
|------|-----|
| **ID** | TC-RT-003 |
| **Title** | VxWorks WDB RPC Agent Fingerprinting and TGT_PING Verification |
| **Objective** | Identify a target device running VxWorks (or confirm its absence) by probing UDP port 17185 with the WDB RPC `TGT_PING` procedure, then perform `TGT_INFO` to extract the VxWorks version, BSP name, and CPU type — without sending any memory-read/write requests. |
| **Steps** | 1. Network scan: `nmap -sU -p 17185 --script=vxworks-wdb <target-ip>` to confirm UDP 17185 is open and responsive.<br>2. Manual WDB RPC probe using the Python skeleton in `payloads.md` §3: send a `TGT_PING` (procedure 21) packet and capture the reply.<br>3. If reply received: extract xid, reply type, reply state — confirm a valid WDB RPC reply (reply_type=1).<br>4. Send `TGT_INFO` (procedure 22) to retrieve the runtime info structure (rtType, rtVersion, rtBspName, rtCpuType).<br>5. Parse XDR-encoded strings to extract the VxWorks version (e.g., "VxWorks 6.9.4.1") and BSP name (e.g., "ti_beaglebone").<br>6. Cross-reference the VxWorks version against the Urgent/11 CVE list (`payloads.md` Appendix A): if version < 6.9.4.1, the device is vulnerable to CVE-2019-12256 et al.<br>7. Document the WDB agent's authentication mode by inspecting the probe response: if `TGT_PING` succeeded with NULL auth, the device is running `WDB_MODE_ANY` (no auth) — proceed to TC-RT-004. |
| **Expected Result** | UDP 17185 responds to WDB RPC probe; `TGT_INFO` returns a parseable version string identifying the VxWorks version and BSP; authentication mode is determined (`WDB_MODE_ANY` vs `WDB_MODE_TASK`). The engagement notes record the VxWorks version, the BSP, and the applicable Urgent/11 CVEs. |
| **Tools** | nmap, Python 3 with `socket` and `struct` modules, WDB RPC reference (Wind River documentation) |
| **MITRE** | T1046-Network Service Scanning; T1210-Exploitation of Remote Services |
| **Difficulty** | 3 - Intermediate |
| **Tags** | vxworks, wdb, rpc, fingerprint, urgent-11 |

### TC-RT-004: VxWorks WDB Agent Memory Read + Task Spawn (WDB_MODE_ANY)

| Field | Value |
|------|-----|
| **ID** | TC-RT-004 |
| **Title** | VxWorks WDB Unauthenticated Memory Read and Task Spawn (WDB_MODE_ANY) |
| **Objective** | Exploit a VxWorks WDB agent running in `WDB_MODE_ANY` (no authentication) to (a) read the system banner and confirm RTOS version, (b) read an arbitrary memory region to extract the symbol table, and (c) spawn a benign task (e.g., `printf("pwned")`) to demonstrate code execution — without crashing the target. |
| **Steps** | 1. Prerequisite: TC-RT-003 confirmed WDB agent open in `WDB_MODE_ANY`.<br>2. Use the `VxWorksWDB` Python class from `payloads.md` §3 to construct calls.<br>3. Read system banner: `wdb.read_mem(0x08008000, 256)` (or the BSP-specific banner address from the symbol table). Decode as ASCII; confirm it matches the version reported by `TGT_INFO`.<br>4. Dump first 4 MB of RAM to disk: `dump_vxworks_ram('target-ip', 0x00000000, 0x00400000)` (function defined in `payloads.md` §3). Save as `target_ram.bin` for offline analysis.<br>5. Extract symbol table from the dump: `strings -a target_ram.bin | grep -E "^[0-9a-f]{8} [tTbBdD] "` and pipe to a file.<br>6. Spawn a benign task: write a small `printf` payload to SRAM (`0x20000000`) and use `TASK_SPAWN` (procedure 11) to create a task named `test_task` executing the payload.<br>7. Verify task spawn via the system console (if accessible) or by reading the task's TCB back via `CTX_READ`.<br>8. Document findings: this is a CRITICAL finding — unauthenticated remote code execution via the WDB agent. The remediation is to disable WDB in production (`INCLUDE_WDB = FALSE`).<br>9. Do NOT install persistence or destructive payloads without explicit authorization — this test case only demonstrates read + benign spawn. |
| **Expected Result** | Memory read succeeds and returns the expected banner; symbol table is extracted (typically 500-5000 symbols); benign task is spawned without affecting device operation. Engagement report documents this as a CRITICAL severity finding with remediation guidance: disable WDB in production kernel configuration. |
| **Tools** | Python 3 (socket, struct), `strings`, WDB RPC reference |
| **MITRE** | T1210-Exploitation of Remote Services; T1055-Process Injection (task spawn); T1005-Data from Local System (memory dump) |
| **Difficulty** | 4 - Intermediate-Advanced |
| **Tags** | vxworks, wdb, memory-read, task-spawn, urgent-11, critical |

### TC-RT-005: QNX qconn Enumeration and Process Launch

| Field | Value |
|------|-----|
| **ID** | TC-RT-005 |
| **Title** | QNX Neutrino qconn Service Enumeration and Unauthenticated Process Launch |
| **Objective** | Identify a QNX Neutrino device by fingerprinting the qconn service (TCP 8000), enumerate exposed services via the JSON launcher protocol, and (if the configuration is the default unauthenticated dev profile) launch `/bin/sh -c id` to confirm remote code execution. |
| **Steps** | 1. Port scan: `nmap -sV -p 8000 --script=qconn-version <target-ip>` to confirm TCP 8000 and identify qconn.<br>2. Manual connect: `nc <target-ip> 8000` — observe the banner (typically `QCONN` or a version string).<br>3. Send JSON service list: `echo '{"service":"launcher","cmd":"list"}' | nc -w 3 <target-ip> 8000`.<br>4. Parse the JSON response and document each exposed service (e.g., pdebug, slinger, qconnect).<br>5. Attempt a benign launch: `echo '{"service":"launcher","cmd":"launch","program":"/bin/sh","argv":["-c","id"]}' | nc -w 3 <target-ip> 8000`.<br>6. If response includes `"exit_code":0,"output":"uid=0(root)..."`, document as CRITICAL — unauthenticated root RCE via qconn.<br>7. If launch is rejected, attempt with explicit user context (QNX uses POSIX credentials): add `"user":"root"` to the JSON.<br>8. Test for known QNX Slinger (HTTP server) vulnerabilities on port 8080 if exposed (`nmap -sV -p 8080`).<br>9. Document findings; remediation is to require qconn authentication (`qconn.cfg`) or disable qconn in production. |
| **Expected Result** | qconn banner and service list successfully retrieved; if unauthenticated launch is permitted, RCE is confirmed (CRITICAL severity). Engagement report documents the qconn configuration, the list of exposed services, and remediation guidance. |
| **Tools** | nmap, nc (netcat), Python 3 for structured JSON interaction |
| **MITRE** | T1210-Exploitation of Remote Services; T1059-Command and Scripting Interpreter (shell launch) |
| **Difficulty** | 3 - Intermediate |
| **Tags** | qnx, qconn, launcher, json, rce |

---

## C. Network Stack Exploitation (FreeRTOS+TCP, Zephyr BT, NetX DUO)

### TC-RT-006: FreeRTOS+TCP ICMP Heap Overflow PoC (CVE-2018-16528)

| Field | Value |
|------|-----|
| **ID** | TC-RT-006 |
| **Title** | FreeRTOS+TCP ICMP Echo Request Heap Overflow (CVE-2018-16528) |
| **Objective** | Trigger CVE-2018-16528 on a bench FreeRTOS+TCP device (or QEMU-emulated instance) running FreeRTOS+TCP < 10.3.1, demonstrating that an oversized ICMP echo request causes a heap overflow in the IP-task. Use a benign payload (no shellcode) to confirm the vulnerability without compromising the target. |
| **Steps** | 1. Prerequisite: a bench device or QEMU instance running FreeRTOS+TCP < 10.3.1 (use the Zimperium PoC repo: `https://github.com/Zimperium/freertostcp_pocs`).<br>2. Verify the device responds to ping: `ping <target-ip>` (should succeed).<br>3. Verify the IP-task is running: attach via OpenOCD/JTAG (TC-RT-001) and `(gdb) info threads` — should show an "IP-task" thread.<br>4. Send the PoC from `payloads.md` §5: `python3 trigger_cve_2018_16528.py <target-ip> 2000`.<br>5. Observe the device: the IP-task should crash (heap corruption detected via FreeRTOS stack-overflow check or HardFault handler).<br>6. If the device crashes: confirm via OpenOCD that the IP-task PC is in `FreeRTOS_ICMP.c` (specifically `FreeRTOS_SendPingReply` or related).<br>7. Document the heap layout before and after (via GDB memory dumps): before — clean heap; after — overflow pattern visible in adjacent heap block.<br>8. Restart the device and verify it returns to a clean state.<br>9. Test against patched FreeRTOS+TCP 10.3.1+ to confirm the fix.<br>10. Document findings as HIGH severity — unauthenticated remote DoS with RCE potential. |
| **Expected Result** | The oversized ICMP echo triggers a crash in the FreeRTOS IP-task on unpatched versions; patched versions (10.3.1+) reject the oversized packet. Heap layout analysis confirms the overflow. Engagement report documents the CVE reference, the affected version, and the remediation (upgrade to 10.3.1+). |
| **Tools** | Scapy, OpenOCD + GDB, FreeRTOS+TCP source for symbol reference, bench/QEMU device |
| **MITRE** | T1499-Endpoint Denial of Service; T1055-Process Injection (potential) |
| **Difficulty** | 4 - Intermediate-Advanced |
| **Tags** | freertos, freertos-tcp, icmp, heap-overflow, cve-2018-16528 |

### TC-RT-007: Zephyr Bluetooth Host L2CAP Fuzzing

| Field | Value |
|------|-----|
| **ID** | TC-RT-007 |
| **Title** | Zephyr Bluetooth Host L2CAP Stack Fuzzing (CVE-2019-17500 / CVE-2023-3353) |
| **Objective** | Fuzz the Zephyr Bluetooth host's L2CAP layer with oversized information payloads to trigger known heap overflow CVEs (CVE-2019-17500, CVE-2023-3353) on a bench BLE device running Zephyr < 3.5. Use a controlled Bluetooth LE interface (hci0) and document any crash signatures. |
| **Steps** | 1. Prerequisite: a bench BLE device running a known-vulnerable Zephyr build (e.g., Zephyr 2.x for CVE-2019-17500, Zephyr 3.4 for CVE-2023-3353), or a QEMU-emulated Zephyr with the `native_posix` Bluetooth HCI.<br>2. Verify the device advertises: `sudo hcitool -i hci0 lescan` — capture the device BD_ADDR.<br>3. Connect and enumerate: `sudo bluetoothctl` -> `connect <bdaddr>` -> `menu gatt` -> `list-attributes`.<br>4. Use Bettercap or a custom Python script to send oversized L2CAP packets:<br>   - Build an L2CAP Connection Request (code 0x02) with an oversized information payload (256-2048 bytes).<br>   - Wrap in a BLE LL Data PDU.<br>   - Send via the Linux kernel's HCI socket interface.<br>5. Monitor the target: via OpenOCD/JTAG, watch for HardFault in `bt_l2cap_recv` or related functions.<br>6. If crash observed: dump the register state (PC, LR, SP) and confirm PC is in the Bluetooth host stack (`subsys/bluetooth/host/l2cap.c`).<br>7. Document the fuzzing campaign: number of attempts, number of crashes, crash signatures.<br>8. Cross-reference crash signatures against the known CVE list.<br>9. Test against patched Zephyr 3.5+ to confirm the fixes.<br>10. Document findings as HIGH/CRITICAL — unauthenticated remote BLE heap overflow with RCE potential. |
| **Expected Result** | Oversized L2CAP packets trigger heap overflows on vulnerable Zephyr versions; patched versions reject oversized payloads. Crash dumps confirm PC in the Bluetooth host stack. Engagement report documents the CVE references, the affected versions, and the remediation (upgrade to Zephyr 3.5+). |
| **Tools** | hcitool, bluetoothctl, Bettercap, Python with `scapy.layers.bluetooth4LE`, OpenOCD + GDB |
| **MITRE** | T1499-Endpoint Denial of Service; T1055-Process Injection; T1210-Exploitation of Remote Services |
| **Difficulty** | 5 - Advanced |
| **Tags** | zephyr, bluetooth, l2cap, fuzzing, cve-2019-17500, cve-2023-3353 |

### TC-RT-008: ThreadX NetX DUO HTTP Server Overflow (CVE-2021-2924)

| Field | Value |
|------|-----|
| **ID** | TC-RT-008 |
| **Title** | ThreadX NetX DUO HTTP Server URL Overflow (CVE-2021-2924) |
| **Objective** | Trigger CVE-2021-2924 on a ThreadX/Azure RTOS device running NetX DUO with an HTTP server, demonstrating that an oversized HTTP request URL causes a buffer overflow in `nx_http_server_entry`. Use a benign payload to confirm the vulnerability without compromising the target. |
| **Steps** | 1. Prerequisite: a bench device or QEMU instance running ThreadX/Azure RTOS NetX DUO with an HTTP server enabled (default port 80).<br>2. Verify HTTP server: `curl -v http://<target-ip>/` — should return a default page or 404.<br>3. Send the PoC from `payloads.md` §6: `python3 trigger_cve_2021_2924.py <target-ip> 80`.<br>4. Observe the device: the HTTP server task should crash (buffer overflow). If stack canaries are enabled (`-fstack-protector-strong`), the canary aborts cleanly; otherwise, RCE is possible.<br>5. If crash: confirm via OpenOCD that the HTTP server task PC is in `nx_http_server_entry` (the URL parser).<br>6. Document the URL length that triggers the overflow (default `NX_HTTP_SERVER_MAX_URL_LENGTH = 100`; trigger length 1024).<br>7. Test variations: oversized header value, oversized body (POST), oversized URI parameters.<br>8. Document findings as HIGH severity — unauthenticated remote DoS with RCE potential on builds without stack canaries.<br>9. Test against patched NetX DUO 6.2+ to confirm the fix. |
| **Expected Result** | Oversized HTTP URL triggers a crash in the NetX HTTP server task on unpatched versions; patched versions reject oversized URLs. Engagement report documents the CVE reference, the affected version, and the remediation (upgrade to NetX DUO 6.2+, enable stack canaries). |
| **Tools** | Python 3 (socket), OpenOCD + GDB, ThreadX NetX DUO source |
| **MITRE** | T1499-Endpoint Denial of Service; T1055-Process Injection |
| **Difficulty** | 3 - Intermediate |
| **Tags** | threadx, netx-duo, http, overflow, cve-2021-2924 |

---

## D. Hardware Fault Injection (Glitching, SCA)

### TC-RT-009: ChipWhisperer Voltage Glitching on Cortex-M Secure Boot

| Field | Value |
|------|-----|
| **ID** | TC-RT-009 |
| **Title** | ChipWhisperer Voltage Glitch Attack to Bypass Secure Boot on Cortex-M |
| **Objective** | Use a ChipWhisperer-Lite (or Husky) to perform voltage glitching on an ARM Cortex-M4 target with fused secure boot enabled, with the goal of bypassing the signature verification check during boot. Document the glitch parameters (width, offset, repeat) that produce a successful bypass. |
| **Steps** | 1. Prerequisite: an STM32F4 (or similar Cortex-M4) target with secure boot enabled (e.g., STM32Trust), ChipWhisperer-Lite with CW308 UFO board, and a known-good firmware image (signed) plus a known-bad image (unsigned).<br>2. Capture power traces of the secure boot signature verification routine: load the known-good image, capture 1000 power traces aligned to the boot clock edge. Identify the cycle(s) where the signature check branch occurs.<br>3. Configure the glitch: `scope.glitch.clk_src = 'clkgen'`, `scope.glitch.trigger_src = 'ext_trigger'`, target reset as trigger.<br>4. Sweep glitch parameters: for `width_ns` in [3, 4, 5, 5.5, 6, 7, 8] and `offset_ns` in [-10, -7.5, -5, -2.5, 0, 2.5, 5], attempt a glitch.<br>5. For each attempt: reset target, arm scope, observe boot log (over UART).<br>6. A successful bypass: the target boots the unsigned image without rejecting it. Confirm by reading the firmware version string.<br>7. Document glitch parameters that produce bypasses: typically width 5-6 ns, offset -7 to -5 ns, repeat 2-3 cycles.<br>8. Document the success rate: glitch attacks are typically 1-5% successful; record attempts vs. successes.<br>9. Note: this test case is DESTRUCTIVE — voltage glitching can brick the target. Use a spare device.<br>10. Document findings as CRITICAL — secure boot bypass is a hardware-level failure with implications for the entire threat model. |
| **Expected Result** | A subset of glitch parameters produce a successful secure boot bypass (the target boots an unsigned image). The success rate is documented (typically < 5%). The engagement report documents the glitch parameters, the implications (any local attacker can boot unsigned firmware), and the remediation (use a glitch-resistant secure boot, e.g., NXP LPC55S69 with anti-glitch circuits). |
| **Tools** | ChipWhisperer-Lite, CW308 UFO board, STM32F4 target, oscilloscope (>100 MHz), Python with `chipwhisperer` module |
| **MITRE** | T1548-Abuse Elevation Control Mechanism; T1499-Endpoint Denial of Service (potential brick) |
| **Difficulty** | 5 - Advanced |
| **Tags** | chipwhisperer, voltage-glitch, secure-boot, cortex-m, critical |

### TC-RT-010: OpenOCD SWD Exploitation — FreeRTOS Task State Dump

| Field | Value |
|------|-----|
| **ID** | TC-RT-010 |
| **Title** | OpenOCD SWD Exploitation — FreeRTOS Task State Dump and Per-Task Stack Inspection |
| **Objective** | Use OpenOCD + GDB with FreeRTOS awareness to dump the full task control block (TCB) list of a running FreeRTOS device, including per-task stack contents, register state, and priority — enabling offline analysis of the RTOS state for vulnerability research. |
| **Steps** | 1. Prerequisite: TC-RT-001 verified OpenOCD attaches successfully with FreeRTOS awareness enabled.<br>2. Connect GDB: `arm-none-eabi-gdb -ex 'target extended-remote :3333'`.<br>3. Halt the target: `(gdb) monitor reset halt`.<br>4. Load symbols: `(gdb) symbol-file firmware.elf` (the .elf file from the build).<br>5. List tasks: `(gdb) info threads` — should show IDLE, IP-task, TCP-RX, TCP-TX, etc.<br>6. For each task, dump its TCB:<br>   - Switch to the task: `(gdb) thread N`.<br>   - Backtrace: `(gdb) bt` — should show the task's call stack.<br>   - Read register state: `(gdb) info registers` — R0-R3, R12, LR, PC, XPSR.<br>   - Read stack: `(gdb) x/32wx $sp` — top 128 bytes of stack.<br>7. Identify the IP-task's pending packet: switch to IP-task thread, examine `pxCurrentTCB` and trace the IP-task's local variables (`prvProcessIPEvents` locals).<br>8. Dump the heap layout: `(gdb) call vPortGetHeapStats()` (if available) or dump the heap region directly.<br>9. Document findings: the task list, per-task priorities, and any anomalies (a task with corrupted stack, unexpected PC, or anomalous priority).<br>10. Detach cleanly: `(gdb) monitor reset; detach; quit`. |
| **Expected Result** | OpenOCD + GDB + FreeRTOS awareness produces a complete task list with per-task register state, stack contents, and priority. The engagement notes record the task list for offline analysis. Anomalies (e.g., a task with PC outside its expected address range) are flagged for further investigation. |
| **Tools** | OpenOCD, arm-none-eabi-gdb, FreeRTOS-aware target, firmware.elf |
| **MITRE** | T1056-Input Capture (task state capture); T1212-Exploitation for Credential Access |
| **Difficulty** | 4 - Intermediate-Advanced |
| **Tags** | openocd, swd, freertos, task-dump, tcb |

---

## E. Static & Dynamic Binary Analysis

### TC-RT-011: VxWorks Symbol Recovery and Ghidra Import

| Field | Value |
|------|-----|
| **ID** | TC-RT-011 |
| **Title** | VxWorks Symbol Table Recovery from Firmware Image and Ghidra Import |
| **Objective** | Recover the VxWorks symbol table (`vxWorks.sym` equivalent) from a raw firmware image using `strings`, parse the `<address> <type> <name>` format, and import the symbols into Ghidra for offline static analysis of the VxWorks kernel, WDB agent, and IP stack. |
| **Steps** | 1. Prerequisite: a firmware image extracted via binwalk (TC-RT-001 or `firmware-reverse` skill) containing a VxWorks binary.<br>2. Extract strings: `strings -a firmware.bin > firmware_strings.txt`.<br>3. Filter for symbol table entries: `grep -E "^[0-9a-f]{8} [tTbBdD] " firmware_strings.txt > vxworks_symbols.txt`.<br>4. Parse the symbol file: each line is `<8-hex-address> <type-char> <name>`. Type chars: t/T = text (code), b/B = bss (uninitialized data), d/D = data, etc.<br>5. Count symbols: `wc -l vxworks_symbols.txt`. A typical VxWorks image has 500-5000 symbols.<br>6. Cross-reference key symbols: `grep -E "wdbDbgArchLib|wdbTaskSpawn|wdbCtxRead|usrAppInit|tgtPing" vxworks_symbols.txt`. The presence of `wdbDbgArchLib` confirms the WDB agent is compiled in.<br>7. Load the firmware into Ghidra: `ghidraRun` -> `File > Import File` -> select `firmware.bin`.<br>8. Configure the loader: Language = `ARM:LE:32:Cortex` (or MIPS/PowerPC depending on the target CPU). Loader options: base address = 0x00100000 (or per symbol table).<br>9. After auto-analysis, run a Python script to import the symbols:<br>   - Read `vxworks_symbols.txt`.<br>   - For each entry, create a symbol at `<address>` with name `<name>`.<br>10. Verify symbol import: navigate to `wdbDbgArchLib` in the symbol tree. Ghidra should jump to the function and show its decompiled C code.<br>11. Use the imported symbols to identify the WDB RPC parser (`wdbRpcDispatch`), the IP stack entry (`ip_recv`), and the task scheduler (`taskSpawn`).<br>12. Document the symbol count, the CPU architecture, and the key functions identified. |
| **Expected Result** | The VxWorks symbol table is recovered (typically 500-5000 symbols); symbols are imported into Ghidra and navigable by name. The engagement notes record the WDB agent's presence (or absence) and the version (from the `VxWorks` version string). |
| **Tools** | binwalk, strings, grep, Ghidra, Python for symbol import scripting |
| **MITRE** | T1583-Gather Victim Host Information (binary analysis); T1055-Process Injection (RCE identification) |
| **Difficulty** | 4 - Intermediate-Advanced |
| **Tags** | vxworks, symbols, ghidra, static-analysis |

### TC-RT-012: Renode Multi-RTOS Emulation and Dynamic Analysis

| Field | Value |
|------|-----|
| **ID** | TC-RT-012 |
| **Title** | Renode Multi-Node RTOS Emulation with Dynamic Analysis |
| **Objective** | Set up a Renode emulation environment for an RTOS target (Zephyr on STM32F4 / FreeRTOS on LM3S6965 / NuttX on VersatilePB), boot the RTOS in the emulator, and use Renode's RTOS awareness (FreeRTOS/Zephyr/ThreadX task listing) and peripheral emulation (UART, networking) to perform dynamic analysis without hardware. |
| **Steps** | 1. Install Renode: `sudo dpkg -i renode-*.pkg` (or use Docker `renode/renode`).<br>2. Write a `.resc` script for the target (see `payloads.md` §13 for templates):<br>   - For Zephyr on STM32F4Discovery: include `memmap.repl`, load `zephyr.elf`, set PC to reset vector, enable semihosting, show UART analyzer.<br>3. Launch Renode: `renode zephyr_stm32f4.resc`.<br>4. At the Renode prompt: `(stm32) start`. Observe the boot log in the UART analyzer window.<br>5. Verify RTOS is running: look for `Booting Zephyr OS` (Zephyr) or `FreeRTOS V10.x` (FreeRTOS) or `NuttShell (NSH)` (NuttX).<br>6. Enable RTOS awareness: `(renode) rtos SetType FreeRTOS` (or `Zephyr` / `ThreadX`).<br>7. List tasks: `(renode) rtos ListTasks` — should show IDLE, IP-task, TCP-RX, etc.<br>8. Inspect a task: `(renode) rtos SwitchTo IP-task; cpu GetRegister`.<br>9. Set up networking: in the `.resc` script, configure a TAP interface for network emulation. Verify network access from the emulated RTOS (e.g., `ifconfig` / `ipconfig`).<br>10. Use the emulated environment for vulnerability research: trigger CVE PoCs (TC-RT-006, TC-RT-007, TC-RT-008) against the emulated target without needing physical hardware.<br>11. Document findings: the emulation setup, the RTOS version, the task list, and any vulnerabilities triggered. |
| **Expected Result** | Renode boots the RTOS in emulation; RTOS-aware task listing works; networking peripheral emulation enables network-based PoCs against the emulated target. The engagement notes record the emulation configuration and the RTOS behavior under PoC triggers. |
| **Tools** | Renode, RTOS ELF images (Zephyr/FreeRTOS/NuttX), TAP interface configuration |
| **MITRE** | T1210-Exploitation of Remote Services; T1055-Process Injection (potential) |
| **Difficulty** | 4 - Intermediate-Advanced |
| **Tags** | renode, emulation, zephyr, freertos, dynamic-analysis |

---

## Severity Rating Reference

| Severity | Description | Examples in this Catalogue |
|------|------|-----------|
| **INFO** | Informational — no direct impact | Lab setup, fingerprinting |
| **LOW** | Limited impact — DoS only, or requires physical access | UART discovery, slowloris |
| **MEDIUM** | Significant impact — privileged information disclosure, RCE on dev builds | qconn enumeration, FreeRTOS GDB stub |
| **HIGH** | Major impact — unauthenticated remote DoS or RCE on production | CVE-2018-16528 ICMP overflow, NetX HTTP overflow |
| **CRITICAL** | Catastrophic impact — unauthenticated remote RCE, secure boot bypass | WDB MODE_ANY exploit, ChipWhisperer secure boot bypass, L2CAP heap overflow |

---

## Cross-References

- **`skills/firmware-reverse/test-cases.md`** — Generic firmware extraction test cases (binwalk, sasquatch, firmadyne). TC-RT-001 assumes this is done.
- **`skills/hardware-security/test-cases.md`** — JTAG/UART/SWD enumeration test cases. TC-RT-001 and TC-RT-002 build on these.
- **`skills/binary-reverse/test-cases.md`** — Ghidra/IDA Pro analysis test cases. TC-RT-011 specializes these for VxWorks symbols.
- **`skills/exploit-development/test-cases.md`** — Exploit development test cases. TC-RT-004 and TC-RT-009 produce findings for exploit development.
- **`skills/iot-pentest/test-cases.md`** — IoT application-layer test cases (MQTT, CoAP, LwM2M). The RTOS underneath those protocols is covered by this catalogue.
- **`skills/scada-ics-security/test-cases.md`** — SCADA protocol test cases (Modbus, DNP3). The VxWorks/MicroC/OS underneath is covered here.

---

End of test-cases.md. See `SKILL.md` for skill overview, `payloads.md` for the complete command catalogue, and `guides/embedded-rtos-security-playbook.md` for the end-to-end red team playbook.
