# Memory Forensics with Volatility Guide

> Practical reference for analyzing memory dumps using Volatility3: process enumeration, malware detection, credential extraction, and rootkit identification through memory artifact analysis.

## 1. Memory Acquisition

```bash
# Acquire memory from a live Linux system
# Using LiME (Linux Memory Extractor)
git clone https://github.com/504ensicsLabs/LiME.git
cd LiME/src && make
# Load kernel module to dump memory
sudo insmod lime-$(uname -r).ko "path=/tmp/memory.lime format=lime"

# Acquire memory from a live Windows system (via remote)
# Using winpmem
winpmem_mini_x64.exe memory.raw

# Convert between formats
volatility3 -f memory.lime layerwriter --output memory.raw

# For virtual machines, suspend and grab memory file:
# VMware: .vmem file
# VirtualBox: .sav file
# QEMU/KVM: virsh dump DOMAIN memory.raw --memory-only
```

## 2. Initial Triage and OS Identification

```bash
# Volatility3 auto-detects OS from memory image
# List available plugins
volatility3 -f memory.raw --help

# Identify OS and kernel version
volatility3 -f memory.raw banners.Banners
volatility3 -f memory.raw windows.info.Info

# Quick triage - process listing
volatility3 -f memory.raw windows.pslist.PsList
volatility3 -f memory.raw windows.pstree.PsTree

# For Linux memory:
volatility3 -f memory.lime linux.pslist.PsList
volatility3 -f memory.lime linux.pstree.PsTree

# Check for hidden processes (compare methods)
volatility3 -f memory.raw windows.pslist.PsList > pslist.txt
volatility3 -f memory.raw windows.psscan.PsScan > psscan.txt
# Processes in psscan but not pslist = potentially hidden (DKOM)
diff <(awk '{print $1}' pslist.txt | sort) \
     <(awk '{print $1}' psscan.txt | sort)
```

## 3. Process Deep Dive

```bash
# Examine a suspicious process in detail
# Command line arguments (reveals malware parameters)
volatility3 -f memory.raw windows.cmdline.CmdLine --pid 4892

# DLLs loaded by process
volatility3 -f memory.raw windows.dlllist.DllList --pid 4892

# Open file handles
volatility3 -f memory.raw windows.handles.Handles --pid 4892

# Network connections per process
volatility3 -f memory.raw windows.netstat.NetStat
volatility3 -f memory.raw windows.netscan.NetScan

# Memory maps and injected code
volatility3 -f memory.raw windows.memmap.Memmap --pid 4892 --dump
volatility3 -f memory.raw windows.vadinfo.VadInfo --pid 4892

# Dump process executable
volatility3 -f memory.raw windows.pslist.PsList --pid 4892 --dump
# Output: pid.4892.0x400000.dmp
```

## 4. Malware Detection Techniques

```bash
# Detect code injection (process hollowing, DLL injection)
volatility3 -f memory.raw windows.malfind.Malfind
# Looks for:
# - Memory regions with PAGE_EXECUTE_READWRITE
# - PE headers in non-image VADs
# - Suspicious memory protection changes

# Detect API hooking (inline hooks, IAT hooks)
volatility3 -f memory.raw windows.ssdt.SSDT
# Compare SSDT entries against known-good kernel addresses

# Scan for YARA signatures in memory
cat > malware_rules.yar << 'EOF'
rule CobaltStrike_Beacon {
    strings:
        $s1 = "%s.4%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x"
        $s2 = "%s/submit.php"
        $s3 = "could not upload file"
    condition:
        2 of them
}

rule Mimikatz_Memory {
    strings:
        $s1 = "gentilkiwi"
        $s2 = "mimikatz"
        $s3 = "sekurlsa"
        $s4 = "kerberos"
    condition:
        3 of them
}
EOF

volatility3 -f memory.raw yarascan.YaraScan --yara-file malware_rules.yar
```

## 5. Credential Extraction

```bash
# Extract password hashes from memory (Windows)
volatility3 -f memory.raw windows.hashdump.Hashdump
# Output: Administrator:500:aad3b435...:31d6cfe0d...:::

# Extract cached domain credentials
volatility3 -f memory.raw windows.cachedump.Cachedump

# Extract LSA secrets
volatility3 -f memory.raw windows.lsadump.Lsadump

# Dump lsass.exe process memory for offline analysis
LSASS_PID=$(volatility3 -f memory.raw windows.pslist.PsList 2>/dev/null | \
  grep lsass | awk '{print $1}')
volatility3 -f memory.raw windows.pslist.PsList --pid $LSASS_PID --dump

# Then use pypykatz on the dump
pip install pypykatz
pypykatz lsa minidump lsass_dump.dmp
# Extracts: NTLM hashes, Kerberos tickets, cleartext passwords

# Linux credential extraction
volatility3 -f memory.lime linux.bash.Bash
# Shows bash history from memory (may contain typed passwords)
```

## 6. Rootkit Detection

```bash
# Detect kernel-level rootkits

# Check for SSDT hooks (Windows)
volatility3 -f memory.raw windows.ssdt.SSDT | grep -v "ntoskrnl\|win32k"
# Any entry not pointing to ntoskrnl.exe or win32k.sys is suspicious

# Check for hidden kernel modules (Linux)
volatility3 -f memory.lime linux.lsmod.Lsmod > loaded_modules.txt
volatility3 -f memory.lime linux.hidden_modules.HiddenModules
# Modules found by scanning but not in module list = hidden

# Detect callback hooks
volatility3 -f memory.raw windows.callbacks.Callbacks
# Look for callbacks registered by unknown drivers

# Check IDT (Interrupt Descriptor Table) for hooks
volatility3 -f memory.raw windows.idt.IDT | grep -v "ntoskrnl"

# Scan for driver objects
volatility3 -f memory.raw windows.driverscan.DriverScan
volatility3 -f memory.raw windows.driverirp.DriverIrp --driver suspicious_driver
```

## 7. Timeline and Event Reconstruction

```python
#!/usr/bin/env python3
# Build a forensic timeline from memory artifacts
import subprocess
import json

memory_file = "memory.raw"

def run_vol(plugin):
    """Run volatility3 plugin and return output."""
    result = subprocess.run(
        ['volatility3', '-f', memory_file, '-r', 'json', plugin],
        capture_output=True, text=True
    )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return []

# Collect timeline events from multiple sources
timeline = []

# Process creation times
for proc in run_vol('windows.pslist.PsList'):
    timeline.append({
        'time': proc.get('CreateTime', ''),
        'type': 'process_create',
        'detail': f"PID:{proc.get('PID')} {proc.get('ImageFileName')}"
    })

# Network connections
for conn in run_vol('windows.netscan.NetScan'):
    timeline.append({
        'time': conn.get('Created', ''),
        'type': 'network',
        'detail': f"{conn.get('LocalAddr')}:{conn.get('LocalPort')} -> "
                  f"{conn.get('ForeignAddr')}:{conn.get('ForeignPort')} "
                  f"({conn.get('Owner')})"
    })

# Sort by timestamp and output
timeline.sort(key=lambda x: x['time'])
for event in timeline:
    print(f"[{event['time']}] {event['type']:20s} {event['detail']}")
```

## 8. Automated Analysis Pipeline

```bash
#!/bin/bash
# Complete memory forensics workflow
MEMORY_FILE="$1"
OUTPUT_DIR="./forensics_output"
mkdir -p "$OUTPUT_DIR"

echo "[*] Starting memory forensics analysis..."

# Phase 1: System info
echo "[+] Gathering system information..."
volatility3 -f "$MEMORY_FILE" windows.info.Info > "$OUTPUT_DIR/sysinfo.txt" 2>/dev/null

# Phase 2: Process analysis
echo "[+] Analyzing processes..."
volatility3 -f "$MEMORY_FILE" windows.pstree.PsTree > "$OUTPUT_DIR/pstree.txt"
volatility3 -f "$MEMORY_FILE" windows.cmdline.CmdLine > "$OUTPUT_DIR/cmdline.txt"

# Phase 3: Network
echo "[+] Extracting network artifacts..."
volatility3 -f "$MEMORY_FILE" windows.netscan.NetScan > "$OUTPUT_DIR/network.txt"

# Phase 4: Malware indicators
echo "[+] Scanning for malware indicators..."
volatility3 -f "$MEMORY_FILE" windows.malfind.Malfind > "$OUTPUT_DIR/malfind.txt"
volatility3 -f "$MEMORY_FILE" windows.ssdt.SSDT > "$OUTPUT_DIR/ssdt.txt"

# Phase 5: Credentials
echo "[+] Extracting credentials..."
volatility3 -f "$MEMORY_FILE" windows.hashdump.Hashdump > "$OUTPUT_DIR/hashes.txt"

# Phase 6: Generate summary
echo "[+] Generating summary..."
echo "=== SUSPICIOUS FINDINGS ===" > "$OUTPUT_DIR/summary.txt"
echo "--- Injected Code ---" >> "$OUTPUT_DIR/summary.txt"
wc -l "$OUTPUT_DIR/malfind.txt" >> "$OUTPUT_DIR/summary.txt"
echo "--- External Connections ---" >> "$OUTPUT_DIR/summary.txt"
grep -v "127.0.0.1\|0.0.0.0\|::1" "$OUTPUT_DIR/network.txt" | \
  grep "ESTABLISHED" >> "$OUTPUT_DIR/summary.txt"

echo "[*] Analysis complete. Results in $OUTPUT_DIR/"
```
