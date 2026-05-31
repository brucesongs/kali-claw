# Network Forensics PCAP Analysis Guide

> Practical reference for network traffic analysis: Wireshark display filters, protocol dissection, IOC extraction, session reconstruction, and evidence correlation from packet captures.

## 1. Capture Acquisition and Initial Triage

Start by understanding the scope of the capture and identifying high-value traffic.

```bash
# Capture live traffic (forensic acquisition)
tcpdump -i eth0 -w capture.pcap -C 100 -W 10 -Z root
# -C 100 = rotate at 100MB, -W 10 = keep 10 files

# Get capture statistics and overview
capinfos capture.pcap
# Shows: file size, packet count, duration, data rate, encapsulation

# Quick protocol breakdown
tshark -r capture.pcap -q -z io,phs
# Protocol hierarchy statistics

# Identify top talkers (source IPs by packet count)
tshark -r capture.pcap -q -z endpoints,ip | sort -t'|' -k3 -rn | head -20

# Identify conversations (bidirectional flows)
tshark -r capture.pcap -q -z conv,tcp | sort -t'|' -k5 -rn | head -20

# Check for unusual ports
tshark -r capture.pcap -T fields -e tcp.dstport | sort | uniq -c | sort -rn | head -30
```

## 2. Wireshark Display Filters for Forensic Analysis

```
# HTTP traffic with potential data exfiltration
http.request.method == "POST" && http.content_length > 10000

# DNS queries to suspicious TLDs or long subdomains
dns.qry.name matches ".*\.(tk|ml|ga|cf|xyz)$"
dns.qry.name matches "^[a-z0-9]{30,}\."

# Detect DNS tunneling (large TXT responses or many unique queries)
dns.qry.type == 16 && dns.resp.len > 200

# SMB lateral movement indicators
smb2.cmd == 5 && smb2.filename contains "\\ADMIN$"
smb2.cmd == 5 && smb2.filename matches ".*\\.(exe|dll|ps1|bat)$"

# Kerberos authentication anomalies (pass-the-ticket, golden ticket)
kerberos.msg_type == 12 && kerberos.cipher_type == 23

# Detect beaconing patterns (C2 communication)
# Filter by destination and look for regular intervals
ip.dst == 192.168.1.100 && tcp.dstport == 443

# TLS with suspicious characteristics
tls.handshake.type == 1 && tls.handshake.extensions_server_name contains "pastebin"
tls.handshake.type == 1 && !(tls.handshake.extensions_server_name)

# ICMP tunneling (data in echo requests)
icmp.type == 8 && data.len > 64
```

## 3. Extracting IOCs from Network Traffic

```bash
# Extract all DNS queries (potential C2 domains)
tshark -r capture.pcap -Y "dns.flags.response == 0" \
  -T fields -e dns.qry.name | sort -u > dns_queries.txt

# Extract all HTTP hosts and URLs
tshark -r capture.pcap -Y "http.request" \
  -T fields -e http.host -e http.request.uri | sort -u > http_urls.txt

# Extract TLS SNI (Server Name Indication) values
tshark -r capture.pcap -Y "tls.handshake.type == 1" \
  -T fields -e tls.handshake.extensions_server_name | sort -u > tls_sni.txt

# Extract all unique IP addresses communicated with
tshark -r capture.pcap -T fields -e ip.dst | sort -u > dest_ips.txt

# Extract email addresses from SMTP traffic
tshark -r capture.pcap -Y "smtp" \
  -T fields -e smtp.req.parameter | grep -oE "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+" \
  | sort -u > email_addresses.txt

# Extract file hashes from transferred files
tshark -r capture.pcap --export-objects "http,/output/http_objects"
find /output/http_objects -type f -exec sha256sum {} \; > file_hashes.txt

# Check extracted hashes against VirusTotal (manual or API)
while read hash filename; do
  echo "$hash $filename"
done < file_hashes.txt
```

## 4. Session Reconstruction and File Extraction

```bash
# Extract all HTTP objects (files transferred via HTTP)
tshark -r capture.pcap --export-objects "http,/output/http_files"
tshark -r capture.pcap --export-objects "smb,/output/smb_files"
tshark -r capture.pcap --export-objects "tftp,/output/tftp_files"
tshark -r capture.pcap --export-objects "imf,/output/email_files"

# Reconstruct TCP streams (follow a conversation)
# First identify the stream index
tshark -r capture.pcap -Y "tcp.stream eq 5" -T fields \
  -e data.data | xxd -r -p > stream5_raw.bin

# Extract specific TCP stream as ASCII
tshark -r capture.pcap -q -z "follow,tcp,ascii,5"

# Reconstruct FTP file transfers
tshark -r capture.pcap -Y "ftp-data" -T fields -e tcp.stream | sort -u
# For each data stream, extract the payload:
tshark -r capture.pcap -Y "tcp.stream eq 7" -T fields \
  -e tcp.payload | tr -d ':' | xxd -r -p > ftp_transferred_file.bin

# NetworkMiner for automated extraction (GUI alternative)
networkminer -r capture.pcap -o /output/networkminer/
# Extracts: files, images, credentials, sessions, DNS, parameters
```

## 5. Detecting Lateral Movement and Exploitation

```bash
# Detect port scanning activity
tshark -r capture.pcap -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0" \
  -T fields -e ip.src -e ip.dst -e tcp.dstport | \
  awk '{print $1" -> "$2":"$3}' | sort | uniq -c | sort -rn | head -20

# Detect SMB/PSExec lateral movement
tshark -r capture.pcap -Y "smb2.cmd == 5" \
  -T fields -e ip.src -e ip.dst -e smb2.filename | grep -iE "\\\\.*(exe|dll|ps1)"

# Detect pass-the-hash (NTLM authentication patterns)
tshark -r capture.pcap -Y "ntlmssp.messagetype == 3" \
  -T fields -e ip.src -e ip.dst -e ntlmssp.auth.username \
  -e ntlmssp.auth.domain | sort -u

# Detect exploit traffic (shellcode patterns)
# Look for NOP sleds in payloads
tshark -r capture.pcap -Y "tcp.payload contains 90:90:90:90:90:90:90:90"

# Detect reverse shell connections (small packets, interactive pattern)
tshark -r capture.pcap -q -z "conv,tcp" | \
  awk -F'|' '$5 > 100 && $3 < 1000 && $4 < 1000 {print}'

# Detect PowerShell download cradles
tshark -r capture.pcap -Y "http.request.uri contains \"powershell\" || \
  http.request.uri contains \"IEX\" || http.request.uri contains \"-enc\""
```

## 6. Detecting C2 Beaconing Patterns

```python
#!/usr/bin/env python3
"""Detect C2 beaconing by analyzing connection intervals."""

import subprocess
import json
from collections import defaultdict
import statistics

# Extract TCP SYN timestamps grouped by destination
cmd = [
    'tshark', '-r', 'capture.pcap',
    '-Y', 'tcp.flags.syn == 1 && tcp.flags.ack == 0',
    '-T', 'json',
    '-e', 'frame.time_epoch',
    '-e', 'ip.dst',
    '-e', 'tcp.dstport'
]

result = subprocess.run(cmd, capture_output=True, text=True)
packets = json.loads(result.stdout)

# Group timestamps by destination
connections = defaultdict(list)
for pkt in packets:
    layers = pkt['_source']['layers']
    dst = layers.get('ip.dst', [''])[0]
    port = layers.get('tcp.dstport', [''])[0]
    ts = float(layers.get('frame.time_epoch', ['0'])[0])
    connections[f"{dst}:{port}"].append(ts)

# Analyze intervals for beaconing
print("=== Potential C2 Beaconing ===")
for dest, timestamps in connections.items():
    if len(timestamps) < 10:
        continue
    intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
    if not intervals:
        continue
    mean_interval = statistics.mean(intervals)
    stdev = statistics.stdev(intervals) if len(intervals) > 1 else 0
    jitter = (stdev / mean_interval * 100) if mean_interval > 0 else 100

    # Low jitter = regular beaconing
    if jitter < 20 and mean_interval > 5:
        print(f"  {dest}: interval={mean_interval:.1f}s, jitter={jitter:.1f}%, "
              f"connections={len(timestamps)}")
```

## 7. Protocol-Specific Deep Analysis

```bash
# SMTP analysis - extract email content
tshark -r capture.pcap -Y "smtp.data.fragment" \
  -T fields -e smtp.data.fragment > smtp_data.txt

# DNS exfiltration detection - entropy analysis
tshark -r capture.pcap -Y "dns.flags.response == 0" \
  -T fields -e dns.qry.name | awk -F'.' '{
    subdomain=$1;
    len=length(subdomain);
    if (len > 20) print len, $0
  }' | sort -rn | head -20

# DHCP analysis - identify rogue DHCP servers
tshark -r capture.pcap -Y "dhcp.type == 2" \
  -T fields -e ip.src -e dhcp.option.dhcp_server_id | sort -u

# ARP analysis - detect ARP spoofing
tshark -r capture.pcap -Y "arp.opcode == 2" \
  -T fields -e arp.src.hw_mac -e arp.src.proto_ipv4 | sort | uniq -c | \
  awk '$1 > 1 {print "DUPLICATE:", $0}'

# Wireless analysis (if 802.11 capture)
tshark -r wireless.pcap -Y "wlan.fc.type_subtype == 0x08" \
  -T fields -e wlan.ssid -e wlan.bssid -e wlan.rsn.akms.type | sort -u

# Extract credentials from cleartext protocols
# FTP credentials
tshark -r capture.pcap -Y "ftp.request.command == USER || ftp.request.command == PASS" \
  -T fields -e ip.src -e ftp.request.command -e ftp.request.arg
# HTTP Basic Auth
tshark -r capture.pcap -Y "http.authorization" \
  -T fields -e ip.src -e http.authorization
```

## 8. Automated Analysis Pipeline

```bash
#!/bin/bash
# Automated PCAP forensic analysis pipeline
PCAP="$1"
OUTPUT="./forensic_output"
mkdir -p "$OUTPUT"/{iocs,files,reports,streams}

echo "=== Network Forensics Analysis Pipeline ==="
echo "PCAP: $PCAP"
echo "Output: $OUTPUT"
echo ""

# Phase 1: Overview
echo "[1/5] Generating capture overview..."
capinfos "$PCAP" > "$OUTPUT/reports/capture_info.txt"
tshark -r "$PCAP" -q -z io,phs > "$OUTPUT/reports/protocol_hierarchy.txt"
tshark -r "$PCAP" -q -z endpoints,ip > "$OUTPUT/reports/endpoints.txt"
tshark -r "$PCAP" -q -z conv,tcp > "$OUTPUT/reports/conversations.txt"

# Phase 2: IOC Extraction
echo "[2/5] Extracting IOCs..."
tshark -r "$PCAP" -Y "dns.flags.response == 0" \
  -T fields -e dns.qry.name | sort -u > "$OUTPUT/iocs/dns_queries.txt"
tshark -r "$PCAP" -Y "http.request" \
  -T fields -e http.host -e http.request.full_uri | sort -u > "$OUTPUT/iocs/http_requests.txt"
tshark -r "$PCAP" -Y "tls.handshake.type == 1" \
  -T fields -e tls.handshake.extensions_server_name | sort -u > "$OUTPUT/iocs/tls_sni.txt"
tshark -r "$PCAP" -T fields -e ip.dst | sort -u > "$OUTPUT/iocs/dest_ips.txt"

# Phase 3: File Extraction
echo "[3/5] Extracting transferred files..."
tshark -r "$PCAP" --export-objects "http,$OUTPUT/files/http" 2>/dev/null
tshark -r "$PCAP" --export-objects "smb,$OUTPUT/files/smb" 2>/dev/null
find "$OUTPUT/files" -type f -exec sha256sum {} \; > "$OUTPUT/iocs/file_hashes.txt"

# Phase 4: Anomaly Detection
echo "[4/5] Detecting anomalies..."
tshark -r "$PCAP" -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0" \
  -T fields -e ip.src -e ip.dst -e tcp.dstport | \
  sort | uniq -c | sort -rn | head -50 > "$OUTPUT/reports/port_scan_candidates.txt"

# Phase 5: Summary
echo "[5/5] Generating summary..."
echo "DNS Queries: $(wc -l < "$OUTPUT/iocs/dns_queries.txt")" > "$OUTPUT/reports/summary.txt"
echo "HTTP Requests: $(wc -l < "$OUTPUT/iocs/http_requests.txt")" >> "$OUTPUT/reports/summary.txt"
echo "Unique Dest IPs: $(wc -l < "$OUTPUT/iocs/dest_ips.txt")" >> "$OUTPUT/reports/summary.txt"
echo "Files Extracted: $(find "$OUTPUT/files" -type f | wc -l)" >> "$OUTPUT/reports/summary.txt"
echo ""
echo "=== Analysis Complete ==="
cat "$OUTPUT/reports/summary.txt"
```
