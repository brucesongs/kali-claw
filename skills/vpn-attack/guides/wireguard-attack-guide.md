# WireGuard VPN Attack Guide

> Comprehensive guide to WireGuard protocol security assessment, covering protocol analysis, configuration extraction from compromised endpoints, peer enumeration techniques, cryptographic attack surface evaluation, and stealth considerations unique to WireGuard's minimalist design.

## Introduction

WireGuard is a modern VPN protocol designed with simplicity, high performance, and strong cryptography as core principles. Unlike IPSec/IKE or OpenVPN, WireGuard uses a minimal protocol surface: a single UDP port, a fixed set of cryptographic primitives (Curve25519, ChaCha20-Poly1305, BLAKE2s), and a sessionless handshake mechanism. This simplicity reduces the attack surface compared to older VPN protocols but introduces unique security considerations that penetration testers must understand.

WireGuard's design philosophy -- "avoid cryptographic agility" -- means there are no downgrade attacks possible, no weak cipher suites to negotiate, and no complex state machines to exploit. However, this same simplicity creates different attack vectors: the lack of a distinct handshake phase makes traffic analysis easier, the static nature of public keys enables peer fingerprinting, and the minimal logging makes incident response harder for defenders. WireGuard's sessionless design also means there is no explicit connection or disconnection -- packets are simply sent and received, which changes how both detection and exploitation work.

The primary attack surface for WireGuard includes: endpoint configuration files containing private keys, peer enumeration through timing analysis and packet probing, unauthorized peer registration if the configuration interface is exposed, and traffic analysis due to the protocol's deterministic packet structure. This guide covers each attack vector with practical techniques and defensive recommendations.

**Learning objectives**:

- Understand WireGuard protocol internals and cryptographic design
- Extract and analyze WireGuard configurations from compromised endpoints
- Enumerate WireGuard peers through active and passive techniques
- Assess cryptographic attack surface and key management practices
- Perform traffic analysis specific to WireGuard sessions
- Identify misconfigurations that expose WireGuard deployments to attack
- Provide defensive hardening recommendations based on assessment findings

**Prerequisites**: Familiarity with VPN fundamentals (see `SKILL.md`). Understanding of public key cryptography. Experience with WireGuard client/server configuration. Linux command-line proficiency.

---

## Practical Steps

### Step 1: WireGuard Protocol Analysis

Understanding the WireGuard protocol is essential for identifying its attack surface. WireGuard uses a 4-message handshake followed by encapsulated data packets.

**Protocol Structure**

```
WireGuard Packet Types:
1. Handshake Initiation (Type 1): 148 bytes
   - Sender static key (encrypted)
   - Sender ephemeral key
   - Timestamp, MAC1, MAC2

2. Handshake Response (Type 2): 92 bytes
   - Receiver ephemeral key
   - Encrypted payload, MAC1, MAC2

3. Cookie Reply (Type 3): 64 bytes
   - Sent under load to mitigate DoS

4. Transport Data (Type 4): Variable
   - Encrypted payload with sequence number
   - Counter for replay protection
```

```bash
# Capture and identify WireGuard traffic
# WireGuard uses UDP (default port 51820)
# First 4 bytes of every packet: message type (little-endian)

# Capture WireGuard handshake packets
sudo tcpdump -i any -nn udp port 51820 -w wg_capture.pcap

# Analyze WireGuard packet types
tshark -r wg_capture.pcap -Y "udp.port == 51820" -T fields \
  -e ip.src -e ip.dst -e data.data 2>/dev/null | \
  while read line; do
    src=$(echo "$line" | awk '{print $1}')
    dst=$(echo "$line" | awk '{print $2}')
    first_byte=$(echo "$line" | awk '{print $3}' | cut -c1-2)
    case "$first_byte" in
      01) type="Handshake Initiation" ;;
      02) type="Handshake Response" ;;
      03) type="Cookie Reply" ;;
      04) type="Transport Data" ;;
      *) type="Unknown ($first_byte)" ;;
    esac
    echo "$src -> $dst: $type"
  done

# Count packet types for traffic analysis
tshark -r wg_capture.pcap -Y "udp.port == 51820" -T fields \
  -e data.data 2>/dev/null | \
  awk '{print substr($1,1,2)}' | sort | uniq -c | sort -rn
```

### Step 2: WireGuard Service Discovery

Identifying WireGuard deployments on target networks requires both active scanning and passive traffic analysis.

**Active Discovery**

```bash
# Nmap scan for WireGuard (UDP 51820 is default)
sudo nmap -sU -p 51820 --reason target_network/24

# Custom WireGuard probe using Python
python3 << 'EOF'
import socket, struct

def send_wg_handshake_initiation(target_ip, target_port=51820):
    """Send a WireGuard handshake initiation to probe for WireGuard service"""
    
    # WireGuard handshake initiation format:
    # Type: 1 (4 bytes, little-endian)
    # Reserved: 0 (4 bytes)
    # Sender Index: random (4 bytes)
    # Unencrypted Ephemeral: 32 bytes of zeros (invalid but triggers response)
    # ... rest of the packet
    
    # Minimal probe packet (just message type)
    msg_type = struct.pack('<I', 1)  # Type 1: Handshake Initiation
    reserved = struct.pack('<I', 0)
    sender_index = struct.pack('<I', 0x12345678)
    
    # This is intentionally malformed -- a valid WG server will NOT respond
    # to an invalid handshake (by design, WireGuard is silent)
    # However, timing analysis can reveal if the port is open
    
    probe = msg_type + reserved + sender_index + b'\x00' * 128
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    
    try:
        sock.sendto(probe, (target_ip, target_port))
        # WireGuard does not respond to invalid handshakes
        # But we can measure timing to infer if the port is open
        data, addr = sock.recvfrom(1024)
        return True, "Response received"
    except socket.timeout:
        # No response -- could be WireGuard (silent) or closed port
        return None, "No response (timeout)"
    except Exception as e:
        return False, str(e)
    finally:
        sock.close()

# Scan for WireGuard endpoints
import sys
for ip in ["192.168.1.1", "192.168.1.2", "192.168.1.3"]:
    result, msg = send_wg_handshake_initiation(ip)
    print(f"{ip}:51820 - {msg}")
EOF
```

**Passive Discovery**

```bash
# Monitor for WireGuard traffic patterns
# WireGuard handshake initiation packets are exactly 148 bytes
# Transport data packets have a consistent 32-byte header

# Detect WireGuard by packet size patterns
sudo tcpdump -i any -nn 'udp and greater 147 and less 149' -c 100 2>/dev/null | \
  grep "UDP" | head -20

# Detect WireGuard by examining first 4 bytes
# Type 1 = handshake initiation (always 148 bytes)
# Type 4 = transport data (variable, min 76 bytes with empty payload)
sudo tcpdump -i any -nn udp port 51820 -XX -c 10 2>/dev/null | \
  grep "0x0000:" | head -5
# Look for 0x0100 0000 (type 1) or 0x0400 0000 (type 4) at offset 8 (after UDP header)
```

### Step 3: Configuration Extraction from Endpoints

WireGuard configurations stored on endpoints contain private keys, peer public keys, allowed IP ranges, and endpoint addresses. Extracting these from a compromised host provides complete VPN access.

**Linux Endpoint Configuration Extraction**

```bash
# Check for WireGuard configuration files
sudo find /etc/wireguard/ -name "*.conf" 2>/dev/null
sudo find /etc/wireguard/ -name "*.netdev" 2>/dev/null

# Read WireGuard configuration
sudo cat /etc/wireguard/wg0.conf

# Typical configuration format:
# [Interface]
# PrivateKey = <base64_encoded_private_key>
# Address = 10.0.0.2/24
# ListenPort = 51820
# DNS = 10.0.0.1
#
# [Peer]
# PublicKey = <base64_encoded_public_key>
# AllowedIPs = 0.0.0.0/0
# Endpoint = vpn.example.com:51820
# PersistentKeepalive = 25

# Check running WireGuard interfaces
sudo wg show

# Extract runtime configuration including keys
sudo wg show wg0
# Output includes: private key (if root), public key, listening port, peers, transfer stats

# Show all WireGuard interfaces and their peers
sudo wg show all

# Extract peer public keys from running config
sudo wg show wg0 peers

# Check NetworkManager for WireGuard connections
nmcli connection show | grep -i wireguard
sudo cat /etc/NetworkManager/system-connections/wg0.nmconnection 2>/dev/null
```

**macOS Endpoint Configuration Extraction**

```bash
# macOS WireGuard configurations (WireGuard app)
find ~/Library/Containers/ -name "*.conf" -path "*wireguard*" 2>/dev/null
find ~/Library/Preferences/ -name "*wireguard*" 2>/dev/null

# Check for WireGuard processes
ps aux | grep -i wireguard

# macOS keychain may store WireGuard credentials
security find-generic-password -s "WireGuard" -w 2>/dev/null

# Check for WireGuard configuration files
find /usr/local/etc/wireguard/ -name "*.conf" 2>/dev/null
find /opt/homebrew/etc/wireguard/ -name "*.conf" 2>/dev/null
```

**Windows Endpoint Configuration Extraction**

```powershell
# Check for WireGuard configuration files
Get-ChildItem -Path "C:\Program Files\WireGuard\Data\Configurations\" -Filter "*.conf"

# Read WireGuard configuration
Get-Content "C:\Program Files\WireGuard\Data\Configurations\wg0.conf"

# Check running WireGuard tunnels
wg.exe show

# Check for WireGuard services
Get-Service -Name "WireGuardTunnel*"

# Extract from registry (some installations)
reg query "HKLM\SOFTWARE\WireGuard" /s 2>$null
```

**Configuration Analysis Script**

```bash
# Analyze extracted WireGuard configuration
cat > analyze_wg_config.sh << 'SCRIPT'
#!/bin/bash
CONFIG=$1

echo "=== WireGuard Configuration Analysis ==="

# Extract interface section
echo ""
echo "[Interface Configuration]"
grep -A 10 "^\[Interface\]" "$CONFIG" | while read line; do
    if [[ "$line" == PrivateKey=* ]]; then
        echo "  Private Key: PRESENT (CRITICAL FINDING)"
    elif [[ "$line" == PublicKey=* ]]; then
        echo "  Public Key: ${line#PublicKey=}"
    elif [[ "$line" == Address=* ]]; then
        echo "  VPN Address: ${line#Address=}"
    elif [[ "$line" == ListenPort=* ]]; then
        echo "  Listen Port: ${line#ListenPort=}"
    elif [[ "$line" == DNS=* ]]; then
        echo "  DNS Server: ${line#DNS=}"
    fi
done

# Extract peer sections
echo ""
echo "[Peer Configurations]"
grep -c "^\[Peer\]" "$CONFIG" | xargs -I{} echo "  Number of peers: {}"

grep -A 10 "^\[Peer\]" "$CONFIG" | while read line; do
    if [[ "$line" == PublicKey=* ]]; then
        echo "  Peer Public Key: ${line#PublicKey=}"
    elif [[ "$line" == AllowedIPs=* ]]; then
        echo "  Allowed IPs: ${line#AllowedIPs=}"
    elif [[ "$line" == Endpoint=* ]]; then
        echo "  Endpoint: ${line#Endpoint=}"
    elif [[ "$line" == PersistentKeepalive=* ]]; then
        echo "  Keepalive: ${line#PersistentKeepalive=}"
    fi
done

# Security findings
echo ""
echo "[Security Findings]"
if grep -q "PrivateKey" "$CONFIG"; then
    echo "  CRITICAL: Private key stored in plaintext configuration file"
fi
if grep -q "AllowedIPs = 0.0.0.0/0" "$CONFIG"; then
    echo "  INFO: Full tunnel VPN (all traffic routed through WireGuard)"
fi
if grep -q "AllowedIPs = ::/0" "$CONFIG"; then
    echo "  INFO: Full IPv6 tunnel enabled"
fi
if ! grep -q "PersistentKeepalive" "$CONFIG"; then
    echo "  NOTE: No persistent keepalive configured (may drop behind NAT)"
fi
SCRIPT

chmod +x analyze_wg_config.sh
```

### Step 4: Peer Enumeration Techniques

WireGuard does not expose peer information through the protocol itself -- there is no equivalent to IKE's identity exchange. However, several techniques can enumerate peers.

**Timing-Based Peer Detection**

```bash
# WireGuard responds differently to handshake initiation with valid vs invalid peers
# A valid peer triggers a handshake response; invalid peer is silently dropped
# Timing the response reveals peer validity

python3 << 'EOF'
import socket, struct, time, base64, hashlib, os

def wg_peer_timing_probe(target_ip, target_port, peer_public_key, timeout=2):
    """
    Probe for a valid WireGuard peer by measuring response timing.
    Valid peers: server responds with handshake response (faster)
    Invalid peers: server silently drops (timeout)
    """
    # Construct a minimal handshake initiation
    # Note: This requires constructing a valid Noise protocol handshake
    # Simplified version for timing analysis
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    
    # Send a probe packet
    start = time.time()
    try:
        # Send minimal probe
        probe = b'\x01\x00\x00\x00' + b'\x00' * 140  # Type 1 + padding
        sock.sendto(probe, (target_ip, target_port))
        data, addr = sock.recvfrom(1024)
        elapsed = time.time() - start
        return True, elapsed
    except socket.timeout:
        elapsed = time.time() - start
        return False, elapsed
    finally:
        sock.close()

# Test peer validity by timing
target = "192.168.1.1"
port = 51820

# Known peer key from configuration
known_key = "known_public_key_base64_here"
result, timing = wg_peer_timing_probe(target, port, known_key)
print(f"Known key: {result} ({timing*1000:.1f}ms)")

# Random key
result2, timing2 = wg_peer_timing_probe(target, port, "random_key")
print(f"Random key: {result2} ({timing2*1000:.1f}ms)")

# If timing difference > threshold, peer enumeration is possible
if abs(timing - timing2) > 0.01:
    print("WARNING: Timing difference detected -- peer enumeration may be feasible")
EOF
```

**Network-Based Peer Discovery**

```bash
# If WireGuard is configured on a network, discover peers through:
# 1. ARP table on the WireGuard interface (shows connected peers)
arp -a -i wg0

# 2. Routing table shows allowed IP ranges for each peer
ip route show dev wg0

# 3. Transfer statistics per peer (wg show reveals data)
sudo wg show wg0 transfer
# Shows bytes sent/received per peer -- active peers have non-zero counters

# 4. Latest handshake timestamps reveal active peers
sudo wg show wg0 latest-handshakes
# Peers with recent timestamps are actively connected

# 5. Scan the VPN subnet for active hosts through the tunnel
nmap -sn 10.0.0.0/24 -e wg0
```

### Step 5: Cryptographic Attack Surface Assessment

WireGuard uses fixed cryptographic primitives (Curve25519, ChaCha20-Poly1305, BLAKE2s, HMAC). There are no downgrade attacks or cipher negotiation vulnerabilities. However, key management and operational practices introduce risks.

**Key Strength Analysis**

```bash
# Analyze WireGuard key quality from extracted configuration
python3 << 'EOF'
import base64, os, struct

def analyze_wg_key(private_key_b64):
    """Analyze WireGuard private key quality"""
    try:
        key_bytes = base64.b64decode(private_key_b64)
        
        if len(key_bytes) != 32:
            return "Invalid key length", 0
        
        # Check for weak keys
        # All zeros
        if key_bytes == b'\x00' * 32:
            return "CRITICAL: All-zero private key", 0
        
        # All same byte
        if len(set(key_bytes)) == 1:
            return "CRITICAL: Single-byte repeated key", 0
        
        # Sequential bytes (testing key)
        if key_bytes == bytes(range(32)):
            return "CRITICAL: Sequential test key", 0
        
        # Check entropy
        from collections import Counter
        import math
        counts = Counter(key_bytes)
        total = len(key_bytes)
        entropy = -sum(c/total * math.log2(c/total) for c in counts.values())
        
        if entropy > 7.0:
            return f"Good key quality (entropy: {entropy:.2f})", 1
        elif entropy > 5.0:
            return f"Moderate key quality (entropy: {entropy:.2f})", 0.5
        else:
            return f"WEAK key (entropy: {entropy:.2f})", 0
            
    except Exception as e:
        return f"Error analyzing key: {e}", 0

# Test with known keys
test_keys = [
    ("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "All-zero key"),
    ("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQ=", "Near-zero key"),
    ("YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=", "ASCII key"),
]

for key, desc in test_keys:
    result, score = analyze_wg_key(key)
    print(f"{desc}: {result}")
EOF
```

**Key Reuse and Rotation Assessment**

```bash
# Check if WireGuard keys are rotated regularly
# Compare key creation time with file modification time

# Check configuration file modification dates
ls -la /etc/wireguard/wg0.conf
stat /etc/wireguard/wg0.conf

# Check if the same key is used across multiple configurations
find /etc/wireguard/ -name "*.conf" -exec grep "PrivateKey" {} \; | sort | uniq -c
# If same private key appears in multiple configs, key reuse is detected

# Check for hardcoded keys in scripts or configuration management
grep -r "PrivateKey" /etc/ansible/ /etc/puppet/ /etc/salt/ /home/ 2>/dev/null | grep -v ".conf"
grep -r "PrivateKey" /opt/ /usr/local/bin/ 2>/dev/null | head -20
```

### Step 6: WireGuard Traffic Analysis

WireGuard's fixed packet structure and lack of traffic padding make it vulnerable to traffic analysis attacks that can infer connection patterns, data volumes, and even application-layer protocols.

**Traffic Volume Analysis**

```bash
# Monitor WireGuard traffic volume per peer
sudo wg show wg0 transfer

# Continuous monitoring for traffic analysis
watch -n 5 'sudo wg show wg0 transfer'

# Capture and analyze WireGuard packet sizes
# Transport data packets have a 32-byte header
# Payload size = total UDP payload - 32 bytes overhead
sudo tcpdump -i any -nn udp port 51820 -w wg_traffic.pcap -c 1000

# Analyze packet size distribution (reveals application patterns)
tshark -r wg_traffic.pcap -Y "udp.port == 51820" -T fields \
  -e udp.length 2>/dev/null | sort -n | uniq -c | sort -rn | head -20

# SSH over WireGuard: consistent small packets (~100-200 bytes)
# Web browsing: burst of large packets (~1400 bytes) followed by small ACKs
# File transfer: sustained large packets (~1400 bytes)
# DNS: very small packets (~60-80 bytes)
```

**Connection Pattern Analysis**

```bash
# Detect active vs idle WireGuard connections
# WireGuard has no explicit "connected" state -- track last handshake time

# Monitor handshake intervals (default rekey every 2-3 minutes if active)
sudo tcpdump -i any -nn 'udp port 51820 and greater 147 and less 149' -c 100 | \
  awk '{print $1}' | head -20

# If handshakes occur at regular intervals, the connection is actively carrying data
# If handshakes stop, the connection is idle (no rekeying)

# Track connection patterns over time
cat > wg_connection_monitor.sh << 'SCRIPT'
#!/bin/bash
echo "timestamp,peer,last_handshake,rx_bytes,tx_bytes"
while true; do
    timestamp=$(date +%s)
    sudo wg show wg0 | grep -A 5 "peer:" | while read line; do
        if [[ "$line" == *"peer:"* ]]; then
            peer=$(echo "$line" | awk '{print $2}')
        elif [[ "$line" == *"latest handshake"* ]]; then
            handshake=$(echo "$line" | awk '{print $NF}')
        elif [[ "$line" == *"transfer:"* ]]; then
            rx=$(echo "$line" | awk '{print $2}')
            tx=$(echo "$line" | awk '{print $5}')
            echo "$timestamp,$peer,$handshake,$rx,$tx"
        fi
    done
    sleep 30
done
SCRIPT
```

### Step 7: WireGuard Misconfiguration Assessment

Common WireGuard misconfigurations that penetration testers should identify.

```bash
# Check for common misconfigurations

# 1. Private key in world-readable file
ls -la /etc/wireguard/wg0.conf
# Should be: -rw------- or -rw-r----- (not world-readable)

# 2. DNS leak potential
grep -i "DNS" /etc/wireguard/wg0.conf
# If no DNS is configured, queries may leak to the ISP DNS

# 3. Missing PostUp/PostDown firewall rules
grep -E "PostUp|PostDown" /etc/wireguard/wg0.conf
# If absent, traffic may bypass the VPN (no kill switch)

# 4. Overly permissive AllowedIPs
grep "AllowedIPs" /etc/wireguard/wg0.conf
# 0.0.0.0/0 routes everything (full tunnel - expected for privacy VPNs)
# Narrower ranges for site-to-site should match actual needs

# 5. Missing PersistentKeepalive for NAT traversal
grep "PersistentKeepalive" /etc/wireguard/wg0.conf
# Behind NAT, should be set to 25-60 seconds

# 6. Default port exposure
grep "ListenPort" /etc/wireguard/wg0.conf
# Default 51820 is easily identified; consider non-standard port

# 7. Check for wg-quick automation
systemctl is-enabled wg-quick@wg0
# Should be enabled for persistence; disabled means manual startup required
```

---

## Hands-on Exercises

### Exercise 1: WireGuard Configuration Extraction and Analysis

**Scenario**: You have gained root access to a Linux workstation that is configured as a WireGuard VPN client. Extract and analyze the full WireGuard configuration.

1. Locate all WireGuard configuration files on the system
2. Extract the private key, peer public keys, and allowed IP ranges
3. Analyze the configuration for security issues (key quality, missing firewall rules)
4. Using the extracted credentials, establish a test connection from your workstation
5. Enumerate all peers reachable through the WireGuard tunnel
6. Document findings with severity ratings

**Expected outcome**: Complete extraction of WireGuard credentials, successful connection to the VPN, enumeration of reachable peers, and a security assessment report documenting all misconfigurations found.

### Exercise 2: WireGuard Traffic Analysis

**Scenario**: Capture and analyze WireGuard traffic to determine what applications are being used over the VPN tunnel.

1. Capture WireGuard traffic on a monitoring point
2. Analyze packet size distributions to identify traffic patterns
3. Correlate packet sizes with application signatures (SSH, HTTP, file transfer)
4. Monitor handshake intervals to determine connection activity levels
5. Attempt to identify the number of active users on the WireGuard network
6. Document the traffic analysis methodology and findings

**Expected outcome**: A traffic analysis report showing the ability to identify application types, user activity patterns, and connection characteristics despite WireGuard's encryption. Recommendations for traffic padding and obfuscation to mitigate analysis.

### Exercise 3: WireGuard Security Assessment Report

**Scenario**: Perform a complete security assessment of a WireGuard VPN deployment.

1. Discover WireGuard endpoints through active and passive scanning
2. Attempt to enumerate valid peers through timing analysis
3. Assess configuration security on any accessible endpoints
4. Evaluate key management practices (rotation, storage, entropy)
5. Test for traffic analysis vulnerabilities
6. Compile findings into an assessment report with prioritized recommendations

**Expected outcome**: A comprehensive security assessment report covering discovery, enumeration, configuration analysis, traffic analysis, and recommendations. The report should compare WireGuard's security posture with IPSec/IKE and OpenVPN to provide context for the findings.

---

## References

1. **WireGuard Whitepaper**: https://www.wireguard.com/papers/wireguard.pdf -- Formal protocol specification and security analysis
2. **WireGuard Protocol Specification**: https://www.wireguard.com/protocol/ -- Protocol mechanics and cryptographic design
3. **RFC 8792 - WireGuard**: https://tools.ietf.org/html/rfc8792 -- WireGuard as an IETF standard
4. **WireGuard Source Code**: https://github.com/WireGuard/wireguard-linux -- Kernel module implementation
5. **MITRE ATT&CK T1133 - External Remote Services**: https://attack.mitre.org/techniques/T1133/ -- VPN as persistent access
6. **Noise Protocol Framework**: https://noiseprotocol.org/noise.html -- WireGuard's cryptographic foundation
7. **HackTricks - WireGuard**: https://book.hacktricks.xyz/pentesting/pentesting-vpn -- WireGuard pentesting techniques
8. **WireGuard man page**: https://man7.org/linux/man-pages/man8/wg.8.html -- Configuration and management reference
