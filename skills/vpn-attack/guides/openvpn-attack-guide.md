# OpenVPN Attack Guide

> Comprehensive guide to OpenVPN security assessment covering protocol analysis, certificate and PKI auditing, compression-based attacks (VORACLE), TLS downgrade testing, configuration exploitation, and post-connection assessment of OpenVPN deployments.

## Introduction

OpenVPN is one of the most widely deployed VPN protocols in both enterprise and consumer applications. Its flexibility -- supporting TCP or UDP transport, a wide range of cryptographic algorithms, multiple authentication methods, and extensive configuration options -- makes it both powerful and complex. This complexity creates a broader attack surface compared to minimalist protocols like WireGuard, with vulnerabilities spanning the TLS handshake, data channel encryption, authentication mechanisms, and configuration parsing.

OpenVPN's architecture consists of a control channel (TLS-encrypted management session) and a data channel (separate encryption for VPN traffic). Both channels have distinct attack surfaces: the control channel is vulnerable to TLS-level attacks (downgrade, certificate forgery), while the data channel can be attacked through compression oracles, key renegotiation manipulation, and traffic analysis. The authentication layer adds further attack vectors through static key mode, PKI certificate management, and credential-based authentication.

The attack surface varies significantly based on the OpenVPN version and configuration. Older deployments using TLS 1.0 with compression enabled are vulnerable to VORACLE-style compression attacks. Misconfigured PKI deployments with weak certificate authorities or poor revocation checking enable certificate forgery. Static key mode deployments lack perfect forward secrecy entirely. This guide covers each attack vector systematically with practical assessment techniques.

**Learning objectives**:

- Understand OpenVPN protocol architecture (control channel vs data channel)
- Extract and analyze OpenVPN configurations and certificates
- Test for TLS downgrade and weak cipher suite acceptance
- Assess PKI deployment security (CA management, certificate revocation)
- Exploit compression oracles in vulnerable OpenVPN configurations
- Perform post-connection assessment of VPN routing and access controls
- Identify and document misconfigurations in OpenVPN deployments

**Prerequisites**: Familiarity with VPN fundamentals and PKI concepts. Experience with OpenSSL for certificate management. Understanding of TLS protocol basics. Access to a test OpenVPN deployment.

---

## Practical Steps

### Step 1: OpenVPN Service Discovery and Fingerprinting

OpenVPN can run on TCP or UDP, on standard ports (1194, 443) or custom ports. Identifying the OpenVPN service is the first step in assessment.

**Active Service Detection**

```bash
# Standard OpenVPN port scan (UDP 1194 is default)
sudo nmap -sU -p 1194 --openvpn target_network/24

# Check for OpenVPN on common alternate ports
sudo nmap -sS -sU -p 1194,443,4433,943,8443 target

# OpenVPN UDP service detection
sudo nmap -sU -p 1194 --script=openvpn-info target

# Manual OpenVPN probe
# OpenVPN control channel starts with a P_CONTROL_HARD_RESET message
# First byte: 'P' or specific opcode
echo -ne '\x38' | nc -u -w3 target 1194
# OpenVPN responds to valid reset packets

# OpenVPN version detection via TLS handshake
# Connect and examine the TLS certificate
openssl s_client -connect target:1194 </dev/null 2>/dev/null | \
  openssl x509 -noout -subject -issuer -dates
```

**Passive Traffic Analysis**

```bash
# Capture and identify OpenVPN traffic
# OpenVPN over UDP: detect by P_CONTROL packet headers
sudo tcpdump -i any -nn udp port 1194 -w openvpn_udp.pcap

# OpenVPN over TCP: detect by initial TLS handshake on non-HTTPS port
sudo tcpdump -i any -nn tcp port 1194 or \(tcp port 443 and 'tcp[((tcp[12:1] & 0xf0) >> 2):4] != 0x47455420 and tcp[((tcp[12:1] & 0xf0) >> 2):4] != 0x504f5354'\) -w openvpn_tcp.pcap

# Identify OpenVPN packet types
# Opcode in first byte (high 5 bits):
# 1 = P_CONTROL_HARD_RESET_CLIENT_V1
# 2 = P_CONTROL_HARD_RESET_SERVER_V1
# 7 = P_CONTROL_HARD_RESET_CLIENT_V2
# 8 = P_CONTROL_HARD_RESET_SERVER_V2
# 9 = P_CONTROL_SOFT_RESET_V1
# 4 = P_CONTROL_V1

tshark -r openvpn_udp.pcap -Y "udp.port == 1194" -T fields \
  -e data.data 2>/dev/null | head -20 | while read hex; do
    opcode=$(( 16#${hex:0:2} >> 3 ))
    case $opcode in
      1) echo "P_CONTROL_HARD_RESET_CLIENT_V1" ;;
      2) echo "P_CONTROL_HARD_RESET_SERVER_V1" ;;
      7) echo "P_CONTROL_HARD_RESET_CLIENT_V2" ;;
      8) echo "P_CONTROL_HARD_RESET_SERVER_V2" ;;
      4) echo "P_CONTROL_V1 (control message)" ;;
      6) echo "P_ACK_V1 (acknowledgment)" ;;
      *) echo "Opcode: $opcode" ;;
    esac
  done
```

### Step 2: Configuration Extraction and Analysis

OpenVPN configurations reveal the authentication method, cipher suite, certificate paths, and network topology.

**Client Configuration Analysis**

```bash
# Locate OpenVPN configuration files
find /etc/openvpn/ -name "*.conf" -o -name "*.ovpn" 2>/dev/null
find /home/ -name "*.ovpn" 2>/dev/null
find /tmp/ -name "*.ovpn" -o -name "*.conf" 2>/dev/null

# Read OpenVPN client configuration
cat /etc/openvpn/client/client.conf

# Key configuration parameters to analyze:
# proto udp|tcp          -- Transport protocol
# remote <host> <port>   -- VPN server endpoint
# dev tun|tap            -- Tunnel mode
# ca <file>              -- CA certificate
# cert <file>            -- Client certificate
# key <file>             -- Client private key
# auth-user-pass         -- Credential authentication
# cipher <name>          -- Data channel cipher
# auth <name>            -- HMAC authentication
# tls-cipher <list>      -- Control channel TLS cipher
# comp-lzo|compress      -- Compression (potential VORACLE)
# keysize <bits>         -- Key size for BF/CAST ciphers
# remote-cert-tls server -- Server certificate verification

# Extract embedded certificates from .ovpn files
# Many .ovpn files contain inline certificates between <ca>, <cert>, <key> tags
awk '/<ca>/,/<\/ca>/' client.ovpn > ca.crt
awk '/<cert>/,/<\/cert>/' client.ovpn > client.crt
awk '/<key>/,/<\/key>/' client.ovpn > client.key
awk '/<tls-auth>/,/<\/tls-auth>/' client.ovpn > tls-auth.key
```

**Server Configuration Analysis**

```bash
# If server access is obtained during assessment
sudo cat /etc/openvpn/server/server.conf

# Critical server parameters:
# mode server            -- Server mode
# tls-server             -- TLS server role
# dh <file>              -- Diffie-Hellman parameters
# server <ip> <mask>     -- VPN subnet assignment
# push "route <net>"     -- Routes pushed to clients
# client-to-client       -- Allow inter-client communication
# duplicate-cn           -- Allow same cert on multiple connections
# ccd-exclusive          -- Require client config directory entry
# verify-client-cert     -- Client certificate verification level
# username-as-common-name -- Use auth username as CN
# plugin /usr/lib/openvpn/openvpn-plugin-auth-pam.so -- PAM auth plugin

# Check for dangerous configurations:
grep -E "duplicate-cn|client-to-client|comp-lzo|compress" /etc/openvpn/server/server.conf

# Check DH parameters strength
openssl dhparam -in /etc/openvpn/server/dh.pem -text -noout | head -5
# Look for "DH Parameters: (2048 bit)" or higher
# 1024-bit DH is weak and vulnerable to Logjam
```

### Step 3: Certificate and PKI Assessment

OpenVPN's PKI deployment is a critical attack surface. Weak CAs, expired certificates, and missing revocation checks can undermine the entire VPN security model.

**Certificate Chain Analysis**

```bash
# Analyze the VPN server certificate
openssl s_client -connect target:1194 </dev/null 2>/dev/null | \
  openssl x509 -noout -text | head -30

# Extract complete certificate chain
openssl s_client -showcerts -connect target:1194 </dev/null 2>/dev/null | \
  awk '/BEGIN CERT/,/END CERT/' | csplit -z -f /tmp/cert- - '/-----BEGIN/' '{*}'

# Analyze each certificate in the chain
for cert in /tmp/cert-*; do
  echo "=== Certificate ==="
  openssl x509 -noout -subject -issuer -dates -serial -in "$cert" 2>/dev/null
  openssl x509 -noout -text -in "$cert" 2>/dev/null | grep -A 2 "Signature Algorithm"
  echo ""
done

# Check for weak signing algorithms
openssl s_client -connect target:1194 </dev/null 2>/dev/null | \
  openssl x509 -noout -text | grep "Signature Algorithm"
# SHA-256 or better: OK
# SHA-1: Weak (deprecated)
# MD5: CRITICAL (broken)
```

**Certificate Validation Testing**

```bash
# Test if server accepts self-signed certificates
# Generate a forged client certificate
openssl req -newkey rsa:2048 -nodes -keyout forged.key \
  -out forged.csr -subj "/CN=vpn-client"

# Self-sign (NOT signed by the real CA)
openssl x509 -req -in forged.csr -signkey forged.key \
  -out forged.crt -days 365

# Test connection with forged certificate
sudo openvpn --config client.ovpn \
  --cert forged.crt \
  --key forged.key \
  --verb 4 2>&1 | grep -i "certificate\|verify\|auth\|error"

# If connection succeeds, certificate validation is disabled (CRITICAL finding)

# Test if server validates certificate revocation
# Revoke a known client cert (if we have CA access for testing)
openssl ca -revoke compromised_client.crt -config openssl.cnf
openssl ca -gencrl -config openssl.cnf -out crl.pem

# Test if revoked cert is still accepted
sudo openvpn --config client.ovpn --verb 4 2>&1 | grep -i "revoked\|crl"
```

**CA Key Strength Assessment**

```bash
# Analyze the CA certificate strength
openssl x509 -in ca.crt -text -noout | grep -A 2 "Public-Key"
# RSA 2048+: OK
# RSA 1024: Weak (factorable)
# ECDSA 256+: OK

# Check CA certificate expiration
openssl x509 -in ca.crt -checkend 0 -noout
openssl x509 -in ca.crt -noout -enddate

# Check if CA has pathlen constraint (limits intermediate CAs)
openssl x509 -in ca.crt -text -noout | grep -A 2 "Basic Constraints"
# pathlen:0 means no intermediate CAs allowed
# Missing pathlen means unlimited intermediate CAs (less secure)

# Verify certificate serial numbers are random (not sequential)
openssl x509 -in ca.crt -serial -noout
# Sequential serials indicate outdated CA management
```

### Step 4: TLS Downgrade and Weak Cipher Testing

OpenVPN's control channel uses TLS, and the data channel uses a separate encryption layer. Both should be tested for weak cipher acceptance.

**Control Channel TLS Assessment**

```bash
# Test supported TLS versions on the OpenVPN server
for proto in tls1 tls1_1 tls1_2 tls1_3; do
  result=$(openssl s_client -connect target:1194 -$proto </dev/null 2>&1 | \
    grep -E "Protocol|Cipher|error|alert")
  echo "$proto: $result"
done

# Test for TLS 1.0/1.1 acceptance (should be disabled)
# TLS 1.0 and 1.1 are deprecated and vulnerable to BEAST/POODLE
openssl s_client -connect target:1194 -tls1 </dev/null 2>&1 | \
  grep -E "Protocol|Cipher"
# If Protocol: TLSv1 is accepted, this is a HIGH finding

# Test cipher suite acceptance
nmap --script ssl-enum-ciphers -p 1194 target
# Look for: weak ciphers (RC4, DES, 3DES), short key lengths (<128 bit)

# Manual cipher testing
for cipher in AES256-SHA AES128-SHA RC4-SHA DES-CBC3-SHA; do
  result=$(openssl s_client -connect target:1194 -cipher $cipher </dev/null 2>&1 | \
    grep -E "Cipher|error")
  echo "$cipher: $result"
done
```

**Data Channel Cipher Assessment**

```bash
# Check configured data channel cipher
grep -i "cipher" /etc/openvpn/server/server.conf

# Common ciphers and their security status:
# AES-256-GCM   -- Excellent (default for OpenVPN 2.4+)
# AES-128-GCM   -- Good
# AES-256-CBC   -- Good (older but secure)
# AES-128-CBC   -- Acceptable
# BF-CBC        -- WEAK (Blowfish, 64-bit block, Sweet32)
# DES-CBC       -- CRITICAL (56-bit, broken)
# RC4           -- CRITICAL (broken)

# Test if the server accepts weak data channel ciphers
sudo openvpn --config client.ovpn \
  --cipher DES-CBC \
  --verb 4 2>&1 | grep -i "cipher\|error\|option"

sudo openvpn --config client.ovpn \
  --cipher BF-CBC \
  --verb 4 2>&1 | grep -i "cipher\|error\"

# Test HMAC authentication algorithm
grep -i "^auth " /etc/openvpn/server/server.conf
# SHA256+: OK
# SHA1: Acceptable (not yet broken for HMAC)
# MD5: Weak (collision-prone)
```

### Step 5: Compression Attack (VORACLE)

OpenVPN versions that support compression are vulnerable to the VORACLE attack, which exploits the BREACH/CRIME-style compression oracle to decrypt VPN traffic.

**Vulnerability Detection**

```bash
# Check if compression is enabled on the server
grep -E "comp-lzo|compress" /etc/openvpn/server/server.conf

# comp-lzo = VULNERABLE (LZO compression)
# compress = VULNERABLE (compress with any algorithm)
# compress lz4 = VULNERABLE (LZ4 compression)
# No compression directive = Not vulnerable (if OpenVPN 2.4+)

# Check OpenVPN version (2.4+ has compression disabled by default)
openvpn --version | head -1

# Test if client can enable compression
sudo openvpn --config client.ovpn --comp-lzo yes --verb 4 2>&1 | \
  grep -i "compress\|lzo\|error"

# Capture and detect compression in traffic
sudo tcpdump -i any -nn udp port 1194 -c 100 -w compressed.pcap
# Compressed packets have different size distribution than uncompressed
tshark -r compressed.pcap -Y "udp.port == 1194" -T fields -e udp.length | \
  sort -n | uniq -c | sort -rn | head
```

**VORACLE Attack Conceptual Demonstration**

```bash
# VORACLE exploits compression to decrypt VPN traffic
# When compression is enabled, repeated patterns in plaintext compress well
# An attacker who can inject traffic into the VPN tunnel can observe
# compression ratio changes to infer the content of encrypted traffic

# Conceptual test (requires specific lab setup):
# 1. Start OpenVPN with compression enabled
# 2. Inject known plaintext patterns into the VPN tunnel
# 3. Observe packet size changes (compression efficiency varies)
# 4. Correlate size changes with plaintext patterns

# Detection in packet captures:
# Measure packet sizes with and without injected patterns
python3 << 'EOF'
# Simplified compression oracle analysis
# Compares packet sizes to detect compression side-channels

import struct

def analyze_compression_oracle(pcap_file):
    """
    Analyze packet sizes in a capture to detect compression side-channel.
    If packet sizes vary inversely with injected pattern length,
    compression is active and the oracle is present.
    """
    # In practice, use dpkt or scapy to read the pcap
    # This is a conceptual framework
    
    print("Compression Oracle Analysis:")
    print("1. Send baseline request through VPN tunnel -> record packet size")
    print("2. Inject pattern 'SecretPrefix' + known padding -> record size")
    print("3. Inject pattern 'WrongPrefix' + known padding -> record size")
    print("4. If sizes differ, compression reveals which prefix matches")
    print("")
    print("Mitigation: Disable compression on OpenVPN server")
    print("  Add 'compress migrate' to server config (allows clients to upgrade)")
    print("  Or remove all compression directives")

analyze_compression_oracle("compressed.pcap")
EOF
```

### Step 6: Static Key Mode Assessment

OpenVPN static key mode (pre-shared key without TLS) lacks perfect forward secrecy and has a simplified handshake that is easier to attack.

```bash
# Detect static key mode configuration
grep -i "secret" /etc/openvpn/server/server.conf
grep -i "secret" /etc/openvpn/client/client.conf

# Static key mode characteristics:
# - No TLS handshake, no certificates
# - Single pre-shared key for both directions
# - No perfect forward secrecy
# - Key is used for both control and data channel
# - Simpler but less secure than TLS mode

# Test static key connection
sudo openvpn --remote target --dev tun \
  --ifconfig 10.8.0.2 10.8.0.1 \
  --secret static.key \
  --cipher AES-256-CBC \
  --verb 4

# Static key vulnerabilities:
# 1. Key compromise exposes ALL past and future traffic (no PFS)
# 2. Key must be distributed to all clients (distribution risk)
# 3. No authentication beyond key possession
# 4. Both directions use same key (no key separation)
# 5. No replay protection in older versions
```

### Step 7: Post-Connection Assessment

After establishing an OpenVPN connection, assess the network access controls and routing configuration.

```bash
# After connecting to OpenVPN:

# Check assigned IP and routes
ip addr show tun0
ip route show

# Check pushed routes and options
sudo openvpn --config client.ovpn --verb 4 2>&1 | grep "PUSH"

# Test routing and access controls
# 1. Can we reach other VPN clients? (client-to-client)
ping 10.8.0.1  # VPN gateway
nmap -sn 10.8.0.0/24  # Other VPN clients

# 2. Can we reach internal networks through the VPN?
nmap -sn 192.168.0.0/24  # Internal network
nmap -sn 172.16.0.0/24   # DMZ network

# 3. Is traffic restricted by firewall rules?
# Test common ports on internal hosts
nmap -sT -Pn 192.168.0.1 -p 22,80,443,3306,3389,8080

# 4. DNS configuration
cat /etc/resolv.conf
dig @10.8.0.1 internal.corp.local
# Test for DNS leaks
dig @8.8.8.8 myip.opendns.com

# 5. Internet access through VPN
curl -s https://ifconfig.me
# Compare with VPN interface IP
ip addr show tun0 | grep inet

# 6. MTU and fragmentation testing
ping -M do -s 1400 192.168.0.1
ping -M do -s 1500 192.168.0.1  # Test for MTU issues

# 7. Check for split tunneling
ip route | grep -v tun0 | grep -v "169.254" | grep -v "127.0.0"
# Non-VPN routes indicate split tunneling
```

---

## Hands-on Exercises

### Exercise 1: OpenVPN Certificate Chain Audit

**Scenario**: You have obtained an OpenVPN client configuration (.ovpn file) from a compromised endpoint. Perform a complete PKI audit.

1. Extract all certificates from the .ovpn file (CA, client cert, client key, TLS auth)
2. Analyze the CA certificate for strength (algorithm, key size, validity period)
3. Check the client certificate for proper CN and extended key usage
4. Test if the server accepts a self-signed certificate (forged cert test)
5. Verify certificate revocation checking is enabled
6. Document all PKI-related findings with severity ratings

**Expected outcome**: A complete PKI audit report documenting certificate chain strength, validation enforcement, revocation checking, and any vulnerabilities that allow certificate forgery or replay.

### Exercise 2: TLS and Cipher Suite Assessment

**Scenario**: Assess the TLS configuration of an OpenVPN server for protocol downgrade and weak cipher acceptance.

1. Enumerate all accepted TLS protocol versions (TLS 1.0 through 1.3)
2. Enumerate all accepted cipher suites for the control channel
3. Test data channel cipher acceptance (try DES, BF-CBC, RC4)
4. Assess HMAC algorithm strength
5. Check for perfect forward secrecy support
6. Compare findings against current NIST/PCI-DSS requirements

**Expected outcome**: A comprehensive cipher suite assessment with a prioritized list of findings. Identification of any deprecated or broken cryptographic algorithms in use. Specific configuration changes recommended to achieve compliance.

### Exercise 3: Full OpenVPN Deployment Assessment

**Scenario**: Perform a complete security assessment of an OpenVPN deployment from both client and server perspectives.

1. Discover and fingerprint the OpenVPN service
2. Extract and analyze client configuration from a compromised endpoint
3. Audit the PKI deployment (CA, certificates, revocation)
4. Test for TLS downgrade and weak cipher acceptance
5. Assess compression settings for VORACLE vulnerability
6. Establish a connection and assess post-connection access controls
7. Test for split tunneling and DNS leaks
8. Compile all findings into a professional assessment report

**Expected outcome**: A complete OpenVPN security assessment report covering discovery, configuration analysis, PKI audit, cryptographic assessment, compression analysis, and post-connection testing. The report should include prioritized recommendations organized by severity.

---

## References

1. **OpenVPN Documentation**: https://openvpn.net/community-resources/documentation/ -- Official configuration and deployment guide
2. **OpenVPN Security Advisory**: https://openvpn.net/security-advisories/ -- Known vulnerabilities and patches
3. **VORACLE Attack Paper**: https://forcepoint.com/sites/default/files/resources/files/report-voracle-attack-vpn.pdf -- Compression oracle attack on OpenVPN
4. **NIST SP 800-113 - Guide to SSL VPNs**: https://csrc.nist.gov/publications/detail/sp/800-113/final -- VPN security guidelines
5. **OpenVPN Source Code**: https://github.com/OpenVPN/openvpn -- Protocol implementation reference
6. **MITRE ATT&CK T1133 - External Remote Services**: https://attack.mitre.org/techniques/T1133/ -- VPN as persistent access mechanism
7. **HackTricks - OpenVPN Pentest**: https://book.hacktricks.xyz/pentesting/pentesting-vpn -- OpenVPN testing techniques
8. **CVE Details - OpenVPN**: https://www.cvedetails.com/vulnerability-list/vendor_id-121/Openvpn.html -- OpenVPN CVE history
