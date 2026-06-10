# SIP Device Reconnaissance

> Guide covering SIP device discovery, extension enumeration, password cracking, and server probing techniques.

## Overview

SIP device reconnaissance is the foundational phase of any VoIP penetration test. Before attacking VoIP infrastructure, you must identify all SIP-capable devices on the network, determine the PBX type and version, enumerate valid extensions, and test authentication strength. This guide covers the complete reconnaissance workflow using svmap, svwar, svcrack, and sipsak.

---

## Network Discovery

### Identifying VoIP Infrastructure

Before using SIP-specific tools, perform general network reconnaissance to map the VoIP infrastructure.

Use nmap with UDP scanning to locate SIP services. SIP commonly listens on UDP port 5060 (plaintext) or 5061 (TLS). The IAX2 protocol uses UDP 4569 on Asterisk servers. RTP media streams use a dynamic port range, typically 10000-20000 on many PBX systems.

```bash
# Quick scan for SIP and IAX2 services
nmap -sU -p 5060,5061,4569 10.0.0.0/24 --open

# Version detection on discovered SIP hosts
nmap -sU -sV -p 5060 10.0.0.1
```

If the target uses a dedicated voice VLAN, you must first gain access to that VLAN (see the VLAN Hopping guide) before SIP scanning will yield results.

---

## Scanning with svmap

### Basic Network Scan

`svmap` is the SIP device scanner from the SIPVicious toolkit. It sends SIP OPTIONS requests to each IP in the target range and identifies devices that respond with SIP headers.

```bash
# Scan a full subnet
svmap 10.0.0.0/24

# Scan a specific IP range
svmap 10.0.1.100-10.0.1.200
```

### Interpreting svmap Results

svmap reports each responding SIP device along with its User-Agent header. This header reveals the device type and often the firmware version:

- `Asterisk PBX X.Y.Z` — Asterisk open-source PBX
- `Cisco/CCM7.0` — Cisco Unified Communications Manager
- `FPBX-2.11.0` — FreePBX (Asterisk-based)
- `Grandstream HT503` — Grandstream ATA adapter
- `Linphone/3.6.1` — Linphone softphone

The User-Agent header is your primary fingerprinting vector. Record all discovered devices with their types for the next enumeration phase.

### Scan Tuning

```bash
# Scan with verbose output
svmap --verbose 10.0.0.0/24

# Scan from a specific source port
svmap -p 5080 10.0.0.0/24
```

Note that aggressive scanning can trigger intrusion detection systems. Use rate limiting and consider scanning during off-hours if stealth is a concern.

---

## Extension Enumeration with svwar

### Understanding SIP Extension Enumeration

Once you identify a SIP server (PBX or proxy), the next step is determining which extension numbers are valid. SIP extensions function like phone numbers internal to the PBX. Extensions that exist will respond differently than non-existent ones, even without authentication.

`svwar` automates this by probing each extension number and analyzing the SIP response codes:

- **200 OK** — Extension exists and may not require authentication (critical finding)
- **401 Unauthorized** — Extension exists but requires authentication
- **403 Forbidden** — Extension exists but access is denied
- **404 Not Found** — Extension does not exist

### Running svwar

```bash
# Enumerate standard 3-digit extensions
svwar -e 100-999 10.0.0.1

# Enumerate 4-digit extensions with OPTIONS method
svwar -m OPTIONS -e 1000-1999 10.0.0.1

# Enumerate with rate limiting (1 request per second)
svwar -e 100-999 -r 1 10.0.0.1

# Enumerate with custom SIP domain
svwar -e 100-999 -d target.lab 10.0.0.1
```

### Choosing Extension Ranges

Common extension numbering patterns vary by organization. Useful ranges to test:

- 100-999 — Small deployments
- 1000-1999 — Medium deployments (first department/floor)
- 2000-3999 — Medium to large deployments
- 10000-19999 — Large enterprise deployments

Start broad and narrow down based on initial results. If you discover extensions in the 1000-1099 range, there may be more in the 1100-1999 range.

---

## Password Cracking with svcrack

### Attacking Authenticated Extensions

Extensions that require SIP digest authentication (401 response) can be attacked using `svcrack`. This tool performs dictionary or brute-force attacks against the SIP digest authentication mechanism.

```bash
# Dictionary attack with common wordlist
svcrack -u 100 -d /usr/share/wordlists/rockyou.txt 10.0.0.1

# Attack with custom wordlist and domain
svcrack -u 100 -d custom_wordlist.txt -D target.lab 10.0.0.1

# Rate-limited attack to avoid detection
svcrack -u 100 -d wordlist.txt -r 2 10.0.0.1
```

### Testing Default Credentials

Before running dictionary attacks, always test common default credential pairs. Many PBX deployments ship with default passwords that are never changed:

- Extension number as both username and password (100/100, 1000/1000)
- `admin`/`admin`, `operator`/`operator`
- Vendor defaults (e.g., Cisco `cisco`/`cisco`, Polycom `456` as admin password)

```bash
# Quick default credential test with sipsak
sipsak -U -s sip:100@target.lab -u 100 -a 100
```

### Confirming Discovered Credentials

After cracking a password, verify it works by completing a full SIP registration:

```bash
sipsak -U -s sip:100@target.lab -u 100 -a crackedpassword
```

A successful 200 OK response confirms the credentials are valid and can be used for further attacks (call spoofing, registration hijacking, toll fraud).

---

## Server Probing with sipsak

### SIP Service Capability Discovery

`sipsak` is a versatile SIP testing tool that goes beyond scanning. Use it to probe server capabilities and gather detailed information.

```bash
# Query server capabilities (supported methods)
sipsak -s sip:100@target.lab -C

# Trace SIP path (SIP traceroute)
sipsak -T -s sip:100@target.lab

# Send OPTIONS request
sipsak -s sip:100@10.0.0.1
```

The `Allow` header in the response lists which SIP methods the server supports (INVITE, ACK, CANCEL, OPTIONS, BYE, REGISTER, SUBSCRIBE, NOTIFY, etc.). This reveals the server's capabilities and potential attack surface.

### SIP Method Fuzzing

sipsak can also be used to test how the server handles various SIP methods and malformed requests. Unexpected methods or malformed headers may trigger errors that reveal internal paths, software versions, or other sensitive information.

---

## Key Takeaways

1. Always scan with both UDP and TCP — SIP can operate on either transport.
2. The User-Agent header is your primary fingerprinting tool — record all unique values.
3. Extensions that respond without authentication are the highest-priority findings.
4. Rate-limit your enumeration to avoid triggering IDS or IP bans.
5. Test default credentials before investing time in dictionary attacks.
6. Document every discovered device, extension, and credential for the final report.
