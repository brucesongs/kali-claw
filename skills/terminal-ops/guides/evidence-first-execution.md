# Evidence-First Execution Guide

Techniques for running every pentest command with evidence capture as the primary objective, ensuring traceability, reproducibility, and court-admissible documentation.

---

## 1. The Evidence-First Mindset

In penetration testing, a finding without evidence is an opinion. The evidence-first mindset flips the traditional approach: instead of running a command and then deciding whether to save the output, every command is designed to produce evidence from the start.

### Why Evidence-First Matters

1. **Legal defensibility** -- Pentest engagements often require proof that actions stayed within scope
2. **Report accuracy** -- Exact timestamps and outputs eliminate guesswork
3. **Reproducibility** -- Another tester can replay your commands and get the same results
4. **Client trust** -- Detailed evidence chains demonstrate professionalism
5. **Self-protection** -- If something breaks, your logs prove what you did (and did not do)

### The Evidence-First Rule

```text
RULE: No command runs without a capture destination.

BEFORE typing any command, answer:
  1. Where will stdout go?        → file, tee, or redirect
  2. Where will stderr go?        → same file or separate error log
  3. What timestamp marks this?   → ISO 8601 UTC
  4. What finding does this link? → finding ID or "recon"
```

### Mental Model

```text
Traditional:  run command → see output → maybe save it
Evidence-first: set up capture → run command → output is already saved
```

Every shell session should start with evidence capture active. If you find yourself copying output from a terminal after the fact, the process has already failed.

---

## 2. Session Recording Best Practices

### 2.1 The `script` Command

The simplest full-session recording tool on any Unix system.

```bash
# Start recording with timestamp in filename
script -q "session_$(date +%Y%m%d_%H%M%S).log"

# Start recording with timing data for playback
script --timing=timing.log "session_$(date +%Y%m%d_%H%M%S).log"

# Replay a session at original speed
scriptreplay timing.log session_20260522_143000.log

# Replay at 2x speed
scriptreplay -d 2 timing.log session_20260522_143000.log
```

**Best practices for `script`**:
- Always use `-q` (quiet) to suppress the "Script started" message from polluting output
- Include the date and time in the filename so sessions sort chronologically
- Run `script` as the first command after opening a terminal for the engagement
- End with `exit` or `Ctrl-D` -- never kill the terminal without stopping the recording

### 2.2 Asciinema

For shareable, replayable session recordings with full terminal rendering.

```bash
# Record a session
asciinema rec "engagement_$(date +%Y%m%d_%H%M%S).cast"

# Record with a title
asciinema rec --title "Target-X recon session" recon.cast

# Record with idle time limit (skip long waits)
asciinema rec --idle-time-limit 5 session.cast

# Play back locally
asciinema play session.cast

# Play back at 2x speed
asciinema play -s 2 session.cast
```

**When to use asciinema over `script`**:
- When you need to share recordings with team members or clients
- When visual terminal layout matters (colors, cursor position)
- When you want to embed recordings in reports or presentations

### 2.3 Tmux Logging

For persistent sessions that survive disconnections.

```bash
# Start tmux session named for the engagement
tmux new-session -s "pentest-targetX"

# Enable logging for the current pane (with tmux-logging plugin)
# Prefix + Shift-P  (toggle logging)
# Prefix + Alt-p    (save complete pane history)

# Manual tmux logging via pipe-pane
tmux pipe-pane -o "cat >> ~/evidence/tmux_$(date +%Y%m%d_%H%M%S).log"

# Stop logging
tmux pipe-pane
```

**Tmux session naming convention**:

```text
Format: pentest-<target>-<phase>
Examples:
  pentest-acme-recon
  pentest-acme-exploit
  pentest-acme-postex
```

### 2.4 Timestamps

Every evidence file and every command block should carry a UTC timestamp.

```bash
# ISO 8601 UTC timestamp function (add to .bashrc for engagements)
ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

# Stamp before every command block
echo "=== $(ts) ===" | tee -a evidence.log

# Timestamp wrapper for any command
stamp() {
  echo "=== $(date -u +%Y-%m-%dT%H:%M:%SZ) | CMD: $* ===" | tee -a evidence.log
  "$@" 2>&1 | tee -a evidence.log
  echo "=== EXIT: $? ===" | tee -a evidence.log
}

# Usage
stamp nmap -sV -sC 192.168.1.100
```

---

## 3. Evidence Chain Construction

An evidence chain links every command to a finding, and every finding to a report section. Without this chain, evidence is just noise.

### 3.1 The Chain Structure

```text
COMMAND (timestamped) → OUTPUT FILE → FINDING REFERENCE → REPORT SECTION
```

### 3.2 Evidence Chain Protocol

Every command block should follow this format, as defined in the terminal-ops SKILL.md:

```text
TIMESTAMP: 2026-05-22T14:30:00Z
ACTION: [human-readable description]
TARGET: [IP/domain] (authorized scope: [scope])
COMMAND: [exact command with all flags]
RESULT: [key output summary]
STATUS: [inspected / executed / verified / changed / reverted / blocked]
FILES: [list of output files]
FINDING: [finding ID or "N/A" for recon]
```

### 3.3 Linking Commands to Findings

```bash
# Directory structure per finding
mkdir -p findings/FIND-001-sqli/{commands,output,screenshots}

# Command log for a finding
cat > findings/FIND-001-sqli/commands/01-initial-discovery.sh << 'CMDEOF'
#!/bin/bash
# Finding: FIND-001-sqli
# Phase: Initial Discovery
# Timestamp: 2026-05-22T14:30:00Z
# Operator: kali-claw

sqlmap -u "http://target.com/search?q=test" --batch --level=3 \
  --output-dir=../output/sqlmap_initial 2>&1 | tee ../output/sqlmap_initial.log
CMDEOF
```

### 3.4 Evidence Hashing

For high-stakes engagements, hash evidence files to prove they have not been tampered with.

```bash
# Hash all evidence files after collection
find evidence/ -type f -exec sha256sum {} \; > evidence/checksums.sha256

# Verify integrity later
sha256sum -c evidence/checksums.sha256

# Sign the checksum file with GPG
gpg --armor --detach-sign evidence/checksums.sha256
```

---

## 4. Command Output Formatting

Raw terminal output is difficult to process programmatically. Structure your output for downstream consumption.

### 4.1 JSON Output

Many security tools support JSON output natively.

```bash
# Nmap XML to JSON (via xsltproc or nmap-parse-output)
nmap -sV -sC -oX scan.xml 192.168.1.0/24
python3 -c "import xmltodict,json,sys; print(json.dumps(xmltodict.parse(sys.stdin.read()),indent=2))" < scan.xml > scan.json

# Nuclei with JSON output
nuclei -u http://target.com -jsonl -o nuclei_results.jsonl

# Parse nuclei JSONL
cat nuclei_results.jsonl | jq -r '[.info.severity, .matched-at, .info.name] | @tsv'

# Nikto with JSON output
nikto -h http://target.com -Format json -output nikto_results.json

# Masscan with JSON
masscan 192.168.1.0/24 -p1-65535 --rate 1000 -oJ masscan_results.json
```

### 4.2 Grepable Output

For quick filtering and pipeline processing.

```bash
# Nmap grepable output
nmap -sV -oG scan.gnmap 192.168.1.0/24

# Extract open ports from grepable output
grep "open" scan.gnmap | awk '{print $2, $4}' | sort -u

# Extract all HTTP services
grep -i "http" scan.gnmap | awk -F'/' '{print $1}' | awk '{print $NF}'

# Custom grepable format for any command
nmap -sV 192.168.1.100 | awk '/open/{printf "%s:%s:%s\n", "192.168.1.100", $1, $3}'
# Output: 192.168.1.100:22/tcp:ssh
# Output: 192.168.1.100:80/tcp:http
```

### 4.3 XML Output

For tool interoperability and structured storage.

```bash
# Nmap XML (consumed by many other tools)
nmap -sV -sC -oX full_scan.xml 192.168.1.0/24

# Parse XML with xmlstarlet
xmlstarlet sel -t -m "//port[@protocol='tcp']" \
  -v "concat(@portid, '/', ../@addr, '/', service/@name)" -n full_scan.xml

# Convert Nessus XML to CSV
xmlstarlet sel -t -m "//ReportItem" \
  -v "concat(@port, ',', @svc_name, ',', @severity, ',', @pluginName)" -n \
  nessus_report.nessus > findings.csv
```

### 4.4 Multi-Format Output

Always produce multiple formats for flexibility.

```bash
# Nmap all-formats output (the -oA flag)
nmap -sV -sC -oA scans/target_full 192.168.1.100
# Produces: target_full.nmap, target_full.xml, target_full.gnmap

# Custom wrapper for multi-format output
run_scan() {
  local target=$1
  local basename="scans/$(echo $target | tr './' '_')_$(date +%Y%m%d_%H%M%S)"
  
  echo "=== $(date -u +%Y-%m-%dT%H:%M:%SZ) | Scanning $target ===" | tee -a evidence.log
  nmap -sV -sC -oA "$basename" "$target" | tee -a evidence.log
  echo "=== Files: ${basename}.{nmap,xml,gnmap} ===" | tee -a evidence.log
}
```

---

## 5. Handling Long-Running Operations

Security scans and brute-force operations can take hours. Proper management prevents lost work.

### 5.1 Background Execution

```bash
# Run in background with nohup
nohup nmap -sV -sC -p- -oA full_scan 10.0.0.0/16 > nmap_full.log 2>&1 &
echo "PID: $!" | tee -a evidence.log

# Check progress
tail -f nmap_full.log

# Run with timeout protection
timeout 3600 nmap -sV -p- -oA scan_1hr 192.168.1.0/24
```

### 5.2 Screen and Tmux Management

```bash
# Create a named screen session for a long scan
screen -S full-scan -dm bash -c \
  'nmap -sV -sC -p- -oA full_scan 10.0.0.0/16 2>&1 | tee full_scan.log'

# Reattach to check progress
screen -r full-scan

# Tmux: create a dedicated window for long operations
tmux new-window -n "full-scan" \
  "nmap -sV -sC -p- -oA full_scan 10.0.0.0/16 2>&1 | tee full_scan.log"

# Tmux: split pane to monitor while working
tmux split-window -h "tail -f full_scan.log"
```

### 5.3 Progress Monitoring

```bash
# Monitor nmap progress (send SIGUSR2 or press Enter during scan)
# In another terminal:
kill -SIGUSR2 $(pgrep -f "nmap.*full_scan")

# Monitor file size growth (indicates active scanning)
watch -n 5 'ls -lh full_scan.* 2>/dev/null'

# Monitor active connections during scanning
watch -n 2 'ss -tnp | grep nmap | wc -l'

# Estimated completion for large scans
start_time=$(date +%s)
# ... scan running ...
elapsed=$(($(date +%s) - start_time))
echo "Elapsed: $((elapsed / 3600))h $((elapsed % 3600 / 60))m"
```

### 5.4 Handling Interruptions

```bash
# Save nmap state for resumption
# Nmap creates a .gnmap file that supports --resume
nmap -sV -p- --resume full_scan.gnmap

# For tools that do not support resume, checkpoint via splitting
# Split a /16 into /24s and track completion
for subnet in $(seq 0 255); do
  if [ ! -f "scans/10.0.${subnet}.0_done" ]; then
    nmap -sV -oA "scans/10.0.${subnet}.0" "10.0.${subnet}.0/24"
    touch "scans/10.0.${subnet}.0_done"
  fi
done
```

---

## 6. Debugging Failed Exploits

When an exploit does not work, systematic debugging with evidence capture pinpoints the problem.

### 6.1 Verbose Mode Escalation

```text
Level 0: Normal output         → initial attempt
Level 1: Verbose (-v)          → see connection details
Level 2: Very verbose (-vv)    → see protocol negotiation
Level 3: Debug (-d / --debug)  → see internal tool state
Level 4: Packet capture        → see raw network traffic
Level 5: System call trace     → see OS-level behavior
```

### 6.2 Verbose Modes by Tool

```bash
# Nmap verbose
nmap -sV -vv --reason 192.168.1.100 2>&1 | tee nmap_debug.log

# SQLmap verbose
sqlmap -u "http://target.com/page?id=1" -v 3 --batch 2>&1 | tee sqlmap_debug.log

# Metasploit debug
msfconsole -q -x "setg LogLevel 3; use exploit/multi/handler; run" 2>&1 | tee msf_debug.log

# Curl verbose (shows TLS handshake, headers, timing)
curl -v --trace-ascii curl_trace.txt http://target.com/api/endpoint

# Hydra verbose
hydra -l admin -P wordlist.txt -vV http-post-form://target.com 2>&1 | tee hydra_debug.log
```

### 6.3 Packet Capture for Exploit Debugging

```bash
# Capture traffic during exploit attempt
tcpdump -i eth0 -w exploit_attempt.pcap host target.com &
TCPDUMP_PID=$!

# Run the exploit
python3 exploit.py --target target.com --port 8080 2>&1 | tee exploit.log

# Stop capture
kill $TCPDUMP_PID

# Analyze the capture
tshark -r exploit_attempt.pcap -Y "http" -T fields \
  -e frame.time -e ip.src -e ip.dst -e http.request.method -e http.request.uri

# Look for the exploit payload in the capture
tshark -r exploit_attempt.pcap -Y "http.request" -V | grep -A5 "payload"
```

### 6.4 System Call Tracing

```bash
# Trace a failing tool to see what system calls it makes
strace -f -o strace_output.txt -e trace=network,file ./exploit_tool target.com

# Trace library calls
ltrace -o ltrace_output.txt -e 'connect+send+recv' ./exploit_tool target.com

# Quick network-only trace
strace -f -e trace=connect,sendto,recvfrom ./exploit_tool 2>&1 | \
  tee strace_network.log

# Filter for failed calls
grep "= -1" strace_output.txt | head -20
```

### 6.5 Debugging Decision Tree

```text
Exploit failed
  ├── Network error?
  │   ├── tcpdump: packets reaching target?
  │   │   ├── NO → check routing, firewall, VPN
  │   │   └── YES → check response packets
  │   │       ├── RST → port closed or filtered
  │   │       ├── No response → firewall dropping
  │   │       └── Response but wrong → version mismatch
  ├── Authentication error?
  │   ├── Credentials correct? → verify manually with curl
  │   ├── Session expired? → re-authenticate
  │   └── CSRF token? → capture token first
  ├── Payload error?
  │   ├── Encoding issue? → check URL/base64/HTML encoding
  │   ├── WAF blocking? → try payload obfuscation
  │   └── Wrong payload for target? → verify target version
  └── Tool error?
      ├── Check tool version → tool --version
      ├── Check dependencies → ldd tool / pip list
      └── Try alternative tool → manual curl/python
```

---

## 7. Evidence Organization

A consistent directory structure ensures evidence is findable months after the engagement.

### 7.1 Directory Structure Per Engagement

```text
engagements/
└── YYYY-MM-DD_client-name/
    ├── scope.txt                  # Authorized targets and rules
    ├── evidence.log               # Master evidence chain log
    ├── checksums.sha256           # Integrity hashes
    ├── sessions/                  # Terminal session recordings
    │   ├── session_20260522_143000.log
    │   ├── session_20260522_143000.cast
    │   └── timing.log
    ├── recon/                     # Reconnaissance phase
    │   ├── nmap/
    │   │   ├── initial_scan.nmap
    │   │   ├── initial_scan.xml
    │   │   └── initial_scan.gnmap
    │   ├── dns/
    │   ├── osint/
    │   └── web-enum/
    ├── findings/                  # Organized by finding ID
    │   ├── FIND-001-sqli/
    │   │   ├── commands/
    │   │   ├── output/
    │   │   └── screenshots/
    │   └── FIND-002-xss/
    │       ├── commands/
    │       ├── output/
    │       └── screenshots/
    ├── exploits/                  # Exploitation phase
    │   ├── payloads/
    │   ├── captures/
    │   └── shells/
    ├── post-exploitation/         # Post-exploitation phase
    │   ├── loot/
    │   ├── persistence/
    │   └── pivoting/
    └── report/                    # Final report artifacts
        ├── evidence-snippets/
        ├── screenshots/
        └── draft/
```

### 7.2 Naming Conventions

```text
Files:
  <tool>_<target>_<timestamp>.<ext>
  nmap_192-168-1-100_20260522_143000.xml
  sqlmap_target-com_20260522_150000.log
  burp_api-endpoint_20260522_160000.xml

Directories:
  <phase>/<category>/
  recon/nmap/
  findings/FIND-001-sqli/
  exploits/payloads/

Findings:
  FIND-<number>-<short-name>
  FIND-001-sqli
  FIND-002-xss-stored
  FIND-003-auth-bypass
```

### 7.3 Initialization Script

```bash
#!/bin/bash
# init_engagement.sh -- Set up evidence directory structure
# Usage: ./init_engagement.sh client-name

CLIENT=$1
DATE=$(date +%Y-%m-%d)
BASE="engagements/${DATE}_${CLIENT}"

mkdir -p "$BASE"/{sessions,recon/{nmap,dns,osint,web-enum},findings,exploits/{payloads,captures,shells},post-exploitation/{loot,persistence,pivoting},report/{evidence-snippets,screenshots,draft}}

# Create scope file template
cat > "$BASE/scope.txt" << 'EOF'
# Engagement Scope
# Client: [CLIENT NAME]
# Start: [DATE]
# End: [DATE]
# Authorized By: [NAME]

## In-Scope Targets
# [List IPs, domains, URLs]

## Out-of-Scope
# [List exclusions]

## Rules of Engagement
# - Testing hours: [hours]
# - Notification required for: [destructive tests, social engineering, etc.]
# - Emergency contact: [phone/email]
EOF

# Initialize master evidence log
echo "=== Evidence Log: ${DATE}_${CLIENT} ===" > "$BASE/evidence.log"
echo "=== Initialized: $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" >> "$BASE/evidence.log"

echo "Engagement directory created: $BASE"
```

---

## 8. Post-Engagement Evidence Packaging

After the engagement, evidence must be packaged securely for delivery and archival.

### 8.1 Pre-Packaging Checklist

```text
Before packaging:
  [ ] All session recordings stopped
  [ ] All temporary files cleaned from target systems
  [ ] Evidence log has closing timestamp
  [ ] All output files verified non-empty
  [ ] Checksums generated for all evidence files
  [ ] No credentials stored in plaintext (redact or encrypt)
  [ ] Scope file complete and accurate
```

### 8.2 Generating Checksums

```bash
# Generate checksums for the entire evidence tree
cd engagements/2026-05-22_client-name/
find . -type f ! -name "checksums.sha256" -exec sha256sum {} \; > checksums.sha256

# Count and verify
echo "Files hashed: $(wc -l < checksums.sha256)"
sha256sum -c checksums.sha256 | grep -c "OK"
```

### 8.3 Encryption and Packaging

```bash
# Create a compressed archive
tar czf "2026-05-22_client-name_evidence.tar.gz" \
  -C engagements "2026-05-22_client-name/"

# Encrypt with GPG (symmetric, for password-based sharing)
gpg --symmetric --cipher-algo AES256 \
  --output "2026-05-22_client-name_evidence.tar.gz.gpg" \
  "2026-05-22_client-name_evidence.tar.gz"

# Encrypt with GPG (asymmetric, for specific recipient)
gpg --encrypt --recipient "client@example.com" \
  --output "2026-05-22_client-name_evidence.tar.gz.gpg" \
  "2026-05-22_client-name_evidence.tar.gz"

# Remove the unencrypted archive
shred -u "2026-05-22_client-name_evidence.tar.gz"
```

### 8.4 Chain of Custody Documentation

```markdown
# Chain of Custody

## Evidence Package
- **Package ID**: EVID-2026-0522-001
- **Created**: 2026-05-22T18:00:00Z
- **Created By**: [operator name]
- **SHA256**: [hash of encrypted archive]
- **Contents**: [engagement directory description]

## Transfer Log

| Date | From | To | Method | Hash Verified |
|------|------|----|--------|---------------|
| 2026-05-22 | [operator] | [team lead] | Encrypted USB | Yes |
| 2026-05-23 | [team lead] | [client] | Secure file transfer | Yes |

## Retention
- **Retention Period**: [per client contract, e.g., 90 days]
- **Destruction Date**: [date]
- **Destruction Method**: Secure deletion (shred/wipe)
```

---

## 9. Integration with Report Generation

Evidence must flow seamlessly from the command line into the final pentest report.

### 9.1 Extracting Evidence Snippets

```bash
# Extract a specific finding's evidence from the master log
grep -A20 "FIND-001" evidence.log > report/evidence-snippets/FIND-001.txt

# Extract all commands for a finding
grep "COMMAND:" evidence.log | grep -i "sqli\|sqlmap\|sql" > report/evidence-snippets/sqli_commands.txt

# Extract timestamped output blocks
awk '/=== 2026-05-22T14:3/{found=1} found{print} /STATUS:/{if(found) exit}' evidence.log
```

### 9.2 Screenshot Integration

```bash
# Capture a terminal screenshot (using gnome-screenshot or scrot)
scrot "findings/FIND-001-sqli/screenshots/sqli_proof_$(date +%Y%m%d_%H%M%S).png"

# Capture specific window
scrot -u "findings/FIND-001-sqli/screenshots/browser_response.png"

# Use cutycapt for headless web screenshots
cutycapt --url=http://target.com/vuln_page --out=findings/FIND-001-sqli/screenshots/vuln_page.png
```

### 9.3 Evidence-to-Report Mapping Template

```text
## Finding: FIND-001 - SQL Injection in Search Parameter

### Evidence Files
- Command log: findings/FIND-001-sqli/commands/01-initial-discovery.sh
- SQLmap output: findings/FIND-001-sqli/output/sqlmap_initial.log
- Packet capture: findings/FIND-001-sqli/output/exploit_capture.pcap
- Screenshot: findings/FIND-001-sqli/screenshots/sqli_proof_20260522_143000.png

### Report Section Reference
- Section: 3.1 Critical Findings
- Severity: Critical (CVSS 9.8)
- Status: CONFIRMED

### Evidence Excerpt (for report inclusion)
```
$ sqlmap -u "http://target.com/search?q=test" --batch --dbs
[14:30:15] [INFO] the back-end DBMS is MySQL
[14:30:15] [INFO] fetching database names
available databases [3]:
[*] information_schema
[*] production_db
[*] test_db
```
```

### 9.4 Automated Report Evidence Assembly

```bash
#!/bin/bash
# assemble_evidence.sh -- Collect evidence snippets for all findings
# Usage: ./assemble_evidence.sh engagements/2026-05-22_client-name

ENGAGEMENT=$1
REPORT_DIR="$ENGAGEMENT/report/evidence-snippets"
mkdir -p "$REPORT_DIR"

for finding_dir in "$ENGAGEMENT"/findings/FIND-*; do
  finding=$(basename "$finding_dir")
  echo "=== $finding ===" > "$REPORT_DIR/${finding}.txt"
  
  # Include commands
  if [ -d "$finding_dir/commands" ]; then
    echo "--- Commands ---" >> "$REPORT_DIR/${finding}.txt"
    cat "$finding_dir"/commands/*.sh >> "$REPORT_DIR/${finding}.txt" 2>/dev/null
  fi
  
  # Include key output (first 50 lines of each output file)
  if [ -d "$finding_dir/output" ]; then
    echo "--- Output ---" >> "$REPORT_DIR/${finding}.txt"
    for output_file in "$finding_dir"/output/*; do
      echo ">> $(basename $output_file)" >> "$REPORT_DIR/${finding}.txt"
      head -50 "$output_file" >> "$REPORT_DIR/${finding}.txt"
      echo "..." >> "$REPORT_DIR/${finding}.txt"
    done
  fi
  
  # List screenshots
  if [ -d "$finding_dir/screenshots" ]; then
    echo "--- Screenshots ---" >> "$REPORT_DIR/${finding}.txt"
    ls "$finding_dir"/screenshots/ >> "$REPORT_DIR/${finding}.txt" 2>/dev/null
  fi
  
  echo "Assembled: $finding"
done

echo "Evidence assembled in: $REPORT_DIR"
```

---

## Quick Reference Card

```text
SESSION START:
  script -q "session_$(date +%Y%m%d_%H%M%S).log"

BEFORE EVERY COMMAND:
  echo "=== $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" | tee -a evidence.log

COMMAND EXECUTION:
  <command> 2>&1 | tee -a evidence.log

MULTI-FORMAT OUTPUT:
  nmap -sV -oA scans/<target>_<timestamp> <target>

FINDING DIRECTORY:
  mkdir -p findings/FIND-<NNN>-<name>/{commands,output,screenshots}

POST-ENGAGEMENT:
  find . -type f -exec sha256sum {} \; > checksums.sha256
  tar czf evidence.tar.gz engagement/
  gpg --symmetric --cipher-algo AES256 evidence.tar.gz

STATUS WORDS:
  inspected | executed | verified | changed | reverted | blocked
```
