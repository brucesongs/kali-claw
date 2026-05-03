# Skill: Terminal Operations

> **Supplementary Files**:
> - `payloads.md` — Common pentest terminal command patterns organized by task (recon, exploitation, post-exploitation, reporting)

## Description

Evidence-first execution workflow for running security commands, inspecting system state, debugging tool failures, and making verified changes. This skill enforces a disciplined approach: inspect before acting, keep changes narrow, and report exact execution state.

This is an operator workflow — it governs how kali-claw executes any terminal task during penetration testing, ensuring every action is traceable, reversible, and verified.

## Use Cases

- Running reconnaissance and scanning commands with structured output capture
- Debugging failed exploits or tool errors during a pentest
- Executing post-exploitation commands with careful state tracking
- Making narrow configuration changes to testing environments
- Verifying that exploits or patches actually work before moving on
- Generating reproducible evidence chains for pentest reports

## Core Tools

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| nmap | Network scanning | `nmap -sV -sC -oA scan_results target` |
| curl | HTTP requests with evidence capture | `curl -v -o response.html http://target 2>&1 \| tee curl_log.txt` |
| tcpdump | Packet capture for evidence | `tcpdump -i eth0 -w capture.pcap host target` |
| jq | JSON output parsing | `cat scan.json \| jq '.[] \| select(.port == 443)'` |
| tee | Dual output (screen + file) | `command \| tee output.log` |
| script | Full terminal session recording | `script -q session_$(date +%Y%m%d_%H%M%S).log` |

## Methodology

### Terminal Ops Five-Phase Process

**Phase 1: Resolve the Working Surface**

Before executing, confirm:
- Target system / IP / URL
- Current network position (local, VPN, pivoted)
- Authorized scope
- Requested mode: `inspect` | `exploit` | `verify` | `cleanup`
- Output destination for evidence

**Phase 2: Read the Failing Surface First**

If debugging or following up:
- Inspect the error message or unexpected output
- Inspect tool version and configuration
- Inspect network state (connectivity, routing, firewalls)
- Use any already-supplied logs before re-running blindly

**Phase 3: Execute with Evidence Capture**

Every command produces verifiable evidence:

```bash
echo "=== $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" | tee -a evidence.log
nmap -sV -sC -oA scans/nmap_$(date +%Y%m%d_%H%M%S) target | tee -a evidence.log
```

**Phase 4: Keep Changes Narrow**

Solve one task at a time:
- Use the smallest useful command first
- Only escalate to broader scans after narrow commands succeed
- If a command keeps failing, stop broad retries and investigate root cause
- Never chain destructive commands without verification at each step

**Phase 5: Report Exact Execution State**

Use precise status words:
- `inspected` — Read-only observation completed
- `executed` — Command ran, output captured
- `verified` — Result confirmed against expected outcome
- `changed` — System state modified
- `reverted` — Change rolled back
- `blocked` — Cannot proceed (state reason)

### Evidence Chain Protocol

For every action during a pentest:

```text
TIMESTAMP: 2026-05-04T14:30:00Z
ACTION: nmap TCP SYN scan
TARGET: 192.168.1.100 (authorized scope: 192.168.1.0/24)
COMMAND: nmap -sS -sV -p- -oA full_scan 192.168.1.100
RESULT: 22/open/tcp/ssh/OpenSSH 8.9, 80/open/tcp/http/nginx 1.24
STATUS: executed
FILES: full_scan.nmap, full_scan.xml, full_scan.gnmap
```

### Defense Perspective

- **Audit trail**: Every command should be reproducible from logged evidence
- **Minimal footprint**: Use the least intrusive command that achieves the goal
- **Cleanup**: Remove temporary files, test accounts, or artifacts after testing
- **Scope compliance**: Never execute against out-of-scope targets

## Output Format

```text
SURFACE
- target: [IP/domain/system]
- scope: [authorized range]
- mode: [inspect/exploit/verify/cleanup]

EVIDENCE
- command: [exact command run]
- output: [key findings or error]
- timestamp: [ISO 8601]

STATUS
- [inspected / executed / verified / changed / reverted / blocked]

FILES
- [any output files generated]
```

## Pitfalls

- Never work from stale memory when live state can be re-read
- Never widen a narrow task into unscoped testing
- Never use destructive commands without explicit confirmation
- Never ignore unrelated findings discovered during execution (log them for follow-up)
- Never assume a command succeeded without verifying its output
