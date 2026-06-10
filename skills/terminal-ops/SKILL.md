---
name: terminal-ops
description: "Evidence-first execution workflow for running security commands, inspecting system state, debugging tool failures, and making verified changes. This skill enforces a disciplined approach: inspect before acting, keep changes narrow, and report exact execution state."
origin: openclaw
version: "0.1.18"
compatibility:
  - openclaw
  - claude-code
  - cursor
  - windsurf
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
  - WebSearch
  - WebFetch
  - Agent
metadata:
  domain: workflow
  tool_count: 0
  guide_count: 5
---




# Skill: Terminal Operations

> **Supplementary Files**:
> - `payloads.md` — Common pentest terminal command patterns organized by task (recon, exploitation, post-exploitation, reporting)
> - `test-cases.md` — Structured test scenarios for terminal operations workflow

## Summary

This skill enforces a disciplined approach: inspect before acting, keep changes narrow, and report exact execution state.

**Domain**: workflow

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

## Orchestration

### ECC Loop Pattern

**Sequential Pipeline**: execute -> capture evidence -> verify -> report

Terminal operations are inherently sequential — each command builds on the previous result. The pipeline does not proceed to the next step until the current step's evidence is captured and verified.

### Integration

All skills that execute terminal commands use terminal-ops for evidence capture. When any skill (network-pentest, web-xss, post-exploitation, etc.) runs a command, it follows the Evidence Chain Protocol defined here to ensure traceability and reproducibility.

### Cross-Skill Pipeline

Terminal-ops provides the evidence protocol consumed by all other skills:

```text
[terminal-ops] -- evidence protocol --> [all skills executing commands]
                                      --> [network-pentest, web-xss, web-sqli,
                                           post-exploitation, password-attack,
                                           cloud-security, ...]
```

Every skill that runs shell commands uses the timestamp, output file, and hash conventions defined in this skill.

### Quality Gate

| Gate | Check | Criteria |
|------|-------|----------|
| Pre-condition | Scope confirmed | Target verified within authorized range |
| Post-condition | Evidence chain complete | Every action has START, metadata, STATUS, END markers |
| Verification | Output files valid | All output files exist and are non-empty |

## Pitfalls

- Never work from stale memory when live state can be re-read
- Never widen a narrow task into unscoped testing
- Never use destructive commands without explicit confirmation
- Never ignore unrelated findings discovered during execution (log them for follow-up)
- Never assume a command succeeded without verifying its output

## Automation and Scripting

Terminal automation transforms repetitive pentest tasks into reproducible, evidence-generating pipelines. Shell functions wrapping common scan patterns with automatic timestamp injection and output file management ensure consistency across engagements. Python orchestration scripts can chain multi-stage attacks (recon -> exploit -> post-exploitation) while maintaining complete evidence logs at each step, enabling one-command execution of complex test sequences with full traceability.

## Error Handling

Terminal command failures during pentests must be diagnosed systematically rather than retried blindly. Inspect exit codes (`$?`) and stderr output before retrying; many tool failures result from environmental issues (missing dependencies, permission denials, network connectivity) that no amount of re-execution will resolve. When a tool fails, capture the exact error output, verify the environment (tool version, target reachability, permission level), and document the root cause before attempting alternative approaches.

## Performance Optimization

Efficient terminal operations minimize wasted time during time-sensitive pentest engagements. Parallelize independent scans using background processes (`&`) and GNU parallel, but avoid overloading the target or local network interface. Use targeted port lists (`-p 22,80,443,8080`) instead of full port scans when only specific services are relevant. Cache scan results in structured files (JSON, XML) to avoid re-scanning when multiple tools need the same reconnaissance data.
