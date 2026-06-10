---
name: search-first
description: "Systematizes the \"search for existing tools, exploits, and techniques before writing custom ones\" workflow."
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




# Skill: Search First — Research Before You Exploit

> **Supplementary Files**:
> - `payloads.md` — Search templates for ExploitDB, GitHub, Metasploit, Nuclei, and Kali packages with evaluation scoring
> - `test-cases.md` — Structured test cases for CVE discovery, tool discovery, technique research, and custom build decisions

## Summary

Search First skill domain covering workflow operations.

**Domain**: workflow

## Description

Systematizes the "search for existing tools, exploits, and techniques before writing custom ones" workflow. In penetration testing, this means: before developing a custom exploit or tool, search for existing solutions in exploit databases, security tools, GitHub repositories, and community resources.

This skill prevents reinventing the wheel and ensures kali-claw leverages the full ecosystem of existing security tools and known exploit techniques.

## Use Cases

- Before writing a custom exploit: search Exploit-DB, GitHub, and security blogs for existing PoCs
- Before building a reconnaissance tool: check if nmap scripts, Nuclei templates, or Metasploit modules already exist
- Before developing a post-exploitation technique: search for existing tools and frameworks
- When facing an unfamiliar technology: research known vulnerabilities and attack paths before testing
- Before creating automation scripts: check if existing tools already provide the capability

## Methodology

### Search-First Decision Flow

```
┌─────────────────────────────────────────────┐
│  1. NEED ANALYSIS                           │
│     Define what capability is needed         │
│     Identify target technology/constraints   │
├─────────────────────────────────────────────┤
│  2. PARALLEL SEARCH                         │
│     ┌──────────┐ ┌──────────┐ ┌──────────┐  │
│     │ ExploitDB│ │  GitHub  │ │  Security │  │
│     │ MSF/NS   │ │  PoCs    │ │  Blogs    │  │
│     └──────────┘ └──────────┘ └──────────┘  │
├─────────────────────────────────────────────┤
│  3. EVALUATE                                │
│     Score: reliability, compatibility,      │
│     OPSEC, maintenance, detection risk      │
├─────────────────────────────────────────────┤
│  4. DECIDE                                  │
│     ┌─────────┐  ┌──────────┐  ┌─────────┐  │
│     │  Use    │  │  Modify  │  │  Build   │  │
│     │ as-is   │  │  /Wrap   │  │  Custom  │  │
│     └─────────┘  └──────────┘  └─────────┘  │
├─────────────────────────────────────────────┤
│  5. EXECUTE                                 │
│     Run existing tool / Modify template /   │
│     Write minimal custom exploit            │
└─────────────────────────────────────────────┘
```

### Decision Matrix

| Signal | Action |
|--------|--------|
| Exact exploit exists for target version | **Use** — run directly, verify results |
| Similar exploit exists for adjacent version | **Modify** — adapt parameters/payloads |
| Multiple partial tools cover the need | **Compose** — chain existing tools together |
| Nothing suitable found | **Build** — write custom, but informed by research |

### Search Sources by Category

#### Exploit & Vulnerability Search
```bash
# Exploit-DB local search
searchsploit apache 2.4.49 remote
searchsploit -x 12345  # Examine exploit code

# GitHub PoC search
gh search code "CVE-2025-12345" --limit 20
gh search repos "<tool-name> exploit" --sort stars

# Metasploit module search
msfconsole -x "search type:exploit name:<keyword>"

# Nuclei template search
nuclei -tl -tags cve | grep "<keyword>"
```

#### Tool & Capability Search
```bash
# Kali package search
apt search <keyword>
dpkg -l | grep <tool>

# GitHub security tool search
gh search repos "<capability> security tool" --sort stars --limit 20

# Exploit framework module search
msfconsole -x "search type:auxiliary name:<keyword>"
msfconsole -x "search type:post name:<keyword>"
```

#### Technique & Methodology Search
```bash
# MITRE ATT&CK technique lookup
# Web: https://attack.mitre.org/techniques/enterprise/

# HackTricks methodology
# Web: https://book.hacktricks.wiki/

# PayloadsAllTheThings
# Web: https://github.com/swisskyrepo/PayloadsAllTheThings

# GTFOBins / LOLBAS
# Web: https://gtfobins.github.io/
# Web: https://lolbas-project.github.io/
```

### Integration with Other Skills

- **With `deep-research`**: Use deep-research for broad topic investigation, search-first for quick tool/exploit lookup
- **With `security-bounty-hunter`**: Search for existing reports before hunting similar vulnerabilities
- **With `terminal-ops`**: Execute found tools with evidence capture protocol
- **With `osint`**: Combine OSINT gathering with tool search for comprehensive preparation

## Anti-Patterns

- **Jumping to custom code**: Writing an exploit without checking Exploit-DB or Metasploit
- **Ignoring version specificity**: Using an exploit for the wrong version without adaptation
- **Over-customizing**: Wrapping a tool so heavily it loses its original capability
- **Tool hoarding**: Installing every tool found instead of mastering the best one

## Examples

### Example 1: Exploit Apache Path Traversal
```
Need: Exploit path traversal in Apache 2.4.49
Search: searchsploit apache 2.4.49 path traversal
Found: CVE-2021-41773, multiple PoCs on GitHub
Action: USE — curl-based PoC is sufficient
Result: curl "http://target/cgi-bin/.%2e/%2e%2e/etc/passwd"
```

### Example 2: Active Directory Enumeration
```
Need: Enumerate AD domain from compromised Windows host
Search: GitHub "Active Directory enumeration tool"
Found: BloodHound, SharpHound, ldapsearch-ad, Certipy
Action: USE — BloodHound/SharpHound is the standard
Result: Run SharpHound, import to BloodHound for analysis
```

### Example 3: TLS Reverse Shell
```
Need: Reverse shell bypassing egress filtering (only port 443)
Search: GitHub "reverse shell tls encrypted"
Found: Several TLS-encrypted shell tools
Action: MODIFY — adapt existing TLS shell for constraint
Result: Minimal custom wrapper around existing tool
```

## Orchestration

### ECC Loop Pattern
- **Pattern**: Learning Cycle (search → evaluate → decide → refine search if needed)
- **Rationale**: Searching is iterative — initial searches inform subsequent queries, and results are refined based on relevance scoring until a suitable solution is found or the decision is made to build custom
- **Integration**: deep-research (broad topic investigation), terminal-ops (execute found tools), continuous-learning (remember which sources are reliable per topic), docker-patterns (lab verification of found exploits)

### Cross-Skill Pipeline
```
search-first → [any attack skill] → verification-loop
      ↓                                     ↑
deep-research (broader context)    continuous-learning (persist tool knowledge)
```

### Quality Gate
- Pre-condition: Need clearly defined (service/version/technique)
- Post-condition: At least one result evaluated with scoring matrix, or documented decision to build custom
- Verification: Selected tool/exploit tested against lab or verified against documentation
