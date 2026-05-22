# Validation Guide — Skill Practice Execution Playbook

> How to run validation sessions for kali-claw skill domains.

---

## 1. Purpose

Prove that each skill domain's documented test cases are executable in a real Kali Linux environment. This validates that payloads work, commands are correct, and expected outcomes are achievable — not just theoretical.

---

## 2. Environment Requirements

### Minimum

| Component | Requirement |
|-----------|-------------|
| OS | Kali Linux 2025-2 (ARM64 or x86_64) |
| Docker | Docker CE + Docker Compose v2 |
| RAM | 8 GB minimum (16 GB recommended for multi-container labs) |
| Disk | 50 GB free (Docker images + evidence storage) |
| Network | Internet access for package downloads and OSINT skills |

### Optional (for full coverage)

| Component | Unlocks |
|-----------|---------|
| Wireless adapter (monitor mode) | wifi-pentest |
| USB-UART adapter | hardware-security (UART tests) |
| Android device or emulator | mobile-security (dynamic analysis) |
| AWS/GCP free-tier account | cloud-security |
| Burp Suite Pro | api-security, web-auth-bypass (advanced) |

---

## 3. Pre-Session Checklist

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Verify Docker is running
docker info > /dev/null 2>&1 || sudo systemctl start docker

# Create evidence directory for today
mkdir -p validation/evidence/$(date +%Y-%m-%d)

# Start terminal recording
script -q validation/evidence/$(date +%Y-%m-%d)/session-$(date +%H%M).log
```

---

## 4. Execution Workflow

For each test case:

### Step 1: Read

Open `skills/{domain}/test-cases.md` and locate the target TC. Read:
- **Scenario** — understand the context
- **Pre-conditions** — what must be true before starting
- **Test Steps** — the numbered execution plan

### Step 2: Check Pre-conditions

Verify all pre-conditions are met. Common ones:
- Docker lab running (`docker compose up -d`)
- Target network reachable
- Required tools installed
- Scope file prepared

### Step 3: Execute

Follow Test Steps exactly. Capture all terminal output via `script` or `asciinema`.

### Step 4: Compare

Check each row in the **Expected Outcomes** table:
- Does the actual output match?
- Are all criteria satisfied?

### Step 5: Record

Update `validation/VALIDATION-TRACKER.md`:
1. Change Status from PENDING to PASS/FAIL/PARTIAL/BLOCKED
2. Set Date to today (YYYY-MM-DD)
3. Add Evidence path (relative to repo root)
4. Add Notes if not a clean PASS

### Step 6: Update Summary

Recalculate the Summary table counts at the top of the tracker.

---

## 5. Evidence Standards

### Naming Convention

```
validation/evidence/{skill-domain}-{TC-ID}-{YYYY-MM-DD}.{ext}
```

Examples:
- `validation/evidence/web-sqli-TC-S001-2026-05-23.log`
- `validation/evidence/docker-patterns-TC-DP-001-2026-05-23.log`
- `validation/evidence/network-pentest-TC-NP-001-2026-05-23.png`

### Acceptable Formats

| Type | Format | Tool |
|------|--------|------|
| Terminal output | `.log` | `script`, `tee` |
| Terminal recording | `.cast` | `asciinema` |
| Screenshot | `.png` | `scrot`, `flameshot` |
| Network capture | `.pcap` | `tcpdump`, `tshark` |
| Scan results | `.xml`, `.json` | `nmap -oX`, tool-native |

### Minimum Evidence

- **PASS**: Terminal log showing command execution and output matching Expected Outcomes
- **FAIL**: Terminal log + description of divergence in Notes
- **PARTIAL**: Terminal log + explanation of what was verified vs. what was not
- **BLOCKED**: No evidence needed; justification in Notes column

---

## 6. Recording Results

### Tracker Columns

| Column | Content |
|--------|---------|
| Status | One of: PASS, FAIL, PARTIAL, BLOCKED |
| Date | YYYY-MM-DD of execution |
| Evidence | Relative path: `evidence/{filename}` |
| Notes | Brief explanation (required for FAIL/PARTIAL/BLOCKED, optional for PASS) |

### Example Entry

```markdown
| 46 | web-sqli | TC-S001 | GET Parameter Injection Point Detection | PASS | 2026-05-23 | evidence/web-sqli-TC-S001-2026-05-23.log | SQLi-Labs Level 1 confirmed |
```

---

## 7. Handling Special Cases

### BLOCKED Skills

Document the specific constraint preventing execution:

| Skill | Likely Block Reason | Partial Workaround |
|-------|--------------------|--------------------|
| wifi-pentest | No monitor-mode adapter available | None — requires hardware |
| hardware-security | No physical device for UART/JTAG | Use binwalk firmware analysis only (PARTIAL) |
| mobile-security | No Android device | Use static analysis with jadx/apktool (PARTIAL) |
| social-engineering | GoPhish requires mail infrastructure | Use local SMTP (Mailhog) for demo |
| cloud-security | No AWS account | Use LocalStack for simulation (PARTIAL) |

### Meta-Skills (No Tool Output)

Meta-skills (chronicle, continuous-learning, safety-guard, knowledge-ops, council, autonomous-loops) validate process correctness rather than tool output:

- Execute the documented workflow
- Verify expected file artifacts are created
- Confirm state transitions match Expected Outcomes

### Lab-Dependent Skills

Many offensive skills require Docker targets. Execute in this order:
1. First validate `docker-patterns` (TC-DP-001) to deploy labs
2. Then use those labs for web-sqli, web-xss, web-ssrf, web-auth-bypass, etc.

---

## 8. Skill Categories & Environment Needs

| Category | Skills | Environment |
|----------|--------|-------------|
| **Web Offensive** | web-sqli, web-xss, web-ssrf, web-auth-bypass, web-access-control, api-security, insecure-design, security-misconfiguration | Docker labs (DVWA, Juice Shop, SQLi-Labs) |
| **Network** | network-pentest, recon-osint, vulnerability-assessment | Basic Kali + target network |
| **Exploitation** | password-attack, post-exploitation, binary-reverse, crypto-attacks | Kali tools + Docker targets |
| **OSINT/Research** | osint, deep-research, social-intelligence, exa-search, data-scraper-agent | Internet access |
| **Cloud/Container** | cloud-security, container-security, supply-chain-security | Docker + optional cloud account |
| **Mobile** | mobile-security | APK files + jadx/apktool (static), device (dynamic) |
| **Specialized** | wifi-pentest, hardware-security, ai-fuzzing, ai-security | Hardware/specialized software |
| **Meta/Process** | chronicle, continuous-learning, safety-guard, autonomous-loops, verification-loop, knowledge-ops, council, search-first, repo-scan, security-review, article-writing, codebase-onboarding, mcp-server-patterns, multi-agent-collaboration, browser-qa, logging-monitoring, security-bounty-hunter, terminal-ops, docker-patterns, social-engineering | Kali + Docker (varies) |

---

## 9. Recommended Execution Order

Execute in this sequence to build dependencies bottom-up:

### Batch 1: Infrastructure
1. `docker-patterns` — deploy vulnerable lab environment
2. `terminal-ops` — establish evidence capture workflow

### Batch 2: Web Skills (use Docker labs)
3. `web-sqli` → `web-xss` → `web-ssrf` → `web-auth-bypass` → `web-access-control`
4. `api-security` → `insecure-design` → `security-misconfiguration`

### Batch 3: Network & Recon
5. `network-pentest` → `recon-osint` → `osint` → `vulnerability-assessment`

### Batch 4: Exploitation
6. `password-attack` → `post-exploitation` → `binary-reverse` → `crypto-attacks`

### Batch 5: Specialized Domains
7. `cloud-security` → `container-security` → `supply-chain-security`
8. `mobile-security` → `logging-monitoring`

### Batch 6: Research & OSINT
9. `deep-research` → `social-intelligence` → `social-engineering`
10. `exa-search` → `data-scraper-agent`

### Batch 7: Meta & Process Skills
11. `chronicle` → `continuous-learning` → `safety-guard` → `autonomous-loops`
12. `verification-loop` → `knowledge-ops` → `council` → `search-first`
13. `repo-scan` → `security-review` → `article-writing` → `codebase-onboarding`
14. `mcp-server-patterns` → `multi-agent-collaboration` → `browser-qa` → `security-bounty-hunter`

### Batch 8: Hardware-Dependent (likely BLOCKED/PARTIAL)
15. `wifi-pentest` → `hardware-security` → `ai-fuzzing` → `ai-security`

---

_Last updated: 2026-05-22_
