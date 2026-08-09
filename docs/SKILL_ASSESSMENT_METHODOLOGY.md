# SKILL Assessment Methodology

> **Project**: Usage instructions + capability assessment for all 139 kali-claw SKILLs
> **Started**: 2026-08-09
> **Estimated duration**: 5-9 months (5-8 SKILLs/week)
> **Plan reference**: [/Users/brucesong/.claude/plans/skill-zesty-frog.md](../../.claude/plans/skill-zesty-frog.md)

---

## 1. Project Goal

For each of the 139 kali-claw SKILLs, produce a human-validated `usage-and-assessment.md` guide that:

1. Tells a new user **how to use** the SKILL (Usage Instructions section)
2. Provides a **quantitative capability score** across 6 dimensions (Capability Assessment section)
3. Records **validation evidence** from Kali VM payload runs
4. Lists **findings** for future improvement (deferred to minor versions, not fixed in this project)

Philosophy: **assess, don't fix**. This project produces evidence; downstream minor versions consume the findings.

---

## 2. 6-Dimension Scoring Model

Each SKILL scored on 6 dimensions, 1-5 per dimension.

| # | Dimension | Source | Automation | Method |
|---|-----------|--------|------------|--------|
| 1 | **Compliance** | `skill-lint.py` | Fully automated | finding count + severity distribution |
| 2 | **Content Completenesseness** | `SCORE.sh` + line counts | Fully automated | section coverage + code-block density |
| 3 | **Command Syntax** | Kali VM runs + shellcheck | Human + automated | per-payload 5-class label (see §3) |
| 4 | **References** | URL scan + CVE status | Semi-automated | link liveness + CVE currency + tool version freshness |
| 5 | **MITRE/OWASP Alignment** | grep + human judgment | Semi-automated | ATT&CK T-code density + OWASP Top 10 mapping accuracy |
| 6 | **Usability** | Human reading | Fully human | entry barrier + doc flow + workflow operability |

### 2.1 Weighted Total

```
weighted_sum = (D1 × 1.0) + (D2 × 1.0) + (D3 × 1.5) + (D4 × 0.8) + (D5 × 1.0) + (D6 × 1.2)
max_possible = 5 × (1.0 + 1.0 + 1.5 + 0.8 + 1.0 + 1.2) = 32.5
score_percent = (weighted_sum / 32.5) × 100
```

Command Syntax (D3) and Usability (D6) carry higher weight because they capture the dimensions most directly affecting real-world usefulness.

### 2.2 Grade Bands

| Score | Grade | Interpretation |
|-------|-------|----------------|
| 90-100 | **Distinguished** | Benchmark template — other SKILLs should learn from this |
| 80-89 | **Excellent** | Production-ready; minor improvements possible |
| 70-79 | **Good** | Usable; some dimensions need work |
| 60-69 | **Fair** | Functional but with notable gaps |
| <60 | **Needs Improvement** | Material issues; should be priority for next minor |

---

## 3. Payload Safety Classification (for D3)

Every payload sampled for D3 validation must be classified into one of 5 classes **before** execution:

| Class | Meaning | Examples | Validation Method |
|-------|---------|----------|-------------------|
| **full** | Safe to run on VM (no damage) | `nmap -sV target`, `sqlmap --batch` against local DVWA | Run on VM + capture output |
| **sandbox-only** | Needs isolation (could affect VM) | `msfconsole exploit`, `hashcat -a 3` heavy load | Run inside docker with `--network none` |
| **theory-only** | Physical risk / hardware dep / legal risk / not reproducible on VM | CAN bus attacks, quantum crypto, RFID cloning, real phishing | Static analysis + literature cross-check |
| **deprecated** | Tool retired or command version outdated | `docker-compose v1`, `crackmapexec` | Note replacement command |
| **broken** | Syntax error / missing dependency / cannot run | Python 3.13 incompatibility, missing library | Document as finding |

### 3.1 Sampling Rules

- Minimum **10 payloads per SKILL** for D3 validation
- Sample stratified across payload types (recon, exploit, post-exploit, defense-evasion, etc.)
- Class distribution: aim for ≥30% `full` + ≥1 `theory-only` (most SKILLs have hardware-dependent items)
- If a SKILL has <10 explicit commands (e.g., council, search-first), document all available + note "limited payload set" in D3 rationale

### 3.2 D3 Scoring Rubric

| Pass Rate (full + sandbox-only) | Score |
|--------------------------------|-------|
| 95-100% pass + 0 broken | 5/5 |
| 85-94% pass + 0 broken | 4/5 |
| 70-84% pass OR 1 broken | 3/5 |
| 50-69% pass OR 2 broken | 2/5 |
| <50% pass OR ≥3 broken | 1/5 |

`theory-only` payloads don't count against pass rate (they're documented as "intentionally not executed").

---

## 4. Kali VM SOP

### 4.1 Connection

```bash
# Test connection (before each assessment)
sshpass -p secmind.cn ssh -o StrictHostKeyChecking=no parallels@10.211.55.5 \
  'uname -a; lsb_release -a 2>/dev/null'

# Expected output:
# Linux kali-linux-2025-2 ... aarch64 GNU/Linux
# Description: Kali GNU/Linux Rolling
# Release: 2026.1
```

### 4.2 Tool Inventory Check (per SKILL assessment)

```bash
# Extract tool list from SKILL frontmatter
TOOLS=$(awk '/^---$/{c++; if(c==2) exit; next} c==1 && /^allowed-tools:/{flag=1; next} flag && /^  - /{gsub(/[ -]/,"",$2); print $2} /^[^ ]/{flag=0}' skills/<name>/SKILL.md)

# Check each tool on VM
sshpass -p secmind.cn ssh parallels@10.211.55.5 \
  "for t in $TOOLS; do command -v \$t >/dev/null 2>&1 && echo \"  ✓ \$t\" || echo \"  ✗ \$t: missing\"; done"
```

If a tool is missing on VM, install on-demand OR mark payload as `theory-only` with rationale.

### 4.3 Safe Targets

- **`scanme.nmap.org`** — Nmap's official test target
- **Local DVWA / Juice Shop / Metasploitable** — `~/lab/` on VM (if present)
- **`127.0.0.1` / `localhost`** — for service enumeration
- **Local Docker containers** — spin up vulnerable images

### 4.4 Safety Boundaries

**NEVER run on VM**:
- Scans / attacks against external public targets (other than `scanme.nmap.org`)
- CAN bus / RFID / SDR / quantum (hardware-dependent; risk to host)
- Real phishing / social engineering templates (legal risk)
- Worms (EternalBlue, WannaCry) — VM isolation is not absolute
- Anything requiring credentials you don't own

**ALLOWED**:
- Local tool version queries (`tool --version`)
- Lab / CTF environments (DVWA, HackTheBox local, docker-compose labs)
- Static analysis (YARA, Sigma, Snort rule syntax checks)
- Read-only reconnaissance (DNS lookups, public OSINT)

### 4.5 Evidence Capture

```bash
# Per-payload evidence directory structure
skills/<name>/evidence/YYYY-MM-DD/
├── cmd-01-nmap-sV.log
├── cmd-02-sqlmap-version.log
├── cmd-03-...log
├── lint.json              # skill-lint output
├── score.json             # SCORE.sh output
└── summary.md             # human-readable summary
```

---

## 5. Guide Template (`usage-and-assessment.md`)

See [plan file](../../.claude/plans/skill-zesty-frog.md) §二 for canonical template. Key sections:

1. **Quick Assessment Dashboard** — 6-row table + weighted total + grade
2. **Usage Instructions** — elevator pitch + triggers + quick-start + pitfalls + cross-refs
3. **Capability Assessment Detail** — per-dimension evidence + score + notes
4. **Findings & Priorities** — P0/P1/P2/P3 findings table
5. **Validation Evidence** — file paths under `evidence/<date>/`
6. **Reviewer Sign-off** — name + date fields

---

## 6. Wave Schedule

### Pilot (2 SKILLs, ~6h)

| # | SKILL | v0.2.3.2 score | Expected range |
|---|-------|---------------|---------------|
| 1 | `ics-fieldbus-attack` | 5.0/5 (benchmark) | 85-95 |
| 2 | `multi-agent-runtime-engineering` | 3.75/5 (needs work) | 70-80 |

**Pilot purpose**: validate template, calibrate scoring, refine methodology.

### Wave 1 (10 SKILLs, ~15h)

Top 10 high-frequency attack SKILLs (see [plan §五](../../.claude/plans/skill-zesty-frog.md)).

### Wave 2 (3 SKILLs, ~4.5h)

Remaining v0.2.3.2 sampled SKILLs.

### Wave 3-7 (124 SKILLs, ~150-250h)

Remaining SKILLs, grouped 20-25 per Wave, ordered by `payloads_lines + testcases_lines + guides_count × 20`.

---

## 7. Version Cadence

- **Each Wave = 1 patch version** (v0.3.x, v0.4.x, ...)
- **No SKILL.md modifications** during assessment (assess-only mode)
- **New files only**: `usage-and-assessment.md` per SKILL + `evidence/` directories
- **Minor version bump** when accumulated findings warrant batch fixing (separate from this project)

---

## 8. Files Produced

### Project-level (this project)

| File | Purpose |
|------|---------|
| `docs/SKILL_ASSESSMENT_METHODOLOGY.md` | This document |
| `docs/SKILL_ASSESSMENT_MATRIX.md` | Running summary of all 139 SKILL scores |

### Per-SKILL (produced during assessment)

| File | Purpose |
|------|---------|
| `skills/<name>/guides/usage-and-assessment.md` | Human-readable assessment |
| `skills/<name>/evidence/<date>/cmd-*.log` | Kali VM run logs |
| `skills/<name>/evidence/<date>/lint.json` | skill-lint output |
| `skills/<name>/evidence/<date>/score.json` | SCORE.sh output |
| `skills/<name>/evidence/<date>/summary.md` | Human-readable validation summary |

---

## 9. Risk Management

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|-----------|
| Kali VM unreachable / credentials change | Medium | Medium | Test connection before each session; fallback to static analysis |
| Human reviewer time insufficient | High | High | Per-Wave review meetings; scheduled in calendar |
| Per-SKILL time exceeds 2h | Medium | Medium | Revise after Pilot; adjust weekly cadence |
| Payload execution damages VM | Low | Medium | Strict sandbox-only isolation; VM snapshots weekly |
| Scoring inconsistency between reviewers | High | Medium | Detailed SOP (this doc) + dual-reviewer sampling calibration |
| User loses interest mid-project | Medium | High | Per-Wave user approval checkpoint + value re-assessment |

---

## 10. Continuous Improvement

After each Wave:
- Revise this methodology based on lessons learned
- Update template if scoring rubric changes
- Re-calibrate grade bands if scores cluster (e.g., everyone getting 90+)

---

**Document version**: 1.0 (2026-08-09)
**Next review**: after Pilot completion
