# multi-agent-runtime-engineering — Usage Instructions & Capability Assessment

> **Assessment Date**: 2026-08-09 | **Reviewer**: Claude (automated + human review) | **Version assessed**: v0.2.0.2
> **Overall Score**: **77/100 (Good)** | **Findings**: P0:0 P1:1 P2:3 P3:1
> **Pilot**: 2nd SKILL under new methodology

## Quick Assessment Dashboard

| Dimension | Score (1-5) | Rationale |
|-----------|-------------|-----------|
| 1. Compliance (lint) | **5** | 0 errors / 0 warnings / 0 findings (perfect) |
| 2. Content Completeness | **5** | payloads 3032 lines + test-cases 972 lines; 12 H2 + 28 H3; 16 code blocks |
| 3. Command Syntax (Kali VM validated) | **3** | 7/10 PASS (70%); 3 fails are missing tools (jq/openai/anthropic/sem); 0 broken |
| 4. References | **2** | **0 unique URLs in SKILL.md**; 1 CVE; needs significant references to Anthropic/LangGraph/MopMonk |
| 5. MITRE/OWASP Alignment | **4** | 6 ATT&CK T-codes (added v0.2.5); frontmatter marked "N/A — meta-skill" with body ATT&CK Mapping section as proper substitute |
| 6. Usability | **4** | 5-layer stack architecture is clear; anti-pattern catalog is a highlight; high concept density (MopMonk 招一二三 may confuse new users) |
| **Weighted Total** | **77/100** | **Good** — solid engineering reference, weak on external citations |

---

## Usage Instructions

### What this SKILL does (elevator pitch)

Codifies the **runtime engineering patterns** for offensive multi-agent systems — structured JSON memory schemas, memory-driven convergence rules, shared-memory multi-agent coordination via POSIX `flock` + atomic writes + version vectors. Inspired by MopMonk Agent (CyberGym 73.1%, China #1) demonstrating that harness engineering beats base-model parameter scaling. This is a **meta-skill** — it provides engineering discipline, not specific attack techniques.

### When to use it (trigger scenarios)

1. You're orchestrating 3+ Claude/GPT/local-LLM agents on a complex engagement and need a coordination substrate
2. You want to reproduce MopMonk-style convergence (failed_attempts memory → no repeated dead-ends)
3. You're building a custom multi-agent runtime and want to avoid reinventing POSIX-based coordination
4. You need shared mutable state across parallel agents without a database or message broker
5. You're writing a write-ahead log of agent decisions for post-engagement replay

### How to start (quick-start in 5 steps)

1. **Verify Python + jq environment** — `python3 --version && jq --version` (if jq missing: `apt install jq`)
2. **Define the memory schema** — copy the 5 canonical schemas from `payloads.md` §1 (engagement, exploit-attempt, patch-diff-repro, evidence, decision-log)
3. **Spin up N parallel agents** with shared memory dir (`/tmp/engagement-mem/`); each agent uses `flock + atomic write` to update JSON
4. **Apply convergence rule** — every action yields a delta or triggers path switch; `failed_attempts_on_active_path` threshold drives switches
5. **Post-engagement replay** — walk the decision-log JSONL file; verify each convergence event and any path switch

### Common pitfalls for new users

- **"招一二三" terminology** — MopMonk Agent research uses Layer 1/2/3 (structured memory / convergence / shared coordination); the SKILL preserves the Chinese terms (扫地僧 / 招一/二/三) as cultural context but they map cleanly to Layer 1/2/3
- **POSIX flock semantics** — `flock(fd, LOCK_EX)` blocks; if you forget `LOCK_UN` your agents will deadlock. Use context managers.
- **Atomic write pattern** — write to temp file → fsync → rename; NOT write-then-fsync on the target file (race window)
- **Version vector arithmetic** — `(child, parent)` tuples must compare element-wise; naive `>` fails
- **Topology choice matters** — parallel-explorers for bug-class coverage; pipeline for phase-sequential (recon → exploit → exfil)

### Cross-references (related SKILLs)

| Related SKILL | When to switch |
|---------------|---------------|
| `multi-agent-collaboration` | Higher-level coordination patterns (Attack Phase Decomposition, Coordinator-Worker, etc.) |
| `autonomous-loops` | Self-reinforcing loop patterns (Sequential, Watch, Batch, Learning) |
| `verification-loop` | Six-phase verification process for agent outputs |
| `council` | Three-perspective analysis (Attacker/Defender/Auditor) for single-agent decisions |
| `continuous-learning` | Capturing agent run insights for future use |
| `detection-engineering` | Defenders using the symmetric patterns for parallel threat hunting |

---

## Capability Assessment Detail

### Dimension 1: Compliance

- **Evidence**: `skill-lint.py --skill multi-agent-runtime-engineering`
- **Result**: 0 errors, 0 warnings, 0 findings (perfect compliance)
- **Score**: **5/5**

### Dimension 2: Content Completeness

- **Evidence**:
  - SKILL.md: 12 H2 sections + 28 H3 subsections + 16 code blocks
  - payloads.md: 3032 lines (most detailed in the corpus)
  - test-cases.md: 972 lines (extensive)
  - guides/: 1 existing + this is the 2nd
- **Coverage**: 5-layer runtime stack fully described; anti-pattern catalog (5 patterns); convergence state machine; topology selection matrix
- **Score**: **5/5**

### Dimension 3: Command Syntax (Kali VM Validated)

- **Method**: Ran 10 commands on Parallels VM (Kali 2026.1)
- **Pass rate**: 7/10 = 70%
- **Class distribution**: 10 full (pure software SKILL, no theory-only)
- **Evidence file**: [evidence/2026-08-09/summary.md](../evidence/2026-08-09/summary.md)
- **Key failures**:
  - `jq` missing (F-002) — core to JSON manipulation patterns
  - `openai` / `anthropic` Python SDK missing (F-003)
  - `sem` (GNU parallel) missing (F-004)
- **Score**: **3/5** (rubric: "70-84% pass OR 1 broken" — we have 70% pass + 0 broken)

### Dimension 4: References

- **Evidence**:
  - **0 unique URLs in SKILL.md** ← critical gap (F-001)
  - 1 CVE reference
  - Chinese press references (36kr MopMonk coverage) embedded in description
- **Improvement opportunity** (high value): add links to
  - Anthropic multi-agent research blog series
  - LangGraph documentation
  - AutoGen (Microsoft) paper
  - Magentic-One (Microsoft) paper
  - MopMonk / CyberGym 73.1% case study (kali-claw internal docs)
- **Score**: **2/5**

### Dimension 5: MITRE/OWASP Alignment

- **Evidence**:
  - 6 ATT&CK T-codes in body (added v0.2.5): T1027, T1057, T1059.004, T1070.004, T1106, T1620
  - frontmatter `mitre: "N/A — meta-skill (runtime engineering, not a specific ATT&CK technique)"` correctly notes meta nature
  - Body has `## MITRE ATT&CK Mapping` section (added v0.2.5) with 6-row table mapping runtime patterns to techniques
- **Score**: **4/5** (excellent v0.2.5 improvement; frontmatter note is appropriate)

### Dimension 6: Usability

- **Strengths**:
  - 5-layer stack architecture is memorable and well-motivated
  - Anti-pattern catalog (5 patterns with detection rules and fixes) is unique and valuable
  - Convergence state machine has explicit schema
  - Cross-references to related SKILLs at the end
  - Skill Identity section clarifies the meta-skill positioning upfront
- **Weaknesses**:
  - High concept density — new users may bounce off "POSIX flock + atomic write + version vector" in the first paragraph
  - MopMonk Chinese terminology (扫地僧, 招一二三) may confuse non-Chinese-speaking readers despite v0.2.2 italic + EN gloss fixes
  - No worked example of a complete engagement from start to finish (just schemas and patterns)
- **Score**: **4/5**

---

## Findings & Priorities

| ID | Priority | Description | Recommended Fix |
|----|----------|-------------|-----------------|
| F-001 | **P1** | 0 unique URLs in SKILL.md — no external references | Add 5-10 references: Anthropic multi-agent research blog, LangGraph docs, AutoGen paper, Magentic-One, MopMonk case study, POSIX flock man page, JSON Schema spec |
| F-002 | P2 | `jq` not in Kali 2026.1 default | Add `apt install jq` to payloads.md prerequisites (jq is fundamental to JSON manipulation patterns) |
| F-003 | P2 | `openai` / `anthropic` Python SDK not installed by default | Add `pip install openai anthropic` to payloads.md prerequisites |
| F-004 | P2 | `sem` (GNU parallel) missing | Add `apt install parallel` to relevant payloads |
| F-005 | P3 | frontmatter `mitre: "N/A — meta-skill"` could note "see body MITRE ATT&CK Mapping for runtime-instantiated techniques" | Update frontmatter mitre field to reference body mapping |

**Total findings**: 1 P1 + 3 P2 + 1 P3 = 5 (0 P0)

---

## Validation Evidence

- **Kali VM run logs**: [evidence/2026-08-09/summary.md](../evidence/2026-08-09/summary.md)
- **Lint JSON**: [evidence/2026-08-09/lint.json](../evidence/2026-08-09/lint.json)
- **Kali VM**: parallels@10.211.55.5 (Kali 2026.1, kernel 6.18.12, aarch64)
- **Assessment method**: 10 payloads sampled (stratified by component: filesystem / Python / IPC / SDK / shell)

---

## Reviewer Sign-off

- Reviewer: Claude (automated assessment + human review of Pilot)
- Approved by: _______________ Date: _______
- Pilot review: this SKILL was the 2nd calibration target; confirmed that scoring rubric distinguishes between benchmark (ics-fieldbus-attack 79/100) and needs-improvement categories

---

## Reference Materials

- [Anthropic Multi-Agent Research System](https://www.anthropic.com/research/multi-agent-research-system) — blog series (TODO: F-001)
- [LangGraph documentation](https://langchain-ai.github.io/langgraph/) — competitor framework (TODO: F-001)
- [AutoGen paper (Microsoft)](https://arxiv.org/abs/2308.08155) — multi-agent conversation (TODO: F-001)
- [MopMonk CyberGym case study](../../../docs/mopmonk-research-and-kali-claw-plan.md) — kali-claw internal
- [SKILL Assessment Methodology](../../../docs/SKILL_ASSESSMENT_METHODOLOGY.md) — methodology reference
