# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**kali-claw** is an AI-powered penetration testing agent built on the OpenClaw framework. It continuously learns and operates across **139 security domains**, mastering all 518 Kali Linux security tools. The runtime environment is Kali Linux 2025-2 (ARM64).

This repo is the agent's workspace — a structured knowledge base and configuration system with automation scripts for validation, orchestration, and reporting.

> **Current Version**: v0.2.7 (skill assessment project complete, 139/139). See [RELEASE-v0.2.7.md](RELEASE-v0.2.7.md) for the latest milestone.

## Architecture

### Core Configuration Files (root level)

| File | Purpose |
|------|---------|
| `SOUL.md` | Agent identity, 12 Hacker Laws, behavioral guidelines — the "personality" |
| `AGENTS.md` | Workspace config and session startup sequence |
| `IDENTITY.md` | Skill tags, personality traits, and skill matrix |
| `USER.md` | Captain (user) profile and interaction preferences |
| `MEMORY.md` | Long-term distilled knowledge and key decisions |
| `TOOLS.md` | Tool inventory and learning progress tracking (518 tools) |
| `HEARTBEAT.md` | Automated health checks and maintenance schedule |
| `TEMPLATE.md` | Template for creating new OpenClaw agent workspaces |

### Phase 1 Project Artifacts (root level)

| File | Purpose |
|---------|---------|
| `RELEASE-v0.2.0.{1-8}.md + RELEASE-v0.2.{1,2,3}.md` | Phase 1 + Phase 2 Track 1 release notes |
| `PHASE1_{LAUNCH,EXECUTION,QUICK_START}.md` | Phase 1 planning documents |
| `PHASE2_PROGRESS.md` | Phase 2 standardization batch tracker (10 batches × 10 SKILLs) |
| `HIGH_PRIORITY_WORKPLAN.md` | 15 P0/P1 SKILL detailed improvement plan |
| `SKILL_REMEDIATION_LIST.json` | Full 137-SKILL audit data (issues, est_hours, completion_pct) |
| `TASK1_2_WORKFLOW.md` | Phase 1 SOP, Definition of Done, commit conventions |
| `KALI_TOOLS_BASELINE_2026_07.md` | 127-tool version reference |
| `TASK1_3_FRAMEWORK.md` | 7 new SKILL candidates (AI RedTeam/IdP/DLP/Edge/Quantum/SCA/5G) |

### Memory System

- **`memory/YYYY-MM-DD.md`** — Daily session logs
- **`MEMORY.md`** — Distilled long-term knowledge (root level)
- **`chronicle/YYYY-MM/*.md`** — Monthly milestone tracking
- **`bak/`** — Backup directory

### Automation Scripts (`validation/`)

| Script | Purpose |
|--------|---------|
| `heartbeat.sh` | Workspace health checks (`--fix`, `--json`) |
| `auto-backup.sh` | Backup rotation (`--restore`, `--keep N`) |
| `drift-detect.sh` | Configuration drift detection (`--create-baseline`, `--update-baseline`) |
| `scenario-runner.sh` | Cross-skill scenario execution (`--resume`, `--dry-run`) |
| `orchestrator.sh` | End-to-end penetration test workflow (`--target`, `--phase`, `--resume`) |
| `tool-selector.sh` | Target-to-tool mapping (`--target-type`, `--phase`, `--stealth`) |
| `report-generator.sh` | Automated report generation (`--source`, `--format`) |
| `update-skill-standard.py` | Align SKILL.md files with Agent Skills Open Standard (`--dry-run`, `--skill <name>`) |

### Engagement Templates (`validation/engagement-template/`)

- `targets.json.example` — Target configuration template
- `scope-rules.json.example` — Scope rules and safety configuration
- `report-template.md` — Standard penetration test report template

### Skills Directory (`skills/`)

**137 security skill domains**, each following a consistent structure aligned with the **Agent Skills Open Standard** (Anthropic, 2025):
- `SKILL.md` — Skill definition with YAML frontmatter (`name`, `description`, `version`, `compatibility`, `allowed-tools`, `metadata` including `last_reviewed`), summary, use cases, tools, methodology, and **Defense Triple**
- `payloads.md` — Attack payloads and commands by type
- `test-cases.md` — Structured test case templates
- `guides/` — Deep-dive learning materials

Each SKILL.md uses **progressive disclosure**:
- Stage 1 (Advertise): YAML frontmatter + `## Summary` — loaded during skill scanning
- Stage 2 (Quick Reference): `## Core Tools` + `## Methodology` — loaded on skill activation
- Stage 3 (Detailed): `## Practical Steps` + Defense Triple — loaded on task execution

#### Defense Triple (v0.2.0.2+ standard)

All newly standardized SKILLs include three defense sections:

1. **`### Defense Perspective`** — Multi-layer defense matrix (table format, ≥5 layers)
2. **`## Detection Methods`** — SIEM-ready detection rules:
   - Splunk SPL queries
   - Sigma rule file paths
   - Sysmon Event IDs
   - Falco / Tetragon runtime rules
   - Cloud-native (GuardDuty / Defender for Cloud)
3. **`## Defense Evasion Techniques`** — Modern attacker evasion patterns (5+ categories)

As of v0.2.0.4, 35/137 SKILLs (27%) meet this standard. See `SKILL_REMEDIATION_LIST.json` for per-SKILL status.

#### Domain Coverage

API Security, Binary Analysis, Cloud Security, Container Security, Crypto Attacks, Digital Forensics, Mobile Security, Network Pentest, OSINT, Password Attack, Post-Exploitation, Social Engineering, Supply Chain Security, Web (XSS/SQLi/SSRF/Auth/Access Control/XXE/File Inclusion/Deserialization), WiFi Pentest, Exploit Development, Payload Generation, AV/EDR Evasion, DNS Attacks, CMS Framework Attack, Steganography, Privilege Escalation, Network Sniffing & MITM, Bluetooth/RFID/NFC, Network Tunneling & Proxy, Firmware Reverse, SCADA/ICS Security, Database Attack, VoIP/SIP Attack, Anti-Forensics, Pentest Reporting, AD/LDAP Attack, AD CS Abuse, Email Protocol Attack, Engagement Manager, Tool Mastery, AI Agent Security, LLM Red Team, Agentic Pentest, 5G Telecom Attack, Automotive Vehicle Security, Blockchain L2 Attack, Cloud-Native Vuln Research, CI/CD Supply Chain Attack, PAM Privilege Attack, CSPM/CASB Attack, SASE/SSE Attack, and others.

## Key Conventions

- All content is in **English** (this is the `-en` variant of the workspace)
- Skills follow the `SKILL.md` + `payloads.md` + `test-cases.md` + `guides/` pattern — maintain this structure when adding new skills
- The agent operates under 12 Hacker Laws defined in `SOUL.md` — any behavioral changes must align with these principles
- Memory hierarchy: daily logs → chronicle → MEMORY.md (progressive distillation)
- `TEMPLATE.md` is the authoritative template for creating new OpenClaw agent workspaces

## Editing Guidelines

- **Adding a new skill domain**: Create directory under `skills/` with `SKILL.md` (must include YAML frontmatter per Agent Skills standard, including `version: "0.2.0.2"` and `last_reviewed: "YYYY-MM-DD"`), `payloads.md`, `test-cases.md`, and optionally `guides/`. Run `python3 validation/update-skill-standard.py --skill <name>` to add standard-compliant frontmatter. Update `TOOLS.md` and `IDENTITY.md` to reference the new domain.
- **Standardizing an existing SKILL (Phase 2 SOP)**: Add the Defense Triple (Defense Perspective table + Detection Methods + Defense Evasion Techniques) per `TASK1_2_WORKFLOW.md`. Bump `version` to `0.2.0.2` and set `last_reviewed`. Verify translation residue is 0 (run `python3 -c "import re; c=open('skills/<name>/SKILL.md').read(); print(len(re.findall(r'[a-z][一-鿿]|[一-鿿][a-z]', c)))"`).
- **Updating agent behavior**: Modify `SOUL.md` for principles, `AGENTS.md` for session flow, `IDENTITY.md` for skill tags.
- **Recording knowledge**: Write to `memory/` for daily logs. Important distilled knowledge goes to `MEMORY.md` (root) or `chronicle/`.
- **Health checks**: `HEARTBEAT.md` defines automated maintenance — modify when adding new subsystems that need monitoring.
- **Version baselines**: All SKILL `version:` fields follow the kali-claw release version (Phase 1 = `0.2.0.2`). Do not use legacy 0.1.x per-SKILL numbering.

## Phase 1 Workflow

When working on Phase 1 tasks (SKILL library enhancement):

1. **Before starting**: Read `SKILL_REMEDIATION_LIST.json` to identify which SKILLs need work and their specific issues.
2. **Branch strategy**: Work on `phase2/standardization` (or `phase1/skill-audit` for high-priority work). Use lightweight cherry-pick strategy if push fails (see `TASK1_2_WORKFLOW.md`).
3. **Commit conventions**: `refactor(<skill>): <change>` for SKILL improvements; `feat(<skill>):` for new SKILLs; `docs:` for documentation.
4. **Network considerations**: SOCKS5 proxy at `127.0.0.1:1086` is configured globally. Push large changes via lightweight branch if packfile exceeds 100MB (see RELEASE-v0.2.1.md Appendix for case study).
5. **Definition of Done**: Verify against `TASK1_2_WORKFLOW.md` DoD checklist before committing.
