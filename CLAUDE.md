# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**kali-claw** is an AI-powered penetration testing agent built on the OpenClaw framework. It continuously learns and operates across 72 security domains, mastering all 518 Kali Linux security tools. The runtime environment is Kali Linux 2025-2 (ARM64).

This repo is the agent's workspace — a structured knowledge base and configuration system with automation scripts for validation, orchestration, and reporting.

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

72 security skill domains, each following a consistent structure aligned with the **Agent Skills Open Standard** (Anthropic, 2025):
- `SKILL.md` — Skill definition with YAML frontmatter (`name`, `description`, `compatibility`, `allowed-tools`, `metadata`), summary, use cases, tools, methodology, and defense perspective
- `payloads.md` — Attack payloads and commands by type
- `test-cases.md` — Structured test case templates
- `guides/` — Deep-dive learning materials

Each SKILL.md uses **progressive disclosure**:
- Stage 1 (Advertise): YAML frontmatter + `## Summary` — loaded during skill scanning
- Stage 2 (Quick Reference): `## Core Tools` + `## Methodology` — loaded on skill activation
- Stage 3 (Detailed): `## Practical Steps` + `## Defense Perspective` — loaded on task execution

Domains include: API Security, Binary Analysis, Cloud Security, Container Security, Crypto Attacks, Digital Forensics, Mobile Security, Network Pentest, OSINT, Password Attack, Post-Exploitation, Social Engineering, Supply Chain Security, Web (XSS/SQLi/SSRF/Auth/Access Control/XXE/File Inclusion/Deserialization), WiFi Pentest, Exploit Development, Payload Generation, AV/EDR Evasion, DNS Attacks, CMS Framework Attack, Steganography, Privilege Escalation, Network Sniffing & MITM, Bluetooth/RFID/NFC, Network Tunneling & Proxy, Firmware Reverse, SCADA/ICS Security, Database Attack, VoIP/SIP Attack, Anti-Forensics, Pentest Reporting, AD/LDAP Attack, Email Protocol Attack, Engagement Manager, Tool Mastery, and others.

## Key Conventions

- All content is in **English** (this is the `-en` variant of the workspace)
- Skills follow the `SKILL.md` + `payloads.md` + `test-cases.md` + `guides/` pattern — maintain this structure when adding new skills
- The agent operates under 12 Hacker Laws defined in `SOUL.md` — any behavioral changes must align with these principles
- Memory hierarchy: daily logs → chronicle → MEMORY.md (progressive distillation)
- `TEMPLATE.md` is the authoritative template for creating new OpenClaw agent workspaces

## Editing Guidelines

- **Adding a new skill domain**: Create directory under `skills/` with `SKILL.md` (must include YAML frontmatter per Agent Skills standard), `payloads.md`, `test-cases.md`, and optionally `guides/`. Run `python3 validation/update-skill-standard.py --skill <name>` to add standard-compliant frontmatter. Update `TOOLS.md` and `IDENTITY.md` to reference the new domain.
- **Updating agent behavior**: Modify `SOUL.md` for principles, `AGENTS.md` for session flow, `IDENTITY.md` for skill tags.
- **Recording knowledge**: Write to `memory/` for daily logs. Important distilled knowledge goes to `MEMORY.md` (root) or `chronicle/`.
- **Health checks**: `HEARTBEAT.md` defines automated maintenance — modify when adding new subsystems that need monitoring.
