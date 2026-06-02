# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**kali-claw** is an AI-powered penetration testing agent built on the OpenClaw framework. It continuously learns and operates across 49 security domains, mastering all 518 Kali Linux security tools. The runtime environment is Kali Linux 2025-2 (ARM64).

This repo is the agent's workspace — a structured knowledge base and configuration system, not a traditional software project. There are no build/test/lint commands.

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

### Skills Directory (`skills/`)

49 security skill domains, each following a consistent structure:
- `SKILL.md` — Skill definition, use cases, tools, methodology
- `payloads.md` — Attack payloads and commands by type
- `test-cases.md` — Structured test case templates
- `guides/` — Deep-dive learning materials

Domains include: API Security, Binary Analysis, Cloud Security, Container Security, Crypto Attacks, Digital Forensics, Mobile Security, Network Pentest, OSINT, Password Attack, Post-Exploitation, Social Engineering, Supply Chain Security, Web (XSS/SQLi/SSRF/Auth/Access Control), WiFi Pentest, and others.

## Key Conventions

- All content is in **English** (this is the `-en` variant of the workspace)
- Skills follow the `SKILL.md` + `payloads.md` + `test-cases.md` + `guides/` pattern — maintain this structure when adding new skills
- The agent operates under 12 Hacker Laws defined in `SOUL.md` — any behavioral changes must align with these principles
- Memory hierarchy: daily logs → chronicle → MEMORY.md (progressive distillation)
- `TEMPLATE.md` is the authoritative template for creating new OpenClaw agent workspaces

## Editing Guidelines

- **Adding a new skill domain**: Create directory under `skills/` with `SKILL.md`, `payloads.md`, `test-cases.md`, and optionally `guides/`. Update `TOOLS.md` and `IDENTITY.md` to reference the new domain.
- **Updating agent behavior**: Modify `SOUL.md` for principles, `AGENTS.md` for session flow, `IDENTITY.md` for skill tags.
- **Recording knowledge**: Write to `memory/` for daily logs. Important distilled knowledge goes to `MEMORY.md` (root) or `chronicle/`.
- **Health checks**: `HEARTBEAT.md` defines automated maintenance — modify when adding new subsystems that need monitoring.
