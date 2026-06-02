# TEMPLATE.md - New Agent Workspace Template

This template describes how to create a new OpenClaw agent workspace based on kali-claw.

---

## Quick Start

### 1. Copy the workspace

```bash
cp -r kali-claw/ <new-agent-name>/
cd <new-agent-name>/
```

### 2. Modify these 4 files

| File | What to Change |
|------|----------------|
| `AGENTS.md` | "Agent Config" block: name, environment, role, specialty |
| `IDENTITY.md` | Name, role description, skill tags, personality traits |
| `SOUL.md` | Nickname and role description in "Identity" section |
| `USER.md` | Captain information |

### 3. Clean up historical data

```bash
rm -f memory/*.md memory/alerts.txt
rm -rf chronicle/
```

### 4. Keep unchanged

The following are universal and reusable as-is:
- **Hacker Laws** in `SOUL.md` — applies to all security agents
- **Heartbeat framework** in `HEARTBEAT.md`
- **All 49 skills** in `skills/`
- **All guides** in `skills/*/guides/`
- **Validation infrastructure** in `validation/`

---

## File Structure

```
<agent-name>/
├── SOUL.md              # Identity + behavioral rules (MODIFY)
├── AGENTS.md            # Workspace config + session startup (MODIFY)
├── IDENTITY.md          # Skill tags + personality traits (MODIFY)
├── USER.md              # Captain profile (MODIFY)
├── MEMORY.md            # Long-term distilled knowledge (RESET)
├── TOOLS.md             # Tool inventory + learning progress
├── HEARTBEAT.md         # Automated heartbeat tasks
├── TEMPLATE.md          # This file
├── CLAUDE.md            # Claude Code integration guide
├── skills/              # 49 security skill domains (REUSE)
│   ├── api-security/
│   │   ├── SKILL.md
│   │   ├── payloads.md
│   │   ├── test-cases.md
│   │   └── guides/
│   ├── web-sqli/
│   ├── web-xss/
│   └── ... (49 domains)
├── validation/          # Quality scoring + integration tests
├── memory/              # Daily session logs (RESET)
├── chronicle/           # Monthly milestones (RESET)
├── bak/                 # Automatic backups
└── docs/                # Documentation
```

---

## Customization Examples

### Web Security Agent

```
AGENTS.md:
  Agent Name: web-hunter
  Role: Web Security Researcher
  Specialty: Web penetration testing + vulnerability discovery

IDENTITY.md:
  Name: web-hunter
  Skill tags: Keep Web Security rows, simplify others

SOUL.md:
  Nickname: web-hunter
  Keep hacker laws unchanged
```

### Cloud Security Agent

```
AGENTS.md:
  Agent Name: cloud-sentinel
  Role: Cloud Security Auditor
  Specialty: AWS/Azure/GCP security + Container security

IDENTITY.md:
  Name: cloud-sentinel
  Skill tags: Focus on cloud security and container security

TOOLS.md:
  Core tools: pacu, scoutsuite, kubeaudit, trivy
```

### Red Team Agent

```
AGENTS.md:
  Agent Name: red-phantom
  Role: Red Team Operator
  Specialty: Full kill chain operations + APT simulation

IDENTITY.md:
  Name: red-phantom
  Skill tags: Emphasize recon, exploitation, post-exploitation, social engineering

SOUL.md:
  Nickname: red-phantom
  Keep hacker laws unchanged
```

---

_Last updated: 2026-06-02_
