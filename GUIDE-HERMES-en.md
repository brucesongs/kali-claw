# kali-claw Skill Pack Migration Guide: OpenClaw to Hermes Agent

> A comprehensive guide to migrating kali-claw's 49 security skill domains from the OpenClaw framework to Hermes Agent.

---

## Table of Contents

1. [Migration Overview](#1-migration-overview)
2. [Environment Setup](#2-environment-setup)
3. [Approach 1: Automatic Migration (Beginners)](#3-approach-1-automatic-migration-beginners)
4. [Approach 2: Semi-Manual Migration (Advanced Users)](#4-approach-2-semi-manual-migration-advanced-users)
5. [Approach 3: Fully Manual Migration (Full Control)](#5-approach-3-fully-manual-migration-full-control)
6. [Post-Migration Configuration](#6-post-migration-configuration)
7. [FAQ](#7-faq)
8. [Architecture Comparison and Reference](#8-architecture-comparison-and-reference)

---

## 1. Migration Overview

### 1.1 Why Migrate to Hermes

Hermes Agent (by Nous Research) is an open-source, self-evolving AI agent framework that offers several capabilities that complement kali-claw's security knowledge base:

**Hermes advantages:**

- **Self-learning loop** -- Hermes automatically distills experience into reusable skill files. Every pentest engagement generates new knowledge that is automatically structured and stored.
- **Persistent memory** -- SQLite database with FTS5 full-text search and LLM-powered summarization. Search across thousands of memories in milliseconds instead of scanning text files.
- **200+ model support** -- Model-agnostic via OpenRouter. Switch between Claude, GPT-4, Llama, Mistral, and 200+ other models without changing your skill files.
- **Multi-platform gateways** -- Telegram, Discord, Slack, WhatsApp, Signal, QQ, and CLI. Use your pentest agent from any chat platform.
- **Active community** -- 100k+ GitHub stars, frequent updates, growing ecosystem of shared skills.

**kali-claw skill pack value:**

- **49 security skill domains** -- covering web exploitation, network pentest, OSINT, crypto attacks, cloud security, mobile security, and more.
- **518 Kali Linux tool knowledge base** -- mastery tracking, usage notes, and learning strategies for the complete Kali toolset.
- **Thousands of lines of payloads and test cases** -- ready-to-use attack payloads organized by type, and structured test case templates with prerequisites and expected results.
- **12 Hacker Laws** -- behavioral guidelines derived from real-world security philosophy.

**Key point:** Migration does not mean abandoning OpenClaw. It lets kali-claw's security knowledge work on Hermes too. You can run both frameworks in parallel and share the same skills directory via git.

### 1.2 Migration Strategy Overview

Three approaches, ordered by increasing complexity and control:

| Approach | Difficulty | Time Required | Best For |
|----------|-----------|---------------|----------|
| **1. Automatic Migration** | Beginner | 5 minutes | Quick evaluation, getting started fast |
| **2. Semi-Manual Migration** | Advanced | 30 minutes | Production use, reference stubs for all skills |
| **3. Fully Manual Migration** | Expert | 4-8 hours | Complete control, custom optimizations |

**Recommendation:** Start with Approach 1 to validate the process. Then use Approach 2 to create reference stubs for all 49 skill domains.

### 1.3 Before/After Comparison

The following table maps every OpenClaw workspace component to its Hermes equivalent:

| kali-claw (OpenClaw) | Hermes Agent | Migration Method |
|---------------------|-------------|------------------|
| `SOUL.md` | `personality.md` | Auto or manual |
| `USER.md` | `config.yaml` (user section) | Manual |
| `AGENTS.md` | `config.yaml` (agent section) | Manual |
| `IDENTITY.md` | `skills/*.md` (YAML frontmatter tags) | Manual |
| `skills/*/SKILL.md` | `skills/skill-name.md` | Reference stub |
| `skills/*/payloads.md` | `skills/skill-name.md` (## Examples) | Reference stub |
| `skills/*/test-cases.md` | `skills/skill-name.md` (## Test Cases) | Reference stub |
| `skills/*/guides/` | `skills/skill-name.md` (## Deep Dive) or attachments | Reference stub |
| `MEMORY.md` | SQLite memory store | Auto-import |
| `memory/*.md` | SQLite memory store | Auto-import |
| `TOOLS.md` | `config.yaml` (tools section) | Manual |
| `HEARTBEAT.md` | `config.yaml` (cron section) | Manual |
| `chronicle/` | SQLite memory store | Auto-import |

---

## 2. Environment Setup

### 2.1 Install Hermes Agent

```bash
# Install Hermes (Linux, macOS, WSL2)
curl -fsSL https://get.hermes.dev | bash

# Verify installation
hermes --version

# Expected output: hermes x.y.z (version number)
```

**Troubleshooting:**

- If `curl` fails with a certificate error, try `curl -fsSL --insecure https://get.hermes.dev | bash`
- On macOS, if you get a "developer cannot be verified" error, run `xattr -d com.apple.quarantine $(which hermes)`
- On Windows, use WSL2 (Windows Subsystem for Linux)

### 2.2 Check OpenClaw Workspace

Verify that your kali-claw workspace exists and contains the expected files:

```bash
# Check workspace location
ls ~/.openclaw/workspace-kali-claw/

# You should see these files:
# SOUL.md       AGENTS.md     USER.md       IDENTITY.md
# MEMORY.md     TOOLS.md      HEARTBEAT.md  skills/
# memory/       chronicle/

# Verify skill count
ls ~/.openclaw/workspace-kali-claw/skills/ | wc -l
# Expected: 49 (or close, depending on your version)
```

If your workspace is at a different path, note it for the migration commands below.

### 2.3 Backup Your Workspace

Before any migration, create a complete backup:

```bash
# Full workspace backup
cp -r ~/.openclaw/workspace-kali-claw/ ~/kali-claw-backup-$(date +%Y%m%d)/

# Verify backup
ls ~/kali-claw-backup-$(date +%Y%m%d)/skills/ | wc -l
```

**Why backup matters:** The migration process is non-destructive (it reads from OpenClaw and writes to Hermes), but having a backup ensures you can always revert if something goes wrong.

---

## 3. Approach 1: Automatic Migration (Beginners)

### 3.1 Run the Migration Command

Hermes includes a built-in OpenClaw migration tool that auto-detects workspaces under `~/.openclaw/`.

```bash
# Step 1: Preview mode (dry run -- shows what will be migrated without making changes)
hermes claw migrate --dry-run

# Review the output carefully. You should see:
# - Workspace detected: kali-claw
# - Skills found: 49 domains
# - Memory files found: X daily logs
# - Personality file found: SOUL.md

# Step 2: Actual migration
hermes claw migrate

# If your workspace is at a custom path:
hermes claw migrate --workspace /path/to/workspace-kali-claw/
```

### 3.2 What Auto-Migration Does

The `hermes claw migrate` command performs the following transformations automatically:

1. **Detects all workspaces** under `~/.openclaw/` and lists them for selection.
2. **Imports SOUL.md** -- converts to Hermes `personality.md` format. The 12 Hacker Laws become behavioral rules, Core Truths become personality traits, and Boundaries become Hermes boundaries.
3. **Imports skills/** -- each `SKILL.md` is imported as a Hermes skill file with YAML frontmatter. The Description becomes the `## When to Use` section, and the Methodology becomes the `## Instructions` section. Note: auto-migration only processes SKILL.md; payloads.md and test-cases.md are left as attachments. Use Approach 2 (reference stubs) for full access to all kali-claw files.
4. **Imports memory/** -- daily memory logs and MEMORY.md are imported into the SQLite memory store with FTS5 indexing. You can search across all memories instantly.
5. **Imports chronicle/** -- monthly milestones are imported as memory entries with date metadata.
6. **Imports API keys and channel configs** -- if present in the OpenClaw configuration.

### 3.3 Limitations of Auto-Migration

Auto-migration handles the basics well, but has important limitations:

| What Auto-Migration Handles | What It Does NOT Handle |
|-----------------------------|------------------------|
| SKILL.md main content | payloads.md (kept as attachment, not parsed) |
| Basic personality conversion | test-cases.md (kept as attachment, not parsed) |
| Memory file import | guides/ directory (kept as attachment) |
| API key transfer | Python/Shell scripts in guides/ |
| Workspace detection | ECC orchestration format conversion |
| YAML frontmatter generation | Cross-skill references and links |
| | USER.md preference migration |
| | TOOLS.md tool registry conversion |

**What this means:** After auto-migration, your skills will work for basic queries, but the rich payload collections and test case templates will not be natively accessible by Hermes. To get full functionality, use Approach 2 to create reference stubs that point to kali-claw's original files (Hermes reads the referenced files when the skill is triggered). Use Approach 3 for fully hand-crafted stubs with custom descriptions.

### 3.4 Verify Migration Results

```bash
# List all imported skills
hermes skills list

# Expected: ~49 skills listed with names like:
# web-sqli, web-xss, network-pentest, osint, ...

# Search imported memories
hermes memory search "penetration testing"

# Test a specific skill
hermes skills test web-sqli

# View personality
hermes personality show
```

If the skill count is lower than expected, check the migration log at `~/.hermes/logs/migration.log` for errors.

---

## 4. Approach 2: Semi-Manual Migration (Advanced Users)

This approach gives you production-quality migration: auto-migration for the base data, then creation of lightweight Hermes stubs that reference kali-claw files in-place. kali-claw's `skills/` directory remains completely untouched.

### 4.1 Run Auto-Migration First for Base Data

```bash
# Preview
hermes claw migrate --dry-run

# Execute base migration
hermes claw migrate
```

This creates the skeleton. Now we will create reference stubs so Hermes can access kali-claw's full skill content.

### 4.2 Create Lightweight Reference Stubs for kali-claw Skills

kali-claw has 4 files per skill domain. Instead of merging or converting these files, we create lightweight Hermes skill stubs that **reference kali-claw files in-place**. The original `skills/` directory remains completely untouched.

**Key principle:** kali-claw skills/ stays as-is. Hermes gets small stub files that point to kali-claw paths. Hermes reads the references when the skill is triggered.

**Reference mapping:**

| OpenClaw Source | Hermes Stub Section | How |
|----------------|---------------------|-----|
| `SKILL.md` Description + Use Cases | `## When to Use` | Summary with reference to SKILL.md |
| `SKILL.md` Methodology + Practical Steps | `## Instructions` | Summary with reference to SKILL.md |
| `payloads.md` all payloads | `## Examples` | Reference to payloads.md |
| `test-cases.md` all test cases | `## Test Cases` | Reference to test-cases.md |
| `guides/` directory | `## Deep Dive` | Reference to guides/ directory |
| `SKILL.md` Hacker Laws | `## Notes` | Reference to SKILL.md |

**Complete stub example -- web-sqli:**

Below is a lightweight Hermes skill stub that references kali-claw's `web-sqli` files without modifying them.

**Resulting Hermes stub file** (`~/.hermes/skills/web-sqli.md`):

```markdown
---
name: web-sqli
version: 1.0
tags: [sqli, sql-injection, web-security, database, owasp, pentest]
triggers: ["sql injection", "sqli", "union select", "blind injection", "error-based injection", "sqlmap", "double query", "waf bypass"]
references:
  - path: ~/.openclaw/workspace-kali-claw/skills/web-sqli/SKILL.md
  - path: ~/.openclaw/workspace-kali-claw/skills/web-sqli/payloads.md
  - path: ~/.openclaw/workspace-kali-claw/skills/web-sqli/test-cases.md
---

# SQL Injection

## When to Use

When testing web applications for SQL injection vulnerabilities. Covers detection, exploitation, data extraction, and privilege escalation across MySQL, PostgreSQL, MSSQL, and Oracle.

## Instructions

Read the referenced kali-claw files for complete methodology and tool guidance:
- **SKILL.md** -- Step-by-step methodology, attack chain (Detection -> Fingerprinting -> Exploitation -> Data Extraction -> Privilege Escalation), core tools (sqlmap, Burp Suite, curl), and defense perspective.

## Examples

See the referenced kali-claw file for ready-to-use attack payloads:
- **payloads.md** -- 10 categories of injection payloads including UNION, error-based, boolean blind, time blind, double query, WAF bypass, and cross-database techniques.

## Test Cases

See the referenced kali-claw file for structured test procedures:
- **test-cases.md** -- 12 test case templates (TC-S001 through TC-S010+) covering GET/POST injection detection, UNION extraction, error-based, blind, WAF bypass, and file read/write testing.
```

This stub is roughly 30 lines instead of 300+ lines for a merged file. The full content stays in kali-claw's `skills/` directory where it belongs. When Hermes activates the skill, it reads the referenced files.

### 4.3 Batch Stub Creation Script

The following Python script iterates over all skill directories and creates lightweight Hermes stub files that **reference** kali-claw files in-place. It does not read, modify, or merge kali-claw skill content -- it only reads directory names and creates small pointer files.

```python
#!/usr/bin/env python3
"""
kali-claw to Hermes Stub Creator
Creates lightweight Hermes skill stubs that reference kali-claw files in-place.
Does NOT modify any files in the kali-claw skills/ directory.

Usage:
    python3 create_stubs.py [--source ~/.openclaw/workspace-kali-claw/skills]
                            [--target ~/.hermes/skills]
                            [--dry-run]
"""

import os
import sys
import argparse
from pathlib import Path


def create_stub(skill_dir: Path, target_dir: Path, dry_run: bool = False) -> str:
    """Create a lightweight Hermes stub referencing kali-claw files."""
    skill_name = skill_dir.name
    skill_md = skill_dir / "SKILL.md"
    payloads_md = skill_dir / "payloads.md"
    test_cases_md = skill_dir / "test-cases.md"
    guides_dir = skill_dir / "guides"

    if not skill_md.exists():
        return f"SKIP {skill_name}: no SKILL.md found"

    skill_path = skill_dir.resolve()

    # Build references list
    references = [f"  - path: {skill_path / 'SKILL.md'}"]
    if payloads_md.exists():
        references.append(f"  - path: {skill_path / 'payloads.md'}")
    if test_cases_md.exists():
        references.append(f"  - path: {skill_path / 'test-cases.md'}")
    if guides_dir.exists() and any(guides_dir.glob("*.md")):
        references.append(f"  - path: {skill_path / 'guides'}")

    # Build tags from skill name
    name_parts = skill_name.replace("-", " ").split()
    tags = ["pentest", "security"] + name_parts
    tags = list(dict.fromkeys(tags))[:10]  # deduplicate, cap at 10

    # Build triggers
    triggers = [skill_name, skill_name.replace("-", " ")]

    # Human-readable title
    title = skill_name.replace("-", " ").title()

    # Assemble stub content
    lines = [
        "---",
        f"name: {skill_name}",
        "version: 1.0",
        f"tags: [{', '.join(tags)}]",
        f"triggers: {triggers}",
        "references:",
        *references,
        "---",
        "",
        f"# {title}",
        "",
        "## When to Use",
        "",
        f"When working with {title.lower()}-related tasks.",
        "",
        "## Instructions",
        "",
        "Read the referenced kali-claw files for complete methodology:",
        "- **SKILL.md** -- Step-by-step methodology, tools, and practical steps",
    ]

    if payloads_md.exists():
        lines.append("- **payloads.md** -- Ready-to-use attack payloads organized by type")
    if test_cases_md.exists():
        lines.append("- **test-cases.md** -- Structured test procedures with prerequisites and expected results")
    if guides_dir.exists() and any(guides_dir.glob("*.md")):
        lines.append("- **guides/** -- Deep-dive learning materials and scripts")

    lines.append("")
    lines.append("## Examples")
    lines.append("")
    lines.append("See payloads.md in the referenced kali-claw directory for ready-to-use payloads.")
    lines.append("")
    lines.append("## Test Cases")
    lines.append("")
    lines.append("See test-cases.md in the referenced kali-claw directory for structured test procedures.")
    lines.append("")

    output_content = "\n".join(lines)
    output_path = target_dir / f"{skill_name}.md"

    if dry_run:
        return f"WOULD WRITE: {output_path} ({len(output_content)} chars)"

    target_dir.mkdir(parents=True, exist_ok=True)
    output_path.write_text(output_content, encoding="utf-8")
    return f"OK {skill_name} -> {output_path} ({len(output_content)} chars)"


def main():
    parser = argparse.ArgumentParser(
        description="Create Hermes skill stubs referencing kali-claw files"
    )
    parser.add_argument(
        "--source",
        default=os.path.expanduser("~/.openclaw/workspace-kali-claw/skills"),
        help="Path to kali-claw skills directory (read-only)",
    )
    parser.add_argument(
        "--target",
        default=os.path.expanduser("~/.hermes/skills"),
        help="Path to Hermes skills output directory",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview stubs without writing files",
    )
    parser.add_argument(
        "--skill",
        default=None,
        help="Create stub for only a specific skill (e.g., web-sqli)",
    )
    args = parser.parse_args()

    source_dir = Path(args.source)
    target_dir = Path(args.target)

    if not source_dir.exists():
        print(f"Error: Source directory not found: {source_dir}")
        sys.exit(1)

    # Find skill directories (read-only scan)
    if args.skill:
        skill_dirs = [source_dir / args.skill]
    else:
        skill_dirs = sorted(
            d for d in source_dir.iterdir()
            if d.is_dir() and (d / "SKILL.md").exists()
        )

    print(f"Found {len(skill_dirs)} skill(s) to create stubs for")
    print(f"Source: {source_dir} (read-only, will not be modified)")
    print(f"Target: {target_dir}")
    print(f"Dry run: {args.dry_run}")
    print("-" * 60)

    success_count = 0
    skip_count = 0

    for skill_dir in skill_dirs:
        result = create_stub(skill_dir, target_dir, dry_run=args.dry_run)
        print(result)
        if result.startswith("OK") or result.startswith("WOULD WRITE"):
            success_count += 1
        else:
            skip_count += 1

    print("-" * 60)
    print(f"Stubs created: {success_count}, Skipped: {skip_count}")

    if args.dry_run:
        print("\nThis was a dry run. Remove --dry-run to write files.")


if __name__ == "__main__":
    main()
```

**How to use the script:**

```bash
# Save the script to a file
nano ~/create_stubs.py
# (paste the script above, then save)

# Make it executable
chmod +x ~/create_stubs.py

# Preview stubs (dry run)
python3 ~/create_stubs.py --dry-run

# Create stub for a single skill to verify
python3 ~/create_stubs.py --skill web-sqli --dry-run

# Create stubs for all skills
python3 ~/create_stubs.py

# Create stubs to a custom output directory
python3 ~/create_stubs.py --target ~/hermes-skills-preview/
```

**Important:** This script only reads directory names from kali-claw's `skills/`. It never reads, parses, copies, or modifies any skill content files.

### 4.4 Map ECC Orchestration Patterns to Hermes Workflows

kali-claw uses ECC (Event-Condition-Command) orchestration patterns. Hermes uses a simpler workflow model. The following mapping table shows how ECC patterns correspond to Hermes workflows. This mapping is for reference only -- no kali-claw files need to be modified.

| kali-claw ECC Pattern | Hermes Workflow | Description |
|----------------------|-----------------|-------------|
| Sequential Pipeline | `workflow: sequential` | Step-by-step pentest flow (Recon -> Scan -> Exploit -> Report) |
| Watch Loop | `workflow: watch` | Monitoring a target for changes (new subdomains, open ports) |
| Batch Processing | `workflow: parallel` | Processing multiple targets (scanning 100 URLs) |
| Learning Cycle | `workflow: iterative` | Tool mastery progression (learn -> practice -> review) |
| Meta-Skill | `workflow: composite` | Combining multiple skills (council analysis) |
| Cross-cutting Interceptor | `workflow: interceptor` | Safety enforcement (safety-guard checking every command) |

**How to add workflow to a Hermes stub:**

Add the `workflow` field to the YAML frontmatter of the Hermes stub file (the file in `~/.hermes/skills/`, not the kali-claw original):

```yaml
---
name: network-pentest
version: 1.0
tags: [network, pentest, nmap, scanning]
triggers: ["network scan", "port scan", "nmap"]
references:
  - path: ~/.openclaw/workspace-kali-claw/skills/network-pentest/SKILL.md
workflow: sequential
---
```

For composite workflows that combine multiple skills:

```yaml
---
name: security-audit
version: 1.0
tags: [audit, owasp, comprehensive]
triggers: ["security audit", "full assessment"]
references:
  - path: ~/.openclaw/workspace-kali-claw/skills/web-sqli/SKILL.md
  - path: ~/.openclaw/workspace-kali-claw/skills/web-xss/SKILL.md
  - path: ~/.openclaw/workspace-kali-claw/skills/web-ssrf/SKILL.md
  - path: ~/.openclaw/workspace-kali-claw/skills/api-security/SKILL.md
workflow: composite
depends_on: [web-sqli, web-xss, web-ssrf, api-security]
---
```

### 4.5 Validate Each Stub

After creating stubs, validate each one:

```bash
# Validate a single skill
hermes skills validate web-sqli

# Test a single skill
hermes skills test web-sqli

# Validate all skills at once
hermes skills validate --all

# Test all skills
hermes skills test --all

# View detailed validation output
hermes skills validate --all --verbose
```

Common validation issues and fixes:

| Issue | Cause | Fix |
|-------|-------|-----|
| "Missing frontmatter" | No YAML header | Add `---` block at the top |
| "Invalid trigger format" | Triggers not a list | Use `["keyword1", "keyword2"]` syntax |
| "Skill too large" | File exceeds size limit | Stub should be small; remove any inline content, use references only |
| "Duplicate triggers" | Same trigger in multiple skills | Make triggers more specific |
| "Missing Instructions section" | Empty Instructions | Ensure Instructions section references SKILL.md |

---

## 5. Approach 3: Fully Manual Migration (Full Control)

This approach gives you complete control over every aspect of the migration. Use this when you want to customize each skill stub individually, optimize trigger keywords, or hand-craft stubs with rich descriptions.

### 5.1 Create Hermes Skills Directory

```bash
# Create the skills directory
mkdir -p ~/.hermes/skills/

# Verify Hermes config directory exists
ls ~/.hermes/
# Should show: config.yaml  personality.md  skills/  memory/
```

### 5.2 Create Custom Stub for a Single Skill

Detailed manual stub creation steps using `ai-security` as an example. This creates a Hermes skill stub that references kali-claw's original files -- kali-claw files are not modified.

**Step 1: Browse the OpenClaw source files (read-only)**

```bash
# Read the source files to understand the skill (do NOT modify them)
cat ~/.openclaw/workspace-kali-claw/skills/ai-security/SKILL.md
cat ~/.openclaw/workspace-kali-claw/skills/ai-security/payloads.md 2>/dev/null
cat ~/.openclaw/workspace-kali-claw/skills/ai-security/test-cases.md 2>/dev/null
ls ~/.openclaw/workspace-kali-claw/skills/ai-security/guides/ 2>/dev/null
```

**Step 2: Create the Hermes stub file**

Open a new file `~/.hermes/skills/ai-security.md` and write a stub with YAML frontmatter and references to kali-claw paths:

```markdown
---
name: ai-security
version: 1.0
tags: [ai, llm, prompt-injection, model-security, adversarial, pentest]
triggers: ["ai security", "llm security", "prompt injection", "model exploitation", "adversarial attack", "ai fuzzing"]
references:
  - path: ~/.openclaw/workspace-kali-claw/skills/ai-security/SKILL.md
  - path: ~/.openclaw/workspace-kali-claw/skills/ai-security/payloads.md
  - path: ~/.openclaw/workspace-kali-claw/skills/ai-security/test-cases.md
---

# AI Security

## When to Use

When testing AI/LLM systems for prompt injection, adversarial inputs, and model exploitation vulnerabilities.

## Instructions

Read the referenced kali-claw files for complete methodology:
- **SKILL.md** -- Step-by-step methodology, tools, and practical steps
- **payloads.md** -- Ready-to-use adversarial prompt payloads organized by type
- **test-cases.md** -- Structured test procedures with prerequisites and expected results

## Examples

See payloads.md in the referenced kali-claw directory for ready-to-use adversarial prompts.

## Test Cases

See test-cases.md in the referenced kali-claw directory for structured AI security test procedures.
```

Tips for writing good triggers:
- Include the full skill name (with spaces replacing hyphens)
- Include common abbreviations and aliases
- Include the primary tool names used in the skill
- Include the attack type or technique names
- Keep each trigger under 5 words for best matching

**Step 3: Save and validate**

```bash
# Save the file
# Then validate
hermes skills validate ai-security
hermes skills test ai-security
```

### 5.3 Migrate Agent Personality

Convert SOUL.md to Hermes personality.md format.

**OpenClaw SOUL.md structure:**
- Identity (nickname, role, creator, runtime, work mode)
- 12 Hacker Laws (principles)
- Core Truths (behavioral rules)
- Boundaries (ethical limits)

**Hermes personality.md structure:**
- Name and role
- Behavioral rules
- Personality traits
- Boundaries

**Conversion steps:**

```bash
# Create personality.md
cat > ~/.hermes/personality.md << 'EOF'
---
name: kali-claw
role: Senior Penetration Testing Engineer
version: 1.0
---

# kali-claw

You are a senior penetration testing engineer and master of all Kali Linux security tools.

## Behavioral Rules

1. **First Principles Thinking** -- Break problems down to the most fundamental facts. Question every "obvious" assumption and reason from basic principles.
2. **Divergent Thinking First** -- Think of at least 3 solutions for every problem, then pick the best. There is always more than one path.
3. **Minimize Attack Surface** -- Less exposure means less risk. Every open port, service, and interface is a potential entry point.
4. **Defense in Depth** -- Never rely on a single layer of defense. Multi-layer protection prevents total collapse from a single point of failure.
5. **Least Privilege** -- Grant only the access that is necessary. Excessive permissions are a stepping stone for attackers.
6. **Assume Breach** -- Design systems assuming the attacker is already inside. Build detection, response, and recovery on this premise.
7. **Obscurity Is Not Security** -- Security comes from design and verification, not from hiding.
8. **Trust but Verify** -- Do not trust any input. Verify everything.
9. **Information Wants to Be Free** -- Knowledge sharing drives security progress. Share discoveries, disclose vulnerabilities, collaborate on defense.
10. **Skill Over Credentials** -- Judge by capability, not by title.
11. **The Weakest Link Is Human** -- People are the weakest link in the security chain. Always consider the human factor.
12. **Murphy's Security Law** -- If it can be exploited, it will be exploited. Do not rely on luck. Do not delay fixes.

## Personality Traits

- Analytical and methodical in approach
- Proactive in identifying security risks
- Clear and direct in communication
- Patient when teaching security concepts
- Cautious about ethical boundaries

## Boundaries

- Never attack systems without explicit authorization
- Never store or transmit sensitive data without encryption
- Always report vulnerabilities through proper channels
- Prioritize safety in every operation
- Refuse requests that violate laws or ethics
EOF
```

### 5.4 Migrate Memory System

Hermes provides multiple options for importing memory data:

```bash
# Option 1: Import all memory files at once (recommended)
hermes claw migrate --memory-only

# Option 2: Import individual memory files
hermes memory import --file ~/.openclaw/workspace-kali-claw/memory/2026-05-17.md
hermes memory import --file ~/.openclaw/workspace-kali-claw/memory/2026-05-16.md
# ... repeat for each daily log

# Option 3: Import MEMORY.md (long-term distilled knowledge)
hermes memory import --file ~/.openclaw/workspace-kali-claw/MEMORY.md

# Option 4: Import chronicle files
hermes memory import --file ~/.openclaw/workspace-kali-claw/chronicle/2026-05/milestones.md

# Verify memory import
hermes memory stats
hermes memory search "nmap"
hermes memory search "sql injection"
```

**Memory import tips:**
- Import memory files in chronological order (oldest first) for best context
- Daily logs are imported as individual memory entries with date metadata
- MEMORY.md is imported as a single entry with "distilled" metadata
- Chronicle entries are imported with month-level metadata
- After import, run `hermes memory reindex` to rebuild the FTS5 search index

### 5.5 Migrate Tool Knowledge Base

TOOLS.md tracks 518 Kali Linux tools. Convert it to Hermes configuration:

```bash
# Create a tools configuration section
cat >> ~/.hermes/config.yaml << 'EOF'

tools:
  kali:
    enabled: true
    path: /usr/bin
    categories:
      - name: Web Security
        tools: [sqlmap, nikto, dirb, gobuster, burpsuite, whatweb]
      - name: Network Pentest
        tools: [nmap, masscan, enum4linux, smbclient, rpcclient]
      - name: Password Attack
        tools: [hydra, hashcat, john, medusa, patator]
      - name: Exploitation
        tools: [metasploit, searchsploit, crackmapexec]
      - name: Wireless
        tools: [aircrack-ng, reaver, wifite, bully]
      - name: Forensics
        tools: [autopsy, volatility, binwalk, foremost, scalpel]
      - name: Reverse Engineering
        tools: [ghidra, radare2, gdb, objdump, strings]
      - name: OSINT
        tools: [maltego, theharvester, recon-ng, spiderfoot, shodan]
EOF
```

---

## 6. Post-Migration Configuration

### 6.1 Configure Kali Tool Access

Hermes needs to know where your Kali Linux tools are located.

**Option A: Hermes running directly on Kali Linux**

```bash
# Set Kali tool path
hermes config set tools.kali_path /usr/bin

# Verify tool access
hermes tools check nmap
hermes tools check sqlmap
hermes tools check hydra
```

**Option B: Remote Kali via SSH**

```bash
# Configure remote SSH access
hermes config set tools.remote_ssh user@kali-host
hermes config set tools.remote_ssh_key ~/.ssh/id_ed25519

# Verify remote tool access
hermes tools check --remote nmap
hermes tools check --remote sqlmap
```

**Option C: Docker container**

```bash
# Configure Docker access
hermes config set tools.docker_container kali-claw-env

# Verify container tool access
hermes tools check --docker nmap
```

### 6.2 Configure Model

Hermes supports 200+ models through multiple providers.

```bash
# Using OpenRouter (access to 200+ models)
hermes config set model.provider openrouter
hermes config set model.name anthropic/claude-sonnet-4-6
hermes config set model.api_key $OPENROUTER_API_KEY

# Alternative: specific providers
# OpenAI
hermes config set model.provider openai
hermes config set model.name gpt-4-turbo

# Anthropic
hermes config set model.provider anthropic
hermes config set model.name claude-sonnet-4-6

# Google Gemini
hermes config set model.provider google
hermes config set model.name gemini-2.0-flash

# Local Ollama (free, offline)
hermes config set model.provider ollama
hermes config set model.name llama3
# Requires Ollama running locally: https://ollama.com
```

### 6.3 Configure Gateways

Gateways let you interact with the agent through different platforms.

```bash
# Telegram gateway
hermes gateway add telegram --token YOUR_TELEGRAM_BOT_TOKEN

# Discord gateway
hermes gateway add discord --token YOUR_DISCORD_BOT_TOKEN --application_id YOUR_APP_ID

# Slack gateway
hermes gateway add slack --bot-token xoxb-YOUR-TOKEN --app-token xapp-YOUR-TOKEN

# WhatsApp gateway (via WhatsApp Web API)
hermes gateway add whatsapp --session-id kali-claw-session

# Signal gateway
hermes gateway add signal --phone-number +1234567890

# Start CLI gateway (default, no configuration needed)
hermes gateway start

# Start a specific gateway
hermes gateway start telegram

# Start all configured gateways
hermes gateway start --all
```

### 6.4 Verify Complete Migration

Run a comprehensive verification:

```bash
# 1. List all migrated skills
hermes skills list
# Expected: ~49 skills

# 2. Test all skills
hermes skills test --all
# Expected: All skills pass validation

# 3. View memory statistics
hermes memory stats
# Shows: total memories, date range, search index status

# 4. Search memory for specific topics
hermes memory search "penetration testing"
hermes memory search "sql injection"
hermes memory search "nmap"

# 5. Run health check
hermes health
# Checks: model connection, gateway status, skill integrity, memory index

# 6. Test a real query
hermes gateway start
# Then send: "What SQL injection types do you know?"
# Expected: Detailed response referencing web-sqli skill content
```

---

## 7. FAQ

### Q1: Auto-migration cannot find OpenClaw

**Problem:** `hermes claw migrate` reports "No OpenClaw workspace found."

**Cause:** The workspace is not at the default location `~/.openclaw/`, or the directory name does not match the expected pattern.

**Solution:**

```bash
# Check if ~/.openclaw/ exists
ls ~/.openclaw/

# If workspace is elsewhere, specify the path
hermes claw migrate --workspace /path/to/your/workspace-kali-claw/

# If workspace name is non-standard
hermes claw migrate --workspace ~/my-custom-workspace/
```

### Q2: Skills not triggering after migration

**Problem:** Skills were migrated but the agent does not activate them when relevant queries are sent.

**Cause:** Trigger keywords may be missing, too generic, or incorrectly formatted.

**Solution:**

```bash
# Check triggers for a specific skill
hermes skills show web-sqli

# Update triggers manually
# Edit ~/.hermes/skills/web-sqli.md
# Ensure the triggers field has specific, diverse keywords:
# triggers: ["sql injection", "sqli", "union select", "blind injection", "sqlmap"]

# Re-validate after changes
hermes skills validate web-sqli
```

### Q3: Payload format incompatible

**Problem:** After auto-migration, payloads are stored as attachments and not natively understood by Hermes.

**Cause:** Auto-migration does not parse payloads.md into the Hermes Examples section.

**Solution:** Use the stub creation approach from Section 4.3 to create lightweight stubs that reference kali-claw's payloads.md files in-place. Hermes will read the referenced files when the skill is triggered. Alternatively, manually write a brief summary in the `## Examples` section of each Hermes stub file.

### Q4: Cannot search imported memories

**Problem:** `hermes memory search "keyword"` returns no results even though memories were imported.

**Cause:** The FTS5 search index may need to be rebuilt.

**Solution:**

```bash
# Rebuild the search index
hermes memory reindex

# Verify index status
hermes memory stats

# Try searching again
hermes memory search "nmap"
```

### Q5: Can I run both OpenClaw and Hermes simultaneously?

**Answer:** Yes. OpenClaw and Hermes are independent frameworks that do not interfere with each other.

- OpenClaw reads from `~/.openclaw/workspace-kali-claw/`
- Hermes reads from `~/.hermes/`
- Both can use the same skill content (the knowledge is in the markdown, not the framework)

**Tip for syncing:** Keep kali-claw as the source of truth in a git repository. Hermes stubs reference kali-claw paths, so both frameworks share the same content:

```bash
# Hermes stubs point to kali-claw files -- no duplication needed
# When kali-claw skills update via git pull, Hermes automatically sees the latest content
cd ~/.openclaw/workspace-kali-claw/
git pull origin main
```

### Q6: How to sync updates between frameworks

**Problem:** You want changes made in one framework to appear in the other.

**Solution:** Since Hermes stubs reference kali-claw files by path, updates to kali-claw skills are automatically visible to Hermes:

```bash
# Update kali-claw skills
cd ~/.openclaw/workspace-kali-claw/
git pull origin main

# No additional step needed -- Hermes stubs reference the same files
# The stubs point to absolute paths, so any content updates are immediately available

# If new skills were added, re-run the stub creation script
python3 ~/create_stubs.py --dry-run   # preview first
python3 ~/create_stubs.py             # create stubs for new skills
```

### Q7: Will Hermes self-learning overwrite migrated skills?

**Answer:** No. Hermes's self-learning loop appends new knowledge; it does not overwrite existing skill files.

When Hermes learns something new during a session:
1. It creates a new memory entry in SQLite
2. If the learning is significant, it creates a new skill file (e.g., `web-sqli-v2.md`) or appends to the existing skill
3. The original migrated skill content is preserved

You can verify this by checking the modification dates:

```bash
ls -lt ~/.hermes/skills/
# Migrated skills keep their original content
# New learnings appear as separate entries or appended sections
```

### Q8: How to handle Python/Shell scripts from guides/

**Problem:** kali-claw skill guides contain executable Python and Shell scripts that Hermes cannot directly reference.

**Solution:** Place scripts in the Hermes tools directory and reference them in skills:

```bash
# Create a tools directory
mkdir -p ~/.hermes/tools/

# Copy scripts from guides
cp ~/.openclaw/workspace-kali-claw/skills/web-sqli/guides/bug_bounty_sqli_scanner.py \
   ~/.hermes/tools/sqli-scanner.py

cp ~/.openclaw/workspace-kali-claw/skills/web-sqli/guides/sqli-labs-auto.sh \
   ~/.hermes/tools/sqli-labs-auto.sh

# Make shell scripts executable
chmod +x ~/.hermes/tools/*.sh

# Reference in the skill file
# Add to the Examples section of ~/.hermes/skills/web-sqli.md:
# See tools/sqli-scanner.py for automated SQL injection scanning
# See tools/sqli-labs-auto.sh for SQLi-Labs automated testing
```

### Q9: Stub creation takes too long for 49 skills

**Problem:** Creating stubs for all 49 skills is slow or produces errors for some skills.

**Solution:** Process skills in batches:

```bash
# Create stubs for first 10 skills
for skill in web-sqli web-xss web-ssrf web-auth-bypass web-access-control \
             api-security network-pentest osint password-attack post-exploitation; do
    python3 ~/create_stubs.py --skill "$skill"
    echo "Stub created: $skill"
done

# Verify first batch
hermes skills validate --all

# Continue with remaining skills
python3 ~/create_stubs.py
```

### Q10: How to remove migrated skills and start over

**Problem:** You want to redo the migration from scratch.

**Solution:**

```bash
# Remove all Hermes skill stubs
rm -f ~/.hermes/skills/*.md

# Remove imported memories
hermes memory clear

# Re-run migration
hermes claw migrate

# Then re-create the stubs
python3 ~/create_stubs.py
```

---

## 8. Architecture Comparison and Reference

### Complete Component Mapping Table

| kali-claw (OpenClaw) | Hermes Agent | Format | Migration Method |
|---------------------|-------------|--------|------------------|
| `SOUL.md` | `personality.md` | Markdown with YAML frontmatter | Auto or manual |
| `USER.md` | `config.yaml` (user section) | YAML | Manual |
| `AGENTS.md` | `config.yaml` (agent section) | YAML | Manual |
| `IDENTITY.md` | `skills/*.md` (YAML frontmatter tags) | YAML + Markdown | Manual (tags extracted from skill content) |
| `skills/*/SKILL.md` | `skills/skill-name.md` | Markdown with YAML frontmatter, references kali-claw in-place | Reference stub |
| `skills/*/payloads.md` | `skills/skill-name.md` (## Examples) | Referenced via path in stub | Reference stub |
| `skills/*/test-cases.md` | `skills/skill-name.md` (## Test Cases) | Referenced via path in stub | Reference stub |
| `skills/*/guides/` | `skills/skill-name.md` (## Deep Dive) or `~/.hermes/tools/` | Referenced via path in stub | Reference stub |
| `MEMORY.md` | SQLite memory store | Database | `hermes claw migrate --memory-only` |
| `memory/*.md` | SQLite memory store | Database | `hermes claw migrate --memory-only` |
| `chronicle/` | SQLite memory store | Database | `hermes claw migrate --memory-only` |
| `TOOLS.md` | `config.yaml` (tools section) | YAML | Manual |
| `HEARTBEAT.md` | `config.yaml` (cron section) | YAML | Manual |

### Framework Comparison

| Feature | OpenClaw (kali-claw) | Hermes Agent |
|---------|---------------------|--------------|
| **Language** | TypeScript / Node.js | Python |
| **Installation** | `npm install -g openclaw` | `curl -fsSL https://get.hermes.dev \| bash` |
| **Config root** | `~/.openclaw/` | `~/.hermes/` |
| **Skill format** | 4 files per skill (SKILL.md + payloads.md + test-cases.md + guides/) | Single .md with YAML frontmatter |
| **Memory storage** | Markdown files (daily logs, chronicles, MEMORY.md) | SQLite + FTS5 + LLM summarization |
| **Memory search** | Full-text scan of markdown files | FTS5 full-text search index |
| **Learning loop** | No built-in loop (manual distillation) | Closed learning loop (auto skill creation) |
| **Personality** | SOUL.md (freeform Markdown) | personality.md (structured YAML + Markdown) |
| **Model support** | Single provider per agent | 200+ models via OpenRouter, OpenAI, Anthropic, etc. |
| **Gateways** | Built-in gateway (single interface) | Telegram, Discord, Slack, WhatsApp, Signal, QQ, CLI |
| **Heartbeat** | HEARTBEAT.md (markdown task definitions) | config.yaml (cron-based scheduling) |
| **Tool management** | TOOLS.md (markdown knowledge base) | config.yaml (structured tool registry) |
| **Orchestration** | ECC patterns (6 types) | Workflow types (sequential, parallel, iterative, composite, watch, interceptor) |
| **Community** | OpenClaw ecosystem | 100k+ GitHub stars, growing skill marketplace |

### Skill Count Reference

kali-claw includes the following 49 security skill domains:

**Attack Skills (17):**
web-sqli, web-xss, web-ssrf, web-auth-bypass, web-access-control, api-security, network-pentest, password-attack, post-exploitation, wifi-pentest, binary-reverse, crypto-attacks, mobile-security, social-engineering, hardware-security, supply-chain-security, insecure-design

**Defense Skills (8):**
security-review, verification-loop, docker-patterns, safety-guard, security-misconfiguration, vulnerability-assessment, logging-monitoring, container-security

**Knowledge Skills (8):**
osint, recon-osint, deep-research, search-first, repo-scan, exa-search, data-scraper-agent, knowledge-ops

**Meta Skills (6):**
autonomous-loops, multi-agent-collaboration, council, chronicle, continuous-learning, codebase-onboarding

**Infrastructure (6):**
terminal-ops, mcp-server-patterns, browser-qa, article-writing, ai-fuzzing, ai-security

**Specialized (4):**
digital-forensics, cloud-security, security-bounty-hunter, social-intelligence

---

_This guide covers kali-claw v0.1.7 migration to Hermes Agent. For the latest updates, visit the [kali-claw repository](https://github.com/brucesongs/kali-claw) and the [Hermes Agent repository](https://github.com/NousResearch/hermes-agent)._
