# Search First — Payloads & Commands

> Companion to `SKILL.md`. Contains search templates, command sequences, and evaluation scripts for exploit/tool/technique discovery organized by source.

---

## Quick Start Checklist

```
1. Define need → 2. Parallel search (ExploitDB + GitHub + MSF + Nuclei) → 3. Evaluate → 4. Decide → 5. Execute
```

---

## Exploit-DB Search Templates

### By CVE

```bash
# Search by CVE ID
searchsploit CVE-2025-12345

# View exploit code
searchsploit -x 12345

# Copy exploit to current directory
searchsploit -m 12345

# Search with exact match
searchsploit -e "Apache 2.4.49"
```

### By Service/Version

```bash
# Search by service name and version
searchsploit apache 2.4.49
searchsploit openssh 8.9
searchsploit nginx 1.24
searchsploit wordpress 6.0

# Filter by type
searchsploit --exclude-poc apache 2.4 remote
searchsploit -t remote apache 2.4

# Output as JSON for processing
searchsploit -j apache 2.4 | jq '.RESULTS_EXPLOIT[] | {Title: .Title, Type: .Type, Platform: .Platform}'
```

### By Technique

```bash
# Search by attack technique
searchsploit "path traversal"
searchsploit "remote code execution" php
searchsploit "sql injection" wordpress
searchsploit "privilege escalation" linux
searchsploit "buffer overflow" x86 remote
```

---

## GitHub Search Templates

### Exploit PoC Search

```bash
# Search for CVE PoC repositories
gh search repos "CVE-2025-12345" --sort stars --limit 20
gh search repos "CVE-2025-12345 poc" --sort stars --limit 10

# Search for exploit code
gh search code "CVE-2025-12345" --language python --limit 20
gh search code "CVE-2025-12345" --language exploit --limit 20

# Search specific security researchers
gh search code "CVE-2025-12345" --user=projectdiscovery
gh search code "CVE-2025-12345" --user=ptswarm
```

### Tool Search

```bash
# Search for security tools by capability
gh search repos "subdomain enumeration tool" --sort stars --limit 20
gh search repos "xss scanner" --sort stars --limit 20
gh search repos "active directory enumeration" --sort stars --limit 20
gh search repos "api security testing" --sort stars --limit 20

# Filter by update recency
gh search repos "nuclei templates" --sort updated --limit 20

# Search in specific organizations
gh search repos "exploit" --owner=projectdiscovery --limit 20
gh search repos "exploit" --owner=rapid7 --limit 20
```

### Technique Search

```bash
# Search for attack technique implementations
gh search code "kerberoasting" --language python --limit 20
gh search code "dll injection" --language c --limit 20
gh search code "token impersonation" --language csharp --limit 20
```

---

## Metasploit Search Templates

### Module Search

```bash
# Search exploit modules
msfconsole -q -x "search type:exploit name:apache; exit"

# Search auxiliary modules
msfconsole -q -x "search type:auxiliary name:scanner; exit"

# Search post-exploitation modules
msfconsole -q -x "search type:post name:escalate; exit"

# Search by platform
msfconsole -q -x "search platform:windows type:exploit name:smb; exit"

# Search by CVE
msfconsole -q -x "search cve:CVE-2025-12345; exit"
```

### Module Evaluation

```bash
# Show module details
msfconsole -q -x "use exploit/windows/smb/ms17_010_eternalblue; show info; exit"

# Check module options
msfconsole -q -x "use exploit/windows/smb/ms17_010_eternalblue; show options; exit"

# List compatible payloads
msfconsole -q -x "use exploit/windows/smb/ms17_010_eternalblue; show payloads; exit"
```

---

## Nuclei Template Search

### Template Discovery

```bash
# List all available templates
nuclei -tl | wc -l

# Search templates by keyword
nuclei -tl -tags cve | grep "2025"
nuclei -tl -tags sqli
nuclei -tl -tags xss
nuclei -tl -tags ssrf
nuclei -tl -tags idor

# Search by severity
nuclei -tl -severity critical
nuclei -tl -severity critical,high

# Search by author
nuclei -tl -author pdteam
```

### Custom Template Search

```bash
# Search in nuclei-templates repo
gh search code "CVE-2025" --repo projectdiscovery/nuclei-templates --limit 20

# Search for specific technology templates
nuclei -tl -tags wordpress
nuclei -tl -tags jenkins
nuclei -tl -tags api
```

---

## Kali Package Search

### Tool Availability Check

```bash
# Search Kali package repository
apt search <keyword> 2>/dev/null | grep -i security

# Check if tool is installed
dpkg -l | grep <tool>
which <tool>

# Install missing tool
apt install -y <tool>

# Search by category
apt search "web scanner" 2>/dev/null
apt search "password crack" 2>/dev/null
apt search "network scanner" 2>/dev/null
```

---

## Evaluation Scoring Template

### Result Quality Matrix

```markdown
## Search Result Evaluation: [Need]

| Source | Result | Reliability | Compatibility | OPSEC | Maintenance | Score |
|--------|--------|-------------|---------------|-------|-------------|-------|
| ExploitDB | [ID] | [High/Med/Low] | [Yes/Partial/No] | [Safe/Risky] | [Active/Stale] | [1-10] |
| GitHub | [URL] | [High/Med/Low] | [Yes/Partial/No] | [Safe/Risky] | [Active/Stale] | [1-10] |
| MSF | [Module] | [High/Med/Low] | [Yes/Partial/No] | [Safe/Risky] | [Active/Stale] | [1-10] |
| Nuclei | [Template] | [High/Med/Low] | [Yes/Partial/No] | [Safe/Risky] | [Active/Stale] | [1-10] |

### Decision
- **Action**: [Use as-is / Modify / Compose / Build custom]
- **Selected**: [source/result]
- **Rationale**: [why this choice]
```

### Scoring Criteria

| Factor | Weight | High (3) | Medium (2) | Low (1) |
|--------|--------|----------|------------|---------|
| Reliability | 30% | Verified PoC, multiple reports | Single report, consistent | Unverified, theoretical |
| Compatibility | 25% | Exact version match | Adjacent version | Requires adaptation |
| OPSEC | 20% | Silent/low noise | Moderate detection | Noisy/widely detected |
| Maintenance | 15% | Updated within 30 days | Updated within 1 year | Abandoned/legacy |
| Documentation | 10% | Full docs + examples | Basic README | No documentation |

---

## Decision Templates

### Use As-Is Decision

```markdown
## Decision: Use Existing Tool/Exploit
- **Source**: [ExploitDB/GitHub/MSF/Nuclei]
- **Result**: [ID/URL/Module]
- **Target match**: [exact version/service confirmed]
- **Risk level**: [low/medium/high]
- **Detection risk**: [minimal/moderate/high]
- **Command**: [exact command to execute]
```

### Modify Decision

```markdown
## Decision: Modify Existing Tool/Exploit
- **Source**: [ExploitDB/GitHub]
- **Original**: [what it does]
- **Modification needed**: [what to change]
- **Estimated effort**: [minutes/hours]
- **Risk of modification**: [low/medium/high]
```

### Build Custom Decision

```markdown
## Decision: Build Custom Exploit/Tool
- **Need**: [what capability is needed]
- **Search results**: [N relevant results, none suitable because...]
- **Approach**: [brief implementation plan]
- **Estimated effort**: [hours/days]
- **Dependencies**: [tools/libraries required]
```
