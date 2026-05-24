# Tool Evaluation and Selection Guide

> Skill: search-first | Type: methodology
> Created: 2026-05-23 | Estimated Study Time: 30 minutes

## Overview

Learn to evaluate and select the best security tools and exploits for penetration testing. Covers evaluation scoring matrices, reliability assessment, compatibility verification, and OPSEC considerations.

## Prerequisites

- Search-first methodology
- Understanding of security tool categories
- Basic penetration testing knowledge

## 1. Evaluation Framework

### Five-Dimensional Scoring Matrix

```
┌─────────────────────────────────────────────────────────────┐
│                    TOOL EVALUATION MATRIX                     │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │RELIABIL- │  │COMPATIBI-│  │   OPSEC   │  │MAINTE-   │  │
│  │ITY (25%) │  │LITY(25%) │  │  (20%)   │  │NANCE(15%)│  │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘  │
│         │             │             │             │        │
│         └─────────────┴─────────────┴─────────────┘        │
│                           │                                  │
│                           ▼                                  │
│                    ┌──────────┐                              │
│                    │DETECTION│                              │
│                    │ RISK(15%)│                              │
│                    └──────────┘                              │
│                           │                                  │
│                           ▼                                  │
│                    FINAL SCORE                               │
│                    (0-100)                                    │
└───────────────────────────────────────────────────────────────┘
```

### Scoring Criteria

| Dimension | Criteria | Score Range |
|-----------|----------|-------------|
| **Reliability** | Works consistently, handles errors well, good documentation | 0-25 |
| **Compatibility** | Matches target version, supported platform, correct dependencies | 0-25 |
| **OPSEC** | Low detection risk, minimal noise, stealthy operation | 0-20 |
| **Maintenance** | Recently updated, active community, issue response time | 0-15 |
| **Detection Risk** | Known signatures, AV evasion, IDS/IPS detection | 0-15 |

**Pass Threshold:** 70/100
**Strong Candidate:** 85/100+

## 2. Reliability Assessment

### Tool Reliability Checklist

```python
def assess_reliability(tool_info):
    """Assess tool reliability (0-25 points)"""
    score = 0

    # Code quality indicators
    if tool_info.get('has_tests'):
        score += 3
    if tool_info.get('has_ci'):
        score += 2

    # Documentation
    if tool_info.get('readme_completeness') == 'full':
        score += 5
    elif tool_info.get('readme_completeness') == 'partial':
        score += 2

    # Error handling
    if tool_info.get('error_handling') == 'robust':
        score += 5
    elif tool_info.get('error_handling') == 'basic':
        score += 2

    # Usage evidence
    if tool_info.get('star_count', 0) > 1000:
        score += 5
    elif tool_info.get('star_count', 0) > 100:
        score += 3

    # Fork diversity
    if tool_info.get('fork_count', 0) > 50:
        score += 3

    # Issues management
    open_issues = tool_info.get('open_issues', 0)
    if open_issues < 10:
        score += 2

    return min(score, 25)
```

### Exploit Reliability Assessment

```bash
# Exploit-DB reliability indicators
echo "=== EXPLOIT RELIABILITY CHECK ==="

# Check exploit verification status
searchsploit -x <exploit-id> | grep -i "verified"

# Check exploit rating
searchsploit -x <exploit-id> | grep -i "rating\|verified"

# Check for proof-of-concept code
searchsploit -x <exploit-id> | grep -i "poc\|proof"

# Check exploit type
searchsploit -x <exploit-id> | grep -i "dos\|remote\|local"

# GitHub PoC reliability
gh search repos "CVE-2024-XXXXX" --limit 20 | while read repo; do
    # Check stars
    stars=$(gh repo view "$repo" --json stargazerCount -q '.stargazerCount')

    # Check forks
    forks=$(gh repo view "$repo" --json forkCount -q '.forkCount')

    # Check last commit
    last_commit=$(gh repo view "$repo" --json pushedAt -q '.pushedAt')

    echo "Repo: $repo"
    echo "  Stars: $stars, Forks: $forks, Last: $last_commit"
done
```

## 3. Compatibility Verification

### Target Version Matching

```python
def check_version_compatibility(exploit_versions, target_version):
    """Check if exploit matches target version"""
    target = parse_version(target_version)

    for exploit_ver in exploit_versions:
        exp = parse_version(exploit_ver)

        if '=' in exploit_ver or target == exp:
            return {'match': True, 'type': 'exact', 'version': exploit_ver}

        elif '<=' in exploit_ver or target <= exp:
            return {'match': True, 'type': 'range', 'version': exploit_ver}

        elif '<' in exploit_ver or target < exp:
            return {'match': True, 'type': 'before', 'version': exploit_ver}

    return {'match': False, 'reason': 'No version match'}
```

### Platform and Dependency Check

```bash
# Platform compatibility
echo "=== PLATFORM COMPATIBILITY ==="

# Check tool availability in Kali
apt-cache search <tool-name>

# Check tool dependencies
dpkg -I /path/to/tool.deb | grep Depends

# For Python tools
pip show <tool-name> | grep Requires

# Check architecture compatibility
uname -m
file <tool-binary>

# Check library dependencies
ldd <tool-binary>
```

### Metasploit Module Verification

```bash
# Check module exists and is compatible
msfconsole -x "search type:exploit <target> <version>"

# Check module details
msfconsole -x "info <module-name>"

# Check required targets
msfconsole -x "info <module-name>" | grep -A 10 "Targets"

# Verify module works against lab target
msfconsole -x "use <module-name>; set RHOSTS <lab-target>; set RPORT <port>; check"
```

## 4. OPSEC Assessment

### Detection Risk Evaluation

```python
def assess_opsec(tool_info):
    """Assess OPSEC characteristics (0-20 points)"""
    score = 20  # Start with full score, deduct for issues

    # Network noise
    if tool_info.get('generates_high_traffic'):
        score -= 5

    # Signature visibility
    if tool_info.get('known_av_signature'):
        score -= 5

    # Default/obvious payloads
    if tool_info.get('uses_default_payloads'):
        score -= 3

    # Logs generated
    if tool_info.get('generates_logs'):
        score -= 2

    # Stealth features
    if tool_info.get('has_stealth_mode'):
        score += 3

    # Encryption support
    if tool_info.get('encryption_supported'):
        score += 2

    return max(0, score)
```

### OPSEC Checklist

```markdown
## Tool OPSEC Assessment

### Network Footprint
- [ ] Minimal connection attempts
- [ ] Support for rate limiting
- [ ] Proxy support (HTTP/SOCKS)
- [ ] Traffic encryption capability
- [ ] No predictable patterns

### Evasion Capabilities
- [ ] AV evasion techniques
- [ ] ID/IPS evasion
- [ ] WAF bypass support
- [ ] Custom user agents
- [ ] Payload encoding options

### Log Impact
- [ ] Minimal event generation
- [ ] No clear exploit signatures
- [ ] Support for timing delays
- [ ] Can mimic legitimate traffic

### Persistence (if applicable)
- [ ] Options for temporary vs permanent
- [ ] Clean-up capabilities
- [ ] No obvious artifacts
```

## 5. Maintenance Assessment

### Project Health Indicators

```bash
# Check GitHub repository health
gh repo view <repo> --json \
  createdAt,updatedAt,pushedAt,stargazerCount,forkCount,openIssues,watchers

# Evaluate:
# - Updated within last 6 months = maintained
# - Recent commits (last 30 days) = active
# - Low open issue count (<50) = responsive
# - Stargazer count > 100 = community trust

# Check release history
gh release list --repo <repo>

# Check for recent versions
gh release view latest --repo <repo>

# Check issue response time
gh issue list --repo <repo> --state closed --limit 10
# Look for issue creation vs closing time gap
```

### Maintenance Scoring

```python
def assess_maintenance(repo_info):
    """Assess project maintenance (0-15 points)"""
    score = 0

    # Recent activity
    last_commit = parse_date(repo_info.get('pushedAt'))
    days_since = (datetime.utcnow() - last_commit).days

    if days_since < 30:
        score += 5
    elif days_since < 180:
        score += 3
    elif days_since < 365:
        score += 1

    # Release activity
    if repo_info.get('latest_release_age_days', 365) < 180:
        score += 3

    # Issue responsiveness
    if repo_info.get('open_issues') < 50:
        score += 3

    # Community engagement
    if repo_info.get('stargazerCount', 0) > 1000:
        score += 2
    elif repo_info.get('stargazerCount', 0) > 100:
        score += 1

    # Fork diversity
    if repo_info.get('forkCount', 0) > 50:
        score += 2

    return min(score, 15)
```

## 6. Decision Matrix

### Use vs Modify vs Build Decision

```
                              ┌─────────────┐
                              │  NEED       │
                              │  ANALYSIS   │
                              └──────┬──────┘
                                     │
                                     ▼
                    ┌────────────────────────────────┐
                    │  SEARCH EXISTING SOLUTIONS     │
                    └────────────────────────────────┘
                                     │
                    ┌────────────────┴────────────────┐
                    │                                 │
                    ▼                                 ▼
          ┌─────────────────┐              ┌─────────────────┐
          │  EXACT MATCH    │              │  PARTIAL MATCH  │
          │  (score ≥ 85)   │              │  (score 60-84)  │
          └────────┬────────┘              └────────┬────────┘
                   │                                 │
                   ▼                                 ▼
          ┌─────────────────┐              ┌─────────────────┐
          │   USE AS-IS     │              │   MODIFY/WRAP   │
          │                 │              │                 │
          │ - Direct use    │              │ - Adapt config  │
          │ - Verify works  │              │ - Add features  │
          │ - Document      │              │ - Customize     │
          └─────────────────┘              └─────────────────┘
                                                     │
                                                     ▼
                                         ┌─────────────────┐
                                         │  TEST MODIFIED  │
                                         └────────┬────────┘
                                                  │
                              ┌─────────────────┴─────────────────┐
                              │                                   │
                              ▼                                   ▼
                    ┌─────────────────┐                ┌─────────────────┐
                    │   USE MODIFIED  │                │    BUILD CUSTOM │
                    │                 │                │                 │
                    │ - Document      │                │ - Informed by   │
                    │   modifications │                │   research      │
                    │ - Track provenance│               │ - Minimal code  │
                    └─────────────────┘                └─────────────────┘
```

### Decision Flow

```python
def decide_tool_action(search_results):
    """Decide whether to use, modify, or build"""
    scored_results = [score_result(r) for r in search_results]

    # Sort by score
    scored_results.sort(key=lambda x: x['score'], reverse=True)

    # Check for strong candidate
    top_result = scored_results[0] if scored_results else None

    if top_result and top_result['score'] >= 85:
        return {
            'action': 'use',
            'tool': top_result,
            'rationale': f"Strong candidate (score {top_result['score']})",
        }

    elif top_result and top_result['score'] >= 60:
        return {
            'action': 'modify',
            'tool': top_result,
            'rationale': f"Partial match (score {top_result['score']}), requires adaptation",
        }

    else:
        return {
            'action': 'build',
            'rationale': f"No suitable tool found (best score {top_result['score'] if top_result else 0}), build custom informed by research",
            'research_findings': scored_results[:3],  # Top 3 for reference
        }
```

## 7. Quick Evaluation Template

```bash
# Tool Evaluation Script
echo "=== TOOL EVALUATION ==="
echo "Tool: $TOOL_NAME"
echo ""

# Reliability (25)
echo "--- RELIABILITY ---"
# [ ] Has tests
# [ ] Has CI
# [ ] Full README
# [ ] Robust error handling
# [ ] High star count
# [ ] Active forks
# [ ] Few open issues
echo "Score: ___/25"

# Compatibility (25)
echo "--- COMPATIBILITY ---"
# [ ] Version matches target
# [ ] Platform supported
# [ ] Dependencies available
# [ ] Architecture compatible
echo "Score: ___/25"

# OPSEC (20)
echo "--- OPSEC ---"
# [ ] Low network noise
# [ ] No known AV signature
# [ ] Custom payloads
# [ ] Minimal logging
# [ ] Stealth features
# [ ] Encryption support
echo "Score: ___/20"

# Maintenance (15)
echo "--- MAINTENANCE ---"
# [ ] Recent commits
# [ ] Recent release
# [ ] Responsive issues
# [ ] Community engagement
echo "Score: ___/15"

# Detection Risk (15)
echo "--- DETECTION RISK ---"
# [ ] Low signature risk
# [ ] Evasion capabilities
# [ ] Legitimate traffic mimicry
echo "Score: ___/15"

# Total
echo ""
echo "TOTAL: ___/100"
echo ""
echo "DECISION:"
echo "  [ ] USE AS-IS"
echo "  [ ] MODIFY/WRAP"
echo "  [ ] BUILD CUSTOM"
```

## Quick Reference

```bash
# Search Exploit-DB
searchsploit apache 2.4.49

# Check exploit details
searchsploit -x 12345

# Search GitHub
gh search repos "CVE-2024-XXXXX"

# Metasploit search
msfconsole -x "search type:exploit <keyword>"

# Check repo health
gh repo view <repo> --json updatedAt,stargazerCount,openIssues

# Install in Kali
apt search <tool-name>
apt install <tool-name>

# Verify compatibility
ldd <tool-binary>
python -c "import <module>"  # Check Python deps
```

## Integration with Other Skills

- **search-first**: Exploit research methodology
- **deep-research**: In-depth tool analysis
- **verification-loop**: Verify selected tool works
- **autonomous-loops**: Automated tool execution
- **docker-patterns**: Lab setup for tool testing