# Continuous Monitoring Guide

> Guide for the deep-research skill — covers persistent intelligence collection, change detection, and alert-driven research.

## Overview

Deep research Phase 7 extends single-shot research into a continuous intelligence operation. Instead of producing one report and moving on, continuous monitoring watches for changes, detects new threats, and triggers follow-up research automatically.

## Monitoring Architecture

```
┌─────────────────────────────────────────────┐
│              Monitoring Targets              │
│  CVE Feeds │ Code Repos │ Paste Sites │ DNS │
└──────┬──────────┬───────────┬──────────┬────┘
       │          │           │          │
       ▼          ▼           ▼          ▼
┌─────────────────────────────────────────────┐
│           Collection Layer                   │
│  Poll each source at defined frequency       │
│  Store snapshots for comparison               │
└──────────────────┬──────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────┐
│           Change Detection                   │
│  Diff current vs. previous snapshot          │
│  Filter noise (known-good, duplicates)       │
└──────────────────┬──────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────┐
│           Alert & Report                     │
│  Trigger conditions met → generate report    │
│  Feed into Phase 8 (correlation) if needed   │
└─────────────────────────────────────────────┘
```

## Source Configuration

### Tier 1: High-Priority (Daily)

| Source | What to Monitor | Collection Command |
|--------|----------------|-------------------|
| NVD | New CVEs matching target CPEs | `curl NVD API with pubStartDate` |
| CISA KEV | Newly added exploited vulns | `curl KEV JSON, compare dateAdded` |
| Exploit-DB | New public exploits | `searchsploit --update && searchsploit <tech>` |
| GitHub Advisories | Security advisories for dependencies | `gh api /advisories` |

### Tier 2: Medium-Priority (Every 6-12 Hours)

| Source | What to Monitor | Collection Command |
|--------|----------------|-------------------|
| GitHub Code | New PoC commits, tool updates | `gh search code <keyword> --sort indexed` |
| Pastebin/Paste sites | Target mentions, credential leaks | `psbdmp API search` |
| Security blogs (RSS) | New research, write-ups | `curl RSS feed, parse new entries` |

### Tier 3: Lower-Priority (Weekly)

| Source | What to Monitor | Collection Command |
|--------|----------------|-------------------|
| Shodan/Censys | Attack surface changes | `shodan search, diff against baseline` |
| Certificate Transparency | New TLS certificates | `crt.sh JSON API` |
| DNS records | Record changes, new subdomains | `dig + subfinder, diff` |
| Dark web (Ahmia, IntelX) | Target mentions | `ahmia/IntelX API search` |

## Snapshot and Diff Pattern

### Basic Snapshot Workflow

```bash
# Directory structure for monitoring
mkdir -p monitoring/{snapshots,diffs,alerts}

# Take daily snapshot
DATE=$(date +%Y%m%d)

# CVE snapshot
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=<tech>&resultsPerPage=50" \
  | jq '[.vulnerabilities[] | {id: .cve.id, severity: .cve.metrics.cvssMetricV31[0].cvssData.baseSeverity}]' \
  > monitoring/snapshots/cve_${DATE}.json

# Compare with previous
PREV_DATE=$(date -d '1 day ago' +%Y%m%d)
diff monitoring/snapshots/cve_${PREV_DATE}.json monitoring/snapshots/cve_${DATE}.json \
  > monitoring/diffs/cve_diff_${DATE}.txt

# If diff is non-empty, there are new findings
if [ -s monitoring/diffs/cve_diff_${DATE}.txt ]; then
  echo "[ALERT] New CVE findings detected" >> monitoring/alerts/alerts_${DATE}.log
fi
```

### Shodan Exposure Diff

```bash
# Weekly exposure snapshot
shodan search "org:<Target>" --fields ip_str,port,product,version --limit 500 \
  | sort > monitoring/snapshots/shodan_${DATE}.txt

# Identify new services
comm -13 monitoring/snapshots/shodan_${PREV}.txt monitoring/snapshots/shodan_${DATE}.txt \
  > monitoring/diffs/new_services_${DATE}.txt

# Identify removed services
comm -23 monitoring/snapshots/shodan_${PREV}.txt monitoring/snapshots/shodan_${DATE}.txt \
  > monitoring/diffs/removed_services_${DATE}.txt
```

### Subdomain Discovery Delta

```bash
# Weekly subdomain enumeration
subfinder -d target.com -silent | sort -u > monitoring/snapshots/subs_${DATE}.txt

# New subdomains since last check
comm -13 monitoring/snapshots/subs_${PREV}.txt monitoring/snapshots/subs_${DATE}.txt \
  > monitoring/diffs/new_subs_${DATE}.txt

# Verify new subdomains are live
cat monitoring/diffs/new_subs_${DATE}.txt | httpx -silent -status-code -title \
  > monitoring/diffs/new_subs_live_${DATE}.txt
```

## Alert Trigger Conditions

### Critical Triggers (Immediate Research)

| Condition | Action |
|-----------|--------|
| New CVE with CVSS >= 9.0 for monitored tech | Full CVE deep-dive (Phase 1-6) |
| New CISA KEV entry for monitored tech | Assess exposure + patch status |
| Public PoC published on GitHub | Evaluate weaponization risk |
| Target credentials found in paste | Incident response workflow |

### High Triggers (Same-Day Research)

| Condition | Action |
|-----------|--------|
| New CVE with CVSS 7.0-8.9 | Quick assessment report |
| New subdomain discovered | Fingerprint and assess |
| New Shodan-visible service | Identify and evaluate exposure |
| Target mentioned on dark web | Context gathering |

### Medium Triggers (Weekly Review)

| Condition | Action |
|-----------|--------|
| New CVE with CVSS 4.0-6.9 | Add to tracking list |
| DNS record changes | Note and investigate if suspicious |
| New security blog post about target tech | Read and extract key points |

## Monitoring Report Template

```markdown
# Monitoring Report: [Target/Technology]
*Period: [start-date] to [end-date] | Sources polled: [N]*

## Critical Alerts
[Any critical triggers fired during this period]

## New Findings
### CVEs
| CVE ID | Severity | Exploit Status | Patch Status |
|--------|----------|----------------|-------------|

### Attack Surface Changes
- New subdomains: [list]
- New services: [list]
- Removed services: [list]

### Code & Leak Activity
- New PoCs: [list with links]
- Paste mentions: [list]

## Trend Analysis
[How findings compare to previous period]

## Recommended Actions
1. [Prioritized action items]
```

## Integration with Other Skills

- **autonomous-loops**: Use the Watch Loop pattern for scheduled monitoring
- **osint**: Feed monitoring discoveries into OSINT workflows for deeper investigation
- **social-intelligence**: Monitor social platforms for complementary intelligence
- **continuous-learning**: Extract patterns from monitoring data over time
