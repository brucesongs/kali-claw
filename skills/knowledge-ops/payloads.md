# Knowledge Operations Payloads

Commands and templates for building, querying, and maintaining the knowledge graph.

---

## Session Startup: Load Context

Run at the start of every session when working on a known target:

```bash
# Find all knowledge files for a target
ls memory/ | grep -i "[target-name]"
grep -rn "target: [target-name]" memory/ | awk -F: '{print $1}' | sort -u

# Find high-confidence findings
grep -rn "confidence: [7-9][0-9]\|confidence: 100" memory/ | head -20

# Find open hypotheses
grep -rn "type: hypothesis" memory/ -l
grep -rn "type: hypothesis" memory/ -A5 | grep -B1 "confidence: [2-5]"

# Find expired intelligence
TODAY=$(date +%Y-%m-%d)
grep -rn "expires:" memory/ | grep -v "null" | while read line; do
  file=$(echo $line | cut -d: -f1)
  expires=$(echo $line | grep -oP '\d{4}-\d{2}-\d{2}')
  if [[ "$expires" < "$TODAY" ]]; then
    echo "EXPIRED: $file (expires: $expires)"
  fi
done
```

---

## Capture: Create New Knowledge Units

### Entity Capture

```markdown
---
id: KU-2026-05-001
type: entity
target: target-org
confidence: 90
created: 2026-05-11
updated: 2026-05-11
tags: [domain, infrastructure, target]
linked: []
source: osint/recon
expires: null
---

## Summary

target.com resolves to 203.0.113.42, hosted on AWS us-east-1.

## Detail

- Primary domain: target.com
- IP: 203.0.113.42
- ASN: AS16509 (Amazon AWS)
- Region: us-east-1 (inferred from response headers: x-amz-cf-id)
- CDN: CloudFront detected (via CNAME to cloudfront.net)
- Nameservers: ns1.target.com, ns2.target.com (custom)

## Connections

- Leads to: subdomain enumeration, CloudFront config bypass research
```

### Finding Capture

```markdown
---
id: KU-2026-05-002
type: finding
target: target-org
confidence: 85
created: 2026-05-11
updated: 2026-05-11
tags: [sql-injection, search, high-risk]
linked: [KU-2026-05-001]
source: codebase-onboarding
expires: null
---

## Summary

SQL injection in search endpoint at search.php:34 via GET parameter `q`.

## Detail

File: `search.php:34`
Code: `$query = "SELECT * FROM products WHERE name LIKE '%" . $_GET['q'] . "%'"`
Type: Classic string concatenation SQL injection
Parameter: GET `q`
Tested: Static analysis only (not confirmed via active testing)
Database: MySQL (from db.php:5 connection string)

## Connections

- Confirms: target uses legacy PHP without parameterized queries
- Leads to: manual verification via sqlmap, data extraction via UNION injection
- Linked entity: KU-2026-05-001 (same target)

## Confidence History

| Date | Score | Reason |
|------|-------|--------|
| 2026-05-11 | 85 | Static code analysis — high probability, not exploited yet |
```

### Relationship Capture

```markdown
---
id: KU-2026-05-003
type: relationship
target: target-org
confidence: 70
created: 2026-05-11
updated: 2026-05-11
tags: [admin, user, access]
linked: [KU-2026-05-001]
source: social-intelligence
expires: 2026-08-11
---

## Summary

John Smith (john@target.com) is the IT administrator, identified via LinkedIn.

## Detail

- Name: John Smith
- Email: john@target.com (format: firstname@domain)
- Role: IT Administrator (LinkedIn profile, 3 years at target.com)
- LinkedIn: linkedin.com/in/johnsmith-target
- GitHub: github.com/jsmith-target (found via email search)
- Notable: Repository named "internal-admin-tool" visible on GitHub (public)

## Connections

- Leads to: Check github.com/jsmith-target for credential exposure
- Leads to: Spear phishing template targeting IT admin role
```

### Pattern Capture

```markdown
---
id: KU-2026-05-004
type: pattern
target: [org-wide pattern]
confidence: 75
created: 2026-05-11
updated: 2026-05-11
tags: [jwt, hs256, pattern, multi-target]
linked: []
source: codebase-onboarding
expires: null
---

## Summary

Organizations using Express.js starter templates frequently use HS256 with a weak or default JWT secret.

## Detail

Observed in: 3 separate targets (target-a, target-b, target-c)
Pattern: `jwt.sign(payload, process.env.JWT_SECRET || 'secret', ...)` — fallback to 'secret' if env not set
Risk: If JWT_SECRET env var is not set in production, all tokens are signed with 'secret'
Frequency: High — Express.js JWT tutorials often use this pattern

## Connections

- Leads to: Check JWT_SECRET in .env for all Express targets
- Leads to: jwt_tool for token forgery attempts if weak secret suspected
```

---

## Knowledge Graph Queries

### Find Attack Chains

```bash
# Find all findings for a target, ordered by confidence
grep -rn "target: target-org" memory/ -l | \
  xargs grep -l "type: finding" | \
  xargs grep -h "confidence:" | \
  sort -t: -k2 -rn | head -10

# Find links between findings (potential attack chains)
grep -rn "linked:" memory/ | grep -v "\[\]" | head -20

# Find hypotheses that could elevate to findings
grep -rn "type: hypothesis" memory/ -A3 | grep -B1 "confidence: [4-6]" | head -10
```

### Cross-Target Pattern Search

```bash
# Find patterns observed across multiple targets
grep -rn "type: pattern" memory/ -l

# Find recurring vulnerability types
grep -rn "tags:.*sql-injection" memory/ | wc -l
grep -rn "tags:.*jwt" memory/ | wc -l
grep -rn "tags:.*xss" memory/ | wc -l

# Most referenced knowledge units (high connectivity = high importance)
grep -rn "linked:" memory/ | grep -oP 'KU-\d{4}-\d{2}-\d{3}' | \
  sort | uniq -c | sort -rn | head -10
```

### Confidence Tracking

```bash
# All high-confidence findings (>= 80)
grep -rn "confidence: [89][0-9]\|confidence: 100" memory/ \
  | grep -v "history\|Reason" | head -20

# All unvalidated findings (confidence 26-50)
grep -rn "confidence: [23456][05]" memory/ | head -20

# Findings that haven't been updated in 30+ days (possibly stale)
find memory/ -name "*.md" -mtime +30 | head -10
```

---

## Knowledge Maintenance

### Update Confidence After Exploitation

```bash
# When a finding is confirmed via exploitation, update confidence
# Edit the memory file:
# 1. Change confidence: 85 → 95
# 2. Add to confidence history table
# 3. Update linked units

# Find the file to update
grep -rn "KU-2026-05-002" memory/
# Edit it:
# confidence: 85 → 95
# Add history row: | 2026-05-11 | 95 | Confirmed via sqlmap, dumped users table |
```

### Archive Disproven Hypotheses

```markdown
# Add to a hypothesis that was disproven:
---
# Change type: hypothesis → type: archived
type: archived
confidence: 0
# Add note:
---

## Archived

Disproven on 2026-05-11. The admin portal does NOT accept VPN bypass — requires client certificate authentication.
```

### Session Capture Template (End of Session)

```bash
# Quick capture script — fill in findings, entities, and relationships
cat > memory/$(date +%Y-%m-%d)-[session-topic].md << 'EOF'
# Session Knowledge Capture — [Topic]

Date: $(date +%Y-%m-%d)
Target: [target]
Session type: [recon / codebase-onboarding / exploitation / research]

## New Entities

[List new domains, IPs, people, systems discovered]

## New Findings

[List vulnerabilities, misconfigurations, sensitive data found]

## Updated Confidence

[List any existing KU IDs with updated confidence scores and reasons]

## Open Hypotheses

[List unconfirmed leads that need follow-up]

## Next Session Priorities

1. [Highest priority follow-up]
2. [Second priority]
3. [Third priority]

## Knowledge Units Created

- KU-YYYY-MM-NNN: [brief description]
- KU-YYYY-MM-NNN: [brief description]
EOF
```

---

## Knowledge-Ops Index File

Maintain an index of all knowledge bases (update monthly):

```markdown
# Knowledge Base Index

## Active Engagements

| Target | KB Files | Findings | Last Updated |
|--------|----------|----------|--------------|
| target-org | 12 | 8 | 2026-05-11 |
| client-b | 5 | 3 | 2026-04-20 |

## Patterns Library

| Pattern ID | Description | Targets Observed |
|-----------|-------------|-----------------|
| KU-2026-05-004 | HS256 JWT with fallback secret | 3 |
| KU-2026-03-021 | Admin endpoints without @PreAuthorize | 2 |

## High-Value Intelligence

| KU ID | Summary | Confidence |
|-------|---------|-----------|
| KU-2026-05-002 | SQL injection in target-org search | 95 |
| KU-2026-04-015 | Exposed admin credentials in GitHub | 90 |
```
