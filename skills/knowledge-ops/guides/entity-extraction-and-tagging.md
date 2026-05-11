# Entity Extraction and Tagging Guide

Systematically identify, extract, and tag entities from raw data. Entities are the building blocks of the knowledge graph — people, systems, domains, IPs, organizations, credentials, and infrastructure.

---

## Entity Types

| Type | Description | Examples |
|------|-------------|----------|
| `domain` | Web domain or subdomain | target.com, api.target.com |
| `ip` | IP address or CIDR range | 203.0.113.42, 203.0.113.0/24 |
| `person` | Individual (name + email) | John Smith, admin@target.com |
| `organization` | Company or team | Target Corp, IT Security Team |
| `credential` | Username, API key, token | admin:password123, AKIA... |
| `system` | Server, service, application | auth-service, nginx/1.18.0 |
| `infrastructure` | Cloud, CDN, ASN | AWS us-east-1, CloudFront |
| `vulnerability` | CVE, known vuln | CVE-2024-12345, Log4Shell |
| `file` | File path, config, script | /etc/passwd, config.php |
| `repository` | Version control repo | github.com/target/api |

---

## Extraction Sources

### From OSINT

```bash
# Domains and subdomains
subfinder -d target.com -o subdomains.txt
cat subdomains.txt | head -20  # Extract each as entity

# IP addresses
dig target.com +short
whois 203.0.113.42 | grep -E "OrgName|NetName|CIDR"

# Email addresses (people)
theharvester -d target.com -b google | grep "@target.com"

# Organizations (from WHOIS)
whois target.com | grep -E "Organization|Registrant"

# ASN and infrastructure
whois 203.0.113.42 | grep -E "ASN|OriginAS"
```

### From Codebase

```bash
# Systems (services, frameworks)
find . -name "Dockerfile" | xargs grep "FROM" | awk '{print $2}'  # Docker base images
grep -rn "version\|VERSION" --include="package.json" --include="go.mod" . | head -10

# Credentials (files only — never capture actual credentials in KB)
grep -rn "username\|password\|api_key" \
  --include="*.env*" --include="config*" . | \
  awk -F: '{print $1}' | sort -u  # File paths only

# File entities (config files)
find . -name "config*" -o -name ".env*" -o -name "settings*" | \
  grep -v node_modules | head -20

# Repositories (dependencies)
cat go.mod | grep "require" | awk '{print $1}' | head -10
cat package.json | python3 -c "import json,sys; d=json.load(sys.stdin); print('\n'.join(d.get('dependencies',{}).keys()))" | head -10
```

### From Social Intelligence

```bash
# People (from Reddit, HN, forums)
# Manual extraction from social-intelligence output
# Pattern: Name (role at org)

# Repositories
# GitHub repos mentioned in discussions

# Vulnerabilities
# CVEs mentioned in recent discussions
```

### From Deep Research

```bash
# CVEs
grep -oP "CVE-\d{4}-\d{4,7}" research_output.md | sort -u

# Domains and IPs from IOC feeds
grep -oP "\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b" research_output.md | sort -u

# Organizations (threat actor groups, vendors)
grep -rn "Vendor|Threat Actor|APT" research_output.md
```

---

## Entity Tagging Strategy

### Tag Dimensions

Every entity should have:
1. **Type tag** (domain, ip, person, etc.)
2. **Source tag** (osint, codebase, social, deep-research)
3. **Context tags** (auth, payment, admin, api, etc.)
4. **Risk tags** (high-value-target, exposed, vulnerable)

### Tag Examples

```markdown
---
type: entity
tags: [domain, infrastructure, cloudfront, osint]
---
# Domain: target.com
```

```markdown
---
type: entity
tags: [person, admin, high-value-target, social]
---
# Person: John Smith (IT Admin)
```

```markdown
---
type: entity
tags: [credential, exposed, github, critical]
---
# Exposed API Key: AKIA...
```

```markdown
---
type: entity
tags: [system, nginx, web-server, codebase]
---
# System: nginx/1.18.0
```

---

## Entity Relationship Mapping

Entities gain value when linked. Common relationship types:

| Relationship | Example |
|--------------|---------|
| `administers` | John Smith administers auth-service |
| `resolves_to` | target.com resolves to 203.0.113.42 |
| `hosted_on` | auth-service hosted on AWS us-east-1 |
| `depends_on` | api-service depends on postgres-db |
| `authenticates_via` | frontend authenticates via JWT from auth-service |
| `exposed_in` | API key exposed in github.com/target/repo |
| `vulnerable_to` | nginx/1.18.0 vulnerable to CVE-2021-23017 |

### Relationship Capture Template

```markdown
---
id: KU-2026-05-020
type: relationship
target: target-org
confidence: 80
tags: [admin, person, system]
linked: [KU-2026-05-001, KU-2026-05-015]
source: social-intelligence
---

## Summary

John Smith (john@target.com) administers auth-service (203.0.113.42).

## Detail

- Person entity: KU-2026-05-015 (John Smith)
- System entity: KU-2026-05-001 (auth-service)
- Evidence: LinkedIn profile lists "Auth Service Admin" role
- Evidence: GitHub commit history shows deployment scripts for auth-service

## Connections

- Links KU-2026-05-015 (person) to KU-2026-05-001 (system)
- Leads to: spear phishing targeting John Smith for auth-service compromise
```

---

## Entity Deduplication

Prevent duplicate entities with different names:

### Detection

```bash
# Find duplicate domains (different subdomains)
grep -rn "type: entity" memory/ -A2 | grep "tags:.*domain" | \
  awk -F: '{print $1}' | xargs grep -h "Summary" | sort

# Find duplicate IPs
grep -rn "type: entity" memory/ -A2 | grep "tags:.*ip" | \
  awk -F: '{print $1}' | xargs grep -h "Summary" | grep -oP "\d+\.\d+\.\d+\.\d+" | sort -u

# Find duplicate people (by email)
grep -rn "type: entity" memory/ -A5 | grep -i "email:" | awk '{print $2}' | sort -u
```

### Merge Strategy

If KU-001 and KU-015 both describe "target.com":
1. Keep the higher-confidence entity
2. Merge tags from both
3. Update all linked KUs to point to the kept entity
4. Archive the duplicate with a note: "Merged into KU-001"

---

## High-Value Entity Identification

Not all entities are equal. Prioritize:

### Critical Entities (Tag: `high-value-target`)

- Admin users
- Root/master API keys
- Production databases
- Payment processing systems
- Auth services
- Code repositories with internal tools

### Detection Query

```bash
# Find all high-value entities
grep -rn "tags:.*high-value-target" memory/ -l

# Find entities with most relationships (high connectivity)
grep -rn "linked:" memory/ | grep -oP "KU-\d{4}-\d{2}-\d{3}" | \
  sort | uniq -c | sort -rn | head -10
# High count = central entity in the graph
```

---

## Entity Confidence Model

Entity confidence represents:
- Source reliability
- Evidence quality
- Recency

| Confidence | Meaning | Example |
|-----------|---------|---------|
| 90-100 | Verified, authoritative source | WHOIS for domain ownership |
| 75-89 | Multiple sources confirm | Email found via LinkedIn + GitHub |
| 60-74 | Single reliable source | Subdomain from subfinder |
| 40-59 | Inferred or indirect | Email format guessed from pattern |
| 0-39 | Speculative | Person role guessed from title |

---

## Entity Lifecycle

### Stage 1: Discovery
- Create entity with initial confidence (often 60-75)
- Tag with source

### Stage 2: Validation
- Confirm entity via second source
- Increase confidence (+10 to +20)

### Stage 3: Enrichment
- Add relationships to other entities
- Add context tags (admin, payment, etc.)

### Stage 4: Deprecation
- Mark as archived if no longer valid
- Example: IP changes, person leaves org, domain expires
