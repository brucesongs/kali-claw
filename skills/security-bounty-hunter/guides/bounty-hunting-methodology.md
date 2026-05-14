# Bounty Hunting Methodology Guide

> Guide for the security-bounty-hunter skill — covers systematic methodology for maximizing bounty hunting return on investment through structured reconnaissance, prioritization, and time management.

## Overview

Bug bounty hunting without methodology is random testing with luck as the only variable. This guide provides a repeatable framework that maximizes the probability of finding high-severity, bounty-worthy vulnerabilities within constrained time budgets.

The methodology is built on one principle: **structured effort outperforms random testing**. Every hour spent following this methodology should produce more actionable findings than an hour of ad-hoc probing.

---

## Target Selection Strategy

### Program Evaluation Criteria

Not all bounty programs are equal. Evaluate programs before investing time:

| Criterion | High Value | Low Value |
|-----------|-----------|-----------|
| Scope breadth | Broad (*.domain.com, APIs, mobile) | Narrow (single subdomain only) |
| Bounty range | $500-$15,000+ for critical | $50-$200 flat |
| Response time | Triage in < 48 hours | Triage in > 2 weeks |
| Signal-to-noise ratio | Few hunters, evolving codebase | Hundreds of hunters, stable codebase |
| Scope clarity | Well-defined with clear boundaries | Vague or contradictory rules |
| Disclosure policy | Allows disclosure after fix | Permanent NDA or no disclosure |

### Technology Stack Analysis

Prefer targets built on technology stacks with known, well-documented attack surfaces:

**High-yield stacks:**
- Modern SPA frameworks with API backends (React/Vue + Node.js/Django/Flask)
- Microservice architectures (more endpoints, more auth boundaries)
- Cloud-native applications (AWS/GCP/Azure metadata, IAM misconfigurations)
- Applications with third-party integrations (OAuth, webhooks, SSO)

**Lower-yield stacks:**
- Static sites with no server-side processing
- Mature applications tested by many hunters already
- Legacy systems with limited scope (e.g., only CDN)

### Competition Assessment

Programs with fewer active hunters provide better ROI:

1. **New programs**: First 2-4 weeks of a new program have the most low-hanging fruit
2. **Private programs**: Invitation-only programs have less competition by design
3. **Recently changed scope**: When scope expands, new territory opens up
4. **Platform events**: Live hacking events draw attention away from other programs
5. **Seasonal gaps**: Holiday periods and summer months often have reduced hunter activity

### Target Selection Decision Matrix

| Factor | Weight | Score (1-5) | Weighted |
|--------|--------|-------------|----------|
| Scope breadth | 3 | ? | ? |
| Bounty range | 2 | ? | ? |
| Tech stack familiarity | 2 | ? | ? |
| Competition level (inverse) | 2 | ? | ? |
| Response time | 1 | ? | ? |
| **Total** | **10** | | **/50** |

Score >= 35: Invest significant time. Score 25-34: Moderate investment. Score < 25: Low priority.

---

## Reconnaissance Pipeline

### Phase 1: Passive Reconnaissance

Goal: Map the target's external attack surface without sending a single packet to the target.

**Subdomain enumeration:**

```bash
# Passive subdomain discovery
subfinder -d target.com -silent -all | sort -u > subs_passive.txt

# Certificate transparency logs
curl -s "https://crt.sh/?q=%25.target.com&output=json" | \
  jq -r '.[].name_value' | sort -u > subs_crt.txt

# DNS resolution of discovered subdomains
cat subs_passive.txt subs_crt.txt | sort -u | dnsx -silent -a -resp > resolved.txt

# HTTP probing to find live services
cat resolved.txt | httpx -silent -status-code -title -tech-detect -o live_services.txt
```

**Technology fingerprinting:**

```bash
# Identify technologies on live services
cat live_services.txt | whatweb -a 3 -q > tech_fingerprint.txt

# Extract JavaScript files for analysis
cat live_services.txt | hakrawler -js -depth 2 | sort -u > js_files.txt
```

**JavaScript analysis for hidden surface:**

Look for in JS files:
- API endpoints not visible in UI navigation
- Hidden parameters and debug flags
- Internal API URLs (staging, admin)
- Hardcoded credentials, API keys, tokens
- Feature flags controlling security functionality

**Output of Phase 1:**
- Complete subdomain list with DNS records
- Live service inventory with technology stack
- JavaScript file inventory with preliminary analysis
- Initial attack surface map

### Phase 2: Active Reconnaissance

Goal: Interact with the target to discover functional attack surface.

**Port scanning:**

```bash
# Service discovery on resolved hosts
nmap -sV -sC -T3 --top-ports 1000 -iL resolved.txt -oN port_scan.txt

# UDP scan for DNS, SNMP, and other UDP services
nmap -sU --top-ports 50 -iL resolved.txt -oN udp_scan.txt
```

**API discovery:**

```bash
# Crawl and discover endpoints
cat live_services.txt | hakrawler -depth 3 -plain -insecure > urls_discovered.txt

# Wayback machine URLs
echo "target.com" | waybackurls | sort -u >> urls_discovered.txt

# GitHub URLs for the target org
gau target.com | sort -u >> urls_discovered.txt

# Parameter mining from discovered URLs
cat urls_discovered.txt | grep "=" | uro | sort -u > params_discovered.txt
```

**Content and endpoint discovery:**

```bash
# Directory bruteforce on primary targets
ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -mc 200,301,302,403 -o ffuf_results.json -of json

# API endpoint discovery
ffuf -u https://api.target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -mc 200,201,401,403 -o api_ffuf_results.json -of json
```

**Output of Phase 2:**
- Complete URL inventory
- Parameter inventory with context (which endpoints accept which params)
- API endpoint map
- Directory and file inventory
- Authentication boundary map (which endpoints require auth)

### Phase 3: Deep Reconnaissance

Goal: Understand business logic and data flows to identify logic flaws and complex vulnerabilities.

**Business logic mapping:**

1. Map all user roles and their capabilities
2. Trace data ownership models (who owns what data)
3. Identify multi-step workflows (checkout, approval chains, state transitions)
4. Document rate limiting and enforcement points
5. Map third-party integrations and data sharing

**Data flow analysis:**

1. Trace user input from source to storage
2. Identify where user input is rendered (stored XSS candidates)
3. Map where user-controlled URLs are fetched (SSRF candidates)
4. Find where user input becomes database queries (SQLi candidates)
5. Locate where user input becomes file paths (traversal candidates)

**Authentication and session analysis:**

1. Map all authentication mechanisms (session cookies, JWT, API keys, OAuth)
2. Test session handling across subdomains
3. Identify password reset flows and their validation
4. Check for OAuth misconfigurations (redirect URI, scope)
5. Test multi-tenancy boundaries (can user A access user B's data?)

**Output of Phase 3:**
- Business logic flow diagram
- Data flow diagram showing user input paths
- Authentication boundary map
- Prioritized target list for vulnerability testing

### Reconnaissance Tool Chain Summary

```
subfinder -> dnsx -> httpx -> whatweb
                            |
          hakrawler <- live services
                            |
          waybackurls + gau -> uro -> param mining
                            |
          ffuf (directories + API endpoints)
                            |
          Manual analysis (business logic, data flows)
```

---

## Vulnerability Classification Priority

### P0 — Always Bounty-Worthy (Critical)

| Vulnerability | Typical Bounty Range | Why Always Valuable |
|--------------|---------------------|-------------------|
| Remote Code Execution (RCE) | $5,000-$15,000+ | Full system compromise |
| SQL Injection (data access) | $2,000-$10,000+ | Data exfiltration, auth bypass |
| SSRF with cloud access | $3,000-$15,000+ | Cloud metadata, internal network |
| Authentication bypass | $3,000-$10,000+ | Full account takeover |
| Server-side template injection | $2,000-$7,000+ | Often leads to RCE |

**Approach**: These are worth dedicating full sessions to. Deep analysis of every potential entry point is justified.

### P1 — Usually Bounty-Worthy (High)

| Vulnerability | Typical Bounty Range | When It Qualifies |
|--------------|---------------------|-------------------|
| IDOR (data access) | $500-$5,000 | Accessing other users' sensitive data |
| Stored XSS | $500-$3,000 | Auto-triggering, no user interaction |
| Privilege escalation | $500-$5,000 | Regular user to admin |
| File upload to RCE | $1,000-$5,000 | Bypassing validation for code execution |
| Business logic flaws | $500-$5,000 | Financial impact, data manipulation |

**Approach**: Worth investigating thoroughly when the attack surface allows. Focus on data sensitivity and real impact.

### P2 — Sometimes Bounty-Worthy (Medium)

| Vulnerability | Typical Bounty Range | When It Qualifies |
|--------------|---------------------|-------------------|
| Reflected XSS | $100-$1,000 | No user interaction beyond clicking link |
| CSRF on sensitive actions | $100-$1,000 | State-changing actions (email change, etc.) |
| Information disclosure | $100-$1,000 | Sensitive data exposed (not just stack traces) |
| Race conditions | $200-$2,000 | Financial or data integrity impact |
| Open redirect | $50-$500 | Used in phishing or OAuth bypass chain |

**Approach**: Only pursue when the impact is clear. Chain with other findings to increase severity.

### P3 — Rarely Bounty-Worthy (Low)

| Vulnerability | Typical Bounty Range | When It Qualifies |
|--------------|---------------------|-------------------|
| Missing security headers | $0-$100 | Only with demonstrated exploitation |
| Clickjacking | $0-$200 | Only on sensitive action pages |
| Self-XSS | $0 | Almost never bounty-worthy alone |
| Error message disclosure | $0 | Only if reveals exploitable information |
| Mixed content | $0 | Rarely accepted by programs |

**Approach**: Skip unless discovered incidentally. Never spend dedicated time searching for P3 findings.

---

## Time Management

### Time-Boxing Per Target

| Target Type | Initial Time Box | Extension Criteria |
|------------|-----------------|-------------------|
| New target (broad scope) | 4 hours | Finding promising attack surface in Phase 1-2 |
| New target (narrow scope) | 2 hours | Finding at least one potential entry point |
| Returning target | 1-2 hours | New code changes, new endpoints discovered |
| Single endpoint deep-dive | 1 hour | Confirmed interesting behavior in first 30 min |

### The 80/20 Rule in Bounty Hunting

80% of bounty payouts come from approximately 20% of vulnerability classes. Focus effort accordingly:

**The high-yield 20%:**
- Injection vulnerabilities (SQLi, command injection, template injection)
- Authentication and authorization flaws (IDOR, privilege escalation, auth bypass)
- Server-side request forgery
- File upload bypasses

**The low-yield 80%:**
- Missing headers, cookie flags, and configuration issues
- Low-impact information disclosure
- Theoretical vulnerabilities without demonstrated impact
- Vulnerabilities requiring unlikely user interaction

### When to Pivot

Pivot to a new target or attack surface when:

1. **No findings after thorough recon**: If Phases 1-3 produce no promising leads, move on
2. **All findings are duplicates**: Check existing reports; if everything is already found, pivot
3. **Diminishing returns**: First 2 hours produced 3 leads, next 2 hours produced 0 — stop
4. **Scope exhaustion**: All endpoints tested with no exploitable results

**Do NOT pivot when:**
- One promising lead remains unexplored
- Business logic analysis is incomplete
- A finding needs one more test to confirm exploitability

### Session Structure

Organize each hunting session into focused phases:

```
Session (2-4 hours)
|
|-- Recon Phase (30-60 min)
|   |-- Quick scope review
|   |-- Subdomain/endpoint delta since last session
|   +-- Technology change detection
|
|-- Triage Phase (30-60 min)
|   |-- Run automated scans (semgrep, nuclei)
|   |-- Filter false positives
|   +-- Prioritize confirmed leads
|
|-- Exploit Phase (60-120 min)
|   |-- Manual testing of prioritized leads
|   |-- PoC development for confirmed findings
|   +-- Impact documentation
|
+-- Report Phase (30 min)
    |-- Draft report per finding
    |-- Evidence collection and sanitization
    +-- Submit or queue for submission
```

---

## ROI Maximization

### Focus Areas for Maximum Return

1. **High-severity, well-understood vulnerability classes**: You know how to find them, programs pay well for them. SQLi, IDOR, and auth bypass are your bread and butter.

2. **Targets with broad scope and modern stacks**: More attack surface means more potential findings. Modern stacks (SPAs + APIs) have more moving parts and more potential misconfigurations.

3. **Recently changed code**: New features, API endpoints, and integrations are less tested. Monitor changelogs, commit history, and release notes.

4. **Cross-boundary interactions**: Where different systems meet (auth systems, API gateways, third-party integrations) is where assumptions break down and vulnerabilities hide.

### Building Reusable Assets

Invest time in building reusable tools and knowledge that compound across sessions:

**Reusable tool chains:**
- Custom semgrep rules for common patterns (see `payloads.md`)
- Nuclei templates for target-specific vulnerability classes
- Parameter fuzzing wordlists refined over time
- Automated recon scripts tailored to your workflow

**Reusable knowledge:**
- Document patterns that lead to findings (feeds into knowledge-ops)
- Maintain a personal CVE-to-technique mapping
- Track which recon techniques produce the most findings per target type
- Record common developer mistakes by framework/language

### Knowledge Feedback Loop

Every finding should improve future hunting effectiveness:

```
Finding discovered -> Document pattern -> Create detection rule -> Add to automation
       ^                                                    |
       +----------- Future sessions find similar issues faster +
```

This feedback loop integrates with the knowledge-ops skill for cross-session intelligence aggregation and pattern recognition.

---

## Common Mistakes That Reduce ROI

1. **Testing without understanding the application**: Read documentation, use the app as a normal user first, understand the business logic before attacking
2. **Chasing P3 findings**: Spending 4 hours on missing security headers that pay $0
3. **Ignoring scope changes**: Programs regularly update scope — check before each session
4. **Skipping reconnaissance**: Jumping straight to exploitation on targets you do not understand
5. **Not checking duplicates**: Spending hours on a finding that was already reported
6. **Poor report quality**: A critical finding with a bad report may get downgraded or rejected
7. **Tunnel vision on one endpoint**: If one approach does not work, try a different angle or move on

---

## Integration with Other Skills

| Skill | Integration Point |
|-------|------------------|
| `recon-osint` | Phase 1 passive reconnaissance pipeline |
| `web-sqli` | SQL injection exploitation in Phase 3 |
| `web-xss` | XSS testing and PoC development |
| `web-ssrf` | SSRF detection and exploitation |
| `web-access-control` | IDOR and privilege escalation testing |
| `api-security` | API endpoint security testing |
| `autonomous-loops` | Automated reconnaissance and monitoring |
| `knowledge-ops` | Pattern documentation and cross-session learning |
| `article-writing` | Professional report writing and advisory drafting |
