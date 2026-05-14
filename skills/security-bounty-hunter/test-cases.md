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
