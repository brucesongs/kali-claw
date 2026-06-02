# Security Review -- Test Cases

> This file is a companion to `SKILL.md`, providing structured test cases for security review methodology.
> Purpose: Systematic verification checklist ensuring all OWASP categories are assessed during a security review.
> Each case includes scenario, pre-conditions, test steps, expected outcomes, and post-conditions.
> All tests are intended solely for authorized security assessments.

---

## Test Case Format

```
TC-SR-XXX | [Category] Test Name
Scenario: What is being tested
Pre-conditions: What must be true before testing
Test Steps: Numbered operations
Expected Outcomes: Observable results in table form
Post-conditions: State after test completion
```

---

## Index

- [TC-SR-001: Secrets Management Review](#tc-sr-001-secrets-management-review)
- [TC-SR-002: Input Validation Assessment](#tc-sr-002-input-validation-assessment)
- [TC-SR-003: Injection Flaw Detection](#tc-sr-003-injection-flaw-detection)
- [TC-SR-004: Authentication and Authorization Audit](#tc-sr-004-authentication-and-authorization-audit)
- [TC-SR-005: Security Headers Verification](#tc-sr-005-security-headers-verification)
- [TC-SR-006: Dependency Security Audit](#tc-sr-006-dependency-security-audit)
- [TC-SR-007: Complete OWASP Top 10 Review](#tc-sr-007-complete-owasp-top-10-review)

---

## TC-SR-001: Secrets Management Review

- **Scenario**: Scan codebase and deployed services for hardcoded secrets, exposed configuration files, and inadequate secret management practices.
- **Pre-conditions**:
  - Access to source code repository or deployed application
  - TruffleHog and/or Gitleaks installed
  - Target URL for exposed file checks identified
- **Test Steps**:
  1. Run `trufflehog filesystem /path/to/repo` to scan codebase for secrets
  2. Run `gitleaks detect --source /path/to/repo -v` for complementary detection
  3. Execute manual grep patterns for API keys, tokens, passwords, private keys
  4. Check for exposed files: `.env`, `.git/HEAD`, `backup.sql`, `config.yml.bak`, `actuator/env`
  5. Verify secret management: confirm secrets are loaded from environment variables or vault
  6. Check client-side code for embedded credentials
  7. Review `.gitignore` for missing sensitive file patterns
- **Expected Outcomes**:

| Check | Finding | Severity |
|-------|---------|----------|
| TruffleHog scan | No hardcoded secrets detected | PASS |
| Gitleaks scan | No leaked credentials | PASS |
| Manual grep | No API keys, tokens, passwords in source | PASS |
| Exposed files | `.env`, `.git/HEAD`, backups return 404 | PASS |
| Secret management | All secrets from env vars or vault | PASS |
| Client-side code | No credentials in JS bundles | PASS |
| `.gitignore` | All sensitive patterns excluded | PASS |

- **Post-conditions**:
  - All discovered secrets documented with file location and type
  - Confirmed secrets reported to asset owner for immediate rotation
  - Secret management recommendations recorded for remediation
- **Reference**: payloads.md sections 1.1 through 1.4

---

## TC-SR-002: Input Validation Assessment

- **Scenario**: Test all input vectors for missing or insufficient server-side validation, including form fields, API parameters, file uploads, and HTTP headers.
- **Pre-conditions**:
  - Application accessible and all entry points identified
  - Burp Suite or similar proxy configured
  - Test account with standard user privileges
- **Test Steps**:
  1. Map all input vectors: URL parameters, POST bodies, HTTP headers, cookies, file uploads
  2. Submit unexpected data types (string where number expected, negative values, zero)
  3. Test boundary values: maximum length, minimum length, empty, null
  4. Submit special characters: `<>, "'", ", &, /, \, {, }, [, ], (, )`
  5. Test file uploads: wrong MIME type, double extension (`shell.php.jpg`), null byte (`shell.php%00.jpg`)
  6. Verify server-side validation exists independent of client-side checks
  7. Check Content-Type validation on API endpoints
  8. Test output encoding by submitting HTML/JS content and inspecting rendered response
- **Expected Outcomes**:

| Input Vector | Validation Check | Expected Behavior |
|--------------|-----------------|-------------------|
| Form fields | Type enforcement | Invalid types rejected with clear error |
| API parameters | Schema validation | Malformed requests return 400 |
| File uploads | Type, size, content check | Disallowed types rejected |
| HTTP headers | Length and charset limit | Oversized headers truncated or rejected |
| Output rendering | HTML encoding | Special characters HTML-encoded in output |
| Client-side bypass | Server validation active | Invalid data rejected regardless of client checks |

- **Post-conditions**:
  - All input vectors documented with validation status
  - Missing validation points flagged with severity rating
  - Recommendations for schema-based validation provided
- **Reference**: SKILL.md section 2 (Input Validation)

---

## TC-SR-003: Injection Flaw Detection

- **Scenario**: Test SQL injection, command injection, LDAP injection, and SSTI across all identified entry points to confirm parameterized queries and input sanitization.
- **Pre-conditions**:
  - All input entry points mapped (from TC-SR-002 or surface mapping)
  - sqlmap installed for automated SQLi testing
  - Burp Suite Repeater available for manual testing
  - Target application accessible with authenticated session
- **Test Steps**:
  1. **SQL Injection**: Submit `' OR 1=1 --` and `' AND SLEEP(5)-- -` at each input point; run sqlmap on confirmed injection points
  2. **Command Injection**: Test `; id`, `$(id)`, `` `id` `` at parameters that may reach OS commands
  3. **LDAP Injection**: Test `*)(uid=*))(|(uid=*` at login/search fields connected to LDAP
  4. **SSTI**: Test `{{7*7}}`, `${7*7}`, `<%= 7*7 %>` at template-rendered input points
  5. Verify all injection attempts are rejected or sanitized
  6. Confirm parameterized queries or ORM usage for database operations
  7. Check for unsafe deserialization in file upload and API endpoints
- **Expected Outcomes**:

| Injection Type | Test Payload | Expected Behavior |
|---------------|-------------|-------------------|
| SQLi (error-based) | `' OR 1=1 --` | No SQL error, application handles gracefully |
| SQLi (time-based) | `' AND SLEEP(5)-- -` | No abnormal delay |
| Command injection | `; id` | Command not executed, input rejected |
| LDAP injection | `*)(uid=*))(|(uid=*` | LDAP query fails safely |
| SSTI (Jinja2) | `{{7*7}}` | Literal string returned, not `49` |
| SSTI (Freemarker) | `${7*7}` | Literal string returned, not `49` |
| Unsafe deserialization | Pickle/YAML payload | Deserialization rejected or sandboxed |

- **Post-conditions**:
  - Each entry point documented with injection test results
  - Confirmed vulnerabilities recorded with CWE classification
  - Remediation guidance: parameterized queries, allowlist input validation, output encoding
- **Reference**: payloads.md section 2 (Injection Test Payloads)

---

## TC-SR-004: Authentication and Authorization Audit

- **Scenario**: Test authentication mechanisms for weaknesses (password policy, MFA, session management) and authorization for access control flaws (IDOR, privilege escalation, missing checks).
- **Pre-conditions**:
  - Minimum two user accounts at different privilege levels
  - Authentication endpoints identified (login, logout, password reset, MFA)
  - Session management mechanism understood (cookie, JWT, OAuth)
- **Test Steps**:
  1. **Password policy**: Test weak passwords, length minimums, complexity requirements
  2. **Default credentials**: Attempt common default username/password combinations
  3. **Account lockout**: Test rate limiting on login after 10+ failed attempts
  4. **Session management**: Check session ID rotation on login, cookie flags (HttpOnly, Secure, SameSite)
  5. **Session fixation**: Attempt to set session ID before authentication
  6. **JWT testing**: Check algorithm (none attack), token expiry, signature verification
  7. **IDOR**: Access resources belonging to other users by modifying IDs in URL/body
  8. **Privilege escalation**: Attempt admin actions as standard user via direct API calls
  9. **Missing authorization**: Access API endpoints without authentication token
  10. **Role-based access**: Verify each role can only access its permitted resources
- **Expected Outcomes**:

| Test Area | Check | Expected Behavior |
|-----------|-------|-------------------|
| Password policy | Weak password acceptance | Complex passwords required |
| Default credentials | admin:admin login | Rejected or changed from default |
| Rate limiting | 50 rapid login attempts | Account locked or rate-limited (429) |
| Session cookies | HttpOnly, Secure, SameSite flags | All three flags present |
| Session rotation | Pre/post login session ID | Session ID changes after authentication |
| JWT validation | Modified token payload | Server rejects tampered token |
| IDOR | Modified resource ID | Access denied for other user resources |
| Privilege escalation | Admin API as standard user | 403 Forbidden returned |
| Unauthenticated access | API without token | 401 Unauthorized returned |

- **Post-conditions**:
  - Authentication mechanism fully documented with weaknesses identified
  - Authorization matrix created showing role vs. endpoint access
  - Session management findings recorded with remediation priority
- **Reference**: payloads.md section 3 (Authentication Testing)

---

## TC-SR-005: Security Headers Verification

- **Scenario**: Verify presence and correct configuration of all security headers, TLS settings, and CORS policy on the target application.
- **Pre-conditions**:
  - Target URL identified and accessible
  - curl, nmap, and optionally testssl.sh available
  - HTTPS endpoint confirmed for TLS testing
- **Test Steps**:
  1. **Security headers**: Run comprehensive header check curl command against target
  2. **HSTS**: Verify `Strict-Transport-Security` header present with adequate max-age
  3. **CSP**: Verify `Content-Security-Policy` header present and not using `unsafe-inline` or `*`
  4. **Clickjacking**: Verify `X-Frame-Options` set to `DENY` or `SAMEORIGIN`
  5. **MIME sniffing**: Verify `X-Content-Type-Options` set to `nosniff`
  6. **TLS configuration**: Run `nmap --script ssl-enum-ciphers` and verify no weak ciphers
  7. **TLS version**: Confirm TLS 1.2+ only, TLS 1.0/1.1 disabled
  8. **Certificate**: Check expiry, chain validity, and hostname match
  9. **CORS policy**: Test with malicious origin, null origin, and subdomain origin
  10. **Referrer-Policy**: Verify set to `strict-origin-when-cross-origin` or stricter
- **Expected Outcomes**:

| Header / Setting | Expected Value | Finding |
|-----------------|---------------|---------|
| Strict-Transport-Security | `max-age=31536000; includeSubDomains` | Present with long max-age |
| Content-Security-Policy | Defined policy without `unsafe-inline` | Restrictive CSP configured |
| X-Frame-Options | `DENY` or `SAMEORIGIN` | Clickjacking protection enabled |
| X-Content-Type-Options | `nosniff` | MIME sniffing prevented |
| TLS version | 1.2 or 1.3 only | No TLS 1.0/1.1 support |
| Weak ciphers | None | Only strong cipher suites enabled |
| CORS | Specific origins only | No wildcard or null origin allowed |
| Referrer-Policy | `strict-origin-when-cross-origin` | Limited referrer leakage |
| Permissions-Policy | Restrictive set | Sensitive features disabled |

- **Post-conditions**:
  - Complete header audit report with present/missing status
  - TLS configuration documented with cipher suite analysis
  - CORS policy assessment with misconfiguration findings
- **Reference**: payloads.md section 4 (Security Headers Verification)

---

## TC-SR-006: Dependency Security Audit

- **Scenario**: Run dependency vulnerability scanners across all project components to identify known CVEs, outdated packages, and vulnerable transitive dependencies.
- **Pre-conditions**:
  - Access to project dependency files (`package.json`, `requirements.txt`, `Cargo.toml`, `go.mod`, `pom.xml`)
  - Relevant audit tools installed (npm audit, pip-audit, cargo audit, govulncheck)
  - Container scanning tools available if Docker images are in scope
- **Test Steps**:
  1. **Language-specific audit**: Run appropriate scanner for each language in the project
  2. **npm**: Run `npm audit` and review results for HIGH and CRITICAL vulnerabilities
  3. **Python**: Run `pip-audit -r requirements.txt` and `safety check`
  4. **Rust**: Run `cargo audit` for known vulnerabilities
  5. **Go**: Run `govulncheck ./...` for Go module vulnerabilities
  6. **Java**: Run OWASP Dependency-Check Maven/Gradle plugin
  7. **Container images**: Run `trivy image` and `grype` on all Docker images
  8. **Snyk scan**: Run `snyk test` for comprehensive dependency analysis
  9. **Transitive dependencies**: Check if vulnerable indirect dependencies exist
  10. **Update status**: Verify if dependencies are on latest stable versions
- **Expected Outcomes**:

| Scan Type | Tool | Expected Result |
|-----------|------|-----------------|
| Node.js dependencies | `npm audit` | No HIGH or CRITICAL vulnerabilities |
| Python packages | `pip-audit` | No known CVEs in dependencies |
| Rust crates | `cargo audit` | No vulnerable crates |
| Go modules | `govulncheck` | No known vulnerabilities |
| Java libraries | OWASP Dependency-Check | No HIGH severity findings |
| Container images | Trivy / Grype | No CRITICAL CVEs in base image |
| Transitive deps | All tools | No vulnerable indirect dependencies |
| Update status | Manual check | Dependencies within latest major version |

- **Post-conditions**:
  - Dependency vulnerability report generated with CVE references
  - Prioritized update recommendations based on severity
  - Base image upgrade path documented for container findings
- **Reference**: payloads.md section 5 (Dependency Audit Commands)

---

## TC-SR-007: Complete OWASP Top 10 Review

- **Scenario**: Full application security audit covering all 10 OWASP Top 10 (2021) categories in a systematic, integrated workflow.
- **Pre-conditions**:
  - Engagement scope and rules of engagement documented
  - Test accounts at multiple privilege levels provisioned
  - Source code or binary access (white-box) or application URL only (black-box)
  - All required tools installed and configured
  - Authorization to test confirmed in writing
- **Test Steps**:
  1. **A01 - Broken Access Control**: Execute TC-SR-004 authorization tests (IDOR, privilege escalation, missing auth checks)
  2. **A02 - Cryptographic Failures**: Check for plaintext data transmission, weak hashing (MD5/SHA1), hardcoded encryption keys
  3. **A03 - Injection**: Execute TC-SR-003 injection tests (SQL, command, LDAP, SSTI, XSS)
  4. **A04 - Insecure Design**: Review business logic for abuse cases (race conditions, workflow bypass)
  5. **A05 - Security Misconfiguration**: Execute TC-SR-005 header verification, check default settings, unnecessary services
  6. **A06 - Vulnerable Components**: Execute TC-SR-006 dependency audit
  7. **A07 - Auth Failures**: Execute TC-SR-004 authentication tests (brute force, credential stuffing, session management)
  8. **A08 - Software and Data Integrity**: Check CI/CD pipeline security, unsigned updates, insecure deserialization
  9. **A09 - Logging and Monitoring**: Verify security event logging, alerting for failed auth, audit trail completeness
  10. **A10 - SSRF**: Test URL-fetching endpoints for internal network access, cloud metadata retrieval
  11. Compile findings into structured report using SKILL.md Report Template
  12. Classify each finding by severity (CRITICAL/HIGH/MEDIUM/LOW/INFO)
  13. Map findings to CWE IDs and OWASP categories
- **Expected Outcomes**:

| OWASP Category | Coverage | Status |
|---------------|----------|--------|
| A01 Broken Access Control | All endpoints tested | Findings documented |
| A02 Cryptographic Failures | Data in transit and at rest checked | Encryption verified |
| A03 Injection | All entry points tested | Injection vectors confirmed/rejected |
| A04 Insecure Design | Business logic reviewed | Abuse cases identified |
| A05 Security Misconfiguration | Headers, defaults, services checked | Misconfigs documented |
| A06 Vulnerable Components | All dependency files scanned | CVEs listed with severity |
| A07 Auth Failures | Auth mechanisms fully tested | Weaknesses recorded |
| A08 Software and Data Integrity | CI/CD and deserialization reviewed | Integrity gaps noted |
| A09 Logging and Monitoring | Log coverage and alerting verified | Gaps identified |
| A10 SSRF | URL-fetching endpoints tested | Internal access verified/blocked |

- **Post-conditions**:
  - Complete security review report delivered using SKILL.md template
  - All findings mapped to OWASP categories and CWE IDs
  - Executive summary with overall risk rating provided
  - Remediation recommendations prioritized by severity
  - Report archived to chronicle for future reference
- **Reference**: SKILL.md (all sections), payloads.md (all sections), guides/owasp-audit-methodology.md

---

## Quick Reference: Test Case to Payload Mapping

| Test Case | Primary Payloads Reference |
|-----------|---------------------------|
| TC-SR-001 | payloads.md section 1 (Secrets Detection) |
| TC-SR-002 | payloads.md section 2.5 (XSS payloads for output encoding) |
| TC-SR-003 | payloads.md section 2 (Injection Test Payloads) |
| TC-SR-004 | payloads.md section 3 (Authentication Testing) |
| TC-SR-005 | payloads.md section 4 (Security Headers Verification) |
| TC-SR-006 | payloads.md section 5 (Dependency Audit Commands) |
| TC-SR-007 | payloads.md (all sections) |

---

## TC-SR-008: Supply Chain Dependency Review Automation

- **Scenario**: Automate the full dependency security review pipeline — from dependency file discovery through vulnerability scanning, license compliance checking, integrity verification, and supply chain attack surface analysis — to produce a comprehensive supply chain risk report.
- **Pre-conditions**:
  - Access to project source code repository
  - All dependency lockfiles present (`package-lock.json`, `yarn.lock`, `Pipfile.lock`, `Cargo.lock`, `go.sum`, `pom.xml`)
  - Tools installed: `trivy`, `grype`, `npm`, `pip-audit`, `cargo audit`, `govulncheck`, `syft`, `cosign`
  - SBOM (Software Bill of Materials) generation capability
  - Repository commit history accessible for dependency change analysis
- **Test Steps**:
  1. **Discover all dependency files** in the repository:
     ```bash
     find . -type f \( -name "package.json" -o -name "package-lock.json" -o -name "yarn.lock" \
       -o -name "requirements.txt" -o -name "Pipfile.lock" -o -name "poetry.lock" \
       -o -name "Cargo.toml" -o -name "Cargo.lock" -o -name "go.mod" -o -name "go.sum" \
       -o -name "pom.xml" -o -name "build.gradle" \) > dependency_files.txt
     cat dependency_files.txt
     ```
  2. **Generate Software Bill of Materials (SBOM)**:
     ```bash
     # Generate SBOM using syft
     syft dir:. -o spdx-json > sbom-spdx.json
     syft dir:. -o cyclonedx-json > sbom-cyclonedx.json

     # Count total dependencies
     jq '.packages | length' sbom-spdx.json
     ```
  3. **Run multi-tool vulnerability scanning**:
     ```bash
     # Trivy comprehensive scan
     trivy fs --format json --output trivy-results.json .

     # Grype scan against SBOM
     grype sbom:sbom-cyclonedx.json -o json > grype-results.json

     # Language-specific audits
     npm audit --json > npm-audit.json 2>/dev/null
     pip-audit -r requirements.txt --format json > pip-audit.json 2>/dev/null
     cargo audit --format json > cargo-audit.json 2>/dev/null
     govulncheck ./... -json > go-vuln.json 2>/dev/null
     ```
  4. **Check dependency integrity and provenance**:
     ```bash
     # Verify npm package integrity (lockfile hashes)
     npm ci --dry-run 2>&1 | grep -i "integrity\|mismatch" || echo "PASS: npm integrity verified"

     # Check for typosquatting in package names
     pip-audit --desc | grep -iE "typosquat|malicious|impersonat" || echo "No typosquatting detected"

     # Verify signed packages where possible
     cosign verify-blob --key cosign.pub --signature artifact.sig artifact.tar.gz
     ```
  5. **Analyze dependency change history** for supply chain risk indicators:
     ```bash
     # Find recently added dependencies (last 30 days)
     git log --since="30 days ago" --diff-filter=A -- "package.json" "requirements.txt" "Cargo.toml" | head -50

     # Find dependencies updated to unexpected versions
     git log --since="30 days ago" -p -- "package-lock.json" | grep -E "^\+.*version" | head -30

     # Check for version jumps (potential compromise indicator)
     git log --oneline -- "package-lock.json" | head -20
     ```
  6. **License compliance check**:
     ```bash
     # Scan for restricted licenses
     trivy fs --scanners license --license-full .

     # Flag copyleft (GPL, AGPL) in proprietary projects
     jq '.results[] | select(.type == "license") | .vulnerabilities[] | select(.severity == "HIGH")' trivy-results.json
     ```
  7. **Cross-reference with known supply chain attacks**:
     ```bash
     # Check against OSV database for known supply chain vulnerabilities
     curl -s -d '{"version": "", "package": {"name": "", "ecosystem": ""}}' \
       https://api.osv.dev/v1/querybatch -d @- < osv-query.json

     # Check for dependencies from abandoned or transferred packages
     # Flag: packages with no updates in >2 years, single maintainer, recently transferred ownership
     ```
  8. **Generate consolidated supply chain risk report**:
     ```bash
     python3 -c "
     import json

     # Load all scan results
     trivy = json.load(open('trivy-results.json'))
     grype = json.load(open('grype-results.json'))

     # Aggregate critical/high findings
     critical = []
     high = []

     for result in trivy.get('Results', []):
         for vuln in result.get('Vulnerabilities', []):
             if vuln.get('Severity') == 'CRITICAL':
                 critical.append(f\"{vuln['PkgName']}:{vuln['InstalledVersion']} - {vuln['VulnerabilityID']}\")
             elif vuln.get('Severity') == 'HIGH':
                 high.append(f\"{vuln['PkgName']}:{vuln['InstalledVersion']} - {vuln['VulnerabilityID']}\")

     print(f'CRITICAL: {len(critical)} findings')
     print(f'HIGH: {len(high)} findings')
     for c in critical[:10]: print(f'  {c}')
     "
     ```
- **Expected Outcomes**:

  | Check | Tool | Expected Result |
  |-------|------|-----------------|
  | SBOM generated | syft | Complete SBOM with all direct and transitive dependencies |
  | Vulnerability scan | trivy + grype | No CRITICAL vulnerabilities in production dependencies |
  | Language-specific audit | npm audit, pip-audit, cargo audit, govulncheck | No HIGH or CRITICAL CVEs |
  | Integrity check | npm ci, cosign | All package hashes match lockfile |
  | Typosquatting check | pip-audit, manual | No suspiciously named packages |
  | License compliance | trivy license scanner | No restricted licenses in proprietary codebase |
  | Change history | git log analysis | No suspicious version jumps or unexpected additions |
  | Supply chain attacks | OSV database | No known supply chain attack patterns detected |

- **Post-conditions**:
  - Consolidated supply chain risk report with all findings prioritized by severity
  - SBOM archived for future reference and audit compliance
  - Dependency update recommendations with specific version targets
  - Supply chain risk score calculated for the project
  - Remediation plan with priority order: CRITICAL CVEs first, then HIGH, then license issues
- **Reference**: payloads.md section 5 (Dependency Audit Commands), TC-SR-006 (Dependency Security Audit)
