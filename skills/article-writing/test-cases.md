# Article Writing Test Cases

## Test Case Summary

| ID | Name | Type | Status |
|----|------|------|--------|
| TC-AW-001 | Pentest Report from Knowledge Base | Pentest Report | Active |
| TC-AW-002 | CVE Disclosure from Finding | Vulnerability Disclosure | Active |
| TC-AW-003 | Technical Blog Post | Blog Post | Active |
| TC-AW-004 | Advisory Bulletin Generation | Security Advisory | Active |
| TC-AW-005 | Comparative Analysis Article | Tool Comparison | Active |

Total: 5 test cases

---

## TC-AW-001: Pentest Report from Knowledge Base

**Objective**: Generate complete penetration test report from knowledge-ops findings

**Input**: Knowledge base with 8 findings (2 critical, 3 high, 2 medium, 1 low) for target-org

**Process**:
1. Aggregate findings using knowledge-ops queries
2. Group by severity
3. Calculate CVSS scores
4. Write executive summary (non-technical)
5. Write technical details per finding
6. Add remediation recommendations
7. Sanitize all sensitive data

**Expected Output**:
- PDF report 15-25 pages
- Executive summary on page 1 (no technical jargon)
- All 8 findings documented with Evidence + Impact + Remediation
- Appendix with tools used and timeline
- No real IPs, domains, or credentials exposed

**Pass Criteria**:
- [ ] All findings from KB included in report
- [ ] CVSS scores calculated for each finding
- [ ] Sanitization complete (no real data)
- [ ] Executive summary understandable by non-technical stakeholders
- [ ] All findings have remediation steps

---

## TC-AW-002: CVE Disclosure from Finding

**Objective**: Write responsible disclosure from high-confidence finding

**Input**: KU-2026-05-002 (SQL injection finding, confidence 98, verified via exploitation)

**Process**:
1. Extract technical details from knowledge unit
2. Create minimal reproducible PoC
3. Calculate CVSS score
4. Write impact analysis
5. Propose fix (code diff or description)
6. Create disclosure timeline

**Expected Output**:
- Vulnerability disclosure document 2-3 pages
- PoC that vendor can reproduce
- Clear remediation steps
- Disclosure timeline (discovery → vendor notification → public disclosure)

**Pass Criteria**:
- [ ] PoC is minimal and reproducible
- [ ] Impact analysis is accurate
- [ ] Remediation is actionable
- [ ] Follows responsible disclosure best practices

---

## TC-AW-003: Technical Blog Post

**Objective**: Write public blog post about discovered technique

**Input**: Pattern KU-2026-05-004 (JWT HS256 weak secret pattern observed across 3 targets)

**Process**:
1. Aggregate pattern observations from knowledge base
2. Write engaging introduction (hook the reader)
3. Explain technical details with code examples
4. Provide detection and mitigation steps
5. Add references to related research

**Expected Output**:
- Blog post 1500-2500 words
- Code examples in 2-3 languages (Python, Go, JavaScript)
- Screenshots or diagrams
- Detection commands for defenders
- Secure coding practices for developers

**Pass Criteria**:
- [ ] Post is engaging and accessible to technical audience
- [ ] All code examples are correct and tested
- [ ] Detection methods are practical
- [ ] References to related research included
- [ ] No sensitive data from actual engagements exposed

---

## TC-AW-004: Advisory Bulletin Generation

**Objective**: Generate a formal security advisory bulletin from raw CVE data and internal findings

**Severity**: HIGH

**Prerequisites**: Raw CVE data (NVD JSON), internal exploitation evidence, affected asset inventory

**Steps**:
1. Parse raw CVE JSON for affected product, versions, CVSS vector
2. Cross-reference with internal asset inventory to determine exposure
3. Calculate organizational risk score (CVSS base * asset criticality)
4. Write advisory header (CVE ID, severity, affected systems, patch status)
5. Write technical analysis section with exploitation evidence
6. Write impact assessment (business impact, data at risk)
7. Write remediation steps (patch, workaround, compensating controls)
8. Write timeline (discovery → vendor notification → patch → disclosure)
9. Format for distribution (email-friendly, PDF-ready)

**Expected Output**:
- Advisory bulletin 2-4 pages
- Header with CVE ID, CVSS score, affected versions
- Technical root cause analysis (2-3 paragraphs)
- Clear remediation steps with priority ordering
- Timeline table with dates
- Distribution-ready format (no raw JSON, no internal hostnames)

**Pass Criteria**:
- [ ] CVE data correctly parsed and presented
- [ ] CVSS score matches NVD calculation
- [ ] Affected systems identified from asset inventory
- [ ] Remediation steps are actionable and prioritized
- [ ] No internal infrastructure details leaked
- [ ] Advisory follows CERT/CC or vendor advisory format

**Remediation**: Template library for common advisory formats (CERT, vendor, internal)

---

## TC-AW-005: Comparative Analysis Article

**Objective**: Write a structured comparison article evaluating multiple security tools for a specific use case

**Severity**: MEDIUM

**Prerequisites**: 3+ tools to compare, defined evaluation criteria, hands-on testing results

**Steps**:
1. Define comparison scope and use case (e.g., "SAST tools for Python web apps")
2. Establish evaluation criteria (detection rate, false positives, speed, integration, cost)
3. Create weighted scoring matrix
4. Test each tool against identical benchmark (same codebase, same vulns)
5. Document results per criterion with evidence (screenshots, metrics)
6. Write introduction explaining the comparison need
7. Write per-tool sections (strengths, weaknesses, best-for)
8. Write comparison matrix table
9. Write recommendation section with use-case-based guidance
10. Add methodology appendix for reproducibility

**Expected Output**:
- Article 2500-4000 words
- Comparison matrix table (tools × criteria with scores)
- Per-tool summary (200-300 words each)
- Clear winner recommendation with caveats
- Methodology section enabling reader reproduction
- Code snippets showing tool configuration/usage

**Pass Criteria**:
- [ ] All tools tested against identical benchmark
- [ ] Scoring criteria defined before testing (no post-hoc bias)
- [ ] Evidence provided for each score (not opinion-based)
- [ ] Recommendation includes use-case context (not one-size-fits-all)
- [ ] Article is balanced (acknowledges strengths of non-winners)
- [ ] Methodology is reproducible by reader

**Verification**: Peer review by someone familiar with at least one of the compared tools

---

## TC-AW-006: Automated Report Generation Pipeline

**Objective**: Validate end-to-end automated report generation from raw evidence files through template rendering to multi-format export

**Severity**: HIGH

**Prerequisites**: Evidence directory with 5+ JSON finding files, Jinja2 template installed, pandoc available for format conversion, at least 2 findings with overlapping titles (for deduplication testing)

**Steps**:
1. Run finding aggregation against evidence directory containing 5+ JSON files
2. Verify findings are sorted by CVSS score descending
3. Run deduplication with 0.8 similarity threshold
4. Verify duplicate findings are merged (evidence combined, count reduced)
5. Run template engine pipeline with pentest_report template
6. Verify generated markdown contains Executive Summary, all findings, and remediation sections
7. Run multi-format export (PDF, DOCX, HTML)
8. Verify all three output files are created with non-zero size
9. Verify PDF has table of contents and numbered sections
10. Verify no raw JSON or internal paths leak into final output

**Expected Output**:
- Aggregated findings list sorted by severity (Critical first)
- Deduplication report showing merged count
- Markdown report with Executive Summary, Findings (per-finding detail), and Appendix
- PDF export with TOC, numbered sections, and proper formatting
- DOCX export suitable for client editing
- HTML export with standalone styling

**Remediation**: If template rendering fails, verify Jinja2 template syntax and context variable names match. If PDF export fails, check xelatex installation. Fall back to wkhtmltopdf if xelatex unavailable.

**Pass Criteria**:
- [ ] All JSON findings loaded and normalized correctly
- [ ] Findings sorted by CVSS score (highest first)
- [ ] Duplicate findings detected and merged (evidence combined)
- [ ] Template renders without errors
- [ ] Generated report contains all required sections
- [ ] PDF, DOCX, and HTML exports all created with non-zero size
- [ ] No internal file paths or raw JSON in final output

---

## TC-AW-007: Sanitization Compliance Verification

**Objective**: Verify that all report outputs pass sanitization checks with zero leakage of real IPs, domains, credentials, or PII

**Severity**: CRITICAL

**Prerequisites**: Draft report containing intentionally planted real-looking data (RFC 1918 IPs, realistic domain names, credential-like strings), sanitization checklist script available

**Steps**:
1. Generate a draft report from evidence containing realistic (but test) sensitive data
2. Run sanitization pass: replace IPs with RFC 5737 documentation addresses
3. Run sanitization pass: replace domains with example.com variants
4. Run sanitization pass: redact credential-like strings
5. Run sanitization pass: anonymize person names
6. Run metadata stripping on any embedded screenshots (exiftool -all=)
7. Run final leak check: grep for patterns matching IPs, emails, API keys
8. Verify zero matches in final output

**Expected Output**:
- Sanitized report with all real IPs replaced (203.0.113.x, 198.51.100.x)
- All domains replaced with *.example.com
- All credentials showing [REDACTED]
- All person names anonymized
- Screenshots stripped of EXIF metadata
- Final grep scan returns zero matches for sensitive patterns

**Remediation**: If leaks detected, add the missed pattern to the sanitization regex list. Common misses: IPv6 addresses, base64-encoded credentials, credentials in URL query parameters.

**Pass Criteria**:
- [ ] Zero RFC 1918 IPs in final output (10.x, 172.16-31.x, 192.168.x)
- [ ] Zero real domain names (only *.example.com allowed)
- [ ] Zero credential-like strings (no API keys, passwords, tokens)
- [ ] Zero real person names or email addresses
- [ ] All screenshots have EXIF metadata stripped
- [ ] Final automated scan confirms zero sensitive pattern matches

---

## TC-AW-008: Multi-Finding Report Consistency Check

**Objective**: Verify that reports with 10+ findings maintain consistent formatting, correct cross-references, and accurate severity statistics throughout

**Severity**: MEDIUM

**Prerequisites**: Evidence directory with 12 findings (3 Critical, 4 High, 3 Medium, 2 Low), report template with cross-reference support

**Steps**:
1. Aggregate all 12 findings and generate full report
2. Verify Executive Summary statistics match actual finding counts (3C, 4H, 3M, 2L = 12 total)
3. Verify each finding has all required sections: Description, Impact, Remediation, Evidence
4. Verify finding IDs are sequential and unique (no gaps, no duplicates)
5. Verify CVSS scores in Executive Summary table match individual finding scores
6. Verify remediation priority ordering matches severity (Critical fixes first)
7. Check that all evidence file references point to files that exist
8. Verify consistent formatting: heading levels, code block languages, table alignment

**Expected Output**:
- Report with accurate statistics (12 findings, correct severity breakdown)
- All 12 findings with complete sections (no missing Description/Impact/Remediation)
- Sequential finding IDs without gaps
- Consistent heading hierarchy (H2 for sections, H3 for findings, H4 for sub-sections)
- All evidence references resolvable

**Remediation**: If statistics mismatch, verify aggregation counts against source files. If formatting inconsistent, apply linting pass with markdownlint before final output.

**Pass Criteria**:
- [ ] Executive Summary counts exactly match finding list (3+4+3+2=12)
- [ ] All 12 findings have Description, Impact, Remediation, and Evidence sections
- [ ] Finding IDs are unique and sequential
- [ ] CVSS scores consistent between summary table and individual findings
- [ ] All evidence file references are valid paths
- [ ] Heading hierarchy is consistent throughout (no H4 under H2)
