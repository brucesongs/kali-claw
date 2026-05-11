# Article Writing Test Cases

## Test Case Summary

| ID | Name | Type | Status |
|----|------|------|--------|
| TC-AW-001 | Pentest Report from Knowledge Base | Pentest Report | Active |
| TC-AW-002 | CVE Disclosure from Finding | Vulnerability Disclosure | Active |
| TC-AW-003 | Technical Blog Post | Blog Post | Active |

Total: 3 test cases

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
