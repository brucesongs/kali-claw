# Penetration Test Report Template

## 1. Executive Summary

**Client**: [Client Name]
**Engagement Date**: [Start Date] — [End Date]
**Assessor**: kali-claw agent
**Report Date**: [Date]
**Classification**: Confidential

### Overall Risk Rating

| Rating | Description |
|--------|-------------|
| [CRITICAL/HIGH/MEDIUM/LOW/INFO] | [One-line risk summary] |

### Finding Summary

| Severity | Count |
|----------|-------|
| Critical | [N] |
| High | [N] |
| Medium | [N] |
| Low | [N] |
| Informational | [N] |

---

## 2. Scope

| Field | Value |
|-------|-------|
| Target(s) | [List all in-scope targets] |
| Target Type | [web/cloud/network/mobile/api] |
| Exclusions | [List out-of-scope items] |
| Methodology | OWASP Testing Guide / PTES / OSSTMM |
| Authorization | [Reference to signed ROE] |

---

## 3. Methodology

### Kill Chain Phases Executed

1. **Reconnaissance** — Passive and active information gathering
2. **Scanning** — Port and service discovery
3. **Enumeration** — Deep service and application analysis
4. **Vulnerability Discovery** — Manual and automated vulnerability identification
5. **Exploitation** — Verified exploitation of findings
6. **Post-Exploitation** — Impact assessment and lateral movement
7. **Reporting** — Documentation and remediation guidance

---

## 4. Findings

### Finding [F-001]: [Title]

| Field | Value |
|-------|-------|
| **Severity** | [Critical/High/Medium/Low/Info] |
| **CVSS Score** | [0.0-10.0] |
| **CVSS Vector** | [AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H] |
| **Affected Asset** | [hostname/IP/URL] |
| **Category** | [OWASP Category] |
| **Kill Chain Phase** | [Phase name] |

#### Description

[Detailed description of the vulnerability]

#### Proof of Concept

```
[Commands, screenshots, or steps to reproduce]
```

#### Impact

[Business and technical impact analysis]

#### Remediation

[Specific steps to fix the vulnerability]

#### References

- [CWE-XXX](https://cwe.mitre.org/data/definitions/XXX.html)
- [OWASP Reference](https://owasp.org/www-community/...)

---

_Repeat F-001 template for each finding._

---

## 5. Risk Matrix

| Finding | Severity | Exploitability | Impact | Status |
|---------|----------|---------------|--------|--------|
| F-001: [Title] | [Severity] | [Easy/Medium/Hard] | [High/Medium/Low] | [Open/Fixed/Accepted] |

---

## 6. Recommendations

### Immediate (Critical)

1. [Recommendation]
2. [Recommendation]

### Short-term (High)

1. [Recommendation]
2. [Recommendation]

### Medium-term (Medium)

1. [Recommendation]
2. [Recommendation]

### Long-term (Low/Info)

1. [Recommendation]
2. [Recommendation]

---

## 7. Conclusion

[Overall assessment summary and strategic recommendations]

---

## Appendix A: Tools Used

| Tool | Version | Purpose |
|------|---------|---------|
| [Tool] | [Version] | [Purpose] |

## Appendix B: Raw Evidence

[Evidence files are stored in engagement/evidence/ directory]

## Appendix C: Rules of Engagement

[Reference or include the signed ROE document]
