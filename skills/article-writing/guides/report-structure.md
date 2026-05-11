# Pentest Report Structure Best Practices

Standard structure for professional penetration test reports.

## Report Sections (In Order)

### 1. Cover Page
- Client name
- Engagement title
- Date range
- Version number
- Classification (Confidential/Restricted)

### 2. Table of Contents
- Auto-generated with page numbers

### 3. Executive Summary (1-2 pages)
- **Audience**: C-level, non-technical
- **Content**:
  - Brief description of engagement
  - Summary of findings by severity
  - Top 3 risks
  - Recommended priority actions
- **Tone**: Business impact, not technical details

### 4. Scope & Methodology (1 page)
- **In Scope**: URLs, IP ranges, systems tested
- **Out of Scope**: Systems excluded
- **Methodology**: OWASP, PTES, NIST, or custom
- **Tools**: List of primary tools used

### 5. Findings (Main Body)
- **Order**: Critical → High → Medium → Low
- **Each Finding**:
  - Title
  - Severity + CVSS
  - Description
  - Evidence (screenshot, logs, commands)
  - Impact
  - Remediation (short-term + long-term)

### 6. Summary & Recommendations (1 page)
- Overall security posture
- Priority remediation roadmap
- Long-term improvements

### 7. Appendix
- Detailed tool list with versions
- Testing timeline
- Raw scan outputs (if requested)
- References

---

## Page Limits by Report Size

| Engagement Size | Expected Pages |
|-----------------|---------------|
| Small (1-3 days) | 10-20 pages |
| Medium (1-2 weeks) | 20-40 pages |
| Large (2+ weeks) | 40-80 pages |

---

## Formatting Standards

- **Font**: Arial or Calibri, 11-12pt
- **Headings**: Bold, larger font
- **Code/Commands**: Monospace font, gray background
- **Screenshots**: Caption below, reference in text
- **Tables**: Border lines, alternating row colors

---

## Common Mistakes to Avoid

1. **Too much technical detail in executive summary** — save it for findings section
2. **No evidence** — every claim needs proof
3. **Generic remediation** — be specific to the client's tech stack
4. **Missing CVSS scores** — clients expect quantified severity
5. **Unsanitized data** — real IPs/domains/credentials must be redacted
