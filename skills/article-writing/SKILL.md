# Article Writing

## Skill Identity

| Attribute | Value |
|-----------|-------|
| Domain | Documentation & Communication |
| Skill ID | article-writing |
| Version | 1.0.0 |
| Hacker Laws | Law 8 (Learn from Every Operation), Law 11 (Share Knowledge, Build Legacy) |
| Related Skills | knowledge-ops, deep-research |

## Purpose

Transform technical findings into clear, structured written content: penetration test reports, vulnerability disclosures, security blog posts, and technical documentation.

Writing is the final step in the intelligence workflow — turning raw findings into actionable deliverables for clients, researchers, or the public.

## Article Types

| Type | Audience | Format | Length |
|------|----------|--------|--------|
| **Pentest Report** | Client (technical + executive) | Executive Summary + Technical Findings | 10-50 pages |
| **Vulnerability Disclosure** | Vendor security team | CVE template + PoC | 2-5 pages |
| **Security Blog Post** | Public (technical) | Narrative + code samples | 1000-3000 words |
| **Advisory** | Public (mixed audience) | CVSS + mitigation steps | 500-1500 words |
| **Technical Documentation** | Internal team | How-to guide | Variable |

## Methodology

### Phase 1: Gather Intelligence

```bash
# Aggregate all findings from knowledge-ops
grep -rn "type: finding" memory/*target*.md | wc -l

# Extract high-confidence findings (>= 75)
grep -rn "confidence: [789][0-9]\|confidence: 100" memory/*target*.md -l | \
  xargs grep -h "## Summary"

# Group by severity
grep -rn "tags:.*critical\|tags:.*high" memory/*target*.md
```

### Phase 2: Structure Content

Follow the appropriate template (see below) for the article type. Outline before writing.

### Phase 3: Write

- **Executive Summary**: Non-technical, business impact-focused
- **Technical Detail**: Reproducible, includes code/commands
- **Evidence**: Screenshots, logs, PoC code
- **Recommendations**: Actionable remediation steps

### Phase 4: Review

- Technical accuracy check
- No sensitive data leakage (sanitize IPs, domains, credentials)
- CVSS scoring (if applicable)
- Proofread for clarity

## Templates

### Pentest Report Template

```markdown
# Penetration Test Report: [Client Name]

**Date**: [date]
**Version**: [version]
**Prepared by**: [your org]
**Classification**: [Confidential/Restricted]

---

## Executive Summary

[Target]: [description of target scope]
[Duration]: [test dates]
[Findings Summary]: [count by severity]

### Key Findings

- **Critical**: [count] — [one-line impact]
- **High**: [count] — [one-line impact]
- **Medium**: [count] — [one-line impact]
- **Low**: [count] — [one-line impact]

### Business Impact

[2-3 sentences on overall risk to the organization]

### Recommendations Priority

1. [Most critical fix]
2. [Second priority]
3. [Third priority]

---

## Scope

**In Scope**:
- [systems/domains tested]

**Out of Scope**:
- [systems excluded]

**Testing Methodology**: [OWASP, PTES, custom]

---

## Findings

### Finding 1: [Vulnerability Name]

**Severity**: Critical
**CVSS**: 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
**Affected Systems**: [list]

#### Description

[What is the vulnerability? How does it work?]

#### Evidence

```bash
[Commands used to discover/exploit]
```

[Screenshot or log output]

#### Impact

- **Confidentiality**: [High/Medium/Low] — [why]
- **Integrity**: [High/Medium/Low] — [why]
- **Availability**: [High/Medium/Low] — [why]

#### Remediation

**Short-term**: [immediate fix]
**Long-term**: [architectural improvement]

**Verification**: [how to verify fix]

---

[Continue for all findings]

---

## Appendix

### Tools Used

- [tool list with versions]

### Testing Timeline

| Date | Activity |
|------|----------|
| [date] | Reconnaissance |
| [date] | Vulnerability scanning |
| [date] | Manual testing |
| [date] | Exploitation |
| [date] | Reporting |

### References

- [OWASP guides, CVE references, etc.]
```

### Vulnerability Disclosure Template

```markdown
# Vulnerability Disclosure: [Vulnerability Name]

**Date**: [discovery date]
**Severity**: [Critical/High/Medium/Low]
**CVSS**: [score] ([vector])
**CVE ID**: [if assigned, otherwise "Pending"]

---

## Summary

[One-paragraph description of the vulnerability]

## Affected Products

- **Product**: [name]
- **Versions**: [affected versions]
- **Fixed in**: [patched version, if known]

## Vulnerability Details

### Type

[SQL Injection / XSS / SSRF / etc.]

### Location

- **File**: [file path or URL]
- **Parameter**: [vulnerable parameter]
- **Method**: [GET/POST/etc.]

### Root Cause

[Technical explanation of why the vulnerability exists]

## Proof of Concept

```bash
[Minimal PoC to reproduce]
```

**Expected Result**: [what should happen]
**Actual Result**: [what happens, demonstrating the vuln]

## Impact

[Detailed impact analysis — what can an attacker achieve?]

## Remediation

### Developer Fix

```diff
[Code diff showing the fix, if simple]
```

### Workaround (if patch not available)

[Temporary mitigation steps]

## Timeline

| Date | Event |
|------|-------|
| [date] | Vulnerability discovered |
| [date] | Vendor notified |
| [date] | Vendor acknowledged |
| [date] | Patch released |
| [date] | Public disclosure |

## Credits

[Your name/org]

## References

- [Related CVEs, vendor advisories, etc.]
```

### Security Blog Post Template

```markdown
# [Catchy Title]: [One-Sentence Hook]

**Published**: [date]
**Author**: [name]
**Tags**: [tag1, tag2, tag3]

---

## TL;DR

[2-3 sentences summarizing the entire post]

---

## Introduction

[Set the stage — why does this topic matter? What problem are you solving?]

## Background

[Context needed to understand the vulnerability/technique/tool]

## Discovery

[How did you find this? What were the initial signals?]

## Deep Dive

[Technical details — this is the meat of the post]

### Step 1: [Phase Name]

[Description]

```bash
[Commands]
```

[Output/screenshot]

### Step 2: [Phase Name]

[Continue for all steps]

## Impact & Exploitation

[What can an attacker do with this? Real-world scenarios]

## Detection & Mitigation

### For Defenders

- [Detection method 1]
- [Detection method 2]

### For Developers

- [Secure coding practice to prevent this]

## Conclusion

[Wrap up — key takeaways, call to action]

## References

- [Links to related research, tools, CVEs]
```

## Use Cases

1. **Pentest Deliverable**: Final report for client after engagement
2. **Responsible Disclosure**: Notify vendor of discovered vulnerability
3. **Knowledge Sharing**: Publish research findings publicly
4. **Internal Documentation**: Record methodology for team playbooks
5. **Advisory Publishing**: Warn community of active threat

## Writing Best Practices

- **Be precise**: Use exact file paths, line numbers, version numbers
- **Be reproducible**: Include all commands, payloads, and environment details
- **Be cautious**: Sanitize sensitive data (IPs, domains, real credentials)
- **Be visual**: Screenshots, diagrams, code blocks
- **Be actionable**: Every finding needs a clear fix

## Integration

- **Input**: knowledge-ops findings, test-cases validation results
- **Output**: Markdown/PDF reports, blog posts, advisories
- **Handoff**: Share with client, vendor, or publish publicly
