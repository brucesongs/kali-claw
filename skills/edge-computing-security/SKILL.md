---
name: edge-computing-security
description: "Edge computing security testing covering CDN bypass, Cloudflare Workers abuse, AWS Lambda@Edge attacks, cache poisoning, origin IP discovery, WAF bypass, and edge function injection."
origin: kali-claw
version: "0.2.0.2"
compatibility:
  - openclaw
  - claude-code
  - cursor
  - windsurf
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
  - WebSearch
  - WebFetch
metadata:
  domain: edge
  category: cdn-edge
  tool_count: 7
  guide_count: 0
  mitre: "TA0001-Initial Access, T1190-Exploit Public-Facing App"
  last_reviewed: "2026-07-26"
  keywords: ["CDN", "Cloudflare", "Lambda@Edge", "cache poisoning", "origin IP", "WAF bypass"]
---

# Skill: edge-computing-security

## Summary

Edge computing security testing covering CDN bypass, Cloudflare Workers abuse, AWS Lambda@Edge attacks, cache poisoning, origin IP discovery, WAF bypass, and edge function injection.

**Tools**: garak, PyRIT, promptfoo, custom harnesses

**Domain**: edge

**MITRE**: TA0001-Initial Access, T1190-Exploit Public-Facing App

## Description

Edge computing security testing covering CDN bypass, Cloudflare Workers abuse, AWS Lambda@Edge attacks, cache poisoning, origin IP discovery, WAF bypass, and edge function injection.

This skill covers the offensive side of cdn-edge security, including reconnaissance, vulnerability discovery, exploitation, persistence, and reporting. Aligned with OWASP Top 10, MITRE ATT&CK, and industry-specific compliance frameworks.

---

## Use Cases

1. **CDN/WAF bypass**: Bypass CDN to attack origin directly.
2. **Edge function exploitation**: Abuse Cloudflare Workers, Lambda@Edge for code execution at edge.
3. **Cache poisoning**: Poison cached responses to affect all users.
4. **Origin IP discovery**: Find direct IP to bypass CDN/WAF.
5. **Edge persistence**: Maintain persistence via edge functions (survives origin compromise).

---

## Core Tools

| **Cloudflare wrangler** | Workers development/deploy | `wrangler deploy` |
| **serverless-cli** | Multi-cloud serverless | `serverless deploy` |
| **waf-bypass** | WAF bypass payloads | Various scripts |
| **Curl with resolver** | Origin IP discovery | `curl --resolve target.com:443:ORIGIN_IP` |
| **Burp Suite Collaborator** | Cache poisoning | Out-of-band detection |
| **DNS recon** | Origin IP discovery | `dig`, `dnsrecon` |
| **Nmap** | Direct origin scan | `nmap -sS ORIGIN_IP` |

---

## Methodology

### Attack Chain

```
[1] CDN Detection           [2] Origin Discovery      [3] Bypass WAF
  - Cloudflare/Akamai/etc     - DNS history (SecurityTrails)   - Origin direct
  - Worker script analysis    - SSL cert SAN            - HTTP/2 multiplexing
  - Edge function audit       - HTTP headers leak         |
  - Cache key analysis        - IP blocks (Shodan)        v
        |                       v            [4] Exploitation
        v             [2.5] WAF fingerprint  - Edge function RCE
[1.5] Cache analysis  - Rule identification  - Cache poisoning
  - Cache key structure      - Bypass technique           - Origin compromise
  - TTL behavior               |                            |
                               v                            v
                          [5] Persistence   [6] Reporting
                          - Edge function   - CDN config audit
                          - Worker script   - Origin compromise
                          - Cache poisoning - WAF effectiveness
```

### Defense Perspective

| Defense Layer | Measures | Key Points |
|---------------|----------|------------|
| **CDN/WAF Configuration** | Strict origin policy; WAF rule set; rate limiting | CDN is first line of defense; configure properly |
| **Origin Protection** | Origin only accessible via CDN (IP allowlist); no direct internet | If origin IP leaks, attacker bypasses CDN entirely |
| **Cache Security** | Proper cache key (include auth header); cache key sanitization | Cache poisoning affects all users; cache key is critical |
| **Edge Function Security** | Sandbox edge functions; least privilege; secret scanning | Edge functions have CDN-wide impact; sandbox is essential |
| **TLS Configuration** | Modern TLS (1.3); HSTS; certificate pinning | TLS downgrade allows interception; HSTS prevents |
| **Origin Network** | Origin in private subnet; security group allows only CDN | Network-level protection; deny direct access |

---

## Practical Steps

> See `payloads.md` for detailed payloads and `test-cases.md` for the complete test checklist.

### 1. Reconnaissance

Identify target infrastructure; fingerprint products; enumerate attack surface.

### 2. Vulnerability Discovery

Run automated scanners (garak, PyRIT); manual testing per OWASP Top 10.

### 3. Exploitation

Chain vulnerabilities for maximum impact; document PoC.

### 4. Persistence

Establish persistence via configuration changes, scheduled tasks, or backdoors.

### 5. Reporting

Map findings to MITRE ATT&CK, OWASP, regulatory frameworks; include concrete remediation.

---

## Detection Methods

### CDN / Edge Function Logs
- **Cloudflare Workers abuse**: Anomalous Worker invocations; outbound fetch to attacker domains.
- **AWS Lambda@Edge anomalies**: Function duration spikes; cross-region data egress from edge.
- **Origin IP discovery**: Direct origin access bypassing CDN (signature: requests to origin IP from internet).

### SIEM Detection Rules
- **Splunk SPL**: `index=cdn sourcetype=cloudflare:workers | stats count by script | sort -count | head 10`
- **Cloudflare Analytics**: Native bot/security analytics.
- **AWS CloudTrail**: Lambda@Edge invocation logs.

## Defense Evasion Techniques

### CDN Bypass
- **Direct origin access**: Find origin IP via DNS history, leak in HTTP headers, SSL cert; bypass CDN/WAF.
- **Cache poisoning**: Poison cached response; affect all users.
- **Cache deception**: Trick CDN into caching dynamic content with sensitive data.

### Edge Function Exploitation
- **Worker script injection**: Inject code into Worker via compromised account or supply chain.
- **Lambda@Edge privilege abuse**: Use Lambda@Edge for global execution.
- **Origin IP rotation**: Use direct IP for exfil; CDN sees only legitimate traffic.

---

## Common Pitfalls

- Testing in unauthorized environments
- Ignoring rate limiting (will get blocked)
- Single-shot testing (real attacks are sustained)
- Neglecting supply chain
- Forgetting monitoring/alerting

## Reporting and Documentation

Reports should include CVSS scores, MITRE ATT&CK mapping, concrete PoC, business impact, and specific remediation.

## Legal and Ethical Considerations

Ensure proper authorization before testing. Document scope in engagement letter. Some attack techniques may violate local laws (e.g., radio transmission without license).

## Hacker Laws

| Law | Application |
|-----|-------------|
| **Trust but Verify** | Verify all outputs; verify all sources |
| **First Principles** | Understand underlying protocols before attacking |
| **Defense in Depth** | Multiple layers required for robust defense |
| **Assume Breach** | Design assuming attacker already inside |
| **Minimize Attack Surface** | Reduce unnecessary features/exposure |

---

## Learning Resources

**Skill supplementary files**: `payloads.md`, `test-cases.md`

**External Resources**:
- [OWASP Top 10](https://owasp.org/Top10/)
- [MITRE ATT&CK](https://attack.mitre.org/)
- Industry-specific compliance frameworks

