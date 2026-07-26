---
name: identity-provider-attack
description: "Identity Provider (IdP) attack patterns covering OAuth 2.0/OIDC, SAML, JWT, token theft/replay, MFA fatigue, service principal abuse (Azure AD/Entra ID), Okta, Auth0, Keycloak, and modern identity-based attacks."
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
  domain: identity
  category: cloud-identity
  tool_count: 7
  guide_count: 0
  mitre: "TA0006-Credential Access, T1556-Modify Authentication Process"
  last_reviewed: "2026-07-26"
  keywords: ["OAuth", "OIDC", "SAML", "JWT", "IdP", "Azure AD", "Okta", "Auth0", "Keycloak", "MFA fatigue", "token theft"]
---

# Skill: identity-provider-attack

## Summary

Identity Provider (IdP) attack patterns covering OAuth 2.0/OIDC, SAML, JWT, token theft/replay, MFA fatigue, service principal abuse (Azure AD/Entra ID), Okta, Auth0, Keycloak, and modern identity-based attacks.

**Tools**: garak, PyRIT, promptfoo, custom harnesses

**Domain**: identity

**MITRE**: TA0006-Credential Access, T1556-Modify Authentication Process

## Description

Identity Provider (IdP) attack patterns covering OAuth 2.0/OIDC, SAML, JWT, token theft/replay, MFA fatigue, service principal abuse (Azure AD/Entra ID), Okta, Auth0, Keycloak, and modern identity-based attacks.

This skill covers the offensive side of cloud-identity security, including reconnaissance, vulnerability discovery, exploitation, persistence, and reporting. Aligned with OWASP Top 10, MITRE ATT&CK, and industry-specific compliance frameworks.

---

## Use Cases

1. **OAuth/OIDC flow attacks**: Authorization code theft, state parameter reuse, PKCE downgrade, redirect_uri bypass.
2. **JWT attacks**: Algorithm confusion (RS256→HS256), kid injection, weak HMAC secret brute force.
3. **SAML exploitation**: XML signature wrapping, assertion injection, certificate confusion.
4. **Token theft and replay**: Session cookie theft, refresh token abuse, primary refresh token (PRT) attacks.
5. **MFA bypass**: Push bombing, SIM swap, OAuth consent phishing, time-based OTP brute force.
6. **Service principal abuse**: Over-privileged SP, certificate-based auth abuse, workload identity federation.

---

## Core Tools

| **jwt_tool** | JWT analysis and exploitation | `python3 jwt_tool.py <JWT>` |
| **tokenhero** | OAuth token analysis | `tokenhero --token <access_token>` |
| **AADInternals** | Azure AD/Entra ID reconnaissance | `Get-AADIntTenantDomains` |
| **MFASweep** | MFA bypass testing | `Invoke-MFASweep -Target user@contoso.com` |
| **ROADtools** | Azure AD device auth | `roadrecon auth` |
| **o365creeper** | Microsoft 365 enumeration | `python3 o365creeper.py` |
| **OktaPostman** | Okta API testing | Postman collection |
| **SAMLExtractor** | SAML assertion analysis | `python3 SAMLExtractor.py` |
| **Burp Suite** | OAuth/SAML flow interception | Proxy + manual testing |
| **mitm6** | IPv6 DNS poisoning for WPAD/NTLM relay | `mitm6 -d contoso.local` |

---

## Methodology

### Attack Chain

```
[1] Reconnaissance          [2] Token Analysis       [3] Vulnerability Discovery
  - IdP identification        - JWT decode              - Algorithm confusion
  - Tenant enumeration        - Refresh token swap      - State reuse
  - User enumeration          - Token replay              |
  - App registration audit      |                        v
        |                       v            [4] Exploitation
        v             [3.5] Authorization   - Account takeover
[2.5] Conditional Access   - Privilege escalation  - Lateral movement
  - Trusted IP spoof            |                      - Persistence
  - Location bypass             v                       |
                          [5] Persistence             v
                          - New app registration  [6] Reporting
                          - Long-lived refresh    - Token exposure
                          - Hidden OAuth consent  - Tenant compromise
```

**Phase Details**:

1. **Reconnaissance**: Identify IdP (Okta, Azure AD, Auth0, Keycloak, Google Workspace) via login page fingerprinting. Enumerate users via login timing, password reset flow, or tenant info API.
2. **Token Analysis**: Decode JWT (header, payload, signature). Identify signing algorithm. Test for algorithm confusion (RS256 → HS256). Check refresh token lifetime.
3. **Vulnerability Discovery**: Test redirect_uri validation, state parameter validation, PKCE requirement, token signing algorithm, consent flow.
4. **Exploitation**: Token replay, account takeover via refresh token, lateral movement via service principal abuse.
5. **Persistence**: Register new OAuth app (persists across password resets), long-lived refresh tokens, hidden consent grants.
6. **Reporting**: Map to MITRE ATT&CK, OWASP API Top 10, regulatory frameworks.

### Defense Perspective

| Defense Layer | Measures | Key Points |
|---------------|----------|------------|
| **Multi-factor Authentication** | Phishing-resistant MFA (FIDO2, smartcard); enforce for all admin accounts | Push-based MFA is vulnerable to push bombing; FIDO2 is the gold standard |
| **Conditional Access** | Device compliance, trusted location, risk-based authentication | Don't trust IP alone (NAT, residential proxies); combine with device posture |
| **Token Lifetime** | Short-lived access tokens (60 min); refresh token rotation | Long-lived tokens are persistent access; rotate regularly |
| **Application Registration Control** | Allowlist users who can register apps; require admin approval | Self-service app registration allows malicious OAuth apps |
| **Consent Framework** | Require admin consent for high-privilege scopes; user consent for low-privilege only | Consent phishing is major attack vector; educate users |
| **JWT Validation** | Strict algorithm allowlist; reject `alg: none`; verify `kid` header | Algorithm confusion is critical vuln; libraries differ in handling |
| **SAML Security** | Require signed assertions; verify certificate chain; replay detection | XML signature wrapping is common attack |
| **Monitoring** | Anomalous logins (geo, IP, device); token use patterns; OAuth consent grants | Detect token replay, consent phishing, MFA fatigue |

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

### Identity Provider Audit Logs
- **AWS CloudTrail**: All STS / IAM events; alert on `AssumeRole` chains, `GetCallerIdentity` from new regions.
- **Azure Activity Log**: Sign-in logs with anomalous geo / IP / device fingerprint; risk events in Identity Protection.
- **GCP Audit Logs**: Cloud Identity logs; alert on `SetIamPolicy` changes, service account key creation.
- **Okta System Log**: App access, user state changes, MFA device enrollment; alert on anomalous patterns.

### Behavioral Anomalies
- **Impossible travel**: Login from US + China within 1h (geographic impossibility).
- **MFA fatigue**: Multiple MFA challenges in short window (push bombing).
- **Token reuse**: Same JWT from many source IPs in short window.
- **Service account abuse**: Service account performing user-level actions.
- **Permission explosion**: User suddenly granted privileged role across many resources.

### Conditional Access Policy Bypass
- **Legacy auth**: Basic authentication bypasses MFA; protocol-specific logging.
- **Device compliance bypass**: User agent strings indicating non-managed device.
- **Location bypass**: Use of residential proxies to mimic legitimate location.
- **App-specific bypass**: Use of legacy protocols (IMAP, SMTP) not subject to modern policies.

### SIEM Detection Rules
- **Splunk SPL**: `index=aws sourcetype=aws:cloudtrail eventName=AssumeRole | stats dc(sourceIPAddress) by userIdentity.arn | where dc > 5`
- **Sigma rule**: `sigma/rules/cloud/aws_sts_role_chain.yml`
- **Microsoft Entra ID Protection**: Native risk detection (impossible travel, anonymous IP, unfamiliar sign-in).
- **AWS GuardDuty**: Detects anomalous API calls; `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration`.

## Defense Evasion Techniques

### Identity Evasion
- **STS role chaining**: Use assume role across multiple accounts; launder credentials.
- **Service account tokens over user credentials**: Don't trigger user-behavior analytics.
- **Long-lived credentials over STS**: Avoid assume-role audit trail.
- **Federation abuse**: Use SAML/OIDC federation; appears as legitimate SSO.
- **Web identity federation**: Use GitHub Actions OIDC, Google Cloud Build; inherit trust.

### MFA Bypass
- **Push bombing**: Trigger MFA fatigue during off-hours; user approves to silence phone.
- **SIM swap**: Social engineer mobile carrier; intercept SMS OTP.
- **MFA fatigue + helpdesk social**: Trigger fatigue, then call helpdesk claiming lost phone.
- **OAuth consent phishing**: Trick user into granting OAuth app; persistent access without MFA.
- **Session token theft**: Steal post-MFA session cookie via XSS/MITM; bypasses MFA entirely.

### Conditional Access Bypass
- **Legacy protocol abuse**: IMAP/SMTP/POP3 often exempt from modern policies.
- **Trusted IP spoofing**: X-Forwarded-For manipulation if gateway trusts header.
- **Device compliance bypass**: Register personal device as compliant; then access resources.
- **App proxy abuse**: Use legitimate reverse proxy app to bypass IP restrictions.

### Token Theft Stealth
- **Steal refresh tokens over access tokens**: Refresh tokens are longer-lived; less suspicious.
- **Off-hours token use**: Use stolen token during user's typical active window; blend with normal activity.
- **Distribute token usage across regions**: Mimic user's travel pattern; avoid impossible-travel alert.
- **Pivot through legitimate SaaS**: Use stolen token to access third-party SaaS that's pre-approved.

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

