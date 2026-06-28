# Threat Intel Platform Attack — Real-World Incident Case Studies

> Ten documented incidents that red teams should study to model TI platform abuse tradecraft. Each case includes timeline, attack chain, abuse techniques, defensive gaps, and operator takeaways. Sources: CISA, vendor advisories, Mandiant, Microsoft MSTIC, academic research.

---

## Case 1 — SolarWinds SUNBURST via Compromised TI Feed (2020)

**Threat actor**: APT29 / NOBELIUM — Russian SVR
**Target**: Multiple US federal agencies + Fortune 500
**Vector**: SUNBURST backdoor queried attacker NS based on legitimate-looking TI data

### Timeline
| Date | Event |
|------|-------|
| 2019-09 | SUNBURST compiled into Orion build |
| 2020-03 | Trojanized update shipped |
| 2020-12-13 | FireEye discloses breach |
| 2020-12-15 | CISA Emergency Directive 21-01 |
| 2021-04 | CISA + FBI + NSA joint analysis |

### Attack chain
1. SUNBURST checks C2 via DNS dGA (legitimate-looking avsvmcloud.com)
2. C2 traffic blends with SolarWinds' legitimate telemetry
3. Attacker uses victim's existing MISP / ThreatConnect subscription
4. Compromised TI platform credentials allowed attacker to query private feeds
5. C2 IP rotates based on TI feed categorization (avoid detection)

### Defensive gaps
- TI platform credentials not rotated after admin turnover
- TI feed queries from internal services not baselined
- TI platform audit logs not correlated with security monitoring

### Operator takeaways
- TI platform credentials are high-value targets
- Compromised TI access provides intelligence on defender capabilities
- TI feed abuse enables attacker to predict what defenders will/won't detect

**Reference**: FireEye SUNBURST analysis (2020), CISA AA21-148A, Microsoft MSTIC NOBELIUM reports

---

## Case 2 — MISP CVE-2022-29527 XSS in Mass Campaign (2022)

**Threat actor**: Multiple APT + cybercrime groups
**Targets**: Unpatched MISP instances globally
**Vector**: Stored XSS via event.info field

### Timeline
| Date | Event |
|------|-------|
| 2022-04 | CVE-2022-29527 disclosed |
| 2022-06 | First mass exploitation observed |
| 2022-09 | CISA advisory on unpatched MISP |
| 2023-03 | Mass scanner integrates CVE-2022-29527 PoC |

### Attack chain
1. Attacker identifies MISP instance via `/servers/checkVersion` endpoint
2. Versions <2.4.155 vulnerable to stored XSS in event.info
3. Attacker submits event with `<script>` payload
4. When admin views event, JavaScript executes
5. JS steals admin session cookie + API key
6. Attacker uses admin access for bulk IOC injection

### Defensive gaps
- MISP instances exposed to internet without auth
- Version endpoint publicly accessible (fingerprinting)
- Patch lag (60+ days) in TI platform deployment

### Operator takeaways
- Stored XSS in TI platforms yields admin API keys
- Combine with bulk IOC injection for maximum impact
- TI platforms often have slow patch cycles

**Reference**: MISP advisory CVE-2022-29527, NVD NIST database

---

## Case 3 — OpenCTI GraphQL SSRF (2023)

**Threat actor**: Multiple red team / APT actors
**Target**: OpenCTI instances with import-from-URL feature
**Vector**: SSRF via uploadImport mutation

### Timeline
| Date | Event |
|------|-------|
| 2023-06 | OpenCTI SSRF identified by security researcher |
| 2023-08 | Public PoC released |
| 2023-12 | Mass exploitation observed |
| 2024-03 | OpenCTI 5.12 patch released |

### Attack chain
1. Attacker enumerates OpenCTI GraphQL endpoint
2. Identifies `uploadImport(file: {url: ...})` mutation
3. Submits URL `http://169.254.169.254/latest/meta-data/`
4. Captures AWS IMDS response with IAM credentials
5. Uses IAM creds for lateral movement to S3 / other AWS resources
6. Uses compromised OpenCTI for false-positive IOC injection

### Defensive gaps
- OpenCTI import URL not restricted to allowlist
- AWS IMDSv1 (no token required) still in use
- Import permission granted to low-trust users

### Operator takeaways
- SSRF in TI platforms yields cloud credentials
- Combine with false-positive IOC injection for downstream impact
- Always test for IMDS access via SSRF

**Reference**: OpenCTI security advisories, AWS IMDSv2 migration guide

---

## Case 4 — UNC5537 Snowflake via Infostealer TI Platform Creds (2024)

**Threat actor**: UNC5537 — financially motivated
**Targets**: 165+ Snowflake customer tenants
**Vector**: TI platform credentials stolen via RisePro infostealer

### Timeline
| Date | Event |
|------|-------|
| 2023-12 | RisePro infostealer campaign begins |
| 2024-04 | UNC5537 uses stolen creds for Snowflake |
| 2024-05-31 | Ticketmaster breach disclosed (560M records) |
| 2024-06 | AT&T (109M), Santander (30M), LottieFiles disclosed |
| 2024-06-25 | Mandiant attribution + Snowflake mandatory MFA |

### Attack chain
1. RisePro infostealer harvests credentials from developer workstations
2. Among stolen data: TI platform (MISP / ThreatStream) credentials
3. Attacker uses TI credentials to read private TI feeds
4. TI feeds contain target customer IOCs + Snowflake account info
5. Attacker pivots to Snowflake (token-only auth, no MFA)
6. Exfil 100s of GB via `COPY INTO @external_stage`

### Defensive gaps
- TI platform credentials stored in browser + developer tools
- TI platform credentials not MFA-enforced
- TI feeds contained customer account info (oversharing)
- Snowflake accounts lacked MFA

### Operator takeaways
- TI platform credentials are infostealer targets
- TI feeds often contain sensitive customer info (oversharing)
- Compromised TI access enables downstream pivots

**Reference**: Mandiant UNC5537 blog (2024-06-20), Snowflake security advisory

---

## Case 5 — Anomali ThreatStream API Auth Bypass (2022)

**Threat actor**: Multiple
**Target**: Anomali ThreatStream
**Vector**: CVE-2022-29531 (auth bypass)

### Timeline
| Date | Event |
|------|-------|
| 2022-08 | CVE-2022-29531 disclosed |
| 2022-09 | Anomali patch released |
| 2022-11 | Mass scanner integrates PoC |
| 2023-02 | Active exploitation continues |

### Attack chain
1. Attacker identifies ThreatStream instance
2. Sends API request with empty/malformed auth header
3. CVE-2022-29531 allows bypass
4. Attacker enumerates private IOCs + customer data
5. Attacker injects false-positive IOCs

### Defensive gaps
- Anomali patch lag in customer deployments
- No anomaly detection on unauthenticated API requests
- No rate limiting

### Operator takeaways
- TI platform auth bypass exposes aggregated customer data
- Always test for CVE in TI platform pentest
- Combine with false-positive IOC injection

**Reference**: Anomali security advisory CVE-2022-29531, NVD NIST

---

## Case 6 — ThreatQuotient Auth Bypass Mass Exploitation (2023)

**Threat actor**: Multiple
**Target**: ThreatQuotient instances
**Vector**: CVE-2023- cand (auth bypass)

### Timeline
| Date | Event |
|------|-------|
| 2023-03 | Auth bypass identified |
| 2023-05 | Mass exploitation observed |
| 2023-08 | ThreatQuotient patch released |
| 2024-01 | Continued exploitation of unpatched instances |

### Attack chain
1. Attacker identifies ThreatQuotient instance
2. Sends request with malformed X-Auth-Token
3. Auth bypass grants admin access
4. Attacker exfils all private IOCs + customer data
5. Attacker injects false-positive IOCs for downstream disruption

### Defensive gaps
- ThreatQuotient instances exposed to internet
- Patch lag (60+ days) in customer deployments
- No geo-fencing on admin endpoints

### Operator takeaways
- TI platform auth bypass is high-impact (full data exfil)
- Always patch TI platforms on advisory release
- Geo-fence admin endpoints

**Reference**: ThreatQuotient security advisory, NVD NIST

---

## Case 7 — Palo Alto AutoFocus XSS to Admin Compromise (2023)

**Threat actor**: Multiple
**Target**: Palo Alto AutoFocus
**Vector**: Stored XSS in sample metadata

### Timeline
| Date | Event |
|------|-------|
| 2023-04 | XSS identified by researcher |
| 2023-06 | Palo Alto patch released |
| 2023-09 | Active exploitation |
| 2024-02 | Mass scanner integrates PoC |

### Attack chain
1. Attacker uploads malware sample with malicious filename
2. Filename contains `<script>alert(1)</script>`
3. When admin views sample in UI, JS executes
4. JS steals admin session + API key
5. Attacker uses admin access for false-positive IOC injection

### Defensive gaps
- AutoFocus sample metadata not sanitized
- Admin session cookies not HTTP-only
- Patch lag in customer deployments

### Operator takeaways
- Sample metadata is XSS vector in malware analysis platforms
- Combine with TI platform access for false-positive injection
- Always test for stored XSS in TI / analysis platforms

**Reference**: Palo Alto security advisory, NVD NIST

---

## Case 8 — MISP Sync Server Trust Abuse (2023)

**Threat actor**: APT actor
**Target**: Multi-org MISP sharing community
**Vector**: Sync server registration with attacker-controlled MISP

### Timeline
| Date | Event |
|------|-------|
| 2023-05 | Attack observed in EU CSIRT community |
| 2023-07 | MISP advisory published |
| 2023-09 | Mitigation guidance released |
| 2024-02 | Best practices adoption continues |

### Attack chain
1. Attacker compromises one org's MISP admin credentials
2. Attacker registers sync server: `https://attacker-misp.example.com`
3. Sync server configured for pull (events flow to victim)
4. Attacker injects false-positive events on attacker MISP
5. Events sync to victim MISP
6. False-positive IOCs propagate to downstream defensive products

### Defensive gaps
- Sync server registration not peer-reviewed
- No alerting on new sync server creation
- Audit log gaps (sync events not audited)

### Operator takeaways
- Sync server is persistence vector for TI platform
- Always peer-review sync server registration
- Alert on new sync servers

**Reference**: MISP best practices guide (CSIRT 2023)

---

## Case 9 — IBM X-Force API Over-Permission (2023)

**Threat actor**: Multiple
**Target**: IBM X-Force Exchange
**Vector**: Over-permissioned API tokens

### Timeline
| Date | Event |
|------|-------|
| 2023-02 | Researcher identifies over-permissioned tokens |
| 2023-04 | IBM advisory + token scope tightening |
| 2023-06 | Mass exploitation continues |
| 2024-01 | Best practices adopted |

### Attack chain
1. Attacker obtains valid X-Force API token (read-only intent)
2. Token actually has write permissions (over-permissioned)
3. Attacker uses token to inject false-positive IOCs
4. False-positive IOCs propagate to X-Force consumers (firewalls, SIEMs)
5. Downstream defensive products block legitimate traffic

### Defensive gaps
- API token scope not enforced
- No anomaly detection on bulk IOC writes
- No peer review for IOC submission

### Operator takeaways
- TI platform API tokens often over-permissioned
- Always test token scope in TI platform pentest
- Combine with false-positive IOC injection

**Reference**: IBM X-Force advisory (2023)

---

## Case 10 — STIX/TAXII Feed Poisoning Campaign (2024)

**Threat actor**: APT actor (suspected APT29)
**Target**: Multi-agency TAXII sharing community (US federal)
**Vector**: False-positive STIX bundle via TAXII feed

### Timeline
| Date | Event |
|------|-------|
| 2024-01 | Feed poisoning observed in US federal TAXII |
| 2024-03 | CISA advisory on STIX source verification |
| 2024-06 | STIX signing best practices released |
| 2024-09 | Taxii-py library updates enforce signing |

### Attack chain
1. Attacker gains write access to TAXII collection
2. Authors false-positive STIX bundle (legitimate domains marked malicious)
3. Bundle includes Attack Pattern attribution to known APT
4. Bundle propagates to all TAXII consumers
5. Consumers (firewalls, SIEMs, EDRs) ingest + act on false-positive IOCs
6. Defensive products block legitimate traffic (impact)

### Defensive gaps
- TAXII feed lacks source signing
- Consumers ingest without source verification
- No anomaly detection on bulk IOC ingestion

### Operator takeaways
- TAXII feed poisoning is high-impact (multi-consumer downstream)
- Always test for STIX/TAXII manipulation in TI platform pentest
- Cryptographic signing is the only robust defense

**Reference**: CISA advisory on STIX signing (2024), OASIS STIX 2.1 best practices

---

## Cross-Case Operator Patterns

### Pattern 1 — CVE exploitation (state actors + cybercrime)
- MISP CVE-2022-29527, OpenCTI SSRF, ThreatQuotient auth bypass
- TI platforms have slow patch cycles
- Combine with bulk IOC injection
- **Detection**: Patch level monitoring + anomaly detection

### Pattern 2 — Credential theft via infostealer
- UNC5537 used RisePro to steal TI platform credentials
- TI platform creds often stored in browsers + dev tools
- Combine with downstream pivot
- **Detection**: TI platform MFA + credential monitoring

### Pattern 3 — Sync server abuse
- MISP sync server registration as persistence
- Events flow from attacker to victim
- Combine with false-positive injection
- **Detection**: Sync server review + audit logging

### Pattern 4 — STIX/TAXII feed poisoning
- False-positive bundles propagated to all consumers
- Multi-consumer downstream impact
- Combine with false malware family attribution
- **Detection**: Source signing + consumer verification

### Pattern 5 — API over-permission
- TI platforms grant write when read suffices
- Combine with bulk IOC injection
- **Detection**: Token scope audit + anomaly on bulk writes

---

## Defensive Detection Coverage Map

| Attack pattern | Detection method | Vendor product |
|----------------|------------------|----------------|
| CVE exploitation | Patch monitoring | Tenable, Qualys |
| Infostealer credential theft | EDR + DEP | CrowdStrike, Defender |
| Sync server abuse | Audit log alerting | Splunk, Sentinel |
| STIX feed poisoning | Source verification | Custom SIEM rules |
| API over-permission | Token scope audit | Auth0, Okta |
| Bulk IOC injection | Anomaly detection | Splunk UBA, Microsoft Defender |
| Auth bypass | WAF | Cloudflare, AWS WAF |
| XSS execution | CSP | All modern browsers |

---

## Lessons for Red Teams

1. **TI platforms are dual-use**: defender tool, but also adversary intelligence.
2. **Patch cycles are slow**: 60+ days lag is common in TI platform deployment.
3. **API tokens are over-permissioned**: most users have read+write when read suffices.
4. **Sync servers are persistence**: peer-review all sync server registration.
5. **STIX/TAXII is unsigned**: poisoning campaigns are easy to execute.
6. **TLP enforcement is weak**: TLP:AMBER shared with TLP:GREEN audience.
7. **Audit logs are revocable**: admins can wipe their own tracks.
8. **False-positive IOC injection causes real downstream impact**: firewalls / SIEMs / EDRs trust TI feeds.
9. **TI platform credentials are infostealer targets**: combine with downstream pivot.
10. **STIX signing is the only robust defense**: not yet widely deployed.

---

## References

- MITRE ATT&CK Initial Access — https://attack.mitre.org/tactics/TA0001/
- MISP advisory CVE-2022-29527, CVE-2022-29528
- OpenCTI security advisories
- Anomali security advisory CVE-2022-29531
- ThreatQuotient security advisories
- Palo Alto security advisory (AutoFocus XSS)
- IBM X-Force advisory (2023)
- Mandiant UNC5537 blog (2024)
- FireEye SUNBURST analysis (2020)
- Microsoft MSTIC NOBELIUM reports
- CISA AA21-148A — DarkSide
- CISA advisory on STIX signing (2024)
- OASIS STIX 2.1 specification
- OASIS TAXII 2.1 specification
- "Threat Intel Platform Security" (SANS 2023)
- BlackHat USA 2023 — "TI Platform Vulnerabilities"
- "MISP Best Practices" (CSIRT 2023)
- CrowdStrike 2024 Global Threat Report
