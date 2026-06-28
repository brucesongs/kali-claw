# Red Team Infrastructure — Real-World Incident Case Studies

> Ten documented incidents that red teams should study to model adversary C2 infrastructure tradecraft. Each case includes timeline, infrastructure architecture, detection gaps, and operator takeaways. Sources: Mandiant, CrowdStrike, CISA, Microsoft MSTIC, vendor IR reports.

---

## Case 1 — APT29 SolarWinds SUNBURST Infrastructure (2020)

**Threat actor**: APT29 / NOBELIUM / Cozy Bear — Russian SVR
**Targets**: 18,000+ SolarWinds Orion customers; ~100 confirmed follow-on
**Infrastructure**: Multi-tier CDN-fronted C2 with dead-drop DNS dGA

### Timeline
| Date | Event |
|------|-------|
| 2019-09 | SUNBURST backdoor compiled into Orion build |
| 2020-03 | Trojanized Orion update shipped |
| 2020-12-13 | FireEye discloses breach |
| 2020-12-15 | CISA Emergency Directive 21-01 |
| 2021-04 | CISA + FBI + NSA joint analysis report |

### Infrastructure architecture
1. **Implant C2**: HTTPS to `*.avsvmcloud[.]com` (dGA-generated subdomains)
2. **CDN front**: Look-alike domains hosted on AWS CloudFront (when fronting still worked)
3. **Decoy**: C2 URL hosted at `*.iqscore[.]com` (legitimate-looking IQ test site)
4. **Steganography**: Commands hidden in HTTP headers (`X-Forwarded-For`, custom)
5. **Multi-tier**: Implant → CDN → AWS CloudFront → attacker origin
6. **Beacon cadence**: Randomized 1–4 weeks (defeats interval detection)

### Defensive gaps observed
- Trusted vendor binary (Orion update) bypassed app allowlist
- AWS CloudFront CDN blended with legitimate customer traffic
- Beaconing cadence randomized below anomaly thresholds
- Multi-tenant cloud egress not correlated with on-prem telemetry

### Operator takeaways
- Layer dGA domains over CDN front for resilience
- Randomized beaconing (1–4 weeks) defeats volume baselines
- Steganographic HTTP headers hide command channel
- Trusted-vendor initial access bypasses app allowlist

**Reference**: FireEye SUNBURST analysis (2020-12), CISA AA21-148A, Microsoft MSTIC NOBELIUM reports

---

## Case 2 — APT41 DNS Tunneling Infrastructure (2014–2024)

**Threat actor**: APT41 (BARIUM / Winnti Group) — Chinese state-sponsored
**Targets**: Healthcare, telecom, gaming, OT
**Infrastructure**: DNS tunneling via TXT/A queries to attacker NS

### Timeline
| Date | Event |
|------|-------|
| 2014-06 | DNS tunneling first observed in APT41 campaigns |
| 2019-09 | DOJ indictment reveals DNS exfil pattern |
| 2022-08 | Microsoft Tag-42 — Covenant + DNS beacons |
| 2024-04 | Google TAG — fresh APT41 DNS exfil targeting Taiwan telecom |

### Infrastructure architecture
1. **Implant**: MESSAGETAP / POISONPLUG backdoor
2. **C2 channel**: DNS TXT queries to `*.cdr1.{domain}`
3. **NS rotation**: Multiple NS subdomains rotated every 4 hours
4. **Data encoding**: Base32 in TXT queries (≤200 bytes per query)
5. **Volume**: <2 MB per host per day (under DLP threshold)
6. **Resilience**: Backup channel over HTTPS to compromised WordPress sites

### Defensive gaps observed
- DNS not inspected by DLP/SWG
- TXT query rate not alerted (≤100/hour)
- Domain age <30 days not flagged

### Operator takeaways
- DNS TXT records bypass most proxies if `+short TXT` is allowed
- Keep per-query payload <200 bytes to dodge anomaly detection
- Rotate NS subdomains every 4 hours to break rate baselines

**Reference**: Mandiant APT41 report (2020), DOJ indictment 1:19-cr-676 (2019), Google TAG 2024 reports

---

## Case 3 — FIN6 Magecart C2 Infrastructure (2019–2024)

**Threat actor**: FIN6 (Skull Spider) — Russian cybercrime
**Targets**: Retail, hospitality, e-commerce (Magecart skimming)
**Infrastructure**: Compromised WordPress C2 + dead-drop resolvers

### Timeline
| Date | Event |
|------|-------|
| 2019-08 | Magecart skimmer found on Ticketmaster |
| 2020-04 | British Airways skimmer (380K records) |
| 2022-03 | Skimmer evolved to use GitHub gist resolver |
| 2024-06 | New FIN6 variant uses Cloudflare Workers for C2 |

### Infrastructure architecture
1. **Skimmer**: JavaScript injected into checkout pages
2. **C2 channel**: HTTPS POST to compromised WordPress sites
3. **Dead-drop resolver**: GitHub gist with current C2 endpoint
4. **Multi-tier**: Skimmer → CDN → WordPress → backend C2
5. **Volume**: <1 KB per card exfil; cadence mimics analytics traffic

### Defensive gaps observed
- Compromised WordPress sites considered trusted (legitimate reputation)
- Beacon volume too small to trip rate-based detection
- JavaScript blended with legitimate analytics traffic

### Operator takeaways
- Compromise legitimate WordPress / Blogger / Tumbler for low-reputation distribution
- Mimic Google Analytics / Facebook Pixel traffic for stealth
- Dead-drop resolver via GitHub gist avoids hardcoded C2 in skimmer

**Reference**: RiskIQ FIN6 report (2019), Visa Magecart advisory (2020), Malwarebytes FIN6 analysis (2024)

---

## Case 4 — Vice Society / Royal / BlackSuit Infrastructure (2022–2024)

**Threat actor**: Vice Society / Royal / BlackSuit — Russian cybercrime
**Targets**: Healthcare, education, government
**Infrastructure**: Custom C2 + Rclone exfil + dual-stage redirectors

### Timeline
| Date | Event |
|------|-------|
| 2022-05 | Royal ransomware emerges (former Conti operators) |
| 2022-12 | Vice Society rebrand |
| 2023-09 | BlackSuit (Royal successor) |
| 2024-03 | Dallas County (royal) — 5 TB exfil |

### Infrastructure architecture
1. **Initial access**: Cobalt Strike via phishing or RDP brute force
2. **C2**: Custom C2 with dual-stage redirectors (Cloudflare → VPS)
3. **Exfil**: Rclone to attacker S3 (parallel HTTPS upload)
4. **Staging**: Compressed tarballs on victim's own file shares
5. **Volume**: 1–5 TB per target over 8 hours

### Defensive gaps observed
- Rclone not on EDR allowlist (free tool, blends with admin activity)
- Cloudflare-fronted exfil destination blends with legitimate CDN traffic
- IT helpdesk didn't notice unusual file compression activity

### Operator takeaways
- Rclone is the modern cybercrime exfil primitive — flag every binary invocation
- Dual-stage Cloudflare → VPS redirectors hide true C2 origin
- Volume >1 TB triggers rate anomaly if detection exists

**Reference**: CISA Stop Ransomware advisory (2022), Mandiant Vice Society report (2023), Microsoft BlackSuit analysis (2024)

---

## Case 5 — UNC5537 Snowflake OAuth Infrastructure (2024)

**Threat actor**: UNC5537 — financially motivated (Mandiant attribution)
**Targets**: 165+ Snowflake customer tenants (Ticketmaster, AT&T, Santander)
**Infrastructure**: Infostealer-recycled OAuth tokens + SaaS-to-SaaS exfil

### Timeline
| Date | Event |
|------|-------|
| 2024-04 | Campaign begins — infostealer logs from 2023-12 recycled |
| 2024-05-31 | Ticketmaster breach disclosed (560M records) |
| 2024-06 | AT&T (109M), Santander (30M), LottieFiles disclosed |
| 2024-06-25 | Mandiant attribution + Snowflake mandatory MFA rollout |

### Infrastructure architecture
1. **Auth**: Infostealer-recycled session cookies (RisePro / Vidar)
2. **Bypass**: Snowflake accounts lacked MFA (token-only)
3. **C2 channel**: Direct Snowflake SaaS API (legitimate)
4. **Exfil**: `COPY INTO @external_stage` to attacker S3 bucket
5. **Cloud-to-cloud**: Snowflake compute → S3 (no victim network visibility)
6. **Volume**: 100s of GB per target

### Defensive gaps observed
- Snowflake allowed token-only auth (no MFA enforced)
- Snowflake egress to customer S3 not anomaly-baselined
- Customer SOC had no visibility into Snowflake-to-S3 transfers
- No geographic anomaly alerts on Snowflake login

### Operator takeaways
- Cloud-to-cloud exfil (SaaS → S3) bypasses victim network monitoring entirely
- `COPY INTO @external_stage` is the canonical SaaS exfil primitive
- Infostealer-recycled sessions bypass MFA — token rotation is the only fix

**Reference**: Mandiant UNC5537 blog (2024-06-20), Snowflake security advisory

---

## Case 6 — Conti Ransomware Double Extortion Infrastructure (2020–2022)

**Threat actor**: Conti (Wizard Spider / GOLD ULRICK) — Russian cybercrime
**Targets**: 1,000+ orgs including HSE (Ireland), Costa Rica government
**Infrastructure**: TrickBot → Cobalt Strike → Conti + Rclone exfil

### Timeline
| Date | Event |
|------|-------|
| 2020-04 | Conti v2 emerges |
| 2021-05 | HSE Ireland breach — 700 GB exfil |
| 2022-02 | Conti Leaks (90K internal chat messages) |
| 2022-05 | Costa Rica government attack (national emergency) |
| 2022-06 | Conti disbands; spins off BlackCat / Royal |

### Infrastructure architecture
1. **Initial access**: TrickBot / BazarLoader dropper
2. **C2 channel**: Cobalt Strike over HTTPS
3. **Exfil**: Rclone parallel HTTPS upload to attacker S3
4. **Backup exfil**: MEGAsync / FileZilla to personal cloud
5. **Staging**: Victim's own `C:\Temp` for staging
6. **Volume**: 100–700 GB per target over 4–8 hours (no throttling — ransomware imminent)

### Defensive gaps observed
- No egress rate limit on port 443
- Rclone not on EDR allowlist
- MEGA / pCloud not blocked at SWG
- Cobalt Strike default profile not signature-flagged

### Operator takeaways
- Rclone is the modern Conti/LockBit exfil primitive — flag every binary invocation
- Stage large dumps in compressed tarball to maximize volume per upload
- High-volume exfil usually precedes ransomware deploy within 48 hours

**Reference**: CISA AA21-148A (Conti advisory), Conti Leaks analysis (IBM Security 2022), Advanced Intelligence reports

---

## Case 7 — DarkSide Colonial Pipeline Infrastructure (2021)

**Threat actor**: DarkSide (rebranded BlackMatter) — Russian cybercrime
**Target**: Colonial Pipeline (May 2021) — 45% US East Coast fuel supply
**Infrastructure**: VPN creds → Cobalt Strike → Rclone exfil

### Timeline
| Date | Event |
|------|-------|
| 2021-04-29 | Initial VPN access (compromised password) |
| 2021-05-06 | 100 GB exfil via Rclone to attacker S3 |
| 2021-05-07 | Ransomware deploy → pipeline shutdown |
| 2021-05-09 | National gas shortage declared |
| 2021-05-13 | DarkSide announces dissolution |
| 2021-06-07 | DOJ recovers 63.7 BTC of 75 BTC ransom |

### Infrastructure architecture
1. **Initial access**: VPN credentials (password reuse, no MFA)
2. **C2 channel**: Cobalt Strike over HTTPS to `cdn.{domain}`
3. **Exfil**: Rclone to attacker-controlled S3 bucket
4. **Staging**: Compressed chunks
5. **Volume**: 100 GB over 8 hours — high volume, no throttle
6. **Exfil-before-encrypt**: Completed before ransomware deploy (typical double extortion)

### Defensive gaps observed
- VPN had no MFA
- No alert on Rclone execution
- No egress anomaly on 100 GB over 8 hours
- IT/OT network boundary relied on segmentation only

### Operator takeaways
- 100 GB exfil over 8 hours triggers rate anomaly if detection exists
- Rclone to a 30-day-old domain should be a critical alert
- IT/OT boundary: only way to stop exfil reaching OT is air-gap or one-way diode

**Reference**: CISA AA21-148A (DarkSide), Mandiant Colonial Pipeline report, DOE EO 14028 follow-up

---

## Case 8 — LockBit 3.0 Multi-Tier Infrastructure (2022–2024)

**Threat actor**: LockBit (affiliated with former Conti/REvil operators)
**Targets**: 2,000+ orgs including Royal Mail, TSMC, Boeing, Port of Nagoya
**Infrastructure**: StealBit exfil tool + Cloudflare-fronted C2

### Timeline
| Date | Event |
|------|-------|
| 2022-03 | LockBit 3.0 released (config customization) |
| 2023-01 | Royal Mail (UK) — 44 GB exfil |
| 2023-06 | Progress MoveIt mass exploitation — LockBit exploits |
| 2023-11 | Boeing breach (43 TB) |
| 2024-02 | LockBit infrastructure seized (Operation Cronos) |
| 2024-05 | LockBit returns under new branding |

### Infrastructure architecture
1. **Initial access**: MoveIt (CVE-2023-34362) or Citrix Bleed (CVE-2023-4966)
2. **Exfil tool**: Custom StealBit (faster than Rclone for sub-100 GB dumps)
3. **C2**: Cloudflare-fronted HTTPS to `cdn.{domain}`
4. **Staging**: `Compress-Archive` PowerShell (signed Microsoft binary)
5. **Volume**: 10–100 GB per target, often <2 hours
6. **Domain rotation**: Burned every 7–14 days

### Defensive gaps observed
- `Compress-Archive` not flagged (signed Microsoft binary)
- Cloudflare-fronted exfil destination blends with legitimate CDN traffic
- MoveIt file transfer not baselined (post-exploitation path abuse)

### Operator takeaways
- StealBit binary is faster than Rclone for sub-100 GB dumps
- Domain fronting via Cloudflare breaks SNI-based detection
- 0-day mass exploitation (MoveIt/Citrix) is the modern initial-access vector

**Reference**: CISA LockBit Stop Ransomware advisory (2023), Mandiant Operation Cronos analysis (2024), Cisco Talos LockBit 3.0 whitepaper

---

## Case 9 — BlackCat / ALPHV MEGA Cloud Infrastructure (2021–2024)

**Threat actor**: BlackCat / ALPHV (rebranded DarkSide/BlackMatter lineage)
**Targets**: 1,000+ orgs including Change Healthcare (2024), Caesars, MGM
**Infrastructure**: MegaSync exfil + MEGA cloud staging

### Timeline
| Date | Event |
|------|-------|
| 2021-11 | BlackCat released — Rust-based ransomware |
| 2023-09 | Caesars ($15M) + MGM ($45M) paid ransoms |
| 2023-12 | SEC disclosure rules (8-K) come into force |
| 2024-02 | Change Healthcare breach — 6 TB exfil, $22M ransom |
| 2024-03 | ALPHV infrastructure disappears (exit scam) |

### Infrastructure architecture
1. **Initial access**: Citrix Bleed / vishing (MGM helpdesk vishing)
2. **C2**: Cobalt Strike over HTTPS to MEGA-look-alike domains
3. **Exfil**: MegaSync + custom exfil scripts
4. **Staging**: MEGA cloud (encrypted, legitimate-looking)
5. **Double-extortion**: Leak site publishes data in 100 GB chunks
6. **Exfil volume**: Often 1–6 TB per target

### Defensive gaps observed
- MEGA not blocked at SWG (legitimate business use)
- Vishing-sourced credentials had full admin privileges
- IT helpdesk MFA bypass via SIM-swap

### Operator takeaways
- Vishing + SIM-swap defeats MFA on helpdesk resets
- MEGA's end-to-end encryption makes content inspection impossible
- Leak-site publication creates additional pressure (reputational damage)

**Reference**: Cisco Talos BlackCat/ALPHV whitepaper (2023), CISA AA23-320A, OCR Change Healthcare breach notification (2024)

---

## Case 10 — REvil / Sodinokibi Affiliate Infrastructure (2019–2024)

**Threat actor**: REvil / Sodinokibi (GandCrab successor) — Russian cybercrime
**Targets**: 10,000+ orgs including Kaseya (2021), JBS (2021), Travelex (2020)
**Infrastructure**: Affiliate program + multi-tier C2 + onion leak site

### Timeline
| Date | Event |
|------|-------|
| 2019-04 | REvil emerges (post-GandCrab) |
| 2020-12 | Travelex breach ($6M ransom) |
| 2021-05 | JBS Foods ($11M ransom) |
| 2021-07 | Kaseya VSA mass exploitation (1,500+ downstream) |
| 2021-11 | REvil arrests (Romania, SBU) |
| 2022-10 | REvil returns under new branding |

### Infrastructure architecture
1. **Initial access**: Kaseya VSA 0-day (CVE-2021-30116) for mass exploitation
2. **C2**: Custom HTTP C2 with multi-tier redirectors
3. **Exfil**: MegaSync + custom HTTP exfil to onion sites
4. **Leak site**: Tor onion (.onion) for victim naming + data leak
5. **Payment**: Monero (privacy) + BTC (with mixing)
6. **Affiliate program**: 70/30 split with initial access brokers (IABs)

### Defensive gaps observed
- Kaseya VSA mass exploitation bypassed MSP segmentation
- Tor onion leak site outside jurisdictional reach
- Cryptocurrency mixing defeats attribution

### Operator takeaways
- MSP / supply chain initial access affects 1,000+ downstream customers
- Tor onion infrastructure is jurisdictionally safe
- Affiliate model means IABs provide initial access — defender must harden IT perimeter

**Reference**: CISA AA21-148A (REvil), FBI Kaseya flash report (2021), US Treasury OFAC sanctions on REvil (2022)

---

## Cross-Case Operator Patterns

### Pattern 1 — Multi-tier CDN-fronted C2 (state actors)
- APT29, NOBELIUM use 3-tier Cloudflare → AWS → attacker origin
- Implant → CDN front → Cloudflare worker → Nginx mTLS → C2
- Defenders see only CDN SNI; backend hidden behind cert pinning
- **Detection**: SNI ≠ Host header delta + JA3 fingerprinting

### Pattern 2 — DNS tunneling (state actors)
- APT41 uses DNS TXT for sub-2 MB/day exfil
- Per-query payload <200 bytes
- NS subdomains rotated every 4 hours
- **Detection**: Zeek DNS analyzer with TXT entropy + count by NS

### Pattern 3 — High-volume HTTPS exfil (cybercrime)
- Conti, DarkSide, LockBit, BlackCat all use Rclone / StealBit / MegaSync
- Volume 100 GB–6 TB per target
- Often precedes ransomware deploy by <48 hours
- **Detection**: Egress anomaly + Rclone binary alert + 30-day-old domain alert

### Pattern 4 — Cloud-to-cloud SaaS exfiltration (modern era)
- UNC5537 Snowflake, APT29 Microsoft 365 tenants
- Bypasses victim network monitoring entirely
- Uses victim's own OAuth tokens
- **Detection**: Geo anomaly on SaaS login + token rotation + cloud-to-cloud flow baselining

### Pattern 5 — Dead-drop resolvers
- FIN6, APT29 use GitHub gist polling for IP distribution
- Looks like dev workflow
- **Detection**: GitHub gist polling from server fleet (not developer host)

---

## Defensive Detection Coverage Map

| Attack pattern | Detection method | Vendor product |
|----------------|------------------|----------------|
| DNS tunneling (TXT/A) | Zeek DNS analyzer + entropy | Corelight, ExtraHop |
| Multi-tier CDN front | SNI ≠ Host header delta | Bluecoat, F5 |
| Rclone invocation | EDR binary alert | CrowdStrike, Defender |
| OAuth token abuse | Cloud anomaly detection | Microsoft Defender for Cloud |
| Compromised WordPress C2 | Threat intel feed correlation | Cisco Talos, Anomali |
| Cloud-to-cloud SaaS exfil | CASB | Netskope, Zscaler ZTNA |
| Domain age anomaly | WHOIS + categorization feed | Cisco Umbrella, Bluecoat |
| TLS JA3 fingerprint | JA3 + JA4 hashing | F5, Citrix, AWS WAF |
| Beacon cadence | Zeek beacon analyzer | Zeek, Suricata, ExtraHop |

---

## Lessons for Red Teams

1. **Multi-tier redirectors are mandatory**: state actors (APT29) always use 3+ tier chains.
2. **Domain fronting is alive**: Cloudflare + Fastly retain it in 2024.
3. **Dead-drop resolvers add resilience**: GitHub gist, Telegram channels.
4. **Compartmentalize everything**: separate accounts, payments, SSH keys per team.
5. **Pre-stage burn plans**: detection during engagement means panic without burn plan.
6. **Match cadence to defender**: randomized beaconing (1–4 weeks) defeats interval detection.
7. **Use CDN-backed C2**: legitimate-looking domains on legitimate-looking infra.
8. **Test OPSEC pre-engagement**: VT, Cisco Umbrella, Bluecoat categorization.
9. **Cloud-native redirectors (Lambda/Functions)**: serverless, no static IP, looks legitimate.
10. **Document every burned asset**: avoid re-use for 6+ months.

---

## References

- Mandiant APT1 / APT29 / APT41 / UNC5537 reports (2013–2024)
- CISA advisories AA21-148A (DarkSide), AA22-320A (LockBit), AA23-320A (BlackCat)
- CrowdStrike 2024 Global Threat Hunting Report
- Microsoft MSTIC NOBELIUM reports (2021–2024)
- FireEye / Trellix SUNBURST analysis (2020)
- Cisco Talos BlackCat/ALPHV whitepaper (2023)
- IBM Security Conti Leaks analysis (2022)
- FBI Kaseya flash report (2021)
- Mandiant Operation Cronos analysis (2024)
- DOJ press releases on DarkSide / Conti / LockBit / REvil indictments (2019–2024)
- RiskIQ FIN6 report (2019)
- Visa Magecart advisory (2020)
- SpecterOps "Tradecraft" series
- "Red Team Infrastructure" (Rasta Mouse, 2023)
- "Defending Against Command-and-Control" (SpecterOps, 2022)
