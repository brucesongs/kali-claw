# Deep Research Test Cases

> This file is a companion to `SKILL.md`, containing structured test cases organized by category with severity ratings.

---

## Statistics

| Category | Count | Severity Range |
|------|------|-----------|
| A. Vulnerability Research | 3 | LOW - HIGH |
| B. Threat Actor Profiling | 3 | MEDIUM - HIGH |
| C. Attack Technique Investigation | 2 | MEDIUM - HIGH |
| D. Technology Security Assessment | 2 | MEDIUM - HIGH |
| E. Continuous Monitoring & Correlation | 3 | MEDIUM - HIGH |
| **Total** | **13** | **LOW - HIGH** |

---

## A. Vulnerability Research

### TC-DR-001: Single CVE Deep-Dive

| Field | Value |
|------|-----|
| **ID** | TC-DR-001 |
| **Name** | Single CVE Deep-Dive Research |
| **Severity** | LOW |
| **Category** | Vulnerability Research |
| **Objective** | Produce a comprehensive report on a specific CVE including affected software, exploit status, patch availability, and mitigation |
| **Prerequisites** | CVE identifier, internet access, NVD/Exploit-DB accessible |
| **Test Steps** | 1. Query NVD API for CVE details and CVSS score<br>2. Search Exploit-DB for public exploits (`searchsploit`)<br>3. Search GitHub for PoC code (`gh search code`)<br>4. Search vendor advisory pages for patch status<br>5. Search security blogs for analysis and write-ups<br>6. Cross-reference at least 3 sources before drawing conclusions |
| **Expected Results** | Structured report with: CVE description, CVSS score, affected versions, exploit availability (public/private/none), patch status, workarounds, and detection guidance |
| **False Positive Risk** | LOW - CVE data is authoritative; risk is outdated information rather than incorrect data |
| **Remediation** | Always verify patch status against the vendor's official advisory; check CVE status (DISPUTED, REJECTED) |
| **Related Tools** | NVD API, searchsploit, gh, curl |

### TC-DR-002: Software Vulnerability Landscape

| Field | Value |
|------|-----|
| **ID** | TC-DR-002 |
| **Name** | Software Vulnerability Landscape Research |
| **Severity** | MEDIUM |
| **Category** | Vulnerability Research |
| **Objective** | Map the complete vulnerability landscape for a specific software product or technology |
| **Prerequisites** | Target software name and version range, internet access |
| **Test Steps** | 1. Query NVD for all CVEs matching the software name<br>2. Filter by version range and severity (CVSS >= 7.0)<br>3. Categorize by vulnerability type (RCE, XSS, DoS, etc.)<br>4. Search Exploit-DB for each high-severity CVE<br>5. Search GitHub for public PoCs<br>6. Research attack chain possibilities (combining multiple vulnerabilities) |
| **Expected Results** | Vulnerability landscape report with: total CVE count by severity, trend over time, most exploitable vulnerabilities, attack chain analysis, and prioritized remediation list |
| **False Positive Risk** | MEDIUM - Some CVEs may be disputed, apply to different versions, or have incorrect CPE mappings |
| **Remediation** | Verify each high-severity CVE against the vendor advisory; check for version-specific applicability |
| **Related Tools** | NVD API, searchsploit, CVE Details, gh |

### TC-DR-003: Zero-Day Vulnerability Investigation

| Field | Value |
|------|-----|
| **ID** | TC-DR-003 |
| **Name** | Zero-Day Vulnerability Investigation |
| **Severity** | HIGH |
| **Category** | Vulnerability Research |
| **Objective** | Research a newly disclosed or rumored vulnerability with limited public information |
| **Prerequisites** | Vulnerability description or rumor source, internet access |
| **Test Steps** | 1. Search for any CVE assignment or advisory<br>2. Check vendor security pages and changelogs<br>3. Search security researcher Twitter/Mastodon/forums<br>4. Check exploit broker sites (publicly observable)<br>5. Analyze related commits in source repositories<br>6. Search dark web monitoring feeds (if available) |
| **Expected Results** | Intelligence report with: confirmed vs. unconfirmed details, affected versions (estimated), potential impact assessment, available mitigations, and confidence level |
| **False Positive Risk** | HIGH - Zero-day research often involves unverified claims; rumors may be exaggerated or fabricated |
| **Remediation** | Clearly label unverified information; maintain separate sections for confirmed facts and intelligence estimates; update report as new information emerges |
| **Related Tools** | NVD, vendor advisories, GitHub commit search, security community monitoring |

---

## B. Threat Actor Profiling

### TC-DR-004: APT Group Profile

| Field | Value |
|------|-----|
| **ID** | TC-DR-004 |
| **Name** | APT Group Comprehensive Profile |
| **Severity** | MEDIUM |
| **Category** | Threat Actor Profiling |
| **Objective** | Build a complete profile of a known threat actor including TTPs, campaigns, targets, and IOCs |
| **Prerequisites** | APT group identifier (e.g., APT28, Lazarus), MITRE ATT&CK access, internet |
| **Test Steps** | 1. Look up group in MITRE ATT&CK database<br>2. Search vendor threat intelligence reports (CrowdStrike, Mandiant, etc.)<br>3. Collect known IOCs (hashes, IPs, domains)<br>4. Map TTPs to MITRE ATT&CK techniques<br>5. Research targeted industries and geographies<br>6. Build campaign timeline from public reports |
| **Expected Results** | Adversary profile with: alias table, campaign timeline, TTP mapping to ATT&CK, IOC list, targeted sectors, and detection opportunities |
| **False Positive Risk** | MEDIUM - Attribution in threat intelligence is probabilistic; different vendors may disagree on group identities |
| **Remediation** | Cross-reference multiple vendor reports; note attribution confidence level; treat IOCs as historical indicators (may be stale) |
| **Related Tools** | MITRE ATT&CK, vendor threat reports, IOC databases |

### TC-DR-005: Campaign Correlation Analysis

| Field | Value |
|------|-----|
| **ID** | TC-DR-005 |
| **Name** | Campaign Correlation Analysis |
| **Severity** | HIGH |
| **Category** | Threat Actor Profiling |
| **Objective** | Correlate multiple attack campaigns to identify common tactics, shared infrastructure, or linked threat actors |
| **Prerequisites** | List of campaigns or incidents to correlate, IOC data, internet |
| **Test Steps** | 1. Gather IOCs and TTPs from each campaign<br>2. Identify shared infrastructure (overlapping IPs, domains, certificates)<br>3. Compare tooling and malware families<br>4. Analyze temporal patterns (campaign timing, operational tempo)<br>5. Map common techniques to MITRE ATT&CK<br>6. Research public attribution claims |
| **Expected Results** | Correlation report with: shared indicators, technique overlap matrix, infrastructure connections, attribution assessment with confidence level |
| **False Positive Risk** | HIGH - Shared TTPs may reflect common tooling rather than common actors; false flags are a known adversarial technique |
| **Remediation** | Weight infrastructure overlap higher than TTP similarity; acknowledge alternative hypotheses; avoid definitive attribution without strong evidence |
| **Related Tools** | MITRE ATT&CK, VirusTotal, PassiveTotal, Shodan |

### TC-DR-006: Emerging Threat Monitoring

| Field | Value |
|------|-----|
| **ID** | TC-DR-006 |
| **Name** | Emerging Threat Monitoring and Assessment |
| **Severity** | MEDIUM |
| **Category** | Threat Actor Profiling |
| **Objective** | Identify and assess emerging threats relevant to a specific industry or technology |
| **Prerequisites** | Target industry or technology scope, access to threat intelligence feeds |
| **Test Steps** | 1. Search recent CVE disclosures relevant to scope<br>2. Monitor security research blogs for new findings<br>3. Check CISA Known Exploited Vulnerabilities catalog<br>4. Search for new exploit kit releases on relevant forums<br>5. Analyze Shodan trends for exposed vulnerable services<br>6. Review recent breach reports in the target sector |
| **Expected Results** | Threat landscape brief with: top emerging threats, vulnerability exposure assessment, trending attack techniques, and recommended defensive actions |
| **False Positive Risk** | MEDIUM - Media amplification can overstate threats; verify actual exploitation evidence |
| **Remediation** | Prioritize threats with confirmed active exploitation; cross-reference CISA KEV for validated threats |
| **Related Tools** | CISA KEV, NVD, Shodan, security blogs, threat feeds |

---

## C. Attack Technique Investigation

### TC-DR-007: Technique Analysis with Detection Rules

| Field | Value |
|------|-----|
| **ID** | TC-DR-007 |
| **Name** | Attack Technique Analysis with Detection Engineering |
| **Severity** | HIGH |
| **Category** | Attack Technique Investigation |
| **Objective** | Research an attack technique in depth and produce detection rules and mitigation guidance |
| **Prerequisites** | Technique identifier or name, MITRE ATT&CK access, internet |
| **Test Steps** | 1. Look up technique in MITRE ATT&CK<br>2. Research all sub-techniques and variants<br>3. Search for existing Sigma/YARA/Snort detection rules on GitHub<br>4. Research known bypasses and evasion techniques<br>5. Identify data sources required for detection<br>6. Compile mitigation strategies from NIST and vendor guides |
| **Expected Results** | Technique dossier with: description, sub-techniques, detection rules (Sigma/YARA format), data source requirements, known bypasses, and mitigation checklist |
| **False Positive Risk** | LOW - Technique documentation is well-established; risk is in detection rule quality rather than factual accuracy |
| **Remediation** | Test detection rules against known benign and malicious samples; validate with purple team exercises |
| **Related Tools** | MITRE ATT&CK, Sigma rule repository, YARA rules, vendor detection guides |

### TC-DR-008: Defense Evasion Technique Research

| Field | Value |
|------|-----|
| **ID** | TC-DR-008 |
| **Name** | Defense Evasion Technique Research |
| **Severity** | HIGH |
| **Category** | Attack Technique Investigation |
| **Objective** | Research current defense evasion methods relevant to specific security controls |
| **Prerequisites** | Target security control (EDR, WAF, SIEM), internet access |
| **Test Steps** | 1. Identify relevant MITRE ATT&CK defense evasion techniques<br>2. Search for recent bypass research and conference talks<br>3. Search GitHub for evasion tools and frameworks<br>4. Research vendor-specific bypass techniques<br>5. Identify countermeasures for each evasion method<br>6. Assess realistic threat level based on complexity and required access |
| **Expected Results** | Evasion technique report with: technique catalog, bypass methods by security control, countermeasures, and threat level assessment |
| **False Positive Risk** | MEDIUM - Some published bypasses may be theoretical or patched in latest versions |
| **Remediation** | Verify bypass applicability against current software versions; check vendor security advisories for patches |
| **Related Tools** | MITRE ATT&CK, conference proceedings (DEF CON, Black Hat), GitHub, vendor docs |

---

## D. Technology Security Assessment

### TC-DR-009: Pre-Engagement Technology Research

| Field | Value |
|------|-----|
| **ID** | TC-DR-009 |
| **Name** | Pre-Engagement Technology Stack Security Research |
| **Severity** | MEDIUM |
| **Category** | Technology Security Assessment |
| **Objective** | Before a penetration test engagement, research all known vulnerabilities and attack vectors for the target's technology stack |
| **Prerequisites** | Identified technology stack (frameworks, servers, services), internet access |
| **Test Steps** | 1. Catalog all identified technologies and versions<br>2. Search NVD for each technology's CVEs<br>3. Search for known misconfigurations and common mistakes<br>4. Research default credentials and settings<br>5. Search for public exploits for each component<br>6. Identify attack chains combining multiple weaknesses |
| **Expected Results** | Pre-engagement intelligence report with: technology inventory, vulnerability matrix, exploit availability, attack chain analysis, and recommended test focus areas |
| **False Positive Risk** | MEDIUM - Version-specific CVEs may not apply; some technologies may be behind WAFs or proxies |
| **Remediation** | Verify technology fingerprints during active reconnaissance; confirm version accuracy before relying on CVE data |
| **Related Tools** | NVD, Exploit-DB, GitHub, technology documentation |

### TC-DR-010: Open-Source Dependency Audit Research

| Field | Value |
|------|-----|
| **ID** | TC-DR-010 |
| **Name** | Open-Source Dependency Security Audit Research |
| **Severity** | MEDIUM |
| **Category** | Technology Security Assessment |
| **Objective** | Research known vulnerabilities in a project's open-source dependencies |
| **Prerequisites** | List of dependencies (package.json, requirements.txt, etc.), internet access |
| **Test Steps** | 1. Extract all dependency names and versions<br>2. Search OSV database for known vulnerabilities<br>3. Search NVD for CVEs in each dependency<br>4. Check GitHub Security Advisories<br>5. Research dependency maintenance status (last update, known issues)<br>6. Identify supply chain attack history for critical dependencies |
| **Expected Results** | Dependency audit report with: vulnerable package list, CVE mapping, severity ranking, update recommendations, and supply chain risk assessment |
| **False Positive Risk** | MEDIUM - Some CVEs may not affect the specific usage pattern; dependency resolution may differ from direct version match |
| **Remediation** | Verify actual usage of vulnerable code paths; test with dependency checkers (npm audit, pip-audit, etc.) |
| **Related Tools** | OSV database, NVD, GitHub Advisories, Snyk, Dependabot |

---

## Summary

| ID | Name | Severity | Category |
|----|------|----------|----------|
| TC-DR-001 | Single CVE Deep-Dive | LOW | Vulnerability Research |
| TC-DR-002 | Software Vulnerability Landscape | MEDIUM | Vulnerability Research |
| TC-DR-003 | Zero-Day Vulnerability Investigation | HIGH | Vulnerability Research |
| TC-DR-004 | APT Group Comprehensive Profile | MEDIUM | Threat Actor Profiling |
| TC-DR-005 | Campaign Correlation Analysis | HIGH | Threat Actor Profiling |
| TC-DR-006 | Emerging Threat Monitoring | MEDIUM | Threat Actor Profiling |
| TC-DR-007 | Technique Analysis with Detection Rules | HIGH | Attack Technique Investigation |
| TC-DR-008 | Defense Evasion Technique Research | HIGH | Attack Technique Investigation |
| TC-DR-009 | Pre-Engagement Technology Research | MEDIUM | Technology Security Assessment |
| TC-DR-010 | Open-Source Dependency Audit Research | MEDIUM | Technology Security Assessment |
| TC-DR-011 | Continuous CVE Monitoring Pipeline | MEDIUM | Continuous Monitoring |
| TC-DR-012 | Multi-Source Intelligence Correlation | HIGH | Intelligence Correlation |
| TC-DR-013 | Adaptive Research Iteration Loop | MEDIUM | Adaptive Refinement |

---

## E. Continuous Monitoring & Correlation

### TC-DR-011: Continuous CVE Monitoring

| Field | Value |
|------|-----|
| **ID** | TC-DR-011 |
| **Name** | Continuous CVE Monitoring Pipeline |
| **Severity** | MEDIUM |
| **Category** | Continuous Monitoring |
| **Objective** | Establish and validate an ongoing CVE monitoring pipeline for a target technology stack |
| **Prerequisites** | Defined technology stack (3+ components), NVD API access, internet access |
| **Test Steps** | 1. Define monitored technologies with CPE names<br>2. Query NVD for CVEs published in the last 24 hours matching each CPE<br>3. Query CISA KEV for newly added entries<br>4. Check Exploit-DB for new public exploits<br>5. Compare results against previous day's snapshot (diff)<br>6. Generate change report highlighting new findings |
| **Expected Results** | Daily monitoring report with: new CVEs per technology, severity breakdown, exploit availability status, delta from previous day, and recommended actions |
| **False Positive Risk** | LOW - CVE data is authoritative; main risk is CPE mismatch causing irrelevant alerts |
| **Remediation** | Tune CPE filters; add version constraints to reduce noise; whitelist known-acceptable CVEs |
| **Related Tools** | NVD API, CISA KEV, searchsploit, diff |

### TC-DR-012: Multi-Source Intelligence Correlation

| Field | Value |
|------|-----|
| **ID** | TC-DR-012 |
| **Name** | Multi-Source Intelligence Correlation |
| **Severity** | HIGH |
| **Category** | Intelligence Correlation |
| **Objective** | Correlate IOCs and findings from 3+ independent sources to build a coherent threat picture with confidence scoring |
| **Prerequisites** | Research reports from at least 3 independent sources (vendor reports, blog posts, MITRE ATT&CK), IOC extraction tools |
| **Test Steps** | 1. Extract IOCs (IPs, hashes, domains, CVEs) from each source<br>2. Merge and deduplicate across all sources<br>3. Count source overlap per IOC (appears in N sources)<br>4. Assign confidence: HIGH (3+), MEDIUM (2), LOW (1)<br>5. Cross-reference IPs against AbuseIPDB and VirusTotal<br>6. Map techniques to MITRE ATT&CK IDs<br>7. Build entity relationship summary (Actor ↔ Campaign ↔ IOC) |
| **Expected Results** | Correlation report with: merged IOC list with confidence scores, ATT&CK technique mapping, entity relationship diagram, and intelligence gaps identified |
| **False Positive Risk** | MEDIUM - Shared infrastructure (CDNs, cloud IPs) may create false correlations; different naming conventions across vendors may cause missed links |
| **Remediation** | Exclude known benign infrastructure (cloud provider IP ranges); normalize vendor-specific names using alias tables; weight infrastructure overlap higher than technique similarity |
| **Related Tools** | grep, jq, AbuseIPDB API, VirusTotal API, MITRE ATT&CK |

### TC-DR-013: Adaptive Research Iteration

| Field | Value |
|------|-----|
| **ID** | TC-DR-013 |
| **Name** | Adaptive Research Iteration Loop |
| **Severity** | MEDIUM |
| **Category** | Adaptive Refinement |
| **Objective** | Validate the iterative refinement process: initial research → gap identification → targeted follow-up → report update |
| **Prerequisites** | A complex research topic with expected knowledge gaps, internet access |
| **Test Steps** | 1. Complete Phase 1-6 (standard deep research) on a complex topic<br>2. Review report for unverified claims (single-source) and unanswered sub-questions<br>3. Generate 2-3 new sub-questions from discovered gaps<br>4. Execute targeted searches for new sub-questions<br>5. Deep-read new sources and update the report<br>6. Verify: all key claims now have 2+ source confirmation<br>7. Confirm: 3 consecutive follow-up searches added no significant new information (convergence) |
| **Expected Results** | Updated report with: all key claims verified (2+ sources), original gaps filled, new discoveries integrated, convergence evidence (diminishing returns log) |
| **False Positive Risk** | LOW - The process itself is sound; risk is premature convergence (stopping too early) or infinite loops (never converging) |
| **Remediation** | Set hard limits: max 3 iteration rounds, max 5 new sub-questions per round; log each iteration's new information count to track convergence |
| **Related Tools** | All search tools from Phase 3, cross-reference tools from Phase 8 |
