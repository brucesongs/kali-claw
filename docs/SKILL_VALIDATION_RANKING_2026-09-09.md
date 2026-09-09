# SKILL Validation & Completeness Ranking — 2026-09-09

> **Scope**: all 139 SKILL domains | **Method**: automated sweep (bash -n syntax check on every bash block, placeholder/outdated-pattern grep, six-dimension scoring) + Top-30 public-URL liveness spot-check (55 URLs)
> **Axes**: **Completeness** = existing six-dimension score (main ranking, same methodology as usage-and-assessment.md); **Usability** = structure + command health; **Reliability** = reference health + review freshness
> **State**: post-fix (v0.3.5 mechanical sweep already applied — 102 syntax blocks, 3 placeholder stubs, 6 outdated patterns resolved to zero)

---

## 1. Methodology

| Axis | Checks | Grading |
|------|--------|---------|
| **Completeness (main sort)** | Six-dimension weighted score: compliance (lint), content volume (payloads+TC lines), command-syntax availability, references (URLs + 2xCVEs), MITRE alignment (T-codes), structure (H2/H3) | 0-100 → Excellent / Good / Fair / Poor |
| **Usability** | bash -n on every bash block (placeholder-aware preprocessing); placeholder markers; structure (guides>=1, H2>=12, TC>=10†) | A = clean; B = one structural gap; C = multiple gaps |
| **Reliability** | last_reviewed age (all <=2 days post truth-sync); public-URL liveness (Top-30 x2); outdated-pattern grep (post-fix: 0) | A = clean; B = auth-gated refs only; C = dead external links |

† TC<10 applies only to the 8 exempt meta skills (closed by policy, v0.3.3) — flagged, not graded D.

**Headline**: 139/139 lint-clean; **0 syntax-error blocks** (was 102); 0 placeholders (was 7 skills); 0 outdated patterns (was 6); repo average 81.1, minimum 65, no Poor.

## 2. Summary Statistics

| Metric | Value |
|--------|-------|
| Skills validated | 139 |
| Completeness avg / min / max | 81.1 / 65 / 92 |
| Excellent (>=80) / Good (70-79) / Fair (60-69) | 57 / 76 / 6 |
| Usability A / B / C | 105 / 6 / 28 |
| Reliability A / B / C | 131 / 4 / 4 |
| Vintage-CVE domains (newest CVE <2018, informational) | 19 |
| Unknown-command tokens (informational, whitelist gap) | 129 skills |
| Public URLs spot-checked / alive / auth-gated / dead | 55 / 22 / 8 / 5 |

## 3. Top 20 (completeness)

| # | SKILL | Score | Usability | Reliability |
|---|-------|-------|-----------|-------------|
| 5g-telecom-attack | 92 | C | 2017 (vintage) |
| quantum-crypto-attack | 92 | A | 2017 (vintage) |
| ad-cs-abuse | 89 | A | 2024 |
| ai-security | 89 | A | 2025 |
| automotive-vehicle-security | 89 | A | 2022 |
| blockchain-l2-attack | 89 | C | 2020 |
| deep-research | 89 | A | 2025 |
| detection-engineering | 89 | A | 2016 (vintage) |
| dns-attacks | 89 | A | 2023 |
| embedded-rtos-security | 89 | C | 2024 |
| hypervisor-introspection | 89 | C | 2023 |
| ics-fieldbus-attack | 89 | A | 2023 |
| pam-privilege-attack | 89 | A | 2025 |
| reverse-engineering-advanced | 89 | B | 2024 |
| sase-sse-attack | 89 | A | 2024 |
| satellite-leo-security | 89 | A | 2014 (vintage) |
| storage-san-attack | 89 | B | 2022 |
| threat-intel-platform-attack | 89 | B | 2022 |
| vulnerability-assessment | 89 | A | 2024 |
| ci-cd-supply-chain-attack | 86 | A | 2024 |

## 4. Bottom 10 (completeness)

| 130 | mcp-server-patterns | 71 | Good | C | A | 2025 | 8 | 6 | 10 | 5 |
| 131 | safety-guard | 71 | Good | B | A | — | 8 | 6 | 18 | 53 |
| 132 | web-sqli | 71 | Good | C | A | — | 14 | 16 | 10 | 0 |
| 133 | identity-provider-attack | 68 | Fair | A | A | 2019 | 10 | 1 | 13 | 0 |
| 134 | chronicle | 65 | Fair | B | A | — | 8 | 6 | 19 | 88 |
| 135 | codebase-onboarding | 65 | Fair | A | A | — | 10 | 6 | 13 | 80 |
| 136 | data-loss-prevention-bypass | 65 | Fair | A | A | — | 10 | 1 | 13 | 2 |
| 137 | edge-computing-security | 65 | Fair | A | A | 2022 | 10 | 1 | 13 | 1 |
| 138 | knowledge-ops | 65 | Fair | B | A | — | 8 | 6 | 16 | 100 |
| 139 | multi-agent-collaboration | 65 | Fair | C | A | 2021 | 8 | 6 | 11 | 14 |

**Bottom-10 note**: dominated by exempt meta skills (codebase-onboarding, knowledge-ops, multi-agent-collaboration, continuous-learning, council, chronicle, article-writing...) whose N/A dimensions are policy-closed; the lowest technical skills (data-loss-prevention-bypass, edge-computing-security, both 65) are content-thin Task-1.3 twins — candidates for the next deepening batch.

## 5. Full Ranking (139)

| # | SKILL | Score | Grade | Usability | Reliability | Newest CVE | TC | Guides | H2 | UnkCmds |
|---|-------|-------|-------|-----------|-------------|------------|----|--------|----|---------|
| 1 | 5g-telecom-attack | 92 | Excellent | A | C | 2017 (vintage) | 18 | 3 | 23 | 66 |
| 2 | quantum-crypto-attack | 92 | Excellent | A | A | 2017 (vintage) | 14 | 4 | 22 | 94 |
| 3 | ad-cs-abuse | 89 | Excellent | A | A | 2024 | 15 | 3 | 14 | 23 |
| 4 | ai-security | 89 | Excellent | A | A | 2025 | 10 | 9 | 22 | 43 |
| 5 | automotive-vehicle-security | 89 | Excellent | A | A | 2022 | 12 | 11 | 13 | 128 |
| 6 | blockchain-l2-attack | 89 | Excellent | A | C | 2020 | 12 | 2 | 12 | 31 |
| 7 | deep-research | 89 | Excellent | A | A | 2025 | 13 | 7 | 24 | 103 |
| 8 | detection-engineering | 89 | Excellent | A | A | 2016 (vintage) | 12 | 3 | 12 | 11 |
| 9 | dns-attacks | 89 | Excellent | A | A | 2023 | 10 | 9 | 19 | 189 |
| 10 | embedded-rtos-security | 89 | Excellent | A | C | 2024 | 12 | 6 | 18 | 87 |
| 11 | hypervisor-introspection | 89 | Excellent | A | C | 2023 | 12 | 2 | 26 | 103 |
| 12 | ics-fieldbus-attack | 89 | Excellent | A | A | 2023 | 12 | 10 | 15 | 65 |
| 13 | pam-privilege-attack | 89 | Excellent | A | A | 2025 | 18 | 4 | 14 | 90 |
| 14 | reverse-engineering-advanced | 89 | Excellent | A | B | 2024 | 40 | 3 | 17 | 57 |
| 15 | sase-sse-attack | 89 | Excellent | A | A | 2024 | 15 | 9 | 13 | 104 |
| 16 | satellite-leo-security | 89 | Excellent | A | A | 2014 (vintage) | 12 | 2 | 13 | 122 |
| 17 | storage-san-attack | 89 | Excellent | A | B | 2022 | 12 | 4 | 15 | 104 |
| 18 | threat-intel-platform-attack | 89 | Excellent | A | B | 2022 | 35 | 3 | 22 | 65 |
| 19 | vulnerability-assessment | 89 | Excellent | A | A | 2024 | 15 | 9 | 20 | 65 |
| 20 | ci-cd-supply-chain-attack | 86 | Excellent | A | A | 2024 | 12 | 6 | 12 | 109 |
| 21 | cloud-identity-attack | 86 | Excellent | A | A | — | 12 | 8 | 13 | 27 |
| 22 | council | 86 | Excellent | A | A | — | 10 | 8 | 14 | 0 |
| 23 | cspm-casb-attack | 86 | Excellent | A | B | 2023 | 14 | 4 | 12 | 52 |
| 24 | data-exfiltration-attack | 86 | Excellent | A | A | — | 34 | 3 | 20 | 72 |
| 25 | deception-honeypot | 86 | Excellent | A | A | 2026 | 12 | 3 | 12 | 72 |
| 26 | exa-search | 86 | Excellent | A | A | 2024 | 10 | 6 | 18 | 1 |
| 27 | exploit-development | 86 | Excellent | A | A | 2022 | 10 | 6 | 12 | 25 |
| 28 | gitops-security | 86 | Excellent | C | A | 2024 | 27 | 3 | 8 | 56 |
| 29 | hf-vhf-radio-attack | 86 | Excellent | A | A | — | 12 | 4 | 14 | 268 |
| 30 | kubernetes-attack | 86 | Excellent | A | A | 2024 | 12 | 8 | 13 | 54 |
| 31 | macos-security | 86 | Excellent | A | A | 2023 | 18 | 3 | 21 | 82 |
| 32 | malware-analysis-advanced | 86 | Excellent | A | A | — | 40 | 3 | 17 | 43 |
| 33 | multi-agent-runtime-engineering | 86 | Excellent | A | A | 2024 | 30 | 5 | 12 | 97 |
| 34 | network-pentest | 86 | Excellent | A | A | 2026 | 11 | 9 | 18 | 111 |
| 35 | patch-to-poc-pipeline | 86 | Excellent | A | A | 2024 | 29 | 3 | 12 | 106 |
| 36 | payload-generation | 86 | Excellent | A | A | 2022 | 10 | 9 | 15 | 27 |
| 37 | privilege-escalation | 86 | Excellent | A | A | 2023 | 10 | 4 | 20 | 54 |
| 38 | red-team-infrastructure | 86 | Excellent | A | A | — | 35 | 3 | 18 | 115 |
| 39 | threat-hunting | 86 | Excellent | A | A | — | 12 | 3 | 19 | 12 |
| 40 | web-xxe | 86 | Excellent | A | A | 2017 (vintage) | 10 | 4 | 18 | 38 |
| 41 | agentic-pentest | 83 | Excellent | A | A | 2026 | 12 | 4 | 15 | 6 |
| 42 | ai-agent-framework-attack | 83 | Excellent | C | A | 2024 | 18 | 3 | 9 | 8 |
| 43 | ai-agent-security | 83 | Excellent | A | A | 2025 | 12 | 3 | 12 | 34 |
| 44 | ai-fuzzing | 83 | Excellent | A | A | 2026 | 10 | 8 | 12 | 89 |
| 45 | blockchain-web3 | 83 | Excellent | C | A | — | 13 | 8 | 11 | 30 |
| 46 | cloud-security | 83 | Excellent | C | A | 2017 (vintage) | 11 | 9 | 11 | 74 |
| 47 | cms-framework-attack | 83 | Excellent | A | A | 2024 | 10 | 4 | 18 | 28 |
| 48 | container-security | 83 | Excellent | A | A | — | 11 | 9 | 19 | 54 |
| 49 | cps-attack | 83 | Excellent | C | A | 2024 | 28 | 3 | 8 | 25 |
| 50 | crypto-attacks | 83 | Excellent | A | A | — | 11 | 7 | 20 | 22 |
| 51 | data-platform-attack | 83 | Excellent | C | A | — | 24 | 3 | 11 | 25 |
| 52 | database-attack | 83 | Excellent | A | A | — | 10 | 6 | 17 | 41 |
| 53 | email-security-deep | 83 | Excellent | A | A | — | 12 | 4 | 15 | 70 |
| 54 | firmware-reverse | 83 | Excellent | A | A | 2001 (vintage) | 10 | 4 | 12 | 62 |
| 55 | hardware-security | 83 | Excellent | A | A | 2026 | 10 | 6 | 13 | 72 |
| 56 | iot-pentest | 83 | Excellent | A | A | 2017 (vintage) | 12 | 3 | 13 | 86 |
| 57 | logging-monitoring | 83 | Excellent | C | A | 2021 | 10 | 6 | 10 | 34 |
| 58 | mainframe-security | 83 | Excellent | C | A | — | 12 | 5 | 9 | 31 |
| 59 | mobile-app-instrumentation | 83 | Excellent | C | A | — | 12 | 3 | 9 | 15 |
| 60 | network-sniffing-mitm | 83 | Excellent | A | A | 2007 (vintage) | 10 | 4 | 18 | 49 |
| 61 | network-tunneling-proxy | 83 | Excellent | A | A | 2018 | 10 | 9 | 15 | 74 |
| 62 | osint | 83 | Excellent | A | A | 2023 | 10 | 9 | 12 | 36 |
| 63 | pentest-reporting | 83 | Excellent | A | A | 2026 | 10 | 4 | 12 | 92 |
| 64 | physical-security-testing | 83 | Excellent | A | A | — | 12 | 2 | 34 | 37 |
| 65 | post-quantum-migration-attack | 83 | Excellent | A | A | 2024 | 33 | 3 | 15 | 29 |
| 66 | recon-osint | 83 | Excellent | C | A | 2026 | 11 | 12 | 10 | 41 |
| 67 | secret-management-attack | 83 | Excellent | A | A | 2021 | 23 | 4 | 15 | 144 |
| 68 | security-bounty-hunter | 83 | Excellent | A | A | 2022 | 10 | 9 | 20 | 19 |
| 69 | security-review | 83 | Excellent | A | A | 2023 | 10 | 6 | 12 | 47 |
| 70 | social-intelligence | 83 | Excellent | A | A | — | 10 | 9 | 20 | 32 |
| 71 | steganography | 83 | Excellent | A | A | 2026 | 10 | 6 | 20 | 149 |
| 72 | supply-chain-security | 83 | Excellent | A | A | 2019 | 12 | 6 | 12 | 84 |
| 73 | tool-mastery | 83 | Excellent | A | A | 2018 | 10 | 4 | 17 | 89 |
| 74 | uav-drone-security | 83 | Excellent | C | A | 2017 (vintage) | 12 | 2 | 10 | 182 |
| 75 | username-profiling | 83 | Excellent | A | A | 2020 | 13 | 4 | 18 | 88 |
| 76 | vpn-attack | 83 | Excellent | A | A | 2020 | 10 | 9 | 14 | 42 |
| 77 | web-access-control | 83 | Excellent | A | A | 2012 (vintage) | 13 | 7 | 13 | 25 |
| 78 | web-auth-bypass | 83 | Excellent | C | A | 2001 (vintage) | 17 | 6 | 10 | 59 |
| 79 | 5g-6g-telecom-attack-advanced | 80 | Excellent | A | A | 2023 | 10 | 1 | 13 | 9 |
| 80 | ai-safety-redteam-advanced | 80 | Excellent | A | A | 2024 | 12 | 2 | 18 | 0 |
| 81 | anti-forensics | 80 | Excellent | A | A | — | 10 | 4 | 13 | 70 |
| 82 | api-security | 80 | Excellent | A | A | 2021 | 20 | 7 | 12 | 34 |
| 83 | article-writing | 80 | Excellent | B | A | 2026 | 8 | 9 | 33 | 94 |
| 84 | binary-reverse | 80 | Excellent | A | A | 2026 | 11 | 6 | 12 | 74 |
| 85 | cloud-native-vuln-research | 80 | Excellent | C | A | 2026 | 12 | 2 | 10 | 62 |
| 86 | command-injection-advanced | 80 | Excellent | A | A | 1999 (vintage) | 10 | 5 | 13 | 0 |
| 87 | confidential-computing-attack | 80 | Excellent | C | A | 2022 | 21 | 3 | 11 | 32 |
| 88 | darkweb-intel | 80 | Excellent | C | A | — | 12 | 8 | 11 | 46 |
| 89 | edge-computing-attack | 80 | Excellent | C | A | 2026 | 19 | 3 | 11 | 8 |
| 90 | file-inclusion | 80 | Excellent | A | A | 2005 (vintage) | 10 | 4 | 18 | 60 |
| 91 | game-anticheat-bypass | 80 | Excellent | C | A | 2021 | 12 | 2 | 10 | 0 |
| 92 | hsm-attack | 80 | Excellent | C | A | 2024 | 26 | 3 | 8 | 29 |
| 93 | insecure-design | 80 | Excellent | A | A | 2024 | 10 | 8 | 19 | 8 |
| 94 | llm-red-team | 80 | Excellent | C | A | 2023 | 12 | 3 | 11 | 19 |
| 95 | open-banking-attack | 80 | Excellent | C | A | 2022 | 29 | 3 | 8 | 47 |
| 96 | post-exploitation | 80 | Excellent | A | A | 2022 | 11 | 8 | 18 | 72 |
| 97 | repo-scan | 80 | Excellent | A | A | — | 10 | 6 | 15 | 65 |
| 98 | sdr-rf-attack | 80 | Excellent | A | A | 2025 | 10 | 10 | 13 | 62 |
| 99 | security-misconfiguration | 80 | Excellent | A | A | 2017 (vintage) | 11 | 9 | 16 | 19 |
| 100 | wifi-pentest | 80 | Excellent | A | A | 2019 | 10 | 6 | 19 | 93 |
| 101 | autonomous-loops | 77 | Good | A | A | — | 10 | 9 | 13 | 135 |
| 102 | av-edr-evasion | 77 | Good | A | A | — | 10 | 10 | 20 | 38 |
| 103 | bluetooth-rfid-nfc | 77 | Good | A | A | 2006 (vintage) | 10 | 4 | 19 | 53 |
| 104 | digital-forensics | 77 | Good | A | A | 2020 | 10 | 6 | 20 | 95 |
| 105 | engagement-manager | 77 | Good | A | A | — | 10 | 4 | 17 | 86 |
| 106 | hardware-side-channel-advanced | 77 | Good | A | A | 2020 | 10 | 1 | 13 | 0 |
| 107 | mobile-security | 77 | Good | C | A | 2024 | 10 | 6 | 11 | 35 |
| 108 | password-attack | 77 | Good | A | A | 2026 | 12 | 8 | 18 | 34 |
| 109 | payment-security | 77 | Good | A | A | 2009 (vintage) | 13 | 3 | 12 | 21 |
| 110 | pqc-implementation-attack | 77 | Good | A | A | — | 10 | 2 | 13 | 14 |
| 111 | protocol-state-exploitation | 77 | Good | A | A | — | 10 | 5 | 12 | 0 |
| 112 | scada-ics-security | 77 | Good | A | A | 2011 (vintage) | 10 | 8 | 13 | 162 |
| 113 | social-engineering | 77 | Good | A | A | — | 10 | 6 | 12 | 119 |
| 114 | terminal-ops | 77 | Good | A | A | — | 10 | 6 | 13 | 95 |
| 115 | web-deserialization | 77 | Good | A | A | 2022 | 10 | 6 | 14 | 74 |
| 116 | web-xss | 77 | Good | A | A | 2020 | 10 | 9 | 19 | 3 |
| 117 | ad-ldap-attack | 74 | Good | C | A | 2005 (vintage) | 10 | 4 | 8 | 38 |
| 118 | ai-agent-supply-chain-attack | 74 | Good | A | A | 2024 | 10 | 2 | 13 | 2 |
| 119 | browser-qa | 74 | Good | A | A | 2026 | 10 | 6 | 18 | 0 |
| 120 | concurrency-exploitation | 74 | Good | A | A | 2024 | 10 | 5 | 13 | 0 |
| 121 | data-scraper-agent | 74 | Good | A | A | 2024 | 10 | 6 | 18 | 28 |
| 122 | docker-patterns | 74 | Good | A | A | — | 10 | 6 | 16 | 30 |
| 123 | email-protocol-attack | 74 | Good | C | A | 2021 | 10 | 4 | 10 | 31 |
| 124 | eu-ai-act-compliance-redteam | 74 | Good | A | A | — | 10 | 2 | 13 | 1 |
| 125 | search-first | 74 | Good | C | A | 2025 | 10 | 6 | 9 | 59 |
| 126 | verification-loop | 74 | Good | B | A | — | 8 | 9 | 14 | 48 |
| 127 | voip-sip-attack | 74 | Good | C | A | 2021 | 12 | 4 | 8 | 21 |
| 128 | web-ssrf | 74 | Good | A | A | 2018 | 11 | 7 | 18 | 29 |
| 129 | continuous-learning | 71 | Good | B | A | — | 9 | 6 | 13 | 64 |
| 130 | mcp-server-patterns | 71 | Good | C | A | 2025 | 8 | 6 | 10 | 5 |
| 131 | safety-guard | 71 | Good | B | A | — | 8 | 6 | 18 | 53 |
| 132 | web-sqli | 71 | Good | C | A | — | 14 | 16 | 10 | 0 |
| 133 | identity-provider-attack | 68 | Fair | A | A | 2019 | 10 | 1 | 13 | 0 |
| 134 | chronicle | 65 | Fair | B | A | — | 8 | 6 | 19 | 88 |
| 135 | codebase-onboarding | 65 | Fair | A | A | — | 10 | 6 | 13 | 80 |
| 136 | data-loss-prevention-bypass | 65 | Fair | A | A | — | 10 | 1 | 13 | 2 |
| 137 | edge-computing-security | 65 | Fair | A | A | 2022 | 10 | 1 | 13 | 1 |
| 138 | knowledge-ops | 65 | Fair | B | A | — | 8 | 6 | 16 | 100 |
| 139 | multi-agent-collaboration | 65 | Fair | C | A | 2021 | 8 | 6 | 11 | 14 |

## 6. Findings Register

### Fixed in v0.3.5 (zeroed)
- **102 broken bash blocks → 0**: fence mislabeling (~47 relabeled text/powershell/python/spl/promql/javascript), uncommented session-transcript lines (~60 commented), genuine shell bugs (~15 fixed: mixed quotes, missing jq quotes, escaped-quote typo, stray paren, printf splice, awk nesting, unquoted parens), 1 nested-fence rendering bug (supply-chain SBOM script switched to ~~~ fence)
- **3 placeholder stubs → 0** (data-loss-prevention-bypass / edge-computing-security / identity-provider-attack): "Additional Payloads" junk replaced with domain-specific exploitation/persistence references
- **6 outdated patterns → 0**: docker-compose command usage x2, Frida pre-17 findExportByName(null) x3 (→ getGlobalExportByName), hashcat -O flag, stale version strings

### Reported only (informational)
| ID | Severity | Finding | Affected |
|----|----------|---------|----------|
| R3-1 | Low | Dead external links: gitea.osmocom.org repos moved (osmo-hlr, osmo-msc), 0xPolygonHermez/trusted-setup-mpc gone, api.us-east-1.mbedcloud.com EOL x2, invisiblethings.org/bluepill.html unreachable | 5g-telecom-attack, blockchain-l2-attack, embedded-rtos-security, hypervisor-introspection |
| R2-1 | Info | Vintage-CVE domains (newest CVE pre-2018) — legitimate for legacy/telecom/hardware domains | 19 skills |
| U3-1 | Info | Unknown command tokens vs whitelist — mostly niche tools below baseline coverage, not errors | 129 skills |

## 7. Recommended Actions

1. **Dead-link touch-up** (4 skills, ~5 URLs, ~15 min) — fold into next patch
2. **Bottom technical twins** (data-loss-prevention-bypass, edge-computing-security): same deepening treatment as v0.3.1's 5g/hardware twins
3. **Whitelist extension** (~30 min): absorb TOOLS.md category tables into the validator to shrink U3 noise
4. Re-run this sweep at the 4th monthly review (2026-10-05) as a standing quality gate

---
*Generated by the v0.3.5 validation sweep; data: validation-results (139 skills) + Top-30 URL spot-check.*
