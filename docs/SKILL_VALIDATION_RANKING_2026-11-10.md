# SKILL Validation & Completeness Ranking — 2026-11-10

> **Scope**: all 139 SKILL domains | **Tool**: `validation/check-skill-usability.py` (v0.3.8 formalization of the 2026-09-09 three-axis methodology)
> **Baseline lineage**: supersedes `SKILL_VALIDATION_RANKING_2026-09-09.md` (scores may differ ±2 vs the informal original — formula is now fixed)
> **URL liveness**: not re-run this cycle (offline reliability only)

## 1. Methodology

| Axis | Definition | Grading |
|------|------------|---------|
| **Completeness** | D1 lint ×1.0, D2 (payloads+TC lines) ×1.0, D3 bash-blocks ×1.5, D4 (URLs + 2×CVEs) ×0.8, D5 T-codes ×1.0, D6 (H2/H3+guides+TC) ×1.2 → /32.5×100 | Excellent ≥80 / Good 70-79 / Fair 60-69 / Poor <60 |
| **Usability** | bash -n (placeholder-aware, transcripts skipped) + placeholder markers + gates (guides≥1, H2≥12, TC≥10; exempt-meta TC gate waived) | A clean / B one gap / C multiple |
| **Reliability** | outdated-pattern grep (docker-compose cmd, Frida pre-17, hashcat -O) + last_reviewed freshness (>90d = gap) | A clean / B one / C multiple |

## 2. Summary Statistics

| Metric | Value |
|--------|-------|
| Skills validated | 139 |
| Completeness avg / min / max | 89.8 / 72.3 / 95.4 |
| Excellent / Good / Fair / Poor | 130 / 9 / 0 / 0 |
| Usability A / B / C | 125 / 1 / 13 |
| Reliability A / B / C (offline) | 62 / 77 / 0 |
| bash blocks with syntax errors | 16 |
| payload-showcase blocks (gate N/A) | 79 |
| mixed-language blocks (relabel candidates) | 179 |
| tolerated mixed-prose blocks (segment majority passes) | 39 |
| outdated patterns | 0 |

## 3. Top 20 (completeness)

| # | SKILL | Score | Grade | Usability | Reliability |
|---|-------|-------|-------|-----------|-------------|
| 1 | 5g-telecom-attack | 95.4 | Excellent | A | B |
| 2 | ad-cs-abuse | 95.4 | Excellent | A | B |
| 3 | ai-agent-framework-attack | 95.4 | Excellent | A | B |
| 4 | ai-security | 95.4 | Excellent | A | A |
| 5 | automotive-vehicle-security | 95.4 | Excellent | B | A |
| 6 | blockchain-l2-attack | 95.4 | Excellent | A | A |
| 7 | cloud-identity-attack | 95.4 | Excellent | A | B |
| 8 | cps-attack | 95.4 | Excellent | A | B |
| 9 | cspm-casb-attack | 95.4 | Excellent | A | B |
| 10 | data-exfiltration-attack | 95.4 | Excellent | A | B |
| 11 | data-platform-attack | 95.4 | Excellent | A | B |
| 12 | deep-research | 95.4 | Excellent | A | A |
| 13 | detection-engineering | 95.4 | Excellent | A | B |
| 14 | dns-attacks | 95.4 | Excellent | A | A |
| 15 | exa-search | 95.4 | Excellent | A | B |
| 16 | exploit-development | 95.4 | Excellent | A | A |
| 17 | gitops-security | 95.4 | Excellent | A | A |
| 18 | hypervisor-introspection | 95.4 | Excellent | A | B |
| 19 | ics-fieldbus-attack | 95.4 | Excellent | A | A |
| 20 | kubernetes-attack | 95.4 | Excellent | A | B |

## 4. Bottom 10 (completeness)

| # | SKILL | Score | Grade | Usability | Reliability | Notes |
|---|-------|-------|-------|-----------|-------------|-------|
| 130 | identity-provider-attack | 72.3 | Good | A | B | — |
| 131 | email-security-deep | 75.4 | Good | C | B | — |
| 132 | codebase-onboarding | 75.7 | Good | A | B | exempt meta: TC gate waived |
| 133 | chronicle | 78.2 | Good | A | A | exempt meta: TC gate waived |
| 134 | knowledge-ops | 78.2 | Good | A | B | exempt meta: TC gate waived |
| 135 | hardware-security | 78.5 | Good | C | B | — |
| 136 | mobile-security | 78.5 | Good | C | A | — |
| 137 | security-review | 78.5 | Good | C | A | — |
| 138 | social-intelligence | 78.5 | Good | C | A | — |
| 139 | multi-agent-collaboration | 80.6 | Excellent | A | B | exempt meta: TC gate waived |

## 5. Full Ranking (139)

| # | SKILL | Score | Grade | Us | Rel | TC | Guides | H2 | URLs | CVEs | T | BashErr | UnkCmds |
|---|-------|-------|-------|----|----|----|--------|----|------|------|---|---------|---------|
| 1 | 5g-telecom-attack | 95.4 | Excellent | A | B | 18 | 3 | 78 | 26 | 4 | 6 | 0 | 83 |
| 2 | ad-cs-abuse | 95.4 | Excellent | A | B | 15 | 3 | 95 | 37 | 8 | 7 | 0 | 23 |
| 3 | ai-agent-framework-attack | 95.4 | Excellent | A | B | 18 | 3 | 97 | 35 | 3 | 8 | 0 | 14 |
| 4 | ai-security | 95.4 | Excellent | A | A | 10 | 9 | 123 | 53 | 6 | 9 | 0 | 68 |
| 5 | automotive-vehicle-security | 95.4 | Excellent | B | A | 12 | 11 | 177 | 31 | 15 | 32 | 0 | 139 |
| 6 | blockchain-l2-attack | 95.4 | Excellent | A | A | 12 | 2 | 60 | 43 | 1 | 8 | 0 | 35 |
| 7 | cloud-identity-attack | 95.4 | Excellent | A | B | 12 | 8 | 135 | 299 | 11 | 15 | 0 | 71 |
| 8 | cps-attack | 95.4 | Excellent | A | B | 28 | 3 | 74 | 24 | 7 | 7 | 0 | 41 |
| 9 | cspm-casb-attack | 95.4 | Excellent | A | B | 14 | 4 | 92 | 102 | 13 | 12 | 0 | 51 |
| 10 | data-exfiltration-attack | 95.4 | Excellent | A | B | 34 | 3 | 86 | 39 | 2 | 16 | 0 | 85 |
| 11 | data-platform-attack | 95.4 | Excellent | A | B | 24 | 3 | 96 | 64 | 1 | 8 | 0 | 46 |
| 12 | deep-research | 95.4 | Excellent | A | A | 13 | 7 | 133 | 97 | 2 | 15 | 0 | 122 |
| 13 | detection-engineering | 95.4 | Excellent | A | B | 12 | 3 | 74 | 54 | 5 | 25 | 0 | 38 |
| 14 | dns-attacks | 95.4 | Excellent | A | A | 10 | 9 | 105 | 109 | 12 | 9 | 0 | 273 |
| 15 | exa-search | 95.4 | Excellent | A | B | 10 | 6 | 92 | 11 | 7 | 8 | 0 | 3 |
| 16 | exploit-development | 95.4 | Excellent | A | A | 10 | 6 | 75 | 21 | 2 | 6 | 0 | 49 |
| 17 | gitops-security | 95.4 | Excellent | A | A | 27 | 3 | 87 | 28 | 4 | 6 | 0 | 73 |
| 18 | hypervisor-introspection | 95.4 | Excellent | A | B | 12 | 2 | 74 | 37 | 50 | 12 | 0 | 102 |
| 19 | ics-fieldbus-attack | 95.4 | Excellent | A | A | 12 | 10 | 145 | 44 | 23 | 30 | 0 | 106 |
| 20 | kubernetes-attack | 95.4 | Excellent | A | B | 12 | 8 | 103 | 170 | 31 | 9 | 0 | 113 |
| 21 | logging-monitoring | 95.4 | Excellent | A | B | 10 | 6 | 74 | 65 | 1 | 14 | 0 | 107 |
| 22 | macos-security | 95.4 | Excellent | A | B | 18 | 3 | 83 | 47 | 21 | 35 | 0 | 99 |
| 23 | mainframe-security | 95.4 | Excellent | A | B | 12 | 5 | 85 | 42 | 13 | 25 | 0 | 41 |
| 24 | malware-analysis-advanced | 95.4 | Excellent | A | B | 40 | 3 | 93 | 20 | 5 | 8 | 0 | 47 |
| 25 | mobile-app-instrumentation | 95.4 | Excellent | A | B | 12 | 3 | 55 | 71 | 4 | 14 | 0 | 29 |
| 26 | network-pentest | 95.4 | Excellent | A | A | 11 | 9 | 102 | 39 | 4 | 6 | 0 | 186 |
| 27 | pam-privilege-attack | 95.4 | Excellent | A | A | 18 | 4 | 102 | 139 | 4 | 7 | 0 | 103 |
| 28 | privilege-escalation | 95.4 | Excellent | A | B | 10 | 4 | 77 | 25 | 9 | 8 | 0 | 54 |
| 29 | quantum-crypto-attack | 95.4 | Excellent | A | A | 12 | 4 | 126 | 52 | 2 | 8 | 0 | 116 |
| 30 | recon-osint | 95.4 | Excellent | A | A | 11 | 12 | 97 | 39 | 4 | 6 | 0 | 52 |
| 31 | red-team-infrastructure | 95.4 | Excellent | A | B | 35 | 3 | 90 | 46 | 3 | 9 | 0 | 117 |
| 32 | reverse-engineering-advanced | 95.4 | Excellent | A | A | 40 | 3 | 141 | 36 | 11 | 36 | 0 | 63 |
| 33 | sase-sse-attack | 95.4 | Excellent | A | A | 15 | 9 | 153 | 111 | 20 | 12 | 0 | 130 |
| 34 | satellite-leo-security | 95.4 | Excellent | A | B | 12 | 2 | 61 | 29 | 4 | 15 | 0 | 136 |
| 35 | storage-san-attack | 95.4 | Excellent | A | B | 12 | 4 | 87 | 199 | 33 | 6 | 0 | 156 |
| 36 | threat-intel-platform-attack | 95.4 | Excellent | A | B | 35 | 3 | 91 | 31 | 3 | 8 | 0 | 68 |
| 37 | vpn-attack | 95.4 | Excellent | A | B | 10 | 9 | 119 | 105 | 6 | 9 | 0 | 193 |
| 38 | vulnerability-assessment | 95.4 | Excellent | A | A | 15 | 9 | 128 | 91 | 10 | 6 | 0 | 131 |
| 39 | web-auth-bypass | 95.4 | Excellent | A | A | 17 | 6 | 83 | 82 | 5 | 6 | 0 | 93 |
| 40 | web-xxe | 95.4 | Excellent | A | B | 10 | 4 | 73 | 56 | 6 | 6 | 0 | 38 |
| 41 | anti-forensics | 94.2 | Excellent | A | A | 10 | 4 | 68 | 15 | 0 | 6 | 0 | 78 |
| 42 | multi-agent-runtime-engineering | 94.2 | Excellent | A | B | 30 | 5 | 121 | 12 | 3 | 6 | 0 | 127 |
| 43 | wifi-pentest | 94.2 | Excellent | A | A | 10 | 6 | 77 | 12 | 1 | 6 | 0 | 146 |
| 44 | data-loss-prevention-bypass | 93.8 | Excellent | A | A | 13 | 1 | 49 | 14 | 6 | 7 | 0 | 17 |
| 45 | ai-fuzzing | 92.3 | Excellent | A | A | 10 | 8 | 80 | 64 | 4 | 5 | 0 | 178 |
| 46 | api-security | 92.3 | Excellent | A | A | 20 | 7 | 93 | 97 | 6 | 5 | 0 | 66 |
| 47 | binary-reverse | 92.3 | Excellent | A | A | 11 | 6 | 76 | 10 | 6 | 5 | 0 | 132 |
| 48 | blockchain-web3 | 92.3 | Excellent | A | A | 13 | 8 | 132 | 91 | 1 | 5 | 0 | 66 |
| 49 | cloud-native-vuln-research | 92.3 | Excellent | A | B | 12 | 2 | 52 | 97 | 33 | 5 | 0 | 79 |
| 50 | cms-framework-attack | 92.3 | Excellent | A | A | 10 | 4 | 66 | 232 | 23 | 5 | 0 | 36 |
| 51 | confidential-computing-attack | 92.3 | Excellent | A | B | 21 | 3 | 91 | 33 | 8 | 4 | 0 | 47 |
| 52 | container-security | 92.3 | Excellent | A | A | 11 | 9 | 121 | 107 | 6 | 5 | 0 | 215 |
| 53 | crypto-attacks | 92.3 | Excellent | A | A | 11 | 7 | 111 | 37 | 4 | 5 | 0 | 55 |
| 54 | database-attack | 92.3 | Excellent | A | A | 10 | 6 | 77 | 34 | 2 | 5 | 0 | 73 |
| 55 | edge-computing-attack | 92.3 | Excellent | A | B | 19 | 3 | 90 | 52 | 3 | 5 | 0 | 39 |
| 56 | file-inclusion | 92.3 | Excellent | A | A | 10 | 4 | 77 | 169 | 3 | 5 | 0 | 76 |
| 57 | firmware-reverse | 92.3 | Excellent | A | A | 10 | 4 | 77 | 35 | 4 | 5 | 0 | 75 |
| 58 | hf-vhf-radio-attack | 92.3 | Excellent | A | B | 12 | 4 | 144 | 40 | 0 | 5 | 0 | 369 |
| 59 | insecure-design | 92.3 | Excellent | A | B | 10 | 8 | 94 | 105 | 4 | 4 | 0 | 24 |
| 60 | llm-red-team | 92.3 | Excellent | A | A | 12 | 3 | 78 | 54 | 5 | 5 | 0 | 52 |
| 61 | network-sniffing-mitm | 92.3 | Excellent | A | B | 10 | 4 | 73 | 31 | 4 | 4 | 0 | 85 |
| 62 | network-tunneling-proxy | 92.3 | Excellent | A | B | 10 | 9 | 112 | 90 | 4 | 5 | 0 | 202 |
| 63 | osint | 92.3 | Excellent | A | A | 10 | 9 | 141 | 146 | 3 | 5 | 0 | 112 |
| 64 | patch-to-poc-pipeline | 92.3 | Excellent | A | A | 29 | 3 | 99 | 31 | 14 | 5 | 0 | 128 |
| 65 | post-exploitation | 92.3 | Excellent | A | B | 11 | 8 | 93 | 25 | 3 | 5 | 0 | 122 |
| 66 | post-quantum-migration-attack | 92.3 | Excellent | A | A | 33 | 3 | 83 | 20 | 3 | 4 | 0 | 34 |
| 67 | repo-scan | 92.3 | Excellent | A | A | 10 | 6 | 93 | 16 | 3 | 4 | 0 | 100 |
| 68 | sdr-rf-attack | 92.3 | Excellent | A | B | 10 | 10 | 124 | 33 | 5 | 5 | 0 | 129 |
| 69 | secret-management-attack | 92.3 | Excellent | A | B | 18 | 4 | 105 | 97 | 6 | 4 | 0 | 192 |
| 70 | security-bounty-hunter | 92.3 | Excellent | A | A | 10 | 9 | 150 | 136 | 4 | 4 | 0 | 78 |
| 71 | security-misconfiguration | 92.3 | Excellent | A | A | 11 | 9 | 127 | 176 | 4 | 5 | 0 | 123 |
| 72 | supply-chain-security | 92.3 | Excellent | A | A | 12 | 6 | 67 | 46 | 4 | 5 | 0 | 126 |
| 73 | tool-mastery | 92.3 | Excellent | A | A | 10 | 4 | 68 | 18 | 4 | 5 | 0 | 126 |
| 74 | username-profiling | 92.3 | Excellent | A | A | 13 | 4 | 112 | 77 | 6 | 5 | 0 | 165 |
| 75 | web-access-control | 92.3 | Excellent | A | A | 13 | 7 | 103 | 173 | 5 | 5 | 0 | 45 |
| 76 | 5g-6g-telecom-attack-advanced | 91.5 | Excellent | A | A | 10 | 1 | 44 | 17 | 7 | 6 | 0 | 9 |
| 77 | edge-computing-security | 91.5 | Excellent | A | A | 13 | 1 | 45 | 11 | 8 | 6 | 0 | 6 |
| 78 | digital-forensics | 91.1 | Excellent | A | A | 10 | 6 | 89 | 9 | 3 | 5 | 0 | 108 |
| 79 | pentest-reporting | 91.1 | Excellent | A | A | 10 | 4 | 58 | 11 | 4 | 5 | 0 | 89 |
| 80 | terminal-ops | 91.1 | Excellent | A | A | 10 | 6 | 85 | 13 | 1 | 4 | 0 | 151 |
| 81 | voip-sip-attack | 91.1 | Excellent | A | A | 12 | 4 | 68 | 6 | 5 | 5 | 0 | 29 |
| 82 | command-injection-advanced | 90.0 | Excellent | A | A | 10 | 5 | 76 | 18 | 4 | 5 | 0 | 9 |
| 83 | engagement-manager | 89.8 | Excellent | A | A | 10 | 4 | 89 | 10 | 0 | 5 | 0 | 92 |
| 84 | eu-ai-act-compliance-redteam | 89.8 | Excellent | A | A | 10 | 2 | 54 | 11 | 0 | 5 | 0 | 9 |
| 85 | game-anticheat-bypass | 89.5 | Excellent | A | B | 12 | 2 | 48 | 10 | 4 | 12 | 0 | 0 |
| 86 | pqc-implementation-attack | 89.5 | Excellent | A | A | 10 | 2 | 43 | 18 | 0 | 5 | 0 | 13 |
| 87 | ad-ldap-attack | 89.2 | Excellent | A | B | 10 | 4 | 62 | 23 | 4 | 2 | 0 | 50 |
| 88 | agentic-pentest | 89.2 | Excellent | A | B | 12 | 4 | 99 | 41 | 6 | 3 | 0 | 31 |
| 89 | ai-agent-security | 89.2 | Excellent | A | B | 12 | 3 | 91 | 59 | 2 | 3 | 0 | 56 |
| 90 | av-edr-evasion | 89.2 | Excellent | A | B | 10 | 10 | 143 | 114 | 8 | 2 | 0 | 87 |
| 91 | darkweb-intel | 89.2 | Excellent | A | B | 12 | 8 | 113 | 184 | 3 | 3 | 0 | 78 |
| 92 | hsm-attack | 89.2 | Excellent | A | B | 26 | 3 | 73 | 17 | 5 | 3 | 0 | 40 |
| 93 | iot-pentest | 89.2 | Excellent | A | B | 12 | 3 | 67 | 51 | 4 | 3 | 0 | 122 |
| 94 | open-banking-attack | 89.2 | Excellent | A | B | 29 | 3 | 71 | 57 | 1 | 3 | 0 | 62 |
| 95 | password-attack | 89.2 | Excellent | A | B | 12 | 8 | 85 | 28 | 4 | 2 | 0 | 98 |
| 96 | physical-security-testing | 88.0 | Excellent | A | B | 12 | 2 | 130 | 18 | 0 | 3 | 0 | 33 |
| 97 | council | 87.7 | Excellent | A | A | 10 | 8 | 181 | 25 | 2 | 5 | 0 | 2 |
| 98 | protocol-state-exploitation | 87.2 | Excellent | A | A | 10 | 5 | 67 | 10 | 4 | 5 | 0 | 4 |
| 99 | ai-agent-supply-chain-attack | 86.9 | Excellent | A | B | 10 | 2 | 52 | 16 | 2 | 2 | 0 | 6 |
| 100 | bluetooth-rfid-nfc | 86.2 | Excellent | A | B | 10 | 4 | 73 | 16 | 5 | 1 | 0 | 52 |
| 101 | email-protocol-attack | 86.2 | Excellent | A | B | 10 | 4 | 45 | 65 | 8 | 1 | 0 | 39 |
| 102 | hardware-side-channel-advanced | 86.2 | Excellent | A | A | 10 | 1 | 42 | 10 | 8 | 5 | 0 | 0 |
| 103 | payment-security | 86.2 | Excellent | A | B | 13 | 3 | 68 | 43 | 4 | 1 | 0 | 41 |
| 104 | scada-ics-security | 86.2 | Excellent | A | B | 10 | 8 | 103 | 33 | 6 | 1 | 0 | 268 |
| 105 | search-first | 86.2 | Excellent | A | B | 10 | 6 | 83 | 33 | 7 | 1 | 0 | 86 |
| 106 | social-engineering | 86.2 | Excellent | A | B | 10 | 6 | 72 | 54 | 0 | 1 | 0 | 133 |
| 107 | web-deserialization | 86.2 | Excellent | A | B | 10 | 6 | 93 | 101 | 20 | 1 | 0 | 136 |
| 108 | web-sqli | 86.2 | Excellent | A | B | 14 | 16 | 206 | 43 | 5 | 1 | 0 | 16 |
| 109 | web-ssrf | 86.2 | Excellent | A | B | 11 | 7 | 93 | 318 | 3 | 1 | 0 | 63 |
| 110 | web-xss | 86.2 | Excellent | A | B | 10 | 9 | 135 | 168 | 5 | 1 | 0 | 37 |
| 111 | concurrency-exploitation | 83.7 | Excellent | A | A | 10 | 5 | 72 | 9 | 2 | 5 | 0 | 5 |
| 112 | continuous-learning | 83.7 | Excellent | A | A | 9 | 6 | 115 | 10 | 0 | 1 | 0 | 82 |
| 113 | ai-safety-redteam-advanced | 83.1 | Excellent | A | B | 12 | 2 | 64 | 13 | 6 | 3 | 0 | 1 |
| 114 | article-writing | 83.1 | Excellent | A | B | 8 | 9 | 251 | 31 | 3 | 0 | 0 | 101 |
| 115 | autonomous-loops | 83.1 | Excellent | A | B | 10 | 9 | 115 | 30 | 0 | 0 | 0 | 160 |
| 116 | data-scraper-agent | 83.1 | Excellent | A | B | 10 | 6 | 98 | 59 | 2 | 0 | 0 | 49 |
| 117 | docker-patterns | 83.1 | Excellent | A | B | 10 | 6 | 81 | 27 | 5 | 0 | 0 | 76 |
| 118 | mcp-server-patterns | 83.1 | Excellent | A | B | 8 | 6 | 85 | 14 | 4 | 0 | 0 | 48 |
| 119 | verification-loop | 83.1 | Excellent | A | B | 8 | 9 | 135 | 108 | 1 | 0 | 0 | 163 |
| 120 | safety-guard | 81.8 | Excellent | A | B | 8 | 6 | 84 | 15 | 0 | 0 | 0 | 52 |
| 121 | ci-cd-supply-chain-attack | 81.5 | Excellent | C | B | 12 | 6 | 114 | 151 | 10 | 6 | 1 | 129 |
| 122 | cloud-security | 81.5 | Excellent | C | A | 11 | 9 | 103 | 85 | 5 | 7 | 2 | 167 |
| 123 | deception-honeypot | 81.5 | Excellent | C | A | 12 | 3 | 68 | 56 | 4 | 16 | 1 | 130 |
| 124 | embedded-rtos-security | 81.5 | Excellent | C | A | 12 | 6 | 105 | 71 | 57 | 30 | 2 | 127 |
| 125 | payload-generation | 81.5 | Excellent | C | B | 10 | 9 | 107 | 78 | 3 | 8 | 1 | 200 |
| 126 | steganography | 81.5 | Excellent | C | B | 10 | 6 | 82 | 15 | 4 | 6 | 1 | 222 |
| 127 | threat-hunting | 81.5 | Excellent | C | B | 12 | 3 | 90 | 30 | 0 | 46 | 1 | 63 |
| 128 | uav-drone-security | 81.5 | Excellent | C | B | 12 | 2 | 50 | 23 | 1 | 12 | 1 | 185 |
| 129 | browser-qa | 80.8 | Excellent | A | B | 10 | 6 | 90 | 19 | 3 | 0 | 0 | 1 |
| 130 | multi-agent-collaboration | 80.6 | Excellent | A | B | 8 | 6 | 81 | 10 | 1 | 0 | 0 | 17 |
| 131 | hardware-security | 78.5 | Good | C | B | 10 | 6 | 93 | 20 | 4 | 5 | 2 | 157 |
| 132 | mobile-security | 78.5 | Good | C | A | 10 | 6 | 79 | 65 | 4 | 5 | 1 | 77 |
| 133 | security-review | 78.5 | Good | C | A | 10 | 6 | 91 | 50 | 2 | 5 | 1 | 78 |
| 134 | social-intelligence | 78.5 | Good | C | A | 10 | 9 | 115 | 153 | 0 | 5 | 1 | 67 |
| 135 | chronicle | 78.2 | Good | A | A | 8 | 6 | 100 | 6 | 0 | 0 | 0 | 104 |
| 136 | knowledge-ops | 78.2 | Good | A | B | 8 | 6 | 121 | 5 | 2 | 0 | 0 | 132 |
| 137 | codebase-onboarding | 75.7 | Good | A | B | 10 | 6 | 85 | 5 | 0 | 0 | 0 | 82 |
| 138 | email-security-deep | 75.4 | Good | C | B | 12 | 4 | 98 | 106 | 2 | 3 | 1 | 92 |
| 139 | identity-provider-attack | 72.3 | Good | A | B | 10 | 1 | 34 | 5 | 6 | 1 | 0 | 0 |

## 6. Findings Register

- **automotive-vehicle-security**: 15 placeholder markers
- **ci-cd-supply-chain-attack**: 1 bash-block syntax errors
- **cloud-security**: 2 bash-block syntax errors
- **deception-honeypot**: 1 bash-block syntax errors
- **email-security-deep**: 1 bash-block syntax errors
- **embedded-rtos-security**: 2 bash-block syntax errors
- **hardware-security**: 2 bash-block syntax errors
- **mobile-security**: 1 bash-block syntax errors
- **payload-generation**: 1 bash-block syntax errors
- **security-review**: 1 bash-block syntax errors
- **social-intelligence**: 1 bash-block syntax errors
- **steganography**: 1 bash-block syntax errors
- **threat-hunting**: 1 bash-block syntax errors
- **uav-drone-security**: 1 bash-block syntax errors

## 7. Reproduce

```bash
python3 validation/check-skill-usability.py --ranking docs/SKILL_VALIDATION_RANKING_$(date +%F).md
```
