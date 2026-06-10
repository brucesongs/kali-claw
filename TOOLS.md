# TOOLS.md - Local Tool Notes

Skills define _how_ tools work. This file records _your_ specific configuration and quick reference.

---

## Environment

- **OS**: Kali Linux 2025-2
- **Kernel**: 6.18.12+kali-arm64
- **Architecture**: aarch64 (ARM64)

---

## Core Tools (Mastered)

| Category | Tools | Status |
|----------|-------|--------|
| Reconnaissance | nmap, dig, whois, whatweb, wpscan, gobuster, theHarvester, sublist3r, assetfinder, dirb, zenmap | ✅ |
| Web Security | sqlmap, burpsuite, hydra | ✅ |
| Post-Exploitation | msfconsole (Metasploit) | ✅ |
| Binary Analysis | radare2 (Expert level) | ✅ |

---

## Category Index

> Full tool inventory (518 tools / 65 categories) see `docs/tools/full-inventory.md`

| Category | Tool Count | Status | Learning Notes |
|----------|------------|--------|----------------|
| recon-osint | 28 | Mastered | memory/photon.md, memory/dirb.md, etc. |
| osint | 12 | Mastered | skills/osint/SKILL.md |
| web-xss | 8 | Mastered | skills/web-xss/guides/ |
| web-sqli | 6 | Mastered | skills/web-sqli/guides/ |
| web-ssrf | 5 | Mastered | skills/web-ssrf/SKILL.md |
| web-auth-bypass | 6 | Mastered | skills/web-auth-bypass/SKILL.md |
| web-access-control | 5 | Mastered | skills/web-access-control/SKILL.md |
| api-security | 7 | Mastered | skills/api-security/SKILL.md |
| network-pentest | 15 | Mastered | memory/tshark.md, memory/bettercap.md |
| post-exploitation | 11 | Mastered | memory/2026-03-21-post-exploitation-tools.md |
| password-attack | 10 | Mastered | memory/2026-03-21-password-attack-tools.md |
| wifi-pentest | 17 | Mastered | memory/wifi-cracking-course.md |
| binary-reverse | 4 | Expert-level | binary_analysis/ |
| cloud-security | 8 | Mastered | guides/cloud_security_complete_guide.md |
| container-security | 6 | Mastered | skills/container-security/SKILL.md |
| crypto-attacks | 5 | Mastered | skills/crypto-attacks/SKILL.md |
| digital-forensics | 7 | Mastered | skills/digital-forensics/SKILL.md |
| insecure-design | 3 | Mastered | skills/insecure-design/SKILL.md |
| logging-monitoring | 4 | Mastered | skills/logging-monitoring/SKILL.md |
| mobile-security | 6 | Mastered | guides/mobile_security_complete_guide.md |
| security-misconfiguration | 5 | Mastered | skills/security-misconfiguration/SKILL.md |
| social-engineering | 4 | Mastered | memory/2026-03-21-social-engineering-tools.md |
| supply-chain-security | 5 | Mastered | skills/supply-chain-security/SKILL.md |
| vulnerability-assessment | 6 | Mastered | skills/vulnerability-assessment/SKILL.md |
| security-bounty-hunter | 4 | Mastered | skills/security-bounty-hunter/SKILL.md |
| social-intelligence | 6 | Mastered | skills/social-intelligence/SKILL.md |
| deep-research | 8 | Mastered | skills/deep-research/SKILL.md |
| codebase-onboarding | 5 | Mastered | skills/codebase-onboarding/SKILL.md |
| knowledge-ops | 3 | Mastered | skills/knowledge-ops/SKILL.md |
| article-writing | 4 | Mastered | skills/article-writing/SKILL.md |
| browser-qa | 2 | Mastered | skills/browser-qa/SKILL.md |
| data-scraper-agent | 4 | Mastered | skills/data-scraper-agent/SKILL.md |
| exa-search | 1 | Mastered | skills/exa-search/SKILL.md |
| ai-fuzzing | 4 | Mastered | skills/ai-fuzzing/SKILL.md |
| ai-security | 3 | Mastered | skills/ai-security/SKILL.md |
| council | 2 | Mastered | skills/council/SKILL.md |
| security-review | 5 | Mastered | skills/security-review/SKILL.md |
| repo-scan | 4 | Mastered | skills/repo-scan/SKILL.md |
| terminal-ops | 3 | Mastered | skills/terminal-ops/SKILL.md |
| verification-loop | 3 | Mastered | skills/verification-loop/SKILL.md |
| docker-patterns | 5 | Mastered | skills/docker-patterns/SKILL.md |
| search-first | 3 | Mastered | skills/search-first/SKILL.md |
| autonomous-loops | 2 | Mastered | skills/autonomous-loops/SKILL.md |
| safety-guard | 2 | Mastered | skills/safety-guard/SKILL.md |
| chronicle | 2 | Mastered | skills/chronicle/SKILL.md |
| continuous-learning | 3 | Mastered | skills/continuous-learning/SKILL.md |
| hardware-security | 4 | Mastered | skills/hardware-security/SKILL.md |
| multi-agent-collaboration | 3 | Mastered | skills/multi-agent-collaboration/SKILL.md |
| mcp-server-patterns | 3 | Mastered | skills/mcp-server-patterns/SKILL.md |
| engagement-manager | 7 | Mastered | skills/engagement-manager/SKILL.md |
| tool-mastery | 518 | Mastered | skills/tool-mastery/SKILL.md |
| network-sniffing-mitm | 9 | Mastered | skills/network-sniffing-mitm/SKILL.md |
| privilege-escalation | 8 | Mastered | skills/privilege-escalation/SKILL.md |
| exploit-development | 8 | Mastered | skills/exploit-development/SKILL.md |
| payload-generation | 7 | Mastered | skills/payload-generation/SKILL.md |
| av-edr-evasion | 7 | Mastered | skills/av-edr-evasion/SKILL.md |
| dns-attacks | 8 | Mastered | skills/dns-attacks/SKILL.md |
| web-xxe | 6 | Mastered | skills/web-xxe/SKILL.md |
| file-inclusion | 6 | Mastered | skills/file-inclusion/SKILL.md |
| cms-framework-attack | 7 | Mastered | skills/cms-framework-attack/SKILL.md |
| steganography | 6 | Mastered | skills/steganography/SKILL.md |
| bluetooth-rfid-nfc | 13 | Mastered | skills/bluetooth-rfid-nfc/SKILL.md |
| network-tunneling-proxy | 10 | Mastered | skills/network-tunneling-proxy/SKILL.md |
| firmware-reverse | 9 | Mastered | skills/firmware-reverse/SKILL.md |
| scada-ics-security | 8 | Mastered | skills/scada-ics-security/SKILL.md |
| database-attack | 8 | Mastered | skills/database-attack/SKILL.md |
| voip-sip-attack | 8 | Mastered | skills/voip-sip-attack/SKILL.md |
| anti-forensics | 7 | Mastered | skills/anti-forensics/SKILL.md |
| pentest-reporting | 7 | Mastered | skills/pentest-reporting/SKILL.md |
| ad-ldap-attack | 15 | Mastered | skills/ad-ldap-attack/SKILL.md |
| web-deserialization | 6 | Mastered | skills/web-deserialization/SKILL.md |
| email-protocol-attack | 8 | Mastered | skills/email-protocol-attack/SKILL.md |

---

## Learning Strategy

### Current Phase
All 518 tools mastered across 70 skill domains. Current focus: quality consolidation (70/70 Excellent), new skill domain development, engagement orchestration, and cross-skill scenario execution.

### Continuous Improvement
- Cross-skill composite attack chain practice
- Real-world scenario validation on authorized targets
- Scoring system v2: guide quality metrics and depth differentiation
- Tool proficiency deepening through engagement-driven practice

### Methodology
1. Attack chain integration: practice tools in realistic multi-step scenarios
2. Scenario-driven learning: design kill chain scenarios that exercise multiple tools
3. Knowledge sharing: distill engagement insights into skill guides and MEMORY.md

---

_Last updated: 2026-06-10_
