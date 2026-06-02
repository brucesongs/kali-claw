# SCEN-003: Social Engineering + Internal Network Penetration

| Field | Value |
|-------|-------|
| **ID** | SCEN-003 |
| **Name** | Social Engineering + Internal Network Penetration |
| **Type** | Attack Chain (Social + Network) |
| **Kill Chain Phase** | Social Engineering → Initial Access → Credential Harvesting → Lateral Movement → Forensic Analysis |
| **Difficulty** | Advanced |
| **Estimated Duration** | 5-8 hours |

---

## Objective

Demonstrate a social engineering-driven attack chain where initial access is obtained through human interaction techniques, followed by network penetration and concluded with forensic analysis of the attack artifacts.

---

## Skill Chain

```
social-engineering → social-intelligence → password-attack → network-pentest → digital-forensics
```

| Step | Skill Domain | Key Actions | Tools |
|------|-------------|-------------|-------|
| 1 | social-intelligence | Target profiling: social media analysis, organizational chart, technology stack | maltego, sherlock, spiderfoot |
| 2 | social-engineering | Phishing campaign: credential harvest, payload delivery, pretexting scenario | gophish, setoolkit |
| 3 | password-attack | Credential exploitation: hash cracking, password spraying, rule-based attacks | hashcat, john, hydra |
| 4 | network-pentest | Network penetration: scanning, exploitation, lateral movement | nmap, metasploit, crackmapexec |
| 5 | digital-forensics | Forensic analysis: evidence preservation, timeline reconstruction, artifact analysis | autopsy, volatility, sleuth-kit |

---

## Prerequisites

- Authorized phishing simulation scope (written approval from target organization)
- Isolated test network for lateral movement exercises
- Forensic workstation with analysis tools
- Incident response team notified of exercise

---

## Execution Steps

### Phase 1: Target Profiling (social-intelligence)

1. Social media OSINT: `sherlock target_username`
2. Organizational intelligence: LinkedIn, GitHub, company website analysis
3. Email format discovery: `hunter.io` or `emailharvester`
4. Technology stack identification from public sources
5. Build target profile with role, interests, and technical skill level

### Phase 2: Social Engineering Campaign (social-engineering)

1. Design phishing template based on target profile
2. Set up credential harvesting: `gophish` campaign configuration
3. Create pretext scenario aligned with target's role/interests
4. Launch campaign with tracking pixels and click monitoring
5. Document engagement rates and credential capture

### Phase 3: Credential Exploitation (password-attack)

1. Analyze captured credentials against password policies
2. If hashes obtained: `hashcat -m 1000 hashes.txt rockyou.txt`
3. Password spraying with common passwords: `hydra -l user -P common.txt target`
4. Rule-based attacks for password variations
5. Credential stuffing across discovered services

### Phase 4: Network Penetration (network-pentest)

1. Initial access using valid credentials from Phase 3
2. Internal network scanning: `nmap -sn 192.168.0.0/24`
3. Service enumeration on discovered hosts
4. Lateral movement via pass-the-hash or credential reuse
5. Document all paths and access levels achieved

### Phase 5: Forensic Analysis (digital-forensics)

1. Preserve evidence: create disk images, capture network traffic
2. Memory forensics: `volatility -f memory.dmp windows.processlist`
3. Timeline reconstruction of the entire attack chain
4. Artifact analysis: browser history, email artifacts, log analysis
5. Generate forensic report linking all phases

---

## Verification Points

- [ ] Target profile comprehensive with actionable intelligence
- [ ] Phishing campaign metrics: open rate, click rate, credential capture rate
- [ ] At least one set of valid credentials obtained through the chain
- [ ] Network penetration path documented with screenshots
- [ ] Forensic timeline correlates all attack phases with timestamps

---

## Data Handoff Between Skills

| From | To | Data Format |
|------|----|-------------|
| social-intelligence | social-engineering | Target profile, email addresses, technology stack |
| social-engineering | password-attack | Captured credentials/hashes, email patterns |
| password-attack | network-pentest | Valid username/password pairs, hash types |
| network-pentest | digital-forensics | Attack timeline, compromised hosts, access paths |

---

## Ethical Boundaries

- Only target pre-approved individuals within the authorized scope
- No actual malware deployment — use benign payloads for tracking
- All credential data must be securely handled and deleted after exercise
- Forensic analysis focuses on attack reconstruction, not victim data
- Full disclosure to participants after exercise completion
