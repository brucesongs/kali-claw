# SCEN-001: Enterprise External Network Penetration Full Chain

| Field | Value |
|-------|-------|
| **ID** | SCEN-001 |
| **Name** | Enterprise External Network Penetration Full Chain |
| **Type** | Attack Chain (Red Team) |
| **Kill Chain Phase** | Reconnaissance → Initial Access → Execution → Persistence → Lateral Movement |
| **Difficulty** | Advanced |
| **Estimated Duration** | 4-6 hours |

---

## Objective

Execute a full external penetration test against an authorized enterprise target, progressing from passive reconnaissance through initial compromise to post-exploitation, demonstrating skill composition across 5+ domains.

---

## Skill Chain

```
recon-osint → network-pentest → web-xss/web-sqli → web-auth-bypass → post-exploitation
```

| Step | Skill Domain | Key Actions | Tools |
|------|-------------|-------------|-------|
| 1 | recon-osint | Passive recon: subdomain enumeration, technology fingerprinting, email harvesting | subfinder, amass, whatweb, theHarvester |
| 2 | network-pentest | Active scanning: port discovery, service identification, vulnerability scanning | nmap, masscan, nuclei |
| 3 | web-xss / web-sqli | Web application attack: identify injection points, exploit SQLi or XSS | sqlmap, burpsuite, dalfox |
| 4 | web-auth-bypass | Authentication bypass: session hijacking, credential brute force, OAuth exploitation | hydra, burpsuite |
| 5 | post-exploitation | Persistence + lateral movement: establish backdoor, escalate privileges, pivot | metasploit, crackmapexec, chisel |

---

## Prerequisites

- Authorized target with signed ROE (Rules of Engagement)
- Kali Linux environment with all tools configured
- Target scope definition (IP ranges, domains, excluded systems)
- Communication channel with client for emergency stops

---

## Execution Steps

### Phase 1: Reconnaissance (recon-osint)

1. Subdomain enumeration: `subfinder -d target.com -all | sort -u`
2. Technology fingerprinting: `whatweb -v https://target.com`
3. Email harvesting: `theHarvester -d target.com -b all`
4. Document metadata extraction: `metagoofil -d target.com -t pdf,docx`
5. Compile attack surface map

### Phase 2: Network Discovery (network-pentest)

1. Port scan: `nmap -sS -sV -O -p- target_ip`
2. Vulnerability scan: `nuclei -u https://target.com -t cves/`
3. Service-specific enumeration based on discovered ports
4. Prioritize vulnerabilities by CVSS and exploitability

### Phase 3: Web Application Exploitation (web-xss / web-sqli)

1. Identify web attack surface from Phase 2
2. SQL injection testing: `sqlmap -u "https://target.com/page?id=1" --dbs`
3. XSS testing on input fields and URL parameters
4. Document all findings with screenshots and proof

### Phase 4: Authentication Bypass (web-auth-bypass)

1. Test default credentials on discovered services
2. Session token analysis and replay attacks
3. OAuth/JWT token manipulation if applicable
4. Credential stuffing if email/password pairs discovered in Phase 1

### Phase 5: Post-Exploitation (post-exploitation)

1. Establish persistent access (scheduled task, SSH key)
2. Privilege escalation: check kernel version, SUID binaries, sudo misconfigurations
3. Lateral movement: discover internal networks, pivot through compromised host
4. Data exfiltration simulation (mark test files, not real data)

---

## Verification Points

- [ ] Attack surface map complete with all subdomains and services
- [ ] At least one exploitable vulnerability documented with PoC
- [ ] Authentication bypass demonstrated OR documented why not possible
- [ ] Post-exploitation evidence: privilege escalation + lateral movement
- [ ] All findings documented with severity, remediation, and evidence

---

## Data Handoff Between Skills

| From | To | Data Format |
|------|----|-------------|
| recon-osint | network-pentest | Subdomain list, IP ranges, technology stack |
| network-pentest | web-xss/web-sqli | URLs with parameters, service versions |
| web-xss/web-sqli | web-auth-bypass | Session cookies, database credentials |
| web-auth-bypass | post-exploitation | Valid credentials, SSH/RDP access |

---

## Defensive Perspective

For each attack step, document the corresponding defense:

| Attack Step | Defensive Measure | Verification Skill |
|-------------|-------------------|-------------------|
| Subdomain enum | DNS security monitoring | logging-monitoring |
| Vulnerability scan | IDS/IPS detection | security-review |
| SQL injection | WAF rules, parameterized queries | security-review |
| Auth bypass | MFA, rate limiting, account lockout | security-misconfiguration |
| Post-exploitation | EDR, network segmentation | vulnerability-assessment |
