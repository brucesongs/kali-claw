# Skill: Logging & Monitoring Security

> **Supplementary Files**:
> - `payloads.md` — Complete attack payload collection covering log injection, evasion, SIEM bypass, audit tampering, WAF flooding, and more
> - `test-cases.md` — Structured test cases categorized by log injection, log evasion, monitoring blind spots, and detection bypass with severity ratings

## Description

Security logging and monitoring deficiencies (OWASP A09:2021) refer to applications failing to properly record security events or lacking effective monitoring, resulting in attacks going undetected, malicious activities being untraceable, and security incidents being impossible to investigate. In environments without adequate logging and monitoring, attackers canlurk for extended periods without detection, and data breaches may go unnoticed for months.

**Core Attack Surfaces**:

- **Log Blind Spots**: Critical events such as failed logins, access control violations, and input validation failures are not recorded, rendering attacker actions completely invisible.
- **Log Injection**: Attackers inject newline characters (`\n`), control characters, or forged log entries to plant fake audit records in logs, misleading security analysts or covering up real attack traces.
- **Log Tampering**: Logs that are not centrally stored and lack integrity protection can be modified or deleted by attackers, destroying the credibility of the audit trail.
- **Monitoring Gaps**: Even when logs exist, without real-time alerting, attacks such as brute forcing, credential stuffing, and privilege escalation can continue indefinitely without triggering any response.
- **SIEM Configuration Deficiencies**: Inconsistent log formats, incomplete data collection, and missing correlation rules render SIEM systems ineffective.

**Defense Dimensions**: Centralized log collection, tamper-proof storage (WORM / hash chain), standardized log formats (JSON + timestamp + correlation ID), real-time alerting thresholds, automated anomaly detection, and regular log audits.

---

## Use Cases

1. **Log Coverage Assessment**: Systematically review whether the application records all security-critical events (authentication, authorization, data access, administrative operations), identifying log blind spots.
2. **Log Injection Penetration Testing**: Verify the logging system's ability to handle malicious input, testing attack vectors such as newline injection, CRLF injection, control character injection, and forged log levels.
3. **SIEM Rule Development and Optimization**: Write detection rules for centralized logging platforms, covering brute force detection, anomalous behavior identification, lateral movement detection, and data exfiltration alerting.
4. **Audit Trail Analysis and Incident Reconstruction**: After a security incident, reconstruct the complete attack process by analyzing timelines, correlating multi-source logs, and tracing attack chains.
5. **Tamper-Proof Log Architecture Design**: Design log storage solutions that meet compliance requirements (PCI-DSS / GDPR / SOC 2), ensuring audit record integrity and non-repudiation.

---

## Core Tools

| Tool | Purpose | Command/Usage Example |
|------|---------|----------------------|
| **ELK Stack** (Elasticsearch + Logstash + Kibana) | Centralized log collection, full-text search, visual analysis | Logstash pipeline parses logs -> Elasticsearch indexes -> Kibana Dashboard displays |
| **Splunk** | Enterprise SIEM, real-time search analysis, correlation detection, alerting | `index=web sourcetype=access_log status=403 \| stats count by src_ip` |
| **Wazuh** | Open-source SIEM + HIDS, file integrity monitoring, rootkit detection, compliance auditing | Agent collection -> Manager analysis -> Elasticsearch storage |
| **OSSEC** | Host-based intrusion detection, log analysis, file integrity checking, active response | `/var/ossec/bin/ossec-control start`; `local_rules.xml` custom rules |
| **auditd** | Linux kernel-level auditing framework, syscall monitoring, file access logging | `auditctl -a exit,always -F arch=b64 -S open -F path=/etc/shadow` |
| **Zeek** (Bro) | Network traffic analysis, protocol parsing, anomalous connection detection, DNS query logging | Passive traffic monitoring -> auto-generates connection/DNS/HTTP/SSL logs |

Supporting tools: **Fluentd** (log collection and forwarding), **Grafana** (monitoring visualization), **Suricata** (IDS alert logging), **journalctl** (systemd log querying), **jq** (JSON log parsing).

---

## Methodology

### Attack Chain

```
[1] Log Discovery           [2] Log Injection           [3] Log Evasion
  - Log storage location      - CRLF / newline injection  - Clear/modify log files
    probing                    - Forge log levels/         - Log rotation exploitation
  - Log format reversing       timestamps                - Noise injection to
  - Collection path            - Control character         overwhelm traces
    tracing                      injection                - Timestamp forgery
  - SIEM rule inference        - Encoding bypass
       |                        sanitization               |
       v                        v                           v
[4] Audit Trail Tampering   [5] Persistentlurking
  - Delete log entries         - Long-term low-frequency
  - Overwrite log files          operations
  - Tamper correlation ID      - Blend into normal traffic
  - Timeline break forgery       baseline
                               - Exploit log retention
                                 policy expiration
                               - Continue exploiting
                                 monitoring blind spots
```

**Key Principle**: The attacker's primary goal is to make the security team "unable to see" or "see incorrectly" — either the logs don't exist, or the logs are untrustworthy.

### Defense Perspective

| Defense Layer | Measure | Key Points |
|---------------|---------|------------|
| **Centralized Logging** | All system logs aggregated to SIEM platform | Eliminates single-point storage, prevents in-place tampering by attackers |
| **Tamper-Proof Storage** | WORM storage, hash chain, remote syslog (TLS) | Ensures logs cannot be modified after writing, meeting compliance requirements |
| **Standardized Format** | JSON format + required fields (timestamp, level, user, ip, action) | Unified format is a prerequisite for automated analysis and correlation detection |
| **Real-Time Alerting** | Brute force thresholds, anomalous behavior baselines, instant notification for critical operations | 5 failed logins within 5 minutes = suspicious; 30 = confirmed attack |
| **Log Integrity Verification** | Regular hash checks, off-site backups, log signing | Detect any tampering attempts, ensure audit trail credibility |
| **Automated Analysis** | SIEM correlation rules, UEBA user behavior analysis, ML anomaly detection | Manual review is not scalable; automated detection is the only viable path |

---

## Practical Steps

### 1. Log Injection Testing

CRLF injection, newline injection, control character injection, and log sanitization testing.

### 2. Log Coverage Assessment

Systematically check whether login events, access control, input validation, cryptographic operations, permission changes, sensitive data access, administrative operations, session management, and other critical events are fully recorded.

### 3. SIEM Rule Development

Splunk SPL brute force detection, ELK lateral movement detection, Wazuh anomalous file access rules, auditd privileged command monitoring.

### 4. Audit Trail Analysis

Event timeline reconstruction, log integrity verification, common tampering indicator identification.

### 5. Incident Response Automation

fail2ban configuration, real-time alerting channels.

> **Detailed payloads in `payloads.md`, complete test checklist in `test-cases.md`.**

---

## Hacker Laws

- **Trust but Verify**: The core value of logging systems is providing verifiable audit records. But logs themselves can be forged or tampered with, so integrity verification mechanisms are needed. Security teams cannot assume log contents are absolutely trustworthy — verifying log integrity is as important as analyzing log content.
- **Assume Breach**: The design premise of security monitoring should be "attackers are already inside the system." Under this assumption, the role of logging and monitoring is to reduce detection time (MTTD) and response time (MTTR), not to prevent initial compromise. Key metric: industry average detection time is 200+ days; the target should be compressed to within 24 hours.
- **Murphy's Security Law**: If logs are not centrally collected and analyzed, then attacks will definitely occur on unmonitored systems. Blind spots in log coverage are the paths most likely to be exploited by attackers — and they will be exploited.

---

## Learning Resources

- **OWASP Logging Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html (Logging best practices)
- **MITRE ATT&CK - Defense Evasion: Indicator Removal**: https://attack.mitre.org/techniques/T1070/ (Log tampering attack techniques)
- **NIST SP 800-92 - Guide to Computer Security Log Management**: https://csrc.nist.gov/publications/detail/sp/800-92/final (Log management framework)
- **SANS - SIEM Implementation Roadmap**: https://www.sans.org/white-papers/ (SIEM deployment methodology)
- **Wazuh Documentation**: https://documentation.wazuh.com/ (Open-source SIEM deployment guide)
- **Elastic Security Labs**: https://www.elastic.co/security-labs (Threat hunting and detection engineering)

**This skill's supplementary files**: payloads.md, test-cases.md
**Related skills**: skills/security-misconfiguration/SKILL.md, skills/vulnerability-assessment/SKILL.md
**External resources**: OWASP Logging Cheat Sheet, MITRE ATT&CK T1070, NIST SP 800-92, SANS SIEM Roadmap, Wazuh Docs, Elastic Security Labs
