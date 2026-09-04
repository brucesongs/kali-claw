---
name: 5g-6g-telecom-attack-advanced
description: "Advanced 5G/6G telecom attacks covering 5G Core (SBA) exploitation, IMSI catcher evolution (5G Stingray), SIP/Diameter protocol attacks, Open RAN vulnerabilities, network slicing abuse, and early 6G research vectors (THz comms, AI-native air interface)."
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
  domain: telecom
  category: telecom-advanced
  tool_count: 7
  guide_count: 0
  mitre: "TA0001-Initial Access, T1557-Adversary-in-the-Middle"
  last_reviewed: "2026-09-04"
  keywords: ["5G Core", "SBA", "IMSI catcher", "Diameter", "SIP", "Open RAN", "network slicing", "6G"]
---

# Skill: 5g-6g-telecom-attack-advanced

## Summary

Advanced 5G/6G telecom attacks covering 5G Core (SBA) exploitation, IMSI catcher evolution (5G Stingray), SIP/Diameter protocol attacks, Open RAN vulnerabilities, network slicing abuse, and early 6G research vectors (THz comms, AI-native air interface).

**Tools**: garak, PyRIT, promptfoo, custom harnesses

**Domain**: telecom

**MITRE**: TA0001-Initial Access, T1557-Adversary-in-the-Middle

## Description

Advanced 5G/6G telecom attacks covering 5G Core (SBA) exploitation, IMSI catcher evolution (5G Stingray), SIP/Diameter protocol attacks, Open RAN vulnerabilities, network slicing abuse, and early 6G research vectors (THz comms, AI-native air interface).

This skill covers the offensive side of telecom-advanced security, including reconnaissance, vulnerability discovery, exploitation, persistence, and reporting. Aligned with OWASP Top 10, MITRE ATT&CK, and industry-specific compliance frameworks.

---

## Use Cases

1. **5G Core (SBA) exploitation**: Abuse NF (Network Function) APIs for unauthorized access.
2. **IMSI catcher evolution**: 5G Stingray that forces fallback to 4G/3G for SUPI disclosure.
3. **SIP/Diameter attacks**: Signaling attacks via Diameter/SIP protocols.
4. **Open RAN vulnerabilities**: Exploit O-RAN fronthaul splits for RAN compromise.
5. **Network slicing abuse**: Escape network slice isolation.
6. **6G research**: Early attack research on THz communications, AI-native air interface.

---

## Core Tools

| **srsRAN** | Open-source 5G RAN + Core | `srsran-enb` / `srsran-gnb` |
| **Open5GS** | Open-source 5G Core | `open5gs-pgwd` |
| **sipp** | SIP/Diameter testing | `sipp -sf scenario.xml` |
| **WireShark** | Protocol analysis | Decode 5G protocols |
| **Py Crate** | Protocol testing | `pycrate_diameter.py` |
| **Scapy** | Custom protocol crafting | `send(IP()/UDP()/Diameter())` |
| **HackRF** | SDR for radio attacks | `hackrf_transfer` |

---

## Methodology

### Attack Chain

```
[1] Reconnaissance         [2] Signaling Attack      [3] Core Exploitation
  - PLMN identification      - Diameter relay            - NF API abuse
  - UE attachment              - SIP REGISTER flood         - Cross-slice access
  - NF discovery              - SMS interception             - AUSF bypass
  - Slice mapping               |                            |
        |                        v                            v
        v             [2.5] Radio Attack       [4] Persistence
[1.5] IMSI catcher      - 5G Stingray             - Rogue NF
  - Force fallback        - IMSI disclosure          - Persistent slice
  - SUCI bypass           - TMSI tracking              |
  - SUPI extraction         |                          v
                            v            [5] Reporting
                          [4] Persistence   - Signaling audit
                          - Rogue base      - Slice compromise
                          - Persistent radio - Regulatory impact
```

### Defense Perspective

| Defense Layer | Measures | Key Points |
|---------------|----------|------------|
| **SUCI Protection** | Mandatory SUCI (Subscription Concealed Identifier) for privacy; strong ECIES encryption | 5G improves over 4G IMSI; deploy properly |
| **NF API Security** | Mutual TLS between NFs; OAuth2 for SBI; strict API allowlist | SBA architecture exposes APIs; protect each |
| **Diameter Firewall** | Message filtering; STP signaling firewall; route validation | Diameter is SS7 successor; protect accordingly |
| **Slice Isolation** | Per-slice NF; per-slice QoS; per-slice security policy | Slice is tenant boundary; enforce isolation |
| **Open RAN Security** | Encrypt fronthaul; authenticate O-RAN components; harden near-RT RIC | O-RAN introduces new attack surface; secure supply chain |
| **Core Network Isolation** | 5G Core in private network; only N6 (internet) interface exposed | Reduce attack surface; core not directly internet-facing |

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

### 5G Core (SBA) Detection
- **SBI anomaly detection**: Northbound API requests from unexpected Network Functions (NF); abnormal requester-respondent patterns.
- **Diameter/SIP signaling storms**: Signaling rate exceeding baseline.
- **AUSF/UDM anomaly**: Authentication vector requests for inactive IMSIs.

### Radio Access Network (RAN) Indicators
- **IMSI Catcher signatures**: Tracking Area Update (TAU) storms; cells with same PLMN but unusual TAC.
- **Rogue gNodeB**: Cell ID not in operator database; tracking area code mismatch.

### SIEM / Probe Detection
- **5G probe**: Active probes for traffic analysis; detect signaling storms.
- **Splunk SPL (telecom probe)**: `index=5g sourcetype=diameter | stats count by calling_party | where count > 1000`

## Defense Evasion Techniques

### IMSSI Catcher Stealth
- **5G Stingray improvements**: 5G uses SUPI (concealed via SUCI); attackers force fallback to 4G/3G.
- **Downlink-only operation**: Receive-only IMSSI catchers don't page subscribers; harder to detect.
- **Burst operation**: Operate for short windows (<30 seconds) to avoid drive-by detection.

### Signaling Attack Stealth
- **Slow & low**: Pace attacks below signaling firewall threshold.
- **Distributed source**: Spread attacks across multiple signaling partners.
- **Use compromised roaming partners**: Route through legitimate roaming STPs.

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

