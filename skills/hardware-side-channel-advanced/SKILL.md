---
name: hardware-side-channel-advanced
description: "Advanced hardware side-channel attacks covering power analysis (SPA/DPA), electromagnetic emanation, timing attacks, cache-timing attacks (Spectre/Meltdown variants), glitching (voltage/clock), optical fault injection, and countermeasure evaluation."
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
  domain: hardware
  category: side-channel
  tool_count: 7
  guide_count: 0
  mitre: "T1041-Physical Attacks; emerging hardware-specific"
  last_reviewed: "2026-07-26"
  keywords: ["SPA", "DPA", "EM", "timing", "Spectre", "Meltdown", "glitching", "fault injection"]
---

# Skill: hardware-side-channel-advanced

## Summary

Advanced hardware side-channel attacks covering power analysis (SPA/DPA), electromagnetic emanation, timing attacks, cache-timing attacks (Spectre/Meltdown variants), glitching (voltage/clock), optical fault injection, and countermeasure evaluation.

**Tools**: garak, PyRIT, promptfoo, custom harnesses

**Domain**: hardware

**MITRE**: T1041-Physical Attacks; emerging hardware-specific

## Description

Advanced hardware side-channel attacks covering power analysis (SPA/DPA), electromagnetic emanation, timing attacks, cache-timing attacks (Spectre/Meltdown variants), glitching (voltage/clock), optical fault injection, and countermeasure evaluation.

This skill covers the offensive side of side-channel security, including reconnaissance, vulnerability discovery, exploitation, persistence, and reporting. Aligned with OWASP Top 10, MITRE ATT&CK, and industry-specific compliance frameworks.

---

## Use Cases

1. **Smart card / HSM key extraction**: Recover AES/RSA keys via power analysis.
2. **SGX enclave attack**: Steal secrets from Intel SGX enclaves via cache-timing.
3. **Glitching for code execution**: Bypass secure boot via voltage glitch.
4. **Side-channel evaluation**: Assess hardware countermeasures (masking, hiding, dual-rail).
5. **Optical fault injection**: Inject faults via laser for Differential Fault Analysis (DFA).

---

## Core Tools

| **ChipWhisperer** | Power analysis / glitching | `chipwhisperer-capture` |
| **glitchcat** | Glitching framework | Various hardware |
| **sgax** | SGX attack framework | SGX side-channel |
| **Inspector** | SCA tool (Riscure) | Commercial |
| **Picoscope** | Oscilloscope for power analysis | Hardware |
| **H-Probe** | EM probe | Hardware |
| **Laser FI Station** | Optical fault injection | Hardware |

---

## Methodology

### Attack Chain

```
[1] Reconnaissance        [2] Side-channel Setup     [3] Trace Acquisition
  - Identify chip            - Power measurement       - 10K-1M traces
  - Clock frequency            - EM probe placement      - Triggered on crypto op
  - Power supply             - Glitch injection            |
  - Physical access            |                          v
        |                       v            [4] Statistical Analysis
        v             [2.5] Trigger Setup   - DPA / CPA
[1.5] Countermeasure   - Crypto operation   - Template attacks
  - Masking              identification        - Machine learning
  - Hiding                 |                      |
  - Random delay           v                      v
                          [5] Key Recovery   [6] Reporting
                          - AES key bits    - Countermeasure evaluation
                          - RSA private     - Practical impact
                          - ECC scalar
```

### Defense Perspective

| Defense Layer | Measures | Key Points |
|---------------|----------|------------|
| **Masking** | Randomize intermediate values; first-order / higher-order masking | Masking breaks correlation between power and data |
| **Hiding** | Make power consumption constant (dual-rail logic); randomize execution order | Hiding reduces signal-to-noise ratio |
| **Noise Injection** | Add random noise to power supply; dummy operations | Increases traces needed for attack |
| **Physical Tamper Detection** | Anti-tamper mesh; light sensors; voltage monitors | Detect physical access attempts |
| **Secure Boot** | Verify firmware signature; prevent downgrade | Blocks exploit persistence |
| **Constant-time Implementation** | Avoid data-dependent branches; avoid data-dependent memory access | Defeats timing attacks |
| **Cache Partitioning** | Per-process cache; CAT (Cache Allocation Technology) | Defeats cache-timing attacks |

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

### Hardware Attack Indicators
- **JTAG/SWD access**: Debug interface activity on production hardware.
- **Glitch detection**: Voltage/clock glitching signatures in power monitoring.
- **Side-channel anomalies**: Unusual power consumption patterns during crypto operations.
- **Physical tamper**: Anti-tamper mesh break; chassis intrusion switch activation.

### SIEM Detection Rules
- **Splunk SPL (IoT)**: `index=iot event_type="jtag_access" | stats count by device_id`
- **Hardware security modules (HSM)**: Audit log monitoring for tamper events.
- **TPM measurements**: Verify boot measurements against golden baseline.

## Defense Evasion Techniques

### Physical Exploitation Stealth
- **Non-invasive attacks first**: Use power/clock glitching before invasive (decapping); preserves device.
- **Laser fault injection**: Use IR laser through backside of die; minimal physical evidence.
- **Cold boot attacks**: Freeze RAM to preserve keys; minimal trace.
- **Glitch detection bypass**: Find devices without glitch detectors (older models).

### Side-Channel Stealth
- **Tolerated side-channels**: Use Spectre/Meltdown variant that's "tolerated" (allowed by design).
- **Slow acquisition**: Pace power analysis over long period; reduces pattern detection.
- **Cross-device averaging**: Use multiple identical devices; average noise to recover key.

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

