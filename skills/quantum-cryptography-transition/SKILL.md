---
name: quantum-cryptography-transition
description: "Post-Quantum Cryptography (PQC) transition security covering NIST standards (ML-KEM, ML-DSA, SLH-DSA), hybrid TLS weaknesses, Quantum Key Distribution (QKD) attacks, HNDL (Harvest Now, Decrypt Later), and migration vulnerability windows."
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
  domain: crypto
  category: pqc
  tool_count: 7
  guide_count: 0
  mitre: "TA0048-Crypto Attack; emerging quantum-specific"
  last_reviewed: "2026-07-26"
  keywords: ["PQC", "post-quantum", "ML-KEM", "ML-DSA", "Kyber", "Dilithium", "QKD", "HNDL", "quantum"]
---

# Skill: quantum-cryptography-transition

## Summary

Post-Quantum Cryptography (PQC) transition security covering NIST standards (ML-KEM, ML-DSA, SLH-DSA), hybrid TLS weaknesses, Quantum Key Distribution (QKD) attacks, HNDL (Harvest Now, Decrypt Later), and migration vulnerability windows.

**Tools**: garak, PyRIT, promptfoo, custom harnesses

**Domain**: crypto

**MITRE**: TA0048-Crypto Attack; emerging quantum-specific

## Description

Post-Quantum Cryptography (PQC) transition security covering NIST standards (ML-KEM, ML-DSA, SLH-DSA), hybrid TLS weaknesses, Quantum Key Distribution (QKD) attacks, HNDL (Harvest Now, Decrypt Later), and migration vulnerability windows.

This skill covers the offensive side of pqc security, including reconnaissance, vulnerability discovery, exploitation, persistence, and reporting. Aligned with OWASP Top 10, MITRE ATT&CK, and industry-specific compliance frameworks.

---

## Use Cases

1. **HNDL risk assessment**: Identify traffic vulnerable to "Harvest Now, Decrypt Later" (long-lived encrypted data).
2. **PQC migration audit**: Verify organization's PQC readiness per CNSA 2.0 / ANSSI guidelines.
3. **Hybrid TLS analysis**: Identify weak combiners (XOR vs HKDF) in hybrid PQC implementations.
4. **QKD security assessment**: Test QKD deployments for detector blinding, PNS attacks.
5. **Side-channel on PQC**: Test Kyber/Dilithium implementations for RowHammer, EM, timing.

---

## Core Tools

| **OQS (Open Quantum Safe)** | PQC library + OpenSSL provider | `openssl3 -provider oqsprovider` |
| **liboqs** | PQC algorithm C library | Link in custom apps |
| **PQClean** | Reference PQC implementations | Testing reference |
| **Cloudflare PQC test** | Public PQC TLS endpoint | `curl --pqc https://pq.cloudflareresearch.com` |
| **Google Chrome PQC** | Browser with PQC TLS | `chrome --enable-features=PqExperiment` |
| **Wireshark** | PQC TLS analysis | Decode PQC handshakes |

---

## Methodology

### Attack Chain

```
[1] Reconnaissance        [2] HNDL Capture          [3] PQC Migration Audit
  - TLS version             - Record encrypted traffic  - Hybrid combiner check
  - Algorithm negotiation     - Long-lived secrets       - Side-channel potential
  - PQC support               - Asymmetric sessions        |
  - QKD infrastructure          |                          v
        |                        v            [4] Side-channel Attack
        v             [2.5] Hybrid Analysis   - Kyber RowHammer
[1.5] Algorithm downgrade   - KEM combiner flaws        - Dilithium timing
  - Force classical fallback - PQC implementation bugs     |
  - Exploit weak combiner       |                          v
                                v            [5] Future Quantum Decryption
                          [6] Reporting        - 2030+ cryptographically relevant
                          - Migration roadmap    quantum computer
                          - HNDL risk           - Decrypts HNDL captures
```

**Phase Details**:

1. **Reconnaissance**: Identify TLS versions, algorithm negotiation (TLS 1.3 + PQC), QKD infrastructure.
2. **HNDL Capture**: Passively record encrypted traffic; long-lived secrets vulnerable to future quantum decryption.
3. **PQC Migration Audit**: Verify hybrid implementations; identify weak combiners; check implementation bugs.
4. **Side-channel Attack**: Test Kyber/Dilithium implementations via RowHammer, EM, timing analysis.
5. **Future Quantum Decryption**: When quantum computer available, decrypt HNDL captures.
6. **Reporting**: PQC migration roadmap per CNSA 2.0 / ANSSI guidelines.

### Defense Perspective

| Defense Layer | Measures | Key Points |
|---------------|----------|------------|
| **PQC Algorithm Selection** | NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA) | Use NIST-standardized algorithms; avoid experimental |
| **Hybrid Implementation** | Hybrid classical + PQC; use HKDF combiner (not XOR) | Hybrid provides defense if PQC algorithm is broken |
| **QKD Deployment** | Use only for point-to-point where detector blinding can be detected | QKD has practical limitations; use as defense in depth |
| **Side-channel Protection** | Constant-time implementations; mask PQC operations | PQC algorithms have different side-channel profiles than RSA/ECC |
| **HNDL Mitigation** | Prioritize PQC migration for long-lived secrets (root CAs, long-term archives) | HNDL is real threat for data with >10 year confidentiality requirement |

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

### PQC Migration Audit
- **Hybrid TLS detection**: TLS handshakes using both classical and PQC algorithms; alert on unexpected configurations.
- **Algorithm downgrade**: PQC algorithm downgraded to classical; classical algorithm with weak key.
- **Certificate anomalies**: Certificate chain with mix of RSA/ECDSA and PQC signatures.

### SIEM Detection Rules
- **Splunk SPL**: `index=tls | where tls_version matches "TLSv1.3" AND cipher matches ".*Kyber.*" | stats count by client`
- **Custom monitoring**: TLS handshake analysis for PQC algorithm usage.

## Defense Evasion Techniques

### HNDL/SNDL (Harvest Now, Decrypt Later) Stealth
- **Passive capture only**: Don't trigger any alerts; just record encrypted traffic.
- **Long-term storage**: Store encrypted traffic indefinitely; wait for quantum computer availability.
- **Distribute storage**: Spread storage across multiple systems; reduces per-system anomaly.

### Hybrid PQC Downgrade
- **Force classical fallback**: If server supports both classical and PQC, force classical via manipulation.
- **Exploit KEM combiner flaws**: Some hybrid implementations use weak combiner (XOR vs HKDF).
- **Side-channel on Kyber**: RowHammer / EM / timing attacks on Kyber implementation.

### QKD (Quantum Key Distribution) Attack
- **Detector blinding**: Blind single-photon detector; forces predictable response.
- **Photon-number-splitting (PNS)**: Exploit weak coherent photon source.
- **Trusted node compromise**: QKD networks with trusted nodes; compromise node to break key exchange.

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

