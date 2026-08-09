# automotive-vehicle-security — Usage Instructions & Capability Assessment

> **Assessment Date**: 2026-08-09 | **Reviewer**: Claude (automated + human review) | **Version**: v0.2.0.2
> **Overall Score**: **75/100 (Good)** | **Findings**: P0:0 P1:1 P2:2 P3:1
> **Wave 1 Batch 1** (5th SKILL assessed) | v0.2.3.2 sampling: 4.5/5 (was)

## Quick Assessment Dashboard

| Dimension | Score (1-5) | Rationale |
|-----------|-------------|-----------|
| 1. Compliance | **5** | 0/0/0 |
| 2. Content Completeness | **5** | payloads 2608 + test-cases 256 + **8 guides** (highest in batch); 13 H2 + 20 H3 |
| 3. Command Syntax | **2** | 0/10 commands executable (all CAN/GNSS/PKES hardware-dependent); CAN tools not even installed |
| 4. References | **2** | 3 URLs + 0 CVEs — limited |
| 5. MITRE/OWASP Alignment | **4** | 3 ATT&CK T-codes (T1530/T1557/T1557.001); frontmatter has TA0001+TA0040+T1557 (reasonable) |
| 6. Usability | **5** | v0.2.4 P2 fix restructured Defense Perspective into 3 categories (Regulatory/In-vehicle/External); 8 guides is benchmark |
| **Weighted Total** | **75/100** | **Good** — but D3/D4 bring score down despite excellent content |

## Usage Instructions

### What this SKILL does
Vehicle cybersecurity testing covering CAN/CAN-FD, LIN, FlexRay, automotive Ethernet, UDS diagnostics, OTA updates, PKES (Passive Keyless Entry), EV V2G charging. Maps to UNECE R155/R156 and ISO/SAE 21434.

### When to use it
1. OEM type approval compliance (UNECE R155/R156 mandatory since 2022-07)
2. Tier-1 supplier audit (e.g., Bosch/Continental delivering ECU to OEM)
3. Penetration testing fleet vehicles
4. Automotive Cybersecurity Management System (CSMS) implementation
5. V2X / connected car security research

### How to start
1. **Hardware prep**: CAN adapter (PCAN-USB/Kvaser/vector VN1630), OBD-II cable, optionally JTAGulator for ECU debug
2. **CAN baseline**: `candump -L can0` to monitor traffic; `isotpsend` for UDS
3. **Identify ECU topology**: use UDS service 0x22 (ReadDataByIdentifier) for ECUID
4. **Recon threats**: scan UDS services 0x10 (session control), 0x27 (security access), 0x31 (routine control)
5. **Map to ISO 21434 TARA**: document each finding with threat scenario + risk rating

### Common pitfalls
- **CAN arbitration IDs are not security boundary**: any ECU can transmit any ID
- **UDS 0x27 security access**: brute-force protected by per-ECU delay; but seed/key algorithm often reverse-engineerable
- **PKES relay attacks**: Time-of-Flight ranging (UWB 802.15.4z) is the modern defense
- **OTA updates**: TCU (Telematics Control Unit) is the typical entry; verify SBOM and signature validation
- **Physical safety**: NEVER test brake/steering ECUs on moving vehicles without controlled test track

### Cross-references
- `ics-fieldbus-attack` (CAN-adjacent: CANopen, Devicenet) — switch for industrial CAN
- `embedded-rtos-security` — switch when targeting ECU OS (AUTOSAR Classic on RTOS)
- `hardware-security` — switch for JTAG/UART ECU debug
- `physical-security-testing` — switch for vehicle physical access
- `sdr-rf-attack` — switch for GNSS spoofing / V2G wireless

## Capability Assessment Detail

### D1: 5/5 | D2: 5/5 (8 guides is the benchmark for guide-rich SKILLs)

### D3: 2/5
- **0/10 commands PASS** (all hardware-dependent; CAN tools not installed)
- **Tool availability on VM**: can-utils ✗, python-can ✗, cantools ✗, isotpsend ✗
- **Static review**: command syntax correct for tools referenced
- **Note**: theory-heavy SKILL by nature; D3 reflects inability to execute + thin installable coverage
- **Evidence**: [evidence/2026-08-09/summary.md](../evidence/2026-08-09/summary.md)

### D4: 2/5
- Only 3 URLs (Auto-ISAC + UNECE + ISO/SAE 21434 — important ones but few)
- **0 CVEs** despite major automotive incidents (Tesla CVE-2017-3527, BMW 2018, Jeep Cherokee 2015)
- Should reference: CVE-2019-9568 (Tesla), Miller/Valasek Jeep research, KEEN LAB BMW research

### D5: 4/5
- 3 ATT&CK T-codes (T1530 Data from Config Repositories, T1557 Adversary-in-the-Middle, T1557.001 LLMNR/NBT-NS)
- Frontmatter: `TA0001-Initial Access, TA0040-Detection, T1557-Adversary-in-the-Middle` — reasonable but body content touches more techniques (T1548 Abuse Elevation via UDS, T1529 System Shutdown via ECU denial)

### D6: 5/5
- **Strengths**:
  - 8 guides (highest in Wave 1) — comprehensive coverage
  - v0.2.4 P2 fix restructured Defense Perspective into 3 categories (Regulatory/In-vehicle/External Interface)
  - Cross-references to法规 (UNECE R155/R156, ISO/SAE 21434, SAE J3061) are accurate
  - Section on HSM (EVITA HSM light/medium/full) is industry-leading clarity
- Benchmark for other automotive / regulated-domain SKILLs

## Findings & Priorities

| ID | Priority | Description | Recommended Fix |
|----|----------|-------------|-----------------|
| F-001 | **P1** | 0 CVE references despite major automotive incidents | Add: Jeep Cherokee (Miller/Valasek 2015, CVE-2015-5611), Tesla (KEEN Lab 2016, CVE-2016-9117), BMW (KEEN Lab 2018), Tesla Mode 3 (2022) |
| F-002 | P2 | CAN tools not in Kali 2026.1 default | Add `apt install can-utils` + `pip install python-can cantools` to payloads |
| F-003 | P2 | Only 3 URLs in SKILL.md | Add: Auto-ISAC, NHTSA cybersecurity, ENISA connected vehicles, ISO 21434 standards portal |
| F-004 | P3 | Test cases thin (256 lines vs 2608 payload lines) | Add ≥10 cases with hardware-specific preconditions |

## Validation Evidence

- [evidence/2026-08-09/summary.md](../evidence/2026-08-09/summary.md)
- [evidence/2026-08-09/lint.json](../evidence/2026-08-09/lint.json)
- Kali VM: parallels@10.211.55.5 (Kali 2026.1, aarch64)

## Reviewer Sign-off
- Reviewer: Claude (Wave 1 Batch 1, SKILL 3/5)
- Approved by: _______________ Date: _______
