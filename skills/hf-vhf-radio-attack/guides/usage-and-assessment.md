# hf-vhf-radio-attack — Usage Instructions & Capability Assessment

> **Assessment Date**: 2026-08-09 | **Reviewer**: Claude (automated + human review) | **Version**: v0.2.0.2
> **Overall Score**: **71/100 (Good)** | **Findings**: P0:0 P1:1 P2:2 P3:1
> **Wave 1 Batch 1** (3rd SKILL assessed)

## Quick Assessment Dashboard

| Dimension | Score (1-5) | Rationale |
|-----------|-------------|-----------|
| 1. Compliance | **5** | 0 errors / 0 warnings / 0 findings |
| 2. Content Completeness | **5** | payloads 3434 lines + test-cases 204 lines + 2 guides; 14 H2 + 28 H3 |
| 3. Command Syntax (theory-heavy) | **3** | 0/10 commands executable on VM (SDR hardware dep); static review shows 2 tools don't exist (dnp3-info pattern not applicable; specific check needed) |
| 4. References | **1** | **0 URLs + 0 CVEs** — major gap |
| 5. MITRE/OWASP Alignment | **3** | 5 ATT&CK T-codes in body (T1499/T1557/T1580/T1592/T1595); frontmatter mitre only T1557 (5 of 5 missing) |
| 6. Usability | **4** | Strong domain coverage (ADS-B/AIS/ACARS/POCSAG/APRS); hardware requirements make hands-on difficult |
| **Weighted Total** | **71/100** | **Good** — needs URL references urgently |

## Usage Instructions

### What this SKILL does
HF/VHF radio frequency attack skill — covers ADS-B (aircraft tracking), AIS (maritime), ACARS (aviation messaging), POCSAG (pager), APRS (amateur radio packet). Requires SDR hardware (HackRF/RTL-SDR/bladeRF).

### When to use it
1. Aviation security research (ADS-B spoofing, ACARS interception)
2. Maritime domain awareness (AIS spoofing, ship tracking evasion)
3. Pager network security testing (POCSAG decoding)
4. Amateur radio / APRS security review
5. RF-layer incident response (RF interference source hunting)

### How to start
1. **Verify SDR hardware**: `hackrf_info` or `rtl_test` (need HackRF One or RTL-SDR dongle)
2. **Install SDR stack**: `apt install hackrf gqrx-sdr gnuradio dump1090-mutability`
3. **Test ADS-B reception**: `dump1090 --net` (will show aircraft within ~100km)
4. **Capture AIS**: `rtlais -r 162000000 -s 96000 -g 40 -d 0` (need marine VHF antenna)
5. **Decode POCSAG**: `rtl_fm -f 157.9e6 -s 22050 | multimon-ng -t raw -a POCSAG512 -`

### Common pitfalls
- **SDR frequency accuracy**: RTL-SDR has ±50ppm drift; need `rtl_epp -p 1` calibration
- **Antenna matters more than SDR**: stock whip antennas are useless for ADS-B; need 1090 MHz specialist
- **Legal**: transmitting without license is illegal in most jurisdictions; this SKILL covers reception + analysis + (where licensed) transmission
- **GNURadio learning curve**: consider GQRX GUI before raw GNURadio flowgraphs

### Cross-references
- `sdr-rf-attack` (broader SDR, including cellular) — switch when targeting cellular/5G
- `bluetooth-rfid-nfc` (close-range RF) — switch for BLE/NFC
- `satellite-leo-security` (LEO satellites) — switch for Starlink/Iridium
- `automotive-vehicle-security` (EV V2G via HomePlug) — for EV charging attacks

## Capability Assessment Detail

### D1: 5/5 (perfect compliance)

### D2: 5/5 (most detailed payloads in corpus — 3434 lines)

### D3: 3/5
- **Method**: 10 SDR commands tested; all require hardware not present on Kali VM
- **Static review**: command syntax correct; tool references valid (hackrf/dump1090/multimon-ng all real tools)
- **Tool availability on VM**: 0/10 (all SDR tools missing by default)
- **Note**: theory-only SKILL by nature; D3 score reflects inability to validate runtime, not command errors
- **Evidence**: [evidence/2026-08-09/summary.md](../evidence/2026-08-09/summary.md)

### D4: 1/5
- **0 URLs + 0 CVEs** in SKILL.md — critical gap (F-001)
- Should reference: ICAO Annex 10 (ADS-B standards), ITU-R M.1371 (AIS), POCSAG specification, APRS standard

### D5: 3/5
- 5 ATT&CK T-codes in body; frontmatter `mitre: "T1557-Adversary-in-the-Middle"` only captures 1 of 5
- Should expand to T1499 Endpoint Denial of Service (RF jamming), T1580 Cloud Infrastructure Discovery (if aviation cloud), T1592 Gather Victim Host Info, T1595 Active Scanning

### D6: 4/5
- **Strengths**: protocol-specific deep dive (ADS-B / AIS / ACARS / POCSAG / APRS all separate sections)
- **Weaknesses**: no quick-start for SDR newbies; assumes HackRF/RTL-SDR familiarity

## Findings & Priorities

| ID | Priority | Description | Recommended Fix |
|----|----------|-------------|-----------------|
| F-001 | **P1** | 0 URLs in SKILL.md | Add: ICAO Annex 10 Vol III (ADS-B), ITU-R M.1371-5 (AIS), POCSAG spec (EDS-9300), APRS 1.0.1 spec, HackRF wiki |
| F-002 | P2 | No CVE references despite known aviation/maritime RF incidents | Reference: 2012 Iran-US RQ-170 ADS-B spoofing, 2013 AIS ghost ships research (U of Texas) |
| F-003 | P2 | Frontmatter mitre field too narrow (1 of 5 T-codes) | Expand to `"T1499-Endpoint Denial of Service, T1557-Adversary-in-the-Middle, T1580-Cloud Infrastructure Discovery, T1592-Gather Victim Host Info, T1595-Active Scanning"` |
| F-004 | P3 | Test cases thin (204 lines vs 3434 payload lines) | Add ≥10 test cases covering each protocol |

## Validation Evidence

- [evidence/2026-08-09/summary.md](../evidence/2026-08-09/summary.md)
- [evidence/2026-08-09/lint.json](../evidence/2026-08-09/lint.json)
- Kali VM: parallels@10.211.55.5 (Kali 2026.1, aarch64)

## Reviewer Sign-off
- Reviewer: Claude (Wave 1 Batch 1, SKILL 1/5)
- Approved by: _______________ Date: _______
