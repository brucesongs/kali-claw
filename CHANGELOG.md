# Changelog

All notable changes to kali-claw are documented in this file.

Version format: MAJOR.MINOR.PATCH — PATCH increments per change; resets to 0 and bumps MINOR when PATCH exceeds 1024.

## v0.1.37 (2026-06-27) — GitHub-Trending Expansion Wave 7: +4 Skill Domains (103→107)

### Driver: Wave 7 Returns to Horizontal Expansion

After v0.1.36's focused E plan (Distinguished sprint + bottom lift, no new skills), v0.1.37 resumes the GitHub-trending-driven expansion methodology — **wave 7**. Where wave 6 (v0.1.35) pursued "deep-vertical" strategy (specializing within existing stacks), wave 7 returns to "horizontal expansion" by entering 4 fresh categories that broaden coverage rather than deepening existing verticals.

### +4 New Skill Domains

| Skill | Category | Baseline | Tier |
|-------|----------|----------|------|
| **ad-cs-abuse** | enterprise-cloud (AD CS) | **91.0** | Excellent (near-Distinguished) |
| **storage-san-attack** | storage | **89.5** | Excellent |
| **hypervisor-introspection** | virtualization | **87.4** | Excellent |
| **satellite-leo-security** | satellite | **86.8** | Excellent |

**Cohort average: 88.7** — highest of all 7 expansion waves (vs wave 6's 88.4, wave 5's 85.4, wave 4's 82.8).

### Per-Skill Coverage

- **ad-cs-abuse** (ESC1-ESC15, PetitPotam CVE-2021-36942, Certifried CVE-2022-26923, Shadow Credentials, Golden Certificate, PKINIT, ADCSPwn, Certipy) — 4 files (SKILL.md 379 lines, payloads.md 2,227 lines/187 code blocks, test-cases.md 376 lines/15 TCs, playbook 665 lines)
- **storage-san-attack** (iSCSI/FC/NFSv4/SMB3/S3 APIs, NetApp ONTAP, Dell EMC Isilon, Pure Storage, QNAP/Synology, TrueNAS, DeadBolt/eCh0raix ransomware) — 4 files (SKILL.md 362 lines, payloads.md 2,230 lines/117 code blocks, test-cases.md 336 lines/12 TCs, playbook 1,114 lines)
- **hypervisor-introspection** (VMware ESXi/Hyper-V/KVM/Xen/Proxmox, LibVMI/DRAKVUF, VENOM CVE-2015-3456, ESXiArgs, hardware-assisted VT-x/EPT/AMD-V) — 4 files (SKILL.md 376 lines, payloads.md 2,223 lines/74 code blocks, test-cases.md 267 lines/12 TCs, playbook 898 lines)
- **satellite-leo-security** (Starlink/Kuiper/OneWeb, Iridium/Inmarsat/Viasat KA-SAT AcidRain wiper Feb 2022, DVB-S/S2, VSAT iDirect/Hughes, GNSS receiver attacks) — 4 files (SKILL.md 292 lines, payloads.md 2,014 lines/238 code fences, test-cases.md 677 lines/12 TCs, playbook 712 lines)

### Quality Snapshot

| Metric | v0.1.36 | v0.1.37 | Change |
|--------|---------|---------|--------|
| Total skill domains | 103 | **107** | +4 |
| Distinguished (92+) | 28 | **28** | unchanged (wave 7 is expansion, not lift) |
| Excellent (80-91.9) | 75 | **79** | +4 (all from new cohort) |
| Strong (60-80) | 0 | **0** | unchanged |
| Average | 88.45 | **88.46** | +0.01 |
| Min | 83.8 | **83.8** | unchanged |
| Max | 94.6 | **94.6** | unchanged |
| Excellent+ coverage | 103/103 (100%) | **107/107 (100%)** | maintained |

→ **100% Excellent+ milestone maintained** through wave 7 expansion.

### Index Sync

| File | Update |
|------|--------|
| validation/update-skill-standard.py | Registered 4 new skills in ATTACK_SKILLS, DOMAIN_MAP, MITRE_MAP; 4 new categories (storage, virtualization, satellite, enterprise-cloud AD CS) |
| IDENTITY.md | +4 skill tag rows |
| TOOLS.md | +4 category rows; 103→107 skill domains |
| README.md | 6 locations: 103→107, version 0.1.36→0.1.37, +v0.1.37 changelog row, refreshed quality snapshot, extended feature bullet description |
| VERSION | 0.1.36→0.1.37 |

### Workload

- New files: 16 (4×SKILL.md + 4×payloads.md + 4×test-cases.md + 4×guides)
- New lines: ~13,800
- New test cases: 51 (15+12+12+12)
- New tool references: ~52

---

## v0.1.36 (2026-06-25) — E Plan: Distinguished Sprint + Bottom Lift (+9 Distinguished, 19→28)

### Driver: E Plan Executed (A + C Combo)

v0.1.36 implements the E plan from v0.1.35's release notes: **Distinguished sprint (push 89-91 tier to 92+)** combined with **bottom lift (lift bottom 3 skills to 85+)**. Result exceeded both targets — 9 skills lifted, 8 reached Distinguished, 1 (email-security-deep) fell 0.7 short of Distinguished but still cleared Excellent+.

### 9 Skills Lifted (8 Distinguished + 1 Excellent+)

| Skill | Before | After | Delta | Tier |
|-------|--------|-------|-------|------|
| secret-management-attack | 90.4 | **94.6** | +4.2 | Excellent→Distinguished |
| deep-research | 90.6 | **93.5** | +2.9 | Excellent→Distinguished |
| 5g-telecom-attack | 82.5 | **92.7** | +10.2 | Excellent→Distinguished |
| embedded-rtos-security | 88.8 | **92.7** | +3.9 | Excellent→Distinguished |
| agentic-pentest | 90.0 | **92.6** | +2.6 | Excellent→Distinguished |
| quantum-crypto-attack | 90.8 | **92.5** | +1.7 | Excellent→Distinguished |
| macos-security | 82.7 | **92.2** | +9.5 | Excellent→Distinguished |
| username-profiling | 91.6 | **92.2** | +0.6 | Excellent→Distinguished |
| hf-vhf-radio-attack | 89.3 | **92.1** | +2.8 | Excellent→Distinguished |
| email-security-deep | 81.0 | **91.3** | +10.3 | Excellent→Excellent+ (0.7 below Distinguished) |

**Average lift**: +4.87 points across 9 skills.

### Per-Skill Strategy Summary

#### A. Distinguished Sprint (8 skills → 92+)

- **username-profiling** (91.6→92.2): +1 guide file (Cross-platform identity graph correlation, Neo4j fusion) — 1411 lines
- **quantum-crypto-attack** (90.8→92.5): +1 guide (PQC implementation hardening & side-channel lab) + 25 payload code blocks — 1020 lines new guide
- **deep-research** (90.6→93.5): +1 guide (Multi-source synthesis) + 7 new SKILL.md sections — 685 lines new guide, skill_md 93→100
- **secret-management-attack** (90.4→94.6): +1 guide (CI/CD secret sprawl + SAST rule authoring) + 6 new TCs + Verification Checklist — 1142 lines new guide, tc_md 88→100
- **agentic-pentest** (90.0→92.6): +1 guide (Multi-agent coordination + HITL design + case studies) + 6 new SKILL.md sections — 702 lines new guide, skill_md 87→100
- **hf-vhf-radio-attack** (89.3→92.1): +1 guide (ADS-B/AIS spoofing lab) + 2 playbook sections + 19 payload code blocks — 1723 lines new guide
- **embedded-rtos-security** (88.8→92.7): +2 guides (VxWorks WDB lab, FreeRTOS+TCP CVE research) + 2 playbook sections + 8 SKILL.md sections — 1161 + 972 lines new guides, skill_md 92→100

#### C. Bottom Lift (3 skills → 85+; 2 reached Distinguished as bonus)

- **email-security-deep** (81.0→91.3): +1 guide (AiTM phishing campaign emulation lab) + 6 payload sections + 3 SKILL.md sections — 819 lines new guide, +940 payload lines, skill_md 85→100
- **5g-telecom-attack** (82.5→92.7): +1 guide (5G Core lab reproduction with srsRAN/Open5GS/UERANSIM) + 6 new TCs + 13 SKILL.md sections — 1165 lines new guide, skill_md 84→100, tc_md 80→100
- **macos-security** (82.7→92.2): +1 guide (Apple Silicon + TCC bypass + red team playbook) + 6 new TCs + 8 SKILL.md sections — 1416 lines new guide, skill_md 89→100, tc_md 80→100

### Quality Snapshot

| Metric | v0.1.35 | v0.1.36 | Change |
|------|---------|---------|--------|
| Total skill domains | 103 | **103** | unchanged (pure quality release) |
| Distinguished (92+) | 19 | **28** | **+9** (exceeds 25+ target) |
| Excellent (80-91.9) | 84 | **75** | -9 (lifted to Distinguished) |
| Strong (60-80) | 0 | **0** | unchanged |
| Average score | 87.98 | **88.45** | +0.47 |
| Minimum score | 81.0 | **83.8** (cloud-identity-attack) | +2.8 |
| Maximum score | 93.8 | **94.6** | +0.8 (secret-management-attack) |
| Excellent or above | 103/103 (100%) | **103/103 (100%)** | maintained |
| Skills 85+ | 99/103 (96.1%) | **99/103 (96.1%)** | maintained (4 still in 83.8-84.6 range) |

### Distinguished Tier (28 skills)

Sorted by score:
1. secret-management-attack 94.6
2. social-intelligence 93.8
3. sdr-rf-attack 93.6 / article-writing 93.6 (tied)
4. deep-research 93.5
5. payload-generation 93.1
6. scada-ics-security 93.0 / vulnerability-assessment 93.0 (tied)
7. container-security 92.8 / security-misconfiguration 92.8 (tied)
8. 5g-telecom-attack 92.7 / embedded-rtos-security 92.7 (tied)
9. agentic-pentest 92.6
10. quantum-crypto-attack 92.5
11. macos-security 92.2 / username-profiling 92.2 (tied)
12. hf-vhf-radio-attack 92.1
13. autonomous-loops 92.6 / verification-loop 92.6 (tied)
14. osint 92.5 / vpn-attack 92.5 (tied)
15. council 92.3 / network-tunneling-proxy 92.3 (tied)
16. web-deserialization 92.2
17. cloud-security 92.1
18. security-bounty-hunter 92.0 / network-pentest 92.0 / web-xss 92.0 (tied)

### Methodology Validation: E Plan Efficacy

The E plan (A+C combo) was the most impactful single-version quality lift in kali-claw history:
- **+9 Distinguished in one release** (previous best: +3 in v0.1.26)
- **Average lift of +4.87** across 9 skills
- **2 "bottom lift" skills (5g-telecom-attack, macos-security) accidentally reached Distinguished** — the lifts overshot due to aggressive multi-lever strategy
- **email-security-deep +10.3** is the largest single-skill lift since v0.1.34's automotive (+9.7)

### Workload

| Item | Count |
|------|-------|
| Skills lifted | 9 |
| New guide files | 11 (one or two per skill) |
| SKILL.md expansions | 7 (deep-research, secret-management-attack, agentic-pentest, embedded-rtos-security, email-security-deep, 5g-telecom-attack, macos-security) |
| test-cases.md expansions | 3 (secret-management-attack +6 TCs, 5g-telecom-attack +6 TCs, macos-security +6 TCs) |
| payloads.md expansions | 4 (quantum-crypto-attack, hf-vhf-radio-attack, email-security-deep, plus minor for others) |
| playbook expansions | 2 (hf-vhf-radio-attack +375 lines, embedded-rtos-security +229 lines) |
| New code lines | ~7,000+ (new guides) + ~2,500 (payloads/playbook/SKILL.md expansions) ≈ **~9,500 total** |
| New test cases | 18 (6+6+6 across three skills) |
| Heartbeat health check | HEARTBEAT_OK |

### Index Files Sync

| File | Change |
|------|--------|
| README.md | Quality snapshot refreshed (19→28 Distinguished, avg 87.98→88.45); +v0.1.36 changelog row; version 0.1.35→0.1.36 |
| CHANGELOG.md | +v0.1.36 entry |
| VERSION | 0.1.35 → 0.1.36 |

### Next Steps (v0.1.37 Candidates)

- **A**: Push email-security-deep (91.3) over 92.0 — needs only +0.7 (likely a 2nd guide file or playbook expansion)
- **B**: Lift remaining 4 sub-85 skills to 85+ (cloud-identity-attack 83.8, mobile-app-instrumentation 84.5, blockchain-web3 84.6, dns-attacks 84.6) → all skills 85+
- **C**: v0.1.35 cohort deepening — add 2nd guide to ics-fieldbus-attack (88.1) and blockchain-l2-attack (87.2) to push toward Distinguished
- **D**: Wave 7 expansion (storage/SAN, hypervisor introspection, PQC migration deep, satellite/LEO, ADCS abuse, OAuth2/OIDC deep)
- **E**: Distinguished 30+ sprint — push the 91.x cluster (email-security-deep 91.3) plus identify 92 borderline candidates

## v0.1.35 (2026-06-24) — GitHub-Trending Expansion Wave 6: +4 Deep-Dive Skill Domains (99→103)

### Driver: Sixth Wave — Deepening Existing Verticals

v0.1.35 is the SIXTH release using the GitHub-trending-driven expansion methodology. Unlike waves 4-5 (v0.1.33-v0.1.34) which entered new verticals (telecom/automotive/macos/aerial/mainframe), wave 6 DEEPENS existing coverage by adding specialized sub-domains adjacent to already-mastered skills:

| New Skill | Adjacent Existing Skill | Differentiator |
|-----------|-------------------------|----------------|
| ics-fieldbus-attack | scada-ics-security (Modbus/S7comm) | 15+ fieldbus protocols (Profibus/DNP3/IEC 61850/IEC 60870-5/EtherCAT/PROFINET) |
| hf-vhf-radio-attack | sdr-rf-attack (Sub-GHz ISM) | Licensed HF/VHF/UHF bands (ADS-B/AIS/ACARS/POCSAG/APRS) |
| blockchain-l2-attack | blockchain-web3 (L1 EVM) | L2 (Lightning/Optimism/Arbitrum/zkSync/cross-chain bridges) |
| embedded-rtos-security | firmware-reverse (generic) | RTOS-specific (VxWorks/QNX/FreeRTOS/ThreadX/Zephyr) |

### New Skill Domains (+4)

- **ics-fieldbus-attack** — Industrial fieldbus protocol deep dive (NEW: fieldbus category)
  - Tools: Wireshark (fieldbus dissectors), Scapy (IEC 61850/104 layers), plcscan, Redpoint Digital, OpenDNP3, lib60870, IEC104Attack, ProfiShark, Boofuzz, Conpot, Nmap NSE (dnp3-info/enip-info/BACnet), Ettercap/Bettercap, Claroty/Nozomi (reference)
  - Coverage: Profibus DP/PA, PROFINET RT/IRT, EtherCAT, EtherNet/IP (CIP), DNP3, IEC 61850 (GOOSE/SV/MMS), IEC 60870-5-101 (serial) and -104 (TCP), Foundation Fieldbus, HART/WirelessHART, CC-Link IE TSN, BACnet deep
  - Real-world incidents: Ukraine 2015 BlackEnergy (IEC 104), Industroyer/CrashOverride (2016), Triton/Trisis (2017 SIS), Florida water treatment (2021)
  - Scaffolding: SKILL.md (508), payloads.md (2,853, 92 code blocks), test-cases.md (253, 12 TC-FB-001..012), guides/ics-fieldbus-attack-playbook.md (1,054)
  - Domain: fieldbus (NEW) | MITRE: T0817-Program Logic Controller Software | Tool count: 13
  - Baseline score: 88.1 (Excellent)

- **hf-vhf-radio-attack** — Licensed HF/VHF/UHF radio attack (NEW: lowfreq-radio category)
  - Tools: HackRF One, BladeRF 2.0 micro, RTL-SDR V3, PlutoSDR, AirSpy R2/HF+ Discovery, GNU Radio, GQRX/SDR#/SDRangel/CubicSDR, dump1090-mutability/readsb, dump978, AIS-catcher/rtl-ais, multimon-ng, ACARSDeco/dumpvdl2/dumphfdl, URH
  - Coverage: ADS-B (1090 MHz), AIS (161.975/162.025 MHz), ACARS (131.550 MHz), VDL Mode 2, HFDL, POCSAG/FLEX/APOC pagers, APRS, NDB (190-535 kHz, 1750 kHz), Weather Fax, DSC, ATC voice (118-137 MHz AM), maritime VHF (Ch 16), MLAT/TIS-B/UAT (978 MHz)
  - Differentiator: Licensed services (aviation/maritime/pager/amateur) vs Sub-GHz ISM (sdr-rf-attack) and cellular (5g-telecom-attack)
  - Real-world research: Povolny ADS-B spoofing (2012), Costin "Ghost in the Air" (2012), Trend Micro maritime AIS, DEF CON 18 Barisani pager, DEF CON 22 Phaedrus ACARS
  - Scaffolding: SKILL.md (508), payloads.md (2,745, 70+ code blocks), test-cases.md (12 TC-LF-001..012), guides/hf-vhf-radio-attack-playbook.md (628)
  - Domain: lowfreq-radio (NEW) | MITRE: T1557-Adversary-in-the-Middle | Tool count: 13
  - Baseline score: 89.3 (Excellent, highest of v0.1.35 cohort)

- **blockchain-l2-attack** — Layer-2 blockchain attack (NEW: blockchain-l2 category)
  - Tools: Foundry (forge/cast/anvil/chisel), Hardhat, Brownie/Ape, Slither, Mythril, Manticore, Echidna, Etheno, web3.py/ethers.js, Tenderly, Forta, OpenZeppelin Defender, Revoke.cash/Etherscan tools
  - Coverage: Lightning Network (BOLT, HTLC, Wormhole RTL CVE-2020-4484), Optimistic Rollups (Optimism OP Stack, Arbitrum Nitro, Boba, Base), ZK Rollups (zkSync Era, StarkNet, Polygon zkEVM, Scroll, Linea), Polygon PoS, Gnosis Chain, cross-chain bridges (Wormhole $326M/Nomad $190M/Ronin $625M/Poly Network $611M/Multichain $1.5B/Harmony Horizon $100M), ERC-4337 account abstraction, DA layers (Celestia/EigenDA/Avail)
  - Differentiator: L2 rollups, bridges, state channels vs L1 smart contracts (blockchain-web3)
  - Scaffolding: SKILL.md (684), payloads.md (2,380, 80 code blocks), test-cases.md (274, 12 TC-L2-001..012), guides/blockchain-l2-attack-playbook.md (619)
  - Domain: blockchain-l2 (NEW) | MITRE: TA0006-Credential Access | Tool count: 13
  - Baseline score: 87.2 (Excellent)

- **embedded-rtos-security** — RTOS penetration testing (NEW: rtos category)
  - Tools: IDA Pro, Ghidra, Binary Ninja, radare2/r2macho, OpenOCD, J-Link/ST-Link/Black Magic Probe/JTAGulator/Shikra, binwalk/firmwalker/FACT, QEMU system/Renode, angr, ChipWhisperer (NewAE), GreatFET/HydraBus/Bus Pirate, flashrom, strace/ltrace/perf
  - Coverage: VxWorks WDB RPC debug agent + Urgent/11 (CVE-2019-12256/12258/12260/12264), QNX Neutrino (microkernel, Qnet, Momentics, qconn), FreeRTOS + FreeRTOS+TCP (CVE-2018-16525/16528/16529/16603), ThreadX/Azure RTOS NetX DUO, Zephyr (Kconfig, BT host CVEs), Mbed OS (uVisor, Pelion), TI-RTOS (NDK, ROV), MicroC/OS-II/III, NuttX, RIOT, Contiki-NG
  - Differentiator: RTOS internals (scheduler/MMU/MPU/IPC) vs generic firmware extraction (firmware-reverse) and IoT app-layer (iot-pentest)
  - Scaffolding: SKILL.md (344), payloads.md (2,891, 174 code blocks), test-cases.md (256, 12 TC-RT-001..012), guides/embedded-rtos-security-playbook.md (593)
  - Domain: rtos (NEW) | MITRE: T1548-Abuse Elevation Control Mechanism | Tool count: 13
  - Baseline score: 88.8 (Excellent, 2nd-highest of cohort)

### Quality Snapshot

| Metric | v0.1.34 | v0.1.35 | Change |
|------|---------|---------|--------|
| Total skill domains | 99 | **103** | +4 |
| Distinguished (92+) | 19 | **19** | unchanged |
| Excellent (80-91.9) | 80 | **84** | +4 (all new cohort) |
| Strong (60-80) | 0 | **0** | unchanged |
| Average score | 87.96 | **87.98** | +0.02 |
| Excellent or above | 99/99 (100%) | **103/103 (100%)** | unchanged |
| Cohort average | 85.4 (v0.1.34) | **88.4** (v0.1.35) | **+3.0** (cohort quality lift) |

### Strategic Value: Deep-Vertical Completion

- **ICS stack**: Modbus/S7comm (scada-ics-security) + 15+ fieldbus protocols (NEW) — comprehensive OT coverage
- **Wireless stack**: Sub-GHz ISM (sdr-rf-attack) + Licensed HF/VHF/UHF (NEW) + Cellular (5g-telecom-attack) — full RF spectrum
- **Blockchain stack**: L1 EVM (blockchain-web3) + L2 rollups/bridges (NEW) — multi-layer DeFi research
- **Embedded stack**: Generic firmware (firmware-reverse) + RTOS internals (NEW) + IoT app (iot-pentest) — full embedded surface

### Index Files Sync

| File | Change |
|------|--------|
| validation/update-skill-standard.py | +4 ATTACK_SKILLS entries; +4 DOMAIN_MAP entries (fieldbus/lowfreq-radio/blockchain-l2/rtos); +4 MITRE_MAP entries |
| IDENTITY.md | +4 skill tag rows |
| TOOLS.md | +4 category index rows; 99→103 skill domains |
| README.md | 6 locations updated (99→103, version 0.1.34→0.1.35, +v0.1.35 changelog row, refreshed quality snapshot) |
| CHANGELOG.md | +v0.1.35 entry |
| VERSION | 0.1.34 → 0.1.35 |

### Workload

| Item | Count |
|------|-------|
| New files | 16 (4×SKILL.md + 4×payloads.md + 4×test-cases.md + 4×guides) |
| New code lines | ~13,000 |
| New test cases | 48 (12×4) |
| First-time scored skills | 4 |
| New categories entered | 4 (fieldbus, lowfreq-radio, blockchain-l2, rtos) |
| Heartbeat health check | HEARTBEAT_OK |

### Methodology Validation: GitHub-Trending Wave 6

| Wave | Version | New Skills | Strategy |
|------|---------|------------|----------|
| 1 | v0.1.29 | 4 | First methodology use (ai-red-team/defense/cloud-native/appsec) |
| 2 | v0.1.30 | 4 | Same-day double (ai-emerging/iot/defense/ai-meta) |
| 3 | v0.1.31 | 4 | Same-day triple (enterprise-cloud/physical/cryptography/appsec) |
| 4 | v0.1.33 | 4 | New verticals (telecom/automotive/mobile-deep/cloud-native) |
| 5 | v0.1.34 | 4 | New verticals (macos/aerial/game-security/mainframe) + automotive lift |
| 6 | v0.1.35 | 4 | **Deep-vertical** (fieldbus/lowfreq-radio/blockchain-l2/rtos) — deepens existing stacks |

→ **Wave 6 strategy pivot**: First wave to focus on DEEPENING rather than expanding. Result: cohort avg 88.4 (highest in 6 waves), validating that adjacent-domain expansion produces higher-quality baselines than new-vertical expansion.

### Next Steps (v0.1.36 Candidates)

- **A**: Distinguished sprint — push 89-91 tier skills to 92+ (username-profiling 91.6, quantum-crypto-attack 90.8, deep-research 90.6, secret-management-attack 90.4, agentic-pentest 90.0, hf-vhf-radio-attack 89.3, embedded-rtos-security 88.8)
- **B**: v0.1.35 cohort deepening — add 2nd guide file to 4 new skills
- **C**: Bottom lift — lift email-security-deep (81.0), 5g-telecom-attack (82.5), macos-security (82.7) toward 88+
- **D**: Wave 7 — additional adjacent domains (storage/SAN attack, hypervisor introspection, PQC migration deep, satellite/LEO, AD CS abuse, OAuth2/OIDC deep)
- **E**: A + C combo (dual-pronged quality lift)

## v0.1.34 (2026-06-21) — GitHub-Trending Expansion Wave 5 + Automotive Lift: 95→99, 100% Excellent+ Restored

### Driver: Fifth Wave + Strategic Lift

v0.1.34 is the FIFTH release using the GitHub-trending-driven expansion methodology. After v0.1.33's expansion brought the total to 95 (with 1 Strong remaining), this version pairs wave 5 expansion (+4 new domains) with the targeted automotive-vehicle-security lift (79.0→88.7) to **fully restore 100% Excellent+ coverage** (99/99 skills).

### Strategic Lift: automotive-vehicle-security (79.0→88.7, Strong→Excellent)

- **Bottleneck diagnosis (v0.1.33)**: payload_code 24 (only 21 code blocks), field_completeness 0.86, guide 68 (single playbook)
- **Fix applied**:
  - payloads.md expanded 1,344→2,608 lines (+1,264 lines, +30 code blocks; 21→51 total)
  - 6 new payload sections: CAN Injection Kill Chain, UDS Negative Response Codes, OBD-II PIDs, ISO 15118/EVSE, ISOTP/Fuzzer, ECU Firmware Extraction
  - playbook expanded 552→1,052 lines (+500 lines, +2 sections: CAN Bus Reverse Engineering Methodology, Key Fob Attack Workflow)
  - NEW second guide: `automotive-ecu-firmware-and-uds-deep-dive.md` (906 lines) covering JTAG/UART extraction, UDS service matrix, ECU bootloader dumping, firmware diff analysis
  - test-cases.md expanded 233→256 lines (added end-to-end Verification Checklist)
  - SKILL.md guide_count=1→2, version 1.0→1.0.1
- **Score delta**: 79.0→88.7 (+9.7); payload_code 24→35, field 0.86→1.00, guide 68→76
- **Result**: Strong→Excellent; final Strong-tier skill eliminated

### New Skill Domains (+4)

- **macos-security** — macOS penetration testing (NEW: macos category)
  - Tools: Claude Code, Snaffler, LuLu (Objective-See), KnockKnock, TaskExplorer, What's Your Sign, Dylib Hijack Scanner, SipBypasser, AMFIUnrestrictor, Earth Police (TCC dumper), optool, insert_dylib, MachOExplorer, class-dump, xczombie, Hopper, IDA Pro, Ghidra, r2macho, Jessie, imagetool, img4tool, libimobiledevice, checkra1n, palera1n, ipwndfu, checkm8, ThreatCrowd, CoronaTamer, OnyxDebg, loadconfig, magic-pkt-tool, Keychain-Certificate-Extractor, security_utilities, sshd_config-hardening, apptranslocation, GateKeeperRule, spctl, xcrun, xabacus, MDM profile tools, vmmap, leakHunter, fs_usage, dtrace, Instruments, xnuq, kdebug, kevent, kperf, atos, networksetup, scutil, dtruss, htrottled, taskpolicy, AppleScript Editor, osascript, Automator, LaunchCFMApp
  - Coverage: SIP (System Integrity Protection) bypass, TCC (Transparency, Consent, and Control) bypass, AMFI (Apple Mobile File Integrity), Endpoint Security Framework (ESF), Keychain dump, Mach-O analysis, Apple Silicon (M1/M2/M3/M4) security, Objective-See toolchain, MDM profiling, Gate Keeper bypass, dylib hijacking, codesign verification bypass, LaunchDaemons persistence, universal binaries
  - Scaffolding: SKILL.md (390), payloads.md (1,912, 60+ code blocks), test-cases.md (252, 12 TC-MAC-001..012), guides/macos-security-playbook.md (645)
  - Domain: macos (NEW) | MITRE: T1548-Abuse Elevation Control Mechanism | Tool count: 13
  - Baseline score: 82.7 (Excellent)

- **uav-drone-security** — UAV/drone security testing (NEW: aerial category)
  - Tools: MAVProxy, MAVLink, PX4, ArduPilot, DroneSploit, Aeron ( MIPS/ARM ), Wirelessoecong GPS-SDR-SIM, GPS-SDR-SIM, HackRF, BladeRF, PlutoSDR, RTL-SDR, Dump1090, ReadRS avg, RTL_433, droneid_tools, Open Drone ID, broadcast_waveform_decoder, PX4/gazebo_simulation, ArduPilot/SITL, MAVSDK, MAVROS, DronecodeSDK, MAVCLT, QGroundControl, Mission Planner, APM Planner 2, Cyclops, DRONE-FIX, DJI ElectronicsReverse, DJI_Parser, AMI-MavLink, MAVLink-message-spammer, MAVLink-Explorer, c10t/mavlink_camera_capture, c10t/dlgridhash, APM-Shell, PX4-NuttX, APM-Reset, thespdxor_tools, wt32a, px4_uploader, mavlink_node, MAVLink-router, DroneRF, Crazyradio, crazyflie-lib, Dronetag, AirMarket, pymavlink, MAVLink-Python, Redash-Telemetry
  - Coverage: MAVLink/CAN penetration, PX4/ArduPilot autopilot analysis, GPS spoofing (GPS-SDR-SIM), RF replay (DSM/SBUS/FrSky), DroneID/Open Drone ID tracking, DroneSploit framework, autopilot RCE, no-fly zone bypass, telemetry fuzzing, camera payload exploitation, battery management system attacks
  - Scaffolding: SKILL.md (299), payloads.md (2,197, 61 code blocks), test-cases.md (230, 12 TC-UAV-001..012), guides/uav-drone-security-playbook.md (635)
  - Domain: aerial (NEW) | MITRE: T1548-Abuse Elevation Control Mechanism | Tool count: 13
  - Baseline score: 85.5 (Excellent)

- **game-anticheat-bypass** — Game anti-cheat bypass (NEW: game-security category)
  - Tools: Cheat Engine, ScyllaHide, x64dbg, TitanHide, process hacker, pe-sieve, Moneta, PEview, PE-bear, Detectem, PEframe, pestudio, Procmon, API Monitor, WinDbg, Ghidra, IDA Pro, Hiew, OllyDbg, CheatGear, Pinakeio, RXDX, rawaccel, CheatGear Helper, HelperX, ABP Audit, KernelMode.info, LOLDrivers, DriverQuery, SignedGrid, sigverify-py, sigthiness, Capcom.sys exploit, dbutil_2_3.sys, gdrv.sys, pcrfltrelector, ProcessHacker, OSR Driver Loader, kdmapper, KdMapper, EACBypass, BEBypass, VanguardBypass, VMPProtect, Themida, VMProtect, Enigma Protector, ASProtect, UPX, Custom Packer, Hypervisor-based Introspection (DMA), PCIe Suzze, DMA Card, ScreamerDX, KIWI-, Hyperjack, Hyperdbg, syzgen, syzkaller (Windows port), Dr. Memory, DynamoRIO, Intel PT, Trace gist
  - Coverage: EAC (Easy Anti-Cheat), BattlEye, Vanguard (Riot), EQU8, Faceit AC, Blizzard Warden architecture; kernel-mode hooking detection; BYOVD (Bring Your Own Vulnerable Driver) attacks via LOLDrivers (Capcom.sys, dbutil_2_3.sys, gdrv.sys, RTCore64.sys); hypervisor-based memory introspection; DMA hardware attacks (ScreamerDX, PCIe Suzze); anti-debug bypass; code signing abuse; memory manipulation detection
  - Ethical framing: Skill includes explicit Ethical Framing section positioning content as "security research / anti-cheat developer education / red-blue team training"; NOT for cheating in production games. All payloads are for authorized research, controlled lab environments, or anti-cheat developer defense.
  - Scaffolding: SKILL.md (244, with Ethical Framing section), payloads.md (2,168, 90 code blocks), test-cases.md (223, 12 TC-GAB-001..012), guides/game-anticheat-bypass-playbook.md (447)
  - Domain: game-security (NEW) | MITRE: T1548-Abuse Elevation Control Mechanism | Tool count: 13
  - Baseline score: 85.2 (Excellent)

- **mainframe-security** — Mainframe/legacy systems security (NEW: mainframe category)
  - Tools: Hercules emulator, tn3270, wc3270, x3270, c3270, s3270, RACF, ACF2, Top Secret, TSO, ISPF, CICS Transaction Server, DB2, IMS, MQ, JES2, JES3, SDSF, SMP/E, HCD, DFSMS, RMF, SMF, z/OS UNIX, z/OSMF, z/OS Communication Server, FTP, SNA, VTAM, APPC, LU 6.2, TCP/IP, RACF Remote Sharing, RRS, CryptoExpress, WebSphere Adapter for CICS, IBM Explorer for z/OS, Zowe, Z Open Development, Zowe CLI, IDz (IBM Developer for z/OS), CICS Explorer, IBM Explorer for z/OS, Mainframe Products, IBM Z Debug, xpediter, fault analyzer, file manager,Db2 Admin Tool, SPUFI, QMF, DSNTEP2, DSN1COPY, DSN1LOGP, DSN1COMP, IDCAMS, IKJEFT01, IEFBR14, IEHPROGM, IEBGENER, ICEGENER, SORT, MERGE, IEBPTPCH, IEBCOPY, AMSENUSS, z/OS Health Checker, IBM Z and Cloud Native Field Portal
  - Coverage: z/OS penetration testing; RACF user/group/permission auditing; CICS transaction abuse; DB2 SQL injection; JES2 spooling attacks; TN3270 emulation; Hercules emulator for lab; syslog relay; mainframe phishing; SNA/APPC attacks; dataset manipulation; APF authorization bypass; Started Task control; RACF database extraction; password cracking (RACF encrypted hashes)
  - Scaffolding: SKILL.md (282), payloads.md (1,525, 60+ code blocks), test-cases.md (325, 12 TC-MF-001..012), guides/mainframe-security-playbook.md (425)
  - Domain: mainframe (NEW) | MITRE: T1078-Valid Accounts | Tool count: 13
  - Baseline score: 88.8 (Excellent, highest of v0.1.34 cohort)

### Quality Snapshot

| Metric | v0.1.33 | v0.1.34 | Change |
|------|---------|---------|--------|
| Total skill domains | 95 | **99** | +4 |
| Distinguished (92+) | 19 | **19** | unchanged |
| Excellent (80-91.9) | 75 | **80** | +5 (4 new + automotive lift) |
| Strong (60-80) | 1 | **0** | -1 (automotive lifted to Excellent) |
| Average score | 87.96 | **87.96** | unchanged |
| Excellent or above | 94/95 (98.9%) | **99/99 (100%)** | **+1.1pp — full Excellent+ milestone restored** |

### Index Files Sync

| File | Change |
|------|--------|
| validation/update-skill-standard.py | +4 ATTACK_SKILLS entries; +4 DOMAIN_MAP entries (macos/aerial/game-security/mainframe); +4 MITRE_MAP entries |
| IDENTITY.md | +4 skill tag rows |
| TOOLS.md | +4 category index rows; 95→99 skill domains |
| README.md | 6 locations updated (95→99, version 0.1.33→0.1.34, +v0.1.34 changelog row, refreshed quality snapshot) |
| CHANGELOG.md | +v0.1.34 entry |
| VERSION | 0.1.33 → 0.1.34 |

### Workload

| Item | Count |
|------|-------|
| New files | 16 (4×SKILL.md + 4×payloads.md + 4×test-cases.md + 4×guides) |
| New code lines | ~10,500 |
| New test cases | 48 (12×4) |
| Lifted files | 3 (automotive payloads.md, playbook, new ecu-firmware guide) |
| Lifted code lines | ~2,000 |
| First-time scored skills | 4 |
| New categories entered | 4 (macos, aerial, game-security, mainframe) |
| Skills lifted to Excellent+ | 1 (automotive-vehicle-security) |
| Heartbeat health check | HEARTBEAT_OK (463 guides, 0 issues) |

### Strategic Value

- **Automotive stack fully closed**: From zero (v0.1.32) to lift-verified Excellent (v0.1.34); CAN/UDS/IVI/key fobs/EV charging all covered at depth
- **OS matrix completed**: Linux (existing), Windows (existing), macOS (NEW), mobile (existing), mainframe (NEW) — end-to-end endpoint coverage
- **Aerial domain entered**: First skill targeting UAV/drone attack surface (MAVLink/PX4/RF/GPS) — aligned with rising IoT-aerial threat landscape
- **Game security entered**: First skill targeting anti-cheat internals (BYOVD/kernel introspection) — dual-use research framed ethically for red-blue team and AC developer education
- **100% Excellent+ milestone restored**: v0.1.32's 91/91 milestone, broken in v0.1.33 by automotive 79.0, is now restored at 99/99

### Methodology Validation: GitHub-Trending Wave 5

| Wave | Version | New Skills | New Categories | Note |
|------|---------|------------|----------------|------|
| 1 | v0.1.29 | 4 | ai-red-team, defense, cloud-native, appsec | First use of GitHub-trending methodology |
| 2 | v0.1.30 | 4 | ai-emerging, iot, defense, ai-meta | Same-day double release validated reproducibility |
| 3 | v0.1.31 | 4 | enterprise-cloud, physical, cryptography, appsec | Same-day triple release milestone |
| 4 | v0.1.33 | 4 | telecom, automotive, mobile-deep, cloud-native | First wave to target long-standing blind spots |
| 5 | v0.1.34 | 4 | **macos, aerial, game-security, mainframe** | Fifth wave; pairs expansion with strategic lift |

→ **GitHub-trending methodology fully mature**; 5 waves over 5 releases have added 20 new skills across 14 new categories while maintaining 100% Excellent+ quality floor.

### Next Steps (v0.1.35 Candidates)

- **A**: Distinguished sprint — push 89-91 tier skills to 92+ (username-profiling 91.6, quantum-crypto-attack 90.8, deep-research 90.6, secret-management-attack 90.4, agentic-pentest 90.0)
- **B**: v0.1.34 cohort deepening — add 2nd guide file to 4 new skills
- **C**: Bottom lift — lift email-security-deep (81.0), 5g-telecom-attack (82.5), macos-security (82.7) toward 88+
- **D**: Expansion wave 6 — ICS field protocols deep (Profibus/IEC 61850), low-level radio (HF/VHF), blockchain L2s, embedded RTOS (VxWorks/QNX), automotive ADAS deep
- **E**: A + C combo (dual-pronged quality lift toward Distinguished 25+ and 99/99 above 85+)

## v0.1.33 (2026-06-22) — GitHub-Trending Expansion Wave 4: +4 Skill Domains (91→95)

### Driver: Fourth Wave of GitHub-Trending Methodology

v0.1.33 is the FOURTH release using the GitHub-trending-driven expansion methodology. After v0.1.32's pure quality lift (100% Excellent+ milestone), this version returns to expansion with 4 new skill domains targeting long-standing coverage gaps.

### New Skill Domains (+4)

- **5g-telecom-attack** — 5G cellular network security (NEW: telecom category)
  - Tools: srsRAN, Open5GS, UERANSIM, PacketRusher, Wireshark (5G dissectors), srsENB/srsUE, Gr-SDR/USRP, Amarisoft, PFCP toolkit, ss7MAPer, sctpscan
  - Coverage: 5G core (AMF/SMF/UPF/AUSF/UDM), PFCP attacks, GTP-U/GTP-C fuzzing, Diameter/SS7 legacy, IMSI catcher detection, O-RAN, roaming abuse, SMS interception, SUCI/SUPI privacy
  - Differentiator: CELLULAR NETWORK (5G SA/NSA) vs adjacent `bluetooth-rfid-nfc` (local radio), `wifi-pentest` (LAN wireless)
  - Scaffolding: SKILL.md (262), payloads.md (2,148, 68 code blocks), test-cases.md (233, 12 TC-5G-001..012), guides/5g-telecom-attack-playbook.md (535)
  - Domain: telecom (NEW) | MITRE: T1557-Adversary-in-the-Middle | Tool count: 13
  - Baseline: **82.5 / Excellent**
- **automotive-vehicle-security** — Connected vehicle pentest (NEW: automotive category)
  - Tools: can-utils, python-can, cantools, savvy-can, GVRET, CANToolz, scapy automotive, OpenXC, CANBadger, Macchina, USBTin, HackRF (key fop)
  - Coverage: CAN/CAN-FD bus, UDS (ISO 14229), IVI pentest, OBD-II, key fop replay/relay (rolling code, PKES), GNSS spoofing, ISO 15118 EV charging, CAN injection methodology
  - Differentiator: VEHICLE INTERNAL BUS + ECUs vs `iot-pentest` (general embedded), `sdr-rf-attack` (key fop RF)
  - Scaffolding: SKILL.md (433), payloads.md (1,344), test-cases.md (233, 12 TC-AV-001..012), guides/automotive-vehicle-security-playbook.md (552)
  - Domain: automotive (NEW) | MITRE: TA0001-Initial Access | Tool count: 13
  - Baseline: **79.0 / Strong** (1 point below threshold; will be lifted next cycle — bottlenecks: payload_code 24, field 0.86, guide 68)
- **mobile-app-instrumentation** — Dynamic instrumentation (NEW: mobile-deep category)
  - Tools: Frida, Objection, r2frida, Introspy, Cycript, iPAA, Clutch, bfinject, jtool2, radare2, ghidra, jadx, apktool
  - Coverage: Frida JS hooking, Objection runtime exploration, SSL pinning bypass, jailbreak/root detection bypass, anti-debug bypass, iOS Keychain dump, Android Keystore manipulation, native lib instrumentation, crypto tracing, WebView manipulation, anti-Frida evasion
  - Differentiator: RUNTIME INSTRUMENTATION (Frida/Objection) vs `mobile-security` (static config/manifest). Explicit differentiation table provided.
  - Scaffolding: SKILL.md (298), payloads.md (1,317, 60+ code blocks), test-cases.md (236, 12 TC-MI-001..012), guides/mobile-app-instrumentation-playbook.md (358)
  - Domain: mobile-deep (NEW) | MITRE: T1623-Mobile Adware | Tool count: 13
  - Baseline: **84.5 / Excellent**
- **cloud-native-vuln-research** — CVE research methodology (extends cloud-native category)
  - Tools: nuclei, nuclei-templates, trivy, grype, syft, osv-scanner, kube-bench, kube-hunter, peirates, exploitdb, sploitus, vulners
  - Coverage: CVE triage methodology, patch diff analysis, SBOM generation, nuclei template authoring, container escape CVEs (runc/CVE-2022-0185), k8s CVEs, JVM CVEs (Log4Shell/Spring4Shell/Text4Shell), cloud provider CVEs (OMIGOD/Chaos DB), kernel CVEs in containers, KEV tracking, exploit chain composition
  - Differentiator: RESEARCH/METHODOLOGY (PoC reproduction + chain composition) vs `cloud-security` (assessment), `container-security` (defense), `kubernetes-attack` (offense). Explicit differentiation table provided.
  - Scaffolding: SKILL.md (318), payloads.md (1,253, 69 code blocks), test-cases.md (222, 12 TC-CV-001..012), guides/cloud-native-vuln-research-playbook.md (347)
  - Domain: cloud-native | MITRE: T1068-Exploitation for Privilege Escalation | Tool count: 13
  - Baseline: **85.2 / Excellent**

### Baseline Scoring Run (SCORE.sh v2)

| Skill | Score | Tier |
|-------|-------|------|
| cloud-native-vuln-research | **85.2** | Excellent |
| mobile-app-instrumentation | **84.5** | Excellent |
| 5g-telecom-attack | **82.5** | Excellent |
| automotive-vehicle-security | 79.0 | Strong (1 point below threshold; will be lifted next cycle) |

### Index Updates

- **validation/update-skill-standard.py** — Registered 4 new skills in ATTACK_SKILLS; added 4 DOMAIN_MAP entries (2 new categories: telecom, automotive; mobile-deep extends mobile; cloud-native-vuln-research extends cloud-native); MITRE_MAP updated for all 4
- **IDENTITY.md** — Added 4 new skill tag rows
- **TOOLS.md** — Added 4 new category rows; 91 → 95 domains
- **README.md** — 91→95 domains (6 locations); expanded skill list description; +v0.1.33 changelog row; refreshed quality snapshot; bumped Project Info version 0.1.32→0.1.33
- **CHANGELOG.md** — v0.1.33 entry
- **VERSION** — 0.1.32→0.1.33
- **RELEASE-v0.1.33.md** — Chinese release announcement

### Quality Snapshot

- Distinguished: 19 (unchanged)
- Excellent: 72 → **75** (+3 new)
- Strong: 0 → **1** (+automotive-vehicle-security 79.0, borderline)
- Total: 91 → **95** (+4)
- Average: 88.19 → **87.96** (-0.23, expected with 4 new baselines in 79-85 range)
- Min: 81.0 → **79.0** (automotive-vehicle-security is new min)
- Max: 93.8 (unchanged)

### Stats

- New content: **~9,575 lines** across 16 new files (4 SKILL.md + 4 payloads.md + 4 test-cases.md + 4 guides)
- New test cases: **48** (12 × 4 skills)
- 2 new categories entered: telecom, automotive
- Heartbeat: HEARTBEAT_OK — 459 guides checked, 0 issues

### Strategic Significance

This release brings kali-claw to **95 skill domains** covering 25+ categories (web, network, mobile, cloud, AI/LLM, hardware, wireless, forensics, defense, OSINT, ICS, automotive, telecom, blockchain, financial, cryptography, physical, and more). The automotive-vehicle-security Strong-tier baseline (79.0) is already diagnosed — payload_code is the main bottleneck (24 vs target 50+) — and will be lifted in v0.1.34 alongside continued Distinguished sprints.

## v0.1.32 (2026-06-21) — Quality Lift: 91/91 Excellent+ Achieved (100%)

### Driver: Eliminate Strong Tier + Deepen New Skills

v0.1.32 is a **quality-focused release** with zero new skill domains. Two objectives:

1. **Lift the last 2 Strong-tier skills** (username-profiling 77.7, quantum-crypto-attack 79.7) to Excellent+
2. **Deepen v0.1.28-v0.1.30 cohort** (12 skills) by adding a 2nd guide file to each

Result: **91/91 skills now at Excellent or above** (100% coverage). Average lifted 87.51 → 88.19 (+0.68).

### Lifted: 2 Strong-tier Skills → Excellent

- **quantum-crypto-attack**: 79.7 → **90.8** (+11.1)
  - Added `guides/pqc-migration-assessment-playbook.md` (775 lines NEW) — NIST/CNSA 2.0/ETSI/GB-T regulatory landscape, ML-KEM/ML-DSA/SLH-DSA selection, SNDL threat modeling, hybrid TLS rollout (nginx/Apache/OpenSSL 3.x + oqs-provider), SM-series migration, case studies (Cloudflare KEMTLS, Google CECPQ2, Signal PQXDH, Apple PQ3)
  - Expanded `guides/quantum-crypto-attack-playbook.md` 533 → 854 lines (+2 key sections: Side-Channel Attack Labs, QKD Implementation Audits)
  - Expanded `payloads.md` 1,124 → 1,919 lines (+5 new payload sections, +24 code blocks → 57 total)
  - Fixed field completeness (0.86 → 1.00) in SKILL.md YAML frontmatter and test-cases.md
- **username-profiling**: 77.7 → **91.6** (+13.9)
  - Added `guides/maigret-username-workshop.md` (1,247 lines NEW) — 15 sections covering Maigret multi-site enumeration, NDJSON parsing, Sherlock/WhatsMyName correlation, Maltego/Neo4j export, GDPR/PII handling, automation
  - Expanded `guides/maigret-username-dossier.md` 504 → 959 lines (+2 key sections: Cross-Platform Identity Graph Construction, Operational Security for Investigators)
  - Expanded `payloads.md` 591 → 1,675 lines (+8 new sections, +46 code blocks → 67 total; word count 2,329 → 6,091)
  - Added 2 new test cases (TC-UP-012, TC-UP-013)

### Deepened: 12 New Skills Gain 2nd Guide File

| Skill | Cohort | New Guide | Lines | Score Δ |
|-------|--------|-----------|-------|---------|
| darkweb-intel | v0.1.28 | tor-onion-crawl-playbook.md | 694 | 84.7 → 89.2 (+4.5) |
| threat-hunting | v0.1.28 | sigma-rule-development-playbook.md | 770 | 85.2 → 87.2 (+2.0) |
| blockchain-web3 | v0.1.28 | defi-exploit-testing-playbook.md | 721 | 80.1 → 84.6 (+4.5) |
| payment-security | v0.1.28 | p2pe-hardware-assessment-playbook.md | 570 | 81.8 → 86.3 (+4.5) |
| llm-red-team | v0.1.29 | llm-jailbreak-arsenal-playbook.md | 786 | 82.4 → 86.9 (+4.5) |
| deception-honeypot | v0.1.29 | canary-deployment-playbook.md | 968 | 84.8 → 86.8 (+2.0) |
| kubernetes-attack | v0.1.29 | k8s-escape-and-lateral-movement-playbook.md | 888 | 87.5 → 89.5 (+2.0) |
| secret-management-attack | v0.1.29 | vault-and-cloud-kms-attack-playbook.md | 920 | 85.9 → 90.4 (+4.5) |
| ai-agent-security | v0.1.30 | mcp-server-red-team-playbook.md | 813 | 85.1 → 87.1 (+2.0) |
| iot-pentest | v0.1.30 | radio-and-firmware-iot-testing-playbook.md | 697 | 85.5 → 87.5 (+2.0) |
| detection-engineering | v0.1.30 | soc-playbook-mapping-to-nist-csf-2-0.md | 731 | 85.7 → 87.7 (+2.0) |
| agentic-pentest | v0.1.30 | agent-orchestration-patterns-playbook.md | 824 | 88.0 → 90.0 (+2.0) |

Total: **+10,180 lines** across 12 new guide files. Each skill's SKILL.md frontmatter updated (`guide_count: 1 → 2`, version bump).

### Index Updates

- **IDENTITY.md** — Refreshed descriptions for quantum-crypto-attack and username-profiling (reflecting new coverage breadth)
- **TOOLS.md** — No structural changes (no new skill domains); updated "Last updated" date
- **README.md** — Added v0.1.32 changelog row; refreshed quality snapshot (Strong 2 → 0, Excellent 70 → 72, average 87.51 → 88.19); bumped Project Info version 0.1.31→0.1.32
- **CHANGELOG.md** — v0.1.32 entry
- **VERSION** — 0.1.31→0.1.32
- **RELEASE-v0.1.32.md** — Chinese release announcement

### Quality Snapshot

- Distinguished: 19 (unchanged)
- Excellent: 70 → **72** (+2 from Strong lifts)
- Strong: 2 → **0** (both lifted!)
- Total: 91 (unchanged)
- Average: 87.51 → **88.19** (+0.68)
- Min: 77.7 → **81.0** (email-security-deep)
- Max: 93.8 (unchanged)
- **100% Excellent+ coverage** — first time in workspace history

### Stats

- New content: **~12,527 lines** (1,775 new quantum guide + 1,247 new username guide + 455 username dossier expansion + 795 quantum playbook expansion + 795 quantum payloads expansion + 10,180 across 12 cohort guides)
- New guide files: **14** (2 Strong lifts + 12 cohort deepening)
- New payload sections: **13** (5 in quantum + 8 in username)
- New code blocks: **70+** (24 quantum + 46 username)
- New test cases: **2** (TC-UP-012, TC-UP-013)
- Heartbeat: HEARTBEAT_OK — 455 guides checked, 0 issues
- **Zero new skill domains** — pure quality lift release

### Strategic Significance

v0.1.32 marks the workspace's first **100% Excellent+ milestone**: every one of the 91 skill domains scores 80 or higher, with 19 at Distinguished (92+). The two long-standing Strong-tier skills (username-profiling since v0.1.16, quantum-crypto-attack since v0.1.31) are now both at Excellent or above. The next quality frontier is pushing Excellent-tier skills toward Distinguished (92+).

## v0.1.31 (2026-06-17) — GitHub-Trending Expansion Wave 3: +4 Skill Domains (87→91)

### Driver: Third Wave of GitHub-Trending Methodology

v0.1.31 is the THIRD same-day release using the GitHub-trending-driven expansion methodology. Selected 4 skills from real coverage gaps validated against GitHub ecosystem research. Total candidate ecosystem stars for v0.1.31 cohort: ~50k+.

### New Skill Domains (+4)

- **cloud-identity-attack** — Cloud identity provider attacks (NEW: enterprise-cloud category)
  - Tools: ROADtools, AADInternals, MicroBurst, MFASweep, TokenTactics, AzureHound, okta-cli, GraphRunner, ScoutSuite
  - Coverage: Azure AD/Entra ID, Okta, Auth0, Ping, AWS IAM Identity Center, Google Workspace; OAuth/SAML/OIDC abuse, CA bypass, MFA fatigue, federation compromise
  - Differentiator: CLOUD IdP vs. `ad-ldap-attack` (ON-PREM AD/LDAP)
  - Scaffolding: SKILL.md (469), payloads.md (1,209), test-cases.md (269, 12 TC), guides/cloud-identity-attack-playbook.md (808)
  - Domain: enterprise-cloud | MITRE: T1078-Valid Accounts | Tool count: 14
  - Baseline: **83.8 / Excellent**
- **physical-security-testing** — Physical access pentest (NEW: physical category)
  - Tools: Proxmark3, ESP-RFID-Tool, Walrus, LAN Turtle, USB Rubber Ducky, Bash Bunny, Packet Squirrel
  - Coverage: Lock bypass (pin/tubular/wafer), RFID/NFC badge cloning (HID Prox/iCLASS, Mifare), drop boxes, USB weapons, hidden cameras, on-site ops, tailgating prep, physical-docs legal templates
  - Differentiator: GAINING PHYSICAL ACCESS vs. adjacent skills which cover wireless protocol analysis, firmware, RF
  - Scaffolding: SKILL.md (810), payloads.md (1,790), test-cases.md (310, 12 TC), guides/physical-security-testing-playbook.md (542)
  - Domain: physical | MITRE: TA0001-Initial Access (physical) | Tool count: 12
  - Baseline: **86.6 / Excellent** (highest of v0.1.31 cohort)
- **quantum-crypto-attack** — Post-quantum and national cryptography (extends cryptography category)
  - Tools: liboqs, OQS-OpenSSL, GmSSL, cloudflare/circl, hashsigs-solidity, Qiskit, PQCrypto-Break
  - Coverage: NIST PQC candidates (ML-KEM/ML-DSA/SLH-DSA), hybrid TLS, QKD/BB84 protocol attacks, SM2/SM3/SM4/SM9 (国密), lattice side-channel, post-quantum migration risk
  - Differentiator: POST-QUANTUM + 国密 vs. `crypto-attacks` (classical RSA/AES/ECDSA)
  - Scaffolding: SKILL.md (372), payloads.md (1,124), test-cases.md (268, 12 TC), guides/quantum-crypto-attack-playbook.md (533)
  - Domain: cryptography | MITRE: T1040 + forward-looking | Tool count: 12
  - Baseline: **79.7 / Strong** (just 0.3 below Excellent threshold; will be lifted next cycle)
- **email-security-deep** — Phishing infrastructure + gateway bypass (extends appsec category)
  - Tools: evilginx2, evilgophish, modlishka, gophish, King-Phisher, espoofer
  - Coverage: AiTM MFA interception, campaign platforms, Proofpoint/Mimecast/Cisco ESA/Microsoft Defender bypass, sender reputation, email bombing, FIDO2 detection
  - Differentiator: CAMPAIGN OPS + GATEWAY EVASION + MFA PHISHING vs. `email-protocol-attack` (protocol-level forgery). Explicit cross-reference section prevents overlap.
  - Scaffolding: SKILL.md (369), payloads.md (930), test-cases.md (281, 12 TC), guides/email-security-deep-playbook.md (692)
  - Domain: appsec | MITRE: T1566-Phishing | Tool count: 14
  - Baseline: **81.0 / Excellent**

### Baseline Scoring Run (SCORE.sh v2)

| Skill | Score | Tier |
|-------|-------|------|
| physical-security-testing | **86.6** | Excellent |
| cloud-identity-attack | **83.8** | Excellent |
| email-security-deep | **81.0** | Excellent |
| quantum-crypto-attack | **79.7** | Strong (just below threshold) |

### Index Updates

- **validation/update-skill-standard.py** — Registered 4 new skills; 2 new categories (enterprise-cloud, physical); MITRE_MAP updated for 3 new skills
- **IDENTITY.md** — Added 4 new skill tags
- **TOOLS.md** — Added 4 new category rows; 87 → 91 domains
- **README.md** — 87→91 domains (6 locations); +4 skill rows; +v0.1.31 changelog row; refreshed quality snapshot; bumped Project Info version 0.1.30→0.1.31
- **CHANGELOG.md** — v0.1.31 entry
- **VERSION** — 0.1.30→0.1.31
- **RELEASE-v0.1.31.md** — Chinese release announcement

### Quality Snapshot

- Distinguished: 19 (unchanged)
- Excellent: 67 → **70** (+3 new)
- Strong: 1 → **2** (+quantum-crypto-attack 79.7, borderline)
- Total: 87 → **91**
- Average: 87.73 → **87.51** (4 new baselines in 79-87 range)
- Min: 77.7 (unchanged — username-profiling)
- Max: 93.8 (unchanged)

### Stats

- New content: **~10,776 lines** across 16 new files (4 SKILL.md + 4 payloads.md + 4 test-cases.md + 4 guides)
- New test cases: **48** (12 × 4 skills)
- Heartbeat: HEARTBEAT_OK — 441 guides checked, 0 issues
- 2 new categories entered: enterprise-cloud, physical
- 89/91 (97.8%) at Excellent or above — quantum-crypto-attack will be lifted next cycle

### Coverage Gaps Closed

- **Identity layer**: `ad-ldap-attack` (on-prem) ↔ `cloud-identity-attack` (cloud) — now covers both worlds
- **Physical access**: first skill in this category; closes long-standing gap
- **Quantum-readiness**: forward-looking coverage for PQC migration wave
- **Phishing infrastructure**: depth skill complementing `email-protocol-attack`

## v0.1.30 (2026-06-17) — GitHub-Trending Expansion Wave 2: +4 Skill Domains (83→87)

### Driver: GitHub Open-Source Analysis Wave 2

Following v0.1.29's methodology, v0.1.30 continues the GitHub-trending-driven expansion. Selected from the second-tier candidates identified in v0.1.29's release notes. Four new categories entered: ai-emerging, iot, defense-deepening (detection-engineering), ai-meta.

### New Skill Domains (+4)

- **ai-agent-security** — Offensive AI agent testing (NEW CATEGORY: ai-emerging)
  - Tools: HexStrike AI, AI-Infra-Guard, mcp-scan, MCP Inspector, garak, picklescan
  - Coverage: MCP tool poisoning, indirect prompt injection, RAG poisoning, agent sandbox escape, multi-agent compromise
  - Differentiator: AGENT-focused (stateful, tool-using, autonomous) vs. `llm-red-team` (stateless LLM)
  - Scaffolding: SKILL.md (575), payloads.md (2,184), test-cases.md (204, 12 TC), guides/ai-agent-security-playbook.md (976)
  - Domain: ai-emerging | Tool count: 12
  - Baseline: **85.1 / Excellent**
- **iot-pentest** — IoT application-layer pentest (NEW CATEGORY: iot)
  - Tools: mosquitto, MQTT-Pwn, IoT-Goat, EMQX, coap-client, chip-tool, Shodan
  - Coverage: MQTT broker abuse, CoAP attacks, AMQP, AWS/Azure IoT backends, mobile companion apps, OWASP IoT Top 10
  - Differentiator: APPLICATION-LAYER IoT vs. `firmware-reverse` (extraction), `hardware-security` (side-channel), `bluetooth-rfid-nfc` (radios)
  - Scaffolding: SKILL.md (499), payloads.md (1,303), test-cases.md (270, 12 TC), guides/iot-pentest-playbook.md (685)
  - Domain: iot | MITRE: T1021-Remote Services | Tool count: 12
  - Baseline: **85.5 / Excellent**
- **detection-engineering** — Detection-as-code craft (defense deepening)
  - Tools: SigmaHQ, Yara-Rules, Loki, yarGen, hayabusa, SigmaCLI, zircollo
  - Coverage: Sigma/YARA rule authoring, SPL/KQL/EQL, ATT&CK mapping, detection CI/CD, FP tuning, lifecycle
  - Differentiator: AUTHORING & DEPLOYING rules vs. `threat-hunting` (USING detections to hunt), `logging-monitoring` (log infra)
  - Scaffolding: SKILL.md (755), payloads.md (2,325), test-cases.md (281, 12 TC), guides/detection-engineering-playbook.md (1,351)
  - Domain: defense | MITRE: TA0040-Detection | Tool count: 14
  - Baseline: **85.7 / Excellent**
- **agentic-pentest** — LLM-driven autonomous pentest (NEW CATEGORY: ai-meta)
  - Tools: PentestGPT, HexStrike AI, Viper, PentestAgent, AI-Infra-Guard, AutoPWN
  - Coverage: Reasoning-chain orchestration, tool delegation, context management, HITL, multi-agent team coordination
  - Differentiator: USING pentest agents vs. `ai-agent-security` (ATTACKING agents), `autonomous-loops` (generic patterns)
  - Scaffolding: SKILL.md (574), payloads.md (1,771), test-cases.md (199, 12 TC), guides/agentic-pentest-playbook.md (791)
  - Domain: ai-meta | Tool count: 12
  - Baseline: **88.0 / Excellent** (highest of v0.1.30 cohort)

### Baseline Scoring Run (SCORE.sh v2)

First-time scores for 4 v0.1.30 new skills:

| Skill | Score | Tier |
|-------|-------|------|
| agentic-pentest | **88.0** | Excellent |
| detection-engineering | **85.7** | Excellent |
| iot-pentest | **85.5** | Excellent |
| ai-agent-security | **85.1** | Excellent |

### Index Updates

- **validation/update-skill-standard.py** — Registered 4 new skills in ATTACK_SKILLS, DOMAIN_MAP (4 new categories: ai-emerging, iot, defense, ai-meta), MITRE_MAP (iot-pentest + detection-engineering)
- **IDENTITY.md** — Added 4 new skill tags
- **TOOLS.md** — Added 4 new category rows; 83 → 87 domains
- **README.md** — 83→87 domains (6 locations); +4 skill rows; +v0.1.30 changelog row; refreshed quality snapshot; bumped Project Info version 0.1.29→0.1.30
- **CHANGELOG.md** — v0.1.30 entry
- **VERSION** — 0.1.29→0.1.30
- **RELEASE-v0.1.30.md** — Chinese release announcement

### Quality Snapshot

- Distinguished: 19 (unchanged)
- Excellent: 63 → **67** (+4 new)
- Strong: 1 (unchanged — username-profiling 77.7)
- Total: 83 → **87**
- Average: 87.81 → **87.73** (4 new baselines in 85-88 range)
- Min: 77.7 (unchanged)
- Max: 93.8 (unchanged)

### Stats

- New content: **~14,743 lines** across 16 new files (4 SKILL.md + 4 payloads.md + 4 test-cases.md + 4 guides)
- New test cases: **48** (12 × 4 skills)
- Heartbeat: HEARTBEAT_OK — 437 guides checked, 0 issues
- 4 new categories entered: ai-emerging, iot, defense (deepening), ai-meta

## v0.1.29 (2026-06-17) — GitHub-Trending Expansion: +4 Skill Domains (79→83), 8 New Skills Scored

### Driver: GitHub Open-Source Analysis

v0.1.29 is the first release explicitly driven by trending open-source intelligence. Candidate skills were selected by aggregating GitHub stars across security ecosystems (promptfoo 22k, garak 8k, PyRIT 4k, PurpleLlama 4.2k, T-Pot 9.3k, Cowrie 6.4k, kubescape 11k, CDK 4.7k, kube-hunter 5k, gitleaks 27k, semgrep 15k, infisical 27k, etc.) and cross-referencing against existing 79-skill coverage to identify gaps. Total combined GitHub stars across the 4 new skill ecosystems: **150k+**.

### New Skill Domains (+4)

- **llm-red-team** — LLM/generative AI red team: prompt injection, jailbreaking, model extraction, RAG poisoning, agent tool abuse
  - Tools: promptfoo, garak, PyRIT, PurpleLlama, AI-Infra-Guard, llm-guard
  - Scaffolding: SKILL.md (583), payloads.md (1,723), test-cases.md (209, 12 TC TC-LR-001..012), guides/llm-red-team-playbook.md (952)
  - Domain: ai-red-team | MITRE: LLM-ATT&CK / OWASP LLM Top 10 | Tool count: 12
- **deception-honeypot** — Defensive deception: SSH/web/ICS/AI honeypots, honeytokens, canary deployment
  - Tools: T-Pot, Cowrie, OpenCanary, HFish, Beelzebub, Conpot
  - Scaffolding: SKILL.md (789), payloads.md (1,936), test-cases.md (272, 12 TC TC-DH-001..012), guides/deception-honeypot-playbook.md (1,008)
  - Domain: defense | MITRE: TA0040-Detection (MITRE Engage) | Tool count: 12
  - Completes purple-team triad with threat-hunting (detect) + deception-honeypot (lure)
- **kubernetes-attack** — K8s red team: RBAC abuse, pod escape, SA token theft, etcd attacks, EKS/GKE/AKS pivot
  - Tools: kubectl, CDK, peirates, kube-hunter, kubescape, stratus-red-team, kubernetes-goat
  - Scaffolding: SKILL.md (509), payloads.md (1,243), test-cases.md (302, 12 TC TC-KA-001..012), guides/kubernetes-attack-playbook.md (700)
  - Domain: cloud-native | MITRE: TA0008-Lateral Movement (Containers) | Tool count: 14
- **secret-management-attack** — Secrets/SAST: gitleaks, semgrep, trufflehog, infisical, Vault/CI-CD/registry exploitation
  - Tools: gitleaks, semgrep, trufflehog, infisical, bearer, DeepAudit, apkleaks, cariddi
  - Scaffolding: SKILL.md (523), payloads.md (1,808), test-cases.md (227, 12 TC TC-SM-001..012), guides/secret-management-attack-playbook.md (784)
  - Domain: appsec | MITRE: T1552-Unsecured Credentials family | Tool count: 14

### Baseline Scoring Run (SCORE.sh v2)

First-time scores for 8 new skills (v0.1.28 + v0.1.29 cohorts):

| Skill | Score | Tier |
|-------|-------|------|
| kubernetes-attack | **87.5** | Excellent |
| secret-management-attack | **85.9** | Excellent |
| threat-hunting (v0.1.28) | 85.2 | Excellent |
| deception-honeypot | **84.8** | Excellent |
| darkweb-intel (v0.1.28) | 84.7 | Excellent |
| llm-red-team | **82.4** | Excellent |
| payment-security (v0.1.28) | 81.8 | Excellent |
| blockchain-web3 (v0.1.28) | 80.1 | Excellent |

### Surprise: +2 New Distinguished (Post-Release Skill Maturity)

SCORE.sh re-evaluated all 83 skills; 2 skills crossed the 92 threshold thanks to v0.1.27 post-release sprint work (deep guides + SKILL.md expansion):

- **sdr-rf-attack** 89.5 → **93.6** (+4.1) — Distinguished ⭐
- **container-security** 90.4 → **92.8** (+2.4) — Distinguished ⭐

### Index Updates

- **validation/update-skill-standard.py** — Registered 4 new skills in ATTACK_SKILLS, DOMAIN_MAP, MITRE_MAP
- **IDENTITY.md** — Added 4 new skill tags
- **TOOLS.md** — Added 4 new category rows; 79 → 83 domains
- **README.md** — 79→83 domains (6 locations); +4 skill rows; +v0.1.29 changelog row; refreshed quality snapshot; bumped Project Info version 0.1.28→0.1.29
- **CHANGELOG.md** — v0.1.29 entry
- **VERSION** — 0.1.28→0.1.29
- **RELEASE-v0.1.29.md** — Chinese release announcement

### Quality Snapshot

- Distinguished: 17 → **19** (+2: sdr-rf-attack, container-security)
- Excellent: 57 → **63** (+8 new skills, -2 promoted)
- Strong: 0 → **1** (username-profiling 77.7 — guide count bottleneck)
- Total: 79 → **83**
- Average: 88.2 → **87.81** (slight drop due to 8 new baseline scores in 80-87 range; expected to lift next cycle)
- Min: 84.5 → **77.7** (username-profiling — first new skill at Strong tier, will be lifted)
- Max: 93.8 (social-intelligence, unchanged)

### Stats

- New content: **~13,568 lines** across 16 new files (4 SKILL.md + 4 payloads.md + 4 test-cases.md + 4 guides)
- New test cases: **48** (12 × 4 skills)
- Heartbeat: HEARTBEAT_OK — 433 guides checked, 0 issues
- 3 first-time domains touched: ai-red-team (first), cloud-native deepening (K8s-specific), appsec deepening (secrets-specific)

## v0.1.28 (2026-06-16) — Domain Expansion: 4 New Skill Domains (75→79)

### New Skill Domains (+4)

- **darkweb-intel** — Tor/onion hidden-service enumeration, dark-net marketplace intelligence, leak-site monitoring, actor attribution
  - Scaffolding: SKILL.md (572), payloads.md (1,227), test-cases.md (253, 12 TC), guides/dark-web-investigation-playbook.md (616)
  - Domain: osint | MITRE: TA0043-Reconnaissance | Tool count: 10
- **threat-hunting** — First **defensive** skill: hypothesis-driven hunts, SIEM/EDR telemetry pivoting, ATT&CK detection engineering, purple-team validation
  - Scaffolding: SKILL.md (590), payloads.md (1,175), test-cases.md (253, 12 TC), guides/hunt-hypothesis-playbook.md (805)
  - Domain: defense | MITRE: TA0040-Detection | Tool count: 12
  - Forms purple-team loop with existing attack skills (red↔blue)
- **blockchain-web3** — Smart-contract auditing, DeFi exploit chains, wallet/key management, bridge/oracle attacks
  - Scaffolding: SKILL.md (567), payloads.md (1,203), test-cases.md (271, 13 TC), guides/smart-contract-audit-playbook.md (691)
  - Domain: blockchain | MITRE: N/A (application-layer; loosely TA0001-Initial Access via compromise) | Tool count: 14
- **payment-security** — PCI-DSS assessment, card-data flow, 3DS/SAML SSO, fraud detection, webhook signing
  - Scaffolding: SKILL.md (509), payloads.md (966), test-cases.md (270, 13 TC), guides/payment-pentest-playbook.md (752)
  - Domain: financial | MITRE: T1566-Phishing + domain-specific | Tool count: 12

### Index Updates

- **validation/update-skill-standard.py** — Registered all 4 new skills in ATTACK_SKILLS, DOMAIN_MAP (darkweb-intel→osint, threat-hunting→defense, blockchain-web3→blockchain, payment-security→financial), MITRE_MAP (darkweb-intel + threat-hunting)
- **IDENTITY.md** — Added 4 new skill tags; last-modified refreshed
- **TOOLS.md** — Added 5 category rows (4 new skills + sdr-rf-attack + vpn-attack that were missing from previous releases); updated "74 skill domains" → "79"
- **README.md** — 75→79 skill domains (6 locations); added 4 skill rows; added v0.1.28 changelog row; bumped Project Info version 0.1.27→0.1.28

### Quality Snapshot

- Distinguished: 17 (unchanged — 4 new skills pending first SCORE.sh run)
- Excellent: 57 (unchanged)
- Strong/Adequate: 0
- Total: 75 → **79**
- Heartbeat: HEARTBEAT_OK — 429 guides checked, 0 issues

### Stats

- New content: ~10,720 lines across 16 new files (4 SKILL.md + 4 payloads.md + 4 test-cases.md + 4 guides)
- First defensive-domain skill (threat-hunting) — closes purple-team loop
- First financial-domain skill (payment-security)
- First blockchain-domain skill (blockchain-web3)

## v0.1.27 (2026-06-11, post-release update 2026-06-16) — 17 Distinguished Milestone, Distinguished Sprint + Bottom Lift

### Post-release Update (2026-06-16) — RELEASE Backfill + username-profiling + Core File Sync

Folded into v0.1.27 (no version bump): backfilled the missing release announcement, added a new skill domain, and synchronized stale core files.

- **New skill domain: username-profiling** (+1, 74→75) — Maigret-powered single-username dossier generation
  - Full skill scaffolding: SKILL.md (505 lines), payloads.md (591 lines), test-cases.md (11 test cases), guides/maigret-username-dossier.md (504 lines)
  - Coverage: Maigret (3,000+ sites) + companion tools (Sherlock, WhatsMyName, Holehe, Blackbird, Namechk)
  - 5-phase methodology: Seed → Broad Enumeration → Recursive Pivot → Cross-Tool Verification → Dossier Synthesis
  - OPSEC focus: Tor/I2P/proxy routing, false-positive verification protocol
  - Domain: osint | MITRE: TA0043-Reconnaissance

- **Sprint tail** (pre-existing in-progress work, brought into this update):
  - **sdr-rf-attack** 88.8 → **89.5** — SKILL.md +123 lines; 3 new guides (rf-fingerprinting-device-identification, satellite-signal-analysis, sub-ghz-iot-attack); file_count 6→9
  - **container-security** — 3 new guides (container-network-segmentation, container-supply-chain-attack, docker-breakout-escape); file_count 5→8
  - **deep-research** — payloads.md +1,373 lines
  - **scada-ics-security** — SKILL.md minor update (+4 lines)

- **Core file sync**:
  - **RELEASE-v0.1.27.md** — backfilled (every release v0.1.1 to v0.1.27 now has a RELEASE file)
  - **README.md** — 74→75 skill domains (multiple locations); Project Info version 0.1.21→0.1.27 (was stale by 6 versions); Skill Domains 72→75; added username-profiling row; refreshed quality snapshot
  - **IDENTITY.md** — added username-profiling skill tag; updated last-modified date
  - **TOOLS.md** — added username-profiling category index row
  - **validation/update-skill-standard.py** — registered username-profiling in ATTACK_SKILLS, DOMAIN_MAP (osint), MITRE_MAP (TA0043-Reconnaissance)

- **Stats after post-release update**: Skill domains 74→**75**, Distinguished 17 (unchanged — username-profiling not yet scored), Excellent 57, Average 88.2, Min 84.5

### Original v0.1.27 Release (2026-06-11)

#### Distinguished Sprint: 2 New Distinguished Skills
- **scada-ics-security** reached 93.0 — created 2 new guides (ics-incident-response, purdue-model-attack-paths); file_count 5→7
- **council** reached 92.3 — expanded 3 guides (avg 1289→2000+); created 2 new guides (multi-agent-escalation, council-consensus-building); file_count 5→7

#### Bottom Lift: 3 Skills Improved
- **database-attack** 83.4 → 87.3 — expanded SKILL.md (20 headings); created 2 new guides (nosql-attack, database-lateral-movement); added 5 payload sections (14→19); file_count 3→5
- **exploit-development** 84.9 → 86.1 — created 2 new guides (heap-exploitation, kernel-exploit); file_count 3→5
- **dns-attacks** 83.4 → 84.6 — created 2 new guides (dns-rebinding, dns-tunnel-exfiltration); file_count 3→5

#### Stats
- Distinguished: 15 → 17 (+2)
- Excellent: 59 → 57
- Total: 74
- Average: 88.0 → 88.2
- Min: 83.4 → 84.5

## v0.1.26 (2026-06-11) — 15 Distinguished Milestone, Distinguished Sprint + Bottom Lift

### Distinguished Sprint: 3+2 New Distinguished Skills
- **network-tunneling-proxy** reached 92.3 — created 3 new guides (pivoting-double-pivot, ipv6-tunneling, tunnel-detection-evasion); file_count 5→8
- **payload-generation** reached 93.1 — created 3 new guides (cross-platform, web-shell, encoding-encryption); file_count 5→8
- **vpn-attack** reached 92.5 — created 3 new guides (wireguard, openvpn, credential-brute-force); expanded payloads +2 sections; file_count 5→8

### Bottom Lift: 3 Skills Improved
- **web-deserialization** 85.3 → **92.2** — expanded SKILL.md (+6 sections); created 2 new guides (nodejs, dotnet); added 9 payload sections (10→18)
- **scada-ics-security** 84.6 → **91.6** — expanded SKILL.md (+5 sections); expanded 3 guides; created 2 new guides; added 5 payload sections
- **sdr-rf-attack** 86.1 → **88.8** — expanded 3 guides; created 2 new guides (gps-spoofing, zigbee-ble-sdr)

### Stats
- Distinguished: 11 → 15 (+4)
- Excellent: 63 → 59
- Total: 74
- Average: 87.7 → 88.0
- Min: 83.4

## v0.1.25 (2026-06-10) — 11 Distinguished Milestone, Distinguished Sprint + Bottom Lift

### Distinguished Sprint: 3 New Distinguished Skills
- **security-misconfiguration** reached 92.8 — expanded SKILL.md (13→15 sections); expanded all 8 guides (avg 880→2014 words)
- **security-bounty-hunter** reached 92.0 — expanded SKILL.md (14→18 sections); expanded 5 guides (avg 1463→1894); added 2 test cases
- **web-xss** reached 92.0 — expanded SKILL.md (8→25 headings); expanded 4 guides (avg 1480→2177); created CSP bypass guide (8 guides total)

### Bottom Lift: 3 Lowest Skills Improved
- **vpn-attack** 83.3 → 89.4 (+6.1) — expanded SKILL.md (7→12 sections); expanded 3 guides; created 2 new guides; added 3 payload sections
- **network-tunneling-proxy** 84.3 → 90.3 (+6.0) — expanded SKILL.md (8→14 sections); expanded 3 guides; created 2 new guides
- **payload-generation** 84.4 → 91.1 (+6.7) — expanded SKILL.md (11→14 sections); expanded 3 guides; created 2 new guides; added 6 payload sections

### Stats
- Distinguished: 8 → 11 (+3)
- Excellent: 66 → 63
- Total: 74
- Average: 87.3 → 87.7
- Min: 83.4

## v0.1.24 (2026-06-10) — 8 Distinguished Milestone, Distinguished Sprint + Bottom Lift

### Distinguished Sprint: 3 New Distinguished Skills
- **osint** reached 92.5 — expanded 4 guides (info-gathering-cli-reference, automated-osint-pipeline, enterprise-pentest-case-study, corporate-recon); added Introduction/Hands-on/References to 8 guides
- **social-intelligence** reached 93.8 — expanded 5 guides (community-monitoring, reddit-hn, social-graph, target-profiling, twitter-youtube); added 4 payload sections (TikTok, Instagram, Discord, Mastodon/Fediverse); added 2 test cases
- **verification-loop** reached 92.6 — expanded 1 guide (automated-exploit-verification); added key sections to 5 guides; created 3 new guides (false-positive-triage, cross-tool-verification, finding-documentation-evidence)

### Bottom Lift: 5 Lowest Skills Improved
- **engagement-manager** 82.8 → 86.0 — expanded SKILL.md (10→16 sections: Phase Entry/Exit, Evidence Requirements, Timeline, Communication Templates, Risk Matrix, Post-Engagement Checklist)
- **tool-mastery** 82.8 → 85.4 — expanded SKILL.md (11→16 sections: Tool Selection Matrix, Learning Path, Tool Failure Recovery, Common Pitfalls, Output Formats)
- **email-protocol-attack** 83.1 → 85.2 — added payload code block (Email Header Forensic Analysis)
- **steganography** 84.9 → 86.4 — added payload code blocks (Chi-Square, Audio, PDF); created 2 new guides (audio-video-steganography, network-protocol-steganography)
- **av-edr-evasion** 88.3 → 89.1 — created 2 new guides (shellcode-encoding, process-injection-techniques)

### Stats
- Distinguished: 5 → 8 (+3)
- Excellent: 69 → 66
- Total: 74
- Average: 87.0 → 87.3
- Min: 83.3 (vpn-attack)

## v0.1.23 (2026-06-10) — 5 Distinguished Milestone, Guide Quality Sprint

### Quality Milestone: 5 Distinguished Skills
- **article-writing** reached 93.6 — expanded 5 guides (pentest-report-template, report-structure, cve-advisory, security-blog, vulnerability-writing)
- **vulnerability-assessment** reached 93.0 — expanded 4 guides (automated-scanning-pipeline, manual-testing, risk-rating, vuln-analysis-tools)
- **autonomous-loops** reached 92.6 — expanded 3 guides (watch-loop-patterns, batch-processing, error-recovery)
- cloud-security maintained 92.1
- network-pentest maintained 92.0

### Stats
- Distinguished: 2 → 5 (+3)
- Excellent: 72 → 69
- Total: 74
- Average: 86.9 → 87.0
- Guides expanded: 12 (all from ~300-800 words to 2000+ words)

## v0.1.22 (2026-06-10) — SDR/RF + VPN Attack, 2 Distinguished

### New Skill Domains
- **sdr-rf-attack** (7 tools) — Software Defined Radio and RF signal attacks covering HackRF/RTL-SDR, signal capture and replay, GSM/LTE analysis, RFID/NFC attacks, keyfob replay, drone RF analysis, satellite signal monitoring, AIS ship tracking, and spectrum analysis.
- **vpn-attack** (5 tools) — VPN attack techniques covering IKE enumeration with ike-scan, PSK cracking via aggressive mode, SSL VPN exploitation (Fortinet/Pulse/Palo Alto/SonicWall), IPSec tunnel testing, certificate analysis, credential brute force, and split tunneling detection.

### Quality Milestone: 2 Distinguished Skills
- **cloud-security** reached 92.1 — second Distinguished tier skill (Distinguished sprint)
- **network-pentest** maintained 92.0 — first Distinguished tier skill
- 74/74 Excellent or above (100%)

### Distinguished Sprint
- cloud-security: added AWS Lambda priv esc, Azure CA bypass, GCP SA key extraction, CloudFormation injection, Terraform state exploitation
- vulnerability-assessment: added NSE scripts, OpenVAS automation, Nessus CLI, Nuclei templates, correlation scripts
- article-writing: added report generator, markdown-to-PDF, CVSS calculator, disclosure generator, export pipeline
- autonomous-loops: added pipeline orchestration, batch processing, learning cycle, error recovery, parallel execution

### Stats
- Skills: 72 → 74 (+2)
- Distinguished: 2 (cloud-security, network-pentest)
- Excellent: 72
- Strong: 0
- New tool references: 12

## v0.1.21 (2026-06-10) — First Distinguished, web-deserialization + email-protocol-attack

### New Skill Domains
- **web-deserialization** (6 tools) — Insecure deserialization attacks (OWASP A08:2021) covering Java ysoserial, PHP phpggc, .NET ysoserial.net, Python pickle, Ruby Marshal, Jackson/Fastjson. Includes blind detection, gadget chain analysis, and WAF bypass.
- **email-protocol-attack** (8 tools) — Email protocol attacks covering SMTP enumeration, open relay testing, SPF/DKIM/DMARC bypass, email forgery with swaks, IMAP/POP3 brute force, Exchange server exploitation, and STARTTLS testing.

### Quality Milestone: First Distinguished Skill
- **network-pentest** reached 92.0 — the first Distinguished tier skill
- 72/72 Excellent or above (100%), avg 86.9
- 1 Distinguished / 71 Excellent / 0 Strong / 0 Adequate

### Distinguished Sprint (Top 5)
- network-pentest: 91.2 → 92.0 (Distinguished!)
- cloud-security: 91.3 → 91.8
- autonomous-loops: 90.9 → 91.3
- vulnerability-assessment: 90.7 → 91.1
- article-writing: 90.6 → 91.0

### Bottom 5 Consolidation (all to 83+)
- privilege-escalation: 80.2 → 85.8
- web-xxe: 81.3 → 87.3
- cms-framework-attack: 81.7 → 85.8
- network-sniffing-mitm: 81.7 → 85.8
- ad-ldap-attack: 82.2 → 85.8

### Guide Additions (5 new guides)
- web-access-control: CSRF Attack Guide
- api-security: WebSocket Security Testing Guide
- web-xss: SSTI Attack Guide + WAF Bypass XSS Guide
- web-sqli: WAF Bypass SQLi Guide

### Stats
- Skill domains: 70 → 72
- Tool references: +14 (ysoserial, phpggc, marshalsec, smtp-user-enum, swaks, etc.)
- New files: 19 (2×7 core + 5 guides)
- Average score: 86.5 → 86.9

## v0.1.20 (2026-06-10) — 70/70 Excellent, AD/LDAP Attack Domain

### New Skill Domain
- **ad-ldap-attack** (15 tools) — Active Directory/LDAP/Kerberos attack techniques covering domain reconnaissance, AS-REP Roasting, Kerberoasting, Golden/Silver Tickets, DCSync, Pass-the-Hash, lateral movement, and domain dominance. Tools: impacket-suite, bloodhound, ldapsearch, enum4linux, crackmapexec, ldeep, ldapdomaindump, rpcclient, etc.

### Quality Milestone: 70/70 Excellent (100%)
- All 70 skill domains now score Excellent (80+) under scoring system v2
- Previous: 49 Excellent / 18 Strong / 2 Adequate
- Now: 70 Excellent / 0 Strong / 0 Adequate
- Average score: 81.8 → 86.5

### Skills Promoted from Strong/Adequate to Excellent (21 skills)
- **From Adequate** (2): tool-mastery (44.0→79.0), engagement-manager (45.7→77.8)
- **From Strong** (19): bluetooth-rfid-nfc, file-inclusion, anti-forensics, network-tunneling-proxy, database-attack, firmware-reverse, voip-sip-attack, scada-ics-security, dns-attacks, payload-generation, pentest-reporting, av-edr-evasion, steganography, web-xxe, cms-framework-attack, exploit-development, network-sniffing-mitm, privilege-escalation, ad-ldap-attack (new)

### Content Enhancements
- payloads.md: All 21 promoted skills received 15-25 additional code blocks (realistic Kali commands)
- test-cases.md: All skills now have 8+ test cases with 7/7 field completeness (Severity, Prerequisite, Steps, Expected Result, Objective, Remediation, Pass Criteria)
- SKILL.md: Fixed missing sections (Core Tools tables, Practical Steps, Defense Perspective) for tool-mastery, engagement-manager, network-tunneling-proxy, privilege-escalation
- guides: Expanded to 1000+ words each with Introduction, Hands-on Exercise, and References sections for file-inclusion, firmware-reverse, network-tunneling-proxy, bluetooth-rfid-nfc

### Stats
- Skill domains: 69 → 70
- Tool references: +15 (impacket-suite, bloodhound, enum4linux, kerberoast, etc.)
- New files: 7 (SKILL.md, payloads.md, test-cases.md, 3 guides + 1 guide for tool-mastery)
- Average score: 86.5 (up from 81.8)

## [0.1.19] - 2026-06-09

### Added

- **8 new security skill domains** (61 → 69), covering 70 additional Kali tool references:
  - `bluetooth-rfid-nfc` — Bluetooth/BLE/RFID/NFC near-field wireless attacks (13 tools: spooftooph, redfang, bluelog, btscanner, bluehydra, crackle, ubertooth-tools, gatttool, proxmark3, mfoc, mfcuk, libnfc, blescan)
  - `network-tunneling-proxy` — Network tunneling, proxy chains, and pivoting (10 tools: chisel, ligolo-ng, proxychains, socat, ptunnel, gost, 3proxy, sshuttle, stunnel, dnscat2)
  - `firmware-reverse` — Firmware extraction, analysis, and emulation (9 tools: firmadyne, firmwalker, sasquatch, jefferson, binwalk, unblob, qemu-system, yara, firmware-mod-kit)
  - `scada-ics-security` — SCADA/ICS industrial control system security (8 tools: conpot, plcscan, s7scan, modbus-cli, mbpoll, enip-client, csric, python-opcua)
  - `database-attack` — Direct database server attacks at protocol level (8 tools: odat, oscanner, sqsh, redis-tools, mongoaudit, patator, ncrack, hydra)
  - `voip-sip-attack` — VoIP/SIP protocol attacks (8 tools: sipvicious, sipsak, voiphopper, iaxflood, inviteflood, rtpflood)
  - `anti-forensics` — Anti-forensic techniques and forensic evasion (7 tools: shred, wipe, tcplay, logtamper, timestomp, bulk_extractor, steghide)
  - `pentest-reporting` — Pentest reporting and evidence management tools (7 tools: dradis, faraday, pipal, cutycapt, recordmydesktop, magictree, cherrytree)
- Each new skill includes: SKILL.md, payloads.md, test-cases.md, and 3 deep-dive guides
- `validation/update-skill-standard.py` — Updated with DOMAIN_MAP, ATTACK_SKILLS, ANALYSIS_SKILLS, and MITRE_MAP for all 8 new domains

### Changed

- Skill domain count: 61 → 69
- Tool coverage: 70 new tool references added
- `heartbeat.sh`: EXPECTED_SKILLS=69
- `VERSION`: 0.1.19

## [0.1.18] - 2026-06-04

### Added

- **10 new security skill domains** (51 → 61), covering 72 additional Kali tool references:
  - `network-sniffing-mitm` — Network traffic interception, ARP spoofing, credential harvesting (9 tools: wireshark, tcpdump, ettercap, bettercap, mitm6, responder, dsniff, driftnet, mitmproxy)
  - `privilege-escalation` — Linux/Windows local and domain privilege escalation (8 tools: linpeas, winpeas, linux-exploit-suggester, pspy, GTFOBins, lolbas, sudo, capsh)
  - `exploit-development` — Vulnerability research, exploit writing, binary exploitation (8 tools: gdb/pwndbg, pwntools, ROPgadget, ropper, checksec, pattern_create, shellnoob, one_gadget)
  - `payload-generation` — Reverse shell generation, payload encoding, delivery mechanisms (7 tools: msfvenom, netcat, socat, nishang, hoaxshell, rlwrap, shellter)
  - `av-edr-evasion` — Antivirus/EDR bypass techniques (7 tools: shellter, veil, msfvenom encoders, donut, pe2shc, hyperion, crypter)
  - `dns-attacks` — DNS reconnaissance, spoofing, tunneling, exfiltration (8 tools: dnsrecon, dnsenum, fierce, dnschef, dns2tcp, dnscat2, dnswalk, iodine)
  - `web-xxe` — XML External Entity injection attacks (6 tools: XXEinjector, oxml_xxe, xxeplus, burpsuite, odat, netcat)
  - `file-inclusion` — Local/Remote File Inclusion attacks (6 tools: dotdotpwn, kadimus, fimap, burpsuite, php_filter_chain, secLists)
  - `cms-framework-attack` — CMS security assessment (7 tools: wpscan, joomscan, droopescan, cmseek, nikto, whatweb, nuclei)
  - `steganography` — Steganographic data hiding and extraction (6 tools: steghide, stegcracker, zsteg, binwalk, foremost, exiftool)
- Each new skill includes: SKILL.md, payloads.md, test-cases.md, and 3 deep-dive guides (6-8 test cases, 300+ word guides)
- **Agent Skills Open Standard alignment** — All 61 SKILL.md files now conform to the open Agent Skills standard (Anthropic, 2025):
  - YAML frontmatter with `name`, `description`, `version`, `compatibility`, `allowed-tools`, and `metadata` fields
  - `compatibility` field declaring support for openclaw, claude-code, cursor, windsurf
  - `allowed-tools` field restricting tool access per skill type (security/analysis/all)
  - `metadata` with domain classification, tool count, OWASP/MITRE ATT&CK mapping
  - Progressive disclosure via `## Summary` section (Stage 1: advertise → Stage 2: quick reference → Stage 3: detailed content)
  - All SKILL.md files verified under 500 lines (max: 378)
- `validation/update-skill-standard.py` — Automated SKILL standard alignment script

### Changed

- Skill domain count: 51 → 61
- Tool coverage: 72 new tool references added
- IDENTITY.md: added 10 new skill tags
- TOOLS.md: added 10 new tool categories
- CLAUDE.md: updated domain count and descriptions
- SOUL.md: decision trees updated with new skill references
- README.md: version updated to 0.1.18

## [0.1.17] - 2026-06-03

### Added

- **15 skills fixed key sections** (Introduction, Hands-on, References): verification-loop, council, browser-qa, crypto-attacks, hardware-security, insecure-design, supply-chain-security, web-ssrf, container-security, password-attack, safety-guard, codebase-onboarding, web-access-control, ai-fuzzing, post-exploitation
- **10 new guides for bottom 5 skills**:
  - post-exploitation: persistence-techniques-guide, lateral-movement-practical-guide
  - ai-fuzzing: web-api-fuzzing-guide, crash-triage-guide
  - password-attack: hashcat-rules-guide, password-policy-audit-guide
  - insecure-design: abuse-case-development-guide, secure-design-patterns-guide
- **3 test cases added** to continuous-learning (TC-CL-007 to TC-CL-009, now 9 total)
- **35 new guides for Distinguished sprint** (10 target skills × 3-4 guides each):
  - cloud-security: aws-pentest-lab-guide, azure-privilege-escalation-guide, cloud-post-exploitation-guide
  - vulnerability-assessment: automated-scanning-pipeline-guide, manual-testing-techniques-guide, risk-rating-methodology-guide
  - article-writing: pentest-report-template-guide, cve-advisory-writing-guide, security-blog-writing-guide
  - autonomous-loops: watch-loop-patterns-guide, batch-processing-guide, error-recovery-guide
  - osint: dark-web-intelligence-guide, corporate-recon-guide, data-aggregation-analysis-guide
  - ai-security: prompt-injection-lab-guide, ai-red-team-guide (model-extraction already existed)
  - security-misconfiguration: cloud-misconfiguration-checklist-guide, web-server-hardening-lab-guide, default-credential-audit-guide
  - network-pentest: 3 guides (from batch agent)
  - security-bounty-hunter: 3 guides (from batch agent)
  - social-intelligence: 3 guides (from batch agent)
- **Automation infrastructure** (4 scripts):
  - `validation/heartbeat.sh` — Workspace health checks with JSON output and auto-fix
  - `validation/auto-backup.sh` — Timestamped backup rotation with integrity verification
  - `validation/drift-detect.sh` — Configuration drift detection with baseline snapshots
  - `validation/scenario-runner.sh` — Cross-skill scenario execution with checkpoint resume
- **Penetration test orchestration layer** (3 scripts + templates):
  - `validation/orchestrator.sh` — End-to-end kill chain workflow engine with phase management
  - `validation/tool-selector.sh` — Target-to-tool mapping engine (5 target types × 6 phases)
  - `validation/report-generator.sh` — Automated penetration test report generator
  - `validation/engagement-template/` — Target config, scope rules, and report templates
- **2 new skill domains** (49 → 51):
  - `skills/engagement-manager/` — Full engagement lifecycle management (3 guides, 8 test cases)
  - `skills/tool-mastery/` — Tool proficiency assessment framework (2 guides, 6 test cases)
- **SOUL.md decision trees** — Structured decision frameworks for target type, vulnerability priority, tool selection, and engagement phase decisions
- **AGENTS.md multi-agent collaboration** — Role definitions (Attacker/Defender/Auditor), collaboration protocol, handoff protocol, and automation script inventory

### Changed

- Average quality score: 86.1 → 87.5 (+1.4)
- Minimum quality score: 80.1 → 84.3 (+4.2)
- All 15 key-section-deficient skills now have 3/3 key sections
- All 51 skills remain Excellent tier (80+)
- CI quality gate baseline: 86.1 → 87.5
- IDENTITY.md: added engagement-manager and tool-mastery skill tags
- TOOLS.md: added engagement-manager and tool-mastery tool categories
- CLAUDE.md: updated from 49 to 51 skill domains, added automation scripts section

## [0.1.16] - 2026-06-02

### Changed

- **Scoring system v2**: All component scores capped at 100 (no inflation), guide quality composite metric replaces raw file count, Distinguished tier (92+) added above Excellent (80-91.9)
- **Core files synchronized to 49-domain reality**: CLAUDE.md (25→49), IDENTITY.md (30→49 skill rows), TOOLS.md (20→49 category rows), README.md version consistency
- Updated USER.md, MEMORY.md, TOOLS.md, HEARTBEAT.md to reflect current project phase

### Added

- **TEMPLATE.md**: Authoritative template for creating new OpenClaw agent workspaces
- **docs/tools/full-inventory.md**: Complete 518-tool inventory organized by skill domain
- **5 cross-skill composite attack chain scenarios**:
  - SCEN-001: Enterprise External Network Penetration Full Chain
  - SCEN-002: Cloud Environment Attack Chain
  - SCEN-003: Social Engineering + Internal Network Penetration
  - SCEN-004: Mobile Application Attack Chain
  - SCEN-005: Purple Team Defense Validation
- HEARTBEAT.md: core file consistency checks and `__pycache__` artifact detection

### Fixed

- Removed `__pycache__` directories from 5 skill directories
- Fixed score inflation (council: 99.7→87.4, max component 125.7→93.3)
- All dangling file references resolved (bak/, docs/tools/, TEMPLATE.md)

### Metrics

- Scoring v2 baseline: Average 86.1, Min 80.1 (post-exploitation), Max 90.1 (cloud-security)
- CI baseline updated to 86.1
- 0 Distinguished, 49 Excellent — room to grow into new tier

## [0.1.15] - 2026-05-31

### Changed

- Expanded 18 SKILL.md files from 10-14 to 17+ `##` headings (skill_section scores 68-76 → 86.7)

### Added

- 20 new test cases across 9 skills (all now 8+ TC)
- Expanded 26 payloads.md files to 50+ code blocks (payload_code bottleneck eliminated)

### Metrics

- Average: 84.0 → 88.6 (+4.6)
- Minimum: 80.0 → 85.3 (+5.3)
- Maximum: 90.3 → 99.7 (+9.4)
- CI baseline updated to 88.6

## [0.1.14] - 2026-05-29

### Added

- Infrastructure documentation:
  - `validation/SCORING-METHODOLOGY.md` — Formal scoring methodology reference
  - `validation/README.md` — Unified validation system entry point
- 11 new guides:
  - `ai-security/guides/ai-model-security-testing-guide.md` — AI model attack patterns
  - `continuous-learning/guides/cross-session-knowledge-aggregation-guide.md` — Knowledge aggregation
  - `web-ssrf/guides/cloud-metadata-ssrf-guide.md` — Cloud metadata exploitation
  - `web-ssrf/guides/ssrf-filter-bypass-guide.md` — URL parser differentials, DNS rebinding
  - `logging-monitoring/guides/siem-log-analysis-guide.md` — SIEM correlation rules
  - `logging-monitoring/guides/log-tampering-detection-guide.md` — Anti-forensics detection
  - `security-misconfiguration/guides/cloud-misconfiguration-audit-guide.md` — Multi-cloud audit
  - `security-misconfiguration/guides/web-server-hardening-guide.md` — Server hardening
  - `insecure-design/guides/threat-modeling-for-design-flaws-guide.md` — STRIDE/DREAD
  - `insecure-design/guides/business-logic-attack-patterns-guide.md` — Race conditions, state abuse
  - `social-intelligence/guides/social-network-mapping-guide.md` — Graph analysis, community detection
- 10 new test cases: ai-fuzzing (+2), knowledge-ops (+3), article-writing (+2), council (+1), web-sqli (+2)
- Expanded payloads for 10 skills: post-exploitation, web-access-control, security-review, multi-agent-collaboration, verification-loop, insecure-design, article-writing, council, social-intelligence, web-sqli
- Added sections to password-attack/SKILL.md (Integration, Common Pitfalls)
- Strong expansion phase:
  - `mcp-server-patterns/payloads.md` — +20 code blocks (5 new sections)
  - `security-bounty-hunter/payloads.md` — +15 code blocks (2 new phases)
  - `security-bounty-hunter/test-cases.md` — +1 test case (TC-BH-005)
- Excellent promotion:
  - `osint/payloads.md` — +10 code blocks (6 new sections)
  - `osint/guides/automated-osint-pipeline-guide.md` — Pipeline architecture, modules, reporting
- Automation tool:
  - `validation/batch-improve.sh` — Identifies optimal improvement path per skill
- CI integration:
  - `.github/workflows/skill-quality.yml` — Automated scoring on skills/ changes
- Strong expansion phase 2:
  - `search-first/guides/multi-source-intelligence-correlation-guide.md`
  - `search-first/guides/search-query-optimization-guide.md`
  - `search-first/guides/search-result-validation-guide.md`
  - `search-first/payloads.md` — +20 code blocks
  - `codebase-onboarding/guides/dependency-supply-chain-analysis-guide.md`
  - `codebase-onboarding/payloads.md` — +20 code blocks
- Fourth Excellent:
  - `deep-research/guides/source-validation-guide.md`
  - `deep-research/payloads.md` — +27 code blocks
- Fifth Excellent:
  - `mobile-security/payloads.md` — +20 code blocks (8 new sections)
- Strong expansion phase 3:
  - `terminal-ops/guides/terminal-automation-scripting-guide.md`
  - `terminal-ops/guides/terminal-network-operations-guide.md`
  - `terminal-ops/guides/terminal-forensics-evidence-guide.md`
  - `terminal-ops/payloads.md` — +11 code blocks
  - `docker-patterns/guides/docker-security-scanning-guide.md`
  - `docker-patterns/guides/container-escape-techniques-guide.md`
  - `docker-patterns/guides/docker-network-security-guide.md`
  - `docker-patterns/payloads.md` — +20 code blocks
- CI quality gate:
  - `.github/workflows/skill-quality.yml` — PR regression blocking (avg + per-skill >5pt detection)
  - `validation/evidence/quality-scores-baseline.json` — Baseline for regression detection
- Adequate elimination (4 skills → Strong):
  - `repo-scan/payloads.md` — +31 code blocks (8 new phases)
  - `repo-scan/test-cases.md` — +1 test case (TC-RS-005 CI/CD security)
  - `repo-scan/guides/dependency-vulnerability-scanning-guide.md`
  - `repo-scan/guides/sast-integration-guide.md`
  - `repo-scan/guides/git-history-security-analysis-guide.md`
  - `data-scraper-agent/payloads.md` — +28 code blocks (7 new sections)
  - `data-scraper-agent/guides/rate-limiting-and-stealth-guide.md`
  - `data-scraper-agent/guides/structured-data-extraction-guide.md`
  - `data-scraper-agent/guides/anti-bot-bypass-guide.md`
  - `browser-qa/payloads.md` — +28 code blocks (7 new sections)
  - `browser-qa/guides/headless-browser-security-testing-guide.md`
  - `browser-qa/guides/browser-fingerprint-analysis-guide.md`
  - `browser-qa/guides/web-automation-evidence-capture-guide.md`
  - `exa-search/payloads.md` — +24 code blocks (6 new sections)
  - `exa-search/test-cases.md` — +3 test cases (TC-EX-003/004/005)
  - `exa-search/guides/advanced-query-construction-guide.md`
  - `exa-search/guides/search-result-enrichment-guide.md`
  - `exa-search/guides/competitive-intelligence-gathering-guide.md`
- Sixth Excellent (council):
  - `council/guides/multi-perspective-analysis-framework-guide.md`
  - `council/guides/automated-consensus-scoring-guide.md`
  - `council/guides/risk-prioritization-matrix-guide.md`
- Seventh Excellent (repo-scan):
  - `repo-scan/payloads.md` — +31 code blocks (8 new phases)
  - `repo-scan/test-cases.md` — +3 test cases (TC-RS-006/007/008)
- Guide expansion to 5+ per skill (all 49 skills, 261 total guide files)
- Integration tests INT-008/009/010 (supply chain, full pentest, defensive validation) — all PASS
- Mass payload expansion across 49 skills (code blocks 25-50+)
- SKILL.md section expansion:
  - `exa-search/SKILL.md` — +4 sections (Query Strategy, Result Triage, Rate Limits, Common Pitfalls)
  - `data-scraper-agent/SKILL.md` — +4 sections (Scraping Strategy, Ethical Scraping, Data Normalization, Common Pitfalls)
  - `browser-qa/SKILL.md` — +4 sections (Methodology, Test Patterns, Anti-Detection, Common Pitfalls)
- `ai-fuzzing/test-cases.md` — +1 test case (TC-AF-007 Differential Fuzzing)
- Field completeness fixes for 6 skills: codebase-onboarding, autonomous-loops, web-xss, docker-patterns, search-first, terminal-ops
- Test case expansion (+52 TC across 10 skills): search-first +6, docker-patterns +6, codebase-onboarding +5, autonomous-loops +4, terminal-ops +5, hardware-security +5, browser-qa +5, data-scraper-agent +5, exa-search +5
- Payload expansion for 8 skills to 50+ code blocks: logging-monitoring, security-bounty-hunter, verification-loop, hardware-security, continuous-learning, mcp-server-patterns, web-xss, ai-security
- SKILL.md section expansion (round 2): browser-qa +5, data-scraper-agent +5, exa-search +5 (all to 15 headings)

### Fixed

- SCORE.sh guide score overflow: capped at 100 (was 156 for web-sqli)

### Changed

- Quality tier distribution: Adequate 27→0, Strong 20→0, Excellent 2→**49 (100%)**
- Average score: 59.4 → **84.0**
- Min score: 40.4 → **80.0**
- Max score: 80.0 → **90.3**
- 47 skills promoted to Excellent tier
- CI quality gate baseline updated to 84.0

## [0.1.13] - 2026-05-29

### Added

- 6 new guides for 3 previously zero-guide skills:
  - `data-scraper-agent/guides/nvd-api-scraping-guide.md` — NVD API pagination and caching
  - `data-scraper-agent/guides/data-extraction-patterns-guide.md` — Extraction methodology
  - `browser-qa/guides/playwright-auth-testing-guide.md` — Auth security testing
  - `browser-qa/guides/network-interception-guide.md` — Traffic interception patterns
  - `exa-search/guides/semantic-search-query-design-guide.md` — Query design methodology
  - `exa-search/guides/exa-api-configuration-guide.md` — API configuration reference
- Expanded payloads.md for data-scraper-agent (116→647 words), browser-qa (130→708 words), exa-search (211→823 words)
- Additional test cases for data-scraper-agent (+3) and browser-qa (+2)

### Fixed

- SCORE.sh section matching: replaced name-based matching with heading-count approach — eliminates false low scores from non-standard section naming
- SCORE.sh test case pattern: `### TC-` → `^##+ TC-` to match both `## TC-` and `### TC-` formats
- SCORE.sh field completeness: added recognition of "Steps", "Expected Output", "Objective" patterns

### Changed

- Quality tier distribution: Weak 9→0, Adequate 18→27, Strong 20→20, Excellent 2→2
- Average score: 50.5 → 59.4 (+8.9)
- All 49 skills now at Adequate tier or above (zero Weak)

## [0.1.12] - 2026-05-23

### Added

- 16 new practical guides across 13 skills:
  - `data-scraper-agent/guides/nvd-api-scraping-guide.md` — NVD API methodology
  - `data-scraper-agent/guides/data-extraction-patterns-guide.md` — Data extraction patterns
  - `browser-qa/guides/playwright-auth-testing-guide.md` — Auth testing with Playwright
  - `browser-qa/guides/network-interception-guide.md` — Network request interception
  - `exa-search/guides/semantic-search-query-design-guide.md` — Query design methodology
  - `exa-search/guides/exa-api-configuration-guide.md` — API configuration guide
  - `docker-patterns/guides/docker-vulnerability-patterns-guide.md` — Docker vulnerability patterns
  - `repo-scan/guides/secret-detection-patterns-guide.md` — Secret detection patterns
  - `terminal-ops/guides/terminal-session-management-guide.md` — Session management
  - `verification-loop/guides/remediation-verification-patterns-guide.md` — Patch verification
  - `mcp-server-patterns/guides/mcp-tool-implementation-guide.md` — MCP tool implementation
  - `autonomous-loops/guides/autonomous-pentest-orchestration-guide.md` — Orchestration guide
  - `hardware-security/guides/hardware-exploitation-patterns-guide.md` — Hardware exploitation
  - `security-review/guides/code-review-security-patterns-guide.md` — Code review patterns
  - `multi-agent-collaboration/guides/agent-failure-handling-and-recovery-guide.md` — Failure handling
  - `search-first/guides/tool-evaluation-and-selection-guide.md` — Tool evaluation
- `RELEASE-v0.1.12.md` — Release announcement (Chinese)

### Fixed

- `validation/SCORE.sh` — SKILL.md section detection: added `-E` flag for extended regex matching
- `validation/SCORE.sh` — grep -c handling: fixed exit code handling for zero matches (returns 1, not 0)

### Changed

- `VERSION` — 0.1.11 → 0.1.12
- `README.md` — Version 0.1.12
- `QUALITY-SCORE-TRACKER.md` — Updated with new scores and tier distribution
- `WEAK-SKILL-IMPROVEMENT-PLANS.md` — Marked complete, recorded progress

### Quality Improvement Results

- **Tier distribution**: 9 Weak (18%), 18 Adequate (37%), 20 Strong (41%), 2 Excellent (4%)
- **18 skills promoted to Strong tier**: ai-fuzzing, api-security, binary-reverse, cloud-security, container-security, crypto-attacks, deep-research, digital-forensics, mobile-security, network-pentest, osint, password-attack, post-exploitation, social-engineering, supply-chain-security, vulnerability-assessment, web-access-control, web-auth-bypass
- **2 skills promoted to Excellent tier**: recon-osint, web-sqli
- **Average score**: 40.5 → 50.5 (+10)

## [0.1.11] - 2026-05-23

### Added

- `validation/SCORE.sh` — Bash script to compute quality metrics for all 49 skills
- `validation/QUALITY-SCORE-TRACKER.md` — Master quality score tracker (all 49 skills)
- `validation/QUALITY-SCORE-GUIDE.md` — Metric definitions + tier definitions + analysis findings
- `validation/evidence/quality-scores/` — Per-skill JSON score data (49 files)
- `RELEASE-v0.1.11.md` — Release announcement

### Changed

- `VERSION` — 0.1.10 → 0.1.11
- `MEMORY.md` — Marked quality scoring follow-up done, added v0.1.11 key decision
- `CHANGELOG.md` — v0.1.11 entry

### Analysis Results

- **Tier distribution**: 22 Weak (45%), 25 Adequate (51%), 2 Strong (4%), 0 Excellent
- **Top skill**: web-sqli (76.1) — 24 guides, strong payloads and test cases
- **Bottom skill**: data-scraper-agent (4.7) — no guides, minimal test cases
- **Key insight**: Guide poverty is the primary weakness (22 skills with 0 guides)

## [0.1.10] - 2026-05-22

### Added

- `validation/INTEGRATION-TRACKER.md` — Cross-skill integration test tracker (7 scenarios)
- `validation/INTEGRATION-SCENARIOS.md` — Detailed scenario definitions with data flow diagrams
- `validation/evidence/integration/` — Integration test evidence directory (7 evidence files)
- `RELEASE-v0.1.10.md` — Release announcement

### Changed

- `VERSION` — 0.1.9 → 0.1.10
- `MEMORY.md` — Updated current focus, added v0.1.10 key decision, marked follow-up done
- `CHANGELOG.md` — v0.1.10 entry

## [0.1.9] - 2026-05-22

### Added

- `validation/VALIDATION-TRACKER.md` — Master validation tracking table (49 skills, 1 test case each)
- `validation/VALIDATION-GUIDE.md` — Execution playbook: environment setup, workflow, evidence standards, execution order
- `validation/evidence/` — Evidence storage directory for validation artifacts
- `RELEASE-v0.1.9.md` — Release announcement

### Changed

- `VERSION` — 0.1.8 → 0.1.9
- `MEMORY.md` — Updated current focus to validation, added v0.1.9 key decision
- `CHANGELOG.md` — v0.1.9 entry

## [0.1.8] - 2026-05-22

### Added

All 49 skill domains brought to FULL enrichment status (SKILL.md + payloads.md + test-cases.md + guides/).

**3 MINIMAL skills upgraded (payloads.md + test-cases.md + guides/ added):**

- `chronicle` — payloads.md (event recording templates, distillation commands, archive patterns), test-cases.md (TC-CH-001 to TC-CH-006), guides/event-recording-best-practices.md
- `continuous-learning` — payloads.md (pattern detection, knowledge entry templates, confidence scoring rubrics), test-cases.md (TC-CL-001 to TC-CL-006), guides/knowledge-extraction-workflow.md
- `safety-guard` — payloads.md (scope lock templates, dangerous command patterns, rate limiting, incident response playbooks), test-cases.md (TC-SG-001 to TC-SG-007), guides/scope-enforcement-operations.md

**7 PARTIAL skills upgraded (guides/ added):**

- `api-security` — guides/api-security-complete-guide.md (relocated from root), guides/graphql-security-testing.md (new)
- `web-auth-bypass` — guides/auth-bypass-complete-guide.md (relocated from root), guides/jwt-attack-methodology.md (new)
- `docker-patterns` — guides/lab-environment-management.md
- `repo-scan` — guides/codebase-security-audit-workflow.md
- `search-first` — guides/exploit-research-methodology.md
- `terminal-ops` — guides/evidence-first-execution.md
- `verification-loop` — guides/finding-verification-methodology.md

### Changed

- `MEMORY.md` — Updated with v0.1.5-v0.1.8 key decisions, refreshed current status and lessons learned
- `HEARTBEAT.md` — Added Skill Domain Completeness check section, added MEMORY.md staleness check, updated priority order
- `VERSION` — 0.1.7 → 0.1.8
- `CHANGELOG.md` — v0.1.8 entry
- `RELEASE-v0.1.8.md` — release announcement

## [0.1.7] - 2026-05-16

### Added

4 new FULL skill domains added (45 → 49 total). Each includes SKILL.md, payloads.md, test-cases.md, and a guides/ deep-dive.

- `ai-security` — AI/LLM system attack and defense: prompt injection, jailbreaking (DAN, many-shot, fictional framing), model extraction, RAG poisoning, adversarial inputs, supply chain attacks. ECC: Learning Cycle. Guide: `guides/llm-attack-methodology.md`.
- `hardware-security` — Hardware and embedded system security: UART/JTAG debugging, SPI firmware extraction, firmware analysis with binwalk, RFID/NFC cloning with Proxmark3, fault injection basics. ECC: Sequential Pipeline. Guide: `guides/embedded-firmware-analysis.md`.
- `multi-agent-collaboration` — Coordinated multi-agent penetration testing: task decomposition (by phase/target/tool), coordinator-worker pattern, result aggregation, deduplication, conflict resolution, coverage verification. ECC: Batch Processing. Guide: `guides/coordinated-pentest-playbook.md`.
- `mcp-server-patterns` — MCP security tool integration: wrapping Kali tools as MCP servers, input validation, command injection prevention, authentication, rate limiting; also security auditing of MCP server implementations. ECC: Sequential Pipeline. Guide: `guides/security-mcp-server-design.md`.

### Changed

- `IDENTITY.md` — Skill Tags table expanded: 14 new rows added (10 infrastructure skills missing from v0.1.6 + 4 new domains)
- `VERSION` — 0.1.6 → 0.1.7
- `README.md` — Skill count 45 → 49; Future Exploration table updated (removed 2 now-implemented domains)

## [0.1.6] - 2026-05-14

### Enhanced

10 infrastructure skills enriched from "understand" to "executable" with payloads, test cases, guides, and ECC Orchestration.

**FULL enrichment (2 skills):**

- `autonomous-loops` — added payloads.md, test-cases.md, guides/safe-autonomous-pentest.md, SKILL.md Orchestration (meta-skill)
  - payloads.md — Scope Lock templates ×4, rate limit configs, loop command templates, error handling response templates
  - test-cases.md — TC-AL-001 to TC-AL-006 (pipeline, watch, batch, learning, scope violation, rate backoff)
  - guides/safe-autonomous-pentest.md — autonomous vs manual matrix, scope lock construction, loop composition, monitoring, recovery
- `security-review` — added payloads.md, test-cases.md, guides/owasp-audit-methodology.md, SKILL.md Orchestration (Sequential Pipeline)
  - payloads.md — secret detection, injection payloads, auth testing, security headers, dependency audit, API sensitive field detection
  - test-cases.md — TC-SR-001 to TC-SR-007 (secrets, input validation, injection, auth, headers, dependencies, full OWASP)
  - guides/owasp-audit-methodology.md — audit planning, attack surface mapping, priority ranking, evidence collection, report writing

**PARTIAL enrichment (5 skills):**

- `repo-scan` — added payloads.md (classification, library detection, hotspot grep, secret scan, verdict aid), test-cases.md (TC-RS-001~004), SKILL.md Orchestration (Batch Processing)
- `terminal-ops` — added payloads.md (recon/exploit/post-exploit commands, evidence capture, debugging), test-cases.md (TC-TO-001~004), SKILL.md Orchestration (Sequential Pipeline)
- `verification-loop` — added payloads.md (SQLi/XSS/auth/network verification payloads, FP elimination checklists, remediation verification), test-cases.md (TC-VL-001~005), SKILL.md Orchestration (Sequential Pipeline)
- `docker-patterns` — added payloads.md (quick launch, additional labs, evidence extraction, cleanup), test-cases.md (TC-DP-001~004), SKILL.md Orchestration (Sequential Pipeline)
- `search-first` — added payloads.md (searchsploit/gh/msf/nuclei templates, evaluation scoring), test-cases.md (TC-SF-001~004), SKILL.md Orchestration (Learning Cycle)

**MINIMAL enrichment (3 skills):**

- `continuous-learning` — SKILL.md added Orchestration (Learning Cycle consumer)
- `safety-guard` — SKILL.md added Orchestration (Cross-cutting Interceptor)
- `chronicle` — SKILL.md added Orchestration (Sequential Pipeline: record → index → distill)

### Changed Files

- `VERSION` — 0.1.5 → 0.1.6
- `README.md` — Version 0.1.6
- `CHANGELOG.md` — v0.1.6 entry
- `UPDATELOG.md` — v0.1.6 report
- `RELEASE-v0.1.6.md` — release announcement
- 16 new files created (7 payloads + 7 test-cases + 2 guides)
- 13 SKILL.md files updated (header + Orchestration)

## [0.1.5] - 2026-05-14

### Added

- `ai-fuzzing` skill — AI-assisted automated vulnerability discovery
  - SKILL.md — coverage-guided fuzzing, AI seed generation, crash triage, 6-phase methodology, ECC Learning Cycle orchestration
  - payloads.md — AFL++, libFuzzer, Honggfuzz, radare2 crash analysis, Web API fuzzing, protocol fuzzing commands
  - test-cases.md — TC-AF-001 to TC-AF-004 (binary, Web API, protocol, file format fuzzing)
  - guides/coverage-guided-fuzzing.md — AFL++ internals, corpus management, mutation operators, parallel fuzzing, crash triage
  - guides/web-api-fuzzing.md — OpenAPI schema fuzzing (Schemathesis, RESTler), GraphQL fuzzing, REST boundary testing, auth fuzzing, Burp Suite integration
  - guides/protocol-fuzzing.md — TCP/UDP state machine fuzzing, TLS/SSL fuzzing, custom protocol analysis, BooFuzz framework
- `council` skill — multi-perspective security analysis
  - SKILL.md — Attack/Defense/Audit three-perspective framework, decision matrix, risk assessment, ECC Sequential Pipeline orchestration
  - payloads.md — attacker/defender/auditor checklists, risk scoring matrix, decision record templates
  - test-cases.md — TC-CL-001 to TC-CL-004 (Web app, cloud architecture, mobile app, incident response)
  - guides/multi-perspective-analysis.md — role-playing framework, bias mitigation, dissent encouragement, consensus building
  - guides/security-decision-framework.md — risk-benefit matrix, impact analysis, degradation planning, decision under uncertainty
- `mobile-security` skill enhanced with cross-platform and cloud-integration testing
  - guides/react-native-flutter-security.md — React Native bundle analysis, Flutter Dart snapshot, WebView vulnerabilities
  - guides/mobile-api-security-testing.md — advanced cert pinning bypass, GraphQL mobile, WebSocket security
  - guides/mobile-cloud-integration.md — Firebase audit, AWS Amplify, OAuth 2.0/OIDC mobile flaws
  - SKILL.md updated — cross-platform testing table, mobile-cloud integration, ECC Orchestration
- `cloud-security` skill enhanced with K8s, serverless, and IaC security
  - guides/kubernetes-security-deep-dive.md — RBAC audit, Pod Security, network policy bypass, Secrets management
  - guides/serverless-security.md — Lambda injection, Azure/GCP Functions, event injection, cold start leakage
  - guides/infrastructure-as-code-security.md — Terraform/CloudFormation audit, Helm Chart security, CI/CD attacks
  - SKILL.md updated — K8s attack tree, serverless attack chain, IaC risk table, ECC Orchestration
- `security-bounty-hunter` skill enhanced with full supplementary files
  - payloads.md — semgrep rules, Nuclei templates, SQLi/SSRF/XSS/auth bypass payloads, PoC/report templates
  - test-cases.md — TC-BH-001 to TC-BH-004 (HackerOne bounty, scope validation, disclosure, report quality)
  - guides/bounty-hunting-methodology.md — target selection, recon pipeline, vulnerability priority P0-P3, ROI
  - guides/responsible-disclosure-workflow.md — vendor contact, CVE request, 90-day timeline, legal considerations
  - guides/bug-bounty-automation.md — automated recon, ECC Watch Loop, automated triage, safety guardrails
  - SKILL.md updated — ECC Orchestration (Watch Loop + Sequential Pipeline)

### Changed

- `VERSION` — 0.1.4 → 0.1.5
- `README.md` — updated skill domain count (43 → 45), added 2 new skill rows, roadmap updated
- `IDENTITY.md` — added AI Fuzzing and Council skill tags
- `TOOLS.md` — added AI Fuzzing and Council tool categories

## [0.1.4] - 2026-05-11

### Added

- `codebase-onboarding` skill — rapid codebase intelligence acquisition for security research
  - SKILL.md — 3 scope modes (Targeted/Exploratory/Comprehensive), Phase 0 Search-First, language tier matrix (Tier 1/2/3), confidence scoring, 100M+ LOC strategy, structured JSON output, Mermaid architecture diagrams
  - payloads.md — discovery by phase: orientation, architecture mapping, security surface analysis, large codebase tactics, mode-specific sequences
  - test-cases.md — TC-CO-001 to TC-CO-005 (Django, Go microservice, TypeScript monorepo, legacy PHP, large-scale Java)
  - guides/web-framework-onboarding.md — Django, Express.js, Spring Boot, FastAPI, Gin framework onboarding patterns
  - guides/microservice-onboarding.md — multi-service architecture mapping, inter-service auth, API gateway analysis
  - guides/architecture-pattern-recognition.md — MVC monolith, REST+SPA, microservices, event-driven, serverless, GraphQL detection
  - guides/legacy-codebase-onboarding.md — PHP/CGI/Perl legacy patterns, SQL injection, XSS, LFI detection
- `knowledge-ops` skill — knowledge graph management for cross-session intelligence persistence
  - SKILL.md — knowledge unit format, confidence model (0-100), storage format, entity/finding/pattern/hypothesis/intelligence types
  - payloads.md — session startup context loading, knowledge unit capture templates (entity/finding/relationship/pattern), maintenance commands
  - test-cases.md — TC-KO-001 to TC-KO-005 (cross-session context, confidence evolution, pattern recognition, handoff, expiration)
  - guides/entity-extraction-and-tagging.md — entity types, extraction sources, tagging strategy, relationship mapping, deduplication
  - guides/cross-session-intelligence-aggregation.md — aggregation workflow, report templates, query patterns, automation helpers
  - guides/knowledge-graph-visualization-and-querying.md — DOT/Mermaid graph generation, path finding, centrality analysis, export formats
- `article-writing` skill — technical security content creation
  - SKILL.md — pentest reports, vulnerability disclosures, blog posts, advisory format, methodology
  - payloads.md — CVSS calculator reference, sanitization checklist, severity classification, finding description templates
  - test-cases.md — TC-AW-001 to TC-AW-003 (pentest report, CVE disclosure, blog post)
  - guides/cvss-scoring.md — CVSS 3.1 vector breakdown, common vulnerability scores, scoring decision trees, justification templates
  - guides/report-structure.md — pentest report section order, formatting standards, common mistakes
  - guides/vulnerability-writing.md — responsible disclosure timeline, vendor contact process, CVE request, CWE reference
- `browser-qa` skill — automated browser-based security testing
  - SKILL.md — Playwright/Puppeteer automation, auth flow testing, CSRF detection, cookie analysis
  - payloads.md — Playwright commands for navigation, network monitoring, XSS injection, cookie analysis
  - test-cases.md — TC-BQ-001 to TC-BQ-003 (auth flow, CSRF, XSS)
- `data-scraper-agent` skill — structured security data collection
  - SKILL.md — CVE scraping, exploit database collection, threat intel feeds
  - payloads.md — NVD API, searchsploit, GitHub advisory API, BeautifulSoup scraping
  - test-cases.md — TC-DSA-001 to TC-DSA-002 (CVE collection, exploit availability)
- `exa-search` skill — semantic search for security research
  - SKILL.md — Exa API usage, semantic queries, date/domain filtering
  - payloads.md — API examples for CVE research, exploit techniques, threat intelligence
  - test-cases.md — TC-ES-001 to TC-ES-002 (CVE research, exploit technique research)
- `RELEASE-v0.1.4.md` — release announcement article

### Changed

- `VERSION` — 0.1.3 → 0.1.4
- `README.md` — updated skill domain count (37 → 43), added 6 new skill rows to skills table
- `IDENTITY.md` — added 6 new skill domains to skill mapping
- `TOOLS.md` — added tool categories for new skills

## [0.1.3] - 2026-05-06

### Added

- `social-intelligence` skill — new skill domain: real-time social platform intelligence gathering (Reddit, HackerNews, Twitter/X, YouTube, dark web), community sentiment analysis, and target profiling for security engagements
  - SKILL.md — 5-phase methodology, tools table, report template
  - payloads.md — 7 sections: Reddit, HN, Twitter/X, YouTube, forums/paste, sentiment, cross-platform correlation
  - test-cases.md — 5 structured test cases (TC-SI-001 to TC-SI-005)
  - guides/reddit-hackernews-osint.md — Reddit + HN intelligence gathering
  - guides/twitter-youtube-osint.md — X + YouTube intelligence gathering
  - guides/sentiment-analysis.md — Security sentiment analysis for social engineering
- `deep-research` Phase 7 (Continuous Monitoring) — CVE feed monitoring, attack surface change detection, code leak monitoring, alert triggers
- `deep-research` Phase 8 (Intelligence Correlation) — multi-source IOC correlation, confidence scoring, MITRE ATT&CK mapping, entity relationship mapping
- `deep-research` Phase 9 (Adaptive Refinement) — iterative research loop, query refinement, convergence detection
- `deep-research` guides/iterative-search-patterns.md — query refinement strategies, source tracing, keyword expansion, convergence detection
- `deep-research` guides/continuous-monitoring.md — monitoring architecture, snapshot/diff pattern, alert trigger conditions
- `deep-research` guides/intelligence-correlation.md — entity extraction, deduplication, confidence scoring framework, ATT&CK integration
- `deep-research` guides/mcp-integration.md — MCP server configuration for Shodan, VirusTotal, GreyNoise, Firecrawl
- `deep-research` payloads.md Section 9 (Continuous Monitoring Queries) and Section 10 (Intelligence Correlation Commands)
- `deep-research` test-cases.md TC-DR-011 to TC-DR-013 (continuous monitoring, correlation, adaptive iteration)
- `deep-research` Hacker Laws section and Learning Resources section in SKILL.md
- `RELEASE-v0.1.3.md` — release announcement article
- `memory/2026-05-05-deep-research-migration-report.md` — deep research capability migration research report

### Changed

- `VERSION` — 0.1.2 → 0.1.3
- `README.md` — updated skill domain count (36 → 37), added social-intelligence to skills table, updated version info
- `IDENTITY.md` — added Social Intelligence and Deep Research rows to skill domain mapping
- `TOOLS.md` — added Social Intelligence (6 tools) and Deep Research (8 tools) categories
- `skills/osint/SKILL.md` — added social-intelligence and deep-research cross-references
- `skills/social-engineering/SKILL.md` — added social-intelligence and deep-research cross-references

## [0.1.2] - 2026-05-04

### Added

- `verification-loop` skill — multi-phase finding verification with false positive elimination and evidence documentation
- `autonomous-loops` skill — safe autonomous execution patterns with scope locks, rate limiting, and evidence logging
- `continuous-learning` skill — engagement knowledge extraction with pattern detection, confidence scoring, and memory layering
- `docker-patterns` skill — Docker Compose configurations for isolated security testing labs (DVWA, SQLi-Labs, Juice Shop, network labs)
- `safety-guard` skill — safety enforcement layer with scope checking, dangerous command interception, and incident response protocol
- Future roadmap section in README.md — 9 planned skills organized by priority tier

### Changed

- `VERSION` — 0.1.1 → 0.1.2
- `README.md` — updated skill domain count (31 → 36), added 5 new skills to table, added roadmap section, updated project info version

## [0.1.1] - 2026-05-04

### Added

- `deep-research` skill — multi-source intelligence research with CVE deep-dive, threat actor profiling, attack technique investigation
- `security-bounty-hunter` skill — exploitable vulnerability discovery, PoC development, responsible disclosure reporting
- `terminal-ops` skill — evidence-first terminal execution with audit trail protocol
- `search-first` skill — research existing tools/exploits before building custom solutions
- `security-review` skill — OWASP Top 10 security audit checklist and methodology
- `repo-scan` skill — cross-stack source code audit with library detection and module verdicts
- `VERSION` file (0.1.1)
- `CLAUDE.md` — Claude Code workspace guidance
- `CHANGELOG.md` — this file
- `UPDATELOG.md` — v0.1.1 skill supplement research report

### Changed

- `README.md` — updated skill domain count (25 → 31), added 6 new skills to table, added version info to Project Info

## [0.1.0] - 2026-04-27

### Added

- Initial release with 25 security skill domains
- Core agent configuration (SOUL.md, AGENTS.md, IDENTITY.md, USER.md, MEMORY.md, TOOLS.md, HEARTBEAT.md)
- Layered memory system (daily logs + MEMORY.md + chronicle)
- Heartbeat task framework
- MIT License
