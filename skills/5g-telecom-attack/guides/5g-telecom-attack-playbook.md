# 5G Telecom Attack Playbook — End-to-End Red Team Workflow Guide

> Deep-dive companion to `skills/5g-telecom-attack/SKILL.md`.
>
> Audience: red teamers, telecom security engineers, and operator-side CSIRT members who know what NGAP, PFCP, GTP, Diameter, and SS7 are, and want a battle-tested playbook for taking a 5G standalone core, an O-RAN deployment, or a roaming interconnect from initial scope to coordinated disclosure — without missing the bug that takes down the network.

---

## Introduction

This playbook is the operational guide for the `5g-telecom-attack` skill. The companion `SKILL.md` defines the domain; the `payloads.md` lists working commands; the `test-cases.md` enumerates structured test cases. This playbook ties them together into a workflow that scales from a $500 software-only lab to a multi-week operator-side engagement against a production 5G core.

The cellular network is one of the largest and most regulated attack surfaces on earth. Every smartphone on the planet depends on it; every national government considers it critical infrastructure; every operator has a CSIRT, a regulatory reporting obligation, and a roaming agreement with every other operator on the planet. Engagements against this surface differ from typical IT pentests in three ways:

1. **Legal regime is different** — Transmission on licensed cellular bands requires an operator license in every jurisdiction (US: FCC Part 22/25/97; EU: national spectrum regulators; China: MIIT). Passive reception is generally legal but verify per jurisdiction. SS7/Diameter messages against a production operator require explicit roaming-partner authorization and may be criminalized (e.g., UK Computer Misuse Act, US CFAA) without it.
2. **Scope is tiered, not holistic** — A 5G system is three networks: RAN, 5GC, and roaming interconnect. Most engagements target one tier. A RAN engagement (SDR + gNB testing) has a different shape, different tools, and different regulatory exposure than a 5GC SBI engagement (HTTP/2 + JSON fuzzing) or a roaming interconnect engagement (SEPP + Diameter testing).
3. **Disclosure is operator-to-operator, not vendor-to-vendor** — Most telecom findings are coordinated via GSMA FS-IS (Fraud and Security Intelligence Group), 3GPP SA3 Liaison, and the operator's CSIRT. Public CVE-style disclosure is rare and usually delayed 6-18 months to allow operator-wide remediation.

This playbook walks through scope confirmation, architecture refresher, lab build, signaling methodology, real-world incidents, and operational considerations — in that order — with the exact commands, decision points, and 3GPP/NIST/ENISA references.

---

## 1. 5G Core Architecture Refresher

### 1.1 The Service-Based Architecture (SBA)

5G introduced a fundamental architectural shift from 4G/LTE: the **Service-Based Architecture (SBA)**. In 4G, network elements (MME, SGW, PGW, HSS) communicated via point-to-point reference interfaces (S1-MME, S11, S6a, etc.) over SCTP/Diameter/GTP-C. In 5G, network functions (NFs) communicate via a common **Service-Based Interface (SBI)** over HTTP/2 with JSON payloads.

The 11 Network Functions of the 5G Core (5GC):

| NF | Full Name | Role | 4G Equivalent |
|----|-----------|------|----------------|
| **AMF** | Access and Mobility Management Function | NAS signaling termination, mobility mgmt, UE registration | MME |
| **SMF** | Session Management Function | PDU session establishment, IP allocation, PFCP to UPF | SGW-C + PGW-C |
| **UPF** | User Plane Function | GTP-U handling, packet forwarding, QoS enforcement | SGW-U + PGW-U |
| **AUSF** | Authentication Server Function | 5G AKA authentication, EAP-AKA' | Part of HSS |
| **UDM** | Unified Data Management | Subscriber data store, generates auth vectors | HSS |
| **UDR** | Unified Data Repository | Database backend for UDM and PCF | HSS backend |
| **PCF** | Policy Control Function | QoS policy, charging rules | PCRF |
| **NRF** | Network Repository Function | NF discovery, service inventory | (new in 5G) |
| **NSSF** | Network Slice Selection Function | Slice selection per UE | (new in 5G) |
| **NEF** | Network Exposure Function | 3rd-party API exposure | SCEF |
| **SEPP** | Security Edge Protection Proxy | N32 roaming security | (new in 5G) |

### 1.2 Reference Points (N1-N11 and beyond)

| Reference Point | Between | Protocol | Purpose |
|-----------------|---------|----------|---------|
| N1 | UE ↔ AMF | NAS-5GS | NAS signaling (registration, auth, session mgmt) |
| N2 | gNB ↔ AMF | NGAP/SCTP | Radio + NAS signaling transport |
| N3 | gNB ↔ UPF | GTP-U/UDP | User plane tunneling |
| N4 | SMF ↔ UPF | PFCP/UDP | Session and forwarding rule control |
| N6 | UPF ↔ DN | IP | Egress to data network (internet) |
| N7 | SMF ↔ PCF | SBI/HTTP-2 | Policy retrieval |
| N8 | AMF ↔ UDM | SBI/HTTP-2 | Subscriber data |
| N9 | UPF ↔ UPF | GTP-U/UDP | Inter-UPF roaming |
| N10 | SMF ↔ UDM | SBI/HTTP-2 | Session subscriber data |
| N11 | AMF ↔ SMF | SBI/HTTP-2 | Session management coordination |
| N12 | AMF ↔ AUSF | SBI/HTTP-2 | Authentication |
| N14 | AMF ↔ AMF | SBI/HTTP-2 | Inter-AMF handover |
| N22 | AMF ↔ NSSF | SBI/HTTP-2 | Slice selection |
| N32 | SEPP ↔ SEPP | HTTPS/JWS+JWE | Roaming interconnect |

### 1.3 Subscriber Identity: SUPI, SUCI, 5G-GUTI

5G inherits IMSI from 4G but renames it **SUPI** (Subscriber Permanent Identifier). The critical 5G privacy improvement is **SUCI** (Subscriber Concealed Identifier) — the SUPI encrypted with the operator's home network public key before being sent on the air.

| Identifier | When Used | Privacy |
|------------|-----------|---------|
| **SUPI** | Permanent identifier, stored on USIM, in UDM | Permanent; never sent cleartext on 5G air interface |
| **SUCI** | Sent in RegistrationRequest on initial attach | ECIES-encrypted SUPI; decryption requires operator's home network private key |
| **5G-GUTI** | Temporary identifier, allocated by AMF | Reallocated periodically; the 5G equivalent of 4G GUTI. Used to prevent tracking |
| **PEI** | Permanent Equipment Identifier | IMEI of the device; sent with SUPI on initial attach |

### 1.4 Authentication: 5G AKA vs EAP-AKA'

5G supports two primary authentication methods:

- **5G AKA** (3GPP TS 33.501 §6.1.3) — Successor to 4G EPS-AKA. Home network (UDM/AUSF) generates a 5G authentication vector (RAND, AUTN, XRES*, HA*). Visited network (AUSF) sends the challenge to the UE; UE computes RES* and returns it. AUSF verifies RES* matches XRES*.
- **EAP-AKA'** (RFC 5448) — Used when the operator deploys EAP-based authentication, typically for non-3GPP access (e.g., untrusted Wi-Fi to 5GC via N3IWF).

The critical difference from 4G: in 5G AKA, the **RES* is sent from the UE to the visited AUSF, not to the home HSS**. This means a malicious visited network cannot replay the RES* to the home network (it doesn't have it). This is a real improvement over 4G EPS-AKA, which had the visited network forwards RES to home — enabling replay-based tracking.

---

## 2. Building a 5G Lab

### 2.1 The Canonical Lab: Open5GS + UERANSIM

The minimum viable 5G lab for engagement reproduction:

- **Hardware**: Any Linux server with 16+ cores, 32GB+ RAM, 100GB+ disk. No SDR required.
- **OS**: Kali Linux 2025-2, Ubuntu 22.04 LTS, or Debian 12.
- **5GC**: Open5GS (open-source, AGPL-3.0, C).
- **gNB + UE**: UERANSIM (open-source, GPL-3.0, C++).
- **Total cost**: ~$500 (server only) or $0 (reuse existing hardware).

Bring-up commands (full configs in `payloads.md` §1):

```bash
# Clone the canonical lab
git clone https://github.com/open5gs/open5gs /opt/open5gs
cd /opt/open5gs/docker
docker compose up -d

# Wait ~15 seconds for NFs to register
docker compose ps
# Expected: amf, smf, upf, nrf, ausf, udm, udr, pcf, nssf, webui all "Up"

# Verify NRF knows all NFs
curl -sk https://127.0.0.10:7777/nnrf-nfm/v1/nf-instances | jq '.nfInstance[].nfType'
# Expected: ["AMF","SMF","UPF","AUSF","UDM","UDR","PCF","NSSF","NRF"]

# Build UERANSIM
git clone https://github.com/aligungr/UERANSIM /opt/UERANSIM
cd /opt/UERANSIM
sudo apt install -y make g++ libsctp-dev
make -j$(nproc)

# Configure gNB and UE (see payloads.md §1.3)
# Launch gNB
./nr-gnb -c config/open5gs-gnb.yaml
# In another shell, launch UE
./nr-ue -c config/open5gs-ue.yaml
# Expected: "PDU session established, IPv4: 10.45.0.x"

# End-to-end data path test
docker exec ue ping -c 3 1.1.1.1
# Expected: ping succeeds through UPF
```

### 2.2 Alternative Labs

| Lab Stack | 5GC | gNB/UE | SDR Required | Cost | Use Case |
|-----------|-----|--------|--------------|------|----------|
| **Open5GS + UERANSIM** | Open5GS | UERANSIM | No | Free | Fastest bring-up; pure software; default for 5GC testing |
| **free5GC + UERANSIM** | free5GC | UERANSIM | No | Free | Alternative 5GC; Go-based; useful for cross-validation |
| **Open5GS + srsRAN** | Open5GS | srsRAN_Project | Yes (USRP/BladeRF) | ~$2,000 | RF-in-the-loop; O-RAN research; PHY-level testing |
| **Open5GS + Amarisoft** | Open5GS | Amarisoft | Yes | Commercial | Reference gNB; vendor interoperability |
| **srsRAN end-to-end** | srsRAN CN | srsRAN gNB + UE | Optional | Free | Full srsRAN stack; useful for O-RAN |

### 2.3 SDR Hardware Selection (for RAN Engagements)

| SDR | Frequency | Bandwidth | Cost (USD) | Best For |
|-----|-----------|-----------|------------|----------|
| HackRF One | 1 MHz - 6 GHz | 20 MHz | ~$300 | Passive survey; low budget |
| BladeRF 2.0 micro (xA4) | 47 MHz - 6 GHz | 61 MHz | ~$480 | Full-duplex; n78 5G coverage |
| BladeRF 2.0 micro (xA9) | 47 MHz - 6 GHz | 61 MHz | ~$720 | Larger FPGA; recommended for serious RAN work |
| USRP B210 | 70 MHz - 6 GHz | 56 MHz | ~$1,400 | Reference; best srsRAN support |
| USRP N310 | 100 MHz - 6 GHz | 100 MHz | ~$3,500 | Lab-grade; gNB-class research |
| USRP X310 | 10 MHz - 6 GHz | 120 MHz | ~$4,500 | Production-grade gNB |

For most engagements: BladeRF 2.0 micro xA9 is the sweet spot. HackRF is sufficient for passive IMSI catcher detection. USRP B210 is the reference for active transmission work.

### 2.4 Operator-Scale Testbed

For engagements requiring operator-scale infrastructure (production HSS, multiple UPFs, SEPP):

- **Mavenir, Parallel Wireless, Altiostar** — Commercial O-RAN stacks. Engagement via vendor or operator.
- **Amarisoft** — Commercial 5G/LTE base station stack (L1/L2/L3). Used as reference gNB in operator labs.
- **Keysight UeSimulator, Anritsu MD8475B** — Commercial UE simulators for conformance testing. Useful for reproducing subscriber-side attack scenarios.

---

## 3. Signaling Attack Methodology

### 3.1 Phase 1: Passive Reconnaissance

The first phase is passive (capture only, no transmission). For a 5GC SBI engagement:

```bash
# From a vantage point on the operator's internal network (engagement-scoped):

# Identify the NRF SBI endpoint
nmap -p 443,7777,8080 <nrf-ip-range>

# Fingerprint the SBI implementation
curl -sk -I https://<nrf-ip>:7777/ | grep -i server
# Known signatures:
#   Open5GS: server: Open5GS v2.7.x
#   free5GC: server: free5GC v3.4.x
#   Amarisoft: server: Amarisoft
#   Mavenir: server: nginx (Mavenir X- headers)

# Enumerate registered NFs (unauthenticated in lab; authenticated in production)
curl -sk https://<nrf-ip>:7777/nnrf-nfm/v1/nf-instances | jq '.nfInstance[] | {nfType, ipv4Addresses, nfServices}'
# This is the 5GC equivalent of `Get-ADUser -Filter *` from ad-ldap-attack.

# Identify the AMF NGAP (N2) endpoint
/opt/sctpscan/sctpscan -a <amf-ip> -p 38412 -v
nmap -p 38412 --script=sctp-init <amf-ip>

# Identify the SMF PFCP (N4) endpoint
nmap -sU -p 8805 <smf-or-upf-ip>
```

### 3.2 Phase 2: Signaling Analysis (Active Capture)

Trigger legitimate signaling and capture every protocol layer:

```bash
# Multi-protocol capture in one pass
sudo tshark -i any -f 'sctp port 38412 or sctp port 3868 or udp port 8805 or udp port 2152 or tcp port 7777' \
  -Y 'ngap || pfcp || gtp || nas-5gs || diameter || http2' \
  -w /tmp/5gc-baseline.pcap

# Trigger a subscriber registration
docker exec ue /UERANSIM/build/nr-ue -c /etc/ueransim/ue.yaml &

# Wait for registration, then trigger some data traffic
docker exec ue ping -c 30 1.1.1.1 &

# Stop capture and analyze
tshark -r /tmp/5gc-baseline.pcap -Y ngap -V | head -100   # NGAP setup
tshark -r /tmp/5gc-baseline.pcap -Y nas_5gs -V | head -100  # NAS registration + auth + security mode
tshark -r /tmp/5gc-baseline.pcap -Y pfcp -V | head -100     # PFCP session establishment
tshark -r /tmp/5gc-baseline.pcap -Y gtp -V | head -100      # GTP-U tunnel
```

### 3.3 Phase 3: Attack Vector Validation

Validate each discovered attack vector with a PoC. Document the exact packet structure, the expected (hardened) and actual (vulnerable) behavior, and the impact in subscriber-count terms.

#### PFCP Source Authentication Check

```bash
# Send a PFCP Heartbeat Request from a non-SMF source IP
python3 - <<'EOF'
import socket, struct
pfcp_header = struct.pack('!BBIB', 0x20, 0x01, 0x00000001, 0x00)
node_id = struct.pack('!BBH', 60, 0, 5) + socket.inet_aton('10.0.0.99')  # attacker IP
ts = struct.pack('!BBHI', 96, 0, 4, 1700000000)
msg = pfcp_header + node_id + ts
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(msg, ('<upf-ip>', 8805))
EOF

# Capture the response
sudo tshark -i any -f 'udp port 8805' -Y pfcp -c 5 -V | grep -A2 'Heartbeat'
# If the UPF responds: it does NOT validate source IP (vulnerable to Praetorian class)
# If no response: source IP filtering is enforced (hardened)
```

#### GTP-U Injection PoC

```bash
# Capture a valid TEID from a subscriber session
sudo tshark -i any -f 'udp port 2152' -Y gtp -w /tmp/gtpu.pcap &
sleep 5
sudo killall tshark
tshark -r /tmp/gtpu.pcap -Y gtp -T fields -e gtp.teid | sort -u | head -1
# Output: a valid TEID, e.g. 0x01000001

# Inject a GTP-U packet with the captured TEID (see payloads.md §6.3 for script)
python3 gtpu-injection-poc.py <upf-ip> 0x01000001
# On the UE, run: tcpdump -ni uesimtun0 'tcp and src host 203.0.113.42'
# If the crafted packet appears: GTP-U injection confirmed
```

#### SEPP Topology Hiding Check

```bash
# Capture N32-f traffic between visited and home SEPP
sudo tshark -i any -f 'host <sepp-ip> and tcp port 443' -w /tmp/n32f.pcap
# Verify that internal NF IPs are NOT visible in the captured traffic
tshark -r /tmp/n32f.pcap -Y http2 -V | grep -E '10\.|172\.|192\.168\.'
# Expected (hardened): no internal IPs visible
# If internal IPs are visible: topology hiding is NOT enforced (vulnerable)
```

### 3.4 Phase 4: Exploitation (Scoped)

For each validated attack vector, scope and execute the exploitation:

- **PFCP DoS**: Iterate PFCP Session Deletion across the SEID space at a controlled rate (e.g., 10/sec, not 10,000/sec). Document impact in subscriber-session terms.
- **GTP-U injection**: One crafted packet per TEID, with engagement-agreed inner payload (e.g., benign ICMP echo to a sinkhole). Never inject malicious payloads.
- **Subscriber traffic redirection**: Mirror only, with explicit per-engagement scope. Never exfiltrate beyond agreed sample size.
- **Diameter roaming abuse**: Use engagement-scoped test IMSIs (test PLMN 001/01) only. Never target production subscriber IMSIs without explicit authorization.

### 3.5 Phase 5: Reporting & Disclosure

```markdown
## Report Structure (Operator-Grade)

1. Executive Summary
   - Engagement scope, duration, team
   - High-level findings (count by severity)
   - Regulatory impact (NIS2 / FCC / GSMA FS-IS notification)

2. Architecture Overview
   - 5GC topology diagram (NF inventory from NRF)
   - RAN topology (cell sites, gNB models)
   - Roaming interconnect (SEPP, Diameter, SS7)

3. Findings (per severity)
   - Title, severity, CVSS, MITRE ATT&CK
   - Description (what is the vuln, where, why)
   - Reproduction (exact commands, packet captures)
   - Impact (subscriber count, blast radius)
   - Remediation (3GPP spec reference, e.g., TS 33.501 §6.6.2)

4. Evidence
   - PCAP files (timestamped, hashed)
   - Log extracts (operator-scoped, redacted)
   - Screenshots (where applicable)

5. Disclosure
   - GSMA FS-IS coordinated disclosure reference
   - 3GPP SA3 liaison (if spec-level)
   - Operator's CSIRT contact
   - Regulator notification status (NIS2 / FCC / national CERT)

6. Appendices
   - Full test case results (TC-5G-001..012)
   - Raw command output
   - References (3GPP TS, NIST, ENISA, GSMA)
```

---

## 4. Real-World Incidents

### 4.1 Karsten Nohl — SS7 Exploitation (2014-2016)

**What**: At 31C3 (December 2014) and BlackHat (July 2016), Karsten Nohl demonstrated SS7-based location tracking, call interception, and SMS interception of members of multiple national governments.

**Class**: SS7 MAP abuse via roaming interconnect. The core issue: SS7 MAP messages (Provide-Subscriber-Info, Any-Time-Interrogation, Send-Authentication-Info) were accepted from any roaming peer without verifying that the target subscriber was actually roaming on that peer's network.

**Impact**: Demonstrated location tracking and SMS interception of cabinet-level government officials in multiple countries. Forced GSMA to publish FS.32 SS7 recommendations (2014) and operators to begin deploying SS7 firewalls (2015-2020).

**Engagement lesson**: SS7 testing against production operators is the most legally sensitive telecom engagement class. Reproduce only in closed labs (OsmoHLR + ss7MAPer). For operator-side SS7 firewall validation, coordinate via GSMA FS-IS.

### 4.2 Praetorian — 5G Standalone Core PFCP DoS (2019)

**What**: Praetorian (2019-2020) demonstrated that several 5G standalone core implementations did not authenticate the source of PFCP messages on the N4 interface. An attacker who could reach the N4 interface (UDP 8805) could send PFCP Session Deletion Requests for any captured SEID, tearing down the subscriber's session.

**Class**: PFCP source authentication bypass. The core issue: 3GPP TS 29.244 does not mandate source authentication on N4; many implementations trust the source IP (which is forgeable on the operator's internal network).

**Impact**: Per-subscriber session teardown DoS. At scale (iterating across the SEID space), mass session teardown affecting all subscribers served by the UPF.

**Engagement lesson**: Always test PFCP source authentication in 5GC engagements. The Praetorian PoC is trivially reproducible in Open5GS lab.

### 4.3 Positive Technologies — Diameter (2017-2023)

**What**: Positive Technologies published a multi-year series (2017-2023) documenting that Diameter (the 4G/LTE successor to SS7) inherited the same class of issues. Their 2023 BlackHat/HITB talks covered SEPP misconfigurations in deployed 5G cores.

**Class**: Diameter S6a abuse — same as SS7 MAP, just a different protocol. Update-Location-Request (ULR) and Authentication-Information-Request (AIR) accepted from unauthorized visited networks.

**Impact**: Authentication vector (RAND/AUTN/XRES/KASME) retrieval for any subscriber from any roaming peer. Enables subscriber impersonation and tracking.

**Engagement lesson**: Diameter engagements require explicit roaming-partner authorization and test IMSIs (PLMN 001/01). Use seagull (open-source) for S6a scenario testing.

### 4.4 Alonso et al. — 5G SUCI/SUPI Privacy (2021)

**What**: Alonso and co-authors (2021+) published research on the SUCI encryption scheme's weaknesses when deployed with weak or known home network public keys.

**Class**: SUCI decryption via weak/known ECIES public key. The 5G SUCI scheme encrypts the SUPI using the operator's home network public key. If the key is weak (low-entropy curve, small subgroup) or known (extracted from a USIM), the SUCI can be decrypted to recover the SUPI.

**Impact**: SUPI recovery enables IMSI catcher class of attack even on 5G with SUCI enabled.

**Engagement lesson**: Operators publish their home network public key in the USIM profile. Engagement: extract the key from a test USIM, verify against 3GPP TS 33.501 Annex C weak key list. If weak, escalate to the operator.

### 4.5 R. Piqueras Jover — 5G UE Security Framework (2023)

**What**: Piqueras Jover published "5G Security Reloaded" (2023), the first open-source 5G SA UE security framework — providing tooling for protocol-level UE fuzzing and security testing.

**Class**: UE-side protocol testing. Most 5G security research focused on the core (AMF/SMF/UPF); Piqueras Jover focused on the UE side — the USIM, the modem, the NAS client.

**Engagement lesson**: UE-side testing is complementary to 5GC testing. For engagements against device vendors (smartphone OEMs, IoT modem vendors), the UE security framework is the entry point.

---

## 5. Operational Considerations

### 5.1 Frequency Licensing and Jammer Laws

- **US**: FCC Part 22/25/97 governs cellular frequency use. Transmission on licensed bands (700 MHz, 850 MHz, 1900 MHz, AWS, WCS, CBRS, mmWave) requires an operator license. CBRS (3.55-3.7 GHz) allows general authorized access with SAS coordination — the easiest path to legal 5G transmission in the US.
- **EU**: National spectrum regulators (Ofcom UK, BNetzA Germany, ARCEP France). Experimental licenses are available for research; engage early.
- **China**: MIIT strictly controls spectrum; no equivalent of FCC experimental license. Engage via domestic operator only.
- **Jammer laws**: Active jamming of cellular frequencies is illegal in every jurisdiction (US: 47 USC §333; EU: national implementations of ECC/DEC/(00)07). Even for authorized engagements, jamming requires specific national security or defense authorization.

### 5.2 Passive Reception Legality

- **US**: Passive reception of unencrypted radio is generally legal (47 USC §605 carves out cellular voice content, but the radio signal itself is receivable). Decoding encrypted subscriber content is illegal.
- **EU**: General passive reception is legal; decoding varies by member state.
- **Always verify**: Check the specific jurisdiction before any SDR-based cellular capture. When in doubt, obtain legal review.

### 5.3 Responsible Disclosure to GSMA / 3GPP

- **GSMA FS-IS** (Fraud and Security Intelligence Group) — Coordinates operator-to-operator disclosure of roaming interconnect vulnerabilities (SS7, Diameter, SEPP). Engagement: report via your operator's FS-IS representative.
- **3GPP SA3** (Security Working Group) — Coordinates spec-level disclosure. If a vulnerability is due to a 3GPP specification gap (e.g., TS 29.244 not mandating PFCP source auth), SA3 may issue a spec change request.
- **Operator CSIRT** — Always the first point of disclosure. Coordinate timing, blast radius, and remediation plan.
- **Regulator notification** — In many jurisdictions (EU NIS2, US FCC), a confirmed operator-side vulnerability with subscriber impact triggers regulatory notification. Confirm with the operator's legal team.

### 5.4 Subscriber Data Handling

- **No real subscriber IMSI/SUPI/K/OPc in engagements** — Use test PLMN 001/01 with engagement-scoped test subscribers.
- **Capture/retention policy** — Every PCAP containing subscriber traffic (GTP-U inner packets, NAS SMS content, authentication vectors) is regulated. Define retention (e.g., 90 days post-engagement) and destruction (cryptographic erase) in the engagement contract.
- **Cross-border data movement** — Subscriber data crossing borders may trigger GDPR (EU), CCPA (California), or national data localization laws.

### 5.5 Engagement Scope Templates

| Scope Type | RAN | 5GC | Roaming | Typical Duration |
|-----------|-----|-----|---------|------------------|
| **Private 5G (enterprise)** | In scope (enterprise RAN) | In scope (private 5GC) | Out of scope (no roaming) | 2-4 weeks |
| **Operator production (5GC only)** | Out of scope | In scope (production 5GC) | Out of scope | 4-8 weeks |
| **Operator production (roaming)** | Out of scope | Out of scope | In scope (SEPP/Diameter/SS7) | 4-12 weeks (regulator coordination) |
| **RAN equipment vendor (gNB)** | In scope (vendor lab) | Lab 5GC (Open5GS) | Out of scope | 3-6 weeks |
| **O-RAN component (RIC, O-DU)** | In scope (component + interfaces) | Out of scope | Out of scope | 2-4 weeks |
| **IMSI catcher detection (defensive)** | Passive survey only | Out of scope | Out of scope | 1-2 weeks (field campaign) |

---

## 6. References

### 6.1 3GPP Specifications

| Spec | Title | Relevance |
|------|-------|-----------|
| TS 23.501 | System Architecture for the 5G System | 5GC architecture, NF roles, reference points |
| TS 23.502 | Procedures for the 5G System | Registration, session setup, handover flows |
| TS 23.503 | Policy and Charging Control Framework | PCF, QoS policy |
| TS 24.501 | NAS Protocol for 5G | NAS-5GS message types, SUCI/SUPI/5G-GUTI |
| TS 29.244 | Interface between SMF and UPF (N4, PFCP) | PFCP message types, IE definitions |
| TS 29.281 | GPRS Tunnelling Protocol User Plane (GTP-U) | GTP-U message format |
| TS 29.274 | GTP-C v2 (4G/LTE, N26 interworking) | GTP-C control plane |
| TS 29.272 | MME and HSS interfaces (S6a/S6d, Diameter) | Diameter S6a |
| TS 29.002 | Mobile Application Part (MAP) | SS7 MAP |
| TS 29.500 | Service-Based Architecture (SBA) | SBI principles, HTTP/2 |
| TS 29.510 | Network Repository Function (NRF) | SBI service discovery |
| TS 29.518 | AMF Services (Namf) | AMF SBI |
| TS 29.502 | SMF Services (Nsmf) | SMF SBI |
| TS 29.509 | AUSF Services (Nausf) | AUSF SBI |
| TS 29.503 | UDM Services (Nudm) | UDM SBI |
| TS 29.504 | UDR Services (Nudr) | UDR SBI |
| TS 29.507 | PCF Services (Npcf) | PCF SBI |
| TS 29.531 | NSSF Services (Nnssf) | NSSF SBI |
| TS 29.522 | NEF Services (Nnef) | NEF SBI |
| TS 29.500 | 5G System; SBA; Stage 3 | SEPP principles |
| TS 33.501 | Security Architecture and Procedures for 5G System | **5G security bible**; SUCI, AKA, N32, NEA/NIA |
| TS 33.401 | 3GPP System Architecture Evolution (SAE); Security Architecture | 4G/LTE security |
| TS 33.102 | 3G Security; Security Architecture | 2G/3G security |
| TS 33.210 | 3G security; Network Domain Security (NDS); IP network layer security | NDS/IP |
| TS 38.331 | NR; Radio Resource Control (RRC); Protocol specification | RRC, SIB1 |
| TS 38.413 | NG-RAN; NG Application Protocol (NGAP) | NGAP procedure codes |
| TS 48.018 | BSSGP | 2G packet core |
| TS 29.060 | GPRS Tunnelling Protocol (GTP) | 2G/3G GTP |

### 6.2 Standards Bodies and Industry Groups

| Body | Role |
|------|------|
| **3GPP** | 3rd Generation Partnership Project — Cellular specification body |
| **GSMA** | Global System for Mobile Communications Association — Operator industry group |
| **GSMA FS-IS** | Fraud and Security Intelligence Group — Coordinates operator disclosure |
| **O-RAN Alliance** | Open RAN specification body |
| **ETSI** | European Telecommunications Standards Institute |
| **IETF** | Internet Engineering Task Force (Diameter RFC 6733, EAP-AKA' RFC 5448) |
| **ISO/IEC JTC1 SC27** | Security techniques standards |

### 6.3 NIST, ENISA, and National Guidance

| Document | Title | Source |
|----------|-------|--------|
| **NIST SP 800-213** | Corporate-Owned, Personally Enabled (COPE) Guidance | NIST |
| **NIST C-SCRM 5G** | 5G Cyber Supply Chain Risk Management | NIST |
| **NIST IR 8441** | 5G Cybersecurity | NIST |
| **CISA 5G Strategy** | Fifth Generation (5G) Mobile Networks | CISA |
| **ENISA Threat Landscape for 5G** | 5G Threat Landscape | ENISA |
| **ENISA 5G Security Measures** | Security Measures for 5G Networks | ENISA |
| **NCSC 5G Guidance** | 5G Security Guidance | UK NCSC |
| **BSI TR-03148** | 5G Security Requirements | German BSI |
| **ANSSI 5G** | 5G Security Recommendations | French ANSSI |

### 6.4 Key Research Papers

| Year | Author(s) | Title | Venue |
|------|-----------|-------|-------|
| 2008 | Tobias Engel | "Locating Mobile Phones using SS7" | 24C3 |
| 2014 | Karsten Nohl | "Mobile Self-Defense" | 31C3 |
| 2016 | Karsten Nohl | "SS7: Locate. Track. Manipulate." | BlackHat USA |
| 2017 | Positive Technologies | "Diameter Vulnerabilities" | Research report |
| 2019 | Praetorian | "5G Standalone Core Vulnerabilities" | Research report |
| 2020 | Hussain et al. | "5G Reason: Analyzing the 5G Standalone Core" | NDSS |
| 2021 | Alonso, et al. | "The 5G AIA/ARIA: Privacy in 5G Standalone" | IEEE S&P / research |
| 2022 | R. Piqueras Jover | "5G Security Reloaded" | Research |
| 2023 | Positive Technologies | "5G Vulnerabilities 2023" | HITB / BlackHat |

### 6.5 Open-Source Tooling References

| Tool | Repository | License |
|------|------------|---------|
| Open5GS | github.com/open5gs/open5gs | AGPL-3.0 |
| UERANSIM | github.com/aligungr/UERANSIM | GPL-3.0 |
| srsRAN_Project | github.com/srsran/srsRAN_Project | AGPL-3.0 |
| srsRAN 4G | github.com/srsran/srsRAN_4G | AGPL-3.0 |
| free5GC | github.com/free5gc/free5gc | Apache-2.0 |
| PacketRusher | github.com/HewlettPackard/PacketRusher | Apache-2.0 |
| OsmoHLR | gitea.osmocom.org/osmo-hlr | AGPL-3.0 |
| OsmoMSC | gitea.osmocom.org/osmo-msc | AGPL-3.0 |
| ss7MAPer | github.com/ernw/ss7MAPer | Research |
| sctpscan | github.com/philippeINSAsly/sctpscan | GPL |
| Seagull | github.com/nickvdp/seagull | GPL-2.0 |
| Wireshark | wireshark.org | GPL-2.0 |
| scapy | github.com/secdev/scapy | GPL-2.0 |
| AIMSICD | github.com/SecUpwN/Android-IMSI-Catcher-Detector | GPL-3.0 |

### 6.6 Operator and Industry Resources

| Resource | Source | Purpose |
|----------|--------|---------|
| **GSMA IR.21** | GSMA | Operator roaming agreement database (PLMN list, MCC/MNC mapping) |
| **GSMA FS.32** | GSMA | SS7 signaling security recommendations |
| **GSMA FS.33** | GSMA | Diameter signaling security recommendations |
| **GSMA FS.07** | GSMA | SMS hubbing security |
| **OpenCellID** | opencellid.org | Open database of cell tower locations |
| **3GPP SA3 Liaison** | 3GPP | Spec-level vulnerability coordination |
| **CISA 5G C-SCRM** | CISA | US national 5G supply chain risk management |

---

## 7. Conclusion

The 5G telecom attack surface is one of the largest and most regulated in information security. The 2020s are the decade of 5G standalone core deployments, O-RAN adoption, and the gradual retirement of 2G/3G (and with them, SS7). The attack classes documented in this playbook — SS7 MAP abuse (2014+), Diameter roaming abuse (2017+), PFCP injection (2019+), SUCI privacy (2021+), SEPP misconfiguration (2023+) — will continue to evolve as operators deploy 5G at scale and as 6G research begins in earnest around 2026-2028.

For the immediate engagement horizon (2025-2027):

- **5G SA cores** are the primary engagement target. Open5GS and free5GC labs reproduce most of the published attack classes in under an hour of bring-up.
- **O-RAN** is the emerging engagement target. O1/O2/E2/A1 interface testing on early O-RAN deployments (2024-2026 vintage) is yielding default-credential and weak-TLS findings at a steady rate.
- **Roaming interconnect** remains the slowest-moving engagement class. SEPP deployment is incomplete in many operators; Diameter S6a abuse remains feasible against operators without Diameter firewalls.
- **UE-side** research (Piqueras Jover 2023+) is opening a new engagement surface for device vendors and IoT modem makers.

The defensive side is also maturing: commercial signaling firewalls (Mavenir, Enea, NetNumber), SEPP deployments, and operator-side anomaly detection (Suricata rules, Splunk SPL for 5GC) are the controls this playbook's payloads are designed to test against.

Engage carefully, document everything, disclose responsibly via GSMA FS-IS and 3GPP SA3, and remember that the cellular network is one of the few attack surfaces where a mistake can take down a national-scale service in seconds.
