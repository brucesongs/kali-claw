---
name: 5g-telecom-attack
description: 5G core (AMF/SMF/UPF), RAN, signaling (PFCP/GTP/Diameter/SS7), IMSI catchers, O-RAN security, roaming abuse, SMS interception, and telecom infrastructure red team operations.
origin: github-trending-2026
version: 1.0.0
compatibility: Claude Code, Claude Agent SDK
allowed-tools:
  - Bash
  - Read
  - Edit
  - Write
  - Glob
  - Grep
metadata:
  domain: telecom
  category: telecom
  tool_count: 13
  guide_count: 1
  mitre: "TA0001-Initial Access, T1557-Adversary-in-the-Middle, T1565-Exfiltration"
  keywords: [5g, telecom, srsran, open5gs, pfcp, gtp, diameter, ss7, imsi-catcher, oran, roaming, sms-interception]
---


# Skill: 5G Telecom Attack

> **Supplementary Files**:
> - `payloads.md` — Command catalogue for 5G core, RAN, and legacy signaling attack surfaces — 18 sections with real commands: Open5GS+UERANSIM Docker lab bring-up, srsRAN gNodeB with USRP/BladeRF, AMF NGAP/SCTP reconnaissance, SMF/UPF PFCP enumeration, PacketRusher fuzzing, GTP-U tunnel injection, GTP-C scapy fuzzing, Diameter (S6a/Sh/Rx) roaming testing, SS7 MAP legacy context, IMSI catcher detection workflow, SUCI/SUPI privacy analysis, NAS SMS interception, O-RAN O1/O2/E2 interface testing, SEPP/border gateway roaming abuse, network slice isolation tests, Wireshark 5G dissectors (NGAP/PFCP/GTP), blue-side detection engineering (Suricata/Splunk), quick reference cheat sheet.
> - `test-cases.md` — Structured test cases (TC-5G-001..012): Open5GS+UERANSIM lab bring-up, AMF NGAP fingerprinting, PFCP enumeration of SMF, GTP-U tunnel injection, GTP-C fuzzing with scapy, Diameter S6a testing, SS7 MAP legacy+caveats, IMSI catcher detection workflow, SUCI/SUPI privacy analysis, O-RAN O1 interface scan, network slice isolation test, 5G dissection with tshark.
> - `guides/5g-telecom-attack-playbook.md` — End-to-end telecom red team playbook: scope/legal (frequency licensing, jammer laws, GSMA disclosure) → 5G architecture refresher (AMF/SMF/UPF/AUSF/UDM/PCF/NRF/NSSF, N1-N11) → lab build (Open5GS+UERANSIM Docker, srsRAN gNB, SDR hardware) → signaling methodology (NGAP/SCTP recon → PFCP probing → GTP injection → fuzzing) → real-world incidents (Karsten Nohl SS7, Praetorian 5G DoS, Positive Technologies 2023, Alonso 5G privacy) → references (3GPP TS 33.501/33.401/29.244, NIST 5G cybersecurity guide, ENISA 5G threat landscape).

## Summary

5G telecom attack skill domain covering the operator-side cellular stack: the 5G Core (5GC) components (AMF, SMF, UPF, AUSF, UDM, PCF, NRF, NSSF), the Radio Access Network (gNodeB, O-RAN), and the signaling protocols that carry subscriber identity, session state, and roaming traffic (NGAP, PFCP, GTP-U, GTP-C, Diameter, MAP/SS7, NAS). This is the cellular network as target — the infrastructure that authenticates 5 billion subscribers, routes their data, and hands them off between cell sites and roaming partners. Where `bluetooth-rfid-nfc` covers the last 10 meters of local radio, this skill covers the 10–10,000 km of operator infrastructure between the UE and the internet.

**Tools**: srsRAN_Project (open-source 5G CU/DU), Open5GS (open-source 5G Core), UERANSIM (UE/gNB simulator), PacketRusher (5GC load/fuzz tester), Wireshark with 5G dissectors (NGAP/PFCP/GTP), srsENB/srsUE (4G/5G SDR stack), Gr-SDR/USRP (SDR hardware drivers), Amarisoft (commercial gNB stack), PFCP toolkit, ss7MAPer (SS7 MAP tester), sctpscan (SCTP scanner), diagpttcc (diag parser), tshark.

**Domain**: telecom

**MITRE ATT&CK**: TA0001-Initial Access, T1557-Adversary-in-the-Middle, T1565-Exfiltration, T1499-Endpoint Denial of Service (5GC signaling DoS)

## Description

Telecom infrastructure is one of the oldest and most regulated attack surfaces in information security. SS7 (Signaling System 7) was designed in 1975 when the assumption was "every switch on this network is owned by a national postal, telephone, and telegraph administration and is therefore trustworthy". That assumption died in 2008 when Tobias Engel demonstrated location tracking and call/SMS interception via SS7 MAP at the Chaos Communication Congress, and it was buried for good in 2014–2016 when Karsten Nohl showed at BlackHat and 31C3 that he could intercept calls and SMS of members of multiple national governments by abusing SS7 roaming messages purchased from a small operator with global reach. Diameter — the 4G/LTE successor that was supposed to fix SS7 — was shown by Positive Technologies (2017+) to have the same class of issues, and 5G's SEPP (Security Edge Protection Proxy) for roaming interconnect is the third attempt at the same problem.

This skill covers the eight things that distinguish 5G/telecom attacks from generic network pentests:

1. **The cellular network is three networks** — The 5G system is the union of (a) the **Radio Access Network** (gNodeB, O-RAN with O1/O2/E2/open fronthaul interfaces), (b) the **5G Core** (AMF/SMF/UPF/AUSF/UDM/PCF/NRF/NSSF service-based architecture on HTTP/2), and (c) the **inter-operator interconnect** (SEPP for N32 roaming, Diameter for 4G roaming, SS7/MAP for 2G/3G roaming). Each has its own protocol stack, threat model, and legal regime. A telecom red team rarely engages all three simultaneously; most engagements target one.

2. **Subscriber identity is the crown jewel — and 5G tried to fix it but didn't** — In 4G/LTE, the **IMSI** (International Mobile Subscriber Identity) is sent in cleartext on the initial attach, enabling the **IMSI catcher** (Stingray, Hailstorm) — a fake base station that triggers the UE to reveal its IMSI, which can then be correlated to a subscriber. 5G introduced **SUPI** (Subscriber Permanent Identifier, the 5G IMSI) and **SUCI** (Subscriber Concealed Identifier) — SUPI encrypted with the operator's public key before being sent on the air. The Alonso et al. research (2021+) showed the encryption scheme is vulnerable if the operator uses an ECIES-based scheme with a weak home network public key or a predictable scheme ID. 5G **reduces** but does not **eliminate** IMSI catcher feasibility.

3. **PFCP is the new GTP-C — and it has the same DoS class** — The Packet Forwarding Control Protocol (3GPP TS 29.244) runs between the SMF (Session Management Function) and the UPF (User Plane Function) to install forwarding rules. Praetorian (2019) and subsequent work showed that PFCP messages with attacker-chosen TEID (Tunnel Endpoint Identifier) and far-end IP can be injected into a UPF that does not authenticate the SMF source — causing session hijack or mass session teardown (DoS for every subscriber whose session the UPF drops). 5G PFCP inherits the design of 4G Sx; the attack class is unchanged.

4. **GTP-U tunnels are the new VPNs — and they have the same injection class** — GTP-U (GPRS Tunneling Protocol User Plane, 3GPP TS 29.281) encapsulates subscriber IP traffic between the gNB and the UPF. Unauthenticated GTP-U on the N3 interface is the classic "untrusted source spoofing" bug: an attacker who can reach the UPF's GTP-U port (UDP 2152) with a captured TEID can inject traffic into the subscriber's session (downlink), or capture and exfiltrate subscriber traffic by advertising a TEID pointing at themselves (uplink redirection). This is the modern successor to "the SS7 location query told me where the subscriber is; now I will intercept their traffic via GTP".

5. **Diameter is SS7 with extra steps** — The 4G/LTE Home Subscriber Server (HSS) speaks Diameter on the S6a interface (MME↔HSS). The same class of issues applies: an attacker with access to a roaming Diameter peer can issue Update-Location-Request (ULR) for any IMSI in any home network, retrieve the authentication vector (RAND/SRES/Kc or RAND/RES*/AUTN in 5G), and impersonate the subscriber or track them via Provide-Subscriber-Info (PSI). Positive Technologies' 2017–2023 series documented this for multiple operators. 5G's SBA still uses Diameter for the UDSF/UDR backend in some profiles.

6. **SEPP is the new "SS7 firewall" — and operators are deploying it slowly** — The Security Edge Protection Proxy (3GPP TS 33.501 §6.2.6) sits at the boundary between the visited and home 5G cores for N32 roaming. It provides message filtering, topology hiding, and integrity protection via JOSE (JWS/JWE). Field deployments are incomplete: many operators deployed the SEPP but configured it in pass-through, or implemented the filtering rules too permissively. Roaming abuse on 5G is the modern equivalent of the 2014 SS7 scandal, just slower-moving because the protocols are newer.

7. **O-RAN is an SDN attack surface** — The O-RAN Alliance architecture splits the gNodeB into O-RU (Radio Unit), O-DU (Distributed Unit), and O-CU (Centralized Unit), and exposes the **O1** (operations, A1/O1 southbound), **O2** (cloud-native and NFVO), **E2** (near-RT RIC), and **A1** (non-RT RIC) interfaces. These are HTTP/2 + gRPC + REST + RAN configuration protocols with authentication that has, in early O-RAN deployments, defaulted to "developer convenience" (shared TLS client certs, default credentials on the RIC). The O-RAN ALLIANCE WG11 (Security) specifications exist; adoption is uneven.

8. **5GC is a microservices attack surface** — The 5G Core Service-Based Architecture (SBA) exposes AMF/SMF/UDM/AUSF/PCF/NRF/NSSF as HTTP/2 + JSON APIs on the SBI (Service-Based Interface). The NRF (Network Repository Function) is a service-discovery endpoint that returns the full NF (Network Function) inventory to any authenticated NF; a compromised NF can enumerate the entire core. The default authentication between NFs is PLMN-wide OAuth-like tokens; in test cores (Open5GS, srsRAN) this is often disabled, and in operator deployments the keys are sometimes shared across all NFs.

This skill is the cellular-network counterpart to `ad-ldap-attack` (enterprise identity infrastructure) and `cloud-identity-attack` (cloud identity infrastructure): where those cover authentication and authorization in the IT and cloud tiers, this covers authentication and authorization in the **telecom tier** — the third identity infrastructure that every smartphone on earth depends on.

## Use Cases

- **5G Core (SBA) pentest** — Black-box or grey-box engagement against a 5GC deployment (operator production, MVNO test core, or private 5G enterprise deployment). Enumerate NRF, walk the SBI, identify unauthenticated NF endpoints, find logic flaws in subscription/session/policy flows.
- **PFCP enumeration and fuzzing** — Identify the SMF↔UPF interface on the N4 reference point, fingerprint the PFCP implementation (Open5GS, free5GC, vendor), fuzz Heartbeat Request / Session Establishment Request / Session Modification Request for crashes or DoS.
- **SS7 / Diameter legacy testing** — Engagements scoped against the 2G/3G (SS7 MAP) or 4G (Diameter S6a) roaming interconnect of a mobile operator. Always requires explicit roaming-partner authorization and legal review; frequently out-of-scope for private 5G deployments that have no roaming footprint.
- **IMSI catcher detection** — Defensive engagement: deploy a monitoring SDR (BladeRF, USRP B210, HackRF) and detect rogue base stations triggering cleartext IMSI or ECIES-encrypted SUCI with anomalous patterns. Used by journalists, defense contractors, and CSIRTs.
- **Roaming abuse assessment** — Operator-side assessment of the SEPP configuration, N32 filtering rules, roaming agreement enforcement. Verify that a visited-network peer cannot issue unauthorized messages (ULR, IDR, PSI) against home-network subscribers.
- **O-RAN component testing** — Vulnerability assessment of the O1/O2/E2/A1 interfaces on an O-RAN compliant gNodeB or RIC. Identify weak TLS, default credentials, command injection in the O1 NETCONF/YANG layer, or path traversal in the O2 Helm chart deployment.
- **SMS interception and NAS-layer analysis** — Engagement that captures and analyzes NAS (Non-Access Stratum) signaling between UE and AMF to identify SMS-in-NAS, emergency-call handling, or subscriber tracking via the 5G-GUTI reallocation pattern.

## Core Tools

| Tool | Purpose | License / Notes |
|------|---------|-----------------|
| **srsRAN_Project** | Open-source 5G CU/DU (gNodeB) — software radio stack. Runs with USRP/BladeRF hardware. Used in lab bring-up and attack reproduction. | AGPL-3.0. github.com/srsran/srsRAN_Project |
| **Open5GS** | Open-source 5G Core (AMF/SMF/UPF/AUSF/UDM/PCF/NRF/NSSF) in C. Default lab core for red team — minimal config, exposes SBI on HTTP/2. | AGPL-3.0. open5gs.org |
| **UERANSIM** | Open-source UE and gNB simulator in C++. Pure-software — no SDR required. Pairs with Open5GS for the canonical 5G lab. | GPL-3.0. github.com/aligungr/UERANSIM |
| **PacketRusher** | 5G Core load tester and protocol fuzzer in Go. Supports NGAP, PFCP, GTP, SBI fuzzing. Default tool for stress/fuzz tests against Open5GS/free5GC. | Apache-2.0. github.com/HewlettPackard/PacketRusher |
| **Wireshark (5G dissectors)** | NGAP, PFCP, GTP-U, GTP-C, NAS-5GS, Diameter, S1AP, RANAP dissection. The lingua franca for telecom packet analysis. | GPL-2.0. wireshark.org |
| **srsENB / srsUE** | srsRAN's 4G LTE eNodeB and UE stack. Used for 4G/LTE-specific engagements (S1AP, GTP-C v2) and to validate 4G IMSI catcher PoCs. | AGPL-3.0. Part of srsRAN 4G. |
| **Gr-SDR / USRP (UHD)** | GNU Radio SDR blocks + Ettus UHD driver. Lower-level than srsRAN; used for custom PHY work, jammer characterization, and capture of cellular downlink for IMSI catcher detection. | GPL-3.0 / GPL-3.0. |
| **Amarisoft** | Commercial 5G/LTE base station stack (L1/L2/L3). Premium lab reference; many operators use it as a known-good gNB. Proprietary. | Commercial license. amarisoft.com |
| **PFCP toolkit / pfcp-fuzzer** | Custom and open-source PFCP packet crafters. Implement 3GPP TS 29.244 PFCP messages — Heartbeat, PFCP Session Establishment Request, PFCP Session Deletion Request — for fuzz and injection. | Various. |
| **ss7MAPer** | SS7 MAP (Mobile Application Part) testing tool. Legacy; mostly used for operator-side SS7 firewall validation. | Research use only. github.com/ernw/ss7MAPer |
| **sctpscan** | SCTP (Stream Control Transmission Protocol) port scanner. SCTP is the transport for NGAP (N2) and S1AP (S1-MME). Used to identify AMF and eNB SCTP endpoints. | GPL. github.com/philippeINSAsly/sctpscan |
| **diagpttcc** | Qualcomm DIAG (Diagnostic) protocol parser. Used to extract baseband state from rooted Android Qualcomm devices during IMSI catcher characterization. | Research. |
| **tshark** | Wireshark's CLI packet analyzer. Used in automation pipelines (capture → dissection → rule matching) for 5G signaling anomaly detection. | GPL-2.0. Part of Wireshark. |

## Methodology

The engagement methodology is organized in five phases, each scoped against one of the three cellular network tiers (RAN, 5GC, Interconnect).

### Phase 1: Reconnaissance (Passive)

- **Spectrum survey** — Sweep the licensed and unlicensed cellular bands (n78 3.3–3.8 GHz, n41 2.5 GHz, n28 700 MHz, B71 600 MHz, and LTE bands 1/2/3/4/5/7/12/13/14/66/71 for 4G coverage). Use a HackRF/BladeRF with `osmocom_fft` or `gnuradio-companion` to identify active base stations (SSB burst pattern for 5G, PSS/SSS for LTE). For engagements inside the operator's RAN team this is unnecessary; for engagements against a target operator's downlink (e.g., detecting rogue base stations) this is the first step.
- **SCTP/HTTP-2 fingerprinting** — From a vantage point on the operator's internal network (engagement-scoped), scan the AMF SCTP port (38412) and the SBI HTTP/2 port (443 / 80) for the 5GC service inventory. `sctpscan`, `nmap -sSU -p 38412,2152,2123`, and `nmap --script http2-fingerprint` against the NRF.
- **NRF enumeration** — Authenticate as a low-priv NF (or, in many lab and misconfigured deployments, unauthenticated) and call `GET /nnrf-nfm/v1/nf-instances`. This returns the full NF inventory — AMF IP, SMF IP, UPF IP, AUSF, UDM, PCF, NSSF, and every service each exposes. This is the 5GC equivalent of `Get-ADUser -Filter *` from `ad-ldap-attack`.

### Phase 2: Signaling Analysis (Passive → Active)

- **NGAP capture** — `tshark -i <iface> -f 'sctp port 38412' -Y ngap` on the N2 interface between gNB and AMF. Identify NGAP messages: Initial UE Message, Downlink/ Uplink NAS Transport, Initial Context Setup, PDU Session Resource Setup. Verify ciphering and integrity protection are enforced on NAS (NAS COUNT incrementing, MAC correct).
- **PFCP enumeration** — Identify the N4 interface between SMF and UPF (UDP 8805). `tshark -i <iface> -f 'udp port 8805' -Y pfcp`. Map SEID (Session Endpoint Identifier) space — this is the per-session handle the SMF uses to address the UPF. Identify whether the UPF authenticates the SMF (most don't — the message source IP is trusted).
- **GTP capture** — Identify the N3 interface between gNB and UPF (UDP 2152 for GTP-U, UDP 2123 for GTP-C in 4G). `tshark -i <iface> -f 'udp port 2152 or udp port 2123' -Y 'gtp || gtp_u'`. Capture TEIDs in use and the mapping between TEID↔subscriber PDU session.

### Phase 3: Attack Vector Validation

- **PFCP injection PoC** — Construct a PFCP Session Deletion Request with a captured SEID, source-spoofed from a different IP (or from a peer SMF in a multi-SMF deployment). Send to the UPF on UDP 8805. A vulnerable UPF will tear down the subscriber's session; the subscriber's data session drops and the operator's monitoring sees a PFCP session release event with no upstream cause. Document as the classic Praetorian class.
- **GTP-U injection PoC** — Capture a downlink GTP-U packet (gNB → UPF) and a TEID in use. Construct a raw UDP packet to the UPF's GTP-U port (2152) with the captured TEID and a payload of a crafted IP packet (e.g., TCP SYN to a known host the subscriber will RST). If the UPF forwards it, the subscriber sees an unsolicited packet from a host they never contacted — confirming GTP-U injection.
- **Diameter ULR PoC** (operator-side only, explicit roaming authorization) — Construct an Update-Location-Request for a test IMSI in the home network, signed with the roaming peer's credentials. Send on the S6a interface (SCTP 3868) to the HSS. A vulnerable HSS returns the authentication vector (RAND/RES*/AUTN) without confirming the IMSI belongs to the visited network.
- **SUCI decryption PoC** (engagement against a test operator using a known-weak home network public key) — Capture a SUCI from the air, apply the ECIES decryption with the operator's home network private key (engagement-scoped), recover the SUPI. Document as the Alonso class of attack.

### Phase 4: Exploitation

- **Session teardown DoS** — Iterate PFCP injection across the captured SEID space. Mass session teardown. Document the rate (sessions/sec) and the recovery behavior (does the SMF re-establish? does the UE re-attach?).
- **Subscriber traffic redirection** — Inject PFCP Session Modification Request changing the UPF's far-end F-TEID for a target session to point at an attacker-controlled endpoint. Capture subscriber uplink traffic. Mirror to a forensic capture. Document scope and exfiltrate engagement-allowed samples only.
- **SMS-in-NAS interception** — If the engagement scope permits and the AMF/SMF use NAS SMS (5G carries SMS over NAS by default), capture the NAS messages and decode the RP-DL / RP-UL SMS. The SMS payload is at the NAS layer after NAS security activation, so this requires either the operator's NAS security keys (engagement-scoped) or a vulnerable AMF that delivers SMS without activating NAS security (rare, but seen in misconfigured cores).
- **Roaming message abuse** — From a visited-network vantage, issue unauthorized Diameter or SEPP messages (IDR, PSI, ULR) against home subscribers. Track the home network's response — auth vector returned, subscriber info returned, etc.

### Phase 5: Reporting

- **Operator-grade report** — Include the SEID/TEID/IMSI/SUPI evidence with redaction; spectrum plots; SCTP/HTTP-2 packet captures with timestamps; impact analysis in terms of affected subscriber counts; remediation mapped to 3GPP TS 33.501 controls (e.g., "N4 interface source IP filtering per TS 33.501 §6.6.2").
- **GSMA/3GPP disclosure** — Most operator-side findings are coordinated via GSMA FS-IS (Fraud and Security Intelligence Group) and 3GPP SA3 Liaison. Reference the GSMA FS.32 SS7 / Diameter / SEPP recommendations and the operator's roaming agreement security clauses.
- **Regulator notification** — In many jurisdictions (EU NIS2, US FCC) a confirmed operator-side vulnerability with subscriber impact triggers regulatory notification. Confirm with the operator's legal team before filing.

## Practical Steps

### Worked Example 1: Lab Bring-Up (Open5GS + UERANSIM)

A canonical 5G lab for red team reproduction is Open5GS (5GC) + UERANSIM (UE + gNB). Bring-up in Docker Compose:

```bash
# Clone the canonical lab
git clone https://github.com/open5gs/open5gs /opt/open5gs
cd /opt/open5gs/docker

# Optionally, use the community-maintained compose
git clone https://github.com/michaelb732/open5gs-docker-compose /opt/open5gs-compose
cd /opt/open5gs-compose
docker compose up -d

# Verify the 5GC is up
docker compose ps
curl -sk https://localhost:8080/  # web UI
# AMF SCTP on 38412, UPF GTP-U on 2152, SMF PFCP on 8805

# Bring up a UE + gNB via UERANSIM
git clone https://github.com/aligungr/UERANSIM /opt/UERANSIM
cd /opt/UERANSIM
make -j$(nproc)
# Configure open5gs-gnb.yaml and open5gs-ue.yaml to point at the lab AMF
./nr-gnb -c config/open5gs-gnb.yaml
./nr-ue -c config/open5gs-ue.yaml
# Confirm the UE gets an IP from the SMF/UPF — ping 1.1.1.1 from UE iface
```

### Worked Example 2: PFCP Fuzzing Workflow

Once the lab is up, fuzz the SMF↔UPF PFCP interface. PacketRusher is the canonical 5GC load/fuzz tester:

```bash
# Install PacketRusher
git clone https://github.com/HewlettPackard/PacketRusher /opt/PacketRusher
cd /opt/PacketRusher
go build -o packetrusher ./cmd/packetrusher
# Edit config.yml: set gnodeb.amf.ip to lab AMF

# Run a normal registration load to baseline
./packetrusher -c config.yml

# In a second shell, capture N4 PFCP
tshark -i any -f 'udp port 8805' -Y pfcp -w /tmp/pfcp-baseline.pcap

# Identify SEID space
tshark -r /tmp/pfcp-baseline.pcap -Y pfcp -T fields \
  -e pfcp.seid -e ip.src -e ip.dst | sort -u

# Fuzz: craft a PFCP Session Deletion Request with a known SEID
python3 - <<'EOF'
# scapy with pfcp contribution; use scapy.contrib.pfcp
from scapy.all import *
from scapy.contrib.pfcp import PFCP, PFCPHeader, IE_F_SEID, IE_Node_ID
# Build a Heartbeat Request first to fingerprint
hb = IP(dst='10.0.0.4')/UDP(sport=8805, dport=8805)/PFCP(version=1, msg_type=1, seq=1)
send(hb)
EOF
```

### Worked Example 3: NGAP / NAS Analysis

Capture the N2 interface between gNB and AMF to verify NAS security and identify the SUPI→5G-GUTI mapping:

```bash
# Capture N2 NGAP
tshark -i any -f 'sctp port 38412' -Y 'ngap || nas-5gs' -w /tmp/n2.pcap

# Extract 5G-GUTI reallocations
tshark -r /tmp/n2.pcap -Y 'nas_5gs.message_type == 0x5b' \
  -T fields -e frame.time -e nas_5gs.guti.plmn.mcc \
  -e nas_5gs.guti.amf_pointer -e nas_5gs.guti_5g_tmsi

# Confirm NAS security mode is complete (ciphered from this point forward)
tshark -r /tmp/n2.pcap -Y 'nas_5gs.security_header_type' -V | head -200
```

### Worked Example 4: IMSI Catcher Detection Workflow

Defensive engagement: deploy an SDR to detect rogue base stations in the operator's downlink band. This is the only worked example that does not require operator authorization — passive reception is legal in most jurisdictions, while transmission requires licensing.

```bash
# Use srsRAN or gr-SDR to capture the 5G SSB bursts in n78 (3.3-3.8 GHz)
# With a USRP B210 or BladeRF 2.0 micro:
osmocom_fft -f 3.5e9 -s 20e6  # visual survey

# Capture SIB1 (carries the operator PLMN, TAC, cell ID)
# srsRAN has a SIB1 decoder; gr-dvbs2 / gr-lte also have cell scanners
srsran_scanner_radio --band 78 --freq_start 3.3e9 --freq_end 3.8e9

# Log SUCI patterns — a high rate of ECIES-encrypted SUCI in a short
# time window from multiple UEs (all hitting the same fake cell) is
# the classic IMSI catcher signature in 5G.
# Open-source IMSI catcher detector: AIMSICD (Android) or srsRAN scan
```

## Defense Perspective

Operators and large enterprises deploying private 5G detect and respond to this class of attack via:

- **SEPP monitoring** — The Security Edge Protection Proxy is the canonical control point for N32 roaming interconnect. Operators deploy SEPP with JOSE message-level integrity, IP allowlisting of roaming peers, and message-type filtering (e.g., ULR/IDR/PSI are limited to subscribers who actually roam on that visited network). Detection: SEPP reject counters, anomalous peer source IPs, unexpected message types.
- **EMSPEC / SIGNTRACE** — Commercial SS7/Diameter/SEPP signaling firewalls (Mavenir, Enea, NetNumber, Tata Communications). Apply rule sets derived from GSMA FS.32 / FS.33. Detect unauthorized ULR/PSI/IDR by correlating the target IMSI/SUPI against the operator's actual roaming footprint.
- **PFCP source authentication** — 3GPP TS 33.501 recommends (but does not mandate) source authentication on the N4 interface. Operators that deploy DTLS on N4 (per RFC 9260 / TS 33.501 §6.6) detect injection by the absence of a DTLS session. Operators without DTLS rely on the SMF and UPF being on a trusted L2 segment.
- **GTP-U filtering** — UPF ACLs: GTP-U traffic from the gNB only, TEID allowlist per session, drop from unexpected source IPs. Modern UPFs (Open5GS 2.7+, free5GC v3.4+) implement per-session TEID validation.
- **NRF audit** — Every NF-to-NF SBI call is logged by the NRF and the SCP (Service Communication Proxy). Detection: NF making unusual calls (e.g., a SMF querying UDM for subscribers not in its service area).
- **5G-GUTI rotation monitoring** — Anomalous 5G-GUTI reallocation rates (too frequent → paging/IMSI catcher indicator; too infrequent → tracking risk) are detected by the AMF and surfaced to the operator's security monitoring.
- **Rogue base station detection** — In operator RAN: drive-test campaigns with measurement UEs that log the SSB / SIB1 fingerprint of every cell they hear. Any cell ID not in the operator's planned inventory is a candidate rogue base station. Commercial tools: Siradel, Rohde & Schwarz ROMES, Asseco AIMSICD (open-source).
- **Spectrum monitoring** — Continuous SDR capture of the operator's licensed band with anomaly detection on the SSB burst pattern. Detects both rogue base stations and jammers.

## Differentiation

This skill is the **only** telecom-focused skill in the workspace. The closest adjacent skills are:

- **`bluetooth-rfid-nfc`** — Covers local-radio (BT/BLE, RFID/NFC) attack surfaces. `5g-telecom-attack` covers **cellular-radio** infrastructure — the operator-side RAN/5GC/interconnect. Different radio, different regulatory regime, different engagement model (operator-scale vs. endpoint-scale).
- **`wifi-pentest`** — Covers 802.11 Wi-Fi attack surfaces (WPA2/3, evil twin, PMF). `5g-telecom-attack` covers **licensed-spectrum cellular** (3GPP) — different protocol stack (NGAP/PFCP/GTP vs. 802.11 management frames), different licensing regime (operator-licensed vs. unlicensed ISM bands).
- **`dns-attacks`** — DNS is a control-plane protocol used inside telecom cores (DNS resolution for SBA/NRF service discovery). `5g-telecom-attack` covers the **3GPP signaling plane** (NGAP/PFCP/GTP/Diameter), not DNS.
- **`ad-ldap-attack`** — Enterprise identity infrastructure. `5g-telecom-attack` covers **telecom identity infrastructure** — the SIM/AUSF/UDM/HSS tier that authenticates the world's 5 billion cellular subscribers. Same conceptual layer (identity), different technology stack.
- **`cloud-identity-attack`** — Cloud IdP infrastructure (Entra ID, Okta). `5g-telecom-attack` covers the **telecom identity tier** that predates and parallels cloud IdPs.
- **`sdr-rf-attack`** — SDR/RF physical-layer attacks (jamming, replay, RF analysis). `5g-telecom-attack` covers the **protocol and infrastructure layer above the SDR PHY** — what the bits mean after the SDR has captured them.

## See Also

- `bluetooth-rfid-nfc/SKILL.md` — local-radio attack surface
- `wifi-pentest/SKILL.md` — Wi-Fi attack surface
- `sdr-rf-attack/SKILL.md` — SDR physical-layer attacks
- `ad-ldap-attack/SKILL.md` — enterprise identity infrastructure
- `cloud-identity-attack/SKILL.md` — cloud identity infrastructure
- `network-tunneling-proxy/SKILL.md` — GTP-U and other tunnel protocols overlap
- `payloads.md` — 18 sections of working telecom attack commands
- `test-cases.md` — 12 structured test cases (TC-5G-001..012)
- `guides/5g-telecom-attack-playbook.md` — end-to-end red team playbook with lab setup, signaling methodology, real-world incidents, and 3GPP/NIST/ENISA references
