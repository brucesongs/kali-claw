# Test Cases — 5g-6g-telecom-attack-advanced

> Structured test cases for 5g-6g-telecom-attack-advanced.
> Offensive cases (TC-006+) assume the authorized lab from payloads.md §1 (srsRAN + Open5GS) or a written engagement scope.

## TC-001: SUCI Protection

**Objective**: Verify SUCI properly conceals SUPI.

**Arrange**: Sniff radio interface.

**Act**: Capture authentication messages.

**Assert**: SUPI not visible; only SUCI.

---

## TC-002: Slice Isolation

**Objective**: Verify network slices are isolated.

**Arrange**: Attempt cross-slice NF access.

**Act**: Send SBI request from slice A to NF in slice B.

**Assert**: Request rejected.

---

## TC-003: Diameter Firewall

**Objective**: Verify Diameter firewall blocks anomalous signaling.

**Arrange**: Send malformed Diameter message.

**Act**: Send Diameter ULR from unauthorized source.

**Assert**: Message blocked; alert generated.

---

## TC-004: Reconnaissance Detection

**Objective**: Verify monitoring detects reconnaissance.

**Arrange**: Run scanning tools.

**Act**: Execute scan against target.

**Assert**: Monitoring alert within 5 minutes.

---

## TC-005: Defense Bypass

**Objective**: Verify defense bypass is detected.

**Arrange**: Attempt to bypass primary control.

**Act**: Execute bypass technique.

**Assert**: Secondary control catches attempt.

---

## TC-006: Rogue NF Registration against NRF

**Objective**: Demonstrate (or disprove) that an unauthorized NF can register with the NRF and enter service discovery.

**Arrange**: Lab core (Open5GS) running with NRF on `:7777`; attacker host on the same L2; capture `nf-instances` baseline (`curl http://NRF:7777/nnrf-nfm/v1/nf-instances | jq '.[].nfType'`).

**Act**: `POST /nnrf-nfm/v1/nf-instances` with a rogue AMF profile (payloads §2), then from a second session request `nnrf-disc` for `target-nf-type=AMF`.

**Assert**: Either registration is rejected (403/mTLS required — hardened) or the rogue instance appears in discovery responses and receives NF traffic (finding: NRF northbound attestation missing). Evidence: HTTP transcripts + discovery response JSON.

---

## TC-007: SUCI Null-Scheme Exposure on N2

**Objective**: Detect whether the deployment transmits plaintext-IMSI SUCI (scheme 0) or leaks IMSI via paging.

**Arrange**: Lab gNB with NAS PCAP enabled (`srsran-gnb --pcap-nas enabled`); UE completes registration.

**Act**: `tshark -r gnb_nas.pcap -Y nas_5gs.msg.type==0x41 -V | grep -A2 SUCI`; separately grep N2 paging captures for IMSI patterns where only S-TMSI/GUTI should appear (payloads §5-§6).

**Assert**: All SUCIs are scheme-1+ (ECIES) and paging uses temporary identities only. Any `suci-0-` or IMSI-in-paging occurrence is a privacy finding with the matching PCAP frame cited.

---

## TC-008: Cross-Slice PDU Session Request (Slice Escape)

**Objective**: Verify slice isolation enforcement for a UE provisioned for one slice requesting service on another.

**Arrange**: Lab UE SIM provisioned for eMBB only (SST=1); srsRAN UE registered; SMF SBI reachable.

**Act**: Submit `nsmf-pdusession` request with forged `3gpp-S-Nssai` header claiming SST=2/URLLC DNN (payloads §7).

**Assert**: Session creation returns 403 with slice-subscription error (hardened) vs. 201 Created (isolation failure — Critical finding). Record HTTP status + core logs.

---

## TC-009: Open5GS WebUI Default-Credential Takeover (CVE-2021-25863)

**Objective**: Confirm whether the management WebUI is exposed with default credentials and demonstrate subscriber-account impact.

**Arrange**: Lab Open5GS with WebUI enabled; `nmap -p 3000 <core-host>` confirms exposure.

**Act**: Authenticate with the documented default (`admin`/`1423`); create a subscriber entry with attacker-controlled key material; register a lab UE with the injected credentials.

**Assert**: Login succeeds and the injected subscriber registers through the core (finding: full subscriber-plane takeover). Counter-evidence: login rejected or WebUI bound to loopback (hardened). Cite CVE-2021-25863.

---

## TC-010: AMF Robustness under Crafted Registration (CVE-2021-44081 class)

**Objective**: Assess core stability against malformed MSIN/NAS fields from the UE side.

**Arrange**: Lab core with AMF health monitored (`journalctl -u open5gs-amfd -f`); srsRAN UE with patchable NAS builder.

**Act**: Submit registrations with oversized MSIN length and malformed FQDN AVPs (payloads §4/§10 corpus), 100 iterations per mutation class.

**Assert**: All malformed inputs rejected with protocol errors and zero AMF restarts/WatchDog loss (hardened). Any AMF crash reproduces with 2/5 runs → DoS finding citing CVE-2021-44081 / CVE-2021-41794 class behavior observed.

---

## Test Suite Summary

10 test cases: defensive verification stubs (TC-001..005) plus offensive AAA cases (TC-006..010) mapping to payloads §2/§5/§6/§7/§11 (rogue NF registration, SUCI/paging privacy, slice escape, WebUI takeover, AMF robustness).
