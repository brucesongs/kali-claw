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
| **Total** | **12** | **INFO - CRITICAL** |

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
