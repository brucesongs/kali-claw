# Test Cases — data-loss-prevention-bypass

> Structured test cases for data-loss-prevention-bypass (authorized lab / DLP coverage validation).

## TC-001: DNS Tunneling Detection

**Objective**: Verify DLP/NDR detects DNS tunneling.

**Arrange**: Run dnscat2 or iodine against an authorized lab domain.

**Act**: Transfer 10MB of marked data via DNS TXT tunnel.

**Assert**: Alert within 5 minutes (label entropy / NXDOMAIN ratio); tunnel blocked or flagged.

---

## TC-002: Image Steganography Detection

**Objective**: Verify DLP flags LSB steganography carriers.

**Arrange**: Embed marked data in cover.jpg via steghide (§5 of payloads).

**Act**: Upload image through sanctioned cloud sync.

**Assert**: DLP flags for stego inspection or content-classification review; silent pass = coverage gap.

---

## TC-003: Cloud Sync Exfil Detection

**Objective**: Verify CASB detects bulk cloud sync exfil.

**Arrange**: CASB integrated with tenant; marked PII dataset (100MB).

**Act**: Upload dataset to personal OneDrive via sync client and Graph API.

**Assert**: CASB alert + rate-limit/quarantine on both paths.

---

## TC-004: ICMP Tunneling Detection

**Objective**: Verify network monitoring detects ICMP tunnels.

**Arrange**: pingtunnel/icmpsh lab against authorized egress.

**Act**: Transfer 1MB via ICMP echo payloads at 1 pkt/s.

**Assert**: Alert on oversized/monotonous ICMP payloads or timing baseline deviation.

---

## TC-005: Slow Exfiltration Detection

**Objective**: Verify UEBA catches slow-drip egress.

**Arrange**: Marked 10MB dataset; business-hours trickle profile (§13).

**Act**: Spread transfer over 100 hours at ~100KB/hr.

**Assert**: UEBA volume-anomaly alert on cumulative egress; document detection latency.

---

## TC-006: Egress Recon Detection

**Objective**: Detect DLP agent fingerprinting attempts (§2 of payloads).

**Arrange**: Endpoint DLP deployed; SIEM agent logs wired.

**Act**: Enumerate agent services/processes and query policy registry keys.

**Assert**: Tamper or recon alert on enumeration; silent pass = visibility gap.

---

## TC-007: Layered Evasion Fallback

**Objective**: Verify secondary controls when primary channel is blocked.

**Arrange**: Block DNS tunnel (TC-001 alert path).

**Act**: Switch to DoH relay (§6) then ICMP (§7); repeat marked transfer.

**Assert**: Fallback channels independently alerted; complete bypass matrix recorded.

---

## TC-008: SaaS API Masquerade Detection

**Objective**: Verify DLP covers exfil over allowed SaaS APIs.

**Arrange**: DLP/CASB with SaaS integration; personal-drive account under tester control.

**Act**: Upload marked 10MB dataset via official sync client and API (renamed extension, polyglot carrier §4).

**Assert**: Upload alerted/blocked or flagged; silent success on any variant = finding.

---

## TC-009: Covert Timing Channel Baseline

**Objective**: Detect data-encoded inter-request timing (§11).

**Arrange**: Lab egress with timing capture; scripted bit-delay encoder.

**Act**: Exfil 1KB marker via request-timing over 10 min, then 60 min.

**Assert**: Timing-anomaly detection fires on fast channel, or gap documented for tuning.

---

## TC-010: Endpoint DLP Agent Bypass Verification

**Objective**: Verify endpoint DLP covers unmonitored paths (§2/§4).

**Arrange**: Endpoint agent deployed; standard user privileges.

**Act**: Attempt transfers via ADS, guest-session SMB, novel browser profile, portable app.

**Assert**: Each path blocked/alarmed or confirmed unmonitored — full bypass matrix recorded.

---

## TC-011: Polyglot & Encrypted-Archive Evasion

**Objective**: Verify inspection of dual-nature/encrypted containers (§4).

**Arrange**: GIF/ZIP polyglot + header-encrypted 7z carrying marked data.

**Act**: Transfer both through proxy and upload lanes.

**Assert**: Polyglot flagged by structural analysis; encrypted archive quarantined by policy; gaps documented.

---

## TC-012: DoH Covert Channel Coverage

**Objective**: Verify coverage when DNS rides HTTPS (§6 DoH variant).

**Arrange**: DNS-inspecting proxy + HTTPS egress logging.

**Act**: Relay marked chunks via public DoH resolver POST/GET patterns.

**Assert**: DoH endpoint volume/entropy alert fires, or coverage gap recorded.

---

## TC-013: Presigned-URL & SAS Exfil Detection

**Objective**: Verify detection of object-store credential abuse (§9).

**Arrange**: Cloud SIEM with S3/blob data-plane logs; leaked-test presigned URL + SAS token.

**Act**: Upload marked data via presigned URL and SAS token to tester-controlled storage.

**Assert**: Anomalous write (new object prefix/pattern) alerted; token scope abuse flagged.

---

## Test Suite Summary

13 test cases: channels (DNS/ICMP/DoH/SaaS/cloud/timing/stego/polyglot), endpoint agent coverage, layered fallback, and credential-abuse exfil — maps to payloads §2–§13.
