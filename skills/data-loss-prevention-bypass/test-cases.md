# Test Cases — data-loss-prevention-bypass

> Structured test cases for data-loss-prevention-bypass.

## TC-001: DNS Tunneling Detection

**Objective**: Verify DLP detects DNS tunneling.

**Arrange**: Run dnscat2 over DNS.

**Act**: Transfer 10MB of data via DNS tunnel.

**Assert**: DLP alert within 5 minutes; tunnel blocked.

---

## TC-002: Image Steganography Detection

**Objective**: Verify DLP detects LSB steganography.

**Arrange**: Embed sensitive data in image via steghide.

**Act**: Upload image to cloud storage.

**Assert**: DLP flags image for steganography inspection.

---

## TC-003: Cloud Sync Exfil Detection

**Objective**: Verify CASB detects cloud sync exfil.

**Arrange**: Upload sensitive data to OneDrive.

**Act**: Upload 100MB of PII to OneDrive.

**Assert**: CASB alert; upload rate limited.

---

## TC-004: ICMP Tunneling Detection

**Objective**: Verify network monitoring detects ICMP tunneling.

**Arrange**: Run ICMP tunnel.

**Act**: Transfer data via ICMP.

**Assert**: Network monitoring alert on large ICMP packets.

---

## TC-005: Slow Exfiltration Detection

**Objective**: Verify behavioral analytics detect slow exfil.

**Arrange**: Exfil data at 100KB/hr.

**Act**: Spread 10MB over 100 hours.

**Assert**: UEBA alert on anomalous egress pattern.


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

## Test Suite Summary

5 test cases covering reconnaissance, exploitation, persistence, detection, and defense bypass.
"""

---

## TC-006: SaaS API Masquerade Detection

**Objective**: Verify DLP covers exfiltration over allowed SaaS APIs (file upload to personal cloud)

**Arrange**: DLP with SaaS/CASB integration enabled in lab; personal-drive account under tester control

**Act**: Upload a marked 10MB dataset to personal cloud storage via the official sync client and API

**Assert**: Upload alerted/blocked or flagged for review; silent success = coverage gap finding

---

## TC-007: Covert Timing Channel Baseline

**Objective**: Verify anomalous inter-request timing patterns (data-encoded delays) raise detection

**Arrange**: Lab egress with timing capture; scripted encoder mapping bits to request delays

**Act**: Exfiltrate a 1KB marker via request-timing encoding over 10 minutes, then 60 minutes

**Assert**: Timing-anomaly detection fires on the fast channel, or both rates pass undetected and the gap is documented

---

## TC-008: Endpoint DLP Agent Bypass Verification

**Objective**: Verify endpoint DLP cannot be sidestepped by unmonitored processes and paths

**Arrange**: Endpoint DLP agent deployed on lab host; standard user privileges

**Act**: Attempt transfers via paths commonly unmonitored: alternate data streams, guest-session SMB, novel browser profile, portable app

**Assert**: Each path either blocked/alarmed or confirmed unmonitored — complete bypass matrix recorded for tuning

---

