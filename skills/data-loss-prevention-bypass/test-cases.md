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
