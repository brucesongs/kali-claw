# Test Cases — hardware-side-channel-advanced

> Structured test cases for hardware-side-channel-advanced.

## TC-001: DPA Resistance

**Objective**: Verify AES implementation resists DPA.

**Arrange**: Capture 10K power traces.

**Act**: Run DPA attack.

**Assert**: Key not recovered within 1M traces.

---

## TC-002: Glitch Resistance

**Objective**: Verify device resists voltage glitch.

**Arrange**: Apply glitch at various offsets/widths.

**Act**: Attempt secure boot bypass.

**Assert**: No bypass within 10K glitch attempts.

---

## TC-003: Cache-timing Resistance

**Objective**: Verify SGX enclave resists cache-timing.

**Arrange**: Run cache-timing attack from outside enclave.

**Act**: Attempt secret recovery.

**Assert**: Secret not recovered.


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
