# Test Cases — quantum-cryptography-transition

> Structured test cases for quantum-cryptography-transition.

## TC-001: HNDL Risk Assessment

**Objective**: Identify long-lived secrets vulnerable to HNDL.

**Arrange**: Audit encrypted traffic for long-lived keys.

**Act**: Catalog secrets with >10 year confidentiality.

**Assert**: HNDL risk register created.

---

## TC-002: PQC Migration Readiness

**Objective**: Verify organization's PQC readiness.

**Arrange**: Inventory cryptographic libraries.

**Act**: Test PQC support per library.

**Assert**: PQC readiness report generated.

---

## TC-003: Hybrid TLS Strength

**Objective**: Verify hybrid uses strong combiner.

**Arrange**: Inspect hybrid implementation.

**Act**: Verify HKDF (not XOR) combiner.

**Assert**: Strong combiner confirmed.


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
