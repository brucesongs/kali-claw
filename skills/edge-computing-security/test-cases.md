# Test Cases — edge-computing-security

> Structured test cases for edge-computing-security.

## TC-001: Origin IP Hidden

**Objective**: Verify origin IP is not discoverable.

**Arrange**: Use DNS history, SSL cert search.

**Act**: Attempt to find direct origin IP.

**Assert**: No direct IP found; only CDN IPs.

---

## TC-002: Cache Poisoning Prevention

**Objective**: Verify cache key includes all relevant headers.

**Arrange**: Test unkeyed headers (X-Forwarded-Host).

**Act**: Submit malicious request.

**Assert**: Response not poisoned for other users.

---

## TC-003: Edge Function Sandbox

**Objective**: Verify edge functions are sandboxed.

**Arrange**: Deploy malicious Worker/Lambda.

**Act**: Attempt to access origin network.

**Assert**: Sandbox blocks network access.


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
