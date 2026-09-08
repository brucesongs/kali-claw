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

---

## TC-006: CDN WAF Rule Effectiveness

**Objective**: Verify the CDN WAF blocks known attack classes at the edge

**Arrange**: Deploy lab origin + CDN WAF in front; OWASP CRS ruleset enabled at chosen sensitivity

**Act**: Send representative attack probes (SQLi/XSS/path traversal payloads) through the CDN hostname

**Assert**: All probe classes blocked or scored at the edge; zero probes reach origin logs

---

## TC-007: Web Cache Deception Protection

**Objective**: Verify cache does not store authenticated personalized content

**Arrange**: Lab site behind cache with authenticated session; cache rules active

**Act**: Request authenticated pages with cacheable suffixes (e.g., `/account/settings.css`) while logged in

**Assert**: No personalized content cached; response headers mark authenticated paths uncacheable (or the suffix trick returns the public variant)

---

## TC-008: Edge Rate-Limit Effectiveness

**Objective**: Verify rate limiting neutralizes credential-stuffing-class traffic

**Arrange**: Rate-limit rule configured at the edge (e.g., 10 req/min/login path)

**Act**: Drive 200 rapid login attempts from one source and from distributed simulated sources

**Assert**: Single-source burst throttled with 429s; distributed slow pattern either challenged or alerted to SIEM

---

## TC-009: Origin Shield Failover Integrity

**Objective**: Verify failover does not bypass protections or leak errors

**Arrange**: Multi-PoP CDN with origin shield; lab ability to take the primary origin down briefly

**Act**: Stop primary origin; drive traffic during failover to backup origin

**Assert**: Failover completes with protections intact (WAF rules, TLS, headers); no stack traces or internal hosts leak in error pages

---

## TC-010: Edge Configuration Drift Audit

**Objective**: Verify edge configuration matches the hardened baseline after changes

**Arrange**: Baseline config snapshot (rules, TLS policy, cache policy) stored in version control

**Act**: Diff current edge config against the baseline after a routine change window

**Assert**: Drift limited to intended changes only; any unintended rule/TLS downgrades flagged and reverted

---

