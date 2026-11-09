# Test Cases — edge-computing-security

> Structured test cases for edge-computing-security (authorized targets / lab CDN only).

## TC-001: Origin IP Hidden

**Objective**: Verify origin IP is not discoverable (§2 of payloads).

**Arrange**: Known discovery toolkit (crt.sh, DNS history, favicon hash pivot).

**Act**: Run full origin-discovery workflow against authorized domain.

**Assert**: No exposed origin IP serves the target vhost; any hit = critical finding.

---

## TC-002: Cache Poisoning Prevention

**Objective**: Verify unkeyed inputs cannot poison shared cache (§5).

**Arrange**: Lab CDN/proxy in front of test origin.

**Act**: Inject X-Forwarded-Host/X-Original-URL/fat-GET variants; request cached page from second vantage.

**Assert**: Second client never receives attacker-controlled content; cache keys validated.

---

## TC-003: Edge Function Sandbox

**Objective**: Verify edge functions are isolated from origin network.

**Arrange**: Deploy test Worker/Lambda@Edge in owned account.

**Act**: Attempt origin-network access, metadata endpoint reads, secret env exposure.

**Assert**: Sandbox blocks lateral network; no secrets in responses or error pages.

---

## TC-004: Edge Recon Detection

**Objective**: Detect origin-discovery probing (§1–§2).

**Arrange**: CDN/WAF logs to SIEM.

**Act**: Run CNAME/CT-log/favicon-hash/origin-scan workflow from test IP.

**Assert**: Recon correlation alert within 15 min; silent pass = visibility gap.

---

## TC-005: Layered Bypass Fallback

**Objective**: Verify defense holds when WAF bypass pairs with origin access (§3–§4).

**Arrange**: Block first bypass vector (direct-to-origin blocked at origin ACL).

**Act**: Chain encoding bypass + protocol downgrade + slow requests.

**Assert**: Each fallback independently detected/blocked; matrix recorded.

---

## TC-006: CDN WAF Rule Effectiveness

**Objective**: Baseline WAF coverage against encoded/protocol-variant attacks (§4).

**Arrange**: Lab WAF with production rule set.

**Act**: Fire encoded XSS/SQLi, HTTP/1.0 and HTTP/3 variants, header-order fuzz.

**Assert**: No variant reaches origin unfiltered; bypasses documented as findings.

---

## TC-007: Web Cache Deception Protection

**Objective**: Verify authenticated content is never cached under static suffixes (§6).

**Arrange**: Authenticated lab app behind cache; session cookie.

**Act**: Request /account/settings.js, /account;/settings.css, %-encoded variants.

**Assert**: Cache MISS + auth enforcement on all variants; any unauth HIT = critical.

---

## TC-008: Edge Rate-Limit Effectiveness

**Objective**: Verify limits resist rotation/downgrade abuse (§4, §9).

**Arrange**: Lab rate limiter; controlled IP pool.

**Act**: Rotate sources, shuffle headers, use slow-header pins.

**Assert**: Aggregate anomaly detection fires beyond per-IP limits; no cheap bypass.

---

## TC-009: Origin Shield Failover Integrity

**Objective**: Verify shield failover cannot be weaponized for DoS (§9).

**Arrange**: Lab origin shield + cache tier.

**Act**: Drive uncacheable-variant fan-out and range amplification at authorized scale.

**Assert**: Shield enforces origin protection (collapse/coalescing); degradation graceful.

---

## TC-010: Edge Configuration Drift Audit

**Objective**: Detect unauthorized edge config/worker changes (§8, §10).

**Arrange**: Baseline config snapshot + CI alerting.

**Act**: Deploy a benign canary worker; modify one cache rule.

**Assert**: Drift alert fires within one polling cycle; rollback path verified.

---

## TC-011: HTTP/2 Smuggling Detection

**Objective**: Detect h2-downgrade desync at the edge (§7).

**Arrange**: h2 front-end + HTTP/1.1 origin lab (ATS/nginx/varnish variants).

**Act**: Run CL.TE/TE.CL/h2-prior-knowledge probes with timing oracle.

**Assert**: Desync probe alerted (or negative-result documented per stack version).

---

## TC-012: Edge Secret Exposure Audit

**Objective**: Verify no secrets leak via edge functions/proxies (§8).

**Arrange**: Deployed edge middleware in lab.

**Act**: Probe .env, debug/vars, proxy SSRF canary, error-page stack traces.

**Assert**: 404/403 on all secret paths; no internal URLs or tokens in any response.

---

## TC-013: Cache-Key Normalization Audit

**Objective**: Verify edge/origin agree on cache-key normalization (§5).

**Arrange**: Lab edge cache + origin with known fragment/path handling.

**Act**: Request fragment (#), double-slash, %-encoded separator, and dot-segment variants; compare cached vs origin responses.

**Assert**: No variant yields divergent cached content (poison class, CVE-2021-27577 family); divergences documented.

---

## Test Suite Summary

13 test cases: origin protection, cache poisoning/deception, WAF effectiveness, smuggling, edge-function secrets, shield DoS, and config-drift audit — maps to payloads §1–§12.
