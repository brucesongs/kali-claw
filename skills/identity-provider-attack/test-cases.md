# Test Cases — identity-provider-attack

> Structured test cases for identity-provider-attack.

## TC-001: JWT Algorithm Confusion

**Objective**: Verify JWT validation rejects algorithm confusion.

**Arrange**: Get RS256-signed JWT; forge as HS256 with public key.

**Act**: Submit forged JWT to API.

**Assert**: API rejects with 401 Unauthorized.

---

## TC-002: OAuth redirect_uri Validation

**Objective**: Verify redirect_uri validation prevents open redirect.

**Arrange**: Construct malicious redirect_uri variations.

**Act**: Submit authorization request with each variation.

**Assert**: All malicious redirect_uri values rejected.

---

## TC-003: MFA Bypass via Legacy Protocol

**Objective**: Verify legacy protocols enforce MFA.

**Arrange**: Attempt IMAP/SMTP login with stolen credentials.

**Act**: Execute legacy protocol login.

**Assert**: Login blocked or MFA required.

---

## TC-004: Token Replay Detection

**Objective**: Verify token replay is detected.

**Arrange**: Capture JWT; replay from different IP.

**Act**: Submit same JWT from new source IP.

**Assert**: Monitoring alert; subsequent use blocked.

---

## TC-005: OAuth Consent Grant Audit

**Objective**: Verify excessive OAuth consent grants are flagged.

**Arrange**: User grants consent to malicious OAuth app.

**Act**: Review OAuth consent audit log.

**Assert**: Alert on high-privilege scope grant.


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
