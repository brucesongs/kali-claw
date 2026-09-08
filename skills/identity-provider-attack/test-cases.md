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

---

## TC-006: SAML Signature Wrapping (XSW) Attack

- **Objective**: Bypass SAML assertion signature verification via signature-wrapping transformations
- **Severity**: HIGH
- **Prerequisites**: SP with SAML SSO in scope; a captured signed assertion; XSW tooling (SAML Raider / Burp)
- **Test Steps**:
  1. Capture a valid signed assertion via the lab IdP login
  2. Apply XSW variants 1-8 (SAML Raider): clone the assertion, modify NameID, reposition SignatureValue references
  3. Replay each wrapped response to the SP ACS endpoint
  4. Record which variant authenticates as the forged identity
  5. Confirm root cause (signature applied to original assertion node only)
- **Expected Result**: At least one XSW variant authenticates as the forged user, or all variants rejected with signature-reference validation verified

## TC-007: OAuth Mix-Up / Token Substitution

- **Objective**: Confuse an OAuth client about which IdP issued a token, replaying one IdP's token against another
- **Severity**: HIGH
- **Prerequisites**: Client registered with multiple IdPs (lab); valid tokens from both
- **Test Steps**:
  1. Obtain token A from IdP-1 for victim account
  2. Initiate flow against IdP-2 but submit token A at the token-validation step
  3. Observe whether the client accepts the foreign token and mints a session
  4. If accepted, test privilege implications (victim identity binding)
  5. Verify `azp`/`iss` claim validation as the missing control
- **Expected Result**: Foreign-token acceptance mints an authenticated session (mix-up confirmed) or all cross-IdP substitutions rejected

## TC-008: IdP Metadata Injection

- **Objective**: Poison SP trust in the IdP by injecting attacker-controlled metadata (entity ID / endpoint)
- **Severity**: HIGH
- **Prerequisites**: SP consuming IdP metadata (URL or file) in a lab; write access to a metadata source the SP refreshes
- **Test Steps**:
  1. Register/modify metadata: point AssertionConsumerService or SingleSignOnService to attacker endpoints
  2. Trigger SP metadata refresh (TTL expiry or forced reload)
  3. Initiate SSO: SP redirects to attacker-controlled endpoint
  4. Return a forged assertion signed by the attacker key from the injected metadata
  5. Verify session minting
- **Expected Result**: SP follows the injected metadata and accepts the forged assertion — full IdP impersonation via trust-anchor poisoning

