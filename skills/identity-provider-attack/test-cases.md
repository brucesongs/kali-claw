# Test Cases — identity-provider-attack

> Structured, authorized-laboratory test cases. Each case must be executed against controlled identities and stopped as soon as the trust decision is proven.

## TC-001: JWT Algorithm Confusion

**Severity**: High

**Arrange**

1. Obtain a valid RS256 ID token from the lab IdP.
2. Retrieve the corresponding public key from JWKS.
3. Confirm that the verifier advertises accepted algorithms.

**Act**

1. Re-sign the token as HS256 using the public key bytes as the HMAC secret.
2. Preserve the original `kid`.
3. Submit the token to the protected API.

**Assert**

- Pass control: the original RS256 token is accepted.
- Finding: the HS256 token is accepted.
- Evidence: request/response, accepted algorithm log, and verifier configuration.

## TC-002: OAuth redirect_uri Validation

**Severity**: High

**Arrange**

1. Register an attacker-controlled callback in the lab.
2. Build the redirect validation matrix in `payloads.md`.
3. Enable request logging on the callback collector.

**Act**

1. Submit one authorization request per redirect value.
2. Observe provider acceptance and code delivery separately.
3. Exchange only codes returned to the controlled callback.

**Assert**

- Exact registered redirect values remain functional.
- Path, query, host-suffix, case, and Unicode variants are rejected.
- Any delivered code is tied to evidence from the callback collector.

## TC-003: PKCE Downgrade Resistance

**Severity**: Medium

**Arrange**

1. Identify a public OAuth client.
2. Capture a normal authorization request containing S256 PKCE.
3. Record provider metadata and client type.

**Act**

1. Remove `code_challenge` and `code_challenge_method`.
2. Retry with `plain`.
3. Retry with a valid S256 challenge from a different browser session.

**Assert**

- Public clients require S256.
- A missing or plain challenge does not issue an authorization code.
- The code is bound to the original verifier/session.

## TC-004: SAML Signature Wrapping

**Severity**: High

**Arrange**

1. Capture a valid signed SAML response.
2. Load it into the approved XSW tooling.
3. Record the service provider's expected assertion and signature reference.

**Act**

1. Apply XSW variants one at a time.
2. Modify only the cloned assertion's NameID.
3. Replay each response to the lab ACS endpoint.

**Assert**

- All wrapped responses are rejected, or one acceptance is isolated to a single variant.
- Evidence identifies the processed assertion ID and signature reference.
- Root cause distinguishes signature wrapping from missing signature enforcement.

## TC-005: OAuth Mix-Up and Token Substitution

**Severity**: High

**Arrange**

1. Configure Client C for both IdP-1 and IdP-2.
2. Obtain a valid token for the lab victim from IdP-1.
3. Preserve both flows' state and nonce values.

**Act**

1. Start a flow with IdP-2.
2. Substitute IdP-1's callback values or token.
3. Observe whether Client C mints a session.

**Assert**

- `iss`, `aud`, `azp`, and state association are validated together.
- A foreign token cannot mint a session.
- Any acceptance is mapped to the exact missing field.

## TC-006: OIDC Claim and Audience Confusion

**Severity**: High

**Arrange**

1. Obtain ID and access tokens for two controlled audiences.
2. Decode claims without altering signatures.
3. Record the verifier's expected issuer and audience values.

**Act**

1. Submit Audience-A token to Audience-B.
2. Independently vary issuer, audience, authorized party, subject, and nonce.
3. For multi-audience tokens, test missing `azp`.

**Assert**

- Every field is checked independently and in combination.
- Tenant issuer suffix matching is not accepted.
- Subject identity cannot be selected through an email hint.

## TC-007: Workload Identity Federation Subject Mismatch

**Severity**: High

**Arrange**

1. Configure a lab trust policy for one repository and branch.
2. Obtain two valid external issuer tokens for controlled subjects.
3. Record the policy's issuer, audience, subject claim, and condition.

**Act**

1. Change repository, environment, actor, workflow, branch, or issuer one field at a time.
2. Exchange each assertion under the trust policy.
3. Compare the resulting workload identity and roles.

**Assert**

- Only the exact configured subject exchanges successfully.
- Changed fields are rejected before role assignment.
- Evidence includes the accepted claim set with secrets redacted.

## TC-008: MFA Request Generation and Legacy Protocol Policy

**Severity**: Medium

**Arrange**

1. Use a controlled victim account with push or one-time-password MFA.
2. Set the request count within the authorized rate limit.
3. Confirm whether IMAP, SMTP, or POP remains enabled.

**Act**

1. Generate the approved number of MFA challenges.
2. Attempt one controlled legacy-protocol login.
3. Review the IdP risk and MFA audit events.

**Assert**

- Number matching or FIDO2 does not create an approval oracle.
- Legacy protocols are blocked or forced through MFA.
- Alerting identifies repeated challenges and legacy authentication.

## TC-009: Conditional Access Trust Bypass

**Severity**: High

**Arrange**

1. Create a policy requiring compliant devices, a trusted location, or risk-based authentication.
2. Register one compliant and one non-compliant controlled device.
3. Preserve the gateway topology and header-trust documentation.

**Act**

1. Attempt access from the non-compliant device.
2. Test approved-location representation without spoofing a third party.
3. Compare token device, IP, user agent, and risk claims.

**Assert**

- Non-compliant devices receive denied or limited tokens.
- Location decisions include risk and device posture, not IP alone.
- The application enforces scopes and device claims rather than trusting forwarded headers.

## TC-010: OAuth Consent and Refresh Token Persistence

**Severity**: High

**Arrange**

1. Register a lab OAuth application requesting `mail.read` or an equivalent read scope.
2. Use a non-admin user and an approved callback.
3. Enable consent and token issuance logging.

**Act**

1. Complete the user-consent flow.
2. Record the refresh token family and rotation behavior.
3. Reuse the old refresh token and attempt exchange from a different client.

**Assert**

- High-privilege scopes require admin consent or publisher verification.
- Refresh token reuse triggers family revocation.
- A different client or redirect cannot redeem the token.
- Consent and revocation are visible in audit logs.

## Coverage Summary

| Area | Cases |
|------|-------|
| OAuth/OIDC flow integrity | TC-002, TC-003, TC-005, TC-006 |
| JWT and SAML trust | TC-001, TC-004 |
| Federation and workload identity | TC-007 |
| MFA, session, and conditional access | TC-008, TC-009 |
| Persistence and token lifecycle | TC-010 |
