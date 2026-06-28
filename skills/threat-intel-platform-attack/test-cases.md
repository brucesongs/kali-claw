# Threat Intel Platform Attack — Test Cases

> Structured test cases for threat intel platform security assessments. Each case covers a specific platform vulnerability or abuse vector. Use during scoping, recon, exploitation, and validation phases.

## Section A — Recon

### TC-TI-001 — Platform identification via version check

**Objective**: Identify TI platform vendor + version from external surface.

**Severity**: Medium

**Prerequisite**:
- Target URL
- Network access to target

**Test Step**:
1. Curl MISP version endpoint
2. Curl OpenCTI GraphQL endpoint
3. Curl Anomali ThreatStream endpoint
4. Curl ThreatQuotient endpoint
5. Identify vendor from response

**Expected Result**: Platform vendor + version identified.

**Pass Criteria**: Vendor confirmed via multiple indicators.

**Remediation**: Restrict version endpoint (no auth).

---

### TC-TI-002 — Subdomain enumeration for TI infrastructure

**Objective**: Identify TI platform subdomains beyond primary.

**Severity**: Medium

**Prerequisite**:
- Domain name
- Subfinder / Amass

**Test Step**:
1. Run subfinder on domain
2. Run Amass passive enum
3. Grep for TI platform indicators (misp, opencti, threat)
4. Document discovered subdomains

**Expected Result**: All TI platform subdomains identified.

**Pass Criteria**: Subdomain list matches actual deployment.

**Remediation**: Restrict DNS, remove unused subdomains.

---

### TC-TI-003 — Exposed header enumeration

**Objective**: Identify platform fingerprinting headers.

**Severity**: Low

**Prerequisite**:
- Network access to target

**Test Step**:
1. Curl -sI to identify Server, X-Powered-By, Set-Cookie
2. Identify platform from headers
3. Document exposure

**Expected Result**: Headers reveal platform info.

**Pass Criteria**: Headers enumerated.

**Remediation**: Strip identifying headers via reverse proxy.

---

## Section B — MISP attacks

### TC-TI-004 — MISP version disclosure (CVE-2022-29527 pre-check)

**Objective**: Identify MISP version vulnerable to known CVEs.

**Severity**: High

**Prerequisite**:
- MISP instance accessible
- No auth required for version check

**Test Step**:
1. Curl `https://misp.example.com/servers/checkVersion`
2. Parse JSON response
3. Compare version to CVE advisory (CVE-2022-29527 affects <2.4.155)
4. Document findings

**Expected Result**: Version identified; CVE exposure determined.

**Pass Criteria**: Version accurately parsed.

**Remediation**: Update MISP to latest; restrict version endpoint.

---

### TC-TI-005 — MISP API enumeration

**Objective**: Enumerate MISP events / orgs / sharing groups via API.

**Severity**: High

**Prerequisite**:
- Valid MISP API key
- Network access

**Test Step**:
1. Curl `/events/index` endpoint
2. Curl `/organisations/index`
3. Curl `/sharingGroups/index`
4. Curl `/admin/users/index` (admin key)
5. Document findings

**Expected Result**: All accessible resources enumerated.

**Pass Criteria**: Resource list matches actual data.

**Remediation**: Restrict API to minimum necessary endpoints.

---

### TC-TI-006 — MISP CVE-2022-29527 XSS exploitation

**Objective**: Verify stored XSS via event.info field.

**Severity**: High

**Prerequisite**:
- MISP < 2.4.155
- Valid API key (any permission level)

**Test Step**:
1. Create event with XSS payload in info field: `<script>alert('XSS')</script>`
2. View event in UI (admin user)
3. Verify XSS executes
4. Document PoC

**Expected Result**: XSS executes when event viewed.

**Pass Criteria**: JavaScript alert fires in browser.

**Remediation**: Patch MISP to >= 2.4.155.

---

### TC-TI-007 — MISP false-positive IOC injection

**Objective**: Verify attacker can inject legitimate infrastructure as malicious IOC.

**Severity**: Critical

**Prerequisite**:
- Valid MISP API key with write permission
- Target infrastructure (legitimate-looking)

**Test Step**:
1. Create event titled "Suspected APT29 C2 - high confidence"
2. Inject legitimate domains as IOCs (google.com, amazonaws.com, etc.)
3. Set distribution=0 (all communities)
4. Set to_ids=True (will block on downstream defensive products)
5. Verify IOC ingestion

**Expected Result**: False-positive IOCs propagated to downstream consumers.

**Pass Criteria**: Event visible to downstream; IOCs flagged.

**Remediation**: Peer review for new events; anomaly detection on bulk IOC injection.

---

### TC-TI-008 — MISP sharing-group trust escalation

**Objective**: Verify attacker can escalate sharing-group access.

**Severity**: Critical

**Prerequisite**:
- Valid low-trust API key
- Target high-trust sharing group ID

**Test Step**:
1. Enumerate sharing groups via `/sharingGroups/index`
2. Attempt to add self to higher-trust group via `/sharingGroups/addOrg/$GROUP_ID`
3. Test if escalation succeeds
4. Document finding

**Expected Result**: Trust escalation blocked.

**Pass Criteria**: Escalation attempt fails (403 or similar).

**Remediation**: Enforce RBAC on sharing-group membership; audit log all changes.

---

### TC-TI-009 — MISP sync server abuse

**Objective**: Verify attacker can register attacker-controlled sync server.

**Severity**: Critical

**Prerequisite**:
- Admin API key
- Attacker-controlled MISP instance

**Test Step**:
1. Curl `/servers/add` to register attacker MISP
2. Configure pull=true (events from attacker flow to victim)
3. Push false-positive events from attacker MISP
4. Verify sync completes
5. Document finding

**Expected Result**: Sync server registered; events flow.

**Pass Criteria**: False-positive events appear in victim MISP.

**Remediation**: Sync server review process; MFA on admin actions.

---

### TC-TI-010 — MISP audit log wipe

**Objective**: Verify attacker can wipe audit logs to cover tracks.

**Severity**: High

**Prerequisite**:
- Admin API key
- Active audit logs

**Test Step**:
1. Generate audit events (create user, modify event)
2. Curl `/admin/logs/deleteAll` to wipe logs
3. Verify logs removed
4. Document finding

**Expected Result**: Logs wiped with no recovery.

**Pass Criteria**: Logs removed from database.

**Remediation**: External immutable audit log sink (Splunk, Chronicle, S3 with lock).

---

## Section C — OpenCTI attacks

### TC-TI-011 — OpenCTI GraphQL introspection enabled

**Objective**: Verify GraphQL introspection is enabled (information disclosure).

**Severity**: Medium

**Prerequisite**:
- OpenCTI instance accessible
- Network access

**Test Step**:
1. Curl GraphQL with introspection query
2. Verify schema exposed
3. Enumerate all types and fields
4. Document finding

**Expected Result**: Full schema exposed.

**Pass Criteria**: Schema documented.

**Remediation**: Disable introspection in production.

---

### TC-TI-012 — OpenCTI GraphQL injection

**Objective**: Verify GraphQL injection in ID parameter.

**Severity**: High

**Prerequisite**:
- OpenCTI instance accessible
- Valid token

**Test Step**:
1. Send `report(id: "1 OR 1=1")` query
2. Send `report(id: "1; DROP TABLE")` query
3. Send `report(id: "1 UNION SELECT")` query
4. Document responses

**Expected Result**: Injection attempts blocked.

**Pass Criteria**: No data leakage; no SQL errors.

**Remediation**: Input validation; parameterized queries; rate limit.

---

### TC-TI-013 — OpenCTI IDOR via ID iteration

**Objective**: Verify IDOR via report/event ID iteration.

**Severity**: High

**Prerequisite**:
- OpenCTI instance accessible
- Valid token
- Existing report IDs

**Test Step**:
1. Send `report(id: "1")` query
2. Iterate ID from 1 to 100
3. Document accessible reports
4. Identify unauthorized access

**Expected Result**: Only authorized reports accessible.

**Pass Criteria**: Unauthorized reports return 403 or null.

**Remediation**: RBAC enforcement at resolver layer.

---

### TC-TI-014 — OpenCTI SSRF via import URL

**Objective**: Verify SSRF via import-from-URL feature.

**Severity**: Critical

**Prerequisite**:
- OpenCTI instance accessible
- Valid token with import permission
- AWS instance (for IMDS check)

**Test Step**:
1. Submit import URL `http://169.254.169.254/latest/meta-data/`
2. Verify IMDS response captured
3. Submit URL to internal services
4. Document findings

**Expected Result**: SSRF blocked or restricted.

**Pass Criteria**: No IMDS data exfil; no internal service access.

**Remediation**: Allowlist for import URLs; block IMDS range.

---

### TC-TI-015 — OpenCTI feed poisoning via STIX bundle

**Objective**: Verify attacker can submit false-positive STIX bundle.

**Severity**: Critical

**Prerequisite**:
- OpenCTI instance accessible
- Valid token
- STIX 2.1 library

**Test Step**:
1. Author STIX bundle with false-positive indicator (e.g., google.com as malicious)
2. Author false malware family (Windows Defender)
3. Submit via uploadImport mutation
4. Verify bundle ingested
5. Verify propagation to downstream

**Expected Result**: False-positive data ingested + propagated.

**Pass Criteria**: Bundle visible in OpenCTI; downstream receives.

**Remediation**: STIX signing; feed source attestation.

---

## Section D — STIX/TAXII feed attacks

### TC-TI-016 — STIX bundle creation

**Objective**: Verify ability to author STIX 2.1 bundle.

**Severity**: Low

**Prerequisite**:
- Python stix2 library

**Test Step**:
1. Create Indicator with false-positive pattern
2. Create Malware with false attribution
3. Create Relationship
4. Bundle into JSON
5. Verify serialization

**Expected Result**: Valid STIX 2.1 bundle.

**Pass Criteria**: Bundle validates against STIX schema.

**Remediation**: N/A (capability).

---

### TC-TI-017 — TAXII feed discovery

**Objective**: Discover TAXII collections on target.

**Severity**: Medium

**Prerequisite**:
- TAXII endpoint accessible
- Valid credentials

**Test Step**:
1. Connect to TAXII server
2. Enumerate API roots
3. Enumerate collections per API root
4. Document collection titles + descriptions

**Expected Result**: All collections enumerated.

**Pass Criteria**: Collection list matches actual deployment.

**Remediation**: Restrict TAXII to authenticated users.

---

### TC-TI-018 — TAXII feed injection

**Objective**: Inject false-positive STIX bundle via TAXII.

**Severity**: Critical

**Prerequisite**:
- TAXII collection with write access
- Valid credentials
- STIX bundle ready

**Test Step**:
1. Connect to TAXII collection
2. Submit STIX bundle via add_objects
3. Verify bundle accepted
4. Verify downstream consumers receive

**Expected Result**: Bundle propagated to all consumers.

**Pass Criteria**: Consumers receive false-positive indicator.

**Remediation**: Sign STIX bundles; verify source before ingesting.

---

## Section E — Other TI platforms

### TC-TI-019 — Anomali ThreatStream API auth bypass

**Objective**: Verify Anomali API requires auth.

**Severity**: High

**Prerequisite**:
- Anomali instance accessible

**Test Step**:
1. Curl `/v1/intelligence/` without auth
2. Curl `/v1/intelligence/` with invalid auth
3. Curl with valid auth
4. Document responses

**Expected Result**: Unauthenticated requests rejected.

**Pass Criteria**: 401 on no-auth; 403 on invalid auth.

**Remediation**: Enforce auth; rate limit.

---

### TC-TI-020 — ThreatQuotient auth bypass

**Objective**: Verify ThreatQuotient auth bypass CVE.

**Severity**: Critical

**Prerequisite**:
- ThreatQuotient instance
- CVE-2023- cand

**Test Step**:
1. Submit request with empty X-Auth-Token
2. Submit with malformed X-Auth-Token
3. Document if any bypass works

**Expected Result**: All auth bypass attempts fail.

**Pass Criteria**: 401 on all attempts.

**Remediation**: Patch to latest version.

---

### TC-TI-021 — Palo Alto AutoFocus XSS

**Objective**: Verify stored XSS in AutoFocus sample metadata.

**Severity**: High

**Prerequisite**:
- AutoFocus instance accessible
- Valid API key

**Test Step**:
1. Submit sample with filename `<script>alert(1)</script>.exe`
2. View sample in UI
3. Verify XSS execution
4. Document PoC

**Expected Result**: XSS blocked.

**Pass Criteria**: No JS execution.

**Remediation**: Patch; sanitize metadata fields.

---

### TC-TI-022 — Mandiant Advantage GraphQL enumeration

**Objective**: Enumerate Mandiant Advantage GraphQL schema.

**Severity**: Medium

**Prerequisite**:
- Advantage instance accessible
- Valid token

**Test Step**:
1. Send introspection query
2. Document schema
3. Identify sensitive queries
4. Document findings

**Expected Result**: Schema enumerated.

**Pass Criteria**: Schema documented.

**Remediation**: Disable introspection; restrict sensitive queries.

---

### TC-TI-023 — IBM X-Force API enumeration

**Objective**: Enumerate IBM X-Force API endpoints.

**Severity**: Medium

**Prerequisite**:
- X-Force instance accessible
- Valid basic auth

**Test Step**:
1. Curl `/ip/8.8.8.8` endpoint
2. Curl `/cases/` endpoint
3. Test for over-permissioned token
4. Document findings

**Expected Result**: API access restricted to authorized endpoints.

**Pass Criteria**: Unauthorized endpoints return 403.

**Remediation**: Scope API tokens to specific endpoints.

---

## Section F — Sharing-group trust abuse

### TC-TI-024 — Sharing-group enumeration

**Objective**: Enumerate all sharing groups accessible to current user.

**Severity**: Medium

**Prerequisite**:
- Valid API key

**Test Step**:
1. Curl `/sharingGroups/index`
2. Document all visible sharing groups
3. Document their trust levels + member orgs
4. Identify higher-trust groups

**Expected Result**: All accessible sharing groups enumerated.

**Pass Criteria**: Sharing group list documented.

**Remediation**: Restrict sharing group visibility.

---

### TC-TI-025 — TLP enforcement testing

**Objective**: Verify TLP:AMBER content cannot be shared with TLP:GREEN audience.

**Severity**: High

**Prerequisite**:
- Low-trust API key
- Target sharing group with TLP:AMBER members

**Test Step**:
1. Create event with TLP:AMBER tag
2. Attempt to distribute to broader (TLP:GREEN) audience
3. Document if enforcement blocks

**Expected Result**: Distribution attempt blocked.

**Pass Criteria**: 403 or rejection response.

**Remediation**: Implement TLP policy engine; audit log violations.

---

### TC-TI-026 — Cross-platform trust escalation

**Objective**: Verify attacker cannot use MISP trust to escalate on OpenCTI (and vice versa).

**Severity**: Medium

**Prerequisite**:
- MISP + OpenCTI instances synced
- Valid MISP key

**Test Step**:
1. Inject event in MISP with high-trust tag
2. Sync to OpenCTI
3. Verify if OpenCTI respects MISP trust level
4. Document findings

**Expected Result**: Trust levels not portable across platforms.

**Pass Criteria**: OpenCTI applies its own trust evaluation.

**Remediation**: Define cross-platform trust mapping policy.

---

## Section G — False-positive IOC injection

### TC-TI-027 — Bulk false-positive IOC injection

**Objective**: Verify attacker can bulk-inject legitimate infrastructure as malicious.

**Severity**: Critical

**Prerequisite**:
- Valid API key with write permission
- Target infrastructure list

**Test Step**:
1. Create event "Suspected APT29 C2"
2. Inject 50+ legitimate domains as malicious IOCs
3. Set distribution=0 (all communities)
4. Set to_ids=True
5. Verify ingestion

**Expected Result**: 50+ IOCs ingested + propagated.

**Pass Criteria**: Downstream consumers receive all IOCs.

**Remediation**: Bulk-write anomaly detection; peer review for new events.

---

### TC-TI-028 — Slow injection (evade detection)

**Objective**: Verify attacker can slow-inject to evade detection.

**Severity**: High

**Prerequisite**:
- Valid API key
- Long engagement window

**Test Step**:
1. Create event with single IOC
2. Inject one IOC per hour for 24 hours
3. Verify if detection triggers
4. Document findings

**Expected Result**: Slow injection evades rate-based detection.

**Pass Criteria**: No alert during 24-hour window.

**Remediation**: Behavioral baseline (new event creation pattern).

---

### TC-TI-029 — False malware family attribution

**Objective**: Verify attacker can create false malware family attributed to legitimate software.

**Severity**: Critical

**Prerequisite**:
- OpenCTI / MISP with malware family support
- STIX 2.1 library

**Test Step**:
1. Author STIX Malware object: name="Windows Defender", malware_types=["backdoor"]
2. Author Indicator pointing to update.microsoft.com
3. Author Relationship (indicator indicates malware)
4. Submit via API
5. Verify ingestion

**Expected Result**: False malware family ingested.

**Pass Criteria**: Family visible in platform with false attributes.

**Remediation**: Peer review for new malware families; vendor verification.

---

## Section H — Supply-chain pivot

### TC-TI-030 — Identify downstream consumers

**Objective**: Enumerate all sync servers / feeds consuming the TI platform.

**Severity**: High

**Prerequisite**:
- Valid API key (admin preferred)

**Test Step**:
1. Curl `/servers/index` on MISP
2. Curl `feeds` GraphQL on OpenCTI
3. Document all sync relationships
4. Identify downstream impact surface

**Expected Result**: All downstream consumers identified.

**Pass Criteria**: Consumer list documented.

**Remediation**: Audit sync relationships quarterly.

---

### TC-TI-031 — Test downstream impact

**Objective**: Verify false-positive IOCs propagate to downstream defensive products.

**Severity**: Critical

**Prerequisite**:
- TI platform feeds firewall / SIEM / EDR
- Test IOC ready

**Test Step**:
1. Inject test IOC (test-bad.example.com)
2. Wait for sync interval
3. Attempt to connect to test IOC
4. Verify block (if firewall feeds)
5. Verify alert (if SIEM feeds)
6. Document findings

**Expected Result**: False-positive IOCs cause downstream disruption.

**Pass Criteria**: Downstream block / alert documented.

**Remediation**: Source attestation; consumer-side filtering.

---

## Section I — Persistence

### TC-TI-032 — Backdoor user creation

**Objective**: Verify attacker can create backdoor user with admin role.

**Severity**: Critical

**Prerequisite**:
- Admin API key
- Target MISP / OpenCTI

**Test Step**:
1. Curl `/admin/users/add` to create backdoor user
2. Set role=admin
3. Verify login works
4. Document finding

**Expected Result**: Backdoor user created.

**Pass Criteria**: User can log in with admin privileges.

**Remediation**: MFA on user creation; peer review.

---

### TC-TI-033 — Sync server persistence

**Objective**: Verify attacker can persist via sync server.

**Severity**: Critical

**Prerequisite**:
- Admin API key
- Attacker-controlled MISP

**Test Step**:
1. Curl `/servers/add` to register attacker MISP
2. Configure pull=true
3. Wait 24 hours
4. Verify events flow from attacker to victim
5. Document finding

**Expected Result**: Sync server persists across reboots.

**Pass Criteria**: Events still flowing after 24 hours.

**Remediation**: Sync server review process; alerting on new sync servers.

---

### TC-TI-034 — Webhook persistence

**Objective**: Verify attacker can persist via webhook (data exfil).

**Severity**: High

**Prerequisite**:
- Admin API key
- Attacker-controlled webhook server

**Test Step**:
1. Curl `/serverSettings/setSetting` to set enrichment URL to attacker
2. Verify all enrichment queries flow to attacker
3. Document finding

**Expected Result**: Webhook configured + exfiltrating.

**Pass Criteria**: Attacker server receives enrichment queries.

**Remediation**: Allowlist enrichment URLs; monitor config changes.

---

### TC-TI-035 — Audit log review for attacker activity

**Objective**: Verify defender can detect attacker activity via audit logs.

**Severity**: Medium

**Prerequisite**:
- Admin API key
- Audit log access

**Test Step**:
1. Generate attacker activity (user creation, IOC injection)
2. Curl `/admin/logs/index` to review
3. Verify attacker actions visible
4. Document detection

**Expected Result**: All attacker actions visible in audit log.

**Pass Criteria**: Audit log complete + tamper-evident.

**Remediation**: External immutable audit log sink.

---

## Test Case Index

| ID | Title | Severity |
|----|-------|----------|
| TC-TI-001 | Platform identification | Medium |
| TC-TI-002 | Subdomain enumeration | Medium |
| TC-TI-003 | Exposed header enumeration | Low |
| TC-TI-004 | MISP version disclosure | High |
| TC-TI-005 | MISP API enumeration | High |
| TC-TI-006 | MISP CVE-2022-29527 XSS | High |
| TC-TI-007 | MISP false-positive IOC injection | Critical |
| TC-TI-008 | MISP sharing-group escalation | Critical |
| TC-TI-009 | MISP sync server abuse | Critical |
| TC-TI-010 | MISP audit log wipe | High |
| TC-TI-011 | OpenCTI introspection enabled | Medium |
| TC-TI-012 | OpenCTI GraphQL injection | High |
| TC-TI-013 | OpenCTI IDOR via iteration | High |
| TC-TI-014 | OpenCTI SSRF via import | Critical |
| TC-TI-015 | OpenCTI feed poisoning | Critical |
| TC-TI-016 | STIX bundle creation | Low |
| TC-TI-017 | TAXII feed discovery | Medium |
| TC-TI-018 | TAXII feed injection | Critical |
| TC-TI-019 | Anomali auth bypass | High |
| TC-TI-020 | ThreatQuotient auth bypass | Critical |
| TC-TI-021 | AutoFocus XSS | High |
| TC-TI-022 | Mandiant Advantage enumeration | Medium |
| TC-TI-023 | IBM X-Force enumeration | Medium |
| TC-TI-024 | Sharing-group enumeration | Medium |
| TC-TI-025 | TLP enforcement testing | High |
| TC-TI-026 | Cross-platform trust escalation | Medium |
| TC-TI-027 | Bulk IOC injection | Critical |
| TC-TI-028 | Slow IOC injection | High |
| TC-TI-029 | False malware family attribution | Critical |
| TC-TI-030 | Identify downstream consumers | High |
| TC-TI-031 | Test downstream impact | Critical |
| TC-TI-032 | Backdoor user creation | Critical |
| TC-TI-033 | Sync server persistence | Critical |
| TC-TI-034 | Webhook persistence | High |
| TC-TI-035 | Audit log review | Medium |
