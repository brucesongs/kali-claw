# Cloud Misconfiguration Checklist Guide

## Introduction

Cloud misconfigurations are the leading cause of data breaches in cloud environments. This guide provides a systematic checklist for identifying and remediating common misconfigurations across AWS, Azure, and GCP. Cloud environments introduce unique risks because resources can be created instantly, often without security review, and misconfigurations can expose data globally within seconds.

This guide is organized by cloud provider with a cross-cloud checklist that applies regardless of platform. Each check includes the specific command to run, the expected secure state, and the risk if the check fails.

## Practical Steps

### 1. AWS Misconfiguration Checks

```bash
# S3 bucket public access
aws s3api get-public-access-block --bucket target-bucket 2>/dev/null || echo "No public access block configured"

# Check for public buckets
aws s3 ls | awk '{print $3}' | while read bucket; do
  acl=$(aws s3api get-bucket-acl --bucket "$bucket" --query 'Grants[?Grantee.URI==`http://acs.amazonaws.com/groups/global/AllUsers`]' --output text)
  [ -n "$acl" ] && echo "PUBLIC: $bucket"
done

# IAM users without MFA
aws iam list-users --query 'Users[?PasswordLastUsed!=`null`].UserName' --output text | \
  tr '\t' '\n' | while read user; do
    mfa=$(aws iam list-mfa-devices --user-name "$user" --query 'MFADevices' --output text)
    [ -z "$mfa" ] && echo "NO MFA: $user"
  done

# Security groups allowing 0.0.0.0/0 on sensitive ports
aws ec2 describe-security-groups --query 'SecurityGroups[?contains(IpPermissions[].IpRanges[].CidrIp, `0.0.0.0/0`)]' \
  --output table
```

**Additional AWS checks:**

```bash
# CloudTrail logging enabled (audit trail requirement)
aws cloudtrail describe-trails --query 'trailList[].{Name:Name,IsMultiRegion:IsMultiRegion,LogFileValidation:LogFileValidationEnabled}'

# Root account MFA enabled
aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled'

# EBS encryption enabled by default
aws ec2 get-ebs-encryption-by-default

# RDS public accessibility check
aws rds describe-db-instances --query 'DBInstances[?PubliclyAccessible==`true`].[DBInstanceIdentifier,Engine,Endpoint.Address]' --output table

# Lambda function public access check
aws lambda get-policy --function-name my-function 2>/dev/null | \
  jq -r '.Policy | fromjson | .Statement[] | select(.Principal=="*" or .Principal.AWS=="*") | .Sid'

# SSM Parameter Store secrets (should use Secrets Manager instead)
aws ssm describe-parameters --filters Key=Type,Value=SecureString --query 'Parameters[].Name'
```

### 2. Azure Misconfiguration Checks

```bash
# Check for public storage accounts
az storage account list --query "[?allowBlobPublicAccess==null || allowBlobPublicAccess==true].name" -o tsv

# Network security groups with overly permissive rules
az network nsg list --query "[].{Name:name, Rules:nsgRules}" -o json | \
  jq '.[] | select(.Rules | any(.properties.destinationPortRange == "*" and .properties.access == "Allow")) | .Name'

# Check for VMs without disk encryption
az vm list --query "[?storageProfile.osDisk.managedDisk.diskEncryptionSet==null].name" -o tsv
```

**Additional Azure checks:**

```bash
# Azure AD: Users without MFA
az ad user list --query "[].{Name:displayName,UPN:userPrincipalName}" -o table | \
  while read upn; do
    mfa=$(az ad user show --id "$upn" --query 'strongAuthenticationDetails' 2>/dev/null)
    [ -z "$mfa" ] && echo "NO MFA: $upn"
  done

# Key Vault soft delete enabled
az keyvault list --query "[?properties.enableSoftDelete==false].name" -o tsv

# App Service HTTPS-only enforcement
az webapp list --query "[?httpsOnly==false].{Name:name, RG:resourceGroup}" -o table

# Container registry admin user enabled (should be disabled)
az acr list --query "[?adminUserEnabled==true].name" -o tsv

# Network security groups allowing inbound from internet on high-risk ports
az network nsg rule list --resource-group $RG --nsg-name $NSG \
  --query "[?sourceAddressPrefix=='*' && access=='Allow' && (destinationPortRange=='22' || destinationPortRange=='3389' || destinationPortRange=='1433')].{Name:name,Port:destinationPortRange,Priority:priority}" -o table
```

### 3. GCP Misconfiguration Checks

```bash
# Public Cloud Storage buckets
gsutil ls | while read bucket; do
  iam=$(gsutil iam get "$bucket" 2>/dev/null)
  echo "$iam" | grep -q "allUsers" && echo "PUBLIC: $bucket"
done

# Firewall rules allowing 0.0.0.0/0
gcloud compute firewall-rules list --format="table(name,sourceRanges.list(),allowed[].map().firewall_rule().list())" \
  --filter="sourceRanges:0.0.0.0/0"

# Service accounts with owner role
gcloud projects get-iam-policy $PROJECT_ID --format=json | \
  jq '.bindings[] | select(.role=="roles/owner") | .members[]'
```

**Additional GCP checks:**

```bash
# Cloud SQL instances with public IP
gcloud sql instances list --format="table(name,ipAddresses,status)"

# Compute instances with serial port logging enabled
gcloud compute instances list --format="table(name,status)" | \
  while read name _; do
    gcloud compute instances describe "$name" --format="value(metadata.items.serial-port-logging-enable)" 2>/dev/null
  done

# Cloud Storage buckets without versioning
gsutil versioning get gs://bucket-name 2>/dev/null

# Service account keys older than 90 days
for sa in $(gcloud iam service-accounts list --format="value(email)"); do
  gcloud iam service-accounts keys list --iam-account="$sa" --managed-by=user --format="table(name,validAfterTime)" 2>/dev/null
done

# DNS zone changes without logging
gcloud dns policies list --format="table(name,enableLogging)"
```

### 4. Cross-Cloud Checklist

| Category | Check | Risk Level |
|----------|-------|------------|
| Storage | Public access disabled on all buckets/containers | Critical |
| Identity | MFA enforced for all human users | Critical |
| Network | No 0.0.0.0/0 ingress on SSH/RDP/SQL ports | Critical |
| Encryption | Encryption at rest enabled for all storage | High |
| Logging | Audit logging enabled in all regions | High |
| Keys | No hardcoded secrets in code or configs | Critical |
| IAM | Least privilege -- no wildcard permissions | High |
| Network | Network segmentation between environments | Medium |
| Backup | Automated backups configured and tested | High |
| Compliance | CIS benchmark compliance verified quarterly | Medium |
| Inventory | All resources tagged with owner and environment | Medium |
| Rotation | Service account keys rotated every 90 days | High |

### 5. Automated Scanning Tools

```bash
# ScoutSuite -- multi-cloud audit
pip install scoutsuite
scout aws -p aws-profile
scout gcp -p gcp-project

# Prowler -- AWS specific
pip install prowler
prowler aws -p aws-profile

# CloudSploit -- multi-cloud
npm install -g cloudsploit
cloudsploit --config cloudsploit.yml
```

**Integration with CI/CD pipelines:**

```yaml
# GitHub Actions example: cloud security scan
name: Cloud Security Scan
on:
  schedule:
    - cron: '0 6 * * 1'  # Weekly Monday 6am
  workflow_dispatch:

jobs:
  aws-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Prowler
        run: |
          pip install prowler
          prowler aws -p default -M json -o prowler-report.json
      - name: Check for critical findings
        run: |
          critical=$(jq '[.[] | select(.severity=="critical")] | length' prowler-report.json)
          if [ "$critical" -gt 0 ]; then
            echo "CRITICAL: $critical critical findings detected"
            exit 1
          fi
```

## Hands-on Exercises

1. **Exercise 1**: Run the complete AWS misconfiguration checklist against a test AWS account. Document each finding with the specific resource ARN, the current insecure configuration, and the recommended remediation command
2. **Exercise 2**: Set up ScoutSuite for a multi-cloud environment (AWS + GCP). Compare findings across both platforms and identify common patterns of misconfiguration
3. **Exercise 3**: Create an automated CI/CD pipeline that runs Prowler on every infrastructure change and blocks deployment if critical misconfigurations are detected
4. **Exercise 4**: Perform a baseline comparison by running all checks twice -- before and after applying CIS Benchmark hardening. Document the improvement in the security score

## IAM Policy Analysis Deep Dive

Overly permissive IAM policies are the most common and most dangerous cloud misconfiguration. This section provides a systematic approach to analyzing IAM policies across all three cloud providers.

### AWS IAM Policy Audit

```bash
# List all customer-managed policies
aws iam list-policies --scope Local --query 'Policies[].Arn' --output text

# For each policy, check for wildcard actions or resources
for arn in $(aws iam list-policies --scope Local --query 'Policies[].Arn' --output text); do
  version=$(aws iam get-policy --policy-arn "$arn" --query 'Policy.DefaultVersionId' --output text)
  doc=$(aws iam get-policy-version --policy-arn "$arn" --version-id "$version" --query 'PolicyVersion.Document.Statement' --output json)

  # Check for admin-level permissions
  if echo "$doc" | jq -r '.[].Action' | grep -q "\*"; then
    echo "WILDCARD ACTION: $arn"
  fi

  # Check for resource wildcard
  if echo "$doc" | jq -r '.[].Resource' | grep -q "\*"; then
    echo "WILDCARD RESOURCE: $arn"
  fi
done

# Find inline policies attached to users (often overlooked)
for user in $(aws iam list-users --query 'Users[].UserName' --output text); do
  policies=$(aws iam list-user-policies --user-name "$user" --query 'PolicyNames' --output text)
  if [ -n "$policies" ]; then
    echo "INLINE POLICIES for $user: $policies"
  fi
done
```

**Least-privilege IAM policy template:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject"
      ],
      "Resource": "arn:aws:s3:::specific-bucket/*",
      "Condition": {
        "IpAddress": {
          "aws:SourceIp": ["10.0.0.0/8"]
        }
      }
    }
  ]
}
```

### Azure RBAC Over-Privilege Detection

Overly permissive IAM policies are the most common and most dangerous cloud misconfiguration. This section provides a systematic approach to analyzing IAM policies across all three cloud providers.

### AWS IAM Policy Audit

```bash
# List all customer-managed policies
aws iam list-policies --scope Local --query 'Policies[].Arn' --output text

# For each policy, check for wildcard actions or resources
for arn in $(aws iam list-policies --scope Local --query 'Policies[].Arn' --output text); do
  version=$(aws iam get-policy --policy-arn "$arn" --query 'Policy.DefaultVersionId' --output text)
  doc=$(aws iam get-policy-version --policy-arn "$arn" --version-id "$version" --query 'PolicyVersion.Document.Statement' --output json)

  # Check for admin-level permissions
  if echo "$doc" | jq -r '.[].Action' | grep -q "\*"; then
    echo "WILDCARD ACTION: $arn"
  fi

  # Check for resource wildcard
  if echo "$doc" | jq -r '.[].Resource' | grep -q "\*"; then
    echo "WILDCARD RESOURCE: $arn"
  fi
done

# Find inline policies attached to users (often overlooked)
for user in $(aws iam list-users --query 'Users[].UserName' --output text); do
  policies=$(aws iam list-user-policies --user-name "$user" --query 'PolicyNames' --output text)
  if [ -n "$policies" ]; then
    echo "INLINE POLICIES for $user: $policies"
  fi
done
```

### Azure RBAC Over-Privilege Detection

```bash
# Find all role assignments at subscription level
az role assignment list --all --query '[].{Principal:principalName, Role:roleDefinitionName, Scope:scope}' -o table

# Identify high-risk role assignments
for role in "Owner" "Contributor" "User Access Administrator" "Key Vault Administrator"; do
  count=$(az role assignment list --role "$role" --query 'length([])' -o tsv)
  echo "$role assignments: $count"
done

# Find custom roles with excessive permissions
az role definition list --custom-role-only --query '[].{Name:roleName, Actions:permissions[0].actions, DataActions:permissions[0].dataActions}' -o json | \
  jq '.[] | select(.Actions[]? == "*" or .DataActions[]? == "*") | .Name'
```

### GCP IAM Policy Analysis

```bash
# Get organization-level IAM policy
gcloud organizations get-iam-policy $ORG_ID --format=json | \
  jq '.bindings[] | select(.role == "roles/owner" or .role == "roles/editor") | {role: .role, members: .members}'

# Find service accounts with excessive roles
for project in $(gcloud projects list --format="value(projectId)"); do
  gcloud projects get-iam-policy "$project" --format=json | \
    jq '.bindings[] | select(.role == "roles/owner" or .role == "roles/editor" or .role == "roles/iam.securityAdmin") | {project: "'$project'", role: .role, members: .members}'
done

# Check for service account key age (keys older than 90 days are a risk)
for sa in $(gcloud iam service-accounts list --format="value(email)" --project=$PROJECT_ID); do
  old_keys=$(gcloud iam service-accounts keys list --iam-account="$sa" --managed-by=user --format="value(validAfterTime)" --project=$PROJECT_ID 2>/dev/null | \
    while read date; do
      key_age=$(( ($(date +%s) - $(date -d "$date" +%s)) / 86400 ))
      if [ "$key_age" -gt 90 ]; then
        echo "OLD KEY: $sa (created $date, $key_age days old)"
      fi
    done)
  [ -n "$old_keys" ] && echo "$old_keys"
done
```

## Cloud Security Monitoring and Alerting

Proactive monitoring catches misconfigurations before they become breaches:

```bash
# AWS CloudWatch alarm for security group changes
aws cloudwatch put-metric-alarm \
  --alarm-name "security-group-change" \
  --alarm-description "Alert on security group modifications" \
  --metric-name "SecurityGroupEventCount" \
  --namespace "AWS/CloudTrail" \
  --statistic Sum \
  --period 300 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --evaluation-periods 1

# AWS Config rule for detecting public S3 buckets
aws configservice put-config-rule \
  --config-rule '{
    "ConfigRuleName": "s3-bucket-public-access-block",
    "Description": "Check that S3 buckets have public access blocks",
    "Source": {
      "Owner": "AWS",
      "SourceIdentifier": "S3_BUCKET_PUBLIC_ACCESS_BLOCK"
    },
    "Scope": {
      "ComplianceResourceTypes": ["AWS::S3::Bucket"]
    }
  }'
```

## References

- [CIS Cloud Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [AWS Security Best Practices](https://docs.aws.amazon.com/security/)
- [Azure Security Benchmark](https://learn.microsoft.com/en-us/security/benchmark/azure/)
- [GCP Security Command Center](https://cloud.google.com/security-command-center)
- [OWASP Cloud Security](https://owasp.org/www-project-cloud-security/)
- [Prowler Documentation](https://docs.prowler.com/)
- [ScoutSuite GitHub](https://github.com/nccgroup/ScoutSuite)
