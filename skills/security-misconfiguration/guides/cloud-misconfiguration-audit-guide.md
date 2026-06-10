# Cloud Misconfiguration Audit Guide

## Overview

Cloud misconfigurations are the leading cause of data breaches in cloud environments. This guide covers systematic auditing of AWS, GCP, and Azure for common security misconfigurations including overly permissive IAM policies, exposed storage, and insecure network configurations.

---

## AWS Misconfiguration Audit

### S3 Bucket Policy Analysis

```bash
# List all buckets
aws s3api list-buckets --query 'Buckets[].Name' --output text

# Check bucket ACL for public access
aws s3api get-bucket-acl --bucket $BUCKET
aws s3api get-bucket-policy --bucket $BUCKET

# Check Block Public Access settings
aws s3api get-public-access-block --bucket $BUCKET

# Find publicly accessible buckets
for bucket in $(aws s3api list-buckets --query 'Buckets[].Name' --output text); do
    acl=$(aws s3api get-bucket-acl --bucket $bucket 2>/dev/null)
    if echo "$acl" | grep -q "AllUsers\|AuthenticatedUsers"; then
        echo "PUBLIC: $bucket"
    fi
done
```

### IAM Policy Audit

```bash
# Find overly permissive policies (Action: "*", Resource: "*")
aws iam list-policies --scope Local --query 'Policies[].Arn' --output text | while read arn; do
    version=$(aws iam get-policy --policy-arn $arn --query 'Policy.DefaultVersionId' --output text)
    doc=$(aws iam get-policy-version --policy-arn $arn --version-id $version --query 'PolicyVersion.Document')
    if echo "$doc" | grep -q '"Action": "\*"'; then
        echo "OVERPRIVILEGED: $arn"
    fi
done

# Check for unused credentials
aws iam generate-credential-report
aws iam get-credential-report --query 'Content' --output text | base64 -d | \
    awk -F, '$5=="false" && $11=="false" {print "UNUSED:", $1}'

# Find users without MFA
aws iam list-users --query 'Users[].UserName' --output text | while read user; do
    mfa=$(aws iam list-mfa-devices --user-name $user --query 'MFADevices' --output text)
    if [ -z "$mfa" ]; then
        echo "NO MFA: $user"
    fi
done
```

### Security Group Analysis

```bash
# Find security groups with 0.0.0.0/0 ingress
aws ec2 describe-security-groups --query 'SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]].[GroupId,GroupName]' --output table

# Find groups allowing all ports
aws ec2 describe-security-groups --query 'SecurityGroups[?IpPermissions[?FromPort==`0` && ToPort==`65535`]].[GroupId,GroupName]' --output table

# Check for unrestricted SSH/RDP
aws ec2 describe-security-groups --filters "Name=ip-permission.from-port,Values=22" "Name=ip-permission.cidr,Values=0.0.0.0/0" --query 'SecurityGroups[].GroupId'
```

### EBS/RDS Encryption Check

```bash
# Unencrypted EBS volumes
aws ec2 describe-volumes --query 'Volumes[?!Encrypted].[VolumeId,State]' --output table

# Unencrypted RDS instances
aws rds describe-db-instances --query 'DBInstances[?!StorageEncrypted].[DBInstanceIdentifier,Engine]' --output table

# Public RDS instances
aws rds describe-db-instances --query 'DBInstances[?PubliclyAccessible==`true`].[DBInstanceIdentifier]' --output table
```

---

## GCP Misconfiguration Audit

### Storage Bucket Permissions

```bash
# List all buckets
gsutil ls

# Check bucket IAM
gsutil iam get gs://$BUCKET

# Find publicly accessible buckets
for bucket in $(gsutil ls); do
    iam=$(gsutil iam get $bucket 2>/dev/null)
    if echo "$iam" | grep -q "allUsers\|allAuthenticatedUsers"; then
        echo "PUBLIC: $bucket"
    fi
done
```

### Firewall Rules

```bash
# List all firewall rules
gcloud compute firewall-rules list --format="table(name,direction,sourceRanges,allowed)"

# Find rules allowing 0.0.0.0/0
gcloud compute firewall-rules list --filter="sourceRanges=0.0.0.0/0" --format="table(name,allowed)"
```

### Service Account Key Audit

```bash
# List service accounts
gcloud iam service-accounts list

# Check for user-managed keys (should be minimized)
for sa in $(gcloud iam service-accounts list --format="value(email)"); do
    keys=$(gcloud iam service-accounts keys list --iam-account=$sa --managed-by=user --format="value(name)")
    if [ -n "$keys" ]; then
        echo "USER KEYS: $sa"
        echo "$keys"
    fi
done
```

---

## Azure Misconfiguration Audit

### Storage Account Access

```bash
# List storage accounts
az storage account list --query '[].{Name:name,AllowBlobPublicAccess:allowBlobPublicAccess}' -o table

# Check for public blob containers
az storage container list --account-name $ACCOUNT --query '[?properties.publicAccess!=`null`].{Name:name,Access:properties.publicAccess}' -o table
```

### Network Security Groups

```bash
# Find NSGs with any/any rules
az network nsg list --query '[].{Name:name,RG:resourceGroup}' -o table
az network nsg rule list --nsg-name $NSG --resource-group $RG --query '[?sourceAddressPrefix==`*` && access==`Allow`].{Name:name,Port:destinationPortRange,Priority:priority}' -o table
```

### RBAC Over-Privilege

```bash
# Find Owner role assignments at subscription level
az role assignment list --role "Owner" --query '[].{Principal:principalName,Scope:scope}' -o table

# Find custom roles with wildcard actions
az role definition list --custom-role-only --query '[?contains(permissions[0].actions, `*`)].{Name:roleName,Actions:permissions[0].actions}' -o table
```

---

## Automated Scanning Tools

### ScoutSuite (Multi-Cloud)

```bash
# AWS
scout aws --profile default --report-dir ./scout-report

# GCP
scout gcp --user-account --report-dir ./scout-report

# Azure
scout azure --cli --report-dir ./scout-report
```

### Prowler (AWS)

```bash
prowler aws --severity critical high
prowler aws -c check11 check12 check13  # Specific checks
prowler aws --compliance cis_1.5_aws    # CIS benchmark
```

### CloudSploit

```bash
git clone https://github.com/aquasecurity/cloudsploit
cd cloudsploit
npm install
node index.js --config config.js --compliance cis
```

---

## Remediation Priorities

| Finding | Severity | Remediation |
|---------|----------|-------------|
| Public S3/GCS bucket | CRITICAL | Enable Block Public Access |
| IAM user without MFA | HIGH | Enforce MFA policy |
| Security group 0.0.0.0/0 on SSH | HIGH | Restrict to known IPs |
| Unencrypted storage | MEDIUM | Enable default encryption |
| Unused credentials >90 days | MEDIUM | Disable and rotate |
| Overly permissive IAM policy | HIGH | Apply least privilege |

---

## Testing Checklist

- [ ] Audit all storage buckets for public access
- [ ] Review IAM policies for wildcard permissions
- [ ] Check network rules for unrestricted ingress
- [ ] Verify encryption at rest for all data stores
- [ ] Audit service account keys and rotation
- [ ] Run automated scanner (ScoutSuite/Prowler)
- [ ] Verify MFA enforcement for all human users
- [ ] Check for publicly accessible databases

---

## Hands-on Exercises

1. **Exercise 1**: Deploy a misconfigured AWS environment using Terraform with 5 intentional security issues (public S3 bucket, overly permissive IAM, unrestricted security group, unencrypted EBS, CloudTrail disabled). Use the audit commands from this guide to identify all 5 issues
2. **Exercise 2**: Run ScoutSuite against a test AWS account. Review the HTML report, identify all CRITICAL and HIGH findings, and create a prioritized remediation plan with specific AWS CLI commands
3. **Exercise 3**: Build a cross-cloud audit script that runs the AWS, GCP, and Azure checks from this guide and outputs a unified JSON report with severity classifications
4. **Exercise 4**: Set up Prowler in a CI/CD pipeline (GitHub Actions or GitLab CI). Configure it to block deployments when critical findings are detected, and verify the pipeline catches misconfigured infrastructure

---

## Cost Optimization and Security Trade-offs

Cloud security misconfigurations often result from attempts to reduce costs or simplify access. Understanding these trade-offs helps security teams provide practical recommendations.

| Shortcut | Apparent Benefit | Hidden Risk | Proper Alternative |
|----------|-----------------|-------------|-------------------|
| `0.0.0.0/0` security group | Easy remote access | Global attack surface | VPN or bastion host |
| Wildcard IAM (`Action: *`) | No permission management | Over-privileged access | Scoped IAM policies per role |
| Public S3 bucket | Easy file sharing | Data breach risk | Pre-signed URLs or CloudFront |
| No encryption | Slightly lower latency | Compliance violation | AES-256 with minimal overhead |
| Shared credentials | No key management | Audit trail loss | IAM roles per service |
| Disabled logging | Reduced storage costs | No incident forensics | S3 lifecycle policies for logs |

---

## Automated Remediation Scripts

### AWS Auto-Remediation Examples

```bash
# Block all public access on an S3 bucket
aws s3api put-public-access-block --bucket $BUCKET \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# Enable encryption on an S3 bucket
aws s3api put-bucket-encryption --bucket $BUCKET \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "AES256"
      }
    }]
  }'

# Restrict security group to specific IP
aws ec2 authorize-security-group-ingress \
  --group-id $SG_ID --protocol tcp --port 22 \
  --cidr 10.0.0.0/8

# Remove the overly permissive rule
aws ec2 revoke-security-group-ingress \
  --group-id $SG_ID --protocol tcp --port 22 \
  --cidr 0.0.0.0/0
```

### Azure Auto-Remediation Examples

```bash
# Disable public access on a storage account
az storage account update --name $ACCOUNT --resource-group $RG \
  --allow-blob-public-access false

# Enable disk encryption on a VM
az vm encryption enable --name $VM --resource-group $RG \
  --disk-encryption-keyvault $KEYVAULT
```

### GCP Auto-Remediation Examples

```bash
# Remove public access from a storage bucket
gsutil iam ch -d allUsers gs://$BUCKET
gsutil iam ch -d allAuthenticatedUsers gs://$BUCKET

# Update firewall rule to restrict source
gcloud compute firewall-rules update $RULE_NAME \
  --source-ranges=10.0.0.0/8
```

---

## Terraform Security Scanning

Infrastructure-as-Code misconfigurations are the root cause of many cloud security issues. Scanning Terraform before deployment catches problems early.

```bash
# Install Checkov (Terraform security scanner)
pip install checkov

# Scan a Terraform directory
checkov -d /path/to/terraform/ --output cli

# Scan with SARIF output for CI/CD integration
checkov -d /path/to/terraform/ --output sarif --output-file results.sarif

# Scan specific checks
checkov -d /path/to/terraform/ --check CKV_AWS_20,CKV_AWS_57,CKV_AWS_78

# Install tfsec (alternative scanner)
brew install tfsec
tfsec /path/to/terraform/

# Install terrascan (another option)
brew install terrascan
terrascan scan -t aws -d /path/to/terraform/
```

**Common Terraform misconfigurations detected by scanners:**

| Check ID | Issue | Severity | Cloud Provider |
|----------|-------|----------|---------------|
| CKV_AWS_20 | S3 bucket has no versioning | Medium | AWS |
| CKV_AWS_57 | S3 bucket has no lifecycle policy | Low | AWS |
| CKV_AWS_78 | SSN not encrypted with KMS | High | AWS |
| CKV_AWS_79 | Instance metadata service uses IMDSv1 | High | AWS |
| CKV_AWS_130 | Security group allows unrestricted inbound | Critical | AWS |
| CKV_AZURE_1 | Storage account allows public access | Critical | Azure |
| CKV_AZURE_35 | Network security group allows all protocols | High | Azure |
| CKV_GCP_1 | GCP firewall allows all ports | Critical | GCP |

**Terraform hardening example (AWS S3):**

```hcl
# Insecure S3 bucket configuration
resource "aws_s3_bucket" "insecure" {
  bucket = "my-data-bucket"
  # Missing: versioning, encryption, public access block, logging
}

# Hardened S3 bucket configuration
resource "aws_s3_bucket" "secure" {
  bucket = "my-data-bucket"
}

resource "aws_s3_bucket_versioning" "secure" {
  bucket = aws_s3_bucket.secure.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "secure" {
  bucket = aws_s3_bucket.secure.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "secure" {
  bucket                  = aws_s3_bucket.secure.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_logging" "secure" {
  bucket        = aws_s3_bucket.secure.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "log/"
}
```

**CI/CD integration for Terraform scanning:**

```yaml
# GitLab CI example
terraform_security_scan:
  stage: test
  image: bridgecrew/checkov
  script:
    - checkov -d terraform/ --output cli --output junitxml --output-file results.xml
    - checkov -d terraform/ --compact --quiet || true
  artifacts:
    reports:
      junit: results.xml
  rules:
    - changes:
        - terraform/**/*
```

---

## Cloud Security Posture Management (CSPM)

Infrastructure-as-Code misconfigurations are the root cause of many cloud security issues. Scanning Terraform before deployment catches problems early.

```bash
# Install Checkov (Terraform security scanner)
pip install checkov

# Scan a Terraform directory
checkov -d /path/to/terraform/ --output cli

# Scan with SARIF output for CI/CD integration
checkov -d /path/to/terraform/ --output sarif --output-file results.sarif

# Scan specific checks
checkov -d /path/to/terraform/ --check CKV_AWS_20,CKV_AWS_57,CKV_AWS_78

# Install tfsec (alternative scanner)
brew install tfsec
tfsec /path/to/terraform/

# Install terrascan (another option)
brew install terrascan
terrascan scan -t aws -d /path/to/terraform/
```

**Common Terraform misconfigurations detected by scanners:**

| Check ID | Issue | Severity | Cloud Provider |
|----------|-------|----------|---------------|
| CKV_AWS_20 | S3 bucket has no versioning | Medium | AWS |
| CKV_AWS_57 | S3 bucket has no lifecycle policy | Low | AWS |
| CKV_AWS_78 | SSN not encrypted with KMS | High | AWS |
| CKV_AWS_79 | Instance metadata service uses IMDSv1 | High | AWS |
| CKV_AWS_130 | Security group allows unrestricted inbound | Critical | AWS |
| CKV_AZURE_1 | Storage account allows public access | Critical | Azure |
| CKV_AZURE_35 | Network security group allows all protocols | High | Azure |
| CKV_GCP_1 | GCP firewall allows all ports | Critical | GCP |

**Terraform hardening example (AWS S3):**

```hcl
# Insecure S3 bucket configuration
resource "aws_s3_bucket" "insecure" {
  bucket = "my-data-bucket"
  # Missing: versioning, encryption, public access block, logging
}

# Hardened S3 bucket configuration
resource "aws_s3_bucket" "secure" {
  bucket = "my-data-bucket"
}

resource "aws_s3_bucket_versioning" "secure" {
  bucket = aws_s3_bucket.secure.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "secure" {
  bucket = aws_s3_bucket.secure.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "secure" {
  bucket                  = aws_s3_bucket.secure.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_logging" "secure" {
  bucket        = aws_s3_bucket.secure.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "log/"
}
```

---

## Cloud Security Posture Management (CSPM)

CSPM tools provide continuous monitoring and automated remediation for cloud misconfigurations:

| Tool | Type | Cloud Providers | Key Features |
|------|------|----------------|-------------|
| AWS Security Hub | Native | AWS | Security standards, automated checks, integration with GuardDuty |
| Azure Security Center | Native | Azure | Secure score, regulatory compliance, JIT VM access |
| GCP Security Command Center | Native | GCP | Asset inventory, threat detection, security health |
| Prisma Cloud | Third-party | Multi-cloud | Runtime protection, compliance, identity security |
| Wiz | Third-party | Multi-cloud | Attack path analysis, agentless scanning |
| Orca Security | Third-party | Multi-cloud | SideScanning, compliance, risk prioritization |
| Lacework | Third-party | Multi-cloud | Polygraph behavioral analysis, compliance |

**Setting up AWS Security Hub:**

```bash
# Enable Security Hub
aws securityhub enable-security-hub \
  --enable-default-standards \
  --tags '{"Environment":"Production"}'

# Enable CIS AWS Foundations Benchmark
aws securityhub batch-enable-standards \
  --standards-subscription-requests '[{
    "StandardsArn": "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.5.0"
  }]'

# List current findings by severity
aws securityhub get-findings \
  --query 'Findings[?Severity.Label==`CRITICAL`].[Title,ResourceId,AwsAccountId]' \
  --output table
```
