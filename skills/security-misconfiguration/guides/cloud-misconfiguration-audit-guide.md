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
