# Cloud Misconfiguration Checklist Guide

## Introduction

Cloud misconfigurations are the leading cause of data breaches in cloud environments. This guide provides a systematic checklist for identifying and remediating common misconfigurations across AWS, Azure, and GCP.

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

### 4. Cross-Cloud Checklist

| Category | Check | Risk Level |
|----------|-------|------------|
| Storage | Public access disabled on all buckets/containers | Critical |
| Identity | MFA enforced for all human users | Critical |
| Network | No 0.0.0.0/0 ingress on SSH/RDP/SQL ports | Critical |
| Encryption | Encryption at rest enabled for all storage | High |
| Logging | Audit logging enabled in all regions | High |
| Keys | No hardcoded secrets in code or configs | Critical |
| IAM | Least privilege — no wildcard permissions | High |
| Network | Network segmentation between environments | Medium |

### 5. Automated Scanning Tools

```bash
# ScoutSuite — multi-cloud audit
pip install scoutsuite
scout aws -p aws-profile
scout gcp -p gcp-project

# Prowler — AWS specific
pip install prowler
prowler aws -p aws-profile

# CloudSploit — multi-cloud
npm install -g cloudsploit
cloudsploit --config cloudsploit.yml
```

## References

- [CIS Cloud Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [AWS Security Best Practices](https://docs.aws.amazon.com/security/)
- [Azure Security Benchmark](https://learn.microsoft.com/en-us/security/benchmark/azure/)
- [GCP Security Command Center](https://cloud.google.com/security-command-center)
- [OWASP Cloud Security](https://owasp.org/www-project-cloud-security/)
