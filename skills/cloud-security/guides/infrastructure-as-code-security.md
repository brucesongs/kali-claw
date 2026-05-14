# Infrastructure as Code Security Guide

## Learning Objectives

Master the security assessment of Infrastructure as Code (IaC) templates across Terraform, CloudFormation, and Helm. Understand CI/CD pipeline security, supply chain attack vectors, and GitOps security considerations.

---

## 1. Terraform Security

### 1.1 Common Misconfigurations

**Public S3 Buckets**:
```hcl
# INSECURE: Public read access
resource "aws_s3_bucket" "data" {
  bucket = "company-data"
  acl    = "public-read"  # DANGEROUS
}

# INSECURE: Public policy
resource "aws_s3_bucket_policy" "allow_public" {
  policy = jsonencode({
    Statement = [{
      Effect    = "Allow"
      Principal = "*"  # DANGEROUS: allows any AWS account
      Action    = "s3:GetObject"
      Resource  = "arn:aws:s3:::company-data/*"
    }]
  })
}

# SECURE: Private bucket with specific IAM access
resource "aws_s3_bucket" "data" {
  bucket = "company-data"
}

resource "aws_s3_bucket_ownership_controls" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

**Open Security Groups**:
```hcl
# INSECURE: Open to the world
resource "aws_security_group" "web" {
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # DANGEROUS: open to entire internet
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]  # DANGEROUS: unrestricted egress
  }
}

# SECURE: Restricted access
resource "aws_security_group" "web" {
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]  # Internal network only
  }
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # HTTPS only
  }
}
```

**Hardcoded Secrets**:
```hcl
# INSECURE: Hardcoded credentials
resource "aws_db_instance" "database" {
  username = "admin"
  password = "MyP@ssw0rd123"  # DANGEROUS: hardcoded in source
}

# SECURE: Reference from secrets manager
resource "aws_db_instance" "database" {
  username = "admin"
  password = aws_secretsmanager_secret_version.db_password.secret_string
}
```

### 1.2 tfsec / checkov / terrascan Usage

```bash
# tfsec: Terraform security scanner
# Install
brew install tfsec

# Scan current directory
tfsec .

# Scan with specific severity thresholds
tfsec . --minimum-severity HIGH

# Output in JSON format for integration
tfsec . --format json --out tfsec-report.json

# Output in SARIF format for GitHub integration
tfsec . --format sarif --out tfsec-report.sarif

# Exclude specific checks
tfsec . --exclude-downloaded-modules

# Scan specific module path
tfsec ./modules/networking/

# checkov: Comprehensive IaC scanner
# Install
pip install checkov

# Scan Terraform files
checkov -d .

# Scan single file
checkov -f main.tf

# Output in JSON
checkov -d . --output json --output-file-path checkov-report.json

# Skip specific checks
checkov -d . --skip-check CKV_AWS_18,CKV_AWS_19

# Scan with framework filter
checkov -d . --framework terraform

# terrascan: IaC security scanner
# Install
brew install terrascan

# Scan Terraform
terrascan scan -t terraform

# Scan with specific policy types
terrascan scan -t terraform --policy-type aws

# Output in JSON
terrascan scan -t terraform -o json > terrascan-report.json

# Scan with severity filter
terrascan scan -t terraform --severity HIGH,CRITICAL
```

### 1.3 State File Security

```bash
# Check state file location (local vs remote)
cat .terraform/terraform.tfstate 2>/dev/null | head -20

# Check for remote backend configuration
grep -rn "backend" *.tf
grep -rn "backend" modules/**/*.tf

# Assess S3 backend security
# INSECURE: No encryption, no versioning, no locking
terraform {
  backend "s3" {
    bucket = "terraform-state"
    key    = "terraform.tfstate"
    region = "us-east-1"
  }
}

# SECURE: Encrypted, versioned, locked
terraform {
  backend "s3" {
    bucket         = "terraform-state-encrypted"
    key            = "terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "terraform-locks"
    kms_key_id     = "arn:aws:kms:us-east-1:123456789012:key/xxx"
  }
}

# Check state file for secrets
terraform state pull | jq '.outputs | with_entries(select(.value.value | type == "string" and test("password|secret|key|token"; "i")))'

# Check state file permissions
ls -la terraform.tfstate
# Should be: readable only by owner (chmod 600)
```

### 1.4 Provider Credential Exposure

```bash
# Check for hardcoded credentials in provider blocks
grep -rn 'provider "' *.tf modules/**/*.tf | head -20
grep -rn 'access_key\s*=' *.tf
grep -rn 'secret_key\s*=' *.tf
grep -rn 'token\s*=' *.tf

# INSECURE: Hardcoded credentials
provider "aws" {
  access_key = "AKIAIOSFODNN7EXAMPLE"  # DANGEROUS
  secret_key = "wJalrXUtnFEMI/K7MDENG"  # DANGEROUS
}

# SECURE: Use environment variables or IAM roles
provider "aws" {
  region = var.aws_region
  # Credentials from env: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
  # Or from IAM instance profile / assumed role
}

# Check for credential files in repository
find . -name ".aws" -o -name "credentials" -o -name "*.pem" -o -name "*.key"
grep -rn "AKIA" . --include="*.tf" --include="*.tfvars"
```

### 1.5 Module Security Assessment

```bash
# Check module sources (local vs remote)
grep -rn 'source\s*=' *.tf modules/**/*.tf

# INSECURE: Unpinned module version
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 0"  # DANGEROUS: any version
}

# SECURE: Pinned version with hash
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.1.0"  # Specific version
}

# Verify module integrity
terraform init -upgrade
terraform providers lock -platform=linux_amd64

# Scan module dependencies
terraform module list
```

---

## 2. CloudFormation Security

### 2.1 Stack Template Vulnerabilities

```bash
# Install cfn-nag
gem install cfn-nag

# Scan CloudFormation template
cfn_nag_scan --input-path template.yaml

# Scan with JSON output
cfn_nag_scan --input-path template.yaml --output-format json

# Scan multiple templates
find . -name "*.yaml" -o -name "*.json" | xargs cfn_nag_scan

# Common findings:
# - IAM role with wildcard actions
# - Security group with 0.0.0.0/0 ingress
# - S3 bucket without encryption
# - RDS without encryption
# - Lambda with wildcard permissions
```

**Common CloudFormation Misconfigurations**:
```yaml
# INSECURE: Overprivileged IAM role
Resources:
  LambdaRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/AdministratorAccess  # DANGEROUS

# INSECURE: Public S3 bucket
Resources:
  S3Bucket:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: PublicReadWrite  # DANGEROUS

# INSECURE: Unencrypted RDS
Resources:
  Database:
    Type: AWS::RDS::DBInstance
    Properties:
      Engine: mysql
      # StorageEncrypted: true  # MISSING: no encryption
      MasterUsername: admin
      MasterUserPassword: MyPassword123  # DANGEROUS: hardcoded
```

### 2.2 IAM Policy Escalation Through CFN

```bash
# Check for privilege escalation via CloudFormation
# An attacker with cloudformation:CreateStack can create resources
# with the permissions of the CloudFormation service role

# Find CloudFormation service roles
aws cloudformation describe-account-limits
aws cloudformation list-types --type RESOURCE

# Check stack sets for cross-account access
aws cloudformation list-stack-sets
aws cloudformation describe-stack-set --stack-set-name <name>

# Find stacks with admin-level service roles
aws cloudformation describe-stacks --output json | jq '.Stacks[] | {name: .StackName, role: .RoleARN}'

# Test: Can current identity create stacks?
aws cloudformation create-stack --stack-name test-escalation \
  --template-body file://malicious-template.yaml \
  --capabilities CAPABILITY_IAM \
  --role-arn arn:aws:iam::123456789012:role/admin-role
```

### 2.3 StackSets Security Considerations

```bash
# List StackSets and their deployment targets
aws cloudformation list-stack-sets --status ACTIVE
aws cloudformation list-stack-instances --stack-set-name <name>

# Check for cross-account deployment
aws cloudformation describe-stack-set --stack-set-name <name> --output json | jq '{name: .StackSet.StackSetName, accounts: .StackSet.AdministrationRoleARN, executionRole: .StackSet.ExecutionRoleName}'

# Check auto-deployment settings (can deploy to new accounts automatically)
aws cloudformation describe-stack-set --stack-set-name <name> --output json | jq '.StackSet.AutoDeployment'
```

---

## 3. Helm Chart Security

### 3.1 Chart Vulnerability Scanning

```bash
# Install trivy for Helm scanning
# Scan a Helm chart for vulnerabilities
trivy config ./chart/

# Scan a specific chart from a repository
helm pull bitnami/nginx --version 15.0.0 --untar --untardir /tmp/chart-scan
trivy config /tmp/chart-scan/nginx/

# Check for known CVEs in chart dependencies
helm dependency list ./chart/
trivy fs ./chart/charts/

# Verify chart signature (if signed)
helm verify chart-1.0.0.tgz
helm provenance chart-1.0.0.tgz
```

### 3.2 values.yaml Secret Exposure

```bash
# Check for secrets in values.yaml
grep -rn "password\|secret\|token\|key\|credential" chart/values.yaml

# INSECURE: Plaintext secrets in values.yaml
# values.yaml:
database:
  host: mysql
  password: "MyS3cretP@ss"  # DANGEROUS: plaintext in chart

# SECURE: Reference external secrets
# values.yaml:
database:
  host: mysql
  existingSecret: "db-credentials"  # Reference to Kubernetes Secret

# Check for secrets in templates
grep -rn "b64enc\|b64dec" chart/templates/
grep -rn "kind: Secret" chart/templates/

# Audit template rendering for leaked secrets
helm template release ./chart/ --debug 2>&1 | grep -i "password\|secret\|token"
```

### 3.3 RBAC Templates in Charts

```bash
# Check for overly permissive RBAC in chart templates
grep -rn "ClusterRole\|ClusterRoleBinding" chart/templates/

# INSECURE: Cluster-wide admin access from a chart
# templates/rbac.yaml:
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: {{ include "chart.fullname" . }}
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]          # DANGEROUS: full cluster admin

# SECURE: Scoped to namespace and specific resources
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {{ include "chart.fullname" . }}
  namespace: {{ .Release.Namespace }}
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get", "list"]
  resourceNames: ["{{ include "chart.fullname" . }}"]

# Check if chart creates service accounts
grep -rn "ServiceAccount" chart/templates/
grep -rn "automountServiceAccountToken" chart/templates/
```

### 3.4 Chart Testing Framework

```bash
# Install chart-testing tool
brew install chart-testing

# Lint the chart
ct lint --chart-dirs ./chart/

# Lint with specific config
ct lint --config ct.yaml --chart-dirs ./charts/

# Run chart tests
ct install --chart-dirs ./chart/

# Validate rendered templates against policies
helm template release ./chart/ | conftest test -
```

---

## 4. CI/CD Pipeline Security

### 4.1 GitHub Actions Workflow Security

```bash
# Check for pull_request_target misuse
# INSECURE: Using pull_request_target with checkout of PR head
# .github/workflows/build.yml:
on:
  pull_request_target:  # Runs in base repo context (has secrets)
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # DANGEROUS: checks out untrusted code

# SECURE: Use pull_request for untrusted code
on:
  pull_request:  # Runs in fork context (no secrets)
jobs:
  build:
    steps:
      - uses: actions/checkout@v4

# Check for secrets exposure in workflow logs
grep -rn "::set-output\|::set-env\|GITHUB_ENV\|GITHUB_OUTPUT" .github/workflows/

# Check for untrusted input usage
grep -rn "github.event.pull_request" .github/workflows/ | grep -v "number\|title\|url"

# Scan workflow files for security issues
# Use actionlint
brew install actionlint
actionlint .github/workflows/*.yaml

# Use zizmor for workflow security
pip install zizmor
zizmor .github/workflows/
```

### 4.2 GitLab CI Security

```bash
# Check for unprotected CI variables
# INSECURE: Variables defined without protection
# .gitlab-ci.yml:
variables:
  AWS_ACCESS_KEY_ID: "AKIAIOSFODNN7EXAMPLE"  # DANGEROUS: in source
  AWS_SECRET_ACCESS_KEY: "wJalrXUtnFEMI"     # DANGEROUS: in source

# SECURE: Use protected and masked variables
# Define in GitLab UI: Settings > CI/CD > Variables
# - Check "Protect variable" (only available in protected branches)
# - Check "Mask variable" (hidden in logs)
# - Check "Expand variable reference" as needed

# Check for runner isolation issues
# INSECURE: Shared runner without isolation
# runners.docker:
#   image: ruby:2.7
#   # No volumes, no security_opt

# SECURE: Isolated runner configuration
# runners.docker:
#   image: ruby:2.7
#   security_opt: ["no-new-privileges:true"]
#   read_only: true
#   volumes: ["/cache"]
#   network_mode: "none"

# Check for Docker-in-Docker abuse
grep -rn "docker:dind\|docker:stable-dind" .gitlab-ci.yml
```

### 4.3 Jenkins Pipeline Security

```bash
# Check for script approval issues
# INSECURE: Script with unsafe methods
// Jenkinsfile:
@NonCPS
def getCredentials() {
  return sh(script: 'cat /etc/passwd', returnStdout: true)  // DANGEROUS
}

# Check for credential binding exposure
# INSECURE: Credentials in plain environment
withCredentials([usernamePassword(credentialsId: 'db-creds', usernameVariable: 'DB_USER', passwordVariable: 'DB_PASS')]) {
  sh "echo $DB_PASS"  // DANGEROUS: exposed in Jenkins log
}

# SECURE: Use withCredentials with masking
withCredentials([usernamePassword(credentialsId: 'db-creds', usernameVariable: 'DB_USER', passwordVariable: 'DB_PASS')]) {
  sh '''#!/bin/bash
    set +x  # Disable command echoing
    mysql -u "$DB_USER" -p"$DB_PASS" -e "SELECT 1"
  '''
}

# Check for shared agent security
# Agents should run with restricted permissions:
# - No host Docker socket mounting
# - No privileged containers
# - Network isolation between builds
```

### 4.4 Supply Chain Attack Vectors in CI/CD

```bash
# Check for unpinned action versions
# INSECURE: Using latest tag
- uses: actions/checkout@main  # DANGEROUS: can change

# SECURE: Pin to specific SHA
- uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1

# Check for third-party action sources
grep -rn "uses:" .github/workflows/ | grep -v "actions/" | grep -v "./"

# Verify action source repositories
for action in $(grep -h "uses:" .github/workflows/*.yaml | awk '{print $2}' | sort -u); do
  repo=$(echo "$action" | cut -d'@' -f1)
  echo "Checking: $repo"
done

# Check for dependency confusion in build systems
# Review package manager configurations
cat package.json 2>/dev/null | jq '.dependencies'
cat requirements.txt 2>/dev/null
cat go.sum 2>/dev/null | head -20

# Verify package integrity
npm audit
pip audit
go vet ./...
```

---

## 5. GitOps Security

### 5.1 ArgoCD Security Assessment

```bash
# Check ArgoCD installation
kubectl get namespace argocd
kubectl get pods -n argocd

# Check ArgoCD RBAC configuration
kubectl get configmap argocd-rbac-cm -n argocd -o yaml

# Check for SSO integration (should not use local accounts)
kubectl get configmap argocd-cm -n argocd -o yaml | grep -A5 "url\|dex.config\|oidc.config"

# Check application source permissions
kubectl get applications -n argocd -o json | jq '.items[] | {name: .metadata.name, source: .spec.source.repoURL, destination: .spec.destination}'

# Check for sync options that bypass security
kubectl get applications -n argocd -o json | jq '.items[] | select(.spec.syncPolicy.automated.prune == true or .spec.syncPolicy.automated.selfHeal == true) | .metadata.name'

# Check for cluster-wide deployments
kubectl get applications -n argocd -o json | jq '.items[] | select(.spec.destination.namespace == "" or .spec.destination.namespace == null) | .metadata.name'
```

### 5.2 Flux Security Assessment

```bash
# Check Flux installation
kubectl get namespace flux-system
kubectl get pods -n flux-system

# Check Flux source credentials
kubectl get gitrepositories -A -o yaml | grep -A5 "secretRef"
kubectl get helmrepositories -A -o yaml | grep -A5 "secretRef"

# Check for unverified sources (no verification)
kubectl get gitrepositories -A -o json | jq '.items[] | select(.spec.verify == null) | .metadata.name'

# Check Kustomization configurations
kubectl get kustomizations -A -o wide
kubectl get kustomizations -A -o json | jq '.items[] | {name: .metadata.name, namespace: .spec.targetNamespace, prune: .spec.prune}'

# Check for cross-namespace references (security risk)
kubectl get kustomizations -A -o json | jq '.items[] | select(.spec.sourceRef.namespace != .metadata.namespace) | .metadata.name'
```

### 5.3 Git Repository Access Control

```bash
# Check Git deploy key permissions (should be read-only)
kubectl get secrets -n argocd -o json | jq '.items[] | select(.metadata.name | test("repo|git|deploy")) | .metadata.name'

# For Flux, check source authentication
kubectl get gitrepositories -A -o json | jq '.items[] | {name: .metadata.name, auth: .spec.ref}'

# Verify no write-access tokens in GitOps namespace
kubectl get secrets -n flux-system -o json | jq '.items[] | select(.type == "Opaque") | .metadata.name'

# Check for hardcoded tokens in GitOps manifests
kubectl get configmaps -n argocd -o yaml | grep -i "token\|password\|secret"
```

### 5.4 Manifest Validation and Admission

```bash
# Check for policy enforcement on GitOps deployments
kubectl get validatingwebhookconfigurations | grep -E "gatekeeper|opa|kyverno|policy"

# Kyverno policies for GitOps
kubectl get clusterpolicies
kubectl get clusterpolicies -o json | jq '.items[] | select(.spec.validationFailureAction == "audit") | .metadata.name'
# Audit mode = not enforced, only logged

# Check for resource validation in ArgoCD
kubectl get appprojects -n argocd -o yaml | grep -A10 "sourceRepos\|destinations\|clusterResourceWhitelist"

# Verify OPA/Gatekeeper constraints cover GitOps paths
kubectl get constraints -o json | jq '.items[] | {name: .metadata.name, enforcement: .spec.enforcementAction}'
```

### 5.5 Drift Detection Security Implications

```bash
# Check for drift detection configuration
# ArgoCD: self-heal and prune settings
kubectl get applications -n argocd -o json | jq '.items[] | {name: .metadata.name, selfHeal: .spec.syncPolicy.automated.selfHeal, prune: .spec.syncPolicy.automated.prune}'

# Flux: prune configuration
kubectl get kustomizations -A -o json | jq '.items[] | {name: .metadata.name, prune: .spec.prune}'

# Security implications:
# - Self-heal enabled: changes made directly to cluster are reverted (good for security)
# - Prune enabled: resources removed from Git are deleted from cluster (risk of accidental deletion)
# - No drift detection: unauthorized changes persist undetected

# Check for manual cluster modifications that bypass GitOps
# Compare Git state vs live state
argocd app diff <app-name> --local ./manifests/
flux diff kustomization <kustomization-name> --path ./manifests/
```

---

## 6. Integrated Scanning Workflow

### Combined IaC Security Assessment

```bash
# Step 1: Clone target repository
git clone <repo-url> /tmp/target-iac && cd /tmp/target-iac

# Step 2: Identify all IaC files
find . -name "*.tf" -o -name "*.tfvars" -o -name "*.yaml" -o -name "*.yml" -o -name "*.json" | grep -v ".terraform" | grep -v "node_modules"

# Step 3: Run Terraform security scanners
tfsec . --format json --out /tmp/tfsec-report.json
checkov -d . --framework terraform --output json --output-file-path /tmp/checkov-report.json
terrascan scan -t terraform -o json > /tmp/terrascan-report.json

# Step 4: Run CloudFormation scanner if CFN templates found
find . -name "*.yaml" -o -name "*.json" | xargs cfn_nag_scan 2>/dev/null

# Step 5: Run Helm scanner if charts found
find . -name "Chart.yaml" -exec dirname {} \; | while read chart; do
  trivy config "$chart"
done

# Step 6: Check for hardcoded secrets
git-secrets --scan-history
trufflehog filesystem --directory .

# Step 7: Generate consolidated report
echo "=== IaC Security Assessment Report ===" > /tmp/iac-report.md
echo "" >> /tmp/iac-report.md
echo "Terraform findings:" >> /tmp/iac-report.md
jq '.results | length' /tmp/tfsec-report.json >> /tmp/iac-report.md
echo "Checkov findings:" >> /tmp/iac-report.md
jq '.results.failed | length' /tmp/checkov-report.json >> /tmp/iac-report.md
echo "Terrascan findings:" >> /tmp/iac-report.md
jq '.results.violations | length' /tmp/terrascan-report.json >> /tmp/iac-report.md
```

---

## Learning Checklist

### Theory Mastery
- [ ] Understand IaC security risks (infrastructure-scale vulnerabilities)
- [ ] Know common Terraform misconfigurations (public resources, hardcoded secrets)
- [ ] Understand CloudFormation privilege escalation paths
- [ ] Know Helm chart security risks (RBAC, secrets in values)
- [ ] Understand CI/CD supply chain attack vectors

### Practical Skills
- [ ] Run tfsec, checkov, and terrascan on Terraform code
- [ ] Scan CloudFormation templates with cfn-nag
- [ ] Audit Helm charts for security misconfigurations
- [ ] Identify hardcoded secrets in IaC repositories
- [ ] Assess CI/CD pipeline security (GitHub Actions, GitLab CI, Jenkins)

### Defense Capabilities
- [ ] Configure secure Terraform backends (encryption, locking)
- [ ] Implement IaC scanning in CI/CD pipelines
- [ ] Secure GitOps deployments (ArgoCD, Flux)
- [ ] Pin action versions and verify supply chain integrity
- [ ] Set up drift detection and enforcement

---

**Document Version**: 1.0
**Created**: 2026-05-14
**Estimated Study Time**: 5-7 hours
**Prerequisites**: Terraform basics, CI/CD familiarity, Kubernetes fundamentals
