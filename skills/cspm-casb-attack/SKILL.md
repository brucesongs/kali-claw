---
name: cspm-casb-attack
description: "CSPM/CASB/CNAPP platform bypass and abuse — rule suppression exploitation, IaC state manipulation, CASB proxy evasion, SaaS shadow discovery, Wiz/Prisma/Lacework/Defender coverage gap identification, and tag-tampering attacks against cloud posture management tools."
origin: github-trending-2026
version: "0.2.0.2"
compatibility:
  - openclaw
  - claude-code
  - cursor
  - windsurf
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
  - WebSearch
  - WebFetch
metadata:
  domain: cloud
  category: cloud-posture-casb
  tool_count: 18
  guide_count: 1
  mitre: "T1068-Exploitation for Privilege Escalation, T1565-Adversary-Inhibited-Response-System, T1611-Escape to Host"
  keywords:
    - cspm
    - casb
    - cnapp
    - wiz
    - prisma-cloud
    - defender-for-cloud
    - security-hub
    - lacework
    - orca
    - sysdig-secure
    - checkov
    - kics
    - prowler
    - scoutsuite
    - cloudfox
    - terrascan
    - snyk-iac
    - kubescape
    - netskope
    - zscaler-casb
    - skyhigh
    - tagsuppression
    - iac-drift
    - terraform-state
    - policy-as-code
    - opa
    - kyverno
  last_reviewed: "2026-07-26"
---

# Skill: CSPM / CASB / CNAPP Attack and Evasion

> **Supplementary Files**:
> - `payloads.md` -- Per-vendor attack catalogues (Wiz, Prisma Cloud, Defender for Cloud, Security Hub, Lacework, Orca, Sysdig Secure, Checkov, KICS, Prowler, ScoutSuite, CloudFox, Terrascan, Snyk IaC, Kubescape; Netskope, Zscaler CASB, Skyhigh, Microsoft Defender for Cloud Apps, Symantec CloudSOC, Trellix MVISION). Common patterns: rule suppression abuse, IaC state file manipulation, policy-as-code bypass, CASB reverse proxy evasion, JWT/session replay through CASB, BYO-CERT pinning, multi-cloud lateral movement evading CSPM.
> - `test-cases.md` -- Structured test cases (CSPM presence enumeration, rule suppression abuse, IaC state tampering, policy-as-code bypass, CASB reverse-proxy evasion, SaaS shadow discovery, tag-based suppression hunting, multi-cloud lateral movement, CNAPP graph coverage gap, Wiz query-language analysis, defender-for-cloud workbook tampering, Kubescape exception abuse) -- 12 cases across 6 categories.
> - `guides/cspm-casb-attack-playbook.md` -- End-to-end playbook: enumerate CSPM/CASB presence -> identify coverage gaps -> exploit misconfig-aware attack paths -> maintain evasion via tag/policy tampering -> detection guidance. Includes a full lab setup (AWS Security Hub + Prowler + mock CASB) and four real-incident case studies (Capital One 2019, Tesla S3 2018, Microsoft SAS token leak 2020, Optus 2022, ICBC ransomware 2023).

## Summary

CSPM (Cloud Security Posture Management), CASB (Cloud Access Security Broker), and CNAPP (Cloud-Native Application Protection Platform) are the defender's primary instrumentation for cloud. They watch for misconfigurations, posture drift, anomalous SaaS access, and runtime threats. This skill is the offensive counterpart: how to enumerate which posture tools are deployed, identify their coverage gaps, exploit the misconfig-aware attack paths they normalize, suppress their findings via exception and tag abuse, and evade the CASB reverse proxy on the way to SaaS targets.

**Tools**: pacu, scoutsuite, prowler, cloudfox, checkov, kics, terrascan, snyk-iac, kubescape,opa, kyverno, mitmproxy, burpsuite, jwt_tool, certificate-pinner, cloudlist, bucketeer, trufflehog, grpcurl

**Domain**: cloud

**MITRE ATT&CK**: T1068 (Exploitation for Privilege Escalation), T1565 (Adversary-Inhibited Response System -- finding suppression), T1611 (Escape to Host -- via IaC state poisoning that privesc to TF automation identity)

## Description

CSPM, CASB, and CNAPP are the three layers defenders layer onto a cloud estate once basic IAM and config hardening are in place. CSPM tools (Wiz, Prisma Cloud, Defender for Cloud, AWS Security Hub, Lacework, Orca, Sysdig Secure) continuously scan the cloud control-plane API for misconfigurations. CASB tools (Netskope, Zscaler CASB, Skyhigh, Defender for Cloud Apps, Symantec CloudSOC, Trellix MVISION) broker and inspect SaaS traffic, enforce DLP, and detect shadow IT. CNAPP platforms (Wiz Code, Prisma CNAPP, Lacework, Orca) fuse CSPM, CWPP, and Kubernetes posture into a single graph.

These tools are not the cloud itself -- they're an API consumer layered on top of the cloud provider's API. Every CSPM has the same shape: a read-only role, a config scraper, a rules engine, a graph (often a graph DB), and a presentation layer. The offensive surface this exposes is large and underexplored:

1. **CSPM rule suppression is a defender-controlled primitive attackers can abuse** -- every CSPM allows operators to mark findings as exceptions, suppress by tag, or define allowlists. A compromised operator identity (or a sufficient-privilege attacker in the target cloud) can create suppression rules that hide the attacker's own misconfigurations. The CSPM becomes an *inhibitor of the response system* (MITRE T1565.001).
2. **Coverage gaps are enumerable** -- CSPM tools query the cloud control plane via specific APIs. The set of services they cover is documented, versioned, and discoverable. An attacker who learns the coverage matrix can choose attack paths that traverse only services the CSPM doesn't yet model. Prowler's check list, ScoutSuite's findings scope, and Wiz's supported resource inventory are all public.
3. **IaC state files are an out-of-band attack surface** -- Terraform state files (`terraform.tfstate`) frequently contain secrets and describe the desired infrastructure. Drift between state and live infrastructure is what CSPM detects; *injected* drift (modifying the state file to suppress a finding, or compromising the CI identity that runs `terraform apply`) is a platform-level bypass.
4. **Policy-as-code is the new gatekeeper** -- OPA, Kyverno, Checkov, KICS, Terrascan, Snyk IaC, and Kubescape run as admission controllers, CI gates, and pre-merge hooks. Every one of them has bypass patterns: scope-narrow exception policies, wildcard resource matches, rego eval injection in older OPA, kyverno pattern mismatches, checkov skip comments (`# checkov:skip=CKV_AWS_18`).
5. **CASB reverse proxies are evadable** -- CASB tools intercept SaaS traffic via a forward proxy (Netskope via client / RFC 2547-style steering, Zscaler via ZTNA, Microsoft via Conditional Access app control). The interception point is a TLS terminator; evasion patterns include BYO-CERT pinning on personal devices, custom-app reverse proxy bypass, JWT replay through the proxy, API token theft from managed apps, and direct-to-origin SaaS API calls that bypass the broker entirely.
6. **The graph DB is the crown jewel** -- Wiz's full-stack graph (and the analogous primitives in Prisma and Lacework) is the source of the kill-chain findings. Querying the Wiz graph directly (via its GraphQL API, if credentials are stolen) reveals what the defender knows about the attacker's resources. A skilled attacker uses this for *self-reconnaissance* -- "what does the defender see?" -- and to identify the exact tags, exceptions, or suppressed findings to abuse.

This skill covers vendor-specific enumeration (Wiz API probing, Prisma API inspection, Defender for Cloud posture enumeration, Security Hub findings filtering), common patterns (rule suppression, IaC drift injection, policy-as-code bypass, CASB proxy evasion), and the defensive counterpart (posture management methodology, real-time graph vs. point-in-time scan, policy-as-code frameworks, drift detection).

## Use Cases

1. **CSPM presence enumeration** -- Given a foothold in a cloud account, identify which CSPM/CNAPP platforms are deployed, what their coverage scope is, and where their blind spots lie. (Output: a coverage gap matrix the red team can plan attack paths around.)
2. **Suppression and exception abuse** -- Use a compromised operator identity (or attacker-controlled cloud role with CSPM write access) to create suppression rules that hide attacker resources, then verify the suppression is effective.
3. **IaC state file manipulation** -- Locate a Terraform state file, identify the secrets it contains, modify it to inject drift (e.g., add a public IP the CSPM will see as `managed by Terraform`), or compromise the CI identity that runs `terraform apply` to weaponize drift at scale.
4. **Policy-as-code bypass** -- Identify the admission/CI gate (OPA, Kyverno, Checkov, etc.), read the policy, and craft an exception or a resource specification that satisfies the policy while remaining exploitable (e.g., a checkov skip comment, an OPA rego pattern that misses a wildcard, a Kyverno pattern that fails to match a generate rule).
5. **CASB reverse proxy evasion** -- Enumerate which SaaS apps are brokered by a CASB, identify the broker's interception method (Netskope client, Zscaler ZTNA, Conditional Access app control), and craft traffic that evades the broker (BYO-CERT pinning, custom-app bypass, direct-to-origin API calls, JWT/session replay).
6. **Shadow SaaS discovery (CASB scope gap)** -- Enumerate unmanaged SaaS apps that users in the target org are accessing (LinkedIn, GitHub, Notion, Figma, ChatGPT) and identify the API tokens, OAuth grants, or session cookies that grant access to corporate data outside the CASB's broker scope.
7. **Multi-cloud lateral movement evading CSPM** -- Chain credentials from one provider to another (AWS role -> Azure service principal -> GCP service account) such that each hop lands outside the per-provider CSPM's coverage scope (cross-region, cross-account, cross-provider).
8. **CNAPP graph coverage gap** -- Identify resources that the CNAPP graph fails to model (e.g., a newly-GA service not yet supported, an alpha-region resource, a custom resource type), and choose attack paths that traverse only those resources.
9. **Real-incident reconstruction** -- Reconstruct the CSPM/CASB bypass from Capital One 2019 (Security Hub alert ignored), Tesla S3 2018 (no CORS/MFA enforcement on console), Microsoft SAS token leak 2020 (no expiry scanning), Optus 2022 (CSPM scope gap on a public-facing API), ICBC 2023 (CSPM alerting failure) -- and distill detection patterns.

## Core Tools

### CSPM / CNAPP Target Enumeration

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **prowler** (7.4k stars) | AWS/Azure/GCP posture checker, 300+ checks mapped to CIS, MITRE, ISO, GDPR | `prowler aws -c check_id` / `prowler aws --list-checks` |
| **scoutsuite** (6.6k stars) | Multi-cloud posture audit, generates interactive report | `scout aws -p default --report-dir /tmp/scout` |
| **cloudfox** (Bishopfox, 2.5k stars) | "I know what permissions you have" -- enumerates the accessible surface | `cloudfox aws --payload all-checks` |
| **checkov** (Bridgecrew/Palo Alto, 6.8k stars) | IaC scanner for Terraform/CFN/K8s/ARM, 1000+ policies | `checkov -d . --framework terraform` |
| **kics** (Checkmarx, 2.2k stars) | IaC scanner -- TF/CFN/K8s/Ansible/Helm/Terraform Plan | `kics scan -p ./iac --report-formats json` |
| **terrascan** (tenable, 4.7k stars) | IaC scanner with flexible policy framework (OPA/Rego) | `terrascan scan -t terraform -d .` |
| **snyk iac** | Snyk's IaC security scanner, deep policy library | `snyk iac test ./terraform/` |
| **kubescape** (kubescape, 15k stars) | K8s posture + NSA/CIS + policy-as-code (OPA/Rego) | `kubescape scan framework nsa --verbose` |

### Policy-as-Code & Drift

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **opa** (Open Policy Agent, 9.5k stars) | Rego policy engine, used as admission controller & CI gate | `opa eval -d policies/ 'data.terraform.deny'` |
| **kyverno** (kyverno, 5.7k stars) | K8s-native policy engine, validates/mutates/generates resources | `kyverno apply policies/ --resource resources/` |
| **tfsec** (aquasecurity, 6.6k stars) | TF static analysis, now merged into Trivy | `trivy config ./terraform/` |

### CASB / SaaS Evasion

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **mitmproxy** | TLS-intercepting proxy for studying CASB broker behavior | `mitmproxy --mode reverse:https://app.example.com` |
| **burpsuite** | Manual CASB proxy evasion, JWT/session tampering | (manual GUI workflow) |
| **jwt_tool** | JWT analysis, alg confusion, session replay | `python3 jwt_tool.py <JWT>` |
| **certificate-pinner** | BYO-CERT pinning for CASB bypass on personal devices | (per-app custom pinner) |

### Recon & State Discovery

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **cloudlist** (projectdiscovery) | Multi-cloud asset enumeration from a credentials set | `cloudlist -provider aws` |
| **trufflehog** (trufflehog, 16k stars) | Secret scanner, finds tokens in state files & git history | `trufflehog filesystem ./terraform.tfstate` |
| **grpcurl** | Used to query Wiz's GraphQL API directly after credential theft | `grpcurl -d @ ...` (actually curl + JSON; see payloads.md §3) |

## Methodology

### Attack Chain: CSPM/CASB Platform Bypass

```
   1. Enumerate               2. Coverage-Gap             3. Choose Attack Path        4. Suppress / Evade          5. Maintain
   ─────────────────          ───────────────             ──────────────────           ──────────────────           ─────────────
   CSPM presence        ──>   identify blind spots   ──>  pick path outside       ──> tag-tamper finding,      ──> cross-cloud lateral
   (prowler, scoutsuite,       (unsupported services,      CSPM coverage                 inject IaC drift,           movement, period
   cloudfox,Security Hub)      regions, resource types)                                  policy-as-code bypass,      re-suppression
                                                                                          CASB proxy evasion
                                                                                                │
                                                                                                ▼
                                                                                          Compromised operator
                                                                                          identity creates a
                                                                                          suppression rule (T1565)
```

### Phase Details

1. **CSPM Presence Enumeration** -- Probe the target cloud account for evidence of a deployed CSPM/CNAPP. AWS: look for `Security Hub` enabled, `AWS Config` recorders, `Audit Manager`, IAM roles matching `Wiz*`, `Prisma*`, `Lacework*`, `Sysdig*`, `Orca*`, `Prowler*`. Azure: `Microsoft Defender for Cloud` provisioning, `Azure Policy` assignments, `Security Center` workspace. GCP: `Security Command Center` (SCC) enabled, `Org Policy` service assignments. Use `cloudfox` and `iam enumeration` to map what the CSPM service-linked roles can read.
2. **Coverage Gap Identification** -- Build a matrix of what the CSPM covers vs. what the cloud offers. Wiz publishes its supported resource list per cloud; Prisma publishes its policies RQL library; Prowler ships its check list. Compare against the cloud provider's full service catalog (e.g., AWS has 200+ services; Wiz may cover 80). Services not covered are blind spots. Newly-GA services, alpha regions, and custom (non-cloud-native) resources are classic blind spots.
3. **Attack Path Selection** -- Choose an attack path that maximizes time in the blind spot. Examples: a service the CSPM doesn't yet model, a region the CSPM isn't scanning, a resource type that requires an exception in the CSPM's rules. Combine with conventional cloud-security attack paths (cross-account role assumption, IMDS-leaked credentials) to make the path viable.
4. **Suppression / Evasion** -- Once the attacker has a foothold, evade the CSPM in one of three ways: (a) tag-tampering -- add a tag the CSPM treats as `exception`/`allowlist`; (b) IaC drift injection -- modify the Terraform state so the CSPM sees the resource as `managed` (some CSPMs treat managed resources differently); (c) policy-as-code bypass -- if Checkov/KICS/OPA run as CI gates, add skip comments or scope exceptions.
5. **CASB Proxy Evasion (when SaaS targets are in play)** -- Enumerate which SaaS apps are brokered, identify the broker's interception method, and craft traffic that bypasses it (direct-to-origin API calls, BYO-CERT pinning, custom-app reverse proxy evasion, JWT/session replay).
6. **Multi-Cloud Lateral Movement** -- Use the foothold to chain credentials across providers (AWS -> Azure -> GCP) such that each hop lands outside the per-provider CSPM's scope. The cross-provider hop is the most common gap because most CSPM deployments are per-provider.
7. **Detection Evasion Maintenance** -- Continuously re-enumerate the CSPM's coverage, re-suppress any findings that surface (using a compromised operator identity), and avoid any resource type the CSPM models well.

### Defense Perspective

| Defense Measure | Description |
|-----------------|-------------|
| **Real-time graph over point-in-time scan** | Wiz and Prisma's real-time graph (driven by CloudTrail + config snapshots) closes the gap between config change and detection. Point-in-time scanners (Prowler scheduled runs) have hours-to-days of exposure window. |
| **Immutable suppression audit trail** | Every CSPM rule exception, suppressed finding, and allowlist must be logged with operator identity, reason, and expiry. Quarterly review of all suppressions. |
| **Tag-based suppression lockdown** | Don't allow arbitrary tags to suppress findings; only allow approved tag keys (e.g., `approved-exception`, `breakglass`) with a change-managed value. |
| **Policy-as-code in CI + admission** | Checkov/KICS/Snyk IaC in CI gates failures on PR; Kyverno/OPA at admission prevents in-cluster bypass. Both must agree -- a CI-only gate is bypassable by a direct apply. |
| **IaC state file encryption + access logging** | Terraform state files contain secrets; store in encrypted backends (S3 SSE-KMS, Azure Storage TDE), grant least-privilege read, and alert on out-of-band modifications. |
| **CASB direct-to-origin detection** | SaaS providers (Microsoft 365, Google Workspace) log the source IP of API calls; configure alerts for direct API access that bypasses the CASB broker IP range. |
| **Shadow SaaS discovery + managed-app onboarding** | Use CASB discovery mode (read-only SaaS log ingestion) to find unmanaged apps; actively onboard those with corporate data; revoke OAuth grants to unmanaged apps. |
| **Cross-cloud graph (CNAPP)** | A CNAPP that correlates AWS+Azure+GCP resources in a single graph closes the cross-provider lateral movement gap; per-provider CSPMs miss the cross-provider hop. |

---

## Practical Steps

> **For detailed payloads see `payloads.md`, and for the complete test checklist see `test-cases.md`.**

### Exercise 1: CSPM Presence Enumeration (AWS)

Identify which posture tools are deployed in a target AWS account.

```bash
# List roles matching common CSPM patterns
aws iam list-roles --query 'Roles[?RoleName.contains(@, `Wiz`) || contains(@, `Prisma`) || contains(@, `Lacework`) || contains(@, `Sysdig`) || contains(@, `Orca`) || contains(@, `Prowler`)].RoleName'

# Is AWS Security Hub enabled?
aws securityhub describe-hub --region us-east-1

# List Config recorders (most CSPMs depend on AWS Config)
aws configservice describe-configuration-recorders

# List GuardDuty detectors (runtime detection layer)
aws guardduty list-detectors --region us-east-1

# Which standards are enabled in Security Hub?
aws securityhub get-enabled-standards

# List CloudTrail trails (every CSPM ingests from CloudTrail)
aws cloudtrail describe-trails
```

### Exercise 2: Coverage Gap Matrix Construction

Use Prowler and ScoutSuite's check lists to identify what's covered, then diff against the cloud provider's full service catalog.

```bash
# List all Prowler checks
prowler aws --list-checks | sort -u > prowler-checks.txt
wc -l prowler-checks.txt   # ~300 checks

# List all AWS services
aws service-allocator list-services 2>/dev/null || aws --region us-east-1 ecs list-services  # placeholder

# Cross-reference: which services have *any* Prowler check?
awk -F_ '{print $2}' prowler-checks.txt | sort -u > prowler-services.txt

# Identify AWS services with no Prowler coverage -- those are CSPM blind spots.
# (Manual review of prowler-services.txt vs. https://docs.aws.amazon.com/serviceindex/)
```

### Exercise 3: Wiz GraphQL API Self-Reconnaissance

After stealing a Wiz service account token, query the graph directly to see what the defender knows about your resources.

```bash
# Wiz uses a JWT service account; decode it to extract the endpoint
echo "$WIZ_JWT" | cut -d. -f2 | base64 -d 2>/dev/null | jq '.'

# Query the GraphQL endpoint -- list your resources and their findings
curl -s "$WIZ_ENDPOINT/graphql" \
  -H "Authorization: Bearer $WIZ_JWT" \
  -H 'Content-Type: application/json' \
  --data '{"query":"query { assets(first: 100) { nodes { id name type findings { severity } } } }"}' \
  | jq '.data.assets.nodes[] | {name, type, sev: [.findings[].severity]}'
```

### Exercise 4: Rule Suppression Abuse (AWS Security Hub)

Create a suppression rule that hides a specific finding.

```bash
# Identify the finding you want to suppress
aws securityhub get-findings --filters 'SeverityLabel=[{Value="HIGH",Comparison="EQUALS"}]' \
  --query 'Findings[0].Id'

# Create a suppression rule (NOTE: requires securityhub:UpdateInsight permission)
aws securityhub create-insight \
  --name "suppressed-non-issue" \
  --filters 'ResourceAwsEc2InstanceId=[{Value="REPLACE_WITH_YOUR_INSTANCE_ID",Comparison="EQUALS"}]' \
  --group-by-attribute 'RuleId'

# Verify suppression is effective
aws securityhub get-findings --filters 'ResourceAwsEc2InstanceId=[{Value="REPLACE_WITH_YOUR_INSTANCE_ID",Comparison="EQUALS"}]' \
  --query 'Findings'
```

### Exercise 5: Terraform State File Drift Injection

Locate a state file, identify the secrets it contains, and craft a drift injection.

```bash
# Locate the state file in a compromised environment
find / -name 'terraform.tfstate*' 2>/dev/null
find / -name '*.tfstate' 2>/dev/null
# Common: S3 buckets, CI artifacts, deployment VMs

# Scan the state file for secrets
trufflehog filesystem ./terraform.tfstate

# Read the resources -- note how each is structured
jq '.resources[] | {type, name, instances: .instances[0].attributes | keys}' terraform.tfstate | head -40

# Drift injection example: add an ingress rule to a security group via state modification,
# then apply (compromised CI identity runs `terraform apply`, propagating the drift to live infra)
# See payloads.md §4 for the full state-file modification workflow.
```

### Exercise 6: CASB Reverse Proxy Evasion

Identify a CASB-brokered SaaS app and craft direct-to-origin traffic.

```bash
# Step 1: Identify the broker. Look for unusual TLS interception in corporate devices.
# Netskope: client installs a root CA; check `security find-certificate -a -c Netskope` on macOS.
# Zscaler: ZTNA tunnels; check `scutil --nwi` for the tunnel interface.
# Microsoft Conditional Access app control: reverse-proxy via `*.mcas.ms` URLs.

# Step 2: Capture the broker URL pattern
mitmproxy --mode regular -p 8080
# (corporate browser through the proxy) -- observe the SaaS app's TLS cert issuer;
# if it's "Netskope", "Zscaler", or "*.mcas.ms", the app is brokered.

# Step 3: Bypass via direct-to-origin API call
# Discover the real SaaS API endpoint
dig app.example.com
# Real: app.example.com -> 13.107.x.x (Microsoft)
# Brokered: app.example.com -> *.mcas.ms CNAME -> broker

# Direct call (bypass broker): use the SaaS API directly
curl -H "Authorization: Bearer $SAAS_JWT" https://app.example.com/api/v1/files

# If the JWT was issued via broker-mediated OAuth, this fails. Steal a refresh token
# via the broker's own logs, or use a session cookie copied from a corporate device.
```

### Exercise 7: Checkov Skip-Comment Bypass

Identify a Checkov gate in CI and add a skip comment to bypass a single check.

```bash
# In a compromised PR (attacker has write access), add a skip comment to the offending resource
cat >> main.tf <<'EOF'
resource "aws_s3_bucket" "exfil" {
  bucket = "REPLACE_WITH_YOUR_BUCKET_NAME"
  # checkov:skip=CKV_AWS_18:internal-only
  # checkov:skip=CKV_AWS_19:internal-only
  # checkov:skip=CKV_AWS_20:internal-only
  # checkov:skip=CKV_AWS_53:internal-only
}
EOF

# Verify the skip is effective
checkov -d . --framework terraform --quiet
# Should report zero findings on aws_s3_bucket.exfil
```

---

## Detection Methods

### CSPM Configuration Drift
- **Public S3 bucket creation**: `s3:CreateBucket` with `public-read` ACL; alert via CSPM tools (Wiz, Prisma Cloud).
- **Security group changes**: `ec2:AuthorizeSecurityGroupIngress` opening 0.0.0.0/0 on sensitive ports.
- **IAM role escalation**: New role with `AdministratorAccess` or `*` permissions.
- **KMS key policy weakening**: KMS key policy granting cross-account access.

### CASB Cloud App Activity
- **Unsanctioned app usage**: Users uploading data to unapproved cloud apps (Shadow IT).
- **Data exfiltration patterns**: Large uploads to personal cloud storage (Dropbox, personal OneDrive).
- **OAuth app abuse**: New OAuth app granted broad scopes; mass data access.

### SIEM Detection Rules
- **Splunk SPL**: `index=aws sourcetype=aws:cloudtrail eventName=CreateBucket | where requestParameters.acl="public-read"`
- **Wiz / Prisma Cloud**: Native CSPM alerts for compliance violations.
- **Microsoft Defender for Cloud Apps**: CASB alerts for unsanctioned app usage.

## Defense Evasion Techniques

### CSPM Rule Bypass
- **Use existing compliant resources**: Don't create new public bucket; abuse existing misconfigured one.
- **Policy-based bypass**: Modify SCP (Service Control Policy) to allowlist specific actions.
- **Cross-account resource sharing**: Share resource to attacker account via legitimate mechanism.
- **Tag-based exemption**: Apply exemption tag that CSPM respects (e.g., `CSPM-Exempt: true`).

### CASB Evasion
- **Approved app abuse**: Use sanctioned app (e.g., corporate OneDrive) for exfil; below suspicion.
- **Protocol tunneling**: Tunnel exfil through HTTPS to approved destination.
- **Encoding tricks**: Encode sensitive data as image files; CASB DLP may not scan images.
- **OAuth app camouflage**: Register OAuth app with legitimate-looking name and logo.
- **Personal app + corporate device**: Use personal account on corporate device; bypasses MDM monitoring.

### Cloud Resource Stealth
- **Use serverless**: Lambda / Cloud Functions for transient exploitation; no always-on resources to detect.
- **Spot instances**: Transient compute; terminated before detection baseline established.
- **Cross-region**: Operate in regions with less CSPM coverage (Africa, Middle East).

## Hacker Laws

| Law | Manifestation in CSPM/CASB Attack |
|------|-----------------------------------|
| **Defense in Depth** | CSPM+CASB+CNAPP is itself a defense-in-depth stack; this skill teaches how to identify which layer is missing and exploit the gap. A single bypassed layer shouldn't mean total compromise. |
| **Trust but Verify** | Don't trust the CSPM's default coverage. Wiz covers 80 services; AWS offers 200+. The gap is the trust deficit. Verify coverage via matrix construction (Exercise 2). |
| **Least Privilege** | A CSPM's read-only role is the ideal target -- it sees everything but writes nothing. A compromised operator identity (with write) is the highest-value primitive for suppression. Enforce least-privilege on operator identities to limit suppression scope. |
| **Assume Breach** | Assume the attacker has a foothold. The CSPM is the alarm; this skill teaches how the attacker silences the alarm (T1565). Run quarterly "suppression hunting" exercises. |
| **Minimize Attack Surface** | Every IaC template, every tag key, every exception policy is attack surface. Reduce by (a) limiting tag keys, (b) scoping exception policies tightly, (c) restricting who can run `terraform apply`. |
| **First Principles** | Understand that the CSPM is just an API consumer layered on top of the cloud's own API. It cannot detect what it cannot query. The coverage matrix is the truth, not the marketing slick. |
| **Compromise = Adversary + Time** | The longer the attacker's dwell time, the higher the chance they enumerate the CSPM, identify the gap, and suppress findings. Real-time graph CSPMs (Wiz, Prisma) shrink the time window; point-in-time scanners (Prowler scheduled runs) widen it. |

---

## Differentiation

| Skill | Focus | Overlap with `cspm-casb-attack` |
|-------|-------|---------------------------------|
| `cspm-casb-attack` (this) | **CSPM/CASB/CNAPP platform bypass -- rule suppression, IaC drift injection, policy-as-code bypass, CASB proxy evasion, coverage gap identification** -- platform-evasion-centric | -- |
| `cloud-security` | General cloud infra assessment (AWS/Azure/GCP IAM, S3, IMDS, storage, networking) | Shares cloud-provider surface; cloud-security assesses the infra, this skill evades the defender's platform layered on top. |
| `kubernetes-attack` | Offensive operations against a live K8s cluster -- RBAC, pod escape, SA token theft, etcd exploitation | Shares K8s admission-policy surface (Kyverno, OPA Gatekeeper); this skill targets policy-as-code at the IaC + admission + CI layers, not cluster-internal attack paths. |
| `container-security` | Container defense and best practices | Shares runtime detection surface; container-security defends, this skill evades the defender's instrumentation. |
| `cloud-identity-attack` | Identity-based attacks (AWS STS, Azure service principals, OAuth grants) | Shares identity primitives; cloud-identity-attack is about *abusing identity*, this skill is about *abusing the platform that watches identity-driven misconfigs*. |
| `cloud-native-vuln-research` | CVE research, PoC reproduction, nuclei templates, exploit chain composition | CVE-driven; this skill is platform-evasion-driven (suppressing a Wiz finding is not a CVE). |
| `api-security` | API attack surface, authn bypass, rate-limit bypass, schema fuzzing | Shares JWT/session replay primitives; this skill applies them specifically to CASB-brokered SaaS apps. |
| `ad-ldap-attack` | AD/LDAP on-prem identity attack | Shares conditional-access surface; Defender for Cloud Apps bridges Azure AD into CASB -- overlap is at the broker layer. |

**This skill is platform-evasion**, not cloud-config assessment (use `cloud-security`), not cluster-internal attack (use `kubernetes-attack`), not CVE research (use `cloud-native-vuln-research`). It produces attack paths that *evade the defender's cloud instrumentation*.

---

## Orchestration

### ECC Loop Pattern

- **Pattern**: Iterative Refinement
- **Rationale**: CSPM/CASB evasion is iterative -- enumerate, identify gap, exploit, suppress, re-enumerate to verify suppression. The ECC loop drives each phase with explicit feedback.
- **Integration**: `cloud-security` (base cloud recon), `codebase-onboarding` (IaC template analysis), `verification-loop` (suppression-effectiveness verification)

### Cross-Skill Pipeline

```
cloud-security -> cloud-identity-attack -> cspm-casb-attack -> verification-loop -> pentest-reporting
```

### Quality Gate

- Pre-condition: A cloud foothold exists (an instance, a role, a credential) -- or the engagement scope is to assess a defender's CSPM/CASB deployment from outside.
- Post-condition: A documented coverage gap matrix, at least one demonstrated suppression/evasion, and a verification artifact showing the suppression was effective.
- Verification: Use `verification-loop` Phase 4 (cross-tool confirmation -- e.g., Prowler + ScoutSuite cross-check that a finding is *actually* suppressed in Security Hub).

---

## Learning Resources

- **Wiz Research Blog**: <https://www.wiz.io/blog/topic/research> -- primary source for Wiz-disclosed cloud CVEs and platform bypasses
- **Palo Alto Networks Prisma Cloud Blog**: <https://www.paloaltonetworks.com/prisma/cloud> -- research and advisory
- **Lacework Labs**: <https://www.lacework.com/labs/> -- cloud threat research
- **Sysdig Threat Research Team**: <https://sysdig.com/blog/tag/threat-research/> -- container + cloud
- **Orca Research**: <https://orca.security/labs/> -- side-scanner-less posture research
- **Prowler Documentation**: <https://docs.prowler.cloud> -- AWS/Azure/GCP posture checks
- **Checkov Documentation**: <https://www.checkov.io/> -- IaC scanner
- **KICS Documentation**: <https://github.com/Checkmarx/kics> -- IaC scanner
- **Kyverno Documentation**: <https://kyverno.io/> -- K8s policy engine
- **OPA Documentation**: <https://www.openpolicyagent.org/> -- Rego policy language
- **MITRE ATT&CK T1565.001**: <https://attack.mitre.org/techniques/T1565/001/> -- Storage Wipe / Inhibit System Recovery analog
- **Capital One Breach (2019)**: <https://www.justice.gov/usao-wdwa/pr/cybersecurity-analyst-charged-hacking-capital-one> -- a Security Hub alert was reportedly ignored
- **Microsoft SAS token leak (2020)**: <https://www.wiz.io/blog/financial-data-of-millions-of-people-exposed-online> -- Wiz research disclosure
- **Optus Breach 2022 (Australian)**: <https://www.oaic.gov.au/privacy/privacy-decisions/investigation-reports/privacy-investigation-report-optus> -- public-facing API exposure outside CSPM scope
- **ICBC Ransomware 2023**: <https://www.reuters.com/business/finance/icbc-financial-services-hit-by-ransomware-attack-2023-11-09/> -- CSPM alerting failure

---

**Supplementary files for this skill**: payloads.md, test-cases.md, guides/cspm-casb-attack-playbook.md

**Related skills**: skills/cloud-security/SKILL.md, skills/kubernetes-attack/SKILL.md, skills/cloud-identity-attack/SKILL.md, skills/cloud-native-vuln-research/SKILL.md

**External resources**:
- https://docs.prowler.cloud
- https://www.checkov.io/
- https://github.com/Checkmarx/kics
- https://kyverno.io/
- https://www.openpolicyagent.org/
- https://www.wiz.io/blog/topic/research
- https://orca.security/labs/
- https://www.lacework.com/labs/
