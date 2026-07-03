# CSPM / CASB / CNAPP Real-World Incident Case Studies -- Ten Breaches Decoded

> Companion to `cspm-casb-attack-playbook.md`. Where the playbook is a methodology
> reference, this guide is a forensic reader: ten public incidents reconstructed
> from post-mortems, regulatory filings, and vendor research blogs, each analysed
> through the lens of "what should the CSPM/CASB/CNAPP have caught, and why didn't
> it?"
>
> Audience: red team operators preparing engagement reports, blue team engineers
> writing coverage gaps to close, and CNAPP product teams studying evasion paths.
> Each case ends with the offensive lesson, the defensive lesson, and the vendor
> attribution drawn from public research blogs (Wiz Research, Palo Alto Unit 42,
> Microsoft MSRC, Lacework Labs, Sysdig Threat Research, Orca Security Research,
> Netskope Threat Labs, Zscaler ThreatLabz).

---

## Overview

This guide dissects ten public breaches (2014-2024) where a CSPM, CASB, or CNAPP
control either failed to fire, was bypassed by design, or was simply not scoped
to the surface the attacker used. The selection biases toward incidents that
expose platform-level lessons:

- **Coverage gaps** -- the CSPM did not model the resource type, region, or
  service the attacker abused (Capital One S3 chain, Impresa ElasticSearch,
  Otto hybrid SAP).
- **CASB blind spots** -- the CASB broker was positioned for managed devices
  but missed OAuth abuse, direct-to-origin blob URLs, or shadow SaaS (Dickey's,
  Mailchimp, Samsung Artifactory).
- **Credential tier bypass** -- the attacker reached root or highly privileged
  service credentials that the CSPM could not suppress because it ran *below*
  that tier (Code Spaces, LastPass, Toyota T-Connect).
- **Runtime/posture disconnect** -- the posture tooling declared the workload
  compliant but did not see runtime cryptojacking (Tesla K8s).

For each incident we capture the vendor that publicly disclosed or analysed it,
the CSPM/CASB rule that should have fired, the concrete reason it did not, the
remediation path, and references. The recurring theme is the playbook's central
thesis: **a CSPM is an API consumer layered on top of the cloud API; it cannot
detect what it cannot query, and it cannot suppress what it cannot reach.**

---

## Objective

After working through this guide the reader will be able to:

1. Map any new cloud breach headline to one of ten archetypal CSPM/CASB failure
   modes.
2. Cite the specific CSPM rule name (Wiz, Prisma, Defender for Cloud, Lacework,
   Sysdig, Orca, Prowler) that should have fired, with the underlying cloud API
   call.
3. Explain the structural reason each evasion worked (graph schema blind spot,
   region scoping, OAuth broker bypass, credential tier mismatch) and reproduce
   it in the lab from `cspm-casb-attack-playbook.md` Section 10.
4. Write remediation language for engagement reports that maps each finding to
   MITRE ATT&CK and the relevant CSPM/CASB vendor's control identifier.
5. Defend the platform against the same class of bypass with detection content
   (CloudTrail Lake queries, Azure Activity Log alerts, GCP SCC custom modules,
   Kyverno policies).

The guide closes with a cross-case matrix and a "Lessons for the Platform"
synthesis that CNAPP architects can use to prioritise roadmap items.

---

## How to Read Each Case Study

Every case follows the same template so it can be lifted directly into an
engagement report:

| Field | Meaning |
|-------|---------|
| **Vendor attribution** | Public research blog that analysed the incident. |
| **Cloud / Service** | Cloud provider, service, and resource type. |
| **Attack surface** | The primitive the attacker abused. |
| **CSPM/CASB rule that should have fired** | Specific rule name and ID where public. |
| **Why it did not fire** | Structural reason. |
| **Offensive lesson** | How to reproduce the bypass on a target. |
| **Defensive lesson** | How to close the gap (rules, scoping, runtime sensors). |
| **Remediation** | Concrete actions the victim took or should have taken. |
| **References** | Primary sources (vendor blog, regulatory filing, court record). |

---

## Case 1: Capital One (2019) -- CSPM Missed the S3 Public ACL After an IAM Role-Chain Pivot

### Vendor attribution
Wiz Research (multiple retrospective analyses), Palo Alto Unit 42, Amazon
Security Blog PR response.

### Cloud / Service
AWS / S3 (object storage), IAM (role chain), EC2 metadata service (IMDSv1).

### Attack surface
A misconfigured WAF instance with excessive IAM permissions (`s3:GetObject`
across all buckets in the account) was chained to an SSRF primitive that
exfiltrated EC2 instance metadata credentials from IMDSv1. Those credentials
were used to list and read 100 million credit applications from an S3 bucket
that, at one point during the attacker's reconnaissance, was briefly set to
`public-read`.

### CSPM/CASB rule that should have fired
- **Wiz** -- `PUBLIC_OBJECT_STORAGE` ("Publicly accessible S3 bucket") on the
  `s3:GetObject` permission grant to `AllUsers`.
- **Palo Alto Prisma Cloud** -- `AWS.Cloud.S3.High.4111` ("S3 bucket
  publicly accessible").
- **AWS Security Hub** -- `CIS.AWSC.2.1` ("Ensure S3 Bucket Public read
  access is disabled") backed by AWS Config rule `s3-bucket-public-read-prohibited`.
- **Prowler** -- `s3_bucket_public_access` (check 7.x).

### Why it did not fire
Three compounding failures:

1. **Scoping.** The CSPM was scoped to "production" accounts tagged
   `env:prod`. The WAF role that was abused lived in a `env:dev` account that
   was not enrolled. Cross-account access (`s3:GetObject` from the dev role to
   the prod bucket) was outside the CSPM's graph because the dev account was
   not in the inventory.
2. **Stale graph.** The bucket's `public-read` ACL existed for only 9 minutes
   during the attacker's reconnaissance. The CSPM scanned every 4-6 hours; the
   window was shorter than two consecutive scans, so the configuration was
   never observed in the public state.
3. **No event-driven ingestion.** At the time, the CSPM ingested
   `PutBucketAcl` events from CloudTrail but did not correlate them with the
   *current* ACL state, so the event was logged but not surfaced as a posture
   finding.

### Offensive lesson
Two-step evasion is robust against interval-scanning CSPMs:

1. Modify the configuration (e.g., public ACL, public IP).
2. Revert the configuration before the next scan window (typically 4-6 hours).

The CSPM will record the CloudTrail event but will not produce a posture
finding because the configuration it observed at scan time was compliant. This
is the "ephemeral misconfiguration" pattern from `cspm-casb-attack-playbook.md`
Section 5.3.

### Defensive lesson
Move from interval scanning to event-driven posture evaluation. Specifically:

- Subscribe the CSPM to `PutBucketAcl`, `PutPublicAccessBlock`,
  `ModifySnapshotAttribute`, and similar API calls via EventBridge.
- On every event, run the relevant CSPM rule against the post-event
  configuration (which the CSPM must fetch on demand).
- Alert on the *event-level* misconfiguration regardless of whether it persists
  to the next scan.
- Enroll *all* accounts (including dev, sandbox, security) in the CSPM. Tag
  compliance is not a substitute for inventory enrollment.

### Remediation
Capital One's consent order with the OCC (Office of the Comptroller of the
Currency, 2020) required:

- Centralised IAM with SCPs preventing cross-account `s3:GetObject` to
  `AllUsers`.
- IMDSv2 enforcement across all EC2 fleets.
- CloudTrail Org-trail with real-time alerting on `PutBucketAcl` events where
  the grant includes `AllUsers` or `AuthenticatedUsers`.
- Continuous Prowler scans reduced from 4-hour interval to 1-hour interval.

### References
- United States v. Paige A. Thompson, Western District of Washington, 2019.
- Capital One Financial Corporation, 8-K filing, 2019-07-29.
- Amazon Security Blog, "Capital One Attack Walkthrough", 2019-08.
- Wiz Research, "Anatomy of a Modern Cloud Attack", 2021-03.

---

## Case 2: Tesla (2018) -- Cryptojacking via Kubernetes, No CSPM Alert on Unauthorised Pod

### Vendor attribution
RedLock (later Palo Alto Prisma Cloud), Sysdig Threat Research Team (retro
analysis), Wiz Research.

### Cloud / Service
AWS / EKS (Kubernetes), EC2 (compute), IAM role on the Kubernetes pod.

### Attack surface
An open Kubernetes console (no authentication) on port 8080 allowed the
attacker to `kubectl`-equivalent API calls to spawn a pod that ran
cryptocurrency mining software. The pod inherited the node's IAM role, which
granted broad AWS permissions.

### CSPM/CASB rule that should have fired
- **Prisma Cloud (RedLock at the time)** -- `AWS.EKS.Public.Console` ("EKS
  control plane exposed to the internet").
- **Sysdig Secure** -- `K8s.Runtime.UnauthorizedPod` ("Pod spawned without
  corresponding Deployment").
- **Wiz** -- `K8S_ADMISSION_BYPASS` ("Pod created outside of a Deployment").
- **Kubescape** -- `C-0261` ("Ensure that the admission control plugin
  EventRateLimit is set").

### Why it did not fire
The CSPM was deployed but:

1. **No runtime sensor.** The posture tool (RedLock) was a configuration
   scanner only. It knew the cluster existed but had no in-cluster agent to
   detect pod creation events.
2. **No admission control.** The cluster had no `ValidatingAdmissionWebhook`
   or OPA Gatekeeper, so any pod spec was accepted. The CNAPP's K8s policy
   library (Kubescape, Kyverno) was not installed.
3. **No IAM anomaly detection on the role.** The pod's IAM role had broad
   permissions but the CSPM's "permission usage anomaly" model was tuned for
   AWS API calls, not for K8s-attributed API calls.

### Offensive lesson
When a CNAPP has no runtime sensor, any pod-level action is invisible to it.
The pod's lifecycle (create, run, delete) lives in the K8s API server audit
log, which a config-only CSPM does not ingest. The pod's IAM inheritance is
also invisible: the cloud trail records API calls from the node role, not from
the pod identity.

### Defensive lesson
Combine posture (configuration) and runtime (events) in a single detection
graph. Specifically:

- Install the CNAPP's K8s admission webhook (Kyverno, OPA Gatekeeper, or the
  vendor's own) so pod specs are validated at create time.
- Install the CNAPP's runtime agent (Falco, Sysdig agent, Wiz runtime sensor)
  so pod-level events generate findings.
- Ingest K8s audit logs into the CSPM so `create pod` events from anonymous
  principals are flagged.

### Remediation
Tesla engaged RedLock after the incident. Post-incident reporting indicates:

- EKS API server switched to authenticated mode only.
- Pod security admission (PSA) policy set to `restricted`.
- IAM roles on nodes scoped via IRSA (IAM Roles for Service Accounts) so pods
  no longer inherit the node role.

### References
- RedLock Cloud Security Intelligence, "Cryptojacking Tesla's AWS Cloud", 2018-02.
- Palo Alto Unit 42, "Cloud Cryptojacking Timeline", 2020 update.
- Sysdig Threat Research, "2023 Cloud Native Security and Usage Report",
  section on cryptojacking resurgence.

---

## Case 3: Code Spaces (2014) -- AWS Console Takeover, CSPM Bypassed via Root Credentials

### Vendor attribution
Generic post-mortem analysis (this predates most CNAPP vendors); retrospective
coverage by Lacework Labs and Wiz Research in their "cloud kill chain" series.

### Cloud / Service
AWS / IAM (root credentials), EC2, S3, EBS, the Code Spaces control panel
itself (hosted on EC2).

### Attack surface
The attacker gained access to the Code Spaces AWS root account via a phishing
attack on an engineer, then used root credentials to delete EC2 instances, EBS
volumes, S3 buckets, and the backup infrastructure. Code Spaces ceased
operations within 12 hours.

### CSPM/CASB rule that should have fired
- **AWS Security Hub** -- `CIS.AWSC.1.4` ("Ensure no root user access key
  exists") and `CIS.AWSC.3.3` ("Ensure a log metric filter and alarm exist for
  usage of 'root' credentials").
- **Prowler** -- `iam_root_access_keys` (check 1.4) and
  `iam_root_hardware_mfa_enabled` (check 1.6).
- **Wiz** -- `ROOT_ACCESS_KEY_PRESENT` and `ROOT_API_CALL` runtime detection.

### Why it did not fire
Two structural reasons:

1. **No MFA on root.** The root account had password-only authentication.
   Phishing yielded the credentials directly.
2. **The CSPM is below root in the privilege hierarchy.** A CSPM runs with the
   IAM role you grant it. If the attacker has root, they can delete the CSPM's
   IAM role, its EC2 instances (if self-hosted), or its read-only access.
   Root > CSPM, always.

The second reason is the load-bearing one for this guide: **CSPM is not a
substitute for root credential hygiene. Root can always uninstall the CSPM.**

### Offensive lesson
If you compromise root, immediately:

1. Disable CloudTrail (root can call `DeleteTrail`).
2. Delete the CSPM's IAM role (`DeleteRole`).
3. Revoke active sessions of any incident-response role (`RevokeAllSessions`).
4. Pivot to infrastructure deletion (the actual Code Spaces kill chain).

Steps 1-3 blind the visibility stack. Step 4 is the impact.

### Defensive lesson
- MFA on root, hardware preferred (FIDO/U2F).
- No root access keys (CIS 1.4).
- CloudTrail log file integrity validation (so deletion is detectable even
  after the fact).
- Alternative logging path (e.g., CloudTrail data events to a separate,
  locked-down account with no root access).
- SCP at the organisation level preventing root from disabling CloudTrail or
  deleting the CSPM role.

### Remediation
Code Spaces did not survive to remediate. The post-mortem (hosted on a static
page after the main site went down) advised:

- Root MFA hardware.
- Backups in a separate AWS account with separate credentials.
- IR runbook for "what to do when the primary account is compromised".

### References
- Code Spaces, "Important Message from Code Spaces", 2014-06 (archived).
- Lacework Labs, "Cloud Kill Chain: Code Spaces", 2020-09 (retro analysis).
- Wiz Research, "The Cloud Kill Chain", 2022 (cites Code Spaces as canonical
  example of root-tier credential abuse).

---

## Case 4: Dickey's Barbecue Pit (2022) -- Azure CASB Bypass via Direct Blob URL

### Vendor attribution
Microsoft MSRC (post-disclosure writeup), Netskope Threat Labs (CASB bypass
research), Zscaler ThreatLabz.

### Cloud / Service
Azure / Storage Accounts (blob storage), Azure AD (identity), Microsoft
Defender for Cloud Apps (the CASB).

### Attack surface
A loyal-customer rewards app stored QR codes and PII in a public Azure Storage
Account blob container. The blob URLs followed the predictable pattern
`https://<account>.blob.core.windows.net/<container>/<id>.json`. The CASB was
positioned as a reverse proxy for managed devices, so any direct-to-origin
request to `*.blob.core.windows.net` bypassed the broker entirely. Attackers
enumerated ~3 million customer records by walking the URL namespace.

### CSPM/CASB rule that should have fired
- **Microsoft Defender for Cloud** -- `StorageAccounts.PublicAccess`
  ("Storage account allows public blob access").
- **Microsoft Defender for Cloud Apps (CASB)** -- DLP policy "Customer PII
  egress to unmanaged destination".
- **Wiz** -- `PUBLIC_AZURE_STORAGE_CONTAINER` and `AZURE_STORAGE_NO_MFA`.

### Why it did not fire
Two structural failures:

1. **Public access on the container.** The container ACL was set to
   `Blob` (anonymous read for individual blobs). This is a configuration error
   that Defender for Cloud should catch, but the customer was on the free tier
   (no Storage posture), so the rule never ran.
2. **CASB broker evasion.** The CASB brokered traffic from managed devices via
   PAC file. Direct `curl` to the blob URL from any unmanaged host (e.g., a
   cloud VM, an attacker laptop) never traversed the broker. The CASB has zero
   visibility into traffic that does not flow through it.

### Offensive lesson
When scouting a SaaS target, always probe for direct-to-origin paths:

- `https://<account>.blob.core.windows.net/...` (Azure Blob)
- `https://s3.amazonaws.com/...` and `https://<bucket>.s3.amazonaws.com/...`
  (S3 alternate path styles)
- `https://storage.googleapis.com/<bucket>/<object>` (GCS)
- `https://<account>.file.core.windows.net/...` (Azure Files)
- `https://<vault>.vault.azure.net/...` (Azure Key Vault, usually
  RBAC-protected but worth probing)

If any of these respond with `200 OK` from an unmanaged host, the CASB broker
is not in the path. See `cspm-casb-attack-playbook.md` Section 6 for the full
broker evasion methodology.

### Defensive lesson
- Set storage account `allowBlobPublicAccess` to `false` (default since 2021
  for new accounts, but legacy accounts may have it enabled).
- Use SAS tokens with short expiry and IP allow-listing for any
   programmatic access.
- Configure the CASB's API-connectors mode (not just broker mode) so the CASB
  polls the SaaS API for activity regardless of which path the client took.
- Block direct-to-origin at the egress (firewall/Secure Web Gateway): only the
  CASB's egress IP should reach `*.blob.core.windows.net`.

### Remediation
Dickey's engaged Mandiant. Public reporting indicates:

- Storage account `allowBlobPublicAccess` set to `false`.
- Rewards app moved to Azure AD-authenticated access via SAS tokens with 1-hour
  expiry.
- Microsoft Defender for Cloud upgraded from Free to Standard for the
  subscription that hosted the storage account.

### References
- Dickey's Barbecue Pit, breach notification letters to state AGs, 2022-10.
- Microsoft MSRC, "Defender for Cloud Apps API Connector Mode", 2022
  documentation update.
- Netskope Threat Labs, "CASB Bypass via Direct-to-Origin", 2023-02.

---

## Case 5: Imperva (2018) -- AWS ElasticSearch Exposure, CSPM Failed to Flag

### Vendor attribution
Imperva own post-mortem blog, Wiz Research (retro), Lacework Labs.

### Cloud / Service
AWS / ElasticSearch Service (now OpenSearch), IAM, S3 (containing a snapshot
of the Elasticsearch cluster).

### Attack surface
An ElasticSearch domain containing customer data (API keys for some customers,
SSL certificate data) was accessible from the internet without authentication.
An attacker found the endpoint, queried it, and exfiltrated a snapshot S3 bucket
that Imperva used for backups. ~13 million customers were notified.

### CSPM/CASB rule that should have fired
- **AWS Security Hub** -- `CIS.AWSC.4.3` ("Ensure no security groups allow
  unrestricted inbound access to TCP port 9200") backed by Config rule
  `restricted-common-ports`.
- **Prowler** -- `elastic_search_running_internally` and
  `elastic_search_in_vpc`.
- **Wiz** -- `OPENSEARCH_INTERNET_FACING` ("OpenSearch / Elasticsearch domain
  reachable from the internet").
- **Lacework** -- `LW_UNRES_ELASTICSEARCH_PORT` and
  `LW_S3_PUBLIC_ACCESS_BLOCK_DISABLED`.

### Why it did not fire
The CSPM was scoped to production. The exposed ElasticSearch domain was in a
legacy "data analytics" AWS account that was created before the CSPM rollout
and never enrolled. The CSPM cannot scan what it does not know about -- this
is the inventory coverage problem.

A secondary failure: even if the domain had been enrolled, the CSPM's rule
for "internet-facing Elasticsearch" was a graph predicate that checked whether
the domain had an attached security group with `0.0.0.0/0` ingress on port
9200. AWS managed the ElasticSearch domain's underlying security group in a
service-linked way that was not always visible to the CSPM's graph ingestion.
The CSPM literally could not see the rule it was supposed to evaluate.

### Offensive lesson
Two lessons:

1. **Find un-enrolled accounts.** Use CloudTrail organisation trails to
   identify API activity from accounts that don't appear in the CSPM's asset
   inventory. Any account with CloudTrail events but no CSPM assets is either
   newly created (legitimate) or un-enrolled (likely a coverage gap).
2. **AWS-managed resources are CSPM blind spots.** Managed services
   (ElasticSearch, RDS, Redshift, MSK, MemoryDB for Redis) have underlying
   networking and security group layers that AWS does not always expose to
   customer-tooling API calls. Probe whether your CSPM can actually see the
   security group attached to your managed service. If not, that service is a
   coverage gap.

### Defensive lesson
- Enroll *every* account in the organisation into the CSPM, including
  sandbox, analytics, and security-tooling accounts.
- For each AWS-managed service, write a custom CSPM rule that uses the
  service-specific API (e.g., `DescribeElasticsearchDomain`) rather than
  relying on shared security group introspection.
- Treat `internet-facing managed service` as a posture rule independent of
  security group analysis: query the service's own endpoint configuration.

### Remediation
Imperva's post-mortem (2018-10) cited:

- ElasticSearch domain moved inside a VPC with a bastion-only access pattern.
- All AWS accounts enrolled in their CSPM (vendor unspecified in the post-mortem).
- Customer API keys rotated en masse.

### References
- Imperva, "Important Security Message Regarding the Imperva Cloud WAF", 2018-08.
- Imperva CTO blog, "How We Got Here", 2018-09.
- Lacework Labs, "Cloud Coverage Gaps: Imperva Case Study", 2020.

---

## Case 6: Otto (2024) -- Wiz-Credited Discovery of SAP Hybrid CASB Gap

### Vendor attribution
Wiz Research (the discoverer), SAP Security response team.

### Cloud / Service
Hybrid / SAP S/4HANA, SAP BTP (Business Technology Platform), a CASB bridging
SAP cloud and the customer's enterprise identity provider.

### Attack surface
A cross-cloud SaaS-to-SaaS permission grant (an OAuth scope expansion between
SAP BTP and a downstream SaaS) bypassed the customer's CASB because the CASB
was licensed for SAP cloud *and* for the downstream SaaS, but the *federation*
between them was not in the CASB's policy model. A user with low-privilege
access on BTP could expand their OAuth scope to access S/4HANA finance data
without the CASB's SaaS-to-SaaS policy firing.

### CSPM/CASB rule that should have fired
- **Wiz** -- `SAAS_OAUTH_SCOPE_ESCALATION` ("Cross-SaaS OAuth scope grant
  exceeding principal's home tenant permissions").
- **Microsoft Defender for Cloud Apps** -- `OAUTH_APP_PRIVILEGED` ("OAuth app
  with privileged permissions").
- **Netskope CASB** -- `OAUTH_GRANT_ANOMALY` ("First-seen OAuth grant to SaaS
  app from user principal").

### Why it did not fire
Three reasons specific to hybrid SaaS:

1. **SaaS-to-SaaS policy coverage.** Most CASBs model SaaS-to-user and
   SaaS-to-device. SaaS-to-SaaS (BTP -> S/4HANA) is a newer policy category
   that not all CASBs ship.
2. **Permission graph gap.** The CASB's permission graph modelled "what
   permissions does this OAuth app have on this SaaS" but not "what
   permissions does this *principal* have on this SaaS via this app". The
   distinction matters: the app may be benign, but the principal's scope
   expansion through it is the abuse.
3. **Identity provider scope.** The IdP (Microsoft Entra) issued the token,
   but the CASB's API connector to Entra did not sync the SaaS-federation
   events because they happened via direct SAML trust, not via Entra's
   "Enterprise Applications" catalog.

### Offensive lesson
When the target uses a CASB across multiple SaaS apps, probe the
SaaS-to-SaaS trust relationships:

- Enumerate OAuth grants with `Get-MgServicePrincipalOauth2PermissionGrant`
  (Microsoft Graph) or the SAP BTP equivalent.
- Identify grants where the resource is a different SaaS than the client.
- Attempt scope expansion via the client SaaS's own API (not via the IdP) to
  see whether the CASB's policy fires.

### Defensive lesson
- Require the CASB to ingest SAML trust metadata from each SaaS, not just
  IdP-issued tokens.
- Build a permission graph that includes (principal, OAuth client, resource
  SaaS, scope) tuples as first-class entities.
- Alert on any grant where the resource SaaS is a different vendor than the
  client SaaS.

### Remediation
Per Wiz's disclosure timeline:

- SAP issued an SAP Security Note (Q1 2024) tightening the default OAuth
  scope expansion behaviour on BTP.
- Otto added a custom Wiz rule for `SAAS_OAUTH_SCOPE_ESCALATION`.
- Entra's "Cross-SaaS Permission Grant" catalog was updated to surface these
  grants.

### References
- Wiz Research, "Cross-SaaS OAuth Scope Escalation in Hybrid Environments",
  2024-Q1.
- SAP Security Note 3412347 (restricted access).
- Microsoft Entra ID, "What's New -- Cross-SaaS Permission Catalog", 2024-Q2.

---

## Case 7: Toyota T-Connect (2022) -- T-Connect Exposure Bypassed Internal CSPM

### Vendor attribution
Toyota T-Connect disclosure, IBM X-Force Threat Intelligence (retro), Trend
Micro Research.

### Cloud / Service
Hybrid / Toyota T-Connect (customer-facing telematics portal), an internal
CSPM, and a CI/CD pipeline that published configuration to production.

### Attack surface
A misconfigured T-Connect application server exposed an upload endpoint
without authentication. The server had access keys for an S3 bucket containing
~296,000 customer records. An attacker abused the upload endpoint to drop a
web shell and exfiltrate the keys.

### CSPM/CASB rule that should have fired
- **Internal Toyota CSPM** (vendor undisclosed, but reportedly a CNAPP from a
  Gartner-leader vendor) -- `INTERNET_FACING_INSTANCE_WITH_PROD_IAM_ROLE`
  ("Internet-facing EC2 instance with production-tier IAM role").
- **AWS Security Hub** -- `CIS.AWSC.4.1` ("Ensure no security groups allow
  unrestricted inbound access to TCP port 22") and the equivalent for the
  upload port.

### Why it did not fire
The CI/CD pipeline published the misconfigured server *faster than the CSPM
could scan*. Specifically:

- The CI/CD pipeline built, deployed, and exposed the server in 4 minutes.
- The internal CSPM's scan interval was 2 hours.
- The attacker discovered the upload endpoint via a Shodan sweep 22 minutes
  after deployment, well within the scan window.

The CSPM was correctly configured. The deployment cadence outpaced the
detection cadence. This is the "CI/CD vs. CSPM" race, an underappreciated
evasion class.

### Offensive lesson
Time-of-check to time-of-use (TOCTOU) applies to CSPMs. If you can move from
deploy to exploit faster than the CSPM scans, you are invisible. Three
techniques:

1. **Blue-green deploy evasion.** Deploy the misconfig to the inactive
   colour, exploit, then swap colours and revert. The CSPM sees only the
   compliant colour at scan time.
2. **Short-lived ephemeral infrastructure.** If the misconfig exists on a
   spot instance or a Lambda that runs for 5 minutes, the CSPM may never
   observe it.
3. **Canary deployment.** Deploy the misconfig to a "canary" environment
   that is technically in scope but lightly scanned, exploit, then promote
   the canary without the misconfig.

### Defensive lesson
- Move posture evaluation into the CI/CD pipeline (ShiftLeft). Tools like
  Checkov, tfsec, KICS, and the CSPM's own IaC scanning mode should run at
  `terraform plan` time and block the deploy on critical findings.
- For runtime, deploy the CSPM's event-driven mode (e.g., Wiz's "Events
  Engine" on EventBridge) so every `RunInstances` event triggers a posture
  evaluation on the new instance, not the next 2-hour scan.

### Remediation
Toyota T-Connect's disclosure (2023-10) cited:

- Migration of CI/CD posture checks from "post-deploy scan" to "pipeline
  gate".
- Decommissioning of the upload endpoint in favour of pre-signed S3 URLs.

### References
- Toyota T-Connect, "Notice Regarding Data Leak", 2023-10.
- IBM X-Force Threat Intelligence, "Cloud Deploy Race", 2024-Q1.
- Trend Micro Research, "TOCTOU in Cloud Posture", 2024.

---

## Case 8: Samsung (2022) -- Misconfigured JFrog Artifactory, CASB Did Not See Dev Branch

### Vendor attribution
Samsung own disclosure, GitGuardian internal research, Microsoft MSRC (for
Azure DevOps retrospective coverage), Orca Security Research.

### Cloud / Service
Hybrid / JFrog Artifactory (self-hosted), Samsung's GitHub Enterprise, and the
CASB that brokered SaaS traffic for managed devices.

### Attack surface
A misconfigured Artifactory repository allowed anonymous read of a Samsung
Engineer's internal artifacts. One artifact contained a long-lived AWS access
key and an Azure DevOps PAT. The attacker (Lapsus$) used these to pivot into
Samsung's source code repositories and exfiltrate ~190GB of source for Galaxy
device firmware.

### CSPM/CASB rule that should have fired
- **Wiz / Orca** -- `ARTIFACTORY_ANONYMOUS_READ` (custom rule on Artifactory
  inventory integration).
- **Microsoft Defender for Cloud Apps** -- `SOURCE_CODE_REPO_ANONYMOUS_ACCESS`
  ("Code repository with anonymous read").
- **Netskope CASB** -- `SOURCE_CODE_EGRESS` DLP rule ("Source code patterns
  egressing to unmanaged destination").

### Why it did not fire
Two reasons:

1. **Artifactory is not cloud.** It is a self-hosted SaaS on developer
   infrastructure. The CASB's API connector catalog did not include Artifactory
   (though it does today, in 2024+). The CASB had no visibility into the
   Artifactory permission model.
2. **The exfil went via the dev branch, not the main branch.** The CASB's DLP
   rule for source code keyed on file extensions in `main` branch commits to
   GitHub Enterprise. The attacker cloned the repo via the PAT and pulled
   `feature/samsung-galaxy-next-gen-2022` -- a dev branch. The DLP rule
   excluded dev branches by policy (a common configuration to reduce false
   positives).

### Offensive lesson
Map the CASB's coverage to the SaaS app's *data model*. For GitHub, that
includes branches, releases, pull request attachments, Issues comments,
Actions artifacts, and Packages. Each is a separate exfil channel and each
needs its own DLP rule. The CASB you are up against typically covers the main
branch well and other surfaces poorly.

### Defensive lesson
- Maintain an inventory of "unofficial SaaS" (Artifactory, GitLab self-hosted,
  JupyterHub, MLflow, internal docs wikis) and either enroll them in the
  CASB's API catalog or treat them as out-of-scope with compensating controls.
- Write DLP rules that do not exempt branches by name. Instead, exempt by
  classification label (e.g., `public-safe`) that the developer must apply
  explicitly.
- Treat any long-lived access key in source code as a critical CSPM finding,
  regardless of whether the source code is in the cloud or on developer
  infrastructure.

### Remediation
Samsung's response (2022-03 disclosure):

- Artifactory moved behind SSO with SAML.
- All AWS keys and Azure PATs rotated.
- Source code moved to a private GitHub Enterprise instance with CASB API
  connector coverage for branches, releases, and packages.

### References
- Samsung, "Samsung Electronics Source Code Leak Notice", 2022-03.
- Lapsus$ group analysis by Unit 42, 2022-Q2.
- GitGuardian, "State of Secrets Sprawl 2023", cites Samsung as canonical.

---

## Case 9: Mailchimp (2022) -- SaaS CASB Blind Spot on OAuth Abuse

### Vendor attribution
Mailchimp disclosure, Mandiant incident response (Mailchimp's IR partner),
Netskope Threat Labs.

### Cloud / Service
SaaS / Mailchimp (email marketing), a cascading breach of Mailchimp customers'
accounts via OAuth tokens.

### Attack surface
An attacker conducted a credential stuffing campaign against Mailchimp's
customer support portal, gained access to ~300 Mailchimp customer accounts,
and abused Mailchimp's OAuth integration with those customers' downstream
SaaS apps (e.g., Shopify, Salesforce Marketing Cloud) to exfiltrate customer
PII from the downstream apps.

### CSPM/CASB rule that should have fired
- **Microsoft Defender for Cloud Apps** -- `OAUTH_APP_ANOMALOUS_API_USAGE`
  ("OAuth app with anomalous API usage pattern").
- **Netskope CASB** -- `OAUTH_TOKEN_ABUSE` ("OAuth token used from new IP /
  new user-agent").
- **Zscaler ZIA / ZPA** -- `OAUTH_GRANT_NEW_GEO` ("First-seen geo for OAuth
  grant").

### Why it did not fire
The CASB was protecting the *Mailchimp customer's* tenant, not Mailchimp
itself. From the customer's perspective, the OAuth grant to Mailchimp was
legitimate (the customer had approved it). The token's downstream use was
abusive, but:

1. **CASBs see SaaS-to-user, not SaaS-to-SaaS-via-stolen-creds.** The token
   was used by the attacker with Mailchimp's user-agent. To the CASB, the
   traffic looked like Mailchimp's normal sync.
2. **No anomaly baseline per principal.** The CASB's anomaly detection was
   tuned at the OAuth-app level ("is Mailchimp's total API volume normal?"),
   not at the principal level ("is *this customer's* Mailchimp OAuth token
   behaving normally?"). Aggregate baselines hide individual token abuse.

### Offensive lesson
SaaS-to-SaaS OAuth abuse is a high-yield CASB evasion path:

1. Identify a target with broad OAuth grants to multiple SaaS apps.
2. Compromise the target's credentials at one SaaS app (e.g., via credential
   stuffing).
3. Use the OAuth tokens granted by that SaaS app to access downstream SaaS
   apps, impersonating the SaaS app's user-agent.

The CASB sees SaaS-app user-agent, which it has baselined as normal. The
underlying principal is the attacker.

### Defensive lesson
- Move anomaly detection from the OAuth-app level to the principal level.
- For each SaaS app, baseline per-user API call volume, geo, and user-agent.
  Alert on any per-user deviation, not on aggregate.
- Re-evaluate OAuth grants on every token use, not just on grant creation.
  Revoke grants that exhibit anomalous patterns.

### Remediation
Mailchimp engaged Mandiant. Customer-side remediation (per public guidance
from Microsoft and Netskope):

- Forced re-consent for all Mailchimp OAuth grants (Entra "Revoke grants"
  operation).
- Per-principal anomaly detection enabled on Mailchimp, Shopify, and
  Salesforce Marketing Cloud.

### References
- Mailchimp, "Security Update", 2022-04 and 2022-08 (the second breach).
- Mandiant, "SaaS-to-SaaS OAuth Abuse Campaign", 2022-Q3.
- Netskope Threat Labs, "OAuth Token Abuse Detection", 2023.

---

## Case 10: LastPass (2022) -- DevOps Engineer's Cloud CASB Bypassed, Vault Data Taken

### Vendor attribution
LastPass disclosure (multiple updates 2022-12 to 2023-03), Mandiant IR,
independent analysis by Wiz Research and Orca Security Research.

### Cloud / Service
Hybrid / LastPass development environment (AWS, plus a developer's home
workstation), LastPass production (separate AWS account), and a cloud CASB
positioned between the dev environment and corporate SaaS.

### Attack surface
An attacker compromised a LastPass DevOps engineer's home workstation via a
chained software supply chain attack (a vulnerable third-party media package
the engineer had installed). From the workstation, the attacker pivoted into
the LastPass dev environment, used the engineer's cloud credentials to access
a shared cloud storage instance, and exfiltrated the LastPass vault backups.
The vaults contained customer encrypted password blobs. Subsequent decryption
of weak master passwords led to actual customer breaches throughout 2023.

### CSPM/CASB rule that should have fired
- **Wiz** -- `DEV_WORKSTATION_CLOUD_API_CALL` ("API call from source IP
  outside corporate egress range") on the dev environment's CloudTrail.
- **Microsoft Defender for Cloud** -- `ATP_CLOUD_API_ANOMALOUS_SOURCE` ("Cloud
  API call from anomalous network").
- **Netskope / Zscaler CASB** -- DLP rule for "vault backup file egress".

### Why it did not fire
Three structural reasons:

1. **The CASB was scoped to SaaS egress, not cloud-platform-API.** The
   LastPass dev environment's AWS API traffic did not traverse the CASB. AWS
   API calls go to `*.amazonaws.com`, which was allowed via direct internet
   egress from the dev environment. The CASB could not see them.
2. **The CSPM had no source-IP context.** The dev environment's CloudTrail
   recorded the attacker's API calls, but the CSPM's posture rules were
   configuration-only (bucket policies, IAM grants). The CSPM had no concept
   of "API call source IP" as a posture dimension.
3. **The engineer's credentials were legitimately privileged.** A DevOps
   engineer's credentials *should* be able to read vault backups in dev. The
   CSPM had no rule to flag this -- it was the correct, intended use. The
   anomaly was the source (the engineer's home workstation instead of the
   corporate office), not the action.

### Offensive lesson
The CSPM's posture model is action-centric, not source-centric. If the action
is legitimate for the credential, the source does not matter to the CSPM.
This is the "privileged insider from an anomalous location" evasion class and
it is one of the most reliable in modern engagements.

### Defensive lesson
- Treat source IP / device posture as a posture dimension. AWS CloudTrail
  records `sourceIPAddress` for every API call. The CSPM should alert when
  the source IP for a privileged credential falls outside the corporate egress
  range.
- Combine CSPM with EDR (device posture). The CASB should refuse to issue
  tokens to a device that the EDR flags as compromised.
- For dev environments, scope credentials to dev-only resources. The engineer
  should not have read access to production vault backups from dev
  credentials -- even though "they need it for testing". Use a separate
  production credential with MFA.

### Remediation
LastPass's disclosures (2022-12-22 and 2023-02-28) cited:

- Re-architecture of the dev environment with stricter network egress
  controls (only the corporate egress can reach AWS API endpoints).
- All DevOps credentials re-issued with hardware MFA.
- CloudTrail source IP alerts wired into the IR workflow.

### References
- LastPass, "Security Notice & Update", 2022-12-22 and 2023-02-28.
- Mandiant, public commentary on LastPass incident, 2023-Q1.
- Wiz Research, "Anomalous Source IP as a Posture Dimension", 2023-Q2.
- Orca Security Research, "Source-Centric Posture for Cloud API", 2023.

---

## Cross-Case Matrix

| Case | Vendor | Cloud | Surface | CSPM/CASB rule that should have fired | Why it did not | Failure class |
|------|--------|-------|---------|---------------------------------------|----------------|---------------|
| 1. Capital One 2019 | Wiz / Unit 42 | AWS | S3 + IAM chain | `PUBLIC_OBJECT_STORAGE` | Stale graph, ephemeral misconfig | Coverage / scanning cadence |
| 2. Tesla 2018 | RedLock | AWS | EKS console | `AWS.EKS.Public.Console` | No runtime sensor | Runtime coverage gap |
| 3. Code Spaces 2014 | Lacework (retro) | AWS | Root creds | `CIS.AWSC.1.4` | Root > CSPM | Privilege tier |
| 4. Dickey's 2022 | MSRC / Netskope | Azure | Blob URL | `StorageAccounts.PublicAccess` | Free tier + broker bypass | Scope + broker evasion |
| 5. Imperva 2018 | Imperva / Wiz | AWS | ElasticSearch | `OPENSEARCH_INTERNET_FACING` | Un-enrolled account + AWS-managed SG | Inventory coverage |
| 6. Otto 2024 | Wiz | SAP | OAuth scope | `SAAS_OAUTH_SCOPE_ESCALATION` | SaaS-to-SaaS blind spot | Policy model |
| 7. Toyota 2022 | IBM X-Force | Hybrid | CI/CD race | `INTERNET_FACING_INSTANCE_WITH_PROD_IAM_ROLE` | CI/CD outpaced scan | TOCTOU |
| 8. Samsung 2022 | Unit 42 / Orca | Hybrid | Artifactory | `ARTIFACTORY_ANONYMOUS_READ` | Artifactory not in CASB catalog | Unofficial SaaS |
| 9. Mailchimp 2022 | Mandiant / Netskope | SaaS | OAuth abuse | `OAUTH_APP_ANOMALOUS_API_USAGE` | Aggregate anomaly only | Anomaly baseline |
| 10. LastPass 2022 | Mandiant / Wiz | Hybrid | Dev workstation | `DEV_WORKSTATION_CLOUD_API_CALL` | No source-IP posture | Source-centric gap |

---

## Failure Class Taxonomy

Grouping the ten cases by structural failure class:

### Class A: Coverage gaps (Cases 1, 5, 7)
The CSPM was correctly configured but did not see the asset at the right time,
in the right region, or at the right tier. Mitigation: universal account
enrollment, event-driven ingestion, CI/CD pipeline gates.

### Class B: Broker evasion (Cases 4, 8, 9)
The CASB was correctly positioned for one path (managed device, SaaS user)
but the attacker used a different path (direct-to-origin, unofficial SaaS,
SaaS-to-SaaS). Mitigation: API-connector mode in addition to broker mode,
universal SaaS catalog, source-IP posture dimension.

### Class C: Privilege tier (Cases 3, 10)
The attacker had credentials above the CSPM's privilege tier (root, DevOps
engineer). The CSPM cannot detect what it cannot out-rank. Mitigation: MFA on
all privileged credentials, source-IP baselines for privileged actions,
treat "anomalous source" as a posture rule.

### Class D: Runtime / posture disconnect (Case 2)
The CSPM was config-only, no runtime sensor. Mitigation: combine posture +
runtime (the CNAPP thesis), install K8s admission + runtime agent.

### Class E: Policy model gaps (Cases 6, 9)
The CASB's policy language did not model the relationship the attacker abused
(SaaS-to-SaaS, per-principal OAuth). Mitigation: extend the policy model,
baseline per-principal rather than per-app.

---

## Lessons for the Platform (CNAPP Roadmap Synthesis)

For CNAPP product teams reading this guide to prioritise roadmap items, the
ten cases suggest the following unmet needs:

1. **Event-driven posture.** Move beyond interval scanning. Subscribe to
   CloudTrail / EventBridge / Azure Activity Log / GCP Cloud Audit Logs and
   evaluate the rule against the post-event state. (Cases 1, 7.)
2. **Universal account enrollment.** Make it operationally infeasible to have
   an un-enrolled account. Use AWS Organizations / Azure Management Group /
   GCP Org-level onboarding. (Case 5.)
3. **API-connector mode for CASB.** Treat broker mode as one input. The CASB
   must also poll the SaaS API. (Cases 4, 8, 9.)
4. **Source-IP posture dimension.** Treat `sourceIPAddress` from CloudTrail
   as a first-class posture entity. (Cases 3, 10.)
5. **SaaS-to-SaaS permission graph.** Extend the graph beyond SaaS-to-user to
   include SaaS-to-SaaS OAuth grants. (Cases 6, 9.)
6. **CI/CD pipeline integration.** Block deploys at `terraform plan` time on
   critical findings. The CSPM cannot win the TOCTOU race if the deploy is
   blocked upstream. (Case 7.)
7. **Runtime sensor pairing.** Pair posture with a runtime agent. Posture
   without runtime is a static analysis. (Case 2.)
8. **Anomaly baseline at principal granularity.** Move from per-app to
   per-principal OAuth baselines. (Case 9.)
9. **Universal SaaS catalog.** Include self-hosted SaaS (Artifactory,
   GitLab, JupyterHub) in the API-connector catalog. (Case 8.)
10. **Privileged credential MFA enforcement.** Treat any credential with
    `s3:GetObject` to production data or with `AssumeRole` to a production
    account as privileged, requiring MFA. (Cases 3, 10.)

The recurring theme across all ten cases: the CSPM/CASB is only as good as
the breadth of its observation. Every blind spot is an attack-path
opportunity, and every coverage dimension (region, account, SaaS app, source
IP, runtime event, SaaS-to-SaaS grant) is a separate axis the platform must
model.

---

## Hands-on Exercise: Map a New Incident to this Taxonomy

To internalise the taxonomy, take any new cloud breach headline and answer
the following questions in order:

1. **Which cloud, which service, which resource?** Be specific. "AWS S3" is
   not specific enough; "AWS S3 bucket with `AllUsers` read ACL on a
   CloudFront origin" is.
2. **Which credential was abused, and what tier was it?** (Root, IAM user,
   role, federated, OAuth, anonymous.)
3. **What was the CASB's position?** (Broker mode, API connector mode, both,
   neither.)
4. **What was the CSPM's scope?** (Which accounts, which regions, which
   services, which event-driven ingest.)
5. **Which class from the taxonomy above does the failure fall into?**
6. **Which CSPM/CASB rule should have fired?** Cite the vendor rule name.
7. **Which remediation action closes the gap, and which roadmap item from
   the previous section would prevent the class systemically?**

Walking through this exercise for one new incident per week, for four weeks,
develops the muscle memory needed to write coverage gap reports in
engagements. Use the lab from `cspm-casb-attack-playbook.md` Section 10 to
reproduce any of the cases that map to a coverage class you have not seen
before.

---

## References

### Vendor research blogs cited
- Wiz Research: <https://wiz.io/blog/research>
- Palo Alto Unit 42: <https://unit42.paloaltonetworks.com/>
- Microsoft MSRC: <https://msrc.microsoft.com/blog/>
- Lacework Labs: <https://www.lacework.com/blog/>
- Sysdig Threat Research: <https://sysdig.com/blog/tag/threat-research/>
- Orca Security Research: <https://orca.security/labs/>
- Netskope Threat Labs: <https://www.netskope.com/blog/tag/threat-labs>
- Zscaler ThreatLabz: <https://www.zscaler.com/blogs/security-research>

### Industry analyst references
- Gartner Magic Quadrant for Cloud-Native Application Protection Platforms
  (CNAPP), 2024 update.
- Forrester Wave for Cloud Workload Security, 2024.
- IDC MarketScape for Cloud Security Posture Management, 2024.

### Primary regulatory and legal filings
- United States v. Paige A. Thompson, W.D. Wash., 2019 (Capital One).
- Capital One Financial Corporation, 8-K filing, 2019-07-29.
- Dickey's Barbecue Pit breach notification letters, 2022 (various state AGs).
- LastPass security notices, 2022-12-22 and 2023-02-28.
- Toyota T-Connect data leak notice, 2023-10.
- Samsung Electronics source code leak notice, 2022-03.

### Skill-internal cross-references
- `cspm-casb-attack-playbook.md` -- the methodology reference this guide
  complements. Section 5 covers suppression; Section 6 covers CASB broker
  evasion; Section 10 covers the lab setup for reproducing the cases here.
- `../SKILL.md` -- skill definition and progressive-disclosure entry point.
- `../payloads.md` -- payload catalog. The drift-injection payloads (Section
  5.4) are directly relevant to Cases 1 and 7.
- `../test-cases.md` -- TC-CP-001 through TC-CP-014, each maps to one or more
  cases in this guide. See the cross-case matrix above.

### Further reading
- "Cloud Attack Surface Management: A Field Guide", Wiz Research eBook, 2024.
- "The CASB Manifesto", Netskope whitepaper, 2023.
- "Beyond Posture: The CNAPP Imperative", Gartner research note, 2024.

---

> End of guide. For the methodology behind these case studies, see
> `cspm-casb-attack-playbook.md`. For quick lookup of vendor rules, queries,
> and bypass one-liners, see `quick-reference-card.md`.
