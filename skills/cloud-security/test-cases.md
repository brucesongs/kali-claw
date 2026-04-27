# Cloud Security Test Cases

> This file is a companion to `SKILL.md`, containing structured test cases with severity ratings.

---

## Statistics

| Category | Count | Severity Range |
|------|------|-------------|
| A. Cloud Reconnaissance | 2 | Low - Medium |
| B. IAM & Access Testing | 3 | Medium - Critical |
| C. Storage Security | 2 | High - Critical |
| D. Network Security | 2 | Medium - High |
| E. Advanced Exploitation | 2 | High - Critical |
| **Total** | **11** | **Low - Critical** |

---

## A. Cloud Reconnaissance

### TC-CS-01: AWS Account Asset Enumeration

| Field | Value |
|------|-----|
| **ID** | TC-CS-01 |
| **Name** | AWS Account Asset Enumeration |
| **Severity** | Low |
| **Objective** | AWS accountin EC2、S3、Lambda、RDS resource |
| **Prerequisites** | effective AWS credentials（ReadOnly permissioni.e.can ） |
| **Test Steps** | 1. Run `aws sts get-caller-identity` Confirmidentity<br>2. Run `aws ec2 describe-regions` Enumerateactivezonedomain<br>3. 逐zonedomainEnumerate EC2、RDS、Lambda、S3 resource<br>4. Use `aws config` or ScoutSuite Generateassetchecklist |
| **Expected Results** | successEnumerateoutputObjectiveaccount all cloudasset，establishcomplete assetchecklist |
| **Remediation** | limitation IAM policyin `List` and `Describe` permission；enable CloudTrail Monitorabnormal API tuneuse |
| **Related Payload** | payloads.md -- "AWS CLI basic Enumerate" |

### TC-CS-02: Multi-cloud Platform Security Audit

| Field | Value |
|------|-----|
| **ID** | TC-CS-02 |
| **Name** | Multi-cloud Platform Security Audit |
| **Severity** | Medium |
| **Objective** | AWS/Azure/GCP accountentirebodysecurity Configure |
| **Prerequisites** | eachcloudplatform CLI already Configureandauthenticationeffective |
| **Test Steps** | 1. for AWS Run `scout aws --profile default`<br>2. for Azure Run `scout azure --cli`<br>3. for GCP Run `scout gcp --project-id my-project`<br>4. Analyzereportin IAM、storage bucket、security group、encryptionConfigureproblem |
| **Expected Results** | ScoutSuite Generatecontainsall Configureerrorandcompliance违rule security auditreport |
| **Remediation** | based on ScoutSuite reportin Remediation逐itementire改；Deploy CSPM ToolscontinuousMonitor |
| **Related Payload** | payloads.md -- "ScoutSuite multiplecloudaudit", "ScoutSuite Azure audit", "ScoutSuite GCP audit" |

---

## B. IAM & Access Testing

### TC-CS-03: IAM User & Role Permission Enumeration

| Field | Value |
|------|-----|
| **ID** | TC-CS-03 |
| **Name** | IAM User & Role Permission Enumeration |
| **Severity** | Medium |
| **Objective** | AWS IAM user、role、policyandinformation任closesystem |
| **Prerequisites** | effective AWS credentials |
| **Test Steps** | 1. Use pacu `run iam__enum_users` Enumerateall user<br>2. Use pacu `run iam__enum_roles` Enumerateall role<br>3. Use pacu `run iam__enum_policies` Enumeratepolicy<br>4. manual Run `aws iam list-attached-user-policies` crossVerify<br>5. Run `aws iam get-role` Checkinformation任policyin crossaccountinformation任 |
| **Expected Results** | complete IAM entitychecklist，Identifyoutputoverdegreeauthorization userandrole |
| **Remediation** | applicationleast privilegeoriginalthen；removewildcard `*:*` policy；regularlyreviewinformation任policy |
| **Related Payload** | payloads.md -- "pacu -- AWS penetration testingframework", "awscli -- manual IAM Enumerate" |

### TC-CS-04: IAM Privilege Escalation Path Detection

| Field | Value |
|------|-----|
| **ID** | TC-CS-04 |
| **Name** | IAM Privilege Escalation Path Detection |
| **Severity** | Critical |
| **Objective** | AWS IAM privilege escalationtoamount |
| **Prerequisites** | lowpermission AWS credentials |
| **Test Steps** | 1. Use pacu `run iam__privesc_scan` Scanprivilege escalationpath<br>2. Analyzeoutputin can reachprivilege escalationtoamount（such as iam:PassRole、iam:CreateAccessKey、lambda:CreateFunction）<br>3. manual Verifyhighriskpath（such as exploit PassRole createnewuser）<br>4. Recordfromlowpermissiontohighpermission complete attackpath |
| **Expected Results** | Discoverat leastaitemcan row IAM privilege escalationpath |
| **Remediation** | removenotnecessary iam:PassRole、iam:Create*、lambda:CreateFunction etc.permission；realimplementpermissionboundary（Permissions Boundaries） |
| **Related Payload** | payloads.md -- "pacu -- AWS penetration testingframework" |

### TC-CS-05: MFA & Access Key Security Audit

| Field | Value |
|------|-----|
| **ID** | TC-CS-05 |
| **Name** | MFA & Access Key Security Audit |
| **Severity** | High |
| **Objective** | IAM user MFA Configureandaccesskeystatus |
| **Prerequisites** | toolhas IAM readpermission AWS credentials |
| **Test Steps** | 1. Run `aws iam list-mfa-devices --user-name target-user` Check MFA<br>2. Run `aws iam list-access-keys --user-name target-user` CheckkeyCountand年龄<br>3. Run `aws iam get-credential-report` Obtaincomplete credentialsreport<br>4. Identifynot enable MFA userandexceeding 90 天not rotation accesskey |
| **Expected Results** | Discovernot enable MFA userorlengthperiodnot rotation accesskey |
| **Remediation** | forceall userenable MFA；setaccesskeyautomated rotationpolicy；Use AWS Organizations SCP forcecredentialspolicy |
| **Related Payload** | payloads.md -- "awscli -- manual IAM Enumerate" |

---

## C. Storage Security

### TC-CS-06: S3 Bucket Public Access Detection

| Field | Value |
|------|-----|
| **ID** | TC-CS-06 |
| **Name** | S3 Bucket Public Access Detection |
| **Severity** | Critical |
| **Objective** | AWS S3 storage bucket publicaccessConfigure |
| **Prerequisites** | effective AWS credentialsoralready know storage bucketNamelist |
| **Test Steps** | 1. Run `aws s3api list-buckets` Obtainall 桶name<br>2. foreach桶Run `aws s3api get-bucket-acl` Check ACL<br>3. Run `aws s3api get-bucket-policy` Checkpolicyin publicstatement<br>4. Use `--no-sign-request` Test匿nameaccess<br>5. Use s3scanner batchamountScanpublic桶 |
| **Expected Results** | Discoverallows匿namereadorwrite S3 storage bucket |
| **Remediation** | enable S3 Block Public Access；收紧桶policyand ACL；enable SSE-KMS encryptionandversioncontrol |
| **Related Payload** | payloads.md -- "S3 Bucket EnumerateandConfigureerrorDetect" |

### TC-CS-07: Bucket Encryption & Logging Configuration Audit

| Field | Value |
|------|-----|
| **ID** | TC-CS-07 |
| **Name** | Bucket Encryption & Logging Configuration Audit |
| **Severity** | High |
| **Objective** | S3 storage bucket encryptionandaccess logstatus |
| **Prerequisites** | toolhas S3 readpermission AWS credentials |
| **Test Steps** | 1. Run `aws s3api get-bucket-encryption` CheckencryptionConfigure<br>2. Run `aws s3api get-bucket-versioning` Checkversioncontrol<br>3. Run `aws s3api get-bucket-logging` Checklogstatus<br>4. Identifynot encryptionornot enablelog storage bucket |
| **Expected Results** | Discovernot enableserviceendencryptionoraccess log storage bucket |
| **Remediation** | force SSE-KMS encryption；enable S3 access logand CloudTrail dataevent；Configure S3 Object Lock |
| **Related Payload** | payloads.md -- "S3 Bucket EnumerateandConfigureerrorDetect" |

---

## D. Network Security

### TC-CS-08: Security Group & NACL Rule Audit

| Field | Value |
|------|-----|
| **ID** | TC-CS-08 |
| **Name** | Security Group & NACL Rule Audit |
| **Severity** | Medium |
| **Objective** | AWS security groupandnetwork ACL rule |
| **Prerequisites** | toolhas EC2 readpermission AWS credentials |
| **Test Steps** | 1. Run `aws ec2 describe-security-groups` Obtainall security group<br>2. 筛selectinputsiterulein 0.0.0.0/0 and ::/0<br>3. Identifyopenhigh危port（22, 3389, 3306, 5432, 27017） rule<br>4. Run `aws ec2 describe-network-acls` Check NACL rule<br>5. Use ScoutSuite VerifynetworkConfigureerror |
| **Expected Results** | Discoverfor 0.0.0.0/0 openhigh危port security grouprule |
| **Remediation** | limitationsecurity groupinputsiteruletonecessary IP segment；Use VPC Endpoint reducepublic networkexposure；regularlyauditnetworkrule |
| **Related Payload** | payloads.md -- "AWS CLI basic Enumerate" |

### TC-CS-09: EC2 Instance Public Exposure Detection

| Field | Value |
|------|-----|
| **ID** | TC-CS-09 |
| **Name** | EC2 Instance Public Exposure Detection |
| **Severity** | High |
| **Objective** | toolhaspublic network IP EC2 realexampleanditssecurity Configure |
| **Prerequisites** | toolhas EC2 readpermission AWS credentials |
| **Test Steps** | 1. Run `aws ec2 describe-instances` 筛selecttoolhaspublic network IP realexample<br>2. Checkrelatedsecurity group inputsiterule<br>3. Confirm IMDSv2 iswhetheralready force（Checkmetadataoption）<br>4. Use nmap forpublic network IP performport scanningVerifyexposure面 |
| **Expected Results** | Discovernotnecessary public networkexposureand IMDSv1 仍enable realexample |
| **Remediation** | willrealexample迁movetoprivatesubnetwork；Use NAT Gateway or VPN alternativepublic networkaccess；force IMDSv2 |
| **Related Payload** | payloads.md -- "AWS CLI basic Enumerate", "AWS IMDSv1 / IMDSv2" |

---

## E. Advanced Exploitation

### TC-CS-10: SSRF to Cloud Metadata Credential Theft

| Field | Value |
|------|-----|
| **ID** | TC-CS-10 |
| **Name** | SSRF to Cloud Metadata Credential Theft |
| **Severity** | Critical |
| **Objective** | EC2 realexamplemetadataservice（IMDS）and IAM temporarywhen credentials |
| **Prerequisites** | applicationexists SSRF vulnerability；Objectiveas EC2 realexample |
| **Test Steps** | 1. through SSRF access `http://169.254.169.254/latest/meta-data/`<br>2. Obtain IAM rolename：`.../iam/security-credentials/`<br>3. Extracttemporarywhen credentials（AccessKeyId, SecretAccessKey, SessionToken）<br>4. Usesteal credentialsConfigure AWS CLI<br>5. Run `aws sts get-caller-identity` Verifycredentialseffectiveity<br>6. AttemptUse Prowler or pacu performlateral movement |
| **Expected Results** | successsteal IAM temporarywhen credentialsandConfirmitseffective，can 进asteplateral movement |
| **Remediation** | force IMDSv2（`HttpTokens: required`）；innetworklayerlimitationfor 169.254.169.254 access；fixcomplexapplicationlayer SSRF vulnerability |
| **Related Payload** | payloads.md -- "Cloud Metadata exploit（SSRF to Cloud）" |

### TC-CS-11: Kubernetes RBAC Misconfiguration & Container Escape

| Field | Value |
|------|-----|
| **ID** | TC-CS-11 |
| **Name** | Kubernetes RBAC Misconfiguration & Container Escape |
| **Severity** | Critical |
| **Objective** | Kubernetes cluster RBAC ruleand Pod security Configure |
| **Prerequisites** | toolhas kubectl accesspermission credentials |
| **Test Steps** | 1. Run `kubeaudit all -n kube-system` performautomated audit<br>2. Run `kubectl get clusterrolebindings` Check匿namebinding<br>3. Run `kubectl auth can-i --list` Checkcurrentpermission<br>4. Checkprivilegecontainer：`kubectl get pods -o json | jq '.items[].spec.containers[].securityContext.privileged'`<br>5. Check hostPath mount：`kubectl get pods -o json | jq '.items[].spec.volumes[] | select(.hostPath)'`<br>6. Use trivy ScansectionpointonRun containerimagevulnerability |
| **Expected Results** | Discoverprivilegecontainer、匿name RBAC binding、hostPath mountorhigh危imagevulnerability |
| **Remediation** | prohibitprivilegecontainer；收紧 RBAC rule；Use Pod Security Standards；realimplement NetworkPolicy；regularlyScanimage |
| **Related Payload** | payloads.md -- "kubeaudit -- Kubernetes security audit", "kubectl -- manual RBAC audit", "trivy -- containerand IaC Scan" |
