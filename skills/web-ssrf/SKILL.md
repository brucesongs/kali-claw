---
name: web-ssrf
description: "Server-Side Request Forgery (SSRF) attacks including basic, blind, and advanced bypass techniques, internal port scanning, cloud metadata extraction (AWS/GCP/Azure), protocol smuggling (gopher://, dict://, file://), and chained RCE exploitation."
origin: openclaw
version: "0.1.18"
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
  domain: web-attack
  tool_count: 6
  guide_count: 6
  owasp: "A10:2021-SSRF"
  mitre: "T1190-Exploit Public-Facing App"
---




# Skill: SSRF serviceendrequestforgery / Server-Side Request Forgery

> **Supplementary Files**:
> - `payloads.md` — SSRF attack payload allset：basic detect、protocolsmuggling、cloud metadatadata extraction、bypasstechnique、DNS rebinding、blind SSRF、RCE groupcombinechain
> - `test-cases.md` — structureizetestinguseexamplechecklist，cover SSRF Detect、internal networkScan、cloud metadatadata、bypasstechnique、advanced exploit，with severelevelother

## Summary

Web Ssrf skill domain covering web attack operations.

**Tools**: Burp Suite, curl, ffuf, Gopherus, SSRFmap, Burp Collaborator

**Domain**: web-attack

**OWASP**: A10:2021-SSRF

**MITRE ATT&CK**: T1190-Exploit Public-Facing App

## Description

Server-Side Request Forgery (SSRF) attacks including basic, blind, and advanced bypass techniques, internal port scanning, cloud metadata extraction (AWS/GCP/Azure), protocol smuggling (gopher://, dict://, file://), and chained RCE exploitation. Also covers defense strategies: URL allowlisting, IP range validation, protocol restrictions, and cloud metadata protection.

**Agent canpowerstatement**: already complete OWASP Top 10 2025 SSRF complete learning，masterautomated SSRF ScanTooldevelopmentandcloud metadatadata extractionToolchain。

## Use Cases / Use Cases

1. **Web applicationpenetration testing** - Detecttargetapplicationin URL obtain、fileimport、Webhook etc.successcan SSRF vulnerability，exploititsaccessinternalresource
2. **cloudenvironmentsecurity assessment** - through SSRF Extract AWS/GCP/Azure realexamplemetadata，obtaintemporarywhen credentialsandsensitiveconfigurationinformation
3. **internal networkpenetration拓expand** - exploit SSRF workasjump板Scaninternal networkserviceport、accessinternal API、detect Kubernetes/Docker etc.basic facility
4. **CTF competitionsolve题** - quick Identify SSRF 题type，constructprotocolsmuggling、DNS rebinding、IP encoding bypassetc.advanced payload
5. **security code audit** - fromDefense Perspectivereview URL handlinglogic，assessmentfilter bypassrisk，realimplementpartlayerdefensesolution

## Core Tools / Core Tools

| Tool | Purpose | Command Example |
|------|------|----------|
| **Burp Suite** | interceptmodify HTTP request，construct SSRF payload，testing redirect bypass | Repeater moduledebug `?url=http://169.254.169.254/` |
| **curl** | quick testing SSRF payload，verifycloud metadatadataendpoint | `curl "http://target/fetch?url=http://127.0.0.1:8080/admin"` |
| **ffuf** | fuzzytesting URL parameter，batchamountdetectinternal network IP andport | `ffuf -u "http://target/fetch?url=http://FUZZ:FUZ2Z" -w ips.txt -w ports.txt` |
| **Gopherus** | generate gopher:// protocol payload，exploit Redis/MySQL/FASTCGI etc. | `python3 gopherus.py --exploit redis` |
| **SSRFmap** | automated SSRF Detectandexploitframework，supportsmultiplekindattackmodule | `python3 ssrfmap.py -r request.txt -p url -m readfiles` |

## Methodology / Methodology

### Attack Chain / Attack Chain

```
URL 参数发现 → 协议走私 → 内网扫描 → 云元数据提取 → RCE 组合链
```

**1. URL parameterdiscovery (Discovery)**
- Identifyaccept URL parameter：`url=`、`path=`、`src=`、`dest=`、`redirect=`、`callback=`
- testing Webhook、PDF generate、imageload、fileimportetc.successcanpoint
- use Burp Suite Hunter or ffuf automated discoveryhideparameter

**2. protocolsmuggling (Protocol Smuggling)**
- `file:///etc/passwd` - readlocalfile
- `gopher://host:port/_DATA` - sendarbitrary TCP data（Redis/MySQL/SMTP）
- `dict://host:port/COMMAND` - executedictionaryprotocolcommand
- `ldap://host:port/` - LDAP query
- `http/https` - standard HTTP requesttointernalservice

**3. internal networkScan (Internal Network Scanning)**
- Scancommon internal networknetworksegment：`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`
- detectcommon port：22、80、443、3306、5432、6379、8080、8443、9200、27017
- exploitresponsewhen intervaldifferencejudgeportopenstatus（blind SSRF）

**4. cloud metadatadata extraction (Cloud Metadata Extraction)**
- AWS: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
- GCP: `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token`
- Azure: `http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01`
- obtaintemporarywhen credentialsafterlateral movementtoitsothercloudresource

**5. RCE groupcombinechain (RCE Chain)**
- SSRF + Redis not authorization: `gopher://127.0.0.1:6379/_CONFIG SET dir /var/www/html` write Webshell
- SSRF + MySQL: `gopher://127.0.0.1:3306/` construct MySQL protocolpackageexecute SQL
- SSRF + FASTCGI: construct FastCGI protocolpackageexecutearbitrarycode
- SSRF + AWS IAM: obtaintemporarywhen credentialsafterthrough AWS CLI takeovercloudresource

### Defense Perspective / Defense Perspective

| Defense Measure | Description | Priority |
|----------|------|--------|
| URL whitelist | onlyallowsaccess预definition domain namelist，denyall itsotherrequest | CRITICAL |
| IP scopechecksum | DNS solveanalysisafterchecktarget IP，blockprivate/return环/chainpathlocaladdress | CRITICAL |
| disabledangerousprotocol | onlyallows http/https protocol，prohibit file/gopher/dict/ldap | HIGH |
| cloud metadatadataprotect | use IMDSv2（AWS）/ deploymentfirewallruleblockfor 169.254.169.254 access | HIGH |
| networkisolation | applicationserverdeploymentinindependentnetworksegment，limitationoutputsiteflowamounttonecessaryservice | HIGH |
| responsesizelimitation | limitation SSRF request responsebodysize，preventlargeamountdataleakage | MEDIUM |
| disableredirect跟random | notautomated 跟random HTTP 3xx redirect，prevent open redirect bypass | MEDIUM |

## Practical Steps / Practical Steps

### Step 1: basic SSRF Detect
testinglocalreturn环address（`127.0.0.1`、`localhost`）andfileprotocol（`file:///etc/passwd`），coordinate IP addresstransformation（hexadecimal、decimal、IPv6、octal、all零）bypassbasic filter。

### Step 2: cloud metadatadata extraction
Extract AWS IAM rolecredentials、GCP Service Account Token、Azure Managed Identity Token，use IP transformationbypasscloud metadatadataaddressfilter。

### Step 3: protocolsmugglingexploit
exploit `gopher://` protocol操控 Redis/MySQL，`dict://` detectserviceversion，`file://` readserversensitivefile。

### Step 4: advanced bypasstechnique
Open Redirect exploit、`@` characternumberspoofing、DNS rebinding、URL encoding bypass、URL solveanalysisdifferenceexploit。

### Step 5: automated SSRF Scan
use SSRFmap automated Detect（readfiles/awsmetadata/portscan module），ffuf batchamountScaninternal networkport，Burp Collaborator Detectblind SSRF。

> **See payloads.md for detailed payloads, and test-cases.md for complete test checklist。**

## Common Pitfalls

- **Testing only 127.0.0.1 and localhost**: Many SSRF filters block these exact strings but fail to block alternative representations like `0x7f000001`, `0177.0.0.1`, `[::1]`, `0`, or `127.1`. Always test a comprehensive list of IP representations to avoid false negatives.
- **Forgetting cloud metadata endpoints**: In cloud environments, SSRF's highest-impact target is the metadata service. Testers sometimes focus on internal port scanning and miss the IAM credential extraction opportunity at `169.254.169.254`.
- **Ignoring blind SSRF**: Not all SSRF returns visible response data. Blind SSRF can be exploited through timing differences, error messages, or out-of-band callbacks (Burp Collaborator) to infer internal service behavior.

## Automation and Scripting

Automate SSRF discovery by fuzzing all URL-accepting parameters with ffuf using lists of internal IP addresses and common cloud metadata endpoints. Use SSRFmap for automated exploitation chains (port scanning, file reading, cloud metadata extraction) once a vulnerable parameter is identified. Script custom DNS rebinding attacks with Python to bypass IP-based filtering by alternating DNS responses between an allowed external IP and the internal target IP within a single TCP connection.

## Reporting and Documentation

SSRF findings must document the vulnerable parameter, the full request payload, and the data accessible through the vulnerability. For cloud metadata extraction, include the specific IAM role credentials or instance metadata exposed and calculate the blast radius (what cloud resources those credentials can access). Provide a network diagram showing the trust boundary violated by the SSRF and include specific code-level remediation recommendations (URL validation library, allowlist approach) rather than generic advice.

## Legal and Ethical Considerations

SSRF testing against cloud environments carries heightened risk because successful exploitation may expose production infrastructure credentials. Never use extracted cloud credentials to access resources beyond what is necessary to demonstrate impact. AWS metadata credentials are temporary but can grant broad permissions — document the permissions available without exercising all of them. When testing SSRF against internal services, be cautious not to disrupt critical internal APIs or services that other customers or users depend on.

## Integration with Other Tools

SSRF findings chain directly into multiple attack paths. Extracted cloud credentials enable cloud-security assessment of the broader infrastructure. Internal port scanning results from SSRF feed into network-pentest methodology for further service enumeration. Gopher protocol SSRF that hits Redis or MySQL connects to database exploitation techniques from web-sqli. DNS rebinding SSRF that accesses internal web applications leads into web-xss and web-auth-bypass testing. Use the SSRF as a pivot point to expand the assessment scope within authorized boundaries.

## Case Studies and Examples

- **AWS metadata extraction via SSRF**: A web application's PDF generation feature accepted a URL parameter. By submitting `http://169.254.169.254/latest/meta-data/iam/security-credentials/`, the attacker extracted AWS IAM temporary credentials that had full S3 read access to the company's customer data buckets.
- **Redis RCE via gopher protocol**: An SSRF vulnerability allowed the `gopher://` protocol. By crafting a gopher payload targeting the internal Redis instance on port 6379, the attacker wrote a cron reverse shell to `/var/spool/cron/root`, achieving remote code execution without any authentication.
- **Kubernetes API access via SSRF**: A pod's web application had an SSRF vulnerability that allowed access to the Kubernetes API server at `https://10.0.0.1:443`. The default ServiceAccount token mounted in the pod had sufficient permissions to read Secrets across the namespace, exposing database credentials.

## Detection Methods

SSRF attacks are detected through: web application firewalls that flag requests to private IP ranges, server-side monitoring of outbound connections to suspicious destinations (169.254.169.254, 127.0.0.1, 10.0.0.0/8), DNS query logs showing unusual internal domain resolutions, and cloud provider metadata access alerts (AWS detects IMDSv1 usage patterns). Defenders should implement network egress filtering, log all outbound connections from application servers, and use IMDSv2 with hop-count limits on all cloud instances.

## Defense Evasion Techniques

Evade SSRF detection by: using DNS rebinding to bypass IP-based blocklists (the DNS lookup returns an allowed IP, then resolves to the target IP on the actual request), encoding IP addresses in decimal/hex/octal formats to bypass string-matching filters, using URL parser inconsistencies (e.g., `http://evil.com#@safe.com` where different parsers disagree on the hostname), and leveraging open redirects on trusted domains to chain through an allowed host to the internal target. For cloud metadata, use IP representations of 169.254.169.254 that may not be in the blocklist.

## Advanced Techniques

Advanced SSRF exploitation includes: HTTP request smuggling combined with SSRF to bypass frontend proxy restrictions, DNS rebinding with precise timing to win race conditions between DNS resolution and application request, SSRF through HTTP headers (Host, X-Forwarded-For, Referer) that get reflected into backend requests, exploiting PDF generators and image processors that fetch external resources, and chaining SSRF with server-side template injection for full code execution. For Kubernetes environments, explore SSRF targeting the cloud metadata service to steal pod service account tokens.

## Tool Comparison Matrix

| Tool | Best For | Automation | Skill Level |
|------|----------|------------|-------------|
| **Burp Suite** | Manual SSRF testing and debugging | Manual | Beginner |
| **ffuf** | Parameter fuzzing for SSRF discovery | Semi-automated | Intermediate |
| **SSRFmap** | Automated exploitation chains | Fully automated | Intermediate |
| **Gopherus** | Gopher protocol payload generation | Semi-automated | Intermediate |
| **curl** | Quick payload verification | Manual | Beginner |
| **Burp Collaborator** | Blind SSRF detection | Automated (OOB) | Beginner |

## Hacker Laws / Hacker Laws

1. **Minimize Attack Surface (minimumizeattack surface)** - SSRF existsmeaningapplicationexposure notnecessary URL requestcanpower。defense coreisreducecan byexternalcontrol requestparameter，usewhitelistandnonblacklist，disablenon必needprotocol。

2. **Trust but Verify (Trust but Verify)** - i.e.make URL seeminglypoint tocombinemethoddomain name，alsomust DNS solveanalysisafterverifyactual IP address。DNS rebinding、Open Redirect、@ characternumberspoofingallexploit "information任table面Value" vulnerability。eachalayerallrequiresindependentverify。

3. **Defense in Depth (defense in depth)** - singleafilter手segment（such as blacklist IP）notenoughwithblock SSRF。mustgroupcombineuse URL whitelist + IP scopechecksum + protocollimitation + networkisolation + cloud metadatadataprotect，形成multiplelayerdefensebodysystem。

4. **Assume Breach (assumptionalready byintrusion)** - incloudenvironmentin，assumptionattackercan canthrough SSRF obtaintorealexamplemetadata。use IMDSv2、least privilege IAM role、短periodcredentials、networksegmentcomelimitationlateral movement impactscope。

## Learning Resources / Learning Resources

**Skill supplementary files**: payloads.md, test-cases.md

**Related Skills**:
- `skills/web-sqli/SKILL.md` — SQL injection：SSRF+MySQL groupcombinechain follow-upexploit
- `skills/web-xss/SKILL.md` — XSS：Web applicationpenetration testingRelated Skills

**External Resources**:
- [PortSwigger Web Security Academy - SSRF](https://portswigger.net/web-security/ssrf)
- [OWASP SSRF Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [HackTricks - SSRF](https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery)
- [Gopherus - SSRF Exploitation Framework](https://github.com/tarunkant/Gopherus)
- [SSRFmap - Automatic SSRF Detection](https://github.com/swisskyrepo/SSRFmap)
- [AWS IMDSv2 Documentation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)
