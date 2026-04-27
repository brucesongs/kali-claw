# Skill: SSRF serviceendrequestforgery / Server-Side Request Forgery

> **Supplementary Files**:
> - `payloads.md` — SSRF attack payload allset：basic detect、protocolsmuggling、cloud metadatadata extraction、bypasstechnique、DNS rebinding、blind SSRF、RCE groupcombinechain
> - `test-cases.md` — structureizetestinguseexamplechecklist，cover SSRF Detect、internal networkScan、cloud metadatadata、bypasstechnique、advanced exploit，with severelevelother

## Description

Server-Side Request Forgery (SSRF) attacktechniquecomprehensive covering - includingbasic SSRF、blind SSRF、advanced bypass、internal networkport scanning、cloud metadatadata extraction（AWS/GCP/Azure）、protocolsmuggling（gopher://、dict://、file://）andgroupcombine RCE exploitchain。This skillsamewhen covercomplete defensepolicy：URL whitelist、IP scopechecksum、protocollimitation、cloud metadatadataprotect。

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
