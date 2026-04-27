# Skill: security configurationerrorDetect / Security Misconfiguration Detection

> **Supplementary Files**:
> - `payloads.md` — byclassotherorganization attackpayloadandtestingcommand（HTTP Header、TLS/SSL、defaultcredentials、directorylist、CORS、Cookie etc.）
> - `test-cases.md` — structureizetestinguseexample，with severelevelotherandverifyStep（HTTP Security、TLS/SSL、Default Config、Information Disclosure、CORS/Cookie）

## Description

security configurationerror（OWASP A02:2025）ismostcommon andmosteasyby忽view vulnerabilityclassother。itnotissometoolbody techniquedefect，andissystemindeployment、configuration、maintenanceoverprocessinbecause疏忽cause entirebodysecurity 姿态belowdowngrade。defaultcredentialsnot more改、notnecessaryservicenot disable、errormessageoveratdetailed 、security Header missing、directorylistenable——thissomeseemingly琐碎 problem，oftenisattackerintrusion No.abreakthrough。security configurationerror 危害inatits普遍ityandcan exploitity：almostall systemallexistssomekindprocessdegree configurationnotwhen，andautomated ToolcaninnumbersecondsinnerScannumber千target。

**coreDetect领domain**:
- **Default Credentials**: output厂defaultusernamepasswordnot modify（admin/admin、root/root、test/test）
- **Unnecessary Services**: productionenvironmentlegacydebugport、managementinterface、exampleapplication
- **Verbose Errors**: stacktrackingleakagefilepath、databasetype、frameworkversion、SQL statement
- **Missing Security Headers**: missing X-Frame-Options、CSP、HSTS、X-Content-Type-Options etc.criticalprotectionhead
- **Directory Listing**: Web serverallowslistdirectorycontent，exposurebackupfile、configurationfile、databasedump

---

## Use Cases / Use Cases

1. **Web applicationpenetration testing** - fortargetperformcomprehensive configurationsecurity audit，discoveryexposure managementinterface、defaultinstallpage、sensitivefile
2. **basic facilitysecurity assessment** - Detectserveronrun 冗余service、openport、defaultconfiguration
3. **TLS/SSL security audit** - assessmentcertificateconfiguration、protocolversion、passwordsetpiecestrongdegree
4. **cloudresourceconfigurationreview** - check S3 Bucket publicaccess、IAM policyoveratlenient、security grouprulenotwhen
5. **complianceitycheck** - for照 CIS Benchmark、OWASP ASVS etc.standardverifyconfigurationcompliance

---

## Core Tools / Core Tools

| Tool | Purpose | Command Example |
|------|------|----------|
| **Nmap** | serviceEnumerate、versionDetect、scriptScan | `nmap -sV -sC --script=default,vuln target` |
| **Nikto** | Web serverconfigurationvulnerability scanning | `nikto -h http://target -o report.html -Format htm` |
| **testssl.sh** | TLS/SSL configurationcomprehensive Detect | `testssl.sh --full --quiet target:443` |
| **Burp Suite** | HTTP Header analysis、responsecheck、Scanner module | Proxy intercept -> check Response Headers -> Scanner maindynamicScan |
| **WhatWeb** | Web techniquefingerprinting、frameworkversionDetect | `whatweb -v http://target` |

auxiliaryTool: **curl**（manual Header check）、**Gobuster**（directory/file暴powerdiscovery）、**Dirsearch**（directoryEnumerate）、**Hydra**（defaultcredentialsbrute force）、**ScoutSuite**（cloudconfigurationaudit）。

---

## Methodology / Methodology

### Attack Chain / Attack Chain

```
[1] Service Enumeration      [2] Default Credential Testing   [3] Header Analysis
    - nmap 版本探测              - 默认用户名/密码字典             - 检查安全 Header
    - whatweb 指纹识别            - Hydra/medusa 爆破              - CSP 策略审计
    - 端口与服务映射              - 管理接口默认凭证               - Cookie 属性检查
         |                           |                              |
         v                           v                              v
[4] Error Page Probing       [5] Config File Discovery
    - 触发详细错误响应            - 目录列表检测
    - 路径遍历探测                - 备份文件发现
    - 堆栈跟踪分析                - 版本控制文件暴露
    - 框架版本识别                - .env / .git / .svn 泄露
```

### Defense Perspective / Defense Perspective

| Defense Measure | Description | Priority |
|----------|------|--------|
| Server Hardening Guide | follow CIS Benchmark / DISA STIG foroperationsystem、inintervalpieceperformhardening | CRITICAL |
| Automated Config Scanning | will Nikto、testssl.sh、ScoutSuite integrationto CI/CD pipeline，eachtimedeploymentautomated Detect | HIGH |
| Security Headers | deploymentcomplete security Header collection（HSTS、CSP、X-Frame-Options、X-Content-Type-Options） | HIGH |
| Remove Default Installs | deletedefaultpage、exampleapplication、testingaccount、admin backenddefaultentry point | CRITICAL |
| Error Handling Policy | productionenvironmentunifiederrorpage，prohibitstacktrackingandinternalinformationleakage | HIGH |
| Least Privilege Services | disablenotnecessary serviceandport，followleast privilegeoriginalthen | HIGH |

---

## Practical Steps / Practical Steps

### Step 1: Nikto Web Scan

use Nikto performautomated Web configurationScan，Detectdefaultfile、dangerousconfigurationandoverwhen component。

### Step 2: HTTP security Header check

obtainandreview HTTP response Header，verifycriticalsecurity Header iswhetherexistsandconfigurationcorrect。

### Step 3: defaultcredentialsbrute force

use Hydra forloginformanddatabaseserviceperformdefaultcredentialstesting。

### Step 4: Verbose Error exploit

throughsendmalformedrequest、superlengthparameter、illegal HTTP methodtriggerdetailed errorinformation。

### Step 5: directorylistandsensitivefilediscovery

Detectdirectorylistenablesituation，discoveryversioncontrolfileandenvironmentconfigurationfileleakage。

> **See payloads.md for detailed payloads, and test-cases.md for complete test checklist。**

---

## Hacker Laws / Hacker Laws

1. **Obscurity Is Not Security (obfuscationnotissecurity )** -- hidemanagemententry point、usenon-standardport、notexposureversionnumberandnotcanblockattacker。真正 security from correct configurationandeffective accesscontrol，andnon依靠attackerfindnottotarget。any exposureinnetworkon serviceallwillbyautomated Scantooldiscovery。

2. **Minimize Attack Surface (minimumizeattack surface)** -- eachaopenport、eacharunservice、eachainstall componentallis潜inattack surface。deletenotnecessarysuccesscan、disablenot useport、uninstallexampleapplication -- attack surface越small，security risk越low。security configuration coretheniscontinuousreduceattack surface。

3. **Defense in Depth (defense in depth)** -- notcanonlydependencysomealayerconfiguration。HSTS preventdowngradelevel、CSP limitationscriptexecute、X-Frame-Options blockclickjacking、WAF providesadditionalfilter -- eachalayerallisitsotherlayer backup。whensomealayerconfiguration失误when ，itsotherlayer仍canprovidesprotect。

---

## Learning Resources / Learning Resources

 **Skill supplementary files**: payloads.md, test-cases.md
 **Related Skills**: skills/logging-monitoring/SKILL.md, skills/container-security/SKILL.md

 **internalmaterial (this workspace)**:
 - `guides/security_misconfiguration_complete_guide.md` -- security configurationerrorcompleteguide（directoryEnumerate、informationleakage、cloud storageconfiguration、automated ScanTool）

 **External Resources**:
 - [OWASP Top 10 - A02:2025 Security Misconfiguration](https://owasp.org/Top10/A02_2021-Security_Misconfiguration/)
 - [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
 - [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/) -- operationsystemandinintervalpiecehardeningbase准
 - [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/) -- TLS bestpracticeconfigurationgeneratetool
 - [SecurityHeaders.com](https://securityheaders.com/) -- online HTTP security Header Detect
 - [HackTricks - Pentesting Methodology](https://book.hacktricks.xyz/pentesting-web/pentesting-web)
