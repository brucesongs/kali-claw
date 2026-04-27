# Security Misconfiguration Detection Test Cases

> This file is a companion to `SKILL.md`, containing structured test cases and verification checklists.

---

## Test Case Statistics

| Category | Count | ID Range |
|------|------|----------|
| A. HTTP Security | 3 | TC-SM-001 ~ TC-SM-003 |
| B. TLS/SSL | 2 | TC-SM-004 ~ TC-SM-005 |
| C. Default Configuration | 2 | TC-SM-006 ~ TC-SM-007 |
| D. Information Disclosure | 2 | TC-SM-008 ~ TC-SM-009 |
| E. CORS / Cookie | 2 | TC-SM-010 ~ TC-SM-011 |
| **Total** | **11** | TC-SM-001 ~ TC-SM-011 |

---

## A. HTTP Security

### TC-SM-001: Security Response Header Missing Detection

| Item | Content |
|------|------|
| **Test ID** | TC-SM-001 |
| **Category** | A. HTTP Security |
| **Severity** | HIGH |
| **OWASP Mapping** | A02:2025 - Security Misconfiguration |
| **Objective** | VerifyObjective Web applicationiswhetherConfigure all necessary security response Header |
| **Prerequisites** | Objective URL can access，TesterhavehascombinemethodTestauthorization |
| **Test Steps** | 1. Execute `curl -sI http://target` Obtainresponse Header<br>2. Checkiswhetherexistswithbelow Header: Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options, Content-Security-Policy<br>3. Use `testssl.sh --headers --quiet target:443` performautomated Verify<br>4. Recordmissing Header andits潜inimpact |
| **Expected Results** | at leastexists Strict-Transport-Security、X-Content-Type-Options、X-Frame-Options 三must Header |
| **Remediation** | in Web serverConfigureinaddmissing security Header，Reference OWASP Secure Headers Project |

---

### TC-SM-002: Server Version Information Disclosure

| Item | Content |
|------|------|
| **Test ID** | TC-SM-002 |
| **Category** | A. HTTP Security |
| **Severity** | MEDIUM |
| **OWASP Mapping** | A02:2025 - Security Misconfiguration |
| **Objective** | Detect HTTP responseiniswhetherexposureserversoftwarepieceName、versionnumberetc.fingerprintinformation |
| **Prerequisites** | Objective URL can access |
| **Test Steps** | 1. Execute `curl -sI http://target \| grep -i "^server:"` Extract Server Header<br>2. Execute `curl -sI http://target \| grep -i "^x-powered-by:"` Extract X-Powered-By<br>3. Execute `whatweb -v http://target` performcomprehensive fingerprintIdentify<br>4. Recordall leakage tech stackandversioninformation |
| **Expected Results** | Server Header notcontainsdetailed versionnumber，X-Powered-By Header notexists |
| **Remediation** | Configure Web serverhideversioninformation（such as Nginx: server_tokens off; Apache: ServerTokens Prod），remove X-Powered-By Header |

---

### TC-SM-003: HTTP Method Improper Restriction

| Item | Content |
|------|------|
| **Test ID** | TC-SM-003 |
| **Category** | A. HTTP Security |
| **Severity** | MEDIUM |
| **OWASP Mapping** | A02:2025 - Security Misconfiguration |
| **Objective** | Detectserveriswhetherallowsnotnecessary HTTP method（such as PUT, DELETE, TRACE, DEBUG） |
| **Prerequisites** | Objective URL can access |
| **Test Steps** | 1. Execute `curl -s -X OPTIONS http://target -v` Check Allow Header<br>2. 逐aTestdangerousmethod: `curl -s -X PUT http://target/test.txt`, `curl -s -X DELETE http://target/test.txt`<br>3. Test TRACE method: `curl -s -X TRACE http://target`<br>4. Test DEBUG method: `curl -s -X DEBUG http://target/`<br>5. Recordall byaccept non-standardmethod |
| **Expected Results** | onlyallows GET, HEAD, POST etc.necessarymethod，PUT, DELETE, TRACE, DEBUG shouldbydeny（return 405） |
| **Remediation** | in Web serverConfigureinlimitationallows HTTP method，explicitdeny TRACE and DEBUG |

---

## B. TLS/SSL

### TC-SM-004: Weak TLS Protocol Version Support

| Item | Content |
|------|------|
| **Test ID** | TC-SM-004 |
| **Category** | B. TLS/SSL |
| **Severity** | CRITICAL |
| **OWASP Mapping** | A02:2025 - Security Misconfiguration |
| **Objective** | DetectObjectiveiswhether仍supportsalready 弃use TLS protocolversion（SSLv3, TLS 1.0, TLS 1.1） |
| **Prerequisites** | Objective HTTPS portcan access，already install testssl.sh and OpenSSL |
| **Test Steps** | 1. Execute `testssl.sh --protocols --quiet target:443` Detectall supports protocol<br>2. manualVerify: `openssl s_client -connect target:443 -tls1`<br>3. manualVerify: `openssl s_client -connect target:443 -tls1_1`<br>4. Confirmonlysupports TLS 1.2+，reason想situationsupports TLS 1.3 |
| **Expected Results** | notsupports SSLv3、TLS 1.0、TLS 1.1；onlysupports TLS 1.2 and TLS 1.3 |
| **Remediation** | disableall lowat TLS 1.2 protocolversion，Reference Mozilla SSL Configuration Generator Generatesecurity Configure |

---

### TC-SM-005: Certificate Configuration & Validity

| Item | Content |
|------|------|
| **Test ID** | TC-SM-005 |
| **Category** | B. TLS/SSL |
| **Severity** | HIGH |
| **OWASP Mapping** | A02:2025 - Security Misconfiguration |
| **Objective** | Verify TLS certificate combinemethodity、effectiveperiod、keystrongdegreeandchainintegrity |
| **Prerequisites** | Objective HTTPS portcan access |
| **Test Steps** | 1. Execute `testssl.sh --cert --quiet target:443` Detectcertificateinformation<br>2. Checkcertificateeffectiveperiod: `echo \| openssl s_client -connect target:443 2>/dev/null \| openssl x509 -noout -dates`<br>3. Verifycertificatechainintegrity<br>4. Checkkeylengthdegree（RSA >= 2048, ECDSA >= 256）<br>5. Confirm SAN containscorrect domain name |
| **Expected Results** | certificatenot overperiod、keystrongdegreereach标、certificatechaincomplete 、SAN Configurecorrect |
| **Remediation** | andwhen continueperiodcertificate，Useat least 2048 bit RSA oretc.effect ECDSA key，ensureinintervalcertificatechaincomplete |

---

## C. Default Configuration

### TC-SM-006: Default Credential Presence Detection

| Item | Content |
|------|------|
| **Test ID** | TC-SM-006 |
| **Category** | C. Default Configuration |
| **Severity** | CRITICAL |
| **OWASP Mapping** | A02:2025 - Security Misconfiguration |
| **Objective** | DetectObjectivesystemiswhetherexistsnot more改 output厂defaultcredentials |
| **Prerequisites** | already Identifyloginentry point，already install Hydra，havehascombinemethodTestauthorization |
| **Test Steps** | 1. Identifyloginformandparameterformat<br>2. UsedefaultcredentialsdictionaryperformTest: `hydra -l admin -P default_passwords.txt target http-post-form "/login:user=^USER^&pass=^PASS^:F=incorrect"`<br>3. Testdatabasedefaultcredentials: `hydra -l root -P default_passwords.txt target mysql`<br>4. Testcommon groupcombine: admin:admin, root:root, test:test, postgres:postgres<br>5. Recordall success defaultcredentials |
| **Expected Results** | nomethodUseany already knowdefaultcredentialsloginsystem |
| **Remediation** | forceuser首timeloginwhen modifydefaultpassword，realimplementpasswordcomplexdegreepolicy，considermultiplebecause素authentication |

---

### TC-SM-007: Default Installation Page & Admin Interface Exposure

| Item | Content |
|------|------|
| **Test ID** | TC-SM-007 |
| **Category** | C. Default Configuration |
| **Severity** | HIGH |
| **OWASP Mapping** | A02:2025 - Security Misconfiguration |
| **Objective** | Detectiswhetherlegacydefaultinstallpage、exampleapplicationornot protect admin backend |
| **Prerequisites** | Objective URL can access，already install Nikto and Gobuster |
| **Test Steps** | 1. Execute `nikto -h http://target -Tuning 1` Detectfileleakage<br>2. Use Gobuster Enumeratemanagementpath: `gobuster dir -u http://target -w admin_paths.txt`<br>3. manualaccesscommon defaultpage: /admin/, /phpmyadmin/, /actuator/, /wp-admin/<br>4. Checkdefault欢迎pageandinstalltoguide<br>5. Verifymanagementinterfaceiswhetherrequiresauthentication |
| **Expected Results** | nodefaultinstallpage、exampleapplicationornot authenticationadmin backendexposure |
| **Remediation** | deleteall defaultpageandexampleapplication，managementinterfacelimitation IP whitelistaccess，forceauthentication |

---

## D. Information Disclosure

### TC-SM-008: Error Page Information Disclosure

| Item | Content |
|------|------|
| **Test ID** | TC-SM-008 |
| **Category** | D. Information Disclosure |
| **Severity** | HIGH |
| **OWASP Mapping** | A02:2025 - Security Misconfiguration |
| **Objective** | throughTriggererrorresponseDetectiswhetherleakagesensitiveinternalinformation（filepath、databaseversion、stacktracking） |
| **Prerequisites** | Objective URL can access |
| **Test Steps** | 1. sendmalformedparameter: `curl -s http://target/page?id[]=xxx`<br>2. accessnotexistspath: `curl -s http://target/nonexistent_page_12345`<br>3. sendsuperlengthparameter: `curl -s "http://target/search?q=$(python3 -c 'print("A"*10000)')"`<br>4. sendmalformed JSON: `curl -s -X POST http://target/api/data -H "Content-Type: application/json" -d '{malformed'`<br>5. Analyzeall errorresponsein sensitiveinformation |
| **Expected Results** | errorresponseonlyreturngeneralerrormessage，notcontainsfilepath、databaseinformation、stacktrackingetc.internal细section |
| **Remediation** | productionenvironmentdisabledetailed erroroutput，Configureunified errorpage，onlyinloginRecorddetailed error |

---

### TC-SM-009: Directory Listing & Sensitive File Disclosure

| Item | Content |
|------|------|
| **Test ID** | TC-SM-009 |
| **Category** | D. Information Disclosure |
| **Severity** | CRITICAL |
| **OWASP Mapping** | A02:2025 - Security Misconfiguration |
| **Objective** | Detect Web serveriswhetherenabledirectorylist，andiswhetherexposureversioncontrolfileandenvironmentConfigurefile |
| **Prerequisites** | Objective URL can access，already install curl and Gobuster |
| **Test Steps** | 1. Detectdirectorylist: `curl -s http://target/backup/ \| grep -i "index of\|parent directory"`<br>2. Detect Git leakage: `curl -s http://target/.git/HEAD`<br>3. Detect SVN leakage: `curl -s http://target/.svn/entries`<br>4. Detectenvironmentfile: `curl -s http://target/.env`<br>5. Use Gobuster Discovermoremultiplesensitivepath: `gobuster dir -u http://target -w common.txt -x .bak,.env,.sql,.log`<br>6. Recordall can access sensitivefile |
| **Expected Results** | directorylistsuccesscandisable，versioncontrolfileandenvironmentConfigurefilenotcan access（return 403 or 404） |
| **Remediation** | disabledirectorylist，through .htaccess orserverConfigureblockforsensitivefile access，Use .gitignore preventsensitivefilebytrace |

---

## E. CORS / Cookie

### TC-SM-010: CORS Misconfiguration

| Item | Content |
|------|------|
| **Test ID** | TC-SM-010 |
| **Category** | E. CORS / Cookie |
| **Severity** | HIGH |
| **OWASP Mapping** | A02:2025 - Security Misconfiguration |
| **Objective** | Detect CORS Configureiswhetherallowsarbitrary Origin accesssensitiveresource，specialotheris携bandcredentials situation |
| **Prerequisites** | Objective URL can access，exists API endpoint |
| **Test Steps** | 1. Testarbitrary Origin: `curl -sI -H "Origin: http://evil.com" http://target/api/data`<br>2. Testsubdomain name Origin: `curl -sI -H "Origin: http://sub.target.com" http://target/api/data`<br>3. Test null Origin: `curl -sI -H "Origin: null" http://target/api/data`<br>4. Checkresponsein Access-Control-Allow-Origin iswhetheranti射request Origin<br>5. Check Access-Control-Allow-Credentials iswhetheras true |
| **Expected Results** | CORS policyonlyallowscan informationdomain name，notanti射arbitrary Origin，Access-Control-Allow-Credentials andwildcard Origin notsamewhen outputnow |
| **Remediation** | explicitspecifyallows Origin whitelist，avoiddynamicanti射 Origin，prohibitwildcardand Credentials samewhen Use |

---

### TC-SM-011: Cookie Security Attribute Missing

| Item | Content |
|------|------|
| **Test ID** | TC-SM-011 |
| **Category** | E. CORS / Cookie |
| **Severity** | MEDIUM |
| **OWASP Mapping** | A02:2025 - Security Misconfiguration |
| **Objective** | Detectsession Cookie iswhetherConfigure necessary security Attribute（Secure, HttpOnly, SameSite） |
| **Prerequisites** | Objective URL can access，existsloginsuccesscan |
| **Test Steps** | 1. Obtainall Set-Cookie Header: `curl -sv http://target 2>&1 \| grep -i "set-cookie"`<br>2. Check Secure Attribute（only HTTPS transmission）<br>3. Check HttpOnly Attribute（prohibit JS access）<br>4. Check SameSite Attribute（Strict or Lax）<br>5. Assess Domain and Path scopeiswhetherover宽<br>6. Checksessionoverperiodwhen intervaliswhethercombinereason |
| **Expected Results** | all session Cookie contains Secure、HttpOnly、SameSite Attribute，Domain and Path setcombinereason |
| **Remediation** | asall Cookie add Secure and HttpOnly Attribute，set SameSite as Strict or Lax，shortensensitivesessionoverperiodwhen interval |
