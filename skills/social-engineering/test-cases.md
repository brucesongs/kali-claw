# Social Engineering Test Cases

> This file is a companion to `SKILL.md`, containing structured test cases with severity ratings.

---

## Statistics Overview

| Category | Test Count | Severity Distribution |
|------|----------|-----------|
| A. Phishing Campaigns | 3 | HIGH x2, MEDIUM x1 |
| B. Email Security Testing | 2 | CRITICAL x1, HIGH x1 |
| C. Credential Harvesting | 2 | CRITICAL x2 |
| D. Physical/Voice SE | 2 | HIGH x1, MEDIUM x1 |
| E. Defense Testing | 1 | INFO x1 |
| **Total** | **10** | **CRITICAL: 3, HIGH: 4, MEDIUM: 2, LOW: 0, INFO: 1** |

---

## A. Phishing Campaigns

### TC-SE-001: GoPhish End-to-End Phishing Campaign

| Field | Value |
|------|-----|
| **ID** | TC-SE-001 |
| **Name** | GoPhish End-to-End Phishing Campaign Execution |
| **Severity** | HIGH |
| **Category** | A. Phishing Campaigns |
| **Prerequisites** | GoPhish Deploycomplete; SMTP channelalready Configure; Objectiveemail addresslistalready authorizationObtain |
| **Test Steps** | 1. create Landing Page (cloneObjective SSO login页) |
| | 2. designmailpiecetemplate (passwordoverperiodpassknowtheme) |
| | 3. Configure Sending Profile (SMTP sendpiecechannel) |
| | 4. importObjectiveusergroup (Finance department门 20 person) |
| | 5. Start Campaign (workworkwhen interval 09:00 send) |
| | 6. Monitor Dashboard: mailpiecesendrate、openrate、point击rate、credentialscommitrate |
| **Expected Results** | Campaign successsendall mailpiece; Dashboard realwhen updateStatistics; credentialsbysecurity Record; userbyredirecttorealpage |
| **Pass Criteria** | sendsuccessrate >95%; Dashboard datacomplete ; credentialscapturesuccesscannormal; redirectnormalworkwork |
| **Cleanup** | delete Campaign dataandcapture credentials; sendsecurity awarenesspassknow |

### TC-SE-002: SET Spear-Phishing Attack Vector

| Field | Value |
|------|-----|
| **ID** | TC-SE-002 |
| **Name** | SET Spear-Phishing Payload Delivery |
| **Severity** | HIGH |
| **Category** | A. Phishing Campaigns |
| **Prerequisites** | SET installcomplete; Metasploit listentoolalready Configure; Objectiveenvironmentalready Identify |
| **Test Steps** | 1. Start `sudo setoolkit` |
| | 2. select Social-Engineering Attacks -> Spear-Phishing Attack Vectors |
| | 3. select Perform a Mass Email Attack |
| | 4. select Payload type (such as Meterpreter Reverse TCP) |
| | 5. selectorfromDefinitionmailpiecetemplate |
| | 6. ConfigureObjectiveemail addresslistand SMTP server |
| | 7. ExecuteattackandMonitorreturntune |
| **Expected Results** | Payload successembedmailpiece; mailpiecesendtoObjective; Objectiveopenafterestablishreverseconnect |
| **Pass Criteria** | mailpiecetemplate渲染correct; Payload 免杀rate >60%; reverse shell successestablish |
| **Cleanup** | disablelistentool; terminateall active session; Cleanup Payload file |

### TC-SE-003: Phishing Email Template Customization Test

| Field | Value |
|------|-----|
| **ID** | TC-SE-003 |
| **Name** | High-fidelity Custom Phishing Email Template A/B Test |
| **Severity** | MEDIUM |
| **Category** | A. Phishing Campaigns |
| **Prerequisites** | OSINT Objective画像already complete; GoPhish already Deploy; 两groupObjectiveuseralready partgroup |
| **Test Steps** | 1. baseat OSINT informationdesign两groupnotsametheme mailpiecetemplate |
| | - template A: IT security passknow (generaltemplate) |
| | - template B: baseat OSINT customizemailpiece (containsObjectiverealinformation) |
| | 2. partotherto A groupand B groupsend |
| | 3. Compare两group openrate、point击rate、commitrate |
| | 4. GenerateComparereport |
| **Expected Results** | customizetemplate B point击ratesignificanthighatgeneraltemplate A |
| **Pass Criteria** | template B point击rateat leastistemplate A 1.5 倍; dataStatisticsaccurate; reportcomplete |
| **Cleanup** | clear Campaign data; toparameterandersendtrainingpassknow |

---

## B. Email Security Testing

### TC-SE-004: SPF/DKIM/DMARC Email Forgery Test

| Field | Value |
|------|-----|
| **ID** | TC-SE-004 |
| **Name** | Email Authentication Bypass Test |
| **Severity** | CRITICAL |
| **Category** | B. Email Security Testing |
| **Prerequisites** | Objectivedomain namealready Confirm; DNS querypermission; Testmailpiecegatewayalready Configure |
| **Test Steps** | 1. Use `dig txt target.com` Check SPF Record |
| | 2. Use `dig txt _dmarc.target.com` Check DMARC policy |
| | 3. Use `dig txt default._domainkey.target.com` Check DKIM |
| | 4. Analyze SPF policystrictly ity (~all vs -all) |
| | 5. Analyze DMARC policy (none/quarantine/reject) |
| | 6. Use `swaks` fromnot authorization IP sendTestmailpiece |
| | 7. Usesimilardomain namesendTestmailpiece |
| | 8. Record哪someforgerymailpiecesuccessenter收piece箱 |
| **Expected Results** | SPF softfail (~all) allowsforgerymailpiecedeliver; DMARC none policynotblockforgery; similardomain namecan bypassall Check |
| **Pass Criteria** | successIdentifyat leastamailpieceforgerybypasspath; Recordcomplete technique细section; GenerateRemediation |
| **Cleanup** | deleteall Testmailpiece; recovercomplexTestenvironment |

### TC-SE-005: Email Gateway Filtering Effectiveness Test

| Field | Value |
|------|-----|
| **ID** | TC-SE-005 |
| **Name** | Email Security Gateway Malicious Content Detection Test |
| **Severity** | HIGH |
| **Category** | B. Email Security Testing |
| **Prerequisites** | mailpiecegatewayalready Deploy; Testemail addressalready Configure; malicioussamplethislibraryalready preparation |
| **Test Steps** | 1. sendwith already knowmalicious URL Testmailpiece |
| | 2. sendwith malicious附piece (.exe, .docm, .xlsm) Testmailpiece |
| | 3. sendwith phishinglink HTML mailpiece |
| | 4. sendwith socialwillengineeringinduceContent puretextthismailpiece |
| | 5. Recordeachkindmailpiecebyfilter/allow result |
| | 6. Test URL 重writeand沙箱Detectsuccesscan |
| **Expected Results** | mailpiecegatewayshouldinterceptlargepartialalready knowmaliciousContent; partialadvanced phishingmailpiececan canbypassfilter |
| **Pass Criteria** | already knowmalicious URL interceptrate >90%; malicious附pieceinterceptrate >95%; Recordbypassmethodused forimprove |
| **Cleanup** | CleanupTestemail address; removeall Testmailpiece |

---

## C. Credential Harvesting

### TC-SE-006: Login Page Clone Credential Harvesting

| Field | Value |
|------|-----|
| **ID** | TC-SE-006 |
| **Name** | High-fidelity Login Page Cloning & Credential Capture |
| **Severity** | CRITICAL |
| **Category** | C. Credential Harvesting |
| **Prerequisites** | Objectiveloginpagealready Identify; domain namealready preparation; SSL certificatealready Configure |
| **Test Steps** | 1. Use SET cloneObjective SSO loginpage |
| | `sudo setoolkit` -> Credential Harvester Attack Method |
| | 2. orUse httrack manual clone |
| | `httrack https://target.com/login -O /var/www/clone/` |
| | 3. modifyform action point tocredentialscapturescript |
| | 4. Configure SSL certificatemakepage看起comecan information |
| | 5. throughphishingmailpieceintroduceguideObjectiveaccessclonepage |
| | 6. Verifycredentialsbysuccesscaptureanduserbyredirecttorealpage |
| **Expected Results** | clonepageview觉andrawpagehighdegreeconsistent; credentialsbysecurity Record; userno感knowredirect |
| **Pass Criteria** | pageview觉similardegree >95%; credentialscapturesuccessrate >80%; redirectnoerror; sessionnotin断 |
| **Cleanup** | deleteclonepageandcredentialslog; disablephishingdomain name |

### TC-SE-007: Reverse Proxy Credential Interception Test

| Field | Value |
|------|-----|
| **ID** | TC-SE-007 |
| **Name** | Nginx Reverse Proxy Credential Interception |
| **Severity** | CRITICAL |
| **Category** | C. Credential Harvesting |
| **Prerequisites** | Nginx + Lua modulealready install; SSL certificatealready Configure; domain namealready preparation |
| **Test Steps** | 1. Configure Nginx reverseproxypoint torealloginserver |
| | 2. enable Lua scriptRecord POST requestbody |
| | 3. Configure SSL 终endanddomain name |
| | 4. throughphishinglinkintroduceguideObjectivethroughproxyaccess |
| | 5. VerifycredentialsbyRecordandcomplete sessionnormalforward |
| | 6. Test MFA tokeniswhetheralsobycapture |
| **Expected Results** | all POST requestbody (with credentials) byRecord; complete HTTP sessionnormalproxy; MFA token can byintercept |
| **Pass Criteria** | credentialsRecordcomplete ; proxynodelayorerror; usersessionnormal; MFA token RecordsuccesscanVerify |
| **Cleanup** | deletecredentialslog; disableproxyservice; Cleanupdomain name DNS |

---

## D. Physical/Voice SE

### TC-SE-008: Vishing (Voice Phishing) Attack Simulation

| Field | Value |
|------|-----|
| **ID** | TC-SE-008 |
| **Name** | Voice Phishing Credential Acquisition Test |
| **Severity** | HIGH |
| **Category** | D. Physical/Voice SE |
| **Prerequisites** | VoIP devicealready Configure; Objectivephone numberalready collect; socialworkscriptalready preparation |
| **Test Steps** | 1. preparation IT Help Desk socialworkscript |
| | 2. Use VoIP initiatecall (can select Caller ID spoofing) |
| | 3. by IT supportsidentityExecutescript |
| | 4. AttemptObtain: username、password、MFA Verifycode |
| | 5. AttemptinduceObjectiveaccessmalicious URL |
| | 6. Recordexchange互overprocessandObjectiveantishould |
| **Expected Results** | partialObjectivecan caninelectric话inprovidescredentialsorExecuteoperation |
| **Pass Criteria** | Recordcomplete exchange互overprocess; at least 1 Objectiveprovidespartialinformation; GeneratebehaviorAnalyzereport |
| **Cleanup** | terminateall VoIP connect; deletepass话Record; sendsecurity passknow |

### TC-SE-009: Physical Tailgating + USB Drop Test

| Field | Value |
|------|-----|
| **ID** | TC-SE-009 |
| **Name** | Physical Security - Tailgating Entry & USB Bait Drop |
| **Severity** | MEDIUM |
| **Category** | D. Physical/Voice SE |
| **Prerequisites** | 物reasonTestauthorizationalready Obtain; USB decoyalready preparation; Monitordevicealready Deploy |
| **Test Steps** | 1. preparation USB decoy (tag: "Q4 Salary Data - Confidential") |
| | 2. in停车场/before台/electric梯口投放 USB |
| | 3. samewhen Attempttailgatingenter办公zonedomain |
| | - Testeachentry point accesscontrol |
| | - Recordiswhetherbyrequirementoutput示证piece |
| | - Recordiswhethercanno障碍enterinternalzonedomain |
| | 4. Monitor USB decoy 拾retrieveandinsertsituation |
| | 5. Record "returntune" informationnumber (USB byinsertwhen ) |
| **Expected Results** | partialemployeecan can拾retrieveandinsert USB; tailgatingcan cansuccessenterpartialzonedomain |
| **Pass Criteria** | Record USB 拾retrieverateandinsertrate; Recordtailgatingsuccessrate; Identify物reasonsecurity 薄weak环section |
| **Cleanup** | return收all USB device; terminateMonitor; sendsecurity awarenesspassknow |

---

## E. Defense Testing

### TC-SE-010: Security Awareness Training Effectiveness Assessment

| Field | Value |
|------|-----|
| **ID** | TC-SE-010 |
| **Name** | Pre/Post Security Awareness Training Comparison Assessment |
| **Severity** | INFO |
| **Category** | E. Defense Testing |
| **Prerequisites** | No.a轮phishing Campaign resultalready has; security trainingalready complete; No.second round Campaign preparationthen绪 |
| **Test Steps** | 1. AnalyzeNo.a轮 Campaign data (baseline) |
| | - mailpieceopenrate、linkpoint击rate、credentialscommitrate |
| | 2. Executesecurity awarenesstraining (lineon课process + now场讲座) |
| | 3. Useidenticaldifficultdegree templateExecuteNo.second round Campaign |
| | 4. Compare两轮data changeize |
| | 5. calculatetrainingeffectresultpoint标: riskreduce百partthan |
| | 6. Generatemanagementlayerreport |
| **Expected Results** | No.second round Campaign point击rateandcommitrateshouldsignificantbelowdowngrade |
| **Pass Criteria** | point击ratebelowdowngrade >30%; commitratebelowdowngrade >40%; reportdatacomplete ; with improverecommend |
| **Cleanup** | clearall Campaign data; archivereport; planfollow-uptraining周period |

---

## Appendix: Severity Level Definitions

| Level | Meaning | Description |
|------|------|------|
| **CRITICAL** | critical | attackcan causecredentialslarge-scaleleakageorcompletebypasssecurity controls |
| **HIGH** | high | attacksuccessrate较high，can causepartialcredentialsleakageorsecurity controls失effect |
| **MEDIUM** | in | attackrequiresspecificcondition，successrateinetc. |
| **LOW** | low | attacksuccessrateloworrequirescomplex Prerequisites |
| **INFO** | information | used forAssessanddegreeamount，notdirectgeneratesecurity risk |
