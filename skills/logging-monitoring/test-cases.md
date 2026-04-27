# Logging & Monitoring Security Test Cases

> This file is a companion to `SKILL.md`, containing test cases for log injection, log evasion, monitoring gaps, and detection bypass with severity ratings.

---

## Statistics

| Category | Cases | Severity Distribution |
|------|--------|-----------|
| A. Log Injection | 2 | CRITICAL x1, HIGH x1 |
| B. Log Evasion | 2 | CRITICAL x1, HIGH x1 |
| C. Monitoring Gaps | 3 | HIGH x2, MEDIUM x1 |
| D. Detection Bypass | 3 | CRITICAL x1, HIGH x2 |
| **Total** | **10** | **CRITICAL x3, HIGH x5, MEDIUM x1** |

---

## A. Log Injection

### TC-LM-001: CRLF Injection Log Entry Forgery

| Field | Value |
|------|-----|
| **Test ID** | TC-LM-001 |
| **Name** | CRLF Injection Log Entry Forgery |
| **Severity** | CRITICAL |
| **Category** | Log Injection |
| **OWASP** | A09:2021 |
| **MITRE ATT&CK** | T1070.001 -- Indicator Removal: Clear Windows Event Logs (adapted) |

**Description**: throughinuserinputinembed CRLF 序column (`%0d%0a`)，inlogfileinforgeryallnew logrow，makesecurity Analyze师nomethodzonepartreallogandforgerylog。

**Prerequisites**:
- Objectiveapplicationacceptuserinputandwritelog
- logsystemnot for CRLF 序columnperformfilterorescape

**Test Steps**:
1. sendcontains CRLF injection request：`curl "http://target.com/api/log?event=normal%0d%0a[ERROR]%20Database%20connection%20failed"`
2. Checkapplication log，Confirmiswhetheroutputnowforgery `[ERROR]` itemtarget
3. UsenotsamepayloadLevelrepeatTest（WARNING、CRITICAL、ALERT）

**Expected Results (through)**:
- applicationfor CRLF performescapeorfilter，loginnotoutputnowforgeryitemtarget
- orlogsystemUsestructureizeformat（JSON）storage，forgeryContentbylimitationinsingleFieldValueinner

**Expected Results (failure)**:
- loginoutputnowforgery independentitemtarget
- forgeryitemtarget formatandnormallogconsistent，nomethodzonepart

**Remediation**: Usestructureizelogformat（JSON）；forall writelog userinputperform CRLF filter；logsolveanalysistoolUsestrictly schema checksum。

---

### TC-LM-002: Control Character Injection Log Parsing Disruption

| Field | Value |
|------|-----|
| **Test ID** | TC-LM-002 |
| **Name** | Control Character Injection Log Parsing Disruption |
| **Severity** | HIGH |
| **Category** | Log Injection |
| **OWASP** | A09:2021 |

**Description**: throughinjection ANSI escape序column、backspacecharacter、NULL byteetc.controlcharacters，干扰logdisplayorsolveanalysis，hiderealattackpayloadorforgeryview觉Content。

**Prerequisites**:
- Objectiveapplicationacceptfrom由textthisinput
- logwithpuretextthisformatstorageordisplay

**Test Steps**:
1. sendcontains ANSI escape序column request：`curl "http://target.com/search?q=test\x1b[31mFAKE+ALERT\x1b[0m"`
2. sendcontainsbackspacecharacters request：`curl "http://target.com/api/log?data=authorized\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08unauthorized"`
3. sendcontains NULL byte request：`curl "http://target.com/search?q=normal_query\x00MALICIOUS_HIDDEN_PART"`
4. inlogviewtoolinCheckthissomeitemtarget displayeffectresult

**Expected Results (through)**:
- logsystemfilterall controlcharacters
- logitemtargetonlycontainscan printtextthis，displayContentandactualdataconsistent

**Expected Results (failure)**:
- ANSI escape序column改change终endinlog displaycolororContent
- backspacecharacterscovering rawtextthis
- NULL bytetruncate follow-upContent

**Remediation**: inwritelogbeforestripall controlcharacters（ASCII 0-31, 127）；Usebinarysecurity logformat。

---

## B. Log Evasion

### TC-LM-003: Selective Log Deletion & Tampering

| Field | Value |
|------|-----|
| **Test ID** | TC-LM-003 |
| **Name** | Selective Log Deletion & Tampering |
| **Severity** | CRITICAL |
| **Category** | Log Evasion |
| **MITRE ATT&CK** | T1070.002 -- Indicator Removal: Clear Linux or Mac System Logs |

**Description**: inObtainsystemaccesspermissionafter，attackercandeleteormodifylocallogfile，destroyaudittrace integrity，makeeventnomethod追溯。

**Prerequisites**:
- attackeralready obtainlogfile所insystem writepermission
- lognot performsetinizecollectorintegrityprotect

**Test Steps**:
1. Confirmlogstoragebitconfiguration：`ls -la /var/log/auth.log /var/log/nginx/access.log`
2. Attemptselectitydeletespecificitemtarget：`sed -i '/192\.168\.1\.100/d' /var/log/nginx/access.log`
3. Attempt覆writespecificstring：`sed -i 's/attacker_ip/legitimate_ip/g' /var/log/apache2/access.log`
4. CheckiswhetherhasintegritychecksummechanismDetecttotamper
5. Verifysetinize SIEM iswhetherretain rawnot tamper log副this

**Expected Results (through)**:
- locallogfilepermissionrestricted，nomethodmodify（such as append-only Attribute）
- fileintegrityMonitor（FIM）DetecttotamperandTriggeralert
- SIEM inretain independent notcan tamper副this

**Expected Results (failure)**:
- logfilecan byarbitrarymodifyordelete
- noany integritychecksummechanism
- setinizelogplatformandlocallogContentconsistent，allbytamper

**Remediation**: Use `chattr +a` set append-only Attribute；Deploy FIM（such as OSSEC/Wazuh）；logrealwhen forwardtoremote SIEM（TLS encryptiontransmission）。

---

### TC-LM-004: Noise Injection Attack Trace Masking

| Field | Value |
|------|-----|
| **Test ID** | TC-LM-004 |
| **Name** | Noise Injection Attack Trace Masking |
| **Severity** | HIGH |
| **Category** | Log Evasion |
| **MITRE ATT&CK** | T1070 -- Indicator Removal |

**Description**: throughGeneratelargeamountnormalrequestpaddinglog，makerealattackeventbyoverwhelminnoisein，increasesecurity Analyze师 troubleshootdifficultdegree。

**Prerequisites**:
- Objectiveapplicationcan bypublicaccess
- logsystemno智canfilteror聚combinemechanism

**Test Steps**:
1. Recordcurrentlogamountlevel：`wc -l /var/log/nginx/access.log`
2. Executenoiseinjection：`for i in $(seq 1 10000); do curl -s "http://target.com/api/health" > /dev/null 2>&1 &; done`
3. innoiseinExecuterealattack：`curl -s "http://target.com/search?q=1' UNION SELECT password FROM users--" > /dev/null 2>&1 &`
4. continuecontinuenoiseinjection：`for i in $(seq 1 10000); do curl -s "http://target.com/api/health" > /dev/null 2>&1 &; done`
5. Attemptinloginlocaterealattackitemtarget，Assesstroubleshootdifficultdegree

**Expected Results (through)**:
- SIEM automated Identifyandfilternoisemode
- abnormalDetectrulemark SQL injectionpayload
- alertsysteminnoiseinaccurateTrigger

**Expected Results (failure)**:
- attackpayloadcompleteoverwhelmin 20000 itemnormalrequestin
- manual troubleshootnomethodincombinereasonwhen intervalinnerlocateattack
- alertsystembynoiseoverwhelm，not Triggerany effectivealert

**Remediation**: Deploybaseatmode automated filter（ignorealready know 健康Checkendpoint）；UseabnormalDetectalternativesimplethresholdValuealert；realnowlog采sampleand聚combinemechanism。

---

## C. Monitoring Gaps

### TC-LM-005: Authentication Event Logging Coverage Verification

| Field | Value |
|------|-----|
| **Test ID** | TC-LM-005 |
| **Name** | Authentication Event Logging Coverage Verification |
| **Severity** | HIGH |
| **Category** | Monitoring Gaps |
| **OWASP** | A09:2021 |

**Description**: Verifyapplicationiswhethercomplete Recordall authenticationrelatedevent（loginsuccess/failure、passwordmodify、sessioncreate/destroy），Identifylogblindzone。

**Prerequisites**:
- Objectiveapplicationtoolhasauthenticationsuccesscan
- TestpersonnelcanTriggereachclassauthenticationevent

**Test Steps**:
1. Usecorrectcredentialslogin，ChecklogiswhetherRecord：successloginevent、user ID、source IP、User-Agent、when timestamp
2. Useerrorcredentialslogin，ChecklogiswhetherRecord：failureloginevent、Attempt username、source IP
3. Triggerpasswordmodifyoperation，ChecklogiswhetherRecord：passwordchangeevent、operationer、Objectiveuser（notRecordpasswordplaintextorhash）
4. Triggersessionoverperiod/注销，ChecklogiswhetherRecord：sessiondestroyevent
5. Usenoeffect Token accessaffectedprotectresource，CheckiswhetherRecord 401/403 event

**Expected Results (through)**:
- all authenticationeventallbycomplete Record
- eachitemRecordcontains：when timestamp、eventtype、user ID、source IP、User-Agent
- passwordFieldnotbyRecord（i.e.makeishashValue）

**Expected Results (failure)**:
- loginfailureeventnot byRecord
- missingsource IP or User-Agent
- passwordplaintextorhashoutputnowinlogin（overdegreeRecord）
- sessiondestroyeventnolog

**Remediation**: establishauthenticationevent logspecification，explicit必recordField；Useunified loginintervalpieceensureall authenticationendpointcovering。

---

### TC-LM-006: Sensitive Data Access Audit Verification

| Field | Value |
|------|-----|
| **Test ID** | TC-LM-006 |
| **Name** | Sensitive Data Access Audit Verification |
| **Severity** | HIGH |
| **Category** | Monitoring Gaps |
| **OWASP** | A09:2021 |

**Description**: Verifyforsensitivedata access（batchamountexport、veryrulequery、managementoperation）iswhetherbychargepartRecordandMonitor。

**Prerequisites**:
- applicationhandlingsensitivedata（personalinformation、财务data、健康Recordetc.）
- existsdataexportorbatchamountquerysuccesscan

**Test Steps**:
1. Executelargebatchamountdataquery：`curl "http://target.com/api/users?limit=100000"`
2. Triggerdataexportsuccesscan：`curl -O "http://target.com/api/export/all-users.csv"`
3. accessadmin backendExecuteConfigurechange
4. Use API Key accesssensitiveendpoint：`curl -H "Authorization: Bearer <api_key>" "http://target.com/api/sensitive"`
5. CheckloginiswhetherRecord withonall operationanddetailed information

**Expected Results (through)**:
- batchamountdataaccessTriggeraudit logand/oralert
- dataexportoperationbyRecord，with operationer、when interval、datascope
- managementoperationbysingleindependentRecordtosecurity auditlog
- API Key Usebyrelatedtotoolbodyidentity

**Expected Results (failure)**:
- batchamountdataexportnoany logRecord
- managementoperationandnormaloperation log混combine，nozonepart
- API Key Usenomethodrelatedtotoolbodyuser

**Remediation**: forsensitivedataaccessrealimplementspecialized门 audit log；setbatchamountdataaccess thresholdValuealert；managementoperation logsingleindependentstorageandstrengthenprotect。

---

### TC-LM-007: SIEM Collection Integrity Verification

| Field | Value |
|------|-----|
| **Test ID** | TC-LM-007 |
| **Name** | SIEM Collection Integrity Verification |
| **Severity** | MEDIUM |
| **Category** | Monitoring Gaps |
| **OWASP** | A09:2021 |

**Description**: Verify SIEM platformiswhethercomplete collect all logsource，andlogformatiswhetherstandardize，ensurerelatedAnalyze basic datacan 靠。

**Prerequisites**:
- SIEM platformalready Deploy
- multiplelogsource（Web、Auth、Database、System）shouldbycollect

**Test Steps**:
1. ineachsystemonGenerateTestlogevent
2. in SIEM inSearchthissomeTestevent，Confirmcollectdelayandintegrity
3. Checklogformatiswhetherunified（timestamp format、Field命name）
4. Verify correlation ID iswhetherineachlogsourceofintervaltransmit
5. Checkiswhetherexistsalready know not collectlogsource

**Expected Results (through)**:
- all logsourceeventin SIEM incan 查，delay < 5 part钟
- logformatunified，Field命nameconsistent
- Correlation ID crosssystemtransmit，supportsrelatedAnalyze

**Expected Results (failure)**:
- partiallogsourcenot by SIEM collect
- logformatnotunified，nomethodautomated Analyze
- missing correlation ID，nomethodcrosssystemrelated

**Remediation**: establishlogsourcechecklistandregularlyaudit；Use Logstash/Fluentd unifiedlogformat；realnow correlation ID endtoendtransmit。

---

## D. Detection Bypass

### TC-LM-008: Low-frequency Brute Force Bypass Time Window Detection

| Field | Value |
|------|-----|
| **Test ID** | TC-LM-008 |
| **Name** | Low-frequency Brute Force Bypass Time Window Detection |
| **Severity** | CRITICAL |
| **Category** | Detection Bypass |
| **MITRE ATT&CK** | T1110.003 -- Brute Force: Password Spraying |

**Description**: throughreducepasswordAttemptfrequencyrate（such as eachsmallwhen onlyAttemptatime），bypassbaseatfixedwhen time window brute forceDetectrule（such as "5 part钟inner 5 timefailure"）。

**Prerequisites**:
- ObjectiveapplicationUsebaseatwhen time window brute forceDetect
- DetectruleUsefixed thresholdValueandwindowparameter

**Test Steps**:
1. Confirmbrute forceDetectrule（such as 5 part钟windowinner 5 timefailure）
2. witheach 320 secondsatime frequencyrateAttemptlogin（略superDetectwindow）
3. continuousExecute 24 smallwhen （约 270 timeAttempt）
4. Check SIEM iswhetherTriggerany alert
5. Assessthefrequencyrateiswhethercancoveringcommon passwordlist

**Expected Results (through)**:
- DetectsystemUse滑dynamicwindow + behaviorbaseline，andnonfixedthresholdValue
- lengthwhen intervaldimensiondegree abnormalbehaviorbyDetect（such as 24 smallwhen inner 50+ timefailure）
- notheoryfrequencyratesuch as what，from singlea IP continuousfailureloginbymark

**Expected Results (failure)**:
- lowfrequencyattackcompletebypassfixedwindowDetect
- 24 smallwhen innernoany alertTrigger
- onlydependency短periodwindowthresholdValue，nolengthperiodbehaviorAnalyze

**Remediation**: UsemultipledimensiondegreeDetect：短periodwindow + lengthperiodbaseline + successrateAnalyze；Deploy UEBA Detect偏leavenormalbehavior mode。

---

### TC-LM-009: Attack Chain Time Fragmentation Bypass Correlation Detection

| Field | Value |
|------|-----|
| **Test ID** | TC-LM-009 |
| **Name** | Attack Chain Time Fragmentation Bypass Correlation Detection |
| **Severity** | HIGH |
| **Category** | Detection Bypass |
| **MITRE ATT&CK** | T1070.004 -- Indicator Removal: File Deletion (log rotation) |

**Description**: willatimecomplete attack拆partasmultiplecross天operation（reconnaissance Day 1、credentialsattack Day 2、privilege escalation Day 3、dataexfiltration Day 4），bypassbaseatwhen time window relatedDetect。

**Prerequisites**:
- SIEM Use短periodrelatedwindow（such as 1 smallwhen or 24 smallwhen ）
- attackercanpersistenceaccessObjectivesystem

**Test Steps**:
1. Day 1: Executeinformation gathering -- accessuserlistendpoint
2. Day 2: Attemptcredentialsattack -- Usecollectto informationAttemptlogin
3. Day 3: privilege escalation -- modifyroleorexploitvulnerabilityprivilege escalation
4. Day 4: dataexfiltration -- batchamountexportsensitivedata
5. in SIEM inCheckiswhethercanwill Day 1-4 eventrelatedassameaAttack Chain

**Expected Results (through)**:
- SIEM relatedrulecancross天tracesameaattacker
- Use session ID、correlation ID or IP relatedlengthperiodactivity
- UEBA Identifyoutputabnormalbehavior序column

**Expected Results (failure)**:
- each天 activitybyworkasindependenteventhandling
- relatedwindowover短，nomethodconnectcross天event
- nolengthperiodbehaviorbaseline，nomethodIdentifyabnormal序column

**Remediation**: realnowbaseatuser lengthperiodbehaviortrace；Use Kill Chain modetyperelatedmultiplephaseattack；延lengthrelatedDetectwindowto 7-30 天。

---

### TC-LM-010: Log Retention Policy Exploitation & Evidence Destruction

| Field | Value |
|------|-----|
| **Test ID** | TC-LM-010 |
| **Name** | Log Retention Policy Exploitation & Evidence Destruction |
| **Severity** | HIGH |
| **Category** | Detection Bypass |
| **MITRE ATT&CK** | T1070.004 -- Indicator Removal: File Deletion |

**Description**: exploitlogretainpolicy overperioddeletemechanism，etc.pendinginitialintrusionlogoverperiodafter再Executefollow-upoperation，makesecurity teamnomethodrebuildcomplete Attack Chain。

**Prerequisites**:
- logsystemConfigure retainperiod限（such as 30 天）
- attackertoolhaspersistenceaccesscanpower
- SIEM nono限periodarchivemechanism

**Test Steps**:
1. Confirmlogretainpolicy：Check `/etc/logrotate.d/` or SIEM retainConfigure
2. Simulate Day 1 initialintrusion（exploitvulnerabilityObtaininitial access）
3. Record此when Generate logitemtarget
4. Simulateetc.pendingexceedingretainperiod限
5. Day 31+: Executeprivilege escalationanddataexfiltration
6. Check SIEM iniswhether仍can retrieve Day 1 initialintrusionlog

**Expected Results (through)**:
- security criticaleventno限periodretainorarchiveto冷storage
- initialintrusionloginretainperiod限after仍can retrieve
- SIEM in alertRecordindependentatrawlogretain

**Expected Results (failure)**:
- all login 30 天afterbyautomated delete
- initialintrusionevidence丢失，nomethodandfollow-upoperationrelated
- alertRecordrandomloga起byclear

**Remediation**: security eventlogand运营logpart开retain，beforeerretainat least 1 年；SIEM alertRecordindependentarchive；realnownotcan changelogarchive（WORM storage）。
