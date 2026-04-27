# Password Attack Test Cases

> thisfileas `SKILL.md` Supplementary Files，providesstructureizeTestuseexampleandStatisticstable。

---

## A. Online Attacks / onlineattack

### TC-PA-001: SSH Online Dictionary Brute Force

| Field | Value |
|------|-----|
| **Test ID** | TC-PA-001 |
| **Category** | Online Attacks |
| **Severity** | Critical |
| **Objective** | Verify SSH serviceiswhethercan throughdictionary attackObtaineffectivecredentials |
| **Prerequisites** | Objective SSH servicecan reach; effectiveusernamedictionary; passworddictionaryfile |
| **Test Steps** | 1. Confirm SSH serviceversionandauthenticationmethod<br>2. Use hydra Executedictionary attack: `hydra -L users.txt -P passwords.txt ssh://target -t 4 -W 3`<br>3. Recordsuccesslogin credentialsfor<br>4. Verifycredentialseffectiveity |
| **Expected Results** | weakpasswordaccountbysuccessbrute force; strongpasswordaccountnot bycrack |
| **Mitigation** | realimplementpublic keyauthentication; disablepasswordlogin; Configure fail2ban; limitation SSH accesssource IP |

### TC-PA-002: HTTP POST Form Authentication Brute Force

| Field | Value |
|------|-----|
| **Test ID** | TC-PA-002 |
| **Category** | Online Attacks |
| **Severity** | High |
| **Objective** | Assess Web applicationloginformfordictionary attack 抵抗canpower |
| **Prerequisites** | Objective Web applicationloginpagecan reach; Identify formparameterandfailureflag |
| **Test Steps** | 1. Analyzeloginform，Identifyrequestparameterandresponsecharacteristic<br>2. Construct hydra command: `hydra -l admin -P passwords.txt target.com http-post-form "/login:user=^USER^&pass=^PASS^:F=incorrect"`<br>3. ExecuteattackandMonitorresponse<br>4. VerifyObtain credentials |
| **Expected Results** | common weakpasswordaccountbysuccessbrute force; Rate limiting or WAF shouldblocklargeamountAttempt |
| **Mitigation** | realimplement Rate Limiting; add CAPTCHA; Deploy WAF; Monitorabnormalloginbehavior; enable MFA |

### TC-PA-003: Multi-protocol Parallel Online Brute Force

| Field | Value |
|------|-----|
| **Test ID** | TC-PA-003 |
| **Category** | Online Attacks |
| **Severity** | High |
| **Objective** | Verify FTP/SMB/RDP etc.serviceforparallelbrute forceattack protectioncanpower |
| **Prerequisites** | multipleObjectiveservicecan reach; usernameandpassworddictionaryalready preparation |
| **Test Steps** | 1. EnumerateObjectiveopenserviceandport<br>2. for FTP Execute: `hydra -l admin -P passwords.txt ftp://target`<br>3. for SMB Execute: `medusa -h target -u admin -P passwords.txt -M smb`<br>4. for RDP Execute: `hydra -l administrator -P passwords.txt -t 1 -W 10 rdp://target`<br>5. summaryall servicesuccesscredentials |
| **Expected Results** | protection薄weak servicebysuccessbrute force; protectionimprove serviceblockattack |
| **Mitigation** | unifiedaccountlockoutpolicy; serviceintervalsharedfailure计number; realimplementnetworklayeraccesscontrol |

---

## B. Offline Cracking / offlinecrack

### TC-PA-004: NTLM Hash Dictionary + Rule Attack

| Field | Value |
|------|-----|
| **Test ID** | TC-PA-004 |
| **Category** | Offline Cracking |
| **Severity** | Critical |
| **Objective** | Assess Windows NTLM hashfordictionary+ruleattack 抵抗canpower |
| **Prerequisites** | already Extract NTLM hashfile; hashcat already installand GPU 驱dynamicnormal |
| **Test Steps** | 1. Confirmhashtype: `hashcat --identify hashes.txt`<br>2. basic dictionary attack: `hashcat -a 0 -m 1000 hashes.txt rockyou.txt`<br>3. ruleattack: `hashcat -a 0 -m 1000 hashes.txt rockyou.txt -r best64.rule`<br>4. deepdegreerule: `hashcat -a 0 -m 1000 hashes.txt rockyou.txt -r dive.rule`<br>5. Recordcrackrateand耗when |
| **Expected Results** | dictionarymatch weakpasswordbyquick crack; ruleattackcoveringcommon transformation |
| **Mitigation** | 迁moveto NTLMv2 or Kerberos; Use LAPS managementlocaladministratorpassword |

### TC-PA-005: bcrypt Hash Brute Force Time Assessment

| Field | Value |
|------|-----|
| **Test ID** | TC-PA-005 |
| **Category** | Offline Cracking |
| **Severity** | Medium |
| **Objective** | Assess bcrypt 慢hashalgorithmforofflinecrack when interval成this |
| **Prerequisites** | bcrypt hashfile (cost factor >= 10); hashcat already install |
| **Test Steps** | 1. Identify bcrypt hashand cost factor<br>2. dictionary attack: `hashcat -a 0 -m 3200 hashes.txt rockyou.txt`<br>3. ruleattack: `hashcat -a 0 -m 3200 hashes.txt rockyou.txt -r best64.rule`<br>4. Measure hash rate andestimatedcrackwhen interval<br>5. Compareidenticalpasswordin MD5 (mode 0) below crackspeeddegree |
| **Expected Results** | bcrypt crackspeeddegreesignificant慢at MD5/NTLM; high cost factor 进astepincreasewhen interval |
| **Mitigation** | Use bcrypt/argon2 alternative MD5/SHA; set cost factor >= 12 |

### TC-PA-006: Encrypted File Password Recovery

| Field | Value |
|------|-----|
| **Test ID** | TC-PA-006 |
| **Category** | Offline Cracking |
| **Severity** | High |
| **Objective** | Verifyencryptionfile (ZIP/Office/PDF/KeePass) passwordcan bycrack processdegree |
| **Prerequisites** | encryptionfilesamplethis; John the Ripper already install |
| **Test Steps** | 1. Extractfilehash: `zip2john protected.zip > hash.txt`<br>2. dictionary attack: `john --wordlist=rockyou.txt hash.txt`<br>3. viewresult: `john --show hash.txt`<br>4. for Office/PDF/KeePass repeatidenticalprocess<br>5. Recordeachclassfileformatcracksuccessrate |
| **Expected Results** | weakpasswordprotect filebysuccesscrack; strongencryptionalgorithmfilecrack耗when significantincrease |
| **Mitigation** | Use AES-256 encryption; setstrongpassword (>= 16 characters); UsespecializeduseencryptionTools |

---

## C. Wordlist & Mutation / dictionaryGenerateandtransformation

### TC-PA-007: Target-customized Wordlist Generation

| Field | Value |
|------|-----|
| **Test ID** | TC-PA-007 |
| **Category** | Wordlist & Mutation |
| **Severity** | Medium |
| **Objective** | VerifybaseatObjectiveinformationGenerate customizedictionarycanwhethereffectiveextracthighpassword命inrate |
| **Prerequisites** | Objectivewebsitecan reach; Objectiveorganizationpublicinformationalready collect |
| **Test Steps** | 1. Use cewl crawlObjectivewebsite: `cewl https://target.com -d 2 -m 4 -w words.txt`<br>2. Use crunch Generatemodedictionary: `crunch 6 8 -t Company@%%% -o pattern.txt`<br>3. mergededuplicate: `cat words.txt pattern.txt rockyou.txt \| sort -u > final.txt`<br>4. Usemost终dictionaryExecute hashcat attack<br>5. Compare rockyou.txt andcustomizedictionary crackrate |
| **Expected Results** | customizedictionaryforObjectiverelatedpassword命inratesignificanthighatgeneraldictionary |
| **Mitigation** | avoidinpasswordinUsecompanyname/productnameetc.publicinformation |

### TC-PA-008: Rule Engine Mutation Efficiency Assessment

| Field | Value |
|------|-----|
| **Test ID** | TC-PA-008 |
| **Category** | Wordlist & Mutation |
| **Severity** | Medium |
| **Objective** | Assessnotsamerulesetforpasswordcoveringrate enhanceeffectresult |
| **Prerequisites** | basic dictionaryfile; hashcat rulefilealready install |
| **Test Steps** | 1. base准Test: puredictionary attacknorule<br>2. best64 ruleattack: `hashcat -a 0 -m 1000 hashes.txt dict.txt -r best64.rule`<br>3. dive ruleattack: `hashcat -a 0 -m 1000 hashes.txt dict.txt -r dive.rule`<br>4. Recordeachkindrule hash rate andcrackrate<br>5. calculatewhen interval/crackrate itypricethan |
| **Expected Results** | best64 providesbestitypricethan; dive coveringmore广but耗when morelength |
| **Mitigation** | realimplementpasswordcomplexdegreepolicymakeruletransformationdifficultwithcovering |

---

## D. Advanced Techniques / advanced technique

### TC-PA-009: Password Spraying Attack Assessment

| Field | Value |
|------|-----|
| **Test ID** | TC-PA-009 |
| **Category** | Advanced Techniques |
| **Severity** | Critical |
| **Objective** | Assessorganizationforpasswordsprayattack Detectanddefensecanpower |
| **Prerequisites** | Objectivedomainuserlistalready Obtain; passwordspraylistalready preparation |
| **Test Steps** | 1. collectObjectivedomainuserlist<br>2. preparationspraypasswordlist (季sectionitypassword、common mode)<br>3. Use kerbrute Execute: `kerbrute passwordspray -d domain.local --dc dc_ip users.txt "Spring2026!"`<br>4. controlsprayinterval隔avoidlockout (each轮interval隔 > lockoutObservewindow)<br>5. Recordsuccessaccountandresponsewhen interval |
| **Expected Results** | Use季sectionity/common password accountbysuccessspray; Detectsystemshouldalertabnormalloginmode |
| **Mitigation** | realimplement Azure AD passwordprotect; Deploy anomalous login detection; MonitorsameapasswordmultipleaccountAttempt |

### TC-PA-010: NTLM Relay Attack Chain

| Field | Value |
|------|-----|
| **Test ID** | TC-PA-010 |
| **Category** | Advanced Techniques |
| **Severity** | Critical |
| **Objective** | Verify NTLM authenticationincontinueattack can rowityandimpactscope |
| **Prerequisites** | internal networkaccesspermission; ObjectivenetworkUse NTLM authentication |
| **Test Steps** | 1. Start ntlmrelayx: `ntlmrelayx.py -t smb://target -smb2support`<br>2. Use Responder captureauthentication: `responder -I eth0 -wrf`<br>3. Triggerauthenticationrequest (NBNS spoofing/LLMNR poisoning)<br>4. incontinuetoObjectiveserviceObtainaccesspermission<br>5. VerifyObtain permissionLevel |
| **Expected Results** | NTLM authenticationbysuccessincontinue; ObtainObjectiveserviceaccesspermission |
| **Mitigation** | enable SMB signature; disable NTLM; enable LDAP signature; Deploy EDR Detect LLMNR/NBT-NS poisoning |

### TC-PA-011: Password Policy Bypass Assessment

| Field | Value |
|------|-----|
| **Test ID** | TC-PA-011 |
| **Category** | Advanced Techniques |
| **Severity** | High |
| **Objective** | AssessObjectivepasswordpolicy effectiveityandcan bypassity |
| **Prerequisites** | already Obtainpasswordpolicyinformation; already Extracthashsamplethis |
| **Test Steps** | 1. Enumeratepasswordpolicy: `crackmapexec smb target --pass-pol`<br>2. Analyzepolicyparameter (lengthdegree、complexdegree、history、lockout)<br>3. based onpolicyGeneratetargetingforitydictionary (such as minimumlengthdegree 8 + complexdegreerequirement)<br>4. AssesslockoutthresholdValueiswhetherallows慢speedspray<br>5. AttemptUsecharactercombinepolicybutcan predict modepassword |
| **Expected Results** | weakpolicy (短password、lowcomplexdegree、highlockoutthresholdValue) byeffectiveexploit |
| **Mitigation** | minimumlengthdegree >= 12; forcecomplexdegree; lockoutthresholdValue <= 5; enablepasswordleakageDetect |

### TC-PA-012: Credential Stuffing Cross-service Test

| Field | Value |
|------|-----|
| **Test ID** | TC-PA-012 |
| **Category** | Advanced Techniques |
| **Severity** | Critical |
| **Objective** | Verifyalready Obtain credentialsinitsotherserviceon complexusesituation |
| **Prerequisites** | already fromsomeserviceObtaineffectivecredentialsfor; multipleObjectiveservicecan reach |
| **Test Steps** | 1. entirereasonalready Obtain credentialsforlist<br>2. for SSH serviceTest: `hydra -C creds.txt ssh://target`<br>3. for SMB serviceTest: `crackmapexec smb target -u users.txt -p passwords.txt --no-bruteforce`<br>4. for Web applicationTestcredentials<br>5. Statisticscrossservicecredentialscomplexuserate |
| **Expected Results** | usercrossservicecomplexusepasswordcausecredentialspaddingsuccess |
| **Mitigation** | realimplement唯a eachservicepasswordpolicy; enable MFA; Monitorabnormalsourcelogin; for接 HIBP leakageDetect |

---

## Test Statistics

| Statisticsitem | numberValue |
|--------|------|
| **Total Test Cases** | 12 |
| **Critical** | 4 |
| **High** | 4 |
| **Medium** | 3 |
| **Categories Covered** | 4 |
| **Tools Covered** | hashcat, john, hydra, medusa, kerbrute, crackmapexec, ntlmrelayx, responder, cewl, crunch |

### byCategoryStatistics

| Category | Cases | IDs |
|------|--------|------|
| A. Online Attacks | 3 | TC-PA-001, TC-PA-002, TC-PA-003 |
| B. Offline Cracking | 3 | TC-PA-004, TC-PA-005, TC-PA-006 |
| C. Wordlist & Mutation | 2 | TC-PA-007, TC-PA-008 |
| D. Advanced Techniques | 4 | TC-PA-009, TC-PA-010, TC-PA-011, TC-PA-012 |
