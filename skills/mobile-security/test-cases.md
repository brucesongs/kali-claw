# Mobile Security Test Cases

> This file is a companion to `SKILL.md`, containing movedynamicsecurity Test structureizeTestuseexample。

---

## Statistics

| Category | Cases |
|------|--------|
| A. Static Analysis | 2 |
| B. Dynamic Analysis | 2 |
| C. Runtime Manipulation | 2 |
| D. Network Testing | 2 |
| E. Data Protection | 2 |
| **Total** | **10** |

---

## A. Static Analysis

### TC-MS-001: APK Manifest Security Audit

| Field | Value |
|------|-----|
| **ID** | TC-MS-001 |
| **Name** | APK Manifest Security Audit |
| **Severity** | HIGH |
| **Category** | staticAnalyze |
| **Prerequisites** | Objective APK file、apktool、jadx already install |
| **Test Steps** | 1. Use `apktool d app.apk -o app_source` decompilation APK<br>2. Check `AndroidManifest.xml` inwithbelowflag：<br>&nbsp;&nbsp;- `android:debuggable="true"`<br>&nbsp;&nbsp;- `android:allowBackup="true"`<br>&nbsp;&nbsp;- `android:usesCleartextTraffic="true"`<br>3. listall `exported="true"` component<br>4. Use `jadx` decompilationandSearchhardencodingcredentials<br>5. Recordall Discover dangerouspermission |
| **Expected Results** | Discoverat leasta Manifest Configuredefect（exportcomponent、debuggable、allowBackup orhardencodingcredentials） |
| **Remediation** | set `debuggable="false"`、`allowBackup="false"`、`usesCleartextTraffic="false"`；removenotnecessary exported component；willcredentials迁movetoserviceendorsecurity storage |
| **OWASP Reference** | MSTG-PLATFORM-1, MSTG-PLATFORM-2, MSTG-CODE-2 |

### TC-MS-002: Hardcoded Credential & Key Scanning

| Field | Value |
|------|-----|
| **ID** | TC-MS-002 |
| **Name** | Hardcoded Credential & Key Scanning |
| **Severity** | CRITICAL |
| **Category** | staticAnalyze |
| **Prerequisites** | jadx decompilationoutputdirectoryalready Generate |
| **Test Steps** | 1. Scan AWS Access Key: `grep -rn "AKIA[0-9A-Z]\{16\}" app_java/`<br>2. Scangeneralcredentials: `grep -rn "api_key\|secret\|password\|token" app_java/`<br>3. Scannotsecurity storage: `grep -rn "MODE_WORLD_READABLE"`<br>4. Scan Base64 encodingcredentials: `grep -rn "Base64.decode"`<br>5. Scan API URL andendpoint |
| **Expected Results** | Identifyoutputall hardencoding API Key、password、Token orprivate key |
| **Remediation** | willall credentials迁movetoenvironmentvariableorsecurity keymanagementservice；Use Android Keystore / iOS Keychain storagesensitivedata |
| **OWASP Reference** | MSTG-STORAGE-1, MSTG-CRYPTO-1 |

---

## B. Dynamic Analysis

### TC-MS-003: Exported Component Attack Surface Enumeration

| Field | Value |
|------|-----|
| **ID** | TC-MS-003 |
| **Name** | Exported Component Attack Surface Enumeration |
| **Severity** | HIGH |
| **Category** | dynamicAnalyze |
| **Prerequisites** | already installObjectiveapplication、drozer already connect、adb can use |
| **Test Steps** | 1. Run `drozer console connect`<br>2. Execute `run app.package.attacksurface com.target.app` Obtainattack surface<br>3. Enumerateexport Activity: `run app.activity.info -a com.target.app`<br>4. AttemptStarteachexport Activity: `run app.activity.start --component ...`<br>5. Test Content Provider dataleakage: `run app.provider.query content://...`<br>6. Test Broadcast Receiver: `run app.broadcast.send ...`<br>7. Use adb Test Deep Link: `adb shell "am start -a android.intent.action.VIEW -d 'scheme://path'"` |
| **Expected Results** | successaccessnot throughauthorization Activity、Extract Provider dataorTriggersensitivebroadcast |
| **Remediation** | removenotnecessary exported Attribute；forexportcomponentrealimplementpermissionchecksum；Verifyall Intent input |
| **OWASP Reference** | MSTG-PLATFORM-1, MSTG-PLATFORM-2 |

### TC-MS-004: Application Backup Extraction Test

| Field | Value |
|------|-----|
| **ID** | TC-MS-004 |
| **Name** | Application Backup Extraction Test |
| **Severity** | MEDIUM |
| **Category** | dynamicAnalyze |
| **Prerequisites** | adb already connect、Objectiveapplicationalready install、`allowBackup=true` |
| **Test Steps** | 1. Confirm Manifest in `android:allowBackup="true"`<br>2. Execute `adb backup -f app.ab com.target.app`<br>3. solvepackagebackup: `dd if=app.ab bs=24 skip=1 \| openssl zlib -d > app.tar`<br>4. ExtractContent: `tar xf app.tar`<br>5. CheckExtract SharedPreferences、databaseandfilein sensitivedata |
| **Expected Results** | successfrombackupinExtractcontainssensitiveinformation SharedPreferences and/ordatabasefile |
| **Remediation** | set `android:allowBackup="false"`；Use `android:fullBackupContent` excludesensitivefile；forcriticaldataenabledeviceencryption |
| **OWASP Reference** | MSTG-STORAGE-4 |

---

## C. Runtime Manipulation

### TC-MS-005: Frida Credential Interception Test

| Field | Value |
|------|-----|
| **ID** | TC-MS-005 |
| **Name** | Frida Credential Interception Test |
| **Severity** | CRITICAL |
| **Category** | Runwhen Manipulation |
| **Prerequisites** | already Root device、Frida Server Runin、Objectiveapplicationalready install |
| **Test Steps** | 1. write Frida Hook scriptinterceptloginmethod<br>2. Use `frida -U -f com.target.app -l hook.js --no-pause` Startapplication<br>3. inapplicationininputTestcredentialsandlogin<br>4. Verify Frida control台iswhetheroutputplaintextusernameandpassword<br>5. write Cipher.doFinal Hook interceptencryptiondataflow<br>6. VerifycanwhetherObtainencryptionbeforeplaintextandencryptionafterciphertext |
| **Expected Results** | successinRunwhen interceptlogincredentialsandencryptionbefore/after data |
| **Remediation** | realimplementantidebugDetect；Usesecurity communicationchanneltransmissioncredentials；inserviceendVerifyall security criticaloperation |
| **OWASP Reference** | MSTG-RESILIENCE-1, MSTG-CRYPTO-2 |

### TC-MS-006: Root Detection Bypass Test

| Field | Value |
|------|-----|
| **ID** | TC-MS-006 |
| **Name** | Root Detection Bypass Test |
| **Severity** | HIGH |
| **Category** | Runwhen Manipulation |
| **Prerequisites** | already Root device、Frida can use、Objectiveapplicationrealimplement Root Detect |
| **Test Steps** | 1. StartapplicationConfirm Root DetectTrigger（application退outputorwarning）<br>2. Use Frida Hook fileexistsityCheck（File.exists）<br>3. Hook common Root Detectpathreturn false<br>4. Use objection Root Detectbypass: `android root disable`<br>5. restartapplicationVerifybypasssuccess<br>6. Recordbypass所needwhen intervalanddifficultdegree |
| **Expected Results** | successbypass Root Detect，applicationin Root deviceonnormalRun |
| **Remediation** | multiplelayerDetectmechanism（fileCheck + systemtuneuse + environmentvariable）；serviceenddeviceintegritychecksum；SafetyNet/Play Integrity API |
| **OWASP Reference** | MSTG-RESILIENCE-1, MSTG-RESILIENCE-2 |

---

## D. Network Testing

### TC-MS-007: SSL Certificate Pinning Bypass

| Field | Value |
|------|-----|
| **ID** | TC-MS-007 |
| **Name** | SSL Certificate Pinning Bypass |
| **Severity** | CRITICAL |
| **Category** | networkTest |
| **Prerequisites** | already Root device、Frida/objection can use、Burp Suite already Configure |
| **Test Steps** | 1. Configuredeviceproxypoint to Burp Suite<br>2. Confirmapplicationbecause SSL Pinning nomethodnormalcommunication<br>3. Use Frida Hook OkHttp CertificatePinner.check makeits空operation<br>4. orUse Frida replace TrustManager asacceptall certificate realnow<br>5. orUse objection fast捷method: `android sslpinning disable`<br>6. Verify Burp Suite cansuccessintercept HTTPS flowamount |
| **Expected Results** | successbypass Certificate Pinning，Burp Suite capturecomplete HTTPS requestandresponse |
| **Remediation** | realimplementmultiplelayer Pinning（certificate + public key）；Pin internal CA certificate；enablecertificatetransparentityMonitor；combineserviceendDetect |
| **OWASP Reference** | MSTG-NETWORK-3, MSTG-NETWORK-4 |

### TC-MS-008: Network Traffic Sensitive Data Leak Detection

| Field | Value |
|------|-----|
| **ID** | TC-MS-008 |
| **Name** | Network Traffic Sensitive Data Leak Detection |
| **Severity** | HIGH |
| **Category** | networkTest |
| **Prerequisites** | SSL Pinning already bypass、proxyalready Configure、mitmproxy/Burp can use |
| **Test Steps** | 1. Configure mitmproxy or Burp Suite captureflowamount<br>2. traverseapplicationall mainsuccesscan（login、payment、setetc.）<br>3. Checkiswhetherexists HTTP plaintextcommunication<br>4. Checkrequest/responsein sensitivedata（password、Token、personalinformation）<br>5. Verify API authenticationmechanism（Token iswhetheroverperiod、iswhethercan replay）<br>6. Checkiswhetherhassensitivedatathrough URL parametertransmission |
| **Expected Results** | Discoverat leasta处sensitivedataincommunicationinnot encryptionorprotectnotenough |
| **Remediation** | allsite HTTPS；sensitivedataonlyinrequestbodytransmission；realimplement Token overperiodand刷newmechanism；API requestsignature |
| **OWASP Reference** | MSTG-NETWORK-1, MSTG-NETWORK-2 |

---

## E. Data Protection

### TC-MS-009: Local Storage Sensitive Data Detection

| Field | Value |
|------|-----|
| **ID** | TC-MS-009 |
| **Name** | Local Storage Sensitive Data Detection |
| **Severity** | CRITICAL |
| **Category** | dataprotect |
| **Prerequisites** | already Root device、adb can use、Objectiveapplicationalready Runandlogin |
| **Test Steps** | 1. Check SharedPreferences: `adb shell "su -c 'cat /data/data/com.target.app/shared_prefs/*.xml'"`<br>2. Extract SQLite database: `adb pull /data/data/com.target.app/databases/app.db`<br>3. querydatabaseContent: `sqlite3 app.db ".dump"`<br>4. Checkexternalstorage: `adb shell "ls -la /sdcard/Android/data/com.target.app/"`<br>5. Searchlogfilein sensitivedata<br>6. Recordall Discover plaintextsensitivedata（password、Token、personalinformation） |
| **Expected Results** | inlocalstorageinDiscoverat leasta处plaintextsensitivedata |
| **Remediation** | Use Android Keystore / iOS Keychain；encryptionall localsensitivedata；notwillsensitivedatawriteexternalstorage；clearlogin sensitiveinformation |
| **OWASP Reference** | MSTG-STORAGE-1, MSTG-STORAGE-2, MSTG-STORAGE-3 |

### TC-MS-010: iOS Keychain / Android Keystore Security Assessment

| Field | Value |
|------|-----|
| **ID** | TC-MS-010 |
| **Name** | iOS Keychain / Android Keystore Security Assessment |
| **Severity** | HIGH |
| **Category** | dataprotect |
| **Prerequisites** | already Root/越狱device、objection can use |
| **Test Steps** | 1. Use objection dump Keychain: `ios keychain dump`<br>2. Check Keychain itemtarget protectLevel（kSecAttrAccessible）<br>3. VerifysensitiveitemtargetiswhetherUse `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`<br>4. for Android，Check Keystore itemtargetiswhethercorrectUsehardpiecesupports<br>5. Use Frida Hook encryptionfunction，Verifydatainenter Keystore beforeiswhetherbyencryption<br>6. Checkiswhetherhassensitivedatabypass Keystore directstorage |
| **Expected Results** | Discover Keychain/Keystore Configurenotwhen（such as Useoverlow protectLevel）orsensitivedatanot throughsecurity storage |
| **Remediation** | UsehighestprotectLevel `WhenUnlockedThisDeviceOnly`；ensureall sensitivedatathrough Keystore/Keychain；enablehardpiecesecurity module |
| **OWASP Reference** | MSTG-STORAGE-1, MSTG-STORAGE-2, MSTG-CRYPTO-2 |
