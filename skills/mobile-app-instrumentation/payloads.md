# Mobile App Instrumentation — Payloads

> Companion to `SKILL.md`. 18 sections, 60+ working code blocks: Frida JS, Objection CLI, r2frida, shell.
> All commands assume authorized scope — signed engagement, owned device, or lab.
> iOS targets: iOS 16/17/18 on jailbroken device (palera1n / Dopamine). Android: 13/14/15 with Magisk root.

---

## 1. Environment Setup

### 1.1 Install Frida toolchain on host

```bash
# Host (Linux/macOS) — Python 3.11+ required
python3 -m venv ~/frida-venv && source ~/frida-venv/bin/activate
pip install --upgrade pip
pip install frida frida-tools objection

# Verify
frida --version          # expect 16.x or 17.x
objection version        # expect 1.11.x
frida-ps -U              # should list iOS/Android processes once device plugged in
```

### 1.2 Deploy frida-server on Android

```bash
# Match frida-server version to the frida client version on host
FRIDA_VER=$(frida --version)
wget https://github.com/frida/frida/releases/download/${FRIDA_VER}/frida-server-${FRIDA_VER}-android-arm64.xz
unxz frida-server-${FRIDA_VER}-android-arm64.xz
adb root
adb push frida-server-${FRIDA_VER}-android-arm64 /data/local/tmp/frida-server
adb shell "chmod 755 /data/local/tmp/frida-server"

# Start in background (root needed)
adb shell "su -c '/data/local/tmp/frida-server &'"

# Verify from host
frida-ps -U | head
```

### 1.3 Deploy frida-server on jailbroken iOS (palera1n / Dopamine)

```bash
# After jailbreak (palera1n for A7-A11 checkm8, Dopamine for A12+ arm64e)
# SSH into device and install via Sileo / Zebra:
ssh root@iphone.local "echo 'deb https://build.frida.re ./' > /etc/apt/sources.list.d/frida.list"
ssh root@iphone.local "apt-get update && apt-get install -y re.frida.server"
ssh root@iphone.local "re.frida.server &"   # or use launchctl

# Verify
frida-ps -U | head
```

### 1.4 Magisk + Zygisk for Android runtime hiding (Android 14/15)

```bash
# In Magisk app:
# Settings → Zygisk → Enable
# Configure → DenyList → add target app package name (e.g., com.example.app)
# Optional: install LSPosed (Zygisk module) for finer hook control

# Verify the target is in DenyList
adb shell "su -c 'magisk --denylist ls'"
```

---

## 2. iOS App Acquisition

### 2.1 List installed apps and bundle IDs

```bash
# Through frida-ps
frida-ps -Uai | grep -i example

# Through SSH on jailbroken device
ssh root@iphone.local "cd /var/containers/Bundle/Application/ && find . -name 'Info.plist' -exec plutil -p {} \; | grep -E 'CFBundleIdentifier|CFBundleExecutable'"
```

### 2.2 Decrypt IPA with Clutch

```bash
# On jailbroken iOS device (SSH)
ssh root@iphone.local "Clutch -i"           # interactive picker
ssh root@iphone.local "Clutch -d com.example.app"
# Output: /var/containers/Bundle/Application/<UUID>/Example.app  (decrypted)
# Pull to host
scp -r root@iphone.local:/var/containers/Bundle/Application/<UUID>/Example.app ./decrypted/
```

### 2.3 Decrypt with iPAA

```bash
# Interactive on device — produces a decrypted .app bundle and IPA
ssh root@iphone.local "iPAA"
# (select target app in TUI → export)
scp root@iphone.local:/var/mobile/Documents/Payload ./payload/
```

### 2.4 Class-dump + jtool2 triage on decrypted binary

```bash
# Extract Objective-C class list
jtool2 -objc ./decrypted/Example.app/Example > classes.txt
grep -iE 'login|auth|pin|trust|crypto' classes.txt

# Dump entitlements
jtool2 --ent ./decrypted/Example.app/Example

# Mach-O segments
jtool2 -L ./decrypted/Example.app/Example
```

---

## 3. Android App Acquisition

### 3.1 Locate APK on device

```bash
# Resolve path of base + split APKs
adb shell pm path com.example.app
# output:
# package:/data/app/~~xyz==/com.example.app-abc==/base.apk
# package:/data/app/~~xyz==/com.example.app-abc==/split_config.arm64_v8a.apk
# package:/data/app/~~xyz==/com.example.app-abc==/split_config.xxhdpi.apk

# Pull each
adb pull /data/app/~~xyz==/com.example.app-abc==/base.apk ./base.apk
adb pull /data/app/~~xyz==/com.example.app-abc==/split_config.arm64_v8a.apk ./split_arm64.apk
```

### 3.2 Decode APK with apktool

```bash
apktool d base.apk -o decoded/
cat decoded/AndroidManifest.xml | grep -E 'debuggable|networkSecurityConfig|usesCleartextTraffic'
ls decoded/lib/arm64-v8a/   # native libs (.so)
```

### 3.3 Decompile DEX with jadx

```bash
# Multidex-aware decompile
jadx -d out_jadx/ --show-bad-code base.apk split_arm64.apk

# Search for high-value targets
grep -rE 'CertificatePinner|X509TrustManager|SSLContext' out_jadx/sources/ | head
grep -rE 'RootBeer|/system/bin/su|debuggable' out_jadx/sources/ | head
grep -rE 'Cipher\.getInstance|MessageDigest\.getInstance' out_jadx/sources/ | head
```

### 3.4 frida-dexdump for packed apps

```bash
# For Bangcle / Jiagu / DEX-protected apps, dump DEX from memory at runtime
pip install frida-dexdump
frida-dexdump -U -f com.example.app -o dumped_dex/

# Then decompile the dumped DEX
jadx -d out_packed/ dumped_dex/*.dex
```

---

## 4. Static Triage

### 4.1 iOS — identify pinning + crypto symbols

```bash
# Strings + ObjC class grep on decrypted binary
strings -a Example | grep -iE 'pin|trustkit|certif|fingerprint' | sort -u

# List native libraries and exports
jtool2 -L Example | grep dylib
for lib in Example.app/Frameworks/*.dylib; do
  echo "=== $lib ==="
  jtool2 -objc "$lib" | head -40
done
```

### 4.2 Android — identify JNI exports

```bash
# After apktool d + jadx — locate native lib
NATIVE=$(find decoded/lib -name 'libNative.so' | head -1)

# r2 static analysis
r2 -A -q -c 'afl' "$NATIVE" | grep -i 'Java_'

# Or via nm (if symbols not stripped)
nm -D --defined-only "$NATIVE" | grep Java_
```

### 4.3 Identify jailbreak/root detection strings

```bash
# iOS
strings -a Example | grep -iE 'cydia|/bin/bash|/bin/sh|sshrunner|apt|substrate|frida|inject|dyld' | sort -u

# Android
grep -rEi 'cydia|/system/bin/su|magisk|/sbin/.magisk|supersu|rootbeer|busybox' out_jadx/sources/ | head
```

---

## 5. Frida Basics

### 5.1 List processes (USB device)

```bash
frida-ps -U          # running processes
frida-ps -Uai        # installed apps (bundle id + name + pid)
frida-ps -Ua         # running apps only
```

### 5.2 Spawn-and-attach with a hook script

```bash
# Spawn the app paused, inject script, then resume
frida -U -f com.example.app -l hook.js --no-pause

# Attach to a running process by name
frida -U -n "Example" -l hook.js

# Attach by PID
frida -U -p 1234 -l hook.js
```

### 5.3 frida-trace — high-level tracing

```bash
# Trace every CC_* call on iOS
frida-trace -U -i "CC_*" -f com.example.app

# Trace every open* on Android
frida-trace -U -i "open*" -f com.example.app

# Trace a specific Java method (by pattern)
frida-trace -U -j 'com.example.*!*/login*' -f com.example.app
```

---

## 6. Frida Hooking Patterns

### 6.1 Hook a Java method (Android)

```javascript
// hook_login.js
Java.perform(function () {
  var Login = Java.use('com.example.auth.LoginManager');
  // overload selection if multiple signatures exist
  Login.login.overload('java.lang.String', 'java.lang.String').implementation = function (user, pass) {
    console.log('[+] LoginManager.login(' + user + ', ' + pass + ')');
    var ret = this.login(user, pass);
    console.log('[+] return = ' + ret);
    return ret;
  };
});
```

### 6.2 Hook an Objective-C method (iOS)

```javascript
// hook_objc.js
if (ObjC.available) {
  var Login = ObjC.classes.LoginManager;
  // Replace '- loginWithUser:password:' (selector)
  Interceptor.attach(Login['- loginWithUser:password:'].implementation, {
    onEnter: function (args) {
      // args[0]=self, args[1]=selector, args[2]=first objc arg, ...
      console.log('[+] loginWithUser: ' + ObjC.Object(args[2]).toString());
    },
    onLeave: function (retval) {
      console.log('[+] return = ' + retval);
    }
  });
}
```

### 6.3 Hook a native export

```javascript
// hook_native.js
var openPtr = Module.getGlobalExportByName( 'open');
if (openPtr) {
  Interceptor.attach(openPtr, {
    onEnter: function (args) {
      var path = Memory.readUtf8String(args[0]);
      console.log('[open] path=' + path);
    }
  });
}
```

### 6.4 Replace a function entirely (NativeCallback)

```javascript
var ptrace = Module.getGlobalExportByName( 'ptrace');
Interceptor.replace(ptrace, new NativeCallback(function (req, pid, addr, data) {
  console.log('[ptrace] spoofing return 0 (allow attach)');
  return 0;
}, 'long', ['int', 'int', 'pointer', 'pointer']));
```

---

## 7. Objection Runtime Exploration

### 7.1 Launch the REPL

```bash
# Spawn target under objection
objection -g com.example.app explore

# Attach to running process instead
objection -g com.example.app explore --startup-command "android hooking list classes"
```

### 7.2 Key commands

```text
android hooking list classes
android hooking search classes keyword
android hooking list activities
android hooking list services
android hooking watch class_method com.example.LoginManager.login --dump-args --dump-return --dump-backtrace

ios hooking list classes
ios hooking search classes keyword
ios hooking watch class_method '-[LoginManager loginWithUser:password:]'
```

### 7.3 Disable common gates

```text
android sslpinning disable
ios     sslpinning disable
android root disable
ios     jailbreak disable
android biometric disable
ios     pasteboard monitor
android heap execute com.example.auth.TokenStore getAccessToken
```

---

## 8. SSL Pinning Bypass

### 8.1 Objection one-liner

```bash
objection -g com.example.app explore --startup-command "android sslpinning disable"
# Then in REPL:
# android sslpinning disable  (repeat after app restarts)
```

### 8.2 Frida script — Android OkHttp pinning

```javascript
// bypass_okhttp_pin.js
Java.perform(function () {
  try {
    var Pinner = Java.use('okhttp3.CertificatePinner');
    Pinner.check.overload('java.lang.String', 'java.util.List').implementation = function () {
      console.log('[+] OkHttp pin check() bypassed');
    };
    Pinner['check$okhttp'].implementation = function () {
      console.log('[+] OkHttp check$okhttp bypassed');
    };
  } catch (e) {
    console.log('[-] OkHttp pinning hook failed: ' + e);
  }
});
```

### 8.3 Frida script — Android TrustManager (generic)

```javascript
// bypass_trustmgr.js
Java.perform(function () {
  var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
  var SSLContext = Java.use('javax.net.ssl.SSLContext');
  var TrustAll = Java.registerClass({
    name: 'org.kali.TrustAll',
    implements: [X509TrustManager],
    methods: {
      checkClientTrusted: function () {},
      checkServerTrusted: function () {},
      getAcceptedIssuers: function () { return []; }
    }
  });
  SSLContext.init.overload(
    '[Ljavax.net.ssl.KeyManager;',
    '[Ljavax.net.ssl.TrustManager;',
    'java.security.SecureRandom'
  ).implementation = function (km, tm, sr) {
    console.log('[+] SSLContext.init hijacked');
    this.init(km, [TrustAll.$new()], sr);
  };
});
```

### 8.4 Frida script — iOS SecTrustEvaluate

```javascript
// bypass_ios_trust.js
var SecTrustEvaluate = Module.findExportByName('Security', 'SecTrustEvaluate');
var SecTrustEvaluateWithError = Module.findExportByName('Security', 'SecTrustEvaluateWithError');

if (SecTrustEvaluateWithError) {
  // iOS 13+
  Interceptor.replace(SecTrustEvaluateWithError, new NativeCallback(function (trust, error) {
    console.log('[+] SecTrustEvaluateWithError forced true');
    return 1; // true = trusted
  }, 'bool', ['pointer', 'pointer']));
} else if (SecTrustEvaluate) {
  Interceptor.replace(SecTrustEvaluate, new NativeCallback(function (trust, result) {
    Memory.writePointer(result, ptr(1)); // kSecTrustResultProceed
    console.log('[+] SecTrustEvaluate forced proceed');
    return 0;
  }, 'int', ['pointer', 'pointer']));
}
```

### 8.5 Network Security Config bypass (Android 7+)

```xml
<!-- network_security_config.xml (repackaging approach; for runtime, hook NetworkSecurityConfig TrustManager) -->
<network-security-config>
  <base-config cleartextTrafficPermitted="true">
    <trust-anchors>
      <certificates src="system" />
      <certificates src="user" />   <!-- added; was missing -->
    </trust-anchors>
  </base-config>
</network-security-config>
```

```bash
# Repackage with the modified config
apktool d base.apk -o decoded/
cp network_security_config.xml decoded/res/xml/
# Patch AndroidManifest.xml to reference @xml/network_security_config
apktool b decoded/ -o patched.apk
# Re-sign
apksigner sign --ks REPLACE_WITH_YOUR_KEYSTORE.jks patched.apk
adb install patched.apk
```

---

## 9. Jailbreak / Root Detection Bypass

### 9.1 Common iOS detection signatures

```javascript
// ios_jailbreak_bypass.js
var paths = [
  '/Applications/Cydia.app', '/Library/MobileSubstrate/MobileSubstrate.dylib',
  '/bin/bash', '/usr/sbin/sshd', '/etc/apt', '/usr/bin/ssh',
  '/private/var/lib/apt', '/Applications/Sileo.app', '/Applications/Zebra.app'
];

// Hook fopen / open / access / stat
['fopen', 'open', 'access', 'stat', 'stat64', 'lstat', 'lstat64'].forEach(function (sym) {
  var p = Module.getGlobalExportByName( sym);
  if (p) Interceptor.attach(p, {
    onEnter: function (args) {
      try {
        var path = Memory.readUtf8String(args[0]);
        if (paths.some(function (b) { return path && path.indexOf(b) !== -1; })) {
          console.log('[jb-bypass] hiding ' + path);
          this.shouldLie = true;
          args[0] = Memory.allocUtf8String('/this/path/does/not/exist');
        }
      } catch (e) {}
    }
  });
});

// Hook fork — apps use fork()!=-1 to detect jailbreak
var fork = Module.getGlobalExportByName( 'fork');
Interceptor.replace(fork, new NativeCallback(function () {
  console.log('[jb-bypass] fork() spoofed to -1');
  return -1;
}, 'int', []));

// Hook sysctl for P_TRACED check
var sysctl = Module.getGlobalExportByName( 'sysctl');
Interceptor.attach(sysctl, {
  onLeave: function (retval) {
    try {
      var kinfo = this.context; // not portable; use args[1] buf write
    } catch (e) {}
  }
});
```

### 9.2 Common Android root detection signatures

```javascript
// android_root_bypass.js
Java.perform(function () {
  // File.exists() override
  var File = Java.use('java.io.File');
  File.exists.implementation = function () {
    var p = this.getAbsolutePath();
    if (/su$|magisk|busybox|\/system\/xbin|\/sbin\/\.magisk|supersu/i.test(p)) {
      console.log('[root-bypass] File.exists() ' + p + ' → false');
      return false;
    }
    return this.exists();
  };

  // Runtime.exec("su")
  var Runtime = Java.use('java.lang.Runtime');
  var execStr = Runtime.exec.overload('java.lang.String');
  execStr.implementation = function (cmd) {
    if (cmd === 'su' || cmd.indexOf('su') === 0) {
      console.log('[root-bypass] Runtime.exec(' + cmd + ') blocked');
      throw Java.use('java.io.IOException').$new('Permission denied');
    }
    return execStr.call(this, cmd);
  };

  // PackageManager.getPackageInfo("eu.chainfire.supersu", ...)
  var PM = Java.use('android.app.ApplicationPackageManager');
  PM.getPackageInfo.overload('java.lang.String', 'int').implementation = function (name, flags) {
    if (/supersu|magisk|chainfire|superuser|busybox|koushik/i.test(name)) {
      console.log('[root-bypass] getPackageInfo(' + name + ') → NameNotFoundException');
      throw Java.use('android.content.pm.PackageManager$NameNotFoundException').$new(name);
    }
    return this.getPackageInfo(name, flags);
  };
});
```

### 9.3 RootBeer library bypass

```javascript
// bypass_rootbeer.js
Java.perform(function () {
  var RootBeer = Java.use('com.scottyab.rootcheck.RootBeer');
  ['isRooted', 'isRootedWithoutBusyBoxCheck', 'detectRootManagementApps',
   'detectPotentiallyDangerousApps', 'detectTestKeys', 'checkForBusyBoxBinary',
   'checkForSuBinary', 'checkSuExists', 'checkForRWPaths', 'checkForRootNative',
   'detectDangerousApps'].forEach(function (m) {
    if (RootBeer[m]) {
      RootBeer[m].implementation = function () {
        console.log('[rootbeer] ' + m + '() → false');
        return false;
      };
    }
  });
});
```

---

## 10. Anti-Debug Bypass

### 10.1 iOS — ptrace(PT_DENY_ATTACH)

```javascript
// bypass_ptrace.js
var ptrace = Module.getGlobalExportByName( 'ptrace');
Interceptor.replace(ptrace, new NativeCallback(function (req, pid, addr, data) {
  console.log('[anti-debug] ptrace(' + req + ') spoofed to 0');
  return 0;
}, 'long', ['int', 'int', 'pointer', 'pointer']));

// Hook sysctl to clear P_TRACED
var sysctl = Module.getGlobalExportByName( 'sysctl');
Interceptor.attach(sysctl, {
  onEnter: function (args) {
    this.oldp = args[2]; // old (output) buffer
  },
  onLeave: function (retval) {
    if (this.oldp && !this.oldp.isNull()) {
      // kinfo_proc.kp_proc.p_flag is at offset 0x20 on most iOS arm64; clear bit 0x800 (P_TRACED)
      try {
        var pFlag = this.oldp.add(0x20);
        var flags = Memory.readU32(pFlag);
        Memory.writeU32(pFlag, flags & ~0x800);
        console.log('[anti-debug] cleared P_TRACED');
      } catch (e) {}
    }
  }
});
```

### 10.2 Android — TracerPid check

```javascript
// bypass_tracerpid.js
var fopen = Module.getGlobalExportByName( 'fopen');
var fgets = Module.getGlobalExportByName( 'fgets');

Interceptor.attach(fopen, {
  onEnter: function (args) {
    var path = Memory.readUtf8String(args[0]);
    if (path && path.indexOf('/proc/self/status') !== -1) {
      console.log('[anti-debug] fopen(/proc/self/status) hooked');
      this.isStatus = true;
    }
  }
});

Interceptor.attach(fgets, {
  onEnter: function (args) {
    this.buf = args[0];
  },
  onLeave: function (retval) {
    if (retval && !retval.isNull()) {
      try {
        var line = Memory.readUtf8String(retval);
        if (line && line.indexOf('TracerPid:') !== -1) {
          var fake = 'TracerPid:\t0\n';
          Memory.writeUtf8String(this.buf, fake);
          console.log('[anti-debug] TracerPid → 0');
        }
      } catch (e) {}
    }
  }
});
```

### 10.3 Bypass debug-trace Frida detection

```javascript
// Apps may scan /proc/self/maps for 'frida-agent' / 'gum-js-loop'
var fopen = Module.getGlobalExportByName( 'fopen');
Interceptor.attach(fopen, {
  onEnter: function (args) {
    try {
      var path = Memory.readUtf8String(args[0]);
      if (path && path.indexOf('/proc/') !== -1 && path.indexOf('maps') !== -1) {
        this.isMaps = true;
        console.log('[anti-frida] fopen(maps) detected — will scrub frida lines');
      }
    } catch (e) {}
  }
});

// Scrub 'frida' / 'gum' / 'linjector' lines from fgets return
var fgets = Module.getGlobalExportByName( 'fgets');
Interceptor.attach(fgets, {
  onLeave: function (retval) {
    if (retval && !retval.isNull()) {
      try {
        var line = Memory.readUtf8String(retval);
        if (line && /frida|gum-js|linjector|pool-frida/i.test(line)) {
          Memory.writeUtf8String(retval, '00000000-00000000 ---p 00000000 00:00 0\n');
        }
      } catch (e) {}
    }
  }
});
```

---

## 11. iOS Keychain Dump

### 11.1 Objection dump

```bash
objection -g com.example.app explore --startup-command "ios keychain dump"
# Dumps all keychain items accessible to the app's keychain-access-groups.
# Filter for tokens:
# ios keychain dump | grep -E 'refresh_token|access_token|bearer'
```

### 11.2 keychain-dumper (device-side)

```bash
# On jailbroken device
ssh root@iphone.local "keychain-dumper -a > /tmp/keychain.txt"
scp root@iphone.local:/tmp/keychain.txt ./keychain.txt

# Inspect
grep -iE 'oauth|refresh|bearer|mfa' keychain.txt
```

### 11.3 Frida — extract SecItemCopyMatching results

```javascript
// hook_secitem.js
var SecItemCopyMatching = Module.findExportByName('Security', 'SecItemCopyMatching');
Interceptor.attach(SecItemCopyMatching, {
  onEnter: function (args) {
    this.query = args[0];
    this.result = args[1];
  },
  onLeave: function (retval) {
    if (retval.equals(0)) {
      var arr = new ObjC.Object(Memory.readPointer(this.result));
      console.log('[SecItem] count=' + arr.count());
      for (var i = 0; i < arr.count(); i++) {
        console.log('  ' + i + ': ' + arr.objectAtIndex_(i).toString());
      }
    }
  }
});
```

---

## 12. Android Keystore Manipulation

### 12.1 List Keystore entries (Objection)

```bash
objection -g com.example.app explore --startup-command "android keystore list"
```

### 12.2 Hook Keystore + Cipher (Android)

```javascript
// trace_keystore.js
Java.perform(function () {
  var KeyStore = Java.use('java.security.KeyStore');
  KeyStore.getEntry.overload('java.lang.String', 'java.security.KeyStore$ProtectionParameter').implementation = function (alias, prot) {
    var entry = this.getEntry(alias, prot);
    console.log('[KeyStore.getEntry] alias=' + alias + ' entry=' + entry);
    return entry;
  };

  var Cipher = Java.use('javax.crypto.Cipher');
  Cipher.init.overload('int', 'java.security.Key').implementation = function (mode, key) {
    var algo = this.getAlgorithm();
    try {
      var enc = key.getEncoded();
      console.log('[Cipher.init] algo=' + algo + ' mode=' + mode + ' key=' + (enc ? bytesToHex(enc) : 'null'));
    } catch (e) {
      console.log('[Cipher.init] algo=' + algo + ' key=<opaque>');
    }
    return this.init(mode, key);
  };

  Cipher.doFinal.overload('[B').implementation = function (input) {
    var out = this.doFinal(input);
    console.log('[Cipher.doFinal] in=' + bytesToHex(input) + ' out=' + bytesToHex(out));
    return out;
  };

  function bytesToHex(arr) {
    var s = '';
    for (var i = 0; i < arr.length; i++) s += ('0' + (arr[i] & 0xff).toString(16)).slice(-2);
    return s;
  }
});
```

### 12.3 Biometric bypass

```javascript
// bypass_biometric.js
Java.perform(function () {
  var BiometricPrompt = Java.use('android.hardware.biometrics.BiometricPrompt');

  BiometricPrompt.authenticate.overload(
    'android.hardware.biometrics.BiometricPrompt$CryptoObject',
    'android.os.CancellationSignal',
    'java.util.concurrent.Executor',
    'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback'
  ).implementation = function (crypto, cancel, exec, cb) {
    console.log('[biometric] hijacking authenticate');
    var AuthResult = Java.use('android.hardware.biometrics.BiometricPrompt$AuthenticationResult');
    // Force onAuthenticationSucceeded with a synthetic AuthenticationResult
    var cbProxy = Java.registerClass({
      name: 'org.kali.BioCb',
      superClass: cb.$class,
      methods: {
        onAuthenticationError: function (code, errString) {},
        onAuthenticationFailed: function () {},
        onAuthenticationSucceeded: function (result) { cb.onAuthenticationSucceeded(result); },
        onAuthenticationHelp: function (helpCode, helpString) {}
      }
    }).$new();
    return this.authenticate(crypto, cancel, exec, cbProxy);
  };
});
```

### 12.4 Force KeyStore attestation chain (for analysis only)

```javascript
Java.perform(function () {
  var Builder = Java.use('android.security.keystore.KeyGenParameterSpec$Builder');
  Builder.setAttestationChallenge.implementation = function (challenge) {
    console.log('[attest] challenge set: ' + (challenge ? bytesToHex(challenge) : 'null'));
    return this.setAttestationChallenge(challenge);
  };
});
```

---

## 13. Native Library Instrumentation

### 13.1 r2frida session

```bash
# Spawn-and-attach via r2frida bridge
r2 'frida://spawn/com.example.app'

# Inside r2:
[0x00000000]> il                      # list libraries
[0x00000000]> iE~libNative            # exports of libNative
[0x00000000]> s sym.Java_com_example_Native_nativeSign
[0xdeadbeef]> pdf                     # disassemble the function
[0xdeadbeef]> pdg                     # decompile via ghidra plugin if installed
[0xdeadbeef]> =?!/is                  # inject a Frida Interceptor hook via the bridge
```

### 13.2 Frida — enumerate + hook native exports

```javascript
// enumerate_native.js
var modules = Process.enumerateModules();
modules.forEach(function (m) {
  if (/libnative|libcrypto|libssl/i.test(m.name)) {
    console.log('[module] ' + m.name + ' base=' + m.base + ' size=' + m.size);
    m.enumerateExports().slice(0, 50).forEach(function (e) {
      console.log('  ' + e.type + ' ' + e.name + ' @ ' + e.address);
    });
  }
});

// Hook a known JNI export
var sym = Module.findExportByName('libnative.so', 'Java_com_example_Native_nativeSign');
if (sym) {
  Interceptor.attach(sym, {
    onEnter: function (args) {
      // args[0]=JNIEnv, args[1]=jobject, args[2..]=jbyteArray etc.
      console.log('[nativeSign] entered env=' + args[0]);
      this.env = args[0];
      this.input = args[2];
    },
    onLeave: function (retval) {
      console.log('[nativeSign] returned ' + retval);
    }
  });
}
```

### 13.3 Read JNI byte[] contents

```javascript
// Helper to extract bytes from jbyteArray given JNIEnv*
function readJByteArray(envPtr, jba) {
  var env = Java.vm.getEnv();
  // For simplicity use Java.cast; in pure-native context, call GetByteArrayElements via NativeFunction
  var GetByteArrayElements = new NativeFunction(
    Memory.readPointer(envPtr).add(216).readPointer(), 'pointer',
    ['pointer', 'pointer', 'pointer']);
  var isCopy = Memory.alloc(8);
  var ptr = GetByteArrayElements(envPtr, jba, isCopy);
  var len = new NativeFunction(
    Memory.readPointer(envPtr).add(192).readPointer(), 'int', ['pointer', 'pointer'])(envPtr, jba);
  var bytes = Memory.readByteArray(ptr, len);
  return bytes;
}
```

---

## 14. Crypto Tracing

### 14.1 iOS — CCCrypt + CCHmac

```javascript
// trace_cc.js
var CCCrypt = Module.findExportByName('libcommonCrypto.dylib', 'CCCrypt');
Interceptor.attach(CCCrypt, {
  onEnter: function (args) {
    this.op       = args[0].toInt32(); // 0=encrypt, 1=decrypt
    this.alg      = args[1].toInt32();
    this.options  = args[2].toInt32();
    this.key      = args[3];
    this.keyLen   = args[4].toInt32();
    this.iv       = args[5];
    this.dataIn   = args[6];
    this.dataInLen= args[7].toInt32();
    this.dataOut  = args[8];
    console.log('[CCCrypt] op=' + this.op + ' alg=' + this.alg + ' keyLen=' + this.keyLen);
    console.log('  key=' + hex(this.key, this.keyLen));
    console.log('  iv='  + (this.iv.isNull() ? 'null' : hex(this.iv, 16)));
    console.log('  in='  + hex(this.dataIn, Math.min(this.dataInLen, 64)));
  },
  onLeave: function (retval) {
    var outLen = Memory.readU32(args_placeholder(this)); // pseudocode; use a captured ref
    console.log('  out=' + hex(this.dataOut, 64));
  }
});

function hex(p, n) {
  var b = Memory.readByteArray(p, n);
  var arr = new Uint8Array(b); var s = '';
  for (var i = 0; i < arr.length; i++) s += ('0' + arr[i].toString(16)).slice(-2);
  return s;
}
function args_placeholder(_) { return 0; }
```

### 14.2 Android — javax.crypto full trace

```javascript
// trace_javax_crypto.js
Java.perform(function () {
  var Cipher = Java.use('javax.crypto.Cipher');
  ['doFinal', 'update'].forEach(function (m) {
    Cipher[m].overloads.forEach(function (overload) {
      overload.implementation = function () {
        var result = overload.apply(this, arguments);
        console.log('[' + m + '] algo=' + this.getAlgorithm());
        for (var i = 0; i < arguments.length; i++) {
          var a = arguments[i];
          if (a && a.length !== undefined && typeof a !== 'string') {
            console.log('  arg' + i + ' (bytes len=' + a.length + ')=' + bytesToHex(a, 64));
          }
        }
        if (result && result.length !== undefined) {
          console.log('  ret (len=' + result.length + ')=' + bytesToHex(result, 64));
        }
        return result;
      };
    });
  });

  var Mac = Java.use('javax.crypto.Mac');
  Mac.doFinal.overload('[B').implementation = function (input) {
    var out = this.doFinal(input);
    console.log('[Mac] algo=' + this.getAlgorithm() + ' in=' + bytesToHex(input, 64) + ' out=' + bytesToHex(out, 64));
    return out;
  };

  var MD = Java.use('java.security.MessageDigest');
  MD.digest.overload().implementation = function () {
    var out = this.digest();
    console.log('[MessageDigest] algo=' + this.getAlgorithm() + ' hash=' + bytesToHex(out, 64));
    return out;
  };

  function bytesToHex(arr, max) {
    var s = ''; var n = max && arr.length > max ? max : arr.length;
    for (var i = 0; i < n; i++) s += ('0' + (arr[i] & 0xff).toString(16)).slice(-2);
    return s;
  }
});
```

---

## 15. WebView Manipulation

### 15.1 Enumerate JavaScript bridges

```javascript
// list_jsbridge.js
Java.perform(function () {
  Java.enumerateLoadedClasses({
    onMatch: function (name) {
      if (/JavascriptInterface|JSBridge|@JavascriptInterface|addJavascriptInterface/i.test(name)) {
        console.log('[JSBridge] ' + name);
      }
    },
    onComplete: function () {}
  });

  var WV = Java.use('android.webkit.WebView');
  WV.addJavascriptInterface.implementation = function (obj, name) {
    console.log('[addJavascriptInterface] name=' + name + ' class=' + obj.$className);
    return this.addJavascriptInterface(obj, name);
  };
});
```

### 15.2 Invoke bridge methods at runtime

```javascript
// invoke_bridge.js
Java.perform(function () {
  var Bridge = Java.use('com.example.web.JSBridge');
  // Find method by name
  Bridge.getToken.implementation = function () {
    var t = this.getToken();
    console.log('[JSBridge.getToken] returned ' + t);
    return t;
  };
  // Trigger from JS side: window.JSBridge.getToken()
});
```

### 15.3 Override WebView URL loading

```javascript
Java.perform(function () {
  var WVClient = Java.use('android.webkit.WebViewClient');
  WVClient.shouldOverrideUrlLoading.overload('android.webkit.WebView', 'java.lang.String').implementation = function (view, url) {
    console.log('[WebView.url] ' + url);
    return false; // allow loading
  };
});
```

---

## 16. Anti-Frida Evasion

### 16.1 Common Frida signatures

| Check | Where | Pattern |
|------|------|------|
| `/proc/self/maps` lines | Android | `frida-agent`, `gum-js-loop`, `pool-frida`, `linjector` |
| `dyld` loaded images | iOS | `FridaGadget`, `frida-agent.dylib` |
| TCP port scan | both | Default port `27042`; many detection routines scan local ports 27000-27100 |
| `frida-server` named thread | both | `gum-js-loop`, `gmain`, `pool-frida` |
| `/data/local/tmp/re.frida.server` | Android | File path presence |

### 16.2 Magisk Hide / Zygisk DenyList

```bash
# Magisk → Configure → DenyList → tick com.example.app
# Verify
adb shell "su -c 'magisk --denylist ls'"
```

### 16.3 Frida server on non-default port

```bash
# Start frida-server on a non-default port
adb shell "su -c '/data/local/tmp/frida-server -l 0.0.0.0:24601 &'"

# Connect with explicit remote
frida -H 127.0.0.1:24601 -n com.example.app -l hook.js
# (forward the port first)
adb forward tcp:24601 tcp:24601
```

### 16.4 objection patchapk (bundled gadget)

```bash
# Patch an APK with embedded Frida gadget — bypasses process-attach detection
objection patchapk -s base.apk
# Output: base.objection.apk
apksigner sign --ks REPLACE_WITH_YOUR_KEYSTORE.jks base.objection.apk
adb install base.objection.apk
# App spawns, gadget listens on port 27042; attach with:
frida -U Gadget
```

### 16.5 Scrub /proc/self/maps in-process

```javascript
// scrub_maps.js
var fgets = Module.getGlobalExportByName( 'fgets');
Interceptor.attach(fgets, {
  onLeave: function (retval) {
    if (retval.isNull()) return;
    try {
      var line = Memory.readUtf8String(retval);
      if (line && /frida|gum-js|pool-frida|linjector/i.test(line)) {
        Memory.writeUtf8String(retval, 'b3351000-b3352000 r--p 00000000 00:00 0\n');
      }
    } catch (e) {}
  }
});

// Override pthread_getname_np / prctl PR_GET_NAME to rename Frida threads
var pthread_getname = Module.getGlobalExportByName( 'pthread_getname_np');
if (pthread_getname) {
  Interceptor.attach(pthread_getname, {
    onLeave: function (retval) {
      try {
        var name = Memory.readUtf8String(this.context); // not portable — capture arg properly
      } catch (e) {}
    }
  });
}
```

---

## 17. Detection (Blue Side)

### 17.1 RASP self-checks (defender reference)

```javascript
// Defense example — pseudo code showing what a robust RASP does
function detect_frida() {
  // 1. Port scan
  for (var p = 27000; p < 27100; p++) {
    if (can_connect('127.0.0.1', p)) return true; // frida-server
  }
  // 2. /proc/self/maps (Android) or dyld (iOS)
  var maps = read_file('/proc/self/maps');
  if (/frida|gum-js|linjector/i.test(maps)) return true;
  // 3. Thread name scan
  for (var tid of threads()) {
    if (/gum-js-loop|gmain|pool-frida/i.test(name_of(tid))) return true;
  }
  // 4. Loaded library scan
  if (enumerate_loaded_libs().some(l => /frida|gum/i.test(l))) return true;
  return false;
}
```

### 17.2 SafetyNet / Play Integrity API

```kotlin
// Android Kotlin — request Play Integrity verdict
val nonce = Base64.encodeToString(ByteArray(16).also { SecureRandom().nextBytes(it) }, Base64.NO_WRAP)
val tokenRequest = StandardIntegrityManager.StandardIntegrityTokenRequest.builder()
    .setNonce(nonce)
    .build()

val integrityManager = IntegrityManagerFactory.createStandard(applicationContext)
integrityManager.requestStandardIntegrityToken(tokenRequest)
    .addOnSuccessListener { response ->
        // Send response.token() to backend for verification against Google Play Integrity API
        apiClient.verifyIntegrityToken(response.token(), nonce)
    }
    .addOnFailureListener { e -> /* flag session as unverified */ }
```

### 17.3 iOS App Attest

```swift
// iOS Swift — request App Attest assertion
import DeviceCheck

let service = DCAppAttestService.shared
service.generateKey { keyId, error in
    guard let keyId = keyId else { return }
    service.attestKey(keyId, clientDataHash: challengeHash) { attestation, error in
        guard let attestation = attestation else { return }
        // Submit attestation (base64) to backend for verification against Apple App Attest service
        apiClient.verifyAttestation(keyId: keyId, attestation: attestation, challenge: challenge)
    }
}
```

### 17.4 Backend verdict check (Python pseudo)

```python
# Verify Play Integrity token on backend
import requests, jwt

GOOGLE_VERIFICATION_URL = "https://www.googleapis.com/androidcheck/v1/attestations/verify"

def verify_play_integrity(token: str, nonce_expected: str) -> dict:
    resp = requests.post(
        GOOGLE_VERIFICATION_URL,
        params={"key": "REPLACE_WITH_YOUR_GOOGLE_API_KEY"},
        json={"integrityToken": token},
        timeout=5,
    ).json()
    payload = jwt.decode(resp["tokenPayload"], options={"verify_signature": False})
    if payload["nonce"] != nonce_expected:
        raise ValueError("nonce mismatch — replay suspected")
    if payload["deviceIntegrity"]["deviceRecognitionVerdict"][0] not in ("MEETS_DEVICE_INTEGRITY", "MEETS_STRONG_INTEGRITY"):
        raise ValueError("device integrity too low")
    return payload
```

---

## 18. Quick Reference Cheat Sheet

### 18.1 Frida one-liners

```bash
# Spawn + attach
frida -U -f com.example.app -l hook.js --no-pause

# Attach running
frida -U -n Example -l hook.js

# List installed apps
frida-ps -Uai

# Trace libc open
frida-trace -U -i "open*" -f com.example.app

# Trace a Java method by pattern
frida-trace -U -j 'com.example.*!login*' -f com.example.app

# Dump DEX from packed app
frida-dexdump -U -f com.example.app -o out/
```

### 18.2 Objection one-liners

```bash
objection -g com.example.app explore
# Inside REPL:
#   android sslpinning disable
#   ios     sslpinning disable
#   android root disable
#   ios     jailbreak disable
#   android keystore list
#   ios     keychain dump
#   ios     nsuserdefaults get
#   ios     pasteboard monitor
#   android hooking watch class_method com.example.LoginManager.login --dump-args --dump-return
```

### 18.3 r2frida one-liners

```bash
r2 'frida://spawn/com.example.app'
# Inside r2:
#   il                  # list libraries
#   iE~libnative        # exports
#   s sym.<symbol>      # seek
#   pdf                 # disassemble
#   dc                  # continue
```

### 18.4 Common TLS pinning libraries + hook targets

| Platform | Library | Hook target |
|------|------|------|
| Android | OkHttp 3.x / 4.x | `okhttp3.CertificatePinner.check` |
| Android | Conscrypt | `com.android.org.conscrypt.TrustManagerImpl.verifyChain` |
| Android | Network Security Config | `android.security.net.config.NetworkSecurityConfig` |
| Android | Apache HTTPClient | `org.apache.http.conn.ssl.SSLSocketFactory` |
| iOS | AFNetworking | `AFSecurityPolicy` |
| iOS | TrustKit | `TSKPinningValidator` |
| iOS | Alamofire | `ServerTrustEvaluating` |
| iOS | NSURLSession | `URLSession:didReceiveChallenge:` delegate |
| iOS | libcommonCrypto | (not pinning, but crypto) `CCCrypt`, `CC_SHA256` |
| iOS | BoringSSL | `SSL_CTX_set_custom_verify` |

### 18.5 Useful Frida CLI utilities

```bash
# Kill target by name
frida-kill -U Example

# Resume a paused spawn
echo "resume" | frida -U -p 1234

# List available devices
frida-ls-devices

# Attach over network
frida -H 192.168.1.50:27042 -n Example -l hook.js
```

### 18.6 Common file paths

| OS | Item | Path |
|------|------|------|
| iOS | App bundles | `/var/containers/Bundle/Application/<UUID>/` |
| iOS | App data | `/var/mobile/Containers/Data/Application/<UUID>/` |
| iOS | Keychain | `/var/protected/var/Keychains/keychain-2.db` (locked) |
| iOS | frida-server | `/usr/sbin/frida-server` (Sileo package) |
| Android | APK installed | `/data/app/~~<hash>==/<pkg>-<hash>==/base.apk` |
| Android | App data | `/data/data/<pkg>/` |
| Android | Keystore | `/data/misc/keystore/` (master keys only; entries in TEE/StrongBox) |
| Android | frida-server | `/data/local/tmp/frida-server` |

### 18.7 Common bundle-id resolution

```bash
# iOS via frida-ps
frida-ps -Uai | grep -i example

# Android via adb
adb shell pm list packages | grep example
adb shell pm path com.example.app
```

### 18.8 MITM chaining (paired with network-sniffing-mitm skill)

```bash
# 1. Confirm target pins (mitmproxy alone fails)
mitmproxy --mode regular -p 8080
# 2. Configure device Wi-Fi proxy → 127.0.0.1:8080
# 3. Install mitmproxy CA on device (Settings → Profile Downloaded)
# 4. App still fails TLS → install SSL pinning bypass
frida -U -f com.example.app -l bypass_ssl_pinning.js --no-pause
# 5. mitmproxy now sees decrypted traffic
```

### 18.9 Cleanup

```bash
# Stop frida-server on device
adb shell "su -c 'pkill frida-server'"
ssh root@iphone.local "killall frida-server"

# Uninstall patched APK
adb uninstall com.example.app
```

---

## References

- Frida docs — https://frida.re/docs/home/
- Objection wiki — https://github.com/sensepost/objection/wiki
- r2frida — https://github.com/nowsecure/r2frida
- NowSecure blog — https://www.nowsecure.com/blog/
- @dki Frida iOS bootcamp — https://github.com/dki Frida-bootcamp
- OWASP MASTG — https://mas.owasp.org/MASTG/
- MITRE ATT&CK for Mobile — https://attack.mitre.org/matrices/mobile/
- Apple Platform Security — https://support.apple.com/guide/security/welcome/web
- Android Security Team — https://security.googleblog.com/
- Frida CodeShare — https://codeshare.frida.re/
