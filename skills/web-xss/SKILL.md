# Skill: Cross-Site Scripting (XSS)

> **Supplementary Files**:
> - `payloads.md` -- XSS attack payloads organized by category (probing, reflected, stored, DOM-based, encoding bypass, WAF bypass, blind, CSP bypass, cookie theft)
> - `test-cases.md` -- Structured test cases with severity levels, preconditions, and expected results (10 test cases covering 5 XSS categories)

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
