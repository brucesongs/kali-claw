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
```

### Network Monitoring
```python
# Intercept requests
def handle_request(request):
    print(f"{request.method} {request.url}")

page.on("request", handle_request)

# Check CSRF token
response = page.goto("https://example.com/form")
csrf_token = page.locator("input[name=_csrf]").get_attribute("value")
print(f"CSRF token: {csrf_token}")
```

### Cookie Analysis
```python
# Get all cookies
cookies = page.context.cookies()
for cookie in cookies:
    print(f"{cookie['name']}: HttpOnly={cookie.get('httpOnly')}, Secure={cookie.get('secure')}")
```

### XSS Payload Injection
```python
# Test XSS via form input
page.fill("input#search", "<script>alert('XSS')</script>")
page.click("button#search-submit")

# Check if payload executed (look for alert or DOM modification)
```

### Screenshot Evidence
```python
page.screenshot(path="finding_evidence.png")
```
