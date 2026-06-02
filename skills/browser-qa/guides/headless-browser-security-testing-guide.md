# Headless Browser Security Testing Guide

> Leveraging Playwright and Puppeteer for automated security testing including form fuzzing, XSS detection, and authentication flow validation.

## 1. Environment Setup

Install Playwright with all browser engines for comprehensive testing:

```bash
npm init -y
npm install playwright @playwright/test
npx playwright install --with-deps chromium firefox webkit
```

Verify the installation works in headless mode:

```bash
npx playwright test --project=chromium --headed=false --reporter=list
```

## 2. Form Fuzzing with Playwright

Inject common attack payloads into all form inputs and observe application behavior:

```python
import asyncio
from playwright.async_api import async_playwright

FUZZ_PAYLOADS = [
    "' OR '1'='1' --",
    "<script>alert(document.domain)</script>",
    "{{7*7}}",
    "${7*7}",
    "../../../etc/passwd",
    "%00",
    "A" * 10000,
]

async def fuzz_forms(url):
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        await page.goto(url)

        forms = await page.query_selector_all("form")
        for form in forms:
            inputs = await form.query_selector_all("input[type='text'], input[type='email'], textarea")
            for payload in FUZZ_PAYLOADS:
                for inp in inputs:
                    await inp.fill("")
                    await inp.fill(payload)
                submit = await form.query_selector("button[type='submit'], input[type='submit']")
                if submit:
                    await submit.click()
                    await page.wait_for_load_state("networkidle")
                    content = await page.content()
                    if payload in content and "<script>" in payload:
                        print(f"[XSS] Reflected payload: {payload}")
                    await page.goto(url)

        await browser.close()

asyncio.run(fuzz_forms("http://target.local/login"))
```

## 3. XSS Detection via DOM Monitoring

Monitor DOM mutations to detect injected script execution:

```python
import asyncio
from playwright.async_api import async_playwright

XSS_VECTORS = [
    '<img src=x onerror="alert(1)">',
    '<svg onload="alert(1)">',
    '"><script>alert(document.cookie)</script>',
    "javascript:alert(1)//",
    '<details open ontoggle="alert(1)">',
]

async def detect_xss(url):
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()
        page = await context.new_page()

        alerts_triggered = []
        page.on("dialog", lambda dialog: alerts_triggered.append(dialog.message))

        for vector in XSS_VECTORS:
            target = f"{url}?q={vector}"
            await page.goto(target)
            await page.wait_for_timeout(1000)

            if alerts_triggered:
                print(f"[VULN] XSS triggered with: {vector}")
                alerts_triggered.clear()

        await browser.close()

asyncio.run(detect_xss("http://target.local/search"))
```

## 4. Authentication Flow Testing

Validate login mechanisms for common weaknesses:

```python
import asyncio
from playwright.async_api import async_playwright

async def test_auth_flow(url, username, password):
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()
        page = await context.new_page()
        await page.goto(url)

        # Test credential stuffing resistance
        for i in range(10):
            await page.fill("#username", username)
            await page.fill("#password", "wrong_pass")
            await page.click("#login-btn")
            await page.wait_for_load_state("networkidle")

        lockout = await page.query_selector(".account-locked, .rate-limit")
        if not lockout:
            print("[WARN] No account lockout after 10 failed attempts")

        # Test session fixation
        await page.fill("#username", username)
        await page.fill("#password", password)
        cookies_before = await context.cookies()
        await page.click("#login-btn")
        await page.wait_for_load_state("networkidle")
        cookies_after = await context.cookies()

        session_before = next((c for c in cookies_before if "session" in c["name"].lower()), None)
        session_after = next((c for c in cookies_after if "session" in c["name"].lower()), None)

        if session_before and session_after and session_before["value"] == session_after["value"]:
            print("[VULN] Session fixation - session ID unchanged after login")

        # Check secure cookie flags
        for cookie in cookies_after:
            if "session" in cookie["name"].lower():
                if not cookie.get("secure"):
                    print(f"[WARN] Session cookie missing Secure flag: {cookie['name']}")
                if not cookie.get("httpOnly"):
                    print(f"[WARN] Session cookie missing HttpOnly flag: {cookie['name']}")

        await browser.close()

asyncio.run(test_auth_flow("http://target.local/login", "admin", "admin123"))
```

## 5. CSRF Token Validation

Verify that forms enforce proper CSRF protection:

```python
import asyncio
from playwright.async_api import async_playwright

async def test_csrf(url):
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        await page.goto(url)

        forms = await page.query_selector_all("form[method='post'], form[method='POST']")
        for i, form in enumerate(forms):
            csrf_input = await form.query_selector("input[name*='csrf'], input[name*='token']")
            if not csrf_input:
                action = await form.get_attribute("action") or "self"
                print(f"[VULN] Form #{i} (action={action}) has no CSRF token")
            else:
                token_val = await csrf_input.get_attribute("value")
                if not token_val or len(token_val) < 16:
                    print(f"[WARN] Form #{i} CSRF token too short or empty")

        await browser.close()

asyncio.run(test_csrf("http://target.local/settings"))
```

## 6. Security Header Inspection

Collect and evaluate HTTP security headers across multiple pages:

```bash
npx playwright test --project=chromium -g "security-headers" 2>/dev/null
```

```python
import asyncio
from playwright.async_api import async_playwright

REQUIRED_HEADERS = [
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "content-security-policy",
    "referrer-policy",
]

async def check_headers(urls):
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()

        for url in urls:
            response = await page.goto(url)
            headers = response.headers
            print(f"\n[*] {url}")
            for h in REQUIRED_HEADERS:
                if h in headers:
                    print(f"  [OK] {h}: {headers[h][:60]}")
                else:
                    print(f"  [MISSING] {h}")

        await browser.close()

asyncio.run(check_headers([
    "http://target.local/",
    "http://target.local/api/v1/users",
    "http://target.local/admin",
]))

## References

- [Playwright Documentation](https://playwright.dev/docs/intro)
- [OWASP Testing Guide - Client-Side Testing](https://owasp.org/www-project-web-security-testing-guide/)
- [Puppeteer API Reference](https://pptr.dev/)
- [Browser Security Handbook (OWASP)](https://cheatsheetseries.owasp.org/cheatsheets/Browser_Security_Cheat_Sheet.html)
```
