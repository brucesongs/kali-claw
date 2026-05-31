# Anti-Bot Bypass Guide

> Techniques for bypassing anti-bot protections including Cloudflare, CAPTCHAs, and browser fingerprinting for authorized security research.

## Prerequisites

- Python 3.8+ with playwright/selenium
- Node.js with puppeteer
- curl-impersonate or similar TLS fingerprint tools
- Understanding of browser fingerprinting concepts

## 1. TLS Fingerprint Evasion

### curl-impersonate

```bash
# Install curl-impersonate (mimics browser TLS fingerprints)
# Impersonate Chrome 124
curl_chrome124 https://target.example.com -o response.html

# Impersonate Firefox 125
curl_ff125 https://target.example.com -o response.html

# Check your JA3 fingerprint
curl_chrome124 https://tls.browserleaks.com/json | jq '{ja3: .ja3_hash, browser: .user_agent}'

# With custom headers matching the impersonated browser
curl_chrome124 \
    -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,*/*;q=0.8" \
    -H "Accept-Language: en-US,en;q=0.9" \
    -H "Sec-Ch-Ua: \"Chromium\";v=\"124\", \"Google Chrome\";v=\"124\"" \
    -H "Sec-Ch-Ua-Platform: \"Windows\"" \
    -H "Sec-Fetch-Dest: document" \
    -H "Sec-Fetch-Mode: navigate" \
    https://target.example.com
```

### Python TLS Fingerprint with tls-client

```python
import tls_client

# Create session mimicking Chrome 124
session = tls_client.Session(
    client_identifier="chrome_124",
    random_tls_extension_order=True,
)

resp = session.get(
    "https://target.example.com",
    headers={
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Sec-Ch-Ua": '"Chromium";v="124", "Google Chrome";v="124"',
        "Sec-Ch-Ua-Platform": '"Windows"',
    },
)
print(resp.status_code, len(resp.text))
```

## 2. Cloudflare Challenge Bypass

### Playwright with Stealth

```python
from playwright.sync_api import sync_playwright

def bypass_cloudflare(url: str) -> str:
    """Use headed browser to pass Cloudflare challenge."""
    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=False,  # Headed mode passes more checks
            args=[
                "--disable-blink-features=AutomationControlled",
                "--no-sandbox",
            ],
        )
        context = browser.new_context(
            viewport={"width": 1920, "height": 1080},
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        )
        page = context.new_page()

        # Remove webdriver detection
        page.add_init_script("""
            Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
            delete navigator.__proto__.webdriver;
        """)

        page.goto(url, wait_until="networkidle")
        # Wait for challenge to resolve (typically 5-8 seconds)
        page.wait_for_timeout(8000)

        content = page.content()
        browser.close()
        return content
```

### Cookie Extraction for Subsequent Requests

```python
def extract_cf_cookies(url: str) -> dict:
    """Extract Cloudflare clearance cookies after challenge pass."""
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        context = browser.new_context()
        page = context.new_page()
        page.goto(url, wait_until="networkidle")
        page.wait_for_timeout(10000)

        cookies = context.cookies()
        cf_cookies = {
            c["name"]: c["value"]
            for c in cookies
            if c["name"] in ("cf_clearance", "__cf_bm", "cf_chl_2")
        }

        browser.close()
        return cf_cookies

# Reuse cookies with httpx
cookies = extract_cf_cookies("https://target.example.com")
import httpx
resp = httpx.get("https://target.example.com/api/data", cookies=cookies)
```

## 3. Browser Fingerprint Hardening

### Puppeteer Stealth Plugin

```javascript
// stealth-scraper.js
const puppeteer = require('puppeteer-extra');
const StealthPlugin = require('puppeteer-extra-plugin-stealth');
puppeteer.use(StealthPlugin());

(async () => {
    const browser = await puppeteer.launch({
        headless: 'new',
        args: [
            '--no-sandbox',
            '--disable-setuid-sandbox',
            '--disable-dev-shm-usage',
            '--disable-accelerated-2d-canvas',
            '--disable-gpu',
            '--window-size=1920,1080',
        ],
    });

    const page = await browser.newPage();
    await page.setViewport({ width: 1920, height: 1080 });

    // Override detection vectors
    await page.evaluateOnNewDocument(() => {
        // Chrome runtime
        window.chrome = { runtime: {} };
        // Plugins array
        Object.defineProperty(navigator, 'plugins', {
            get: () => [1, 2, 3, 4, 5],
        });
        // Languages
        Object.defineProperty(navigator, 'languages', {
            get: () => ['en-US', 'en'],
        });
        // WebGL vendor
        const getParameter = WebGLRenderingContext.prototype.getParameter;
        WebGLRenderingContext.prototype.getParameter = function(param) {
            if (param === 37445) return 'Intel Inc.';
            if (param === 37446) return 'Intel Iris OpenGL Engine';
            return getParameter.call(this, param);
        };
    });

    await page.goto('https://target.example.com', { waitUntil: 'networkidle2' });
    const content = await page.content();
    console.log(content.length);
    await browser.close();
})();
```

## 4. CAPTCHA Handling Strategies

### Detection and Classification

```python
from playwright.sync_api import Page

def detect_captcha(page: Page) -> str | None:
    """Detect CAPTCHA type on page."""
    indicators = {
        "recaptcha": "iframe[src*='recaptcha']",
        "hcaptcha": "iframe[src*='hcaptcha']",
        "turnstile": "iframe[src*='challenges.cloudflare.com']",
        "funcaptcha": "iframe[src*='funcaptcha']",
    }
    for captcha_type, selector in indicators.items():
        if page.query_selector(selector):
            return captcha_type
    return None

def handle_turnstile(page: Page):
    """Wait for Cloudflare Turnstile to auto-solve."""
    frame = page.frame_locator("iframe[src*='challenges.cloudflare.com']")
    # Turnstile often auto-solves for non-bot traffic
    page.wait_for_timeout(5000)
    checkbox = frame.locator("input[type='checkbox']")
    if checkbox.is_visible():
        checkbox.click()
        page.wait_for_timeout(3000)
```

### Retry with Backoff on CAPTCHA Detection

```bash
#!/bin/bash
# Retry loop with CAPTCHA detection
MAX_RETRIES=3
RETRY=0

while [ $RETRY -lt $MAX_RETRIES ]; do
    RESPONSE=$(curl_chrome124 -s -w "\n%{http_code}" "$TARGET_URL")
    HTTP_CODE=$(echo "$RESPONSE" | tail -1)
    BODY=$(echo "$RESPONSE" | sed '$d')

    # Check for challenge page indicators
    if echo "$BODY" | grep -q "challenge-platform\|captcha\|cf-turnstile"; then
        echo "Challenge detected, attempt $((RETRY+1))/$MAX_RETRIES"
        RETRY=$((RETRY+1))
        sleep $((RETRY * 10))
    elif [ "$HTTP_CODE" = "403" ]; then
        echo "Blocked (403), rotating identity..."
        RETRY=$((RETRY+1))
        sleep $((RETRY * 15))
    else
        echo "$BODY"
        break
    fi
done
```

## 5. JavaScript Rendering Detection

```python
import httpx
from playwright.sync_api import sync_playwright

def needs_js_rendering(url: str) -> bool:
    """Determine if a page requires JavaScript rendering."""
    # Fetch static HTML
    static_resp = httpx.get(url, follow_redirects=True)
    static_len = len(static_resp.text)

    # Fetch with JS rendering
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto(url, wait_until="networkidle")
        rendered_len = len(page.content())
        browser.close()

    # If rendered content is significantly larger, JS is needed
    ratio = rendered_len / max(static_len, 1)
    return ratio > 1.5

def smart_fetch(url: str) -> str:
    """Fetch with appropriate method based on JS requirement."""
    if needs_js_rendering(url):
        return fetch_with_browser(url)
    return httpx.get(url, follow_redirects=True).text
```

## 6. Detection Test Suite

```bash
#!/bin/bash
# Test your scraper's stealth against common detection endpoints

echo "=== Anti-Bot Detection Test ==="

# Test 1: Basic bot detection
echo -n "[1] Bot detection: "
curl_chrome124 -s https://bot.sannysoft.com | grep -c "missing" | xargs -I{} echo "{} detections"

# Test 2: TLS fingerprint
echo -n "[2] JA3 hash: "
curl_chrome124 -s https://tls.browserleaks.com/json | jq -r '.ja3_hash'

# Test 3: IP reputation
echo -n "[3] IP info: "
curl_chrome124 -s https://httpbin.org/ip | jq -r '.origin'

# Test 4: Header consistency
echo "[4] Headers sent:"
curl_chrome124 -s https://httpbin.org/headers | jq '.headers | keys[]'

# Test 5: WebRTC leak (browser only)
echo "[5] Run browser test at: https://browserleaks.com/webrtc"
```

## Quick Reference

| Protection | Bypass Technique | Tool |
|------------|-----------------|------|
| Cloudflare | TLS fingerprint + cookies | curl-impersonate, playwright |
| reCAPTCHA | Browser automation + wait | playwright stealth |
| Turnstile | Auto-solve with real browser | playwright |
| Bot detection | Stealth plugins + fingerprint | puppeteer-stealth |
| Rate limiting | See rate-limiting-and-stealth-guide | httpx + proxy rotation |

## Integration with Other Skills

- **data-scraper-agent**: Anti-bot as prerequisite for scraping protected targets
- **web-pentest**: Understanding WAF behavior during testing
- **osint**: Accessing protected public data sources
