# Browser Fingerprint Analysis Guide

> Techniques for analyzing, detecting, and spoofing browser fingerprints to maintain operational security during web-based security testing.

## 1. Understanding Browser Fingerprints

Browser fingerprinting collects device and browser attributes to create a unique identifier without cookies. During penetration testing, controlling your fingerprint prevents detection and correlation of testing activity.

Key fingerprint vectors:
- User-Agent string
- Screen resolution and color depth
- Installed plugins and fonts
- Canvas and WebGL rendering
- AudioContext signatures
- Navigator properties (platform, language, hardware concurrency)

## 2. Extracting Your Current Fingerprint

Use Playwright to capture what fingerprinting scripts see:

```python
import asyncio
import json
from playwright.async_api import async_playwright

async def extract_fingerprint():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()

        fingerprint = await page.evaluate("""() => {
            return {
                userAgent: navigator.userAgent,
                platform: navigator.platform,
                language: navigator.language,
                languages: navigator.languages,
                hardwareConcurrency: navigator.hardwareConcurrency,
                deviceMemory: navigator.deviceMemory,
                screenRes: `${screen.width}x${screen.height}`,
                colorDepth: screen.colorDepth,
                timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                touchSupport: navigator.maxTouchPoints,
                webdriver: navigator.webdriver,
                plugins: Array.from(navigator.plugins).map(p => p.name),
            }
        }""")

        print(json.dumps(fingerprint, indent=2))
        await browser.close()

asyncio.run(extract_fingerprint())
```

## 3. Canvas Fingerprint Detection

Detect and analyze canvas fingerprinting attempts on target sites:

```python
import asyncio
from playwright.async_api import async_playwright

async def detect_canvas_fingerprinting(url):
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()

        canvas_calls = []
        await page.add_init_script("""
            const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
            const origGetImageData = CanvasRenderingContext2D.prototype.getImageData;

            HTMLCanvasElement.prototype.toDataURL = function(...args) {
                window.__canvasCalls = window.__canvasCalls || [];
                window.__canvasCalls.push({method: 'toDataURL', stack: new Error().stack});
                return origToDataURL.apply(this, args);
            };

            CanvasRenderingContext2D.prototype.getImageData = function(...args) {
                window.__canvasCalls = window.__canvasCalls || [];
                window.__canvasCalls.push({method: 'getImageData', stack: new Error().stack});
                return origGetImageData.apply(this, args);
            };
        """)

        await page.goto(url)
        await page.wait_for_timeout(3000)

        calls = await page.evaluate("() => window.__canvasCalls || []")
        if calls:
            print(f"[ALERT] Canvas fingerprinting detected: {len(calls)} call(s)")
            for call in calls[:5]:
                print(f"  Method: {call['method']}")
                print(f"  Stack: {call['stack'][:200]}")
        else:
            print("[OK] No canvas fingerprinting detected")

        await browser.close()

asyncio.run(detect_canvas_fingerprinting("https://target.local"))
```

## 4. Spoofing Browser Fingerprints with Playwright

Configure a browser context with a custom fingerprint profile:

```python
import asyncio
from playwright.async_api import async_playwright

PROFILES = {
    "windows_chrome": {
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "viewport": {"width": 1920, "height": 1080},
        "locale": "en-US",
        "timezone_id": "America/New_York",
        "color_scheme": "light",
    },
    "macos_safari": {
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
        "viewport": {"width": 1440, "height": 900},
        "locale": "en-US",
        "timezone_id": "America/Los_Angeles",
        "color_scheme": "dark",
    },
    "linux_firefox": {
        "user_agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
        "viewport": {"width": 1366, "height": 768},
        "locale": "en-GB",
        "timezone_id": "Europe/London",
        "color_scheme": "light",
    },
}

async def spoofed_session(url, profile_name):
    profile = PROFILES[profile_name]
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(**profile)

        # Override navigator properties
        await context.add_init_script("""
            Object.defineProperty(navigator, 'webdriver', {get: () => false});
            Object.defineProperty(navigator, 'hardwareConcurrency', {get: () => 8});
            Object.defineProperty(navigator, 'deviceMemory', {get: () => 8});
            Object.defineProperty(navigator, 'platform', {get: () => 'Win32'});
        """)

        page = await context.new_page()
        await page.goto(url)
        print(f"[*] Loaded {url} with profile: {profile_name}")
        await browser.close()

asyncio.run(spoofed_session("https://target.local", "windows_chrome"))
```

## 5. WebGL Fingerprint Spoofing

Override WebGL renderer information to avoid hardware-based tracking:

```python
import asyncio
from playwright.async_api import async_playwright

WEBGL_SPOOFS = {
    "nvidia_generic": {
        "vendor": "Google Inc. (NVIDIA)",
        "renderer": "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)"
    },
    "intel_integrated": {
        "vendor": "Google Inc. (Intel)",
        "renderer": "ANGLE (Intel, Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0, D3D11)"
    },
}

async def spoof_webgl(url, gpu_profile):
    spoof = WEBGL_SPOOFS[gpu_profile]
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()

        await context.add_init_script(f"""
            const getParameter = WebGLRenderingContext.prototype.getParameter;
            WebGLRenderingContext.prototype.getParameter = function(param) {{
                if (param === 37445) return '{spoof["vendor"]}';
                if (param === 37446) return '{spoof["renderer"]}';
                return getParameter.call(this, param);
            }};
            const getParameter2 = WebGL2RenderingContext.prototype.getParameter;
            WebGL2RenderingContext.prototype.getParameter = function(param) {{
                if (param === 37445) return '{spoof["vendor"]}';
                if (param === 37446) return '{spoof["renderer"]}';
                return getParameter2.call(this, param);
            }};
        """)

        page = await context.new_page()
        await page.goto(url)

        result = await page.evaluate("""() => {
            const canvas = document.createElement('canvas');
            const gl = canvas.getContext('webgl');
            const ext = gl.getExtension('WEBGL_debug_renderer_info');
            return {
                vendor: gl.getParameter(ext.UNMASKED_VENDOR_WEBGL),
                renderer: gl.getParameter(ext.UNMASKED_RENDERER_WEBGL)
            };
        }""")
        print(f"[*] WebGL reports: {result}")
        await browser.close()

asyncio.run(spoof_webgl("https://target.local", "nvidia_generic"))
```

## 6. Fingerprint Consistency Validation

Verify your spoofed fingerprint is internally consistent using known fingerprint test sites:

```bash
# Quick check using curl to compare headers vs JS-reported UA
curl -s -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
  https://httpbin.org/headers | jq '.headers["User-Agent"]'
```

```python
import asyncio
from playwright.async_api import async_playwright

async def validate_consistency(url):
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
        )
        await context.add_init_script("""
            Object.defineProperty(navigator, 'platform', {get: () => 'Win32'});
            Object.defineProperty(navigator, 'webdriver', {get: () => false});
        """)

        page = await context.new_page()
        await page.goto(url)

        checks = await page.evaluate("""() => {
            const ua = navigator.userAgent;
            const platform = navigator.platform;
            const issues = [];
            if (ua.includes('Windows') && !platform.includes('Win'))
                issues.push('UA says Windows but platform disagrees');
            if (ua.includes('Mac') && !platform.includes('Mac'))
                issues.push('UA says Mac but platform disagrees');
            if (navigator.webdriver)
                issues.push('webdriver flag is true');
            return {issues, ua, platform};
        }""")

        if checks["issues"]:
            print("[FAIL] Fingerprint inconsistencies:")
            for issue in checks["issues"]:
                print(f"  - {issue}")
        else:
            print("[PASS] Fingerprint appears consistent")

        await browser.close()

asyncio.run(validate_consistency("https://target.local"))
```
