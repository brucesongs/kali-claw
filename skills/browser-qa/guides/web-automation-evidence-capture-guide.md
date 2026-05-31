# Web Automation Evidence Capture Guide

> Systematic methods for capturing screenshots, HAR files, and network logs as forensic evidence during automated browser-based security testing.

## 1. Screenshot Capture Strategy

Capture full-page and element-specific screenshots at critical test points:

```python
import asyncio
from pathlib import Path
from datetime import datetime
from playwright.async_api import async_playwright

async def capture_evidence(url, output_dir="./evidence"):
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page(viewport={"width": 1920, "height": 1080})
        await page.goto(url)

        # Full page screenshot
        await page.screenshot(
            path=f"{output_dir}/{timestamp}_fullpage.png",
            full_page=True
        )

        # Viewport-only screenshot
        await page.screenshot(
            path=f"{output_dir}/{timestamp}_viewport.png",
            full_page=False
        )

        # Specific element capture (e.g., error messages, forms)
        error_el = await page.query_selector(".error, .alert, .vulnerability")
        if error_el:
            await error_el.screenshot(path=f"{output_dir}/{timestamp}_finding.png")

        print(f"[*] Evidence saved to {output_dir}/")
        await browser.close()

asyncio.run(capture_evidence("http://target.local/admin"))
```

## 2. HAR File Recording

Record complete HTTP Archive files capturing all requests, responses, headers, and timing:

```python
import asyncio
from datetime import datetime
from playwright.async_api import async_playwright

async def record_har(url, actions_fn=None):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    har_path = f"./evidence/{timestamp}_capture.har"

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(record_har_path=har_path)
        page = await context.new_page()

        await page.goto(url)

        if actions_fn:
            await actions_fn(page)
        else:
            await page.wait_for_timeout(3000)

        await context.close()
        await browser.close()
        print(f"[*] HAR saved: {har_path}")

async def login_actions(page):
    await page.fill("#username", "admin")
    await page.fill("#password", "test123")
    await page.click("#login-btn")
    await page.wait_for_load_state("networkidle")

asyncio.run(record_har("http://target.local/login", login_actions))
```

Parse and analyze HAR files for security findings:

```bash
# Extract all URLs from HAR file
cat evidence/*_capture.har | jq -r '.log.entries[].request.url' | sort -u

# Find requests with sensitive data in query params
cat evidence/*_capture.har | jq -r '.log.entries[].request.url' | grep -iE '(password|token|key|secret|api_key)'

# Extract response status codes summary
cat evidence/*_capture.har | jq '[.log.entries[] | {url: .request.url, status: .response.status}] | group_by(.status) | map({status: .[0].status, count: length})'
```

## 3. Network Request Logging

Intercept and log all network traffic with request/response bodies:

```python
import asyncio
import json
from datetime import datetime
from pathlib import Path
from playwright.async_api import async_playwright

async def log_network(url, output_dir="./evidence"):
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_entries = []

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()

        async def handle_response(response):
            entry = {
                "timestamp": datetime.now().isoformat(),
                "url": response.url,
                "status": response.status,
                "method": response.request.method,
                "request_headers": await response.request.all_headers(),
                "response_headers": await response.all_headers(),
            }
            try:
                body = await response.text()
                if len(body) < 50000:
                    entry["response_body"] = body
            except Exception:
                entry["response_body"] = "[binary or unavailable]"
            log_entries.append(entry)

        page.on("response", handle_response)
        await page.goto(url)
        await page.wait_for_load_state("networkidle")

        log_path = f"{output_dir}/{timestamp}_network.json"
        with open(log_path, "w") as f:
            json.dump(log_entries, f, indent=2)

        print(f"[*] Logged {len(log_entries)} requests to {log_path}")
        await browser.close()

asyncio.run(log_network("http://target.local"))
```

## 4. Console and Error Log Capture

Record browser console messages, JavaScript errors, and uncaught exceptions:

```python
import asyncio
import json
from datetime import datetime
from pathlib import Path
from playwright.async_api import async_playwright

async def capture_console_logs(url, output_dir="./evidence"):
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    logs = []

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()

        page.on("console", lambda msg: logs.append({
            "type": msg.type,
            "text": msg.text,
            "timestamp": datetime.now().isoformat(),
        }))

        page.on("pageerror", lambda err: logs.append({
            "type": "page_error",
            "text": str(err),
            "timestamp": datetime.now().isoformat(),
        }))

        await page.goto(url)
        await page.wait_for_timeout(5000)

        log_path = f"{output_dir}/{timestamp}_console.json"
        with open(log_path, "w") as f:
            json.dump(logs, f, indent=2)

        errors = [l for l in logs if l["type"] in ("error", "page_error")]
        print(f"[*] Captured {len(logs)} console entries ({len(errors)} errors)")
        print(f"[*] Saved to {log_path}")
        await browser.close()

asyncio.run(capture_console_logs("http://target.local"))
```

## 5. Automated Evidence Report Generation

Combine all evidence artifacts into a structured report:

```python
import asyncio
import json
from datetime import datetime
from pathlib import Path
from playwright.async_api import async_playwright

async def full_evidence_capture(url, test_name, output_dir="./evidence"):
    run_dir = Path(output_dir) / f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{test_name}"
    run_dir.mkdir(parents=True, exist_ok=True)

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(
            record_har_path=str(run_dir / "traffic.har"),
            viewport={"width": 1920, "height": 1080},
        )
        page = await context.new_page()

        console_logs = []
        page.on("console", lambda msg: console_logs.append({
            "type": msg.type, "text": msg.text
        }))

        # Navigate and capture
        response = await page.goto(url)
        await page.wait_for_load_state("networkidle")
        await page.screenshot(path=str(run_dir / "initial.png"), full_page=True)

        # Build metadata
        metadata = {
            "test_name": test_name,
            "url": url,
            "timestamp": datetime.now().isoformat(),
            "status_code": response.status,
            "response_headers": await response.all_headers(),
            "console_entries": len(console_logs),
            "artifacts": ["traffic.har", "initial.png", "console.json", "metadata.json"],
        }

        with open(run_dir / "console.json", "w") as f:
            json.dump(console_logs, f, indent=2)
        with open(run_dir / "metadata.json", "w") as f:
            json.dump(metadata, f, indent=2)

        await context.close()
        await browser.close()
        print(f"[*] Evidence package: {run_dir}/")
        print(f"    Artifacts: {', '.join(metadata['artifacts'])}")

asyncio.run(full_evidence_capture("http://target.local/admin", "admin_panel_recon"))
```

## 6. Evidence Integrity with Hashing

Generate SHA-256 hashes for all evidence files to ensure chain of custody:

```bash
# Hash all evidence files in a capture directory
find ./evidence -type f \( -name "*.png" -o -name "*.har" -o -name "*.json" \) \
  -exec sha256sum {} \; | tee ./evidence/checksums.sha256

# Verify integrity later
sha256sum -c ./evidence/checksums.sha256
```

```python
import hashlib
from pathlib import Path

def generate_checksums(evidence_dir):
    checksums = {}
    for f in Path(evidence_dir).rglob("*"):
        if f.is_file() and f.name != "checksums.json":
            sha256 = hashlib.sha256(f.read_bytes()).hexdigest()
            checksums[str(f.relative_to(evidence_dir))] = sha256

    checksum_path = Path(evidence_dir) / "checksums.json"
    import json
    with open(checksum_path, "w") as out:
        json.dump(checksums, out, indent=2)
    print(f"[*] Generated {len(checksums)} checksums -> {checksum_path}")

generate_checksums("./evidence/20260529_143000_admin_panel_recon")
```
