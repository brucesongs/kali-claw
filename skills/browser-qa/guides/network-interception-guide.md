# Network Interception Guide

> Skill: browser-qa | Type: practical
> Created: 2026-05-29 | Estimated Study Time: 25 minutes

## Overview

Learn to intercept, analyze, and modify network traffic using Playwright for security testing — API monitoring, request tampering, response modification, and traffic recording.

## Prerequisites

- Playwright installed (`pip install playwright && playwright install`)
- Understanding of HTTP request/response lifecycle
- Basic knowledge of web application architecture

## 1. Request Monitoring

### Log All Requests
```python
from playwright.sync_api import sync_playwright

def monitor_traffic(url):
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        
        requests_log = []
        
        def on_request(request):
            requests_log.append({
                "method": request.method,
                "url": request.url,
                "headers": dict(request.headers),
                "post_data": request.post_data,
            })
        
        def on_response(response):
            for entry in requests_log:
                if entry["url"] == response.url:
                    entry["status"] = response.status
                    entry["response_headers"] = dict(response.headers)
                    break
        
        page.on("request", on_request)
        page.on("response", on_response)
        page.goto(url)
        page.wait_for_load_state("networkidle")
        
        browser.close()
        return requests_log
```

### Filter API Calls
```python
def monitor_api_calls(page, url, api_pattern="/api/"):
    api_calls = []
    
    def on_response(response):
        if api_pattern in response.url:
            try:
                body = response.json()
            except:
                body = response.text()[:500]
            
            api_calls.append({
                "url": response.url,
                "status": response.status,
                "body": body,
                "headers": dict(response.headers),
            })
    
    page.on("response", on_response)
    page.goto(url)
    page.wait_for_load_state("networkidle")
    
    return api_calls
```

## 2. Request Modification

### Header Injection
```python
def inject_headers(page, target_url):
    def modify_request(route):
        headers = route.request.headers.copy()
        headers["X-Forwarded-For"] = "127.0.0.1"
        headers["X-Original-URL"] = "/admin"
        headers["X-Custom-IP-Authorization"] = "127.0.0.1"
        route.continue_(headers=headers)
    
    page.route("**/*", modify_request)
    page.goto(target_url)
```

### Parameter Tampering
```python
def tamper_request(page, url_pattern, modifications):
    def modify(route):
        url = route.request.url
        for old, new in modifications.items():
            url = url.replace(old, new)
        route.continue_(url=url)
    
    page.route(url_pattern, modify)

# Usage: change user ID in API calls
tamper_request(page, "**/api/users/*", {"user_id=1": "user_id=2"})
```

### Body Modification (POST Requests)
```python
import json

def modify_post_body(page, url_pattern, field_changes):
    def modify(route):
        if route.request.method == "POST" and route.request.post_data:
            try:
                body = json.loads(route.request.post_data)
                body.update(field_changes)
                route.continue_(post_data=json.dumps(body))
            except json.JSONDecodeError:
                route.continue_()
        else:
            route.continue_()
    
    page.route(url_pattern, modify)

# Usage: escalate privileges in request
modify_post_body(page, "**/api/profile", {"role": "admin", "is_admin": True})
```

## 3. Response Modification

### Mock API Response
```python
def mock_response(page, url_pattern, mock_body, status=200):
    def fulfill(route):
        route.fulfill(
            status=status,
            content_type="application/json",
            body=json.dumps(mock_body)
        )
    
    page.route(url_pattern, fulfill)

# Usage: bypass client-side authorization
mock_response(page, "**/api/user/permissions", {
    "role": "admin",
    "permissions": ["read", "write", "delete", "admin"]
})
```

### Remove Security Headers
```python
def strip_security_headers(page, url_pattern):
    def modify(route):
        response = route.fetch()
        headers = dict(response.headers)
        
        for header in ["content-security-policy", "x-frame-options", 
                       "x-content-type-options", "strict-transport-security"]:
            headers.pop(header, None)
        
        route.fulfill(
            status=response.status,
            headers=headers,
            body=response.body()
        )
    
    page.route(url_pattern, modify)
```

## 4. HAR Recording and Analysis

```python
def record_har(url, actions_fn, output_path="traffic.har"):
    with sync_playwright() as p:
        browser = p.chromium.launch()
        context = browser.new_context(record_har_path=output_path)
        page = context.new_page()
        
        page.goto(url)
        actions_fn(page)  # Perform test actions
        
        context.close()
        browser.close()

# Analyze HAR file
def analyze_har(har_path):
    with open(har_path) as f:
        har = json.load(f)
    
    findings = []
    for entry in har["log"]["entries"]:
        req = entry["request"]
        resp = entry["response"]
        
        # Check for sensitive data in URLs
        if any(keyword in req["url"].lower() for keyword in ["token", "key", "password"]):
            findings.append(f"Sensitive param in URL: {req['url'][:100]}")
        
        # Check for missing security headers
        resp_headers = {h["name"].lower(): h["value"] for h in resp["headers"]}
        if "strict-transport-security" not in resp_headers:
            findings.append(f"Missing HSTS: {req['url'][:80]}")
    
    return findings
```

## 5. WebSocket Interception

```python
def monitor_websockets(page, url):
    ws_messages = []
    
    def on_ws(ws):
        def on_frame_sent(payload):
            ws_messages.append({"direction": "sent", "data": payload[:500]})
        
        def on_frame_received(payload):
            ws_messages.append({"direction": "received", "data": payload[:500]})
        
        ws.on("framesent", on_frame_sent)
        ws.on("framereceived", on_frame_received)
    
    page.on("websocket", on_ws)
    page.goto(url)
    page.wait_for_timeout(5000)
    
    return ws_messages
```

## 6. Security Header Analysis

```python
def check_security_headers(page, url):
    response = page.goto(url)
    headers = response.headers
    
    checks = {
        "strict-transport-security": "Missing HSTS — vulnerable to downgrade attacks",
        "content-security-policy": "Missing CSP — XSS risk increased",
        "x-content-type-options": "Missing X-Content-Type-Options — MIME sniffing possible",
        "x-frame-options": "Missing X-Frame-Options — clickjacking possible",
        "referrer-policy": "Missing Referrer-Policy — URL leakage risk",
        "permissions-policy": "Missing Permissions-Policy — unnecessary API access",
    }
    
    findings = []
    for header, message in checks.items():
        if header not in headers:
            findings.append({"header": header, "issue": message, "severity": "MEDIUM"})
    
    # Check CSP quality if present
    csp = headers.get("content-security-policy", "")
    if "unsafe-inline" in csp:
        findings.append({"header": "CSP", "issue": "unsafe-inline allows XSS", "severity": "HIGH"})
    if "unsafe-eval" in csp:
        findings.append({"header": "CSP", "issue": "unsafe-eval allows code injection", "severity": "HIGH"})
    
    return findings
```

## 7. Blocking and Filtering

```python
# Block tracking and analytics (reduce noise)
def setup_clean_context(browser):
    context = browser.new_context()
    page = context.new_page()
    
    block_patterns = [
        "**/*.{png,jpg,jpeg,gif,svg,ico}",
        "**/analytics*",
        "**/tracking*",
        "**/*google-analytics*",
        "**/*facebook*",
    ]
    
    for pattern in block_patterns:
        page.route(pattern, lambda route: route.abort())
    
    return page
```

## Quick Reference

| Technique | Method | Use Case |
|-----------|--------|----------|
| `page.on("request")` | Passive | Traffic logging |
| `page.route()` | Active | Request/response modification |
| `route.continue_()` | Pass-through | Header/body tampering |
| `route.fulfill()` | Mock | Response spoofing |
| `route.abort()` | Block | Filter unwanted traffic |
| HAR recording | Record | Full session capture |

## Integration with Other Skills

- **web-auth-bypass**: Modify auth tokens in intercepted requests
- **web-ssrf**: Detect internal service calls via traffic monitoring
- **api-security**: Full API traffic analysis through interception
