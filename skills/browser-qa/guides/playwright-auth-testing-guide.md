# Playwright Auth Testing Guide

> Skill: browser-qa | Type: tool-specific
> Created: 2026-05-29 | Estimated Study Time: 30 minutes

## Overview

Master Playwright for automated authentication security testing — login flow attacks, session management verification, cookie security auditing, and OAuth/SSO testing patterns.

## Prerequisites

- Python 3.8+ with playwright installed (`pip install playwright && playwright install`)
- Target application with login functionality
- Basic understanding of HTTP auth mechanisms

## 1. Setup and Configuration

```python
from playwright.sync_api import sync_playwright, expect
import json
import time

def create_test_context(headless=True):
    p = sync_playwright().start()
    browser = p.chromium.launch(
        headless=headless,
        args=["--disable-blink-features=AutomationControlled"]
    )
    context = browser.new_context(
        viewport={"width": 1280, "height": 720},
        ignore_https_errors=True,
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    )
    return p, browser, context
```

## 2. Login Flow Testing

### Credential Stuffing Detection
```python
def test_rate_limiting(page, login_url, username_field, password_field):
    results = []
    
    for i in range(20):
        page.goto(login_url)
        page.fill(username_field, "admin")
        page.fill(password_field, f"wrong_password_{i}")
        page.click("button[type=submit]")
        page.wait_for_load_state("networkidle")
        
        status = {
            "attempt": i + 1,
            "url": page.url,
            "blocked": "locked" in page.content().lower() or "rate" in page.content().lower(),
            "captcha": page.locator("[class*=captcha], [id*=captcha]").count() > 0,
        }
        results.append(status)
        
        if status["blocked"] or status["captcha"]:
            print(f"Rate limiting triggered at attempt {i + 1}")
            return results
    
    print("WARNING: No rate limiting detected after 20 failed attempts")
    return results
```

### Username Enumeration
```python
def test_username_enumeration(page, login_url, valid_user, invalid_user):
    responses = {}
    
    for username in [valid_user, invalid_user]:
        page.goto(login_url)
        page.fill("#username", username)
        page.fill("#password", "definitely_wrong_password")
        page.click("button[type=submit]")
        page.wait_for_load_state("networkidle")
        
        responses[username] = {
            "error_text": page.locator(".error, .alert, [role=alert]").text_content() or "",
            "response_time": page.evaluate("performance.now()"),
            "url": page.url,
        }
    
    if responses[valid_user]["error_text"] != responses[invalid_user]["error_text"]:
        print(f"VULNERABLE: Different error messages reveal valid usernames")
        print(f"  Valid user msg: {responses[valid_user]['error_text']}")
        print(f"  Invalid user msg: {responses[invalid_user]['error_text']}")
    
    return responses
```

## 3. Session Management Testing

### Session Fixation
```python
def test_session_fixation(page, login_url, username, password):
    page.goto(login_url)
    cookies_before = {c["name"]: c["value"] for c in page.context.cookies()}
    session_before = cookies_before.get("session_id") or cookies_before.get("JSESSIONID")
    
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("button[type=submit]")
    page.wait_for_load_state("networkidle")
    
    cookies_after = {c["name"]: c["value"] for c in page.context.cookies()}
    session_after = cookies_after.get("session_id") or cookies_after.get("JSESSIONID")
    
    if session_before and session_after and session_before == session_after:
        print("VULNERABLE: Session ID unchanged after login (session fixation)")
        return True
    
    print("SAFE: Session regenerated on login")
    return False
```

### Session Timeout
```python
def test_session_timeout(page, protected_url, login_url, username, password, wait_minutes=31):
    # Login first
    page.goto(login_url)
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("button[type=submit]")
    page.wait_for_url("**/dashboard*")
    
    # Store session cookies
    cookies = page.context.cookies()
    
    # Wait for timeout period
    print(f"Waiting {wait_minutes} minutes for session timeout test...")
    time.sleep(wait_minutes * 60)
    
    # Try to access protected resource
    page.goto(protected_url)
    page.wait_for_load_state("networkidle")
    
    if login_url in page.url or page.locator("#login-form").count() > 0:
        print(f"SAFE: Session expired after {wait_minutes} minutes")
        return True
    else:
        print(f"WARNING: Session still valid after {wait_minutes} minutes")
        return False
```

### Concurrent Session Detection
```python
def test_concurrent_sessions(browser, login_url, username, password):
    # Login in context 1
    context1 = browser.new_context()
    page1 = context1.new_page()
    page1.goto(login_url)
    page1.fill("#username", username)
    page1.fill("#password", password)
    page1.click("button[type=submit]")
    page1.wait_for_load_state("networkidle")
    
    # Login in context 2 (different session)
    context2 = browser.new_context()
    page2 = context2.new_page()
    page2.goto(login_url)
    page2.fill("#username", username)
    page2.fill("#password", password)
    page2.click("button[type=submit]")
    page2.wait_for_load_state("networkidle")
    
    # Check if first session is still valid
    page1.reload()
    page1.wait_for_load_state("networkidle")
    
    if login_url in page1.url:
        print("First session invalidated — concurrent session protection active")
    else:
        print("WARNING: Multiple concurrent sessions allowed")
    
    context1.close()
    context2.close()
```

## 4. Cookie Security Audit

```python
def audit_cookies(page, url):
    page.goto(url)
    cookies = page.context.cookies()
    findings = []
    
    for cookie in cookies:
        issues = []
        
        if not cookie.get("httpOnly"):
            issues.append("Missing HttpOnly flag (XSS risk)")
        
        if not cookie.get("secure"):
            issues.append("Missing Secure flag (sent over HTTP)")
        
        if cookie.get("sameSite", "").lower() == "none":
            issues.append("SameSite=None (CSRF risk)")
        elif not cookie.get("sameSite"):
            issues.append("No SameSite attribute set")
        
        if cookie.get("expires", -1) > time.time() + (365 * 24 * 3600):
            issues.append("Expiry > 1 year (excessive lifetime)")
        
        if issues:
            findings.append({
                "name": cookie["name"],
                "domain": cookie.get("domain"),
                "issues": issues,
            })
    
    return findings
```

## 5. OAuth/SSO Testing

### Redirect URI Manipulation
```python
def test_redirect_uri_bypass(page, auth_url, client_id):
    malicious_redirects = [
        "https://attacker.com/callback",
        "https://legitimate.com.attacker.com/callback",
        "https://legitimate.com@attacker.com/callback",
        "https://legitimate.com/callback/../../../attacker",
        "https://legitimate.com/callback?next=https://attacker.com",
    ]
    
    results = []
    for redirect in malicious_redirects:
        url = f"{auth_url}?client_id={client_id}&redirect_uri={redirect}&response_type=code"
        page.goto(url)
        page.wait_for_load_state("networkidle")
        
        result = {
            "redirect_uri": redirect,
            "accepted": "error" not in page.url.lower() and "invalid" not in page.content().lower(),
            "final_url": page.url,
        }
        results.append(result)
        
        if result["accepted"]:
            print(f"POTENTIAL VULN: Redirect accepted: {redirect}")
    
    return results
```

## 6. Password Reset Testing

```python
def test_password_reset_flow(page, reset_url):
    findings = []
    
    # Test with valid email
    page.goto(reset_url)
    page.fill("input[type=email], input[name=email]", "test@example.com")
    page.click("button[type=submit]")
    page.wait_for_load_state("networkidle")
    valid_response = page.content()
    
    # Test with invalid email
    page.goto(reset_url)
    page.fill("input[type=email], input[name=email]", "nonexistent@example.com")
    page.click("button[type=submit]")
    page.wait_for_load_state("networkidle")
    invalid_response = page.content()
    
    # Check for user enumeration
    if valid_response != invalid_response:
        findings.append("User enumeration possible via password reset")
    
    return findings
```

## Quick Reference

| Test | Risk Level | Impact |
|------|------------|--------|
| No rate limiting | HIGH | Credential stuffing |
| Username enumeration | MEDIUM | Targeted attacks |
| Session fixation | HIGH | Account takeover |
| Missing HttpOnly | MEDIUM | Cookie theft via XSS |
| No session timeout | LOW | Unauthorized access |
| Open redirect URI | HIGH | OAuth token theft |

## Integration with Other Skills

- **web-auth-bypass**: Use findings to chain authentication bypass attacks
- **web-xss**: Cookie analysis feeds directly into XSS exploitation strategy
- **security-review**: Automated auth testing as part of security review checklist
