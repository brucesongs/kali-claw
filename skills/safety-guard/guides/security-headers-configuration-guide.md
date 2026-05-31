# Security Headers Configuration Guide

> Comprehensive reference for configuring HTTP security headers including Content-Security-Policy, HSTS, X-Frame-Options, and CORS. Covers deployment patterns for nginx, Apache, and application-level middleware.

---

## 1. Content-Security-Policy (CSP)

CSP prevents XSS by declaring which sources of content are trusted. Start strict and relax only when necessary.

```nginx
# nginx — Strict CSP for a modern web application
add_header Content-Security-Policy "
  default-src 'none';
  script-src 'self' https://cdn.example.com;
  style-src 'self' 'unsafe-inline';
  img-src 'self' data: https://images.example.com;
  font-src 'self' https://fonts.googleapis.com;
  connect-src 'self' https://api.example.com;
  frame-ancestors 'none';
  base-uri 'self';
  form-action 'self';
  upgrade-insecure-requests;
" always;
```

```python
# Python Flask — CSP with nonce-based script allowlisting
import secrets
from flask import Flask, g, render_template

app = Flask(__name__)

@app.before_request
def generate_csp_nonce():
    """Generate a unique nonce per request for inline scripts."""
    g.csp_nonce = secrets.token_urlsafe(32)

@app.after_request
def add_security_headers(response):
    nonce = getattr(g, 'csp_nonce', '')
    response.headers['Content-Security-Policy'] = (
        f"default-src 'none'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        f"style-src 'self'; "
        f"img-src 'self' data:; "
        f"connect-src 'self'; "
        f"frame-ancestors 'none'; "
        f"base-uri 'self'"
    )
    return response
```

## 2. HTTP Strict Transport Security (HSTS)

HSTS forces browsers to use HTTPS for all future requests to the domain. Once set, HTTP connections are automatically upgraded.

```nginx
# nginx — HSTS with preload readiness
# max-age=31536000 (1 year) is required for preload submission
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
```

```bash
# Verify HSTS header is correctly deployed
curl -sI https://target.com | grep -i strict-transport

# Check HSTS preload eligibility
# Requirements: valid cert, redirect HTTP->HTTPS, HSTS on root domain,
# max-age >= 31536000, includeSubDomains, preload directive
curl -sI http://target.com | grep -i location
# Should show 301/302 redirect to https://

# Test with ssllabs
# https://www.ssllabs.com/ssltest/analyze.html?d=target.com
```

## 3. X-Frame-Options and Frame-Ancestors

Prevent clickjacking by controlling whether your site can be embedded in frames.

```nginx
# nginx — Complete anti-clickjacking configuration
# X-Frame-Options for legacy browser support
add_header X-Frame-Options "DENY" always;

# CSP frame-ancestors is the modern replacement (supersedes X-Frame-Options)
# Use both for backward compatibility
add_header Content-Security-Policy "frame-ancestors 'none'" always;
```

```yaml
# Apache — .htaccess configuration
Header always set X-Frame-Options "SAMEORIGIN"
Header always set X-Content-Type-Options "nosniff"
Header always set X-XSS-Protection "0"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"
```

## 4. CORS Configuration

Cross-Origin Resource Sharing must be configured precisely. Overly permissive CORS negates same-origin protections.

```python
# Python Flask — Strict CORS configuration
from flask_cors import CORS

ALLOWED_ORIGINS = [
    'https://app.example.com',
    'https://admin.example.com',
]

def configure_cors(app):
    """Configure CORS with explicit origin allowlist."""
    CORS(app, resources={
        r"/api/*": {
            "origins": ALLOWED_ORIGINS,
            "methods": ["GET", "POST", "PUT", "DELETE"],
            "allow_headers": ["Authorization", "Content-Type", "X-Request-ID"],
            "expose_headers": ["X-RateLimit-Remaining", "X-Request-ID"],
            "supports_credentials": True,
            "max_age": 3600
        }
    })

# WRONG — never do this in production:
# CORS(app, origins="*", supports_credentials=True)
# Browsers reject credentials with wildcard origin anyway
```

## 5. Complete Security Headers Stack

```nginx
# nginx — Production-ready security headers block
server {
    listen 443 ssl http2;
    server_name app.example.com;

    # HSTS — force HTTPS for 1 year
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

    # Prevent MIME type sniffing
    add_header X-Content-Type-Options "nosniff" always;

    # Clickjacking protection
    add_header X-Frame-Options "DENY" always;

    # Disable XSS auditor (it causes more problems than it solves)
    add_header X-XSS-Protection "0" always;

    # Control referrer information leakage
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Restrict browser features
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;

    # CSP — adjust per application needs
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'" always;

    # Prevent caching of sensitive responses
    add_header Cache-Control "no-store, no-cache, must-revalidate" always;
}
```

## 6. Validation and Testing

```bash
# Scan security headers with curl
curl -sI https://target.com | grep -iE \
  "(strict-transport|content-security|x-frame|x-content-type|referrer-policy|permissions-policy)"

# Use securityheaders.com API for grading
curl -s "https://securityheaders.com/?q=https://target.com&followRedirects=on" \
  | grep -o 'class="[A-F][+-]*"'

# Test CSP violations with report-uri
# Add to CSP header for monitoring before enforcement:
# Content-Security-Policy-Report-Only: ...; report-uri /csp-report;
```

## 7. Header Priority Reference

| Header | Impact | Deployment Priority |
|--------|--------|-------------------|
| Content-Security-Policy | Prevents XSS, injection | Critical |
| Strict-Transport-Security | Forces HTTPS | Critical |
| X-Content-Type-Options | Prevents MIME sniffing | High |
| X-Frame-Options | Prevents clickjacking | High |
| Referrer-Policy | Controls info leakage | Medium |
| Permissions-Policy | Restricts browser APIs | Medium |
| Cache-Control | Prevents sensitive data caching | Context-dependent |

Deploy CSP in report-only mode first to identify violations before enforcement. Monitor reports for 1-2 weeks, then switch to enforcing mode.
