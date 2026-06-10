# Web Server Hardening Guide

## Overview

Web server misconfiguration is a top attack vector. This guide covers hardening Apache, Nginx, and IIS against common security issues including information disclosure, default credentials, directory listing, and missing security headers.

---

## Information Disclosure

### Server Version Hiding

```nginx
# Nginx - hide version
server_tokens off;

# In response headers
# Before: Server: nginx/1.24.0
# After:  Server: nginx
```

```apache
# Apache - hide version and OS
ServerTokens Prod
ServerSignature Off

# Before: Server: Apache/2.4.57 (Ubuntu)
# After:  Server: Apache
```

```xml
<!-- IIS - remove version header -->
<system.webServer>
  <httpProtocol>
    <customHeaders>
      <remove name="X-Powered-By" />
    </customHeaders>
  </httpProtocol>
  <security>
    <requestFiltering removeServerHeader="true" />
  </security>
</system.webServer>
```

### Error Page Customization

```nginx
# Nginx - custom error pages (no stack traces)
error_page 404 /custom_404.html;
error_page 500 502 503 504 /custom_50x.html;

location = /custom_404.html {
    root /usr/share/nginx/html;
    internal;
}
```

```apache
# Apache - custom error documents
ErrorDocument 404 /errors/404.html
ErrorDocument 500 /errors/500.html
```

### PHP Information Disclosure

```ini
; php.ini
expose_php = Off
display_errors = Off
log_errors = On
error_log = /var/log/php/error.log
```

---

## Directory Listing Prevention

```nginx
# Nginx - disable autoindex globally
autoindex off;
```

```apache
# Apache - disable directory listing
<Directory /var/www/html>
    Options -Indexes
</Directory>

# Or via .htaccess
Options -Indexes
```

### Sensitive File Protection

```nginx
# Block access to hidden files and sensitive paths
location ~ /\. {
    deny all;
    return 404;
}

location ~* \.(git|svn|env|bak|old|sql|log|conf|ini)$ {
    deny all;
    return 404;
}

location ~ /(wp-config\.php|\.htaccess|\.htpasswd) {
    deny all;
}
```

```apache
# Apache - protect sensitive files
<FilesMatch "^\.">
    Require all denied
</FilesMatch>

<FilesMatch "\.(env|bak|old|sql|log)$">
    Require all denied
</FilesMatch>
```

---

## Security Headers

```nginx
# Nginx security headers
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
```

```apache
# Apache security headers
Header always set X-Frame-Options "SAMEORIGIN"
Header always set X-Content-Type-Options "nosniff"
Header always set X-XSS-Protection "1; mode=block"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
Header always set Content-Security-Policy "default-src 'self'"
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"
```

---

## TLS Configuration

```nginx
# Nginx - modern TLS configuration
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers off;
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:10m;
ssl_session_tickets off;
ssl_stapling on;
ssl_stapling_verify on;
```

### Certificate Validation

```bash
# Check certificate expiry
echo | openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -noout -dates

# Check for weak ciphers
nmap --script ssl-enum-ciphers -p 443 target.com

# Test with testssl.sh
./testssl.sh target.com
```

---

## Default Credentials Audit

### Common Default Credentials

| Service | Default User | Default Password |
|---------|-------------|-----------------|
| Tomcat Manager | tomcat | tomcat |
| Jenkins | admin | admin |
| phpMyAdmin | root | (empty) |
| Grafana | admin | admin |
| Kibana | elastic | changeme |
| WordPress | admin | admin |

### Automated Credential Testing

```bash
# Hydra against web login
hydra -l admin -P /usr/share/wordlists/common-passwords.txt target.com http-post-form "/login:user=^USER^&pass=^PASS^:Invalid"

# Nmap default credential scripts
nmap --script http-default-accounts -p 80,8080,8443 target.com

# Check for exposed admin panels
for path in /admin /manager /console /dashboard /phpmyadmin /wp-admin; do
    code=$(curl -s -o /dev/null -w "%{http_code}" "http://target.com$path")
    if [ "$code" != "404" ]; then
        echo "FOUND: $path (HTTP $code)"
    fi
done
```

---

## HTTP Method Restriction

```nginx
# Nginx - allow only GET, POST, HEAD
if ($request_method !~ ^(GET|POST|HEAD)$) {
    return 405;
}
```

```apache
# Apache - restrict methods
<LimitExcept GET POST HEAD>
    Require all denied
</LimitExcept>
```

### Testing Allowed Methods

```bash
# Check allowed methods
curl -X OPTIONS -i http://target.com/
curl -X TRACE -i http://target.com/
curl -X PUT -d "test" http://target.com/test.txt
curl -X DELETE http://target.com/test.txt
```

---

## Rate Limiting

```nginx
# Nginx rate limiting
limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
limit_req_zone $binary_remote_addr zone=api:10m rate=30r/m;

server {
    location /login {
        limit_req zone=login burst=3 nodelay;
    }
    location /api/ {
        limit_req zone=api burst=10 nodelay;
    }
}
```

```apache
# Apache mod_ratelimit
<Location /login>
    SetOutputFilter RATE_LIMIT
    SetEnv rate-limit 5
</Location>
```

---

## File Upload Security

```nginx
# Limit upload size
client_max_body_size 10m;

# Prevent execution in upload directory
location /uploads/ {
    location ~ \.(php|py|pl|cgi|sh|asp|jsp)$ {
        deny all;
    }
}
```

```apache
# Apache - prevent script execution in uploads
<Directory /var/www/html/uploads>
    php_admin_flag engine off
    <FilesMatch "\.(php|py|pl|cgi|sh)$">
        Require all denied
    </FilesMatch>
</Directory>
```

---

## Audit Checklist

- [ ] Server version headers hidden
- [ ] Custom error pages (no stack traces)
- [ ] Directory listing disabled
- [ ] Sensitive files blocked (.env, .git, backups)
- [ ] Security headers configured (CSP, HSTS, X-Frame-Options)
- [ ] TLS 1.2+ only, strong ciphers
- [ ] Default credentials changed
- [ ] Unnecessary HTTP methods disabled
- [ ] Rate limiting on auth endpoints
- [ ] File upload restrictions enforced
- [ ] Admin panels access-restricted
- [ ] PHP/ASP information disclosure disabled

---

## Logging and Monitoring Configuration

Proper logging configuration is essential for detecting attacks and investigating incidents. Web servers should log all requests with enough detail for forensic analysis without logging sensitive data.

### Nginx Logging

```nginx
# Custom log format with useful security information
log_format security '$remote_addr - $remote_user [$time_local] '
                    '"$request" $status $body_bytes_sent '
                    '"$http_referer" "$http_user_agent" '
                    '$request_time $upstream_response_time';

access_log /var/log/nginx/security.log security;
error_log /var/log/nginx/error.log warn;

# Log rate-limited requests
limit_req_log_level warn;

# Do not log health check requests
location /health {
    access_log off;
    return 200 "OK";
}
```

### Apache Logging

```apache
# Custom log format with additional security fields
LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" %D %{X-Forwarded-For}i" security
CustomLog /var/log/apache2/security.log security

# Do not log certain paths (reduce noise)
SetEnvIf Request_URI "^/health$" dontlog
CustomLog /var/log/apache2/access.log combined env=!dontlog
```

### Log Analysis for Security Events

```bash
# Find most frequent 404s (possible scanning activity)
awk '$9 == 404 {print $7}' /var/log/nginx/security.log | sort | uniq -c | sort -rn | head -20

# Find requests with suspicious user agents
grep -iE "nikto|nmap|sqlmap|dirbuster|gobuster|masscan" /var/log/nginx/security.log

# Find requests to sensitive paths
grep -iE "/\.env|/\.git|/admin|/phpmyadmin|/wp-config|/backup" /var/log/nginx/security.log

# Find potential SQL injection attempts
grep -iE "union.*select|or.*1=1|--|;.*drop|concat\(" /var/log/nginx/security.log

# Find requests with unusually large bodies (potential buffer overflow)
awk '$10 > 1000000 {print $0}' /var/log/nginx/security.log
```

---

## Reverse Proxy Security

When Nginx or Apache serves as a reverse proxy, additional hardening is needed to prevent proxy-based attacks.

### Nginx Reverse Proxy Hardening

```nginx
# Prevent Host header injection
server {
    listen 80;
    server_name _;  # Default server for unknown hosts
    return 444;     # Drop connection
}

# Actual server block
server {
    listen 80;
    server_name target.com;

    # Validate Host header
    if ($host != "target.com") {
        return 444;
    }

    location / {
        proxy_pass http://backend:8080;

        # Hide backend server information
        proxy_hide_header X-Powered-By;
        proxy_hide_header Server;

        # Prevent SSRF via proxy
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Block proxy access to internal networks
        # (prevent SSRF through the reverse proxy)
        # This must be handled at the application layer
    }
}
```

### Apache Reverse Proxy Hardening

```apache
# Prevent proxy requests to internal networks
<Proxy "http://127.0.0.1*">
    Require all denied
</Proxy>
<Proxy "http://10.*">
    Require all denied
</Proxy>
<Proxy "http://192.168.*">
    Require all denied
</Proxy>
<Proxy "http://169.254.*">
    Require all denied
</Proxy>

# Set proper headers
ProxyAddHeaders Off
RequestHeader set X-Forwarded-Proto "https"
RequestHeader set X-Forwarded-Port "443"
```

### WebSocket Proxy Security

```nginx
# WebSocket proxy with security hardening
location /ws/ {
    proxy_pass http://backend:8080;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";

    # Limit WebSocket message size (prevent large payload attacks)
    proxy_buffers 8 4k;

    # Timeout settings (prevent resource exhaustion)
    proxy_read_timeout 300s;
    proxy_send_timeout 300s;

    # Rate limit WebSocket connections
    limit_req zone=ws burst=5 nodelay;
}
```

---

## Content Security Policy (CSP) Configuration

CSP is one of the most powerful but often misconfigured security headers. A well-tuned CSP prevents XSS, clickjacking, and code injection. This section covers progressive CSP deployment, testing, and common patterns for different application types.

### Progressive CSP Deployment

```nginx
# Step 1: Report-only mode (monitor without blocking)
add_header Content-Security-Policy-Report-Only "default-src 'self'; report-uri /csp-report" always;

# Step 2: Restrictive CSP for production
add_header Content-Security-Policy "default-src 'self'; script-src 'self' https://cdn.trusted.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self' https://api.target.com; frame-ancestors 'none'; base-uri 'self'; form-action 'self'" always;
```

**CSP directive reference:**

| Directive | Purpose | Recommended Value |
|-----------|---------|-------------------|
| `default-src` | Fallback for all fetches | `'self'` |
| `script-src` | JavaScript sources | `'self'` (avoid `unsafe-inline`, `unsafe-eval`) |
| `style-src` | CSS sources | `'self' 'unsafe-inline'` (often required by frameworks) |
| `img-src` | Image sources | `'self' data: https:` |
| `connect-src` | AJAX/WebSocket targets | `'self'` plus specific API domains |
| `frame-ancestors` | Who can embed this page | `'none'` (replaces X-Frame-Options) |
| `base-uri` | Restricts `<base>` tag | `'self'` |
| `form-action` | Restricts form submissions | `'self'` |
| `object-src` | Flash/Java plugins | `'none'` |

### CSP Testing Workflow

```bash
# Start with report-only mode and collect violations
# Monitor /csp-report endpoint for violation reports
curl -s "https://target.com/csp-reports" | jq '.[] | .["violated-directive"]' | sort | uniq -c | sort -rn

# Common CSP violations and their fixes:
# 1. inline scripts → Move to external files, use nonces or hashes
# 2. eval() usage → Refactor code to avoid eval, new Function()
# 3. CDN resources → Add specific CDN domains to script-src
# 4. Inline styles → Add 'unsafe-inline' to style-src (acceptable risk)

# Generate CSP nonces in Nginx
# Requires ngx_http_sub_module or Lua module
# Example with Nginx JavaScript:
js_set $csp_nonce "function() { return require('crypto').randomBytes(16).toString('base64') }";
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'nonce-$csp_nonce'" always;
```

### CSP for Specific Frameworks

**React/Next.js CSP:**

```nginx
# React applications often need specific CSP settings
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-eval' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: https:; connect-src 'self' https://api.target.com https://*.sentry.io" always;
# Note: 'unsafe-eval' is needed by some bundlers; remove in production if possible
```

**Django CSP (via django-csp middleware):**

```python
# settings.py
CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = ("'self'",)
CSP_STYLE_SRC = ("'self'", "'unsafe-inline'")  # Django admin needs inline styles
CSP_IMG_SRC = ("'self'", "data:")
CSP_CONNECT_SRC = ("'self'",)
CSP_FRAME_ANCESTORS = ("'none'",)
CSP_REPORT_URI = "/csp-report/"
CSP_REPORT_ONLY = False  # Set True during testing
```

CSP is one of the most powerful but often misconfigured security headers. A well-tuned CSP prevents XSS, clickjacking, and code injection.

### Progressive CSP Deployment

```nginx
# Step 1: Report-only mode (monitor without blocking)
add_header Content-Security-Policy-Report-Only "default-src 'self'; report-uri /csp-report" always;

# Step 2: Restrictive CSP for production
add_header Content-Security-Policy "default-src 'self'; script-src 'self' https://cdn.trusted.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self' https://api.target.com; frame-ancestors 'none'; base-uri 'self'; form-action 'self'" always;
```

**CSP directive reference:**

| Directive | Purpose | Recommended Value |
|-----------|---------|-------------------|
| `default-src` | Fallback for all fetches | `'self'` |
| `script-src` | JavaScript sources | `'self'` (avoid `unsafe-inline`, `unsafe-eval`) |
| `style-src` | CSS sources | `'self' 'unsafe-inline'` (often required by frameworks) |
| `img-src` | Image sources | `'self' data: https:` |
| `connect-src` | AJAX/WebSocket targets | `'self'` plus specific API domains |
| `frame-ancestors` | Who can embed this page | `'none'` (replaces X-Frame-Options) |
| `base-uri` | Restricts `<base>` tag | `'self'` |
| `form-action` | Restricts form submissions | `'self'` |
| `object-src` | Flash/Java plugins | `'none'` |

### CSP Testing Workflow

```bash
# Start with report-only mode and collect violations
# Monitor /csp-report endpoint for violation reports
curl -s "https://target.com/csp-reports" | jq '.[] | .["violated-directive"]' | sort | uniq -c | sort -rn

# Common CSP violations and their fixes:
# 1. inline scripts → Move to external files, use nonces or hashes
# 2. eval() usage → Refactor code to avoid eval, new Function()
# 3. CDN resources → Add specific CDN domains to script-src
# 4. Inline styles → Add 'unsafe-inline' to style-src (acceptable risk)

# Generate CSP nonces in Nginx
# Requires ngx_http_sub_module or Lua module
# Example with Nginx JavaScript:
js_set $csp_nonce "function() { return require('crypto').randomBytes(16).toString('base64') }";
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'nonce-$csp_nonce'" always;
```

---

## Hands-on Exercises

1. **Exercise 1**: Deploy Apache with default configuration. Run Nikto and document all findings. Apply every hardening step from this guide and re-run Nikto. Create a before/after comparison table showing eliminated findings
2. **Exercise 2**: Configure Nginx as a reverse proxy for a backend application. Implement all security headers, rate limiting, and TLS hardening. Test with testssl.sh and aim for an A+ rating on SecurityHeaders.com
3. **Exercise 3**: Set up a custom log format in Nginx that captures security-relevant information. Simulate common attacks (directory traversal, SQL injection, XSS) and verify that each attack is logged with enough detail for forensic analysis
4. **Exercise 4**: Build an automated hardening verification script that checks all items in the audit checklist above, outputs pass/fail for each, and provides the specific command or configuration needed to fix any failures
