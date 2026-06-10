# Web Server Hardening Lab Guide

## Introduction

Web server misconfigurations expose applications to enumeration, data leakage, and exploitation. This lab guide covers hardening Apache, Nginx, and common application servers with practical configuration exercises. Each section provides before-and-after verification commands so you can measure the security improvement from each hardening step.

This guide is designed as a hands-on lab. You will need a Linux environment (Kali, Ubuntu, or Docker) with Apache and Nginx installed. All configurations can be tested safely in a local environment.

**Lab prerequisites:**
- Linux environment with root/sudo access
- Apache2 and Nginx installed (`apt install apache2 nginx`)
- OpenSSL for certificate testing
- curl, nmap, nikto for verification
- testssl.sh for TLS auditing

## Practical Steps

### 1. Apache Hardening

```apache
# /etc/apache2/conf-available/security-hardened.conf

# Hide server version
ServerTokens Prod
ServerSignature Off

# Disable directory listing
Options -Indexes

# Security headers
Header always set X-Content-Type-Options "nosniff"
Header always set X-Frame-Options "DENY"
Header always set X-XSS-Protection "1; mode=block"
Header always set Content-Security-Policy "default-src 'self'"
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"

# Disable unnecessary modules
# a2dismod autoindex cgi env imap include ldap userdir
```

**Additional Apache hardening:**

```apache
# /etc/apache2/conf-available/security-hardened.conf (continued)

# Prevent MIME type sniffing
Header always set X-Content-Type-Options "nosniff"

# Clickjacking protection
Header always set X-Frame-Options "SAMEORIGIN"

# Referrer policy
Header always set Referrer-Policy "strict-origin-when-cross-origin"

# Permissions policy
Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"

# Disable ETag headers (prevents inode disclosure)
FileETag None

# Timeout settings (prevent slowloris attacks)
Timeout 60
KeepAliveTimeout 5
MaxRequestWorkers 150

# Request size limits
LimitRequestBody 10485760
LimitRequestFields 50
LimitRequestFieldSize 4096
LimitRequestLine 8190

# Protect sensitive files
<FilesMatch "^\.">
    Require all denied
</FilesMatch>

<FilesMatch "\.(env|bak|old|sql|log|conf|ini|sh)$">
    Require all denied
</FilesMatch>

# Disable server-status and server-info
<LocationMatch "/(server-status|server-info)">
    Require all denied
</LocationMatch>
```

### 2. Nginx Hardening

```nginx
# /etc/nginx/conf.d/security-hardened.conf

# Hide version
server_tokens off;

# Security headers
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Content-Security-Policy "default-src 'self'" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;

# Disable unnecessary HTTP methods
if ($request_method !~ ^(GET|HEAD|POST)$ ) {
    return 405;
}

# SSL configuration (modern)
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
ssl_prefer_server_ciphers on;
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:50m;

# Buffer size limits
client_body_buffer_size 1K;
client_header_buffer_size 1k;
client_max_body_size 10m;
large_client_header_buffers 2 1k;
```

**Additional Nginx hardening:**

```nginx
# /etc/nginx/conf.d/security-hardened.conf (continued)

# Prevent clickjacking with allow-from specific domain
add_header X-Frame-Options "SAMEORIGIN" always;

# Disable content type sniffing
add_header X-Content-Type-Options "nosniff" always;

# Permissions policy
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;

# Rate limiting zones (define in http block)
limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
limit_req_zone $binary_remote_addr zone=api:10m rate=30r/m;
limit_req_zone $binary_remote_addr zone=general:10m rate=100r/m;

# Apply rate limiting to specific locations
# location /login {
#     limit_req zone=login burst=3 nodelay;
# }
# location /api/ {
#     limit_req zone=api burst=10 nodelay;
# }

# Block sensitive file access
location ~ /\. {
    deny all;
    return 404;
}

location ~* \.(git|svn|env|bak|old|sql|log|conf|ini|sh)$ {
    deny all;
    return 404;
}

# Block access to WordPress config
location ~* /wp-config\.php {
    deny all;
}

# Prevent image hotlinking (optional)
# location ~* \.(jpg|jpeg|png|gif|webp)$ {
#     valid_referers none blocked server_names;
#     if ($invalid_referer) {
#         return 403;
#     }
# }

# SSL stapling
ssl_stapling on;
ssl_stapling_verify on;
resolver 8.8.8.8 8.8.4.4 valid=300s;
resolver_timeout 5s;
```

### 3. TLS Configuration Testing

```bash
# Test SSL/TLS configuration
testssl https://target.com

# Quick check for common issues
nmap --script ssl-enum-ciphers -p 443 target.com

# Check certificate validity
echo | openssl s_client -connect target.com:443 2>/dev/null | \
  openssl x509 -noout -dates -subject -issuer

# Verify HSTS preload eligibility
curl -sI https://target.com | grep -i strict-transport

# Check for weak ciphers specifically
nmap --script ssl-enum-ciphers -p 443 target.com | \
  grep -iE "least strength|weak|insecure"
```

**TLS hardening verification checklist:**

| Check | Command | Expected Result |
|-------|---------|-----------------|
| No SSLv3 | `openssl s_client -ssl3 -connect target:443` | Connection refused/handshake failure |
| No TLS 1.0 | `openssl s_client -tls1 -connect target:443` | Connection refused/handshake failure |
| No TLS 1.1 | `openssl s_client -tls1_1 -connect target:443` | Connection refused/handshake failure |
| TLS 1.2 works | `openssl s_client -tls1_2 -connect target:443` | Successful connection |
| TLS 1.3 works | `openssl s_client -tls1_3 -connect target:443` | Successful connection |
| HSTS present | `curl -sI target:443 \| grep Strict` | `max-age=31536000; includeSubDomains` |
| Strong ciphers | `testssl.sh -E target:443` | No A, B, or C rated ciphers |

### 4. Information Disclosure Prevention

```bash
# Test for information disclosure
# Check server headers
curl -sI https://target.com | grep -iE "server:|x-powered-by:|x-aspnet-version:"

# Check for common sensitive files
for path in /.git/HEAD /.env /wp-config.php /robots.txt /.svn/entries /config.yml /backup.sql; do
  status=$(curl -so /dev/null -w "%{http_code}" "https://target.com$path")
  [ "$status" != "404" ] && echo "FOUND $status: $path"
done

# Check error page information leakage
curl -s https://target.com/nonexistent_path_12345 | \
  grep -iE "stack trace|error|exception|debug|version|apache|nginx|php"
```

**Testing HTTP methods for information disclosure:**

```bash
# Check which HTTP methods are allowed
curl -X OPTIONS -i http://target.com/ 2>/dev/null | grep -i "allow:"

# Test dangerous methods
for method in PUT DELETE TRACE CONNECT PATCH; do
  status=$(curl -X "$method" -s -o /dev/null -w "%{http_code}" "http://target.com/")
  echo "$method: $status"
done

# TRACE should always return 405 (prevents XST attacks)
# PUT/DELETE should return 405 unless intentionally enabled
```

### 5. Lab Exercise: Harden a Vulnerable Server

```bash
# Setup vulnerable test server (Docker)
docker run -d --name vulnerable-web -p 8080:80 vulnerable/nginx:latest

# Before hardening — document findings
nmap -sV -p 8080 localhost
curl -sI http://localhost:8080
nikto -h http://localhost:8080

# Apply hardening configurations
# (edit configs from sections above)

# After hardening — verify improvements
nmap -sV -p 8080 localhost
curl -sI http://localhost:8080
nikto -h http://localhost:8080
```

**Lab scoring matrix:**

| Hardening Action | Points | Verification Command |
|-----------------|--------|---------------------|
| Server version hidden | 10 | `curl -sI target \| grep Server` |
| Directory listing disabled | 10 | `curl target/uploads/` |
| All 6 security headers present | 20 | `curl -sI target \| grep -c "X-\|Strict\|Content-Security"` |
| TLS 1.2+ only | 20 | `testssl.sh target` |
| Sensitive files blocked | 15 | `curl target/.env` |
| Default page removed | 5 | `curl target/` (should not show default page) |
| Unnecessary methods disabled | 10 | `curl -X TRACE target` |
| Custom error pages | 10 | `curl target/nonexistent` (no stack trace) |
| **Total** | **100** | |

## Hands-on Exercises

1. **Exercise 1**: Deploy an intentionally vulnerable Apache container. Run Nikto and document all findings. Apply the hardening configurations from this guide. Run Nikto again and document the improvement in the scan results. Calculate your score using the lab scoring matrix above
2. **Exercise 2**: Configure Nginx as a reverse proxy with TLS termination. Generate a self-signed certificate, configure modern TLS settings, and verify the configuration with testssl.sh. Aim for an A rating on SSL Labs
3. **Exercise 3**: Build an automated hardening verification script that checks all items in the Apache/Nginx hardening checklist and outputs a pass/fail report with specific remediation commands for each failure

## Automated Verification Script

Use this script to verify that all hardening measures are properly applied:

```bash
#!/bin/bash
# verify-hardening.sh — Automated web server hardening verification

TARGET="$1"
SCORE=0
TOTAL=100

echo "=== Web Server Hardening Verification ==="
echo "Target: $TARGET"
echo "Date: $(date -Iseconds)"
echo ""

# Check 1: Server version hidden (10 points)
server_header=$(curl -sI "https://$TARGET" | grep -i "^server:" | head -1)
if echo "$server_header" | grep -qE "[0-9]+\.[0-9]+"; then
  echo "[FAIL] Server version exposed: $server_header (-10 points)"
else
  echo "[PASS] Server version hidden"
  SCORE=$((SCORE + 10))
fi

# Check 2: Security headers present (20 points)
headers=$(curl -sI "https://$TARGET")
header_count=0
for header in "Strict-Transport-Security" "Content-Security-Policy" "X-Frame-Options" "X-Content-Type-Options"; do
  if echo "$headers" | grep -qi "$header"; then
    header_count=$((header_count + 1))
  else
    echo "[FAIL] Missing header: $header"
  fi
done
if [ "$header_count" -eq 4 ]; then
  echo "[PASS] All 4 security headers present"
  SCORE=$((SCORE + 20))
else
  echo "[PARTIAL] $header_count/4 security headers present (+$((header_count * 5)) points)"
  SCORE=$((SCORE + header_count * 5))
fi

# Check 3: Directory listing disabled (10 points)
dir_listing=$(curl -s "https://$TARGET/uploads/" | grep -ci "index of")
if [ "$dir_listing" -gt 0 ]; then
  echo "[FAIL] Directory listing enabled on /uploads/ (-10 points)"
else
  echo "[PASS] Directory listing disabled"
  SCORE=$((SCORE + 10))
fi

# Check 4: Sensitive files blocked (15 points)
sensitive_found=0
for path in /.git/HEAD /.env /.htaccess /web.config /backup.sql; do
  status=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET$path")
  if [ "$status" = "200" ]; then
    echo "[FAIL] Sensitive file accessible: $path (HTTP $status)"
    sensitive_found=$((sensitive_found + 1))
  fi
done
if [ "$sensitive_found" -eq 0 ]; then
  echo "[PASS] No sensitive files accessible"
  SCORE=$((SCORE + 15))
fi

# Check 5: TLS configuration (20 points)
if command -v testssl.sh &>/dev/null; then
  tls_result=$(testssl.sh --quiet "$TARGET:443" 2>&1)
  if echo "$tls_result" | grep -q "TLS 1.0\|TLS 1.1\|SSLv3"; then
    echo "[FAIL] Weak TLS protocol versions detected"
  else
    echo "[PASS] TLS 1.2+ only"
    SCORE=$((SCORE + 20))
  fi
else
  echo "[SKIP] testssl.sh not installed (cannot verify TLS)"
fi

# Check 6: HTTP methods restricted (10 points)
trace_status=$(curl -sk -o /dev/null -w "%{http_code}" -X TRACE "https://$TARGET/")
if [ "$trace_status" = "200" ]; then
  echo "[FAIL] TRACE method enabled (-10 points)"
else
  echo "[PASS] TRACE method disabled"
  SCORE=$((SCORE + 10))
fi

# Check 7: Custom error pages (10 points)
error_check=$(curl -sk "https://$TARGET/nonexistent_path_test_12345" | grep -ciE "stack trace|exception|debug|traceback")
if [ "$error_check" -gt 0 ]; then
  echo "[FAIL] Error page leaks technical information"
else
  echo "[PASS] Error pages do not leak technical information"
  SCORE=$((SCORE + 10))
fi

# Check 8: Default page removed (5 points)
default_check=$(curl -sk "https://$TARGET/" | grep -ciE "welcome to nginx|apache2 ubuntu default|it works|iis")
if [ "$default_check" -gt 0 ]; then
  echo "[FAIL] Default server page still present"
else
  echo "[PASS] Default page removed"
  SCORE=$((SCORE + 5))
fi

echo ""
echo "=== Hardening Score: $SCORE/$TOTAL ==="
if [ "$SCORE" -ge 90 ]; then
  echo "Grade: A (Excellent)"
elif [ "$SCORE" -ge 80 ]; then
  echo "Grade: B (Good)"
elif [ "$SCORE" -ge 70 ]; then
  echo "Grade: C (Needs improvement)"
else
  echo "Grade: F (Critical issues found)"
fi
```

## IIS Hardening (Windows)

For Windows environments running IIS, apply these hardening measures:

```xml
<!-- web.config — IIS security hardening -->
<system.webServer>
  <!-- Remove unnecessary headers -->
  <httpProtocol>
    <customHeaders>
      <remove name="X-Powered-By" />
      <remove name="Server" />
      <add name="X-Content-Type-Options" value="nosniff" />
      <add name="X-Frame-Options" value="SAMEORIGIN" />
      <add name="Content-Security-Policy" value="default-src 'self'" />
      <add name="Strict-Transport-Security" value="max-age=31536000; includeSubDomains" />
      <add name="Referrer-Policy" value="strict-origin-when-cross-origin" />
    </customHeaders>
  </httpProtocol>

  <!-- Request filtering -->
  <security>
    <requestFiltering removeServerHeader="true">
      <!-- Block dangerous file extensions -->
      <fileExtensions allowUnlisted="true">
        <add fileExtension=".config" allowed="false" />
        <add fileExtension=".bak" allowed="false" />
        <add fileExtension=".sql" allowed="false" />
        <add fileExtension=".log" allowed="false" />
        <add fileExtension=".env" allowed="false" />
      </fileExtensions>
      <!-- Block hidden segments -->
      <hiddenSegments>
        <add segment=".git" />
        <add segment=".svn" />
        <add segment=".env" />
        <add segment="App_Data" />
        <add segment="bin" />
      </hiddenSegments>
      <!-- Limit request size -->
      <requestLimits maxAllowedContentLength="10485760" maxQueryString="2048" maxUrl="4096" />
    </requestFiltering>
  </security>

  <!-- Custom error pages -->
  <httpErrors errorMode="Custom" existingResponse="Replace">
    <remove statusCode="404" />
    <remove statusCode="500" />
    <error statusCode="404" path="/errors/404.html" responseMode="File" />
    <error statusCode="500" path="/errors/500.html" responseMode="File" />
  </httpErrors>
</system.webServer>
```

```xml
<!-- machine-level web.config for debug mode off -->
<system.web>
  <deployment retail="true" />
  <compilation debug="false" />
  <customErrors mode="On" defaultRedirect="/errors/error.html" />
  <trace enabled="false" />
  <httpRuntime enableVersionHeader="false" requestValidationMode="4.5" />
</system.web>
```

## References

- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)
- [CIS Apache Benchmark](https://www.cisecurity.org/cis-benchmarks/)
- [Nginx Security Hardening Guide](https://docs.nginx.com/nginx/admin-guide/security-controls/)
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [testssl.sh](https://testssl.sh/)
- [SSL Labs Server Test](https://www.ssllabs.com/ssltest/)
- [Apache Security Tips](https://httpd.apache.org/docs/2.4/misc/security_tips.html)
- [IIS Security Best Practices](https://learn.microsoft.com/en-us/iis/get-started/whats-new-in-iis-10/http-strict-transport-security-iis)
