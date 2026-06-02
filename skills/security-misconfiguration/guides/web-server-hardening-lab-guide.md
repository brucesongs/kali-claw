# Web Server Hardening Lab Guide

## Introduction

Web server misconfigurations expose applications to enumeration, data leakage, and exploitation. This lab guide covers hardening Apache, Nginx, and common application servers with practical configuration exercises.

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
```

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

## References

- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)
- [CIS Apache Benchmark](https://www.cisecurity.org/cis-benchmarks/)
- [Nginx Security Hardening Guide](https://docs.nginx.com/nginx/admin-guide/security-controls/)
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [testssl.sh](https://testssl.sh/)
