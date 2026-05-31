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
