# Tor .onion Crawl & Intelligence Gathering Playbook

> Deep-dive companion to `skills/darkweb-intel/SKILL.md` and `guides/dark-web-investigation-playbook.md`.
>
> Audience: OSINT investigators and threat-intel analysts who already know how to launch the Tor Browser and want a battle-tested playbook for crawling `.onion` services at scale — enumerating marketplaces, forums, and paste sites without burning their cover identity or contaminating the dataset with clearnet leakage.
>
> Scope: Tor `.onion` v3 services (56-char addresses), onion-to-onion crawling, marketplace/forum enumeration, breach-data market monitoring, and the OPSEC discipline that investigator-side scraping demands. I2P eepsites are mentioned for context but not deeply covered here — see `payloads.md` for the I2P setup commands.

---

## 1. Why a Crawl Playbook, Not Just `torify wget`

`torify wget -r -l 2 http://exampleonion.onion` produces a directory full of HTML in 10 minutes. The trap is treating that directory as the deliverable. A defensible dark-web crawl produces:

1. **Provenance-preserving capture** — every page saved with timestamp, response headers, exit-node fingerprint, and a SHA-256 hash for chain-of-custody.
2. **Isolation from the investigator's identity** — no clearnet DNS leak, no clearnet cookie jar, no shared browser profile with the analyst's personal accounts.
3. **Rate-limited, identifiable traffic** — high-speed crawlers trip forum anti-bot protections in minutes and get the exit node (or the investigator's persona) banned.
4. **Structured extraction** — forum posts, marketplace listings, threat-actor handles, Monero wallet addresses, and PGP fingerprints normalized into a queryable store.
5. **Durable references** — `.onion` URLs disappear weekly. The deliverable must use PGP fingerprints, wallet addresses, and screenshot hashes that survive URL rotation.
6. **OPSEC verification** — start-of-session and end-of-session checks confirming no clearnet leakage, no persona contamination, no host-side artifacts.
7. **Legal/ethical posture** — written scope, no purchasing of contraband, no undercover interaction without authorization, no distribution of CSAM/PII discovered in the wild.

This guide walks through all seven, in order, with the exact commands, decision points, and references.

---

## 2. Pre-Flight: Scope, Authority, and Isolation Strategy

Before any active crawling, answer these — in writing, in the statement of work or rules of engagement:

- **What's the investigative question?** "Map the dark-web footprint of threat actor X" yields a different crawl than "monitor breach forum Y for our employee emails" or "track listing volumes for product Z on marketplace W". The question defines seed lists, depth, and frequency.
- **What's the authorized footprint?** Specific `.onion` services? All services linked from a seed list? Forums where registration is required? Get explicit authorization for any forum you intend to register on — undercover participation without sign-off is a fast track to an HR/legal escalation.
- **What's the data-handling policy?** Breach data often contains PII, sometimes CSAM. Decide before crawling how you'll handle incidental discovery of CSAM (mandatory reporting in many jurisdictions), how you'll segregate PII, and who in the org is cleared to see raw captures.
- **What's the publication scope?** Internal-only report? Customer-facing? Law-enforcement referral? Each has different redaction standards.
- **Is purchasing authorized?** Most dark-web investigations stop at listing enumeration. Purchasing contraband or stolen data for "verification" is almost never authorized and creates evidence-handling problems even when it is.
- **What's the OPSEC posture?** Dedicated hardware? Whonix VM? Tails bootable USB? Each has different isolation guarantees and different failure modes.

If any of these are unclear, stop and resolve before proceeding. Forum registration and breach-data downloads are the two most common "we didn't realize that was in scope" escalations.

### 2.1 Isolation architecture decision tree

| Posture | When to use | Setup effort | OPSEC risk |
|---------|-------------|--------------|------------|
| Tor Browser on host | Never for real investigations | Low | High — clearnet identity exposure via host DNS, cookies, browser fingerprint |
| Tails bootable USB | One-off lookups, field triage | Medium | Low if rebooted between sessions; no host persistence |
| Whonix gateway + workstation VMs | Sustained investigations, persona-based forum work | High | Very low — workstation cannot leak without compromising the gateway |
| Dedicated crawl box (Whonix + scrapy + Postgres) | High-volume enumeration | Very high | Lowest — physical separation, network-segmented, snapshot-revertible |

For anything beyond a 5-minute lookup, use Whonix or a dedicated crawl box. Tor Browser on the host is for emergency lookups only, never for sustained work.

---

## 3. Tor Setup with Hardened Isolation

### 3.1 Whonix gateway + workstation (recommended baseline)

Whonix splits Tor into two VMs: the gateway (runs Tor, forces all workstation traffic through it) and the workstation (runs the browser/crawler, cannot reach the network directly). Even a root compromise of the workstation cannot leak the investigator's real IP — the gateway enforces the routing.

```bash
# Download Whonix from https://www.whonix.org/wiki/Virtual_Box
# Import the OVA into VirtualBox/KVM, boot gateway first, then workstation.

# In the gateway, confirm Tor is running and the control port is up
sudo systemctl status tor@default
# Active: active (running) — Tor is up

# Confirm the workstation has no clearnet path
# In the workstation:
ip route
# default via 10.152.152.10 — all traffic routes through the gateway
curl --max-time 5 https://check.torproject.org/api/ip 2>&1 | head -5
# Expected: {"IsTor":true, "IP":"<exit-node-IP>"}
# If IsTor:false — STOP. You have a leak. Do not proceed.

# Verify DNS is going through Tor (not the host resolver)
sudo tcpdump -i eth0 -n port 53
# In another terminal, browse somewhere. All DNS should be TCP/9040
# (Tor's transparent DNS proxy), not UDP/53 to an external resolver.
```

### 3.2 Tails for field work

Tails routes everything through Tor and forgets everything on reboot — ideal for one-off lookups on shared hardware.

```bash
# Write Tails to a USB stick
sudo dd if=tails-amd64-*.img of=/dev/sdX bs=16M status=progress conv=fsync
# Boot from the USB (not the internal disk). Set an administration password
# at the greeter if you need root for tooling.

# After boot, confirm Tor
curl --silent https://check.torproject.org/api/ip
# {"IsTor":true, ...}

# Configure persistent storage (encrypted) only if you intentionally want
# data to survive reboot — by default Tails forgets everything, which is
# usually what you want for OPSEC.
```

### 3.3 Bridges and pluggable transports

If Tor is blocked at the network level (corporate guest Wi-Fi, hotel, hostile jurisdiction), use obfs4 bridges or Snowflake:

```bash
# In Tor Browser / Whonix: configure bridges via the connection wizard.
# Snowflake is the easiest to bootstrap — it tunnels through WebRTC volunteers.
# obfs4 is more reliable for hostile DPI but requires published bridge lines.

# Fetch fresh bridges (do this from a clearnet connection — bridge distribution
# over .onion is a chicken-and-egg problem)
# https://bridges.torproject.org/  (web form)
# or email bridges@torproject.org from a Riseup/ProtonMail account
```

### 3.4 OPSEC baseline — run before every session

```bash
# 1. Verify Tor exit
curl --silent --max-time 10 https://check.torproject.org/api/ip | jq

# 2. Confirm no clearnet DNS leak
sudo tcpdump -i any -n -c 50 'port 53 and not port 5353' & sleep 5; kill %1
# Only Tor DNS (TCP 9040) should appear, no UDP/53 to external resolvers.

# 3. Check the workstation's clearnet identity is not loaded
# No personal SSH keys, no personal PGP keys, no personal browser profile
ls -la ~/.ssh/ ~/.gnupg/ 2>&1 | head
# Should be empty or contain only persona-specific material.

# 4. Verify the time zone is UTC (not your local zone)
date
sudo timedatectl set-timezone UTC
# Local timezone leaks region — adversary can correlate.

# 5. Verify the hostname is generic
hostname
# Whonix ships with 'host' — if it's your real hostname, change it.

# 6. Snapshot the VM state (VirtualBox/KVM)
# VBoxManage snapshot "<vm>" take "pre-session-$(date -u +%Y%m%dT%H%M%SZ)"
# So you can revert to a known-clean state at end of session.
```

---

## 4. Onion Service Discovery & Resolution

### 4.1 Discovery surfaces (clearnet indices of .onion)

Start with clearnet indices — they're faster, more stable, and don't expose the investigator to the underlying services:

| Source | URL | Coverage | Notes |
|--------|-----|----------|-------|
| Ahmia | ahmia.fi | General-purpose search | Largest indexed surface; provides REST API |
| Torch | torchdeeqk6u4kuxc.onion (was) | General-purpose | Service occasionally rotates; check dark.fail |
| dark.fail | dark.fail | High-profile verified services | Gold-standard for "is this URL still alive" |
| Onionland | onionland.io | Search + categorization | Useful for topic discovery |
| Haystak | haystak5atjsz2r1.onion (was) | Large indexed corpus | Quality variable; cross-check results |
| IntelX | intelx.io | Breach data, paste sites | Commercial; best for breach/leak lookups |

```bash
# Ahmia's clearnet search returns JSON
curl --silent "https://ahmia.fi/api/search/?search=marketplace+drugs&limit=50" | jq '.results[] | {title, url, description}'

# dark.fail verifies that a listed .onion is online and is the legitimate service
curl --silent "https://dark.fail/" | grep -E 'href.*\.onion' | head
# Only trust URLs from dark.fail's verified list — phishers clone marketplaces.
```

### 4.2 .onion resolution — v3 addresses

Tor v3 onion services use 56-character addresses derived from the service's ed25519 public key. There is no central DNS — an address either resolves (the service is up and the address is correct) or it doesn't.

```bash
# Resolve and probe a known v3 address
torify curl --silent --max-time 30 -I http://duckduckgogg42yfjl2i2f4nphnu3tthd5wuc3oqf6r7zlksxlpfd.onion/
# HTTP/1.1 200 OK — service is alive.
# 503 / connection refused — service is down or has moved.

# Use torsocks (preferred over torify — better error handling)
torsocks curl --silent --max-time 30 -o /dev/null -w "%{http_code} %{time_total}s\n" \
  http://exampleonion.onion/

# Batch-check a list of seeds
cat seeds.txt | while read onion; do
  printf "%-60s " "$onion"
  torsocks curl --silent --max-time 20 -o /dev/null -w "%{http_code}\n" "http://$onion/" \
    || echo "TIMEOUT"
done | tee seed-check-$(date -u +%Y%m%d).txt
```

### 4.3 Onionbalance and vanguards — for crawling high-traffic services

`.onion` services that receive a lot of traffic (large marketplaces, popular forums) use Onionbalance to distribute load across multiple backend instances behind a single address, and Vanguards to defend against guard-discovery attacks. As a crawler, this matters because:

- A single `.onion` may have multiple backend IPs that rotate — rate-limit on the address, not the IP.
- The same content may be served from different backends with subtly different timestamps — normalize on content hash, not response time.

You don't run these — you observe their effect on the services you're crawling.

---

## 5. OnionScan Automation — Service Enumeration

OnionScan is the workhorse for `.onion` service enumeration: it identifies the server software, extracts metadata, finds linked services, and checks for common OPSEC mistakes on the operator's side (which is often the most valuable intelligence — operators who leak their real IP or SSH key leave a trail).

### 5.1 Single-service scan

```bash
# Install OnionScan
go install github.com/s-rah/onionscan/v3/onionscan@latest
# Or grab a prebuilt binary from github.com/s-rah/onionscan/releases

# Basic scan of one service
torsocks onionscan --verbose http://exampleonion.onion/ 2>&1 | tee onionscan-example-$(date -u +%Y%m%d).json

# Key fields to capture from the JSON report:
# - SSHKey:        if the operator reused an SSH key on a clearnet box, pivot is possible
# - ApacheModStatus / NginxStatus: leaks internal paths and client IPs
# - IndexedDirectories: open directory listings
# - RelatedServices: other .onions run by the same operator
# - BitcoinAddresses / MoneroAddresses: payment surface
# - PGPKeyFingerprints: durable identifier for the operator
# - AnalyticsID: Google/PIA analytics IDs — operators sometimes reuse them on clearnet
```

### 5.2 Bulk scan with correlation

```bash
# Scan a seed list, accumulating reports
mkdir -p onionscan-reports
while read onion; do
  echo "[*] $onion"
  torsocks onionscan --jsonReport --timeout 60 \
    "http://${onion}/" > "onionscan-reports/${onion}.json" 2>/dev/null
done < seeds.txt

# Cross-correlate: find services sharing SSH keys (same operator)
jq -r 'select(.SSHKey) | {onion: .onion, key: .SSHKey}' onionscan-reports/*.json \
  | jq -s 'group_by(.key) | map({key: .[0].key, onions: [.[].onion]})'

# Cross-correlate: shared PGP fingerprints
jq -r 'select(.PGPKeyFingerprints) | .onion as $o | .PGPKeyFingerprints[] | {onion: $o, fingerprint: .}' \
  onionscan-reports/*.json | jq -s 'group_by(.fingerprint)'

# Cross-correlate: shared Monero wallet addresses (subaddress reuse = same operator)
jq -r 'select(.MoneroAddresses) | .onion as $o | .MoneroAddresses[] | {onion: $o, addr: .}' \
  onionscan-reports/*.json | jq -s 'group_by(.addr)'
```

### 5.3 Operator OPSEC mistakes — the highest-value findings

OnionScan finds what the operator did wrong. Common findings and their pivot value:

| Finding | Pivot value |
|---------|-------------|
| SSH public key leaked | Fingerprint in clearnet `authorized_keys` = real identity |
| Analytics ID (Google/PIA) | Same ID on a clearnet site = same operator |
| Apache mod_status exposed | Internal IPs, request URLs — sometimes real client IP if backend is misconfigured |
| Exposed `.git/` directory | Commit emails, sometimes the developer's real name |
| phpinfo() exposed | Real path structure, environment variables, sometimes internal hostnames |
| Open directory listing | Database dumps, config files, backup archives |
| TLS cert with CN/SAN matching clearnet domain | Catastrophic — direct attribution |

Always preserve these as separate evidence items with screenshots — they're the findings most likely to warrant a separate, more sensitive appendix to the deliverable.

---

## 6. Crawling with Scrapy + Polipo Chain

For sustained enumeration, a `scrapy` spider running through Tor gives you rate-limited, parseable, restartable crawling with structured output.

### 6.1 The proxy chain

Tor provides SOCKS5 on `127.0.0.1:9050` (or the Whonix gateway's internal address). Polipo (or its successor, Privoxy) bridges SOCKS to HTTP for tools that only speak HTTP proxies — but modern scrapy speaks SOCKS directly.

```bash
# Option A: direct SOCKS5 in scrapy (preferred)
pip install scrapy pysocks
# In settings.py:
# DOWNLOADER_MIDDLEWARES = {
#     'socks5.middleware.Socks5ProxyDownloaderMiddleware': 100,
# }
# SOCKS5_PROXY = '127.0.0.1:9050'   # or the Whonix workstation's gateway

# Option B: Privoxy as HTTP-to-SOCKS bridge (if a tool only speaks HTTP)
sudo apt install privoxy
# Add to /etc/privoxy/config:
#   forward-socks5t / 127.0.0.1:9050 .
#   listen-address  127.0.0.1:8118
sudo systemctl restart privoxy
# Point scrapy at http://127.0.0.1:8118
```

### 6.2 A minimal forum-crawl spider

```python
# skills/darkweb-intel/spiders/forum_spider.py (illustrative)
import scrapy, hashlib, json, os, time
from urllib.parse import urljoin

class ForumSpider(scrapy.Spider):
    name = 'forum'
    custom_settings = {
        'DOWNLOAD_DELAY': 8.0,           # be polite — .onion operators ban scrapers
        'CONCURRENT_REQUESTS': 1,         # serial — no parallel hammering
        'AUTOTHROTTLE_ENABLED': True,
        'AUTOTHROTTLE_TARGET_CONCURRENCY': 1.0,
        'ROBOTSTXT_OBEY': False,          # most .onion robots.txt is empty anyway
        'USER_AGENT': 'Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0',
        'HTTPPROXY_ENABLED': True,
        'HTTPPROXY_ADDRESS': '127.0.0.1:8118',
        'RETRY_TIMES': 2,
        'DOWNLOAD_TIMEOUT': 90,
    }

    def __init__(self, seed=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.seed = seed
        self.seen = set()
        self.out_dir = f'captures/{int(time.time())}'
        os.makedirs(self.out_dir, exist_ok=True)

    def start_requests(self):
        yield scrapy.Request(self.seed, callback=self.parse, dont_filter=True)

    def parse(self, response):
        body = response.body
        digest = hashlib.sha256(body).hexdigest()
        record = {
            'url': response.url,
            'status': response.status,
            'captured_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'sha256': digest,
            'bytes': len(body),
            'title': response.xpath('//title/text()').get('').strip(),
        }
        with open(f'{self.out_dir}/manifest.jsonl', 'a') as f:
            f.write(json.dumps(record) + '\n')
        with open(f'{self.out_dir}/{digest}.html', 'wb') as f:
            f.write(body)
        # Extract links and recurse, depth-limited
        for href in response.css('a::attr(href)').getall():
            absurl = urljoin(response.url, href)
            if absurl.endswith('.onion') or '.onion/' in absurl:
                if absurl not in self.seen:
                    self.seen.add(absurl)
                    yield scrapy.Request(absurl, callback=self.parse)
```

Run it:

```bash
torsocks scrapy runspider forum_spider.py \
  -a seed=http://exampleforum.onion/ \
  -L INFO
# Output lands in captures/<timestamp>/ with HTML by hash and a manifest.
```

### 6.3 Rate-limit discipline

`.onion` operators ban aggressive crawlers fast, and a ban on one exit node hits every other Tor user on that node. Discipline:

- `DOWNLOAD_DELAY >= 5 seconds` for any service you intend to revisit.
- `CONCURRENT_REQUESTS = 1` — no parallelism within a single service.
- `RANDOMIZE_DOWNLOAD_DELAY = True` — jitter defeats simple rate-limit patterns.
- Rotate the Tor circuit between distinct services, not within one service — circuit rotation mid-crawl looks like IP-hopping to the operator.

```bash
# Force a new circuit before starting a new service
echo -e 'AUTHENTICATE ""\nSIGNAL NEWNYM\nQUIT' | nc 127.0.0.1 9051
# (Requires ControlPort 9051 and a cookie/password in torrc.)
```

---

## 7. Marketplace & Forum Enumeration

### 7.1 Marketplace types and what to capture

| Type | Examples | Capturable without login | Capturable with login |
|------|----------|--------------------------|-----------------------|
| Drug market | ASAP, Abacus, Bohemia | Listing categories, vendor counts, listing volume | Vendor profiles, prices, shipping origin, escrow terms |
| Stolen data market | BreachForums, Proxy | Forum sections, breach announcement titles | Sample data, prices, breach metadata |
| Carding market | Brian's Dumps (historical), Union Hit (current) | Nothing useful | BIN lists, prices, card volume by region |
| Counterfeit documents | various | Sample images (redacted), categories | Pricing, samples, fulfillment claims |
| Cybercrime-as-a-service | various | Service menus | Pricing, TOS, sample outputs |

For each, capture:

- **Listing volume by category** — what's actually moving on this market.
- **Top vendors by feedback** — recurring actor handles.
- **Pricing benchmarks** — for the asset class your org cares about (corporate credentials, customer PII, etc.).
- **Breach announcements** — title, claimed record count, sample fields, date.
- **Monero addresses** for escrow — durable identifier for the marketplace itself.

### 7.2 Forum enumeration — BreachForums / Dread methodology

Forums require registration for anything beyond the public index. **Do not register without explicit written authorization** — doing so as an undercover investigator has legal and ethical consequences. The pattern below is for *reading* public or pre-authorized content only.

```bash
# Step 1: capture the public index — no login required
torsocks curl --silent http://exampleforum.onion/ -o forum-index.html

# Step 2: enumerate the public subforum list
cat forum-index.html | grep -oE 'href="[^"]+"' | sort -u | grep -i '\.onion'

# Step 3: with authorization, log in via the Tor Browser and export cookies
# (Tor Browser -> Developer -> Storage -> copy the session cookie)
# Then use the cookie for headless fetches:
SESSION_COOKIE='PHPSESSID=abc123...'
torsocks curl --silent -H "Cookie: $SESSION_COOKIE" \
  "http://exampleforum.onion/forumdisplay.php?fid=12" \
  -o subforum-12.html

# Step 4: parse threads, extract posts
# Each thread has a stable ID — capture the ID, not the URL.
python3 -c "
import re, sys, html
content = open('subforum-12.html').read()
threads = re.findall(r'thread-([0-9]+)\.html[\"\\\']>.*?<span[^>]*>([^<]+)</span>', content)
for tid, title in threads[:50]:
    print(f'{tid}\t{html.unescape(title)}')
"
```

### 7.3 Threat-actor pivoting from forum content

Forum posts yield durable identifiers that survive handle rotation:

| Identifier | Pivot value |
|------------|-------------|
| PGP fingerprint | Same fingerprint across markets = same actor |
| Monero subaddress | Same subaddress reuse = same operator (often same actor across markets) |
| PGP-signed message body | Confirms the actor controls the private key |
| Contact `.onion` (Telegram handle, Signal number) | Pivot to messengers; numbers are searchable via contact-discovery APIs |
| Linguistic markers (chronemics, typo patterns) | Weak signal — supporting, never sufficient alone |

```bash
# Extract PGP keys from captured pages
for f in captures/*.html; do
  gpg --dearmor < "$f" 2>/dev/null | gpg --list-packets 2>/dev/null | grep -E 'keyid|user ID'
done | sort -u

# Extract Monero addresses (standard + subaddress formats)
grep -ohE '(4[0-9AB][0-9a-zA-Z]{93}|8[0-9a-zA-Z]{95})' captures/*.html | sort -u
```

---

## 8. Breach Forum Monitoring & Notification

### 8.1 Continuous monitoring pattern

For "alert me when our org appears in a breach forum" use cases, a recurring poll beats one-off crawls:

```bash
# /etc/cron.weekly/onion-watch.sh
#!/bin/bash
set -euo pipefail
KEYWORDS="acme-corp.com acme_corp \"Acme Inc\""
WATCH_DIR=/var/lib/onion-watch
mkdir -p "$WATCH_DIR"

# Use a commercial API where possible — IntelX, DarkOwl, Flare, Recorded Future
# all have dedicated breach-forum feeds with cleaner signal than raw scraping.
# This script uses IntelX as an example.
INTELX_KEY=$(cat /etc/intelx/api.key)
for kw in $KEYWORDS; do
  curl --silent "https://2.intelx.io/phonebook/search" \
    -H "x-key: $INTELX_KEY" \
    -H "Content-Type: application/json" \
    -d "{\"term\":\"$kw\",\"maxresults\":100,\"media\":0}" \
    > "$WATCH_DIR/$(date -u +%Y%m%d)-$kw.json"
done

# Diff against last week's snapshot to find new appearances
for kw in $KEYWORDS; do
  prev=$(ls -1t "$WATCH_DIR"/*-$kw.json 2>/dev/null | sed -n '2p')
  curr=$(ls -1t "$WATCH_DIR"/*-$kw.json 2>/dev/null | sed -n '1p')
  [ -z "$prev" ] && continue
  diff <(jq -S . "$prev") <(jq -S . "$curr") | mail -s "[onion-watch] new hits for $kw" soc@acme-corp.com
done
```

### 8.2 HaveIBeenPwned for known breach correlation

For credentials already in known public breaches, HIBP is the gold-standard source — it does not require any dark-web access.

```bash
# HIBP API (requires key for some endpoints)
HIBP_KEY=$(cat /etc/hibp/api.key)
curl --silent "https://haveibeenpwned.com/api/v3/breachedaccount/ceo@acme-corp.com" \
  -H "hibp-api-key: $HIBP_KEY" \
  -H "user-agent: acme-soc" | jq

# Domain-wide search requires a paid subscription but returns every
# corporate email seen in any breach HIBP has indexed.
```

### 8.3 Breach data triage

When you find your org's data listed on a breach forum:

1. **Confirm authenticity** — request a sample from the listing or the forum operator through authorized channels. Most operators provide samples to verify before purchase is even discussed.
2. **Identify the source breach** — match the data shape (columns, count, format) against known public breaches and against internal incident history. A "new" breach is often a repackage of an old one.
3. **Assess currency** — when was the data stolen? Stale data has lower urgency.
4. **Notify affected users** if internal incident response determines the breach is novel and contains PII.
5. **Law enforcement referral** — for ransomware-leak sites, the FBI/local equivalent often wants a copy of the listing for their own attribution work.

---

## 9. OPSEC for the Investigator

### 9.1 Persona discipline

A dark-web investigation persona is a separate identity with its own:

- Username (not derived from any clearnet handle)
- PGP keypair (generated on the Whonix workstation, never exported to clearnet)
- Monero wallet (for any authorized test purchases)
- Browser fingerprint (Tor Browser ships uniform — don't customize)
- Time zone (UTC always)
- Linguistic register (avoid region-specific slang or spellings)

```bash
# Generate a persona PGP keypair on the Whonix workstation
gpg --batch --generate-key <<EOF
%no-protection
Key-Type: eddsa
Key-Curve: ed25519
Subkey-Type: ecdh
Subkey-Curve: cv25519
Name-Real: $(openssl rand -hex 4)
Name-Email: $(openssl rand -hex 6)@protonmail.com
Expire-Date: 6m
%commit
EOF
gpg --list-secret-keys --keyid-format=long
# Never export the secret key off this workstation. The fingerprint is the
# durable identifier; the secret key stays put.
```

### 9.2 Anti-fingerprinting — what Tor Browser already does for you

Tor Browser ships with a uniform fingerprint — same window size, same fonts, same plugins. The most common OPSEC mistake is *customizing* the browser: installing extensions, resizing the window, enabling JavaScript globally. Each customization narrows the anonymity set.

- Keep the window at the default size.
- Don't install browser extensions.
- Use the default security level ("Standard" for casual lookups, "Safer" or "Safest" for forum work — Safest disables JS globally).
- Don't log in to clearnet accounts (Gmail, GitHub) from Tor Browser — the account correlation defeats the anonymization.

### 9.3 Host-side OPSEC

```bash
# Don't leave bash history containing onion URLs
shred -uvz ~/.bash_history 2>/dev/null

# Don't leave captures on the host disk unencrypted
gpg --symmetric --cipher-algo AES256 captures.tar.gz
# Or use LUKS for the whole capture volume.

# Don't share screenshots that include your window manager chrome,
# desktop wallpaper, or clock — they leak OS, locale, and time zone.
# Use Tor Browser's built-in screenshot or `import -window root` from a
# clean WM session.

# Don't copy/paste between Tor Browser and clearnet apps — clipboard
# contents have been known to leak through unrelated processes.
```

### 9.4 Investigator safety — mental health

Dark-web investigations surface distressing content: CSAM (incidentally, in marketplace crawls), graphic violence (cartel advertising), threats against named individuals (your org's executives, sometimes yourself). Investigator burnout and PTSD are occupational hazards.

- **Rotate investigators** on sustained distressing-content engagements.
- **Mandatory debrief** after any engagement involving CSAM or graphic violence.
- **Reporting pipelines** for incidental CSAM discovery — in the US, NCMEC CyberTipline; in the EU, INHOPE. Don't transmit the material — report the URL and let the hotline retrieve it.

---

## 10. Legal & Ethical Considerations

### 10.1 Jurisdictional posture

Laws governing dark-web investigation vary by jurisdiction:

- **United States**: 18 U.S.C. § 1030 (CFAA) — accessing a computer without authorization is a crime. Most courts treat publicly accessible `.onion` services as not "without authorization," but registration under false pretenses is riskier. Possession of CSAM (18 U.S.C. § 2252) is strict-liability — incidental discovery during a crawl must be reported, not stored.
- **European Union**: Similar framework (Directive 2013/40/EU). GDPR applies to any PII you collect, including breach data.
- **United Kingdom**: Computer Misuse Act 1990 — broadly similar to CFAA.
- **Authoritarian jurisdictions**: Russia, China, Iran — accessing Tor at all can be criminalized. The investigator's local law matters as much as the target's.

### 10.2 Ethical lines

- **No purchasing of contraband** without explicit, written authorization from a client who has authority to authorize it (typically: law enforcement with a controlled-buy authorization). Almost no private engagement includes this.
- **No enticement** — don't ask a forum operator to commit a new crime they wouldn't have committed without your prompting. That's entrapment in many jurisdictions and taints any resulting evidence.
- **No distribution of discovered PII** — even back to the client without redaction. Aggregate findings ("500 records matching the customer-email regex were observed"), don't transfer raw data.
- **No undercover participation** in forums without written authorization and a documented legend. Dabbling gets people hurt.
- **Mandatory reporting** for CSAM — non-negotiable, in any jurisdiction the investigator is subject to.

### 10.3 Chain of custody

For findings that may end up in litigation (insurance claims, law-enforcement referral, regulatory disclosure):

- Capture every page with timestamp, response headers, SHA-256 of the body, and the exit node fingerprint.
- Store captures in a write-once volume (optical, WORM tape, or a S3 bucket with Object Lock).
- Document every access to the captures in an access log.
- Sign the final deliverable with the investigator's PGP key.

```bash
# Capture with full provenance
onion="exampleforum.onion"
ts=$(date -u +%Y%m%dT%H%M%SZ)
torsocks curl --silent -D "headers-${ts}.txt" -o "body-${ts}.html" "http://${onion}/"
sha256sum "body-${ts}.html" | tee "body-${ts}.sha256"
echo "{\"url\":\"http://${onion}/\",\"captured_at\":\"$ts\",\"exit\":\"$(torsocks curl -s https://check.torproject.org/api/ip | jq -r .IP)\",\"sha256\":\"$(cut -d' ' -f1 body-${ts}.sha256)\"}" >> provenance.jsonl
```

---

## 11. Post-Crawl Cleanup

```bash
# 1. Revert the Whonix workstation to its pre-session snapshot
VBoxManage snapshot "Whonix-Workstation" restore "pre-session-$(date -u +%Y%m%dT%H%M%SZ)"

# 2. Or, on Tails, reboot — everything volatile is gone

# 3. On the host: shred any logs that touched the .onion URLs
find ~/onion-watch/ -type f -exec shred -uvz {} +

# 4. Rotate the persona (if engagement is closing)
gpg --delete-secret-and-public-keys <persona-fingerprint>
# The persona's PGP fingerprint remains in the deliverable as a citation;
# the keys are gone.

# 5. Encrypt the deliverable and captures for handoff
gpg --symmetric --cipher-algo AES256 final-deliverable.pdf
gpg --symmetric --cipher-algo AES256 captures.tar.gz

# 6. Wipe any Tor Browser state if you ran it on the host (you shouldn't have)
rm -rf ~/.tor/ ~/.config/torbrowser/

# 7. Run the end-of-session OPSEC check (mirrors the start-of-session check from §3.4)
curl --silent https://check.torproject.org/api/ip
# IsTor should be false now (you're not on Tor) — confirming no residual leak.
```

---

## 12. Closing Checklist

Before marking the crawl complete:

- [ ] Isolation verified — Whonix/Tails, no host leakage, no clearnet identity loaded
- [ ] OPSEC start-of-session check run and recorded (§3.4)
- [ ] Seed list captured with response codes and timestamps
- [ ] OnionScan reports generated for every live seed
- [ ] Captures saved with SHA-256 manifest and provenance records
- [ ] Rate-limit discipline observed — no service banned during the crawl
- [ ] Marketplace / forum enumeration results extracted to structured form
- [ ] Breach data triaged — authenticity confirmed, source identified, client notified if in scope
- [ ] Threat-actor pivots documented — PGP fingerprints, Monero addresses, handles
- [ ] Legal/ethical posture reviewed — no purchases, no undercover, mandatory reports filed if applicable
- [ ] Captures encrypted at rest with AES-256
- [ ] Persona rotated (if engagement closing) or preserved (if ongoing)
- [ ] Whonix snapshot reverted / Tails rebooted
- [ ] Host-side traces shredded
- [ ] Investigator debrief scheduled (mandatory for distressing-content engagements)

---

## 13. References

- **Tor Project**: [torproject.org](https://www.torproject.org)
- **Tor Protocol Specification**: [gitlab.torproject.org/tpo/core/torspec](https://gitlab.torproject.org/tpo/core/torspec)
- **Onion Service v3 Protocol**: [2019-onion-services-v3.txt](https://gitweb.torproject.org/torspec.git/tree/rend-spec-v3.txt)
- **Whonix**: [whonix.org](https://www.whonix.org)
- **Tails**: [tails.net](https://tails.net)
- **OnionScan**: [github.com/s-rah/onionscan](https://github.com/s-rah/onionscan)
- **Ahmia**: [ahmia.fi](https://ahmia.fi)
- **dark.fail**: [dark.fail](https://dark.fail)
- **Hunchly**: [hunch.ly](https://www.hunch.ly) — commercial dark-web capture tool with strong chain-of-custody
- **IntelX**: [intelx.io](https://intelx.io)
- **HaveIBeenPwned**: [haveibeenpwned.com](https://haveibeenpwned.com)
- **EFF Surveillance Self-Defense**: [ssd.eff.org](https://ssd.eff.org)
- **Bellingcat Online Investigation Toolkit**: [bellingcat.gitbook.io/toolkit](https://bellingcat.gitbook.io/toolkit)
- **NCMEC CyberTipline**: [missingkids.org/gethelpnow/cybertipline](https://www.missingkids.org/gethelpnow/cybertipline)
- **INHOPE (EU)**: [inhope.org](https://www.inhope.org)

---

**Related files**: `../SKILL.md`, `../payloads.md`, `../test-cases.md`, `./dark-web-investigation-playbook.md`
**Integration**: `skills/osint/`, `skills/username-profiling/`, `skills/social-intelligence/`, `skills/threat-intelligence/`, `skills/deep-research/`, `skills/social-engineering/`
