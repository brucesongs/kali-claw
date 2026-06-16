# Dark Web Intelligence Payloads / Command Catalogue

> Companion to `SKILL.md`. Every command here is reproducible on Kali Linux 2025-2 with `sudo apt install tor` plus the additional tools noted per section.
>
> Placeholder convention: `<target>` is the search term, `<handle>` is a forum handle, `<onion>` is a 56-char v2/v3 `.onion` URL, `<email>` is a target email, `<KEY>` is an API key.
>
> **OPSEC WARNING**: Every command in sections 2 onward assumes Tor SOCKS routing (`--socks5-hostname 127.0.0.1:9050`) or a Tails/Whonix environment. Running any of these from a corporate or personal IP is an investigator deanonymization risk.

---

## 1. Tor & Access Setup

### 1.1 Install and start Tor

```bash
sudo apt update
sudo apt install -y tor torsocks curl jq dnsutils obfs4proxy
sudo service tor start
sleep 3

# Verify egress — Tor IP must NOT equal your real IP
echo "Real IP: $(curl -s https://api.ipify.org)"
echo "Tor IP:  $(curl -s --socks5-hostname 127.0.0.1:9050 https://api.ipify.org)"
```

### 1.2 `torrc` snippets — bridges, Snowflake, isolation

```bash
# Edit /etc/tor/torrc

# Basic: route via Tor with SOCKS on 9050 (default)
SocksPort 9050

# Isolate streams by destination (prevents cross-site correlation)
SocksPort 9050 IsolateDestAddr IsolateDestPort

# obfs4 bridge (when Tor direct is blocked)
UseBridges 1
Bridge obfs4 <IP>:<PORT> <FINGERPRINT> cert=<CERT> iat-mode=0
ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy

# Snowflake bridge (WebRTC-based, harder to block)
UseBridges 1
Bridge snowflake 192.0.2.3:80
ClientTransportPlugin snowflake exec /usr/bin/snowflake-client -url https://snowflake-broker.torproject.net.global.prod.fastly.net/ -amp -ice stun:stun.l.google.com:19302,stun:stun.antisip.com:3478 -utlsclienthello-interpolation

# Restart to apply
sudo service tor restart
```

### 1.3 Whonix two-VM isolation

```bash
# 1. Download Whonix-Gateway and Whonix-Workstation KVM/Quantum images from whonix.org
# 2. Verify the SHA256 signature with the Whonix signing key (separate from Tor)
gpg --verify Whonix-*-Signature.asc

# 3. Import both images into VirtManager
# 4. The Gateway forces ALL Workstation traffic through Tor — even apps that don't
#    honor SOCKS settings are covered
# 5. Snapshot the Workstation before any dark-net work; revert after

# Inside Whonix-Workstation, verify Tor routing
curl -s https://check.torproject.org | grep -o 'Congratulations'
```

### 1.4 Tails amnesic boot

```bash
# 1. Download Tails from tails.net and verify the signature
gpg --verify tails-amd64-*-img.sig

# 2. Write to USB (NOT to your internal disk)
sudo dd if=tails-amd64-*.img of=/dev/sdX bs=16M status=progress conv=fsync
sync

# 3. Boot the investigation machine from USB; everything runs in RAM
# 4. Configure an administration password andPersistent Storage only if you need
#    persistence (default is amnesic — recommended for high-risk work)
# 5. All traffic routes through Tor automatically; Tor Browser is pre-installed
```

### 1.5 Egress verification (run before EVERY investigation session)

```bash
# 1. Real IP
curl -s https://api.ipify.org

# 2. Tor IP — must differ
curl -s --socks5-hostname 127.0.0.1:9050 https://api.ipify.org

# 3. Tor exit geolocation
curl -s --socks5-hostname 127.0.0.1:9050 https://ifconfig.me/json | \
  jq '{ip, country, city, region}

# 4. DNS resolver — should be 127.0.0.1 (Tor DNS) in Tails/Whonix
cat /etc/resolv.conf

# 5. Active Tor circuit (per-stream)
#    In Tor Browser, click the circuit icon next to the URL bar
```

---

## 2. Search Engines & Indexing

### 2.1 Ahmia (clearnet entry)

```bash
# URL-encode the search term
ENC=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "<target>")

# Clearnet Ahmia (exposes your IP to ahmia.fi — fast, but not anonymous to the indexer)
curl -s "https://ahmia.fi/search/?q=${ENC}" \
  | grep -oE 'https?://[a-z2-7]{56}\.onion' | sort -u

# Pretty-printed results with surrounding context
curl -s "https://ahmia.fi/search/?q=${ENC}" \
  | grep -B1 -A2 '[a-z2-7]\{56\}\.onion' | head -100
```

### 2.2 Ahmia (onion-service mirror — full anonymity)

```bash
ENC=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "<target>")

# Onion Ahmia — same data, full anonymity via Tor
curl -s --socks5-hostname 127.0.0.1:9050 \
  "http://juhanurmihxlp77nkq76byazc4y2sphl4a5hfo3hxnlhkbgz7q6fqd.onion/search/?q=${ENC}" \
  | grep -oE 'https?://[a-z2-7]{56}\.onion' | sort -u > ahmia_onion_results.txt

# Note: the Ahmia onion address above may rotate; verify current via dark.fail
curl -s --socks5-hostname 127.0.0.1:9050 https://dark.fail | grep -i ahmia
```

### 2.3 Torch

```bash
ENC=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "<target>")

# Torch is .onion-only — Tor routing mandatory
curl -s --socks5-hostname 127.0.0.1:9050 \
  "http://torchde7jygjnqjjp6lcyrch6gzflyol3c5zfsa6uejwnbq7qiiyfqd.onion/search?query=${ENC}" \
  | grep -oE 'https?://[a-z2-7]{56}\.onion' | sort -u > torch_results.txt

# Verify the current Torch address via dark.fail or Tor Blog before relying on it
curl -s --socks5-hostname 127.0.0.1:9050 https://dark.fail | grep -i torch
```

### 2.4 dark.fail (uptime status, no listings)

```bash
# dark.fail reports uptime for well-known services; it does NOT index listings
curl -s --socks5-hostname 127.0.0.1:9050 https://dark.fail | \
  grep -E '<td>[A-Za-z ]+</td>.*<td>(online|offline|down)</td>' | head -20

# Use dark.fail to verify a service's current .onion before visiting
# A marketplace may have 3-5 active mirrors; dark.fail tracks them
```

### 2.5 Onionland & Haystak

```bash
# Onionland — .onion search engine with category pages
# Current address rotates; verify via Tor Blog or dark.fail
curl -s --socks5-hostname 127.0.0.1:9050 \
  "http://<onionland-current>.onion/search?q=<target>" \
  | grep -oE 'https?://[a-z2-7]{56}\.onion' | sort -u

# Haystak — clearnet entry, limited free tier
# Visit via Tor Browser for manual searches; API requires registration
curl -s --socks5-hostname 127.0.0.1:9050 \
  "https://haystak.com/search/?q=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "<target>")"
```

### 2.6 Multi-engine orchestration

```bash
#!/usr/bin/env bash
# sweep.sh — run target term across multiple dark-net search engines
set -euo pipefail
TARGET="${1:-}"
[ -z "$TARGET" ] && { echo "usage: $0 <term>"; exit 1; }

ENC=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$TARGET")
OUTDIR="sweep_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTDIR"

# Ahmia clearnet
curl -s "https://ahmia.fi/search/?q=${ENC}" \
  | grep -oE 'https?://[a-z2-7]{56}\.onion' | sort -u > "$OUTDIR/ahmia_clearnet.txt"

# Ahmia onion
curl -s --socks5-hostname 127.0.0.1:9050 \
  "http://juhanurmihxlp77nkq76byazc4y2sphl4a5hfo3hxnlhkbgz7q6fqd.onion/search/?q=${ENC}" \
  | grep -oE 'https?://[a-z2-7]{56}\.onion' | sort -u > "$OUTDIR/ahmia_onion.txt"

# Torch
curl -s --socks5-hostname 127.0.0.1:9050 \
  "http://torchde7jygjnqjjp6lcyrch6gzflyol3c5zfsa6uejwnbq7qiiyfqd.onion/search?query=${ENC}" \
  | grep -oE 'https?://[a-z2-7]{56}\.onion' | sort -u > "$OUTDIR/torch.txt"

# Aggregate unique hits
sort -u "$OUTDIR"/*.txt > "$OUTDIR/all_unique.txt"
echo "Sweep complete: $(wc -l < "$OUTDIR/all_unique.txt") unique onion URLs across 3 engines"
echo "Results in: $OUTDIR"
```

---

## 3. Onion Service Enumeration

### 3.1 OnionScan — fingerprint a discovered `.onion`

```bash
# Install OnionScan (Go install for current version)
go install github.com/s-rah/onionscan@latest
# Or: sudo apt install onionscan  (Kali repo, may lag)

# Scan via Tor — fingerprint, find linked services, expose misconfigurations
onionscan --verbose \
  --tor-proxy-address 127.0.0.1:9050 \
  --timeout 120 \
  --depth 1 \
  http://<onion>.onion 2>&1 | tee onionscan_report.txt

# OnionScan detects:
#   - Apache mod_status leaks
#   - Exposed PHP info, phpMyAdmin, /server-status
#   - Directory listings
#   - PGP keys in page content (becomes a pivot identifier)
#   - Linked .onion services (becomes Phase 4 pivots)
#   - Server software versions
#   - Known dangerous configurations (CGI, exposed config files)
```

### 3.2 ahmia-cli — programmatic enumeration

```bash
# Ahmia provides a JSON API (rate-limited)
curl -s --socks5-hostname 127.0.0.1:9050 \
  "http://juhanurmihxlp77nkq76byazc4y2sphl4a5hfo3hxnlhkbgz7q6fqd.onion/api/search/?q=<term>&limit=50" \
  | jq '.results[] | {title, url, domain, last_seen}'

# Discover newly registered onions in Ahmia's last-crawled window
curl -s --socks5-hostname 127.0.0.1:9050 \
  "http://juhanurmihxlp77nkq76byazc4y2sphl4a5hfo3hxnlhkbgz7q6fqd.onion/api/latest/?limit=100" \
  | jq '.[] | {domain, last_seen, title}'
```

### 3.3 Manual discovery — directory pages & link farms

```bash
# Many onion services host directory pages — useful for surfacing niche communities
DIRS=(
  "http://juhanurmihxlp77nkq76byazc4y2sphl4a5hfo3hxnlhkbgz7q6fqd.onion"
  "http://torchde7jygjnqjjp6lcyrch6gzflyol3c5zfsa6uejwnbq7qiiyfqd.onion"
  "http://<other-directory>.onion"
)

for d in "${DIRS[@]}"; do
  echo "=== $d ==="
  curl -s --socks5-hostname 127.0.0.1:9050 "$d" \
    | grep -oE 'https?://[a-z2-7]{56}\.onion' | sort -u
done > directory_corpus.txt
sort -u directory_corpus.txt -o directory_corpus.txt
echo "Total unique onions discovered: $(wc -l < directory_corpus.txt)"
```

### 3.4 v2 vs v3 detection

```bash
# v2 onions are 16 chars; v3 are 56 chars. v2 is deprecated since 2021.
grep -E 'https?://[a-z2-7]{16}\.onion' results.txt   # v2 (likely dead)
grep -E 'https?://[a-z2-7]{56}\.onion' results.txt   # v3 (current)

# Drop v2 hits — they're either dead or honeypots left online
grep -E 'https?://[a-z2-7]{56}\.onion' results.txt | sort -u > v3_only.txt
```

---

## 4. Marketplace Monitoring

### 4.1 IntelX phonebook + intelligent search

```bash
# IntelX phonebook — find related identifiers for a seed (email, domain, handle)
curl -s "https://2.intelx.io/phonebook/search?k=<INTELX_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "term": "<target_email>",
    "maxresults": 100,
    "media": 0,
    "target": 1
  }' | jq '.selectors[]?.selectorvalue' | sort -u

# IntelX intelligent search — full-text across leaks, paste sites, dark-net
# Step 1: initiate search
ID=$(curl -s "https://2.intelx.io/intelligent/search?k=<INTELX_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "term": "<target_term>",
    "maxresults": 100,
    "media": 0,
    "sort": 1,
    "terminate": []
  }' | jq -r '.id')

# Step 2: poll for results (search is async)
sleep 5
curl -s "https://2.intelx.io/intelligent/search/result?k=<INTELX_KEY>&id=$ID&limit=100" \
  | jq '.selectors[] | {selectorvalue, type, source, tags}'
```

### 4.2 DarkOwl API (commercial reference)

```bash
# DarkOwl requires an enterprise license; syntax documented for reference
# Authentication via API key
curl -s "https://api.darkowl.com/api/v3/search" \
  -H "Authorization: Bearer <DARKOWL_KEY>" \
  -d '{"query": "<target>", "limit": 50}' \
  | jq '.results[] | {title, url, snippet, source_type, captured_at}'
```

### 4.3 Manual marketplace crawl (read-only observer role)

```bash
# Step 1: Verify the marketplace's current .onion via dark.fail
curl -s --socks5-hostname 127.0.0.1:9050 https://dark.fail | grep -i market

# Step 2: In Tor Browser (manual), navigate to the verified .onion
# Step 3: Search for target brand/product/handle
# Step 4: For each match, capture into an encrypted evidence vault:
#   - Listing URL (.onion + path)
#   - Vendor profile URL
#   - Vendor PGP key (often on profile)
#   - Screenshot (Tor Browser built-in)
#   - Captured_at timestamp (UTC)

# Step 5: Encrypt all artifacts before storage
tar czf market_evidence_$(date -u +%Y%m%d).tar.gz evidence/
gpg --symmetric --cipher-algo AES256 market_evidence_$(date -u +%Y%m%d).tar.gz
shred -uvz market_evidence_$(date -u +%Y%m%d).tar.gz

# CRITICAL OPSEC RULES:
# - Observer role only — never register, never purchase, never contact vendor
# - Limit session length to 30-60 minutes
# - Rotate persona between marketplaces
# - If you accidentally log in from a clearnet IP: burn the persona
```

### 4.4 Vendor profile pivot

```bash
# From a marketplace listing, pivot to the vendor profile
# Vendor profiles usually expose:
#   - PGP key (most important pivot identifier)
#   - Monero/Bitcoin wallet (escrow + donations)
#   - "Other markets I'm on" (cross-marketplace identity)
#   - "Formerly known as" (handle rotation history)
#   - Forum references (which communities talk about this vendor)

# Extract PGP fingerprint from a vendor profile page
curl -s --socks5-hostname 127.0.0.1:9050 \
  "http://<marketplace>.onion/vendor/<vendor_id>" \
  | grep -oE '[A-F0-9]{40}' | sort -u > pgp_fingerprints.txt

# Extract Monero (XMR) wallet addresses
curl -s --socks5-hostname 127.0.0.1:9050 \
  "http://<marketplace>.onion/vendor/<vendor_id>" \
  | grep -oE '4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}' | sort -u > xmr_wallets.txt
```

---

## 5. Forum & Paste Site Enumeration

### 5.1 Forum search (handle pivot)

```bash
# For each known dark-net forum, search for the handle
# (Current addresses verified via dark.fail — these rotate frequently)
FORUMS=(
  "<forum1>.onion"
  "<forum2>.onion"
  "<forum3>.onion"
)

for f in "${FORUMS[@]}"; do
  echo "=== $f ==="
  curl -s --socks5-hostname 127.0.0.1:9050 \
    "http://$f/search?q=<handle>" \
    | grep -oE 'href="[^"]*"' | grep -iE 'post|thread|profile' | head -10
done > forum_corpus.html

# WARNING: Forum login pages frequently have honeypot accounts designed to
# deanonymize investigators. Do not log in without authorization.
```

### 5.2 Paste site enumeration (breach announcements)

```bash
# Major paste sites (often where new breach announcements appear first):
#   - Various .onion paste sites (rotating addresses)
#   - Ransomware leak sites (one per gang)

# For a ransomware leak site:
curl -s --socks5-hostname 127.0.0.1:9050 \
  "http://<ransomware_gang>.onion" \
  | grep -iE '<client_name>' \
  | sed -E 's/<[^>]+>//g' | sort -u

# Search across paste sites for the target brand
for paste in psite1.onion psite2.onion psite3.onion; do
  curl -s --socks5-hostname 127.0.0.1:9050 \
    "http://$paste/search?q=<brand>" \
    >> paste_corpus.html
done
```

### 5.3 Ransomware leak-site tracker

```bash
# Track which victims appear on which ransomware gang's leak site
# Useful for incident-response firms to brief clients on active threat actors

GANGS=(
  "gang1.onion"
  "gang2.onion"
  "gang3.onion"
)

DATE=$(date -u +%Y-%m-%d)
OUT="ransomware_tracker_${DATE}.tsv"
echo -e "gang\tvictim\tdiscovered_at" > "$OUT"

for g in "${GANGS[@]}"; do
  curl -s --socks5-hostname 127.0.0.1:9050 "http://$g" \
    | grep -ioE '<victim>([^<]+)</victim>' \
    | sed -E "s/<[^>]+>//g; s/.*/$g\t&\t$DATE/i" >> "$OUT"
done

column -t -s $'\t' "$OUT" | head -50
```

---

## 6. Threat Actor Profiling

### 6.1 Handle → PGP key lookup

```bash
# Many actors publish a PGP fingerprint in forum signatures
# Search keyservers for keys with a uid matching the handle
gpg --keyserver hkps://keys.openpgp.org --search-keys "<handle>"
gpg --keyserver hkps://keyserver.ubuntu.com --search-keys "<handle>@<forum_domain>"

# Cross-reference fingerprint across keyservers
FPR="<40-char fingerprint>"
gpg --keyserver hkps://keys.openpgp.org --recv-keys "$FPR"
gpg --keyserver hkps://keyserver.ubuntu.com --recv-keys "$FPR"

# If a key has multiple uids across forum domains, the actor reused the key
# Each new uid is a pivot to another community
gpg --list-keys --with-sig-list "$FPR"
```

### 6.2 Handle → Monero wallet extraction

```bash
# Scrape the actor's profile / posts for wallet addresses
PROFILE="http://<forum>.onion/profile/<handle>"
HTML=$(curl -s --socks5-hostname 127.0.0.1:9050 "$PROFILE")

# Monero (XMR) — 95 chars starting with 4
echo "$HTML" | grep -oE '4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}' | sort -u > xmr.txt

# Bitcoin (legacy) — 26-35 chars starting with 1 or 3
echo "$HTML" | grep -oE '[13][a-km-zA-HJ-NP-Z1-9]{25,34}' | sort -u > btc_legacy.txt

# Bitcoin (bech32) — starts with bc1
echo "$HTML" | grep -oE 'bc1[a-z0-9]{39,59}' | sort -u > btc_bech32.txt

# Cross-reference each wallet across other forums and marketplaces
# Same wallet on multiple sites = same actor (high confidence)
```

### 6.3 Behavioral fingerprinting (advanced)

```bash
# Authorship attribution: many actors reuse distinctive phrasing
# Collect their posts across forums; run stylometric analysis

# Step 1: Collect post corpus per handle
for f in forum1.onion forum2.onion forum3.onion; do
  curl -s --socks5-hostname 127.0.0.1:9050 \
    "http://$f/user/<handle>/posts" >> posts_<handle>.html
done

# Step 2: Extract text, run through Python stylometry
python3 -c "
from bs4 import BeautifulSoup
import re
with open('posts_<handle>.html') as f:
    soup = BeautifulSoup(f, 'html.parser')
posts = [p.get_text() for p in soup.select('.post-body')]
corpus = '\n'.join(posts)
# Then run through a stylometric tool (e.g., JGAAP, or a custom sklearn pipeline)
print(f'Corpus: {len(corpus)} chars across {len(posts)} posts')
"

# Step 3: Compare to other handles' corpora to find likely aliases
# Distinctive markers: emoji usage, misspelling patterns, punctuation habits,
# regional English variants (US vs UK), timezone-of-activity windows
```

---

## 7. Cryptocurrency Tracing on Darknet

### 7.1 Bitcoin (traceable) — basic address intelligence

```bash
# Bitcoin on-chain tracing is feasible; exchanges usually require KYC
ADDR="<btc_address>"

# Blockchain.com API (via Tor)
curl -s --socks5-hostname 127.0.0.1:9050 \
  "https://blockchain.info/rawaddr/$ADDR" \
  | jq '{n_tx, total_received, total_sent, final_balance, txs: .txs[:5]}'

# Blockstream Explorer (via Tor)
curl -s --socks5-hostname 127.0.0.1:9050 \
  "https://blockstream.info/api/address/$ADDR" \
  | jq '{chain_stats: .chain_stats, mempool_stats: .mempool_stats}'

# Identify cluster — find co-spent addresses that share the same UTXO
# This usually requires a commercial tool (Chainalysis, TRM Labs)
```

### 7.2 Monero (privacy-preserving) — limited tracing

```bash
# Monero is designed to defeat on-chain tracing
# On-chain visibility is limited to:
#   - Sender's tx key (revealed only if sender chooses)
#   - View key (reveals incoming transactions only, holder-controlled)

ADDR="<xmr_address>"

# xmrchain.net (via Tor) — view public chain data
curl -s --socks5-hostname 127.0.0.1:9050 \
  "https://xmrchain.net/search?value=$ADDR" \
  | grep -iE 'outputs|inputs' | head -20

# What you CAN do:
#   1. Correlate the same address across forums/marketplaces (off-chain pivot)
#   2. Note when the address appears in escrow pages, donation posts
#   3. If you have a view key (sometimes leaked), trace incoming payments

# What you CANNOT do:
#   - Trace funds through mixing (RingCT)
#   - Identify the recipient of any given output
#   - Link address to a real-world identity from on-chain data alone
```

### 7.3 Bitcoin tumbler / mixer detection

```bash
# Bitcoin tumblers mix outputs across many users to break clustering
# Detection requires commercial tooling, but heuristics:

# A "tumbler" wallet typically has:
#   - High fan-in (many inputs to one transaction)
#   - High fan-out (many outputs in same transaction)
#   - Repetitive transaction timing (automated)

ADDR="<suspected_tumbler>"
TXS=$(curl -s --socks5-hostname 127.0.0.1:9050 \
  "https://blockchain.info/rawaddr/$ADDR" | jq -r '.txs[].hash')

for tx in $TXS; do
  echo "=== $tx ==="
  curl -s --socks5-hostname 127.0.0.1:9050 \
    "https://blockchain.info/rawtx/$tx" \
    | jq '{in: .inputs | length, out: .out | length}'
done | paste - - - -
```

---

## 8. OPSEC for Investigators

### 8.1 Tails workflow (amnesic)

```bash
# Boot from USB; everything is RAM-resident; shutdown wipes everything
# Pre-session:
#   1. Boot Tails from a USB on dedicated hardware
#   2. Set administration password (Administration Password at welcome screen)
#   3. Configure Persistent Storage ONLY if needed (default: amnesic)
#   4. Open Tor Browser; verify egress via https://check.torproject.org

# Session:
#   - All traffic routes through Tor
#   - Screenshots save to /home/amnesia/Tor Browser (RAM, wiped on shutdown)
#   - To preserve evidence: encrypt + copy to external USB before shutdown
#     gpg --symmetric --cipher-algo AES256 evidence.tar.gz
#     cp evidence.tar.gz.gpg /media/amnesia/usb/

# Post-session:
#   - Reboot; RAM is wiped; no traces remain on the boot USB
```

### 8.2 Whonix workflow (persistent, isolated)

```bash
# Two-VM setup:
#   Whonix-Gateway: Tor routing only; no direct internet
#   Whonix-Workstation: all traffic forced through Gateway

# Pre-session:
#   1. Launch VirtManager, start Whonix-Gateway VM
#   2. Start Whonix-Workstation VM
#   3. Inside Workstation, verify Tor egress
curl -s https://check.torproject.org | grep -o 'Congratulations'

# Session:
#   - All Workstation apps route through Gateway → Tor
#   - Even apps that ignore SOCKS settings are covered (VM-level routing)
#   - Snapshot the Workstation before sensitive work; revert after

# Post-session:
virsh snapshot-revert whonix-workstation pre-investigation-snapshot
```

### 8.3 Dedicated burner hardware

```bash
# For high-risk investigations, use a dedicated laptop:
#   - Not your corporate device
#   - Not your personal device
#   - Bought with cash or by a third party (chain-of-custody for forensic soundness)
#   - No persistent accounts (no logged-in browser, no email client)
#   - Used only for dark-net work; never dual-purpose

# OS options:
#   - Tails (amnesic, recommended)
#   - Qubes + Whonix (compartmentalized, more flexible)
#   - Debian minimal + Tor + hardened Firefox (lowest isolation, NOT recommended)
```

### 8.4 Persona management

```bash
# Each investigation gets its own dedicated persona:
#   - Unique handle (NEVER reuse across investigations)
#   - Unique PGP key (generate fresh, never import personal key)
#   - Unique Monero wallet (if needed for vendor interaction)
#   - Unique Tor Browser profile (in Whonix snapshot)
#   - Unique timezone-of-activity window (avoid correlation)

# Generate a fresh PGP key for the persona
gpg --full-generate-key   # RSA 4096, no expiry, fake name/email

# Never sign anything with both your personal key AND a persona key — that links them
# Never email from your personal account while the persona's key is in the keyring
```

---

## 9. OPSEC Detection (Am I Real / Fingerprint Checks)

### 9.1 Egress verification

```bash
# Run before EVERY session
REAL=$(curl -s https://api.ipify.org)
TOR=$(curl -s --socks5-hostname 127.0.0.1:9050 https://api.ipify.org)
[ "$REAL" = "$TOR" ] && echo "FAIL: Tor egress equals real IP" || echo "PASS: Tor egress differs"

# Geolocation (must NOT be your real location)
curl -s --socks5-hostname 127.0.0.1:9050 https://ifconfig.me/json | jq '{ip, country, city}
```

### 9.2 DNS leak test

```bash
# In Tails/Whonix, DNS resolves via Tor (no leak to ISP resolver)
cat /etc/resolv.conf
# Expected: nameserver 127.0.0.1

# Run a DNS leak test via Tor Browser
# Visit https://dnsleaktest.com via Tor Browser → Extended Test
# All servers should be Tor exit relays (varied geographies)
```

### 9.3 Browser fingerprint audit

```bash
# In Tor Browser, verify uniform fingerprint:
#   1. Visit https://check.torproject.org → "Congratulations" green banner
#   2. Visit https://amiunique.org → fingerprint should NOT be unique
#      (Tor Browser is designed to make all users look identical)
#   3. Visit https://browserleaks.com/javascript → Tor Browser fingerprint matches default

# Common fingerprint leak vectors (verify each is disabled):
#   - WebRTC (Tor Browser disables by default)
#   - Canvas (Tor Browser returns a noise canvas)
#   - Installed fonts (Tor Browser ships a fixed font list)
#   - Screen resolution (Tor Browser forces a windowed default)
#   - Timezone (Tor Browser matches the exit relay's timezone)
```

### 9.4 Behavioral fingerprinting (correlation attacks)

```bash
# Adversaries can correlate an investigator's behavior across sessions:
#   - Session time windows (same 4-hour block every day)
#   - Click patterns (which onion services visited in what order)
#   - Search term sequences (Ahmia searches in the same order)
#   - Concurrent activity (investigator's clearnet accounts active at the same time)

# Mitigation:
#   - Vary session times; avoid a fixed daily window
#   - Use different personas for different investigations
#   - Do NOT have personal accounts logged in on the same physical machine
#     during a dark-net session (timing correlation)
#   - In Tails: nothing persists, so cross-session correlation is harder
#   - In Whonix: revert to pre-investigation snapshot after each session
```

### 9.5 Persona contamination audit

```bash
# Periodically verify the persona hasn't been linked to the org
PERSONA="<monitoring_persona_handle>"

# 1. Has the handle appeared on clearnet? (Bad — should be dark-net-only)
maigret "$PERSONA" --tags us --html

# 2. PGP key — any uid matching real name/email?
gpg --list-keys "$PERSONA_PGP_FPR"
# Burn the persona if any uid is non-fake

# 3. Wallet — appears in unexpected places?
#    Search the wallet address on forums; if mentioned by another account,
#    someone has correlated the persona

# 4. Has the persona's Tor circuit been deanonymized?
#    Check the dark-net monitoring community for doxx of your persona handle
curl -s --socks5-hostname 127.0.0.1:9050 \
  "http://<watch_forum>.onion/search?q=$PERSONA" \
  | grep -i "burned\|opsec fail\|deanon"
```

---

## 10. Breach Data Correlation

### 10.1 HaveIBeenPwned (HIBP) API

```bash
# Single-account breach check (needs API key — get at haveibeenpwned.com/API/Key)
curl -s -H "hibp-api-key: <KEY>" \
     -H "User-Agent: <your-app-name>" \
  "https://haveibeenpwned.com/api/v3/breachedaccount/<EMAIL>?truncateResponse=false" \
  | jq '.[] | {Name, Domain, BreachDate, DataClasses, PwnCount}'

# Domain-wide breach search (enterprise subscription only)
curl -s -H "hibp-api-key: <KEY>" \
  "https://haveibeenpwned.com/api/v3/breacheddomain/<DOMAIN>" \
  | jq 'to_entries[] | {email: .key, breaches: .value}'

# Paste-site search (compromised emails appearing in pastes)
curl -s -H "hibp-api-key: <KEY>" \
  "https://haveibeenpwned.com/api/v3/pasteaccount/<EMAIL>" \
  | jq '.[] | {Source, Id, Date, EmailCount}'
```

### 10.2 DeHashed API

```bash
# Full-record search (returns hashes, sometimes plaintext)
curl -s "https://api.dehashed.com/search?query=email:<target_email>" \
  -u "<account_email>:<API_KEY>" \
  | jq '.entries[] | {email, username, password, hashed_password, database, ip_address, name, address, phone}'

# Search by username
curl -s "https://api.dehashed.com/search?query=username:<handle>" \
  -u "<account_email>:<API_KEY>" | jq '.entries[]'

# Search by IP
curl -s "https://api.dehashed.com/search?query=ip_address:<ip>" \
  -u "<account_email>:<API_KEY>" | jq '.entries[]'

# Search by domain (find all leaked emails for an organization)
curl -s "https://api.dehashed.com/search?query=domain:<domain>" \
  -u "<account_email>:<API_KEY>" | jq '.entries[] | .email' | sort -u
```

### 10.3 IntelX phonebook search

```bash
# Phonebook search — find related identifiers for a seed
curl -s "https://2.intelx.io/phonebook/search?k=<KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "term": "<target_email>",
    "maxresults": 100,
    "media": 0,
    "target": 1
  }' | jq '.selectors[] | {selectorvalue, type}'

# intelx CLI tool (alternative to curl)
pip3 install intelx
intelx --api-key <KEY> search "<target_email>" --phonebook --limit 100
```

### 10.4 Local breach aggregator (h8mail)

```bash
# Install h8mail
pip3 install h8mail

# Search one email
h8mail -t <target_email> -o h8mail_results.json

# Search all emails for a domain (after collecting them via DeHashed)
h8mail -t @<domain> -o domain_leaks.json --local /path/to/local/breach/db

# Configure API keys in h8mail.ini for richer results:
#   [hibp]
#   key = <HIBP_KEY>
#   [hunter]
#   key = <HUNTER_KEY>
#   [snusbase]
#   key = <SNUSBASE_KEY>
```

---

## 11. Recon-ng with Darkweb Modules

### 11.1 Setup

```bash
# Install Recon-ng (Kali has it pre-installed)
sudo apt install recon-ng

# Launch
recon-ng

# Create a dedicated workspace
[recon-ng] > workspaces create darkweb_intel
[recon-ng] > db insert domains
domain (text): example.com
notes (text): investigation target
[recon-ng] > show domains

# Install marketplace modules
[recon-ng] > marketplace install all
[recon-ng] > marketplace search dark
```

### 11.2 Common module chain

```bash
[recon-ng] > workspaces load darkweb_intel

# Resolve subdomains (clearnet pivot point)
[recon-ng] > use recon/domains-hosts/brute_hosts
[recon-ng] > run

# Resolve hosts to IPs
[recon-ng] > use recon/hosts-hosts/resolve
[recon-ng] > run

# Cross-reference hosts in IntelX (if API key configured)
[recon-ng] > keys add INTELX_KEY <KEY>
[recon-ng] > use recon/hosts-contacts/intelx
[recon-ng] > run

# Show contacts (emails harvested from breach data)
[recon-ng] > show contacts

# Export for downstream analysis
[recon-ng] > export csv /tmp/darkweb_recon.csv
[recon-ng] > export json /tmp/darkweb_recon.json
```

### 11.3 Modules of interest

| Module | Purpose |
|--------|---------|
| `recon/domains-hosts/brute_hosts` | Subdomain brute force (clearnet pivot) |
| `recon/hosts-hosts/resolve` | DNS resolution |
| `recon/hosts-contacts/intelx` | IntelX breach correlation |
| `recon/hosts-contacts/haveibeenpwned` | HIBP breach lookup |
| `recon/profiles-contacts/github_commits` | GitHub commit email extraction |
| `recon/profiles-repositories/github_gist` | GitHub gist enumeration |

> Recon-ng dark-web specific modules are limited; for true `.onion` work, pair Recon-ng output (clearnet pivot identifiers) with manual Tor Browser + OnionScan pipeline.

---

## 12. Python Async Pipeline (via Tor SOCKS)

```python
"""
Async dark-web intelligence pipeline routed through Tor SOCKS5.

Sweeps: Ahmia search, OnionScan CLI invocation, IntelX phonebook,
and selective .onion fetches — all in one async pipeline.
"""
import asyncio
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote

import aiohttp
from aiohttp_socks import ProxyConnector

TOR_SOCKS = "socks5://127.0.0.1:9050"
ONION_RE = re.compile(r"https?://[a-z2-7]{56}\.onion", re.IGNORECASE)
AHMIA_ONION = (
    "http://juhanurmihxlp77nkq76byazc4y2sphl4a5hfo3hxnlhkbgz7q6fqd.onion"
)


@dataclass(frozen=True)
class SweepResult:
    term: str
    ahmia_onions: frozenset[str] = field(default_factory=frozenset)
    intelx_identifiers: frozenset[str] = field(default_factory=frozenset)
    errors: tuple[str, ...] = field(default_factory=tuple)


async def _fetch(session: aiohttp.ClientSession, url: str) -> str:
    timeout = aiohttp.ClientTimeout(total=180)
    try:
        async with session.get(url, timeout=timeout) as resp:
            return await resp.text()
    except Exception as exc:
        return f"ERROR: {exc}"


async def ahmia_search(term: str) -> tuple[frozenset[str], str | None]:
    connector = ProxyConnector.from_url(TOR_SOCKS)
    async with aiohttp.ClientSession(connector=connector) as session:
        url = f"{AHMIA_ONION}/search/?q={quote(term)}"
        html = await _fetch(session, url)
        if html.startswith("ERROR:"):
            return frozenset(), html
        return frozenset(ONION_RE.findall(html)), None


async def intelx_phonebook(term: str, api_key: str) -> tuple[frozenset[str], str | None]:
    url = "https://2.intelx.io/phonebook/search"
    payload = {"term": term, "maxresults": 100, "media": 0, "target": 1}
    timeout = aiohttp.ClientTimeout(total=60)
    connector = ProxyConnector.from_url(TOR_SOCKS)
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        async with session.post(
            url, json=payload, headers={"x-key": api_key}
        ) as resp:
            if resp.status != 200:
                return frozenset(), f"HTTP {resp.status}"
            data = await resp.json()
        ids = frozenset(
            sel.get("selectorvalue", "")
            for sel in data.get("selectors", [])
            if sel.get("selectorvalue")
        )
        return ids, None


async def sweep(term: str, intelx_key: str | None = None) -> SweepResult:
    tasks = [ahmia_search(term)]
    if intelx_key:
        tasks.append(intelx_phonebook(term, intelx_key))

    results = await asyncio.gather(*tasks)

    onions = results[0][0] if results else frozenset()
    intelx = results[1][0] if len(results) > 1 else frozenset()
    errors = tuple(
        r[1] for r in results if r[1] is not None
    )

    return SweepResult(
        term=term,
        ahmia_onions=onions,
        intelx_identifiers=intelx,
        errors=errors,
    )


async def main() -> None:
    terms = ["<brand_1>", "<brand_2>", "<executive_email>"]
    intelx_key = None  # set if available
    for term in terms:
        result = await sweep(term, intelx_key)
        print(f"\n=== {term} ===")
        print(f"  Ahmia onions: {len(result.ahmia_onions)}")
        for o in sorted(result.ahmia_onions):
            print(f"    {o}")
        if result.intelx_identifiers:
            print(f"  IntelX identifiers: {len(result.intelx_identifiers)}")
            for i in sorted(result.intelx_identifiers):
                print(f"    {i}")
        if result.errors:
            print(f"  Errors: {result.errors}")

        # Persist for later synthesis
        Path(f"sweep_{quote(term)}.json").write_text(
            json.dumps(
                {
                    "term": result.term,
                    "ahmia_onions": sorted(result.ahmia_onions),
                    "intelx_identifiers": sorted(result.intelx_identifiers),
                    "errors": list(result.errors),
                },
                indent=2,
            )
        )


if __name__ == "__main__":
    asyncio.run(main())
```

---

## 13. Counter-OSINT (Investigator Self-Defense)

### 13.1 Clean up investigator traces

```bash
# After each session:
# 1. Tails: just reboot — everything in RAM is wiped
# 2. Whonix: revert to pre-investigation snapshot
virsh snapshot-revert whonix-workstation pre-investigation

# 3. Encrypt all evidence before storage
tar czf session_$(date -u +%Y%m%d).tar.gz evidence/
gpg --symmetric --cipher-algo AES256 session_$(date -u +%Y%m%d).tar.gz
shred -uvz session_$(date -u +%Y%m%d).tar.gz   # remove unencrypted

# 4. Scrub bash history
shred -uvz ~/.bash_history
history -c && history -w

# 5. Scrub any tmp files
shred -uvz /tmp/*onion* /tmp/*darkweb* /tmp/*intelx* 2>/dev/null

# 6. Rotate Tor circuits (forces new exit relay)
sudo service tor reload
```

### 13.2 Periodic persona burn-and-rotate

```bash
# Every N months, rotate the persona (handles, keys, wallets):
#   1. Generate new persona identity
gpg --full-generate-key   # fresh key, fake uid
#   2. Generate new Monero wallet (if needed)
monero-wallet-cli
#   3. Migrate monitoring to new persona
#   4. Burn old persona (delete keys, never reuse)

# Document the rotation in an encrypted log
echo "$(date -u +%Y-%m-%d) Rotated persona: <old> -> <new>" >> rotation.log
gpg --symmetric --cipher-algo AES256 rotation.log
shred -uvz rotation.log
```

### 13.3 Audit own dark-net footprint (defense)

```bash
# Search for your org's leaked credentials/data in dark-net
ORG_DOMAIN="example.com"

# HIBP domain check (enterprise)
curl -s -H "hibp-api-key: <KEY>" \
  "https://haveibeenpwned.com/api/v3/breacheddomain/$ORG_DOMAIN" \
  | jq 'to_entries[] | {email: .key, breaches: .value}'

# DeHashed domain search
curl -s "https://api.dehashed.com/search?query=domain:$ORG_DOMAIN" \
  -u "<email>:<KEY>" | jq '.entries[] | {email, password, database}'

# IntelX intelligent search
curl -s "https://2.intelx.io/intelligent/search?k=<KEY>" \
  -H "Content-Type: application/json" \
  -d "{\"term\": \"$ORG_DOMAIN\", \"maxresults\": 100}" \
  | jq '.'

# Ahmia sweep for brand mentions
curl -s "https://ahmia.fi/search/?q=$ORG_DOMAIN" \
  | grep -oE 'https?://[a-z2-7]{56}\.onion' | sort -u
```

---

## 14. Cross-Reference with Clearnet OSINT

### 14.1 Username pivot — clearnet handle → dark-net persona

```bash
HANDLE="<target_handle>"

# Step 1: Clearnet enumeration (Maigret)
maigret "$HANDLE" -a --html --json ndjson --tor-proxy socks5://127.0.0.1:9050

# Step 2: Extract discovered emails/PGP fingerprints from clearnet profiles
jq -r 'select(.status=="Claimed") | .extracted.emails[]? // empty' \
  reports/$HANDLE/*_ndjson.json | sort -u > emails.txt

# Step 3: Pivot each email into breach databases (HIBP, DeHashed, IntelX)
for email in $(cat emails.txt); do
  curl -s -H "hibp-api-key: <KEY>" \
    "https://haveibeenpwned.com/api/v3/breachedaccount/$email" \
    | jq --arg e "$email" '{email: $e, breaches: .}'
done > breach_corpus.json

# Step 4: Check if the handle appears on dark-net paste sites
curl -s --socks5-hostname 127.0.0.1:9050 \
  "http://juhanurmihxlp77nkq76byazc4y2sphl4a5hfo3hxnlhkbgz7q6fqd.onion/search/?q=$HANDLE" \
  | grep -oE 'https?://[a-z2-7]{56}\.onion' | sort -u

# Step 5: If found, capture listing URL, vendor profile, PGP key, wallet
#         (See §6 — Threat Actor Profiling)
```

### 14.2 Email pivot — breach email → dark-net listings

```bash
EMAIL="<leaked_email>"

# Step 1: HIBP — what breaches contain this email?
curl -s -H "hibp-api-key: <KEY>" \
  "https://haveibeenpwned.com/api/v3/breachedaccount/$EMAIL" \
  | jq '.[].Name'

# Step 2: DeHashed — what data was leaked?
curl -s "https://api.dehashed.com/search?query=email:$EMAIL" \
  -u "<email>:<KEY>" | jq '.entries[]'

# Step 3: IntelX phonebook — what other identifiers correlate?
curl -s "https://2.intelx.io/phonebook/search?k=<KEY>" \
  -H "Content-Type: application/json" \
  -d "{\"term\": \"$EMAIL\", \"maxresults\": 100}" \
  | jq '.selectors[]?.selectorvalue' | sort -u

# Step 4: Search dark-net paste sites for the email
ENC=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$EMAIL")
curl -s --socks5-hostname 127.0.0.1:9050 \
  "http://juhanurmihxlp77nkq76byazc4y2sphl4a5hfo3hxnlhkbgz7q6fqd.onion/search/?q=$ENC" \
  | grep -oE 'https?://[a-z2-7]{56}\.onion' | sort -u

# Step 5: If found on a paste site — the email/credentials are for sale or leaked
```

---

## 15. Quick-Reference Cheat Sheet

```bash
# ─── Egress verification (run before EVERY session) ───
REAL=$(curl -s https://api.ipify.org)
TOR=$(curl -s --socks5-hostname 127.0.0.1:9050 https://api.ipify.org)
[ "$REAL" = "$TOR" ] && echo "FAIL" || echo "PASS"

# ─── Ahmia clearnet search ───
curl -s "https://ahmia.fi/search/?q=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))" "<term>")" \
  | grep -oE 'https?://[a-z2-7]{56}\.onion' | sort -u

# ─── Ahmia onion search (full anonymity) ───
curl -s --socks5-hostname 127.0.0.1:9050 \
  "http://juhanurmihxlp77nkq76byazc4y2sphl4a5hfo3hxnlhkbgz7q6fqd.onion/search/?q=<term>" \
  | grep -oE 'https?://[a-z2-7]{56}\.onion' | sort -u

# ─── dark.fail uptime check ───
curl -s --socks5-hostname 127.0.0.1:9050 https://dark.fail

# ─── OnionScan a service ───
onionscan --verbose --tor-proxy-address 127.0.0.1:9050 http://<onion>.onion

# ─── HIBP single-account ───
curl -s -H "hibp-api-key: <KEY>" -H "User-Agent: <app>" \
  "https://haveibeenpwned.com/api/v3/breachedaccount/<EMAIL>" | jq '.'

# ─── DeHashed search ───
curl -s "https://api.dehashed.com/search?query=email:<EMAIL>" \
  -u "<email>:<KEY>" | jq '.entries[]'

# ─── IntelX phonebook ───
curl -s "https://2.intelx.io/phonebook/search?k=<KEY>" \
  -H "Content-Type: application/json" \
  -d '{"term":"<target>","maxresults":100,"media":0}' | jq '.selectors[]?.selectorvalue'

# ─── PGP key lookup ───
gpg --keyserver hkps://keys.openpgp.org --search-keys "<handle>"

# ─── Monero wallet extraction ───
grep -oE '4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}' profile.html | sort -u

# ─── Encrypt evidence ───
gpg --symmetric --cipher-algo AES256 evidence.tar.gz
shred -uvz evidence.tar.gz

# ─── Tor circuit rotation ───
sudo service tor reload

# ─── Whonix snapshot revert ───
virsh snapshot-revert whonix-workstation pre-investigation
```

---

**Related files**: `SKILL.md`, `test-cases.md`, `guides/dark-web-investigation-playbook.md`
**Key upstreams**: [Tor Project](https://www.torproject.org) | [Ahmia](https://ahmia.fi) | [OnionScan](https://github.com/s-rah/onionscan) | [IntelX](https://intelx.io) | [HaveIBeenPwned](https://haveibeenpwned.com)
