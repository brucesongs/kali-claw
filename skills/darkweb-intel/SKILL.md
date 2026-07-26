---
name: darkweb-intel
description: "Dark web intelligence gathering — Tor/onion service reconnaissance, marketplace monitoring, breach data markets, threat actor profiling, with strict OPSEC for investigators."
origin: openclaw
version: "0.2.0.2"
compatibility:
  - openclaw
  - claude-code
  - cursor
  - windsurf
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
  - WebSearch
  - WebFetch
metadata:
  domain: osint
  tool_count: 10
  guide_count: 2
  mitre: "TA0043-Reconnaissance"
  keywords:
    - tor
    - onion-crawl
    - onionscan
    - ahmia
    - hunchly
    - whonix
    - tails
    - breach-forum
    - opsec
  last_reviewed: "2026-07-26"
---





# Skill: Dark Web Intelligence

> **Supplementary Files**:
> - `payloads.md` — Tor/Whonix/Tails setup, ahmia.fi/Torch/dark.fail/Onionland/Haystak search patterns, OnionScan enumeration, IntelX/DarkOwl/HIBP/DeHashed API usage, threat actor pivot (handles, PGP keys, XMR wallets), Recon-ng darkweb modules, async Python scraping pipeline, OPSEC detection, counter-OSINT cleanup, and a quick-reference cheat sheet
> - `test-cases.md` — 12 structured test cases (Tor setup, .onion resolution, Ahmia query, IntelX query, marketplace enumeration, threat actor pivot, OPSEC verification, breach correlation, counter-OSINT audit) with severity levels and summary tables
> - `guides/dark-web-investigation-playbook.md` — End-to-end investigation playbook (pre-flight, 5-phase workflow, persona management, investigator safety, marketplace reference table, integration with adjacent skills)

## Summary

Darkweb Intel skill domain covering osint operations.

**Tools**: Tor, Tor Browser, Whonix, Tails, Ahmia, Torch, OnionScan, IntelX, HIBP, SpiderFoot

**Domain**: osint

**MITRE ATT&CK**: TA0043-Reconnaissance

## Description

Dark web intelligence gathering across Tor `.onion` services, I2P eepsites, dark-net marketplaces, breach-data forums, and paste sites — with the OPSEC discipline that investigator-side work demands. The skill covers: hardened access setup (Tails/Whonix, obfs4 bridges, Snowflake), discovery (Ahmia, Torch, dark.fail, Onionland, Haystak), service enumeration (OnionScan, ahmia-cli), marketplace & forum monitoring, threat actor profiling (handle, PGP key, Monero wallet correlation), breach data correlation (HIBP, DeHashed, IntelX), and synthesis pipelines that funnel findings back into a defensible dossier.

This is the depth-first complement to clearnet OSINT. Where `osint` casts a wide passive net across clear-web domains, emails, and subdomains, darkweb-intel drills into `.onion`/`.i2p` services and the threat actor economy that lives there.

**Difference from `osint`**: OSINT orchestrates clearnet collection (domain, email, IP, breach data, Shodan). Darkweb-intel focuses specifically on `.onion`/`.i2p` services, dark-net marketplaces, and threat actor communities — it requires Tor/I2P routing, dedicated OPSEC (Tails/Whonix), and a different threat model (investigators are themselves targets).

**Difference from `username-profiling`**: Username profiling runs Maigret against 3,000+ clearnet sites. Darkweb-intel pivots a known handle *into* the darknet — searching paste sites, breach forums, marketplace vendor profiles, and threat actor communities that Maigret does not cover.

**Difference from `social-intelligence`**: Social intelligence mines mainstream discourse (Reddit, HN, X). Darkweb-intel mines discourse that has been deliberately pushed off the clearnet — threat actor forums, vendor reviews, leak announcements, and credentialed paste dumps.

## Use Cases

- **Brand / executive monitoring**: Detect when a brand name, executive email, or proprietary codebase appears in a dark-net marketplace listing, leak forum, or ransomware gang blog — before the public disclosure.
- **Breach impact triage**: When a new breach drops on a leak site, correlate the dump against the client's email/domain/employee list via HIBP, DeHashed, and IntelX to scope impact.
- **Threat actor profiling**: From a single forum handle, recover associated PGP keys, Monero wallets, prior handles, marketplace vendor profiles, and clearnet identities (when actors slip) — building a dossier for attribution.
- **Ransomware leak-site monitoring**: Track which victim organizations appear on each major ransomware gang's leak site, with timestamps and download links, to inform client briefings.
- **Investigative journalism / due diligence**: Verify whether a company, individual, or product is mentioned in dark-net markets, counterfeiting listings, or fraud communities.
- **Insider threat indicator gathering**: Pivot from a suspected insider's clearnet identity into their dark-net persona — looking for credentials-for-sale listings, resentment posts, or criminal market participation.
- **Counter-OSINT (defense)**: Audit your own organization's dark-net footprint — leaked credentials, insider PII, proprietary source code listings — and submit takedowns.
- **Lawful marketplace takedown support**: For a law-enforcement or platform-trust engagement, enumerate vendor accounts, listings, and transaction patterns for evidentiary use.

## Core Tools

### Access & Proxies

| Tool | Purpose | Command / Setup Example |
|------|---------|-------------------------|
| **Tor** | Routing daemon (SOCKS5 on `127.0.0.1:9050`) | `sudo apt install tor && sudo service tor start` |
| **Tor Browser** | Hardened Firefox bundle for manual `.onion` browsing | Download from `torproject.org`; verify PGP signature |
| **obfs4 bridges** | Tor pluggable transport for censored networks | `Bridge obfs4 IP:PORT FINGERPRINT cert=... iat-mode=0` in `torrc` |
| **Snowflake** | WebRTC-based Tor pluggable transport | `UseBridges 1` + `ClientTransportPlugin snowflake exec /usr/bin/snowflake-client` in `torrc` |
| **Whonix** | Two-VM Tor gateway/workstation isolation | Whonix-Gateway routes all Whonix-Workstation traffic through Tor |
| **Tails** | Amnesic live OS — nothing is written to disk | Boot from USB; all traffic routes through Tor; memory wiped on shutdown |

### Search & Discovery

| Tool | Purpose | Query / URL Pattern |
|------|---------|---------------------|
| **Ahmia** (ahmia.fi) | Clearnet-indexed `.onion` search engine | `curl "https://ahmia.fi/search/?q=<term>"` |
| **Ahmia hidden-service** | `.onion`-accessible Ahmia mirror | `curl --socks5-hostname 127.0.0.1:9050 "http://juhanurmihxlp77nkq76byazc4y2sphl4a5hfo3hxnlhkbgz7q6fqd.onion/search/?q=<term>"` |
| **Torch** | Long-running `.onion` search engine | `http://torchde7jygjnqjjp6lcyrch6gzflyol3c5zfsa6uejwnbq7qiiyfqd.onion/search?query=<term>` |
| **dark.fail** | Monitors uptime of well-known `.onion` services (no listings) | `https://dark.fail` |
| **Onionland** | `.onion` search engine with category pages | `http://onionland<random>.onion` (verify current address via Tor Browser) |
| **Haystak** | Indexed `.onion` content (limited free tier) | `https://haystak.com` (clearnet entry, onion mirror available) |
| **Recon-ng** (darkweb modules) | Modular framework with `.onion` host modules | `recon-ng > marketplace install recon/domains-hosts/hackertarget` then onion modules |

### Marketplace & Forum Monitoring

| Tool | Purpose | Notes |
|------|---------|-------|
| **IntelX** (intelligencex.com) | Searches leaks, paste sites, dark-net listings | `curl "https://2.intelx.io/phonebook/search?k=<API_KEY>" -d '{"term":"<target>","maxresults":100}'` |
| **DarkOwl** (commercial reference) | Dark-net index with API | Enterprise license; reference only for this skill |
| **Ahmia marketplace crawler** | Custom Python crawler over Ahmia results | See `payloads.md` section 4 |
| **Manual enumeration** | Direct marketplace browse + scrape via Tor Browser | High-risk — see OPSEC rules |

### Breach & Leak

| Tool | Purpose | Query Pattern |
|------|---------|---------------|
| **HaveIBeenPwned** | Email/domain breach notification | `curl -H "hibp-api-key: <KEY>" "https://haveibeenpwned.com/api/v3/breachedaccount/<EMAIL>"` |
| **DeHashed** | Searchable breach data (email, username, password hash) | `curl "https://api.dehashed.com/search?query=email:<target>" -u "<email>:<key>"` |
| **IntelX** | Phonebook / leak / paste site search | See marketplace monitoring row above |
| **Leaked-data-site enumeration** | Manual review of major leak sites via Tor Browser | varies — sites rotate frequently |

### Profiling

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **Maltego** (with dark-web transforms) | Visual link analysis with `.onion` transforms | GUI hub: Maltego CE + Transforms Marketplace |
| **Lampyre** | OSINT graphical analysis with dark-web sources | Commercial; reference only |
| **SpiderFoot** (with `.onion` modules) | Automated OSINT, optional Tor SOCKS routing | `spiderfoot -s <target> -t DARK_WEB,DARK_WEB_SEARCH --socks5 127.0.0.1:9050` |

### OPSEC

| Tool | Purpose | Setup Notes |
|------|---------|-------------|
| **Tails** | Amnesic live OS | Boot from USB on dedicated hardware |
| **Whonix** | Two-VM isolation | Whonix-Gateway + Whonix-Workstation in VirtManager |
| **VirtManager / KVM** | VM isolation for investigator work | `virt-manager` on a Linux host |
| **Dedicated burner hardware** | Physical isolation for sensitive investigations | No corporate device, no personal device |

## Methodology

### Dark Web Investigation Five-Phase Process

```
Phase 1              Phase 2              Phase 3              Phase 4              Phase 5
Access Setup     →   Discovery &       →  Marketplace &     →  Threat Actor       →  OPSEC-Hardened
                       Search               Forum Monitoring    Profiling              Synthesis
   │                    │                    │                    │                    │
   ▼                    ▼                    ▼                    ▼                    ▼
Tails/Whonix,        Ahmia, Torch,        IntelX, DarkOwl,    Handle → PGP key     Merge findings,
bridges, SOCKS,      dark.fail, Onion-    manual enumeration  → XMR wallet →      encrypt at rest,
egress verified      land, OnionScan      of markets &        prior handles,      produce dossier,
                                          forums              clearnet pivots     schedule monitoring
```

**Phase 1: Access Setup**

Never investigate the dark web from a corporate or personal device with bare Tor. Provision an isolated environment first.

```bash
# Option A: Tails (amnesic, recommended for high-risk investigations)
# Boot from USB; everything is in RAM; shutdown wipes everything

# Option B: Whonix in VirtManager (more flexible, persists between sessions)
# Download Whonix-Gateway and Whonix-Workstation KVM images
# Import both into VirtManager; the Gateway forces all Workstation traffic through Tor

# Option C: Tor on a dedicated VM (lowest isolation, only for low-risk triage)
sudo apt install tor
sudo service tor start
# Verify egress before any work
curl --socks5-hostname 127.0.0.1:9050 https://api.ipify.org
curl --socks5-hostname 127.0.0.1:9050 https://ifconfig.me/json | jq '{ip, country, city}'
```

Add bridges if Tor is blocked on your network (`/etc/tor/torrc`):

```
UseBridges 1
Bridge obfs4 <IP>:<PORT> <FINGERPRINT> cert=<CERT> iat-mode=0
ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy
```

**Phase 2: Discovery & Search**

Use clearnet-indexed search engines first (faster, lower-risk), then pivot to direct `.onion` access for results that require it.

```bash
# Ahmia via clearnet (indexed onion URLs)
curl -s "https://ahmia.fi/search/?q=<target>" \
  | grep -oE 'http[s]?://[a-z2-7]{56}\.onion[^" ]*' | sort -u

# Ahmia via its own onion service (full anonymity)
curl -s --socks5-hostname 127.0.0.1:9050 \
  "http://juhanurmihxlp77nkq76byazc4y2sphl4a5hfo3hxnlhkbgz7q6fqd.onion/search/?q=<target>" \
  | grep -oE 'http[s]?://[a-z2-7]{56}\.onion[^" ]*' | sort -u

# dark.fail (uptime status of well-known services, no listings)
curl -s --socks5-hostname 127.0.0.1:9050 https://dark.fail

# OnionScan a discovered .onion for service fingerprinting, linked services, artifacts
onionscan --verbose --tor-proxy-address 127.0.0.1:9050 \
  http://<56-char-onion>.onion
```

**Phase 3: Marketplace & Forum Monitoring**

Mix automated commercial APIs (IntelX, DarkOwl) with manual Tor Browser enumeration. Marketplaces rotate addresses frequently — track current addresses via dark.fail and Ahmia, never trust a static list.

```bash
# IntelX phonebook search (credential/breach context for an identifier)
curl -s "https://2.intelx.io/phonebook/search?k=<API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"term":"<target_email_or_handle>","maxresults":100,"media":0}' \
  | jq '.selectors[]?.selectorvalue // empty'

# Manual enumeration via Tor Browser:
# 1. Navigate to current marketplace .onion (verified via dark.fail)
# 2. Search vendor name, brand string, or product identifier
# 3. Capture screenshots, listing URLs, vendor profile URLs into an encrypted evidence vault
# 4. NEVER purchase anything — observer role only
```

**Phase 4: Threat Actor Profiling**

From a forum handle, correlate every identifier the actor exposes — PGP keys, Monero wallets, prior handles, signed messages, marketplace vendor profiles.

```bash
# PGP key lookup (many actors publish a fingerprint in forum signatures)
gpg --keyserver hkps://keys.openpgp.org --search-keys "<handle>@<forum_domain>"

# Cross-reference the PGP fingerprint across other forums:
#   - Many actors reuse the same key across communities
#   - sks-keyservers mirror at keys.openpgp.org, keyserver.ubuntu.com

# Monero (XMR) wallet tracing is intentionally limited — but wallet addresses
# appear in marketplace vendor profiles, donation posts, and escrow pages.
# Correlate the same address across sites; note that XMR is privacy-preserving
# and on-chain tracing is far weaker than Bitcoin.

# Handle pivot: search the handle across every forum and paste site
for forum in forum1.onion forum2.onion forum3.onion; do
  curl -s --socks5-hostname 127.0.0.1:9050 \
    "http://$forum/search?q=<handle>" \
    >> handle_corpus.html
done
```

**Phase 5: OPSEC-Hardened Synthesis**

Aggregate findings, encrypt the deliverable, and define a monitoring cadence — dark-net evidence goes stale quickly.

```bash
# Encrypt the dossier before storage
gpg --symmetric --cipher-algo AES256 darkweb_dossier.md
shred -uvz darkweb_dossier.md   # remove plaintext

# Set up recurring Ahmia + IntelX monitoring for the target term
echo "0 8 * * * curl -s 'https://ahmia.fi/search/?q=<target>' >> /var/log/dw-monitor.log" | crontab -

# Hand to a non-technical client? Use Maltego or a PDF export — never raw .onion URLs
# without context (clients will click them from a clearnet browser and burn themselves).
```

### Quick Selection Guide

| Scenario | Primary Approach | Alternative |
|----------|------------------|-------------|
| First-time dark-net triage | Tails boot + Tor Browser + Ahmia clearnet search | Whonix VM + Ahmia onion service |
| Censored network (Tor blocked) | obfs4 bridges or Snowflake in `torrc` | Snowflake via Tor Browser config |
| Find onion services mentioning a term | `ahmia.fi/search/?q=<term>` (clearnet entry) | Torch `.onion` direct |
| Verify a well-known onion's uptime | `curl https://dark.fail` | Manual Tor Browser visit |
| Enumerate a discovered `.onion` for leaks | `onionscan --tor-proxy-address 127.0.0.1:9050 <URL>` | Manual Tor Browser inspection |
| Search breach data for an email | HIBP API + DeHashed + IntelX | h8mail local aggregator |
| Marketplace vendor pivot | IntelX + manual Tor Browser enum (read-only) | DarkOwl commercial API |
| Threat actor PGP correlation | `gpg --search-keys <handle>@<domain>` + openpgp keyserver | Manual signature scraping |
| Investigator OPSEC verification | Egress check via `curl --socks5-hostname` + browser fingerprint audit | Tails reboot + DNS leak test |
| Continuous brand monitoring | `cron` job hitting Ahmia + IntelX daily | Commercial dark-web monitoring service |
| Python pipeline for bulk analysis | Async `aiohttp` via Tor SOCKS (see `payloads.md` §12) | SpiderFoot + dark-web modules |

### Defense Perspective

| Defense Measure | Description |
|-----------------|-------------|
| **Brand / executive dark-net monitoring** | Run weekly Ahmia + IntelX sweeps on brand names, executive emails, and proprietary product identifiers — catch leaks before they hit the clearnet. |
| **Breach subscription + dark-net correlation** | Subscribe to HIBP domain notifications; when an alert fires, immediately check IntelX for dark-net listings referencing the same data. |
| **Credential hygiene response** | When dark-net listings surface employee credentials, force password rotation + MFA enrollment for affected accounts. Do not assume "the password is old." |
| **Source code leak monitoring** | Index proprietary code identifiers (unusual function names, internal module names) and sweep dark-net paste sites and source markets weekly. |
| **Insider threat indicator gathering** | For lawfully authorized insider-threat programs, monitor known insider handles and PGP keys for distress signals, resentment posts, or for-cred sale listings. |
| **Investigator OPSEC training** | Anyone running dark-net collection must understand: Tails/Whonix isolation, persona contamination, behavioral fingerprinting, and physical safety. Tooling alone is not sufficient. |
| **Persona separation** | Never use a corporate email, corporate device, or personal handle when registering a dark-net monitoring account. Maintain a dedicated persona per investigation. |
| **Counter-OSINT for investigators** | Periodically audit your own monitoring persona's footprint — has the persona been linked back to the org via reused PGP keys, wallets, or browser fingerprints? |

## Practical Steps

> **Detailed payloads in `payloads.md`, complete test checklist in `test-cases.md`.**

### Exercise 1: Hardened Tor Access Setup

Goal: provision a Tor-routed investigation environment with verified egress and DNS leak protection.

```bash
# Install Tor + verification tooling
sudo apt update
sudo apt install -y tor curl jq dnsutils

# Start Tor and verify
sudo service tor start
sleep 3

# Verify egress IP — must NOT be your real IP
echo "Real IP:    $(curl -s https://api.ipify.org)"
echo "Tor IP:     $(curl -s --socks5-hostname 127.0.0.1:9050 https://api.ipify.org)"

# Verify DNS doesn't leak (must show Tor exit location)
curl -s --socks5-hostname 127.0.0.1:9050 https://ifconfig.me/json | \
  jq '{ip, country, city}

# Optional: configure obfs4 bridge if Tor direct is blocked
# Add to /etc/tor/torrc:
#   UseBridges 1
#   Bridge obfs4 <IP>:<PORT> <FINGERPRINT> cert=<CERT> iat-mode=0
#   ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy
sudo service tor restart
```

### Exercise 2: Ahmia Clearnet + Onion Search

Goal: discover onion services mentioning a target term, using both clearnet Ahmia (fast) and the onion Ahmia mirror (full anonymity).

```bash
TARGET="<brand_or_term>"

# Clearnet Ahmia (faster, but exposes your IP to ahmia.fi)
curl -s "https://ahmia.fi/search/?q=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$TARGET")" \
  | grep -oE 'http[s]?://[a-z2-7]{56}\.onion' | sort -u > onions_clearnet.txt

# Onion Ahmia (full anonymity, slower)
curl -s --socks5-hostname 127.0.0.1:9050 \
  "http://juhanurmihxlp77nkq76byazc4y2sphl4a5hfo3hxnlhkbgz7q6fqd.onion/search/?q=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$TARGET")" \
  | grep -oE 'http[s]?://[a-z2-7]{56}\.onion' | sort -u > onions_hidden.txt

# Diff — onion-Ahmia often surfaces results the clearnet indexer skips
sort -u onions_clearnet.txt onions_hidden.txt | uniq -c | sort -rn
```

### Exercise 3: OnionScan a Discovered Service

Goal: fingerprint a discovered `.onion` — find linked services, open ports, server banners, and exposed artifacts.

```bash
# Install OnionScan
go install github.com/s-rah/onionscan@latest
# Or: sudo apt install onionscan  (older but functional)

# Scan via Tor
onionscan --verbose \
  --tor-proxy-address 127.0.0.1:9050 \
  --timeout 120 \
  http://<56-char-onion>.onion

# OnionScan reports: Apache mod_status, exposed directories, PGP keys,
# linked .onion services (which become Phase 4 pivots), server software,
# and known dangerous configurations
```

### Exercise 4: Marketplace Enumeration (Read-Only)

Goal: identify whether a target brand or product appears in a dark-net marketplace — strictly as an observer.

```bash
# Step 1: Verify the marketplace's current .onion via dark.fail (NEVER trust a static list)
curl -s --socks5-hostname 127.0.0.1:9050 https://dark.fail | \
  grep -iE 'market|forum' | head -20

# Step 2: In Tor Browser (manual), navigate to the verified .onion
# Step 3: Search for the target brand/product term
# Step 4: For each match, capture:
#   - Listing URL (.onion + path)
#   - Vendor profile URL
#   - Vendor PGP key (often published on profile)
#   - Screenshot (Tor Browser's built-in screenshot tool)
# Step 5: Store artifacts in an encrypted vault
gpg --symmetric --cipher-algo AES256 market_evidence.tar.gz

# CRITICAL OPSEC RULES:
# - Never register an account unless authorized
# - Never purchase anything
# - Never message a vendor
# - Limit session length; rotate personas between marketplaces
```

### Exercise 5: Threat Actor Pivot (Handle → PGP → Wallet)

Goal: from a single forum handle, build the threat actor's identifier graph.

```bash
HANDLE="<forum_handle>"

# Step 1: PGP key lookup (many actors publish a key with a forum-domain uid)
gpg --keyserver hkps://keys.openpgp.org --search-keys "$HANDLE"
gpg --keyserver hkps://keyserver.ubuntu.com --search-keys "$HANDLE"

# Step 2: Scrape the actor's forum profile (via Tor) for:
#   - Monero wallet address (donation / vendor escrow page)
#   - Prior handles ("formerly known as ...")
#   - Other communities ("also on ...")
curl -s --socks5-hostname 127.0.0.1:9050 \
  "http://<forum>.onion/profile/$HANDLE" > profile.html

# Step 3: Extract wallet addresses
grep -oE '4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}' profile.html | sort -u  # Monero
grep -oE '[13][a-km-zA-HJ-NP-Z1-9]{25,34}' profile.html | sort -u   # Bitcoin (legacy)
grep -oE 'bc1[a-z0-9]{39,59}' profile.html | sort -u                 # Bitcoin (bech32)

# Step 4: Pivot the PGP fingerprint and wallet address to other forums
# Re-run this exercise with each new identifier as the seed
```

### Exercise 6: Breach Data Correlation

Goal: when a breach is announced, scope impact against the client's email/domain/employee list.

```bash
# HIBP single-account check (needs API key)
curl -s -H "hibp-api-key: <KEY>" -H "User-Agent: <app-name>" \
  "https://haveibeenpwned.com/api/v3/breachedaccount/<EMAIL>?truncateResponse=false" \
  | jq '.[] | {Name, BreachDate, DataClasses}'

# HIBP domain-wide (enterprise subscription)
curl -s -H "hibp-api-key: <KEY>" \
  "https://haveibeenpwned.com/api/v3/breacheddomain/<DOMAIN>" | jq '.'

# DeHashed search (returns full record including hashes)
curl -s "https://api.dehashed.com/search?query=email:<target_email>" \
  -u "<account_email>:<API_KEY>" | jq '.entries[] | {email, username, password, hashed_password}'

# IntelX phonebook search (find related identifiers)
curl -s "https://2.intelx.io/phonebook/search?k=<INTELX_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"term":"<target_email>","maxresults":100,"media":0}' \
  | jq '.selectors[]?.selectorvalue' | sort -u
```

### Exercise 7: Investigator OPSEC Verification

Goal: verify your dark-web investigation environment leaks no real identity.

```bash
# 1. Egress IP — must NOT be your real IP
REAL_IP=$(curl -s https://api.ipify.org)
TOR_IP=$(curl -s --socks5-hostname 127.0.0.1:9050 https://api.ipify.org)
echo "Real IP: $REAL_IP"
echo "Tor IP:  $TOR_IP"
[ "$REAL_IP" = "$TOR_IP" ] && echo "FAIL: Tor not routing" || echo "PASS: Tor egress differs"

# 2. DNS leak — DNS queries must NOT go to your ISP resolver
# Check /etc/resolv.conf in Tails/Whonix — should be 127.0.0.1 (local Tor DNS)
cat /etc/resolv.conf | grep -v '^#'

# 3. WebRTC leak (in Tor Browser) — visit https://browserleaks.com/webrtc via Tor Browser
#    Tor Browser disables WebRTC by default; verify it stays disabled

# 4. Browser fingerprint — Tor Browser is designed to make all users look identical
#    Visit https://check.torproject.org via Tor Browser — should show green "Congratulations"
#    Visit https://www.amiunique.org — should NOT show a unique fingerprint

# 5. Persona contamination audit
#    Have you ever logged into this dark-net monitoring persona from a clearnet
#    identity? From your real IP? If yes, the persona is compromised — burn it.
```

### Exercise 8: Python Async Pipeline via Tor

Goal: orchestrate Ahmia + IntelX + manual `.onion` fetches in a single async pipeline.

```python
"""
Async dark-web intelligence pipeline routed through Tor SOCKS5.
"""
import asyncio
import re
from urllib.parse import quote

import aiohttp
from aiohttp_socks import ProxyConnector

TOR_SOCKS = "socks5://127.0.0.1:9050"
ONION_RE = re.compile(r"https?://[a-z2-7]{56}\.onion", re.IGNORECASE)


async def fetch(session: aiohttp.ClientSession, url: str, *, via_tor: bool = True) -> str:
    timeout = aiohttp.ClientTimeout(total=120)
    try:
        async with session.get(url, timeout=timeout) as resp:
            return await resp.text()
    except Exception as exc:
        return f"ERROR: {exc}"


async def ahmia_search(term: str) -> set[str]:
    connector = ProxyConnector.from_url(TOR_SOCKS) if True else None
    async with aiohttp.ClientSession(connector=connector) as session:
        url = f"http://juhanurmihxlp77nkq76byazc4y2sphl4a5hfo3hxnlhkbgz7q6fqd.onion/search/?q={quote(term)}"
        html = await fetch(session, url)
        return set(ONION_RE.findall(html))


async def main(term: str) -> None:
    onions = await ahmia_search(term)
    print(f"Discovered {len(onions)} onion services for term: {term}")
    for o in sorted(onions):
        print(f"  {o}")


if __name__ == "__main__":
    asyncio.run(main("example target term"))
```

### Exercise 9: Counter-OSINT Audit (Investigator Self-Defense)

Goal: periodically verify your dark-net monitoring persona has not been linked back to the organization.

```bash
# 1. Search the persona's handle across clearnet + dark-net for doxing
curl -s "https://ahmia.fi/search/?q=<persona_handle>" | grep -i <persona_handle>
maigret <persona_handle> --tags us   # is the handle used on clearnet?

# 2. Verify PGP key attached to persona has no clearnet uid
gpg --list-keys <persona_pgp_fingerprint>
# Any uid matching your real name/email = persona burned

# 3. Verify Monero wallet used by persona appears nowhere else
# Search the wallet address on the major block explorers (xmrchain.net etc.) —
# only transactions YOU initiated should appear

# 4. Audit Tor Browser profile for accidental bookmark/history leakage
# In Tails: nothing persists (amnesic). In Whonix: snapshots must be discarded.

# 5. If persona is burned: rotate name, PGP key, wallet, and never reuse on the
# same forum. The forum's admins now have your old persona flagged.
```

## Safety Notes

- **Lawful use only**: Dark-net investigation is heavily regulated in most jurisdictions. Accessing `.onion` services is generally legal; purchasing controlled substances, stolen data, or attack tools is not. Many marketplaces operate as honeypots. Confirm engagement scope and lawful basis before any collection.
- **Jurisdictional complexity**: Servers you contact may be in jurisdictions where the content you're viewing is criminal to even view (CSAM, certain political content). Investigators must know their home jurisdiction's strict-liability rules.
- **Investigator OPSEC is non-negotiable**: Dark-net actors actively deanonymize investigators. Real-IP leaks, persona contamination, and behavioral fingerprinting have led to investigators being doxxed, swatted, and physically threatened. Use Tails/Whonix, dedicated hardware, and rotate personas.
- **Investigator safety**: If during an investigation you encounter credible threats of physical harm, or content that triggers mandatory reporting (CSAM), stop, document, and contact the appropriate authorities. Do not attempt to handle in-channel.
- **Authorization scope**: A pentest engagement authorizes the target organization's systems. It does *not* authorize purchasing stolen data about the client from a marketplace, even with the client's nominal consent — that can be trafficking in stolen property.
- **Data minimization**: Dark-net artifacts (screenshots, PGP keys, wallet addresses) are sensitive. Encrypt at rest (`gpg --symmetric --cipher-algo AES256`), restrict access, and securely delete (`shred -uvz`) when the engagement closes.

## Detection Methods

### Dark Web Monitoring
- **Credential leak detection**: Services like SpyCloud, HaveIBeenPwned, IntelX alert when org credentials appear in dark web dumps.
- **Mention monitoring**: Brand keywords (company name, executive names, product codenames) appearing on dark web forums.
- **Stolen data marketplaces**: New dataset listings matching org's data fingerprint.
- **Ransomware leak sites**: New entries on ransomware gang blogs matching org's data.

### SIEM Detection Rules
- **Splunk SPL**: Correlate internal auth events with dark web credential dumps via threat intel feeds.
- **Recorded Future / Flashpoint**: Dark web threat intelligence platform alerts.
- **ZeroFox / LookingGlass**: Brand protection and dark web monitoring services.

## Defense Evasion Techniques

### Source Concealment
- **Tor + VPN chain**: Tor circuit exit to VPN; masks Tor usage from network monitoring.
- **Bridge relays**: Use Tor bridges (obfs4, Snowflake) to bypass Tor blocking.
- **I2P / Freenet**: Alternative darknets for monitoring beyond Tor.
- **Forum burners**: Unique credentials for each dark web forum; rotate regularly.

### Detection Evasion
- **Time-shifted monitoring**: Slow, distributed reads of forum data; avoids burst detection.
- **Avoid direct contact**: Use OSINT aggregators (IntelX, Ahmia) rather than direct forum access.
- **Mimic legitimate researcher**: Use academic / journalist credentials; access appears legitimate.
- **Cryptocurrency mixers**: Use Monero or Bitcoin mixers for paid access; avoid address correlation.

## Hacker Laws

- **Information Wants to Be Free** — Breach data, leaked credentials, and internal documents on the dark-net are already free; they exist outside the control of their original owners. Darkweb-intel makes them findable. Defense cannot recall them; it can only detect exposure earlier and rotate affected credentials.
- **Obscurity Is Not Security** — A `.onion` address is only obscure, not secure. Indexers (Ahmia, Torch), crawlers (IntelX, DarkOwl), and law-enforcement sweeps map the dark-net continuously. Treat any dark-net service as potentially indexed and act accordingly.
- **Trust but Verify** — Marketplace listings can be fraud; breach data can be repackaged or fabricated; threat actor claims of responsibility can be false-flag. Cross-verify every dark-net finding against at least one independent source (second marketplace, second breach corpus, second forum) before treating it as fact.
- **Weakest Link Is Human** — Investigators are the weakest link. Real-IP leaks, persona reuse, and careless browser fingerprinting have deanonymized more investigators than any technical vulnerability. Tails and Whonix are necessary but not sufficient — training and discipline are the actual control.
- **Divergent Thinking First** — A single dark-net source has blind spots. Run Ahmia (clearnet-indexed) AND Torch (direct `.onion`); run IntelX AND manual Tor Browser enumeration; cross-reference PGP keys across keyservers AND forum signatures. Overlapping collection catches what any single source misses.

## Learning Resources

- **This skill's supplementary files**: `payloads.md`, `test-cases.md`
- **Deep-dive guide**: `guides/dark-web-investigation-playbook.md` — end-to-end investigation workflow with persona management, OPSEC hardening, and integration with adjacent OSINT skills
- **Related skills**:
  - `skills/osint/SKILL.md` — broader clearnet OSINT (email, domain, breach, Shodan)
  - `skills/username-profiling/SKILL.md` — clearnet username enumeration via Maigret; pivot input for dark-net handle correlation
  - `skills/social-intelligence/SKILL.md` — mainstream discourse mining; complementary signal for threat actor sentiment
  - `skills/deep-research/SKILL.md` — synthesis and report writing for the final dossier
  - `skills/social-engineering/SKILL.md` — turning threat actor dossiers into defensive priorities (NOT into pretext for offense)
- **External resources**:
  - Tor Project: [torproject.org](https://www.torproject.org)
  - Ahmia: [ahmia.fi](https://ahmia.fi)
  - dark.fail: [dark.fail](https://dark.fail)
  - OnionScan: [github.com/s-rah/onionscan](https://github.com/s-rah/onionscan)
  - IntelX: [intelx.io](https://intelx.io)
  - HaveIBeenPwned: [haveibeenpwned.com](https://haveibeenpwned.com)
  - DeHashed: [dehashed.com](https://dehashed.com)
  - Whonix: [whonix.org](https://www.whonix.org)
  - Tails: [tails.net](https://tails.net)
  - EFF OPSEC guides: [eff.org/issues/anonymity](https://www.eff.org/issues/anonymity)
  - Bellingcat Online Investigation Toolkit: [bellingcat.gitbook.io/toolkit](https://bellingcat.gitbook.io/toolkit)
- **Core system files**: `SOUL.md`, `TOOLS.md`, `IDENTITY.md`
