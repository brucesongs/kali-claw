# Username Profiling Payloads / Maigret Command Catalogue

> Companion to `SKILL.md`. Every command here is reproducible on Kali Linux 2025-2 with `pip3 install maigret` (and optionally `pip3 install 'maigret[pdf]'`).
>
> Placeholder convention: `<username>` is the seed handle, `<URL>` is a profile URL, `<email>` is a discovered email.

---

## 1. Installation & First Run

```bash
# From PyPI (CLI)
pip3 install maigret

# Optional: PDF report support (needs system graphics libs on Linux/macOS)
pip3 install 'maigret[pdf]'
# Linux prerequisites for PDF:
sudo apt-get install libcairo2 libpango-1.0-0 libpangoft2-1.0-0

# From source
git clone https://github.com/soxoj/maigret && cd maigret
pip3 install .

# Docker (CLI mode)
docker pull soxoj/maigret
docker run -v "$PWD/reports:/app/reports" soxoj/maigret:latest <username> --html

# Docker (web UI mode — open http://localhost:5000)
docker run -p 5000:5000 soxoj/maigret:web

# Standalone Windows exe (no Python needed)
# Download maigret_standalone.exe from https://github.com/soxoj/maigret/releases
maigret_standalone.exe <username>
maigret_standalone.exe <username> --html
maigret_standalone.exe --help

# Verify install + DB auto-update
maigret --version
maigret <username>      # first run auto-fetches site DB from GitHub (24h cache)
```

---

## 2. Basic Scan Modes

```bash
# Default scan: top 500 sites ranked by traffic
maigret <username>

# Full scan: all 3,000+ sites (slow, ~30-60 min depending on connection)
maigret <username> -a

# Multi-username batch (single report, multiple subjects)
maigret user1 user2 user3 -a

# Filter by tag (categories like photo, dating, social, forum)
maigret <username> --tags photo,dating

# Filter by country tag (us, ru, cn, de, fr, etc.)
maigret <username> --tags us

# Combine tags
maigret <username> --tags photo,us

# Limit concurrent connections (be nicer to target sites)
maigret <username> -a --max-connections 10

# Per-site timeout and retries
maigret <username> -a --timeout 15 --retries 2

# Disable color (cleaner logs)
maigret <username> -a --no-color
```

---

## 3. Report Generation

### 3.1 HTML / PDF / XMind (Human-Readable)

```bash
# HTML — browsable dossier with screenshots and metadata
maigret <username> --html

# PDF — printable executive briefing
# Needs pip3 install 'maigret[pdf]' AND system graphics libs
maigret <username> --pdf

# XMind 8 mindmap — analyst-friendly relationship map
# NOT compatible with XMind 2022+ (use older XMind 8 to open)
maigret <username> --xmind

# Generate multiple formats at once
maigret <username> --html --pdf --xmind
```

### 3.2 Interactive Graph

```bash
# D3.js interactive graph (open the HTML in a browser)
# Shows claimed accounts as nodes, pivot relationships as edges
maigret <username> --graph

# Combined with full scan
maigret <username> -a --html --graph
```

### 3.3 Machine-Readable Exports

```bash
# NDJSON — one JSON object per line per site result
# Best for downstream scripting (jq, awk, grep)
maigret <username> --json ndjson

# Simple JSON — single nested document
maigret <username> --json simple

# CSV — spreadsheet import
maigret <username> --csv

# Plain text — terminal-friendly summary
maigret <username> --txt
```

### 3.4 Parsing NDJSON Output

```bash
# All claimed sites
jq -r 'select(.status=="Claimed") | "\(.site_name)\t\(.url)"' \
  reports/<username>_ndjson.json | sort

# All discovered usernames (for recursive pivot)
jq -r 'select(.status=="Claimed") | .extracted.usernames[]? // empty' \
  reports/<username>_ndjson.json | sort -u

# All discovered emails
jq -r 'select(.status=="Claimed") | .extracted.emails[]? // empty' \
  reports/<username>_ndjson.json | sort -u

# Sites that mention specific keywords (matches --keywords highlight)
jq -r 'select(.keywords_matched | length > 0) | "\(.site_name): \(.keywords_matched)"' \
  reports/<username>_ndjson.json

# Count of claimed / available / unknown per site category (if tagged)
jq -r 'select(.status=="Claimed") | .tags[]?' \
  reports/<username>_ndjson.json | sort | uniq -c | sort -rn
```

---

## 4. Recursive Pivot & Discovery

```bash
# Parse a profile page, extract embedded usernames/IDs, recurse on each
maigret --parse <URL> --html --graph

# Common starting points for --parse
maigret --parse https://github.com/<username> --html
maigret --parse https://x.com/<username> --html
maigret --parse https://www.reddit.com/user/<username> --html
maigret --parse https://keybase.io/<username> --html

# Full recursive workflow: extract discovered usernames, re-run Maigret
jq -r 'select(.status=="Claimed") | .extracted.usernames[]? // empty' \
  reports/<username>_ndjson.json | sort -u > discovered_usernames.txt

head -5 discovered_usernames.txt | while read user; do
  maigret "$user" --html --tags us --timeout 15
done

# Permute a real name into likely usernames and search each
maigret "john doe" --permute --html --graph

# Highlight sites mentioning target-relevant keywords (e.g. tech stack)
maigret <username> --keywords python rust linux docker kubernetes --html
```

---

## 5. Proxies, Tor, I2P

```bash
# Generic HTTP proxy
maigret <username> --proxy http://user:pass@proxy.local:8080

# SOCKS5 proxy (e.g. SSH dynamic forward)
ssh -D 1080 user@bastion
maigret <username> --proxy socks5://127.0.0.1:1080

# Tor (start daemon first: sudo service tor start)
maigret <username> --tor-proxy socks5://127.0.0.1:9050 --timeout 30

# I2P (start i2pd first)
maigret <username> --i2p-proxy http://127.0.0.1:4444

# .onion and .i2p sites (Tor/I2P proxy is mandatory)
maigret "darkforum-user" --tor-proxy socks5://127.0.0.1:9050 -a

# Cloudflare-protected sites — start FlareSolverr, then opt in
docker run -d -p 8191:8191 --name flaresolverr ghcr.io/flaresolverr/flaresolverr:latest
maigret --cloudflare-bypass <username> --html

# Verify your egress IP through Tor before running
curl --socks5-hostname 127.0.0.1:9050 https://api.ipify.org
# Should NOT match your real IP
```

---

## 6. AI-Assisted Summary

```bash
# Requires OpenAI-compatible API key
export OPENAI_API_KEY=sk-...

# Default model (whatever OpenAI/compatible endpoint serves)
maigret <username> -a --ai

# Pick a specific model
maigret <username> -a --ai --ai-model gpt-4o-mini

# Point at a non-OpenAI endpoint via settings.json:
# {
#   "openai_api_key": "sk-...",
#   "openai_api_base_url": "http://localhost:8000/v1",
#   "openai_ai_model": "llama3.1:70b"
# }
maigret <username> -a --ai

# Output includes: likely real name, location, occupation, interests,
# languages, overall confidence, and follow-up leads
```

---

## 7. Database & Self-Check (Maintainer Mode)

```bash
# Self-check: verify usernameClaimed/usernameUnclaimed pairs against live sites
# Used by maintainers to detect sites whose detection rules have broken
maigret --self-check

# Self-check and auto-disable broken sites
maigret --self-check --auto-disable

# Use a custom site database file
maigret <username> --db /path/to/custom_data.json

# Disable the auto-update (use built-in DB only, offline-friendly)
maigret <username> --no-db-update

# Use a manually updated DB pulled from GitHub
wget https://raw.githubusercontent.com/soxoj/maigret/main/maigret/resources/data.json
maigret <username> --db ./data.json

# Force a DB refresh (Maigret normally caches for 24h)
rm -rf ~/.cache/maigret   # or wherever the cache lives on your install
maigret <username>
```

---

## 8. Cross-Tool Verification Workflow

```bash
# Step 1: Run Maigret (full coverage)
maigret <username> -a --json ndjson --html --graph

# Step 2: Run Sherlock (independent ruleset, 300+ sites)
sherlock <username> --json --output sherlock_<username>.json --timeout 10

# Step 3: Run WhatsMyName (different site list, different logic)
# Install: pip3 install whatsmyname  OR  use the web/JSON file directly
whatsmyname -u <username> --format json --output wmn_<username>.json

# Step 4: Run Holehe (if an email was discovered via Maigret)
email=$(jq -r 'select(.status=="Claimed") | .extracted.emails[]? // empty' \
  reports/<username>_ndjson.json | head -1)
[ -n "$email" ] && holehe "$email" > holehe_<username>.txt

# Step 5: Diff Maigret vs Sherlock to find Maigret-only claims
# (these need manual verification — most likely to be false positives)
jq -r '.site' reports/<username>_ndjson.json | sort -u > maigret_sites.txt
jq -r 'keys[]' sherlock_<username>.json | sort -u > sherlock_sites.txt
comm -23 maigret_sites.txt sherlock_sites.txt > maigret_only.txt
wc -l maigret_only.txt   # number of manual verification candidates

# Step 6: Merge claimed accounts from all sources
jq -r 'select(.status=="Claimed") | "\(.site_name)\t\(.url)"' \
  reports/<username>_ndjson.json > claimed_maigret.tsv
jq -r 'to_entries[] | select(.value.status=="claimed") | "\(.key)\t\(.value.url)"' \
  sherlock_<username>.json > claimed_sherlock.tsv 2>/dev/null
cat claimed_*.tsv | sort -u > claimed_all.tsv
```

---

## 9. Companion Tool Quick Reference

### Sherlock

```bash
pip3 install sherlock-project

# Basic search (300+ sites)
sherlock <username>

# JSON output
sherlock <username> --json --output profiles.json

# Multi-username
sherlock user1 user2 user3 --json

# Site-specific (filter)
sherlock <username> --site GitHub --site Twitter

# Print found only (suppress negative results)
sherlock <username> --print-found

# Timeout / rate limit
sherlock <username> --timeout 10 --ratelimit 2
```

### WhatsMyName

```bash
# One-off username check using the public JSON list
# (no install — just curl the data and grep)
curl -s https://raw.githubusercontent.com/webbreacher/whatsmyname/main/wmn-data.json \
  | jq -r --arg u "<username>" '
      .sites[]
      | .uri_check as $uri
      | "\(.name)\t\($uri | sub("{username}"; $u))"
    ' > candidate_urls.txt

# Then check each candidate URL
while IFS=$'\t' read -r name url; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "$url")
  echo "$code  $name  $url"
done < candidate_urls.txt | sort

# Or install whatsmyname CLI
pip3 install whatsmyname
whatsmyname -u <username> --format json --output wmn_<username>.json
```

### Holehe (Email → Service Registration)

```bash
pip3 install holehe

# Check which services an email is registered with (120+ services)
holehe <email>

# Example: j.doe@example.com
holehe j.doe@example.com

# Output lines like:
# [+] spotify.com
# [+] twitter.com
# [-] github.com
```

### Blackbird

```bash
# Install: https://github.com/p1ngul1n0/blackbird
# Searches across 500+ sites with API integrations
blackbird --username <username>
```

---

## 10. Python Library Embedding

```python
"""
Async Maigret call from a custom OSINT pipeline.
Useful when you want to feed results directly into a graph database
or another tool without round-tripping through JSON files.
"""
import asyncio
from maigret import maigret
from maigret.sites import MaigretDatabase
from maigret.output import MaigretReport


async def investigate(
    username: str,
    *,
    tags: list[str] | None = None,
    timeout: int = 20,
    max_connections: int = 20,
) -> dict:
    """Run Maigret on a username, return a dict of site_name -> status."""
    db = MaigretDatabase()
    db.load_default_db()
    sites = db.ranked_sites_top_only() if not tags else db.ranked_sites_tags(tags)

    results = await maigret(
        username=username,
        site_list=sites,
        timeout=timeout,
        max_connections=max_connections,
    )

    return {
        site_name: {
            "status": str(result.status),
            "url": result.site_url,
            "extracted": result.extracted,
        }
        for site_name, result in results.items()
    }


async def recursive_pivot(seed: str, depth: int = 2) -> dict:
    """Run Maigret, extract discovered usernames, recurse up to depth times."""
    visited: set[str] = {seed}
    all_findings: dict[str, dict] = {}

    queue = [seed]
    for _ in range(depth):
        next_queue: list[str] = []
        for user in queue:
            findings = await investigate(user)
            all_findings[user] = findings
            for site_result in findings.values():
                for discovered in site_result.get("extracted", {}).get("usernames", []):
                    if discovered not in visited:
                        visited.add(discovered)
                        next_queue.append(discovered)
        queue = next_queue
        if not queue:
            break

    return all_findings


if __name__ == "__main__":
    findings = asyncio.run(recursive_pivot("johndoe123", depth=2))
    for user, sites in findings.items():
        claimed = [k for k, v in sites.items() if v["status"] == "Claimed"]
        print(f"{user}: {len(claimed)} claimed accounts")
```

---

## 11. Tag Reference (Common Categories)

> Tags live in Maigret's `data.json`. Run `maigret --help` or inspect the DB for the full current list.

| Tag Category | Example Tags | Use Case |
|--------------|--------------|----------|
| Content type | `photo`, `video`, `blog`, `forum`, `dating`, `shopping` | Narrow by content type |
| Country / Region | `us`, `ru`, `cn`, `de`, `fr`, `jp`, `br` | Geo-focused investigations |
| Tech / Dev | `dev`, `github`, `gitlab` | Developer footprint |
| Social | `social`, `microblog` | Mainstream social platforms |
| Gaming | `gaming`, `chess` | Gaming community footprint |
| Finance | `finance`, `crypto` | Financial / crypto footprint |
| Adult | `adult` | Adult content platforms (legal scope check required) |

```bash
# Discover available tags from the DB
python3 -c "
from maigret.sites import MaigretDatabase
db = MaigretDatabase()
db.load_default_db()
tags = set()
for site in db.sites:
    tags.update(site.tags.get('tags', []))
for t in sorted(tags):
    print(t)
"
```

---

## 12. Web UI Usage

```bash
# Launch web UI (graph viewer + all report formats from one page)
docker run -p 5000:5000 soxoj/maigret:web

# Custom port
docker run -e PORT=8080 -p 8080:8080 soxoj/maigret:web

# Open http://localhost:5000
# - Enter username in the search box
# - Watch live results stream in
# - Download report in any format (HTML / PDF / XMind / CSV / JSON / graph) from one page
# - Browse identity graph interactively
```

---

## 13. OPSEC Hardening Checklist

```bash
# 1. NEVER run from your corporate egress IP
# Always tunnel:
maigret <username> --tor-proxy socks5://127.0.0.1:9050

# 2. Rotate User-Agent (Maigret does this internally, verify)
maigret <username> --help | grep -i 'user-agent'

# 3. Add delays between requests if WAFs trigger
# (Use --max-connections to throttle concurrency)
maigret <username> --max-connections 5 --timeout 30

# 4. Verify your egress before each run
curl --socks5-hostname 127.0.0.1:9050 https://api.ipify.org
curl --socks5-hostname 127.0.0.1:9050 https://ifconfig.me/json | jq '{ip, country}'

# 5. Don't reuse the same proxy for multiple unrelated targets
# (correlation across usernames → operator fingerprint)

# 6. Clean up reports directory after engagement
shred -uvz reports/<username>/*
rm -rf reports/<username>/

# 7. Encrypt sensitive reports at rest
gpg --symmetric --cipher-algo AES256 reports/<username>_dossier.pdf
```

---

## 14. Troubleshooting

| Symptom | Likely Cause | Fix |
|---------|--------------|-----|
| Many `403` / `405` responses | Datacenter IP blocked by WAF | Use Tor / residential proxy / FlareSolverr |
| Timeouts on most sites | Slow or unstable connection | Increase `--timeout 30`, decrease `--max-connections 5` |
| PDF generation fails | Missing `maigret[pdf]` extras or system libs | `pip3 install 'maigret[pdf]'` + install `libcairo2 libpango-1.0-0` |
| XMind report won't open in XMind 2022+ | Format is XMind 8 only | Use older XMind 8, or use `--html --graph` instead |
| Site DB outdated | Cache older than 24h | `rm -rf ~/.cache/maigret` and re-run |
| `--ai` returns nothing | Missing `OPENAI_API_KEY` | `export OPENAI_API_KEY=sk-...` or set in `settings.json` |
| Many false positives | Auto-generated SEO stubs | Cross-verify with Sherlock/WhatsMyName; manually inspect each `Claimed` URL |
| Tor exit blocked by target | Hard-blocked Tor exits | Switch to a residential proxy: `--proxy http://...` |

```bash
# Diagnose connectivity issues
maigret <username> --no-color --timeout 10 2>&1 | tee debug.log
grep -E '40[0-9]|50[0-9]|Error|Timeout' debug.log | sort | uniq -c | sort -rn

# Check Maigret version and DB freshness
maigret --version
ls -lh ~/.cache/maigret/ 2>/dev/null
```

---

## 15. Quick-Reference Cheat Sheet

```bash
# ─── 30-second quick check ───
maigret <username> --html

# ─── 5-minute full dossier ───
maigret <username> -a --html --graph --json ndjson

# ─── Stealth scan via Tor ───
sudo service tor start
maigret <username> -a --tor-proxy socks5://127.0.0.1:9050 --html --timeout 30

# ─── Recursive pivot from a known profile ───
maigret --parse https://github.com/<username> --html --graph

# ─── Username permutation ───
maigret "first last" --permute --html --tags us

# ─── Tag-filtered niche search ───
maigret <username> --tags photo,dating --html

# ─── AI summary ───
export OPENAI_API_KEY=sk-...
maigret <username> -a --ai

# ─── Cross-verify with Sherlock ───
sherlock <username> --json --output check.json
jq -r 'to_entries[] | select(.value.status=="claimed") | .key' check.json

# ─── Extract claimed accounts from NDJSON ───
jq -r 'select(.status=="Claimed") | "\(.site_name)\t\(.url)"' \
  reports/<username>_ndjson.json | sort
```

---

## 16. Maigret Advanced Usage

### 16.1 JSON Output Parsing

```bash
# Pretty-print the first claimed record
jq -c 'select(.status=="Claimed") | .' reports/<username>_ndjson.json | head -1 | jq .

# Summarize the report: claimed / available / unknown counts
jq -r '.status' reports/<username>_ndjson.json \
  | sort | uniq -c | sort -rn

# Group claimed accounts by tag category
jq -r 'select(.status=="Claimed") | .tags[]?' \
  reports/<username>_ndjson.json | sort | uniq -c | sort -rn

# Extract every (site, url, bio, location) tuple for spreadsheet import
jq -r 'select(.status=="Claimed") | [.site_name, .url, (.extracted.bio // ""), (.extracted.location // "")] | @tsv' \
  reports/<username>_ndjson.json > claimed_summary.tsv

# Find claimed sites with the longest bios (richest intel first)
jq -r 'select(.status=="Claimed") | {site_name, bio: (.extracted.bio // ""), bio_len: ((.extracted.bio // "") | length)}' \
  reports/<username>_ndjson.json \
  | jq -s 'sort_by(-.bio_len) | .[0:10]'

# Sites where response_time_ms was suspiciously fast (often a CDN stub)
jq -r 'select(.status=="Claimed" and (.response_time_ms // 9999) < 100) | "\(.site_name)\t\(.url)"' \
  reports/<username>_ndjson.json
```

### 16.2 Tag-Based Filtering

```bash
# Available tags across the DB
python3 -c "
from maigret.sites import MaigretDatabase
db = MaigretDatabase(); db.load_default_db()
tags = set()
for s in db.sites:
    for t in s.tags.get('tags', []):
        tags.add(t)
for t in sorted(tags): print(t)
" > available_tags.txt
less available_tags.txt

# Run only dating-tagged sites
maigret <username> --tags dating --html

# Run only US-targeted sites
maigret <username> --tags us --html

# Multiple tags (intersection semantics — see maigret --help for current logic)
maigret <username> --tags photo,us --html

# Negative tag filtering (exclude adult sites if out of scope)
maigret <username> --tags social --html
# (Maigret does not natively support tag negation; hand-edit data.json if needed)
```

### 16.3 Custom Site DB Updates

```bash
# Pull the latest site DB from upstream
wget -O ~/.cache/maigret/data.json \
  https://raw.githubusercontent.com/soxoj/maigret/main/maigret/resources/data.json

# Or use the DB pinned to a specific release
wget -O ~/.cache/maigret/data.json \
  https://raw.githubusercontent.com/soxoj/maigret/v0.4.0/maigret/resources/data.json

# Verify the DB parses cleanly
python3 -c "
import json
db = json.load(open('/dev/stdin'))
print(f'sites={len(db.get(\"sites\", []))}, schema_version={db.get(\"schemaVersion\")}')
" < ~/.cache/maigret/data.json

# Disable auto-update (use the local DB as-is, good for offline engagements)
maigret <username> --no-db-update --db ~/.cache/maigret/data.json --html

# Add a custom site (for niche platforms not in upstream DB)
python3 - <<'PY'
import json
from pathlib import Path

DB_PATH = Path.home() / ".cache/maigret/data.json"
db = json.loads(DB_PATH.read_text())

new_site = {
    "name": "AcmeInternal",
    "url": "https://internal.acme.example/u/{username}",
    "checkType": "status_code",
    "tags": {"tags": ["internal"], "checked": True},
    "usernameClaimed": "test_admin",
    "usernameUnclaimed": "nope_not_a_real_user_xyz"
}
db["sites"].append(new_site)
DB_PATH.write_text(json.dumps(db, indent=2))
print(f"Added AcmeInternal; DB now has {len(db['sites'])} sites")
PY

maigret <username> --db ~/.cache/maigret/data.json --html
```

### 16.4 Proxy Rotation

```bash
# Rotate proxies across runs (one engagement per proxy)
PROXIES=(
  "socks5://127.0.0.1:9050"                                   # Tor
  "http://user:pass@res-us.example.com:8080"                   # US residential
  "http://user:pass@res-eu.example.com:8080"                   # EU residential
  "http://user:pass@datacenter-rotate.example.com:8080"        # datacenter rotating
)

for i in "${!PROXIES[@]}"; do
  maigret "target_${i}" -a --proxy "${PROXIES[$i]}" --html --timeout 45 --max-connections 5
done

# Within a single Maigret run, you cannot natively rotate proxies per-request.
# Workaround: front Maigret with a local rotating proxy.
# Run a local HAProxy that round-robins to N upstreams on each connect:
sudo apt install haproxy
cat > /tmp/haproxy.cfg <<'CFG'
mode http
listen maigret_rotator
  bind 127.0.0.1:8192
  balance roundrobin
  server p1 upstream-1.example.com:8080
  server p2 upstream-2.example.com:8080
  server p3 upstream-3.example.com:8080
CFG
haproxy -f /tmp/haproxy.cfg &
maigret <username> -a --proxy http://127.0.0.1:8192 --html --timeout 45

# Verify the rotation is actually working
for i in 1 2 3 4 5; do
  curl -x http://127.0.0.1:8192 https://api.ipify.org
done
# Each request should return a different upstream IP
```

### 16.5 Recursive Workflows

```bash
# Depth-limited recursive pivot
VISITED=/tmp/visited.txt; echo "<seed>" > "$VISITED"
DEPTH=2

for ((d=0; d<DEPTH; d++)); do
  NEW_QUEUE=()
  while read u; do
    grep -qx "$u" "$VISITED" && continue
    echo "$u" >> "$VISITED"
    maigret "$u" -a --json ndjson --tags us --timeout 30 \
      --output "reports/pivot_d${d}_${u}/" --no-color
    while read u2; do
      grep -qx "$u2" "$VISITED" || NEW_QUEUE+=("$u2")
    done < <(jq -r 'select(.status=="Claimed") | .extracted.usernames[]? // empty' \
              reports/pivot_d${d}_${u}/*_ndjson.json 2>/dev/null | sort -u)
  done < <(cat "$VISITED")
  printf '%s\n' "${NEW_QUEUE[@]}" > /tmp/next_queue.txt
  [ -s /tmp/next_queue.txt ] || break
done
```

### 16.6 Output Diffing

```bash
# Diff two runs of the same target (e.g., before and after a takedown request)
jq -r 'select(.status=="Claimed") | .site_name' reports/run1_ndjson.json | sort -u > run1.sites
jq -r 'select(.status=="Claimed") | .site_name' reports/run2_ndjson.json | sort -u > run2.sites

# Sites that went away
comm -23 run1.sites run2.sites > resolved.sites
# Sites that appeared
comm -13 run1.sites run2.sites > new.sites

cat resolved.sites   # accounts successfully removed
cat new.sites        # new accounts since run 1
```

---

## 17. Sherlock + WhatsMyName Integration

### 17.1 Parallel Orchestration

```bash
# Run Maigret, Sherlock, WhatsMyName in parallel and merge outputs
TARGET=johndoe123

maigret "$TARGET" -a --tor-proxy socks5://127.0.0.1:9050 \
  --json ndjson --output "reports/maigret_${TARGET}.ndjson" &
P1=$!

sherlock "$TARGET" --json --output "reports/sherlock_${TARGET}.json" \
  --timeout 10 --ratelimit 2 --print-found &
P2=$!

whatsmyname -u "$TARGET" --format json \
  --output "reports/wmn_${TARGET}.json" &
P3=$!

wait $P1 $P2 $P3
echo "All three finished."
ls -lh reports/*.{ndjson,json} 2>/dev/null
```

### 17.2 Result Merging with jq

```bash
# Normalize each tool to a uniform TSV: (site, status)
jq -r '[.site_name, .status] | @tsv' reports/maigret_${TARGET}.ndjson \
  | sort -u > parsed/maigret.tsv
jq -r 'to_entries[] | [.key, .value.status] | @tsv' reports/sherlock_${TARGET}.json \
  | sort -u > parsed/sherlock.tsv
jq -r '.[] | [.site, .status] | @tsv' reports/wmn_${TARGET}.json \
  | sort -u > parsed/wmn.tsv

# Full outer join via awk
awk -F'\t' '
  FNR==1 { next }
  { sites[$1] = sites[$1] " " $2 }
  END { for (s in sites) print s "\t" sites[s] }
' parsed/*.tsv | column -t | sort
```

### 17.3 Dedup by Platform

```bash
# Normalize site names so Maigret's "GitHub" matches Sherlock's "github.com"
python3 - <<'PY'
import re, csv
from pathlib import Path

def norm(site: str) -> str:
    s = site.lower().strip()
    s = re.sub(r"\.(com|org|net|io|dev|me|co|app)$", "", s)
    s = re.sub(r"[^a-z0-9]", "", s)
    return s

parsed = Path("parsed")
rows = []
for tool, fname in [("maigret","maigret.tsv"),("sherlock","sherlock.tsv"),("wmn","wmn.tsv")]:
    p = parsed / fname
    if not p.exists(): continue
    for line in p.read_text().splitlines():
        parts = line.split("\t")
        if len(parts) < 2: continue
        rows.append({"norm_site": norm(parts[0]), "orig_site": parts[0],
                     "tool": tool, "status": parts[1]})

# Group by norm_site
from collections import defaultdict
grouped = defaultdict(list)
for r in rows: grouped[r["norm_site"]].append(r)

with (parsed / "merged.csv").open("w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["norm_site", "orig_site_maigret", "orig_site_sherlock", "orig_site_wmn",
                "maigret", "sherlock", "wmn", "claimed_count"])
    for ns, recs in sorted(grouped.items()):
        by_tool = {r["tool"]: r for r in recs}
        claimed = sum(1 for r in recs if "claim" in r["status"].lower())
        w.writerow([ns,
                    by_tool.get("maigret",{}).get("orig_site",""),
                    by_tool.get("sherlock",{}).get("orig_site",""),
                    by_tool.get("wmn",{}).get("orig_site",""),
                    by_tool.get("maigret",{}).get("status",""),
                    by_tool.get("sherlock",{}).get("status",""),
                    by_tool.get("wmn",{}).get("status",""),
                    claimed])
print("Wrote parsed/merged.csv")
PY
```

### 17.4 Triangulated Confidence Scoring

```bash
# HIGH: claimed by >= 2 tools, MEDIUM: claimed by 1 tool, LOW: not claimed
python3 - <<'PY'
import csv
with open("parsed/merged.csv") as f:
    for row in csv.DictReader(f):
        n = int(row["claimed_count"])
        conf = "HIGH" if n >= 2 else ("MEDIUM" if n == 1 else "LOW")
        print(f"{conf}\t{row['norm_site']}")
PY
```

### 17.5 Site Coverage Diff

```bash
# Sites that Maigret has but Sherlock doesn't
comm -23 \
  <(jq -r '.site_name' reports/maigret_${TARGET}.ndjson | sort -u) \
  <(jq -r 'keys[]' reports/sherlock_${TARGET}.json | sort -u) \
  > parsed/maigret_only_sites.txt

# Sites that Sherlock has but Maigret doesn't
comm -13 \
  <(jq -r '.site_name' reports/maigret_${TARGET}.ndjson | sort -u) \
  <(jq -r 'keys[]' reports/sherlock_${TARGET}.json | sort -u) \
  > parsed/sherlock_only_sites.txt

wc -l parsed/maigret_only_sites.txt parsed/sherlock_only_sites.txt
```

---

## 18. Social Searcher + Pipl API Scripts

> Note: Social Searcher and Pipl are commercial APIs. The scripts below assume you have valid API keys. Holehe (free, no key) remains the recommended starting point for email-to-service pivots.

### 18.1 Social Searcher Wrapper

```python
"""
social_searcher.py — minimal wrapper around the Social Searcher public API.
Requires SOCIAL_SEARCHER_KEY env var.
"""
import os
import sys
import time
import json
import requests

API_BASE = "https://api.social-searcher.com/v2"

def search(query: str, *, network: str = "", limit: int = 100) -> dict:
    key = os.environ.get("SOCIAL_SEARCHER_KEY")
    if not key:
        sys.exit("Set SOCIAL_SEARCHER_KEY env var")
    params = {
        "q": query,
        "key": key,
        "network": network,
        "limit": limit,
    }
    for attempt in range(3):
        r = requests.get(f"{API_BASE}/search", params=params, timeout=20)
        if r.status_code == 429:
            wait = 2 ** attempt
            print(f"  rate-limited; sleeping {wait}s", file=sys.stderr)
            time.sleep(wait)
            continue
        r.raise_for_status()
        return r.json()
    raise RuntimeError("exceeded rate-limit retries")

if __name__ == "__main__":
    q = sys.argv[1] if len(sys.argv) > 1 else "johndoe123"
    out = search(q)
    print(json.dumps(out, indent=2))
```

```bash
# Usage
export SOCIAL_SEARCHER_KEY=ss_xxxxx
python3 social_searcher.py "johndoe123" > social_searcher_johndoe123.json

# Extract posts that mention the handle
jq '.posts[]? | {network, posted, title, url, user: .user.username}' \
  social_searcher_johndoe123.json | head -20
```

### 18.2 Rate Limit Handling

```python
"""
Generic rate-limit handler for any paginated OSINT API.
"""
import time
import requests
from typing import Iterator

def paginated_get(url: str, *, headers: dict, params: dict, page_key: str = "page") -> Iterator[dict]:
    page = 1
    while True:
        params[page_key] = page
        r = requests.get(url, headers=headers, params=params, timeout=20)
        if r.status_code == 429:
            reset = int(r.headers.get("X-RateLimit-Reset", "60"))
            print(f"  429; sleeping {reset}s")
            time.sleep(reset)
            continue
        r.raise_for_status()
        data = r.json()
        if not data.get("results"):
            return
        yield from data["results"]
        page += 1
        time.sleep(float(r.headers.get("X-RateLimit-Interval", "1").split(",")[0]))
```

### 18.3 Pipl Wrapper

```python
"""
pipl_client.py — minimal wrapper around the Pipl API (paid).
Requires PIPL_KEY env var.
"""
import os, sys, json, requests

def lookup(email: str | None = None, username: str | None = None) -> dict:
    key = os.environ.get("PIPL_KEY")
    if not key: sys.exit("Set PIPL_KEY env var")
    params = {"key": key}
    if email: params["email"] = email
    if username: params["username"] = username
    if not (email or username): sys.exit("Provide email or username")
    r = requests.get("https://api.pipl.com/search/", params=params, timeout=30)
    r.raise_for_status()
    return r.json()

if __name__ == "__main__":
    email = sys.argv[1] if "@" in sys.argv[1] else None
    user = None if email else sys.argv[1]
    data = lookup(email=email, username=user)
    print(json.dumps(data, indent=2)[:4000])
```

```bash
export PIPL_KEY=xxxxx
python3 pipl_client.py johndoe123 > pipl_johndoe123.json
python3 pipl_client.py j.doe@example.com > pipl_email.json

# Extract person record
jq '.person | {name: .names[0], username: .usernames[0], emails: [.emails[].address]}' \
  pipl_johndoe123.json
```

### 18.4 Email-to-Service via Holehe (Free Alternative)

```bash
# Holehe is free and does not need an API key
pip3 install holehe

holehe j.doe@example.com > holehe_jdoe.txt 2>&1
grep -E '^\[' holehe_jdoe.txt | sort

# Bulk: run holehe on every discovered email
while read email; do
  holehe "$email" > "holehe_${email//@/_}.txt" 2>&1
done < parsed/pivot_emails.txt
```

---

## 19. Email-to-Username Pivoting

### 19.1 HaveIBeenPwned API

```python
"""
hibp_client.py — query HaveIBeenPwned for breaches involving an email.
Requires HIBP_API_KEY env var (https://haveibeenpwned.com/API/Key).
"""
import os, sys, json, requests

def breaches(email: str) -> list:
    key = os.environ.get("HIBP_API_KEY")
    if not key: sys.exit("Set HIBP_API_KEY")
    headers = {
        "hibp-api-key": key,
        "user-agent": "kali-claw-osint/0.1",
    }
    r = requests.get(
        f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
        headers=headers, params={"truncateResponse": "false"}, timeout=20,
    )
    if r.status_code == 404: return []
    r.raise_for_status()
    return r.json()

if __name__ == "__main__":
    for email in sys.argv[1:]:
        data = breaches(email)
        print(json.dumps({"email": email, "breaches": data}, indent=2))
```

```bash
export HIBP_API_KEY=xxxxx
python3 hibp_client.py j.doe@example.com > hibp_jdoe.json

# Extract breach names + data classes leaked
jq '.breaches[] | {name, dataclasses: .DataClasses, date: .BreachDate}' hibp_jdoe.json
```

### 19.2 Hunter.io Email Verification + Domain Search

```python
"""
hunter_client.py — verify an email + find related emails on a domain.
Requires HUNTER_KEY env var.
"""
import os, sys, json, requests

BASE = "https://api.hunter.io/v2"

def verify(email: str) -> dict:
    key = os.environ.get("HUNTER_KEY")
    r = requests.get(f"{BASE}/email-verifier",
                     params={"email": email, "api_key": key}, timeout=20)
    r.raise_for_status()
    return r.json()

def domain_search(domain: str, *, limit: int = 20) -> dict:
    key = os.environ.get("HUNTER_KEY")
    r = requests.get(f"{BASE}/domain-search",
                     params={"domain": domain, "limit": limit, "api_key": key},
                     timeout=20)
    r.raise_for_status()
    return r.json()

if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "verify":   print(json.dumps(verify(sys.argv[2]), indent=2))
    elif cmd == "search": print(json.dumps(domain_search(sys.argv[2]), indent=2))
```

```bash
export HUNTER_KEY=xxxxx
python3 hunter_client.py verify j.doe@example.com > hunter_verify.json
python3 hunter_client.py search acme.com > hunter_domain.json

# Pull all emails found on the domain
jq '.data.emails[] | {value, type, confidence}' hunter_domain.json
```

### 19.3 Email-to-GitHub Pattern Matching

```bash
# Use GitHub's commit search to find commits authored by a specific email
# This is a public endpoint; no auth required for low volume.
curl -s "https://api.github.com/search/commits?q=author-email:j.doe@example.com" \
  -H "Accept: application/vnd.github.cloak-preview" \
  | jq '.items[]? | {repo: .repository.full_name, sha: .sha, author: .commit.author.name, date: .commit.author.date}'

# Wrap in a script for multiple emails
python3 - <<'PY'
import sys, requests, json
email = sys.argv[1]
r = requests.get(
    "https://api.github.com/search/commits",
    params={"q": f"author-email:{email}", "per_page": 20},
    headers={"Accept": "application/vnd.github.cloak-preview"},
    timeout=20,
)
for item in r.json().get("items", []):
    print(f"{item['repository']['full_name']}\t{item['sha'][:8]}\t{item['commit']['author']['name']}\t{item['commit']['author']['date']}")
PY

# Once you have a commit SHA, fetch the patch to find associated user identities
SHA=abc123def456
curl -s "https://api.github.com/repos/OWNER/REPO/commits/$SHA" \
  | jq '.commit.author, .commit.committer'
```

### 19.4 Gravatar Lookup

```bash
# Gravatar uses MD5 of the lowercased email as the avatar URL
EMAIL=j.doe@example.com
HASH=$(printf "%s" "$EMAIL" | tr '[:upper:]' '[:lower:]' | md5sum | awk '{print $1}')
curl -s -o gravatar.jpg "https://www.gravatar.com/avatar/${HASH}?s=400&d=404"
file gravatar.jpg   # JPEG if exists, 404 otherwise

# Fetch the Gravatar profile JSON
curl -s "https://www.gravatar.com/${HASH}.json" | jq '.entry[0] | {displayName, currentLocation, aboutMe, accounts}'
```

### 19.5 Username-from-Email Heuristics

```python
"""
Derive likely usernames from an email local-part.
"""
import re

def username_candidates(email: str) -> list[str]:
    local = email.split("@")[0].lower()
    candidates = set()
    # john.doe -> john.doe, johndoe, j.doe, jdoe, doe.john
    if "." in local:
        first, last = local.split(".", 1)
        candidates |= {local, local.replace(".", ""),
                       f"{first[0]}.{last}", f"{first[0]}{last}",
                       f"{last}.{first}", f"{last}{first}"}
    elif "_" in local:
        first, last = local.split("_", 1)
        candidates |= {local, local.replace("_", ""),
                       f"{first[0]}_{last}", f"{first[0]}{last}"}
    else:
        candidates.add(local)
    # Add common suffixes
    suffixed = set()
    for c in candidates:
        for suffix in ["", "123", "_dev", "1", "2024", "_official"]:
            suffixed.add(f"{c}{suffix}")
    return sorted(suffixed)

if __name__ == "__main__":
    for c in username_candidates("john.doe@example.com"):
        print(c)
```

```bash
# Generate candidates and pipe into Maigret
python3 username_candidates.py > candidates.txt
while read u; do
  maigret "$u" --html --tags us
done < candidates.txt
```

---

## 20. Breach Data Correlation

### 20.1 DeHashed

```python
"""
dehashed_client.py — query the DeHashed API (paid).
Requires DEHASHED_KEY env var.
"""
import os, sys, json, requests

def search(field: str, value: str) -> dict:
    key = os.environ.get("DEHASHED_KEY")
    if not key: sys.exit("Set DEHASHED_KEY")
    r = requests.get(
        f"https://api.dehashed.com/search?query={field}:{value}",
        headers={"Authorization": f"Bearer {key}",
                 "Accept": "application/json"},
        timeout=30,
    )
    r.raise_for_status()
    return r.json()

if __name__ == "__main__":
    field, value = sys.argv[1], sys.argv[2]
    data = search(field, value)
    print(json.dumps(data, indent=2)[:8000])
```

```bash
export DEHASHED_KEY=xxxxx
python3 dehashed_client.py email j.doe@example.com > dehashed_email.json
python3 dehashed_client.py username johndoe123 > dehashed_user.json

# Extract all distinct usernames + emails observed in breaches
jq '.dehashed | map({email, username, database_name, breached_password})' dehashed_user.json
```

### 20.2 Intelligence-X

```bash
# IntelX uses a query-based API with a phonebook endpoint
export INTELX_API_KEY=xxxxx

# Search by email
curl -s "https://2.intelx.io/phonebook/search" \
  -H "x-key: $INTELX_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"term":"j.doe@example.com","maxresults":100,"media":0,"target":1}' \
  | jq '.selectors[] | .selectorvalue'

# Or via the intx CLI tool
pip3 install intelligencex
intx --api-key "$INTELX_API_KEY" search "johndoe123" --type username
```

### 20.3 Snusbase

```bash
# Snusbase exposes a simple HTTP API
export SNUSBASE_KEY=xxxxx

curl -s "https://api.snusbase.com/v2/search/email/j.doe@example.com" \
  -H "Authorization: Bearer $SNUSBASE_KEY" \
  | jq '.results[] | {source, username, email, password, ip}'
```

### 20.4 h8mail (Free / Local)

```bash
# h8mail queries free breach dumps (and paid APIs if configured)
pip3 install h8mail

# Basic email search
h8mail -t j.doe@example.com -o h8mail_jdoe.json

# Local breach corpus search
h8mail -t j.doe@example.com --local /path/to/breach/collection

# Output to CSV
h8mail -t j.doe@example.com -c h8mail_jdoe.csv

# Parse the output
jq '.[]' h8mail_jdoe.json 2>/dev/null | head -20
```

### 20.5 Username Variant Extraction from Breach Data

```python
"""
mine_breach_for_variants.py — given a breach JSON dump, find every username
variant that shares an email with the seed identity.
"""
import json, sys
from collections import defaultdict

def mine(breach_json: str, seed_email: str) -> dict[str, list[str]]:
    data = json.loads(breach_json) if isinstance(breach_json, str) else breach_json
    by_email: dict[str, list[str]] = defaultdict(list)
    for rec in data.get("dehashed", data.get("results", [])):
        email = rec.get("email") or ""
        user = rec.get("username") or ""
        if email and user:
            by_email[email.lower()].append(user)
    return {"seed": by_email.get(seed_email.lower(), []),
            "related_emails": sorted(by_email.keys())[:50]}

if __name__ == "__main__":
    seed_email = sys.argv[1]
    breach = sys.stdin.read()
    print(json.dumps(mine(breach, seed_email), indent=2))
```

```bash
# Pipe a breach JSON into the miner
python3 mine_breach_for_variants.py j.doe@example.com < dehashed_user.json \
  > variants_from_breach.json

# Feed those variants back into Maigret
jq -r '.seed[]' variants_from_breach.json | sort -u \
  | while read u; do maigret "$u" --html --tags us; done
```

### 20.6 Password-Reuse Pivot (Caution!)

> ⚠️ **OPSEC + scope warning**: Using leaked plaintext passwords to attempt authentication is almost always outside pentest scope and may be illegal. The correct use of breach passwords in username profiling is **as a pivot signal only** — observing that the same password was used by the same username on a different breach confirms identity correlation without any active auth attempt.

```python
"""
correlate_passwords.py — observe password reuse across breaches as a signal
of identity correlation. NO auth attempts; purely passive.
"""
import json, sys
from collections import defaultdict

def correlate(breach_records: list[dict]) -> dict:
    by_password: dict[str, list[str]] = defaultdict(list)
    for r in breach_records:
        pw = r.get("password")
        if not pw: continue
        by_password[pw].append({
            "email": r.get("email"),
            "username": r.get("username"),
            "source": r.get("database_name") or r.get("source"),
        })
    # Strongest reuse signals: passwords used by >1 email
    return {pw: recs for pw, recs in by_password.items() if len(set(r["email"] for r in recs)) > 1}

if __name__ == "__main__":
    data = json.load(sys.stdin)
    records = data.get("dehashed", data.get("results", []))
    print(json.dumps(correlate(records), indent=2))
```

---

## 21. Username Variant Generation

### 21.1 Leet Speak Variants

```python
"""
leet_variants.py — generate leet-speak and case variants of a username.
"""
import itertools

LEET_MAP = {
    "a": ["a", "4", "@"],
    "e": ["e", "3"],
    "i": ["i", "1", "!"],
    "o": ["o", "0"],
    "s": ["s", "5", "$"],
    "t": ["t", "7"],
    "l": ["l", "1"],
    "b": ["b", "8"],
    "g": ["g", "9"],
}

def leet_variants(username: str, *, max_variants: int = 50) -> list[str]:
    """Generate up to max_variants leet-speak variants."""
    options = [LEET_MAP.get(c.lower(), [c]) for c in username]
    variants = set()
    for combo in itertools.product(*options):
        variants.add("".join(combo))
        if len(variants) >= max_variants: break
    return sorted(variants)

if __name__ == "__main__":
    import sys
    for v in leet_variants(sys.argv[1]):
        print(v)
```

```bash
python3 leet_variants.py johndoe | head -20
# john.doe, j0hndoe, j0hn.d03, johnd03, ...
```

### 21.2 Year Suffix Variants

```python
"""
year_variants.py — append common year / number suffixes to a base username.
"""
from datetime import datetime

def year_variants(base: str, *, birth_years: range = range(1980, 2010)) -> list[str]:
    current = datetime.now().year
    out = set()
    for y in birth_years:
        out.add(f"{base}{y}")
        out.add(f"{base}{str(y)[-2:]}")           # last 2 digits
        out.add(f"{base}_{y}")
        out.add(f"{base}-{y}")
    for n in range(0, 100):
        out.add(f"{base}{n:02d}")
    for n in [1, 12, 123, 1234, 99, 420, 666, 777, 2023, 2024, 2025]:
        out.add(f"{base}{n}")
    return sorted(out)

if __name__ == "__main__":
    import sys
    for v in year_variants(sys.argv[1]):
        print(v)
```

```bash
python3 year_variants.py johndoe | wc -l
# ~570 candidates
```

### 21.3 Separator / Case Variants

```python
"""
separator_variants.py — vary separator characters and casing.
"""
import itertools

def separator_variants(name_parts: list[str]) -> list[str]:
    """Given ['john','doe'], produce john.doe, john_doe, johndoe, JohnDoe, etc."""
    seps = ["", ".", "_", "-"]
    variants = set()
    for sep in seps:
        joined = sep.join(name_parts)
        variants.add(joined.lower())
        variants.add(joined.upper())
        variants.add(joined.capitalize())
        variants.add(joined.title())
    # Initial-only variants
    if len(name_parts) >= 2:
        first, last = name_parts[0], name_parts[-1]
        variants.add(f"{first[0]}{last}")
        variants.add(f"{first[0]}.{last}")
        variants.add(f"{first[0]}_{last}")
        variants.add(f"{first}{last[0]}")
        variants.add(f"{first}.{last[0]}")
    return sorted(variants)

if __name__ == "__main__":
    import sys
    parts = sys.argv[1:]
    for v in separator_variants(parts):
        print(v)
```

```bash
python3 separator_variants.py john doe
# john.doe, john_doe, johndoe, JohnDoe, jdoe, j.doe, ...
```

### 21.4 Full Variant Generator

```python
"""
variant_generator.py — combine leet, year, and separator variants.
Outputs a sorted unique list suitable for piping into Maigret.
"""
import sys
from leet_variants import leet_variants
from year_variants import year_variants
from separator_variants import separator_variants

def all_variants(seed: str, real_name_parts: list[str] | None = None) -> list[str]:
    out = set()
    out.add(seed)
    out.update(leet_variants(seed, max_variants=30))
    out.update(year_variants(seed))

    if real_name_parts:
        out.update(separator_variants(real_name_parts))
        # Permute name parts
        if len(real_name_parts) >= 2:
            out.update(separator_variants([real_name_parts[0]]))
            out.update(separator_variants([real_name_parts[-1]]))

    # Filter to plausible handles
    return sorted(v for v in out if 3 <= len(v) <= 24 and v.isalnum() or all(c.isalnum() or c in "._-" for c in v))

if __name__ == "__main__":
    seed = sys.argv[1]
    name = sys.argv[2:] if len(sys.argv) > 2 else None
    for v in all_variants(seed, name):
        print(v)
```

```bash
python3 variant_generator.py johndoe123 john doe > all_variants.txt
wc -l all_variants.txt

# Run Maigret against each variant (cap at 20 to bound runtime)
head -20 all_variants.txt | while read u; do
  maigret "$u" --html --tags us --timeout 10 --max-connections 5
done
```

### 21.5 Manual Variant Curation

Not every variant is worth scanning. Discipline yourself:

```bash
# Hand-curated high-likelihood variants (better than auto-generation for humans)
cat > curated_variants.txt <<'EOF'
johndoe
johndoe123
john.doe
j.doe
jdoe
johnd
johndoe_dev
johndoe88
EOF

# Always include the seed handle
echo "johndoe123" >> curated_variants.txt
sort -u curated_variants.txt | tee curated_variants.txt | wc -l
```

---

## 22. Operational Use Patterns

### 22.1 Engagement Bootstrap

```bash
#!/usr/bin/env bash
# bootstrap_engagement.sh — standard scaffolding for a new investigation.
set -euo pipefail
CASE_NAME=${1:?usage: $0 <case-name>}
CASE_DIR=~/engagements/$CASE_NAME

mkdir -p "$CASE_DIR"/{seed,reports,parsed,verified,final}

cat > "$CASE_DIR/seed/context.json" <<JSON
{
  "case_name": "$CASE_NAME",
  "seed_username": "",
  "suspected_real_name": "",
  "country_hint": "us",
  "language_hint": "en",
  "tech_hints": [],
  "email_fragments": [],
  "authorization_ref": "",
  "lawful_basis": "legitimate_interest",
  "created": "$(date -u +%FT%TZ)"
}
JSON

cat > "$CASE_DIR/chain-of-custody.txt" <<EOF
$(date -u +%FT%TZ)  engagement_opened  case=$CASE_NAME
EOF

echo "Engagement scaffolded at $CASE_DIR"
echo "Edit $CASE_DIR/seed/context.json to populate seed data."
```

### 22.2 One-Shot Investigation Runner

```bash
#!/usr/bin/env bash
# run_investigation.sh — full pipeline for a single seed username.
set -euo pipefail
CASE_DIR=${1:?usage: $0 <case_dir>}
TARGET=$(jq -r .seed_username "$CASE_DIR/seed/context.json")

# Verify Tor is up
sudo service tor start
EGRESS=$(curl --silent --socks5-hostname 127.0.0.1:9050 https://api.ipify.org || echo "TOR_DOWN")
if [ "$EGRESS" = "TOR_DOWN" ]; then echo "Tor is down"; exit 1; fi

# Phase B: Broad sweep
maigret "$TARGET" -a \
  --tor-proxy socks5://127.0.0.1:9050 \
  --html --graph --json ndjson \
  --tags "$(jq -r .country_hint "$CASE_DIR/seed/context.json")" \
  --keywords $(jq -r '.tech_hints | join(" ")' "$CASE_DIR/seed/context.json") \
  --timeout 30 --max-connections 15 --retries 2 \
  --output "$CASE_DIR/reports/" \
  --no-color

# Phase C: Parse
jq -r 'select(.status=="Claimed") | [.site_name, .url] | @tsv' \
  "$CASE_DIR"/reports/*_ndjson.json | sort -u > "$CASE_DIR/parsed/claimed.tsv"

# Phase E: Cross-verify
sherlock "$TARGET" --json --output "$CASE_DIR/parsed/sherlock_${TARGET}.json"
whatsmyname -u "$TARGET" --format json --output "$CASE_DIR/parsed/wmn_${TARGET}.json"

echo "Pipeline complete. Review $CASE_DIR/parsed/"
```

### 22.3 Teardown

```bash
#!/usr/bin/env bash
# teardown_engagement.sh — encrypt the final deliverable, shred the rest.
set -euo pipefail
CASE_DIR=${1:?usage: $0 <case_dir>}

# Encrypt the final dossier
gpg --symmetric --cipher-algo AES256 "$CASE_DIR/final/dossier.pdf"

# Shred intermediate artifacts
find "$CASE_DIR/reports" "$CASE_DIR/parsed" "$CASE_DIR/verified" \
  -type f -exec shred -uvz {} +

# Remove empty dirs
rmdir "$CASE_DIR"/{reports,parsed,verified} 2>/dev/null || true

# Log the destruction
echo "$(date -u +%FT%TZ)  shredded  case=$CASE_DIR" >> "$CASE_DIR/chain-of-custody.txt"
echo "Engagement torn down. Encrypted deliverable: $CASE_DIR/final/dossier.pdf.gpg"
```

---

## 23. Quick Reference

```bash
# One-liner: full Maigret sweep via Tor
sudo service tor start && maigret <user> -a --tor-proxy socks5://127.0.0.1:9050 --html --graph --json ndjson

# One-liner: claimed sites only, sorted
jq -r 'select(.status=="Claimed") | "\(.site_name)\t\(.url)"' reports/*_ndjson.json | sort

# One-liner: discovered pivot emails
jq -r 'select(.status=="Claimed") | .extracted.emails[]? // empty' reports/*_ndjson.json | sort -u

# One-liner: parallel triangulation
( maigret <user> -a --json ndjson --output m.ndjson &
  sherlock <user> --json --output s.json &
  whatsmyname -u <user> --format json --output w.json &
  wait )

# One-liner: verify Tor egress
diff <(curl -s https://api.ipify.org) <(curl -s --socks5-hostname 127.0.0.1:9050 https://api.ipify.org)

# One-liner: weekly diff
join -t $'\t' -v2 <(jq -r '[.site_name,.status]|@tsv' week_old.json | sort) <(jq -r '[.site_name,.status]|@tsv' week_new.json | sort) | awk -F'\t' '$2=="Claimed"'

# One-liner: variant generation
python3 -c "import itertools; [print(''.join(p)) for p in itertools.product(*[('aA4@','eE3','oO0')[i] if c in 'aeo' else (c,) for i,c in enumerate('johndoe')])]"
```

---

**Related files**: `SKILL.md`, `test-cases.md`, `guides/maigret-username-dossier.md`, `guides/maigret-username-workshop.md`
**Maigret upstream**: [github.com/soxoj/maigret](https://github.com/soxoj/maigret) | [maigret.readthedocs.io](https://maigret.readthedocs.io)
