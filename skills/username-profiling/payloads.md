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

**Related files**: `SKILL.md`, `test-cases.md`, `guides/maigret-username-dossier.md`
**Maigret upstream**: [github.com/soxoj/maigret](https://github.com/soxoj/maigret) | [maigret.readthedocs.io](https://maigret.readthedocs.io)
