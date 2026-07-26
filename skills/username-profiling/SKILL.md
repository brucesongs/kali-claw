---
name: username-profiling
description: "Build a complete dossier on a person using only a username."
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
  tool_count: 12
  guide_count: 3
  mitre: "TA0043-Reconnaissance"
  keywords:
    - maigret
    - sherlock
    - whatsmyname
    - holehe
    - username-enumeration
    - osint
    - identity-resolution
    - cross-platform
    - breach-correlation
    - pivot
  last_reviewed: "2026-07-26"
---




# Skill: Username Profiling

> **Supplementary Files**:
> - `payloads.md` — Maigret command catalogue: basic search, report formats (HTML/PDF/XMind/JSON/CSV/TXT/graph), tag filtering, recursive `--parse`, `--permute` variants, keyword highlighting, proxy/Tor/I2P routing, AI summary, database self-check, and cross-tool workflow with Sherlock/Holehe/WhatsMyName
> - `test-cases.md` — Structured test cases (default scan, full scan, tag-filtered scan, recursive parse, permutation, report export, proxy routing, AI summary, false-positive validation, OPSEC verification) with severity levels and summary tables

## Summary

Username Profiling skill domain covering osint operations.

**Tools**: Sherlock, WhatsMyName, Holehe, Namechk, Blackbird, jq, Username hygiene audit, Pivot surface reduction (+4 more)

**Domain**: osint

**MITRE ATT&CK**: TA0043-Reconnaissance

## Description

Build a complete dossier on a person using only a username. Maigret checks 3,000+ websites for accounts owned by the target, extracts every piece of public information from profile pages and site APIs (display name, avatar, bio, location, links to other accounts), and recursively pivots into newly discovered usernames or IDs — all without any API keys.

This skill is the depth-first complement to broad OSINT collection. Where `osint` casts a wide passive net across domains, emails, and subdomains, username profiling drills into one human identity and follows it across the internet until the picture stops growing.

**Difference from `osint`**: OSINT orchestrates many tools against many targets (domain, email, IP, breach data). Username profiling orchestrates one tool class — username enumeration — against one target identity, with the goal of producing a single coherent human dossier rather than a list of disconnected artifacts.

**Difference from `social-intelligence`**: Social intelligence mines unstructured discourse (Reddit, HN, X posts) about an organization. Username profiling identifies *where* a specific human has accounts so that subsequent social intelligence gathering has concrete profiles to target.

**Difference from Sherlock usage in `osint` skill**: Sherlock returns a yes/no list of claimed usernames. Maigret goes further — it parses each found profile, extracts metadata, follows links to other identities, and produces graph/PDF/HTML reports suitable for handing to a client.

## Use Cases

- **Pre-engagement target profiling**: From a single leaked forum handle, recover the target's GitHub, LinkedIn, Twitter, personal blog, and any other account that shares the username — building a complete human attack surface before touching systems.
- **Red team social engineering prep**: Given a target employee's handle discovered in a breach, identify their hobby forums, dating profiles, and gaming accounts to craft convincing phishing pretexts.
- **Investigative journalism / due diligence**: Verify whether a single online persona maps to one human across 3,000+ platforms — uncover alt accounts, prior usernames, and inconsistent location claims.
- **Brand impersonation detection**: Run a brand name or executive handle through 3,000+ sites to surface impersonator accounts, fake reviews, and typosquatted profiles.
- **Missing persons / Trace Labs CTFs**: From a known handle, recursively pivot into newly discovered usernames, emails, and profile photos to geolocate a subject.
- **Insider threat indicator gathering**: Pivot from a suspect's current username to historical accounts that may reveal motivation, grievances, or capability signals.
- **Username hygiene audit (defense)**: Audit your own executive team's handles across 3,000+ sites to identify forgotten accounts that should be closed or hardened.

## Core Tools

### Primary Tool — Maigret

| Capability | Command Example |
|------------|-----------------|
| Default scan (top 500 sites by traffic) | `maigret <username>` |
| Full scan (all 3,000+ sites) | `maigret <username> -a` |
| Generate HTML report | `maigret <username> --html` |
| Generate PDF report | `maigret <username> --pdf` |
| Generate XMind 8 mindmap | `maigret <username> --xmind` |
| Generate interactive D3 graph | `maigret <username> --graph` |
| Filter by site tags | `maigret <username> --tags photo,dating` |
| Filter by country tag | `maigret <username> --tags us` |
| Highlight keyword-matching sites | `maigret <username> --keywords python rust` |
| Recursive parse from a profile URL | `maigret --parse <URL>` |
| Generate username permutations | `maigret "john doe" --permute` |
| Multi-username batch | `maigret user1 user2 user3 -a` |
| AI-assisted summary | `maigret <username> --ai` |
| Machine-readable exports | `maigret <username> --csv` / `--txt` / `--json ndjson` |

### Companion Tools

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **Sherlock** | Cross-platform username search (300+ sites), JSON-only output | `sherlock <username> --json --output profiles.json` |
| **WhatsMyName** | Web/JSON username enumeration with broader site coverage | `whatsmyname -u <username>` |
| **Holehe** | Email → registered service detection (120+ services) | `holehe <email>` |
| **Namechk** | Quick web-based username availability check | `curl https://namechk.com/<username>` |
| **Blackbird** | OSINT username search with API integrations | `blackbird --username <username>` |
| **jq** | Parse Maigret JSON / NDJSON exports | `jq '.[] | select(.status=="Claimed")' report_ndjson.json` |

## Methodology

### Username Profiling Five-Phase Process

```
Phase 1            Phase 2            Phase 3            Phase 4            Phase 5
Seed Username   →  Broad Enumeration →  Recursive Pivot →  Cross-Tool        →  Dossier
& Context          (Maigret -a)         (--parse / IDs)    Verification        Synthesis
   │                  │                    │                  │                  │
   ▼                  ▼                    ▼                  ▼                  ▼
Known handle,     3,000+ sites,       Re-run Maigret    Sherlock, Holehe,   Merge findings,
variants,         tag filtering,       on discovered     WhatsMyName         remove false
country,          HTML + graph         usernames,         cross-validate      positives,
language hints    report               emails, IDs                             produce report
```

**Phase 1: Seed Username & Context**

Collect every known identifier before running anything.

```
Target: "johndoe123"
Known context:
  - Primary handle: johndoe123
  - Suspected real name: John Doe
  - Suspected country: US
  - Suspected language: en
  - Email fragment: j.doe@
Seed variants:
  - johndoe123 (primary)
  - john.doe, j.doe, jdoe (permutation candidates)
  - "john doe" (input to --permute)
```

**Phase 2: Broad Enumeration**

Run Maigret across the widest site list, capture structured output.

```bash
# Full scan with HTML + graph + NDJSON for downstream parsing
maigret johndoe123 -a \
  --html \
  --graph \
  --json ndjson \
  --tags us \
  --keywords security crypto linux \
  --timeout 15

# Outputs in ./reports/johndoe123/:
#   - report_johndoe123.html      (browsable dossier)
#   - graph_johndoe123.html       (D3 relationship graph)
#   - report_johndoe123_ndjson.json (machine-readable, one line per site)
```

**Phase 3: Recursive Pivot**

Feed discovered usernames, emails, or profile URLs back into Maigret.

```bash
# Extract newly discovered usernames from the NDJSON report
jq -r 'select(.status=="Claimed") | .extracted.usernames[]?' \
  reports/johndoe123/report_johndoe123_ndjson.json \
  | sort -u > discovered_usernames.txt

# Re-run Maigret on each discovered username
while read user; do
  maigret "$user" --html --graph --tags us
done < discovered_usernames.txt

# Or parse a specific profile page and let Maigret auto-pivot
maigret --parse https://github.com/johndoe123 --html --graph
```

**Phase 4: Cross-Tool Verification**

Validate Maigret findings against independent tools — false positives are common on auto-generated profile pages.

```bash
# Sherlock cross-check (independent detection rules)
sherlock johndoe123 --json --output sherlock_check.json

# WhatsMyName (different site list, different detection logic)
whatsmyname -u johndoe123 --format json --output wmn_check.json

# Holehe (if an email was discovered)
holehe j.doe@example.com

# Merge results
jq -s 'map(.username) | unique' sherlock_check.json wmn_check.json
```

**Phase 5: Dossier Synthesis**

Aggregate findings into a single human-readable dossier.

```markdown
# Dossier: johndoe123

## Identity
- Real name (claimed): John Doe
- Suspected location: San Francisco, CA, US
- Languages: English, basic Spanish
- Confidence: HIGH (corroborated across 7 platforms)

## Confirmed Accounts (15)
| Platform | URL | Bio | First Seen |
|----------|-----|-----|------------|
| GitHub | github.com/johndoe123 | "Backend @ Acme" | 2019-03 |
| Twitter | x.com/johndoe123 | "thoughts are my own" | 2018-07 |
| ... | ... | ... | ... |

## Discovered Pivot Identities
- Email: j.doe@example.com (3 platforms)
- Alt username: jdoe_dev (1 platform — Reddit)
- Phone: +1-415-XXX-XXXX (1 platform — public Discord bio)

## Inconsistencies / Anomalies
- Twitter bio claims "London" but GitHub commits are PST timezone
- Reddit account jdoe_dev uses different avatar — possible impersonation

## Recommended Follow-Up
- Deep dive on Reddit account (sentiment, technical leaks)
- Check j.doe@example.com against breach databases (h8mail)
- Verify timezone inconsistency via Twitter API / GitHub commit times
```

### Quick Selection Guide

| Scenario | Primary Approach | Alternative |
|----------|------------------|-------------|
| Quick check across popular sites | `maigret <user>` (default 500) | `sherlock <user>` |
| Maximum coverage | `maigret <user> -a` | WhatsMyName |
| Specific platform category | `maigret <user> --tags photo,dating` | Manual per-platform check |
| Pivot from a known profile URL | `maigret --parse <URL>` | Manual scrape + Maigret |
| Username variations likely | `maigret "first last" --permute` | Hand-curated variant list |
| Want an AI summary | `maigret <user> --ai` (needs OPENAI_API_KEY) | Manual LLM prompt with NDJSON |
| Stealth / region-locked targets | `maigret <user> --tor-proxy socks5://127.0.0.1:9050` | VPN + `--proxy http://...` |
| Cloudflare-protected sites | `maigret --cloudflare-bypass <user>` + FlareSolverr | Skip those sites |
| Hand to non-technical client | `maigret <user> --html` or `--pdf` | `--xmind` for analyst-friendly mindmap |

### Defense Perspective

| Defense Measure | Description |
|-----------------|-------------|
| **Username hygiene audit** | Run Maigret on your own executives' handles quarterly to find abandoned accounts and impersonators. |
| **Pivot surface reduction** | Don't reuse the same username across corporate and personal platforms — Maigret's `--permute` exploits `john.doe` → `jdoe` patterns. |
| **Profile metadata hygiene** | Maigret extracts bio, location, links — audit your team's public profiles for inadvertent technology stack or location leaks. |
| **Impersonation monitoring** | Set a recurring Maigret run on brand and executive names to detect typosquatted accounts early. |
| **OPSEC for investigators** | Maigret exposes your IP to 3,000+ sites — always use Tor, a rotating proxy, or a dedicated VPS. Don't run from your corporate egress. |
| **False-positive awareness** | Auto-generated profile pages (e.g., SEO stubs) trigger false "Claimed" — manually verify any account before acting on it. |

## Practical Steps

> **Detailed payloads in `payloads.md`, complete test checklist in `test-cases.md`.**

### Exercise 1: Single-Username Quick Profile

Goal: from one handle, produce a browsable HTML dossier in under 5 minutes.

```bash
# Install Maigret
pip3 install maigret
pip3 install 'maigret[pdf]'   # optional: enables --pdf

# Default scan (top 500 sites by traffic) + HTML report
maigret johndoe123 --html

# Open the dossier
open reports/johndoe123/report_johndoe123.html   # macOS
xdg-open reports/johndoe123/report_johndoe123.html   # Linux
```

### Exercise 2: Full-Coverage Scan with Pivot

Goal: maximize coverage, capture structured data, then recursively pivot.

```bash
# Step 1: Full scan, all sites, NDJSON export
maigret johndoe123 -a \
  --json ndjson \
  --html \
  --graph \
  --timeout 20 \
  --retries 2

# Step 2: Extract every claimed site
jq -r 'select(.status=="Claimed") | "\(.site_username)  \(.url)"' \
  reports/johndoe123/report_johndoe123_ndjson.json \
  | sort > claimed_sites.txt

# Step 3: Extract any usernames discovered inside profile pages
jq -r 'select(.status=="Claimed") | .extracted.usernames[]? // empty' \
  reports/johndoe123/report_johndoe123_ndjson.json \
  | sort -u > discovered_usernames.txt

# Step 4: Recurse on each discovered username (limit to top 5 to avoid runaway)
head -5 discovered_usernames.txt | while read user; do
  maigret "$user" --html --tags us --timeout 15
done
```

### Exercise 3: Recursive Parse from a Known Profile

Goal: start from one profile URL and let Maigret auto-discover identities.

```bash
# Maigret parses the page, extracts any embedded usernames/IDs, recurses
maigret --parse https://github.com/johndoe123 --html --graph

# Useful for pivoting off a single leaked profile into the rest of the identity graph
```

### Exercise 4: Username Permutation Search

Goal: catch variant handles (`johndoe`, `j.doe`, `jdoe`, `johndoe123`) from a real name.

```bash
# --permute takes a space-separated name and generates likely usernames
maigret "john doe" --permute --html --tags us

# Maigret runs each permutation across the site list and consolidates the report
# Review reports/john%20doe/ for consolidated findings
```

### Exercise 5: Stealth Scan via Tor

Goal: avoid leaking your real IP to 3,000+ sites.

```bash
# Start Tor first (Maigret does not manage the daemon)
sudo service tor start
# or: tor &

# Run via Tor SOCKS proxy
maigret johndoe123 -a \
  --html \
  --tor-proxy socks5://127.0.0.1:9050 \
  --timeout 30

# For .onion sites specifically, --tor-proxy is mandatory
maigret "darkforum-user" --tor-proxy socks5://127.0.0.1:9050 -a
```

### Exercise 6: AI-Assisted Investigation Summary

Goal: turn a raw Maigret report into a short investigator brief.

```bash
# Requires OpenAI-compatible API key
export OPENAI_API_KEY=sk-...

# Default model
maigret johndoe123 -a --ai

# Pick a different model
maigret johndoe123 -a --ai --ai-model gpt-4o-mini

# Point at a local / non-OpenAI endpoint via settings.json:
# { "openai_api_base_url": "http://localhost:8000/v1" }
```

The AI summary includes: likely real name, location, occupation, interests, languages, overall confidence, and follow-up leads.

### Exercise 7: Cross-Tool Verification Pipeline

Goal: rule out Maigret false positives before handing findings to a client.

```bash
# Maigret
maigret johndoe123 -a --json ndjson --html
# Sherlock (independent ruleset)
sherlock johndoe123 --json --output sherlock_johndoe123.json
# WhatsMyName (different site list)
whatsmyname -u johndoe123 --format json --output wmn_johndoe123.json

# Sites Maigret claims but Sherlock doesn't — manual verification candidates
jq -r '.site' reports/johndoe123/report_johndoe123_ndjson.json \
  | sort -u > maigret_sites.txt
jq -r 'keys[]' sherlock_johndoe123.json | sort -u > sherlock_sites.txt
comm -23 maigret_sites.txt sherlock_sites.txt > maigret_only.txt

# Manually inspect each URL in maigret_only.txt
while read site; do
  url=$(jq -r --arg s "$site" 'select(.site==$site and .status=="Claimed") | .url' \
    reports/johndoe123/report_johndoe123_ndjson.json | head -1)
  echo "Verify: $url"
done < maigret_only.txt
```

### Exercise 8: Tag-Filtered Niche Search

Goal: when you only need photo-sharing or dating site hits, avoid scanning 3,000 sites.

```bash
# Photo-sharing sites only
maigret johndoe123 --tags photo --html

# Dating sites only
maigret johndoe123 --tags dating --html

# US-targeted sites only
maigret johndoe123 --tags us --html

# Combine tags (AND/OR semantics — see --help)
maigret johndoe123 --tags photo,dating,us --html

# List available tags
maigret --list-tags  # if supported in current version
# Otherwise: grep maigret's sites.md for tag metadata
```

### Exercise 9: Python Library Embedding

Goal: integrate Maigret into a custom OSINT pipeline.

```python
import asyncio
from maigret import maigret
from maigret.sites import MaigretDatabase

async def investigate(username: str) -> dict:
    db = MaigretDatabase()
    db.load_default_db()
    sites = db.ranked_sites_top_only()
    results = await maigret(
        username=username,
        site_list=sites,
        timeout=20,
        max_connections=20,
    )
    return {
        site_name: result.status
        for site_name, result in results.items()
    }

findings = asyncio.run(investigate("johndoe123"))
claimed = {k: v for k, v in findings.items() if v.get("status") == "Claimed"}
print(f"Found {len(claimed)} claimed accounts")
```

## Reporting Formats

Maigret supports seven report formats — choose based on the audience.

| Format | Flag | Best For |
|--------|------|----------|
| HTML | `--html` | Browsable dossier, hand to client |
| PDF | `--pdf` (needs `pip install 'maigret[pdf]'`) | Printable report, executive briefing |
| XMind 8 mindmap | `--xmind` | Analyst-friendly relationship map (NOT compatible with XMind 2022+) |
| Interactive D3 graph | `--graph` | Live exploration of identity links in a browser |
| NDJSON | `--json ndjson` | Downstream scripting, one line per site result |
| Simple JSON | `--json simple` | Single nested object, all results in one document |
| CSV | `--csv` | Spreadsheet import, sortable/filterable |
| TXT | `--txt` | Plain-text summary, terminal-friendly |

> The web UI (`maigret:web` Docker image, port 5000) generates every format on demand from a single search — useful for collaborative investigations.

## Proxies & Stealth

| Transport | Flag | Example |
|-----------|------|---------|
| HTTP proxy | `--proxy` | `--proxy http://user:pass@proxy.local:8080` |
| SOCKS5 proxy | `--proxy` | `--proxy socks5://127.0.0.1:1080` |
| Tor | `--tor-proxy` | `--tor-proxy socks5://127.0.0.1:9050` |
| I2P | `--i2p-proxy` | `--i2p-proxy http://127.0.0.1:4444` |
| Cloudflare bypass (FlareSolverr) | `--cloudflare-bypass` | Run `docker run -d -p 8191:8191 ghcr.io/flaresolverr/flaresolverr` first |

**OPSEC rules**:
- Never run from your corporate egress IP — 3,000+ sites will see it.
- Rotate proxies between usernames to avoid fingerprinting.
- For `.onion` and `.i2p` targets, Tor/I2P is mandatory, not optional.
- `--timeout 30 --retries 2` over Tor — slower but more reliable.

## Detection Methods

### Username Enumeration Detection
- **Profile scraping patterns**: LinkedIn / Twitter / Instagram mass profile reads.
- **Reverse username lookup**: Spike in API calls to username lookup services.
- **Cross-platform correlation**: Same username queried across many platforms.

### SIEM Detection Rules
- **Splunk SPL**: `index=social | stats count by query | where count > 100`
- **Maigret / Sherlock audit**: Detect execution of username enumeration tools.

## Defense Evasion Techniques

### Username Enumeration Stealth
- **Distribute across platforms**: Pace enumeration; below per-platform rate limit.
- **Use sanctioned APIs**: Twitter/X API over web scraping.
- **Off-hours operation**: Enumerate during low-traffic hours.
- **Browser fingerprint rotation**: Rotate User-Agent to evade per-UA rate limit.

## Safety Notes

- **Lawful use only**: Maigret's MIT license and the repo's disclaimer explicitly place legal compliance (GDPR, CCPA, etc.) on the operator. Username profiling of a person without a lawful basis can be illegal in many jurisdictions.
- **Authorization scope**: Penetration testing engagements authorize the target organization's systems — they do *not* automatically authorize profiling individual employees on personal platforms. Confirm scope with the client before running Maigret on named individuals.
- **Rate / footprint awareness**: A full `-a` scan hits 3,000+ sites from one IP in minutes. This can trigger ISP-level rate limiting, downstream WAF blocks, and operator-identifiable traffic patterns. Always tunnel through Tor or a dedicated VPS.
- **Don't act on unverified findings**: Auto-generated profile stubs, archived accounts, and impersonators all produce "Claimed" results. Manually verify before publishing a dossier, confronting a subject, or escalating.
- **Data minimization**: Maigret output can contain sensitive personal data. Encrypt at rest, restrict access, and delete when the engagement closes.

## Hacker Laws

- **Information Wants to Be Free** — A single username is the most common cross-platform identifier humans use. People almost never invent a fresh handle for every site; Maigret's `--permute` and recursive pivot exploit this directly. The information is already public — Maigret just correlates it.
- **Divergent Thinking First** — Never trust a single tool's hit list. Maigret's detection rules go stale as sites change; Sherlock and WhatsMyName use different rulesets and catch different things. Cross-validate any finding you intend to act on.
- **Trust but Verify** — Maigret's "Claimed" status is probabilistic. SEO stub pages, archived accounts, soft-404s, and impersonators all produce false positives. Manually open any account you plan to include in a deliverable.
- **Obscurity Is Not Security** — A target who thinks their hobby forum handle is unconnected to their work identity is wrong. Maigret's recursive pivot (`--parse`, discovered-username re-runs) follows those connections automatically. Treat every account as linked to every other account.
- **Weakest Link Is Human** — Username reuse is a human convenience behavior, not a technical flaw. Defense starts with teaching people not to reuse handles, not with blocking Maigret (which is impossible — it only reads public pages).

## Learning Resources

- **This skill's supplementary files**: `payloads.md`, `test-cases.md`
- **Deep-dive guide**: `guides/maigret-username-dossier.md` — end-to-end dossier workflow with recursive pivot, OPSEC, and cross-tool verification
- **Workshop guide**: `guides/maigret-username-workshop.md` — multi-platform OSINT investigation workshop with JSON parsing, Maltego export, GDPR handling, and cron automation
- **Related skills**:
  - `skills/osint/SKILL.md` — broader OSINT collection (email, domain, breach data)
  - `skills/social-intelligence/SKILL.md` — discourse mining on discovered accounts
  - `skills/social-engineering/SKILL.md` — turning dossiers into phishing pretexts
  - `skills/recon-osint/SKILL.md` — active reconnaissance complement
  - `skills/deep-research/SKILL.md` — synthesis and report writing
- **External resources**:
  - Maigret repo: [github.com/soxoj/maigret](https://github.com/soxoj/maigret)
  - Maigret docs: [maigret.readthedocs.io](https://maigret.readthedocs.io)
  - Sherlock: [github.com/sherlock-project/sherlock](https://github.com/sherlock-project/sherlock)
  - WhatsMyName: [github.com/webbreacher/whatsmyname](https://github.com/webbreacher/whatsmyname)
  - Holehe: [github.com/megadose/holehe](https://github.com/megadose/holehe)
  - OSINT Framework: [osintframework.com](https://osintframework.com)
  - TRACE Labs (missing persons CTFs): [tracelabs.org](https://tracelabs.org)
  - Bellingcat Toolkit: [bellingcat.gitbook.io/toolkit](https://bellingcat.gitbook.io/toolkit)
- **Core system files**: `SOUL.md`, `TOOLS.md`, `IDENTITY.md`
