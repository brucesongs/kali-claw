# Maigret Username Workshop — Multi-Platform OSINT Investigation Playbook

> Deep-dive companion to `skills/username-profiling/SKILL.md` and `guides/maigret-username-dossier.md`.
>
> Audience: investigators who want a hands-on, end-to-end workshop for taking a single alias from zero to a 200+ site enumeration dossier, complete with JSON parsing, cross-tool correlation, Maltego/Spyse export, false-positive triage, and cron-based automation. Every command here is reproducible on Kali Linux 2025-2 with `pip3 install maigret sherlock-project whatsmyname holehe`.
>
> Learning outcomes: by the end of this workshop you will have stood up a complete Maigret investigation pipeline, parsed its NDJSON into structured entities, correlated those entities against Sherlock/WhatsMyName outputs, exported them to a graph DB / Maltego, automated the workflow on a weekly cron with JSON diffing, and hardened the whole stack against operator fingerprinting.

---

## 1. Introduction & Objective

### 1.1 Why a Workshop?

`maigret <username> --html` produces a dossier in two minutes. That is the floor, not the ceiling. A defensible multi-platform investigation requires:

1. **Setup discipline** — reproducible Python environment, pinned Maigret version, isolated network egress.
2. **Workflow fluency** — knowing which flags change signal vs. noise, when to recurse, when to stop.
3. **Parsing skills** — Maigret's NDJSON is rich; leaving it un-mined wastes 80% of the value.
4. **Correlation discipline** — Maigret alone produces false positives; Sherlock + WhatsMyName provide independent detection rules.
5. **Export plumbing** — Maltego, Spyse, Neo4j each consume a different shape; build transforms once.
6. **False-positive triage** — auto-generated stubs, soft-404s, archived accounts all look like "Claimed" until you inspect them.
7. **Automation** — once the workflow is sound, run it weekly with diff alerts to catch new accounts.
8. **Legal awareness** — GDPR/CCPA apply even when data is public; document your basis.

This workshop walks through each of those, end to end, in the order you would execute them on a real engagement.

### 1.2 Workshop Lab Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Investigation VM (Kali)                  │
│                                                             │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌────────┐ │
│  │ Maigret  │───▶│ NDJSON   │───▶│ jq / py  │───▶│ Neo4j  │ │
│  │ 0.4.0+   │    │ exports  │    │  parsers │    │ graph  │ │
│  └────┬─────┘    └──────────┘    └──────────┘    └────────┘ │
│       │                                                     │
│       │ coordinated runs        ┌──────────┐                │
│       └────────────────────────▶│ Sherlock │                │
│                                 │ WhatsMyN │                │
│                                 │ Holehe   │                │
│                                 └────┬─────┘                │
│                                      │                      │
│                              ┌───────▼────────┐             │
│                              │ Merge / Dedup  │             │
│                              │ -> Maltego CSV │             │
│                              └────────────────┘             │
│                                                             │
│   Network: Tor SOCKS5 :9050  /  residential rotating proxy  │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼ egress hidden
                  3,000+ target sites
```

### 1.3 Prerequisites

- Kali Linux 2025-2 (ARM64 or x86_64)
- Python 3.11+ (`python3 --version`)
- Tor daemon (`sudo apt install tor`)
- Docker (for FlareSolverr / web UI / Neo4j)
- 10 GB free disk (for reports + breach data caches)
- Lawful authorization covering the target identity

---

## 2. Maigret Installation & Setup

### 2.1 Isolated Python Environment

Never install OSINT tools into the system Python. Use a dedicated venv so dependency upgrades do not break other tooling.

```bash
# Create a dedicated venv for OSINT work
python3 -m venv ~/venvs/osint
source ~/venvs/osint/bin/activate

# Pin Maigret to a known-good version
pip install --upgrade pip wheel
pip install maigret==0.4.0

# Optional: PDF report support (requires system libs)
pip install 'maigret[pdf]'
sudo apt-get install -y libcairo2 libpango-1.0-0 libpangoft2-1.0-0

# Companion tools in the same venv
pip install sherlock-project==0.14.4
pip install whatsmyname holehe
pip install requests jq jq-ng rich

# Sanity check
maigret --version
sherlock --version
which maigret sherlock whatsmyname holehe
```

### 2.2 Database Bootstrap

Maigret auto-fetches its site database (3,000+ entries) from GitHub on first run. The DB is cached for 24h. For reproducibility, pin it.

```bash
# Trigger the first-run DB fetch
maigret --version  # loads DB metadata
maigret <test_username> --no-color --timeout 5   # forces DB download

# Locate the cache
find ~/.cache/maigret -type f 2>/dev/null
ls -lh ~/.cache/maigret/data.json 2>/dev/null

# Pin the current DB snapshot for engagement reproducibility
cp ~/.cache/maigret/data.json ~/engagements/<case>/maigret_data_$(date +%Y%m%d).json
md5sum ~/engagements/<case>/maigret_data_*.json >> ~/engagements/<case>/chain-of-custody.txt
```

### 2.3 Settings File

Maigret supports a JSON settings file for repeated configurations.

```bash
mkdir -p ~/.config/maigret
cat > ~/.config/maigret/settings.json <<'JSON'
{
  "site_data": null,
  "db_file": "~/.cache/maigret/data.json",
  "cookies_file": null,
  "tor_proxy": "socks5://127.0.0.1:9050",
  "max_connections": 15,
  "timeout": 30,
  "retries": 2,
  "color": false,
  "no_db_update": false,
  "tags": ["us"],
  "keywords": [],
  "parse_links": true
}
JSON

# Now every invocation inherits these defaults
maigret <username> --html
```

### 2.4 Install Verification

```bash
# Self-check (maintainer mode — verifies detection rules against live sites)
maigret --self-check --no-color 2>&1 | tee selfcheck.log
grep -cE 'OK|FAIL' selfcheck.log

# Verify Tor works before relying on it
sudo service tor start
curl --socks5-hostname 127.0.0.1:9050 https://api.ipify.org
# Should NOT match: curl -s https://api.ipify.org
```

---

## 3. Multi-Site Investigation Workflow

### 3.1 Phase Map

```
Phase A: Seed Intake ───▶ Phase B: Broad Sweep ───▶ Phase C: Triage
   manual handle            maigret -a + tags         NDJSON parse,
   variants, context        --html --graph            entity extraction
        │                          │                          │
        ▼                          ▼                          ▼
   seed_variants.txt         reports/<u>/               claimed.tsv
   context.json              *.html *.json              pivots.txt
                                                         emails.txt

Phase D: Pivot Recursion ─▶ Phase E: Cross-Verify ─▶ Phase F: Dossier
   re-run maigret on        sherlock + whatsmyname     merge, dedupe,
   discovered handles       + holehe diff              graph export,
                                                         PDF/HTML report
```

### 3.2 Phase A — Seed Intake

```bash
CASEDIR=~/engagements/case-001
mkdir -p "$CASEDIR"/{seed,reports,parsed,verified,final}

# Capture every known identifier up front
cat > "$CASEDIR/seed/context.json" <<'JSON'
{
  "seed_username": "johndoe123",
  "suspected_real_name": "John Doe",
  "country_hint": "us",
  "language_hint": "en",
  "tech_hints": ["python", "rust", "linux", "docker"],
  "email_fragments": ["j.doe@", "johndoe@"],
  "time_window": "2018-01 to present",
  "authorization_ref": "SOW-2026-0142"
}
JSON

# Build variant list
cat > "$CASEDIR/seed/variants.txt" <<'EOF'
johndoe123
johndoe
john.doe
j.doe
jdoe
johnd
johndoe_dev
EOF

# Hand off to Maigret's --permute to expand the list
maigret "John Doe" --permute --no-color --tags us \
  --json ndjson --output "$CASEDIR/seed/permute_ndjson.json" 2>&1 \
  | tee "$CASEDIR/seed/permute.log"
```

### 3.3 Phase B — Broad Sweep

```bash
# Always via Tor. Always with NDJSON + HTML + graph for downstream parsing.
cd "$CASEDIR"
TARGET=$(jq -r .seed_username seed/context.json)

maigret "$TARGET" -a \
  --tor-proxy socks5://127.0.0.1:9050 \
  --html \
  --graph \
  --json ndjson \
  --csv \
  --tags us \
  --keywords $(jq -r '.tech_hints | join(" ")' seed/context.json) \
  --timeout 30 \
  --max-connections 15 \
  --retries 2 \
  --output "$CASEDIR/reports/" \
  --no-color 2>&1 | tee reports/sweep.log

# Verify the artifacts exist
ls -lh reports/
ls -lh reports/*.json reports/*.html 2>/dev/null
```

### 3.4 Phase C — Triage & Entity Extraction

```bash
# Count claimed / available / unknown
jq -r '.status' reports/*_ndjson.json | sort | uniq -c

# Pull every claimed account into TSV
jq -r 'select(.status=="Claimed") | [.site_name, .url, (.extracted.bio // "")] | @tsv' \
  reports/*_ndjson.json | sort -u > parsed/claimed.tsv

# Pull discovered pivot identities
jq -r 'select(.status=="Claimed") | .extracted.usernames[]? // empty' \
  reports/*_ndjson.json | sort -u > parsed/pivot_users.txt
jq -r 'select(.status=="Claimed") | .extracted.emails[]? // empty' \
  reports/*_ndjson.json | sort -u > parsed/pivot_emails.txt
jq -r 'select(.status=="Claimed") | .extracted.phones[]? // empty' \
  reports/*_ndjson.json | sort -u > parsed/pivot_phones.txt
jq -r 'select(.status=="Claimed") | .extracted.images[]? // empty' \
  reports/*_ndjson.json | sort -u > parsed/pivot_avatars.txt

wc -l parsed/*.txt parsed/*.tsv
```

### 3.5 Phase D — Pivot Recursion (Depth-Limited)

```bash
# Never recurse deeper than 2 layers without explicit authorization
DEPTH=2
VISITED="$CASEDIR/parsed/visited.txt"
echo "$TARGET" > "$VISITED"

queue=( $(head -10 parsed/pivot_users.txt) )   # cap breadth
for ((i=0; i<DEPTH; i++)); do
  next_queue=()
  for user in "${queue[@]}"; do
    grep -qx "$user" "$VISITED" && continue
    echo "$user" >> "$VISITED"

    maigret "$user" -a \
      --tor-proxy socks5://127.0.0.1:9050 \
      --html --json ndjson \
      --tags us --timeout 30 --max-connections 10 \
      --output "$CASEDIR/reports/pivot_${i}_${user}/" \
      --no-color

    # Pull next layer
    while read u2; do
      grep -qx "$u2" "$VISITED" || next_queue+=("$u2")
    done < <(jq -r 'select(.status=="Claimed") | .extracted.usernames[]? // empty' \
              reports/pivot_${i}_${user}/*_ndjson.json 2>/dev/null | sort -u)
  done
  queue=("${next_queue[@]}")
  [ ${#queue[@]} -eq 0 ] && break
done

# Aggregate every discovered (username, site) edge
cat reports/*/report_*_ndjson.json reports/*_ndjson.json 2>/dev/null \
  | jq -r 'select(.status=="Claimed") | [.site_username, .site_name, .url] | @tsv' \
  | sort -u > parsed/identity_graph.tsv

wc -l parsed/identity_graph.tsv
```

### 3.6 Phase E — Cross-Tool Verification

```bash
# Sherlock: independent ruleset
sherlock "$TARGET" \
  --json --output "$CASEDIR/parsed/sherlock_${TARGET}.json" \
  --timeout 10 --ratelimit 2 --print-found

# WhatsMyName: different site list, different detection logic
whatsmyname -u "$TARGET" \
  --format json --output "$CASEDIR/parsed/wmn_${TARGET}.json"

# Holehe: if any email was discovered
[ -s parsed/pivot_emails.txt ] && head -1 parsed/pivot_emails.txt \
  | xargs holehe > parsed/holehe_${TARGET}.txt

# Diff: sites Maigret claims but Sherlock does not even check
jq -r '.site_name' reports/*_ndjson.json | sort -u > parsed/maigret_sites.txt
jq -r 'keys[]' parsed/sherlock_${TARGET}.json | sort -u > parsed/sherlock_sites.txt
comm -23 parsed/maigret_sites.txt parsed/sherlock_sites.txt > parsed/maigret_only_sites.txt
wc -l parsed/maigret_only_sites.txt   # manual verification candidates
```

### 3.7 Phase F — Dossier Synthesis

```bash
# Build the authoritative confirmed set:
# Maigret Claimed + (Sherlock claimed OR WhatsMyName claimed)
python3 - <<'PY'
import json, csv, sys
from pathlib import Path

CASEDIR = Path.home() / "engagements/case-001"
target = json.loads((CASEDIR/"seed/context.json").read_text())["seed_username"]

# Load Maigret NDJSON
maigret = []
for f in (CASEDIR/"reports").glob("*_ndjson.json"):
    for line in f.read_text().splitlines():
        try:
            maigret.append(json.loads(line))
        except json.JSONDecodeError:
            continue

# Load Sherlock + WhatsMyName
sherlock = json.loads((CASEDIR/f"parsed/sherlock_{target}.json").read_text())
wmn = json.loads((CASEDIR/f"parsed/wmn_{target}.json").read_text())

# Triangulate
confirmed = []
for rec in maigret:
    if rec.get("status") != "Claimed":
        continue
    site = rec.get("site_name", "")
    url = rec.get("url", "")
    bio = rec.get("extracted", {}).get("bio", "")
    in_sherlock = site.lower() in (s.lower() for s in sherlock.keys())
    in_wmn = any(site.lower() in w.get("site", "").lower() for w in wmn if isinstance(w, dict))
    confidence = "HIGH" if (in_sherlock or in_wmn) else "MEDIUM"
    confirmed.append([site, url, bio, confidence])

with open(CASEDIR/"final/confirmed_accounts.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["site", "url", "bio", "confidence"])
    w.writerows(sorted(confirmed))

print(f"Wrote {len(confirmed)} confirmed accounts")
PY

# Render the final HTML dossier
cat > "$CASEDIR/final/dossier.md" <<'EOF'
# Dossier: <seed_username>

## Identity Summary
- Real name (claimed): John Doe
- Location: San Francisco, CA (HIGH confidence — 4 platforms)
- Languages: English, basic Spanish
- Tech stack: python, rust, docker (matched keywords on 6 profiles)

## Confirmed Accounts
EOF
column -t -s, "$CASEDIR/final/confirmed_accounts.csv" | tail -n +2 >> "$CASEDIR/final/dossier.md"

pandoc "$CASEDIR/final/dossier.md" -o "$CASEDIR/final/dossier.pdf" 2>/dev/null \
  || echo "pandoc not installed; ship markdown"
```

---

## 4. Result Parsing & Entity Extraction

### 4.1 NDJSON Shape

Each line of a Maigret NDJSON report is one site result. Knowing the schema unlocks every downstream transform.

```python
"""
Reference shape of a Maigret NDJSON record.
"""
import json
from typing import Any

sample_record: dict[str, Any] = {
    "site_name": "GitHub",
    "site_url": "https://github.com",
    "url": "https://github.com/johndoe123",
    "status": "Claimed",        # Claimed / Available / Unknown
    "site_username": "johndoe123",
    "tags": {"tags": ["dev", "us"], "checked": True},
    "extracted": {
        "usernames": ["jdoe_dev", "johndoe"],
        "emails": ["j.doe@example.com"],
        "phones": [],
        "images": ["https://avatars.githubusercontent.com/u/12345"],
        "bio": "Backend engineer @ Acme.",
        "location": "San Francisco",
        "links": ["https://johndoe.dev"]
    },
    "keywords_matched": ["python", "docker"],
    "response_time_ms": 412,
    "http_status": 200
}

print(json.dumps(sample_record, indent=2))
```

### 4.2 Common Extraction Queries

```bash
# Every (site, bio) pair, for keyword extraction downstream
jq -r 'select(.status=="Claimed") | [.site_name, (.extracted.bio // "")] | @tsv' \
  reports/*_ndjson.json | sort -u > parsed/bios.tsv

# Top 20 sites by frequency across all pivot reports
jq -r '.site_name' reports/*_ndjson.json \
  | sort | uniq -c | sort -rn | head -20

# Sites where extracted location is non-empty (geoint pivot candidates)
jq -r 'select(.status=="Claimed") | select(.extracted.location | length > 0) | [.site_name, .extracted.location] | @tsv' \
  reports/*_ndjson.json | sort -u

# Avatar image URLs (for reverse image search)
jq -r 'select(.status=="Claimed") | .extracted.images[]? // empty' \
  reports/*_ndjson.json | sort -u > parsed/avatar_urls.txt

# Per-site response time distribution (helps identify WAF-blocked sites)
jq -r '[.site_name, (.response_time_ms // 0)] | @tsv' \
  reports/*_ndjson.json | sort -k2 -n | tail -20
```

### 4.3 Python Parser Library

For repeat engagements, encapsulate the parsing in a small library.

```python
"""
maigret_parser.py — reusable parsing utilities for Maigret NDJSON output.
"""
from __future__ import annotations
import json
import csv
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Iterator


@dataclass(frozen=True)
class Account:
    site: str
    url: str
    username: str | None = None
    bio: str | None = None
    location: str | None = None
    emails: tuple[str, ...] = field(default_factory=tuple)
    phones: tuple[str, ...] = field(default_factory=tuple)
    usernames: tuple[str, ...] = field(default_factory=tuple)
    images: tuple[str, ...] = field(default_factory=tuple)
    keywords: tuple[str, ...] = field(default_factory=tuple)


def iter_records(ndjson_path: Path) -> Iterator[dict]:
    """Yield each JSON record from a Maigret NDJSON file."""
    for line in ndjson_path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue


def accounts_from_ndjson(ndjson_path: Path) -> list[Account]:
    """Extract all claimed accounts from one NDJSON file."""
    out: list[Account] = []
    for rec in iter_records(ndjson_path):
        if rec.get("status") != "Claimed":
            continue
        ext = rec.get("extracted", {}) or {}
        out.append(Account(
            site=rec.get("site_name", ""),
            url=rec.get("url", ""),
            username=rec.get("site_username"),
            bio=ext.get("bio"),
            location=ext.get("location"),
            emails=tuple(ext.get("emails", []) or []),
            phones=tuple(ext.get("phones", []) or []),
            usernames=tuple(ext.get("usernames", []) or []),
            images=tuple(ext.get("images", []) or []),
            keywords=tuple(rec.get("keywords_matched", []) or []),
        ))
    return out


def merge_accounts(*sources: list[Account]) -> dict[str, Account]:
    """Merge multiple account lists by URL, unioning extracted fields."""
    merged: dict[str, Account] = {}
    for src in sources:
        for acc in src:
            key = acc.url
            if key not in merged:
                merged[key] = acc
            else:
                prev = merged[key]
                merged[key] = Account(
                    site=prev.site,
                    url=prev.url,
                    username=prev.username or acc.username,
                    bio=prev.bio or acc.bio,
                    location=prev.location or acc.location,
                    emails=tuple(set(prev.emails) | set(acc.emails)),
                    phones=tuple(set(prev.phones) | set(acc.phones)),
                    usernames=tuple(set(prev.usernames) | set(acc.usernames)),
                    images=tuple(set(prev.images) | set(acc.images)),
                    keywords=tuple(set(prev.keywords) | set(acc.keywords)),
                )
    return merged


def write_csv(accounts: dict[str, Account], out_path: Path) -> None:
    """Write merged accounts to CSV."""
    with out_path.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["site", "url", "username", "bio", "location",
                    "emails", "phones", "usernames", "images", "keywords"])
        for acc in sorted(merged.values(), key=lambda a: a.site):
            w.writerow([
                acc.site, acc.url, acc.username or "", acc.bio or "",
                acc.location or "",
                ";".join(acc.emails), ";".join(acc.phones),
                ";".join(acc.usernames), ";".join(acc.images),
                ";".join(acc.keywords),
            ])


if __name__ == "__main__":
    import sys
    files = [Path(p) for p in sys.argv[1:]]
    sources = [accounts_from_ndjson(f) for f in files]
    merged = merge_accounts(*sources)
    write_csv(merged, Path("merged_accounts.csv"))
    print(f"Merged {len(merged)} unique accounts from {len(files)} files")
```

### 4.4 Pulling Pivot Identities for Downstream Skills

```python
"""
Export discovered emails / usernames / phones for use by adjacent skills.
- emails  -> h8mail / DeHashed / HaveIBeenPwned
- phones  -> Twilio lookup / carrier OSINT
- avatars -> reverse image search (Yandex, Google Images)
"""
import json
from pathlib import Path

CASEDIR = Path.home() / "engagements/case-001"
reports_dir = CASEDIR / "reports"

emails, usernames, phones, avatars = set(), set(), set(), set()

for f in reports_dir.glob("*_ndjson.json"):
    for line in f.read_text().splitlines():
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if rec.get("status") != "Claimed":
            continue
        ext = rec.get("extracted", {}) or {}
        emails.update(ext.get("emails", []) or [])
        usernames.update(ext.get("usernames", []) or [])
        phones.update(ext.get("phones", []) or [])
        avatars.update(ext.get("images", []) or [])

out = CASEDIR / "parsed"
(out / "emails.txt").write_text("\n".join(sorted(emails)))
(out / "usernames.txt").write_text("\n".join(sorted(usernames)))
(out / "phones.txt").write_text("\n".join(sorted(phones)))
(out / "avatars.txt").write_text("\n".join(sorted(avatars)))

print(f"emails={len(emails)} usernames={len(usernames)} phones={len(phones)} avatars={len(avatars)}")
```

---

## 5. Correlation with Sherlock / WhatsMyName

### 5.1 Why Three Tools

| Tool | Site List | Detection Method | Strength |
|------|-----------|------------------|----------|
| **Maigret** | 3,000+ | Regex + parser per site | Richest extraction (bios, links, images) |
| **Sherlock** | 300+ | HTTP status + regex | Independent ruleset, fast, JSON-first |
| **WhatsMyName** | 600+ | JSON-defined per-site rules | Different detection logic, broader niche coverage |

Running only one tool biases the dossier toward that tool's blind spots. The triangulation principle: a finding confirmed by 2+ tools is HIGH confidence; Maigret-only is a manual verification candidate.

### 5.2 Parallel Orchestration

```bash
#!/usr/bin/env bash
# run_triangulation.sh — run all three tools, normalize outputs.
set -euo pipefail
TARGET=${1:?usage: $0 <username>}
OUT=~/engagements/case-001/parsed
mkdir -p "$OUT"

# Run all three in parallel (Tor for Maigret only — Sherlock/WhatsMyName have their own rate limiting)
maigret "$TARGET" -a --tor-proxy socks5://127.0.0.1:9050 \
  --json ndjson --output "$OUT/maigret_${TARGET}.ndjson" &
PID_M=$!

sherlock "$TARGET" --json --output "$OUT/sherlock_${TARGET}.json" --timeout 10 &
PID_S=$!

whatsmyname -u "$TARGET" --format json --output "$OUT/wmn_${TARGET}.json" &
PID_W=$!

wait $PID_M $PID_S $PID_W
echo "All three tools finished. Outputs in $OUT"
ls -lh "$OUT"/*.{ndjson,json} 2>/dev/null
```

### 5.3 Result Merging with jq

```bash
# Normalize Sherlock to (site, status) tuples
jq -r 'to_entries[] | [.key, .value.status] | @tsv' \
  parsed/sherlock_${TARGET}.json | sort -u > parsed/sherlock_normalized.tsv

# Normalize WhatsMyName to (site, status)
jq -r '.[] | [.site, .status] | @tsv' \
  parsed/wmn_${TARGET}.json | sort -u > parsed/wmn_normalized.tsv

# Normalize Maigret to (site, status)
jq -r '[.site_name, .status] | @tsv' \
  parsed/maigret_${TARGET}.ndjson | sort -u > parsed/maigret_normalized.tsv

# Full outer join on site name
python3 - <<'PY'
import csv
from pathlib import Path
from collections import defaultdict

OUT = Path.home() / "engagements/case-001/parsed"
rows = defaultdict(dict)  # site -> tool -> status

for tool, fname in [("maigret","maigret_normalized.tsv"),
                    ("sherlock","sherlock_normalized.tsv"),
                    ("wmn","wmn_normalized.tsv")]:
    p = OUT / fname
    if not p.exists(): continue
    for line in p.read_text().splitlines():
        parts = line.split("\t")
        if len(parts) < 2: continue
        site, status = parts[0].lower(), parts[1].lower()
        rows[site][tool] = status

with (OUT / "triangulation.csv").open("w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["site", "maigret", "sherlock", "wmn", "confidence"])
    for site, tools in sorted(rows.items()):
        claimed_count = sum(1 for s in tools.values() if "claim" in s)
        confidence = ("HIGH" if claimed_count >= 2 else
                      "MEDIUM" if claimed_count == 1 else "LOW")
        w.writerow([site, tools.get("maigret",""),
                    tools.get("sherlock",""), tools.get("wmn",""),
                    confidence])

print(f"Wrote {len(rows)} sites to triangulation.csv")
PY
```

### 5.4 Deduplication by Platform

```bash
# Sometimes Maigret lists "GitHub" while Sherlock lists "github.com".
# Normalize by stripping TLD + lowercasing before joining.
python3 - <<'PY'
import re
from pathlib import Path

def norm(site: str) -> str:
    s = site.lower().strip()
    s = re.sub(r"\.(com|org|net|io|dev|me|co)$", "", s)
    return s

# Apply norm() before the join in the previous section.
print(norm("GitHub"))       # -> github
print(norm("github.com"))   # -> github
PY
```

---

## 6. False Positive Triage

### 6.1 False Positive Categories

| Category | What it looks like | How to detect |
|----------|--------------------|---------------|
| **SEO stub** | Page exists because the platform auto-generates a profile page for every checked username | Bio empty, no avatar, no activity dates, generic template text |
| **Archived account** | Account existed, was deleted, but the URL still returns 200 | "Account suspended" / "User not found" text inside a 200 response |
| **Soft 404** | Site returns 200 with a "create this profile" CTA | Look for "Sign up to claim" wording |
| **Impersonation** | Real account, but not the target human | Avatar/bio mismatch vs. other platforms |
| **Common-handle collision** | Two different humans share the same username | Bio/location/employer disagree across platforms |

### 6.2 Programmatic Triage Heuristics

```python
"""
fp_triage.py — score each claimed account for false-positive likelihood.
Score >= 0.7 -> needs manual verification.
"""
import json
from pathlib import Path

def fp_score(rec: dict) -> float:
    """Return a 0..1 false-positive likelihood score."""
    score = 0.0
    ext = rec.get("extracted", {}) or {}

    # Empty bio -> likely stub
    if not (ext.get("bio") or "").strip():
        score += 0.3
    # No avatar -> likely stub
    if not ext.get("images"):
        score += 0.2
    # No usernames discovered inside the profile -> low engagement signal
    if not ext.get("usernames"):
        score += 0.1
    # Suspicious keywords in bio
    bio = (ext.get("bio") or "").lower()
    for red_flag in ["sign up", "claim this", "register", "create your"]:
        if red_flag in bio:
            score += 0.4
            break
    # HTTP 200 + very fast response -> sometimes a CDN stub
    if rec.get("http_status") == 200 and rec.get("response_time_ms", 9999) < 100:
        score += 0.1

    return min(score, 1.0)


if __name__ == "__main__":
    ndjson = Path("reports/case_ndjson.json")
    for line in ndjson.read_text().splitlines():
        if not line.strip(): continue
        rec = json.loads(line)
        if rec.get("status") != "Claimed": continue
        s = fp_score(rec)
        if s >= 0.5:
            print(f"{s:.2f}  {rec.get('site_name')}  {rec.get('url')}")
```

### 6.3 Manual Verification Queue

```bash
# Build the verification queue (anything Maigret-only + FP score >= 0.5)
python3 fp_triage.py > parsed/verification_queue.txt
wc -l parsed/verification_queue.txt

# Walk the queue in Tor Browser, record verdict per URL
cat > parsed/verification_log.tsv <<'EOF'
site	url	verdict	notes
EOF

# Append one row per manually verified URL
echo -e "GitHub.com\thttps://github.com/johndoe123\tCONFIRMED\tBio + avatar consistent with target" \
  >> parsed/verification_log.tsv
echo -e "SomeStub.com\thttps://somestub.com/johndoe123\tSTUB_FALSE_POSITIVE\tEmpty bio, no avatar, template page" \
  >> parsed/verification_log.tsv
```

---

## 7. Output to Maltego / Spyse

### 7.1 Maltego CSV Import

Maltego consumes a CSV with columns matching its entity types. Generate one from the merged accounts.

```bash
python3 - <<'PY'
import csv
from pathlib import Path

CASEDIR = Path.home() / "engagements/case-001"
infile = CASEDIR / "final/confirmed_accounts.csv"
outfile = CASEDIR / "final/maltego_import.csv"

with infile.open() as fin, outfile.open("w", newline="") as fout:
    reader = csv.DictReader(fin)
    w = csv.writer(fout)
    w.writerow(["entity_type", "entity_value", "url", "notes"])
    for row in reader:
        # Map each site to a Maltego entity type
        site = row["site"].lower()
        if "github" in site: etype = "maltego.GitHubAccount"
        elif "twitter" in site or "x.com" in site: etype = "maltego.TwitterProfile"
        elif "linked" in site: etype = "maltego.Person"
        elif "reddit" in site: etype = "maltego.Alias"
        elif "keybase" in site: etype = "maltego.NSAlias"
        else: etype = "maltego.Website"
        w.writerow([etype, row["username"] or row["site"], row["url"], row["bio"]])

print(f"Wrote Maltego CSV: {outfile}")
PY
```

### 7.2 Maltego Graph CSV

For the identity graph (username -> site edges):

```bash
python3 - <<'PY'
import csv
from pathlib import Path

CASEDIR = Path.home() / "engagements/case-001"
tsv_in = CASEDIR / "parsed/identity_graph.tsv"
csv_out = CASEDIR / "final/maltego_edges.csv"

with tsv_in.open() as fin, csv_out.open("w", newline="") as fout:
    w = csv.writer(fout)
    w.writerow(["from_entity", "from_type", "to_entity", "to_type", "edge_label"])
    for line in fin:
        parts = line.strip().split("\t")
        if len(parts) < 3: continue
        user, site, url = parts
        w.writerow([user, "maltego.Alias", site, "maltego.Website", "HAS_ACCOUNT_ON"])

print(f"Wrote Maltego edges CSV: {csv_out}")
PY
```

### 7.3 Spyse / Intelligence-X Export

Spyse and Intelligence-X consume newline-delimited JSON of `(indicator, type, source)` tuples.

```python
"""
spyse_export.py — emit NDJSON suitable for Spyse/IntelX ingestion.
"""
import json
from pathlib import Path
from datetime import datetime

CASEDIR = Path.home() / "engagements/case-001"
infile = CASEDIR / "final/confirmed_accounts.csv"
outfile = CASEDIR / "final/spyse_import.ndjson"
now = datetime.utcnow().isoformat() + "Z"

with infile.open() as f, outfile.open("w") as out:
    # Skip header
    next(f)
    for line in f:
        parts = line.strip().split(",")
        if len(parts) < 4: continue
        site, url, bio, confidence = parts[:4]
        record = {
            "indicator": url,
            "type": "url",
            "tags": ["maigret", "username-profiling", site],
            "confidence": confidence,
            "source": "maigret",
            "first_seen": now,
            "context": {"bio": bio, "site": site}
        }
        out.write(json.dumps(record) + "\n")

print(f"Wrote Spyse NDJSON: {outfile}")
```

### 7.4 Neo4j Cypher Import

For graph-database analysis (find communities, central identities, bridges).

```cypher
// nodes
LOAD CSV WITH HEADERS FROM 'file:///identity_nodes.csv' AS row
MERGE (u:Username {name: row.username});

LOAD CSV WITH HEADERS FROM 'file:///identity_sites.csv' AS row
MERGE (s:Site {name: row.site, url: row.url});

// edges
LOAD CSV WITH HEADERS FROM 'file:///identity_edges.csv' AS row
FIELDTERMINATOR ','
MATCH (u:Username {name: row.username})
MATCH (s:Site {name: row.site})
MERGE (u)-[:HAS_ACCOUNT_ON {bio: row.bio, confidence: row.confidence}]->(s);

// Find the most connected usernames (bridges between communities)
MATCH (u:Username)-[:HAS_ACCOUNT_ON]->(s:Site)
RETURN u.name, COUNT(s) AS site_count
ORDER BY site_count DESC LIMIT 10;
```

---

## 8. Case Studies: Tracking a Target Across 200+ Sites

### 8.1 Case Study A — Forum Handle to Real Human

Starting point: a single leaked forum handle `darkfoe` on a breach corpus.

```
Phase A: seed       darkfoe
Phase B: sweep      maigret darkfoe -a --tags us
Phase C: triage     47 claimed accounts, 12 pivot usernames
Phase D: pivot      recurse on top 5 pivots -> 31 more accounts
Phase E: verify     Sherlock confirms 28/47; WhatsMyName adds 6 more
Phase F: dossier    cross-correlated bio + avatar -> real identity confirmed
```

**Result**: 200+ minute wall-clock; 78 confirmed accounts; identity resolved via a Keybase proof linking to a GitHub account that committed under a real name.

**Key lesson**: the single highest-value pivot was Keybase — its cryptographic proofs chain to Twitter, GitHub, and Reddit simultaneously. Always include `--parse https://keybase.io/<user>` in any pivot phase.

### 8.2 Case Study B — Impersonation Detection

Starting point: an executive received a phishing email that appeared to come from their own CEO's handle on a hobby forum.

```
Phase A: seed       CEO_handle (from internal directory)
Phase B: sweep      maigret CEO_handle -a
Phase C: triage     23 claimed accounts
Phase D: pivot      no new usernames discovered (CEO has a tight footprint)
Phase E: verify     3 accounts have avatars / bios inconsistent with CEO's known profile
Phase F: dossier    flagged 3 impersonations, sent takedown requests
```

**Result**: 3 impersonation accounts identified across Reddit, Steam, and a dating site. Takedown requests submitted; CEO's footprint unchanged.

**Key lesson**: impersonation detection benefits from running Maigret quarterly, not once. New impersonations appear continuously.

### 8.3 Case Study C — Missing Persons (Trace Labs CTF)

Starting point: a known alias `luna_ray` from a Trace Labs CTF brief.

```
Phase A: seed       luna_ray + permutations (lunaray, luna.ray, luna_ray_)
Phase B: sweep      maigret --permute "Luna Ray" --tags us
Phase C: triage     14 claimed accounts, geo signals in 4 bios
Phase D: pivot      recurse on 4 discovered usernames -> 9 more accounts
Phase E: verify     avatar reverse-image-searched -> matched a LinkedIn profile
Phase F: dossier    geo triangulated from 3 platform bios -> city-level location
```

**Result**: 90-minute CTF; city-level location submitted; team placed in top 5.

**Key lesson**: avatar reverse-image search (Yandex is best for faces) is the highest-yield cross-correlation step. Always export avatar URLs from Maigret output.

---

## 9. Legal Considerations: GDPR / PII Handling

### 9.1 Lawful Basis

Username profiling collects personal data even when every source is public. Under GDPR Article 6, you need a documented lawful basis:

| Basis | When it applies |
|-------|-----------------|
| **Consent** | Subject has explicitly consented to the investigation |
| **Contract** | Investigation is necessary to fulfill a contract with the subject (rare in pentest) |
| **Legal obligation** | Court order, regulatory mandate |
| **Legitimate interest** | Internal investigations where the subject's interest is not overridden — most pentest/due-diligence cases |

Document the basis in writing before the investigation starts. The engagement file should reference it:

```bash
# Add to chain-of-custody.txt
echo "$(date -u +%FT%TZ)  lawful_basis=legitimate_interest  ref=SOW-2026-0142" \
  >> "$CASEDIR/chain-of-custody.txt"
```

### 9.2 Data Minimization

GDPR Article 5(1)(c) requires collecting only what is necessary for the purpose. Practical steps:

```bash
# Drop fields you do not need from the parsed output
jq 'del(.extracted.images, .extracted.phones)' \
  reports/*_ndjson.json > reports/minimized_ndjson.json

# Or filter at parse time
python3 -c "
import json, sys
for line in sys.stdin:
    rec = json.loads(line)
    if rec.get('status') == 'Claimed':
        print(json.dumps({'site': rec['site_name'], 'url': rec['url']}))
"
```

### 9.3 Retention & Destruction

```bash
# Set a destruction date up front
DESTRUCTION_DATE=$(date -d '+90 days' +%Y-%m-%d)
echo "destruction_date=$DESTRUCTION_DATE" >> "$CASEDIR/chain-of-custody.txt"

# At destruction time:
shred -uvz "$CASEDIR/reports/"*.{json,html,pdf,tsv,txt,log} 2>/dev/null
rm -rf "$CASEDIR/reports" "$CASEDIR/parsed" "$CASEDIR/verified"
gpg --symmetric --cipher-algo AES256 "$CASEDIR/final/dossier.pdf"  # keep only the encrypted deliverable
```

### 9.4 Cross-Border Transfer

If the investigation data crosses borders (e.g., US investigator profiling an EU subject), GDPR Chapter V applies. Practical mitigations:

- Store data only on EU-based servers or use end-to-end encrypted storage
- Use Standard Contractual Clauses if working with a US client
- Document the transfer mechanism in the chain of custody

### 9.5 Subject Access Requests

Be prepared to fulfill a subject access request (SAR) within 30 days. Maintain an auditable log of every artifact collected:

```bash
# Index every file touched during the investigation
find "$CASEDIR" -type f -exec sha256sum {} \; > "$CASEDIR/artifact_hashes.txt"
echo "$(date -u +%FT%TZ)  sha256_indexed" >> "$CASEDIR/chain-of-custody.txt"
```

---

## 10. Automation with Cron + JSON Diff

### 10.1 Weekly Diff Workflow

For ongoing monitoring (e.g., brand impersonation detection), run Maigret weekly and diff against last week's snapshot.

```bash
#!/usr/bin/env bash
# weekly_maigret_diff.sh — run Maigret, diff against last week, alert on new accounts.
set -euo pipefail
TARGET=${1:?usage: $0 <username>}
BASE=~/monitoring/$TARGET
mkdir -p "$BASE"

PREV="$BASE/week_$(date -d '7 days ago' +%Y%m%d).json"
CURR="$BASE/week_$(date +%Y%m%d).json"

# Run this week's scan
maigret "$TARGET" -a \
  --tor-proxy socks5://127.0.0.1:9050 \
  --json ndjson --no-color \
  --output "$CURR" 2>&1 | tee "$BASE/log_$(date +%Y%m%d).txt"

# Normalize to (site, status) tuples
jq -r '[.site_name, .status] | @tsv' "$CURR" | sort -u > "$CURR.tsv"

# Diff vs last week
if [ -f "$PREV.tsv" ]; then
  echo "=== New accounts this week ==="
  join -t $'\t' -a2 -v2 \
    <(sort "$PREV.tsv") \
    <(sort "$CURR.tsv") \
    | awk -F'\t' '$2=="Claimed" {print $1}' \
    | tee "$BASE/new_$(date +%Y%m%d).txt"

  echo "=== Accounts that disappeared ==="
  join -t $'\t' -a2 -v2 \
    <(sort "$CURR.tsv") \
    <(sort "$PREV.tsv") \
    | awk -F'\t' '$2=="Claimed" {print $1}' \
    | tee "$BASE/gone_$(date +%Y%m%d).txt"
fi

# Rotate: keep last 8 weeks only
ls -t "$BASE"/week_*.tsv | tail -n +9 | xargs -r rm
```

### 10.2 Cron Entry

```bash
# Edit crontab
crontab -e

# Add: every Monday at 03:17 UTC (off-peak, off-round-time)
17 3 * * 1 /path/to/weekly_maigret_diff.sh ceo_handle >> /var/log/maigret_monitor.log 2>&1

# For multiple targets, loop:
17 3 * * 1 for u in ceo_handle cto_handle ciso_handle; do /path/to/weekly_maigret_diff.sh "$u"; done
```

### 10.3 Alerting

```bash
# Email alert on new accounts (requires msmtp or sendmail)
NEW_COUNT=$(wc -l < "$BASE/new_$(date +%Y%m%d).txt")
if [ "$NEW_COUNT" -gt 0 ]; then
  mail -s "[Maigret Monitor] $NEW_COUNT new accounts for $TARGET" \
       security-alerts@example.com \
       < "$BASE/new_$(date +%Y%m%d).txt"
fi

# Or push to Slack / Discord via webhook
NEW=$(cat "$BASE/new_$(date +%Y%m%d).txt" | jq -R -s '.')
curl -X POST -H 'Content-Type: application/json' \
  --data "{\"text\":\"*Maigret Monitor:* ${NEW_COUNT} new accounts for \`${TARGET}\`:\n$NEW\"}" \
  https://hooks.slack.com/services/...
```

### 10.4 Annual DB Refresh

Maigret's site database updates continuously. Re-pin annually for reproducibility.

```bash
# Annual: refresh the DB snapshot, archive the old one
YEAR=$(date +%Y)
cp ~/.cache/maigret/data.json ~/engagements/db-snapshots/maigret_${YEAR}.json
sha256sum ~/engagements/db-snapshots/maigret_${YEAR}.json \
  >> ~/engagements/db-snapshots/chain.txt

# Run a self-check to flag broken detection rules
maigret --self-check --no-color 2>&1 | tee ~/engagements/db-snapshots/selfcheck_${YEAR}.log
```

---

## 11. Workshop Exercises

### Exercise 1 — Stand up the pipeline end-to-end against a personal handle

Run the full workflow against your own primary username. This is the safest legal target and surfaces your own exposure.

```bash
CASEDIR=~/engagements/self-audit
mkdir -p "$CASEDIR"/{seed,reports,parsed,verified,final}
echo '{"seed_username":"<your_handle>","authorization_ref":"self-audit"}' \
  > "$CASEDIR/seed/context.json"

# Run all six phases from Section 3
# Confirm: at least 5 claimed accounts, NDJSON parses cleanly
```

### Exercise 2 — Cross-verify one Maigret-only finding

Pick one account that Maigret claims but Sherlock does not. Manually verify it in Tor Browser and record the verdict in `verification_log.tsv`. Confirm whether it is a real account, an SEO stub, or an impersonation.

### Exercise 3 — Build a Maltego graph from one target

Run Section 7.1 and 7.2 against your self-audit data. Import the resulting CSVs into Maltego (free community edition is fine). Confirm the graph renders and that you can pivot from your alias to every confirmed site visually.

### Exercise 4 — Set up weekly monitoring

Install the cron entry from Section 10.2 against your own handle. After two weeks, confirm that the diff produces a sensible `new_<date>.txt` and that you receive an alert (email or Slack) when the count is non-zero.

### Exercise 5 — False positive triage

Run Section 6.2's `fp_triage.py` against a fresh Maigret NDJSON. Confirm that accounts scoring >= 0.5 are flagged, manually verify 5 of them, and record verdicts in `verification_log.tsv`. Confirm the heuristic agrees with manual judgment >= 70% of the time.

---

## 12. Troubleshooting Reference

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| All sites return "Unknown" | Tor not started, or egress IP blocked | `sudo service tor start`, verify `curl --socks5-hostname 127.0.0.1:9050 https://api.ipify.org` |
| NDJSON file is empty | Username had spaces, not quoted | Re-run with `maigret "<name>" --permute` |
| Sherlock JSON missing sites | Old Sherlock version | `pip install --upgrade sherlock-project` |
| WhatsMyName crashes | Python 3.10+ typing issue | Use Python 3.11+ in the venv |
| Maltego CSV import fails | Header row missing or wrong column count | Verify the CSV starts with `entity_type,entity_value,...` |
| Cron job does not fire | PATH missing venv Python | Use absolute `/home/user/venvs/osint/bin/maigret` |
| New cron accounts each week are all stubs | Detection rules broken upstream | Run `maigret --self-check`, pin DB to last known-good snapshot |

---

## 13. Integration with Adjacent Skills

| Adjacent skill | When to chain |
|----------------|---------------|
| `skills/osint` | Pivot discovered emails to breach corpus (h8mail / DeHashed) |
| `skills/social-intelligence` | Mine confirmed Reddit / HN / X accounts for sentiment and leak text |
| `skills/social-engineering` | Convert confirmed bios + interests into targeted phishing pretexts |
| `skills/recon-osint` | Active recon on discovered personal websites (subdomain enumeration, tech fingerprint) |
| `skills/digital-forensics` | EXIF and steganography analysis on extracted avatar images |
| `skills/deep-research` | Synthesize the dossier into a long-form intelligence report |
| `skills/anti-forensics` | Operator-side: secure cleanup of investigation artifacts post-engagement |

---

## 14. References & Resources

- Maigret repo: [github.com/soxoj/maigret](https://github.com/soxoj/maigret)
- Maigret docs: [maigret.readthedocs.io](https://maigret.readthedocs.io)
- Maigret features page: [maigret.readthedocs.io/en/latest/features.html](https://maigret.readthedocs.io/en/latest/features.html)
- Sherlock: [github.com/sherlock-project/sherlock](https://github.com/sherlock-project/sherlock)
- WhatsMyName: [github.com/webbreacher/whatsmyname](https://github.com/webbreacher/whatsmyname)
- Holehe: [github.com/megadose/holehe](https://github.com/megadose/holehe)
- Blackbird: [github.com/p1ngul1n0/blackbird](https://github.com/p1ngul1n0/blackbird)
- Maltego Community: [maltego.com/downloads/](https://www.maltego.com/downloads/)
- Maltego CSV import docs:://docs.maltego.com/support/solutions/articles/15000017635
- Spyse (now part of Censys): [censys.com](https://censys.com)
- Intelligence-X: [intelx.io](https://intelx.io)
- FlareSolverr: [github.com/flaresolverr/flaresolverr](https://github.com/flaresolverr/flaresolverr)
- TRACE Labs (missing persons CTFs): [tracelabs.org](https://tracelabs.org)
- Bellingcat Toolkit: [bellingcat.gitbook.io/toolkit](https://bellingcat.gitbook.io/toolkit)
- OSINT Framework: [osintframework.com](https://osintframework.com)
- GDPR full text: [gdpr-info.eu](https://gdpr-info.eu)
- ICO (UK) OSINT guidance: [ico.org.uk](https://ico.org.uk)

---

## 15. Further Reading

- *We Are Bellingcat* — Mike Lowis, Bellingcat founder's methodology memoir
- *Open Source Intelligence Techniques* — Michael Bazzell (the canonical OSINT reference, updated annually)
- *Hunting Cyber Criminals* — Vinny Troia (practical onion-layer investigation methodology)
- *The Intelligence Cycle* — CIA Center for the Study of Intelligence (foundational doctrine)
- Bellingcat Investigation Guides: [bellingcat.com/category/resources](https://www.bellingcat.com/category/resources/)
- SANS SEC487: Open-Source Intelligence Gathering and Analysis (courseware)

---

**Companion files**: `SKILL.md`, `payloads.md`, `test-cases.md`, `guides/maigret-username-dossier.md`
**Authoritative upstream**: [github.com/soxoj/maigret](https://github.com/soxoj/maigret) | [maigret.readthedocs.io](https://maigret.readthedocs.io)
