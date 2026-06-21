# Maigret Username Dossier — End-to-End Workflow Guide

> Deep-dive companion to `skills/username-profiling/SKILL.md`.
>
> Audience: investigators who already know what Maigret does and want a battle-tested playbook for going from a single leaked handle to a defensible human dossier — without leaking operator identity or shipping false positives to a client.

---

## 1. Why a Workflow, Not Just Commands

Maigret is deceptively easy to run: `maigret <username> --html` produces a dossier in two minutes. The trap is treating that one-shot output as the deliverable. A defensible dossier requires:

1. **Coverage** — did you scan all relevant sites, or just the top 500?
2. **Pivot** — did you follow discovered identities to their next accounts?
3. **Verification** — did you rule out the false positives Maigret is known for?
4. **OPSEC** — did you expose your IP, your client's IP, or correlation patterns to 3,000 sites?
5. **Synthesis** — did you turn a JSON dump into a coherent human story?

This guide walks through all five, in order, with the exact commands and decision points.

---

## 2. Pre-Flight: Scope & Authorization

Before any Maigret invocation, answer these — in writing:

- **Who authorized this?** Penetration testing engagements authorize the target organization's *systems*, not its employees' personal accounts. Confirm scope before running Maigret on named individuals.
- **What's the lawful basis?** GDPR, CCPA, and equivalent regimes treat personal data collection as regulated activity even when the data is public. Have a documented basis (consent, contract, legitimate interest).
- **What's the deliverable?** Internal threat intel? Client report? Personal due diligence? Different deliverables need different verification depth.
- **Where does the data live after?** Encrypt at rest, restrict access, define retention.

If any of these are unclear, stop and resolve before proceeding.

---

## 3. Phase 1 — Seed Collection

Don't run Maigret yet. Collect every known identifier first.

### 3.1 Direct identifiers
- Username (primary handle)
- Suspected real name
- Email fragments (e.g., `j.doe@`)
- Phone fragments
- Avatar image (for reverse image search later)

### 3.2 Context
- Country / region (drives `--tags us` etc.)
- Language (drives keyword selection)
- Tech stack hints (drives `--keywords`)
- Time window (when did this identity appear?)

### 3.3 Variants

People reuse usernames with predictable variations. Build a variant list before running Maigret so you don't have to re-scan later.

```bash
# Use Maigret's --permute to generate variants from a real name
maigret "john doe" --permute --help   # see what variants it generates

# Or hand-curate a variant list
cat <<EOF > seed_variants.txt
johndoe123
johndoe
john.doe
j.doe
jdoe
jdoe_dev
johnd
EOF
```

### 3.4 Decision point

If you have only a single username, proceed to Phase 2. If you have a real name and want permutation coverage, use `--permute` in Phase 2.

---

## 4. Phase 2 — Broad Enumeration

### 4.1 Choose scan depth

| Scenario | Flag | Wall-clock | Use When |
|----------|------|------------|----------|
| Quick triage | (default, top 500) | ~5 min | Just want to know if the handle is widely used |
| Full coverage | `-a` (3,000+) | ~30-60 min | Building a real dossier |
| Niche category | `--tags photo,dating` | ~5-15 min | Only one platform category matters |
| Country focus | `--tags us` | ~15-30 min | Subject is US-based |

**Recommendation**: always run `-a` for a real dossier. The cost is wall-clock; the benefit is finding the one niche forum that cracks the case.

### 4.2 The canonical Phase 2 command

```bash
# Setup
sudo service tor start
curl --socks5-hostname 127.0.0.1:9050 https://api.ipify.org   # verify Tor egress

# Full scan via Tor, with structured + human output
maigret <username> -a \
  --tor-proxy socks5://127.0.0.1:9050 \
  --html \
  --graph \
  --json ndjson \
  --keywords security crypto linux docker python \  # tech-stack hints
  --timeout 30 \
  --max-connections 15 \
  --retries 2
```

### 4.3 Immediate triage on the output

```bash
# How many accounts claimed?
jq -r 'select(.status=="Claimed")' reports/<username>_ndjson.json | wc -l

# Which sites claim the account?
jq -r 'select(.status=="Claimed") | .site_name' reports/<username>_ndjson.json | sort | uniq -c | sort -rn

# What pivot identities were discovered?
jq -r 'select(.status=="Claimed") | .extracted.usernames[]? // empty' \
  reports/<username>_ndjson.json | sort -u > phase2_usernames.txt
jq -r 'select(.status=="Claimed") | .extracted.emails[]? // empty' \
  reports/<username>_ndjson.json | sort -u > phase2_emails.txt
jq -r 'select(.status=="Claimed") | .extracted.phones[]? // empty' \
  reports/<username>_ndjson.json | sort -u > phase2_phones.txt

wc -l phase2_*.txt
```

### 4.4 Decision point

- **If `phase2_usernames.txt` has > 0 new usernames**: proceed to Phase 3 (pivot).
- **If only the original username**: skip to Phase 4 (verification).
- **If `phase2_emails.txt` is non-empty**: queue for breach DB checking (h8mail, DeHashed) outside this skill.

---

## 5. Phase 3 — Recursive Pivot

### 5.1 Why recurse

A single Maigret run finds accounts for one username. But each found account *contains* more identities: a GitHub profile links to a personal site, the personal site links to Twitter, Twitter bio links to Keybase. Following this chain is what turns a username into a real human.

### 5.2 Manual recursion (recommended for control)

```bash
# Limit to top 5 newly discovered usernames to avoid runaway
head -5 phase2_usernames.txt | while read user; do
  echo "=== Pivoting to $user ==="
  maigret "$user" -a \
    --tor-proxy socks5://127.0.0.1:9050 \
    --html \
    --json ndjson \
    --timeout 30 \
    --max-connections 15 \
    --retries 2

  # Extract next layer of discovered usernames
  jq -r 'select(.status=="Claimed") | .extracted.usernames[]? // empty' \
    "reports/${user}_ndjson.json" 2>/dev/null >> phase3_usernames.txt
done

# Deduplicate against visited
sort -u phase3_usernames.txt > phase3_candidates.txt
wc -l phase3_candidates.txt
```

### 5.3 Auto-pivot from a known profile URL

When you have one specific profile URL (e.g., a leaked GitHub), let Maigret parse it:

```bash
maigret --parse https://github.com/<username> --html --graph --tor-proxy socks5://127.0.0.1:9050
```

Maigret extracts every embedded handle/ID and recurses automatically. The `--graph` output visualizes the auto-discovered relationships.

### 5.4 Depth limits

Hard rule: **never recurse deeper than 2 layers without explicit authorization**. By depth 3, you're profiling people who didn't consent to investigation. Cap the workflow:

```bash
# Depth 2: seed → discovered → their discovered (stop)
# Anything at depth 3+ is out of scope unless explicitly added
```

### 5.5 Identity graph synthesis

After all recursion completes, build the unified identity graph:

```bash
# Collect every (username, site) edge discovered
cat reports/*/report_*_ndjson.json 2>/dev/null \
  | jq -r 'select(.status=="Claimed") | "\(.site_username // .site_name)\t\(.site_name)\t\(.url)"' \
  | sort -u > identity_graph.tsv

# Nodes (usernames)
cut -f1 identity_graph.tsv | sort -u > identity_nodes.txt

# Edges (username → site)
cut -f1,2 identity_graph.tsv | sort -u > identity_edges.tsv

wc -l identity_nodes.txt identity_edges.tsv
```

Optional: import into Neo4j for visual graph analysis.

```cypher
// Neo4j import (conceptual)
LOAD CSV WITH HEADERS FROM 'file:///identity_edges.tsv' AS row
FIELDTERMINATOR '\t'
MERGE (u:Username {name: row.username})
MERGE (s:Site {name: row.site})
MERGE (u)-[:HAS_ACCOUNT_ON]->(s);
```

---

## 6. Phase 4 — Cross-Tool Verification

### 6.1 Why verify

Maigret's detection rules go stale as sites change. False positives cluster around:
- Auto-generated SEO stubs
- Archived accounts that still resolve
- Soft-404 pages
- Impersonators with similar usernames

Cross-verification with independent tools eliminates most false positives.

### 6.2 Independent runs

```bash
# Sherlock (300+ sites, independent ruleset)
sherlock <username> --json --output sherlock_<username>.json --timeout 10

# WhatsMyName (different site list, different detection)
whatsmyname -u <username> --format json --output wmn_<username>.json

# Holehe (if email discovered)
[ -s phase2_emails.txt ] && head -1 phase2_emails.txt | xargs holehe > holehe_<username>.txt
```

### 6.3 Diff analysis

```bash
# Sites Maigret claims but Sherlock doesn't — manual verification candidates
jq -r '.site' reports/<username>_ndjson.json | sort -u > maigret_sites.txt
jq -r 'keys[]' sherlock_<username>.json | sort -u > sherlock_sites.txt
comm -23 maigret_sites.txt sherlock_sites.txt > maigret_only.txt

# Manual verification loop
while read site; do
  url=$(jq -r --arg s "$site" 'select(.site==$s and .status=="Claimed") | .url' \
    reports/<username>_ndjson.json | head -1)
  echo "[$site] Verify: $url"
done < maigret_only.txt > verification_queue.txt

cat verification_queue.txt
```

### 6.4 Manual verification protocol

For each URL in `verification_queue.txt`:

1. Open in Tor Browser (don't use your real browser session)
2. Does the page show a real profile, or a stub/404/soft-error?
3. Does the profile bio/avatar match the seed identity?
4. Is the username exact, or a fuzzy/impersonation match?
5. Record verdict: `CONFIRMED` / `IMPERSONATION` / `STUB_FALSE_POSITIVE` / `UNVERIFIABLE`

```bash
# Tracking sheet
cat <<EOF > verification_log.tsv
site	url	verdict	notes
EOF

# Append as you verify
echo -e "dating.com\thttps://...\tSTUB_FALSE_POSITIVE\tAuto-generated stub, no real profile content" >> verification_log.tsv
```

### 6.5 Final confirmed set

After verification, produce the authoritative list:

```bash
# Join NDJSON with verification log
jq -r 'select(.status=="Claimed") | [.site_name, .url] | @tsv' \
  reports/<username>_ndjson.json \
  | join -t $'\t' -1 1 -2 1 \
    <(awk -F'\t' '$3=="CONFIRMED" {print $1"\t"$3"\t"$4}' verification_log.tsv) \
  > confirmed_accounts.tsv
```

(Or just hand-edit a spreadsheet — sometimes manual is faster than the perfect `join`.)

---

## 7. Phase 5 — Dossier Synthesis

### 7.1 Dossier structure

```markdown
# Dossier: <seed_username>

## Preamble
- Investigator: <you>
- Authorization reference: <engagement-id>
- Date range: <start> to <end>
- Tools used: Maigret v<version>, Sherlock, WhatsMyName, Holehe
- Verification status: N of M claimed accounts manually verified

## Identity Summary
- Suspected real name: <name> (confidence: HIGH/MEDIUM/LOW)
- Suspected location: <city, country> (confidence: ...)
- Languages: <list>
- Timezone (inferred from activity): <tz>
- Tech stack signals: <keywords found in bios/posts>

## Confirmed Accounts
| Platform | URL | Bio Excerpt | First Activity | Confidence |
|----------|-----|-------------|----------------|------------|
| GitHub | ... | "Backend @ Acme" | 2019-03 | HIGH |
| Twitter/X | ... | "thoughts my own" | 2018-07 | HIGH |
| Reddit (u/jdoe_dev) | ... | "rust evangelist" | 2020-11 | MEDIUM (avatar differs) |
| ... | ... | ... | ... | ... |

## Discovered Pivot Identities
- Emails: j.doe@example.com (3 platforms), j.doe@protonmail.com (1 platform)
- Alt usernames: jdoe_dev, j_d_backend
- Phone: +1-415-XXX-XXXX (Discord bio)

## Inconsistencies & Anomalies
- Twitter bio claims "London" but GitHub commits are PST timezone → possible relocation or deception
- Reddit avatar differs from all other platforms → possible impersonation or alternate persona
- Discord phone number is unformatted → may be a voip/burner

## Recommended Follow-Up
- Run h8mail against j.doe@example.com for breach data
- Cross-check jdoe_dev on Reddit via social-intelligence skill (sentiment, leaks)
- Reverse image search the GitHub avatar (Yandex, Google Images)
- Verify timezone inconsistency via GitHub commit timestamps vs Twitter post times

## Limitations
- Maigret's site list may not include private/invite-only platforms
- Tor egress was used; some sites may have blocked Tor exits
- Verification depth: 1 hour per platform manual review; deeper review available on request

## Source Artifacts
- reports/<username>/report_<username>.html — Maigret HTML dossier
- reports/<username>/graph_<username>.html — identity graph
- reports/<username>_ndjson.json — machine-readable
- sherlock_<username>.json — cross-verification
- verification_log.tsv — manual verification record
```

### 7.2 AI-assisted drafting (optional)

For the Executive Summary section, Maigret's `--ai` flag produces a starting draft:

```bash
export OPENAI_API_KEY=sk-...
maigret <username> -a --ai --ai-model gpt-4o-mini

# Output includes: likely real name, location, occupation, interests,
# languages, overall confidence, follow-up leads
# Use as a starting point — verify each claim before publishing
```

**Rule**: AI output is a draft, never a final. Every claim must trace to a verified source.

---

## Cross-Platform Identity Graph Construction

The dossier stops being a list and becomes a graph once you have data from 200+ sites. A graph model is what lets you find the *bridges* — the single accounts that connect otherwise-disjoint communities (work identity, hobby identity, dating identity, political identity). Those bridges are where investigations win or lose.

### Why a Graph?

A flat table of "site, username, bio" hides structure. The questions that matter are relational:

- Which usernames appear on more than one platform? (corroborated identity)
- Which platforms share an avatar? (cross-platform reuse)
- Which bios link to a common personal site? (a hub)
- Which timezone overlaps appear across commit timestamps and post times?

These are graph queries. Answering them on a TSV is painful; answering them in Neo4j is a one-liner.

### Data Model

A minimal Cypher-friendly model:

```
(:Username {handle, first_seen, last_seen})
(:Site {name, url, category})
(:Email {address})
(:Phone {number})
(:Avatar {url, hash})
(:Person {real_name, country, languages})

(:Username)-[:HAS_ACCOUNT_ON {bio, confidence, first_seen}]->(:Site)
(:Username)-[:USES_EMAIL]->(:Email)
(:Username)-[:USES_PHONE]->(:Phone)
(:Username)-[:HAS_AVATAR]->(:Avatar)
(:Person)-[:KNOWN_AS]->(:Username)
(:Avatar)-[:SAME_IMAGE_AS]->(:Avatar)   // computed via reverse image search
```

### Import Pipeline

```bash
# Emit CSVs that Neo4j's LOAD CSV can ingest
python3 - <<'PY'
import csv, json
from pathlib import Path

CASEDIR = Path.home() / "engagements/case-001"
reports = list((CASEDIR/"reports").glob("*_ndjson.json"))

# Nodes
usernames, sites, emails, phones, avatars = set(), set(), set(), set(), set()
# Edges
account_edges, email_edges, phone_edges, avatar_edges = [], [], [], []

for f in reports:
    for line in f.read_text().splitlines():
        if not line.strip(): continue
        try: rec = json.loads(line)
        except json.JSONDecodeError: continue
        if rec.get("status") != "Claimed": continue
        site = rec.get("site_name","")
        url  = rec.get("url","")
        user = rec.get("site_username") or ""
        if user: usernames.add(user)
        if site: sites.add((site, url))
        ext = rec.get("extracted", {}) or {}
        bio = ext.get("bio") or ""
        account_edges.append((user, site, bio))
        for e in ext.get("emails", []) or []:
            emails.add(e); email_edges.append((user, e))
        for p in ext.get("phones", []) or []:
            phones.add(p); phone_edges.append((user, p))
        for a in ext.get("images", []) or []:
            avatars.add(a); avatar_edges.append((user, a))

out = CASEDIR / "parsed" / "graph"
out.mkdir(parents=True, exist_ok=True)

with (out/"usernodes.csv").open("w", newline="") as f:
    w = csv.writer(f); w.writerow(["handle"])
    for u in sorted(usernames): w.writerow([u])

with (out/"sitenodes.csv").open("w", newline="") as f:
    w = csv.writer(f); w.writerow(["name","url"])
    for s,u in sorted(sites): w.writerow([s,u])

for fname, header, rows in [
    ("emailnodes.csv", ["address"], [(e,) for e in sorted(emails)]),
    ("phonenodes.csv", ["number"],  [(p,) for p in sorted(phones)]),
    ("avatarnodes.csv",["url"],     [(a,) for a in sorted(avatars)]),
    ("account_edges.csv", ["username","site","bio"], account_edges),
    ("email_edges.csv",   ["username","address"],    email_edges),
    ("phone_edges.csv",   ["username","number"],     phone_edges),
    ("avatar_edges.csv",  ["username","url"],        avatar_edges),
]:
    with (out/fname).open("w", newline="") as f:
        w = csv.writer(f); w.writerow(header); w.writerows(rows)

print(f"Emitted graph CSVs in {out}")
PY
```

### Neo4j Load Script

```cypher
// nodes
LOAD CSV WITH HEADERS FROM 'file:///usernodes.csv' AS row
MERGE (u:Username {handle: row.handle});

LOAD CSV WITH HEADERS FROM 'file:///sitenodes.csv' AS row
MERGE (s:Site {name: row.name}) SET s.url = row.url;

LOAD CSV WITH HEADERS FROM 'file:///emailnodes.csv' AS row
MERGE (e:Email {address: row.address});

LOAD CSV WITH HEADERS FROM 'file:///phonenodes.csv' AS row
MERGE (p:Phone {number: row.number});

LOAD CSV WITH HEADERS FROM 'file:///avatarnodes.csv' AS row
MERGE (a:Avatar {url: row.url});

// edges
LOAD CSV WITH HEADERS FROM 'file:///account_edges.csv' AS row
MATCH (u:Username {handle: row.username}), (s:Site {name: row.site})
MERGE (u)-[r:HAS_ACCOUNT_ON]->(s) SET r.bio = row.bio;

LOAD CSV WITH HEADERS FROM 'file:///email_edges.csv' AS row
MATCH (u:Username {handle: row.username}), (e:Email {address: row.address})
MERGE (u)-[:USES_EMAIL]->(e);

LOAD CSV WITH HEADERS FROM 'file:///phone_edges.csv' AS row
MATCH (u:Username {handle: row.username}), (p:Phone {number: row.number})
MERGE (u)-[:USES_PHONE]->(p);

LOAD CSV WITH HEADERS FROM 'file:///avatar_edges.csv' AS row
MATCH (u:Username {handle: row.username}), (a:Avatar {url: row.url})
MERGE (u)-[:HAS_AVATAR]->(a);
```

### High-Value Graph Queries

```cypher
// Find the most connected usernames (identity hubs)
MATCH (u:Username)-[:HAS_ACCOUNT_ON]->(s:Site)
RETURN u.handle, COUNT(s) AS breadth
ORDER BY breadth DESC LIMIT 10;

// Bridge nodes: usernames that share an email with another username
MATCH (u1:Username)-[:USES_EMAIL]->(e:Email)<-[:USES_EMAIL]-(u2:Username)
WHERE u1 <> u2
RETURN u1.handle, u2.handle, e.address
LIMIT 50;

// Avatar reuse across usernames (impersonation or alt-account signal)
MATCH (u1:Username)-[:HAS_AVATAR]->(a:Avatar)<-[:HAS_AVATAR]-(u2:Username)
WHERE u1 <> u2
RETURN u1.handle, u2.handle, a.url;

// Communities via Louvain (if APOC installed)
CALL algo.louvain('Username', 'HAS_ACCOUNT_ON|USES_EMAIL|HAS_AVATAR', {})
YIELD nodes, community, communities
RETURN community, COUNT(*) AS size ORDER BY size DESC LIMIT 5;
```

### Entity Resolution Heuristics

A graph alone does not prove two usernames are the same human. Use these heuristics to merge nodes programmatically:

| Heuristic | Rule | Confidence |
|-----------|------|------------|
| Email match | Two usernames share the same verified email | HIGH |
| Avatar perceptual hash match | Two avatars have pHash distance < 5 | HIGH |
| Bio string similarity | Bio Jaccard >= 0.7 | MEDIUM |
| Same timezone + similar handle | Timezone overlap >= 80%, handle Levenshtein <= 3 | MEDIUM |
| Site cross-link | Site A profile links to site B profile of other username | HIGH |

```python
"""
entity_resolution.py — merge usernames that likely refer to the same human.
"""
import csv, json
from collections import defaultdict
from pathlib import Path

CASEDIR = Path.home() / "engagements/case-001"
graph = CASEDIR / "parsed" / "graph"

# Build clusters keyed by shared email (highest-confidence signal)
clusters: dict[str, set[str]] = defaultdict(set)
edges = list(csv.DictReader((graph/"email_edges.csv").open()))
for row in edges:
    clusters[row["address"]].add(row["username"])

# Union-Find to merge clusters sharing any username
parent = {}
def find(x):
    parent.setdefault(x, x)
    while parent[x] != x:
        parent[x] = parent[parent[x]]
        x = parent[x]
    return x
def union(a, b):
    ra, rb = find(a), find(b)
    if ra != rb: parent[ra] = rb

for members in clusters.values():
    m = list(members)
    for x in m[1:]: union(m[0], x)

resolved: dict[str, set[str]] = defaultdict(set)
for node in parent: resolved[find(node)].add(node)

print(f"Merged {len(parent)} usernames into {len(resolved)} person-clusters")
for cid, members in resolved.items():
    if len(members) > 1:
        print(f"  Cluster: {sorted(members)}")
```

### Pruning the Graph

A 3,000-site sweep produces a noisy graph. Prune before declaring victory:

```cypher
// Drop usernames with only one site (no corroborating signal)
MATCH (u:Username)
WITH u, COUNT { (u)-[:HAS_ACCOUNT_ON]->() } AS deg
WHERE deg < 2
DETACH DELETE u;

// Drop sites where no confirmed account remains
MATCH (s:Site)
WHERE NOT (s)<-[:HAS_ACCOUNT_ON]-()
DELETE s;
```

### Output: Single-Page Identity Map

```bash
# Generate a single-page HTML identity map from the graph
python3 - <<'PY'
import csv, html
from pathlib import Path

graph = Path.home() / "engagements/case-001/parsed/graph"
edges = list(csv.DictReader((graph/"account_edges.csv").open()))

# Group by username
from collections import defaultdict
by_user = defaultdict(list)
for e in edges:
    by_user[e["username"]].append((e["site"], e.get("bio","")))

out = ["<!doctype html><html><head><meta charset='utf-8'>",
       "<title>Identity Map</title>",
       "<style>body{font-family:system-ui;margin:2rem}"
       "h2{border-bottom:1px solid #ccc}ul{line-height:1.6}</style></head><body>"]

for user, sites in sorted(by_user.items(), key=lambda kv: -len(kv[1])):
    out.append(f"<h2>{html.escape(user)} ({len(sites)} sites)</h2><ul>")
    for site, bio in sorted(sites):
        out.append(f"<li><b>{html.escape(site)}</b> — <i>{html.escape(bio[:200])}</i></li>")
    out.append("</ul>")
out.append("</body></html>")

Path("identity_map.html").write_text("".join(out))
print("Wrote identity_map.html")
PY
```

---

## Operational Security for Investigators

An investigator who gets owned while investigating compromises the engagement, the client, and every future subject whose data touches the same machine. The OPSEC rules below are non-negotiable for any sensitive investigation.

### Why OPSEC for Investigators?

Every Maigret invocation sends your IP to 3,000+ sites. Several of those sites are themselves operated by adversaries — scammers, organized crime, nation-state personas — who log every visitor. A serious investigation requires treating your own infrastructure as a target and hardening it accordingly.

### VM Isolation

Run every investigation from a dedicated, disposable VM. Never from your daily-driver host.

```bash
# libvirt / qemu baseline
virt-install \
  --name osint-vm \
  --ram 8192 \
  --vcpus 4 \
  --disk size=50,path=/var/lib/libvirt/images/osint-vm.qcow2 \
  --os-variant kali2023.2 \
  --network network=default \
  --graphics spice \
  --cdrom /srv/iso/kali-linux-2025-2-installer-arm64.iso

# Inside the VM: full-disk encryption, separate user account, no shared folders
# Inside the VM: install only OSINT tooling, nothing else
```

Snapshot discipline:

```bash
# Before each engagement, snapshot the clean state
virsh snapshot-create-as --domain osint-vm clean-base

# After the engagement, revert and discard
virsh snapshot-revert --domain osint-vm clean-base
virsh snapshot-delete --domain osint-vm snapshot-$(date +%Y%m%d)
```

### Proxy Chaining

Layered proxies give you failover and rotate the egress IP seen by targets.

```bash
# Chain: local -> Tor -> residential rotating proxy -> target
# Configure Tor to use a bridge + pluggable transport (obfs4) first

# Install obfs4proxy
sudo apt install obfs4proxy

# Edit /etc/tor/torrc to use a bridge
sudo tee -a /etc/tor/torrc <<'EOF'
UseBridges 1
Bridge obfs4 IP:PORT CERT=... iat-mode=0
ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy
EOF
sudo service tor restart

# Then chain to a residential proxy
maigret <username> -a \
  --proxy http://user:pass@residential-rotating.example.com:8080 \
  --tor-proxy socks5://127.0.0.1:9050 \
  --timeout 45 \
  --max-connections 5
```

For maximum isolation, run each engagement through a different residential proxy:

```bash
# Engagement A: proxy provider X, US exits
export HTTPS_PROXY=http://userA:passA@providerX.example.com:8080

# Engagement B: proxy provider Y, EU exits
export HTTPS_PROXY=http://userB:passB@providerY.example.com:8080

# Never reuse the same egress across unrelated targets
```

### Sock Puppet Account Lifecycle

Browser-based verification often requires accounts on the target platforms. Sock puppets must be built, aged, and burned on a disciplined schedule.

```bash
# Phase 1: creation (use a dedicated VM + dedicated proxy per puppet)
#   - Realistic persona: photo (AI-generated is fine), bio, posting history
#   - Creation from residential IP only — datacenter IPs trigger anti-abuse
#   - Each puppet tied to a unique email + unique phone (Google Voice, MySudo)

# Phase 2: aging (3-6 months minimum before sensitive use)
#   - Routine login from the same residential IP
#   - Routine benign activity: likes, follows, low-stakes posts
#   - Build friends / followers organically

# Phase 3: active use (the investigation window)
#   - Limited, scoped actions only
#   - Never contact the target directly from a puppet
#   - Never log in from an IP that touches another puppet

# Phase 4: burn (after engagement closes)
#   - Cease all activity
#   - Optionally delete the account
#   - Record the burn date in chain of custody

# Track every puppet in a local encrypted store
echo "$(date -u +%FT%TZ)  puppet=alice_dev_2026  platform=github  purpose=verification  status=active" \
  >> ~/.local/share/osint/puppets.tsv
gpg --symmetric --cipher-algo AES256 ~/.local/share/osint/puppets.tsv
```

### Browser Fingerprint Randomization

Every browser exposes a fingerprint (canvas, fonts, WebGL, screen size). A consistent fingerprint across puppets links them. Randomize.

```bash
# Use a fingerprint-spoofing browser: Mullvad Browser, LibreWolf with resistFingerprinting
sudo apt install mullvad-browser

# Or configure Firefox manually
# In about:config:
#   privacy.resistFingerprinting = true
#   privacy.spoof_english = 2
#   webgl.disabled = true

# Per-puppet profile, with isolated container
firefox --no-remote -P puppet-alice --new-instance about:config &

# Rotate user-agent per session (within believable bounds)
# Use a browser extension: "User-Agent Switcher and Manager"
# Or, for curl-based checks:
UA_LIST=("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
         "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15")
UA=${UA_LIST[$RANDOM % ${#UA_LIST[@]}]}
curl -A "$UA" https://example.com/profile/johndoe123
```

### OPSEC Verification Protocol

Before each engagement, verify your OPSEC stack holds.

```bash
# 1. Verify Tor egress
sudo service tor start
curl --socks5-hostname 127.0.0.1:9050 https://api.ipify.org
# Compare against:
curl -s https://api.ipify.org
# Should NOT match

# 2. Verify no DNS leak
curl --socks5-hostname 127.0.0.1:9050 https://dnsleaktest.com/check\?nodetect=1 | jq

# 3. Verify browser fingerprint uniqueness (visit from VM)
# Open https://coveryourtracks.eff.org in the puppet browser
# Record fingerprint uniqueness; aim for "Your browser has a unique fingerprint"

# 4. Verify VM isolation (no host filesystem leakage)
# Confirm no shared folders mounted
sudo findmnt | grep -E 'fuse.vmhgfs|virtiofs|9p'
# Should return nothing

# 5. Verify chain of custody started
[ -f ~/engagements/case-001/chain-of-custody.txt ] \
  && head ~/engagements/case-001/chain-of-custody.txt
```

### Operator Hygiene

- **Time gaps between unrelated targets.** Investigating Target A on Monday and Target B on Tuesday from the same Tor exit creates an observable pattern. Wait a week.
- **No cross-puppet logins.** A single login from Puppet A's session to Puppet B's account links them permanently.
- **No investigation artifacts on the host.** All work stays in the disposable VM. Reports ship out only through an encrypted channel, then the VM is reverted.
- **No social media activity about the work.** Do not tweet "interesting investigation today" — it narrows the candidate set for anyone monitoring.
- **Mental OPSEC.** Stress and fatigue lead to mistakes. Set a hard stop after 4 hours of investigation work; review all actions the next morning with fresh eyes.

### Pre-Engagement OPSEC Checklist

- [ ] Dedicated VM created from a clean snapshot
- [ ] VM has no shared folders with host
- [ ] Tor daemon running and verified
- [ ] DNS leak test passes
- [ ] Residential proxy credentials valid and tested
- [ ] Sock puppet accounts aged and ready (one per platform to be visited)
- [ ] Browser fingerprint randomized (resistFingerprinting, canvas spoofing)
- [ ] Chain-of-custody file initialized with engagement ID, date, lawful basis
- [ ] Encryption-at-rest keys generated and stored separately from data
- [ ] Destruction date set in calendar (90 days default)

---

## 8. OPSEC Hardening

### 8.1 Egress

```bash
# 1. Always Tor
sudo service tor start
maigret <username> --tor-proxy socks5://127.0.0.1:9050

# 2. Verify before every run
curl --socks5-hostname 127.0.0.1:9050 https://api.ipify.org
# Should NOT match your real IP, your VPN IP, or your client's IP

# 3. For parallel multi-username investigations, use different circuits
# (Tor's stream isolation: configure via torrc SocksPolicy / IsolateDestPort)
```

### 8.2 Rate & concurrency

```bash
# Default is aggressive. Dial back for sensitivity:
maigret <username> -a --max-connections 5 --timeout 30 --retries 2

# Add jitter if available
# (Maigret doesn't natively support request jitter, but lower concurrency helps)
```

### 8.3 Reports hygiene

```bash
# Encrypt at rest
gpg --symmetric --cipher-algo AES256 reports/<username>_dossier.pdf
gpg --symmetric --cipher-algo AES256 reports/<username>_ndjson.json

# Restrict permissions
chmod 600 reports/<username>/*

# Shred on engagement close
shred -uvz reports/<username>/*
rm -rf reports/<username>/

# Confirm
ls reports/ | grep <username>   # should be empty
```

### 8.4 Operator correlation

If you investigate Username A today and Username B tomorrow from the same Tor exit, a sophisticated observer can correlate them. Mitigations:
- Use stream isolation in Tor config
- Use different proxy providers across engagements
- Time-gap investigations of related targets

---

## 9. Common Failure Modes

### 9.1 "Maigret found 200 accounts and they're all real"

**Probably wrong**. Auto-generated stubs and archived accounts inflate counts. Run TC-UP-010 cross-verification.

### 9.2 "Tor egress is blocked on every site"

Switch to a residential proxy:
```bash
maigret <username> --proxy http://user:pass@residential-proxy.example.com:8080
```
Or use FlareSolverr for Cloudflare-protected sites (TC-UP-009).

### 9.3 "Maigret found the username on a niche forum I've never heard of"

Don't dismiss — niche forums are where people post differently than on mainstream platforms. But also don't assume. Open in Tor Browser, verify the account is real, then decide.

### 9.4 "The graph is too dense to read"

You've pivoted too deep. Roll back to depth 2 and prune nodes that don't connect to a verified identity marker (email, real name, phone).

### 9.5 "AI summary contradicts my manual findings"

The AI is working from the same NDJSON you are, but with weaker verification. Trust the manual findings, update the AI's claims with corrected evidence.

---

## 10. Workflow Checklist

Before declaring the dossier complete:

- [ ] Authorization scope documented and matches deliverable
- [ ] Tor egress verified (real IP never appears in any test)
- [ ] Full `-a` scan completed for primary username
- [ ] Recursive pivot to depth ≤ 2 executed
- [ ] Cross-verification with Sherlock + WhatsMyName completed
- [ ] Manual verification of all "Maigret-only" claimed accounts
- [ ] Identity graph deduplicated and pruned
- [ ] Dossier synthesized with confidence ratings per claim
- [ ] Anomalies and inconsistencies explicitly called out
- [ ] Follow-up actions specified (not just findings)
- [ ] Reports encrypted at rest
- [ ] Retention/destruction date set

---

## 11. Integration with Other Skills

| Adjacent Skill | When to Chain |
|----------------|---------------|
| `skills/osint` | Email breach checking (h8mail) on discovered emails; domain recon on discovered personal sites |
| `skills/social-intelligence` | Sentiment / leak mining on confirmed Reddit/HN/X accounts |
| `skills/social-engineering` | Crafting phishing pretexts from confirmed bios and interests |
| `skills/deep-research` | Synthesizing the dossier into a longer-form intelligence report |
| `skills/recon-osint` | Active recon on discovered personal websites |
| `skills/digital-forensics` | If avatar images are extracted, run EXIF / steganography analysis |

---

## 12. References

- Maigret repo: [github.com/soxoj/maigret](https://github.com/soxoj/maigret)
- Maigret docs: [maigret.readthedocs.io](https://maigret.readthedocs.io)
- Maigret features page: [maigret.readthedocs.io/en/latest/features.html](https://maigret.readthedocs.io/en/latest/features.html)
- Sherlock: [github.com/sherlock-project/sherlock](https://github.com/sherlock-project/sherlock)
- WhatsMyName: [github.com/webbreacher/whatsmyname](https://github.com/webbreacher/whatsmyname)
- Holehe: [github.com/megadose/holehe](https://github.com/megadose/holehe)
- FlareSolverr: [github.com/flaresolverr/flaresolverr](https://github.com/flaresolverr/flaresolverr)
- TRACE Labs (missing persons CTFs, real-world practice): [tracelabs.org](https://tracelabs.org)
- Bellingcat Toolkit: [bellingcat.gitbook.io/toolkit](https://bellingcat.gitbook.io/toolkit)
- OSINT Framework: [osintframework.com](https://osintframework.com)

---

**Companion files**: `SKILL.md`, `payloads.md`, `test-cases.md`
