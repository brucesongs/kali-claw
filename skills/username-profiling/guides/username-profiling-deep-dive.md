# Cross-Platform Identity Graph Correlation — Deep Dive

> Deep-dive companion to `skills/username-profiling/SKILL.md`.
>
> Audience: senior pentesters and OSINT analysts who already run Maigret, Sherlock, and WhatsMyName and want to fuse their outputs into a single queryable identity graph, resolve entities probabilistically, and produce defensible dossiers that survive cross-examination.
>
> Scope: this guide focuses on **graph-based identity resolution**. It does not re-teach Maigret basics (see `maigret-username-workshop.md`) or the end-to-end dossier workflow (see `maigret-username-dossier.md`). It assumes you can already produce JSON output from each tool.

---

## 1. Introduction & Objective

Username enumeration tools disagree. Maigret finds 47 accounts for a handle, Sherlock finds 38, WhatsMyName finds 61 — and the overlap is rarely clean. Some sites are checked by only one tool. Some return false positives. Some accounts belong to different people who happened to pick the same handle. The raw JSON from each tool is a list, not a picture.

This guide teaches you to:

1. **Normalize** outputs from Maigret, Sherlock, WhatsMyName, Blackbird, and Holehe into a single schema.
2. **Load** the normalized records into a graph database (Neo4j) where identity is a first-class concept.
3. **Resolve** entities probabilistically — decide which accounts belong to the same human, even when display names, bios, or avatars differ.
4. **Filter** false positives using confidence scoring and cross-evidence rules.
5. **Pivot** from resolved identities into breach data, email providers, and adjacent handles via graph traversal.
6. **Export** the resolved graph as a defensible dossier artifact.

The objective is not "more accounts found" — it is "higher-confidence attribution with auditable reasoning".

### Why a graph, not a spreadsheet?

A spreadsheet forces one row per account. A graph lets you ask questions a spreadsheet cannot answer:

- "Show me every account that shares an avatar image hash with the seed handle."
- "Show me every email that has ever appeared alongside any variant of this username in breach data."
- "Show me the shortest path between this handle and a known real-name identity."
- "Which accounts were created within 48 hours of each other?"

These are graph traversal queries. Doing them by hand across 200+ accounts is infeasible. Doing them in Cypher (Neo4j's query language) takes milliseconds.

---

## 2. Prerequisites & Environment

### 2.1 Tool stack

| Layer | Tool | Purpose |
|-------|------|---------|
| Enumeration | Maigret, Sherlock, WhatsMyName, Blackbird | Discover candidate accounts |
| Email pivot | Holehe | Reverse email → registered services |
| Breach data | HIBP, DeHashed, IntelX (API clients) | Correlate handles to breach records |
| Normalization | Python 3.11+, `jq`, `pandas` | Reshape tool outputs |
| Graph store | Neo4j 5.x (Community) | Store and query the identity graph |
| Avatar hashing | `pdqhash`, `ImageHash` | Perceptual avatar fingerprints |
| Visualization | Neo4j Browser, `pyvis`, Gephi | Inspect and report |

### 2.2 Isolated environment

Run the pipeline in a dedicated workspace. Do not contaminate it with unrelated cases.

```bash
# Create isolated case directory
CASE_ID="case-2026-06-21-acme-foe"
mkdir -p ~/cases/$CASE_ID/{raw,normalized,graph,reports,avatars,logs}
cd ~/cases/$CASE_ID

# Pin Python dependencies
cat <<EOF > requirements.txt
neo4j==5.26.0
pandas==2.2.3
pdqhash==0.3.2
imagehash==4.3.1
python-dateutil==2.9.0
httpx==0.27.2
EOF

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2.3 Neo4j setup

Use Docker for reproducibility. Pin the version.

```bash
# Launch Neo4j with persistent volume
docker run -d --name neo4j-identity \
  -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/REPLACE_WITH_YOUR NEO4J_PASSWORD \
  -e NEO4J_PLUGINS='["apoc"]' \
  -v $(pwd)/neo4j/data:/data \
  -v $(pwd)/neo4j/logs:/logs \
  neo4j:5.26.0

# Wait for it to be ready
until curl -sf http://localhost:7474 >/dev/null 2>&1; do sleep 2; done
echo "Neo4j ready"

# Test connection
python3 -c "
from neo4j import GraphDatabase
d = GraphDatabase.driver('bolt://localhost:7687', auth=('neo4j', 'REPLACE_WITH_YOUR_NEO4J_PASSWORD'))
with d.session() as s:
    print(s.run('RETURN 1 AS ok').single()['ok'])
"
```

### 2.4 OPSEC reminders

- All enumeration traffic must route through your investigator proxy chain (see Section 11).
- Breach API calls must use a burner API account, never a personal one.
- Case directories must be encrypted at rest (`fscrypt` or `gocryptfs`).
- Do not load real breach data into a shared Neo4j instance — use per-case containers.

---

## 3. Tool Output Schemas

Each tool emits a different JSON shape. You cannot merge them as-is. Below are the schemas you must normalize from.

### 3.1 Maigret JSON

Maigret emits one JSON file per username. Top-level structure:

```json
{
  "username": "johndoe123",
  "sites": {
    "GitHub": {
      "url": "https://github.com/johndoe123",
      "status": "found",
      "tags": ["coding", "tech"],
      "extracted": {
        "name": "John Doe",
        "bio": "Backend engineer @ Acme",
        "location": "Berlin, DE",
        "image": "https://avatars.githubusercontent.com/u/12345",
        "links": ["https://twitter.com/johndoe123"]
      }
    }
  }
}
```

Key fields: `username`, `sites.<site>.status`, `sites.<site>.extracted.*`.

### 3.2 Sherlock JSON

Sherlock emits a flat JSON (or CSV) with one entry per site:

```json
{
  "results": {
    "GitHub": {
      "url": "https://github.com/johndoe123",
      "status": "claimed",
      "http_status": 200,
      "response_time_s": 0.42
    },
    "Twitter": {
      "url": "https://twitter.com/johndoe123",
      "status": "claimed",
      "http_status": 200
    }
  }
}
```

Key fields: `results.<site>.status` (values: `claimed`, `available`, `unknown`).

### 3.3 WhatsMyName JSON

WhatsMyName emits per-site entries with raw HTTP metadata:

```json
{
  "target": "johndoe123",
  "sites": [
    {
      "name": "GitHub",
      "uri": "https://github.com/johndoe123",
      "cat": "coding",
      "status": "found",
      "http_status": 200,
      "raw": "<!DOCTYPE html>..."
    }
  ]
}
```

Key fields: `sites[].name`, `sites[].status`, `sites[].cat`, `sites[].http_status`.

### 3.4 Blackbird JSON

Blackbird emits a nested object per site:

```json
{
  "username": "johndoe123",
  "sites": {
    "GitHub": {
      "found": true,
      "url": "https://github.com/johndoe123",
      "response": {
        "status_code": 200,
        "title": "johndoe123 (John Doe) · GitHub"
      }
    }
  }
}
```

### 3.5 Holehe JSON

Holehe reverses email → registered services. Output is a list:

```json
{
  "email": "j.doe@example.com",
  "services": [
    {"service": "github", "exists": true},
    {"service": "spotify", "exists": true},
    {"service": "twitter", "exists": false}
  ]
}
```

### 3.6 Schema unification target

You will normalize every record to this shape:

```python
@dataclass(frozen=True)
class AccountRecord:
    record_id: str            # "<tool>:<site>:<handle>"
    tool: str                 # maigret | sherlock | whatsmyname | blackbird | holehe
    site: str                 # canonical site name (see Section 4.2)
    site_category: str        # coding | social | gaming | ...
    handle: str               # the username on this site
    url: str
    http_status: int
    found: bool               # unified boolean
    display_name: str | None
    bio: str | None
    location: str | None
    avatar_url: str | None
    avatar_phash: str | None  # perceptual hash, populated later
    external_links: tuple[str, ...]
    discovered_at: str        # ISO 8601
    confidence: float         # 0.0–1.0, assigned by normalizer
```

---

## 4. Normalization Layer

### 4.1 Site name canonicalization

The single biggest source of merge failures is inconsistent site naming. Maigret says `"GitHub"`, Sherlock says `"GitHub"`, WhatsMyName says `"GitHub"` — until one day WhatsMyName renames it `"github.com"` and your join silently breaks.

Build a canonical site dictionary:

```python
# canonical_sites.py
SITE_ALIASES = {
    "github": "GitHub",
    "github.com": "GitHub",
    "GitHub": "GitHub",
    "twitter": "Twitter",
    "X": "Twitter",
    "x.com": "Twitter",
    "instagram": "Instagram",
    "insta": "Instagram",
    # ... extend as you encounter variants
}

def canonical_site(raw: str) -> str:
    key = raw.strip().lower().removeprefix("https://").removeprefix("www.").split("/")[0]
    return SITE_ALIASES.get(key, raw)
```

### 4.2 Unified status mapping

```python
STATUS_FOUND = {"found", "claimed", True, "yes"}
STATUS_UNKNOWN = {"unknown", "unverified", None}
STATUS_NOT_FOUND = {"available", "notfound", "not found", False}

def unify_status(raw) -> tuple[bool, float]:
    """Return (found_bool, confidence_0_to_1)."""
    if raw in STATUS_FOUND:
        return True, 0.95
    if raw in STATUS_NOT_FOUND:
        return False, 0.95
    return False, 0.2
```

Confidence is not 1.0 even for `found` because Maigret's heuristic detection can misfire on sites that return 200 for any username (see Section 7 on false-positive filtering).

### 4.3 Per-tool parsers

Each parser reads its tool's raw output and emits `AccountRecord` instances.

```python
# parsers.py
import json
from datetime import datetime, timezone
from dataclasses import asdict
from canonical_sites import canonical_site
from models import AccountRecord
from status import unify_status

def parse_maigret(path: str, handle: str) -> list[AccountRecord]:
    with open(path) as f:
        data = json.load(f)
    now = datetime.now(timezone.utc).isoformat()
    out = []
    for site_raw, info in data.get("sites", {}).items():
        site = canonical_site(site_raw)
        found, conf = unify_status(info.get("status"))
        ext = info.get("extracted") or {}
        out.append(AccountRecord(
            record_id=f"maigret:{site}:{handle}",
            tool="maigret",
            site=site,
            site_category=(info.get("tags") or ["unknown"])[0],
            handle=handle,
            url=info.get("url", ""),
            http_status=info.get("http_status", 0),
            found=found,
            display_name=ext.get("name"),
            bio=ext.get("bio"),
            location=ext.get("location"),
            avatar_url=ext.get("image"),
            avatar_phash=None,
            external_links=tuple(ext.get("links") or ()),
            discovered_at=now,
            confidence=conf,
        ))
    return out

def parse_sherlock(path: str, handle: str) -> list[AccountRecord]:
    with open(path) as f:
        data = json.load(f)
    now = datetime.now(timezone.utc).isoformat()
    out = []
    for site_raw, info in data.get("results", {}).items():
        site = canonical_site(site_raw)
        found, conf = unify_status(info.get("status"))
        out.append(AccountRecord(
            record_id=f"sherlock:{site}:{handle}",
            tool="sherlock",
            site=site,
            site_category="unknown",
            handle=handle,
            url=info.get("url", ""),
            http_status=info.get("http_status", 0),
            found=found,
            display_name=None,
            bio=None,
            location=None,
            avatar_url=None,
            avatar_phash=None,
            external_links=(),
            discovered_at=now,
            confidence=conf,
        ))
    return out

def parse_whatsmyname(path: str, handle: str) -> list[AccountRecord]:
    with open(path) as f:
        data = json.load(f)
    now = datetime.now(timezone.utc).isoformat()
    out = []
    for entry in data.get("sites", []):
        site = canonical_site(entry.get("name", ""))
        found, conf = unify_status(entry.get("status"))
        out.append(AccountRecord(
            record_id=f"whatsmyname:{site}:{handle}",
            tool="whatsmyname",
            site=site,
            site_category=entry.get("cat", "unknown"),
            handle=handle,
            url=entry.get("uri", ""),
            http_status=entry.get("http_status", 0),
            found=found,
            display_name=None,
            bio=None,
            location=None,
            avatar_url=None,
            avatar_phash=None,
            external_links=(),
            discovered_at=now,
            confidence=conf,
        ))
    return out
```

### 4.4 Driver

```python
# normalize.py
import json
from pathlib import Path
from dataclasses import asdict
from parsers import parse_maigret, parse_sherlock, parse_whatsmyname

HANDLE = "REPLACE_WITH_TARGET_HANDLE"
RAW_DIR = Path("raw")
NORM_DIR = Path("normalized")
NORM_DIR.mkdir(exist_ok=True)

runs = [
    (RAW_DIR / "maigret.json", parse_maigret),
    (RAW_DIR / "sherlock.json", parse_sherlock),
    (RAW_DIR / "whatsmyname.json", parse_whatsmyname),
]

all_records = []
for path, parser in runs:
    if path.exists():
        all_records.extend(parser(str(path), HANDLE))

out_path = NORM_DIR / "accounts.jsonl"
with out_path.open("w") as f:
    for r in all_records:
        f.write(json.dumps(asdict(r)) + "\n")

print(f"Wrote {len(all_records)} records to {out_path}")
```

Run:

```bash
python3 normalize.py
# → Wrote 167 records to normalized/accounts.jsonl
```

---

## 5. Graph Model

### 5.1 Nodes and relationships

Use four node labels and five relationship types.

**Nodes:**

| Label | Properties | Description |
|-------|------------|-------------|
| `:Handle` | `id`, `value`, `variant_of` | A username string, possibly a variant of another |
| `:Account` | `url`, `site`, `category`, `http_status`, `found_at`, `display_name`, `bio`, `location`, `avatar_url`, `avatar_phash`, `confidence` | A specific account on a specific site |
| `:Site` | `name`, `category` | The platform (GitHub, Twitter, ...) |
| `:Email` | `address`, `domain`, `first_seen` | An email address observed in any source |
| `:BreachRecord` | `source`, `year`, `password_hash`, `password_plain` | A single breach row |

**Relationships:**

| Type | From → To | Properties |
|------|-----------|------------|
| `:ON_SITE` | `:Account` → `:Site` | — |
| `:HAS_HANDLE` | `:Account` → `:Handle` | — |
| `:VARIANT_OF` | `:Handle` → `:Handle` | `edit_distance`, `method` |
| `:LINKS_TO` | `:Account` → `:Account` | `source_field` (bio, link, etc.) |
| `:SHARES_AVATAR` | `:Account` → `:Account` | `phash`, `hamming_distance` |
| `:EMAIL_SEEN_AT` | `:Email` → `:Account` | `source` (breach, bio, holehe) |
| `:IN_BREACH` | `:BreachRecord` → `:Email` | — |

### 5.2 Constraints and indexes

Define these before loading any data:

```cypher
CREATE CONSTRAINT handle_id IF NOT EXISTS
FOR (h:Handle) REQUIRE h.id IS UNIQUE;

CREATE CONSTRAINT account_id IF NOT EXISTS
FOR (a:Account) REQUIRE a.url IS UNIQUE;

CREATE CONSTRAINT site_name IF NOT EXISTS
FOR (s:Site) REQUIRE s.name IS UNIQUE;

CREATE CONSTRAINT email_addr IF NOT EXISTS
FOR (e:Email) REQUIRE e.address IS UNIQUE;

CREATE INDEX account_phash IF NOT EXISTS
FOR (a:Account) ON (a.avatar_phash);

CREATE INDEX account_site IF NOT EXISTS
FOR (a:Account) ON (a.site);
```

---

## 6. Loading the Graph

### 6.1 Bulk loader

```python
# load_graph.py
import json
from pathlib import Path
from neo4j import GraphDatabase

DRIVER = GraphDatabase.driver(
    "bolt://localhost:7687",
    auth=("neo4j", "REPLACE_WITH_YOUR_NEO4J_PASSWORD"),
)

ACCOUNTS_JSONL = Path("normalized/accounts.jsonl")

def load_accounts(tx, batch):
    tx.run("""
    UNWIND $rows AS row
    MERGE (h:Handle {id: row.handle})
    MERGE (s:Site {name: row.site})
    SET s.category = row.site_category
    MERGE (a:Account {url: row.url})
    SET a.site = row.site,
        a.category = row.site_category,
        a.http_status = row.http_status,
        a.found = row.found,
        a.display_name = row.display_name,
        a.bio = row.bio,
        a.location = row.location,
        a.avatar_url = row.avatar_url,
        a.discovered_at = row.discovered_at,
        a.confidence = row.confidence,
        a.tool = row.tool
    MERGE (a)-[:ON_SITE]->(s)
    MERGE (a)-[:HAS_HANDLE]->(h)
    """, rows=batch)

def stream_jsonl(path, batch_size=200):
    batch = []
    with path.open() as f:
        for line in f:
            batch.append(json.loads(line))
            if len(batch) >= batch_size:
                yield batch
                batch = []
    if batch:
        yield batch

with DRIVER.session() as s:
    for i, batch in enumerate(stream_jsonl(ACCOUNTS_JSONL)):
        s.execute_write(load_accounts, batch)
        print(f"  Loaded batch {i+1} ({len(batch)} rows)")
```

Run:

```bash
python3 load_graph.py
# → Loaded batch 1 (167 rows)
```

### 6.2 Verify load

```cypher
// How many accounts per site?
MATCH (a:Account)-[:ON_SITE]->(s:Site)
RETURN s.name AS site, count(a) AS accounts
ORDER BY accounts DESC
LIMIT 10;

// How many tools saw each account?
MATCH (a:Account)<-[:HAS_HANDLE]-(h:Handle)
MATCH (a)
RETURN a.tool AS tool, count(*) AS cnt
ORDER BY cnt DESC;
```

---

## 7. Avatar Perceptual Hashing

Avatar reuse is the single strongest cross-platform signal. Two accounts with the same handle on different sites could be anyone. Two accounts with the same avatar perceptual hash are almost certainly the same human.

### 7.1 Compute pHashes

```python
# hash_avatars.py
import asyncio
import httpx
import pdqhash
import imagehash
from PIL import Image
import io
import json
from pathlib import Path
from neo4j import GraphDatabase

DRIVER = GraphDatabase.driver(
    "bolt://localhost:7687",
    auth=("neo4j", "REPLACE_WITH_YOUR_NEO4J_PASSWORD"),
)

PROXY_URL = "socks5://REPLACE_WITH_YOUR_PROXY_HOST:9050"

async def fetch_one(client, url):
    try:
        r = await client.get(url, timeout=15)
        r.raise_for_status()
        return r.content
    except Exception as e:
        return None

def compute_phashes(content):
    """Return (pdq_hex, imagehash_hex)."""
    img = Image.open(io.BytesIO(content)).convert("RGB").resize((256, 256))
    _, pdq_bytes, _ = pdqhash.compute(img)
    pdq_hex = "".join(f"{b:02x}" for b in pdq_bytes)
    ih = str(imagehash.phash(img, hash_size=16))
    return pdq_hex, ih

async def process():
    async with httpx.AsyncClient(proxy=PROXY_URL, headers={"User-Agent": "Mozilla/5.0"}) as client:
        with DRIVER.session() as s:
            rows = s.run("""
                MATCH (a:Account)
                WHERE a.avatar_url IS NOT NULL AND a.avatar_phash IS NULL
                RETURN a.url AS url, a.avatar_url AS avatar_url
            """).data()
            print(f"Hashing {len(rows)} avatars")
            for row in rows:
                content = await fetch_one(client, row["avatar_url"])
                if not content:
                    continue
                try:
                    pdq_hex, ih_hex = compute_phashes(content)
                    s.run("""
                        MATCH (a:Account {url: $url})
                        SET a.avatar_phash = $ph, a.avatar_phash_ih = $ih
                    """, url=row["url"], ph=pdq_hex, ih=ih_hex)
                except Exception as e:
                    print(f"  Failed {row['url']}: {e}")

asyncio.run(process())
```

Run:

```bash
python3 hash_avatars.py
```

### 7.2 Link accounts that share avatars

PDQ hash with Hamming distance ≤ 8 is considered a match (Facebook's published threshold).

```cypher
// Create SHARES_AVATAR edges between accounts with PDQ distance <= 8
MATCH (a:Account), (b:Account)
WHERE a.avatar_phash IS NOT NULL
  AND b.avatar_phash IS NOT NULL
  AND a.url < b.url
  AND apoc.distance.hamming(a.avatar_phash, b.avatar_phash) <= 8
MERGE (a)-[r:SHARES_AVATAR]->(b)
SET r.phash = a.avatar_phash,
    r.hamming_distance = apoc.distance.hamming(a.avatar_phash, b.avatar_phash);
```

Query the avatar cluster:

```cypher
MATCH (a:Account)-[r:SHARES_AVATAR]-(b:Account)
RETURN a.site, a.url, b.site, b.url, r.hamming_distance
ORDER BY r.hamming_distance ASC;
```

---

## 8. Entity Resolution

Now the graph has raw accounts. The next step is deciding which accounts belong to the same real human. This is entity resolution (ER).

### 8.1 ER signals

Sort signals by reliability (highest first):

1. **Avatar pHash match** (PDQ distance ≤ 8) — very strong unless the avatar is a stock image or a meme.
2. **Same handle + same external link** — an account that links from site A to site B is a self-declared identity bridge.
3. **Same handle + bio keyword overlap** — same niche technical vocabulary across profiles.
4. **Same handle + same country/location** — corroborating geography.
5. **Same handle alone** — weakest; people reuse handles but so do strangers.
6. **Email→username breach co-occurrence** — if `j.doe@x.com` and `johndoe123` always appear together in breach data, they likely share an owner.

### 8.2 Confidence scoring

Each signal contributes to a 0–1 score. Combine them with weights:

```python
WEIGHTS = {
    "avatar_match":     0.40,
    "external_link":    0.25,
    "bio_overlap":      0.15,
    "location_match":   0.10,
    "handle_only":      0.05,
    "breach_cooccur":   0.05,
}

def resolve_confidence(signals: dict) -> float:
    return min(1.0, sum(WEIGHTS[k] * v for k, v in signals.items() if k in WEIGHTS))
```

A pair of accounts with avatar match AND external link AND bio overlap gets `0.40 + 0.25 + 0.15 = 0.80` — high confidence.

### 8.3 ER query in Cypher

Create a `:SameIdentity` edge with a confidence property:

```cypher
// Step 1: avatar matches (very strong)
MATCH (a:Account), (b:Account)
WHERE a.url < b.url
  AND (a)-[:SHARES_AVATAR]-(b)
MERGE (a)-[r:SAME_IDENTITY]->(b)
SET r.avatar_match = 1.0,
    r.confidence = coalesce(r.confidence, 0) + 0.40;

// Step 2: external-link cross-references
MATCH (a:Account)-[:LINKS_TO]->(b:Account)
WHERE NOT (a)-[:SAME_IDENTITY]->(b)
MERGE (a)-[r:SAME_IDENTITY]->(b)
SET r.external_link = 1.0,
    r.confidence = coalesce(r.confidence, 0) + 0.25;

// Step 3: bio keyword overlap (>=3 shared non-stopword tokens)
MATCH (a:Account), (b:Account)
WHERE a.url < b.url
  AND a.bio IS NOT NULL AND b.bio IS NOT NULL
  AND NOT (a)-[:SAME_IDENTITY]->(b)
WITH a, b,
     size([t IN split(toLower(a.bio), ' ')
           WHERE t IN split(toLower(b.bio), ' ')
             AND size(t) > 4]) AS shared
WHERE shared >= 3
MERGE (a)-[r:SAME_IDENTITY]->(b)
SET r.bio_overlap = 1.0,
    r.confidence = coalesce(r.confidence, 0) + 0.15;

// Step 4: location match
MATCH (a:Account), (b:Account)
WHERE a.url < b.url
  AND a.location IS NOT NULL
  AND toLower(a.location) = toLower(b.location)
  AND NOT (a)-[:SAME_IDENTITY]->(b)
MERGE (a)-[r:SAME_IDENTITY]->(b)
SET r.location_match = 1.0,
    r.confidence = coalesce(r.confidence, 0) + 0.10;
```

### 8.4 Cluster identities

Treat `:SAME_IDENTITY` as an undirected edge and find connected components:

```cypher
// Use APOC to expand clusters
CALL apoc.periodic.iterate(
  "MATCH (a:Account) WHERE a.confidence IS NULL RETURN a",
  "MATCH (a)-[:SAME_IDENTITY*]-(b:Account)
   WITH collect(DISTINCT b) AS cluster
   UNWIND cluster AS member
   SET member.cluster_id = apoc.hash.five(cluster[0].url)",
  {batchSize: 50}
);
```

After this, every account has a `cluster_id` grouping accounts that likely belong to the same human.

### 8.5 Inspect clusters

```cypher
MATCH (a:Account)
WHERE a.cluster_id IS NOT NULL
RETURN a.cluster_id AS cluster,
       collect(DISTINCT a.site) AS sites,
       count(a) AS account_count,
       max(a.confidence) AS top_confidence
ORDER BY account_count DESC
LIMIT 10;
```

A healthy resolution usually yields one dominant cluster (the target) and a few small clusters (strangers who happen to share the handle).

---

## 9. False-Positive Filtering

Username tools are notorious for false positives. A site that returns HTTP 200 with a generic "user not found" page is indistinguishable from a real profile to a naive checker.

### 9.1 Common false-positive patterns

| Pattern | Symptom | Cause |
|---------|---------|-------|
| Soft 404 | HTTP 200, empty profile | Site returns success for any username |
| Placeholder avatar | All accounts share the same default avatar | Default user image |
| Login wall | Account page redirects to login | Site requires auth to view profile |
| Geoblock | HTTP 403 from your IP | Region-restricted content |
| Captcha | Returns challenge page | Bot detection triggered |
| Username recycling | Account exists but belongs to a previous owner | Handle was reassigned |

### 9.2 Filtering rules

Apply these as Cypher updates that lower confidence or mark `found = false`.

```cypher
// Rule 1: no display name AND no bio AND no avatar => suspect
MATCH (a:Account)
WHERE a.display_name IS NULL
  AND a.bio IS NULL
  AND a.avatar_url IS NULL
SET a.confidence = a.confidence * 0.3,
    a.suspect = true;

// Rule 2: default avatar hash matches a known default
// Maintain a denylist of default avatar hashes per site
MATCH (a:Account)
WHERE a.avatar_phash IN [
  'REPLACE_WITH_DEFAULT_AVATAR_PHASH_GITHUB',
  'REPLACE_WITH_DEFAULT_AVATAR_PHASH_TWITTER'
]
SET a.confidence = a.confidence * 0.2,
    a.default_avatar = true;

// Rule 3: only one tool saw it AND no enrichment
MATCH (a:Account)
WHERE a.tool = 'sherlock'
  AND a.display_name IS NULL
  AND NOT (a)--(:Account)
SET a.confidence = a.confidence * 0.5;

// Rule 4: account exists but in a different cluster from the seed
// (only valid after ER step)
MATCH (seed:Account {url: 'REPLACE_WITH_SEED_URL'})
MATCH (a:Account)
WHERE a.cluster_id <> seed.cluster_id
SET a.confidence = a.confidence * 0.4,
    a.different_cluster = true;
```

### 9.3 Verification via direct HTTP

For any account still above threshold confidence, fetch the profile page through the investigator proxy and grep for canonical markers:

```python
# verify_live.py
import asyncio
import httpx
from bs4 import BeautifulSoup

PROXY = "socks5://REPLACE_WITH_YOUR_PROXY_HOST:9050"

async def verify(client, account):
    try:
        r = await client.get(account["url"], timeout=15, follow_redirects=True)
    except Exception:
        return False
    if r.status_code != 200:
        return False
    soup = BeautifulSoup(r.text, "html.parser")
    title = soup.find("title")
    text = soup.get_text(" ", strip=True)
    # Generic "not found" markers across many sites
    not_found_markers = ["user not found", "page not found", "doesn't exist",
                         "account suspended", "404"]
    if any(m in text.lower() for m in not_found_markers):
        return False
    return True

async def main():
    accounts = [...]  # pull from Neo4j
    async with httpx.AsyncClient(proxy=PROXY) as client:
        results = await asyncio.gather(*[verify(client, a) for a in accounts])
    for a, ok in zip(accounts, results):
        if not ok:
            mark_unverified(a["url"])

asyncio.run(main())
```

---

## 10. Breach Data Correlation

Once you have a resolved identity cluster, you can pivot to breach data to discover associated emails, passwords, and additional handles.

### 10.1 API clients

Use three sources in parallel — each covers different breach sets.

```python
# breach_clients.py
import httpx
import asyncio

HIBP_KEY = "REPLACE_WITH_YOUR_HIBP_API_KEY"
DEHASHED_KEY = "REPLACE_WITH_YOUR_DEHASHED_API_KEY"
INTELX_KEY = "REPLACE_WITH_YOUR_INTELX_API_KEY"

async def hibp_username(handle: str) -> list[dict]:
    async with httpx.AsyncClient() as c:
        r = await c.get(
            f"https://haveibeenpwned.com/api/v3/username/{handle}",
            headers={"hibp-api-key": HIBP_KEY, "user-agent": "investigator"},
        )
        if r.status_code != 200:
            return []
        return r.json()

async def dehashed_email(email: str) -> list[dict]:
    # DeHashed uses basic auth with email:key
    import base64
    token = base64.b64encode(f"REPLACE_WITH_YOUR_DEHASHED_EMAIL:{DEHASHED_KEY}".encode()).decode()
    async with httpx.AsyncClient() as c:
        r = await c.get(
            f"https://api.dehashed.com/search?query=email:{email}",
            headers={"Authorization": f"Basic {token}"},
        )
        if r.status_code != 200:
            return []
        return r.json().get("dehashed", [])

async def intelx_search(query: str) -> list[dict]:
    async with httpx.AsyncClient() as c:
        # IntelX flow: start search → poll for results
        r = await c.post(
            "https://2.intelx.io/phonebook/search",
            headers={"x-key": INTELX_KEY},
            json={"term": query, "maxresults": 100, "media": 0, "target": 1},
        )
        if r.status_code != 200:
            return []
        id_ = r.json()["id"]
        await asyncio.sleep(3)
        r2 = await c.get(
            f"https://2.intelx.io/phonebook/search/result?id={id_}",
            headers={"x-key": INTELX_KEY},
        )
        return r2.json().get("selectors", [])
```

### 10.2 Load breach records into graph

```cypher
// From Python, batch-merge breach records
UNWIND $rows AS row
MERGE (e:Email {address: row.email})
SET e.domain = split(row.email, '@')[1]
MERGE (b:BreachRecord {
  source: row.source,
  year: row.year,
  email: row.email
})
SET b.password_hash = row.password_hash,
    b.password_plain = row.password_plain
MERGE (b)-[:IN_BREACH]->(e);

// Link email to any account whose handle appears in the same breach row
UNWIND $rows AS row
MATCH (h:Handle {value: row.handle})
MATCH (e:Email {address: row.email})
MATCH (a:Account)-[:HAS_HANDLE]->(h)
MERGE (e)-[r:EMAIL_SEEN_AT]->(a)
SET r.source = 'breach:' + row.source;
```

### 10.3 Pivot queries

```cypher
// All emails ever seen alongside this handle in breach data
MATCH (h:Handle {value: 'johndoe123'})<-[:HAS_HANDLE]-(a:Account)
MATCH (e:Email)-[:EMAIL_SEEN_AT]->(a)
RETURN DISTINCT e.address AS email, e.domain AS domain;

// All handles sharing an email with our target (pivoting to new identities)
MATCH (target:Handle {value: 'johndoe123'})<-[:HAS_HANDLE]-(a:Account)
MATCH (e:Email)-[:EMAIL_SEEN_AT]->(a)
MATCH (e)-[:EMAIL_SEEN_AT]->(other:Account)
WHERE other <> a
RETURN DISTINCT other.handle AS new_handle, count(*) AS shared_emails
ORDER BY shared_emails DESC;

// Password reuse pattern (mask passwords)
MATCH (b:BreachRecord)-[:IN_BREACH]->(e:Email)
WHERE e.address STARTS WITH 'j.doe'
RETURN b.source, b.year,
       CASE
         WHEN b.password_plain IS NOT NULL THEN
           regexp_replace(b.password_plain, '(.)', '*')
         ELSE 'hash-only'
       END AS masked;
```

### 10.4 Password pattern extraction

Useful for threat modeling (will the target reuse a password pattern on internal corporate systems?).

```python
# password_patterns.py
import re
from collections import Counter

def patterns(passwords):
    out = Counter()
    for p in passwords:
        if not p:
            continue
        if re.match(r"^[a-z]+[0-9]{1,4}$", p):
            out["word+digits"] += 1
        elif re.match(r"^[A-Z][a-z]+[0-9]{2,4}[!@#]?$", p):
            out["Capital+digits+sym?"] += 1
        elif re.match(r"^[a-z]{6,}[0-9]{4}$", p):
            out["longword+year"] += 1
        else:
            out["other"] += 1
    return out
```

---

## 11. Operational Security for Investigators

OPSEC is not optional. A careless investigator exposes the target (who gets notification emails), the client (whose infrastructure gets logged), and themselves (whose investigator IP gets blocked).

### 11.1 Proxy chain

Chain a residential or datacenter rotating proxy behind Tor. Direct Tor exits are blocked by many social platforms.

```
investigator box
  ↓ socks5://127.0.0.1:9050     (Tor)
  ↓ http://REPLACE_WITH_PROXY_USER:REPLACE_WITH_PROXY_PASS@proxy.example:8000
  ↓ target site
```

Configure Maigret:

```bash
# Tor + custom proxy
maigret johndoe123 \
  --proxy socks5://127.0.0.1:9050 \
  --tor-control-port 9051 \
  --timeout 15
```

### 11.2 Header randomization

Default `requests` / `httpx` User-Agents are fingerprintable. Rotate realistic headers.

```python
# headers.py
import random

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
]

def headers() -> dict:
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept-Language": random.choice(["en-US,en;q=0.9", "en-GB,en;q=0.9", "de-DE,de;q=0.8,en;q=0.5"]),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "DNT": "1",
    }
```

### 11.3 Rate limiting

Never hit more than one request per site per 5 seconds from a single exit. Spread bursts.

```python
# rate_limiter.py
import asyncio
import time

class PerHostLimiter:
    def __init__(self, min_interval_s: float = 5.0):
        self.min_interval = min_interval_s
        self.last_call: dict[str, float] = {}

    async def acquire(self, host: str):
        now = time.monotonic()
        last = self.last_call.get(host, 0)
        wait = max(0, self.min_interval - (now - last))
        if wait:
            await asyncio.sleep(wait)
        self.last_call[host] = time.monotonic()
```

### 11.4 Audit trail

Every external request should be logged with case ID, timestamp, target URL, exit IP used, and response status. Store logs outside the case directory, in a tamper-evident append-only store.

```python
# audit.py
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

AUDIT_LOG = Path("/var/log/investigator/audit.log")
AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)

def log_request(case_id: str, url: str, exit_ip: str, status: int, note: str = ""):
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "case": case_id,
        "url": url,
        "exit_ip": exit_ip,
        "status": status,
        "note": note,
    }
    line = json.dumps(entry, separators=(",", ":"))
    h = hashlib.sha256(line.encode()).hexdigest()
    with AUDIT_LOG.open("a") as f:
        f.write(f"{h} {line}\n")
```

### 11.5 GDPR / data-minimization checklist

- Collect only what the engagement requires.
- Mask or hash PII (emails, passwords) at rest unless the client has a documented need for the raw value.
- Define retention in writing. Default: 90 days post-engagement, then cryptographic erase.
- Do not move PII across jurisdictional borders without a lawful basis (e.g., GDPR Article 44+).
- Maintain a data-subject access request (DSAR) procedure — clients and subjects may ask what you hold.

---

## 12. Walkthrough: A Complete Case

A worked example with synthetic data.

### 12.1 Seed

Client (a fintech) provides a single handle: `ghostfox` — observed in a phishing kit targeting their customers.

### 12.2 Phase 1: enumerate

```bash
mkdir -p raw normalized graph reports
cd ~/cases/case-ghostfox

maigret ghostfox --json --output raw/maigret.json \
  --proxy socks5://127.0.0.1:9050 --timeout 15

python3 -m sherlock ghostfox --timeout 15 --json --output raw/sherlock.json \
  --proxy socks5://127.0.0.1:9050

python3 -m whatsmyname -u ghostfox --json --output raw/whatsmyname.json \
  --proxy socks5://127.0.0.1:9050
```

### 12.3 Phase 2: normalize and load

```bash
python3 normalize.py
python3 load_graph.py
python3 hash_avatars.py
```

### 12.4 Phase 3: resolve entities

Run the Cypher from Section 8.3 inside the Neo4j browser, then inspect clusters:

```cypher
MATCH (a:Account)
RETURN a.cluster_id AS cluster,
       collect(DISTINCT a.site) AS sites,
       count(a) AS n
ORDER BY n DESC;
```

Hypothetical output:

```
cluster    sites                                             n
af31c9d2   [GitHub, Twitter, Reddit, Keybase, HackTheBox]    7
b1e84e07   [Instagram, TikTok]                               2
```

The first cluster is the target. The second is unrelated users.

### 12.5 Phase 4: pivot

```cypher
MATCH (h:Handle {value: 'ghostfox'})<-[:HAS_HANDLE]-(a:Account)
WHERE a.cluster_id = 'af31c9d2'
OPTIONAL MATCH (e:Email)-[:EMAIL_SEEN_AT]->(a)
RETURN a.site, a.url, a.display_name, collect(DISTINCT e.address) AS emails;
```

### 12.6 Phase 5: export

Export the resolved cluster as a dossier-ready JSON:

```python
# export_dossier.py
import json
from neo4j import GraphDatabase

DRIVER = GraphDatabase.driver(
    "bolt://localhost:7687",
    auth=("neo4j", "REPLACE_WITH_YOUR_NEO4J_PASSWORD"),
)

with DRIVER.session() as s:
    rows = s.run("""
        MATCH (a:Account)
        WHERE a.cluster_id = $cid
        OPTIONAL MATCH (e:Email)-[:EMAIL_SEEN_AT]->(a)
        RETURN a.site AS site, a.url AS url, a.display_name AS name,
               a.bio AS bio, a.location AS loc, a.confidence AS conf,
               collect(DISTINCT e.address) AS emails
    """, cid="af31c9d2").data()

dossier = {
    "cluster_id": "af31c9d2",
    "account_count": len(rows),
    "accounts": rows,
}

with open("reports/dossier_ghostfox.json", "w") as f:
    json.dump(dossier, f, indent=2)
```

---

## 13. Reporting and Visualization

### 13.1 Cypher queries for the report

Five queries that should be in every identity-graph report:

```cypher
// Q1: Coverage — how many tools confirmed each account?
MATCH (a:Account)
RETURN a.site AS site, a.url AS url, a.confidence AS conf
ORDER BY conf DESC;

// Q2: Avatar reuse — which avatars were seen on multiple sites?
MATCH (a:Account)-[:SHARES_AVATAR]-(b:Account)
RETURN a.avatar_phash AS phash, collect(DISTINCT a.site) AS sites;

// Q3: Cross-site self-links
MATCH (a:Account)-[:LINKS_TO]->(b:Account)
RETURN a.site, a.url, b.site, b.url;

// Q4: Suspected false positives
MATCH (a:Account {suspect: true})
RETURN a.site, a.url, a.confidence;

// Q5: Breach pivots discovered
MATCH (e:Email)-[:EMAIL_SEEN_AT]->(a:Account)
RETURN e.address, collect(DISTINCT a.site) AS sites;
```

### 13.2 Visual export

```python
# export_pyvis.py
from pyvis.network import Network
from neo4j import GraphDatabase

DRIVER = GraphDatabase.driver(
    "bolt://localhost:7687",
    auth=("neo4j", "REPLACE_WITH_YOUR_NEO4J_PASSWORD"),
)

net = Network(height="800px", width="100%", notebook=False, directed=False)

with DRIVER.session() as s:
    rows = s.run("""
        MATCH (a:Account)-[r]-(b:Account)
        WHERE a.cluster_id = 'af31c9d2'
        RETURN a.url AS a, b.url AS b, type(r) AS rel
    """).data()
    seen = set()
    for row in rows:
        for url in (row["a"], row["b"]):
            if url not in seen:
                net.add_node(url, label=url.split("/")[2])
                seen.add(url)
        net.add_edge(row["a"], row["b"], label=row["rel"])

net.write_html("reports/identity_graph.html")
```

Open `reports/identity_graph.html` in a browser to inspect the cluster visually.

---

## 14. Decision Trees

### 14.1 "Is this account real or a false positive?"

```
START
  ├─ HTTP status == 200?
  │    ├─ No  → likely false positive (or login wall). STOP.
  │    ├─ Yes → Does the page contain a display name?
  │              ├─ No  → SUSPECT. Set confidence *= 0.3.
  │              ├─ Yes → Does the avatar match the target's known pHash?
  │                        ├─ Yes → HIGH confidence. KEEP.
  │                        ├─ No  → Does the bio overlap with the target's bio?
  │                                  ├─ Yes (>=3 tokens) → MEDIUM. KEEP.
  │                                  ├─ No  → UNKNOWN. Flag for manual review.
```

### 14.2 "Should I pivot to this new handle?"

```
START
  ├─ Was the new handle found via an external link from a confirmed account?
  │    ├─ Yes → Pivot. Weight = 0.25.
  │    ├─ No  → Was it found in breach data alongside the target's email?
  │              ├─ Yes → Pivot. Weight = 0.20.
  │              ├─ No  → Was it discovered via permutation only?
  │                        ├─ Yes → Pause. Run avatar/bio correlation first.
  │                        ├─ No  → Do NOT pivot. Treat as unconfirmed.
```

---

## 15. Integration with Adjacent Skills

- **`osint`** — broad passive collection provides the seed identifiers (emails, domains, subdomains) that feed into username profiling.
- **`email-protocol-attack`** — phishing-kit analysis often yields the attacker's handle, which becomes the seed for this pipeline.
- **`digital-forensics`** — when you have a disk image, extracted usernames from browser history become high-confidence seeds.
- **`social-engineering`** — pretexts are more credible when built on resolved identity clusters (knowing the target's bio + breach password pattern).
- **`pentest-reporting`** — the dossier JSON export from Section 12.6 plugs directly into the standard engagement report template.

---

## 16. Workshop Exercises

### Exercise 1: Build a single-source graph
Use only Maigret output for a handle you control (your own alt account). Load it, hash avatars, run ER. You should end up with a single-node cluster — verify that no false positives slipped in.

### Exercise 2: Force a false positive
Pick a handle likely to be reused (e.g., `admin`). Run all three tools. Confirm that ER produces multiple clusters, and that the filtering rules in Section 9.2 lower the confidence of strangers.

### Exercise 3: Breach pivot on yourself
Query HIBP for an email you own. Load the result into the graph. Verify the EMAIL_SEEN_AT edge correctly links your email to accounts with the same handle.

### Exercise 4: OPSEC audit
Run the full pipeline once with headers and once without. Diff the per-site success rates. Expect a 20–40% drop without proper headers — that is the cost of being fingerprintable.

### Exercise 5: Cluster diff over time
Run the pipeline now and again in 30 days. Diff the cluster contents. New accounts in the same cluster are high-value intelligence — they show what the target is doing *now*.

---

## 17. Troubleshooting Reference

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `apoc.distance.hamming` not found | APOC plugin not loaded | Recreate container with `NEO4J_PLUGINS='["apoc"]'` |
| All accounts have the same `avatar_phash` | Default avatar returned to anonymous users | Add default avatar hashes to the denylist in Section 9.2 |
| Empty avatar pHash column | Images fetched but hashing failed | Check PIL can decode the format; some sites serve WebP — install `pillow-heif` if needed |
| ER produces one giant cluster | Threshold too loose; `bio_overlap` matching stopword-like tokens | Raise minimum token length from 4 to 6, or require 4+ shared tokens instead of 3 |
| ER produces no edges at all | Avatar hashing didn't run, or all confidence weights are 0 | Re-run `hash_avatars.py`, check `a.avatar_phash IS NOT NULL` count |
| Breach API returns 401 | Wrong key or key expired | Rotate via the provider's dashboard, never commit the new key to git |
| Sherlock returns 0 results | Site list out of date | `python3 -m sherlock --site_list` to refresh |
| Maigret hangs on one site | Site is geoblocked or behind Cloudflare challenge | Add `--timeout 15` and `--no-recursion` to skip pathological sites |

---

## 18. Further Reading

- Neo4j Cypher Manual — https://neo4j.com/docs/cypher-manual/current/
- APOC User Guide — https://neo4j.com/docs/apoc/current/
- Facebook PDQ hashing paper — https://scontentcdn.sec.s-msft.com/metadata/file2/21/87/64/PHOTO_HASHING_FINAL.pdf
- imagehash library docs — https://github.com/JohannesBuchner/imagehash
- Have I Been Pwned API docs — https://haveibeenpwned.com/API/v3
- DeHashed API docs — https://www.dehashed.com/docs
- IntelX API docs — https://github.com/IntelligenceX/SDK/blob/master/JavaScript/README.md
- Maigret project — https://github.com/soxoj/maigret
- Sherlock project — https://github.com/sherlock-project/sherlock
- WhatsMyName project — https://github.com/WebBreacher/WhatsMyName
- OWASP OSINT Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/OSINT_Cheat_Sheet.html
- ENISA Handbook on Personal Data Breach Assessment — https://www.enisa.europa.eu/publications/dbn/ar

---

## 19. References & Resources

- **Tooling**: Maigret, Sherlock, WhatsMyName, Blackbird, Holehe, Neo4j 5.x, APOC, `pdqhash`, `imagehash`, `pyvis`, Gephi
- **Breach APIs**: Have I Been Pwned, DeHashed, Intelligence X
- **Graph concepts**: entity resolution, probabilistic record linkage, connected components, perceptual hashing, Hamming distance
- **OPSEC**: Tor + rotating proxy chain, header randomization, per-host rate limiting, append-only audit log
- **Legal**: GDPR Articles 5 (data minimization), 17 (right to erasure), 44 (cross-border transfers); CCPA §1798.100 et seq.
- **Related guides in this skill**: `maigret-username-workshop.md` (installation + multi-site workflow), `maigret-username-dossier.md` (end-to-end dossier lifecycle)

---

## 20. Checklist Before Closing a Case

- [ ] All raw tool outputs saved in `raw/`
- [ ] Normalized JSONL written to `normalized/accounts.jsonl`
- [ ] Graph loaded into a per-case Neo4j container
- [ ] Avatar pHashes computed for every account with an avatar URL
- [ ] `:SAME_IDENTITY` edges created with confidence weights
- [ ] False-positive filters applied
- [ ] Breach pivots attempted (if scope permits)
- [ ] Dossier JSON exported to `reports/`
- [ ] Visual graph HTML exported to `reports/`
- [ ] Audit log entries written for every external request
- [ ] PII masked or encrypted at rest
- [ ] Retention date set in the case metadata file
- [ ] Neo4j container stopped and volume snapshotted
