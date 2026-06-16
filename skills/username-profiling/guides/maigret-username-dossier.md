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
