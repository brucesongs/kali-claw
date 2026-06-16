# Dark Web Investigation Playbook — End-to-End Workflow

> Deep-dive companion to `skills/darkweb-intel/SKILL.md`.
>
> Audience: investigators who already know what Tor and Ahmia do, and want a battle-tested playbook for taking a target from "we heard a rumor" to "defensible dossier with monitoring cadence" — without leaking operator identity, burning personas, or shipping stale evidence to a client.

---

## 1. Why a Playbook, Not Just Commands

A defensible dark-net investigation requires more than tooling. The five failure modes are predictable:

1. **Egress leak** — investigator's real IP appears in a target's logs.
2. **Persona contamination** — monitoring persona linked back to the org via a reused PGP key, wallet, or browser fingerprint.
3. **Behavioral fingerprinting** — adversary correlates session windows across days.
4. **Stale evidence** — dark-net services rotate addresses weekly; last month's `.onion` is dead or honeypot today.
5. **Jurisdictional exposure** — investigator accessed content that is strict-liability criminal in their home jurisdiction.

This playbook addresses all five. Follow it in order; do not skip the pre-flight.

---

## 2. Pre-Flight: Scope, Authorization, Hardware

Before any Tor connection, answer these — in writing:

### 2.1 Legal scope

- **Who authorized this?** Pentest engagements authorize the target organization's *systems*, not its employees' personal dark-net activities. Confirm scope with the client and with internal legal.
- **What's the lawful basis?** GDPR/CCPA/equivalent treat personal data collection as regulated even when the data is public. Document the basis (consent, contract, legitimate interest, statutory authority).
- **What's the jurisdictional exposure?** Know your home jurisdiction's strict-liability rules for content (CSAM, certain political content, controlled substance listings). Some content is criminal to *view*, not just possess.
- **What's the deliverable?** Internal threat intel? Client report? Lawful marketplace takedown support? Different deliverables need different verification depth.

### 2.2 OPSEC commitment

Document the OPSEC rules and have every investigator sign:

- All dark-net work happens in Tails or Whonix (no bare-Tor VMs on corporate devices).
- Dedicated hardware (not corporate, not personal).
- One persona per investigation; persona never reused.
- No clearnet accounts active on the same machine during sessions.
- All evidence encrypted at rest with `gpg --symmetric --cipher-algo AES256`.
- All evidence shredded when the engagement closes (`shred -uvz`).

### 2.3 Hardware provisioning

| Tier | Setup | Use When |
|------|-------|----------|
| **Tier 1 (highest OPSEC)** | Tails bootable USB on dedicated burner laptop, bought with cash | High-risk investigation; adversary is sophisticated |
| **Tier 2** | Qubes + Whonix on dedicated burner laptop | Compartmentalized; need persistent tooling across sessions |
| **Tier 3** | Whonix in VirtManager on dedicated laptop | Persistent, but laptop also has other VMs (more attack surface) |
| **Tier 4 (lowest OPSEC)** | Tor on a dedicated VM | Low-risk triage only; NOT for adversarial investigations |

> Tier 4 is acceptable for "is our brand mentioned anywhere" sweeps but NOT for active threat actor profiling, where the adversary has reason to deanonymize you.

---

## 3. Phase 1 — Access Setup

### 3.1 Choose environment

For most engagements, Whonix in VirtManager is the right balance: persistent, isolated, snapshot-revertible. For high-risk work, Tails is mandatory.

### 3.2 Boot and verify

```bash
# Inside Whonix-Workstation (or Tails, after boot)
# 1. Verify Tor is up
sudo service tor status   # Whonix
# (Tails: Tor starts at boot automatically)

# 2. Verify egress
REAL=$(curl -s https://api.ipify.org)
TOR=$(curl -s --socks5-hostname 127.0.0.1:9050 https://api.ipify.org)
[ "$REAL" = "$TOR" ] && echo "FAIL: Tor egress equals real IP" || echo "PASS: Tor egress differs"

# 3. Verify exit geolocation
curl -s --socks5-hostname 127.0.0.1:9050 https://ifconfig.me/json | jq '{ip, country, city}

# 4. Verify DNS resolver
cat /etc/resolv.conf
# Expected in Tails/Whonix: nameserver 10.152.152.10 (Whonix) or 127.0.0.1 (Tails)

# 5. If Tor is blocked on the host network, configure bridges in /etc/tor/torrc
#    See payloads.md §1.2 for obfs4 and Snowflake snippets
```

### 3.3 Take a pre-investigation snapshot (Whonix)

```bash
# On the VirtManager host
virsh snapshot-create-as whonix-workstation pre-investigation-$(date -u +%Y%m%d)
```

This snapshot is your "revert" point after each session — everything collected in the Workstation can be discarded, eliminating persistent forensic traces.

---

## 4. Phase 2 — Discovery & Search

### 4.1 Start with the clearnet indexers

Faster, lower-risk. Use them to build an initial candidate list, then pivot to direct `.onion` access only for the hits that matter.

```bash
TARGET="<brand_or_term>"
ENC=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$TARGET")

# Ahmia clearnet
curl -s "https://ahmia.fi/search/?q=${ENC}" \
  | grep -oE 'https?://[a-z2-7]{56}\.onion' | sort -u > ahmia_clearnet.txt

# Filter v3 only (drop deprecated v2 16-char addresses)
grep -E 'https?://[a-z2-7]{56}\.onion' ahmia_clearnet.txt > ahmia_v3.txt
```

### 4.2 Move to direct .onion search

```bash
# Ahmia onion mirror — full anonymity
curl -s --socks5-hostname 127.0.0.1:9050 \
  "http://juhanurmihxlp77nkq76byazc4y2sphl4a5hfo3hxnlhkbgz7q6fqd.onion/search/?q=${ENC}" \
  | grep -oE 'https?://[a-z2-7]{56}\.onion' | sort -u > ahmia_onion.txt

# Torch (verify current address via dark.fail first)
curl -s --socks5-hostname 127.0.0.1:9050 \
  "http://torchde7jygjnqjjp6lcyrch6gzflyol3c5zfsa6uejwnbq7qiiyfqd.onion/search?query=${ENC}" \
  | grep -oE 'https?://[a-z2-7]{56}\.onion' | sort -u > torch.txt

# Aggregate and dedupe
sort -u ahmia_v3.txt ahmia_onion.txt torch.txt > all_candidates.txt
echo "Discovered $(wc -l < all_candidates.txt) unique v3 onion URLs"
```

### 4.3 Triage candidates with OnionScan

OnionScan fingerprints each candidate: server software, exposed directories, PGP keys in content, linked `.onion` services. Run on the top 10-20 candidates.

```bash
mkdir -p onionscan_reports
while read onion; do
  echo "Scanning $onion"
  onionscan --verbose \
    --tor-proxy-address 127.0.0.1:9050 \
    --timeout 120 \
    "$onion" > "onionscan_reports/$(basename "$onion" .onion).txt" 2>&1
done < <(head -20 all_candidates.txt)

# Quick triage of reports
for r in onionscan_reports/*.txt; do
  echo "=== $r ==="
  grep -iE 'pgp|bitcoin|monero|linked|server-status|exposed' "$r" | head -10
done
```

---

## 5. Phase 3 — Marketplace & Forum Monitoring

### 5.1 Verify current addresses

Marketplaces and major forums rotate addresses weekly. Never trust a static list.

```bash
# dark.fail tracks uptime of well-known services
curl -s --socks5-hostname 127.0.0.1:9050 https://dark.fail | \
  grep -E '<td>[A-Za-z ]+</td>.*<td>(online|offline|down)</td>' | head -30

# Capture current addresses into a per-session reference
curl -s --socks5-hostname 127.0.0.1:9050 https://dark.fail > darkfail_$(date -u +%Y%m%d).html
```

### 5.2 Commercial API sweeps

For brand monitoring at scale, use commercial APIs rather than manual marketplace visits — lower OPSEC risk and lower labor cost.

```bash
# IntelX intelligent search (full-text across dark-net + leaks)
ID=$(curl -s "https://2.intelx.io/intelligent/search?k=<KEY>" \
  -H "Content-Type: application/json" \
  -d '{"term":"<brand>","maxresults":100,"sort":1}' | jq -r '.id')

sleep 10
curl -s "https://2.intelx.io/intelligent/search/result?k=<KEY>&id=$ID&limit=100" \
  | jq '.selectors[] | {selectorvalue, type, source}' > intelx_brand_$(date -u +%Y%m%d).json
```

### 5.3 Manual marketplace enumeration (read-only)

For investigations where commercial APIs miss something (niche markets, new markets), manual enumeration via Tor Browser is required. Strict observer role.

```bash
# In Tor Browser (manual):
# 1. Navigate to verified marketplace .onion (from dark.fail)
# 2. Search for target brand / product / handle
# 3. For each match, capture:
#    - Listing URL
#    - Vendor profile URL
#    - Vendor PGP fingerprint (often on profile)
#    - Vendor Monero wallet (escrow + donations)
#    - Screenshot
#    - UTC timestamp

# 4. Encrypt evidence before storage
tar czf session_$(date -u +%Y%m%d).tar.gz evidence/
gpg --symmetric --cipher-algo AES256 session_$(date -u +%Y%m%d).tar.gz
shred -uvz session_$(date -u +%Y%m%d).tar.gz
```

**Rules** (non-negotiable):
- Observer only. No account creation, no purchase, no vendor contact.
- Limit session length to 30-60 minutes.
- Rotate persona between marketplaces.
- If persona contamination is suspected, burn and rotate immediately.

### 5.4 Ransomware leak-site monitoring

For incident-response firms, tracking which victims appear on which ransomware gang's leak site is a regular deliverable.

```bash
GANGS=("<gang1>.onion" "<gang2>.onion" "<gang3>.onion")
DATE=$(date -u +%Y-%m-%d)
OUT="ransomware_tracker_${DATE}.tsv"
echo -e "gang\tvictim\tdiscovered_at" > "$OUT"

for g in "${GANGS[@]}"; do
  curl -s --socks5-hostname 127.0.0.1:9050 "http://$g" \
    | grep -ioE '<victim>([^<]+)</victim>' \
    | sed -E "s/<[^>]+>//g; s/.*/$g\t&\t$DATE/i" >> "$OUT"
done

column -t -s $'\t' "$OUT"
```

---

## 6. Phase 4 — Threat Actor Profiling

### 6.1 Seed collection

From the discovery phase, you should have one or more forum handles or vendor names. Treat each as a seed.

### 6.2 PGP key pivot

```bash
HANDLE="<forum_handle>"

# Search keyservers for keys with a uid matching the handle
gpg --keyserver hkps://keys.openpgp.org --search-keys "$HANDLE"
gpg --keyserver hkps://keyserver.ubuntu.com --search-keys "$HANDLE"

# If a key is found, list its uids — each uid is a pivot to another community
gpg --list-keys --with-sig-list "$HANDLE"
```

Actors rarely rotate PGP keys. A key found under two uids (`handle@forumA.onion` and `handle@forumB.onion`) is high-confidence same-actor attribution.

### 6.3 Cryptocurrency wallet pivot

```bash
# Scrape the actor's profile / posts for wallet addresses
PROFILE="http://<forum>.onion/profile/$HANDLE"
HTML=$(curl -s --socks5-hostname 127.0.0.1:9050 "$PROFILE")

# Monero (XMR) — 95 chars starting with 4
echo "$HTML" | grep -oE '4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}' | sort -u > xmr_wallets.txt

# Bitcoin (legacy) — 26-35 chars starting with 1 or 3
echo "$HTML" | grep -oE '[13][a-km-zA-HJ-NP-Z1-9]{25,34}' | sort -u > btc_legacy.txt

# Bitcoin (bech32) — starts with bc1
echo "$HTML" | grep -oE 'bc1[a-z0-9]{39,59}' | sort -u > btc_bech32.txt

# For each wallet, search other forums for the same address (off-chain pivot)
for w in $(cat xmr_wallets.txt); do
  echo "=== $w ==="
  curl -s --socks5-hostname 127.0.0.1:9050 \
    "http://<forum>.onion/search?q=$w" | grep -c "$w"
done
```

For Monero, on-chain tracing is intentionally limited. Off-chain pivot (same address on multiple forums/marketplaces) is the main attribution vector.

### 6.4 Behavioral fingerprinting (advanced)

```bash
# Collect post corpus per handle
for f in <forum1>.onion <forum2>.onion <forum3>.onion; do
  curl -s --socks5-hostname 127.0.0.1:9050 \
    "http://$f/user/$HANDLE/posts" >> posts_$HANDLE.html
done

# Extract text and run stylometric analysis
python3 <<'EOF'
from bs4 import BeautifulSoup
import re
with open(f'posts_<handle>.html') as f:
    soup = BeautifulSoup(f, 'html.parser')
posts = [p.get_text() for p in soup.select('.post-body')]
corpus = '\n'.join(posts)
print(f'Corpus: {len(corpus)} chars across {len(posts)} posts')
# Distinctive markers: emoji usage, misspelling patterns, punctuation habits,
# regional English variants (US vs UK), timezone-of-activity windows
EOF
```

### 6.5 Build the identity graph

Aggregate every pivot into a single graph (Maltego or a custom Neo4j instance).

```markdown
# Threat Actor Dossier: <handle>

## Primary Identifiers
- Handle: <handle> (forumA, forumB, marketC)
- PGP fingerprint: <40-char fingerprint>
  - uids: handle@forumA.onion, handle@forumB.onion, altname@forumD.onion
- Monero wallet: <95-char address>
  - appears on: forumA profile, marketC escrow, forumD donation page
- Bitcoin wallet (legacy): <34-char address>
  - appears on: marketC only

## Inferred Real Identity (low confidence)
- Likely timezone: UTC+2 ± 2 (session windows cluster 18:00-23:00 UTC)
- Likely native language: Russian (English has consistent Russian-English calque patterns)
- Likely region: Eastern Europe (Monero wallet appears in regional forum signatures)

## Active Communities (5)
| Community | Role | First Seen | Last Seen |
|-----------|------|------------|-----------|
| forumA    | Member | 2023-04   | 2026-05   |
| forumB    | Senior | 2023-08   | 2026-06   |
| marketC   | Vendor | 2024-01   | 2026-06   |
| forumD    | Senior | 2024-05   | 2026-04   |
| forumE    | Member | 2024-11   | 2026-03   |

## Confidence: MEDIUM
- High confidence: handle correlation across 5 communities via PGP + wallet
- Medium confidence: timezone and region inference
- Low confidence: real identity (no clearnet pivot yet)
```

---

## 7. Phase 5 — OPSEC-Hardened Synthesis

### 7.1 Aggregate findings

```bash
# Merge all sweep outputs, OnionScan reports, pivot results
mkdir -p dossier
cp sweep_*.json onionscan_reports/*.txt intelx_*.json dossier/
cp threat_actor_pgp.txt threat_actor_wallets.txt dossier/
cp ransomware_tracker_*.tsv dossier/

# Encrypt the dossier
tar czf dossier_$(date -u +%Y%m%d).tar.gz dossier/
gpg --symmetric --cipher-algo AES256 dossier_$(date -u +%Y%m%d).tar.gz
shred -uvz dossier_$(date -u +%Y%m%d).tar.gz
```

### 7.2 Define monitoring cadence

Dark-net evidence goes stale quickly. Define a recurring monitoring pipeline before closing the engagement.

```bash
# Daily Ahmia sweep for brand
echo "0 8 * * * curl -s 'https://ahmia.fi/search/?q=<brand>' >> /var/log/dw-monitor.log" | crontab -

# Daily IntelX sweep
echo "30 8 * * * curl -s 'https://2.intelx.io/intelligent/search?k=<KEY>' -H 'Content-Type: application/json' -d '{\"term\":\"<brand>\",\"maxresults\":50}' >> /var/log/intelx-monitor.log" | crontab -

# Weekly ransomware leak-site review (manual, via Tor Browser)
# Monthly persona rotation review
# Quarterly scope review with client
```

### 7.3 Revert the environment

```bash
# Whonix: revert to pre-investigation snapshot
virsh snapshot-revert whonix-workstation pre-investigation-$(date -u +%Y%m%d)

# Tails: just reboot — everything in RAM is wiped

# Scrub any host-side traces
shred -uvz ~/.bash_history
history -c && history -w
```

---

## 8. Common Pitfalls

### 8.1 Egress leaks

**Failure mode**: investigator runs a quick `curl` without `--socks5-hostname 127.0.0.1:9050`, leaking real IP to a `.onion` service (which is logged server-side).

**Mitigation**: route everything through Tails/Whonix at the VM level (Whonix-Gateway forces all Workstation traffic through Tor). Never run a bare-Tor setup where a single forgotten flag leaks.

### 8.2 Behavioral fingerprinting

**Failure mode**: investigator always works 18:00-22:00 UTC, in the same sequence of onion services, with the same search terms in the same order. Adversary correlates sessions.

**Mitigation**: vary session times; vary the order of sites visited; use different personas for different investigations; do not have personal clearnet accounts active on the same physical machine during dark-net sessions.

### 8.3 Persona contamination

**Failure mode**: investigator uses the same PGP key across investigations, or signs dark-net monitoring posts with a key that has a real-name uid. The persona is linked to the org.

**Mitigation**: one persona per investigation; fresh PGP key per persona (fake uid); never import personal key into the investigation keyring; periodic contamination audit (test-cases.md TC-DW-010).

### 8.4 Stale evidence

**Failure mode**: investigator hands the client a deliverable with `.onion` URLs that died last week. Client clicks them from a clearnet browser; they 404 or — worse — resolve to a honeypot.

**Mitigation**: re-verify every `.onion` URL via dark.fail immediately before delivery. Hand the client screenshots + PGP fingerprints + wallet addresses (the durable identifiers), not URLs.

### 8.5 Jurisdictional exposure

**Failure mode**: investigator clicks into a forum thread that contains CSAM, or browses a marketplace listing for a controlled substance. In many jurisdictions, viewing is strict-liability criminal.

**Mitigation**: stay on the search results page; do not click into threads without reading the title and preview first; immediately close and document any accidental CSAM exposure; for jurisdictions with mandatory reporting, follow the reporting protocol.

---

## 9. Persona Management

### 9.1 Persona creation checklist

For each new investigation, generate a fresh persona:

- [ ] Unique handle (NEVER reused across investigations)
- [ ] Unique PGP key (`gpg --full-generate-key`, RSA 4096, no expiry, fake name/email)
- [ ] Unique Monero wallet (if vendor interaction needed)
- [ ] Unique Tor Browser profile (in Whonix snapshot)
- [ ] Unique timezone-of-activity window (avoid your real timezone)
- [ ] Unique writing style (avoid your real vocabulary patterns)

### 9.2 Persona rotation

Rotate personas every N months (N depends on adversarial interest: 3 months for high-risk, 12 months for low-risk).

```bash
# Burn and rotate
# 1. Document the rotation in an encrypted log
echo "$(date -u +%Y-%m-%d) Rotated persona: <old> -> <new>" >> rotation.log
gpg --symmetric --cipher-algo AES256 rotation.log
shred -uvz rotation.log

# 2. Generate new persona key + wallet (see checklist above)

# 3. Migrate monitoring queries to new persona

# 4. Never reuse the old persona's identifiers
```

### 9.3 Persona burn criteria

Burn a persona immediately if any of these occur:

- Real IP ever used to access the persona's accounts
- Persona's PGP key appears with a real-name uid
- Persona's wallet appears in unexpected contexts (someone else is using it)
- Persona is mentioned on watch forums as "burned", "opsec fail", or "deanon"
- Investigator's physical machine is compromised

---

## 10. Investigator Safety

### 10.1 When to abort

Stop the investigation immediately if:

- You encounter credible threats of physical harm to yourself or the org.
- You encounter CSAM (mandatory reporting rules apply).
- You encounter content that triggers strict-liability criminal exposure in your jurisdiction.
- Your environment fails an OPSEC check (egress leak, DNS leak, fingerprint deviation).
- Your persona is burned.

In all cases: document the trigger, secure the evidence, contact your engagement lead and (where applicable) the appropriate authorities.

### 10.2 If exposed

If you believe your investigator identity has been exposed:

1. **Stop all dark-net activity** immediately. Disconnect the investigation machine from any network.
2. **Secure the evidence vault** (move encrypted archives to offline storage).
3. **Burn the persona** (delete keys, never reuse).
4. **Document the exposure**: what was exposed, when, how, what's the likely adversary response.
5. **Notify your engagement lead**. If physical safety is at risk, contact appropriate protection.
6. **Rebuild from scratch**: new hardware, new persona, new investigation cadence.

### 10.3 Mental health

Dark-net investigation includes regular exposure to distressing content (CSAM, violence, exploitation). Normalize:
- Regular check-ins with a therapist familiar with content moderation work.
- Time-boxed sessions (max 2 hours).
- Mandatory breaks after exposure to high-distress content.
- Peer support among investigators.

Tooling is necessary but not sufficient. The human is the weakest link.

---

## 11. Marketplace & Forum Reference (as of 2026)

> **WARNING**: This table is a starting point for verification via dark.fail — NOT a static reference. Addresses rotate weekly. Verify every address immediately before visit.

| Service | Type | Access Notes |
|---------|------|--------------|
| **Breached / leak forums** | Breach-data forum | Address rotates; verify via dark.fail; PGP-required registration; high honeypot risk |
| **Major narcotics markets** | Marketplace | Address rotates; observer-only for monitoring; high law-enforcement interest; marketplaces regularly seized |
| **Major fraud-focused markets** | Marketplace | Address rotates; observer-only; high honeypot risk; never register without authorization |
| **Ransomware leak sites** (one per gang) | Leak site | Each gang has 1-N mirrors; victims listed with countdown timer; screenshots + URLs are evidence |
| **Crypto-cashout forums** | Forum | Mixers, tumblers, P2P exchange; high scam risk; observer-only |
| **Threat-actor discussion forums** | Forum | General cybercrime discussion; PGP-key rich; useful for handle pivots |
| **Paste sites** | Paste | Where new breach announcements often appear first; high churn |

For each engagement, build a current address list by:

1. Visiting `https://dark.fail` via Tor Browser.
2. Recording current addresses with timestamps.
3. Storing the list in an encrypted reference file.
4. Re-verifying before each session.

---

## 12. Integration with Adjacent Skills

### 12.1 osint (clearnet OSINT)

`skills/osint/SKILL.md` runs the clearnet side of the investigation: domain, email, subdomain, Shodan, breach, code-leak. Output of `osint` (emails, usernames, PGP keys) becomes seed input for darkweb-intel.

Workflow:
```
[osint] ─── emails, handles, PGP keys ───> [darkweb-intel] ─── .onion findings, wallet addresses ───> [synthesis]
```

### 12.2 username-profiling (clearnet handle enumeration)

`skills/username-profiling/SKILL.md` runs Maigret against 3,000+ clearnet sites. A handle that appears on clearnet (GitHub, Reddit, Twitter) often has a dark-net persona under the same handle.

Workflow:
```
[username-profiling] ─── clearnet handle ───> [darkweb-intel] ─── search handle on forums/paste sites ───> dark-net dossier
```

### 12.3 social-intelligence (mainstream discourse)

`skills/social-intelligence/SKILL.md` mines Reddit, HN, X posts about an organization. Threat actor sentiment on mainstream platforms often signals dark-net activity — actors planning an attack frequently discuss the target on clearnet forums first.

Workflow:
```
[social-intelligence] ─── "we're going after <target>" sentiment ───> [darkweb-intel] ─── search for <target> on leak sites, marketplaces ───> confirm threat
```

### 12.4 deep-research (synthesis)

`skills/deep-research/SKILL.md` is the synthesis layer. The dark-web dossier is one input; combine with clearnet OSINT, social-intelligence, and traditional threat intel for the final deliverable.

Workflow:
```
[darkweb-intel] ─┐
[osint] ─────────┼──> [deep-research] ───> executive briefing / client report
[social-intel] ──┤
[external TI] ───┘
```

### 12.5 social-engineering (defensive priority)

`skills/social-engineering/SKILL.md` is the bridge to defense: dark-net findings (leaked credentials, resentment posts, insider distress signals) should inform phishing-resistance training, not become pretext for offense.

Workflow:
```
[darkweb-intel] ─── leaked credentials, insider signals ───> [social-engineering (defensive)] ───> phishing-resistance training, insider-threat program
```

---

## 13. Closing Checklist

Before marking the investigation complete:

- [ ] All evidence encrypted at rest (`gpg --symmetric --cipher-algo AES256`)
- [ ] All `.onion` URLs in the deliverable re-verified via dark.fail within 24h of delivery
- [ ] Deliverable uses durable identifiers (PGP fingerprints, wallet addresses, screenshots) rather than URLs
- [ ] OPSEC checks run at start and end of every session (test-cases.md TC-DW-008, TC-DW-009)
- [ ] Persona contamination audit clean (test-cases.md TC-DW-010)
- [ ] Monitoring cadence defined and scheduled (cron + commercial API subscriptions)
- [ ] Whonix snapshot reverted / Tails rebooted
- [ ] Host-side traces shredded (`shred -uvz ~/.bash_history`)
- [ ] Persona rotation scheduled (if investigation ongoing)
- [ ] Investigator debrief (mental health check after high-distress content)

---

## 14. References

- **Tor Project**: [torproject.org](https://www.torproject.org)
- **Tails**: [tails.net](https://tails.net)
- **Whonix**: [whonix.org](https://www.whonix.org)
- **Ahmia**: [ahmia.fi](https://ahmia.fi)
- **dark.fail**: [dark.fail](https://dark.fail)
- **OnionScan**: [github.com/s-rah/onionscan](https://github.com/s-rah/onionscan)
- **IntelX**: [intelx.io](https://intelx.io)
- **HaveIBeenPwned**: [haveibeenpwned.com](https://haveibeenpwned.com)
- **DeHashed**: [dehashed.com](https://dehashed.com)
- **EFF Surveillance Self-Defense**: [ssd.eff.org](https://ssd.eff.org)
- **Bellingcat Online Investigation Toolkit**: [bellingcat.gitbook.io/toolkit](https://bellingcat.gitbook.io/toolkit)

---

**Related files**: `../SKILL.md`, `../payloads.md`, `../test-cases.md`
**Integration**: `skills/osint/`, `skills/username-profiling/`, `skills/social-intelligence/`, `skills/deep-research/`, `skills/social-engineering/`
