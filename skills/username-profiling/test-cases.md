# Username Profiling Test Cases

> Companion to `SKILL.md`, containing structured test cases organized by category with severity ratings.
> All commands assume a non-production investigation target and lawful authorization (engagement scope, consent, or self-audit).

---

## Statistics

| Category | Count | Severity Range |
|------|------|-----------|
| A. Discovery & Enumeration | 3 | LOW - MEDIUM |
| B. Recursive Pivot | 2 | MEDIUM - HIGH |
| C. Report Generation & Export | 2 | LOW - MEDIUM |
| D. Stealth & OPSEC | 2 | MEDIUM - HIGH |
| E. Cross-Tool Verification & Defense | 2 | MEDIUM - HIGH |
| F. Workshop Integration | 2 | MEDIUM - HIGH |
| **Total** | **13** | **LOW - HIGH** |

---

## A. Discovery & Enumeration

### TC-UP-001: Default Username Scan (Top 500 Sites)

| Field | Value |
|------|-----|
| **ID** | TC-UP-001 |
| **Name** | Default Username Scan (Top 500 Sites) |
| **Severity** | LOW |
| **Category** | Discovery & Enumeration |
| **Objective** | From a single username, identify which of the top 500 highest-traffic sites have a claimed account — fast triage before deeper investigation. |
| **Prerequisites** | Maigret installed (`pip3 install maigret`); lawful authorization for the target identity; egress via Tor or VPN recommended. |
| **Test Steps** | 1. `maigret <username> --html --json ndjson`<br>2. Inspect `reports/<username>/report_<username>.html` for the browsable dossier<br>3. Extract claimed accounts: `jq -r 'select(.status=="Claimed") | "\(.site_name)\t\(.url)"' reports/<username>_ndjson.json \| sort`<br>4. Spot-check 3 claimed URLs in a browser to confirm they are real accounts (not SEO stubs) |
| **Expected Results** | 5-50 confirmed accounts across major platforms (GitHub, Twitter/X, Reddit, Instagram, etc.); HTML report with screenshots, metadata, and links. |
| **False Positive Risk** | MEDIUM — auto-generated profile stubs, archived accounts, and soft-404s produce false "Claimed" results. Manual verification of any account that will be acted on is mandatory. |
| **Remediation (defense)** | Reduce username reuse across corporate and personal platforms; close abandoned accounts; audit profile metadata (bio, location, links) for inadvertent information leaks. |
| **Related Tools** | maigret, jq |

### TC-UP-002: Full-Coverage Scan (All 3,000+ Sites)

| Field | Value |
|------|-----|
| **ID** | TC-UP-002 |
| **Name** | Full-Coverage Scan (All 3,000+ Sites) |
| **Severity** | MEDIUM |
| **Category** | Discovery & Enumeration |
| **Objective** | Maximize platform coverage to surface niche accounts (hobby forums, regional platforms, dating sites, etc.) invisible to default scan. |
| **Prerequisites** | Maigret installed; Tor or rotating proxy (3,000+ requests from one IP triggers rate limiting); ~30-60 min wall-clock budget. |
| **Test Steps** | 1. Start Tor: `sudo service tor start`<br>2. Verify egress: `curl --socks5-hostname 127.0.0.1:9050 https://api.ipify.org`<br>3. Run full scan: `maigret <username> -a --tor-proxy socks5://127.0.0.1:9050 --html --graph --json ndjson --timeout 30`<br>4. Extract discovered pivot identities: `jq -r 'select(.status=="Claimed") \| .extracted.usernames[]? // empty' reports/<username>_ndjson.json \| sort -u > discovered_usernames.txt`<br>5. Count: `wc -l discovered_usernames.txt` |
| **Expected Results** | 20-200 claimed accounts across major + niche + regional platforms; discovered pivot identities feed TC-UP-004 / TC-UP-005. |
| **False Positive Risk** | HIGH — niche sites have less reliable detection rules; cross-verify any unexpected finding with Sherlock or WhatsMyName before acting. |
| **Remediation (defense)** | Identify and close forgotten niche accounts; rotate usernames if reuse is detected across sensitive contexts (work vs personal vs dating). |
| **Related Tools** | maigret, jq, tor |

### TC-UP-003: Tag-Filtered Niche Scan

| Field | Value |
|------|-----|
| **ID** | TC-UP-003 |
| **Name** | Tag-Filtered Niche Scan |
| **Severity** | LOW |
| **Category** | Discovery & Enumeration |
| **Objective** | When only a specific platform category matters (photo-sharing, dating, dev, finance), avoid scanning 3,000 sites and focus on the relevant subset. |
| **Prerequisites** | Maigret installed; known target category (e.g., photo, dating, dev, us). |
| **Test Steps** | 1. `maigret <username> --tags photo --html`<br>2. `maigret <username> --tags dating --html`<br>3. `maigret <username> --tags us --html`<br>4. Combine tags: `maigret <username> --tags photo,us --html`<br>5. Review the generated HTML reports per tag run |
| **Expected Results** | Focused results: e.g., dating-only run surfaces Tinder/OkCupid/Bumble-style hits without noise from GitHub/Reddit. Faster wall-clock (2-5 min per tag set). |
| **False Positive Risk** | MEDIUM — same auto-stub issue as TC-UP-001 but limited to the filtered site set, so smaller blast radius. |
| **Remediation (defense)** | Same as TC-UP-001; additionally, audit which platforms your team's handles appear on by category. |
| **Related Tools** | maigret |

---

## B. Recursive Pivot

### TC-UP-004: Recursive Pivot from Discovered Usernames

| Field | Value |
|------|-----|
| **ID** | TC-UP-004 |
| **Name** | Recursive Pivot from Discovered Usernames |
| **Severity** | HIGH |
| **Category** | Recursive Pivot |
| **Objective** | Treat Maigret's first-pass output as a graph, not a list — recurse on every newly discovered username to surface the full identity graph. |
| **Prerequisites** | TC-UP-002 completed; `discovered_usernames.txt` populated; depth limit decided (recommend ≤ 2 to avoid runaway). |
| **Test Steps** | 1. `head -5 discovered_usernames.txt \| while read user; do maigret "$user" --html --tags us --timeout 15; done`<br>2. For each new discovered-username report, repeat extraction: `jq -r 'select(.status=="Claimed") \| .extracted.usernames[]? // empty' reports/$u/*_ndjson.json \| sort -u`<br>3. Build the cumulative identity graph: `cat reports/*/report_*_ndjson.json \| jq -r 'select(.status=="Claimed") \| "\(.site_username)\t\(.site_name)"' \| sort -u > identity_graph.tsv`<br>4. Manually inspect the graph for nodes that bridge to a real name, email, or phone |
| **Expected Results** | Identity graph expands from 1 seed to N confirmed accounts across multiple usernames; pivot points reveal real name, email, location, employer. |
| **False Positive Risk** | HIGH — recursive runs compound false positives; cross-verify pivot edges before treating them as the same human. Look for corroborating signals (same avatar, bio text, timezone). |
| **Remediation (defense)** | Avoid linking identities across platforms (no shared avatar, no shared bio, no cross-links in profiles); treat every account as potentially discoverable from every other account. |
| **Related Tools** | maigret, jq |

### TC-UP-005: Profile-Page Parse & Auto-Pivot

| Field | Value |
|------|-----|
| **ID** | TC-UP-005 |
| **Name** | Profile-Page Parse & Auto-Pivot |
| **Severity** | MEDIUM |
| **Category** | Recursive Pivot |
| **Objective** | From one known profile URL (e.g., a leaked GitHub account), let Maigret parse the page, extract embedded usernames/IDs, and recurse — without manually extracting handles. |
| **Prerequisites** | Maigret installed; one known profile URL (GitHub, Keybase, personal blog with bio links). |
| **Test Steps** | 1. `maigret --parse https://github.com/<username> --html --graph`<br>2. `maigret --parse https://keybase.io/<username> --html --graph`<br>3. `maigret --parse https://x.com/<username> --html --graph`<br>4. Inspect `--graph` output to see Maigret's auto-discovered identity links<br>5. Cross-check discovered links against TC-UP-004 manual pivot output |
| **Expected Results** | Maigret auto-discovers 1-10 linked identities per starting profile; graph output visualizes the relationship tree; reduces manual handle-extraction work. |
| **False Positive Risk** | MEDIUM — parsing rules may extract display names or unrelated mentions as candidate usernames; verify each discovered edge. |
| **Remediation (defense)** | Audit profile bios for inadvertent cross-platform links; remove personal site links from professional profiles when investigating a sensitive topic. |
| **Related Tools** | maigret |

---

## C. Report Generation & Export

### TC-UP-006: Multi-Format Dossier Generation

| Field | Value |
|------|-----|
| **ID** | TC-UP-006 |
| **Name** | Multi-Format Dossier Generation |
| **Severity** | LOW |
| **Category** | Report Generation |
| **Objective** | Produce audience-appropriate reports: HTML for browsing, PDF for clients, XMind for analysts, NDJSON for downstream tooling. |
| **Prerequisites** | Maigret installed; for PDF: `pip3 install 'maigret[pdf]'` + system libs (`libcairo2 libpango-1.0-0`). |
| **Test Steps** | 1. `maigret <username> --html --pdf --xmind --graph --json ndjson --csv --txt`<br>2. Open `report_<username>.html` in a browser — confirm it renders the browsable dossier<br>3. Open `report_<username>.pdf` — confirm printable layout<br>4. Open `graph_<username>.html` — confirm interactive D3 graph<br>5. Open `.xmind` in XMind 8 — confirm mindmap (note: NOT XMind 2022+ compatible)<br>6. Verify NDJSON parses: `jq '.[0]' report_<username>_ndjson.json`<br>7. Verify CSV opens in a spreadsheet |
| **Expected Results** | All 7 formats generate without errors; each format suits its intended audience (HTML=browsing, PDF=executive, XMind=analyst, NDJSON=scripting). |
| **False Positive Risk** | LOW — format generation is deterministic; risk is in the underlying data quality, not the format itself. |
| **Remediation (defense)** | N/A — this is an output format exercise. |
| **Related Tools** | maigret |

### TC-UP-007: NDJSON Parsing for Downstream Pipelines

| Field | Value |
|------|-----|
| **ID** | TC-UP-007 |
| **Name** | NDJSON Parsing for Downstream Pipelines |
| **Severity** | LOW |
| **Category** | Report Generation |
| **Objective** | Convert Maigret's NDJSON into structured data for graph databases, SIEM ingestion, or custom dashboards. |
| **Prerequisites** | TC-UP-002 or TC-UP-001 completed; `jq` installed. |
| **Test Steps** | 1. All claimed accounts: `jq -r 'select(.status=="Claimed") \| "\(.site_name)\t\(.url)"' reports/<username>_ndjson.json \| sort`<br>2. All discovered emails: `jq -r 'select(.status=="Claimed") \| .extracted.emails[]? // empty' reports/<username>_ndjson.json \| sort -u`<br>3. All discovered usernames: `jq -r 'select(.status=="Claimed") \| .extracted.usernames[]? // empty' reports/<username>_ndjson.json \| sort -u`<br>4. Keyword-matched sites: `jq -r 'select(.keywords_matched \| length > 0) \| "\(.site_name): \(.keywords_matched)"' reports/<username>_ndjson.json`<br>5. Count per category: `jq -r 'select(.status=="Claimed") \| .tags[]?' reports/<username>_ndjson.json \| sort \| uniq -c \| sort -rn` |
| **Expected Results** | Clean tabular/structured output suitable for grep, sort, graph DB import (Neo4j, etc.), or spreadsheet. |
| **False Positive Risk** | LOW — `jq` is deterministic; risk is in upstream Maigret data quality. |
| **Remediation (defense)** | N/A — pipeline plumbing. |
| **Related Tools** | maigret, jq |

---

## D. Stealth & OPSEC

### TC-UP-008: Tor-Routed Stealth Scan

| Field | Value |
|------|-----|
| **ID** | TC-UP-008 |
| **Name** | Tor-Routed Stealth Scan |
| **Severity** | MEDIUM |
| **Category** | Stealth & OPSEC |
| **Objective** | Hide the operator's real IP from 3,000+ target sites; required for any sensitive investigation. |
| **Prerequisites** | Tor daemon installed (`sudo apt install tor`); Tor running (`sudo service tor start`); Maigret installed. |
| **Test Steps** | 1. Start Tor: `sudo service tor start`<br>2. Verify daemon: `curl --socks5-hostname 127.0.0.1:9050 https://api.ipify.org`<br>3. Confirm the IP is NOT your real egress IP<br>4. Run scan: `maigret <username> -a --tor-proxy socks5://127.0.0.1:9050 --html --timeout 30`<br>5. After completion, re-verify egress IP (should rotate)<br>6. Confirm reports generated correctly despite Tor latency |
| **Expected Results** | All Maigret traffic egresses via Tor; real IP never appears in target site logs; scan completes successfully (slower, ~2-3x direct connection). |
| **False Positive Risk** | LOW — OPSEC control, not a finding. Risk is in *not* using Tor: 3,000+ sites log your IP. |
| **Remediation (defense)** | N/A — this is the defense (for the operator). Target-side: be aware that someone scanning your accounts via Tor is intentionally hiding identity. |
| **Related Tools** | maigret, tor |

### TC-UP-009: Cloudflare Bypass via FlareSolverr

| Field | Value |
|------|-----|
| **ID** | TC-UP-009 |
| **Name** | Cloudflare Bypass via FlareSolverr |
| **Severity** | HIGH |
| **Category** | Stealth & OPSEC |
| **Objective** | Access Cloudflare-protected sites that block non-browser clients (and datacenter IPs), by offloading JavaScript challenge solving to FlareSolverr. |
| **Prerequisites** | Docker installed; FlareSolverr image pulled; Maigret installed with `--cloudflare-bypass` support. |
| **Test Steps** | 1. Start FlareSolverr: `docker run -d -p 8191:8191 --name flaresolverr ghcr.io/flaresolverr/flaresolverr:latest`<br>2. Verify: `curl http://localhost:8191`<br>3. Run Maigret with bypass: `maigret --cloudflare-bypass <username> --html`<br>4. Compare claimed-account count to a non-bypass run; identify which sites required the bypass |
| **Expected Results** | Cloudflare-protected sites now return real account status instead of 403/challenge pages; some previously "Unknown" sites become "Claimed" or "Available". |
| **False Positive Risk** | MEDIUM — FlareSolverr solves challenges but the underlying detection logic remains Maigret's; SEO stubs still produce false positives. |
| **Remediation (defense)** | Cloudflare is a useful defense-in-depth layer but not a guarantee — assume a determined investigator can bypass. Layer with account-takedown monitoring. |
| **Related Tools** | maigret, flaresolverr, docker |

---

## E. Cross-Tool Verification & Defense

### TC-UP-010: Multi-Tool Cross-Verification (Maigret + Sherlock + WhatsMyName)

| Field | Value |
|------|-----|
| **ID** | TC-UP-010 |
| **Name** | Multi-Tool Cross-Verification |
| **Severity** | MEDIUM |
| **Category** | Cross-Tool Verification |
| **Objective** | Rule out Maigret false positives by running Sherlock and WhatsMyName independently and diffing results. |
| **Prerequisites** | Maigret, Sherlock (`pip3 install sherlock-project`), WhatsMyName installed; one username target. |
| **Test Steps** | 1. `maigret <username> -a --json ndjson`<br>2. `sherlock <username> --json --output sherlock_<username>.json`<br>3. `whatsmyname -u <username> --format json --output wmn_<username>.json`<br>4. Diff Maigret vs Sherlock: `comm -23 <(jq -r '.site' reports/<username>_ndjson.json \| sort -u) <(jq -r 'keys[]' sherlock_<username>.json \| sort -u) > maigret_only.txt`<br>5. Manually verify each site in `maigret_only.txt` (these are most likely false positives) |
| **Expected Results** | Overlap of 60-90% across tools (common sites all detect); Maigret-only sites are verification candidates; sites only Sherlock/WhatsMyName flag are bonus coverage. |
| **False Positive Risk** | LOW after this test — manual verification eliminates the remaining false positives. |
| **Remediation (defense)** | N/A — verification methodology. |
| **Related Tools** | maigret, sherlock, whatsmyname, jq |

### TC-UP-011: Self-Audit Username Hygiene (Defense)

| Field | Value |
|------|-----|
| **ID** | TC-UP-011 |
| **Name** | Self-Audit Username Hygiene (Defense) |
| **Severity** | HIGH |
| **Category** | Defense / Self-Audit |
| **Objective** | From the defensive side, run Maigret on your own executive team's handles to identify abandoned accounts, impersonators, and inadvertent metadata leaks. |
| **Prerequisites** | Authorization from the audited individuals (or HR/legal sign-off); list of executive handles; Maigret installed. |
| **Test Steps** | 1. `for u in ceo_handle cto_handle ciso_handle; do maigret "$u" -a --html --json ndjson --tags us; done`<br>2. For each executive report, extract: `jq -r 'select(.status=="Claimed") \| "\(.site_name)\t\(.url)\t\(.extracted.bio // "")"' reports/<handle>_ndjson.json`<br>3. Flag accounts that:<br>   - The executive doesn't recognize (potential impersonation or forgotten account)<br>   - Contain location/employer info in bios (metadata leak)<br>   - Use the same avatar across work and personal platforms (correlation risk)<br>4. Generate remediation ticket per flagged account: close, harden, or report-as-impersonation |
| **Expected Results** | Inventory of all accounts discoverable from executive handles; prioritized remediation list (impersonation > forgotten account > metadata leak > acceptable exposure). |
| **False Positive Risk** | MEDIUM — must verify each "unrecognized" account is actually unrecognized by the executive before flagging as impersonation. |
| **Remediation (defense)** | Close abandoned accounts; report impersonations to platform trust & safety; sanitize bios; rotate usernames if work/personal correlation is unacceptable; institute quarterly Maigret audits. |
| **Related Tools** | maigret, jq |

### TC-UP-012: Maigret 200+ Site Enumeration with JSON Validation

| Field | Value |
|------|-----|
| **ID** | TC-UP-012 |
| **Name** | Maigret 200+ Site Enumeration with JSON Validation |
| **Severity** | MEDIUM |
| **Category** | Workshop Integration |
| **Objective** | Validate end-to-end Maigret workshop workflow against a sample alias: stand up isolated venv, run full `-a` sweep via Tor, parse NDJSON output programmatically, verify claimed-account count is non-trivial (200+ enumeration attempts across the site DB), and confirm every claimed record contains the required JSON fields for downstream pipeline ingestion. |
| **Prerequisites** | Kali Linux 2025-2; Python 3.11+; isolated venv (`python3 -m venv ~/venvs/osint`); `pip install maigret==0.4.0 sherlock-project whatsmyname holehe requests jq`; Tor daemon running; 60-minute wall-clock budget; a sample alias (self-handle or authorized test target). |
| **Test Steps** | 1. Stand up isolated venv: `python3 -m venv ~/venvs/osint && source ~/venvs/osint/bin/activate`<br>2. Install pinned toolchain: `pip install maigret==0.4.0 sherlock-project==0.14.4 whatsmyname holehe requests rich`<br>3. Verify install: `maigret --version && sherlock --version`<br>4. Verify Tor egress: `curl --socks5-hostname 127.0.0.1:9050 https://api.ipify.org`<br>5. Run full sweep: `maigret <sample_alias> -a --tor-proxy socks5://127.0.0.1:9050 --html --graph --json ndjson --csv --tags us --timeout 30 --max-connections 15 --retries 2 --no-color`<br>6. Count enumeration attempts: `jq -r '.site_name' reports/<alias>_ndjson.json \| wc -l` — expect 2000+ lines (site DB enumeration scope)<br>7. Count claimed: `jq -r 'select(.status=="Claimed")' reports/<alias>_ndjson.json \| wc -l`<br>8. Validate JSON schema on claimed records: `jq -r 'select(.status=="Claimed") \| [.site_name, .url, .site_username, .extracted] \| @tsv' reports/<alias>_ndjson.json \| head -5`<br>9. Verify all claimed records have non-empty `url`: `jq -r 'select(.status=="Claimed" and (.url \| length == 0))' reports/<alias>_ndjson.json \| wc -l` — expect 0<br>10. Run cross-tool verification: `sherlock <sample_alias> --json --output sherlock_check.json && whatsmyname -u <sample_alias> --format json --output wmn_check.json`<br>11. Confirm at least 60% overlap between Maigret and Sherlock claimed sites (sanity threshold) |
| **Expected Results** | Full enumeration scope visible in NDJSON (2000+ site records touched); 5-50 claimed accounts for a real-world alias; every claimed record has valid `site_name`, `url`, and `extracted` fields; HTML and graph reports generated; cross-tool overlap >= 60% on common platforms (GitHub, Twitter/X, Reddit). |
| **False Positive Risk** | MEDIUM — the NDJSON parses cleanly regardless of underlying claim accuracy; FP risk is in the claims themselves, addressed by cross-verification in step 10-11. |
| **Remediation (defense)** | Run the same workflow against your own executive handles quarterly; the enumeration-scope count tells you how many platforms could expose your team, regardless of claim count. |
| **Related Tools** | maigret, sherlock, whatsmyname, jq, tor |

### TC-UP-013: Email-to-Username Pivot Chain Produces Correlated Dossier

| Field | Value |
|------|-----|
| **ID** | TC-UP-013 |
| **Name** | Email-to-Username Pivot Chain Produces Correlated Dossier |
| **Severity** | HIGH |
| **Category** | Workshop Integration |
| **Objective** | Validate the complete email-to-username pivot pipeline: from a single seed email, run HaveIBeenPwned breach search, Hunter.io domain search, GitHub commit-email search, and Gravatar lookup; collect every discovered username variant; feed those back into Maigret; produce a single correlated dossier that maps the email to N confirmed accounts with confidence ratings. |
| **Prerequisites** | Maigret + Sherlock + WhatsMyName installed; HIBP_API_KEY, HUNTER_KEY env vars set (or skip those steps if testing free path only); a seed email for an authorized target (own email is safest); Tor daemon running; 30-minute budget. |
| **Test Steps** | 1. Seed: `SEED_EMAIL=j.doe@example.com`<br>2. HIBP breaches: `python3 hibp_client.py "$SEED_EMAIL" > hibp.json && jq '.breaches[] \| .Name' hibp.json`<br>3. Hunter verify: `python3 hunter_client.py verify "$SEED_EMAIL" > hunter.json && jq '.data.status' hunter.json` (expect "valid")<br>4. Hunter domain search: `python3 hunter_client.py search example.com > hunter_domain.json && jq '.data.emails[] \| .value' hunter_domain.json`<br>5. GitHub commits: `curl -s "https://api.github.com/search/commits?q=author-email:$SEED_EMAIL" -H "Accept: application/vnd.github.cloak-preview" \| jq '.items[]? \| .repository.full_name'`<br>6. Gravatar: `HASH=$(printf "%s" "$SEED_EMAIL" \| tr '[:upper:]' '[:lower:]' \| md5sum \| awk '{print $1}'); curl -s -o grav.jpg "https://www.gravatar.com/avatar/${HASH}?s=400&d=404"; file grav.jpg`<br>7. Generate username candidates from email local-part: `python3 username_candidates.py "$SEED_EMAIL" > candidates.txt`<br>8. Run Maigret on each candidate (cap 5): `head -5 candidates.txt \| while read u; do maigret "$u" --html --json ndjson --tags us --timeout 15; done`<br>9. Aggregate all claimed accounts across runs: `cat reports/*_ndjson.json \| jq -r 'select(.status=="Claimed") \| [.site_username, .site_name, .url] \| @tsv' \| sort -u > pivot_chain.tsv`<br>10. Cross-verify with Sherlock: `sherlock "$(head -1 candidates.txt)" --json --output pivot_check.json`<br>11. Produce correlated dossier: for each (username, site) tuple, rate confidence HIGH if confirmed by >= 2 tools, MEDIUM if 1 tool, LOW otherwise<br>12. Verify the dossier contains at least one cross-platform confirmation (same username on 2+ sites) |
| **Expected Results** | Seed email resolves to: at least one breach record (HIBP), a delivery status from Hunter, 0-N GitHub commits, optional Gravatar image, and 1-5 username candidates that Maigret can scan. The final dossier correlates at least one username across multiple platforms (cross-platform identity confirmation). Confidence ratings distribute as: ~30% HIGH (multi-tool confirmed), ~50% MEDIUM (single-tool), ~20% LOW (Maigret-only). |
| **False Positive Risk** | HIGH — pivoting across data sources compounds uncertainty. A breach record may be stale (email closed years ago); GitHub commit search may surface repos that share the email by coincidence; Gravatar may return a default image (file command says "ASCII text" instead of JPEG). Mitigate by requiring cross-tool confirmation for any HIGH-confidence claim. |
| **Remediation (defense)** | Email reuse across personal and corporate contexts is the root cause — once an email leaks in a breach, every account that used it for signup becomes pivot-discoverable. Use email aliases (SimpleLogin, Apple Hide My Email) for each service; rotate credentials after any breach notification. |
| **Related Tools** | maigret, sherlock, hibp, hunter, github-api, gravatar, jq |

---

## Summary Table

| ID | Name | Severity | Category |
|------|------|----------|----------|
| TC-UP-001 | Default Username Scan (Top 500 Sites) | LOW | Discovery |
| TC-UP-002 | Full-Coverage Scan (All 3,000+ Sites) | MEDIUM | Discovery |
| TC-UP-003 | Tag-Filtered Niche Scan | LOW | Discovery |
| TC-UP-004 | Recursive Pivot from Discovered Usernames | HIGH | Pivot |
| TC-UP-005 | Profile-Page Parse & Auto-Pivot | MEDIUM | Pivot |
| TC-UP-006 | Multi-Format Dossier Generation | LOW | Report |
| TC-UP-007 | NDJSON Parsing for Downstream Pipelines | LOW | Report |
| TC-UP-008 | Tor-Routed Stealth Scan | MEDIUM | Stealth |
| TC-UP-009 | Cloudflare Bypass via FlareSolverr | HIGH | Stealth |
| TC-UP-010 | Multi-Tool Cross-Verification | MEDIUM | Verification |
| TC-UP-011 | Self-Audit Username Hygiene (Defense) | HIGH | Defense |
| TC-UP-012 | Maigret 200+ Site Enumeration with JSON Validation | MEDIUM | Workshop |
| TC-UP-013 | Email-to-Username Pivot Chain Produces Correlated Dossier | HIGH | Workshop |

---

**Related files**: `SKILL.md`, `payloads.md`, `guides/maigret-username-dossier.md`
**Maigret upstream**: [github.com/soxoj/maigret](https://github.com/soxoj/maigret)
