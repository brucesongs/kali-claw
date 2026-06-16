# Dark Web Intelligence Test Cases

> Companion to `SKILL.md`, containing structured test cases organized by category with severity ratings.
> All commands assume lawful authorization (engagement scope, court order, or self-audit) and Tor-routed egress via Tails/Whonix or a dedicated VM.

---

## Statistics

| Category | Count | Severity Range |
|------|------|-----------|
| A. Access & Discovery | 3 | LOW - HIGH |
| B. Marketplace Monitoring | 2 | MEDIUM - HIGH |
| C. Threat Actor Profiling | 2 | MEDIUM - HIGH |
| D. OPSEC Verification | 3 | HIGH |
| E. Defense & Counter-OSINT | 2 | MEDIUM - HIGH |
| **Total** | **12** | **LOW - HIGH** |

---

## A. Access & Discovery

### TC-DW-001: Hardened Tor Access Setup

| Field | Value |
|------|-----|
| **ID** | TC-DW-001 |
| **Name** | Hardened Tor Access Setup |
| **Severity** | HIGH |
| **Category** | Access & Discovery |
| **Objective** | Provision a Tor-routed investigation environment with verified egress, DNS leak protection, and (optionally) obfs4/Snowflake bridges for censored networks. |
| **Prerequisites** | Tor installed (`sudo apt install tor`); Tails/Whonix recommended for sensitive work; obfs4proxy and snowflake-client optional for bridged access. |
| **Test Steps** | 1. `sudo service tor start && sleep 3`<br>2. Verify egress: `REAL=$(curl -s https://api.ipify.org); TOR=$(curl -s --socks5-hostname 127.0.0.1:9050 https://api.ipify.org); [ "$REAL" = "$TOR" ] && echo FAIL \|\| echo PASS`<br>3. Verify exit geolocation: `curl -s --socks5-hostname 127.0.0.1:9050 https://ifconfig.me/json \| jq '{ip, country, city}'`<br>4. Verify DNS resolver: `cat /etc/resolv.conf` (should be 127.0.0.1 in Tails/Whonix)<br>5. If Tor is blocked, configure obfs4 bridge in `/etc/tor/torrc` and `sudo service tor restart` |
| **Expected Results** | Tor IP differs from real IP; exit geolocation matches a Tor exit relay country; DNS resolver is local (Tor DNS); bridges restore connectivity when direct Tor is blocked. |
| **False Positive Risk** | LOW — control validation. The real failure mode is *not* running this check before an investigation session. |
| **Remediation (defense)** | Always run this check at the start of every session. For sensitive work, use Tails (amnesic) or Whonix (snapshot-revert) rather than a bare-Tor VM. |
| **Related Tools** | tor, curl, jq, dnsutils, obfs4proxy |

### TC-DW-002: .onion Service Resolution & Verification

| Field | Value |
|------|-----|
| **ID** | TC-DW-002 |
| **Name** | .onion Service Resolution & Verification |
| **Severity** | MEDIUM |
| **Category** | Access & Discovery |
| **Objective** | Verify a discovered `.onion` URL is reachable, v3 (not deprecated v2), and consistent with its claimed identity via dark.fail uptime monitoring. |
| **Prerequisites** | TC-DW-001 completed; one or more `.onion` URLs (from Ahmia/Torch or from a client). |
| **Test Steps** | 1. Validate format: `echo "<onion>" \| grep -qE 'https?://[a-z2-7]{56}\.onion' && echo "v3 valid" \|\| echo "invalid or v2"`<br>2. Check uptime on dark.fail: `curl -s --socks5-hostname 127.0.0.1:9050 https://dark.fail \| grep -i "<service_name>"`<br>3. Direct fetch: `curl -s -o /dev/null -w "%{http_code}" --socks5-hostname 127.0.0.1:9050 --max-time 120 "http://<onion>.onion"`<br>4. Capture response headers: `curl -s -I --socks5-hostname 127.0.0.1:9050 --max-time 120 "http://<onion>.onion"` |
| **Expected Results** | URL is 56-char v3 (not 16-char v2); dark.fail shows the service as online in recent polling; HTTP response is 2xx/3xx/4xx (not a timeout); server headers are reasonable for the claimed service type. |
| **False Positive Risk** | MEDIUM — services go offline frequently; a service reported online 12h ago may now be down. A 16-char v2 address is a strong honeypot/dead-service indicator. |
| **Remediation (defense)** | Never trust a static list of `.onion` URLs; always verify via dark.fail immediately before visit. Treat v2 (16-char) addresses as dead or honeypot. |
| **Related Tools** | tor, curl, dark.fail |

### TC-DW-003: Ahmia Multi-Engine Search

| Field | Value |
|------|-----|
| **ID** | TC-DW-003 |
| **Name** | Ahmia Multi-Engine Search (Clearnet + Onion) |
| **Severity** | LOW |
| **Category** | Access & Discovery |
| **Objective** | Discover `.onion` services mentioning a target term by querying both Ahmia clearnet (fast, exposes IP to indexer) and Ahmia onion mirror (full anonymity). |
| **Prerequisites** | TC-DW-001 completed; one target search term (brand, handle, email). |
| **Test Steps** | 1. URL-encode the term: `ENC=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "<term>")`<br>2. Clearnet Ahmia: `curl -s "https://ahmia.fi/search/?q=${ENC}" \| grep -oE 'https?://[a-z2-7]{56}\.onion' \| sort -u > ahmia_clearnet.txt`<br>3. Onion Ahmia: `curl -s --socks5-hostname 127.0.0.1:9050 "http://juhanurmihxlp77nkq76byazc4y2sphl4a5hfo3hxnlhkbgz7q6fqd.onion/search/?q=${ENC}" \| grep -oE 'https?://[a-z2-7]{56}\.onion' \| sort -u > ahmia_onion.txt`<br>4. Diff: `comm -3 ahmia_clearnet.txt ahmia_onion.txt`<br>5. Aggregate: `sort -u ahmia_clearnet.txt ahmia_onion.txt \| uniq -c \| sort -rn \| head -20` |
| **Expected Results** | 0-100 unique v3 `.onion` URLs per engine; onion-Ahmia often surfaces results the clearnet indexer skips; the diff identifies engine-specific blind spots. |
| **False Positive Risk** | MEDIUM — Ahmia indexes stale and honeypot pages; not every result is a real, current service. Manual verification of high-priority hits is required. |
| **Remediation (defense)** | Cross-verify high-priority hits with Torch and OnionScan before treating them as actionable intelligence. |
| **Related Tools** | tor, curl, python3 |

---

## B. Marketplace Monitoring

### TC-DW-004: IntelX Phonebook & Intelligent Search

| Field | Value |
|------|-----|
| **ID** | TC-DW-004 |
| **Name** | IntelX Phonebook & Intelligent Search |
| **Severity** | MEDIUM |
| **Category** | Marketplace Monitoring |
| **Objective** | Use IntelX APIs to enumerate related identifiers (emails, usernames, hashes) for a seed target, and to full-text search across dark-net listings, paste sites, and breach corpora. |
| **Prerequisites** | IntelX API key; TC-DW-001 completed; seed target (email, domain, or handle). |
| **Test Steps** | 1. Phonebook search: `curl -s "https://2.intelx.io/phonebook/search?k=<KEY>" -H "Content-Type: application/json" -d '{"term":"<target>","maxresults":100,"media":0}' \| jq '.selectors[]?.selectorvalue' \| sort -u`<br>2. Initiate intelligent search: `ID=$(curl -s "https://2.intelx.io/intelligent/search?k=<KEY>" -H "Content-Type: application/json" -d '{"term":"<target>","maxresults":100,"sort":1}' \| jq -r '.id')`<br>3. Poll for results: `sleep 5; curl -s "https://2.intelx.io/intelligent/search/result?k=<KEY>&id=$ID&limit=100" \| jq '.selectors[] \| {selectorvalue, type, source}'`<br>4. Filter for `.onion` sources: `... \| jq '. \| select(.source \| test("onion"))'` |
| **Expected Results** | Phonebook returns 0-100 related identifiers per seed; intelligent search returns full-text hits with source attribution; some hits link to `.onion` URLs that become Phase 3 enumeration targets. |
| **False Positive Risk** | MEDIUM — IntelX indexes old and stale data; some hits reference taken-down services or repackaged breach data. Verify before treating as current. |
| **Remediation (defense)** | Combine IntelX results with manual Tor Browser verification of any high-priority `.onion` source before including in a deliverable. |
| **Related Tools** | curl, jq, IntelX API |

### TC-DW-005: Manual Marketplace Enumeration (Read-Only)

| Field | Value |
|------|-----|
| **ID** | TC-DW-005 |
| **Name** | Manual Marketplace Enumeration (Read-Only Observer) |
| **Severity** | HIGH |
| **Category** | Marketplace Monitoring |
| **Objective** | Enumerate whether a target brand, product, or executive appears in a dark-net marketplace's listings, strictly as an observer — no account creation, no purchase, no vendor contact. |
| **Prerequisites** | Lawful authorization for monitoring; TC-DW-001 completed in Tails/Whonix; verified marketplace `.onion` (via dark.fail); encrypted evidence vault. |
| **Test Steps** | 1. Verify current marketplace `.onion`: `curl -s --socks5-hostname 127.0.0.1:9050 https://dark.fail \| grep -i market`<br>2. In Tor Browser (manual), navigate to the verified `.onion`<br>3. Search for target brand/product/handle<br>4. For each match, capture: listing URL, vendor profile URL, vendor PGP fingerprint, Monero wallet address, screenshot, UTC timestamp<br>5. Encrypt artifacts: `tar czf market_evidence_$(date -u +%Y%m%d).tar.gz evidence/; gpg --symmetric --cipher-algo AES256 market_evidence_$(date -u +%Y%m%d).tar.gz; shred -uvz market_evidence_$(date -u +%Y%m%d).tar.gz`<br>6. Limit session to 30-60 min; rotate persona between marketplaces |
| **Expected Results** | Evidence vault (encrypted) containing screenshots, PGP fingerprints, and wallet addresses for any matching listings — sufficient for client briefing without investigator identity exposure. |
| **False Positive Risk** | HIGH — listings can be fraudulent (vendor selling non-existent data); honeypot marketplaces may capture investigator fingerprints; even observer-only access generates logs the marketplace operator can analyze. |
| **Remediation (defense)** | Observer role only. Never log in, never purchase, never message vendors. Rotate personas between marketplaces. If persona contamination is suspected, burn and rotate. |
| **Related Tools** | Tor Browser, dark.fail, gpg, shred |

---

## C. Threat Actor Profiling

### TC-DW-006: Handle Correlation Across Forums

| Field | Value |
|------|-----|
| **ID** | TC-DW-006 |
| **Name** | Handle Correlation Across Forums & Paste Sites |
| **Severity** | HIGH |
| **Category** | Threat Actor Profiling |
| **Objective** | From a single forum handle, discover all other communities where the same handle appears — building the actor's identity graph across the dark-net. |
| **Prerequisites** | TC-DW-001 completed; one known forum handle; list of forum `.onion` addresses (verified via dark.fail). |
| **Test Steps** | 1. Define forum list: `FORUMS=("<forum1>.onion" "<forum2>.onion" "<forum3>.onion")`<br>2. Sweep: `for f in "${FORUMS[@]}"; do echo "=== $f ==="; curl -s --socks5-hostname 127.0.0.1:9050 "http://$f/search?q=<handle>" \| grep -oE 'href="[^"]*"' \| grep -iE 'post\|thread\|profile' \| head -10; done > handle_corpus.html`<br>3. Ahmia sweep for handle: `curl -s "https://ahmia.fi/search/?q=<handle>" \| grep -oE 'https?://[a-z2-7]{56}\.onion' \| sort -u`<br>4. For each forum where handle appears, scrape profile page for: PGP key, wallet addresses, prior handles, "also on" references |
| **Expected Results** | Handle appears on 0-N forums; each appearance exposes a profile page with pivot identifiers (PGP, wallets, prior handles). The union of these pivots forms the actor's identity graph. |
| **False Positive Risk** | HIGH — handle reuse across actors is common (handles like "shadow", "phantom", etc.); corroborate with PGP key reuse, wallet reuse, or behavioral fingerprinting before asserting same actor. |
| **Remediation (defense)** | Corroborate each pivot edge with at least one independent identifier (same PGP key, same wallet, same behavioral marker). Treat handle-only matches as low-confidence leads. |
| **Related Tools** | tor, curl, Ahmia |

### TC-DW-007: PGP Key & Monero Wallet Pivot

| Field | Value |
|------|-----|
| **ID** | TC-DW-007 |
| **Name** | PGP Key & Monero Wallet Pivot |
| **Severity** | MEDIUM |
| **Category** | Threat Actor Profiling |
| **Objective** | From a known PGP fingerprint or Monero wallet address, find every other community where the same identifier appears — high-confidence pivots because actors rarely rotate keys/wallets. |
| **Prerequisites** | TC-DW-006 completed; at least one PGP fingerprint (40 hex chars) or Monero wallet (95 chars starting with 4) extracted from a forum profile. |
| **Test Steps** | 1. PGP key lookup: `gpg --keyserver hkps://keys.openpgp.org --search-keys "<handle>"; gpg --keyserver hkps://keyserver.ubuntu.com --search-keys "<handle>"`<br>2. Inspect uids: `gpg --list-keys --with-sig-list "<fingerprint>"` — each uid is a pivot to another community<br>3. Wallet pivot — search the wallet address across forum posts and marketplace vendor profiles: `curl -s --socks5-hostname 127.0.0.1:9050 "http://<forum>.onion/search?q=<wallet>" \| grep -c "<wallet>"`<br>4. Repeat Step 3 across multiple forums<br>5. Aggregate: each community where the same PGP/wallet appears = high-confidence same-actor attribution |
| **Expected Results** | PGP key reveals 0-N uids beyond the original forum; wallet appears in 0-N other forums/marketplaces. Each new appearance is a high-confidence pivot. |
| **False Positive Risk** | LOW — actors rarely rotate PGP keys or wallets. False positives mainly arise from shared donation addresses (legitimate shared wallets) or key reuse by a different person sharing the same uid domain. |
| **Remediation (defense)** | Combine PGP and wallet pivots with behavioral fingerprinting (TC-DW-006) for highest confidence. If PGP and wallet disagree, one of them is borrowed/stolen. |
| **Related Tools** | gpg, tor, curl |

---

## D. OPSEC Verification

### TC-DW-008: Egress & DNS Leak Verification

| Field | Value |
|------|-----|
| **ID** | TC-DW-008 |
| **Name** | Egress & DNS Leak Verification |
| **Severity** | HIGH |
| **Category** | OPSEC Verification |
| **Objective** | Verify the investigation environment leaks no real IP address and no DNS queries to the ISP resolver. |
| **Prerequisites** | TC-DW-001 completed; investigation environment active (Tails/Whonix/dedicated VM). |
| **Test Steps** | 1. Real IP: `curl -s https://api.ipify.org`<br>2. Tor IP: `curl -s --socks5-hostname 127.0.0.1:9050 https://api.ipify.org` — must differ<br>3. Tor exit geo: `curl -s --socks5-hostname 127.0.0.1:9050 https://ifconfig.me/json \| jq '{ip, country, city}'`<br>4. DNS resolver: `cat /etc/resolv.conf` — should be 127.0.0.1 (Tor DNS) in Tails/Whonix<br>5. DNS leak test: visit https://dnsleaktest.com via Tor Browser → Extended Test — all servers should be Tor exits, varied geographies |
| **Expected Results** | Real IP and Tor IP differ; Tor exit geolocation is consistent with a Tor exit relay country; DNS resolver is local; dnsleaktest.com shows only Tor exit relays. |
| **False Positive Risk** | LOW — control validation. The real failure mode is *not* running this check. |
| **Remediation (defense)** | Run this check at the start of EVERY session. If any check fails, halt the investigation and re-provision the environment (Tails reboot, Whonix snapshot-revert). |
| **Related Tools** | curl, jq, dnsleaktest.com |

### TC-DW-009: Browser Fingerprint Uniformity Check

| Field | Value |
|------|-----|
| **ID** | TC-DW-009 |
| **Name** | Tor Browser Fingerprint Uniformity Check |
| **Severity** | HIGH |
| **Category** | OPSEC Verification |
| **Objective** | Verify Tor Browser produces a uniform fingerprint (all Tor Browser users look identical) rather than a unique fingerprint that could deanonymize the investigator. |
| **Prerequisites** | TC-DW-001 completed; Tor Browser launched in Tails/Whonix/dedicated VM. |
| **Test Steps** | 1. Tor check: visit https://check.torproject.org → "Congratulations. This browser is configured to use Tor."<br>2. AmIUnique: visit https://amiunique.org → fingerprint should NOT be unique (should match the default Tor Browser fingerprint)<br>3. BrowserLeaks JavaScript: visit https://browserleaks.com/javascript → fingerprint matches default<br>4. BrowserLeaks WebRTC: visit https://browserleaks.com/webrtc → should show no local IP leak<br>5. BrowserLeaks Canvas: visit https://browserleaks.com/canvas → Tor Browser returns a noise canvas (signature should match default) |
| **Expected Results** | Tor Project check is green; AmIUnique does not flag a unique fingerprint; WebRTC shows no local IP; Canvas returns a noise signature matching default Tor Browser. |
| **False Positive Risk** | LOW — control validation. If AmIUnique flags uniqueness, the investigator has modified Tor Browser or installed extensions that break uniformity. |
| **Remediation (defense)** | Do NOT install additional extensions in Tor Browser; do NOT modify default settings; do NOT resize the window (default size is part of the fingerprint). If a uniformity check fails, restore default Tor Browser settings or reboot Tails. |
| **Related Tools** | Tor Browser, check.torproject.org, amiunique.org, browserleaks.com |

### TC-DW-010: Behavioral Fingerprinting & Persona Contamination Audit

| Field | Value |
|------|-----|
| **ID** | TC-DW-010 |
| **Name** | Behavioral Fingerprinting & Persona Contamination Audit |
| **Severity** | HIGH |
| **Category** | OPSEC Verification |
| **Objective** | Detect investigator-side behavioral patterns (fixed session windows, concurrent clearnet activity) that an adversary could use for timing correlation, and detect persona contamination (handle, PGP key, wallet appearing in unexpected places). |
| **Prerequisites** | Established monitoring persona with handle, PGP key, wallet; Tails/Whonix environment. |
| **Test Steps** | 1. Session window analysis: review investigation logs over 30 days — are all sessions in the same 4-hour daily window? `grep "session_start" /var/log/dw-monitor.log \| awk '{print $1, $2}' \| sort \| uniq -c`<br>2. Concurrent clearnet activity: during dark-net sessions, were any clearnet accounts (personal email, social media) active on the same physical machine? Document any overlap.<br>3. Handle contamination: `maigret <persona_handle> --tags us --html` — should return zero clearnet hits<br>4. PGP key contamination: `gpg --list-keys <persona_pgp_fpr>` — any uid matching real name/email?<br>5. Wallet contamination: search persona wallet address across forums for unexplained mentions<br>6. Burned-persona detection: `curl -s --socks5-hostname 127.0.0.1:9050 "http://<watch_forum>.onion/search?q=<persona_handle>" \| grep -i "burned\|opsec fail\|deanon"` |
| **Expected Results** | Session windows vary across days; no clearnet account activity concurrent with dark-net sessions on the same machine; persona handle does not appear on clearnet; PGP key has only fake uids; wallet appears only in investigator-initiated contexts; no burned-persona indicators on watch forums. |
| **False Positive Risk** | MEDIUM — fixed session windows can be coincidental (work hours); wallet mentions may be legitimate shared donation addresses. Investigate each anomaly before burning a persona. |
| **Remediation (defense)** | Vary session times; isolate the investigation machine from clearnet accounts during sessions; rotate personas every N months; burn and rotate immediately if any contamination is confirmed. |
| **Related Tools** | tor, curl, maigret, gpg |

---

## E. Defense & Counter-OSINT

### TC-DW-011: Organization Dark-Net Footprint Audit

| Field | Value |
|------|-----|
| **ID** | TC-DW-011 |
| **Name** | Organization Dark-Net Footprint Audit (Defense) |
| **Severity** | MEDIUM |
| **Category** | Defense / Counter-OSINT |
| **Objective** | Audit the organization's dark-net footprint: leaked credentials, employee PII, proprietary source code listings, brand impersonation in marketplaces. |
| **Prerequisites** | Lawful authorization from the organization; HIBP enterprise key; DeHashed key; IntelX key; TC-DW-001 completed. |
| **Test Steps** | 1. HIBP domain check: `curl -s -H "hibp-api-key: <KEY>" "https://haveibeenpwned.com/api/v3/breacheddomain/<DOMAIN>" \| jq 'to_entries[] \| {email: .key, breaches: .value}'`<br>2. DeHashed domain search: `curl -s "https://api.dehashed.com/search?query=domain:<DOMAIN>" -u "<email>:<KEY>" \| jq '.entries[] \| {email, password, database}'`<br>3. IntelX intelligent search: `curl -s "https://2.intelx.io/intelligent/search?k=<KEY>" -H "Content-Type: application/json" -d '{"term":"<DOMAIN>","maxresults":100}' \| jq '.'`<br>4. Ahmia sweep for brand mentions: `curl -s "https://ahmia.fi/search/?q=<DOMAIN>" \| grep -oE 'https?://[a-z2-7]{56}\.onion' \| sort -u`<br>5. Proprietary code identifiers: index unusual function names from internal codebase; sweep paste sites and source markets via IntelX<br>6. Aggregate findings into a prioritized remediation report |
| **Expected Results** | Inventory of leaked credentials (with breach source and date), employee PII exposure, source code listings, and any marketplace brand impersonation — prioritized for remediation. |
| **False Positive Risk** | MEDIUM — DeHashed and IntelX index stale data; some "leaked" credentials are years old and already rotated; marketplace brand mentions can be unrelated companies with similar names. |
| **Remediation (defense)** | Force password rotation + MFA for any active leaked credentials; submit takedowns for marketplace impersonation; rotate proprietary code identifiers that appear in leaks; institute recurring (weekly) monitoring. |
| **Related Tools** | curl, jq, HIBP, DeHashed, IntelX, Ahmia |

### TC-DW-012: Continuous Brand & Breach Monitoring

| Field | Value |
|------|-----|
| **ID** | TC-DW-012 |
| **Name** | Continuous Brand & Breach Monitoring (Defense) |
| **Severity** | HIGH |
| **Category** | Defense / Counter-OSINT |
| **Objective** | Establish a recurring monitoring pipeline that detects new dark-net mentions of the organization's brand, executives, and proprietary identifiers within hours of appearance. |
| **Prerequisites** | TC-DW-011 completed (baseline established); HIBP notifications subscribed; IntelX API key; cron or task scheduler. |
| **Test Steps** | 1. Ahmia daily sweep: `echo "0 8 * * * curl -s 'https://ahmia.fi/search/?q=<DOMAIN>' >> /var/log/dw-monitor.log" \| crontab -`<br>2. IntelX daily sweep: `echo "30 8 * * * curl -s 'https://2.intelx.io/intelligent/search?k=<KEY>' -H 'Content-Type: application/json' -d '{\"term\":\"<DOMAIN>\",\"maxresults\":50}' >> /var/log/intelx-monitor.log" \| crontab -`<br>3. HIBP domain subscription: subscribe via HIBP enterprise dashboard for real-time notifications<br>4. Ransomware leak-site tracker: weekly manual review of major gang leak sites via Tor Browser<br>5. Alerting: diff daily sweep output against baseline; alert on new matches (e.g. via Slack webhook)<br>6. Quarterly review: tune search terms, retire stale queries, add new identifiers |
| **Expected Results** | New dark-net mentions of the brand, executives, or proprietary code appear in the daily sweep within 24 hours of publication; HIBP notifications fire within minutes of new breach data being loaded. |
| **False Positive Risk** | MEDIUM — daily sweeps generate noise (mentions of similar brands, unrelated context); tuning is required to reduce false positives. HIBP alerts are high-confidence but historical breach re-uploads can trigger duplicate alerts. |
| **Remediation (defense)** | Tune search terms (require multi-word brand strings to reduce collisions); deduplicate alerts against historical breach IDs; escalate only high-confidence matches to incident response. |
| **Related Tools** | cron, curl, jq, HIBP, IntelX, Ahmia |

---

## Summary Table

| ID | Name | Severity | Category |
|------|------|----------|----------|
| TC-DW-001 | Hardened Tor Access Setup | HIGH | Access |
| TC-DW-002 | .onion Service Resolution & Verification | MEDIUM | Access |
| TC-DW-003 | Ahmia Multi-Engine Search | LOW | Access |
| TC-DW-004 | IntelX Phonebook & Intelligent Search | MEDIUM | Marketplace |
| TC-DW-005 | Manual Marketplace Enumeration (Read-Only) | HIGH | Marketplace |
| TC-DW-006 | Handle Correlation Across Forums | HIGH | Profiling |
| TC-DW-007 | PGP Key & Monero Wallet Pivot | MEDIUM | Profiling |
| TC-DW-008 | Egress & DNS Leak Verification | HIGH | OPSEC |
| TC-DW-009 | Tor Browser Fingerprint Uniformity Check | HIGH | OPSEC |
| TC-DW-010 | Behavioral Fingerprinting & Persona Contamination Audit | HIGH | OPSEC |
| TC-DW-011 | Organization Dark-Net Footprint Audit | MEDIUM | Defense |
| TC-DW-012 | Continuous Brand & Breach Monitoring | HIGH | Defense |

---

**Related files**: `SKILL.md`, `payloads.md`, `guides/dark-web-investigation-playbook.md`
**Key upstreams**: [Tor Project](https://www.torproject.org) | [Ahmia](https://ahmia.fi) | [OnionScan](https://github.com/s-rah/onionscan) | [IntelX](https://intelx.io)
