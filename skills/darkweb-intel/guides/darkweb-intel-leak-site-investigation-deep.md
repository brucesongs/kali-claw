# Dark Web Intelligence: Ransomware Leak Site Investigation Deep Dive

## Overview

The ransomware leak site — sometimes called a "data blog" or "victim board" — is the single most important artifact in modern ransomware intelligence. Since the emergence of the Maze Crew in late 2019, virtually every major ransomware-as-a-service (RaaS) operation has operated a Tor-hidden website where they name victims, post countdown timers, and ultimately publish stolen data when negotiations fail. This guide walks an analyst through the lifecycle of a leak site investigation: taxonomy of leak site states, the commercial and open-source platforms that monitor them, OPSEC for crawling them safely, victim triage, stolen data validation, attribution through TTP mapping, evidence collection with chain of custody, and a worked example using the MOVEit Clop campaign of 2023.

The audience is a threat intelligence analyst, incident response consultant, or law enforcement investigator who needs to operationalize leak site monitoring. Treat every command in this guide as OPSEC-sensitive: assume the leak site operator is fingerprinting your visitor, and route all access through a hardened analyst workstation.

## Leak Site Taxonomy: Posted, Available for Sale, Deleted

Leak sites follow a predictable lifecycle, and the current state of a victim entry determines the analyst's response window. The four primary states are:

- Listed / Pending: the victim has been added to the leak site but no data has been published yet. Often accompanied by a countdown timer (typically 7 to 14 days). This is the analyst's primary response window: confirm the breach internally, engage the negotiator, and prepare external messaging.
- Posted / Released: stolen data has been published and is freely downloadable. At this point the operational response window has closed and the focus shifts to damage assessment, customer notification, and (potentially) regulatory disclosure.
- Available for Sale: data is being offered for sale at a fixed price or via auction, but not yet publicly posted. This model is used by some crews and by independent data brokers on forums like BreachForums. Payment does not guarantee exclusivity.
- Deleted / Settled: the entry has been removed, typically indicating the victim paid or the operator accepted a settlement. Note that deletion does not guarantee data was not retained by the operator or shared with affiliates; treat deletion as a soft signal only.

Some operators add intermediate states (e.g., " proof of compromise" preview, "additional data added" updates). LockBit historically used a five-stage progression; BlackCat used a similar model. Familiarize yourself with each crew's local conventions.

## Commercial Monitoring Platforms

Three commercial platforms dominate ransomware leak site monitoring:

- Recorded Future's Insikt Group maintains the most mature dark web collection practice and publishes regularly on emerging crews. Their platform aggregates leak site postings with structured fields (victim name, sector, country, posting crew, posted-at, status) and offers API access.
- Intel 471's Gemini platform provides deep coverage of Russian-language forums and leak sites, with human analysts actively embedded in criminal communities. Their Titan endpoint allows programmatic querying of victims, actors, and indicators.
- Flashpoint, born out of iDefense and now part of Accel-KKR, offers strong coverage of underground forums and historically had the best archive of pre-2021 leak site data.

Other notable platforms include DarkOwl (strong surface / dark web paste-site coverage), Searchlight Cyber (enterprise dark web monitoring), and ZeroFox (consumer-facing brand protection with dark web overlap). For budget-constrained teams, the open-source projects RansomLook (ransomlook.io), Ransomware Tracker by abuse.ch (now tehillimShield), and the curated list at ransomwatch maintain a free public view of the same data with a few hours' delay.

## Onion Crawl OPSEC: Tails and Whonix

Crawling ransomware leak sites carries real risk to the analyst and the analyst's organization. Leak site operators routinely fingerprint visitors (User-Agent, browser viewport size, JavaScript fingerprint, language headers) and have been known to publish IPs of careless researchers. A defensive analyst workstation should follow three principles: isolation, anonymity, and reproducibility.

Tails is a Debian-based live operating system that boots from USB, routes all traffic through Tor, and leaves no trace on the host. Tails is appropriate for short, ephemeral tasks such as verifying a single leak site posting. Its main drawback is that persistent storage is opt-in and fragile; losing an investigator's notebook mid-engagement is a real risk.

Whonix is a two-VM design: a Tor gateway VM that all traffic must traverse, and a workstation VM where the analyst runs tools. Whonix's compartmentalization is stronger than Tails for sustained investigations because the workstation cannot leak its real IP even if an application is compromised. The trade-off is more setup complexity.

```bash
# Example: fetch a leak site through torsocks from a Whonix Workstation
torsocks curl -s -A "Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0" \
  --max-time 60 \
  http://exampleleak7onionaddress.onion/index.php \
  | tee -a /home/user/case-2024-001/leak-site-snapshot-$(date +%Y%m%d-%H%M%S).html

# Hash the snapshot for chain of custody
sha256sum /home/user/case-2024-001/leak-site-snapshot-*.html \
  | tee -a /home/user/case-2024-001/chain-of-custody.log
```

Additional OPSEC hardening: rotate analyst identities across engagements, never log in to corporate email or social media from the analyst workstation, disable JavaScript unless absolutely required, and prefer text-based scraping over graphical browser sessions. Document the analyst workstation configuration in a runbook so that evidence is reproducible.

## Victim Identification and Triage

When a new victim appears on a leak site, the analyst's first job is identification and triage: is this victim real, are they in our scope (our organization, our supply chain, our M&A targets), and what is the severity?

Triage checklist:

1. Confirm victim identity: match the leak site listing to a real organization (look for corroborating evidence on the org's own website, recent press, or LinkedIn layoffs). Some crews post inaccurate or exaggerated entries to drum up credibility.
2. Map to your inventory: is this victim in your CMDB, vendor risk register, or M&A pipeline? Cross-reference immediately.
3. Determine the data category claimed: PII, PHI, financial, source code, internal communications, credentials. The severity of the claim drives the response.
4. Identify the crew and their typical playbook: LockBit tends to encrypt and exfiltrate; Clop increasingly exfiltrates without encrypting; BlackSuit favors large corporate victims.
5. Engage the negotiator (if your organization uses one) and legal within hours, not days, of the listing.

## Stolen Data Validation

Once data has been posted, validate its authenticity and scope before responding externally. Naive acceptance of attacker claims leads to both over- and under-disclosure.

Tools for validation:

- Kore Logic's data validation techniques (originally published for breach response): look for internal consistency (do dates, names, and email addresses match expected patterns?), for source-code integrity (do file headers match known commit history?), and for freshness (is the data consistent with the claimed breach date?).
- Have I Been Pwned (HIBP) for cross-referencing email addresses: a HIBP match does not prove the data came from this breach, but the absence of HIBP matches for emails that should be present is a strong negative signal.
- Steganography and metadata analysis on screenshots: file system timestamps, file sizes, and PNG chunks can reveal whether screenshots have been manipulated.
- Sampling and spot-checking: download a representative sample of files (typically 5-10%), verify against known internal data, and document findings.

```bash
# Download a sample archive from a leak site and hash it
torsocks curl -s -o case-001-sample.zip \
  http://exampleleak7onionaddress.onion/case-001-sample.zip
sha256sum case-001-sample.zip

# Extract and inspect metadata only (do NOT execute any binaries)
mkdir -p case-001-sample && cd case-001-sample
unzip -o ../case-001-sample.zip
find . -type f -exec file {} \; | tee ../case-001-file-types.log
find . -type f -exec stat -c '%n %s %y' {} \; | tee ../case-001-timestamps.log
```

## Attribution: Cluster Identification and TTP Mapping

Attribution of a ransomware incident is rarely a single piece of evidence; it is a convergence of signals. The analyst's goal is to identify the cluster of activity (in Mandiant's naming, a UNC — "uncategorized" group) and to map that cluster's tactics, techniques, and procedures to MITRE ATT&CK techniques.

Cluster identification signals to collect per incident:

- Initial access vector (exploited CVE, credential reuse, phishing lures used).
- Persistence mechanism (scheduled task names, service names, registry keys).
- Lateral movement tool (Cobalt Strike beacon config, PsExec, WMI, AnyDesk, Atera).
- Encryption extension and ransom note formatting (the ransom note template is often copied across affiliates).
- Negotiation language, time zone, and working hours (from chat timestamps).
- Cryptocurrency wallet addresses for payment.

Cross-reference these signals against Mandiant, CrowdStrike, Microsoft, and Palo Alto Unit 42 published reports. When enough signals overlap, the cluster can be assigned to a named crew (e.g., UNC2589 = Clop; UNC2452 = SolarWinds/Nobelium). Publish your attribution logic in your intel dossier so it can be reviewed and challenged.

## Safe Evidence Collection and Chain of Custody

Evidence collected from dark web leak sites can end up in regulatory filings, civil litigation, or criminal proceedings. Treat every artifact as potential exhibit evidence and maintain chain of custody from the moment of collection.

Chain of custody principles:

- Document who collected what, when, from where, and with what tooling, in an immutable log.
- Hash every file at the moment of collection (SHA-256 minimum).
- Store originals on write-once media where possible, or in an immutable cloud object store with object lock.
- Maintain a custody log that is updated every time the evidence changes hands.
- Avoid any processing that mutates the original (work on copies).
- If you re-mirror a leak site over time, store each snapshot separately — never overwrite.

```bash
# Snapshot script: fetch, hash, and log a leak site entry
CASE="case-2024-001"
SITE="http://exampleleak7onionaddress.onion"
TS=$(date -u +%Y%m%dT%H%M%SZ)
OUT="$CASE/leak-site-$TS"
mkdir -p "$OUT"

torsocks wget --mirror --convert-links --adjust-extension \
  --user-agent="Mozilla/5.0 (analyst)" \
  --no-verbose \
  -P "$OUT" "$SITE/" 2>&1 | tee "$OUT/wget.log"

( cd "$OUT" && find . -type f -exec sha256sum {} \; ) \
  | tee "$OUT/sha256sums.txt"

cat <<EOF >> "$CASE/custody.log"
$TS  collected by analyst=X tool=wget-via-torsocks
  source=$SITE
  sha256sums in $OUT/sha256sums.txt
EOF
```

## Hands-on: CVE-2023-34362 MOVEit Investigation

In late May 2023 the Clop ransomware crew began exploiting a zero-day SQL injection vulnerability (CVE-2023-34362) in Progress Software's MOVEit Transfer. Clop had previously used the same data-theft extortion model against Accellion FTA (2021) and GoAnywhere MFT (early 2023); the MOVEit campaign was the largest iteration yet.

A worked investigation, step by step:

### Step 1: Detect the Campaign via Leak Site

```bash
# Monitor Clop's leak site (historically on a rotating onion address)
torsocks curl -s -A "Mozilla/5.0 (analyst)" \
  http://cl0pleaksozony7vvjqhdse3nxktxrmyhcdqxzvpm765yv6x2haqad.onion/ \
  > clop-$(date +%Y%m%d).html

# Extract victim list
python3 -c "
import re, sys
html = open('clop-20230531.html').read()
victims = re.findall(r'<title>([^<]+)</title>', html)
for v in victims[:20]: print(v)
"
```

### Step 2: Identify the Vulnerability and Build an IOC List

Cross-reference with CISA's advisory on CVE-2023-34362, published 2 June 2023. Build an IOC list of suspicious MOVEit web requests (specifically the `x-msworks-resetpassword` and `M2.aspx` endpoints). Hunt across your SIEM for May 2023 hits.

### Step 3: Cluster the Activity via TTP Mapping

Map observed TTPs to Clop's known playbook: SQL injection for initial access (T1190), web shell deployment for persistence (T1505.003), data staging and exfiltration over HTTPS (T1567.002). The convergence of these TTPs with the leak site listing is sufficient to attribute the campaign to Clop (UNC2589).

### Step 4: Validate Stolen Data

For any victim in your scope that appeared on the Clop leak site, download a sample of the posted data and validate against your internal records using the techniques described above. Document findings in the intel dossier.

### Step 5: Engage External Stakeholders

Within hours of confirming victimization, engage: the organization's general counsel (for privilege), outside cyber counsel (for negotiation and disclosure), the cyber insurance carrier, and the negotiator firm. Coordinate any regulatory disclosure with counsel.

### Step 6: Preserve Evidence and Document Lessons Learned

Snapshot the leak site entry daily throughout the incident. Maintain custody logs. After the incident, conduct a lessons-learned review covering detection gaps, vendor management (was MOVEit in your vendor risk register?), and negotiation effectiveness. Fold lessons back into your monitoring playbook.

## Defensive Recommendations

Operationalize leak site monitoring: subscribe to at least one commercial feed, supplement with open-source feeds, and tune alerts to your organization's name, brands, and supply chain. Run a tabletop scenario each quarter based on a real incident (MOVEit, Colonial Pipeline, Change Healthcare). Maintain pre-negotiated relationships with a ransomware negotiation firm, outside cyber counsel, and your cyber insurance carrier. Build the analyst workstation runbook now, not during an incident, and rehearse it. Finally, archive everything: the open-source community maintains historical archives of leak sites, but for evidentiary purposes your own snapshots are irreplaceable.

## References

1. CISA / FBI / NSA Joint Advisory: CVE-2023-34362 MOVEit Transfer — https://www.cisa.gov/news-events/alerts/2023/06/05/cisa-and-partners-investigating-compromise-moveit
2. Mandiant: Zero-Day Vulnerability in MOVEit Transfer (Clop Attribution) — https://www.mandiant.com/resources/clop-moveit-zero-day
3. Recorded Future: Insikt Group Ransomware Leaks Data Set — https://www.recordedfuture.com/ransomware-leaks
4. Intel 471: Gemini Platform Documentation — https://intel471.com/gemini-platform
5. Flashpoint: Underground Forum Intelligence — https://flashpoint.io/underground-communities/
6. DarkOwl: Dark Web OSINT Methodology — https://www.darkowl.com/blog
7. RansomLook: Open-Source Ransomware Leak Site Monitor — https://www.ransomlook.io/
8. abuse.ch: Ransomware Tracker (now tehillimShield) — https://ransomware.tehillimShield.com/
9. Tails: Portable Operating System for Privacy — https://tails.net/
10. Whonix: Anonymous Operating System — https://www.whonix.org/
11. Chain of Custody Best Practices (NIST SP 800-86) — https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-86.pdf
12. MITRE ATT&CK Matrix for Enterprise — https://attack.mitre.org/matrices/enterprise/
13. Have I Been Pwned — https://haveibeenpwned.com/
14. Kore Logic: Breach Data Validation Techniques — https://www.korelogic.com/Documents/pubdocs/KoreLogic_BreachValidation_2015.pdf
15. DOJ: BreachForums Seizure Press Release (March 2023) — https://www.justice.gov/usao-sdny/pr/brooklyn-man-charged-operating-breachforums-computer-hacking-forum
