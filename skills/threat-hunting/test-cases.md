# Threat Hunting Test Cases

> Companion to `SKILL.md`, containing structured test cases organized by category with severity ratings.
> All commands assume an authorized hunting environment (own tenant, signed-off engagement, or a controlled lab such as HELK + Splunk Free + SwiftOnSecurity Sysmon config).

---

## Statistics

| Category | Count | Severity Range |
|------|------|-----------|
| A. Hunt Hypothesis Development | 3 | MEDIUM - HIGH |
| B. Detection Engineering | 2 | MEDIUM - HIGH |
| C. Telemetry Hunts | 3 | MEDIUM - HIGH |
| D. Threat Intelligence Correlation | 2 | MEDIUM |
| E. Purple-Team Validation | 2 | HIGH |
| **Total** | **12** | **MEDIUM - HIGH** |

---

## A. Hunt Hypothesis Development

### TC-TH-001: Hunt Hypothesis — T1003.001 LSASS Memory Dump

| Field | Value |
|------|-----|
| **ID** | TC-TH-001 |
| **Name** | Hunt Hypothesis — T1003.001 LSASS Memory Dump |
| **Severity** | HIGH |
| **Category** | Hunt Hypothesis Development |
| **Objective** | Author a complete, testable hunt hypothesis for LSASS memory dumping via `comsvcs.dll`, with explicit ATT&CK mapping, data requirements, triage plan, and confidence rating. |
| **Prerequisites** | MITRE ATT&CK reference; `hunts/` directory; markdown authoring; understanding of Pyramid-of-Pain levels. |
| **Test Steps** | 1. `mkdir -p hunts/t1003-001-lsass-comsvcs`<br>2. Author `hypothesis.md` per the template in `SKILL.md` Practical Steps Exercise 1<br>3. Confirm the hypothesis names: ATT&CK ID (`T1003.001`), tactic (`TA0006 Credential Access`), Pyramid-of-Pain level (`TTP`), required data (Sysmon EID 1 + EID 10), confidence-if-hit (`HIGH`)<br>4. Validate the hypothesis is testable — i.e., the query in section 4 can be written in Sigma and run on the listed data<br>5. Peer-review with one other analyst |
| **Expected Results** | One markdown file (`hypothesis.md`) covering all five sections; the hypothesis is specific, falsifiable, and maps to a single ATT&CK sub-technique; the data required is already collected or is filed as a sensor gap. |
| **False Positive Risk** | LOW for the hypothesis itself (it is a planning artifact). HIGH if executed naively — legitimate crash-dumping tools (e.g., `procdump -ma lsass.exe` run by an on-call engineer) can match the Sigma pattern. Mitigation: filter known-good parents and known-dump-tool signers. |
| **Remediation (defense)** | Ship the Sigma rule to `sigma/rules/credential_access/`. Add a runbook entry: any hit on this rule pages the on-call DFIR engineer immediately. |
| **Related Tools** | markdown, MITRE ATT&CK Navigator, Sigma |

### TC-TH-002: Hunt Hypothesis — T1059.001 Encoded PowerShell

| Field | Value |
|------|-----|
| **ID** | TC-TH-002 |
| **Name** | Hunt Hypothesis — T1059.001 Encoded PowerShell |
| **Severity** | MEDIUM |
| **Category** | Hunt Hypothesis Development |
| **Objective** | Author a hypothesis for detecting encoded PowerShell (`-EncodedCommand` / `-enc` / `-e`) used to obfuscate malicious payloads. |
| **Prerequisites** | MITRE ATT&CK reference; PowerShell ScriptBlock logging enabled (EID 4104); Sysmon EID 1 with command-line auditing. |
| **Test Steps** | 1. `mkdir -p hunts/t1059-001-encoded-powershell`<br>2. Author `hypothesis.md` covering: ATT&CK (`T1059.001`), tactic (`TA0002 Execution`), data required (Sysmon EID 1 + WinEvent 4104), detection logic (CommandLine contains `-enc`/`-EncodedCommand`/`-e ` followed by a base64 blob), triage plan (decode base64, compare against known admin scripts), confidence rating (`HIGH` if decoded payload is suspicious)<br>3. Identify legitimate uses (e.g., SCCM, DSC, some in-house IT tools that ship scripts encoded) — these go in the FP-filter section<br>4. Document the decode step: `echo "<blob>" \| base64 -d` |
| **Expected Results** | Hypothesis markdown that distinguishes TTP-level detection (encoded PowerShell in general) from IOC-level detection (specific blob contents). FP list captures SCCM/DSC. |
| **False Positive Risk** | HIGH — many legitimate admin tools use encoded PowerShell. Mitigation: whitelist by ParentImage / signer; only alert when the decoded payload contains suspicious tokens (e.g., `DownloadString`, `Invoke-Mimikatz`, `IEX`). |
| **Remediation (defense)** | Constrain PowerShell via Constrained Language Mode + Script Block Logging + Module Logging + AppLocker/WDAC. Then this detection has near-zero FP. |
| **Related Tools** | PowerShell, Sysmon, Sigma, base64 |

### TC-TH-003: Hunt Hypothesis — T1071.004 DNS Tunneling

| Field | Value |
|------|-----|
| **ID** | TC-TH-003 |
| **Name** | Hunt Hypothesis — T1071.004 DNS Tunneling |
| **Severity** | HIGH |
| **Category** | Hunt Hypothesis Development |
| **Objective** | Author a hypothesis for detecting DNS-based C2 / data exfiltration (`T1071.004`). |
| **Prerequisites** | Zeek `dns.log` or AD DNS debug logs ingested; ability to compute per-query label length & entropy. |
| **Test Steps** | 1. `mkdir -p hunts/t1071-004-dns-tunneling`<br>2. Author `hypothesis.md` covering: ATT&CK (`T1071.004`), tactic (`TA0011 Command and Control`), data required (Zeek `dns.log`), detection signals (leftmost label >30 chars, high base64-entropy, repeated queries to one domain, TXT or NULL query type, short TTL)<br>3. Define the threshold: any host issuing >50 such queries to one domain in 1h<br>4. Identify legitimate lookalikes: Azure Managed DNS (`*.azure-dns.com`), AWS metadata, etc. — these do NOT generate >30-char leftmost labels<br>5. Validate the hypothesis is testable with current data |
| **Expected Results** | Hypothesis with concrete numeric thresholds (label length, query count, time window) and a list of known-legitimate domains that may trigger length-based filters. |
| **False Positive Risk** | MEDIUM — some legitimate services (DKIM, SPF, DNSSEC) generate long labels but rarely with the volume/frequency signature of a tunnel. Mitigation: combine length + entropy + volume + duration thresholds. |
| **Remediation (defense)** | Block TXT queries to untrusted recursive resolvers at the egress firewall; restrict external DNS to known corporate resolvers; deploy DNS firewall (e.g., Cisco Umbrella, BlueCat). |
| **Related Tools** | Zeek, Sigma, Python (entropy calculation) |

---

## B. Detection Engineering

### TC-TH-004: Sigma Rule Authoring & Multi-SIEM Translation

| Field | Value |
|------|-----|
| **ID** | TC-TH-004 |
| **Name** | Sigma Rule Authoring & Multi-SIEM Translation |
| **Severity** | HIGH |
| **Category** | Detection Engineering |
| **Objective** | Author a vendor-neutral Sigma YAML rule, then translate it to Splunk SPL, Elastic Lucene, and Sentinel KQL using `sigma-cli`. Validate all translations. |
| **Prerequisites** | `pip3 install sigma-cli`; Sigma plugins installed (`sigma-cli plugin list`); a clean Sigma rule from TC-TH-001. |
| **Test Steps** | 1. Author `sigma/rules/credential_access/comsvcs_minidump.yml` per `payloads.md` Section 2.1<br>2. Validate schema: `sigma-cli check sigma/rules/credential_access/comsvcs_minidump.yml`<br>3. Translate to Splunk SPL: `sigma-cli convert -t splunk -p sysmon sigma/rules/credential_access/comsvcs_minidump.yml > out/comsvcs_minidump.spl`<br>4. Translate to Elastic Lucene: `sigma-cli convert -t lucene sigma/rules/credential_access/comsvcs_minidump.yml > out/comsvcs_minidump.lucene`<br>5. Translate to ES|QL: `sigma-cli convert -t eql sigma/rules/credential_access/comsvcs_minidump.yml > out/comsvcs_minidump.eql`<br>6. Translate to Sentinel KQL (if azure-sentinel backend installed): `sigma-cli convert -t azure-sentinel sigma/rules/credential_access/comsvcs_minidump.yml > out/comsvcs_minidump.kql`<br>7. Visually verify each translation captures the same semantics |
| **Expected Results** | Four translated files; each query references `rundll32.exe`, `comsvcs.dll`, and `MiniDump`; no syntax errors. |
| **False Positive Risk** | LOW for the translation itself — risk is in the underlying rule. Use TC-TH-005 to measure FP rate before shipping. |
| **Remediation (defense)** | Add the Sigma file to Git; CI runs `sigma-cli check` and the translate pipeline on every PR (see `payloads.md` Section 13.4). |
| **Related Tools** | sigma-cli, Sigma YAML, jq |

### TC-TH-005: SIEM Query Translation & False-Positive Tuning

| Field | Value |
|------|-----|
| **ID** | TC-TH-005 |
| **Name** | SIEM Query Translation & False-Positive Tuning |
| **Severity** | MEDIUM |
| **Category** | Detection Engineering |
| **Objective** | Run the Sigma-derived query against 30 days of historical data, measure the false-positive rate, and tune the query to hit the target FP threshold (<5%). |
| **Prerequisites** | TC-TH-004 completed; SIEM with 30d+ retention of the target log source; a known-malicious test event to confirm true-positive detection. |
| **Test Steps** | 1. Run the translated query in Splunk over `-30d`:<br>`index=win source="*Sysmon*" EventCode=1 Image="*\\rundll32.exe" CommandLine="*comsvcs.dll*MiniDump*" \| stats count by host, User, ParentImage`<br>2. Categorize each hit: TRUE_POSITIVE, FALSE_POSITIVE, INCONCLUSIVE<br>3. For each FP, identify the discriminator (e.g., ParentImage is `C:\Program Files\Microsoft Monitoring Agent\...`) and add a `filter_*` clause to the Sigma rule<br>4. Re-run; iterate until FP rate < 5%<br>5. Confirm true-positive detection: trigger a test `comsvcs.dll MiniDump` invocation in a lab and confirm the rule fires<br>6. Document the final FP rate and tuning history in the Sigma rule's `falsepositives` field |
| **Expected Results** | Pre-tuning hit count is N; post-tuning hit count is N' where (N-N')/N > 95% are filtered as legitimate. True-positive test fires the rule within the SIEM alert latency SLO. |
| **False Positive Risk** | LOW after tuning — this test is *the* FP-reduction exercise. Document residual FPs in the Sigma rule for SOC triage awareness. |
| **Remediation (defense)** | Ship the tuned Sigma rule. Add a quarterly re-tune cadence — software changes (e.g., a new monitoring agent that uses `comsvcs.dll` legitimately) can reintroduce FPs. |
| **Related Tools** | Splunk (or Sentinel / Elastic), sigma-cli |

---

## C. Telemetry Hunts

### TC-TH-006: Sysmon Event Correlation Hunt

| Field | Value |
|------|-----|
| **ID** | TC-TH-006 |
| **Name** | Sysmon Event Correlation Hunt |
| **Severity** | HIGH |
| **Category** | Telemetry Hunts |
| **Objective** | Correlate Sysmon EID 1 (process create), EID 10 (process access), and EID 3 (network connect) to find a credential-dumping operation followed by outbound C2. |
| **Prerequisites** | Sysmon deployed with SwiftOnSecurity or olafhartong config; SIEM ingesting EID 1/3/7/10; `payloads.md` Section 3.3 reference. |
| **Test Steps** | 1. Find every EID 10 process-access event against `lsass.exe` with `GrantedAccess` in `(0x1010, 0x1410, 0x143a, 0x1f0fff)` over the last 24h<br>2. For each hit, look up the `SourceImage` in EID 1 to recover the parent process and command line<br>3. For each hit, look up EID 3 events from the same host in the ±10 min window around the EID 10 timestamp<br>4. Tag any (EID10 + suspicious EID1 + novel EID3) triple as a high-confidence lead<br>5. For each lead, pull the EDR process-tree export and Zeek outbound flow for the host<br>6. Document in a hunt report |
| **Expected Results** | A list of correlated triples; zero to a handful in a clean environment; each lead enriched with parent process, command line, and outbound network telemetry. |
| **False Positive Risk** | MEDIUM — EDR/AV products legitimately access LSASS. Mitigation: whitelist by signer (Microsoft, CrowdStrike, etc.); filter on `GrantedAccess` 0x1410 + non-Microsoft signer first. |
| **Remediation (defense)** | If true positive: trigger IR; preserve host image and memory before further investigation. If false positive: add the signer/path to the Sigma rule's `filter_*` clauses. |
| **Related Tools** | Sysmon, Splunk, Sentinel, Elastic |

### TC-TH-007: Zeek DNS C2 Beacon Hunt

| Field | Value |
|------|-----|
| **ID** | TC-TH-007 |
| **Name** | Zeek DNS C2 Beacon Hunt |
| **Severity** | HIGH |
| **Category** | Telemetry Hunts |
| **Objective** | Use Zeek `conn.log` and `dns.log` to identify periodic, low-volume outbound flows characteristic of a C2 beacon (`T1071.001` or `T1071.004`). |
| **Prerequisites** | Zeek deployed at the egress; `conn.log` and `dns.log` ingested to SIEM; Python with `statistics` module for beacon-shape computation (see `payloads.md` Section 8.2). |
| **Test Steps** | 1. Export 24h of `conn.log`: `zeek-cut id.orig_h id.resp_h id.resp_p ts < conn.log > convos.tsv`<br>2. Run the Python beacon-detection script from `payloads.md` Section 8.2<br>3. For each beacon-shaped conversation (`mean_iat` in 30-120s, `stdev` < 5s, `n` > 30):<br>   a. Pivot to `dns.log` — does the host resolve the destination IP to a suspicious domain?<br>   b. Pivot to `ssl.log` — what is the SNI? Is the cert self-signed?<br>   c. Pivot to `http.log` — what is the user agent? Is it default (`Python-urllib`, empty, etc.)?<br>4. Flag any conversation where the SNI, user agent, or cert does not match a known corporate service |
| **Expected Results** | A shortlist of beacon-like conversations, each enriched with DNS/SSL/HTTP context. Most legitimate beacons are update checkers (Chrome, Windows Update) — these match well-known infrastructure and are easily filtered. |
| **False Positive Risk** | MEDIUM — many legitimate services have periodic polling (NTP, Windows Update, Chrome update, Slack heartbeat). Mitigation: maintain a corporate-allowed destination list and filter; focus on unknown destinations. |
| **Remediation (defense)** | Block unknown destinations at the egress firewall; route all DNS through corporate resolvers; deploy JA3/JA3S fingerprinting to identify malware C2 even when SNI is benign. |
| **Related Tools** | Zeek, Python, Splunk / Elastic |

### TC-TH-008: Windows Lateral Movement Hunt (EID 4624/4688)

| Field | Value |
|------|-----|
| **ID** | TC-TH-008 |
| **Name** | Windows Lateral Movement Hunt (EID 4624/4688) |
| **Severity** | HIGH |
| **Category** | Telemetry Hunts |
| **Objective** | Identify Type 3 (network) logons from unusual source IPs that immediately spawned a shell — classic lateral movement signature (`T1021`, `T1550`, `T1570`). |
| **Prerequisites** | WinEvent Security log with EID 4624 (LogonType=3) and EID 4688 (process create with command line) ingested; known DHCP range to exclude; see `SKILL.md` Practical Steps Exercise 5 for the KQL. |
| **Test Steps** | 1. Run the KQL query from Practical Steps Exercise 5 over the last 24h<br>2. Filter out the corporate DHCP range and known service accounts<br>3. For each remaining (logon → shell-spawn) pair, extract: source IP, target user, target host, spawned process, command line<br>4. Pivot to EDR process tree for the target host to confirm the spawned process's parent and siblings<br>5. Pivot to Zeek for the source IP's outbound flows in the surrounding ±10 min<br>6. Tag any (network logon → `powershell.exe`/`wmic.exe`/`cmd.exe` with `-enc` or remote-target arguments) as a high-confidence lateral-movement lead |
| **Expected Results** | A small set of correlated (logon + shell) pairs. In a healthy environment: zero. In a compromised environment: 1-N leads pointing to the lateral-movement hop. |
| **False Positive Risk** | MEDIUM — legitimate admin tooling (PsExec, SCCM remote exec, Ansible WinRM) generates Type 3 logons followed by process spawns. Mitigation: whitelist by source host (jump boxes) and source user (service accounts). |
| **Remediation (defense)** | Restrict lateral movement: disable SMBv1, enforce SMB signing, restrict WinRM to specific hosts/users, deploy LAPS to randomize local admin passwords (defeats pass-the-hash reuse). |
| **Related Tools** | Windows Event Logs, Sentinel / Splunk, EDR |

---

## D. Threat Intelligence Correlation

### TC-TH-009: MISP IOC Match Hunt

| Field | Value |
|------|-----|
| **ID** | TC-TH-009 |
| **Name** | MISP IOC Match Hunt |
| **Severity** | MEDIUM |
| **Category** | Threat Intelligence Correlation |
| **Objective** | Pull high-confidence IOCs from MISP (IP/domain/hash) and sweep the SIEM for matches over the last 30 days. |
| **Prerequisites** | MISP instance accessible with API key; `pymisp` installed; SIEM with 30d+ retention of Zeek `dns.log`, `conn.log`, `http.log`, and Sysmon file-hash events. |
| **Test Steps** | 1. Pull IOCs from MISP: `pymisp.search(controller="attributes", type_attribute=["ip-dst","domain","sha256"], tags=["tlp:white","confidence:high"])`<br>2. Deduplicate and bucket by type<br>3. For each IP: `index=zeek sourcetype=zeek:conn id.resp_h="<ip>" \| stats count by id.orig_h, id.resp_p`<br>4. For each domain: `index=zeek sourcetype=zeek:dns query="<domain>" \| stats count by id.orig_h`<br>5. For each hash: `index=win source="*Sysmon*" (EventCode=1 OR EventCode=7 OR EventCode=11) Hashes="<hash>" \| stats count by host, Image`<br>6. Tabulate matches; for each match, enrich with MISP event info (threat actor, malware family, campaign) |
| **Expected Results** | A list of (IOC, MISP event, SIEM match count, affected hosts). Matches connect observed traffic/files to known threat-actor infrastructure/campaigns. |
| **False Positive Risk** | LOW-MEDIUM — IOCs from MISP may be stale (sinkholed IPs change ownership, expired domains get re-registered). Mitigation: filter IOCs older than 90 days; cross-check against VirusTotal for current reputation. |
| **Remediation (defense)** | For each confirmed match: trigger IR; preserve evidence; block the IOC at egress firewall, DNS sinkhole, and EDR. Publish back to MISP: "We saw this IOC engaging with our infrastructure on <date>." |
| **Related Tools** | MISP, pymisp, Splunk / Sentinel / Elastic |

### TC-TH-010: OpenCTI Knowledge-Graph Pivot

| Field | Value |
|------|-----|
| **ID** | TC-TH-010 |
| **Name** | OpenCTI Knowledge-Graph Pivot |
| **Severity** | MEDIUM |
| **Category** | Threat Intelligence Correlation |
| **Objective** | From one observed indicator (e.g., a suspicious hash), pivot through the OpenCTI knowledge graph to discover the associated intrusion set, malware family, and other known IOCs. |
| **Prerequisites** | OpenCTI instance accessible; `pycti` installed; one observed indicator (hash or domain) from a SIEM lead. |
| **Test Steps** | 1. From the SIEM lead, extract the indicator value (e.g., a file SHA256)<br>2. Query OpenCTI: `client.indicator.list(filters=[{"key":"observable_value","values":["<sha256>"]}])`<br>3. Walk the relationships: indicator → malware → intrusion-set → campaign → other indicators<br>4. Pull all sibling indicators (IPs, domains, hashes) related to the same intrusion set<br>5. Re-run TC-TH-009 hunt against the sibling IOCs to find additional compromises<br>6. Document the pivot chain in the hunt report |
| **Expected Results** | A knowledge-graph traversal that maps one observed indicator to a threat actor / campaign / malware family; sibling IOCs surface additional historical compromises. |
| **False Positive Risk** | LOW — OpenCTI relationships are curated. Risk is in acting on stale indicators; check `valid_from` / `valid_until` on each indicator. |
| **Remediation (defense)** | Update detections to cover the broader intrusion-set TTPs (not just the one observed indicator). Brief SOC on the identified threat actor's tradecraft for future awareness. |
| **Related Tools** | OpenCTI, pycti, GraphQL |

---

## E. Purple-Team Validation

### TC-TH-011: Red-Team TTP Simulation & Detection Verification

| Field | Value |
|------|-----|
| **ID** | TC-TH-011 |
| **Name** | Red-Team TTP Simulation & Detection Verification |
| **Severity** | HIGH |
| **Category** | Purple-Team Validation |
| **Objective** | Have the red team emulate `T1003.001` (LSASS dump) on a test host; verify that the blue team's Sigma-derived detection catches it within the alert-latency SLO. |
| **Prerequisites** | Authorized purple-team exercise; isolated test host with Sysmon + EDR; pre-existing Sigma rule (TC-TH-004 + TC-TH-005); red team tooling (Atomic Red Team or manual Mimikatz). |
| **Test Steps** | 1. Confirm the Sigma-derived Splunk detection is active with severity = high<br>2. Red team executes the TTP on the test host: `rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <lsass_pid> C:\temp\lsass.dmp full`<br>3. Blue team monitors the SIEM for the alert; note wall-clock time from execution to alert<br>4. Confirm the alert fires within the SLO (e.g., <5 min)<br>5. Triage the alert as the SOC would: confirm it is the red-team test, not a real intrusion<br>6. Document: detection latency, alert content quality, triage step count |
| **Expected Results** | The Sigma-derived detection fires; alert latency is within SLO; alert contains sufficient context (host, user, parent process, command line) for SOC to triage in <2 minutes. |
| **False Positive Risk** | LOW for the exercise itself — the red-team execution is the test. Real-world FP rate was already measured in TC-TH-005. |
| **Remediation (defense)** | If alert latency is outside SLO: investigate SIEM indexing delay, detection schedule, or query performance. If alert lacks context: enrich the Sigma rule with additional fields (e.g., `ParentCommandLine`, `SourceUser`). |
| **Related Tools** | Atomic Red Team, Splunk (or Sentinel / Elastic), Sysmon, EDR |

### TC-TH-012: ATT&CK Coverage Gap Analysis

| Field | Value |
|------|-----|
| **ID** | TC-TH-012 |
| **Name** | ATT&CK Coverage Gap Analysis |
| **Severity** | HIGH |
| **Category** | Purple-Team Validation |
| **Objective** | Produce an ATT&CK Navigator layer showing which techniques are covered by current detections, which are partially covered, and which are uncovered; prioritize the next sprint of detection work. |
| **Prerequisites** | Inventory of all Sigma rules with `attack.t*` tags; ATT&CK Navigator (web or local); `payloads.md` Section 2 reference. |
| **Test Steps** | 1. Parse every Sigma rule in `sigma/rules/`; extract the `tags` list<br>2. Build a coverage map: technique ID → list of Sigma rule IDs that detect it<br>3. For each ATT&CK sub-technique, classify coverage as: COVERED (≥1 rule), PARTIAL (rule exists but FP rate too high or scope too narrow), UNCOVERED (no rule)<br>4. Export the coverage layer as ATT&CK Navigator JSON<br>5. Import into Navigator; visualize as heatmap<br>6. Prioritize: rank UNCOVERED techniques by (relevance to threat intel) × (data availability) × (Pyramid-of-Pain level)<br>7. Generate a backlog of new Sigma rules to author in the next sprint |
| **Expected Results** | An ATT&CK Navigator layer file; a ranked backlog of detection gaps; documentation of partial-coverage rules that need tuning. |
| **False Positive Risk** | N/A — this is a coverage exercise, not a detection. The risk is mis-prioritizing gaps (e.g., covering an obscure technique while leaving a high-prevalence one uncovered). Mitigation: prioritize by threat-intel-driven relevance. |
| **Remediation (defense)** | Feed the backlog into the detection-engineering sprint cadence. Re-run quarterly as new ATT&CK techniques are published and as detections are added/retired. |
| **Related Tools** | ATT&CK Navigator, Sigma, jq, Python |

---

## Summary Table

| ID | Name | Severity | Category |
|------|------|----------|----------|
| TC-TH-001 | Hunt Hypothesis — T1003.001 LSASS Memory Dump | HIGH | Hypothesis Development |
| TC-TH-002 | Hunt Hypothesis — T1059.001 Encoded PowerShell | MEDIUM | Hypothesis Development |
| TC-TH-003 | Hunt Hypothesis — T1071.004 DNS Tunneling | HIGH | Hypothesis Development |
| TC-TH-004 | Sigma Rule Authoring & Multi-SIEM Translation | HIGH | Detection Engineering |
| TC-TH-005 | SIEM Query Translation & False-Positive Tuning | MEDIUM | Detection Engineering |
| TC-TH-006 | Sysmon Event Correlation Hunt | HIGH | Telemetry Hunts |
| TC-TH-007 | Zeek DNS C2 Beacon Hunt | HIGH | Telemetry Hunts |
| TC-TH-008 | Windows Lateral Movement Hunt (EID 4624/4688) | HIGH | Telemetry Hunts |
| TC-TH-009 | MISP IOC Match Hunt | MEDIUM | Threat Intelligence Correlation |
| TC-TH-010 | OpenCTI Knowledge-Graph Pivot | MEDIUM | Threat Intelligence Correlation |
| TC-TH-011 | Red-Team TTP Simulation & Detection Verification | HIGH | Purple-Team Validation |
| TC-TH-012 | ATT&CK Coverage Gap Analysis | HIGH | Purple-Team Validation |

---

**Related files**: `SKILL.md`, `payloads.md`, `guides/hunt-hypothesis-playbook.md`
**External resources**: MITRE ATT&CK, Sigma project, Splunk Security Essentials, Sentinel hunting queries, Elastic Security Labs
