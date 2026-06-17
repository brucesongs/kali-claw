# Detection Engineering Test Cases

> Companion to `SKILL.md`, containing structured test cases organized by category with severity ratings.
> All commands assume an authorized environment — own tenant, signed-off engagement, or a controlled lab with EVTX-ATTACK-SAMPLES and a benign EVTX corpus.

---

## Statistics

| Category | Count | Severity Range |
|------|------|-----------|
| A. Sigma Rule Authoring | 3 | MEDIUM - CRITICAL |
| B. YARA Rule Authoring | 2 | MEDIUM - HIGH |
| C. SigmaCLI & Translation | 1 | MEDIUM |
| D. EVTX Scanning & Generation | 3 | HIGH |
| E. Detection CI/CD & Lifecycle | 3 | HIGH |
| **Total** | **12** | **MEDIUM - CRITICAL** |

---

## A. Sigma Rule Authoring

### TC-DE-001: Author a Sigma Rule for Mimikatz (T1003.001)

| Field | Value |
|------|-----|
| **ID** | TC-DE-001 |
| **Name** | Author a Sigma Rule for Mimikatz (T1003.001) |
| **Severity** | CRITICAL |
| **Category** | Sigma Rule Authoring |
| **Objective** | Draft a Sigma YAML that detects canonical Mimikatz command-line patterns (`sekurlsa::logonpasswords`, `lsadump::sam`, etc.), validate the schema with `sigma-cli parse`, and verify the rule structure is complete (title, id, status, tags, logsource, detection, condition, level). |
| **Tools** | SigmaCLI, Sigma YAML, MITRE ATT&CK reference |
| **Test Steps** | 1. `mkdir -p detections/t1003-001-mimikatz && cd detections/t1003-001-mimikatz`<br>2. Generate a UUID: `python3 -c "import uuid; print(uuid.uuid4())"`<br>3. Draft `mimikatz-cmdline.yml` with `title`, `id`, `status: experimental`, `tags: [attack.credential_access, attack.t1003.001]`, `logsource: { product: windows, category: process_creation }`, `detection: { selection: { Image\|endswith: '\mimikatz.exe' }, condition: selection }`, `level: high`<br>4. Add a second selection block for the canonical command-line tokens (`sekurlsa::logonpasswords`, `lsadump::sam`, `kerberos::golden`)<br>5. Add a `filter_legitimate_admin` block on `ParentImage\|endswith: '\sccm.exe'`<br>6. Validate: `sigma-cli parse mimikatz-cmdline.yml`<br>7. Translate to Splunk: `sigma-cli convert -t splunk mimikatz-cmdline.yml` and confirm the SPL references `rundll32.exe` and `mimikatz.exe` |
| **Expected Result** | `sigma-cli parse` exits 0; the Splunk SPL translation includes `Image="*\\mimikatz.exe"` and the canonical command-line tokens. The YAML has `id`, `status`, `tags`, `logsource`, `detection`, `condition`, `level` populated. |
| **False Positive Risk** | LOW if the rule is constrained to `Image\|endswith: '\mimikatz.exe'`. MEDIUM if the command-line-only branch is used (PowerShell `Invoke-Mimikatz` produces similar tokens). Mitigation: filter by ParentUser for the red-team account. |
| **Cleanup** | Remove `detections/t1003-001-mimikatz/` if not promoting to the detections repo. Otherwise, commit and ship per TC-DE-012. |
| **References** | `payloads.md` §1, §2.1, §2.5; `SKILL.md` Exercise 1; MITRE ATT&CK T1003.001 |

### TC-DE-002: Author a Sigma Rule for Suspicious PowerShell (T1059.001)

| Field | Value |
|------|-----|
| **ID** | TC-DE-002 |
| **Name** | Author a Sigma Rule for Suspicious PowerShell (T1059.001) |
| **Severity** | MEDIUM |
| **Category** | Sigma Rule Authoring |
| **Objective** | Draft a Sigma rule that detects PowerShell invocations with encoded commands (`-EncodedCommand`, `-enc`, `-e`), excluding known-good parents (SCCM, DSC). |
| **Tools** | SigmaCLI, Sigma YAML, Sysmon EID 1 reference |
| **Test Steps** | 1. `mkdir -p detections/t1059-001-encoded-powershell`<br>2. Generate a UUID and draft `encoded-powershell.yml`<br>3. Configure `logsource: { product: windows, category: process_creation }`<br>4. Add `selection` on `Image\|endswith: ['\powershell.exe', '\pwsh.exe']` AND `CommandLine\|contains: ['-EncodedCommand', ' -enc ', ' -e ']`<br>5. Add `filter_sccm` on `ParentImage\|endswith: '\sccm.exe'` and `filter_dsc` on `ParentImage\|endswith: '\wmiapriv.exe'` plus `CommandLine\|contains: 'DSC'`<br>6. Set `condition: selection and not 1 of filter_*`<br>7. Validate: `sigma-cli parse encoded-powershell.yml`<br>8. Translate to Elastic Lucene: `sigma-cli convert -t lucene encoded-powershell.yml` |
| **Expected Result** | `sigma-cli parse` exits 0. The Lucene translation includes `process.command_line:(*\\-EncodedCommand* OR *\\ \\-enc\\ * OR *\\ \\-e\\ *)` and the negation of the SCCM/DSC filters. |
| **False Positive Risk** | HIGH — many legitimate admin tools use encoded PowerShell. Mitigation: this rule includes the SCCM/DSC filters; tune further with `ParentUser` whitelist if FP rate exceeds 5/day. |
| **Cleanup** | Remove the local draft directory. If shipping, commit per TC-DE-012. |
| **References** | `payloads.md` §2.4; `SKILL.md` Practical Steps Exercise 1; MITRE ATT&CK T1059.001 |

### TC-DE-003: Author a Sigma Rule for AWS Console Login from New Geo (T1078)

| Field | Value |
|------|-----|
| **ID** | TC-DE-003 |
| **Name** | Author a Sigma Rule for AWS Console Login from New Geo (T1078) |
| **Severity** | MEDIUM |
| **Category** | Sigma Rule Authoring |
| **Objective** | Draft a Sigma rule for AWS CloudTrail `ConsoleLogin` events from a source IP not seen for the user in the preceding 14 days. |
| **Tools** | SigmaCLI, AWS CloudTrail schema reference, Sigma YAML |
| **Test Steps** | 1. `mkdir -p detections/t1078-aws-console-new-geo`<br>2. Draft `aws-console-new-geo.yml` with `logsource: { product: aws, service: cloudtrail }`<br>3. Configure `selection_console_login` on `eventName: ConsoleLogin`, `eventSource: signin.amazonaws.com`, `responseElements_ConsoleLogin: Success`<br>4. Set `condition: selection_console_login`<br>5. Add `tags: [attack.initial_access, attack.t1078]`<br>6. Set `falsepositives: [User travel, VPN egress changes]` and `level: medium`<br>7. Validate: `sigma-cli parse aws-console-new-geo.yml`<br>8. Translate to Kibana NDJSON: `sigma-cli convert -t kibana-ndjson aws-console-new-geo.yml > kibana-import.ndjson`<br>9. Inspect the NDJSON: confirm `event.action: ConsoleLogin` and `event.provider: signin.amazonaws.com` |
| **Expected Result** | `sigma-cli parse` exits 0. The Kibana NDJSON import is valid JSON with the correct CloudTrail field mappings. |
| **False Positive Risk** | MEDIUM — legitimate user travel and VPN egress changes will trigger. The "new geo" component requires a backend lookup (Sentinel watchlist, Splunk KV store); the Sigma rule alone is the coarse filter. |
| **Cleanup** | Remove the local draft. If shipping, commit per TC-DE-012. |
| **References** | `payloads.md` §1.2, §2.7; `SKILL.md` Practical Steps Exercise 3; MITRE ATT&CK T1078 |

---

## B. YARA Rule Authoring

### TC-DE-004: Author a YARA Rule for a Malware Family

| Field | Value |
|------|-----|
| **ID** | TC-DE-004 |
| **Name** | Author a YARA Rule for a Malware Family |
| **Severity** | HIGH |
| **Category** | YARA Rule Authoring |
| **Objective** | Author a YARA rule for the Cobalt Strike beacon loader using PE-header markers, rich-header magic, and a XOR-decrypt loop pattern. Validate the syntax and confirm zero matches on a benign PE corpus. |
| **Tools** | YARA CLI, Yara-Rules reference, PE samples |
| **Test Steps** | 1. `mkdir -p yara-rules/malware-family && cd yara-rules/malware-family`<br>2. Draft `cobalt-strike-beacon.yar` with `meta`, `strings` (`$rich1`, `$rich2 = "DanS"`, `$xor_loop`, `$api_resolve`), and `condition: uint16(0) == 0x5A4D and $rich1 and $rich2 and ($xor_loop or $api_resolve) and filesize < 500KB`<br>3. Validate syntax: `yara cobalt-strike-beacon.yar /tmp/any-file.bin` (any non-PE file should not crash the parser)<br>4. Test against positive corpus: `yara -r cobalt-strike-beacon.yar /opt/samples/cobalt-strike/` — expect at least one match per known sample<br>5. Test against negative corpus: `yara -r cobalt-strike-beacon.yar /opt/samples/benign-pe/` — expect zero matches<br>6. If negative corpus matches, identify the matching string and tighten the condition |
| **Expected Result** | YARA parses the rule without syntax errors. Positive corpus produces a match on each known beacon sample. Negative corpus produces zero matches. |
| **False Positive Risk** | LOW if the rich-header magic + XOR loop are combined. MEDIUM if only the API string is used (appears in legitimate software too). Mitigation: require `uint16(0) == 0x5A4D` (PE MZ magic) AND the rich-header pattern AND a second signal. |
| **Cleanup** | Remove the test scratch directory. If shipping, commit per TC-DE-012. |
| **References** | `payloads.md` §4, §5.1; `SKILL.md` Practical Steps Exercise 2; MITRE ATT&CK S0154 |

### TC-DE-005: Author a YARA Rule for Web Shell Detection

| Field | Value |
|------|-----|
| **ID** | TC-DE-005 |
| **Name** | Author a YARA Rule for Web Shell Detection |
| **Severity** | MEDIUM |
| **Category** | YARA Rule Authoring |
| **Objective** | Author a YARA rule that matches PHP web shell patterns (command-execution functions combined with request-variable access and obfuscation primitives). Validate against known web shells and confirm zero matches on benign PHP. |
| **Tools** | YARA CLI, web-shell sample collection, benign PHP corpus |
| **Test Steps** | 1. Draft `php-webshell.yar` with strings for `$eval`, `$system`, `$exec`, `$passthru`, `$shell_exec`, `$popen`, `$proc_open` (command-execution functions) AND `$request`, `$post`, `$get`, `$cookie` (request-variable access) AND `$base64_decode`, `$str_rot13`, `$gzinflate` (obfuscation primitives)<br>2. Set `condition: filesize < 100KB and 1 of (cmd-exec functions) and 1 of (request vars) and (1 of (obfuscation) or 1 of (eval, assert))`<br>3. Validate syntax: `yara php-webshell.yar /tmp/any-file`<br>4. Test against positive corpus: `yara -r php-webshell.yar /opt/samples/webshells/` — expect matches on known web shells (b4ckdoor, WSO, China Chopper)<br>5. Test against negative corpus: `yara -r php-webshell.yar /opt/samples/benign-php/` (WordPress, Drupal, MediaWiki) — expect zero matches |
| **Expected Result** | Positive corpus matches; negative corpus produces zero matches. If negative corpus matches, identify the matching PHP file (likely a legitimate admin tool) and tighten the condition (require the request variable AND a specific function name). |
| **False Positive Risk** | MEDIUM — legitimate admin PHP (phpMyAdmin, WordPress admin-ajax.php) uses request variables and command execution. Mitigation: require multiple signals (request var + obfuscation + command-exec) AND constrain by filesize. |
| **Cleanup** | Remove the test scratch directory. If shipping, commit per TC-DE-012. |
| **References** | `payloads.md` §5.3; `SKILL.md` Practical Steps Exercise 2 |

---

## C. SigmaCLI & Translation

### TC-DE-006: Translate One Sigma Rule to Three SIEM Backends

| Field | Value |
|------|-----|
| **ID** | TC-DE-006 |
| **Name** | Translate One Sigma Rule to Three SIEM Backends |
| **Severity** | MEDIUM |
| **Category** | SigmaCLI & Translation |
| **Objective** | Given one Sigma YAML (e.g., the AWS Console Login rule from TC-DE-003), produce Splunk SPL, Microsoft Sentinel/Defender KQL, and Elastic EQL translations using `sigma-cli convert`. Verify each translation references the same detection logic. |
| **Tools** | SigmaCLI, pySigma backends |
| **Test Steps** | 1. `sigma-cli convert -t splunk aws-console-new-geo.yml > aws.spl`<br>2. `sigma-cli convert -t microsoft-365-defender aws-console-new-geo.yml > aws.kql`<br>3. `sigma-cli convert -t eql aws-console-new-geo.yml > aws.eql`<br>4. `cat aws.spl` — confirm `eventName=ConsoleLogin eventSource=signin.amazonaws.com` is present<br>5. `cat aws.kql` — confirm `eventName == "ConsoleLogin"` (note: Microsoft 365 Defender backend is for Defender, may not natively translate AWS CloudTrail; verify and document gaps)<br>6. `cat aws.eql` — confirm the EQL references `event.action: "ConsoleLogin"`<br>7. Verify the three translations reference the same detection semantics (ConsoleLogin + signin.amazonaws.com + Success) |
| **Expected Result** | All three translations succeed without errors. Each translation includes the canonical CloudTrail field references. Document any backend that does not natively support AWS CloudTrail (e.g., Microsoft 365 Defender) — those gaps go in the rule's documentation. |
| **False Positive Risk** | LOW for translation itself. The translation is generated content; the Sigma file is the source of truth. |
| **Cleanup** | Remove `aws.spl`, `aws.kql`, `aws.eql` (committed alongside the Sigma rule in the detections repo, but ephemeral here). |
| **References** | `payloads.md` §3.3, §3.6; `SKILL.md` Practical Steps Exercise 3 |

---

## D. EVTX Scanning & Generation

### TC-DE-007: Generate a YARA Rule with yarGen from Samples

| Field | Value |
|------|-----|
| **ID** | TC-DE-007 |
| **Name** | Generate a YARA Rule with yarGen from Samples |
| **Severity** | HIGH |
| **Category** | EVTX Scanning & Generation |
| **Objective** | Use yarGen to auto-generate a YARA rule from a folder of 10+ malware samples, review the generated rule, remove low-signal strings, and verify the rule matches the source samples while producing zero matches on a benign PE corpus. |
| **Tools** | yarGen, YARA CLI, malware sample collection, benign PE corpus |
| **Test Steps** | 1. `git clone https://github.com/Neo23x0/yarGen.git && cd yarGen && pip install -r requirements.txt`<br>2. (One-time) Initialize the benign string database: `python3 yarGen.py --update` (~1 hour)<br>3. Generate a rule from a folder of 10+ malware samples: `python3 yarGen.py --malware /opt/samples/family-x/ --top 20 --output /tmp/family-x.yar`<br>4. Review the generated rule: `cat /tmp/family-x.yar` — identify low-signal strings (generic PE headers, compiler artifacts) and remove them<br>5. Tighten the condition (e.g., from `3 of them` to `4 of them` or add a filesize constraint)<br>6. Test positive corpus: `yara -r /tmp/family-x.yar /opt/samples/family-x/` — expect matches on each sample<br>7. Test negative corpus: `yara -r /tmp/family-x.yar /opt/samples/benign-pe/` — expect zero matches<br>8. If negative matches: identify the offending string and remove it, re-test |
| **Expected Result** | yarGen produces a draft rule. After hand-tuning, the rule matches every sample in the source folder and produces zero matches on the benign PE corpus. The rule has at least 3 signal strings and a PE magic check (`uint16(0) == 0x5A4D`). |
| **False Positive Risk** | HIGH in the raw yarGen output (it includes generic strings). LOW after hand-tuning + negative-corpus validation. Mitigation: always run the negative-corpus test before shipping. |
| **Cleanup** | Remove `/tmp/family-x.yar`. If shipping, commit to `yara-rules/malware-family/family-x.yar` per TC-DE-012. |
| **References** | `payloads.md` §6; `SKILL.md` Practical Steps Exercise 4 |

### TC-DE-008: Scan EVTX Files with hayabusa

| Field | Value |
|------|-----|
| **ID** | TC-DE-008 |
| **Name** | Scan EVTX Files with hayabusa |
| **Severity** | HIGH |
| **Category** | EVTX Scanning & Generation |
| **Objective** | Run hayabusa against a folder of Windows EVTX files using the built-in SigmaHQ rule repo; produce a CSV timeline; confirm the output includes ATT&CK technique tags per match. |
| **Tools** | hayabusa, SigmaHQ rule repo, Windows EVTX files |
| **Test Steps** | 1. Download hayabusa: `wget https://github.com/YamatoSecurity/hayabusa/releases/latest/download/hayabusa-*-linux.zip`<br>2. `unzip hayabusa-*-linux.zip -d hayabusa && cd hayabusa && chmod +x hayabusa`<br>3. Update built-in rules: `./hayabusa update-rules`<br>4. Stage EVTX: copy `Security.evtx`, `System.evtx`, `Microsoft-Windows-Sysmon%4Operational.evtx` from a Windows host to `/opt/evtx/test-host/`<br>5. Run: `./hayabusa csv-timeline -d /opt/evtx/test-host/ -o timeline.csv --min-level medium --no-color`<br>6. Inspect the output: `head -20 timeline.csv` — confirm columns include Timestamp, Computer, EventID, Level, RuleTitle, MitreTactics, MitreTags<br>7. Verify MitreTags is non-empty for at least one match: `awk -F, '$NF != "" {print}' timeline.csv \| head` |
| **Expected Result** | hayabusa produces `timeline.csv` with one row per match. At least one match has a populated MitreTags field (e.g., `attack.t1003.001`). The summary line at the end of the run reports the count of detections by severity level. |
| **False Positive Risk** | MEDIUM — the SigmaHQ repo is broad and includes experimental rules; some matches will be benign admin activity. The `--min-level medium` flag suppresses low-confidence rules. |
| **Cleanup** | Remove `timeline.csv` if not needed for follow-up analysis. If retained, treat as sensitive (it contains usernames and command lines). |
| **References** | `payloads.md` §11; `SKILL.md` Practical Steps Exercise 5 |

### TC-DE-009: Scan Files with Loki for YARA + IOC Matches

| Field | Value |
|------|-----|
| **ID** | TC-DE-009 |
| **Name** | Scan Files with Loki for YARA + IOC Matches |
| **Severity** | HIGH |
| **Category** | EVTX Scanning & Generation |
| **Objective** | Use Loki to scan a directory of binaries against a curated YARA + IOC database; review the results; confirm the severity scoring is sensible. |
| **Tools** | Loki, YARA rules, IOC database |
| **Test Steps** | 1. `git clone https://github.com/Neo23x0/Loki.git && cd Loki && pip install -r requirements.txt`<br>2. Update signature database: `python3 loki.py --update`<br>3. Stage test files: a directory containing at least one known-bad sample (e.g., EICAR test file) and 10+ benign files<br>4. Run scan: `python3 loki.py --path /opt/samples --results /tmp/loki-results.txt --alert-level 40 --no-sigs --force`<br>5. Review the results: `cat /tmp/loki-results.txt` — confirm the EICAR file is flagged with severity >= 70<br>6. Confirm the benign files are NOT flagged (severity < 40 or absent from output)<br>7. Optionally test with a custom YARA rule (`--rules /opt/custom-yara/`) and confirm the custom rule fires |
| **Expected Result** | Loki produces `/tmp/loki-results.txt`. The EICAR test file is flagged with severity >= 70. The benign files do not appear in the alerts. The severity scoring (0-100) reflects the IOCs + YARA matches. |
| **False Positive Risk** | LOW for the EICAR test file (canonical). MEDIUM for general scans — Loki's IOC database may include stale indicators that produce FPs. Mitigation: review each high-severity alert manually. |
| **Cleanup** | Remove `/tmp/loki-results.txt`. If retained, treat as sensitive. |
| **References** | `payloads.md` §7; `SKILL.md` Practical Steps Exercise 6 |

---

## E. Detection CI/CD & Lifecycle

### TC-DE-010: Build a Detection CI Pipeline (GitHub Actions)

| Field | Value |
|------|-----|
| **ID** | TC-DE-010 |
| **Name** | Build a Detection CI Pipeline (GitHub Actions) |
| **Severity** | HIGH |
| **Category** | Detection CI/CD & Lifecycle |
| **Objective** | Create a GitHub Actions workflow that validates Sigma rule schema, checks ATT&CK tag coverage, translates every rule to Splunk/Elastic/KQL backends, runs hayabusa on positive and negative EVTX corpora, and builds an ATT&CK Navigator coverage layer artifact. |
| **Tools** | GitHub Actions, SigmaCLI, hayabusa (Docker), Python |
| **Test Steps** | 1. Create `.github/workflows/detection-ci.yml` in the detections repo<br>2. Configure jobs: `sigma-schema-validate`, `attack-tag-coverage`, `backend-translation`, `positive-corpus-test`, `negative-corpus-test`, `navigator-layer-build`<br>3. Each job: checkout, setup Python 3.11, install sigma-cli + backends, run the validation script<br>4. `positive-corpus-test` job: run `docker run --rm -v $PWD:/work yamatosecurity/hayabusa:latest csv-timeline -d /work/test-data/positive/ -r /work/rules/ -o /tmp/pos.csv --min-level low`; assert output non-empty<br>5. `negative-corpus-test` job: same hayabusa against `test-data/negative/`; assert no rule with level >= medium fired<br>6. `navigator-layer-build` job: run `python3 scripts/build-navigator-layer.py rules/ -o coverage.json`; upload as artifact<br>7. Open a PR with a new rule; observe each job runs and either passes or fails informatively |
| **Expected Result** | Each job runs on every PR. The `positive-corpus-test` job passes when the rule fires on positive EVTX. The `negative-corpus-test` job passes when no rule with level >= medium fires on negative EVTX. The Navigator coverage layer is uploaded as a workflow artifact. |
| **False Positive Risk** | LOW for the pipeline itself. The pipeline IS the FP-prevention mechanism. |
| **Cleanup** | None — the workflow lives in the repo. |
| **References** | `payloads.md` §14.1; `SKILL.md` Practical Steps Exercise 7 |

### TC-DE-011: Tune a Noisy Detection's False-Positive Rate

| Field | Value |
|------|-----|
| **ID** | TC-DE-011 |
| **Name** | Tune a Noisy Detection's False-Positive Rate |
| **Severity** | HIGH |
| **Category** | Detection CI/CD & Lifecycle |
| **Objective** | Take a Sigma rule that fires 50+ times per day on legitimate SCCM activity, identify the common FP signal, add a filter clause, re-test against 30 days of historical data, and confirm the FP rate drops below the target threshold. |
| **Tools** | Splunk SPL, Sigma YAML, historical SIEM data |
| **Test Steps** | 1. Pull every hit from the last 7 days: `index=win EventCode=1 Image="*\\rundll32.exe" CommandLine="*comsvcs.dll*MiniDump*" \| stats count by Computer, User, ParentImage \| sort -count \| outputlookup noisy-hits.csv`<br>2. Identify the dominant FP cluster: top-3 row by count, common `ParentImage` (likely `\sccm.exe`)<br>3. Edit the Sigma rule: add `filter_sccm: { ParentImage\|endswith: ['\sccm.exe', '\cmmcompiler.exe'] }` and update condition to `selection and not 1 of filter_*`<br>4. Re-translate to SPL: `sigma-cli convert -t splunk rule.yml`<br>5. Re-test against historical data: run the new SPL over `-30d`; confirm hit count dropped from 50/day to < 1/day<br>6. Re-validate against positive corpus: run the tuned rule against EVTX-ATTACK-SAMPLES; confirm it still fires on known-malicious<br>7. Commit: `git add rules/credential_access/comsvcs-minidump.yml && git commit -m "fix(detection): filter SCCM parent (FP 50/d → 0.3/d)"` |
| **Expected Result** | After tuning, the rule fires < 1 time per day on the historical 30-day dataset. The rule still fires on the positive EVTX corpus (true-positive rate preserved). The commit message documents the FP improvement. |
| **False Positive Risk** | LOW after tuning. The act of tuning IS FP management. Risk: over-tuning (filtering so aggressively that true positives are missed). Mitigation: always re-test against the positive corpus after each filter addition. |
| **Cleanup** | None — the tuned rule replaces the noisy one in the repo. |
| **References** | `payloads.md` §15.1, §15.2.1; `SKILL.md` Practical Steps Exercise 8 |

### TC-DE-012: Detection-as-Code Lifecycle — Author to Retirement

| Field | Value |
|------|-----|
| **ID** | TC-DE-012 |
| **Name** | Detection-as-Code Lifecycle — Author to Retirement |
| **Severity** | HIGH |
| **Category** | Detection CI/CD & Lifecycle |
| **Objective** | Execute the full detection-as-code lifecycle on one Sigma rule: threat-intel intake → draft → unit test → CI validation → staging soak → FP tuning → production ship → quarterly review → retirement. Demonstrate the workflow end-to-end. |
| **Tools** | Git, SigmaCLI, hayabusa, GitHub Actions, ATT&CK Navigator, ticketing system |
| **Test Steps** | 1. **Intake**: pick a TTP from a threat-intel report (e.g., `T1059.001` PowerShell download cradle); write a one-paragraph detection design capturing ATT&CK ID, log source, hypothesis, expected FP rate, Pyramid-of-Pain level<br>2. **Draft**: author `rules/execution/powershell-download-cradle.yml` with full Sigma structure (title, id, status: experimental, tags, logsource, detection, fields, falsepositives, level)<br>3. **Unit test**: run hayabusa against EVTX-ATTACK-SAMPLES (`test-data/positive/`); confirm rule fires; run against benign EVTX (`test-data/negative/`); confirm silence<br>4. **CI validation**: open a PR; CI pipeline runs schema validation, ATT&CK tag check, backend translation, positive/negative corpus tests; all must pass<br>5. **Peer review**: at least one detection engineer approves the PR<br>6. **Merge to main**: rule deploys to staging SIEM via CD pipeline<br>7. **Staging soak**: observe for 7-30 days; measure hit rate; triage each hit; tune FPs per TC-DE-011 if hit rate > threshold<br>8. **Promotion**: after soak with FP rate < 1/day, change `status: experimental → stable`; the rule deploys to production SIEM via CD<br>9. **Coverage update**: CI regenerates the ATT&CK Navigator coverage layer; the T1059.001 cell turns green<br>10. **Quarterly review** (simulated): run `scripts/rule-liveness.py rules/execution/powershell-download-cradle.yml --since 90d`; if hit count > 0, keep; if hit count = 0 for 24 months, retire<br>11. **Retirement** (simulated): `git mv rules/execution/powershell-download-cradle.yml rules/deprecated/`; edit `status: stable → deprecated`; commit; coverage layer regenerates (cell turns yellow or red) |
| **Expected Result** | A complete audit trail exists for the rule: intake ticket, draft YAML, positive/negative corpus test logs, CI run logs, peer review comments, staging soak metrics, FP-tuning commits, promotion commit, coverage-layer diff, retirement commit. Each phase has a documented exit criterion. |
| **False Positive Risk** | LOW for the lifecycle process. The lifecycle IS the FP management and quality gate mechanism. |
| **Cleanup** | If simulating in a sandbox, the `rules/deprecated/` and CI history can be cleaned. In production, the audit trail is permanent. |
| **References** | `payloads.md` §16; `SKILL.md` Practical Steps Exercises 9-10; `guides/detection-engineering-playbook.md` |

---

## Summary Table

| ID | Name | Severity | Category |
|------|------|------|------|
| TC-DE-001 | Author a Sigma Rule for Mimikatz (T1003.001) | CRITICAL | Sigma Rule Authoring |
| TC-DE-002 | Author a Sigma Rule for Suspicious PowerShell (T1059.001) | MEDIUM | Sigma Rule Authoring |
| TC-DE-003 | Author a Sigma Rule for AWS Console Login from New Geo (T1078) | MEDIUM | Sigma Rule Authoring |
| TC-DE-004 | Author a YARA Rule for a Malware Family | HIGH | YARA Rule Authoring |
| TC-DE-005 | Author a YARA Rule for Web Shell Detection | MEDIUM | YARA Rule Authoring |
| TC-DE-006 | Translate One Sigma Rule to Three SIEM Backends | MEDIUM | SigmaCLI & Translation |
| TC-DE-007 | Generate a YARA Rule with yarGen from Samples | HIGH | EVTX Scanning & Generation |
| TC-DE-008 | Scan EVTX Files with hayabusa | HIGH | EVTX Scanning & Generation |
| TC-DE-009 | Scan Files with Loki for YARA + IOC Matches | HIGH | EVTX Scanning & Generation |
| TC-DE-010 | Build a Detection CI Pipeline (GitHub Actions) | HIGH | Detection CI/CD & Lifecycle |
| TC-DE-011 | Tune a Noisy Detection's False-Positive Rate | HIGH | Detection CI/CD & Lifecycle |
| TC-DE-012 | Detection-as-Code Lifecycle — Author to Retirement | HIGH | Detection CI/CD & Lifecycle |

---

## Quick Severity Reference

| Severity | Meaning | Action |
|------|------|------|
| CRITICAL | Skill exercise produces a detection for the highest-impact TTP | Page on-call IR if detection fires in production |
| HIGH | Skill exercise involves real malware samples or full lifecycle | Handle with care; preserve audit trail |
| MEDIUM | Skill exercise involves rule authoring or translation | Standard care; validate before shipping |
| LOW | Skill exercise is documentation or planning | No special handling |

---

## Lab Setup Reference

For running these test cases, the following lab components are recommended:

| Component | Purpose | Source |
|------|------|------|
| SigmaCLI + pySigma backends | Rule parsing and translation | `pip install sigma-cli pySigma-backend-splunk pySigma-backend-elasticsearch pySigma-backend-microsoft365defender` |
| YARA | File scanning | `apt install yara` or build from source |
| yarGen | YARA rule generation | `git clone https://github.com/Neo23x0/yarGen.git` |
| Loki | IOC + YARA scanning | `git clone https://github.com/Neo23x0/Loki.git` |
| hayabusa | Sigma-to-EVTX fast scanning | `https://github.com/YamatoSecurity/hayabusa/releases` |
| zircollo | Sigma-to-EVTX offline (Python) | `git clone https://github.com/wagga40/zircollo.git` |
| EVTX-ATTACK-SAMPLES | Positive corpus | `git clone https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git` |
| Splunk Free | Local Splunk instance for SPL testing | `https://www.splunk.com/en_us/download.html` |
| Elastic Stack (single-node) | Local Elastic for EQL/Lucene testing | `docker.elastic.co/elasticsearch/elasticsearch` |
| Microsoft Sentinel (free tier) | KQL testing | Azure subscription required |
| Git + GitHub (or GitLab) | Detection-as-code repo + CI | `https://github.com/` or self-hosted GitLab |

For each test case, ensure the lab is configured BEFORE running the steps. Time spent on lab setup is repaid in reproducible test runs.
