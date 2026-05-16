# Multi-Agent Collaboration — Test Cases

Structured test cases for validating multi-agent coordination, task decomposition, result aggregation, conflict resolution, and full coordinator-worker engagements.

---

## TC-MC-001: Parallel Reconnaissance

**Objective**: Validate that three independent agents can simultaneously conduct OSINT, port scanning, and web discovery on the same target without interference, and that coordinator correctly aggregates non-overlapping results.

**Collaboration Model**: Model 3 — Tool Specialization

**Agents Involved**:
- OSINT-Agent (theHarvester, amass, shodan)
- Network-Scanner-Agent (nmap, masscan)
- Web-Discovery-Agent (ffuf, whatweb, nikto)

**Prerequisites**:
- Target host in-scope and reachable
- Authorization document confirmed
- All three agent mandates written using Section 2 templates from `payloads.md`
- Evidence logging directory prepared

### Setup

1. Define scope: single target IP + its associated domain (e.g., `192.168.10.50` / `target.lab`)
2. Confirm scope is legal and authorization is current
3. Prepare three separate agent instances with their role definition prompts (from `payloads.md` Section 2)
4. Set shared time budget: 30 minutes
5. Initialize coordinator agent with Coordinator Dispatch Template (Section 3)
6. Prepare coverage matrix with three rows (OSINT scope, network scope, web scope)

### Steps

1. Coordinator dispatches all three agents simultaneously — record dispatch timestamps
2. Agents run in parallel using their designated tool sets:
   - OSINT-Agent: `theHarvester -d target.lab -b all`, `amass enum -d target.lab`, Shodan lookup
   - Network-Scanner-Agent: `nmap -sV -sC -T3 192.168.10.50`, `masscan -p1-65535 192.168.10.50`
   - Web-Discovery-Agent: `whatweb http://192.168.10.50`, `nikto -h http://192.168.10.50`, `ffuf -u http://192.168.10.50/FUZZ -w /usr/share/wordlists/dirb/common.txt`
3. Monitor each agent at 10-minute checkpoints; log status
4. Collect results from all three agents after 30 minutes (or earlier if all complete)
5. Run deduplication checklist (Section 5 of `payloads.md`) on combined findings
6. Build coverage matrix and verify all three scope rows show Status=Complete
7. Confirm no agent touched another agent's designated tool set

### Expected Results

- All three agents return results independently within 30-minute window
- Finding sets are non-overlapping in category (OSINT findings ≠ port scan findings ≠ web findings)
- If same host appears in both OSINT and network scan (same IP), entries are correctly categorized — not flagged as duplicates (different finding types)
- Deduplication step reports 0 merged duplicates (findings are complementary, not overlapping)
- Coverage matrix shows 3/3 rows with Status=Complete

### Verification

- [ ] Each agent's log shows it used only its designated tools
- [ ] No agent produced findings in another agent's category (OSINT agent did not port scan)
- [ ] Coordinator received all three result sets
- [ ] Combined finding count equals sum of individual agent finding counts (no silent drops)
- [ ] Coverage matrix is fully populated with no gaps

**Complexity**: Low

---

## TC-MC-002: Multi-Target Scan Aggregation

**Objective**: Validate that five independent target agents can assess five separate web applications simultaneously, return results in standard finding JSON format, and that coordinator correctly aggregates and deduplicates the combined finding set.

**Collaboration Model**: Model 2 — Target Parallelization

**Agents Involved**:
- Web-Tester-T01 through Web-Tester-T05 (one per target)
- Coordinator Agent

**Prerequisites**:
- Five distinct web application targets, all in-scope and reachable
- All five are assessable with identical methodology (web application assessment)
- Standard finding JSON schema (Section 4 of `payloads.md`) reviewed by all agents
- Time budget: 45 minutes per agent

### Setup

1. List five targets: `app1.lab`, `app2.lab`, `app3.lab`, `app4.lab`, `app5.lab`
2. Confirm all five targets are in authorization scope
3. Prepare five agent instances, each with Web Tester Agent mandate (Section 2 of `payloads.md`), assigned to one target
4. Inject same known vulnerability type (SQL injection) into `app2.lab` and `app4.lab` to test deduplication — these are distinct instances on distinct targets, so they should NOT be merged
5. Initialize coordinator with target decomposition template (Section 1b of `payloads.md`)

### Steps

1. Coordinator dispatches all five Web-Tester agents simultaneously
2. Each agent runs full web application assessment on assigned target:
   - Endpoint discovery: `ffuf -u http://{target}/FUZZ -w /usr/share/wordlists/dirb/common.txt`
   - Vulnerability scan: `nikto -h http://{target}` and `nuclei -u http://{target}`
   - Injection test: `sqlmap -u "http://{target}/search?q=test" --level=3 --risk=2`
3. All agents return findings in standard finding JSON format
4. Coordinator collects all five result sets
5. Run deduplication checklist: SQL injection on `app2.lab` vs SQL injection on `app4.lab` — different targets, should NOT be merged
6. Build master finding list
7. Build coverage matrix with five rows (one per target)

### Expected Results

- Five agents return results within 45-minute window
- SQL injection findings on `app2.lab` and `app4.lab` are retained as distinct findings (same title, different targets)
- Deduplication step correctly identifies them as distinct (target host differs in target.host field)
- Coverage matrix shows 5/5 rows with Status=Complete
- Master finding list includes findings from all five targets without data loss
- Finding IDs are globally unique across all five agent result sets

### Verification

- [ ] All five agents returned results (no timeout gaps)
- [ ] SQL injection on `app2.lab` and `app4.lab` are two separate entries in master finding list
- [ ] Each finding has a unique `finding_id` with correct `agent_id` prefix
- [ ] `reported_by` arrays contain exactly one agent_id each (no phantom merges)
- [ ] Coverage matrix: 5/5 complete, 0 gaps
- [ ] Master finding list `total_findings` matches manual count

**Complexity**: Medium

---

## TC-MC-003: Finding Deduplication and Conflict Resolution

**Objective**: Validate the deduplication and conflict resolution procedures when two agents independently discover the same vulnerability instance with differing severity ratings, and when one agent reports a finding the other contradicts.

**Collaboration Model**: Model 3 — Tool Specialization (web testing with two concurrent agents)

**Agents Involved**:
- Web-Tester-A (sqlmap, automated scanner)
- Web-Tester-B (manual/Burp-equivalent approach)
- Verification-Agent (independent retest)
- Coordinator Agent

**Prerequisites**:
- Single target with a confirmed SQL injection vulnerability at `/search?q=`
- Web-Tester-A configured to rate this finding as High severity (standard automated score)
- Web-Tester-B configured to rate the same finding as Critical severity (manual analysis with full exploitation chain demonstrated)
- Second endpoint `/login` — Web-Tester-A reports reflected XSS, Web-Tester-B reports no vulnerability found there

### Setup

1. Target: `vulnapp.lab` with SQLi at `/search?q=` and ambiguous `/login` endpoint
2. Deploy Web-Tester-A with automated scanner methodology
3. Deploy Web-Tester-B with manual methodology
4. Both agents run in parallel
5. Coordinator collects both result sets and initiates deduplication + conflict resolution

### Steps

**Part A — Severity Conflict (SQLi)**:

1. Web-Tester-A returns: SQLi at `/search?q=`, severity=High, evidence: sqlmap confirmation
2. Web-Tester-B returns: SQLi at `/search?q=`, severity=Critical, evidence: manual full DB dump PoC
3. Coordinator identifies duplicate candidate: same title + same target + same path
4. Run deduplication Step 3: evidence confirms same vulnerability instance → confirmed duplicate
5. Apply deduplication Step 4: keep Critical (higher severity), keep Confirmed (higher confidence), merge evidence
6. Verify merged finding has both agent IDs in `reported_by` array

**Part B — Existence Conflict (XSS)**:

1. Web-Tester-A returns: Reflected XSS at `/login`, severity=Medium, evidence: payload `<script>alert(1)</script>` reflected in response
2. Web-Tester-B returns: No XSS found at `/login` after manual testing
3. Coordinator identifies conflict: same title + same target + same path → conflicting status
4. Apply Conflict Resolution Decision Tree (Section 6 of `payloads.md`):
   - Step 1: gather both evidence sets
   - Step 2: methodology differs (automated vs manual) — investigate
   - Step 3: target state consistent (tested within same window)
   - Step 4: dispatch Verification-Agent with both methodologies
5. Verification-Agent tests `/login` with both approaches → returns result
6. Apply Step 5 based on Verification-Agent result

### Expected Results

**Part A**:
- Single merged SQLi finding in master list (not two)
- Severity = Critical (higher wins)
- Confidence = Confirmed (higher wins)
- `reported_by` = ["web-tester-a-01", "web-tester-b-01"]
- `corroborating_evidence` includes both agents' evidence
- `duplicates_merged` counter = 1

**Part B** (assuming Verification-Agent confirms XSS):
- XSS finding status = "Verified"
- Evidence from all three agents attached
- Finding severity = Medium
- `reported_by` includes all contributing agents

**Part B** (if Verification-Agent returns inconclusive):
- XSS finding status = "Conflict — Manual Verification Required"
- Severity = Medium (higher of the two)
- All three evidence sets attached
- Finding flagged for human review

### Verification

- [ ] Part A: exactly one SQLi entry in master list (not two)
- [ ] Part A: severity = Critical, confidence = Confirmed
- [ ] Part A: `reported_by` has 2 agent IDs
- [ ] Part B: conflict correctly flagged (not silently resolved to one agent's view)
- [ ] Part B: Verification-Agent dispatched and result applied
- [ ] Part B: if unresolved conflict — finding is NOT closed as clean; it is escalated
- [ ] `duplicates_merged` = 1, `conflicts_resolved` matches actual resolution count

**Complexity**: Medium

---

## TC-MC-004: Coverage Verification and Gap Detection

**Objective**: Validate that the coordinator's coverage verification matrix correctly identifies scope items that received no assessment (gaps), partially assessed items, and fully assessed items — and that gap actions are taken before engagement is closed.

**Collaboration Model**: Model 4 — Coordinator-Worker Pattern

**Agents Involved**:
- Coordinator Agent
- Worker-A (Network scope)
- Worker-B (Web applications — intended to time out before completing)
- Worker-C (OSINT — intended to fail)

**Prerequisites**:
- Scope defined with 5 items: network range, 3 web apps, OSINT footprint
- Worker-B is given insufficient time budget (simulate partial coverage)
- Worker-C is given unreachable target (simulate agent failure)

### Setup

1. Define scope:
   - `192.168.20.0/24` (network) → assigned to Worker-A
   - `app1.lab` → assigned to Worker-B (full budget: 30 min)
   - `app2.lab` → assigned to Worker-B (insufficient budget: 5 min — will be partial)
   - `app3.lab` → Worker-C (unreachable target — agent fails)
   - OSINT footprint → Coordinator assigns to Worker-C (same failure)
2. Coordinator initializes coverage matrix with 5 rows, all Status=Unstarted
3. Dispatch all workers simultaneously

### Steps

1. Worker-A completes successfully — returns 4 findings for network scope
2. Worker-B completes `app1.lab` fully (30 min budget) — returns 2 findings
3. Worker-B hits time budget on `app2.lab` at 60% coverage — returns partial results (1 finding), status=Partial
4. Worker-C cannot reach `app3.lab` — returns failure report, 0 findings
5. Worker-C's OSINT task also fails due to dependency on unreachable infrastructure
6. Coordinator updates coverage matrix:
   - `192.168.20.0/24`: Complete, 4 findings
   - `app1.lab`: Complete, 2 findings
   - `app2.lab`: Partial, 1 finding, "60% coverage reached before time budget expired"
   - `app3.lab`: Failed, 0 findings, "target unreachable"
   - OSINT: Failed, 0 findings, "agent failure"
7. Coordinator executes gap actions:
   - `app2.lab` Partial: dispatches new agent with remaining-scope brief
   - `app3.lab` Failed: confirms target is genuinely unreachable (ping/traceroute) → documents as known gap with evidence of unreachability
   - OSINT Failed: reassigns to new agent instance
8. Coordinator re-runs coverage matrix after gap actions
9. Final matrix audit: all rows must show Complete, Partial (with documented justification), or Gap (with evidence)

### Expected Results

- Initial coverage matrix correctly shows 2 failed rows and 1 partial row
- Gap actions dispatched for all non-Complete rows
- After gap resolution: `app2.lab` shows Complete or documented Partial with remaining-scope noted
- `app3.lab` documented as known gap with unreachability evidence (not silently ignored)
- OSINT reassigned and completed (or also documented as gap if retry fails)
- Engagement is NOT closed while any row shows Failed without gap documentation

### Verification

- [ ] Coverage matrix has a row for every scope item (5 rows for 5 scope items)
- [ ] No scope item is silently omitted from matrix
- [ ] Every non-Complete row has a gap action recorded
- [ ] Gap actions were actually executed (not just noted)
- [ ] `coverage_gaps` field in master finding list lists the unresolved gaps
- [ ] Engagement close checklist confirms coordinator reviewed every gap

**Complexity**: Medium

---

## TC-MC-005: Complete Coordinated Penetration Test

**Objective**: Validate the full end-to-end multi-agent penetration test lifecycle — from scope intake through coordinator dispatch, parallel agent execution, deduplication, conflict resolution, coverage verification, finding verification, and final report generation — using the Coordinator-Worker pattern on a multi-component lab environment.

**Collaboration Model**: Model 4 — Coordinator-Worker Pattern (with elements of all four models)

**Agents Involved**:
- Coordinator Agent (orchestrator, aggregator)
- Recon-Agent (passive recon + OSINT)
- Network-Scanner-Agent (port/service enumeration)
- Web-Tester-Agent (web application assessment, 2 instances)
- Exploit-Agent (targeted exploitation of confirmed vulnerabilities)
- Verification-Agent (independent confirmation of Critical/High findings)
- Report-Writer-Agent (final report synthesis)

**Prerequisites**:
- Lab environment: 3 hosts — `10.10.10.10` (Linux server), `10.10.10.11` (Windows server), `app.lab` (web app)
- Authorization document signed and current
- All agent role definition prompts prepared from `payloads.md` Section 2
- Evidence logging directory initialized
- All agents have access to `safety-guard` scope enforcement

### Setup

1. Coordinator reads scope: `10.10.10.10`, `10.10.10.11`, `app.lab`
2. Coordinator selects Phase Decomposition model for `10.10.10.10` and `10.10.10.11`; Tool Specialization for `app.lab`
3. Coordinator initializes coverage matrix (5 scope items: 2 hosts × network+web scope, 1 web app)
4. Coordinator dispatches Phase 1 (Recon) and Web Discovery simultaneously — both immediate-start

### Steps

**Phase 1 — Recon + Web Discovery (parallel)**:
1. Recon-Agent: passive DNS, WHOIS, certificate transparency for `app.lab` + subnet OSINT for `10.10.10.0/24`
2. Web-Discovery-Agent: `whatweb http://app.lab`, `ffuf -u http://app.lab/FUZZ`, initial nikto scan
3. Both agents return results; coordinator updates coverage matrix

**Phase 2 — Network Scanning (triggered by Phase 1 host list)**:
1. Coordinator triggers Network-Scanner-Agent with host list from Recon
2. Network-Scanner-Agent: `nmap -sV -sC -A -p- 10.10.10.10 10.10.10.11`
3. Returns: Linux host running SSH:22, HTTP:80, MySQL:3306; Windows host running SMB:445, RDP:3389, HTTP:8080

**Phase 3 — Web Testing + Initial Exploitation (parallel where possible)**:
1. Web-Tester-01 assigned to `app.lab` — full web assessment
2. Web-Tester-02 assigned to `http://10.10.10.10:80` and `http://10.10.10.11:8080`
3. Both web testers run in parallel
4. Exploit-Agent triggered by Network-Scanner results: `SMB:445` on Windows host with EternalBlue candidate — dispatched to test MS17-010

**Phase 4 — Aggregation**:
1. Coordinator collects all results
2. Runs deduplication (SMB finding reported by both Network-Scanner and Exploit-Agent — merge)
3. Runs conflict resolution (Web-Tester-01 and Web-Tester-02 both found SQLi on app.lab — same finding, different evidence — merge as duplicate)
4. Builds master finding list
5. Audits coverage matrix — all 5 scope items showing Complete

**Phase 5 — Verification**:
1. Coordinator dispatches Verification-Agent for all Critical findings: MS17-010 (Critical), SQLi with DB access (Critical)
2. Verification-Agent independently confirms both
3. Status updated to "Verified" in master finding list

**Phase 6 — Report**:
1. Coordinator dispatches Report-Writer-Agent with master finding list
2. Report-Writer produces structured report: executive summary, technical findings, remediation roadmap
3. Coordinator performs final quality gate check (all 7 items from SKILL.md Quality Gate)
4. Engagement closed

### Expected Results

- Coordinator dispatched all 7 agents in correct order respecting phase dependencies
- Phase 1 and Web Discovery ran truly in parallel (both start timestamps within 30 seconds of each other)
- Phase 2 triggered only after Phase 1 host list was available
- Deduplication merged SMB finding and SQLi finding (each appeared in 2 agents' result sets) → 2 merged
- Conflict resolution log shows 0 conflicts (no contradictions in this engagement)
- Coverage matrix: 5/5 Complete
- Master finding list: all Critical/High findings have status=Verified
- Final report produced and returned to operator
- All 7 Quality Gate checks passed

### Verification

- [ ] Coordinator log shows correct phase dependency enforcement (Phase 2 waited for Phase 1)
- [ ] Parallel phase timestamps confirm true parallel execution
- [ ] `duplicates_merged` = 2 in master finding list
- [ ] `conflicts_resolved` = 0 (no conflicts in this run)
- [ ] Coverage matrix: 5/5 rows Complete, 0 gaps
- [ ] All Critical/High findings status = "Verified" (not just "Confirmed")
- [ ] Report-Writer output contains executive summary, technical findings, and remediation roadmap
- [ ] Quality Gate: all 7 checks passed (documented in coordinator log)
- [ ] No agent exceeded its assigned scope (safety-guard logs reviewed)
- [ ] Total wall-clock time < single-agent equivalent (validate parallelism benefit)

**Complexity**: High
