# Continuous Learning — Test Cases

> Structured test scenarios for validating the continuous learning cycle. Each test case covers a specific phase of the learning pipeline, from pattern detection to knowledge maintenance. Companion to `SKILL.md` and `payloads.md`.

---

## Index

- [TC-CL-001: Attack Pattern Learning — SQL Injection Discovery](#tc-cl-001-attack-pattern-learning--sql-injection-discovery)
- [TC-CL-002: Tool Behavior Learning — False Positive Detection](#tc-cl-002-tool-behavior-learning--false-positive-detection)
- [TC-CL-003: Confidence Evolution — Low to High Promotion](#tc-cl-003-confidence-evolution--low-to-high-promotion)
- [TC-CL-004: Cross-Reference Validation — Contradiction Detection](#tc-cl-004-cross-reference-validation--contradiction-detection)
- [TC-CL-005: Knowledge Pruning — Stale Entry Lifecycle](#tc-cl-005-knowledge-pruning--stale-entry-lifecycle)
- [TC-CL-006: Multi-Skill Integration — Engagement Debrief Pipeline](#tc-cl-006-multi-skill-integration--engagement-debrief-pipeline)
- [TC-CL-007: Cross-Session Knowledge Aggregation](#tc-cl-007-cross-session-knowledge-aggregation)
- [TC-CL-008: Confidence Score Calibration](#tc-cl-008-confidence-score-calibration)
- [TC-CL-009: Skill Reinforcement Cycle Validation](#tc-cl-009-skill-reinforcement-cycle-validation)

---

## TC-CL-001: Attack Pattern Learning — SQL Injection Discovery

### Scenario

During a web application engagement, the agent discovers that a specific SQL injection technique (time-based blind injection via the `ORDER BY` clause) successfully bypasses a target's WAF. This novel pattern must be detected, structured, scored, stored, and cross-referenced against existing attack knowledge.

### Pre-conditions

1. Engagement is active with daily logs being written to `memory/`
2. Evidence of the successful injection exists in the evidence directory
3. MEMORY.md contains existing SQL injection knowledge entries
4. The specific `ORDER BY` time-based technique is not yet recorded
5. Continuous learning skill is activated

### Test Steps

1. **Pattern Detection**: Scan engagement logs for success indicators matching "injection confirmed" or "bypass successful"
2. **Extract & Structure**: Create a knowledge entry using the Attack Pattern template (KE-ATK-{NNN}), populating all fields including technique, prerequisites, steps, indicators of success, and counter-indications
3. **Confidence Scoring**: Apply the scoring worksheet — single observation (score 2/10 on observation count), successful reproduction (score 10/10 on reproduction), clear root cause (WAF did not inspect ORDER BY clause — score 8/10 on root cause)
4. **Calculate total score**: Weighted total determines confidence level (expect Medium range)
5. **Storage**: Store as a medium-term technique-level entry in MEMORY.md
6. **Cross-Reference**: Check existing SQL injection entries for contradictions or reinforcement; link to related web-sqli skill entries

### Expected Outcomes

| Criterion | Expected Result |
|-----------|-----------------|
| Pattern detection | Successful injection flagged as a learnable attack pattern |
| Entry structure | All Attack Pattern template fields populated with specific details |
| Confidence score | Medium confidence (40-74 range) — single observation but clear root cause |
| Storage tier | Medium-term (technique-level) in MEMORY.md, not just daily log |
| Cross-reference | Entry linked to existing SQL injection knowledge; no contradictions flagged |
| Source attribution | Entry traces back to specific engagement, date, and evidence file |
| Negative results included | Entry notes that the technique does NOT work against ModSecurity CRS rules |

### Post-conditions

- New KE-ATK entry exists in MEMORY.md with all required fields
- Entry is cross-referenced with existing SQL injection entries
- Daily log contains a reference to the new knowledge entry
- Confidence level is set for quarterly review (Medium tier)

---

## TC-CL-002: Tool Behavior Learning — False Positive Detection

### Scenario

During a network engagement, the agent observes that nmap's version detection (`-sV`) consistently misidentifies a custom HTTP server as "Apache 2.4.49" when it is actually a Go-based server returning similar headers. This tool behavior anomaly must be captured as a Tool Mastery Note to prevent future false positives.

### Pre-conditions

1. nmap version detection has been run against at least two targets with the same custom server
2. Manual verification (curl, direct banner grab) confirms the server is not Apache
3. Existing nmap knowledge entries exist in MEMORY.md
4. TOOLS.md has an nmap entry

### Test Steps

1. **Pattern Detection**: Scan logs for tool anomaly indicators — "false positive" or "incorrect result" near nmap references
2. **Extract & Structure**: Create a Tool Mastery Note (KE-TOOL-{NNN}) documenting the misidentification, the specific command flags, the misleading output, and the correct interpretation
3. **Confidence Scoring**: Two independent observations on different targets, manual verification confirms root cause — expect Medium-High confidence
4. **Storage**: Store in MEMORY.md tool knowledge section with gotcha documented
5. **Cross-Reference**: Link to existing nmap entries and note as a caveat for version detection workflows
6. **Verify no overwrite**: Existing nmap knowledge entries remain unchanged; new entry adds context

### Expected Outcomes

| Criterion | Expected Result |
|-----------|-----------------|
| Anomaly detection | False positive pattern identified from engagement logs |
| Entry completeness | Tool Mastery Note includes: command, context, gotcha, alternatives, and correct interpretation |
| Gotcha documented | Entry clearly states that `-sV` can misidentify Go HTTP servers as Apache |
| Alternatives noted | Entry suggests alternative verification methods (curl headers, response body analysis) |
| Confidence score | Medium-High (60-74 range) — two observations with confirmed root cause |
| Existing entries preserved | No modification to pre-existing nmap knowledge entries |
| TOOLS.md linkage | Entry references TOOLS.md nmap section for broader context |

### Post-conditions

- New KE-TOOL entry in MEMORY.md warns about nmap `-sV` false positives for Go servers
- Existing nmap entries are supplemented, not replaced
- Daily log notes the learning observation with a link to the new entry

---

## TC-CL-003: Confidence Evolution — Low to High Promotion

### Scenario

A knowledge entry about a specific SSH misconfiguration pattern was initially stored at Low confidence after a single observation. Over three subsequent engagements, the same pattern is observed independently. The confidence level must evolve through the defined promotion rules: Low to Medium after the second observation, then Medium to High after the third.

### Pre-conditions

1. KE-ENV-{NNN} entry exists in MEMORY.md with Low confidence (score 25/100)
2. Original entry has clear source attribution and date
3. Two new observations of the same pattern exist in recent engagement logs
4. Each observation is from a different target environment

### Test Steps

1. **First evolution (Low to Medium)**: Second observation confirmed in a different engagement
   a. Verify the new observation matches the existing pattern
   b. Apply upgrade rule: `low_to_medium` trigger = "second independent observation"
   c. Add new source attribution to the entry
   d. Recalculate confidence score (expect 45-60 range)
   e. Update review frequency from Monthly to Quarterly
2. **Second evolution (Medium to High)**: Third observation confirmed in yet another engagement
   a. Verify the third observation is truly independent (different target, different date)
   b. Apply upgrade rule: `medium_to_high` trigger = "third observation"
   c. Add third source attribution
   d. Recalculate confidence score (expect 75-85 range)
   e. Update review frequency from Quarterly to Annually
   f. Promote entry label from "provisional pattern" to "established pattern"
3. **Verify audit trail**: Entry contains complete history of confidence changes

### Expected Outcomes

| Criterion | Expected Result |
|-----------|-----------------|
| Low to Medium upgrade | Confidence increases from 25/100 to 45-60 range after second observation |
| Medium to High upgrade | Confidence increases to 75-85 range after third observation |
| Source accumulation | Entry lists all three observations with independent sources and dates |
| Review frequency update | Monthly (Low) to Quarterly (Medium) to Annually (High) |
| Pattern label | Changes from "observation only" to "provisional pattern" to "established pattern" |
| Audit trail | Entry includes dated log of each confidence change with trigger reason |
| No data loss | Original observation preserved; new observations are additive |

### Post-conditions

- KE-ENV entry now has High confidence with three independent sources
- Review frequency is set to Annual
- Entry is labeled as an established pattern
- Confidence evolution history is documented within the entry

---

## TC-CL-004: Cross-Reference Validation — Contradiction Detection

### Scenario

A new observation suggests that a previously recorded attack pattern (KE-ATK-005: "WordPress REST API always exposes user enumeration") no longer works on WordPress 6.5+. The cross-reference step must detect the contradiction, flag the existing entry, and store the corrective knowledge.

### Pre-conditions

1. KE-ATK-005 exists in MEMORY.md with Medium confidence claiming WordPress REST API user enumeration is universally effective
2. New observation from a WordPress 6.5 target shows the endpoint returns 403 (access restricted by default)
3. A second test on another WordPress 6.5 target confirms the behavior change

### Test Steps

1. **New observation**: Agent notes that user enumeration via `/wp-json/wp/v2/users` returns 403 on WordPress 6.5
2. **Cross-reference check**: Search MEMORY.md for existing entries about WordPress user enumeration
3. **Contradiction detected**: KE-ATK-005 claims the technique works universally, but new evidence contradicts this for version 6.5+
4. **Flag existing entry**: Add a contradiction flag to KE-ATK-005 with reference to new evidence
5. **Downgrade confidence**: Apply downgrade rule — existing entry confidence reduced from Medium to Low
6. **Store correction**: Create new entry (KE-ATK-{NNN}) documenting the version boundary: works on WordPress <6.5, blocked on 6.5+
7. **Link entries**: Cross-reference the old entry with the correction entry bidirectionally

### Expected Outcomes

| Criterion | Expected Result |
|-----------|-----------------|
| Contradiction detected | Cross-reference check identifies KE-ATK-005 as conflicting with new evidence |
| Existing entry flagged | KE-ATK-005 receives a contradiction flag with date and reference |
| Confidence downgrade | KE-ATK-005 confidence reduced from Medium to Low |
| Correction stored | New entry documents the version boundary with both working and non-working contexts |
| Bidirectional linking | Old entry references correction; correction entry references old entry |
| No data destruction | Original KE-ATK-005 is modified but not deleted — historical record preserved |
| Version specificity | Correction entry specifies exact version boundary (WordPress 6.5+) |

### Post-conditions

- KE-ATK-005 is flagged with contradiction and downgraded to Low confidence
- New correction entry exists with specific version applicability
- Both entries cross-reference each other
- Future queries about WordPress user enumeration return both entries with context

---

## TC-CL-005: Knowledge Pruning — Stale Entry Lifecycle

### Scenario

During periodic maintenance, the staleness detection command identifies multiple knowledge entries that have exceeded their review threshold. The pruning workflow must triage entries into retain, update, downgrade, archive, or delete actions.

### Pre-conditions

1. MEMORY.md contains at least 5 entries of varying confidence and age:
   - 1 High-confidence entry, 400 days old (exceeds 365-day threshold)
   - 1 Medium-confidence entry, 120 days old (exceeds 90-day threshold)
   - 1 Low-confidence entry, 45 days old (exceeds 30-day threshold)
   - 1 Medium-confidence entry, 60 days old (within threshold — control case)
   - 1 Entry that is factually incorrect (should be deleted)
2. Staleness detection script is available

### Test Steps

1. **Run staleness detection**: Scan MEMORY.md for entries exceeding their review threshold
2. **Verify detection**: Confirm 3 stale entries identified (High/400d, Medium/120d, Low/45d), 1 within threshold skipped
3. **Triage each stale entry**:
   a. High/400d: Knowledge still accurate — **Retain**, update review date
   b. Medium/120d: Target technology has changed — **Update** entry with new version info, reset date
   c. Low/45d: Never independently verified — **Downgrade** to archive with note
4. **Handle incorrect entry**: Identify the factually wrong entry — **Delete** with correction entry
5. **Execute all actions** and update cross-references
6. **Re-run staleness detection**: Verify 0 stale entries remain

### Expected Outcomes

| Criterion | Expected Result |
|-----------|-----------------|
| Detection accuracy | Exactly 3 entries flagged as stale; within-threshold entry not flagged |
| Retain action | High-confidence entry retains content, gets updated review date |
| Update action | Medium-confidence entry gets modified content and reset review date |
| Archive action | Low-confidence entry moved to archived section with explanation |
| Delete action | Incorrect entry removed; correction entry created in its place |
| Cross-reference cleanup | All references to archived/deleted entries updated or noted |
| Post-pruning state | Re-run of staleness detection shows 0 stale entries |

### Post-conditions

- All stale entries have been triaged and actioned
- No orphaned cross-references remain
- Maintenance actions logged in daily memory file
- Knowledge base is healthier: fewer stale entries, more accurate confidence levels

---

## TC-CL-006: Multi-Skill Integration — Engagement Debrief Pipeline

### Scenario

After completing a full penetration test engagement, the continuous learning skill must process all observations from the engagement, extract multiple knowledge entries across different categories, and coordinate with chronicle and verification-loop skills for recording and validation.

### Pre-conditions

1. Engagement is complete with 10+ daily logs in `memory/`
2. Evidence directory contains findings from web testing, network scanning, and post-exploitation
3. At least one novel attack pattern was discovered
4. At least one tool anomaly was observed
5. Chronicle skill is available for event recording
6. Verification-loop skill is available for finding validation

### Test Steps

1. **Bulk pattern detection**: Scan all engagement daily logs and evidence for learnable patterns across all categories (Attack, Defense, Tool, Environment, Engagement)
2. **Prioritize findings**: Rank detected patterns by novelty and impact
3. **Process top findings**:
   a. Novel attack pattern: Create KE-ATK entry, score confidence, store
   b. Tool anomaly: Create KE-TOOL entry, score confidence, store
   c. Environment pattern: Create KE-ENV entry, score confidence, store
   d. Engagement lesson: Create KE-ENG entry, score confidence, store
4. **Cross-reference all new entries**: Check each against existing knowledge, link related entries
5. **Chronicle integration**: Trigger chronicle recording for any P0/P1 events (significant discoveries, milestones)
6. **Verification integration**: Flag any Low-confidence entries for verification-loop validation
7. **Generate engagement debrief summary**: Statistics on entries created, confidence distribution, skills improved

### Expected Outcomes

| Criterion | Expected Result |
|-----------|-----------------|
| Pattern detection coverage | All five categories scanned; patterns detected in at least 3 categories |
| Entry creation | At least 4 knowledge entries created (one per category processed) |
| Confidence distribution | Mix of confidence levels reflecting evidence strength per finding |
| Cross-referencing | All new entries checked against existing knowledge; related entries linked |
| Chronicle trigger | Significant findings forwarded to chronicle for P0/P1 recording |
| Verification queue | Low-confidence entries flagged for verification-loop follow-up |
| Debrief summary | Statistics include: entries created, by category, by confidence, skills touched |
| No duplicate entries | New entries do not duplicate existing knowledge already in MEMORY.md |

### Post-conditions

- MEMORY.md contains new knowledge entries from the engagement
- Chronicle contains P0/P1 event records for significant discoveries
- Low-confidence findings are queued for verification
- Engagement debrief summary exists in the daily log
- All cross-references are valid and bidirectional

---

## TC-CL-007: Cross-Session Knowledge Aggregation

### Scenario

The agent has completed three separate engagements over a month, each targeting different technologies but encountering the same class of vulnerability: JWT algorithm confusion. Observations are split across multiple daily logs in different session directories. The continuous learning pipeline must aggregate these independent observations into a single, high-confidence knowledge entry with complete source attribution.

### Pre-conditions

1. Three completed engagements exist with daily logs in `memory/`
2. Each engagement independently discovered a JWT algorithm confusion issue:
   - Engagement A (Node.js API): `alg: none` bypass on `/api/auth`
   - Engagement B (Python Flask): RS256-to-HS256 key reuse on `/api/token`
   - Engagement C (Java Spring): Unverified `alg` header leading to key leak
3. No single knowledge entry yet covers the general JWT algorithm confusion pattern
4. Each observation is stored as a separate KE-ATK entry at Low or Medium confidence

### Test Steps

1. **Scan all engagement logs**: Run pattern detection across all daily logs from the past 30 days, searching for JWT-related vulnerability indicators
2. **Cluster related findings**: Group the three independent observations by vulnerability class (JWT algorithm confusion)
3. **Verify independence**: Confirm each observation is from a different target, date, and technology stack
4. **Create aggregated entry**: Merge the three KE-ATK entries into a single comprehensive KE-ATK entry covering the general pattern with technology-specific sub-variants
5. **Assign aggregated confidence**: Apply promotion rules — three independent observations qualify for High confidence (75+ score)
6. **Preserve source attribution**: List all three engagements as sources with dates, targets, and technology stacks
7. **Mark individual entries as superseded**: Flag the original three KE-ATK entries as merged into the aggregated entry
8. **Update cross-references**: Link the aggregated entry to web-auth-bypass and api-security skill entries

### Expected Outcomes

| Criterion | Expected Result |
|-----------|-----------------|
| Pattern detection across sessions | All three JWT observations identified from different engagement logs |
| Clustering accuracy | Observations correctly grouped under JWT algorithm confusion class |
| Independence verification | Each observation confirmed as unique target, date, and technology |
| Aggregated entry quality | Single entry covers general pattern plus three technology-specific variants |
| Confidence level | High (75-85 range) based on three independent observations with confirmed root causes |
| Source attribution | Entry lists all three engagements with dates, targets, and evidence references |
| Superseded entries | Original three entries marked as merged, not deleted |
| Cross-reference update | Aggregated entry linked to relevant skill domains |

### Post-conditions

- Single aggregated KE-ATK entry exists in MEMORY.md at High confidence
- Three original entries marked as superseded with bidirectional links
- Daily log records the aggregation event
- Cross-references to web-auth-bypass and api-security skills are updated

---

## TC-CL-008: Confidence Score Calibration

### Scenario

The agent's confidence scoring has drifted: recent Medium-confidence entries are proving unreliable in the field, while some Low-confidence entries have been independently verified by external sources. A calibration cycle must audit confidence assignments against actual field performance and adjust scoring weights accordingly.

### Pre-conditions

1. At least 20 knowledge entries exist in MEMORY.md across all confidence levels (Low, Medium, High)
2. At least 5 entries have been tested in subsequent engagements (field validation data available)
3. Some entries have external corroboration (CVE references, published research, community confirmation)
4. The confidence scoring worksheet has not been reviewed in over 90 days

### Test Steps

1. **Inventory all entries**: Extract all knowledge entries from MEMORY.md with their current confidence scores and scoring worksheet details
2. **Field performance audit**: For each entry that has been tested in subsequent engagements, record whether the knowledge was:
   - Confirmed accurate (true positive)
   - Partially accurate (needs update)
   - Inaccurate (false positive)
   - Not tested (no data)
3. **Calculate accuracy rates by tier**:
   - High tier accuracy rate = confirmed / (confirmed + inaccurate)
   - Medium tier accuracy rate = confirmed / (confirmed + inaccurate)
   - Low tier accuracy rate = confirmed / (confirmed + inaccurate)
4. **Identify misaligned entries**:
   - Medium entries with < 50% accuracy → flag for downgrade
   - Low entries with > 80% accuracy → flag for upgrade
   - High entries with < 70% accuracy → flag for review
5. **Adjust scoring weights**: If systematic drift is detected (e.g., observation count is overweighted relative to root cause clarity), adjust the scoring worksheet weights
6. **Apply corrections**: Downgrade or upgrade flagged entries with documented justification
7. **Record calibration event**: Log the calibration results, including before/after statistics, in the daily log

### Expected Outcomes

| Criterion | Expected Result |
|-----------|-----------------|
| Field performance collected | Accuracy data gathered for all entries tested in subsequent engagements |
| Tier accuracy rates calculated | Numeric accuracy rates computed for High, Medium, and Low tiers |
| Misaligned entries identified | Specific entries flagged where confidence does not match field performance |
| Downgrades executed | Overconfident entries reduced to appropriate level |
| Upgrades executed | Underconfident entries promoted with justification |
| Scoring weights adjusted | Worksheet parameters updated if systematic drift detected |
| Calibration logged | Complete before/after statistics recorded in daily log |

### Post-conditions

- All knowledge entries reflect calibrated confidence levels
- Scoring worksheet weights updated if drift was detected
- Calibration statistics are available for the next review cycle
- Daily log contains the calibration audit trail

---

## TC-CL-009: Skill Reinforcement Cycle Validation

### Scenario

The agent has not used the binary-reverse skill in 60 days. The reinforcement cycle should detect that this skill is decaying, schedule a refresher exercise, validate that the skill has been refreshed, and confirm that the skill's knowledge entries remain current. This tests the complete reinforcement loop from decay detection through re-validation.

### Pre-conditions

1. The binary-reverse skill has a last-used timestamp older than 45 days
2. The skill has associated knowledge entries in MEMORY.md (tool notes, technique patterns)
3. The reinforcement schedule defines a 30-day interval for active skills and 45-day for backup skills
4. A refresher exercise exists in the skill's `guides/` directory

### Test Steps

1. **Decay detection**: Run the skill freshness check against all skills in IDENTITY.md. Verify that binary-reverse is flagged as stale (last used > 45 days ago)
2. **Prioritize refresh**: Confirm that the stale skill is queued for refresher based on its role (active vs. backup) and time since last use
3. **Execute refresher**: Perform the binary-reverse refresher exercise:
   a. Read the skill's SKILL.md and top guides
   b. Execute a practice exercise (e.g., basic ELF analysis with Ghidra)
   c. Document the refresher session in the daily log
4. **Validate refresh**: After the refresher exercise:
   a. Confirm the skill's last-used timestamp is updated
   b. Verify the skill is no longer flagged as stale
   c. Confirm the refresher log entry exists in `memory/`
5. **Knowledge currency check**: Verify that the skill's associated MEMORY.md entries are still accurate:
   a. Check tool versions referenced in entries against current versions
   b. Flag any entries referencing deprecated tools or techniques
   c. Update entries if needed or schedule for the next knowledge maintenance cycle
6. **Record reinforcement event**: Log the complete reinforcement cycle (detection, prioritization, execution, validation, knowledge check) in the daily log

### Expected Outcomes

| Criterion | Expected Result |
|-----------|-----------------|
| Decay detection | binary-reverse skill correctly flagged as stale |
| Prioritization | Skill queued with correct priority based on role and age |
| Refresher execution | Practice exercise completed with documented results |
| Timestamp update | Skill's last-used timestamp reflects the refresher date |
| Staleness cleared | Skill no longer appears in the stale skills list |
| Knowledge currency | Tool version references validated; deprecated entries flagged |
| Complete audit trail | Daily log contains full reinforcement cycle documentation |

### Post-conditions

- binary-reverse skill is marked as refreshed with updated timestamp
- Refresher exercise results are documented in the daily log
- Knowledge entries are validated for currency or flagged for update
- The reinforcement cycle is verified end-to-end for future automated execution
