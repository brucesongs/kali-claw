# Chronicle System — Test Cases

> Structured test scenarios for validating chronicle system operations. Each test case covers a specific chronicle workflow, from event recording to knowledge distillation and maintenance. Companion to `SKILL.md` and `payloads.md`.

---

## Index

- [TC-CH-001: P0 Event Recording — Critical Security Discovery](#tc-ch-001-p0-event-recording--critical-security-discovery)
- [TC-CH-002: P1 Milestone Recording — Tool Mastery Achievement](#tc-ch-002-p1-milestone-recording--tool-mastery-achievement)
- [TC-CH-003: Memory Archival Process — 30-Day Distillation](#tc-ch-003-memory-archival-process--30-day-distillation)
- [TC-CH-004: Monthly Summary Generation](#tc-ch-004-monthly-summary-generation)
- [TC-CH-005: Cross-System Integration Trigger](#tc-ch-005-cross-system-integration-trigger)
- [TC-CH-006: Index Integrity Validation](#tc-ch-006-index-integrity-validation)

---

## TC-CH-001: P0 Event Recording — Critical Security Discovery

### Scenario

During a penetration test engagement, the agent discovers a critical SQL injection vulnerability that exposes the target database. This P0 event must be recorded immediately with full detail, indexed in CHRONICLE.md, and knowledge distilled to MEMORY.md.

### Pre-conditions

1. Agent is in an active engagement session with daily log in `memory/`
2. Chronicle directory structure exists: `chronicle/YYYY-MM/`
3. `CHRONICLE.md` index file exists at project root
4. `MEMORY.md` exists at project root
5. Evidence files from the discovery are available

### Test Steps

1. Classify the event: Security Discovery, Priority P0
2. Create detail file at `chronicle/{YYYY-MM}/{YYYY-MM-DD}-critical-sqli-in-target.md` using the P0 Security Discovery template
3. Populate all required sections: Summary (one-liner + key outcomes), Background, Process (Detection, Confirmation, Impact Assessment phases), Outputs (linked evidence files), Impact, Related
4. Update `CHRONICLE.md` with a new index entry including type, priority, one-liner, outcomes, and detail link
5. Distill lesson to `MEMORY.md` with source attribution back to the chronicle entry
6. Verify cross-references: daily log links to chronicle, chronicle links to MEMORY.md

### Expected Outcomes

| Criterion | Expected Result |
|-----------|-----------------|
| Recording delay | P0 event recorded within the current session (0 delay) |
| Detail file | `chronicle/YYYY-MM/YYYY-MM-DD-critical-sqli-in-target.md` exists with all required sections |
| Summary quality | One-liner captures vulnerability type, target, and severity in a single sentence |
| Process phases | All three phases (Detection, Confirmation, Impact Assessment) are populated |
| Evidence links | Outputs section links to actual evidence files that exist on disk |
| Index entry | `CHRONICLE.md` contains a new entry with correct date, type, priority, and detail link |
| Knowledge distillation | `MEMORY.md` contains a new entry referencing the chronicle source |
| Cross-references | Detail file links to daily log and MEMORY.md section; MEMORY.md links back to chronicle |

### Post-conditions

- Chronicle detail file is complete and self-contained
- CHRONICLE.md index is updated and links resolve correctly
- MEMORY.md contains the distilled lesson with source attribution
- No orphaned entries (all links are bidirectional)

---

## TC-CH-002: P1 Milestone Recording — Tool Mastery Achievement

### Scenario

The agent completes mastery of the nmap tool suite, having demonstrated proficiency across all scanning modes, output formats, and scripting engine usage. This P1 milestone must be recorded same-day with process documentation and cross-updates to TOOLS.md and IDENTITY.md.

### Pre-conditions

1. Agent has completed nmap learning plan documented in daily logs
2. `TOOLS.md` contains an nmap entry with current mastery status
3. `IDENTITY.md` contains relevant skill tags
4. Chronicle directory for current month exists

### Test Steps

1. Classify the event: Milestone Achieved, Priority P1
2. Create detail file at `chronicle/{YYYY-MM}/{YYYY-MM-DD}-nmap-mastery-milestone.md` using the P0 Milestone Achieved template (P1 uses same structure with abbreviated Process)
3. Populate Summary with metrics: number of techniques mastered, tools covered, practice targets used
4. Document Process: Preparation (study plan), Execution (how mastery was achieved), Verification (how confirmed)
5. Update Outputs section with links to `TOOLS.md` nmap entry and `IDENTITY.md` skill tag
6. Update `CHRONICLE.md` index with new milestone entry
7. Verify recording occurred within the same working session (P1 deadline)

### Expected Outcomes

| Criterion | Expected Result |
|-----------|-----------------|
| Recording timing | Milestone recorded within the same working day |
| Detail file | Chronicle entry exists with Summary, Background, Process, Outputs, Impact sections |
| Metrics captured | Summary includes concrete numbers: techniques mastered, practice targets used |
| Process documentation | At least Preparation and Verification phases documented |
| Cross-updates | Outputs section references TOOLS.md and IDENTITY.md by path |
| Index entry | CHRONICLE.md updated with milestone type, P1 priority, and detail link |
| No scope creep | Recording focuses on the nmap milestone only, not unrelated events |

### Post-conditions

- Chronicle detail file documents the complete mastery journey
- CHRONICLE.md index reflects the new milestone
- TOOLS.md nmap entry can be independently verified against chronicle claims

---

## TC-CH-003: Memory Archival Process — 30-Day Distillation

### Scenario

Memory files older than 30 days need to be archived. The archival process must extract important content to chronicle entries, distill lessons to MEMORY.md, and mark original files as archived without deleting them.

### Pre-conditions

1. `memory/` directory contains files older than 30 days with significant content
2. At least one memory file contains a notable event that has not been recorded in chronicle
3. At least one memory file has already been fully archived (control case)
4. CHRONICLE.md and MEMORY.md exist

### Test Steps

1. Run stale entry detection: scan `memory/` for files older than 30 days
2. For each stale file, check if it has already been archived in chronicle
3. For unarchived files, extract significant events meeting P0/P1/P2 thresholds
4. Create chronicle detail entries for extracted events
5. Update CHRONICLE.md index with new entries
6. Distill reusable lessons to MEMORY.md with source attribution
7. Mark original memory files as archived by adding `> [ARCHIVED]` header
8. Verify no original memory files were deleted

### Expected Outcomes

| Criterion | Expected Result |
|-----------|-----------------|
| Stale detection | All memory files older than 30 days identified correctly |
| Already-archived skip | Files already in chronicle are detected and skipped |
| Event extraction | Significant events are identified and classified by priority |
| Chronicle entries | New detail files created in `chronicle/YYYY-MM/` for each extracted event |
| Index update | CHRONICLE.md updated with all new entries |
| MEMORY.md distillation | Lessons from archived events added to MEMORY.md with source links |
| Archive marking | Original memory files have `> [ARCHIVED]` header added |
| No data loss | Original memory files are preserved — never deleted |
| Completeness | No significant events lost in the archival process |

### Post-conditions

- All memory files older than 30 days are marked as archived
- Chronicle contains entries for all significant events from archived files
- MEMORY.md contains distilled lessons with source attribution
- Original memory files remain on disk for reference

---

## TC-CH-004: Monthly Summary Generation

### Scenario

At the end of a month, a summary must be generated aggregating all chronicle events, statistics, highlights, and carry-forward items. The summary must accurately reflect all events recorded during the month.

### Pre-conditions

1. `chronicle/YYYY-MM/` directory contains at least 5 event files of mixed priorities
2. At least one P0 event, two P1 events, and two P2 events exist
3. At least one event has been distilled to MEMORY.md
4. At least one event has NOT been distilled (for carry-forward detection)

### Test Steps

1. Count all chronicle entries for the month by priority level
2. Categorize events by type (Security Discovery, Milestone, Environment, Learning, etc.)
3. Generate statistics table: total events, P0/P1/P2 counts, discoveries, milestones, distilled entries
4. Identify top 3 highlights (P0 events first, then by impact)
5. List events grouped by category with date, name, and one-liner
6. Generate knowledge distillation table showing entries, sources, confidence, and MEMORY.md sections
7. Identify carry-forward items: undistilled events, pending follow-ups
8. Write summary to `chronicle/YYYY-MM/SUMMARY.md`

### Expected Outcomes

| Criterion | Expected Result |
|-----------|-----------------|
| Statistics accuracy | Event counts match actual files in the directory (P0 + P1 + P2 = total) |
| Highlight selection | Top 3 highlights prioritize P0 events and high-impact discoveries |
| Category grouping | Events correctly categorized by type with no misclassification |
| Distillation tracking | Knowledge table accurately reflects which entries have been distilled |
| Carry-forward detection | Undistilled events listed as carry-forward items |
| File output | `chronicle/YYYY-MM/SUMMARY.md` created with all sections populated |
| No data fabrication | Summary only references events that actually exist in the directory |

### Post-conditions

- Monthly summary file exists at `chronicle/YYYY-MM/SUMMARY.md`
- All statistics are independently verifiable against the chronicle directory
- Carry-forward items provide actionable next steps for the following month

---

## TC-CH-005: Cross-System Integration Trigger

### Scenario

A safety-guard incident occurs during an autonomous loop. The incident must flow through the chronicle pipeline: recorded as a P0 event in chronicle, indexed in CHRONICLE.md, and trigger a continuous-learning knowledge extraction. This tests the cross-skill pipeline defined in the chronicle orchestration.

### Pre-conditions

1. An autonomous loop is running with safety-guard active
2. Safety-guard detects and logs a scope violation incident
3. Chronicle system is operational
4. Continuous-learning skill is available for knowledge extraction
5. HEARTBEAT.md has P0 event checking enabled

### Test Steps

1. Safety-guard raises a Level 2 incident (service impact from scope violation)
2. HEARTBEAT.md periodic check detects the P0 event requiring recording
3. Chronicle system creates detail file: `chronicle/YYYY-MM/YYYY-MM-DD-scope-violation-incident.md`
4. Detail file includes: incident timeline, safety-guard response, evidence preserved, root cause
5. CHRONICLE.md index updated with the incident entry
6. Continuous-learning skill extracts a defense pattern from the incident (scope checking improvement)
7. Knowledge entry stored in MEMORY.md with cross-reference to chronicle and safety-guard
8. Verify the full pipeline: `safety-guard -> chronicle -> CHRONICLE.md -> MEMORY.md -> continuous-learning`

### Expected Outcomes

| Criterion | Expected Result |
|-----------|-----------------|
| Trigger detection | HEARTBEAT.md check identifies the P0 event from safety-guard |
| Chronicle recording | Detail file created with incident-specific sections (timeline, response, evidence) |
| Index update | CHRONICLE.md entry references both the incident and safety-guard skill |
| Knowledge extraction | Continuous-learning produces a structured knowledge entry from the incident |
| Cross-references | Chronicle links to safety-guard, MEMORY.md links to chronicle, all bidirectional |
| Pipeline completeness | Every step in the cross-skill pipeline executed without manual intervention |
| No information loss | Incident details preserved in chronicle even after knowledge distillation |

### Post-conditions

- Chronicle contains a complete incident record independent of safety-guard logs
- MEMORY.md contains a distilled lesson about scope enforcement
- Continuous-learning has a new defense pattern entry
- The cross-skill pipeline can be traced end-to-end through document links

---

## TC-CH-006: Index Integrity Validation

### Scenario

Verify that the CHRONICLE.md index is consistent with the actual chronicle directory contents. Every detail file must be indexed, every index reference must point to an existing file, and no orphaned or broken references exist.

### Pre-conditions

1. `chronicle/` directory contains multiple months of event files
2. `CHRONICLE.md` index has been maintained over time
3. At least one intentional discrepancy is introduced for testing:
   - One detail file exists but is missing from the index
   - One index entry references a file that does not exist

### Test Steps

1. List all `.md` files in `chronicle/` (excluding SUMMARY.md files)
2. Extract all file references from CHRONICLE.md
3. Compare: identify files present on disk but missing from the index
4. Compare: identify index references pointing to nonexistent files
5. For each discrepancy, classify as: missing-from-index or broken-reference
6. Report findings with actionable repair instructions

### Expected Outcomes

| Criterion | Expected Result |
|-----------|-----------------|
| File discovery | All chronicle detail files found across all month directories |
| Missing-from-index detection | Files on disk without index entries are flagged |
| Broken-reference detection | Index entries pointing to nonexistent files are flagged |
| Zero false positives | SUMMARY.md files are correctly excluded from the check |
| Repair guidance | Each discrepancy includes the file path and suggested action |
| Clean state | After repairs, re-running the check produces zero discrepancies |

### Post-conditions

- Integrity report lists all discrepancies with classification and repair instructions
- After manual repairs, the index and directory are fully synchronized
- No orphaned detail files and no broken index references remain

---

## TC-CH-007: Timeline Correlation Analysis — Multi-Source Event Merging

### Objective

Validate that the timeline correlation pipeline correctly merges events from memory logs, chronicle entries, and tool mastery records into a unified, chronologically sorted timeline, and accurately detects coverage gaps.

### Severity

MEDIUM

### Prerequisites

1. `memory/` directory contains at least 10 daily log files spanning 30+ days
2. `chronicle/` directory contains at least 5 event files across 2+ months
3. `TOOLS.md` contains at least 3 dated mastery entries
4. At least one intentional gap of 10+ days exists between chronicle entries
5. At least one memory file contains significant content with no matching chronicle entry

### Steps

1. Run the multi-source event merging script against all three sources (memory, chronicle, TOOLS.md)
2. Verify output contains entries from all three sources with correct source labels
3. Verify chronological sorting — all entries ordered by date ascending
4. Run gap detection script with threshold of 7 days
5. Verify the intentional 10+ day gap is detected and reported
6. Run cross-source correlation report
7. Verify the uncovered significant memory entry is flagged as [MISSING]
8. Verify already-covered entries are flagged as [COVERED]

### Expected Output

- Unified timeline file containing entries from memory, chronicle, and TOOLS.md
- Each entry labeled with source type: [MEMORY], [CHRONICLE-P0/P1/P2], or [TOOLS]
- Gap analysis report identifying all periods > 7 days without chronicle coverage
- Correlation report showing MISSING and COVERED classifications
- All dates in ISO 8601 format, sorted ascending

### Remediation

If correlation fails: verify date parsing handles all filename formats; ensure grep patterns match actual content structure in each source file.

### Pass Criteria

- [ ] All three sources (memory, chronicle, tools) represented in unified timeline
- [ ] Timeline is strictly chronologically sorted
- [ ] Known 10+ day gap is detected by gap analysis
- [ ] Significant memory entries without chronicle coverage are flagged as MISSING
- [ ] No false positives — entries with matching chronicle are not flagged as MISSING
- [ ] Output files are created at expected paths with non-zero content

---

## TC-CH-008: Knowledge Distillation Pipeline — Automated Insight Extraction

### Objective

Validate that the knowledge distillation pipeline correctly extracts insights from chronicle entries, scores them by confidence level, deduplicates overlapping entries, and produces MEMORY.md-ready formatted output.

### Severity

HIGH

### Prerequisites

1. `chronicle/` directory contains at least 8 event files with populated Impact sections
2. At least 2 chronicle entries contain high-confidence keywords ("always", "never", "critical", "proven")
3. At least 2 chronicle entries contain medium-confidence keywords ("usually", "pattern", "learned")
4. `MEMORY.md` contains at least 3 existing distilled entries (for deduplication testing)
5. At least one pair of MEMORY.md entries has > 60% word overlap (intentional duplicate)

### Steps

1. Run the key insight extraction script against the chronicle directory
2. Verify insights are extracted from Impact sections of chronicle entries
3. Verify confidence scoring: high-signal entries scored "High", medium-signal scored "Medium"
4. Verify output format matches MEMORY.md entry template (Source, Confidence, Lesson fields)
5. Run the deduplication pipeline against MEMORY.md
6. Verify the intentional duplicate pair is detected (> 60% word overlap)
7. Run the automated summarization script for the past 7 days of daily logs
8. Verify categorized output contains Techniques, Tool Usage, and Patterns sections

### Expected Output

- Insight extraction produces structured entries with source attribution and confidence scores
- High-confidence insights sorted before medium and low confidence
- Deduplication report identifies the known duplicate pair with overlap percentage
- Summarization output contains categorized knowledge under correct headings
- All outputs include line counts and processing statistics

### Remediation

If extraction fails: verify chronicle entries have `## Impact` sections with > 20 characters of content. If deduplication misses known duplicates: lower the overlap threshold from 0.6 to 0.5 and verify word tokenization handles punctuation.

### Pass Criteria

- [ ] Insights extracted from all chronicle entries with Impact sections
- [ ] Confidence scoring correctly classifies high/medium/low based on keyword presence
- [ ] Output format is valid for direct insertion into MEMORY.md
- [ ] Known duplicate pair detected with reported overlap > 60%
- [ ] Summarization produces non-empty Techniques, Tool Usage, and Patterns sections
- [ ] No insights extracted from SUMMARY.md files (correctly excluded)
- [ ] Source attribution paths are valid and point to existing files
