# Event Recording Best Practices

Operational guide for recording, classifying, distilling, and archiving agent lifecycle events. Covers the complete chronicle workflow from initial detection through long-term knowledge preservation.

---

## 1. When to Record Events

Not every observation deserves a chronicle entry. The priority classification system prevents both under-recording (missing critical events) and over-recording (noise that buries signal).

### 1.1 P0 — Record Immediately

P0 events change the agent's capability profile or represent findings with external impact. Recording must happen within the same session as the event itself.

**Trigger criteria (any one is sufficient):**

- High-severity vulnerability confirmed (Critical or High CVSS)
- Data breach or credential exposure discovered
- Learning plan completed (all milestones achieved)
- Full mastery of a tool or skill domain achieved

**Examples:**

```text
P0: Critical SQL injection discovered in production API during engagement
    → Record in the same session. Link evidence files. Distill to MEMORY.md.

P0: Completed Network Pentest skill domain — all 47 tools at proficiency
    → Record milestone. Update TOOLS.md and IDENTITY.md. Distill capability change.

P0: Found exposed AWS credentials in public S3 bucket during OSINT
    → Record immediately. Cross-reference with cloud-security skill.
```

**Common mistakes:**

- Deferring P0 recording to "write up later" — context degrades rapidly
- Recording the event but skipping the MEMORY.md distillation step
- Failing to link supporting evidence files in the Outputs section

### 1.2 P1 — Record Same Day

P1 events are operationally significant but do not require immediate documentation. They must be recorded before the end of the working session.

**Trigger criteria (any one is sufficient):**

- New engagement phase or project launched
- Individual tool learning completed
- Environment or toolchain configuration changed
- Penetration test report delivered to client

**Examples:**

```text
P1: Completed learning ffuf for directory enumeration
    → Record before session ends. Update TOOLS.md mastery status.

P1: Migrated Kali environment from 2025-1 to 2025-2
    → Record configuration change. Note any tool compatibility issues.

P1: Delivered web application assessment report for client Alpha
    → Record delivery. Reference engagement chronicle entries.
```

**Common mistakes:**

- Promoting P1 to P0 out of excitement (wastes immediate-recording overhead)
- Forgetting to record by session end and losing context overnight

### 1.3 P2 — Record This Week

P2 events are improvements and planning activities. They have a seven-day recording window.

**Trigger criteria (any one is sufficient):**

- Workflow or directory structure optimized
- New learning goals or plans set
- Non-critical system maintenance completed

**Examples:**

```text
P2: Reorganized evidence directory structure for faster retrieval
    → Record within 7 days. Brief summary is sufficient.

P2: Set new quarterly goal — master all container security tools
    → Record the goal, rationale, and success criteria.
```

**Decision tree for classification:**

```text
Does this event change capability or have external impact?
  YES → P0 (record now)
  NO  ↓
Does this event mark a completed deliverable or operational change?
  YES → P1 (record today)
  NO  ↓
Is this event worth finding again in 3 months?
  YES → P2 (record this week)
  NO  → Do not record in chronicle (daily log in memory/ is sufficient)
```

---

## 2. Event Recording Workflow

Every chronicle event follows a five-step pipeline: detect, classify, record, index, and cross-reference.

### 2.1 Step 1 — Detect the Event

Events surface from three sources:

```text
Source 1: Active session — something significant happens during work
Source 2: Heartbeat check — periodic review identifies unrecorded events
Source 3: Memory review — scanning daily logs reveals patterns worth elevating
```

During active work, watch for these signals:

- A tool reports a finding with severity High or Critical
- A learning milestone is reached (tracked in TOOLS.md)
- The operating environment changes (new tools installed, configs modified)
- An engagement deliverable is completed

### 2.2 Step 2 — Classify Priority

Apply the decision tree from Section 1. When uncertain, classify one level higher and downgrade later if needed. A P1 incorrectly classified as P0 wastes 10 minutes of immediate effort. A P0 incorrectly classified as P1 risks losing critical context.

```text
Classification checklist:
  [ ] Reviewed against P0 trigger criteria
  [ ] Reviewed against P1 trigger criteria
  [ ] Reviewed against P2 trigger criteria
  [ ] Confirmed: not already recorded in chronicle
  [ ] Confirmed: not a duplicate of an existing entry
```

### 2.3 Step 3 — Create the Detail Record

Use the event template from SKILL.md. The file goes in `chronicle/YYYY-MM/`:

```bash
# File naming convention
chronicle/YYYY-MM/YYYY-MM-DD-event-slug.md

# Examples
chronicle/2026-05/2026-05-22-critical-rce-in-jenkins.md
chronicle/2026-05/2026-05-18-nmap-mastery-complete.md
chronicle/2026-05/2026-05-10-quarterly-goals-set.md
```

**Required sections by priority:**

| Section | P0 | P1 | P2 |
|---------|----|----|-----|
| Summary (one-liner + outcomes) | Required | Required | Required |
| Background | Required | Required | Optional |
| Process (phases) | Required (detailed) | Required (abbreviated) | Optional |
| Outputs (file links) | Required (all evidence) | Required (key files) | Optional |
| Impact | Required | Optional | Optional |
| Related (cross-references) | Required | Required | Optional |

**Writing tips:**

- The one-liner should be understandable without reading the rest of the entry
- Process phases should be written as action-result pairs, not narratives
- Link to actual files in the Outputs section — do not paste content inline
- The Impact section answers "why does this matter for future work?"

### 2.4 Step 4 — Update the CHRONICLE.md Index

Every detail record must have a corresponding entry in the root-level `CHRONICLE.md` file. This is the navigational layer.

```markdown
## 2026-05

### 2026-05-22 (Thursday) — Critical RCE in Jenkins Target
**Type**: Security Discovery | **Priority**: P0

Remote code execution via CVE-2024-XXXX in Jenkins 2.440, confirmed with
independent manual exploitation and nuclei scan.

**Outcomes**: RCE confirmed, full system access demonstrated, remediation drafted
**Details**: -> chronicle/2026-05/2026-05-22-critical-rce-in-jenkins.md

---
```

**Index integrity rules:**

- Entries within a month section are ordered newest-first
- Every detail file in `chronicle/YYYY-MM/` must appear in the index
- Every index reference must point to an existing detail file
- Run the integrity check script from payloads.md periodically

### 2.5 Step 5 — Cross-Reference

After recording, connect the new entry to the broader knowledge base:

```text
Cross-reference checklist:
  [ ] Daily log in memory/ references the chronicle entry
  [ ] MEMORY.md updated if lessons were learned (P0 mandatory, P1/P2 if applicable)
  [ ] TOOLS.md updated if a tool mastery milestone was reached
  [ ] IDENTITY.md updated if a skill tag changed
  [ ] Related chronicle entries linked in the Related section
  [ ] Relevant SKILL.md files referenced
```

---

## 3. Knowledge Distillation Process

Distillation is the process of extracting reusable knowledge from raw events. Chronicle records "what happened." MEMORY.md records "what was learned."

### 3.1 The Three-Layer Progression

```text
Layer 1: memory/YYYY-MM-DD.md    → Raw daily observations (high volume, low structure)
Layer 2: chronicle/YYYY-MM/*.md  → Structured event records (medium volume, high structure)
Layer 3: MEMORY.md               → Distilled knowledge (low volume, maximum reuse value)
```

Not everything progresses through all three layers:

```text
Daily observation without lasting value:
  memory/ → (stays in memory/, eventually archived)

Significant event without a generalizable lesson:
  memory/ → chronicle/ → (stays in chronicle/, referenced but not distilled)

Event with a reusable lesson:
  memory/ → chronicle/ → MEMORY.md
```

### 3.2 When to Distill

**Immediately (same session):**

- P0 Security Discovery — the lesson is time-sensitive and may affect ongoing work
- Any event that contradicts existing MEMORY.md knowledge

**Within 48 hours:**

- P0 Milestone — the capability change should be reflected promptly
- P1 events with clear lessons

**During monthly review:**

- P1 events that did not yield immediate lessons but show patterns in aggregate
- P2 events that prove relevant in hindsight

### 3.3 How to Distill

Extract the generalizable lesson from the specific event:

```text
BAD distillation (too specific, not reusable):
  "Jenkins 2.440 on target Alpha at 10.0.0.5 was vulnerable to CVE-2024-XXXX"

GOOD distillation (generalizable, actionable):
  "Jenkins instances running behind reverse proxies often expose the /script
   endpoint through misconfigured proxy rules. Always check /script and
   /manage even when the main interface appears hardened."
```

**Distillation template for MEMORY.md:**

```markdown
### [Category] Title (YYYY-MM-DD)

**Source**: `chronicle/YYYY-MM/YYYY-MM-DD-slug.md`
**Confidence**: High / Medium / Low

**Lesson**: One or two sentences of reusable knowledge.

**Context**: When this knowledge applies (target type, engagement phase, conditions).

**Related**: Links to other MEMORY.md entries or skills.
```

### 3.4 Confidence Assignment for Distilled Knowledge

| Distillation Source | Default Confidence | Rationale |
|--------------------|--------------------|-----------|
| Single P0 security discovery | Medium | One observation, even if confirmed | 
| P0 milestone with measurable metrics | High | Objective achievement verified |
| P1 event confirmed across 2+ engagements | High | Repeated observation |
| P1 event from single engagement | Medium | Needs additional confirmation |
| P2 pattern identified in aggregate review | Low | Inferred from indirect evidence |

---

## 4. Monthly Review Procedure

Monthly reviews aggregate individual events into patterns and ensure the chronicle system stays healthy.

### 4.1 Timing

Run the monthly review within the first three days of the following month. For example, the May 2026 review should be completed by June 3, 2026.

### 4.2 Aggregation Phase

Collect all chronicle entries for the month and generate statistics:

```bash
# Use the monthly summary generation script from payloads.md
YEAR_MONTH="2026-05"
CHRONICLE_DIR="chronicle/$YEAR_MONTH"

# Count events by priority and type
TOTAL=$(find "$CHRONICLE_DIR" -name "*.md" ! -name "SUMMARY.md" -type f | wc -l)
P0=$(grep -rl "Priority.*P0" "$CHRONICLE_DIR" 2>/dev/null | wc -l)
P1=$(grep -rl "Priority.*P1" "$CHRONICLE_DIR" 2>/dev/null | wc -l)
P2=$(grep -rl "Priority.*P2" "$CHRONICLE_DIR" 2>/dev/null | wc -l)
```

### 4.3 Pattern Identification

Review all entries together and look for:

```text
Recurring themes:
  - Same vulnerability class appearing in multiple engagements
  - Same tool producing false positives across different targets
  - Time allocation patterns (too much time on recon, too little on reporting)

Trend lines:
  - Is tool mastery accelerating or plateauing?
  - Are security discoveries increasing in severity?
  - Are engagement lessons being applied (same mistake not repeated)?

Gaps:
  - Weeks with no entries (were events missed or was there genuinely nothing?)
  - Skill domains with no associated chronicle entries (stagnant learning areas)
  - P0 events without MEMORY.md distillation (missed knowledge extraction)
```

### 4.4 Summary Generation

Create a `SUMMARY.md` file in the month's chronicle directory using the template from payloads.md. The summary includes:

1. Statistics table (total events, breakdown by priority and type)
2. Top three highlights (most significant events)
3. Events grouped by category
4. Knowledge distilled this month (table linking to MEMORY.md sections)
5. Carry-forward items (undistilled events, follow-up actions)

### 4.5 CHRONICLE.md Index Audit

Verify index integrity after completing the monthly review:

```text
Integrity checklist:
  [ ] Every detail file in chronicle/YYYY-MM/ is referenced in CHRONICLE.md
  [ ] Every reference in CHRONICLE.md points to an existing file
  [ ] Monthly section header includes accurate event count
  [ ] Entries are ordered newest-first within each month
  [ ] No duplicate entries exist
```

---

## 5. Archive Management

Archives preserve historical knowledge while keeping the active workspace lean.

### 5.1 When to Archive

Memory files (`memory/YYYY-MM-DD.md`) become archive candidates after 30 days. Chronicle entries themselves are never archived — they are the archival layer.

```text
Archive trigger conditions:
  - Memory file is older than 30 days
  - Important content has been extracted to chronicle
  - Lessons have been distilled to MEMORY.md
  - File is not referenced by any active engagement
```

### 5.2 Archive Procedure

```text
Step 1: Run the stale entry detection script from payloads.md
Step 2: For each stale file, check extraction status:
  - Has significant content been captured in chronicle/?
  - Have lessons been distilled to MEMORY.md?
Step 3: If yes to both, mark the memory file as archived:
  Add this line to the top of the file:
  > [ARCHIVED] Content distilled to chronicle and MEMORY.md on YYYY-MM-DD
Step 4: Do NOT delete the original file
Step 5: Log the archival action in the current daily memory file
```

**Why not delete?** Archived memory files serve as a forensic trail. If a chronicle entry or MEMORY.md distillation is later questioned, the original daily log provides ground truth.

### 5.3 Retrieval Strategies

When you need to find historical information:

```text
Strategy 1 — Known date range:
  Use the timeline query script from payloads.md to list events in a range.

Strategy 2 — Known skill or tool:
  Use the skill-reference query to find all entries mentioning a specific skill.

Strategy 3 — Known event type:
  Use the event-type query to find all security discoveries, milestones, etc.

Strategy 4 — Keyword search:
  grep -rl "keyword" chronicle/ memory/ MEMORY.md

Strategy 5 — CHRONICLE.md index scan:
  Read the index top-to-bottom (newest first) for a chronological overview.
```

### 5.4 Long-Term Preservation

For chronicle entries older than 12 months:

```text
  [ ] Verify the entry is still accurate (technologies change)
  [ ] Check if the distilled MEMORY.md knowledge is still relevant
  [ ] Update confidence levels based on subsequent observations
  [ ] Mark outdated entries with a staleness note
  [ ] Do NOT delete old entries — they provide historical context
```

---

## 6. Integration with Other Skills

Chronicle is a hub that connects to every other skill through event recording and knowledge flow.

### 6.1 Chronicle and Continuous Learning

```text
Direction: continuous-learning → chronicle (event source)
           chronicle → continuous-learning (knowledge patterns)

When continuous-learning identifies a new pattern:
  1. The pattern observation goes to the daily memory log
  2. If significant, a chronicle entry is created (usually P1)
  3. The distilled knowledge feeds back into continuous-learning's knowledge base

When chronicle monthly review identifies recurring patterns:
  1. These become candidates for continuous-learning knowledge entries
  2. Confidence scores from chronicle observation counts inform scoring
```

### 6.2 Chronicle and Knowledge-Ops

```text
Direction: chronicle → knowledge-ops (feeds retrieval system)
           knowledge-ops → chronicle (organizes and queries)

Chronicle provides the structured records that knowledge-ops indexes.
Knowledge-ops provides the search and retrieval infrastructure that
makes chronicle entries findable.
```

### 6.3 Chronicle and Safety Guard

```text
Direction: safety-guard → chronicle (incident events)

All safety incidents (Level 1, 2, or 3) must be recorded in chronicle:
  - Level 1: P1 recording (same day)
  - Level 2: P0 recording (immediate)
  - Level 3: P0 recording (immediate, with full evidence chain)
```

### 6.4 Chronicle and HEARTBEAT.md

```text
Direction: HEARTBEAT.md → chronicle (triggers periodic maintenance)

Heartbeat tasks that involve chronicle:
  - Every heartbeat: Check if P0 events need recording
  - Weekly: Review CHRONICLE.md completeness
  - Monthly: Trigger monthly review procedure (Section 4)
  - Quarterly: Review classification system and template effectiveness
```

---

## 7. Best Practices and Anti-Patterns

### Best Practices

```text
1. Record P0 events in the same session — never defer
2. Write one-liners that stand alone without the full entry
3. Use action-result pairs in Process sections, not prose
4. Link to files in Outputs — do not paste content inline
5. Cross-reference aggressively — isolated entries lose value fast
6. Run integrity checks after every monthly review
7. Distill to MEMORY.md within 48 hours for P0 events
8. Keep the CHRONICLE.md index as the single source of navigation
9. Date everything — chronicle entries without dates are worthless
10. Include negative results — "attempted X, it did not work" is valuable
```

### Anti-Patterns

```text
1. OVER-RECORDING
   Problem: Recording every minor observation as a chronicle event
   Impact: Signal-to-noise ratio drops; important events get buried
   Fix: Use the P0/P1/P2 classification strictly. Minor observations
        belong in daily memory logs, not chronicle.

2. UNDER-DISTILLING
   Problem: Recording events in chronicle but never distilling to MEMORY.md
   Impact: Knowledge stays locked in specific event context, not reusable
   Fix: Every P0 event must distill. Monthly review catches missed P1/P2.

3. ORPHANED ENTRIES
   Problem: Detail files in chronicle/ not referenced in CHRONICLE.md
   Impact: Entries become unfindable through normal navigation
   Fix: Always update the index in the same commit as the detail file.

4. STALE CROSS-REFERENCES
   Problem: Related links point to moved or deleted files
   Impact: Navigation breaks; trust in the system degrades
   Fix: Run integrity checks monthly. Update links when reorganizing.

5. NARRATIVE BLOAT
   Problem: Process sections written as long prose instead of action-result pairs
   Impact: Entries take too long to read; key information buried in text
   Fix: Use the Phase/Action/Result structure from the template strictly.

6. DEFERRED P0 RECORDING
   Problem: "I'll write it up later" for critical events
   Impact: Context degrades within hours. Details become fuzzy.
   Fix: P0 means now. Not after lunch. Not tomorrow. Now.

7. MISSING EVIDENCE LINKS
   Problem: Recording events without linking supporting evidence files
   Impact: Claims cannot be verified later; report quality suffers
   Fix: The Outputs section is not optional for P0 and P1 entries.

8. CLASSIFICATION INFLATION
   Problem: Marking everything as P0 to feel important
   Impact: P0 loses meaning; actual critical events do not stand out
   Fix: Apply the decision tree honestly. Most events are P1 or P2.
```
