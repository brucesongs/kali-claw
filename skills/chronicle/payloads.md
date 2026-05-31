# Chronicle System — Payloads & Commands

> Companion to `SKILL.md`. Contains event recording templates, knowledge distillation commands, and maintenance payloads organized by chronicle operation. For structured test scenarios, see `test-cases.md`.

---

## Index

1. [Event Recording Templates](#1-event-recording-templates)
2. [Chronicle Entry Formats](#2-chronicle-entry-formats)
3. [Knowledge Distillation Commands](#3-knowledge-distillation-commands)
4. [Monthly Summary Generation Templates](#4-monthly-summary-generation-templates)
5. [Archive & Maintenance Commands](#5-archive--maintenance-commands)
6. [Cross-Reference & Query Patterns](#6-cross-reference--query-patterns)

---

## 1. Event Recording Templates

### P0 Event — Record Immediately

```markdown
## Scope Lock: P0 Event Recording
- **Operation ID**: OP-CH-{timestamp}
- **Priority**: P0 — Record Immediately
- **Event types**: Security Discovery, Milestone Achieved
- **Max delay**: 0 minutes (record during current session)
- **Required fields**: Summary, Background, Process, Outputs, Impact
- **Cross-updates**: CHRONICLE.md index, MEMORY.md distillation (if lessons learned)
- **Evidence**: All supporting files linked in Outputs section
```

#### P0 Security Discovery

```markdown
# {YYYY-MM-DD} - {Vulnerability/Discovery Name}

> **Type**: Security Discovery
> **Priority**: P0
> **Recorded**: {YYYY-MM-DD HH:MM}

---

## Summary

**One-liner**: [Critical finding: CVE/technique/impact in one sentence]

**Key Outcomes**:
- [Vulnerability confirmed with evidence]
- [Impact assessment completed]
- [Remediation recommendation drafted]

---

## Background

[What engagement or task led to this discovery. Target context, scope, methodology in use.]

---

## Process

### Phase 1: Detection
- **Action**: [How the vulnerability was initially detected]
- **Result**: [Initial indicators — error messages, anomalous responses, tool output]

### Phase 2: Confirmation
- **Action**: [Steps taken to verify the finding]
- **Result**: [Confirmed exploitable / confirmed false positive / needs further analysis]

### Phase 3: Impact Assessment
- **Action**: [Assessed blast radius, data at risk, privilege level]
- **Result**: [Severity rating: Critical/High/Medium/Low]

---

## Outputs

- `evidence/{engagement}/finding-{id}.txt` — Raw tool output
- `evidence/{engagement}/screenshot-{id}.png` — Visual proof
- `evidence/{engagement}/exploit-chain-{id}.md` — Reproduction steps

---

## Impact

[Why this matters for future engagements: new technique learned, tool gap identified, defense pattern discovered]

---

## Related

- Daily notes: `memory/{YYYY-MM-DD}.md`
- Knowledge distillation: `MEMORY.md#[section]`
- Related skill: `skills/[relevant-skill]/SKILL.md`
```

#### P0 Milestone Achieved

```markdown
# {YYYY-MM-DD} - {Milestone Name}

> **Type**: Milestone Achieved
> **Priority**: P0
> **Recorded**: {YYYY-MM-DD HH:MM}

---

## Summary

**One-liner**: [Milestone achieved in one sentence]

**Key Outcomes**:
- [What was completed]
- [Metrics: tools mastered, coverage achieved, skills unlocked]

---

## Background

[Learning plan or goal that led to this milestone]

---

## Process

### Phase 1: Preparation
- **Action**: [Study plan, practice targets, resources used]
- **Result**: [Readiness indicators]

### Phase 2: Execution
- **Action**: [How the milestone was achieved]
- **Result**: [Concrete deliverables or demonstrations]

### Phase 3: Verification
- **Action**: [How mastery was confirmed]
- **Result**: [Test results, successful engagements, peer review]

---

## Outputs

- `TOOLS.md#[tool-section]` — Updated tool mastery status
- `IDENTITY.md#[skill-tag]` — Updated skill tag if applicable

---

## Impact

[How this milestone changes capability profile and future engagement readiness]

---

## Related

- Daily notes: `memory/{YYYY-MM-DD}.md`
- Knowledge distillation: `MEMORY.md#[section]`
- Related skill: `skills/[skill-name]/SKILL.md`
```

### P1 Event — Record Same Day

```markdown
## Scope Lock: P1 Event Recording
- **Operation ID**: OP-CH-{timestamp}
- **Priority**: P1 — Record Same Day
- **Event types**: Project Launch, Learning Completed, Environment Config, Report Delivered
- **Max delay**: End of current working session
- **Required fields**: Summary, Background, Process (abbreviated), Outputs
- **Cross-updates**: CHRONICLE.md index
- **Evidence**: Key files linked; detailed evidence optional
```

### P2 Event — Record This Week

```markdown
## Scope Lock: P2 Event Recording
- **Operation ID**: OP-CH-{timestamp}
- **Priority**: P2 — Record This Week
- **Event types**: System Optimization, Goal Setting
- **Max delay**: 7 calendar days from event occurrence
- **Required fields**: Summary, Key Outcomes
- **Cross-updates**: CHRONICLE.md index
- **Evidence**: Summary only; detailed evidence not required
```

---

## 2. Chronicle Entry Formats

### CHRONICLE.md Index Entry

```markdown
### {YYYY-MM-DD} ({Weekday}) — {Event Name}
**Type**: {icon} {type name} | **Priority**: P{0/1/2}

{One-line summary of what happened and why it matters.}

**Outcomes**: {comma-separated key outcomes}
**Details**: -> chronicle/{YYYY-MM}/{YYYY-MM-DD}-{event-name}.md

---
```

### Monthly Section Header

```markdown
## {YYYY-MM}

> {Month name} {Year} — {N} events recorded ({P0_count} critical, {P1_count} standard, {P2_count} minor)
```

### Quick-Reference Table Format

```markdown
| Date | Type | Priority | Event | Details |
|------|------|----------|-------|---------|
| {YYYY-MM-DD} | {Type} | P{N} | {Event Name} | [Detail](chronicle/{YYYY-MM}/{YYYY-MM-DD}-{slug}.md) |
```

### Detail File Naming Convention

```bash
# Pattern: chronicle/YYYY-MM/YYYY-MM-DD-event-slug.md
# Examples:
chronicle/2026-05/2026-05-22-critical-sqli-in-target-alpha.md
chronicle/2026-05/2026-05-15-nmap-mastery-milestone.md
chronicle/2026-05/2026-05-10-kali-2025-2-environment-setup.md
```

---

## 3. Knowledge Distillation Commands

### Extract Highlights from Daily Logs

```bash
# Scan memory/ directory for high-value entries from a specific date range
# Looks for keywords indicating learnable content

MEMORY_DIR="memory"
START_DATE="2026-05-01"
END_DATE="2026-05-31"
OUTPUT="chronicle/distillation-$(date +%Y%m%d).txt"

echo "[DISTILL-START] Scanning $MEMORY_DIR for $START_DATE to $END_DATE"

find "$MEMORY_DIR" -name "*.md" -newer "$MEMORY_DIR/$START_DATE.md" ! -newer "$MEMORY_DIR/$END_DATE.md" \
  -exec grep -l -iE "learned|discovered|important|critical|milestone|breakthrough|pattern|lesson" {} \; \
  | sort | while IFS= read -r file; do
    echo "=== $file ===" >> "$OUTPUT"
    grep -iE "learned|discovered|important|critical|milestone|breakthrough|pattern|lesson" "$file" >> "$OUTPUT"
    echo "" >> "$OUTPUT"
  done

echo "[DISTILL-END] Results saved to $OUTPUT ($(wc -l < "$OUTPUT") lines)"
```

### Distill to MEMORY.md

```markdown
## Distillation Entry Template

Add to the appropriate section of MEMORY.md:

### [{Category}] {Title} ({YYYY-MM-DD})

**Source**: `chronicle/{YYYY-MM}/{YYYY-MM-DD}-{slug}.md`
**Confidence**: {High / Medium / Low}

**Lesson**: {One or two sentences capturing the reusable knowledge}

**Context**: {When this knowledge is applicable}

**Related**: {Links to related MEMORY.md entries or skills}
```

### Batch Distillation from Chronicle

```bash
# Extract all undistilled chronicle entries (those not yet referenced in MEMORY.md)

CHRONICLE_DIR="chronicle"
MEMORY_FILE="MEMORY.md"
OUTPUT="chronicle/undistilled-$(date +%Y%m%d).txt"

echo "[DISTILL-CHECK] Finding undistilled chronicle entries"

find "$CHRONICLE_DIR" -name "*.md" -type f | sort | while IFS= read -r entry; do
  BASENAME=$(basename "$entry")
  if ! grep -q "$BASENAME" "$MEMORY_FILE" 2>/dev/null; then
    echo "[UNDISTILLED] $entry" >> "$OUTPUT"
    # Extract the one-liner summary
    grep -A1 "One-liner" "$entry" 2>/dev/null | tail -1 >> "$OUTPUT"
    echo "" >> "$OUTPUT"
  fi
done

TOTAL=$(grep -c "UNDISTILLED" "$OUTPUT" 2>/dev/null || echo "0")
echo "[DISTILL-CHECK] Found $TOTAL undistilled entries. Review: $OUTPUT"
```

---

## 4. Monthly Summary Generation Templates

### Monthly Summary Template

```markdown
# Chronicle Summary: {YYYY-MM}

> Auto-generated summary of all chronicle events for {Month Name} {Year}.

## Statistics

| Metric | Value |
|--------|-------|
| **Total Events** | {N} |
| **P0 (Critical)** | {N} |
| **P1 (Standard)** | {N} |
| **P2 (Minor)** | {N} |
| **Security Discoveries** | {N} |
| **Milestones Achieved** | {N} |
| **Knowledge Entries Distilled** | {N} |

## Highlights

1. {Most significant event with one-line description}
2. {Second most significant event}
3. {Third most significant event}

## Events by Category

### Security Discoveries
- [{YYYY-MM-DD}] {Event name} — {one-liner}

### Milestones
- [{YYYY-MM-DD}] {Event name} — {one-liner}

### Environment & Configuration
- [{YYYY-MM-DD}] {Event name} — {one-liner}

### Learning & Development
- [{YYYY-MM-DD}] {Event name} — {one-liner}

## Knowledge Distilled This Month

| Entry | Source | Confidence | Section in MEMORY.md |
|-------|--------|------------|---------------------|
| {Title} | {chronicle file} | {High/Med/Low} | {MEMORY.md#section} |

## Carry-Forward Items

- [ ] {Undistilled events that need review}
- [ ] {Follow-up actions from this month's events}
```

### Monthly Summary Generation Script

```bash
# Generate monthly summary from chronicle directory

YEAR_MONTH="${1:-$(date +%Y-%m)}"
CHRONICLE_DIR="chronicle/$YEAR_MONTH"
OUTPUT="chronicle/$YEAR_MONTH/SUMMARY.md"

if [ ! -d "$CHRONICLE_DIR" ]; then
  echo "[ERROR] No chronicle directory for $YEAR_MONTH"
  exit 1
fi

TOTAL=$(find "$CHRONICLE_DIR" -name "*.md" ! -name "SUMMARY.md" -type f | wc -l | tr -d ' ')
P0=$(grep -rl "Priority.*P0" "$CHRONICLE_DIR" 2>/dev/null | wc -l | tr -d ' ')
P1=$(grep -rl "Priority.*P1" "$CHRONICLE_DIR" 2>/dev/null | wc -l | tr -d ' ')
P2=$(grep -rl "Priority.*P2" "$CHRONICLE_DIR" 2>/dev/null | wc -l | tr -d ' ')

echo "[SUMMARY] $YEAR_MONTH: $TOTAL total ($P0 P0, $P1 P1, $P2 P2)"
echo "[SUMMARY] Output: $OUTPUT"
```

---

## 5. Archive & Maintenance Commands

### Find Stale Memory Entries

```bash
# Identify memory/ files older than 30 days that have not been archived

MEMORY_DIR="memory"
CHRONICLE_DIR="chronicle"
STALE_DAYS=30
OUTPUT="chronicle/stale-entries-$(date +%Y%m%d).txt"

echo "[ARCHIVE-CHECK] Finding memory files older than $STALE_DAYS days"

find "$MEMORY_DIR" -name "*.md" -type f -mtime +"$STALE_DAYS" | sort | while IFS= read -r file; do
  BASENAME=$(basename "$file" .md)
  # Check if already archived in chronicle
  if ! find "$CHRONICLE_DIR" -name "*${BASENAME}*" -type f 2>/dev/null | grep -q .; then
    echo "[STALE] $file (not archived)" >> "$OUTPUT"
  else
    echo "[ARCHIVED] $file (already in chronicle)" >> "$OUTPUT"
  fi
done

STALE_COUNT=$(grep -c "STALE" "$OUTPUT" 2>/dev/null || echo "0")
echo "[ARCHIVE-CHECK] $STALE_COUNT stale entries need archiving. See: $OUTPUT"
```

### Archive Memory to Chronicle

```markdown
## Memory Archival Checklist

For each stale memory file (>30 days):

1. **Extract important content**
   - [ ] Identify key findings, decisions, and lessons
   - [ ] Check if events meet P0/P1/P2 recording threshold

2. **Create chronicle entries**
   - [ ] For each significant event, create detail file in chronicle/YYYY-MM/
   - [ ] Update CHRONICLE.md index with new entries

3. **Distill to MEMORY.md**
   - [ ] Extract reusable lessons and add to appropriate MEMORY.md section
   - [ ] Include source attribution back to chronicle entry

4. **Mark as archived**
   - [ ] Add `> [ARCHIVED] Content distilled to chronicle and MEMORY.md on {date}` to top of file
   - [ ] Do NOT delete the original memory file
```

### Consolidate Duplicate Entries

```bash
# Find potential duplicate chronicle entries (similar titles or dates)

CHRONICLE_DIR="chronicle"

echo "[CONSOLIDATE] Checking for potential duplicates"

find "$CHRONICLE_DIR" -name "*.md" ! -name "SUMMARY.md" -type f | sort | while IFS= read -r file; do
  TITLE=$(grep -m1 "^# " "$file" 2>/dev/null | sed 's/^# //')
  echo "$TITLE|$file"
done | sort -t'|' -k1,1 | uniq -d -f0

echo "[CONSOLIDATE] Review any duplicates above and merge if appropriate"
```

### Prune Empty or Placeholder Entries

```bash
# Find chronicle entries that are incomplete (missing required sections)

CHRONICLE_DIR="chronicle"
REQUIRED_SECTIONS=("Summary" "Background" "Process")
OUTPUT="chronicle/incomplete-entries-$(date +%Y%m%d).txt"

echo "[PRUNE-CHECK] Scanning for incomplete chronicle entries"

find "$CHRONICLE_DIR" -name "*.md" ! -name "SUMMARY.md" -type f | sort | while IFS= read -r file; do
  MISSING=""
  for section in "${REQUIRED_SECTIONS[@]}"; do
    if ! grep -q "## $section" "$file" 2>/dev/null; then
      MISSING="$MISSING $section"
    fi
  done
  if [ -n "$MISSING" ]; then
    echo "[INCOMPLETE] $file — missing:$MISSING" >> "$OUTPUT"
  fi
done

INCOMPLETE=$(grep -c "INCOMPLETE" "$OUTPUT" 2>/dev/null || echo "0")
echo "[PRUNE-CHECK] $INCOMPLETE incomplete entries found. See: $OUTPUT"
```

---

## 6. Cross-Reference & Query Patterns

### Find All Entries Referencing a Skill

```bash
# Query chronicle for all entries related to a specific skill

SKILL_NAME="${1:-web-sqli}"
CHRONICLE_DIR="chronicle"

echo "[QUERY] Chronicle entries referencing skill: $SKILL_NAME"

grep -rl "$SKILL_NAME" "$CHRONICLE_DIR" 2>/dev/null | sort | while IFS= read -r file; do
  TITLE=$(grep -m1 "^# " "$file" 2>/dev/null | sed 's/^# //')
  PRIORITY=$(grep -m1 "Priority" "$file" 2>/dev/null | grep -oE "P[0-2]")
  echo "  [$PRIORITY] $TITLE — $file"
done
```

### Find All Entries by Event Type

```bash
# Query chronicle for all entries of a specific type

EVENT_TYPE="${1:-Security Discovery}"
CHRONICLE_DIR="chronicle"

echo "[QUERY] Chronicle entries of type: $EVENT_TYPE"

grep -rl "Type.*$EVENT_TYPE" "$CHRONICLE_DIR" 2>/dev/null | sort | while IFS= read -r file; do
  DATE=$(grep -m1 "Recorded" "$file" 2>/dev/null | grep -oE "[0-9]{4}-[0-9]{2}-[0-9]{2}")
  TITLE=$(grep -m1 "^# " "$file" 2>/dev/null | sed 's/^# //')
  echo "  [$DATE] $TITLE — $file"
done
```

### Validate CHRONICLE.md Index Integrity

```bash
# Verify that every detail file in chronicle/ is referenced in CHRONICLE.md
# and every reference in CHRONICLE.md points to an existing file

CHRONICLE_INDEX="CHRONICLE.md"
CHRONICLE_DIR="chronicle"

echo "[INTEGRITY] Checking CHRONICLE.md index integrity"

# Files not in index
echo "--- Files missing from CHRONICLE.md index ---"
find "$CHRONICLE_DIR" -name "*.md" ! -name "SUMMARY.md" -type f | sort | while IFS= read -r file; do
  RELPATH=$(echo "$file" | sed 's|^\./||')
  if ! grep -q "$RELPATH" "$CHRONICLE_INDEX" 2>/dev/null; then
    echo "  [MISSING-FROM-INDEX] $RELPATH"
  fi
done

# Index references to missing files
echo "--- Broken references in CHRONICLE.md ---"
grep -oE "chronicle/[^ )]*\.md" "$CHRONICLE_INDEX" 2>/dev/null | while IFS= read -r ref; do
  if [ ! -f "$ref" ]; then
    echo "  [BROKEN-REF] $ref"
  fi
done

echo "[INTEGRITY] Check complete"
```

### Timeline Query

```bash
# Query chronicle events within a date range

START="${1:-2026-05-01}"
END="${2:-2026-05-31}"
CHRONICLE_DIR="chronicle"

echo "[TIMELINE] Events from $START to $END"

find "$CHRONICLE_DIR" -name "*.md" ! -name "SUMMARY.md" -type f | sort | while IFS= read -r file; do
  FILE_DATE=$(basename "$file" | grep -oE "^[0-9]{4}-[0-9]{2}-[0-9]{2}")
  if [ -n "$FILE_DATE" ] && [[ "$FILE_DATE" > "$START" || "$FILE_DATE" == "$START" ]] && [[ "$FILE_DATE" < "$END" || "$FILE_DATE" == "$END" ]]; then
    PRIORITY=$(grep -m1 "Priority" "$file" 2>/dev/null | grep -oE "P[0-2]")
    TYPE=$(grep -m1 "Type" "$file" 2>/dev/null | sed 's/.*Type.*: //' | head -c 30)
    TITLE=$(grep -m1 "^# " "$file" 2>/dev/null | sed 's/^# //')
    echo "  [$FILE_DATE] [$PRIORITY] $TYPE — $TITLE"
  fi
done
```

---

## 7. Timeline Correlation Analysis

### Multi-Source Event Merging

```bash
# Merge events from multiple sources (memory, chronicle, tools) into unified timeline
# Correlates timestamps across daily logs, chronicle entries, and tool mastery updates

MEMORY_DIR="memory"
CHRONICLE_DIR="chronicle"
TOOLS_FILE="TOOLS.md"
OUTPUT="chronicle/correlation-$(date +%Y%m%d).txt"

echo "[CORRELATE] Building unified timeline from all sources"

# Extract dated events from memory
echo "=== Memory Events ===" > "$OUTPUT"
find "$MEMORY_DIR" -name "*.md" -type f | sort | while IFS= read -r file; do
  DATE=$(basename "$file" .md)
  HIGHLIGHTS=$(grep -c -iE "discovered|milestone|critical|breakthrough" "$file" 2>/dev/null)
  if [ "$HIGHLIGHTS" -gt 0 ]; then
    echo "  [$DATE] [MEMORY] $HIGHLIGHTS notable entries — $file" >> "$OUTPUT"
  fi
done

# Extract dated events from chronicle
echo "=== Chronicle Events ===" >> "$OUTPUT"
find "$CHRONICLE_DIR" -name "*.md" ! -name "SUMMARY.md" -type f | sort | while IFS= read -r file; do
  DATE=$(basename "$file" | grep -oE "^[0-9]{4}-[0-9]{2}-[0-9]{2}")
  PRIORITY=$(grep -m1 "Priority" "$file" 2>/dev/null | grep -oE "P[0-2]")
  TITLE=$(grep -m1 "^# " "$file" 2>/dev/null | sed 's/^# //')
  [ -n "$DATE" ] && echo "  [$DATE] [CHRONICLE-$PRIORITY] $TITLE" >> "$OUTPUT"
done

# Extract tool mastery date markers from TOOLS.md
echo "=== Tool Mastery Events ===" >> "$OUTPUT"
grep -oE "[0-9]{4}-[0-9]{2}-[0-9]{2}.*mastered\|learned\|completed" "$TOOLS_FILE" 2>/dev/null \
  | while IFS= read -r line; do
    echo "  [TOOLS] $line" >> "$OUTPUT"
  done

# Sort unified timeline by date
sort -t'[' -k2 "$OUTPUT" > "${OUTPUT}.sorted"
mv "${OUTPUT}.sorted" "$OUTPUT"
echo "[CORRELATE] Unified timeline saved to $OUTPUT ($(wc -l < "$OUTPUT") entries)"
```

### Gap Detection in Chronicle Coverage

```bash
# Detect gaps in chronicle coverage — periods with no recorded events
# Useful for identifying undocumented activity periods

CHRONICLE_DIR="chronicle"
GAP_THRESHOLD_DAYS=7
OUTPUT="chronicle/gap-analysis-$(date +%Y%m%d).txt"

echo "[GAP-DETECT] Scanning for coverage gaps > $GAP_THRESHOLD_DAYS days"

# Extract all event dates and find gaps
find "$CHRONICLE_DIR" -name "*.md" ! -name "SUMMARY.md" -type f \
  | xargs -I{} basename {} | grep -oE "^[0-9]{4}-[0-9]{2}-[0-9]{2}" \
  | sort -u > /tmp/chronicle_dates.txt

PREV_DATE=""
while IFS= read -r date; do
  if [ -n "$PREV_DATE" ]; then
    PREV_EPOCH=$(date -j -f "%Y-%m-%d" "$PREV_DATE" "+%s" 2>/dev/null || date -d "$PREV_DATE" "+%s" 2>/dev/null)
    CURR_EPOCH=$(date -j -f "%Y-%m-%d" "$date" "+%s" 2>/dev/null || date -d "$date" "+%s" 2>/dev/null)
    GAP_DAYS=$(( (CURR_EPOCH - PREV_EPOCH) / 86400 ))
    if [ "$GAP_DAYS" -gt "$GAP_THRESHOLD_DAYS" ]; then
      echo "  [GAP] $GAP_DAYS days between $PREV_DATE and $date" >> "$OUTPUT"
    fi
  fi
  PREV_DATE="$date"
done < /tmp/chronicle_dates.txt

GAP_COUNT=$(grep -c "GAP" "$OUTPUT" 2>/dev/null || echo "0")
echo "[GAP-DETECT] Found $GAP_COUNT coverage gaps. See: $OUTPUT"
rm -f /tmp/chronicle_dates.txt
```

### Cross-Source Event Correlation Report

```bash
# Generate correlation report showing which memory entries have matching chronicle records
# Identifies undocumented significant events

MEMORY_DIR="memory"
CHRONICLE_DIR="chronicle"
OUTPUT="chronicle/correlation-report-$(date +%Y%m%d).txt"

echo "[CORRELATION] Cross-referencing memory against chronicle"
echo "=== Correlation Report ===" > "$OUTPUT"

find "$MEMORY_DIR" -name "*.md" -type f | sort | while IFS= read -r memfile; do
  DATE=$(basename "$memfile" .md)
  # Check if this date has a chronicle entry
  CHRONICLE_MATCH=$(find "$CHRONICLE_DIR" -name "${DATE}*" -type f 2>/dev/null | wc -l | tr -d ' ')
  # Check if memory file has significant content
  HAS_SIGNIFICANT=$(grep -c -iE "critical|milestone|discovered|breakthrough|P0|P1" "$memfile" 2>/dev/null)

  if [ "$HAS_SIGNIFICANT" -gt 0 ] && [ "$CHRONICLE_MATCH" -eq 0 ]; then
    echo "  [MISSING] $DATE — significant memory content with no chronicle entry" >> "$OUTPUT"
    grep -m3 -iE "critical|milestone|discovered|breakthrough" "$memfile" 2>/dev/null \
      | sed 's/^/    /' >> "$OUTPUT"
  elif [ "$HAS_SIGNIFICANT" -gt 0 ] && [ "$CHRONICLE_MATCH" -gt 0 ]; then
    echo "  [COVERED] $DATE — memory content has matching chronicle ($CHRONICLE_MATCH entries)" >> "$OUTPUT"
  fi
done

MISSING=$(grep -c "MISSING" "$OUTPUT" 2>/dev/null || echo "0")
COVERED=$(grep -c "COVERED" "$OUTPUT" 2>/dev/null || echo "0")
echo "[CORRELATION] $COVERED covered, $MISSING missing chronicle entries. See: $OUTPUT"
```

---

## 8. Automated Milestone Detection

### Pattern Recognition for Milestone Triggers

```bash
# Scan daily logs for patterns that indicate milestone achievement
# Triggers: tool count thresholds, skill completions, engagement completions

MEMORY_DIR="memory"
TOOLS_FILE="TOOLS.md"
OUTPUT="chronicle/milestone-candidates-$(date +%Y%m%d).txt"

echo "[MILESTONE-DETECT] Scanning for unrecorded milestone patterns"

# Pattern 1: Tool mastery clusters (3+ tools mastered in same domain within 7 days)
echo "=== Tool Mastery Clusters ===" > "$OUTPUT"
grep -rn -iE "mastered|proficient|completed.*tool" "$MEMORY_DIR" 2>/dev/null \
  | sort -t: -k1 | while IFS= read -r line; do
    FILE=$(echo "$line" | cut -d: -f1)
    DATE=$(basename "$FILE" .md)
    CONTENT=$(echo "$line" | cut -d: -f3-)
    echo "  [$DATE] $CONTENT" >> "$OUTPUT"
  done

# Pattern 2: Engagement completion markers
echo "=== Engagement Completions ===" >> "$OUTPUT"
grep -rn -iE "engagement.*complete|report.*delivered|assessment.*finished" "$MEMORY_DIR" 2>/dev/null \
  | while IFS= read -r line; do
    FILE=$(echo "$line" | cut -d: -f1)
    DATE=$(basename "$FILE" .md)
    echo "  [$DATE] $(echo "$line" | cut -d: -f3-)" >> "$OUTPUT"
  done

# Pattern 3: Skill domain coverage thresholds
echo "=== Skill Coverage Thresholds ===" >> "$OUTPUT"
TOTAL_TOOLS=$(grep -c "^\|" "$TOOLS_FILE" 2>/dev/null || echo "0")
MASTERED=$(grep -c -iE "mastered\|proficient" "$TOOLS_FILE" 2>/dev/null || echo "0")
PERCENT=$(( MASTERED * 100 / (TOTAL_TOOLS + 1) ))
echo "  [CURRENT] $MASTERED/$TOTAL_TOOLS tools mastered ($PERCENT%)" >> "$OUTPUT"
if [ "$PERCENT" -ge 25 ] || [ "$PERCENT" -ge 50 ] || [ "$PERCENT" -ge 75 ]; then
  echo "  [THRESHOLD] Coverage milestone reached: $PERCENT%" >> "$OUTPUT"
fi

CANDIDATES=$(grep -c "^\s*\[" "$OUTPUT" 2>/dev/null || echo "0")
echo "[MILESTONE-DETECT] Found $CANDIDATES potential milestones. See: $OUTPUT"
```

### Threshold-Based Trigger Configuration

```yaml
# Milestone detection thresholds — triggers automatic P1 chronicle recording
# when any threshold is crossed

milestone_triggers:
  tool_mastery:
    description: "Tool mastery count crosses threshold"
    thresholds: [10, 25, 50, 100, 200, 300, 400, 518]
    check_frequency: "daily"
    priority: "P1"
    template: "milestone-achieved"

  domain_completion:
    description: "All tools in a skill domain reach proficient+"
    domains: 25
    check_frequency: "daily"
    priority: "P1"
    template: "milestone-achieved"

  engagement_count:
    description: "Completed engagement count crosses threshold"
    thresholds: [1, 5, 10, 25, 50]
    check_frequency: "weekly"
    priority: "P1"
    template: "milestone-achieved"

  streak_days:
    description: "Consecutive days with learning activity"
    thresholds: [7, 14, 30, 60, 90, 180, 365]
    check_frequency: "daily"
    priority: "P2"
    template: "milestone-achieved"

  knowledge_entries:
    description: "MEMORY.md distilled entries count"
    thresholds: [10, 25, 50, 100]
    check_frequency: "weekly"
    priority: "P2"
    template: "milestone-achieved"
```

### Automated Milestone Recording Script

```bash
# Check all milestone thresholds and auto-record if crossed
# Designed to run as part of HEARTBEAT.md periodic checks

TOOLS_FILE="TOOLS.md"
MEMORY_FILE="MEMORY.md"
CHRONICLE_DIR="chronicle"
STATE_FILE="chronicle/.milestone-state.json"
TODAY=$(date +%Y-%m-%d)
MONTH_DIR="chronicle/$(date +%Y-%m)"

# Initialize state file if missing
if [ ! -f "$STATE_FILE" ]; then
  echo '{"last_tool_count":0,"last_engagement_count":0,"last_check":""}' > "$STATE_FILE"
fi

# Count current tool mastery
CURRENT_MASTERED=$(grep -c -iE "mastered\|proficient" "$TOOLS_FILE" 2>/dev/null || echo "0")
LAST_RECORDED=$(python3 -c "import json; print(json.load(open('$STATE_FILE'))['last_tool_count'])" 2>/dev/null || echo "0")

# Check if a threshold was crossed
THRESHOLDS="10 25 50 100 200 300 400 518"
for T in $THRESHOLDS; do
  if [ "$CURRENT_MASTERED" -ge "$T" ] && [ "$LAST_RECORDED" -lt "$T" ]; then
    echo "[MILESTONE-AUTO] Tool mastery threshold crossed: $T (current: $CURRENT_MASTERED)"
    mkdir -p "$MONTH_DIR"
    # Create chronicle entry
    cat > "$MONTH_DIR/${TODAY}-tool-mastery-${T}.md" << EOF
# ${TODAY} - Tool Mastery Milestone: ${T} Tools

> **Type**: Milestone Achieved
> **Priority**: P1
> **Recorded**: ${TODAY} (auto-detected)

## Summary
**One-liner**: Reached ${T} tools at mastered/proficient level (current: ${CURRENT_MASTERED}/518)
**Key Outcomes**: Tool mastery rate progressing on schedule

## Impact
Expanded operational capability across multiple security domains.
EOF
    echo "[MILESTONE-AUTO] Chronicle entry created: $MONTH_DIR/${TODAY}-tool-mastery-${T}.md"
    break  # Only record the highest crossed threshold
  fi
done

# Update state
python3 -c "
import json
state = json.load(open('$STATE_FILE'))
state['last_tool_count'] = $CURRENT_MASTERED
state['last_check'] = '$TODAY'
json.dump(state, open('$STATE_FILE', 'w'))
"
```

---

## 9. Knowledge Distillation Pipelines

### Automated Summarization from Daily Logs

```bash
# Extract and summarize key insights from a batch of daily logs
# Produces structured summaries ready for MEMORY.md insertion

MEMORY_DIR="memory"
START_DATE="${1:-$(date -v-7d +%Y-%m-%d 2>/dev/null || date -d '7 days ago' +%Y-%m-%d)}"
END_DATE="${2:-$(date +%Y-%m-%d)}"
OUTPUT="chronicle/distillation-summary-$(date +%Y%m%d).md"

echo "[DISTILL-PIPELINE] Processing logs from $START_DATE to $END_DATE"
echo "# Knowledge Distillation: $START_DATE to $END_DATE" > "$OUTPUT"
echo "" >> "$OUTPUT"
echo "Generated: $(date -Iseconds)" >> "$OUTPUT"
echo "" >> "$OUTPUT"

# Phase 1: Extract high-signal content
echo "## Extracted Insights" >> "$OUTPUT"
find "$MEMORY_DIR" -name "*.md" -type f | sort | while IFS= read -r file; do
  FILE_DATE=$(basename "$file" .md)
  if [[ "$FILE_DATE" > "$START_DATE" || "$FILE_DATE" == "$START_DATE" ]] && \
     [[ "$FILE_DATE" < "$END_DATE" || "$FILE_DATE" == "$END_DATE" ]]; then

    # Extract lines with learning signals
    INSIGHTS=$(grep -iE "learned|key takeaway|important|pattern|always|never|best practice" "$file" 2>/dev/null)
    if [ -n "$INSIGHTS" ]; then
      echo "" >> "$OUTPUT"
      echo "### $FILE_DATE" >> "$OUTPUT"
      echo "$INSIGHTS" | head -5 | sed 's/^/- /' >> "$OUTPUT"
    fi
  fi
done

# Phase 2: Categorize by knowledge type
echo "" >> "$OUTPUT"
echo "## Categorized Knowledge" >> "$OUTPUT"
echo "" >> "$OUTPUT"
echo "### Techniques" >> "$OUTPUT"
grep -rh -iE "technique|method|approach" "$MEMORY_DIR"/*.md 2>/dev/null \
  | grep -iE "learned|discovered|works" | head -5 | sed 's/^/- /' >> "$OUTPUT"
echo "" >> "$OUTPUT"
echo "### Tool Usage" >> "$OUTPUT"
grep -rh -iE "tool|command|flag|option" "$MEMORY_DIR"/*.md 2>/dev/null \
  | grep -iE "useful|effective|remember" | head -5 | sed 's/^/- /' >> "$OUTPUT"
echo "" >> "$OUTPUT"
echo "### Patterns" >> "$OUTPUT"
grep -rh -iE "pattern|always.*when|if.*then" "$MEMORY_DIR"/*.md 2>/dev/null \
  | head -5 | sed 's/^/- /' >> "$OUTPUT"

TOTAL_INSIGHTS=$(grep -c "^- " "$OUTPUT" 2>/dev/null || echo "0")
echo "[DISTILL-PIPELINE] Extracted $TOTAL_INSIGHTS insights. Output: $OUTPUT"
```

### Key Insight Extraction with Confidence Scoring

```python
#!/usr/bin/env python3
"""Extract key insights from chronicle entries and score by confidence level.
Produces MEMORY.md-ready entries with source attribution."""

import os
import re
import glob
from datetime import datetime

SIGNAL_KEYWORDS = {
    "high": ["always", "never", "critical", "must", "proven", "confirmed", "verified"],
    "medium": ["usually", "often", "pattern", "learned", "discovered", "effective"],
    "low": ["might", "possibly", "seems", "appears", "consider", "maybe"]
}

def score_confidence(text):
    """Score confidence based on keyword presence."""
    text_lower = text.lower()
    for level, keywords in SIGNAL_KEYWORDS.items():
        if any(kw in text_lower for kw in keywords):
            return level
    return "low"

def extract_insights(chronicle_dir="chronicle"):
    """Extract insights from all chronicle entries."""
    insights = []
    for filepath in sorted(glob.glob(f"{chronicle_dir}/**/*.md", recursive=True)):
        if "SUMMARY" in filepath:
            continue
        with open(filepath) as f:
            content = f.read()

        # Extract Impact and Lesson sections
        impact_match = re.search(r"## Impact\s*\n(.*?)(?=\n## |\Z)", content, re.DOTALL)
        if impact_match:
            text = impact_match.group(1).strip()
            if len(text) > 20:
                insights.append({
                    "source": filepath,
                    "text": text[:200],
                    "confidence": score_confidence(text),
                    "date": re.search(r"\d{4}-\d{2}-\d{2}", os.path.basename(filepath)).group(0)
                        if re.search(r"\d{4}-\d{2}-\d{2}", os.path.basename(filepath)) else "unknown"
                })
    return insights

def format_for_memory(insights):
    """Format insights as MEMORY.md entries."""
    output = []
    for ins in sorted(insights, key=lambda x: x["confidence"] == "high", reverse=True):
        output.append(f"### [{ins['confidence'].upper()}] Insight ({ins['date']})\n")
        output.append(f"**Source**: `{ins['source']}`\n")
        output.append(f"**Confidence**: {ins['confidence'].capitalize()}\n")
        output.append(f"**Lesson**: {ins['text']}\n")
        output.append("")
    return "\n".join(output)

if __name__ == "__main__":
    insights = extract_insights()
    print(f"[DISTILL] Extracted {len(insights)} insights")
    print(format_for_memory(insights))
```

### Deduplication and Merge Pipeline

```bash
# Detect and merge duplicate knowledge entries across MEMORY.md
# Prevents knowledge fragmentation from multiple distillation passes

MEMORY_FILE="MEMORY.md"
OUTPUT="chronicle/dedup-report-$(date +%Y%m%d).txt"

echo "[DEDUP] Scanning MEMORY.md for duplicate or overlapping entries"

# Extract all lesson lines
grep -n "^\*\*Lesson\*\*:" "$MEMORY_FILE" 2>/dev/null > /tmp/memory_lessons.txt

# Find similar entries using simple word overlap
python3 -c "
import re
from collections import defaultdict

lessons = []
with open('/tmp/memory_lessons.txt') as f:
    for line in f:
        match = re.match(r'(\d+):\*\*Lesson\*\*:\s*(.*)', line.strip())
        if match:
            lessons.append((int(match.group(1)), match.group(2).lower()))

# Compare each pair for word overlap
duplicates = []
for i, (line_a, text_a) in enumerate(lessons):
    words_a = set(text_a.split())
    for j, (line_b, text_b) in enumerate(lessons[i+1:], i+1):
        words_b = set(text_b.split())
        overlap = len(words_a & words_b) / max(len(words_a | words_b), 1)
        if overlap > 0.6:
            duplicates.append((line_a, line_b, f'{overlap:.0%}'))

if duplicates:
    print(f'[DEDUP] Found {len(duplicates)} potential duplicates:')
    for a, b, pct in duplicates:
        print(f'  Lines {a} and {b} — {pct} word overlap')
else:
    print('[DEDUP] No duplicates found')
" > "$OUTPUT"

cat "$OUTPUT"
rm -f /tmp/memory_lessons.txt
echo "[DEDUP] Report saved to $OUTPUT"
```

### Priority Re-Classification Audit

```bash
# Audit chronicle entries for potential priority misclassification
# Flags P2 entries that contain P0/P1 keywords, and P0 entries lacking critical content

CHRONICLE_DIR="chronicle"
OUTPUT="chronicle/priority-audit-$(date +%Y%m%d).txt"

echo "[PRIORITY-AUDIT] Checking for misclassified priorities"

find "$CHRONICLE_DIR" -name "*.md" ! -name "SUMMARY.md" -type f | sort | while IFS= read -r file; do
  PRIORITY=$(grep -m1 "Priority" "$file" 2>/dev/null | grep -oE "P[0-2]")
  TITLE=$(grep -m1 "^# " "$file" 2>/dev/null | sed 's/^# //')

  case "$PRIORITY" in
    P2)
      # Check if P2 contains critical keywords suggesting higher priority
      if grep -qi -E "critical|vulnerability|exploit|breach|CVE-" "$file" 2>/dev/null; then
        echo "[UPGRADE?] $file — P2 contains critical keywords, consider P0/P1" >> "$OUTPUT"
      fi
      ;;
    P0)
      # Check if P0 lacks required depth (Impact section, evidence links)
      if ! grep -q "## Impact" "$file" 2>/dev/null; then
        echo "[INCOMPLETE] $file — P0 missing Impact section" >> "$OUTPUT"
      fi
      if ! grep -q "evidence/" "$file" 2>/dev/null; then
        echo "[NO-EVIDENCE] $file — P0 has no evidence links" >> "$OUTPUT"
      fi
      ;;
  esac
done

ISSUES=$(grep -c "^\[" "$OUTPUT" 2>/dev/null || echo "0")
echo "[PRIORITY-AUDIT] Found $ISSUES potential issues. See: $OUTPUT"
```

### Knowledge Freshness Scoring

```python
#!/usr/bin/env python3
"""Score MEMORY.md entries by freshness and relevance.
Identifies stale knowledge that may need re-validation or archival."""

import re
import os
from datetime import datetime, timedelta

def score_freshness(memory_file="MEMORY.md"):
    """Score each knowledge entry by age and cross-reference count."""
    entries = []
    current_entry = None

    with open(memory_file) as f:
        for line in f:
            # Detect entry headers
            date_match = re.search(r'\((\d{4}-\d{2}-\d{2})\)', line)
            if line.startswith("### ") and date_match:
                if current_entry:
                    entries.append(current_entry)
                current_entry = {
                    "title": line.strip().lstrip("# "),
                    "date": date_match.group(1),
                    "references": 0,
                    "content_lines": 0
                }
            elif current_entry:
                current_entry["content_lines"] += 1
                # Count cross-references
                if re.search(r'chronicle/|skills/|TOOLS\.md', line):
                    current_entry["references"] += 1

    if current_entry:
        entries.append(current_entry)

    # Score entries
    today = datetime.now()
    for entry in entries:
        try:
            entry_date = datetime.strptime(entry["date"], "%Y-%m-%d")
            age_days = (today - entry_date).days
        except ValueError:
            age_days = 999

        # Freshness score: 100 for today, decays over time
        entry["freshness"] = max(0, 100 - (age_days // 7) * 5)
        # Relevance boost from cross-references
        entry["relevance"] = min(100, entry["freshness"] + entry["references"] * 10)
        entry["age_days"] = age_days

    # Report stale entries
    stale = [e for e in entries if e["freshness"] < 30]
    print(f"[FRESHNESS] Total entries: {len(entries)}")
    print(f"[FRESHNESS] Stale (freshness < 30): {len(stale)}")
    for entry in sorted(stale, key=lambda x: x["freshness"]):
        print(f"  [{entry['freshness']:3d}] {entry['title']} (age: {entry['age_days']}d, refs: {entry['references']})")

    return entries

if __name__ == "__main__":
    score_freshness()
```

### Chronicle Statistics Dashboard

```bash
# Generate comprehensive statistics about the chronicle system health
# Useful for monthly reviews and system optimization

CHRONICLE_DIR="chronicle"
MEMORY_FILE="MEMORY.md"
OUTPUT="chronicle/stats-dashboard-$(date +%Y%m%d).txt"

echo "[STATS] Generating chronicle system statistics"
echo "=== Chronicle System Dashboard ===" > "$OUTPUT"
echo "Generated: $(date -Iseconds)" >> "$OUTPUT"
echo "" >> "$OUTPUT"

# Total entries by priority
echo "## Entry Counts" >> "$OUTPUT"
TOTAL=$(find "$CHRONICLE_DIR" -name "*.md" ! -name "SUMMARY.md" -type f | wc -l | tr -d ' ')
P0=$(grep -rl "Priority.*P0" "$CHRONICLE_DIR" 2>/dev/null | wc -l | tr -d ' ')
P1=$(grep -rl "Priority.*P1" "$CHRONICLE_DIR" 2>/dev/null | wc -l | tr -d ' ')
P2=$(grep -rl "Priority.*P2" "$CHRONICLE_DIR" 2>/dev/null | wc -l | tr -d ' ')
echo "Total: $TOTAL | P0: $P0 | P1: $P1 | P2: $P2" >> "$OUTPUT"

# Monthly distribution
echo "" >> "$OUTPUT"
echo "## Monthly Distribution" >> "$OUTPUT"
for dir in $(find "$CHRONICLE_DIR" -mindepth 1 -maxdepth 1 -type d | sort); do
  MONTH=$(basename "$dir")
  COUNT=$(find "$dir" -name "*.md" ! -name "SUMMARY.md" -type f | wc -l | tr -d ' ')
  HAS_SUMMARY=$([ -f "$dir/SUMMARY.md" ] && echo "YES" || echo "NO")
  echo "  $MONTH: $COUNT entries (summary: $HAS_SUMMARY)" >> "$OUTPUT"
done

# Distillation coverage
echo "" >> "$OUTPUT"
echo "## Distillation Coverage" >> "$OUTPUT"
DISTILLED=$(grep -c "chronicle/" "$MEMORY_FILE" 2>/dev/null || echo "0")
COVERAGE=$(( DISTILLED * 100 / (TOTAL + 1) ))
echo "Entries referenced in MEMORY.md: $DISTILLED/$TOTAL ($COVERAGE%)" >> "$OUTPUT"

# Average entry size
echo "" >> "$OUTPUT"
echo "## Content Quality" >> "$OUTPUT"
AVG_LINES=$(find "$CHRONICLE_DIR" -name "*.md" ! -name "SUMMARY.md" -type f \
  -exec wc -l {} \; | awk '{sum+=$1; n++} END {print int(sum/n)}')
echo "Average entry length: $AVG_LINES lines" >> "$OUTPUT"

echo "[STATS] Dashboard saved to $OUTPUT"
cat "$OUTPUT"
```

### Automated Cross-Reference Link Validator

```bash
# Validate all internal links within chronicle entries point to valid targets
# Checks: file links, MEMORY.md section links, skill references

CHRONICLE_DIR="chronicle"
OUTPUT="chronicle/link-validation-$(date +%Y%m%d).txt"
ERRORS=0

echo "[LINK-CHECK] Validating all internal links in chronicle entries"

find "$CHRONICLE_DIR" -name "*.md" -type f | sort | while IFS= read -r file; do
  # Extract markdown links [text](path)
  grep -oE '\[.*?\]\(([^)]+)\)' "$file" 2>/dev/null | grep -oE '\(([^)]+)\)' | tr -d '()' | while IFS= read -r link; do
    # Skip external URLs
    if echo "$link" | grep -qE "^https?://"; then
      continue
    fi
    # Resolve relative path
    FILE_DIR=$(dirname "$file")
    if echo "$link" | grep -q "^/"; then
      TARGET="$link"
    else
      TARGET="$FILE_DIR/$link"
    fi
    # Remove anchor
    TARGET=$(echo "$TARGET" | cut -d'#' -f1)
    if [ -n "$TARGET" ] && [ ! -f "$TARGET" ]; then
      echo "[BROKEN] $file -> $link (target not found)" >> "$OUTPUT"
      ERRORS=$((ERRORS + 1))
    fi
  done
done

TOTAL_BROKEN=$(grep -c "BROKEN" "$OUTPUT" 2>/dev/null || echo "0")
echo "[LINK-CHECK] Found $TOTAL_BROKEN broken links. See: $OUTPUT"
```
