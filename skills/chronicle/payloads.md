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
