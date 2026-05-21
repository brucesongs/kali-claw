# Continuous Learning — Payloads & Commands

> Companion to `SKILL.md`. Contains pattern detection commands, knowledge entry templates, confidence scoring rubrics, and maintenance payloads organized by learning cycle phase. For structured test scenarios, see `test-cases.md`.

---

## Index

1. [Pattern Detection Commands](#1-pattern-detection-commands)
2. [Knowledge Entry Templates](#2-knowledge-entry-templates)
3. [Confidence Scoring Rubrics](#3-confidence-scoring-rubrics)
4. [Storage Layer Commands](#4-storage-layer-commands)
5. [Cross-Reference Queries](#5-cross-reference-queries)
6. [Knowledge Maintenance Commands](#6-knowledge-maintenance-commands)

---

## 1. Pattern Detection Commands

### Scan Engagement Logs for Attack Patterns

```bash
# Search memory/ and evidence/ for successful exploitation indicators
# Looks for keywords suggesting a learnable attack pattern

MEMORY_DIR="memory"
EVIDENCE_DIR="evidence"
OUTPUT="learning/attack-patterns-$(date +%Y%m%d).txt"

mkdir -p learning/

echo "[DETECT] Scanning for attack patterns in $MEMORY_DIR and $EVIDENCE_DIR"

# Attack success indicators
grep -rl -iE "exploited|shell obtained|injection confirmed|bypass successful|credential found|privilege escalated" \
  "$MEMORY_DIR" "$EVIDENCE_DIR" 2>/dev/null | sort -u | while IFS= read -r file; do
  echo "=== $file ===" >> "$OUTPUT"
  grep -iE "exploited|shell obtained|injection confirmed|bypass successful|credential found|privilege escalated" \
    "$file" >> "$OUTPUT"
  echo "" >> "$OUTPUT"
done

HITS=$(grep -c "^===" "$OUTPUT" 2>/dev/null || echo "0")
echo "[DETECT] Found attack pattern indicators in $HITS files. See: $OUTPUT"
```

### Scan for Defense Pattern Observations

```bash
# Identify observations about defensive measures encountered

MEMORY_DIR="memory"
OUTPUT="learning/defense-patterns-$(date +%Y%m%d).txt"

echo "[DETECT] Scanning for defense pattern observations"

grep -rl -iE "WAF detected|IDS triggered|rate limit|blocked|filtered|403 forbidden|honeypot|deception" \
  "$MEMORY_DIR" 2>/dev/null | sort -u | while IFS= read -r file; do
  echo "=== $file ===" >> "$OUTPUT"
  grep -n -iE "WAF detected|IDS triggered|rate limit|blocked|filtered|403 forbidden|honeypot|deception" \
    "$file" >> "$OUTPUT"
  echo "" >> "$OUTPUT"
done

HITS=$(grep -c "^===" "$OUTPUT" 2>/dev/null || echo "0")
echo "[DETECT] Found defense pattern observations in $HITS files. See: $OUTPUT"
```

### Scan for Tool Behavior Anomalies

```bash
# Find instances where tools produced unexpected results

MEMORY_DIR="memory"
OUTPUT="learning/tool-anomalies-$(date +%Y%m%d).txt"

echo "[DETECT] Scanning for tool behavior anomalies"

grep -rl -iE "false positive|missed finding|unexpected output|tool bug|incorrect result|unreliable|timeout" \
  "$MEMORY_DIR" 2>/dev/null | sort -u | while IFS= read -r file; do
  echo "=== $file ===" >> "$OUTPUT"
  grep -n -iE "false positive|missed finding|unexpected output|tool bug|incorrect result|unreliable|timeout" \
    "$file" >> "$OUTPUT"
  echo "" >> "$OUTPUT"
done

HITS=$(grep -c "^===" "$OUTPUT" 2>/dev/null || echo "0")
echo "[DETECT] Found tool anomaly observations in $HITS files. See: $OUTPUT"
```

### Scan for Recurring Patterns Across Engagements

```bash
# Cross-reference patterns that appear in multiple daily logs
# Patterns seen 3+ times become candidates for High confidence

MEMORY_DIR="memory"
PATTERN_FILE="${1:-learning/attack-patterns-latest.txt}"
OUTPUT="learning/recurring-patterns-$(date +%Y%m%d).txt"

echo "[DETECT] Checking pattern recurrence across engagements"

# Extract unique pattern descriptions and count occurrences
grep -h "exploited\|bypass\|injection\|credential" "$MEMORY_DIR"/*.md 2>/dev/null \
  | sed 's/.*: //' | sort | uniq -c | sort -rn | while IFS= read -r line; do
  COUNT=$(echo "$line" | awk '{print $1}')
  PATTERN=$(echo "$line" | sed 's/^ *[0-9]* *//')
  if [ "$COUNT" -ge 3 ]; then
    echo "[HIGH-CONFIDENCE] ($COUNT occurrences) $PATTERN" >> "$OUTPUT"
  elif [ "$COUNT" -ge 2 ]; then
    echo "[MEDIUM-CONFIDENCE] ($COUNT occurrences) $PATTERN" >> "$OUTPUT"
  fi
done

echo "[DETECT] Recurring pattern analysis complete. See: $OUTPUT"
```

---

## 2. Knowledge Entry Templates

### Attack Pattern Entry

```markdown
## Knowledge Entry: KE-ATK-{NNN}

- **Category**: Attack
- **Technique**: {ATT&CK ID if applicable, e.g., T1190}
- **Context**: {Engagement type, target technology, network position}
- **Pattern**: {What technique worked and why}
- **Root Cause**: {Why the target was vulnerable — misconfiguration, missing patch, design flaw}
- **Prerequisites**: {What must be true for this to work}
- **Steps**: {Concise reproduction steps}
- **Indicators of Success**: {How to confirm exploitation}
- **Variations Observed**: {Different contexts where this applied}
- **Counter-Indications**: {When NOT to attempt this}
- **Applicability**: {Target technologies, versions, configurations where this is relevant}
- **Source**: {Engagement name/date or research reference}
- **Date**: {YYYY-MM-DD}
- **Confidence**: {High / Medium / Low}
```

### Defense Pattern Entry

```markdown
## Knowledge Entry: KE-DEF-{NNN}

- **Category**: Defense
- **Context**: {Where and when this defense was encountered}
- **Pattern**: {What defense mechanism was observed}
- **Behavior**: {How the defense responded to attacks — blocking, alerting, redirecting}
- **Bypass Attempted**: {YES / NO — if yes, what was tried}
- **Bypass Result**: {Successful / Failed / Partial}
- **Bypass Technique**: {If successful, how the defense was circumvented}
- **Indicators**: {How to detect this defense in future engagements}
- **Applicability**: {Products, versions, configurations where this defense is common}
- **Source**: {Engagement name/date}
- **Date**: {YYYY-MM-DD}
- **Confidence**: {High / Medium / Low}
```

### Tool Mastery Note

```markdown
## Knowledge Entry: KE-TOOL-{NNN}

- **Category**: Tool
- **Tool**: {Tool name and version}
- **Use Case**: {Specific scenario this note applies to}
- **Command**: {Exact command with flags}
- **Context**: {When this configuration is optimal}
- **Output Interpretation**: {How to read the results correctly}
- **Gotchas**: {Common mistakes, misleading output, known bugs}
- **Alternatives**: {Other tools for the same job with trade-offs}
- **Performance Notes**: {Speed, resource usage, noise level}
- **Source**: {Engagement or testing session}
- **Date**: {YYYY-MM-DD}
- **Confidence**: {High / Medium / Low}
```

### Environment Pattern Entry

```markdown
## Knowledge Entry: KE-ENV-{NNN}

- **Category**: Environment
- **Context**: {Industry, infrastructure type, deployment pattern}
- **Pattern**: {Common misconfiguration or architectural weakness observed}
- **Prevalence**: {How often this pattern appears — rare / occasional / common / ubiquitous}
- **Risk**: {What an attacker could achieve by exploiting this pattern}
- **Detection Method**: {How to identify this pattern during reconnaissance}
- **Remediation**: {How the target should fix this}
- **Source**: {Engagement name/date}
- **Date**: {YYYY-MM-DD}
- **Confidence**: {High / Medium / Low}
```

### Engagement Lesson Entry

```markdown
## Knowledge Entry: KE-ENG-{NNN}

- **Category**: Engagement
- **Engagement Type**: {Black box / White box / Red team / Bug bounty}
- **What Happened**: {Description of the event or outcome}
- **What We Learned**: {Key takeaway}
- **What We Would Do Differently**: {Process improvement}
- **Time Impact**: {Hours saved or wasted due to this lesson}
- **Applicable Scenarios**: {When this lesson is relevant}
- **Source**: {Engagement name/date}
- **Date**: {YYYY-MM-DD}
- **Confidence**: {High / Medium / Low}
```

---

## 3. Confidence Scoring Rubrics

### Confidence Decision Table

```yaml
# Confidence scoring rubric for knowledge entries
# Score 0-100 with qualitative levels mapped to ranges

confidence_levels:
  high:
    range: "75-100"
    criteria:
      - "Observed 3+ times across different engagements"
      - "Independently verified through multiple tools or methods"
      - "Consistent with documented CVE, advisory, or published research"
      - "Reproduction steps confirmed on different targets"
    storage_action: "Store as established pattern"
    review_frequency: "Annually"

  medium:
    range: "40-74"
    criteria:
      - "Observed 1-2 times with consistent results"
      - "Consistent with known security theory or vendor documentation"
      - "Single-tool verification but logical root cause identified"
      - "Partial reproduction — works in some configurations"
    storage_action: "Store as provisional pattern"
    review_frequency: "Quarterly"

  low:
    range: "10-39"
    criteria:
      - "Single observation with unclear root cause"
      - "Anecdotal evidence only — not independently verified"
      - "May be environment-specific or coincidental"
      - "Tool output ambiguous — possible false positive"
    storage_action: "Store as observation only"
    review_frequency: "Monthly"

  negative:
    range: "0-9"
    criteria:
      - "Previously held belief contradicted by new evidence"
      - "Multiple failed reproduction attempts"
      - "Original observation identified as false positive"
      - "Superseded by newer, conflicting knowledge"
    storage_action: "Flag old entry for review, store correction"
    review_frequency: "Immediate review of related entries"
```

### Confidence Score Calculation

```markdown
## Scoring Worksheet

| Factor | Weight | Score (0-10) | Weighted |
|--------|--------|-------------|----------|
| Observation count (1=2, 2=5, 3+=10) | 3x | __ | __ |
| Independent verification (none=0, partial=5, full=10) | 2x | __ | __ |
| Root cause clarity (unknown=0, hypothesis=5, confirmed=10) | 2x | __ | __ |
| Reproduction success (failed=0, partial=5, reliable=10) | 2x | __ | __ |
| Consistency with prior knowledge (contradicts=0, neutral=5, reinforces=10) | 1x | __ | __ |

**Total**: __ / 100
**Level**: {High / Medium / Low / Negative}
```

### Confidence Evolution Rules

```yaml
# Rules for upgrading or downgrading confidence over time

upgrade_rules:
  low_to_medium:
    trigger: "Second independent observation confirms the pattern"
    action: "Update confidence score, add new source attribution"

  medium_to_high:
    trigger: "Third observation OR independent tool verification"
    action: "Update confidence score, promote to established pattern"

downgrade_rules:
  high_to_medium:
    trigger: "Contradicting observation from a reliable source"
    action: "Add contradicting evidence, lower score, flag for review"

  medium_to_low:
    trigger: "Failed reproduction attempt OR tool identified as unreliable"
    action: "Add failure evidence, lower score, mark as needs verification"

  any_to_negative:
    trigger: "Definitive evidence contradicts the pattern"
    action: "Flag original entry, create correction entry, notify dependent entries"
```

---

## 4. Storage Layer Commands

### Write Knowledge Entry to MEMORY.md

```markdown
## Storage Protocol

1. **Determine storage tier**:
   - Short-term (engagement-specific) -> `memory/YYYY-MM-DD.md`
   - Medium-term (technique-level) -> `MEMORY.md` technique section
   - Long-term (strategic) -> `MEMORY.md` strategic section

2. **Format the entry** using the appropriate template from Section 2

3. **Add to MEMORY.md**:
   ```
   ### [{Category}] {Title} ({YYYY-MM-DD})

   **ID**: KE-{CAT}-{NNN}
   **Confidence**: {score}/100 ({level})
   **Source**: {engagement or chronicle reference}

   {Lesson in 1-2 sentences}

   **Context**: {When to apply this knowledge}
   **See also**: {Related entries by ID}
   ```

4. **Update index** if MEMORY.md has a table of contents or index section
```

### Write Knowledge Entry to Chronicle

```bash
# Create a chronicle entry for a significant learning event

CATEGORY="${1:-Attack}"
TITLE="${2:-New Pattern Discovered}"
DATE=$(date +%Y-%m-%d)
MONTH=$(date +%Y-%m)
SLUG=$(echo "$TITLE" | tr '[:upper:]' '[:lower:]' | sed 's/ /-/g' | sed 's/[^a-z0-9-]//g')
OUTPUT="chronicle/$MONTH/${DATE}-${SLUG}.md"

mkdir -p "chronicle/$MONTH"

echo "[STORE] Creating chronicle entry: $OUTPUT"
echo "[STORE] Category: $CATEGORY | Title: $TITLE | Date: $DATE"
```

### Append to Daily Log

```bash
# Append a learning observation to the current daily log

DATE=$(date +%Y-%m-%d)
DAILY_LOG="memory/${DATE}.md"
OBSERVATION="${1:-No observation provided}"
CATEGORY="${2:-General}"

if [ ! -f "$DAILY_LOG" ]; then
  echo "# Daily Log: $DATE" > "$DAILY_LOG"
  echo "" >> "$DAILY_LOG"
fi

{
  echo "## Learning Observation ($CATEGORY) — $(date +%H:%M)"
  echo ""
  echo "$OBSERVATION"
  echo ""
  echo "---"
  echo ""
} >> "$DAILY_LOG"

echo "[STORE] Observation appended to $DAILY_LOG"
```

---

## 5. Cross-Reference Queries

### Find Related Knowledge Entries

```bash
# Search MEMORY.md for entries related to a keyword or technique

KEYWORD="${1:-sql injection}"
MEMORY_FILE="MEMORY.md"

echo "[XREF] Searching MEMORY.md for entries related to: $KEYWORD"

grep -n -i -B2 -A5 "$KEYWORD" "$MEMORY_FILE" 2>/dev/null | head -100

echo ""
echo "[XREF] Also checking chronicle for related entries..."
grep -rl -i "$KEYWORD" chronicle/ 2>/dev/null | sort | while IFS= read -r file; do
  TITLE=$(grep -m1 "^# " "$file" 2>/dev/null | sed 's/^# //')
  echo "  [CHRONICLE] $TITLE — $file"
done
```

### Check for Contradictions

```bash
# Find knowledge entries that may contradict a new observation
# Compare new pattern against existing entries in the same category

CATEGORY="${1:-Attack}"
NEW_PATTERN="${2:-SQL injection in WordPress 6.x}"
MEMORY_FILE="MEMORY.md"

echo "[XREF] Checking for contradictions to: $NEW_PATTERN"
echo "[XREF] Category: $CATEGORY"

# Find existing entries in the same category
grep -n -A10 "\[$CATEGORY\]" "$MEMORY_FILE" 2>/dev/null | while IFS= read -r line; do
  # Check for keywords that might indicate contradiction
  if echo "$line" | grep -qiE "not vulnerable|patched|fixed|no longer|deprecated|false positive"; then
    echo "[POTENTIAL-CONTRADICTION] $line"
  fi
done

echo "[XREF] Contradiction check complete. Review any flagged entries."
```

### Link Related Entries by Tool

```bash
# Find all knowledge entries mentioning a specific tool

TOOL_NAME="${1:-nmap}"
MEMORY_FILE="MEMORY.md"
CHRONICLE_DIR="chronicle"

echo "[XREF] All knowledge entries referencing tool: $TOOL_NAME"

echo ""
echo "--- MEMORY.md entries ---"
grep -n -B1 -A3 -i "$TOOL_NAME" "$MEMORY_FILE" 2>/dev/null

echo ""
echo "--- Chronicle entries ---"
grep -rl -i "$TOOL_NAME" "$CHRONICLE_DIR" 2>/dev/null | sort | while IFS= read -r file; do
  TITLE=$(grep -m1 "^# " "$file" 2>/dev/null | sed 's/^# //')
  CONFIDENCE=$(grep -i "Confidence" "$file" 2>/dev/null | head -1 | sed 's/.*: //')
  echo "  [$CONFIDENCE] $TITLE — $file"
done

echo ""
echo "--- Skills references ---"
grep -rl -i "$TOOL_NAME" skills/ 2>/dev/null | sort | while IFS= read -r file; do
  echo "  [SKILL] $file"
done
```

### Build Dependency Graph

```bash
# Trace all cross-references from a single knowledge entry

ENTRY_ID="${1:-KE-ATK-001}"
MEMORY_FILE="MEMORY.md"
CHRONICLE_DIR="chronicle"

echo "[XREF] Dependency graph for entry: $ENTRY_ID"

echo ""
echo "--- Direct references ---"
grep -n "$ENTRY_ID" "$MEMORY_FILE" 2>/dev/null
grep -rl "$ENTRY_ID" "$CHRONICLE_DIR" 2>/dev/null

echo ""
echo "--- Entries that reference this entry ---"
grep -n "See also.*$ENTRY_ID\|Related.*$ENTRY_ID" "$MEMORY_FILE" 2>/dev/null

echo ""
echo "--- Entries this entry references ---"
SECTION=$(grep -A20 "$ENTRY_ID" "$MEMORY_FILE" 2>/dev/null)
echo "$SECTION" | grep -oE "KE-[A-Z]+-[0-9]+" | sort -u | while IFS= read -r ref; do
  [ "$ref" = "$ENTRY_ID" ] && continue
  echo "  -> $ref"
done
```

---

## 6. Knowledge Maintenance Commands

### Staleness Detection

```bash
# Find knowledge entries that have not been reviewed within their review period

MEMORY_FILE="MEMORY.md"
TODAY=$(date +%Y-%m-%d)
OUTPUT="learning/stale-knowledge-$(date +%Y%m%d).txt"

mkdir -p learning/

echo "[MAINTAIN] Checking knowledge entry freshness as of $TODAY"

# Extract entries with dates and confidence levels
grep -n -E "KE-[A-Z]+-[0-9]+" "$MEMORY_FILE" 2>/dev/null | while IFS= read -r line; do
  LINE_NUM=$(echo "$line" | cut -d: -f1)
  ENTRY_ID=$(echo "$line" | grep -oE "KE-[A-Z]+-[0-9]+")

  # Look for the date in the next 10 lines
  ENTRY_DATE=$(sed -n "${LINE_NUM},$((LINE_NUM + 10))p" "$MEMORY_FILE" | grep -oE "[0-9]{4}-[0-9]{2}-[0-9]{2}" | head -1)
  CONFIDENCE=$(sed -n "${LINE_NUM},$((LINE_NUM + 10))p" "$MEMORY_FILE" | grep -i "confidence" | head -1)

  if [ -n "$ENTRY_DATE" ]; then
    # Calculate age in days
    ENTRY_EPOCH=$(date -j -f "%Y-%m-%d" "$ENTRY_DATE" "+%s" 2>/dev/null || date -d "$ENTRY_DATE" "+%s" 2>/dev/null)
    TODAY_EPOCH=$(date "+%s")
    AGE_DAYS=$(( (TODAY_EPOCH - ENTRY_EPOCH) / 86400 ))

    # Determine staleness threshold based on confidence
    if echo "$CONFIDENCE" | grep -qi "low"; then
      THRESHOLD=30
    elif echo "$CONFIDENCE" | grep -qi "medium"; then
      THRESHOLD=90
    else
      THRESHOLD=365
    fi

    if [ "$AGE_DAYS" -gt "$THRESHOLD" ]; then
      echo "[STALE] $ENTRY_ID (${AGE_DAYS}d old, threshold ${THRESHOLD}d) — line $LINE_NUM" >> "$OUTPUT"
    fi
  fi
done

STALE=$(grep -c "STALE" "$OUTPUT" 2>/dev/null || echo "0")
echo "[MAINTAIN] $STALE stale entries found. See: $OUTPUT"
```

### Pruning Workflow

```markdown
## Knowledge Pruning Checklist

For each stale entry identified by staleness detection:

1. **Review the entry**
   - [ ] Is the knowledge still accurate?
   - [ ] Has the target technology changed since this was recorded?
   - [ ] Has a newer entry superseded this one?

2. **Decide action**
   - **Retain**: Knowledge still valid. Update the date and confirm confidence level.
   - **Update**: Knowledge partially valid. Modify the entry and reset review date.
   - **Downgrade**: Confidence reduced due to age or contradicting evidence. Lower the score.
   - **Archive**: Knowledge no longer applicable. Move to an archived section with note.
   - **Delete**: Knowledge was incorrect. Remove entry, add correction if needed.

3. **Execute**
   - [ ] Apply the chosen action
   - [ ] Update cross-references if entry was archived or deleted
   - [ ] Log the maintenance action in daily memory log
```

### Consolidate Duplicate Knowledge

```bash
# Find potential duplicate knowledge entries in MEMORY.md

MEMORY_FILE="MEMORY.md"

echo "[MAINTAIN] Checking for potential duplicate knowledge entries"

# Extract all entry titles and look for similar ones
grep -E "^### \[" "$MEMORY_FILE" 2>/dev/null | sed 's/### //' | sort | while IFS= read -r title; do
  # Extract key terms (remove dates and common words)
  TERMS=$(echo "$title" | sed 's/([^)]*)//g' | tr '[:upper:]' '[:lower:]' | tr -cs '[:alpha:]' '\n' | sort -u | tr '\n' ' ')
  echo "$TERMS|$title"
done | sort | uniq -d -w 40

echo "[MAINTAIN] Review any similar entries above and merge if appropriate"
```

### Knowledge Health Report

```bash
# Generate a health summary of the knowledge base

MEMORY_FILE="MEMORY.md"
CHRONICLE_DIR="chronicle"

echo "[HEALTH] Knowledge Base Health Report — $(date +%Y-%m-%d)"
echo "==========================================="

# Count entries by category
echo ""
echo "--- Entries by Category ---"
for CAT in ATK DEF TOOL ENV ENG; do
  COUNT=$(grep -c "KE-${CAT}-" "$MEMORY_FILE" 2>/dev/null || echo "0")
  echo "  KE-$CAT: $COUNT entries"
done

# Count by confidence level
echo ""
echo "--- Entries by Confidence ---"
for LEVEL in High Medium Low; do
  COUNT=$(grep -ci "Confidence.*$LEVEL" "$MEMORY_FILE" 2>/dev/null || echo "0")
  echo "  $LEVEL: $COUNT entries"
done

# Chronicle coverage
echo ""
echo "--- Chronicle Coverage ---"
TOTAL_CHRONICLE=$(find "$CHRONICLE_DIR" -name "*.md" ! -name "SUMMARY.md" -type f 2>/dev/null | wc -l | tr -d ' ')
TOTAL_MONTHS=$(find "$CHRONICLE_DIR" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l | tr -d ' ')
echo "  Total entries: $TOTAL_CHRONICLE across $TOTAL_MONTHS months"

echo ""
echo "==========================================="
echo "[HEALTH] Report complete"
```
