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

---

## 7. Spaced Repetition Systems

### Review Scheduler

```python
#!/usr/bin/env python3
"""Spaced repetition scheduler for knowledge review based on confidence level."""
import datetime
import json

INTERVALS = {
    "high":   [365, 540, 730],
    "medium": [90, 120, 180, 270],
    "low":    [14, 30, 60, 90, 120],
}

def next_review_date(confidence, review_count):
    intervals = INTERVALS.get(confidence, INTERVALS["low"])
    idx = min(review_count, len(intervals) - 1)
    return datetime.date.today() + datetime.timedelta(days=intervals[idx])

def generate_review_schedule(entries):
    schedule = []
    for entry in entries:
        confidence = entry.get("confidence", "low")
        review_count = entry.get("review_count", 0)
        next_review = next_review_date(confidence, review_count)
        schedule.append({
            "entry_id": entry["id"],
            "next_review": next_review.isoformat(),
            "confidence": confidence,
        })
    schedule.sort(key=lambda x: x["next_review"])
    return schedule
```

### Flashcard Generation Script

```bash
#!/bin/bash
# Generate flashcard-style review items from knowledge entries

MEMORY_FILE="MEMORY.md"
OUTPUT="learning/flashcards-$(date +%Y%m%d).txt"

grep -A8 "^### \[" "$MEMORY_FILE" | while IFS= read -r line; do
  if echo "$line" | grep -q "^### \["; then
    TITLE=$(echo "$line" | sed 's/^### //')
    echo "Q: What is the key takeaway from: $TITLE"
    echo "A:"
  elif echo "$line" | grep -q "^\*\*Confidence\*\*"; then
    echo "---"
  elif echo "$line" | grep -q "^-"; then
    echo "   $(echo "$line" | sed 's/^- //')"
  fi
done > "$OUTPUT"

CARDS=$(grep -c "^Q:" "$OUTPUT" 2>/dev/null || echo "0")
echo "[FLASHCARD] Generated $CARDS review cards. See: $OUTPUT"
```

---

## 8. Knowledge Graph Construction

### Relationship Mapping Script

```bash
#!/bin/bash
# Build a knowledge graph from cross-references in MEMORY.md

MEMORY_FILE="MEMORY.md"
OUTPUT_DOT="learning/knowledge-graph.dot"

echo "digraph knowledge {" > "$OUTPUT_DOT"
echo "  rankdir=LR;" >> "$OUTPUT_DOT"

grep -oE "KE-[A-Z]+-[0-9]+" "$MEMORY_FILE" | sort -u | while read -r id; do
  echo "  \"$id\";" >> "$OUTPUT_DOT"
done

grep -A5 "See also" "$MEMORY_FILE" | grep -oE "KE-[A-Z]+-[0-9]+" | sort -u | while read -r ref; do
  echo "  \"$ref\";" >> "$OUTPUT_DOT"
done

echo "}" >> "$OUTPUT_DOT"
echo "[GRAPH] DOT file saved to $OUTPUT_DOT"
```

---

## 9. Learning Path Generation

### Skill Progression Generator

```python
#!/usr/bin/env python3
"""Generate a learning path based on skill gaps and target expertise."""

SKILL_DEPENDENCIES = {
    "sql_injection": {"prerequisites": ["http_basics", "database_theory"], "difficulty": 2},
    "blind_sqli": {"prerequisites": ["sql_injection"], "difficulty": 3},
    "time_based_sqli": {"prerequisites": ["blind_sqli"], "difficulty": 4},
    "xss_reflected": {"prerequisites": ["html_js_basics"], "difficulty": 2},
    "xss_stored": {"prerequisites": ["xss_reflected"], "difficulty": 3},
    "xss_dom": {"prerequisites": ["xss_reflected", "javascript_advanced"], "difficulty": 4},
    "ssrf": {"prerequisites": ["http_basics", "networking"], "difficulty": 3},
    "buffer_overflow": {"prerequisites": ["c_programming", "assembly_basics"], "difficulty": 5},
    "rop_chains": {"prerequisites": ["buffer_overflow"], "difficulty": 6},
}

def generate_path(known_skills, target_skill):
    path = []
    visited = set()

    def dfs(skill):
        if skill in visited or skill in known_skills:
            return
        visited.add(skill)
        for dep in SKILL_DEPENDENCIES.get(skill, {}).get("prerequisites", []):
            dfs(dep)
        path.append(skill)

    dfs(target_skill)
    return path
```

---

## 10. Progress Tracking

### Skill Level Tracker

```python
#!/usr/bin/env python3
"""Track skill progression over time with quantitative metrics."""
import json
from datetime import datetime

LEVELS = {
    1: "Awareness", 2: "Understanding", 3: "Application",
    4: "Analysis", 5: "Expertise",
}

class SkillTracker:
    def __init__(self, db_file="learning/skill_progress.json"):
        self.db_file = db_file
        try:
            with open(db_file) as f:
                self.data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            self.data = {"skills": {}, "history": []}

    def update_skill(self, skill_name, level, evidence=""):
        old_level = self.data["skills"].get(skill_name, {}).get("level", 0)
        self.data["skills"][skill_name] = {
            "level": level,
            "level_name": LEVELS.get(level, "Unknown"),
            "last_updated": datetime.now().isoformat(),
            "evidence": evidence,
        }
        self.data["history"].append({
            "skill": skill_name, "old_level": old_level, "new_level": level,
            "date": datetime.now().isoformat(),
        })
        self._save()

    def _save(self):
        with open(self.db_file, "w") as f:
            json.dump(self.data, f, indent=2)
```

---

## 11. Skill Gap Analysis

### Gap Identification Script

```python
#!/usr/bin/env python3
"""Identify gaps between current knowledge and target skill profile."""

TARGET_PROFILE = {
    "web_app": {"sqli": 4, "xss": 4, "ssrf": 3, "auth_bypass": 4, "idor": 3},
    "network": {"scanning": 4, "exploitation": 3, "post_exploit": 3, "pivot": 2},
    "cloud": {"aws": 3, "azure": 2, "gcp": 2, "containers": 3},
}

def analyze_gaps(current_skills, target_area):
    target = TARGET_PROFILE.get(target_area, {})
    gaps = []
    for skill, required_level in target.items():
        current_level = current_skills.get(skill, 0)
        if current_level < required_level:
            gaps.append({
                "skill": skill, "current": current_level,
                "required": required_level, "gap": required_level - current_level,
            })
    gaps.sort(key=lambda x: x["gap"], reverse=True)
    return gaps
```

---

## 12. Adaptive Learning

### Adaptive Priority Queue

```python
#!/usr/bin/env python3
"""Adaptive learning priority queue that adjusts based on performance."""

class LearningPriorityQueue:
    def __init__(self):
        self.items = []

    def add(self, topic, base_priority=5):
        self.items.append({
            "topic": topic, "priority": base_priority,
            "attempts": 0, "successes": 0,
        })

    def record_attempt(self, topic, success):
        for item in self.items:
            if item["topic"] == topic:
                item["attempts"] += 1
                if success:
                    item["successes"] += 1
                    item["priority"] = max(1, item["priority"] - 1)
                else:
                    item["priority"] = min(10, item["priority"] + 1)
                break

    def get_next(self, count=3):
        sorted_items = sorted(self.items, key=lambda x: x["priority"], reverse=True)
        return sorted_items[:count]

    def get_mastery_report(self):
        report = []
        for item in self.items:
            rate = item["successes"] / item["attempts"] if item["attempts"] else 0
            mastery = "mastered" if rate >= 0.8 else "learning" if rate >= 0.5 else "struggling"
            report.append({"topic": item["topic"], "mastery": mastery, "rate": round(rate * 100, 1)})
        return sorted(report, key=lambda x: x["rate"])
```

---

## 13. Engagement Learning Automation

### Auto-Learn from Session Logs

```bash
#!/bin/bash
# Automatically extract learning observations from engagement logs

SESSION_LOG="$1"
OUTPUT="learning/auto-learned-$(date +%Y%m%d).md"

echo "# Auto-Extracted Learning Observations" > "$OUTPUT"
echo "" >> "$OUTPUT"

# Extract successful exploits
grep -iE "(exploited|shell obtained|injection confirmed|bypass successful)" "$SESSION_LOG" | \
  while read -r line; do
    echo "- [ATTACK] $line" >> "$OUTPUT"
  done

# Extract defense encounters
grep -iE "(WAF detected|IDS triggered|rate limit|blocked|filtered)" "$SESSION_LOG" | \
  while read -r line; do
    echo "- [DEFENSE] $line" >> "$OUTPUT"
  done

# Extract tool observations
grep -iE "(tool error|unexpected output|false positive|timeout|incorrect result)" "$SESSION_LOG" | \
  while read -r line; do
    echo "- [TOOL] $line" >> "$OUTPUT"
  done

echo "[AUTO-LEARN] Extracted observations to $OUTPUT"
```

### Knowledge Decay Tracker

```python
#!/usr/bin/env python3
"""Track knowledge decay and surface items needing review."""
import json
from datetime import datetime, timedelta

DECAY_RATES = {
    "high":   365,  # Decays after 1 year without review
    "medium": 90,   # Decays after 90 days
    "low":    30,   # Decays after 30 days
}

def check_decay(entries):
    """Find entries whose knowledge may have decayed."""
    now = datetime.now()
    decayed = []
    for entry in entries:
        confidence = entry.get("confidence", "low")
        last_reviewed = entry.get("last_reviewed")
        if not last_reviewed:
            continue
        reviewed_date = datetime.fromisoformat(last_reviewed)
        age_days = (now - reviewed_date).days
        threshold = DECAY_RATES.get(confidence, 30)
        if age_days > threshold:
            decayed.append({
                "id": entry["id"],
                "title": entry.get("title", ""),
                "age_days": age_days,
                "threshold": threshold,
                "decay_percent": min(100, int(age_days / threshold * 100)),
            })
    decayed.sort(key=lambda x: x["decay_percent"], reverse=True)
    return decayed
```

---

## 14. Cross-Skill Integration Verification

### Skill Dependency Checker

```bash
#!/bin/bash
# Verify all skill references in knowledge base point to valid files

SKILLS_DIR="skills"
MEMORY_FILE="MEMORY.md"

echo "[XREF] Checking skill references in $MEMORY_FILE"

grep -oE 'skills/[a-z-]+/[A-Z_-]+\.(md|txt)' "$MEMORY_FILE" | sort -u | while read -r ref; do
  if [ -f "$ref" ]; then
    echo "[OK] $ref"
  else
    echo "[BROKEN] $ref"
  fi
done

# Check for orphaned skills (skills not referenced in MEMORY.md or IDENTITY.md)
echo ""
echo "[XREF] Checking for orphaned skills..."
ls -d "$SKILLS_DIR"/*/ | while read -r skill_dir; do
  skill_name=$(basename "$skill_dir")
  if ! grep -rq "$skill_name" MEMORY.md IDENTITY.md TOOLS.md 2>/dev/null; then
    echo "[ORPHAN] $skill_name not referenced in core files"
  fi
done
```

### Knowledge Base Integrity Audit

```bash
#!/bin/bash
# Full integrity audit of the knowledge base

echo "[AUDIT] Knowledge base integrity check - $(date +%Y-%m-%d)"

# Check all KE- IDs have proper format
echo "[CHECK] Entry ID format validation..."
grep -oE 'KE-[A-Z]+-[0-9]+' MEMORY.md | sort | uniq -d | while read -r dupe; do
  echo "[DUPLICATE] $dupe appears multiple times"
done

# Check all entries have required fields
echo "[CHECK] Required field validation..."
for id in $(grep -oE 'KE-[A-Z]+-[0-9]+' MEMORY.md | sort -u); do
  section=$(grep -A15 "$id" MEMORY.md)
  for field in "Confidence" "Date" "Category"; do
    if ! echo "$section" | grep -q "$field"; then
      echo "[MISSING] $id missing field: $field"
    fi
  done
done

# Check date validity
echo "[CHECK] Date format validation..."
grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}' MEMORY.md | while read -r date; do
  if ! date -d "$date" &>/dev/null; then
    echo "[INVALID DATE] $date"
  fi
done
```

---

## 15. Tool Mastery Tracking

### Tool Proficiency Assessment

```bash
#!/bin/bash
# Assess proficiency with security tools based on usage history

MEMORY_DIR="memory"
TOOLS=("nmap" "sqlmap" "burpsuite" "metasploit" "nikto" "hydra" "gobuster" "ffuf")

for tool in "${TOOLS[@]}"; do
  usage_count=$(grep -ri "$tool" "$MEMORY_DIR" 2>/dev/null | wc -l | tr -d ' ')
  advanced_count=$(grep -riE "$tool.*(advanced|expert|custom|bypass|evasion)" "$MEMORY_DIR" 2>/dev/null | wc -l | tr -d ' ')
  error_count=$(grep -riE "$tool.*(error|failed|timeout|incorrect|bug)" "$MEMORY_DIR" 2>/dev/null | wc -l | tr -d ' ')

  if [ "$usage_count" -eq 0 ]; then
    level="Not Used"
  elif [ "$usage_count" -lt 5 ]; then
    level="Beginner"
  elif [ "$advanced_count" -lt 2 ]; then
    level="Intermediate"
  else
    level="Advanced"
  fi

  echo "[$level] $tool: usage=$usage_count advanced=$advanced_count errors=$error_count"
done
```

### Learning Milestone Tracker

```python
#!/usr/bin/env python3
"""Track and celebrate learning milestones."""
import json
from datetime import datetime

MILESTONES = {
    "first_find": {"name": "First Finding", "threshold": 1},
    "ten_findings": {"name": "Ten Findings", "threshold": 10},
    "first_critical": {"name": "First Critical", "threshold": 1, "filter": {"severity": "critical"}},
    "first_chain": {"name": "First Chain", "threshold": 1, "filter": {"type": "chain"}},
    "tool_mastery": {"name": "Tool Mastery", "threshold": 50},
}

def check_milestones(entries):
    """Check which milestones have been achieved."""
    achieved = []
    for milestone_id, milestone in MILESTONES.items():
        count = len(entries)
        filt = milestone.get("filter", {})
        if filt:
            count = sum(1 for e in entries if all(e.get(k) == v for k, v in filt.items()))
        if count >= milestone["threshold"]:
            achieved.append({
                "id": milestone_id,
                "name": milestone["name"],
                "achieved_at": datetime.now().isoformat(),
                "count": count,
            })
    return achieved
```

---

## 16. Learning Session Automation

### Daily Review Generator

```bash
#!/bin/bash
# Generate a daily review set from high-priority knowledge entries

OUTPUT="learning/daily-review-$(date +%Y%m%d).md"
MEMORY_FILE="MEMORY.md"

echo "# Daily Review - $(date +%Y-%m-%d)" > "$OUTPUT"
echo "" >> "$OUTPUT"

# Priority 1: Low confidence entries (need reinforcement)
echo "## Priority: Low Confidence Items" >> "$OUTPUT"
grep -B1 -A10 -i "confidence.*low" "$MEMORY_FILE" | head -80 >> "$OUTPUT"

# Priority 2: Entries not reviewed in 30+ days
echo "" >> "$OUTPUT"
echo "## Priority: Overdue Review Items" >> "$OUTPUT"
THIRTY_DAYS_AGO=$(date -d '30 days ago' +%Y-%m-%d 2>/dev/null || date -v-30d +%Y-%m-%d)
grep -B1 -A5 "[0-9]\{4\}-[0-9]\{2\}-[0-9]\{2\}" "$MEMORY_FILE" | \
  grep -B1 -A5 "[0-9]\{4\}-[0-9]\{2\}-[0-9]\{2\}" | \
  head -60 >> "$OUTPUT"

echo "[REVIEW] Daily review generated: $OUTPUT"
```

### Knowledge Transfer Template

```markdown
## Knowledge Transfer Session Template

### Session: [TOPIC]
**Date**: [YYYY-MM-DD]
**Duration**: [X hours]
**Instructor**: [Name]
**Learner**: [Name]

#### Pre-Assessment
- Current confidence level: [1-5]
- Prior experience: [None / Basic / Intermediate]

#### Topics Covered
1. [Topic 1] — [Confidence: __/5]
2. [Topic 2] — [Confidence: __/5]
3. [Topic 3] — [Confidence: __/5]

#### Hands-On Exercises Completed
- [ ] Exercise 1: [Description]
- [ ] Exercise 2: [Description]
- [ ] Exercise 3: [Description]

#### Post-Assessment
- New confidence level: [1-5]
- Key takeaways: [Notes]
- Areas needing more practice: [Notes]

#### Follow-Up Actions
- [ ] Review [topic] within [N] days
- [ ] Practice [technique] in lab environment
- [ ] Read [resource] for deeper understanding
```

---

## 17. Learning Metrics Dashboard

### Weekly Progress Reporter

```python
#!/usr/bin/env python3
"""Generate weekly learning metrics report."""
import json
from datetime import datetime, timedelta

def weekly_report(entries, events_file):
    """Calculate learning metrics for the past week."""
    one_week_ago = datetime.now() - timedelta(days=7)

    recent_entries = [
        e for e in entries
        if datetime.fromisoformat(e.get("date", "2000-01-01")) > one_week_ago
    ]

    by_confidence = {"high": 0, "medium": 0, "low": 0}
    by_category = {}
    for entry in recent_entries:
        conf = entry.get("confidence", "low")
        by_confidence[conf] = by_confidence.get(conf, 0) + 1
        cat = entry.get("category", "unknown")
        by_category[cat] = by_category.get(cat, 0) + 1

    return {
        "period": f"{one_week_ago.strftime('%Y-%m-%d')} to {datetime.now().strftime('%Y-%m-%d')}",
        "new_entries": len(recent_entries),
        "by_confidence": by_confidence,
        "by_category": by_category,
    }
```

### Learning Velocity Calculator

```bash
#!/bin/bash
# Calculate learning velocity (new entries per week)

MEMORY_FILE="MEMORY.md"
OUTPUT="learning/velocity-$(date +%Y%m%d).txt"

# Count entries added in last 7 days
SEVEN_DAYS_AGO=$(date -d '7 days ago' +%Y-%m-%d 2>/dev/null || date -v-7d +%Y-%m-%d)

grep -c "KE-[A-Z]\+-[0-9]\+" "$MEMORY_FILE" > "$OUTPUT"

# Calculate entries per week for the last 4 weeks
for weeks_ago in 0 1 2 3; do
  start=$(date -d "$((weeks_ago * 7 + 7)) days ago" +%Y-%m-%d 2>/dev/null || date -v-${weeks_ago}w +%Y-%m-%d)
  end=$(date -d "$((weeks_ago * 7)) days ago" +%Y-%m-%d 2>/dev/null || date -v-${weeks_ago}w +%Y-%m-%d)
  echo "Week $((4 - weeks_ago)): $start to $end" >> "$OUTPUT"
done

echo "[VELOCITY] Report saved to $OUTPUT"
```

---

## 18. Knowledge Validation

### Self-Test Generator

```bash
#!/bin/bash
# Generate self-test questions from knowledge entries

MEMORY_FILE="MEMORY.md"
OUTPUT="learning/self-test-$(date +%Y%m%d).txt"

echo "# Self-Test Questions - $(date +%Y-%m-%d)" > "$OUTPUT"
echo "" >> "$OUTPUT"

# Extract knowledge entry titles and generate questions
grep "^### \[" "$MEMORY_FILE" | while IFS= read -r line; do
  title=$(echo "$line" | sed 's/^### //')
  echo "Q: Explain the concept: $title" >> "$OUTPUT"
  echo "A: [Write answer from memory, then check MEMORY.md]" >> "$OUTPUT"
  echo "---" >> "$OUTPUT"
done

QUESTIONS=$(grep -c "^Q:" "$OUTPUT" 2>/dev/null || echo "0")
echo "[SELF-TEST] Generated $QUESTIONS questions. See: $OUTPUT"
```

### Peer Review Template

```markdown
## Knowledge Entry Review Template

### Entry Under Review
- **ID**: KE-XXX-NNN
- **Title**: [Entry title]
- **Reviewer**: [Name]
- **Review Date**: [YYYY-MM-DD]

### Accuracy Check
- [ ] Technical details are correct
- [ ] Commands/examples work as described
- [ ] References to tools/versions are current
- [ ] No dangerous or misleading advice

### Completeness Check
- [ ] All required fields are present
- [ ] Context is sufficient for future application
- [ ] Variations/edge cases are noted
- [ ] Counter-indications are documented

### Reviewer Notes
- [Add any corrections, additions, or concerns]

### Verdict
- [ ] Approved as-is
- [ ] Approved with minor corrections
- [ ] Needs revision before approval
- [ ] Should be archived/deprecated
```

---

## 19. Engagement Knowledge Extraction

### Post-Engagement Report Parser

```bash
#!/bin/bash
# Extract learnable knowledge from engagement reports

REPORT="$1"
OUTPUT="learning/engagement-extract-$(date +%Y%m%d).md"

echo "# Engagement Knowledge Extraction" > "$OUTPUT"
echo "" >> "$OUTPUT"

# Extract tools used
echo "## Tools Used" >> "$OUTPUT"
grep -oiE '(nmap|sqlmap|burp|metasploit|nikto|hydra|gobuster|ffuf|nuclei|dirb|wpscan|masscan|amass|subfinder|httpx|dnsx)' "$REPORT" | sort -u | while read -r tool; do
  echo "- $tool" >> "$OUTPUT"
done

# Extract vulnerabilities found
echo "" >> "$OUTPUT"
echo "## Vulnerabilities Found" >> "$OUTPUT"
grep -iE '(SQL injection|XSS|SSRF|IDOR|CSRF|RCE|LFI|RFI|XXE|SSRF|authentication bypass|privilege escalation)' "$REPORT" | sort -u >> "$OUTPUT"

# Extract defenses encountered
echo "" >> "$OUTPUT"
echo "## Defenses Encountered" >> "$OUTPUT"
grep -iE '(WAF|IDS|IPS|rate limit|captcha|2FA|MFA|CSP|HSTS|input validation|prepared statement)' "$REPORT" | sort -u >> "$OUTPUT"
```

### Cross-Engagement Pattern Analyzer

```python
#!/usr/bin/env python3
"""Find patterns that appear across multiple engagement reports."""
import os
import re
from collections import Counter

MEMORY_DIR = "memory"

def find_cross_engagement_patterns():
    """Analyze all daily logs for recurring patterns."""
    all_lines = []
    for filename in os.listdir(MEMORY_DIR):
        if filename.endswith(".md"):
            with open(os.path.join(MEMORY_DIR, filename)) as f:
                all_lines.extend(f.readlines())

    # Find recurring technical terms
    tech_terms = re.findall(r'\b(nmap|sqlmap|burpsuite|metasploit|CVE-\d{4}-\d+)\b',
                            " ".join(all_lines), re.IGNORECASE)
    term_counts = Counter(tech_terms)

    # Find recurring vulnerability types
    vuln_types = re.findall(r'\b(SQLi|XSS|SSRF|IDOR|CSRF|RCE|LFI|RFI|XXE)\b',
                            " ".join(all_lines), re.IGNORECASE)
    vuln_counts = Counter(vuln_types)

    return {
        "top_tools": term_counts.most_common(10),
        "top_vulns": vuln_counts.most_common(10),
        "total_entries": len(all_lines),
    }

results = find_cross_engagement_patterns()
print(f"Tools: {results['top_tools']}")
print(f"Vulns: {results['top_vulns']}")
```

---

## 20. Adaptive Knowledge Refresh

### Stale Knowledge Reviver

```bash
#!/bin/bash
# Surface stale knowledge entries that need refreshing

MEMORY_FILE="MEMORY.md"
OUTPUT="learning/refresh-queue-$(date +%Y%m%d).txt"

echo "# Knowledge Refresh Queue - $(date +%Y-%m-%d)" > "$OUTPUT"

# Find entries with old dates that haven't been reviewed
grep -n -E "[0-9]{4}-[0-9]{2}-[0-9]{2}" "$MEMORY_FILE" | while IFS= read -r line; do
  entry_date=$(echo "$line" | grep -oE "[0-9]{4}-[0-9]{2}-[0-9]{2}" | head -1)
  line_num=$(echo "$line" | cut -d: -f1)

  if [ -n "$entry_date" ]; then
    entry_epoch=$(date -j -f "%Y-%m-%d" "$entry_date" "+%s" 2>/dev/null || date -d "$entry_date" "+%s" 2>/dev/null)
    today_epoch=$(date "+%s")
    age_days=$(( (today_epoch - entry_epoch) / 86400 ))

    if [ "$age_days" -gt 90 ]; then
      content=$(sed -n "${line_num}p" "$MEMORY_FILE")
      echo "- [${age_days}d old] $content" >> "$OUTPUT"
    fi
  fi
done

TOTAL=$(grep -c "^\- \[" "$OUTPUT" 2>/dev/null || echo "0")
echo "[REFRESH] $TOTAL entries need review. See: $OUTPUT"
```

---

## 21. Knowledge Base Backup and Restore

### Automated Backup Script

```bash
#!/bin/bash
# Backup the entire knowledge base with timestamp

BACKUP_DIR="bak/knowledge-backup-$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

# Backup core files
cp MEMORY.md "$BACKUP_DIR/"
cp IDENTITY.md "$BACKUP_DIR/"
cp TOOLS.md "$BACKUP_DIR/"

# Backup memory directory
cp -r memory/ "$BACKUP_DIR/memory/"

# Backup chronicle
cp -r chronicle/ "$BACKUP_DIR/chronicle/" 2>/dev/null

# Backup learning data
cp -r learning/ "$BACKUP_DIR/learning/" 2>/dev/null

# Create integrity manifest
find "$BACKUP_DIR" -type f -exec sha256sum {} \; > "$BACKUP_DIR/manifest.sha256"

echo "[BACKUP] Knowledge base backed up to $BACKUP_DIR"
du -sh "$BACKUP_DIR"
```

### Knowledge Base Restore Script

```bash
#!/bin/bash
# Restore knowledge base from backup

BACKUP_DIR="$1"

if [ ! -d "$BACKUP_DIR" ]; then
  echo "[ERROR] Backup directory not found: $BACKUP_DIR"
  exit 1
fi

# Verify backup integrity
echo "[RESTORE] Verifying backup integrity..."
sha256sum -c "$BACKUP_DIR/manifest.sha256" > /dev/null 2>&1
if [ $? -ne 0 ]; then
  echo "[ERROR] Backup integrity check failed"
  exit 1
fi

echo "[RESTORE] Integrity verified. Restoring..."
cp "$BACKUP_DIR/MEMORY.md" .
cp -r "$BACKUP_DIR/memory/" memory/
echo "[RESTORE] Complete"
```

---

## 22. Knowledge Base Statistics Export

### Statistics Aggregator

```python
#!/usr/bin/env python3
"""Aggregate knowledge base statistics for trend analysis."""
import os
import re
import json
from datetime import datetime

def aggregate_stats():
    """Collect statistics about the entire knowledge base."""
    stats = {
        "generated_at": datetime.now().isoformat(),
        "memory_entries": 0,
        "chronicle_entries": 0,
        "skill_count": 0,
        "total_lines": 0,
    }

    # Count memory entries
    with open("MEMORY.md") as f:
        content = f.read()
        stats["memory_entries"] = len(re.findall(r"KE-[A-Z]+-[0-9]+", content))
        stats["total_lines"] = content.count("\n")

    # Count chronicle entries
    chronicle_dir = "chronicle"
    if os.path.isdir(chronicle_dir):
        for root, dirs, files in os.walk(chronicle_dir):
            stats["chronicle_entries"] += len([f for f in files if f.endswith(".md")])

    # Count skills
    skills_dir = "skills"
    if os.path.isdir(skills_dir):
        stats["skill_count"] = len([d for d in os.listdir(skills_dir)
                                    if os.path.isdir(os.path.join(skills_dir, d))])

    return json.dumps(stats, indent=2)

print(aggregate_stats())
```

---

## 23. Knowledge Base Migration

### Format Migration Script

```bash
#!/bin/bash
# Migrate knowledge entries between formats (e.g., add new required fields)

MEMORY_FILE="MEMORY.md"
BACKUP="bak/MEMORY-pre-migration-$(date +%Y%m%d).md"

cp "$MEMORY_FILE" "$BACKUP"
echo "[MIGRATE] Backup created at $BACKUP"

# Add 'Review Date' field to entries that lack it
grep -n "^### \[" "$MEMORY_FILE" | while IFS=: read -r line_num rest; do
  # Check if next 15 lines contain "Review Date"
  section=$(sed -n "$((line_num)),$((line_num + 15))p" "$MEMORY_FILE")
  if ! echo "$section" | grep -q "Review Date"; then
    # Insert Review Date after the Date line
    sed -i '' "$((line_num + 5))a\\
- **Review Date**: Pending
" "$MEMORY_FILE" 2>/dev/null || sed -i "$((line_num + 5))a\\- **Review Date**: Pending" "$MEMORY_FILE"
    echo "[MIGRATE] Added Review Date to entry at line $line_num"
  fi
done

echo "[MIGRATE] Migration complete"
```
