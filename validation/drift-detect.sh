#!/bin/bash
# drift-detect.sh — Detect drift in skill directory structure
# Compares current state against a baseline snapshot.
# Usage: bash validation/drift-detect.sh [--create-baseline] [--update-baseline]
#   --create-baseline  Create initial baseline snapshot
#   --update-baseline  Update baseline to match current state

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
EVIDENCE_DIR="$SCRIPT_DIR/evidence/drift"
BASELINE_FILE="$EVIDENCE_DIR/baseline.txt"

ACTION="detect"

for arg in "$@"; do
    case "$arg" in
        --create-baseline|--update-baseline) ACTION="update" ;;
        --help) echo "Usage: bash validation/drift-detect.sh [--create-baseline] [--update-baseline]"; exit 0 ;;
    esac
done

mkdir -p "$EVIDENCE_DIR"

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# ── Generate current state snapshot ─────────────────────────────────────

generate_snapshot() {
    local snapshot_file="$1"
    {
        echo "# kali-claw skill directory snapshot — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo ""

        # File listing with sizes
        echo "## files"
        find "$ROOT_DIR/skills" -type f -name "*.md" | sort | while read -r f; do
            REL="${f#$ROOT_DIR/}"
            SIZE=$(wc -w < "$f" | tr -d ' ')
            echo "$REL|$SIZE"
        done

        echo ""
        echo "## directories"
        find "$ROOT_DIR/skills" -type d | sort | while read -r d; do
            REL="${d#$ROOT_DIR/}"
            echo "$REL"
        done

        echo ""
        echo "## skill_key_sections"
        for skill_dir in "$ROOT_DIR"/skills/*/; do
            skill_name=$(basename "$skill_dir")
            skill_md="$skill_dir/SKILL.md"
            if [ -f "$skill_md" ]; then
                sections=$(grep -c "^## " "$skill_md" 2>/dev/null || echo "0")
                echo "$skill_name|$sections"
            fi
        done
    } > "$snapshot_file"
}

# ── Update baseline mode ────────────────────────────────────────────────

if [ "$ACTION" = "update" ]; then
    echo "Creating/updating baseline snapshot..."
    generate_snapshot "$BASELINE_FILE"
    FILE_COUNT=$(grep -c "^skills/" "$BASELINE_FILE" 2>/dev/null || echo "0")
    echo "  Baseline: $BASELINE_FILE"
    echo "  Files tracked: $FILE_COUNT"
    echo "Done."
    exit 0
fi

# ── Detect mode ─────────────────────────────────────────────────────────

if [ ! -f "$BASELINE_FILE" ]; then
    echo "Error: No baseline found. Run with --create-baseline first."
    exit 1
fi

echo "═══════════════════════════════════════════"
echo " Drift Detection — $TIMESTAMP"
echo "═══════════════════════════════════════════"
echo ""

CURRENT_FILE="$EVIDENCE_DIR/current-snapshot.txt"
generate_snapshot "$CURRENT_FILE"

# Compare files section
BASELINE_FILES=$(grep "^skills/" "$BASELINE_FILE" | cut -d'|' -f1 | sort)
CURRENT_FILES=$(grep "^skills/" "$CURRENT_FILE" | cut -d'|' -f1 | sort)

ADDED=0
REMOVED=0
WORD_DRIFT=0
TOTAL_DRIFT=0

# ── Detect added files ──────────────────────────────────────────────────

echo "── Added Files ──"
while IFS= read -r file; do
    if ! echo "$BASELINE_FILES" | grep -qx "$file"; then
        echo "  + $file"
        ADDED=$((ADDED + 1))
        TOTAL_DRIFT=$((TOTAL_DRIFT + 1))
    fi
done <<< "$CURRENT_FILES"

[ "$ADDED" -eq 0 ] && echo "  (none)"

# ── Detect removed files ────────────────────────────────────────────────

echo ""
echo "── Removed Files ──"
while IFS= read -r file; do
    if ! echo "$CURRENT_FILES" | grep -qx "$file"; then
        echo "  - $file"
        REMOVED=$((REMOVED + 1))
        TOTAL_DRIFT=$((TOTAL_DRIFT + 1))
    fi
done <<< "$BASELINE_FILES"

[ "$REMOVED" -eq 0 ] && echo "  (none)"

# ── Detect word count drift ─────────────────────────────────────────────

echo ""
echo "── Word Count Drift (>50% change) ──"

while IFS='|' read -r file words; do
    [ -z "$file" ] && continue
    BASELINE_WORDS=$(grep "^${file}|" "$BASELINE_FILE" | cut -d'|' -f2)
    [ -z "$BASELINE_WORDS" ] && continue

    if [ "$BASELINE_WORDS" -gt 0 ]; then
        CHANGE=$(( (words - BASELINE_WORDS) * 100 / BASELINE_WORDS ))
        ABS_CHANGE=${CHANGE#-}
        if [ "$ABS_CHANGE" -gt 50 ]; then
            echo "  ~ $file: $BASELINE_WORDS → $words words (${CHANGE}%)"
            WORD_DRIFT=$((WORD_DRIFT + 1))
            TOTAL_DRIFT=$((TOTAL_DRIFT + 1))
        fi
    fi
done < <(grep "^skills/" "$CURRENT_FILE")

[ "$WORD_DRIFT" -eq 0 ] && echo "  (none)"

# ── Detect SKILL.md section drift ───────────────────────────────────────

echo ""
echo "── SKILL.md Section Drift ──"

SECTION_DRIFT=0
while IFS='|' read -r skill sections; do
    [ -z "$skill" ] && continue
    BASELINE_SECTIONS=$(grep "^${skill}|" "$BASELINE_FILE" | tail -1 | cut -d'|' -f2)
    [ -z "$BASELINE_SECTIONS" ] && continue

    if [ "$sections" != "$BASELINE_SECTIONS" ]; then
        echo "  ~ $skill: $BASELINE_SECTIONS → $sections sections"
        SECTION_DRIFT=$((SECTION_DRIFT + 1))
        TOTAL_DRIFT=$((TOTAL_DRIFT + 1))
    fi
done < <(grep "^skills/.*|" "$CURRENT_FILE" | grep "skill_key_sections" -A 100 || true)

[ "$SECTION_DRIFT" -eq 0 ] && echo "  (none)"

# ── Summary ─────────────────────────────────────────────────────────────

echo ""
echo "═══════════════════════════════════════════"
echo " Drift Summary"
echo "═══════════════════════════════════════════"
echo "  Added files:     $ADDED"
echo "  Removed files:   $REMOVED"
echo "  Word count drift: $WORD_DRIFT"
echo "  Section drift:   $SECTION_DRIFT"
echo "  Total drift:     $TOTAL_DRIFT"
echo ""

if [ "$TOTAL_DRIFT" -eq 0 ]; then
    echo "DRIFT_NONE — workspace matches baseline"
else
    echo "DRIFT_DETECTED — $TOTAL_DRIFT difference(s) found"
    echo "Run with --update-baseline to accept current state as new baseline."
fi

# Save report
REPORT_FILE="$EVIDENCE_DIR/drift-$(date +%Y%m%d-%H%M%S).txt"
{
    echo "# Drift Report — $TIMESTAMP"
    echo "Added: $ADDED | Removed: $REMOVED | Word drift: $WORD_DRIFT | Section drift: $SECTION_DRIFT | Total: $TOTAL_DRIFT"
} > "$REPORT_FILE"

exit $TOTAL_DRIFT
