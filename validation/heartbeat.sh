#!/bin/bash
# heartbeat.sh — Automated health check for kali-claw workspace
# Replaces manual HEARTBEAT.md checklist with executable checks.
# Usage: bash validation/heartbeat.sh [--fix] [--json]
#   --fix   Automatically fix issues (remove __pycache__, etc.)
#   --json  Output results as JSON

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
EVIDENCE_DIR="$SCRIPT_DIR/evidence/heartbeat"
FIX_MODE=false
JSON_MODE=false

for arg in "$@"; do
    case "$arg" in
        --fix)   FIX_MODE=true ;;
        --json)  JSON_MODE=true ;;
        --help)  echo "Usage: bash validation/heartbeat.sh [--fix] [--json]"; exit 0 ;;
    esac
done

mkdir -p "$EVIDENCE_DIR"

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
ISSUES=0
FIXES=0
RESULTS=()

check_pass() {
    RESULTS+=("PASS|$1|$2")
    [ "$JSON_MODE" = true ] && echo "  ✓ $1" >&2 || echo "  ✓ $1" >&2
}

check_fail() {
    RESULTS+=("FAIL|$1|$2")
    ISSUES=$((ISSUES + 1))
    [ "$JSON_MODE" = true ] && echo "  ✗ $1 — $2" >&2 || echo "  ✗ $1 — $2" >&2
}

check_warn() {
    RESULTS+=("WARN|$1|$2")
    [ "$JSON_MODE" = true ] && echo "  ⚠ $1 — $2" >&2 || echo "  ⚠ $1 — $2" >&2
}

# ── 1. Core File Integrity ──────────────────────────────────────────────

echo "── Core File Integrity ──" >&2

CORE_FILES=(
    "SOUL.md" "AGENTS.md" "IDENTITY.md" "USER.md" "MEMORY.md"
    "TOOLS.md" "HEARTBEAT.md" "TEMPLATE.md" "VERSION" "CHANGELOG.md"
    "README.md" "CLAUDE.md"
)

for f in "${CORE_FILES[@]}"; do
    filepath="$ROOT_DIR/$f"
    if [ -f "$filepath" ] && [ -s "$filepath" ]; then
        check_pass "$f" "exists and non-empty"
    else
        check_fail "$f" "missing or empty"
    fi
done

# ── 2. Version Consistency ──────────────────────────────────────────────

echo "" >&2
echo "── Version Consistency ──" >&2

CURRENT_VERSION=$(cat "$ROOT_DIR/VERSION" 2>/dev/null || echo "unknown")
README_VERSION=$(grep -oP 'v\K[0-9]+\.[0-9]+\.[0-9]+' "$ROOT_DIR/README.md" 2>/dev/null | head -1 || echo "unknown")

if [ "$CURRENT_VERSION" = "$README_VERSION" ]; then
    check_pass "VERSION matches README" "$CURRENT_VERSION"
else
    check_warn "VERSION ($CURRENT_VERSION) differs from README ($README_VERSION)" "verify manually"
fi

# ── 3. Skill Domain Count ──────────────────────────────────────────────

echo "" >&2
echo "── Skill Domain Completeness ──" >&2

SKILL_COUNT=$(find "$ROOT_DIR/skills" -maxdepth 1 -mindepth 1 -type d | wc -l | tr -d ' ')
EXPECTED_SKILLS=74  # 74 v0.1.22 + Distinguished sprint v0.1.23

if [ "$SKILL_COUNT" -ge 69 ]; then
    check_pass "Skill domains" "$SKILL_COUNT directories found"
else
    check_fail "Skill domains" "expected 49+, found $SKILL_COUNT"
fi

# Check each skill has required files
INCOMPLETE=0
for skill_dir in "$ROOT_DIR"/skills/*/; do
    skill_name=$(basename "$skill_dir")
    missing=""
    [ ! -f "$skill_dir/SKILL.md" ] && missing="SKILL.md "
    [ ! -f "$skill_dir/payloads.md" ] && missing="${missing}payloads.md "
    [ ! -f "$skill_dir/test-cases.md" ] && missing="${missing}test-cases.md "
    [ ! -d "$skill_dir/guides" ] && missing="${missing}guides/ "
    if [ -n "$missing" ]; then
        check_fail "$skill_name" "missing: $missing"
        INCOMPLETE=$((INCOMPLETE + 1))
    fi
done

if [ "$INCOMPLETE" -eq 0 ]; then
    check_pass "All skills have required files" ""
fi

# ── 4. __pycache__ Detection ────────────────────────────────────────────

echo "" >&2
echo "── Artifact Detection ──" >&2

PYCACHE_COUNT=$(find "$ROOT_DIR/skills" -type d -name "__pycache__" 2>/dev/null | wc -l | tr -d ' ')

if [ "$PYCACHE_COUNT" -eq 0 ]; then
    check_pass "No __pycache__ artifacts" ""
else
    check_fail "__pycache__ found" "$PYCACHE_COUNT directories"
    if [ "$FIX_MODE" = true ]; then
        find "$ROOT_DIR/skills" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
        FIXES=$((FIXES + PYCACHE_COUNT))
        echo "    Fixed: removed $PYCACHE_COUNT __pycache__ directories" >&2
    fi
fi

# ── 5. Guide Key Sections ───────────────────────────────────────────────

echo "" >&2
echo "── Guide Key Sections (spot check) ──" >&2

MISSING_SECTIONS=0
CHECKED=0

for guide in "$ROOT_DIR"/skills/*/guides/*.md; do
    [ -f "$guide" ] || continue
    CHECKED=$((CHECKED + 1))
    has_intro=$(grep -cl "## Introduction\|## Objective" "$guide" 2>/dev/null || echo "")
    has_refs=$(grep -cl "## References\|## Further Reading\|## Resources" "$guide" 2>/dev/null || echo "")
    if [ -z "$has_intro" ] || [ -z "$has_refs" ]; then
        MISSING_SECTIONS=$((MISSING_SECTIONS + 1))
    fi
done

if [ "$MISSING_SECTIONS" -eq 0 ]; then
    check_pass "Guide key sections" "all $CHECKED guides have Introduction + References"
else
    check_warn "Guide key sections" "$MISSING_SECTIONS/$CHECKED guides missing sections"
fi

# ── 6. Backup Freshness ─────────────────────────────────────────────────

echo "" >&2
echo "── Backup Freshness ──" >&2

BAK_DIR="$ROOT_DIR/bak"
if [ -d "$BAK_DIR" ]; then
    NEWEST_BACKUP=$(find "$BAK_DIR" -name "*.tar.gz" -maxdepth 1 -printf '%T@\n' 2>/dev/null | sort -rn | head -1 || echo "0")
    NOW=$(date +%s)
    if [ "$NEWEST_BACKUP" != "0" ]; then
        AGE_SECONDS=$(( NOW - ${NEWEST_BACKUP%.*} ))
        AGE_HOURS=$(( AGE_SECONDS / 3600 ))
        if [ "$AGE_HOURS" -le 3 ]; then
            check_pass "Backup freshness" "${AGE_HOURS}h old"
        else
            check_warn "Backup stale" "${AGE_HOURS}h old (recommended: ≤3h)"
        fi
    else
        check_warn "No backups found" "run auto-backup.sh"
    fi
else
    check_warn "bak/ directory missing" ""
fi

# ── 7. Memory Staleness ─────────────────────────────────────────────────

echo "" >&2
echo "── Memory Staleness ──" >&2

MEMORY_FILE="$ROOT_DIR/MEMORY.md"
if [ -f "$MEMORY_FILE" ]; then
    MEMORY_AGE=$(( $(date +%s) - $(stat -f %m "$MEMORY_FILE" 2>/dev/null || stat -c %Y "$MEMORY_FILE" 2>/dev/null || echo 0) ))
    MEMORY_DAYS=$(( MEMORY_AGE / 86400 ))
    if [ "$MEMORY_DAYS" -le 14 ]; then
        check_pass "MEMORY.md freshness" "${MEMORY_DAYS}d old"
    else
        check_warn "MEMORY.md stale" "${MEMORY_DAYS}d old (recommended: ≤14d)"
    fi
fi

# ── Output ──────────────────────────────────────────────────────────────

echo "" >&2

if [ "$JSON_MODE" = true ]; then
    echo "{"
    echo "  \"timestamp\": \"$TIMESTAMP\","
    echo "  \"issues\": $ISSUES,"
    echo "  \"fixes\": $FIXES,"
    echo "  \"fix_mode\": $FIX_MODE,"
    echo "  \"skill_count\": $SKILL_COUNT,"
    echo "  \"guides_checked\": $CHECKED,"
    echo "  \"guides_missing_sections\": $MISSING_SECTIONS,"
    echo "  \"pycache_found\": $PYCACHE_COUNT,"
    echo "  \"version\": \"$CURRENT_VERSION\","
    echo "  \"results\": ["
    FIRST=true
    for r in "${RESULTS[@]}"; do
        IFS='|' read -r status name detail <<< "$r"
        [ "$FIRST" = true ] && FIRST=false || echo ","
        printf '    {"status": "%s", "name": "%s", "detail": "%s"}' "$status" "$name" "$detail"
    done
    echo ""
    echo "  ]"
    echo "}"
else
    echo "─────────────────────────────────"
    if [ "$ISSUES" -eq 0 ]; then
        echo "HEARTBEAT_OK — $CHECKED guides checked, 0 issues"
    else
        echo "HEARTBEAT_ISSUES — $ISSUES issue(s) found"
        [ "$FIX_MODE" = true ] && [ "$FIXES" -gt 0 ] && echo "  ($FIXES auto-fixed)"
    fi
    echo "─────────────────────────────────"
fi

# Save report
REPORT_FILE="$EVIDENCE_DIR/heartbeat-$(date +%Y%m%d-%H%M%S).txt"
{
    echo "# Heartbeat Report — $TIMESTAMP"
    echo "Issues: $ISSUES | Fixes: $FIXES | Skills: $SKILL_COUNT | Guides: $CHECKED"
    echo ""
    for r in "${RESULTS[@]}"; do
        echo "$r"
    done
} > "$REPORT_FILE"

exit $ISSUES
