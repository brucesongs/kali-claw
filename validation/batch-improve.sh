#!/bin/bash
# batch-improve.sh — Identifies the optimal improvement path for each skill
# Reads SCORE.sh evidence JSON and recommends targeted actions per skill.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
SKILLS_DIR="$REPO_ROOT/skills"
EVIDENCE_DIR="$SCRIPT_DIR/evidence/quality-scores"

# Thresholds (from SCORE.sh)
# payload_word_count: 300/1000/2000/2000
# payload_section_count: 5/7/9/9
# payload_code_blocks: 20/35/50/50
# test_case_count: 3/5/8/8
# guide_file_count: 0/2/5/5

usage() {
    echo "Usage: $0 [--target-tier strong|excellent] [--skill SKILL_NAME]"
    echo ""
    echo "Options:"
    echo "  --target-tier   Target tier to reach (default: next tier up)"
    echo "  --skill         Analyze a single skill (default: all non-Excellent)"
    echo "  --top N         Show only top N easiest improvements (default: all)"
    echo ""
    echo "Examples:"
    echo "  $0                          # Show all improvement recommendations"
    echo "  $0 --target-tier excellent  # What's needed to reach Excellent"
    echo "  $0 --skill osint            # Single skill analysis"
    echo "  $0 --top 10                 # Top 10 easiest wins"
    exit 0
}

TARGET_TIER=""
SINGLE_SKILL=""
TOP_N=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --target-tier) TARGET_TIER="$2"; shift 2;;
        --skill) SINGLE_SKILL="$2"; shift 2;;
        --top) TOP_N="$2"; shift 2;;
        --help|-h) usage;;
        *) echo "Unknown option: $1"; usage;;
    esac
done

if [ ! -d "$EVIDENCE_DIR" ] || [ -z "$(ls "$EVIDENCE_DIR"/*.json 2>/dev/null)" ]; then
    echo "[!] No score evidence found. Run SCORE.sh first:"
    echo "    bash validation/SCORE.sh"
    exit 1
fi

# Compute what's needed to gain points in each component
analyze_skill() {
    local json_file="$1"
    local skill=$(jq -r '.skill' "$json_file")
    local score=$(jq -r '.overall_score' "$json_file")
    local tier=$(jq -r '.tier' "$json_file")

    # Determine target
    local target_score
    if [ -n "$TARGET_TIER" ]; then
        case $TARGET_TIER in
            strong) target_score=60;;
            excellent) target_score=80;;
            *) target_score=60;;
        esac
    else
        case $tier in
            Weak) target_score=40;;
            Adequate) target_score=60;;
            Strong) target_score=80;;
            Excellent) return;;  # Already at top
        esac
    fi

    # Skip if already at/above target
    if (( $(awk "BEGIN {print ($score >= $target_score)}") )); then
        return
    fi

    local gap=$(awk "BEGIN {printf \"%.1f\", $target_score - $score}")

    # Extract current metrics
    local words=$(jq -r '.metrics.payload_word_count' "$json_file")
    local sections=$(jq -r '.metrics.payload_section_count' "$json_file")
    local code_blocks=$(jq -r '.metrics.payload_code_blocks' "$json_file")
    local test_cases=$(jq -r '.metrics.test_case_count' "$json_file")
    local guides=$(jq -r '.metrics.guide_file_count' "$json_file")

    # Extract component scores
    local payload_comp=$(jq -r '.component_scores.payloads_md' "$json_file")
    local testcase_comp=$(jq -r '.component_scores.test_cases_md' "$json_file")
    local guide_comp=$(jq -r '.component_scores.guides' "$json_file")
    local skill_comp=$(jq -r '.component_scores.skill_md' "$json_file")

    # Find weakest component (highest improvement potential)
    local recommendations=""
    local effort=0  # Lower = easier

    # Guide recommendations (25% weight, high ROI per file)
    if [ "$guides" -lt 5 ]; then
        local needed=$((5 - guides))
        local guide_potential=$(awk "BEGIN {printf \"%.1f\", (100 - $guide_comp) * 0.25}")
        recommendations="${recommendations}  [GUIDE +${needed} files] potential +${guide_potential} pts (current: ${guides}/5 files)\n"
        effort=$((effort + needed * 2))
    fi

    # Test case recommendations (30% weight)
    if [ "$test_cases" -lt 8 ]; then
        local needed=$((8 - test_cases))
        local tc_potential=$(awk "BEGIN {printf \"%.1f\", (100 - $testcase_comp) * 0.30}")
        recommendations="${recommendations}  [TEST-CASES +${needed}] potential +${tc_potential} pts (current: ${test_cases}/8 cases)\n"
        effort=$((effort + needed * 3))
    fi

    # Payload code block recommendations (part of 30% weight)
    if [ "$code_blocks" -lt 50 ]; then
        local needed=$((50 - code_blocks))
        local payload_potential=$(awk "BEGIN {printf \"%.1f\", (100 - $payload_comp) * 0.30}")
        recommendations="${recommendations}  [PAYLOADS +${needed} code blocks] potential +${payload_potential} pts (current: ${code_blocks}/50 blocks)\n"
        effort=$((effort + needed))
    fi

    # Payload word count
    if [ "$words" -lt 2000 ]; then
        local needed=$((2000 - words))
        recommendations="${recommendations}  [PAYLOADS +${needed} words] (current: ${words}/2000 words)\n"
    fi

    # SKILL.md sections
    if (( $(awk "BEGIN {print ($skill_comp < 60)}") )); then
        recommendations="${recommendations}  [SKILL.MD +sections] add more ## headings (current score: ${skill_comp})\n"
        effort=$((effort + 5))
    fi

    # Output
    printf "%-30s %5s → %-5s  gap: %s  effort: %d\n" "$skill" "$score" "$target_score" "$gap" "$effort"
    printf "$recommendations"
    echo ""
}

echo "============================================================"
echo " batch-improve.sh — Skill Improvement Recommendations"
echo " Target: ${TARGET_TIER:-next tier up}"
echo " Evidence: $EVIDENCE_DIR"
echo "============================================================"
echo ""

if [ -n "$SINGLE_SKILL" ]; then
    json_file="$EVIDENCE_DIR/${SINGLE_SKILL}.json"
    if [ ! -f "$json_file" ]; then
        echo "[!] No evidence for skill: $SINGLE_SKILL"
        exit 1
    fi
    analyze_skill "$json_file"
    exit 0
else
    # Process all skills, sort by score ascending (easiest wins first)
    TMPFILE=$(mktemp)
    for json_file in "$EVIDENCE_DIR"/*.json; do
        score=$(jq -r '.overall_score' "$json_file")
        echo "$score $json_file"
    done | sort -n > "$TMPFILE"

    count=0
    while IFS=' ' read -r score json_file; do
        if [ -n "$TOP_N" ] && [ "$count" -ge "$TOP_N" ]; then
            break
        fi
        analyze_skill "$json_file"
        ((count++)) || true
    done < "$TMPFILE"
    rm -f "$TMPFILE"
fi

echo "============================================================"
echo " Legend:"
echo "   effort = estimated relative work units (lower = easier)"
echo "   potential = max possible score gain from that component"
echo ""
echo " Quickest wins: guides (1 file = ~5 pts), test cases (1 case = ~3-4 pts)"
echo "============================================================"
