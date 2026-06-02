#!/bin/bash
# Skill Quality Scoring Script v2 for kali-claw
# Computes 7+ metrics for each skill domain and generates JSON output
#
# v2 changes:
#   - All normalized/component scores capped at 100 (no inflation)
#   - Guide quality: composite metric (file count 40% + avg word count 30% + key sections 30%)
#   - Distinguished tier (92+) above Excellent (80-91.9)
#   - Enhanced test case field completeness

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
SKILLS_DIR="$REPO_ROOT/skills"
EVIDENCE_DIR="$SCRIPT_DIR/evidence/quality-scores"
TIMESTAMP=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

# Ensure evidence directory exists
mkdir -p "$EVIDENCE_DIR"

# Skills list (all skill domains)
SKILLS=($(ls -1 "$SKILLS_DIR" | grep -v '^\.' | sort))

echo "Scoring ${#SKILLS[@]} skills (v2)..."

# Function to compute normalized score (0-100) based on tier thresholds
# All scores capped at 100 (no inflation)
compute_normalized_score() {
    local value=$1
    local min_weak=$2
    local min_adequate=$3
    local min_strong=$4
    local min_excellent=$5

    if [ "$value" -lt "$min_adequate" ]; then
        # Weak tier: 0-40
        awk "BEGIN {printf \"%.1f\", ($value / $min_adequate) * 40}"
    elif [ "$value" -lt "$min_strong" ]; then
        # Adequate tier: 40-60
        awk "BEGIN {printf \"%.1f\", 40 + (($value - $min_adequate) / ($min_strong - $min_adequate)) * 20}"
    elif [ "$value" -lt "$min_excellent" ]; then
        # Strong tier: 60-80
        awk "BEGIN {printf \"%.1f\", 60 + (($value - $min_strong) / ($min_excellent - $min_strong)) * 20}"
    else
        # Excellent tier: 80-100 (hard capped at 100)
        awk "BEGIN {v = 80 + ((($value - $min_excellent) / $min_excellent) * 20); if (v > 100) v = 100; printf \"%.1f\", v}"
    fi
}

# Function to compute section score (0-1) based on heading count
compute_section_score() {
    local file=$1
    local count
    count=$(grep -cE "^##" "$file" 2>/dev/null || true)
    count=${count:-0}
    local score
    if [ "$count" -lt 6 ]; then
        score=$(awk "BEGIN {printf \"%.2f\", ($count / 6) * 40}")
    elif [ "$count" -lt 10 ]; then
        score=$(awk "BEGIN {printf \"%.2f\", 40 + (($count - 6) / 4) * 20}")
    elif [ "$count" -lt 15 ]; then
        score=$(awk "BEGIN {printf \"%.2f\", 60 + (($count - 10) / 5) * 20}")
    else
        score=$(awk "BEGIN {v = 80 + (($count - 15) / 15) * 20; if (v > 100) v = 100; printf \"%.2f\", v}")
    fi
    awk "BEGIN {printf \"%.2f\", $score / 100}"
}

# Function to compute field completeness score (0-1) for test-cases.md
compute_field_completeness() {
    local file=$1
    local pattern_count=0
    local total_patterns=7

    if grep -qiE "Severity|CRITICAL|HIGH|MEDIUM|LOW" "$file" 2>/dev/null; then ((pattern_count++)); fi
    if grep -qiE "Prerequisite|Pre-condition|Pre-requisite" "$file" 2>/dev/null; then ((pattern_count++)); fi
    if grep -qiE "Test Step|Steps|Step [0-9]" "$file" 2>/dev/null; then ((pattern_count++)); fi
    if grep -qiE "Expected Result|Expected Outcome|Expected Output" "$file" 2>/dev/null; then ((pattern_count++)); fi
    if grep -qiE "Objective|Purpose|Goal" "$file" 2>/dev/null; then ((pattern_count++)); fi
    if grep -qiE "Remediation|Defense|Mitigation" "$file" 2>/dev/null; then ((pattern_count++)); fi
    if grep -qiE "Pass Criteria|Verification|Checklist" "$file" 2>/dev/null; then ((pattern_count++)); fi

    awk "BEGIN {printf \"%.2f\", $pattern_count / $total_patterns}"
}

# Function to compute guide quality composite score (0-100)
# Composite: file_count (40%) + avg_word_count (30%) + key_section_presence (30%)
compute_guide_quality() {
    local skill_dir=$1
    local guides_dir="$skill_dir/guides"
    local file_count=0
    local total_words=0
    local file_list=()
    local key_section_count=0

    if [ ! -d "$guides_dir" ]; then
        echo "0.0 0 0 0 0.00"
        return
    fi

    # Get list of guide files
    while IFS= read -r f; do
        file_list+=("$f")
    done < <(find "$guides_dir" -type f \( -name "*.md" -o -name "*.py" -o -name "*.sh" \) 2>/dev/null)

    file_count=${#file_list[@]}

    if [ "$file_count" -eq 0 ]; then
        echo "0.0 0 0 0 0.00"
        return
    fi

    # Compute total words across all guide files
    for f in "${file_list[@]}"; do
        local words
        words=$(wc -w < "$f" 2>/dev/null | tr -d ' ')
        words=${words:-0}
        total_words=$((total_words + words))
    done

    local avg_words=$((total_words / file_count))

    # Check key sections across all guide files combined
    local all_content
    all_content=$(cat "${file_list[@]}" 2>/dev/null)

    local intro_present=0
    local practice_present=0
    local refs_present=0

    if echo "$all_content" | grep -qiE "Introduction|Objective|Overview|Purpose"; then intro_present=1; fi
    if echo "$all_content" | grep -qiE "Hands-on|Practice|Exercise|Lab|Walkthrough|Tutorial|Step-by-step"; then practice_present=1; fi
    if echo "$all_content" | grep -qiE "References|Resources|See also|Further reading|Links"; then refs_present=1; fi

    key_section_count=$((intro_present + practice_present + refs_present))

    # Sub-score 1: file count score (0-100, thresholds: 0→0, 2→40, 5→60, 8→80, 10→100)
    local file_score
    if [ "$file_count" -lt 2 ]; then
        file_score=$(awk "BEGIN {printf \"%.1f\", ($file_count / 2) * 40}")
    elif [ "$file_count" -lt 5 ]; then
        file_score=$(awk "BEGIN {printf \"%.1f\", 40 + (($file_count - 2) / 3) * 20}")
    elif [ "$file_count" -lt 8 ]; then
        file_score=$(awk "BEGIN {printf \"%.1f\", 60 + (($file_count - 5) / 3) * 20}")
    else
        file_score=$(awk "BEGIN {v = 80 + (($file_count - 8) / 2) * 20; if (v > 100) v = 100; printf \"%.1f\", v}")
    fi

    # Sub-score 2: avg word count score (0-100, thresholds: 0→0, 200→40, 500→60, 1000→80, 2000→100)
    local word_score
    if [ "$avg_words" -lt 200 ]; then
        word_score=$(awk "BEGIN {printf \"%.1f\", ($avg_words / 200) * 40}")
    elif [ "$avg_words" -lt 500 ]; then
        word_score=$(awk "BEGIN {printf \"%.1f\", 40 + (($avg_words - 200) / 300) * 20}")
    elif [ "$avg_words" -lt 1000 ]; then
        word_score=$(awk "BEGIN {printf \"%.1f\", 60 + (($avg_words - 500) / 500) * 20}")
    else
        word_score=$(awk "BEGIN {v = 80 + (($avg_words - 1000) / 1000) * 20; if (v > 100) v = 100; printf \"%.1f\", v}")
    fi

    # Sub-score 3: key section presence score (0-100, 3 sections → 100)
    local section_score
    section_score=$(awk "BEGIN {printf \"%.1f\", ($key_section_count / 3) * 100}")

    # Composite: 40% file + 30% word + 30% section, capped at 100
    local composite
    composite=$(awk "BEGIN {v = ($file_score * 0.40) + ($word_score * 0.30) + ($section_score * 0.30); if (v > 100) v = 100; printf \"%.1f\", v}")

    echo "$composite $file_count $avg_words $key_section_count $section_score"
}

# Function to compute tier from overall score (v2: includes Distinguished)
compute_tier() {
    local score=$1
    if (( $(awk "BEGIN {print ($score < 40)}") )); then
        echo "Weak"
    elif (( $(awk "BEGIN {print ($score < 60)}") )); then
        echo "Adequate"
    elif (( $(awk "BEGIN {print ($score < 80)}") )); then
        echo "Strong"
    elif (( $(awk "BEGIN {print ($score < 92)}") )); then
        echo "Excellent"
    else
        echo "Distinguished"
    fi
}

# Main scoring loop
for skill in "${SKILLS[@]}"; do
    SKILL_DIR="$SKILLS_DIR/$skill"
    OUTPUT_FILE="$EVIDENCE_DIR/${skill}.json"

    echo "Processing $skill..."

    SKILL_NAME=$(basename "$SKILL_DIR")

    # Initialize metrics
    PAYLOAD_WORD_COUNT=0
    PAYLOAD_SECTION_COUNT=0
    PAYLOAD_CODE_BLOCKS=0
    TEST_CASE_COUNT=0
    FIELD_COMPLETENESS_SCORE=0
    GUIDE_FILE_COUNT=0
    SKILL_SECTION_SCORE=0

    # Metric 1: payload_word_count
    if [ -f "$SKILL_DIR/payloads.md" ]; then
        PAYLOAD_WORD_COUNT=$(wc -w < "$SKILL_DIR/payloads.md" | tr -d ' ')
    fi

    # Metric 2: payload_section_count (## headings)
    if [ -f "$SKILL_DIR/payloads.md" ]; then
        PAYLOAD_SECTION_COUNT=$(grep -c "^## " "$SKILL_DIR/payloads.md" 2>/dev/null || true)
        PAYLOAD_SECTION_COUNT=${PAYLOAD_SECTION_COUNT:-0}
    fi

    # Metric 3: payload_code_blocks (``` markers / 2)
    if [ -f "$SKILL_DIR/payloads.md" ]; then
        PAYLOAD_CODE_BLOCKS=$(grep -c '```' "$SKILL_DIR/payloads.md" 2>/dev/null || true)
        PAYLOAD_CODE_BLOCKS=${PAYLOAD_CODE_BLOCKS:-0}
        PAYLOAD_CODE_BLOCKS=$((PAYLOAD_CODE_BLOCKS / 2))
    fi

    # Metric 4: test_case_count
    if [ -f "$SKILL_DIR/test-cases.md" ]; then
        TEST_CASE_COUNT=$(grep -cE "^##+ TC-" "$SKILL_DIR/test-cases.md" 2>/dev/null || true)
        TEST_CASE_COUNT=${TEST_CASE_COUNT:-0}
    fi

    # Metric 5: field_completeness_score
    if [ -f "$SKILL_DIR/test-cases.md" ]; then
        FIELD_COMPLETENESS_SCORE=$(compute_field_completeness "$SKILL_DIR/test-cases.md")
    fi

    # Metric 6: guide quality (v2 composite)
    GUIDE_QUALITY_OUTPUT=$(compute_guide_quality "$SKILL_DIR")
    GUIDE_COMPOSITE_SCORE=$(echo "$GUIDE_QUALITY_OUTPUT" | awk '{print $1}')
    GUIDE_FILE_COUNT=$(echo "$GUIDE_QUALITY_OUTPUT" | awk '{print $2}')
    GUIDE_AVG_WORDS=$(echo "$GUIDE_QUALITY_OUTPUT" | awk '{print $3}')
    GUIDE_KEY_SECTIONS=$(echo "$GUIDE_QUALITY_OUTPUT" | awk '{print $4}')

    # Metric 7: skill_section_score
    if [ -f "$SKILL_DIR/SKILL.md" ]; then
        SKILL_SECTION_SCORE=$(compute_section_score "$SKILL_DIR/SKILL.md")
    fi

    # Compute normalized scores (0-100) for payload/test-case metrics
    PAYLOAD_WORD_SCORE=$(compute_normalized_score $PAYLOAD_WORD_COUNT 300 1000 2000 2000)
    PAYLOAD_SECTION_SCORE=$(compute_normalized_score $PAYLOAD_SECTION_COUNT 5 7 9 9)
    PAYLOAD_CODE_SCORE=$(compute_normalized_score $PAYLOAD_CODE_BLOCKS 20 35 50 50)
    TEST_CASE_SCORE=$(compute_normalized_score $TEST_CASE_COUNT 3 5 8 8)
    FIELD_SCORE=$(awk "BEGIN {printf \"%.1f\", $FIELD_COMPLETENESS_SCORE * 100}")
    SKILL_SCORE=$(awk "BEGIN {printf \"%.1f\", $SKILL_SECTION_SCORE * 100}")

    # Compute component scores (all capped at 100)
    PAYLOAD_COMPONENT=$(awk "BEGIN {v = ($PAYLOAD_WORD_SCORE + $PAYLOAD_SECTION_SCORE + $PAYLOAD_CODE_SCORE) / 3; if (v > 100) v = 100; printf \"%.2f\", v}")
    TESTCASE_COMPONENT=$(awk "BEGIN {v = ($TEST_CASE_SCORE + $FIELD_SCORE) / 2; if (v > 100) v = 100; printf \"%.2f\", v}")

    # Guide component is now the composite score (already capped at 100)
    GUIDE_SCORE=$GUIDE_COMPOSITE_SCORE

    # Weighted overall score
    OVERALL_SCORE=$(awk "BEGIN {printf \"%.1f\", ($SKILL_SCORE * 0.15) + ($PAYLOAD_COMPONENT * 0.30) + ($TESTCASE_COMPONENT * 0.30) + ($GUIDE_SCORE * 0.25)}")

    # Compute tier (v2: includes Distinguished)
    TIER=$(compute_tier $OVERALL_SCORE)

    # Write JSON output
    cat > "$OUTPUT_FILE" << EOF
{
  "skill": "$SKILL_NAME",
  "timestamp": "$TIMESTAMP",
  "version": "v2",
  "metrics": {
    "payload_word_count": $PAYLOAD_WORD_COUNT,
    "payload_section_count": $PAYLOAD_SECTION_COUNT,
    "payload_code_blocks": $PAYLOAD_CODE_BLOCKS,
    "test_case_count": $TEST_CASE_COUNT,
    "field_completeness_score": $FIELD_COMPLETENESS_SCORE,
    "guide_file_count": $GUIDE_FILE_COUNT,
    "guide_avg_words": $GUIDE_AVG_WORDS,
    "guide_key_sections": $GUIDE_KEY_SECTIONS,
    "skill_section_score": $SKILL_SECTION_SCORE
  },
  "normalized_scores": {
    "payload_word": $PAYLOAD_WORD_SCORE,
    "payload_section": $PAYLOAD_SECTION_SCORE,
    "payload_code": $PAYLOAD_CODE_SCORE,
    "test_case": $TEST_CASE_SCORE,
    "field": $FIELD_SCORE,
    "guide": $GUIDE_SCORE,
    "skill_section": $SKILL_SCORE
  },
  "component_scores": {
    "skill_md": $(awk "BEGIN {printf \"%.2f\", $SKILL_SCORE}"),
    "payloads_md": $PAYLOAD_COMPONENT,
    "test_cases_md": $TESTCASE_COMPONENT,
    "guides": $GUIDE_SCORE
  },
  "overall_score": $OVERALL_SCORE,
  "tier": "$TIER"
}
EOF

    echo "  → Score: $OVERALL_SCORE, Tier: $TIER"
done

echo ""
echo "Scoring complete (v2). Results saved to $EVIDENCE_DIR/"
echo ""
echo "Summary:"
echo "  - Skills scored: ${#SKILLS[@]}"
echo "  - JSON files generated: $(ls -1 "$EVIDENCE_DIR"/*.json 2>/dev/null | wc -l | tr -d ' ')"
