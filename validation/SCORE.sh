#!/bin/bash
# Skill Quality Scoring Script for kali-claw
# Computes 7 metrics for each skill domain and generates JSON output

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

echo "Scoring ${#SKILLS[@]} skills..."

# Function to compute normalized score (0-100) based on tier thresholds
# Returns 0-100 where min_threshold=0, max_threshold=100
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
        # Excellent tier: 80-100 (capped at 100)
        awk "BEGIN {printf \"%.1f\", 80 + ((($value - $min_excellent) / $min_excellent) * 20)}"
    fi
}

# Function to compute section score (0-1) based on expected sections
compute_section_score() {
    local file=$1
    local expected_sections="$2"

    local sections_found=0
    local expected_count=$(echo "$expected_sections" | wc -w | tr -d ' ')

    for section in $expected_sections; do
        if grep -qEi "^#+.*$section" "$file" 2>/dev/null; then
            ((sections_found++))
        fi
    done

    awk "BEGIN {printf \"%.2f\", $sections_found / $expected_count}"
}

# Expected SKILL.md sections
SKILL_SECTIONS="Description Use Cases Core Tools Methodology Attack Chain Defense Perspective Practical Steps Hacker Laws Learning Resources"

# Function to compute field completeness score (0-1) for test-cases.md
compute_field_completeness() {
    local file=$1

    # Expected fields to check for (keywords that indicate presence)
    local expected_patterns="Severity|Prerequisites|Pre-conditions|Test Steps|Expected Results|Expected Outcomes|Remediation|Pass Criteria|Verification"

    local pattern_count=0
    local total_patterns=7  # We check for 7 key patterns

    # Count how many of the patterns appear in the file
    if echo "$expected_patterns" | grep -qEi "Severity" && grep -qiE "Severity|CRITICAL|HIGH|MEDIUM|LOW" "$file"; then ((pattern_count++)); fi
    if echo "$expected_patterns" | grep -qEi "Prerequisite" && grep -qiE "Prerequisite|Pre-condition" "$file"; then ((pattern_count++)); fi
    if echo "$expected_patterns" | grep -qEi "Step" && grep -qiE "Test Step|Step [0-9]" "$file"; then ((pattern_count++)); fi
    if echo "$expected_patterns" | grep -qEi "Result" && grep -qiE "Expected Result|Expected Outcome" "$file"; then ((pattern_count++)); fi
    if echo "$expected_patterns" | grep -qEi "Payload" && grep -qi "payloads\.md" "$file"; then ((pattern_count++)); fi
    if echo "$expected_patterns" | grep -qEi "Remediation" && grep -qiE "Remediation|Defense|Mitigation" "$file"; then ((pattern_count++)); fi
    if echo "$expected_patterns" | grep -qEi "Pass|Verification" && grep -qiE "Pass Criteria|Verification|Checklist" "$file"; then ((pattern_count++)); fi

    awk "BEGIN {printf \"%.2f\", $pattern_count / $total_patterns}"
}

# Function to compute tier from overall score
compute_tier() {
    local score=$1
    if (( $(awk "BEGIN {print ($score < 40)}") )); then
        echo "Weak"
    elif (( $(awk "BEGIN {print ($score < 60)}") )); then
        echo "Adequate"
    elif (( $(awk "BEGIN {print ($score < 80)}") )); then
        echo "Strong"
    else
        echo "Excellent"
    fi
}

# Main scoring loop
for skill in "${SKILLS[@]}"; do
    SKILL_DIR="$SKILLS_DIR/$skill"
    OUTPUT_FILE="$EVIDENCE_DIR/${skill}.json"

    # Initialize JSON structure
    echo "Processing $skill..."

    # Extract skill name from directory
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

    # Metric 3: payload_code_blocks (``` markers)
    if [ -f "$SKILL_DIR/payloads.md" ]; then
        PAYLOAD_CODE_BLOCKS=$(grep -c '```' "$SKILL_DIR/payloads.md" 2>/dev/null || true)
        PAYLOAD_CODE_BLOCKS=${PAYLOAD_CODE_BLOCKS:-0}
        # Each code block has 2 ``` markers, so divide by 2
        PAYLOAD_CODE_BLOCKS=$((PAYLOAD_CODE_BLOCKS / 2))
    fi

    # Metric 4: test_case_count (### TC- headings)
    if [ -f "$SKILL_DIR/test-cases.md" ]; then
        TEST_CASE_COUNT=$(grep -c "### TC-" "$SKILL_DIR/test-cases.md" 2>/dev/null || true)
        TEST_CASE_COUNT=${TEST_CASE_COUNT:-0}
    fi

    # Metric 5: field_completeness_score
    if [ -f "$SKILL_DIR/test-cases.md" ]; then
        FIELD_COMPLETENESS_SCORE=$(compute_field_completeness "$SKILL_DIR/test-cases.md")
    fi

    # Metric 6: guide_file_count (non-cache files in guides/)
    if [ -d "$SKILL_DIR/guides" ]; then
        GUIDE_FILE_COUNT=$(find "$SKILL_DIR/guides" -type f \( -name "*.md" -o -name "*.py" -o -name "*.sh" \) 2>/dev/null | wc -l | tr -d ' ')
    fi

    # Metric 7: skill_section_score
    if [ -f "$SKILL_DIR/SKILL.md" ]; then
        SKILL_SECTION_SCORE=$(compute_section_score "$SKILL_DIR/SKILL.md" "$SKILL_SECTIONS")
    fi

    # Compute normalized scores (0-100) for each metric
    PAYLOAD_WORD_SCORE=$(compute_normalized_score $PAYLOAD_WORD_COUNT 300 1000 2000 2000)
    PAYLOAD_SECTION_SCORE=$(compute_normalized_score $PAYLOAD_SECTION_COUNT 5 7 9 9)
    PAYLOAD_CODE_SCORE=$(compute_normalized_score $PAYLOAD_CODE_BLOCKS 20 35 50 50)
    TEST_CASE_SCORE=$(compute_normalized_score $TEST_CASE_COUNT 3 5 8 8)
    FIELD_SCORE=$(awk "BEGIN {printf \"%.1f\", $FIELD_COMPLETENESS_SCORE * 100}")
    GUIDE_SCORE=$(compute_normalized_score $GUIDE_FILE_COUNT 0 2 5 5)
    SKILL_SCORE=$(awk "BEGIN {printf \"%.1f\", $SKILL_SECTION_SCORE * 100}")

    # Compute component scores (weighted as planned)
    # SKILL.md: 15%, payloads.md: 30%, test-cases.md: 30%, guides/: 25%
    # payloads.md score = average of 3 payload metrics
    PAYLOAD_COMPONENT=$(awk "BEGIN {printf \"%.2f\", ($PAYLOAD_WORD_SCORE + $PAYLOAD_SECTION_SCORE + $PAYLOAD_CODE_SCORE) / 3}")
    # test-cases.md score = average of test_case_count and field_completeness
    TESTCASE_COMPONENT=$(awk "BEGIN {printf \"%.2f\", ($TEST_CASE_SCORE + $FIELD_SCORE) / 2}")

    # Weighted overall score
    OVERALL_SCORE=$(awk "BEGIN {printf \"%.1f\", ($SKILL_SCORE * 0.15) + ($PAYLOAD_COMPONENT * 0.30) + ($TESTCASE_COMPONENT * 0.30) + ($GUIDE_SCORE * 0.25)}")

    # Compute tier
    TIER=$(compute_tier $OVERALL_SCORE)

    # Write JSON output
    cat > "$OUTPUT_FILE" << EOF
{
  "skill": "$SKILL_NAME",
  "timestamp": "$TIMESTAMP",
  "metrics": {
    "payload_word_count": $PAYLOAD_WORD_COUNT,
    "payload_section_count": $PAYLOAD_SECTION_COUNT,
    "payload_code_blocks": $PAYLOAD_CODE_BLOCKS,
    "test_case_count": $TEST_CASE_COUNT,
    "field_completeness_score": $FIELD_COMPLETENESS_SCORE,
    "guide_file_count": $GUIDE_FILE_COUNT,
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
echo "Scoring complete. Results saved to $EVIDENCE_DIR/"
echo ""
echo "Summary:"
echo "  - Skills scored: ${#SKILLS[@]}"
echo "  - JSON files generated: $(ls -1 "$EVIDENCE_DIR"/*.json 2>/dev/null | wc -l | tr -d ' ')"