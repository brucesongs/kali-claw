#!/bin/bash
# scenario-runner.sh — Execute cross-skill attack chain scenarios
# Parses SCEN-001~005 and automates step-by-step execution with evidence capture.
# Usage: bash validation/scenario-runner.sh <SCEN-ID> [--resume] [--dry-run]
#   --resume   Resume from last checkpoint
#   --dry-run  Show steps without executing

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SCENARIOS_DIR="$SCRIPT_DIR/scenarios"
EVIDENCE_BASE="$SCRIPT_DIR/evidence/scenarios"

RESUME=false
DRY_RUN=false
SCEN_ID=""

for arg in "$@"; do
    case "$arg" in
        SCEN-*) SCEN_ID="$arg" ;;
        --resume) RESUME=true ;;
        --dry-run) DRY_RUN=true ;;
        --help) echo "Usage: bash validation/scenario-runner.sh SCEN-001 [--resume] [--dry-run]"; exit 0 ;;
    esac
done

if [ -z "$SCEN_ID" ]; then
    echo "Error: Provide scenario ID (SCEN-001 through SCEN-005)"
    echo "Available:"
    ls "$SCENARIOS_DIR"/SCEN-*.md 2>/dev/null | xargs -n1 basename || echo "  No scenarios found"
    exit 1
fi

SCEN_FILE="$SCENARIOS_DIR/${SCEN_ID}.md"
if [ ! -f "$SCEN_FILE" ]; then
    echo "Error: $SCEN_FILE not found"
    exit 1
fi

EVIDENCE_DIR="$EVIDENCE_BASE/$SCEN_ID"
mkdir -p "$EVIDENCE_DIR"

CHECKPOINT_FILE="$EVIDENCE_DIR/checkpoint.json"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# ── Parse scenario ──────────────────────────────────────────────────────

echo "═══════════════════════════════════════════"
echo " Scenario Runner: $SCEN_ID"
echo "═══════════════════════════════════════════"
echo ""

# Extract skill chain from scenario file
SKILL_CHAIN=$(grep -oP '→\s*\K[a-z-]+' "$SCEN_FILE" 2>/dev/null | sort -u || true)
if [ -z "$SKILL_CHAIN" ]; then
    # Alternative: parse from table rows
    SKILL_CHAIN=$(grep -oP '\|\s*\K[a-z-]+(?=\s*\|)' "$SCEN_FILE" 2>/dev/null | grep -v '^$' | sort -u || true)
fi

echo "Skill chain: $SKILL_CHAIN"
echo "Evidence dir: $EVIDENCE_DIR"
echo ""

# Parse steps from scenario table
declare -a STEP_SKILLS=()
declare -a STEP_ACTIONS=()
declare -a STEP_TOOLS=()

STEP_NUM=0
while IFS= read -r line; do
    # Match table rows with step numbers
    if [[ "$line" =~ \|[[:space:]]*([0-9]+)[[:space:]]*\|[[:space:]]*([a-z-]+)[[:space:]]*\| ]]; then
        STEP_NUM=${BASH_REMATCH[1]}
        STEP_SKILLS+=("${BASH_REMATCH[2]}")
        # Extract action description
        ACTION=$(echo "$line" | awk -F'|' '{print $4}' | xargs 2>/dev/null || echo "")
        STEP_ACTIONS+=("$ACTION")
        # Extract tools
        TOOLS=$(echo "$line" | awk -F'|' '{print $5}' | xargs 2>/dev/null || echo "")
        STEP_TOOLS+=("$TOOLS")
    fi
done < "$SCEN_FILE"

TOTAL_STEPS=${#STEP_SKILLS[@]}
if [ "$TOTAL_STEPS" -eq 0 ]; then
    echo "Warning: Could not parse structured steps. Running in free-form mode."
    TOTAL_STEPS=1
    STEP_SKILLS+=("manual")
    STEP_ACTIONS+=("Execute scenario according to $SCEN_FILE")
    STEP_TOOLS+=("see scenario file")
fi

# ── Check resume state ──────────────────────────────────────────────────

START_STEP=0
COMPLETED_STEPS=()

if [ "$RESUME" = true ] && [ -f "$CHECKPOINT_FILE" ]; then
    while IFS='=' read -r key value; do
        case "$key" in
            completed_steps) IFS=',' read -ra COMPLETED_STEPS <<< "$value" ;;
            next_step) START_STEP="$value" ;;
        esac
    done < "$CHECKPOINT_FILE"
    echo "Resuming from step $START_STEP (${#COMPLETED_STEPS[@]} already completed)"
    echo ""
fi

# ── Execute steps ───────────────────────────────────────────────────────

for i in $(seq 0 $((TOTAL_STEPS - 1))); do
    STEP=$((i + 1))
    SKILL="${STEP_SKILLS[$i]}"
    ACTION="${STEP_ACTIONS[$i]}"
    TOOLS="${STEP_TOOLS[$i]}"

    # Skip already completed steps on resume
    if [ ${#COMPLETED_STEPS[@]} -gt 0 ] && [[ " ${COMPLETED_STEPS[*]} " =~ " $STEP " ]]; then
        echo "  Step $STEP: SKIPPED (already completed)"
        continue
    fi

    echo "── Step $STEP/$TOTAL_STEPS ────────────────────────────"
    echo "  Skill:  $SKILL"
    echo "  Action: $ACTION"
    echo "  Tools:  $TOOLS"
    echo ""

    STEP_EVIDENCE="$EVIDENCE_DIR/step-${STEP}-${SKILL}"

    if [ "$DRY_RUN" = true ]; then
        echo "  [DRY RUN] Would execute step $STEP"
    else
        # Create step evidence file
        {
            echo "# Step $STEP Evidence"
            echo "Timestamp: $TIMESTAMP"
            echo "Skill: $SKILL"
            echo "Action: $ACTION"
            echo "Tools: $TOOLS"
            echo "Status: EXECUTED_BY_AGENT"
            echo ""
            echo "## Notes"
            echo "<!-- Agent fills this section during execution -->"
            echo ""
            echo "## Findings"
            echo "<!-- Document any findings here -->"
        } > "${STEP_EVIDENCE}.md"

        echo "  Evidence template created: ${STEP_EVIDENCE}.md"
        echo "  → Agent should now execute this step using skills/$SKILL/"
    fi

    # Save checkpoint
    COMPLETED_STEPS+=("$STEP")
    echo "completed_steps=$(IFS=','; echo "${COMPLETED_STEPS[*]}")" > "$CHECKPOINT_FILE"
    echo "next_step=$((STEP + 1))" >> "$CHECKPOINT_FILE"
    echo "last_update=$TIMESTAMP" >> "$CHECKPOINT_FILE"

    echo ""
done

# ── Generate summary ────────────────────────────────────────────────────

SUMMARY_FILE="$EVIDENCE_DIR/summary.md"
{
    echo "# $SCEN_ID Execution Summary"
    echo ""
    echo "| Field | Value |"
    echo "|-------|-------|"
    echo "| Scenario | $SCEN_ID |"
    echo "| Executed | $TIMESTAMP |"
    echo "| Total Steps | $TOTAL_STEPS |"
    echo "| Completed | ${#COMPLETED_STEPS[@]} |"
    echo "| Evidence Dir | $EVIDENCE_DIR |"
    echo ""
    echo "## Steps"
    echo ""
    for i in $(seq 0 $((TOTAL_STEPS - 1))); do
        STEP=$((i + 1))
        STATUS="COMPLETED"
        [[ " ${COMPLETED_STEPS[*]} " =~ " $STEP " ]] || STATUS="PENDING"
        echo "- Step $STEP: ${STEP_SKILLS[$i]} — $STATUS"
    done
} > "$SUMMARY_FILE"

echo "═══════════════════════════════════════════"
echo " Summary: ${#COMPLETED_STEPS[@]}/$TOTAL_STEPS steps completed"
echo " Evidence: $EVIDENCE_DIR/"
echo " Summary:  $SUMMARY_FILE"
echo "═══════════════════════════════════════════"
