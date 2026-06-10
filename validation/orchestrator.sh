#!/bin/bash
# orchestrator.sh — End-to-end penetration test workflow engine
# Executes kill chain phases with evidence capture and data handoff.
# Usage: bash validation/orchestrator.sh [options]
#   -t, --target <file>    Target config file (JSON)
#   -o, --output <dir>     Output directory (default: engagement/)
#   -p, --phase <phase>    Run specific phase only (recon|scan|enum|vuln|exploit|postexp|report)
#   --resume               Resume from last checkpoint
#   --dry-run              Show plan without executing
#   --help                 Show this help

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

TARGET_FILE=""
OUTPUT_DIR="$ROOT_DIR/engagement"
PHASE_FILTER=""
RESUME=false
DRY_RUN=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        -t|--target) TARGET_FILE="$2"; shift 2 ;;
        -o|--output) OUTPUT_DIR="$2"; shift 2 ;;
        -p|--phase) PHASE_FILTER="$2"; shift 2 ;;
        --resume) RESUME=true; shift ;;
        --dry-run) DRY_RUN=true; shift ;;
        --help) echo "Usage: bash validation/orchestrator.sh -t targets.json [-o output_dir] [-p phase] [--resume] [--dry-run]"; exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
CHECKPOINT_FILE="$OUTPUT_DIR/checkpoint.json"

# ── Kill chain phases ───────────────────────────────────────────────────

PHASES=("recon" "scan" "enum" "vuln" "exploit" "postexp" "report")
PHASE_NAMES=("Reconnaissance" "Scanning" "Enumeration" "Vulnerability Discovery" "Exploitation" "Post-Exploitation" "Reporting")

PHASE_SKILLS=(
    "recon-osint"
    "network-pentest"
    "network-pentest api-security"
    "vulnerability-assessment web-xss web-sqli web-auth-bypass web-ssrf web-access-control"
    "web-xss web-sqli web-auth-bypass post-exploitation"
    "post-exploitation password-attack"
    "article-writing"
)

PHASE_TOOLS=(
    "subfinder, amass, whatweb, theHarvester, metagoofil"
    "nmap, masscan, nuclei, rustscan"
    "nmap --script, nikto, gobuster, ffuf, enum4linux"
    "sqlmap, burpsuite, dalfox, nuclei, nikto"
    "metasploit, sqlmap, hydra, burpsuite, crackmapexec"
    "metasploit, crackmapexec, chisel, mimikatz, linpeas"
    "pandoc, markdown"
)

# ── Validate target config ──────────────────────────────────────────────

if [ -n "$TARGET_FILE" ] && [ ! -f "$TARGET_FILE" ]; then
    echo "Error: Target file not found: $TARGET_FILE"
    exit 1
fi

# Parse target info
TARGET_NAME="unknown"
TARGET_TYPE="web"
TARGET_SCOPE=""

if [ -n "$TARGET_FILE" ]; then
    TARGET_NAME=$(python3 -c "import json; d=json.load(open('$TARGET_FILE')); print(d.get('name','unknown'))" 2>/dev/null || echo "unknown")
    TARGET_TYPE=$(python3 -c "import json; d=json.load(open('$TARGET_FILE')); print(d.get('type','web'))" 2>/dev/null || echo "web")
    TARGET_SCOPE=$(python3 -c "import json; d=json.load(open('$TARGET_FILE')); print(','.join(d.get('scope',[])))" 2>/dev/null || echo "")
fi

# Adjust phases by target type
case "$TARGET_TYPE" in
    cloud)
        PHASE_SKILLS[0]="recon-osint cloud-security"
        PHASE_SKILLS[3]="cloud-security container-security api-security vulnerability-assessment"
        ;;
    network)
        PHASE_SKILLS[0]="recon-osint network-pentest"
        PHASE_SKILLS[3]="network-pentest vulnerability-assessment"
        ;;
    mobile)
        PHASE_SKILLS[0]="recon-osint mobile-security"
        PHASE_SKILLS[3]="mobile-security vulnerability-assessment"
        ;;
esac

# ── Resume from checkpoint ──────────────────────────────────────────────

COMPLETED_PHASES=()
START_PHASE_IDX=0

if [ "$RESUME" = true ] && [ -f "$CHECKPOINT_FILE" ]; then
    while IFS='=' read -r key value; do
        case "$key" in
            completed) IFS=',' read -ra COMPLETED_PHASES <<< "$value" ;;
            next_phase) START_PHASE_IDX="$value" ;;
        esac
    done < "$CHECKPOINT_FILE"
fi

# ── Setup output directory ──────────────────────────────────────────────

mkdir -p "$OUTPUT_DIR/evidence"
mkdir -p "$OUTPUT_DIR/logs"

# ── Print header ────────────────────────────────────────────────────────

echo "═══════════════════════════════════════════"
echo " Penetration Test Orchestrator"
echo "═══════════════════════════════════════════"
echo "  Target:   $TARGET_NAME ($TARGET_TYPE)"
echo "  Scope:    ${TARGET_SCOPE:-<not specified>}"
echo "  Output:   $OUTPUT_DIR"
echo "  Time:     $TIMESTAMP"
echo "  Phases:   ${#PHASES[@]}"
[ -n "$PHASE_FILTER" ] && echo "  Filter:   $PHASE_FILTER"
echo ""

# ── Save engagement metadata ────────────────────────────────────────────

{
    echo "# Engagement Metadata"
    echo "target_name=$TARGET_NAME"
    echo "target_type=$TARGET_TYPE"
    echo "target_scope=$TARGET_SCOPE"
    echo "start_time=$TIMESTAMP"
    echo "target_file=${TARGET_FILE:-none}"
} > "$OUTPUT_DIR/metadata.txt"

# ── Execute phases ──────────────────────────────────────────────────────

TOTAL=${#PHASES[@]}
OVERALL_STATUS="IN_PROGRESS"

for idx in $(seq 0 $((TOTAL - 1))); do
    PHASE="${PHASES[$idx]}"
    PHASE_NAME="${PHASE_NAMES[$idx]}"
    SKILLS="${PHASE_SKILLS[$idx]}"
    TOOLS="${PHASE_TOOLS[$idx]}"
    STEP=$((idx + 1))

    # Apply phase filter
    if [ -n "$PHASE_FILTER" ] && [ "$PHASE_FILTER" != "$PHASE" ]; then
        continue
    fi

    # Skip completed phases on resume
    if [ ${#COMPLETED_PHASES[@]} -gt 0 ] && [[ " ${COMPLETED_PHASES[*]} " =~ " $PHASE " ]]; then
        echo "  Phase $STEP/$TOTAL: $PHASE_NAME — SKIPPED (completed)"
        continue
    fi

    echo "── Phase $STEP/$TOTAL: $PHASE_NAME ($PHASE) ──────────────────"
    echo "  Skills: $SKILLS"
    echo "  Tools:  $TOOLS"
    echo ""

    PHASE_DIR="$OUTPUT_DIR/evidence/$PHASE"
    PHASE_LOG="$OUTPUT_DIR/logs/${PHASE}.log"

    if [ "$DRY_RUN" = true ]; then
        echo "  [DRY RUN] Would execute phase: $PHASE_NAME"
    else
        mkdir -p "$PHASE_DIR"

        # Create phase evidence template
        {
            echo "# Phase: $PHASE_NAME"
            echo "Timestamp: $TIMESTAMP"
            echo "Phase: $PHASE"
            echo "Skills: $SKILLS"
            echo "Tools: $TOOLS"
            echo "Status: PENDING_AGENT_EXECUTION"
            echo ""
            echo "## Input Data"
            echo "<!-- Data from previous phase -->"
            echo ""
            echo "## Findings"
            echo "<!-- Document findings here -->"
            echo ""
            echo "## Evidence"
            echo "<!-- Screenshots, logs, command outputs -->"
            echo ""
            echo "## Output Data"
            echo "<!-- Data to pass to next phase -->"
        } > "$PHASE_DIR/evidence.md"

        # Run tool-selector to generate specific commands
        if [ -f "$SCRIPT_DIR/tool-selector.sh" ]; then
            echo "  Generating tool commands for $TARGET_TYPE targets..."
            bash "$SCRIPT_DIR/tool-selector.sh" --target-type "$TARGET_TYPE" --phase "$PHASE" --format markdown > "$PHASE_DIR/commands.md" 2>/dev/null || true
        fi

        echo "  Evidence template: $PHASE_DIR/evidence.md"
        echo "  → Agent should execute this phase using: $SKILLS"
    fi

    # Save checkpoint
    COMPLETED_PHASES+=("$PHASE")
    {
        echo "completed=$(IFS=','; echo "${COMPLETED_PHASES[*]}")"
        echo "next_phase=$STEP"
        echo "last_update=$TIMESTAMP"
    } > "$CHECKPOINT_FILE"

    echo ""
done

# ── Generate final report ───────────────────────────────────────────────

if [ -f "$SCRIPT_DIR/report-generator.sh" ]; then
    echo "── Generating Report ────────────────────────────"
    if [ "$DRY_RUN" != true ]; then
        bash "$SCRIPT_DIR/report-generator.sh" --source "$OUTPUT_DIR" --output "$OUTPUT_DIR/report.md" 2>/dev/null || echo "  (report generation deferred — run report-generator.sh manually)"
    else
        echo "  [DRY RUN] Would generate report"
    fi
    echo ""
fi

# ── Summary ─────────────────────────────────────────────────────────────

COMPLETED_COUNT=${#COMPLETED_PHASES[@]}

echo "═══════════════════════════════════════════"
echo " Orchestrator Summary"
echo "═══════════════════════════════════════════"
echo "  Target:       $TARGET_NAME ($TARGET_TYPE)"
echo "  Completed:    $COMPLETED_COUNT/$TOTAL phases"
echo "  Output:       $OUTPUT_DIR"
echo "  Checkpoint:   $CHECKPOINT_FILE"
echo ""

if [ "$COMPLETED_COUNT" -eq "$TOTAL" ]; then
    echo "ENGAGEMENT_COMPLETE — all phases processed"
    OVERALL_STATUS="COMPLETE"
else
    echo "ENGAGEMENT_PARTIAL — $COMPLETED_COUNT/$TOTAL phases processed"
    echo "Run with --resume to continue from checkpoint."
    OVERALL_STATUS="PARTIAL"
fi

# Save final state
{
    echo "# Orchestrator Final State — $TIMESTAMP"
    echo "status=$OVERALL_STATUS"
    echo "completed=$COMPLETED_COUNT/$TOTAL"
    echo "target=$TARGET_NAME"
} > "$OUTPUT_DIR/state.txt"

exit 0
