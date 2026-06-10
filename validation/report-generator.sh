#!/bin/bash
# report-generator.sh — Automated penetration test report generator
# Reads evidence from engagement/ and produces structured markdown reports.
# Usage: bash validation/report-generator.sh [options]
#   -s, --source <dir>    Evidence source directory (default: engagement/)
#   -o, --output <file>   Output file (default: engagement/report.md)
#   --format <fmt>        Output format: markdown|html (default: markdown)
#   --template <file>     Custom report template
#   --help                Show this help

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

SOURCE_DIR="$ROOT_DIR/engagement"
OUTPUT_FILE="$ROOT_DIR/engagement/report.md"
REPORT_FORMAT="markdown"
TEMPLATE_FILE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -s|--source) SOURCE_DIR="$2"; shift 2 ;;
        -o|--output) OUTPUT_FILE="$2"; shift 2 ;;
        --format) REPORT_FORMAT="$2"; shift 2 ;;
        --template) TEMPLATE_FILE="$2"; shift 2 ;;
        --help) echo "Usage: bash validation/report-generator.sh [-s source_dir] [-o output_file] [--format markdown|html]"; exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

if [ ! -d "$SOURCE_DIR" ]; then
    echo "Error: Source directory not found: $SOURCE_DIR"
    exit 1
fi

# ── Gather engagement metadata ──────────────────────────────────────────

TARGET_NAME="Unknown"
TARGET_TYPE="web"
ENGAGEMENT_DATE="$TIMESTAMP"

if [ -f "$SOURCE_DIR/metadata.txt" ]; then
    TARGET_NAME=$(grep '^target_name=' "$SOURCE_DIR/metadata.txt" | cut -d'=' -f2 || echo "Unknown")
    TARGET_TYPE=$(grep '^target_type=' "$SOURCE_DIR/metadata.txt" | cut -d'=' -f2 || echo "web")
    ENGAGEMENT_DATE=$(grep '^start_time=' "$SOURCE_DIR/metadata.txt" | cut -d'=' -f2 || echo "$TIMESTAMP")
fi

# ── Count findings from evidence directories ─────────────────────────────

SEVERITY_CRITICAL=0
SEVERITY_HIGH=0
SEVERITY_MEDIUM=0
SEVERITY_LOW=0
SEVERITY_INFO=0
TOTAL_FINDINGS=0

FINDINGS_LIST=""

for phase_dir in "$SOURCE_DIR"/evidence/*/; do
    [ -d "$phase_dir" ] || continue
    phase_name=$(basename "$phase_dir")

    if [ -f "$phase_dir/evidence.md" ]; then
        # Count severity markers in evidence
        local_critical=$(grep -ci 'critical\|CVSS.*9\.' "$phase_dir/evidence.md" 2>/dev/null || echo "0")
        local_high=$(grep -ci 'high\|CVSS.*7\.' "$phase_dir/evidence.md" 2>/dev/null || echo "0")
        local_medium=$(grep -ci 'medium\|CVSS.*4\.' "$phase_dir/evidence.md" 2>/dev/null || echo "0")
        local_low=$(grep -ci 'low\|CVSS.*[0-3]\.' "$phase_dir/evidence.md" 2>/dev/null || echo "0")

        SEVERITY_CRITICAL=$((SEVERITY_CRITICAL + local_critical))
        SEVERITY_HIGH=$((SEVERITY_HIGH + local_high))
        SEVERITY_MEDIUM=$((SEVERITY_MEDIUM + local_medium))
        SEVERITY_LOW=$((SEVERITY_LOW + local_low))
    fi

    # Check for commands.md
    if [ -f "$phase_dir/commands.md" ]; then
        TOOL_COUNT=$(grep -c '^|' "$phase_dir/commands.md" 2>/dev/null || echo "0")
    fi

    # Collect findings
    if [ -f "$phase_dir/evidence.md" ]; then
        # Extract finding titles (## headings after Findings)
        findings=$(awk '/^## Findings/,/^## [A-Z]/' "$phase_dir/evidence.md" | grep -E '^###|^-\s+\*\*' 2>/dev/null || true)
        if [ -n "$findings" ]; then
            FINDINGS_LIST="${FINDINGS_LIST}
### Phase: ${phase_name}
${findings}
"
        fi
    fi
done

TOTAL_FINDINGS=$((SEVERITY_CRITICAL + SEVERITY_HIGH + SEVERITY_MEDIUM + SEVERITY_LOW + SEVERITY_INFO))

# ── Determine overall risk rating ───────────────────────────────────────

if [ "$SEVERITY_CRITICAL" -gt 0 ]; then
    RISK_RATING="CRITICAL"
    RISK_COLOR="red"
elif [ "$SEVERITY_HIGH" -gt 0 ]; then
    RISK_RATING="HIGH"
    RISK_COLOR="orange"
elif [ "$SEVERITY_MEDIUM" -gt 0 ]; then
    RISK_RATING="MEDIUM"
    RISK_COLOR="yellow"
elif [ "$SEVERITY_LOW" -gt 0 ]; then
    RISK_RATING="LOW"
    RISK_COLOR="green"
else
    RISK_RATING="INFORMATIONAL"
    RISK_COLOR="blue"
fi

# ── Generate markdown report ────────────────────────────────────────────

OUTPUT_DIR=$(dirname "$OUTPUT_FILE")
mkdir -p "$OUTPUT_DIR"

{
    echo "# Penetration Test Report"
    echo ""
    echo "## Executive Summary"
    echo ""
    echo "A penetration test was conducted against **${TARGET_NAME}** (type: ${TARGET_TYPE})"
    echo "on ${ENGAGEMENT_DATE}. The assessment covered the full kill chain from reconnaissance"
    echo "through post-exploitation."
    echo ""
    echo "**Overall Risk Rating: ${RISK_RATING}**"
    echo ""
    echo "| Severity | Count |"
    echo "|----------|-------|"
    echo "| Critical | ${SEVERITY_CRITICAL} |"
    echo "| High     | ${SEVERITY_HIGH} |"
    echo "| Medium   | ${SEVERITY_MEDIUM} |"
    echo "| Low      | ${SEVERITY_LOW} |"
    echo "| Info     | ${SEVERITY_INFO} |"
    echo "| **Total** | **${TOTAL_FINDINGS}** |"
    echo ""

    echo "## Scope"
    echo ""
    echo "| Field | Value |"
    echo "|-------|-------|"
    echo "| Target | ${TARGET_NAME} |"
    echo "| Type | ${TARGET_TYPE} |"
    echo "| Date | ${ENGAGEMENT_DATE} |"
    echo "| Framework | kali-claw v$(cat "$ROOT_DIR/VERSION" 2>/dev/null || echo "unknown") |"
    echo ""

    echo "## Methodology"
    echo ""
    echo "The assessment followed the standard penetration testing kill chain:"
    echo ""
    echo "1. **Reconnaissance** — Passive and active information gathering"
    echo "2. **Scanning** — Port discovery and service identification"
    echo "3. **Enumeration** — Deep service and application enumeration"
    echo "4. **Vulnerability Discovery** — Automated and manual vulnerability assessment"
    echo "5. **Exploitation** — Verified exploitation of discovered vulnerabilities"
    echo "6. **Post-Exploitation** — Privilege escalation and lateral movement assessment"
    echo ""

    echo "## Findings"
    echo ""
    if [ -n "$FINDINGS_LIST" ]; then
        echo "$FINDINGS_LIST"
    else
        echo "_Detailed findings are documented in the evidence files under engagement/evidence/._"
        echo ""
        echo "### Evidence Files"
        echo ""
        for phase_dir in "$SOURCE_DIR"/evidence/*/; do
            [ -d "$phase_dir" ] || continue
            phase_name=$(basename "$phase_dir")
            echo "- **${phase_name}**: \`${phase_dir}\`"
        done
    fi
    echo ""

    echo "## Recommendations"
    echo ""
    echo "### Critical & High Priority"
    echo ""
    echo "_Address all critical and high-severity findings immediately._"
    echo ""
    echo "### Medium Priority"
    echo ""
    echo "_Plan remediation for medium-severity findings within 30 days._"
    echo ""
    echo "### Low Priority"
    echo ""
    echo "_Address low-severity findings during regular maintenance cycles._"
    echo ""

    echo "## Conclusion"
    echo ""
    echo "The penetration test of **${TARGET_NAME}** identified ${TOTAL_FINDINGS} findings"
    echo "with an overall risk rating of **${RISK_RATING}**."
    echo ""
    echo "---"
    echo ""
    echo "_Generated by kali-claw report-generator on ${TIMESTAMP}_"

} > "$OUTPUT_FILE"

# ── HTML output (optional) ──────────────────────────────────────────────

if [ "$REPORT_FORMAT" = "html" ]; then
    HTML_FILE="${OUTPUT_FILE%.md}.html"
    if command -v pandoc &>/dev/null; then
        pandoc "$OUTPUT_FILE" -o "$HTML_FILE" --standalone --metadata title="Penetration Test Report" 2>/dev/null || {
            echo "Warning: pandoc conversion failed. Markdown report saved."
            echo "  Report: $OUTPUT_FILE"
            exit 0
        }
        echo "Report generated: $HTML_FILE"
    else
        echo "Report generated: $OUTPUT_FILE"
        echo "  (Install pandoc for HTML output: apt install pandoc)"
    fi
else
    echo "Report generated: $OUTPUT_FILE"
fi

WORD_COUNT=$(wc -w < "$OUTPUT_FILE")
echo "  Words: $WORD_COUNT"
echo "  Risk:  $RISK_RATING"
echo "  Findings: $TOTAL_FINDINGS (C:${SEVERITY_CRITICAL} H:${SEVERITY_HIGH} M:${SEVERITY_MEDIUM} L:${SEVERITY_LOW})"

exit 0
