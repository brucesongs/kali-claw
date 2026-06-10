#!/bin/bash
# tool-selector.sh — Target-to-tool mapping engine
# Maps target type and phase to recommended tools and commands.
# Usage: bash validation/tool-selector.sh [options]
#   --target-type <type>  Target type: web|cloud|network|mobile|api (default: web)
#   --phase <phase>       Kill chain phase (recon|scan|enum|vuln|exploit|postexp)
#   --stealth             Prefer stealth/low-noise tools
#   --format <fmt>        Output format: markdown|json|commands (default: markdown)
#   --list-types          List all supported target types
#   --help                Show this help

set -euo pipefail

TARGET_TYPE="web"
PHASE=""
STEALTH=false
FORMAT="markdown"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target-type) TARGET_TYPE="$2"; shift 2 ;;
        --phase) PHASE="$2"; shift 2 ;;
        --stealth) STEALTH=true; shift ;;
        --format) FORMAT="$2"; shift 2 ;;
        --list-types) echo "Supported: web cloud network mobile api"; exit 0 ;;
        --help) echo "Usage: bash validation/tool-selector.sh --target-type <type> [--phase <phase>] [--stealth] [--format <fmt>]"; exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# ── Tool lookup (bash 3 compatible — no associative arrays) ────────────

get_tools() {
    local phase="$1"
    local type="$2"
    local key="${phase}_${type}"
    case "$key" in
        recon_web)      echo "subfinder amass whatweb theHarvester metagoofil waybackurls gau httpx" ;;
        recon_cloud)    echo "subfinder amass whatweb theHarvester cloudlist s3scanner dnsrecon" ;;
        recon_network)  echo "nmap masscan rustscan arp-scan fping naabu" ;;
        recon_mobile)   echo "apkleak mobfs jadx apktool frida" ;;
        recon_api)      echo "httpx ffuf kiterunner arjun whatweb postman" ;;
        scan_web)       echo "nmap nuclei nikto wpscan testssl whatweb" ;;
        scan_cloud)     echo "nmap nuclei scoutSuite pmapper cloudsploit" ;;
        scan_network)   echo "nmap masscan rustscan nuclei zmap" ;;
        scan_mobile)    echo "frida objection drozer mobfs qark" ;;
        scan_api)       echo "nuclei ffuf burpsuite postman kiterunner arjun" ;;
        enum_web)       echo "gobuster ffuf feroxbuster dirsearch nikto wpscan" ;;
        enum_cloud)     echo "awscli azcli gcloud pacu cloudfox" ;;
        enum_network)   echo "enum4linux smbclient rpcclient ldapsearch snmpwalk" ;;
        enum_mobile)    echo "frida objection drozer apktool jadx" ;;
        enum_api)       echo "ffuf arjun kiterunner postman burpsuite" ;;
        vuln_web)       echo "sqlmap burpsuite dalfox xsser commix nuclei nikto" ;;
        vuln_cloud)     echo "nuclei pmapper cloudsploit scoutSuite prowler" ;;
        vuln_network)   echo "nuclei nmap openvas nessus nikto" ;;
        vuln_mobile)    echo "frida drozer mobfs qark supersploit" ;;
        vuln_api)       echo "sqlmap burpsuite ffuf arjun nuclei" ;;
        exploit_web)    echo "sqlmap metasploit burpsuite commix weevely" ;;
        exploit_cloud)  echo "metasploit pacu pmapper awscli" ;;
        exploit_network) echo "metasploit crackmapexec impacket responder" ;;
        exploit_mobile) echo "frida objection drozer supersploit" ;;
        exploit_api)    echo "sqlmap burpsuite postman httpie" ;;
        postexp_web)    echo "metasploit chisel ligolo socat" ;;
        postexp_cloud)  echo "metasploit pacu pmapper cloudfox" ;;
        postexp_network) echo "metasploit crackmapexec mimikatz chisel linpeas winpeas" ;;
        postexp_mobile) echo "frida objection termux" ;;
        postexp_api)    echo "httpie curl postman" ;;
        *)              echo "" ;;
    esac
}

get_skills() {
    local type="$1"
    case "$type" in
        web)     echo "web-xss web-sqli web-auth-bypass web-access-control web-ssrf" ;;
        cloud)   echo "cloud-security container-security api-security supply-chain-security" ;;
        network) echo "network-pentest password-attack post-exploitation" ;;
        mobile)  echo "mobile-security binary-reverse" ;;
        api)     echo "api-security web-auth-bypass web-access-control" ;;
        *)       echo "" ;;
    esac
}

get_command() {
    local tool="$1"
    local stealth="$2"
    # Stealth variants
    if [ "$stealth" = true ]; then
        case "$tool" in
            nmap)    echo "nmap -sS -T2 -f -D RND:10 <target>" ;;
            masscan) echo "masscan --rate=100 <target>" ;;
            nuclei)  echo "nuclei -rl 50 -c 5 -u <target>" ;;
            sqlmap)  echo "sqlmap --delay=3 --random-agent -u <target>" ;;
            hydra)   echo "hydra -t 2 -w 30 <target>" ;;
            *)       echo "$tool <target>" ;;
        esac
        return
    fi
    # Normal variants
    case "$tool" in
        nmap)      echo "nmap -sV -sC -T4 -p- <target>" ;;
        masscan)   echo "masscan --rate=10000 <target>" ;;
        nuclei)    echo "nuclei -c 25 -bs 50 -u <target>" ;;
        subfinder) echo "subfinder -d <target> -all -v" ;;
        amass)     echo "amass enum -d <target>" ;;
        nikto)     echo "nikto -h <target>" ;;
        sqlmap)    echo "sqlmap -u <target> --batch --dbs" ;;
        ffuf)      echo "ffuf -u <target>/FUZZ -w /usr/share/wordlists/dirb/common.txt" ;;
        gobuster)  echo "gobuster dir -u <target> -w /usr/share/wordlists/dirb/common.txt" ;;
        hydra)     echo "hydra -l admin -P /usr/share/wordlists/rockyou.txt <target> http-post-form" ;;
        *)         echo "$tool <target>" ;;
    esac
}

# ── Output formatters ───────────────────────────────────────────────────

output_markdown() {
    echo "# Tool Selection Report"
    echo ""
    echo "## Target Type: $TARGET_TYPE"
    echo ""
    echo "## Recommended Skills"
    echo ""
    for skill in $(get_skills "$TARGET_TYPE"); do
        echo "- \`$skill\`"
    done
    echo ""

    if [ -n "$PHASE" ]; then
        local tools
        tools=$(get_tools "$PHASE" "$TARGET_TYPE")
        echo "## Phase: $PHASE"
        echo ""
        echo "| Tool | Command Template |"
        echo "|------|-----------------|"
        for tool in $tools; do
            local cmd
            cmd=$(get_command "$tool" "$STEALTH")
            echo "| $tool | \`$cmd\` |"
        done
        echo ""
    else
        echo "## All Phases"
        echo ""
        for phase in recon scan enum vuln exploit postexp; do
            local tools
            tools=$(get_tools "$phase" "$TARGET_TYPE")
            echo "### $phase"
            echo ""
            echo "| Tool | Command Template |"
            echo "|------|-----------------|"
            for tool in $tools; do
                local cmd
                cmd=$(get_command "$tool" "$STEALTH")
                echo "| $tool | \`$cmd\` |"
            done
            echo ""
        done
    fi
}

output_json() {
    echo "{"
    echo "  \"target_type\": \"$TARGET_TYPE\","
    echo "  \"stealth\": $STEALTH,"
    echo "  \"skills\": ["
    local first=true
    for skill in $(get_skills "$TARGET_TYPE"); do
        [ "$first" = true ] && first=false || echo ","
        printf '    "%s"' "$skill"
    done
    echo ""
    echo "  ],"

    if [ -n "$PHASE" ]; then
        local tools
        tools=$(get_tools "$PHASE" "$TARGET_TYPE")
        echo "  \"phase\": \"$PHASE\","
        echo "  \"tools\": ["
        local first=true
        for tool in $tools; do
            [ "$first" = true ] && first=false || echo ","
            local cmd
            cmd=$(get_command "$tool" "$STEALTH")
            printf '    {"name": "%s", "command": "%s"}' "$tool" "$cmd"
        done
        echo ""
        echo "  ]"
    else
        echo "  \"phases\": {"
        local first_phase=true
        for phase in recon scan enum vuln exploit postexp; do
            [ "$first_phase" = true ] && first_phase=false || echo ","
            local tools
            tools=$(get_tools "$phase" "$TARGET_TYPE")
            echo "    \"$phase\": ["
            local first=true
            for tool in $tools; do
                [ "$first" = true ] && first=false || echo ","
                local cmd
                cmd=$(get_command "$tool" "$STEALTH")
                printf '      {"name": "%s", "command": "%s"}' "$tool" "$cmd"
            done
            echo ""
            printf '    ]'
        done
        echo ""
        echo "  }"
    fi

    echo "}"
}

output_commands() {
    if [ -n "$PHASE" ]; then
        local tools
        tools=$(get_tools "$PHASE" "$TARGET_TYPE")
        for tool in $tools; do
            local cmd
            cmd=$(get_command "$tool" "$STEALTH")
            echo "# $tool"
            echo "$cmd"
            echo ""
        done
    else
        for phase in recon scan enum vuln exploit postexp; do
            local tools
            tools=$(get_tools "$phase" "$TARGET_TYPE")
            echo "# === Phase: $phase ==="
            for tool in $tools; do
                local cmd
                cmd=$(get_command "$tool" "$STEALTH")
                echo "$cmd"
            done
            echo ""
        done
    fi
}

# ── Main output ─────────────────────────────────────────────────────────

case "$FORMAT" in
    markdown) output_markdown ;;
    json)     output_json ;;
    commands) output_commands ;;
    *)        echo "Unknown format: $FORMAT (use: markdown, json, commands)"; exit 1 ;;
esac
