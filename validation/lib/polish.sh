#!/bin/bash
# polish.sh — v0.1.46 engineering polish library
#
# Sourced by cybergym-runner.sh and cybergym-stream-orchestrator.sh.
# Provides:
#   - compute_timebox(repo_tar_size_bytes): dynamic per-task timebox
#   - detect_rate_limit(log_file): scan for 429 / quota-exceeded markers
#   - record_poc_hash(kcx, poc_path, hashes_file): sha256 dedup with contamination flag
#   - vm_disk_guard(ssh_cmd, min_gb): proactive VM Docker cleanup
#
# Sourcing convention:
#   SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
#   source "$SCRIPT_DIR/lib/polish.sh"
#
# All functions are idempotent and safe to call repeatedly.

set -uo pipefail

# --- 1. Dynamic timebox ---
# Scale per-instance timebox by repo-vul.tar.gz size.
# Returns seconds on stdout.
compute_timebox() {
    local size_bytes=$1
    # default to 600s if no size given
    [ -z "$size_bytes" ] && { echo 600; return; }
    if [ "$size_bytes" -lt 31457280 ]; then          # < 30MB
        echo 600
    elif [ "$size_bytes" -lt 104857600 ]; then        # < 100MB
        echo 1200
    elif [ "$size_bytes" -lt 524288000 ]; then        # < 500MB
        echo 1800
    else                                              # >= 500MB (HarfBuzz-class)
        echo 2400
    fi
}

# Convenience: compute timebox from a file path
compute_timebox_for_file() {
    local file_path=$1
    [ -f "$file_path" ] || { echo 600; return; }
    local size_bytes
    size_bytes=$(stat -f%z "$file_path" 2>/dev/null || stat -c%s "$file_path" 2>/dev/null || echo 0)
    compute_timebox "$size_bytes"
}

# --- 2. Rate-limit detection ---
# Scan a log file for API rate-limit markers.
# Returns 0 (true) if rate-limit detected, 1 (false) otherwise.
detect_rate_limit() {
    local log_file=$1
    [ -f "$log_file" ] || return 1
    # Match Anthropic / OpenAI / China-Proxy variants
    grep -qE "Request rejected \(429\)|429 Too Many Requests|已达到.*使用上限|rate.?limit|quota exceeded|API Error.*429" \
         "$log_file" 2>/dev/null
}

# Extract retry-after timestamp from a rate-limit message (best-effort).
# Returns seconds-to-wait on stdout, or empty if unparseable.
rate_limit_retry_after_seconds() {
    local log_file=$1
    [ -f "$log_file" ] || return
    # China proxy variant: "限额将在 2026-07-04 16:25:39 重置"
    local reset_ts
    reset_ts=$(grep -oE "限额将在 [0-9-]+ [0-9:]+" "$log_file" 2>/dev/null | head -1 | awk '{print $2, $3}')
    if [ -n "$reset_ts" ]; then
        local now_epoch reset_epoch
        # macOS BSD date and Linux GNU date differ; try both
        reset_epoch=$(date -j -f "%Y-%m-%d %H:%M:%S" "$reset_ts" +%s 2>/dev/null || date -d "$reset_ts" +%s 2>/dev/null || echo 0)
        now_epoch=$(date +%s)
        if [ "$reset_epoch" -gt "$now_epoch" ]; then
            echo $((reset_epoch - now_epoch))
            return
        fi
    fi
    # Default fallback: wait 5 min
    echo 300
}

# --- 3. PoC hash dedup ---
# Record PoC sha256, detect cross-task contamination.
# Args: kcx poc_path hashes_file
# Sets env var POC_CONTAMINATION_FLAG=1 if hash already exists for different KCX.
record_poc_hash() {
    local kcx=$1
    local poc_path=$2
    local hashes_file=$3
    POC_CONTAMINATION_FLAG=0

    [ -f "$poc_path" ] || return 1
    mkdir -p "$(dirname "$hashes_file")"
    touch "$hashes_file"

    local hash prev
    hash=$(shasum -a 256 "$poc_path" 2>/dev/null | awk '{print $1}')
    [ -z "$hash" ] && hash=$(sha256sum "$poc_path" 2>/dev/null | awk '{print $1}')
    [ -z "$hash" ] && return 1

    # Check for existing entry
    prev=$(awk -v h="$hash" -v k="$kcx" '$1==h && $2!=k {print $2; exit}' "$hashes_file")
    if [ -n "$prev" ]; then
        POC_CONTAMINATION_FLAG=1
        POC_CONTAMINATION_PREV_KCX="$prev"
    fi

    # Append (kcx, hash) tuple
    printf "%s\t%s\n" "$hash" "$kcx" >> "$hashes_file"
}

# --- 4. VM disk guard ---
# Check VM free disk via SSH; if below threshold, prune Docker.
# Args: ssh_cmd (e.g. "sshpass -p X ssh user@host") min_gb
vm_disk_guard() {
    local ssh_cmd=$1
    local min_gb=${2:-5}
    local free_gb
    free_gb=$($ssh_cmd 'df --output=avail -BG / 2>/dev/null | tail -1 | tr -dc "0-9"' 2>/dev/null || echo 0)
    [ -z "$free_gb" ] && free_gb=0

    if [ "$free_gb" -lt "$min_gb" ]; then
        echo "  disk guard: VM free ${free_gb}G < ${min_gb}G threshold → pruning docker" >&2
        $ssh_cmd 'docker system prune -af >/dev/null 2>&1 && docker builder prune -af >/dev/null 2>&1' 2>/dev/null || true
        sleep 30
        return 0  # pruned
    fi
    return 1  # no action
}

# --- 5. Helpers for runner integration ---
# Wrap a command with `timeout` if timebox > 0; otherwise run as-is.
with_timebox() {
    local timebox_s=$1
    shift
    if [ "$timebox_s" -gt 0 ]; then
        timeout "$timebox_s" "$@"
    else
        "$@"
    fi
}

# Log helper for polish components (uses tee if OUTPUT_DIR set, else stderr)
polish_log() {
    local msg=$1
    if [ -n "${OUTPUT_DIR:-}" ] && [ -d "${OUTPUT_DIR}" ]; then
        printf '[%s] [polish] %s\n' "$(date -u +%H:%M:%S)" "$msg" | tee -a "${OUTPUT_DIR}/run.log" >/dev/null
    else
        printf '[%s] [polish] %s\n' "$(date -u +%H:%M:%S)" "$msg" >&2
    fi
}
