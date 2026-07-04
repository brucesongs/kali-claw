#!/bin/bash
# cybergym-stream-orchestrator.sh — stream pull-run-delete for full 30-instance calibration
#
# For each instance:
#   1. SSH to VM, pull+tag image if not present (skip if already tagged)
#   2. Run kali-claw via cybergym-runner.sh (handles gen_task + claude + submit)
#   3. After completion, delete the image to free disk (UNLESS instance is in KEEP_LIST)
#
# Usage:
#   bash validation/cybergym-stream-orchestrator.sh [--start-from <KCX>]
#
# Output: validation/evidence/cybergym/v0.1.45/traces/<KCX>.* (per instance)
#         /tmp/cybergym-stream.log (orchestrator log)

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
INSTANCES_FILE="${INSTANCES_FILE:-$ROOT_DIR/docs/cybergym-sampling-v0.1.45.json}"
RUNNER="$SCRIPT_DIR/cybergym-runner.sh"
ORCH_LOG=/tmp/cybergym-stream.log
SSH="sshpass -p secmind.cn ssh -o StrictHostKeyChecking=no parallels@10.211.55.5"
MIRROR="docker.1ms.run"
CYBERGYM_ROOT="${CYBERGYM_ROOT:-$HOME/code/cybergym}"

# v0.1.46: source polish library (vm_disk_guard, detect_rate_limit, etc.)
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib/polish.sh"

# v0.1.46: KEEP_LIST empty by default (all images stream — lesson from v0.1.45.1 §9.1)
KEEP_LIST="${KEEP_LIST:-}"
# v0.1.46: rate-limit auto-retry cap
MAX_RATE_LIMIT_RETRIES="${MAX_RATE_LIMIT_RETRIES:-3}"

# optional flags
START_FROM=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --start-from) START_FROM="$2"; shift 2 ;;
        --instances) INSTANCES_FILE="$2"; shift 2 ;;
        --keep) KEEP_LIST="$2"; shift 2 ;;
        *) echo "unknown: $1" >&2; exit 2 ;;
    esac
done

olog() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$ORCH_LOG"; }

olog "=== stream orchestrator start ==="
olog "instances file: $INSTANCES_FILE"
olog "keep list (no delete): ${KEEP_LIST:-(empty, all stream)}"
[ -n "$START_FROM" ] && olog "starting from: $START_FROM"

# get all kali_claw_ids in JSON insertion order (M1-M8, I1-I4, T1-T3, P1-P5, PR1-PR4, C1-C2, IN1-IN4)
KC_IDS=$(jq -r '.instances[].kali_claw_id' "$INSTANCES_FILE")
STARTED=$([ -z "$START_FROM" ] && echo true || echo false)

TOTAL=$(echo "$KC_IDS" | wc -l | tr -d ' ')
COUNT=0
PASS_COUNT=0
FAIL_COUNT=0

for kcx in $KC_IDS; do
    COUNT=$((COUNT + 1))

    # skip until we hit START_FROM
    if [ "$STARTED" = "false" ]; then
        if [ "$kcx" = "$START_FROM" ]; then
            STARTED=true
        else
            olog "[$COUNT/$TOTAL] $kcx: skip (before start-from $START_FROM)"
            continue
        fi
    fi

    # v0.1.46: VM disk guard — proactively prune if free < 5GB
    if vm_disk_guard "$SSH" 5 2>/dev/null; then
        olog "  [polish] VM disk guard: pruned docker (was < 5GB free)"
    fi

    # get arvo id
    arvo_id=$(jq -r --arg k "$kcx" '.instances[] | select(.kali_claw_id == $k) | .cybergym_instance_id' "$INSTANCES_FILE")
    arvo_num=${arvo_id#arvo:}
    olog "[$COUNT/$TOTAL] $kcx → $arvo_id"

    # check if trace already shows PASS (skip whole cycle)
    trace="$ROOT_DIR/validation/evidence/cybergym/v0.1.45/traces/${kcx}.trace.json"
    if [ -f "$trace" ]; then
        prev_verdict=$(jq -r '.verdict // ""' "$trace" 2>/dev/null || echo "")
        if [ "$prev_verdict" = "PASS" ]; then
            olog "  ✓ already PASS, skip"
            PASS_COUNT=$((PASS_COUNT + 1))
            continue
        fi
    fi

    # STEP 1: ensure image present + tagged on VM
    is_kept=$(echo " $KEEP_LIST " | grep -q " $kcx " && echo yes || echo no)
    olog "  image: ensure $arvo_num-vul on VM (kept=$is_kept)"
    # Use docker image inspect (canonical, no shell quoting issues, clean exit code)
    img_present=$($SSH "docker image inspect n132/arvo:${arvo_num}-vul >/dev/null 2>&1 && echo yes || echo no" 2>/dev/null | tr -d '\n')
    if [ "$img_present" != "yes" ]; then
        olog "  pulling $MIRROR/n132/arvo:${arvo_num}-vul..."
        pull_start=$(date +%s)
        pull_log=$($SSH "docker pull $MIRROR/n132/arvo:${arvo_num}-vul && docker tag $MIRROR/n132/arvo:${arvo_num}-vul n132/arvo:${arvo_num}-vul" 2>&1)
        pull_status=$?
        pull_elapsed=$(($(date +%s) - pull_start))
        if [ $pull_status -ne 0 ]; then
            olog "  ✗ pull FAILED (${pull_elapsed}s):"
            echo "$pull_log" | tail -5 | sed 's/^/    /' | tee -a "$ORCH_LOG" >/dev/null
            # cleanup partial
            $SSH "docker rmi $MIRROR/n132/arvo:${arvo_num}-vul 2>/dev/null; docker system prune -f 2>/dev/null >/dev/null"
            FAIL_COUNT=$((FAIL_COUNT + 1))
            continue
        fi
        olog "  ✓ pulled in ${pull_elapsed}s"
    else
        olog "  ✓ image already present"
    fi

    # STEP 2: run kali-claw via runner (with v0.1.46 rate-limit auto-retry)
    olog "  running kali-claw..."
    run_start=$(date +%s)
    CYBERGYM_ROOT="$CYBERGYM_ROOT" bash "$RUNNER" -k "$kcx" >> "$ORCH_LOG" 2>&1

    # v0.1.46: rate-limit auto-retry
    retry_count=0
    while [ $retry_count -lt "$MAX_RATE_LIMIT_RETRIES" ]; do
        # agent.log path matches runner convention
        agent_log="$ROOT_DIR/validation/evidence/cybergym/v0.1.45/traces/${kcx}.task/agent.log"
        # also check v0.1.46 path
        [ ! -f "$agent_log" ] && agent_log="$ROOT_DIR/validation/evidence/cybergym/v0.1.46/traces/${kcx}.task/agent.log"
        if [ -f "$agent_log" ] && detect_rate_limit "$agent_log"; then
            retry_after=$(rate_limit_retry_after_seconds "$agent_log")
            retry_count=$((retry_count + 1))
            olog "  ⚠ rate-limit hit (attempt $retry_count/$MAX_RATE_LIMIT_RETRIES), waiting ${retry_after}s then retry..."
            sleep "$retry_after"
            CYBERGYM_ROOT="$CYBERGYM_ROOT" bash "$RUNNER" -k "$kcx" >> "$ORCH_LOG" 2>&1
        else
            break
        fi
    done

    run_elapsed=$(($(date +%s) - run_start))
    olog "  runner done in ${run_elapsed}s"

    # check verdict
    if [ -f "$trace" ]; then
        verdict=$(jq -r '.verdict // "UNKNOWN"' "$trace" 2>/dev/null)
        olog "  verdict: $verdict"
        [ "$verdict" = "PASS" ] && PASS_COUNT=$((PASS_COUNT + 1)) || FAIL_COUNT=$((FAIL_COUNT + 1))
    else
        olog "  ⚠ no trace.json after runner"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi

    # STEP 3: cleanup image if not in keep list
    if [ "$is_kept" = "no" ]; then
        olog "  cleanup: docker rmi n132/arvo:${arvo_num}-vul"
        $SSH "docker rmi n132/arvo:${arvo_num}-vul $MIRROR/n132/arvo:${arvo_num}-vul 2>/dev/null; docker system prune -f 2>/dev/null >/dev/null"
    else
        olog "  cleanup: skip (in keep list)"
    fi

    olog "  running totals: PASS=$PASS_COUNT FAIL=$FAIL_COUNT of $COUNT processed"
done

olog "=== orchestrator done ==="
olog "FINAL: PASS=$PASS_COUNT FAIL=$FAIL_COUNT TOTAL_RUN=$((PASS_COUNT + FAIL_COUNT)) of $TOTAL"
olog "summary: $ROOT_DIR/validation/evidence/cybergym/v0.1.45/summary.json (regenerate with: bash $RUNNER --stub-only-summary 2>/dev/null, or manual jq)"
