#!/bin/bash
# cybergym-skill-optimizer.sh — v0.1.47.1 实时技能优化钩子
#
# 在 CyberGym 测试失败后分析失败原因，推荐技能改进
#
# 使用:
#   bash validation/cybergym-skill-optimizer.sh \
#     --trace <trace.json> \
#     --agent-log <agent.log> \
#     --kali-root <kali-claw-root> \
#     --kcx <instance-id>
#
# 输出: 失败分析报告 + 改进建议记录

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# 参数
TRACE_FILE=""
AGENT_LOG=""
KALI_ROOT="$ROOT_DIR"
INSTANCE_ID=""
VERBOSE=${VERBOSE:-false}

# 参数解析
while [[ $# -gt 0 ]]; do
  case "$1" in
    --trace) TRACE_FILE="$2"; shift 2 ;;
    --agent-log) AGENT_LOG="$2"; shift 2 ;;
    --kali-root) KALI_ROOT="$2"; shift 2 ;;
    --kcx) INSTANCE_ID="$2"; shift 2 ;;
    --verbose) VERBOSE=true; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

# 验证必需参数
if [ ! -f "$TRACE_FILE" ]; then
  echo "✗ trace file not found: $TRACE_FILE" >&2
  exit 1
fi

if [ ! -f "$AGENT_LOG" ]; then
  echo "✗ agent log not found: $AGENT_LOG" >&2
  exit 1
fi

# ===== 分析失败 =====
BUG_CLASS=$(jq -r '.bug_class // "unknown"' "$TRACE_FILE")
FAIL_STAGE=$(jq -r '.fail_stage // "unknown"' "$TRACE_FILE")
FAIL_REASON=$(jq -r '.fail_reason // "unknown"' "$TRACE_FILE")
CVE_ID=$(jq -r '.cve_id // "unknown"' "$TRACE_FILE")
PROJECT=$(jq -r '.project // "unknown"' "$TRACE_FILE")

OPTIMIZER_LOG="${TRACE_FILE%.trace.json}.optimizer.log"

log() {
  echo "[$(date -u +%H:%M:%S)] $*" | tee -a "$OPTIMIZER_LOG"
}

log "=== Skill Optimizer Report ==="
log "Instance: $INSTANCE_ID"
log "Bug Class: $BUG_CLASS"
log "CVE: $CVE_ID"
log "Project: $PROJECT"
log "Fail Stage: $FAIL_STAGE"
log "Fail Reason: $FAIL_REASON"

# ===== 仅对特定失败类型进行优化分析 =====
# 跳过基础设施失败（docker pull, timeout 等）
if [[ "$FAIL_REASON" == "docker"* ]] || [[ "$FAIL_REASON" == "timeout"* ]] || [[ "$FAIL_REASON" == "server response unparsable"* ]]; then
  log "ℹ skip optimizer: infrastructure failure, not skill-related"
  exit 0
fi

# 跳过 gen_task 失败（数据问题）
if [ "$FAIL_STAGE" = "gen_task" ]; then
  log "ℹ skip optimizer: gen_task failed (data issue, not skill-related)"
  exit 0
fi

# ===== 关键失败：agent 启动但无 PoC =====
if [ "$FAIL_REASON" = "not-started" ] || [ "$FAIL_STAGE" = "init" ]; then
  log "⚠ agent initiated but no PoC generated"

  # 检查 agent 是否给出了错误信息
  if [ -f "$AGENT_LOG" ]; then
    log ""
    log "Agent log (last 30 lines):"
    tail -30 "$AGENT_LOG" | sed 's/^/  /'
  fi

  # 映射 bug_class → 相关技能
  case "$BUG_CLASS" in
    concurrency)
      log ""
      log "📌 Recommended skill improvement:"
      log "  Skill: concurrency-exploitation"
      log "  Issue: Agent may need more TOCTOU/race condition patterns"
      log "  Action: Review skills/concurrency-exploitation/payloads.md"
      log "  Files to check:"
      log "    - skills/concurrency-exploitation/SKILL.md"
      log "    - skills/concurrency-exploitation/payloads.md"
      ;;
    injection)
      log ""
      log "📌 Recommended skill improvement:"
      log "  Skill: command-injection-advanced"
      log "  Issue: Agent may need more injection bypass techniques"
      log "  Action: Review skills/command-injection-advanced/payloads.md"
      log "  Files to check:"
      log "    - skills/command-injection-advanced/SKILL.md"
      log "    - skills/command-injection-advanced/payloads.md"
      ;;
    protocol_bug)
      log ""
      log "📌 Recommended skill improvement:"
      log "  Skill: protocol-state-exploitation"
      log "  Issue: Agent may need more protocol state machine patterns"
      log "  Action: Review skills/protocol-state-exploitation/payloads.md"
      log "  Files to check:"
      log "    - skills/protocol-state-exploitation/SKILL.md"
      log "    - skills/protocol-state-exploitation/payloads.md"
      ;;
    memory_corruption|integer_overflow|type_confusion)
      log ""
      log "📌 Recommended skill improvement:"
      log "  Skill: patch-to-poc-pipeline"
      log "  Issue: Agent may need better PoC generation from patches"
      log "  Action: Review skills/patch-to-poc-pipeline/"
      log "  Files to check:"
      log "    - skills/patch-to-poc-pipeline/SKILL.md"
      log "    - skills/patch-to-poc-pipeline/payloads.md"
      ;;
    *)
      log ""
      log "📌 Generic recommendation:"
      log "  Issue: No specific skill matched for bug_class=$BUG_CLASS"
      log "  Action: Manually review agent.log for errors"
      ;;
  esac

  log ""
  log "💡 Next steps (manual for v0.1.47.1):"
  log "  1. Review agent.log above for specific errors"
  log "  2. Edit the recommended skill file (payloads.md)"
  log "  3. Add patterns/payloads that match the CVE vulnerability"
  log "  4. Rerun this instance to verify improvement"

  if [ "$VERBOSE" = true ]; then
    log ""
    log "Full agent.log:"
    cat "$AGENT_LOG" | sed 's/^/  /'
  fi
else
  log "ℹ fail_reason not eligible for skill optimization: $FAIL_REASON"
fi

log ""
log "=== End Optimizer Report ==="
