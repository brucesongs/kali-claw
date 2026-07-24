#!/bin/bash
# cybergym-download-all-data.sh — Phase 0 数据准备脚本
#
# 下载 v0.1.47.1 完整测试所需的所有数据：
#   1. cybergym-server-data/ (binary 模式，~130GB)
#   2. 剩余 1408 个实例的任务数据（~292GB）
#
# 注意：需要~450GB 磁盘空间，下载时间可能需要 24+ 小时

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CYBERGYM_ROOT="${CYBERGYM_ROOT:-$HOME/code/cybergym}"

echo "=== v0.1.47.1 Phase 0: 数据准备 ==="
echo ""
echo "⚠️  此脚本将下载大量数据，需要约 450GB 磁盘空间和 24+ 小时"
echo ""

# ===== Step 1: 下载 cybergym-server-data（binary 模式前提）=====
echo "📦 Step 1/2: 下载 cybergym-server-data/（binary 数据，~130GB）"
echo ""

cd "$CYBERGYM_ROOT" || exit 1

if [ -d "cybergym-server-data" ]; then
  echo "✓ cybergym-server-data/ 已存在，跳过下载"
else
  echo "下载 cybergym-server-data.7z from HuggingFace..."
  echo "注: 使用国内镜像 hf-mirror.com"

  # 尝试使用 hf-mirror.com（curl）
  if curl -L -C - -o cybergym-server-data.7z \
       "https://hf-mirror.com/datasets/sunblaze-ucb/cybergym-server-binary/resolve/main/cybergym-server-data.7z" 2>/dev/null; then
    echo "✓ 下载完成"
    echo "解压中..."
    7z x cybergym-server-data.7z || {
      echo "✗ 解压失败，尝试删除部分文件后重试"
      rm -f cybergym-server-data.7z
      exit 1
    }
    echo "✓ 解压完成"

    # 验证
    if [ -d "cybergym-server-data/arvo" ]; then
      count=$(ls -d cybergym-server-data/arvo/*/ 2>/dev/null | wc -l)
      echo "✓ 验证: cybergym-server-data/arvo/ 包含 $count 个实例"
    fi
  else
    echo "✗ 下载失败"
    echo "  尝试其他方式："
    echo "  1. 手动从 HuggingFace 下载: https://huggingface.co/datasets/sunblaze-ucb/cybergym-server-binary"
    echo "  2. 或使用备用镜像: https://hf-mirror.com/datasets/sunblaze-ucb/cybergym-server-binary"
    exit 1
  fi
fi

echo ""

# ===== Step 2: 下载剩余 1408 个实例的任务数据 =====
echo "📦 Step 2/2: 下载剩余 1408 个实例的任务数据（~292GB）"
echo ""

echo "使用 cybergym-download-tasks.py 下载..."
echo "注: 已内置 hf-mirror.com 支持"
echo ""

python3 "$SCRIPT_DIR/gen-full-instance-list.py" \
  --mask-map "$CYBERGYM_ROOT/mask_map.json" \
  --output "$ROOT_DIR/docs/cybergym-full-1508.json" || {
  echo "✗ 生成实例列表失败"
  exit 1
}

echo ""
echo "调用 cybergym-download-tasks.py..."
# 注: 此脚本需要在 cybergym 目录中运行
cd "$CYBERGYM_ROOT" || exit 1

if [ ! -f "validation/cybergym-download-tasks.py" ]; then
  echo "✗ cybergym-download-tasks.py 不存在"
  echo "  应该位于: $CYBERGYM_ROOT/validation/cybergym-download-tasks.py"
  exit 1
fi

# 下载所有实例（使用 4 个 worker 并行）
python3 validation/cybergym-download-tasks.py \
  --mask-map "mask_map.json" \
  --output-dir "cybergym_data/data" \
  --workers 4 || {
  echo "✗ 下载实例数据失败"
  exit 1
}

echo ""
echo "=== Phase 0 完成 ==="
echo ""
echo "✓ 数据准备完毕，可以启动完整测试"
echo ""
echo "启动测试命令:"
echo ""
echo "  CYBERGYM_ROOT=$CYBERGYM_ROOT \\"
echo "  BINARY_DIR=$CYBERGYM_ROOT/cybergym-server-data \\"
echo "  ENABLE_SKILL_OPTIMIZER=false \\"
echo "  OUTPUT_DIR=$ROOT_DIR/validation/evidence/cybergym/v0.1.47.1 \\"
echo "  bash $SCRIPT_DIR/cybergym-stream-orchestrator.sh \\"
echo "    --instances $ROOT_DIR/docs/cybergym-full-1508.json \\"
echo "    --resume"
echo ""
