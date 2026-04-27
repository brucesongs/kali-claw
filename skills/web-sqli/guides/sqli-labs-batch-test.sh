#!/bin/bash

# SQLi-Labs 快速批量测试脚本
# 用途: 快速识别关卡注入类型
# 时间: 2026-03-25 06:22

BASE_URL="http://localhost/sqli-labs"
LOG_FILE="/home/parallels/.openclaw/workspace/memory/sqli-labs-scan-$(date +%Y%m%d-%H%M%S).log"

echo "=== SQLi-Labs 快速扫描 ===" | tee "$LOG_FILE"
echo "开始时间: $(date '+%Y-%m-%d %H:%M:%S')" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# 批量测试 GET 注入
for i in {21..30}; do
  echo "=== Less-$i ===" | tee -a "$LOG_FILE"
  
  # 获取标题
  TITLE=$(curl -s "$BASE_URL/Less-$i/" 2>/dev/null | grep -o "title>.*</title" | cut -d'>' -f2 | sed 's/<\/title//')
  echo "标题: $TITLE" | tee -a "$LOG_FILE"
  
  # 测试 GET 注入
  RESPONSE=$(curl -s "$BASE_URL/Less-$i/?id=1'" 2>&1)
  if echo "$RESPONSE" | grep -qi "error\|syntax\|mysql"; then
    echo "✓ GET 注入点存在" | tee -a "$LOG_FILE"
  fi
  
  # 测试 POST 注入
  RESPONSE=$(curl -s -X POST "$BASE_URL/Less-$i/" -d "uname=test'&passwd=test&submit=Submit" 2>&1)
  if echo "$RESPONSE" | grep -qi "error\|syntax\|mysql"; then
    echo "✓ POST 注入点存在" | tee -a "$LOG_FILE"
  fi
  
  # 测试 Cookie 注入
  RESPONSE=$(curl -s "$BASE_URL/Less-$i/" -b "uname=test'" 2>&1)
  if echo "$RESPONSE" | grep -qi "error\|syntax\|mysql"; then
    echo "✓ Cookie 注入点存在" | tee -a "$LOG_FILE"
  fi
  
  echo "" | tee -a "$LOG_FILE"
  sleep 0.3
done

echo "=== 扫描完成 ===" | tee -a "$LOG_FILE"
echo "结束时间: $(date '+%Y-%m-%d %H:%M:%S')" | tee -a "$LOG_FILE"
