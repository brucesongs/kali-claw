#!/bin/bash

# SQLi-Labs 自动化学习脚本
# 用法: ./sqli-labs-auto.sh [start_lesson] [end_lesson]

START=${1:-1}
END=${2:-65}
BASE_URL="http://localhost/sqli-labs"

echo "=== SQLi-Labs 自动化学习 ==="
echo "范围: Less-$START 到 Less-$END"
echo "开始时间: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

for i in $(seq $START $END); do
  echo "--- Testing Less-$i ---"
  
  # 检查关卡是否存在
  HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/Less-$i/")
  
  if [ "$HTTP_CODE" = "200" ]; then
    # 获取关卡标题
    TITLE=$(curl -s "$BASE_URL/Less-$i/" | grep -o "title>.*</title" | cut -d'>' -f2 | sed 's/<\/title//')
    echo "标题: $TITLE"
    
    # 测试常见注入点
    # GET 注入测试
    RESPONSE=$(curl -s "$BASE_URL/Less-$i/?id=1'" 2>&1)
    if echo "$RESPONSE" | grep -qi "error\|syntax\|mysql"; then
      echo "✓ GET 注入点可能存在"
    fi
    
    # POST 注入测试
    RESPONSE=$(curl -s -X POST "$BASE_URL/Less-$i/" -d "uname=test'&passwd=test&submit=Submit" 2>&1)
    if echo "$RESPONSE" | grep -qi "error\|syntax\|mysql"; then
      echo "✓ POST 注入点可能存在"
    fi
    
    echo ""
  else
    echo "✗ 关卡不存在或无法访问 (HTTP $HTTP_CODE)"
  fi
  
  sleep 0.5
done

echo "=== 学习完成 ==="
echo "结束时间: $(date '+%Y-%m-%d %H:%M:%S')"
