# Phase 1 快速启动检查清单

> **日期**：2026-07-17  
> **状态**：🚀 就绪启动

---

## ✅ 前置条件检查

- [x] kali-claw 项目结构完整 (skills/, validation/, docs/)
- [x] 130 个 SKILL 已创建
- [x] Anthropic SKILL 标准已应用
- [x] update-skill-standard.py 脚本可用
- [x] 项目 git 状态干净

---

## 🎯 第一步：生成基线审查报告（1-2 天）

### 命令序列

```bash
cd ~/code/kali-claw-en

# 1. 检查当前 SKILL 数和前言完整性
find skills -name "SKILL.md" | wc -l
find skills -name "SKILL.md" -exec grep -l "^---" {} \; | wc -l

# 2. 扫描缺失前言的 SKILL
echo "=== SKILL without frontmatter ==="
for f in skills/*/SKILL.md; do
  if ! head -5 "$f" | grep -q "^---"; then
    dirname "$f" | sed 's/.*\///'
  fi
done

# 3. 统计防御视角完成率
echo "=== Defense Perspective completion ==="
with_defense=$(find skills -name "SKILL.md" -exec grep -l "## Defense Perspective" {} \; | wc -l)
total=$(find skills -name "SKILL.md" | wc -l)
echo "Defense Perspective: $with_defense/$total ($(( with_defense * 100 / total ))%)"

# 4. 统计 payloads.md 和 test-cases.md 完成率
echo "=== Payloads & Test-cases completion ==="
with_payloads=$(find skills -name "payloads.md" | wc -l)
with_testcases=$(find skills -name "test-cases.md" | wc -l)
echo "payloads.md: $with_payloads/$total"
echo "test-cases.md: $with_testcases/$total"

# 5. 生成初步报告
cat > BASELINE_AUDIT.md << 'EOF'
# SKILL 库基线审查报告 (2026-07-17)

## 数据快照

| 指标 | 数值 | 完成度 |
|------|------|--------|
| 总 SKILL 数 | $(find skills -name "SKILL.md" \| wc -l) | 100% |
| 有 YAML 前言 | $(find skills -name "SKILL.md" -exec grep -l "^---" {} \; \| wc -l) | ? |
| 防御视角 | ? | ? |
| payloads.md | ? | ? |
| test-cases.md | ? | ? |

## 缺失项汇总

[自动生成...]

## 优先级修复列表

[自动生成...]
EOF

echo "✓ Baseline audit report generated: BASELINE_AUDIT.md"
```

### 预期输出

```
SKILL 库基线（2026-07-17）:
├─ 总数: 130
├─ 前言完整: 125 (96%)
├─ 防御视角: 85 (65%)  ← 需要补齐
├─ payloads.md: 128 (98%)
├─ test-cases.md: 122 (94%)
└─ 完成度: 85% → 目标 95%+
```

---

## 📋 Task 1.1 工作清单

### Week 1 (7.22-7.26)

- [ ] **7.22 (周一)**
  - [ ] 8:00 - 生成基线审查报告
  - [ ] 10:00 - 统计缺失项 (防御视角、工具版本)
  - [ ] 下午 - 创建修复优先级清单

- [ ] **7.23 (周二)**
  - [ ] 上午 - 审查 Web Security, Network Pentest, Post-Exploitation
  - [ ] 下午 - 标记缺失内容

- [ ] **7.24-7.26 (周三-周五)**
  - [ ] 整合反馈
  - [ ] 最终审查报告
  - [ ] 生成 audit-report.md, missing-items.json, fix-priority.json

### 输出物清单

```
kali-claw-en/
├── BASELINE_AUDIT.md                    # 基线数据
├── AUDIT_REPORT_v1.md                   # 完整审查报告
├── missing-items.json                   # {skill: [missing_fields]}
├── fix-priority.json                    # {skill: {priority, effort, ...}}
└── HIGH_PRIORITY_15_SKILLS.md          # 15 个高优先级 SKILL 清单
```

---

## 🛠️ Task 1.2 工作清单（依赖 1.1）

### Week 2 (7.29-8.02) - P0 SKILL

高优先级 SKILL 补齐（3 个 P0）：

1. **web-security**
   - [ ] 添加/完善防御视角
   - [ ] 补充 XSS/SQLi/SSRF 的最新 Payload
   - [ ] 更新工具版本 (burp-suite, zaproxy)
   - [ ] 规范 test-cases.md

2. **network-pentest**
   - [ ] 同上

3. **post-exploitation**
   - [ ] 同上

### Week 3 (8.05-8.09) - P1 SKILL

继续补齐 P1 SKILL (1-10)：
- [ ] osint
- [ ] password-attack
- [ ] privilege-escalation
- [ ] phishing-social-engineering
- [ ] api-security
- [ ] cloud-security
- [ ] container-security
- [ ] binary-reverse
- [ ] exploit-development
- [ ] payload-generation

### 完成标准

- [ ] 15 个 SKILL 完成度 ≥ 95%
- [ ] 所有防御视角已补齐
- [ ] 所有工具版本更新到 2026-07
- [ ] payloads 和 test-cases 规范化

---

## 🚀 Task 1.3 工作清单（并行执行）

### Week 2-3 新 SKILL 创建（7 个）

- [ ] **iot-security-pentest** (中等)
- [ ] **blockchain-smart-contract-audit** (高)
- [ ] **threat-intelligence-integration** (中等)
- [ ] **malware-reverse-advanced** (高)
- [ ] **red-team-infrastructure** (高)
- [ ] **data-exfiltration-antidlp** (中等)
- [ ] **advanced-post-exploitation** (中等)

### 每个 SKILL 的检查清单

- [ ] SKILL.md 框架完成
  - [ ] YAML 前言完整
  - [ ] Summary (2-3 句)
  - [ ] Core Tools (5+)
  - [ ] Methodology (5-8 步)
  - [ ] Practical Steps 详细
  - [ ] Defense Perspective
  
- [ ] payloads.md (10+ PoC)
- [ ] test-cases.md (5-8 测试)
- [ ] guides/ (可选，推荐)

- [ ] 运行验证：`update-skill-standard.py --skill <name>`
- [ ] Git commit with proper message

---

## 📚 Task 1.4 工作清单（Week 4）

### 文档生成

- [ ] 创建 docs/generators/ 目录
- [ ] **generate-handbook.py** - SKILL 使用手册
- [ ] **generate-quick-ref.py** - 快速参考卡片
- [ ] **generate-matrix.py** - Tools vs SKILL 热力图
- [ ] **generate-index.py** - JSON 索引

### 输出文档

- [ ] docs/SKILL_HANDBOOK.md (完整使用手册)
- [ ] docs/QUICK_REFERENCE.md (速查表)
- [ ] docs/TOOLS_LIFECYCLE.md (工具版本管理)
- [ ] docs/SKILL_INDEX.json (机器可读)
- [ ] docs/DOMAIN_MATRIX.md (覆盖分析)
- [ ] CHANGELOG.md (v0.2.0.2 更新说明)

---

## ⚙️ Task 1.5 工作清单（Week 4-5）

### 脚本开发

- [ ] **validation/skill-lint.py** - SKILL 代码检查
  - [ ] 检查 YAML 前言语法
  - [ ] 验证 markdown 格式
  - [ ] 检查必填字段
  
- [ ] **validation/validate-payloads.py** - Payload 验证
  - [ ] 语法检查
  - [ ] 工具命令有效性
  - [ ] 重复项检测
  
- [ ] **validation/validate-testcases.py** - Test-case 验证
  - [ ] AAA 模式检查
  - [ ] 预期结果明确

### GitHub Actions (可选)

- [ ] .github/workflows/skill-quality.yml
  - [ ] PR 检查
  - [ ] 自动索引生成
  - [ ] 质量报告上传

### 维护指南

- [ ] docs/SKILL_MAINTENANCE.md
  - [ ] SKILL 创建 checklist
  - [ ] 更新流程
  - [ ] 工具版本更新指南
  - [ ] 常见问题 FAQ

---

## 📊 关键数据收集

### 每日报告模板（简化版）

```
=== Phase 1 Daily Report ===
Date: 2026-07-XX
Day: Task 1.2 (补齐 SKILL)

Completed:
- [ ] 3 SKILL 完成度提升到 95%+
- [ ] 防御视角补齐: +5 SKILL
- [ ] Payload 更新: +10 PoC

Blocked:
- [ ] 工具版本信息 (需要 Kali 官方确认)

Next:
- [ ] 继续 P1 SKILL (password-attack)
- [ ] 开始新 SKILL (iot-security)

Velocity: 3 SKILL/day
```

---

## 🎯 成功标志

**Phase 1 完成** 当：

- [x] Task 1.1 完成 - 审查报告 ✓
- [ ] Task 1.2 完成 - 15 SKILL 补齐到 95%
- [ ] Task 1.3 完成 - 7 个新 SKILL 创建
- [ ] Task 1.4 完成 - 6 个文档输出
- [ ] Task 1.5 完成 - CI/CD 自动化

**最终指标**：
- SKILL 总数 ≥ 150
- 完成度 ≥ 95%
- 所有文档输出完成
- 自动化检查可用

---

## 🚀 立即开始

**第一行代码**（现在就可以执行）：

```bash
cd ~/code/kali-claw-en

# Step 1: 生成基线
python3 validation/update-skill-standard.py --stats > baseline.txt
cat baseline.txt

# Step 2: 统计缺失项
echo "=== Scanning SKILL completeness ==="
for dir in skills/*/; do
  skill=$(basename "$dir")
  has_defense=$(grep -l "## Defense Perspective" "$dir/SKILL.md" 2>/dev/null)
  [ -z "$has_defense" ] && echo "Missing: $skill (Defense Perspective)"
done

# Step 3: 创建工作 branch
git checkout -b phase1/skill-audit
git commit --allow-empty -m "chore: start Phase 1 SKILL library audit and enhancement"
git push -u origin phase1/skill-audit

# Step 4: 开始工作
echo "✓ Phase 1 启动完成！"
echo "Next: 运行 BASELINE_AUDIT 脚本"
```

---

**预计启动时间**：2026-07-17 晚间  
**首个 milestone**：2026-07-22 (基线审查报告)  
**完成时间**：2026-08-23 (Phase 1 完成)
