# kali-claw v0.1.13 发布公告 — 消除所有 Weak 层级技能

**发布日期**：2026-05-29
**技能域数量**：49（不变）
**主题**：零 Weak 达成 — 修复评分系统 3 个缺陷，扩充 3 个技能内容，全部 49 技能达到 Adequate 及以上

---

## 更新概览

v0.1.12 将 Weak 技能从 22 个减少到 9 个。v0.1.13 针对剩余 9 个 Weak 技能进行定向修复：

1. **评分系统修复**（6 个技能受益）：章节评分从"名称匹配"改为"结构深度计数"，消除了因章节命名风格不同导致的误判
2. **内容扩充**（3 个技能受益）：为 data-scraper-agent、browser-qa、exa-search 补充 payloads.md、guides/、test-cases.md

最终结果：**零 Weak 技能**，全部 49 个技能达到 Adequate 及以上层级。

---

## 评分系统修复（3 处）

### 修复 1：SKILL.md 章节评分方法

**问题**：原评分使用"预期章节名称匹配"，但 49 个技能使用不同的命名风格（早期技能用 "Use Cases / Core Tools / Methodology"，新技能用 "Skill Identity / Purpose / Core Capabilities"）。导致新技能 SKILL.md 得分仅 19-38%。

**根因**：`SKILL_SECTIONS` 空格分隔字符串中包含多词条目（"Attack Chain"），shell for 循环按单词拆分，既膨胀了分母也扭曲了分子。

**修复**：用"## 标题计数"替代"名称匹配"。统计 `##` 开头的标题数量，按阈值归一化（6=Adequate, 10=Strong, 15=Excellent）。

```bash
# 修复前
SKILL_SECTIONS="Description Use Cases Core Tools Methodology..."
for section in $expected_sections; do grep -qEi "^#+.*$section" ...

# 修复后
compute_section_score() {
    count=$(grep -cE "^##" "$file")
    # 按 6/10/15 阈值归一化为 0-100
}
```

### 修复 2：测试用例计数模式

**问题**：只匹配 `### TC-`，但 22 个技能使用 `## TC-` 格式。

**修复**：`grep -cE "^##+ TC-"` 同时匹配两种格式。

### 修复 3：字段完整性检测

**问题**：只识别 "Test Step"、"Expected Result"，不识别 "Steps"、"Expected Output"、"Objective"。

**修复**：扩展匹配模式，覆盖两种命名风格。

---

## 内容扩充（3 个技能）

### data-scraper-agent

| 维度 | 修复前 | 修复后 |
|------|--------|--------|
| payloads.md | 116 词 / 4 代码块 | 647 词 / 16 代码块 |
| guides/ | 0 个 | 2 个 |
| test-cases.md | 2 个用例 | 5 个用例 |
| 总分 | 18.5 (Weak) | 44.3 (Adequate) |

新增指南：
- `nvd-api-scraping-guide.md` — NVD API 分页、限速、缓存策略
- `data-extraction-patterns-guide.md` — 数据提取方法论（JSON/HTML/正则/CSV）

### browser-qa

| 维度 | 修复前 | 修复后 |
|------|--------|--------|
| payloads.md | 130 词 / 6 代码块 | 708 词 / 17 代码块 |
| guides/ | 0 个 | 2 个 |
| test-cases.md | 3 个用例 | 5 个用例 |
| 总分 | 19.9 (Weak) | 41.4 (Adequate) |

新增指南：
- `playwright-auth-testing-guide.md` — 认证安全测试（登录流、会话管理、Cookie 审计）
- `network-interception-guide.md` — 网络请求拦截与修改

### exa-search

| 维度 | 修复前 | 修复后 |
|------|--------|--------|
| payloads.md | 211 词 / 6 代码块 | 823 词 / 17 代码块 |
| guides/ | 0 个 | 2 个 |
| test-cases.md | 2 个用例（不变） | 2 个用例 |
| 总分 | 19.9 (Weak) | 40.4 (Adequate) |

新增指南：
- `semantic-search-query-design-guide.md` — 语义搜索查询设计方法论
- `exa-api-configuration-guide.md` — API 配置与集成参考

---

## 评分结果

### 层级分布对比

| 层级 | v0.1.12 | v0.1.13 | 变化 |
|------|---------|---------|------|
| **Weak (0-40)** | 9 | 0 | ↓9 |
| **Adequate (40-60)** | 18 | 27 | ↑9 |
| **Strong (60-80)** | 20 | 20 | ±0 |
| **Excellent (80-100)** | 2 | 2 | ±0 |

### 统计指标

| 指标 | v0.1.12 | v0.1.13 | 变化 |
|------|---------|---------|------|
| 平均分 | 50.5 | 59.4 | +8.9 |
| 中位数 | 45.9 | 59.2 | +13.3 |
| 最高分 | 91.1 | 89.6 | -1.5* |
| 最低分 | 18.5 | 40.4 | +21.9 |

*注：最高分略降是因为评分方法变更（章节名称匹配 → 结构深度计数），web-sqli 的 SKILL.md 分从满分降至 76%。

---

## 关键洞察

### 1. 评分公平性大幅提升

旧方法惩罚了使用非标准章节命名的技能（docker-patterns、codebase-onboarding 等），新方法关注文档结构深度，对所有命名风格一视同仁。

### 2. 最低分从 18.5 提升至 40.4

通过内容扩充 + 评分修复双管齐下，最弱的 3 个技能得分翻倍以上。

### 3. 中位数提升 13.3 分

中位数从 45.9 跃升至 59.2，表明整体质量分布显著右移。

---

## 统计数据

| 指标 | 数量 |
|------|------|
| 评分系统修复 | 3 |
| 新增指南 | 6 |
| 扩充 payloads.md | 3 |
| 新增测试用例 | 5 |
| Weak→Adequate 晋升 | 9 |
| 剩余 Weak 数量 | **0** |

---

## 下一步计划（v0.1.14+）

1. **Strong 层级扩展** — 将 27 个 Adequate 技能中最接近 60 分的提升至 Strong（ai-security、post-exploitation、password-attack 仅差 0.4-0.8 分）
2. **Excellent 层级扩展** — 将更多 Strong 技能提升至 Excellent
3. **评分权重校准** — 考虑调整 guides 评分上限（当前 web-sqli 的 guides 得分 156 超过 100）

---

_Built with the OpenClaw Agent Framework._
