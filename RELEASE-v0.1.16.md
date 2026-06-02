# kali-claw v0.1.16 发布公告 — 基础加固 + 评分 v2 + 5 条跨技能攻击链

**发布日期**：2026-06-02
**技能域数量**：49（不变）
**主题**：评分系统 v2（消除膨胀、指南质量复合指标、Distinguished 层级），核心文件全面同步到 49 域，5 个跨技能复合攻击链场景设计

---

## 更新概览

v0.1.15 达成 49/49 Excellent 均分 88.6。v0.1.16 是一次从"量"到"质"的转型——修复评分系统的结构性缺陷、同步所有核心文件到真实状态、设计跨技能联动场景为实战做准备：

1. **评分系统 v2**：所有组件分数上限 100（消除膨胀），指南质量从文件计数升级为复合指标（文件 40% + 字数 30% + 关键段落 30%），新增 Distinguished 层级（92+）
2. **核心文件同步**：CLAUDE.md（25→49 域）、IDENTITY.md（30→49 行）、TOOLS.md（20→49 分类）全部更新
3. **缺失基础设施补齐**：创建 TEMPLATE.md、docs/tools/full-inventory.md、bak/ 目录
4. **构建残留清理**：删除 5 个 `__pycache__` 目录
5. **HEARTBEAT.md 增强**：新增核心文件一致性检查和 `__pycache__` 残留检测
6. **5 条跨技能攻击链**：企业外网、云环境、社工+内网、移动端、紫队防御

---

## 评分系统 v2 详解

### 三项核心改进

| 改进 | v1 | v2 |
|------|----|----|
| 分数膨胀 | 组件分可达 125.7（council） | 所有组件分硬上限 100 |
| 指南指标 | 仅计文件数量 | 复合：文件数(40%) + 平均字数(30%) + 关键段落实备率(30%) |
| 层级体系 | Excellent (80-100) | Excellent (80-91.9) + Distinguished (92-100) |

### 指南质量复合指标（v2 新增）

| 子指标 | 权重 | 衡量内容 |
|--------|------|----------|
| 文件计数 | 40% | 指南文件数量（阈值：0/2/5/8） |
| 平均字数 | 30% | 指南文件平均字数（阈值：0/200/500/1000） |
| 关键段落 | 30% | 是否包含 Introduction、Hands-on/Practice、References |

### 评分公式变化

```
# v1
guide_score = normalize(file_count, 0, 2, 5, 5)  # 仅文件数
overall = skill*0.15 + payload*0.30 + testcase*0.30 + guide*0.25

# v2
guide_score = file_score*0.40 + word_score*0.30 + section_score*0.30  # 复合
payload_component = min(100, avg(word, section, code))  # 封顶
overall = skill*0.15 + payload*0.30 + testcase*0.30 + guide*0.25
```

---

## 核心文件同步（6 文件）

| 文件 | 变更内容 |
|------|----------|
| `CLAUDE.md` | "25 security domains" → "49" |
| `IDENTITY.md` | 技能标签表 30→49 行，新增 21 个缺失域（api-security, cloud-security, container-security 等） |
| `TOOLS.md` | 分类索引 20→49 行，所有工具状态更新为 Mastered，学习策略重写 |
| `USER.md` | Current Focus 更新为当前阶段 |
| `MEMORY.md` | Current Phase 更新，新增 4 个 follow-ups |
| `HEARTBEAT.md` | 新增 2 项健康检查 |

---

## 新增基础设施

| 文件/目录 | 内容 |
|-----------|------|
| `TEMPLATE.md` | 新 Agent 工作区创建模板（Quick Start + 文件结构 + 自定义示例） |
| `docs/tools/full-inventory.md` | 518 工具完整清单，按 49 个技能域分类 |
| `bak/` | 备份目录（运行时使用） |
| `validation/scenarios/SCEN-001~005.md` | 5 个跨技能复合攻击链场景 |

---

## 跨技能联动场景（5 条攻击链）

| ID | 场景名称 | 技能链 | Kill Chain 阶段 |
|----|----------|--------|----------------|
| SCEN-001 | 企业外网渗透全链路 | recon-osint → network-pentest → web-xss/web-sqli → web-auth-bypass → post-exploitation | 侦察→初始访问→执行→持久化→横向移动 |
| SCEN-002 | 云环境攻击链 | osint → cloud-security → container-security → api-security → supply-chain-security | 侦察→初始访问→提权→容器逃逸→供应链 |
| SCEN-003 | 社工+内网渗透 | social-engineering → social-intelligence → password-attack → network-pentest → digital-forensics | 社工→凭证收割→横向移动→取证分析 |
| SCEN-004 | 移动端攻击链 | wifi-pentest → mobile-security → api-security → crypto-attacks | 无线拦截→应用分析→API 利用→加密破解 |
| SCEN-005 | 紫队防御验证 | vulnerability-assessment → security-review → security-misconfiguration → logging-monitoring → container-security | 评估→检测→加固→监控→验证 |

---

## 评分变化

| 指标 | v0.1.15 (v1) | v0.1.16 (v2) | 变化 | 说明 |
|------|-------------|-------------|------|------|
| 平均分 | 88.6 | **86.1** | -2.5 | 更准确（去除膨胀） |
| 最低分 | 85.3 | **80.1** | -5.2 | 暴露真实短板 |
| 最高分 | 99.7 | **90.1** | -9.6 | 膨胀消除 |
| 中位数 | 88.3 | **86.6** | -1.7 | 更紧凑 |
| 分数区间 | 14.4 | **10.0** | -4.4 | 区分度更合理 |
| Distinguished | N/A | **0** | — | 新层级，成长空间 |

### 关键洞察

v2 评分系统揭示了 v1 掩盖的问题：

- **council**：从 99.7 降至 87.4（指南分从 80.0 降至 69.7）——虽有很多文件但平均字数低
- **post-exploitation**：最低分 80.1（指南分仅 54.7）——指南质量是最大短板
- **web-sqli**：指南分最高 92.0（24 个文件，平均字数高，关键段落齐全）——质量标杆

---

## Top 5 / Bottom 5（v2）

### Top 5

| 排名 | 技能 | 分数 | 指南分 |
|------|------|------|--------|
| 1 | cloud-security | 90.1 | 83.9 |
| 2 | vulnerability-assessment | 89.3 | 79.0 |
| 3 | article-writing | 89.2 | 76.7 |
| 4 | autonomous-loops | 89.0 | 80.3 |
| 5 | osint | 89.0 | 78.7 |

### Bottom 5

| 排名 | 技能 | 分数 | 指南分 |
|------|------|------|--------|
| 45 | ai-fuzzing | 82.4 | 62.6 |
| 46 | continuous-learning | 81.6 | 80.3 |
| 47 | insecure-design | 82.7 | 68.3 |
| 48 | password-attack | 82.5 | 67.2 |
| 49 | post-exploitation | 80.1 | 54.7 |

---

## 清理与修复

| 项目 | 详情 |
|------|------|
| `__pycache__` 清理 | 删除 5 个目录（chronicle, web-access-control, crypto-attacks, web-sqli, supply-chain-security） |
| 分数膨胀修复 | council 组件分 125.7→93.3，article-writing 105.8→93.3 |
| 悬空引用修复 | bak/、docs/tools/、TEMPLATE.md 引用全部生效 |

---

## 下一步计划（v0.1.17+）

1. **指南深度提升** — 针对指南分 < 70 的技能（post-exploitation、ai-fuzzing 等），扩充指南内容和关键段落，冲击 Distinguished 层级
2. **场景执行验证** — 在授权靶机上执行 SCEN-001~005 攻击链，产出实战报告
3. **实战渗透验证** — 在授权靶机上执行完整攻击链，产出真实渗透报告
4. **AI 驱动的自动化** — 利用 LLM 自动生成 payload 和攻击方案

---

_Built with the OpenClaw Agent Framework._
