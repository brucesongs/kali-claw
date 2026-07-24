# Task 1.2 高优先级 SKILL 改进工作计划

> **创建日期**：2026-07-18 (Saturday)  
> **基础数据**：Task 1.1 BASELINE_AUDIT_DATA.txt + 深度扫描  
> **方向**：Direction B - 全量优化  
> **目标**：15 个 P0/P1 SKILL 完成 95%+ → 优化到 98%+

---

## 📊 实际扫描发现 (vs. 原预期)

### 原预期 vs 实际差距

| 维度 | 原预期 | 实际 | 差距 |
|------|--------|------|------|
| Defense Perspective | 65% 缺失 | 全部存在 (H3 格式) | 工作量大幅减少 |
| payloads.md 数量 | 10+ PoC | 60-103 sections | 已超目标 6-10x |
| test-cases.md 数量 | 5+ tests | 9-22 tests | 已超目标 |
| 整体完成度 | 85% | 90-93% (估算) | 工作量减半 |

### 主要发现

1. **结构已规范**：所有 18 个候选 SKILL 都有完整的 YAML 前言、Summary、Description、Core Tools、Methodology、Practical Steps
2. **Defense Perspective 已存在**：作为 `### Defense Perspective` (H3) 嵌入在 Practical Steps 内
3. **Defense 内容质量分化**：
   - 优秀 (表格化)：web-xss, api-security, web-sqli, web-auth-bypass
   - 良好 (要点化)：network-pentest, post-exploitation
   - 待加强：cloud-security, container-security (检查格式)
4. **关键质量问题**：
   - **翻译残留**：network-pentest 有中英文混排 ("networksegment", "limitationattacker")
   - **辅助 Defense 章节缺失**：部分 SKILL 缺少 `## Detection Methods` 和 `## Defense Evasion Techniques`
   - **版本一致性**：所有 SKILL version=0.1.18，需 bump 到 0.2.0.2 (Phase 1 目标版本)

---

## 🎯 15 个高优先级 SKILL 实际清单

基于实际目录结构（web-security 拆分为 7 子域），选择以下 15 个：

### P0 核心 (3 个)

| 序号 | SKILL | 当前状态 | 主要改进点 | 预估工时 |
|------|-------|---------|-----------|---------|
| 1 | network-pentest | 230 行，翻译残留严重 | 修复中英混排、规范 Defense 表格、添加 2026 工具版本 | 1.5h |
| 2 | post-exploitation | 209 行，格式良好 | 完善 Defense Perspective 表格化、补 Detection Methods | 1h |
| 3 | web-xss | 363 行，表格化优秀 | 添加最新 XSS bypass payloads、bump 版本 | 0.5h |

### P1 重要 (12 个)

| 序号 | SKILL | 当前状态 | 主要改进点 | 预估工时 |
|------|-------|---------|-----------|---------|
| 4 | web-sqli | 260 行，15 guides，16 tests | 添加 2026 SQLi techniques、bump 版本 | 0.5h |
| 5 | web-ssrf | 214 行，格式良好 | 补充 Cloud metadata SSRF 新向量 | 0.5h |
| 6 | web-auth-bypass | 263 行，19 tests | 添加 OAuth/OIDC 攻击向量 | 0.5h |
| 7 | api-security | 264 行，22 tests | 添加 GraphQL/gRPC 2026 新攻击面 | 0.5h |
| 8 | password-attack | 209 行，2013 词 | 更新 hashcat/john 版本、添加新攻击模式 | 0.5h |
| 9 | privilege-escalation | 280 行 | 添加 Linux kernel 2026 LPE、容器逃逸 | 0.5h |
| 10 | social-engineering | 237 行 | 添加 AI-driven phishing/ deepfake vectors | 0.5h |
| 11 | osint | 372 行，最大 | 添加 2026 OSINT 工具、AI-augmented OSINT | 0.5h |
| 12 | cloud-security | 227 行，103 payload sections | 添加 2026 cloud LPE、K8s 新攻击 | 0.5h |
| 13 | container-security | 211 行 | 添加 2026 container escapes | 0.5h |
| 14 | binary-reverse | 285 行 | 添加 AI-assisted RE、新工具版本 | 0.5h |
| 15 | exploit-development | 270 行 | 添加 2026 mitigations bypass | 0.5h |

### 总工时估算

- **P0 (3 SKILLs)**: 3 hours
- **P1 (12 SKILLs)**: 6 hours
- **总计**: 9 hours (远低于原估 25-30h)

---

## 🔧 每日执行计划

### Day 1 (2026-07-20 周一): 修复 P0 + 1 个 P1

| 时段 | SKILL | 工作 |
|------|-------|------|
| 09:00-10:30 | network-pentest | 修复翻译残留 (1.5h) |
| 10:30-11:30 | post-exploitation | 表格化 Defense + Detection (1h) |
| 11:30-12:00 | web-xss | 添加 2026 payloads (0.5h) |
| 14:00-14:30 | web-sqli | 添加 2026 SQLi (0.5h) |
| 14:30-17:00 | **Buffer + 验证** | 验证、运行 lint、commit |

**Day 1 目标**: 4 SKILLs 完成

### Day 2 (2026-07-21 周二): 4 个 P1

| 时段 | SKILL | 工作 |
|------|-------|------|
| 09:00-09:30 | web-ssrf | 0.5h |
| 09:30-10:00 | web-auth-bypass | 0.5h |
| 10:00-10:30 | api-security | 0.5h |
| 10:30-11:00 | password-attack | 0.5h |
| 11:00-12:00 | **验证 + commit** | |
| 14:00-17:00 | **Buffer / 超前完成** | |

**Day 2 目标**: 4 SKILLs 完成 (累计 8)

### Day 3 (2026-07-22 周三): 4 个 P1

| 时段 | SKILL | 工作 |
|------|-------|------|
| 09:00-09:30 | privilege-escalation | 0.5h |
| 09:30-10:00 | social-engineering | 0.5h |
| 10:00-10:30 | osint | 0.5h |
| 10:30-11:00 | cloud-security | 0.5h |
| 11:00-12:00 | **验证 + commit** | |
| 14:00-17:00 | **Buffer** | |

**Day 3 目标**: 4 SKILLs 完成 (累计 12)

### Day 4 (2026-07-23 周四): 最后 3 个 + 整体审查

| 时段 | SKILL | 工作 |
|------|-------|------|
| 09:00-09:30 | container-security | 0.5h |
| 09:30-10:00 | binary-reverse | 0.5h |
| 10:00-10:30 | exploit-development | 0.5h |
| 10:30-12:00 | **15 SKILL 整体审查** | |
| 14:00-16:00 | **修复发现的问题** | |
| 16:00-17:00 | **最终 commit + 准备 Day 5 报告** | |

**Day 4 目标**: 15 SKILLs 全部完成 ✅

### Day 5 (2026-07-24 周五): Phase 1 完成报告 + 启动 Phase 2

| 时段 | 工作 |
|------|------|
| 09:00-10:00 | 生成 P0/P1 SKILL 完成度报告 |
| 10:00-11:00 | 更新 BASELINE_AUDIT_DATA.txt |
| 11:00-12:00 | 准备 Phase 2 (剩余 115 SKILLs) 启动 |
| 14:00-17:00 | **启动 Phase 2 第一批 (10 SKILLs)** |

---

## 📋 单 SKILL 改进 SOP (标准操作程序)

每个 SKILL 按以下步骤：

### Step 1: 阅读当前状态 (5 min)
```bash
cat skills/<skill>/SKILL.md
```

### Step 2: 识别问题 (5 min)
- 翻译残留？
- Defense Perspective 是否表格化？
- Detection Methods 是否存在？
- Defense Evasion Techniques 是否存在？

### Step 3: 应用修复 (20-30 min)
1. **修复翻译**：使用 sed/awk 替换中英混排词
2. **表格化 Defense Perspective**：转换 bullet 为表格
3. **添加 Detection Methods** (若缺)：参考 network-pentest 格式
4. **添加 Defense Evasion Techniques** (若缺)：参考 network-pentest 格式
5. **更新 payloads.md**：添加 2026 新攻击向量
6. **bump version**: 0.1.18 → 0.2.0.2

### Step 4: 验证 (5 min)
```bash
python3 validation/update-skill-standard.py --skill <skill>
```

### Step 5: Commit (5 min)
```bash
git add skills/<skill>/
git commit -m "refactor(<skill>): polish defense perspective and bump to v0.2.0.2

- Standardize Defense Perspective as table
- Add Detection Methods section
- Add Defense Evasion Techniques section
- Update payloads with 2026 attack vectors
- Fix translation residue"
```

---

## ✅ 完成定义 (Definition of Done)

每个 SKILL 必须满足：

- [ ] `## Summary` 存在且 2-3 句
- [ ] `## Core Tools` 至少 5 个工具
- [ ] `## Methodology` 至少 5 步
- [ ] `## Practical Steps` 详细可执行
- [ ] `### Defense Perspective` 表格化 (≥5 防御层)
- [ ] `## Detection Methods` 存在
- [ ] `## Defense Evasion Techniques` 存在
- [ ] `payloads.md` 至少 60 sections
- [ ] `test-cases.md` 至少 8 tests (AAA 格式)
- [ ] YAML `version: "0.2.0.2"`
- [ ] 无中英混排翻译残留
- [ ] 通过 `update-skill-standard.py` 验证

---

## 🎯 整体目标

完成 Task 1.2 Phase 1 (15 SKILLs) 后：

- **15 个高优先级 SKILL**: 完成度 95%+ → **98%+**
- **基线提升**: 整体完成度 92% → 94%+
- **质量提升**: 翻译残留 0、结构一致、Defense 完整
- **版本一致**: 全部 v0.2.0.2 (2026-07)

---

## 📊 风险评估

| 风险 | 概率 | 影响 | 对策 |
|------|------|------|------|
| 翻译残留比预期多 | 中 | 工时增加 50% | 优先处理 P0，P1 按需 |
| Defense 表格化耗时 | 低 | 单 SKILL +15min | 使用模板加速 |
| 工具版本查询困难 | 中 | 部分更新延迟 | 使用 KALI_TOOLS_BASELINE_2026_07.md |
| AI 生成内容质量 | 低 | 需人工 review | 每个 commit 后必验证 |

---

**最后更新**：2026-07-18 08:00 CST  
**下一步**：开始项目 2 SKILL_REMEDIATION_LIST.json
