# kali-claw 持续维护路线图

> **规划日期**：2026-08-06（替代原 v0.2.1 版本，原 Track 2 xAgent 内容已转移）
> **当前版本**：v0.2.3（skill-lint 0 errors / 0 warnings，137/137 clean pass）
> **维护节奏**：月度质量审查 + 季度工具基线 + 年度战略评估
> **仓库定位**：kali-claw 是 **专注的 SKILL 库维护者**（single-responsibility）

---

## 一、维护定位

**kali-claw** 是基于 OpenClaw 框架构建的 AI 渗透测试智能体工作空间，覆盖 **137 个安全技能域**，掌握 Kali Linux 2025-2 全部 518 款安全工具。

经过 Phase 1 全量构建（v0.1.x → v0.2.1，2026-03 ~ 2026-07）和 Phase 2 Track 1 月度质量审查（v0.2.2 / v0.2.3，2026-08），仓库已达到**稳定维护状态**：

- 137/137 SKILL 通过严格化 linter 检查（0 errors, 0 warnings）
- Defense Triple 三件套结构性 100% 合规（122 严格匹配 + 15 显式豁免）
- 翻译残留清零；frontmatter 100% 合规；自动化工具链成熟

**单一职责**：维护好这 137 个 SKILL，使其持续反映现代攻击技术、防御检测规则、和 Kali 工具生态的最新状态。

> **Note on xAgent (2026-08-06)**：早期版本的 PHASE2_ROADMAP 包含 "Track 2: xAgent 项目启动" 章节，规划将 SKILL 转化为可交付 agent。该工作已**转移到独立仓库**另行维护。本仓库不再承担 agent runtime / rcogo 集成 / 多 agent 协作等工程工作。历史 RELEASE / CHANGELOG / chronicle 中的 xAgent 引用保留作为时间快照。

---

## 二、维护节奏

| 周期 | 任务 | 工具 | 预估工时 |
|------|------|------|---------|
| **月度** | SKILL 质量审查 | `skill-lint.py` + `validate-payloads.py` + `validate-testcases.py` | ≤2h |
| **季度** | 工具版本基线更新 | 扫描 SKILL → 查询 Kali 版本 → 更新 `KALI_TOOLS_BASELINE_*.md` | 4h |
| **半年** | Defense Triple 完整性审计 | 全量 `skill-lint.py --json` + 内容质量抽样 | 8h |
| **年度** | 战略评估 + 新域规划 | 市场分析 + 新 SKILL 候选评估 | 16h |

### 月度审查 SOP

1. 运行 `python3 validation/skill-lint.py --json > /tmp/lint-YYYY-MM-DD.json`
2. 检查 `summary`：errors 必须 0；warnings 目标 0
3. 如有 INFO 级 finding 升级或降级，评估是否需要规则调整
4. 抽样审查 5 个 SKILL 的 Defense Perspective 内容质量（不只是结构存在）
5. 处理 GitHub Issues / PR（如有）
6. 写 chronicle 记录（`chronicle/YYYY-MM/skill-review-YYYY-MM-DD.md`）
7. 不发布新版本号（除非有非平凡变更）

### 季度工具基线更新 SOP

1. 扫描 137 SKILL 中引用的工具列表
2. 查询 Kali Linux 当前版本（`apt show <tool>` 或官网）
3. 对比 `KALI_TOOLS_BASELINE_2026_07.md`，标记版本漂移
4. 更新基线文件并发布 `RELEASE-vX.Y.Z.md`
5. 同步更新相关 SKILL 的 `last_reviewed` 字段

---

## 三、2026-Q3 / Q4 计划

### 月度质量审查

| 日期 | 内容 | 预估 |
|------|------|------|
| 2026-09-05 | 第 1 次月度审查（v0.2.3 后首次） | ≤2h |
| 2026-10-05 | 第 2 次月度审查 + Q4 工具基线 | 6h |
| 2026-11-05 | 第 3 次月度审查 | ≤2h |
| 2026-12-05 | 第 4 次月度审查 + 年度战略评估 | 18h |

### 季度工具基线

| 季度 | 任务 | 备注 |
|------|------|------|
| 2026-Q4 (10 月) | 更新 `KALI_TOOLS_BASELINE_2026_07.md` → `2026_10.md` | 首次季度更新 |
| 2027-Q1 (1 月) | 季度更新 + 半年 Defense Triple 审计 | 半年节点 |

### 年度战略评估

- **2026-12**：评估是否需要新增 SKILL 域（基于市场变化、新攻击技术、新合规要求）
- 候选评估方向：
  - AI 安全法规（EU AI Act、NIST AI RMF）
  - 5G/6G 攻击演进
  - 量子安全迁移最新进展
  - 新型 side-channel 攻击向量

---

## 四、关键工具与流程

### 自动化校验脚本（`validation/`）

| 脚本 | 用途 | 触发频率 |
|------|------|---------|
| `skill-lint.py` | SKILL.md 质量检查（YAML / sections / Defense Triple / 翻译残留） | 月度 |
| `validate-payloads.py` | Payloads 内容验证 | 季度 |
| `validate-testcases.py` | Test cases 结构验证 | 季度 |
| `update-skill-standard.py` | 单 SKILL 标准对齐 | 按需 |
| `auto-backup.sh` | 仓库备份 | 每次修改前 |
| `drift-detect.sh` | 配置漂移检测 | 季度 |
| `heartbeat.sh` | 工作区健康检查 | 月度 |

### CI/CD（GitHub Actions）

- `.github/workflows/skill-quality.yml`
  - **Lint job**：skill-lint + validate-payloads + validate-testcases（每个 PR 必跑）
  - **Score job**：SCORE.sh + batch-improve + quality gate
  - PR 检查：lint 通过 + score 不退化

### 文档体系

| 文档 | 用途 |
|------|------|
| `CLAUDE.md` | 开发指南（项目结构 + 编辑规范） |
| `docs/SKILL_HANDBOOK.md` | 137 SKILL 完整使用手册 |
| `docs/SKILL_MAINTENANCE.md` | SKILL 创建 / 更新 / FAQ |
| `docs/QUICK_REFERENCE.md` | 速查表（29 个渗透场景） |
| `docs/SKILL_INDEX.json` | 机器可读 SKILL 索引 |
| `MEMORY.md` | 长期决策记录 |
| `chronicle/YYYY-MM/*.md` | 月度事件记录 |

---

## 五、成功指标

### 月度审查通过标准

- [ ] `skill-lint` errors = 0
- [ ] `skill-lint` warnings = 0（允许 INFO 级 finding）
- [ ] 文档与实际 SKILL 库一致（VERSION / README / CLAUDE / AGENTS）
- [ ] GitHub Issues 响应 < 48h（如有）

### 季度工具基线完成标准

- [ ] 所有 137 SKILL 中引用的工具已核对版本
- [ ] `KALI_TOOLS_BASELINE_*.md` 更新并发布
- [ ] 重大版本变更（如 nmap 7.9x → 8.0x）有 RELEASE 说明

### 年度战略评估产出

- [ ] 新 SKILL 候选清单（基于市场调研）
- [ ] 老 SKILL 退役评估（如有过时域）
- [ ] 下一年度维护节奏调整（如需要）

---

## 六、风险与对策

| 风险 | 概率 | 影响 | 对策 |
|------|------|------|------|
| Kali Linux 重大版本升级（如 2026.4 → 2027.1）破坏工具引用 | 中 | 中 | 季度基线更新时统一核对；保留旧 baseline 文件作为参考 |
| Linter 规则演进引入误报 | 低 | 低 | 通过 INFO 级 finding + `defense_triple_required` 等字段保持弹性 |
| SKILL 内容老化（攻击技术演进） | 中 | 中 | 半年 Defense Triple 审计时抽样核对前 20 个高频 SKILL 的时效性 |
| 仓库增长导致克隆/CI 变慢 | 低 | 低 | 已经从 v0.1.x 时代的 3.7GB 降到 v0.2.x 的 ~50MB；持续监控 |
| 单一维护者精力波动 | 中 | 低 | 月度审查工时严格控制在 ≤2h；自动化优先 |

---

## 七、立即行动项

### 下次月度审查（2026-09-05）

```
□ 运行 skill-lint + validate-payloads + validate-testcases
□ 抽样审查 5 个 SKILL Defense Perspective 内容质量
□ 检查 GitHub Issues（如有）
□ 写 chronicle/2026-09/skill-review-2026-09-05.md
□ 不发布新版本（除非有非平凡变更）
```

### 季度准备（2026-10）

```
□ 扫描 137 SKILL 中所有工具引用
□ 查询 Kali Linux 2026.4 版本工具列表
□ 对比 KALI_TOOLS_BASELINE_2026_07.md
□ 更新基线 + 发布 RELEASE-vX.Y.Z.md
```

---

**规划日期**：2026-08-06
**下次审查**：2026-09-05
**维护模式**：轻量级月度审查 + 季度工具基线 + 年度战略评估
