# kali-claw v0.3.8 版本说明 — 验证器沉淀 + 11 月排名基线 🛠️

> **版本编号**：v0.3.8（patch release）
> **发布日期**：2026 年 11 月 10 日
> **版本类型**：P2 backlog 清偿（/tmp 验证器沉淀）+ 月度审查自动化基线
> **上一版本**：v0.3.7（2026-11-09，Bottom 技术孪生加深）
> **下一里程碑**：P3 域归并（83→~20）→ 季度工具基线 2026-12 → 第 5 次月度审查 2026-12-07

---

## 一、版本概述

v0.3.5 的三轴验证方法论（当时写在 `/tmp/validate-all.py`，已被系统清理）正式沉淀为
`validation/check-skill-usability.py`，并产出 2026-11 全量排名基线。第 5 次月度审查
自此可一条命令复跑。

## 二、新工具：check-skill-usability.py

| 能力 | 说明 |
|------|------|
| **轴 1 完整性** | 六维加权分（lint ×1.0 / 内容量 ×1.0 / bash 块 ×1.5 / 引用 ×0.8 / T-codes ×1.0 / 结构 ×1.2）→ 0-100 |
| **轴 2 可用性** | 占位符感知 bash -n + 结构门（guides≥1 / H2≥12 / TC≥10，豁免 meta 政策沿用）|
| **轴 3 可靠性** | 过时模式 grep（注释剥离防假阳性）+ last_reviewed 新鲜度；`--urls N` 可选活链抽查 |
| **白名单** | 吸收 TOOLS.md 工具表 → 未识别命令 token 降为信息级（U3-1 部分清偿）|
| CLI | `--skill` / `--json` / `--ranking` / `--urls`；exit 0=干净，2=有 findings |

### 相对 v0.3.5 一次性脚本的工程化改进

1. **块级分类**：payload 展示块（gate N/A，79 个）/ 多语言混合块（relabel 候选，179 个）/ 混合散文块（分段多数通过容忍，39 个）与 shell 意图块分离——语法门只作用于真正的 shell 块
2. **注释剥离的过时模式匹配**：修复 `hashcat -O` 跨行假阳性（v0.3.5 报 0 过时是真 0；初版工具曾误报 2）
3. **TC 计数口径对齐**：`## TC-` 与 `### TC-` 双格式（仓库主流为 H3）
4. **可复跑**：`--ranking` 直接产出标准报告（方法论 + 统计 + Top/Bottom + 全表 + findings）

## 三、2026-11 排名基线（docs/SKILL_VALIDATION_RANKING_2026-11-10.md）

| 指标 | 值 | vs 09-09 基线 |
|------|-----|---------------|
| 完整性均分 / 最低 / 最高 | **89.8 / 72.3 / 95.4** | 81.1 / 65 / 92 |
| Excellent / Good / Fair / Poor | **130 / 9 / 0 / 0** | 57 / 76 / 6 / 0 |
| Usability A / B / C | **125 / 1 / 13** | 105 / 6 / 28 |
| Reliability A / B / C（离线）| 62 / 77 / 0 | 131 / 4 / 4 |
| bash 语法错误块（shell 意图）| **16**（13 技能，findings register 列名）| 0 |
| 过时模式 | 0 | 0 |

**口径说明**：均分上移主因是公式固化（分段容忍提升 D3）+ v0.3.7 孪生加深 + TC 计数修正，
报告中已注明 lineage；Reliability B=77 为真实信号——77 个技能 last_reviewed 落后 >90 天
（truth-sync 只覆盖评估文档），列入下次月度审查行动项。

**Top 5**：ai-security / exa-search / reverse-engineering-advanced / vpn-attack（并列 95.4）、
data-loss-prevention-bypass（93.8，v0.3.7 孪生）

## 四、Findings（新发现，入 register）

| 类 | 数量 | 处置 |
|----|------|------|
| F-1 shell 意图块语法残留 | 16 块 / 13 技能（cloud-security、embedded-rtos、hardware-security 各 2，其余各 1）| 下个 patch：围栏 relabel 或修语法 |
| F-2 last_reviewed 落后 >90d | 77 技能 | 下次月度审查 freshness sweep |
| F-3 多语言混合块（relabel 候选）| 179 块（信息级）| 随 F-1 顺手处理 |
| F-4 占位符 marker（>10/技能）| automotive-vehicle-security 15 个 | 信息级，随下次该技能触碰修复 |

## 五、验证

| 检查 | 结果 |
|------|------|
| 全量运行（139 技能，~35s）| 完成，exit=2（有 findings，按设计）✅ |
| 单技能模式 / --json / --ranking | 均正常 ✅ |
| outdated 假阳性修复 | hashcat -O 注释文字 2→0 ✅ |
| skill-lint | 139/139, 0/0（本版本未触碰 skills/）✅ |

## 六、修改文件

| 文件 | 改动 |
|------|------|
| `validation/check-skill-usability.py` | 新增（~470 行三轴验证器）|
| `docs/SKILL_VALIDATION_RANKING_2026-11-10.md` | 新增（240 行全量排名基线）|
| `validation/README.md` | 工具索引更新 |
| 版本同步 | RELEASE + VERSION + CHANGELOG + README/AGENTS/CLAUDE/MEMORY + memory/2026-11-10 |

## 七、后续规划

| 优先级 | 任务 | 预估 | 触发条件 |
|-------|------|------|---------|
| P1 | F-1 语法残留修复（13 技能 16 块）+ F-2 freshness sweep（77 技能）| ~2h | 下个 patch / 月度审查 |
| P3 | 域归并 83 → ~20 | ~2h | 下次 minor |
| Q4 | 季度工具基线 2026-12 | ~4h | 2026-12 |
| 定期 | 第 5 次月度审查（现在 = 1 条命令 + 人工汇总）| ≤1h | 2026-12-07 |

## 八、版本签名

```
版本编号：v0.3.8
发布日期：2026-11-10
版本类型：验证器沉淀 + 排名基线（tooling patch）
上一版本：v0.3.7
skill-lint：0/0/139（保持，未触碰 skills/）
新工具：validation/check-skill-usability.py（三轴 + 白名单 + 报告生成）
新基线：docs/SKILL_VALIDATION_RANKING_2026-11-10.md（均分 89.8，无 Fair/Poor）
新 findings：16 语法残留块（13 技能）/ 77 freshness 落后 / 179 relabel 候选（信息级）
```

**kali-claw 团队**
**2026 年 11 月 10 日**
