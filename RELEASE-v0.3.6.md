# kali-claw v0.3.6 版本说明 — 第 4 次月度审查 + 死链清偿 🧹

> **版本编号**：v0.3.6（patch release）
> **发布日期**：2026 年 11 月 9 日
> **版本类型**：月度质量审查（逾期补做）+ R3-1 死链清零 + 手册重建 + 工作区清理
> **上一版本**：v0.3.5（2026-09-09，全量验证与完整性排序）
> **下一里程碑**：Bottom 技术孪生加深（P2 遗留）+ 验证器沉淀（P3 遗留）→ 目标 2026-12

---

## 一、版本概述

补做第 4 次月度审查（原定 2026-10-05，逾期 5 周），以 v0.3.5 排名报告为基线。审查确认**仓库无回归**；同版本清偿 v0.3.5 遗留的 R3-1 死链（5 → 0）、清理工作区两个 zip、并以可复跑脚本重建陈旧的 SKILL_HANDBOOK / SKILL_INDEX。

## 二、月度审查结果

| 检查 | 结果 |
|------|------|
| skill-lint | **139/139, 0 errors / 0 warnings**（无回归）✅ |
| validate-payloads / validate-testcases | 0 errors / 0 errors ✅ |
| TC 总量 | 1,841（v0.2.7 期 1,779 → 净增 62）|
| pqi 稳定性（pqc-implementation-attack，9 周）| ✅ 稳定（创建后仅 2 次内容 commit）|
| v0.2.4 双子 | ✅ 稳定 |
| GitHub Issues/PRs | ⚠️ 执行环境不通 github.com，未核验 |

详见 [chronicle/2026-11/v0.3.6-monthly-review-2026-11-09.md](chronicle/2026-11/v0.3.6-monthly-review-2026-11-09.md)。

## 三、死链清偿（R3-1 → 0）

| 技能 | 处置 | 新链活性 |
|------|------|---------|
| 5g-telecom-attack ×2 | Osmocom gitea 路径迁移 → `cellular-infrastructure/` 组路径（payloads + playbook + TC 共 3 处文件）| 200 ✅ |
| blockchain-l2-attack | Hermez trusted-setup-mpc 仓库消失 → archived-mirror 说明 + Polygon zkEVM 官方文档 + 保留链上校验 | 200 ✅ |
| embedded-rtos-security | mbedcloud EOL → 标注历史签名 + Arm Pelion 现行产品页 | 200 ✅ |
| hypervisor-introspection | bluepill 双死链 → canonical blog 镜像 + Black Hat 2006 论文 PDF | 200 ✅ |

## 四、手册与索引重建

新增 `validation/gen-skill-handbook.py`（frontmatter 为权威源；支持 `--check` drift gate）：

- `docs/SKILL_HANDBOOK.md`：v0.2.0.8 手写快照（137 技能 / 全部 "uncategorized"）→ 自动生成 **139 技能 / 83 域分组 / 1,928 行**
- `docs/SKILL_INDEX.json`：metadata 陈旧（v0.3.0）→ 全量重建并标注生成来源

## 五、工作区清理

- 删除 `skills.zip`（tracked 9MB 二进制快照，git 历史即快照，冗余且污染 diff）
- 删除 `skills/5g-6g-telecom-attack-advanced.zip`（untracked，含 `__MACOSX/` 垃圾）
- 均经 `trash` 可恢复

## 六、验证

| 检查 | 结果 |
|------|------|
| skill-lint（全量 + 4 个修改技能）| 139/139, 0/0 ✅ |
| 死链旧 URL 残留 grep | 0（唯一命中为刻意保留的 `historical signature` 注释）|
| 新链活性 curl | 5/5 全部 200 ✅ |
| `gen-skill-handbook.py --check` | OK / OK（无 drift）✅ |

## 七、后续规划

| 优先级 | 任务 | 预估 | 触发条件 |
|-------|------|------|---------|
| P1 | Bottom 技术孪生加深（data-loss-prevention-bypass / edge-computing-security）| ~2h | 2026-12 前 |
| P2 | `/tmp/validate-all.py` 沉淀为 `validation/check-skill-usability.py` + 白名单扩充 | ~1h | 下次月度审查前 |
| P3 | 域分类归并（83 → ~20，消除单技能域碎片）| ~2h | 下次 minor |
| Q4 | 季度工具基线 2026-12 | ~4h | 2026-12 |
| 定期 | 第 5 次月度审查 | ≤2h | 2026-12-07 |

## 八、版本签名

```
版本编号：v0.3.6
发布日期：2026-11-09
版本类型：第 4 次月度审查 + 死链清偿 + 手册重建 + 工作区清理
上一版本：v0.3.5
skill-lint：0/0/139（保持）
死链：R3-1 5 → 0（新链 5/5 活性 200）
手册：139 技能 / 83 域，自动生成（gen-skill-handbook.py --check 可复跑）
删除：skills.zip + skills/5g-6g-telecom-attack-advanced.zip（trash 可恢复）
```

**kali-claw 团队**
**2026 年 11 月 9 日**
