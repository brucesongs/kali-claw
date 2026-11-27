# kali-claw v0.3.4 版本说明 — Q4 工具基线提前 🧰

> **版本编号**：v0.3.4（patch release）
> **发布日期**：2026 年 9 月 9 日
> **版本类型**：季度工具基线更新（提前执行，原定 2026-11）+ 漂移检查自动化
> **上一版本**：v0.3.3（2026-09-08，TC 清偿 & backlog 归零）
> **下一里程碑**：第 4 次月度审查（2026-10-05，零 backlog 首查 + pqi 3 周稳定性复查）

---

## 一、版本概述

v0.3.4 把 Q4 季度工具基线提前执行（用户 2026-09-09 确认），产出第三个基线文件并落实 08 基线三大改进项之首——漂移检查自动化脚本。沿用 v0.2.3.1 的**文档型 patch** 先例：SKILL 内容修改最小化（仅 Trivy 行动项处置 3 处），lint 独立可验证。

## 二、2026_09 基线扫描结论（增量口径，~45 工具复查）

| 项 | 结论 |
|----|------|
| **新 MAJOR 跃迁** | **0** —— 安静月份 |
| 上次 6 个 MAJOR 复查 | 全部停留在各自 MAJOR 内（hashcat 7.1.2 / ghidra 12.1.2 / frida 17.24 / docker 29.8 / openssl 4.0.2 / radare2 6.2）；v0.2.4 阶段 A 的兼容修复**全部持续有效，0 回归** |
| MINOR/PATCH 升级 | 11（docker、openssl、burp 2026.9、wireshark/tshark 4.6.9、nuclei 3.16、terraform 1.16、radare2 6.2、frida 17.24、kubectl 1.35、trivy 0.78）|
| 其余 | ~115 rolling/=（nmap 7.99、sqlmap 1.10、ghidra、hashcat 等稳定）|
| 重点观察对象 | ghidra 12.2（预计 Q4 发布）——下次基线首要关注 |

## 三、Trivy 行动项处置（关闭 08 基线遗留）

CVE-2026-33634 供应链事件复查：全仓扫描发现 **3 处 `trivy-action@master` 未固定引用**（container-security guide ×2、repo-scan guide ×1）——正是事件打击的 tag 覆写模式——已处置为固定 release tag `@0.78.2` + SHA 校验注释。无任何受污染 v0.69.4 引用。**行动项关闭**。

## 四、漂移检查自动化（08 改进项 #1 落地）

新建 `validation/check-tool-versions.py`：

- 读最新基线（或 `--baseline` 指定），解析 Top-N 工具表
- **在线模式**（Kali 实机）：`apt-cache policy` + `--version` 探测，逐工具 match/DRIFT 判定
- **离线模式** `--offline`：人工复核清单（任意环境可跑，已在维护机端到端自测）
- `--json`：结构化报告（含 `drift[]` 数组），可直接喂给基线的 MAJOR 行动 SOP

08 基线三大改进项进度：#1 ✅（本版）；#2（Kali release notes 对齐）→ 下次基线；#3（SKILL frontmatter tool_versions）→ 年度评估定夺。

## 五、修改文件

| 文件 | 改动 |
|------|------|
| `KALI_TOOLS_BASELINE_2026_09.md` | 新建（十节结构镜像 08；头部声明提前 Q4；diff 锚点 = 08）|
| `validation/check-tool-versions.py` | 新建（自动化漂移检查）|
| `skills/container-security/guides/...` + `skills/repo-scan/guides/...` | 3 处 trivy-action 固定版本 |
| 版本同步 | VERSION + CHANGELOG / UPDATELOG / README / AGENTS / CLAUDE / MEMORY |

Commits：5e8b0f0（基线 + Trivy 处置）/ 7b33013（自动化脚本）/ 本提交（release）。

## 六、验证

| 检查 | 结果 |
|------|------|
| skill-lint | 139/139, 0/0（SKILL 修改最小化，无回归）|
| check-tool-versions.py | 离线/在线/JSON 三模式端到端通过（27 工具解析，token 清洗正确）|
| Diff 摘要一致性 | 摘要计数 = 表行实际计数（0 MAJOR / 11 MINOR / 其余 =）|
| trivy-action@master 残留 | 0 |

## 七、后续规划

| 优先级 | 任务 | 预估 | 触发条件 |
|-------|------|------|---------|
| P1 | 第 4 次月度审查 + pqi 3 周稳定性复查 | ≤2h | 2026-10-05 |
| P2 | 下次基线（2026-12，Q4 末）：用新脚本实机跑 + 对齐 Kali release notes | ~2h | 2026-12 |
| P3 | 年度战略评估（新域候选 / 豁免 meta 迁出 / tool_versions 字段定夺）| ~16h | 2026-12 |

## 八、版本签名

```
版本编号：v0.3.4
发布日期：2026-09-09
版本类型：季度工具基线（提前）+ 自动化
上一版本：v0.3.3
skill-lint：0/0/139（保持）
新 MAJOR：0（上次 6 个复查全稳定，0 修复回归）
MINOR/PATCH：11；rolling ~115
Trivy 行动项：关闭（3 处 @master 已固定）
新增脚本：validation/check-tool-versions.py
SKILL 内容修改：3 行（trivy-action pin）
```

**kali-claw 团队**
**2026 年 9 月 9 日**
