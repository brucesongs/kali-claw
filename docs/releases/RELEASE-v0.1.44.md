# kali-claw v0.1.44 发布公告 — 跨域联动 scenario 波：从"专家"到"作战指挥官"

**发布日期**：2026-07-01
**版本号**：v0.1.44（技能域总数 125 不变；新增 1 份 schema 基础设施 + 3 份跨域 scenario）

---

## 这次更新干了啥？

简单说：**把 125 个独立"专家"技能域，串成"作战指挥官"——能像真正的红队那样把侦察、入侵、提权、横移、外发串成完整攻击链**。

v0.1.43 收尾时承诺"v0.1.44 跨域联动 scenario 建设，吸收 MopMonk 三招"。本次交付：

- **1 份 schema 基础设施**：`SCEN-MEMORY-SCHEMA.md`（365 行）
- **3 份跨域 scenario**：
  - `SCEN-006.md`：Structured Memory-Driven Pentest（465 行）
  - `SCEN-007.md`：Shared-Memory Multi-Agent Exploit Dev（505 行）
  - `SCEN-008.md`：Patch-Diff Vulnerability Reproduction（424 行）

**总计 1759 行新文档**，全部围绕 MopMonk Agent 三招工程模式重新组织 kali-claw 的工作流。

---

## MopMonk 三招 × kali-claw 落地

2026-06-30 调研的 MopMonk Agent（CyberGym 73.1%，中国第 1）核心三招是 Agent runtime 工程模式，与基座模型无关。v0.1.44 把这三招固化进 kali-claw 的工作流：

### 招一 — 结构化记忆（Structured Memory）

**问题**：kali-claw 之前的 `MEMORY.md` 是人类可读的散文，对 Agent 不友好——Agent 无法快速查询"我对 X 的当前了解是什么？"。

**解法**：定义了 3 套 JSON schema：
- **Schema 1**：Pentest Engagement Memory（用于 SCEN-006）
- **Schema 2**：Exploit Attempt Memory（用于 SCEN-007，共享）
- **Schema 3**：Patch-Diff Reproduction Memory（用于 SCEN-008）

每套 schema 包含字段：`findings` / `hypotheses` / `candidate_pocs` / `evidence_index` / `next_constraints` / `convergence_state` / `decision_log`。

**关键约束**：每个 phase 必须 READ 当前 memory → 执行任务 → WRITE delta（更新至少一个字段 + 至少一个 `decision_log` 条目）。

### 招二 — 记忆驱动收敛（Memory-Driven Convergence）

**问题**：传统 Agent 挖漏洞是"开放试错"——生成输入、跑、看结果、再生成。容易陷入循环。

**解法**：每个 phase 必须满足**收敛规则**：

```yaml
if action.yielded_new_evidence == false:
    memory.failed_attempts += 1
    if memory.failed_attempts >= path_switch_threshold:
        memory.active_path = pick_next_path(memory.candidate_paths)
        log_decision("switched path after N evidence-free attempts")
```

`SCEN-MEMORY-SCHEMA.md` 显式定义了 5 个 **anti-patterns**（禁止行为）：
1. Free-form exploration（不读 memory 就动手）
2. Memory drift（写散文而不更新字段）
3. Repeat-without-delta（同一假设无证据试 3 次以上）
4. Path-claim deadlock（两个 agent 抢同一路径）
5. Premature stop（没做完差分验证就停）

### 招三 — 共享记忆多 Agent（Shared-Memory Multi-Agent）

**问题**：kali-claw 的 `council` skill 之前是"各 Agent 表态、人工汇总"——没有真正的并行协作。

**解法**：SCEN-007 定义的多 Agent 协议：
- **Agent A — patch-diff 方向**：BinDiff + angr，从补丁反推漏洞点
- **Agent B — harness-entry 方向**：AFL++ + libFuzzer，从崩溃反向定位
- **Agent C — sanitizer 方向**：ASan/UBSan，从运行时检测正推

三个 Agent 共享同一份 `exploit-attempt-memory.json`，使用 POSIX 原子 `mv` + 版本向量协议避免冲突。**收敛事件**：当 2+ Agent 独立指向同一假设（如 `png_read_row() line 412`），自动 promote 到 `CONFIRMED`。

---

## 3 个 Scenario 的核心设计

### SCEN-006 — Structured Memory-Driven Pentest

**做什么**：执行 5-phase 渗透测试（recon → intrusion → privesc → lateral → exfil），每个 phase 强制使用 Schema 1 的 JSON memory。

**skill chain**：`recon-osint → network-pentest → web-sqli → post-exploitation → ad-ldap-attack → data-exfiltration-attack` + `verification-loop` + `engagement-manager`（cross-cutting）

**核心创新**（vs SCEN-001~005）：
- 每个 phase 有显式 "Memory Contract" 子节，给出 before/after JSON 快照
- 每个 phase 有 "Convergence Trigger" 子节，定义什么算"新证据"、什么触发 path switch
- Worked example 展示 memory 从 v0（空）→ v8-12（CONFIRMED 凭证）的完整演化

### SCEN-007 — Shared-Memory Multi-Agent Exploit Dev

**做什么**：3 个并行 Agent 协同发现并验证一个漏洞 PoC。

**skill chain**：`binary-reverse → reverse-engineering-advanced → exploit-development → ai-fuzzing → verification-loop → multi-agent-collaboration` + `council`（periodic sync）

**核心创新**：
- 三路并行探索（patch-diff / harness-entry / sanitizer）
- 文件级多 Agent 同步协议（atomic write + version vector）
- 收敛事件机制（多 Agent 独立抵达同一假设 → 自动 CONFIRMED）
- Worked example：CVE-2019-7317 libpng，t=25min 触发收敛，t=40min PoC 差分验证通过

### SCEN-008 — Patch-Diff Vulnerability Reproduction（CyberGym 风格）

**做什么**：给定补丁，反推漏洞、生成 PoC、差分验证。这是 kali-claw 走向"实弹可量化"的关键第一步。

**skill chain**：`binary-reverse → reverse-engineering-advanced → exploit-development → ai-fuzzing → verification-loop → detection-engineering`

**核心创新**：
- 5-phase 标准化流程（patch analysis → code path walk → PoC generation → differential verify → detection rule authoring）
- Worked example：CVE-2023-4863 libwebp heap buffer overflow（BuildHuffmanTable）
- 产出不仅包含 PoC，还包含 YARA + Sigma 检测规则
- 显式映射 CyberGym 基准任务结构

**战略意义**：这是 kali-claw 从"自评 89.43"进化到"外部基准双校准"的入口。Q3 2026 计划用 50-100 个 CyberGym 实例做 kali-claw 的外部基准校准（详见 `docs/mopmonk-research-and-kali-claw-plan.md` § 5.4）。

---

## 战略意义：从"专家"到"作战指挥官"

至此 kali-claw 的能力栈已经完成三层堆叠：

| 层 | 代表版本 | 内容 |
|---|---|---|
| **第一层：单点专家** | v0.1.1 → v0.1.42 | 125 个独立 skill domain，覆盖全攻击面 |
| **第二层：质量基线** | v0.1.43 | 55 个 Distinguished（44%），全员 Excellent+ |
| **第三层：作战指挥官** | **v0.1.44** | **3 个跨域 scenario + 结构化记忆基础设施** |

**第三层是质变**。前两层解决"会不会"，第三层解决"能不能串起来打赢一场战役"。

具体含义：
- **红队师傅视角**：v0.1.44 之前 kali-claw 是 125 个实习生；v0.1.44 之后，它能像一个有 8 周经验的红队队长那样调度这些实习生
- **防守方视角**：v0.1.44 之前 kali-claw 能告诉你"这个漏洞怎么打"；之后能告诉你"如果对手打你，他们会怎么从 recon 一路串到 exfil，你该在哪一步拦截"
- **平台工程视角**：v0.1.44 之前 kali-claw 是知识库；之后它是 Harness——一个可与任何基座模型配合、有持久记忆、能多 Agent 协作的 runtime

这正是 MopMonk 调研报告核心论点 **"Harness > Parameters"** 在 kali-claw 上的直接落地。

---

## 整体进展（v0.1.43 → v0.1.44）

| 指标 | v0.1.43 | v0.1.44 | 变化 |
|---|---|---|---|
| 技能域总数 | 125 | 125 | — |
| Distinguished | 55 | 55 | — |
| Excellent+ 覆盖率 | 100% | 100% | — |
| 平均分 | 89.43 | 89.43 | — |
| 跨域 scenario | 5（SCEN-001~005） | **8（+SCEN-006/007/008 + MEMORY-SCHEMA）** | **+3 scenario + 1 schema** |
| 结构化 memory schema | 0 | **3**（Schema 1/2/3） | 全新维度 |

**注**：v0.1.44 是工作流升级波，不直接产生 SCORE.sh 分数变化。新增 scenario 文件位于 `validation/scenarios/`，不计入 skill domain 质量分。但其战略价值远大于单一 skill 提升——它定义了 kali-claw 未来所有跨域协作的标准模式。

---

## 详细交付物清单

### 1. `validation/scenarios/SCEN-MEMORY-SCHEMA.md`（365 行）

- 3 套 JSON schema（Pentest / Exploit / Reproduction memory）
- 5 个 anti-patterns（禁止行为清单）
- POSIX atomic write 同步协议
- 与现有 `MEMORY.md` / `chronicle/` 的关系（不替换，并行）
- 完整 worked example

### 2. `validation/scenarios/SCEN-006.md`（465 行）

- Header + Objective + Skill Chain + Prerequisites
- 5 phase × {Commands + Memory Contract before/after + Convergence Trigger}
- Verification Points（5 项）
- Data Handoff（显式 JSON 字段映射）
- 完整 worked example（v0 → v8 memory 演化）
- Defensive Perspective（SOC playbooks）

### 3. `validation/scenarios/SCEN-007.md`（505 行）

- 3 个 agent 角色定义（A/B/C）
- 文件级同步协议（atomic write + version vector）
- 完整 jq 命令模板（atomic write pattern）
- Convergence event 机制（多 Agent 独立指向同一假设 → 自动 promote）
- Worked example：CVE-2019-7317 libpng，t=0 → t=45min 完整时间线

### 4. `validation/scenarios/SCEN-008.md`（424 行）

- 5-phase 标准化流程
- Worked example：CVE-2023-4863 libwebp
- YARA + Sigma 检测规则产出
- CyberGym calibration hook（映射 CyberGym 任务结构）
- Defensive Perspective（compiler flags / SBOM / CodeQL）

---

## 当前跨域 Scenario 全景（8 个）

| ID | 名称 | 类型 | 引入版本 |
|---|---|---|---|
| SCEN-001 | Enterprise External Network Pentest | Attack Chain (Red Team) | v0.1.10 |
| SCEN-002 | Internal Network Pivot | Attack Chain | v0.1.10 |
| SCEN-003 | Web App Full Stack | Attack Chain | v0.1.10 |
| SCEN-004 | Cloud Compromise | Attack Chain | v0.1.10 |
| SCEN-005 | IoT + OT Convergence | Attack Chain | v0.1.10 |
| **SCEN-006** | **Structured Memory-Driven Pentest** | **Memory-Driven** | **v0.1.44** |
| **SCEN-007** | **Shared-Memory Multi-Agent Exploit Dev** | **Multi-Agent** | **v0.1.44** |
| **SCEN-008** | **Patch-Diff Vulnerability Reproduction** | **CyberGym-style** | **v0.1.44** |

加上 `SCEN-MEMORY-SCHEMA.md` 作为基础设施。

---

## 下一步

**v0.1.45（预计 2026-07 中旬）—— Wave 12 扩面 + CyberGym 子集校准**：
- 候选新域：
  - `vuln-reproduction-attack`（CyberGym 方法论固化进知识库）
  - `agent-harness-engineering`（Harness 工程经验系统化）
- CyberGym 校准：从 1,507 实例中选 50-100 个做 kali-claw 外部基准
- 目标：从"自评 89.43"进化到"自评 + 外部基准双校准"

**v0.1.46+**：把 SCEN-006/007/008 真正在 kali-claw 多 Agent 模式下跑通，沉淀运行时数据，迭代 schema。

---

## 总结

v0.1.44 是 kali-claw 的**首波工作流升级波**：

- **3 份跨域 scenario + 1 份 schema 基础设施**（共 1759 行新文档）
- **吸收 MopMonk Agent 三招**：结构化记忆 + 记忆驱动收敛 + 共享记忆多 Agent
- **完成能力栈第三层**：单点专家 → 质量基线 → **作战指挥官**
- **直接落地 "Harness > Parameters" 战略论点**

**关键里程碑**：
1. kali-claw 历史上**首次定义跨域协作的标准模式**
2. **首次出现 CyberGym 风格的实弹校准入口**（SCEN-008）
3. **首次把 MopMonk 三招从"调研发现"变成"工程模式"**

至此 kali-claw 不只是 125 个技能域的集合，而是一个能像真正的红队那样调度的作战系统。下一站 Q3 2026：用 CyberGym 把这个系统跑一遍实弹。
