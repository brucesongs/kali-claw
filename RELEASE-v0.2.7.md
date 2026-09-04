# kali-claw v0.2.7 版本说明 — 评估项目收尾（Wave 4-7，139/139）🏁

> **版本编号**：v0.2.7（minor-grade patch release）
> **发布日期**：2026 年 9 月 4 日
> **版本类型**：SKILL 评估项目收尾 + 欠账清理 + 第 3 次月度审查
> **上一版本**：v0.2.6（2026-08-29，月度审查）
> **下一里程碑**：v0.3 minor（PQC / Kyber 新 SKILL）— Wave 4-7 门槛已扫清

---

## 一、版本概述

v0.2.7 一次性完成 v0.2.6 遗留的全部三笔账，并将第 3 次月度审查（原定 2026-09-05）并入版本流程：

1. **Wave 4-7 批量评估**：剩余 104 个 SKILL 全部完成 → **评估项目 139/139 闭环**
2. **Frontmatter `mitre:` 批量补齐**（多次延迟的 P1）：45 个 → **139/139 覆盖**
3. **P2 backlog TC 补充**：sase-sse 12→15、vuln-assess 10→15（含机翻残留重写）

**结论**：评估项目闭环，0 回归，仓库维持稳定维护状态。

---

## 二、Wave 4-7 批量评估（104 SKILL）

### 方法

沿用 Wave 3（commit 0b57015）批量模式：自动扫描 D1/D2/D4/D5（lint、URL 数、CVE 数、ATT&CK T-code 数）+ 公式化 D3/D6 评分。无单 SKILL 实战验证。名单 = `skills/` 与已有 `usage-and-assessment.md` 的差集（104 个），按字典序分 4 波各 26 个。

### 评分分布（104 个）

| 等级 | 数量 | 示例 |
|------|------|------|
| Excellent (80-100) | 31 | api-security 71 域内另有 network-pentest、exploit-development 等 |
| Good (70-79) | 47 | — |
| Fair (60-69) | 22 | — |
| Poor (<60) | 4 | — |
| **均分** | **74.4** | Wave 3 均分 79.5（本轮含更多 meta/工具类 SKILL）|

### 每波产出

| Wave | SKILL 数 | P1/P2 closed | Commit |
|------|---------|--------------|--------|
| Wave 4 | 26 | 13 | afa45f3 |
| Wave 5 | 26 | 11 | 9ac60fd |
| Wave 6 | 26 | 9 | 0080997 |
| Wave 7 | 26 | 13 | d6064c5 |
| **合计** | **104** | **46** | 4 commits |

每 SKILL 产出 `guides/usage-and-assessment.md` + `evidence/2026-09-04/{lint.json,summary.md}`（312 个新文件）。

### Findings 应用明细

**P1（0 ATT&CK T-codes）× 37 — 全部新增 5-6 行映射表至 payloads.md**：

| Wave | SKILL（新增映射） |
|------|-------------------|
| Wave 4 | ai-fuzzing, anti-forensics, api-security, binary-reverse, cms-framework-attack, command-injection-advanced, concurrency-exploitation, container-security |
| Wave 5 | council*, crypto-attacks, database-attack, digital-forensics, engagement-manager*, eu-ai-act-compliance-redteam, exploit-development, file-inclusion, firmware-reverse |
| Wave 6 | llm-red-team, mobile-security, network-pentest, osint, pentest-reporting*, protocol-state-exploitation, quantum-cryptography-transition, recon-osint |
| Wave 7 | repo-scan, security-bounty-hunter, security-misconfiguration, security-review*, supply-chain-security, terminal-ops*, tool-mastery*, username-profiling, voip-sip-attack, web-access-control, web-auth-bypass, wifi-pentest |

\* 为 meta 类技能（非豁免），映射表以 "reference mapping" 形式给出（其工作流最常引用的 TTPs）。

**P2（URLs < 5）× 9 — 全部补充权威参考链接**：

5g-6g-telecom-attack-advanced、binary-reverse、chronicle、concurrency-exploitation、continuous-learning、data-loss-prevention-bypass、hardware-side-channel-advanced、quantum-cryptography-transition、voip-sip-attack

**P3 × 69（0 CVEs / TC thin）— 记录为 backlog，不阻塞**。

**豁免处理**：15 个 `defense_triple_required: false` 的非攻击 meta SKILL（article-writing、chronicle 等）不参与 ATT&CK/CVE 类 finding（沿用 Defense Triple 豁免先例），URL/TC 类保留。

---

## 三、mitre Frontmatter 批量补齐（45 个）

| 来源 | 数量 | 说明 |
|------|------|------|
| Wave 4-7 新增映射表派生 | 20 | 取各 SKILL 映射表前 4 个技术 |
| 域内容手工精选 | 10 | steganography（T1001.002）、vpn-attack（T1133）、web-xxe、vulnerability-assessment、ai-security、deep-research、hardware-security、insecure-design、logging-monitoring、sdr-rf-attack |
| 非攻击 meta 标注 | 15 | `"N/A (non-attack meta skill)"` |

Commit：a654a67。格式沿用既有惯例（metadata 块内逗号分隔 `ID-Name` 字符串）。

---

## 四、Test Cases 补充

| SKILL | 之前 | 之后 | 新增类别 |
|-------|------|------|---------|
| sase-sse-attack | 12 | 15 | G：WARP split-tunnel exclusion、Netskope STAgent 凭据重放、IPv6 双栈绕过 |
| vulnerability-assessment | 10 | 15 | F：OpenVAS 认证扫描、WPScan、ssh-audit、Censys/Shodan ASM、pip-audit/npm-audit SCA |

vulnerability-assessment 原有 10 条 TC 同步重写为规范英文（原文本存在严重机翻残留）。Commit：81f868c。

---

## 五、文档清理

| 文件 | 改动 |
|------|------|
| `HEARTBEAT.md` | 计数 130 → 139（第 12 行）|
| `PHASE2_PROGRESS.md` | 顶部加 DEPRECATED 头，指向权威进度来源 |
| `HIGH_PRIORITY_WORKPLAN.md` | 回填 COMPLETED 状态横幅（2026-07-30 完成证据指针）|

Commit：1569818。

---

## 六、验证（第 3 次月度审查，原定 2026-09-05）

| 检查 | 结果 |
|------|------|
| skill-lint | **139/139 pass, 0 errors / 0 warnings**（无回归）|
| validate-payloads | 0 errors（45 条 TODO 类 warning 为存量，本轮新增内容 0 条）|
| validate-testcases | 0 errors, 1779 TCs（sase-sse / vuln-assess 无 warning）|
| `mitre:` 覆盖 | **139/139** |
| usage-and-assessment.md | **139/139** |
| GitHub | 0 open issues / 0 open PRs |
| INFO findings | NO_GUIDES **6 → 0**（Wave 4-7 副产品）|

详见 [chronicle/2026-09/v0.2.7-review-2026-09-04.md](chronicle/2026-09/v0.2.7-review-2026-09-04.md)。

---

## 七、修改文件汇总

| 类别 | 数量 |
|------|------|
| 新增 usage-and-assessment.md | 104 |
| 新增 evidence/2026-09-04/ | 104 组（lint.json + summary.md）|
| payloads.md 追加 ATT&CK/参考章节 | 42 |
| SKILL.md 更新（last_reviewed + mitre）| 87 |
| test-cases.md 重写/扩充 | 2 |
| 文档清理 | 3 |
| 版本同步 | VERSION + 6 个文件 + 本文档 + chronicle |

Commits：afa45f3 / 9ac60fd / 0080997 / d6064c5（Wave 4-7）、a654a67（mitre）、81f868c（TC）、1569818（docs）、本提交（release）。

---

## 八、后续规划

| 优先级 | 任务 | 预估 | 触发条件 |
|-------|------|------|---------|
| **P0** | v0.3 minor: 新 SKILL（PQC / Kyber）| ~8h | 门槛已扫清，可启动 |
| P2 | 69 条 P3 backlog（按域分批处理）| 按需 | 下次 minor 前 |
| Q4 | 季度工具基线 2026-11 | ~4h | 2026-11 |
| 2027-02 | Defense Triple 半年完整性审计 | ~8h | 半年节点 |

---

## 九、版本签名

```
版本编号：v0.2.7
发布日期：2026-09-04
版本类型：评估项目收尾 + 欠账清理 + 月度审查
上一版本：v0.2.6
skill-lint：0/0/139（保持）
新 SKILL：0
评估项目：139/139（100%，闭环）✅
Wave 4-7：104 SKILL 评估 + 46 P1/P2 findings 应用
mitre 覆盖：139/139（+45）
TC 补充：sase-sse 15 / vuln-assess 15
```

**kali-claw 团队**
**2026 年 9 月 4 日**
