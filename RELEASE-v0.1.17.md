# kali-claw v0.1.17 发布公告 — 底层补强 + Distinguished 冲刺

**发布日期**：2026-06-03
**技能域数量**：49（不变）
**主题**：15 个关键段落修复、5 个底层技能补强（+10 指南）、10 个 Distinguished 候选技能冲刺（+35 指南）、3 个 TC 修复

---

## 更新概览

v0.1.16 建立了评分系统 v2，暴露了指南质量的真实短板。v0.1.17 同时拉高底部和冲击顶部：

1. **关键段落修复**：15 个技能缺失 Introduction / Hands-on / References 段落，全部修复至 3/3
2. **底层 5 技能补强**：post-exploitation、ai-fuzzing、password-attack、insecure-design 各新增 2 个指南；continuous-learning 新增 3 个测试用例
3. **Distinguished 冲刺**：10 个候选技能各新增 3-4 个高质量指南文件（共 35 个新指南），cloud-security 距 Distinguished 仅 0.8 分
4. **分数全面提升**：平均 86.1→87.5，最低 80.1→84.3，0 个指南分 < 70

---

## 关键段落修复（15 个技能）

| 类型 | 技能 | 修复内容 |
|------|------|----------|
| References | verification-loop, council, browser-qa, crypto-attacks, hardware-security, insecure-design, supply-chain-security, web-ssrf | 添加 `## References` 段落 |
| Introduction | container-security, password-attack, safety-guard | 添加 `## Introduction` 段落 |
| Hands-on | codebase-onboarding, web-access-control | 添加 `## Hands-on Exercise` 段落 |
| Introduction + References | ai-fuzzing, post-exploitation | 同时添加两个段落 |

---

## 底层 5 技能补强

| 技能 | v0.1.16 | v0.1.17 | 变化 | 操作 |
|------|---------|---------|------|------|
| post-exploitation | 80.1 | 86.3 | +6.2 | 2 新指南 + 关键段落修复 |
| ai-fuzzing | 82.4 | 88.2 | +5.8 | 2 新指南 + 关键段落修复 |
| continuous-learning | 81.6 | 87.0 | +5.4 | 3 新测试用例 (TC-CL-007~009) |
| insecure-design | 82.7 | 86.4 | +3.7 | 2 新指南 + 关键段落修复 |
| password-attack | 82.5 | 86.1 | +3.6 | 2 新指南 + 关键段落修复 |

### 新增指南文件

| 技能 | 新文件 |
|------|--------|
| post-exploitation | persistence-techniques-guide.md, lateral-movement-practical-guide.md |
| ai-fuzzing | web-api-fuzzing-guide.md, crash-triage-guide.md |
| password-attack | hashcat-rules-guide.md, password-policy-audit-guide.md |
| insecure-design | abuse-case-development-guide.md, secure-design-patterns-guide.md |

---

## Distinguished 冲刺（10 个技能，35 个新指南）

| 技能 | v0.1.16 | v0.1.17 | 变化 | 新文件数 | 指南文件数 |
|------|---------|---------|------|----------|-----------|
| cloud-security | 90.1 | **91.2** | +1.1 | +3 | 8 |
| network-pentest | 88.9 | **90.9** | +2.0 | +3 | 8 |
| article-writing | 89.2 | **90.6** | +1.4 | +3 | 8 |
| vulnerability-assessment | 89.3 | **90.6** | +1.3 | +3 | 8 |
| autonomous-loops | 89.0 | **90.5** | +1.5 | +3 | 8 |
| osint | 89.0 | **90.3** | +1.3 | +3 | 8 |
| social-intelligence | 88.2 | **90.0** | +1.8 | +3 | 8 |
| security-bounty-hunter | 88.4 | **89.7** | +1.3 | +3 | 8 |
| ai-security | 88.1 | **89.2** | +1.1 | +2 | 7 |
| security-misconfiguration | 87.5 | **89.0** | +1.5 | +3 | 8 |

### 新增指南清单

**cloud-security**: aws-pentest-lab-guide, azure-privilege-escalation-guide, cloud-post-exploitation-guide

**network-pentest**: 3 guides (wireless, lateral movement, pivoting)

**article-writing**: pentest-report-template-guide, cve-advisory-writing-guide, security-blog-writing-guide

**vulnerability-assessment**: automated-scanning-pipeline-guide, manual-testing-techniques-guide, risk-rating-methodology-guide

**autonomous-loops**: watch-loop-patterns-guide, batch-processing-guide, error-recovery-guide

**osint**: dark-web-intelligence-guide, corporate-recon-guide, data-aggregation-analysis-guide

**social-intelligence**: 3 guides (social graph, community monitoring, target profiling)

**security-bounty-hunter**: 3 guides (scope recon, PoC development, report writing)

**ai-security**: prompt-injection-lab-guide, ai-red-team-guide (model-extraction-attack-guide already existed at 264 words)

**security-misconfiguration**: cloud-misconfiguration-checklist-guide, web-server-hardening-lab-guide, default-credential-audit-guide

---

## 评分变化

| 指标 | v0.1.16 | v0.1.17 | 变化 |
|------|---------|---------|------|
| 平均分 | 86.1 | **87.5** | +1.4 |
| 最低分 | 80.1 | **84.3** | +4.2 |
| 最高分 | 90.1 | **91.2** | +1.1 |
| 分数区间 | 10.0 | **6.9** | -3.1（更紧凑） |
| 关键段落 < 3/3 | 15 | **0** | 全部修复 |
| 指南分 < 70 | 6 | **0** | 全部消除 |

---

## Top 5 / Bottom 5（v0.1.17）

### Top 5

| 排名 | 技能 | 分数 | 指南分 |
|------|------|------|--------|
| 1 | cloud-security | 91.2 | 88.0 |
| 2 | network-pentest | 90.9 | 86.9 |
| 3 | article-writing | 90.6 | 82.5 |
| 4 | vulnerability-assessment | 90.6 | 84.1 |
| 5 | autonomous-loops | 90.5 | 86.2 |

### Bottom 5

| 排名 | 技能 | 分数 | 指南分 |
|------|------|------|--------|
| 45 | multi-agent-collaboration | 85.2 | 82.8 |
| 46 | chronicle | 85.1 | 79.5 |
| 47 | docker-patterns | 85.0 | 79.0 |
| 48 | web-sqli | 84.9 | 92.0 |
| 49 | deep-research | 84.3 | 76.0 |

---

## 关键洞察

1. **cloud-security 距 Distinguished 仅 0.8 分**（91.2，指南分 88.0）——需进一步提升指南深度或字数
2. **分数区间收窄至 6.9**——技能质量更加均匀，底部不再拖后腿
3. **所有技能关键段落 3/3**——文件结构标准化完成
4. **指南分 < 70 完全消除**——最低的 social-engineering 76.6，其次是 browser-qa 75.2

---

## 下一步计划（v0.1.18+）

1. **首批 Distinguished** — cloud-security 需再 +0.8，可通过扩充指南内容（avg_words 提升）或增加 1-2 个深度指南
2. **第二批 Distinguished 冲刺** — network-pentest (90.9)、article-writing (90.6) 各差约 1-2 分
3. **底部继续提升** — deep-research (84.3)、web-sqli (84.9) 需要指南或 payloads 补强
4. **场景执行验证** — 在授权靶机上执行 SCEN-001~005 攻击链

---

_Built with the OpenClaw Agent Framework._
