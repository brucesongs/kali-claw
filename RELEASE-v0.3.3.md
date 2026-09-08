# kali-claw v0.3.3 版本说明 — TC 薄类清偿 & 评估 backlog 归零 🧪🏁

> **版本编号**：v0.3.3（patch release）
> **发布日期**：2026 年 9 月 8 日
> **版本类型**：TC 薄类 P3 批量清偿 + 全仓评估文档 truth-sync
> **上一版本**：v0.3.2（2026-09-07，0-CVE 批量清偿）
> **下一里程碑**：第 4 次月度审查（2026-10-05，含 pqi 稳定性复查）——首次面对零 backlog 基线

---

## 一、版本概述

v0.3.3 清偿最后一个 P3 类别（TC 薄，现场实测 44 个技能），并借 DoD 验证发现的全仓评估文档失真问题做了一次 **truth-sync**。

**结果**：新增 **88 条 TC**；34 个技术技能精确达标 10 条；9 个豁免 meta 策略关闭；command-injection-advanced 计数口径修复；**全仓 139 个技能的评估文档全部重算至 2026-09-08，非策略 open findings = 0 —— 评估 backlog 自 v0.2.7 启动以来首次归零**。lint 全程 0/0/139。

## 二、TC 补齐明细（88 条 / 34 技能 + 计数修复）

| 批次 | 技能数 | 新增 TC | 代表主题 |
|------|--------|---------|---------|
| 格式归一化 | 1 | +4 | command-injection-advanced：旧 `Test Case N` 头归一为 TC-CI-nnn（6 条完好用例获计数）+ 盲时序/编码绕过/参数注入/OOB 4 条新用例 |
| 批 A（Web/注入）| 11 | +22 | XInclude、Ruby/Node 反序列化、session 污染、WP REST→theme-editor RCE、DNS 放大/缓存窥探、NFS no_root_squash、直接系统调用/睡眠混淆、one_gadget、LOLBAS、Redis/MongoDB、DMARC |
| 批 B（网络/无线/IoT）| 12 | +28 | 伪 DHCP、隧道混淆、SSL VPN 链、NFC 中继、Zigbee/TPMS、DNP3/BACnet、固件重打包、TLS 0-RTT 重放/SMB 状态混淆/QUIC/状态机推断（protocol-state 6→10）、单包竞速/双重释放/丢失更新（concurrency 6→10）、fileless 内存取证规避、视频/空白隐写、熵秘密检测/许可合规 |
| 批 C（AI/平台/报告）| 11 | +32 | 模型蒸馏提取、garak/promptfoo、Keras Lambda/Chroma 投毒/ModelScan 规避/MLflow/Kubeflow（AISC 5→10）、WAF/缓存欺骗/限流/故障转移/配置漂移（edge-security 5→10）、SAML XSW/mix-up/元数据注入（IdP 7→10）、PtT/GPP cpassword、EU AI Act 条款 13/14/12/72+合规就绪（5→10）、SaaS 伪装/时序信道/DLP 绕过矩阵（DLP 7→10）、API 审查/威胁模型验证、CVSS 一致性/高管摘要、复盘闭环 |
| truth-sync 修正 | 1 | +2 | council 8→10（决策记录可追溯性、视角覆盖完整性）——council 实非 lint 豁免，按真实 TC 修复 |

每条 TC 选题来自"payloads 有而 TC 无"的主题缺口；格式跟随各文件既有惯例（字段表格型 / bullet 型 / AAA 型）。

## 三、策略关闭（9 个豁免 meta）

article-writing、chronicle、continuous-learning、knowledge-ops、mcp-server-patterns、multi-agent-collaboration、safety-guard、verification-loop（8 条 TC）+ council 曾被误归此类（已改为真实补齐）。既有 TC 保留不删；finding 行标注 "closed by policy — non-attack meta skill"。

## 四、Truth-Sync（DoD 验证发现的账实不符）

发布前验证发现 **~85 行 legacy finding 残留**于旧评估文档：一类是**陈旧行**（问题早已修复但文档未再生成——council ATT&CK、crypto-attacks T-codes、gitops gitleaks 等），一类是两轮 patch 目标名单之外、从未重算的文档。处置：

1. 全仓 139 个技能评估文档按当日活体指标重算（evidence/2026-09-08 全覆盖；旧 evidence 保留）
2. 恢复 9 个 v0.3.2 策略域 + pqi NVD-gate 的 policy 标注
3. **终扫结果：非策略 open findings = 0**

自此评估文档与仓库状态严格一致；后续月度审查将以 truth-sync 重算为常规动作。

## 五、验证

| 检查 | 结果 |
|------|------|
| skill-lint | 139/139, 0/0（全程无回归）|
| validate-testcases | 0 errors；warning 17 → **16**（不降反升为负）|
| TC<10 存活 | 仅 8 个豁免 meta（全部策略标注）|
| 评估闭环 | usage-and-assessment 139/139 + evidence/2026-09-08 × 139 |
| Backlog | **非策略 open findings = 0（全仓）** |

Commits：f3708b7（归一化）/ 622a7a2（批 A）/ 2231bc8（批 B）/ c7f8cf9（批 C）/ 2af65f7（策略关闭+重评）/ 2ad3abe（truth-sync）/ 本提交（release）。

## 六、后续规划

| 优先级 | 任务 | 预估 | 触发条件 |
|-------|------|------|---------|
| P1 | 第 4 次月度审查 + pqc-implementation-attack 出厂 3 周稳定性复查（零 backlog 首查）| ≤2h | 2026-10-05 |
| P2 | 季度工具基线（2026-11，对照 2026-08 基线找 MAJOR 漂移）| ~4h | 2026-11 |
| P3 | 半年 Defense Triple 内容质量审计（结构已 100%，查内容时效）| ~8h | 2027-02 |

## 七、版本签名

```
版本编号：v0.3.3
发布日期：2026-09-08
版本类型：TC 薄类清偿 + truth-sync
上一版本：v0.3.2
skill-lint：0/0/139（保持）
新 SKILL：0（总数 139 不变）
新增 TC：88（34 技能 + 计数修复）；策略关闭 9
评估文档：139/139 重算至 2026-09-08
Backlog：非策略 open findings = 0（全仓归零）🏁
```

**kali-claw 团队**
**2026 年 9 月 8 日**
