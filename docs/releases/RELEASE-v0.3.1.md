# kali-claw v0.3.1 版本说明 — Poor 技能清偿 📈

> **版本编号**：v0.3.1（patch release）
> **发布日期**：2026 年 9 月 5 日
> **版本类型**：P3 backlog 首批清偿（3 个 Poor 技能 + pqi TC rider）
> **上一版本**：v0.3.0（2026-09-04，PQC 实现层攻击域）
> **下一里程碑**：第 4 次月度审查（2026-10-05，含 pqi 稳定性复查）；0-CVE 类批量清偿（v0.3.2 候选）

---

## 一、版本概述

v0.3.1 是评估项目闭环后的首个质量 patch：把仓库最低分的 3 个 Poor 技能全部抬出 Poor 区间，并顺手清偿 v0.3.0 新技能的最后一条可操作 P3。

**结果**：3/3 技能达标（最低分 56 → 74），全部 20 个新增 CVE 经 NVD API 逐个核验，lint 保持 0/0/139。

---

## 二、评分变化

| SKILL | v0.3.0 时 | v0.3.1 | 变化 |
|-------|-----------|--------|------|
| voip-sip-attack | 56（Poor）| **74（Good）** | +18 |
| 5g-6g-telecom-attack-advanced | 59（Poor）| **80（Excellent）** | +21 |
| hardware-side-channel-advanced | 59（Poor）| **77（Good）** | +18 |
| pqc-implementation-attack | 77（Good）| 77（Good） | 0（TC 5→10，0-CVE 策略性保留）|

仓库最低分：56 → 74；Poor 技能清零。

---

## 三、Findings 应用详情

### voip-sip-attack（F-VOIP-003/004）

| Finding | 应用 |
|---------|------|
| F-VOIP-003（0 CVEs）| ✅ payloads §19 新增 5 个 NVD 核验 CVE（FreeSWITCH CVE-2019-19492/CVE-2018-19911/CVE-2021-36513、Kamailio CVE-2018-8828/CVE-2018-14767）+ 攻击面 bullets |
| F-VOIP-004（TC 薄，8）| ✅ 扩至 12 TC：新类别 I-L（toll fraud CRITICAL、注册劫持/re-INVITE、伪造 BYE/CANCEL 注入、SIPS/SRTP 降级与密钥泄漏）|

### 5g-6g-telecom-attack-advanced（F-5G6G-003/004 + 内容债）

| Finding | 应用 |
|---------|------|
| 内容债 | ✅ payloads 87 → 347 行：删除模板占位垃圾；新增 5G Core SBA（rogue NF/NRF 注册、SBI JWT 伪造与 relay、AUSF/UDM AV 重放）、SUPI/SUCI 解掩蔽 + GUTI 追踪、伪 gNB 强制降级 + 5G paging 泄漏、切片逃逸（S-NSSAI 伪造）、O-RAN（RIC xApp/O1/eCPRI）、Diameter/sipp 场景、NAS/RRC fuzzing、检测工程、6G 研究向量 |
| F-5G6G-003（0 CVEs）| ✅ payloads §11 新增 7 个核验 CVE（Open5GS CVE-2021-25863/-44081/-41794/-45462、Exynos 基带 CVE-2023-26075/-26072/-26074）|
| F-5G6G-004（TC 薄，5）| ✅ 扩至 10 TC（rogue NF 注册、SUCI/paging 隐私、切片逃逸、WebUI 接管、AMF 鲁棒性）|
| T-codes | 1 → 6（T1557/T1595/T1498/T1621/T1046/T1078）|

### hardware-side-channel-advanced（F-HARDW-003/004 + 内容债）

| Finding | 应用 |
|---------|------|
| 内容债 | ✅ payloads 86 → 313 行：删除占位垃圾；新增完整 CPA 工作流、模板攻击、RSA CRT 时序、EM 近场采集与 EM DPA、Prime+Probe/Flush+Reload 完整代码、Meltdown/MDS/LVI/SGX（Plundervolt）原语、DFA on AES（phoenixAES）+ Rowhammer（TRRespass）、对策评估（masking/dual-rail/TVLA）、检测工程 |
| F-HARDW-003（0 CVEs）| ✅ payloads §9 新增 8 个核验 CVE（Spectre CVE-2017-5753/-5715、Meltdown CVE-2017-5754、MDS CVE-2018-12126/-12127/-12130、Plundervolt CVE-2019-11157、LVI CVE-2020-0551）。**核验中剔除 CVE-2018-11091**（NVD 显示为其他产品，记忆映射错误）——核验门生效的实例 |
| F-HARDW-004（TC 薄，5）| ✅ 扩至 10 TC（CPA 全钥恢复、模板攻击、跨 VM Flush+Reload、enclave 电压故障、DFA）|
| T-codes | 1 → 5（T1041/T1200/T1040/T1592/T1068）|

### pqc-implementation-attack（F-PQI2-004，rider）

| Finding | 应用 |
|---------|------|
| F-PQI2-004（TC 薄，5）| ✅ 扩至 10 TC（固件符号 diff、dudect 常数时间验证、毛刺故障预算、keygen RNG 缺陷、跨受害者密钥复用）|
| F-PQI2-003（0 CVEs）| 保持 open（策略性：仅引 NVD 核验编号，见 payloads §2.3）|

### 统计

| 优先级 | 数量 | 关闭 |
|-------|------|------|
| P3（0 CVEs）| 3 | 3 ✅（第 4 个为策略性保留）|
| P3（TC 薄）| 4 | 4 ✅ |
| 内容债（payloads <100 行）| 2 | 2 ✅ |
| **合计** | **9** | **8 关闭 + 1 策略保留** |

---

## 四、修改文件清单

| 文件 | 改动 |
|------|------|
| `skills/voip-sip-attack/{payloads.md,test-cases.md}` | +CVE 段、+4 TC、评估更新 |
| `skills/5g-6g-telecom-attack-advanced/{payloads.md,test-cases.md}` | payloads 重建 87→347、+5 TC、评估更新 |
| `skills/hardware-side-channel-advanced/{payloads.md,test-cases.md}` | payloads 重建 86→313、+5 TC、评估更新 |
| `skills/pqc-implementation-attack/test-cases.md` | +5 TC |
| 4 个 `guides/usage-and-assessment.md` + `evidence/2026-09-05/` | 重评（旧 2026-09-04 evidence 保留）|

Commits：eebe16e / f4b69c6 / 9e0846e / 375000f / 本提交（release）。

---

## 五、验证

| 检查 | 结果 |
|------|------|
| skill-lint | **139/139, 0 errors / 0 warnings**（无回归）|
| validate-payloads / validate-testcases | 0 errors（warning 数与 v0.2.7 基线一致）|
| 新增 CVE 核验 | 20/20 通过 NVD API 逐个核验（含 1 个候选被剔除）|
| 占位垃圾残留 | 0（`grep "See kali-claw for full library"` 空）|
| 评估闭环 | usage-and-assessment 139/139 保持 |

---

## 六、后续规划

| 优先级 | 任务 | 预估 | 触发条件 |
|-------|------|------|---------|
| P1 | 0-CVE 类 P3 脚本化批量清偿（约 44 个技能，逐个 NVD 核验）| ~2-3h | v0.3.2 |
| P2 | 第 4 次月度审查 + pqc-implementation-attack 出厂 3 周稳定性复查 | ≤2h | 2026-10-05 |
| P3 | TC 薄类 P3 剩余批次（约 35 个技能）| 按批 | 后续 patch |
| Q4 | 季度工具基线 2026-11 | ~4h | 2026-11 |

---

## 七、版本签名

```
版本编号：v0.3.1
发布日期：2026-09-05
版本类型：P3 首批清偿（quality patch）
上一版本：v0.3.0
skill-lint：0/0/139（保持）
新 SKILL：0；退役：0（总数 139 不变）
评分抬升：voip 56→74、5g-6g 59→80、hardware 59→77（Poor 清零）
Findings：9 条处理（8 关闭 + 1 策略保留）
新增 CVE：20（全部 NVD 核验，1 个候选被核验门剔除）
```

**kali-claw 团队**
**2026 年 9 月 5 日**
