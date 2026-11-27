# kali-claw v0.3.7 版本说明 — Bottom 技术孪生加深 📈

> **版本编号**：v0.3.7（patch release）
> **发布日期**：2026 年 11 月 9 日
> **版本类型**：v0.3.5/v0.3.6 P1 backlog 清偿（Bottom 双子加深）
> **上一版本**：v0.3.6（2026-11-09，第 4 次月度审查 + 死链清偿）
> **下一里程碑**：验证器沉淀（P2）+ 域归并（P3）→ 第 5 次月度审查 2026-12-07

---

## 一、版本概述

对排名报告 Bottom-2 技术技能（均 65 分 Fair）执行 v0.3.1 先例的孪生加深处置：payloads 全量重建、NVD 核验 CVE 补入、TC 规范化扩充、MITRE 映射扩展。

**结果**：双双 65 → **78（Good）**，仓库最低技术技能分抬升至 78；lint 保持 0/0/139。

## 二、评分变化

| SKILL | v0.3.6 时 | v0.3.7 | 变化 |
|-------|-----------|--------|------|
| data-loss-prevention-bypass | 65（Fair，Bottom-1）| **78（Good）** | +13 |
| edge-computing-security | 65（Fair，Bottom-2）| **78（Good）** | +13 |

## 三、处置明细

### data-loss-prevention-bypass

| 项 | 前 | 后 |
|----|----|----|
| payloads | 109 行模板化 | **319 行 / 18 节**：通道选择矩阵、端点 Agent 侦察、零宽/同形字变换、polyglot+ADS、图像/音频/视频 LSB stego、DNS 隧道（dnscat2/iodine/dns2tcp + DoH 变体）、ICMP、SaaS 伪装（Graph/Drive/webhook/GitHub）、presigned/SAS/rclone-crypt、WSS/HTTP2/HTTP3、时序信道、语义分块 AI 外泄、慢滴、HLS/备份拟态、蓝色检测（Suricata/SPL/Falco）|
| CVEs | 0（策略关闭）| **6 个 NVD 核验**（Forcepoint ×2、Digital Guardian ×3、Symantec DLP ×1）— 策略重开：技术孪生加深后 DLP 产品面 CVE 类适用 |
| TCs | 编号重复 + 模板残留 | **13 条规范化**（去重 +3 新：polyglot/archive、DoH 覆盖、presigned-URL/SAS）|
| MITRE | 1 T-code | **8 T-codes**（T1048/.003、T1008、T1567.002、T1001、T1132、T1030）|

### edge-computing-security

| 项 | 前 | 后 |
|----|----|----|
| payloads | 88 行模板化 | **245 行 / 14 节**：边缘指纹、源站发现（CT/DNS 历史/favicon hash/CDN 段排除扫描）、直连源站、WAF 绕过、缓存投毒（unkeyed/fat GET/cache-key 归一化）、缓存欺骗、CL.TE/TE.CL/h2 走私、Worker/Lambda@Edge 滥用、shield DoS、控制面滥用、蓝色检测 |
| CVEs | 3（KubeEdge）| **8**（+ATS ×3、Envoy ×1、Varnish ×1，全部 NVD 核验 2026-11-09）|
| TCs | 编号重复 + 模板残留 | **13 条规范化**（+3 新：h2 走私检测、边缘密钥暴露审计、cache-key 归一化审计）|
| MITRE | 1 T-code | **7 T-codes**（T1190、T1592、T1557、T1505.003、T1499、T1595.002）|

## 四、验证

| 检查 | 结果 |
|------|------|
| skill-lint | **139/139, 0 errors / 0 warnings** ✅ |
| bash -n 门（重建 payloads 全部 bash 块）| 0 错误 ✅ |
| validate-payloads / validate-testcases | 0 errors ✅ |
| 新增 CVE NVD 核验 | 11/11（2026-11-09 逐个 API 核验）✅ |
| 评估文档 + evidence | 2 个 usage-and-assessment 重写 + evidence/2026-11-09/ ✅ |
| SKILL_HANDBOOK/INDEX | 再生成 + --check 无 drift ✅ |

## 五、修改文件

| 文件 | 改动 |
|------|------|
| `skills/data-loss-prevention-bypass/{payloads.md,test-cases.md,SKILL.md,guides/usage-and-assessment.md}` | payloads 重建 109→319、TC 13、MITRE 8、重评 78 |
| `skills/edge-computing-security/{payloads.md,test-cases.md,SKILL.md,guides/usage-and-assessment.md}` | payloads 重建 88→245、TC 13、MITRE 7、重评 78 |
| `skills/*/evidence/2026-11-09/` | lint.json + summary.md ×2 |
| `docs/SKILL_HANDBOOK.md` / `docs/SKILL_INDEX.json` | frontmatter 变化后再生 |
| 版本同步 | RELEASE + VERSION + CHANGELOG + README/AGENTS/CLAUDE/MEMORY |

## 六、后续规划

| 优先级 | 任务 | 预估 | 触发条件 |
|-------|------|------|---------|
| P2 | `/tmp/validate-all.py` 沉淀为 `validation/check-skill-usability.py` + 白名单扩充 | ~1h | 第 5 次月度审查前 |
| P3 | 域归并 83 → ~20 | ~2h | 下次 minor |
| Q4 | 季度工具基线 2026-12 | ~4h | 2026-12 |
| 定期 | 第 5 次月度审查 | ≤2h | 2026-12-07 |

## 七、版本签名

```
版本编号：v0.3.7
发布日期：2026-11-09
版本类型：Bottom 技术孪生加深（quality patch）
上一版本：v0.3.6
skill-lint：0/0/139（保持）
新 SKILL：0（总数 139 不变）
评分抬升：DLP-bypass 65→78、edge-computing-security 65→78
新增 CVE：11（全部 NVD 核验 2026-11-09）
TC 规范化：两技能去重 +3 新 ×2 = 13/13
MITRE：+7/+6 T-codes
```

**kali-claw 团队**
**2026 年 11 月 9 日**
