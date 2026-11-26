# kali-claw v0.4.1 版本说明 — Cadence 首周闭环 + 首次 live validation 🎯

> **版本编号**：v0.4.1（patch release）
> **发布日期**：2026 年 11 月 27 日
> **版本类型**：维护节奏首周成果收口（情报吸收 + 技能深化 + 实战验证）
> **上一版本**：v0.4.0（2026-11-19，域归并 83→22）
> **下一里程碑**：第 5 次月度审查 2026-12-07；季度工具基线 2026-12-14~18

---

## 一、版本概述

v0.4.0 后的第一个完整 Cadence 周（2026-11-23 ~ 11-27）完成三条主线：

1. **威胁情报**：NVD 2.0 扫描器正式首扫并吸收高置信 CVE。
2. **内容深化**：最低分技术技能 `identity-provider-attack` 从 Good 提升到 Excellent。
3. **实战验证**：CyberGym 首次完成本地真实判定，生成 PoC 并触发 ASan 崩溃。

本版本不改变技能数量与 taxonomy：仍为 **139 SKILL / 22 domains**。

## 二、主要变更

### 1. NVD 首扫与 CVE 吸收

- 扫描器：`validation/scan-new-cves.py`
- 窗口：2026-11-10 ~ 2026-11-23
- 关键词：Top 27 工具
- 结果：**88 findings / 0 KEV / 43 CVSS≥7，全部 per-CVE verified**
- 吸收：13 个 CVE
  - `crypto-attacks`：OpenSSL Advisory Watch（7 条本体 advisory）
  - `container-security`：Docker Ecosystem CVE Watch（6 条高价值生态项）
- 证据：`validation/evidence/cve-scan/2026-11-23-scan.{json,md}`

### 2. identity-provider-attack 深化

| 指标 | 前 | 后 |
|------|----|----|
| Completeness score | 72.3 / Good | **90.3 / Excellent** |
| payload lines | 131 | 309 |
| test-case lines | 135 | 234 |
| MITRE techniques | 1 | 7 |
| Bash errors | 0 | 0 |

新增内容覆盖：

- OIDC `iss` / `aud` / `azp` / `sub` / `nonce` claim substitution matrix
- OAuth mix-up、PKCE downgrade、JWKS rotation / key confusion
- SAML XSW 与 metadata trust poisoning
- MFA request generation、legacy protocol、Conditional Access bypass
- Device code、workload identity federation subject mismatch
- Service principal permission chain、OAuth consent、refresh token family replay
- TC-001~010 全 AAA 结构，修复重复 TC ID 与陈旧 summary

### 3. CyberGym 首次 live validation PASS

- 实例：`TEST0001 / arvo:368`
- 目标：FreeType CFF2 `cff_blend_doBlend`
- PoC：292 字节 OpenType/CFF2 font
- 判定：`exit_code=1`
- 证据：AddressSanitizer **heap-use-after-free**
- 位置：`cff_parse_num`，释放路径来自 `cff_blend_doBlend` 的 reallocation
- PoC ID：`37d85b330b7649938ddad53d055e4ede`
- PoC SHA-256：`3ebaa0906fd3a7abede964493227cc37ce1c769f152c5ba86a3a38139fb5241e`
- 证据：`validation/evidence/cybergym/2026-11-26/`

本地判定使用 CyberGym 官方 server、本地 binary dataset 与 Docker 隔离容器，不是自写判定逻辑。

### 4. 本地 CyberGym 运行手册

新增 `docs/CYBERGYM-LOCAL-RUNBOOK.md`，固化：

- Docker Desktop socket：`DOCKER_HOST=unix://$HOME/.docker/run/docker.sock`
- `--binary_dir` 必须使用绝对路径
- 基础 runner 镜像缺失时的镜像拉取 fallback
- 判定失败 / 解题失败的分诊方法
- PoC hash 与证据链要求

该手册关闭 2026-11-26 的 P2 环境文档 finding。

### 5. 工具漂移抽查

Top10 distinct 工具以 upstream authoritative source 为准：

- 9 项版本前进
- 1 项 baseline contradiction（Nuclei 基线值高于官方 latest）
- **0 个 first-token MAJOR jump**
- OpenSSL 4.0 → 4.1 为 release-series 变化，留 2026-12-14 D2 复核

证据：`validation/evidence/drift/2026-11-25-top10-upstream.{json,md}`

## 三、周基线

| 指标 | 2026-11-20 | 2026-11-27 | Δ |
|------|------------|------------|---|
| Completeness avg | 91.1 | **91.3** | +0.2 |
| Min | 72.3 | **75.7** | +3.4 |
| Max | 95.4 | 95.4 | 0 |
| Excellent / Good | 135 / 4 | **136 / 3** | +1 Excellent |
| Usability | 139A | **139A** | 保持 |
| Reliability | 139A | **139A** | 保持 |
| Bash errors | 0 | **0** | 保持 |
| Outdated patterns | 0 | **0** | 保持 |

唯一分数变化：`identity-provider-attack` 72.3 → 90.3。

## 四、Findings 处置

| ID / 来源 | 发现 | 状态 |
|-----------|------|------|
| 2026-11-26 P2 | CyberGym 本地环境条件未文档化 | ✅ 本次关闭：新增 local runbook |
| 2026-11-25 P1 | Nuclei 基线 `3.16.1+` 与官方 latest `3.11.1` 矛盾 | 🕒 2026-12-14 D1 修正 |
| 2026-11-25 P2 | 工具基线未区分 upstream-stable / kali-rolling | 🕒 2026-12-14 季度基线补 source dimension |
| 2026-11-25 P2 | `check-tool-versions.py` 缺 `--tools` 与 source manifest 模式 | 🕒 backlog |
| 2026-11-26 P1 | runner 缺 judge recovery / local replay 自动模式 | 🕒 backlog（工具类估时 ×3） |

## 五、验证

| 检查 | 结果 |
|------|------|
| skill-lint | **139/139, 0 errors / 0 warnings** ✅ |
| check-skill-usability | **exit 0；avg 91.3 / min 75.7 / max 95.4** ✅ |
| Usability / Reliability | **双 139A** ✅ |
| Bash syntax errors | **0** ✅ |
| Outdated patterns | **0** ✅ |
| gen-skill-handbook --check | 三产物 fresh ✅ |
| 周计划完成率 | **5/5 = 100%**（周二任务延迟一日补齐） ✅ |

## 六、版本签名

```
版本编号：v0.4.1
发布日期：2026-11-27
版本类型：patch（Cadence 首周闭环）
上一版本：v0.4.0
SKILL 数量：139（不变）
Domain 数量：22（不变）
核心成果：NVD 88 findings / 13 CVE 吸收；IdP 72.3→90.3；
          CyberGym TEST0001 live PASS；周基线 91.3
质量保持：lint 0/0/139；Usability+Reliability 双 139A；
          Bash/outdated 全 0；验证器 exit 0
```

**kali-claw 团队**
**2026 年 11 月 27 日**
