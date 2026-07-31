# kali-claw v0.2.0.8 版本说明

> **版本编号**：v0.2.0.8  
> **发布日期**：2026 年 7 月 29 日  
> **版本类型**：里程碑版本（Task 1.3 完成 - 7 个新 SKILL 创建）  
> **上一版本**：v0.2.0.7（2026-07-28）  
> **下一里程碑**：v0.2.0.9（Task 1.4 文档输出）

---

## 项目地址

- **GitHub 仓库**：[https://github.com/brucesongs/kali-claw](https://github.com/brucesongs/kali-claw)
- **主分支**：[main](https://github.com/brucesongs/kali-claw/tree/main)
- **版本标签**：[v0.2.0.8](https://github.com/brucesongs/kali-claw/releases/tag/v0.2.0.8)
- **问题反馈**：[GitHub Issues](https://github.com/brucesongs/kali-claw/issues)
- **讨论区**：[GitHub Discussions](https://github.com/brucesongs/kali-claw/discussions)

---

## 一、版本概述

kali-claw 是基于 OpenClaw 框架构建的 AI 渗透测试智能体工作空间。v0.2.0.8 是 Phase 1 SKILL 库完善项目的第八个迭代版本。

本次发布的核心成就是 **Task 1.3 全部完成** — **创建 7 个战略价值高的新 SKILL**，填补 AI 安全、身份提供商、数据保护、边缘计算、后量子密码、硬件侧信道、5G/6G 电信等战略空白。SKILL 总数从 130 扩展至 **137**。

---

## 二、版本亮点

### 🎊 Task 1.3 完成 - 7 个新 SKILL 创建

| # | SKILL | 类别 | 战略价值 |
|---|-------|------|---------|
| 1 | ai-safety-redteam-advanced | AI 安全 | OWASP LLM Top 10 + AI 红队（市场热点） |
| 2 | identity-provider-attack | 云身份 | 现代 IAM（Okta/Azure AD/Auth0/Keycloak） |
| 3 | data-loss-prevention-bypass | 数据保护 | DLP 绕过 + AI 增强外泄 |
| 4 | edge-computing-security | 边缘计算 | CDN/Edge（Cloudflare Workers/Lambda@Edge） |
| 5 | quantum-cryptography-transition | 后量子密码 | PQC 迁移（NIST FIPS 203/204/205） |
| 6 | hardware-side-channel-advanced | 硬件侧信道 | SPA/DPA/EM/光学故障注入（ChipWhisperer） |
| 7 | 5g-6g-telecom-attack-advanced | 5G/6G 电信 | 5G Core/Open RAN/网络切片/6G 研究 |

### 每个新 SKILL 包含

- ✅ **SKILL.md**（含 YAML 前言 + Defense Triple）
- ✅ **payloads.md**（实战攻击载荷集合）
- ✅ **test-cases.md**（结构化测试用例，AAA 格式）
- ✅ **guides/**（深度参考资料，部分 SKILL）
- ✅ 版本统一至 v0.2.0.2
- ✅ `last_reviewed: 2026-07-27` 元数据

### 关键 PR

| PR | 内容 | 状态 |
|----|------|------|
| #17 | Task 1.3 #1 - ai-safety-redteam-advanced（完整版含 guides） | ✅ MERGED |
| #18 | Task 1.3 #2-7 - 6 个新 SKILL | ✅ MERGED |

---

## 三、详细新增 SKILL 详解

### 1. ai-safety-redteam-advanced

**适用场景**：AI 安全红队进阶，针对 LLM 集成应用、Agent 框架、RAG 系统的渗透测试。

**核心内容**：

- **OWASP LLM Top 10 (2025)** 全覆盖（LLM01-LLM10）
- **MITRE ATLAS** 对抗技术映射
- **多智能体协同攻击**（Agent 间注入传播）
- **多模态注入**（图像/音频/PDF）
- **Tokenizer 级攻击**（BPE 合并、Unicode）
- **Model Extraction**（API 查询克隆模型）
- **Supply Chain 攻击**（Pickle RCE、Backdoored Tokenizer）

**核心工具**：garak、PyRIT、promptfoo、Giskard、Counterfit、Lakera Guard、Llama Guard、OpenAI Evals、textattack、CleverHans

**详细深度指南**：`guides/owasp-llm-top10-complete-guide.md`（OWASP LLM Top 10 10 大类风险全深度解析，380+ 行）

### 2. identity-provider-attack

**适用场景**：身份提供商攻击 — OAuth/OIDC、SAML、JWT 现代身份攻击。

**核心内容**：

- **OAuth 2.0/OIDC 流程攻击**：authorization code 盗窃、state 重用、PKCE 降级、redirect_uri 绕过
- **JWT 攻击**：algorithm confusion（RS256→HS256）、kid 注入、weak HMAC brute force、null signature
- **SAML 利用**：XML 签名包装、断言注入、证书混淆
- **令牌盗窃与重放**：session cookie 盗窃、refresh token 滥用、Primary Refresh Token (PRT) 攻击
- **MFA 绕过**：push bombing、SIM swap、OAuth 同意钓鱼、TOTP 暴力破解
- **Service Principal 滥用**：Azure AD/Entra ID 特权 SP、证书认证滥用、Workload Identity Federation

**核心工具**：jwt_tool、tokenhero、AADInternals、MFASweep、ROADtools、o365creeper、OktaPostman、SAMLExtractor、mitm6

### 3. data-loss-prevention-bypass

**适用场景**：DLP（数据防泄漏）绕过 - 隐写术、隧道、云同步、AI 增强外泄。

**核心内容**：

- **隐写术**：LSB（图像/音频/视频）、PDF 对象流、网络包时序
- **DNS 隧道**：dnscat2、iodine
- **ICMP 隧道**：数据在 ICMP echo payload 中
- **WebSocket / HTTP/3 (QUIC)**：新一代协议，监控工具跟不上
- **云同步滥用**：使用受批准的应用（OneDrive、Dropbox）
- **AI 增强外泄**：使用 LLM 语义分块敏感数据，绕过基于模式的 DLP

### 4. edge-computing-security

**适用场景**：边缘计算安全 - CDN 绕过、边缘函数利用、缓存投毒。

**核心内容**：

- **CDN 绕过**：通过 DNS 历史、HTTP 头泄漏、SSL 证书 SAN 发现源 IP
- **Cloudflare Workers 滥用**：注入恶意 Worker 代码、利用 worker.dev 域名信誉
- **AWS Lambda@Edge 攻击**：边缘函数 RCE、跨区域数据外泄
- **缓存投毒**：unkeyed header poisoning、cache key 操纵
- **缓存欺骗**：欺骗 CDN 缓存动态敏感内容
- **WAF 绕过**：HTTP/2 多路复用、协议混淆、origin 直接访问

### 5. quantum-cryptography-transition

**适用场景**：后量子密码（PQC）迁移安全 - NIST 标准、混合 TLS、QKD、HNDL。

**核心内容**：

- **NIST PQC 标准**：FIPS 203 (ML-KEM/Kyber)、FIPS 204 (ML-DSA/Dilithium)、FIPS 205 (SLH-DSA/SPHINCS+)
- **混合 TLS 弱点**：KEM combiner 缺陷（XOR vs HKDF）
- **QKD（Quantum Key Distribution）攻击**：detector blinding、PNS（Photon-Number-Splitting）、trusted node compromise
- **HNDL（Harvest Now, Decrypt Later）风险评估**：识别长期保密数据（>10 年）
- **PQC 实现侧信道**：Kyber RowHammer、Dilithium 时序攻击

### 6. hardware-side-channel-advanced

**适用场景**：硬件侧信道攻击进阶 - SPA/DPA、EM、glitching、光学故障注入。

**核心内容**：

- **功耗分析**：SPA（Simple Power Analysis）、DPA（Differential Power Analysis）、CPA（Correlation Power Analysis）
- **电磁泄漏**：EM probe 采集、模板攻击
- **时序攻击**：RSA 时序、ECC scalar 时序
- **缓存时序攻击**：Spectre v1/v2、Meltdown、LVI、Retbleed 变种
- **Glitching**：电压/时钟故障注入
- **光学故障注入**：IR 激光从 die 背面注入、DFA（Differential Fault Analysis）
- **对策评估**：masking、hiding、constant-time、cache partitioning

### 7. 5g-6g-telecom-attack-advanced

**适用场景**：5G/6G 电信攻击进阶 - 5G Core、IMSI Catcher 演进、Open RAN、网络切片。

**核心内容**：

- **5G Core (SBA) 利用**：NF（Network Function）API 滥用、跨切片访问、AUSF 绕过
- **IMSI Catcher 演进（5G Stingray）**：强制回退到 4G/3G 暴露 SUPI、TMSI tracking
- **SIP/Diameter 协议攻击**：信令风暴、SMS 拦截
- **Open RAN 漏洞**：fronthaul 未加密、near-RT RIC 利用、供应链攻击
- **网络切片滥用**：逃逸切片隔离、跨切片 NF 访问
- **6G 早期研究**：THz 通信、AI-native air interface、量子通信集成

---

## 四、累计成果

### SKILL 库扩展

```
v0.2.0.1 (起点):     130 SKILLs
v0.2.0.7 (Phase 2):  130 SKILLs 全部 v0.2.0.2 (100%)
v0.2.0.8 (Task 1.3): 137 SKILLs (130 + 7 new) 全部 v0.2.0.2 (100%) 🎊
```

### 质量指标终极对照

| 指标 | v0.2.0.1（升级前） | v0.2.0.8（本版本） | 提升 |
|------|-------------------|------------------|------|
| SKILL 总数 | 130 | **137** | +7 |
| 高优先级 SKILL 完成数 | 0/15 | **15/15 (100%)** | +15 |
| 标准化 SKILL 完成数 | 0/100 | **100/100 (100%)** | +100 |
| 新建 SKILL 数 | 0/7 | **7/7 (100%)** | +7 |
| **总累计** | **0/130** | **137/137 (100%)** 🎊 | +137 |
| SKILL 版本统一 | 各为 0.1.x | **全部 v0.2.0.2** | +100% |
| Defense Triple 覆盖 | 部分 | **100%** | 显著 |
| 检测方法章节 | 30% | **100%** | +70% |
| 防御规避技术章节 | 20% | **100%** | +80% |
| 翻译残留 | 多处 | **0** | 100% 清理 |
| `.git/` 目录大小 | 3.7 GB | **19 MB** | -99.5% |

### 安全域覆盖（137 个 SKILL）

新增覆盖域：

```
AI 安全红队进阶域      ✓ ai-safety-redteam-advanced
身份提供商攻击域       ✓ identity-provider-attack
数据防泄漏绕过域       ✓ data-loss-prevention-bypass
边缘计算安全域         ✓ edge-computing-security
后量子密码迁移域       ✓ quantum-cryptography-transition
硬件侧信道进阶域       ✓ hardware-side-channel-advanced
5G/6G 电信进阶域       ✓ 5g-6g-telecom-attack-advanced
```

加上原有 130 个 SKILL 覆盖的全部安全域，共 137 个完整安全域。

---

## 五、安装与使用

### 快速开始

```bash
git clone https://github.com/brucesongs/kali-claw.git
cd kali-claw
claude
/init
```

支持平台：OpenClaw、Claude Code、OpenAI Codex、Hermes Agent、OpenCode

详见 [README.md](https://github.com/brucesongs/kali-claw/blob/main/README.md)

### 文件结构

```
kali-claw/
├── skills/                          # 137 个安全技能库（全部 v0.2.0.2 + Defense Triple）
│   ├── network-pentest/
│   ├── ai-safety-redteam-advanced/  # 新增
│   ├── identity-provider-attack/    # 新增
│   ├── data-loss-prevention-bypass/ # 新增
│   ├── edge-computing-security/     # 新增
│   ├── quantum-cryptography-transition/  # 新增
│   ├── hardware-side-channel-advanced/   # 新增
│   ├── 5g-6g-telecom-attack-advanced/    # 新增
│   └── ... (130 个原有域)
├── validation/                      # 自动化校验脚本
├── RELEASE-v0.2.0.{1-8}.md          # 8 个版本说明文档
├── PHASE2_PROGRESS.md               # Phase 2 标准化进度（100%）
└── GUIDE-*.md                       # 10 个 agent 平台使用指南
```

---

## 六、SKILL 标准说明

所有 SKILL 遵循 **Anthropic Agent Skills Open Standard**（2025），采用渐进式披露设计：

### 第一阶段（广告层）

YAML 前言 + `## Summary` 部分，在技能扫描时加载。

### 第二阶段（快速参考层）

`## Core Tools` + `## Methodology` 部分，在技能激活时加载。

### 第三阶段（详细层）

`## Practical Steps` + Defense Triple 部分，在任务执行时加载：

- **Defense Perspective**（防御视角，表格化）
- **Detection Methods**（检测方法，含 SIEM 规则）
- **Defense Evasion Techniques**（防御规避技术）

---

## 七、版本路线图

### 已发布版本

| 版本 | 日期 | 主要内容 |
|------|------|---------|
| v0.2.0.1 | 2026-07-16 | 项目战略定位与计划文档 |
| v0.2.0.2 | 2026-07-19 | 完成 8 个高优先级 SKILL 升级（53%） |
| v0.2.0.3 | 2026-07-21 | 完成累计 12 个高优先级 SKILL 升级（80%） |
| v0.2.0.4 | 2026-07-24 | Phase 1 第一阶段完成（15/15 = 100%）里程碑 |
| v0.2.0.5 | 2026-07-26 | Phase 2 Batch 1-2 完成（20 SKILLs）+ 文档基线 |
| v0.2.0.6 | 2026-07-27 | Phase 2 Batch 3-5 完成（30 SKILLs）半程里程碑 |
| v0.2.0.7 | 2026-07-28 | Phase 2 全部完成（100/100 = 100%）总 130/130 |
| **v0.2.0.8** | **2026-07-29** | **Task 1.3 完成（7 个新 SKILL）总 137 个 SKILL** 🎊 |

### 后续版本

| 版本 | 预计日期 | 主要内容 |
|------|---------|---------|
| v0.2.0.9 | 2026-08-02 | Task 1.4 完成（文档输出：手册/速查表/索引/矩阵） |
| v0.2.0.10 | 2026-08-09 | Task 1.5 完成（自动化：CI/CD + lint 脚本） |
| **v0.2.1** | **2026-08-23** | **Phase 1 全部完成，发布稳定版本** |

### Phase 1 全程目标

- ✅ SKILL 总数：130 → **137**（Task 1.3 完成）
- ✅ 平均完成度：95.4% → **100%**（Defense Triple 全覆盖）
- ✅ 防御视角覆盖率：86% → **100%**
- ⬜ 自动化校验脚本：1 个 → **5 个**（Task 1.5）

---

## 八、下一版本（v0.2.0.9）预告

下一版本将完成 **Task 1.4 - 文档输出**，输出 6 个核心文档：

1. **docs/SKILL_HANDBOOK.md** — 完整使用手册（含所有 137 SKILLs）
2. **docs/QUICK_REFERENCE.md** — 速查表（按场景）
3. **docs/TOOLS_LIFECYCLE.md** — 工具版本管理指南
4. **docs/SKILL_INDEX.json** — 机器可读索引
5. **docs/DOMAIN_MATRIX.md** — SKILL × Tools 覆盖热力图
6. **CHANGELOG.md** — v0.2.0.2 ~ v0.2.1 更新说明

---

## 九、致谢与协作

### 工作模式

```
人类工程师：战略意图、需求定义、质量审查
              ↓
Claude Code：扫描分析、内容生成、验证执行
              ↓
人类工程师：决策反馈、优先级调整
              ↓
迭代优化
```

### Phase 1 关键决策时间线

- **2026-07-17**：启动 Phase 1，选择 Direction B（全量优化）
- **2026-07-19**：修正版本基线至 v0.2.0.2
- **2026-07-24**：Phase 1 Phase 1 完成（15/15 = 100%）里程碑
- **2026-07-26**：Phase 2 全部完成（130/130 = 100%）→ v0.2.0.7
- **2026-07-29**：**Task 1.3 完成（7 个新 SKILL）→ v0.2.0.8** 🎊

### 反馈渠道

- **GitHub Issues**：[https://github.com/brucesongs/kali-claw/issues](https://github.com/brucesongs/kali-claw/issues)
- **GitHub Discussions**：[https://github.com/brucesongs/kali-claw/discussions](https://github.com/brucesongs/kali-claw/discussions)
- **Pull Requests**：欢迎通过 PR 贡献

### 相关文档

- [RELEASE-v0.2.0.1.md](RELEASE-v0.2.0.1.md) ~ [RELEASE-v0.2.0.7.md](RELEASE-v0.2.0.7.md) — 全部历史版本
- [CLAUDE.md](CLAUDE.md) — 项目结构与开发指南
- [CHANGELOG.md](CHANGELOG.md) — 完整变更日志

---

## 十、版本签名

```
版本编号：v0.2.0.8
发布日期：2026-07-29
分支：main（合并自 task1.3/new-skills + task1.3/skill-2）
版本类型：里程碑版本（Task 1.3 完成 - 7 个新 SKILL）
项目地址：https://github.com/brucesongs/kali-claw
许可证：参见仓库 LICENSE 文件
```

**kali-claw 团队**  
**2026 年 7 月 29 日**
