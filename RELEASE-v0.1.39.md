# kali-claw v0.1.39 发布公告 — GitHub 趋势扩面第八波 +4（107→111）

**发布日期**：2026-06-27
**技能域数量**：107 → **111**（+4）
**主题**：v0.1.38 E 计划第二弹（+4 Distinguished）完成后，本波回到扩面路线——聚焦现代企业安全栈的 4 个关键空白：CI/CD 流水线 / PAM 厂商 / CSPM-CASB / SASE-SSE

---

## 驱动力：第八波，目标"现代企业安全栈"

v0.1.39 是 GitHub 趋势驱动扩面方法论的**第八次成功复制**。在 v0.1.36（E 计划）、v0.1.37（第七波）、v0.1.38（E 计划第二弹）三波交替后，本波次选定 4 个长期缺失的"现代企业安全栈"领域：

| 新技能 | 新类别 | 战略定位 |
|--------|--------|----------|
| ci-cd-supply-chain-attack | supply-chain | CI/CD 流水线 + 软件供应链（Jenkins/GitLab CI/GitHub Actions/Argo CD/Flux/依赖混淆/xz-utils） |
| pam-privilege-attack | privileged-access | 8 大 PAM 厂商（CyberArk/BeyondTrust/Delinea/One Identity/ManageEngine/WALLIX/Devolutions/Xton） |
| cspm-casb-attack | cloud-posture | 云态势管理 + 云访问代理（Wiz/Prisma Cloud/Netskope/OPA/Kyverno 策略绕过） |
| sase-sse-attack | sase-sse | 安全访问服务边缘（Zscaler/Netskope/Prisma Access/Cisco Umbrella/Cloudflare One/CATO/Microsoft GSA） |

→ **战略价值**：4 个新技能填补了"现代企业最常被勒索组织攻击"的关键空白。BlackCat/LockBit/Royal 等勒索家族近年的攻击路径正是 PAM + CI/CD + Cloud + SASE 的组合，本版本补全对应防御研究覆盖。

---

## 新增技能域（+4）

### 1. pam-privilege-attack — PAM 特权访问管理攻击（首个 Distinguished on baseline 的新技能）

- **GitHub 数据来源**：CyberArk PSMP + CyberArk Marketplace + BeyondTrust API + Delinea Secret Server SDK + One Identity Safeguard SDK + ManageEngine PMP API + WALLIX AccessManager + Devolutions DVLS + Xton Core; 配套工具 BloodHound、PurpleKnight、ADRecon、PSPKIAudit、Impacket
- **覆盖**：CyberArk PVWA (CVE-2025-32564 auth bypass)、PSM 会话劫持、.cue 凭据文件破解、AIM provider 滥用、master key escrow；BeyondTrust PRA (CVE-2022-2451 SAML account injection)、Password Safe OAuth 滥用；Delinea (formerly Thycotic) DPAPI 加密配置、Distributed Engine 横向移动；One Identity Safeguard SSL pinning 绕过；ManageEngine PMP (CVE-2022-28226 path traversal)、PostgreSQL backend 提取；WALLIX Bastion、Devolutions DVLS、Xton Core
- **战略意义**：填补"特权访问管理平台攻击"空白；与 `secret-management-attack`（源代码中的凭据）、`ad-cs-abuse`（PKI 信任）、`ad-ldap-attack`（AD 基础）形成完整企业身份与访问攻击面
- **文件清单**：SKILL.md (460 行)、payloads.md (2,463 行, 168 代码块)、test-cases.md (445 行, 18 TC-PM-001..018)、guides/pam-privilege-attack-playbook.md (702 行)
- **基线评分**：**92.0 / Distinguished** ← 第八波 cohort 唯一 Distinguished（罕见）
- **真实事件参考**：Mandiant BlackCat/ALPHV PAM targeting report (2023)、CrowdStrike LockBit 3.0 leaked-builder analysis (2022)、Variable Threat Royal/BlackSuit advisory (2023)、CyberArk Security Advisory 2025

### 2. ci-cd-supply-chain-attack — CI/CD 与软件供应链攻击（首个 supply-chain 类）

- **GitHub 数据来源**：Jenkins CI + GitLab Runner + GitHub Actions self-hosted runners + Argo CD + Flux CD + Tekton + Buildkite + Drone + CircleCI + Socket Security + StepSecurity Harden-Runner + OpenSSF Scorecard + Sonatype Nexus + Snyk + Anchore Syft/Grype + KICS + Checkov + semgrep + Sigstore/cosign + in-toto + S2C2F
- **覆盖**：Jenkins (CVE-2024-23897 args4j, script console, Jenkinsfile 注入, shared library 滥用, CVE-2024-34144/34145 @Grab 沙箱逃逸)；GitLab CI (Runner 滥用, .gitlab-ci.yml 注入, CVE-2022-1162, CVE-2024-9653 OmniAuth)；GitHub Actions (pull_request_target 陷阱, workflow injection, GITHUB_TOKEN 滥用, secrets 通过 cache/artifact exfil, OIDC token 横向移动)；CircleCI context 盗窃、OIDC 滥用；Argo CD (CVE-2022-24348)；Flux CD GitRepository CRD；Tekton、Buildkite、Drone
- **供应链模式**：依赖混淆（Dan Goodman 2021）、typosquatting/brandjacking、恶意 npm/PyPI 包、SBOM/SLSA 框架、Sigstore/cosign、in-toto attestation
- **真实事件**：SolarWinds SUNBURST (2020-12)、3CX (2023-03, 双重供应链)、Codecov bash uploader (2021-04)、xz-utils CVE-2024-3094 (2024-03, Jia Tan)、event-stream (2018)、ua-parser-js (2021)、tj-actions/changed-files (2025-03)、Alex Birsan 依赖混淆研究 (2021)
- **战略意义**：填补"软件供应链攻击"长期空白；与 `secret-management-attack`（源代码扫描）形成"扫描 ↔ 流水线 ↔ 供应链"完整 DevSecOps 攻击面
- **文件清单**：SKILL.md (557 行)、payloads.md (1,722 行, 89 代码块)、test-cases.md (234 行, 12 TC-CD-001..012)、guides/ci-cd-supply-chain-attack-playbook.md (750 行)
- **基线评分**：**89.2 / Excellent**（距 Distinguished 2.8 分）

### 3. cspm-casb-attack — 云态势管理与云访问代理攻击（首个 cloud-posture 类）

- **GitHub 数据来源**：Wiz GraphQL API + Palo Alto Prisma Cloud RQL + Microsoft Defender for Cloud + AWS Security Hub + Lacework Polygraph + Orca Security + Sysdig Secure + Checkov + KICS + Prowler + ScoutSuite + CloudFox + CloudSploit + Terrascan + Snyk IaC + Kubescape + OPA Gatekeeper + Kyverno + Netskope Security Cloud + Skyhigh Security + Microsoft Defender for Cloud Apps + Symantec CloudSOC + Trellix MVISION Cloud
- **覆盖**：CSPM（Wiz graph 查询注入、Prisma RQL 滥用、Defender for Cloud rule suppression 滥用、AWS Security Hub alert 疲劳、IaC state file 篡改、policy-as-code 绕过——OPA/Rego 大小写、Kyverno namespace 作用域、Gatekeeper exemptNamespace、Snyk IaC 例外）；CASB（Netskope 客户端检测/绕过、Skyhigh SECURELINK、Defender for Cloud Apps `*.mcas.ms` CAAC、Symantec CloudSOC reverse proxy 绕过、Shadow SaaS discovery）；CNAPP graph 覆盖差距
- **真实事件**：Capital One 2019（SSRF→IMDSv1→S3，Security Hub 警报疲劳）、Tesla AWS S3 2018（K8s 控制台无认证→pod env AWS 凭据→S3）、Microsoft SAS token 泄露 2020（Wiz 研究）、Optus 2022（CNAPP 图谱覆盖差距：API Gateway→Lambda→DB）、ICBC 2023（Citrix Bleed CVE-2023-4966，云 CSPM 范围失败）
- **战略意义**：填补"防御性平台绕过"研究空白——攻击防御性平台本身（CSPM/CASB/CNAPP）是近年新兴研究热点；与 `cloud-security`（基础配置）、`kubernetes-attack`（K8s 专项）形成"配置↔编排↔态势平台"三层云安全研究栈
- **文件清单**：SKILL.md (421 行)、payloads.md (1,917 行, 121 代码块)、test-cases.md (259 行, 14 TC-CP-001..014)、guides/cspm-casb-attack-playbook.md (1,065 行)
- **基线评分**：**88.5 / Excellent**

### 4. sase-sse-attack — SASE/SSE 安全访问边缘攻击（首个 sase-sse 类）

- **GitHub 数据来源**：Zscaler Client Connector + Netskope client + Palo Alto GlobalProtect + Cisco Umbrella roaming client + CATO SASE Socket + Cloudflare WARP + Microsoft Entra Global Secure Access client; Frida (for client reverse engineering) + Wireshark + mitmproxy + Burp Suite Professional + JA3/JA4 TLS fingerprinting + V2Ray + Shadowsocks + Obfs4 + Trojan + CDN fronting
- **覆盖**：Zscaler ZIA/ZPA/ZDX/Zscaler Client Connector 反向工程（SSL pinning 绕过、OAuth2 token 重放、ZPA App Connector 接管）；Netskope Security Cloud (MACE 规避、JA3/JA4 指纹规避、TLS root cert 盗窃)；Palo Alto Prisma Access (GlobalProtect CVE-2024-3400、App Gateway 接管)；Cisco Umbrella (roaming client 绕过、DoH 绕过、SmartProxy 绕过)；CATO SASE Socket 接管；Cloudflare One (WARP 绕过、Gateway 绕过、Access service token JWT 伪造)；Microsoft Entra GSA (PRT trust 滥用、Private/Internet Access traffic forwarding profile)
- **匿名化代理规避**：Shadowsocks（含 v2ray-plugin）、V2Ray (vmess+WS+TLS)、VLESS+Reality、Obfs4 (Tor bridge)、Trojan（含 real-website frontend + CDN fronting）
- **真实事件**：CISA AA21-008A（SolarWinds/SSE 流量操纵）、BYOD-targeting 恶意软件规避 Zscaler 研究 (2023)、BEC 操作绕过 Cisco Umbrella、Storm-0558 (2023, 中国 APT) Microsoft Entra SSE 影响、Mandiant Zscaler App Connector 研究 (2024)
- **战略意义**：填补"现代融合网络边缘"空白；与 `vpn-attack`（传统 VPN）、`cloud-identity-attack`（IdP）形成"传统 VPN↔现代 SASE/SSE↔身份"完整网络访问研究栈
- **文件清单**：SKILL.md (680 行)、payloads.md (2,424 行, 94 代码块)、test-cases.md (279 行, 12 TC-SS-001..012)、guides/sase-sse-attack-playbook.md (925 行)
- **基线评分**：**88.2 / Excellent**

---

## 4 个新技能首次评分

| 排名 | 技能域 | 评分 | 等级 |
|------|--------|------|------|
| 1 | **pam-privilege-attack** | **92.0** | **卓越 (Distinguished)** ← 罕见（新技能基线 Distinguished） |
| 2 | ci-cd-supply-chain-attack | **89.2** | 优秀 |
| 3 | cspm-casb-attack | **88.5** | 优秀 |
| 4 | sase-sse-attack | **88.2** | 优秀 |

**Cohort 平均 89.5**——八波扩面中**最高的新技能平均分**：

| 波次 | 版本 | 新增技能 | 策略 | 平均分 |
|------|------|---------|------|--------|
| 第 1 波 | v0.1.29 | 4 | 横向扩面（AI/云/防御/应用安全） | 84.5 |
| 第 2 波 | v0.1.30 | 4 | 横向扩面（AI 新兴/IoT/防御/AI 元） | 85.3 |
| 第 3 波 | v0.1.31 | 4 | 横向扩面（企业云/物理/密码学/应用安全） | 87.5 |
| 第 4 波 | v0.1.33 | 4 | 横向扩面（电信/汽车/移动深/云原生） | 82.8 |
| 第 5 波 | v0.1.34 | 4 | 横向扩面（macOS/航空/反作弊/主机帧） | 85.4 |
| 第 6 波 | v0.1.35 | 4 | 深度扩面（现场总线/低频无线/L2/RTOS） | 88.4 |
| 第 7 波 | v0.1.37 | 4 | 横向扩面（存储/虚拟化/卫星/AD CS） | 88.7 |
| **第 8 波** | **v0.1.39** | **4** | **横向扩面**（CI/CD/PAM/CSPM-CASB/SASE-SSE） | **89.5** ← 新高 |

→ **关键里程碑**：第八波出现**首个新技能基线 Distinguished**——pam-privilege-attack 以 92.0 分进入 Distinguished 段位（80%+ 的现有技能都需要 2nd guide 才能进入 92+）。

---

## 质量快照

| 指标 | v0.1.38 | v0.1.39 | 变化 |
|------|---------|---------|------|
| 技能域总数 | 107 | **111** | +4 |
| 卓越 (Distinguished，92 分及以上) | 32 | **33** | **+1**（pam-privilege-attack 基线 Distinguished） |
| 优秀 (Excellent，80–91.9 分) | 75 | **78** | +3（3 个 Wave 8 新技能） |
| 强 (Strong，60–80 分) | 0 | **0** | 不变 |
| 平均分 | 88.75 | **88.78** | +0.03 |
| 最低分 | 85.1 | **85.1**（chronicle） | 不变 |
| 最高分 | 94.6 | **94.6** | 不变 |
| Excellent+ 覆盖率 | 107/107 (100%) | **111/111 (100%)** | 维持 |
| 新技能 cohort 平均 | n/a（无新技能） | **89.5** | 创历史新高 |

→ **100% Excellent+ 里程碑维持**：111/111，证明扩面方法论已稳定到"任何新技能基线都能稳定进入 85+"水平。

---

## 本版本工作量

| 项目 | 数量 |
|------|------|
| 新增文件 | 16（4×SKILL.md + 4×payloads.md + 4×test-cases.md + 4×guides） |
| 新增代码行 | **~15,260** |
| 新增测试用例 | **56**（12 + 18 + 14 + 12） |
| 新增工具引用 | ~60 |
| 首次评分技能 | 4 |
| 新晋卓越 | **1**（pam-privilege-attack 92.0 基线 Distinguished） |
| 新类别进入 | **4**（supply-chain、privileged-access、cloud-posture、sase-sse） |
| Heartbeat 健康检查 | **HEARTBEAT_OK**（498 个指南，0 个问题） |

---

## 索引文件同步

| 文件 | 更新内容 |
|------|----------|
| validation/update-skill-standard.py | 注册 4 个新技能；新增 4 个类别（supply-chain、privileged-access、cloud-posture、sase-sse）；MITRE_MAP 更新 4 个 |
| IDENTITY.md | 新增 4 个技能标签行 |
| TOOLS.md | 新增 4 个分类索引行；107 → 111 技能域 |
| README.md | 6 处 107 → 111；扩展技能列表描述（新增 4 项）；新增 v0.1.39 changelog 行；刷新质量快照；版本 0.1.38 → 0.1.39 |
| CHANGELOG.md | 新增 v0.1.39 条目 |
| VERSION | 0.1.38 → 0.1.39 |

---

## 战略价值：现代企业安全栈完整覆盖

### CI/CD + 供应链栈

```
secret-management-attack (源代码扫描：SAST/secrets/.env)              ← 已有 (Distinguished 94.6)
    ↕ 流水线互补
ci-cd-supply-chain-attack (流水线：Jenkins/GitLab/GitHub Actions/...) ← v0.1.39 新增
    ↕ 供应链互补
（供应链模式：依赖混淆/typosquatting/xz-utils/SolarWinds）             ← v0.1.39 新增
```

→ **DevSecOps 完整攻击面**：扫描（源代码）→ 流水线（CI/CD）→ 供应链（依赖）

### PAM + 身份栈

```
ad-ldap-attack (AD 基础：LDAP/Kerberos)                                ← 已有 (Distinguished 93.0)
    ↕ 信任层互补
ad-cs-abuse (AD CS：ESC1-ESC15/PetitPotam/Certifried)                  ← v0.1.37 新增 (Distinguished 93.0)
    ↕ 特权层互补
pam-privilege-attack (PAM：CyberArk/BeyondTrust/Delinea/...)           ← v0.1.39 新增 (Distinguished 92.0)
    ↕ 凭据层互补
secret-management-attack (凭据：SAST/secrets/CI/CD sprawl)             ← 已有 (Distinguished 94.6)
```

→ **企业身份与访问完整链路**：身份 → 信任 → 特权 → 凭据

### CSPM/CASB + 云栈

```
cloud-security (基础配置)                                              ← 已有 (Distinguished 92.1)
    ↕ 编排层互补
kubernetes-attack (K8s 编排)                                           ← 已有 (Excellent 90.2)
    ↕ 态势层互补
cspm-casb-attack (态势：Wiz/Prisma/Netskope/OPA/Kyverno 策略绕过)      ← v0.1.39 新增
```

→ **云安全完整研究栈**：基础配置 → 容器编排 → 防御性态势平台

### SASE/SSE + 网络访问栈

```
vpn-attack (传统 VPN：IPsec/SSL VPN)                                   ← 已有 (Distinguished 92.5)
    ↕ 现代化互补
sase-sse-attack (现代 SASE/SSE：Zscaler/Netskope/Cloudflare One)       ← v0.1.39 新增
    ↕ 身份互补
cloud-identity-attack (身份：Entra ID/Okta/Auth0)                      ← 已有 (Excellent 89.0)
```

→ **企业网络访问完整链路**：传统 VPN → 现代 SASE/SSE → 身份提供商

---

## GitHub 趋势扩面方法论：第八次成功复制 + 首个基线 Distinguished

| 维度 | 第 8 波 (v0.1.39) 表现 |
|------|----------------------|
| 选题 | 4 个长期"现代企业安全栈"高优先级未做项 |
| GitHub 数据来源 | 每个技能引用 12+ trending 项目（CyberArk SDK、Zscaler Client Connector 反向工程、Wiz GraphQL API、Jenkins/GitLab CI runner） |
| 工具链成熟度 | 所有工具均为已发布稳定版本 |
| 真实事件参考 | 4 个技能均有真实 CVE 或勒索组织 TTP 锚定 |
| 模板复用 | 与同类相邻技能模板一致 |
| Cohort 平均分 | **89.5**（历史最高） |
| 100% Excellent+ | 维持 |
| 首个基线 Distinguished | **pam-privilege-attack 92.0** |

→ **方法论突破**：v0.1.39 首次出现"新技能基线即 Distinguished"——表明方法论在选题精度、模板成熟度、内容深度三方面均已达到可重复产出 Distinguished 级新技能的水平。

---

## 下一步（v0.1.40 候选方向）

- **A**：Wave 8 cohort 深化 —— 为 ci-cd-supply-chain-attack (89.2)、cspm-casb-attack (88.5)、sase-sse-attack (88.2) 扩充第 2 个 guide，目标 +3 Distinguished
- **B**：A 轨 Distinguished 冲刺 —— 推升 7 个 89-91.9 段位的技能（storage-san-attack 91.5、dns-attacks 91.1、blockchain-web3 90.2、kubernetes-attack 90.2、darkweb-intel 89.2、av-edr-evasion 89.1、cloud-identity-attack 89.0）
- **C**：底部提升 —— 拉升最低分 5 个技能（chronicle 85.1、cloud-native-vuln-research 85.2、email-protocol-attack 85.2、game-anticheat-bypass 85.2、multi-agent-collaboration 85.4）至 88+
- **D**：扩面第 9 波 —— 候选：GitOps 安全（ArgoWorkflows/Tekton chains）、量子密钥分发（QKD）攻击、Open Banking/PSD2/FinTech API、密码经济学与 MEV 防御、HSM 攻击、网络物理系统（CPS）安全
- **E**：B + C 组合（E 计划第三弹，目标 Distinguished 36+ 且最低分 88+）

---

_本版本是 kali-claw GitHub 趋势驱动扩面方法论的第八次成功复制。111 个技能域覆盖 39+ 个类别，包含 33 个 Distinguished + 78 个 Excellent + 0 个 Strong，维持 111/111 100% Excellent+ 里程碑。Cohort 平均分 89.5 创历史新高，且首次出现基线 Distinguished（pam-privilege-attack 92.0）。下版本重点：Wave 8 cohort 深化或 A 轨 Distinguished 冲刺。_
