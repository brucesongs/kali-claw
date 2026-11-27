# kali-claw v0.1.39 发布公告 — 给"现代企业安全栈"补 4 块拼图

**发布日期**：2026-06-27
**版本号**：v0.1.39（技能域 107 → **111**，新增 4 个域）

---

## 这次更新干了啥？

简单说：**补了 4 个长期"该做但还没做"的现代企业安全栈领域**。前几版（v0.1.36、v0.1.38）都在给已有技能"补课"，这一版回到扩面路线，新建 4 个完整技能域——每个都是 GitHub 上 trending、且对应近几年勒索组织攻击路径中"绕不开"的环节。

为啥要补这 4 块？因为 BlackCat、LockBit、Royal、Black Basta 这些勒索家族的攻击链**就是 PAM + CI/CD + Cloud + SASE 的组合拳**。少了任何一块，红队推演就断链，蓝队布防就有盲区。补齐之后，Kali-claw 对现代企业攻防场景的覆盖基本闭环了。

更有意思的是——这 4 个新技能里**有 1 个直接以 92.0 分进入了 Distinguished（卓越）段位**，这种"新技能基线即卓越"的情况是 8 波扩面以来的头一次。

---

## 新增了哪些"作战能力"？（重点讲攻防价值）

### 1. PAM 特权访问管理攻击（pam-privilege-attack）—— **基线即 Distinguished**

PAM 平台是企业的"金库钥匙保管箱"，所有的管理员密码、SSH 密钥、数据库账号都集中存在 CyberArk / BeyondTrust / Delinea 这些系统里。但**PAM 本身怎么打**之前国内几乎没系统资料。这版补上：

- **8 大 PAM 厂商全覆盖** —— CyberArk PVWA/PSM、BeyondTrust PRA、Delinea Secret Server、One Identity Safeguard、ManageEngine PMP、WALLIX Bastion、Devolutions DVLS、Xton Core
- **CyberArk CVE-2025-32564** —— PVWA 认证绕过，最新披露
- **BeyondTrust CVE-2022-2451** —— SAML 账户注入，直接以任意身份登录
- **ManageEngine PMP CVE-2022-28226** —— 未授权路径遍历
- **CyberArk `.cue` 凭据文件破解** —— 从 cred file 直接还原明文密码
- **BlackCat / LockBit 3.0 / Royal 的 PAM 攻击 TTP 复盘** —— Mandiant 2023、CrowdStrike 2022 报告引用

**攻防价值**：红队拿到一份"按厂商查战术"的作战手册；蓝队第一次有了 PAM 平台本身的监控事件清单（哪个 .cue 文件被读、哪个 OAuth token 被签、哪个 PSM 会话被劫持）。

### 2. CI/CD 与软件供应链攻击（ci-cd-supply-chain-attack）—— 填 DevSecOps 大空白

CI/CD 流水线是现代研发的"心脏"，但 Kali-claw 之前只有 `secret-management-attack`（管源代码里的 secrets），**管线本身怎么被攻陷**没人讲。SolarWinds、3CX、xz-utils 这些供应链事件一年比一年多，研究空白必须补：

- **Jenkins CVE-2024-23897**（args4j 漏洞） —— 任意文件读取，直接拿到 Jenkins 管理员
- **GitLab CI Runner CVE-2022-1162 / CVE-2024-9653 OmniAuth** —— 自托管 Runner 接管
- **GitHub Actions `pull_request_target` 陷阱** —— PR 标题里写命令就能拿到 secret token
- **Argo CD CVE-2022-24348** —— K8s GitOps 工具的标准应用凭据泄露
- **xz-utils CVE-2024-3094（Jia Tan 后门）** —— 2024 年 3 月最轰动的供应链事件，深度复盘
- **依赖混淆攻击**（Alex Birsan 2021 经典研究） —— 通过命名冲突让企业内部包被替换为外部恶意包
- **SolarWinds SUNBURST / 3CX 双重供应链 / Codecov bash uploader** —— 三大里程碑事件完整复盘

**攻防价值**：红队第一次有了"从开发流水线一路打到生产"的完整 playbook；防御方拿到了 OpenSSF Scorecard、StepSecurity Harden-Runner、Sigstore/cosign、in-toto attestation 的部署清单。

### 3. CSPM / CASB 攻击（cspm-casb-attack）—— 攻击"防御性平台本身"

这是个新兴研究热点——企业花大价钱买了 Wiz、Prisma Cloud、Netskope 这些平台，但**这些平台自己能不能真的拦住攻击者**？没人系统测过。这版补上：

- **Wiz 图查询注入** —— 通过 GraphQL 查询操纵 Wiz 的攻击路径图谱
- **OPA / Kyverno 策略绕过**（3 种姿势） —— Rego 大小写陷阱、namespace 作用域规避、Gatekeeper `exemptNamespace` 滥用
- **IaC 状态文件篡改**（Terraform state file） —— 改 state 让 CSPM 看不到真实配置
- **Netskope 客户端检测/绕过** —— BYOD 设备隐藏真实流量
- **Capital One 2019 复盘** —— SSRF→IMDSv1→S3，期间 AWS Security Hub 警报疲劳被利用
- **Optus 2022 复盘** —— CNAPP 图谱在 API Gateway→Lambda→DB 这条路径上完全没覆盖
- **Microsoft SAS token 2020 泄露**（Wiz 自己的研究） —— 高调曝光

**攻防价值**：红队第一次能系统性测试"CSPM 到底拦不拦得住"；蓝队拿到"哪些规则最容易被绕过"的对应加固清单。

### 4. SASE / SSE 攻击（sase-sse-attack）—— 现代网络边缘突破

VPN 攻击技能早就有，但**Zscaler、Netskope、Cloudflare One、Cisco Umbrella 这些现代 SASE/SSE 平台怎么绕**——也就是现代企业网络出口的"新边界"——一直没系统讲。这版补上：

- **Zscaler ZIA/ZPA/ZDX Client Connector 反向工程** —— Frida + 抓包还原，绕 SSL 检查
- **Netskope TLS 检查规避** —— 利用 JA3/JA4 指纹差异
- **Cisco Umbrella roaming client 绕过** —— DoH/DoT 直连外部 resolver
- **Cloudflare One WARP / Gateway / Access 绕过** —— JWT 伪造、Tunnel 操纵
- **PAN-OS GlobalProtect CVE-2024-3400** —— Prisma Access 底层漏洞
- **Microsoft Entra Global Secure Access** —— PRT trust 滥用、traffic forwarding profile 篡改
- **匿名化代理规避全套** —— Shadowsocks / V2Ray (vmess+WS+TLS) / VLESS+Reality / Obfs4 / Trojan + CDN fronting
- **Storm-0558（2023 中国 APT 攻陷 Microsoft）**、**Mandiant 2024 Zscaler App Connector 研究**

**攻防价值**：红队拿到"绕过企业 SSE 出口控制"完整路线图；防御方知道该监控 Client Connector 的什么遥测、怎么部署 continuous authorization（持续授权）模型。

---

## 4 个新技能首次评分

| 排名 | 技能域 | 分数 | 等级 | 备注 |
|------|--------|------|------|------|
| 1 | pam-privilege-attack | **92.0** | **Distinguished** | **首次出现"新技能基线即 Distinguished"** |
| 2 | ci-cd-supply-chain-attack | 89.2 | Excellent | 距 Distinguished 2.8 分 |
| 3 | cspm-casb-attack | 88.5 | Excellent | |
| 4 | sase-sse-attack | 88.2 | Excellent | |

**Cohort（同期）平均分：89.5**——**8 波扩面以来的历史最高**（前 7 波最高是 v0.1.37 的 88.7）。

**整体：**
- 技能域总数：107 → **111**
- Distinguished（92+）：32 → **33**（+1，pam-privilege-attack 基线即进）
- Excellent（80-91.9）：75 → **78**（+3）
- 平均分：88.75 → **88.78**
- 最低分 / 最高分：85.1 / 94.6（均不变）
- **111/111 Excellent+ 维持 100%**

---

## 下个版本（v0.1.40）会做啥？

v0.1.39 是扩面版本，按 Kali-claw 的"扩面↔质量"交替节奏，下一版**很可能回到质量提升路线**。三个候选方向（最终版前会跟用户确认）：

- **A. Wave 8 cohort 深化**：为 ci-cd-supply-chain-attack、cspm-casb-attack、sase-sse-attack 各加第 2 个 guide，目标把它们也推到 Distinguished。pam-privilege-attack 已经 92.0，可以选择继续冲分或保持。
- **B. A 轨 Distinguished 冲刺**：现在还有 7 个技能卡在 89-91.9 段位（storage-san-attack 91.5、dns-attacks 91.1、blockchain-web3 90.2、kubernetes-attack 90.2、darkweb-intel 89.2、av-edr-evasion 89.1、cloud-identity-attack 89.0）——再加 1 个 guide 文件大多能进 92+，目标 Distinguished 33→37-39。
- **C. 底部提升**：还有 5 个技能卡在 85-86（chronicle 85.1、cloud-native-vuln-research 85.2、email-protocol-attack 85.2、game-anticheat-bypass 85.2、multi-agent-collaboration 85.4），拉到 88+ 能让最低分再次抬升。
- **D. 扩面第 9 波**：候选——GitOps 安全、量子密钥分发（QKD）攻击、Open Banking / PSD2、HSM 攻击、CPS 网络物理系统。

我个人倾向 B（A 轨冲刺）——因为 7 个技能卡在 89-91.9 是"最容易摘的果子"，每个加 1 个 guide 就能让 Distinguished 数再翻一档。

---

## 总结

_v0.1.39 新增 4 个现代企业安全栈技能：PAM（基线 92.0 即 Distinguished，覆盖 8 大厂商）、CI/CD 与软件供应链（含 SolarWinds / xz-utils / 3CX 复盘）、CSPM/CASB（攻击防御性平台本身）、SASE/SSE（绕过 Zscaler / Netskope / Cloudflare One 等现代网络边缘）。Cohort 平均 89.5 创 8 波新高，首次出现新技能基线即 Distinguished。111/111 维持 100% Excellent+。补齐之后，Kali-claw 对 BlackCat / LockBit / Royal 等勒索家族攻击链的覆盖基本闭环。下版本预计回到质量提升路线。_
