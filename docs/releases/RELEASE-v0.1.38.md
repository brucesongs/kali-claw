# kali-claw v0.1.38 发布公告 — 让 10 个技能"上了个台阶"

**发布日期**：2026-06-27
**版本号**：v0.1.38（技能域总数 107 不变，纯质量提升版本）

---

## 这次更新干了啥？

简单说：**给 10 个已有技能"补课"**。不新增领域，而是把那些"内容还不够深、案例还不够多"的技能做厚。10 个技能平均提升了 +3.25 分，4 个冲进了 Distinguished（卓越）段位，4 个底部技能从 84-85 分跃升到 87-91 分。

为啥要做这个？因为这些技能覆盖的是**当下最常被攻击的目标**——AD 证书服务、邮件网关、AI 大模型、加密实现、K8s 容器、企业身份、移动 App、DNS、区块链。把它们研究透了，红队和防御方都有现成的"作战手册"。

---

## 新增了哪些"作战能力"？（重点讲攻防价值）

### 1. Active Directory 证书服务攻击（ad-cs-abuse）

以前 Kali-claw 有 AD LDAP 攻击、Kerberos 攻击，但漏了**证书服务**这块——而现实里，勒索软件 Black Basta、Akira、Royal 全都用 AD CS 横向移动。这版本补上了：

- **ESC1-ESC15 完整 15 类滥用模式** —— 从低权限用户到 Domain Admin 的标准路径
- **PetitPotam + NTLM Relay → AD CS** —— 把 DC 当跳板，让攻击者拿到域控证书
- **Certifried (CVE-2022-26923)** —— 微软 2022 年 5 月才修的 0day，能让任意用户冒充机器账户
- **10 条检测规则**（KQL / Splunk SPL / Sigma 格式）—— 蓝队拿到就能直接部署

**攻防价值**：红队拿到了一套从入口到拿域的完整 playbook；蓝队拿到了对应的检测规则集，攻防双方都有了基准。

### 2. 邮件基础设施攻击（email-security-deep）

之前的邮件攻击偏 AiTM（中间人钓鱼）和发件技巧，但**邮件网关本身怎么绕、邮件链路怎么取证**没人深挖。新增了：

- **Proofpoint / Defender Safe Links / Mimecast / Cisco ESA** —— 主流邮件网关的规避技巧
- **MTA 链取证** —— 邮件被中转过几次、被哪个 MTA 加了什么 Received 头，Python 脚本一键解析
- **CVE-2024-21413 MonikerLink** —— Outlook 远程代码执行，2024 年 2 月才披露的 9.8 分漏洞
- **OAuth + Outlook Rules 邮箱持久化** —— 不改密码也能持续监听受害者邮箱

**攻防价值**：钓鱼演练从"能骗到点击"升级到"绕过网关 + 落地后持久驻留"；防御方知道了该监控哪些 Graph API 调用和 Mail-Flow Rule 创建事件。

### 3. AI 安全 / LLM 越狱研究（ai-security）

AI 应用越来越普及，但**怎么系统地攻击 LLM**这块国内资料少。这版本补上：

- **GCG（Greedy Coordinate Gradient）** —— 通过梯度优化生成对抗后缀，让 GPT-4/Claude 失去安全过滤
- **AutoDAN / PAIR / TAP** —— 自动化越狱算法族
- **Crescendo 多轮越狱** —— 微软 2024 年研究，通过 5-10 轮对话渐进式突破
- **真实案例** —— Bing Sydney 暴走、ChatGPT 插件系统提示词泄露、Anthropic many-shot 越界
- **3 个评测基准**（HarmBench / AdvBench / StrongREJECT）—— 给红队方法论工具

**攻防价值**：AI 红队从"灵感驱动"变成"工程化方法"；防御方拿到了 Llama Guard / Lakera / Azure Prompt Shields 的对比选型清单。

### 4. 后量子密码迁移 + 侧信道（crypto-attacks）

Shor 算法一旦跑在量子计算机上，RSA/ECC 全军覆没——但**NIST 2024 年刚发布的 PQC 标准**（ML-KEM、ML-DSA）实现层漏洞百出：

- **KyberSlash** —— 通过除零时间侧信道恢复 Kyber 私钥
- **Injecting Crystals** —— Dilithium 签名错误注入攻击
- **ChipWhisperer 功耗分析 Lab** —— 在 STM32 上实操捕获 AES/ML-KEM 功耗轨迹
- **TLS 1.3 后量子握手仿真** —— 用 OQS-OpenSSL 模拟 X25519Kyber768 握手

**攻防价值**：在 PQC 大规模部署前，红队/研究员能提前发现实现层漏洞；蓝队拿到 crypto-agility（密码敏捷性）框架，能在算法被破解时快速切换。

### 5. 企业身份攻击（cloud-identity-attack）—— 这个是底部大补

之前的 cloud-identity-attack 只有 1 个 guide，整体分数 83.8 是工作区最低。这版本一口气加了 2 个深度 guide，专门讲：

- **Entra ID（原 Azure AD）** —— PRT（Primary Refresh Token）盗窃、ROADtools、Conditional Access 绕过 7 种姿势
- **Okta / Auth0** —— Cookie 劫持、JWT 算法混淆（CVE-2022-23539）、SAML Golden SAML 攻击
- **真实事件复盘** —— SolarWinds SUNBURST、Lapsus$ 攻 Okta、Cloudflare Okta 中招、23andMe 凭据填充

**攻防价值**：身份是现代企业的"新边界"，这版本把 Entra ID + Okta + Auth0 三大 IdP 的攻击面讲透了。

### 6. 移动 App 插桩（mobile-app-instrumentation）—— 也是底部大补

移动 App 安全研究里**SSL Pinning 绕过**是入门门槛，但没有系统目录。这版本给了：

- **18 个 Pinning 库的绕过矩阵** —— TrustKit / AFNetworking / OkHttp Pinner / Conscrypt / Flutter BoringSSL，每个都有对应技术
- **iOS** —— Frida gadget 嵌入、SSL Kill Switch 3、越狱检测绕过（Shadow / A-Bypass / Liberty）、CVE-2023-41974 kfd 链
- **Android** —— Magisk + LSPosed + Zygisk、Play Integrity 绕过（pif）、Flutter 反向（reflutter）、React Native Hermes 反编译

**攻防价值**：移动安全研究员拿到一份"全平台插桩工具目录"；App 开发方拿到了反逆向加固清单。

### 7. DNS 攻击（dns-attacks）—— 加了 1,290 行新 payload

DNS 是网络侦察的"白月光"，但很多新攻击没人系统整理：

- **DNS 重绑定** —— 浏览器跨域攻击，Tesla Model S 2014 中招的套路
- **DNS 隧道（现代版）** —— DoH/DoT/DoQ 三种加密 DNS 都能用来绕过出口控制
- **SAD DNS（CVE-2020-25705）** —— 通过 ICMP 侧信道攻陷 DNS 缓存
- **子域名接管** —— 9 大云厂商（Azure/AWS S3/GitHub Pages/Heroku/Shopify/Fastly/...）的指纹库 + 复现脚本

**攻防价值**：红队外网打点多了 5-6 条新路径；蓝队拿到 Suricata / Zeek 的检测规则模板。

### 8. 区块链 DeFi 重入（blockchain-web3）—— 加了 1,423 行新 payload

DeFi 攻击每年都几十亿美金损失，但攻击模式分类一直乱：

- **ERC-777 / ERC-721 / ERC-1155 重入变体** —— 通过代币回调触发非预期执行
- **只读重入**（read-only reentrancy） —— Curve 2023 年 7 月被攻陷的元凶
- **MEV（最大可提取价值）** —— 三明治攻击、闪电贷套利、跨链 MEV
- **跨链桥攻击** —— Wormhole / Nomad / Ronin 的真实 PoC 复现
- **真实事件深度复盘** —— Curve (2023, $70M)、Euler Finance (2023, $197M)、Beanstalk (2022, $182M)

**攻防价值**：DeFi 审计员拿到了现代重入分类；智能合约开发者拿到了 Slither / Mythril / Echidna 的对比清单和 CI 集成方案。

### 9. Kubernetes 容器逃逸（kubernetes-attack）

K8s 攻击以前停留在"提权到 cluster-admin"，但**从容器逃逸到宿主机**这块没人系统讲：

- **runc CVE-2024-21626（Leaky Vessels）** —— 2024 年最严重的容器逃逸
- **21 个内核 CVE**（含补丁 commit） —— 从容器内打内核：CVE-2022-0185、CVE-2022-0847 Dirty Pipe、CVE-2024-1086 nf_tables
- **Kubelet 10250 端口利用** —— `/run`、`/exec`、`/pods` 完整利用链
- **Falco / Tracee eBPF 检测规则** —— 蓝队配套检测

**攻防价值**：容器逃逸从"理论"变成"21 条具体路径"；云原生防御方拿到了对应的 eBPF 检测签名。

### 10. 存储/SAN 厂商深挖（storage-san-attack）

企业存储设备里放着全部数据，但**NetApp / Dell EMC / Pure / QNAP / Synology / TrueNAS** 这些厂商具体怎么打没人系统讲：

- **NetApp ONTAP** —— SVM 突围、NDMP 快照窃取、CVE-2022-43982 内置账户
- **QNAP** —— QuickConnect SQL 注入 CVE-2021-28799（Qloader 勒索入口）、Photo Station LFI
- **Dell EMC Unity / PowerStore** —— Unisphere 反序列化 CVE-2021-36342、JWT 绕过 CVE-2022-24316
- **DeadBolt / eCh0raix / Qlocker** —— 三大针对 NAS 的勒索家族 TTP 复盘

**攻防价值**：企业 IT 知道自己的存储设备有哪些暴露面；存储厂商拿到了对应加固清单。

---

## 技能分数变化

| 技能 | 旧分 | 新分 | Δ | 等级变化 |
|------|------|------|----|---------|
| email-security-deep | 91.3 | **92.0** | +0.7 | Excellent → **Distinguished** |
| ad-cs-abuse | 91.0 | **93.0** | +2.0 | Excellent → **Distinguished** |
| ai-security | 89.3 | **92.3** | +3.0 | Excellent → **Distinguished** |
| crypto-attacks | 89.0 | **92.2** | +3.2 | Excellent → **Distinguished** |
| storage-san-attack | 89.5 | 91.5 | +2.0 | Excellent（距 Distinguished 0.5） |
| kubernetes-attack | 89.5 | 90.2 | +0.7 | Excellent（距 Distinguished 1.8） |
| cloud-identity-attack | 83.8 | **89.0** | +5.2 | C 轨超目标 +2.0 |
| mobile-app-instrumentation | 84.5 | **87.3** | +2.8 | C 轨达标 |
| dns-attacks | 84.6 | **91.1** | +6.5 | C 轨超目标 +4.1 |
| blockchain-web3 | 84.6 | **90.2** | +5.6 | C 轨超目标 +3.2 |

**整体：**
- Distinguished（92+）：28 → **32**（首次破 30）
- 平均分：88.46 → **88.75**
- 最低分：83.8 → **85.1**（再无技能 <85，质量债务清零）
- 107/107 Excellent+ 维持 100%

---

## 下个版本（v0.1.39）会做啥？

经过两轮 E 计划（v0.1.36 + v0.1.38），下一版会**回到扩面路线**——选 4 个长期"该做但还没做"的现代企业安全栈领域，每个加 1 个完整技能域。候选方向（最终版前会跟用户确认）：

- **CI/CD 与软件供应链攻击**（Jenkins / GitLab CI / GitHub Actions / Argo CD / Flux / 依赖混淆 / xz-utils / SolarWinds 类后门）
- **PAM（特权访问管理）攻击**（CyberArk / BeyondTrust / Delinea / One Identity / ManageEngine / WALLIX —— 8 大厂商）
- **CSPM / CASB 攻击**（Wiz / Prisma Cloud / Defender for Cloud / Netskope —— 攻击防御性平台本身）
- **SASE / SSE 攻击**（Zscaler / Netskope / Cloudflare One / Cisco Umbrella —— 现代网络边缘）

选这些是因为：BlackCat、LockBit、Royal 这些勒索家族的攻击路径**就是 PAM + CI/CD + Cloud + SASE 的组合拳**，补上之后 Kali-claw 对现代企业攻防场景的覆盖就基本完整了。

---

## 总结

_v0.1.38 给 10 个核心技能补课：4 个进 Distinguished（AD CS、邮件、AI、密码学），4 个底部技能从 84-85 跳到 87-91。新增的 11 个深度指南（约 1.35 万行）覆盖了红队/蓝队最迫切需要的现代攻防场景：从 AD 证书滥用到 LLM 越狱，从 PQC 实现层漏洞到 K8s 容器逃逸。32 个 Distinguished 首次破 30，质量债务清零，107/107 维持 100% Excellent+。下版本将扩面 4 个新企业安全栈领域。_
