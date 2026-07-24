# kali-claw v0.2.0.3 版本说明

> **版本编号**：v0.2.0.3  
> **发布日期**：2026 年 7 月 21 日  
> **版本类型**：质量升级版本  
> **上一版本**：v0.2.0.2（2026-07-19）  
> **下一里程碑**：v0.2.0.4（Phase 1 第一阶段全部完成）

---

## 一、版本概述

kali-claw 是基于 OpenClaw 框架构建的 AI 渗透测试智能体工作空间，覆盖 127 个安全技能域，掌握 Kali Linux 2025-2 全部 518 款安全工具。本仓库作为智能体的结构化知识库与配置系统，配套自动化脚本完成校验、编排与报告工作。

v0.2.0.3 是 kali-claw **Phase 1 SKILL 库完善项目**的第三个迭代版本，本次发布的核心目标是**对 4 个高优先级安全技能域进行深度质量升级**，重点补齐检测方法（Detection Methods）与防御规避技术（Defense Evasion Techniques）两大防御侧章节。

截至本版本发布，Phase 1 第一阶段已完成 **12/15 个高优先级 SKILL**（完成度 80%），覆盖网络安全、Web 安全、后渗透、凭证攻击、社会工程、OSINT、云安全等核心领域。

---

## 二、版本亮点

### 1. 四个核心 SKILL 完成深度升级

本次发布的四个 SKILL 全部具备完整的"防御三件套"：**防御视角（Defense Perspective）**、**检测方法（Detection Methods）**、**防御规避技术（Defense Evasion Techniques）**。

| SKILL 名称 | 中文领域 | 主要新增内容 |
|-----------|---------|------------|
| privilege-escalation | 权限提升 | Linux/Windows/容器三层检测体系；6 类规避技术 |
| social-engineering | 社会工程 | 商业邮件欺诈（BEC）检测、深度伪造对抗、二维码钓鱼 |
| osint | 开源情报收集 | 蜜罐识别、Canary 令牌检测；7 类隐身侦察技术 |
| cloud-security | 云安全 | 云审计日志监控、STS 角色链追踪、容器逃逸规避 |

### 2. 防御视角全面表格化

所有 SKILL 的防御视角章节由原来的简单条目列表升级为**多层防御矩阵**，每个 SKILL 至少覆盖 5 个防御层，并提供：

- 具体的防护措施（如 VLAN 隔离 + 微分段）
- 部署建议（如 IMDSv2 强制启用）
- 关键注意事项（如误报率控制、季度审查节奏）

### 3. 检测方法章节对接主流 SOC 工具链

所有新增的检测方法章节均提供**可直接复制使用**的 SIEM 检测规则，包括：

- Splunk SPL 查询语句
- Sigma 规则文件路径
- Windows Sysmon 事件 ID（1/10/13 等）
- AWS GuardDuty 检测器配置
- Linux auditd 规则

### 4. 翻译质量全面清理

消除了上一版本遗留的**机器翻译中英文混杂**问题（如 "attack surfaceminimumize"、"Defense Perspectivethenisdisablea切notnecessary" 等），所有 SKILL 文档达到生产级专业度。

---

## 三、详细更新内容

### 1. privilege-escalation（权限提升）

**适用场景**：渗透测试中从普通用户权限提升至 root 或 SYSTEM。

#### 检测方法（新增 4 类）

- **Linux 主机检测**：SUID 二进制滥用、sudo 配置异常、Cron 任务篡改、内核利用签名、Capabilities 滥用
- **Windows 主机检测**：令牌模拟、UAC 绕过、服务漏洞利用、LSASS 内存访问、SAM/NTDS 转储
- **容器场景检测**：逃逸尝试（如访问 `/proc/1/root`）、kubelet API 异常调用、`CAP_SYS_ADMIN` 能力使用
- **SIEM 规则**：Sysmon Event ID 1/10/13、Linux auditd、Splunk SPL 查询语句

#### 防御规避技术（新增 6 类）

- **隐身枚举**：使用系统自带二进制（LOLBins）替代自定义工具、AMSI 内存补丁、内存枚举
- **服务漏洞利用隐身**：DLL 劫持替代独立可执行文件、WMI 订阅替代 PsExec、DCOM 替代 RPC
- **令牌模拟隐身**：注入到 `explorer.exe` 等合法进程、使用被盗令牌避免新增登录事件
- **内核利用隐身**：在隔离主机上运行、版本精确匹配避免崩溃、纯内存利用
- **日志操纵**：选择性清除而非整文件删除、时间戳伪造（`timestomp`）、auditd 规则暂停
- **容器逃逸隐身**：Sidecar 注入替代新建容器、Docker Socket 挂载、kubelet 替代 API Server、eBPF 规则绕过

### 2. social-engineering（社会工程）

**适用场景**：渗透测试中针对人员的攻击与防护。

#### 检测方法（扩展 4 类）

- **邮件网关指标**：SPF/DKIM/DMARC 验证失败、同形异义字域名（Homoglyph）、`Reply-To` 与 `From` 不一致、附件模式异常
- **Web/凭证窃取指标**：Modlishka/Evilginx 反向代理特征、新注册域名（<7 天）、表单 action URL 动态修改
- **行为/人员指标**：非工作时间资金转账请求、紧急性诱导（"ASAP"等关键词）、地理位置异常、报告节奏异常
- **SIEM 规则**：Splunk SPL、Sigma BEC 模式规则、Microsoft 365 ATP 反钓鱼策略、SOAR 自动化剧本

#### 防御规避技术（新增 6 类）

- **邮件绕过**：合法邮件中继滥用（Mailchimp/SendGrid/M365）、`Reply-To` 错位利用、显示名伪装、Unicode 同形异义字（西里尔字母 а）、会话劫持注入恶意链接
- **Web/凭证窃取**：反向代理钓鱼（Modlishka/Evilginx/Muraena）、Cloudflare Workers 滥用、Blob URL 规避扫描、开放重定向链、JS 按访问者类型分流
- **场景预设工程**：供应商冒充（信任传递）、内部团队伪装、MFA 疲劳 + 客服社工、AI 语音克隆（ElevenLabs）、实时深度伪造视频
- **载荷投递隐身**：短信优于邮件（98% vs 20% 打开率）、QR 码钓鱼（Quishing）规避邮件 URL 扫描、多部分 MIME 结构、密码保护压缩包、隐写术
- **持久化**：OAuth 同意钓鱼（无需凭证的持久访问）、会话令牌窃取优于凭证、隐藏邮箱规则、自动转发规则
- **追踪规避**：CSS-only 追踪（无图片像素）、每收件人唯一 URL、时间衰减链接、地理围栏链接

### 3. osint（开源情报收集）

**适用场景**：渗透测试前期对目标的情报收集。

#### 检测方法（新增 5 类）

- **网络层指标**：证书透明度日志监控、DNS 枚举模式、Shodan/Censys 暴露面监控、搜索引擎 dorking 检测、WHOIS 查询峰值
- **Web 基础设施指标**：子域名接管监控、Wayback Machine 泄露、GitHub dorking、Pastebin 监控
- **社会/人员侦察指标**：LinkedIn 抓取模式、Twitter 提及异常、招聘信息泄露技术栈、员工博客过度分享
- **蜜罐/诱饵检测**：Canary 令牌（Thinkst Canary）、蜜罐子域名（`vpn-internal.yourdomain.com`）、伪造的泄露数据、Honeydocs
- **SIEM 规则**：Splunk SPL 子域名枚举检测、Sigma 侦察规则、AWS CloudTrail 异常 API 调用、GitHub 审计日志监控

#### 防御规避技术（新增 7 类）

- **隐身侦察**：被动优先于主动（`crt.sh` 替代 `nmap`）、速率限制、分布式源 IP、非高峰时段、源端口伪造（`--source-port 53`）
- **搜索引擎 Dorking 隐身**：多引擎分散查询、自然语言替代明显操作符、Yandex/Baidu/Mojeek、缓存内容访问
- **社会工程侦察隐身**：LinkedIn Sales Navigator 替代抓取、Twitter API 替代浏览器抓取、浏览器指纹轮换、Burner 账号
- **暗网研究隐身**：Tor 网络访问、Tor + VPN 链式匿名、论坛一次性账号、Monero 替代比特币
- **代码仓库侦察**：GitHub API 替代网页搜索、本地克隆后搜索、私有 Fork 后扫描、TruffleHog 本地运行
- **邮件/用户枚举隐身**：避免 SMTP VRFY（被记录）、使用 M365 `GetCredentialType` API（无日志）、OAuth consentGrant 模式
- **云侦察隐身**：认证 API 替代匿名访问、S3 `ListObjectsV2` 使用合法凭证、Azure Storage Explorer 替代匿名 GET

### 4. cloud-security（云安全）

**适用场景**：AWS、Azure、GCP、Kubernetes 环境的安全评估。

#### 检测方法（新增 6 类）

- **云厂商审计日志**：AWS CloudTrail 全 API 调用、Azure Activity Log、GCP Audit Logs、Kubernetes Audit Log；监控 `DeleteTrail`、`StopLogging` 等反取证行为
- **身份与访问异常**：IMDS 元数据服务异常访问、STS AssumeRole 长链（A→B→C）、Service Account 密钥创建峰值、管理员角色即时分配、SSRF 元数据提取
- **存储/数据外泄**：S3 GetObject 突增、Bucket 策略变更为公开、EBS 快照共享至外部账号、AMI 发布为公开、Cloud Storage 出站流量异常
- **计算/容器指标**：EC2 UserData 包含反向 Shell、Lambda 创建带过度权限、ECS 特权任务、EKS Pod 创建异常
- **SIEM 规则**：Splunk SPL（AWS / K8s）、Sigma 规则、AWS GuardDuty、Microsoft Defender for Cloud、Falco 运行时检测
- **CSPM 态势管理**：公开 S3 桶持续扫描、对互联网开放的安全组、缺失加密、超过 90 天的 IAM 密钥

#### 防御规避技术（新增 6 类）

- **CloudTrail/日志规避**：禁用追踪、事件选择器操纵、日志文件 KMS 密钥禁用、VPC Flow Logs 篡改、跨区域操作（部分区域未配置追踪）
- **身份规避**：STS 角色链洗钱、跨账号角色假设、EC2 实例配置文件凭证滥用、长效密钥替代 STS、SAML 联邦伪造
- **计算隐身**：同区域 Lambda、Fargate 替代 EC2（无主机日志）、Spot 实例（瞬态）、Lightsail（日志更简略）、Lambda 层混淆代码
- **数据外泄隐身**：S3 跨区域复制（伪装为灾备）、EBS 快照复制、AMI 复制、Snowball 物理外泄、AWS Transfer Family SFTP、VPC 终端节点
- **容器/Kubernetes 规避**：Sidecar 注入替代新建 Pod、ServiceAccount 令牌窃取、匿名认证滥用、ConfigMap 嵌入 kubeconfig、CronJob 短生命周期 Pod、仅 hostPID/hostNetwork（无 privileged 标志）、多层镜像载荷隐藏
- **网络隐身**：VPC 对等连接、Transit Gateway 复杂路由、PrivateLink 私有 IP 空间、Direct Connect 专线、CloudFront/API Gateway 反向代理

---

## 四、Phase 1 累计成果

### 已完成 SKILL 清单（12 个）

**P0 核心域（3 个）**：

1. network-pentest（网络渗透测试）
2. post-exploitation（后渗透）
3. web-xss（跨站脚本攻击）

**P1 重要域（9 个）**：

4. web-sqli（SQL 注入攻击）
5. web-ssrf（服务端请求伪造）
6. web-auth-bypass（认证绕过）
7. api-security（API 安全）
8. password-attack（口令攻击）
9. privilege-escalation（权限提升）
10. social-engineering（社会工程）
11. osint（开源情报收集）
12. cloud-security（云安全）

### 质量指标对照

| 指标 | v0.2.0.1（升级前） | v0.2.0.3（本版本） | 提升 |
|------|-------------------|------------------|------|
| 高优先级 SKILL 处理数 | 0 / 15 | 12 / 15 | +12 |
| SKILL 版本统一 | 0% (各为 0.1.18) | 100% (统一 v0.2.0.2) | +100% |
| 防御视角表格化 | 部分 | 100% | 显著提升 |
| 检测方法章节 | 30% | 100% (12/12) | +70% |
| 防御规避技术章节 | 20% | 100% (12/12) | +80% |
| 翻译残留（中英混杂） | 多处 | 全部清零 | 100% 清理 |

### 安全域覆盖

```
网络攻击域       ✓ network-pentest
Web 攻击域       ✓ web-xss / web-sqli / web-ssrf / web-auth-bypass
凭证访问域       ✓ password-attack
后渗透域         ✓ post-exploitation / privilege-escalation
社会工程域       ✓ social-engineering
情报收集域       ✓ osint
API 安全域       ✓ api-security
云安全域         ✓ cloud-security
```

---

## 五、安装与使用

### 快速开始

```bash
# 克隆仓库
git clone https://github.com/brucesongs/kali-claw.git
cd kali-claw

# 启动 Claude Code
claude

# 初始化（自动加载所有 SKILL）
/init

# 自然语言安排工作（示例）
# "帮我分析 kali-claw 的所有技能，生成详细使用手册"
# "针对 web-xss 技能，给出完整攻击链与检测规则"
```

### 文件结构

```
kali-claw/
├── skills/                          # 130 个安全技能库
│   ├── network-pentest/
│   │   ├── SKILL.md                 # 主技能文件
│   │   ├── payloads.md              # 攻击载荷集合
│   │   ├── test-cases.md            # 结构化测试用例
│   │   └── guides/                  # 深度参考资料
│   ├── web-xss/
│   ├── api-security/
│   └── ...
├── validation/                      # 自动化校验脚本
├── RELEASE-v0.2.0.*.md              # 版本说明文档
└── PHASE1_*.md                      # Phase 1 执行计划
```

### 单 SKILL 使用示例

以 `web-xss` 为例：

```bash
# 查看 SKILL 主文件
cat skills/web-xss/SKILL.md

# 查看攻击载荷
cat skills/web-xss/payloads.md | head -50

# 查看测试用例
cat skills/web-xss/test-cases.md | head -30

# 查看深度指南
ls skills/web-xss/guides/
```

---

## 六、SKILL 标准说明

所有 SKILL 遵循 **Anthropic Agent Skills Open Standard**（2025），采用渐进式披露设计：

### 第一阶段（广告层）

YAML 前言 + `## Summary` 部分，在技能扫描时加载。

```yaml
---
name: web-xss
description: "XSS (Cross-Site Scripting) is an attack that injects malicious scripts into trusted websites."
version: "0.2.0.2"
compatibility:
  - openclaw
  - claude-code
  - cursor
  - windsurf
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
metadata:
  domain: web-attack
  owasp: "A03:2021-Injection"
  mitre: "T1189-Drive-by Compromise"
  last_reviewed: "2026-07-21"
---
```

### 第二阶段（快速参考层）

`## Core Tools` + `## Methodology` 部分，在技能激活时加载。

### 第三阶段（详细层）

`## Practical Steps` + `## Defense Perspective` + `## Detection Methods` + `## Defense Evasion Techniques` 部分，在任务执行时加载。

---

## 七、版本路线图

### 已发布版本

| 版本 | 日期 | 主要内容 |
|------|------|---------|
| v0.2.0.1 | 2026-07-16 | 项目战略定位与计划文档 |
| v0.2.0.2 | 2026-07-19 | 完成 8 个高优先级 SKILL 升级（P0 全部完成） |
| **v0.2.0.3** | **2026-07-21** | **完成累计 12 个高优先级 SKILL 升级（80%）** |

### 后续版本

| 版本 | 预计日期 | 主要内容 |
|------|---------|---------|
| v0.2.0.4 | 2026-07-22 | Phase 1 第一阶段完成（15/15 SKILL，100%） |
| v0.2.0.5 | 2026-07-29 | Phase 2 启动（标准化 95 个 SKILL）+ Task 1.3 启动 |
| v0.2.0.6 | 2026-08-05 | 完成 7 个新 SKILL 创建（AI 红队、IdP 攻击、DLP 绕过等） |
| v0.2.0.7 | 2026-08-12 | 文档输出体系完成（使用手册、速查表、覆盖矩阵等） |
| **v0.2.1** | **2026-08-23** | **Phase 1 全部完成，发布稳定版本** |

### Phase 1 最终目标

- SKILL 总数：130 → **150+**
- 平均完成度：95.4% → **98%+**
- 防御视角覆盖率：86% → **100%**
- 自动化校验脚本：1 个 → **5 个**

---

## 八、下一版本（v0.2.0.4）预告

下一版本将完成 Phase 1 第一阶段剩余 3 个 SKILL：

1. **container-security**（容器安全）
   - 新增检测方法（容器运行时异常、镜像漏洞扫描）
   - 新增防御规避（容器逃逸、镜像层混淆）

2. **binary-reverse**（二进制逆向）
   - 已有检测方法，补全防御规避技术
   - 新增 AI 辅助逆向工程对抗

3. **exploit-development**（漏洞利用开发）
   - 新增检测方法（调试器检测、沙箱识别）
   - 新增防御规避（反调试、反虚拟机）

完成后将发布 **v0.2.0.4 稳定版本**，正式启动 Phase 2（标准化 95 个 SKILL）。

---

## 九、致谢与协作

### 工作模式

kali-claw 的日常开发遵循以下协作模式：

```
人类工程师：战略意图、需求定义、质量审查
              ↓
Claude Code：扫描分析、内容生成、验证执行
              ↓
人类工程师：决策反馈、优先级调整
              ↓
迭代优化
```

### 反馈渠道

- **问题反馈**：[GitHub Issues](https://github.com/brucesongs/kali-claw/issues)
- **建议提交**：欢迎通过 GitHub Discussions 或 Pull Request
- **安全漏洞报告**：请通过负责任披露流程

### 相关文档

- [RELEASE-v0.2.0.1.md](RELEASE-v0.2.0.1.md) — 项目战略定位与长远规划
- [RELEASE-v0.2.0.2.md](RELEASE-v0.2.0.2.md) — v0.2.0.2 版本说明
- [CLAUDE.md](CLAUDE.md) — 项目结构与开发指南

---

## 十、版本签名

```
版本编号：v0.2.0.3
发布日期：2026-07-21
分支：phase1/skill-audit
版本类型：质量升级版本（Phase 1 进行中）
许可证：参见仓库 LICENSE 文件
```

**kali-claw 团队**  
**2026 年 7 月 21 日**
