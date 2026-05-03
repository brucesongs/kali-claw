# kali-claw v0.1.1 技能补充调研报告

*Generated: 2026-05-04 | Version: 0.1.0 → 0.1.1 | New Skills: 6 | Total: 31*

---

## 摘要

kali-claw v0.1.0 包含 25 个安全技能领域，覆盖 OWASP Top 10 攻击技术、网络渗透、OSINT、云安全等核心渗透测试环节。但在**工作流编排、情报研究、代码审计、漏洞变现**四个维度存在空白。v0.1.1 新增的 6 个技能正是针对这些空白进行补充。本报告分析现有技能矩阵的覆盖情况、新增技能的定位逻辑、以及二者之间的协同关系。

---

## 一、现有技能矩阵分析（v0.1.0，25 个技能）

### 1.1 按攻击链阶段分布

| 攻击链阶段 | 覆盖技能 | 数量 |
|------------|----------|------|
| 侦察 (Reconnaissance) | `recon-osint`, `osint` | 2 |
| 武器化 (Weaponization) | `password-attack`, `social-engineering` | 2 |
| 漏洞利用 (Exploitation) | `web-sqli`, `web-xss`, `web-ssrf`, `web-auth-bypass`, `web-access-control`, `api-security`, `crypto-attacks`, `network-pentest` | 8 |
| 后渗透 (Post-Exploitation) | `post-exploitation`, `wifi-pentest` | 2 |
| 持久化/横向移动 | `container-security`, `cloud-security` | 2 |
| 防御与分析 | `digital-forensics`, `logging-monitoring`, `insecure-design`, `security-misconfiguration` | 4 |
| 专项领域 | `binary-reverse`, `mobile-security`, `supply-chain-security`, `vulnerability-assessment` | 4 |
| 知识管理 | `chronicle` | 1 |

### 1.2 能力空白识别

通过分析攻击链覆盖和实际渗透测试工作流，识别出以下四个关键空白：

| 空白维度 | 具体问题 | 影响场景 |
|----------|----------|----------|
| **情报研究** | 缺少系统性多源情报整合能力，OSINT 仅限于被动收集工具操作 | 面对新 CVE 时无法快速产出深度分析报告；无法系统化研究威胁组织和攻击技术 |
| **漏洞变现** | 缺少从"发现漏洞"到"提交报告"的结构化流程 | 漏洞评估停留在扫描结果层面，无法产出可提交的 PoC 和赏金报告 |
| **工作流编排** | 缺少终端操作的规范化流程和证据链管理 | 渗透测试过程中操作不可追溯，结果不可重现 |
| **代码审计** | 缺少白盒审计方法论，仅有黑盒漏洞利用技能 | 面对源代码时无法系统化分析攻击面和依赖风险 |

---

## 二、新增技能定位分析（v0.1.1，+6 个技能）

### 2.1 每个技能的定位与填补的空白

#### `deep-research` — 情报研究

| 维度 | 分析 |
|------|------|
| **填补空白** | 系统性多源情报研究 |
| **与现有技能的关系** | 补充 `osint` 和 `recon-osint`。OSINT 侧重工具驱动的被动信息收集（域名枚举、邮件抓取），deep-research 侧重主题级深度调查（CVE 深挖、威胁组织画像、攻击技术研究） |
| **差异** | OSINT = "目标有什么" → deep-research = "这件事的来龙去脉" |
| **核心价值** | 六阶段研究流程（范围定义→搜索策略→多源检索→深度阅读→交叉验证→报告综合），要求每个结论有来源引用 |

**协同示例：** 渗透测试前先用 `osint` 收集目标域名和子域，再用 `deep-research` 深入研究目标使用的某个 CMS 的已知漏洞生态。

---

#### `security-bounty-hunter` — 漏洞变现

| 维度 | 分析 |
|------|------|
| **填补空白** | 从漏洞发现到可提交报告的完整流程 |
| **与现有技能的关系** | 是 `vulnerability-assessment` 的下游延伸。漏洞评估产出扫描结果清单，赏金猎手从中筛选可利用项并产出 PoC |
| **差异** | vulnerability-assessment = "有什么弱点" → security-bounty-hunter = "哪个弱点可以证明利用并获得赏金" |
| **核心价值** | 明确界定高价值漏洞模式（SSRF、认证绕过、反序列化 RCE 等），过滤低信号噪音，提供标准报告结构 |

**协同示例：** `vulnerability-assessment` 扫描发现目标存在多个 SQL 注入点，`security-bounty-hunter` 从中筛选远程可达的注入点，构造最小 PoC 并撰写赏金报告。

---

#### `terminal-ops` — 工作流编排

| 维度 | 分析 |
|------|------|
| **填补空白** | 规范化终端操作流程和证据链管理 |
| **与现有技能的关系** | 横切所有技能。任何需要在终端执行命令的场景都应遵循 terminal-ops 的证据协议 |
| **差异** | 不是攻击技术技能，而是**操作纪律技能** — 确保每步操作可追溯、可验证、可重现 |
| **核心价值** | 五阶段执行流程（确认目标→读取失败面→带证据执行→窄幅变更→精确状态报告），精确的状态词汇体系 |

**协同示例：** 执行 `network-pentest` 的端口扫描时，按 `terminal-ops` 的证据链协议记录每条 nmap 命令的时间戳、参数、输出文件和状态，确保渗透测试报告可审计。

---

#### `search-first` — 效率提升

| 维度 | 分析 |
|------|------|
| **填补空白** | 利用已有工具和利用代码，避免重复造轮子 |
| **与现有技能的关系** | 横切所有技能。在执行任何技能的具体任务前，先通过 search-first 检查现有工具和利用代码 |
| **差异** | 不是攻击技能，而是**效率技能** — 决策矩阵决定是直接使用、修改适配、组合利用还是自建 |
| **核心价值** | 四级决策矩阵（Use → Modify → Compose → Build），搜索源覆盖 Exploit-DB、GitHub、Metasploit、Nuclei 模板 |

**协同示例：** 面对 `web-sqli` 场景，先通过 `search-first` 搜索目标版本的已知 SQL 注入 PoC，找到现成利用代码后直接使用，而非从零开始手工测试。

---

#### `security-review` — 代码审计方法论

| 维度 | 分析 |
|------|------|
| **填补空白** | 系统性安全审计清单和白盒测试方法论 |
| **与现有技能的关系** | 为所有攻击技术技能提供**系统级审计框架**。`web-sqli` 教你如何注入，`security-review` 教你在审计时如何系统性寻找注入点 |
| **差异** | 攻击技能 = "如何利用特定漏洞" → security-review = "如何全面审计一个系统的安全状态" |
| **核心价值** | 覆盖 OWASP Top 10 全部类别的检查清单，七步审计流程，五级严重性分类体系 |

**协同示例：** 对目标应用执行 `security-review` 的系统审计时，在"注入缺陷"环节调用 `web-sqli`、`web-xss`、`web-ssrf` 的具体技术进行深入测试。

---

#### `repo-scan` — 源码资产审计

| 维度 | 分析 |
|------|------|
| **填补空白** | 白盒测试前的代码库资产分类和攻击面映射 |
| **与现有技能的关系** | 是 `security-review` 的前置技能。先通过 repo-scan 了解代码库结构，再通过 security-review 进行深度安全审计 |
| **差异** | security-review = "审计安全问题" → repo-scan = "先搞清楚代码库里有什么" |
| **核心价值** | 四级模块判定（Core Asset / Extract & Update / Rebuild / Deprecate），跨技术栈覆盖（C/C++、Java、Web、Python、Go、Rust、PHP），嵌入式第三方库检测 |

**协同示例：** 白盒渗透测试前，先用 `repo-scan` 扫描目标代码库，发现嵌入了一个 2015 年版本的 FFmpeg，判定为"Extract & Update"并标记高安全优先级，然后用 `security-review` 深入审计该组件。

---

## 三、技能协同矩阵

新增技能与现有技能的关键协同关系：

```
                         ┌─────────────┐
                         │ search-first │ ← 所有技能执行前的效率检查
                         └──────┬──────┘
                                │
    ┌───────────┐    ┌──────────┴──────────┐    ┌────────────────┐
    │  osint    │───→│   deep-research      │───→│ security-bounty│
    │  recon    │    │   (情报深度研究)      │    │   -hunter      │
    └───────────┘    └──────────────────────┘    └────────────────┘
                                                          │
    ┌───────────┐    ┌──────────────────────┐             │
    │  vuln     │───→│  security-review     │─────────────┘
    │  -assess  │    │  (系统性安全审计)     │
    └───────────┘    └──────────┬───────────┘
                                │
    ┌───────────┐    ┌──────────┴───────────┐
    │  supply   │───→│     repo-scan         │
    │  -chain   │    │  (源码资产审计)        │
    └───────────┘    └──────────────────────┘

                         ┌─────────────┐
                         │ terminal-ops │ ← 所有终端操作的证据协议
                         └─────────────┘
```

### 协同场景示例

| 场景 | 技能组合 | 流程 |
|------|----------|------|
| Bug Bounty 完整流程 | `osint` → `deep-research` → `vulnerability-assessment` → `security-bounty-hunter` | 收集目标 → 研究技术栈 → 扫描漏洞 → 构造 PoC 提交 |
| 白盒渗透测试 | `repo-scan` → `security-review` → `web-sqli`/`web-xss` | 代码资产分类 → 安全审计 → 深度利用 |
| 新 CVE 响应 | `search-first` → `deep-research` → `terminal-ops` | 搜索现有 PoC → 深入研究影响范围 → 带证据验证 |
| 红队演练 | `terminal-ops` → `recon-osint` → `network-pentest` → `post-exploitation` | 全程按证据链协议执行，确保可审计 |

---

## 四、技能类型分类

v0.1.1 的 31 个技能可分为三层：

### 第一层：攻击技术技能（17 个）
直接对应具体攻击技术和漏洞利用：
`api-security`, `binary-reverse`, `cloud-security`, `container-security`, `crypto-attacks`, `mobile-security`, `network-pentest`, `password-attack`, `post-exploitation`, `web-access-control`, `web-auth-bypass`, `web-sqli`, `web-ssrf`, `web-xss`, `wifi-pentest`, `social-engineering`, `security-bounty-hunter`

### 第二层：安全分析技能（8 个）
提供系统级分析框架和方法论：
`vulnerability-assessment`, `osint`, `recon-osint`, `digital-forensics`, `insecure-design`, `security-misconfiguration`, `logging-monitoring`, `supply-chain-security`, `security-review`, `repo-scan`

### 第三层：元技能（3 个）
提升其他技能的执行质量：
`deep-research`, `terminal-ops`, `search-first`

### 跨层技能（3 个）
覆盖多个层级：
`chronicle`, `deep-research`, `terminal-ops`

---

## 五、覆盖率评估

### 5.1 按 MITRE ATT&CK 战术覆盖

| 战术 | v0.1.0 | v0.1.1 | 提升 |
|------|--------|--------|------|
| Reconnaissance | ✓ (osint, recon) | ✓+ (deep-research) | 深度情报研究 |
| Resource Development | — | ✓ (search-first) | 工具/PoC 发现 |
| Initial Access | ✓ (web-*, social) | ✓ | — |
| Execution | ✓ (network, sqli) | ✓ | — |
| Persistence | ✓ (post-exploitation) | ✓ | — |
| Privilege Escalation | ✓ (post-exploitation) | ✓ | — |
| Defense Evasion | ✓ (logging-monitoring) | ✓+ (terminal-ops) | 操作隐匿 |
| Credential Access | ✓ (password) | ✓ | — |
| Discovery | ✓ (recon) | ✓+ (repo-scan) | 白盒发现 |
| Lateral Movement | ✓ (network, post) | ✓ | — |
| Collection | ✓ (osint) | ✓ | — |
| Command and Control | ✓ (network) | ✓ | — |
| Exfiltration | ✓ (post) | ✓ | — |
| Impact | ✓ | ✓+ (security-bounty-hunter) | 影响证明 |

### 5.2 按渗透测试方法论覆盖（PTES）

| 阶段 | v0.1.0 | v0.1.1 | 变化 |
|------|--------|--------|------|
| Intelligence Gathering | ✓ | ✓✓ | +deep-research: 多源情报综合 |
| Threat Modeling | ✓ (insecure-design) | ✓ | — |
| Vulnerability Analysis | ✓ (vuln-assess) | ✓✓ | +security-review: 系统化审计 |
| Exploitation | ✓✓ | ✓✓ | +security-bounty-hunter: 精准利用 |
| Post-Exploitation | ✓ | ✓ | — |
| Reporting | ✗ | ✓ | +terminal-ops: 证据链 + 通用报告格式 |

**关键提升：** Reporting 阶段从无覆盖变为有覆盖 — terminal-ops 的证据链协议和 bounty-hunter 的报告结构直接服务于渗透测试报告产出。

---

## 六、结论

v0.1.1 新增的 6 个技能不是对现有技能的简单数量叠加，而是从四个维度**补强了 kali-claw 作为完整渗透测试智能体的能力闭环**：

1. **情报闭环** — `deep-research` 补强了从信息收集到情报产出的转化能力
2. **变现闭环** — `security-bounty-hunter` 补强了从漏洞发现到可提交报告的转化能力
3. **流程闭环** — `terminal-ops` + `search-first` 补强了操作纪律和效率
4. **白盒闭环** — `security-review` + `repo-scan` 补强了源代码审计能力

v0.1.0 的 kali-claw 是一个**攻击技术全面的渗透测试工具库**；v0.1.1 将其升级为一个**从侦察到报告全流程覆盖的渗透测试智能体**。

---

## 附录：v0.1.1 变更清单

| 变更类型 | 内容 |
|----------|------|
| 新增技能 | `deep-research` (SKILL.md + payloads.md + test-cases.md) |
| 新增技能 | `security-bounty-hunter` (SKILL.md) |
| 新增技能 | `terminal-ops` (SKILL.md) |
| 新增技能 | `search-first` (SKILL.md) |
| 新增技能 | `security-review` (SKILL.md) |
| 新增技能 | `repo-scan` (SKILL.md) |
| 新增文件 | `VERSION` (0.1.1) |
| 新增文件 | `CLAUDE.md` (Claude Code 工作区指引) |
| 更新文件 | `README.md` (25→31 技能域, 版本号) |
