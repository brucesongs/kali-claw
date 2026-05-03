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

---

# kali-claw v0.1.2 技能补充调研报告

*Generated: 2026-05-04 | Version: 0.1.1 → 0.1.2 | New Skills: 5 | Total: 36*

---

## 摘要

kali-claw v0.1.1 通过新增 6 个技能建立了从侦察到报告的全流程能力闭环。但在**操作质量保障、自主执行能力、经验积累、测试环境、安全边界**五个维度存在空白。v0.1.2 新增的 5 个技能正是针对这些空白进行补充，同时将 9 个未来技能按优先级纳入路线图。

---

## 一、v0.1.1 能力空白分析

| 空白维度 | 具体问题 | 影响场景 |
|----------|----------|----------|
| **验证保障** | 漏洞发现后缺少系统化的确认流程，假阳性和假阴性无法有效过滤 | 提交的赏金报告被退回；渗透测试报告出现不可重现的发现 |
| **自主执行** | 重复性任务（批量扫描、迭代爆破）缺少安全的自动化框架 | 效率低下；手动重复操作引入人为错误 |
| **经验积累** | 每次渗透测试的经验无法结构化沉淀，跨会话知识流失 | 相同错误重复出现；工具使用经验无法复用 |
| **测试环境** | 缺少标准化的本地靶场环境，无法安全验证攻击技术 | 无法离线练习；无法在隔离环境中验证工具行为 |
| **安全边界** | 缺少操作安全护栏，自动化或批量操作时可能越界 | 超出授权范围测试；对目标系统造成意外影响 |

---

## 二、新增技能定位分析（v0.1.2，+5 个技能）

### `verification-loop` — 多阶段验证协议

| 维度 | 分析 |
|------|------|
| **填补空白** | 系统化的发现验证和假阳性消除 |
| **与现有技能的关系** | 是 `security-bounty-hunter` 和 `vulnerability-assessment` 的质量保障层。赏金猎手在提交前必须通过验证循环；漏洞评估结果必须经过假阳性消除 |
| **核心价值** | 六阶段验证流程（前置条件→执行观察→后置条件→独立确认→假阳性消除→证据文档），要求每个发现至少通过两种独立方法确认 |

**协同示例：** `vulnerability-assessment` 扫描发现 10 个 SQL 注入点，`verification-loop` 对每个点执行独立确认，最终确认 3 个为真实漏洞，7 个为误报。

---

### `autonomous-loops` — 安全自主执行

| 维度 | 分析 |
|------|------|
| **填补空白** | 重复性任务的安全自动化框架 |
| **与现有技能的关系** | 横切所有技能。为 `network-pentest`、`osint`、`vulnerability-assessment` 等提供批量执行能力 |
| **核心价值** | 四种循环模式（顺序管道、监控循环、批处理、学习循环），每种都内建范围锁、速率限制、证据日志和错误处理 |

**协同示例：** 对 C 段目标执行 `network-pentest` 的端口扫描时，使用 `autonomous-loops` 的顺序管道模式逐主机扫描，每步记录证据，遇到关键错误自动停止。

---

### `continuous-learning` — 持续学习

| 维度 | 分析 |
|------|------|
| **填补空白** | 跨会话经验积累和知识结构化 |
| **与现有技能的关系** | 与 `chronicle` 知识管理系统互补。chronicle 记录事件，continuous-learning 提取可复用的知识模式 |
| **核心价值** | 学习循环（模式检测→结构化提取→置信度评分→分层存储→交叉引用），三级记忆层（短期战术/中期技术/长期战略） |

**协同示例：** 在多次渗透测试中发现某 WAF 对特定 SQL 注入绕过技术的拦截规律，`continuous-learning` 将此模式提取并存储为高置信度知识，下次遇到相同 WAF 时可直接调用。

---

### `docker-patterns` — 安全测试实验室

| 维度 | 分析 |
|------|------|
| **填补空白** | 标准化的本地靶场和隔离测试环境 |
| **与现有技能的关系** | 为所有攻击技术技能提供安全的练习环境。`web-sqli` 可以在 DVWA 中练习，`network-pentest` 可以在多服务网络靶场中练习 |
| **核心价值** | 五种 Docker 模式（脆弱 Web 应用靶场、网络渗透靶场、多阶段攻击链靶场、一次性测试、工具校准），所有环境仅绑定 127.0.0.1 |

**协同示例：** 学习 `web-sqli` 时，使用 `docker-patterns` 的 DVWA 靶场搭建本地练习环境，在隔离环境中安全地实践注入技术。

---

### `safety-guard` — 安全护栏

| 维度 | 分析 |
|------|------|
| **填补空白** | 操作安全边界和紧急响应机制 |
| **与现有技能的关系** | 横切所有技能，为每个操作提供安全前置检查。与 `autonomous-loops` 的范围锁配合，确保自动化操作不越界 |
| **核心价值** | 三级安全模式（谨慎/冻结/守卫），危险命令拦截表，参与规则模板，事件响应协议 |

**协同示例：** `autonomous-loops` 执行批量扫描前，`safety-guard` 检查每个目标是否在授权范围内，拦截超出范围的命令，遇到异常行为触发冻结模式。

---

## 三、技能类型更新

v0.1.2 的 36 个技能三层分类：

### 第一层：攻击技术技能（17 个）
`api-security`, `binary-reverse`, `cloud-security`, `container-security`, `crypto-attacks`, `mobile-security`, `network-pentest`, `password-attack`, `post-exploitation`, `web-access-control`, `web-auth-bypass`, `web-sqli`, `web-ssrf`, `web-xss`, `wifi-pentest`, `social-engineering`, `security-bounty-hunter`

### 第二层：安全分析技能（10 个）
`vulnerability-assessment`, `osint`, `recon-osint`, `digital-forensics`, `insecure-design`, `security-misconfiguration`, `logging-monitoring`, `supply-chain-security`, `security-review`, `repo-scan`

### 第三层：元技能（6 个）
`deep-research`, `terminal-ops`, `search-first`, `verification-loop`, `autonomous-loops`, `continuous-learning`

### 基础设施技能（3 个）
`chronicle`, `docker-patterns`, `safety-guard`

---

## 四、未来路线图

### 第一梯队 — 高优先级（v0.1.3+）

| 技能 | 定位 | 填补空白 |
|------|------|----------|
| `codebase-onboarding` | 快速代码库理解 | 白盒审计前的架构理解和依赖映射 |
| `knowledge-ops` | 知识图谱管理 | 跨会话知识持久化和关系维护 |

### 第二梯队 — 中优先级（v0.1.4+）

| 技能 | 定位 | 填补空白 |
|------|------|----------|
| `article-writing` | 安全报告撰写 | 标准化渗透测试报告和安全文章产出 |
| `browser-qa` | 浏览器安全测试 | 客户端漏洞验证和 JavaScript 调试 |
| `data-scraper-agent` | 结构化数据提取 | CVE 数据库和威胁情报自动化收集 |
| `exa-search` | 高级网络搜索 | 安全研究专用搜索能力 |

### 第三梯队 — 未来探索

| 技能 | 定位 | 填补空白 |
|------|------|----------|
| `mcp-server-patterns` | MCP 服务器集成 | 安全工具 API 封装和自定义集成 |
| `council` | 多视角分析 | 安全决策的多专家视角评估 |
| `strategic-compact` | 战略上下文管理 | 长期项目的上下文压缩和优先级信息保留 |

---

## 五、结论

v0.1.2 新增的 5 个技能从五个维度强化了 kali-claw 的操作能力：

1. **质量保障** — `verification-loop` 确保每个发现都经过独立验证
2. **自动化能力** — `autonomous-loops` 提供安全的批量执行框架
3. **经验沉淀** — `continuous-learning` 将操作经验转化为可复用知识
4. **训练环境** — `docker-patterns` 提供标准化的本地靶场
5. **安全边界** — `safety-guard` 为所有操作提供安全护栏

v0.1.1 建立了全流程能力闭环；v0.1.2 通过质量保障、自动化、经验积累和安全边界，将 kali-claw 从"能做"提升为"做得好、做得安全"。

---

## 附录：v0.1.2 变更清单

| 变更类型 | 内容 |
|----------|------|
| 新增技能 | `verification-loop` (SKILL.md) |
| 新增技能 | `autonomous-loops` (SKILL.md) |
| 新增技能 | `continuous-learning` (SKILL.md) |
| 新增技能 | `docker-patterns` (SKILL.md) |
| 新增技能 | `safety-guard` (SKILL.md) |
| 更新文件 | `VERSION` (0.1.1 → 0.1.2) |
| 更新文件 | `README.md` (31→36 技能域, 路线图, 版本号) |
| 更新文件 | `CHANGELOG.md` (新增 v0.1.2 条目) |
| 更新文件 | `UPDATELOG.md` (新增 v0.1.2 调研报告) |
