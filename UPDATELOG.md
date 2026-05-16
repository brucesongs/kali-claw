# kali-claw v0.1.7 New Skill Domains Report

*Generated: 2026-05-16 | Version: 0.1.6 → 0.1.7 | New Skills: 4 | Total: 49*

---

## Summary

v0.1.7 adds 4 new FULL skill domains to kali-claw, expanding coverage into AI/LLM security, hardware/embedded systems, multi-agent coordination, and MCP tool integration. All 4 domains follow the FULL tier: SKILL.md + payloads.md + test-cases.md + guides/. IDENTITY.md is updated with 14 new Skill Tags rows (10 backfilled from v0.1.6 + 4 new).

---

## New Skill Domains

### 1. ai-security — AI/LLM System Attack and Defense

**ECC Pattern**: Learning Cycle  
**Files**: SKILL.md (283 lines) + payloads.md (648 lines) + test-cases.md (362 lines) + guides/llm-attack-methodology.md (476 lines)

**Coverage**:
- Direct prompt injection (8 payload variants: instruction override, delimiter confusion, role-play, token smuggling, zero-width spaces, base64, nested, continuation hijacking)
- Indirect injection via document/web/tool output poisoning
- Jailbreaking (DAN, developer mode, many-shot 20-pair, fictional framing, research framing)
- Model extraction probe sequences and training data extraction
- RAG poisoning document templates (3 variants)
- AI API fuzzing (parameter tampering, multimodal injection, rate limit probing)
- Attack surface enumeration with bash commands and STRIDE threat model applied to LLMs
- OWASP LLM Top 10 mapped to each test case (TC-AS-001 through TC-AS-006)

### 2. hardware-security — Hardware and Embedded System Security

**ECC Pattern**: Sequential Pipeline (Physical → Interface → Extract → Analyze → Exploit)  
**Files**: SKILL.md (192 lines) + payloads.md (580 lines) + test-cases.md (357 lines) + guides/embedded-firmware-analysis.md (404 lines)

**Coverage**:
- UART baud rate enumeration and serial connection commands
- JTAG discovery with JTAGulator + OpenOCD target configs for ARM Cortex/MIPS/AVR
- SPI/I2C logic analyzer capture procedures
- Firmware extraction: flashrom (CH341A/Bus Pirate), JTAG dump, U-Boot serial exfil, OTA interception
- Firmware analysis: binwalk -e, unsquashfs, jefferson (JFFS2), cramfsck, entropy analysis
- RFID/NFC attacks: Proxmark3 EM4100 and MIFARE Classic cloning + UID spoofing
- Fault injection setup with ChipWhisperer
- Credential/service hunting patterns in extracted firmware
- 5 test cases (TC-HS-001 to TC-HS-005), 4 rated Critical
- Firmware extraction decision tree (6 methods ranked by speed/reliability)

### 3. multi-agent-collaboration — Coordinated Multi-Agent Penetration Testing

**ECC Pattern**: Batch Processing (dispatch → parallel workers → aggregate)  
**Files**: SKILL.md (234 lines) + payloads.md (610 lines) + test-cases.md (371 lines) + guides/coordinated-pentest-playbook.md (339 lines)

**Coverage**:
- 4 collaboration models: attack phase decomposition, target parallelization, tool specialization, coordinator-worker
- Task decomposition templates with `{PLACEHOLDER}` variables for all 3 models
- 5 agent role prompts: Recon, Web Tester, Network Scanner, Binary Analyst, Report Writer
- Coordinator dispatch template covering all 6 lifecycle phases
- Standardized finding JSON schema for cross-agent aggregation
- 5-step deduplication checklist + 7-step conflict resolution decision tree
- Coverage verification matrix template
- 7 common failure modes with mitigations
- 5 test cases (TC-MC-001 to TC-MC-005) from simple parallel recon to full 7-agent coordinated pentest

### 4. mcp-server-patterns — MCP Security Tool Integration

**ECC Pattern**: Sequential Pipeline (analyze → design → implement → test → deploy)  
**Files**: SKILL.md (205 lines) + payloads.md (682 lines) + test-cases.md (446 lines) + guides/security-mcp-server-design.md (406 lines)

**Coverage**:
- Complete minimal MCP server scaffold (Python SDK, ~40 lines working code)
- 3 full tool implementations: nmap wrapper, nikto wrapper, generic safe command pattern
- Input validation snippets: IP/CIDR, URL, port range, file path allowlist, scope enforcement
- Authentication middleware with `hmac.compare_digest` constant-time comparison
- Thread-safe sliding-window rate limiter class
- JSON schemas for scan results, vulnerability findings, host enumeration
- Security testing commands: schema bypass, injection, auth bypass, rate limit testing
- 7 non-negotiable secure wrapping rules (no shell=True, allowlists, timeout, output sanitization, etc.)
- 5 test cases (TC-MP-001 to TC-MP-005) from basic wrapping to full security audit

---

## IDENTITY.md Update

14 new rows added to Skill Tags table:

| Row | Domain |
|-----|--------|
| Backfilled | Security Review, Repo Scan, Terminal Ops, Verification Loop, Docker Patterns, Search First, Autonomous Loops, Safety Guard, Chronicle, Continuous Learning |
| New (v0.1.7) | AI/LLM Security, Hardware Security, Multi-Agent Collaboration, MCP Server Patterns |

---

## Statistics

| Metric | v0.1.6 | v0.1.7 | Delta |
|--------|--------|--------|-------|
| Skill Domains | 45 | 49 | +4 |
| New Files Created | — | 16 | +16 |
| IDENTITY.md Rows | 18 | 32 | +14 |
| Total Lines Added | — | ~6,596 | — |

# kali-claw v0.1.6 基础设施技能补强报告

*Generated: 2026-05-14 | Version: 0.1.5 → 0.1.6 | Enhanced Skills: 10 | Total: 45*

---

## 摘要

v0.1.5 完成后，kali-claw 拥有 45 个技能域，其中 10 个仅有 SKILL.md（无 payloads.md / test-cases.md / guides/）。这些是 kali-claw 的基础设施技能——代理行为层（循环、验证、学习、安全）和工具层（终端操作、搜索、扫描、Docker、记录）。v0.1.6 为这 10 个技能补充操作手册，从"理解"升级到"可执行"。

---

## 一、补强策略

| 层级 | 技能 | 补充内容 | 新建文件数 |
|------|------|---------|-----------|
| **FULL** | `autonomous-loops`, `security-review` | payloads + test-cases + guides | 4×2=8 |
| **PARTIAL** | `repo-scan`, `terminal-ops`, `verification-loop`, `docker-patterns`, `search-first` | payloads + test-cases | 3×5=15 |
| **MINIMAL** | `continuous-learning`, `safety-guard`, `chronicle` | SKILL.md ECC Orchestration | 1×3=3 |

**新建 16 个文件** + **更新 15 个文件** = 31 次操作。技能数不变（45→45）。

---

## 二、FULL 补强详情

### autonomous-loops（元技能）

- `payloads.md` — Scope Lock 模板×4、速率限制配置、4种循环命令模板、错误处理响应模板
- `test-cases.md` — TC-AL-001~006（顺序管道、监控循环、批量扫描、学习循环、范围违规、速率回退）
- `guides/safe-autonomous-pentest.md` — 自主vs手动决策矩阵、Scope Lock 构建、循环模式组合、监控干预
- SKILL.md — 添加 Supplementary Files 引用 + Meta-Skill Orchestration

### security-review（安全审计）

- `payloads.md` — 秘密检测命令、注入测试载荷（SQLi/命令/LDAP/SSTI）、认证测试、安全头验证、依赖审计
- `test-cases.md` — TC-SR-001~007（秘密管理、输入验证、注入、认证、安全头、依赖、完整 OWASP）
- `guides/owasp-audit-methodology.md` — 审计规划、攻击面映射、优先级排序、证据文档、报告撰写
- SKILL.md — 添加 Supplementary Files 引用 + Sequential Pipeline Orchestration

---

## 三、PARTIAL 补强详情

| 技能 | payloads.md 内容 | test-cases.md 内容 | ECC 模式 |
|------|-----------------|-------------------|---------|
| repo-scan | 分类命令、库检测、热点grep、秘密扫描、判定辅助 | TC-RS-001~004 | Batch Processing |
| terminal-ops | 侦察/利用/后渗透命令、证据捕获、调试排错 | TC-TO-001~004 | Sequential Pipeline |
| verification-loop | SQLi/XSS/认证/网络验证载荷、误报消除清单、补丁验证 | TC-VL-001~005 | Sequential Pipeline |
| docker-patterns | 快速启动、额外实验室、证据提取、清理命令 | TC-DP-001~004 | Sequential Pipeline |
| search-first | searchsploit/gh/msf/nuclei 模板、评估评分矩阵 | TC-SF-001~004 | Learning Cycle |

---

## 四、MINIMAL 补强详情

| 技能 | Orchestration 模式 | 角色定位 |
|------|-------------------|---------|
| continuous-learning | Learning Cycle 消费者 | 从所有技能消费观察结果，提取结构化知识 |
| safety-guard | Cross-cutting Interceptor | 拦截所有技能操作，执行 scope 检查和危险命令检测 |
| chronicle | Sequential Pipeline (record → index → distill) | 记录事件 → 建立索引 → 蒸馏知识 |

---

## 五、ECC 编排覆盖

v0.1.6 完成后，45 个技能中所有技能的 SKILL.md 都包含 Orchestration 章节：

- Sequential Pipeline: terminal-ops, security-review, verification-loop, docker-patterns, chronicle
- Watch Loop: security-bounty-hunter
- Batch Processing: repo-scan
- Learning Cycle: search-first, continuous-learning
- Meta-Skill: autonomous-loops
- Cross-cutting Interceptor: safety-guard
- Learning Cycle (已有): ai-fuzzing, deep-research

---

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

---

# kali-claw v0.1.3 技能补充调研报告

*Generated: 2026-05-06 | Version: 0.1.2 → 0.1.3 | New Skills: 1 | Enhanced: 1 | Updated: 2 | Total: 37*

---

## 摘要

kali-claw v0.1.2 建立了质量保障、自动化、经验积累和安全边界能力。但在**社交平台实时情报收集**和**持续性情报运营**两个维度存在空白。v0.1.3 通过新建 `social-intelligence` 技能域和深度增强 `deep-research` 技能，补强了从"社交雷达"到"情报分析台"的完整情报能力链。

---

## 一、v0.1.2 能力空白分析

| 空白维度 | 具体问题 | 影响场景 |
|----------|----------|----------|
| **社交情报** | 缺少社交平台（Reddit、HN、X、YouTube）的系统化情报收集方法论 | 无法获取目标员工社交画像、技术栈泄露、安全事件舆情 |
| **持续监控** | deep-research 仅支持单次研究，缺少持续监控和变化检测 | 无法追踪 CVE feed、代码泄露、暗网提及的持续变化 |
| **情报关联** | 缺少跨源 IOC 关联和置信度评分框架 | 多源情报无法汇聚成统一视图，无法评估情报可靠性 |
| **迭代精化** | 研究过程为单次通过，缺少基于发现自动生成新问题的迭代能力 | 研究深度受限，无法自动发现和填补知识空白 |

---

## 二、调研背景

本次升级源于对行业 "Deep Research" 能力的系统调研（详见 `memory/2026-05-05-deep-research-migration-report.md`），核心发现：

1. **行业趋势**：Google Deep Research Max（2026-04-21发布）、OpenAI o3-deep-research、Perplexity Deep Research 均采用"自主搜索循环 + MCP + 扩展推理"架构
2. **last30days 技能**：开源 Claude Code 技能，专注社交平台最近30天讨论的实时收集与聚类分析
3. **核心区别**：last30days = "人们在说什么"（社交雷达）；deep-research = "事实是什么"（情报分析台）
4. **结论**：两者互补，应同时纳入 kali-claw

---

## 三、新增技能定位分析

### `social-intelligence` — 社交平台实时情报

| 维度 | 分析 |
|------|------|
| **填补空白** | 社交平台系统化情报收集（Reddit、HN、X、YouTube、暗网论坛、paste 站点） |
| **与现有技能的关系** | 补充 `osint`（被动工具驱动）和 `deep-research`（权威源深度分析），专注**非结构化社区讨论** |
| **差异** | osint = "目标有什么资产" → social-intelligence = "人们在讨论目标什么" → deep-research = "关于这个话题的权威事实是什么" |
| **核心价值** | 五阶段方法论（定义目标 → 平台选择 → 并行检索 → 去重重排序 → 聚类报告），覆盖 7 大平台类型 |

**协同示例：** 渗透测试前，先用 `social-intelligence` 发现目标员工在 Reddit 上抱怨新 VPN 系统，再用 `deep-research` 深入研究该 VPN 产品的已知 CVE，最后用 `social-engineering` 利用员工对 VPN 的不满设计钓鱼方案。

---

### `deep-research` 增强 — 持续监控 + 情报关联 + 迭代精化

| 维度 | 分析 |
|------|------|
| **Phase 7: Continuous Monitoring** | 定义监控目标（CVE feed、代码仓库、paste 站点、暗网），设定轮询频率，快照 diff 对比，告警触发 |
| **Phase 8: Intelligence Correlation** | IOC 提取 → 跨源合并去重 → 置信度评分（5级） → MITRE ATT&CK 映射 → 实体关系图 |
| **Phase 9: Adaptive Refinement** | 基于 Phase 6 报告识别知识空白 → 生成新子问题 → 定向搜索 → 更新报告 → 收敛检测 |
| **4 个新 guides** | 迭代搜索模式、持续监控、情报关联、MCP 工具接入 |

---

## 四、技能协同矩阵更新

```
                    ┌──────────────────┐
                    │ social-intelligence │ ← "人们在说什么"
                    └────────┬─────────┘
                             │ 发现线索
                             ▼
┌──────────┐    ┌────────────────────────┐    ┌────────────────┐
│  osint   │───→│    deep-research        │───→│ social-        │
│  recon   │    │ (情报分析 + 持续监控)    │    │  engineering   │
└──────────┘    └────────────────────────┘    └────────────────┘
                         │ Phase 8
                         ▼
                ┌────────────────────┐
                │ Intelligence       │
                │ Correlation        │ ← IOC 关联 + 置信度评分
                └────────────────────┘
```

### 完整情报收集流水线

```
social-intelligence（社交雷达：发现目标讨论和泄露）
  → osint（被动收集：域名、邮件、子域）
    → deep-research（深度分析：CVE、攻击技术、威胁情报）
      → deep-research Phase 7（持续监控：变化检测 + 告警）
        → deep-research Phase 8（情报关联：IOC + ATT&CK 映射）
          → social-engineering（利用情报：精准社工攻击）
```

---

## 五、文件变更清单

### 新建文件（11 个）

| 文件 | 说明 |
|------|------|
| `skills/social-intelligence/SKILL.md` | 社交情报技能定义：5 阶段方法论、工具表、报告模板 |
| `skills/social-intelligence/payloads.md` | 7 大平台搜索查询模板 |
| `skills/social-intelligence/test-cases.md` | 5 个测试用例（TC-SI-001 ~ TC-SI-005） |
| `skills/social-intelligence/guides/reddit-hackernews-osint.md` | Reddit + HN 情报收集实操 |
| `skills/social-intelligence/guides/twitter-youtube-osint.md` | X + YouTube 情报收集实操 |
| `skills/social-intelligence/guides/sentiment-analysis.md` | 安全情绪分析 → 社工向量映射 |
| `skills/deep-research/guides/iterative-search-patterns.md` | 迭代搜索循环、查询精化、收敛检测 |
| `skills/deep-research/guides/continuous-monitoring.md` | 持续监控架构、快照 diff、告警触发 |
| `skills/deep-research/guides/intelligence-correlation.md` | IOC 关联、置信度评分、MITRE ATT&CK 映射 |
| `skills/deep-research/guides/mcp-integration.md` | MCP 工具链配置、API 接入模式 |
| `memory/2026-05-05-deep-research-migration-report.md` | Deep Research 能力迁移调研报告 |

### 修改文件（7 个）

| 文件 | 变更 |
|------|------|
| `skills/deep-research/SKILL.md` | +Phase 7/8/9、+2 个 Use Case、+Hacker Laws、+Learning Resources |
| `skills/deep-research/payloads.md` | +Section 9（持续监控查询）+ Section 10（情报关联命令） |
| `skills/deep-research/test-cases.md` | +TC-DR-011/012/013（总数 10→13） |
| `IDENTITY.md` | +Social Intelligence、+Deep Research 技能域行 |
| `TOOLS.md` | +Social Intelligence（6 tools）、+Deep Research（8 tools）分类 |
| `skills/osint/SKILL.md` | +social-intelligence、+deep-research 交叉引用 |
| `skills/social-engineering/SKILL.md` | +social-intelligence、+deep-research 交叉引用 |

### 版本文件（4 个）

| 文件 | 变更 |
|------|------|
| `VERSION` | 0.1.2 → 0.1.3 |
| `README.md` | 36→37 技能域、版本号、技能表 |
| `CHANGELOG.md` | +v0.1.3 条目 |
| `UPDATELOG.md` | +v0.1.3 调研报告 |

---

# kali-claw v0.1.4 知识运营能力增强报告

*Generated: 2026-05-11 | Version: 0.1.3 → 0.1.4 | New Skills: 6 | Total: 43*

---

## 摘要

kali-claw v0.1.2 建立了质量保障、自动化、经验积累和安全边界能力。但在**社交平台实时情报收集**和**持续性情报运营**两个维度存在空白。v0.1.3 通过新建 `social-intelligence` 技能域和深度增强 `deep-research` 技能，补强了从"社交雷达"到"情报分析台"的完整情报能力链。

---

## 一、v0.1.2 能力空白分析

| 空白维度 | 具体问题 | 影响场景 |
|----------|----------|----------|
| **社交情报** | 缺少社交平台（Reddit、HN、X、YouTube）的系统化情报收集方法论 | 无法获取目标员工社交画像、技术栈泄露、安全事件舆情 |
| **持续监控** | deep-research 仅支持单次研究，缺少持续监控和变化检测 | 无法追踪 CVE feed、代码泄露、暗网提及的持续变化 |
| **情报关联** | 缺少跨源 IOC 关联和置信度评分框架 | 多源情报无法汇聚成统一视图，无法评估情报可靠性 |
| **迭代精化** | 研究过程为单次通过，缺少基于发现自动生成新问题的迭代能力 | 研究深度受限，无法自动发现和填补知识空白 |

---

## 二、调研背景

本次升级源于对行业 "Deep Research" 能力的系统调研（详见 `memory/2026-05-05-deep-research-migration-report.md`），核心发现：

1. **行业趋势**：Google Deep Research Max（2026-04-21发布）、OpenAI o3-deep-research、Perplexity Deep Research 均采用"自主搜索循环 + MCP + 扩展推理"架构
2. **last30days 技能**：开源 Claude Code 技能，专注社交平台最近30天讨论的实时收集与聚类分析
3. **核心区别**：last30days = "人们在说什么"（社交雷达）；deep-research = "事实是什么"（情报分析台）
4. **结论**：两者互补，应同时纳入 kali-claw

---

## 三、新增技能定位分析

### `social-intelligence` — 社交平台实时情报

| 维度 | 分析 |
|------|------|
| **填补空白** | 社交平台系统化情报收集（Reddit、HN、X、YouTube、暗网论坛、paste 站点） |
| **与现有技能的关系** | 补充 `osint`（被动工具驱动）和 `deep-research`（权威源深度分析），专注**非结构化社区讨论** |
| **差异** | osint = "目标有什么资产" → social-intelligence = "人们在讨论目标什么" → deep-research = "关于这个话题的权威事实是什么" |
| **核心价值** | 五阶段方法论（定义目标 → 平台选择 → 并行检索 → 去重重排序 → 聚类报告），覆盖 7 大平台类型 |

**协同示例：** 渗透测试前，先用 `social-intelligence` 发现目标员工在 Reddit 上抱怨新 VPN 系统，再用 `deep-research` 深入研究该 VPN 产品的已知 CVE，最后用 `social-engineering` 利用员工对 VPN 的不满设计钓鱼方案。

---

### `deep-research` 增强 — 持续监控 + 情报关联 + 迭代精化

| 维度 | 分析 |
|------|------|
| **Phase 7: Continuous Monitoring** | 定义监控目标（CVE feed、代码仓库、paste 站点、暗网），设定轮询频率，快照 diff 对比，告警触发 |
| **Phase 8: Intelligence Correlation** | IOC 提取 → 跨源合并去重 → 置信度评分（5级） → MITRE ATT&CK 映射 → 实体关系图 |
| **Phase 9: Adaptive Refinement** | 基于 Phase 6 报告识别知识空白 → 生成新子问题 → 定向搜索 → 更新报告 → 收敛检测 |
| **4 个新 guides** | 迭代搜索模式、持续监控、情报关联、MCP 工具接入 |

---

## 四、技能协同矩阵更新

```
                    ┌──────────────────┐
                    │ social-intelligence │ ← "人们在说什么"
                    └────────┬─────────┘
                             │ 发现线索
                             ▼
┌──────────┐    ┌────────────────────────┐    ┌────────────────┐
│  osint   │───→│    deep-research        │───→│ social-        │
│  recon   │    │ (情报分析 + 持续监控)    │    │  engineering   │
└──────────┘    └────────────────────────┘    └────────────────┘
                         │ Phase 8
                         ▼
                ┌────────────────────┐
                │ Intelligence       │
                │ Correlation        │ ← IOC 关联 + 置信度评分
                └────────────────────┘
```

### 完整情报收集流水线

```
social-intelligence（社交雷达：发现目标讨论和泄露）
  → osint（被动收集：域名、邮件、子域）
    → deep-research（深度分析：CVE、攻击技术、威胁情报）
      → deep-research Phase 7（持续监控：变化检测 + 告警）
        → deep-research Phase 8（情报关联：IOC + ATT&CK 映射）
          → social-engineering（利用情报：精准社工攻击）
```

---

## 五、文件变更清单

### 新建文件（11 个）

| 文件 | 说明 |
|------|------|
| `skills/social-intelligence/SKILL.md` | 社交情报技能定义：5 阶段方法论、工具表、报告模板 |
| `skills/social-intelligence/payloads.md` | 7 大平台搜索查询模板 |
| `skills/social-intelligence/test-cases.md` | 5 个测试用例（TC-SI-001 ~ TC-SI-005） |
| `skills/social-intelligence/guides/reddit-hackernews-osint.md` | Reddit + HN 情报收集实操 |
| `skills/social-intelligence/guides/twitter-youtube-osint.md` | X + YouTube 情报收集实操 |
| `skills/social-intelligence/guides/sentiment-analysis.md` | 安全情绪分析 → 社工向量映射 |
| `skills/deep-research/guides/iterative-search-patterns.md` | 迭代搜索循环、查询精化、收敛检测 |
| `skills/deep-research/guides/continuous-monitoring.md` | 持续监控架构、快照 diff、告警触发 |
| `skills/deep-research/guides/intelligence-correlation.md` | IOC 关联、置信度评分、MITRE ATT&CK 映射 |
| `skills/deep-research/guides/mcp-integration.md` | MCP 工具链配置、API 接入模式 |
| `memory/2026-05-05-deep-research-migration-report.md` | Deep Research 能力迁移调研报告 |

### 修改文件（7 个）

| 文件 | 变更 |
|------|------|
| `skills/deep-research/SKILL.md` | +Phase 7/8/9、+2 个 Use Case、+Hacker Laws、+Learning Resources |
| `skills/deep-research/payloads.md` | +Section 9（持续监控查询）+ Section 10（情报关联命令） |
| `skills/deep-research/test-cases.md` | +TC-DR-011/012/013（总数 10→13） |
| `IDENTITY.md` | +Social Intelligence、+Deep Research 技能域行 |
| `TOOLS.md` | +Social Intelligence（6 tools）、+Deep Research（8 tools）分类 |
| `skills/osint/SKILL.md` | +social-intelligence、+deep-research 交叉引用 |
| `skills/social-engineering/SKILL.md` | +social-intelligence、+deep-research 交叉引用 |

### 版本文件（4 个）

| 文件 | 变更 |
|------|------|
| `VERSION` | 0.1.2 → 0.1.3 |
| `README.md` | 36→37 技能域、版本号、技能表 |
| `CHANGELOG.md` | +v0.1.3 条目 |
| `UPDATELOG.md` | +v0.1.3 调研报告 |

---

## 摘要

v0.1.3 建立了社交情报（social-intelligence）和深度研究的持续监控能力。v0.1.4 将路线图 Tier 1 和 Tier 2 合并实施，新增 **6 个知识运营技能域**，从"代码库快速理解"到"知识图谱管理"再到"安全内容产出"，建立完整的知识运营闭环。

v0.1.4 的核心突破：**从"即时操作"到"知识沉淀"**，从"单次审计"到"跨会话情报积累"，从"发现漏洞"到"产出专业报告"。

---

## 一、v0.1.3 能力空白分析

| 空白维度 | 具体问题 | 影响场景 |
|----------|----------|----------|
| **代码库理解** | 白盒审计前缺少快速代码库理解方法论，无法在巨型代码库（100M+ LOC）中快速定位攻击面 | 代码审计效率低下，无法快速识别关键入口点和安全热点 |
| **知识持久化** | 跨会话情报无法结构化存储，发现的实体、模式、关系会话结束后丢失 | 每次审计重新发现相同问题，无法积累目标情报库 |
| **报告产出** | 缺少结构化的安全报告撰写能力，从发现到报告需要手动整理 | 报告质量不稳定，CVSS 评分不一致，数据脱敏不规范 |
| **自动化测试** | 浏览器端安全测试依赖手工操作，无法自动化验证 XSS、CSRF、Cookie 配置 | 测试覆盖不全面，重复性测试效率低 |
| **情报收集** | CVE、Exploit-DB、GitHub advisory 数据收集依赖手工搜索 | 情报收集速度慢，数据格式不统一 |
| **深度搜索** | 缺少语义搜索能力，传统 Google 搜索无法精准定位安全研究资料 | 研究效率受限，无法快速找到上下文相关的技术文档 |

---

## 二、新增技能定位分析（v0.1.4，+6 个技能）

### 核心能力：codebase-onboarding — 代码库快速理解

| 维度 | 分析 |
|------|------|
| **填补空白** | 白盒审计前的代码库快速理解，支持 100M+ LOC 巨型代码库 |
| **与现有技能的关系** | 是 `repo-scan` 和 `security-review` 的前置技能。repo-scan 专注文件分类和依赖检测，codebase-onboarding 专注架构理解和攻击面映射 |
| **核心价值** | **3 种scope模式**（Targeted/Exploratory/Comprehensive）、**Phase 0 Search-First** 策略、**语言分级支持**（Tier 1: Python/JS/TS/Java/Go/PHP 75-90%自动化；Tier 2: C/C++/Rust/Ruby/C# 50-70%；Tier 3: 其他 20-40%）、**置信度评分系统**（0-100）、**100M+ LOC 策略**（Index First + Smart Sampling + Divide & Conquer） |

**协同示例：** 白盒审计 Django 项目前，先用 `codebase-onboarding` Targeted 模式快速定位认证入口点（urls.py → views.py → middleware），输出结构化 JSON 和 Mermaid 架构图，再用 `security-review` 审计认证逻辑漏洞。

---

### 核心能力：knowledge-ops — 知识图谱管理

| 维度 | 分析 |
|------|------|
| **填补空白** | 跨会话知识持久化、实体关系管理、情报聚合 |
| **与现有技能的关系** | 与 `continuous-learning` 互补。continuous-learning 专注模式提取和经验沉淀，knowledge-ops 专注结构化知识存储和图谱管理 |
| **核心价值** | **Knowledge Unit (KU)** 标准格式（frontmatter: id, type, confidence, tags, linked, source, expires）、**5 种知识类型**（entity, finding, relationship, pattern, hypothesis, intelligence）、**置信度模型**（0-25 speculation, 26-50 unconfirmed, 51-75 probable, 76-90 high confidence, 91-100 verified）、**知识图谱可视化**（DOT/Mermaid）、**置信度历史追踪** |

**协同示例：** 使用 `osint` 发现目标域名、使用 `social-intelligence` 发现员工社交账号、使用 `deep-research` 发现 CVE，所有发现通过 `knowledge-ops` 存储为 Knowledge Units，下次审计时直接加载历史情报，实现跨会话情报积累。

---

### 核心能力：article-writing — 安全内容产出

| 维度 | 分析 |
|------|------|
| **填补空白** | 结构化的安全报告撰写：渗透测试报告、CVE 披露、技术博客 |
| **与现有技能的关系** | 是 `security-bounty-hunter` 和 `verification-loop` 的下游技能。从验证后的发现生成专业报告 |
| **核心价值** | **3 种文章类型**（Pentest Report 10-50页、Vulnerability Disclosure 2-5页、Security Blog Post 1000-3000词）、**CVSS 3.1 评分指南**、**数据脱敏标准**（真实 IP → RFC 5737 IP, 域名 → example.com）、**Markdown → PDF 转换** |

**协同示例：** `vulnerability-assessment` 发现 SQL 注入，`verification-loop` 验证确认，`knowledge-ops` 存储为 KU，最后用 `article-writing` 生成带 CVSS 评分和 PoC 的渗透测试报告，所有真实 IP 和域名自动脱敏。

---

### 支持技能：browser-qa — 浏览器自动化测试

| 维度 | 分析 |
|------|------|
| **填补空白** | 浏览器端安全测试自动化（Playwright/Puppeteer） |
| **与现有技能的关系** | 为 `web-xss`、`web-auth-bypass`、`web-access-control` 提供自动化验证能力 |
| **核心价值** | **网络监控**、**Cookie 分析**（HttpOnly/Secure/SameSite）、**CSRF 检测**、**XSS payload 注入** |

---

### 支持技能：data-scraper-agent — 结构化数据采集

| 维度 | 分析 |
|------|------|
| **填补空白** | CVE、Exploit-DB、GitHub advisory 自动化数据采集 |
| **与现有技能的关系** | 为 `deep-research` 提供数据源，为 `knowledge-ops` 提供结构化输入 |
| **核心价值** | **NVD API 采集**、**searchsploit 自动化**、**GitHub advisory API**、**BeautifulSoup HTML 解析** |

---

### 支持技能：exa-search — 语义搜索

| 维度 | 分析 |
|------|------|
| **填补空白** | 安全研究专用的语义搜索，超越传统 Google 搜索 |
| **与现有技能的关系** | 为 `deep-research` Phase 2（搜索策略）提供语义搜索能力 |
| **核心价值** | **上下文感知查询**、**日期过滤**、**域名过滤**、**全文提取**、**Exa API 集成** |

---

## 三、技能协同矩阵更新

### 代码审计流水线

```
codebase-onboarding（快速理解架构和入口点）
  → repo-scan（文件分类和依赖检测）
    → security-review（OWASP Top 10 系统审计）
      → verification-loop（假阳性消除）
        → knowledge-ops（发现存储为 KU）
          → article-writing（生成渗透测试报告）
```

### 情报运营流水线

```
osint + social-intelligence（被动收集 + 社交情报）
  → deep-research（深度分析 + 持续监控）
    → data-scraper-agent（结构化数据采集）
      → exa-search（语义搜索补充）
        → knowledge-ops（情报聚合 + 图谱管理）
          → article-writing（CVE 披露 / 技术博客）
```

### 自动化测试流水线

```
browser-qa（浏览器自动化测试）
  → verification-loop（验证和确认）
    → knowledge-ops（测试结果存储）
      → article-writing（测试报告生成）
```

---

## 四、技能类型更新

v0.1.4 的 43 个技能四层分类：

### 第一层：攻击技术技能（17 个）
`api-security`, `binary-reverse`, `cloud-security`, `container-security`, `crypto-attacks`, `mobile-security`, `network-pentest`, `password-attack`, `post-exploitation`, `web-access-control`, `web-auth-bypass`, `web-sqli`, `web-ssrf`, `web-xss`, `wifi-pentest`, `social-engineering`, `security-bounty-hunter`

### 第二层：安全分析技能（10 个）
`vulnerability-assessment`, `osint`, `recon-osint`, `digital-forensics`, `insecure-design`, `security-misconfiguration`, `logging-monitoring`, `supply-chain-security`, `security-review`, `repo-scan`

### 第三层：元技能（9 个）
`deep-research`, `terminal-ops`, `search-first`, `verification-loop`, `autonomous-loops`, `continuous-learning`, `codebase-onboarding`, `exa-search`, `browser-qa`

### 第四层：知识运营技能（4 个）
`knowledge-ops`, `article-writing`, `data-scraper-agent`, `chronicle`

### 基础设施技能（3 个）
`docker-patterns`, `safety-guard`, `social-intelligence`

---

## 五、文件变更清单

### 新建文件（35 个）

#### codebase-onboarding（6 个）
- `skills/codebase-onboarding/SKILL.md` — 3 scope模式、Phase 0-5、语言分级、100M+ LOC 策略
- `skills/codebase-onboarding/payloads.md` — Phase 0-4 命令、模式特定序列
- `skills/codebase-onboarding/test-cases.md` — TC-CO-001~005（Django/Go/Node/PHP/Java）
- `skills/codebase-onboarding/guides/web-framework-onboarding.md` — Django/Express/Spring Boot/FastAPI/Gin
- `skills/codebase-onboarding/guides/microservice-onboarding.md` — 服务发现、API 契约、网关分析
- `skills/codebase-onboarding/guides/architecture-pattern-recognition.md` — MVC/REST+SPA/微服务/事件驱动/Serverless/GraphQL
- `skills/codebase-onboarding/guides/legacy-codebase-onboarding.md` — PHP/Perl CGI/ASP 遗留代码策略

#### knowledge-ops（7 个）
- `skills/knowledge-ops/SKILL.md` — KU 格式、5种类型、置信度模型、存储格式
- `skills/knowledge-ops/payloads.md` — 会话启动、KU 捕获模板、图谱查询、维护脚本
- `skills/knowledge-ops/test-cases.md` — TC-KO-001~005（跨会话上下文、置信度演化、模式识别、交接、过期）
- `skills/knowledge-ops/guides/entity-extraction-and-tagging.md` — 10 种实体类型、提取源、标签策略
- `skills/knowledge-ops/guides/cross-session-intelligence-aggregation.md` — 聚合工作流、报告模板、查询模式
- `skills/knowledge-ops/guides/knowledge-graph-visualization-and-querying.md` — DOT/Mermaid 图、路径查找、中心性分析

#### article-writing（7 个）
- `skills/article-writing/SKILL.md` — 3 种文章类型、模板、方法论
- `skills/article-writing/payloads.md` — CVSS 计算、脱敏清单、发现描述模板
- `skills/article-writing/test-cases.md` — TC-AW-001~003（渗透报告/CVE披露/博客）
- `skills/article-writing/guides/cvss-scoring.md` — CVSS 3.1 向量分解、常见漏洞评分、决策树
- `skills/article-writing/guides/report-structure.md` — 7 个章节顺序、格式标准、常见错误
- `skills/article-writing/guides/vulnerability-writing.md` — 90天披露周期、CVE 申请、CWE 参考

#### browser-qa（3 个）
- `skills/browser-qa/SKILL.md` — Playwright/Puppeteer 自动化、网络监控、Cookie 分析
- `skills/browser-qa/payloads.md` — Playwright Python 命令参考
- `skills/browser-qa/test-cases.md` — TC-BQ-001~003（认证流程/CSRF/XSS）

#### data-scraper-agent（3 个）
- `skills/data-scraper-agent/SKILL.md` — CVE 采集、Exploit-DB、威胁情报 feeds
- `skills/data-scraper-agent/payloads.md` — NVD API、searchsploit、GitHub advisory、BeautifulSoup
- `skills/data-scraper-agent/test-cases.md` — TC-DSA-001~002（CVE采集/Exploit可用性）

#### exa-search（3 个）
- `skills/exa-search/SKILL.md` — Exa API 语义搜索、日期/域名过滤
- `skills/exa-search/payloads.md` — CVE 研究、Exploit 技术、工具研究、威胁情报查询示例
- `skills/exa-search/test-cases.md` — TC-ES-001~002（CVE 研究/Exploit 技术研究）

#### 发布文件（1 个）
- `RELEASE-v0.1.4.md` — v0.1.4 中文发布公告

### 修改文件（6 个）

| 文件 | 变更 |
|------|------|
| `VERSION` | 0.1.3 → 0.1.4 |
| `README.md` | 37→43 技能域、技能表新增 6 行、版本号 |
| `CHANGELOG.md` | +v0.1.4 条目（35 个新文件 + 6 个修改文件） |
| `IDENTITY.md` | +6 个新技能域行（待更新） |
| `TOOLS.md` | +6 个新技能分类（待更新） |
| `UPDATELOG.md` | +v0.1.4 知识运营能力增强报告（本文件） |

---

## 六、核心突破点

### 1. 代码库理解能力飞跃

- **v0.1.3**: repo-scan 仅支持文件分类和依赖检测
- **v0.1.4**: codebase-onboarding 支持 100M+ LOC 代码库快速理解，语言分级支持，置信度评分

### 2. 知识持久化能力飞跃

- **v0.1.3**: continuous-learning 仅支持模式提取，知识无法跨会话持久化
- **v0.1.4**: knowledge-ops 建立标准化 KU 格式，知识图谱可视化，置信度历史追踪

### 3. 报告产出能力飞跃

- **v0.1.3**: security-bounty-hunter 仅支持赏金报告模板
- **v0.1.4**: article-writing 支持 3 种报告类型（渗透报告/CVE披露/博客），CVSS 评分，数据脱敏

### 4. 自动化测试能力飞跃

- **v0.1.3**: 浏览器端测试依赖手工操作
- **v0.1.4**: browser-qa 支持 Playwright/Puppeteer 自动化，网络监控，Cookie 分析

### 5. 情报采集能力飞跃

- **v0.1.3**: deep-research 依赖手工搜索
- **v0.1.4**: data-scraper-agent + exa-search 自动化数据采集和语义搜索

---

## 七、结论

v0.1.4 新增的 6 个知识运营技能从六个维度强化了 kali-claw 的知识闭环能力：

1. **代码理解** — `codebase-onboarding` 支持 100M+ LOC 代码库快速理解
2. **知识持久化** — `knowledge-ops` 建立跨会话知识图谱管理
3. **报告产出** — `article-writing` 规范化渗透报告和 CVE 披露
4. **自动化测试** — `browser-qa` 自动化浏览器端安全测试
5. **情报采集** — `data-scraper-agent` 自动化结构化数据采集
6. **深度搜索** — `exa-search` 语义搜索能力

v0.1.3 建立了"社交雷达"到"情报分析台"的情报能力链；v0.1.4 通过知识运营闭环，将 kali-claw 从"即时操作型代理"升级为"知识积累型情报平台"。

---

## 附录：v0.1.4 变更清单

| 变更类型 | 数量 | 文件列表 |
|----------|------|----------|
| 新增技能 | 6 | codebase-onboarding, knowledge-ops, article-writing, browser-qa, data-scraper-agent, exa-search |
| 新增文件 | 35 | 6 个技能目录 × (SKILL.md + payloads.md + test-cases.md + guides/) + RELEASE-v0.1.4.md |
| 更新文件 | 6 | VERSION, README.md, CHANGELOG.md, IDENTITY.md, TOOLS.md, UPDATELOG.md |
| 总技能域 | 43 | 37 → 43 (+6) |
