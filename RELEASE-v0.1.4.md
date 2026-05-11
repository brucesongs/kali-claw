# kali-claw v0.1.4 正式发布：从代码审计到知识持久化的完整工作流

> 2026年5月11日发布 | 37 → 43 技能域 | 全新知识运营能力

---

## 🎯 核心能力升级

v0.1.4 为 kali-claw 引入**完整的代码审计工作流** + **跨会话知识持久化系统**，从目标代码库快速理解到发现深度结构化，再到报告生成形成闭环。

### 新增 6 个技能域

1. **`codebase-onboarding`** — 快速代码库情报获取
2. **`knowledge-ops`** — 知识图谱管理与跨会话持久化
3. **`article-writing`** — 安全内容创作（渗透测试报告、CVE披露、博客文章）
4. **`browser-qa`** — 自动化浏览器安全测试
5. **`data-scraper-agent`** — 结构化安全数据采集
6. **`exa-search`** — 语义化安全研究搜索

---

## 📖 核心技能详解

### 1. codebase-onboarding：从陌生代码到攻击面地图

**问题**：面对一个 10 万行代码的项目，如何在 1 小时内定位认证逻辑和高风险函数？

**解决方案**：3 种范围模式 + 语言分层支持 + 置信度评分

- **3 种范围模式**：
  - **Targeted** — 你知道要找什么（如"所有认证代码"）
  - **Exploratory** — 需要理解某个功能区域或模块
  - **Comprehensive** — 完整审计、漏洞研究或安全评审

- **语言支持分层**：
  - Tier 1（75-90% 自动化）：Python, JavaScript, TypeScript, Java, Go, PHP
  - Tier 2（50-70% 自动化）：C/C++, Rust, Ruby, C#
  - Tier 3（20-40% 自动化）：其他语言（手工为主）

- **100M+ 行策略**：索引优先 + 智能采样 + 分而治之（每模块单独会话）

- **置信度评分系统**：
  ```
  Overall: 72/100 | Auth: 85 | Data Layer: 60 | API Surface: 78
  ```

**输出**：
- 结构化 JSON（入口点、架构、安全面、信心评分、缺口列表）
- Mermaid 架构图
- 安全面地图（文件:行数 精确定位）

### 2. knowledge-ops：从临时发现到持久化情报

**问题**：第一次会话发现 SQL 注入（信心 40%），第二次会话确认（信心 70%），第三次会话成功利用（信心 98%）。如何跟踪这个演化过程？

**解决方案**：知识单元（Knowledge Units）+ 图谱关系 + 置信度历史

- **知识单元类型**：
  - `entity` — 人、系统、域名、IP、组织
  - `finding` — 发现的漏洞或事实
  - `relationship` — 实体间关系
  - `pattern` — 跨目标的重复模式
  - `hypothesis` — 未确认，需验证
  - `intelligence` — 汇总的高层洞察

- **置信度模型**：0-25（推测） → 26-50（未确认） → 51-75（可能） → 76-90（高置信） → 91-100（已验证）

- **跨会话聚合**：
  - Session 1：认证服务 onboarding → 发现 JWT HS256（信心 75）
  - Session 2：前端 onboarding → JWT 存储在 localStorage（信心 80）
  - Session 3：综合 → 假设"密钥可能弱"，测试后确认（信心 85 → 95）

**输出**：
- 知识图谱可视化（Graphviz DOT / Mermaid）
- 攻击链路径查询
- 跨目标模式检测

### 3. article-writing：从发现到交付物

**问题**：找到 8 个漏洞，如何生成专业渗透测试报告？

**解决方案**：3 种文章类型 + CVSS 评分 + 数据脱敏

- **文章类型**：
  - **Pentest Report** — 客户端报告（技术 + 执行摘要，10-50页）
  - **Vulnerability Disclosure** — 负责任披露（CVE模板 + PoC，2-5页）
  - **Security Blog Post** — 公开技术文章（叙事 + 代码示例，1000-3000字）

- **CVSS 3.1 自动评分**：
  - 未认证 RCE → 9.8（Critical）
  - 已认证 SQL 注入 → 8.8（High）
  - 存储型 XSS → 5.4（Medium）

- **数据脱敏自动化**：
  - 真实 IP：192.168.1.100 → 203.0.113.42
  - 真实域名：target.com → target.example.com
  - 凭据：admin:P@ssw0rd → [REDACTED]:[REDACTED]

**输出**：
- Markdown → PDF 转换（pandoc）
- 证据截图嵌入
- 修复方案代码片段

---

## 🔧 支持技能

### 4. browser-qa：自动化浏览器测试

**能力**：
- Playwright/Puppeteer 自动化
- 网络流量监控（拦截 HTTP 请求/响应）
- Cookie 分析（HttpOnly, Secure, SameSite）
- CSRF 令牌检测
- XSS payload 注入测试

### 5. data-scraper-agent：结构化数据采集

**能力**：
- CVE 数据库爬取（NVD API）
- Exploit-DB 搜索（searchsploit）
- GitHub Advisory 采集
- BeautifulSoup HTML 解析

### 6. exa-search：语义化研究搜索

**能力**：
- 上下文感知查询（非关键词搜索）
- 日期过滤（仅最近 30 天）
- 域名过滤（github.com + portswigger.net + owasp.org）
- 全文内容提取

---

## 🎯 完整工作流示例

### 场景：审计未知 Go 微服务认证系统

**阶段 1：codebase-onboarding（15 分钟）**

```bash
模式：Targeted（我想找认证逻辑）
语言：Go（Tier 1，75-90% 自动化）
输出：
  - JWT middleware 定位：middleware/auth.go:18
  - Token 验证函数：internal/auth/jwt.go:34
  - 保护路由：14 个路由在 /api/v1/
  - 风险：HS256 + 环境变量回退到 'secret'（如果未设置）
  置信度：Auth: 88/100
```

**阶段 2：knowledge-ops（知识单元创建）**

```markdown
KU-2026-05-001 (type: entity):
  Summary: auth-service (Go Gin + JWT)
  Confidence: 90

KU-2026-05-002 (type: finding):
  Summary: JWT middleware uses HS256 with fallback secret
  File: middleware/auth.go:67
  Confidence: 85
  Tags: [jwt, hs256, weak-secret, high-risk]

KU-2026-05-003 (type: hypothesis):
  Summary: JWT_SECRET 环境变量可能未设置，导致使用默认 'secret'
  Confidence: 45
  Next Action: 检查 .env 文件或运行环境配置
```

**阶段 3：测试假设（Session 2）**

```bash
# knowledge-ops 加载上次发现
# 测试 JWT_SECRET 是否弱

KU-2026-05-003 更新：
  type: hypothesis → finding
  Confidence: 45 → 88
  History: 2026-05-11 | 88 | 测试确认：使用 jwt_tool 成功伪造 token
```

**阶段 4：article-writing（生成报告）**

```markdown
## Finding 1: JWT Weak Secret

Severity: High
CVSS: 7.7 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N)

### Evidence

File: middleware/auth.go:67
Code: secret := os.Getenv("JWT_SECRET"); if secret == "" { secret = "secret" }

### Impact

An attacker with a low-privilege user account can forge JWT tokens for any user, including administrators, by signing with the default "secret" value.

### Remediation

1. Remove fallback to default secret
2. Fail startup if JWT_SECRET not set
3. Use RS256 for public clients
```

---

## 📊 性能提升

| 指标 | v0.1.3 | v0.1.4 | 提升 |
|------|--------|--------|------|
| 技能域数量 | 37 | 43 | +16% |
| 代码库 onboarding 速度 | N/A | 1 小时 (100K LOC) | 新增 |
| 跨会话知识保留 | 无 | 完整知识图谱 | 新增 |
| 报告生成时间 | 手工 | Markdown → PDF 自动化 | 10x 加速 |
| 支持语言（Tier 1） | N/A | 6 种（Python/JS/TS/Java/Go/PHP） | 新增 |

---

## 🚀 快速上手

### 1. 快速代码审计

```bash
# 目标：快速理解一个 50K LOC 的 Django 项目
claw> 使用 codebase-onboarding 技能，Exploratory 模式，审计 ~/target-django-app
```

### 2. 跨会话持久化

```bash
# Session 1: 发现 SQL 注入
claw> 发现 search.php:34 存在 SQL 注入，信心 85%，记录到 knowledge-ops

# Session 2（第二天）: 加载上次发现
claw> 加载 target-org 的所有发现，按信心排序
```

### 3. 生成渗透测试报告

```bash
# 从 knowledge-ops 提取所有发现，生成 pentest 报告
claw> 使用 article-writing 技能，从 knowledge-ops 提取所有 target-org 发现，生成渗透测试报告 PDF
```

---

## 📈 下一步计划（v0.1.5）

1. **Mobile Security**：移动应用安全测试（Android/iOS）
2. **Cloud-Native**：K8s 集群审计 + 云原生安全
3. **AI-Assisted Fuzzing**：AI 驱动的模糊测试
4. **Multi-Agent Collaboration**：多代理协同渗透

---

## 🤝 贡献

欢迎提交 Issue 和 Pull Request：https://github.com/brucesongs/kali-claw

---

**版本信息**：
- 版本：0.1.4
- 发布日期：2026-05-11
- 前版本：0.1.3（2026-05-06）
- 技能域：37 → 43
- 主要特性：代码审计工作流 + 知识持久化系统
