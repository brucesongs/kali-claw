# kali-claw v0.1.7 发布公告

**发布日期**：2026-05-16  
**技能域数量**：45 → 49  
**主题**：前沿领域扩展 — AI 安全、硬件安全、多智能体协作、MCP 集成

---

## 更新概览

v0.1.7 新增 4 个 FULL 级技能域，覆盖当前最具增长潜力的攻击面：AI/LLM 系统、硬件与嵌入式设备、多智能体协同渗透、MCP 工具集成。每个域均配备 SKILL.md、payloads.md、test-cases.md 和深度指南。

---

## 新增技能域

### `ai-security` — AI/LLM 系统攻防

AI 攻击面已成为正式渗透测试目标。本技能覆盖从直接提示注入到模型权重供应链攻击的完整攻击谱系。

**核心能力**：
- 8 种直接提示注入变体（令牌走私、零宽字符、Base64 编码、分隔符混淆）
- 5 套越狱框架（DAN、开发者模式、20 对 Many-shot、虚构/研究视角）
- 模型提取探针序列 + 训练数据提取模式
- RAG 知识库投毒（3 种文档模板）
- AI API 模糊测试与多模态注入
- 测试用例 TC-AS-001 至 TC-AS-006，全部对应 OWASP LLM Top 10
- 指南：`guides/llm-attack-methodology.md` — 攻击链构建、越狱分类体系、STRIDE 威胁建模应用于 LLM

**ECC 模式**：Learning Cycle（AI 攻击技术每周迭代，本技能持续更新有效载荷）

---

### `hardware-security` — 硬件与嵌入式系统安全

从物理接入到固件漏洞利用，覆盖 IoT 设备和嵌入式系统的完整安全测试链。

**核心能力**：
- UART 波特率枚举 + root shell 获取
- JTAG 发现（JTAGulator）+ OpenOCD 内存转储
- 固件提取：SPI 闪存（CH341A/Bus Pirate）、JTAG 读取、U-Boot 串口导出、OTA 拦截
- binwalk 完整分析流程：扫描 → 熵分析 → 提取 → 挂载 → 清点
- Proxmark3 RFID/NFC 克隆（EM4100、MIFARE Classic、UID 伪造）
- ChipWhisperer 故障注入基础配置
- 5 个测试用例（TC-HS-001 至 TC-HS-005，其中 4 个评级 Critical）
- 指南：`guides/embedded-firmware-analysis.md` — FCC ID 查询、PCB 标注、提取决策树、漏洞模式识别

**ECC 模式**：Sequential Pipeline（物理接入 → 接口发现 → 固件提取 → 分析 → 漏洞利用）

---

### `multi-agent-collaboration` — 多智能体协同渗透

面向大范围、时间受限的渗透任务，协调多个专职代理并行作业。

**核心能力**：
- 4 种协作模型：攻击阶段分解、目标并行化、工具专长分工、协调者-工作者模式
- 任务分解模板（含 `{SCOPE}`、`{TARGET_LIST}`、`{TIME_BUDGET}` 占位变量）
- 5 种代理角色 prompt（侦察、Web 测试、网络扫描、二进制分析、报告撰写）
- 标准化发现报告 JSON Schema，支持跨代理结果聚合
- 5 步去重流程 + 7 步冲突解决决策树（Critical 级别强制人工上报）
- 覆盖率验证矩阵，一眼定位盲区
- 7 种常见失败模式及应对（范围蔓延、格式不匹配、协调者过载、部分覆盖误报完成等）
- 指南：`guides/coordinated-pentest-playbook.md` — 启用条件、角色设计、任务分解方法、通信协议

**ECC 模式**：Batch Processing（协调者分发 → 工作者并行执行 → 结果聚合）

---

### `mcp-server-patterns` — MCP 安全工具集成

将 Kali Linux 安全工具包装为安全的 MCP 服务器供 AI 代理调用，同时提供 MCP 服务器本身的安全审计能力。

**核心能力**：
- 完整 Python MCP 服务器脚手架（~40 行可运行代码）
- 3 个完整工具实现：nmap 封装、nikto 封装、通用安全命令模式（无 shell=True）
- 输入验证：IP/CIDR、URL、端口范围、文件路径白名单、目标范围校验
- `hmac.compare_digest` 常数时间认证中间件（防时序攻击）
- 线程安全滑动窗口限流器
- 安全测试命令：Schema 绕过、注入、认证绕过、限流验证
- 7 条不可妥协的安全包装规则
- 5 个测试用例（TC-MP-001 基础功能 → TC-MP-005 完整安全审计）
- 指南：`guides/security-mcp-server-design.md` — 工具选型标准、MCP 协议基础、安全实现步骤

**ECC 模式**：Sequential Pipeline（需求分析 → 接口设计 → 实现 → 安全测试 → 部署）

---

## 其他变更

- **IDENTITY.md** — Skill Tags 表从 18 行扩展至 32 行：补入 v0.1.6 遗漏的 10 个基础设施技能行 + 4 个新域
- **README.md** — 技能域数量更新为 49；Future Exploration 表移除已实现的域
- **CHANGELOG.md / UPDATELOG.md** — v0.1.7 条目已添加

---

## 数据统计

| 指标 | 数量 |
|------|------|
| 新增技能域 | 4 |
| 新建文件 | 16 |
| 新增代码行数 | ~6,600 |
| IDENTITY.md 新增行 | 14 |

---

## 下一步计划（v0.2.0）

- `strategic-compact` — 长期任务上下文管理：上下文压缩、优先级信息保留策略
- `ai-assisted-exploit-dev` — AI 驱动的漏洞利用开发与载荷定制
- 深度补强：supply-chain-security、crypto-attacks、digital-forensics
