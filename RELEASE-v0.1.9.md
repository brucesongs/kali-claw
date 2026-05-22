# kali-claw v0.1.9 发布公告 — 技能实践验证

**发布日期**：2026-05-22
**技能域数量**：49（不变）
**主题**：实践验证基础设施 — 证明每个技能在真实 Kali 环境中可执行

---

## 更新概览

v0.1.9 为 kali-claw 的 49 个技能域建立了验证体系。v0.1.8 确保了每个技能都具备完整文档（SKILL.md + payloads.md + test-cases.md + guides/），本次发布则新增了追踪和验证这些技能实际可用性的基础设施。

验证系统为每个技能域选取 1 个代表性测试用例（共 49 个），提供结构化的执行手册，并以证据链追踪结果。

---

## 新增：验证系统

### 验证追踪器（`validation/VALIDATION-TRACKER.md`）

单一 Markdown 表格追踪全部 49 个技能域：
- 每个技能一行：TC ID、标题、状态、日期、证据路径、备注
- 五级状态：PASS / FAIL / PARTIAL / BLOCKED / PENDING
- 顶部汇总计数，一目了然
- 变更日志记录验证会话历史

### 验证指南（`validation/VALIDATION-GUIDE.md`）

全面的执行手册，涵盖：
- 环境要求（Kali 2025-2、Docker、可选硬件）
- 会话前检查清单及设置命令
- 逐步执行工作流（阅读 → 检查前置条件 → 执行 → 对比 → 记录）
- 证据标准（命名规范、可接受格式、最低要求）
- 特殊情况处理（BLOCKED、PARTIAL、元技能、依赖实验环境的技能）
- 按环境需求分类的技能表（8 个类别）
- 推荐执行顺序（8 个批次，基础设施优先）

### 证据目录（`validation/evidence/`）

验证产物的专用存储：
- 终端日志、asciinema 录制、截图、pcap 文件
- 命名规范：`{skill-domain}-{TC-ID}-{YYYY-MM-DD}.{ext}`
- 从追踪器引用，确保可追溯性

---

## 测试用例选取

每个技能域选取第一个（最基础的）测试用例：

| 类别 | 示例技能 | 示例 TC |
|------|---------|---------|
| Web 攻击 | web-sqli, web-xss, api-security | TC-S001: GET 参数注入点检测 |
| 网络 | network-pentest, recon-osint | TC-NP-001: 主机发现与网络拓扑映射 |
| 漏洞利用 | password-attack, binary-reverse | TC-PA-001: SSH 在线字典暴力破解 |
| 元/流程 | chronicle, safety-guard | TC-CH-001: P0 事件记录 |
| 专项 | wifi-pentest, hardware-security | TC-WIFI-001: 全频段被动扫描 |

---

## 预期挑战

| 技能 | 挑战 | 缓解方案 |
|------|------|---------|
| wifi-pentest | 需要监听模式无线网卡 | 标记 BLOCKED 或在专用硬件会话中验证 |
| hardware-security | 需要物理 UART/JTAG 接入 | 通过 binwalk 固件分析实现 PARTIAL |
| mobile-security | 需要 Android 设备或模拟器 | 通过静态分析（jadx/apktool）实现 PARTIAL |
| cloud-security | 需要 AWS/GCP 账户 | 通过 LocalStack 模拟实现 PARTIAL |
| social-engineering | 需要邮件基础设施 | 使用本地 SMTP（Mailhog） |

---

## 文档更新

- **CHANGELOG.md** — 新增 v0.1.9 条目
- **VERSION** — 0.1.8 → 0.1.9
- **MEMORY.md** — 更新当前焦点，新增 v0.1.9 关键决策

---

## 统计数据

| 指标 | 数量 |
|------|------|
| 新增文件 | 3（追踪器、指南、evidence/.gitkeep） |
| 新增目录 | 2（validation/、validation/evidence/） |
| 选取测试用例 | 49 |
| 可直接验证的技能 | ~40（基础 Kali + Docker） |
| 预计 BLOCKED 技能 | ~4（依赖硬件） |
| 预计 PARTIAL 技能 | ~5（环境受限） |

---

## 下一步计划（v0.1.10+）

- **执行验证** — 在 Kali 环境中逐一完成 49 个测试用例
- **跨技能集成测试** — 验证 ECC Pipeline 跨技能域端到端流程
- **技能质量评分** — 自动化指标：payload 覆盖率、测试用例通过率、指南完整度
- **战略上下文管理** — 长周期渗透任务的上下文压缩与优先信息保留
