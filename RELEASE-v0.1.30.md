# kali-claw v0.1.30 发布公告 — GitHub 趋势扩面第二波 +4（83→87）

**发布日期**：2026-06-17
**技能域数量**：83 → **87**（+4）
**主题**：v0.1.29 GitHub 趋势驱动方法论的延续；进入 4 个新类别（ai-emerging / iot / defense 深化 / ai-meta）

---

## 驱动力：GitHub 趋势驱动扩面方法论第二波

v0.1.30 延续 v0.1.29 验证过的"GitHub 开源情报 → 缺口识别 → 技能扩面"工作流，从 v0.1.29 候选清单的第二梯队中选定 4 个：

| 新技能 | v0.1.29 候选列表中的定位 | 选定理由 |
|--------|--------------------------|----------|
| ai-agent-security | "MCP/Agent 攻击面，新兴高价值" | 100k+ 星生态，Agent 安全是 2026 年最热门方向 |
| iot-pentest | "MQTT/CoAP 应用层 IoT" | 填补现有 firmware/hardware 未覆盖的应用层 |
| detection-engineering | "Sigma/YARA 规则工程" | threat-hunting 的天然搭档，blue team 高需求 |
| agentic-pentest | "LLM 驱动的自动化渗透" | 与 autonomous-loops 互补，引入具体框架 |

---

## 新增技能域（+4）

### 1. ai-agent-security — AI Agent 攻击面（首个 ai-emerging 类）

- **GitHub 数据来源**：HexStrike AI (9.6k) + PentestGPT (13.7k) + AI-Infra-Guard (3.9k) + 整个 agent 生态（nanocoai 29k、ECC 216k、gemini-cli 105k、playwright-mcp 33k 等）= **100k+ 星**
- **覆盖**：MCP 工具投毒、间接提示注入、RAG 中毒、Agent 沙箱逃逸、多 Agent 横向移动
- **战略意义**：与 `llm-red-team`（v0.1.29）形成 LLM vs Agent 双技能矩阵（stateless vs stateful）
- **文件清单**：SKILL.md (575 行)、payloads.md (2,184 行)、test-cases.md (204 行, 12 TC-AA-001..012)、guides/ai-agent-security-playbook.md (976 行)
- **基线评分**：**85.1 / Excellent**
- **真实事件参考**：CVE-2025-3128 (Cursor)、CVE-2025-3148、MCP rug-pull 攻击、ChatGPT 插件注入

### 2. iot-pentest — IoT 应用层渗透（首个 iot 类）

- **GitHub 数据来源**：IoT-Technical-Guide (4.5k) + JWT-Goat (3.3k) + IoT-Goat + MQTT-Pwn + EMQX + awesome-connected-things-sec (3.3k) + awesome-embedded-and-iot-security (2.3k)
- **覆盖**：MQTT broker 滥用、CoAP 攻击、AMQP、AWS IoT / Azure IoT Hub / GCP IoT 后端、移动伴侣应用、Zigbee 应用层、OT/IoT 网关
- **战略意义**：与 `firmware-reverse` / `hardware-security` / `bluetooth-rfid-nfc` / `sdr-rf-attack` / `scada-ics-security` 形成 IoT 全栈覆盖
- **文件清单**：SKILL.md (499 行)、payloads.md (1,303 行)、test-cases.md (270 行, 12 TC-IP-001..012)、guides/iot-pentest-playbook.md (685 行)
- **基线评分**：**85.5 / Excellent**
- **OWASP IoT Top 10 (2018)** 全覆盖

### 3. detection-engineering — 检测规则工程（defense 深化）

- **GitHub 数据来源**：SigmaHQ (10.5k) + Yara-Rules (4.8k) + Loki (3.7k) + yarGen (1.8k) + sbousseaden/EVTX-ATTACK-SAMPLES (2.6k) + hayabusa + SigmaCLI + zircollo
- **覆盖**：Sigma 规则编写、YARA 签名、SPL/KQL/EQL 查询、ATT&CK 映射、检测 CI/CD、误报调优、检测即代码全生命周期
- **战略意义**：补齐 `threat-hunting`（用检测狩猎）+ `logging-monitoring`（日志基础设施）+ `deception-honeypot`（欺骗防御）四联体的检测规则编写维度
- **文件清单**：SKILL.md (755 行)、payloads.md (2,325 行)、test-cases.md (281 行, 12 TC-DE-001..012)、guides/detection-engineering-playbook.md (1,351 行)
- **基线评分**：**85.7 / Excellent**

### 4. agentic-pentest — LLM 驱动自动化渗透（首个 ai-meta 类）

- **GitHub 数据来源**：PentestGPT (13.7k) + HexStrike AI (9.6k) + Viper (5k) + PentestAgent (2.6k) + AI-Infra-Guard (3.9k) + AutoPWN + EvilPrompt
- **覆盖**：推理链编排、工具委派、上下文窗口管理、人机协同检查点、多 Agent 团队协作、成本优化
- **战略意义**：与 `ai-agent-security`（攻击 agent）形成攻/守对偶；与 `autonomous-loops`（通用模式）互补（提供领域专精框架）
- **文件清单**：SKILL.md (574 行)、payloads.md (1,771 行)、test-cases.md (199 行, 12 TC-AP-001..012)、guides/agentic-pentest-playbook.md (791 行)
- **基线评分**：**88.0 / Excellent**（v0.1.30 cohort 最高）

---

## 4 个新技能首次评分

SCORE.sh v2 首次为 4 个 v0.1.30 新技能打分：

| 排名 | 技能域 | 评分 | 等级 |
|------|--------|------|------|
| 1 | agentic-pentest | **88.0** | 优秀 (Excellent) |
| 2 | detection-engineering | **85.7** | 优秀 |
| 3 | iot-pentest | **85.5** | 优秀 |
| 4 | ai-agent-security | **85.1** | 优秀 |

**4/4 全部进入优秀 (Excellent) 区间**，且平均分（86.1）高于 v0.1.28 cohort（83.0）和 v0.1.29 cohort（85.2）—— 写作方法论渐趋成熟。

---

## 质量快照

| 指标 | v0.1.29 | v0.1.30 | 变化 |
|------|---------|---------|------|
| 技能域总数 | 83 | **87** | +4 |
| 卓越 (Distinguished，92 分及以上) | 19 | **19** | 不变 |
| 优秀 (Excellent，80–91.9 分) | 63 | **67** | +4 新 |
| 强 (Strong，60–80 分) | 1 | **1** | 不变（username-profiling 77.7） |
| 平均分 | 87.81 | **87.73** | -0.08（4 个新基线分微幅拖低） |
| 最低分 | 77.7 | **77.7** | 不变 |
| 最高分 | 93.8 | **93.8** | 不变 |

**86/87 技能域达到优秀或以上**（98.9%）。username-profiling 仍在 Strong 区间，下版本将针对性提升。

---

## 本版本工作量

| 项目 | 数量 |
|------|------|
| 新增文件 | 16（4×SKILL.md + 4×payloads.md + 4×test-cases.md + 4×guides） |
| 新增代码行 | **~14,743** |
| 新增测试用例 | **48**（12 × 4） |
| 新增工具引用 | ~52（4 技能 × 13 工具均值） |
| 首次评分技能 | 4 |
| 新晋卓越 | 0（v0.1.27 后续工作的红利已在 v0.1.29 兑现） |
| Heartbeat 健康检查 | **HEARTBEAT_OK**（437 个指南，0 个问题） |

---

## 索引文件同步

| 文件 | 更新内容 |
|------|----------|
| validation/update-skill-standard.py | 注册 4 个新技能；新增 4 个类别（ai-emerging、iot、defense 深化、ai-meta） |
| IDENTITY.md | 新增 4 个技能标签行 |
| TOOLS.md | 新增 4 个分类索引行；83 → 87 技能域 |
| README.md | 6 处 83 → 87；新增 4 行技能表格；新增 v0.1.30 changelog 行；刷新质量快照；版本 0.1.29 → 0.1.30 |
| CHANGELOG.md | 新增 v0.1.30 条目 |
| VERSION | 0.1.29 → 0.1.30 |

---

## 战略价值

### 三个"首个" / 类别深化

| 类别 | 技能 | 战略意义 |
|------|------|----------|
| ai-emerging（首个） | ai-agent-security | 与 ai-security + llm-red-team 形成 AI 三联体（普攻+精攻+Agent攻） |
| iot（首个） | iot-pentest | 与 firmware-reverse + hardware-security + bluetooth-rfid-nfc + sdr-rf-attack + scada-ics-security 形成 IoT 全栈 |
| defense 深化 | detection-engineering | 与 threat-hunting + logging-monitoring + deception-honeypot 形成蓝队四联体（检测规则+狩猎+日志+欺骗） |
| ai-meta（首个） | agentic-pentest | 与 autonomous-loops + multi-agent-collaboration 形成 Agent 元技能三联体（通用模式+多智能体+领域专精） |

### AI 技能矩阵成型

经过 v0.1.28 → v0.1.30 三波扩面，AI 类技能已形成完整矩阵：

```
ai-security (89.3)             ← 通用 AI 安全（普攻）
├── llm-red-team (82.4)        ← LLM 红队精攻（v0.1.29）
├── ai-agent-security (85.1)   ← Agent 攻击（v0.1.30）
├── ai-fuzzing (XX)            ← 模糊测试 AI
└── agentic-pentest (88.0)     ← LLM 驱动渗透（v0.1.30，工具视角）
```

### 蓝队技能矩阵成型

defense 类技能形成完整闭环：

```
threat-hunting (85.2)          ← 狩猎（v0.1.28）
├── deception-honeypot (84.8)  ← 欺骗诱捕（v0.1.29）
├── detection-engineering (85.7) ← 检测规则工程（v0.1.30）
└── logging-monitoring (XX)    ← 日志基础设施
```

---

## 下一步（v0.1.31 候选方向）

- **A**：底层提升 —— 将 username-profiling（77.7）拉升至 85+，重夺 100% Excellent+
- **B**：新技能深化 —— 为 v0.1.28+v0.1.29+v0.1.30 的 12 个新技能扩充指南数，目标全部进入 88+
- **C**：卓越冲刺 —— 将 deep-research（90.6）、ai-security（89.3）、av-edr-evasion（89.1）等 89-90 分段技能推升至 92+
- **D**：继续扩面 —— 量子密码学攻击、5G/移动网络攻击、云身份（IAM/SSO）攻击、邮件安全深度、物理安全测试等
- **E**：A + B 组合（专注质量，不再扩面）
- **F**：A + C 组合（底层提升 + 卓越冲刺，专注质量）

---

_本版本是 kali-claw 第一次在同一个日历日内连续发布两个版本（v0.1.29 → v0.1.30），标志着 GitHub 趋势驱动扩面工作流已成熟可复制。87 个技能域覆盖 19 个 Distinguished + 67 个 Excellent + 1 个 Strong，平均 87.73。_
