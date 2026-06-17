# kali-claw v0.1.29 发布公告 — GitHub 趋势驱动扩面 +4（79→83）

**发布日期**：2026-06-17
**技能域数量**：79 → **83**（+4）
**主题**：首个 GitHub 开源情报驱动的扩面版本；8 个新技能完成首次评分；意外收获 +2 卓越

---

## 驱动力：GitHub 开源情报分析

v0.1.29 是 kali-claw 首个**显式以 GitHub 趋势数据为依据**的扩面版本。候选技能通过以下流程筛选：

1. **领域扫描** —— 收集 GitHub 最近 12 个月内活跃的安全相关项目（按 stars 排序）
2. **缺口比对** —— 与现有 79 个技能域交叉比对，识别覆盖空白
3. **价值评估** —— 按"GitHub 星总数 × 与现有技能互补度 × 工具生态成熟度"加权
4. **最终选定** —— 4 个技能域覆盖 4 个独立的高密度生态

**4 个新技能生态累计 GitHub 星数：150k+**

---

## 新增技能域（+4）

### 1. llm-red-team — LLM 红队测试（首个 ai-red-team 类）

- **GitHub 数据来源**：promptfoo (22k) + garak (8k) + PyRIT (4k) + PurpleLlama (4.2k) + AI-Infra-Guard (3.9k) + llm-guard (3k) = **45k+ 星**
- **覆盖**：提示注入、越狱、模型抽取、RAG 中毒、Agent 工具滥用
- **MITRE**：LLM-ATT&CK + OWASP LLM Top 10 (LLM01-LLM10)
- **文件清单**：SKILL.md (583 行)、payloads.md (1,723 行)、test-cases.md (209 行, 12 TC-LR-001..012)、guides/llm-red-team-playbook.md (952 行)
- **基线评分**：**82.4 / Excellent**

### 2. deception-honeypot — 防御欺骗（补齐紫队三联体）

- **GitHub 数据来源**：T-Pot (9.3k) + Cowrie (6.4k) + OpenCanary (2.9k) + HFish (4.5k) + Beelzebub (2k) + Conpot (1.5k) = **26.6k 星**
- **覆盖**：SSH/Telnet/Web/ICS/AI 蜜罐、蜜标、Canary 部署、IOC 提取
- **MITRE**：TA0040-Detection（与 MITRE Engage 框架对齐）
- **战略意义**：与 `threat-hunting`（检测）+ `deception-honeypot`（诱捕）形成完整紫队三联体
- **文件清单**：SKILL.md (789 行)、payloads.md (1,936 行)、test-cases.md (272 行, 12 TC-DH-001..012)、guides/deception-honeypot-playbook.md (1,008 行)
- **基线评分**：**84.8 / Excellent**

### 3. kubernetes-attack — K8s 红队（云原生深度专项）

- **GitHub 数据来源**：kubescape (11k) + CDK (4.7k) + kube-hunter (5k) + stratus-red-team (2.3k) + kubernetes-goat (5.7k) + peirates = **28.7k+ 星**
- **覆盖**：RBAC 滥用、Pod 逃逸、ServiceAccount Token 盗用、API Server 攻击、etcd 攻击、EKS/GKE/AKS 横向移动
- **MITRE**：TA0008-Lateral Movement（Containers ATT&CK）
- **战略意义**：从 `cloud-security` / `container-security` 宽泛技能中抽取 K8s 专项深度
- **文件清单**：SKILL.md (509 行)、payloads.md (1,243 行)、test-cases.md (302 行, 12 TC-KA-001..012)、guides/kubernetes-attack-playbook.md (700 行)
- **基线评分**：**87.5 / Excellent**（4 个新技能中最高）

### 4. secret-management-attack — 秘密/代码审计（应用安全深度专项）

- **GitHub 数据来源**：gitleaks (27k) + semgrep (15k) + infisical (27k) + bearer (2.7k) + DeepAudit (6.4k) + trufflehog + apkleaks (6k) + cariddi (3.4k) = **87k+ 星**
- **覆盖**：秘密扫描、SAST、Vault/秘密管理平台攻击、CI/CD 秘密盗取、容器镜像层分析
- **MITRE**：T1552-Unsecured Credentials 全家族
- **战略意义**：从 `security-review` / `repo-scan` 宽泛技能中抽取秘密/审计专项深度
- **文件清单**：SKILL.md (523 行)、payloads.md (1,808 行)、test-cases.md (227 行, 12 TC-SM-001..012)、guides/secret-management-attack-playbook.md (784 行)
- **基线评分**：**85.9 / Excellent**

---

## 8 个新技能首次评分（含 v0.1.28 cohort）

SCORE.sh v2 首次为 v0.1.28 的 4 个 + v0.1.29 的 4 个 = 共 8 个新技能打分：

| 排名 | 技能域 | 版本 | 评分 | 等级 |
|------|--------|------|------|------|
| 1 | kubernetes-attack | v0.1.29 | **87.5** | 优秀 (Excellent) |
| 2 | secret-management-attack | v0.1.29 | **85.9** | 优秀 |
| 3 | threat-hunting | v0.1.28 | 85.2 | 优秀 |
| 4 | deception-honeypot | v0.1.29 | **84.8** | 优秀 |
| 5 | darkweb-intel | v0.1.28 | 84.7 | 优秀 |
| 6 | llm-red-team | v0.1.29 | **82.4** | 优秀 |
| 7 | payment-security | v0.1.28 | 81.8 | 优秀 |
| 8 | blockchain-web3 | v0.1.28 | 80.1 | 优秀 |

**8/8 全部进入优秀 (Excellent) 区间** —— 无需后续修复。

---

## 意外收获：+2 卓越 (Distinguished)

SCORE.sh v2 重新评估全部 83 个技能时，2 个旧技能因 v0.1.27 后续冲刺工作（深度指南 + SKILL.md 扩充）跨越了 92 分门槛：

| 技能域 | v0.1.27 → v0.1.29 | 提升 | 措施 |
|--------|-------------------|------|------|
| **sdr-rf-attack** | 89.5 → **93.6** | **+4.1** ⭐ | v0.1.27 后续工作新增 3 个指南（rf-fingerprinting、satellite-analysis、sub-ghz-iot）；SKILL.md +123 行 |
| **container-security** | 90.4 → **92.8** | **+2.4** ⭐ | v0.1.27 后续工作新增 3 个指南（network-segmentation、supply-chain-attack、docker-breakout） |

**卓越 (Distinguished) 总数：17 → 19**

---

## 完整卓越列表（19 个）

| 序号 | 技能域 | 分数 |
|------|--------|------|
| 1 | social-intelligence | 93.8 |
| 2 | sdr-rf-attack | **93.6** ⭐ 新晋 |
| 3 | article-writing | 93.6 |
| 4 | payload-generation | 93.1 |
| 5 | scada-ics-security | 93.0 |
| 6 | vulnerability-assessment | 93.0 |
| 7 | container-security | **92.8** ⭐ 新晋 |
| 8 | security-misconfiguration | 92.8 |
| 9 | autonomous-loops | 92.6 |
| 10 | verification-loop | 92.6 |
| 11 | osint | 92.5 |
| 12 | vpn-attack | 92.5 |
| 13 | council | 92.3 |
| 14 | network-tunneling-proxy | 92.3 |
| 15 | web-deserialization | 92.2 |
| 16 | cloud-security | 92.1 |
| 17 | network-pentest | 92.0 |
| 18 | security-bounty-hunter | 92.0 |
| 19 | web-xss | 92.0 |

---

## 质量快照

| 指标 | v0.1.28 | v0.1.29 | 变化 |
|------|---------|---------|------|
| 技能域总数 | 79 | **83** | +4 |
| 卓越 (Distinguished，92 分及以上) | 17 | **19** | **+2**（sdr-rf-attack、container-security） |
| 优秀 (Excellent，80–91.9 分) | 57 | **63** | +8 新 -2 升 |
| 强 (Strong，60–80 分) | 0 | **1** | +1（username-profiling 77.7） |
| 平均分 | 88.2 | **87.81** | -0.39（8 个新基线分拖低） |
| 最低分 | 84.5 | **77.7** | username-profiling 需扩充指南 |
| 最高分 | 93.8 | **93.8** | social-intelligence 不变 |

**82/83 技能域达到优秀或以上**（98.8%）。username-profiling 进入 Strong 区间，下版本将针对性提升。

---

## 本版本工作量

| 项目 | 数量 |
|------|------|
| 新增文件 | 16（4×SKILL.md + 4×payloads.md + 4×test-cases.md + 4×guides） |
| 新增代码行 | **~13,568** |
| 新增测试用例 | **48**（12 × 4） |
| 新增工具引用 | ~52（4 技能 × 13 工具均值） |
| 首次评分技能 | 8（含 v0.1.28 cohort） |
| 新晋卓越 | 2（sdr-rf-attack、container-security） |
| Heartbeat 健康检查 | **HEARTBEAT_OK**（433 个指南，0 个问题） |

---

## 索引文件同步

| 文件 | 更新内容 |
|------|----------|
| validation/update-skill-standard.py | 注册 4 个新技能到 ATTACK_SKILLS / DOMAIN_MAP / MITRE_MAP |
| IDENTITY.md | 新增 4 个技能标签行 |
| TOOLS.md | 新增 4 个分类索引行；79 → 83 技能域 |
| README.md | 6 处 79 → 83；新增 4 行技能表格；新增 v0.1.29 changelog 行；刷新质量快照；版本 0.1.28 → 0.1.29 |
| CHANGELOG.md | 新增 v0.1.29 条目 |
| VERSION | 0.1.28 → 0.1.29 |

---

## 战略价值

### 三个"首个" / "深度专项"

| 类别 | 技能 | 战略意义 |
|------|------|----------|
| ai-red-team（首个） | llm-red-team | 与 ai-security 形成普攻+精攻组合；覆盖 OWASP LLM Top 10 |
| defense 补齐 | deception-honeypot | 与 threat-hunting 形成检测+诱捕紫队三联体 |
| cloud-native 深化 | kubernetes-attack | 从 cloud/container 宽泛技能中抽取 K8s 专项 |
| appsec 深化 | secret-management-attack | 从 security-review/repo-scan 中抽取秘密/审计专项 |

### GitHub 趋势驱动方法论首次落地

v0.1.29 验证了"GitHub 开源情报 → 缺口识别 → 技能扩面"的工作流。此方法论可复用于后续版本：

- v0.1.30 候选：`ai-agent-security`（MCP/Agent 攻击面）、`iot-pentest`（MQTT/CoAP）、`detection-engineering`（Sigma/YARA）、`agentic-pentest`（LLM 驱动的自动化渗透）

---

## 下一步（v0.1.30 候选方向）

- **A**：底层提升 —— 将 username-profiling（77.7）拉升至 85+，重夺 100% Excellent+
- **B**：新技能深化 —— 为 v0.1.28+v0.1.29 的 8 个新技能扩充指南数（每个 1→3），目标全部进入 88+
- **C**：继续扩面 —— ai-agent-security / iot-pentest / detection-engineering / agentic-pentest 任选
- **D**：卓越冲刺 —— 将 deep-research（90.6）、exa-search、ai-fuzzing、terminal-ops 等 90 分段技能推升至 92+
- **E**：A + B + D 组合（不再扩面，专注质量）

---

_本版本是 kali-claw 首次将 GitHub 开源情报分析纳入版本规划工作流，并意外收获 +2 卓越技能。验证了"扩面也能带动深化"的版本节奏。_
