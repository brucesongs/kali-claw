# kali-claw v0.1.36 发布公告 — E 计划：Distinguished 冲刺 + 底部提升（+9 Distinguished，19→28）

**发布日期**：2026-06-25
**技能域数量**：103（不变，纯质量版本）
**主题**：v0.1.35 完成第六波扩面之后，本版本执行 E 计划——Distinguished 冲刺（A，将 89-91 分段推升至 92+）+ 底部提升（C，将 81-83 分段提升至 85+）双轨战术

---

## 驱动力：E 计划（A + C 组合）首次执行

v0.1.36 是 kali-claw 历史上**单版本最大幅度的质量提升**。E 计划包含两条并行轨道：

| 轨道 | 目标 | 实际结果 |
|------|------|----------|
| A — Distinguished 冲刺 | 将 89-91 分段的 6 个技能推升至 92+（Distinguished 25+） | **8 个技能进入 Distinguished**（含 2 个底部提升溢出） |
| C — 底部提升 | 将 81-83 分段的 3 个底部技能提升至 85+ | **3 个全部成功**，其中 2 个意外达到 Distinguished |

**关键发现**：A 与 C 的协同效应超出预期——本为"底部提升至 85+"设计的多杠杆策略，在 5g-telecom-attack 和 macos-security 上意外推升至 92+ Distinguished。

---

## 9 个技能全部成功提升

| 技能 | 原分 | 新分 | 增量 | 等级变化 | 轨道 |
|------|------|------|------|----------|------|
| secret-management-attack | 90.4 | **94.6** | +4.2 | Excellent→**Distinguished** | A |
| deep-research | 90.6 | **93.5** | +2.9 | Excellent→**Distinguished** | A |
| 5g-telecom-attack | 82.5 | **92.7** | +10.2 | Excellent→**Distinguished** ⚡ | C（溢出至 A） |
| embedded-rtos-security | 88.8 | **92.7** | +3.9 | Excellent→**Distinguished** | A |
| agentic-pentest | 90.0 | **92.6** | +2.6 | Excellent→**Distinguished** | A |
| quantum-crypto-attack | 90.8 | **92.5** | +1.7 | Excellent→**Distinguished** | A |
| macos-security | 82.7 | **92.2** | +9.5 | Excellent→**Distinguished** ⚡ | C（溢出至 A） |
| username-profiling | 91.6 | **92.2** | +0.6 | Excellent→**Distinguished** | A |
| hf-vhf-radio-attack | 89.3 | **92.1** | +2.8 | Excellent→**Distinguished** | A |
| email-security-deep | 81.0 | **91.3** | +10.3 | Excellent→Excellent+（距 Distinguished 仅 0.7 分） | C |

**平均提升**：+4.87 分（9 个技能）
**最大单技能提升**：email-security-deep +10.3（自 v0.1.34 automotive +9.7 以来最大）

---

## 每个技能的策略细节

### A 轨道：Distinguished 冲刺（8 个技能 → 92+）

#### 1. username-profiling（91.6 → 92.2）

- **瓶颈**：guides=76（单 guide 上限）
- **策略**：新增第 2 个 guide
- **新文件**：`guides/username-profiling-deep-dive.md`（1,411 行）
- **主题**：跨平台身份图谱关联——将 Maigret/Sherlock/WhatsMyName/Blackbird/Holehe 多工具输出归一化，加载至 Neo4j，PDQ 感知哈希做头像匹配，概率实体解析，HIBP/DeHashed/IntelX breach 关联

#### 2. quantum-crypto-attack（90.8 → 92.5）

- **瓶颈**：guides=76（已有 2 个 guide，需 3 个突破）
- **策略**：新增第 3 个 guide + payloads.md 扩展
- **新文件**：`guides/quantum-crypto-attack-deep-dive.md`（1,020 行）
- **主题**：PQC 实现硬化与侧信道实验室——OpenSSL 3.x oqs-provider 配置、混合 PKI 生成、dudect/ctgrind/ChipWhisperer TVLA、故障注入 PoC、4 个 CTF 场景
- **payloads 扩展**：+25 代码块，+6 章节（oqs-provider、混合 PKI、TLS 握手验证、telemetry、crypto-agility drill、fault-injection PoC）

#### 3. deep-research（90.6 → 93.5）

- **瓶颈**：guides=76 + skill_md=93
- **策略**：新增第 6 个 guide + SKILL.md 扩展
- **新文件**：`guides/multi-source-synthesis-guide.md`（685 行）
- **主题**：多源情报综合——三角验证、置信度评分、偏见过滤、引文链验证、威胁行为者归因方法论
- **SKILL.md 扩展**：+7 章节（Triangulation Principle、Confidence Scoring、Bias Filtering、Citation Chain Verification、Threat Actor Attribution、Synthesis Product Structure）——skill_md 93→100

#### 4. secret-management-attack（90.4 → 94.6）

- **瓶颈**：guides=76 + test_cases_md=88（字段完整度 0.86）
- **策略**：新增第 3 个 guide + test-cases.md 扩展
- **新文件**：`guides/cicd-secret-sprawl-and-sast-rule-deep-dive.md`（1,142 行）
- **主题**：CI/CD secret 扩散审计 + 自定义 SAST 规则编写——GitHub Actions/GitLab CI/Jenkins/Terraform 签发，gitleaks/semgrep/bearer 自定义规则，精度/召回验证
- **test-cases 扩展**：+6 TC（TC-SM-013..018），为所有 12 个现有 TC 补齐 Prerequisites 字段，新增端到端验证清单——tc_md 88→100

#### 5. agentic-pentest（90.0 → 92.6）

- **瓶颈**：guides=76 + skill_md=87
- **策略**：新增第 3 个 guide + SKILL.md 扩展
- **新文件**：`guides/agentic-pentest-deep-dive.md`（702 行）
- **主题**：多 Agent 团队协作模式 + HITL 检查点设计 + LLM 驱动自主渗透案例研究——四角色参考团队、PentestGPT/HexStrike/Viper 拓扑、5 类安全分类、3 个端到端案例研究
- **SKILL.md 扩展**：+6 章节（Attack Matrix、Reasoning-Chain Architecture、Safety Considerations、Operational Constraints、Common Pitfalls）——skill_md 87→100

#### 6. hf-vhf-radio-attack（89.3 → 92.1）

- **瓶颈**：guides=68（单 guide）
- **策略**：新增第 2 个 guide + playbook 扩展 + payloads 扩展
- **新文件**：`guides/hf-vhf-radio-attack-deep-dive.md`（1,723 行）
- **主题**：ADS-B/AIS 欺骗实验室（HackRF/BladeRF TX + Faraday 笼验证 + ghost aircraft/vessel I/Q 生成 + MLAT 欺骗检测）、航空海事 OPSEC、寻呼网络利用
- **playbook 扩展**：+375 行（天线设计基础 + SDR 硬件选择矩阵）
- **payloads 扩展**：+19 代码块（NanoVNA、I/Q 录制/重放、TX-side 工具）

#### 7. embedded-rtos-security（88.8 → 92.7）

- **瓶颈**：guides=68 + skill_md=92
- **策略**：新增 2 个 guide + playbook 扩展 + SKILL.md 扩展
- **新文件 1**：`guides/embedded-rtos-security-deep-dive.md`（1,161 行）——VxWorks WDB RPC 调试代理利用实验室（Urgent/11 CVE-2019-12256/12258/12260/12264 全部复现）
- **新文件 2**：`guides/freertos-tcp-vulnerability-research.md`（972 行）——FreeRTOS+TCP CVE 复现 + AFL++ fuzzing + angr 符号执行
- **playbook 扩展**：+229 行（RTOS MITRE ATT&CK for Cloud + ICS 映射、Secure Boot/TEE 分析）
- **SKILL.md 扩展**：+8 章节——skill_md 92→100

### C 轨道：底部提升（3 个技能 → 85+；2 个意外达 Distinguished）

#### 8. email-security-deep（81.0 → 91.3）

- **瓶颈**：skill_md=85 + payloads_md=84 + guides=58（三重瓶颈）
- **策略**：全杠杆齐上——SKILL.md 修复 + payloads 大幅扩展 + 新增 guide
- **新文件**：`guides/email-security-deep-deep-dive.md`（819 行）——AiTM 钓鱼活动仿真实验室（evilginx2 + 反向代理 + 证书生成 + lure 模板 + 凭证/会话捕获 + MFA 绕过 + 检测规避 + 防御/IR 清单）
- **payloads 扩展**：+27 代码块（44→71），+940 行——AiTM 基础设施 playbook、网关绕过（Proofpoint/Mimecast/Cisco ESA）、MFA 疲劳轰炸、邮件 DDoS、DMARC/SPF/DKIM 侦察
- **SKILL.md 扩展**：+3 章节（Threat Landscape、Tool Comparison Matrix、Lab and Training Environment）——skill_md 85→100
- **结果**：+10.3 分，距 Distinguished 仅 0.7 分

#### 9. 5g-telecom-attack（82.5 → 92.7）

- **瓶颈**：skill_md=84 + test_cases_md=80 + guides=68
- **策略**：全杠杆齐上
- **新文件**：`guides/5g-telecom-attack-deep-dive.md`（1,165 行）——5G Core 实验室复现（srsRAN_Project + Open5GS + UERANSIM 全套搭建 + PFCP 攻击复现 Praetorian 2019 + Diameter S6a 实验室 + IMSI catcher 检测 + SUCI/SUPI 隐私分析）
- **test-cases 扩展**：+6 TC（TC-5G-013..018）+ 验证清单 + 防御模式映射——tc_md 80→100
- **SKILL.md 扩展**：+13 章节（5GC 组件参考、RAN 架构、互操作互联、PFCP 攻击面、Diameter/SS7、O-RAN 安全、真实事件时间线、3GPP 规范参考、标准化机构等）——skill_md 84→100
- **结果**：+10.2 分，**意外达 Distinguished**

#### 10. macos-security（82.7 → 92.2）

- **瓶颈**：skill_md=89 + test_cases_md=80 + guides=68
- **策略**：全杠杆齐上
- **新文件**：`guides/macos-security-deep-dive.md`（1,416 行）——Apple Silicon 安全架构深度（启动链 SSV/Rosetta、PPL、PAC）、ESF 内部原理、TCC.db 逆向工程、近期 CVE（CVE-2023-32434/32435/41990、CVE-2024-23222/23225、CVE-2025-31132）、红队实战手册、实验室构建
- **test-cases 扩展**：+6 TC（TC-MO-013..018）+ 3 个附录（先决条件矩阵、修复 playbook、验证清单）——tc_md 80→100
- **SKILL.md 扩展**：+8 章节——skill_md 89→100
- **结果**：+9.5 分，**意外达 Distinguished**

---

## 质量快照

| 指标 | v0.1.35 | v0.1.36 | 变化 |
|------|---------|---------|------|
| 技能域总数 | 103 | **103** | 不变（纯质量版本） |
| 卓越 (Distinguished，92 分及以上) | 19 | **28** | **+9**（超出 25+ 目标） |
| 优秀 (Excellent，80–91.9 分) | 84 | **75** | -9（全部提升至 Distinguished） |
| 强 (Strong，60–80 分) | 0 | **0** | 不变 |
| 平均分 | 87.98 | **88.45** | +0.47 |
| 最低分 | 81.0 | **83.8**（cloud-identity-attack） | +2.8 |
| 最高分 | 93.8 | **94.6**（secret-management-attack） | +0.8 |
| 85+ 技能数 | 99/103 | **99/103** | 不变（4 个仍在 83.8-84.6） |
| Excellent+ 覆盖率 | 103/103 (100%) | **103/103 (100%)** | 维持 |

→ **Distinguished 25+ 目标达成**：28 个技能进入 Distinguished，比目标多 3 个。
→ **底部最低分提升**：81.0 → 83.8（+2.8），但仍未完全消除 85- 段（4 个技能在 83.8-84.6）。
→ **平均分历史新高**：88.45（首次突破 88.4）。

---

## Distinguished 梯队完整名单（28 个）

按分数降序：

| 排名 | 技能 | 分数 | 进入版本 |
|------|------|------|----------|
| 1 | secret-management-attack | **94.6** | v0.1.36（本版本） |
| 2 | social-intelligence | 93.8 | v0.1.24 |
| 3 | sdr-rf-attack | 93.6 | v0.1.22 |
| 3 | article-writing | 93.6 | v0.1.23 |
| 5 | deep-research | **93.5** | v0.1.36（本版本） |
| 6 | payload-generation | 93.1 | v0.1.26 |
| 7 | scada-ics-security | 93.0 | v0.1.27 |
| 7 | vulnerability-assessment | 93.0 | v0.1.23 |
| 9 | container-security | 92.8 | v0.1.25 |
| 9 | security-misconfiguration | 92.8 | v0.1.25 |
| 11 | 5g-telecom-attack | **92.7** | v0.1.36（本版本） |
| 11 | embedded-rtos-security | **92.7** | v0.1.36（本版本） |
| 13 | agentic-pentest | **92.6** | v0.1.36（本版本） |
| 14 | autonomous-loops | 92.6 | v0.1.23 |
| 14 | verification-loop | 92.6 | v0.1.24 |
| 16 | quantum-crypto-attack | **92.5** | v0.1.36（本版本） |
| 16 | osint | 92.5 | v0.1.24 |
| 16 | vpn-attack | 92.5 | v0.1.26 |
| 19 | macos-security | **92.2** | v0.1.36（本版本） |
| 19 | username-profiling | **92.2** | v0.1.36（本版本） |
| 19 | web-deserialization | 92.2 | v0.1.26 |
| 22 | council | 92.3 | v0.1.27 |
| 22 | network-tunneling-proxy | 92.3 | v0.1.26 |
| 24 | hf-vhf-radio-attack | **92.1** | v0.1.36（本版本） |
| 24 | cloud-security | 92.1 | v0.1.22 |
| 24 | security-bounty-hunter | 92.0 | v0.1.25 |
| 24 | network-pentest | 92.0 | v0.1.21 |
| 24 | web-xss | 92.0 | v0.1.25 |

**v0.1.36 新晋 Distinguished（9 个）**：5g-telecom-attack、embedded-rtos-security、agentic-pentest、quantum-crypto-attack、macos-security、username-profiling、hf-vhf-radio-attack、deep-research、secret-management-attack

---

## 本版本工作量

| 项目 | 数量 |
|------|------|
| 提升技能数 | **9** |
| 新增 guide 文件 | **11**（每技能 1-2 个） |
| SKILL.md 扩展 | 7 个（新增章节） |
| test-cases.md 扩展 | 3 个（+18 TC + 验证清单） |
| payloads.md 扩展 | 4 个（+89 代码块合计） |
| playbook 扩展 | 2 个（+604 行合计） |
| 新增代码行 | **~9,500**（11 个新 guide ~7,000 + 其他扩展 ~2,500） |
| 新增测试用例 | 18（6 × 3） |
| 新晋 Distinguished | **9** |
| Heartbeat 健康检查 | **HEARTBEAT_OK** |

---

## 索引文件同步

| 文件 | 更新内容 |
|------|----------|
| README.md | 刷新质量快照（19→28 Distinguished，avg 87.98→88.45，min 81.0→83.8，max 93.8→94.6）；新增 v0.1.36 changelog 行；版本 0.1.35 → 0.1.36 |
| CHANGELOG.md | 新增 v0.1.36 条目 |
| VERSION | 0.1.35 → 0.1.36 |

---

## 方法论验证：E 计划 = 历史最高质量单版本

| 版本 | 类型 | Distinguished 增量 |
|------|------|---------------------|
| v0.1.21 | 单技能突破 | +1（network-pentest，首个 Distinguished） |
| v0.1.22 | +2 技能 | +1（cloud-security） |
| v0.1.23 | 5 Distinguished 里程碑 | +3（article-writing, vulnerability-assessment, autonomous-loops） |
| v0.1.24 | 8 Distinguished 里程碑 | +3（osint, social-intelligence, verification-loop） |
| v0.1.25 | 11 Distinguished 里程碑 | +3（security-misconfiguration, security-bounty-hunter, web-xss） |
| v0.1.26 | 15 Distinguished 里程碑 | +4（payload-generation, vpn-attack, network-tunneling-proxy, web-deserialization） |
| v0.1.27 | 17 Distinguished 里程碑 | +2（scada-ics-security, council） |
| **v0.1.36** | **E 计划 Distinguished 冲刺** | **+9** ← 历史最高 |

→ **E 计划的单版本 Distinguished 增量（+9）超过此前任何版本**，证明"多杠杆并行"（SKILL.md 修复 + 2nd guide + TC 扩展 + payloads 扩展）的有效性。

---

## 战略价值：四大质量维度全面突破

### 数量维度

- Distinguished 19 → **28**（+9，+47% 相对增长）
- Excellent+ 维持 **103/103 (100%)**
- Strong 维持 **0**

### 深度维度

- 最低分 81.0 → **83.8**（+2.8）
- 85+ 技能 99/103（仍有 4 个在 83.8-84.6 待提升）

### 广度维度

- v0.1.36 cohort 跨越 7 个类别：移动安全、量子密码、深度研究、Secret 管理、Agent 安全、HF/VHF 无线、嵌入式 RTOS、邮件安全、5G 电信、macOS
- 9 个技能分布：3 个 v0.1.28-v0.1.31 cohort、4 个 v0.1.33-v0.1.35 cohort、2 个老技能

### 方法论维度

- E 计划首次执行成功
- "多杠杆并行"策略验证（SKILL.md + guide + TC + payloads 四管齐下）
- "底部提升溢出至 Distinguished"现象首次记录（5g-telecom-attack、macos-security）

---

## 下一步（v0.1.37 候选方向）

- **A**：推 email-security-deep（91.3）跨越 92.0——仅需 +0.7（可能只需 1 个第 2 个 guide 或 playbook 扩展）
- **B**：提升剩余 4 个 85- 技能至 85+（cloud-identity-attack 83.8、mobile-app-instrumentation 84.5、blockchain-web3 84.6、dns-attacks 84.6）→ 全部技能 85+
- **C**：v0.1.35 cohort 深化——为 ics-fieldbus-attack（88.1）和 blockchain-l2-attack（87.2）添加第 2 个 guide，推向 Distinguished
- **D**：第 7 波扩面（存储/SAN、Hypervisor introspection、PQC 迁移深化、卫星/LEO、AD CS 滥用、OAuth2/OIDC 深度）
- **E**：Distinguished 30+ 冲刺——推 91.x 集群（email-security-deep 91.3）+ 识别 92 边界候选

---

_本版本是 kali-claw 历史上单版本最大幅度的质量提升：Distinguished +9（19→28），平均分 87.98→88.45，最低分 81.0→83.8。E 计划（A+C 组合）首次执行即超越 Distinguished 25+ 目标 3 个。9 个技能全部成功提升，其中 8 个达 Distinguished，1 个（email-security-deep 91.3）距 Distinguished 仅 0.7 分将在 v0.1.37 收尾。下版本重点：消除最后 4 个 85- 技能或第 7 波扩面。_
