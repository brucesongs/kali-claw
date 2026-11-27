# kali-claw v0.1.28 发布公告 — 技能域扩面 +4（75→79）

**发布日期**：2026-06-16
**技能域数量**：75 → **79**（+4）
**主题**：技能域扩面双线推进 —— 新增 4 个跨域技能，补齐防御 / 金融 / 区块链空白

---

## 新增技能域（+4）

| 序号 | 技能域 | 类别 | 工具数 | MITRE | 测试用例 |
|------|--------|------|--------|-------|----------|
| 1 | **darkweb-intel** | osint（开源情报） | 10 | TA0043-Reconnaissance | 12 |
| 2 | **threat-hunting** | defense（防御，**首个防御类**） | 12 | TA0040-Detection | 12 |
| 3 | **blockchain-web3** | blockchain（区块链，**首个区块链类**） | 14 | N/A（应用层；松散对应 TA0001-Initial Access） | 13 |
| 4 | **payment-security** | financial（金融，**首个金融类**） | 12 | T1566-Phishing + 领域特定 | 13 |

---

## 各技能域内容

### darkweb-intel — 暗网情报

- **场景**：Tor/onion 隐藏服务枚举、暗网市场情报、泄露站点监控、攻击者归因
- **核心工具**：tor、ahmia、onionsearch、darkdump、intelx、shodan(onion)、hunchly
- **方法论**：OPSEC 隔离 → onion 发现 → 内容抽取 → 关联归因 → 持续监控
- **文件清单**：SKILL.md（572 行）、payloads.md（1,227 行）、test-cases.md（253 行，12 个测试用例 TC-DW-001..012）、guides/dark-web-investigation-playbook.md（616 行）

### threat-hunting — 威胁狩猎（首个防御类技能）

- **场景**：假设驱动的主动狩猎、SIEM/EDR 遥测数据透视、ATT&CK 检测工程、紫队验证
- **核心工具**：splunk、elk、sentinel、zeek、veliciraptor、yara、sigma、mitre-attack
- **方法论**：威胁建模 → 假设生成 → 数据透视 → 检测工程 → 紫队验证闭环
- **价值**：与现有攻击技能形成**红↔蓝紫队闭环**（attack skills ↔ threat-hunting）
- **文件清单**：SKILL.md（590 行）、payloads.md（1,175 行）、test-cases.md（253 行，12 个测试用例 TC-TH-001..012）、guides/hunt-hypothesis-playbook.md（805 行）

### blockchain-web3 — 区块链/Web3 安全（首个区块链类技能）

- **场景**：智能合约审计、DeFi 漏洞链、钱包/密钥管理、跨链桥/预言机攻击
- **核心工具**：slither、mythril、echidna、foundry、ganache、securify、solidity-coverage
- **方法论**：源码审计 → 字节码分析 → 模糊测试 → 形式化验证 → 攻击 PoC
- **文件清单**：SKILL.md（567 行）、payloads.md（1,203 行）、test-cases.md（271 行，13 个测试用例 TC-BW-001..013）、guides/smart-contract-audit-playbook.md（691 行）

### payment-security — 支付安全（首个金融类技能）

- **场景**：PCI-DSS 评估、卡数据流分析、3DS/SAML SSO、欺诈检测、Webhook 签名验证
- **核心工具**：burpsuite、pwntools、openssl、gitleaks、testssl、token-explorer
- **方法论**：范围确认 → 卡数据流追踪 → PCI-DSS 控制验证 → 应用层攻击面测试 → 持续合规
- **文件清单**：SKILL.md（509 行）、payloads.md（966 行）、test-cases.md（270 行，13 个测试用例 TC-PS-001..013）、guides/payment-pentest-playbook.md（752 行）

---

## 索引文件同步

| 文件 | 更新内容 |
|------|----------|
| validation/update-skill-standard.py | 注册 4 个新技能到 ATTACK_SKILLS / DOMAIN_MAP / MITRE_MAP |
| IDENTITY.md | 新增 4 个技能标签行 |
| TOOLS.md | 新增 5 个分类索引行（含补齐 sdr-rf-attack、vpn-attack）；74 → 79 技能域 |
| README.md | 6 处 75 → 79 技能域；新增 4 行技能表格行；新增 v0.1.28 changelog 行；版本 0.1.27 → 0.1.28 |
| CHANGELOG.md | 新增 v0.1.28 条目 |
| VERSION | 0.1.27 → 0.1.28 |

---

## 质量快照

| 指标 | v0.1.27 | v0.1.28 |
|------|---------|---------|
| 技能域总数 | 75 | **79**（+4） |
| 卓越（Distinguished，92 分及以上） | 17 | **17**（不变，新技能尚未首次评分） |
| 优秀（Excellent，80–91.9 分） | 57 | **57**（不变） |
| 平均分 | 88.2 | **88.2**（不变） |
| 最低分 | 84.5 | **84.5**（不变） |
| Heartbeat 健康检查 | — | **HEARTBEAT_OK**（429 个指南检查，0 个问题） |

**100% 技能域达到优秀或以上**（79/79）。

---

## 本版本工作量

- **新增文件**：16 个（4 × SKILL.md + 4 × payloads.md + 4 × test-cases.md + 4 × guides/）
- **新增代码**：约 **10,720 行**
- **新增测试用例**：**50 个**（darkweb 12 + threat-hunting 12 + blockchain 13 + payment 13）
- **首次覆盖领域**：防御（defense）、金融（financial）、区块链（blockchain）
- **首个紫队闭环**：threat-hunting（蓝队）↔ 现有 70+ 攻击技能（红队）

---

## 战略价值

### 三个"首次"领域

| 领域 | 首个技能 | 战略意义 |
|------|----------|----------|
| defense（防御） | threat-hunting | 补齐红队技能体系的蓝队对应面，实现紫队闭环 |
| financial（金融） | payment-security | 覆盖 PCI-DSS、3DS、卡数据流等高价值目标 |
| blockchain（区块链） | blockchain-web3 | 覆盖 DeFi、智能合约、跨链桥等新兴攻击面 |

### OSINT 横向扩面

- `darkweb-intel` 是 `username-profiling`（v0.1.27 新增）之后的第二个 OSINT 类新技能
- 形成 OSINT 全栈：表层网（osint、recon-osint）→ 用户画像（username-profiling）→ 暗网（darkweb-intel）

---

## 下一步（v0.1.29 候选方向）

- **A**：新技能评分冲刺 —— 为 4 个新技能首次运行 SCORE.sh，确立基线分
- **B**：卓越冲刺延续 —— 将 sdr-rf-attack（89.5）、web-access-control（88.1）、exploit-development（86.1）推升至 92 分以上
- **C**：底层提升 —— 将最低分技能群（83–85 分区间）拉升至 87 分以上
- **D**：继续扩面 —— 物联网安全（IoT/IIoT）、量子密码学攻击、云原生供应链等
- **E**：A + B + C + D 组合推进

---

_本版本是 kali-claw 项目首次在同一次发布中同时跨入防御、金融、区块链三个新领域，标志着从纯攻击导向转向攻防兼备的全面安全代理。_
