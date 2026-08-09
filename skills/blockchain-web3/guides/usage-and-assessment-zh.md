# blockchain-web3 — 使用说明与能力评估

> **评估日期**：2026-08-09 | **评估者**：Claude（自动化 + 人工审查） | **评估版本**：v0.2.0.2
> **总分**：**70/100（良好）** | **问题**：P0:0 P1:2 P2:1 P3:1
> **Wave 1 Batch 1**（第 6 个评估的 SKILL）

## 评估速览

| 维度 | 得分（1-5） | 说明 |
|------|-----------|------|
| 1. 合规性 | **5** | 0/0/0 |
| 2. 内容完整性 | **5** | payloads 2626 + test-cases 271 + 5 guides；11 H2 + 25 H3 |
| 3. 命令语法 | **2** | VM 上 0/10 工具可用（Ethereum 工具链全缺）；静态审查命令有效 |
| 4. 参考文献 | **4** | 15 URL（好）；0 CVE（可补主流智能合约利用） |
| 5. MITRE/OWASP 对齐 | **1** | **body 中 0 个 ATT&CK T-codes**；frontmatter 标 N/A — 严重缺口 |
| 6. 可用性 | **4** | 智能合约 / DeFi / 钱包覆盖强；EVM/Solana/Cosmos 都覆盖 |
| **加权总分** | **70/100** | **良好** — D3+D5 拉低总分；OWASP Top 10 / SAFECode 未映射 |

---

## 使用说明

### 这个 SKILL 做什么
区块链/web3 安全测试，覆盖 EVM（Ethereum/BSC/Polygon/Arbitrum）、Solana、Cosmos 等链。涵盖：智能合约利用（重入/整数溢出/访问控制）、DeFi 攻击（闪电贷/预言机操纵）、钱包攻陷（MetaMask/Phantom）、跨链桥攻击、MEV 利用。

### 何时使用
1. 智能合约审计（部署前或事件后）
2. DeFi 协议渗透（借贷 DEX、AMM、衍生品）
3. 钱包安全审查（硬件钱包交互、密钥管理）
4. 跨链桥安全评估
5. MEV（最大可提取价值）研究

### 如何开始
1. **安装工具**：`pip install web3 slither-config` + `apt install solc` + 安装 Foundry（`curl -L https://foundry.paradigm.xyz | bash`）
2. **网络选择**：本地 Hardhat/Anvil 安全；然后测试网（Sepolia/Mumbai）；再主网分叉
3. **先做静态分析**：Solidity 跑 `slither .`；更深入用 `mythril analyze contract.sol`
4. **动态测试**：部署到本地 Anvil，重放已知利用（ERC-20 重入、闪电贷攻击）
5. **取证**：Tenderly / Etherscan 做事件后交易追踪

### 新手常见坑
- **重入不是唯一 bug**：访问控制、整数溢出（0.8.0 前）、抢跑、预言机操纵都常见
- **测试网 ≠ 主网**：流动性深度、gas 定价、MEV 行为都不同
- **Approval 骗局**：无限 ERC-20 approval 是持续风险；为客户文档化
- **跨链消息**：每个桥有自己的消息验证；不要假设共享安全模型
- **代码中 privateKey**：永远不要提交钱包私钥；用 `.env` + Foundry keystore

### 交叉引用
- `blockchain-l2-attack`（L2 专项：rollup、桥、sequencer）— 目标 L2 时切换
- `crypto-attacks`（经典密码学：哈希、签名）— 密码学原语攻击切换
- `secret-management-attack` — 密钥/助记词管理切换
- `ai-agent-supply-chain-attack` — AI × 区块链交叉（罕见）切换

---

## 能力评估详情

### D1: 5/5 | D2: 5/5

### D3: 2/5
- **Kali VM 默认 0/10 工具可用**：solc、geth、foundry、cast、forge、web3.py、slither、mythril 全缺
- **静态审查**：命令有效；`apt install solc` + `pip install web3 slither` + Foundry 安装后即可工作
- **分类分布**：0 full + 10 sandbox-only（全需测试网/docker；安装直接但未执行）
- **说明**：SKILL 可通过添加 "Setup" 章节含批量安装命令改进
- **证据**：[evidence/2026-08-09/summary.md](../evidence/2026-08-09/summary.md)

### D4: 4/5
- 15 URL（好：Solidity 文档、OpenZeppelin、Ethereum.org、Solana 等）
- **0 CVE**，尽管重大利用：补 Ronin（$625M，2022）、Wormhole（$326M，2022）、Curve（$70M，2023）、Poly Network（$611M，2021）

### D5: 1/5
- **body 中 0 个 ATT&CK T-codes** — 严重缺口
- frontmatter 标 `N/A (application-layer; maps loosely to TA0001)` 不充分
- 推荐映射：
  - T1552 Unsecured Credentials（私钥泄漏）
  - T1068 Exploitation for Privilege Escalation（合约漏洞）
  - T1570 Lateral Tool Transfer（跨链桥攻击）
  - T1027 Obfuscated Files（代理合约隐藏）
  - T1486 Data Encrypted for Impact（钱包勒索）
- 与 `blockchain-l2-attack` 在 v0.2.5 修复前同样问题；应补 `## MITRE ATT&CK Mapping` 节

### D6: 4/5
- 优点：EVM / Solana / Cosmos 分章清晰；DeFi 攻击模式解释到位
- 不足：无 MITRE ATT&CK 映射（F-002）；假设 Solidity 已熟悉

---

## 问题与优先级

| ID | 优先级 | 描述 | 推荐修复 |
|----|-------|------|---------|
| F-001 | **P1** | body 中 0 个 ATT&CK T-codes（frontmatter N/A 不充分） | 补 `## MITRE ATT&CK Mapping` 节，仿 v0.2.5 对 blockchain-l2-attack 的修复 |
| F-002 | **P1** | 0 CVE 引用，尽管 2022-2024 web3 利用累计超 $1B | 补：Ronin Network（2022）、Wormhole（2022）、Curve（2023）、Poly Network（2021）、Euler（2023） |
| F-003 | P2 | Kali 默认全缺工具；无安装脚本 | 补 `scripts/setup.sh`：`apt install -y solc && pip install web3 slither && curl -L https://foundry.paradigm.xyz \| bash` |
| F-004 | P3 | test cases 偏薄（271 行 vs 2626 行 payloads，10%） | 补 ≥10 个 test case（重入、闪电贷、预言机操纵、approval 骗局、签名重放） |

---

## 验证证据

- [evidence/2026-08-09/summary.md](../evidence/2026-08-09/summary.md)
- [evidence/2026-08-09/lint.json](../evidence/2026-08-09/lint.json)
- Kali VM：parallels@10.211.55.5（Kali 2026.1，aarch64）

## 评估签字
- 评估者：Claude（Wave 1 Batch 1，SKILL 4/5）
- 批准人：_______________ 日期：_______
