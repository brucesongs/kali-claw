# blockchain-web3 — Usage Instructions & Capability Assessment

> **Assessment Date**: 2026-08-09 | **Reviewer**: Claude (automated + human review) | **Version**: v0.2.0.2
> **Overall Score**: **70/100 (Good)** | **Findings**: P0:0 P1:2 P2:1 P3:1
> **Wave 1 Batch 1** (6th SKILL assessed)

## Quick Assessment Dashboard

| Dimension | Score (1-5) | Rationale |
|-----------|-------------|-----------|
| 1. Compliance | **5** | 0/0/0 |
| 2. Content Completeness | **5** | payloads 2626 + test-cases 271 + 5 guides; 11 H2 + 25 H3 |
| 3. Command Syntax | **2** | 0/10 tools available on VM (Ethereum tooling entirely missing); static review shows commands valid |
| 4. References | **4** | 15 URLs (good); 0 CVEs (could add major smart contract exploits) |
| 5. MITRE/OWASP Alignment | **1** | **0 ATT&CK T-codes in body**; frontmatter marked N/A — major gap |
| 6. Usability | **4** | Strong smart contract / DeFi / wallet coverage; EVM/Solana/Cosmos all addressed |
| **Weighted Total** | **70/100** | **Good** — D3+D5 bring score down; OWASP Top 10 / SAFECode not mapped |

## Usage Instructions

### What this SKILL does
Blockchain/web3 security testing across EVM (Ethereum/BSC/Polygon/Arbitrum), Solana, Cosmos, and other chains. Covers: smart contract exploitation (reentrancy/integer overflow/access control), DeFi attacks (flash loans/oracle manipulation), wallet compromise (MetaMask/Phantom), bridge attacks, MEV exploitation.

### When to use it
1. Smart contract audit (pre-deployment or post-incident)
2. DeFi protocol pentest (lending DEX, AMM, derivative)
3. Wallet security review (hardware wallet interaction, key management)
4. Cross-chain bridge security assessment
5. MEV (Maximal Extractable Value) research

### How to start
1. **Install tooling**: `pip install web3 slither-config` + `apt install solc` + install Foundry (`curl -L https://foundry.paradigm.xyz | bash`)
2. **Network selection**: local Hardhat/Anvil for safety, then testnet (Sepolia/Mumbai), then mainnet fork
3. **Static analysis first**: `slither .` for Solidity; `mythril analyze contract.sol` for deeper
4. **Dynamic testing**: deploy to local Anvil, replay known exploits (ERC-20 reentrancy, flash loan attacks)
5. **Forensics**: Tenderly / Etherscan for post-incident tx trace

### Common pitfalls
- **Reentrancy is not the only bug**: access control, integer overflow (pre-0.8.0), front-running, oracle manipulation all common
- **Testnet ≠ mainnet**: liquidity depth, gas pricing, MEV behavior all differ
- **Approval scams**: unlimited ERC-20 approvals are persistent risk; document for clients
- **Cross-chain messages**: each bridge has own message verification; don't assume shared security model
- ** privateKey in code**: NEVER commit wallet private keys; use `.env` + Foundry keystore

### Cross-references
- `blockchain-l2-attack` (L2-specific: rollups, bridges, sequencers) — switch when targeting L2
- `crypto-attacks` (classical crypto: hash, signature) — switch for cryptographic primitive attacks
- `secret-management-attack` — switch for key/seed phrase management
- `ai-agent-supply-chain-attack` — switch for AI × blockchain intersection (rare)

## Capability Assessment Detail

### D1: 5/5 | D2: 5/5

### D3: 2/5
- **0/10 tools available on Kali VM default**: solc, geth, foundry, cast, forge, web3.py, slither, mythril all missing
- **Static review**: commands valid; would work after `apt install solc` + `pip install web3 slither` + Foundry install
- **Class distribution**: 0 full + 10 sandbox-only (all need testnet/docker; install is straightforward but not done)
- **Note**: SKILL could improve by adding a "Setup" section with batch install commands
- **Evidence**: [evidence/2026-08-09/summary.md](../evidence/2026-08-09/summary.md)

### D4: 4/5
- 15 URLs (good: Solidity docs, OpenZeppelin, Ethereum.org, Solana, etc.)
- **0 CVEs** despite major exploits: add Ronin ($625M, 2022), Wormhole ($326M, 2022), Curve ($70M, 2023), Poly Network ($611M, 2021)

### D5: 1/5
- **0 ATT&CK T-codes in body** — major gap
- Frontmatter marked `N/A (application-layer; maps loosely to TA0001)` is inadequate
- Recommended mappings:
  - T1552 Unsecured Credentials (private key leakage)
  - T1068 Exploitation for Privilege Escalation (contract vulnerability)
  - T1570 Lateral Tool Transfer (cross-chain bridge attacks)
  - T1027 Obfuscated Files (proxy contract hiding)
  - T1486 Data Encrypted for Impact (ransomware to wallet)
- Same issue as `blockchain-l2-attack` pre-v0.2.5 fix; should add `## MITRE ATT&CK Mapping` section

### D6: 4/5
- Strengths: clear separation EVM / Solana / Cosmos; DeFi attack patterns well-explained
- Weaknesses: no MITRE ATT&CK mapping (F-002); assumes Solidity familiarity

## Findings & Priorities

| ID | Priority | Description | Recommended Fix |
|----|----------|-------------|-----------------|
| F-001 | **P1** | 0 ATT&CK T-codes in body (frontmatter N/A is insufficient) | Add `## MITRE ATT&CK Mapping` section mirroring the v0.2.5 fix applied to blockchain-l2-attack |
| F-002 | **P1** | 0 CVE references despite $1B+ in 2022-2024 web3 exploits | Add: Ronin Network (2022), Wormhole (2022), Curve (2023), Poly Network (2021), Euler (2023) |
| F-003 | P2 | All tools missing in Kali default; no install script | Add `scripts/setup.sh` with: `apt install -y solc && pip install web3 slither && curl -L https://foundry.paradigm.xyz \| bash` |
| F-004 | P3 | Test cases thin (271 lines vs 2626 payload lines, 10%) | Add ≥10 test cases (reentrancy, flash loan, oracle manipulation, approval scam, signature replay) |

## Validation Evidence

- [evidence/2026-08-09/summary.md](../evidence/2026-08-09/summary.md)
- [evidence/2026-08-09/lint.json](../evidence/2026-08-09/lint.json)
- Kali VM: parallels@10.211.55.5 (Kali 2026.1, aarch64)

## Reviewer Sign-off
- Reviewer: Claude (Wave 1 Batch 1, SKILL 4/5)
- Approved by: _______________ Date: _______
