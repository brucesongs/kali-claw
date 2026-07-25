# Phase 2 标准化进度跟踪

> **任务**：Task 1.2 Phase 2 — 95 个非高优先级 SKILL 标准化  
> **分支**：phase2/standardization  
> **启动日期**：2026-07-24  
> **预估工时**：28h（7-10 工作日）

---

## 📋 工作目标

对 95 个非高优先级 SKILL 应用统一标准：

1. ✅ YAML 前言完整（version, last_reviewed）
2. ✅ 翻译残留清零
3. ✅ `## Detection Methods` 章节存在
4. ✅ `## Defense Evasion Techniques` 章节存在
5. ✅ Defense Perspective 表格化
6. ✅ 版本统一至 `v0.2.0.2`

---

## 📊 批次计划（每批 10 个 SKILLs）

### Batch 1 — 网络与 AD 攻击域（10 个）
- [ ] 5g-telecom-attack
- [ ] ad-cs-abuse
- [ ] ad-ldap-attack
- [ ] agentic-pentest
- [ ] ai-agent-framework-attack
- [ ] ai-agent-security
- [ ] ai-fuzzing
- [ ] ai-security
- [ ] anti-forensics
- [ ] automotive-vehicle-security

### Batch 2 — 智能体与区块链（10 个）
- [ ] autonomous-loops
- [ ] av-edr-evasion
- [ ] blockchain-l2-attack
- [ ] blockchain-web3
- [ ] bluetooth-rfid-nfc
- [ ] browser-qa
- [ ] chronicle
- [ ] ci-cd-supply-chain-attack
- [ ] cloud-identity-attack
- [ ] cloud-native-vuln-research

### Batch 3 — 云与代码（10 个）
- [ ] cms-framework-attack
- [ ] codebase-onboarding
- [ ] command-injection-advanced
- [ ] concurrency-exploitation
- [ ] confidential-computing-attack
- [ ] continuous-learning
- [ ] council
- [ ] cps-attack
- [ ] crypto-attacks
- [ ] cspm-casb-attack

### Batch 4 — 数据与检测（10 个）
- [ ] darkweb-intel
- [ ] data-exfiltration-attack
- [ ] data-platform-attack
- [ ] data-scraper-agent
- [ ] database-attack
- [ ] deception-honeypot
- [ ] deep-research
- [ ] detection-engineering
- [ ] digital-forensics
- [ ] dns-attacks

### Batch 5 — Docker 与边缘（10 个）
- [ ] docker-patterns
- [ ] edge-computing-attack
- [ ] email-protocol-attack
- [ ] email-security-deep
- [ ] embedded-rtos-security
- [ ] engagement-manager
- [ ] exa-search
- [ ] file-inclusion
- [ ] firmware-reverse
- [ ] game-anticheat-bypass

### Batch 6 — GitOps 与硬件（10 个）
- [ ] gitops-security
- [ ] hardware-security
- [ ] hf-vhf-radio-attack
- [ ] hsm-attack
- [ ] hypervisor-introspection
- [ ] ics-fieldbus-attack
- [ ] insecure-design
- [ ] iot-pentest
- [ ] knowledge-ops
- [ ] kubernetes-attack

### Batch 7 — LLM 与移动（10 个）
- [ ] llm-red-team
- [ ] logging-monitoring
- [ ] macos-security
- [ ] mainframe-security
- [ ] malware-analysis-advanced
- [ ] mcp-server-patterns
- [ ] mobile-app-instrumentation
- [ ] mobile-security
- [ ] multi-agent-collaboration
- [ ] multi-agent-runtime-engineering

### Batch 8 — 网络与后量子（10 个）
- [ ] network-sniffing-mitm
- [ ] network-tunneling-proxy
- [ ] open-banking-attack
- [ ] pam-privilege-attack
- [ ] patch-to-poc-pipeline
- [ ] payload-generation
- [ ] payment-security
- [ ] pentest-reporting
- [ ] physical-security-testing
- [ ] post-quantum-migration-attack

### Batch 9 — 协议与量子（10 个）
- [ ] protocol-state-exploitation
- [ ] quantum-crypto-attack
- [ ] recon-osint
- [ ] red-team-infrastructure
- [ ] repo-scan
- [ ] reverse-engineering-advanced
- [ ] safety-guard
- [ ] sase-sse-attack
- [ ] satellite-leo-security
- [ ] scada-ics-security

### Batch 10 — 剩余（5 个 + 缺 Defense 的 17 个补齐）
- [ ] sdr-rf-attack
- [ ] search-first
- [ ] secret-management-attack
- [ ] security-bounty-hunter
- [ ] security-misconfiguration
- [ ] 17 个缺 Defense Perspective 的非核心 SKILLs（详见 SKILL_REMEDIATION_LIST.json）

---

## 📈 进度统计

| 批次 | 完成 / 总数 | 状态 |
|------|------------|------|
| Batch 1 | 0/10 | ⬜ 待启动 |
| Batch 2 | 0/10 | ⬜ |
| Batch 3 | 0/10 | ⬜ |
| Batch 4 | 0/10 | ⬜ |
| Batch 5 | 0/10 | ⬜ |
| Batch 6 | 0/10 | ⬜ |
| Batch 7 | 0/10 | ⬜ |
| Batch 8 | 0/10 | ⬜ |
| Batch 9 | 0/10 | ⬜ |
| Batch 10 | 0/22 | ⬜ |
| **总计** | **0/112** | **0%** |

---

## 🔧 标准化 SOP

### 单 SKILL 工作流（约 15-20 分钟）

```bash
1. 扫描状态 (2 min)
   python3 -c "import re; c=open('skills/<skill>/SKILL.md').read(); print('residue:', len(re.findall(r'[a-z][一-鿿]|[一-鿿][a-z]', c)))"
   grep -c "^## Detection Methods" skills/<skill>/SKILL.md
   grep -c "^## Defense Evasion Techniques" skills/<skill>/SKILL.md

2. 应用修复 (10-15 min)
   - 修复翻译残留
   - 添加 Detection Methods (3-5 类)
   - 添加 Defense Evasion Techniques (3-5 类)
   - 更新 version 到 0.2.0.2
   - 添加 last_reviewed 元数据

3. 验证 (1 min)
   python3 validation/update-skill-standard.py --skill <name>
```

### 批量提交工作流

```bash
# 完成一批 10 个 SKILLs 后：
git add skills/<batch-skills>/
git commit -m "refactor: Phase 2 batch N - standardize 10 SKILLs

- Add Detection Methods + Defense Evasion Techniques sections
- Fix translation residue
- Bump version to v0.2.0.2
- Add last_reviewed metadata

Batch N: <skill-list>"
```

### Push 工作流

```bash
# 直接 push（不再需要轻量分支，packfile 应该很小）
git push origin phase2/standardization

# 每周或完成所有 batches 后创建 PR 合并到 main
gh pr create --title "Phase 2: standardize 95 SKILLs" \
  --base main --head phase2/standardization
```

---

## 📝 备注

- 此文件用于跟踪 Phase 2 进度，每次完成一批后更新复选框
- 完成全部 10 个批次后，此文件可保留作为 Phase 2 完成记录
- 如某 SKILL 已通过 Phase 1 处理（不太可能），跳过即可
