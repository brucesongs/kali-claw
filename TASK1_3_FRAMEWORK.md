# Task 1.3 新 SKILL 扩展框架

> **创建日期**：2026-07-18 (Saturday)  
> **启动日期**：2026-07-25 (Week 2 后半, 与 Task 1.2 Phase 2 并行)  
> **目标**：新增 7 个 SKILL，总数从 130 → 137+

---

## 📊 当前状态分析

### 已有 130 SKILLs 覆盖范围

**强项 (深度好)**：
- Web 攻击 (7 子域: XSS/SQLi/SSRF/Auth/XXE/File Inclusion/Deserialization)
- Network Pentest, Post-Exploitation, Privilege Escalation
- Cloud Security, Container Security
- Binary RE, Exploit Development

**中等 (有覆盖但可深化)**：
- Mobile Security, IoT Pentest
- OSINT, Threat Intel
- Social Engineering

**弱项/缺失** (Task 1.3 重点扩展)：
- AI Safety/LLM Red Team (现有 1 个，需补强)
- Data Loss Prevention (DLP) 攻防
- Identity-Provider attack (Okta/Auth0/Keycloak)
- Edge computing security
- 5G/Telecom attack (现有，但需扩展)
- Hardware Security / Side-channel
- Quantum-resilient cryptography

---

## 🎯 7 个新 SKILL 候选清单

### Priority A (必做, 4 个) - 高战略价值

#### 1. `ai-safety-redteam-advanced`

- **理由**：现有 ai-security / llm-red-team 较基础，需深化
- **领域**：AI/LLM Red Teaming
- **覆盖**：
  - OWASP LLM Top 10 (2025)
  - Prompt Injection (direct/indirect)
  - jailbreak techniques (DAN, multi-turn)
  - Data poisoning detection
  - Model inversion attacks
  - Adversarial examples (evasion)
- **预估工时**：8h
- **依赖工具**：garak, promptfoo, PyRIT

#### 2. `identity-provider-attack`

- **理由**：现代企业依赖 IdP (Okta/Auth0/Keycloak/Azure AD)，攻击面大
- **领域**：Identity & Access Management attacks
- **覆盖**：
  - OAuth/OIDC flow attacks
  - SAML assertion injection
  - JWT algorithm confusion (RS256 → HS256)
  - Token replay & theft
  - Service principal abuse (Azure)
  - MFA fatigue/bypass
- **预估工时**：8h
- **依赖工具**：tokenhero, jwt_tool, AADInternals, MFASweep

#### 3. `data-loss-prevention-bypass`

- **理由**：现有 data-exfiltration-attack 偏攻击视角，需补充 DLP 绕过专项
- **领域**：DLP evasion
- **覆盖**：
  - Steganography-based exfil (图像/音频/视频 LSB)
  - DNS tunneling (dnscat2, iodine)
  - ICMP tunneling
  - Cloud sync abuse (Dropbox/Google Drive)
  - WebSocket/HTTP3 exfil
  - AI-augmented exfil (semantic chunking)
- **预估工时**：6h
- **依赖工具**：dnscat2, iodine, steghide, cococrack

#### 4. `edge-computing-security`

- **理由**：CDN/WAF/Edge Functions 攻击面快速增长
- **领域**：Edge infrastructure attacks
- **覆盖**：
  - Cloudflare Workers abuse
  - AWS Lambda@Edge attacks
  - CDN cache poisoning
  - Origin IP discovery
  - WAF bypass techniques
  - Edge function injection
- **预估工时**：6h
- **依赖工具**：Cloudflare wrangler, serverless-cli, waf-bypass

### Priority B (推荐, 3 个) - 市场差异化

#### 5. `quantum-cryptography-transition`

- **理由**：PQC (Post-Quantum Cryptography) 迁移期，攻击者已开始 "harvest now, decrypt later"
- **领域**：Quantum-resilient crypto attacks
- **覆盖**：
  - NIST PQC standards (ML-KEM, ML-DSA, SLH-DSA)
  - Hybrid TLS weaknesses
  - Quantum key distribution attacks
  - HSM-side channel for PQC
  - Migration vulnerability window
- **预估工时**：6h
- **依赖工具**：OQS (Open Quantum Safe), liboqs

#### 6. `hardware-side-channel-advanced`

- **理由**：现有 hardware-security 偏基础，需深化 SCA
- **领域**：Side-channel attacks
- **覆盖**：
  - Power analysis (SPA/DPA)
  - Electromagnetic emanation
  - Timing attacks
  - Cache-timing attacks (Spectre/Meltdown variants)
  - Glitching attacks (voltage/clock)
  - Optical fault injection
- **预估工时**：6h
- **依赖工具**：ChipWhisperer, glitchcat, sgax

#### 7. `5g-6g-telecom-attack-advanced`

- **理由**：5G/6G 是 2026+ 关键基础设施攻击面
- **领域**：Mobile network attacks
- **覆盖**：
  - 5G Core (SBA) attacks
  - IMSI catcher evolution (5G Stingray)
  - SIP/Diameter protocol attacks
  - Open RAN vulnerabilities
  - Network slicing abuse
  - 6G early research vectors
- **预估工时**：6h
- **依赖工具**：srsRAN, Open5GS, sipp

---

## 📋 SKILL 创建 SOP

### Step 1: 规划与文献调研 (1h)

```bash
# 1. 创建工作目录
mkdir -p skills/<skill-name>/{guides}

# 2. 收集参考资料
# - OWASP / MITRE ATT&CK 相关条目
# - 近 12 个月 CVE 相关
# - 学术论文 (usenix-security, IEEE S&P)
# - GitHub trending 相关工具
```

### Step 2: SKILL.md 主文件 (1.5h)

按 Anthropic Agent Skills Open Standard 模板：

```markdown
---
name: <skill-name>
description: "<2-3 sentence description>"
origin: openclaw
version: "0.2.0.2"
compatibility:
  - openclaw
  - claude-code
  - cursor
  - windsurf
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
  - WebSearch
  - WebFetch
metadata:
  domain: <domain>
  tool_count: <N>
  guide_count: <N>
  mitre: "<T-XXXX>"
  created: "2026-07-25"
---

## Summary
<2-3 sentence overview>

## Description
<200+ word detailed description>

## Use Cases
<3-5 scenarios>

## Core Tools
| Tool | Version | Purpose |
|------|---------|---------|
| ... | ... | ... |

## Methodology
1. Reconnaissance
2. Vulnerability identification
3. Exploitation
4. Post-exploitation
5. Reporting

## Practical Steps
### Step 1: ...
### Step 2: ...

### Defense Perspective
| Layer | Measures | Key Points |
|-------|----------|------------|

## Detection Methods
### <indicators>

## Defense Evasion Techniques
### <techniques>

## Tool Comparison Matrix
| Tool | Capability | Stealth | Difficulty |
|------|------------|---------|-----------|

## Learning Resources
- [External link]

## Hacker Laws
| Law | Application |
|-----|-------------|
```

### Step 3: payloads.md (2h)

- 目标：60+ sections, 1000+ lines
- 分类组织 (Basic/Intermediate/Advanced/Specialized)
- 每个 payload 有：
  - Title
  - Target (technology/version)
  - Command/code
  - Expected output
  - Cleanup (if needed)

### Step 4: test-cases.md (1h)

- 目标：8+ test cases in AAA format
- 涵盖：Basic, Bypass, Edge case, Defense validation

### Step 5: guides/ (1.5h)

- 至少 3 deep-dive guides
- 每个 guide 200-500 lines
- 主题：Complete guide, Defense guide, Tool comparison

### Step 6: 验证 (0.5h)

```bash
python3 validation/update-skill-standard.py --skill <name>
```

### Step 7: Commit (0.5h)

```bash
git add skills/<name>/
git commit -m "feat: add <name> SKILL for <domain>

- 7-section SKILL.md per Anthropic Agent Skills standard
- 60+ payloads covering <N> attack techniques
- 8 test cases in AAA format
- 3 deep-dive guides
- Defense perspective with 5+ layers

Implements: Task 1.3 Wave 12 expansion
Addresses: <OWASP/MITRE reference>"
```

---

## 📅 7 个新 SKILL 执行计划

### Week 2 (2026-07-25 ~ 07-31): 创建 4 个 Priority A

| 日期 | SKILL | 预估工时 | 状态 |
|------|-------|---------|------|
| 07-25 (Fri) | ai-safety-redteam-advanced | 8h | ⬜ |
| 07-26 (Sat) | (Weekend buffer) | - | - |
| 07-27 (Sun) | (Weekend buffer) | - | - |
| 07-28 (Mon) | identity-provider-attack | 8h | ⬜ |
| 07-29 (Tue) | data-loss-prevention-bypass | 6h | ⬜ |
| 07-30 (Wed) | edge-computing-security | 6h | ⬜ |

### Week 3 (2026-08-01 ~ 08-04): 创建 3 个 Priority B

| 日期 | SKILL | 预估工时 | 状态 |
|------|-------|---------|------|
| 08-01 (Thu) | quantum-cryptography-transition | 6h | ⬜ |
| 08-02 (Fri) | hardware-side-channel-advanced | 6h | ⬜ |
| 08-03-04 | 5g-6g-telecom-attack-advanced | 6h | ⬜ |

### Week 3 末 (08-05+): 集成与文档

- [ ] 更新 IDENTITY.md skill 标签
- [ ] 更新 TOOLS.md 工具进度
- [ ] 生成 SKILL_INDEX.json (Task 1.4)
- [ ] 撰写 CHANGELOG 条目

---

## 🔗 与 Task 1.2 协调

### 并行执行策略

```
Week 2 (7.25 - 8.01):
┌─────────────────────────────────────────────┐
│ Task 1.2 Phase 2 (115 standard SKILLs)     │
│  - 17 missing Defense Perspective           │
│  - 98 standard polish                       │
│  - Daily: 4-6 SKILLs polish                │
└─────────────────────────────────────────────┘
                  ↓ (parallel)
┌─────────────────────────────────────────────┐
│ Task 1.3 (7 new SKILLs)                     │
│  - Priority A: 4 SKILLs (28h)               │
│  - Priority B: 3 SKILLs (18h)               │
│  - Daily: 1 SKILL creation                  │
└─────────────────────────────────────────────┘
```

### 资源分配

- **上午精力峰值 (09:00-12:00)**: Task 1.3 新 SKILL 创建 (创意工作)
- **下午 (14:00-17:00)**: Task 1.2 Phase 2 polish (执行工作)

---

## 🎯 成功标志

### Task 1.3 完成标准

- [ ] 7 个新 SKILL 全部创建
- [ ] 每个 SKILL 通过 update-skill-standard.py 验证
- [ ] 平均完成度 ≥ 95% (新 SKILL 起点)
- [ ] 每个 SKILL 至少 60 payloads, 8 tests, 3 guides
- [ ] 总数 SKILL: 130 → 137+ (目标 150+, 还需 Task 1.3+ 后续补 13+)
- [ ] 提交 7 个 feat commits

### 战略价值

- **填补 4 个战略空白**：AI Red Team, IdP, DLP, Edge
- **市场差异化**：Quantum, SCA, 5G/6G (前瞻性)
- **Skill 库现代化**：覆盖 2026 主流攻击面

---

## ⚠️ 风险与应对

| 风险 | 应对 |
|------|------|
| 单 SKILL 工时超 10h | 缩减 guides 数量至 2 个 |
| 工具版本查询困难 | 引用本基线 KALI_TOOLS_BASELINE_2026_07.md |
| 内容深度不够 | 复用已有 SKILLs 相关章节 |
| 与现有 SKILL 重叠 | 先扫现有内容，差异化定位 |

---

## 📚 相关文档

- [HIGH_PRIORITY_WORKPLAN.md](./HIGH_PRIORITY_WORKPLAN.md)
- [TASK1_2_WORKFLOW.md](./TASK1_2_WORKFLOW.md)
- [KALI_TOOLS_BASELINE_2026_07.md](./KALI_TOOLS_BASELINE_2026_07.md)
- [PHASE1_EXECUTION.md](./PHASE1_EXECUTION.md)

---

**最后更新**：2026-07-18  
**执行周期**：2026-07-25 ~ 2026-08-04 (Week 2-3)  
**目标新增**：7 SKILLs
