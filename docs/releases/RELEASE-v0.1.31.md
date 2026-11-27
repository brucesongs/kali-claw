# kali-claw v0.1.31 发布公告 — GitHub 趋势扩面第三波 +4（87→91）

**发布日期**：2026-06-17
**技能域数量**：87 → **91**（+4）
**主题**：同日第三发；填补身份/物理/量子/钓鱼基础设施四大覆盖盲区

---

## 驱动力：GitHub 趋势驱动扩面方法论第三波

v0.1.31 是 v0.1.29 / v0.1.30 之后的第三次同日发布，进一步验证"GitHub 开源情报 → 缺口识别 → 技能扩面"工作流的可复制性。本版本聚焦于四个长期存在的覆盖盲区：

| 盲区 | 现状 | 新技能 |
|------|------|--------|
| 云身份攻击 | 仅有 `ad-ldap-attack`（本地 AD），无云 IdP | **cloud-identity-attack** |
| 物理安全测试 | 0 个技能覆盖 | **physical-security-testing** |
| 后量子/国密 | 仅有 `crypto-attacks`（经典密码），无 PQC/SM 系列 | **quantum-crypto-attack** |
| 钓鱼基础设施 | 仅有 `email-protocol-attack`（协议层），无 AiTM/网关绕过 | **email-security-deep** |

---

## 新增技能域（+4）

### 1. cloud-identity-attack — 云身份攻击（首个 enterprise-cloud 类）

- **GitHub 数据来源**：casdoor (13.8k) + kratos (13.7k) + **ROADtools (2.6k)** + **AzureAD-Attack-Defense (2.5k)** + GlobalProtect-openconnect (2.1k) + AADInternals + MicroBurst + MFASweep + TokenTactics
- **覆盖**：Azure AD/Entra ID、Okta、Auth0、Ping、AWS IAM Identity Center、Google Workspace；OAuth/SAML/OIDC token 滥用、Conditional Access 绕过、MFA fatigue、federation 滥用、JIT access 攻击
- **战略意义**：与 `ad-ldap-attack`（本地 AD/LDAP/Kerberos）形成 **AD↔Cloud 身份攻击双技能**——这是 2026 年企业身份混合环境的真实需求
- **文件清单**：SKILL.md (469 行)、payloads.md (1,209 行)、test-cases.md (269 行, 12 TC-CI-001..012)、guides/cloud-identity-attack-playbook.md (808 行)
- **基线评分**：**83.8 / Excellent**
- **真实事件参考**：SolarWinds/SUNBURST（SAML 供应链）、LAPSUS$（MFA fatigue 攻击 Okta/Cisco/Uber）、Nobelji（AAD 滥用）

### 2. physical-security-testing — 物理安全测试（首个 physical 类）

- **GitHub 数据来源**：awesome-lockpicking (1.9k) + RedTeam-Physical-Tools (583) + ESP-RFID-Tool (572) + TeamWalrus/Walrus (488) + trustedsec/physical-docs (496) + Proxmark3 生态
- **覆盖**：锁匠（pin/tubular/wafer/dimple/bump keys）、RFID/NFC 卡克隆（HID Prox/Indala/Mifare Classic/iCLASS）、drop box 部署（LAN Turtle/Packet Squirrel/Pi Zero）、USB 武器（Rubber Ducky/Bash Bunny/P4wnP1）、隐蔽摄像头、现场作战、尾随借口准备、legal-docs 模板
- **战略意义**：填补长期存在的零物理安全覆盖；强调法律/伦理/范围控制（jurisdictional lock pick law、abort criteria、chain-of-custody）
- **文件清单**：SKILL.md (810 行)、payloads.md (1,790 行)、test-cases.md (310 行, 12 TC-PS-001..012)、guides/physical-security-testing-playbook.md (542 行)
- **基线评分**：**86.6 / Excellent**（v0.1.31 cohort 最高）

### 3. quantum-crypto-attack — 后量子与国密攻击（cryptography 类深化）

- **GitHub 数据来源**：open-quantum-safe/liboqs (2.9k) + QuipNetwork/hashsigs-solidity (11.3k) + QuipNetwork/hashsigs-rs (11.3k) + guanzhi/GmSSL (6.1k) + Peergos (2.4k) + cloudflare/circl (1.7k)
- **覆盖**：Shor/Grover 算法影响评估、NIST PQC 候选（ML-KEM/ML-DSA/SLH-DSA）、混合 TLS 分析、QKD/BB84 协议攻击（photon-number-splitting、detector blinding）、SM2/SM3/SM4/SM9 国密实现缺陷、lattice/hashing 签名侧信道、PQC 迁移风险评估
- **战略意义**：前瞻性覆盖；"store-now-decrypt-later" 威胁建模；中国国密合规攻击面
- **文件清单**：SKILL.md (372 行)、payloads.md (1,124 行)、test-cases.md (268 行, 12 TC-QC-001..012)、guides/quantum-crypto-attack-playbook.md (533 行)
- **基线评分**：**79.7 / Strong**（距 Excellent 仅 0.3 分，下版本将提升）
- **真实 CVE 参考**：ROCA (CVE-2017-15361)、Dragonblood (WPA3)、Kyber 侧信道

### 4. email-security-deep — 钓鱼基础设施与网关绕过（appsec 类深化）

- **GitHub 数据来源**：chenjj/espoofer (1.7k, SPF/DKIM/DMARC bypass) + emalderson/ThePhish (1.3k, 自动化钓鱼邮件分析) + evilginx2 + evilgophish + modlishka + gophish + King-Phisher
- **覆盖**：AiTM 反向代理（evilginx2/evilgophish/modlishka）、campaign 平台（gophish/King-Phisher）、企业邮件网关绕过（Proofpoint/Mimecast/Cisco ESA/Microsoft Defender for Office）、邮件轰炸/DoS、sender reputation 工程、HTML smuggling、点击后遥测、FIDO2 检测
- **战略意义**：与 `email-protocol-attack`（协议层伪造）形成 **协议↔应用/社会层** 互补；明确"差异化"章节避免重叠
- **文件清单**：SKILL.md (369 行)、payloads.md (930 行)、test-cases.md (281 行, 12 TC-ED-001..012)、guides/email-security-deep-playbook.md (692 行)
- **基线评分**：**81.0 / Excellent**
- **真实事件参考**：CozyCar、EvilProxy、NakedTenant AiTM 战役

---

## 4 个新技能首次评分

| 排名 | 技能域 | 评分 | 等级 |
|------|--------|------|------|
| 1 | physical-security-testing | **86.6** | 优秀 (Excellent) |
| 2 | cloud-identity-attack | **83.8** | 优秀 |
| 3 | email-security-deep | **81.0** | 优秀 |
| 4 | quantum-crypto-attack | 79.7 | 强 (Strong) ⚠️ 边缘 |

quantum-crypto-attack 距 Excellent 仅 0.3 分，将在下版本（v0.1.32）针对性提升。

---

## 质量快照

| 指标 | v0.1.30 | v0.1.31 | 变化 |
|------|---------|---------|------|
| 技能域总数 | 87 | **91** | +4 |
| 卓越 (Distinguished，92 分及以上) | 19 | **19** | 不变 |
| 优秀 (Excellent，80–91.9 分) | 67 | **70** | +3 新 |
| 强 (Strong，60–80 分) | 1 | **2** | +1（quantum-crypto-attack 79.7） |
| 平均分 | 87.73 | **87.51** | -0.22（4 个新基线分拖低） |
| 最低分 | 77.7 | **77.7** | 不变 |
| 最高分 | 93.8 | **93.8** | 不变 |

**89/91 技能域达到优秀或以上**（97.8%）。两个 Strong 技能（username-profiling 77.7、quantum-crypto-attack 79.7）均在 v0.1.32 提升计划中。

---

## 本版本工作量

| 项目 | 数量 |
|------|------|
| 新增文件 | 16（4×SKILL.md + 4×payloads.md + 4×test-cases.md + 4×guides） |
| 新增代码行 | **~10,776** |
| 新增测试用例 | **48**（12 × 4） |
| 新增工具引用 | ~52（4 技能 × 13 工具均值） |
| 首次评分技能 | 4 |
| 新晋卓越 | 0 |
| 新类别进入 | **2**（enterprise-cloud、physical） |
| Heartbeat 健康检查 | **HEARTBEAT_OK**（441 个指南，0 个问题） |

---

## 索引文件同步

| 文件 | 更新内容 |
|------|----------|
| validation/update-skill-standard.py | 注册 4 个新技能；新增 2 个类别（enterprise-cloud、physical）；MITRE_MAP 更新 3 个 |
| IDENTITY.md | 新增 4 个技能标签行 |
| TOOLS.md | 新增 4 个分类索引行；87 → 91 技能域 |
| README.md | 6 处 87 → 91；新增 4 行技能表格；新增 v0.1.31 changelog 行；刷新质量快照；版本 0.1.30 → 0.1.31 |
| CHANGELOG.md | 新增 v0.1.31 条目 |
| VERSION | 0.1.30 → 0.1.31 |

---

## 战略价值：四大覆盖盲区全部填补

### 身份层闭环

```
ad-ldap-attack (本地 AD/LDAP/Kerberos)        ← 已有
    ↕ 互补
cloud-identity-attack (Azure AD/Okta/Auth0)   ← v0.1.31 新增
```

→ 覆盖 2026 年企业混合身份环境的完整攻击面

### 物理安全从零到一

```
（此前：零物理安全技能）                       ← 真实盲区
    ↓ 新增
physical-security-testing                     ← v0.1.31 新增
```

→ 锁匠 + 卡克隆 + USB 武器 + 现场作战全栈

### 密码学普攻 + 前瞻

```
crypto-attacks (经典 RSA/AES/ECDSA)            ← 已有
    ↕ 互补
quantum-crypto-attack (PQC/国密/QKD)          ← v0.1.31 新增
```

→ 经典 + 后量子 + 国密 全维度

### 邮件安全双层

```
email-protocol-attack (SMTP/SPF/DKIM/DMARC)   ← 已有
    ↕ 互补
email-security-deep (AiTM/网关绕过/campaign)  ← v0.1.31 新增
```

→ 协议层 + 应用/社会层 互补

---

## 同日三连发里程碑

2026-06-17 单日发布 **三个版本**：

| 版本 | 新增技能 | 新增代码 | 类别 |
|------|---------|---------|------|
| v0.1.29 | 4 | ~13.6k | ai-red-team, defense, cloud-native, appsec |
| v0.1.30 | 4 | ~14.7k | ai-emerging, iot, defense, ai-meta |
| v0.1.31 | 4 | ~10.8k | enterprise-cloud, physical, cryptography, appsec |
| **合计** | **12** | **~39k** | **12 个类别** |

→ **GitHub 趋势驱动扩面工作流已成熟可复制**；3 个版本节奏稳定，平均每个版本 ~13k 行新代码、12 个新测试用例 × 12 = 144 个新测试用例。

---

## 下一步（v0.1.32 候选方向）

- **A**：底层提升 —— 将 username-profiling（77.7）和 quantum-crypto-attack（79.7）双双拉升至 85+，重夺 91/91 Excellent+
- **B**：新技能深化 —— 为 v0.1.28+v0.1.29+v0.1.30+v0.1.31 的 16 个新技能扩充指南数，目标全部进入 88+
- **C**：卓越冲刺 —— 将 deep-research（90.6）、ai-security（89.3）、av-edr-evasion（89.1）等 89-90 分段技能推升至 92+
- **D**：继续扩面 —— 5G/移动网络（GitHub 生态薄，需评估）、云身份深度、移动应用安全深度、云原生漏洞研究
- **E**：A + C 组合（专注质量，暂停扩面）

---

_本版本是 kali-claw 同日发布的第三个版本，也是 GitHub 趋势驱动扩面方法论第三次成功复制。91 个技能域覆盖 19 个 Distinguished + 70 个 Excellent + 2 个 Strong，平均 87.51。下版本重点：提升两个 Strong 至 Excellent+。_
