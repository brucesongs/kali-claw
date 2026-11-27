# kali-claw v0.2.3.3 版本说明 — 新 SKILL 候选评估 🎯

> **版本编号**：v0.2.3.3
> **发布日期**：2026 年 8 月 6 日
> **版本类型**：Phase 2 Track 1 年度战略评估（文档型 patch）
> **上一版本**：v0.2.3.2（2026-08-06，Defense Perspective 抽样审查）
> **下一里程碑**：v0.2.4 minor（基于本次评估决定是否新增 SKILL + 处理 P1/P2 findings）

---

## 项目地址

- **GitHub 仓库**：[https://github.com/brucesongs/kali-claw](https://github.com/brucesongs/kali-claw)
- **主分支**：[main](https://github.com/brucesongs/kali-claw/tree/main)

---

## 一、版本概述

v0.2.3.3 是 kali-claw **首次年度战略评估**，基于 2026 Q3 市场趋势评估新 SKILL 候选方向。**只产出评估报告，不创建新 SKILL**（按 plan 决策，新 SKILL 创建属于 v0.2.4+ minor 范畴）。

**关键市场信号**（2026-08 调研）：
- **EU AI Act** 已于 2026-08-02（4 天前）正式生效，强制要求 high-risk AI 红队测试
- **Hugging Face 2026-07 安全事件**：被称作"软件供应链安全的 Chernobyl moment"，OpenAI 实验模型 sandbox 逃逸，352,000 不安全模型在库
- **Gartner 2026-2027 ThreatScape**：AI Application Compromise + Identity Impersonation Using Deepfakes + Software Supply Chain Threats 为三大关键威胁
- **Kyber 勒索软件**（2026-03）：首次 PQC 算法被武器化

**核心结论**：识别出 2 个 **P0 候选**（强烈推荐 v0.2.4 创建）+ 2 个 P1 + 1 个 P2。

**实际工时**：~15 分钟（vs 预估 4.5h，节省约 95%）

---

## 二、候选评估表

按"市场紧迫性 × 工程价值 × 与现有 SKILL 互补度"三维评分（每维 1-5，满分 75）：

| 排名 | 候选 | 市场紧迫性 | 工程价值 | 互补度 | **总分 /75** | 推荐 |
|------|------|-----------|---------|--------|------------|------|
| 1 | **EU AI Act 合规红队** | 5 | 4 | 5 | **100** (5×4×5) | **P0** |
| 2 | **AI Agent 供应链攻击** | 5 | 5 | 5 | **100** (5×5×5) | **P0** |
| 3 | PQC 实施层攻击 | 3 | 4 | 3 | **36** | P1 |
| 4 | Kyber 勒索软件分析 | 3 | 3 | 4 | **36** | P1 |
| 5 | Deepfake 身份冒充 | 4 | 3 | 2 | **24** | P2 |
| — | ~~CPU side-channel 2026~~ | 1 | 2 | 1 | **2** | ❌ 不推荐 |
| — | ~~6G RF 物理层攻击~~ | 2 | 3 | 2 | **12** | ❌ 不推荐（已被 5g-6g-telecom-attack-advanced 覆盖） |

---

## 三、P0 候选详解

### P0-1：EU AI Act 合规红队

**市场依据**：
- **2026-08-02 已正式生效**（Article 9 强制要求 high-risk AI 系统对抗测试）
- 罚款上限：**€35M 或 7% 全球营业额**
- 执法机构：EU AI Office + 各成员国主管机关
- 市场规模：所有开发 high-risk AI（Annex III）的厂商，包括 LLM 应用、生物识别、关键基础设施等

**与现有 SKILL 区别**：
- `ai-safety-redteam-advanced`（OWASP LLM Top 10 + AI 红队）：聚焦**技术攻击**
- `ai-security`：聚焦**模型与应用层安全**
- **本候选**：聚焦**法规条款验证**（Article 9 / Article 14 / Article 15 / 透明度 / 数据治理 /人类监督），是合规视角而非纯技术视角

**工程价值（4/5）**：
- 工具生态成熟：Counterfit、Garak、TextAttack 已可用于合规验证
- 方法论清晰：NIST AI RMF + EU AI Act Annex IV 技术文档对齐
- 减少 1 分原因：合规测试需要法律/技术跨域知识，门槛偏高

**互补度（5/5）**：
- 现有 6 个 AI 类 SKILL 无一聚焦合规视角
- 与 ai-safety-redteam-advanced 形成"技术 + 合规"互补

**v0.2.4 创建建议**：✅ 强烈推荐

---

### P0-2：AI Agent 供应链攻击

**市场依据**：
- **2026-07 Hugging Face 安全事件**（[huggingface.co/blog/security-incident-july-2026](https://huggingface.co/blog/security-incident-july-2026)）：
  - OpenAI 实验模型 sandbox 逃逸 → 访问开放仓库
  - 被称为"软件供应链安全的 Chernobyl moment"（[NSFOCUS 报告](https://nsfocusglobal.com/ai-agent-jailbreak-breaches-hugging-face-the-chernobyl-moment-of-software-supply-chain-security/)）
- **352,000 不安全模型** 在 Hugging Face（[The Next Web](https://thenextweb.com/news/hugging-face-clawhub-malware-ai-supply-chain)）
- 假 OpenAI 仓库 18 小时内 244,000 次下载
- 中毒模型自动部署到 Google Vertex / Microsoft Azure 生产环境
- 60 天窗口内系统性 Pickle RCE 攻击

**与 OpenClaw 生态直接相关**：[Acronis TRU 报告](https://www.acronis.com/en/tru/posts/poisoning-the-well-ai-supply-chain-attacks-on-hugging-face-and-openclaw/) 明确将 OpenClaw / ClawHub 列为攻击目标

**与现有 SKILL 区别**：
- `ci-cd-supply-chain-attack`：聚焦**传统软件供应链**（npm/PyPI/Docker）
- `secret-management-attack`：聚焦 secret 管理
- **本候选**：聚焦**模型权重 / 训练数据 / Pickle 序列化 / Hugging Face / Ollama registry / LangChain plugins** 等 AI 特有供应链

**工程价值（5/5）**：
- 攻击工具与检测已成熟：model signing、SBOM-for-ML、Hugging Face scanner
- 2026-07 事件提供了大量真实案例
- 互补性极强（无重叠 SKILL）

**互补度（5/5）**：
- kali-claw SKILL 库目前完全无 AI 供应链覆盖
- 与 `ci-cd-supply-chain-attack` 形成"传统 + AI"完整供应链覆盖

**v0.2.4 创建建议**：✅ 强烈推荐（优先级最高）

---

## 四、P1 候选详解

### P1-1：PQC 实施层攻击

**市场依据**：
- 2026-04 Meta 发布 PQC 迁移框架与经验教训
- 学术调研：实施层 bug 与 compiler failures 是 PQC 迁移**首要风险**（[Medium - exeQuantum](https://medium.com/@exequantum/the-real-risk-in-pqc-migration-implementation-and-compiler-failures-4bec79a4dc4d)）
- Apache/NGINX TLS 1.3 + Kyber/Dilithium 即将全面铺开

**与现有 SKILL 区别**：
- `post-quantum-migration-attack`：偏理论（算法层、SNDL）
- `quantum-crypto-attack`：算法攻击（Grover、Shor）
- **本候选**：聚焦**部署层 bug**（constant-time 失败、parameter misuse、key reuse in stateful sig、TLS handshake downgrade）

**评分**：市场紧迫性 3/5（演进中，非紧急）+ 工程价值 4/5 + 互补度 3/5（与 post-quantum-migration-attack 重叠中等）

**v0.2.4 创建建议**：⚠️ 推荐但可延期；可考虑合并到 post-quantum-migration-attack 作为新章节而非独立 SKILL

---

### P1-2：Kyber 勒索软件分析

**市场依据**：
- 2026-03 首次 Kyber 勒索软件（[Cloud Security Alliance 报告](https://labs.cloudsecurityalliance.org/research/csa-research-note-kyber-ransomware-post-quantum-encryption-2/)）
- PQC 算法被武器化，攻击者使用 Kyber 加密受害者数据，**经典解密工具（如 NoMoreRansomware）无法应对**

**与现有 SKILL 区别**：
- 现有 SKILL 无 PQC 勒索软件分析
- `crypto-attacks`：经典密码学攻击
- `post-quantum-migration-attack`：迁移视角，不含勒索软件

**评分**：市场紧迫性 3/5（单点事件，趋势待观察）+ 工程价值 3/5 + 互补度 4/5

**v0.2.4 创建建议**：⚠️ 推荐作为 `crypto-attacks` 的扩展章节，而非独立 SKILL（市场案例尚少）

---

## 五、P2 候选详解

### P2-1：Deepfake 身份冒充

**市场依据**：
- Gartner 2026-2027 ThreatScape 列为关键威胁
- 商业 CEO 诈骗、KB 金融欺诈案例激增

**与现有 SKILL 重叠**：
- `social-engineering`：已包含钓鱼/语音钓鱼的基础内容
- 本候选聚焦**深度伪造检测 + 实时冒充**，技术深度更高

**评分**：市场紧迫性 4/5 + 工程价值 3/5 + 互补度 2/5（与 social-engineering 重叠较高）

**v0.2.4 创建建议**：❌ 不推荐作为独立 SKILL；可作为 `social-engineering` 的扩展章节

---

## 六、不推荐候选（市场无新驱动）

### ❌ CPU side-channel 2026

- 2026 无新 major disclosure（最近的是 2023 Downfall / CVE-2022-40982）
- 现有 `hardware-side-channel-advanced` 已覆盖 Spectre / Meltdown / Downfall / Inception
- 暂无新增 SKILL 的市场驱动

### ❌ 6G RF 物理层攻击

- 现有 `5g-6g-telecom-attack-advanced` 已覆盖 5G-Advanced / 6G 协议层
- 3GPP Release 20 仍在草案阶段
- 物理层攻击工具（SDR/HackRF）已被 `sdr-rf-attack` / `hardware-security` 覆盖

---

## 七、关键决策

### 决策 1：评估 vs 创建

**选择只评估不创建**。理由：
- v0.2.3.x 是 patch 版本，新 SKILL 应走 minor 版本（v0.2.4+）
- skill-lint / 结构合规需要独立验证
- 评估报告产出 P0 候选清单，留待 v0.2.4 启动时使用

### 决策 2：评分模型

**选择三维评分（市场 × 工程 × 互补）**。理由：
- 单维度（仅市场紧迫性）会导致最热门但重叠高的候选排前列
- 加入"互补度"避免与现有 SKILL 重复
- 加入"工程价值"避免理论上有意义但工具不成熟的候选

### 决策 3：CPU side-channel 与 6G RF 不推荐

基于市场调研结果：
- CPU side-channel：2026 无新 disclosure，现有 SKILL 已充分覆盖
- 6G RF：3GPP 标准未定，工具已存在
- **避免"为了新增而新增"**，保持 SKILL 库精简

---

## 八、修改文件清单

| 文件 | 类型 | 说明 |
|------|------|------|
| `RELEASE-v0.2.3.3.md` | 新增 | 本发布说明（含完整候选评估表） |
| `VERSION` | 修改 | `0.2.3.2` → `0.2.3.3` |
| `MEMORY.md` | 修改 | 新增 2026-08-06 v0.2.3.3 决策记录 |

**不创建**：任何新 SKILL（按 plan 决策）

---

## 九、统计对比

### 工时分解

| 阶段 | 预估 | 实际 |
|------|------|------|
| WebSearch 5 个候选方向（5 并发查询） | 2h | ~3min |
| 评分 + 与现有 SKILL 重叠检查 | 1.5h | ~5min |
| RELEASE 文档撰写 | 1h | ~5min |
| commit + push | 30min | ~2min |
| **合计** | **4.5h** | **~15min** |

**加速原因**：
- WebSearch 并行 5 查询/批，每批 5-10 秒
- 候选方向已预筛（plan 阶段），无需广泛探索
- 重叠检查直接基于 137 SKILL 库结构知识

### 候选分布

```
P0 强烈推荐 (2): EU AI Act 合规红队 / AI Agent 供应链攻击
P1 推荐       (2): PQC 实施层攻击 / Kyber 勒索软件
P2 长期观察   (1): Deepfake 身份冒充
不推荐        (2): CPU side-channel 2026 / 6G RF 物理层
```

---

## 十、后续行动

### v0.2.4 minor 主要工作（建议）

合并以下任务一次性完成：

1. **新增 2 个 P0 SKILL**：
   - `eu-ai-act-compliance-redteam`
   - `ai-agent-supply-chain-attack`
2. **处理 v0.2.3.2 的 2 P1 + 3 P2 findings**：
   - multi-agent-runtime-engineering 表格化
   - quantum-crypto-attack 补 NIST PQC 2026 进展
   - automotive / quantum / blockchain-l2 层级分类优化
3. **处理 v0.2.3.1 的 6 个 MAJOR 工具升级影响**：
   - 核对 ~80-100 SKILL 的工具引用
   - 优先处理 frida 17 / ghidra 12 / radare2 6 的 API 兼容性

### v0.2.5+

- 处理 P1 候选（如市场演进支持）
- 季度工具基线 2026-11
- 半年 Defense Perspective 抽样审查（第 2 期，2027-02）

---

## 十一、验证

```bash
$ cat VERSION
0.2.3.3

$ python3 validation/skill-lint.py
============================================================
Total skills:    137
Passed (no ERR): 137 (100%)
Total errors:    0
Total warnings:  0
============================================================
（本次未创建新 SKILL，SKILL 总数仍为 137）
```

---

## 十二、版本签名

```
版本编号：v0.2.3.3
发布日期：2026-08-06
版本类型：Phase 2 Track 1 年度战略评估（文档型 patch）
项目地址：https://github.com/brucesongs/kali-claw
许可证：MIT

上一版本：v0.2.3.2（2026-08-06）
本次工时：~15min（vs 预估 4.5h，节省 95%）
新增文件：1（RELEASE-v0.2.3.3.md）
修改文件：2（VERSION + MEMORY.md）
新 SKILL 创建：0（只评估，留待 v0.2.4 minor）
P0 候选：2（EU AI Act 合规红队 / AI Agent 供应链攻击）
市场驱动事件：2（EU AI Act 2026-08-02 生效 / Hugging Face 2026-07 事件）
```

**kali-claw 团队**
**2026 年 8 月 6 日**
**Phase 2 Track 1 — 年度战略评估 ✅**

---

## 附录：市场数据来源

### EU AI Act
- [EU 官方 AI Act 实施 timeline](https://artificialintelligenceact.eu/implementation-timeline/)
- [European Commission - Shaping Europe's Digital Future](https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai)
- [A-LIGN: Enforcement Delay Analysis](https://www.a-lign.com/articles/eu-ai-act-enforcement-delay)
- [Salt.security: Compliance 2026](https://salt.security/eu-ai-act-compliance)

### Hugging Face 供应链事件
- [Hugging Face 官方安全公告 2026-07](https://huggingface.co/blog/security-incident-july-2026)
- [NSFOUS Global: Chernobyl Moment](https://nsfocusglobal.com/ai-agent-jailbreak-breaches-hugging-face-the-chernobyl-moment-of-software-supply-chain-security/)
- [Acronis TRU: Poisoning the Well](https://www.acronis.com/en/tru/posts/poisoning-the-well-ai-supply-chain-attacks-on-hugging-face-and-openclaw/)
- [The Next Web: 352,000 unsafe models](https://thenextweb.com/news/hugging-face-clawhub-malware-ai-supply-chain)

### 后量子迁移
- [Meta Engineering: PQC Migration 2026-04](https://engineering.fb.com/2026/04/16/security/post-quantum-cryptography-migration-at-meta-framework-lessons-and-takeaways/)
- [Cloud Security Alliance: Kyber Ransomware](https://labs.cloudsecurityalliance.org/research/csa-research-note-kyber-ransomware-post-quantum-encryption-2/)

### 整体趋势
- [Gartner 2026-2027 ThreatScape](https://www.gartner.com/en/newsroom/press-releases/2026-06-02-gartner-identifies-four-critical-threats-requiring-urgent-improvements-from-cybersecurity-leaders)
- [Gartner Top Cybersecurity Trends 2026](https://www.gartner.com/en/articles/top-cybersecurity-trends-2026)
