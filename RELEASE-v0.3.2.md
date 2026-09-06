# kali-claw v0.3.2 版本说明 — 0-CVE 批量清偿 📦

> **版本编号**：v0.3.2（patch release）
> **发布日期**：2026 年 9 月 7 日
> **版本类型**：P3 backlog 批量清偿（0-CVE 类）
> **上一版本**：v0.3.1（2026-09-05，Poor 技能清偿）
> **下一里程碑**：第 4 次月度审查（2026-10-05，含 pqi 稳定性复查）；TC 薄类批次（v0.3.3 候选）

---

## 一、版本概述

v0.3.2 执行 v0.3.1 路线图的 P1 任务：0-CVE 类 P3 一次性清偿。范围按用户确认为**现场扫描口径 62 个**（超出路线图估计的 44 个，多出的 ~18 个是 Wave 1-3 时期技能，当时 finding 体系无 0-CVE 维度）。

**结果**：47 个技能补入 **208 个 NVD 核验 CVE**，14 个 meta/活动类技能策略关闭（+1 pqi 既有的策略保留）；61 个技能重评；**仓库均分 74.4 → 81.1**，最低分 62，无 Poor；lint 保持 0/0/139。

---

## 二、执行方法

1. **现场扫描**锁定 62 个 0-CVE 技能（`pqc-implementation-attack` 排除——已策略保留）
2. **逐技能定制关键词**，NVD API 节流批量检索（≥6.5s 间隔、429 退避、断点续跑）
3. **人工策展**：逐条审读 NVD 返回描述，剔除关键词噪声误匹配（如 chronicle 命中内核 changelog 文本、tool-mastery 命中描述含 "nmap" 的无关 CVE）；3 个技能换词重搜（ad-ldap→domain controller、command-injection→remote command execution、supply-chain→npm）
4. **核验纪律**：208 个入库 CVE 逐个有 NVD 原始返回作证据；策展中另剔除若干误匹配候选

---

## 三、命中明细（47 技能 / 208 CVE，节选代表性集合）

| 集合类型 | 技能 → CVE 集 |
|---------|--------------|
| 工具自反 | binary-reverse（Ghidra 6 个）、detection-engineering（Splunk）、network-pentest（Metasploit/pymetasploit3）、password-attack（hashcat）、network-sniffing-mitm（Wireshark dissectors）、tool-mastery（nmap/nmap4j）|
| 平台纵深 | identity-provider-attack（Keycloak 6 个）、secret-management-attack（HashiCorp Vault 6 个）、digital-forensics（Cellebrite UFED）、network-tunneling-proxy（OpenVPN）、cloud-security（Docker/container）、edge-computing-attack/security（KubeEdge，分集去重）|
| 漏洞类锚点 | web-xxe（Apache Solr/Sling/JBoss）、web-ssrf（NetScaler/Adminer）、web-auth-bypass / web-access-control（认证绕过经典集）、file-inclusion（路径穿越）、command-injection（CGI 时代经典：phf/FormMail/aglimpse）、username-profiling（用户枚举集）|
| 新兴域 | llm-red-team / ai-safety / ai-security / agentic-pentest（LangChain/llama_index/vLLM/agent 框架，三技能去重分集）、mcp-server-patterns（真实 MCP 客户端/宿主 CVE）、pentest-reporting（PwnDoc/Allure——报告工具链）|
| 垂直域 | scada-ics（含 CVE-2010-2568 Stuxnet 投递向量）、satellite-leo（Cobham/Iridium 终端固件）、sdr-rf（goTenna RF 注入）、mobile-security（Stagefright 全集）、5g-telecom（华为电信设备 + M3UA dissector）、steganography（Aperi'Solve/SecureKit）|

## 四、策略关闭（14 个）

anti-forensics、autonomous-loops、chronicle、codebase-onboarding、continuous-learning、data-loss-prevention-bypass、engagement-manager、eu-ai-act-compliance-redteam、hf-vhf-radio-attack、physical-security-testing、safety-guard、social-engineering、social-intelligence、threat-hunting

以上技能在评估文档中将 0-CVE finding 标注 **"closed by policy — no applicable CVE class for this meta/activity domain"**（沿用 pqi 先例）。其中 6 个 `defense_triple_required: false` 豁免技能的 ATT&CK 行同样按策略关闭。

全仓 0-CVE 技能现存 15 个 = 14 策略关闭 + 1 pqi 策略保留，全部有文档标注。

## 五、批量重评（61 个技能）

- 35 个评分上升（v0.2.7 的 ATT&CK/URL 修复首次入账 + 本次 CVE）：web-xxe 77→86、network-pentest 74→86、binary-reverse 65→80、tool-mastery 68→83、recon-osint 71→83、steganography 71→83 等
- **仓库均分 81.1，最低 62，无 Poor**；评估闭环维持 139/139
- Wave 1-3 时期旧评估文档统一为现行标准格式（旧 evidence 全部保留）

## 六、验证

| 检查 | 结果 |
|------|------|
| skill-lint | 139/139, 0/0（无回归）|
| validate-payloads / validate-testcases | 0 errors |
| CVE 核验 | 208/208 有 NVD 原始返回证据；策展剔除误匹配若干（核验门持续生效）|
| 0-CVE 存活 | 15 个（14 策略 + 1 pqi），全部文档标注 |
| evidence/2026-09-07/ | 61 个技能，lint.json 自单次全量运行切片 |

Commits：09a0953（CVE 批量）、efa9033（策略关闭 + 重评）、本提交（release）。

## 七、后续规划

| 优先级 | 任务 | 预估 | 触发条件 |
|-------|------|------|---------|
| P1 | TC 薄类 P3 批次（~35 个技能）| 按批 | v0.3.3 |
| P2 | 第 4 次月度审查 + pqi 出厂 3 周稳定性复查 | ≤2h | 2026-10-05 |
| Q4 | 季度工具基线 2026-11 | ~4h | 2026-11 |

## 八、版本签名

```
版本编号：v0.3.2
发布日期：2026-09-07
版本类型：0-CVE P3 批量清偿
上一版本：v0.3.1
skill-lint：0/0/139（保持）
新 SKILL：0（总数 139 不变）
CVE 新增：208（47 技能，全部 NVD 核验）
策略关闭：14（meta/活动域）+ pqi 既有 1
重评：61 技能；仓库均分 74.4 → 81.1
```

**kali-claw 团队**
**2026 年 9 月 7 日**
