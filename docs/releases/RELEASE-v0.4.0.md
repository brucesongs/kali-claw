# kali-claw v0.4.0 版本说明 — 域归并：83 → 22 🗂️

> **版本编号**：v0.4.0（minor release）
> **发布日期**：2026 年 11 月 19 日
> **版本类型**：结构性域分类归并（taxonomy v2）+ 文档生成体系扩展
> **上一版本**：v0.3.9.1（2026-11-16，F-4 清偿 Usability 满分）
> **下一里程碑**：季度工具基线 2026-12 → 第 5 次月度审查 2026-12-07

---

## 一、版本概述

将 139 个技能的域分类从 **83 个碎片域**（47 个单技能域）归并为 **22 个主题域**（最小域 3 技能）。
`gen-skill-handbook.py` 扩展为三产物生成器（INDEX / HANDBOOK / DOMAIN_MATRIX），陈旧的
DOMAIN_MATRIX 与 QUICK_REFERENCE 处置完毕。SKILL 内容零改动，纯元数据结构变更。

## 二、新分类法（22 域 / 139 技能）

| 域 | 技能数 | 覆盖 |
|----|--------|------|
| web-appsec | 13 | XSS/SQLi/SSRF/XXE/反序列化/注入/文件包含/CMS/访问控制/认证/设计缺陷/配置错误 |
| assessment-workflow | 11 | 漏扫/众测/代码审计/repo 扫描/engagement/报告/工具精通/搜索/终端/Docker/Browser |
| cloud-container | 11 | AWS-Azure-GCP/云身份/云原生/云安全态势/SASE-SSE/机密计算/边缘×2/容器/K8s/GitOps |
| agent-meta | 8 | 自主循环/议会/安全护栏/验证环/多 agent 协作×2/MCP/持续学习 |
| ai-security | 8 | LLM 红队/agent 安全×2/agentic pentest/AI fuzzing/AI 安全/合规红队 |
| hardware-ot | 8 | 硬件/侧信道/RTOS/固件/IoT/CPS/SCADA/现场总线 |
| network-attack | 8 | 内网渗透/嗅探 MITM/隧道代理/DNS/邮件协议/VoIP/协议状态机/VPN |
| identity-attack | 7 | AD LDAP/AD CS/PAM/IdP/密钥管理/密码/HSM |
| research-meta | 7 | chronicle/知识运维/写作/代码入库/深研/Exa/爬虫 |
| wireless-telecom | 7 | WiFi/蓝牙 RFID NFC/SDR/HF-VHF/卫星/5G/5G-6G |
| exploit-development | 6 | 漏洞开发/二进制×2/patch-to-PoC/并发/恶意软件分析 |
| osint-recon | 6 | 侦察/OSINT/用户画像/社媒情报/暗网/威胁情报平台 |
| post-exploit-evasion | 5 | 后渗透/提权/AV-EDR 规避/载荷生成/游戏反作弊 |
| mobility-vehicle ×7 域（4 技能）| 4×7=28 | mobility-vehicle、platform-attack、fintech-blockchain、crypto-attack、data-attack、red-team-ops、defense-detection |
| supply-chain-attack / forensics | 3+3 | 供应链×3（含 AI agent 供应链）/ 取证-反取证-隐写 |

**归并原则**：按攻击面/目标类型聚类；每域 ≥3 技能；攻击域 `-attack` 后缀，meta 域 `-meta` 后缀。

## 三、文档生成体系扩展

| 产物 | 前 | 后 |
|------|----|----|
| `docs/SKILL_HANDBOOK.md` | 83 域分组（47 个单技能标题）| **22 域分组**（1,745 行，结构清晰）|
| `docs/SKILL_INDEX.json` | 83 domains | **22 domains** |
| `docs/DOMAIN_MATRIX.md` | v0.2.0.8 手写快照（81 域/137 技能，陈旧 4 个月）| **自动生成**（22 域 + Defense Triple 完整率 + 豁免数 + 清单）|
| `docs/QUICK_REFERENCE.md` | 陈旧手写（137 技能）| 加 SUPERSEDED 横幅 → 指向 HANDBOOK/MATRIX |

`gen-skill-handbook.py --check` 现覆盖三产物（新增 `--matrix-only`）。

## 四、顺带处置

- 5 个技能 last_reviewed 跨过 90 天线（v0.3.9 bump 到 11-16，本次 3 天后 92d）→ truth-sync 至 2026-11-19
- 迁移脚本一次性应用（139 技能显式映射，断言全覆盖；131 个 SKILL.md 更新 domain 字段，8 个原本同名）

## 五、验证

| 检查 | 结果 |
|------|------|
| 覆盖断言 | 139/139 技能显式映射，无遗漏/多余 ✅ |
| skill-lint | 139/139, 0/0 ✅ |
| check-skill-usability | **exit 0**；Usability 139A + Reliability 139A 保持 ✅ |
| gen-skill-handbook --check | 三产物全部 fresh ✅ |
| 评分影响 | 无（domain 非评分维度；均分 91.1 / 最低 72.3 不变）✅ |

## 六、版本签名

```
版本编号：v0.4.0
发布日期：2026-11-19
版本类型：域归并 taxonomy v2（minor，纯元数据）
上一版本：v0.3.9.1
域数：83 → 22（消除 47 个单技能域，最小域 3 技能）
SKILL 内容改动：0（131 个 frontmatter domain 字段 + 5 个 last_reviewed）
新产物：DOMAIN_MATRIX.md 自动生成（gen-skill-handbook 三产物体系）
质量保持：lint 0/0/139；Usability+Reliability 双 139A；验证器 exit 0
```

**kali-claw 团队**
**2026 年 11 月 19 日**
