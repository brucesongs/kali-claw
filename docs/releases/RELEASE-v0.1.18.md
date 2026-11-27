# kali-claw v0.1.18 发布公告 — 10 个新技能域，72 个新工具引用

**发布日期**：2026-06-04
**技能域数量**：51 → 61（+10）
**主题**：10 个新安全技能域研发，基于 Kali 518 工具的实质性能力扩展

---

## 更新概览

v0.1.17 完成了底层补强和自动化基础设施。v0.1.18 不再调分数，而是真正研发新技能：

1. **10 个全新技能域**：覆盖从 exploit 开发到隐写术的完整攻击链
2. **72 个新工具引用**：每个技能绑定 6-9 个 Kali 专属工具
3. **60 个新文件**：每个技能 3 核心文件 + 3 深度指南
4. **61-65 个测试用例**：每个技能 6-8 个结构化测试用例

---

## 10 个新技能域

### 1. network-sniffing-mitm — 网络流量拦截与中间人攻击

| 项目 | 内容 |
|------|------|
| 工具数 | 9 (wireshark, tcpdump, ettercap, bettercap, mitm6, responder, dsniff, driftnet, mitmproxy) |
| 指南 | ettercap/bettercap MITM 攻击、wireshark/tshark 协议分析、responder/mitm6 凭证收割 |
| 填补空白 | 无专属 MITM/sniffing 技能 |

### 2. privilege-escalation — 本地提权

| 项目 | 内容 |
|------|------|
| 工具数 | 8 (linpeas, winpeas, linux-exploit-suggester, pspy, GTFOBins, lolbas, sudo, capsh) |
| 指南 | Linux 提权枚举、Windows 提权攻击、内核利用安全 |
| 填补空白 | 仅是 post-exploitation 的一个子节，提取为独立技能 |

### 3. exploit-development — Exploit 开发

| 项目 | 内容 |
|------|------|
| 工具数 | 8 (gdb/pwndbg, pwntools, ROPgadget, ropper, checksec, pattern_create, shellnoob, one_gadget) |
| 指南 | 缓冲区溢出到 ROP 链、pwntools exploit 开发、shellcode 编写编码 |
| 填补空白 | 未覆盖（binary-reverse 覆盖分析，本技能覆盖武器化） |

### 4. payload-generation — Payload 生成

| 项目 | 内容 |
|------|------|
| 工具数 | 7 (msfvenom, netcat, socat, nishang, hoaxshell, rlwrap, shellter) |
| 指南 | 反弹 shell 完整指南、msfvenom 深度指南、payload 投递规避 |
| 填补空白 | 分散在 3 个技能中，统一为独立技能 |

### 5. av-edr-evasion — AV/EDR 绕过

| 项目 | 内容 |
|------|------|
| 工具数 | 7 (shellter, veil, msfvenom encoders, donut, pe2shc, hyperion, crypter) |
| 指南 | payload 混淆 AV 绕过、内存执行 .NET、EDR 检测规避 |
| 填补空白 | 未覆盖 |

### 6. dns-attacks — DNS 攻击

| 项目 | 内容 |
|------|------|
| 工具数 | 8 (dnsrecon, dnsenum, fierce, dnschef, dns2tcp, dnscat2, dnswalk, iodine) |
| 指南 | DNS 枚举侦察、DNS 隧道数据外泄、DNS 欺骗缓存投毒 |
| 填补空白 | 分散在 recon-osint 和 network-pentest，统一为独立技能 |

### 7. web-xxe — XML 外部实体注入

| 项目 | 内容 |
|------|------|
| 工具数 | 6 (XXEinjector, oxml_xxe, xxeplus, burpsuite, odat, netcat) |
| 指南 | XXE 攻击技术、盲 XXE 数据外泄、oxml-xxe 社工投递 |
| 填补空白 | 未覆盖（OWASP A05） |

### 8. file-inclusion — 文件包含攻击

| 项目 | 内容 |
|------|------|
| 工具数 | 6 (dotdotpwn, kadimus, fimap, burpsuite, php_filter_chain, secLists) |
| 指南 | LFI 转 RCE 利用、路径穿越绕过、RFI 远程代码执行 |
| 填补空白 | 未覆盖 |

### 9. cms-framework-attack — CMS 系统攻击

| 项目 | 内容 |
|------|------|
| 工具数 | 7 (wpscan, joomscan, droopescan, cmseek, nikto, whatweb, nuclei) |
| 指南 | WordPress 渗透、Joomla/Drupal 攻击、CMS 识别枚举 |
| 填补空白 | CMS 仅用于侦察，未覆盖攻击 |

### 10. steganography — 隐写术

| 项目 | 内容 |
|------|------|
| 工具数 | 6 (steghide, stegcracker, zsteg, binwalk, foremost, exiftool) |
| 指南 | 隐写术检测技术、steghide/stegcracker 实战、CTF 隐写挑战 |
| 填补空白 | 未覆盖 |

---

## 技能域分类

| 分类 | 技能 |
|------|------|
| Web 攻击 (8) | web-xss, web-sqli, web-ssrf, web-auth-bypass, web-access-control, web-xxe, file-inclusion, api-security |
| 网络攻击 (4) | network-pentest, network-sniffing-mitm, dns-attacks, wifi-pentest |
| 漏洞利用 (4) | exploit-development, payload-generation, av-edr-evasion, vulnerability-assessment |
| 后渗透 (3) | post-exploitation, privilege-escalation, password-attack |
| 侦察 (3) | recon-osint, osint, cms-framework-attack |
| 防御/审计 (4) | security-review, security-misconfiguration, verification-loop, safety-guard |
| 云/容器 (3) | cloud-security, container-security, supply-chain-security |
| 二进制/移动 (3) | binary-reverse, mobile-security, hardware-security |
| 其他 (29) | 数字取证、隐写术、社工、AI、自动化、知识管理等 |

---

## SOUL.md 决策树更新

新增决策分支：
- XXE 漏洞 → 激活 web-xxe 技能
- 文件包含 → 激活 file-inclusion 技能
- CMS 检测 → 激活 cms-framework-attack 技能
- 网络攻击 → 增加 network-sniffing-mitm 到激活列表
- 后渗透 → 激活 privilege-escalation 独立技能
- EDR 环境 → 激活 av-edr-evasion 技能
- DNS 受限 → 激活 dns-attacks 隧道技能
- Payload + Evasion 决策树（新增完整分支）

---

## 关键洞察

1. **从分数优化转向能力扩展** — v0.1.18 不调分数，真正增加 10 个新的安全能力
2. **61 个技能域** — 覆盖完整 kill chain 从侦察到报告的每一个环节
3. **72 个新工具引用** — 大幅提升 518 工具清单的实际覆盖深度
4. **决策树闭环** — SOUL.md 决策树更新，确保新技能在自动化流程中被正确激活
5. **Agent Skills 开放标准对齐** — 所有 61 个 SKILL.md 符合 Agent Skills Open Standard (Anthropic, 2025)

---

## Agent Skills 标准对齐

v0.1.18 将全部 61 个技能域对齐至 [Agent Skills Open Standard](https://docs.anthropic.com/en/docs/agents/skills)，实现跨平台兼容：

| 标准字段 | 实现 | 覆盖 |
|----------|------|------|
| `name` | 技能目录名（kebab-case） | 61/61 |
| `description` | 从 Description 段落提取（≤300 字符） | 61/61 |
| `version` | "0.1.18" | 61/61 |
| `compatibility` | openclaw, claude-code, cursor, windsurf | 61/61 |
| `allowed-tools` | 按技能类型分三档（security/analysis/all） | 61/61 |
| `metadata.domain` | 安全域分类（web-attack, network-attack 等 20 类） | 61/61 |
| `metadata.tool_count` | Core Tools 表中的工具数量 | 61/61 |
| `metadata.owasp` | OWASP Top 10 映射（12 个技能有映射） | 12/61 |
| `metadata.mitre` | MITRE ATT&CK 映射（19 个技能有映射） | 19/61 |

### 渐进式披露结构

```
Stage 1 (Advertise): YAML frontmatter + ## Summary
  → 平台扫描时加载，快速展示技能名称、描述、工具、域分类

Stage 2 (Quick Reference): ## Core Tools + ## Methodology
  → 技能激活时加载，展示工具表和攻击链

Stage 3 (Detailed): ## Practical Steps + ## Defense Perspective + ## Hacker Laws
  → 任务执行时加载，提供完整操作指南
```

### 文件验证

- 所有 SKILL.md ≤ 500 行（最大：378 行）
- 自动化脚本：`validation/update-skill-standard.py`
- 心跳检查通过：`bash validation/heartbeat.sh` → HEARTBEAT_OK

---

## 下一步计划（v0.1.19+）

1. **Web 攻击链完善** — web-csrf（跨站请求伪造）、web-websocket（WebSocket 安全）
2. **无线扩展** — bluetooth-attacks（蓝牙安全）
3. **数据库攻击** — database-attack（Redis、MongoDB、MSSQL、Oracle 专项）
4. **容器编排深化** — kubernetes-attack（K8s 专项攻击）
5. **新技能评分验证** — 重跑 SCORE.sh 确认所有 61 个技能达到 Excellent

---

_Built with the OpenClaw Agent Framework._
