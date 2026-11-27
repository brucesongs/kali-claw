# kali-claw v0.1.21 发布公告 — 首个 Distinguished 技能，反序列化 + 邮件协议攻击域

**发布日期**：2026-06-10
**技能域数量**：70 → 72（+2）
**主题**：首个 Distinguished 技能诞生 + 反序列化攻击与邮件协议攻击填补 Web/协议层空白

---

## 更新概览

v0.1.20 实现了 70/70 Excellent 全域达标。v0.1.21 在此基础上三管齐下：

1. **新增 2 个技能域**：web-deserialization（反序列化攻击）+ email-protocol-attack（邮件协议攻击）
2. **首个 Distinguished 技能**：network-pentest 达到 92.0 分，成为首个突破 Distinguished 层级的技能
3. **Top 5 冲刺 + Bottom 5 补强**：Top 5 全部 91+，Bottom 5 全部提升至 83+

---

## 里程碑：首个 Distinguished 技能

| 指标 | v0.1.20 | v0.1.21 | 变化 |
|------|---------|---------|------|
| 技能域数量 | 70 | 72 | +2 |
| Distinguished (92+) | 0 | **1** | +1 |
| Excellent (80-91.9) | 70 | 71 | +1 |
| Strong/Adequate/Weak | 0 | 0 | — |
| 平均分 | 86.5 | 86.9 | +0.4 |
| 最高分 | 91.3 | **92.0** | +0.7 |

---

## 新增技能域

### 1. web-deserialization — 不安全反序列化攻击

| 项目 | 内容 |
|------|------|
| 工具数 | 6 (ysoserial, phpggc, marshalsec, ysoserial.net, gadgetprobe, jackson-deserialization) |
| 覆盖语言 | Java (ysoserial), PHP (phpggc), .NET (ysoserial.net), Python (pickle), Ruby (Marshal), Java JSON (Jackson/Fastjson) |
| 攻击技术 | 盲检测、Gadget Chain 分析、WAF 绕过、RCE 利用链 |
| OWASP | A08:2021 — Software and Data Integrity Failures |
| 填补空白 | 反序列化攻击分散在各语言技能中，无统一覆盖 |

### 2. email-protocol-attack — 邮件协议攻击

| 项目 | 内容 |
|------|------|
| 工具数 | 8 (smtp-user-enum, swaks, sendemail, nailgun, smtpmap, mutt, openssl, imap-brute) |
| 覆盖协议 | SMTP, IMAP, POP3, Exchange, STARTTLS |
| 攻击技术 | SMTP 用户枚举、开放中继测试、SPF/DKIM/DMARC 绕过、邮件伪造（swaks）、IMAP/POP3 暴力破解、Exchange 服务器利用 |
| 填补空白 | 邮件协议攻击此前完全未覆盖 |

---

## Distinguished 冲刺（Top 5）

| 技能 | 原分 | 现分 | 变化 |
|------|------|------|------|
| **network-pentest** | 91.2 | **92.0** | **+0.8（Distinguished!）** |
| cloud-security | 91.3 | 91.8 | +0.5 |
| autonomous-loops | 90.9 | 91.3 | +0.4 |
| vulnerability-assessment | 90.7 | 91.1 | +0.4 |
| article-writing | 90.6 | 91.0 | +0.4 |

---

## Bottom 5 补强（全部提升至 83+）

| 技能 | 原分 | 现分 | 提升 |
|------|------|------|------|
| privilege-escalation | 80.2 | 85.8 | +5.6 |
| web-xxe | 81.3 | 87.3 | +6.0 |
| cms-framework-attack | 81.7 | 85.8 | +4.1 |
| network-sniffing-mitm | 81.7 | 85.8 | +4.1 |
| ad-ldap-attack | 82.2 | 85.8 | +3.6 |

---

## 指南新增（5 篇）

| 技能 | 指南 | 内容 |
|------|------|------|
| web-access-control | CSRF Attack Guide | CSRF 漏洞检测、Token 绕过、SameSite cookie 利用 |
| api-security | WebSocket Security Testing Guide | WebSocket 劫持、注入攻击、认证绕过 |
| web-xss | SSTI Attack Guide | 服务端模板注入（Jinja2/Twig/FreeMarker） |
| web-xss | WAF Bypass XSS Guide | 编码绕过、分块传输、HTML 实体混淆 |
| web-sqli | WAF Bypass SQLi Guide | 注释绕过、HTTP 参数污染、内联注释技术 |

---

## 质量分布

| 层级 | 数量 | 说明 |
|------|------|------|
| Distinguished (92+) | 1 | network-pentest (92.0) |
| Excellent (80-91.9) | 71 | 其余所有技能域 |
| Strong (60-80) | 0 | — |
| Adequate (40-60) | 0 | — |
| Weak (0-40) | 0 | — |

**平均分：86.9** | **72/72 Excellent 或以上 (100%)**

---

## 关键洞察

1. **首个 Distinguished** — network-pentest 从 91.2 突破至 92.0，标志质量体系进入新阶段
2. **Top 5 全部 91+** — 冲刺组持续增长，下一个 Distinguished 候选：cloud-security (91.8)
3. **Bottom 5 全部 83+** — 底部补强策略生效，最低分从 80.2 提升至 85.8
4. **72 个技能域** — 覆盖从 Web 反序列化到邮件协议的完整攻击面

---

## 下一步计划（v0.1.22+）

1. **更多 Distinguished** — cloud-security (91.8)、autonomous-loops (91.3) 冲刺 92+
2. **新域扩展** — sdr-rf-attack（SDR/射频）、vpn-attack（VPN/IPSec）
3. **指南深化** — 已有技能的指南补充（目标每个技能 5+ 指南）

---

_Built with the OpenClaw Agent Framework._
