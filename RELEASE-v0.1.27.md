# kali-claw v0.1.27 发布公告 — 17 Distinguished 里程碑

**发布日期**：2026-06-11
**技能域数量**：74（不变）
**主题**：Distinguished 冲刺 + 底层提升双轨推进，达成 17 Distinguished 里程碑

---

## Distinguished 冲刺结果

v0.1.26 有 15 个 Distinguished，v0.1.27 新增 2 个：

| 技能域 | v0.1.26 → v0.1.27 | 提升 | 措施 |
|--------|-------------------|------|------|
| scada-ics-security | 91.6 → **93.0** | +1.4 | 创建 2 个新 guides (ics-incident-response, purdue-model-attack-paths); file_count 5→7 |
| council | 89.9 → **92.3** | +2.4 | 扩充 3 个 guides (avg 1289→2000+); 创建 2 个新 guides (multi-agent-escalation, council-consensus-building); file_count 5→7 |

---

## 底层提升结果

| 技能域 | v0.1.26 → v0.1.27 | 提升 | 措施 |
|--------|-------------------|------|------|
| database-attack | 83.4 → **87.3** | +3.9 | SKILL.md 扩充至 20 标题; 创建 2 个新 guides (nosql-attack, database-lateral-movement); 新增 5 个 payload sections (14→19); file_count 3→5 |
| exploit-development | 84.9 → **86.1** | +1.2 | 创建 2 个新 guides (heap-exploitation, kernel-exploit); file_count 3→5 |
| dns-attacks | 83.4 → **84.6** | +1.2 | 创建 2 个新 guides (dns-rebinding, dns-tunnel-exfiltration); file_count 3→5 |

---

## 完整 Distinguished 列表（17 个）

| # | 技能域 | 分数 |
|---|--------|------|
| 1 | social-intelligence | 93.8 |
| 2 | article-writing | 93.6 |
| 3 | payload-generation | 93.1 |
| 4 | scada-ics-security | **93.0** ⭐ 新晋 |
| 5 | vulnerability-assessment | 93.0 |
| 6 | security-misconfiguration | 92.8 |
| 7 | autonomous-loops | 92.6 |
| 8 | verification-loop | 92.6 |
| 9 | osint | 92.5 |
| 10 | vpn-attack | 92.5 |
| 11 | council | **92.3** ⭐ 新晋 |
| 12 | network-tunneling-proxy | 92.3 |
| 13 | web-deserialization | 92.2 |
| 14 | cloud-security | 92.1 |
| 15 | network-pentest | 92.0 |
| 16 | security-bounty-hunter | 92.0 |
| 17 | web-xss | 92.0 |

---

## 质量快照

| 指标 | v0.1.26 | v0.1.27 |
|------|---------|---------|
| 技能域总数 | 74 | **74** |
| Distinguished (92+) | 15 | **17** (+2) |
| Excellent (80-91.9) | 59 | **57** (-2) |
| 平均分 | 88.0 | **88.2** |
| 最低分 | 83.4 | **84.5** |

**100% 技能域达到 Excellent 或以上**（74/74）。

---

## 本版本工作量

- **新增 guides**：8 个（scada-ics-security ×2, council ×2, database-attack ×2, exploit-development ×2, dns-attacks ×2）
- **SKILL.md 扩充**：2 个（database-attack, scada-ics-security）
- **Guides 扩充**：3+ 个（council 等三个 guides 大幅扩写）
- **新增 payload sections**：5 个（database-attack）

---

## 下一步（v0.1.28 候选方向）

- **A**: 继续冲刺 — sdr-rf-attack (88.8), web-access-control (88.1), exploit-development (86.1) 推至 92+
- **B**: 底层提升 — 最低分技能群（83-85 区间）拉至 87+
- **C**: 新增技能域 — 用户名 OSINT (Maigret)、暗网情报、威胁狩猎 等
- **D**: A+B+C 组合
