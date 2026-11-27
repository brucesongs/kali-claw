# kali-claw v0.1.22 发布公告 — SDR/RF 攻击 + VPN 攻击，2 个 Distinguished

**发布日期**：2026-06-10
**技能域数量**：72 → 74（+2）
**主题**：SDR/RF 无线攻击 + VPN 攻击填补无线与网络隧道空白，Distinguished 冲刺新增 cloud-security

---

## 新增技能域

### sdr-rf-attack（7 工具）
SDR/RF 信号攻击域，覆盖 HackRF/RTL-SDR 硬件操作、信号捕获与重放、GSM/LTE 基站分析、RFID/NFC 无线层攻击、车钥匙重放、无人机 RF 分析、卫星信号监测、AIS 船舶追踪、频谱分析。

**填补空白**：wifi-pentest 仅覆盖 WiFi 协议，SDR/RF 整个无线电频谱攻击完全空白。SDR 攻击域将 agent 能力扩展到 IoT、车联网、工控无线等场景。

**工具引用**：gnuradio, gr-gsm, hackrf, rtl-sdr, urh, gqrx, inspectrum

### vpn-attack（5 工具）
VPN 攻击域，覆盖 IKE 枚举（ike-scan）、Aggressive Mode PSK 破解、SSL VPN 漏洞利用（Fortinet CVE-2018-13379、Pulse Secure CVE-2019-11510、Palo Alto CVE-2020-2021、SonicWall CVE-2021-20016）、IPSec 隧道测试、证书分析、凭据暴力破解、分隧道检测。

**填补空白**：network-pentest 仅覆盖网络层，VPN 协议（IKE/IPSec/SSL VPN/WireGuard/OpenVPN）攻击完全空白。

**工具引用**：ike-scan, ikeforce, ikecrack, vpnc, strongswan

---

## Distinguished 冲刺

v0.1.21 实现首个 Distinguished 技能（network-pentest 92.0），v0.1.22 将 cloud-security 推至 92.1：

| 技能域 | v0.1.21 → v0.1.22 | 操作 |
|--------|-------------------|------|
| cloud-security | 87.x → **92.1** | +5 payloads 段（AWS Lambda 提权、Azure CA 绕过、GCP SA 密钥提取、CloudFormation 注入、Terraform 状态利用） |
| network-pentest | **92.0** → **92.0** | 维持 |
| vulnerability-assessment | 88.x → **91.6** | +5 payloads 段（NSE 脚本、OpenVAS 自动化、Nessus CLI、Nuclei 模板、关联脚本） |
| autonomous-loops | 87.x → 89.x | +5 payloads 段 |
| article-writing | 85.x → 87.x | +7 payloads 段 |

---

## 质量快照

| 指标 | v0.1.21 | v0.1.22 |
|------|---------|---------|
| 技能域总数 | 72 | **74** |
| Distinguished (92+) | 1 | **2** |
| Excellent (80-91.9) | 71 | **72** |
| Strong (60-79.9) | 0 | 0 |
| 平均分 | 86.9 | **~87.1** |

---

## 文件变更

### 新增文件（14）
- `skills/sdr-rf-attack/` — SKILL.md + payloads.md + test-cases.md + 3 guides
- `skills/vpn-attack/` — SKILL.md + payloads.md + test-cases.md + 3 guides

### 编辑文件（12）
- VERSION, CHANGELOG.md, RELEASE-v0.1.22.md
- IDENTITY.md, TOOLS.md, CLAUDE.md, README.md, SOUL.md
- validation/heartbeat.sh, validation/update-skill-standard.py
- skills/cloud-security/payloads.md, skills/vulnerability-assessment/payloads.md, skills/autonomous-loops/payloads.md, skills/article-writing/payloads.md

---

## 下一步（v0.1.23 候选方向）

- **A**: 继续从 Kali 518 工具挖掘新技能域（剩余候选：radio-jammer、satellite-attack、ics-scada-deep）
- **B**: Distinguished 冲刺 — 将 vulnerability-assessment (91.6)、verification-loop (90.4) 等推至 92+
- **C**: 质量修复 — 所有 Strong/Adequate 技能提升至 Excellent
