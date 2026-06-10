# kali-claw v0.1.19 发布公告 — 8 个空白覆盖域，70 个新工具引用

**发布日期**：2026-06-09
**技能域数量**：61 → 69（+8）
**主题**：8 个空白覆盖域研发，填补 Kali 518 工具中尚未覆盖的攻击面

---

## 更新概览

v0.1.18 完成了 10 个新技能域和 Agent Skills 开放标准对齐。v0.1.19 继续扩展，瞄准此前完全未覆盖的攻击面：

1. **8 个全新技能域**：覆盖蓝牙/RFID、工控系统、固件逆向、数据库协议、VoIP 等空白领域
2. **70 个新工具引用**：每个技能绑定 7-13 个 Kali 专属工具
3. **48 个新文件**：每个技能 3 核心文件 + 3 深度指南
4. **54 个测试用例**：每个技能 6-8 个结构化测试用例

---

## 8 个新技能域

### 1. bluetooth-rfid-nfc — 蓝牙/BLE/RFID/NFC 近场无线攻击

| 项目 | 内容 |
|------|------|
| 工具数 | 13 (spooftooph, redfang, bluelog, btscanner, bluehydra, crackle, ubertooth-tools, gatttool, proxmark3, mfoc, mfcuk, libnfc, blescan) |
| 指南 | 蓝牙设备侦察与攻击、BLE GATT 服务攻击、RFID/NFC 卡克隆攻击 |
| 填补空白 | wifi-pentest 仅覆盖 WiFi，近场无线攻击面完全空白 |

### 2. network-tunneling-proxy — 网络隧道与代理

| 项目 | 内容 |
|------|------|
| 工具数 | 10 (chisel, ligolo-ng, proxychains, socat, ptunnel, gost, 3proxy, sshuttle, stunnel, dnscat2) |
| 指南 | SSH/HTTP 隧道与 pivoting、DNS/ICMP 隐蔽隧道、SOCKS 代理链与流量伪装 |
| 填补空白 | 隧道技术分散在 4+ 个技能中，统一为独立技能 |

### 3. firmware-reverse — 固件逆向工程

| 项目 | 内容 |
|------|------|
| 工具数 | 9 (firmadyne, firmwalker, sasquatch, jefferson, binwalk, unblob, qemu-system, yara, firmware-mod-kit) |
| 指南 | 固件提取与文件系统分析、Firmadyne 固件模拟执行、固件漏洞分析与后门检测 |
| 填补空白 | 介于 hardware-security 和 binary-reverse 之间，无专属域 |

### 4. scada-ics-security — SCADA/ICS 工控安全

| 项目 | 内容 |
|------|------|
| 工具数 | 8 (conpot, plcscan, s7scan, modbus-cli, mbpoll, enip-client, csric, python-opcua) |
| 指南 | ICS 协议侦察与枚举、Modbus/S7comm 攻击、ICS 网络安全评估 |
| 填补空白 | 工控安全（Modbus、S7comm、DNP3、OPC UA 等）完全空白 |

### 5. database-attack — 数据库服务器攻击

| 项目 | 内容 |
|------|------|
| 工具数 | 8 (odat, oscanner, sqsh, redis-tools, mongoaudit, patator, ncrack, hydra) |
| 指南 | Oracle 数据库攻击、Redis/MongoDB 未授权访问、数据库协议暴力破解 |
| 填补空白 | web-sqli 仅覆盖注入攻击，数据库协议层攻击未覆盖 |

### 6. voip-sip-attack — VoIP/SIP 协议攻击

| 项目 | 内容 |
|------|------|
| 工具数 | 8 (sipvicious, sipsak, voiphopper, iaxflood, inviteflood, rtpflood) |
| 指南 | SIP 设备侦察与枚举、VoIP 欺骗与窃听攻击、VoIP 拒绝服务攻击 |
| 填补空白 | VoIP 攻击（SIP、RTP、IAX2 协议）完全空白 |

### 7. anti-forensics — 反取证技术

| 项目 | 内容 |
|------|------|
| 工具数 | 7 (shred, wipe, tcplay, logtamper, timestomp, bulk_extractor, steghide) |
| 指南 | 文件系统反取证、日志清理与时间戳篡改、加密隐藏与数据销毁 |
| 填补空白 | digital-forensics 仅覆盖防御侧，攻击侧未覆盖 |

### 8. pentest-reporting — 渗透测试报告工具

| 项目 | 内容 |
|------|------|
| 工具数 | 7 (dradis, faraday, pipal, cutycapt, recordmydesktop, magictree, cherrytree) |
| 指南 | Dradis/Faraday 报告管理、渗透测试证据收集、漏洞分析与密码审计报告 |
| 填补空白 | article-writing 覆盖写作方法，报告工具使用未覆盖 |

---

## 覆盖空白分析

| 空白领域 | 修复前 | 修复后 |
|----------|--------|--------|
| 近场无线（蓝牙/BLE/RFID/NFC） | 无覆盖 | bluetooth-rfid-nfc（13 工具） |
| 工控系统（SCADA/ICS） | 无覆盖 | scada-ics-security（8 工具） |
| 固件逆向 | 分散在 2 个技能 | firmware-reverse（9 工具） |
| 数据库协议攻击 | 仅 SQL 注入 | database-attack（8 工具） |
| VoIP/SIP 攻击 | 无覆盖 | voip-sip-attack（8 工具） |
| 网络隧道/代理 | 分散在 4+ 个技能 | network-tunneling-proxy（10 工具） |
| 反取证 | 仅防御侧 | anti-forensics（7 工具） |
| 报告工具 | 仅写作方法 | pentest-reporting（7 工具） |

---

## 技能域分类更新

| 分类 | 技能 |
|------|------|
| Web 攻击 (8) | web-xss, web-sqli, web-ssrf, web-auth-bypass, web-access-control, web-xxe, file-inclusion, api-security |
| 网络攻击 (5) | network-pentest, network-sniffing-mitm, network-tunneling-proxy, dns-attacks, wifi-pentest |
| 漏洞利用 (4) | exploit-development, payload-generation, av-edr-evasion, vulnerability-assessment |
| 后渗透 (3) | post-exploitation, privilege-escalation, password-attack |
| 侦察 (3) | recon-osint, osint, cms-framework-attack |
| 防御/审计 (4) | security-review, security-misconfiguration, verification-loop, safety-guard |
| 云/容器 (3) | cloud-security, container-security, supply-chain-security |
| 二进制/移动 (3) | binary-reverse, mobile-security, hardware-security |
| 无线攻击 (2) | wifi-pentest, bluetooth-rfid-nfc |
| 固件/取证 (3) | firmware-reverse, digital-forensics, steganography, anti-forensics |
| 工控安全 (1) | scada-ics-security |
| 数据库攻击 (1) | database-attack |
| VoIP 攻击 (1) | voip-sip-attack |
| 报告 (2) | article-writing, pentest-reporting |
| 其他 (25) | 知识管理、AI、自动化、社工、供应链等 |

---

## 关键洞察

1. **连续两版本扩展 18 个新域** — v0.1.18（+10）和 v0.1.19（+8）合计增加 142 个工具引用
2. **69 个技能域** — 覆盖从 WiFi 到蓝牙、从 Web 到工控、从取证到反取证的完整攻击面
3. **8 个空白域全部填补** — 蓝牙/RFID、工控、固件、数据库协议、VoIP、隧道代理、反取证、报告工具
4. **新增 MITRE ATT&CK 映射** — ICS Attack（TA0100）、Lateral Movement（TA0008）等 7 个新映射

---

## 下一步计划（v0.1.20+）

1. **质量冲刺** — 将 18 个 Strong + 2 个 Adequate 技能全部提升至 Excellent（80+），目标 69/69 Excellent
2. **Payloads 扩充** — 20 个 Below Excellent 技能的 `payloads.md` 代码块不足，需补充实战命令
3. **Test Cases 深化** — 部分技能的测试用例仅 6 个，需扩展覆盖更多攻击路径
4. **Distinguished 冲刺** — 已有技能中接近 92 分的（cloud-security 91.2）冲击 Distinguished 层级

---

_Built with the OpenClaw Agent Framework._
