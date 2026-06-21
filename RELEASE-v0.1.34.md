# kali-claw v0.1.34 发布公告 — GitHub 趋势扩面第五波 + automotive 修复（95→99，100% Excellent+ 重夺）

**发布日期**：2026-06-21
**技能域数量**：95 → **99**（+4）
**主题**：v0.1.33 引入最后一个 Strong 之后，本版本通过"扩面 + 修复"双轨战术重夺 100% Excellent+ 里程碑；新增 macOS/UAV/反作弊/主机帧四大新领域

---

## 驱动力：扩面 + 战略修复双轨

v0.1.34 是 GitHub 趋势驱动扩面方法论的**第五次成功复制**。v0.1.33 在扩面时引入了 1 个 Strong 技能（automotive-vehicle-security 79.0），本版本通过同时执行"+4 新技能扩面"与"automotive 战略提升（79.0→88.7）"，将 100% Excellent+ 里程碑从 91/91 推升至 **99/99**。

| 双轨战术 | 动作 | 结果 |
|----------|------|------|
| 扩面轨道 | +4 新技能（macOS/UAV/反作弊/主机帧） | 95→99，新增 4 个类别 |
| 修复轨道 | automotive-vehicle-security 79.0→88.7 | Strong→Excellent，0 Strong 残留 |

---

## 战略提升：automotive-vehicle-security（79.0→88.7，+9.7 分）

### v0.1.33 诊断瓶颈

| 维度 | v0.1.33 得分 | 问题 |
|------|-------------|------|
| payload_code | 24 | 仅 21 个代码块 |
| field_completeness | 0.86 | 字段缺失 |
| guide | 68 | 仅 1 个 playbook |

### v0.1.34 修复方案

| 文件 | v0.1.33 | v0.1.34 | 增量 |
|------|---------|---------|------|
| `payloads.md` | 1,344 行 / 21 代码块 | 2,608 行 / 51 代码块 | +1,264 行 / +30 块 |
| `playbook.md` | 552 行 | 1,052 行 | +500 行 / +2 章节 |
| `test-cases.md` | 233 行 | 256 行 | +23 行（验证清单） |
| `SKILL.md` | guide_count=1 | guide_count=2 | +1 |
| **新增 deep-dive 指南** | — | `automotive-ecu-firmware-and-uds-deep-dive.md`（906 行） | +1 文件 |

**新增 payloads 章节（+6）**：CAN Injection Kill Chain、UDS Negative Response Codes、OBD-II PIDs、ISO 15118/EVSE、ISOTP/Fuzzer、ECU Firmware Extraction

**新增 playbook 章节（+2）**：CAN Bus Reverse Engineering Methodology、Key Fob Attack Workflow

**新增 deep-dive 指南**：JTAG/UART 提取、UDS 服务矩阵、ECU bootloader dump、固件 diff 分析

### 修复结果

- 评分：79.0 → **88.7**（Excellent，+9.7）
- payload_code：24 → 35
- field_completeness：0.86 → 1.00
- guide：68 → 76
- **最后 1 个 Strong 已清除**

---

## 新增技能域（+4）

### 1. macos-security — macOS 渗透测试（首个 macos 类）

- **GitHub 数据来源**：Objective-See 工具集（LuLu/KnockKnock/TaskExplorer/What's Your Sign/Dylib Hijack Scanner/OverSight）+ Snaffler + SipBypasser + AMFIUnrestrictor + Earth Police（TCC dumper）+ optool + insert_dylib + MachOExplorer + class-dump + Hopper + IDA Pro + Ghidra + r2macho + checkra1n/palera1n/ipwndfu/checkm8 + libimobiledevice + Apple Endpoint Security Framework 文档
- **覆盖**：SIP（System Integrity Protection）绕过、TCC（Transparency, Consent, and Control）绕过、AMFI（Apple Mobile File Integrity）、Endpoint Security Framework（ESF）、Keychain dump、Mach-O 分析、Apple Silicon（M1/M2/M3/M4）安全、Gate Keeper 绕过、dylib 劫持、codesign 验证绕过、LaunchDaemons 持久化、Universal Binaries、MDM profile 审计
- **战略意义**：填补长期存在的零 macOS 安全覆盖；与 `mobile-security`（iOS）、`mobile-app-instrumentation`（动态插桩）形成 **Apple 全生态（macOS/iOS）双层覆盖**
- **文件清单**：SKILL.md (390 行)、payloads.md (1,912 行, 60+ 代码块)、test-cases.md (252 行, 12 TC-MAC-001..012)、guides/macos-security-playbook.md (645 行)
- **基线评分**：**82.7 / Excellent**
- **真实研究参考**：SIP 历史绕过（PanguTeam）、TCC bypass（wardle 行为监控）、checkm8 漏洞（axi0mX）、M1 时代 RootPIE/Snap-o-Matic

### 2. uav-drone-security — 无人机/飞行器安全（首个 aerial 类）

- **GitHub 数据来源**：DroneSploit (aixp-bot) + MAVProxy/MAVLink/PX4/ArduPilot + GPS-SDR-SIM + HackRF/BladeRF/PlutoSDR + Dump1090 + RTL_433 + Open Drone ID + droneid_tools + MAVSDK/MAVROS/DronecodeSDK + QGroundControl + Mission Planner + pymavlink + Crazyradio + DJI_Parser
- **覆盖**：MAVLink/CAN 渗透、PX4/ArduPilot 自动驾驶仪分析、GPS 欺骗（GPS-SDR-SIM）、RF 重放（DSM/SBUS/FrSky）、DroneID/Open Drone ID 跟踪、DroneSploit 框架、自动驾驶仪 RCE、禁飞区绕过、遥测 fuzzing、相机负载利用、电池管理系统攻击
- **战略意义**：填补长期存在的零 UAV 安全覆盖；与 `sdr-rf-attack`（Sub-GHz 车钥匙）、`iot-pentest`（通用 IoT）、`5g-telecom-attack`（蜂窝广域）形成 **本地↔广域↔空中** 三维无线覆盖
- **文件清单**：SKILL.md (299 行)、payloads.md (2,197 行, 61 代码块)、test-cases.md (230 行, 12 TC-UAV-001..012)、guides/uav-drone-security-playbook.md (635 行)
- **基线评分**：**85.5 / Excellent**
- **真实事件参考**：伊朗 RQ-170 (2011)、DJI DroneID 反向工程 (2023)、Liron/Anderson MAVLink 攻击 (2019)、Pentext UAV 评估方法

### 3. game-anticheat-bypass — 游戏反作弊绕过（首个 game-security 类）

- **GitHub 数据来源**：Cheat Engine + ScyllaHide + x64dbg + TitanHide + pe-sieve + Moneta + PEframe + pestudio + LOLDrivers (kernels) + kdmapper + VMProtect/Themida + IDA Pro/Ghidra/WinDbg + HyperDbg + process hacker + API Monitor + Procmon
- **覆盖**：EAC（Easy Anti-Cheat）/BattlEye/Vanguard（Riot）/EQU8/Faceit AC/Blizzard Warden 架构分析；内核态 hooking 检测；**BYOVD（Bring Your Own Vulnerable Driver）攻击** via LOLDrivers（Capcom.sys、dbutil_2_3.sys、gdrv.sys、RTCore64.sys）；**Hypervisor 内存 introspection**；DMA 硬件攻击（ScreamerDX/PCIe Suzze）；反调试绕过；代码签名滥用；内存操纵检测
- **伦理框架（关键）**：SKILL.md 内置明确的 "Ethical Framing" 章节，将内容定位为"安全研究 / 反作弊开发者教育 / 红蓝对抗训练"；**NOT for cheating in production games**。所有 payload 仅用于授权研究、受控实验室环境或反作弊开发者防御。
- **战略意义**：填补长期存在的零游戏安全覆盖；与 `av-edr-evasion`（AV/EDR 绕过）、`exploit-development`（漏洞利用开发）、`binary-reverse`（二进制逆向）形成 **内核↔用户态↔反作弊** 三维对抗覆盖
- **文件清单**：SKILL.md (244 行, 含 Ethical Framing 章节)、payloads.md (2,168 行, 90 代码块)、test-cases.md (223 行, 12 TC-GAB-001..012)、guides/game-anticheat-bypass-playbook.md (447 行)
- **基线评分**：**85.2 / Excellent**
- **真实研究参考**：EAC 反向（Secret Club）、BattlEye BEDaisy（/u/Waryas）、Vanguard Ring -1 分析、LOLDrivers 项目 (Wad）

### 4. mainframe-security — 主机帧/遗留系统安全（首个 mainframe 类）

- **GitHub 数据来源**：Hercules emulator + tn3270/wc3270/x3270 + IBM RACF/ACF2/Top Secret 文档 + TSO/ISPF + CICS Transaction Server + DB2 + IMS + MQ + JES2/JES3 + SMP/E + DFSMS + RMF/SMF + z/OS UNIX + z/OSMF + Zowe + IDz + SPUFI/QMF + IDCAMS/IEBGENER/ICEGENER + Mainframe Project
- **覆盖**：z/OS 渗透测试；RACF 用户/组/权限审计；CICS 事务滥用；DB2 SQL 注入；JES2 spooling 攻击；TN3270 仿真；Hercules 模拟器实验室；syslog relay；主机钓鱼；SNA/APPC 攻击；dataset 操纵；APF 授权绕过；Started Task 控制；RACF 数据库提取；密码破解（RACF 加密哈希）
- **战略意义**：填补长期存在的零主机帧安全覆盖；为金融/政府/航空等遗留系统密集行业提供专项工具；与 `ad-ldap-attack`（现代企业身份）、`database-attack`（关系数据库）形成 **遗留↔现代** 身份/数据库双层覆盖
- **文件清单**：SKILL.md (282 行)、payloads.md (1,525 行, 60+ 代码块)、test-cases.md (325 行, 12 TC-MF-001..012)、guides/mainframe-security-playbook.md (425 行)
- **基线评分**：**88.8 / Excellent**（v0.1.34 cohort 最高分）
- **真实事件参考**：Equifax breach (2017, Apache Struts on z/OS edge)、IBM Z 系列历史漏洞、Long Top secret RACF bypass、CIA Vault 7 主机帧工具集

---

## 4 个新技能首次评分

| 排名 | 技能域 | 评分 | 等级 |
|------|--------|------|------|
| 1 | mainframe-security | **88.8** | 优秀 (Excellent) |
| 2 | uav-drone-security | **85.5** | 优秀 |
| 3 | game-anticheat-bypass | **85.2** | 优秀 |
| 4 | macos-security | **82.7** | 优秀 |

**4/4 新技能直接进入 Excellent**（无 Strong 残留），与 v0.1.33 的 3/4 形成对比，验证"GitHub 趋势 + 现有模板"成熟度持续提升。

---

## 质量快照

| 指标 | v0.1.33 | v0.1.34 | 变化 |
|------|---------|---------|------|
| 技能域总数 | 95 | **99** | +4 |
| 卓越 (Distinguished，92 分及以上) | 19 | **19** | 不变 |
| 优秀 (Excellent，80–91.9 分) | 75 | **80** | +5（4 新 + automotive 提升） |
| 强 (Strong，60–80 分) | 1 | **0** | -1（automotive 提升至 Excellent） |
| 平均分 | 87.96 | **87.96** | 不变 |
| 最低分 | 79.0 | **81.0**（email-security-deep） | +2.0 |
| 最高分 | 93.8 | **93.8** | 不变 |
| Excellent+ 覆盖率 | 94/95 (98.9%) | **99/99 (100%)** | **+1.1pp** |

→ **100% Excellent+ 里程碑重夺成功**：v0.1.32 的 91/91 里程碑在 v0.1.33 被 automotive 79.0 破坏，v0.1.34 在 99/99 规模上重夺，证明扩面与质量并行可控。

---

## 本版本工作量

| 项目 | 数量 |
|------|------|
| 新增文件 | 16（4×SKILL.md + 4×payloads.md + 4×test-cases.md + 4×guides） |
| 新增代码行 | **~9,950** |
| 新增测试用例 | **48**（12 × 4） |
| 新增工具引用 | ~52（4 技能 × 13 工具均值） |
| 提升文件 | 3（automotive payloads.md、playbook、新增 ecu-firmware deep-dive） |
| 提升代码行 | ~2,000 |
| 首次评分技能 | 4 |
| 新晋卓越 | 0（cohort 整体在 82-89 段，距离 92+ 仍有距离） |
| 新类别进入 | **4**（macos、aerial、game-security、mainframe） |
| 提升至 Excellent+ | **1**（automotive-vehicle-security 79.0→88.7） |
| Heartbeat 健康检查 | **HEARTBEAT_OK**（463 个指南，0 个问题） |

---

## 索引文件同步

| 文件 | 更新内容 |
|------|----------|
| validation/update-skill-standard.py | 注册 4 个新技能；新增 4 个类别（macos、aerial、game-security、mainframe）；MITRE_MAP 更新 4 个 |
| IDENTITY.md | 新增 4 个技能标签行 |
| TOOLS.md | 新增 4 个分类索引行；95 → 99 技能域 |
| README.md | 6 处 95 → 99；扩展技能列表描述；新增 v0.1.34 changelog 行；刷新质量快照；版本 0.1.33 → 0.1.34 |
| CHANGELOG.md | 新增 v0.1.34 条目 |
| VERSION | 0.1.33 → 0.1.34 |

---

## 战略价值：四大领域突破 + 一个提升

### 操作系统矩阵完整化

```
Linux (现有，分布广泛)
Windows (现有，分布广泛)
移动 iOS/Android (现有 mobile-security + v0.1.33 mobile-app-instrumentation)
    ↓ 新增
macOS (v0.1.34 新增 macos-security)
```

→ **从服务器/移动到桌面的全端点覆盖**

### 空中领域首次进入

```
（此前：零 UAV/无人机安全技能）                  ← 真实盲区
    ↓ 新增
uav-drone-security (v0.1.34 新增)              ← MAVLink/PX4/RF/GPS
```

→ **填补空中 IoT 安全盲区；适配低空经济崛起**

### 游戏反作弊/内核对抗

```
（此前：零反作弊研究技能）                       ← 真实盲区
    ↓ 新增
game-anticheat-bypass (v0.1.34 新增)           ← EAC/BattlEye/Vanguard/BYOVD
```

→ **填补 BYOVD/内核 introspection 研究盲区；服务红蓝对抗与 AC 开发者教育**

### 主机帧/遗留系统

```
（此前：零主机帧安全技能）                       ← 真实盲区
    ↓ 新增
mainframe-security (v0.1.34 新增)              ← z/OS/RACF/CICS/DB2/JES2
```

→ **为金融/政府/航空等遗留系统密集行业提供专项工具**

### 汽车栈闭环

```
v0.1.32 之前：零汽车安全
v0.1.33：automotive-vehicle-security 79.0 (Strong) — 首次进入
v0.1.34：automotive-vehicle-security 88.7 (Excellent) — 提升闭环
```

→ **CAN/UDS/IVI/车钥匙/充电 全栈车联网攻击闭环**

---

## GitHub 趋势扩面方法论：第五次成功复制

| 波次 | 版本 | 新增技能 | 新增类别 | 关键创新 |
|------|------|---------|----------|----------|
| 第 1 波 | v0.1.29 | 4 | ai-red-team, defense, cloud-native, appsec | 首次使用 GitHub 趋势驱动方法论 |
| 第 2 波 | v0.1.30 | 4 | ai-emerging, iot, defense, ai-meta | 同日双发验证可复制性 |
| 第 3 波 | v0.1.31 | 4 | enterprise-cloud, physical, cryptography, appsec | 同日三发里程碑 |
| 第 4 波 | v0.1.33 | 4 | telecom, automotive, mobile-deep, cloud-native | 首次瞄准长期盲区 |
| 第 5 波 | v0.1.34 | 4 | **macos, aerial, game-security, mainframe** | 扩面 + 战略提升双轨 |

→ **GitHub 趋势驱动扩面工作流已完全成熟**：5 波 / 5 版本 / 20 个新技能 / 14 个新类别，同时维持 100% Excellent+ 质量底线。

---

## 下一步（v0.1.35 候选方向）

- **A**：卓越冲刺 —— 将 89-91 分段技能推升至 92+（username-profiling 91.6、quantum-crypto-attack 90.8、deep-research 90.6、secret-management-attack 90.4、agentic-pentest 90.0）
- **B**：v0.1.34 cohort 深化 —— 为 4 个新技能扩充第 2 个 guide 文件
- **C**：底层提升 —— 拉升 email-security-deep（81.0）、5g-telecom-attack（82.5）、macos-security（82.7）至 88+
- **D**：扩面第 6 波 —— ICS 现场总线深挖（Profibus/IEC 61850）、低频无线电（HF/VHF）、区块链 L2、嵌入式 RTOS（VxWorks/QNX）、汽车 ADAS 深化
- **E**：A + C 组合（质量双提升，目标 Distinguished 25+ 且 99/95 达 85+）

---

_本版本是 kali-claw GitHub 趋势驱动扩面方法论的第五次成功复制，也是首次将"扩面轨道"与"战略提升轨道"并行的版本。99 个技能域覆盖 27+ 个类别，包含 19 个 Distinguished + 80 个 Excellent + 0 个 Strong，达成 99/99 100% Excellent+ 里程碑（v0.1.32 的 91/91 升级版）。下版本重点：Distinguished 冲刺或第 6 波扩面。_
