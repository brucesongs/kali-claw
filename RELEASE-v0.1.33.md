# kali-claw v0.1.33 发布公告 — GitHub 趋势扩面第四波 +4（91→95）

**发布日期**：2026-06-22
**技能域数量**：91 → **95**（+4）
**主题**：v0.1.32 100% Excellent+ 里程碑之后，回归 GitHub 趋势驱动扩面；填补电信/汽车两大长期盲区；移动端/云原生方向深化

---

## 驱动力：GitHub 趋势驱动扩面方法论第四波

v0.1.33 是 v0.1.29/v0.1.30/v0.1.31 之后的第四次 GitHub 趋势驱动扩面。v0.1.32 专注于纯质量提升（达成 100% Excellent+），本版本回归扩面，聚焦于四个长期存在的覆盖盲区：

| 盲区 | 现状 | 新技能 |
|------|------|--------|
| 蜂窝网络攻击 | 0 个技能覆盖 5G/4G/电信信令 | **5g-telecom-attack** |
| 车载/车联网安全 | 0 个技能覆盖 CAN/UDS/车钥匙 | **automotive-vehicle-security** |
| 移动应用深度 | 仅有 `mobile-security`（配置/静态），无运行时插桩 | **mobile-app-instrumentation** |
| 云原生漏洞研究 | 仅有 `cloud-security`/`container-security`/`kubernetes-attack`，无 CVE 研究方法论 | **cloud-native-vuln-research** |

---

## 新增技能域（+4）

### 1. 5g-telecom-attack — 5G 蜂窝网络安全（首个 telecom 类）

- **GitHub 数据来源**：ravens/awesome-telco + TelcoSec 组织 + srsran/srsRAN_Project（O-RAN 5G CU/DU）+ Open5GS（5G Core 开源实现）+ UERANSIM（UE/RAN 模拟器）+ PacketRusher（5G Core 性能/验证）
- **覆盖**：5G 核心网（AMF/SMF/UPF/AUSF/UDM/PCF/NRF/NSSF）、PFCP 攻击、GTP-U/GTP-C fuzzing、Diameter（S6a/Sh/Rx）、SS7（MAP）遗留协议、IMSI catcher 检测、O-RAN（O1/O2/E2）、漫游滥用、SMS 拦截、SUCI/SUPI 隐私
- **战略意义**：填补长期存在的零蜂窝网络安全覆盖；与 `bluetooth-rfid-nfc`（本地无线）、`wifi-pentest`（局域无线）形成 **本地↔局域↔广域** 无线三层完整覆盖
- **文件清单**：SKILL.md (262 行)、payloads.md (2,148 行, 68 个代码块)、test-cases.md (233 行, 12 TC-5G-001..012)、guides/5g-telecom-attack-playbook.md (535 行)
- **基线评分**：**82.5 / Excellent**
- **真实研究参考**：Karsten Nohl SS7 (2014/2016)、Praetorian PFCP DoS (2019)、Positive Technologies 5G (2023)、"UE Security Reloaded" 论文

### 2. automotive-vehicle-security — 车联网安全（首个 automotive 类）

- **GitHub 数据来源**：hexsecs/awesome-automotive-security + iDoka/awesome-canbus + Linux SocketCAN/can-utils + python-can + cantools + savvy-can + GVRET + CANToolz（eik00d，Black Hat EU 2016）+ Scapy automotive 层 + OpenXC（福特）
- **覆盖**：CAN/CAN-FD 总线分析、UDS（ISO 14229-1）诊断、IVI（车载信息娱乐）渗透、OBD-II 标准 PID、ECU 固件提取、CANToolz 黑盒分析、Scapy 汽车层（XCPScanner、UDS、GMLAN）、滚动码车钥匙（HackRF/Flipper Zero）、PKES 中继攻击（Tesla/BMW）、GNSS 欺骗、ISO 15118 EV 充电安全、CAN injection 方法论
- **战略意义**：填补长期存在的零车联网安全覆盖；与 `iot-pentest`（通用嵌入式）、`sdr-rf-attack`（车钥匙 RF）形成互补
- **文件清单**：SKILL.md (433 行)、payloads.md (1,344 行)、test-cases.md (233 行, 12 TC-AV-001..012)、guides/automotive-vehicle-security-playbook.md (552 行)
- **基线评分**：**79.0 / Strong** ⚠️ 距 Excellent 仅 1 分
- **诊断瓶颈**：payload_code 24（仅 21 个代码块）、field_completeness 0.86、guide 68（仅 1 文件）。**v0.1.34 将针对性提升。**
- **真实事件参考**：Jeep Cherokee (2015, Miller/Valasek)、Tesla Model S (2017, 腾讯科恩)、BMW ConnectedDrive (2015)、CAN injection 盗窃案 UK (2023)

### 3. mobile-app-instrumentation — 移动应用动态插桩（首个 mobile-deep 类）

- **GitHub 数据来源**：Frida (19.7k stars, 工业标准) + Objection (SensePost) + r2frida (radare2 + Frida) + Introspy (iOS/Android) + Cycript (legacy iOS) + AppSec Santa 2026 Frida review
- **覆盖**：Frida JS hooking（`Java.use`/`ObjC.classes`/`Interceptor.attach`）、Objection 运行时探索、SSL pinning bypass、越狱/Root 检测绕过、反调试绕过、iOS Keychain dump、Android Keystore 操作、原生库插桩（r2frida）、加密追踪（CC/CryptoKit / javax.crypto）、WebView 操控、反 Frida 检测绕过
- **战略意义**：与 `mobile-security`（静态配置/清单审查）形成 **静态↔动态** 移动安全双层覆盖；SKILL.md 内置明确的"差异化"章节
- **文件清单**：SKILL.md (298 行, 含 vs `mobile-security` 差异化表)、payloads.md (1,317 行, 60+ 代码块)、test-cases.md (236 行, 12 TC-MI-001..012)、guides/mobile-app-instrumentation-playbook.md (358 行)
- **基线评分**：**84.5 / Excellent**
- **真实案例参考**：Instagram cookie 劫持、Snapchat 越狱检测历史、Uber cert pinning 演进、TikTok keystore bypass

### 4. cloud-native-vuln-research — 云原生漏洞研究（cloud-native 类深化）

- **GitHub 数据来源**：projectdiscovery/nuclei-templates (12.6k stars, 3.5k forks, 1,060+ contributors) + April 2026 KEV + AI/LLM 模板推送 + trivy + grype + syft + osv-scanner + kube-bench + kube-hunter + peirates
- **覆盖**：CVE 研究方法论、Patch diff 分析、SBOM 生成（syft/tern）、漏洞扫描（trivy/grype/osv-scanner）、nuclei 模板创作与社区 PR、容器逃逸 CVE（runc CVE-2019-5736、CVE-2022-0185、CVE-2021-30465）、k8s CVE（CVE-2018-1002105、CVE-2019-11253、CVE-2022-3162）、JVM CVE（Log4Shell/Spring4Shell/Text4Shell）、云供应商 CVE（OMIGOD/Chaos DB）、内核 CVE（Dirty Pipe、CVE-2021-22555）、KEV 跟踪、漏洞链组合
- **战略意义**：与 `cloud-security`（评估）、`container-security`（防御）、`kubernetes-attack`（攻击）形成 **方法论↔评估↔防御↔攻击** 四维云原生覆盖；SKILL.md 内置明确差异化章节
- **文件清单**：SKILL.md (318 行, 含 vs 5 个相邻技能的差异化表)、payloads.md (1,253 行, 69 个代码块)、test-cases.md (222 行, 12 TC-CV-001..012)、guides/cloud-native-vuln-research-playbook.md (347 行)
- **基线评分**：**85.2 / Excellent**
- **真实 CVE 参考**：Log4Shell (CVE-2021-44228)、Spring4Shell (CVE-2022-22965)、Text4Shell (CVE-2022-42889)、OMIGOD (CVE-2021-38645)、Chaos DB (CVE-2021-42306)、Dirty Pipe (CVE-2022-0847)、Codecov 供应链事件

---

## 4 个新技能首次评分

| 排名 | 技能域 | 评分 | 等级 |
|------|--------|------|------|
| 1 | cloud-native-vuln-research | **85.2** | 优秀 (Excellent) |
| 2 | mobile-app-instrumentation | **84.5** | 优秀 |
| 3 | 5g-telecom-attack | **82.5** | 优秀 |
| 4 | automotive-vehicle-security | 79.0 | 强 (Strong) ⚠️ 边缘（距 Excellent 仅 1 分） |

3/4 新技能直接进入 Excellent。automotive-vehicle-security 仅差 1 分，将在 v0.1.34 针对性提升（瓶颈已诊断：payload_code 24、field 0.86、guide 68）。

---

## 质量快照

| 指标 | v0.1.32 | v0.1.33 | 变化 |
|------|---------|---------|------|
| 技能域总数 | 91 | **95** | +4 |
| 卓越 (Distinguished，92 分及以上) | 19 | **19** | 不变 |
| 优秀 (Excellent，80–91.9 分) | 72 | **75** | +3 新 |
| 强 (Strong，60–80 分) | 0 | **1** | +1（automotive-vehicle-security 79.0） |
| 平均分 | 88.19 | **87.96** | -0.23（4 个新基线分拖低） |
| 最低分 | 81.0 | **79.0** | -2.0（新基线为 automotive） |
| 最高分 | 93.8 | **93.8** | 不变 |

**94/95 技能域达到优秀或以上**（98.9%）。1 个 Strong 技能（automotive-vehicle-security 79.0）在 v0.1.34 提升计划中。

---

## 本版本工作量

| 项目 | 数量 |
|------|------|
| 新增文件 | 16（4×SKILL.md + 4×payloads.md + 4×test-cases.md + 4×guides） |
| 新增代码行 | **~9,575** |
| 新增测试用例 | **48**（12 × 4） |
| 新增工具引用 | ~52（4 技能 × 13 工具均值） |
| 首次评分技能 | 4 |
| 新晋卓越 | 0 |
| 新类别进入 | **2**（telecom、automotive） |
| Heartbeat 健康检查 | **HEARTBEAT_OK**（459 个指南，0 个问题） |

---

## 索引文件同步

| 文件 | 更新内容 |
|------|----------|
| validation/update-skill-standard.py | 注册 4 个新技能；新增 2 个类别（telecom、automotive）；MITRE_MAP 更新 4 个 |
| IDENTITY.md | 新增 4 个技能标签行 |
| TOOLS.md | 新增 4 个分类索引行；91 → 95 技能域 |
| README.md | 6 处 91 → 95；扩展技能列表描述；新增 v0.1.33 changelog 行；刷新质量快照；版本 0.1.32 → 0.1.33 |
| CHANGELOG.md | 新增 v0.1.33 条目 |
| VERSION | 0.1.32 → 0.1.33 |

---

## 战略价值：四大覆盖盲区全部填补

### 无线三层闭环

```
bluetooth-rfid-nfc (本地无线，2.4GHz/13.56MHz)    ← 已有
wifi-pentest (局域无线，2.4/5GHz Wi-Fi)           ← 已有
sdr-rf-attack (无线射频，Sub-GHz/车钥匙/ISM)       ← 已有
    ↓ 新增
5g-telecom-attack (广域蜂窝，5G SA/NSA/LTE)        ← v0.1.33 新增
```

→ **从近场到广域的完整无线攻击面**

### 汽车安全从零到一

```
（此前：零汽车安全技能）                            ← 真实盲区
    ↓ 新增
automotive-vehicle-security                       ← v0.1.33 新增
```

→ CAN/UDS/IVI/车钥匙/充电 全栈车联网攻击

### 移动安全双层

```
mobile-security (静态配置/清单审查/证书 pinning 配置)  ← 已有
    ↕ 互补
mobile-app-instrumentation (Frida/Objection 运行时插桩) ← v0.1.33 新增
```

→ 静态 + 动态 完整移动应用安全

### 云原生四维

```
cloud-security (评估)                              ← 已有
container-security (防御)                          ← 已有
kubernetes-attack (攻击)                           ← 已有
    ↕ 互补
cloud-native-vuln-research (方法论/研究)           ← v0.1.33 新增
```

→ 评估 + 防御 + 攻击 + 研究 完整云原生闭环

---

## GitHub 趋势扩面方法论：第四次成功复制

| 版本 | 新增技能 | 类别 | 关键创新 |
|------|---------|------|----------|
| v0.1.29 | 4 | ai-red-team, defense, cloud-native, appsec | 首次使用 GitHub 趋势驱动方法论 |
| v0.1.30 | 4 | ai-emerging, iot, defense, ai-meta | 同日双发验证可复制性 |
| v0.1.31 | 4 | enterprise-cloud, physical, cryptography, appsec | 同日三发里程碑 |
| v0.1.33 | 4 | **telecom, automotive, mobile-deep, cloud-native** | 第四波；填补两大长期盲区 |

→ **GitHub 趋势驱动扩面工作流已稳定成熟**；每个版本节奏稳定，~10k 行新代码、48 个新测试用例。

---

## 下一步（v0.1.34 候选方向）

- **A**：底层提升 —— 将 automotive-vehicle-security（79.0）拉升至 85+，重夺 95/95 Excellent+；同时拉升 email-security-deep（81.0）等其他底部技能
- **B**：卓越冲刺 —— 将 89-91 分段技能推升至 92+（username-profiling 91.6、quantum-crypto-attack 90.8、deep-research 90.6、secret-management-attack 90.4、agentic-pentest 90.0）
- **C**：v0.1.33 cohort 深化 —— 为 4 个新技能扩充第 2 个 guide 文件
- **D**：扩面新领域 —— macOS 安全测试、无人机/UAV 安全、游戏反作弊绕过、主机帧（mainframe）安全等
- **E**：A + B 组合（专注质量，目标 95/95 Excellent+ + Distinguished 25+）

---

_本版本是 kali-claw GitHub 趋势驱动扩面方法论的第四次成功复制，也是首次填补电信与汽车两大长期覆盖盲区的版本。95 个技能域覆盖 25+ 个类别，包含 19 个 Distinguished + 75 个 Excellent + 1 个 Strong（已诊断、v0.1.34 提升计划中）。下版本重点：消除最后一个 Strong 并推进 Distinguished 冲刺。_
