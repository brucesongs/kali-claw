# kali-claw v0.1.35 发布公告 — GitHub 趋势扩面第六波 +4（99→103）深度扩面

**发布日期**：2026-06-24
**技能域数量**：99 → **103**（+4）
**主题**：v0.1.34 完成 100% Excellent+ 重夺之后，本版本作为第六波，采用"深度扩面"策略——不进入新行业，而是在已掌握的 4 个垂直栈（ICS/无线/区块链/嵌入式）旁添加专门化子域

---

## 驱动力：从"横向扩面"转向"纵向深度"

v0.1.35 是 GitHub 趋势驱动扩面方法论的**第六次成功复制**，也是**首次采用"深度扩面"策略**。前 5 波（v0.1.29-v0.1.34）通过进入新行业领域（AI/云/电信/汽车/macOS/主机帧等）扩张版图，而本波次专注于**在已成熟栈旁添加专门化子域**：

| 新技能 | 相邻已有技能 | 差异定位 |
|--------|--------------|----------|
| ics-fieldbus-attack | scada-ics-security（Modbus/S7comm 基础） | 15+ 现场总线协议（Profibus/DNP3/IEC 61850/IEC 60870-5/EtherCAT/PROFINET） |
| hf-vhf-radio-attack | sdr-rf-attack（Sub-GHz ISM 非授权频段） | 授权 HF/VHF/UHF 频段（ADS-B/AIS/ACARS/POCSAG/APRS） |
| blockchain-l2-attack | blockchain-web3（L1 EVM 智能合约） | L2（Lightning/Optimism/Arbitrum/zkSync/跨链桥） |
| embedded-rtos-security | firmware-reverse（通用固件提取） | RTOS 内部（VxWorks/QNX/FreeRTOS/ThreadX/Zephyr） |

**策略验证**：本波 cohort 平均分 **88.4**，比 v0.1.34 cohort 的 85.4 高 3 分，证明"深度扩面"比"新行业扩面"的基线质量更高（受益于已有模板复用与领域知识沉淀）。

---

## 新增技能域（+4）

### 1. ics-fieldbus-attack — 工业现场总线深度（首个 fieldbus 类）

- **GitHub 数据来源**：Wireshark ICS 拆包器 + Scapy 工业层（IEC 61850/104）+ plcscan (scada-stuff) + Redpoint Digitals + OpenDNP3 + lib60870 (MZ Automation) + IEC104Attack (corelight) + ProfiShark + Boofuzz + Conpot + Claroty/Nozomi（参考）
- **覆盖**：Profibus DP/PA（IEC 61158, EN 50170）、PROFINET RT/IRT、EtherCAT、EtherNet/IP (CIP)、DNP3、IEC 61850（GOOSE/SV/MMS/IED 配置）、IEC 60870-5-101（串行）与 -104（TCP）、Foundation Fieldbus (H1/HSE)、HART/WirelessHART、CC-Link IE TSN、BACnet 深度、ICCP/TASE.2
- **战略意义**：将 OT 覆盖从基础 Modbus 推升至 15+ 现场总线协议；与 `scada-ics-security`（基础）形成 **广度↔深度** 双层 OT 覆盖
- **文件清单**：SKILL.md (508 行)、payloads.md (2,853 行, 92 代码块)、test-cases.md (253 行, 12 TC-FB-001..012)、guides/ics-fieldbus-attack-playbook.md (1,054 行)
- **基线评分**：**88.1 / Excellent**
- **真实事件参考**：乌克兰 2015 BlackEnergy（IEC 104）、Industroyer/CrashOverride（2016，多协议 CVE）、Triton/Trisis（2017，SIS）、Florida 水处理（2021，Oldsmar）

### 2. hf-vhf-radio-attack — 授权 HF/VHF/UHF 无线电（首个 lowfreq-radio 类）

- **GitHub 数据来源**：HackRF One + BladeRF 2.0 micro + RTL-SDR V3 + PlutoSDR + AirSpy R2/HF+ Discovery + GNU Radio + GQRX/SDR#/SDRangel/CubicSDR + dump1090-mutability/readsb + dump978 + AIS-catcher/rtl-ais + multimon-ng + ACARSDeco/dumpvdl2/dumphfdl + URH
- **覆盖**：ADS-B（1090 MHz 飞机跟踪）、AIS（161.975/162.025 MHz 海事船舶）、ACARS（131.550 MHz 航空公司数据）、VDL Mode 2、HFDL（多 HF 频段海洋）、POCSAG/FLEX/APOC 寻呼、APRS（业余无线电位置）、NDB（190-535 kHz）、Weather Fax、DSC（海事遇险）、ATC 语音（118-137 MHz AM）、海事 VHF Ch 16、MLAT/TIS-B/UAT（978 MHz）
- **战略意义**：填补授权频段（航空/海事/寻呼/业余）的覆盖空白；与 `sdr-rf-attack`（Sub-GHz ISM 车钥匙/温度传感器）、`5g-telecom-attack`（蜂窝运营商频段）形成 **非授权↔授权↔蜂窝** 完整 RF 频谱三层覆盖
- **文件清单**：SKILL.md (508 行)、payloads.md (2,745 行, 70+ 代码块)、test-cases.md (12 TC-LF-001..012)、guides/hf-vhf-radio-attack-playbook.md (628 行)
- **基线评分**：**89.3 / Excellent**（v0.1.35 cohort 最高分）
- **真实研究参考**：Povolny ADS-B 欺骗（2012）、Costin "Ghost in the Air"（2012）、Trend Micro 海事 AIS 研究、DEF CON 18 Barisani 寻呼研究、DEF CON 22 Phaedrus ACARS

### 3. blockchain-l2-attack — 区块链 Layer-2 攻击（首个 blockchain-l2 类）

- **GitHub 数据来源**：Foundry (forge/cast/anvil/chisel) + Hardhat + Brownie/Ape + Slither + Mythril + Manticore + Echidna + Etheno + web3.py/ethers.js + Tenderly + Forta + OpenZeppelin Defender + Revoke.cash
- **覆盖**：Lightning Network（BOLT 规范、HTLC、Wormhole RTL CVE-2020-4484）、Optimistic Rollups（Optimism OP Stack、Arbitrum Nitro/One、Boba、Base）、ZK Rollups（zkSync Era、StarkNet、Polygon zkEVM、Scroll、Linea）、Polygon PoS、Gnosis Chain、跨链桥（Wormhole $326M/Nomad $190M/Ronin $625M/Poly Network $611M/Multichain $1.5B/Harmony Horizon $100M/Orbit/Aurora）、ERC-4337 账户抽象（Bundler/Paymaster）、DA 层（Celestia/EigenDA/Avail）
- **战略意义**：将 DeFi 研究从 L1 推升至 L2 + 跨链桥完整栈；与 `blockchain-web3`（L1 EVM）形成 **L1↔L2↔桥** 三层 DeFi 覆盖
- **文件清单**：SKILL.md (684 行，含差异化表对比 5 个相邻技能)、payloads.md (2,380 行, 80 代码块)、test-cases.md (274 行, 12 TC-L2-001..012)、guides/blockchain-l2-attack-playbook.md (619 行)
- **基线评分**：**87.2 / Excellent**
- **真实事件参考**：Ronin Bridge $625M (2022)、Wormhole $326M (2022)、Nomad $190M (2022)、Poly Network $611M (2021)、Multichain $1.5B (2023)、Harmony Horizon $100M (2022)

### 4. embedded-rtos-security — 嵌入式 RTOS 渗透（首个 rtos 类）

- **GitHub 数据来源**：IDA Pro + Ghidra + Binary Ninja + radare2/r2macho + OpenOCD + J-Link/ST-Link/Black Magic Probe/JTAGulator/Shikra + binwalk/firmwalker/FACT + QEMU system/Renode + angr + ChipWhisperer (NewAE) + GreatFET/HydraBus/Bus Pirate + flashrom + strace/ltrace/perf
- **覆盖**：VxWorks（WIND IP 栈、WDB RPC 调试代理、Urgent/11 CVE-2019-12256/12258/12260/12264）、QNX Neutrino（微内核、Qnet、Momentics、qconn）、FreeRTOS + FreeRTOS+TCP（CVE-2018-16525/16528/16529/16603）、ThreadX/Azure RTOS NetX DUO、Zephyr（Kconfig、BT host CVE）、Mbed OS（uVisor、Pelion）、TI-RTOS（NDK、ROV）、MicroC/OS-II/III、NuttX、RIOT、Contiki-NG
- **战略意义**：将嵌入式研究从通用固件推升至 RTOS 内部（调度器/MMU/MPU/IPC）；与 `firmware-reverse`（通用提取）、`iot-pentest`（应用层 MQTT/CoAP）形成 **提取↔内部↔应用** 三层嵌入式覆盖
- **文件清单**：SKILL.md (344 行)、payloads.md (2,891 行, 174 代码块)、test-cases.md (256 行, 12 TC-RT-001..012)、guides/embedded-rtos-security-playbook.md (593 行)
- **基线评分**：**88.8 / Excellent**（cohort 第 2 名）
- **真实研究参考**：JSOF Urgent/11 (2019)、Zimperium FreeRTOS TCP/IP (2018)、Zephyr 蓝牙栈 CVE 系列、Azure RTOS NetX DUO 漏洞

---

## 4 个新技能首次评分

| 排名 | 技能域 | 评分 | 等级 |
|------|--------|------|------|
| 1 | hf-vhf-radio-attack | **89.3** | 优秀 (Excellent) |
| 2 | embedded-rtos-security | **88.8** | 优秀 |
| 3 | ics-fieldbus-attack | **88.1** | 优秀 |
| 4 | blockchain-l2-attack | **87.2** | 优秀 |

**Cohort 平均 88.4**——六波扩面中**最高的新技能平均分**，证明深度扩面策略的优越性：
- v0.1.29 cohort (4): avg 84.5
- v0.1.30 cohort (4): avg 85.3
- v0.1.31 cohort (4): avg 87.5
- v0.1.33 cohort (4): avg 82.8（含 1 个 Strong 拖累）
- v0.1.34 cohort (4): avg 85.4
- **v0.1.35 cohort (4): avg 88.4** ← 新高

---

## 质量快照

| 指标 | v0.1.34 | v0.1.35 | 变化 |
|------|---------|---------|------|
| 技能域总数 | 99 | **103** | +4 |
| 卓越 (Distinguished，92 分及以上) | 19 | **19** | 不变 |
| 优秀 (Excellent，80–91.9 分) | 80 | **84** | +4（全部来自新 cohort） |
| 强 (Strong，60–80 分) | 0 | **0** | 不变 |
| 平均分 | 87.96 | **87.98** | +0.02 |
| 最低分 | 81.0 | **81.0**（email-security-deep） | 不变 |
| 最高分 | 93.8 | **93.8** | 不变 |
| Excellent+ 覆盖率 | 99/99 (100%) | **103/103 (100%)** | 维持 |
| 新技能 cohort 平均 | 85.4 | **88.4** | **+3.0**（深度策略验证） |

→ **100% Excellent+ 里程碑维持**：在 4 个新技能加入后仍为 103/103，证明深度扩面在扩张的同时不牺牲质量底线。

---

## 本版本工作量

| 项目 | 数量 |
|------|------|
| 新增文件 | 16（4×SKILL.md + 4×payloads.md + 4×test-cases.md + 4×guides） |
| 新增代码行 | **~13,000** |
| 新增测试用例 | **48**（12 × 4） |
| 新增工具引用 | ~52（4 技能 × 13 工具均值） |
| 首次评分技能 | 4 |
| 新晋卓越 | 0（cohort 整体在 87-89 段，接近 92+ 但仍有差距） |
| 新类别进入 | **4**（fieldbus、lowfreq-radio、blockchain-l2、rtos） |
| Heartbeat 健康检查 | **HEARTBEAT_OK**（468 个指南，0 个问题） |

---

## 索引文件同步

| 文件 | 更新内容 |
|------|----------|
| validation/update-skill-standard.py | 注册 4 个新技能；新增 4 个类别（fieldbus、lowfreq-radio、blockchain-l2、rtos）；MITRE_MAP 更新 4 个 |
| IDENTITY.md | 新增 4 个技能标签行 |
| TOOLS.md | 新增 4 个分类索引行；99 → 103 技能域 |
| README.md | 6 处 99 → 103；扩展技能列表描述；新增 v0.1.35 changelog 行；刷新质量快照；版本 0.1.34 → 0.1.35 |
| CHANGELOG.md | 新增 v0.1.35 条目 |
| VERSION | 0.1.34 → 0.1.35 |

---

## 战略价值：四大垂直栈全部完成"基础↔深度"双层

### OT 栈（运营技术）

```
scada-ics-security (基础：Modbus/S7comm/EtherNet/IP)        ← 已有
    ↕ 深化
ics-fieldbus-attack (深度：15+ 现场总线协议)                 ← v0.1.35 新增
```

→ **从 PLC 基础到 15+ 行业现场总线协议的完整 OT 攻击面**

### 无线频谱栈

```
sdr-rf-attack (Sub-GHz ISM 非授权：车钥匙/温度传感器)         ← 已有
    ↕ 频段互补
hf-vhf-radio-attack (授权 HF/VHF/UHF：航空/海事/寻呼/业余)    ← v0.1.35 新增
    ↕ 蜂窝补充
5g-telecom-attack (蜂窝广域：5G/LTE)                          ← 已有
```

→ **从 Sub-GHz 到毫米波的完整 RF 频谱三层覆盖**

### 区块链栈

```
blockchain-web3 (L1 EVM 智能合约：Solidity/reentrancy/ERC-20)  ← 已有
    ↕ 层级互补
blockchain-l2-attack (L2 + 跨链桥：Optimism/zkSync/Wormhole)   ← v0.1.35 新增
```

→ **L1 智能合约 + L2 rollup + 跨链桥的多层 DeFi 研究栈**

### 嵌入式栈

```
firmware-reverse (通用固件：binwalk 提取/QEMU 仿真)            ← 已有
    ↕ 内部互补
embedded-rtos-security (RTOS 内部：调度器/MMU/MPU/WDB)         ← v0.1.35 新增
    ↕ 应用互补
iot-pentest (应用层：MQTT/CoAP/云 IoT)                         ← 已有
```

→ **提取 ↔ 内部 ↔ 应用 的完整嵌入式三层覆盖**

---

## GitHub 趋势扩面方法论：第六次成功复制 + 策略演进

| 波次 | 版本 | 新增技能 | 策略 | 新技能平均分 |
|------|------|---------|------|-------------|
| 第 1 波 | v0.1.29 | 4 | 横向扩面（AI/云/防御/应用安全） | 84.5 |
| 第 2 波 | v0.1.30 | 4 | 横向扩面（AI 新兴/IoT/防御/AI 元） | 85.3 |
| 第 3 波 | v0.1.31 | 4 | 横向扩面（企业云/物理/密码学/应用安全） | 87.5 |
| 第 4 波 | v0.1.33 | 4 | 横向扩面（电信/汽车/移动深/云原生） | 82.8 |
| 第 5 波 | v0.1.34 | 4 | 横向扩面（macOS/航空/反作弊/主机帧） | 85.4 |
| 第 6 波 | v0.1.35 | 4 | **深度扩面**（现场总线/低频无线/L2/RTOS） | **88.4** |

→ **策略验证**：深度扩面（在已有栈旁添加专门化子域）比横向扩面（进入新行业）的 cohort 平均分高 **3 分以上**，原因是：
1. **模板复用**：相邻技能的 payloads/guides 结构可直接套用
2. **领域知识沉淀**：已有研究上下文降低新技能学习成本
3. **工具链复用**：Wireshark/SDR/Foundry/OpenOCD 等核心工具已熟练
4. **MITRE 映射明确**：相邻技能的 ATT&CK 战术可继承

→ **GitHub 趋势驱动扩面方法论已成熟到支持多种策略**：横向扩面（广度）+ 深度扩面（纵深）+ 战略提升（针对性修复）三轨并行可控。

---

## 下一步（v0.1.36 候选方向）

- **A**：卓越冲刺 —— 将 89-91 分段技能推升至 92+（username-profiling 91.6、quantum-crypto-attack 90.8、deep-research 90.6、secret-management-attack 90.4、agentic-pentest 90.0、hf-vhf-radio-attack 89.3、embedded-rtos-security 88.8）
- **B**：v0.1.35 cohort 深化 —— 为 4 个新技能扩充第 2 个 guide 文件
- **C**：底层提升 —— 拉升 email-security-deep（81.0）、5g-telecom-attack（82.5）、macos-security（82.7）至 88+
- **D**：扩面第 7 波 —— 存储/SAN 攻击、Hypervisor introspection、PQC 迁移深化、卫星/LEO 安全、AD CS 滥用、OAuth2/OIDC 深度
- **E**：A + C 组合（质量双提升，目标 Distinguished 25+ 且 103/103 达 85+）

---

_本版本是 kali-claw GitHub 趋势驱动扩面方法论的第六次成功复制，也是首次采用"深度扩面"策略（在已有垂直栈旁添加专门化子域）。103 个技能域覆盖 31+ 个类别，包含 19 个 Distinguished + 84 个 Excellent + 0 个 Strong，维持 103/103 100% Excellent+ 里程碑。Cohort 平均分 88.4 创历史新高，验证深度扩面的质量优势。下版本重点：Distinguished 冲刺或第 7 波扩面。_
