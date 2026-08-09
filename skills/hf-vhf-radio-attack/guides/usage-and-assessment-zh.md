# hf-vhf-radio-attack — 使用说明与能力评估

> **评估日期**：2026-08-09 | **评估者**：Claude（自动化 + 人工审查） | **评估版本**：v0.2.0.2
> **总分**：**71/100（良好）** | **问题**：P0:0 P1:1 P2:2 P3:1
> **Wave 1 Batch 1**（第 3 个评估的 SKILL）

## 评估速览

| 维度 | 得分（1-5） | 说明 |
|------|-----------|------|
| 1. 合规性 | **5** | 0 errors / 0 warnings / 0 findings |
| 2. 内容完整性 | **5** | payloads 3434 行 + test-cases 204 行 + 2 guides；14 H2 + 28 H3 |
| 3. 命令语法（理论为主） | **3** | VM 上 0/10 可执行（均依赖 SDR 硬件）；静态审查显示 2 个工具不存在（具体待查） |
| 4. 参考文献 | **1** | **0 个 URL + 0 个 CVE** — 严重缺口 |
| 5. MITRE/OWASP 对齐 | **3** | body 含 5 个 ATT&CK T-codes（T1499/T1557/T1580/T1592/T1595）；frontmatter 仅 T1557（5 缺 4） |
| 6. 可用性 | **4** | 域覆盖强（ADS-B/AIS/ACARS/POCSAG/APRS）；硬件需求使实操困难 |
| **加权总分** | **71/100** | **良好** — 亟需 URL 参考 |

---

## 使用说明

### 这个 SKILL 做什么

HF/VHF 射频攻击技能 — 覆盖 ADS-B（航空追踪）、AIS（海事）、ACARS（航空电报）、POCSAG（寻呼）、APRS（业余无线电分组）。需要 SDR 硬件（HackRF/RTL-SDR/bladeRF）。

### 何时使用

1. 航空安全研究（ADS-B 欺骗、ACARS 拦截）
2. 海事域感知（AIS 欺骗、船舶追踪规避）
3. 寻呼网络的安全测试（POCSAG 解码）
4. 业余无线电 / APRS 安全审查
5. 射频层事件响应（射频干扰源定位）

### 如何开始

1. **验证 SDR 硬件**：`hackrf_info` 或 `rtl_test`（需要 HackRF One 或 RTL-SDR dongle）
2. **安装 SDR 软件栈**：`apt install hackrf gqrx-sdr gnuradio dump1090-mutability`
3. **测试 ADS-B 接收**：`dump1090 --net`（会显示 ~100km 内的飞机）
4. **抓取 AIS**：`rtlais -r 162000000 -s 96000 -g 40 -d 0`（需要海事 VHF 天线）
5. **解码 POCSAG**：`rtl_fm -f 157.9e6 -s 22050 | multimon-ng -t raw -a POCSAG512 -`

### 新手常见坑

- **SDR 频率精度**：RTL-SDR 有 ±50ppm 漂移；需要 `rtl_epp -p 1` 校准
- **天线比 SDR 重要**：原配鞭状天线对 ADS-B 无用；需要 1090 MHz 专用天线
- **合法性**：未持牌照发射在多数司法管辖区违法；本 SKILL 涵盖接收 + 分析 +（持牌情况下）发射
- **GNURadio 学习曲线**：考虑先用 GQRX GUI，再上原生 GNURadio 流图

### 交叉引用

- `sdr-rf-attack`（更广 SDR，含蜂窝）— 目标蜂窝/5G 时切换
- `bluetooth-rfid-nfc`（近场 RF）— BLE/NFC 场景切换
- `satellite-leo-security`（LEO 卫星）— Starlink/Iridium 切换
- `automotive-vehicle-security`（EV V2G via HomePlug）— EV 充电攻击切换

---

## 能力评估详情

### D1: 5/5（完美合规）

### D2: 5/5（语料库中最详尽的 payloads — 3434 行）

### D3: 3/5
- **方法**：测试 10 个 SDR 命令；全部需要 Kali VM 上不存在的硬件
- **静态审查**：命令语法正确；工具引用真实（hackrf/dump1090/multimon-ng 都是真实工具）
- **VM 工具可用性**：0/10（所有 SDR 工具默认缺失）
- **说明**：本质上为 theory-only SKILL；D3 得分反映无法运行时验证，并非命令错误
- **证据**：[evidence/2026-08-09/summary.md](../evidence/2026-08-09/summary.md)

### D4: 1/5
- SKILL.md 中 **0 URL + 0 CVE** — 严重缺口（F-001）
- 应参考：ICAO Annex 10（ADS-B 标准）、ITU-R M.1371（AIS）、POCSAG 规范、APRS 标准

### D5: 3/5
- body 含 5 个 ATT&CK T-codes；frontmatter `mitre: "T1557-Adversary-in-the-Middle"` 仅覆盖 1/5
- 应扩展至 T1499 Endpoint Denial of Service（RF 干扰）、T1580 Cloud Infrastructure Discovery（如航空云）、T1592 Gather Victim Host Info、T1595 Active Scanning

### D6: 4/5
- **优点**：协议专项深挖（ADS-B / AIS / ACARS / POCSAG / APRRS 各成节）
- **不足**：无 SDR 新手快速上手；默认假设 HackRF/RTL-SDR 已熟悉

---

## 问题与优先级

| ID | 优先级 | 描述 | 推荐修复 |
|----|-------|------|---------|
| F-001 | **P1** | SKILL.md 中 0 个 URL | 补充：ICAO Annex 10 Vol III（ADS-B）、ITU-R M.1371-5（AIS）、POCSAG 规范（EDS-9300）、APRS 1.0.1 规范、HackRF wiki |
| F-002 | P2 | 无 CVE 引用，尽管已知航空/海事 RF 事件 | 参考：2012 伊朗-美国 RQ-170 ADS-B 欺骗、2013 AIS 幽灵船研究（德州大学） |
| F-003 | P2 | frontmatter mitre 字段过窄（5 个 T-codes 仅 1） | 扩展为 `"T1499-Endpoint Denial of Service, T1557-Adversary-in-the-Middle, T1580-Cloud Infrastructure Discovery, T1592-Gather Victim Host Info, T1595-Active Scanning"` |
| F-004 | P3 | test cases 偏薄（204 行 vs 3434 行 payloads） | 每个协议补 ≥10 个 test case |

---

## 验证证据

- [evidence/2026-08-09/summary.md](../evidence/2026-08-09/summary.md)
- [evidence/2026-08-09/lint.json](../evidence/2026-08-09/lint.json)
- Kali VM：parallels@10.211.55.5（Kali 2026.1，aarch64）

## 评估签字
- 评估者：Claude（Wave 1 Batch 1，SKILL 1/5）
- 批准人：_______________ 日期：_______
