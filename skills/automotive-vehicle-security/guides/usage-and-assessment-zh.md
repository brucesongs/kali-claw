# automotive-vehicle-security — 使用说明与能力评估

> **评估日期**：2026-08-09 | **评估者**：Claude（自动化 + 人工审查） | **评估版本**：v0.2.0.2
> **总分**：**75/100（良好）** | **问题**：P0:0 P1:1 P2:2 P3:1
> **Wave 1 Batch 1**（第 5 个评估的 SKILL） | v0.2.3.2 抽样评分：4.5/5

## 评估速览

| 维度 | 得分（1-5） | 说明 |
|------|-----------|------|
| 1. 合规性 | **5** | 0/0/0 |
| 2. 内容完整性 | **5** | payloads 2608 + test-cases 256 + **8 guides**（本批最多）；13 H2 + 20 H3 |
| 3. 命令语法 | **2** | 0/10 可执行（全部 CAN/GNSS/PKES 硬件依赖）；CAN 工具默认未装 |
| 4. 参考文献 | **2** | 3 URL + 0 CVE — 有限 |
| 5. MITRE/OWASP 对齐 | **4** | 3 个 ATT&CK T-codes（T1530/T1557/T1557.001）；frontmatter TA0001+TA0040+T1557（合理） |
| 6. 可用性 | **5** | v0.2.4 P2 修复将 Defense Perspective 重组为 3 类（法规/车内/外部）；8 guides 为标杆 |
| **加权总分** | **75/100** | **良好** — 但 D3/D4 拉低总分，尽管内容质量优秀 |

---

## 使用说明

### 这个 SKILL 做什么
车辆网络安全测试，覆盖 CAN/CAN-FD、LIN、FlexRay、车载以太网、UDS 诊断、OTA 更新、PKES（被动无钥匙进入）、EV V2G 充电。映射 UNECE R155/R156 与 ISO/SAE 21434。

### 何时使用
1. OEM 型号认证合规（UNECE R155/R156 自 2022-07 强制）
2. Tier-1 供应商审计（如 Bosch/Continental 向 OEM 交付 ECU）
3. 车队车辆渗透测试
4. 汽车 CSMS（网络安全管理系统）实施
5. V2X / 车联网安全研究

### 如何开始
1. **硬件准备**：CAN 适配器（PCAN-USB/Kvaser/vector VN1630）、OBD-II 线缆，可选 JTAGulator 用于 ECU 调试
2. **CAN 基线**：`candump -L can0` 监听流量；`isotpsend` 跑 UDS
3. **识别 ECU 拓扑**：用 UDS 服务 0x22（ReadDataByIdentifier）查 ECUID
4. **侦察威胁**：扫描 UDS 服务 0x10（会话控制）、0x27（安全访问）、0x31（例程控制）
5. **映射到 ISO 21434 TARA**：每个 finding 文档化威胁场景 + 风险等级

### 新手常见坑
- **CAN 仲裁 ID 不是安全边界**：任何 ECU 都能发任何 ID
- **UDS 0x27 安全访问**：受每 ECU 延迟保护防暴力破解；但 seed/key 算法常可逆向
- **PKES 中继攻击**：UWB 飞行时间测距（802.15.4z）是现代防御
- **OTA 更新**：TCU（Telematics Control Unit）是典型入口；验证 SBOM 与签名校验
- **物理安全**：绝对不要在运动车辆上测试制动/转向 ECU，除非在受控测试场

### 交叉引用
- `ics-fieldbus-attack`（CAN 邻接：CANopen、Devicenet）— 工业 CAN 切换
- `embedded-rtos-security` — 目标 ECU 操作系统（AUTOSAR Classic on RTOS）切换
- `hardware-security` — JTAG/UART ECU 调试切换
- `physical-security-testing` — 车辆物理访问切换
- `sdr-rf-attack` — GNSS 欺骗 / V2G 无线切换

---

## 能力评估详情

### D1: 5/5 | D2: 5/5（8 guides 是 guide 丰富 SKILL 的标杆）

### D3: 2/5
- **0/10 命令 PASS**（全部硬件依赖；CAN 工具未安装）
- **VM 工具可用性**：can-utils ✗、python-can ✗、cantools ✗、isotpsend ✗
- **静态审查**：命令语法对所引用工具均正确
- **说明**：本质上 theory-heavy SKILL；D3 反映无法执行 + 可安装覆盖薄
- **证据**：[evidence/2026-08-09/summary.md](../evidence/2026-08-09/summary.md)

### D4: 2/5
- 仅 3 URL（Auto-ISAC + UNECE + ISO/SAE 21434 — 重要但太少）
- **0 CVE**，尽管重大汽车事件（Tesla CVE-2017-3527、BMW 2018、Jeep Cherokee 2015）
- 应参考：CVE-2019-9568（Tesla）、Miller/Valasek Jeep 研究、KEEN LAB BMW 研究

### D5: 4/5
- 3 个 ATT&CK T-codes（T1530 Data from Config Repositories、T1557 Adversary-in-the-Middle、T1557.001 LLMNR/NBT-NS）
- frontmatter：`TA0001-Initial Access, TA0040-Detection, T1557-Adversary-in-the-Middle` — 合理，但 body 涉及更多技术（T1548 Abuse Elevation via UDS、T1529 System Shutdown via ECU denial）

### D6: 5/5
- **优点**：
  - 8 guides（Wave 1 中最多）— 覆盖全面
  - v0.2.4 P2 修复将 Defense Perspective 重组为 3 类（法规/车内网络/外部接口）
  - 对法规（UNECE R155/R156、ISO/SAE 21434、SAE J3061）引用准确
  - HSM（EVITA HSM light/medium/full）章节在行业中领先
- 受监管域 SKILL 的标杆

---

## 问题与优先级

| ID | 优先级 | 描述 | 推荐修复 |
|----|-------|------|---------|
| F-001 | **P1** | 0 CVE 引用，尽管重大汽车事件 | 补充：Jeep Cherokee（Miller/Valasek 2015，CVE-2015-5611）、Tesla（KEEN Lab 2016，CVE-2016-9117）、BMW（KEEN Lab 2018）、Tesla Mode 3（2022） |
| F-002 | P2 | CAN 工具不在 Kali 2026.1 默认 | payloads 补 `apt install can-utils` + `pip install python-can cantools` |
| F-003 | P2 | SKILL.md 仅 3 URL | 补充：Auto-ISAC、NHTSA cybersecurity、ENISA connected vehicles、ISO 21434 标准门户 |
| F-004 | P3 | test cases 偏薄（256 行 vs 2608 行 payloads） | 补 ≥10 个 case，注明硬件特定前置条件 |

---

## 验证证据

- [evidence/2026-08-09/summary.md](../evidence/2026-08-09/summary.md)
- [evidence/2026-08-09/lint.json](../evidence/2026-08-09/lint.json)
- Kali VM：parallels@10.211.55.5（Kali 2026.1，aarch64）

## 评估签字
- 评估者：Claude（Wave 1 Batch 1，SKILL 3/5）
- 批准人：_______________ 日期：_______
