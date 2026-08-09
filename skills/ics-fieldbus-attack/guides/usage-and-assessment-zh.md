# ics-fieldbus-attack — 使用说明与能力评估

> **评估日期**：2026-08-09 | **评估者**：Claude（自动化 + 人工审查） | **评估版本**：v0.2.0.2
> **总分**：**79/100（良好）** | **问题**：P0:0 P1:1 P2:1 P3:2
> **Pilot**：新方法学下首个评估的 SKILL（详见 [SKILL_ASSESSMENT_METHODOLOGY.md](../../../docs/SKILL_ASSESSMENT_METHODOLOGY.md)）

## 评估速览

| 维度 | 得分（1-5） | 说明 |
|------|-----------|------|
| 1. 合规性（lint） | **5** | 0 errors / 0 warnings；1 INFO（PRACTICAL_STEPS_COVERED_BY_METHODOLOGY，Methodology 122 行） |
| 2. 内容完整性 | **5** | payloads 2853 行 + test-cases 267 行 + 3 guides；15 H2 + 24 H3；覆盖全部协议 |
| 3. 命令语法（Kali VM 实测） | **3** | 9 条命令 5 条 PASS（56%）；4 FAIL（1 个无效命令 + 3 个缺依赖）；0 broken |
| 4. 参考文献 | **3** | 3 个唯一 URL + 1 个 CVE；引用 IEC 62443 但 URL 密度低 |
| 5. MITRE/OWASP 对齐 | **4** | body 含 7 个 ATT&CK for ICS T-codes；frontmatter 仅 T0817（过窄） |
| 6. 可用性 | **4** | 结构优秀（基础 + IEC 62443 架构 + 检测 + 加固）；ASCII 区域图；分协议检测矩阵；缺新手快速上手 |
| **加权总分** | **79/100** | **良好** — 可用，ICS 域标杆，但 1 个 P1 finding（无效 nmap 命令） |

---

## 使用说明

### 这个 SKILL 做什么（一句话）

工业现场总线协议渗透测试，**覆盖 Modbus 之外** — Profibus/PROFINET、EtherCAT、DNP3、IEC 61850（GOOSE/SV/MMS）、IEC 60870-5-101/104、Foundation Fieldbus、HART、CC-Link、BACnet。适用于电力、过程自动化、楼宇自动化、汽车现场总线攻击面。完美映射 **IEC 62443 区域/通道** 与 **MITRE ATT&CK for ICS**。

### 何时使用（触发场景）

1. 电力变电站渗透测试（IEC 61850 / DNP3 / IEC 60870-5-104）
2. 工厂车间审计（PROFINET / EtherCAT / Modbus TCP）
3. 楼宇自动化评估（BACnet / KNX）
4. EV 充电桩汽车 CAN 总线邻接现场总线（HomePlug AV2）
5. 安全仪表系统（SIS）审查（ISA 84 / IEC 61511）

### 如何开始（5 步快速上手）

1. **盘点现场总线** — `tshark -G protocols | grep -iE "dnp3|iec|modbus|profinet|ethercat"` 确认 Wireshark 解析器可用
2. **被动抓包** — `tcpdump -i eth0 -w capture.pcap port 20000 or port 2404 or port 502`（不要主动扫描生产 OT）
3. **识别** — `nmap -sV --script iec-identify,iec61850-mms,modbus-discover,s7-info` 针对授权目标
4. **解码** — `tshark -r capture.pcap -Y iec60870_asdu -V` 做协议级取证
5. **规划攻击** — 交叉参考 SKILL 的分协议检测矩阵 + IEC 62443 区域图选择向量

### 新手常见坑

- **未经授权不要对生产 PLC 运行 `nmap -sV`** — 即使是版本检测也可能打挂老旧固件；某些 PLC（西门子 S7-300、ABB RTU560）已知异常流量会故障
- **`dnp3-info` NSE 脚本不存在** — payloads.md 引用了但 nmap 从未提供该脚本。改用 `tshark` 或 `modbus-discover.nse`（见 F-001）
- **组播协议（GOOSE、PROFINET IRT）需要镜像口** — 交换机 SPAN/RSPAN 必备
- **时间敏感协议（GOOSE <4ms）** — 加 TLS 或认证会破坏确定性；不要在生产环境测试
- **HART 是 4-20mA 模拟量** — 需要 HART 调制解调器（USB-HART）主动测试；不能通过 IP 完成

### 交叉引用（相关 SKILL）

| 相关 SKILL | 何时切换 |
|-----------|---------|
| `scada-ics-security` | 更广 SCADA 范围（HMI + 工程师站攻击） |
| `automotive-vehicle-security` | CAN bus / UDS / EV 充电（现场总线邻接） |
| `embedded-rtos-security` | 当目标是 PLC/RTU 操作系统本身（VxWorks、QNX） |
| `physical-security-testing` | 当测试 RTU 机柜的物理访问 |
| `detection-engineering` | 当为 OT 监控构建 Sigma/Suricata 规则 |

---

## 能力评估详情

### 维度 1：合规性

- **证据**：`skill-lint.py --skill ics-fieldbus-attack`
- **结果**：0 errors、0 warnings、1 INFO（`PRACTICAL_STEPS_COVERED_BY_METHODOLOGY` — Methodology 122 行，合理替代 Practical Steps）
- **得分**：**5/5**

### 维度 2：内容完整性

- **证据**：
  - SKILL.md：15 个 H2 节 + 24 个 H3 子节 + 4 个代码块
  - payloads.md：2853 行
  - test-cases.md：267 行
  - guides/：3 个 markdown 文件（本文件为第 4 个）
- **覆盖**：全部 10 个协议（DNP3、IEC 60870、IEC 61850、PROFINET、EtherCAT、Modbus、Foundation Fieldbus、HART、CC-Link、BACnet）在 payloads 有专节
- **得分**：**5/5**

### 维度 3：命令语法（Kali VM 实测）

- **方法**：在 Parallels VM（Kali 2026.1 aarch64）执行 9 条命令；1 条 sandbox-only 未执行
- **通过率**：5/9 = 56%
- **分类分布**：9 full + 1 sandbox-only
- **证据文件**：[evidence/2026-08-09/summary.md](../evidence/2026-08-09/summary.md)
- **关键失败**：
  - `nmap --script dnp3-info` — 该脚本不存在（F-001）
  - `python3 -c "from pyModbusTCP.client import ModbusClient"` — 库默认未安装（F-002）
- **得分**：**3/5**（评分标准："70-84% 通过 或 1 个 broken"；本次 56% 通过 + 0 broken，刚过 50% 阈值；将无效命令失败视为严重）

### 维度 4：参考文献

- **证据**：
  - SKILL.md 仅 3 个唯一 URL（偏少）
  - 1 个 CVE 引用
  - IEC 62443 / ISA 引用 4 次（语境充分）
- **改进空间**：补充 IEC 62443 标准门户、MITRE ATT&CK for ICS 矩阵、Dragos/Claroty/Nozomi 博客、SANS ICS 峰会
- **得分**：**3/5**

### 维度 5：MITRE/OWASP 对齐

- **证据**：
  - body 含 7 个 ATT&CK for ICS T-codes：T0807、T0817、T0858、T0859、T0866、T0884、T0890
  - IEC 62443 区域/通道模型明确（Level 0-5 ASCII 图）
  - **问题**：frontmatter `mitre: "T0817-Program Logic Controller Software"` 仅覆盖 7 个技术中的 1 个（F-003）
- **得分**：**4/5**

### 维度 6：可用性

- **优点**：
  - 出色的 4 段结构：现场总线基础 → IEC 62443 架构 → 分协议检测策略 → 加固措施
  - ASCII 区域图让 IEC 62443 一目了然
  - 分协议检测矩阵（8 行：DNP3、IEC 104、GOOSE、MMS、PROFINET、EtherCAT、BACnet、HART）将理论与工具结合
  - 交叉引用 detection-engineering、threat-hunting
- **不足**：
  - 缺新手 "Quick Start" 章节（本 guide 已补）
  - payloads.md 2853 行 — 可按协议拆分为多个文件
- **得分**：**4/5**

---

## 问题与优先级

| ID | 优先级 | 描述 | 推荐修复 |
|----|-------|------|---------|
| F-001 | **P1** | payloads.md（第 40、43、354 行）3 次引用 `nmap --script dnp3-info`，但任何 nmap 版本都不存在该 NSE 脚本 | 替换为 `tshark` 过滤器（如 `tshark -Y dnp3 -V`）；Modbus-via-DNP3 网关可用 `nmap --script modbus-discover`；通过 20000 端口 + banner grab 文档化 DNP3 识别 |
| F-002 | P2 | Python 库 `pyModbusTCP`、`cpppo` 不在 Kali 2026.1 默认安装 | payloads.md 前置条件补充 `pip install pyModbusTCP cpppo` |
| F-003 | P3 | frontmatter `mitre: "T0817-Program Logic Controller Software"` 过窄 | 扩展为 `"T0807-Discovery, T0817-Program Logic Controller Software, T0858-Change Operating Mode, T0859-Valid Accounts, T0866-Exploitation of Remote Services, T0884-Connection Proxy, T0890-Mitigation of DLP"` |
| F-004 | P3 | SKILL.md 仅 3 个唯一 URL | 补充：IEC 62443 门户（isa.org/standards）、MITRE ATT&CK for ICS 矩阵、CISA ICS-CERT、Dragos/Claroty/Nozomi 博客 |

**问题合计**：1 P1 + 1 P2 + 2 P3 = 4（0 P0）

---

## 验证证据

- **Kali VM 运行日志**：[evidence/2026-08-09/summary.md](../evidence/2026-08-09/summary.md)
- **Lint JSON**：[evidence/2026-08-09/lint.json](../evidence/2026-08-09/lint.json)
- **Kali VM**：parallels@10.211.55.5（Kali 2026.1，kernel 6.18.12，aarch64）
- **评估方法**：抽样 10 个 payload（按类型分层：侦察 / 解码 / 库检查 / 静态参考）

---

## 评估签字

- 评估者：Claude（自动化评估 + Pilot 人工审查）
- 批准人：_______________ 日期：_______
- Pilot 审查：本 SKILL 用于校准评估方法学；后续评估沿用同一模板

---

## 参考资料

- [MITRE ATT&CK for ICS](https://attack.mitre.org/matrices/ics/) — OT 技术 T-code 参考
- [IEC 62443 standards](https://www.isa.org/standards) — 区域/通道模型
- [CISA ICS-CERT](https://ics-cert.us-cert.gov/) — 安全公告
- [SKILL 评估方法学](../../../docs/SKILL_ASSESSMENT_METHODOLOGY.md) — 方法学参考
