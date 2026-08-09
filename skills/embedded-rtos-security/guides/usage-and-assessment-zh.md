# embedded-rtos-security — 使用说明与能力评估

> **评估日期**：2026-08-09 | **评估者**：Claude（自动化 + 人工审查） | **评估版本**：v0.2.0.2
> **总分**：**83/100（优秀）** | **问题**：P0:0 P1:0 P2:1 P3:2
> **Wave 1 Batch 1**（第 4 个评估的 SKILL）

## 评估速览

| 维度 | 得分（1-5） | 说明 |
|------|-----------|------|
| 1. 合规性 | **5** | 0/0/0 |
| 2. 内容完整性 | **5** | payloads 2891 行 + test-cases 256 行 + 3 guides；18 H2 + 37 H3（本批最高 H3 数） |
| 3. 命令语法 | **4** | VM 上 6/10 可用（binwalk/sasquatch/ghidra analyzeHeadless）；qemu/firmwalker/jefferson 缺失 |
| 4. 参考文献 | **5** | 16 个 URL + 13 个 CVE — 本批最佳 |
| 5. MITRE/OWASP 对齐 | **4** | 6 个 ATT&CK T-codes（T1049/T1055/T1068/T1210/T1499/T1548）；frontmatter 仅 T1548 |
| 6. 可用性 | **4** | RTOS 覆盖强（VxWorks/QNX/FreeRTOS/ThreadX/Zephyr）；商业工具门槛高 |
| **加权总分** | **83/100** | **优秀** — Wave 1 Batch 1 之首 |

---

## 使用说明

### 这个 SKILL 做什么
RTOS 利用，覆盖主流嵌入式操作系统：VxWorks（Wind River）、QNX（BlackBerry）、FreeRTOS、ThreadX、Zephyr、RIOT-OS。流程：固件提取 → 静态 RE → 动态仿真 → 利用。

### 何时使用
1. 自定义 RTOS（非 Linux）IoT 设备渗透
2. ICS/SCADA 设备审计（多数 PLC 跑 VxWorks 或自研 RTOS）
3. 医疗设备安全（许多跑 QNX 或 VxWorks 653）
4. 汽车 ECU 逆向（AUTOSAR Classic 常跑在 RTOS）
5. 航空 / DO-178C 安全关键软件审查

### 如何开始
1. **提取固件**：`binwalk -e firmware.bin`（或 `binwalk -X` 原始提取）
2. **识别 RTOS**：在提取的文件系统中找字符串 "VxWorks"、"QNX"、"FreeRTOS" 版本标记
3. **Ghidra 静态 RE**：加载固件，选择正确处理器（ARM/MIPS），如有 RTOS loader 用之
4. **QEMU 仿真**：`qemu-system-arm -M vexpress-a9 -kernel firmware.bin`（RTOS 仿真可能需自定义 QEMU 配置）
5. **已知 CVE 搜寻**：交叉参考 SKILL 的 13 CVE 表与提取版本

### 新手常见坑
- **VxWorks WINDML debug agent**（端口 17185）：生产环境常未关闭；可读写内存
- **QNX Qconn**（端口 8000）：类似的调试后门
- **FreeRTOS 栈金丝雀**：默认较弱；检测 `--disable-stack-protector` 标志
- **ThreadX trace FIFO**：若完整提取，是有价值的取证源
- **Zephyr Kconfig**：错误配置常留下调试 shell

### 交叉引用
- `firmware-reverse`（Linux 导向固件分析）— 设备跑 Linux 时切换
- `binary-reverse`（通用二进制 RE）— 提取后需反汇编时切换
- `hardware-security`（UART/JTAG）— 硬件调试接口访问切换
- `ics-fieldbus-attack` — RTOS 设备处于 OT 环境时切换
- `automotive-vehicle-security` — 目标 AUTOSAR ECU 时切换

---

## 能力评估详情

### D1: 5/5 | D2: 5/5（3 guides + 子节覆盖丰富）

### D3: 4/5
- **6/10 命令 PASS**：binwalk ✓、sasquatch ✓、Ghidra analyzeHeadless ✓、Python numpy/scipy ✓
- **4/10 缺失**：qemu-system-arm、qemu-system-mips、firmwalker、jefferson
- **证据**：[evidence/2026-08-09/summary.md](../evidence/2026-08-09/summary.md)

### D4: 5/5
- 16 URL + 13 CVE（本批参考密度最佳）
- 引用包含：CVE-2019-12260（VxWorks）、CVE-2019-11890（FreeRTOS）等

### D5: 4/5
- body 含 6 个 ATT&CK T-codes；frontmatter `T1548-Abuse Elevation Control Mechanism` 仅覆盖 1/6
- 应扩展包含 T1049 System Network Connections、T1055 Process Injection、T1068 Exploitation for Privilege Escalation、T1210 Exploitation of Remote Services、T1499 Endpoint Denial of Service

### D6: 4/5
- 优点：18 H2 节，5 个 RTOS 分别覆盖
- 不足：商业工具（VxWorks Workbench、QNX Momentics）Kali 上无法安装；payloads 应明确说明

---

## 问题与优先级

| ID | 优先级 | 描述 | 推荐修复 |
|----|-------|------|---------|
| F-001 | P2 | qemu-system-arm / qemu-system-mips 不在 Kali 2026.1 默认 | payloads 前置条件补 `apt install qemu-system-arm qemu-system-mips` |
| F-002 | P2 | firmwalker / jefferson 缺失 | 补 `pip install jefferson` + clone `firmwalker`（github.com/craigz28/firmwalker） |
| F-003 | P3 | frontmatter mitre 字段过窄（6 个 T-codes 仅 1） | 扩展枚举全部 6 个 T-codes |
| F-004 | P3 | test cases 偏薄（256 行 vs 2891 行 payloads，比率 8.8%） | 补 ≥15 个 test case |

---

## 验证证据

- [evidence/2026-08-09/summary.md](../evidence/2026-08-09/summary.md)
- [evidence/2026-08-09/lint.json](../evidence/2026-08-09/lint.json)
- Kali VM：parallels@10.211.55.5（Kali 2026.1，aarch64）

## 评估签字
- 评估者：Claude（Wave 1 Batch 1，SKILL 2/5）
- 批准人：_______________ 日期：_______
