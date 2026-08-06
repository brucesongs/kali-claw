# Kali Linux Tools Baseline (2026-08)

> **生成日期**：2026-08-06
> **数据源**：WebSearch（GitHub Releases + Kali Package Tracker + 官网） + 与 `KALI_TOOLS_BASELINE_2026_07.md` diff
> **目的**：Q3 季度工具版本更新；标记 major 版本跃迁（影响 SKILL 引用兼容性）
> **覆盖范围**：Top 30 高频工具全查 + 5 个类别代表抽查；其余 ~72 个稳定工具标注 "= 2026-07"
> **历史基线**：[KALI_TOOLS_BASELINE_2026_07.md](KALI_TOOLS_BASELINE_2026_07.md)（保留作为 diff 基准）

---

## 📊 Diff 摘要 vs 2026-07

| 类别 | 数量 | 说明 |
|------|------|------|
| **MAJOR 版本跃迁** | **6** | hashcat 6→7、ghidra 11→12、frida 16→17、docker 27→29、openssl 3→4、radare2 5→6 |
| MINOR/PATCH 升级 | 11 | nmap 7.95→7.99、nuclei 3.3→3.11、sqlmap 1.8→1.10、burpsuite 2024.12→2026.4、wireshark/tshark 4.2→4.6、metasploit 6.4→6.5、kubectl 1.30→1.34、terraform 1.9→1.15、trivy 0.54→0.73、impacket 0.12 patch |
| 未变（rolling） | ~110 | strings、grep、file、socat、hydra、shodan、hackrf、tor、gdb、binwalk、ffuf 等 |

### ⚠️ Critical Security Notice

**Trivy 供应链攻击事件（CVE-2026-33634）**：
- 事件日期：2026-03-19
- 攻击者用窃取的凭据发布恶意 `trivy v0.69.4` 和 `trivy-action` tags
- 影响：75+ 个 tag 被覆写；用户可能在 CI 中拉取到恶意版本
- **行动项**：升级到 v0.73.0+；验证 binary checksum；审查 `trivy-action` 使用历史
- 详见：[aquasec.com/blog/trivy-supply-chain-attack](https://www.aquasec.com/blog/trivy-supply-chain-attack-what-you-need-to-know/)

---

## 🔝 工具引用 Top 30 (按 SKILL 数排序) — 2026-08 状态

| 排名 | 工具 | SKILLs 数 | 引用次数 | 类别 | **2026-08 版本** | Δ vs 2026-07 |
|------|------|----------|---------|------|-----------------|--------------|
| 1 | strings | 63 | 424 | Binary Analysis | binutils 2.42 (rolling) | = |
| 2 | nmap | 57 | 818 | Network Pentest | **7.99** (2026-03-26) | ⬆ 7.95→7.99 |
| 3 | docker | 48 | 664 | Container | **29.7.1** (2026-07-31) | ⬆⬆ **MAJOR** 27→29 |
| 4 | openssl | 49 | 521 | Crypto | **4.0.1** (stable) / 3.5.7 LTS | ⬆⬆ **MAJOR** 3→4 |
| 5 | burp | 37 | 149 | Web Proxy | **2026.4.3** (2026-05-08) | ⬆ 2024.12→2026.4 |
| 6 | tcpdump | 37 | 221 | Network Sniffing | 4.99.4 (rolling) | = |
| 7 | wireshark | 27 | 170 | Network Analysis | **4.6.7** | ⬆ 4.2.5→4.6.7 |
| 8 | tshark | 31 | 459 | Network Analysis (CLI) | **4.6.7** | ⬆ 4.2.5→4.6.7 |
| 9 | sqlmap | 22 | 154 | Web SQLi | **1.10** | ⬆ 1.8.10→1.10 |
| 10 | ffuf | 22 | 171 | Web Fuzzing | 2.1.0 (rolling) | = |
| 11 | nuclei | 22 | 376 | Web Scanner | **3.11.0+** (JS sig required) | ⬆ 3.3.5→3.11+ |
| 12 | hydra | 21 | 198 | Password Brute | 9.5 (rolling) | = |
| 13 | hashcat | 20 | 250 | Password Hash | **7.1.2** (2025-08-23) | ⬆⬆ **MAJOR** 6→7 |
| 14 | ghidra | 20 | 184 | Reverse Engineering | **12.1.2** (2026-06) | ⬆⬆ **MAJOR** 11→12 |
| 15 | shodan | 18 | 171 | OSINT | CLI 1.30.1 (rolling) | = |
| 16 | binwalk | 18 | 187 | Firmware RE | 3.1.0+ (Kali patch) | = |
| 17 | terraform | 16 | 141 | IaC | **1.15.8** (2026-07-08) | ⬆ 1.9.5→1.15.8 |
| 18 | radare2 (r2) | 16 | 138 | Reverse Engineering | **6.1.0** | ⬆⬆ **MAJOR** 5→6 |
| 19 | gdb | 16 | 159 | Debugger | 15.0 (with pwndbg/gef) | = |
| 20 | frida | 15 | 414 | Dynamic RE | **17.17.0** (PyPI) | ⬆⬆ **MAJOR** 16→17 |
| 21 | kubectl | 15 | 399 | Container Orchestration | **1.34.9** (2026-06-09) | ⬆ 1.30.2→1.34.9 |
| 22 | impacket | 15 | 229 | Windows Protocol | 0.12.x+ (2026-01 Windows updates) | = (patch) |
| 23 | tor | 15 | 242 | Anonymity | 0.4.8.13 (rolling) | = |
| 24 | socat | 14 | 202 | Network Relay | 1.8.0.0 (rolling) | = |
| 25 | trivy | 13 | 184 | Container Scan | **0.73.0** ⚠️ (see CVE-2026-33634) | ⬆ 0.54.1→0.73.0 |
| 26 | bettercap | 12 | 129 | MITM | 2.40.0 (rolling) | = |
| 27 | hackrf | 10 | 141 | SDR | hackrf-tools 2024.10 | = |
| 28-30 | (详见 2026-07 baseline) | — | — | — | — | = |

---

## 🛠️ 类别代表抽查 — 2026-08 状态

| 类别 | 工具 | 2026-07 | **2026-08** | Δ |
|------|------|---------|-------------|---|
| Reverse Engineering | rizin | 0.7.0 | 0.7.x (rolling) | = |
| Web Fuzzing | feroxbuster | 2.11.0 | 2.11.x (rolling) | = |
| Wireless | aircrack-ng | 1.7 | 1.7.x (rolling) | = |
| Cloud Security | kube-bench | 0.8.0 | 0.8.x (rolling) | = |
| Mobile | jadx | 1.5.0 | 1.5.x (rolling) | = |
| Forensics | volatility | 3-2.7.0 | 3-2.7.x | = |
| Post-Exploitation | bloodhound | 5.12.0 | 5.12.x | = |
| Crypto | sslyze | 6.0.0 | 6.0.x | = |

类别代表本次抽查均无 major 变化，反映这些子领域相对稳定。

---

## 🚨 MAJOR 升级影响分析（6 个工具）

这 6 个工具跨 major 版本，可能影响 SKILL 中 payloads 命令的兼容性。建议在下次月度审查（2026-09-05）时针对性核对相关 SKILL：

| 工具 | 升级路径 | 影响范围（SKILL 数） | 兼容性风险 | 建议行动 |
|------|---------|---------------------|-----------|---------|
| **hashcat 6 → 7** | major upgrade 2025-08 | 20 | 低（攻击模式语法未变；新增 hash modes） | payloads 中 `-m` 模式号需要时再核 |
| **ghidra 11 → 12** | 2026-06 release | 20 | 中（脚本 API 变化；Ghidrathon 集成） | 检查 binary-reverse、firmware-reverse 的 guides |
| **frida 16 → 17** | 2025-Q4 release | 15 | 高（脚本引擎升级；ObjC.choose API 变化） | **优先**审查 mobile-security、mobile-app-instrumentation |
| **docker 27 → 29** | 跨两个 major（28 + 29） | 48 | 中（compose 插件默认；buildkit 默认） | container-security guides 需核 |
| **openssl 3 → 4** | 2026-Q1 release | 49 | 中（EVP API 强化；旧 deprecated 移除） | crypto-attacks、tls 相关 SKILL |
| **radare2 5 → 6** | 2025-Q4 release | 16 | 中（命令兼容；r2pipe API 变化） | binary-reverse guides |

**累计影响 SKILL 数（去重）**：约 80-100 个有引用，但实际需要修改的预计 < 20 个（多数是版本号引用而非命令语法）。

---

## 📋 工具引用统计（沿用 2026-07）

- **Total tools referenced**: 127
- **Total references**: 14,949
- **Average refs per tool**: 117.7
- **Tools referenced in >20 skills**: 13 (core tools)
- **Tools referenced in 5-20 skills**: 30 (specialized tools)
- **Tools referenced in <5 skills**: 84 (niche tools)

---

## 🔍 数据可信度说明

### 高可信度（双源校验）
nmap、nuclei、hashcat、ghidra、frida、docker、openssl、burpsuite、wireshark、kubectl、terraform、trivy、radare2、metasploit、sqlmap — 来自工具官网 / GitHub Releases / Kali Package Tracker 中至少两个独立源。

### 中可信度（单源）
impacket 0.12.x — GitHub Releases 提及 2026-01 Windows 更新，具体版本号未明确。

### 低可信度（未查）
其余 ~72 个稳定工具：标注 "= 2026-07" + "rolling"。这些工具是 Kali Linux rolling 系统工具（strings、grep、socat、hydra、shodan、tor 等），版本跟随 Kali 自动更新，无独立版本号概念。

---

## 📚 数据源参考

- **Kali Linux Tools**：[kali.org/tools](https://www.kali.org/tools/) — 官方工具索引
- **Kali Package Tracker**：[pkg.kali.org](https://pkg.kali.org/) — 版本追踪
- **GitHub Releases**：各工具官方仓库
- **NVD CVE 数据库**：[nvd.nist.gov](https://nvd.nist.gov/vuln/detail/CVE-2026-33634) — Trivy 供应链 CVE

---

## 📋 应用指南（沿用 2026-07）

### 何时使用本基线

**必须使用**：
- 修改 `SKILL.md` 中的工具版本号（先用本表核对最新）
- 验证 payloads.md 中的工具命令有效性
- 创建新 SKILL（避免引用已过时版本）

**参考使用**：
- 写 Defense Perspective 中的防御对策
- 添加 Detection Methods 中的 SIEM 规则（避免引用已废弃工具）

### MAJOR 升级行动 SOP

发现 MAJOR 升级（如 hashcat 6→7）时：

1. 查阅工具 changelog（GitHub Releases）
2. 评估 API/语法破坏性变更
3. 扫描受影响 SKILL：`grep -l "hashcat" skills/*/payloads.md`
4. 决定是即时修复（高优先级）还是等待下次 minor 版本
5. 修复后跑 `python3 validation/skill-lint.py` 确认无回归

---

## 🚧 已知局限

1. **未全量扫描 127 工具**：本次仅覆盖 Top 30 + 5 个类别代表；其余标注 rolling
2. **WebSearch 结果可能延迟**：某些工具的最新 patch（如几小时前发布的）可能未反映
3. **Kali 实例验证缺失**：理想情况应在 Kali 2025.4 / 2026.1 实例上 `apt show <tool>` 核对
4. **未覆盖 Windows 商业工具**：Cobalt Strike、Canvas 等不在 baseline 范围

### 后续改进方向

- 创建 `validation/check-tool-versions.py` 自动查询（避免手动 WebSearch）
- 与 Kali Linux 2026.1 / 2026.2 release notes 对齐（季度发布节奏）
- 添加 `metadata.tool_versions` 字段到 SKILL frontmatter（机器可读）

---

**最后更新**：2026-08-06
**下次审查**：2026-11（Q4 2026 review）或 MAJOR 升级时即时更新
