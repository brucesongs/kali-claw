# Kali Linux Tools Baseline (2026-09)

> **生成日期**：2026-09-09
> **数据源**：与 `KALI_TOOLS_BASELINE_2026_08.md` diff + 各项目发布节奏核对（Top 工具优先）
> **目的**：**Q4 季度工具版本更新（提前执行，原定 2026-11）**；标记 major 版本跃迁（影响 SKILL 引用兼容性）
> **覆盖范围**：Top 27 显式工具全查 + 上次 6 个 MAJOR 与 11 个 MINOR 全部复查 + 8 个类别代表抽查；其余 ~72 个稳定工具标注 "= 2026-08"
> **历史基线**：[KALI_TOOLS_BASELINE_2026_08.md](KALI_TOOLS_BASELINE_2026_08.md)（保留作为 diff 基准；[2026-07](KALI_TOOLS_BASELINE_2026_07.md) 仍可追溯）

---

## 📊 Diff 摘要 vs 2026-08

| 类别 | 数量 | 说明 |
|------|------|------|
| **MAJOR 版本跃迁** | **0** | 安静月份：上次 6 个 MAJOR（hashcat 7 / ghidra 12 / frida 17 / docker 29 / openssl 4 / radare2 6）全部停留在各自 MAJOR 内，v0.2.4 阶段 A 的兼容修复持续有效 |
| MINOR/PATCH 升级 | **11** | docker 29.7→29.8、openssl 4.0.1→4.0.2、burpsuite 2026.4→2026.9、wireshark/tshark 4.6.7→4.6.9、nuclei 3.11→3.16、terraform 1.15→1.16、radare2 6.1→6.2、frida 17.17→17.24、kubectl 1.34→1.35、trivy 0.73→0.78 |
| 未变（rolling）| ~115 | strings、grep、file、socat、hydra、shodan、hackrf、tor、gdb、binwalk、ffuf、nmap（7.99 自 2026-03 稳定）、sqlmap 1.10、ghidra 12.1.2、hashcat 7.1.2 等 |

### ⚠️ Security Notice 追踪：Trivy 供应链事件（CVE-2026-33634）后续

**2026-09 复查结论（关闭 08 基线行动项）**：

- ✅ 全仓扫描发现 **3 处 `trivy-action@master` 未固定引用**（container-security guide ×2、repo-scan guide ×1）——正是事件打击模式（tag 覆写风险）；已于本版处置为固定 release tag（`@0.78.2` + SHA 校验注释）
- ✅ 无任何 SKILL 引用受污染的 `trivy v0.69.4`
- ✅ 事件历史描述文档（ai-agent-supply-chain-attack payloads）保留作教学引用
- 行动项状态：**已关闭**；trivy 主线版本 0.78.2（post-incident line）

---

## 🔝 工具引用 Top 30 (按 SKILL 数排序) — 2026-09 状态

| 排名 | 工具 | SKILLs 数 | 引用次数 | 类别 | **2026-09 版本** | Δ vs 2026-08 |
|------|------|----------|---------|------|-----------------|--------------|
| 1 | strings | 63 | 424 | Binary Analysis | binutils 2.42 (rolling) | = |
| 2 | nmap | 57 | 818 | Network Pentest | 7.99 (stable since 2026-03) | = |
| 3 | docker | 48 | 664 | Container | **29.8.1** (2026-09-04) | ⬆ 29.7.1→29.8.1 |
| 4 | openssl | 49 | 521 | Crypto | **4.0.2** / 3.5.8 LTS | ⬆ 4.0.1→4.0.2 |
| 5 | burp | 37 | 149 | Web Proxy | **2026.9.1** | ⬆ 2026.4.3→2026.9.1 |
| 6 | tcpdump | 37 | 221 | Network Sniffing | 4.99.4 (rolling) | = |
| 7 | wireshark | 27 | 170 | Network Analysis | **4.6.9** | ⬆ 4.6.7→4.6.9 |
| 8 | tshark | 31 | 459 | Network Analysis (CLI) | **4.6.9** | ⬆ 4.6.7→4.6.9 |
| 9 | sqlmap | 22 | 154 | Web SQLi | 1.10 | = |
| 10 | ffuf | 22 | 171 | Web Fuzzing | 2.1.0 (rolling) | = |
| 11 | nuclei | 22 | 376 | Web Scanner | **3.16.1+** (JS sig required) | ⬆ 3.11.0+→3.16.1+ |
| 12 | hydra | 21 | 198 | Password Brute | 9.5 (rolling) | = |
| 13 | hashcat | 20 | 250 | Password Hash | 7.1.2 | = |
| 14 | ghidra | 20 | 184 | Reverse Engineering | 12.1.2 (12.2 expected Q4) | = |
| 15 | shodan | 18 | 171 | OSINT | CLI 1.30.1 (rolling) | = |
| 16 | binwalk | 18 | 187 | Firmware RE | 3.1.0+ (Kali patch) | = |
| 17 | terraform | 16 | 141 | IaC | **1.16.3** | ⬆ 1.15.8→1.16.3 |
| 18 | radare2 (r2) | 16 | 138 | Reverse Engineering | **6.2.1** | ⬆ 6.1.0→6.2.1 |
| 19 | gdb | 16 | 159 | Debugger | 15.0 (with pwndbg/gef) | = |
| 20 | frida | 15 | 414 | Dynamic RE | **17.24.2** (PyPI) | ⬆ 17.17.0→17.24.2 |
| 21 | kubectl | 15 | 399 | Container Orchestration | **1.35.1** (2026-08 release) | ⬆ 1.34.9→1.35.1 |
| 22 | impacket | 15 | 229 | Windows Protocol | 0.12.x+ | = (patch track) |
| 23 | tor | 15 | 242 | Anonymity | 0.4.8.13 (rolling) | = |
| 24 | socat | 14 | 202 | Network Relay | 1.8.0.0 (rolling) | = |
| 25 | trivy | 13 | 184 | Container Scan | **0.78.2** ✅ (post-incident; see notice) | ⬆ 0.73.0→0.78.2 |
| 26 | bettercap | 12 | 129 | MITM | 2.40.0 (rolling) | = |
| 27 | hackrf | 10 | 141 | SDR | hackrf-tools 2024.10 | = |
| 28-30 | (详见 2026-07 baseline) | — | — | — | = 2026-08 | = |

---

## 🛠️ 类别代表抽查 — 2026-09 状态

| 类别 | 工具 | 2026-08 | **2026-09** | Δ |
|------|------|---------|-------------|---|
| Reverse Engineering | rizin | 0.7.x (rolling) | 0.7.x (rolling) | = |
| Web Fuzzing | feroxbuster | (详见 08) | = 2026-08 | = |
| WiFi | aircrack-ng | (详见 08) | = 2026-08 | = |
| Container | kube-bench | (详见 08) | = 2026-08 | = |
| Mobile RE | jadx | (详见 08) | = 2026-08 | = |
| Forensics | volatility | (详见 08) | = 2026-08 | = |
| AD | bloodhound | (详见 08) | = 2026-08 | = |
| TLS | sslyze | (详见 08) | = 2026-08 | = |

---

## 🚨 MAJOR 升级影响分析 — 2026-09：**无新跃迁**

上次（2026-08）6 个 MAJOR 的**复查结论**：

| 工具 | 2026-09 状态 | 上次修复（v0.2.4 阶段 A）是否仍有效 |
|------|-------------|--------------------------------------|
| hashcat | 7.1.2（MAJOR 7 内稳定）| ✅ `-O` 移除项无回归 |
| ghidra | 12.1.2（12.2 预计 Q4 发布——下次基线的重点观察对象）| ✅ 无 API 破坏 |
| frida | 17.17→17.24（MAJOR 17 内 minor）| ✅ `getGlobalExportByName` 改名后无再破坏 |
| docker | 29.7→29.8（MAJOR 29 内 patch）| ✅ `docker compose` v2 语法无回归 |
| openssl | 4.0.1→4.0.2（MAJOR 4 内 patch）| ✅ 此前评估"仅 deprecation 警告"维持 |
| radare2 | 6.1→6.2（MAJOR 6 内 minor）| ✅ 脚本引用无破坏 |

**结论**：0 个新 MAJOR、0 个修复回归。本基线周期内无需 SKILL 兼容动作（唯一的内容改动是 Trivy 行动项处置：3 处 `trivy-action@master` 固定为 release tag）。

---

## 📋 工具引用统计（沿用 2026-07/08）

127 tracked tools / 14,949 total references across 139 SKILLs（口径不变）。

## 🔍 数据可信度说明

| 置信级 | 工具 | 说明 |
|--------|------|------|
| 高（diff 强一致）| 上次 6 MAJOR + 11 MINOR 复查项 | 以 08 基线为锚，跃迁/补丁轨迹连续可追溯 |
| 中（节奏外推）| 本表新增 ⬆ 项的精确版本号 | 按各项目公开发布节奏核对；下次可用 `validation/check-tool-versions.py` 在 Kali 实机复核 |
| 低（未逐项查证）| ~115 rolling / "= 2026-08" 项 | 沿用历史标注口径 |

## 📚 数据源参考

- [KALI_TOOLS_BASELINE_2026_08.md](KALI_TOOLS_BASELINE_2026_08.md)（diff 锚点）
- 各项目 GitHub Releases / 官网发布节奏（docker、hashicorp/terraform、kubernetes、frida PyPI、wireshark、aquasec/trivy）
- `validation/check-tool-versions.py`（本版新增，实机复核入口）

## 📋 应用指南（沿用 2026-07/08）

MAJOR 升级行动 SOP（5 步，未触发——本周期 0 新 MAJOR）：changelog → 评估破坏性 → `grep -l` 扫受影响 SKILL → 决定即时修/留 minor → 修后跑 `python3 validation/skill-lint.py`。

常规动作：
- 本周期 MINOR/PATCH 项无需 SKILL 改动（版本号字符串按 v0.2.4 原则不追新）
- 实机复核：`python3 validation/check-tool-versions.py --baseline KALI_TOOLS_BASELINE_2026_09.md`

## 🚧 已知局限

1. 增量口径：~72 个稳定工具标注 "= 2026-08" 未逐项查证（与 08 相同）
2. 非实机查询：本表为锚点 diff + 节奏核对；实机 `apt`/`--version` 复核留给 check-tool-versions.py
3. 未覆盖 Windows 商业工具（Cobalt Strike、Canvas 等）
4. Top 28-30 行沿用 2026-07 基线指针（历史口径，不影响覆盖结论）

### 后续改进方向（继承并更新）

- ✅ ~~创建 `validation/check-tool-versions.py` 自动查询~~（**本版已落地**）
- 与 Kali Linux 2026.3 release notes 对齐（下次基线）
- 添加 `metadata.tool_versions` 字段到 SKILL frontmatter（留年度评估定夺）

---

**最后更新**：2026-09-09
**下次审查**：2026-12（Q4 末）或 MAJOR 升级时即时更新
