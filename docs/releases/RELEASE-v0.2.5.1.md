# kali-claw v0.2.5.1 版本说明 — ics-fieldbus-attack 实战改进 🛠️

> **版本编号**：v0.2.5.1（patch release）
> **发布日期**：2026 年 8 月 12 日
> **版本类型**：单 SKILL 内容改进（来自实战验证 findings）
> **上一版本**：v0.2.5（2026-08-09，月度审查 A+B 范围）
> **下一里程碑**：v0.2.5.2（其他 SKILL 实战验证）或 v0.2.6（月度审查）

---

## 项目地址

- **GitHub 仓库**：[https://github.com/brucesongs/kali-claw](https://github.com/brucesongs/kali-claw)
- **主分支**：[main](https://github.com/brucesongs/kali-claw/tree/main)

---

## 一、版本概述

v0.2.5.1 是 kali-claw **首个基于"实战验证反馈"的 SKILL 内容改进 patch**。基于 2026-08-10 对 `ics-fieldbus-attack` 在真实 OpenPLC（GRFICSv3）上的实战验证发现的 4 个 SKILL gap，本次 patch 全部修复。

**核心产出**：
- `skills/ics-fieldbus-attack/payloads.md` 新增 §21（OpenPLC 实战发现，+119 行）
- 4 个 findings 全部应用（F-008 P0 + F-009 P1 + F-010 P2 + F-011 P3）
- skill-lint 保持 0/0/139（无回归）

**实际工时**：~15 分钟

---

## 二、版本亮点

### 1. F-008 P0 修复：补 `openplc:openplc` 默认凭据

实战发现：OpenPLC Web HMI 默认凭据是 `openplc:openplc`（不是文档常见的 admin/admin）。

**新增内容**（payloads.md §21.1）：
- 多凭据组合测试脚本（`for cred in admin:admin admin:openplc openplc:openplc ...`）
- 完整利用链（登录 → cookie → dashboard → Modbus 配置页 → ST 程序上传）
- 防御建议（改默认密码 + 8080 端口限制 + 反爆破）

**意义**：这是 kali-claw SKILL 首次基于**真实靶场实证**发现并补全默认凭据，而非引用文献。

### 2. F-009 P1 修复：澄清 `nmap modbus-discover` 真实行为

实战发现：SKILL 原文（line 40 等）暗示 `nmap modbus-discover` 返回设备识别信息；实际 OpenPLC + 多数现代 PLC（施耐德 Modicon M340、ABB AC500、西门子 S7-1500 经网关）返回 `ILLEGAL FUNCTION`。

**新增内容**（payloads.md §21.2）：
- 解释：拒绝 FC 0x2B 反而确认目标是 Modbus 设备
- 替代方案：依赖 `nmap -sV` 服务版本指纹 + MBAP banner

### 3. F-010 P2 修复：补 HR 0xFFFF 内存泄漏模式

实战发现：OpenPLC ST runtime 编译时未清零 %QW 映射区，0xFFFF 是 UINT 默认值；远程匿名读取即可洞察内部状态。HR[12] = 65535 / HR[13] = 65535 对应 ST 程序变量 `purge_manual_sp` / `product_manual_sp`。

**新增内容**（payloads.md §21.3）：
- Python 探测脚本（读 HR 0-50，找 0xFFFF 位置）
- 漏洞机制说明
- 防御建议（VAR_BLOCK 显式初始化为 0）

### 4. F-011 P3 修复：补 Werkzeug + Python 版本指纹

实战发现：`nmap -p 8080 -sV` 直接披露 OpenPLC Web HMI 的 Werkzeug + Python 版本（"Werkzeug httpd 2.3.7 (Python 3.9.2)"）。

**新增内容**（payloads.md §21.4）：
- 利用价值：Werkzeug 2.3.7 已知 CVE-2023-46136；Python 3.9.2 EOL
- 防御建议：前置 nginx 反代隐藏 Server header + 定期升级

---

## 三、修改文件清单

| 文件 | 改动 | 行数 |
|------|------|------|
| `skills/ics-fieldbus-attack/payloads.md` | TOC 新增 §21 + 末尾新增 §21 完整内容（6 子节） | +119 |
| `skills/ics-fieldbus-attack/SKILL.md` | last_reviewed 2026-07-26 → 2026-08-12 | +1/-1 |
| `VERSION` | 0.2.5 → 0.2.5.1 | +1/-1 |
| `RELEASE-v0.2.5.1.md` | 新建（本文档） | 新增 |
| `CHANGELOG.md` | 追加 v0.2.5.1 条目 | +25 |
| `UPDATELOG.md` | 追加 v0.2.5.1 条目 | +30 |
| `MEMORY.md` | 追加 2026-08-12 v0.2.5.1 决策记录 | +15 |
| `README.md` | 版本表追加 v0.2.5.1 行 + Current Version | +2/-2 |

---

## 四、关键决策

### 决策 1：新增 §21 而非修改原 §14（Modbus RTU/Plus）

**采用**：在 payloads.md 末尾新增 `## 21. OpenPLC Web HMI + Modbus TCP 实战发现`。
**理由**：
- 原 §14 是 Modbus RTU/Plus（串行/令牌环），与 OpenPLC（Modbus TCP + Web HMI）不同
- 新增 §21 不破坏原 TOC 序号，便于读者查阅
- §21 集中所有 v0.2.5.1 实战发现，便于未来追加（如 v0.2.5.2 其他 PLC 验证）

### 决策 2：保留"beyond Modbus TCP"叙事

**采用**：保持 payloads.md 顶部 "fieldbus protocols BEYOND Modbus TCP" 叙述。
**理由**：
- SKILL 核心仍是非 Modbus TCP 协议（DNP3/IEC/PROFINET 等）
- §21 是"实战验证发现"，非主协议覆盖
- §21 标题明确标注"OpenPLC Web HMI + Modbus TCP"，读者不会混淆

### 决策 3：4 个 findings 一次性全应用

**采用**：v0.2.5.1 一次性应用 F-008 ~ F-011（4 个 findings）。
**理由**：
- 4 个 findings 来自同一次验证（2026-08-10 GRFICSv3），关联性强
- 单次 commit 单次发布，便于回滚
- 工时仅 ~15 分钟（内容已成型）

### 决策 4：不修改 frontmatter mitre 字段

**跳过**：未修改 SKILL.md frontmatter `mitre: "T0817-Program Logic Controller Software"`。
**理由**：
- Pilot finding F-003（frontmatter mitre 过窄）不在本次范围
- frontmatter mitre 修改影响 SKILL 评分，应在下次 minor 单独处理
- 本次专注 payload 内容（实战发现）

---

## 五、Findings 应用统计

| Finding | 优先级 | 应用前状态 | 应用后状态 | 应用方式 |
|---------|-------|-----------|-----------|---------|
| F-008 | **P0** | SKILL 缺 openplc:openplc 默认凭据 | ✅ §21.1 完整记录 + 利用链 | 新增 §21.1 |
| F-009 | P1 | modbus-discover 暗示返回设备信息 | ✅ §21.2 解释 ILLEGAL FUNCTION 是预期 | 新增 §21.2 |
| F-010 | P2 | HR 0xFFFF 内存泄漏模式缺失 | ✅ §21.3 Python 探测脚本 | 新增 §21.3 |
| F-011 | P3 | Werkzeug 版本指纹未提 | ✅ §21.4 利用价值 + 防御 | 新增 §21.4 |

**P0 findings 关闭**：1/1 ✅
**P1 findings 关闭**：1/1 ✅
**P2 findings 关闭**：1/1 ✅
**P3 findings 关闭**：1/1 ✅
**总关闭**：4/4 = 100%

---

## 六、统计对比

### 工时分解

| 阶段 | 预估 | 实际 |
|------|------|------|
| payloads.md TOC 更新 | 1min | ~1min |
| §21 内容撰写（6 子节） | 30min | ~10min |
| SKILL.md last_reviewed | 1min | ~1min |
| 验证 lint | 2min | ~1min |
| RELEASE + 同步入口文档 | 10min | ~2min |
| **合计** | **~45min** | **~15min** |

### v0.2.5 → v0.2.5.1 变化

| 维度 | v0.2.5 | v0.2.5.1 |
|------|--------|----------|
| SKILL 总数 | 139 | 139（不变） |
| skill-lint | 0/0/139 | **0/0/139** |
| payloads.md 总行数 | 2853 | **2972** (+119) |
| 实战 findings 关闭数 | 0/4 | **4/4** ✅ |
| 实战 findings 待处理（F-001~F-007） | 7 | 7（不在本次范围） |

---

## 七、与既有版本衔接

- **承接 v0.2.5**：本次 patch 全部基于 v0.2.5 月度审查中产生的实战验证（2026-08-10）
- **衔接 v0.2.5 实战**：4 个 findings 来自 GRFICSv3 OpenPLC 验证（commit 9c04aca + 3b5c3ef）
- **不影响其他 SKILL**：仅修改 `ics-fieldbus-attack` 一个 SKILL
- **下次 patch 候选**：
  - F-001（dnp3-info 脚本不存在）— P1
  - F-002（pyModbusTCP/cpppo 缺安装提示）— P2
  - F-003（frontmatter mitre 过窄）— P3
  - F-005/006/007（来自 Python sim 验证）— P2/P3/P3

---

## 八、风险与对策

| 风险 | 概率 | 影响 | 对策 |
|------|------|------|------|
| OpenPLC 新版本改了默认凭据 | 中 | 低 | §21.1 加"实测版本"说明；下次验证时再核 |
| §21 与原"beyond Modbus TCP"叙事冲突 | 低 | 低 | 标题明确"OpenPLC Web HMI + Modbus TCP"；不混淆 |
| 用户误以为是 Modbus TCP 全套覆盖 | 低 | 低 | §21 头部链接到 validation-walkthrough-zh.md（限定上下文） |

---

## 九、验证

```bash
$ cat VERSION
0.2.5.1

$ python3 validation/skill-lint.py
============================================================
Total skills:    139
Passed (no ERR): 139 (100%)
Failed:          0
Total errors:    0
Total warnings:  0
============================================================

$ grep -c "^## " skills/ics-fieldbus-attack/payloads.md
21  # 原 20 节 + §21
```

---

## 十、后续路线

### v0.2.5.2（其他 SKILL 实战验证）

- 用同样方法验证 Wave 1 Batch 1 其他 4 个 SKILL（embedded-rtos / automotive / blockchain-web3 / pam-privilege）
- 每验证一个 SKILL 找到 findings → 类似 v0.2.5.1 patch 应用

### v0.2.6（月度审查）

- 第 2 次 v0.2.5 后月度审查
- 评估 v0.2.5.1 改进在真实使用中的反馈

### v0.3 minor（基于实战 findings 批量修复）

- 处理累积的 P1/P2 findings（F-001/002/003 + 其他 SKILL 类似问题）
- 可能基于 v0.2.3.3 P1 候选决定新增 SKILL

---

## 十一、版本签名

```
版本编号：v0.2.5.1（patch release）
发布日期：2026-08-12
版本类型：单 SKILL 内容改进（来自实战验证 findings）
项目地址：https://github.com/brucesongs/kali-claw
许可证：MIT

上一版本：v0.2.5（2026-08-09，月度审查 A+B 范围）
本次工时：~15min（vs 预估 45min，节省 67%）
新增内容：skills/ics-fieldbus-attack/payloads.md §21（+119 行）
修改文件：~8（payloads + SKILL + RELEASE + VERSION + CHANGELOG + UPDATELOG + MEMORY + README）
SKILL 修改：1（ics-fieldbus-attack）
SKILL 总数：139（不变）
skill-lint：0 errors / 0 warnings（保持）
P0 findings 关闭：1/1（F-008 openplc:openplc）
实战 findings 总关闭：4/4（F-008 ~ F-011）
```

**kali-claw 团队**
**2026 年 8 月 12 日**
**首个基于实战验证反馈的 SKILL 改进 patch ✅**
