# kali-claw v0.3.9.1 版本说明 — F-4 清偿：Usability 满分 139A 🏁

> **版本编号**：v0.3.9.1（micro patch）
> **发布日期**：2026 年 11 月 16 日
> **版本类型**：v0.3.9 P2 收尾（F-4 占位符清理）
> **上一版本**：v0.3.9（2026-11-16，P1 清偿三轴全绿）

---

## 一、F-4：automotive-vehicle-security 占位符 15 → 0

| 处置 | 明细 |
|------|------|
| **验证器 DBC 感知**（误报修正）| DBC 语法行（`BU_/BO_/SG_/CM_/VAL_/BA_`，含注释形态）中的 `XXX` 是 Vector DBC 规范的 sender/unknown-node 字段，非占位符——12 处误报排除 |
| 真实占位修复 ×4 | Toyota IVI 包名通配 `-XXXX` → 实例后缀；3 处伪 CVE 引用（`CVE-2022-XXXXX` RPMB / `CVE-2018-XXXX` SecOC / `CVE-2017-XXXXX` STM32F4）→ 按 CVE 纪律改写为不编号的类别描述（STM32F4 标注 LimitedResults 2020 class）|

## 二、终态：三轴 + 占位符全绿

| 指标 | 值 |
|------|-----|
| Usability | **139 A / 0 B / 0 C（满分，历史首次）** |
| Reliability | 139 A / 0 B / 0 C |
| bash / outdated / placeholders / stale | **0 / 0 / 0 / 0** |
| 验证器 exit | **0** |
| skill-lint | 0/0/139 |

## 三、版本签名

```
版本编号：v0.3.9.1
发布日期：2026-11-16
版本类型：F-4 微补丁（Usability 139A 满分达成）
上一版本：v0.3.9
F-4：15 → 0（12 DBC 误报修正 + 4 真实占位修复，其中 1 处为计数重合）
全绿矩阵：bash/outdated/placeholder/stale = 0；Usability+Reliability 双 139A
```

**kali-claw 团队**
**2026 年 11 月 16 日**
