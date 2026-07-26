# Kali Linux 工具版本生命周期管理

> **版本**: v0.2.0.8 | **最后更新**: 2026-07-26

---

## 一、工具版本基线

kali-claw 维护 518 款 Kali Linux 安全工具的版本基线。最新基线参考 `KALI_TOOLS_BASELINE_2026_07.md`。

---

## 二、工具引用统计

kali-claw 137 个 SKILL 中，工具引用频次最高的 20 个：

| 排名 | 工具 | 引用次数 | 覆盖 SKILL 数 |
|------|------|---------|--------------|
| 1 | nmap | 818 | 57 |
| 2 | docker | 664 | 48 |
| 3 | openssl | 521 | 49 |
| 4 | tshark | 459 | 31 |
| 5 | strings | 424 | 63 |
| 6 | frida | 414 | 15 |
| 7 | kubectl | 399 | 15 |
| 8 | nuclei | 376 | 22 |
| 9 | hashcat | 250 | 20 |
| 10 | tor | 242 | 15 |
| 11 | impacket | 229 | 15 |
| 12 | tcpdump | 221 | 37 |
| 13 | socat | 202 | 14 |
| 14 | hydra | 198 | 21 |
| 15 | binwalk | 187 | 18 |
| 16 | ghidra | 184 | 20 |
| 17 | trivy | 184 | 13 |
| 18 | msfvenom | 176 | 5 |
| 19 | ffuf | 171 | 22 |
| 20 | shodan | 171 | 18 |

---

## 三、工具版本更新策略

### 1. 季度基线更新

每季度更新 `KALI_TOOLS_BASELINE_YYYY_MM.md`：

- 扫描所有 SKILL 中引用的工具
- 查询 Kali Linux 官方版本库
- 编译工具版本映射表
- 标记需要更新的工具

### 2. SKILL 工具版本同步

更新工具版本时同步更新 SKILL.md：

- `## Core Tools` 表格中的版本号
- `## Tool Comparison Matrix` 中的版本号
- `payloads.md` 中命令行示例的兼容性验证

### 3. 工具生命周期

| 状态 | 说明 | 处理方式 |
|------|------|---------|
| Active | 当前可用、维护中 | 正常使用 |
| Deprecated | 已弃用、有替代 | 标注替代工具，逐步迁移 |
| EOL | 已停止维护 | 标注替代工具，计划移除 |
| Removed | 已从 Kali 仓库移除 | 从 SKILL 中移除引用 |

---

## 四、工具供应链安全

### 1. 签名验证

- 使用 Kali 官方仓库（已签名）
- 验证第三方工具签名（GitHub Releases 等）
- 不从非可信源下载工具

### 2. 工具哈希审计

- 定期对比工具二进制哈希与官方发布
- 异常时降级使用、上报
- 重大安全事件时全量审计

### 3. 工具漏洞管理

- 监控工具 CVE（如 `nmap`、`wireshark` 自身的漏洞）
- 及时升级或限制使用范围
- 文档化已知风险

---

## 五、自定义工具集成

如需集成 kali-claw 未覆盖的工具：

1. 在 `skills/<skill>/SKILL.md` 的 `## Core Tools` 表格中添加
2. 在 `payloads.md` 中补充使用示例
3. 在 `TOOLS.md` 中更新工具库存
4. 在 `KALI_TOOLS_BASELINE_YYYY_MM.md` 中记录版本

---

_Last updated: 2026-07-26 (v0.2.0.8)_
