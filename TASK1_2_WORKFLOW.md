# Task 1.2 工作流程与日常执行规范

> **创建日期**：2026-07-18 (Saturday)  
> **适用范围**：Task 1.2 Phase 1 + Phase 2 执行期间  
> **基础数据**：SKILL_REMEDIATION_LIST.json

---

## 📅 每日执行循环

### Morning Standup (08:00-08:15, 15 min)

```bash
cd ~/code/kali-claw-en

# 1. 检查 git 状态
git status
git log --oneline -5

# 2. 检查当前 branch (应为 task1.2-enhancement 或 phase1/skill-audit)
git branch --show-current

# 3. 打开当日工作清单
cat HIGH_PRIORITY_WORKPLAN.md | grep -A 5 "Day $(date +%u)"

# 4. 确认今日目标 SKILLs
python3 -c "
import json
data = json.load(open('SKILL_REMEDIATION_LIST.json'))
print(f'今日待处理 P0/P1 SKILLs:')
for s in data['high_priority']:
    if s['est_hours'] > 0.5:  # 需要重点处理的
        print(f\"  - {s['skill']}: {s['est_hours']}h, issues={s['issues']}\")
"
```

### Core Work Loop (每个 SKILL)

```
For each SKILL in today's list:
  ├── Step 1: Read current state (5 min)
  │   └── cat skills/<skill>/SKILL.md
  │
  ├── Step 2: Identify gaps (5 min)
  │   ├── Check issues from SKILL_REMEDIATION_LIST.json
  │   └── Verify against Definition of Done
  │
  ├── Step 3: Apply fixes (20-40 min)
  │   ├── Fix translation residue (if any)
  │   ├── Standardize Defense Perspective as table
  │   ├── Add Detection Methods (if missing)
  │   ├── Add Defense Evasion Techniques (if missing)
  │   ├── Update payloads.md with 2026 vectors
  │   └── Bump version: 0.1.18 → 0.2.0.2
  │
  ├── Step 4: Validate (5 min)
  │   └── python3 validation/update-skill-standard.py --skill <name>
  │
  └── Step 5: Commit (5 min)
      └── git commit -m "refactor(<skill>): polish defense + bump to v0.2.0.2"
```

### Daily Wrap-up (17:00-17:30, 30 min)

```bash
# 1. 验证所有今日 commits
git log --oneline --since="08:00"

# 2. 运行验证脚本
python3 validation/update-skill-standard.py --stats > /tmp/daily_stats.txt
diff BASELINE_AUDIT_DATA.txt /tmp/daily_stats.txt

# 3. 更新进度跟踪
python3 -c "
import json
data = json.load(open('SKILL_REMEDIATION_LIST.json'))
# (Update completion_pct for completed skills)
"

# 4. 记录当日报告
cat >> memory/$(date +%Y-%m-%d).md << EOF
## Task 1.2 Day $(date +%u) Report

### Completed SKILLs
- [list]

### Issues encountered
- [list]

### Hours invested: X
### Next day plan: [list]
EOF

# 5. Push to remote (optional)
git push origin phase1/skill-audit 2>/dev/null || true
```

---

## ✅ Definition of Done (单 SKILL 完成标准)

每个 SKILL 必须满足全部以下条件才能视为完成：

### 结构完整性
- [ ] YAML 前言完整 (name, description, version, compatibility, allowed-tools, metadata)
- [ ] `## Summary` 存在且 2-3 句
- [ ] `## Description` 详细说明 (≥200 words)
- [ ] `## Core Tools` 至少 5 个工具，含用途说明
- [ ] `## Methodology` 至少 5 步
- [ ] `## Practical Steps` 详细可执行

### Defense 三件套
- [ ] `### Defense Perspective` 表格化 (≥5 防御层)
- [ ] `## Detection Methods` 存在且 ≥3 检测手段
- [ ] `## Defense Evasion Techniques` 存在且 ≥3 绕过技术

### 配套文件
- [ ] `payloads.md` ≥ 500 lines 或 60 sections
- [ ] `test-cases.md` ≥ 8 tests (AAA 格式)
- [ ] `guides/` ≥ 3 deep-dive 文档

### 质量标准
- [ ] YAML `version: "0.2.0.2"`
- [ ] 无中英混排翻译残留
- [ ] 通过 `update-skill-standard.py --skill <name>` 验证
- [ ] Markdown 格式规范 (无空 link、无破损 table)

---

## 🛠️ SKILL 改进模板

### Template A: Defense Perspective 表格化

将以下 bullet 格式：

```markdown
### Defense Perspective

- **网络分段** - 通过 VLAN 和子网隔离限制攻击者横向移动范围
- **IDS/IPS** - 部署 Snort/Suricata 检测异常流量模式和扫描行为
```

转换为表格：

```markdown
### Defense Perspective

| Defense Layer | Measures | Key Points |
|---------------|----------|------------|
| **Network Segmentation** | VLAN + subnet isolation + microsegmentation | Limit lateral movement scope; default-deny between zones |
| **IDS/IPS** | Snort/Suricata + signature + anomaly detection | Deploy at perimeter + critical segments; tune for low FP |
| **Port Security** | Disable unused ports + firewall ingress/egress rules | Follow least-privilege; review quarterly |
```

### Template B: Detection Methods 章节

```markdown
## Detection Methods

### Network-level Indicators
- **Port scan patterns**: nmap-typical patterns (SYN without ACK, XMAS tree)
- **Service fingerprinting**: Repeated connections to multiple ports from same source
- **Anomalous protocols**: Unusual SMB/RPC traffic outside business hours

### Host-level Indicators
- **Process anomalies**: Unexpected nmap/wireshark binary execution
- **Network connections**: New outbound connections to unknown IPs
- **Log gaps**: Suspicious gaps in /var/log/auth.log or event log

### SIEM Detection Rules
- **Sigma rule**: `sigma/rules/network/net_scan_pattern.yml`
- **ELK query**: `event.action:"connection_attempt" AND source.port:<1024 GROUP BY destination.ip`
```

### Template C: Defense Evasion Techniques

```markdown
## Defense Evasion Techniques

### IDS/IPS Evasion
- **Fragmented packets**: nmap `-f` flag splits probe packets
- **Decoy scans**: nmap `-D RND:10` mixes real source with decoys
- **Timing manipulation**: nmap `-T0` (paranoid) spreads probes over time
- **Custom payloads**: Modify signature to avoid pattern matching

### Logging Evasion
- **Log injection**: Modify `/var/log/wtmp` to remove records
- **Time-stomping**: Change file timestamps with `timestomp`
- **Clear specific events**: Use `wevtutil` to delete specific Event IDs

### Tool Obfuscation
- **Binary renaming**: Rename nmap binary to avoid process-name detection
- **Static compilation**: Avoid dynamic library dependencies
- **Memory-only execution**: Use `memfd_create()` to avoid disk artifacts
```

---

## 🔧 Commit Message 规范

### Type 前缀
- `refactor(skill-name):` - 改进现有 SKILL (主要用于 Task 1.2)
- `feat(skill-name):` - 新增 SKILL (用于 Task 1.3)
- `fix(skill-name):` - 修复 SKILL bug
- `docs:` - 文档更新
- `chore:` - 维护性变更

### 标准格式

```
refactor(<skill-name>): polish defense sections and bump to v0.2.0.2

- Standardize Defense Perspective as table format (5+ layers)
- Add Detection Methods section (3+ indicators)
- Add Defense Evasion Techniques section
- Update payloads.md with 2026 attack vectors
- Fix translation residue (mixed CN/EN terms)
- Bump version: 0.1.18 → 0.2.0.2

Addresses: SKILL_REMEDIATION_LIST.json high_priority
```

### 范例

```bash
git commit -m "$(cat <<'EOF'
refactor(network-pentest): fix translation residue and standardize defense

- Fix 35 instances of mixed CN/EN words in Hacker Laws and Defense Perspective
- Convert Defense Perspective bullets to structured table (6 layers)
- Expand Detection Methods with SIEM Sigma rules
- Expand Defense Evasion Techniques with timing manipulation
- Update tool versions: nmap 7.95, wireshark 4.2.5, bettercap 2.40
- Bump SKILL version: 0.1.18 → 0.2.0.2

Quality gate: passes update-skill-standard.py validation
EOF
)"
```

---

## 📊 进度追踪机制

### 每日进度图表 (Manual)

```markdown
## Task 1.2 Phase 1 Progress

### Day 1 (2026-07-20) - P0 SKILLs
- [x] network-pentest (1.5h) - DONE
- [x] post-exploitation (1.0h) - DONE
- [x] web-xss (0.5h) - DONE
- [x] web-sqli (0.5h) - DONE
**Velocity**: 4 SKILLs/day, 3.5h

### Day 2 (2026-07-21) - P1 SKILLs (4)
- [ ] web-ssrf
- [ ] web-auth-bypass
- [ ] api-security
- [ ] password-attack

### Cumulative
- Completed: 4/15 (26.7%)
- Remaining: 11
- Est remaining hours: 5.5h
```

### 自动化指标收集

```bash
# 每日运行：生成进度对比
python3 << 'EOF'
import json
from pathlib import Path
from datetime import datetime

data = json.load(open('SKILL_REMEDIATION_LIST.json'))
today = datetime.now().strftime('%Y-%m-%d')

# Count completed (based on git log)
import subprocess
log = subprocess.check_output(
    ['git', 'log', '--since=midnight', '--oneline', '--grep=refactor']
).decode()

completed_skills = []
for line in log.split('\n'):
    if 'refactor(' in line:
        skill = line.split('refactor(')[1].split(')')[0]
        completed_skills.append(skill)

# Generate progress report
report = {
    'date': today,
    'completed_skills': completed_skills,
    'count': len(completed_skills),
    'target': 15,
    'pct_complete': round(len(completed_skills) / 15 * 100, 1),
}

print(json.dumps(report, indent=2))
EOF
```

---

## ⚠️ 风险与应对

| 风险 | 概率 | 影响 | 应对策略 |
|------|------|------|---------|
| 翻译残留超出预期 | 中 | 单 SKILL +1h | 优先处理 P0；P1 按时间窗限制 |
| Defense 内容质量不一 | 中 | 表格化耗时 | 使用模板 A/B/C 标准化 |
| 工具版本查询困难 | 中 | 部分 SKILL 延迟 | 预生成 KALI_TOOLS_BASELINE_2026_07.md |
| Payload 创作疲劳 | 高 | 创意枯竭 | 复用已有 payloads，增量补充 |
| Commit message 不规范 | 低 | 历史难追溯 | 严格遵守 §Commit Message 规范 |

### 异常处理流程

```
If 单 SKILL 工时 > 2h:
  → 暂停，记录 root cause
  → 评估是否需要拆分工作
  → 决定 skip or persist

If 验证脚本失败:
  → 不 commit
  → 检查失败原因 (通常是 YAML 格式)
  → 修复后重新验证

If 当日未完成目标:
  → 记录 carry-over
  → 次日优先处理
  → 不影响下一日新计划
```

---

## 📁 文件命名规范

```
kali-claw-en/
├── skills/<skill-name>/
│   ├── SKILL.md                          # 主文件
│   ├── payloads.md                       # 攻击载荷
│   ├── test-cases.md                     # 测试用例
│   └── guides/                           # 深度指南
│       ├── 01-<topic>.md                 # 编号命名
│       └── 02-<topic>.md
│
├── memory/YYYY-MM-DD.md                  # 每日工作日志
│
├── TASK1_2_PREPARATION.md                # 准备阶段计划
├── HIGH_PRIORITY_WORKPLAN.md             # 15 SKILL 改进计划
├── SKILL_REMEDIATION_LIST.json           # 全量补齐清单
├── TASK1_2_WORKFLOW.md                   # 本文件
├── KALI_TOOLS_BASELINE_2026_07.md        # 工具版本基线
└── TASK1_3_FRAMEWORK.md                  # Task 1.3 框架
```

---

## 🚀 Phase 切换检查清单

### Phase 1 → Phase 2 切换 (2026-07-24 → 2026-07-25)

切换前必须确认：

- [ ] 15 个高优先级 SKILL 全部完成
- [ ] 平均完成度 ≥ 98%
- [ ] 所有 commits 通过验证
- [ ] HIGH_PRIORITY_WORKPLAN.md 状态更新
- [ ] memory/ 日志记录 Phase 1 完成总结

### Phase 2 → Task 1.3 切换 (2026-07-25)

切换前必须确认：

- [ ] 17 个缺失 Defense Perspective 的 SKILL 处理方案明确
- [ ] Task 1.3 框架文档就绪
- [ ] Phase 2 时间窗 (7.25-8.01) 可用

---

## 📞 沟通与升级

### 自主决策范围
- 单 SKILL 改进方法选择 (表格 vs bullet)
- Payload 示例选择
- 工具版本选择 (主版本 vs LTS)
- Translation 修复策略

### 需要升级的情况
- 单 SKILL 工时 > 3h → 暂停，标记 blocked
- 验证脚本持续失败 → 检查脚本本身
- 工具版本查询不可行 → 跳过版本 bump
- 发现 SKILL 主题与 kali-claw 定位不符 → 标记 deprecation candidate

---

## 📚 相关文档

- [HIGH_PRIORITY_WORKPLAN.md](./HIGH_PRIORITY_WORKPLAN.md) - 15 SKILL 详细改进计划
- [SKILL_REMEDIATION_LIST.json](./SKILL_REMEDIATION_LIST.json) - 全量补齐清单
- [TASK1_2_PREPARATION.md](./TASK1_2_PREPARATION.md) - 周末准备阶段状态
- [PHASE1_EXECUTION.md](./PHASE1_EXECUTION.md) - Phase 1 总执行计划

---

**最后更新**：2026-07-18  
**适用周期**：2026-07-20 ~ 2026-08-01 (Phase 1 + Phase 2)
