# Phase 1 执行计划 - SKILL 库完善与质量升级

> **启动日期**：2026-07-17  
> **目标版本**：v0.2.0.2 ~ v0.2.1  
> **状态**：🚀 启动中

---

## 📊 当前基线

- **SKILL 总数**：130 个 (预期 143，差 13 个)
- **完成度**：85% (目标 95%+)
- **工具数**：518 个 Kali Linux 工具
- **标准**：Anthropic Agent Skills Open Standard

---

## 🎯 Task 1.1: SKILL 全量质量审查

### 第一步：生成完整审查报告

```bash
# 运行完整的质量检查并生成报告
cd ~/code/kali-claw-en

# 检查所有 SKILL 的前言完整性
python3 validation/update-skill-standard.py --repair --dry-run > audit-draft.txt

# 生成缺失项目清单
find skills -name "SKILL.md" -exec grep -L "^name:" {} \; > missing-frontmatter.txt

# 统计防御视角完成率
find skills -name "SKILL.md" -exec grep -l "## Defense Perspective" {} \; | wc -l
# 结果应该是现有数字，然后统计缺失数
find skills -name "SKILL.md" | wc -l
```

### 第二步：逐个审查高优先级 SKILL

**优先级排序**（按使用频率和实战价值）：

| 优先级 | SKILL | 理由 | 预期工作量 |
|--------|-------|------|-----------|
| P0 | Web Security | 最高频使用 (XSS/SQLi/SSRF/Auth) | 高 |
| P0 | Network Penetration | 标准渗透流程 | 高 |
| P0 | Post-Exploitation | 实战必备 | 中 |
| P1 | OSINT | 信息收集基础 | 中 |
| P1 | Password Attack | 通用技能 | 中 |
| P1 | Privilege Escalation | 权限提升 | 高 |
| P1 | Phishing & Social Engineering | 初期入口 | 中 |
| P1 | API Security | 现代应用必备 | 中 |
| P1 | Cloud Security | 云化趋势 | 中 |
| P1 | Container Security | Docker/K8s | 中 |

### 第三步：补齐缺失内容

每个高优先级 SKILL 需要检查：

- [ ] YAML 前言完整（name, description, compatibility, allowed-tools, metadata）
- [ ] ## Summary 存在且简洁（2-3 句）
- [ ] ## Core Tools 列表完整（至少 5 个）
- [ ] ## Methodology 步骤清晰（5-8 步）
- [ ] ## Defense Perspective 已补齐（关键缺失项）
- [ ] ## Practical Steps 详细可行
- [ ] payloads.md 至少 10 个 PoC
- [ ] test-cases.md 符合 AAA 模式（5-8 个）
- [ ] guides/ 目录（可选但推荐）

### 输出物

**生成时间线**：
- [ ] 2026-07-18 中午：完成缺失项目清单（missing-items.json）
- [ ] 2026-07-19 下午：完成修复优先级表（fix-priority.json）
- [ ] 2026-07-22：完成审查报告（audit-report.md）

**输出文件**：
```
kali-claw-en/
├── AUDIT_REPORT_2026-07-22.md          # 完整审查报告
├── missing-items.json                   # 缺失项清单 {skill: [missing_fields]}
├── fix-priority.json                    # 修复优先级和预估工作量
└── HIGH_PRIORITY_SKILLS.md             # 高优先级 SKILL 清单 + 执行计划
```

---

## 🛠️ Task 1.2: 高优先级 SKILL 补齐

### 补齐流程（per SKILL）

以 `web-security` 为例：

```bash
cd ~/code/kali-claw-en/skills/web-security

# 1. 检查前言
head -20 SKILL.md

# 2. 检查缺失的 ## 节点
grep "^## " SKILL.md

# 3. 补齐内容（如果缺失 Defense Perspective）
cat >> SKILL.md << 'EOF'

## Defense Perspective

### 防守者的视角
- Web 应用防火墙 (WAF) 规则配置
- 输入/输出验证和净化
- CSRF token 和 SameSite cookie
- 内容安全策略 (CSP)
- 数据加密和传输安全

### 检测方法
- 异常流量模式（扫描工具特征）
- SQL 注入检测（参数异常、注释字符）
- XSS 检测（HTML 实体转义、脚本标签）
- 文件包含检测（../、文件协议）

### 响应步骤
1. 禁用易受攻击的功能
2. 修复代码中的漏洞
3. 更新 WAF 规则
4. 审计日志发现异常
5. 对用户进行安全教育
EOF

# 4. 验证标准
python3 ../validation/update-skill-standard.py --skill web-security

# 5. 提交
git add SKILL.md payloads.md test-cases.md
git commit -m "refactor: enhance web-security SKILL with defense perspective & tools update"
```

### 补齐周期

- **Week 1**（7.22-7.26）：P0 SKILL（Web/Network/Post-Exploitation）
- **Week 2**（7.29-8.02）：P1 SKILL 前 5 个
- **Week 3**（8.05-8.09）：P1 SKILL 后 5 个 + 遗漏修复

### 完成标准

- [ ] 15 个 SKILL 完成度达 95%+
- [ ] 所有必填字段齐全
- [ ] 防御视角每个都有
- [ ] payloads 和 test-cases 符合标准

---

## 🚀 Task 1.3: 新 SKILL 扩展 (7+ 个)

### 新 SKILL 候选

**新增需求分析**：当前 130 个 SKILL 的空白点：

```bash
# 统计各 domain 下的 SKILL 数
find skills -type d -maxdepth 1 | sed 's/.*\///' | sort | uniq -c

# 按类别统计
grep -h "^domain:" skills/*/SKILL.md | sort | uniq -c | sort -rn
```

**候选列表**（按优先级）：

| # | SKILL 名称 | 原因 | 工作量 |
|---|-----------|------|--------|
| 1 | **IoT Security Pentest** | Wave 12 计划；物联网设备渗透 | 中 |
| 2 | **Blockchain Smart Contract Audit** | DeFi 漏洞分析 | 高 |
| 3 | **Threat Intelligence Platform Integration** | TI 运营必备 | 中 |
| 4 | **Malware Reverse Engineering Advanced** | 高级样本分析 | 高 |
| 5 | **Red Team Infrastructure** | C2 搭建、代理隧道 | 高 |
| 6 | **Data Exfiltration & Anti-DLP** | 数据外泄技术 | 中 |
| 7 | **Advanced Post-Exploitation** | 横向移动、权限维持 | 中 |

### 创建流程

```bash
cd ~/code/kali-claw-en

# 模板
mkdir -p skills/iot-security-pentest
cd skills/iot-security-pentest

# 1. 生成 SKILL.md 框架
cat > SKILL.md << 'EOF'
---
name: iot-security-pentest
description: Comprehensive IoT device penetration testing methodology, tools, and techniques
compatibility:
  - kali-linux
  - arm64
  - x86_64
allowed-tools:
  - nmap
  - hydra
  - wireshark
  - firmwalker
  - binwalk
metadata:
  domain: IoT Security
  difficulty: advanced
  time-estimate: "2-4 hours per target"
  version: "1.0.0"
  last-update: "2026-07-17"
---

## Summary

IoT device penetration testing covers network reconnaissance, firmware extraction and analysis, default credential exploitation, firmware flashing, and post-exploitation persistence. This SKILL focuses on ARM/MIPS-based IoT devices commonly found in networks.

## Core Tools

- **nmap** - Network enumeration and service detection
- **hydra** - Credential brute-forcing
- **binwalk** - Firmware analysis and extraction
- **firmwalker** - Firmware static analysis
- **qemu** - Firmware emulation and execution
- **openocd** - JTAG debugging
- **wireshark** - Network traffic analysis
- **burp-suite** - Web interface testing

## Methodology

1. **Asset Discovery** - Scan network for IoT devices
2. **Service Enumeration** - Identify open ports, services, firmware version
3. **Default Credential Check** - Test common default credentials
4. **Firmware Extraction** - UART, JTAG, or web-based firmware download
5. **Firmware Analysis** - Strings, binwalk, IDA Pro for vulnerability search
6. **Web Interface Testing** - Exploit auth bypass, RCE, information disclosure
7. **Hardware Attack** - JTAG/UART debugging, memory extraction
8. **Persistence** - Establish foothold (backdoor, modified firmware)

## Core Tools & Techniques

[details...]

## Practical Steps

[step-by-step implementation...]

## Defense Perspective

[防守视角...]

EOF

# 2. 生成 payloads.md
cat > payloads.md << 'EOF'
# IoT Security Pentest - Payloads

## UART Communication

\`\`\`bash
# 连接 UART 终端
picocom /dev/ttyUSB0 -b 115200

# 常见默认密码
root/root
admin/admin
admin/12345
root/123456
\`\`\`

...
EOF

# 3. 生成 test-cases.md
cat > test-cases.md << 'EOF'
# IoT Security Pentest - Test Cases

## Test Case 1: Default Credentials on Web Interface

**Arrange:**
- IoT device deployed with factory defaults
- Web interface accessible on port 80/443

**Act:**
- Try common default credentials (admin/admin, root/root)

**Assert:**
- Login succeeds → **VULN**
- Login failed → **OK**

...
EOF

# 4. 验证
python3 ../validation/update-skill-standard.py --skill iot-security-pentest
```

### 新 SKILL 周期

- **Week 2-3**（7.29-8.09）：并行创建 7 个新 SKILL
- **Week 4**（8.12-8.16）：测试、整合、最终审查

### 完成标准

- [ ] 7 个新 SKILL 创建完成
- [ ] 总 SKILL 数达到 150+
- [ ] 所有必填字段齐全
- [ ] payloads.md 和 test-cases.md 规范

---

## 📚 Task 1.4: 文档升级与参考输出

### 输出物列表

| 文档 | 描述 | 用途 | ETA |
|------|------|------|-----|
| **SKILL_HANDBOOK.md** | 143+ SKILL 使用手册 | 用户快速查阅 | 8.16 |
| **QUICK_REFERENCE.md** | 快速参考卡片 | 实战查询 | 8.16 |
| **TOOLS_LIFECYCLE.md** | 工具版本管理 | 维护跟踪 | 8.16 |
| **SKILL_INDEX.json** | 机器可读索引 | 集成查询 | 8.16 |
| **DOMAIN_MATRIX.md** | SKILL vs Tools 热力图 | 覆盖分析 | 8.16 |
| **CHANGELOG.md** | v0.2.0.2 更新说明 | 发布说明 | 8.20 |

### 生成脚本

```bash
# docs/generate-handbook.py
python3 docs/generate-handbook.py \
  --input skills/ \
  --output SKILL_HANDBOOK.md \
  --format markdown

# docs/generate-index.py
python3 docs/generate-index.py \
  --input skills/ \
  --output SKILL_INDEX.json \
  --format json

# docs/generate-matrix.py
python3 docs/generate-matrix.py \
  --input skills/ \
  --output DOMAIN_MATRIX.md \
  --tool-count 518
```

---

## ⚙️ Task 1.5: CI/CD 和自动化优化

### 新脚本清单

```
validation/
├── skill-lint.py              # SKILL 代码检查
├── validate-payloads.py       # Payload 验证
├── validate-testcases.py      # Test-case 验证
├── generate-skill-index.py    # 索引生成
└── skill-quality-report.py    # 质量报告
```

### GitHub Actions 工作流

```yaml
# .github/workflows/skill-quality.yml
name: SKILL Quality Check
on: [pull_request, push]

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run SKILL linter
        run: python3 validation/skill-lint.py --all
      - name: Validate payloads
        run: python3 validation/validate-payloads.py
      - name: Generate report
        run: python3 validation/skill-quality-report.py --output report.md
```

---

## 📈 进度跟踪

```
Phase 1 Timeline (2026-07-22 ~ 2026-08-20)
│
├─ Week 1 (7.22-7.26)
│  ├─ 1.1: Complete audit report ✓
│  ├─ 1.2: Fix P0 SKILL (Web/Network/Post-Expl)
│  └─ Status: Baseline established
│
├─ Week 2 (7.29-8.02)
│  ├─ 1.2: Fix P1 SKILL (1-5)
│  ├─ 1.3: Create new SKILL (1-4)
│  └─ Status: Major improvements in progress
│
├─ Week 3 (8.05-8.09)
│  ├─ 1.2: Fix P1 SKILL (6-10) + missing fixes
│  ├─ 1.3: Create new SKILL (5-7) + testing
│  └─ Status: Core expansion complete
│
├─ Week 4 (8.12-8.16)
│  ├─ 1.4: Generate all documentation
│  ├─ 1.5: Set up CI/CD pipelines
│  └─ Status: Final polish & automation
│
└─ Week 5 (8.19-8.23)
   ├─ Final QA and validation
   ├─ Release v0.2.0.2 ~ v0.2.1
   └─ Status: ✅ PHASE 1 COMPLETE
```

---

## 🎓 关键约定

### SKILL 标准（必须遵守）

**YAML 前言必填字段**：
```yaml
---
name: <kebab-case-name>
description: <one-line-summary>
compatibility: [kali-linux, arm64, ...]
allowed-tools: [tool1, tool2, ...]
metadata:
  domain: <category>
  difficulty: beginner|intermediate|advanced
  time-estimate: "X-Y hours"
  version: "X.Y.Z"
  last-update: "YYYY-MM-DD"
---
```

**必需的 ## 节点**：
- Summary
- Core Tools
- Methodology
- Practical Steps
- Defense Perspective (关键)

**payloads.md 格式**：
- 至少 10 个 PoC
- 代码块带语言标记 (bash/python/sql/etc)
- 每个 payload 附带说明

**test-cases.md 格式**：
- AAA 模式 (Arrange-Act-Assert)
- 5-8 个测试用例
- 每个测试都有预期结果

### 提交约定

```bash
# 修复已有 SKILL
git commit -m "refactor(<skill-name>): <description>

- Added defense perspective
- Updated tool versions
- Enhanced payloads"

# 新增 SKILL
git commit -m "feat: add <skill-name> SKILL

- Covers <main-technique>
- 12 payloads, 6 test cases
- Tools: <tool1>, <tool2>, ..."
```

---

**执行负责人**：团队  
**预期交付**：2026-08-23  
**版本号**：v0.2.0.2 ~ v0.2.1
