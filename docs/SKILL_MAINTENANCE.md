# SKILL 维护指南

> **版本**: v0.2.0.8 | **最后更新**: 2026-07-26

---

## 一、SKILL 创建 Checklist

创建新 SKILL 时，按以下步骤执行：

### 1. 目录结构

```
skills/<skill-name>/
├── SKILL.md          ← 必需
├── payloads.md       ← 必需
├── test-cases.md     ← 必需
└── guides/           ← 推荐（≥3 个深度指南）
    ├── 01-topic.md
    ├── 02-topic.md
    └── 03-topic.md
```

### 2. SKILL.md 必须包含

```yaml
---
name: <skill-name>                   # 必需，与目录名一致
description: "<2-3 句描述>"           # 必需
origin: kali-claw                     # 或 openclaw
version: "0.2.0.2"                   # 必需，当前基线
compatibility:                        # 必需
  - openclaw
  - claude-code
  - cursor
  - windsurf
allowed-tools:                        # 必需
  - Bash
  - Read
  - Write
  - Edit
  - WebSearch
  - WebFetch
metadata:                             # 必需
  domain: <domain>                    # 必需
  category: <category>
  tool_count: <N>
  guide_count: <N>
  mitre: "TXXXX-Name"
  owasp: "AXX:2021-Name"             # 如适用
  last_reviewed: "YYYY-MM-DD"         # 必需
  keywords:                           # 推荐
    - keyword1
    - keyword2
---
```

### 3. 必需章节（按顺序）

```markdown
# Skill: <名称>
## Summary
## Description
## Use Cases
## Core Tools (表格格式)
## Methodology
  ### Attack Chain (流程图)
  ### Defense Perspective (表格格式，≥5 层)
## Practical Steps
## Common Pitfalls
## Detection Methods              ← Defense Triple
## Defense Evasion Techniques     ← Defense Triple
## Hacker Laws
## Learning Resources
```

### 4. 质量门检查

创建后运行验证脚本：

```bash
# Lint 检查
python3 validation/skill-lint.py --skill <skill-name>

# Payloads 验证
python3 validation/validate-payloads.py --skill <skill-name>

# Test cases 验证
python3 validation/validate-testcases.py --skill <skill-name>

# 标准对齐
python3 validation/update-skill-standard.py --skill <skill-name>
```

---

## 二、SKILL 更新流程

### 1. 标准化升级（Phase 2 模式）

当需要将旧版本 SKILL 升级到 v0.2.0.2 标准：

1. **扫描当前状态**
   ```bash
   python3 validation/skill-lint.py --skill <skill-name>
   ```

2. **添加缺失章节**
   - 添加 `## Detection Methods`（含 SIEM 规则）
   - 添加 `## Defense Evasion Techniques`（≥3 类）
   - 表格化 `### Defense Perspective`

3. **版本升级**
   - `version: "0.2.0.2"`
   - `last_reviewed: "YYYY-MM-DD"`

4. **翻译残留清理**
   ```bash
   python3 -c "
   import re
   c = open('skills/<skill>/SKILL.md').read()
   matches = re.findall(r'[a-z][一-鿿]|[一-鿿][a-z]', c)
   print(f'Residue: {len(matches)}')
   "
   ```

5. **验证 + 提交**
   ```bash
   python3 validation/skill-lint.py --skill <skill-name>
   git add skills/<skill>/
   git commit -m "refactor(<skill>): standardize to v0.2.0.2"
   ```

### 2. 批量标准化

使用 Python 脚本批量处理多个 SKILL（参考 Phase 2 Batch 模式）：

```python
# 参见 /tmp/batch3_standardize.py 等模板
# 核心逻辑：version bump + last_reviewed + Detection/Evasion 插入
```

---

## 三、工具版本更新指南

### 1. 季度基线更新

```bash
# 扫描所有 SKILL 中的工具引用
python3 -c "
import re
from pathlib import Path
from collections import Counter

tools = Counter()
for f in Path('skills').rglob('SKILL.md'):
    content = f.read_text()
    # 提取工具引用
    for match in re.finditer(r'\|\s*\*\*(\w+)\*\*', content):
        tools[match.group(1).lower()] += 1

for tool, count in tools.most_common(30):
    print(f'{tool:30s} {count}')
"
```

### 2. 更新 KALI_TOOLS_BASELINE

参考 `KALI_TOOLS_BASELINE_2026_07.md` 格式更新工具版本。

### 3. 同步 SKILL.md 工具表格

更新 `## Core Tools` 和 `## Tool Comparison Matrix` 中的版本号。

---

## 四、Commit 规范

### 类型前缀

- `feat(skill-name):` — 新增 SKILL
- `refactor(skill-name):` — 改进现有 SKILL
- `fix(skill-name):` — 修复 SKILL bug
- `docs:` — 文档更新
- `chore:` — 维护性变更
- `ci:` — CI/CD 配置

### 示例

```bash
git commit -m "refactor(network-pentest): polish defense perspective and bump to v0.2.0.2

- Standardize Defense Perspective as table format
- Add Detection Methods section
- Add Defense Evasion Techniques section
- Fix translation residue
- Bump version: 0.1.18 → 0.2.0.2"
```

---

## 五、CI/CD 集成

### GitHub Actions 工作流

已有 `.github/workflows/skill-quality.yml`。每次 PR 自动运行：

- skill-lint.py（YAML + 章节 + 翻译残留）
- validate-payloads.py
- validate-testcases.py
- SKILL_INDEX.json 重新生成

### 本地验证

提交前运行：

```bash
# 全量验证
python3 validation/skill-lint.py
python3 validation/validate-payloads.py
python3 validation/validate-testcases.py
```

---

## 六、常见问题（FAQ）

### Q1: 翻译残留怎么清理？

```bash
# 查找残留
python3 -c "
import re
content = open('skills/<skill>/SKILL.md').read()
for i, line in enumerate(content.split('\n'), 1):
    if re.search(r'[a-z][一-鿿]|[一-鿿][a-z]', line):
        print(f'L{i}: {line[:100]}')
"
```

然后手动编辑修复每处残留。

### Q2: Defense Triple 怎么写？

参考已有 v0.2.0.2 SKILL（如 `skills/network-pentest/SKILL.md`）的格式：

- **Defense Perspective**: 表格化，≥5 行（防御层 + 措施 + 关键点）
- **Detection Methods**: 4-6 类（如 Server-side indicators + SIEM rules）
- **Defense Evasion Techniques**: 4-6 类（如 WAF Bypass + Stealth）

### Q3: 新 SKILL 需要多少 payloads？

最低要求：50 行 + 5 个代码块。

推荐：100+ 行 + 10+ 代码块 + 5+ section。

### Q4: SKILL 版本号怎么选？

- Phase 1 期间统一使用 `0.2.0.2`
- Phase 1 完成后（v0.2.1 release）使用 `0.2.1`
- 不再使用旧的 0.1.x 内部编号

### Q5: 如何处理 evidence/ 大文件？

- 不要 commit `*.tar.gz` 等大文件
- `.gitignore` 已配置阻止 CyberGym evidence 文件
- 如需保存，使用 Git LFS 或外部存储

---

_Last updated: 2026-07-26 (v0.2.0.8)_
