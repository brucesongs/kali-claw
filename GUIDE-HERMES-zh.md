# kali-claw 技能包迁移指南：从 OpenClaw 到 Hermes Agent

> 面向希望将 kali-claw 安全技能包迁移到 Hermes Agent 框架运行的安全工程师和渗透测试人员
> 最后更新：2026-05-18

---

## 一、迁移概述

### 1.1 为什么要迁移到 Hermes

Hermes Agent（由 Nous Research 开发，github.com/NousResearch/hermes-agent）是一个开源的、自进化的 AI 智能体框架。与 OpenClaw 相比，Hermes 提供了以下关键优势：

| 能力 | 说明 |
|------|------|
| **自学习闭环** | Hermes 会自动从经验中提炼知识，生成可复用的技能文件，无需人工维护 |
| **持久记忆** | 基于 SQLite + FTS5 全文检索 + LLM 摘要，比纯 Markdown 文件更高效 |
| **200+ 模型支持** | 通过 OpenRouter 接入 200+ 模型，也可直连 OpenAI、Anthropic、Gemini、Ollama |
| **多平台网关** | Telegram、Discord、Slack、WhatsApp、Signal、QQ、CLI 一键接入 |
| **MIT 开源协议** | 100k+ GitHub 星标（截至 2026 年 5 月），社区活跃 |

### 1.2 kali-claw 技能包的价值

kali-claw 的核心资产不是代码，而是经过系统化整理的 **安全知识库**：

- **49 个安全技能域** — 覆盖 Web 安全、网络渗透、密码攻击、云安全、AI 安全等
- **518 个 Kali Linux 工具知识库** — 从 nmap 到 sqlmap，从 burpsuite 到 metasploit
- **数千行实战载荷** — payloads.md 中按类型分类的即用型攻击载荷
- **结构化测试用例** — test-cases.md 中 TC-SXXX 格式的标准测试模板
- **12 条黑客法则** — 定义安全思维方式的底层原则

**核心观点**：迁移不是抛弃 OpenClaw，而是让 kali-claw 的安全知识在 Hermes 上也能使用。两个框架可以并行运行，共享同一份技能文件。

### 1.3 迁移策略总览

根据你的技术水平和控制需求，有三种迁移方式：

| 方式 | 适合人群 | 耗时 | 控制度 |
|------|---------|------|--------|
| **自动迁移** | 新手 / 想快速体验 | 5 分钟 | 低 |
| **半手动迁移** | 进阶用户 / 追求最佳效果 | 1-2 小时 | 中 |
| **纯手动迁移** | 需要完全控制每个细节 | 3-5 小时 | 高 |

**推荐路径**：先用自动迁移快速导入，再用半手动方式为每个技能创建引用式存根文件。

### 1.4 迁移前后对比表

| 组件 | OpenClaw (kali-claw) | Hermes Agent | 对应关系 |
|------|---------------------|--------------|---------|
| 智能体人格 | `SOUL.md` | `~/.hermes/personality.md` | 概念对应，格式不同 |
| 用户配置 | `USER.md` | `~/.hermes/config.yaml` (user 段) | 需手动映射 |
| 工作空间配置 | `AGENTS.md` | `~/.hermes/config.yaml` (agent 段) | 需手动映射 |
| 技能标签 | `IDENTITY.md` | 技能文件 YAML frontmatter tags | 格式不同 |
| 技能定义 | `skills/*/SKILL.md` (4 文件) | `~/.hermes/skills/skill-name.md` (1 文件) | 引用 |
| 记忆系统 | `memory/*.md` + `MEMORY.md` | SQLite + FTS5 检索 | 存储机制不同 |
| 工具知识库 | `TOOLS.md` | `~/.hermes/config.yaml` (tools 段) | 需手动配置 |
| 健康检查 | `HEARTBEAT.md` | `~/.hermes/config.yaml` (cron 段) | 需手动配置 |

---

## 二、环境准备

### 2.1 安装 Hermes Agent

```bash
# Linux / macOS / WSL2（推荐安装方式）
curl -fsSL https://get.hermes.dev | bash

# 验证安装
hermes --version
# 预期输出：hermes 2.x.x

# 查看配置目录
ls ~/.hermes/
# 预期输出：config.yaml  personality.md  skills/  memory/  tools/
```

### 2.2 检查 OpenClaw 工作空间

```bash
# 确认 OpenClaw 已安装
which openclaw || npm list -g openclaw

# 确认 kali-claw 工作空间存在
ls ~/.openclaw/workspace-kali-claw/
# 应看到：SOUL.md  AGENTS.md  USER.md  IDENTITY.md  MEMORY.md  TOOLS.md  HEARTBEAT.md  skills/  memory/  chronicle/

# 确认技能目录结构
ls ~/.openclaw/workspace-kali-claw/skills/ | head -20
# 应看到：api-security  web-sqli  network-pentest  osint  ...
```

### 2.3 备份

在执行任何迁移操作之前，**务必先备份原始数据**：

```bash
# 备份整个 kali-claw 工作空间
cp -r ~/.openclaw/workspace-kali-claw/ ~/kali-claw-backup-$(date +%Y%m%d)/

# 验证备份
diff -rq ~/.openclaw/workspace-kali-claw/ ~/kali-claw-backup-$(date +%Y%m%d)/ | head -5
# 应无输出，说明备份完整
```

---

## 三、方式一：自动迁移（推荐新手）

### 3.1 运行迁移命令

Hermes 内置了 OpenClaw 迁移工具，会自动检测 `~/.openclaw/` 目录下的所有工作空间：

```bash
# 第一步：预览模式（不执行任何操作，只显示将要迁移的内容）
hermes claw migrate --dry-run

# 输出示例：
# [DRY RUN] Found OpenClaw workspace: workspace-kali-claw
# [DRY RUN]   -> SOUL.md → personality.md
# [DRY RUN]   -> 49 skills detected
# [DRY RUN]   -> 156 memory files detected
# [DRY RUN]   -> API keys: 3 channels configured
# [DRY RUN] No changes made. Run without --dry-run to execute.
```

确认预览结果无误后，执行正式迁移：

```bash
# 第二步：正式迁移
hermes claw migrate

# 输出示例：
# [MIGRATE] Importing workspace-kali-claw...
# [MIGRATE]   ✓ SOUL.md → personality.md
# [MIGRATE]   ✓ 49 skills imported
# [MIGRATE]   ✓ 156 memory files imported to SQLite
# [MIGRATE]   ✓ 3 channel configurations preserved
# [MIGRATE] Migration complete. Run `hermes skills list` to verify.
```

### 3.2 自动迁移会做什么

| 步骤 | 操作 | 目标 |
|------|------|------|
| 1 | 扫描 `~/.openclaw/` 下所有工作空间 | 找到 kali-claw |
| 2 | 读取 `SOUL.md` | 转换为 `~/.hermes/personality.md` |
| 3 | 读取 `skills/*/SKILL.md` | 导入到 `~/.hermes/skills/` |
| 4 | 读取 `memory/*.md` + `MEMORY.md` | 导入到 SQLite 记忆库 |
| 5 | 读取网关配置 | 迁移 API 密钥和通道设置 |

### 3.3 自动迁移的局限

自动迁移很方便，但有以下已知局限：

| 局限 | 说明 | 影响 |
|------|------|------|
| 不生成引用路径 | `payloads.md`、`test-cases.md`、`guides/` 会被复制到附件目录，但 Hermes 不会原生理解它们 | 技能触发后只能看到 SKILL.md 的内容 |
| 不转换 ECC 编排格式 | OpenClaw 的 Sequential Pipeline / Batch Processing 等编排模式不会映射到 Hermes 的 workflow 格式 | 自动化编排功能缺失 |
| 不处理脚本工具 | `guides/` 中的 Python/Shell 脚本不会被注册为 Hermes 工具 | 脚本类工具无法被 Hermes 调用 |
| 标签和触发词缺失 | Hermes 技能需要 YAML frontmatter 中的 `tags` 和 `triggers`，自动迁移只生成基础标签 | 技能可能无法被正确触发 |

### 3.4 验证迁移结果

```bash
# 查看已导入的技能列表
hermes skills list

# 预期输出：49 个技能名称

# 搜索已导入的记忆
hermes memory search "SQL injection"
hermes memory search "penetration testing"

# 查看特定技能内容
hermes skills show web-sqli

# 测试技能是否能被触发
hermes chat "帮我检测一下这个网站的 SQL 注入漏洞"
```

---

## 四、方式二：半手动迁移（推荐进阶用户）

这是**推荐的迁移方式**：先用自动迁移获取基础数据，再手动创建引用式技能存根文件以充分利用 Hermes 的能力。

### 4.1 先运行自动迁移获取基础数据

```bash
# 预览
hermes claw migrate --dry-run

# 执行自动迁移（建立基础数据）
hermes claw migrate

# 验证基础数据已到位
hermes skills list
```

### 4.2 创建引用式 Hermes 技能文件（不修改 kali-claw）

**重要原则**：kali-claw 的 `skills/` 目录中的文件不会被修改、合并或转换。相反，Hermes 技能文件通过路径引用（`references`）指向 kali-claw 的原始文件，Hermes 在运行时读取这些引用文件的内容。

**引用关系**：

| kali-claw 文件 | Hermes 技能文件中的引用 | 说明 |
|---------------|------------------------|------|
| `SKILL.md` | `references` 路径条目 | 核心方法论和工具指引 |
| `payloads.md` | `references` 路径条目 | 按类型分类的即用型攻击载荷 |
| `test-cases.md` | `references` 路径条目 | 结构化测试用例模板 |
| `guides/*.md` | `references` 路径条目（可选） | 深度学习材料 |

**引用机制说明**：

- 在 Hermes 技能文件的 YAML frontmatter 中使用 `references` 字段列出 kali-claw 文件的绝对路径
- Hermes 在触发该技能时会自动读取引用的文件内容
- 当 kali-claw 的技能文件更新时（如添加新的载荷或测试用例），Hermes 自动获得最新内容，无需同步
- 两个框架并行运行，共享同一份知识源

### 4.3 引用式技能文件示例：web-sqli

以下是在 `~/.hermes/skills/` 目录下创建一个轻量级 Hermes 技能存根文件的示例。这个存根文件**不复制任何内容**，而是通过 `references` 字段指向 kali-claw 的原始文件。

**kali-claw 原始文件**（不会被修改）：

```
skills/web-sqli/
├── SKILL.md                      # 技能定义（220 行）
├── payloads.md                   # 载荷集合（304 行）
├── test-cases.md                 # 测试用例（202 行）
├── sqli-cross-db-guide.md        # 跨库注入指南
└── sqli-double-query-guide.md    # 双查询注入指南
```

**Hermes 存根文件**（`~/.hermes/skills/web-sqli.md`）：

```markdown
---
name: web-sqli
version: 1.0
tags: [sqli, sql-injection, web-security, database, union-injection, blind-injection, error-based, double-query, waf-bypass, cross-database]
triggers: ["sql injection", "sqli", "SQL注入", "union select", "blind injection", "error-based injection", "double query", "注入检测", "sqlmap", "order by", "extractvalue", "updatexml"]
references:
  - path: /path/to/kali-claw/skills/web-sqli/SKILL.md
  - path: /path/to/kali-claw/skills/web-sqli/payloads.md
  - path: /path/to/kali-claw/skills/web-sqli/test-cases.md
---

# SQL Injection

## When to Use

当出现以下场景时使用此技能：

1. **Web 应用渗透测试** — 检测和利用目标应用中的 SQL 注入漏洞，提取敏感数据库信息
2. **CTF 竞赛解题** — 快速识别 SQL 注入题目类型（回显/盲注/报错/过滤绕过），构造有效载荷
3. **安全代码审计** — 从防御角度审查应用数据库交互代码，识别不安全的查询构造
4. **WAF 绕过研究** — 针对过滤关键字、注释符、空格的场景构造编码/变换绕过载荷
5. **跨数据库注入** — 针对 MySQL、PostgreSQL、MSSQL、Oracle 数据库引擎的特定注入技术

## Instructions

读取引用的文件以获取完整的方法论、载荷和测试用例。

- **SKILL.md** → 分步方法论、工具指引和攻击链
- **payloads.md** → 按类型组织的即用型攻击载荷（UNION注入、报错注入、盲注、WAF绕过等）
- **test-cases.md** → 结构化测试程序（TC-S001 至 TC-S012）

### 攻击链

检测 → 指纹识别 → 利用 → 数据提取 → 权限提升

## Examples

详见 payloads.md 中按类型分类的载荷集合。

## Test Cases

详见 test-cases.md 中的 TC-S001 至 TC-S012 结构化测试模板。
```

**使用说明**：

1. 将 `references` 中的 `/path/to/kali-claw/` 替换为你的 kali-claw 工作空间的实际绝对路径
2. 保存到 `~/.hermes/skills/web-sqli.md`
3. Hermes 在触发此技能时会自动读取引用的文件内容
4. 当 kali-claw 更新技能文件时，Hermes 自动获得最新内容

### 4.4 批量创建引用式技能存根

以下 Shell 脚本会遍历 kali-claw 的 `skills/` 目录，为每个技能在 `~/.hermes/skills/` 下创建轻量级存根文件。**kali-claw 的原始文件不会被修改、合并或转换。** 存根文件仅通过 `references` 字段指向 kali-claw 的原始路径，Hermes 在运行时读取这些引用文件。

**前置条件**：确认 kali-claw 工作空间的绝对路径。

```bash
# 确认路径（示例）
KALI_CLAW_SKILLS="$HOME/.openclaw/workspace-kali-claw/skills"
# 或者如果 kali-claw 在当前项目目录下：
# KALI_CLAW_SKILLS="$PWD/skills"

ls "$KALI_CLAW_SKILLS" | head -10
# 应看到：api-security  web-sqli  network-pentest  osint  ...
```

**批量创建脚本**：

```bash
#!/usr/bin/env bash
#
# create-hermes-stubs.sh
#
# 在 ~/.hermes/skills/ 下为每个 kali-claw 技能创建引用式存根文件。
# 不会修改、合并或转换 kali-claw 的任何原始文件。
#
# 用法：
#   ./create-hermes-stubs.sh /path/to/kali-claw/skills
#   ./create-hermes-stubs.sh --dry-run /path/to/kali-claw/skills

set -euo pipefail

DRY_RUN=false
if [[ "${1:-}" == "--dry-run" ]]; then
    DRY_RUN=true
    shift
fi

SOURCE_DIR="${1:-$HOME/.openclaw/workspace-kali-claw/skills}"
TARGET_DIR="$HOME/.hermes/skills"

if [[ ! -d "$SOURCE_DIR" ]]; then
    echo "错误：源目录不存在: $SOURCE_DIR"
    exit 1
fi

mkdir -p "$TARGET_DIR"

created=0
skipped=0

for skill_dir in "$SOURCE_DIR"/*/; do
    skill_name="$(basename "$skill_dir")"

    # 跳过没有 SKILL.md 的目录
    if [[ ! -f "$skill_dir/SKILL.md" ]]; then
        echo "  [SKIP] $skill_name: SKILL.md 不存在"
        ((skipped++)) || true
        continue
    fi

    target_file="$TARGET_DIR/$skill_name.md"

    # 收集存在的文件作为 references
    refs=""
    for f in SKILL.md payloads.md test-cases.md; do
        if [[ -f "$skill_dir$f" ]]; then
            refs="${refs}  - path: ${skill_dir}${f}
"
        fi
    done

    # 添加 guides/ 目录下的文件（可选）
    if [[ -d "$skill_dir/guides" ]]; then
        for g in "$skill_dir/guides"/*.md; do
            if [[ -f "$g" ]]; then
                refs="${refs}  - path: ${g}
"
            fi
        done
    fi

    # 生成显示标题（web-sqli -> Web Sqli）
    title=$(echo "$skill_name" | tr '-' ' ' | awk '{for(i=1;i<=NF;i++) $i=toupper(substr($i,1,1)) tolower(substr($i,2))}1')

    if $DRY_RUN; then
        echo "  [DRY-RUN] 将创建: $target_file"
        echo "           引用: $(echo -n "$refs" | grep -c 'path:') 个文件"
        ((created++)) || true
    else
        cat > "$target_file" <<HEREDOC
---
name: $skill_name
version: 1.0
tags: [$skill_name]
triggers: ["$(echo "$skill_name" | tr '-' ' ')"]
references:
$(echo -n "$refs")
---

# $title

读取引用的文件以获取完整的方法论、载荷和测试用例。

- **SKILL.md** -> 技能定义、方法论和工具指引
- **payloads.md** -> 按类型组织的攻击载荷
- **test-cases.md** -> 结构化测试程序模板
HEREDOC
        echo "  [OK] 已创建: $target_file"
        ((created++)) || true
    fi
done

echo "----------------------------------------"
echo "完成！创建: $created, 跳过: $skipped"
if $DRY_RUN; then
    echo "这是预览模式，未写入任何文件。去掉 --dry-run 参数执行正式创建。"
else
    echo "kali-claw skills/ 目录未被修改。"
fi
```

**使用方法**：

```bash
# 预览模式（查看将创建哪些存根）
bash create-hermes-stubs.sh --dry-run ~/.openclaw/workspace-kali-claw/skills

# 正式创建
bash create-hermes-stubs.sh ~/.openclaw/workspace-kali-claw/skills

# 如果 kali-claw 在当前目录
bash create-hermes-stubs.sh ./skills
```

**创建后优化**：批量创建的存根文件使用通用 `tags` 和 `triggers`。建议逐个编辑，添加更精确的触发词和标签（参考 4.3 节中 web-sqli 的完整示例）。

```bash
# 列出已创建的存根
ls ~/.hermes/skills/

# 编辑某个技能的触发词
vim ~/.hermes/skills/web-sqli.md

# 验证格式
hermes skills validate --all
```

**关键特性**：此脚本：
- **不读取** kali-claw 技能文件的内容（只检查文件是否存在以构建 references 列表）
- **不复制** 任何内容到 Hermes 存根文件中
- **不修改** kali-claw 的任何文件
- 生成的存根文件只是轻量级的"指针"，指向 kali-claw 的原始文件

### 4.5 ECC 编排模式映射

kali-claw 中的 ECC（Enhanced Cognitive Choreography）编排模式可以映射到 Hermes 的 workflow 格式。这里只描述**概念映射关系**，不修改 kali-claw 中的任何编排定义。在 Hermes 侧创建独立的 workflow 配置文件即可。

| OpenClaw ECC 模式 | Hermes workflow | 说明 |
|-------------------|-----------------|------|
| Sequential Pipeline | `workflow: sequential` | 按顺序依次执行步骤 |
| Batch Processing | `workflow: parallel` | 多个步骤并行执行 |
| Learning Cycle | `workflow: iterative` | 迭代执行直到满足条件 |
| Watch Loop | `workflow: cron` | 定时循环执行 |

**Sequential Pipeline 示例**（在 `~/.hermes/workflows/` 中创建新文件）：

```yaml
# ~/.hermes/workflows/pentest-pipeline.yaml
name: pentest-pipeline
workflow: sequential
steps:
  - skill: recon-osint
    description: "信息收集"
  - skill: network-pentest
    description: "端口扫描"
  - skill: vulnerability-assessment
    description: "漏洞扫描"
  - skill: web-sqli
    description: "SQL 注入测试"
```

**Batch Processing 示例**：

```yaml
# ~/.hermes/workflows/batch-scan.yaml
name: batch-scan
workflow: parallel
steps:
  - skill: web-sqli
    description: "SQL 注入测试"
  - skill: web-xss
    description: "XSS 测试"
  - skill: web-ssrf
    description: "SSRF 测试"
  - skill: web-auth-bypass
    description: "认证绕过测试"
```

**Learning Cycle 示例**：

```yaml
# ~/.hermes/workflows/learning-cycle.yaml
name: tool-mastery
workflow: iterative
max_iterations: 10
exit_condition: "confidence > 0.9"
steps:
  - skill: continuous-learning
    description: "学习工具使用"
  - skill: verification-loop
    description: "验证掌握程度"
```

注意：以上 workflow 文件引用的是 Hermes 侧的技能存根文件（`~/.hermes/skills/`），这些存根通过 `references` 指向 kali-claw 的原始技能文件。整个过程中 kali-claw 的 `skills/` 目录保持不变。

### 4.6 验证生成的技能存根

```bash
# 验证单个技能
hermes skills validate web-sqli

# 运行技能测试
hermes skills test web-sqli

# 批量验证所有技能
hermes skills validate --all

# 批量测试所有技能
hermes skills test --all

# 查看技能触发效果
hermes chat "这个网站可能存在 SQL 注入，帮我检测一下"
```

---

## 五、方式三：纯手动迁移（完全控制）

如果你需要对每个技能的迁移进行精细控制，或者只迁移部分技能，可以使用纯手动方式。

### 5.1 创建 Hermes 技能目录

```bash
# 确保目录存在
mkdir -p ~/.hermes/skills/
mkdir -p ~/.hermes/tools/
mkdir -p ~/.hermes/workflows/
```

### 5.2 逐个创建技能存根（以 ai-security 为例）

以下是手动为 `ai-security` 技能创建 Hermes 引用式存根文件的完整步骤。**kali-claw 的原始文件不会被修改。**

**第一步：创建 YAML frontmatter 和 references**

```yaml
---
name: ai-security
version: 1.0
tags: [ai-security, llm, prompt-injection, jailbreak, model-extraction, rag-poisoning, adversarial-inputs, ai-supply-chain]
triggers: ["prompt injection", "jailbreak", "AI安全", "LLM安全", "model extraction", "RAG poisoning", "AI安全测试"]
references:
  - path: /path/to/kali-claw/skills/ai-security/SKILL.md
  - path: /path/to/kali-claw/skills/ai-security/payloads.md
  - path: /path/to/kali-claw/skills/ai-security/test-cases.md
---
```

**第二步：编写 When to Use 章节**

简要描述使用场景（不需要复制 SKILL.md 的完整内容）：

```markdown
## When to Use

1. **LLM API 安全评估** — 评估独立 LLM API 部署的提示注入、越狱、数据泄露和速率限制漏洞
2. **RAG 系统安全** — 测试检索增强生成管道的文档投毒、上下文污染、间接注入
3. **AI 集成应用测试** — 评估嵌入 LLM 的 Web 和移动应用的注入路径
4. **模型行为提取** — 通过系统化查询序列重建模型系统提示和能力边界
5. **AI 供应链评估** — 评估第三方模型权重、Hugging Face 模型、LangChain 插件的风险
6. **AI 治理审计** — 通过对抗性压力测试评估 AI 系统是否遵守安全策略
```

**第三步：编写 Instructions 章节**

说明引用文件的内容结构，引导 Hermes 按需读取：

```markdown
## Instructions

读取引用的文件以获取完整的方法论、载荷和测试用例。

- **SKILL.md** → 分步方法论、工具指引和攻击链
- **payloads.md** → 按类型组织的即用型攻击载荷（直接注入、越狱框架、间接注入等）
- **test-cases.md** → 结构化测试程序（TC-A001 至 TC-AXXX）
```

**第四步：编写 Examples 和 Test Cases 引导**

```markdown
## Examples

详见引用的 payloads.md 中按类型分类的载荷集合（直接提示注入、越狱框架、间接注入等）。

## Test Cases

详见引用的 test-cases.md 中的结构化测试模板。
```

**第五步：保存并验证**

```bash
# 保存到 Hermes 技能目录
vim ~/.hermes/skills/ai-security.md

# 验证格式
hermes skills validate ai-security

# 测试触发
hermes chat "帮我测试一下这个 LLM 应用的安全性"
```

### 5.3 迁移代理人格

SOUL.md 包含 12 条黑客法则和核心真理，需要转换为 Hermes 的 `personality.md` 格式：

**OpenClaw 原始格式**（SOUL.md）：

```markdown
## Hacker Laws

### 1. First Principles Thinking
Break problems down to the most fundamental facts...

### 2. Divergent Thinking First
Think of at least 3 solutions for every problem...

## Core Truths
- You are a penetration tester, not a chatbot
- ...
```

**Hermes 转换后格式**（`~/.hermes/personality.md`）：

```markdown
# kali-claw Personality

## Traits

- **好奇心驱动**：对未知系统和技术的强烈好奇心
- **实践优先**：理论是浅薄的，每个工具都必须亲自动手验证
- **系统思维**：不孤立地看问题，全局考虑整个攻击链
- **负责任的披露**：发现漏洞是为了让系统更安全

## Behavioral Rules

1. **第一性原理**：将问题分解为最基本的事实，不盲目跟随工具或经验
2. **发散思维**：每个问题至少想 3 种解决方案，然后选择最优的
3. **最小攻击面**：减少暴露就是减少风险，每个开放端口都是潜在入口
4. **纵深防御**：不依赖单层防御，确保单点故障不会导致全面崩溃
5. **最小权限**：只授予必要的访问权限，过度权限是攻击者的跳板
6. **假设已被入侵**：假设攻击者已在网络内部，建立检测和响应能力
7. **模糊不是安全**：安全来自设计和验证，而非隐藏
8. **信任但要验证**：不信任任何输入，验证一切
9. **信息渴望自由**：知识共享推动安全进步
10. **技能优于证书**：以能力评判，而非头衔
11. **最薄弱环节是人**：人员是安全链中最薄弱的环节
12. **墨菲安全法则**：如果可以被利用，就会被利用

## Boundaries

- 仅在授权范围内进行安全测试
- 不参与非法攻击或未经授权的渗透测试
- 发现漏洞后遵循负责任的披露流程
- 遵守当地法律法规和职业道德准则
```

### 5.4 迁移记忆系统

Hermes 的记忆系统基于 SQLite + FTS5 全文检索，比 OpenClaw 的纯 Markdown 文件更高效。

**方法一：使用 Hermes 内置命令**

```bash
# 导入单个记忆文件
hermes memory import --file ~/.openclaw/workspace-kali-claw/memory/2026-05-17.md

# 导入长期精炼知识
hermes memory import --file ~/.openclaw/workspace-kali-claw/MEMORY.md

# 仅导入记忆（不迁移其他内容）
hermes claw migrate --memory-only
```

**方法二：批量导入**

```bash
# 批量导入所有每日日志
for f in ~/.openclaw/workspace-kali-claw/memory/*.md; do
    echo "导入: $f"
    hermes memory import --file "$f"
done

# 导入月度编年史
for f in ~/.openclaw/workspace-kali-claw/chronicle/*/*.md; do
    echo "导入: $f"
    hermes memory import --file "$f"
done
```

**验证记忆导入**：

```bash
# 查看记忆统计
hermes memory stats

# 搜索测试
hermes memory search "SQL injection"
hermes memory search "nmap"
hermes memory search "渗透测试方法论"
```

### 5.5 迁移工具知识库

TOOLS.md 中记录了 518 个 Kali Linux 工具的学习进度和使用方法。在 Hermes 中，工具通过配置文件注册：

**方法一：手动配置**

```bash
# 配置 Kali 工具路径
hermes config set tools.kali_path /usr/bin

# 添加常用工具别名
hermes config set tools.aliases.sqlmap "/usr/bin/sqlmap"
hermes config set tools.aliases.nmap "/usr/bin/nmap"
hermes config set tools.aliases.burpsuite "/usr/bin/burpsuite"
```

**方法二：批量导入工具配置**

```bash
# 如果 kali-claw 运行在 Kali Linux 上
hermes config set tools.auto_detect true
hermes config set tools.search_path /usr/bin:/usr/sbin:/usr/local/bin
hermes tools scan
```

---

## 六、迁移后配置

### 6.1 配置 Kali 工具访问

根据你的部署方式选择对应配置：

```bash
# 方案 A：Hermes 直接运行在 Kali Linux 上（推荐）
hermes config set tools.kali_path /usr/bin
hermes config set tools.auto_detect true

# 方案 B：通过 SSH 远程访问 Kali 主机
hermes config set tools.remote_ssh user@kali-host
hermes config set tools.remote_ssh_key ~/.ssh/id_rsa

# 方案 C：通过 Docker 容器访问 Kali 工具
hermes config set tools.docker_image kalilinux/kali-rolling
hermes config set tools.docker_exec true
```

### 6.2 配置模型

Hermes 支持多种模型提供商，推荐使用 OpenRouter 获取最佳性价比：

```bash
# 方案 A：使用 OpenRouter（200+ 模型，推荐）
hermes config set model.provider openrouter
hermes config set model.name anthropic/claude-sonnet-4-6
hermes config set model.api_key $OPENROUTER_API_KEY

# 方案 B：直连 Anthropic
hermes config set model.provider anthropic
hermes config set model.name claude-sonnet-4-6
hermes config set model.api_key $ANTHROPIC_API_KEY

# 方案 C：直连 OpenAI
hermes config set model.provider openai
hermes config set model.name gpt-4o
hermes config set model.api_key $OPENAI_API_KEY

# 方案 D：使用本地 Ollama（免费，适合离线）
hermes config set model.provider ollama
hermes config set model.name llama3
hermes config set model.base_url http://localhost:11434
```

### 6.3 配置网关

Hermes 支持多种平台网关，可以同时启用多个：

```bash
# Telegram 网关
hermes gateway add telegram --token YOUR_TELEGRAM_BOT_TOKEN

# Discord 网关
hermes gateway add discord --token YOUR_DISCORD_BOT_TOKEN

# Slack 网关
hermes gateway add slack --token YOUR_SLACK_BOT_TOKEN --signing-secret YOUR_SIGNING_SECRET

# CLI 网关（默认，直接在终端使用）
hermes gateway start

# 查看已配置的网关
hermes gateway list

# 启用所有网关
hermes gateway start --all
```

### 6.4 验证完整迁移

```bash
# 1. 查看技能列表
hermes skills list
# 预期：49 个技能

# 2. 测试所有技能
hermes skills test --all

# 3. 查看记忆统计
hermes memory stats
# 预期：数百条记忆记录

# 4. 重建记忆索引（如果搜索不到）
hermes memory reindex

# 5. 健康检查
hermes health

# 6. 端到端测试
hermes chat "帮我用 nmap 扫描目标，然后用 sqlmap 测试 SQL 注入"
```

---

## 七、常见问题

### Q1：自动迁移报错"找不到 OpenClaw 工作空间"

**原因**：`~/.openclaw/` 目录不存在或路径不对。

**解决**：

```bash
# 检查 OpenClaw 安装
npm list -g openclaw

# 检查工作空间位置
openclaw agents list

# 如果工作空间在非标准位置，手动指定路径
hermes claw migrate --path /path/to/openclaw/workspace-kali-claw
```

### Q2：迁移后技能不被触发

**原因**：YAML frontmatter 中的 `triggers` 关键词不匹配用户输入。

**解决**：

```bash
# 查看技能的触发词
hermes skills show web-sqli

# 手动编辑触发词
vim ~/.hermes/skills/web-sqli.md
# 在 frontmatter 的 triggers 中添加更多关键词

# 或者使用 CLI 更新
hermes skills edit web-sqli --add-trigger "SQL注入检测" --add-trigger "注入漏洞"
```

### Q3：载荷格式不兼容

**原因**：OpenClaw 的 payloads.md 是独立文件，Hermes 要求载荷在 `## Examples` 章节内。

**解决**：使用引用式存根方案（第四章 4.4 节）生成技能存根文件，通过 `references` 字段指向 kali-claw 的 payloads.md。Hermes 在触发技能时会自动读取引用文件的内容，无需手动复制或合并。

### Q4：记忆导入后搜索不到内容

**原因**：FTS5 全文索引可能需要重建。

**解决**：

```bash
# 重建索引
hermes memory reindex

# 验证索引状态
hermes memory stats
```

### Q5：可以同时保持 OpenClaw 和 Hermes 双运行吗

**可以**。两个框架完全独立，互不影响。它们只是读取同一份知识的不同方式：

```bash
# OpenClaw 继续运行
openclaw gateway start

# Hermes 同时运行
hermes gateway start
```

### Q6：如何在两个框架间同步更新

使用引用式存根方案，两个框架可以共享同一份技能源文件而无需同步：

- **kali-claw** 直接读写 `skills/` 目录中的文件
- **Hermes** 通过存根文件中的 `references` 路径读取同一份文件
- 当 kali-claw 的技能文件更新时，Hermes 在下次触发该技能时自动获得最新内容

不需要手动同步、符号链接或 git submodule。

### Q7：Hermes 的自学习会覆盖迁移的技能吗

**不会**。Hermes 的自学习机制会**追加**新的经验到技能文件中，而非覆盖已有内容。当 Hermes 通过实践学到新知识时，它会在技能文件的 `## Examples` 部分追加新的示例，在 `## Instructions` 部分补充新的方法。

### Q8：Python/Shell 脚本工具怎么处理

`guides/` 中的脚本工具通过存根文件的 `references` 字段指向，Hermes 会在运行时读取：

```bash
# 确保 references 中包含 guides 目录的路径
# 在 ~/.hermes/skills/web-sqli.md 的 references 中已有：
#   - path: /path/to/kali-claw/skills/web-sqli/guides/sqli-automation.py

# 如果需要将脚本注册为 Hermes 可调用工具，可以单独配置
hermes config set tools.custom.sqli-automation "/path/to/kali-claw/skills/web-sqli/guides/sqli-automation.py"
```

### Q9：如何只迁移部分技能

```bash
# 方法一：自动迁移后删除不需要的
hermes claw migrate
hermes skills remove cloud-security  # 删除不需要的技能

# 方法二：手动为指定技能创建存根
# 参考 4.3 节的示例，只为需要的技能创建存根文件
vim ~/.hermes/skills/web-sqli.md
hermes skills validate web-sqli

# 方法三：修改批量脚本，只处理指定目录
# 在 create-hermes-stubs.sh 的循环中添加条件过滤
# for skill_dir in "$SOURCE_DIR"/{web-sqli,web-xss,network-pentest}/; do
```

### Q10：迁移后性能有差异吗

Hermes 使用 SQLite + FTS5 进行记忆检索，理论上比 OpenClaw 的文件遍历更快。由于采用引用式存根方案，Hermes 的技能文件本身很轻量（只有路径引用和基本描述），运行时通过 `references` 按需读取 kali-claw 的原始文件。如果遇到性能问题，可以考虑：

```bash
# 启用技能缓存
hermes config set skills.cache_enabled true

# 如果引用文件读取延迟较高，考虑将 kali-claw 放在本地 SSD 上
```

---

## 八、架构对比与参考

### 8.1 完整组件映射表

| kali-claw (OpenClaw) | Hermes Agent | 迁移方法 | 优先级 |
|---------------------|--------------|---------|--------|
| `SOUL.md` | `~/.hermes/personality.md` | 自动/手动 | 高 |
| `USER.md` | `~/.hermes/config.yaml` (user 段) | 手动 | 中 |
| `AGENTS.md` | `~/.hermes/config.yaml` (agent 段) | 手动 | 中 |
| `IDENTITY.md` | 技能文件 YAML frontmatter tags | 手动 | 低 |
| `skills/*/SKILL.md` | `~/.hermes/skills/skill-name.md` | 引用（存根 references） | 高 |
| `skills/*/payloads.md` | 存根文件 `references` 路径 | 引用（不修改原文） | 高 |
| `skills/*/test-cases.md` | 存根文件 `references` 路径 | 引用（不修改原文） | 中 |
| `skills/*/guides/` | 存根文件 `references` 路径 | 引用（不修改原文） | 低 |
| `MEMORY.md` | SQLite (hermes memory) | 自动导入 | 高 |
| `memory/*.md` | SQLite (hermes memory) | 自动导入 | 高 |
| `chronicle/` | SQLite (hermes memory) | 自动导入 | 低 |
| `TOOLS.md` | `~/.hermes/config.yaml` (tools 段) | 手动 | 中 |
| `HEARTBEAT.md` | `~/.hermes/config.yaml` (cron 段) | 手动 | 低 |

### 8.2 技能格式对比

**OpenClaw 格式**（多文件）：

```
skills/web-sqli/
├── SKILL.md                        # 技能定义（Description, Use Cases, Methodology, Tools, Hacker Laws）
├── payloads.md                     # 按类型分类的攻击载荷（10 大类）
├── test-cases.md                   # 结构化测试用例模板（12 个 TC-SXXX 用例）
├── sqli-cross-db-guide.md          # 跨库注入指南
└── sqli-double-query-guide.md      # 双查询注入指南
```

**Hermes 格式**（引用式存根）：

```
~/.hermes/skills/
└── web-sqli.md                     # 轻量级存根，通过 references 指向 kali-claw 原始文件
                                      # 不包含合并内容，运行时动态读取引用文件
```

### 8.3 记忆系统对比

| 特性 | OpenClaw | Hermes |
|------|---------|--------|
| 存储方式 | Markdown 文件 | SQLite 数据库 |
| 检索方式 | 文件遍历 | FTS5 全文检索 |
| 容量 | 受文件系统限制 | SQLite 支持数百万条记录 |
| 摘要 | 手动精炼到 MEMORY.md | LLM 自动摘要 |
| 持久性 | 文件级持久 | 数据库级持久 + 自动备份 |

### 8.4 推荐迁移顺序

1. **先迁移核心安全技能**（web-sqli, web-xss, network-pentest, osint）
2. **再迁移代理人格**（SOUL.md -> personality.md）
3. **然后迁移记忆系统**（memory/ -> SQLite）
4. **最后迁移辅助配置**（TOOLS.md, HEARTBEAT.md）
5. **逐步验证**，确保每个阶段都能正常工作

---

> **下一步**：完成迁移后，建议阅读 Hermes 官方文档了解更多高级功能：github.com/NousResearch/hermes-agent
