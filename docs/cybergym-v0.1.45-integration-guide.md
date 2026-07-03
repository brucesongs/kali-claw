# CyberGym × kali-claw 集成指南 (v0.1.45)

> **目的**：让 kali-claw 在 CyberGym 1,508 实例集上跑实弹校准，产出首个外部基准分。
> **关联文档**：[cybergym-sampling-v0.1.45.md](cybergym-sampling-v0.1.45.md) · [cybergym-sampling-v0.1.45.json](cybergym-sampling-v0.1.45.json) · [validation/cybergym-runner.sh](../validation/cybergym-runner.sh) · [validation/cybergym-download-tasks.py](../validation/cybergym-download-tasks.py)

---

## 1. 架构总览

```
┌──────────────────────────────────────────────────────────────────────┐
│                        kali-claw workspace                           │
│  ~/code/kali-claw-en/                                                │
│  ┌────────────────────────┐    ┌──────────────────────────────────┐  │
│  │ 127 skill domains      │    │ validation/cybergym-runner.sh    │  │
│  │ (patch-to-poc-pipeline │    │  - reads sampling JSON           │  │
│  │  multi-agent-runtime   │    │  - invokes agent                 │  │
│  │  binary-reverse, etc.) │    │  - aggregates results            │  │
│  └────────────────────────┘    └────────────┬─────────────────────┘  │
│          │                                  │                        │
│          │ Claude Code session              │ spawn + collect        │
│          │ (the kali-claw agent)            │                        │
└──────────┼──────────────────────────────────┼────────────────────────┘
           │                                  │
           ▼                                  ▼
┌────────────────────────────┐    ┌───────────────────────────────────┐
│ CyberGym repo              │    │ CyberGym server (FastAPI + Docker)│
│ ~/code/cybergym/           │    │ http://10.211.55.5:8666           │
│                            │    │                                   │
│ ┌────────────────────────┐ │    │ ┌─────────────────────────────┐   │
│ │ cybergym_data/data/    │ │    │ │ run_container(_binary)()    │   │
│ │   arvo/<id>/           │◄┼────┼─┤   runs PoC in Docker        │   │
│ │     description.txt    │ │    │ │   exit_code != 0 = crash    │   │
│ │     repo-vul.tar.gz    │ │    │ └─────────────────────────────┘   │
│ │     repo-fix.tar.gz    │ │    │                                   │
│ │     patch.diff         │ │    │ SQLite poc.db                     │
│ │     error.txt          │ │    │   PoCRecord table                 │
│ └────────────────────────┘ │    │                                   │
│                            │    │ verify_agent_result.py            │
│ src/cybergym/task/         │    │   aggregates per-agent            │
│   gen_task.py              │    │                                   │
│ src/cybergym/server/       │    │                                   │
│ src/cybergym/firewall/     │    │                                   │
│ mask_map.json (1,508 IDs)  │    │                                   │
│                            │    │                                   │
│ scripts/prompts/expert.txt │    │                                   │
└────────────────────────────┘    └───────────────────────────────────┘
```

**关键事实：**
- CyberGym 实例 ID 是 `arvo:N`（不是 CVE）。`mask_map.json` 列了全部 1,508 个
- 你 5 月已下载 7 个本地：`368 / 1065 / 3938 / 10096 / 10400 / 10864 / 10900`
- 还需下载 23 个新任务（用 `cybergym-download-tasks.py` 选择性拉，无需拉 240GB 全集）
- Server 必须运行（默认在 Parallels VM `10.211.55.5:8666`）

---

## 2. 一次性环境准备（仅首次）

### 2.1 CyberGym server 启动

```bash
cd ~/code/cybergym
source .venv/bin/activate

# 选择一：binary-only mode（130GB 数据，推荐）
python3 -m cybergym.server \
    --host 0.0.0.0 --port 8666 \
    --mask_map_path mask_map.json \
    --log_dir ./server_poc --db_path ./server_poc/poc.db \
    --binary_dir ./cybergym-server-data

# 选择二：full mode（240GB，每 task 单独 Docker image）
python3 -m cybergym.server \
    --host 0.0.0.0 --port 8666 \
    --mask_map_path mask_map.json \
    --log_dir ./server_poc --db_path ./server_poc/poc.db
```

确认 server 在跑：
```bash
curl -sS http://10.211.55.5:8666/health 2>&1 || echo "(no /health route, but server should be reachable)"
```

### 2.2 下载 23 个新 arvo 任务

```bash
cd ~/code/kali-claw-en

python3 validation/cybergym-download-tasks.py \
    --cybergym-root ~/code/cybergym \
    --from-sampling docs/cybergym-sampling-v0.1.45.json \
    --workers 4
```

下载量预估：每 task 5 文件 ≈ 80-400MB，23 tasks ≈ 2-9GB（视源码大小）。比 240GB 全集轻量得多。

### 2.3 验证环境

```bash
# 1. 检查 kali-claw sampling JSON 配置
jq '.instances[] | {kcx: .kali_claw_id, arvo: .cybergym_instance_id, local: .local_data_available}' \
   docs/cybergym-sampling-v0.1.45.json | head -20

# 2. 检查 CyberGym 本地数据
ls ~/code/cybergym/cybergym_data/data/arvo/ | wc -l  # should be 30 after download

# 3. runner dry-run
cd ~/code/kali-claw-en
bash validation/cybergym-runner.sh --dry-run
# Should show "Mode: REAL-AUTO" or "REAL-INTERACTIVE"
```

---

## 3. 运行校准

### 3.1 单实例试跑（先验证 plumbing）

```bash
# M1 = arvo:10400 (libwebp, 旗舰例子)
bash validation/cybergym-runner.sh -k M1
```

Runner 会：
1. 读 M1 配置
2. 调 `gen_task --task-id arvo:10400 --difficulty level1`
3. 自动模式：调 `claude --print` 跑 kali-claw；交互模式：提示你手动开 session
4. 提交 PoC 到 server
5. 解析 server 响应 → verdict PASS/FAIL

输出落到：`validation/evidence/cybergym/v0.1.45/traces/M1.{trace,memory,task-card,server-response}.*`

### 3.2 全 30 实例

```bash
# 默认 REAL-AUTO（claude CLI 在 PATH）
bash validation/cybergym-runner.sh

# 或强制交互模式（你手动开 Claude Code session per task）
bash validation/cybergym-runner.sh --interactive

# 中断后断点续跑
bash validation/cybergym-runner.sh --resume
```

预估时间：
- 每个 task 5-15 分钟（gen_task 30s + agent 5-12min + submit 30s）
- 30 task ≈ 2.5-7.5 小时
- 全自动模式可一晚跑完；交互模式需全程在场

### 3.3 查看结果

```bash
# 即时 summary
jq '.verdict_counts, .core_score, .by_bug_class' \
   validation/evidence/cybergym/v0.1.45/summary.json

# 失败实例
jq 'select(.verdict=="FAIL") | {kcx: .instance_id, stage: .fail_stage, reason: .fail_reason}' \
   validation/evidence/cybergym/v0.1.45/traces/*.trace.json

# 对标官方
jq '.comparison_to_baseline' \
   validation/evidence/cybergym/v0.1.45/summary.json
```

---

## 4. 模式选择决策树

```
有 CYBERGYM_ROOT?
├── 否 → STUB 模式（仅 plumbing 验证，不出真分数）
└── 是 → claude CLI 在 PATH?
         ├── 是 → 默认 REAL-AUTO（headless 跑 claude --print per task）
         │        ⚠ headless 模式对 kali-claw skills 的访问受限（skills 在文件系统，
         │          claude --print 不一定加载 SOUL.md），可能不如交互模式聪明
         └── 否 → REAL-INTERACTIVE（gen_task 后暂停，你开 Claude Code session，
                  手动操作 kali-claw，PoC 写好后回车继续 submit）
                  ✓ 最贴近你 5 月成功跑出 85.7% 的方式
```

**推荐路径（基于你 5 月已有 85.7% 数据）：**

1. **第一次跑 v0.1.45 校准**：用 `--interactive` 在 7 个本地 task 上跑（M1-M7），与 5 月数据对照
2. **验证 patch-to-poc-pipeline 升级是否提升成功率**：5 月是 6/7=85.7%，v0.1.45 加了 Wave 12 的 patch-to-poc-pipeline + multi-agent-runtime-engineering 两 skill，看是否到 7/7
3. **扩展到 30 实例**：下载 23 新 task 后跑全套

---

## 5. 已知问题（来自 5 月调研报告）

| 问题 | 影响 | v0.1.45 缓解 |
|------|------|---------------|
| PoC 跨任务污染（workspace 持久化导致 hash 复用） | 4 task 共享同 PoC hash，不是真正独立 PoC | runner 每个 task 用独立 `task_dir`，不共享 workspace |
| 大源码 timeout（HarfBuzz 180MB 600s 超时） | arvo:10900 类型任务卡死 | runner timebox 可调，超过的标 timeout 不算 fail |
| CyberGym 闭卷约束 vs kali-claw 开卷 skill 库 | 与 MopMonk 73.1% 不可直接比较 | summary.json 的 `comparison_to_baseline.note` 显式说明 |
| mask_map 反查（防止 agent 查 CVE） | kali-claw skill 库含 CVE 知识，开卷作弊风险 | 诚实标注 kali-claw 是 open-book；MopMonk 等也是工程化 harness |

---

## 6. D5 校准报告模板

D5 输出 `RELEASE-v0.1.45-cybergym.md`，结构：

```markdown
# kali-claw v0.1.45 CyberGym 校准报告

## 1. Executive Summary
- kali-claw 在 N 个 CyberGym arvo 任务（level1，expert prompt）上的 pass rate: X/Y = Z%
- vs MopMonk 73.1%（全集、闭卷）— 不可直接比较但形式上 [领先/持平/落后]
- Wave 12 新增 patch-to-poc-pipeline + multi-agent-runtime-engineering 的实际贡献: ...

## 2. 实例集与方法
- N 实例分布（bug_class / difficulty / project category）
- difficulty level: 1 (description + source + error output)
- prompt: scripts/prompts/expert.txt
- agent: kali-claw via claude --print | interactive

## 3. 主要结果
| 指标 | 值 |
| Core pass rate | X/Y = Z% |
| Weighted (含 partial) | ... |
| 平均 wall clock | ... |
| Median wall clock | ... |

## 4. 失败模式画像
- 按 fail_stage 分布
- 按 bug_class 分布
- v0.1.46 候选改进

## 5. 与 5 月基线对比
| 维度 | 5 月（7 task, level1, expert） | v0.1.45 | 变化 |
| Pass rate | 6/7 = 85.7% | ... | ... |
| 平均耗时 | 88s（不含 HarfBuzz） | ... | ... |
| PoC 同质化 | 4+2 task 共享 2 hash | ... | runner 独立 task_dir 后是否解决 |

## 6. 与外部基准对比
- 不可直接对比的 caveat
- 同小集子集对比（如可比）

## 7. 局限与下一步（v0.1.46+）
- 扩到 50/100 实例
- 修 PoC 污染
- 加 level2/level3 难度
- 闭卷模式（关 skill 库）做对比
```

---

## 7. Quickstart TL;DR

```bash
# 0. 一次性：启动 CyberGym server（在 cybergym repo）
cd ~/code/cybergym && source .venv/bin/activate
python3 -m cybergym.server --host 0.0.0.0 --port 8666 \
    --mask_map_path mask_map.json --log_dir ./server_poc --db_path ./server_poc/poc.db \
    --binary_dir ./cybergym-server-data

# 1. 一次性：下载 23 个新 task
cd ~/code/kali-claw-en
python3 validation/cybergym-download-tasks.py \
    --cybergym-root ~/code/cybergym \
    --from-sampling docs/cybergym-sampling-v0.1.45.json

# 2. 试跑单实例
bash validation/cybergym-runner.sh -k M1

# 3. 全 30 实例
bash validation/cybergym-runner.sh

# 4. 看 summary
jq '.verdict_counts, .core_score' \
   validation/evidence/cybergym/v0.1.45/summary.json
```
