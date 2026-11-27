# kali-claw v0.1.8 发布公告 — 49 个技能域全部达到 FULL 级别

**发布日期**：2026-05-22
**技能域数量**：49（不变）
**主题**：技能缺口消除 — 每个域均配备完整的 payloads、test-cases 和 guides

---

## 更新概览

v0.1.8 彻底消除了前序版本遗留的技能补强缺口。v0.1.6 引入了三层补强策略（FULL / PARTIAL / MINIMAL），但仍有 10 个技能域低于 FULL 级别。本次发布将其全部升级：

- **3 个 MINIMAL → FULL**：chronicle、continuous-learning、safety-guard（新增 payloads.md + test-cases.md + guides/）
- **7 个 PARTIAL → FULL**：api-security、docker-patterns、repo-scan、search-first、terminal-ops、verification-loop、web-auth-bypass（新增 guides/）

kali-claw 的每个技能域现在都具备完整的四文件结构：`SKILL.md` + `payloads.md` + `test-cases.md` + `guides/`。

---

## MINIMAL → FULL：3 个元技能补全

### `chronicle` — 事件记录与知识蒸馏

此前仅有 SKILL.md，定义了三层架构（事件 → 编年史 → MEMORY.md）。

**新增**：
- `payloads.md`（568 行）— P0/P1/P2 事件记录模板、编年史条目格式、知识蒸馏命令、月度总结生成、归档与维护命令、交叉引用查询
- `test-cases.md`（281 行）— TC-CH-001 至 TC-CH-006：P0 事件记录、P1 里程碑记录、记忆归档、月度总结生成、跨系统集成触发、索引完整性验证
- `guides/event-recording-best-practices.md`（550 行）— 何时记录、事件工作流、蒸馏流程、月度审查、归档管理、与其他技能的集成

### `continuous-learning` — 模式检测与知识提取

此前仅有 SKILL.md，定义了学习循环（Learning Cycle）模式。

**新增**：
- `payloads.md`（629 行）— 模式检测命令、知识条目模板（ATK/DEF/TOOL/ENV/ENG 五类）、置信度评分标准、存储层命令、交叉引用查询、维护命令
- `test-cases.md`（295 行）— TC-CL-001 至 TC-CL-006：攻击模式学习、工具行为学习、置信度演化、矛盾检测、知识修剪、多技能复盘
- `guides/knowledge-extraction-workflow.md`（632 行）— 学习循环实操、模式检测技巧、条目创建、置信度评分实践、维护流程、常见陷阱

### `safety-guard` — 作用域执行与应急响应

此前仅有 SKILL.md，定义了三模式系统（Careful / Guard / Cowboy）。

**新增**：
- `payloads.md`（888 行）— 作用域锁定模板（4 种类型）、危险命令正则模式、速率限制配置、ROE 模板、操作前检查清单、应急响应手册（L1/L2/L3）、安全自审命令
- `test-cases.md`（408 行）— TC-SG-001 至 TC-SG-007：范围内操作放行、范围外阻断、危险命令拦截、速率限制执行、应急响应触发、ROE 时间窗口执行、模式切换
- `guides/scope-enforcement-operations.md`（842 行）— 作用域锁定设置、操作模式深度解析、模式管理、速率限制实践、应急响应演练、操作前检查清单、ROE 合规验证

---

## PARTIAL → FULL：7 个技能新增 Guides

### `api-security`
- `guides/api-security-complete-guide.md`（594 行）— 从根目录 `api-security-guide.md` 迁入
- `guides/graphql-security-testing.md`（727 行）— **新增**：内省攻击、批量查询滥用、嵌套查询 DoS、授权绕过、Mutation 注入，工具（InQL、graphql-cop、BatchQL）

### `web-auth-bypass`
- `guides/auth-bypass-complete-guide.md`（550 行）— 从根目录 `auth-bypass-guide.md` 迁入
- `guides/jwt-attack-methodology.md`（673 行）— **新增**：算法混淆攻击、密钥暴力破解、令牌篡改、kid 注入、JWK/JWKS 滥用，工具（jwt_tool、hashcat）

### `docker-patterns`
- `guides/lab-environment-management.md`（814 行）— 实验环境生命周期、网络拓扑、多容器编排、证据提取、预构建靶机环境、资源清理

### `repo-scan`
- `guides/codebase-security-audit-workflow.md`（750 行）— 四阶段审计方法论、依赖分析、密钥检测、SAST 集成、裁定生成、CI/CD 自动化

### `search-first`
- `guides/exploit-research-methodology.md`（617 行）— 搜索优先决策流、ExploitDB/GitHub/MSF/Nuclei 搜索策略、评估评分、使用/修改/构建决策框架、CVE 案例分析

### `terminal-ops`
- `guides/evidence-first-execution.md`（784 行）— 会话录制、证据链构建、输出格式化、长时间操作管理、漏洞利用调试、后期证据打包

### `verification-loop`
- `guides/finding-verification-methodology.md`（938 行）— 六阶段验证流程、误报消除、独立确认、严重性验证、修复验证、决策树

---

## 文档更新

- **MEMORY.md** — 新增 v0.1.5 至 v0.1.8 关键决策，更新当前状态（49 技能域、运行 10 周），补充经验教训（三层补强策略、可移植技能设计）
- **HEARTBEAT.md** — 新增"技能域完整性检查"章节，增加 MEMORY.md 过期监控，更新优先级顺序
- **CHANGELOG.md** — 新增 v0.1.8 条目

---

## 统计数据

| 指标 | 数量 |
|------|------|
| 新增文件 | ~18 |
| 新增代码行 | ~10,000+ |
| 升级前 FULL 技能 | 39/49（79.6%） |
| 升级后 FULL 技能 | 49/49（100%） |
| guides 目录 | 49/49 |
| payloads.md 文件 | 49/49 |
| test-cases.md 文件 | 49/49 |

---

## 下一步计划（v0.1.9）

- **技能实践验证** — 在 Kali 实战环境中为每个技能域至少执行 1 个测试用例
- **跨技能集成测试** — 验证 ECC Pipeline 跨技能域端到端流程
- **技能质量评分** — 自动化指标：payload 覆盖率、测试用例通过率、指南完整度
- **战略上下文管理** — 长周期渗透任务的上下文压缩与优先信息保留
