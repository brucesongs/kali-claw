# kali-claw v0.2.0.4 版本说明

> **版本编号**：v0.2.0.4  
> **发布日期**：2026 年 7 月 24 日  
> **版本类型**：里程碑版本（Phase 1 第一阶段完成）  
> **上一版本**：v0.2.0.3（2026-07-21）  
> **下一里程碑**：v0.2.0.5（Phase 2 启动 + Task 1.3 启动）

---

## 一、版本概述

kali-claw 是基于 OpenClaw 框架构建的 AI 渗透测试智能体工作空间，覆盖 127 个安全技能域，掌握 Kali Linux 2025-2 全部 518 款安全工具。本仓库作为智能体的结构化知识库与配置系统，配套自动化脚本完成校验、编排与报告工作。

v0.2.0.4 是 kali-claw **Phase 1 SKILL 库完善项目**的第四个迭代版本，本次发布的核心成就是**Phase 1 Task 1.2 第一阶段全部完成**——15 个高优先级 SKILL 已全部完成深度质量升级，达到 100% 完成度。

本版本新增完成最后 3 个 P1 优先级 SKILL：

- **container-security**（容器安全）
- **binary-reverse**（二进制逆向）
- **exploit-development**（漏洞利用开发）

至此，覆盖**网络安全、Web 安全、后渗透、凭证攻击、社会工程、OSINT、云安全、容器安全、二进制逆向、漏洞利用开发**等全部核心攻击域的 15 个 SKILL 全部具备完整的"防御三件套"——**防御视角（Defense Perspective）**、**检测方法（Detection Methods）**、**防御规避技术（Defense Evasion Techniques）**。

---

## 二、版本亮点

### 1. Phase 1 第一阶段全部完成（100%）

15 个 P0/P1 高优先级 SKILL 全部达到生产级质量标准：

```
P0 核心域（3/3 = 100%）
├── network-pentest（网络渗透测试）
├── post-exploitation（后渗透）
└── web-xss（跨站脚本攻击）

P1 重要域（12/12 = 100%）
├── web-sqli（SQL 注入攻击）
├── web-ssrf（服务端请求伪造）
├── web-auth-bypass（认证绕过）
├── api-security（API 安全）
├── password-attack（口令攻击）
├── privilege-escalation（权限提升）
├── social-engineering（社会工程）
├── osint（开源情报收集）
├── cloud-security（云安全）
├── container-security（容器安全）      ← 本版本新增
├── binary-reverse（二进制逆向）        ← 本版本新增
└── exploit-development（漏洞利用开发）  ← 本版本新增
```

### 2. 三个 SKILL 完成本版本升级

| SKILL 名称 | 中文领域 | 主要新增内容 |
|-----------|---------|------------|
| container-security | 容器安全 | 拆分原合并章节为独立检测/规避；新增容器运行时与 K8s API Server 监控规则 |
| binary-reverse | 二进制逆向 | 大幅扩展检测方法至 5 类；新增完整 7 类防御规避技术 |
| exploit-development | 漏洞利用开发 | 全新创建检测方法（6 类）与防御规避技术（6 类），含现代防御绕过（AMSI/ETW/BYOVD） |

### 3. 防御视角全面表格化与现代化

所有 SKILL 的防御视角章节全部升级为**多层防御矩阵**，至少覆盖 5 个防御层。本版本尤其强化的现代攻击向量包括：

- **进程注入隐身**：进程镂空、APC 注入、线程劫持、原子投弹（Atom Bombing）、进程二重身
- **现代内存保护绕过**：ROP、信息泄漏、Canary 暴力破解、CFG/CET 绕过
- **AMSI/ETW 绕过**：内存补丁、纯 syscall 调用、SysWhispers
- **BYOVD 攻击**：利用存在漏洞的签名驱动获取内核读/写能力

### 4. 检测规则对接主流 SOC 工具链

所有新增的检测方法章节均提供**可直接复制使用**的 SIEM 检测规则：

- Splunk SPL 查询语句
- Sigma 规则文件路径
- Windows Sysmon 事件 ID（1/8/10/13 等）
- Falco / Tetragon 容器运行时规则
- AWS GuardDuty / Microsoft Defender for Cloud 云检测器
- YARA 静态签名规则

---

## 三、详细更新内容

### 1. container-security（容器安全）

**适用场景**：容器镜像构建、仓库管理、运行时防护、Kubernetes 编排平台全生命周期安全评估。

#### 检测方法（拆分独立章节，5 类）

- **容器运行时指标**：意外 Shell 执行（Falco 默认规则）、敏感文件访问（`/etc/shadow`、`/proc/sysrq-trigger`）、异常系统调用（`ptrace`、`keyctl`、`mount`、`unshare`）、能力滥用（`CAP_SYS_ADMIN`、`CAP_SYS_PTRACE`）
- **Kubernetes API Server 指标**：特权 Pod 创建、ServiceAccount Token 滥用、RBAC 越权、匿名认证滥用、`kubectl exec` 在系统 Pod 上的异常调用
- **容器镜像/仓库指标**：未使用摘要固定的镜像（`:latest`）、可疑基础镜像、Cosign/Notation 签名校验失败、仓库失陷
- **CI/CD 流水线指标**：构建参数注入、缓存投毒、依赖混淆、CI 容器以 root 运行
- **SIEM 检测规则**：Falco 默认规则、Tetragon eBPF 策略、Splunk SPL（K8s 审计 + 容器日志）、Sigma 规则、AWS GuardDuty EKS Protection

#### 防御规避技术（拆分独立章节，6 类）

- **运行时隐身**：静态二进制替代解释型脚本、LOLBins、纯内存执行（`memfd_create`）、进程名伪装、Syscall 代理
- **容器逃逸隐身**：选择较新 CVE（CVE-2024-1086 netfilter）规避签名、利用已有能力而非升级至 privileged、使用较少监控的系统调用（`openat2`、`io_uring`、`bpf`）、Cgroup v2 滥用
- **Kubernetes 隐身**：使用已有 ServiceAccount Token 而非新建 RBAC、Sidecar 注入替代新建 Pod、ConfigMap 替代 Secret、CronJob 一次性 Pod、PreStop 钩子滥用、仅 hostPID/hostNetwork 替代 privileged
- **镜像/供应链隐身**：多层镜像载荷隐藏、Cosign 签名密钥窃取、准入控制器绕过、构建缓存投毒、依赖混淆混合攻击、SBOM 操纵
- **网络隐身**：Cloudflare/API Gateway 代理、DoH 隧道、WebSocket 持久连接、PrivateLink/VPC 对等等私有路径、服务网格 mTLS 滥用
- **持久化隐身**：DaemonSet 部署、准入 Webhook 持久化、CRD 持久化、etcd 直接操纵、kubelet 匿名认证滥用

### 2. binary-reverse（二进制逆向）

**适用场景**：静态分析、动态调试、漏洞挖掘、漏洞利用开发、恶意代码分析。

#### 检测方法（扩展至 5 类）

- **二进制分析指标**：硬编码密钥泄露（AKIA/JWT/RSA 私钥）、危险函数导入（`strcpy`/`strcat`/`sprintf`/`gets`/`system`）、缺失保护（RELRO/Canary/NX/PIE）、调试符号残留、可疑熵值（加壳/加密载荷）
- **运行时/动态分析指标**：调试器附加痕迹（`ptrace`、TracerPid）、内存保护绕过（`mprotect` 修改为 `PROT_WRITE|PROT_EXEC`）、异常系统调用（非 Shell 二进制调用 `execve`）、库注入（`LD_PRELOAD`）、函数 Hook（PLT/GOT 修改）
- **逆向工程工具检测**：`gdb`/`radare2`/`ghidra`/`ida`/`frida-server` 进程在生产环境运行；Frida 默认端口（27042）、Ghidra 调试桥（18001）；文件系统痕迹（`/tmp/.ghidra`、`~/.radare2_history`）
- **防篡改检测**：AIDE/OSSEC 完整性监控、代码签名（macOS Notarization/Windows Authenticode/Linux IMA-EVM）、UEFI Secure Boot、eBPF 可观测性
- **SIEM 检测规则**：Splunk SPL（auditd）、Sysmon Event ID 1、Falco 规则（`Launching Suspicious Reverse Engineering Tool`）、YARA 文件系统扫描

#### 防御规避技术（全新章节，7 类）

- **反调试**：`ptrace self-attach`、时序检查（`rdtsc`）、INT 3 检测（扫描 `0xCC` 字节）、硬件断点检测（DR0-DR7）、单步检测（Trap Flag）、调试寄存器投毒
- **反虚拟机/反沙箱**：MAC 地址检查（VMware `00:50:56`、VirtualBox `08:00:27`、Hyper-V `00:15:5D`）、CPU 厂商检查（CPUID hypervisor bit）、时序异常、注册表痕迹（Windows）、文件系统痕迹（`/proc/vz`、`/proc/xen`）、进程列表检查
- **代码混淆**：加壳（UPX/ASPack/Themida/VMProtect）、多态代码、变形代码、控制流平坦化、垃圾代码插入、不透明谓词、字符串加密
- **反插桩**：Frida 检测（扫描 `frida-agent`、`gum-js-loop` 线程、27042 端口）、Hook 检测（对比磁盘与内存中函数序言）、内联 syscall、自完整性检查
- **反分析文件**：反反汇编（`jmp` + 垃圾字节）、反 IDA 模式、PE 资源段滥用、PDB 路径伪造
- **隐身执行**：进程镂空、进程注入、反射式 DLL 注入、原子投弹（Atom Bombing）、进程二重身
- **网络 C2 隐身**：域前置、TLS 指纹匹配（`curl-impersonate`）、协议伪装（DNS/ICMP/HTTPS）、信标抖动

### 3. exploit-development（漏洞利用开发）

**适用场景**：漏洞挖掘、崩溃分析、漏洞利用代码开发、覆盖缓冲区溢出、ROP 链、格式化字符串漏洞、shellcode 注入、x86/ARM 跨架构。

#### 检测方法（全新章节，6 类）

- **静态二进制分析**：危险函数导入检测、缺失保护检测（`checksec`）、易漏洞代码模式（Semgrep/CodeQL）、格式化字符串漏洞模式、整数溢出签名
- **运行时内存保护**：DEP/NX 位、ASLR、栈 Canary、RELRO（部分/完全）、PIE、CFG（Windows 控制流保护）、CET（Intel IBT + Shadow Stack）
- **行为检测（EDR/XDR）**：进程注入模式（`CreateRemoteThread` + `VirtualAllocEx` + `WriteProcessMemory`）、反射式 DLL 加载、异常进程父子关系（`lsass.exe` 派生 `cmd.exe`）、纯内存执行、可疑系统调用
- **Shellcode 检测**：签名匹配（Metasploit/shell-storm）、熵分析、API 调用模式（`LoadLibraryA` + `GetProcAddress`）、NoPS 纯 syscall shellcode
- **网络/漏洞投递检测**：IDS 签名（MS17-010/Log4Shell/ProxyShell）、WAF 检测、网络异常、信标检测（RITA 统计分析）
- **SIEM 检测规则**：Splunk SPL（auditd）、Sysmon Event ID 8/10、Sigma 规则（进程注入通用模式）、Falco 规则、YARA 内存扫描

#### 防御规避技术（全新章节，6 类）

- **内存保护绕过**：DEP 绕过（ROP 链）、ASLR 绕过（信息泄漏）、Canary 绕过（fork 服务器暴力破解）、RELRO 绕过（GOT 替代目标 `.fini_array`）、PIE 绕过（基址泄漏）、CFG 绕过（`__free_hook` <2.34）、CET 绕过（合法间接分支）
- **Shellcode 规避**：编码器（Metasploit `shikata_ga_nai`）、NoPS 纯 syscall shellcode、反射式加载、分阶段加载、内存模块加载（`ManualMap`）、Donut shellcode（.NET/PE/DLL 转 PIC）
- **反分析**：反调试、反虚拟机、反取证（`timestomp`、选择性清日志、`memfd_create`）、工具混淆（修改开源工具源码）、睡眠混淆（Ekko/Foliage）
- **进程注入隐身**：进程镂空、反射式 DLL 注入、APC 注入、线程劫持、原子投弹、进程二重身、EarlyBird 注入
- **网络 C2 规避**：域前置、TLS 指纹匹配（JA3 哈希）、协议伪装、Malleable C2 配置文件、信标抖动、长期潜伏信标（24 小时间隔）
- **现代防御绕过**：AMSI 绕过（`amsi.dll` 内存补丁、`AmsiScanBuffer` 返回值伪造）、ETW 绕过（`ntdll!EtwEventWrite` 内存补丁、直接 syscall）、EDR 分裂（跨进程分散载荷）、内核回调绕过（BYOVD：`RTCore64.sys`、`gdrv.sys`）、直接 syscall（NoPS/SysWhispers）、硬件断点 Hook

---

## 四、Phase 1 第一阶段累计成果

### 完整 SKILL 清单（15 个，全部完成）

#### P0 核心域（3 个）

1. **network-pentest**（网络渗透测试）— 网络侦察、端口扫描、服务指纹、漏洞识别、流量嗅探、MITM 攻击
2. **post-exploitation**（后渗透）— 权限提升、持久化、横向移动、数据收集、外泄、痕迹清理
3. **web-xss**（跨站脚本攻击）— 反射型、存储型、DOM 型、突变型（mXSS）

#### P1 重要域（12 个）

4. **web-sqli**（SQL 注入攻击）— 错误型、联合型、盲注、双查询、堆叠查询、带外注入
5. **web-ssrf**（服务端请求伪造）— 基础、盲注、高级绕过、云元数据提取、协议走私
6. **web-auth-bypass**（认证绕过）— 设计缺陷、实现漏洞、OAuth/OIDC 滥用、JWT 攻击
7. **api-security**（API 安全）— REST/GraphQL/gRPC、OWASP API Security Top 10、BOLA
8. **password-attack**（口令攻击）— 哈希提取、类型识别、字典攻击、规则攻击、在线暴力破解
9. **privilege-escalation**（权限提升）— Linux 内核漏洞、Windows 服务漏洞、容器逃逸
10. **social-engineering**（社会工程）— 钓鱼、预设场景、诱饵、尾随、语音钓鱼、深度伪造
11. **osint**（开源情报收集）— 公开来源情报收集、关联分析、暗网研究
12. **cloud-security**（云安全）— AWS/Azure/GCP、IAM 配置缺陷、存储桶暴露、元数据攻击
13. **container-security**（容器安全）— Docker、Kubernetes、镜像、运行时、CI/CD
14. **binary-reverse**（二进制逆向）— 静态分析、动态调试、漏洞挖掘、恶意代码分析
15. **exploit-development**（漏洞利用开发）— 缓冲区溢出、ROP 链、格式化字符串、shellcode 注入

### 质量指标对照

| 指标 | v0.2.0.1（升级前） | v0.2.0.4（本版本） | 提升 |
|------|-------------------|------------------|------|
| 高优先级 SKILL 完成数 | 0 / 15 | **15 / 15** | +15 |
| Phase 1 第一阶段完成度 | 0% | **100%** | +100% |
| SKILL 版本统一 | 0% (各为 0.1.18) | **100%** (统一 v0.2.0.2) | +100% |
| 防御视角表格化 | 部分 | **100%** | 显著提升 |
| 检测方法章节 | 30% | **100%** (15/15) | +70% |
| 防御规避技术章节 | 20% | **100%** (15/15) | +80% |
| 翻译残留（中英混杂） | 多处 | **全部清零** | 100% 清理 |

### 工时统计

| 阶段 | 日期 | 完成数 | 累计 | 实际工时 |
|------|------|--------|------|---------|
| Day 1 | 2026-07-19 | 4 | 4 / 15 (27%) | ~3h |
| Day 2 | 2026-07-19 | 4 | 8 / 15 (53%) | ~2h |
| Day 3 | 2026-07-21 | 4 | 12 / 15 (80%) | ~2h |
| Day 4 | 2026-07-22 | 3 | **15 / 15 (100%)** | ~1.5h |
| **总计** | **5 个工作日** | **15** | **100%** | **~8.5h** |

**vs 预算**：原估 9h，实际节省 0.5h。

### 安全域覆盖全景

```
网络攻击域       ✓ network-pentest
Web 攻击域       ✓ web-xss / web-sqli / web-ssrf / web-auth-bypass
凭证访问域       ✓ password-attack
后渗透域         ✓ post-exploitation / privilege-escalation
社会工程域       ✓ social-engineering
情报收集域       ✓ osint
API 安全域       ✓ api-security
云安全域         ✓ cloud-security
容器安全域       ✓ container-security
二进制分析域     ✓ binary-reverse
漏洞利用开发域   ✓ exploit-development
```

---

## 五、安装与使用

### 快速开始

```bash
# 克隆仓库
git clone https://github.com/brucesongs/kali-claw.git
cd kali-claw

# 启动 Claude Code
claude

# 初始化（自动加载所有 SKILL）
/init

# 自然语言安排工作（示例）
# "帮我分析 kali-claw 的所有技能，生成详细使用手册"
# "针对 web-xss 技能，给出完整攻击链与检测规则"
# "使用 cloud-security 技能评估 AWS 环境的 IAM 配置"
```

### 文件结构

```
kali-claw/
├── skills/                          # 130 个安全技能库
│   ├── network-pentest/
│   │   ├── SKILL.md                 # 主技能文件（v0.2.0.2）
│   │   ├── payloads.md              # 攻击载荷集合
│   │   ├── test-cases.md            # 结构化测试用例
│   │   └── guides/                  # 深度参考资料
│   ├── cloud-security/
│   ├── container-security/
│   ├── binary-reverse/
│   ├── exploit-development/
│   └── ...
├── validation/                      # 自动化校验脚本
├── RELEASE-v0.2.0.*.md              # 版本说明文档
└── PHASE1_*.md                      # Phase 1 执行计划
```

### 单 SKILL 使用示例

以 `container-security` 为例：

```bash
# 查看 SKILL 主文件
cat skills/container-security/SKILL.md

# 查看攻击载荷
cat skills/container-security/payloads.md | head -50

# 查看测试用例
cat skills/container-security/test-cases.md | head -30

# 查看深度指南
ls skills/container-security/guides/
```

---

## 六、SKILL 标准说明

所有 SKILL 遵循 **Anthropic Agent Skills Open Standard**（2025），采用渐进式披露设计：

### 第一阶段（广告层）

YAML 前言 + `## Summary` 部分，在技能扫描时加载。

```yaml
---
name: container-security
description: "Container security covers the complete lifecycle..."
version: "0.2.0.2"
compatibility:
  - openclaw
  - claude-code
  - cursor
  - windsurf
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
metadata:
  domain: cloud
  tool_count: 6
  guide_count: 5
  mitre: "TA0008-Lateral Movement"
  last_reviewed: "2026-07-22"
---
```

### 第二阶段（快速参考层）

`## Core Tools` + `## Methodology` 部分，在技能激活时加载。

### 第三阶段（详细层）

`## Practical Steps` + `## Defense Perspective` + `## Detection Methods` + `## Defense Evasion Techniques` 部分，在任务执行时加载。

---

## 七、版本路线图

### 已发布版本

| 版本 | 日期 | 主要内容 |
|------|------|---------|
| v0.2.0.1 | 2026-07-16 | 项目战略定位与计划文档 |
| v0.2.0.2 | 2026-07-19 | 完成 8 个高优先级 SKILL 升级（53%） |
| v0.2.0.3 | 2026-07-21 | 完成累计 12 个高优先级 SKILL 升级（80%） |
| **v0.2.0.4** | **2026-07-22** | **Phase 1 第一阶段全部完成（15/15 = 100%）** |

### 后续版本

| 版本 | 预计日期 | 主要内容 |
|------|---------|---------|
| v0.2.0.5 | 2026-07-29 | Phase 2 启动（标准化 95 个 SKILL）+ Task 1.3 启动（创建 7 个新 SKILL） |
| v0.2.0.6 | 2026-08-05 | 完成 7 个新 SKILL 创建（AI 红队、IdP 攻击、DLP 绕过等） |
| v0.2.0.7 | 2026-08-12 | 文档输出体系完成（使用手册、速查表、覆盖矩阵等） |
| **v0.2.1** | **2026-08-23** | **Phase 1 全部完成，发布稳定版本** |

### Phase 1 全程目标

- SKILL 总数：130 → **150+**
- 平均完成度：95.4% → **98%+**
- 防御视角覆盖率：86% → **100%**
- 自动化校验脚本：1 个 → **5 个**

---

## 八、下一版本（v0.2.0.5）预告

下一版本将正式启动 **Phase 2（标准化 95 个 SKILL）** 与 **Task 1.3（创建 7 个新 SKILL）** 双线并行。

### Phase 2 工作范围

对剩余 95 个非高优先级 SKILL 进行批量标准化优化：

- 修复翻译残留
- 添加缺失的检测方法与防御规避章节
- 版本统一升级至 v0.2.0.2
- 目标完成度：90%+

预估工时：约 28.5 小时（5-7 个工作日）

### Task 1.3 工作范围（与 Phase 2 并行）

创建 7 个战略价值高的新 SKILL，填补现有空白：

1. **ai-safety-redteam-advanced**（AI 安全红队进阶）
   - OWASP LLM Top 10 (2025)
   - 提示注入（直接/间接）
   - 越狱技术（DAN、多轮）
   - 数据投毒检测、模型反演、对抗样本

2. **identity-provider-attack**（身份提供商攻击）
   - OAuth/OIDC 流程攻击
   - SAML 断言注入
   - JWT 算法混淆（RS256 → HS256）
   - 令牌重放、服务主体滥用、MFA 绕过

3. **data-loss-prevention-bypass**（数据防泄漏绕过）
   - 隐写术外泄（图像/音频/视频 LSB）
   - DNS 隧道、ICMP 隧道
   - 云同步滥用、WebSocket/HTTP3 外泄
   - AI 增强外泄（语义分块）

4. **edge-computing-security**（边缘计算安全）
   - Cloudflare Workers 滥用
   - AWS Lambda@Edge 攻击
   - CDN 缓存投毒、源站 IP 发现
   - WAF 绕过、边缘函数注入

5. **quantum-cryptography-transition**（量子密码迁移）
   - NIST PQC 标准（ML-KEM、ML-DSA、SLH-DSA）
   - 混合 TLS 弱点、QKD 攻击
   - 迁移脆弱窗口

6. **hardware-side-channel-advanced**（硬件侧信道进阶）
   - 功耗分析（SPA/DPA）、电磁泄漏
   - 时序攻击、缓存时序攻击（Spectre/Meltdown 变种）
   - 故障注入（电压/时钟）、光学故障注入

7. **5g-6g-telecom-attack-advanced**（5G/6G 电信攻击进阶）
   - 5G Core (SBA) 攻击、IMSI Catcher 演进
   - SIP/Diameter 协议攻击
   - Open RAN 漏洞、网络切片滥用
   - 6G 早期研究方向

完成后将发布 **v0.2.1 稳定版本**，正式启动 Phase 3。

---

## 九、致谢与协作

### 工作模式

kali-claw 的日常开发遵循以下协作模式：

```
人类工程师：战略意图、需求定义、质量审查
              ↓
Claude Code：扫描分析、内容生成、验证执行
              ↓
人类工程师：决策反馈、优先级调整
              ↓
迭代优化
```

### Phase 1 第一阶段关键决策

- **2026-07-17**：启动 Phase 1，选择 Direction B（全量优化）
- **2026-07-17**：提前完成周末准备工作（节省 12h）
- **2026-07-19**：提前启动 Day 1（节省 1 天）
- **2026-07-19**：修正版本基线至 v0.2.0.2（避免后续错误）
- **2026-07-21**：完成 12/15 SKILL（80%）
- **2026-07-22**：完成 15/15 SKILL（100%）— 本版本

### 反馈渠道

- **问题反馈**：[GitHub Issues](https://github.com/brucesongs/kali-claw/issues)
- **建议提交**：欢迎通过 GitHub Discussions 或 Pull Request
- **安全漏洞报告**：请通过负责任披露流程

### 相关文档

- [RELEASE-v0.2.0.1.md](RELEASE-v0.2.0.1.md) — 项目战略定位与长远规划
- [RELEASE-v0.2.0.2.md](RELEASE-v0.2.0.2.md) — v0.2.0.2 版本说明
- [RELEASE-v0.2.0.3.md](RELEASE-v0.2.0.3.md) — v0.2.0.3 版本说明
- [CLAUDE.md](CLAUDE.md) — 项目结构与开发指南

---

## 十、版本签名

```
版本编号：v0.2.0.4
发布日期：2026-07-22
分支：phase1/skill-audit
版本类型：里程碑版本（Phase 1 第一阶段全部完成）
许可证：参见仓库 LICENSE 文件
```

**kali-claw 团队**  
**2026 年 7 月 22 日**
