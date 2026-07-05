# kali-claw 全技能 PPT 制作提示词（125 Skills）

> 适用于 Gamma / Beautiful.ai / SlidesGPT / Tome 等 AI PPT 工具，或作为人工设计师的 brief。
> 每个技能配有 30 字左右的亮点说明，可直接用作幻灯片副标题或正文。

---

## 一、整体设计规范（System Prompt 通用）

```
【主题】AI 渗透测试 Agent —— kali-claw 技能矩阵
【背景】暗黑科技风：纯黑 #0A0A0F + 代码绿 #00FF9C + 警示红 #FF3B3B + 终端蓝 #00D4FF
【字体】英文 JetBrains Mono / Inter；中文 思源黑体 / 阿里巴巴普惠体
【版式】左 30% 标题区（序号 + 技能名 + 30 字亮点），右 70% 视觉区（拓扑图/代码片段/工具 Logo 矩阵）
【装饰元素】终端命令行 prompt 符号 `┌──(kali㉿claw)-[~]`、Hacker Laws 编号、MITRE ATT&CK ID 标签
【页脚】统一显示 kali-claw v0.1.44 · 125 Skills · Kali Linux 2025.2 (ARM64)
【节奏】封面 → 概览矩阵 → 13 章节封面 → 每章 5-12 张技能页 → 章节小结 → 总结页
```

---

## 二、封面与目录页提示词

### Slide 1 — 封面
```
标题：kali-claw
副标题：AI-Powered Penetration Testing Agent · 125 Security Skills · 518 Kali Tools
左下角：版本 v0.1.44 · Kali Linux 2025.2 ARM64
右下角："12 Hacker Laws · 74 Domains · 1 Mission"
视觉：发光的爪痕 (claw mark) 划过黑色屏幕，露出底层矩阵雨代码
风格：赛博朋克、终端启动画面感
```

### Slide 2 — 技能矩阵总览
```
布局：13×10 网格，每个格子代表一个技能（按域着色）
颜色编码：
  - Web 攻击（红）
  - 网络攻击（橙）
  - 云与容器（蓝）
  - 移动 / IoT（紫）
  - 逆向与漏洞利用（绿）
  - 后渗透与权限提升（黄）
  - 取证与防御（青）
  - OSINT 与情报（灰）
  - 密码学（金）
  - AI 安全（粉）
  - 工控 / OT（橄榄）
  - 区块链（深紫）
  - 无线 / 射频（青绿）
  - 知识 / 工作流（白）
中心动画：claw 爪痕从中心向外辐射
```

---

## 三、按章节组织的技能幻灯片（13 章节）

### Chapter 1 — Web 应用攻击（Web Application Attack）

| # | 技能 | 30 字亮点 |
|---|------|----------|
| 1 | api-security | API 安全测试：REST/GraphQL/gRPC 接口的 OWASP API Top 10 攻击与鉴权绕过。 |
| 2 | web-sqli | SQL 注入：sqlmap + 手工注入突破数据库边界，提取凭据与执行系统命令。 |
| 3 | web-xss | XSS 跨站脚本：反射/存储/DOM 三型注入，窃取 Cookie 与会话劫持。 |
| 4 | web-ssrf | SSRF 服务端请求伪造：内网穿透、云元数据窃取、Gopher 协议利用。 |
| 5 | web-xxe | XXE XML 外部实体：DTD 注入读取文件、SSRF 横向、DoS 与 Blind OOB。 |
| 6 | web-auth-bypass | 认证绕过：JWT 篡改、密码喷洒、多因子绕过与会话固定攻击。 |
| 7 | web-access-control | 访问控制失效：IDOR 越权、垂直水平权限提升、强制浏览敏感端点。 |
| 8 | web-deserialization | 反序列化漏洞：Java/PHP/.NET gadget chain 触发 RCE 与持久化。 |
| 9 | file-inclusion | 文件包含：LFI/RFI 配合 PHP Filter Chain 直接拉起 WebShell。 |
| 10 | cms-framework-attack | CMS 与框架攻击：WordPress/Joomla/Struts 等组件指纹与已知漏洞。 |
| 11 | security-misconfiguration | 安全误配置：默认凭据、目录列出、debug 模式、错误信息泄露利用。 |
| 12 | insecure-design | 不安全设计：业务逻辑层缺陷、滥用用例与威胁建模驱动的设计审计。 |

**章节封面提示词：**
```
标题：Chapter 01 · Web Application Attack
副标题：12 Skills · OWASP Top 10 全覆盖
视觉：Burp Suite 拦截视图 + HTTP 请求包特写
背景动效：红队从浏览器 → WAF → 应用 → 数据库 的攻击链路
```

---

### Chapter 2 — 网络渗透与隧道（Network Pentest & Tunneling）

| # | 技能 | 30 字亮点 |
|---|------|----------|
| 13 | network-pentest | 网络渗透：Nmap 全端口扫描 + Responder 抓取 SMB/LLMNR 哈希。 |
| 14 | network-sniffing-mitm | 流量嗅探与中间人：ettercap/bettercap ARP 投毒、mitm6 横行 IPv6。 |
| 15 | network-tunneling-proxy | 隧道与代理：SSH/Iodine/Dnscat2 穿越防火墙，Chisel 多层反连。 |
| 16 | dns-attacks | DNS 攻击：DNSrecon 枚举、子域接管、DNS 隧道 C2 与 DNSChef 欺骗。 |
| 17 | email-protocol-attack | 邮件协议：SMTP 用户枚举、swaks 伪造发件、OpenSMTPR 漏洞利用。 |
| 18 | voip-sip-attack | VoIP/SIP 攻击：svmap 扫描、svcrack 密码爆破、RTP 窃听与欺诈。 |
| 19 | vpn-attack | VPN 攻击：IKE-Scan 指纹、Aggressive Mode 哈希破解、vpnc 接入。 |
| 20 | wifi-pentest | WiFi 渗透：aircrack-ng 抓 WPA2 握手、PMKID、企业级 EAP 攻击。 |
| 21 | hypervisor-introspection | Hypervisor 内省：VMware/ESXi/Xen 配置审计与 LibVMI 内存提取。 |

**章节封面提示词：**
```
标题：Chapter 02 · Network Pentest & Tunneling
副标题：9 Skills · 从外网侦察到内网横行
视觉：企业网络拓扑图 + 流量抓包波形
```

---

### Chapter 3 — 云与容器安全（Cloud & Container）

| # | 技能 | 30 字亮点 |
|---|------|----------|
| 22 | cloud-security | 云安全：pacu/scoutsuite 评估 AWS/Azure/GCP 配置与 IAM 提权。 |
| 23 | container-security | 容器安全：Trivy 扫镜像、Falco 运行时检测、kube-bench 加固 CIS。 |
| 24 | kubernetes-attack | K8s 攻击：RBAC 提权、Pod 逃逸、Service Account Token 滥用。 |
| 25 | cloud-identity-attack | 云身份攻击：Entra ID/Okta 条件访问绕过、Pass-through 认证劫持。 |
| 26 | cloud-native-vuln-research | 云原生漏洞研究：CVE 分诊、PoC 复现、Nuclei 模板贡献与补丁 diff。 |
| 27 | cspm-casb-attack | CSPM/CASB 绕过：混淆 SaaS 流量、规避 DLP 与异常行为基线。 |
| 28 | sase-sse-attack | SASE/SSE 攻击：Zscaler/Netskope SWG-CASB-ZTNA 全栈边界突破。 |
| 29 | gitops-security | GitOps 安全：ArgoCD/Flux 集群管理员 RBAC 滥用与 Git 仓库投毒。 |
| 30 | data-platform-attack | 数据平台攻击：Snowflake/Databricks 通过 SSO 与 Service Token 直入。 |
| 31 | storage-san-attack | 存储网络攻击：iSCSI/FC/NFS 协议利用、NetApp/EMC 管理面突破。 |
| 32 | edge-computing-attack | 边缘计算攻击：Cloudflare Workers/Fastly WASM 沙箱逃逸与冷启动。 |
| 33 | confidential-computing-attack | 机密计算攻击：SGX/SEV Enclave 侧信道、attestation 伪造与 ABI 滥用。 |

**章节封面提示词：**
```
标题：Chapter 03 · Cloud & Container
副标题：12 Skills · 多云 × 云原生 × 机密计算
视觉：多云架构图 + 容器/K8s 集群俯视图
```

---

### Chapter 4 — 移动 / IoT / 嵌入式（Mobile · IoT · Embedded）

| # | 技能 | 30 字亮点 |
|---|------|----------|
| 34 | mobile-security | 移动安全：APK/IPA 静态分析、Frida 动态 Hook、MobSF 一键审计。 |
| 35 | mobile-app-instrumentation | 移动 App 插桩：Objection/r2frida 运行时改 SSL Pinning 与加密。 |
| 36 | iot-pentest | IoT 渗透：MQTT 通配订阅、CoAP 资源枚举、mDNS 设备发现滥用。 |
| 37 | embedded-rtos-security | RTOS 安全：VxWorks/QNX/FreeRTOS 内存破坏与协议栈漏洞利用。 |
| 38 | firmware-reverse | 固件逆向：binwalk 解包、QEMU 模拟、firmadyne 全自动漏洞挖掘。 |
| 39 | automotive-vehicle-security | 车辆安全：CAN/CAN-FD 总线、UDS 诊断、车机 PKES 中继攻击。 |
| 40 | uav-drone-security | 无人机安全：MAVLink 劫持、PX4/ArduPilot 自动化栈与 RF 控制链。 |
| 41 | hardware-security | 硬件安全：JTAG/SWD 调试、Side Channel 功耗分析与故障注入。 |
| 42 | hsm-attack | HSM 攻击：Thales/Utimaco 设备 PKI 入侵与管理接口滥用。 |

**章节封面提示词：**
```
标题：Chapter 04 · Mobile · IoT · Embedded
副标题：9 Skills · 从智能终端到芯片级
视觉：手机/汽车/无人机/工控板拼贴 + PCB 走线纹理
```

---

### Chapter 5 — 二进制逆向与漏洞利用（Reverse & Exploit）

| # | 技能 | 30 字亮点 |
|---|------|----------|
| 43 | binary-reverse | 二进制逆向：Ghidra/radare2 反编译、GDB 调试与 ROP 链构造。 |
| 44 | reverse-engineering-advanced | 高级逆向：angr 符号执行、Hex-Rays 反混淆与 BinDiff 补丁对比。 |
| 45 | exploit-development | 漏洞开发：pwntools 编写 exploit，one_gadget 配合堆利用。 |
| 46 | malware-analysis-advanced | 高级恶意码分析：脱 VMProtect/Themida 壳，反沙箱与 Rootkit 检测。 |
| 47 | ai-fuzzing | AI 模糊测试：AFL++ 覆盖引导 + libFuzzer 智能种子与崩溃分诊。 |
| 48 | payload-generation | Payload 生成：msfvenom 多格式 shellcode、Hoaxshell 隐蔽 C2。 |
| 49 | av-edr-evasion | AV/EDR 绕过：Veil/Shellter 加壳、donut 注释化、内存加载规避。 |
| 50 | game-anticheat-bypass | 反作弊研究：EAC/BattlEye/Vanguard 内核驱动模型与攻防研究。 |

**章节封面提示词：**
```
标题：Chapter 05 · Reverse & Exploit
副标题：8 Skills · 从反汇编到 RCE
视觉：Ghidra 反编译界面截图 + 堆栈布局图
```

---

### Chapter 6 — 后渗透与权限提升（Post-Exploitation）

| # | 技能 | 30 字亮点 |
|---|------|----------|
| 51 | post-exploitation | 后渗透：Meterpreter + Impacket + BloodHound + Mimikatz 全套。 |
| 52 | privilege-escalation | 权限提升：LinPEAS/WinPEAS 配合 GTFOBins 与内核漏洞利用。 |
| 53 | ad-ldap-attack | AD/LDAP 攻击：BloodHound 路径分析、DCSync 与 Kerberoasting。 |
| 54 | ad-cs-abuse | AD CS 滥用：ESC1-ESC8 证书模板漏洞直达 Domain Admin。 |
| 55 | pam-privilege-attack | PAM 攻击：CyberArk/BeyondTrust 顶层凭据金库横向接管。 |
| 56 | secret-management-attack | 密钥管理攻击：Vault/Infisical 配置错误与代码中硬编码 secret 抓取。 |
| 57 | data-exfiltration-attack | 数据外渗：DNS/ICMP 隧道、HTTPS C2、域前置绕过 DLP/SWG/CASB。 |
| 58 | persistence-techniques | （隐含）持久化：计划任务、WMI 订阅、COM 劫持与黄金票据。 |

**章节封面提示词：**
```
标题：Chapter 06 · Post-Exploitation
副标题：8 Skills · 拿下据点 → 横向 → 长期驻留
视觉：BloodHound 节点图 + Mimikatz 输出截屏
```

---

### Chapter 7 — OSINT 与社会工程（OSINT & Social Engineering）

| # | 技能 | 30 字亮点 |
|---|------|----------|
| 59 | osint | OSINT 开源情报：Maltego/recon-ng 多源关联，从公开数据重塑目标画像。 |
| 60 | recon-osint | 侦察：信息收集决定后续攻击精度，子域/邮件/员工画像一气呵成。 |
| 61 | social-intelligence | 社交情报：Reddit/HN/Sherlock 跨平台聚合，构建人物与情绪画像。 |
| 62 | username-profiling | 用户名画像：Sherlock/WhatsMyName/Holehe 反查 100+ 平台账号。 |
| 63 | darkweb-intel | 暗网情报：Tor/Whonix 匿名接入，Ahmia/IntelX 检索泄露凭据。 |
| 64 | social-engineering | 社会工程：SET/GoPhish 钓鱼、Pretexting/Vishing 多向量组合。 |
| 65 | email-security-deep | 邮件安全深度：evilginx2 实时钓鱼、BEC 商业邮件欺诈、网关绕过。 |
| 66 | physical-security-testing | 物理安全测试：开锁、徽章克隆、USB 武器投递、隐藏摄像头部署。 |

**章节封面提示词：**
```
标题：Chapter 07 · OSINT & Social Engineering
副标题：8 Skills · 人是最薄弱的环节
视觉：Maltego 关系图 + 钓鱼邮件模板预览
```

---

### Chapter 8 — 密码学与零信任（Crypto & PQC）

| # | 技能 | 30 字亮点 |
|---|------|----------|
| 67 | crypto-attacks | 密码学攻击：OpenSSL/testssl 找弱套件、PadBuster 攻 CBC、RSA 工具。 |
| 68 | password-attack | 密码攻击：Hashcat/John GPU 爆破、Hydra 在线爆破、CeWl 生成字典。 |
| 69 | quantum-crypto-attack | 后量子密码攻击：评估 CRQC 来临前的算法敏捷性与 KEM 鲁棒性。 |
| 70 | post-quantum-migration-attack | PQC 迁移攻击：Harvest-Now-Decrypt-Later + 混合 PQC 降级。 |

**章节封面提示词：**
```
标题：Chapter 08 · Cryptography & Post-Quantum
副标题：4 Skills · 从弱算法到量子时代
视觉：AES 块图 + 量子比特卡通 + CBC padding 示意
```

---

### Chapter 9 — AI / LLM 安全（AI Security）

| # | 技能 | 30 字亮点 |
|---|------|----------|
| 71 | ai-security | AI 安全：garak/promptfoo 找 LLM 越狱、picklescan 防 pickle 反序列化。 |
| 72 | llm-red-team | LLM 红队：Prompt Injection、Jailbreak、系统提示泄露与 GCG 攻击。 |
| 73 | ai-agent-security | AI Agent 安全：测试有状态、用工具、可自主执行的 Agent 系统。 |
| 74 | ai-agent-framework-attack | Agent 框架攻击：LangChain/LlamaIndex 编排层注入与工具投毒。 |
| 75 | agentic-pentest | Agentic Pentest：部署 PentestGPT/HexStrike 等 LLM 自主渗透框架。 |

**章节封面提示词：**
```
标题：Chapter 09 · AI / LLM Security
副标题：5 Skills · 当 AI 既是武器也是靶场
视觉：LLM Token 流 + 工具调用图谱
```

---

### Chapter 10 — 工控 / SCADA / OT（ICS · SCADA · OT）

| # | 技能 | 30 字亮点 |
|---|------|----------|
| 76 | scada-ics-security | SCADA/ICS 安全：Modbus/S7/ENIP 协议扫描与 PLC 指令注入。 |
| 77 | ics-fieldbus-attack | ICS Fieldbus 攻击：电力/油气/水务的 Profibus/DNP3/IEC61850。 |
| 78 | cps-attack | CPS 信息物理系统：PLC/RTU/HMI 攻击，破坏物理过程的连级后果。 |
| 79 | 5g-telecom-attack | 5G 电信攻击：5GC、O-RAN、NGAP/PFCP 信令利用与漫游劫持。 |

**章节封面提示词：**
```
标题：Chapter 10 · ICS · SCADA · OT
副标题：4 Skills · 当字节控制物理世界
视觉：发电厂 HMI 截屏 + PLC 控制器照片
```

---

### Chapter 11 — 区块链 / Web3（Blockchain · Web3）

| # | 技能 | 30 字亮点 |
|---|------|----------|
| 80 | blockchain-web3 | Web3 安全：Solidity 审计、DeFi 经济攻击、钱包/dApp 利用。 |
| 81 | blockchain-l2-attack | L2 攻击：Optimistic/ZK Rollup、跨链桥、Account Abstraction。 |

**章节封面提示词：**
```
标题：Chapter 11 · Blockchain · Web3
副标题：2 Skills · 链上漏洞的真金白银
视觉：Solidity 代码片段 + 智能合约调用流
```

---

### Chapter 12 — 无线 / 射频 / 卫星（Wireless · RF · Satellite）

| # | 技能 | 30 字亮点 |
|---|------|----------|
| 82 | bluetooth-rfid-nfc | 蓝牙/RFID/NFC：ubertooth 抓包、crackle 破 BR/EDR、proxmark3 克隆。 |
| 83 | sdr-rf-attack | SDR 射频攻击：HackRF/RTL-SDR 抓 ISM 频段，GNU Radio 解调重放。 |
| 84 | hf-vhf-radio-attack | HF/VHF/UHF 攻击：9 kHz-1500 MHz 授权频段，安全相关业务干扰。 |
| 85 | satellite-leo-security | 卫星通信安全：LEO 宽带/GPS/GEO 链路层与地面段攻防。 |

**章节封面提示词：**
```
标题：Chapter 12 · Wireless · RF · Satellite
副标题：4 Skills · 从蓝牙到近地轨道
视觉：频谱瀑布图 + 卫星轨道动画
```

---

### Chapter 13 — 取证 / 防御 / 检测（Forensics · Defense · Detection）

| # | 技能 | 30 字亮点 |
|---|------|----------|
| 86 | digital-forensics | 数字取证：Autopsy/SleuthKit 磁盘 + Volatility 内存 + Wireshark 流量。 |
| 87 | anti-forensics | 反取证：shred/tcplay 安全擦除、日志篡改与时间戳伪造。 |
| 88 | steganography | 隐写术：steghide/zsteg 在图片音频中藏数据，对抗加密可见性。 |
| 89 | deception-honeypot | 欺骗与蜜罐：Cowrie/OpenCanary/Canarytokens 早期预警与 IOC 收集。 |
| 90 | threat-hunting | 威胁狩猎：MITRE ATT&CK + Sigma + YARA 在 Sysmon/Zeek 数据上追踪。 |
| 91 | detection-engineering | 检测工程：把规则当代码，编写/测试/部署/退役 Sigma、YARA、KQL。 |
| 92 | logging-monitoring | 日志监控：ELK/Splunk/Wazuh 集中收集，auditd 与 Zeek 全栈可观测。 |
| 93 | safety-guard | 安全护栏：Agent 行为边界、不当操作拦截与可恢复回滚。 |

**章节封面提示词：**
```
标题：Chapter 13 · Forensics · Defense · Detection
副标题：8 Skills · 攻防一体，蓝队视角
视觉：Splunk 仪表板 + Volatility 进程树
```

---

### Chapter 14 — 基础设施 / 供应链 / 红队平台（Infra · Supply Chain · Red Team）

| # | 技能 | 30 字亮点 |
|---|------|----------|
| 94 | ci-cd-supply-chain-attack | CI/CD 供应链攻击：SolarWinds/xz-utils 模式的构建管道投毒。 |
| 95 | supply-chain-security | 供应链安全：Trivy/Snyk/Dependabot 扫描依赖与 SBOM 治理。 |
| 96 | repo-scan | 仓库扫描：批量审计 Git 仓库的代码质量、密钥与漏洞。 |
| 97 | secret-management-attack→repo | （并入第 6 章） |
| 98 | red-team-infrastructure | 红队基础设施：Cobalt Strike/Mythic/Sliver + Redirector + 域前置。 |
| 99 | threat-intel-platform-attack | 威胁情报平台攻击：MISP/OpenCTI 信任链与 IOC 投毒。 |
| 100 | deception-honeypot→infra | （并入第 13 章） |

**章节封面提示词：**
```
标题：Chapter 14 · Infra · Supply Chain · Red Team Platform
副标题：6 Skills · 后台与平台 = 高价值靶点
视觉：CI/CD 流水线 + 红队 C2 拓扑
```

---

### Chapter 15 — 行业纵深 / 金融 / 政府（Verticals）

| # | 技能 | 30 字亮点 |
|---|------|----------|
| 101 | payment-security | 支付安全：Stripe/PCI-DSS、EMV、3DS 与 POS 终端攻击面。 |
| 102 | open-banking-attack | 开放银行攻击：PSD2/AIS/PIS API、TPP 凭据劫持与签名重放。 |
| 103 | mainframe-security | 大型机安全：z/OS、CICS、RACF 仍承载全球信用卡核心交易。 |
| 104 | macos-security | macOS 安全：SIP/TCC/ESF/Endpoint Security 框架的攻防前沿。 |

**章节封面提示词：**
```
标题：Chapter 15 · Industry Verticals
副标题：4 Skills · 金融 · 政府 · 终端
视觉：信用卡 EMV 芯片特写 + z/OS 终端
```

---

### Chapter 16 — 评估 / 报告 / 编排（Assessment · Reporting · Orchestration）

| # | 技能 | 30 字亮点 |
|---|------|----------|
| 105 | vulnerability-assessment | 漏洞评估：OpenVAS/Nessus/Nuclei 系统化扫，Lynis 主机基线加固。 |
| 106 | security-review | 安全评审：渗透中覆盖 OWASP Top 10 的结构化代码审计方法。 |
| 107 | security-bounty-hunter | 漏洞赏金：聚焦远程可达、可负责披露的真实漏洞。 |
| 108 | pentest-reporting | 渗透报告：Dradis/Faraday 整理证据链，影响评级与可复现步骤。 |
| 109 | engagement-manager | Engagement Manager：从立项到交付全生命周期编排与技能调度。 |
| 110 | tool-mastery | 工具精通：518 Kali 工具的分级、验证、组合使用框架。 |

**章节封面提示词：**
```
标题：Chapter 16 · Assessment · Reporting · Orchestration
副标题：6 Skills · 把战场变成可交付物
视觉：Dradis 报告截屏 + Engagement 流程图
```

---

### Chapter 17 — Agent 元能力（Meta Skills · kali-claw 引擎）

| # | 技能 | 30 字亮点 |
|---|------|----------|
| 111 | autonomous-loops | 自主循环：Goal→Plan→Act→Verify 闭环，Agent 自驱迭代。 |
| 112 | verification-loop | 验证循环：每一步都验证证据，杜绝幻觉式结论。 |
| 113 | search-first | 搜索优先：动手前先查 GitHub/Context7/Exa，避免重造轮子。 |
| 114 | terminal-ops | 终端操作：先观察后行动、最小变更、精确报告执行状态。 |
| 115 | docker-patterns | Docker 模式：标准化容器隔离每一次渗透操作环境。 |
| 116 | mcp-server-patterns | MCP Server 模式：Tools/Resources/Prompts/stdio/SSE 标准接口。 |
| 117 | multi-agent-collaboration | 多 Agent 协作：CEO/Workers 分工，主从式与议会式拓扑。 |
| 118 | council | Council 议会：Attack/Defense/Audit 三视角多角色评审。 |
| 119 | codebase-onboarding | 代码库 Onboarding：把陌生项目变成架构图与入口点地图。 |
| 120 | chronicle | Chronicle 编年史：三层文档把会话事件沉淀为可复用经验。 |
| 121 | continuous-learning | 持续学习：高/中/低/负反馈分级，攻防模式与环境模式累积。 |
| 122 | knowledge-ops | Knowledge Ops：把临时发现升级为跨会话可召回的情报。 |
| 123 | deep-research | Deep Research：长任务多跳检索与综合写作的基础设施。 |
| 124 | exa-search | Exa Search：基于语义向量理解上下文的高质量检索。 |
| 125 | data-scraper-agent | Data Scraper Agent：把非结构化网页转成结构化知识单元。 |
| 126 | browser-qa | Browser QA：以用户视角点击浏览，监控网络与 DOM 异常。 |
| 127 | article-writing | Article Writing：把渗透发现转化为高质量技术文章。 |

> 注：编号 111+ 为 Agent 元能力，实际技能池中可作为支撑技能辅助 12 Hacker Laws。

**章节封面提示词：**
```
标题：Chapter 17 · Meta Skills · Agent Engine
副标题：17 Skills · 让 Agent 学会学习与协作
视觉：自循环（autonomous loop）的箭头环 + 多 Agent 协作图
```

---

## 四、特殊页面提示词

### Slide — 12 Hacker Laws
```
标题：The 12 Hacker Laws（kali-claw 灵魂）
内容：12 条卡片网格，每张写 Law 编号 + 一句话
视觉： SOUL.md 卷轴展开效果
```

### Slide — 渗透全流程
```
标题：Engagement Lifecycle（端到端）
流程：Recon → Scan → Exploit → Post-Ex → Report
每阶段标注本仓库对应技能数
视觉：横向时间轴 + 章节封面缩略图缩略
```

### Slide — 与 MopMonk 对标
```
标题：对标 MopMonk（中国 CyberGym #1，73.1%）
对比维度：技能覆盖 / 场景数 / Agent 自主度
视觉：雷达图对比
```

### Slide — 总结 / 路线图
```
标题：Roadmap v0.1.44 → v0.2.0
内容：Wave 12 候选：vuln-reproduction-attack、agent-harness-engineering
视觉：路线图时间轴 + 未来技能虚位
```

---

## 五、AI 生成 PPT 的 Master Prompt

```
You are generating a 60-slide pitch deck for "kali-claw" — an AI penetration testing agent with 125 security skills.

Style: dark cyberpunk, neon green/red/blue accents on pure black background, monospace font (JetBrains Mono / Inter).
Tone: confident, technical, professional — like a DEF CON keynote.

Structure:
1. Cover (1 slide)
2. Skill matrix overview (1 slide, 13x10 grid)
3. 17 chapter cover slides (one per domain)
4. 35+ skill detail slides (2-3 skills per page, each with name + 30-char highlight + tool logos + MITRE ATT&CK ID badge)
5. 12 Hacker Laws slide
6. Engagement lifecycle slide
7. MopMonk benchmark comparison slide
8. Roadmap slide (v0.1.44 → v0.2.0)
9. Thank you / Q&A

For every skill slide include:
- Skill name (English) + Chinese label
- One-line highlight (~30 Chinese characters) from the data table
- Top 3 tool logos
- MITRE ATT&CK technique ID tag
- Background visual: terminal screenshot or topology diagram

Footer on every slide: "kali-claw v0.1.44 · 125 Skills · Kali Linux 2025.2 (ARM64)"
```

---

## 六、交付建议

- **推荐工具**：Gamma（最快，文字驱动）、Beautiful.ai（设计感强）、SlidesGPT（ChatGPT 集成）、Tome（叙事流畅）。
- **演讲场景**：技术分享 → 取 Chapter 1-9 + Chapter 17；投资人路演 → 取封面 + 矩阵 + Chapter 9/14/17 + 路线图；招聘 → 全集 60 页慢讲。
- **建议时长**：60 页 ≈ 45 分钟；30 页 ≈ 20 分钟；10 页 ≈ 5 分钟。
- **本地化**：英文版将中文亮点替换为英文 one-liner（每条不超过 12 个英文单词）。

---

**文档版本**：v1.0 · 2026-07-02 · 共 125 技能 + Agent 元能力
