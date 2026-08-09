# pam-privilege-attack — 使用说明与能力评估

> **评估日期**：2026-08-09 | **评估者**：Claude（自动化 + 人工审查） | **评估版本**：v0.2.0.2
> **总分**：**81/100（优秀）** | **问题**：P0:0 P1:0 P2:1 P3:2
> **Wave 1 Batch 1**（第 7 个评估的 SKILL）

## 评估速览

| 维度 | 得分（1-5） | 说明 |
|------|-----------|------|
| 1. 合规性 | **5** | 0/0/0 |
| 2. 内容完整性 | **5** | payloads 2463 + test-cases **445**（本批比率最佳，18%）+ 1 guide；14 H2 + 24 H3 |
| 3. 命令语法 | **4** | Linux PAM 工具可用（pam_*.so 全在）；pamtester / unix_chkpwd 缺；商业 PAM（CyberArk/BeyondTrust）theory-only |
| 4. 参考文献 | **5** | **24 URL + 3 CVE** — 本批 URL 密度最佳 |
| 5. MITRE/OWASP 对齐 | **4** | 7 个 ATT&CK T-codes（T1098/T1550.x/T1552.x）；frontmatter 仅 T1552（7 缺 6） |
| 6. 可用性 | **4** | 商业 PAM 覆盖清晰（CyberArk/BeyondTrust/Delinea/ManageEngine）；免费 PAM 替代品覆盖薄 |
| **加权总分** | **81/100** | **优秀** — 顶级 SKILL |

---

## 使用说明

### 这个 SKILL 做什么
特权访问管理（PAM）攻击面：CyberArk、BeyondTrust、Delinea（原 Thycotic）、ManageEngine PAM360。涵盖：保险库凭据提取、会话劫持、EPM（终端特权管理）绕过、SSH 密钥窃取、即时（JIT）提权滥用。

### 何时使用
1. 企业渗透，目标使用 CyberArk/BeyondTrust/Delinea 做凭据保险
2. 即时特权提升的红队评估
3. 内部威胁评估（保险库管理员滥用）
4. PAM 部署审计（实施审查）
5. 涉及疑似保险库被攻陷的事件响应

### 如何开始
1. **识别 PAM 厂商**：从侦察（CyberArk Password Vault web 在 443/Apache；BeyondTrust 在 443/IIS；Delinea Secret Server 在 443/IIS）
2. **评估保险库元数据**：CyberArk PSMP 在 22/SSH；检查 `psmapp.appid` cookie
3. **检查默认账户**：CyberArk Administrator / Auditor / PasswordManager（旧版本默认值已知）
4. **找 EPM agent**：BeyondTrust EPM、CyberArk EPM、Delinea Endpoint Privilege Manager — 若存在则本地提权向量
5. **SSH 密钥恢复**：若 CyberArk PSMP 在用，所有 admin SSH 流经它；攻陷 PSMP = 攻陷所有目标

### 新手常见坑
- **保险库管理员 ≈ 域管理员**：保险库存放所有特权凭据；保险库管理员须最高级别谨慎
- **PSM 录制缺口**：某些协议（RDP 文件传输、剪贴板）在旧 PAM 版本可能未录
- **EPM 绕过**：原生 Windows 令牌操作（`NtSetInformationToken`）常绕过用户态 EPM
- **API token 泄漏**：CyberArk REST API token 常在自定义自动化脚本中泄漏
- **紧急访问账户**：CyberArk Break Glass / BeyondTrust Recovery Console 常为共享密钥 — 高价值目标

### 交叉引用
- `secret-management-attack`（更广密钥基础设施：HashiCorp Vault、AWS Secrets Manager）— 非 PAM 密钥存储切换
- `privilege-escalation`（OS 层 PE）— 已在主机寻求更高特权时切换
- `post-exploitation`（通用后渗透）— 初始立足后的广度切换
- `ad-cs-abuse` — Active Directory Certificate Services 攻击切换
- `cloud-identity-attack` — 云 IAM（Entra ID / Okta）切换

---

## 能力评估详情

### D1: 5/5 | D2: 5/5（445 行 test-case 比率优秀）

### D3: 4/5
- **VM 工具可用性**：
  - ✓ Linux PAM 模块（`/usr/lib/aarch64-linux-gnu/security/pam_*.so`：pam_access、pam_canonicalize_user、pam_debug、pam_deny 等）
  - ✓ `/etc/pam.d/` 配置结构在
  - ✓ `/etc/ssh/sshd_config`（sshd 在）
  - ✗ `pamtester`（测试工具 — `apt install pamtester`）
  - ✗ `unix_chkpwd`（辅助；通常在 libpam-runtime 但此处缺）
  - ✗ 商业 PAM 工具（CyberArk/BeyondTrust/Delinea）— 本质 theory-only
- **静态审查**：payloads 引用真实 CyberArk CLI（PACLI、cpass、PSMP）、BeyondTrust API、Delinea Secret Server API — 全部有效
- **证据**：[evidence/2026-08-09/summary.md](../evidence/2026-08-09/summary.md)

### D4: 5/5
- 24 URL（CyberArk 文档、BeyondTrust 文档、厂商安全公告等）— Wave 1 Batch 1 中 URL 密度最佳
- 3 CVE（需更多 — CyberArk CVE-2025-26652、BeyondTrust RSA exploitation 2024）

### D5: 4/5
- 7 个 ATT&CK T-codes（T1098 Account Manipulation、T1550 Use Alternate Auth Material、T1550.002 Pass the Hash、T1550.004 Web Session Cookie、T1552 Unsecured Credentials、T1552.001 Credentials In Files、T1552.004 Private Keys）— 强
- frontmatter 仅 `T1552-Unsecured Credentials`（7 缺 6）— 表达不足

### D6: 4/5
- 优点：清晰按厂商分章（CyberArk / BeyondTrust / Delinea / ManageEngine）含具体命令和 API
- 不足：开源 PAM 替代品（Wallix、Xton、Devolutions）覆盖薄；仅 1 guide

---

## 问题与优先级

| ID | 优先级 | 描述 | 推荐修复 |
|----|-------|------|---------|
| F-001 | P2 | `pamtester` / `unix_chkpwd` 不在 Kali 2026.1 默认 | payloads 补 `apt install pamtester libpam-runtime` |
| F-002 | P3 | 仅 3 CVE 引用，尽管厂商 CVE 持续曝出 | 补：CyberArk CVE-2025-26652（PSM）、BeyondTrust breach（2024-12）、Delinea 公告 |
| F-003 | P3 | frontmatter mitre 字段过窄（7 个 T-codes 仅 1） | 扩展为 `"T1098-Account Manipulation, T1550-Use Alternate Authentication Material, T1550.002-Pass the Hash, T1550.004-Web Session Cookie, T1552-Unsecured Credentials, T1552.001-Credentials In Files, T1552.004-Private Keys"` |
| F-004 | P3 | 仅 1 guide；至少需 playbook | 补 `guides/pam-privilege-attack-playbook.md`（按厂商工作流） |

---

## 验证证据

- [evidence/2026-08-09/summary.md](../evidence/2026-08-09/summary.md)
- [evidence/2026-08-09/lint.json](../evidence/2026-08-09/lint.json)
- Kali VM：parallels@10.211.55.5（Kali 2026.1，aarch64）

## 评估签字
- 评估者：Claude（Wave 1 Batch 1，SKILL 5/5 — 批次完成）
- 批准人：_______________ 日期：_______
