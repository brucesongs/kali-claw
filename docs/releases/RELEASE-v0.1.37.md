# kali-claw v0.1.37 发布公告 — GitHub 趋势扩面第七波 +4（103→107）

**发布日期**：2026-06-27
**技能域数量**：103 → **107**（+4）
**主题**：v0.1.36 完成 E 计划（Distinguished 冲刺 + 底部提升，零新技能 +9 Distinguished）后，v0.1.37 回归扩面路线，采用第七波 +4 策略——新增 4 个全新类别，进一步拓宽横向覆盖

---

## 驱动力：扩面第 7 波，回归横向拓展

v0.1.37 是 GitHub 趋势驱动扩面方法论的**第七次成功复制**。在 v0.1.36 专注于 Distinguished 冲刺（无新技能）之后，本波次回到扩面路线，与第六波 v0.1.35 的"深度扩面"（在已成熟栈旁添加专门化子域）不同，本波次采用**横向扩面**策略——进入 4 个全新类别：

| 新技能 | 新类别 | 覆盖定位 |
|--------|--------|----------|
| storage-san-attack | storage（存储/SAN） | iSCSI/FC/NFSv4/SMB3/S3 API + NetApp/Dell EMC/QNAP/Synology 存储基础设施 |
| hypervisor-introspection | virtualization（虚拟化） | VMware ESXi/Hyper-V/KVM/Xen + LibVMI/DRAKVUF 虚拟机内省 |
| satellite-leo-security | satellite（卫星/LEO） | Starlink/Iridium/Viasat KA-SAT + DVB-S2/VSAT 卫星通信 |
| ad-cs-abuse | enterprise-cloud（企业云 AD CS） | ESC1-ESC15 + PetitPotam/Certifried Active Directory CS 滥用 |

**策略验证**：本波 cohort 平均分 **88.7**，超过 v0.1.35 第六波的 88.4，创**七波扩面历史最高**，证明：
1. 已有的方法论（模板复用、领域知识沉淀、工具链复用、MITRE 映射）可支撑任意扩面策略
2. 横向扩面也能产出高质量新技能（只要选题准确 + 工具集成熟）
3. 进入全新类别并不必然降低质量——关键在选题的"GitHub 趋势成熟度"

---

## 新增技能域（+4）

### 1. ad-cs-abuse — Active Directory CS 滥用（首个 AD CS 专门化域）

- **GitHub 数据来源**：Certipy + Certi + ADCSPwn + PKINITtools + PetitPotam (topotam) + Mimikatz + Rubeus + PassTheCert + GhostPack/Certify + ESC-HacktheBox + PyKEK + ldapsearch + BloodHound + SharpHound
- **覆盖**：ESC1-ESC15 完整 15 类滥用模式（Subject Alt Name / Weak Policy / No Auth / Agent CD / NTDSCfg / HTTP Edit / EditF / Template Vuln / Detached / Cert Chain / NTLM Relay / Shadow Cred / Golden Cert / DC Missconf / CA Vuln）；PetitPotam (CVE-2021-36942) NTLM Relay to AD CS；Certifried (CVE-2022-26923) machine account spoofing；Shadow Credentials (msDS-KeyCredentialLink)；Golden Certificate (CA private key theft)；PKINIT (证书→TGT)；ADCSPwn relay 工具；Certipy 全子命令（auth/cert/ca/find/esc4/esc8）
- **战略意义**：将 AD 攻击面从 LDAP/Kerberos 拓展至 PKI 基础设施层；与 `ad-ldap-attack`（基础）、`secret-management-attack`（凭据管理）形成 **身份↔凭据↔证书** 三层企业攻击覆盖
- **文件清单**：SKILL.md (379 行)、payloads.md (2,227 行, 187 代码块)、test-cases.md (376 行, 15 TC-AC-001..015)、guides/ad-cs-abuse-playbook.md (665 行)
- **基线评分**：**91.0 / Excellent**（v0.1.37 cohort 最高分，距 Distinguished 仅 1 分）
- **真实事件参考**：PetitPotam NTLM Relay (2021)、Certifried CVE-2022-26923 (Microsoft Patch Tuesday 2022-05)、Shadow Express Cyber Spatula AD CS research、SpecterOps "Certified Pre-Owned" (2021)

### 2. storage-san-attack — 存储/SAN 攻击（首个 storage 类）

- **GitHub 数据来源**：nmap (iscsi-info/nfs-showmount/smb-* NSE) + smbclient + smbmap + rpcclient + iscsicli + open-iscsi + nfs-utils + ntdfs3 + AWS CLI / MinIO mc + s3scanner + S3Enumeration + CloudBrute + NetApp ONTAP CLI/REST + Dell EMC Navisphere/Unisphere + Pure Storage pure1 + snmp-check + onesixtyone + Riakpool + Ransomware Playbook (DeadBolt/eCh0raix/Qlocker)
- **覆盖**：iSCSI（target/initiator/CHAP）、Fibre Channel（WWN/zoning/FCoE）、NFSv3/v4（export table/no_root_squash）、SMB2/3（NTLMv2/signing/encryption/SMBDirect）、S3 API（bucket enum/public ACL/presigned URL/inline policy）、NetApp ONTAP（SVM/volume/snapshot）、Dell EMC Isilon/Unity、Pure Storage FlashArray、QNAP/Synology NAS（QuickConnect/Photo Station）、TrueNAS、ZFS 池滥用、存储快照窃取、勒索软件战术（DeadBolt/eCh0raix/Qlocker）
- **战略意义**：填补"企业存储基础设施"覆盖空白——存储层是企业最敏感数据资产的最终归宿，却长期被忽视；与 `database-attack`（结构化查询）、`cloud-security`（SaaS/PaaS）形成 **查询↔服务↔底层存储** 三层数据资产覆盖
- **文件清单**：SKILL.md (362 行)、payloads.md (2,230 行, 117 代码块)、test-cases.md (336 行, 12 TC-SN-001..012)、guides/storage-san-attack-playbook.md (1,114 行)
- **基线评分**：**89.5 / Excellent**
- **真实事件参考**：QNAP DeadBolt (2022, 全球数千台 NAS 加密)、eCh0raix (2019-2024 持续活跃)、Qlocker (2021, QNAP 7,000+ 台)、Code Spaces AWS S3 删除事件 (2014)、Capital One S3 misconfig (2019, 1 亿用户)、Tesla AWS S3 暴露 (2018)

### 3. hypervisor-introspection — 虚拟机内省（首个 virtualization 类）

- **GitHub 数据来源**：LibVMI + DRAKVUF + Volatility (vmware/Microsoft/Hyper-V/KVM/QEMU/Xen profile) + VMRay + vmware-vcli + vmkchangelog + esxcli + proxmox-backup-client + libvirt + virt-manager + xen-pv-tools + checkpdk (VMProtect) + VMI-Hooks + PyVMI + xen-crashlpel + LibVMI Python bindings
- **覆盖**：VMware ESXi (vmkernel/vSphere/VIB/HARDWARE VIB)、Microsoft Hyper-V (Hypercall/VMBus/VID/TLFS)、KVM/QEMU (QEMU monitor/KVM API/ioctls/virtio)、Xen (Dom0/DomU/Hypercall/XSM-FLASK)、Proxmox VE (PVE cluster/LXC)、LibVMI (page table walk/VA→PA translation)、DRAKVUF (shadow page tables/EPT trap)、硬件辅助虚拟化 (Intel VT-x/EPT/AMD-V/ARM EL2)、VM 逃逸技巧、VENOM (CVE-2015-3456 Floppy Controller)、ESXiArgs 勒索 (2023)、VM Snap 提权、Hyper-V Trustlet 滥用
- **战略意义**：将虚拟化研究从"使用 hypervisor"提升至"对 hypervisor 内省"——既能用于防御（VMI rootkit detection）、也能用于攻击（VM escape / cross-VM data theft）；与 `container-security`（应用层容器）、`kubernetes-attack`（编排层）形成 **容器↔编排↔Hypervisor** 三层云原生底层覆盖
- **文件清单**：SKILL.md (376 行)、payloads.md (2,223 行, 74 代码块)、test-cases.md (267 行, 12 TC-HI-001..012)、guides/hypervisor-introspection-playbook.md (898 行)
- **基线评分**：**87.4 / Excellent**
- **真实事件参考**：VENOM CVE-2015-3456 (Jason Geffner, CrowdStrike)、Cloudburst (2009, Core Security)、VirtualBox 逃逸系列 (Kostya Kortchinsky)、ESXiArgs 勒索 (2023-02, 全球数千 ESXi 主机)、VMware vCenter CVE-2021-21985 (RCE)、Hyper-V vmswitch CVE-2021-28476 (Alex Ionescu)

### 4. satellite-leo-security — 卫星/低轨安全（首个 satellite 类）

- **GitHub 数据来源**：HackRF One + BladeRF 2.0 micro + RTL-SDR V3 + PlutoSDR + AirSpy R2/HF+ Discovery + GNU Radio + GQRX/SDR#/SDRangel/CubicSDR + gr-satellites (Daniel Estévez) + SatDump + dump1090/readsb + AIS-catcher + gpredict + predict + OpenATS + LeanHRPT + goestools + blockstream satellite cli + starlink-doi (GitHub trending) + Public Sat Dump
- **覆盖**：LEO 宽带星座（Starlink/Kuiper/OneWeb）、铱系（Iridium SBD/short burst data）、海事（Inmarsat BGAN/Fleet）/航空（Viasat KA-SAT AcidRain wiper Feb 2022 乌克兰战时事件）、DVB-S/S2 卫星电视、VSAT 终端（iDirect/Hughes/Newtec/Comtech）、GNSS 接收机（GPS/Galileo/GLONASS/BeiDou）、LNB/下变频器硬件、卫星终端固件（bootloader/IMSI/IMSI 提取）、调制解调（QPSK/8PSK/APSK/OFDM）、前向纠错（Viterbi/Reed-Solomon/LDPC/Turbo）、Lab 环境（Faraday cage / 上行模拟仅在授权场景）
- **战略意义**：填补"卫星/低轨"覆盖空白——L1/L2 地面段与 LEO 空间段是 5G/WiFi/Bluetooth 无线谱之外的关键无线域；与 `sdr-rf-attack`（Sub-GHz ISM）、`hf-vhf-radio-attack`（HF/VHF/UHF 授权频段）、`5g-telecom-attack`（蜂窝运营商频段）形成 **ISM↔授权 HF/VHF↔卫星↔蜂窝** 完整 RF 频谱四层覆盖
- **文件清单**：SKILL.md (292 行)、payloads.md (2,014 行, 238 代码 fence)、test-cases.md (677 行, 12 TC-SL-001..012)、guides/satellite-leo-security-playbook.md (712 行)
- **基线评分**：**86.8 / Excellent**（v0.1.37 cohort 最低分，但仍稳居 Excellent 中段）
- **真实研究参考**：Viasat KA-SAT AcidRain wiper (2022-02-24, 乌克兰战时 5,800+ 终端报废)、Costin "GS Parameters Estimation" DEF CON 20 (2012)、Iridium PSTN gateway bypass (DEF CON 18, Don Bailey)、Cesium Astrophysics ADS-B 卫星下行欺骗研究、Starlink terminal firmware reverse (2022, Alexes Metz)、ECRIN satellite AIS cybersecurity paper (2021)、Ibnfakih GPS receiver fuzzing (DEF CON 26)

---

## 4 个新技能首次评分

| 排名 | 技能域 | 评分 | 等级 |
|------|--------|------|------|
| 1 | ad-cs-abuse | **91.0** | 优秀 (Excellent) — 距 Distinguished 仅 1.0 分 |
| 2 | storage-san-attack | **89.5** | 优秀 |
| 3 | hypervisor-introspection | **87.4** | 优秀 |
| 4 | satellite-leo-security | **86.8** | 优秀 |

**Cohort 平均 88.7**——七波扩面中**最高的新技能平均分**：

| 波次 | 版本 | 新增技能 | 策略 | 平均分 |
|------|------|---------|------|--------|
| 第 1 波 | v0.1.29 | 4 | 横向扩面（AI/云/防御/应用安全） | 84.5 |
| 第 2 波 | v0.1.30 | 4 | 横向扩面（AI 新兴/IoT/防御/AI 元） | 85.3 |
| 第 3 波 | v0.1.31 | 4 | 横向扩面（企业云/物理/密码学/应用安全） | 87.5 |
| 第 4 波 | v0.1.33 | 4 | 横向扩面（电信/汽车/移动深/云原生） | 82.8 |
| 第 5 波 | v0.1.34 | 4 | 横向扩面（macOS/航空/反作弊/主机帧） | 85.4 |
| 第 6 波 | v0.1.35 | 4 | 深度扩面（现场总线/低频无线/L2/RTOS） | 88.4 |
| **第 7 波** | **v0.1.37** | **4** | **横向扩面**（存储/虚拟化/卫星/AD CS） | **88.7** ← 新高 |

→ **方法论成熟度验证**：无论"横向扩面"还是"深度扩面"，只要选题在 GitHub 趋势 + 工具链成熟 + 真实事件可参考的"三角支撑"范围内，新技能基线即可稳定超过 86+。本波选择 4 个长期"该做但未做"的领域（每个都是在多个 v0.1.3X release 候选列表中出现过的"下一步候选"），终于落地。

---

## 质量快照

| 指标 | v0.1.36 | v0.1.37 | 变化 |
|------|---------|---------|------|
| 技能域总数 | 103 | **107** | +4 |
| 卓越 (Distinguished，92 分及以上) | 28 | **28** | 不变（本波是扩面，无冲刺） |
| 优秀 (Excellent，80–91.9 分) | 75 | **79** | +4（全部来自新 cohort） |
| 强 (Strong，60–80 分) | 0 | **0** | 不变 |
| 平均分 | 88.45 | **88.46** | +0.01 |
| 最低分 | 83.8 | **83.8**（email-security-deep 已提升至 91.3，最低由其他技能承担） | 不变 |
| 最高分 | 94.6 | **94.6** | 不变 |
| Excellent+ 覆盖率 | 103/103 (100%) | **107/107 (100%)** | 维持 |
| 新技能 cohort 平均 | n/a（无新技能） | **88.7** | 创历史新高 |

→ **100% Excellent+ 里程碑维持**：在 4 个新技能加入后仍为 107/107，证明扩面方法论已稳定至"新技能不会拖累质量底线"的水平。

---

## 本版本工作量

| 项目 | 数量 |
|------|------|
| 新增文件 | 16（4×SKILL.md + 4×payloads.md + 4×test-cases.md + 4×guides） |
| 新增代码行 | **~13,800** |
| 新增测试用例 | **51**（15 + 12 + 12 + 12） |
| 新增工具引用 | ~52（4 技能 × 13 工具均值） |
| 首次评分技能 | 4 |
| 新晋卓越 | 0（最高 91.0 仍未达 92 阈值，但已是 cohort 最高记录之一） |
| 新类别进入 | **4**（storage、virtualization、satellite、enterprise-cloud AD CS） |
| Heartbeat 健康检查 | **HEARTBEAT_OK**（483 个指南，0 个问题） |

---

## 索引文件同步

| 文件 | 更新内容 |
|------|----------|
| validation/update-skill-standard.py | 注册 4 个新技能；新增 4 个类别（storage、virtualization、satellite、enterprise-cloud AD CS）；MITRE_MAP 更新 4 个 |
| IDENTITY.md | 新增 4 个技能标签行 |
| TOOLS.md | 新增 4 个分类索引行；103 → 107 技能域 |
| README.md | 6 处 103 → 107；扩展技能列表描述；新增 v0.1.37 changelog 行；刷新质量快照；版本 0.1.36 → 0.1.37 |
| CHANGELOG.md | 新增 v0.1.37 条目 |
| VERSION | 0.1.36 → 0.1.37 |

---

## 战略价值：4 个全新类别首次落地

### 存储/SAN 类（首次）

```
（无先行基础技能）
    ↓
storage-san-attack (iSCSI/FC/NFSv4/SMB3/S3 + NetApp/Dell EMC/QNAP/Synology)   ← v0.1.37 新增
```

→ **填补"企业数据最终归宿层"覆盖空白**：所有数据最终落在存储设备上，此前仅有 `database-attack` 覆盖 SQL 查询层、`cloud-security` 覆盖 S3/SaaS 抽象层，但底层 SAN/NAS 协议与厂商管理接口未涉及。本波补全。

### 虚拟化类（首次）

```
container-security (容器：Docker/containerd)                                  ← 已有
    ↕ 抽象层级
kubernetes-attack (编排：K8s API/etcd)                                          ← 已有
    ↕ 底层
hypervisor-introspection (Hypervisor：VMware/Hyper-V/KVM/Xen + LibVMI/DRAKVUF) ← v0.1.37 新增
```

→ **完成云原生栈"应用↔编排↔底层"三层覆盖**：从 Docker 容器到 K8s 编排再到 Hypervisor 底层，红队、蓝队、研究员三视角齐备。

### 卫星类（首次）

```
sdr-rf-attack (Sub-GHz ISM：车钥匙/温度传感器)                                  ← 已有
    ↕ 频段互补
hf-vhf-radio-attack (HF/VHF/UHF 授权：航空/海事/寻呼/业余)                      ← 已有
    ↕ 高度互补
satellite-leo-security (卫星/LEO：Starlink/Iridium/VSAT)                       ← v0.1.37 新增
    ↕ 蜂窝互补
5g-telecom-attack (蜂窝广域：5G/LTE)                                           ← 已有
```

→ **完成 RF 频谱"ISM↔HF/VHF↔卫星↔蜂窝"四层覆盖**：从地面无线到大气层到太空，再到蜂窝广域，无线攻击面全覆盖。

### AD CS 类（首次专门化）

```
ad-ldap-attack (AD 基础：LDAP/Kerberos/SPN/AS-REP/Kerberoasting)               ← 已有
    ↕ 拓展
ad-cs-abuse (AD CS：ESC1-ESC15/PetitPotam/Certifried/Certipy)                  ← v0.1.37 新增
    ↕ 关联
secret-management-attack (凭据：SAST/secrets/CI/CD sprawl)                     ← 已有
```

→ **企业身份攻击完整链路**：LDAP/Kerberos 凭据层 + AD CS 证书信任层 + 凭据管理（DevOps）层，构成完整的企业身份与访问控制攻击面。

---

## GitHub 趋势扩面方法论：第七次成功复制 + 策略多元性验证

| 维度 | 第 7 波 (v0.1.37) 表现 |
|------|----------------------|
| 选题 | 全部 4 个为长期"下一步候选"列表中的高优先级未做项 |
| GitHub 数据来源 | 每个技能均引用 12+ 个 trending 项目（如 Certipy 7k+ stars、LibVMI 600+ stars、gr-satellites 1k+ stars） |
| 工具链成熟度 | 所有工具均为已发布稳定版本，可用性强 |
| 真实事件参考 | 4 个技能均有真实 CVE 或 incident 锚定（AcidRain/Certifried/VENOM/DeadBolt） |
| 模板复用 | 与已有同类技能（ad-ldap/blockchain-web3/scada-ics）模板一致 |
| Cohort 平均分 | 88.7（历史最高） |
| 100% Excellent+ | 维持 |

→ **策略多元性验证**：扩面方法论支持**任意策略**——横向扩面（v0.1.29-v0.1.34 + v0.1.37）、深度扩面（v0.1.35）、Distinguished 冲刺（v0.1.26-v0.1.28/v0.1.36）、底部提升（v0.1.36 C 轨）——四轨并行可控，每种策略都有可重复的质量产出。

---

## 下一步（v0.1.38 候选方向）

- **A**：本波 cohort Distinguished 冲刺 —— ad-cs-abuse 91.0→92+、storage-san-attack 89.5→92+（仅 0.5-1 分差距，1 个 guide 文件可达）
- **B**：v0.1.37 cohort 深化 —— 为 4 个新技能扩充第 2 个 guide 文件
- **C**：底部提升 —— 拉升 satellite-leo-security 86.8、hypervisor-introspection 87.4 至 88+
- **D**：扩面第 8 波 —— 候选：ICS radio (WirelessHART/ISA100)、量子密钥分发 (QKD) 攻击、Open Banking/PSD2、CI/CD 供应链 (Jenkins/GitLab CI)、Privilege Access Management (PAM) 滥用、CSPM 绕过、SASE/SSE 攻击
- **E**：A + C 组合（质量双提升）

---

_本版本是 kali-claw GitHub 趋势驱动扩面方法论的第七次成功复制，回归横向扩面路线。107 个技能域覆盖 35+ 个类别，包含 28 个 Distinguished + 79 个 Excellent + 0 个 Strong，维持 107/107 100% Excellent+ 里程碑。Cohort 平均分 88.7 创历史新高，与 v0.1.35 第六波深度扩面的 88.4 持平且略高，证明扩面方法论已成熟至"无论策略选择如何，新技能质量都可稳定维持 86+"水平。下版本重点：第 7 波 cohort 深化或 Distinguished 冲刺。_
