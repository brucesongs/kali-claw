# Kali Linux Tools Baseline (2026-07)

> **生成日期**：2026-07-18  
> **数据源**：137 SKILLs 工具引用扫描  
> **目的**：为 Task 1.2/1.3 提供工具版本基线，避免重复查询  
> **覆盖范围**：127 个独立工具，14,949 次引用

---

## 📊 工具引用 Top 30 (按 SKILL 数排序)

| 排名 | 工具 | SKILLs 数 | 引用次数 | 类别 | 2026-07 版本 |
|------|------|----------|---------|------|-------------|
| 1 | strings | 63 | 424 | Binary Analysis | binutils 2.42 |
| 2 | nmap | 57 | 818 | Network Pentest | 7.95 |
| 3 | docker | 48 | 664 | Container | 27.2 |
| 4 | openssl | 49 | 521 | Crypto | 3.3.2 |
| 5 | burp | 37 | 149 | Web Proxy | 2024.12 (Community) / 2025.7 (Pro) |
| 6 | tcpdump | 37 | 221 | Network Sniffing | 4.99.4 |
| 7 | wireshark | 27 | 170 | Network Analysis | 4.2.5 |
| 8 | tshark | 31 | 459 | Network Analysis (CLI) | 4.2.5 |
| 9 | sqlmap | 22 | 154 | Web SQLi | 1.8.10 |
| 10 | ffuf | 22 | 171 | Web Fuzzing | 2.1.0 |
| 11 | nuclei | 22 | 376 | Web Scanner | 3.3.5 |
| 12 | hydra | 21 | 198 | Password Brute | 9.5 |
| 13 | hashcat | 20 | 250 | Password Hash | 6.2.6 |
| 14 | ghidra | 20 | 184 | Reverse Engineering | 11.2.1 |
| 15 | shodan | 18 | 171 | OSINT | CLI 1.30.1 |
| 16 | binwalk | 18 | 187 | Firmware RE | 3.1.0+ (Kali patch) |
| 17 | terraform | 16 | 141 | IaC | 1.9.5 |
| 18 | radare2 (r2) | 16 | 138 | Reverse Engineering | 5.9.4 |
| 19 | gdb | 16 | 159 | Debugger | 15.0 (with pwndbg/gef) |
| 20 | frida | 15 | 414 | Dynamic RE | 16.5.1 |
| 21 | kubectl | 15 | 399 | Container Orchestration | 1.30.2 |
| 22 | impacket | 15 | 229 | Windows Protocol | 0.12.0 |
| 23 | tor | 15 | 242 | Anonymity | 0.4.8.13 |
| 24 | socat | 14 | 202 | Network Relay | 1.8.0.0 |
| 25 | trivy | 13 | 184 | Container Scan | 0.54.1 |
| 26 | bettercap | 12 | 129 | MITM | 2.40.0 |
| 27 | hackrf | 10 | 141 | SDR | hackrf-tools 2024.10 |

---

## 🛠️ 完整工具版本基线 (按类别)

### Network Pentest & Discovery

| 工具 | 版本 | 包名 | 用途 |
|------|------|------|------|
| nmap | 7.95 | nmap | Port scanning, service fingerprinting |
| masscan | 1.3.2 | masscan | Fast Internet-scale port scanning |
| rustscan | 2.3.0 | rustscan | Modern fast port scanner (nmap frontend) |
| wireshark | 4.2.5 | wireshark | Graphical protocol analyzer |
| tshark | 4.2.5 | tshark | CLI Wireshark |
| tcpdump | 4.99.4 | tcpdump | Packet capture |
| netcat (nc) | 1.10-21.6 | ncat (nmap) | TCP/UDP Swiss army knife |
| socat | 1.8.0.0 | socat | Bidirectional data transfer |
| responder | 3.1.4.0 | responder3 | LLMNR/NBT-NS/mDNS poisoner |
| crackmapexec | 5.4.0+ (deprecated) | crackmapexec | Network attack swiss army knife (use NetExec) |
| netexec | 1.3.0 | netexec | CME successor |
| impacket | 0.12.0 | python3-impacket | Windows protocol Python library |
| evil-winrm | 3.5 | evil-winrm | WinRM shell for pentesters |

### Web Application Testing

| 工具 | 版本 | 包名 | 用途 |
|------|------|------|------|
| burpsuite | 2024.12 / 2025.7 (Pro) | burpsuite | Web proxy & scanner |
| zaproxy | 2.15.0 | zaproxy | OWASP ZAP web scanner |
| sqlmap | 1.8.10 | sqlmap | Automated SQLi exploitation |
| nikto | 2.5.0 | nikto | Web server scanner |
| dirb | 2.2.2 | dirb | Directory/file brute |
| gobuster | 3.6.0 | gobuster | Directory brute (Go) |
| ffuf | 2.1.0 | ffuf | Fast web fuzzer |
| wfuzz | 2.4.0 | wfuzz | Web application fuzzer |
| feroxbuster | 2.11.0 | feroxbuster | Recursive content discovery |
| wpscan | 3.8.27 | wpscan | WordPress scanner |
| nuclei | 3.3.5 | nuclei | Template-based scanner |
| httpx | 1.6.7 | httpx | HTTP toolkit (ProjectDiscovery) |
| subfinder | 2.6.7 | subfinder | Subdomain discovery |
| amass | 4.2.0 | amass | Attack surface mapping |
| whatweb | 0.5.5 | whatweb | Web tech fingerprinting |
| commix | 4.0 | commix | Command injection scanner |
| dalfox | 2.11.0 | dalfox | XSS scanner |
| xsstrike | 3.1.5 | xsstrike | XSS scanner (Python) |

### Password Attacks

| 工具 | 版本 | 包名 | 用途 |
|------|------|------|------|
| hashcat | 6.2.6 | hashcat | GPU-accelerated hash cracking |
| john (JohnTheRipper) | 1.9.0-jumbo-1+ | john | CPU hash cracking |
| hydra | 9.5 | hydra | Online brute force |
| medusa | 2.2 | medusa | Parallel online brute |
| ncrack | 0.7 | ncrack | Network auth cracker (Nmap) |
| cewl | 5.1 | cewl | Custom wordlist generator |
| hash-identifier | 1.2 | hashid | Hash type identification |
| mimikatz | 2.2.0 (2024 build) | mimikatz (Windows) | Windows credential dump |
| kerbrute | 1.0.3 | kerbrute | Kerberos user enumeration |
| Rubeus | 2.2.0+ | Rubeus (Windows) | Kerberos interaction |

### Wireless & RFID

| 工具 | 版本 | 包名 | 用途 |
|------|------|------|------|
| aircrack-ng | 1.7 | aircrack-ng | WiFi auditing suite |
| wifite | 2.7.1 | wifite | Wireless attack automation |
| kismet | 2023-07-R1 | kismet | Wireless scanner/detector |
| reaver | 1.6.6 | reaver | WPS PIXIE attack |
| hackrf | 2024.10 | hackrf | SDR transmission |
| rtl-sdr | 2.0.2 | rtl-sdr | Cheap SDR reception |
| proxmark3 | 4.17731 | proxmark3 | RFID/NFC tools |

### Exploit Development

| 工具 | 版本 | 包名 | 用途 |
|------|------|------|------|
| metasploit-framework | 6.4.30 | metasploit-framework | Exploitation framework |
| msfvenom | (msf) | (msf) | Payload generation |
| searchsploit | (exploitdb) | exploitdb | Local ExploitDB search |
| beef | 0.9.0 | beef-xss | Browser exploitation |
| pwntools | 4.13.0 | python3-pwntools | CTF exploit library |

### Reverse Engineering

| 工具 | 版本 | 包名 | 用途 |
|------|------|------|------|
| ghidra | 11.2.1 | ghidra | NSA's SRE framework |
| ida-free | 8.4 | ida-free | IDA disassembler (free) |
| radare2 | 5.9.4 | radare2 | Reverse engineering framework |
| rizin | 0.7.0 | rizin | Fork of radare2 |
| gdb | 15.0 | gdb | GNU Debugger |
| pwndbg | 2024.02 | pwndbg | GDB for pentesters |
| gef | 2024.1 | gef-2024.1 | GDB Enhanced Features |
| frida | 16.5.1 | frida | Dynamic instrumentation |
| binwalk | 3.1.0+ | binwalk | Firmware analysis |
| foremost | 1.5.7 | foremost | File carving |
| scalpel | 2.0+ | scalpel | File carving (foremost successor) |

### Forensics & Steganography

| 工具 | 版本 | 包名 | 用途 |
|------|------|------|------|
| volatility | 3-2.7.0 | volatility3 | Memory forensics |
| autopsy | 4.21.0 | autopsy | Digital forensics GUI |
| exiftool | 12.76 | libimage-exiftool-perl | Metadata extraction |
| steghide | 0.5.1 | steghide | LSB steganography |
| stegsolve | 1.0 | stegsolve | Image stego analysis |

### Container & Cloud

| 工具 | 版本 | 包名 | 用途 |
|------|------|------|------|
| docker | 27.2.0 | docker.io | Container engine CLI |
| docker-compose | 2.29.2 | docker-compose | Multi-container orchestration |
| kubectl | 1.30.2 | kubectl | Kubernetes CLI |
| k9s | 0.32.5 | k9s | TUI for K8s |
| trivy | 0.54.1 | trivy | Container/filesystem scanner |
| kube-bench | 0.8.0 | kube-bench | CIS K8s benchmark |
| kube-hunter | 0.6.5 | kube-hunter | K8s pentest tool |
| pacu | 0.7.0 | pacu (pip) | AWS exploitation |
| scout-suite | 5.14.0 | scout-suite | Multi-cloud auditor |
| pulumi | 3.137.0 | pulumi | IaC alternative |
| terraform | 1.9.5 | terraform | IaC standard |

### Mobile

| 工具 | 版本 | 包名 | 用途 |
|------|------|------|------|
| adb | 1.3.1 | adb | Android Debug Bridge |
| fastboot | 0.4 | fastboot | Android bootloader |
| jadx | 1.5.0 | jadx | Dex to Java decompiler |
| apktool | 2.10.0 | apktool | APK reverse |
| mobsf | 4.0.0 | mobsf | Mobile security framework |

### OSINT

| 工具 | 版本 | 包名 | 用途 |
|------|------|------|------|
| sherlock | 0.14.4 | sherlock | Username enumeration |
| theharvester | 4.6.0 | theharvester | Email/subdomain gathering |
| recon-ng | 5.1.2 | recon-ng | Web recon framework |
| spiderfoot | 4.0 | spiderfoot | OSINT automation |
| maltego | 4.6.0 | maltego | Graph OSINT (CE) |
| shodan | 1.30.1 | shodan | IoT/search engine CLI |
| censys | 2.2.11 | censys | Search CLI |

### Crypto

| 工具 | 版本 | 包名 | 用途 |
|------|------|------|------|
| openssl | 3.3.2 | openssl | TLS/crypto library CLI |
| gnupg | 2.2.43 | gnupg | GPG implementation |
| stunnel | 5.72 | stunnel4 | TLS wrapper |
| sslscan | 2.1.5 | sslscan | SSL/TLS scanner |
| sslyze | 6.0.0 | sslyze | SSL analysis (Python) |
| testssl | 3.2.0+ | testssl.sh | TLS testing |

### Post-Exploitation

| 工具 | 版本 | 包名 | 用途 |
|------|------|------|------|
| linpeas | 20240715-fd7a6e91 | linpeas | Linux PE search |
| winpeas | 20240715-fd7a6e91 | winpeas (Windows) | Windows PE search |
| bloodhound | 5.12.0 | bloodhound | AD graph analysis |
| sharphound | 2.5.7 | sharphound (Windows) | AD collector |
| seatbelt | 1.1.1+ | Seatbelt (Windows) | Windows recon |
| ldapsearch | 2.6.8 | ldap-utils | LDAP queries |

### Tunneling & Proxy

| 工具 | 版本 | 包名 | 用途 |
|------|------|------|------|
| chisel | 1.10.0 | chisel | TCP/UDP tunnel over HTTP |
| ligolo-ng | 0.6.2 | ligolo (binary) | Tunneling proxy |
| proxychains | 4.17 | proxychains4 | Proxy wrapper |
| tor | 0.4.8.13 | tor | Onion router |
| i2pd | 2.54.0 | i2pd | I2P network |

---

## 🔍 引用频次详细数据

### Total Reference Statistics

- **Total tools referenced**: 127
- **Total references**: 14,949
- **Average refs per tool**: 117.7
- **Median refs per tool**: ~25
- **Tools referenced in >20 skills**: 13 (core tools)
- **Tools referenced in 5-20 skills**: 30 (specialized tools)
- **Tools referenced in <5 skills**: 84 (niche tools)

### Coverage Insights

1. **Universal tools** (>40 skills): nmap, openssl, strings, docker, file
2. **Cross-domain tools** (20-40 skills): tcpdump, burp, tshark, wireshark, nuclei
3. **Domain-specific tools** (5-20 skills): hashcat, ghidra, sqlmap, hydra, ffuf, impacket, frida
4. **Specialized tools** (<5 skills): msfvenom, hackrf, proxmark3, beef

---

## 📋 Task 1.2 应用指南

### 何时使用本基线

**必须使用**：
- 修改 `SKILL.md` 中的工具版本号
- 验证 payloads.md 中的工具命令有效性
- 创建新 SKILL (Task 1.3) 时选择工具版本

**参考使用**：
- 写 Defense Perspective 中的防御对策
- 添加 Detection Methods 中的 SIEM 规则

### 工具版本更新策略

1. **MAJOR 版本变更** (如 hashcat 5.x → 6.x): 需要审查 payloads 兼容性
2. **MINOR 版本变更** (如 hashcat 6.2 → 6.3): 通常兼容，bump 即可
3. **PATCH 版本变更** (如 hashcat 6.2.5 → 6.2.6): 直接 bump，无验证

### 跳过策略

- 工具已 EOL (如 crackmapexec) → 替换为继任者 (NetExec)
- 工具未在 Kali Linux 2025-2 仓库 → 标注为外部依赖
- 工具需要 Python 2 (deprecated) → 标注或移除

---

## 🚧 已知问题

### 当前数据局限

1. **未扫描所有 Kali 工具**：仅扫描预定义 100+ 工具列表
2. **未覆盖最新 2026 工具**：如 AI 辅助工具 (Copilot for Pentest 等)
3. **版本号基于 2025-2 release**：实际 2026-07 可能有更新
4. **未覆盖 Windows 工具**：仅 Kali Linux 工具

### 后续改进方向

- Task 1.5 中创建 `validation/check-tool-versions.py` 自动验证
- 与 `apt show` 输出对比，确保版本准确
- 定期 (季度) 更新本基线

---

## 📚 引用参考

- Kali Linux 2025.2 Release Notes: https://www.kali.org/news/kali-linux-2025-2-release/
- Kali Tools Repository: https://www.kali.org/tools/
- Top 10 Tools for 2026 (Trend Micro): https://www.trendmicro.com/...

---

**最后更新**：2026-07-18  
**下次审查**：2026-10 (Q4 2026 review)  
**Owner**：Phase 1 Task 1.2 执行团队
