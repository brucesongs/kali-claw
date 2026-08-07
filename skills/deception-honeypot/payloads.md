# Deception & Honeypot Payloads / Reference

> Companion to `SKILL.md`. Every command and config here is reproducible on a Linux host within an authorized scope. Verify engagement scope and legal authorization before deploying any of these.
>
> Placeholder convention: `<honeypot_ip>` is the decoy host's IP, `<prod_ip>` is a production host, `<SIEM>` is your SIEM endpoint, `<API_KEY>` is a third-party API key (VirusTotal, Shodan, AbuseIPDB, MISP), `<TOKEN>` is a Canarytoken or honeytoken string.

---

## Table of Contents

1. Cowrie SSH/Telnet Deployment & Configuration
2. OpenCanary Multi-Service Configuration
3. HFish Enterprise Honeypot
4. Conpot ICS/SCADA Honeypot (Modbus, S7, IEC-104)
5. T-Pot All-in-One Deployment
6. Beelzebub AI-Driven Deception Runtime
7. Honeytoken Design (Fake Credentials, Canary Files, Honey-URLs)
8. Canarytokens Deployment (Thinkst)
9. Network Deception (Syn-Ack Dark Space, Tarpits, Honeyports)
10. Email/Web Honeypots (Spam Traps, Glastopf)
11. Database Honeypots (HoneyDB, MySQL Fake, Elasticpot)
12. Log Analysis & IOC Extraction Pipelines
13. Deception Architecture Cheat Sheet

---

## 1. Cowrie SSH/Telnet Deployment & Configuration

### 1.1 Install Cowrie

```bash
# Debian/Ubuntu prerequisites
sudo apt update
sudo apt install -y python3 python3-venv python3-dev \
  build-essential libssl-dev libffi-dev \
  git curl authbind

# Create a dedicated non-root user
sudo adduser --disabled-password --gecos "" cowrie

# Switch to cowrie user
sudo -u cowrie -i

# Clone and set up the virtualenv
git clone https://github.com/cowrie/cowrie.git ~/cowrie
cd ~/cowrie
python3 -m venv cowrie-env
source cowrie-env/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### 1.2 Configuration

```bash
# Copy the sample config
cp etc/cowrie.cfg.dist etc/cowrie.cfg
```

Edit `etc/cowrie.cfg` for the engagement:

```ini
[honeypot]
# The hostname displayed to attackers — make it realistic
hostname = prod-web-07
# Sensor name for log tagging
sensor_name = cowrie-dmz-01
# Pretended OS
pretend_version = Ubuntu 22.04 LTS

[ssh]
# Listening port (use 22 if you have authbind configured; 2222 is simpler for testing)
listen_endpoints = tcp:2222:interface=0.0.0.0

[telnet]
listen_endpoints = tcp:2323:interface=0.0.0.0

[output_jsonlog]
# JSON log for SIEM ingestion
enabled = true
logfile = var/log/cowrie/cowrie.json
epoch_timestamp = false

[output_splunk]
# Optional: forward directly to Splunk HTTP Event Collector
enabled = false
# url = https://splunk.example.org:8088/services/collector
# token = <HEC_TOKEN>

[output_virustotal]
# Optional: auto-submit uploads to VirusTotal
enabled = false
# api_key = <VT_KEY>
# upload = true
```

### 1.3 Generate the Honeypot Host Key

```bash
# Cowrie needs an SSH host key (NOT the production host's key)
ssh-keygen -t ed25519 -f var/lib/cowrie/ssh_host_ed25519_key -N ""
ssh-keygen -t rsa -b 2048 -f var/lib/cowrie/ssh_host_rsa_key -N ""
```

### 1.4 Run Cowrie

```bash
# Foreground (testing)
bin/cowrie fg

# Daemonized
bin/cowrie start
bin/cowrie status
bin/cowrie stop
```

### 1.5 systemd Unit (Production)

```ini
# /etc/systemd/system/cowrie.service
[Unit]
Description=Cowrie SSH/Telnet Honeypot
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
User=cowrie
Group=cowrie
WorkingDirectory=/home/cowrie/cowrie
ExecStart=/home/cowrie/cowrie/bin/cowrie start
ExecStop=/home/cowrie/cowrie/bin/cowrie stop
Restart=always
RestartSec=5
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now cowrie
```

### 1.6 Listening on Privileged Port 22 via authbind

```bash
# Allow cowrie to bind port 22 without root
sudo touch /etc/authbind/byport/22
sudo chown cowrie:cowrie /etc/authbind/byport/22
sudo chmod 755 /etc/authbind/byport/22
# Then set in cowrie.cfg:
#   [ssh] listen_endpoints = tcp:22:interface=0.0.0.0
```

### 1.7 The Fake Filesystem (fsctl)

```bash
# Cowrie ships a pickle-backed fake filesystem in honeyfs/
# Use fsctl to add/modify files
source cowrie-env/bin/activate
python bin/fsctl

# At the fsctl prompt:
#   add /etc/issue /etc/issue    # mirror a real file
#   edit /etc/passwd              # edit a fake passwd
#   list /
```

### 1.8 Realistic Fake `passwd`

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
jenkins:x:1001:1001:Jenkins:/var/lib/jenkins:/bin/bash
postgres:x:114:118:PostgreSQL administrator:/var/lib/postgresql:/bin/bash
```

### 1.9 Realism Checklist

- [ ] `hostname` matches a plausible production host
- [ ] `pretend_version` matches the org's OS version
- [ ] SSH banner (`SSH-2.0-OpenSSH_X.Y`) matches the org's fleet
- [ ] Fake `passwd`/`shadow` include plausible accounts
- [ ] Fake `~/.bash_history` exists with realistic-looking commands
- [ ] Fake `/var/log/` includes auth.log, syslog, etc.
- [ ] Fake `/etc/ssh/sshd_config` exists (matches production look)

### 1.10 Common Cowrie Events (eventid)

| eventid | Meaning |
|---------|---------|
| `cowrie.session.connect` | TCP connection established |
| `cowrie.login.failed` | Failed login attempt (capture creds) |
| `cowrie.login.successful` | Successful login (Cowrie accepts many) |
| `cowrie.command.input` | Command typed by attacker |
| `cowrie.command.success` | Command completed |
| `cowrie.session.file_download` | Attacker downloaded a file (URL captured) |
| `cowrie.session.file_upload` | Attacker uploaded a file (sample saved) |
| `cowrie.session.closed` | Session ended |

### 1.11 Sample cowrie.json Event

```json
{
  "eventid": "cowrie.login.failed",
  "timestamp": "2026-06-16T12:34:56.789000Z",
  "src_ip": "203.0.113.45",
  "src_port": 54321,
  "dst_ip": "198.51.100.10",
  "dst_port": 2222,
  "session": "abc123def456",
  "username": "root",
  "password": "toor",
  "message": "login attempt [root/toor] failed"
}
```

### 1.12 Forwarding Cowrie Logs to Splunk via HEC

```ini
[output_splunk]
enabled = true
url = https://splunk.example.org:8088/services/collector
token = <HEC_TOKEN>
index = honeypot
sourcetype = cowrie:json
```

Splunk SPL to query:

```spl
index=honeypot sourcetype=cowrie:json
| stats count by src_ip, username, password
| sort -count
```

### 1.13 Forwarding Cowrie Logs to Elastic via Filebeat

```yaml
# /etc/filebeat/inputs.d/cowrie.yml
- type: log
  enabled: true
  paths:
    - /home/cowrie/cowrie/var/log/cowrie/cowrie.json
  json.keys_under_root: true
  json.add_error_key: true
  fields:
    source: honeypot
    honeypot_type: cowrie
  fields_under_root: true
```

Kibana KQL:

```
source:"honeypot" AND honeypot_type:"cowrie" AND eventid:"cowrie.login.successful"
```

---

## 2. OpenCanary Multi-Service Configuration

### 2.1 Install OpenCanary

```bash
# Install via pip (recommend virtualenv)
sudo apt install -y python3-dev python3-pip libffi-dev libssl-dev
sudo pip3 install virtualenv
sudo virtualenv /opt/canary-env
sudo /opt/canary-env/bin/pip install opencanary
```

### 2.2 Generate Default Config

```bash
sudo /opt/canary-env/bin/opencanaryd --copyconfig
# Lands at /etc/opencanaryd/opencanary.conf
```

### 2.3 Example Multi-Service Config

```json
{
  "device.name": "internal-fileshare-3",
  "device.description": "Dell PowerEdge R740",
  "device.ip_address": "10.20.30.40",
  "device.mac_address": "00:11:22:33:44:55",

  "loglevel": 20,

  "logger": {
    "class": "PySysLoggerEventLogger",
    "kwargs": {"ident": "opencanary"}
  },

  "ssh.enabled": true,
  "ssh.port": 22,
  "ssh.version": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4",

  "http.enabled": true,
  "http.port": 80,
  "http.skin": "nasLogin",
  "http.banner": "Apache/2.4.52 (Ubuntu)",

  "https.enabled": true,
  "https.port": 443,
  "https.skin": "nasLogin",
  "https.cert": "/etc/opencanaryd/ssl/cert.pem",
  "https.key": "/etc/opencanaryd/ssl/key.pem",

  "ftp.enabled": true,
  "ftp.port": 21,
  "ftp.banner": "Microsoft FTP Service",
  "ftp.expected_user": "guest",
  "ftp.expected_password": "guest",

  "smb.auditfile": "/var/log/opencanary/smb-audit.log",
  "smb.enabled": true,

  "mssql.enabled": true,
  "mssql.port": 1433,
  "mssql.version": "Microsoft SQL Server 2019",

  "redis.enabled": true,
  "redis.port": 6379",

  "rdp.enabled": true,
  "rdp.port": 3389,

  "vnc.enabled": true,
  "vnc.port": 5900,

  "mysql.enabled": true,
  "mysql.port": 3306,
  "mysql.banner": "5.7.40-0ubuntu0.18.04.1",

  "ntp.enabled": true,
  "ntp.port": 123,

  "snmp.enabled": true,
  "snmp.port": 161,

  "tftp.enabled": true,
  "tftp.port": 69,

  "telnet.enabled": true,
  "telnet.port": 23,
  "telnet.banner": "Cisco Systems Console",

  "tcpbanner.enabled": true,
  "tcpbanner.port": 2222,
  "tcpbanner.data": "HELLO\r\n",

  "git.enabled": true,
  "git.port": 9418",

  "httpproxy.enabled": true,
  "httpproxy.port": 8080,

  "portscan.enabled": true,
  "portscan.logfile": "/var/log/opencanary/portscan.log"
}
```

### 2.4 Run OpenCanary

```bash
# Need root for ports < 1024
sudo /opt/canary-env/bin/opencanaryd --start
sudo /opt/canary-env/bin/opencanaryd --stop
sudo /opt/canary-env/bin/opencanaryd --restart
sudo /opt/canary-env/bin/opencanaryd --dev
```

### 2.5 Alert via Slack Webhook

```json
{
  "logger": {
    "class": "JSONLogEventLogger",
    "kwargs": {"filename": "/var/log/opencanary/opencanary.log"}
  }
}
```

```bash
# Pipe to Slack via a tail + curl loop
tail -F /var/log/opencanary/opencanary.log | while read line; do
  msg=$(echo "$line" | jq -r '"\(.log_type) \(.dst_port): from \(.src_host)"')
  curl -s -X POST "$SLACK_WEBHOOK" \
    -H "Content-Type: application/json" \
    -d "{\"text\": \"Honeypot alert: $msg\"}"
done
```

### 2.6 Sample OpenCanary Alert (syslog)

```
Jun 16 12:34:56 internal-fileshare-3 opencanary[1234]: Log Type: 6001 (HTTP GET) 
  src_host: 10.20.30.50  src_port: 54321  dst_host: 10.20.30.40  dst_port: 80 
  logdata: {"HTTP_METHOD": "GET", "HTTP_PATH": "/" }
```

### 2.7 Sigma Rule for OpenCanary Events

```yaml
title: OpenCanary Honeypot - Any Service Hit
id: a1b2c3d4-0010-4000-8000-000000000002
status: stable
description: Any OpenCanary service interaction is unauthorized
logsource:
  product: linux
  service: syslog
  ident: opencanary
detection:
  selection:
    ident: opencanary
  condition: selection
level: high
```

---

## 3. HFish Enterprise Honeypot

### 3.1 Docker Deployment

```bash
mkdir -p /opt/hfish && cd /opt/hfish

# Pull and run the HFish server (the management node)
docker run -d --name hfish \
  --restart=always \
  -p 4433:4433 \
  -p 4434:4434 \
  -v /opt/hfish:/opt/hfish \
  --privileged \
  hfish/hfish:latest
```

### 3.2 Access the Console

```
URL:          https://<hfish_host>:4433/
Initial user: admin
Initial pass: admin  # CHANGE IMMEDIATELY
```

### 3.3 Enroll Endpoints (Agents)

On each remote honeypot host:

```bash
# Linux agent
docker run -d --name hfish-agent \
  -e HFISH_SERVER=https://<hfish_host>:4433 \
  -e HFISH_USER=admin \
  -e HFISH_PASS=<changed_password> \
  -e ENDPOINT_NAME=dmz-decoy-02 \
  -e ENDPOINT_IP=0.0.0.0 \
  --net=host \
  --privileged \
  hfish/hfish-agent:latest
```

Windows agent (PowerShell as Administrator):

```powershell
# Download the HFish Windows agent
Invoke-WebRequest -Uri "https://github.com/hacklcx/HFish/releases/latest/download/hfish-agent-windows-amd64.zip" -OutFile "hfish-agent.zip"
Expand-Archive hfish-agent.zip -DestinationPath C:\hfish-agent
cd C:\hfish-agent
.\hfish-agent.exe `
  -server https://<hfish_host>:4433 `
  -user admin `
  -pass <changed_password> `
  -name internal-decoy-01
```

Register as a Windows service:

```powershell
sc.exe create hfish-agent binPath= "C:\hfish-agent\hfish-agent.exe -server https://... " start= auto
sc.exe start hfish-agent
```

### 3.4 Protocol Templates

HFish comes with built-in templates. Enable per endpoint in the console:

| Template | Port | Description |
|----------|------|-------------|
| SSH | 22 | Low-interaction SSH |
| Web | 80/443 | Generic HTTP honeypot |
| MySQL | 3306 | MySQL decoy |
| Redis | 6379 | Redis decoy |
| FTP | 21 | FTP decoy |
| Telnet | 23 | Telnet decoy |
| Elasticsearch | 9200 | ES decoy |
| Memcached | 11211 | Memcached decoy |
| VNC | 5900 | VNC decoy |
| RDP | 3389 | RDP decoy |
| SMB | 445 | SMB decoy (Windows) |

### 3.5 Built-in Alerting

In the console: **Configuration -> Mail/Slack/Telegram/Webhook**. Configure a webhook (e.g., Slack):

```
Webhook URL: https://hooks.slack.com/services/T.../B.../...
Trigger: Any honeypot hit
Format: JSON
```

Sample Slack alert format:

```json
{
  "text": "[HFish Alert] Honeypot type: SSH, src_ip: 203.0.113.45, creds tried: root:toor, time: 2026-06-16T12:34:56Z"
}
```

### 3.6 Backup & Restore

```bash
# HFish stores state in /opt/hfish/data
# Back up daily:
tar czf /opt/backups/hfish-$(date +%F).tar.gz /opt/hfish/data

# Restore
docker stop hfish
tar xzf /opt/backups/hfish-2026-06-15.tar.gz -C /
docker start hfish
```

---

## 4. Conpot ICS/SCADA Honeypot (Modbus, S7, IEC-104)

### 4.1 Install Conpot

```bash
sudo apt install -y libsmi2-dev libxslt1-dev libxml2-dev python3-dev libevent-dev
python3 -m venv /opt/conpot-env
source /opt/conpot-env/bin/activate
pip install --upgrade pip
pip install conpot
```

### 4.2 Default Templates

```bash
conpot --list-templates
# Common templates:
#   default         - Siemens S7 PLC profile
#   kemel           - custom ICS device profile
#   ipmi            - IPMI server profile
#   guardian_ast    - Guardian AST tank-monitoring profile
```

### 4.3 Run Conpot

```bash
# Default (S7) template
conpot -f --template default

# Custom IP and template
conpot -f --template kemel --host 10.10.50.200

# With JSON logging for SIEM
conpot -f --template default --logfile /var/log/conpot/conpot.json
```

### 4.4 systemd Unit

```ini
# /etc/systemd/system/conpot.service
[Unit]
Description=Conpot ICS Honeypot
After=network-online.target

[Service]
Type=simple
User=conpot
ExecStart=/opt/conpot-env/bin/conpot -f --template default
WorkingDirectory=/opt/conpot
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### 4.5 Verify with pymodbus

```bash
pip install pymodbus
python3 - <<'EOF'
from pymodbus.client import ModbusTcpClient
c = ModbusTcpClient('10.10.50.200', port=502)
result = c.read_holding_registers(0, 10)
if result.isError():
    print("Error:", result)
else:
    print("Registers:", result.registers)
c.close()
EOF
```

### 4.6 Verify with python-snap7 (S7comm)

```bash
pip install python-snap7
python3 - <<'EOF'
import snap7
client = snap7.client.Client()
client.connect('10.10.50.200', 0, 1)
print("Connected to S7 PLC")
# Read DB1, start 0, size 10
data = client.db_read(1, 0, 10)
print("Data:", data)
client.disconnect()
EOF
```

### 4.7 Docker Compose (T-Pot style)

```yaml
# docker-compose.yml
version: "3"
services:
  conpot:
    image: stingar/conpot:1.0
    container_name: conpot
    restart: always
    network_mode: "host"
    volumes:
      - /opt/conpot/logs:/var/log/conpot
    command: ["-f", "--template", "default", "--host", "10.10.50.200"]
```

### 4.8 Sample Conpot JSON Event

```json
{
  "timestamp": "2026-06-16T12:34:56.789Z",
  "remote": ["203.0.113.45", 54321],
  "data_type": "modbus",
  "data": {
    "function_code": 3,
    "start_addr": 0,
    "quantity": 10
  }
}
```

### 4.9 ICS Honeypot Realism Checklist

- [ ] Device name matches the plant's naming convention (`PLC-Line3-Filling`, not `conpot`)
- [ ] Vendor (Siemens, Schneider, Allen-Bradley) matches the plant
- [ ] Firmware version is current and realistic
- [ ] Process variables in registers look plausible (temperatures 20-90C, pressures 1-10 bar)
- [ ] VLAN-isolated from production OT
- [ ] Outbound traffic blocked

### 4.10 Forward Conpot Logs to Splunk via Filebeat

```yaml
# /etc/filebeat/inputs.d/conpot.yml
- type: log
  paths:
    - /var/log/conpot/conpot.json
  json.keys_under_root: true
  fields:
    source: honeypot
    honeypot_type: conpot
```

---

## 5. T-Pot All-in-One Deployment

### 5.1 System Requirements

- Debian 12+ or Ubuntu 22.04+
- 16GB+ RAM (recommended 32GB)
- 8+ vCPU
- 256GB+ disk
- Dedicated host (no shared production workload)

### 5.2 Install T-Pot

```bash
# Clone
git clone https://github.com/telekom-security/tpotce.git
cd tpotce/iso

# Option A: download the pre-built ISO and install
#   https://github.com/telekom-security/tpotce/releases

# Option B: install on an existing Debian/Ubuntu host
sudo ./install.sh --type=auto
```

Follow prompts; on completion:

```
T-Pot Web UI:    https://<tpot_host>:64297/
Kibana:          https://<tpot_host>:5601/
Attack Map:      https://<tpot_host>:64297/#!/attackmap
```

Default credentials are in `/etc/tpot/tpot.yml` — change immediately.

### 5.3 Default Honeypots (in `docker-compose.yml`)

| Honeypot | Protocol(s) |
|----------|-------------|
| Cowrie | SSH, Telnet |
| Dionaea | SMB, HTTP, FTP, MSSQL, MySQL, SIP |
| Heralding | POP3, IMAP, SMTP, SSH, FTP, MSSQL, MySQL, PostgreSQL, RDP |
| Conpot | Modbus, IPMI, S7 |
| Glastopf | HTTP (PHP vulns) |
| Glutton | Generic |
| Honeytrap | Multi-TCP |
| Elasticpot | Elasticsearch |
| ADBHoney | ADB (Android Debug Bridge) |
| Mailoney | SMTP |
| Rdpy | RDP |
| Sentrypepot | Sentinel |
| Dicompot | DICOM (medical imaging) |
| Tanner | Web (with Snare) |

### 5.4 T-Pot's docker-compose.yml (excerpt)

```yaml
# /opt/tpot/docker-compose.yml (excerpt)
version: "3"
services:
  cowrie:
    image: stingar/cowrie:1.0
    container_name: cowrie
    restart: always
    networks:
      - ewsposter_local
    ports:
      - "22:2222"
      - "23:2223"
    volumes:
      - /data/cowrie/downloads:/data/cowrie/downloads
      - /data/cowrie/log:/data/cowrie/log
      - /data/cowrie/etc:/data/cowrie/etc
```

### 5.5 T-Pot Tools / Web UIs

| Service | URL | Default Port |
|---------|-----|--------------|
| T-Pot Web | https://<host>:64297/ | 64297 |
| Kibana | https://<host>:5601/ | 5601 |
| Attack Map | https://<host>:64297/#!/attackmap | (in T-Pot Web) |
| CyberChef | https://<host>:8000/ | 8000 |
| Elasticvue | https://<host>:8080/ | 8080 |
| Spiderfoot | https://<host>:6430/ | 6430 |
| Nginx (reverse proxy) | https://<host>:64297/ | 64297 |

### 5.6 ELK Queries in T-Pot

KQL: top source IPs hitting Cowrie:

```
type:cowrie AND eventid:cowrie.login.successful
| group by src_ip | count
```

KQL: unique credentials tried:

```
type:cowrie AND (eventid:cowrie.login.successful OR eventid:cowrie.login.failed)
| group by username,password | count
```

### 5.7 Forward T-Pot Data to Centralized SIEM

Edit `/opt/tpot/docker-compose.yml` to add a Logstash output:

```yaml
  logstash:
    image: docker.elastic.co/logstash/logstash:8.11.0
    container_name: logstash
    restart: always
    environment:
      - LS_JAVA_OPTS="-Xmx2g -Xms2g"
    volumes:
      - /data/tpot/logstash/pipeline:/usr/share/logstash/pipeline
```

`/data/tpot/logstash/pipeline/output.conf`:

```
output {
  splunk_hec {
    id => "splunk_forwarder"
    url => "https://splunk.example.org:8088/services/collector"
    token => "<HEC_TOKEN>"
    index => "honeypot"
    sourcetype => "tpot:%{type}"
  }
}
```

### 5.8 Operational Tasks

```bash
# Update T-Pot
sudo /opt/tpot/update.sh

# Restart all honeypots
cd /opt/tpot && docker compose restart

# View logs of one honeypot
docker logs -f cowrie

# View all honeypot logs at once
docker compose logs -f

# Backup state
tar czf /opt/backups/tpot-$(date +%F).tar.gz /data
```

---

## 6. Beelzebub AI-Driven Deception Runtime

### 6.1 Install Beelzebub

```bash
# Via Docker (recommended)
mkdir -p /opt/beelzebub/config
cd /opt/beelzebub

# Pull and run
docker run -d --name beelzebub \
  --restart=always \
  -p 22:22 \
  -p 80:8080 \
  -p 9090:9090 \
  -v /opt/beelzebub/config:/config \
  ghcr.io/mariocandela/beelzebub:latest
```

### 6.2 Sample Configuration (SSH + HTTP)

```yaml
# /opt/beelzebub/config/config.yaml
beelzebub:
  core:
    queryTimeInterval: 5
    schedulerSecond: 30
    PrometheusEnable: true
    PrometheusPort: 9090
    tcpTimeout: 30

  plugins:
    openai:
      enabled: false
      # secret: "sk-..."
      # model: "gpt-4o-mini"

  protocols:
    - name: "ssh-honeypot"
      protocol: "ssh"
      address: "0.0.0.0:22"
      serverVersion: "OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"
      serverName: "prod-web-07"
      prompt: "root@prod-web-07:~# "
      commands:
        - regex: "^uname.*"
          handler: "/usr/bin/uname -a"
        - regex: "^id.*"
          handler: "uid=0(root) gid=0(root) groups=0(root)"
        - regex: "^whoami.*"
          handler: "root"
        - regex: "^ls.*"
          handler: "bin boot dev etc home lib lib64 media mnt opt proc root run sbin srv sys tmp usr var"
        - regex: "^cat /etc/passwd.*"
          handler: "root:x:0:0:root:/root:/bin/bash\\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\\nubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash"

    - name: "http-honeypot"
      protocol: "http"
      address: "0.0.0.0:8080"
      serverName: "Apache/2.4.52 (Ubuntu)"
      endpoints:
        - path: "/"
          statusCode: 200
          body: "<html><body>It works!</body></html>"
        - path: "/admin"
          statusCode: 401
          body: "401 Unauthorized"
        - path: "/.env"
          statusCode: 200
          body: "DB_PASSWORD=hunter2"
```

### 6.3 Enable the LLM Plugin (Optional)

```yaml
beelzebub:
  plugins:
    openai:
      enabled: true
      secret: "sk-..."
      model: "gpt-4o-mini"
```

When enabled, Beelzebub generates dynamic bash responses for commands not matched by `regex`/`handler` rules. The responses are LLM-generated and more believable to an attacker.

### 6.4 Run

```bash
docker compose up -d   # if using docker-compose
# Or via the direct docker run command above

# Verify
curl http://localhost:8080/                                # HTTP honeypot
ssh -p 22 root@localhost                                   # SSH honeypot
curl http://localhost:9090/metrics | grep beelzebub        # Prometheus metrics
```

### 6.5 Sample Prometheus Metrics

```
# HELP beelzebub_commands_total Total commands run by attackers
# TYPE beelzebub_commands_total counter
beelzebub_commands_total{protocol="ssh",command="ls"} 42
beelzebub_commands_total{protocol="ssh",command="whoami"} 28

# HELP beelzebub_connections_total Total connections per protocol
# TYPE beelzebub_connections_total counter
beelzebub_connections_total{protocol="ssh"} 17
beelzebub_connections_total{protocol="http"} 3
```

### 6.6 Forward Beelzebub Logs

```bash
docker logs -f beelzebub | jq .
# Forward via Filebeat or Vector:
#   docker logs beelzebub --follow --timestamps | vector
```

---

## 7. Honeytoken Design (Fake Credentials, Canary Files, Honey-URLs)

### 7.1 Honeytoken Principles

A honeytoken is any digital artifact (file, credential, URL, DNS name) that:

- Has **no legitimate use** in production
- Is **uniquely identifiable** (each token is distinct, so a triggered token maps to exactly one deployment location)
- Triggers an **alert** when accessed

### 7.2 Types of Honeytokens

| Type | Example | Trigger |
|------|---------|---------|
| Honey credential | `backup-vault:` unique password | Login attempt with the password |
| Honey AWS key | `AKIA...` (fake, never registered) | API call with the key |
| Honey URL | `https://intranet.<unique>.example.org/secret` | HTTP GET to the URL |
| Honey DNS | `<unique>.canarytokens.com` | DNS resolution |
| Honey file | `HR-Salaries-FY26.docx` with embedded beacon | Document opened |
| Honey DB row | A user row in `users` table with a unique email | DB query returning the row |
| Honey SSH key | Planted in `~/.ssh/authorized_keys` | SSH login attempt with the key |

### 7.3 Designing a Honey AWS Key

```python
# Generate a fake AWS access key (looks like the real format)
import random
import string

def fake_aws_access_key_id():
    # AKIA + 16 chars from A-Z, 2-7
    chars = string.ascii_uppercase + "234567"
    suffix = "".join(random.choices(chars, k=16))
    return "AKIA" + suffix

def fake_aws_secret_key():
    chars = string.ascii_letters + string.digits + "+/"
    return "".join(random.choices(chars, k=40))

print("AWS_ACCESS_KEY_ID=" + fake_aws_access_key_id())
print("AWS_SECRET_ACCESS_KEY=" + fake_aws_secret_key())
```

Plant the fake key:

```bash
# In a decoy location (NOT a real ~/.aws/credentials)
mkdir -p /opt/decoy/backup-config
cat > /opt/decoy/backup-config/.aws/credentials <<'EOF'
[default]
aws_access_key_id = AKIAEXAMPLEKEY123
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
EOF
# Use Thinkst Canarytokens for the actual trigger — see Section 8
```

### 7.4 Designing a Honey Database Row

```sql
-- Add a unique decoy row to a real users table
INSERT INTO users (email, name, password_hash, is_honeytoken)
VALUES ('david.thompson.<unique_tag>@example.org',
        'David Thompson',
        '<bcrypt_hash>',
        TRUE);

-- Alert on any query that returns this row
-- Configure DB audit logging for SELECT queries that match the email
```

```sql
-- PostgreSQL: enable pgAudit to log the SELECT
ALTER SYSTEM SET pgaudit.log = 'read';
SELECT pg_reload_conf();

-- Then in log analysis, alert on any audit entry mentioning david.thompson.<unique_tag>
```

### 7.5 Designing a Honey File

```bash
# Use Thinkst Canarytokens to generate a .docx with an embedded beacon
# Or plant a honey file manually with a unique content hash

cat > /opt/decoy/sensitive/production-credentials.txt <<'EOF'
# Production Database Credentials
# ===============================
# DO NOT SHARE - last updated 2026-06-16
# Honeytoken ID: HT-2026-06-16-001

DB_HOST=prod-db-01.example.org
DB_USER=admin
DB_PASS=hunter2-honeytoken-12345
EOF

# File integrity monitoring (FIM) on this file
auditctl -w /opt/decoy/sensitive/production-credentials.txt -p rwa -k honeytoken
ausearch -k honeytoken | tail -50
```

### 7.6 Designing a Honey SSH authorized_keys Entry

```bash
# Generate a unique keypair for the honeytoken
ssh-keygen -t ed25519 -f /opt/decoy/honeytoken_key -N "" -C "honeytoken-2026-06-16"

# Append the public key to a real user's authorized_keys
# (with that user's consent and per engagement scope)
cat /opt/decoy/honeytoken_key.pub >> /home/ubuntu/.ssh/authorized_keys

# Monitor sshd logs for any login attempt using the honeytoken key
# (ssh-key fingerprint is unique to this key)
journalctl -u ssh -f | grep "Accepted publickey"
# Pivot: any login with this key fingerprint is an intruder
```

---

## 8. Canarytokens Deployment (Thinkst)

### 8.1 Hosted Canarytokens (Free)

```
URL: https://canarytokens.org/generate
```

Available token types:

- Web Bug / URL Token
- DNS Token
- Microsoft Word Document Token
- PDF Document Token
- AWS API Key Token
- Cloned Website Token
- SQL Injection Token (SQL server)
- Fast Redirect Token
- Slow Redirect Token
- Surreal DNS Token
- Windows Directory Token (file system watcher)
- Acunetix Web Vulnerability Scanner Token
- Synology NAS Token

### 8.2 Generate a Word Document Token

1. Navigate to `https://canarytokens.org/generate`
2. Select "Microsoft Word Document"
3. Enter your email (or webhook URL) for alert delivery
4. Click "Create Token"
5. Download the generated `.docx`
6. Place the `.docx` in a location an insider/attacker might find (`\\fileserver\HR\`, a code repo, an S3 bucket)

When the `.docx` is opened in Word, Word fetches an embedded image resource — the token fires, alerting with the opener's IP.

### 8.3 Generate an AWS API Key Token

1. Select "AWS API Keys" on the Canarytokens page
2. Enter your email/webhook
3. Click "Create Token"
4. Receive a fake `aws_access_key_id` and `aws_secret_access_key`
5. Plant in a decoy `~/.aws/credentials`, `terraform.tfvars`, or env file

Any `aws ...` call using those credentials triggers an alert.

### 8.4 Generate a DNS Token

1. Select "DNS Token"
2. Enter your email/webhook
3. Click "Create Token"
4. Receive a unique hostname: `<random>.canarytokens.com`
5. Plant the hostname in a config file, code comment, or DNS record

Any DNS resolution of that hostname triggers an alert.

```bash
# Test
nslookup <random>.canarytokens.com
dig +short <random>.canarytokens.com
```

### 8.5 Self-Host the Canarytokens Server

```bash
git clone https://github.com/thinkst/canarytokens.git
cd canarytokens

# Configure
cp docker-compose.yml.dist docker-compose.yml
cp .env-dist .env

# Edit .env:
#   DOMAIN=<your-domain>
#   CANARY_DOMAIN_ID=<unique>
#   SMTP_*

# Bring up
docker compose up -d

# Generate tokens at https://<your-domain>/generate
# Manage tokens at https://<your-domain>/manage
```

### 8.6 Sample Canarytoken Alert (Email)

```
Subject: Canary Token Triggered

Your canary token was just triggered:
  Token Type:   DNS Token
  Triggered:    2026-06-16 12:34:56 UTC
  Source IP:    203.0.113.45
  Memo:         "Planted in /opt/decoy/.env on host-01"

This indicates someone accessed the decoy resource.
```

### 8.7 Forward Canarytoken Alerts to Splunk via Webhook

```json
// Canarytokens webhook receiver (Flask example)
// Pivots to Splunk HEC
{
  "token_id": "abc123",
  "type": "dns",
  "src_ip": "203.0.113.45",
  "memo": "Planted in /opt/decoy/.env",
  "timestamp": "2026-06-16T12:34:56Z"
}
```

```python
from flask import Flask, request
import requests
app = Flask(__name__)

@app.route("/canary-webhook", methods=["POST"])
def webhook():
    data = request.json
    hec_event = {
        "time": data.get("timestamp"),
        "source": "honeypot",
        "sourcetype": "canarytoken",
        "event": data
    }
    requests.post(
        "https://splunk.example.org:8088/services/collector",
        headers={"Authorization": f"Splunk <HEC_TOKEN>"},
        json=hec_event,
        verify=False
    )
    return "ok"
```

---

## 9. Network Deception (Syn-Ack Dark Space, Tarpits, Honeyports)

### 9.1 Honeyport (bash one-liner)

```bash
# Simplest possible network canary
PORT=${1:-12345}
LOG=/var/log/honeyport.log
while true; do
    CONNECTION=$(nc -l -p "$PORT" -v 2>&1)
    echo "[$(date)] $CONNECTION" >> "$LOG"
done
```

### 9.2 Honeyport with Auto-Firewall

```bash
#!/bin/bash
# /usr/local/bin/honeyport.sh
PORT=${1:-12345}
LOG=/var/log/honeyport.log
while true; do
    CONNECTION=$(nc -l -p "$PORT" -v 2>&1)
    echo "[$(date)] $CONNECTION" >> "$LOG"
    SRC_IP=$(echo "$CONNECTION" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)
    if [ -n "$SRC_IP" ]; then
        iptables -A INPUT -s "$SRC_IP" -j DROP
        echo "[$(date)] blocked $SRC_IP" >> "$LOG"
        # Optional: alert via Slack/email
    fi
done
```

### 9.3 Honeyport systemd Unit

```ini
# /etc/systemd/system/honeyport.service
[Unit]
Description=Honeyport Network Canary
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/honeyport.sh 12345
Restart=always

[Install]
WantedBy=multi-user.target
```

### 9.4 Endlessh (SSH Tarpit)

```bash
# Install
sudo apt install -y endlessh

# /etc/endlessh/config
Port 22
Delay 1000        # milliseconds between banner bytes
MaxClients 4096
LogLevel 1
```

```bash
# Run as systemd service
sudo systemctl enable --now endlessh

# View logs
journalctl -u endlessh -f

# Verify from another host: connection hangs indefinitely
timeout 15 nc -v <tarpit_ip> 22
```

Sample Endlessh log:

```
Jun 16 12:34:56 endlessh[1234]: 203.0.113.45:54321 connected
Jun 16 12:35:56 endlessh[1234]: 203.0.113.45:54321 closed (60 seconds)
```

### 9.5 LaBrea Tarpit

```bash
# Older but still useful — responds to ARP for unused IPs in your subnet,
# then answers TCP SYN-ACK and holds the connection in a "stuck" state
sudo apt install -y labrea
sudo labrea -v -i eth0 -s 192.168.1.0/24
```

### 9.6 Honeytrap (Multi-TCP)

```bash
# Part of T-Pot; standalone:
docker run -d --name honeytrap \
  --net=host \
  -v /opt/honeytrap/logs:/opt/honeytrap/logs \
  stingar/honeytrap:1.0

# Configure /opt/honeytrap/honeytrap.conf to listen on many ports
```

### 9.7 Network Dark-Space Monitoring

```bash
# A "dark space" is an IP range with no production hosts. Any packet to it is suspicious.
# Configure iptables to LOG all packets to dark space, then DROP
iptables -N DARKSPACE 2>/dev/null
iptables -A DARKSPACE -j LOG --log-prefix "DARKSPACE: " --log-level 4
iptables -A DARKSPACE -j DROP
# Apply to the dark-space CIDR
iptables -A INPUT -d 192.168.1.240/29 -j DARKSPACE

# View logs
journalctl -k | grep DARKSPACE | tail -20
```

### 9.8 syn-ack Generator (Canary Ports)

```bash
# Open ports with no service behind them — any connection is a scanner
# Use a simple Python listener that accepts and logs
python3 - <<'EOF'
import socket, datetime
PORTS = [12345, 23456, 34567, 45678, 56789]  # canary ports
for port in PORTS:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(5)
    print(f"Listening on port {port}")
    
# (Run in parallel with threads or via xinetd-style inetd)
EOF
```

### 9.9 Cisco ASA / Juniper SRX Honeyport ACL

```cisco
# Cisco ASA — log any connection to a honey port
access-list HONEYPORT extended permit tcp any host 192.168.1.50 eq 12345 log
access-list HONEYPORT extended deny ip any any
access-group HONEYPORT in interface outside
```

---

## 10. Email/Web Honeypots (Spam Traps, Glastopf)

### 10.1 Mailoney SMTP Honeypot

```bash
# Part of T-Pot; standalone:
docker run -d --name mailoney \
  -p 25:25 \
  -v /opt/mailoney/logs:/opt/mailoney/logs \
  stingar/mailoney:1.0 \
  -l /opt/mailoney/logs -p 25 -s postfix -t postfix_creds

# Mailoney captures SMTP commands, MAIL FROM/RCPT TO, and AUTH attempts
tail -f /opt/mailoney/logs/session.log
```

### 10.2 Spam Trap (Dedicated Email Addresses)

```
1. Register a handful of email addresses that will never be used legitimately:
   - honeytrap-001@example.org
   - honeytrap-002@example.org
   - ...
2. Plant these addresses in:
   - Public web pages (in hidden form fields)
   - Decoy documents
   - Newsgroup/forum posts (low-traffic)
3. Any email to these addresses is spam (or a harvested list).
4. Configure the MX to deliver to a quarantine + IOCs pipeline:
   - Extract URLs, attachments, sender IPs
   - Submit to VirusTotal / MISP
```

### 10.3 Glastopf Web Honeypot

```bash
# Part of T-Pot; standalone:
docker run -d --name glastopf \
  -p 80:80 \
  -v /opt/glastopf/db:/opt/glastopf/db \
  -v /opt/glastopf/log:/opt/glastopf/log \
  stingar/glastopf:1.0

# Configure /opt/glastopf/glastopf.cfg
[webserver]
host = 0.0.0.0
port = 80

[logging]
loglevel = INFO
logfile = /opt/glastopf/log/glastopf.log

[output]
# JSON output for SIEM
json_enabled = true
json_file = /opt/glastopf/log/events.json
```

### 10.4 Glastopf Event Sample

```json
{
  "timestamp": "2026-06-16T12:34:56Z",
  "source": "203.0.113.45",
  "request_url": "/admin/login.php",
  "request_method": "POST",
  "request_body": "user=admin&pass=admin",
  "response_code": 200,
  "pattern": "rfi",
  "comment": "RFI attempt"
}
```

### 10.5 Honey-URL Design

```bash
# Plant honey-URLs in:
#   - robots.txt (Disallow entries that don't exist)
#   - HTML comments
#   - Decoy documents
# Each URL is unique and triggers an alert on HTTP GET
# Use Canarytokens "Web Bug / URL" type for the trigger

# Sample robots.txt entry
User-agent: *
Disallow: /internal-admin-panel-7x3y/
Disallow: /backup-2024-q4/
Disallow: /api/v2/private/
```

### 10.6 Honey-JWT (in APIs)

```python
# Plant a unique JWT in a decoy API response or config
# The JWT signature uses a unique secret, so it's verifiable as "the honeytoken"
# Any API call using this JWT is unauthorized
import jwt, secrets
payload = {"sub": "honeytoken", "exp": 9999999999}
secret = secrets.token_hex(32)
honey_jwt = jwt.encode(payload, secret, algorithm="HS256")
# Alert: any inbound request with Authorization: Bearer <honey_jwt>
```

---

## 11. Database Honeypots (HoneyDB, MySQL Fake, Elasticpot)

### 11.1 HoneyDB (Community)

```
URL: https://riskdiscovery.com/honeydb/
```

HoneyDB is a community-curated database of attacker IP addresses (collected from honeypots worldwide). Query it for reputation:

```bash
# Free API (registration required)
curl -s -H "X-HoneyDb-ApiKey: $HONEYDB_KEY" \
  "https://riskdiscovery.com/api/v1/honeydb/ip/<ip>" | jq .
```

### 11.2 MySQL Fake Honeypot (HFish / Custom)

```bash
# HFish has a built-in MySQL template — enable it in the console
# For a standalone MySQL honeypot, use Cowrie-style emulation or mariadb-fake
docker run -d --name mysql-honeypot \
  -p 3306:3306 \
  -e MYSQL_ROOT_PASSWORD=hunter2 \
  -v /opt/mysql-honeypot/logs:/var/log/mysql \
  mysql:8

# Enable MySQL general_log to capture every query
mysql -uroot -phunter2 -e "
  SET GLOBAL general_log = 'ON';
  SET GLOBAL general_log_file='/var/log/mysql/queries.log';
"

# Monitor queries
tail -f /var/log/mysql/queries.log | grep -E "INSERT|UPDATE|SELECT"
```

### 11.3 Elasticpot (Elasticsearch Decoy)

```bash
# Part of T-Pot; standalone:
docker run -d --name elasticpot \
  -p 9200:9200 \
  -v /opt/elasticpot/logs:/opt/elasticpot/logs \
  stingar/elasticpot:1.0

# Elasticpot emulates Elasticsearch's REST API
# Captures _search, _cat, _cluster/health queries from attackers
tail -f /opt/elasticpot/logs/elasticpot.log
```

### 11.4 Redis Honeypot

```bash
# Redis decoy via OpenCanary
# Enable in /etc/opencanaryd/opencanary.conf:
{
  "redis.enabled": true,
  "redis.port": 6379
}
sudo /opt/canary-env/bin/opencanaryd --restart

# Verify from another host
redis-cli -h <honeypot_ip> -p 6379 ping
# OpenCanary logs the connection
```

### 11.5 Honey-DB Row (Revisited — Alert Pipeline)

```sql
-- Add a decoy row to the users table
INSERT INTO users (email, password_hash, role, is_honeytoken)
VALUES ('david.thompson.abc123@example.org', '$2b$12$...', 'admin', TRUE);

-- Enable query logging
ALTER SYSTEM SET pgaudit.log = 'read, write';
SELECT pg_reload_conf();

-- Alert on any query mentioning the decoy email
-- via pgaudit + SIEM rule
```

```sql
-- Splunk SPL:
index=postgres sourcetype=pgaudit "david.thompson.abc123"
| stats count by src_ip, query
```

### 11.6 Memcached Honeypot

```bash
# Memcached decoy — catches attackers scanning for exposed memcached (DDoS amplification)
# OpenCanary has no memcached module; use a custom Python listener:
python3 - <<'EOF'
import socket, datetime
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 11211))
s.listen(100)
print("Listening on 11211")
while True:
    conn, addr = s.accept()
    print(f"{datetime.datetime.now()} - Memcached connection from {addr}")
    # Mimic memcached stats response
    conn.send(b"STAT pid 1\r\nSTAT version 1.6.9\r\nEND\r\n")
    conn.close()
EOF
```

---

## 12. Log Analysis & IOC Extraction Pipelines

### 12.1 Cowrie IOC Extraction (jq)

```bash
LOG=/opt/cowrie/var/log/cowrie/cowrie.json
OUT=/opt/iocs/cowrie-$(date +%F)
mkdir -p /opt/iocs

# 1. Source IPs (any session)
jq -r 'select(.eventid=="cowrie.session.connect") | .src_ip' "$LOG" \
  | sort -u > "$OUT.src_ips.txt"

# 2. Source IPs that successfully logged in
jq -r 'select(.eventid=="cowrie.login.successful") | .src_ip' "$LOG" \
  | sort -u > "$OUT.login_success_ips.txt"

# 3. Credentials tried
jq -r 'select(.eventid | startswith("cowrie.login")) |
  "\(.username)\t\(.password)"' "$LOG" \
  | sort -u > "$OUT.creds.tsv"

# 4. Commands executed post-login
jq -r 'select(.eventid=="cowrie.command.input") | .input' "$LOG" \
  | sort -u > "$OUT.commands.txt"

# 5. URLs fetched (file_download)
jq -r 'select(.eventid=="cowrie.session.file_download") |
  "\(.url) (\(.shasum))"' "$LOG" \
  | sort -u > "$OUT.downloads.tsv"

# 6. SHA256 of uploaded files
jq -r 'select(.eventid=="cowrie.session.file_upload") |
  .shasum' "$LOG" | sort -u > "$OUT.uploads_hashes.txt"

# 7. Outbound IPs (for sessions that downloaded from external URLs)
jq -r 'select(.eventid=="cowrie.session.file_download") | .url' "$LOG" \
  | grep -oE 'https?://[^/]+' | sort -u > "$OUT.external_urls.txt"
```

### 12.2 Conpot IOC Extraction

```bash
LOG=/var/log/conpot/conpot.json
OUT=/opt/iocs/conpot-$(date +%F)
mkdir -p /opt/iocs

# Source IPs
jq -r '.remote[0]' "$LOG" | sort -u > "$OUT.src_ips.txt"

# Protocol distribution
jq -r '.data_type' "$LOG" | sort | uniq -c | sort -rn > "$OUT.protocols.txt"

# Function codes called (Modbus)
jq -r 'select(.data_type=="modbus") | .data.function_code' "$LOG" \
  | sort | uniq -c | sort -rn > "$OUT.modbus_function_codes.txt"
```

### 12.3 Submit Cowrie Uploads to VirusTotal

```bash
#!/bin/bash
# /usr/local/bin/vt-submit.sh
VT_KEY=${VT_KEY:?missing}
DIR=/opt/cowrie/var/lib/cowrie/downloads
OUT=/opt/iocs/vt-results-$(date +%F).json
touch "$OUT"

for f in "$DIR"/*; do
  [ -f "$f" ] || continue
  hash=$(sha256sum "$f" | awk '{print $1}')
  # Check if already analyzed
  result=$(curl -s -H "x-apikey: $VT_KEY" "https://www.virustotal.com/api/v3/files/$hash")
  malicious=$(echo "$result" | jq -r '.data.attributes.last_analysis_stats.malicious // "unknown"')
  echo "{\"hash\":\"$hash\",\"malicious\":$malicious,\"time\":\"$(date -Iseconds)\"}" >> "$OUT"
  sleep 15   # respect rate limits
done
```

### 12.4 Submit to MISP

```python
#!/usr/bin/env python3
# /usr/local/bin/misp-submit.py
import json, datetime, sys
from pathlib import Path
from pymisp import PyMISP, MISPEvent

misp = PyMISP("https://misp.example.org", sys.argv[1], False)

event = MISPEvent()
event.info = f"Cowrie honeypot IOCs {datetime.date.today()}"
event.distribution = 0
event.add_tag("honeypot")
event.add_tag("cowrie")
event.add_tag("tlp:amber")

today = datetime.date.today().isoformat()
base = Path(f"/opt/iocs/cowrie-{today}")

# Source IPs
if (base / "src_ips.txt").exists():
    for ip in (base / "src_ips.txt").read_text().splitlines():
        event.add_attribute("ip-src", ip.strip(), to_ids=True)

# Credentials (NOT marked to_ids — they are attacker-tried, not confirmed valid)
if (base / "creds.tsv").exists():
    for line in (base / "creds.tsv").read_text().splitlines():
        u, p = line.split("\t", 1)
        event.add_attribute(
            "text", f"{u}:{p}",
            comment="Credentials tried against Cowrie honeypot",
            to_ids=False
        )

# Upload hashes
if (base / "uploads_hashes.txt").exists():
    for h in (base / "uploads_hashes.txt").read_text().splitlines():
        if len(h) == 64:
            event.add_attribute("sha256", h.strip(), to_ids=True)

misp.add_event(event)
print(f"MISP event created: {event.id}")
```

### 12.5 Pivot to Shodan / AbuseIPDB

```bash
#!/bin/bash
# /usr/local/bin/ip-enrich.sh
IP=${1:?missing}
SHODAN_KEY=${SHODAN_KEY:?missing}
ABUSEIPDB_KEY=${ABUSEIPDB_KEY:?missing}

echo "=== Shodan ==="
curl -s "https://api.shodan.io/shodan/host/$IP?key=$SHODAN_KEY" \
  | jq '{ip, country_name, org, ports, vulns, last_update}'

echo "=== AbuseIPDB ==="
curl -s "https://api.abuseipdb.com/api/v2/check?ipAddress=$IP&maxAgeInDays=90" \
  -H "Key: $ABUSEIPDB_KEY" -H "Accept: application/json" \
  | jq '.data | {abuseConfidenceScore, country_code, usageType, isp, domain}'

echo "=== VirusTotal (IP) ==="
curl -s -H "x-apikey: $VT_KEY" "https://www.virustotal.com/api/v3/ip_addresses/$IP" \
  | jq '.data.attributes.last_analysis_stats'
```

### 12.6 Splunk SPL: Top Cowrie Attacker IPs

```spl
index=honeypot sourcetype=cowrie:json eventid=cowrie.session.connect
| stats count as sessions, dc(username) as unique_users_tried,
        values(username) as users by src_ip
| sort -sessions
| head 20
```

### 12.7 Splunk SPL: Cowrie Commands Distribution

```spl
index=honeypot sourcetype=cowrie:json eventid=cowrie.command.input
| stats count by input
| sort -count
| head 30
```

### 12.8 Splunk SPL: Cowrie — Unique Uploaded Binaries

```spl
index=honeypot sourcetype=cowrie:json eventid=cowrie.session.file_upload
| stats dc(shasum) as unique_binaries by src_ip
| sort -unique_binaries
```

### 12.9 Sentinel KQL: OpenCanary Hits

```kql
Syslog
| where ProcessName == "opencanary"
| parse kind=relaxed Message with * "src_host: " src_ip " " * "dst_port: " dst_port
| summarize count(), makeset(src_ip) by bin(TimeGenerated, 1h), dst_port
| order by count_ desc
```

### 12.10 Elastic ES|QL: Cowrie Sessions

```esql
FROM cowrie-*
| WHERE event.eventid == "cowrie.session.connect"
| STATS sessions = COUNT(*) BY source.ip
| SORT sessions DESC
| LIMIT 20
```

### 12.11 Automated Alert Pipeline (Python)

```python
#!/usr/bin/env python3
"""Cowrie event processor — alert on login success and pipe to Slack."""
import json, sys, requests
from pathlib import Path
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

LOG = Path("/opt/cowrie/var/log/cowrie/cowrie.json")
SLACK_WEBHOOK = "<your_webhook>"

def alert(message: str) -> None:
    requests.post(SLACK_WEBHOOK, json={"text": message}, timeout=5)

class CowrieHandler(FileSystemEventHandler):
    def __init__(self):
        self._f = open(LOG)
        self._f.seek(0, 2)  # seek to end

    def on_modified(self, event):
        if event.src_path != str(LOG):
            return
        for line in self._f:
            try:
                evt = json.loads(line)
            except json.JSONDecodeError:
                continue
            if evt.get("eventid") == "cowrie.login.successful":
                alert(f"!!! Cowrie SUCCESS: {evt['src_ip']} logged in as "
                      f"{evt['username']}/{evt['password']}")

if __name__ == "__main__":
    obs = Observer()
    obs.schedule(CowrieHandler(), str(LOG.parent))
    obs.start()
    try:
        while True:
            pass
    except KeyboardInterrupt:
        obs.stop()
    obs.join()
```

### 12.12 Sigma Rule: Honeypot Session

```yaml
title: Honeypot Tripwire - Cowrie Login Successful
id: a1b2c3d4-0100-4000-8000-000000000003
status: stable
description: >-
  Any successful login to a Cowrie honeypot is, by definition, unauthorized
  and indicates active attacker credential reuse.
references:
  - https://attack.mitre.org/
  - https://github.com/cowrie/cowrie
tags:
  - attack.credential_access
  - attack.t1110
logsource:
  product: honeypot
  service: cowrie
detection:
  selection:
    eventid: cowrie.login.successful
  condition: selection
fields:
  - src_ip
  - username
  - password
  - session
falsepositives:
  - Honeypot researcher (verify via reverse DNS / known research networks)
level: critical
```

---

## 13. Deception Architecture Cheat Sheet

### 13.1 Selecting a Honeypot by Engagement Type

| Engagement Type | Recommended | Why |
|-----------------|-------------|-----|
| DMZ SSH-attack capture | Cowrie | Medium-interaction, captures commands + uploads |
| Internal lateral-movement tripwire | OpenCanary (multi-service) | Lightweight, many services |
| ICS/OT perimeter | Conpot | Realistic PLC profiles |
| Enterprise-wide rollout | HFish | Central console, multi-endpoint agents |
| Demonstration / lab | T-Pot | All-in-one, ~20 honeypots in one box |
| Modern, AI-driven responses | Beelzebub | LLM-generated believable interactions |
| Web-app scanner capture | Glastopf | SQLi/RFI payload capture |
| Multi-protocol credential capture | Heralding | SSH/SMTP/IMAP/POP3/FTP/MSSQL/MySQL |
| Malware sample capture | Dionaea | SMB/HTTP capture + auto-sandbox |

### 13.2 Engagement Pre-flight Checklist

```
[ ] Written authorization (RoE / SoW) covers the deployment scope
[ ] Decoy host is in the authorized network segment
[ ] Decoy host has NO production data or production accounts
[ ] Decoy host is isolated from production (VLAN/firewall)
[ ] Outbound egress is blocked (or restricted to sandbox only)
[ ] Honeypot banners/config match production look (realism)
[ ] Honeypot host key / certs are unique (don't reuse prod)
[ ] Logging pipeline to SIEM is configured and tested
[ ] Alert thresholds and escalation path defined
[ ] Data retention and access-control policy documented
[ ] Legal review completed for jurisdiction cross-border data
```

### 13.3 Engagement Shutdown Checklist

```
[ ] Capture final IOC exports (creds, IPs, hashes)
[ ] Submit IOCs to MISP and SIEM
[ ] Wipe the honeypot host (reinstall OS)
[ ] Revoke any honeytokens (Canarytokens, AWS keys)
[ ] Remove decoy host from network (DHCP, DNS)
[ ] Archive logs (encrypted at rest) per retention policy
[ ] Generate engagement report
```

### 13.4 MITRE Engage Mapping

| Engage Goal | This Skill's Implementation |
|-------------|------------------------------|
| **Prepare** | Deploy Cowrie/Conpot/HFish/OpenCanary within authorized scope |
| **Expose** | Any honeypot interaction is an adversary indicator |
| **Affect** | Tarpits (Endlessh, LaBrea), honeyports burn attacker time |
| **Collect** | Cowrie sessions, Conpot events, OpenCanary hits → IOC pipeline |
| **Understand** | Pivot IOCs through MISP/Shodan/VirusTotal for attribution |
| **Engage** | (Out of scope for most engagements — do not actively interact) |

### 13.5 Quick Reference: Honeypot Default Ports

| Service | Port(s) |
|---------|---------|
| Cowrie SSH | 22 (or 2222 for testing) |
| Cowrie Telnet | 23 (or 2323 for testing) |
| OpenCanary (modular) | varies (80, 443, 21, 22, 3389, 3306, 6379) |
| Conpot Modbus | 502 |
| Conpot S7comm | 102 |
| Conpot IPMI | 623 |
| Glastopf HTTP | 80 |
| Dionaea SMB | 445 |
| Heralding (multi) | 21, 22, 25, 110, 143, 3306, 5432, 3389 |
| T-Pot Web UI | 64297 |
| T-Pot Kibana | 5601 |
| HFish Console | 4433 |
| Beelzebub | 22, 8080, 9090 (Prometheus) |

### 13.6 Cheat Sheet: One-Liner IOC Extraction

```bash
# Quick summary of Cowrie activity in the last 24h
LOG=/opt/cowrie/var/log/cowrie/cowrie.json
echo "Connections: $(jq -r 'select(.eventid=="cowrie.session.connect") | .src_ip' "$LOG" | wc -l)"
echo "Unique IPs:  $(jq -r 'select(.eventid=="cowrie.session.connect") | .src_ip' "$LOG" | sort -u | wc -l)"
echo "Logins:      $(jq -r 'select(.eventid=="cowrie.login.successful") | .src_ip' "$LOG" | wc -l)"
echo "Uploads:     $(jq -r 'select(.eventid=="cowrie.session.file_upload") | .shasum' "$LOG" | sort -u | wc -l)"
echo "Downloads:   $(jq -r 'select(.eventid=="cowrie.session.file_download") | .url' "$LOG" | sort -u | wc -l)"
echo "Commands:    $(jq -r 'select(.eventid=="cowrie.command.input") | .input' "$LOG" | sort -u | wc -l)"
```

---

> **End of payloads.md** — every command here is reproducible on an authorized deployment. Pair with `SKILL.md` (conceptual framework) and `test-cases.md` (validation). For the end-to-end workflow, see `guides/deception-honeypot-playbook.md`.
