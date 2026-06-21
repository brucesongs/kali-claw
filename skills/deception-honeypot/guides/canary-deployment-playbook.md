# Canary Token and Distributed Honeypot Deployment Playbook

> Deep-dive companion to `skills/deception-honeypot/SKILL.md` and `guides/deception-honeypot-playbook.md`.
>
> Audience: blue teamers, deception engineers, and detection engineers who understand honeypot basics and want a deployment-focused playbook covering the full spectrum — from lightweight canary tokens to distributed all-in-one honeypot platforms. Every section contains concrete deployment commands, configuration templates, tuning guidance, and notification pipelines.

---

## 1. Why a Deployment Playbook?

A honeypot that is not deployed is just an interesting idea. A honeypot deployed incorrectly generates false positives, alerts nobody, and quietly erodes trust in deception as a defensive technique. This playbook is the operational answer to:

1. **Where** should I put deception assets? (Network location, host location, identity.)
2. **What kind** of deception asset fits each location? (Token vs honeypot vs full-interaction system.)
3. **How** do I deploy it without disrupting production?
4. **Who** needs to be notified when the deception asset fires? (Webhook, SIEM, on-call.)
5. **How** do I tune out false positives? (Static scanners, vulnerability scanners, health checks.)
6. **What** do I do when a real attacker interacts? (Engagement playbook.)

This guide complements `deception-honeypot-playbook.md` (which focuses on architecture and methodology) with the actual deployment commands.

### 1.1 Decision tree: which deception asset?

```
What is the location?
├── Production file server / NAS
│   └── Deploy file-based Canarytokens (DOCX, PDF, AWS keys)
├── Production database (read-only replica OK)
│   └── Deploy SQL Canarytokens (fake rows, fake credentials table)
├── Internal DNS namespace
│   └── Deploy DNS Canarytoken (subdomain that never resolves legitimately)
├── Internet-exposed perimeter
│   └── Deploy Cowrie (SSH) or Dionaea (multi-protocol) on non-production IPs
├── Internal network segments
│   └── Deploy HFish or OpenCanary as internal lures
├── Cloud account (AWS / GCP / Azure)
│   └── Deploy AWS API Canarytoken (fake keys), cloud bucket canaries
└── Comprehensive deception program
    └── Deploy T-Pot (all-in-one platform on a dedicated host)
```

---

## 2. Thinkst Canarytokens — Lightweight Lures Everywhere

Canarytokens (by Thinkst) are the single highest-value deception tool for the effort required to deploy. A canarytoken is a tiny artifact — a DNS hostname, a file, an AWS key, a SQL query — that "fires" when touched, sending an alert to a webhook or inbox. They are free for personal use at [canarytokens.org](https://canarytokens.org).

### 2.1 Why canarytokens work

- **Cost**: free (community) or low-cost (enterprise).
- **Deployment**: generate the token, place the artifact, done.
- **False positive rate**: very low, because legitimate users never touch the artifacts.
- **Detection value**: very high — a fired canarytoken is almost always a real attacker or a real insider threat.

### 2.2 DNS Canarytokens

A DNS canarytoken is a hostname that resolves to a marker server. When any DNS resolver queries the hostname, the marker logs the source IP and timestamp.

**Deployment**:

1. Visit [canarytokens.org](https://canarytokens.org/generate).
2. Select "DNS" token type.
3. Provide an email or webhook URL.
4. Receive: `random-string.x.y.canarytokens.com`.
5. Place the hostname in:
   - A `~/.bash_history` line on production servers (e.g., `ssh deploy@random-string.x.y.canarytokens.com`)
   - A DNS zone file as a CNAME
   - A configuration file that attackers might grep for
   - A browser bookmark file
   - An environment variable on a production host

**Trigger**: any DNS resolver anywhere on the Internet that queries this hostname.

**Alert**:

```json
{
  "type": "dns_token",
  "token": "random-string",
  "src_ip": "1.2.3.4",
  "timestamp": "2026-06-21T14:30:00Z",
  "user_agent": "...",
  "reminder": "DNS lookup of canary hostname"
}
```

### 2.3 HTTP Canarytokens

An HTTP token fires when an HTTP client requests a URL. Useful as:

- A tracking pixel in an internal email
- An `<img src>` in an internal web page
- A URL embedded in a document that an attacker might open

**Deployment**:

1. Select "Web Bug / URL" token type.
2. Receive a URL like `https://canarytokens.org/tags?tag=random-string`.
3. Embed the URL as a 1x1 pixel image in documents or emails.

### 2.4 File-based Canarytokens

File tokens are documents (DOCX, PDF, XLSX) that "phone home" when opened. Internally they embed a URL request triggered when macros or document-link features execute.

**Deployment (DOCX)**:

1. Select "Microsoft Word Document" token type.
2. Receive a `.docx` file.
3. Name it something tempting: `passwords.docx`, `network-diagram.docx`, `salary-2026.xlsx`.
4. Place the file on:
   - A shared file server
   - A `C:\Users\Administrator\Desktop` folder on a Windows host
   - An S3 bucket that attackers might enumerate

**Trigger**: opening the file in Microsoft Office.

**Caveat**: modern Office versions block external content by default. The user sees a yellow bar "Enable Content." If the user (or attacker) clicks Enable, the token fires.

### 2.5 AWS API key Canarytokens

An AWS API key canarytoken is a fake AWS access key that, when used to call any AWS API, fires the alert. This is one of the highest-value canaries — attackers almost always try stolen keys quickly.

**Deployment**:

1. Select "AWS API Key" token type.
2. Receive: an access key ID (`AKIA...`) and a secret access key.
3. Place the credentials in:
   - A `~/.aws/credentials` file on a host likely to be compromised
   - An environment variable dump in a CI/CD log
   - A code repository (with canary-token-aware commit hooks)
   - A Slack channel the attacker might enumerate

**Trigger**: any AWS API call signed with the key. The canarytokens.org infrastructure emulates an AWS STS endpoint that logs the call.

### 2.6 SQL Canarytokens

A SQL canarytoken is a row in a database that, when SELECTed, fires an outbound HTTP request. Useful for detecting database exfiltration.

**MySQL template**:

```sql
CREATE TABLE fake_users (
  id INT PRIMARY KEY AUTO_INCREMENT,
  username VARCHAR(255),
  password VARCHAR(255),
  last_login DATETIME
);

INSERT INTO fake_users (username, password, last_login) VALUES
  ('admin', '$2b$10$N9qo8uLOickgx2ZMRZoMy.MrqK3a8uLaL4YfXGj5XpJ5qkYvF9aWK', NOW()),
  ('backup', '$2b$10$D4H3lZ6lZkZq5l5pVlN5xu8KqZ6qX8oVlO8uVY9lZ6pKqX8Y9lKlK', NOW());

-- The password hash is a fake. The canarytoken fires when the row is SELECTed.
-- Real canarytokens use a different mechanism (loaded UDF, view, etc.) — see the
-- canarytokens.org SQL token generation flow.
```

### 2.7 Other token types

| Token type | Use case |
|-----------|----------|
| `cmd` | Windows command-line execution canary |
| `wireguard` | WireGuard VPN config that fires when loaded |
| `slack_api` | Fake Slack API token |
| `azure_service_principal` | Fake Azure Service Principal credentials |
| `kubeconfig` | Fake Kubernetes config that fires when kubectl uses it |
| `signed_executable` | Executable that fires when run |

### 2.8 Self-hosting Canarytokens (enterprise)

The [Canarytokens Docker image](https://github.com/thinkst/canarytokens) can be self-hosted:

```bash
# On a server with a public IP and DNS A record
git clone https://github.com/thinkst/canarytokens
cd canarytokens
cp docker-compose.yml.example docker-compose.yml
# Edit: set DOMAIN, FRONTEND_DOMAIN, SMTP_*
docker-compose up -d
```

You now control the marker server and the data. Useful for air-gapped environments, regulated industries, or large token volumes.

### 2.9 Notification pipeline for Canarytokens

Canarytokens supports email and webhook notifications. For SOC integration:

```python
# Example webhook receiver (Flask)
from flask import Flask, request
import json

app = Flask(__name__)

@app.route('/canary-webhook', methods=['POST'])
def canary():
    event = request.json
    # Forward to SIEM (Splunk HEC example)
    import requests
    requests.post(
        "https://splunk.example.com:8088/services/collector",
        headers={"Authorization": f"Splunk {HEC_TOKEN}"},
        json={
            "sourcetype": "canarytoken",
            "event": event,
            "index": "deception",
        }
    )
    # Forward to Slack
    requests.post(SLACK_WEBHOOK_URL, json={
        "text": f":rotating_light: Canarytoken {event.get('token')} fired from {event.get('src_ip')}"
    })
    return "", 200
```

---

## 3. Cowrie — Medium-Interaction SSH/Telnet Honeypot

Cowrie is the workhorse medium-interaction honeypot. It emulates an SSH (and optionally Telnet) service, captures login attempts (credentials, source IP), and provides a fake shell where attacker commands are logged.

### 3.1 Why Cowrie

- **Realistic attacker interaction**: attackers get a shell; they run commands; you capture everything.
- **Multi-protocol**: SSH and Telnet.
- **File capture**: any file the attacker downloads (`wget`, `curl`) is saved for analysis.
- **Easy integration**: logs to JSON, can ship to ELK / Splunk / Honeysnap.

### 3.2 Deployment on a Linux host

```bash
# Create a non-root user for cowrie
sudo useradd -m -s /bin/bash cowrie

# Clone the repo
sudo -u cowrie -H git clone https://github.com/cowrie/cowrie /home/cowrie/cowrie
cd /home/cowrie/cowrie

# Set up Python virtualenv
sudo -u cowrie -H python3 -m venv cowrie-env
sudo -u cowrie -H cowrie-env/bin/pip install -r requirements.txt

# Configure
cp etc/cowrie.cfg.dist etc/cowrie.cfg
# Edit etc/cowrie.cfg:
#   hostname = srv-prod-04       # looks like a real production host
#   log_path = /home/cowrie/cowrie/var/log/cowrie
#   download_path = /home/cowrie/cowrie/var/lib/cowrie/downloads
#
#   [ssh]
#   listen_endpoints = tcp:2222  # cowrie listens on 2222; iptables redirects 22 to 2222
#
#   [telnet]
#   enabled = true
#   listen_endpoints = tcp:2223

# Redirect ports 22 and 23 to cowrie (real SSH moves to 22022)
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
sudo iptables -t nat -A PREROUTING -p tcp --dport 23 -j REDIRECT --to-port 2223

# Move real SSH to port 22022 (edit /etc/ssh/sshd_config: Port 22022)
sudo systemctl restart sshd

# Start cowrie
sudo -u cowrie -H bin/cowrie start
```

### 3.3 Cowrie configuration deep-dive

`etc/cowrie.cfg` key sections:

```ini
[honeypot]
hostname = prod-db-03
log_path = var/log/cowrie
download_path = var/lib/cowrie/downloads
output_path = var/lib/cowrie/output

# Pretend to be Ubuntu 22.04
[shell]
fs = var/lib/cowrie/fs
arch = linux-x64-lsb

[ssh]
listen_endpoints = tcp:2222
# Banner — match a real-looking SSH version
version = SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4

[telnet]
enabled = true
listen_endpoints = tcp:2223

# Database output (optional)
[output_mysql]
enabled = false
# OR ship via JSON log:
[output_jsonlog]
enabled = true
logfile = var/log/cowrie/cowrie.json
```

### 3.4 Fake filesystem and "fake" files

Cowrie's fake filesystem lives in `var/lib/cowrie/fs/`. Customize it to look like a real production host:

```
var/lib/cowrie/fs/
├── etc/
│   ├── passwd            # realistic-looking users
│   ├── shadow            # fake password hashes (canarytokens!)
│   ├── hostname
│   └── issue
├── home/
│   ├── admin/            # fake home dir with .bash_history
│   ├── deploy/
│   └── backup/
├── root/
│   ├── .ssh/             # fake SSH keys
│   └── .bash_history     # juicy-looking commands
└── var/log/
    └── auth.log          # fake auth log
```

Place canarytoken files in `/home/admin/passwords.docx`, `/root/.aws/credentials`, etc. When the attacker cats these files, multiple layers of detection fire.

### 3.5 Log analysis

Cowrie logs every session. The JSON log:

```json
{
  "eventid": "cowrie.session.connect",
  "src_ip": "1.2.3.4",
  "src_port": 54321,
  "dst_port": 2222,
  "session": "abc123",
  "timestamp": "2026-06-21T14:30:00.000Z"
}
{
  "eventid": "cowrie.login.failed",
  "src_ip": "1.2.3.4",
  "username": "root",
  "password": "123456",
  "session": "abc123"
}
{
  "eventid": "cowrie.login.success",
  "src_ip": "1.2.3.4",
  "username": "root",
  "password": "toor",
  "session": "abc123"
}
{
  "eventid": "cowrie.command.input",
  "src_ip": "1.2.3.4",
  "session": "abc123",
  "input": "cat /etc/passwd"
}
```

Pipe into ELK / Splunk / Loki for SOC analysis.

### 3.6 False positive tuning for Cowrie

Common false positives:

| Source | Pattern | Mitigation |
|--------|---------|-----------|
| Internet-wide scanners (Shodan, Censys, Shadowserver) | Single SYN, no login attempt | Filter source ASNs |
| Vulnerability scanners (Nessus, Qualys) | Login with `admin/admin` then immediate disconnect | Tag the scanner's source IP |
| Health check systems | Periodic SSH banner grab | Filter the health-check source IP |
| Misconfigured clients | Repeated failed logins from a legitimate IP | Investigate before filtering |

Use a pre-filter:

```bash
# Example: drop events from known scanners
jq 'select(.src_ip | IN("1.1.1.1", "2.2.2.2") | not)' var/log/cowrie/cowrie.json
```

---

## 4. Dionaea — Multi-Protocol Honeypot

Dionaea is a multi-protocol honeypot that emulates SMB, FTP, HTTP, TFTP, MSSQL, MySQL, and several other services. It is best known for capturing malware samples dropped by automated attacks (especially via SMB / MS17-010 EternalBlue-style exploitation).

### 4.1 Why Dionaea

- **Protocol breadth**: catches attacks across many services from a single host.
- **Malware capture**: any uploaded file is saved for analysis.
- **p0f integration**: passive OS fingerprinting of the attacker.

### 4.2 Deployment

```bash
# Ubuntu / Debian
sudo apt install dionaea

# Edit /etc/dionaea/dionaea.conf
# - Set the list of services to enable
# - Configure logging (log to /var/log/dionaea/)
# - Configure the bistream save directory

# Or via Docker
docker run -d \
  --name dionaea \
  -p 21:21 -p 80:80 -p 443:443 -p 445:445 -p 1433:1433 -p 3306:3306 \
  -v /opt/dionaea:/data \
  dinotools/dionaea:latest

# Verify it's listening
ss -tlnp | grep dionaea
```

### 4.3 Configuration for SMB capture

```ini
# /etc/dionaea/dionaea.conf
[services]
smb = "yes"
ftp = "yes"
http = "yes"
tftp = "yes"
mssql = "yes"
mysql = "yes"

[logging]
default.logdir = "/var/log/dionaea/"
default.levels = "all"
default.logger.domain = "log"

[processor.filter_emu]
# enables emulation of shellcode via libemu
```

### 4.4 Captured malware handling

Dionaea saves uploaded binaries to `/var/lib/dionaea/binaries/`. Handle these carefully:

```bash
# List captured binaries (last 24h)
find /var/lib/dionaea/binaries/ -mtime -1 -type f

# Compute hashes and submit to VirusTotal
for f in /var/lib/dionaea/binaries/*; do
  sha256sum "$f"
  # or automate: vt-cli scan file "$f"
done

# Add to your malware zoo for further analysis
```

### 4.5 Dionaea + log shipping

Ship Dionaea's logs to your SIEM:

```bash
# /etc/rsyslog.d/30-dionaea.conf
if $programname == 'dionaea' then /var/log/dionaea/dionaea.log
& stop

# Forward to SIEM
*.* action(type="omfwd" target="siem.example.com" port="514" protocol="tcp")
```

---

## 5. HFish — Internal Deception Platform

HFish is a Chinese-developed (but open-source and English-supported) internal deception platform. It is designed for enterprise deployment with a centralized management UI, multiple sensors across the network, and built-in alerting.

### 5.1 Why HFish

- **Centralized management**: deploy one HFish server, push sensors to multiple network segments.
- **Web UI**: operations-friendly; non-engineers can review alerts.
- **Multi-protocol sensors**: SSH, web, FTP, Redis, MySQL, etc.
- **Bilingual**: works in Chinese and English.

### 5.2 Deployment

```bash
# Download the latest release
wget https://github.com/hacklcx/HFish/releases/download/v0.7.0/HFish-v0.7.0-linux-amd64.tar.gz
tar -xzf HFish-v0.7.0-linux-amd64.tar.gz
cd HFish-v0.7.0

# Initialize the database (SQLite by default; MySQL for production)
./HFish -init

# Start the management UI on port 443 (web)
./HFish -service

# Access https://<server-ip>:443/web
# Default credentials: admin / HFish2021
# CHANGE THE PASSWORD IMMEDIATELY.
```

### 5.3 Deploying sensors

From the management UI, generate a sensor-install command for each network segment:

```bash
# Sensor install (run on a host in the target segment)
curl -s https://hfish.example.com/api/sensor/install | bash
```

The sensor reports back to the central HFish server. Alerts are aggregated and visible in the UI.

### 5.4 Configuration

```yaml
# /opt/hfish/config.yml
listen:
  - {port: 22, protocol: ssh, name: "prod-ssh"}
  - {port: 3306, protocol: mysql, name: "prod-mysql"}
  - {port: 6379, protocol: redis, name: "prod-redis"}
  
alerting:
  webhook:
    url: https://hooks.slack.com/services/...
    events: [ssh_login, mysql_query, redis_cmd]
  
  email:
    smtp_server: smtp.example.com
    from: hfish@example.com
    to: soc@example.com
```

### 5.5 Use case: catching lateral movement

Deploy HFish sensors in:

- Each production VLAN
- The management network
- The DMZ
- The OT / ICS network (if you have one)

An attacker who compromises a host in one VLAN and starts scanning for SSH / MySQL / Redis in adjacent VLANs will hit an HFish sensor almost immediately. The resulting alert is high-fidelity: legitimate users do not typically try to SSH into "honeypot" hosts.

---

## 6. T-Pot — The All-in-One Honeypot Platform

T-Pot (by Telekom Security / Deutsche Telekom) is a Docker-based all-in-one honeypot platform. It bundles 20+ honeypot daemons (Cowrie, Dionaea, Heralding, Honeytrap, Conpot, etc.) behind a single front-end (nginx, with a bootstrap landing page), and ships logs to a pre-configured ELK stack.

### 6.1 Why T-Pot

- **One VM, twenty honeypots**: minimal operational overhead.
- **Pre-built ELK**: logs are ingested into Elasticsearch / Kibana automatically.
- **Attack visualization**: the Kibana dashboard shows attack maps, top usernames, top passwords, captured malware.
- **Maintenance**: the team releases ISO images quarterly.

### 6.2 Deployment (ISO)

1. Download the T-Pot ISO from [github.com/telekom-security/tpotce](https://github.com/telekom-security/tpotce/releases).
2. Install on a dedicated VM (8 GB RAM minimum, 16+ GB recommended).
3. Boot. The system comes up with all honeypots running.
4. Access the web UI at `https://<host>:64297/` (admin / some-long-password-changed-on-first-boot).

### 6.3 Deployment (Postinstall on Ubuntu)

```bash
git clone https://github.com/telekom-security/tpotce
cd tpotce/iso/installer
./install.sh --type=auto
```

### 6.4 T-Pot architecture

```
                          Internet
                              │
                              ▼
                    ┌──────────────────┐
                    │   nginx (frontend) │
                    └──────────────────┘
                              │
        ┌────┬────┬────┬──────┼──────┬────┬────┬────┐
        ▼    ▼    ▼    ▼      ▼      ▼    ▼    ▼    ▼
      Cowrie Dionaea Heralding ...  Conpot ... EWSpout ...
        │    │    │    │      │      │    │    │    │
        └────┴────┴────┴──────┴──────┴────┴────┴────┘
                              │
                       (JSON logs to /data)
                              │
                              ▼
                    ┌──────────────────┐
                    │ Filebeat / Logstash │
                    └──────────────────┘
                              │
                              ▼
                    ┌──────────────────┐
                    │  Elasticsearch   │
                    └──────────────────┘
                              │
                              ▼
                    ┌──────────────────┐
                    │     Kibana       │
                    └──────────────────┘
```

### 6.5 Tuning T-Pot for production

T-Pot is designed for Internet-exposed research honeypots. For internal production deployment:

1. **Reduce the honeypot set**: edit `/opt/tpot/etc/tpot.yml` to disable honeypots that conflict with production services.
2. **Bind to specific interfaces**: do not expose honeypots on interfaces serving production traffic.
3. **Increase logging retention**: default retention may be too short. Set `ES_JAVA_OPTS=-Xms16g -Xmx16g` and increase disk.
4. **Lock down the admin UI**: the Kibana UI must be behind a firewall — it is not Internet-safe by default.

### 6.6 Useful T-Pot commands

```bash
# Status of all honeypots
tpots.sh status

# View logs for a specific honeypot
tpots.sh logs cowrie

# Update T-Pot
tpots.sh update

# Restart everything
tpots.sh restart
```

---

## 7. Notification Pipelines — Slack, Teams, Webhooks

The point of deception is to alert when something fires. The alert pipeline is the most operationally important component.

### 7.1 Slack webhook

```bash
# Create a Slack app, add an incoming webhook (replace with your own webhook URL)
curl -X POST "https://hooks.slack.com/services/REPLACE_WITH_YOUR_WEBHOOK" \
  -H 'Content-type: application/json' \
  -d '{
    "text": ":rotating_light: Honeypot alert",
    "blocks": [
      {
        "type": "section",
        "text": {
          "type": "mrkdwn",
          "text": "*Cowrie SSH login* from `1.2.3.4`\nUsername: `root`\nPassword: `toor`\nSession: abc123"
        }
      }
    ]
  }'
```

### 7.2 Microsoft Teams webhook

```bash
curl -X POST https://outlook.office.com/webhook/XXXX \
  -H 'Content-Type: application/json' \
  -d '{
    "@type": "MessageCard",
    "@context": "http://schema.org/extensions",
    "themeColor": "FF0000",
    "summary": "Honeypot alert",
    "title": "Cowrie SSH login",
    "sections": [{
      "activityTitle": "1.2.3.4 attempted root/toor login",
      "facts": [
        {"name": "Source IP", "value": "1.2.3.4"},
        {"name": "Username", "value": "root"},
        {"name": "Password", "value": "toor"}
      ]
    }]
  }'
```

### 7.3 Splunk HEC

```python
import requests

SPLUNK_HEC = "https://splunk.example.com:8088/services/collector"
TOKEN = "..."

def ship_to_splunk(event):
    requests.post(
        SPLUNK_HEC,
        headers={"Authorization": f"Splunk {TOKEN}"},
        json={
            "sourcetype": "honeypot",
            "source": "cowrie",
            "index": "deception",
            "event": event,
        },
        verify=False
    )
```

### 7.4 The "phone-the-on-call" pipeline

For high-severity deception events (e.g., a canarytoken in production fired), the alert should page the on-call:

```python
# PagerDuty
def page_on_call(title, severity, details):
    requests.post(
        "https://events.pagerduty.com/v2/enqueue",
        json={
            "routing_key": PAGERDUTY_KEY,
            "event_action": "trigger",
            "payload": {
                "summary": title,
                "severity": severity,
                "source": "deception-platform",
            },
            "details": details,
        }
    )
```

### 7.5 Multi-tier alerting

Not every honeypot event should page a human. Tier the alerts:

| Tier | Examples | Routing |
|------|----------|---------|
| 1 — Critical | Production canarytoken fired; insider threat | Page on-call immediately |
| 2 — High | Cowrie successful login from internal IP | Slack #soc-high |
| 3 — Medium | Dionaea captured new malware sample | Slack #soc-medium |
| 4 — Low | Internet-wide scanner hit Cowrie | Log only (no alert) |

---

## 8. False Positive Tuning

A honeypot that fires constantly is a honeypot the SOC will eventually mute. False positive tuning is an ongoing operational discipline.

### 8.1 Common false positives

| Source | Pattern | Mitigation |
|--------|---------|-----------|
| Shodan, Censys, Shadowserver | Periodic banner grabs | Source ASN / IP allowlist |
| Internal vulnerability scanners | Nessus, Qualys scanning the honeypot | Tag the scanner's source IP, route to low-tier alert |
| Configuration management tools | Ansible / Puppet / Chef attempting to enroll the honeypot | Allowlist the CM source |
| Health-check systems | TCP-connect from monitoring | Allowlist |
| Reverse DNS / SMTP callbacks | Some services do DNS lookups that hit DNS canarytokens | Whitelist the internal resolver |
| Legitimate users who mistype | SSH to a honeypot hostname by accident | Investigate before muting |

### 8.2 Building a baseline

When deploying a new honeypot, expect:

1. **First 24 hours**: a flood of internet-wide scanner traffic. This is normal.
2. **Days 2-7**: the scanner noise stabilizes. Build an allowlist of scanner ASNs.
3. **Week 2+**: residual traffic should be a mix of opportunistic attackers and (occasionally) targeted attackers. Alerts at this stage are higher signal.

### 8.3 Per-event triage rubric

For each alert, answer:

1. Is the source IP a known scanner? (Shodan, Censys, etc.)
2. Is the source IP an internal CM tool? (Ansible, Puppet)
3. Is the activity consistent with the honeypot's expected "background radiation"?
4. Is there a second event from the same source shortly after? (Suggests targeted activity.)
5. Does the source IP appear in threat intel feeds?

If 1, 2, or 3 → mute or low-tier. If 4 or 5 → escalate.

---

## 9. Attacker Engagement Playbook

When an attacker interacts with a honeypot — especially over multiple sessions — the deception platform becomes an intelligence-collection asset. Follow this engagement playbook.

### 9.1 Phase 1: Detect

The first event fires. Triage per §8.3. If classified as a real attacker (not scanner noise), move to Phase 2.

### 9.2 Phase 2: Observe

Do not engage yet. Let the attacker explore the honeypot. Capture:

- All credentials tried
- All commands executed
- All files uploaded or downloaded
- All outbound connection attempts (C2 callbacks)
- The attacker's TTPs (tool choices, command sequences, persistence attempts)

### 9.3 Phase 3: Enrich

Enrich the captured data:

- Source IP → ASN, geo, threat-intel reputation
- Credentials tried → check against HaveIBeenPwned corpora (are they testing known breaches?)
- Uploaded malware → VirusTotal, ReversingLabs, internal sandbox
- C2 callbacks → domain reputation, passive DNS

### 9.4 Phase 4: Decide

Decision tree:

```
Is the attacker a targeted threat (APT) or opportunistic?
├── Opportunistic → log for threat intel; do not engage further.
└── Targeted →
    ├── Is insider threat possible? → coordinate with HR / legal.
    └── Is external APT? → coordinate with IR team and (potentially) law enforcement.
```

### 9.5 Phase 5: Contain

If the attacker is real and the engagement scope allows, contain:

- Block the source IP at the perimeter (knowing they will return with a different IP).
- Search production logs for the same TTPs (the attacker may have hit production first).
- Issue canarytoken sweep: confirm no production canaries are also firing.

### 9.6 Phase 6: Document

Every engagement becomes a case file:

```
engagement-2026-06-21-cowrie-1.2.3.4/
├── session-transcripts/        # raw cowrie logs
├── captured-files/             # files the attacker downloaded
├── malware-samples/            # binaries, with hashes
├── enrichment/
│   ├── ip-reputation.json
│   ├── asn-info.json
│   └── virustotal-reports/
├── timeline.md                 # chronological narrative
└── summary.md                  # 1-page executive summary
```

---

## 10. Integration with Adjacent Skills

### 10.1 Threat hunting

When a honeypot captures an attacker's TTPs, hand those TTPs to the threat-hunting team. They will hunt the production network for the same indicators:

- Same credentials tried against production SSH
- Same malware hash on production endpoints
- Same C2 domains in production DNS logs

This is the highest-value output of a deception program: it converts honeypot intelligence into production-network detections.

### 10.2 Digital forensics

Captured honeypot artifacts (malware, credentials, command sequences) are forensically valuable. Preserve them under chain of custody in case the engagement escalates to incident response.

### 10.3 Threat intelligence

Share sanitized indicators with:

- Internal threat intel platform (MISP)
- ISAC (Information Sharing and Analysis Center) for your sector
- Public feeds (e.g., AbuseIPDB) — when policy allows

### 10.4 Incident response

A honeypot firing is often the first indicator of a broader incident. Have a pre-defined IR runbook for "honeypot alert received" — the runbook should answer:

1. Who pages whom?
2. What is the threshold for declaring an incident?
3. What logging does IR need preserved?
4. What is the communication protocol (internal, external, regulatory)?

---

## 11. Metrics for a Deception Program

A deception program without metrics is an article of faith. Track:

| Metric | Definition | Target |
|--------|------------|--------|
| Coverage | % of in-scope assets with at least one deception element | > 80% |
| MTTD (mean time to detect) | Time between honeypot interaction and SOC alert | < 5 min |
| Alert fidelity | % of alerts classified as real attackers | > 20% |
| False positive rate | % of alerts classified as noise | < 80% (after tuning) |
| Engagement-to-action conversion | % of real-attacker engagements that produced actionable intel | > 30% |
| Production cross-over | % of honeypot-sourced TTPs that produced detections in production | > 10% |

Report these quarterly to leadership. Deception programs that cannot show metrics get cut.

---

## 12. References

### 12.1 Tools

- Thinkst Canarytokens: [canarytokens.org](https://canarytokens.org) / [github.com/thinkst/canarytokens](https://github.com/thinkst/canarytokens)
- Thinkst Canary (commercial): [canary.tools](https://canary.tools)
- Cowrie: [github.com/cowrie/cowrie](https://github.com/cowrie/cowrie)
- Dionaea: [github.com/DinoTools/dionaea](https://github.com/DinoTools/dionaea)
- HFish: [github.com/hacklcx/HFish](https://github.com/hacklcx/HFish)
- T-Pot: [github.com/telekom-security/tpotce](https://github.com/telekom-security/tpotce)
- OpenCanary: [github.com/thinkst/opencanary](https://github.com/thinkst/opencanary)
- Beelzebub (AI-driven deception): [github.com/mariocandela/beelzebub](https://github.com/mariocandella/beelzebub)
- Conpot (ICS/SCADA): [github.com/mushorg/conpot](https://github.com/mushorg/conpot)
- Honeysnap (log analysis): [github.com/Geekdom/honeysnap](https://github.com/Geekdom/honeysnap)

### 12.2 Frameworks and references

- MITRE Engage: [engage.mitre.org](https://engage.mitre.org/)
- The Honeynet Project: [honeynet.org](https://www.honeynet.org/)
- Honeypots: Tracking Hackers (book, Lance Spitzner): [amazon](https://www.amazon.com/Honeypots-Tracking-Hackers-Lance-Spitzner/dp/0321108957)
- "Know Your Enemy" series (Honeynet Project): [honeynet.org/books](https://www.honeynet.org/books)

### 12.3 Research papers

- Spitzner, "Honeypots: Definitions and Value of Honeypots" (2003)
- Provos & Holz, "Virtual Honeypots: From Botnet Tracking to Intrusion Detection" (2007)
- Fansi et al, "Honeypots in the Age of Encryption" (2019)

### 12.4 Deployment references

- T-Pot documentation: [github.com/telekom-security/tpotce/wiki](https://github.com/telekom-security/tpotce/wiki)
- Cowrie documentation: [cowrie.readthedocs.io](https://cowrie.readthedocs.io/)
- Thinkst Canarytokens documentation: [canarytokens.org/help](https://canarytokens.org/help)

---

## Appendix A: One-Page Deployment Cheat Sheet

```bash
# Generate a DNS canarytoken
# Visit https://canarytokens.org/generate and select "DNS"
# Place the returned hostname in production artifacts.

# Deploy Cowrie
sudo useradd -m cowrie
sudo -u cowrie git clone https://github.com/cowrie/cowrie /home/cowrie/cowrie
cd /home/cowrie/cowrie && sudo -u cowrie python3 -m venv cowrie-env
sudo -u cowrie cowrie-env/bin/pip install -r requirements.txt
sudo -u cowrie cp etc/cowrie.cfg.dist etc/cowrie.cfg
# Edit etc/cowrie.cfg: hostname, listen_endpoints
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
sudo -u cowrie bin/cowrie start

# Deploy Dionaea via Docker
docker run -d --name dionaea \
  -p 21:21 -p 445:445 -p 1433:1433 -p 3306:3306 \
  -v /opt/dionaea:/data \
  dinotools/dionaea:latest

# Deploy HFish
wget https://github.com/hacklcx/HFish/releases/download/v0.7.0/HFish-v0.7.0-linux-amd64.tar.gz
tar -xzf HFish-v0.7.0-linux-amd64.tar.gz && cd HFish-v0.7.0
./HFish -init && ./HFish -service

# Deploy T-Pot (ISO recommended; quick start via installer)
git clone https://github.com/telekom-security/tpotce && cd tpotce/iso/installer
./install.sh --type=auto

# Slack webhook test (replace placeholder with your real webhook URL)
curl -X POST "https://hooks.slack.com/services/REPLACE_WITH_YOUR_WEBHOOK" \
  -H 'Content-type: application/json' \
  -d '{"text":":rotating_light: honeypot deployed"}'

# Splunk HEC shipper
curl -k https://splunk.example.com:8088/services/collector \
  -H "Authorization: Splunk $TOKEN" \
  -d '{"event":"test","sourcetype":"honeypot","index":"deception"}'
```

---

*This playbook is maintained as part of the kali-claw `deception-honeypot` skill. Updates are tracked via `skills/deception-honeypot/SKILL.md` metadata version.*
