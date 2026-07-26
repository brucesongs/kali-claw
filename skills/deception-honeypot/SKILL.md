---
name: deception-honeypot
description: Defensive deception and honeypot deployment covering SSH/Telnet (Cowrie), web (OpenCanary), enterprise (HFish), ICS/SCADA (Conpot), all-in-one (T-Pot), AI-driven deception (Beelzebub), Thinkst Canarytokens (DNS, HTTP, file, AWS API key, SQL), Dionaea multi-protocol honeypot, notification pipelines (Slack/Teams webhooks), false positive tuning, and attacker engagement — including lure design, deployment OPSEC, IOC extraction, and attacker attribution.
origin: github-trending-2026
version: "0.2.0.2"
compatibility: ">=0.1.29"
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
  - Glob
  - Grep
  - WebFetch
metadata:
  domain: defense
  tool_count: 12
  guide_count: 2
  mitre: "TA0040-Detection (deception), maps to MITRE Engage framework"
  last_reviewed: "2026-07-26"
---




# Skill: Deception & Honeypot

> **Supplementary Files**:
> - `payloads.md` — Cowrie SSH/Telnet config, OpenCanary multi-service templates, HFish enterprise deployment, Conpot ICS/SCADA (Modbus/S7) templates, T-Pot all-in-one Docker Compose, Beelzebub AI-deception manifests, honeytoken/canarytoken design patterns, syn-ack dark-space & tarpit network deception, Glastopf web honeypot, HoneyDB database decoys, log-analysis & IOC-extraction pipelines, and a deception-architecture cheat sheet
> - `test-cases.md` — 12 structured test cases (Cowrie deploy, OpenCanary multi-service, HFish enterprise, Conpot ICS, T-Pot all-in-one, honeytoken design, Canarytokens, tarpit/dark-space, Glastopf web, HoneyDB, IOC extraction, attribution pipeline) with severity ratings and summary tables
> - `guides/deception-honeypot-playbook.md` — End-to-end deception playbook (deception architecture, lure-design principles, deployment OPSEC, monitoring & alerting, IOC extraction, attribution workflow, integration with adjacent skills)
> - `guides/canary-deployment-playbook.md` — Distributed honeypot and canary token deployment playbook (Thinkst Canarytokens for DNS/HTTP/file/AWS API keys/SQL, Cowrie SSH/Telnet honeypot setup, Dionaea multi-protocol capture, HFish internal deception sensors, T-Pot all-in-one platform, Slack/Teams webhook pipelines, false positive tuning, attacker engagement phases, deception program metrics)

## Summary

Deception & Honeypot skill domain covering defensive deception operations.

**Tools**: Cowrie, OpenCanary, HFish, Conpot, T-Pot, Beelzebub, Canarytokens (Thinkst), Honeyport, Glastopf, HoneyDB, Cowrie-Analyzer, MISP (for IOC sharing)

**Domain**: defense

**MITRE ATT&CK / MITRE Engage**: TA0040-Detection (deception); aligned to the MITRE Engage framework's *Prepare* (lure deployment), *Expose* (attacker interaction), *Affect* (resource burn), and *Collect* (IOC and TTP harvesting) goals.

## Description

Defensive deception turns the adversary's own reconnaissance against them. A honeypot is a system with no production value — any interaction with it is, by definition, suspicious. A well-designed deception program deploys lures across the attack surface (network, host, identity, application, OT), instruments each interaction with high-fidelity logging, and pipelines the resulting IOCs (source IPs, credentials tried, payloads uploaded, C2 callbacks) into the SOC, the threat-intel platform, and — when the engagement scope allows — the attribution workflow. This is the *active-defense* complement to threat hunting: hunting asks "what is already inside?", deception asks "what walks in if we leave the door open and instrumented?"

**Difference from `threat-hunting`**: Threat hunting consumes telemetry from production sensors and asks hypothesis-driven questions about an environment the adversary may already be inside. Deception *manufactures* telemetry — the honeypot's logs are pure signal, because no legitimate user has any reason to touch them. Hunting has a false-positive problem; a correctly deployed honeypot does not. Pair them: hunting catches the adversary who evades the decoys, deception catches the adversary who never reaches production.

**Difference from `digital-forensics`**: DFIR reconstructs a compromise after the fact under chain of custody. Deception records the adversary's behavior in real time, *before* they reach production. The forensic value of a honeypot session is enormous — it captures the attacker's toolkit, credentials, and tradecraft in a sterile, replayable artifact. A Cowrie session transcript is a portable IOCs package.

**Difference from `scada-ics-security`**: That skill includes a defensive ICS-honeypot subsection (Conpot deployment, indicator table). This skill generalizes deception across *all* domains — SSH/Telnet, web, enterprise, ICS, database, email — and adds the architecture, OPSEC, monitoring, IOC extraction, and attribution layers that an organization-wide deception program requires.

**MITRE Engage alignment**: This skill operationalizes the four Engage goals. *Prepare*: deploy Cowrie/Conpot/HFish lures within authorized scope. *Expose*: any interaction is an adversary indicator. *Affect*: tarpits and honeyports consume attacker time and resources. *Collect*: every session feeds the IOC pipeline and attribution graph.

## Use Cases

- **SSH/Telnet brute-force early warning**: Deploy Cowrie on a non-production IP in the DMZ. Any login attempt is a scanner or a worm. The captured credentials feed the password-policy review (are employees reusing credentials that show up in Cowrie?) and the SIEM (alert on any production login using a password Cowrie observed).
- **Internal lateral-movement tripwire**: Deploy internal honeypots (OpenCanary on a decoy file share, a fake `admin` account with a honeytoken in `~/.aws/credentials`) so an adversary who lands on one host and begins enumerating the interior trips an alert *before* they reach a real asset. Internal deception has near-zero false-positive rate — no user reaches a decoy share.
- **ICS/OT perimeter tripwire**: Deploy Conpot on the plant floor's management VLAN (within scope, on a switchport that connects to nothing real). Any Modbus/S7 read is unauthorized — industrial networks are deterministic, and unexpected traffic on a decoy PLC is a high-confidence intrusion indicator.
- **Web-application reconnaissance capture**: Deploy Glastopf (or T-Pot's web stack) on a decoy subdomain (`vpn.<domain>` that resolves but serves no real content) to capture SQLi payloads, LFI attempts, and scanner signatures. Feeds WAF tuning and the threat-intel feed.
- **Credential leak detection via honeytokens**: Plant a Canarytoken in a fake `Backup-vault.kdbx`, in a decoy `web.config` with a unique SMTP password, or in an AWS access key whose only legitimate use is "never." Any use of that credential is, by definition, an intruder (or an insider) and the alert is high-confidence.
- **Enterprise-wide deception rollout**: Deploy HFish as a centralized management plane — multiple honeypot endpoints across business units, aggregated alerts, and a unified IOC pipeline. HFish's web console gives the SOC a single pane to triage hits across dozens of deployed lures.
- **Attacker attribution & TTP harvesting**: When a honeypot captures a unique payload (uploaded malware, a C2 callback, a password-spray pattern), pivot that IOC through MISP, VirusTotal, and Shodan to attribute to a threat actor. The honeypot is now an intelligence-collection platform, not just an early-warning system.
- **Worm propagation tracking**: A T-Pot multi-honeypot deployment observed over weeks reveals worm families by their propagation patterns (which ports, which credentials, which payloads) and provides empirical input to network-segmentation and patch-priority decisions.
- **Insider-threat tripwire**: Honeytoken files on a sensitive share (`HR-Salaries-FY26.xlsx.canarytoken.docx`) trigger on insider exfiltration where network telemetry is silent (an employee with legitimate access copying data they shouldn't).

## Core Tools

### Multi-Purpose & All-in-One

| Tool | Purpose | Deployment |
|------|---------|------------|
| **T-Pot** | All-in-one honeypot platform — bundles 20+ honeypots (Cowrie, Dionaea, Heralding, Conpot, Honeytrap, Glutton, etc.) with ElasticStack, Attack Map, and the Pottee management UI on a single host | `docker compose up -d` against the T-Pot `docker-compose.yml`; 16GB RAM minimum |
| **HFish** | Enterprise honeypot with a centralized management console, multi-endpoint agents, and built-in alerting — designed for organizational rollout across business units | Docker: `docker run -d --name hfish -p 4433:4433 ... hfish/hfish:latest`; or binary on Linux/Windows |
| **Beelzebub** | AI-driven deception framework — uses LLMs to generate dynamic, context-aware honeypot responses (more believable bash sessions, HTTP error pages) to extend attacker engagement | `docker run -d -v ./config:/config ghcr.io/mariocandela/beelzebub:latest` |

### Service-Specific Honeypots

| Tool | Protocol(s) | Purpose |
|------|-------------|---------|
| **Cowrie** | SSH, Telnet | Medium-interaction shell — fake filesystem, command execution emulation, captures uploads and downloaded malware. The workhorse of SSH-attack intelligence. |
| **OpenCanary** | Modular (SSH, HTTP, FTP, SMB, MSSQL, Redis, RDP, VNC, NTP, TFTP, SNMP, etc.) | Lightweight daemon with a modular service list — each service is a low-interaction canary that alerts on any TCP connection. Ideal for internal tripwires. |
| **Conpot** | ICS/SCADA — Modbus TCP, S7comm (Siemens), IPMI, IEC-104, BACnet | Industrial honeypot with real PLC templates (e.g., Siemens S7-200). Critical for OT/ICS deception — production ICS has no legitimate unplanned traffic. |
| **Dionaea** | SMB, HTTP, FTP, TFTP, MSSQL, MySQL, SIP | Nepenthes successor; embedded in T-Pot. Captures malware samples via SMB/HTTP and submits them to Cuckoo/VirusTotal. |
| **Glastopf** | HTTP (PHP/SQLi-focused) | Web honeypot that emulates vulnerable PHP apps and responds to SQLi/RCE/RFI payloads. Captures exploit payloads and bot-scanner signatures. |
| **Heralding** | POP3, IMAP, SMTP, HTTP, SSH, Telnet, FTP, MSSQL, MySQL, PostgreSQL, RDP | Credential-capture honeypot — collects username/password pairs tried against many protocols. Feeds password-policy review. |

### Network Deception & Honeytokens

| Tool | Purpose | Usage |
|------|---------|-------|
| **Canarytokens (Thinkst)** | Generates honeytokens — unique URLs, DNS names, AWS keys, Word docs, etc. — that alert when triggered. Hosted or self-hosted Canarytoken server. | `https://canarytokens.org/generate` (free hosted); or self-host the open-source server |
| **Honeyport** | A bash one-liner that opens a port and logs (or firewalls) any IP that connects. Simplest possible network canary. | `while true; do nc -l -p 12345 >> honeyport.log; done` |
| **Endlessh (tarpit)** | SSH tarpit that advertises an SSH banner then slowly sends endless SSH version-exchange bytes. Traps SSH worms/scanners indefinitely. | `endlessh -p 22 -v` (deployment on a non-production IP) |
| **Honeytrap** | Modular network honeypot that listens on many TCP ports simultaneously and redirects attacker connections to higher-interaction backends. | Part of T-Pot; standalone: `honeytrap -P` |

### Monitoring & Analysis

| Tool | Purpose |
|------|---------|
| **Elastic Stack (Kibana)** | T-Pot ships with full ELK — indexes all honeypot logs, Attack Map visualization, per-protocol dashboards |
| **MISP** | Open-source threat-intel platform — receive honeypot IOCs, correlate with community feeds, share back |
| **Cowrie-Analyzer / playbooks** | Cowrie-output parsing scripts (`cowrie-analyzer`, `honeypot-scripts`) that extract uploaded binaries, decode commands, and pivot to VirusTotal |
| **Cuckoo Sandbox** | Optional automated malware-analysis backend for binaries Cowrie/Dionaea capture |

## Methodology

### Deception Six-Phase Process

```
Phase 1              Phase 2              Phase 3              Phase 4              Phase 5              Phase 6
Architecture      →  Lure Design       →  Deployment OPSEC  →  Monitoring &       →  IOC Extraction   →  Attribution &
& Scoping            & Realism             (within scope)        Alerting             & TTP Harvesting      Sharing
   │                    │                    │                    │                    │                    │
   ▼                    ▼                    ▼                    ▼                    ▼                    ▼
Map attack surface,  Pick tools per       Decoy IPs, naming,   High-fidelity logs   Parse sessions,      Pivot IOCs through
define authorized    target vector,       honeytoken uniqueness to SIEM, alert on     extract binaries,    MISP/VirusTotal/
scope, isolation     fake data realism,   network isolation,   ANY interaction      decode commands,     Shodan, attribute
strategy             banner fidelity      egress controls                           send binaries to     to threat actor,
                                                                                     sandbox              feed detections
```

**Phase 1: Architecture & Scoping**

Before any lure ships, define the engagement. Deception is high-value but legally sensitive — the honeypot's logs will capture attacker IP addresses, passwords, and malware, all of which may be subject to wiretap, data-protection, or computer-fraud statutes.

```
Scope checklist:
- [ ] What network(s) are authorized for the deployment? (DMZ, internal VLANs, OT/ICS)
- [ ] Is a written authorization (RoE / SoW) in place? Honeypots are sensors, not traps.
      Do not configure the honeypot to encourage attackers to attack *other* systems.
- [ ] Isolation: can an attacker who pops the honeypot reach production? (It must NOT.)
      Use VLAN/firewall isolation; never deploy a honeypot on a flat L2 alongside prod.
- [ ] Data handling: who can read honeypot logs? They contain attacker-attributable data.
- [ ] Egress policy: can a high-interaction honeypot phone out? (Default: NO.)
      Block all outbound except to a controlled malware-analysis sandbox.
- [ ] Jurisdiction: where are the logs stored? Cross-border data movement triggers GDPR/PIPL.
```

**Phase 2: Lure Design & Realism**

A honeypot that looks obviously fake will be ignored by a sophisticated adversary and only catch the noisiest worms. Realism is in the details.

```bash
# Cowrie realism checklist:
# - Banner: matches the production SSH version (don't ship "SSH-2.0-OpenSSH_6.0p1"
#   if your fleet is on 9.x — attackers fingerprint this)
# - Fake filesystem: populate /etc/, /home/, /var/log/ with realistic-looking files
#   (use Cowrie's fsctl to manage the pickle filesystem)
# - Fake users: include names from your org's directory (with manager approval)
# - Hostname: matches the org's naming convention (prod-web-07, not "honeypot-1")
# - Architecture: arm vs x86_64 — pick what your real fleet runs

# OpenCanary / web realism checklist:
# - DNS record exists for the decoy hostname (don't ship on a bare IP)
# - TLS cert matches the decoy hostname (use LetsEncrypt for free)
# - Banner matches production web server (don't run Apache 2.2 if prod is nginx 1.25)
```

**Phase 3: Deployment OPSEC**

The honeypot must be observable but not exposable. It must not become a launchpad.

```bash
# Network isolation (iptables example on the honeypot host)
# Allow inbound from the monitored segment
iptables -A INPUT -s $MONITORED_CIDR -j ACCEPT
# Allow management SSH from jump host only
iptables -A INPUT -s $JUMP_HOST -p tcp --dport 22 -j ACCEPT
# DROP outbound — high-interaction honeypots do NOT phone home
iptables -P OUTPUT DROP
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
# Allow outbound ONLY to the controlled malware-analysis sandbox
iptables -A OUTPUT -d $SANDBOX_IP -j ACCEPT

# Heralding / Cowrie systemd unit (auto-start, auto-restart)
cat > /etc/systemd/system/cowrie.service <<'EOF'
[Unit]
Description=Cowrie SSH/Telnet Honeypot
After=network.target

[Service]
Type=simple
User=cowrie
WorkingDirectory=/opt/cowrie
ExecStart=/opt/cowrie/bin/cowrie start -n
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
systemctl enable --now cowrie
```

**Phase 4: Monitoring & Alerting**

Every honeypot session is an event worth alerting on. Forward to the SIEM with high priority.

```bash
# Cowrie ships JSON logs to /opt/cowrie/var/log/cowrie/cowrie.json
# Tail to SIEM via Filebeat, rsyslog, or Vector
# /etc/filebeat/inputs.d/cowrie.yml
- type: log
  paths:
    - /opt/cowrie/var/log/cowrie/cowrie.json
  json.keys_under_root: true
  fields:
    source: honeypot
    honeypot_type: cowrie
    severity: high

# Sigma rule: any Cowrie session (no FP — production users never hit Cowrie)
title: Honeypot Session — Cowrie SSH/Telnet Interaction
id: a1b2c3d4-0001-4000-8000-000000000001
status: stable
description: Any interaction with a Cowrie honeypot is unauthorized. Alert on every event.
logsource:
  product: honeypot
  service: cowrie
detection:
  selection:
    source: honeypot
    honeypot_type: cowrie
  condition: selection
level: high
```

**Phase 5: IOC Extraction & TTP Harvesting**

A honeypot session is a packaged IOCs artifact. Pipeline it.

```bash
# Cowrie: extract uploaded binaries from session logs
jq -r 'select(.eventid=="cowrie.session.file_download") | .destfile' \
  /opt/cowrie/var/log/cowrie/cowrie.json | sort -u

# Cowrie: extract every credential tried
jq -r 'select(.eventid=="cowrie.login.successful" or .eventid=="cowrie.login.failed") |
  "\(.src_ip) \(.username):\(.password)"' \
  /opt/cowrie/var/log/cowrie/cowrie.json | sort -u > iocs/creds.tsv

# Cowrie: extract every command executed (post-login)
jq -r 'select(.eventid=="cowrie.command.input") | "\(.src_ip)\t\(.input)"' \
  /opt/cowrie/var/log/cowrie/cowrie.json

# Submit binaries to VirusTotal (with API key) — see payloads.md §12
for bin in /opt/cowrie/var/lib/cowrie/downloads/*; do
  hash=$(sha256sum "$bin" | awk '{print $1}')
  curl -s -H "x-apikey: $VT_KEY" "https://www.virustotal.com/api/v3/files/$hash" \
    | jq -r '.data.attributes.last_analysis_stats'
done
```

**Phase 6: Attribution & Sharing**

Pivot the harvested IOCs into the threat-intel ecosystem. Reciprocity: share back.

```bash
# Push IOCs to MISP
misp-add-event --distribution 0 --info "Cowrie observed IOCs $(date +%F)" \
  --tag honeypot --tag cowrie

# Query Shodan for the attacker IP's exposed services (reconnaissance context)
curl -s "https://api.shodan.io/shodan/host/<attacker_ip>?key=$SHODAN_KEY" | \
  jq '{ip, country_name, org, ports, vulns}'

# Correlate attacker IP against AbuseIPDB
curl -s "https://api.abuseipdb.com/api/v2/check?ipAddress=<attacker_ip>&maxAgeInDays=90" \
  -H "Key: $ABUSEIPDB_KEY" -H "Accept: application/json" | jq '.data'
```

### Quick Selection Guide

| Scenario | Primary Approach | Alternative |
|----------|------------------|-------------|
| Catch SSH/Telnet worms and credential stuffing | Cowrie on a non-prod IP in the DMZ | Heralding for multi-protocol cred capture |
| Catch internal lateral movement | OpenCanary on internal VLANs with SMB/HTTP modules | Canarytoken in `~/.aws/credentials` |
| Catch ICS/OT intrusions | Conpot on plant management VLAN | T-Pot's conpot module |
| Enterprise-wide rollout with central console | HFish (multi-endpoint, web UI) | T-Pot per-region, ELK aggregator |
| Single-host demonstration / lab | T-Pot (everything in one box) | Beelzebub (AI-driven, lighter) |
| Catch web-app scanners (SQLi, RFI) | Glastopf on a decoy subdomain | T-Pot's web stack |
| Catch credential leak via honeytoken | Canarytokens (Word doc, AWS key, DNS) | Honeytoken files in KeePass/Knox |
| Slow down SSH worms (tarpit) | Endlessh on a non-prod port 22 | Labrea tarpit |
| Capture uploaded malware for sandbox | Dionaea (in T-Pot) | Cowrie + Cuckoo backend |
| Forward alerts to Splunk/Sentinel | Filebeat from Cowrie JSON logs | HFish built-in SIEM forwarder |

### Defense Perspective

| Defense Output | Description |
|----------------|-------------|
| **High-confidence alerts** | A correctly deployed honeypot produces zero false positives — no legitimate user has reason to touch a decoy. Every alert is high priority. This is the unique value of deception vs. signature-based detection. |
| **IOC feed (internal + shared)** | Honeypot sessions are packaged IOCs: source IPs, credentials, payloads, C2 callbacks. Feed them into MISP, the SIEM, and (reciprocally) back to the community via AbuseIPDB. |
| **TTP intelligence** | The commands an attacker runs post-login, the payloads they upload, the lateral movement they attempt — all are TTPs that feed the threat-hunting hypotheses. Cowrie transcripts are the basis of new ATT&CK-mapped detections. |
| **Password-policy feedback** | Credentials captured by Heralding/Cowrie that match real employee passwords (via a one-way hash comparison against AD) are an immediate rotation-and-MFA trigger. |
| **Worm/malware family tracking** | T-Pot over months reveals the propagation patterns of worm families — which ports, which default creds, which payloads — informing patch prioritization and segmentation. |
| **Engage-mapped KPIs** | Track the deception program against MITRE Engage metrics: # of *Expose* events (decoys hit), # of *Affect* events (attacker time burned in tarpits), # of *Collect* artifacts (unique malware samples). |

## Practical Steps

> **Detailed payloads in `payloads.md`, complete test checklist in `test-cases.md`.**

### Exercise 1: Deploy Cowrie as a Medium-Interaction SSH Honeypot

Goal: stand up Cowrie, capture one login attempt, extract the credentials.

```bash
# Install dependencies (Debian/Ubuntu)
sudo apt update
sudo apt install -y python3 python3-venv python3-dev git authbind \
  build-essential libssl-dev libffi-dev curl

# Create cowrie user and clone
sudo adduser --disabled-password --gecos "" cowrie
sudo -u cowrie -i
cd ~
git clone https://github.com/cowrie/cowrie.git
cd cowrie
python3 -m venv cowrie-env
source cowrie-env/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Configure: copy the sample config and set the listening port
cp etc/cowrie.cfg.dist etc/cowrie.cfg
# Edit etc/cowrie.cfg:
#   [ssh] listen_endpoints = tcp:2222:interface=0.0.0.0
#   hostname = prod-web-07   # realistic decoy name
#   sensor_name = cowrie-dmz-01

# Run (authbind allows listening on privileged ports if you set 22;
# for testing, 2222 is simpler)
bin/cowrie start

# Generate SSH key for the honeypot host
ssh-keygen -t ed25519 -f var/lib/cowrie/ssh_host_ed25519_key -N ""

# Tail the JSON log
tail -f var/log/cowrie/cowrie.json

# From another host, attempt a login:
ssh -p 2222 root@<honeypot_ip>      # password anything — Cowrie accepts most

# Extract credentials tried:
jq -r 'select(.eventid | startswith("cowrie.login")) |
  "\(.timestamp) \(.src_ip) \(.username):\(.password)"' \
  var/log/cowrie/cowrie.json | tail -20
```

### Exercise 2: Deploy OpenCanary as an Internal Tripwire

Goal: deploy OpenCanary on an internal Linux host with SMB, SSH, and HTTP modules, triggering on internal scans.

```bash
# Install via pip
sudo pip3 install virtualenv
sudo virtualenv /opt/canary-env
sudo /opt/canary-env/bin/pip install opencanary

# Generate config
sudo /opt/canary-env/bin/opencanaryd --copyconfig
# Config lands at /etc/opencanaryd/opencanary.conf — edit modules:

# /etc/opencanaryd/opencanary.conf (JSON)
{
  "device.name": "internal-fileshare-3",
  "ssh.enabled": true,
  "ssh.port": 22,
  "http.enabled": true,
  "http.port": 80,
  "http.skin": "nasLogin",
  "smb.auditfile": "/var/log/opencanary/smb-audit.log",
  "smb.enabled": true,
  "ftp.enabled": true,
  "ftp.port": 21,
  "logger": {
    "class": "PySysLoggerEventLogger",
    "kwargs": {"ident": "opencanary"}
  }
}

# Run (need root for low ports)
sudo /opt/canary-env/bin/opencanaryd --start

# Trigger: from another internal host, attempt to connect
nc -v <internal_decoy_ip> 22         # SSH canary fires
curl http://<internal_decoy_ip>/      # HTTP canary fires
smbclient -L //<internal_decoy_ip>/   # SMB canary fires

# Logs land in syslog (PySysLoggerEventLogger)
journalctl -t opencanary -f
```

### Exercise 3: Deploy HFish for Enterprise-Wide Deception Management

Goal: stand up HFish, enroll two endpoints, observe the management console.

```bash
# Quick-start: Docker
docker run -d --name hfish \
  -p 4433:4433 \
  -v /opt/hfish:/opt/hfish \
  --privileged \
  hfish/hfish:latest

# Access the management console:
#   https://<hfish_host>:4433/
# Initial credentials (CHANGE IMMEDIATELY): admin / admin

# Through the console:
#   1. Add honeypot endpoints (other hosts running the HFish agent)
#   2. Configure protocol templates (SSH, HTTP, MySQL, Redis, etc.) per endpoint
#   3. Set up alert notifications (Slack, email, webhook)
#   4. Review the "Attack Map" for real-time hit visualization

# On each endpoint, install the agent:
docker run -d --name hfish-agent \
  -e HFISH_SERVER=https://<hfish_host>:4433 \
  -e ENDPOINT_NAME=dmz-decoy-02 \
  hfish/hfish-agent:latest

# Verify in the console that each endpoint reports "online"
# Trigger a test hit against one endpoint and confirm the alert fires
```

### Exercise 4: Deploy Conpot as an ICS/SCADA Decoy

Goal: deploy Conpot emulating a Siemens S7 PLC on the OT management VLAN.

```bash
# Install Conpot
sudo apt install -y libsmi2-dev libxslt1-dev libxml2-dev python3-dev
python3 -m venv /opt/conpot-env
source /opt/conpot-env/bin/activate
pip install conpot

# Run with the default template (a Siemens S7 PLC profile)
conpot -f --template default

# Or specify a custom template on a custom IP
conpot -f --template kemel --host 10.10.50.200

# Verify with a Modbus client (from another host)
pip install pymodbus
python3 -c "
from pymodbus.client import ModbusTcpClient
c = ModbusTcpClient('10.10.50.200', port=502)
print(c.read_holding_registers(0, 10).registers)
"

# Conpot logs Modbus/S7 interactions — forward to SIEM
tail -f /var/log/conpot.json | \
  jq 'select(.remote[0] != null) | {time: .timestamp, src_ip: .remote[0],
       proto: .data_type, data: .data}'
```

### Exercise 5: Deploy T-Pot as an All-in-One Lab

Goal: deploy T-Pot on a dedicated Linux host (16GB+ RAM), access the Attack Map.

```bash
# T-Pot requires a clean Debian/Ubuntu install, 16GB+ RAM, 8+ vCPU recommended
# Clone and run the installer
git clone https://github.com/telekom-security/tpotce.git
cd tpotce
sudo ./install.sh --type=auto

# Follow prompts; on completion, the Attack Map is at:
#   https://<tpot_host>:64297/
# Default credentials in /etc/tpot/tpot.yml — CHANGE IMMEDIATELY

# T-Pot runs these honeypots by default (docker compose ps):
#   cowrie, dionaea, heralding, conpot, glastopf, glutton, honeytrap,
#   malcolm, elasticpot, adbhoney, cnijing, dicompot, dicompot-vln,
#   mailoney, multipot, rdpy, sentrypepot

# View real-time hits in Kibana (Attack Map):
#   https://<tpot_host>:5601/

# Forward T-Pot's ELK data to a centralized SIEM via Logstash output
```

### Exercise 6: Deploy Beelzebub as an AI-Driven Deception Layer

Goal: stand up Beelzebub with an LLM-driven SSH honeypot that produces dynamic bash sessions.

```bash
# Beelzebub config — YAML manifest
mkdir -p /opt/beelzebub/config
cat > /opt/beelzebub/config/config.yaml <<'EOF'
beelzebub:
  core:
    queryTimeInterval: 5
    schedulerSecond: 30
    PrometheusEnable: true
    PrometheusPort: 9090

  plugins:
    # Optional OpenAI / Mistral key for the LLM-driven responses
    openai:
      enabled: false
      # secret: "sk-..."
      # model: "gpt-4o-mini"

  protocols:
    - name: "ssh-honeypot"
      protocol: "ssh"
      address: "0.0.0.0:22"
      prompt: "prod-web-07:~$ "
      commands:
        - regex: "^uname.*"
          handler: "/usr/bin/uname -a"
        - regex: "^id.*"
          handler: "uid=0(root) gid=0(root) groups=0(root)"
EOF

# Run via Docker
docker run -d --name beelzebub \
  -p 22:22 -p 9090:9090 \
  -v /opt/beelzebub/config:/config \
  ghcr.io/mariocandela/beelzebub:latest

# Trigger: SSH in and run commands — Beelzebub responds dynamically
ssh root@<beelzebub_ip>

# Observe Prometheus metrics for hit counts per protocol
curl http://<beelzebub_ip>:9090/metrics | grep beelzebub
```

### Exercise 7: Deploy Canarytokens for Honeytoken Alerts

Goal: generate three Canarytokens (Word doc, DNS, AWS API key) and confirm alerts on use.

```bash
# Option A: use the free hosted service
#   https://canarytokens.org/generate
# Choose:
#   - "Web Bug / URL Token" -> a unique URL that fires when fetched
#   - "DNS Token"            -> a unique hostname that fires when resolved
#   - "AWS API Keys"         -> fake AWS creds that fire when used
#   - "Microsoft Word Document" -> .docx with an embedded beacon

# Option B: self-host the open-source Canarytoken server
git clone https://github.com/thinkst/canarytokens.git
cd canarytokens
cp docker-compose.yml.dist docker-compose.yml
# Edit .env: set DOMAIN and CANARY_DOMAIN_ID
docker-compose up -d
# Self-hosted instance now generates tokens at https://<your-domain>/generate

# Test 1: Word-doc token
#   1. Generate the token; download the resulting .docx
#   2. Open the .docx on a Windows host with Word
#   3. Word fetches an image resource — the token fires
#   4. Receive email/webhook notification with the opener's IP

# Test 2: AWS API key token
#   1. Generate the token; receive a fake AWS access key + secret
#   2. Plant it in a decoy ~/.aws/credentials
#   3. (From a test host) attempt to use it:
aws configure set aws_access_key_id AKIAXXXXXX...
aws configure set aws_secret_access_key wJalrXUt...
aws sts get-caller-identity
#   4. Receive alert with the caller's IP

# Test 3: DNS token
#   1. Generate the token; receive a unique hostname
#   2. Trigger from any host:
nslookup <unique-hostname>.canarytokens.com
#   3. Receive alert with the resolver's source IP
```

### Exercise 8: Network Deception — Honeyport and Endlessh Tarpit

Goal: deploy a low-overhead network canary and an SSH tarpit.

```bash
# Honeyport: log any IP that connects to a chosen port
cat > /usr/local/bin/honeyport.sh <<'EOF'
#!/bin/bash
PORT=${1:-12345}
LOG=/var/log/honeyport.log
while true; do
    echo "[$(date)] listening on $PORT" >> "$LOG"
    CONNECTION=$(nc -l -p "$PORT" -v 2>&1)
    echo "[$(date)] $CONNECTION" >> "$LOG"
    # Optional: auto-firewall the source IP
    SRC_IP=$(echo "$CONNECTION" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)
    if [ -n "$SRC_IP" ]; then
        iptables -A INPUT -s "$SRC_IP" -j DROP
        echo "[$(date)] blocked $SRC_IP" >> "$LOG"
    fi
done
EOF
chmod +x /usr/local/bin/honeyport.sh

# Run as systemd service (see payloads.md §9 for the unit file)
/usr/local/bin/honeyport.sh 12345 &

# Endlessh: SSH tarpit
sudo apt install -y endlessh
# /etc/endlessh/config:
#   Port 22
#   Delay 1000        # milliseconds between SSH banner bytes
#   MaxClients 4096
sudo systemctl enable --now endlessh

# Verify from another host: a connection to port 22 hangs indefinitely
timeout 10 nc -v <honeypot_ip> 22

# Endlessh's logs show which IPs it trapped
journalctl -u endlessh -f
```

### Exercise 9: Extract IOCs from Cowrie and Pivot to MISP

Goal: parse a Cowrie JSON log, extract unique IOCs, and push them to MISP.

```bash
# Parse Cowrie JSON for the last 24h
LOG=/opt/cowrie/var/log/cowrie/cowrie.json
OUT=/opt/iocs/cowrie-$(date +%F)
mkdir -p /opt/iocs

# 1. Source IPs that logged in (failed or successful)
jq -r 'select(.eventid | startswith("cowrie.login")) | .src_ip' "$LOG" \
  | sort -u > "$OUT.src_ips.txt"

# 2. Credentials tried
jq -r 'select(.eventid | startswith("cowrie.login")) |
  "\(.username):\(.password)"' "$LOG" \
  | sort -u > "$OUT.creds.txt"

# 3. Commands executed post-login
jq -r 'select(.eventid=="cowrie.command.input") | .input' "$LOG" \
  | sort -u > "$OUT.commands.txt"

# 4. SHA256s of downloaded/uploaded files
jq -r 'select(.eventid=="cowrie.session.file_download") |
  .shasum // .destfile' "$LOG" | sort -u > "$OUT.hashes.txt"

# Push to MISP (using PyMISP)
python3 - <<'PY'
from pymisp import PyMISP, MISPEvent, MISPAttribute
misp = PyMISP("https://misp.example.org", "<API_KEY>", False)

event = MISPEvent()
event.info = f"Cowrie honeypot IOCs {__import__('datetime').date.today()}"
event.distribution = 0   # your org only
event.add_tag(" honeypot")
event.add_tag("cowrie")

with open("/opt/iocs/cowrie-$(date +%F).src_ips.txt") as f:
    for ip in f.read().splitlines():
        event.add_attribute("ip-src", ip.strip())
with open("/opt/iocs/cowrie-$(date +%F).hashes.txt") as f:
    for h in f.read().splitlines():
        if len(h) == 64:
            event.add_attribute("sha256", h.strip())

misp.add_event(event)
PY
```

### Exercise 10: Honeypot-Triggered Detection via Sigma and SIEM

Goal: ship a Sigma rule that pages the SOC when any honeypot fires.

```yaml
# Sigma rule: any honeypot event is high-confidence
title: Honeypot Tripwire - Any Interaction
id: a1b2c3d4-0002-4000-8000-000000000001
status: stable
description: >-
  Honeypots have no legitimate users. Any interaction is high-confidence
  adversary activity. Map to MITRE Engage "Expose" goal.
references:
  - https://attack.mitre.org/
  - https://engage.mitre.org/
tags:
  - attack.reconnaissance
  - attack.discovery
  - engage.expose
logsource:
  product: honeypot
  service: any
detection:
  selection:
    source: honeypot
  condition: selection
fields:
  - honeypot_type
  - src_ip
  - src_port
  - dest_port
  - protocol
  - username
  - command
falsepositives:
  - Misconfigured scanner or vulnerability-assessment tool —
    confirm with the scanning team before paging
level: high
```

```bash
# Translate to Splunk SPL
sigma-cli convert -t splunk honeypot-tripwire.yml
# Output: (index=honeypot source="honeypot")

# Ship to Splunk as a saved search with email + Slack alert
# In Splunk:
#   Settings -> Searches, reports, and alerts -> New
#   Search: (index=honeypot source="honeypot")
#   Schedule: real-time (or every 1 minute)
#   Alert action: email SOC, page on-call if honeypot_type is "cowrie" or "conpot"
```

## Defense Perspective (When Honeypots Backfire)

Honeypots are a powerful active-defense tool, but they introduce risks that pure detection does not.

| Risk | Description | Mitigation |
|------|-------------|------------|
| **Honeypot becomes a launchpad** | A high-interaction honeypot that an attacker fully owns can become a jump host to attack other systems — including production. Some jurisdictions treat this as the defender's liability (you operated an insecure system that harmed third parties). | Network-isolate the honeypot. Default-deny outbound at the firewall. Allow outbound *only* to a controlled malware sandbox. Never deploy high-interaction honeypots on flat L2 alongside production. |
| **Entanglement (anti-entrapment)** | "Entanglement" is the legal doctrine that a defender who actively invites an attacker in (e.g., by running an obvious honeypot with weak creds) may share liability for the attacker's subsequent actions, especially if they harm third parties. Most jurisdictions distinguish enticement (legal — you left the door open) from entrapment (illegal — you induced someone who otherwise wouldn't have committed the crime). Honeypots are generally *enticement*, but the line is jurisdiction-dependent. | Do NOT configure the honeypot to encourage attacks on third-party systems. Do NOT deploy honeypots outside your authorized scope. Document the engagement scope in writing. Consult counsel before any high-interaction deployment. |
| **Wiretap / data-protection exposure** | Honeypot logs capture attacker IP addresses, credentials, and (sometimes) the contents of their network traffic. In many jurisdictions this is regulated under wiretap statutes (US ECPA, EU GDPR). Storing attacker-attributable data without a lawful basis can be illegal. | Include honeypot logs in the organization's data-protection impact assessment. Restrict access. Define retention (e.g., 90 days raw, 1 year aggregated). Anonymize when sharing externally. |
| **Insider threat to the program** | An insider who knows where the honeypots are can deliberately trigger them to distract the SOC, or worse, avoid them when conducting malicious activity. | Compartmentalize honeypot locations and configs. Rotate deployment details. Treat a "honeypot avoided while adjacent production hosts were hit" as an insider indicator. |
| **Honeypot fingerprinting by adversaries** | Sophisticated adversaries fingerprint honeypots (default Conpot templates, Cowrie's specific bash behavior, OpenCanary's TLS fingerprint) and route around them. A detected honeypot provides *negative* intelligence to the adversary. | Customize templates. Rotate banners and filesystem contents. Use higher-interaction or LLM-driven honeypots (Beelzebub) where budget allows. Don't deploy honeypots as your only detection layer. |
| **False sense of security** | Honeypots catch attackers who touch the decoy. An attacker who compromises a real asset and stays quiet will *never* hit the honeypot. | Pair deception with threat hunting. Honeypots are a tripwire, not a complete detection program. |

### Legal Considerations Summary

```
BEFORE DEPLOYING A HONEYPOT:
1. Confirm written authorization (RoE / SoW) covers the deployment scope.
2. Confirm the honeypot's network location is within the authorized perimeter.
3. Confirm outbound egress is controlled — no third-party launchpad.
4. Confirm the data-protection impact assessment covers honeypot logs.
5. Confirm the honeypot will not be advertised in a way that invites attacks
   on third parties (no "come attack this, anyone on the internet!" posts).
6. Where the adversary may be traced into another jurisdiction, confirm
   cross-border data handling is lawful (GDPR / PIPL / etc.).

DURING OPERATION:
- Limit honeypot log access to authorized SOC analysts and IR.
- Forward to SIEM with retention consistent with other security logs.
- Treat hits as intelligence — do not act against the attacker's IP outside
  of authorized defensive measures (block at perimeter, share IOC).
```

## Detection Methods

### Honeypot/Honeynet Telemetry
- **Canary token activation**: Thinkst Canarytokens (PDF, AWS keys, DNS, web bugs) trigger on access.
- **Honeypot interaction**: Any interaction with `vpn-internal.yourdomain.com` or fake admin accounts is malicious by definition.
- **Honeytoken access**: Fake credentials in `/etc/passwd` or `~/.aws/credentials`; any auth attempt is malicious.
- **Fake document access**: Honeydoc in filesystem; alert on read.

### SIEM Detection Rules
- **Splunk SPL**: `index=dns query="*.fake-sub.yourdomain.com"` — any DNS resolution of fake subdomain is attacker.
- **Custom rules**: Alert on access to `/decoy/*` paths in any application.
- **CounterCraft / TrapX**: Commercial deception platform with native SIEM integration.

## Defense Evasion Techniques

### Honeypot Detection
- **Service fingerprinting**: Honeypots often have outdated signatures (Cowrie default SSH banners).
- **Network architecture**: Honeypots often on isolated VLANs; check ARP table for fake MACs.
- **Behavioral fingerprint**: Honeypots respond too quickly to commands; no real system latency.
- **Filesystem analysis**: Honeypot filesystems often sparse; check inode count.

### Canary Token Detection
- **URL pattern matching**: Canarytokens often use predictable domains (`canarytokens.com`).
- **Image dimension check**: 1x1 tracking pixels; identify by size.
- **Honeytoken detection**: Check `/etc/passwd` for fake users (often named `canary`, `honeypot`).

### Evasion Best Practices
- **Test against decoys**: Always probe new environment for honeypots before full operation.
- **Use legitimate credentials**: Stolen valid creds don't trigger honeypot auth alerts.
- **Avoid fake resources**: Don't access files/resources that don't match your reconnaissance findings.
- **Slow & methodical**: Honeypots often have logging triggered by speed (rapid enumeration).

## Cross-References

This skill is the defensive deception complement to several offensive and forensic skills.

- `skills/threat-hunting/SKILL.md` — consumes honeypot IOCs as hunt hypotheses; this skill feeds that one
- `skills/digital-forensics/SKILL.md` — post-fact investigation; a honeypot session transcript is a packaged forensic artifact
- `skills/darkweb-intel/SKILL.md` — pivots IOCs harvested from honeypots into dark-net attribution
- `skills/ad-ldap-attack/SKILL.md` — offensive counterpart; the credentials and lateral-movement TTPs observed in honeypots inform and are informed by this skill
- `skills/scada-ics-security/SKILL.md` — contains the ICS-specific Conpot deployment subsection; this skill generalizes it
- `skills/logging-monitoring/SKILL.md` — the sensor infrastructure honeypot logs flow through
- `skills/anti-forensics/SKILL.md` — adversary tradecraft for evading detection; informs lure realism (make honeypots less obvious)

## Hacker Laws

- **Assume Breach** — Deception starts from the premise that the adversary will get in. Rather than only trying to keep them out, deploy tripwires that fire when they do. Internal honeypots assume the perimeter has already fallen.
- **Defense in Depth** — Honeypots are not a standalone defense. They catch the adversary who reaches the decoy; threat hunting catches the one who doesn't. Pair them — neither alone is sufficient.
- **Weakest Link Is Human** — Honeypots catch technical attackers, but the most damaging adversary may be an insider who knows where the decoys are. Compartmentalize, rotate, and audit.
- **Trust but Verify** — A honeypot hit is high-confidence, but verify the IOC before acting. Honeypots can be triggered by misconfigured scanners, friendly pen-testers, or honeypot-researchers (who will publish your deployment if they spot it). Confirm before you page the CEO.
- **Obscurity Is Not Security** — A honeypot whose presence is unknown provides little protection; a honeypot whose presence is *obvious* provides negative protection (the adversary routes around). Realism in banner, filesystem, and naming is what makes a honeypot effective.

## Learning Resources

- **This skill's supplementary files**: `payloads.md`, `test-cases.md`
- **Deep-dive guide**: `guides/deception-honeypot-playbook.md` — end-to-end deception operations, from architecture through attribution, with deployment recipes and an OPSEC checklist
- **Related skills** (see Cross-References above)
- **External resources**:
  - T-Pot (Deutsche Telekom): [github.com/telekom-security/tpotce](https://github.com/telekom-security/tpotce)
  - Cowrie: [github.com/cowrie/cowrie](https://github.com/cowrie/cowrie)
  - OpenCanary (Thinkst): [github.com/thinkst/opencanary](https://github.com/thinkst/opencanary)
  - HFish: [github.com/hacklcx/HFish](https://github.com/hacklcx/HFish)
  - Conpot: [github.com/mushorg/conpot](https://github.com/mushorg/conpot)
  - Beelzebub: [github.com/mariocandela/beelzebub](https://github.com/mariocandela/beelzebub)
  - Canarytokens (Thinkst): [canarytokens.org](https://canarytokens.org) and [github.com/thinkst/canarytokens](https://github.com/thinkst/canarytokens)
  - Endlessh (tarpit): [github.com/skeeto/endlessh](https://github.com/skeeto/endlessh)
  - MITRE Engage framework: [engage.mitre.org](https://engage.mitre.org)
  - MITRE ATT&CK: [attack.mitre.org](https://attack.mitre.org)
  - Lance Spitzner, "Honeypots: Tracking Hackers" (foundational reference)
  - The Honeynet Project: [honeynet.org](https://www.honeynet.org)
  - MISP (threat-intel platform): [misp-project.org](https://www.misp-project.org)
- **Core system files**: `SOUL.md`, `TOOLS.md`, `IDENTITY.md`
