# Deception & Honeypot Playbook

> A deep-dive playbook for designing, deploying, operating, and harvesting intelligence from a deception program. This guide synthesizes the patterns in `SKILL.md`, `payloads.md`, and `test-cases.md` into an end-to-end operational workflow.
>
> Every technique here assumes an authorized engagement scope. Deception is powerful and legally sensitive; confirm written authorization before any deployment.

---

## Table of Contents

1. [Foundations: Why Deception Works](#1-foundations-why-deception-works)
2. [The Six-Phase Deception Workflow](#2-the-six-phase-deception-workflow)
3. [Architecture Patterns](#3-architecture-patterns)
4. [Lure Design Principles](#4-lure-design-principles)
5. [Deployment OPSEC](#5-deployment-opsec)
6. [Monitoring & Alerting](#6-monitoring--alerting)
7. [IOC Extraction & TTP Harvesting](#7-ioc-extraction--ttp-harvesting)
8. [Attribution Workflow](#8-attribution-workflow)
9. [Legal & Ethical Considerations](#9-legal--ethical-considerations)
10. [Cross-Skill Integration](#10-cross-skill-integration)
11. [Operational Runbooks](#11-operational-runbooks)
12. [Metrics & KPIs](#12-metrics--kpis)
13. [Common Pitfalls](#13-common-pitfalls)

---

## 1. Foundations: Why Deception Works

### 1.1 The Asymmetry of Telemetry

Traditional detection (signatures, anomaly detection, threat hunting) fights the **false-positive problem**: legitimate activity looks like malicious activity, and the analyst must separate them at scale. Deception inverts this — by definition, **no legitimate user has any reason to interact with a decoy**, so the signal-to-noise ratio of a correctly deployed honeypot is near infinity.

A SIEM rule that fires on "any SSH connection to `prod-web-07`" generates thousands of FPs (every admin, every cron job, every monitoring poll). A SIEM rule that fires on "any SSH connection to `cowrie-decoy-02`" generates **zero FPs** in normal operation — every hit is, by construction, unauthorized.

### 1.2 The Pyramid of Pain (Deception View)

David Bianco's Pyramid of Pain ranks indicators by how painful they are for the adversary to change. Hashes and IPs are cheap; TTPs are expensive. Deception aims high on the pyramid:

- A honeypot that captures a **specific malware sample** (hash) catches one campaign.
- A honeypot that captures **credential reuse** (TTP: `T1110.004`) catches a class of attack.
- A honeypot that captures a **lateral-movement pattern** (TTP: `T1021.002` SMB+PsExec) catches the adversary's tradecraft itself — they must change procedure to evade.

The Cowrie session where an attacker logs in, runs `uname -a`, downloads a payload from a C2, and tries to pivot — that's a packaged TTP. Replaying it forward: this becomes a Sigma detection. Replaying it backward: it becomes a hunt hypothesis.

### 1.3 The MITRE Engage Framework

MITRE Engage is the adversary-engagement counterpart to ATT&CK. It defines four goals:

| Goal | Adversary Impact | This Skill's Implementation |
|------|------------------|------------------------------|
| **Prepare** | (Defender action) | Deploy Cowrie, OpenCanary, Conpot, HFish within scope |
| **Expose** | Adversary reveals themselves | Any interaction with a decoy is a high-confidence indicator |
| **Affect** | Adversary loses time/resources | Tarpits (Endlessh), honeyports consume attacker cycles |
| **Collect** | Defender gains intelligence | Cowrie sessions, Conpot events → IOC pipeline → MISP/SIEM |

A mature deception program tracks metrics against each Engage goal (see §12).

### 1.4 What Deception Is Not

- **Not entrapment** — entrapment requires inducing someone to commit a crime they otherwise wouldn't. Honeypots are *enticement* (you left the door open) not *entrapment* (you induced the attack). The distinction is jurisdiction-dependent; consult counsel.
- **Not a complete detection program** — a quiet adversary who lands on a real asset and stays there will never touch a honeypot. Pair deception with threat hunting.
- **Not risk-free** — a high-interaction honeypot, if compromised and connected, can become a launchpad. Network isolation is non-negotiable.

---

## 2. The Six-Phase Deception Workflow

```
Phase 1              Phase 2              Phase 3              Phase 4              Phase 5              Phase 6
Architecture      →  Lure Design       →  Deployment OPSEC  →  Monitoring &       →  IOC Extraction   →  Attribution &
& Scoping            & Realism             (within scope)        Alerting             & TTP Harvesting      Sharing
```

Each phase has a checklist. Skip a phase, and the program will fail in operation.

### 2.1 Phase 1: Architecture & Scoping

**Goal**: decide where deception fits, what it covers, and what scope constraints apply.

**Checklist**:
- [ ] Identify the threat model: external scanner? Worm? Insider? APT? Each requires different lures.
- [ ] Map the attack surface: DMZ, internal VLANs, OT/ICS, cloud (VPCs), remote access.
- [ ] Decide on coverage: low-interaction (Cowrie, OpenCanary — catch the noisy) vs high-interaction (real OS — catch the sophisticated).
- [ ] Confirm written authorization (RoE / SoW) covering the exact deployment scope.
- [ ] Define data handling: who can read honeypot logs? Where are they stored? Retention?
- [ ] Plan isolation: VLAN, firewall, egress controls — the honeypot must NOT be able to reach production.
- [ ] Define shutdown criteria: when does the engagement end? What's the wipe procedure?

**Architecture pattern (small enterprise)**:

```
DMZ segment (decoy subnet, /29):
    - Cowrie on 203.0.113.10 (SSH/Telnet)
    - Glastopf on 203.0.113.11 (HTTP)
    - Endlessh on 203.0.113.12 (SSH tarpit)
    
Internal VLAN (decoy subnet, /28):
    - OpenCanary on 10.20.30.40 (SMB, HTTP, SSH, MSSQL)
    - Honeytokens planted on real file shares (Canarytokens)

OT management VLAN (decoy subnet, /29):
    - Conpot on 10.50.10.50 (Modbus/S7)

Central:
    - HFish server (management console) - 10.20.30.5
    - Splunk indexer (honeypot index) - 10.20.30.10
    - MISP instance (IOC correlation) - 10.20.30.15
```

### 2.2 Phase 2: Lure Design & Realism

**Goal**: make the decoys believable enough that a sophisticated adversary interacts with them.

**Realism layers**:

1. **Network-layer realism**
   - Decoy hostname resolves in DNS (don't ship on a bare IP)
   - TLS certificate matches the decoy hostname (LetsEncrypt is free)
   - Decoy IP is in the org's authorized range (not aReserved block)

2. **Service-layer realism**
   - SSH banner matches production fleet (`SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4`)
   - Web server version matches production (`Apache/2.4.52` not `Apache/2.2`)
   - Service-level banners and welcome messages match production

3. **Filesystem-layer realism**
   - Cowrie's fake `/etc/passwd` includes plausible accounts (matching AD naming convention)
   - Fake `~/.bash_history` has realistic commands
   - Fake `/var/log/` has rotated logs (not empty)

4. **Data-layer realism**
   - Honey DB rows have plausible names and roles
   - Honey credentials look like real credentials (`Backup-vault.kdbx`, not `decoy.txt`)
   - Canarytoken documents look like real internal docs

5. **Behavioral realism**
   - Cowrie's responses match what an Ubuntu host would say (not Cowrie's defaults)
   - Beelzebub's LLM-driven responses adapt to attacker commands (harder to fingerprint)

**Anti-fingerprinting**:

Sophisticated adversaries fingerprint honeypots. Known fingerprints:
- Cowrie: predictable responses to certain commands (`ps aux` returns Cowrie's hardcoded list)
- Conpot: default template has known register patterns
- OpenCanary: TLS fingerprint is non-standard
- Beelzebub: classic regex-based responses are detectable

Mitigations:
- Customize templates (don't ship defaults)
- Rotate banner strings and filesystem contents
- Use LLM-driven honeypots (Beelzebub with the OpenAI plugin) where budget allows
- Deploy a *variety* of honeypots — if an adversary fingerprints Cowrie, they may not fingerprint Conpot

### 2.3 Phase 3: Deployment OPSEC

**Goal**: deploy the lures such that they catch attackers without becoming attack vectors.

**Critical controls**:

```bash
# Honeypot host isolation (iptables on the honeypot itself)
# Default-deny outbound
iptables -P OUTPUT DROP
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
# Allow outbound ONLY to the controlled malware sandbox (if high-interaction)
iptables -A OUTPUT -d $SANDBOX_IP -j ACCEPT

# Honeypot host: allow inbound from monitored segments only
iptables -A INPUT -s $MONITORED_CIDR -j ACCEPT
iptables -A INPUT -s $JUMP_HOST -p tcp --dport 22 -j ACCEPT   # admin SSH
iptables -A INPUT -j DROP
```

```bash
# Firewall rules at the segment boundary
# (on the L3 switch / firewall between decoy VLAN and production)
# 1. Allow inbound to decoy VLAN (from authorized monitored segments)
# 2. DENY decoy VLAN -> production (the honeypot must NOT reach prod)
# 3. DENY decoy VLAN -> internet (no phone-home)
# 4. Allow decoy VLAN -> SIEM (for log forwarding)
```

**Privilege separation**:

- Honeypot processes run as a dedicated non-root user (`cowrie`, not `root`)
- Honeypot host has no production accounts, no production data, no production SSH keys
- Honeypot host's SSH host key is UNIQUE (don't reuse a production key)

**Systemd auto-restart**:

```ini
[Service]
Restart=always
RestartSec=5
```

If the honeypot crashes (or is crashed by an attacker), it comes back up.

### 2.4 Phase 4: Monitoring & Alerting

**Goal**: every honeypot session is a high-priority event. Wire it to the SOC.

**Pipeline**:

```
Honeypot (Cowrie/Conpot/OpenCanary)
   ↓ JSON log
Filebeat / Vector / rsyslog
   ↓ HTTP Event Collector (HEC) or syslog
SIEM (Splunk / Sentinel / Elastic)
   ↓ Sigma detection rule
SOC paging (email, Slack, PagerDuty)
```

**Sigma rule template**:

```yaml
title: Honeypot Tripwire - Cowrie Login
id: <generated-uuid>
status: stable
description: Any successful login to a Cowrie honeypot is unauthorized.
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
  - Vulnerability scanner (coordinate with scanning team)
level: critical
```

**Alert severity guide**:

| Event | Severity | Action |
|-------|----------|--------|
| Cowrie: login.successful | CRITICAL | Page on-call immediately; investigate credential reuse against AD |
| Cowrie: login.failed (high volume from one IP) | HIGH | Triage; consider firewall block; correlate with prod logs |
| Conpot: any Modbus/S7 read | CRITICAL | Page OT on-call; industrial traffic is deterministic |
| OpenCanary: SMB hit on internal decoy | HIGH | Likely lateral movement; investigate source host |
| Canarytoken: AWS key triggered | CRITICAL | The key was used; trace the source IP and revoke |
| Honeyport: connection | MEDIUM | Likely scanner; correlate with other alerts |

### 2.5 Phase 5: IOC Extraction & TTP Harvesting

**Goal**: turn honeypot sessions into structured intelligence.

**Daily IOC pipeline** (cron at 02:00):

```bash
#!/bin/bash
# /usr/local/bin/honeypot-daily-pipeline.sh
DATE=$(date +%F)
OUT=/opt/iocs/$DATE
mkdir -p $OUT

# Cowrie
COWRIE=/opt/cowrie/var/log/cowrie/cowrie.json
[ -f "$COWRIE" ] && {
    jq -r 'select(.eventid=="cowrie.session.connect") | .src_ip' "$COWRIE" | sort -u > $OUT/cowrie_src_ips.txt
    jq -r 'select(.eventid|startswith("cowrie.login")) | "\(.username)\t\(.password)"' "$COWRIE" | sort -u > $OUT/cowrie_creds.tsv
    jq -r 'select(.eventid=="cowrie.command.input") | .input' "$COWRIE" | sort -u > $OUT/cowrie_commands.txt
    jq -r 'select(.eventid=="cowrie.session.file_upload") | .shasum' "$COWRIE" | sort -u > $OUT/cowrie_uploads.txt
}

# Conpot
CONPOT=/var/log/conpot/conpot.json
[ -f "$CONPOT" ] && {
    jq -r '.remote[0]' "$CONPOT" | sort -u > $OUT/conpot_src_ips.txt
}

# Submit uploads to VirusTotal
[ -f $OUT/cowrie_uploads.txt ] && \
    xargs -I{} -a $OUT/cowrie_uploads.txt vt-submit.sh {}

# Push IOCs to MISP
misp-submit.py $MISP_API_KEY

# Rotate honeypot logs (keep 30 days)
find /opt/cowrie/var/log/cowrie/ -name "cowrie.json.*" -mtime +30 -delete
```

**Cron**:

```cron
0 2 * * * /usr/local/bin/honeypot-daily-pipeline.sh >> /var/log/honeypot-pipeline.log 2>&1
```

**TTP harvesting**:

Each unique Cowrie command sequence is a TTP candidate. Pipeline:

1. Extract command sequences per session
2. Cluster similar sequences (e.g., `uname -a` → `id` → `wget http://.../payload.sh`)
3. Map to MITRE ATT&CK (`T1082` for system info discovery, `T1105` for ingress tool transfer)
4. Generate Sigma detections for the cluster
5. Validate against historical data; ship to SIEM

### 2.6 Phase 6: Attribution & Sharing

**Goal**: pivot harvested IOCs into the threat-intel ecosystem; share back.

**Pivot order** (cheapest to most expensive):

1. **MISP** (internal) — is this IP/hash already known to my org?
2. **AbuseIPDB** — has this IP been reported by others?
3. **VirusTotal** — is this hash/domain/IP known malicious?
4. **Shodan** — what services does this IP expose? (Reconnaissance context)
5. **Threat actor databases** (e.g., Mandiant, CrowdStrike) — attribution

**Sharing back**:

- Submit confirmed IOCs to community MISP feeds (reciprocity)
- Report confirmed malicious IPs to AbuseIPDB
- Share Cowrie-captured malware samples with the Honeynet Project

---

## 3. Architecture Patterns

### 3.1 Single-Host Lab (T-Pot)

Best for: demonstrations, training, small org.

```
[ Internet ]
    ↓
[ T-Pot host (16GB RAM) ]
    ├── Cowrie
    ├── Dionaea
    ├── Heralding
    ├── Conpot
    ├── Glastopf
    ├── Honeytrap
    └── (etc.)
    ↓
[ ELK stack (on same host) ]
```

Pros: simple, all-in-one. Cons: no isolation between honeypots; single point of failure.

### 3.2 Distributed Enterprise (HFish + endpoints)

Best for: enterprise-wide deception rollout.

```
[ Endpoint 1 (DMZ) ] --\
[ Endpoint 2 (internal) ] --+--> [ HFish server (management) ] --> [ Splunk ]
[ Endpoint 3 (OT) ] -----/                              --> [ MISP ]
```

Pros: central management, scalable, multi-protocol. Cons: requires endpoint deployment across business units.

### 3.3 Cloud Deception (VPC honeytokens)

Best for: cloud-native orgs.

```
[ Decoy AWS access key ] planted in:
    - code repos (decoy branches)
    - terraform.tfvars (decoy)
    - S3 bucket policies (decoy)
    - CloudTrail alert on API call with the key
    
[ Decoy S3 bucket ] with canary objects:
    - CloudTrail alert on GetObject

[ Decoy IAM user ] that never logs in:
    - CloudTrail alert on ConsoleLogin
```

### 3.4 OT/ICS Deception (Conpot on plant VLAN)

Best for: industrial / critical infrastructure.

```
[ OT management VLAN (decoy subnet) ]
    └── [ Conpot PLC emulator ]
        ↓ Modbus/S7 traffic logged
[ OT SIEM (segregated from IT SIEM) ]
```

Critical: OT deception must be on a physically or logically segregated VLAN, with no path to production OT.

---

## 4. Lure Design Principles

### 4.1 Make Lures Plausible, Not Perfect

A lure that's *too* good (e.g., a honeypot named `domain-controller-01`) is suspicious. A lure that's plausible (a `prod-web-07` with default creds) catches scanners and opportunistic adversaries — the bulk of real-world traffic.

### 4.2 Make Lures Unique

Every honeytoken must be uniquely identifiable. If two deployments use the same honey-credential, a triggered token doesn't tell you which deployment was hit. Use Thinkst Canarytokens (unique per token) or generate unique values per deployment (Python script in `payloads.md` §7.3).

### 4.3 Plant Lures Where Adversaries Look

- **Recon paths**: robots.txt, `.git/`, `.env`, `backup.sql`, `phpinfo.php`
- **Discovery paths**: `~/.bash_history`, `~/.aws/credentials`, `~/.ssh/config`
- **Lateral paths**: `\\fileserver\HR\`, `\\fileserver\Finance\`, decoy admin shares
- **Cloud paths**: decoy IAM keys in code repos, decoy S3 objects with canary names

### 4.4 Rotate Lures

Honeypot fingerprints circulate. Rotate:
- Cowrie banners every quarter
- Canarytoken documents every 6 months
- Decoy credentials after any confirmed exposure
- Decoy locations (don't always plant in `~/.aws/credentials`; rotate to `.env`, then `terraform.tfvars`, etc.)

### 4.5 Lure Telemetry Must Be High-Fidelity

A honeypot that produces a syslog entry like "connection from X" is low-fidelity. A honeypot that produces a JSON event with `{src_ip, src_port, dst_port, protocol, command, payload, session_id, timestamp}` is high-fidelity. Always opt for JSON-structured logs over free-text syslog.

---

## 5. Deployment OPSEC

### 5.1 Network Isolation

The honeypot must NEVER be able to reach production. Layers:

1. **VLAN isolation** (L2)
2. **Firewall deny rules** (L3): deny `honeypot_vlan -> production_vlan`
3. **Host firewall** (iptables/nftables on the honeypot): default-deny outbound
4. **Egress proxy** (if any outbound is needed): force through an authenticated proxy that logs

### 5.2 Privilege Separation

```bash
# Dedicated user per honeypot
sudo adduser --disabled-password --gecos "" cowrie
sudo adduser --disabled-password --gecos "" conpot
sudo adduser --disabled-password --gecos "" opencanary

# Honeypot user has NO sudo access
# Honeypot user has NO production data access
# Honeypot processes are confined via AppArmor/SELinux where possible
```

### 5.3 Egress Control

```bash
# On the honeypot host
iptables -P OUTPUT DROP
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
# Allow only to SIEM (for log forwarding)
iptables -A OUTPUT -d $SIEM_IP -p tcp --dport 8088 -j ACCEPT
# (Optional) Allow to controlled malware sandbox
iptables -A OUTPUT -d $SANDBOX_IP -j ACCEPT
```

### 5.4 Host Hardening

The honeypot host itself must be hardened:
- Full disk encryption
- Minimal package install
- No GUI
- SSH with key-only auth, no password
- Fail2ban on the management interface
- Automatic security updates
- Centralized logging (honeypot host logs forwarded to SIEM, not just honeypot app logs)

### 5.5 Data Minimization

The honeypot host should not store:
- Production credentials (even for testing)
- Production user data
- Internal documentation (beyond what's needed for realism)
- Backups of production systems

---

## 6. Monitoring & Alerting

### 6.1 Log Pipeline Architecture

```
Honeypot hosts
   ↓ JSON logs
[ Filebeat / Vector / rsyslog ]
   ↓
[ SIEM (Splunk / Sentinel / Elastic) ]
   ↓ Sigma detection rules
[ Alert Triage Queue ]
   ↓
[ SOC analyst ]
   ↓
[ IR if confirmed ]
```

### 6.2 Sigma Detection Rule Template

Every honeypot alert starts as a Sigma rule (vendor-neutral):

```yaml
title: <descriptive name>
id: <generated uuid>
status: stable
description: <what this catches>
logsource:
  product: honeypot
  service: <cowrie|conpot|opencanary|...>
detection:
  selection:
    <field>: <value>
  condition: selection
fields:
  - src_ip
  - <other useful fields>
falsepositives:
  - <known FP sources>
level: <low|medium|high|critical>
```

### 6.3 Alert Workflow

1. **Detection** — Sigma rule fires in the SIEM
2. **Triage** — SOC analyst reviews:
   - Is this a known scanner (AbuseIPDB reputation)?
   - Is this a known honeypot researcher?
   - Is this a vulnerability scanner (coordinate with scanning team)?
   - Is this an authorized penetration tester (check engagement calendar)?
3. **Validation** — If confirmed malicious:
   - Page on-call if severity is HIGH or CRITICAL
   - Open an IR case
   - Preserve evidence (honeypot session transcript, uploaded binaries)
4. **Containment** — Block the source IP at the perimeter
5. **Eradication** — Sweep production for indicators related to the captured TTPs
6. **Recovery** — Restore any affected production systems
7. **Lessons learned** — Update detections, tune the honeypot, share IOCs

### 6.4 Common False Positives

| FP Source | Mitigation |
|-----------|-----------|
| Internal vulnerability scanner | Coordinate with scanning team; exclude scanner IPs from paging |
| External honeypot researcher | Maintain a list of known research networks; lower severity for those IPs |
| Misconfigured monitoring tool | Identify and fix the misconfiguration; add to exclusions |
| Penetration tester (authorized) | Check engagement calendar before paging |

---

## 7. IOC Extraction & TTP Harvesting

### 7.1 Daily IOC Pipeline

(See §2.5 for the script.)

### 7.2 TTP Clustering

Group Cowrie sessions by command sequence:

```python
# Cluster Cowrie sessions by command sequence
import json
from collections import Counter, defaultdict

sessions = defaultdict(list)
with open("/opt/cowrie/var/log/cowrie/cowrie.json") as f:
    for line in f:
        evt = json.loads(line)
        if evt.get("eventid") == "cowrie.command.input":
            sessions[evt["session"]].append(evt["input"])

# Now `sessions` is a dict of session_id -> list of commands
# Cluster by command-sequence signature
sigs = Counter()
for sid, cmds in sessions.items():
    # Normalize: strip arguments, keep the command name
    sig = " ".join(c.split()[0] if c.split() else "" for c in cmds)
    sigs[sig] += 1

# Top 10 most common attack patterns
for sig, count in sigs.most_common(10):
    print(f"{count}\t{sig}")
```

### 7.3 ATT&CK Mapping

Map common Cowrie command sequences to ATT&CK:

| Command | ATT&CK |
|---------|--------|
| `uname -a` | T1082 (System Information Discovery) |
| `id` | T1087 (Account Discovery) |
| `cat /etc/passwd` | T1087.001 (Local Account) |
| `wget http://...` | T1105 (Ingress Tool Transfer) |
| `curl http://...` | T1105 |
| `chmod +x` | T1222 (File and Directory Permissions Modification) |
| `/etc/init.d/...` or `systemctl` | T1543.002 (Systemd Service) |
| `crontab -e` | T1053.003 (Cron) |
| `nmap ...` | T1046 (Network Service Discovery) |
| `masscan ...` | T1046 |
| `passwd root` | T1098 (Account Manipulation) |

### 7.4 Sigma Detection Generation

For each clustered TTP, generate a Sigma detection:

```yaml
# T1082 - uname -a invocation post-honeypot-login
title: Honeypot Captured - uname System Info Discovery
id: <uuid>
status: experimental
description: >-
  Adversaries who successfully log in to a Cowrie honeypot frequently run
  `uname` to fingerprint the host. This Sigma detection hunts for the same
  TTP (T1082) in production Sysmon telemetry.
logsource:
  product: windows   # or linux for sysmon-for-linux
  category: process_creation
detection:
  selection:
    Image|endswith: 
      - '\uname.exe'
      - '/bin/uname'
  condition: selection
fields:
  - Computer
  - User
  - ParentImage
falsepositives:
  - System inventory scripts
level: low
```

The honeypot has now fed a hunt hypothesis.

---

## 8. Attribution Workflow

### 8.1 Pivot Chain

When the honeypot captures a high-fidelity IOC (e.g., a unique malware sample), pivot:

```
Honeypot captures SHA256 of uploaded malware
    ↓
VirusTotal lookup: hash matches "Trojan.Linux.Mirai"
    ↓
Extract embedded C2 domains from sample (reverse engineering)
    ↓
C2 domain's WHOIS / passive DNS: registered by Actor-X
    ↓
Actor-X's TTPs match ATT&CK T1059.004 (Unix Shell) + T1105
    ↓
Hunt production for T1059.004 + T1105 patterns
    ↓
Find one compromised production host
    ↓
Begin IR
```

### 8.2 Attribution Levels

| Confidence | Indicator | Example |
|-----------|-----------|---------|
| LOW | IP hit a honeypot | 203.0.113.45 SSH-brute-forced Cowrie |
| MEDIUM | Known malware family | Uploaded binary matches Mirai signatures |
| HIGH | Known C2 infra | C2 domain is in published threat reports |
| VERY HIGH | Known threat actor | TTPs match a published actor profile |

### 8.3 Sharing Back

Reciprocity is key. If your honeypots benefit from community-shared IOCs, share back:

- **MISP**: submit events with TLP:AMBER (limited distribution) or TLP:GREEN (community)
- **AbuseIPDB**: report confirmed malicious IPs
- **VirusTotal**: upload novel malware samples
- **Honeynet Project**: contribute research

---

## 9. Legal & Ethical Considerations

### 9.1 Authorization

Deception requires written authorization. The RoE / SoW must specify:
- Which networks are in scope
- Which honeypot types are approved
- Data handling and retention
- Shutdown criteria
- Cross-border data movement (GDPR / PIPL)

### 9.2 Wiretap Statutes

In the US, the Electronic Communications Privacy Act (ECPA) and similar statutes in other jurisdictions regulate the interception of electronic communications. Honeypot logs capture attacker communications, which may be subject to these statutes.

**Mitigation**: include honeypot logs in the organization's data-protection impact assessment. Limit access. Define retention. Anonymize when sharing externally.

### 9.3 Entanglement vs. Entrapment

- **Enticement** (legal): you left the door open. The adversary chose to enter.
- **Entrapment** (illegal, generally law-enforcement-only): you induced the adversary to commit a crime they otherwise wouldn't.

Honeypots are generally enticement. But the line is jurisdiction-dependent, and a high-interaction honeypot that actively *encourages* attacks on third parties can cross into entanglement liability.

**Mitigation**: don't configure the honeypot to encourage third-party attacks. Document the engagement scope. Consult counsel.

### 9.4 Data Protection

Honeypot logs capture attacker-attributable data:
- Source IPs (PII in some jurisdictions)
- Credentials tried (potentially real employee passwords if reused)
- Payloads (potentially containing stolen data)

**Mitigation**: 
- Encrypt honeypot logs at rest
- Restrict access to authorized SOC analysts and IR
- Define retention (e.g., 90 days raw, 1 year aggregated)
- Anonymize (truncate source IPs to /24) when sharing externally
- Include honeypot logs in GDPR / PIPL data inventory

### 9.5 When Honeypots Find Real Employee Credentials

A common scenario: Cowrie captures a credential attempt that matches a real employee's AD password. This is a **password reuse** event — the employee's password has appeared in a breach, and an attacker is using it.

**Handling**:
1. Do NOT accuse the employee. The reuse may be unknowing.
2. Force a password rotation for the affected account.
3. Enroll the account in MFA if not already.
4. Hunt production logs for the same credential in successful logins (was the credential used to log in before the honeypot captured it?).
5. Use it as a teaching moment: password reuse is a top risk.

---

## 10. Cross-Skill Integration

### 10.1 Threat Hunting

Honeypots feed threat hunting:
- Captured TTPs become hunt hypotheses
- Captured IOCs become Sigma detections
- Captured lateral-movement patterns inform hunt queries

See `skills/threat-hunting/SKILL.md`.

### 10.2 Digital Forensics

A honeypot session transcript is a packaged forensic artifact:
- It captures the attacker's toolkit, commands, and timing
- It can be replayed forward (Sigma detection) or backward (timeline reconstruction)
- It serves as a baseline for "what does this malware family look like?"

See `skills/digital-forensics/SKILL.md`.

### 10.3 Dark Web Intelligence

Honeypot-captured IOCs pivot into dark-web attribution:
- A captured C2 domain may appear in a dark-net marketplace listing
- A captured malware sample may be sold on a forum
- Threat actor handles may surface in breach-data forums

See `skills/darkweb-intel/SKILL.md`.

### 10.4 AD / LDAP Attack

Honeypots catch AD-focused attacks:
- SMB honeypots catch lateral-movement attempts
- Honeytokens planted in AD objects (decoy service accounts) catch Kerberoasting
- Cowrie captures that include `nmap` sweeps of internal AD subnets are immediate red flags

See `skills/ad-ldap-attack/SKILL.md`.

### 10.5 SCADA / ICS Security

Conpot deployment for OT is covered in:
- `skills/scada-ics-security/SKILL.md` (ICS-specific)
- This skill (generalized deception)

### 10.6 Logging & Monitoring

Honeypot logs flow through the same infrastructure as production logs. The sensor grid matters:
- `skills/logging-monitoring/SKILL.md` is the foundation this skill builds on

---

## 11. Operational Runbooks

### 11.1 Runbook: Daily Pipeline

**Frequency**: daily at 02:00 (cron)

1. Honeypot logs rotate (yesterday's `cowrie.json` becomes `cowrie.json.YYYY-MM-DD`)
2. Pipeline script (`payloads.md` §12.1) extracts IOCs to `/opt/iocs/<date>/`
3. Uploads submitted to VirusTotal (rate-limited)
4. IOCs pushed to MISP
5. Splunk summary index updated
6. Pipeline success/failure alerted to SOC

### 11.2 Runbook: Honeypot Alert (HIGH Severity)

**Trigger**: Cowrie `login.successful` event

1. SOC analyst reviews the alert in the SIEM
2. Identify source IP, username, password
3. Pivot source IP via AbuseIPDB / Shodan
4. **Critical**: check if the captured password matches any real AD account (via hash compare)
   - If YES: immediately force password rotation; treat as credential-reuse incident
5. Check production logs for the same source IP in the last 30 days
6. Page on-call DFIR if any production touch is found
7. Open an IR case; preserve evidence

### 11.3 Runbook: Honeypot Alert (CRITICAL — Conpot ICS Hit)

**Trigger**: Conpot Modbus/S7 interaction

1. Page OT on-call immediately (industrial traffic is deterministic)
2. Identify the source IP and the physical/logical port
3. Check if the source IP is from a known engineering workstation (false alarm — misconfigured device)
4. If unknown source: assume intrusion until proven otherwise
5. Activate OT IR plan; isolate the OT segment from IT
6. Begin forensic capture on the affected OT VLAN

### 11.4 Runbook: Honeytoken Alert (Canarytoken)

**Trigger**: Canarytoken triggered

1. Review the alert: which token? What decoy location?
2. Pivot the source IP
3. Determine access path: how did the adversary reach the decoy file?
4. Check production logs for the same source IP
5. If the decoy was a credential: revoke immediately, then investigate
6. Open an IR case

### 11.5 Runbook: Engagement Shutdown

**Trigger**: engagement end date OR confirmed production compromise

1. Capture final IOC exports
2. Stop honeypot processes (`systemctl stop cowrie conpot ...`)
3. Wipe honeypot hosts (reinstall OS; do not trust the host after exposure)
4. Revoke Canarytokens and honey-credentials
5. Remove decoy DNS/DHCP entries
6. Archive logs (encrypted at rest) per retention policy
7. Generate engagement report
8. Share IOCs with MISP community (reciprocity)

---

## 12. Metrics & KPIs

Track the deception program against MITRE Engage goals:

### 12.1 Prepare Metrics

- # of honeypot types deployed
- # of endpoints (decoys) deployed
- Coverage: % of attack surface with at least one decoy
- Realism score: # of honeypots with customized banners/filesystem (vs defaults)

### 12.2 Expose Metrics

- # of unique source IPs observed (per week)
- # of unique credential pairs captured (per week)
- # of unique malware samples captured (per week)
- # of confirmed malicious source IPs (after triage)
- False-positive rate: % of alerts determined to be authorized scanners/researchers

### 12.3 Affect Metrics

- # of attacker-hours burned in tarpits (Endlessh logs)
- # of attacker IPs auto-firewalled (honeyport auto-block)

### 12.4 Collect Metrics

- # of unique IOCs added to MISP (per week)
- # of TTPs extracted and mapped to ATT&CK
- # of Sigma detections generated from honeypot TTPs

### 12.5 Program Health Metrics

- Mean time from honeypot trigger to SOC alert (latency SLO: <5 min)
- Mean time from alert to triage completion (SLO: <30 min for HIGH severity)
- # of hunts triggered by honeypot intelligence
- # of IR cases triggered by honeypot intelligence
- Detection coverage: % of ATT&CK techniques with at least one honeypot-sourced detection

---

## 13. Common Pitfalls

### 13.1 Deploying Without Authorization

**Pitfall**: deploying honeypots "to see what happens" without written authorization.

**Result**: legal exposure, possibly criminal (wiretap), certainly career-limiting.

**Mitigation**: never deploy without RoE / SoW. Confirm scope in writing.

### 13.2 No Network Isolation

**Pitfall**: deploying Cowrie on a flat L2 alongside production.

**Result**: an attacker who pops Cowrie can pivot to production. You've handed them a launchpad.

**Mitigation**: VLAN isolation. Firewall deny rules. Default-deny outbound on the honeypot host.

### 13.3 Shipping Default Templates

**Pitfall**: deploying Conpot with the default Siemens S7 template; deploying Cowrie with the default `Cowrie-1.0` banner.

**Result**: sophisticated adversaries fingerprint the honeypot in seconds and route around it. You've given them free intelligence about your detection posture.

**Mitigation**: customize every banner, filesystem, and template. Rotate periodically.

### 13.4 Treating Honeypots as a Complete Detection Program

**Pitfall**: "we have honeypots, we don't need threat hunting."

**Result**: a quiet adversary who compromises a real asset will never touch a honeypot. You miss the sophisticated attacks.

**Mitigation**: pair deception with hunting. Honeypots are a tripwire, not a complete sensor grid.

### 13.5 Not Forwarding Logs to SIEM

**Pitfall**: honeypots capture rich data, but the logs sit on the honeypot host and no one looks at them.

**Result**: the deception program produces no operational value.

**Mitigation**: forward all honeypot logs to the SIEM with Sigma detection rules wired to SOC paging.

### 13.6 Acting on Honeypot Intel Without Corroboration

**Pitfall**: a honeypot captures an attacker IP; the SOC immediately blocks the IP at the perimeter.

**Result**: you may have blocked a Tor exit node, a VPN, or a legitimate security researcher. The next time the adversary uses a different IP, you're back to square one.

**Mitigation**: corroborate honeypot intelligence with at least one independent source (AbuseIPDB reputation, VirusTotal, prior SIEM hits) before acting. Treat honeypot intelligence as one input to a decision, not the decision itself.

### 13.7 Not Handling Captured Credentials Properly

**Pitfall**: Cowrie captures credentials; they're logged in plaintext; the logs are accessible to the whole SOC; some captured credentials match real employee passwords.

**Result**: insider risk (SOC analysts see real passwords), privacy violation, possible regulatory breach.

**Mitigation**: hash-capture passwords (store only the hash). Restrict access to logs. Define a credentials-handling runbook (see §9.5).

### 13.8 No Shutdown Plan

**Pitfall**: honeypots accumulate over years; no one remembers why each was deployed; decommissioning is impossible.

**Result**: honeypot sprawl; eventual misconfiguration; security debt.

**Mitigation**: document each deployment (purpose, scope, shutdown criteria). Review deployments quarterly. Decommission honeypots that no longer serve a purpose.

---

## Appendix: Quick Reference

### A.1 Honeypot Quick-Deploy Commands

```bash
# Cowrie (one-liner)
git clone https://github.com/cowrie/cowrie.git ~/cowrie && cd ~/cowrie && \
  python3 -m venv cowrie-env && source cowrie-env/bin/activate && \
  pip install -r requirements.txt && cp etc/cowrie.cfg.dist etc/cowrie.cfg && \
  bin/cowrie start

# OpenCanary (one-liner)
sudo pip3 install virtualenv && sudo virtualenv /opt/canary-env && \
  sudo /opt/canary-env/bin/pip install opencanary && \
  sudo /opt/canary-env/bin/opencanaryd --copyconfig && \
  sudo /opt/canary-env/bin/opencanaryd --start

# Conpot (one-liner)
python3 -m venv /opt/conpot-env && source /opt/conpot-env/bin/activate && \
  pip install conpot && conpot -f --template default

# HFish (Docker)
docker run -d --name hfish -p 4433:4433 -v /opt/hfish:/opt/hfish --privileged hfish/hfish:latest

# Endlessh
sudo apt install -y endlessh && sudo systemctl enable --now endlessh
```

### A.2 Quick IOC Extraction

```bash
# Cowrie one-liner
LOG=/opt/cowrie/var/log/cowrie/cowrie.json
echo "Connections: $(jq -r 'select(.eventid=="cowrie.session.connect") | .src_ip' $LOG | wc -l)"
echo "Unique IPs:  $(jq -r 'select(.eventid=="cowrie.session.connect") | .src_ip' $LOG | sort -u | wc -l)"
echo "Logins:      $(jq -r 'select(.eventid=="cowrie.login.successful") | .src_ip' $LOG | wc -l)"
```

### A.3 MITRE Engage Goals (One-Page Summary)

```
PREPARE  →  Deploy lures within authorized scope
EXPOSE   →  Any decoy interaction is adversary activity
AFFECT   →  Tarpits and honeyports consume attacker time
COLLECT  →  Pipeline sessions to IOC/TTP extraction
```

---

> End of `deception-honeypot-playbook.md`. Pair with `SKILL.md`, `payloads.md`, and `test-cases.md` for the complete deception program reference.
