# Deception & Honeypot Test Cases

> Companion to `SKILL.md`, containing structured test cases organized by category with severity ratings.
> All commands assume an authorized engagement scope. Confirm written authorization (RoE / SoW) before deploying any honeypot. Honeypots must be network-isolated from production with outbound egress controlled.

---

## Statistics

| Category | Count | Severity Range |
|------|------|-----------|
| A. Honeypot Deployment | 5 | MEDIUM - HIGH |
| B. Honeytoken & Canary Token | 2 | MEDIUM - HIGH |
| C. Network Deception | 2 | MEDIUM |
| D. Log Analysis & IOC Extraction | 2 | HIGH |
| E. Attribution & Integration | 1 | HIGH |
| **Total** | **12** | **MEDIUM - HIGH** |

---

## A. Honeypot Deployment

### TC-DH-001: Deploy Cowrie SSH/Telnet Honeypot

| Field | Value |
|------|-----|
| **ID** | TC-DH-001 |
| **Name** | Deploy Cowrie SSH/Telnet Honeypot |
| **Severity** | HIGH |
| **Category** | Honeypot Deployment |
| **Objective** | Stand up Cowrie as a medium-interaction SSH/Telnet honeypot, capture one login attempt, and extract the credentials from the JSON log. |
| **Prerequisites** | Authorized DMZ segment; dedicated Linux host; root or sudo; see `payloads.md` §1. |
| **Test Steps** | 1. `sudo adduser --disabled-password --gecos "" cowrie`<br>2. `sudo -u cowrie -i && git clone https://github.com/cowrie/cowrie.git && cd cowrie && python3 -m venv cowrie-env && source cowrie-env/bin/activate && pip install -r requirements.txt`<br>3. `cp etc/cowrie.cfg.dist etc/cowrie.cfg`; set `hostname = prod-web-07`, `listen_endpoints = tcp:2222:interface=0.0.0.0`, JSON log enabled<br>4. Generate host keys: `ssh-keygen -t ed25519 -f var/lib/cowrie/ssh_host_ed25519_key -N ""`<br>5. `bin/cowrie start`<br>6. From another host: `ssh -p 2222 root@<honeypot_ip>` (use any password)<br>7. Extract credentials: `jq -r 'select(.eventid \| startswith("cowrie.login")) \| "\(.timestamp) \(.src_ip) \(.username):\(.password)"' var/log/cowrie/cowrie.json \| tail -20` |
| **Expected Results** | Cowrie process running (`bin/cowrie status` returns OK); SSH connection from step 6 lands in `cowrie.json` with eventid `cowrie.login.successful` or `cowrie.login.failed`; jq query in step 7 returns the credential pair attempted. |
| **False Positive Risk** | LOW for the honeypot itself (Cowrie accepts most logins). HIGH for downstream actions — do not block or pursue any attacker IP without additional corroboration (could be a scanner or a researcher). |
| **Cleanup** | `bin/cowrie stop`; disable systemd unit (`sudo systemctl disable --now cowrie`); revoke any decoy host firewall rules; preserve logs under chain of custody if escalation is warranted. |
| **References** | `payloads.md` §1; `SKILL.md` Exercise 1; Cowrie docs (github.com/cowrie/cowrie) |

### TC-DH-002: Deploy OpenCanary Multi-Service Internal Tripwire

| Field | Value |
|------|-----|
| **ID** | TC-DH-002 |
| **Name** | Deploy OpenCanary Multi-Service Internal Tripwire |
| **Severity** | MEDIUM |
| **Category** | Honeypot Deployment |
| **Objective** | Deploy OpenCanary with SSH, HTTP, and SMB modules on an internal Linux host; trigger each module and confirm an alert fires via syslog. |
| **Prerequisites** | Internal VLAN (non-production); dedicated Linux host; sudo for low ports; see `payloads.md` §2. |
| **Test Steps** | 1. `sudo pip3 install virtualenv && sudo virtualenv /opt/canary-env && sudo /opt/canary-env/bin/pip install opencanary`<br>2. `sudo /opt/canary-env/bin/opencanaryd --copyconfig` (creates `/etc/opencanaryd/opencanary.conf`)<br>3. Edit config to enable `ssh.enabled`, `http.enabled`, `smb.enabled` with realistic skins<br>4. `sudo /opt/canary-env/bin/opencanaryd --start`<br>5. From another internal host: `nc -v <decoy_ip> 22` (SSH trigger)<br>6. From another internal host: `curl http://<decoy_ip>/` (HTTP trigger)<br>7. From another internal host: `smbclient -L //<decoy_ip>/` (SMB trigger)<br>8. `journalctl -t opencanary -f` to confirm each module fires |
| **Expected Results** | OpenCanary process listens on configured ports; each trigger in steps 5-7 produces a syslog entry with the source IP and service identifier; the syslog entries are machine-parseable. |
| **False Positive Risk** | LOW — no legitimate user should hit an internal decoy. Misconfigured vulnerability scanners may trigger; coordinate with the scanning team before alert paging. |
| **Cleanup** | `sudo /opt/canary-env/bin/opencanaryd --stop`; remove config; decommission the decoy host; revoke DNS/DHCP entries. |
| **References** | `payloads.md` §2; `SKILL.md` Exercise 2; OpenCanary docs (github.com/thinkst/opencanary) |

### TC-DH-003: Deploy HFish Enterprise Honeypot with Multi-Endpoint

| Field | Value |
|------|-----|
| **ID** | TC-DH-003 |
| **Name** | Deploy HFish Enterprise Honeypot with Multi-Endpoint |
| **Severity** | HIGH |
| **Category** | Honeypot Deployment |
| **Objective** | Deploy HFish as a centralized management node, enroll two endpoint agents (one Linux, one Windows), enable at least three protocol templates per endpoint, and verify hit visibility in the console. |
| **Prerequisites** | Authorized enterprise network; HFish Docker host; two endpoint hosts (one Linux, one Windows); see `payloads.md` §3. |
| **Test Steps** | 1. `docker run -d --name hfish -p 4433:4433 -v /opt/hfish:/opt/hfish --privileged hfish/hfish:latest`<br>2. Browse to `https://<hfish_host>:4433/`, log in with `admin/admin`, change password immediately<br>3. On Linux endpoint: `docker run -d --name hfish-agent -e HFISH_SERVER=https://<hfish_host>:4433 -e ENDPOINT_NAME=dmz-decoy-02 --net=host --privileged hfish/hfish-agent:latest`<br>4. On Windows endpoint: download HFish Windows agent, run with `-server`, `-user`, `-pass`, `-name internal-decoy-01`<br>5. In the console, enable SSH/HTTP/MySQL templates on the Linux agent and SMB/RDP/FTP templates on the Windows agent<br>6. From a third host, trigger each enabled port (e.g., `ssh user@<linux_endpoint>`, `smbclient -L //<windows_endpoint>/`)<br>7. Confirm each hit appears in the console's "Attack Map" and "Logs" page |
| **Expected Results** | Both endpoints show "online" status in the console; each trigger in step 6 produces an alert in the console with timestamp, source IP, and protocol; alerts can be configured for Slack/email/webhook delivery. |
| **False Positive Risk** | LOW for the honeypots themselves. MEDIUM for alerts if the organization has routine vulnerability scanning — coordinate with the scanning team. |
| **Cleanup** | Stop and remove HFish and agent containers; back up `/opt/hfish/data`; decommission endpoint hosts. |
| **References** | `payloads.md` §3; HFish docs (github.com/hacklcx/HFish) |

### TC-DH-004: Deploy Conpot ICS/SCADA Honeypot

| Field | Value |
|------|-----|
| **ID** | TC-DH-004 |
| **Name** | Deploy Conpot ICS/SCADA Honeypot |
| **Severity** | HIGH |
| **Category** | Honeypot Deployment |
| **Objective** | Deploy Conpot emulating a Siemens S7 PLC on the OT management VLAN, verify Modbus responses with pymodbus, and confirm a Modbus interaction is logged. |
| **Prerequisites** | Authorized OT management VLAN; dedicated Linux host; OT network isolation; see `payloads.md` §4. |
| **Test Steps** | 1. Install deps: `sudo apt install -y libsmi2-dev libxslt1-dev libxml2-dev python3-dev`<br>2. `python3 -m venv /opt/conpot-env && source /opt/conpot-env/bin/activate && pip install conpot`<br>3. `conpot -f --template default --host <ot_decoy_ip>`<br>4. From another OT host, run pymodbus: `python3 -c "from pymodbus.client import ModbusTcpClient; c=ModbusTcpClient('<ot_decoy_ip>', port=502); print(c.read_holding_registers(0, 10).registers)"`<br>5. Verify the response (registers should be plausible process values)<br>6. Tail the Conpot JSON log: `tail -f /var/log/conpot/conpot.json`<br>7. Confirm the Modbus interaction from step 4 appears with the source IP and function code |
| **Expected Results** | Conpot listens on port 502; pymodbus query returns a list of integer registers; JSON log entry shows the client IP, function code 3 (read holding registers), and the requested register range. |
| **False Positive Risk** | VERY LOW — industrial networks are deterministic; any unplanned Modbus traffic on a decoy PLC is a high-confidence intrusion indicator. |
| **Cleanup** | Stop Conpot (`Ctrl+C` or `systemctl stop conpot`); disable the systemd unit; remove the decoy host from the OT VLAN. |
| **References** | `payloads.md` §4; `SKILL.md` Exercise 4; Conpot docs (github.com/mushorg/conpot) |

### TC-DH-005: Deploy T-Pot All-in-One Honeypot Platform

| Field | Value |
|------|-----|
| **ID** | TC-DH-005 |
| **Name** | Deploy T-Pot All-in-One Honeypot Platform |
| **Severity** | HIGH |
| **Category** | Honeypot Deployment |
| **Objective** | Install T-Pot on a dedicated Linux host (16GB+ RAM), access the web console and Attack Map, confirm multiple honeypots are running, and verify at least one inbound hit appears in Kibana. |
| **Prerequisites** | Dedicated Linux host with 16GB+ RAM, 8+ vCPU, 256GB+ disk; authorized DMZ segment; see `payloads.md` §5. |
| **Test Steps** | 1. `git clone https://github.com/telekom-security/tpotce.git && cd tpotce`<br>2. `sudo ./install.sh --type=auto`; follow prompts<br>3. Browse to `https://<tpot_host>:64297/`; log in with credentials from `/etc/tpot/tpot.yml`; change password<br>4. Verify `docker compose ps` shows Cowrie, Dionaea, Heralding, Conpot, Glastopf, Honeytrap, Elasticpot running<br>5. Browse to Kibana at `https://<tpot_host>:5601/`<br>6. From an external host, trigger one honeypot (e.g., `ssh root@<tpot_host>` to trigger Cowrie)<br>7. Within 1-2 minutes, confirm the hit appears in Kibana with src_ip, honeypot type, and payload |
| **Expected Results** | T-Pot install completes; 15+ honeypot containers running; web UI and Kibana accessible; inbound trigger in step 6 appears in Kibana within 1-2 minutes with full event details. |
| **False Positive Risk** | LOW for the platform itself. HIGH operational risk if T-Pot is deployed in production or without outbound egress controls — T-Pot honeypots can capture malware that, if outbound is allowed, can phone home. |
| **Cleanup** | `cd /opt/tpot && docker compose down`; wipe `/data`; reinstall the host OS; remove from DMZ. |
| **References** | `payloads.md` §5; T-Pot docs (github.com/telekom-security/tpotce) |

---

## B. Honeytoken & Canary Token

### TC-DH-006: Design and Deploy Honeytokens

| Field | Value |
|------|-----|
| **ID** | TC-DH-006 |
| **Name** | Design and Deploy Honeytokens |
| **Severity** | MEDIUM |
| **Category** | Honeytoken & Canary Token |
| **Objective** | Design three honeytokens (fake AWS key, honey DB row, honey SSH key) and confirm each triggers an alert when used. |
| **Prerequisites** | Authorized production environment (with org's written consent for planting honeytokens); AWS account (decoy key generation); PostgreSQL with pgAudit; see `payloads.md` §7. |
| **Test Steps** | 1. Generate a fake AWS access key pair (script in `payloads.md` §7.3)<br>2. Plant in a decoy `~/.aws/credentials` or `terraform.tfvars`<br>3. From a test host, attempt to use: `aws sts get-caller-identity` (will fail, but the attempt is logged)<br>4. (If using Thinkst Canarytokens for AWS) confirm the Canarytokens dashboard shows the trigger with source IP<br>5. For the honey DB row: `INSERT INTO users (email, name, password_hash, is_honeytoken) VALUES ('david.thompson.<unique>@example.org', ...);`<br>6. Enable pgAudit: `ALTER SYSTEM SET pgaudit.log = 'read'; SELECT pg_reload_conf();`<br>7. Run a SELECT that returns the decoy row; confirm pgaudit logs the query<br>8. For the honey SSH key: `ssh-keygen -t ed25519 -f /opt/decoy/honeytoken_key -N ""`<br>9. Append the public key to a real user's `authorized_keys` (with consent)<br>10. Attempt to log in with the honey key from a test host; confirm sshd logs the public-key fingerprint |
| **Expected Results** | AWS key attempt in step 3 fires the Canarytokens alert; pgAudit in step 7 logs the SELECT; sshd log in step 10 shows the unique honey key fingerprint. Each honeytoken is uniquely identifiable so the trigger source is traceable. |
| **False Positive Risk** | LOW if honeytokens are kept truly decoy. MEDIUM if a honeytoken is accidentally planted where a legitimate process touches it (e.g., honey-credential in a script that runs in cron) — design tokens to be inert in normal operation. |
| **Cleanup** | Revoke Canarytokens; remove decoy DB row; remove honey SSH key from authorized_keys; wipe decoy `~/.aws/credentials`. |
| **References** | `payloads.md` §7; `SKILL.md` §"Honeytoken Principles" |

### TC-DH-007: Deploy Canarytokens (Thinkst)

| Field | Value |
|------|-----|
| **ID** | TC-DH-007 |
| **Name** | Deploy Canarytokens (Thinkst) |
| **Severity** | HIGH |
| **Category** | Honeytoken & Canary Token |
| **Objective** | Generate three Canarytokens (Word doc, AWS API key, DNS), deploy each in a plausible decoy location, trigger each, and confirm alerts arrive. |
| **Prerequisites** | Access to `https://canarytokens.org/generate` (or self-hosted Canarytokens server); email or webhook for alert delivery; see `payloads.md` §8. |
| **Test Steps** | 1. Generate a Word-doc Canarytoken; download the `.docx`<br>2. Open the `.docx` on a Windows host with Word<br>3. Confirm email/webhook alert arrives with the opener's IP<br>4. Generate an AWS API key Canarytoken; receive the fake `aws_access_key_id` and `aws_secret_access_key`<br>5. Plant in `/opt/decoy/.aws/credentials`<br>6. From a test host, attempt to use: `aws --profile honey configure set aws_access_key_id <KEY>; aws sts get-caller-identity`<br>7. Confirm alert arrives with the caller's IP<br>8. Generate a DNS Canarytoken; receive a unique hostname<br>9. From a test host, `nslookup <unique>.canarytokens.com`<br>10. Confirm alert arrives with the resolver's source IP |
| **Expected Results** | All three Canarytokens trigger alerts with source IP information; alerts include the token memo (decoy location) for triage; alerts arrive within seconds to minutes of the trigger. |
| **False Positive Risk** | LOW for the triggers themselves. MEDIUM for false attribution — a Canarytoken planted in a shared folder may be triggered by a well-meaning employee opening the file; design tokens to be planted in locations only adversaries (or specific insider scenarios) would touch. |
| **Cleanup** | Revoke each Canarytoken via the manage page; remove decoy files; document the engagement. |
| **References** | `payloads.md` §8; Canarytokens docs (github.com/thinkst/canarytokens) |

---

## C. Network Deception

### TC-DH-008: Deploy Endlessh Tarpit and Honeyport

| Field | Value |
|------|-----|
| **ID** | TC-DH-008 |
| **Name** | Deploy Endlessh Tarpit and Honeyport |
| **Severity** | MEDIUM |
| **Category** | Network Deception |
| **Objective** | Deploy Endlessh as an SSH tarpit and a Honeyport bash canary on a non-production IP; verify each traps/logs connections from a test host. |
| **Prerequisites** | Authorized non-production IP; dedicated Linux host; sudo; see `payloads.md` §9. |
| **Test Steps** | 1. Install: `sudo apt install -y endlessh`<br>2. Configure `/etc/endlessh/config`: `Port 22`, `Delay 1000`, `MaxClients 4096`<br>3. `sudo systemctl enable --now endlessh`<br>4. From another host: `timeout 15 nc -v <tarpit_ip> 22` (should hang for 15s then exit)<br>5. `journalctl -u endlessh -f` should show the connection<br>6. Deploy honeyport: `/usr/local/bin/honeyport.sh 12345 &`<br>7. From another host: `nc -v <honeypot_ip> 12345`<br>8. Check `/var/log/honeyport.log` for the connection<br>9. If auto-firewall variant is enabled, verify the source IP was added to iptables DROP chain: `sudo iptables -L INPUT -n | grep <test_ip>` |
| **Expected Results** | Endlessh accepts the SSH connection in step 4 and hangs indefinitely (the timeout kills nc after 15s); Endlessh log shows the source IP; honeyport in step 7 accepts and logs the connection; iptables DROP rule is added if auto-firewall variant is used. |
| **False Positive Risk** | LOW — Endlessh on a non-production port 22 is unlikely to be touched by legitimate traffic. MEDIUM for honeyport if the chosen port is one that legitimate scanners (e.g., monitoring tools) probe — pick a non-standard port. |
| **Cleanup** | `sudo systemctl disable --now endlessh`; kill honeyport; `sudo iptables -F INPUT` to clear auto-firewall rules (carefully — verify rules are honeyport-added before flushing). |
| **References** | `payloads.md` §9.1-9.4; `SKILL.md` Exercise 8 |

### TC-DH-009: Network Dark-Space Monitoring

| Field | Value |
|------|-----|
| **ID** | TC-DH-009 |
| **Name** | Network Dark-Space Monitoring |
| **Severity** | MEDIUM |
| **Category** | Network Deception |
| **Objective** | Configure an IP range with no production hosts as a "dark space" with iptables logging; verify inbound packets to the dark space are logged. |
| **Prerequisites** | Unused IP range within the authorized segment; Linux router/firewall with iptables; see `payloads.md` §9.7. |
| **Test Steps** | 1. Identify a dark-space CIDR (e.g., `192.168.1.240/29` — 8 IPs, none used in production)<br>2. Configure iptables: `sudo iptables -N DARKSPACE; sudo iptables -A DARKSPACE -j LOG --log-prefix "DARKSPACE: " --log-level 4; sudo iptables -A DARKSPACE -j DROP; sudo iptables -A INPUT -d 192.168.1.240/29 -j DARKSPACE`<br>3. From another host, send a probe: `nmap -sT 192.168.1.242`<br>4. View kernel logs: `sudo journalctl -k | grep DARKSPACE | tail -20`<br>5. (Optional) Forward logs to SIEM via Filebeat/Vector<br>6. (Optional) Configure a syn-ack canary on one of the dark-space IPs (Python listener in `payloads.md` §9.8) and confirm connections to it log with the dark-space tag |
| **Expected Results** | Step 3's nmap probe generates DARKSPACE log entries in step 4 with the source IP, destination IP, and port; the dark-space IP never responds (DROP chain); SIEM (if configured) receives the events. |
| **False Positive Risk** | LOW for legitimate dark space — by definition, no production host is there. MEDIUM if a service is accidentally deployed to the dark-space CIDR; verify the CIDR is truly unused. |
| **Cleanup** | `sudo iptables -D INPUT -d 192.168.1.240/29 -j DARKSPACE; sudo iptables -F DARKSPACE; sudo iptables -X DARKSPACE`. |
| **References** | `payloads.md` §9.7-9.8 |

---

## D. Log Analysis & IOC Extraction

### TC-DH-010: Cowrie Log Analysis and IOC Extraction

| Field | Value |
|------|-----|
| **ID** | TC-DH-010 |
| **Name** | Cowrie Log Analysis and IOC Extraction |
| **Severity** | HIGH |
| **Category** | Log Analysis & IOC Extraction |
| **Objective** | Parse a Cowrie JSON log, extract unique source IPs, credentials, commands, and file hashes, and generate a structured IOC export suitable for SIEM ingestion or MISP submission. |
| **Prerequisites** | Cowrie deployment with at least 100 sessions in the JSON log; `jq` installed; see `payloads.md` §12.1. |
| **Test Steps** | 1. `LOG=/opt/cowrie/var/log/cowrie/cowrie.json; OUT=/opt/iocs/cowrie-$(date +%F); mkdir -p /opt/iocs`<br>2. Extract source IPs: `jq -r 'select(.eventid=="cowrie.session.connect") \| .src_ip' "$LOG" \| sort -u > "$OUT.src_ips.txt"`<br>3. Extract credentials: `jq -r 'select(.eventid \| startswith("cowrie.login")) \| "\(.username)\t\(.password)"' "$LOG" \| sort -u > "$OUT.creds.tsv"`<br>4. Extract commands: `jq -r 'select(.eventid=="cowrie.command.input") \| .input' "$LOG" \| sort -u > "$OUT.commands.txt"`<br>5. Extract upload hashes: `jq -r 'select(.eventid=="cowrie.session.file_upload") \| .shasum' "$LOG" \| sort -u > "$OUT.uploads_hashes.txt"`<br>6. Run the quick summary one-liner (`payloads.md` §13.6) to confirm counts<br>7. Validate the exports are non-empty and structured correctly |
| **Expected Results** | Five text/TSV files generated; summary one-liner reports reasonable counts (sessions, unique IPs, logins, uploads, downloads, commands); each file is unique-sorted and free of JSON parsing errors. |
| **False Positive Risk** | LOW for the extraction itself. MEDIUM for downstream actions — credentials tried against Cowrie may include real employee passwords (if reused); validate before sharing externally. |
| **Cleanup** | No specific cleanup; preserve the IOC exports per retention policy. |
| **References** | `payloads.md` §12.1, §13.6; `SKILL.md` Exercise 9 |

### TC-DH-011: Pivot IOCs to MISP, Shodan, and AbuseIPDB

| Field | Value |
|------|-----|
| **ID** | TC-DH-011 |
| **Name** | Pivot IOCs to MISP, Shodan, and AbuseIPDB |
| **Severity** | HIGH |
| **Category** | Log Analysis & IOC Extraction |
| **Objective** | Take a set of attacker IPs (and file hashes) extracted from honeypot logs, query Shodan and AbuseIPDB for context, and push the IOCs to MISP for organizational correlation. |
| **Prerequisites** | Shodan API key; AbuseIPDB API key; VirusTotal API key; MISP instance with API key; `pymisp` installed; see `payloads.md` §12.4-12.5. |
| **Test Steps** | 1. Take the top 10 attacker IPs from TC-DH-010's `$OUT.src_ips.txt`<br>2. For each, run `ip-enrich.sh` (`payloads.md` §12.5): queries Shodan, AbuseIPDB, and VirusTotal<br>3. Inspect outputs: country, abuse confidence score, exposed ports, prior reports<br>4. Submit to MISP via `misp-submit.py` (`payloads.md` §12.4)<br>5. In MISP, verify the event was created with the IPs, hashes, and credentials (creds marked non-to_ids)<br>6. Confirm the event is tagged `honeypot`, `cowrie`, `tlp:amber`<br>7. (Optional) Share the event with a community MISP feed |
| **Expected Results** | Each attacker IP returns a JSON enrichment with country, abuse score, and exposed services; MISP event is created with all IOCs; event is properly tagged and distribution-limited per policy. |
| **False Positive Risk** | LOW for the pipeline itself. HIGH for false attribution — IPs observed hitting honeypots may be Tor exit nodes, VPNs, or other infra not exclusively malicious. Do not pursue legal action based on honeypot IP alone. |
| **Cleanup** | No cleanup; MISP events follow the platform's retention policy. |
| **References** | `payloads.md` §12.4-12.5; `SKILL.md` Exercise 9 |

---

## E. Attribution & Integration

### TC-DH-012: End-to-End Deception Pipeline (Sigma + SIEM + Alert)

| Field | Value |
|------|-----|
| **ID** | TC-DH-012 |
| **Name** | End-to-End Deception Pipeline (Sigma + SIEM + Alert) |
| **Severity** | HIGH |
| **Category** | Attribution & Integration |
| **Objective** | Configure a Sigma rule that fires on any honeypot event, ship it to a SIEM (Splunk or Sentinel), and verify that an inbound honeypot trigger pages the SOC within the alert latency SLO. |
| **Prerequisites** | Honeypot logs flowing to SIEM; `sigma-cli` installed; Splunk HEC token or Sentinel workspace; SOC paging mechanism; see `payloads.md` §12.12 and `SKILL.md` Exercise 10. |
| **Test Steps** | 1. Author `honeypot-tripwire.yml` (Sigma) per `SKILL.md` Exercise 10<br>2. Validate schema: `sigma-cli check honeypot-tripwire.yml`<br>3. Translate to SIEM: `sigma-cli convert -t splunk honeypot-tripwire.yml` (or sentinel)<br>4. Configure SIEM saved search/analytic rule with the translated query, scheduled at 1-min intervals<br>5. Configure alert actions: email SOC, page on-call for `honeypot_type=cowrie` or `honeypot_type=conpot`<br>6. Trigger a test honeypot hit (e.g., SSH to the Cowrie port from a known test IP)<br>7. Measure time-from-trigger-to-page; verify it meets the SLO (e.g., <5 minutes)<br>8. Document the alert workflow, FP handling (vulnerability scanners), and escalation path<br>9. Validate that the Sigma rule is checked into Git and CI runs `sigma-cli check` on every PR |
| **Expected Results** | Sigma rule validates cleanly; translated query runs without errors in the SIEM; test trigger in step 6 produces an alert within the SLO; SOC paging fires; alert includes source IP, honeypot type, and (for Cowrie) credentials tried. |
| **False Positive Risk** | LOW for the rule itself. MEDIUM for production — vulnerability scanners and routine security testing will trigger; coordinate with the scanning team and document exclusions. |
| **Cleanup** | Disable or tune the SIEM alert if it's a test; keep the Sigma rule in Git for future deployment; document the test outcome. |
| **References** | `payloads.md` §12.12; `SKILL.md` Exercise 10; Sigma project (github.com/SigmaHQ/sigma) |

---

## Summary Table

| ID | Name | Severity | Category |
|----|------|----------|----------|
| TC-DH-001 | Deploy Cowrie SSH/Telnet Honeypot | HIGH | Honeypot Deployment |
| TC-DH-002 | Deploy OpenCanary Multi-Service Internal Tripwire | MEDIUM | Honeypot Deployment |
| TC-DH-003 | Deploy HFish Enterprise Honeypot with Multi-Endpoint | HIGH | Honeypot Deployment |
| TC-DH-004 | Deploy Conpot ICS/SCADA Honeypot | HIGH | Honeypot Deployment |
| TC-DH-005 | Deploy T-Pot All-in-One Honeypot Platform | HIGH | Honeypot Deployment |
| TC-DH-006 | Design and Deploy Honeytokens | MEDIUM | Honeytoken & Canary Token |
| TC-DH-007 | Deploy Canarytokens (Thinkst) | HIGH | Honeytoken & Canary Token |
| TC-DH-008 | Deploy Endlessh Tarpit and Honeyport | MEDIUM | Network Deception |
| TC-DH-009 | Network Dark-Space Monitoring | MEDIUM | Network Deception |
| TC-DH-010 | Cowrie Log Analysis and IOC Extraction | HIGH | Log Analysis & IOC Extraction |
| TC-DH-011 | Pivot IOCs to MISP, Shodan, and AbuseIPDB | HIGH | Log Analysis & IOC Extraction |
| TC-DH-012 | End-to-End Deception Pipeline (Sigma + SIEM + Alert) | HIGH | Attribution & Integration |

---

## Severity Definitions

| Severity | Meaning |
|----------|---------|
| **HIGH** | Test exercises a complete deployment or a full IOC pipeline; failure indicates a significant gap in the deception program. |
| **MEDIUM** | Test exercises a single component or a subset of capabilities; failure is recoverable. |

---

## Test Environment Recommendations

- **Isolated lab VLAN** for honeypot hosts — never deploy on flat L2 alongside production
- **Outbound egress blocked** at the firewall (or restricted to a controlled sandbox)
- **Dedicated decoy hosts** — no production data, no production accounts
- **Realistic banners** — match production SSH version, web server version, hostname convention
- **SIEM integration tested** before deployment (alert latency SLO measured)
- **Engagement RoE on file** — written authorization, scope, and shutdown criteria

---

> End of `test-cases.md`. Pair with `SKILL.md` (conceptual framework), `payloads.md` (command reference), and `guides/deception-honeypot-playbook.md` (end-to-end workflow).
