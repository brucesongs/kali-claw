# SCADA/ICS Security Assessment Test Cases

> This file is a companion to `SKILL.md`, containing structured test cases for ICS security assessment in authorized lab environments only.

---

## Statistics

| Category | Cases | Severity Distribution |
|----------|-------|-----------------------|
| A. Device Enumeration | 2 | Medium, Medium |
| B. Protocol Interaction | 2 | Medium, High |
| C. Protocol Exploitation | 2 | High, Critical |
| D. Defense & Detection | 2 | Medium, High |
| **Total** | **8** | **M:3, H:3, C:2** |

---

## A. Device Enumeration

### TC-ICS-001: PLC and RTU Discovery via plcscan

| Attribute | Value |
|----------|-------|
| **ID** | TC-ICS-001 |
| **Category** | A. Device Enumeration |
| **Severity** | Medium |
| **Objective** | Discover all PLCs and RTUs on the target ICS network segment and identify device models, firmware versions, and reachable protocol services |
| **Prerequisites** | Tester has layer-3 access to the target OT network; target IP range is documented in scope agreement |
| **Test Steps** | 1. Run `plcscan -i 192.168.1.0/24 -t 5` to scan for PLCs |
| | 2. Run `nmap -sT -p 502,102,4840,44818,20000 -sV 192.168.1.0/24` for protocol service detection |
| | 3. Correlate plcscan results with nmap port findings |
| | 4. Document each discovered device: IP, model, firmware, open protocol ports |
| **Expected Results** | All PLCs and RTUs are identified with accurate model and firmware information. Protocol services (Modbus, S7comm, EtherNet/IP) are mapped to their respective devices |
| **Remediation** | Disable unused protocol services on each device; implement network segmentation to limit scanning reachability; deploy IDS rules to detect unauthorized enumeration scans |

### TC-ICS-002: Siemens S7 PLC Fingerprinting with s7scan

| Attribute | Value |
|----------|-------|
| **ID** | TC-ICS-002 |
| **Category** | A. Device Enumeration |
| **Severity** | Medium |
| **Objective** | Fingerprint Siemens S7-series PLCs to determine exact model, firmware version, module type, and protection level |
| **Prerequisites** | Siemens PLCs are in scope; tester has network access to port 102 |
| **Test Steps** | 1. Run `s7scan -t 192.168.1.0/24` to enumerate Siemens devices |
| | 2. For each discovered PLC, attempt to read SZL 0x0011 (module identification) |
| | 3. Read SZL 0x001C (component identification) for hardware details |
| | 4. Read SZL 0x0232 to determine protection level (none/read-only/full) |
| | 5. Cross-reference firmware versions with known CVE databases |
| **Expected Results** | Each S7 PLC is fingerprinted with model, firmware, serial number, and protection level. Outdated firmware versions with known vulnerabilities are flagged |
| **Remediation** | Enable S7comm password protection on all PLCs; update firmware to latest stable versions; configure protection level to at least read-only for unauthorized sessions |

---

## B. Protocol Interaction

### TC-ICS-003: Modbus Register Enumeration and Access Testing

| Attribute | Value |
|----------|-------|
| **ID** | TC-ICS-003 |
| **Category** | B. Protocol Interaction |
| **Severity** | Medium |
| **Objective** | Determine accessible Modbus register ranges, enumerate valid slave IDs, and assess whether unauthorized read/write operations are possible |
| **Prerequisites** | Modbus TCP devices identified on port 502; lab environment only |
| **Test Steps** | 1. Enumerate valid slave IDs by reading register 0 from each ID (1-247) |
| | 2. Read holding registers (function code 3) across full address range in blocks of 100 |
| | 3. Read input registers (function code 4) to identify sensor data |
| | 4. Attempt to write to holding register 0 (function code 6) with a non-destructive test value |
| | 5. Attempt coil writes (function code 5) on an unused coil address |
| | 6. Document all successful operations and accessible register ranges |
| **Expected Results** | Valid slave IDs are identified. All accessible register ranges are documented. Write operations either succeed (indicating no access control) or return exception codes |
| **Remediation** | Deploy a Modbus TCP gateway with IP-based access control and command allowlisting; block write function codes at the protocol-aware firewall unless explicitly required by operations |

### TC-ICS-004: OPC UA Server Endpoint and Security Policy Audit

| Attribute | Value |
|----------|-------|
| **ID** | TC-ICS-004 |
| **Category** | B. Protocol Interaction |
| **Severity** | High |
| **Objective** | Evaluate OPC UA server endpoints for weak security policies, missing encryption, and overly permissive access controls |
| **Prerequisites** | OPC UA server identified at target address; tester has network access to port 4840 |
| **Test Steps** | 1. Connect to the OPC UA discovery endpoint and enumerate all registered servers |
| | 2. Retrieve all endpoint URLs and their associated security policies |
| | 3. Attempt unencrypted (None) connection to each endpoint |
| | 4. For each endpoint, document SecurityMode (None/Sign/SignAndEncrypt) and SecurityPolicyUri |
| | 5. Browse the address space and attempt to read/write variables without authentication |
| | 6. Check server certificate validity, expiration, and chain of trust |
| **Expected Results** | Endpoints using SecurityMode=None or SecurityPolicy=None are identified. Variables writable without authentication are documented. Expired or self-signed certificates are flagged |
| **Remediation** | Enforce SignAndEncrypt security mode on all endpoints; disable None security policy; implement certificate-based authentication; restrict variable write access using OPC UA role-based access control |

---

## C. Protocol Exploitation

### TC-ICS-005: EtherNet/IP CIP Device Deep Enumeration

| Attribute | Value |
|----------|-------|
| **ID** | TC-ICS-005 |
| **Category** | C. Protocol Exploitation |
| **Severity** | High |
| **Objective** | Enumerate CIP device attributes, register unauthorized sessions, and assess whether implicit messaging connections can be established without credentials |
| **Prerequisites** | EtherNet/IP devices identified on port 44818; lab environment with Allen-Bradley or compatible devices |
| **Test Steps** | 1. Run `enip-client -i 192.168.1.0/24 --list-identity` to discover all CIP devices |
| | 2. For each device, register a session using `enip-client -t <ip> --register-session` |
| | 3. Read identity object attributes: vendor ID, product name, serial number, firmware revision |
| | 4. Enumerate all supported CIP classes using `--list-classes` |
| | 5. Attempt a ForwardOpen request to establish implicit messaging |
| | 6. Document all successful session registrations and data reads |
| **Expected Results** | All CIP devices respond with identity information. Sessions can be registered without credentials. Supported CIP classes reveal device capabilities. Implicit messaging may be established without authentication |
| **Remediation** | Enable CIP security where supported; restrict EtherNet/IP access to authorized IPs via firewall; monitor for unexpected session registrations using ICS-aware IDS |

### TC-ICS-006: ICS Protocol Fuzzing with csric

| Attribute | Value |
|----------|-------|
| **ID** | TC-ICS-006 |
| **Category** | C. Protocol Exploitation |
| **Severity** | Critical |
| **Objective** | Fuzz ICS protocol implementations (Modbus, DNP3, S7comm) to identify parsing vulnerabilities, buffer overflows, and denial-of-service conditions in PLC firmware |
| **Prerequisites** | Isolated lab environment only; target devices are non-production; tcpdump capturing baseline traffic for comparison |
| **Test Steps** | 1. Start traffic capture: `tcpdump -i eth0 -w fuzz_baseline.pcap port 502` |
| | 2. Run Modbus fuzzer: `csric -t 192.168.1.10 -p 502 -P modbus -f fuzz --iterations 1000` |
| | 3. Monitor target device for crashes, reboots, or abnormal behavior |
| | 4. If device crashes, capture the last packet that caused the crash from the pcap |
| | 5. Repeat for DNP3: `csric -t 192.168.1.15 -p 20000 -P dnp3 -f fuzz` |
| | 6. Document all crashes, exception responses, and anomalies |
| **Expected Results** | Fuzzer identifies malformed packets that cause exception responses, device hangs, or crashes. Specific function codes and payload patterns that trigger vulnerabilities are documented |
| **Remediation** | Apply vendor firmware updates that address parsing vulnerabilities; deploy protocol-aware firewalls that validate message structure before forwarding; implement network monitoring to detect malformed ICS protocol packets |

---

## D. Defense and Detection

### TC-ICS-007: ICS Honeypot Deployment with conpot

| Attribute | Value |
|----------|-------|
| **ID** | TC-ICS-007 |
| **Category** | D. Defense and Detection |
| **Severity** | Medium |
| **Objective** | Deploy conpot ICS honeypots to detect unauthorized network scanning, protocol interaction, and attack attempts against emulated ICS devices |
| **Prerequisites** | Dedicated host or VM for honeypot deployment; network tap or SPAN port configured for the OT network segment |
| **Test Steps** | 1. Install conpot and select an appropriate template: `conpot -f --template default` |
| | 2. Configure the honeypot IP on the OT network: `conpot -f --template kemel --host 192.168.1.200` |
| | 3. Enable logging: `conpot -f --template default --logfile /var/log/conpot.log` |
| | 4. Simulate attacker scanning from a separate host: `nmap -sT -p 502,102,4840 192.168.1.200` |
| | 5. Simulate Modbus interaction: `modbus-cli read -a 192.168.1.200 -r 0 -n 10` |
| | 6. Verify that conpot logs all interaction attempts with timestamps and source IPs |
| | 7. Check syslog/json logs for alerts |
| **Expected Results** | Honeypot responds to Modbus and other ICS protocol queries with realistic-looking device data. All scanner and client interactions are logged with source IP, timestamp, protocol, and requested operation |
| **Remediation** | Deploy honeypots in unused IP spaces across all OT network segments; integrate conpot logs with SIEM for real-time alerting; use honeypot detections to trigger automated firewall rules blocking the source IP |

### TC-ICS-008: ICS Network Segmentation and Cross-Zone Reachability Audit

| Attribute | Value |
|----------|-------|
| **ID** | TC-ICS-008 |
| **Category** | D. Defense and Detection |
| **Severity** | High |
| **Objective** | Verify that proper network segmentation exists between IT and OT zones following the Purdue Model, and that no unauthorized cross-zone communication paths exist |
| **Prerequisites** | Network architecture diagram provided; tester has access to both IT and OT network segments; authorized to test firewall rules |
| **Test Steps** | 1. From the IT network, attempt to reach OT devices on ICS ports: `nmap -sT -p 502,102,44818,4840 10.0.1.0/24` (OT subnet) |
| | 2. From the OT network, attempt to reach IT systems: `nmap -sT -p 80,443,3389,22 192.168.100.0/24` (IT subnet) |
| | 3. Test DMZ reachability from both zones: attempt connections to historian, OPC UA gateway, and web HMI in the DMZ |
| | 4. Attempt to reach internet from OT network: `nmap -sT -p 80 scanme.nmap.org` |
| | 5. Test for dual-homed hosts bridging IT and OT without firewall |
| | 6. Document all successful cross-zone connections |
| **Expected Results** | IT-to-OT direct access is blocked. OT-to-IT access is limited to specific DMZ services. No direct internet access from OT. Dual-homed hosts are identified and assessed. All violations of the Purdue Model segmentation are documented |
| **Remediation** | Implement a proper DMZ between IT and OT networks; deploy firewalls that enforce unidirectional gateways (data diodes) for critical zones; remove dual-homed hosts or isolate them behind firewalls; block all outbound internet access from OT network |

---

## Pass Criteria Checklist

- [ ] All PLCs and RTUs identified with model, firmware, and protocol services
- [ ] Siemens S7 PLCs fingerprinted with protection level assessed
- [ ] Modbus register ranges enumerated with read/write access verified
- [ ] OPC UA endpoints audited for weak security policies and unauthenticated access
- [ ] EtherNet/IP CIP device enumeration completed with session registration tested
- [ ] Protocol fuzzing executed with crash-inducing payloads documented
- [ ] Conpot honeypot deployed and logging verified
- [ ] IT/OT network segmentation validated against Purdue Model
- [ ] All cross-zone communication paths documented
