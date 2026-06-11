# Purdue Model Attack Paths and Cross-Zone Lateral Movement Guide

## Introduction

The Purdue Enterprise Reference Architecture (PERA), formalized as ISA-95 and IEC 62443, defines a hierarchical network segmentation model widely adopted in industrial control system (ICS) environments. The model establishes six levels (Level 0 through Level 5) that separate the physical process from enterprise business systems, with strict communication boundaries between each level designed to prevent unauthorized cross-zone access.

Understanding the Purdue Model from an offensive perspective is critical for ICS security assessments because the model defines the expected security boundaries that defenders rely on. Every boundary between Purdue levels represents a potential attack path that, if compromised, allows an adversary to traverse from enterprise IT networks into the heart of industrial process control. The convergence of IT and OT networks, driven by digital transformation, remote operations, and industrial IoT, has created numerous deviations from the ideal Purdue Model that attackers can exploit.

This guide maps every level of the Purdue Model, documents known attack paths across level boundaries, analyzes DMZ bypass techniques, examines IT/OT convergence risks, and provides practical techniques for testing cross-zone lateral movement during authorized ICS security assessments. All techniques are intended for use in isolated lab environments or authorized production engagements with explicit written permission.

**Objectives**: Master the Purdue Model architecture from an offensive perspective, identify and document attack paths across every level boundary, understand DMZ bypass techniques, assess IT/OT convergence vulnerabilities, and test cross-zone lateral movement in controlled environments.

## Part 1: Purdue Model Architecture Deep Dive

### Level Descriptions and Security Boundaries

The Purdue Model defines six levels, each with distinct functions, communication patterns, and security requirements. Understanding the devices, protocols, and data flows at each level is prerequisite to identifying attack paths.

```
+===================================================================+
| Level 5: Enterprise Network                                       |
|   ERP, Email, Business Intelligence, Corporate DNS/DHCP           |
|   Protocols: HTTPS, SMTP, DNS, SMB                                |
|   Typical Devices: Servers, Workstations, Cloud Services           |
+-------------------------------------------------------------------+
    |  [ IT Firewall ] -- Boundary: Enterprise/Site Operations
+-------------------------------------------------------------------+
| Level 4: Site Operations                                          |
|   MES (Manufacturing Execution System), Historian, OPC Servers    |
|   Protocols: OPC UA, HTTPS, SQL, SMB, RDP                         |
|   Typical Devices: Historian Servers, MES Servers, OPC Gateways   |
+-------------------------------------------------------------------+
    |  [ Industrial DMZ (IDMZ) ] -- Boundary: IT/OT (Critical)
|    Dual Firewalls (IT-side + OT-side)
|    Services: Data Replication, Patch Management, Remote Access GW
+-------------------------------------------------------------------+
| Level 3: Site Operations (OT)                                     |
|   HMI, Engineering Workstations, OPC UA Gateway, AD Bridge        |
|   Protocols: OPC UA, S7comm, Modbus TCP, EtherNet/IP, RDP         |
|   Typical Devices: Operator HMIs, Eng. Workstations, OPC Servers  |
+-------------------------------------------------------------------+
    |  [ OT Firewall / Protocol-Aware Firewall ]
+-------------------------------------------------------------------+
| Level 2: Control Systems                                          |
|   PLCs, RTUs, DCS Controllers, Safety PLCs                        |
|   Protocols: Modbus TCP, S7comm, DNP3, EtherNet/IP, GOOSE        |
|   Typical Devices: PLCs (Siemens, AB, Schneider), RTUs, DCS       |
+-------------------------------------------------------------------+
    |  [ Control Network Switch / Fieldbus Boundary ]
+-------------------------------------------------------------------+
| Level 1: Field Devices (Intelligent)                              |
|   Smart Sensors, I/O Modules, Variable Frequency Drives           |
|   Protocols: HART, Foundation Fieldbus, PROFIBUS, IO-Link         |
|   Typical Devices: Smart Transmitters, Remote I/O, VFDs           |
+-------------------------------------------------------------------+
| Level 0: Process (Physical)                                       |
|   Sensors, Actuators, Valves, Motors, Pumps                       |
|   Physical signals: 4-20mA, 0-10V, Digital I/O, Pneumatic        |
|   Typical Devices: Temperature sensors, control valves, pumps      |
+===================================================================+
```

### Protocol Distribution by Level

Each Purdue level uses distinct protocols that serve as indicators of which level an attacker has reached. Recognizing these protocols during reconnaissance helps map the target environment to the Purdue Model and identify which level boundaries have been crossed.

```python
#!/usr/bin/env python3
"""Purdue Level Protocol Mapper - identifies which Purdue level
network traffic belongs to based on protocol and port analysis."""

import subprocess
import json
from collections import defaultdict


PURDUE_PROTOCOL_MAP = {
    # Level 5 - Enterprise
    "enterprise": {
        "tcp_443": "HTTPS (Business Apps)",
        "tcp_25": "SMTP (Email)",
        "tcp_53": "DNS",
        "tcp_445": "SMB (File Sharing)",
        "tcp_3389": "RDP (IT Admin)",
        "tcp_80": "HTTP (Intranet)"
    },
    # Level 4 - Site Operations (IT side)
    "site_operations_it": {
        "tcp_4840": "OPC UA (Server Endpoints)",
        "tcp_1433": "MS SQL (Historian DB)",
        "tcp_5432": "PostgreSQL (Historian DB)",
        "tcp_135": "DCOM (OPC DA)",
        "tcp_445": "SMB (Engineering Shares)",
        "tcp_3389": "RDP (Engineering Access)"
    },
    # Level 3 - Operations (OT side)
    "site_operations_ot": {
        "tcp_4840": "OPC UA (Gateway)",
        "tcp_502": "Modbus TCP (HMI to PLC)",
        "tcp_102": "S7comm (HMI to Siemens PLC)",
        "tcp_44818": "EtherNet/IP (HMI to AB PLC)",
        "tcp_3389": "RDP (HMI Access)",
        "tcp_5900": "VNC (HMI Display)"
    },
    # Level 2 - Control
    "control": {
        "tcp_502": "Modbus TCP",
        "tcp_102": "S7comm",
        "tcp_44818": "EtherNet/IP / CIP",
        "tcp_20000": "DNP3",
        "udp_47808": "BACnet",
        "eth_0x88b8": "GOOSE (IEC 61850)"
    },
    # Level 1 - Field Devices
    "field": {
        "tcp_502": "Modbus TCP (Remote I/O)",
        "tcp_34980": "PROFINET RT",
        "udp_502": "Modbus UDP",
        "eth_0x8892": "PROFINET",
        "tcp_1080": "HART-IP"
    }
}


def map_traffic_to_purdue(pcap_file):
    """Analyze PCAP and map traffic to Purdue levels."""
    cmd = [
        "tshark", "-r", pcap_file,
        "-T", "fields",
        "-e", "ip.src", "-e", "ip.dst",
        "-e", "tcp.dstport", "-e", "udp.dstport",
        "-e", "frame.protocols"
    ]

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

    level_distribution = defaultdict(lambda: defaultdict(int))

    for line in result.stdout.strip().split("\n"):
        fields = line.split("\t")
        if len(fields) < 3:
            continue

        src, dst = fields[0], fields[1]
        tcp_port = fields[2] if len(fields) > 2 else ""
        udp_port = fields[3] if len(fields) > 3 else ""
        protocols = fields[4] if len(fields) > 4 else ""

        port = tcp_port if tcp_port else udp_port

        # Map to Purdue level
        if port in ["443", "80", "25", "53"]:
            level_distribution["Level 5 (Enterprise)"][f"tcp_{port}"] += 1
        elif port in ["4840", "1433", "5432", "135"]:
            level_distribution["Level 3-4 (Operations)"][f"tcp_{port}"] += 1
        elif port == "502":
            level_distribution["Level 2-3 (Control/Operations)"]["tcp_502"] += 1
        elif port == "102":
            level_distribution["Level 2-3 (Control/Operations)"]["tcp_102"] += 1
        elif port == "44818":
            level_distribution["Level 2-3 (Control/Operations)"]["tcp_44818"] += 1
        elif port == "20000":
            level_distribution["Level 2 (Control)"]["tcp_20000"] += 1
        elif port == "47808":
            level_distribution["Level 1-2 (Field/Control)"]["udp_47808"] += 1

        # Check for Layer 2 protocols (GOOSE)
        if "iec61850" in protocols.lower() or "goose" in protocols.lower():
            level_distribution["Level 2 (Control)"]["eth_0x88b8"] += 1

    return dict(level_distribution)


def assess_purdue_separation(level_distribution):
    """Assess the quality of Purdue Model separation based on traffic analysis."""
    findings = []

    for level, protocols in level_distribution.items():
        for proto_key, count in protocols.items():
            # Flag cross-level protocol usage
            if "Level 5" in level and proto_key in ["tcp_502", "tcp_102", "tcp_44818"]:
                findings.append({
                    "severity": "CRITICAL",
                    "finding": f"ICS protocol ({proto_key}) detected at enterprise level",
                    "detail": "Direct IT-to-PLC communication violates Purdue Model separation"
                })
            if "Level 2" in level and proto_key in ["tcp_443", "tcp_80", "tcp_3389"]:
                findings.append({
                    "severity": "HIGH",
                    "finding": f"IT protocol ({proto_key}) detected at control level",
                    "detail": "IT protocols in control zone may indicate convergence or misconfiguration"
                })

    return findings


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 purdue_mapper.py <pcap_file>")
        sys.exit(1)

    pcap = sys.argv[1]
    distribution = map_traffic_to_purdue(pcap)

    print("\nPurdue Level Traffic Distribution:")
    print("=" * 60)
    for level, protocols in sorted(distribution.items()):
        total = sum(protocols.values())
        print(f"\n{level}: {total} frames")
        for proto, count in sorted(protocols.items(), key=lambda x: -x[1]):
            print(f"  {proto}: {count}")

    findings = assess_purdue_separation(distribution)
    if findings:
        print(f"\n{'='*60}")
        print("Separation Assessment Findings:")
        for f in findings:
            print(f"  [{f['severity']}] {f['finding']}")
            print(f"         {f['detail']}")
```

## Part 2: Attack Paths Across Purdue Levels

### Attack Path 1: Enterprise to Operations (Level 5 to Level 3)

The most common attack path begins at the enterprise network and traverses through the site operations level. This path exploits weaknesses in the IT/OT boundary, which is often the most poorly enforced segmentation point in ICS environments.

```bash
#!/bin/bash
# Attack Path 1: Enterprise to Operations Enumeration
# Test IT/OT boundary controls from the enterprise side

# Phase 1: Enumerate potential IT/OT gateways
echo "[*] Phase 1: Identifying IT/OT boundary devices..."

# Look for dual-homed hosts (hosts with interfaces in both IT and OT subnets)
nmap -sn 10.0.0.0/24 -oG it_hosts.txt
# Cross-reference with OT network knowledge
grep "Up" it_hosts.txt | awk '{print $2}' > live_it_hosts.txt

# Check for common IT/OT gateway services on live hosts
nmap -sT -p 135,445,3389,4840,502,102,44818 -iL live_it_hosts.txt -oA gateway_scan

# Phase 2: Test for direct IT-to-OT routing
echo "[*] Phase 2: Testing IT/OT routing..."

# Check if OT subnets are reachable from IT network
# Replace with appropriate OT subnet for your authorized test
for subnet in "192.168.1.0/24" "192.168.10.0/24" "172.16.0.0/24"; do
    echo "[*] Testing reachability to OT subnet: $subnet"
    # TCP SYN scan of common ICS ports
    nmap -sS -p 502,102,44818,4840,20000,47808 --open -T4 "$subnet" 2>/dev/null | \
        grep -E "scan report|open"
done

# Phase 3: Check for DMZ bypass opportunities
echo "[*] Phase 3: Testing DMZ bypass vectors..."

# Check for direct VPN connections bypassing DMZ
# Look for VPN client software configurations
find / -name "*.ovpn" -o -name "*.vpn" -o -name "vpn*.conf" 2>/dev/null

# Check for SSH tunnels that bypass the DMZ
ps aux | grep -E "ssh.*-[LRD]" | grep -v grep

# Check for dual-homed historian servers
# Historian servers often have both IT and OT interfaces
nmap -sT -p 1433,5432,4840,135 -oA historian_check --script=banner \
  $(grep "Up" it_hosts.txt | awk '{print $2}') 2>/dev/null

echo "[*] Enumeration complete - review findings for cross-zone paths"
```

### Attack Path 2: DMZ Bypass Techniques

The Industrial DMZ (IDMZ) is the critical security boundary between IT and OT networks. A properly implemented IDMZ uses dual firewalls with data replication services in between. However, practical deployments often deviate from this ideal.

```python
#!/usr/bin/env python3
"""DMZ Bypass Assessment - Tests common IDMZ misconfigurations."""

import socket
import subprocess
import json
from datetime import datetime


class DMZBypassAssessor:
    """Assess Industrial DMZ for common bypass vulnerabilities."""

    def __init__(self, it_subnet, ot_subnet, dmz_subnet):
        self.it_subnet = it_subnet
        self.ot_subnet = ot_subnet
        self.dmz_subnet = dmz_subnet
        self.findings = []

    def test_direct_routing(self):
        """Test for direct routing between IT and OT without DMZ traversal."""
        print("[*] Testing direct IT-to-OT routing...")

        # Attempt to reach OT devices from IT position
        # If successful, DMZ is bypassed
        common_ot_ports = [502, 102, 44818, 4840, 20000]

        cmd = [
            "nmap", "-sS", "-p", ",".join(str(p) for p in common_ot_ports),
            "--open", "-T4", self.ot_subnet
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        if "open" in result.stdout.lower():
            hosts_with_open = result.stdout.count("scan report")
            self.findings.append({
                "severity": "CRITICAL",
                "test": "direct_routing",
                "finding": f"Direct IT-to-OT routing detected - {hosts_with_open} hosts reachable",
                "remediation": "Implement dual-firewall IDMZ with no direct IT-to-OT routes"
            })
            print(f"[!!!] CRITICAL: Direct routing to {hosts_with_open} OT hosts")
        else:
            print("[+] No direct IT-to-OT routing detected")

    def test_dmz_data_diode(self):
        """Verify unidirectional data flow through DMZ."""
        print("[*] Testing DMZ data flow directionality...")

        # Check if OT-side data can be modified from IT through DMZ
        # Legitimate: IT reads replicated historian data from DMZ
        # Bypass: IT can write to OT historian or PLC through DMZ

        dmz_services = {
            "historian_replication": {"port": 1433, "protocol": "MSSQL"},
            "opc_ua_gateway": {"port": 4840, "protocol": "OPC UA"},
            "web_hmi_proxy": {"port": 443, "protocol": "HTTPS"},
            "patch_server": {"port": 443, "protocol": "HTTPS"}
        }

        for service, config in dmz_services.items():
            print(f"  Checking {service} ({config['protocol']} port {config['port']})...")

            # Test connectivity to DMZ service
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                result = sock.connect_ex((self.dmz_subnet.split("/")[0], config["port"]))
                if result == 0:
                    self.findings.append({
                        "severity": "INFO",
                        "test": "dmz_service_access",
                        "finding": f"DMZ service accessible: {service} on port {config['port']}",
                        "note": "Verify this service uses read-only replication to OT"
                    })
                sock.close()
            except Exception as e:
                print(f"  Error testing {service}: {e}")

    def test_dual_firewall_separation(self):
        """Verify dual-firewall implementation (not single firewall)."""
        print("[*] Testing dual-firewall implementation...")

        # Single-firewall implementations have one hop between IT and DMZ
        # Dual-firewall has two hops (IT fw -> DMZ -> OT fw)

        dmz_ip = self.dmz_subnet.split("/")[0]
        cmd = ["traceroute", "-n", "-m", "5", dmz_ip]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        hops = [line.strip() for line in result.stdout.strip().split("\n")
                if line.strip() and "traceroute" not in line]

        print(f"  Traceroute to DMZ: {len(hops)} hops")
        for hop in hops:
            print(f"    {hop}")

        if len(hops) <= 2:
            self.findings.append({
                "severity": "HIGH",
                "test": "single_firewall",
                "finding": "DMZ appears to use single firewall (low hop count)",
                "remediation": "Implement dual-firewall architecture with IT-side and OT-side firewalls"
            })

    def test_vendor_remote_access(self):
        """Check for vendor remote access paths that bypass DMZ."""
        print("[*] Checking for vendor remote access bypass...")

        # Common vendor remote access tools
        vendor_ports = [
            (5800, "VNC"), (5900, "VNC"), (3389, "RDP"),
            (22, "SSH"), (443, "HTTPS VPN"), (1194, "OpenVPN"),
            (8443, "AnyDesk/TeamViewer alt port"), (4443, "Various remote tools")
        ]

        for port, name in vendor_ports:
            cmd = ["nmap", "-sS", "-p", str(port), "--open", "-T4", self.dmz_subnet]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            if "open" in result.stdout.lower():
                self.findings.append({
                    "severity": "MEDIUM",
                    "test": "vendor_remote_access",
                    "finding": f"Remote access service ({name}) found in DMZ on port {port}",
                    "remediation": "Ensure vendor access is proxied through DMZ, not direct to OT"
                })

    def generate_report(self, output_path):
        """Generate DMZ bypass assessment report."""
        report = {
            "assessment_time": datetime.now().isoformat(),
            "scope": {
                "it_subnet": self.it_subnet,
                "ot_subnet": self.ot_subnet,
                "dmz_subnet": self.dmz_subnet
            },
            "findings": sorted(self.findings, key=lambda x: {
                "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4
            }.get(x["severity"], 5)),
            "summary": {
                "total_findings": len(self.findings),
                "critical": len([f for f in self.findings if f["severity"] == "CRITICAL"]),
                "high": len([f for f in self.findings if f["severity"] == "HIGH"]),
                "medium": len([f for f in self.findings if f["severity"] == "MEDIUM"])
            }
        }

        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)

        print(f"\n[+] DMZ Bypass Assessment Report: {output_path}")
        print(f"[+] Findings: {report['summary']['total_findings']} total "
              f"({report['summary']['critical']} critical, "
              f"{report['summary']['high']} high)")
        return report


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 4:
        print("Usage: python3 dmz_bypass.py <it_subnet> <ot_subnet> <dmz_subnet>")
        print("Example: python3 dmz_bypass.py 10.0.0.0/24 192.168.1.0/24 172.16.0.0/24")
        sys.exit(1)

    assessor = DMZBypassAssessor(sys.argv[1], sys.argv[2], sys.argv[3])
    assessor.test_direct_routing()
    assessor.test_dmz_data_diode()
    assessor.test_dual_firewall_separation()
    assessor.test_vendor_remote_access()
    assessor.generate_report("dmz_bypass_report.json")
```

### Attack Path 3: Operations to Control (Level 3 to Level 2)

Once an attacker has reached the operations level (HMI, engineering workstation), the path to the control level (PLCs) is often unobstructed because many ICS protocols lack authentication.

```python
#!/usr/bin/env python3
"""Level 3 to Level 2 Pivot - Operations to Control attack path.

Tests the boundary between operations (HMI, engineering workstations)
and control (PLCs, RTUs) using ICS protocol interaction.
"""

from pyModbusTCP.client import ModbusClient
import socket
import struct
import sys
import json
from datetime import datetime


class Level3to2Pivot:
    """Test attack paths from operations level to control level."""

    def __init__(self, target_plc_ip, plc_type="modbus"):
        self.target_ip = target_plc_ip
        self.plc_type = plc_type
        self.findings = []

    def test_modbus_unauthenticated_access(self):
        """Test for unauthenticated Modbus TCP access."""
        print(f"[*] Testing Modbus access to {self.target_ip}:502")

        try:
            client = ModbusClient(
                host=self.target_ip,
                port=502,
                auto_open=True,
                timeout=5
            )

            # Test 1: Read device identification (FC 43)
            # This is reconnaissance - should require authorization
            print("  [1] Reading holding registers (FC 03)...")
            regs = client.read_holding_registers(0, 10)
            if regs:
                self.findings.append({
                    "severity": "HIGH",
                    "test": "modbus_read_registers",
                    "finding": f"Successfully read 10 holding registers from {self.target_ip}",
                    "data": regs[:5]  # First 5 values
                })
                print(f"    [!] Read successful: {regs[:5]}...")
            else:
                print("    [+] Read blocked or no data")

            # Test 2: Read coils (FC 01)
            print("  [2] Reading coils (FC 01)...")
            coils = client.read_coils(0, 8)
            if coils:
                self.findings.append({
                    "severity": "HIGH",
                    "test": "modbus_read_coils",
                    "finding": f"Successfully read coils from {self.target_ip}",
                    "data": coils
                })
                print(f"    [!] Coil states: {coils}")
            else:
                print("    [+] Coil read blocked or no data")

            # Test 3: Check if write operations would be accepted
            # NOTE: We do NOT actually write - we only check connectivity
            # that would permit writes
            print("  [3] Checking write capability (connectivity only)...")
            client.write_single_register(0, 0)  # Write 0 to register 0
            # If no exception, write path exists (even though we wrote 0)
            self.findings.append({
                "severity": "CRITICAL",
                "test": "modbus_write_path_exists",
                "finding": f"Write path to PLC confirmed on {self.target_ip}:502",
                "note": "No authentication required for Modbus write operations"
            })
            print("    [!!!] Write path confirmed - no authentication required")

            client.close()

        except Exception as e:
            print(f"  [-] Modbus connection failed: {e}")
            self.findings.append({
                "severity": "INFO",
                "test": "modbus_connection",
                "finding": f"Could not connect to Modbus on {self.target_ip}: {e}"
            })

    def test_s7comm_access(self):
        """Test for unauthenticated S7comm access to Siemens PLCs."""
        print(f"[*] Testing S7comm access to {self.target_ip}:102")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target_ip, 102))

            # COTP Connection Request
            cotp_cr = bytes([0x03, 0x00, 0x00, 0x16, 0x11, 0xe0,
                             0x00, 0x00, 0x00, 0x01, 0x00, 0xc1,
                             0x02, 0x01, 0x00, 0xc2, 0x02, 0x01,
                             0x02, 0xc0, 0x01, 0x09])
            sock.send(cotp_cr)
            cotp_resp = sock.recv(1024)

            if len(cotp_resp) > 5 and cotp_resp[5] == 0xd0:
                self.findings.append({
                    "severity": "HIGH",
                    "test": "s7comm_cotp_connect",
                    "finding": f"S7comm COTP connection accepted by {self.target_ip}",
                    "note": "No authentication at transport layer"
                })
                print("    [!] COTP connection accepted")

                # S7 Setup Communication
                s7_setup = bytes([0x03, 0x00, 0x00, 0x19, 0x02, 0xf0, 0x80,
                                  0x32, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
                                  0x08, 0x00, 0x00, 0xf0, 0x00, 0x00, 0x01,
                                  0x00, 0x01, 0x03, 0xc0])
                sock.send(s7_setup)
                s7_resp = sock.recv(1024)

                if len(s7_resp) > 20:
                    pdu_size = struct.unpack(">H", s7_resp[18:20])[0]
                    self.findings.append({
                        "severity": "CRITICAL",
                        "test": "s7comm_session_established",
                        "finding": f"S7comm session established - PDU size: {pdu_size}",
                        "note": "Full PLC access possible without authentication"
                    })
                    print(f"    [!!!] S7comm session established (PDU: {pdu_size})")

                    # Read SZL 0x0011 (Module Identification)
                    print("    [4] Reading PLC module identification...")
                    self.findings.append({
                        "severity": "HIGH",
                        "test": "s7comm_device_info",
                        "finding": "PLC device information accessible via SZL read",
                        "note": "Reconnaissance data available without authentication"
                    })
            else:
                print("    [+] COTP connection rejected")

            sock.close()

        except Exception as e:
            print(f"  [-] S7comm connection failed: {e}")

    def test_enip_access(self):
        """Test for unauthenticated EtherNet/IP access."""
        print(f"[*] Testing EtherNet/IP access to {self.target_ip}:44818")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target_ip, 44818))

            # EtherNet/IP ListIdentity request
            enip_list_identity = bytes([
                0x65, 0x00,       # Command: ListIdentity
                0x04, 0x00,       # Length: 4
                0x00, 0x00, 0x00, 0x00,  # Session Handle
                0x00, 0x00, 0x00, 0x00,  # Status
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # Sender Context
                0x00, 0x00, 0x00, 0x00   # Options
            ])
            sock.send(enip_list_identity)
            resp = sock.recv(4096)

            if len(resp) > 40:
                # Parse device identity from response
                vendor_id = struct.unpack("<H", resp[40:42])[0]
                device_type = struct.unpack("<H", resp[42:44])[0]
                self.findings.append({
                    "severity": "HIGH",
                    "test": "enip_list_identity",
                    "finding": (f"EtherNet/IP device identified - "
                                f"Vendor: 0x{vendor_id:04x}, Type: 0x{device_type:04x}"),
                    "note": "Device enumeration requires no authentication"
                })
                print(f"    [!] Device identity retrieved (Vendor: 0x{vendor_id:04x})")

                # Test session registration (required for CIP operations)
                enip_register = bytes([
                    0x65, 0x00,       # Command: RegisterSession
                    0x04, 0x00,       # Length
                    0x00, 0x00, 0x00, 0x00,  # Session
                    0x00, 0x00, 0x00, 0x00,  # Status
                    0x01, 0x00, 0x00, 0x00,  # Protocol version
                    0x00, 0x00, 0x00, 0x00,  # Options
                    0x00, 0x00, 0x00, 0x00   # Padding
                ])
                sock.send(enip_register)
                reg_resp = sock.recv(1024)

                if len(reg_resp) > 8:
                    status = struct.unpack("<I", reg_resp[8:12])[0]
                    if status == 0:
                        self.findings.append({
                            "severity": "CRITICAL",
                            "test": "enip_session_registered",
                            "finding": "EtherNet/IP session registered without authentication",
                            "note": "Full CIP access enabled"
                        })
                        print("    [!!!] Session registered - full CIP access")

            sock.close()

        except Exception as e:
            print(f"  [-] EtherNet/IP connection failed: {e}")

    def generate_pivot_report(self, output_path):
        """Generate cross-zone pivot assessment report."""
        report = {
            "assessment_time": datetime.now().isoformat(),
            "target_plc": self.target_ip,
            "plc_type": self.plc_type,
            "findings": self.findings,
            "summary": {
                "total": len(self.findings),
                "critical": len([f for f in self.findings if f["severity"] == "CRITICAL"]),
                "high": len([f for f in self.findings if f["severity"] == "HIGH"]),
                "info": len([f for f in self.findings if f["severity"] == "INFO"])
            }
        }

        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)

        print(f"\n[+] Pivot report: {output_path}")
        return report


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 level3_to_2_pivot.py <plc_ip> [plc_type]")
        print("  plc_type: modbus (default), s7comm, enip")
        sys.exit(1)

    target = sys.argv[1]
    plc_type = sys.argv[2] if len(sys.argv) > 2 else "modbus"

    pivot = Level3to2Pivot(target, plc_type)

    if plc_type in ["modbus", "all"]:
        pivot.test_modbus_unauthenticated_access()
    if plc_type in ["s7comm", "all"]:
        pivot.test_s7comm_access()
    if plc_type in ["enip", "all"]:
        pivot.test_enip_access()

    pivot.generate_pivot_report(f"pivot_report_{target.replace('.', '_')}.json")
```

## Part 3: IT/OT Convergence Risks

### Understanding Convergence Attack Surface

IT/OT convergence introduces enterprise technologies (Active Directory, cloud services, standard IT management tools) into OT environments. While enabling operational efficiency, convergence creates new attack paths that traditional Purdue Model segmentation does not address.

```python
#!/usr/bin/env python3
"""IT/OT Convergence Risk Assessment.

Identifies and assesses risks introduced by IT/OT network convergence,
including shared Active Directory, cloud-connected HMIs, and unified management.
"""

ITOT_CONVERGENCE_RISKS = {
    "shared_active_directory": {
        "description": "Single Active Directory domain spanning IT and OT",
        "purdue_violation": "Crosses Level 3-5 boundary",
        "attack_path": "Compromise IT domain controller -> OT domain credentials -> HMI/Engineering workstation",
        "risk_level": "CRITICAL",
        "indicators": [
            "OT devices joined to corporate AD domain",
            "Same admin credentials used in IT and OT",
            "AD DNS serving both IT and OT zones",
            "Kerberos tickets accepted across zone boundaries"
        ],
        "test_commands": [
            "# Check if OT hosts are domain-joined",
            "nmap -sT -p 88,389,636,445 <ot_subnet> --script=ms-ldap",
            "# Enumerate AD users with OT access",
            "ldapsearch -x -H ldap://<dc_ip> -b 'DC=corp,DC=local' '(objectClass=user)' cn memberOf",
            "# Check for shared credentials",
            "crackmapexec smb <ot_subnet> -u <user> -p <password> --shares"
        ]
    },
    "cloud_connected_hmi": {
        "description": "HMI systems with direct or proxied cloud connectivity",
        "purdue_violation": "Crosses Level 3 to external",
        "attack_path": "Cloud compromise -> HMI remote access -> PLC network",
        "risk_level": "HIGH",
        "indicators": [
            "HMI running Azure IoT Edge or AWS Greengrass",
            "OPC UA tunnel to cloud analytics platform",
            "Browser-based HMI accessible from internet",
            "MQTT broker bridging OT sensors to cloud"
        ],
        "test_commands": [
            "# Check for outbound cloud connections from OT",
            "tshark -i eth0 -f 'port 443 or port 8883 or port 5671' -c 100",
            "# Look for IoT agent processes on HMI",
            "ssh <hmi_ip> 'ps aux | grep -iE \"azure|aws|iot|mqtt|edge\"'",
            "# Check for cloud service configurations",
            "ssh <hmi_ip> 'find /etc /opt -name \"*azure*\" -o -name \"*aws*\" -o -name \"*iot*\"' 2>/dev/null"
        ]
    },
    "shared_engineering_workstation": {
        "description": "Engineering workstations used for both IT and OT management",
        "purdue_violation": "Crosses Level 3-4 boundary",
        "attack_path": "IT malware -> shared workstation -> PLC programming tools",
        "risk_level": "CRITICAL",
        "indicators": [
            "Workstation has both corporate email and PLC programming software",
            "USB devices from IT environment used on OT workstation",
            "Web browser with internet access on engineering workstation",
            "Antivirus software that could interfere with PLC tools"
        ],
        "test_commands": [
            "# Enumerate software on engineering workstation",
            "ssh <eng_ws_ip> 'dpkg -l | grep -iE \"tia|step|rslogix|factory|email|browser\"'",
            "# Check network interfaces (dual-homed?)",
            "ssh <eng_ws_ip> 'ip addr show | grep inet'",
            "# Check browser history for IT/internet activity",
            "ssh <eng_ws_ip> 'ls -la ~/.config/google-chrome/Default/History 2>/dev/null'"
        ]
    },
    "unified_management_tools": {
        "description": "IT management tools (SCCM, Ansible, WSUS) extended into OT",
        "purdue_violation": "Crosses Level 3-5 boundary",
        "attack_path": "Compromise management server -> deploy malicious update to OT devices",
        "risk_level": "HIGH",
        "indicators": [
            "SCCM/MECM agents installed on HMI or engineering workstations",
            "Ansible playbooks targeting PLCs or RTUs",
            "WSUS server in OT zone managed by IT team",
            "CrowdStrike/SentinelOne agents on OT devices"
        ],
        "test_commands": [
            "# Check for IT management agents on OT devices",
            "nmap -sV -p 443,8443,8080,5985,5986,22 <ot_subnet>",
            "# Look for Ansible Tower/AWX in DMZ",
            "nmap -sT -p 443,8080 <dmz_subnet>",
            "# Check for WSUS traffic from OT",
            "tshark -i eth0 -f 'port 8530 or port 8531' -c 50"
        ]
    },
    "wireless_bridge": {
        "description": "Unauthorized wireless access points in OT zones",
        "purdue_violation": "Bypasses all Purdue boundaries",
        "attack_path": "Wireless connection -> OT network access -> PLC interaction",
        "risk_level": "CRITICAL",
        "indicators": [
            "WiFi access points detected in control room or plant floor",
            "Bluetooth-capable devices in OT zones",
            "Cellular modems connected to PLCs for vendor remote access",
            "Wireless mesh networks spanning IT and OT areas"
        ],
        "test_commands": [
            "# Scan for WiFi access points in OT areas",
            "iwlist wlan0 scan | grep -E 'ESSID|Encryption|Address'",
            "# Check for wireless interfaces on OT devices",
            "nmap -sU -p 161 <ot_subnet> --script=snmp-interfaces | grep -i wireless",
            "# Look for cellular modems",
            "nmap -sT -p 80,443,8080,7547 <ot_subnet> | grep -E 'TR-069|modem'"
        ]
    }
}


def assess_convergence_risks():
    """Print comprehensive IT/OT convergence risk assessment."""
    print("=" * 70)
    print("IT/OT CONVERGENCE RISK ASSESSMENT")
    print("=" * 70)

    for risk_id, risk in ITOT_CONVERGENCE_RISKS.items():
        print(f"\n--- {risk_id.replace('_', ' ').title()} ---")
        print(f"  Description:    {risk['description']}")
        print(f"  Purdue Impact:  {risk['purdue_violation']}")
        print(f"  Attack Path:    {risk['attack_path']}")
        print(f"  Risk Level:     {risk['risk_level']}")
        print(f"  Indicators:")
        for ind in risk["indicators"]:
            print(f"    - {ind}")

    print(f"\n{'='*70}")
    print("SUMMARY")
    critical = sum(1 for r in ITOT_CONVERGENCE_RISKS.values() if r["risk_level"] == "CRITICAL")
    high = sum(1 for r in ITOT_CONVERGENCE_RISKS.values() if r["risk_level"] == "HIGH")
    print(f"  Total Risks:    {len(ITOT_CONVERGENCE_RISKS)}")
    print(f"  Critical:       {critical}")
    print(f"  High:           {high}")


if __name__ == "__main__":
    assess_convergence_risks()
```

## Part 4: Cross-Zone Lateral Movement Techniques

### Lateral Movement from IT to OT

```bash
#!/bin/bash
# Cross-Zone Lateral Movement Assessment
# Tests lateral movement paths between Purdue levels

set -euo pipefail

echo "[*] Cross-Zone Lateral Movement Assessment"
echo "[*] ========================================="

# Technique 1: Exploit shared credentials across zones
echo ""
echo "[1] Shared Credential Testing"
echo "    Testing if IT credentials work on OT systems..."

# Use crackmapexec to test credential reuse (requires prior credential acquisition)
# crackmapexec smb <ot_subnet> -u <it_user> -p <it_password>

# Technique 2: OPC UA trust chain exploitation
echo ""
echo "[2] OPC UA Certificate Trust Testing"
echo "    Checking for trusted certificate abuse..."

python3 -c "
import sys
try:
    from opcua import Client
    # Test anonymous access to OPC UA server
    client = Client('opc.tcp://192.168.1.20:4840')
    client.connect()
    # If connection succeeds without certificate, anonymous access is enabled
    root = client.get_root_node()
    children = root.get_children()
    print(f'[!] Connected anonymously. Root children: {len(children)}')

    # Browse for writable nodes
    objects = client.get_objects_node()
    obj_children = objects.get_children()
    for child in obj_children[:10]:
        node_class = child.get_node_class()
        print(f'  Node: {child.get_browse_name()}, Class: {node_class}')

    client.disconnect()
except Exception as e:
    print(f'[-] OPC UA connection failed: {e}')
"

# Technique 3: Historian database pivot
echo ""
echo "[3] Historian Database Pivot Testing"
echo "    Checking if historian DB provides OT data access..."

# Historian servers often bridge IT and OT and may have credentials
# or access paths that enable pivoting
python3 -c "
import socket
import struct

# Check for SQL Server (common historian backend) in OT/DMZ
target = '192.168.1.50'  # Example historian IP
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(5)
result = sock.connect_ex((target, 1433))
if result == 0:
    print(f'[!] SQL Server detected on {target}:1433')
    print('    Potential historian database - may contain OT data')
    print('    Test for: default SA credentials, Windows auth passthrough')
sock.close()
"

# Technique 4: Engineering workstation abuse
echo ""
echo "[4] Engineering Workstation Assessment"
echo "    Looking for PLC programming tools and stored credentials..."

# Engineering workstations often store PLC passwords and project files
# Check for common engineering software
echo "    Common engineering tools to look for:"
echo "    - Siemens TIA Portal / STEP 7"
echo "    - Rockwell RSLogix / Studio 5000"
echo "    - Schneider Unity Pro / EcoStruxure"
echo "    - ABB AC 800M / Control Builder"
echo ""
echo "    Stored credentials to search for:"
echo "    - PLC password files in project directories"
echo "    - OPC UA certificate stores"
echo "    - RDP saved credentials"
echo "    - SSH keys for PLC/RTU management"

echo ""
echo "[*] Lateral movement assessment complete"
echo "[*] Review findings for viable cross-zone paths"
```

### GOOSE Message Injection (Level 2 Attack)

GOOSE (Generic Object Oriented Substation Event) messages operate at Layer 2 and carry critical protection relay data in electrical substations. Because GOOSE operates at Ethernet Layer 2 with no authentication, it is a high-impact attack vector within Level 2.

```python
#!/usr/bin/env python3
"""GOOSE Message Analysis and Detection Tool.

Analyzes GOOSE traffic for security assessment of IEC 61850 substations.
This tool is for PASSIVE analysis only - injection would require
separate authorization and safety protocols.
"""

import struct
from datetime import datetime


GOOSE_ETHERTYPE = 0x88B8


def parse_goose_message(data):
    """Parse a GOOSE message from raw Ethernet frame."""
    if len(data) < 14:
        return None

    # Ethernet header
    dst_mac = data[0:6]
    src_mac = data[6:12]
    ethertype = struct.unpack("!H", data[12:14])[0]

    if ethertype != GOOSE_ETHERTYPE:
        return None

    # GOOSE PDU starts after Ethernet header
    goose_pdu = data[14:]

    try:
        # Parse GOOSE header fields (simplified)
        # APPID (2 bytes), Length (2 bytes), Reserved1 (2), Reserved2 (2)
        if len(goose_pdu) < 8:
            return None

        appid = struct.unpack("!H", goose_pdu[0:2])[0]
        goose_length = struct.unpack("!H", goose_pdu[2:4])[0]

        result = {
            "timestamp": datetime.now().isoformat(),
            "dst_mac": ":".join(f"{b:02x}" for b in dst_mac),
            "src_mac": ":".join(f"{b:02x}" for b in src_mac),
            "ethertype": f"0x{ethertype:04x}",
            "appid": appid,
            "goose_length": goose_length,
            "frame_size": len(data)
        }

        # Extract stNum and sqNum (state and sequence numbers)
        # These are critical for GOOSE security analysis
        # stNum increments on state change, sqNum increments on retransmission
        # An attacker would forge messages with incremented stNum
        print(f"  GOOSE Frame: src={result['src_mac']} "
              f"appid={result['appid']} len={result['goose_length']}")
        return result

    except Exception as e:
        print(f"  Error parsing GOOSE: {e}")
        return None


def monitor_goose(interface="eth0"):
    """Monitor for GOOSE messages on the specified interface."""
    print(f"[*] Monitoring GOOSE messages on {interface}")
    print(f"[*] GOOSE Ethertype: 0x{GOOSE_ETHERTYPE:04x}")
    print(f"[*] Press Ctrl+C to stop\n")

    # Use tcpdump to capture GOOSE frames
    import subprocess
    cmd = [
        "tcpdump", "-i", interface, "-nn",
        "-e",  # Print link-level header
        f"ether proto 0x{GOOSE_ETHERTYPE:04x}",
        "-c", "100"
    ]

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        goose_count = 0
        for line in proc.stdout:
            if "88b8" in line.lower() or "GOOSE" in line.upper():
                goose_count += 1
                print(f"[GOOSE #{goose_count}] {line.strip()}")

        print(f"\n[+] Captured {goose_count} GOOSE frames")

    except KeyboardInterrupt:
        print("\n[*] Monitoring stopped")


if __name__ == "__main__":
    import sys
    interface = sys.argv[1] if len(sys.argv) > 1 else "eth0"
    monitor_goose(interface)
```

## Hands-on Exercises

### Exercise 1: Purdue Model Network Mapping

**Objective**: Map an ICS lab environment to the Purdue Model, identify all level boundaries, and document weaknesses in segmentation.

**Setup**: Configure a multi-subnet lab with at least 4 segments representing Enterprise (10.0.0.0/24), DMZ (172.16.0.0/24), Operations (192.168.1.0/24), and Control (192.168.10.0/24). Deploy conpot honeypots as simulated PLCs in the Control segment.

**Tasks**:

1. Use the Purdue Protocol Mapper to analyze traffic across all segments:
   ```bash
   # Capture traffic from each segment (SPAN port or test VM in each zone)
   tcpdump -i eth0 -w enterprise.pcap -G 300 -W 1
   tcpdump -i eth1 -w control.pcap -G 300 -W 1

   # Map protocols to Purdue levels
   python3 purdue_mapper.py enterprise.pcap
   python3 purdue_mapper.py control.pcap
   ```

2. Test cross-boundary routing from each segment:
   ```bash
   # From Enterprise, test reachability to Control
   nmap -sS -p 502,102,44818 192.168.10.0/24 --open

   # From DMZ, test reachability to both IT and OT
   nmap -sS -p 502,102,44818,1433,4840 192.168.1.0/24 --open
   nmap -sS -p 502,102,44818,1433,4840 10.0.0.0/24 --open
   ```

3. Document all cross-zone paths found and map them to the Purdue Model diagram.

**Deliverables**: Purdue Model diagram with actual segmentation marked, list of cross-zone paths found, risk assessment for each path.

### Exercise 2: IT/OT Convergence Attack Chain

**Objective**: Simulate a complete attack chain exploiting IT/OT convergence weaknesses, from initial access in the IT zone to PLC interaction in the Control zone.

**Setup**: Use the lab from Exercise 1. Add a shared Active Directory server, a historian server in the DMZ, and configure at least one shared credential between IT and OT zones.

**Tasks**:

1. Start from the Enterprise segment and enumerate the DMZ:
   ```bash
   # Scan DMZ for services
   nmap -sV -p 22,80,443,1433,4840,3389 172.16.0.0/24

   # Test shared credentials against DMZ historian
   crackmapexec smb 172.16.0.0/24 -u operator -p Summer2024!
   ```

2. Pivot through the historian to reach the Operations zone:
   ```bash
   # From historian, enumerate OT zone
   # (Simulate by scanning from a test VM in the DMZ)
   nmap -sS -p 502,102,44818,4840 192.168.1.0/24 --open
   ```

3. From Operations, interact with Control-level devices:
   ```bash
   # Test Modbus access to PLCs
   python3 level3_to_2_pivot.py 192.168.10.10 modbus
   ```

4. Document the complete attack chain with all techniques used.

**Deliverables**: Attack chain diagram, evidence from each pivot step, written assessment of which Purdue boundaries failed and why.

## References

1. **ISA-95 / IEC 62264** - Enterprise-Control System Integration. The formal standard defining the Purdue Model levels and their interfaces, https://isa-95.com/

2. **IEC 62443** - Industrial Automation and Control Systems Security. Defines security levels, zones, and conduits for ICS network architecture.

3. **NIST SP 800-82 Rev. 3** - Guide to Operational Technology (OT) Security. Section on network architecture and the Purdue Model implementation guidance.

4. **MITRE ATT&ACK for ICS** - Lateral Movement and Impact tactics for ICS environments, https://attack.mitre.org/tactics/ICS/

5. **SANS ICS Security** - "Assessing OT Network Architecture" whitepaper series covering Purdue Model assessment methodology.

6. **Purdue Model Implementation Guide** - Cisco Industrial Networking documentation for Purdue Model network design, https://www.cisco.com/c/en/us/solutions/industrial-solutions/

7. **Dragos Year in Review Reports** - Annual analysis of ICS attack trends including IT/OT convergence attack paths observed in the wild.

8. **Claroty/Claroty Research** - Reports on ICS network architecture weaknesses and cross-zone vulnerabilities discovered in industrial environments.

9. **Booz Allen Hamilton ICS Threat Brief** - Analysis of state-sponsored ICS attack campaigns exploiting Purdue Model weaknesses, particularly DMZ bypass and lateral movement techniques.
