# ICS Incident Response and Forensic Evidence Collection Guide

## Introduction

Incident response in Industrial Control System (ICS) and SCADA environments differs fundamentally from traditional IT incident response. When an incident occurs in an OT (Operational Technology) environment, the immediate priority is maintaining safe process operation and preventing physical harm, not preserving digital evidence. This creates unique tensions between safety, operational continuity, and forensic investigation that require specialized procedures, tools, and training.

ICS incidents may involve unauthorized access to PLCs, manipulation of process setpoints, ransomware deployment on HMI systems, supply chain compromises of engineering workstations, or network-level attacks targeting industrial protocols such as Modbus, S7comm, DNP3, or EtherNet/IP. The convergence of IT and OT networks through digital transformation initiatives has expanded the attack surface, making ICS incident response a critical capability for organizations operating critical infrastructure, manufacturing plants, water treatment facilities, and energy distribution systems.

This guide provides a structured methodology for ICS incident detection, safe containment in operational environments, evidence collection that respects safety constraints, forensic analysis of ICS-specific artifacts, and recovery playbooks designed to restore safe operations. Every procedure is designed to be compatible with the safety-first philosophy governing OT environments and assumes an isolated lab or authorized production environment with explicit written permission.

**Objectives**: Establish ICS-specific incident detection capabilities, implement safe containment procedures that preserve process safety, collect forensic evidence without disrupting operations, analyze ICS artifacts (PCAP, PLC memory, HMI logs), and build recovery playbooks for common ICS incident scenarios.

## Part 1: ICS Incident Detection and Alerting

### Understanding Normal ICS Behavior

Effective incident detection begins with establishing baselines of normal ICS network behavior. Unlike IT environments where traffic patterns are diverse and bursty, ICS networks exhibit highly predictable communication patterns: periodic polling between masters and slaves, consistent register access patterns, and stable protocol distributions.

```python
#!/usr/bin/env python3
"""ICS Network Baseline Profiler - establishes normal traffic patterns."""

import subprocess
import json
import statistics
from datetime import datetime, timedelta
from collections import defaultdict

class ICSBaselineProfiler:
    """Build a statistical baseline of ICS network traffic patterns."""

    def __init__(self, interface, duration_seconds=3600):
        self.interface = interface
        self.duration = duration_seconds
        self.baseline = {
            "timestamp": datetime.now().isoformat(),
            "duration_seconds": duration_seconds,
            "protocol_distribution": defaultdict(int),
            "communication_pairs": defaultdict(int),
            "timing_stats": defaultdict(list),
            "anomaly_thresholds": {}
        }

    def capture_traffic(self):
        """Capture ICS traffic for baseline profiling."""
        ics_filter = (
            "port 502 or port 102 or port 44818 or port 4840 or "
            "port 20000 or udp port 47808 or ether proto 0x88b8"
        )
        output_file = f"/tmp/ics_baseline_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"

        cmd = [
            "tcpdump", "-i", self.interface, "-w", output_file,
            ics_filter, "-G", str(self.duration), "-W", "1", "-nn"
        ]
        print(f"[*] Capturing baseline traffic on {self.interface} for {self.duration}s...")
        print(f"[*] Output: {output_file}")
        return output_file

    def analyze_baseline(self, pcap_file):
        """Analyze captured traffic to establish baseline metrics."""
        # Extract protocol distribution
        cmd = [
            "tshark", "-r", pcap_file, "-T", "fields",
            "-e", "ip.src", "-e", "ip.dst", "-e", "tcp.dstport",
            "-e", "frame.time_delta"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        for line in result.stdout.strip().split("\n"):
            if not line.strip():
                continue
            fields = line.split("\t")
            if len(fields) >= 3:
                src, dst, port = fields[0], fields[1], fields[2]
                port_map = {
                    "502": "Modbus", "102": "S7comm",
                    "44818": "EtherNet/IP", "4840": "OPC UA",
                    "20000": "DNP3", "47808": "BACnet"
                }
                proto = port_map.get(port, f"Unknown({port})")
                self.baseline["protocol_distribution"][proto] += 1
                self.baseline["communication_pairs"][(src, dst)] += 1
                if len(fields) >= 4 and fields[3]:
                    try:
                        delta = float(fields[3])
                        self.baseline["timing_stats"][f"{src}->{dst}"].append(delta)
                    except ValueError:
                        pass

        # Calculate anomaly thresholds
        for pair, deltas in self.baseline["timing_stats"].items():
            if len(deltas) > 10:
                mean = statistics.mean(deltas)
                stdev = statistics.stdev(deltas)
                self.baseline["anomaly_thresholds"][pair] = {
                    "mean_interval_ms": round(mean * 1000, 2),
                    "stdev_ms": round(stdev * 1000, 2),
                    "upper_threshold_ms": round((mean + 3 * stdev) * 1000, 2),
                    "lower_threshold_ms": round(max(0, (mean - 3 * stdev)) * 1000, 2),
                    "sample_count": len(deltas)
                }

        return self.baseline

    def export_baseline(self, output_path):
        """Export baseline to JSON for comparison during incident analysis."""
        serializable = {
            "timestamp": self.baseline["timestamp"],
            "duration_seconds": self.baseline["duration_seconds"],
            "protocol_distribution": dict(self.baseline["protocol_distribution"]),
            "communication_pairs": {
                f"{k[0]}->{k[1]}": v
                for k, v in self.baseline["communication_pairs"].items()
            },
            "anomaly_thresholds": self.baseline["anomaly_thresholds"]
        }
        with open(output_path, "w") as f:
            json.dump(serializable, f, indent=2)
        print(f"[+] Baseline exported to {output_path}")


# Usage
if __name__ == "__main__":
    profiler = ICSBaselineProfiler(interface="eth0", duration_seconds=1800)
    pcap = profiler.capture_traffic()
    baseline = profiler.analyze_baseline(pcap)
    profiler.export_baseline("/opt/ics_baseline/baseline_normal.json")
```

### Real-Time Anomaly Detection

Once baselines are established, real-time monitoring can detect deviations that indicate potential incidents. The key indicators for ICS anomaly detection include unexpected communication pairs, new protocol usage, timing pattern changes, unauthorized function codes, and after-hours activity.

```python
#!/usr/bin/env python3
"""Real-time ICS anomaly detector comparing live traffic against baseline."""

import json
import subprocess
import sys
import time
from datetime import datetime
from collections import defaultdict

class ICSAnomalyDetector:
    """Monitor live ICS traffic and alert on baseline deviations."""

    SEVERITY_MAP = {
        "new_communication_pair": "HIGH",
        "unexpected_protocol": "MEDIUM",
        "timing_anomaly": "MEDIUM",
        "unauthorized_function_code": "CRITICAL",
        "new_device": "HIGH",
        "after_hours_activity": "LOW"
    }

    def __init__(self, baseline_path, interface="eth0"):
        with open(baseline_path) as f:
            self.baseline = json.load(f)
        self.interface = interface
        self.alerts = []
        self.known_pairs = set()
        for key in self.baseline.get("communication_pairs", {}):
            parts = key.split("->")
            self.known_pairs.add((parts[0], parts[1]))

    def start_monitoring(self):
        """Begin real-time monitoring of ICS traffic."""
        print(f"[*] Starting ICS anomaly detection on {self.interface}")
        print(f"[*] Baseline loaded: {len(self.known_pairs)} known communication pairs")

        ics_filter = (
            "port 502 or port 102 or port 44818 or port 4840 or "
            "port 20000 or udp port 47808"
        )
        cmd = [
            "tshark", "-i", self.interface, "-l", "-T", "fields",
            "-e", "ip.src", "-e", "ip.dst", "-e", "tcp.dstport",
            "-e", "modbus.funccode", "-e", "frame.time",
            "-e", "s7comm.header.rosctr", "-f", ics_filter
        ]

        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            for line in proc.stdout:
                self._analyze_packet(line.strip())
        except KeyboardInterrupt:
            print("\n[*] Monitoring stopped by user")
        finally:
            self._print_summary()

    def _analyze_packet(self, line):
        """Analyze a single packet against baseline."""
        fields = line.split("\t")
        if len(fields) < 3:
            return

        src, dst, port = fields[0], fields[1], fields[2]

        # Check for new communication pairs
        if (src, dst) not in self.known_pairs:
            severity = self.SEVERITY_MAP["new_communication_pair"]
            alert = {
                "timestamp": datetime.now().isoformat(),
                "severity": severity,
                "type": "new_communication_pair",
                "source": src,
                "destination": dst,
                "port": port,
                "message": f"New communication pair detected: {src} -> {dst} on port {port}"
            }
            self.alerts.append(alert)
            self._log_alert(alert)

        # Check for unauthorized Modbus function codes (write operations)
        if port == "502" and len(fields) > 3 and fields[3]:
            func_code = int(fields[3])
            if func_code in [5, 6, 15, 16]:  # Write operations
                severity = self.SEVERITY_MAP["unauthorized_function_code"]
                alert = {
                    "timestamp": datetime.now().isoformat(),
                    "severity": severity,
                    "type": "unauthorized_function_code",
                    "source": src,
                    "function_code": func_code,
                    "message": f"Modbus write function code {func_code} from {src}"
                }
                self.alerts.append(alert)
                self._log_alert(alert)

        # Check for S7comm CPU stop commands
        if port == "102" and len(fields) > 4 and fields[4]:
            rosctr = int(fields[4])
            if rosctr == 0x28:  # PLC Control (includes CPU Stop)
                alert = {
                    "timestamp": datetime.now().isoformat(),
                    "severity": "CRITICAL",
                    "type": "s7comm_cpu_stop",
                    "source": src,
                    "destination": dst,
                    "message": f"S7comm PLC control command from {src} to {dst}"
                }
                self.alerts.append(alert)
                self._log_alert(alert)

    def _log_alert(self, alert):
        """Output alert to console and log file."""
        severity = alert["severity"]
        msg = alert["message"]
        prefix = {
            "CRITICAL": "[!!!]",
            "HIGH": "[!! ]",
            "MEDIUM": "[!  ]",
            "LOW": "[.  ]"
        }.get(severity, "[?  ]")
        print(f"{prefix} {severity}: {msg}")

        with open("/var/log/ics_anomaly_detector.log", "a") as f:
            f.write(json.dumps(alert) + "\n")

    def _print_summary(self):
        """Print monitoring session summary."""
        print(f"\n{'='*60}")
        print(f"ICS Anomaly Detection Summary")
        print(f"Total alerts: {len(self.alerts)}")
        by_severity = defaultdict(int)
        for a in self.alerts:
            by_severity[a["severity"]] += 1
        for sev, count in sorted(by_severity.items()):
            print(f"  {sev}: {count}")
        print(f"{'='*60}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 ics_anomaly_detector.py <baseline.json> [interface]")
        sys.exit(1)
    detector = ICSAnomalyDetector(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "eth0")
    detector.start_monitoring()
```

## Part 2: Safe Containment in OT Environments

### Containment Principles for ICS

Containment in ICS environments must balance security objectives with operational safety. Unlike IT environments where infected systems can be immediately isolated, ICS containment must consider:

1. **Process safety**: Network isolation must not disable safety instrumented systems (SIS) or prevent emergency shutdown capability.
2. **Process continuity**: Some processes cannot be safely stopped without following specific shutdown sequences (chemical reactions, power generation, continuous manufacturing).
3. **Graceful degradation**: Containment actions should maintain the minimum required communication paths for safe operation.
4. **Operator awareness**: Control room operators must be informed before any network changes and must retain ability to manually control processes.

### Containment Decision Matrix

```python
#!/usr/bin/env python3
"""ICS Incident Containment Decision Framework."""

CONTAINMENT_ACTIONS = {
    "network_isolation_it_ot": {
        "description": "Isolate IT/OT boundary at the industrial DMZ",
        "safety_impact": "LOW",
        "operational_impact": "LOW",
        "prerequisites": ["Dual firewall IDMZ architecture in place"],
        "reversible": True,
        "commands": [
            "# On IT-side firewall - block all traffic to OT zone",
            "iptables -A INPUT -s 10.0.0.0/8 -d 192.168.0.0/16 -j DROP",
            "# On OT-side firewall - block all traffic from IT zone",
            "iptables -A INPUT -s 10.0.0.0/8 -d 192.168.0.0/16 -j DROP",
            "# Maintain DMZ services (historian replication, patch management)",
            "# Do NOT block DMZ-to-OT historian replication if process monitoring depends on it"
        ]
    },
    "device_level_isolation": {
        "description": "Isolate specific compromised device at network level",
        "safety_impact": "MEDIUM",
        "operational_impact": "MEDIUM",
        "prerequisites": [
            "Verified the device is not a safety controller",
            "Backup communication path exists for operators",
            "Control room notified and prepared"
        ],
        "reversible": True,
        "commands": [
            "# Isolate compromised HMI from PLC network",
            "iptables -A FORWARD -s <compromised_hmi_ip> -d <plc_subnet> -j DROP",
            "# Allow management access for forensic investigation",
            "iptables -A INPUT -s <forensic_workstation_ip> -d <compromised_hmi_ip> -j ACCEPT",
            "# Block all other access to compromised device",
            "iptables -A INPUT -d <compromised_hmi_ip> -j DROP"
        ]
    },
    "protocol_filtering": {
        "description": "Filter specific malicious protocol commands while maintaining normal operations",
        "safety_impact": "LOW",
        "operational_impact": "LOW",
        "prerequisites": [
            "Protocol-aware firewall in place",
            "Known malicious function codes or command patterns identified"
        ],
        "reversible": True,
        "commands": [
            "# Block Modbus write operations from unauthorized sources",
            "# Using iptables with string matching for Modbus FC 5,6,15,16",
            "iptables -A FORWARD -p tcp --dport 502 -s <unauthorized_ip> -j DROP",
            "# More granular: use a Modbus-aware proxy to filter specific function codes",
            "# This requires a protocol-aware gateway or SCADA firewall"
        ]
    },
    "emergency_shutdown": {
        "description": "Initiate controlled process shutdown through operator procedures",
        "safety_impact": "HIGH",
        "operational_impact": "CRITICAL",
        "prerequisites": [
            "Incident poses imminent physical safety risk",
            "Control room operator authorization obtained",
            "Emergency procedures documented and rehearsed"
        ],
        "reversible": False,
        "commands": [
            "# This is NOT a network command - it is a procedure",
            "# 1. Notify control room operator immediately",
            "# 2. Operator initiates controlled shutdown sequence",
            "# 3. Network team isolates all OT network segments",
            "# 4. Maintain power to safety systems (SIS must remain active)",
            "# 5. Physical team verifies safe state of process equipment",
            "# 6. Document all actions with timestamps for post-incident review"
        ]
    }
}


def select_containment(incident_type, affected_zone, safety_risk):
    """Select appropriate containment action based on incident characteristics."""
    if safety_risk == "IMMINENT":
        return CONTAINMENT_ACTIONS["emergency_shutdown"]

    if incident_type in ["ransomware", "wiper", "destructive"]:
        if affected_zone in ["IT", "DMZ"]:
            return CONTAINMENT_ACTIONS["network_isolation_it_ot"]
        elif affected_zone == "OT":
            return CONTAINMENT_ACTIONS["device_level_isolation"]

    if incident_type in ["unauthorized_access", "lateral_movement"]:
        return CONTAINMENT_ACTIONS["protocol_filtering"]

    return CONTAINMENT_ACTIONS["network_isolation_it_ot"]


# Example usage during incident
if __name__ == "__main__":
    print("ICS Containment Decision Framework")
    print("=" * 50)

    # Example: ransomware detected on HMI in operations zone
    action = select_containment(
        incident_type="ransomware",
        affected_zone="OT",
        safety_risk="MODERATE"
    )
    print(f"\nScenario: Ransomware on HMI in OT zone")
    print(f"Recommended Action: {action['description']}")
    print(f"Safety Impact: {action['safety_impact']}")
    print(f"Operational Impact: {action['operational_impact']}")
    print(f"Prerequisites:")
    for prereq in action["prerequisites"]:
        print(f"  - {prereq}")
    print(f"\nCommands:")
    for cmd in action["commands"]:
        print(f"  {cmd}")
```

## Part 3: Forensic Evidence Collection in SCADA Environments

### Evidence Collection Priorities

Forensic evidence collection in ICS environments must follow a strict priority order: (1) preserve volatile network traffic, (2) capture running process state, (3) image memory of compromised systems, (4) create disk images, and (5) collect logs from all devices. Throughout this process, maintain awareness that some collection actions may impact process operations.

```bash
#!/bin/bash
# ICS Forensic Evidence Collection Script
# Designed for minimal operational impact during evidence gathering

set -euo pipefail

EVIDENCE_DIR="/opt/ics_evidence/$(date +%Y%m%d_%H%M%S)"
INTERFACE="${1:-eth0}"
CASE_NUMBER="${2:-ICS-INC-$(date +%Y%m%d-%H%M%S)}"

mkdir -p "${EVIDENCE_DIR}/network" "${EVIDENCE_DIR}/memory" \
         "${EVIDENCE_DIR}/disk" "${EVIDENCE_DIR}/logs" \
         "${EVIDENCE_DIR}/analysis"

echo "[*] ICS Forensic Evidence Collection"
echo "[*] Case: ${CASE_NUMBER}"
echo "[*] Evidence directory: ${EVIDENCE_DIR}"
echo "[*] Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Step 1: Capture volatile network traffic (HIGHEST PRIORITY)
echo "[1/6] Capturing network traffic on ${INTERFACE}..."
tcpdump -i "${INTERFACE}" -w "${EVIDENCE_DIR}/network/full_capture.pcap" \
  -G 3600 -W 4 -Z root -nn \
  'port 502 or port 102 or port 44818 or port 4840 or port 20000 or udp port 47808' &
TCPDUMP_PID=$!
sleep 60  # Capture 1 minute minimum before moving to next steps
echo "[+] Network capture started (PID: ${TCPDUMP_PID})"

# Step 2: Capture ARP tables and routing information
echo "[2/6] Capturing network state..."
arp -a > "${EVIDENCE_DIR}/network/arp_table.txt" 2>&1
ip route show > "${EVIDENCE_DIR}/network/routing_table.txt" 2>&1
ip neigh show > "${EVIDENCE_DIR}/network/neighbor_table.txt" 2>&1
iptables-save > "${EVIDENCE_DIR}/network/firewall_rules.txt" 2>&1
cat /proc/net/tcp > "${EVIDENCE_DIR}/network/tcp_connections.txt" 2>&1
ss -tunap > "${EVIDENCE_DIR}/network/active_connections.txt" 2>&1

# Step 3: Capture running processes and services
echo "[3/6] Capturing process state..."
ps auxww > "${EVIDENCE_DIR}/memory/process_list.txt" 2>&1
systemctl list-units --type=service --state=running > "${EVIDENCE_DIR}/memory/running_services.txt" 2>&1
crontab -l > "${EVIDENCE_DIR}/memory/crontab.txt" 2>&1
cat /etc/crontab > "${EVIDENCE_DIR}/memory/etc_crontab.txt" 2>&1
ls -la /tmp/ > "${EVIDENCE_DIR}/memory/tmp_contents.txt" 2>&1

# Step 4: Collect ICS-specific logs
echo "[4/6] Collecting ICS application logs..."
declare -A LOG_SOURCES=(
    ["/var/log/syslog"]="system_syslog"
    ["/var/log/auth.log"]="authentication_log"
    ["/var/log/ics_monitor.log"]="ics_monitor"
    ["/opt/conpot/log/conpot.log"]="conpot_honeypot"
    ["/var/log/opcua/server.log"]="opcua_server"
    ["/var/log/modbus/proxy.log"]="modbus_proxy"
)

for src in "${!LOG_SOURCES[@]}"; do
    if [ -f "${src}" ]; then
        cp -p "${src}" "${EVIDENCE_DIR}/logs/${LOG_SOURCES[$src]}"
        echo "[+] Collected: ${src}"
    fi
done

# Step 5: Create ICS traffic statistics
echo "[5/6] Generating traffic statistics..."
tshark -r "${EVIDENCE_DIR}/network/full_capture.pcap" \
  -q -z io,stat,1 2>/dev/null > "${EVIDENCE_DIR}/analysis/traffic_stats.txt" || true

tshark -r "${EVIDENCE_DIR}/network/full_capture.pcap" \
  -q -z conv,tcp 2>/dev/null > "${EVIDENCE_DIR}/analysis/tcp_conversations.txt" || true

tshark -r "${EVIDENCE_DIR}/network/full_capture.pcap" \
  -q -z endpoints,tcp 2>/dev/null > "${EVIDENCE_DIR}/analysis/tcp_endpoints.txt" || true

# Step 6: Generate evidence manifest and hashes
echo "[6/6] Generating evidence manifest..."
cd "${EVIDENCE_DIR}"
find . -type f -exec sha256sum {} \; > manifest_sha256.txt
find . -type f -exec md5sum {} \; > manifest_md5.txt

echo "CASE_NUMBER=${CASE_NUMBER}" > evidence_manifest.txt
echo "COLLECTION_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> evidence_manifest.txt
echo "COLLECTOR=$(whoami)@$(hostname)" >> evidence_manifest.txt
echo "INTERFACE=${INTERFACE}" >> evidence_manifest.txt
echo "FILES_COLLECTED=$(find . -type f | wc -l)" >> evidence_manifest.txt
echo "TOTAL_SIZE=$(du -sh . | cut -f1)" >> evidence_manifest.txt

echo ""
echo "[+] Evidence collection complete"
echo "[+] Files collected: $(find . -type f | wc -l)"
echo "[+] Total size: $(du -sh . | cut -f1)"
echo "[+] Evidence directory: ${EVIDENCE_DIR}"
echo "[+] Network capture still running (PID: ${TCPDUMP_PID})"
echo "[*] Stop capture when ready: kill ${TCPDUMP_PID}"
```

### PLC Memory Acquisition

Acquiring PLC memory for forensic analysis requires protocol-specific approaches. Unlike general-purpose computers, PLCs do not have operating systems in the traditional sense and cannot run standard forensic tools. Memory must be extracted through the PLC's native protocol interface.

```python
#!/usr/bin/env python3
"""S7 PLC Memory Acquisition for Forensic Analysis.

Extracts memory blocks from Siemens S7 PLCs via S7comm protocol
for forensic investigation. This script performs READ operations only.
"""

import socket
import struct
import sys
import hashlib
import json
from datetime import datetime


class S7ForensicAcquisition:
    """Acquire memory from Siemens S7 PLCs for forensic analysis."""

    def __init__(self, target_ip, port=102):
        self.target_ip = target_ip
        self.port = port
        self.session = None
        self.pdu_size = 0
        self.evidence_log = []

    def connect(self):
        """Establish S7comm session with target PLC."""
        self.session = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.session.settimeout(10)
        self.session.connect((self.target_ip, self.port))

        # COTP Connection Request
        cotp_cr = bytes([0x03, 0x00, 0x00, 0x16, 0x11, 0xe0,
                         0x00, 0x00, 0x00, 0x01, 0x00, 0xc1,
                         0x02, 0x01, 0x00, 0xc2, 0x02, 0x01,
                         0x02, 0xc0, 0x01, 0x09])
        self.session.send(cotp_cr)
        resp = self.session.recv(1024)

        # S7 Setup Communication
        s7_setup = bytes([0x03, 0x00, 0x00, 0x19, 0x02, 0xf0, 0x80,
                          0x32, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x08, 0x00, 0x00, 0xf0, 0x00, 0x00, 0x01,
                          0x00, 0x01, 0x03, 0xc0])
        self.session.send(s7_setup)
        resp = self.session.recv(1024)

        if len(resp) > 20:
            self.pdu_size = struct.unpack(">H", resp[18:20])[0]
            self._log_evidence("session_established", f"PDU size: {self.pdu_size}")
        return True

    def read_szl(self, szl_id, index=0x0000):
        """Read System Status List (SZL) for device information."""
        # SZL Read request
        szl_req = self._build_s7_read_szl(szl_id, index)
        self.session.send(szl_req)
        resp = self.session.recv(4096)
        return resp

    def _build_s7_read_szl(self, szl_id, index):
        """Build SZL read request packet."""
        return bytes([
            0x03, 0x00, 0x00, 0x21,  # TPKT header
            0x02, 0xf0, 0x80,        # COTP DT
            0x32, 0x01, 0x00, 0x00,  # S7 header: Job
            0x00, 0x00, 0x00, 0x0e,  # Parameter
            0x00, 0x00, 0x00, 0x00,  # Data
            0x04,                     # Function: Read Var
            0x01,                     # Item count
            0x12, 0x04, 0x11, 0x44,  # SZL item
            0x01, 0x00,
            (szl_id >> 8) & 0xff, szl_id & 0xff,
            (index >> 8) & 0xff, index & 0xff
        ])

    def read_db_block(self, db_number, start, size):
        """Read data from a specific DB block."""
        # Build S7 Read Var request for DB area
        items = 1
        area_code = 0x84  # DB area
        max_pdu = min(self.pdu_size - 28, size) if self.pdu_size > 28 else 222

        packet = bytearray([
            0x03, 0x00, 0x00, 0x1f,  # TPKT (length updated below)
            0x02, 0xf0, 0x80,        # COTP DT
            0x32, 0x01, 0x00, 0x00,  # S7: Job
            0x00, 0x00, 0x00, 0x0c,  # Parameter length
            0x00, 0x00, 0x00, 0x00,  # Data length
            0x04,                     # Function: Read Var
            0x01,                     # Item count
            0x12, 0x0a, 0x10,        # Var specification
            0x04,                     # Byte size
            0x00, 0x08,               # Length in bits (placeholder)
            area_code,                # Area: DB
            (db_number >> 8) & 0xff, db_number & 0xff,
            (start >> 16) & 0xff, (start >> 8) & 0xff, start & 0xff
        ])

        # Update length fields
        total_len = len(packet)
        struct.pack_into(">H", packet, 2, total_len)
        struct.pack_into(">H", packet, 24, max_pdu * 8)  # Length in bits

        self.session.send(bytes(packet))
        resp = self.session.recv(8192)
        return resp

    def acquire_device_info(self):
        """Acquire device identification for forensic record."""
        # Read SZL 0x0011 - Module Identification
        info_resp = self.read_szl(0x0011)
        # Read SZL 0x001C - Component Identification
        comp_resp = self.read_szl(0x001C)

        device_info = {
            "target_ip": self.target_ip,
            "acquisition_time": datetime.now().isoformat(),
            "pdu_size": self.pdu_size,
            "raw_szl_0011_length": len(info_resp),
            "raw_szl_001c_length": len(comp_resp)
        }

        self._log_evidence("device_info_acquired", json.dumps(device_info))
        return device_info

    def _log_evidence(self, action, details):
        """Log all forensic actions with timestamps."""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "details": details
        }
        self.evidence_log.append(entry)

    def export_forensic_report(self, output_path):
        """Export complete forensic acquisition log."""
        report = {
            "acquisition_summary": {
                "target": self.target_ip,
                "timestamp": datetime.now().isoformat(),
                "total_actions": len(self.evidence_log)
            },
            "evidence_log": self.evidence_log
        }
        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)
        print(f"[+] Forensic report exported to {output_path}")

    def close(self):
        """Close the session."""
        if self.session:
            self.session.close()
            self._log_evidence("session_closed", "Normal disconnect")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 s7_forensic_acquire.py <plc_ip> [output_dir]")
        sys.exit(1)

    target = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "/opt/ics_evidence"

    print(f"[*] S7 PLC Forensic Acquisition - Target: {target}")
    acq = S7ForensicAcquisition(target)

    try:
        acq.connect()
        device_info = acq.acquire_device_info()
        print(f"[+] Device info: {json.dumps(device_info, indent=2)}")

        # Read DB blocks for forensic evidence
        for db_num in [1, 2, 3]:  # Common DB blocks
            print(f"[*] Reading DB{db_num}...")
            data = acq.read_db_block(db_num, 0, 222)
            # Calculate hash of raw response for integrity verification
            data_hash = hashlib.sha256(data).hexdigest()
            acq._log_evidence(f"db{db_num}_read", f"sha256={data_hash}, length={len(data)}")

            # Save raw data
            evidence_file = f"{output_dir}/s7_db{db_num}_{target.replace('.', '_')}.bin"
            with open(evidence_file, "wb") as f:
                f.write(data)
            print(f"[+] DB{db_num} saved: {evidence_file} (hash: {data_hash[:16]}...)")

    except Exception as e:
        print(f"[!] Error during acquisition: {e}")
        acq._log_evidence("error", str(e))
    finally:
        acq.export_forensic_report(f"{output_dir}/s7_acquisition_report_{target.replace('.', '_')}.json")
        acq.close()
```

## Part 4: ICS Forensic Analysis Techniques

### Protocol-Aware PCAP Analysis

Standard PCAP analysis tools may not decode ICS protocols effectively. Protocol-aware analysis extracts ICS-specific information such as Modbus function codes, register values, and device communication patterns that reveal attack timelines.

```python
#!/usr/bin/env python3
"""ICS Protocol-Aware PCAP Analyzer for forensic investigation."""

import subprocess
import json
from collections import defaultdict
from datetime import datetime


class ICSForensicAnalyzer:
    """Analyze captured ICS traffic for forensic evidence of attacks."""

    MODBUS_FUNC_NAMES = {
        1: "Read Coils", 2: "Read Discrete Inputs",
        3: "Read Holding Registers", 4: "Read Input Registers",
        5: "Write Single Coil", 6: "Write Single Register",
        15: "Write Multiple Coils", 16: "Write Multiple Registers",
        43: "Read Device Identification",
        0x80: "Exception Response", 0x81: "Exception Response",
        0x82: "Exception Response", 0x83: "Exception Response"
    }

    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.findings = []
        self.timeline = []

    def extract_modbus_sessions(self):
        """Extract and analyze all Modbus TCP sessions."""
        print("[*] Extracting Modbus sessions...")

        cmd = [
            "tshark", "-r", self.pcap_file,
            "-Y", "modbus",
            "-T", "fields",
            "-e", "frame.time_relative",
            "-e", "ip.src", "-e", "ip.dst",
            "-e", "modbus.transactionid",
            "-e", "modbus.unitid",
            "-e", "modbus.funccode",
            "-e", "modbus.regnum16",
            "-e", "modbus.regval_uint16",
            "-e", "frame.len"
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        sessions = []

        for line in result.stdout.strip().split("\n"):
            fields = line.split("\t")
            if len(fields) >= 5:
                try:
                    entry = {
                        "time": float(fields[0]),
                        "src": fields[1],
                        "dst": fields[2],
                        "transaction_id": int(fields[3], 16) if fields[3] else 0,
                        "unit_id": int(fields[4], 16) if fields[4] else 0,
                        "func_code": int(fields[5], 16) if fields[5] else 0,
                        "func_name": self.MODBUS_FUNC_NAMES.get(
                            int(fields[5], 16) if fields[5] else 0, "Unknown"
                        )
                    }
                    sessions.append(entry)
                except (ValueError, IndexError):
                    continue

        print(f"[+] Extracted {len(sessions)} Modbus frames")
        return sessions

    def detect_anomalous_writes(self, sessions):
        """Detect unauthorized or anomalous write operations."""
        write_fcs = {5, 6, 15, 16}
        writes = [s for s in sessions if s["func_code"] in write_fcs]

        if not writes:
            print("[+] No Modbus write operations detected")
            return []

        print(f"[!] {len(writes)} Modbus write operations detected")
        self.findings.append({
            "type": "modbus_write_operations",
            "severity": "HIGH",
            "count": len(writes),
            "sources": list(set(w["src"] for w in writes)),
            "targets": list(set(w["dst"] for w in writes)),
            "details": [
                {
                    "time": w["time"],
                    "source": w["src"],
                    "target": w["dst"],
                    "function": w["func_name"],
                    "unit_id": w["unit_id"]
                }
                for w in writes[:20]  # Limit detail output
            ]
        })

        return writes

    def build_attack_timeline(self, sessions):
        """Build chronological timeline of suspicious ICS activities."""
        suspicious_events = []

        for s in sessions:
            fc = s["func_code"]
            # Flag all write operations
            if fc in [5, 6, 15, 16]:
                suspicious_events.append({
                    "time": s["time"],
                    "event": f"Modbus {self.MODBUS_FUNC_NAMES.get(fc, f'FC{fc}')}",
                    "source": s["src"],
                    "target": s["dst"],
                    "severity": "HIGH"
                })
            # Flag exception responses (potential scanning/probing)
            if fc >= 0x80:
                suspicious_events.append({
                    "time": s["time"],
                    "event": f"Modbus Exception (code {fc & 0x7f})",
                    "source": s["src"],
                    "target": s["dst"],
                    "severity": "MEDIUM"
                })
            # Flag device identification requests (reconnaissance)
            if fc == 43:
                suspicious_events.append({
                    "time": s["time"],
                    "event": "Modbus Device Identification (reconnaissance)",
                    "source": s["src"],
                    "target": s["dst"],
                    "severity": "LOW"
                })

        # Sort by time
        suspicious_events.sort(key=lambda x: x["time"])
        self.timeline = suspicious_events
        return suspicious_events

    def generate_forensic_report(self, output_path):
        """Generate comprehensive forensic analysis report."""
        report = {
            "report_metadata": {
                "generated": datetime.now().isoformat(),
                "source_pcap": self.pcap_file,
                "finding_count": len(self.findings),
                "timeline_events": len(self.timeline)
            },
            "findings": self.findings,
            "attack_timeline": self.timeline,
            "recommendations": [
                "Isolate affected devices based on attack timeline",
                "Preserve all PCAP evidence with cryptographic hashes",
                "Review Modbus write operations against authorized source list",
                "Check PLC register values against expected process parameters",
                "Examine exception responses for scanning patterns"
            ]
        }

        with open(output_path, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"[+] Forensic report generated: {output_path}")
        return report


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 ics_forensic_analyzer.py <pcap_file> [output.json]")
        sys.exit(1)

    pcap = sys.argv[1]
    output = sys.argv[2] if len(sys.argv) > 2 else "ics_forensic_report.json"

    analyzer = ICSForensicAnalyzer(pcap)
    sessions = analyzer.extract_modbus_sessions()
    writes = analyzer.detect_anomalous_writes(sessions)
    timeline = analyzer.build_attack_timeline(sessions)

    print(f"\n[*] Timeline: {len(timeline)} suspicious events")
    for event in timeline[:10]:
        print(f"  {event['time']:.3f}s [{event['severity']}] {event['event']} "
              f"{event['source']} -> {event['target']}")

    analyzer.generate_forensic_report(output)
```

## Part 5: Recovery Playbooks for ICS Incidents

### Recovery Phase Overview

Recovery in ICS environments follows a structured approach: (1) verify the threat is eliminated, (2) restore from known-good configurations, (3) validate system operation, (4) restore network connectivity, and (5) monitor for reinfection. Each phase has ICS-specific considerations.

```python
#!/usr/bin/env python3
"""ICS Incident Recovery Playbook Runner.

Provides structured recovery procedures for common ICS incident types.
"""

RECOVERY_PLAYBOOKS = {
    "hmi_compromise": {
        "name": "HMI System Compromise Recovery",
        "description": "Recovery procedure for compromised HMI/operator workstation",
        "phases": [
            {
                "phase": 1,
                "name": "Threat Elimination",
                "steps": [
                    "Isolate compromised HMI from all networks (IT and OT)",
                    "Capture forensic image of HMI disk before any modifications",
                    "Dump HMI memory for forensic analysis",
                    "Document all running processes and network connections",
                    "Physically disconnect or disable wireless interfaces"
                ]
            },
            {
                "phase": 2,
                "name": "Clean System Restoration",
                "steps": [
                    "Restore HMI from known-good backup (verified clean image)",
                    "If no clean backup exists, rebuild from vendor installation media",
                    "Apply all security patches and firmware updates during rebuild",
                    "Install endpoint detection and response (EDR) agent",
                    "Configure application whitelisting for HMI application binaries"
                ]
            },
            {
                "phase": 3,
                "name": "Configuration Verification",
                "steps": [
                    "Verify HMI project file integrity against engineering workstation copy",
                    "Confirm all PLC communication addresses and register mappings",
                    "Verify OPC UA or DDE server configurations if used",
                    "Test HMI display functions against simulation or lab environment",
                    "Validate alarm and notification configurations"
                ]
            },
            {
                "phase": 4,
                "name": "Controlled Reconnection",
                "steps": [
                    "Connect HMI to OT network segment only (no IT connectivity)",
                    "Monitor all traffic from HMI for 30 minutes before operator use",
                    "Verify PLC polling resumes with correct timing patterns",
                    "Confirm operator can view and interact with process displays",
                    "Enable additional logging on all firewall and switch ports near HMI"
                ]
            },
            {
                "phase": 5,
                "name": "Post-Recovery Monitoring",
                "steps": [
                    "Maintain enhanced monitoring for 72 hours minimum",
                    "Review all HMI network connections hourly for first 24 hours",
                    "Compare process variable readings with physical measurements",
                    "Brief operators on incident details and indicators to watch for",
                    "Schedule follow-up forensic analysis of captured evidence"
                ]
            }
        ]
    },
    "plc_unauthorized_access": {
        "name": "PLC Unauthorized Access Recovery",
        "description": "Recovery procedure for PLC with suspected unauthorized access or modification",
        "phases": [
            {
                "phase": 1,
                "name": "Impact Assessment",
                "steps": [
                    "Identify which PLCs were accessed and from which sources",
                    "Determine if program blocks were read, modified, or downloaded",
                    "Check PLC diagnostic buffers for error entries during incident window",
                    "Verify current running program matches authorized version",
                    "Compare current register values against expected process state"
                ]
            },
            {
                "phase": 2,
                "name": "Safe PLC Restoration",
                "steps": [
                    "Ensure process is in a safe state or under manual control",
                    "Download verified program backup to PLC from engineering workstation",
                    "Verify PLC enters RUN mode without faults after program restore",
                    "Confirm all I/O modules are communicating correctly",
                    "Test safety instrumented functions (if in lab environment)"
                ]
            },
            {
                "phase": 3,
                "name": "Access Control Hardening",
                "steps": [
                    "Enable S7comm password protection (Siemens) or equivalent",
                    "Configure PLC communication access control lists if supported",
                    "Implement protocol-aware firewall rules restricting PLC access",
                    "Remove any unauthorized user accounts or access methods",
                    "Enable PLC event logging if supported by firmware version"
                ]
            },
            {
                "phase": 4,
                "name": "Validation and Return to Service",
                "steps": [
                    "Perform controlled process test with operator oversight",
                    "Monitor PLC communication patterns against baseline for anomalies",
                    "Verify process variables match physical measurements",
                    "Document all changes made during recovery for audit trail",
                    "Update asset inventory with new firmware versions and configurations"
                ]
            }
        ]
    },
    "network_intrusion_ot": {
        "name": "OT Network Intrusion Recovery",
        "description": "Recovery procedure for network-level intrusion into OT environment",
        "phases": [
            {
                "phase": 1,
                "name": "Scope Containment",
                "steps": [
                    "Identify all network segments affected by intrusion",
                    "Map lateral movement paths using forensic evidence",
                    "List all devices that communicated with known-compromised systems",
                    "Verify industrial DMZ integrity and data diode function",
                    "Check for persistent access mechanisms (rogue devices, backdoor scripts)"
                ]
            },
            {
                "phase": 2,
                "name": "Network Infrastructure Hardening",
                "steps": [
                    "Reset all management credentials on switches, routers, and firewalls",
                    "Update firmware on network infrastructure devices",
                    "Verify and strengthen VLAN segmentation between Purdue levels",
                    "Implement or verify port security on all OT switch ports",
                    "Deploy or update network intrusion detection rules for ICS protocols"
                ]
            },
            {
                "phase": 3,
                "name": "Device-by-Device Verification",
                "steps": [
                    "For each device in affected segments, verify configuration integrity",
                    "Compare running configurations against known-good baselines",
                    "Check for unauthorized user accounts on all HMIs and engineering stations",
                    "Verify PLC programs match authorized versions from version control",
                    "Scan for unauthorized wireless access points in OT zones"
                ]
            },
            {
                "phase": 4,
                "name": "Incremental Reconnection",
                "steps": [
                    "Reconnect OT network segments one at a time, starting with field level",
                    "Monitor each segment for 2 hours before reconnecting the next",
                    "Verify normal communication patterns resume after each reconnection",
                    "Confirm no unexpected cross-zone traffic after full reconnection",
                    "Restore vendor remote access only through hardened DMZ paths"
                ]
            }
        ]
    }
}


def run_playbook(incident_type, output_file=None):
    """Execute a recovery playbook and generate step-by-step guide."""
    playbook = RECOVERY_PLAYBOOKS.get(incident_type)
    if not playbook:
        print(f"[!] No playbook found for: {incident_type}")
        print(f"Available playbooks: {', '.join(RECOVERY_PLAYBOOKS.keys())}")
        return

    print(f"\n{'='*70}")
    print(f"RECOVERY PLAYBOOK: {playbook['name']}")
    print(f"Description: {playbook['description']}")
    print(f"{'='*70}")

    total_steps = 0
    for phase in playbook["phases"]:
        print(f"\n--- Phase {phase['phase']}: {phase['name']} ---")
        for i, step in enumerate(phase["steps"], 1):
            total_steps += 1
            print(f"  {phase['phase']}.{i} [ ] {step}")

    print(f"\n{'='*70}")
    print(f"Total steps: {total_steps}")
    print(f"Phases: {len(playbook['phases'])}")
    print(f"{'='*70}")

    if output_file:
        with open(output_file, "w") as f:
            json.dump(playbook, f, indent=2)
        print(f"[+] Playbook exported to {output_file}")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        run_playbook(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
    else:
        print("Available ICS Recovery Playbooks:")
        for key, pb in RECOVERY_PLAYBOOKS.items():
            phases = len(pb["phases"])
            steps = sum(len(p["steps"]) for p in pb["phases"])
            print(f"  {key}: {pb['name']} ({phases} phases, {steps} steps)")
        print(f"\nUsage: python3 ics_recovery_playbook.py <playbook_type> [output.json]")
```

## Hands-on Exercises

### Exercise 1: ICS Incident Detection and Triage

**Objective**: Build a complete ICS incident detection pipeline using baseline profiling and real-time anomaly detection.

**Setup**: Configure a lab environment with at least one Modbus TCP device (use a Modbus simulator or conpot honeypot) and generate baseline traffic followed by simulated attack traffic.

**Tasks**:

1. Deploy conpot as a Modbus honeypot to simulate a target ICS environment:
   ```bash
   # Start conpot with Modbus template
   conpot -f --template modbus -l WARN

   # In another terminal, generate baseline Modbus polling traffic
   # Using mbpoll to simulate normal HMI polling behavior
   mbpoll -t <conpot_ip> -p 502 -r 0 -c 10 -1 -0 3
   ```

2. Capture baseline traffic and build a traffic profile:
   ```bash
   # Capture 15 minutes of baseline traffic
   tcpdump -i eth0 -w baseline.pcap 'port 502' -G 900 -W 1

   # Analyze baseline patterns
   tshark -r baseline.pcap -Y "modbus" -T fields \
     -e ip.src -e ip.dst -e modbus.funccode | sort | uniq -c | sort -rn
   ```

3. Generate simulated attack traffic:
   ```bash
   # Simulate unauthorized write operations
   python3 -c "
   from pyModbusTCP.client import ModbusClient
   c = ModbusClient(host='<conpot_ip>', port=502, auto_open=True)
   # Normal read
   print('Normal read:', c.read_holding_registers(0, 10))
   # Simulated attack: unauthorized write
   result = c.write_single_register(0, 9999)
   print('Write result:', result)
   c.close()
   "
   ```

4. Detect the simulated attack using the anomaly detection script from Part 1.

**Deliverables**: Baseline profile JSON, attack detection log, written analysis of detection gaps and improvements.

### Exercise 2: Forensic Evidence Collection and Analysis

**Objective**: Perform complete forensic evidence collection and analysis on a simulated ICS incident.

**Setup**: Use the PCAP file from Exercise 1 that contains both baseline and attack traffic. You will also need access to a Siemens S7 PLC simulator or conpot with the S7comm template.

**Tasks**:

1. Run the forensic evidence collection script against the captured PCAP:
   ```bash
   # Analyze the PCAP for Modbus anomalies
   python3 ics_forensic_analyzer.py attack_capture.pcap forensic_report.json
   ```

2. Manually identify the attack timeline using tshark filters:
   ```bash
   # Find all Modbus write operations
   tshark -r attack_capture.pcap -Y "modbus.funccode >= 5 && modbus.funccode <= 6" \
     -T fields -e frame.time -e ip.src -e ip.dst -e modbus.funccode -e modbus.regval_uint16

   # Find all Modbus exception responses (indicators of scanning)
   tshark -r attack_capture.pcap -Y "modbus.funccode >= 128" \
     -T fields -e frame.time -e ip.src -e ip.dst -e modbus.funccode
   ```

3. Write a forensic timeline report documenting:
   - Time of first anomalous activity
   - Source IP addresses involved in the attack
   - Specific registers targeted by write operations
   - Any exception responses indicating reconnaissance
   - Estimated duration of the attack

4. Calculate cryptographic hashes of all evidence files and create an evidence manifest:
   ```bash
   sha256sum *.pcap *.json *.bin > evidence_manifest.sha256
   md5sum *.pcap *.json *.bin > evidence_manifest.md5
   ```

**Deliverables**: Forensic report JSON, attack timeline analysis, evidence manifest with hashes, written post-incident assessment.

## References

1. **NIST SP 800-82 Rev. 3** - Guide to Operational Technology (OT) Security. Provides comprehensive guidance on ICS security including incident response planning, https://csrc.nist.gov/publications/detail/sp/800-82/rev-3/final

2. **IEC 62443** - Industrial Automation and Control Systems Security. International standard defining security levels, zones, conduits, and incident response procedures for ICS environments.

3. **SANS ICS Security** - ICS Incident Response and Forensics training resources and whitepapers, https://www.sans.org/industrial-control-systems/

4. **MITRE ATT&CK for ICS** - Framework describing adversary tactics, techniques, and procedures specific to industrial control systems, https://attack.mitre.org/techniques/ics/

5. **CISA ICS-CERT** - Industrial Control Systems Cyber Emergency Response Team advisories and incident response guidance, https://www.cisa.gov/topics/industrial-control-systems

6. **Dragos ICS Cybersecurity** - Resources on ICS threat intelligence, incident response playbooks, and adversary tracking for industrial environments.

7. **ISA-95 / IEC 62264** - Enterprise-control system integration standard that defines the Purdue Model levels and the interfaces between them, relevant for understanding incident scope and containment boundaries.

8. **RFC 5044** - Datamover Technologies for TCP Offload. Provides context on TCP session handling relevant to ICS network forensic analysis.
