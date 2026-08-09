# Validation Summary — ics-fieldbus-attack

**Date**: 2026-08-09
**Reviewer**: Claude (automated + human review)
**Kali VM**: parallels@10.211.55.5 (Kali 2026.1, kernel 6.18.12, aarch64)

## Tool inventory on VM

| Tool | Version | Status |
|------|---------|--------|
| nmap | 7.98 | ✓ available |
| tshark | 4.6.4 | ✓ all ICS dissectors (DNP3, IEC 60870, Modbus, PROFINET) |
| tcpdump | 4.99.6 | ✓ |
| scapy | 2.7.01 | ✓ modbus contrib |
| pyserial | 3.5 | ✓ |
| pyModbusTCP | — | ✗ missing (pip install pyModbusTCP) |
| cpppo | — | ✗ missing (pip install cpppo) |
| nmap dnp3-info script | — | ✗ does not exist in nmap 7.98 |
| nmap iec-identify | ✓ | /usr/share/nmap/scripts/iec-identify.nse |
| nmap iec61850-mms | ✓ | /usr/share/nmap/scripts/iec61850-mms.nse |
| nmap modbus-discover | ✓ | /usr/share/nmap/scripts/modbus-discover.nse |
| nmap multicast-profinet-discovery | ✓ | available |
| nmap profinet-cm-lookup | ✓ | available |
| nmap s7-info | ✓ | available |

## Payload sample (10 tested)

| # | Command (excerpt) | Class | Result | Notes |
|---|-------------------|-------|--------|-------|
| 1 | `nmap -p 20000 --script dnp3-info 192.168.1.0/24` | full | **FAIL** | nmap 7.98 has no `dnp3-info` script |
| 2 | `ls /usr/share/nmap/scripts/dnp3*` | full | **FAIL** | confirms: no dnp3 NSE script exists |
| 3 | `tshark -G protocols \| grep -i dnp3\|iec\|modbus` | full | PASS | all ICS dissectors present |
| 4 | `tcpdump -i eth0 -w dnp3_capture.pcap port 20000` | full | PASS | tcpdump 4.99.6 works |
| 5 | `python3 -c "from scapy.contrib import modbus"` | full | PASS | scapy 2.7.01 |
| 6 | `pip3 list \| grep pyserial` | full | PASS | pyserial 3.5 |
| 7 | `ls /usr/share/nmap/scripts/iec*` | full | PASS | iec-identify + iec61850-mms |
| 8 | `command -v cpppo claroty-osint minimalmodbus` | full | **FAIL** | ICS tools missing |
| 9 | `python3 -c "from pyModbusTCP.client import ModbusClient"` | full | **FAIL** | pyModbusTCP missing |
| 10 | `git clone https://github.com/mz-automation/lib60870.git` | sandbox-only | NOT RUN | static reference (no runtime need) |

**Pass rate**: 5/9 run = 56% (4 fail)
**Class distribution**: 9 full + 1 sandbox-only = 10 sample
**Broken count**: 0 (the 4 fails are missing dependencies or invalid commands)

## Key Findings

- **F-001 P1**: `nmap --script dnp3-info` referenced 3 times in payloads.md (lines 40, 43, 354) but no such NSE script exists in nmap 7.98 (or earlier). Recommended fix: replace with `tshark` or `modbus-discover.nse` depending on target.
- **F-002 P2**: Python libraries pyModbusTCP and cpppo not in Kali 2026.1 default; payloads should add `pip install` hints.
- **F-003 P3**: frontmatter `mitre: "T0817-Program Logic Controller Software"` is too narrow; SKILL body references 7 ATT&CK for ICS T-codes (T0807/T0817/T0858/T0859/T0866/T0884/T0890).
- **F-004 P3**: Only 3 unique URLs in SKILL.md; could benefit from references to IEC 62443 standards portal, ATT&CK for ICS matrix, Dragos/Claroty/Nozomi resources.
