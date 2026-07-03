# Automotive Security Testing Tools — Practical Reference Guide

> Companion to `quick-reference-card.md`. This guide covers **which tools to reach for** in each phase of a vehicle security engagement, with install commands and minimum-viable workflows.

---

## Overview

The vehicle security toolkit is broader than generic embedded. You need CAN adapters, JTAG extractors, SDRs, BLE relays, and the software to glue them together. This guide lists what to use and when.

---

## Objective

Have the right tool installed and configured before you start, so you're not fighting dependencies at 2am.

---

## Tool Categories by Engagement Phase

| Phase | Tools |
|-------|-------|
| Recon (vehicle scan) | `candump`, `savvy-can`, `python-can`, `udsoncan` |
| DBC reverse engineering | SavvyCAN, `cantools`, custom Python |
| UDS fuzzing | `udsoncan`, custom fuzzers, Scapy |
| Firmware extraction | JTAGulator, Shikra, Bus Blaster, Flashrom, binwalk |
| RF / key fob | HackRF One, RTL-SDR, Proxmark3, Universal Radio Hacker |
| BLE / PEPS relay | ESP32, nRF52, GATTacker, relay scripts |
| Wi-Fi / cellular | Wireshark, Bettercap, Burp Suite (for cloud API) |
| Forensic | Autopsy, Velociraptor, custom ECU log parsers |
| Reporting | Dradis, Faraday, custom Markdown templates |

---

## CAN Tools

### python-can

The Python standard for CAN bus access. Cross-platform, supports 20+ adapter families.

```bash
pip install python-can
```

```python
import can
bus = can.interface.Bus(channel='can0', interface='socketcan')
msg = bus.recv(timeout=1.0)
print(msg)
```

### can-utils (Linux)

The C-based kernel tools. Faster than Python; use for high-throughput captures.

```bash
sudo apt install can-utils
candump -L can0  # timestamped capture
cansend can0 123#DEADBEEF  # send frame
cansniffer can0  # live view with delta highlighting
```

### SavvyCAN

Cross-platform GUI. Built on QT. Best for DBC reverse engineering visually.

- GitHub: `github.com/collin80/SavvyCAN`
- Pre-built binaries for Windows / macOS / Linux.

### cantools

Python DBC parser, encoder, decoder.

```bash
pip install cantools
cantools decode hs-can.dbc candump.log
```

### PCAN-Basic / PCAN-View

Peak System's official tools. Use the PCAN-USB on Windows.

### Vector CANalyzer / CANoe

Industry standard. $5k+ per seat license. Use if you have access via OEM engagement.

---

## UDS Tools

### udsoncan

Python UDS client. Implements ISO 14229-1.

```bash
pip install udsoncan
```

```python
import udsoncan
from udsoncan.connections import PythonIsoTpConnection
from udsoncan.client import Client
# Setup ISO-TP over CAN
conn = PythonIsoTpConnection('can0', tx_id=0x7E0, rx_id=0x7E8)
client = Client(conn)
with client:
    response = client.read_data_by_identifier(0xF190)  # VIN
    print(response.value)
```

### Caringcaribou

 Modular automotive attack framework. UDS fuzzer included.

- GitHub: `github.com/CaringCaribou/caringcaribou`
- Use: `python3 -m caringcaribou uds all 0x7E0`

### Scapy with ISO-TP module

For low-level UDS work.

```python
from scapy.all import *
from scapy.contrib.isotp import *
sock = ISOTPSocket('can0', tx_id=0x7E0, rx_id=0x7E8)
sock.send(CAN(flags='extended'))
```

---

## Firmware Extraction Tools

### JTAGulator

Discover JTAG / UART pins on a PCB automatically.

- Cost: ~$200 from Crowd Supply.
- Use case: any ECU you've desoldered and want to dump.

### Shikra / Bus Pirate

Cheap UART / SPI / I2C bridges.

- Cost: $50-$100.
- Use case: simple UART console access.

### Flashrom

SPI flash programmer. Reads/writes 25-series flash chips (Winbond, Macronix, etc.).

```bash
sudo apt install flashrom
sudo flashrom -p ft2232_spi:type=2232H,port=A -r ecu-flash.bin
```

### binwalk

Firmware image analyzer. Identifies embedded filesystems, compression, and code segments.

```bash
binwalk -e ecu-flash.bin
```

### Ghidra / IDA Pro

Reverse engineering frameworks. Ghidra is free; IDA Pro starts at $5k.

- Ghidra supports many embedded architectures: ARM Cortex-M, V850, PowerPC, TriCore.
- Use the **Processor Module** for the ECU's MCU family.

---

## RF / Key Fob Tools

### HackRF One

Half-duplex SDR, 1 MHz - 6 GHz. Use for key fob recording / replay.

```bash
# Record 433.92 MHz key fob transmission
hackrf_transfer -r key-fob-433.cs8 -f 433920000 -l 32 -g 32 -s 8000000
# Replay
hackrf_transfer -t key-fob-433.cs8 -f 433920000 -l 32 -g 32 -s 8000000 -R
```

### RTL-SDR

Receive-only SDR, $25. Good for capturing and analyzing without replay.

### Universal Radio Hacker

GUI for SDR-based signal analysis. Decoder for ASK / FSK / OOK.

```bash
pip install urh
urh
```

### Proxmark3

LF / HF RFID. For classic PEPS systems using 125 kHz or 13.56 MHz.

```bash
# Sniff LF
pm3 --> hf 14a sniff
# Replay
pm3 --> hf 14a sim
```

---

## BLE / PEPS Relay Tools

### ESP32 + nRF52

Custom firmware for $15 BLE relay.

- Firmware example: `github.com/nccgroup/noble-relay` (concept).
- Two devices: one near car antenna, one near fob.

### GATTacker / btlejack

For BLE MITM / jamming.

```bash
npm install -g gattacker
gattacker scan
```

---

## Network / Cloud API Tools

### Wireshark

For Automotive Ethernet, DOIP, SOME/IP captures.

```bash
sudo apt install wireshark
# Capture eth0 with DOIP dissector enabled
wireshark -k -i eth0 -f "tcp port 13400"
```

### Burp Suite

For OEM cloud APIs (Nissan Leaf-style).

- Intercept phone-app traffic to OEM cloud.
- Test for the VIN-as-auth-token pattern.

### Bettercap

For Wi-Fi attacks against IVI hotspots.

---

## Forensic Tools

### Autopsy / The Sleuth Kit

GUI over TSK. For analyzing ECU filesystems once dumped.

### Velociraptor

Endpoint visibility. Use on the bench-vehicle's IVI when running a fleet.

### Custom CAN Log Parsers

The author has a public tool: `github.com/example/can-forensic` (illustrative). Pares `.asc` files and correlates with GPS / cellular events.

---

## Reporting Tools

### Dradis

Engagement-focused reporting. Imports nmap, nessus, custom findings.

### Faraday

Similar to Dradis with more IDE-like UX.

### Custom Markdown Templates

For CVD reports: use the I Am The Cavalry template (Coordinated Disclosure for Connected Vehicles, 2015).

---

## Hands-on Practice: A 1-Hour Tooling Lab

Goal: configure a Linux laptop for a complete CAN engagement.

1. Install python-can, can-utils, udsoncan, cantools, SavvyCAN.
2. Plug in PCAN-USB. Verify `ip link` shows `can0`.
3. Set bitrate 500k, bring up interface.
4. Capture 1 minute of idle CAN traffic on a development vehicle.
5. Decode using SavvyCAN's frequency-cluster view.
6. Send one frame via `cansend can0 123#01`.
7. Write a 5-line Python script that reads the bus and prints IDs.

If all 7 work, your laptop is ready for a real engagement.

---

## Tool Cost Summary

| Tier | Tools | Cost |
|------|-------|------|
| Beginner | RTL-SDR, CANalyst-II, ESP32 ×2 | $60 |
| Intermediate | HackRF One, PCAN-USB, Proxmark3 RDV4 | $1,100 |
| Professional | All above + Kvaser, JTAGulator, Ghidra Pro | $3,000+ |
| Enterprise | + Vector CANoe license | $10k+/year |

---

## References

- DEF CON Car Hacking Village: tool reviews and vendor discounts.
- IOActive blog: hardware reviews.
- OpenGarages: tool setup tutorials.
- /r/CarHacking subreddit: community support.

---

## See Also

- `quick-reference-card.md` — pinouts and protocol cheats
- `automotive-vehicle-security-playbook.md` — engagement workflow
- `automotive-ecu-firmware-and-uds-deep-dive.md` — UDS deep dive
