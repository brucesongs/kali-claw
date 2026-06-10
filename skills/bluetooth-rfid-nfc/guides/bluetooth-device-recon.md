# Bluetooth Device Reconnaissance and Attack Guide

This guide covers the complete Bluetooth device reconnaissance and attack methodology, from initial device discovery through targeted exploitation. It focuses on Bluetooth Classic (BR/EDR) devices, with BLE-specific attacks covered in the companion `ble-gatt-attack.md` guide.

## Introduction and Objectives

Bluetooth device reconnaissance is the foundational phase of any wireless security assessment targeting Bluetooth-enabled devices. This guide covers the complete reconnaissance methodology from active device discovery to traffic capture and device spoofing, providing the intelligence needed for targeted exploitation.

**Learning objectives**:

- Perform active Bluetooth device discovery using hcitool, bluelog, and bluehydra
- Detect non-discoverable devices using redfang brute-force MAC scanning
- Enumerate device capabilities and Bluetooth profiles using sdptool and btscanner
- Capture Bluetooth traffic with Ubertooth for pairing exchange analysis
- Clone device identities using spooftooph for impersonation testing

**Prerequisites**: A Bluetooth adapter (Class 1 recommended for extended range). For traffic capture: Ubertooth One hardware. Understanding of Bluetooth protocol basics (inquiry, paging, pairing, profiles).

---

## Overview

Bluetooth reconnaissance is the critical first phase of any wireless assessment targeting Bluetooth-enabled devices. Unlike WiFi, Bluetooth uses frequency-hopping spread spectrum (FHSS) across 79 channels in the 2.4 GHz band, making passive sniffing significantly harder without dedicated hardware. Bluetooth devices can operate in discoverable or non-discoverable modes, and the first challenge is often simply finding devices that do not want to be found.

Bluetooth Classic devices are categorized by power class:
- **Class 1**: 100m range (industrial/access points)
- **Class 2**: 10m range (most consumer devices -- phones, headsets, keyboards)
- **Class 3**: 1m range (rare, specialized devices)

Understanding the target device class dictates your physical approach and hardware requirements for the assessment.

---

## Phase 1: Active Device Discovery

The simplest form of Bluetooth reconnaissance queries for devices in discoverable mode. Most consumer devices disable discoverable mode after pairing, but many IoT devices, car infotainment systems, and smart home devices remain permanently discoverable.

```bash
# Quick scan for discoverable devices
hcitool scan

# Extended inquiry with device class and clock offset
hcitool inq --length=10 --flush

# Get detailed capabilities of a specific device
hcitool info XX:XX:XX:XX:XX:XX

# Query SDP (Service Discovery Protocol) for supported profiles
sdptool browse XX:XX:XX:XX:XX:XX
```

The `sdptool browse` output is particularly valuable as it reveals which Bluetooth profiles the device supports. Key profiles to watch for include:
- **SPP (Serial Port Profile)**: Often used by IoT devices for raw data transfer, frequently unauthenticated
- **HFP (Hands-Free Profile)**: Smart speakers and car systems, potential for audio eavesdropping
- **A2DP (Advanced Audio Distribution)**: Audio streaming, potential for audio injection
- **OBEX (Object Exchange)**: File transfer capability, potential for unauthorized data access

For continuous monitoring during an assessment, bluelog provides automated logging:

```bash
# Continuous scan with logging
bluelog -i hci0 -o /tmp/bt_scan.log -c -v

# bluehydra for persistent monitoring with device tracking
sudo bluehydra -i hci0 --ble -d /opt/bh_data
```

Bluehydra is especially useful for building a complete device map over time, as it tracks device appearances, signal strength changes, and name variations. Run it for the duration of the assessment to capture devices that enter and leave the area.

---

## Phase 2: Non-Discoverable Device Detection

Many devices are configured as non-discoverable but still respond to directed inquiries. Redfang exploits this by performing brute-force MAC address queries across a specified range:

```bash
# Scan a specific vendor OUI range
redfang -r A4:83:E7:00:00:00 -s A4:83:E7:FF:FF:FF

# Scan a smaller range for faster results
redfang -r 00:1A:7D:DA:71:00 -s 00:1A:7D:DA:71:FF
```

Redfang works by sending connection attempts to each MAC address in the range. If a device responds (even with a negative response), its presence is confirmed. This technique is slow (approximately 10-20 addresses per second) but effective for finding hidden devices when you know the vendor OUI.

The btscanner tool provides an interactive curses-based interface for deeper device inspection:

```bash
btscanner -i hci0
```

Within btscanner, you can perform inquiry scans, view extended inquiry response data, and query SDP records for each discovered device. It maintains a persistent display of all discovered devices with their signal strength and last-seen timestamp.

---

## Phase 3: Traffic Capture with Ubertooth

Software-only Bluetooth reconnaissance is limited to the inquiry and page scan mechanisms of the host adapter. For full traffic capture -- including connection establishment, authentication exchanges, and data transfer -- you need dedicated sniffing hardware like the Ubertooth One.

```bash
# Capture all Bluetooth BR/EDR traffic in the area
ubertooth-rx -f -c /tmp/bt_full_capture.pcap

# Follow a specific device connection
ubertooth-rx -a XX:XX:XX:XX:XX:XX -c /tmp/bt_target.pcap

# Spectral scan to detect Bluetooth activity before targeting
ubertooth-scan -t 30 -x
```

Ubertooth operates in promiscuous mode, capturing Bluetooth frames regardless of whether they are addressed to the sniffer. This is essential for capturing pairing exchanges, which contain the link key derivation data needed for offline attacks.

Key capture scenarios:
1. **Pairing capture**: Capture the entire pairing exchange (IN RAND, IN RSP, COMB KEY, AU RAND, SRES) for offline PIN/link key recovery
2. **Connection hijacking**: Monitor for connection establishment patterns to identify authentication weaknesses
3. **Data exfiltration detection**: Capture data transfers to identify unencrypted or weakly encrypted communication

---

## Phase 4: Device Spoofing with spooftooph

Once a target device's identity (MAC, name, device class) is known from reconnaissance, spooftooph enables identity cloning:

```bash
# Clone complete device identity
spooftooph -i hci0 -a XX:XX:XX:XX:XX:XX -n "TargetPhone" -c 0x7a020c

# Spoof as a Bluetooth headset to intercept audio
spooftooph -i hci0 -n "Jabra Elite 75t" -c 0x240404

# Randomize identity for anonymous operations
spooftooph -i hci0 -r
```

Device class values are important for convincing spoofing. Common values:
- `0x7a020c`: Smartphone
- `0x240404`: Headset
- `0x040808`: Keyboard/mouse combo
- `0x5a020c`: Phone with audio capabilities

After spoofing, test whether previously paired devices attempt to auto-connect to your adapter. Many devices automatically reconnect to trusted MAC addresses without user confirmation, enabling passive credential harvesting or man-in-the-middle positioning.

---

## Attack Methodology Summary

The complete Bluetooth Classic attack chain follows this progression:

1. **Discover** (hcitool scan, bluelog, bluehydra) -- Identify all devices in the target area
2. **Enumerate** (btscanner, sdptool, hcitool info) -- Map services, profiles, and device capabilities for each target
3. **Find hidden devices** (redfang) -- Scan non-discoverable devices using known OUI ranges
4. **Capture traffic** (ubertooth-rx) -- Sniff pairing exchanges and connection data
5. **Spoof identity** (spooftooph) -- Clone trusted device identities for impersonation
6. **Exploit** -- Leverage discovered services (unauthenticated SPP, OBEX file access) or captured pairing data for unauthorized access

Key indicators to look for during reconnaissance:
- Devices using legacy pairing (PIN-based) rather than Secure Simple Pairing
- Permanently discoverable IoT devices with default names or configurations
- SPP or OBEX profiles exposed without authentication requirements
- Devices with weak or default PINs (0000, 1234, 9999)
- Car infotainment systems that accept automatic reconnection from any paired device

---

## Common Mistakes

1. **Skipping non-discoverable scanning**: Most interesting targets (phones, laptops) are non-discoverable. Redfang is essential, not optional.
2. **Ignoring device class**: Device class tells you what the device is and what attack surface it presents. Always record it during discovery.
3. **Not capturing pairing exchanges**: The pairing exchange is the most valuable data to capture. Position Ubertooth before triggering any re-pairing events.
4. **Underestimating range**: Use a directional Bluetooth antenna to extend range and focus on specific target areas, especially for Class 1 devices.

---

> **Legal Notice**: Bluetooth scanning and device probing may be restricted by law in your jurisdiction. Only perform these techniques on devices you own or have explicit written authorization to test.

## Hands-on Exercise: Bluetooth Reconnaissance

Practice the complete Bluetooth reconnaissance methodology:

**Setup**:

```bash
# Ensure Bluetooth adapter is available and powered on
sudo hciconfig hci0 up
# Have several Bluetooth devices in the area for testing (phone, headset, IoT device)
```

**Exercise steps**:

1. Run hcitool scan to discover all discoverable devices and record MAC addresses, names, and device classes
2. For each discovered device, run `sdptool browse` to enumerate supported Bluetooth profiles
3. Start bluelog for continuous monitoring and observe device appearances over 10 minutes
4. Attempt to find non-discoverable devices using redfang against a known vendor OUI range
5. Use btscanner for interactive device inspection and record extended inquiry response data
6. If Ubertooth is available, capture Bluetooth traffic and identify pairing exchanges in Wireshark
7. Attempt device identity cloning with spooftooph and test whether paired devices attempt reconnection
8. Document the complete device map with profiles, signal strength, and security observations

**Validation criteria**: Discover at least 5 Bluetooth devices including at least one non-discoverable device. Successfully enumerate profiles for each discovered device. Capture at least one Bluetooth frame with Ubertooth (if available).

## References and Resources

- [Bluetooth SIG - Core Specification](https://www.bluetooth.com/specifications/bluetooth-core-specification/)
- [Ubertooth GitHub Repository](https://github.com/greatscottgadgets/ubertooth)
- [BlueZ - Linux Bluetooth Stack](http://www.bluez.org/)
- [redfang GitHub Repository](https://github.com/White-hat/redfang)
- [NIST SP 800-121 - Bluetooth Security Guide](https://csrc.nist.gov/publications/detail/sp/800-121/rev-1/final)
