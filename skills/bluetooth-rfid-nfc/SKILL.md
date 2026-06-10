---
name: bluetooth-rfid-nfc
description: "Near-field wireless penetration testing skills covering Bluetooth Classic device enumeration and exploitation, BLE GATT service attacks against IoT devices, RFID card cloning (MIFARE Classic/DESFire), NFC tag manipulation, and contactless payment probing."
origin: openclaw
version: "0.1.19"
compatibility:
  - openclaw
  - claude-code
  - cursor
  - windsurf
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
  - WebSearch
  - WebFetch
metadata:
  domain: wireless
  tool_count: 13
  guide_count: 3
  mitre: "TA0046-Initial Access"
---

# Bluetooth, RFID & NFC Security

> **Supplementary Files**:
> - `payloads.md` — Attack commands and payloads categorized by Bluetooth Reconnaissance, Bluetooth Exploitation, BLE GATT Attacks, RFID/NFC Card Operations, and NFC Tag Operations
> - `test-cases.md` — Structured test case list (8 scenarios covering Bluetooth, BLE, RFID, NFC attacks with severity levels)

## Summary

Bluetooth Rfid Nfc skill domain covering wireless operations.

**Tools**: spooftooph, redfang, bluelog, btscanner, bluehydra, crackle, ubertooth-tools, gatttool (+5 more)

**Domain**: wireless

**MITRE ATT&CK**: TA0046-Initial Access

## Description

Near-field wireless penetration testing skills covering Bluetooth Classic device enumeration and exploitation, BLE GATT service attacks against IoT devices, RFID card cloning (MIFARE Classic/DESFire), NFC tag manipulation, and contactless payment probing. Built on the BlueZ stack, Ubertooth hardware sniffing, and Proxmark3 RFID toolkit.

**Core Principle**: Bluetooth Legacy Pairing uses a static link key derivable from the PIN and unit key; BLE Legacy Pairing (Just Works) provides no man-in-the-middle protection; MIFARE Classic uses the proprietary CRYPTO1 cipher with known vulnerabilities enabling key recovery in minutes.

## Use Cases

1. **Bluetooth IoT Device Audit** - Assess smart locks, medical devices, fitness trackers, and industrial BLE sensors for unauthorized access and data leakage
2. **RFID Access Control Testing** - Evaluate physical security of building access cards (MIFARE, HID iCLASS) for cloning and replay attacks
3. **NFC Payment Security Assessment** - Test contactless payment terminal and card implementations for relay attacks and transaction manipulation
4. **Red Team Wireless Entry Point** - Exploit Bluetooth or BLE vulnerabilities as an initial access vector into target environments (smart device pivot)
5. **Wireless Device Fingerprinting** - Enumerate and catalog all Bluetooth/BLE devices in a facility for asset inventory and rogue device detection
6. **Badge Cloning for Physical Penetration** - Clone RFID/NFC badges to bypass building access controls during physical security assessments

## Core Tools

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **spooftooph** | Bluetooth device identity spoofing (name, class, MAC) | `spooftooph -i hci0 -a XX:XX:XX:XX:XX:XX -n "TargetPhone"` |
| **redfang** | Discover non-discoverable Bluetooth devices via brute force | `redfang -r 00:00:00:00:00:00 -s XX:XX:XX:XX:XX:XX` |
| **bluelog** | Bluetooth device scanner with automated logging | `bluelog -i hci0 -o /tmp/bt_scan.log` |
| **btscanner** | Interactive Bluetooth device information gathering | `btscanner -i hci0` |
| **bluehydra** | Continuous Bluetooth/BLE device monitoring and tracking | `sudo bluehydra -i hci0 -d /tmp/bluehydra` |
| **crackle** | BLE Legacy Pairing encryption cracking (LK decryption) | `crackle -i ble_capture.pcap -o decrypted.pcap` |
| **ubertooth-tools** | Bluetooth BR/EDR and BLE promiscuous sniffing | `ubertooth-btle -f -c /tmp/ble_sniff.pcap` |
| **gatttool** | BLE GATT service enumeration and characteristic R/W | `gatttool -b XX:XX:XX:XX:XX:XX --characteristics` |
| **proxmark3** | RFID/NFC universal transceiver (read/clone/emulate) | `proxmark3-client -c "hf search"` |
| **mfoc** | MIFARE Classic offline key recovery (nested attack) | `mfoc -P 500 -O card_dump.mfd` |
| **mfcuk** | MIFARE Classic offline key recovery (darkside attack) | `mfcuk -C -R 0:A -s 250 -S 5 -v 3` |
| **libnfc** | NFC device enumeration and tag operations | `nfc-list && nfc-mfclassic r a card.mfd /dev/ttyUSB0` |
| **blescan** | BLE device scanning using BlueZ (Python-based) | `blescan -i hci0 -t 30 -o ble_results.json` |

## Methodology

### Attack Chain

```
1. Device Discovery      -> Active/passive scanning (bluelog, blescan, redfang)
2. Target Selection       -> Evaluate device type, signal strength, services advertised
3. Protocol Fingerprint   -> Identify Bluetooth version, pairing method, service profiles
4. Service Enumeration    -> GATT service/characteristic mapping (gatttool, ubertooth-tools)
5. Exploitation
   +-- BT Classic         -> Identity spoofing (spooftooph), PIN brute force, pairing hijack
   +-- BLE                -> GATT R/W attacks, encryption cracking (crackle), MITM
   +-- RFID/NFC           -> Key recovery (mfoc/mfcuk), card cloning (proxmark3), emulation
6. Post-Exploitation      -> Persistent access via cloned badge or spoofed device identity
```

**Key Decision Points**:
- **Bluetooth Classic non-discoverable** -> Use redfang for brute-force discovery
- **BLE device with GATT services** -> Enumerate with gatttool, test for unauthenticated read/write
- **BLE Legacy Pairing captured** -> Crack with crackle for link key recovery
- **MIFARE Classic card** -> Use mfoc (nested) first; if single known key needed, use mfcuk (darkside)
- **Unknown card type** -> Use proxmark3 `hf search` to auto-detect card technology

### Attack Phases

| Phase | Bluetooth | BLE | RFID/NFC |
|-------|-----------|-----|----------|
| Recon | redfang, bluelog, btscanner, bluehydra | blescan, ubertooth-btle | proxmark3 `hf search`, nfc-list |
| Enum | sdptool, btscanner | gatttool, blescan | proxmark3 `hf mf info`, mfoc |
| Attack | spooftooph, PIN brute | crackle, gatttool R/W | mfoc, mfcuk, proxmark3 clone |
| Persist | Spoofed identity | Extracted encryption key | Cloned/emulated card |

## Defense Perspective

| Attack Vector | Defense Measure |
|---------------|-----------------|
| Bluetooth Device Discovery | Disable discoverable mode, use LE Secure Connections (BLE 4.2+) |
| BLE Legacy Pairing Cracking | Use LE Secure Connections with authenticated pairing (OOB or numeric comparison) |
| BLE GATT Unauthorized Access | Implement proper authentication on sensitive characteristics, use bonded connections |
| RFID Card Cloning (MIFARE Classic) | Upgrade to MIFARE DESFire (AES-128), use diversified keys |
| NFC Relay Attacks | Implement distance bounding protocols, transaction timeouts |
| Bluetooth Spoofing | Enable Secure Simple Pairing with MITM protection, disable legacy pairing |
| Proxmark3 Emulation | Deploy card-specific challenge-response sequences, use dynamic card numbers |

**Security Configuration Priority**: MIFARE DESFire EV2/EV3 > MIFARE Classic (fully randomized keys) > BLE Secure Connections > BLE Legacy Pairing > Bluetooth Classic SSP without MITM protection

## Practical Steps

> **Detailed payloads in `payloads.md`, complete test checklist in `test-cases.md`.**

### Quick Reference

1. **Bluetooth Scan** -- `bluelog -i hci0 -o scan.log` or `btscanner -i hci0`
2. **BLE Discovery** -- `blescan -i hci0 -t 30` or `sudo hcitool lescan`
3. **GATT Enum** -- `gatttool -b XX:XX:XX:XX:XX:XX -I` then `connect` and `primary`
4. **BLE Crack** -- `crackle -i capture.pcap -o decrypted.pcap`
5. **MIFARE Key Recovery** -- `mfoc -P 500 -O dump.mfd` or `mfcuk -C -R 0:A -v 3`
6. **Card Clone** -- `proxmark3-client -c "hf mf clone --uid TARGET_UID"`

## Common Pitfalls

- **Missing Ubertooth hardware for BLE sniffing**: Software-only BLE sniffing (hcitool lescan) only captures advertisement packets, not connection data. Full BLE traffic capture requires Ubertooth One or similar dedicated sniffer hardware for promiscuous mode. Plan hardware procurement before BLE assessments.
- **Assuming BLE pairing equals encryption**: BLE Legacy Pairing (Just Works) generates a link key using a temporary key that is transmitted in the clear. Capturing the pairing exchange with Ubertooth allows offline decryption with crackle in seconds. Always verify which pairing method the target uses.
- **Ignoring MIFARE Classic key diversification**: Well-configured systems use diversified keys (unique per card) rather than a single global key. mfoc requires at least one known key to start the nested attack. If all sector keys are diversified, mfoc will fail and mfcuk (darkside) may be the only option, which is much slower.
- **Bluetooth range underestimation**: Class 1 Bluetooth devices (100m range) can be targeted from significant distances, especially with directional antennas. Class 2 (10m) and Class 3 (1m) devices require close proximity, which may not be practical during covert assessments.
- **RFID frequency mismatch**: Not all RFID readers support all frequencies. Low-frequency (125 kHz) and high-frequency (13.56 MHz) cards require different hardware. Verify target card frequency before selecting tools -- proxmark3 supports both, but standalone tools like mfoc only work with 13.56 MHz MIFARE cards.

## Automation and Scripting

Automate Bluetooth assessments with bluehydra for continuous device monitoring and tracking, piping device discoveries into spooftooph for automated identity cloning. Use Python with pygatt or bluepy libraries to script BLE GATT enumeration and characteristic fuzzing across multiple devices simultaneously. For RFID, wrap proxmark3-client commands in shell scripts to batch-read and clone cards, or use the proxmark3 Lua scripting engine for custom attack sequences. Schedule bluehydra scans during business hours to build a complete device map of the target environment.

## Reporting and Documentation

Bluetooth/RFID reports should include a complete device inventory with MAC address, device name, device class, signal strength, discovered services, and identified vulnerabilities. For BLE assessments, document the full GATT service map with all handles, UUIDs, and their read/write permissions. RFID reports must specify card type, UID, key recovery method, time required, and whether cloning was successful. Include specific remediation recommendations: disable legacy pairing, upgrade card technology, implement distance bounding. Attach raw capture files (pcap for Bluetooth, mfd/bin for RFID) as evidence.

## Legal and Ethical Considerations

Bluetooth and RFID testing often involves devices you do not own -- smart locks, payment terminals, access control systems, and personal devices. Only scan and test devices within your authorized scope. Passive Bluetooth scanning in public spaces may be legal in some jurisdictions but actively probing or attempting to connect to devices without authorization is typically illegal. RFID card cloning for access control systems requires explicit written authorization from the system owner. Never attempt to clone payment cards or government-issued IDs, as this violates federal law in most jurisdictions regardless of authorization scope.

## Integration with Other Tools

Bluetooth/BLE findings often connect to IoT device exploitation -- after identifying a vulnerable BLE device, use the extracted credentials or keys to access associated cloud services or mobile application APIs. RFID/NFC access card cloning leads directly into physical penetration testing: a cloned badge provides building access for planting rogue devices (network-pentest) or social engineering operations. Bluetooth device spoofing can be combined with wifi-pentest for multi-vector wireless assessments targeting both WiFi and Bluetooth entry points simultaneously.

## Case Studies and Examples

- **BLE smart lock bypass**: During a smart home assessment, gatttool enumeration revealed an unprotected write characteristic on the lock service handle. Writing a single byte (0x01) to handle 0x0025 unlocked the door without authentication. The vendor had not implemented any authorization check on the GATT write operation.
- **MIFARE Classic corporate badge clone**: A Fortune 500 company used MIFARE Classic cards for building access. mfoc recovered all sector keys in 3 minutes using the well-known default key (0xA0A1A2A3A4A5) on sector 0. The card was fully dumped and cloned onto a blank MIFARE Classic card using proxmark3, granting unrestricted building access.
- **BLE fitness tracker data leakage**: An unauthenticated gatttool connection to a fitness tracker exposed heart rate, step count, GPS coordinates, and user profile data through readable GATT characteristics. No encryption or authentication was required to access any data on the device.

## Detection Methods

Bluetooth intrusion detection monitors for: rapid inquiry scans from a single source (scanning for non-discoverable devices), unexpected pairing attempts (especially with legacy pairing), characteristic read/write operations on protected services, and cloned device MAC addresses appearing simultaneously in different locations. RFID/NFC detection systems monitor for: proxmark3 or similar SDR-based reader emulation signals, repeated authentication failures indicating key recovery attempts, and cloned card UIDs authenticating from geographically impossible locations. Deploy BLE monitoring solutions like blue_hydra or internal BLE beacons to detect rogue devices.

## Advanced Techniques

Advanced Bluetooth testing includes: Ubertooth promiscuous sniffing of encrypted BLE connections when the pairing exchange was captured, BtleJuice or GATTacker MITM proxy attacks requiring dual BLE adapters, and proxmark3 relay attacks against NFC payment systems using two devices separated by distance. For RFID, explore MIFARE DESFire side-channel attacks, SAM (Security Access Module) key extraction, and ISO 15693 long-range reading. For BLE, investigate KNOB (Key Negotiation of Bluetooth) attack to force entropy reduction on the encryption key, and BLESA (BLE Spoofing Attack) to inject fabricated data into reconnected BLE sessions.

## Tool Comparison Matrix

| Tool | Best For | Coverage | Skill Level |
|------|----------|----------|-------------|
| **spooftooph** | BT Classic identity spoofing | Narrow (Classic only) | Intermediate |
| **redfang** | Non-discoverable BT discovery | Narrow (Classic only) | Beginner |
| **bluehydra** | Continuous BT/BLE monitoring | Broad (Classic + BLE) | Intermediate |
| **crackle** | BLE encryption cracking | Narrow (Legacy Pairing) | Intermediate |
| **ubertooth-tools** | Full BT/BLE traffic capture | Very broad (BR/EDR + BLE) | Advanced |
| **gatttool** | BLE GATT service exploration | Narrow (BLE only) | Beginner |
| **proxmark3** | RFID/NFC universal operations | Very broad (all RFID/NFC) | Advanced |
| **mfoc** | MIFARE Classic key recovery | Narrow (MIFARE Classic) | Intermediate |
| **mfcuk** | MIFARE Classic darkside attack | Narrow (MIFARE Classic) | Intermediate |
| **libnfc** | NFC device operations | Broad (13.56 MHz NFC) | Intermediate |

## Performance and Remediation

Bluetooth attack performance depends on signal strength, interference, and hardware capability. Class 1 devices at close range with minimal 2.4 GHz interference produce the most reliable results. BLE pairing capture requires catching the exact moment of pairing -- position Ubertooth close to the target device and trigger a re-pair. MIFARE Classic key recovery with mfoc typically completes in 2-15 minutes with a good antenna, while mfcuk darkside attack can take 30+ minutes. Proxmark3 with the RDV4 antenna provides the best RFID read range and clone reliability.

Prioritize remediation by impact: immediately upgrade all MIFARE Classic access cards to MIFARE DESFire EV2+, disable Bluetooth legacy pairing on all devices, enforce BLE Secure Connections with authenticated pairing for IoT devices, implement distance bounding for NFC payment systems, and deploy continuous Bluetooth monitoring (bluehydra) to detect rogue devices.

## Hacker Laws

| Law | Bluetooth/RFID Scenario Application |
|-----|--------------------------------------|
| **Minimize Attack Surface** | Disable Bluetooth discoverable mode when not in use, require authentication on all GATT characteristics |
| **First Principles** | Understand CRYPTO1 cipher weaknesses (LFSR state recovery) and BLE Legacy Pairing temporary key derivation to design targeted attacks |
| **Obscurity Is Not Security** | Non-discoverable Bluetooth devices are still detectable via redfang; unknown RFID card types can be identified by proxmark3 auto-detection |
| **Trust but Verify** | Verify BLE pairing actually uses Secure Connections (check auth requirements in GATT); test that MIFARE keys are diversified rather than using defaults |

## Learning Resources

### External Recommendations

- **Books**: "Inside Bluetooth Low Energy" (Naik), "The Hacker's Guide to NFC Contactless Attacks" (Garcia et al.)
- **Online Courses**: Udemy Bluetooth Hacking, Pentester Academy Wireless & IoT Security
- **Lab Environments**: Proxmark3 Easy (budget RFID lab), Ubertooth One (BLE sniffing), ESP32-BLE-CTF (BLE capture-the-flag)
- **Tool Documentation**: [proxmark.com](https://proxmark.com), [greatscottgadgets.com/ubertooth](https://greatscottgadgets.com/ubertooth/), [bluez.org](http://www.bluez.org/)

> **Legal Disclaimer**: Only conduct testing on devices and systems you own or have explicit authorization to test. Unauthorized Bluetooth scanning, RFID card cloning, and NFC manipulation are illegal in most jurisdictions. RFID payment card cloning is a federal offense regardless of authorization scope.

---

**This skill's supplementary files**: payloads.md, test-cases.md, guides/bluetooth-device-recon.md, guides/ble-gatt-attack.md, guides/rfid-nfc-clone.md
**Related skills**: skills/wifi-pentest/SKILL.md, skills/hardware-security/SKILL.md, skills/post-exploitation/SKILL.md
**External resources**: [bluez.org](http://www.bluez.org/), [proxmark.com](https://proxmark.com), [greatscottgadgets.com/ubertooth](https://greatscottgadgets.com/ubertooth/)
