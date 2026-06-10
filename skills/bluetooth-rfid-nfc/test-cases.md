# Bluetooth, RFID & NFC Security Test Cases

> This file is a companion to `SKILL.md`, containing 8 structured test cases covering Bluetooth reconnaissance, BLE exploitation, RFID card operations, and NFC attack scenarios.

---

## Statistics

| Category | Count | Severity Distribution |
|------|------|-------------|
| A. Bluetooth Reconnaissance | 2 | Medium x2 |
| B. BLE GATT Exploitation | 2 | Critical x1, High x1 |
| C. RFID Card Attacks | 2 | Critical x1, High x1 |
| D. NFC Operations | 2 | High x1, Medium x1 |
| **Total** | **8** | **Critical x2, High x3, Medium x3** |

---

## A. Bluetooth Reconnaissance

### TC-BT-001: Bluetooth Device Discovery and Service Mapping

| Field | Content |
|------|------|
| **Test ID** | TC-BT-001 |
| **Category** | A. Bluetooth Reconnaissance |
| **Severity** | Medium |
| **Objective** | Discover and map all Bluetooth devices and their service profiles within the authorized test range |
| **Title** | Bluetooth Device Discovery and Service Mapping |
| **Prerequisites** | Bluetooth adapter (hci0) available; target devices within range; authorized test environment |
| **Test Steps** | 1. `hcitool scan` to discover discoverable devices |
| | 2. `bluelog -i hci0 -o /tmp/bt_scan.log -v` for continuous logging |
| | 3. `btscanner -i hci0` for interactive device information gathering |
| | 4. `sdptool browse XX:XX:XX:XX:XX:XX` for each discovered device to map services |
| | 5. `hcitool info XX:XX:XX:XX:XX:XX` for detailed device capabilities |
| | 6. `sudo bluehydra -i hci0 --ble` for continuous monitoring with BLE support |
| **Expected Result** | All discoverable Bluetooth devices within range are identified with MAC address, device name, device class, and supported service profiles (SPP, A2DP, HFP, etc.) |
| **Verification Method** | bt_scan.log contains complete device list; SDP records reveal all supported profiles; bluehydra database shows device tracking history |
| **Related Tools** | hcitool, bluelog, btscanner, bluehydra, sdptool |
| **Related Payload** | payloads.md 1.1, 1.3, 1.4, 1.5 |

### TC-BT-002: Non-Discoverable Bluetooth Device Detection

| Field | Content |
|------|------|
| **Test ID** | TC-BT-002 |
| **Category** | A. Bluetooth Reconnaissance |
| **Severity** | Medium |
| **Objective** | Detect Bluetooth devices that have disabled discoverable mode by actively probing known MAC address ranges |
| **Title** | Non-Discoverable Bluetooth Device Detection via Brute Force |
| **Prerequisites** | Bluetooth adapter (hci0) available; target device MAC address range known or estimated (vendor OUI); authorization for active probing |
| **Test Steps** | 1. Identify target vendor OUI from engagement scope documentation |
| | 2. `redfang -r XX:XX:XX:00:00:00 -s XX:XX:XX:FF:FF:FF` to scan vendor OUI range |
| | 3. Monitor for responses indicating active but non-discoverable devices |
| | 4. For confirmed devices: `hcitool info XX:XX:XX:XX:XX:XX` to extract device details |
| | 5. `ubertooth-scan -t 60 -x` for spectral confirmation of Bluetooth activity |
| **Expected Result** | Non-discoverable Bluetooth devices identified within the scanned MAC range; device name, class, and basic capabilities extracted without the device being in discoverable mode |
| **Verification Method** | redfang output lists responsive MAC addresses; hcitool info confirms device presence and returns device metadata; ubertooth spectral scan corroborates RF activity on 2.4 GHz Bluetooth channels |
| **Related Tools** | redfang, hcitool, ubertooth-tools |
| **Related Payload** | payloads.md 1.2, 2.3 |

---

## B. BLE GATT Exploitation

### TC-BT-003: BLE Device Discovery and GATT Service Enumeration

| Field | Content |
|------|------|
| **Test ID** | TC-BT-003 |
| **Category** | B. BLE GATT Exploitation |
| **Severity** | High |
| **Objective** | Enumerate BLE GATT services and characteristics to identify data exposure and authentication weaknesses |
| **Title** | BLE Device Discovery and GATT Service Enumeration |
| **Prerequisites** | BLE-capable adapter (hci0); target BLE devices within range; authorized test environment |
| **Test Steps** | 1. `sudo hcitool lescan` to discover BLE devices advertising in range |
| | 2. `blescan -i hci0 -t 30 -o ble_results.json` for structured BLE scan output |
| | 3. For each target device: `gatttool -b XX:XX:XX:XX:XX:XX --primary` to list GATT services |
| | 4. `gatttool -b XX:XX:XX:XX:XX:XX --characteristics` to enumerate all characteristics |
| | 5. `gatttool -b XX:XX:XX:XX:XX:XX --char-desc` to list all descriptors |
| | 6. Attempt to read each characteristic: `gatttool -b XX:XX:XX:XX:XX:XX --char-read -a 0xHANDLE` |
| **Expected Result** | Complete GATT service map generated for each target BLE device, including service UUIDs, characteristic handles, properties (read/write/notify), and current values of all readable characteristics |
| **Verification Method** | ble_results.json contains device advertisement data; gatttool output shows complete service hierarchy; sensitive data (tokens, credentials, PII) found in readable characteristics without authentication |
| **Related Tools** | hcitool, blescan, gatttool |
| **Related Payload** | payloads.md 3.1, 3.2, 3.3 |

### TC-BT-004: BLE Legacy Pairing Encryption Cracking

| Field | Content |
|------|------|
| **Test ID** | TC-BT-004 |
| **Category** | B. BLE GATT Exploitation |
| **Severity** | Critical |
| **Objective** | Crack BLE Legacy Pairing encryption by capturing and analyzing the pairing exchange to recover the Short-Term Key |
| **Title** | BLE Legacy Pairing Encryption Cracking via Captured Pairing Exchange |
| **Prerequisites** | Ubertooth One hardware connected; target BLE device using Legacy Pairing (Just Works or Passkey); ability to trigger a new pairing event |
| **Test Steps** | 1. `ubertooth-btle -f -c /tmp/ble_capture.pcap` to start BLE promiscuous capture |
| | 2. Trigger pairing on target device (reset or initiate new bond) |
| | 3. Wait for pairing completion (LL_ENC_REQ/LL_ENC_RSP exchange captured) |
| | 4. Stop capture and run: `crackle -i /tmp/ble_capture.pcap -o /tmp/ble_decrypted.pcap` |
| | 5. Open decrypted capture: `wireshark /tmp/ble_decrypted.pcap` |
| | 6. Analyze decrypted GATT operations for sensitive data (credentials, commands) |
| **Expected Result** | crackle recovers the Short-Term Key (STK) from the captured pairing exchange and decrypts all subsequent BLE traffic, revealing plaintext GATT read/write operations including any credentials or control commands |
| **Verification Method** | crackle output displays "Temporary Key" and "STK" values; decrypted pcap opens in Wireshark showing cleartext ATT protocol data; no "Encrypted" filter needed to read GATT operations |
| **Related Tools** | ubertooth-tools, crackle, wireshark |
| **Related Payload** | payloads.md 3.4, 3.5 |

---

## C. RFID Card Attacks

### TC-BT-005: MIFARE Classic Key Recovery and Card Dump

| Field | Content |
|------|------|
| **Test ID** | TC-BT-005 |
| **Category** | C. RFID Card Attacks |
| **Severity** | Critical |
| **Objective** | Recover all encryption keys and dump the full contents of a MIFARE Classic card for cloning or analysis |
| **Title** | MIFARE Classic Key Recovery and Full Card Dump |
| **Prerequisites** | NFC reader/writer hardware (proxmark3 or compatible); MIFARE Classic 1K/4K card within scope; at least one known sector key (default keys often work) |
| **Test Steps** | 1. `proxmark3-client -c "hf search"` to identify card type and confirm MIFARE Classic |
| | 2. `proxmark3-client -c "hf mf info"` to read card metadata (UID, type, ATQA, SAK) |
| | 3. Check for default keys: `proxmark3-client -c "hf mf chk --1k -d /tmp/default_keys.txt"` |
| | 4. If default key found: `mfoc -P 500 -O card_dump.mfd -k A0A1A2A3A4A5` |
| | 5. If no default key: `mfcuk -C -R 0:A -s 250 -S 5 -v 3` for darkside attack |
| | 6. Verify dump integrity: compare block count and sector trailer structure |
| **Expected Result** | All 32 (1K) or 64 (4K) sector keys recovered; complete card dump saved to .mfd file with all block data including sector trailers, access conditions, and user data |
| **Verification Method** | mfoc completes with "dumping ... OK" message; card_dump.mfd file size is 1024 bytes (1K) or 4096 bytes (4K); key file shows unique keys per sector or confirms default key usage |
| **Related Tools** | proxmark3, mfoc, mfcuk |
| **Related Payload** | payloads.md 4.1, 4.2, 4.3, 4.4 |

### TC-BT-006: RFID Card Cloning and Emulation

| Field | Content |
|------|------|
| **Test ID** | TC-BT-006 |
| **Category** | C. RFID Card Attacks |
| **Severity** | High |
| **Objective** | Clone a dumped RFID card to a blank card or emulate it to bypass access control systems |
| **Title** | RFID Card Cloning and Emulation for Access Control Bypass |
| **Prerequisites** | Successfully dumped MIFARE Classic card (from TC-BT-005); blank MIFARE Classic card (gen1UID or gen2); proxmark3 hardware |
| **Test Steps** | 1. Verify dump file: `proxmark3-client -c "hf mf info"` on original card |
| | 2. Present blank card and verify it is writable: `proxmark3-client -c "hf search"` |
| | 3. Clone with UID: `proxmark3-client -c "hf mf clone --uid ORIGINAL_UID"` |
| | 4. Alternatively write dump via libnfc: `nfc-mfclassic w a card_dump.mfd /dev/ttyACM0` |
| | 5. Verify clone: `proxmark3-client -c "hf mf info"` on cloned card (compare UID and block 0) |
| | 6. Test clone against actual access control reader (within authorized scope) |
| | 7. Alternative: emulate card directly: `proxmark3-client -c "hf mf sim --uid ORIGINAL_UID -i card_dump.bin"` |
| **Expected Result** | Blank card written with identical UID, all sector data, and access keys; cloned card successfully authenticates against the same reader as the original card |
| **Verification Method** | hf mf info on clone shows identical UID and block 0 data; authentication attempt against target reader succeeds with same behavior as original card |
| **Related Tools** | proxmark3, libnfc (nfc-mfclassic) |
| **Related Payload** | payloads.md 4.4, 4.5, 5.2 |

---

## D. NFC Operations

### TC-BT-007: Bluetooth Device Identity Spoofing

| Field | Content |
|------|------|
| **Test ID** | TC-BT-007 |
| **Category** | D. NFC Operations |
| **Severity** | High |
| **Objective** | Spoof Bluetooth device identity to test trust relationships and auto-reconnection behavior of paired devices |
| **Title** | Bluetooth Device Identity Spoofing for Impersonation Testing |
| **Prerequisites** | Bluetooth adapter (hci0); target device MAC, name, and class identified from TC-BT-001; authorization for active spoofing tests |
| **Test Steps** | 1. Gather target device identity: MAC address, device name, device class from reconnaissance |
| | 2. `spooftooph -i hci0 -a XX:XX:XX:XX:XX:XX -n "TargetPhone" -c 0x7a020c` |
| | 3. Verify spoofed identity: `hcitool dev` and `hciconfig hci0` |
| | 4. Test if other devices attempt to auto-connect to spoofed adapter |
| | 5. Attempt to pair with devices that trust the spoofed identity |
| | 6. Document which trust relationships can be exploited via identity spoofing |
| **Expected Result** | Local Bluetooth adapter successfully impersonates target device identity (MAC, name, class); paired/trusted devices may attempt automatic reconnection to the spoofed adapter, potentially exposing services or data |
| **Verification Method** | hcitool shows spoofed MAC address; remote devices display spoofed device name in their Bluetooth settings; connection attempts from previously paired devices logged |
| **Related Tools** | spooftooph, hcitool, hciconfig |
| **Related Payload** | payloads.md 2.1 |

### TC-BT-008: NFC Tag Manipulation and NDEF Payload Testing

| Field | Content |
|------|------|
| **Test ID** | TC-BT-008 |
| **Category** | D. NFC Operations |
| **Severity** | Medium |
| **Objective** | Manipulate NFC tag NDEF records and test NFC protocol-level relay and sniffing capabilities |
| **Title** | NFC Tag NDEF Manipulation and Payload Injection |
| **Prerequisites** | Proxmark3 or NFC writer hardware; writable NFC tags (NTAG213/215/216 or MIFARE Ultralight); test NFC reader/phone available |
| **Test Steps** | 1. Read existing NDEF content: `proxmark3-client -c "hf mf ndefread"` |
| | 2. Write test URL to tag: `proxmark3-client -c "hf mf ndefwrite -t \"https://security-test.example.com\""` |
| | 3. Verify NDEF record with test phone (scan tag) |
| | 4. Write custom NDEF with multiple records (URI + text): construct via proxmark3 Lua script |
| | 5. Test NFC relay: `proxmark3-client -c "hf 14a sniff"` to capture reader-card communication |
| | 6. Analyze captured communication for protocol-level vulnerabilities |
| **Expected Result** | NDEF records successfully written and read by standard NFC devices; captured sniff data reveals reader-card protocol exchange; relay setup demonstrated for distance extension testing |
| **Verification Method** | Test phone reads correct URL from reprogrammed tag; sniff capture shows complete ISO 14443-A frame exchange; NDEF content matches written payload exactly |
| **Related Tools** | proxmark3, libnfc |
| **Related Payload** | payloads.md 5.1, 5.2 |

---

## Usage Guide

### Filter by Severity

| Level | Test Cases | Description |
|------|----------|------|
| **Critical** | TC-BT-004, TC-BT-005 | Direct credential/card compromise; immediate access gain |
| **High** | TC-BT-003, TC-BT-006, TC-BT-007 | Require specific conditions or hardware but provide significant access |
| **Medium** | TC-BT-001, TC-BT-002, TC-BT-008 | Information gathering and manipulation; no direct system compromise |

### Order by Attack Phase

```
Reconnaissance (TC-001, TC-002) -> BLE Enumeration (TC-003) -> Encryption Crack (TC-004)
  -> RFID Key Recovery (TC-005) -> Card Clone (TC-006) -> Spoofing (TC-007) -> NFC Testing (TC-008)
```

### Hardware Requirements Matrix

| Test Case | Required Hardware |
|-----------|-------------------|
| TC-BT-001, TC-BT-002, TC-BT-007 | Bluetooth adapter (built-in or USB) |
| TC-BT-003 | BLE-capable adapter |
| TC-BT-004 | Ubertooth One (mandatory for capture) |
| TC-BT-005, TC-BT-006, TC-BT-008 | Proxmark3 (RDV4 recommended) or compatible NFC reader |

> **Legal Notice**: All test cases are restricted to authorized environments only. See `SKILL.md` for legal statement.

---

## Remediation and Defense Summary

### Bluetooth Defense

- Disable Bluetooth when not in use; set devices to non-discoverable mode by default
- Use BLE Secure Connections (LESC) pairing instead of Legacy Pairing to prevent crackle-based decryption
- Monitor for unauthorized Bluetooth scanning activity using btlog or Blue Hydra detection mode
- Implement Bluetooth device allowlisting on sensitive systems

### RFID/NFC Defense

- Upgrade from MIFARE Classic to MIFARE DESFire or SAM-based cards for access control
- Deploy RFID shielding (Faraday sleeves) for cards when not in active use
- Implement mutual authentication between readers and cards (challenge-response)
- Monitor for cloning attempts using reader-side anomaly detection (unexpected UID changes, timing anomalies)

### Pass Criteria Checklist

- [ ] All Bluetooth devices within range are identified and documented
- [ ] Non-discoverable devices detected via active probing
- [ ] BLE GATT services fully enumerated with sensitive characteristics identified
- [ ] Legacy Pairing encryption successfully cracked (or confirmed not in use)
- [ ] RFID card keys recovered and full dump created
- [ ] Card clone successfully authenticates against test reader
- [ ] Device identity spoofing tested against paired/trusted devices
- [ ] NFC tag manipulation and relay demonstrated
