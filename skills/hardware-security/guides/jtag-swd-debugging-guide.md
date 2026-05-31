# JTAG/SWD Debugging Guide

> Practical methodology for discovering JTAG and SWD debug interfaces on embedded devices, connecting to them, and extracting firmware through debug access ports.

## 1. Interface Discovery and Pin Identification

Locate debug headers on the target PCB using visual inspection and electrical probing.

```bash
# Common JTAG pinout (standard 20-pin ARM header)
# Pin 1:  VTref    Pin 2:  VCC
# Pin 3:  nTRST    Pin 4:  GND
# Pin 5:  TDI      Pin 6:  GND
# Pin 7:  TMS      Pin 8:  GND
# Pin 9:  TCK      Pin 10: GND
# Pin 11: RTCK     Pin 12: GND
# Pin 13: TDO      Pin 14: GND
# Pin 15: nSRST    Pin 16: GND
# Pin 17: DBGRQ    Pin 18: GND
# Pin 19: DBGACK   Pin 20: GND

# SWD uses only 2 data pins:
# SWDIO (data) - bidirectional
# SWCLK (clock)
# Plus VCC and GND

# Use JTAGulator to auto-detect pinout
# Connect all candidate pins to JTAGulator channels
# In JTAGulator serial console:
screen /dev/ttyUSB0 115200
# Set target voltage
voltage 3.3
# Run JTAG scan (specify number of connected channels)
jtag idcode 0 7
# Run SWD scan
swd idcode 0 7
```

## 2. Connecting with OpenOCD

```bash
# Install OpenOCD
sudo apt install openocd

# Create interface config for common adapters
# For ST-Link V2:
cat > stlink-target.cfg << 'EOF'
source [find interface/stlink.cfg]
transport select hla_swd
source [find target/stm32f4x.cfg]
adapter speed 4000
EOF

# For Bus Pirate as JTAG adapter:
cat > buspirate-jtag.cfg << 'EOF'
source [find interface/buspirate.cfg]
buspirate port /dev/ttyUSB0
buspirate speed normal
transport select jtag
adapter speed 1000

# Target: generic ARM Cortex-M
set _CHIPNAME cortexm
jtag newtap $_CHIPNAME cpu -irlen 4 -expected-id 0x4ba00477
target create $_CHIPNAME.cpu cortex_m -chain-position $_CHIPNAME.cpu
EOF

# Launch OpenOCD
openocd -f stlink-target.cfg
# OpenOCD listens on:
#   Port 3333 - GDB
#   Port 4444 - Telnet (command interface)
#   Port 6666 - TCL
```

## 3. Firmware Extraction via Debug Port

```bash
# Connect to OpenOCD telnet interface
telnet localhost 4444

# Halt the processor
> halt

# Identify flash memory regions
> flash list
# Output: {name stm32f4x base 0x08000000 size 0x100000 bus_width 0 chip_width 0}

# Dump entire flash to file
> flash read_bank 0 /tmp/firmware_dump.bin

# Dump specific memory regions
> dump_image /tmp/sram_dump.bin 0x20000000 0x20000
> dump_image /tmp/flash_dump.bin 0x08000000 0x100000

# Read individual registers
> reg
# Shows all CPU registers (r0-r15, cpsr, etc.)

# Resume execution
> resume
```

## 4. GDB Remote Debugging

```bash
# Connect GDB to OpenOCD's GDB server
arm-none-eabi-gdb

# In GDB:
(gdb) target remote localhost:3333
(gdb) monitor halt

# Dump memory regions
(gdb) dump binary memory flash.bin 0x08000000 0x08100000
(gdb) dump binary memory sram.bin 0x20000000 0x20020000

# Set breakpoints on interesting functions
(gdb) break *0x08001234
(gdb) continue

# Examine memory at runtime
(gdb) x/32xw 0x20000000
(gdb) x/s 0x08010000

# Step through code
(gdb) stepi
(gdb) info registers

# Find strings in memory (credentials, keys)
(gdb) find 0x08000000, 0x08100000, "password"
(gdb) find 0x20000000, 0x20020000, "admin"
```

## 5. Bypassing Read Protection

```bash
# Check if Read-Out Protection (RDP) is enabled
telnet localhost 4444
> stm32f4x lock_status

# For STM32 - RDP Level 1 can be downgraded (erases flash)
> stm32f4x unlock 0
# WARNING: This erases all flash contents

# Alternative: Voltage glitching to bypass RDP
# Using ChipWhisperer:
python3 << 'EOF'
import chipwhisperer as cw

scope = cw.scope()
target = cw.target(scope)
scope.default_setup()

# Configure glitch parameters
scope.glitch.clk_src = "clkgen"
scope.glitch.output = "enable_only"
scope.glitch.trigger_src = "ext_single"

# Sweep glitch timing to find bypass window
for width in range(1, 50):
    for offset in range(-40, 40):
        scope.glitch.width = width
        scope.glitch.offset = offset
        scope.glitch.ext_offset = 1000  # Adjust based on boot timing

        # Reset target and trigger glitch
        scope.io.nrst = 'low'
        time.sleep(0.05)
        scope.io.nrst = 'high'
        scope.arm()

        # Check if RDP bypass succeeded
        # Try reading flash via SWD
        if can_read_flash():
            print(f"BYPASS at width={width}, offset={offset}")
            dump_firmware()
            break
EOF
```

## 6. SWD-Specific Techniques

```bash
# SWD is more common on modern ARM Cortex-M devices
# Only needs SWDIO + SWCLK (2 wires vs 4-5 for JTAG)

# Using pyOCD for SWD access
pip install pyocd

# List connected probes
pyocd list

# Connect and identify target
pyocd commander -t cortex_m

# In pyOCD commander:
>>> target.halt()
>>> print(hex(target.read32(0xE000ED00)))  # Read CPUID
>>> target.read_memory_block8(0x08000000, 0x1000)  # Read flash

# Dump full firmware
pyocd cmd -t cortex_m -c "savemem 0x08000000 0x100000 firmware.bin"

# Using SWD with a Raspberry Pi GPIO
# Connect SWDIO to GPIO24, SWCLK to GPIO25
openocd -f interface/raspberrypi-native.cfg \
        -c "transport select swd" \
        -f target/stm32f1x.cfg
```

## 7. Post-Extraction Analysis

```bash
# Identify firmware format
file firmware_dump.bin
binwalk firmware_dump.bin

# Extract embedded filesystems
binwalk -e firmware_dump.bin

# Analyze ARM firmware with Ghidra
# Set base address to match flash origin (e.g., 0x08000000)
ghidra &
# File > Import > firmware_dump.bin
# Language: ARM:LE:32:Cortex (for Cortex-M)
# Options > Base Address: 0x08000000

# Search for hardcoded credentials
strings firmware_dump.bin | grep -iE "(pass|key|secret|token|admin)"

# Find interrupt vector table (first 4 bytes = initial SP)
hexdump -C firmware_dump.bin | head -20
# First word: Initial Stack Pointer
# Second word: Reset Handler address (entry point)
```

## 8. Countermeasure Assessment

```bash
# Check for common debug protections:

# 1. Debug Authentication (ARM CoreSight)
# Read Debug Authentication Status Register
telnet localhost 4444
> mdw 0xE000EDF0  # DHCSR - Debug Halting Control and Status

# 2. Check if debug port is disabled in option bytes
> mdw 0x1FFFC000  # Option bytes (STM32)

# 3. Test for JTAG fuse (permanently disabled)
# If IDCODE scan returns 0x00000000 or no response,
# debug port may be fused off

# 4. Check for software-based debug disable
# Look for writes to DBGMCU_CR that disable debug in sleep/stop
strings firmware_dump.bin | grep -i "dbgmcu"

# Document findings for report
echo "Debug Interface Assessment:" > debug_report.txt
echo "- JTAG: [enabled/disabled/fused]" >> debug_report.txt
echo "- SWD: [enabled/disabled/fused]" >> debug_report.txt
echo "- RDP Level: [0/1/2]" >> debug_report.txt
echo "- Glitch Susceptibility: [yes/no]" >> debug_report.txt
```
