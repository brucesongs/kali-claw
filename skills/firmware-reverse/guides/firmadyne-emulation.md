# Firmadyne Firmware Emulation

> Complete guide to setting up Firmadyne, ingesting firmware images, configuring network emulation, and performing dynamic analysis of running firmware services.

## Introduction and Objectives

Firmware emulation bridges the gap between static analysis and real-world testing by running extracted firmware in a virtualized environment. This guide walks through the complete Firmadyne workflow: from installing dependencies and configuring the PostgreSQL backend, through the automated ingestion pipeline, to booting firmware in QEMU and performing dynamic analysis of running services.

**Learning objectives**:

- Set up the Firmadyne environment with all dependencies (PostgreSQL, QEMU, binwalk)
- Execute the four-step ingestion pipeline (extract, identify architecture, create image, infer network)
- Boot firmware in QEMU using architecture-specific run scripts
- Troubleshoot common boot failures and fall back to manual QEMU emulation
- Configure network connectivity to interact with emulated firmware services
- Perform dynamic analysis including service enumeration and web interface testing

**Prerequisites**: A Linux system with KVM/QEMU support. An extracted firmware image (see `firmware-extraction-filesystem.md`). Basic familiarity with QEMU, TAP interfaces, and network configuration.

## Overview

Firmadyne is an automated firmware emulation framework that bridges the gap between static firmware analysis and dynamic testing. After extracting a firmware filesystem, the critical question becomes: "Does this vulnerability actually work against the running device?" Firmadyne automates the complex process of building QEMU images, configuring network interfaces, and booting firmware in an emulated environment.

The framework handles three architectures common in embedded devices: ARM (little-endian), MIPS (big-endian), and MIPS (little-endian). It automatically detects the firmware architecture, builds a QEMU disk image with the extracted rootfs, infers network configuration from the firmware's init scripts, and boots the image with appropriate QEMU parameters.

## Setup and Prerequisites

Firmadyne requires PostgreSQL for firmware metadata storage, QEMU for emulation, and binwalk for extraction. The setup process installs all dependencies and downloads pre-built QEMU kernels for supported architectures.

```bash
# Install system dependencies
sudo apt-get install -y postgresql qemu-system-arm qemu-system-mips \
  qemu-system-mipsel binwalk python3-pip

# Clone Firmadyne
git clone https://github.com/firmadyne/firmadyne.git
cd firmadyne

# Download pre-built binaries (QEMU kernels and Firmadyne helper binaries)
./download.sh

# Setup PostgreSQL database
sudo service postgresql start
sudo -u postgres createuser -P firmadyne    # set password: firmadyne
sudo -u postgres createdb -O firmadyne firmware
sudo -u postgres psql -d firmware < ./database/schema
```

Configure the database connection in `firmadyne.config`:

```bash
cat > firmadyne.config << 'EOF'
FIRMADYNE_PATH=/opt/firmadyne
DATABASE_HOST=127.0.0.1
DATABASE_USER=firmadyne
DATABASE_PASS=firmadyne
DATABASE_NAME=firmware
EOF
```

## Firmware Ingestion Pipeline

The ingestion pipeline processes a raw firmware image through extraction, architecture detection, database storage, and QEMU image creation.

**Step 1: Extract firmware**

The extractor runs binwalk, extracts the filesystem, and stores metadata in PostgreSQL.

```bash
sudo python3 ./sources/extractor/extractor.py -b firmware.bin -sql \
  -np -nk "TP-Link WR841N v16" images
```

Flags:
- `-b` -- Run binwalk extraction
- `-sql` -- Store results in PostgreSQL database
- `-np` -- Do not use containerized binwalk (use system binwalk)
- `-nk` -- Do not keep binary containers after extraction

The extractor assigns an image ID (integer) used in all subsequent steps.

**Step 2: Identify architecture**

```bash
sudo python3 ./scripts/getArch.py images/<image_id>.tar.gz
```

This analyzes the extracted binaries to determine the CPU architecture and endianness. The output is stored in the database and determines which QEMU binary is used for emulation.

**Step 3: Create QEMU disk image**

```bash
sudo python3 ./scripts/makeImage.sh <image_id>
```

This step creates a QEMU disk image containing the extracted rootfs. It patches the firmware's init system to work within the emulated environment (e.g., modifying `/etc/init.d/` scripts, fixing device paths, disabling hardware-specific services that would fail in QEMU).

**Step 4: Infer network configuration**

```bash
sudo python3 ./scripts/inferNetwork.sh <image_id>
```

This is the most sophisticated step. Firmadyne analyzes the firmware's network configuration scripts, DHCP configurations, and routing tables to determine the network topology the firmware expects. It then creates appropriate TAP interfaces and configures IP addresses so the emulated firmware's network services are accessible from the host.

## QEMU-Based Emulation

After the ingestion pipeline completes, boot the firmware with the architecture-specific run script:

```bash
# ARM (little-endian) -- common in modern routers and IoT devices
sudo ./scripts/run.armel.sh <image_id>

# MIPS (big-endian) -- common in older Broadcom/Atheros routers
sudo ./scripts/run.mipseb.sh <image_id>

# MIPS (little-endian) -- common in MediaTek/Atheros routers
sudo ./scripts/run.mipsel.sh <image_id>
```

The run script launches QEMU with the correct machine type, kernel image, disk image, and network configuration inferred in Step 4.

### Manual QEMU Emulation (When Firmadyne Fails)

Firmadyne's automation does not handle all firmware variants. When the automated pipeline fails, manual QEMU emulation provides more control:

```bash
# ARM manual emulation
qemu-system-arm -M versatilepb \
  -kernel /opt/firmadyne/binaries/vmlinux.armel \
  -drive file=/opt/firmadyne/images/<image_id>.qcow2,format=qcow2 \
  -m 256M -nographic \
  -append "root=/dev/sda1 console=ttyAMA0 rootfstype=squashfs" \
  -net nic -net tap,ifname=tap0,script=no

# MIPS (little-endian) manual emulation
qemu-system-mipsel -M malta \
  -kernel /opt/firmadyne/binaries/vmlinux.mipsel \
  -drive file=/opt/firmadyne/images/<image_id>.qcow2,format=qcow2 \
  -m 256M -nographic \
  -append "root=/dev/sda1 console=ttyS0 rootfstype=squashfs" \
  -net nic -net tap,ifname=tap0,script=no
```

### Common Boot Failures and Solutions

| Symptom | Cause | Solution |
|---------|-------|----------|
| Kernel panic: no init found | Root filesystem not mounted | Change `root=` parameter; try `/dev/sda`, `/dev/sda2`, or use `rootfstype=jffs2` |
| Kernel panic: not syncing | Wrong machine type | Try `-M realview-pb-a8` (ARM) or `-M malta` (MIPS) |
| No network connectivity | TAP interface not configured | Manually configure: `ifconfig tap0 <ip> up` |
| Services fail to start | Hardware dependencies | Patch init scripts to skip hardware checks |
| Hang during boot | Serial console mismatch | Try different `console=` parameters: `ttyS0`, `ttyAMA0`, `ttyS1` |

## Network Configuration

Firmadyne's `inferNetwork.sh` creates a TAP interface for communication with the emulated firmware. For manual setup:

```bash
# Create TAP interface
sudo tunctl -t tap0
sudo ifconfig tap0 192.168.0.1 netmask 255.255.255.0 up

# Enable NAT for internet access from emulated firmware
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -i tap0 -o eth0 -j ACCEPT
sudo iptables -A FORWARD -i eth0 -o tap0 -m state --state RELATED,ESTABLISHED -j ACCEPT

# Port forwarding for web service access
sudo iptables -t nat -A PREROUTING -p tcp --dport 8080 -j DNAT --to-destination 192.168.0.2:80
```

## Dynamic Analysis of Running Firmware

Once firmware is running in QEMU, perform dynamic testing:

**Service Enumeration**:
```bash
# Scan emulated firmware from host
nmap -sV -p- 192.168.0.2

# Common ports to check: 21 (FTP), 22 (SSH), 23 (Telnet), 80/443 (HTTP),
# 8080 (alt HTTP), 543 (Klog), 161 (SNMP)
```

**Web Interface Testing**:
```bash
# Identify web server
curl -I http://192.168.0.2/

# Directory enumeration
dirb http://192.168.0.2/ /usr/share/wordlists/dirb/common.txt

# Test authentication
curl -u admin:admin http://192.168.0.2/
curl -u admin:password http://192.168.0.2/
```

**Process Monitoring** (inside emulated firmware console):
```bash
ps aux                   # List running processes
netstat -tlnp            # List listening ports
cat /etc/passwd          # Check user accounts
cat /etc/shadow          # Check password hashes
ls -la /tmp/             # Check for temporary files with sensitive data
```

## Limitations and Caveats

Firmadyne emulation is not perfect. Common limitations include:

- **Hardware-specific peripherals** (GPIO, I2C sensors, wireless radios) cannot be emulated. Services depending on these peripherals will fail.
- **Memory-mapped I/O** access to hardware registers will cause segfaults or hangs in the emulated environment.
- **NVRAM/flash operations** may fail because the emulated environment does not have real flash partitions. Firmadyne patches some NVRAM implementations but not all.
- **Timing-dependent code** (watchdog timers, hardware polling loops) may behave differently under emulation.

Always validate critical findings against the actual hardware device when possible. Emulation is a powerful triage tool but should not be the sole basis for critical vulnerability reports.

## Hands-on Exercise: Firmware Emulation

Practice the complete firmware emulation workflow:

**Setup**:

```bash
# Download a known-working firmware image for testing
wget https://firmware.example.com/test-router-v1.bin
# Or use a firmware image from the Firmadyne test set
```

**Exercise steps**:

1. Complete the Firmadyne setup (PostgreSQL, QEMU kernels, helper binaries)
2. Run the extractor on the test firmware image and record the assigned image ID
3. Identify the architecture and create the QEMU disk image
4. Run `inferNetwork.sh` and examine the inferred network configuration
5. Boot the firmware with the appropriate run script and observe the boot sequence
6. If boot succeeds, scan the emulated firmware with nmap to identify running services
7. If boot fails, diagnose the issue using the troubleshooting table and attempt manual QEMU boot
8. Configure TAP interface networking and verify you can access the firmware's web interface
9. Test authentication against the web interface with common default credentials

**Validation criteria**: Successfully boot at least one firmware image in QEMU. Identify at least three running services. Access the web administration interface and document default credentials if found.

## References and Resources

- [Firmadyne GitHub Repository](https://github.com/firmadyne/firmadyne)
- [Firmadyne Paper - Scalable Dynamic Analysis](https://www.ndss-symposium.org/ndss2015/ndss-2015-programme/)
- [QEMU Documentation](https://www.qemu.org/docs/master/)
- [binwalk Wiki](https://github.com/ReFirmLabs/binwalk/wiki)
- [OWASP IoT Firmware Testing Guide](https://owasp.org/www-project-iot-security-verification-standard/)
