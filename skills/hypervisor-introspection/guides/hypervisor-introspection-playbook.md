# Hypervisor Introspection (VMI) and Virtualization Escape Playbook

> Comprehensive playbook for hypervisor introspection (VMI) and virtualization escape assessment. Covers Type-1 and Type-2 hypervisors, hardware-assisted virtualization, VMI tooling, real-world incident analysis, lab setup, and defensive guidance. For authorized security testing only.

---

## Table of Contents

1. [Hypervisor Landscape and Comparison Matrix](#1-hypervisor-landscape-and-comparison-matrix)
2. [Hardware-assisted Virtualization Primitives](#2-hardware-assisted-virtualization-primitives)
3. [Attack Surface Taxonomy](#3-attack-surface-taxonomy)
4. [Virtual Machine Introspection (VMI) Use Cases](#4-virtual-machine-introspection-vmi-use-cases)
5. [Real-World Incidents and Lessons Learned](#5-real-world-incidents-and-lessons-learned)
6. [Lab Setup](#6-lab-setup)
7. [Defensive Guidance](#7-defensive-guidance)
8. [Engagement Workflow](#8-engagement-workflow)
9. [Reporting Templates](#9-reporting-templates)
10. [Common Mistakes and Anti-Patterns](#10-common-mistakes-and-anti-patterns)
11. [Future Directions](#11-future-directions)
12. [References](#12-references)

---

## 1. Hypervisor Landscape and Comparison Matrix

### 1.1 Type-1 vs Type-2

The traditional taxonomy divides hypervisors into two classes:

- **Type-1 (bare-metal)**: The hypervisor runs directly on the hardware, without a host OS underneath. The hypervisor itself is the kernel. Examples: VMware ESXi (vmkernel), Microsoft Hyper-V (when the host boots directly into the hypervisor), Xen (hypervisor boots first, then Dom0), Proxmox VE (Debian + KVM, technically the host kernel is the hypervisor).
- **Type-2 (hosted)**: The hypervisor runs as a process on top of a host OS. The host OS kernel manages hardware; the hypervisor translates guest operations to host syscalls. Examples: VMware Workstation/Fusion, VirtualBox, Parallels Desktop, QEMU in pure-emulation mode (no KVM).

In practice the distinction has blurred:
- KVM is technically Type-1 (the Linux kernel becomes the hypervisor when KVM is loaded) but is usually categorized as Type-2 because the host is a general-purpose Linux distribution.
- Hyper-V is sometimes called "Type-1.5" because the parent partition (host OS) runs on top of the hypervisor but has special privileges.
- Xen is unambiguously Type-1, but Dom0 is a privileged guest that handles device drivers.

### 1.2 Hypervisor Comparison Matrix

| Hypervisor | Type | Vendor | Default Devices | Management Plane | Notable CVE Family |
|------------|------|--------|-----------------|------------------|---------------------|
| **VMware ESXi** | 1 | VMware | vmxnet3, pvscsi, vmware-tools | hostd (443), MOB, SLP (427), SSH (22), DCUI | VMSA series, OpenSLP (CVE-2021-21974), vCenter analytics (CVE-2021-22005) |
| **VMware vCenter** | 1 (appliance) | VMware | — | vpxd (443), REST API (/api), SOAP (/sdk) | SSO bypass (CVE-2022-31656), vSphere Client CVEs |
| **VMware Workstation/Fusion** | 2 | VMware | vmxnet, vmware-tools | local GUI, vmrun CLI | Local LPE in vmware-authd, VIX API issues |
| **Microsoft Hyper-V** | 1 (with parent partition) | Microsoft | netvsc, storvsc, vmbus | WMI (root\virtualization\v2), Hyper-V Manager, Failover Cluster | vmbus.sys RCE series (CVE-2017-0180, CVE-2023-21558) |
| **KVM/QEMU** | 1/2 hybrid | OSS (Linux kernel) | virtio-net/blk/scsi, e1000, IDE | libvirt (16509), virsh, virt-manager | QEMU device emulation (VENOM CVE-2015-3456, PCNET CVE-2015-7504, USB XHCI CVE-2020-14364, e1000e CVE-2021-3947) |
| **Xen** | 1 | OSS (Linux Foundation) | netback/blkback (PV), qemu-xen (HVM) | xl, XenStore, XenCenter (xe) | XSA series (XSA-148, XSA-182, XSA-242, XSA-253, XSA-417, XSA-419) |
| **Proxmox VE** | 1 (Debian + KVM) | Proxmox | virtio, cloud-init | pveproxy (8006), qm, pct, Corosync (UDP 5404/5405) | Inherits KVM CVEs plus pveproxy issues |
| **VirtualBox** | 2 | Oracle | vboxnet, guest-additions | VBoxManage CLI, web UI (historical) | VRDE (CVE-2018-2693), guest additions CVEs |
| **Parallels Desktop** | 2 | Parallels | parallels-tools | prlctl CLI | Local LPE in helper tools (CVE-2021-31440) |
| **bhyve** | 1 (FreeBSD) | OSS | virtio | bhyve CLI, vm-bhyve | Fewer public CVEs; smaller attack surface |
| **AHV (Nutanix)** | 1 (KVM-based) | Nutanix | virtio | Prism Central (9440), acli | Inherits KVM CVEs |
| **Apple Virtualization Framework** | 1 | Apple | virtio | swift API, no CLI | Newer; less public CVE research |

### 1.3 Hardware-assisted Virtualization Comparison

| Feature | Intel VT-x | AMD-V (SVM) | ARMv8-A |
|---------|-----------|-------------|---------|
| **CPU modes** | VMX root / VMX non-root | Host / Guest (via EFER.SVME) | EL1 (guest) / EL2 (hypervisor) / EL3 (secure monitor) |
| **Per-VCPU state** | VMCS (Virtual Machine Control Structure) | VMCB (Virtual Machine Control Block) | VTCR_EL2, VTTBR_EL2 |
| **Second-level paging** | EPT (Extended Page Tables) | NPT (Nested Page Tables) / RVI | Stage-2 page tables |
| **TLB tagging** | VPID | ASID | VMID |
| **IOMMU** | Intel VT-d | AMD-Vi / AMD IOMMU | SMMU (System MMU) |
| **Posted interrupts** | Yes | Yes (AVIC) | Yes (GICv3) |
| **Nested virtualization** | Yes (VMCS shadowing) | Yes (since AMD-V gen 2) | Yes (since ARMv8.3) |
| **Confidential computing** | Intel TDX | AMD SEV / SEV-ES / SEV-SNP | ARM CCA / Realm |
| **Notable malicious hypervisors** | Vitriol, SubVirt | BluePill | (less research) |

### 1.4 Cross-platform Notes

- Apple Silicon (M1/M2/M3) has its own virtualization story: the host runs at EL1 with the Apple Hypervisor at EL2, exposed via the `Hypervisor.framework`. KVM is not mainstream on Apple Silicon; the Asahi Linux project has reverse-engineered much of the hypervisor.
- ARM servers (Ampere Altra, AWS Graviton) run standard KVM with ARM virtualization extensions. The attack surface is similar to x86 KVM but the device tree differs.
- IBM POWER has its own hypervisor (PHYP - POWER Hypervisor) with a separate CVE family. Out of scope for this skill but worth noting for mainframe engagements.

---

## 2. Hardware-assisted Virtualization Primitives

### 2.1 VMX Root Mode (Intel)

VMX provides two execution modes: VMX root (the hypervisor) and VMX non-root (the guest). The hypervisor enters root mode with `VMXON`, configures a VMCS (Virtual Machine Control Structure) per virtual CPU, and launches the guest with `VMLAUNCH`. The guest runs in non-root mode until it triggers a `#VMEXIT`, which transfers control back to the hypervisor at a predefined RIP.

Key primitives:
- **VMXON / VMXOFF**: enter / exit VMX root mode
- **VMPTRLD / VMCLEAR**: load / clear current VMCS
- **VMLAUNCH / VMRESUME**: launch a new guest / resume after exit
- **VMREAD / VMWRITE**: read / write VMCS fields
- **VMCALL**: explicit hypercall from guest to hypervisor
- **INVEPT / INVVPID**: invalidate EPT / VPID TLB entries

VMCS fields control every aspect of guest execution: guest registers, host registers (saved on exit), execution controls (exceptions that cause exits, I/O bitmaps, MSR bitmaps), and entry/exit controls.

### 2.2 SVM (AMD)

AMD-V's SVM (Secure Virtual Machine) is functionally equivalent to Intel VMX but with different instructions and data structures:
- **VMRUN**: launch guest (interacts with VMCB)
- **#VMEXIT**: implicit, transfers control to host RIP stored in VMCB
- **VMMCALL**: explicit hypercall
- **VMLOAD / VMSAVE**: load / save extended guest state
- **INVLPGA**: invalidate guest ASID TLB entry

The VMCB (Virtual Machine Control Block) is a 4KB-aligned structure containing both control area (intercepts, exception filtering) and state save area (guest registers).

### 2.3 EPT and NPT (Second-level Paging)

Without second-level paging, a guest's virtual address must be translated to a guest physical address (via the guest's page tables) and then to a host physical address (via a shadow page table maintained by the hypervisor). Shadow page tables are expensive to maintain.

EPT (Intel) and NPT (AMD) add a second level of address translation: guest virtual -> guest physical (via guest page tables) -> host physical (via EPT/NPT). The CPU walks both tables in hardware, removing the shadow page table maintenance burden.

EPT/NPT also enable **memory hiding**:
- Set up two EPT entries for the same guest physical page: one presents the real page, one presents a decoy.
- Use EPT violation (or NPT #VMEXIT) to swap entries based on access type.
- Result: a page that reads one thing and executes another. Used by HyperPlatform-based defensive tools to hide EPT hooks.

### 2.4 Posted Interrupts and AVIC

Posted interrupts (Intel) and AVIC (AMD) allow a virtual interrupt to be delivered to a guest vCPU without the hypervisor getting involved. The hypervisor writes the interrupt to a per-vCPU "posted interrupt descriptor" and sends an IPI; the CPU delivers the interrupt directly to the guest. This is critical for performance but also a (small) attack surface: bugs in posted interrupt handling could allow a guest to inject interrupts into the wrong vCPU or escape the virtual APIC.

### 2.5 Confidential Computing Extensions

Modern extensions add hardware-attested guest memory encryption:
- **Intel TDX (Trust Domain Extensions)**: introduces a "Trust Domain" (TD) concept. Guest memory is encrypted with a key the hypervisor cannot read. The hypervisor loses introspection but gains assurance against operator-side attacks.
- **AMD SEV / SEV-ES / SEV-SNP**: SEV encrypts per-VM; SEV-ES also encrypts register state on #VMEXIT; SEV-SNP adds integrity protection (a reverse-map table prevents the hypervisor from remapping guest pages).
- **ARM CCA (Confidential Compute Architecture)**: introduces "Realms" — guests with hardware-attested isolation.

The threat model for confidential computing is different: the hypervisor operator is the adversary. VMI is no longer possible (the hypervisor cannot read guest memory). Audit targets shift to:
- Firmware in the measured launch (OVMF/UEFI)
- Guest kernel attestation flow
- Side-channel attacks via shared cache lines
- Hardware bugs that leak the encryption key

---

## 3. Attack Surface Taxonomy

A hypervisor exposes attack surface at three layers:

### 3.1 Management Plane

The control plane used by administrators to create, configure, and migrate VMs. Examples:
- VMware: vCenter SOAP API, REST API, MOB, ESXi hostd
- Hyper-V: WMI provider (root\virtualization\v2), Hyper-V Manager, Failover Cluster Manager
- KVM/QEMU: libvirt (16509 TCP, qemu+ssh), virsh, virt-manager
- Xen: xl, XenStore, XenServer API
- Proxmox: pveproxy (8006)

Management plane compromise is the dominant attack vector for ESXi ransomware crews. They rarely exploit a hypervisor CVE; they walk in via stolen credentials or unpatched management plane services.

### 3.2 Hypervisor Process / Kernel

The actual hypervisor code running on the host. Examples:
- VMware: vmware-vmx (per-VM process), vmkernel (host kernel)
- Hyper-V: VMWP.exe (per-VM worker process), ntoskrnl with virtualization drivers (vmbus.sys, vid.sys, hvp.sys)
- KVM/QEMU: qemu-system-x86_64 (per-VM process), kvm.ko + kvm-intel.ko / kvm-amd.ko (host kernel modules)
- Xen: hypervisor itself, qemu-dp / qemu-system-i386 (device model for HVM guests), Dom0 kernel (toolstack)
- Proxmox: qemu-system (per-VM), kvm modules, plus the LXC userland (for containers)

Bugs here are the classic "VM escape" CVEs: VENOM, PCNET, USB XHCI, vmbus.sys, etc.

### 3.3 Paravirtualized Backends

The PV drivers that handle guest I/O requests without full device emulation. Examples:
- VMware: vmxnet3, pvscsi, vmware-tools
- Hyper-V: netvsc, storvsc, vmbus itself
- KVM: virtio-net, virtio-blk, virtio-scsi, virtio-gpu, virtio-balloon, virtio-console, virtio-rng; in-kernel vhost-net and vhost-scsi
- Xen: netback, blkback (PV); virtio backends via qemu-xen (HVM)
- Proxmox: inherits KVM's virtio

PV backends are written for performance, not security, and have been the source of multiple high-severity escape bugs. Auditors frequently focus on emulated legacy devices (floppy, PCNET) because they are well-known, while skipping the PV drivers that are actually enabled in production.

---

## 4. Virtual Machine Introspection (VMI) Use Cases

### 4.1 Stealth Malware Analysis

Traditional malware analysis runs the sample in a VM and instruments it from inside (hooks, debuggers, sandboxes). Sophisticated malware detects this instrumentation and behaves differently — or refuses to run at all. VMI solves this by instrumenting from outside the guest, using the hypervisor's privileged vantage point.

**DRAKVUF** is the leading open-source dynamic malware analysis platform built on Xen + LibVMI. It can:
- Inject a process into a running guest without the guest knowing
- Trap and log every syscall
- Trap file, registry, and network operations
- Extract dropped binaries
- Trace kernel-mode rootkit behavior

The malware cannot detect this because:
- No in-guest instrumentation exists (no hooks, no debugger, no agents)
- The traps are EPT-based (memory pages) or breakpoint-based (INT3 in guest memory), invisible to guest-mode code
- Timing impact is small (DRAKVUF's trap absorption features reduce overhead)

### 4.2 Memory Forensics from Outside the Guest

Traditional memory forensics requires an agent in the guest (e.g., WinPMEM) or a crash dump. Both require guest cooperation and can be subverted by rootkits. VMI captures guest RAM from the hypervisor:
- `virsh dump <domain> dump.bin --memory-only` (libvirt)
- `pmemsave` QMP command (QEMU)
- ESXi snapshot (.vmsn file contains RAM)
- Hyper-V `Save-VM` (.bin file)
- VMware Workstation/Fusion suspend (.vmem file)

The dump can then be analyzed by Volatility 3 or Rekall without ever touching the guest.

### 4.3 Kernel-mode Rootkit Detection

A kernel-mode rootkit in a guest can unlink itself from the Active Process Head, hide its kernel module from the module list, and hook system calls. From inside the guest, these manipulations are invisible. From outside the guest:
- Walk the Active Process Head via LibVMI
- Walk the PspCidTable (Windows handle table) via LibVMI
- Compare: any discrepancy reveals hidden processes
- Read SSDT and IDT to detect hooks
- Read kernel module list (PsLoadedModuleList) to detect hidden modules

This is the basis for the Hunter and Moneta defensive tools (HyperPlatform-based).

### 4.4 Out-of-guest EDR for Legacy OS

Some guests cannot run modern EDR: legacy Windows (XP/2003), embedded OS (VxWorks, QNX), or hardened systems that disallow kernel drivers. VMI deploys detection on the hypervisor host, monitoring every guest without requiring any in-guest component.

### 4.5 Live Patch Verification

After patching a guest (e.g., a critical kernel CVE), VMI can verify that the patched code is actually loaded in memory — not just present on disk. This catches cases where a guest has been told to reboot but hasn't, or where a rootkit has reverted the patch in memory.

### 4.6 Hypervisor-based Defense (HyperPlatform, DdiMon, Hunter, Moneta)

These tools deploy a thin Intel VT-x hypervisor on a Windows host, then use EPT hooks to monitor specific kernel functions:
- **HyperPlatform**: the framework itself
- **DdiMon**: monitors specific DDI (Device Driver Interface) functions for credential theft
- **Hunter**: detects in-memory code injection (process hollowing, etc.) via EPT
- **Moneta**: detects in-memory anomalies (RWX pages, unbacked executable memory)

These tools detect kernel rootkits that would be invisible from inside the OS.

---

## 5. Real-World Incidents and Lessons Learned

### 5.1 VENOM (CVE-2015-3456, 2015)

**What**: Buffer overflow in the QEMU floppy disk controller emulation (`hw/fdc.c`). The flaw was in the `fdctrl_to_command()` handler: it copied command data into a fixed-size buffer without bounds-checking the track number. A guest could issue a malformed READ_ID command with a track value > 79 (the default maximum) and overflow the buffer.

**Who disclosed**: Jason Geffner of CrowdStrike. The disclosure process was exemplary: 12 months of coordinated disclosure with QEMU, Xen, Red Hat, SUSE, etc. before public release.

**Impact**: Affected every QEMU-based platform — Xen, KVM/QEMU, and any platform that shipped QEMU's floppy backend. The vulnerable code had been present since 2004.

**Why it matters**: VENOM is the canonical example of a guest-to-host escape. It established the playbook for hypervisor escape disclosure and remediation.

**Lessons**:
- Legacy device emulation kept for compatibility is a persistent source of escape bugs. The floppy device had no legitimate use in modern VMs but was enabled by default until QEMU 2.x.
- The disclosure model worked. 12 months of coordinated work meant that patches were available the day the CVE went public.
- The vulnerability was in the device emulation, not in the hypervisor itself (KVM/Xen/VMware). This is typical — KVM and Xen rarely have direct escape CVEs; their device models (QEMU) do.

**Remediation today**: QEMU 5.x+ ships with `-nodefaults` recommended; modern virt-manager / libvirt configurations do not include a floppy by default. Audit: `ps aux | grep qemu-system | grep -E 'fda|fdc'` should return nothing.

### 5.2 VMware OpenSLP (CVE-2019-5544, CVE-2020-3992, CVE-2021-21974)

**What**: ESXi shipped an outdated OpenSLP daemon on UDP 427 for service discovery. The daemon had multiple memory corruption vulnerabilities, each leading to unauthenticated remote code execution on the ESXi host itself.

**Who disclosed**: Various researchers across three years.

**Impact**: CVE-2021-21974 was the basis for ESXiArgs ransomware in February 2023, two years after the patch was released. Thousands of internet-facing ESXi hosts that had not patched were compromised.

**Why it matters**: OpenSLP is a textbook example of an auxiliary service that should have been disabled by default. VMware shipped it for years despite three successive critical CVEs.

**Lessons**:
- Auxiliary services on the management plane are escape vectors. SLP, CIM, SNMP, SSH, DCUI, MOB — each is an attack surface.
- Even two-year-old CVEs become mass-exploitation vectors when management planes are exposed.
- The patch worked. ESXiArgs hit only hosts that had not applied the patch in two years. Patching is the highest-ROI defensive action.

**Remediation today**: Stop the SLP daemon: `/etc/init.d/slpd stop; chkconfig slpd off`. Block UDP 427 at the ESXi firewall. Migrate the management network to a dedicated non-routable VLAN.

### 5.3 ESXiArgs Ransomware (February 2023)

**What**: A ransomware crew mass-exploited CVE-2021-21974 (OpenSLP) against thousands of internet-facing ESXi hosts. The encryptor:
- Dropped payload to /tmp/, executed via /bin/sh -c
- Modified /etc/rc.local.d/local.sh for persistence (until reboot)
- Suspended VMs via `vim-cmd vmsvc/power.suspend`
- Encrypted .vmdk files, renamed .vmdk.args
- Left ransom note in /etc/motd

**Impact**: Thousands of ESXi hosts compromised globally, including French hospitals, US schools, and German universities. Many victims had no offline backups.

**Why it matters**: This is the canonical example of a modern ESXi ransomware operation. The technique was simple (suspend VMs, encrypt VMDKs), but the impact was catastrophic because the targets had no offline backups and no rapid recovery plan.

**Lessons**:
- Patch velocity matters. The patch was two years old; the victims did not apply it.
- Offline backups are mandatory. Cloud backups are insufficient if the cloud account is on the same management plane.
- Internet-facing ESXi is unacceptable. Every production ESXi host must be behind a VPN or jump host.
- ESXi's vmfs file system makes recovery harder than NTFS — encrypted VMFS volumes cannot be partially recovered.

**Remediation today**: Migrate management plane to dedicated VLAN. Apply VMSA patches within 7 days for Critical CVEs. Maintain offline (air-gapped) backups of all critical VMs. Test restore-from-backup quarterly.

### 5.4 Akira / Royal / BlackCat / Play ESXi Ransomware (2023-2024)

**What**: Multiple ransomware crews pivoted from Windows targets to ESXi. Their techniques converged:
- Initial access via stolen VPN credentials (often from info-stealer malware on an administrator's laptop)
- Lateral movement to vCenter via SSH/HTTPS
- Use of `vim-cmd` to suspend VMs
- Encryption of .vmdk, .vmx, .vmsn, .lck files
- Renamed to .akira / .royal / .blackcat / .play extensions

**Impact**: Hundreds of organizations compromised globally. Many paid ransoms because they could not recover from backups.

**Why it matters**: These crews did NOT use a hypervisor CVE. They used management-plane credential theft. The defense is not better patching — it is better credential hygiene and MFA on vCenter SSO.

**Lessons**:
- The dominant ESXi ransomware vector is credential theft, not CVE exploitation.
- vCenter SSO must have MFA. Default `administrator@vsphere.local` with a password is unacceptable.
- VPN credentials must be MFA-protected. Info-stealer malware on an admin laptop is the most common ransomware entry point.
- vSphere admin accounts must not be Domain Admins. Separate realms.

### 5.5 Hyper-V vmbus (CVE-2017-0180 and successors)

**What**: Multiple CVEs in the Hyper-V vmbus.sys driver, the paravirtualized communication channel between guest and host. A guest could trigger memory corruption in vmbus.sys via malformed channel messages.

**Impact**: Hyper-V guest-to-host escape. Microsoft patched in monthly rollups (MS17-0113 and successors).

**Why it matters**: Hyper-V flaws tend to be in the paravirtualized vmbus backend, not in emulated devices, because Hyper-V does not ship legacy device emulation by default.

**Lessons**:
- Apply MSRC monthly rollups within 7 days for Critical.
- Audit vmbus.sys version on every Hyper-V host.
- Monitor VMWP.exe for unexpected child processes (sign of escape).
- Run Hyper-V guests with minimum integration services.

### 5.6 BluePill / SubVirt (2006)

**What**: Proof-of-concept thin hypervisors deployed beneath a running OS, using AMD SVM (BluePill, Joanna Rutkowska) or Intel VT-x (SubVirt, King et al.). The OS continues to run, but is now a guest; the malicious hypervisor can hide memory via NPT/EPT and intercept any operation.

**Impact**: Conceptual rather than operational. BluePill demonstrated that hardware-assisted virtualization is dual-use: the same primitives that power legitimate hypervisors enable stealth rootkits.

**Why it matters**: BluePill and SubVirt are the foundation of modern hypervisor-based rootkit research. The defensive counterpart is HyperPlatform, DdiMon, Hunter, Moneta — which deploy the same primitives for defense.

**Lessons**:
- Hardware-assisted virtualization is dual-use. Defenders must monitor for unexpected thin hypervisors.
- Detection is possible via timing (RDTSC differences), CPUID leaf 0x40000000 anomalies, and IA32_FEATURE_CONTROL MSR inspection.
- The same primitives that enable stealth rootkits also enable stealth defense.

### 5.7 Confidential Computing Shift (2023+)

**What**: AMD SEV-SNP, Intel TDX, and ARM CCA introduce hardware-attested guest memory encryption. The hypervisor cannot read guest memory; the guest attests the hypervisor at boot.

**Impact**: VMI is no longer possible. Defenders must redesign detection:
- In-guest agents only (cannot subvert rootkits)
- Hardware attestation (TPM-based, runs in TEE)
- Side-channel monitoring (cache, power)

**Why it matters**: This is the next decade's challenge. VMI was the gold standard for stealth malware analysis; with confidential computing, the gold standard shifts to attestation and in-guest instrumentation.

---

## 6. Lab Setup

### 6.1 Nested ESXi on VMware Workstation/Fusion

Use case: ESXi shell enumeration, VIB packaging, OpenSLP testing, MOB exploration.

Steps:
1. On the host (Workstation Pro 16+ or Fusion Pro 12+), verify VT-x and EPT are enabled in BIOS.
2. Create a new VM with hardware version 17+.
3. Edit the .vmx file:
   ```
   vhv.enable = "TRUE"
   guestOS = "vmkernel6"
   ```
4. Boot from the ESXi 7.0/8.0 ISO.
5. Install ESXi to the virtual disk.
6. After installation, the nested ESXi can run its own VMs (double-nested), but performance is poor.
7. For OpenSLP testing, configure the management network on an isolated vSwitch.

### 6.2 KVM on Linux with Nested Virtualization

Use case: QEMU device emulation CVE reproduction, LibVMI deployment, DRAKVUF analysis.

Steps:
1. Install KVM and libvirt:
   ```bash
   sudo apt-get install qemu-kvm libvirt-daemon-system libvirt-clients \
       virt-manager bridge-utils
   ```
2. Enable nested virtualization (Intel):
   ```bash
   echo "options kvm-intel nested=1" | sudo tee /etc/modprobe.d/kvm-intel.conf
   sudo modprobe -r kvm-intel && sudo modprobe kvm-intel
   cat /sys/module/kvm_intel/parameters/nested    # Should be Y
   ```
3. Create a network bridge for VMs to share host LAN:
   ```bash
   sudo brctl addbr br0
   sudo brctl addif br0 eth0
   sudo ip addr flush dev eth0
   sudo ip addr add 192.168.1.10/24 dev br0
   sudo ip link set br0 up
   ```
4. Define and start a VM:
   ```bash
   virt-install --name=win7lab \
     --os-variant=win7 \
     --vcpus=2 --ram=2048 \
     --disk path=/var/lib/libvirt/images/win7lab.qcow2,size=40,format=qcow2 \
     --cdrom=/path/to/win7.iso \
     --network bridge=br0 \
     --graphics spice
   ```

### 6.3 QEMU with Debugging Symbols

Use case: QEMU CVE PoC reproduction, device emulation bug analysis.

Steps:
1. Clone QEMU and check out a specific vulnerable version:
   ```bash
   git clone https://gitlab.com/qemu-project/qemu.git
   cd qemu && git checkout v2.3.0    # For VENOM reproduction
   ```
2. Configure with debug enabled:
   ```bash
   mkdir build && cd build
   ../configure --target-list=x86_64-softmmu --enable-debug --enable-debug-info \
     --extra-cflags='-O0 -g3'
   make -j$(nproc) && sudo make install
   ```
3. Launch QEMU with GDB stub:
   ```bash
   qemu-system-x86_64 \
     -m 2048 -hda disk.qcow2 \
     -S -gdb tcp::1234 \
     -monitor stdio
   ```
4. Attach from another terminal:
   ```bash
   gdb -ex 'target remote :1234' ./build/qemu-system-x86_64
   ```

### 6.4 Xen on Debian

Use case: XSA verification, LibVMI deployment on Xen, DRAKVUF analysis.

Steps:
1. Install Xen hypervisor:
   ```bash
   sudo apt-get install xen-hypervisor-amd64 xen-tools xenstore-utils \
       bridge-utils
   ```
2. Reboot into Xen (verify):
   ```bash
   sudo xl info
   # Should show: xen_version, xen_caps, xen_changeset
   ```
3. Create a network bridge:
   ```bash
   sudo brctl addbr xenbr0
   sudo brctl addif xenbr0 eth0
   ```
4. Create a guest:
   ```bash
   sudo xen-create-image --hostname=guest1 --memory=1024 --vcpus=2 \
     --lvm=vg0 --bridge=xenbr0 --dist=bullseye --role=udev
   ```
5. Start guest:
   ```bash
   sudo xl create /etc/xen/guest1.cfg
   sudo xl console guest1
   ```
6. For DRAKVUF, install and configure per the project README.

### 6.5 Proxmox VE Single Node

Use case: Proxmox API auditing, qm/pct CLI testing, Corosync configuration.

Steps:
1. Download Proxmox VE 8 ISO from https://www.proxmox.com/.
2. Install on a dedicated test host (Debian-based).
3. Post-install, configure networking via the web UI (8006).
4. Create a test VM via CLI:
   ```bash
   qm create 100 --name testvm --memory 1024 --cores 2 \
       --net0 virtio,bridge=vmbr0
   qm set 100 --scsi0 local-lvm:vm-100-disk-0,size=20G
   qm set 100 --cdrom local:iso/debian-12.iso
   qm start 100
   ```
5. For multi-node cluster, install Proxmox on 3+ hosts and join via `pvecm add`.

### 6.6 Hyper-V Lab

Use case: VMWP enumeration, Live Migration testing, Shielded VM bypass research.

Steps:
1. Install Windows Server 2019/2022 with the Hyper-V role.
2. Configure external virtual switch.
3. Create a test VM via PowerShell:
   ```powershell
   New-VM -Name TestVM -MemoryStartupBytes 2GB -Generation 2 \
     -VHDPath D:\VMs\TestVM.vhdx -SwitchName External
   ```
4. For Live Migration testing, deploy 2+ Hyper-V hosts with shared storage (SMB3 or CSV).
5. For Shielded VM research, deploy a Host Guardian Service on a separate Windows Server.

### 6.7 HyperPlatform Lab (Intel VT-x Research)

Use case: Defensive hypervisor deployment, EPT hook experimentation.

Steps:
1. Install Windows 10/11 on a test host with Intel VT-x enabled.
2. Install Visual Studio with WDK 10.
3. Clone HyperPlatform: https://github.com/tandasat/HyperPlatform.
4. Build the kernel driver in Test mode (or with a test cert).
5. Enable test signing: `bcdedit /set testsigning on` (reboot).
6. Load the driver: `sc create HyperPlatform type= kernel binPath= C:\HyperPlatform.sys; sc start HyperPlatform`.
7. Use DebugView (sysinternals) to see DbgPrint output.
8. Build custom EPT hooks via the HyperPlatform API.

---

## 7. Defensive Guidance

### 7.1 VMware ESXi Hardening

**Lockdown Mode (Strict)**: Disables direct SSH/DCUI/root access to ESXi hosts. All administration flows through vCenter with explicit role assignment. Strict mode further restricts even vCenter's emergency access.

```bash
# Enable lockdown mode
vim-cmd hostsvc/enable_lockdown

# Verify
vim-cmd hostsvc/query_lockdown_mode
```

**Disable auxiliary services**:
- OpenSLP: `/etc/init.d/slpd stop; chkconfig slpd off`
- SSH: Stop SSH service, set to disabled (not just stopped)
- DCUI: Disable on production hosts or restrict to specific users
- ESXi Shell: Disable after maintenance
- MOB: `vim-cmd hostsvc/advopt/update Config.HostAgent.plugins.solo.enableMob string false`

**Network segmentation**: Place vCenter, ESXi vmkernel networks, and vMotion on dedicated non-routable VLANs.

**MFA on vCenter SSO**: Use vSphere Identity Federation with AD FS, Okta, or Entra ID for SSO MFA.

**vTPM and vSB**: Enable on every VM whose guest OS supports it.

**Patch velocity**: Subscribe to VMware VMSA feed. Apply Critical/High patches within 7 days.

**Syslog forwarding**: Configure ESXi syslog to remote SIEM (`esxcli system syslog config set --remote-host=<siem>`).

**Backup strategy**: Maintain offline (air-gapped) backups. Test restore quarterly.

### 7.2 Microsoft Hyper-V Hardening

**Apply MSRC monthly rollups** within 7 days for Critical.

**Configure Live Migration** to use Kerberos over dedicated VLAN:
```powershell
Set-VMHost -VirtualMachineMigrationAuthType Kerberos
Set-VMHost -UseAnyNetworkForMigration $false
```

**Deploy Shielded VMs** for high-value guests. Stand up a Host Guardian Service on a dedicated hardened domain controller.

**Enable VBS / HVCI** on the host:
```powershell
# Check current state
$dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace 'root\Microsoft\Windows\DeviceGuard'
$dg.SecurityServicesRunning

# Enable (requires compatible hardware + UEFI settings)
Set-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard `
  -ClassName Win32_DeviceGuard `
  -Property @{SecurityServicesConfigured=@(1,2)}
```

**Audit VMWP child processes**: Any non-empty result from `Get-WmiObject Win32_Process -Filter "ParentProcessId=<vmwp-pid>"` is suspicious.

**Restrict Hyper-V Manager access** to Domain Admins via RBAC.

### 7.3 KVM/QEMU Hardening

**Run qemu-system as unprivileged user**: libvirt does this by default. Verify with `ps -ef | grep qemu-system`.

**Apply QEMU seccomp filter**:
```bash
qemu-system-x86_64 ... \
  -sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny
```

**Use `-nodefaults`**: Disable unnecessary default devices:
```bash
qemu-system-x86_64 -nodefaults \
  -device virtio-net ... \
  -device virtio-blk ...
```

**Patch host kernel aggressively**: vhost-* bugs are common in stable kernels. Subscribe to the Linux stable CVE feed.

**Enable IOMMU** if doing PCI passthrough: kernel cmdline `intel_iommu=on,strict iommu=pt`.

**Restrict libvirt TCP** to management network with SASL:
```
# /etc/libvirt/libvirtd.conf
listen_tcp = 1
auth_tcp = "sasl"
tls_port = "16514"
```

**Enable AppArmor or SELinux** for libvirt:
```bash
# Debian/Ubuntu: apparmor
sudo apt-get install apparmor libvirt-daemon-system
# Verify: ps -ef | grep libvirtd | grep -i aa
```

### 7.4 Xen Hardening

**Migrate PV guests to PVH**: PV guests have larger attack surface (grant tables, event channels). PVH (PV-on-HVM hybrid) gives HVM-level isolation with PV-level performance.

**Enable XSM-FLASK policy**: Most deployments leave XSM in "dummy" mode (permits everything). Switch to FLASK:
```
# grub: flask=enforcing
```

**Apply XSA patches within 7 days** for Critical. Subscribe to xen-announce mailing list.

**Run Dom0 as a minimal hardened distribution**: Qubes OS is the canonical example. Remove unnecessary packages.

**Audit XenStore permissions**: Restrict guest write access to its own subtree.

### 7.5 Proxmox VE Hardening

**Enable 2FA on root@pam**:
```bash
pveum user modify root@pam -keys tstotp
```

**Restrict pveproxy (8006)** to management VLAN:
```bash
# /etc/default/pveproxy
LISTEN_IP="<mgmt-ip>"
```

**Isolate Corosync (UDP 5404/5405)** on dedicated VLAN.

**Avoid privileged LXC containers** in production: `privileged: 1` drops user namespace; `nesting: 1` enables container-in-container (often used to escape).

**Apply Proxmox security updates monthly**: `apt update && apt upgrade`.

**Use signed Cloud-Init images** for VM templates.

---

## 8. Engagement Workflow

A typical hypervisor security engagement follows these phases:

### Phase 1: Scoping

- Identify the customer's hypervisor stack (vendor, version, topology)
- Identify the management plane exposure (vCenter URL, ESXi hosts, libvirt, pveproxy)
- Determine if scope includes active exploitation of escape CVEs or only configuration audit
- Determine if scope includes ransomware TTP simulation
- Obtain written authorization, including emergency contact and rollback procedures
- Confirm the engagement window (avoid peak hours, especially for any active testing)

### Phase 2: Reconnaissance (Passive)

- Identify internet-exposed surfaces via Shodan, Censys
- Identify management plane CVEs that are public but unpatched in the customer's environment
- Review customer's patch history (if provided)
- Review customer's network architecture diagrams
- Review customer's incident response history (if any)

### Phase 3: Active Enumeration

- Map the management plane (vCenter, ESXi hosts, libvirt, Hyper-V hosts, Proxmox nodes)
- Enumerate running VMs, datastores, networks, users, roles
- Identify exposed services (SLP, MOB, SSH, libvirt TCP, pveproxy)
- Identify version and patch level of every hypervisor component
- Map network segmentation (management VLAN reachability from guest subnets)

### Phase 4: Vulnerability Verification

- For each identified CVE, attempt to verify in a lab (nested environment) before touching customer infrastructure
- For configuration weaknesses (no vTPM, no lockdown, default credentials), verify directly
- For escape CVEs, do NOT execute PoCs against production; verify in lab only and report findings based on version mismatch

### Phase 5: Exploitation (If In Scope)

- For management plane credential abuse: obtain valid credentials (via phishing simulation or kerberoasting), walk through vCenter
- For ransomware TTP simulation: enumerate VMs, document the blast radius (which VMs would be encrypted, which datastores would be inaccessible), do NOT actually encrypt
- For escape PoCs: never execute against production

### Phase 6: Post-Exploitation

- Document every step with timestamps
- Capture screenshots, command outputs, packet captures
- Do not modify any production data
- Pivot only as documented in scope; lateral movement outside scope is forbidden

### Phase 7: Reporting

- Separate findings by layer: management plane, escape paths, configuration, VMI/forensic capability
- For each finding: CVE/technique, CVSS, affected version, patched version, recommended mitigation, blast radius
- Include a remediation roadmap prioritized by impact

### Phase 8: Remediation Support

- Walk the customer through remediation for Critical findings
- Re-test after remediation to confirm

---

## 9. Reporting Templates

### 9.1 Executive Summary Template

```
[Customer] Hypervisor Security Assessment - [Date]

Scope: [vCenter URL, ESXi host count, Hyper-V host count, KVM host count,
       Proxmox cluster details]

Methodology: [Configuration audit + passive reconnaissance +
              lab-verified escape PoCs (no production exploitation)]

Key Findings:
  - [N] Critical findings (immediate remediation required)
  - [N] High findings (remediate within 7 days)
  - [N] Medium findings (remediate within 30 days)
  - [N] Informational findings (consider)

Top Risks:
  1. [Risk 1: e.g., "ESXi hosts unpatched against CVE-2021-21974 (OpenSLP) -
       risk of ESXiArgs ransomware compromise"]
  2. [Risk 2: e.g., "vCenter SSO without MFA - risk of credential theft
       enabling mass VM encryption"]
  3. [Risk 3: e.g., "Management VLAN reachable from guest subnet - risk of
       hypervisor compromise from inside a compromised VM"]

Recommendations:
  1. Apply all Critical/High patches within 7 days
  2. Enable ESXi lockdown mode (Strict) fleet-wide
  3. Implement MFA on vCenter SSO via Identity Federation
  4. Migrate management network to dedicated non-routable VLAN
  5. Deploy offline backups and test restore quarterly
```

### 9.2 Technical Finding Template

```
[Finding ID]: [Short Title]

Severity: [CRITICAL | HIGH | MEDIUM | LOW]
Category: [Management Plane | Escape CVE | Configuration | VMI Gap]
Affected Component: [vCenter / ESXi host / Hyper-V host / KVM host / etc.]
Affected Version: [Version and build number]
Patched Version: [Version that resolves the issue]
CVE / XSA / VMSA: [Identifier(s)]
CVSS: [Score]

Description:
[1-2 paragraphs explaining the issue]

Impact:
[1-2 paragraphs explaining what an attacker could do]

Evidence:
[Command output, screenshots, packet captures]

Remediation:
[Specific commands to apply, version to upgrade to, configuration to change]

Verification:
[Re-test steps to confirm remediation]

References:
[URLs to advisories, CVE details, vendor docs]
```

---

## 10. Common Mistakes and Anti-Patterns

### 10.1 Treating the Management Plane as Trusted

ESXi ransomware crews almost never exploit a hypervisor CVE. They walk through exposed vCenter/ESXi management interfaces using stolen or default credentials. A fully patched vSphere 8 cluster with lockdown disabled, SSH enabled, and SLP reachable on 427/UDP is far more likely to be ransomed than an unpatched cluster with proper management segmentation.

### 10.2 Conflating Containers with VMs

Container escape (a namespace/cgroup boundary violation) is conceptually similar to VM escape but the primitives, defensive tooling, and CPU-level mechanisms are entirely different. A "container escape" via `/var/run/docker.sock` mount has no analog in KVM/QEMU; a "VM escape" via VENOM has no analog in Docker. Always scope the assessment to the correct isolation boundary.

### 10.3 Ignoring Paravirtualized Drivers

Virtio-net, virtio-blk, VMware VMXNET3/PVSCSI, Xen netback/blkback, and Hyper-V netvsc/storvsc are written for performance, not defense, and have been the source of multiple high-severity escape bugs. Auditors frequently focus on emulated legacy devices (floppy, PCNET) because they are well-known, while skipping the PV drivers that are actually enabled in production.

### 10.4 Assuming VMI Is Undetectable

VMI via LibVMI/DRAKVUF is stealthy relative to in-guest instrumentation but not invisible. Single-step traps, EPT violations, and altered TSC offsets can be detected by a sufficiently paranoid guest. For high-assurance malware analysis, use DRAKVUF's trap absorption features and avoid single-stepping where possible.

### 10.5 Skipping Nested Virtualization in Labs

Reproducing a VM escape against a bare-metal production host can brick the host, crash sibling VMs, or worse. Always reproduce in a nested virtualization environment first (ESXi-on-Workstation, KVM-on-KVM with nested=1, Hyper-V-on-Hyper-V) and only then verify on bare metal in a sacrificial lab.

### 10.6 Forgetting the Host Kernel Is Part of the Boundary

For KVM and Xen, the host kernel (or Dom0) is part of the trust boundary. A Linux kernel LPE in the host (e.g., CVE-2024-1086 netfilter) often beats hypervisor CVEs as the more reliable escape path, because the attacker can escape the guest to QEMU, then LPE from qemu-system (running as an unprivileged user) to host root.

### 10.7 Executing Ransomware TTPs Against Production

Even "read-only" ransomware enumeration (walking the MOB tree, listing VMs via govc, listing datastores via ssh) can destabilize a cluster at scale and trigger monitoring alerts. Always perform in an isolated lab or with explicit per-step approval.

### 10.8 Skipping the Patch Velocity Check

The most common finding in hypervisor engagements is "patch available, customer has not applied it". Patch velocity is the highest-ROI defensive action. Always check the customer's patch level against the latest advisories as the first step of any engagement.

### 10.9 Not Maintaining Offline Backups

Cloud backups are insufficient if the cloud account is on the same management plane. Every critical VM must have offline (air-gapped) backups. Test restore quarterly. Many ESXi ransomware victims had cloud backups that were encrypted alongside the production VMs because the cloud backup agent was a VM on the same cluster.

### 10.10 Assuming Public-cloud Hypervisors Are In Scope

AWS Nitro, Azure Hyper-V, and GCE KVM are operated by the CSP. They are out of scope for direct testing. The CSP's responsible disclosure policy applies. Public-cloud hypervisor findings should be reported to the CSP's security team, not to the customer.

---

## 11. Future Directions

### 11.1 Confidential Computing

AMD SEV-SNP, Intel TDX, and ARM CCA shift the threat model: the hypervisor operator is the adversary. VMI is no longer possible. Defensive tooling must redesign around:
- Hardware attestation (TPM-based, runs in TEE)
- In-guest agents (cannot subvert rootkits but cannot be subverted by hypervisor operator either)
- Side-channel monitoring (cache, power, electromagnetic)

### 11.2 VM-based Detection at Scale

HyperPlatform, DdiMon, Hunter, Moneta — these tools are research-grade today. As they mature, expect commercial VMI-based detection offerings for high-value guests (e.g., domain controllers, database servers).

### 11.3 eBPF for Hypervisor Monitoring

On KVM hosts, eBPF can monitor qemu-system processes for anomalous behavior (file access, network connections, child process spawns) with minimal overhead. Expect more eBPF-based hypervisor monitoring tools.

### 11.4 ARM Server Adoption

Ampere Altra, AWS Graviton, and Apple Silicon are driving ARM server adoption. ARM's EL2 hypervisor mode has different attack surface from x86 VMX/SVM. Expect more ARM-specific hypervisor CVE research.

### 11.5 WebAssembly (Wasm) as a Sandbox

Wasm runtimes (Wasmtime, Wasmer, WasmEdge) are emerging as an alternative to containers and VMs for some workloads. Wasm-based isolation is a different trust boundary; expect a future skill domain for Wasm security.

### 11.6 Kata Containers and Firecracker

Kata Containers runs VMs (QEMU-based, with a stripped-down guest kernel) as Kubernetes pods. Firecracker (AWS) is a minimal VMM designed for microVMs. Both bridge the container/VM boundary. Assessments should treat them as VMs (this skill) for the VM-layer analysis and as containers (container-security) for the orchestration layer.

---

## 12. References

### Vendor Advisories

- [VMware Security Advisories (VMSA)](https://www.vmware.com/security/advisories)
- [Microsoft Security Response Center (MSRC)](https://msrc.microsoft.com/update-guide/)
- [Xen Project Security Advisories (XSA)](https://xenbits.xen.org/xsa/)
- [QEMU Security Process](https://www.qemu.org/contribute/security-process/)
- [Proxmox Security](https://forum.proxmox.com/threads/security-advisories.42238/)

### Tool Documentation

- [LibVMI](https://libvmi.com/)
- [DRAKVUF](https://github.com/tklengyel/drakvuf)
- [HyperPlatform](https://github.com/tandasat/HyperPlatform)
- [DdiMon](https://github.com/tandasat/DdiMon)
- [PANDA](https://github.com/panda-re/panda)
- [DECAF](https://github.com/sycurelab/DECAF)
- [Volatility 3](https://github.com/volatilityfoundation/volatility3)
- [govc](https://github.com/vmware/govmomi/tree/main/govc)
- [pyvmomi](https://github.com/vmware/pyvmomi)

### Benchmarks and Standards

- [CIS VMware ESXi Benchmark](https://www.cisecurity.org/benchmark/vmware)
- [CIS Hyper-V Benchmark](https://www.cisecurity.org/benchmark/microsoft_windows_server)
- [NIST SP 800-125A: Guide to Security for Full Virtualization Technologies](https://csrc.nist.gov/publications/detail/sp/800-125a/final)
- [MITRE ATT&CK T1068 (Exploitation for Privilege Escalation)](https://attack.mitre.org/techniques/T1068/)

### Real-World Incidents

- [CISA AA23-061A: ESXiArgs Ransomware (Feb 2023)](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-061a)
- [CrowdStrike VENOM Disclosure (2015)](https://www.crowdstrike.com/blog/venom-is-the-tip-of-the-iceberg/)
- [VMware PSOD Advisory on ESXi OpenSLP (CVE-2019-5544)](https://www.vmware.com/security/advisories/VMSA-2019-0022.html)
- [Hyper-V CVE-2017-0180 (MS17-0113)](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2017-0180)

### Academic References

- King, Chen, Wang, Verbowski, Joshi, Lids (2006). "SubVirt: Implementing malware with virtual machines." IEEE S&P.
- Rutkowska, J. (2006). "Subverting Vista Kernel for Fun and Profit." Black Hat USA. (BluePill)
- Payne, B. (2012). "LibVMI: A library for virtual machine introspection." (PhD dissertation)
- Lengyel, T. et al. (2014). "DRAKVUF: Scalable malware analysis system based on Xen." SSTIC.

---

**End of hypervisor-introspection-playbook.md**
