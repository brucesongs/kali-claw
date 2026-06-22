---
name: hypervisor-introspection
description: "Hypervisor introspection (VMI) and virtualization escape attacks — VMware ESXi, Hyper-V, KVM/QEMU, Xen, Proxmox, VirtualBox, LibVMI, DRAKVUF, VENOM CVE-2015-3456, hardware-assisted VT-x/EPT/AMD-V"
origin: kali-claw
version: "1.0"
compatibility:
  - claude-code
  - claude-sonnet-4.5
  - openclaw
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
  - WebSearch
  - WebFetch
metadata:
  domain: hypervisor-introspection
  category: virtualization
  tool_count: 13
  guide_count: 1
  mitre: "T1068-Exploitation for Privilege Escalation"
  keywords:
    - hypervisor
    - VMI
    - VMware ESXi
    - Hyper-V
    - KVM
    - QEMU
    - Xen
    - escape
    - LibVMI
    - DRAKVUF
---


# Skill: Hypervisor Introspection (VMI) and Virtualization Escape

> **Supplementary Files**:
> - `payloads.md` — Attack payloads and commands organized by hypervisor family: VMware ESXi/vSphere, Hyper-V, KVM/QEMU, Xen, Proxmox, VirtualBox, VMI tooling (LibVMI/DRAKVUF/DECAF/PANDA), and hardware-assisted virtualization abuse
> - `test-cases.md` — 12 structured test cases (TC-HI-001 through TC-HI-012) covering VMware MOB enumeration, ESXi SLP fingerprinting, QEMU QMP unauth access, KVM PCI passthrough auditing, LibVMI memory reads, DRAKVUF malware tracing, VENOM reproduction, Hyper-V VMWP enumeration, and more
> - `guides/hypervisor-introspection-playbook.md` — Comprehensive playbook with hypervisor comparison matrix, VMI use cases, real-world incident analysis (VENOM, OpenSLP, ESXiArgs, Akira/Royal), lab setup for each hypervisor, and defensive guidance

## Summary

Hypervisor Introspection skill domain covering virtualization layer operations.

**Tools**: VMware vSphere CLI (govc, pyvmomi, PowerCLI), ESXi Shell/DCUI/vMA, LibVMI/PyVMI, DRAKVUF, DECAF/PANDA, QEMU (QMP/HMP), virsh/libvirt, Xen xl/xm/xe, Hyper-V PowerShell, Proxmox VE qm/pct, Wireshark (VMware/VNC dissectors), Volatility (VM memory forensics), HyperPlatform/DdiMon

**Domain**: virtualization

**MITRE ATT&CK**: T1068 - Exploitation for Privilege Escalation

## Description

Hypervisor introspection (VMI) and virtualization escape assessment covers the full virtualization stack: Type-1 bare-metal hypervisors (VMware ESXi/vSphere, Microsoft Hyper-V, KVM/QEMU, Xen, Proxmox VE, bhyve, AHV), Type-2 hosted hypervisors (VMware Workstation/Fusion, VirtualBox, Parallels), and the hardware-assisted virtualization primitives they rely on (Intel VT-x/EPT, AMD-V/RVI/NPT, ARM EL2). The discipline spans two complementary perspectives: offensive testing of escape paths from guest to host (CVE-driven device emulation flaws, paravirtualized backend bugs, host-passthrough misconfigurations, management plane abuse) and defensive introspection from outside the guest using Virtual Machine Introspection (VMI) tooling such as LibVMI, PyVMI, DRAKVUF, DECAF, and PANDA. The defender's perspective centers on stealthy malware analysis, kernel rootkit detection, and memory forensics performed from the hypervisor layer, where the observer cannot be tampered with by guest malware.

Mastering this skill requires deep fluency in CPU virtualization extensions (VMX root/non-root, SVM guest/host, EPT/NPT second-level address translation), hypervisor attack surfaces (QEMU device emulation, VMware VMX, Xen toolstack, Hyper-V VMWP worker processes), and the protocols used to control the management plane (vSphere REST API, MOB, QMP, libvirt, XenStore). The attacker's perspective focuses on chaining a guest-visible vulnerability into code execution in the hypervisor or host kernel (the actual "escape"), while the defender's perspective uses the hypervisor's privileged vantage point to inspect and contain malicious guests.

### Differentiation

This domain is distinct from adjacent virtualization-themed skills:

- **container-security** covers Linux containers (Docker, containerd, podman) which share the host kernel via namespaces and cgroups. Containers are not full virtual machines — there is no separate kernel and no hardware-assisted isolation layer. Container "escape" is a namespace/cgroup boundary violation, whereas hypervisor "escape" requires breaking out of a hardware-enforced CPU virtualization container. The two skills share some conceptual overlap (both are isolation boundary failures leading to host compromise) but the attack primitives, defensive tooling, and CPU-level primitives are entirely different. A container running as root can still be introspected from the host trivially (`nsenter`, `/proc/<pid>/root`); a VM requires VMI tooling to inspect without the guest's cooperation.
- **kubernetes-attack** covers the orchestration layer above containers — the API server, etcd, RBAC, scheduler, and controllers. Kubernetes runs containers (typically via containerd/CRI-O on top of containerd/runc), not VMs, although projects like KubeVirt and Kata Containers bridge the two by running VMs as Kubernetes workloads. When assessing KubeVirt or Kata, this skill informs the VM-layer analysis while kubernetes-attack informs the orchestration-layer analysis; the two are complementary, not redundant.
- **cloud-security** covers CSP-managed IaaS/PaaS/SaaS and the cloud control plane (IAM, metadata services, object storage). Public-cloud hypervisors (AWS Nitro, Azure Hyper-V, Google GCE's KVM) are typically out of scope for direct testing because the CSP hardens and operates them; this skill focuses on customer-managed hypervisors (private vSphere, on-prem Hyper-V, KVM clusters, Proxmox VE) where the customer owns and is responsible for the hypervisor security posture.
- **firmware-reverse** and **hardware-security** cover pre-OS firmware and physical hardware, respectively. Hardware-assisted virtualization primitives (VT-x, AMD-V) are adjacent to hardware-security but the attack patterns here are about abusing virtualization features (e.g., deploying a malicious hypervisor that subverts an existing one) rather than physical glitching or JTAG abuse.

---

## Use Cases

1. **VMware vSphere/ESXi Attack Surface Mapping** — Enumerate the vSphere REST API, Managed Object Browser (MOB), SLP services, and SSH/DCUI surfaces; fingerprint build numbers and patch levels to identify missing fixes for OpenSLP CVE-2019-5544, CVE-2020-3992, CVE-2021-21974, and related ESXi issues
2. **ESXi Ransomware Posture Assessment** — Evaluate a vSphere cluster's exposure to the ESXiArgs, Akira, Royal, BlackCat, and Play ransomware families that specifically target VM hosts and encrypt datastores; verify lockdown mode, role-based access control, and network segmentation of the management network
3. **Hyper-V Worker Process (VMWP) Auditing** — Enumerate VMWP.exe instances, identify the vmbus, vid, and hvp device drivers, audit Live Migration and Replica traffic, and assess Shielded VM and Guarded Fabric configurations for bypass paths
4. **KVM/QEMU Device Emulation Vulnerability Verification** — Reproduce and verify mitigations for QEMU device emulation flaws including VENOM (CVE-2015-3456 floppy), CVE-2015-7504 PCNET, CVE-2020-14364 USB XHCI, CVE-2021-3947 e1000e, CVE-2023-3354 OBjective-C (jobs overflow), and virtio-ring issues
5. **Xen DomU-to-Dom0 Privilege Escalation Testing** — Audit Xen security advisories (XSA-148, XSA-182, XSA-242, XSA-253, XSA-344, XSA-392, and successors) against running guest configurations; test PV vs HVM guest isolation boundaries
6. **Virtual Machine Introspection for Malware Analysis** — Deploy LibVMI/PyVMI, DRAKVUF, DECAF, or PANDA against a target VM to extract kernel structures, walk process lists, and trace malware behavior from outside the guest — defeating in-guest anti-analysis techniques
7. **Hypervisor-based Memory Forensics** — Use HyperPlatform, DdiMon, Hunter, or Moneta on Windows to deploy a thin Intel VT-x hypervisor that monitors kernel memory writes, detects rootkits, and supports Volatility-based analysis of protected guests
8. **Proxmox VE Cluster Auditing** — Assess Proxmox VE (KVM + LXC on Debian) management interfaces (the `pveproxy` web UI on 8006), Corosync cluster communication, and the boundary between LXC containers and KVM guests running on the same host
9. **Nested Virtualization Lab Setup** — Build reproducible labs for vulnerability reproduction: nested ESXi on Workstation/Fusion, KVM on Linux with nested=1, Hyper-V on Hyper-V, or Xen-on-Xen, so that escape PoCs can be safely tested without risking bare-metal hosts
10. **Hardware-assisted Virtualization Abuse Research** — Reproduce BluePill (AMD64 SVM), Vitriol/SubVirt (Intel VT-x), HyperJack, and similar proof-of-concept malicious hypervisors that install themselves as a stealth layer beneath an existing OS; evaluate EPT-based memory hiding and SMBus-based side channels
11. **VM Memory Forensics with Volatility** — Capture guest RAM via hypervisor-level snapshots (vmware-vmx checkpoint, QEMU `pmemsave`, `virsh dump`, Hyper-V `Save-VM`) and process with Volatility 3 for process tree, network connections, and malware extraction without ever touching the guest OS
12. **Shielded VM and Guarded Fabric Bypass Testing** — For Hyper-V Shielded VMs and guarded fabrics, assess whether the attestation flow (Host Guardian Service, TPM-based measured boot, virtualization-based security) can be subverted via administrative compromise of the fabric or via the VM worker process

---

## Core Tools

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **govc** | Go-based vSphere CLI for ESXi/vCenter management and enumeration | `govc about -u user:pass@vc.example.com` |
| **pyvmomi** | Python SDK for vSphere API; programmatic MOB traversal | `python3 -c "from pyVim.connect import SmartConnect; ..."` |
| **PowerCLI** | PowerShell module for VMware automation (Windows hosts) | `Get-VM \| Select Name,PowerState` |
| **ESXi Shell / DCUI** | Direct shell on ESXi host; DCUI = Direct Console User Interface | `vim-cmd vmsvc/getallvms` |
| **LibVMI / PyVMI** | C library and Python bindings for VM introspection (Xen/KVM/QEMU) | `pyvmi -d win7 -n pslist` |
| **DRAKVUF** | Dynamic malware analysis system built on LibVMI/Xen | `drakvuf -r kernel.json -d win7malware -e malware.exe` |
| **DECAF / PANDA** | QEMU-based dynamic analysis platforms with taint and plugin support | `panda-system-x86_64 -os windows-32-7 -mem 2G` |
| **QEMU (QMP/HMP)** | Machine emulator and virtualizer with QEMU Monitor Protocol (JSON) and Human Monitor | `qemu-system-x86_64 -qmp tcp:127.0.0.1:4444,server,nowait` |
| **virsh / libvirt** | Generic virtualization API and CLI for KVM/QEMU/Xen/LXC | `virsh list --all; virsh dump win7 win7.dump` |
| **Xen xl / xm / xe** | Xen toolstack (xl is the modern LBL tool; xe for XenServer/XCP) | `xl list; xl info` |
| **Hyper-V PowerShell** | Hyper-V module (Get-VM, Get-VHD, Get-VMNetworkAdapter) | `Get-VM \| Format-Table Name,State,CPUUsage` |
| **Proxmox qm / pct** | Proxmox VE CLI for KVM (qm) and LXC (pct) guests | `qm list; pct list` |
| **Wireshark (VMware/VNC)** | Network analyzer with dissectors for VNC, VMware VMotion, and CIFS used by Hyper-V Live Migration | `tshark -i vmnet8 -Y vnc` |
| **Volatility 3** | Memory forensics framework for VM RAM dump analysis | `vol -f win7.dump windows.pslist` |
| **HyperPlatform / DdiMon** | Intel VT-x research hypervisors for kernel memory monitoring on Windows | `HyperPlatform.exe -driver:MyDriver` |

> The 13 tools enumerated in the YAML metadata map directly to the rows above (govc/pyvmomi/PowerCLI are listed as a single "VMware vSphere CLI" family per the spec).

---

## Methodology

### Attack Chain

```
   Management Plane         Guest Kernel         Device Emulation        Hypervisor           Host / Sibling VMs
   Enumeration              Reconnaissance       Vulnerability           Compromise           Lateral Movement
   (vSphere API, MOB,       (Detect VMware       (QEMU device,           (RCE in vmx,         (vmkloadapp,
    SLP, libvirt, Xen       Tools, Hyper-V       virtio, paravirt        qemu-system,          vmktools, host
    Store, Proxmox 8006)    driver, /sys/hypervisor)  backend)              VMWP worker)         shell, datastore)
       |                       |                       |                       |                       |
       v                       v                       v                       v                       v
   Credentials               Guest-level            CVE-driven              Hypervisor             Datastore
   / Access Token             RCE Primitive          Escape Primitive        Root / Kernel          Encryption /
   (Lockdown bypass,          (Web shell,            (VENOM, XSA,            Mode                   VM Image
    SSO abuse, vMA)            kernel exploit)        Hyper-V vmbus)                                  Manipulation
```

**Phase Details**:

1. **Management Plane Enumeration** — Map every externally reachable management surface: vCenter on 443 (SOAP/REST), ESXi hostd on 443 and MOB on `/mob`, OpenSLP on 427 (UDP), SSH on 22 (if enabled), DCUI on the physical console, libvirt on 16509 (TCP) or 22 (qemu+ssh), Proxmox `pveproxy` on 8006, XenServer API on 443. The management plane is the most common intrusion vector for ESXi ransomware crews.
2. **Guest Kernel Reconnaissance** — From inside the guest, detect the hypervisor (`cpuid` leaf `0x40000000`, /sys/hypervisor/type, VMware Tools service, Hyper-V integration services, QEMU virtio PCI device IDs). This informs escape strategy: PV drivers often expose more attack surface than emulated hardware.
3. **Device Emulation Vulnerability Discovery** — Map guest-visible emulated devices (PCI IDs, I/O ports, MMIO regions) to known CVEs. QEMU's floppy, PCNET, E1000, USB XHCI, NVMe, and virtio backends have all had remotely triggerable flaws reachable from inside the guest.
4. **Hypervisor Compromise (Escape)** — Trigger the vulnerable code path from the guest to achieve code execution in the hypervisor process (qemu-system, vmware-vmx, VMWP) or in the kernel of the host (vmkernel, Linux host, Windows). At this point the attacker has crossed the virtualization boundary.
5. **Host / Sibling VM Lateral Movement** — From the hypervisor host, enumerate datastores (`/vmfs/volumes` on ESXi), manipulate VMDK/IMG files, deploy ransomware against all suspended VMs, or pivot into sibling VMs by editing their virtual disks offline.

### Defense Perspective

- **ESXi Lockdown Mode** — Disable direct root SSH/DCUI access to ESXi hosts; all administration flows through vCenter with explicit role assignment. Lockdown mode "Strict" further restricts even vCenter's emergency access.
- **Network Segmentation of Management Plane** — vCenter, ESXi vmkernel networks, Hyper-V cluster networks, Proxmox Corosync, and Live Migration/VMotion networks must be on dedicated non-routable VLANs. ESXi ransomware crews scan the internet for exposed 443/427/22 and then ransom every VM in minutes.
- **vTPM and Virtual Secure Boot (vSB)** — Enable vTPM and vSB on every VM whose guest OS supports it. This prevents offline tampering with VMDKs (the attacker can still delete or encrypt, but cannot modify boot chain or bitlocker-sealed secrets in a way that survives reboot).
- **Hyper-V Shielded VMs / Guarded Fabric** — Shielded VMs run only on attested healthy hosts (Host Guardian Service attests measured boot). Shielded VM local admin cannot log into the VM worker process, cannot mount the VHDX read-write on a different host, and cannot read the VM's BitLocker key. The bypass target is the HGS itself, not the VM.
- **Xen Security Modules (XSM-FLASK)** — Xen XSM with FLASK policy enforces mandatory access control between domains, limiting what a compromised Dom0 or DomU can do to other domains. Most deployments leave XSM in "dummy" mode; switch to FLASK for defense in depth.
- **QEMU Sandbox and Seccomp** — Run qemu-system behind a seccomp filter (`-sandbox on,obsolete=deny,elevateprivileges=deny`) and as an unprivileged user. Combined with libvirt's `dynamic_ownership` and namespace isolation, this contains many device emulation flaws.
- **Patch Velocity** — Hypervisor CVEs frequently have public PoCs within weeks. Subscribe to VMware VMSA, Xen XSA, and QEMU security advisory feeds; patch within the SLA appropriate to the CVSS (typically 7 days for Critical in a datacenter).
- **VMI-Based Detection** — Deploy DRAKVUF or a LibVMI-based sensor to high-value guests so that in-guest malware is detected by out-of-guest introspection, even if the malware subverts the guest kernel itself.

---

## Practical Steps

### 1. VMware vSphere / ESXi Attack Surface Mapping

Use govc, pyvmomi, and the MOB to enumerate vCenter objects, host configurations, and network exposures. Confirm whether lockdown mode is enabled, whether OpenSLP is reachable on UDP 427 (the CVE-2019-5544 / CVE-2020-3992 surface), and whether SSH is disabled on production hosts. Test default credentials against the SSO administrator account and against host local users (`root`).

### 2. QEMU / KVM Device Emulation Vulnerability Verification

Build a QEMU reproduction lab with debugging symbols. Reproduce VENOM (CVE-2015-3456) against an old floppy backend, then verify that a patched QEMU rejects the malformed commands. Repeat for PCNET (CVE-2015-7504), USB XHCI (CVE-2020-14364), and the e1000e out-of-bounds (CVE-2021-3947). For each, document the QEMU command line, the guest-side PoC, and the patched version threshold.

### 3. Hyper-V VMWP and VMBus Enumeration

From the parent partition (host), enumerate VMWP.exe worker processes, map each to its VM via `Get-VM \| Select Name,Id`, and inspect the loaded modules inside VMWP. Identify the vid.sys, vmbus.sys, and hvp.sys drivers and confirm patch level against MSRC bulletins. Audit the Live Migration and Replica configuration for plaintext or weakly authenticated transport.

### 4. Xen XSA Verification Lab

Stand up a Debian-based Xen host with both PV and HVM guests. Test XSA-148 (PV MMIO), XSA-182 (grant table issue), and XSA-242 (PV block backend) against unpatched vs patched dom0. Document whether XSM-FLASK was enabled by default and whether the XenStore daemon (dom0) is reachable from guest qemu-dp processes.

### 5. Virtual Machine Introspection Deployment

Install LibVMI on a Xen or KVM host, configure the VM with a known kernel (`/etc/libvmi/<domain>.conf`), and use PyVMI to walk the Active Process List of a Windows guest without ever logging into the guest. Scale up to DRAKVUF for full dynamic malware analysis: trap syscalls, log network activity, and extract dropped binaries without the malware knowing it is being observed.

### 6. Proxmox VE Cluster Audit

Enumerate the 8006 web UI, the Corosync cluster on UDP 5404/5405, the SPICE/VNC consoles on each VM's allocated port, and the LXC container boundary (`/proc/<pid>/cgroup` to distinguish KVM from LXC). Verify that no production cluster has `pveproxy` exposed to the internet and that no host's root password is shared across nodes.

### 7. Hypervisor-based Defense Tooling (HyperPlatform)

On a Windows host, install HyperPlatform and a custom kernel-mode driver that registers EPT violations on the page hosting `nt!PsActiveProcessHead`. The driver logs every process creation in real time and survives kernel rootkit attempts to unlink the process list, because the rootkit's own CR3 manipulation is caught by the EPT hook. Use DdiMon to monitor specific kernel functions (e.g., `MmCopyVirtualMemory`) for credential theft.

### 8. VM Memory Forensics Pipeline

Snapshot the guest via `virsh dump <domain> out.dump --memory-only`, `qemu-monitor pmemsave`, ESXi snapshot consolidation, or Hyper-V `Save-VM`. Then run Volatility 3 against the dump: `vol -f out.dump windows.pslist`, `windows.netscan`, `windows.malfind`. This is the canonical "deadbox" forensics path for a VM suspected of compromise.

> Detailed payloads in `payloads.md`, complete test checklist in `test-cases.md`, and the end-to-end playbook in `guides/hypervisor-introspection-playbook.md`.

---

## Common Pitfalls

- **Treating the management plane as trusted**: ESXi ransomware crews (Akira, Royal, BlackCat, Play, ESXiArgs) almost never exploit a hypervisor CVE — they simply walk through exposed vCenter/ESXi management interfaces using stolen or default credentials. A fully patched vSphere 8 cluster with lockdown disabled, SSH enabled, and SLP reachable on 427/UDP is far more likely to be ransomed than an unpatched cluster with proper management segmentation.
- **Conflating containers with VMs**: Container escape (a namespace/cgroup boundary violation) is conceptually similar to VM escape but the primitives, defensive tooling, and CPU-level mechanisms are entirely different. A "container escape" via `/var/run/docker.sock` mount has no analog in KVM/QEMU; a "VM escape" via VENOM has no analog in Docker. Always scope the assessment to the correct isolation boundary.
- **Ignoring paravirtualized drivers**: Virtio-net, virtio-blk, VMware VMXNET3/PVSCSI, Xen netback/blkback, and Hyper-V netvsc/storvsc are written for performance, not defense, and have been the source of multiple high-severity escape bugs. Auditors frequently focus on emulated legacy devices (floppy, PCNET) because they are well-known, while skipping the PV drivers that are actually enabled in production.
- **Assuming VMI is undetectable**: VMI via LibVMI/DRAKVUF is stealthy relative to in-guest instrumentation but not invisible. Single-step traps, EPT violations, and altered TSC offsets can be detected by a sufficiently paranoid guest. For high-assurance malware analysis, use DRAKVUF's trap absorption features and avoid single-stepping where possible.
- **Skipping nested virtualization in labs**: Reproducing a VM escape against a bare-metal production host can brick the host, crash sibling VMs, or worse. Always reproduce in a nested virtualization environment first (ESXi-on-Workstation, KVM-on-KVM with nested=1, Hyper-V-on-Hyper-V) and only then verify on bare metal in a sacrificial lab.
- **Forgetting the host kernel is part of the boundary**: For KVM and Xen, the host kernel (or Dom0) is part of the trust boundary. A Linux kernel LPE in the host (e.g., CVE-2024-1086 netfilter) often beats hypervisor CVEs as the more reliable escape path, because the attacker can escape the guest to QEMU, then LPE from qemu-system (running as an unprivileged user) to host root.

## Automation and Scripting

Automate ESXi enumeration with `govc` wrapped in a shell script that iterates over a list of vCenters, dumps `host/*`, `vm/*`, and `network/*` trees, and diffs against a baseline to detect new hosts, new VMs, and newly enabled services. Wrap pyvmomi in a Python orchestrator that walks the MOB tree, extracts SSO identity sources, and flags any user in the `Administrators` group with weak password policy. Script QEMU fuzzing with libFuzzer harnesses that invoke the QEMU device emulation code directly (as QEMU itself does internally with `tests/qtest`) — this is far faster than running a full guest. Automate LibVMI-based monitoring with a Python loop that snapshots the guest process list every 60 seconds and writes a structured log; integrate with Volatility 3's `windows.pslist` to detect process list manipulation. For Proxmox clusters, wrap `pvesh` and `qm/pct` in a single audit script that dumps cluster state, identifies running VMs/CTs, and flags any with `onboot: 1` plus a missing vTPM. Schedule all of these via cron in a CI-like fashion so that hypervisor drift is caught early.

## Reporting and Documentation

Hypervisor security reports should separate findings by layer: management plane exposures (vCenter/ESXi/Hyper-V/Proxmox API surface, lockdown status, SSH/DCUI status, SLP exposure), guest-to-host escape paths (CVE list with CVSS, patched version threshold, reproducible PoC reference), configuration weaknesses (no vTPM, no vSB, missing network segmentation, default credentials), and VMI/forensic capability gaps (no LibVMI sensor deployed, no Volatility 3 pipeline, no RAM snapshot automation). For each escape finding, document the full chain: guest-side primitive, the specific CVE, the QEMU/vmware-vmx/VMWP version tested, the patched version, and the recommended mitigation. Include a "blast radius" analysis showing what a successful escape on each host would compromise (number of sibling VMs, business sensitivity of datastores, exposure of cluster credentials). Reference the MITRE ATT&CK technique (typically T1068 for the CVE chain and T1021 for remote services such as vmkloadapp/SSH) and map the finding to the relevant CIS Hypervisor Benchmark control.

## Legal and Ethical Considerations

Hypervisor escape testing against production virtualization infrastructure carries extreme risk: a successful PoC can crash the host, corrupt datastores, or affect every sibling VM on the host. Always reproduce escapes in a nested lab first, and only verify against bare metal in a sacrificial test cluster that has been explicitly approved by the customer in the engagement scope. ESXi and Hyper-V ransomware techniques (enumeration, datastore access, VMDK manipulation) must never be executed against a production cluster even in "read-only" mode, because the enumeration itself often triggers monitoring alerts and can destabilize the cluster if it walks the MOB tree at scale. VMI tooling (LibVMI, DRAKVUF, HyperPlatform) that deploys a hypervisor should be tested only on hosts that are explicitly authorized for kernel-mode instrumentation, because deploying a malicious-looking hypervisor on a hardened host can cause the host's TPM-measured boot to fail attestation. Public-cloud hypervisors (AWS Nitro, Azure Hyper-V, GCE KVM) are out of scope for direct testing — the CSP's responsible disclosure policy applies.

## Integration with Other Tools

Hypervisor findings connect to multiple adjacent skills. A successful ESXi compromise transitions to `post-exploitation` (host-level privilege escalation, persistence via vmkloadapp or vSphere Auto Deploy), `digital-forensics` (RAM snapshots, datastore timeline), and `pentest-reporting` (ransomware blast-radius analysis). VMI output from DRAKVUF and Volatility 3 analysis feeds into `anti-forensics` (when defending against in-guest anti-analysis), `detection-engineering` (writing EDR rules from observed malware behavior), and `av-edr-evasion` (when red-teaming EDR by deploying a hypervisor beneath the OS). Container escape in a KubeVirt environment transitions to this skill for the VM-layer analysis and to `kubernetes-attack` for the orchestration layer. Hardware-assisted virtualization abuse (BluePill, Vitriol) overlaps with `hardware-security` for the CPU-specific primitives and with `firmware-reverse` when the malicious hypervisor hooks UEFI runtime services. Public-cloud IaaS findings (metadata service abuse, IMDSv2 bypass) connect to `cloud-security`.

## Case Studies and Examples

- **VENOM (CVE-2015-3456)**: The floppy disk controller emulation in QEMU had a buffer overflow in the `fdctrl_to_command()` handler reachable from inside any guest with a virtual floppy (default on until QEMU 2.x). CrowdStrike and Jason Geffner disclosed; the flaw affected Xen, KVM/QEMU, and any virtualization platform that shipped QEMU's floppy backend. Remediation was to disable the floppy device (`-nodefaults` or `-device floppy=off`) and upgrade QEMU. The lesson: legacy device emulation kept for compatibility is a persistent source of escape bugs.
- **VMware OpenSLP (CVE-2019-5544, CVE-2020-3992, CVE-2021-21974)**: ESXi shipped an outdated OpenSLP daemon on UDP 427 reachable from the management network. The flaws allowed unauthenticated remote heap corruption and led to remote code execution on the ESXi host itself. ESXiArgs ransomware (2023) used CVE-2021-21974 to mass-exploit exposed ESXi hosts and encrypt VMFS datastores. The lesson: even auxiliary services on the management plane are escape vectors; disable SLP if not needed (`/etc/init.d/slpd stop`).
- **Akira / Royal / BlackCat ESXi ransomware**: These crews typically enter via exposed VPN credentials (often stolen via info-stealer malware on an administrator's laptop), pivot to vCenter, suspend all VMs, and then encrypt the VMDK files in place. The attack rarely uses a hypervisor CVE; it is a management-plane compromise. The lesson: lockdown mode, network segmentation of the management plane, and MFA on vCenter SSO are more effective defenses than any patch.
- **Hyper-V VMBus (CVE-2017-0180 family)**: Multiple flaws in the Hyper-V vmbus driver (vid.sys, vmbus.sys) allowed a Windows guest to compromise the VMWP worker process on the host. Microsoft patched in monthly rollups. The lesson: Hyper-V flaws tend to be in the paravirtualized vmbus backend, not in emulated devices, because Hyper-V does not ship legacy device emulation by default.
- **BluePill (Joanna Rutkowska, 2006)**: Proof-of-concept malicious hypervisor using AMD64 SVM (Secure Virtual Machine) extensions. BluePill demonstrated that a thin hypervisor could be deployed beneath a running OS without rebooting, making it nearly undetectable from inside the OS. The lesson: hardware-assisted virtualization is dual-use — the same primitives that power legitimate hypervisors enable stealth rootkits.
- **HyperPlatform**: A research hypervisor by tandasat that demonstrates how to deploy a thin Intel VT-x hypervisor on Windows for defensive monitoring (kernel memory hooks via EPT, syscall tracing). HyperPlatform is the basis for DdiMon and other defensive introspection tools. The lesson: VMI does not require a heavy-weight full hypervisor; a thin Intel VT-x layer is sufficient for many defensive use cases.

## Detection and Evasion

Detection of hypervisor escape attempts focuses on three signals: management-plane anomalies (unusual vCenter API calls, ESXi SSH sessions from unexpected IPs, MOB access to sensitive managed objects), hypervisor process anomalies (qemu-system, vmware-vmx, or VMWP consuming abnormal CPU, opening unexpected files, spawning child processes), and guest-side anomalies (the guest attempting DMA to unusual MMIO regions, issuing malformed device commands, or testing for hypervisor presence via `cpuid` and timing attacks). Defenders should enable ESXi syslog to a SIEM, configure vCenter alarm definitions for "host connection state" changes, and deploy Falco or sysmon on the host OS for KVM/QEMU and Hyper-V respectively. Attackers evade by matching the timing of legitimate device traffic, issuing only one malformed command per guest reboot to defeat rate-based detection, and by pivoting through vCenter rather than direct host SSH so that alarms fire on the host where the crew has the least visibility. VMI-based detection (LibVMI, DRAKVUF, HyperPlatform) is itself hard to evade because the guest cannot directly observe the EPT hooks or the single-step traps; a sufficiently paranoid malware sample can attempt to detect VMI via timing (RDTSC deltas on trapped instructions), but this is rare in the wild.

## Advanced Techniques

Advanced hypervisor security testing includes: nested escape chains (guest-to-hypervisor followed by hypervisor-to-host-kernel LPE), cross-VM side channels via shared L3 cache (Prime+Probe, Flush+Reload on sibling VMs), VMBus/virtio backend fuzzing with custom QEMU harnesses, ESXi vmkernel heap spraying via crafted vmkloadapp modules, Hyper-V VTL1 (Virtual Trust Level 1 / Secure Kernel) bypass research, Xen altp2m abuse for stealth memory aliasing, ARM EL2 hypervisor deployment via KVM on Apple Silicon, and TrustZone-based introspection on ARMv8 devices. For high-assurance labs, deploy BluePill-style thin hypervisors beneath Windows or Linux hosts and instrument the entire guest from EPT hooks without ever loading a kernel module into the guest itself. The state of the art also includes confidential computing research: AMD SEV-SNP, Intel TDX, and ARM CCA introduce hardware-attested guest memory encryption that even the hypervisor cannot read — auditing these requires a different threat model (the hypervisor operator is the adversary).

## Tool Comparison Matrix

| Tool | Best For | Scope | Coverage | Skill Level |
|------|----------|-------|----------|-------------|
| **govc / pyvmomi / PowerCLI** | VMware enumeration & admin | vSphere only | Very broad | Beginner-Intermediate |
| **LibVMI / PyVMI** | Out-of-guest VM introspection (Xen/KVM/QEMU) | VMI only | Narrow | Advanced |
| **DRAKVUF** | Dynamic malware analysis on Xen | VMI + tracing | Medium | Advanced |
| **DECAF / PANDA** | Taint-based dynamic analysis | QEMU-based | Broad | Advanced |
| **QEMU (QMP/HMP)** | Reproducing device CVEs | All QEMU users | Broad | Intermediate |
| **virsh / libvirt** | KVM/QEMU/Xen/LXC management | Multi-hypervisor | Very broad | Beginner |
| **Xen xl / xe** | Xen toolstack | Xen only | Medium | Intermediate |
| **Hyper-V PowerShell** | Hyper-V admin & enumeration | Hyper-V only | Broad | Beginner |
| **Proxmox qm / pct** | Proxmox VE admin | Proxmox only | Broad | Beginner |
| **Wireshark (VMware/VNC)** | Management plane traffic analysis | Network only | Narrow | Intermediate |
| **Volatility 3** | VM RAM forensics | All (post-snapshot) | Very broad | Intermediate |
| **HyperPlatform / DdiMon** | Hypervisor-based defense (Windows) | Intel VT-x only | Narrow | Expert |

## Performance and Remediation

Performance characteristics vary significantly by tool and use case. govc and pyvmomi enumeration of a vCenter with 200 hosts and 4000 VMs takes 1-5 minutes depending on network latency; for scale, use the vSphere REST API with `$filter` and `$select` rather than the legacy SOAP API. LibVMI process-list walks on a Windows guest take 50-500 ms depending on guest memory pressure; DRAKVUF syscall tracing adds 2-10x overhead to the guest. HyperPlatform deployment on Windows is a one-time kernel-mode load (sub-second) but every EPT violation costs ~1000 cycles, so hooks should be selective. Volatility 3 against a 16 GB RAM dump takes 2-20 minutes depending on the plugin set; use the `banners` and `windows.info` plugins first to triage. For remediation, prioritize in order: disable ESXi SSH and DCUI, enable lockdown mode (Strict), segment the management network, patch all Critical/High hypervisor CVEs within 7 days, enable vTPM and vSB on every VM that supports it, deploy QEMU seccomp sandboxing on KVM, switch Xen XSM to FLASK policy, deploy a VMI sensor on high-value guests, and verify the ransomware backup strategy by performing a quarterly restore-from-backup drill on a representative VM.

## Hacker Laws

| Law | Application in Hypervisor Security |
|-----|-----------------------------------|
| **Defense in Depth** | A hypervisor is not a security boundary by itself. Lockdown mode + management network segmentation + vTPM + VMI monitoring + host kernel hardening must be layered; no single layer can be trusted as the sole defense against escape or ransomware |
| **Least Privilege** | ESXi hosts should not have SSH enabled; vCenter administrators should not be Domain Admins; Proxmox root should not be shared across nodes; VMs should not have PCI passthrough unless explicitly required. Every unnecessary permission is an escape or pivot vector |
| **Assume Breach** | Design monitoring assuming the hypervisor host has already been compromised. VMI sensors should be deployed on a separate hardened management VM, not on the host being monitored. RAM snapshot automation should run on a schedule, not on alert, so that post-incident forensics always has a recent baseline |
| **Supply Chain Trust** | Hypervisor firmware (UEFI on the host), hypervisor binaries (VMware ESXi image, QEMU package), and guest images all pass through multiple layers from vendor to runtime. Verify the SHA256 of every ESXi patch ISO and every QEMU package against the vendor's signed manifest; a poisoned mirror is a real threat |
| **Minimize Attack Surface** | Disable the ESXi MOB if not needed (`Config.HostAgent.plugins.solo.enableMob`), disable OpenSLP (`slpd stop`), disable QEMU default devices (`-nodefaults`), disable Hyper-V default vSwitches if not used. Reducing attack surface is more effective than chasing the next CVE |

---

## Learning Resources

  **This skill's supplementary files**: payloads.md, test-cases.md, guides/hypervisor-introspection-playbook.md
  **Related skills**: skills/container-security/SKILL.md (Linux containers, different boundary), skills/kubernetes-attack/SKILL.md (orchestration layer), skills/cloud-security/SKILL.md (CSP-managed hypervisors), skills/firmware-reverse/SKILL.md (pre-OS firmware)
  **External resources**:
- [VMware Security Advisories (VMSA)](https://www.vmware.com/security/advisories) - Authoritative patch and CVE source for vSphere/ESXi
- [Xen Project Security Advisories (XSA)](https://xenbits.xen.org/xsa/) - Xen hypervisor vulnerability archive
- [QEMU Security](https://www.qemu.org/contribute/security-process/) - QEMU vulnerability disclosure process and CVE list
- [LibVMI Project](https://libvmi.com/) - Virtual Machine Introspection library documentation
- [DRAKVUF on GitHub](https://github.com/tklengyel/drakvuf) - Dynamic malware analysis system
- [HyperPlatform on GitHub](https://github.com/tandasat/HyperPlatform) - Intel VT-x research hypervisor for Windows
- [MSRC Security Updates](https://msrc.microsoft.com/update-guide/) - Hyper-V monthly CVE bulletins
- [CIS VMware ESXi Benchmark](https://www.cisecurity.org/benchmark/vmware) - ESXi hardening baseline
- [MITRE ATT&CK T1068](https://attack.mitre.org/techniques/T1068/) - Exploitation for Privilege Escalation

---

## Threat Model and Trust Boundaries

### Trust Boundaries in Virtualization

A virtualized environment has multiple trust boundaries; this skill targets the boundaries that contain a hypervisor or VM. Understanding which boundary is in scope clarifies which attack primitive and which defensive tooling apply:

1. **Guest OS Kernel to Guest User Space**: This is the standard OS boundary (ring 0 vs ring 3 / kernel vs user). Not the focus of this skill; covered by `privilege-escalation`.
2. **Guest User to Guest OS Kernel via Syscalls**: Same as above, OS-level.
3. **Guest OS to Hypervisor**: The classic VM escape boundary. An attacker inside a guest triggers a hypervisor bug (in QEMU device emulation, VMware VMX, Hyper-V VMWP) to gain code execution in the hypervisor process or in the host kernel. This is the primary focus of this skill's offensive track.
4. **Hypervisor to Host Kernel**: For Type-2 hypervisors (KVM/QEMU, VMware Workstation, VirtualBox), the hypervisor process runs as a userland process on the host kernel. After escape from guest to hypervisor, the next step is host-kernel LPE. For Type-1 hypervisors (ESXi, Hyper-V parent partition, Xen Dom0), this distinction is murkier; vmkernel is the host kernel, and the Dom0 is a privileged guest.
5. **Hypervisor to Sibling VMs**: After compromising the hypervisor, the attacker pivots to other VMs running on the same host. For ESXi ransomware, this is the primary objective: suspend all sibling VMs, then encrypt their VMDKs in place.
6. **Management Plane to Hypervisor**: The vCenter/vpxd, ESXi hostd, libvirt, XenStore, Hyper-V vmms, and Proxmox pveproxy services constitute the management plane. Compromising the management plane (via credentials, API abuse, or CVE) gives the attacker control of every VM under management without needing a guest-to-host escape at all.
7. **Guest to Host Kernel via Hardware (DMA, side channels)**: A guest with PCI passthrough or a guest exploiting Spectre/Meltdown/L1TF/MDS variants can attack the host or sibling VMs through hardware, bypassing the hypervisor entirely.

### Out of Scope for This Skill

- **Container escape** (Docker, containerd, podman, runc): See `container-security`.
- **Kubernetes API server / etcd / RBAC**: See `kubernetes-attack`.
- **Public-cloud IaaS control plane** (AWS IMDS, Azure ARM, GCP IAM): See `cloud-security`.
- **OS kernel LPE inside the guest**: See `privilege-escalation`.
- **Pre-OS firmware (UEFI/BIOS) attacks**: See `firmware-reverse`.
- **Physical hardware attacks (JTAG, glitching, fault injection)**: See `hardware-security`.

---

## Real-World Incident Timeline

A non-exhaustive timeline of notable public hypervisor/virtualization incidents to inform scope and prioritization:

| Year | Incident | Lesson |
|------|----------|--------|
| 2006 | BluePill (Joanna Rutkowska, Black Hat USA) | Demonstrated that a thin AMD64 SVM hypervisor can be deployed beneath a running OS without reboot. The hardware-assisted virtualization primitives that power legitimate hypervisors also enable stealth rootkits. |
| 2006 | SubVirt (King, Chen, Wang, Verbowski, Joshi, Lids, 2006) | Comparable to BluePill but on Intel VT-x. Established the field of VM-based rootkits. |
| 2011 | Hyper-V CVE-2017-0180 series | First widely-publicized Hyper-V guest-to-host escape (MS17-0113). Demonstrated that vmbus.sys is a real attack surface. |
| 2015 | VENOM (CVE-2015-3456) | QEMU floppy buffer overflow disclosed by Jason Geffner (CrowdStrike). Affected every QEMU-based platform. Established the playbook for responsible disclosure of hypervisor escape CVEs. |
| 2017 | VMware OpenSLP issues (CVE-2017-15645 et al) | First signs that ESXi's OpenSLP service was a recurring escape vector. Should have prompted removal; was not. |
| 2019 | CVE-2019-5544 (OpenSLP) | First of three (ultimately four) ESXi OpenSLP RCEs. Every patch cycle, the bug came back. |
| 2020 | CVE-2020-3992 (OpenSLP) | Second OpenSLP RCE in ESXi. |
| 2021 | CVE-2021-21974 (OpenSLP) | Third OpenSLP RCE in ESXi. Two years later, this became the basis for ESXiArgs ransomware. |
| 2023 (Feb) | ESXiArgs ransomware | Mass-exploited CVE-2021-21974 against thousands of internet-facing ESXi hosts. Lesson: even two-year-old CVEs become mass-exploitation vectors when management plane is exposed. |
| 2023 (Mar) | Akira ransomware targeting ESXi | New crew pivoting from Windows to ESXi. Initial access via stolen VPN credentials, not CVE. Lesson: management plane credential theft is the dominant ESXi ransomware vector. |
| 2023 (May) | CVE-2023-3354 (QEMU jobs overflow) | Reminder that QEMU device emulation continues to produce escape bugs; even relatively minor devices matter. |
| 2024+ | Confidential computing (SEV-SNP, TDX) shift | Threat model shifts to "operator is adversary"; defenders must now attest the hypervisor itself, not just patch it. |

---

## Mapping to MITRE ATT&CK

This skill maps most directly to the following MITRE ATT&CK techniques:

| Technique | Name | Hypervisor Application |
|-----------|------|------------------------|
| T1068 | Exploitation for Privilege Escalation | The canonical "VM escape" technique — guest exploits hypervisor bug to elevate from guest user to hypervisor/host kernel |
| T1190 | Exploit Public-Facing Application | OpenSLP (CVE-2021-21974), vCenter (CVE-2021-22005), libvirt TCP — exploitation of exposed management plane |
| T1078 | Valid Accounts | ESXi ransomware crews' dominant vector — stolen VPN / vCenter SSO credentials |
| T1486 | Data Encrypted for Impact | VMDK encryption by ESXi ransomware (Akira, Royal, BlackCat, Play, ESXiArgs) |
| T1562 | Impair Defenses | Disabling vmware-tools, killing vmware-vmx, deleting ESXi syslog |
| T1490 | Inhibit System Recovery | Deleting ESXi snapshots (.vmsn) before encryption to prevent restore |
| T1210 | Exploitation of Remote Services | Hyper-V Live Migration interception, libvirt remote protocol abuse |
| T1557 | Adversary-in-the-Middle | Live Migration / vMotion traffic interception (cleartext or weakly authed) |
| T1005 | Data from Local System | VMDK offline mount + read |
| T1003 | OS Credential Dumping | VM RAM snapshot + Volatility lsass dump |
| T1055 | Process Injection | Hypervisor-based rootkit (BluePill, Vitriol) injecting beneath the OS |

---

## Performance Considerations and Operational Notes

Hypervisor security work has several operational characteristics that affect scheduling, scoping, and reporting:

- **VMI overhead is real**: DRAKVUF and similar VMI tools add 2-10x guest CPU overhead under heavy tracing. Schedule VMI runs off-peak or on dedicated malware- analysis hosts, never on production guests.
- **Escape reproduction is fragile**: QEMU device emulation bugs are often timing- sensitive; a PoC that triggers the bug reliably on one host may not reproduce on another. Always pin QEMU version, host kernel version, and guest kernel version in lab notes.
- **ESXi patching requires maintenance windows**: ESXi cannot patch certain components without reboot. Schedule patch windows monthly for non-critical CVEs and emergency (within 24h) for Critical CVEs with public PoCs.
- **RAM capture is space-intensive**: A 16 GB guest's RAM dump is 16 GB. Plan storage capacity before enabling automated snapshots; consider compression (`virsh dump --memory-only | pigz > dump.gz`).
- **Nested virtualization is slow**: Reproducing a hypervisor escape inside a nested hypervisor adds 30-50% overhead. Acceptable for verification, not for fuzzing at scale.
- **Confidential computing breaks VMI**: SEV-SNP/TDX guests cannot be introspected by the hypervisor. As confidential computing adoption grows, the VMI use case narrows to customer-side deployments only.

---

## Integration with kali-claw Operating Rhythm

This skill integrates with the broader kali-claw agent workspace as follows:

- **Daily memory log**: When a hypervisor engagement is active, log lab environment state (versions, snapshots) to `memory/YYYY-MM-DD.md` for resumption.
- **Chronicle milestones**: When a new CVE PoC is reproduced in the lab, record the milestone in `chronicle/YYYY-MM/hypervisor.md`.
- **Heartbeat health check**: Verify that LibVMI, DRAKVUF, and Volatility 3 are installed and runnable (`validation/heartbeat.sh --json` should include a check).
- **Tool inventory**: Update `TOOLS.md` when a new VMI tool (e.g., Moneta, DdiMon) is added to the lab.
- **Engagement templates**: Use `validation/engagement-template/targets.json.example` to scope hypervisor engagements (target: a vCenter URL, a single ESXi host IP, a QEMU monitor socket).

---

## Conclusion

Hypervisor introspection and virtualization escape assessment is a distinct discipline within offensive security: it sits at the boundary between guest and host, between attacker code and the platform's isolation guarantees, and between offense (escape CVEs) and defense (VMI-based detection). Mastering it requires fluency in CPU virtualization primitives (Intel VT-x, AMD-V, ARM EL2), the major hypervisor families (VMware, Microsoft, KVM/QEMU, Xen, Proxmox, bhyve, AHV), the management plane protocols that expose them, and the defensive tooling that introspects them from outside. The discipline is increasingly relevant as ESXi ransomware crews exploit the management plane at scale, as confidential computing shifts the threat model to "operator is adversary," and as VM-based detection (VMI, HyperPlatform) becomes a compensating control where in-guest EDR cannot be deployed.

---
