# Hypervisor Introspection (VMI) Test Cases

> Structured test cases (TC-HI-001 through TC-HI-012) covering VMware MOB enumeration, ESXi SLP fingerprinting, QEMU QMP unauth access, KVM PCI passthrough auditing, LibVMI memory reads, DRAKVUF malware tracing, VENOM reproduction, Hyper-V VMWP enumeration, and more. All tests are for authorized security testing only — reproduce escape PoCs only in nested lab environments.

---

## Statistics

| Category | Test Cases |
|----------|-----------|
| A. VMware ESXi/vSphere | 3 |
| B. Microsoft Hyper-V | 2 |
| C. KVM/QEMU | 2 |
| D. Xen | 1 |
| E. Proxmox VE | 1 |
| F. Virtual Machine Introspection | 2 |
| G. Hypervisor-based Defense | 1 |
| **Total** | **12** |

---

## A. VMware ESXi / vSphere

### TC-HI-001: VMware MOB (Managed Object Browser) Enumeration and Access Control

| Field | Value |
|------|-----|
| **Test ID** | TC-HI-001 |
| **Name** | VMware MOB (Managed Object Browser) Enumeration and Access Control |
| **Category** | A. VMware ESXi/vSphere |
| **Severity** | HIGH |
| **Prerequisites** | Network access to ESXi hostd (TCP 443) or vCenter vpxd (TCP 443); valid credentials OR anonymous access |
| **Test Steps** | 1. Browse to `https://<target>/mob` and observe whether the MOB is enabled<br>2. If authentication is required, attempt login with `root:<PASSWORD>` for ESXi or `administrator@vsphere.local:<PASSWORD>` for vCenter<br>3. Without authenticating, attempt to read the root folder: `curl -k https://<target>/mob/?moid=ha-folder-root`<br>4. If authenticated, enumerate sensitive paths: `/mob/?moid=ha-host&doPath=configManager`, `/mob/?moid=ha-host&doPath=config.option`, `/mob/?moid=AuthorizationManager`<br>5. Look for plaintext credentials in `config.option` (VLAN IDs, license keys, SSO configuration)<br>6. Test the `Config.HostAgent.plugins.solo.enableMob` advanced option state: `govc host.option.get Config.HostAgent.plugins.solo.enableMob` |
| **Expected Results** | MOB should be DISABLED in production (`enableMob=false`). If enabled, anonymous access should be impossible (HTTP 401). Authenticated access should require SSO or root only; no low-privilege user should reach `config.option`. The advanced option value should read `false` on hardened hosts. |
| **Remediation** | Disable MOB on every ESXi host: `vim-cmd hostsvc/advopt/update Config.HostAgent.plugins.solo.enableMob string false` and restart hostd: `/etc/init.d/hostd restart`. On vCenter, restrict `/mob` URL access via reverse-proxy ACL. Audit ESXi host configuration via govc to confirm `enableMob=false` across the fleet. |

### TC-HI-002: ESXi OpenSLP Fingerprinting and CVE-2021-21974 Exposure

| Field | Value |
|------|-----|
| **Test ID** | TC-HI-002 |
| **Name** | ESXi OpenSLP Fingerprinting and CVE-2021-21974 Exposure |
| **Category** | A. VMware ESXi/vSphere |
| **Severity** | CRITICAL |
| **Prerequisites** | Network reachability to ESXi host on UDP 427; nmap with slp scripts; slptool |
| **Test Steps** | 1. Confirm SLP is reachable: `nmap -sU -p 427 --script=slp-systeminfo <target>`<br>2. Enumerate SLP service types: `slptool -u <target> findsrvtypes`<br>3. Enumerate specific services: `slptool -u <target> findsrvs service:service-agent`<br>4. Check ESXi build number: `govc about -u root:<PW>@<target>`<br>5. Compare build number against the VMware patch matrix for CVE-2019-5544 (ESXi 6.7 U3), CVE-2020-3992 (ESXi 7.0 U2c), CVE-2021-21974 (ESXi 7.0 U2c / 6.7 U3o / 6.5 U3q)<br>6. If vulnerable, attempt to reach the SLP service from the guest network (indicates management VLAN leak) |
| **Expected Results** | SLP should NOT be reachable from the guest network or the internet. Build number should be at or above the patched threshold for the latest OpenSLP CVE. SLP daemon should ideally be stopped entirely (`/etc/init.d/slpd status` returns stopped) unless explicitly required for service discovery. |
| **Remediation** | Stop SLP daemon: `/etc/init.d/slpd stop; chkconfig slpd off`. Block UDP 427 at the ESXi firewall: `esxcli network firewall ruleset set -r slp -e false`. Patch ESXi to a version above the CVE-2021-21974 threshold. Migrate the management network to a dedicated non-routable VLAN. |

### TC-HI-003: vSphere REST API / SSO Authentication Audit

| Field | Value |
|------|-----|
| **Test ID** | TC-HI-003 |
| **Name** | vSphere REST API / SSO Authentication Audit |
| **Category** | A. VMware ESXi/vSphere |
| **Severity** | HIGH |
| **Prerequisites** | Network access to vCenter on TCP 443; valid read-only credentials; PowerCLI or govc |
| **Test Steps** | 1. Acquire a session token via REST API: `curl -k -X POST https://<vc>/api/session -H "Content-Type: application/json" -d '{"username":"administrator@vsphere.local","password":"<PW>"}'`<br>2. Verify SSO realm is `vsphere.local` (not customer AD) for the primary admin<br>3. Enumerate SSO users via dir-cli: `/usr/lib/vmware-vmafd/bin/dir-cli user list --login administrator@vsphere.local`<br>4. List SSO Administrators group members<br>5. Check password policy: complexity, expiration, lockout threshold<br>6. Check for stale SSO sessions: `govc session.ls`<br>7. Test for CVE-2022-31656 (auth bypass) by issuing a malformed SSO request |
| **Expected Results** | SSO admin should be in `vsphere.local` realm. Password policy should require 15+ characters, lockout after 5 attempts. No stale sessions older than 24 hours. CVE-2022-31656 should not reproduce (request rejected). No service accounts in the Administrators group. |
| **Remediation** | Rotate SSO admin password quarterly. Enable SSO password lockout. Apply vCenter patches for CVE-2022-31656 (vCenter 7.0 U3g / 6.7 U3t). Move service accounts to dedicated roles with least privilege. Enable vCenter alarm for SSO admin logins from unexpected IPs. |

---

## B. Microsoft Hyper-V

### TC-HI-004: Hyper-V VMWP (Virtual Machine Worker Process) Enumeration

| Field | Value |
|------|-----|
| **Test ID** | TC-HI-004 |
| **Name** | Hyper-V VMWP (Virtual Machine Worker Process) Enumeration |
| **Category** | B. Microsoft Hyper-V |
| **Severity** | MEDIUM |
| **Prerequisites** | Local administrator on Hyper-V host; PowerShell with Hyper-V module |
| **Test Steps** | 1. List VMWP processes: `Get-Process vmwp \| Select Id, StartTime, @{N='VM';E={(Get-VM \| Where-Object {$_.Id -eq (Get-WmiObject -Namespace root\virtualization\v2 -Class Msvm_ComputerSystem -Filter "ProcessId=$($_.Id)").Name}}}`<br>2. For each VMWP, list loaded modules: `Get-Process -Id <PID> \| Select-Object -ExpandProperty Modules \| Select ModuleName, FileVersion`<br>3. Check vmbus.sys, vid.sys, hvp.sys versions against MSRC patch matrix<br>4. Enumerate child processes of each VMWP: `Get-WmiObject Win32_Process -Filter "ParentProcessId=<PID>"` (any non-empty result is suspicious — VMWP should not spawn children)<br>5. Check Hyper-V integration services version on each guest: `Get-VMIntegrationService -VMName <vm>`<br>6. Verify VBS / HVCI state: `$dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace 'root\Microsoft\Windows\DeviceGuard'; $dg.SecurityServicesRunning` |
| **Expected Results** | Each VM has exactly one VMWP. VMWP module versions match the latest MSRC patch. No VMWP has child processes (sign of escape). Integration services up to date. VBS and HVCI both running on capable hosts. |
| **Remediation** | Apply latest MSRC rollup to Hyper-V host. Update integration services in each guest. Investigate any VMWP child process as a possible escape. Enable VBS and HVCI where hardware supports. Deploy Sysmon on the Hyper-V host with rules to alert on VMWP process creation events. |

### TC-HI-005: Hyper-V Live Migration Traffic Inspection

| Field | Value |
|------|-----|
| **Test ID** | TC-HI-005 |
| **Name** | Hyper-V Live Migration Traffic Inspection |
| **Category** | B. Microsoft Hyper-V |
| **Severity** | HIGH |
| **Prerequisites** | Hyper-V failover cluster with multiple nodes; network capture capability on cluster network |
| **Test Steps** | 1. Enumerate cluster networks: `Get-ClusterNetwork \| Select Name, Address, Role`<br>2. Identify the Live Migration network (Role = 1, internal)<br>3. Check Live Migration auth: `Get-VMHost \| Select VirtualMachineMigrationAuthType` (should be Kerberos, not CredSSP or None)<br>4. Trigger a test Live Migration and capture traffic: `tcpdump -i <lm-iface> -w lm.pcap host <dest-node>`<br>5. Inspect capture in Wireshark — look for SMB (port 445), Live Migration (port 6600), and plaintext credentials<br>6. Verify Live Migration network is non-routable: `Get-NetRoute -InterfaceAlias <lm-iface>` should show no default route<br>7. Test from a guest subnet whether the LM network is reachable (should NOT be) |
| **Expected Results** | Live Migration network should be isolated (no default route, unreachable from guest subnet). Auth should be Kerberos. Traffic should be encrypted (TLS or Kerberos-protected SMB). No plaintext credentials visible in the capture. |
| **Remediation** | Set LM auth to Kerberos: `Set-VMHost -VirtualMachineMigrationAuthType Kerberos`. Configure constrained delegation for the Hyper-V host computer accounts in AD. Place LM network on a dedicated non-routable VLAN. Block SMB and TCP 6600 at the firewall for any interface other than the LM network. |

---

## C. KVM / QEMU

### TC-HI-006: QEMU Monitor Protocol (QMP) Unauthenticated Access

| Field | Value |
|------|-----|
| **Test ID** | TC-HI-006 |
| **Name** | QEMU Monitor Protocol (QMP) Unauthenticated Access |
| **Category** | C. KVM/QEMU |
| **Severity** | CRITICAL |
| **Prerequisites** | Network access to suspected QEMU monitor port (TCP 4444, 55555, etc., or Unix socket); netcat or qmp-shell |
| **Test Steps** | 1. Identify QEMU instances on the host: `ps aux \| grep qemu-system`<br>2. Read each QEMU command line for `-qmp` or `-monitor` options: `cat /proc/<PID>/cmdline \| tr '\0' '\n' \| grep -E 'qmp\|monitor'`<br>3. For TCP-exposed QMP, test connection: `echo '{"execute":"qmp_capabilities"}' \| nc <host> <port>`<br>4. If successful, enumerate guest: `{"execute":"query-name"}`, `{"execute":"query-uuid"}`, `{"execute":"query-version"}`<br>5. Test memory dump (high-impact): `{"execute":"pmemsave","arguments":{"val":0,"size":16777216,"filename":"/tmp/dump.bin"}}`<br>6. For Unix-socket QMP, check permissions: `ls -la /var/lib/libvirt/qemu/<domain>.monitor` (should be 0600 owned by libvirt-qemu, not world-readable)<br>7. Verify QMP is bound to 127.0.0.1, not 0.0.0.0 |
| **Expected Results** | QMP should NEVER be exposed on a public interface. TCP QMP should bind to 127.0.0.1 only. Unix socket QMP should be mode 0600, owned by libvirt-qemu or qemu user. No unauthenticated access should be possible. If exposed, an attacker can dump guest RAM (extracting credentials) or shut down the guest at will. |
| **Remediation** | Bind QMP to 127.0.0.1: `-qmp tcp:127.0.0.1:4444,server,nowait`. Prefer Unix socket over TCP. Set restrictive permissions on Unix socket. Use TLS (`-qmp tcp:...:port,tls,server,nowait`) if remote access is required. Restrict at the firewall: drop TCP <qmp-port> from all interfaces except localhost. |

### TC-HI-007: KVM PCI Passthrough and IOMMU Configuration Audit

| Field | Value |
|------|-----|
| **Test ID** | TC-HI-007 |
| **Name** | KVM PCI Passthrough and IOMMU Configuration Audit |
| **Category** | C. KVM/QEMU |
| **Severity** | HIGH |
| **Prerequisites** | Root access to KVM host; IOMMU enabled in BIOS; libvirt CLI access |
| **Test Steps** | 1. Verify IOMMU is enabled in kernel cmdline: `cat /proc/cmdline \| grep -E 'intel_iommu\|amd_iommu'`<br>2. List IOMMU groups on host: `for d in /sys/kernel/iommu_groups/*/devices/*; do n=${d#*/iommu_groups/*}; n=${n%%/*}; printf 'IOMMU Group %s %s\n' "$n" "${d##*/}"; done`<br>3. List PCI devices assigned to guests: `virsh nodedev-list --tree \| grep pci` then `virsh nodedev-dumpxml pci_0000_<addr>`<br>4. For each passthrough device, verify the entire IOMMU group is owned by vfio-pci on the host: `lspci -nnk -s <addr>` (Kernel driver should be `vfio-pci`, not the native driver)<br>5. Verify no host filesystem access to the device (no /dev nodes referencing the PCI BDF)<br>6. Check for SR-IOV virtual functions and their assignment: `lspci \| grep -i 'virtual function'`<br>7. Audit device firmware version (often the source of VF shared bugs): `lspci -vvv -s <addr>` |
| **Expected Results** | IOMMU is enabled. Each passthrough device's entire IOMMU group is assigned to vfio-pci on the host (no half-groups). No host filesystem access to passthrough devices. SR-IOV VFs are documented. Device firmware is current. |
| **Remediation** | Enable IOMMU strict mode: kernel cmdline `intel_iommu=on,strict iommu=pt`. Migrate from whole-device passthrough to SR-IOV where the device supports it. Apply device firmware updates. Document every passthrough assignment and review quarterly. Prefer paravirtualized (virtio) devices over passthrough for any workload that does not require bare-metal device performance. |

---

## D. Xen

### TC-HI-008: Xen Dom0/DomU Privilege Boundary and XSA Patch Audit

| Field | Value |
|------|-----|
| **Test ID** | TC-HI-008 |
| **Name** | Xen Dom0/DomU Privilege Boundary and XSA Patch Audit |
| **Category** | D. Xen |
| **Severity** | HIGH |
| **Prerequisites** | Root on Xen Dom0; xl CLI; xenstore-utils |
| **Test Steps** | 1. Verify Xen version: `xl info \| grep xen_changeset` and compare against XSA patch matrix<br>2. List all domains: `xl list`<br>3. Identify PV vs HVM vs PVH guests: `xl list -l <domid> \| grep -E '"type"\|"builder"'`<br>4. Check XSM/FLASK state: `xl info \| grep -i xsm` (should report `xsm: flask`)<br>5. Enumerate XenStore permissions: `xenstore-ls \| grep -E 'domid\|perm'`<br>6. For each PV guest, check toolstack version (qemu-dp, blkback): `xl block-list <domid>` and cross-reference with XSA-242 (PV block backend)<br>7. For each HVM guest, check device model version: `xl list -l <domid> \| grep device_model_version` (should be `qemu-xen`, not `qemu-xen-traditional`)<br>8. Verify Dom0 is hardened (Debian Security Guide, minimal package set) |
| **Expected Results** | Xen version patched against all Critical XSAs (XSA-148, XSA-182, XSA-242, XSA-253, XSA-417, XSA-419, XSA-424 and successors). XSM-FLASK enabled in enforcing mode. No PV guests (migrated to PVH). Device model is `qemu-xen` (modern) not `qemu-xen-traditional`. Dom0 is minimal and hardened. |
| **Remediation** | Patch Xen to the latest stable. Enable XSM-FLASK: `grub: flask=enforcing`. Migrate PV guests to PVH (`type = "pvh"` in config). Replace `qemu-xen-traditional` with `qemu-xen`. Harden Dom0: remove unnecessary packages, restrict network exposure, run Dom0 as a Qubes-style minimal appliance. |

---

## E. Proxmox VE

### TC-HI-009: Proxmox VE Cluster Audit (pveproxy, Corosync, LXC Boundary)

| Field | Value |
|------|-----|
| **Test ID** | TC-HI-009 |
| **Name** | Proxmox VE Cluster Audit (pveproxy, Corosync, LXC Boundary) |
| **Category** | E. Proxmox VE |
| **Severity** | HIGH |
| **Prerequisites** | SSH root access to a Proxmox VE node; pvesh, qm, pct CLIs |
| **Test Steps** | 1. Verify Proxmox version: `pveversion`<br>2. Check cluster state: `pvecm status` and `pvecm nodes`<br>3. Audit pveproxy binding: `ss -tlnp \| grep 8006` (should bind to management IP, not 0.0.0.0)<br>4. Check 2FA state for root@pam: `pveum user list` and `pveum acl list`<br>5. List KVM guests: `qm list`; for each, audit config: `qm config <vmid> \| grep -E 'vnc\|spice\|cloudinit\|onboot'`<br>6. List LXC containers: `pct list`; for each, audit config: `pct config <ctid> \| grep -E 'privileged\|nesting\|keyctl\|features\|mountpoint'`<br>7. Test LXC escape indicators: `pct config <ctid> \| grep -E 'privileged: 1\|nesting: 1\|keyctl: 1'`<br>8. Audit Corosync config: `cat /etc/pve/corosync.conf`<br>9. Verify Corosync network isolation: `ss -ulnp \| grep -E '5404\|5405'` (should bind to cluster interface only) |
| **Expected Results** | pveproxy binds to management IP only (not 0.0.0.0). 2FA enabled for root@pam. No LXC container has `privileged: 1` or `nesting: 1` unless explicitly documented. Corosync on dedicated non-routable VLAN. All guests have current Proxmox security updates applied. |
| **Remediation** | Bind pveproxy to management IP: edit `/etc/default/pveproxy` with `LISTEN_IP="<mgmt-ip>"`. Enable 2FA: `pveum user modify root@pam -keys tstotp`. Migrate LXC `privileged: 1` containers to unprivileged (rebuilds user/group mapping). Isolate Corosync on a dedicated VLAN. Apply Proxmox security updates monthly via `apt update && apt upgrade`. |

---

## F. Virtual Machine Introspection

### TC-HI-010: LibVMI Out-of-Guest Memory Read and Process Walk

| Field | Value |
|------|-----|
| **Test ID** | TC-HI-010 |
| **Name** | LibVMI Out-of-Guest Memory Read and Process Walk |
| **Category** | F. Virtual Machine Introspection |
| **Severity** | INFO |
| **Prerequisites** | LibVMI installed on Xen or KVM host; test VM running with known kernel; /etc/libvmi.conf configured |
| **Test Steps** | 1. Configure LibVMI for the target guest: edit `/etc/libvmi.conf` and add a stanza for the guest name with ostype and sysmap or rekall_profile<br>2. Verify LibVMI can attach: `pyvmi -d <guest> -n pslist` (should print a process list)<br>3. Read a kernel symbol from outside the guest: `python3 -c "import libvmi; vmi=libvmi.VMI('<guest>'); print(hex(vmi.translate_ksym2v('init_task')))"` (Linux) or `PsActiveProcessHead` (Windows)<br>4. Walk the Linux process list (init_task -> tasks) or Windows process list (PsActiveProcessHead -> ActiveProcessLinks)<br>5. Cross-validate against the in-guest process list (`ps aux` inside the guest): both lists should match<br>6. Measure timing: a process list walk should take 50-500ms on a moderately loaded guest<br>7. Verify the guest cannot detect the introspection (no CPU spike, no QEMU monitor events visible to guest) |
| **Expected Results** | LibVMI successfully attaches to the guest. Kernel symbol translation returns valid virtual address. Process list walk returns the same processes as the in-guest `ps` command. The guest shows no detectable sign of introspection (no CPU spike visible in `top`). |
| **Remediation** | (Informational test; no remediation required.) For defensive use, deploy LibVMI on dedicated monitoring VMs to avoid performance impact on production guests. Integrate output with SIEM for anomaly detection. Cross-validate with DRAKVUF for syscall-level tracing. |

### TC-HI-011: DRAKVUF Dynamic Malware Analysis Trace

| Field | Value |
|------|-----|
| **Test ID** | TC-HI-011 |
| **Name** | DRAKVUF Dynamic Malware Analysis Trace |
| **Category** | F. Virtual Machine Introspection |
| **Severity** | INFO |
| **Prerequisites** | Xen host with DRAKVUF installed; Windows guest with Rekall profile; safe malware sample (e.g., from MalwareBazaar, labeled for research) |
| **Test Steps** | 1. Snapshot the clean Windows guest (so analysis can be reverted): `xl save <domid> /var/lib/xen/snapshots/clean.state`<br>2. Configure /etc/libvmi.conf with the guest's Rekall profile path<br>3. Run DRAKVUF with syscall, file, registry, and network tracers: `drakvuf -r /root/profiles/win10.json -d <vm> -e 'C:\\sample.exe' -o json -D /var/log/drakvuf/ -a syscalls -a filetracer -a regtracer -a socketmon`<br>4. Wait for analysis to complete (typically 60-300 seconds for most samples)<br>5. Inspect JSON output for indicators: `jq 'select(.Plugin == "syscalls" and .EventName == "NtCreateFile" and .FileName \| contains("AppData"))' /var/log/drakvuf/*.log`<br>6. Extract any dropped files (filetracer plugin logs full paths)<br>7. Compare the DRAKVUF-derived process tree against the in-guest view to detect any rootkit activity (process list manipulation)<br>8. Revert the guest to clean snapshot |
| **Expected Results** | DRAKVUF successfully traces the malware sample. Output JSON contains all four tracer plugin events. No in-guest instrumentation detected (malware was tricked). Reverted snapshot is clean for the next sample. |
| **Remediation** | (Informational test.) For production deployment, automate this as a pipeline: sample submission -> DRAKVUF analysis -> JSON upload to SIEM -> automated YARA matching on extracted files. Schedule regular sample processing during off-peak hours. |

---

## G. Hypervisor-based Defense

### TC-HI-012: VENOM (CVE-2015-3456) Reproduction Lab

| Field | Value |
|------|-----|
| **Test ID** | TC-HI-012 |
| **Name** | VENOM (CVE-2015-3456) Reproduction Lab |
| **Category** | G. Hypervisor-based Defense |
| **Severity** | CRITICAL |
| **Prerequisites** | Nested lab only (NEVER production); QEMU source for v2.3.0; development tools (gcc, make, python); isolated test VM with a Linux guest |
| **Test Steps** | 1. Build vulnerable QEMU in an isolated lab VM: `git clone https://gitlab.com/qemu-project/qemu.git && cd qemu && git checkout v2.3.0 && ./configure --target-list=x86_64-softmmu --enable-debug && make -j$(nproc)`<br>2. Create a test disk image: `qemu-img create -f qcow2 disk.qcow2 1G`<br>3. Create an empty floppy image (the vulnerable device): `dd if=/dev/zero of=empty.img bs=512 count=2880`<br>4. Launch QEMU with the floppy device attached: `./x86_64-softmmu/qemu-system-x86_64 -m 256 -hda disk.qcow2 -fda empty.img -monitor stdio`<br>5. From inside the guest, execute the VENOM PoC (assembly: reset FDC, issue READ_ID with malformed track value, trigger heap overflow)<br>6. Observe QEMU crash or unexpected behavior in the monitor (heap corruption -> RCE in qemu-system process)<br>7. Repeat with patched QEMU (v2.3.1+ or current): `git checkout v2.3.1 && make -j$(nproc)` and re-test<br>8. Document: vulnerable version crashes, patched version rejects the malformed command |
| **Expected Results** | Vulnerable QEMU (v2.3.0) crashes or exhibits heap corruption when the PoC is executed. Patched QEMU (v2.3.1+) rejects the malformed floppy command without crashing. The reproduction confirms both the vulnerability and the effectiveness of the patch. |
| **Remediation** | (Lab test.) Production remediation: ensure all production QEMU is at v2.3.1 or later (modern distros ship 5.x+). Disable the floppy device by default: `-nodefaults` or `-global isa-fdc.driveA=`. Run qemu-system as unprivileged user with seccomp filtering: `-sandbox on,obsolete=deny,elevateprivileges=deny`. Audit running QEMU instances for legacy device exposure: `ps aux \| grep qemu-system \| grep -E 'fda\|fdc'`. |

---

## Test Case Index

| Test ID | Name | Severity | Category |
|---------|------|----------|----------|
| TC-HI-001 | VMware MOB Enumeration and Access Control | HIGH | VMware ESXi/vSphere |
| TC-HI-002 | ESXi OpenSLP Fingerprinting and CVE-2021-21974 Exposure | CRITICAL | VMware ESXi/vSphere |
| TC-HI-003 | vSphere REST API / SSO Authentication Audit | HIGH | VMware ESXi/vSphere |
| TC-HI-004 | Hyper-V VMWP (Virtual Machine Worker Process) Enumeration | MEDIUM | Microsoft Hyper-V |
| TC-HI-005 | Hyper-V Live Migration Traffic Inspection | HIGH | Microsoft Hyper-V |
| TC-HI-006 | QEMU Monitor Protocol (QMP) Unauthenticated Access | CRITICAL | KVM/QEMU |
| TC-HI-007 | KVM PCI Passthrough and IOMMU Configuration Audit | HIGH | KVM/QEMU |
| TC-HI-008 | Xen Dom0/DomU Privilege Boundary and XSA Patch Audit | HIGH | Xen |
| TC-HI-009 | Proxmox VE Cluster Audit | HIGH | Proxmox VE |
| TC-HI-010 | LibVMI Out-of-Guest Memory Read and Process Walk | INFO | VMI |
| TC-HI-011 | DRAKVUF Dynamic Malware Analysis Trace | INFO | VMI |
| TC-HI-012 | VENOM (CVE-2015-3456) Reproduction Lab | CRITICAL | Hypervisor-based Defense |

---

## Severity Distribution

| Severity | Count |
|----------|-------|
| CRITICAL | 3 |
| HIGH | 5 |
| MEDIUM | 1 |
| INFO | 2 |
| LOW | 0 |
| **Total** | **12** (note: CRITICAL count exceeds HIGH because the most severe findings — QMP unauth, OpenSLP exposure, VENOM reproduction — are precisely the highest-priority items in hypervisor security work)

---

## Reporting and Documentation

For each finding, document:

1. **Test ID** — TC-HI-NNN
2. **Target** — hostname/IP, hypervisor version and build
3. **Finding** — pass / fail / partial
4. **Evidence** — command output (sanitized of credentials), screenshots, packet captures
5. **Impact** — business consequence (e.g., "ESXi host with CVE-2021-21974 unpatched and SLP reachable from guest VLAN is at high risk of ESXiArgs ransomware compromise")
6. **Remediation** — specific commands to apply
7. **Verification** — re-test steps to confirm remediation

Reference the MITRE ATT&CK technique in each finding (typically T1068 for escape CVEs, T1190 for management plane exposure, T1486 for ransomware impact, T1078 for credential abuse).

---

## References

- [VMware Security Advisories (VMSA)](https://www.vmware.com/security/advisories)
- [Xen Project Security Advisories (XSA)](https://xenbits.xen.org/xsa/)
- [QEMU Security Process](https://www.qemu.org/contribute/security-process/)
- [MSRC Security Updates](https://msrc.microsoft.com/update-guide/)
- [LibVMI Documentation](https://libvmi.com/)
- [DRAKVUF on GitHub](https://github.com/tklengyel/drakvuf)
- [MITRE ATT&CK T1068](https://attack.mitre.org/techniques/T1068/)
- [CISA ESXiArgs Advisory (AA23-061A)](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-061a)

---

**End of test-cases.md**
