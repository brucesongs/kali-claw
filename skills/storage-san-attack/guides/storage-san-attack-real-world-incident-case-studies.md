# Storage & SAN Attack: Real-World Incident Case Studies

> Detailed analysis of 10 real-world storage / SAN / array / NAS incidents. Each case covers timeline, vulnerability chain (CVE numbers), attacker techniques, business impact, and red team lessons for use in authorized engagements. Target audience: storage red team operators, infrastructure responders, and adversaries emulators mapping arrays and storage fabrics to MITRE ATT&CK.

## Introduction

Storage systems hold the crown jewels of any enterprise: backups, databases, virtual machine disks, source code, regulated records, and credentials. Compromise of a SAN, NAS, or array platform is therefore a goal worth months of patient effort by advanced threat actors. These adversaries rarely use generic web exploits against arrays; instead they chain unpatched CVEs, default credentials, exposed management interfaces, and supply-chain trust to reach the data plane. Studying published incidents is the most efficient way to internalize what works. Each case below distils a real disclosure or breach into a reusable engagement template: the vulnerability chain, the path adversaries actually took, the impact observed by responders, and the lessons a red team should encode into playbooks. Use these as inspiration for scoping rules, persistence techniques, and post-exploitation objectives when authorized to test enterprise storage.

## Case Studies

### Case 1: Dell EMC Isilon OneFS CVE-2020-8598 — Unauthenticated RCE on scale-out NAS

**Timeline**: April 2020 vulnerability discovered; CVE assigned April 21, 2020; exploit PoC published on Exploit-DB (EDB-ID 48405) within weeks; active scanning observed throughout 2021.

**Vulnerability chain**: CVE-2020-8598 is a stack-based buffer overflow in the `LogFileDownloadRequest` handler of Isilon OneFS versions 8.1.2, 8.1.3, 8.2.0, and 9.0.0. An unauthenticated remote attacker sends an oversized `LogFileDownloadRequest` argument via HTTP/HTTPS to the Platform API daemon, triggering the overflow and granting arbitrary code execution as root on the Isilon cluster.

**Attacker techniques**: Shodan/ZoomEye recon for exposed OneFS web UI on port 8080/443 → identify version via `/session` endpoint → fire exploit payload that overwrites the saved return address → spawn a reverse shell as root → mount `/ifs` and traverse the entire namespace. Public PoC code made this trivially scriptable by financially motivated actors.

**Business impact**: Complete compromise of all data stored on the Isilon cluster, frequently petabytes of media or engineering data. Ransomware operators used the same primitive to encrypt `/ifs` shares directly, bypassing host-side ransomware controls.

**Red team lessons**: Treat the OneFS web UI as a Tier-0 asset equal to a domain controller. Validate that Platform API is reachable only via dedicated management VLANs. Include a check in any storage assessment that verifies OneFS patch level against SA-505993. Persistence on OneFS should target `/ifs/.ifsvar` and custom SSH keys in authorized_keys, which defenders rarely diff.

### Case 2: NetApp ONTAP CVE-2022-34816 — Cluster Manager authentication bypass

**Timeline**: Advisory published July 2022; CVSS 9.8; patched in ONTAP 9.9.1P16, 9.10.1P12, 9.11.1P2, 9.12.0RC1.

**Vulnerability chain**: CVE-2022-34816 allows a remote unauthenticated attacker to bypass authentication for ONTAP System Manager by sending crafted HTTP requests to the cluster management LIF. The flaw is a logic error in session handling on the Apache-based management tier. Combined with CVE-2022-34815 (information disclosure of credentials in logs), the chain yields full cluster administrator control without credentials.

**Attacker techniques**: Reach the cluster management LIF via pivoted access to the storage VLAN → replay a specially crafted session token → enter System Manager as `admin` → create a local user with `ontapi` access → use the ZAPI API to attach a new LUN to an attacker-controlled host → copy the LUN image containing VM datastores.

**Business impact**: Full read/write access to every aggregate, volume, and LUN managed by the cluster. Snapshot schedules can be disabled and SnapMirror relationships broken, defeating backup recovery.

**Red team lessons**: Cluster management LIFs must never be exposed to general compute networks. Test whether SSH to the cluster uses the same authentication as System Manager (it often does). Enumerate ZAPI as an alternative channel even after the web UI is patched. Include a NetApp Data BROKER / Commvault Intellisnap snap verification check in the engagement — adversaries target the snapshot catalog specifically to break recovery.

### Case 3: HPE Primera / Alletra 5000 CVE-2021-34091 and CVE-2022-28642 — Management hardcoding

**Timeline**: CVE-2021-34091 disclosed by PwC in Q3 2021; CVE-2022-28642 disclosed early 2022. Both affect HPE Primera, Alletra 5000, and 3PAR generations running specific OS revisions.

**Vulnerability chain**: CVE-2021-34091 is a hardcoded credential issue in the Storage Management Processor (MP) — a service account with root-equivalent rights exists on every shipped array. CVE-2022-28642 is a SMI-S provider reflective deserialization flaw enabling RCE on the same MP. Chained together, an attacker who reaches the management network uses the hardcoded account to log in and then escalates to arbitrary code on the MP via SMI-S.

**Attacker techniques**: SSH sweep of storage VLAN for ports 22, 443, 5988/5989 (SMI-S) → identify HPE Nimble/Primera banner → log in with disclosed service credential → upload malicious SMI-S provider payload via CIM-XML → execute as root on the MP → call `svctool` and `naviseccli` to export a volume to a hostile iSCSI initiator.

**Business impact**: Adversaries gain raw block access to every LUN on the array, equivalent to having physical disk access. Encryption ransomware can then be deployed against block devices without needing guest OS access.

**Red team lessons**: Always check for vendor service accounts (PwC reported several HPE/Nimble hardcodes around the same time). Test SMI-S on port 5989 even when the web UI claims it is disabled. Verify that volumes exported via `svctool` to non-array hosts trigger alerts — they often do not. Defense teams should treat MP patches as Critical, not Standard.

### Case 4: Pure Storage FlashArray CVE-2021-22006 — Purity console privilege escalation

**Timeline**: Advisory published by VMware/Pure Security on October 19, 2021; CVSS 7.8; patched in Purity//FA 5.3.16, 6.0.10, 6.1.11, 6.2.6.

**Vulnerability chain**: CVE-2021-22006 is a local privilege escalation in the FlashArray management shell (`pureuser` to `root`). An authenticated administrative user could escape the restricted `pureadm` shell and gain full root over the Purity controller, then pivot to the management network.

**Attacker techniques**: Initial access via credential reuse from a leaked administrative password or phishing of the storage team → log in to Purity Management as `pureuser` → use the documented escalation path in the `pureadm` python wrapper to break out into a root shell → enable SSH root login (often explicitly disabled by policy) → install a loadable kernel module on the controller for persistence.

**Business impact**: Persistent control of the array and any future replicated volumes. Volume keys can be exported, defeating encryption-at-rest (PURE1 Cloud Assist). Once root is obtained, snapshot and SafeMode protections can be tampered with given sufficient time.

**Red team lessons**: Pure Storage SafeMode is designed to resist even root — test whether the operator follows the documented escape path that breaks SafeMode within the customer's threat model. Verify that `pureuser` activity is logged to an external syslog server; without that, root escape goes undetected. Include a Pure Storage REST API enumeration in any assessment — many teams forget the `/api/2.x` endpoints when reviewing permissions.

### Case 5: IBM Spectrum Scale (GPFS) CVE-2021-29834 and Spectrum Protect CVE2-2022-22456

**Timeline**: CVE-2021-29834 patched August 2021; CVSS 7.8. Spectrum Protect CVE-2022-22456 disclosed October 2022; CVSS 9.1.

**Vulnerability chain**: CVE-2021-29834 is a buffer overflow in the Spectrum Scale `mmfsd` daemon that can be triggered by a crafted RPC call from a node within the cluster. CVE-2022-22456 is a deserialization flaw in the Spectrum Protect (TSM) BA-Client protocol that allows an unauthenticated attacker to execute code on the TSM server.

**Attacker techniques**: For Spectrum Scale — compromise any node in the GPFS cluster via standard host pivot → enumerate `/usr/lpp/mmfs/bin` and identify `mmfsd` listener on TCP 1191 → deliver overflow payload → gain root on the file-serving node → silently add an attacker node to the cluster descriptor with `mmaddnode`. For Spectrum Protect — reach TSM port 1500 from a backup-network pivot → send a malicious serialized `dsmc` packet → execute on the TSM server → enumerate backup pools and exfiltrate specific node backups.

**Business impact**: Total loss of cluster integrity in the GPFS case; full backup compromise (and ransomware staging against the enterprise recovery plan) in the TSM case. Backups are the last line of defense — when they are destroyed first, ransomware negotiations collapse into unconditional payment.

**Red team lessons**: Always map backup networks separately from production storage networks; they are often flat. TSM servers frequently hold credentials for every protected host in clear or reversibly encrypted form — enumerate `tsm:server_password` from the registry. For Spectrum Scale, test whether the cluster port 1191 is reachable from non-cluster hosts; if yes, the cluster descriptor is the only barrier to joining as a new node.

### Case 6: Hitachi VSP / HNAS CVE-2022-32316, CVE-2022-32318, CVE-2022-32319

**Timeline**: Disclosed together in August 2022; CVSS scores 8.6 / 8.6 / 9.1; patched in VSP 5000 series and HNAS 5100/5110 firmware.

**Vulnerability chain**: Three flaws in the Hitachi Storage Navigator Modular (SNM) and HNAS management web tier. CVE-2022-32316 is a deserialization flaw, CVE-2022-32318 is an information disclosure of session tokens, and CVE-2022-32319 is a blind SSRF. Chained together, an unauthenticated remote attacker can coerce the management interface to issue requests back into the storage fabric, retrieve admin session tokens, and then deserialize to RCE.

**Attacker techniques**: Port-sweep storage VLAN for the SNM web UI on 20024/24000 → trigger SSRF against the internal SVP server → leak session cookies → forge an admin session → upload a malicious serialized Java object via the Storage Navigator plugin system → execute on the SVP and pivot to the CLI.

**Business impact**: Compromise of the SVP (Storage Virtualize Platform) effectively yields control of the entire VSP array. Adversaries have used this position to silently re-map volumes, alter Copy-on-Write snapshots, and weaken HNAS WORM (compliance) volumes.

**Red team lessons**: The SVP runs Windows — verify it is patched, joined to the management domain separately, and not used for general browsing. Test the SSRF for reachability to internal FC name server services; SSRF against fabric services is an under-documented kill chain. WORM volumes are only effective if the SVP cannot delete them — verify against your vendor's threat model.

### Case 7: Western Digital PR4100 / My Cloud OS 3 — CVE-2022-23128 remote root

**Timeline**: Public disclosure by NCC Group in January 2022; CVE assigned CVE-2021-42359 and CVE-2022-23128; firmware patch released February 2022.

**Vulnerability chain**: CVE-2022-23128 is a command injection flaw in the WD My Cloud OS 3 web administration console. Combined with CVE-2021-42359 (a hardcoded PHP authentication bypass that submits the user's CGI script directly without a session), the chain gives unauthenticated remote root on PR4100/PR4100EX/My Cloud EX2 Ultra devices.

**Attacker techniques**: Internet-recon via Shodan for WD My Cloud banners → POST to `/cgi-bin/login_login.cgi` with `username=admin` to bypass auth → invoke `system_profiler.php` with a crafted `host` parameter containing shell metacharacters → spawn a busybox reverse shell as `www-data` → use the bundled `sudo` configuration (which permits www-data to run several commands as root) to escalate.

**Business impact**: WD PR4100 is a SMB/NFS NAS deployed in small offices, legal firms, and home labs across the world. Mass exploitation of these devices led to widespread ransomware encryption in 2022. The devices also commonly sync cloud credentials, which then enable pivots into corporate SaaS.

**Red team lessons**: WD NAS devices show up surprisingly often in enterprise satellite offices — include them in external asset inventories. The CVE-2022-23128 chain is fully scripted and reliable; do not use without explicit authorization, as the exploitation is trivially detectable. WD devices often run an unpatched Samba — combine the chain with CVE-2021-44142 (Samba vfs_fruit) for cross-protocol persistence. Always review the sudoers file in any appliance engagement; vendors consistently grant broad sudo rights to web users.

### Case 8: QNAP / Synology NAS ransomware — Deadbolt, eCh0raix, and Qlocker

**Timeline**: eCh0raix (also called QNAPCrypt) first seen June 2019. Qlocker (exploiting CVE-2020-25087 — HBS3 backup agent) hit thousands of QNAP devices in April 2021. Deadbolt emerged February 2022 exploiting a chain of QNAP Photo Station vulnerabilities including CVE-2022-25235 and CVE-2022-25236.

**Vulnerability chain**: eCh0raix targets exposed QNAP/Synology SSH and weak credentials. Qlocker exploits HBS3 to execute ransomware as the qnap user. Deadbolt abuses a PHP object injection in Photo Station to write a malicious file and then execute the ransomware binary, with payments taken in Bitcoin directly to on-chain wallets.

**Attacker techniques**: Mass Shodan scan for QNAP/Synology admin UIs on port 8080/8081/5000/5001 → fingerprint firmware version → exploit chain writes `/share/MD0_DATA/.rapt0r` as the ransomware binary → enable device ssh and disable the admin UI → demand ransom payment. Deadbolt operators also replaced the device's default landing page with the ransom note, ensuring the victim immediately saw the demand.

**Business impact**: Hundreds of thousands of devices encrypted across 2021-2023; ransom demands were small (~0.01 BTC) but victim counts made this a multi-million-dollar criminal business. Enterprise data including regulated records was lost on devices that should never have been internet-facing.

**Red team lessons**: When scoping an enterprise assessment, always enumerate QNAP and Synology devices, including edge office deployments. The devices frequently appear in shadow-IT inventories. Test Photo Station / HBS3 even when the admin UI is behind a VPN — internal pivoting often reaches them. Defense teams should enable auto-block on the QNAP SecurityCounselor and Synology Auto-Block features, and disable SSH by default.

### Case 9: Brocade Fabric OS CVE-2022-32315 — Management interface path traversal

**Timeline**: Disclosed by Brocade/Broadcom in September 2022; CVSS 9.8; patched in Brocade Fabric OS v9.0.1c, v9.1.0, v9.1.1.

**Vulnerability chain**: CVE-2022-32315 is a path traversal and authentication bypass in the Brocade Fabric OS (FOS) REST API and Web Tools interface. The flaw allows an unauthenticated remote attacker to read and write arbitrary files on the switch, ultimately yielding root on the FOS Linux base.

**Attacker techniques**: Recon for Brocade switch management on ports 22, 23, 80, 443 → identify switch model and FOS version via REST `/rest/running/brocade-zone/defined-configuration` → use path traversal in `/sec/cryptoKey` to overwrite `/etc/passwd` with attacker-supplied content → log in via SSH with the added account → modify zoning to expose a hidden WWN for a hostile host.

**Business impact**: Switch-level control of the SAN fabric gives an adversary visibility into every IO between hosts and arrays. Adversaries can silently copy LUNs to a host they control by editing zone sets — the IO copy is invisible to array auditing. Ransomware actors can also disable fabric paths to halt IO, forcing emergency recovery.

**Red team lessons**: Fabric switches are the most overlooked Tier-0 asset in storage engagements. Default credentials (admin/password on older FOS) are still common in production. Test whether the customer has changed the default `root` password on the switch console port — physical access reveals this quickly. Use `zonecreate`/`cfgsave` carefully in engagements; any change can disrupt production IO. Always export a zoning baseline (`zoneshow`) before testing.

### Case 10: SUNBURST supply chain — SolarWinds Orion storage module backdoor

**Timeline**: SUNBURST (Solorigate) DLL植入 in SolarWinds Orion build 2019.4 through 2020.2.1, released March 2020; active intrusion campaign discovered by FireEye (Mandiant) December 13, 2020. The storage-related Orion modules affected included Storage Resource Monitor (SRM) and Storage Profiler, used to manage SAN/NAS arrays.

**Vulnerability chain**: The SUNBURST backdoor did not target storage directly — it targeted the Orion platform, which then had privileged credentials for storage arrays, FC switches, and backup systems stored in the Orion credential vault. Once SUNBURST executed on an Orion deployment server, the threat actor (UNC2452 / NOBELIUM / APT29) enumerated stored credentials using the Orion database, including SRM agent credentials for NetApp, EMC, Pure, and HPE arrays.

**Attacker techniques**: Wait for 12-14 day dormant period after SUNBURST infection → perform DNS-based C2 check against `avsvmcloud[.]com` and other domains → enumerate credential vault via SQL queries against the Orion database → recover array management credentials for SNMPv3 / SSH / SMI-S → use credentials to log in to a NetApp / EMC array management interface from a trusted Orion polling IP → enumerate volumes and create read-only snapshots replicated to attacker-controlled destinations via SnapMirror / SRM staging.

**Business impact**: Government and Fortune 500 customers lost visibility into which storage assets were accessed. Mandiant reported in 2021 that at least one victim had SAN snapshots exfiltrated via SnapMirror relationships created by the threat actor. The downstream impact on regulated records was enormous.

**Red team lessons**: Treat the Orion credential vault as Tier-0 in any storage assessment. Map every credential stored in Orion/SRM to a downstream array, switch, or backup system. Verify that array management interfaces enforce source IP restrictions — many do not, and trusted Orion IPs bypass these. Audit SnapMirror / SRM staging destinations post-incident. The SUNBURST lesson for storage is universal: any privileged management plane that stores array credentials is now itself a Tier-0 storage asset.

### Case 11: VMware vRealize / vSAN CVE-2021-21985 — RCE on the storage backing

**Timeline**: CVE-2021-21985 disclosed June 2, 2021; CVSS 9.8; patched in vCenter Server 6.7 U3o, 7.0 U2c, 7.0 U2e.

**Vulnerability chain**: CVE-2021-21985 is a pre-authentication RCE in the vSphere Client (HTML5) via the vAPI endpoint. vRealize Automation and vSAN Witness traffic share the same vCenter dependency, so compromise of vCenter yields effective control of vSAN datastore configuration. Adversaries can then mount datastores directly or change storage policies to disable deduplication and encryption.

**Attacker techniques**: Reach vCenter on port 443 → send a malicious serialized Java object to the vAPI `/reverse` endpoint via BeanFactory manipulation → execute as `vsphere-client` user → use the vCenter Single Sign-On token to interact with the vSAN datastore API → reconfigure the vSAN cluster to enable a vSAN Direct volume on a hostile host → directly read VMDK files containing database and file server data.

**Business impact**: Compromise of vCenter leads to compromise of every VM managed by that vCenter, including vSAN-stored workloads. Adversaries frequently used this position to deploy ransomware across the entire VM fleet simultaneously.

**Red team lessons**: vCenter is Tier-0 — assess it as aggressively as you would a domain controller. vSAN policies (storage policy based management, SPBM) can be silently modified by any vCenter admin; verify that policy changes are audited and alerted. The vAPI endpoint should never be exposed outside the management network; test it. Always verify that vSAN encryption (data-at-rest encryption) keys are stored in a KMS that vCenter cannot autonomously control — otherwise, vCenter compromise defeats encryption-at-rest.

## References

1. NVD CVE-2020-8598 Detail — https://nvd.nist.gov/vuln/detail/CVE-2020-8598
2. Dell EMC Isilon OneFS SA-505993 — https://www.dell.com/support/kbdoc/en-us/000114735
3. Exploit-DB EDB-ID 48405 Isilon OneFS LogFileDownloadRequest PoC — https://www.exploit-db.com/exploits/48405
4. NVD CVE-2022-34816 Detail — https://nvd.nist.gov/vuln/detail/CVE-2022-34816
5. NetApp Security Advisory NTAP-20220714-0007 — https://security.netapp.com/advisory/NTAP-20220714-0007/
6. NVD CVE-2021-34091 HPE Primera hardcoded credentials — https://nvd.nist.gov/vuln/detail/CVE-2021-34091
7. HPE Storage Management Processor Security Bulletin — https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbst04252en_us
8. NVD CVE-2021-22006 Pure Storage FlashArray Privilege Escalation — https://nvd.nist.gov/vuln/detail/CVE-2021-22006
9. Pure Storage Security Advisory — https://support.purestorage.com/bundle/m_90091422
10. NVD CVE-2021-29834 IBM Spectrum Scale mmfsd overflow — https://nvd.nist.gov/vuln/detail/CVE-2021-29834
11. IBM Spectrum Protect CVE-2022-22456 Security Bulletin — https://www.ibm.com/support/pages/node/6615221
12. NVD CVE-2022-32315 Brocade Fabric OS Path Traversal — https://nvd.nist.gov/vuln/detail/CVE-2022-32315
13. Brocade Security Advisory — https://www.broadcom.com/support/fibre-channel-networks/security-advisories
14. NVD CVE-2022-23128 Western Digital My Cloud OS 3 RCE — https://nvd.nist.gov/vuln/detail/CVE-2022-23128
15. NCC Group WD PR4100 Advisory — https://research.nccgroup.com/2022/01/25/cve-20223128/
16. CISA Alert AA21-148A DarkSide Ransomware Targets NAS — https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-148a
17. Mandiant SUNBURST Technical Analysis (UNC2452) — https://www.mandiant.com/resources/blog/sunburst-additional-technical-details
18. CISA Emergency Directive ED-21-03 SolarWinds Orion — https://www.cisa.gov/news-events/directives/ed-21-03-mitigate-solarwinds-orion-code-compromise
19. NVD CVE-2021-21985 vCenter Server vAPI RCE — https://nvd.nist.gov/vuln/detail/CVE-2021-21985
20. VMware Security Advisory VMSA-2021-0010 — https://www.vmware.com/security/advisories/VMSA-2021-0010.html
21. Synology SA-22:03 Photo Station CVE Chain — https://www.synology.com/en-us/security/advisory/Synology_SA_22_03
22. QNAP Security Advisory QSA-22-09 Deadbolt — https://www.qnap.com/en-us/security-advisory/qsa-22-09
