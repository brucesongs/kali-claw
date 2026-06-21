# Post-Quantum Cryptography Implementation Hardening & Side-Channel Lab

> Deep-dive companion to `skills/quantum-crypto-attack/SKILL.md`, `guides/quantum-crypto-attack-playbook.md`, and `guides/pqc-migration-assessment-playbook.md`.
>
> Audience: **engineers** who have already done the inventory (guide 1) and the migration roadmap (guide 2) and now have to *actually deploy, harden, and operate* a hybrid-TLS + PQC-signature stack in production. This is the operator's manual that fills in the gap between "we picked ML-KEM-768" and "the production servers serve hybrid TLS, side-channel-hardened, with telemetry that will tell us the day something drifts."
>
> Scope: OpenSSL 3.x `oqs-provider` configuration, hybrid TLS group negotiation (`x25519_mlkem768`, `secpar256r1_mlkem768`, `p256_mldsa65`), hybrid signature chains, deterministic-vs-randomized signing, constant-timeness verification with `dudect`, fault-injection labs (loop-abort, skip, RNG subversion), lattice side-channel TVLA capture with ChipWhisperer/NAEKS, performance/cost budgeting, and four hands-on CTF-style scenarios with worked solutions.

---

## 1. Introduction and Objective

Post-quantum migration has two halves. The first half is **deciding** what to deploy — that is covered by the migration playbook (`guides/pqc-migration-assessment-playbook.md`): regulatory alignment, SNDL modelling, algorithm selection. The second half is **operating** the deployment once it exists. That second half is what this guide covers, because the failure mode of PQC in production is not "the lattice was solved" — it is "the implementation was non-constant-time" or "the TLS stack silently downgraded to classical because a config typo broke the negotiation" or "the cert chain had a hybrid signature on the leaf but a classical-only signature on the intermediate, creating a downgrade target."

The objective of this guide is operational correctness:

- Configure OpenSSL 3.x with `oqs-provider` so that a server actually negotiates the hybrid groups you intend.
- Verify, with traffic capture and offline analysis, that the negotiated handshake is the hybrid one and not a silent fallback.
- Audit the production stack for constant-timeness and fault-injection resistance — not as a research exercise, but with the exact tools (`dudect`, `dudle`, ChipWhisperer, `ctgrind`, `valgrind-mmt`) and the exact verdict thresholds used in academic literature.
- Run four CTF-style lab scenarios end-to-end so that when the same bug shows up in production, the engineer has already fixed it once.
- Produce operational artifacts (telemetry spec, runbook, SLO dashboard) so that the deployment survives the next OpenSSL CVE, the next provider update, and the next TLS 1.3 group deprecation.

This guide assumes the reader is fluent in TLS 1.3, OpenSSL CLI, and C. It does **not** re-explain the migration rationale.

### How this guide differs from the two existing guides

| Aspect | `quantum-crypto-attack-playbook.md` | `pqc-migration-assessment-playbook.md` | **This guide** |
|--------|-------------------------------------|----------------------------------------|----------------|
| Audience | Assessment operator / pentester | CISO / PKI architect / regulator | **Production engineer / SRE / crypto maintainer** |
| Output | Assessment report | Migration roadmap | **Hardened deployment + telemetry** |
| Focus | What is wrong today | What to change by when | **How to operate it correctly day-to-day** |
| Side-channel depth | Conceptual | None | **Hands-on: dudect, ChipWhisperer, TVLA** |
| Fault injection | Not covered | Not covered | **Loop-abort, skip, RNG-subversion labs** |
| OpenSSL 3.x config | Survey-level | Selection-level | **Provider config, group pinning, downgrade detection** |

---

## 2. Hands-on Practice: Lab Topology

The lab is a single Linux host (Kali 2025.2 ARM64 or any recent Debian/Ubuntu). It runs OpenSSL 3.x as both client and server, with `oqs-provider` loaded, against a self-signed hybrid-PQC PKI. All commands below assume the working directory `/tmp/pqc-lab/` and `$REPLACE_WITH_YOUR_DOMAIN=lab.local`.

### 2.1 Topology diagram

```
                  ┌──────────────────────────────────────────┐
                  │              pqc-lab host                │
                  │                                          │
   (loopback)  ───┤  openssl s_server   <--->  openssl s_client
                  │       |                       |          │
                  │  oqs-provider          oqs-provider      │
                  │       |                       |          │
                  │  hybrid PKI            hybrid PKI       │
                  │  (root: P-256+ML-DSA)  (leaf: ditto)    │
                  │                                          │
                  │  side-channel harness: dudect, ctgrind   │
                  │  ChipWhisperer-Nano  (USB, optional)     │
                  └──────────────────────────────────────────┘
```

### 2.2 Provisioning script

```bash
#!/usr/bin/env bash
# provision_pqc_lab.sh — idempotent setup for the PQC implementation lab.
# Run as a non-root user; uses sudo where needed. Tested on Kali 2025.2 ARM64.

set -euo pipefail
LAB_DIR="${PQC_LAB_DIR:-/tmp/pqc-lab}"
mkdir -p "$LAB_DIR" && cd "$LAB_DIR"

# 1. Build dependencies
sudo apt-get update -qq
sudo apt-get install -y --no-install-recommends \
    build-essential cmake ninja-build git autoconf libtool pkg-config \
    python3 python3-pip python3-venv \
    libssl-dev openssl valgrind

# 2. Build liboqs (the canonical PQC primitive library, used by oqs-provider)
if [ ! -d liboqs ]; then
    git clone --depth=1 https://github.com/open-quantum-safe/liboqs.git
fi
cmake -S liboqs -B liboqs/build -GNinja \
    -DCMAKE_INSTALL_PREFIX="$LAB_DIR/opt/liboqs" \
    -DOQS_USE_OPENSSL=ON \
    -DBUILD_SHARED_LIBS=ON
cmake --build liboqs/build --parallel "$(nproc)"
cmake --install liboqs/build

# 3. Build oqs-provider (OpenSSL 3.x provider that exposes PQC algorithms)
if [ ! -d oqs-provider ]; then
    git clone --depth=1 https://github.com/open-quantum-safe/oqs-provider.git
fi
cmake -S oqs-provider -B oqs-provider/build -GNinja \
    -DCMAKE_INSTALL_PREFIX="$LAB_DIR/opt/oqs-provider" \
    -Dliboqs_DIR="$LAB_DIR/opt/liboqs/lib/cmake/liboqs" \
    -DOPENSSL_ROOT_DIR=/usr
cmake --build oqs-provider/build --parallel "$(nproc)"
cmake --install oqs-provider/build

# 4. Register the provider with OpenSSL
OPENSSL_CONF="$LAB_DIR/openssl-pqc.cnf"
cat > "$OPENSSL_CONF" <<'EOF'
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect
ssl_conf = ssl_sect

[provider_sect]
default = default_sect
oqsprovider = oqsprovider_sect

[default_sect]
activate = 1

[oqsprovider_sect]
activate = 1
module = REPLACE_WITH_YOUR_OQS_PROVIDER_MODULE_PATH

[ssl_sect]
system_default = tls_system_default

[tls_system_default]
Groups = x25519_mlkem768:X25519:secp256r1_mlkem768:secp384r1_mlkem1024
SignatureAlgorithms = p256_mldsa65:ed25519:rsa_pss_pss_sha256:ecdsa_secp256r1_sha256
EOF

# Patch the module path (the install step places the .so under modules/)
MODULE_PATH="$(find "$LAB_DIR/opt/oqs-provider" -name 'oqsprovider.so' | head -1)"
sed -i "s|REPLACE_WITH_YOUR_OQS_PROVIDER_MODULE_PATH|${MODULE_PATH}|" "$OPENSSL_CONF"

export OPENSSL_CONF
echo "Lab ready at: $LAB_DIR"
echo "Verify with:  openssl list -providers -verbose"
openssl list -providers -verbose | head -20
```

Run `bash provision_pqc_lab.sh` once. The expected final output lists `oqsprovider` as active alongside `default`. If the provider fails to load, the most common cause is an OpenSSL version mismatch — OpenSSL 3.0+ is required, OpenSSL 3.2+ is recommended.

### 2.3 Sanity check — list PQC algorithms

```bash
export OPENSSL_CONF=/tmp/pqc-lab/openssl-pqc.cnf

# KEM algorithms (key encapsulation)
openssl list -kem-algorithms | grep -iE 'mlkem|kyber|frodokem|hqc'

# Signature algorithms
openssl list -signature-algorithms | grep -iE 'mldsa|slhdsa|falcon|sphincs'

# TLS 1.3 groups available for key exchange (look for the *_mlkem* hybrids)
openssl list -tls1_3 -groups

# Expected hybrid groups (OpenSSL 3.2 + oqs-provider 0.6+):
#   x25519_mlkem768
#   secp256r1_mlkem768
#   secp384r1_mlkem1024
#   x25519_kyber768     (legacy alias, deprecated)
#   x25519_kyber512
```

If the hybrid groups do not appear, the provider was loaded but the TLS glue was not. Re-run `cmake --build oqs-provider/build` and verify the module path printed by the provisioning script.

---

## 3. Hybrid PKI Generation

A correctly-deployed hybrid-PQC TLS stack requires a PKI that is itself hybrid. The classic mistake is to issue a classical (RSA/ECDSA) leaf cert on top of a classical intermediate, and then expect the TLS handshake to be post-quantum. The handshake will negotiate ML-KEM for key exchange, but the certificate signature is the long-term forgeable asset — and SNDL attackers record the cert chain today precisely because of this.

### 3.1 Hybrid root and leaf

```bash
cd /tmp/pqc-lab
export OPENSSL_CONF=/tmp/pqc-lab/openssl-pqc.cnf
REPLACE_WITH_YOUR_DOMAIN="lab.local"

# 1. Hybrid root CA: P-256 self-signed for stability, ML-DSA-65 for PQ-forward safety.
#    The "hybrid" here is achieved by issuing the root with BOTH signature algorithms
#    (cross-signed), so that a verifier that does not understand ML-DSA still accepts.
openssl genpkey -algorithm ec -pkeyopt ec_paramgen_curve:P-256 -out root-ec-key.pem
openssl genpkey -algorithm mldsa65 -provider oqsprovider -out root-mldsa-key.pem

openssl req -x509 -new -key root-ec-key.pem \
    -subj "/CN=PQC Lab Hybrid Root (EC leg)" \
    -days 3650 -sha256 -out root-ec-cert.pem

openssl req -x509 -new -key root-mldsa-key.pem \
    -subj "/CN=PQC Lab Hybrid Root (ML-DSA leg)" \
    -days 3650 -provider oqsprovider -out root-mldsa-cert.pem

# 2. Leaf cert signed by BOTH roots (verifier picks whichever it understands)
openssl genpkey -algorithm ec -pkeyopt ec_paramgen_curve:P-256 -out leaf-ec-key.pem
openssl req -new -key leaf-ec-key.pem \
    -subj "/CN=${REPLACE_WITH_YOUR_DOMAIN}" -out leaf-ec-csr.pem

openssl x509 -req -in leaf-ec-csr.pem -CA root-ec-cert.pem -CAkey root-ec-key.pem \
    -CAcreateserial -days 825 -sha256 -out leaf-ec-cert.pem

# For the ML-DSA leg we sign the same CSR with the ML-DSA root:
openssl x509 -req -in leaf-ec-csr.pem \
    -CA root-mldsa-cert.pem -CAkey root-mldsa-key.pem \
    -CAcreateserial -days 825 -provider oqsprovider \
    -out leaf-mldsa-cert.pem

# 3. Concatenate into a hybrid chain the server will present
cat leaf-ec-cert.pem leaf-mldsa-cert.pem root-ec-cert.pem root-mldsa-cert.pem \
    > leaf-hybrid-fullchain.pem
cat leaf-ec-key.pem > leaf-hybrid-key.pem   # servers want key+cert separate
ls -la leaf-hybrid-*.pem
```

The fullchain file presents both signature legs. Modern OpenSSL 3.2+ clients will validate via whichever leg matches their provider configuration; older clients fall back to the EC leg and the deployment remains non-broken during migration.

### 3.2 Verify the hybrid chain locally

```bash
# Validate the EC leg
openssl verify -CAfile root-ec-cert.pem leaf-ec-cert.pem
# Expected: leaf-ec-cert.pem: OK

# Validate the ML-DSA leg (provider must be loaded)
openssl verify -CAfile root-mldsa-cert.pem \
    -provider oqsprovider -provider default leaf-mldsa-cert.pem
# Expected: leaf-mldsa-cert.pem: OK

# Inspect the ML-DSA signature OID on the root
openssl x509 -in root-mldsa-cert.pem -noout -text \
    -provider oqsprovider | grep -A1 "Signature Algorithm"
# Expected: Signature Algorithm: mldsa65
```

If the `openssl verify` for the ML-DSA leg fails with "unable to get local issuer certificate," the most likely cause is that `oqsprovider` is not active in the verify subcommand. The `-provider default` flag must also be passed because the verify path needs `default` for chain building and `oqsprovider` for the signature primitive.

---

## 4. Hybrid TLS Server and Client

With the hybrid PKI in hand, the lab is ready to bring up a hybrid TLS endpoint and verify end-to-end that the negotiated handshake is the hybrid one.

### 4.1 Bring up the server

```bash
# Terminal 1: server
cd /tmp/pqc-lab
export OPENSSL_CONF=/tmp/pqc-lab/openssl-pqc.cnf

openssl s_server \
    -accept 127.0.0.1:4433 \
    -cert leaf-hybrid-fullchain.pem \
    -key leaf-hybrid-key.pem \
    -www -tls1_3 \
    -groups x25519_mlkem768 \
    -sigalgs p256_mldsa65
```

The `-groups` flag pins the server's preferred key-exchange group; `-sigalgs` pins the preferred signature algorithm. Both must be set explicitly — relying on defaults means relying on the provider's compile-time choice, which can change with the next `liboqs` update.

### 4.2 Connect the client and capture the negotiated group

```bash
# Terminal 2: client
cd /tmp/pqc-lab
export OPENSSL_CONF=/tmp/pqc-lab/openssl-pqc.cnf

# Force the client to accept ONLY the hybrid group (no fallback)
openssl s_client -connect 127.0.0.1:4433 -tls1_3 \
    -groups x25519_mlkem768 \
    -sigalgs p256_mldsa65 \
    -CAfile root-ec-cert.pem \
    -brief </dev/null

# Expected s_client output includes:
#   Peer signature type: p256_mldsa65
#   Shared groups returned: x25519_mlkem768
#   Protocol: TLSv1.3
#   Cipher: TLS_AES_256_GCM_SHA384
```

If the `Shared groups returned:` line shows `X25519` alone, the negotiation silently fell back to classical. This is the most common production failure and is covered in detail in scenario 7.1 below.

### 4.3 Capture and decode the handshake

```bash
# Terminal 3: packet capture
sudo tcpdump -i lo -w pqc-handshake.pcap 'tcp port 4433' &
TCPDUMP_PID=$!

# Trigger one handshake
openssl s_client -connect 127.0.0.1:4433 -tls1_3 \
    -groups x25519_mlkem768 </dev/null >/dev/null 2>&1

sudo kill $TCPDUMP_PID
wait $TCPDUMP_PID 2>/dev/null

# Decode the ServerHello (frame 3 in a typical capture) and locate the
# "key_share" extension — for x25519_mlkem768 it is 1216 bytes long
# (1184 bytes ML-KEM-768 + 32 bytes X25519), which is unambiguous in the hex dump.
tshark -r pqc-handshake.pcap -Y "tls.handshake.type == 2" \
    -T fields -e tls.handshake.extensions.key_share

# Also dump the supported_groups extension from ClientHello to verify the client
# actually advertised the hybrid group:
tshark -r pqc-handshake.pcap -Y "tls.handshake.type == 1" \
    -T fields -e tls.handshake.extensions_supported_group
```

The `tshark` queries are the authoritative check. The `Shared groups returned:` line from `openssl s_client` is a display-only summary; the wire-level capture is what an external auditor will ask to see.

---

## 5. Constant-Timeness Lab

A constant-time implementation is one whose execution time and memory-access pattern do not depend on secret values. Lattice cryptosystems (ML-KEM, ML-DSA) and hash-based signatures (SLH-DSA) involve operations that are mathematically uniform but implementation-fragile: rejection sampling, conditional moves in NTT butterfly, and modular reduction all leak if written naively.

The lab below uses **dudect** (Reparaz et al., 2017) — the de-facto academic tool for constant-timeness verification. The verdict threshold `|t| > 4.5` is the standard TVLA (Test Vector Leakage Assessment) rule used in side-channel literature.

### 5.1 Install dudect

```bash
cd /tmp/pqc-lab
git clone --depth=1 https://github.com/oreparaz/dudect.git
cd dudect
make
```

### 5.2 Build a fixture for ML-KEM-768 decapsulation

The `dudect` harness measures many executions of a target function on two classes of input (fixed vs random) and runs Welch's t-test on the timing distribution. The fixture below wraps the liboqs ML-KEM-768 decapsulation primitive.

```c
/* /tmp/pqc-lab/dudect/fixture-mlkem768.c
 * dudect fixture: measure ML-KEM-768 decapsulation timing.
 * Compile into dudect as src/fixture.c (replace the existing one).
 */
#include <oqs/oqs.h>
#include <string.h>
#include <stdlib.h>

static OQS_KEM *kem = NULL;
static uint8_t *ct_fixed = NULL;
static uint8_t *ss       = NULL;
static uint8_t *sk       = NULL;
static uint8_t *ct_random = NULL;

int8_t do_one_computation(uint8_t *data, size_t len) {
    (void)len;
    /* `data` alternates between fixed and random per dudect's protocol */
    OQS_KEM_decaps(kem, ss, data, sk);
    return (int8_t)ss[0];   /* prevent dead-code elimination */
}

void prepare_inputs(dudect_config_t *c, uint8_t *input_data, uint8_t *classes) {
    for (size_t i = 0; i < c->number_measurements; i++) {
        classes[i] = randombit();
        if (classes[i] == 0) {
            memcpy(input_data + i * c->chunk_size, ct_fixed, c->chunk_size);
        } else {
            memcpy(input_data + i * c->chunk_size, ct_random, c->chunk_size);
        }
    }
}

int main(int argc, char **argv) {
    kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!kem) { fprintf(stderr, "ML-KEM-768 not available\n"); return 1; }

    sk       = malloc(kem->length_secret_key);
    ct_fixed = malloc(kem->length_ciphertext);
    ct_random= malloc(kem->length_ciphertext);
    ss       = malloc(kem->length_shared_secret);

    /* Keypair once; fixture measures decaps only. */
    uint8_t *pk = malloc(kem->length_public_key);
    OQS_KEM_keypair(kem, pk, sk);
    OQS_KEM_encaps(kem, ct_fixed, ss, pk);          /* fixed ciphertext */
    OQS_randombytes(ct_random, kem->length_ciphertext);  /* random ciphertext */

    dudect_config_t config = {
        .chunk_size = kem->length_ciphertext,
        .number_measurements = 20000,
    };
    dudect_main(&config);

    OQS_KEM_free(kem);
    free(sk); free(ct_fixed); free(ct_random); free(ss); free(pk);
    return 0;
}
```

Build and run:

```bash
cd /tmp/pqc-lab/dudect
# Patch Makefile to add liboqs include/link flags
sed -i 's|CFLAGS += -Iinclude|CFLAGS += -Iinclude -I/tmp/pqc-lab/opt/liboqs/include|' Makefile
sed -i 's|LDFLAGS +=|LDFLAGS += -L/tmp/pqc-lab/opt/liboqs/lib -loqs|' Makefile

cp src/fixture.c src/fixture.c.bak
cp /tmp/pqc-lab/dudect/fixture-mlkem768.c src/fixture.c

make clean && make

# Pin to an isolated core to reduce scheduler noise
sudo taskset -c 3 ./dudect | tee /tmp/dudect_mlkem768.log
```

Interpretation rules:

| Output line | Meaning | Action |
|-------------|---------|--------|
| `t < 4.5` for >100k measurements | No first-order leakage | Pass |
| `t > 4.5` occasionally, then settles | Measurement noise | Re-run on isolated core |
| `t > 4.5` consistently climbing | Real leakage | **CRITICAL** — file upstream bug, halt production rollout |
| `max t = NaN` | Captured too few samples | Increase `number_measurements` |

### 5.3 ctgrind as a fast second opinion

`ctgrind` is a Valgrind-based tool that flags secret-dependent branches and memory accesses without needing a statistical model. It is much faster than `dudect` but only catches *deterministic* leaks (not timing).

```bash
# Build liboqs with the ctgrind annotation macros enabled
cmake -S liboqs -B liboqs/build-ctgrind -GNinja \
    -DCMAKE_INSTALL_PREFIX=/tmp/pqc-lab/opt/liboqs-ctgrind \
    -DOQS_USE_OPENSSL=ON \
    -DCMAKE_C_FLAGS="-g -O0 -DCTGRIND_ENABLED"
cmake --build liboqs/build-ctgrind --parallel "$(nproc)"

# Run any binary that exercises ML-KEM decaps under Valgrind's memcheck
LD_LIBRARY_PATH=/tmp/pqc-lab/opt/liboqs-ctgrind/lib \
    valgrind --tool=memcheck --track-origins=yes \
    ./mlkem-decaps-test-binary 2>&1 | grep -E 'CTGRIND|uninitial'

# ctgrind emits warnings of the form:
#   "Conditional jump or move depends on uninitialised value(s)"
# Each such warning is a candidate secret-dependent branch. Triage one by one.
```

### 5.4 ChipWhisperer capture (lab-only, authorized hardware)

For the ChipWhisperer-Nano or Husky platform, the target is typically a Cortex-M4 (STM32F4) running liboqs. The harness below captures 10,000 power traces for first-order TVLA on the decapsulation primitive.

```python
#!/usr/bin/env python3
# cw_capture_mlkem.py — ChipWhisperer power trace capture for ML-KEM-768 decaps.
# Lab-only. Requires authorized ChipWhisperer hardware connected via USB.

import os
import chipwhisperer as cw

# 1. Connect scope and target
scope = cw.scope()
target = cw.target(scope, cw.targets.SimpleSerial)
scope.default_setup()
scope.adc.samples = 24000
scope.clock.adc_src = "clkgen_x4"
scope.clock.clkgen_freq = 100_000_000

# 2. Verify the target firmware exposes simpleserial command 'd' (decaps)
target.reset_output()
target.simpleserial_write('i', b'')
print("Target ID:", target.simpleserial_read('i', 32, ack=False))

# 3. Capture 10000 traces alternating fixed and random ciphertexts
project = cw.create_project("/tmp/pqc-lab/mlkem_traces.cwp", overwrite=True)
N = 10_000
for i in range(N):
    if i % 2 == 0:
        ct = b'\x00' * 1088            # fixed input (TVLA "fixed" class)
    else:
        ct = os.urandom(1088)          # random input (TVLA "random" class)
    target.simpleserial_write('d', ct)
    ret = cw.capture_trace(scope, target, ct, 'd')
    if ret is None:
        print(f"Capture {i} failed, retrying")
        continue
    project.traces.append(ret)
project.save()
print(f"Captured {len(project.traces)} traces to {project.path}")
```

```python
#!/usr/bin/env python3
# cw_tvla.py — First-order TVLA on the captured trace set.

import numpy as np
from scipy import stats

# Load traces (the .cwp format is loaded via chipwhisperer; here we use the
# exported numpy array for portability)
proj = np.load("/tmp/pqc-lab/mlkem_traces.npy")  # shape (N, samples)
fixed  = proj[0::2]
random = proj[1::2]

t, p = stats.ttest_ind(fixed, random, axis=0, equal_var=False)
leak_points = np.where(np.abs(t) > 4.5)[0]
print(f"TVLA: {len(leak_points)} sample points exceed |t|=4.5")
if len(leak_points) > 0:
    print(f"  First leakage at sample {leak_points[0]}, t={t[leak_points[0]]:.2f}")
    print("  Verdict: LEAKAGE — investigate the implementation at this offset")
else:
    print("  Verdict: no first-order leakage detected (constant-time OK)")
```

---

## 6. Fault-Injection Lab

Where side-channel attacks exploit *what the implementation leaks*, fault-injection attacks exploit *what the implementation does wrong under stress*. Lattice schemes have a well-documented family of fault attacks:

- **Loop-abort** (Bruinderink-Pürr-Pöppelmann 2017) — skipping a single iteration of the rejection-sampling loop in ML-KEM decryption leaks enough of the secret to recover the key.
- **Skipping** (Poddebniak et al. 2018) — skipping the final NTT butterfly yields a malformed ciphertext that decodes to a known function of the secret.
- **RNG subversion** — determinizing the random tape in ML-DSA signing enables transcript-compatibility attacks.

The lab reproduces these in software by patching liboqs to inject the faults deterministically.

### 6.1 Loop-abort PoC

```c
/* /tmp/pqc-lab/faults/loop_abort_inject.c
 * Build as a shared library preloaded into the liboqs decapsulation.
 * LD_PRELOAD=this.so forces the rejection-sampling loop to exit after iteration 0,
 * reproducing the Bruinderink et al. fault.
 */
#include <oqs/oqs.h>
#include <dlfcn.h>

/* Wrap OQS_KEM_decaps. After the first call, fault-inject by skipping
 * the final message-recovery step. */
OQS_API OQS_STATUS OQS_KEM_decaps(const OQS_KEM *kem,
                                  uint8_t *secret,
                                  const uint8_t *ciphertext,
                                  const uint8_t *secret_key) {
    static OQS_STATUS (*real_decaps)(const OQS_KEM*, uint8_t*, const uint8_t*, const uint8_t*) = NULL;
    if (!real_decaps) {
        real_decaps = dlsym(RTLD_NEXT, "OQS_KEM_decaps");
    }
    OQS_STATUS rc = real_decaps(kem, secret, ciphertext, secret_key);

    /* Inject: zero the high half of the shared secret.
     * In the real fault, the abort happens during message recovery and
     * yields a malformed shared secret; we approximate that here. */
    for (size_t i = 0; i < kem->length_shared_secret / 2; i++) {
        secret[i] = 0;
    }
    return rc;
}
```

```bash
# Compile and demonstrate that faulted decaps produces a detectable signature
gcc -shared -fPIC -o loop_abort_inject.so loop_abort_inject.c -ldl

# Run the legitimate decaps
./mlkem-decaps-test > /tmp/legit.txt

# Run the faulted decaps
LD_PRELOAD=./loop_abort_inject.so ./mlkem-decaps-test > /tmp/faulted.txt

# The faulted output is detectable: the shared secret's high half is zero.
# This is exactly what a fault-detection countermeasure (e.g., a redundancy
# check on the recovered message) is designed to catch.
diff <(xxd /tmp/legit.txt) <(xxd /tmp/faulted.txt) | head -20
```

### 6.2 Detection: redundancy check

The standard countermeasure for ML-KEM is **re-encryption**: after recovering the message `m` from the ciphertext, re-encrypt `m` and compare the result to the input ciphertext. If they differ, a fault occurred and the operation must fail closed.

```python
#!/usr/bin/env python3
# mlkem_re_encryption_check.py — Detect loop-abort / skipping faults via re-encryption.

def mlkem_decaps_hardened(kem, sk, ct):
    """Decapsulate with re-encryption countermeasure. Raises on fault."""
    m_prime = _mlkem_decaps_recover_message(kem, sk, ct)   # step 1: recover m
    ct_check = _mlkem_encrypt_with_message(kem, pk_of(sk), m_prime)  # step 2: re-encrypt
    if ct_check != ct:
        raise RuntimeError("ML-KEM fault detected (re-encryption mismatch)")
    return _mlkem_hash_shared_secret(m_prime, ct)           # step 3: derive K
```

The cost is one extra encryption per decryption. In TLS 1.3 this is negligible because decapsulation happens once per handshake.

---

## 7. CTF-Style Scenarios with Worked Solutions

The four scenarios below are the most common production failures seen in PQC rollouts during 2024-2026. Each is reproducible in the lab and ships with a worked solution so that the engineer has already debugged the failure mode before seeing it in production.

### 7.1 Scenario A — Silent Downgrade to Classical

**Setup**: Server is configured with `-groups x25519_mlkem768:X25519`, but the operator mis-specified `OPENSSL_CONF` so the `oqsprovider` never loads.

**Symptom**: `openssl s_client -brief` reports `Shared groups returned: X25519` instead of `x25519_mlkem768`.

**Reproduce**:

```bash
# Mis-configure: do NOT export OPENSSL_CONF (provider never loads)
unset OPENSSL_CONF
openssl s_server -accept 127.0.0.1:4434 -cert leaf-hybrid-fullchain.pem -key leaf-hybrid-key.pem -www -tls1_3 &
SERVER_PID=$!

# Client expects hybrid but falls back silently
OPENSSL_CONF=/tmp/pqc-lab/openssl-pqc.cnf \
    openssl s_client -connect 127.0.0.1:4434 -tls1_3 -groups x25519_mlkem768 -brief </dev/null \
    | grep "Shared groups"

kill $SERVER_PID
```

**Solution**: pin the group on the server, and add a startup-time assertion that the provider loaded:

```bash
#!/usr/bin/env bash
# assert_provider_loaded.sh — fail fast if oqsprovider is missing
openssl list -providers 2>/dev/null | grep -q '^  oqsprovider' || {
    echo "FATAL: oqsprovider not loaded. Refusing to start TLS server." >&2
    exit 2
}
```

Call this from the systemd unit `ExecStartPre=`. The server will refuse to start if the provider is missing, rather than silently serving classical TLS.

### 7.2 Scenario B — Non-Constant-Time NTT

**Setup**: A custom build of liboqs compiled with `-O3 -ffast-math` (which permits the compiler to reorder floating-point operations and break constant-timeness in Falcon, and to vectorize ML-KEM's NTT in a secret-dependent way).

**Reproduce**:

```bash
cmake -S liboqs -B liboqs/build-fast -GNinja \
    -DCMAKE_INSTALL_PREFIX=/tmp/pqc-lab/opt/liboqs-fast \
    -DOQS_USE_OPENSSL=ON \
    -DCMAKE_C_FLAGS="-O3 -ffast-math -march=native"
cmake --build liboqs/build-fast --parallel "$(nproc)"
cmake --install liboqs/build-fast

# Rebuild dudect against this liboqs and re-run
LD_LIBRARY_PATH=/tmp/pqc-lab/opt/liboqs-fast/lib \
    sudo taskset -c 3 ./dudect | tee /tmp/dudect_fast.log

# Compare against the constant-time build:
#   constant-time:  t < 4.5 throughout
#   -O3 -ffast-math: t climbs past 4.5 within ~50k measurements
```

**Solution**: never compile liboqs with `-ffast-math`. Pin the production build flags:

```cmake
# CMakeLists.txt (operator-controlled overlay)
set(CMAKE_C_FLAGS_RELEASE "-O2 -fno-fast-math -fomit-frame-pointer")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fcf-protection=full")
```

`-O2` is sufficient; `-O3` provides marginal speedup at the cost of correctness guarantees.

### 7.3 Scenario C — Deterministic ML-DSA Nonce Reuse

**Setup**: An HSM-backed ML-DSA signer that uses deterministic signing (per FIPS 204) and signs two different messages. Because the signing is deterministic, an attacker who controls the random tape can force a fault that produces two signatures on the same nonce, which leaks the secret key via the standard lattice-nonce-reuse attack (Howgrave-Graham-Silverman 1999 analogue).

**Reproduce**:

```python
#!/usr/bin/env python3
# mldsa_deterministic_fault.py — Reproduce the deterministic-signing fault
import subprocess, hashlib

def sign(privkey, msg, deterministic=True):
    args = ["openssl", "-provider", "oqsprovider", "pkeyutl", "-sign",
            "-inkey", privkey, "-rawin"]
    if not deterministic:
        # Provider-specific flag to force randomized mode.
        # Real liboqs uses OQS_RANDOM_FLAG_RANDZ=auto; here we mock.
        args += ["-rand", "/dev/urandom"]
    out = subprocess.run(args, input=msg, capture_output=True)
    return out.stdout

# Sign the same message twice in deterministic mode — signatures should match
msg1 = b"first message"
msg2 = b"second message"
s1 = sign("mldsa65-priv.pem", msg1)
s2 = sign("mldsa65-priv.pem", msg2)

# In randomized mode, two signatures on the same message differ.
# In deterministic mode, they match.
print(f"deterministic signatures match: {s1[:32].hex() == s2[:32].hex()}")
print("Recommendation: prefer randomized signing for code-signing use cases")
```

**Solution**: For code-signing and identity-binding signatures, force randomized mode (FIPS 204 allows both). For root-of-trust signatures where reproducibility is required, enforce transcript-level logging so any nonce reuse is detectable.

### 7.4 Scenario D — Hybrid Signature Chain Downgrade

**Setup**: A leaf cert is presented with both an EC and an ML-DSA signature, but the *intermediate* CA is signed only with EC. An active MITM strips the ML-DSA signature from the leaf; the client still validates against the EC chain and accepts.

**Reproduce**:

```bash
# Server presents the full hybrid chain (EC + ML-DSA leafs on EC root)
openssl s_server -accept 127.0.0.1:4435 \
    -cert leaf-hybrid-fullchain.pem -key leaf-hybrid-key.pem -www -tls1_3 &
SERVER_PID=$!

# MITM (mitmproxy) rewrites the chain to present only the EC leaf
mitmdump --mode reverse:https://127.0.0.1:4435 \
    --set ssl_insecure=true \
    --set tls_version_server_min=tls1_3 \
    -q &
MITM_PID=$!

# Client connects through the MITM and sees only the EC chain
openssl s_client -connect 127.0.0.1:8080 -tls1_3 \
    -CAfile root-ec-cert.pem -brief </dev/null

kill $SERVER_PID $MITM_PID 2>/dev/null || true
```

**Solution**: pin the expected signature algorithms on the client and fail closed if the ML-DSA leg is missing:

```bash
# Client pin: accept ONLY hybrid signatures
openssl s_client -connect 127.0.0.1:4435 -tls1_3 \
    -groups x25519_mlkem768 \
    -sigalgs p256_mldsa65:rsa_pss_pss_sha256 \
    -CAfile root-hybrid-chain.pem \
    </dev/null
```

With `-sigalgs p256_mldsa65` as the *only* acceptable signature, the client rejects any chain that does not include the ML-DSA leg.

---

## 8. Operational Telemetry and SLOs

A hybrid-PQC deployment is only as good as the telemetry that proves it is operating correctly. The metrics below are the minimum set that an SRE team should export.

### 8.1 Required Prometheus metrics

```
# Server-side
tls_handshakes_total{group="x25519_mlkem768", result="success"} 1024
tls_handshakes_total{group="x25519",         result="success"}    3   # CRITICAL if non-zero
tls_handshakes_total{group="x25519",         result="fallback"}  47   # client-initiated fallback

# Provider health
oqs_provider_loaded 1
oqs_provider_algorithm_available{algorithm="mlkem768"} 1
oqs_provider_algorithm_available{algorithm="mldsa65"}  1

# Side-channel monitoring (exported by the dudect daemon, see 8.2)
pqc_constant_time_tstat{primitive="mlkem768_decaps"} 2.1   # |t| < 4.5 → OK
pqc_constant_time_tstat{primitive="mldsa65_sign"}    1.4
```

### 8.2 Continuous constant-timeness daemon

In production, side-channel verification should not be a one-time lab exercise. The daemon below runs dudect-style measurements against the production liboqs continuously and exports the t-statistic.

```python
#!/usr/bin/env python3
# pqc_ct_daemon.py — Continuous constant-timeness monitor.
# Exposes Prometheus metrics on :9102. Alerts when |t| > 4.5 for any primitive.

import time, ctypes, statistics
from prometheus_client import start_http_server, Gauge

liboqs = ctypes.CDLL("liboqs.so")
t_stat = Gauge("pqc_constant_time_tstat", "Welch t-stat from dudect-style probe",
               ["primitive"])

def measure(primitive_name, liboqs_fn, n=20000):
    """Take n timing samples for fixed-input and n for random-input."""
    fixed_times, random_times = [], []
    for _ in range(n):
        t0 = time.perf_counter_ns()
        liboqs_fn(b"\x00" * 1088)
        fixed_times.append(time.perf_counter_ns() - t0)
    for _ in range(n):
        t0 = time.perf_counter_ns()
        liboqs_fn(b"\xff" * 1088)
        random_times.append(time.perf_counter_ns() - t0)
    return welch_t(fixed_times, random_times)

def welch_t(a, b):
    from scipy.stats import ttest_ind
    t, _ = ttest_ind(a, b, equal_var=False)
    return t

if __name__ == "__main__":
    start_http_server(9102)
    while True:
        for prim, fn in [("mlkem768_decaps", liboqs.OQS_KEM_ml_kem_768_decaps)]:
            t = measure(prim, fn, n=5000)
            t_stat.labels(primitive=prim).set(t)
            if abs(t) > 4.5:
                # Emit a critical log; Prometheus alerts on the gauge threshold.
                print(f"ALERT: {prim} t={t:.2f} exceeds 4.5")
        time.sleep(60)
```

### 8.3 SLO definition

The deployment should publish the following SLO, reviewed quarterly:

| SLO | Target | Window |
|-----|--------|--------|
| Hybrid-group handshakes | ≥ 99% of total | 30-day rolling |
| Classical-only fallbacks | ≤ 0.1% of total | 30-day rolling |
| Provider loaded | 100% of server uptime | Always |
| `|t|` on production primitives | < 4.5 for 100% of measurements | 7-day rolling |
| ML-DSA signing mode | Randomized (or determinism logged) | Always |

A breach of any SLO is a P2 incident. A classical-only fallback rate above 1% is a P1 because it indicates either a provider regression or an attacker actively downgrading the negotiation.

---

## 9. Crypto-Agility Runbook

The crypto-agility framework defined in `pqc-migration-assessment-playbook.md` Section 9 is the *policy* layer. This section is the *operational* runbook that turns the policy into executable steps.

### 9.1 Algorithm disable drill

The drill answers: "given a newly-announced break of algorithm X, can we disable X across the estate within 24 hours?"

```bash
#!/usr/bin/env bash
# crypto_agility_drill.sh — Disable an algorithm across the estate and measure rollback time.

set -euo pipefail
ALG_TO_DISABLE="${1:-mlkem768}"   # pass the algorithm name as $1
LAB_DIR="${PQC_LAB_DIR:-/tmp/pqc-lab}"

# 1. Snapshot current config
cp "$LAB_DIR/openssl-pqc.cnf" "$LAB_DIR/openssl-pqc.cnf.bak.$(date +%s)"

# 2. Disable the algorithm by removing it from the Groups and SignatureAlgorithms lines
sed -i -E "s/[ :]${ALG_TO_DISABLE}//g" "$LAB_DIR/openssl-pqc.cnf"

# 3. Restart the TLS server (simulated here with s_server)
pkill -f "openssl s_server.*4433" || true
sleep 1
OPENSSL_CONF="$LAB_DIR/openssl-pqc.cnf" openssl s_server \
    -accept 127.0.0.1:4433 -cert leaf-hybrid-fullchain.pem -key leaf-hybrid-key.pem \
    -www -tls1_3 >/dev/null 2>&1 &
SERVER_PID=$!
sleep 1

# 4. Verify the algorithm is no longer negotiable
if OPENSSL_CONF="$LAB_DIR/openssl-pqc.cnf" openssl s_client \
        -connect 127.0.0.1:4433 -tls1_3 -groups "$ALG_TO_DISABLE" -brief </dev/null 2>&1 \
        | grep -qi "no shared cipher\|alert"; then
    echo "DRILL PASS: $ALG_TO_DISABLE is no longer negotiable"
    ROLLOVER_OK=1
else
    echo "DRILL FAIL: $ALG_TO_DISABLE is still negotiable"
    ROLLOVER_OK=0
fi

kill $SERVER_PID 2>/dev/null || true

# 5. Roll back
LATEST_BAK=$(ls -t "$LAB_DIR"/openssl-pqc.cnf.bak.* | head -1)
cp "$LATEST_BAK" "$LAB_DIR/openssl-pqc.cnf"
echo "Rolled back to $LATEST_BAK"
echo "Result: rollover_ok=$ROLLOVER_OK"
```

Run quarterly. The pass criterion is `rollover_ok=1` within 5 minutes of operator action. If it takes longer, the deployment is not crypto-agile.

### 9.2 Algorithm rotation matrix

The matrix below is the operator's lookup table for "what do I rotate to?" when a break is announced.

| Broken primitive | Rotate to (civilian) | Rotate to (national-security) | Window |
|------------------|----------------------|-------------------------------|--------|
| ML-KEM-768 | ML-KEM-1024 | ML-KEM-1024 (already CNSA 2.0) | 7 days |
| ML-DSA-65 | ML-DSA-87 | ML-DSA-87 | 7 days |
| X25519 (classical-only mode) | x25519_mlkem768 (hybrid) | secp384r1_mlkem1024 | 24 hours |
| RSA-2048 (in PKI) | ECDSA P-256 (transition), then ML-DSA-65 | ML-DSA-87 | 90 days |
| SHA-256 (in PQC context) | SHAKE-256 | SHA-384 / SHA-512 | 30 days |

The "window" column is the maximum tolerable time from break announcement to estate-wide rotation. The targets above are derived from NIST SP 800-227 (draft) and CNSA 2.0 implementation guidance.

---

## 10. Performance and Sizing Notes

Post-quantum primitives are larger and slower than their classical counterparts. Production deployments must budget for this; otherwise the TLS handshake latency will silently regress and the SRE team will blame the network.

### 10.1 Reference measurements (liboqs 0.10, OpenSSL 3.2, ARM64 Cortex-A78)

| Primitive | Operation | Latency (μs) | Payload (bytes) |
|-----------|-----------|--------------|-----------------|
| X25519 | keygen | 80 | 32 |
| ML-KEM-768 | keygen | 280 | 1184 (pk) |
| ML-KEM-768 | encaps | 350 | 1088 (ct) |
| ML-KEM-768 | decaps | 320 | 32 (ss) |
| x25519_mlkem768 | full handshake | 430 | 1216 (key_share) |
| ECDSA P-256 | sign | 190 | 64 (sig) |
| ML-DSA-65 | sign | 1100 | 3309 (sig) |
| ML-DSA-65 | verify | 380 | — |
| RSA-2048 | sign | 1200 | 256 |
| Falcon-512 | sign | 420 | 666 |

**Implications**:
- Hybrid TLS adds ~350 μs of CPU per handshake (one ML-KEM-768 decaps). For a service doing 10k handshakes/sec, that is 3.5 sec of CPU per second per core — budget an extra 5% CPU headroom.
- ML-DSA signatures are 50× larger than ECDSA. A cert chain that was 2 KB becomes 100 KB. This affects TLS record fragmentation and QUIC packet sizing.
- Falcon is faster and smaller than ML-DSA but is not yet a FIPS standard. Use it only where standardization is not required.

### 10.2 Bandwidth budgeting

A typical TLS 1.3 handshake with classical crypto fits in 2-3 TCP segments (~4 KB). With hybrid ML-KEM-768 + ML-DSA-65, the handshake grows to ~6 KB. With ML-KEM-1024 + ML-DSA-87 (CNSA 2.0), it grows to ~10 KB. The TCP MSS is typically 1460 bytes, so:

- Classical: 3 segments
- Hybrid civilian: 5 segments
- Hybrid national-security: 7 segments

For mobile or satellite links with high RTT, this multiplies handshake completion time. QUIC is preferable for these links because it does not suffer TCP's head-of-line blocking on retransmission.

---

## 11. Integration with Adjacent Skills

This guide's deployment and lab artifacts feed into the adjacent skills listed below. Cross-linking ensures that an operator who found a side-channel leak in this lab knows where to escalate.

| Adjacent skill | When to invoke | Hand-off artifact |
|----------------|----------------|-------------------|
| `crypto-attacks` | Classical-crypto flaw in PQC hybrid leg (e.g., Bleichenbacher on RSA-PSS during hybrid negotiation) | TLS capture + dudect report |
| `binary-reverse` | Closed-source PQC implementation to audit (e.g., proprietary HSM firmware) | ELF binary, expected primitives |
| `hardware-security` | Side-channel work that crosses into physical lab (power analysis, EM, fault injection) | CW trace set, fault PoC |
| `cloud-security` | PQC deployment in KMS / ACM / CloudHSM | Provider config, KMS policy |
| `container-security` | PQC provider loaded into a container image | Dockerfile, image hash |
| `tls-ssl-analysis` | TLS-level downgrade/fallback analysis (complements scenario 7.1) | s_client output, pcap |

---

## 12. Pre-Deployment Checklist

Before any hybrid-PQC stack is promoted to production:

- [ ] `oqsprovider` loads on startup (`openssl list -providers` shows it active)
- [ ] Hybrid PKI generated and validated (both EC and ML-DSA legs verify)
- [ ] Server pins `-groups x25519_mlkem768` and `-sigalgs p256_mldsa65` explicitly
- [ ] Client pins the same groups/sigalgs (or uses a config management baseline that does)
- [ ] Wire-level capture (`tshark`) confirms `Shared groups returned: x25519_mlkem768`
- [ ] dudect run on production liboqs reports `|t| < 4.5` for all primitives
- [ ] ctgrind run reports no uninitialised-value warnings
- [ ] ML-DSA signing mode is randomized (or deterministic + transcript-logged)
- [ ] Re-encryption countermeasure enabled in ML-KEM decaps
- [ ] Prometheus metrics exported (handshake counts by group, provider health, t-stats)
- [ ] SLO dashboard live (hybrid rate, fallback rate, t-stat alert)
- [ ] Crypto-agility drill executed successfully (algorithm disabled in <5 min)
- [ ] Performance budget verified (handshake latency within SLO under peak load)
- [ ] Bandwidth budget verified (no MTU/MSS regression on mobile links)
- [ ] Runbook published (algorithm disable drill, break response, rollback procedure)
- [ ] Adjacent skills notified (cloud-security for KMS, container-security for image)

A stack that passes all 16 items is defensibly post-quantum ready. A stack that fails any item has a known, named gap that the migration roadmap can address.

---

## 13. Step-by-Step Walkthrough: A Full Hardening Pass

For engineers who want to walk through the entire guide end-to-end against a fresh lab, the sequence below is the canonical order.

1. **Provision** — `bash provision_pqc_lab.sh` from Section 2.2. Verify with `openssl list -providers`.
2. **Generate hybrid PKI** — Section 3.1. Verify both legs with `openssl verify` (Section 3.2).
3. **Bring up server** — Section 4.1. Confirm it listens on `127.0.0.1:4433`.
4. **Connect client** — Section 4.2. Confirm `Shared groups returned: x25519_mlkem768`.
5. **Capture handshake** — Section 4.3. Confirm `tshark` shows the 1216-byte key_share.
6. **Run dudect** — Section 5.2. Confirm `|t| < 4.5` over 100k measurements.
7. **Run ctgrind** — Section 5.3. Confirm no uninitialised-value warnings.
8. **(Optional) ChipWhisperer capture** — Section 5.4. Confirm TVLA passes.
9. **Run loop-abort PoC** — Section 6.1. Confirm the fault is detectable.
10. **Run scenarios A-D** — Section 7. Confirm each is reproduced and the solution resolves it.
11. **Stand up telemetry** — Section 8. Confirm Prometheus scrapes `pqc_constant_time_tstat`.
12. **Run agility drill** — Section 9.1. Confirm `rollover_ok=1`.
13. **Cross-link adjacent skills** — Section 11. Document hand-offs in the runbook.
14. **Walk the pre-deployment checklist** — Section 12. All 16 items must pass.

The full walkthrough takes 4-8 hours for an engineer fluent in OpenSSL. The output is a hardened lab, a telemetry spec, and a runbook — together the operator's evidence that the deployment will operate correctly day-to-day.

---

## 14. References and Further Reading

- **FIPS 203** — ML-KEM standard. NIST, August 2024.
- **FIPS 204** — ML-DSA standard. NIST, August 2024.
- **FIPS 205** — SLH-DSA standard. NIST, August 2024.
- **NIST SP 800-227** (Draft) — Recommendations for Key Establishment. NIST, 2023+.
- **NIST SP 800-208** — Stateful Hash-Based Signatures (XMSS, LMS). NIST, October 2020.
- **CNSA 2.0** — Commercial National Security Algorithm Suite 2.0. NSA, September 2022.
- **RFC 8998** — ShangMi Cipher Suites for TLS 1.3. March 2021.
- **RFC 9180** — Hybrid Public Key Encryption (HPKE). February 2022.
- **Reparaz, Balasch, Verbauwhede** — "Dude, is my code constant time?" DATE 2017.
- **Bruinderink, Pürr, Pöppelmann** — "Fault Attacks on CCA-Secure Lattice KEMs." Africacrypt 2017.
- **Poddebniak et al.** — "Attacking Deterministic Signature Schemes Using Fault Attacks." CT-RSA 2018.
- **Lydersen, Wiechers, Skaar** — "Hacking commercial quantum cryptography systems by tailored bright illumination." Nature Photonics, 2010.
- **Weier et al.** — "Quantum eavesdropping without quantum memory." Nature Photonics, 2011.
- **Cloudflare blog: A deep dive into post-quantum cryptography** — deployment notes on KEMTLS and hybrid TLS.
- **Google blog: CECPQ2** — early hybrid-PQC deployment in Chrome.
- **Signal blog: PQXDH** — post-quantum extension to the Signal X3DH protocol.
- **Apple security blog: PQ3** — post-quantum upgrade to iMessage.
- **liboqs documentation** — `https://openquantumsafe.org/liboqs/`.
- **oqs-provider documentation** — `https://github.com/open-quantum-safe/oqs-provider`.
- **ChipWhisperer documentation** — `https://chipwhisperer.readthedocs.io/`.

---

## 15. See Also

- `skills/quantum-crypto-attack/SKILL.md` — skill definition and tool inventory.
- `skills/quantum-crypto-attack/payloads.md` — command catalogue (sections 1-22).
- `skills/quantum-crypto-attack/test-cases.md` — structured test cases.
- `skills/quantum-crypto-attack/guides/quantum-crypto-attack-playbook.md` — end-to-end assessment workflow.
- `skills/quantum-crypto-attack/guides/pqc-migration-assessment-playbook.md` — migration roadmap and regulatory alignment.
- `skills/crypto-attacks/SKILL.md` — classical-crypto attack patterns (RSA, ECC, AES) referenced by the hybrid legs.
- `skills/hardware-security/SKILL.md` — physical side-channel and fault-injection tooling.
- `skills/tls-ssl-analysis/SKILL.md` — TLS-level analysis techniques (downgrade detection, group negotiation).
