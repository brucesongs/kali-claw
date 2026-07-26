# Payloads — quantum-cryptography-transition

> Attack payloads for quantum-cryptography-transition.

## HNDL Capture

```bash
# Passive capture of encrypted traffic
tcpdump -i eth0 -w hndl_capture.pcap 'tcp port 443'

# Store indefinitely; decrypt when quantum computer available
```

## PQC Hybrid TLS Test

```bash
# Test hybrid TLS (classical + PQC)
curl --pqc --tls13-ciphers TLS_AES_256_GCM_SHA384:KYBER768      https://target.com
```

## Weak KEM Combiner Check

```python
# Test if hybrid uses XOR (weak) or HKDF (strong)
from oqs import KeyEncapsulation
kex = KeyEncapsulation("Kyber768")
# Check combiner implementation in source code
```

## QKD Detector Blinding

```python
# Theoretical attack (requires hardware access)
# Send bright light at specific wavelength to blind single-photon detector
# Detector reports deterministic value; attacker controls key
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
