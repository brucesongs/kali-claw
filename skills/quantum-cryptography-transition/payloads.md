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

---

## MITRE ATT&CK Mapping + Reference Expansion (v0.2.7)

### ATT&CK Mapping (F-QUAN-001)

| ATT&CK Technique | Skill Activity | Detection Hint |
|------------------|----------------|-----------------|
| **T1600 — Weaken Encryption** | Harvest-now-decrypt-later risk class | TLS scan: crypto inventory |
| **T1600.001 — Weaken Encryption: Reduce Key Space** | Legacy key-size downgrade targets | Audit: RSA-1024 survivors |
| **T1110.002 — Password Cracking** | Quantum-accelerated offline cracking risk | SIEM: GPU cluster anomalies |
| **T1040 — Network Sniffing** | HNDL capture infrastructure | Netflow: long-lived taps |
| **T1552.001 — Credentials In Files** | Static key rotation debt discovery | Secret scan: PQ-unready keys |

### Reference Expansion (F-QUAN-002)

- [NIST PQC standardization](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [FIPS 203 ML-KEM (Kyber)](https://csrc.nist.gov/pubs/fips/203/final)
- [PQClean reference implementations](https://pqcrystals.org)
- [liboqs integration library](https://github.com/open-quantum-safe/liboqs)
- [ENISA PQC guidance](https://www.enisa.europa.eu)
- [PQC deployment field reports](https://blog.cloudflare.com)
