# TLS/SSL Misconfiguration Guide

> Identify and exploit weak TLS configurations including deprecated protocols, vulnerable cipher suites, and certificate issues. Covers testssl.sh, sslscan, and active downgrade attacks.

## 1. Comprehensive TLS Assessment with testssl.sh

The primary tool for thorough TLS configuration analysis:

```bash
# Full scan of a target
testssl.sh https://target.com

# Scan specific checks with JSON output
testssl.sh --jsonfile results.json --severity HIGH \
  --protocols --ciphers --vulnerabilities target.com:443

# Scan an internal host on a non-standard port
testssl.sh --ip=one --sneaky 192.168.1.50:8443
```

Key flags:
- `--protocols` — Check supported SSL/TLS versions
- `--ciphers` — Enumerate all accepted cipher suites
- `--vulnerabilities` — Test for known attacks (BEAST, POODLE, Heartbleed)
- `--severity` — Filter output by severity level

## 2. Quick Cipher Suite Analysis

Rapidly identify weak ciphers with targeted tools:

```bash
# sslscan for quick overview
sslscan --no-colour target.com:443

# Nmap SSL enumeration
nmap --script ssl-enum-ciphers -p 443 target.com

# OpenSSL manual cipher check
openssl s_client -connect target.com:443 -tls1 -cipher 'RC4' 2>/dev/null | \
  grep -i "cipher\|protocol"

# Check for specific weak cipher acceptance
for cipher in RC4-SHA DES-CBC3-SHA NULL-MD5 EXPORT; do
  echo -n "$cipher: "
  openssl s_client -connect target.com:443 -cipher "$cipher" 2>&1 | \
    grep -c "Cipher is"
done
```

## 3. Protocol Downgrade Attacks

Test whether a server can be forced to use deprecated protocols:

```bash
# Force SSLv3 connection (POODLE vulnerability)
openssl s_client -connect target.com:443 -ssl3

# Force TLS 1.0 (BEAST vulnerability context)
openssl s_client -connect target.com:443 -tls1

# Test TLS_FALLBACK_SCSV support (downgrade prevention)
openssl s_client -connect target.com:443 -fallback_scsv -tls1_1
# If connection succeeds, server does NOT enforce fallback protection
```

```bash
# Automated downgrade test with testssl.sh
testssl.sh --protocols --each-cipher target.com:443 2>&1 | \
  grep -E "SSLv[23]|TLS 1\.[01]|offered"
```

## 4. Certificate Chain Validation Issues

Identify exploitable certificate problems:

```bash
# Check full certificate chain
openssl s_client -connect target.com:443 -showcerts 2>/dev/null | \
  openssl x509 -noout -text | \
  grep -E "Issuer|Subject|Not After|DNS:"

# Verify certificate against hostname
openssl s_client -connect target.com:443 -verify_hostname target.com

# Check for wildcard abuse and SAN entries
echo | openssl s_client -connect target.com:443 2>/dev/null | \
  openssl x509 -noout -ext subjectAltName

# Test for expired certificates
echo | openssl s_client -connect target.com:443 2>/dev/null | \
  openssl x509 -noout -dates
```

## 5. HSTS and Security Header Analysis

Missing transport security headers enable stripping attacks:

```bash
# Check HSTS header
curl -sI https://target.com | grep -i "strict-transport"

# Verify HSTS preload eligibility
curl -sI https://target.com | grep -iE "strict-transport|includeSubDomains|preload"

# Test HTTP to HTTPS redirect behavior
curl -sI -L http://target.com | grep -E "^HTTP|^Location"
```

```yaml
# Expected secure HSTS configuration
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

## 6. Exploiting Weak Key Exchange

Identify and exploit weak Diffie-Hellman parameters:

```bash
# Test for weak DH parameters (Logjam)
openssl s_client -connect target.com:443 -cipher 'EDH' 2>/dev/null | \
  grep "Server Temp Key"
# DH key < 2048 bits is vulnerable

# Check for export-grade ciphers (FREAK)
openssl s_client -connect target.com:443 -cipher 'EXPORT' 2>&1 | \
  grep -c "Cipher is"

# Nmap Logjam detection
nmap --script ssl-dh-params -p 443 target.com
```

## 7. Automated Reporting Script

Combine findings into an actionable report:

```bash
#!/bin/bash
TARGET="${1:?Usage: $0 <host:port>}"
OUTDIR="tls-report-$(date +%Y%m%d)"
mkdir -p "$OUTDIR"

echo "[*] Running testssl.sh..."
testssl.sh --jsonfile "$OUTDIR/testssl.json" \
  --htmlfile "$OUTDIR/report.html" \
  --severity LOW "$TARGET"

echo "[*] Running sslscan..."
sslscan --xml="$OUTDIR/sslscan.xml" "$TARGET"

echo "[*] Checking security headers..."
curl -sI "https://$TARGET" > "$OUTDIR/headers.txt"

echo "[*] Results saved to $OUTDIR/"
echo "[*] Critical findings:"
grep -E '"severity":"(HIGH|CRITICAL)"' "$OUTDIR/testssl.json" | \
  python3 -m json.tool
```

## 8. Remediation Checklist

After identifying issues, verify fixes:

- Disable SSLv2, SSLv3, TLS 1.0, TLS 1.1
- Remove RC4, DES, 3DES, NULL, EXPORT ciphers
- Use ECDHE key exchange with 256-bit curves minimum
- Deploy HSTS with includeSubDomains and minimum 1-year max-age
- Ensure certificate chain is complete and valid
- Enable TLS_FALLBACK_SCSV
- Use DH parameters of 2048 bits or higher
