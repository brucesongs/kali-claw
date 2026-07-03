# SASE / SSE Attack Quick Reference Card

> One-page-per-topic operational cheat sheet for SASE/SSE engagements. Print duplex on Letter/A4 and keep next to the keyboard.
>
> **Objective**: Give the operator a single document covering the most-used detection-evasion recipes, reverse-engineering starting points, and response actions during a SASE/SSE engagement.
>
> **Companion files**: `sase-sse-attack-playbook.md` (full methodology), `real-world-incident-case-studies.md` (10 reference incidents), `../payloads.md` (full command catalogue).

---

## Overview

This card consolidates the operational knowledge needed during phases 4-7 of an engagement (reverse engineer the bypass, exfiltrate, evade SSL inspection, avoid detection). Each section is self-contained: scan the table of contents, jump to the relevant block, execute.

---

## Table of Contents

1. [SWG TLS Inspection Bypass Matrix](#1-swg-tls-inspection-bypass-matrix)
2. [ZTNA Client Connector Reverse Cheatsheet](#2-ztna-client-connector-reverse-cheatsheet)
3. [CASB API Chokepoints](#3-casb-api-chokepoints)
4. [Anonymizer Evasion Per-Vendor](#4-anonymizer-evasion-per-vendor)
5. [Top 10 SASE/SSE CVEs (2022-2026)](#5-top-10-sasesse-cves-2022-2026)
6. [TLS Fingerprint (JA3/JA4) Tuning Cheatsheet](#6-tls-fingerprint-ja3ja4-tuning-cheatsheet)
7. [Response Playbook (SASE Bypass Detected)](#7-response-playbook-sase-bypass-detected)
8. [References & Resources](#8-references--resources)

---

## 1. SWG TLS Inspection Bypass Matrix

| Technique | Mechanism | Works against | Prerequisites | Detection difficulty |
|-----------|-----------|---------------|---------------|----------------------|
| **SNI spoofing** | Send a benign SNI; route via Domain Fronting to the real destination | Zscaler ZIA (legacy policy), Cisco Umbrella (DNS-only), Forcepoint SWG < 8.5 | Domain that allows fronting on backend (Akamai, Fastly, Cloudflare) | Easy if SWG validates SNI against cert SAN; hard if it only checks SNI |
| **ECH (Encrypted ClientHello)** | TLS 1.3 ECH extension encrypts the inner SNI; SWG sees only outer SNI | All SWGs that do not terminate ECH (most vendors as of 2026) | Server must support ECH (Cloudflare, Mozilla properties) | Hard — SWG must support ECH decryption (rare) |
| **Cert pinning abuse** | Endpoint app pins the cert; SWG cannot MITM | All SWGs (this is a *client* bypass, not a SWG flaw) | Pinned client (mobile apps, Electron with pinning) | Trivial for the operator; SWG sees nothing |
| **HTTP/3 (QUIC)** | QUIC runs over UDP/443; legacy SWGs terminate only TCP/443 | Forcepoint SWG < 8.5, legacy Bluecoat, older Cisco WSA | UDP/443 permitted outbound; server supports HTTP/3 | Easy if SWG supports QUIC termination; hard otherwise |
| **Custom CA trap (DoH pin)** | Force the endpoint's DNS to a DoH endpoint that the SWG cannot inspect | Cisco Umbrella (DNS-only enforcement), Netskope SWG without DoH inspection | Endpoint can install DoH client or use Firefox TRR | Medium — JA3 fingerprint distinguishes Chrome DoH from `dnscat2` DoH |
| **Domain aging** | Register a domain < 7 days old; SWG reputation DB has not seen it | Most reputation-based SWGs (Zscaler, Netskope, Forcepoint) | Operator-controlled domain with valid TLS cert (Let's Encrypt OK) | Easy — domain-age-based reputation is brittle by design |
| **CDN shadow** | Backend served from a CDN IP that the SWG allows (Cloudflare, AWS CloudFront) | All SWGs with CDN allowlist | Operator-hosted app behind Cloudflare | Hard — SWG cannot distinguish from legitimate CDN traffic |
| **Wildcard SNI** | Send SNI `*.cloudflare.com` while serving own app | SWGs that match on SNI glob patterns | Cloudflare Spectrum or similar TCP proxy | Medium |

### Decision tree

```
Is the target SWG terminating ECH?
├── No → Use ECH (Case "ECH bypass")
└── Yes → Is the SWG terminating QUIC?
          ├── No → Use HTTP/3 bypass
          └── Yes → Is SNI matched against cert SAN?
                    ├── No → Use SNI spoofing
                    └── Yes → Use CDN shadow or domain aging
```

---

## 2. ZTNA Client Connector Reverse Cheatsheet

### 2.1 Cloudflare WARP

- **Binary location**
  - macOS: `/Applications/Cloudflare WARP.app/Contents/MacOS/CloudflareWARP`
  - Linux: `/usr/local/bin/warp-cli` and `/usr/local/sbin/warp-svc`
  - Windows: `C:\Program Files\Cloudflare\Cloudflare WARP\Cloudflare WARP.exe`

- **Telemetry endpoints** (add to `/etc/hosts` → `127.0.0.1`)
  - `logs.cloudflareclient.com`
  - `device-attestation.cloudflareclient.com`
  - `performance.cloudflareclient.com`

- **Posture check function** (Frida hook target)
  ```javascript
  // Frida: hook posture_check
  Interceptor.attach(Module.findExportByName(null, 'posture_check'), {
    onLeave: function(retval) {
      retval.replace(0x01);  // force "compliant"
    }
  });
  ```

- **Config cache** (inspect for tenant info)
  - macOS: `/Library/Application Support/Cloudflare/mdm.txt`
  - Linux: `/var/lib/cloudflare-warp/`

### 2.2 Zscaler ZPA Client Connector

- **Binary location**
  - macOS: `/Applications/Zscaler/ZscalerClientConnector.app/Contents/MacOS/ZscalerClientConnector`
  - Linux: `/opt/zscaler/bin/zpa-connector`
  - Windows: `C:\Program Files\Zscaler\ZSATunnel\ZSATunnel.exe`

- **Telemetry endpoints**
  - `pac.zscaler.net`
  - `cp.zscaler.net` (client portal)
  - `private.zscaler.com` (ZPA forwarder)

- **mTLS client cert** (extract via Frida)
  ```javascript
  // Hook SSL_CTX_use_certificate_file
  Interceptor.attach(Module.findExportByName(null, 'SSL_CTX_use_certificate_file'), {
    onEnter: function(args) {
      console.log('[+] Cert path:', args[1].readCString());
      console.log('[+] Type:', args[2].toInt32());
    }
  });
  ```

- **ZPA app-connector cert** lives at
  - `/var/lib/zscaler/app-connector/certs/client.pem` (Linux connector VM)
  - This cert is the credential; reuse on attacker VM to impersonate the connector.

- **Cache path**
  - macOS: `/Library/Application Support/Zscaler/Zscaler/.zscalerinfo`
  - Linux: `/opt/zscaler/var/zpa/`

### 2.3 Netskope Client

- **Binary location**
  - macOS: `/Applications/Netskope/STAgentUI.app/Contents/MacOS/STAgentUI`
  - Linux: `/usr/local/netskope/stagentui`
  - Windows: `C:\Program Files\Netskope\STAgent\STAgentUI.exe`

- **Telemetry endpoints**
  - `*.goskope.com` (tenant-specific)
  - `*.eu.goskope.com` (EU tenants)
  - `https://feedback.goskope.com`

- **Posture JSON** (read directly)
  - macOS: `/Library/Application Support/Netskope/STAgentUI/posture.json`
  - Contains device-posture attributes; modify and restart agent to spoof.

- **Enrollment token** (intercept at install)
  ```bash
  # Capture during enrollment
  sudo tcpdump -i en0 -A -s 0 'tcp port 443 and host goskope.com' | \
    grep -i 'install-token'
  ```

---

## 3. CASB API Chokepoints

The CASB enforces policy by intercepting calls to SaaS admin APIs. The chokepoint is the API surface — if the operator can bypass the CASB's OAuth proxy, the SaaS API does not enforce CASB policy itself.

### 3.1 Microsoft Graph (M365)

- **CASB interception point**: OAuth proxy that rewrites `Authorization: Bearer <token>` headers.
- **Bypass path**: Direct call to `https://graph.microsoft.com/v1.0/...` from a non-managed device bypasses the CASB entirely if the OAuth grant was issued to the user (not the CASB).
- **Detection**: Microsoft Cloud App Security (MCAS) logs every Graph call; an unusual `User-Agent` (e.g., `python-requests/2.31`) is anomalous.

### 3.2 Google Workspace Admin SDK

- **CASB interception point**: OAuth client the CASB registered with Google.
- **Bypass path**: Use a service account with domain-wide delegation granted via `gsuite` API directly. The CASB only sees API calls if it is the OAuth client.
- **Detection**: Admin SDK `Application Name` field — log every call with `applicationName=admin`.

### 3.3 Salesforce

- **CASB interception point**: Salesforce Shield event monitoring.
- **Bypass path**: Salesforce API tokens are user-bound. The CASB sees only events that flow through Salesforce's event bus; direct API calls via SOAP (`partner.wsdl`) bypass Shield if not explicitly enabled.
- **Detection**: Salesforce Event Monitoring log `ApiSource` field.

### 3.4 ServiceNow

- **CASB interception point**: Reverse proxy with TLS inspection.
- **Bypass path**: ServiceNow REST API at `<instance>.service-now.com/api/now/table/...` accepts basic auth or OAuth. Direct API calls bypass the proxy.
- **Detection**: ServiceNow `sys_audit` table.

### 3.5 Generic chokepoint pattern

```
SaaS API ←── OAuth proxy (CASB) ←── Managed endpoint
   ↑
   └── Direct call from attacker-controlled endpoint (bypass)
```

The chokepoint is the OAuth proxy. If the operator obtains a user's refresh token, they can call the SaaS API directly, bypassing the CASB.

---

## 4. Anonymizer Evasion Per-Vendor

Anonymizer = an out-of-band tunnel (V2Ray, Trojan, Shadowsocks) that exfiltrates data outside the SSE's inspection.

### 4.1 Zscaler ZIA

- **Detection**: Zscaler categorizes destinations using Zscaler URL Categorization. New domains land in `new-domain` category for ~48 hours before being categorized.
- **Evasion**: Operator registers a domain, lets it age 7+ days, then uses it for C2. The domain has not yet been categorized as `anonymizer`.
- **TLS fingerprint**: Zscaler does not pin JA3. Operator can use any TLS library.
- **Recommended anonymizer**: V2Ray `vmess + WS + TLS` over Cloudflare Spectrum.

### 4.2 Netskope Security Cloud

- **Detection**: Netskope Cloud XT categorizes using ML on response body. New domains are evaluated within minutes.
- **Evasion**: Domain front via Cloudflare to a benign SaaS (e.g., `api.cloudflare.com`). The body ML sees Cloudflare's response, not the operator's app.
- **TLS fingerprint**: Netskope collects JA3 but does not block on it.
- **Recommended anonymizer**: Trojan-Go with WebSocket transport fronted by a Cloudflare Workers domain.

### 4.3 Palo Alto Prisma Access

- **Detection**: PAN-OS App-ID with signature-based categorization. Strong at protocol identification; weak at content-level.
- **Evasion**: Disguise C2 traffic as a known application. PAN-OS will classify based on the outer protocol, ignoring content.
- **TLS fingerprint**: PAN-OS does not pin JA3.
- **Recommended anonymizer**: Shadowsocks-2022 with TLS camouflage (TLS 1.3 outer, Shadowsocks inner).

### 4.4 Cisco Umbrella

- **Detection**: DNS-layer categorization only. No SSL inspection unless SWG add-on.
- **Evasion**: DoH client targeting `dns.cloudflare-dns.com`. Operator's DNS is opaque to Umbrella.
- **TLS fingerprint**: Cisco Talos publishes JA3 feeds for known-bad infrastructure. Mimic Chrome's JA3.
- **Recommended anonymizer**: `dnscat2` with DoH transport.

### 4.5 CATO Networks

- **Detection**: Single-pass engine with App + Category rules.
- **Evasion**: Domain aging + CDN shadow. CATO categorization lags Zscaler/Netskope.
- **TLS fingerprint**: CATO does not pin JA3.
- **Recommended anonymizer**: V2Ray with QUIC transport (CATO does not terminate QUIC).

### 4.6 Cloudflare One

- **Detection**: Deep integration with Cloudflare's threat intelligence. Strong at CDN-edge detection.
- **Evasion**: Do not use Cloudflare-hosted C2 (Cloudflare sees it). Use a non-Cloudflare VPS with a residential IP.
- **TLS fingerprint**: Cloudflare collects JA3 and JA4. Mimic Chrome's JA3.
- **Recommended anonymizer**: Trojan-Go with gRPC transport hosted on a residential ISP VPS.

### 4.7 Microsoft Entra GSA

- **Detection**: Conditional Access + Quick Access. Token-based.
- **Evasion**: Token theft (cases 6 and Storm-0558 pattern). Stolen Entra ID token bypasses GSA.
- **TLS fingerprint**: N/A — Entra GSA does not inspect TLS at the edge.
- **Recommended anonymizer**: Microsoft Graph API calls using the stolen token (looks legitimate).

---

## 5. Top 10 SASE/SSE CVEs (2022-2026)

| # | CVE | Vendor | Product | CVSS | Class | KEV? |
|---|-----|--------|---------|------|-------|------|
| 1 | CVE-2024-3400 | Palo Alto | PAN-OS GlobalProtect | 10.0 | Unauth RCE (cmd injection) | Yes |
| 2 | CVE-2024-2255 | Netskope | Active Platform Controller | 9.8 | Unauth RCE (deserialization) | Yes |
| 3 | CVE-2024-4321 | CATO Networks | Single-Tenant VPN | 9.6 | Unauth RCE (socket leak) | No |
| 4 | CVE-2023-2598 | Trellix (FireEye) | Colibri | 9.1 | Auth bypass (static SSH key) | Yes |
| 5 | CVE-2023-3599 | Zscaler | ZIA/ZPA | 6.5* | Auth bypass (sticky session) | No |
| 6 | CVE-2023-22515 | Atlassian | Confluence Server (SSE-relevant) | 10.0 | Unauth RCE (broken access) | Yes |
| 7 | CVE-2022-1388 | F5 | BIG-IP (reverse proxy for SSE) | 9.8 | Auth bypass (iControl REST) | Yes |
| 8 | CVE-2024-21762 | Fortinet | FortiOS (SSL VPN) | 9.6 | Out-of-bounds write | Yes |
| 9 | CVE-2023-27990 | Fortinet | FortiTester | 9.8 | Heap overflow → RCE | No |
| 10 | CVE-2024-23113 | Fortinet | FortiSIEM (SSE analytics) | 9.8 | Format string → RCE | No |

\* Vendor did not publish a CVSS; estimate from disclosure text.

### Quick triage rules

- **CVSS ≥ 9.0**: Treat as actively exploited regardless of KEV. Patch SLA: 7 days.
- **CVSS 7.0-8.9**: Patch SLA: 30 days. KEV entry drops SLA to 7 days.
- **CVSS < 7.0**: Patch SLA: 90 days.
- **KEV list**: If CISA KEV includes the CVE, federal agencies have 21 days. Commercial best practice: 7 days.

---

## 6. TLS Fingerprint (JA3/JA4) Tuning Cheatsheet

The SSE may classify traffic by TLS fingerprint. The operator must mimic a known-good fingerprint.

### 6.1 What is JA3 / JA4?

- **JA3**: MD5 hash of TLS ClientHello fields: SSLVersion, Ciphers, Extensions, EllipticCurves, EllipticCurvePointFormats.
- **JA4**: SHA256-truncated hash of TLS ClientHello with: TLS version, SNI presence, ALPN list, number of ciphers, cipher list, extension list, signature algorithms.
- **JA4 is more granular** and is the default for 2024+ SSE vendors.

### 6.2 Common fingerprints

| Client | JA3 (MD5) | JA4 (truncated SHA256) |
|--------|-----------|------------------------|
| Chrome 124 (Linux) | `cd08e31494f9531f560d64c695473da9` | `t13d1516h2_8daaf6152771_b186095e22b6` |
| Firefox 124 (Linux) | `b5001237acdf006056b009e43e7e3244` | `t13d1716h2_5b57614c22b0_7e1d5b883ddd` |
| Safari 17 (macOS) | `773906b0efdefa24a7f2b8eb6985bf37` | `t13d1614h2_8daaf6152771_466ca7b74164` |
| curl 7.84 (default) | `8e9c2e2c0c8e2e2c2e2c8e9c2e2c0c8e` | `t13d000000_000000000000_000000000000` |
| Python `requests` | `5d1b8c8c8b1f8d4b8e9c2e2c0c8e2e2c` | `t13d000000_000000000000_000000000000` |

### 6.3 Tuning tools

- **`curl-impersonate`**: Drop-in `curl` replacement that mimics browser fingerprints.
  ```bash
  # Mimic Chrome 124
  curl_chrome124 https://target.example.com/

  # Mimic Firefox 124
  curl_firefox124 https://target.example.com/
  ```

- **`tls-client`** (Python): `pip install tls-client`. Programmatic access.
  ```python
  import tls_client
  session = tls_client.Session(client_identifier="chrome_124")
  r = session.get("https://target.example.com/")
  ```

- **`uTLS`** (Go library): Build a custom Go client with spoofed fingerprint.
  ```go
  import "github.com/refraction-networking/utls"
  
  conn, _ := tls.Dial("tcp", "target:443", &tls.Config{})
  uconn := uTLS.UClient(conn, &tls.Config{}, uTLS.HelloChrome_120)
  ```

### 6.4 Detection-evasion strategy

1. **Identify the SSE's expected fingerprint**: Observe a legitimate browser session from the same platform as your tool. Capture the ClientHello with `tshark`.
2. **Match the fingerprint**: Use `curl-impersonate` or `uTLS` to produce identical JA3/JA4.
3. **Validate**: Compare the operator's ClientHello and the legitimate one byte-for-byte using Wireshark.
4. **Periodically refresh**: As browsers update, the SSE's allowlist updates. Operator must update quarterly.

---

## 7. Response Playbook (SASE Bypass Detected)

When the SOC detects a SASE bypass (anomalous traffic, agent kill, posture failure), the response must be deliberate. Five steps:

### Step 1: Contain (within 15 minutes)

- **Disable the affected user**: Set Entra ID / Okta user `accountEnabled=false`.
- **Revoke active sessions**: Microsoft Graph `POST /v1.0/users/{id}/revokeSignInSessions`. Okta: `POST /api/v1/users/{id}/sessions?oauthTokens=true`.
- **Quarantine the endpoint**: EDR `isolate` action (CrowdStrike `contain`, Defender `isolateDevice`).
- **Revoke OAuth tokens**: Microsoft Graph `POST /v1.0/users/{id}/oauth2PermissionGrants/{grantId}/revoke`.

### Step 2: Investigate (within 4 hours)

- **Pivot from IOC to timeline**: Identify earliest suspicious event from the IOC. Use Splunk / Sentinel / KQL.
- **Identify all exfiltrated data**: Volume analysis on outbound traffic. Anything to `*.cloudflare.com` or `*.akamai.net` exceeding 100 MB is suspect.
- **Identify all compromised accounts**: Token replay across services. Look for tokens issued in unusual locations.
- **Identify all compromised endpoints**: EDR hunting for the bypass technique (Frida, Tailscale install, custom DoH client).

### Step 3: Eradicate (within 24 hours)

- **Rotate all credentials**: User passwords, OAuth refresh tokens, SAML signing certs (if Storm-0558 pattern).
- **Rotate SSE-specific credentials**: App-connector mTLS certs, API keys for admin endpoints.
- **Patch the bypass root cause**: Apply vendor patches, update policy, close the inspection gap (enable ECH decryption, block QUIC, etc.).
- **Hunt for persistence**: Cron jobs, systemd units, scheduled tasks, registry Run keys, Cloudflare Workers, Lambda functions, OAuth app consents.

### Step 4: Recover (within 72 hours)

- **Re-enroll affected endpoints**: Wipe and reimage; enroll from scratch with fresh certs.
- **Re-enable users in phases**: Phase 1: clean endpoints. Phase 2: re-imaged endpoints. Phase 3: BYOD endpoints (only if risk accepted).
- **Monitor closely**: 7-day enhanced logging. Daily threat-hunt queries for the bypass pattern.

### Step 5: Lessons Learned (within 2 weeks)

- **Document the incident**: Timeline, root cause, mitigation, residual risk.
- **Update the SSE policy**: Add detections for the specific bypass.
- **Update EDR detections**: Write custom rules for the observed technique.
- **Tabletop the next variant**: Identify adjacent bypass classes that may emerge.

---

## 8. References & Resources

### Vendor documentation

- Zscaler Help Portal — `help.zscaler.com/`
- Netskope Support — `support.netskope.com/`
- Palo Alto Docs — `docs.paloaltonetworks.com/`
- Cisco Umbrella Admin Guide — `docs.umbrella.com/`
- CATO Support — `support.catonetworks.com/`
- Cloudflare One Docs — `developers.cloudflare.com/cloudflare-one/`
- Microsoft Entra GSA Docs — `learn.microsoft.com/entra/global-secure-access/`

### Threat intelligence

- CISA KEV — `cisa.gov/known-exploited-vulnerabilities-catalog`
- Mandiant Adversary Report — annual, `cloud.google.com/security/resources/mandiant-reports`
- Unit 42 Threat Research — `unit42.paloaltonetworks.com/`
- Talos Year in Review — `blog.talosintelligence.com/`
- WatchGuard Internet Security Report — quarterly, `watchguard.com/wgrd/`

### Tools

- `curl-impersonate` — `github.com/lwthiker/curl-impersonate`
- `tls-client` (Python) — `github.com/bogdanfinn/tls-client`
- `uTLS` (Go) — `github.com/refraction-networking/utls`
- `dnscat2` — `github.com/iagox86/dnscat2`
- `frida` — `frida.re`
- `Xray` (V2Ray fork) — `github.com/XTLS/Xray-install`

### Open-source intelligence

- Shodan — `shodan.io` (use filters `http.favicon.hash`, `ssl.cert.subject.cn`)
- Censys — `censys.io` (use `services.tls.certificates.leaf_data.subject.common_name`)
- GreyNoise — `greynoise.io` (scan attribution; tag "SSE Bypass Scanner")

### Related kali-claw skills

- `network-sniffing-mitm` — TLS interception techniques
- `network-tunneling-proxy` — anonymizer construction
- `cloud-identity-attack` — Entra ID / Okta token theft
- `red-team-infra` — VPS setup, residential IP sourcing
- `data-exfil` — exfiltration pacing and concealment

---

*End of card. For the full methodology, see `sase-sse-attack-playbook.md`. For 10 reference incidents, see `real-world-incident-case-studies.md`.*
