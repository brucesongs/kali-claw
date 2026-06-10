# Wireshark and tshark Protocol Analysis Guide

## Introduction

Packet capture analysis is the foundational skill for network sniffing and MITM operations. Whether you are performing passive reconnaissance before an active engagement, extracting credentials from intercepted traffic, or documenting findings for a penetration test report, proficiency with Wireshark and tshark is essential. Wireshark provides a graphical interface for interactive analysis, while tshark offers the same protocol dissection engine on the command line, making it ideal for automation, remote systems, and headless environments.

This guide covers PCAP triage workflows, display filter techniques, protocol hierarchy analysis, and credential extraction patterns. The focus is on practical, repeatable workflows that can be applied during penetration testing engagements to quickly extract actionable intelligence from captured network traffic.

## PCAP Triage Workflow

When you receive or capture a PCAP file, follow this structured triage process to quickly understand what it contains before diving into specific protocol analysis.

### Step 1: Protocol Hierarchy

The protocol hierarchy statistics provide an instant overview of traffic composition by percentage:

```bash
tshark -r capture.pcap -q -z io,phs
```

This reveals:
- Which protocols dominate the traffic (TCP vs UDP vs ICMP)
- Application-layer protocols present (HTTP, DNS, SMB, FTP, SMTP)
- Any unexpected protocols that warrant deeper investigation
- The relative volume of each protocol for prioritization

Look for: cleartext protocols (HTTP, FTP, Telnet, SMTP) that indicate credential exposure opportunities, and encrypted traffic percentages (TLS/SSL) that indicate the encryption posture of the environment.

### Step 2: Endpoint and Conversation Statistics

Identify the key communicators in the capture:

```bash
# Top talkers by IP
tshark -r capture.pcap -q -z endpoints,ip

# IP conversation pairs
tshark -r capture.pcap -q -z conv,ip

# TCP conversations with byte counts
tshark -r capture.pcap -q -z conv,tcp
```

Focus on: the gateway IP (all traffic passes through it), DNS server IPs (reveal name resolution patterns), and any IPs with unusually high byte counts (potential data exfiltration or file transfers).

### Step 3: DNS Quick Scan

DNS queries reveal the hostnames and services accessed by target hosts:

```bash
# All DNS queries
tshark -r capture.pcap -Y "dns.qr == 0" -T fields -e ip.src -e dns.qry.name | sort -u

# Unique domains queried (frequency analysis)
tshark -r capture.pcap -Y "dns.qr == 0" -T fields -e dns.qry.name | sort | uniq -c | sort -rn | head -20

# DNS response codes (NXDOMAIN = failed lookups, potential LLMNR fallback trigger)
tshark -r capture.pcap -Y "dns.flags.rcode != 0" -T fields -e dns.qry.name -e dns.flags.rcode
```

Failed DNS lookups (NXDOMAIN responses) are significant because they trigger LLMNR/NBT-NS fallback on Windows hosts, which Responder exploits for credential harvesting.

### Step 4: HTTP Traffic Overview

HTTP traffic is the richest source of credentials and session data:

```bash
# HTTP request methods and URLs
tshark -r capture.pcap -Y "http.request" -T fields \
  -e ip.src -e http.request.method -e http.host -e http.request.uri

# HTTP response status codes
tshark -r capture.pcap -Y "http.response" -T fields \
  -e http.response.code -e http.content_type

# User-Agent strings (identify browsers and applications)
tshark -r capture.pcap -Y "http.request" -T fields \
  -e http.user_agent | sort -u
```

## Display Filters

Display filters are tshark's most powerful feature. They use Wireshark's protocol dissection engine to filter at every protocol layer with fine-grained precision.

### Essential Display Filters

```bash
# IP address filters
ip.addr == 192.168.1.100                    # Either source or destination
ip.src == 192.168.1.100 && ip.dst == 10.0.0.1  # Specific direction

# Port filters
tcp.port == 80                               # Source or destination port 80
tcp.dstport == 443                           # Destination port 443 only
udp.port == 53                               # DNS traffic

# Protocol filters
http                                         # All HTTP traffic
dns                                          # All DNS traffic
ftp                                          # All FTP traffic
kerberos                                     # Kerberos authentication
ntlmssp                                      # NTLM authentication
smb2                                         # SMB2 protocol

# Combined filters
http.request.method == "POST"                # HTTP POST requests only
http.response.code == 401                    # Unauthorized responses
http.authorization                           # HTTP Basic/Digest Auth headers
http.cookie                                  # HTTP cookies
http.set_cookie                              # Server Set-Cookie headers
```

### Advanced Display Filters

```bash
# TCP flags
tcp.flags.syn == 1 && tcp.flags.ack == 0     # SYN only (connection initiation)
tcp.flags.rst == 1                           # RST (connection reset)
tcp.flags.fin == 1                           # FIN (connection close)

# Frame-level filters
frame.time >= "2025-06-01 09:00:00"          # Time range filtering
frame.len > 1000                             # Large frames (file transfers)

# String matching
http.request.uri contains "login"            # URI contains "login"
http.host contains "intranet"                # Host contains "intranet"

# Boolean logic
(http.request.method == "GET" || http.request.method == "POST") && ip.src == 192.168.1.100
```

### Time-Based Analysis

```bash
# Traffic over time (requests per minute)
tshark -r capture.pcap -T fields -e frame.time_relative | \
  awk '{printf "%d\n", int($1/60)}' | sort -n | uniq -c

# Identify beaconing patterns (regular intervals between same src/dst)
tshark -r capture.pcap -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0" \
  -T fields -e frame.time_epoch -e ip.src -e ip.dst | sort
```

## Credential Extraction Patterns

### HTTP Basic Authentication

HTTP Basic Auth sends credentials in Base64 encoding within the Authorization header:

```bash
# Extract Basic Auth credentials
tshark -r capture.pcap -Y "http.authorization" \
  -T fields -e ip.src -e ip.dst -e http.host -e http.authorization

# Decode Base64 credentials
echo "Basic dXNlcjpwYXNzd29yZA==" | base64 -d
# Output: user:password
```

### HTTP Form POST Credentials

Login forms submit credentials via POST requests with URL-encoded form data:

```bash
# Extract POST form data containing credentials
tshark -r capture.pcap -Y "http.request.method == POST && urlencoded-form.key" \
  -T fields -e ip.src -e http.host -e http.request.uri \
  -e urlencoded-form.key -e urlencoded-form.value

# Alternative: extract raw POST body
tshark -r capture.pcap -Y "http.request.method == POST" \
  -T fields -e ip.src -e http.file_data
```

### FTP Credentials

FTP sends username and password in separate cleartext commands:

```bash
# Extract FTP USER and PASS commands
tshark -r capture.pcap \
  -Y "ftp.request.command == USER || ftp.request.command == PASS" \
  -T fields -e ip.src -e ftp.request.command -e ftp.request.arg

# Correlate USER/PASS pairs from same source IP
tshark -r capture.pcap -Y "ftp.request" \
  -T fields -e ip.src -e ftp.request.command -e ftp.request.arg
```

### SMTP Authentication

SMTP AUTH sends credentials in cleartext (unless STARTTLS is used):

```bash
# Extract SMTP AUTH credentials
tshark -r capture.pcap -Y "smtp.auth" \
  -T fields -e ip.src -e smtp.auth.username -e smtp.auth.password

# Extract SMTP MAIL FROM and RCPT TO (email metadata)
tshark -r capture.pcap \
  -Y "smtp.req.command == MAIL || smtp.req.command == RCPT" \
  -T fields -e ip.src -e smtp.req.command -e smtp.req.parameter
```

### NTLM / Kerberos Authentication

Windows authentication hashes are extractable from SMB and HTTP traffic:

```bash
# NTLM SSP authentication over SMB
tshark -r capture.pcap -Y "ntlmssp.auth" \
  -T fields -e ip.src -e ip.dst -e ntlmssp.auth.username -e ntlmssp.auth.domain

# Kerberos AS-REQ (pre-authentication data)
tshark -r capture.pcap -Y "kerberos.msg_type == 10" \
  -T fields -e ip.src -e kerberos.cname -e kerberos.realm

# Kerberos TGS-REQ (service ticket requests — reveals SPNs)
tshark -r capture.pcap -Y "kerberos.msg_type == 12" \
  -T fields -e ip.src -e kerberos.sname
```

### Cookie and Session Token Extraction

Session cookies enable account takeover without password knowledge:

```bash
# Extract all cookies from HTTP requests
tshark -r capture.pcap -Y "http.cookie" \
  -T fields -e ip.src -e http.host -e http.cookie

# Extract Set-Cookie headers from responses
tshark -r capture.pcap -Y "http.set_cookie" \
  -T fields -e ip.src -e ip.dst -e http.set_cookie

# Find session tokens in URLs (query parameters)
tshark -r capture.pcap -Y "http.request.uri contains session || http.request.uri contains token" \
  -T fields -e ip.src -e http.request.uri
```

## Object Export

Wireshark and tshark can extract files, images, and objects transferred over various protocols:

```bash
# Export all HTTP objects (images, PDFs, executables, documents)
tshark -r capture.pcap --export-objects http,/tmp/http_exports

# Export all SMB objects (files transferred over SMB)
tshark -r capture.pcap --export-objects smb,/tmp/smb_exports

# Export email attachments (IMF format — SMTP/IMAP/POP3)
tshark -r capture.pcap --export-objects imf,/tmp/email_exports

# List exported files
find /tmp/http_exports -type f -ls
```

After export, analyze the files for sensitive content:

```bash
# Find interesting file types
find /tmp/http_exports -type f \( -name "*.pdf" -o -name "*.doc" -o -name "*.xlsx" -o -name "*.conf" -o -name "*.xml" \)

# Check for credentials in exported text files
grep -rli "password\|secret\|api_key\|token" /tmp/http_exports/
```

## Live Traffic Monitoring

For real-time analysis during an active engagement, use tshark in live mode:

```bash
# Monitor HTTP credentials in real-time
tshark -i eth0 -Y "http.authorization || http.cookie" \
  -T fields -e ip.src -e http.authorization -e http.cookie -l

# Monitor DNS queries in real-time
tshark -i eth0 -Y "dns.qr == 0" -T fields -e ip.src -e dns.qry.name -l

# Monitor all plaintext credentials (FTP, HTTP, SMTP, IMAP)
tshark -i eth0 -Y "ftp.request || http.authorization || smtp.auth || imap.request" \
  -T fields -e ip.src -e frame.protocols -e frame.time -l

# Real-time protocol distribution
tshark -i eth0 -q -z io,phs
```

The `-l` flag enables line-buffered output for real-time display.

## Performance Tips for Large PCAP Files

```bash
# Split large PCAP by time (one file per hour)
editcap -F pcap -A "2025-06-01 09:00:00" -B "2025-06-01 10:00:00" large.pcap hour_09.pcap

# Split by packet count
editcap -c 100000 large.pcap split_

# Use capture filters (BPF) during capture to reduce file size
tcpdump -i eth0 -w targeted.pcap "port 80 or port 443 or port 21"

# Use display filters early to reduce processing
tshark -r large.pcap -Y "http.authorization" -T fields -e ip.src -e http.authorization
```

## References

- [Wireshark Display Filter Reference](https://www.wireshark.org/docs/dfref/) — Complete field reference for all protocols
- [tshark Manual Page](https://www.wireshark.org/docs/man-pages/tshark.html) — Command-line options and usage
- [Wireshark Wiki — Display Filters](https://gitlab.com/wireshark/wireshark/-/wikis/DisplayFilters) — Filter syntax guide and examples
- [tcpdump Manual Page](https://www.tcpdump.org/manpages/tcpdump.1.html) — BPF filter syntax for capture filters
- [PCAP Analysis for Incident Response](https://www.sans.org/white-papers/33861/) — SANS guide to network forensics
