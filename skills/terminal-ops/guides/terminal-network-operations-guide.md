# Terminal Network Operations Guide

> Command patterns for network reconnaissance, traffic analysis, and connection management from the terminal.

---

## 1. Network Reconnaissance

### Interface and Routing

```bash
# List all interfaces with IPs
ip -br addr show

# Show routing table
ip route show
netstat -rn

# ARP table (local network hosts)
arp -a
ip neigh show

# Active connections
ss -tunapl
netstat -tlnp
```

### Port Scanning from Terminal

```bash
# Quick TCP scan with bash (no tools needed)
scan_port() {
    local host="$1" port="$2"
    (echo >/dev/tcp/"$host"/"$port") 2>/dev/null && echo "$port open" || echo "$port closed"
}

# Scan range
for port in $(seq 1 1024); do
    (echo >/dev/tcp/target/$port) 2>/dev/null && echo "$port open" &
done 2>/dev/null
wait

# Netcat port scan
nc -zv target.com 1-1000 2>&1 | grep "succeeded\|open"
```

---

## 2. Traffic Capture and Analysis

### tcpdump Patterns

```bash
# Capture HTTP traffic
sudo tcpdump -i eth0 -A 'tcp port 80' -w http_capture.pcap

# Capture DNS queries
sudo tcpdump -i any 'udp port 53' -nn

# Capture traffic to/from specific host
sudo tcpdump -i eth0 host 192.168.1.100 -w target_traffic.pcap

# Read pcap with filters
tcpdump -r capture.pcap 'tcp[tcpflags] & (tcp-syn) != 0' -nn

# Extract HTTP requests from pcap
tcpdump -r capture.pcap -A 'tcp port 80' | grep -E "^(GET|POST|PUT|DELETE|HEAD)"
```

### Connection Monitoring

```bash
# Watch new connections in real-time
watch -n 1 "ss -tunapl | grep ESTAB"

# Log all outbound connections
ss -tunapl | awk '/ESTAB/{print $5}' | cut -d: -f1 | sort -u

# Detect suspicious outbound connections
ss -tunapl | grep ESTAB | grep -vE "(127\.0\.0\.1|::1|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01]))" | sort
```

---

## 3. Tunneling and Pivoting

### SSH Tunnels

```bash
# Local port forward (access remote service locally)
ssh -L 8080:internal-host:80 user@jumpbox

# Remote port forward (expose local service remotely)
ssh -R 9090:localhost:8080 user@remote

# Dynamic SOCKS proxy
ssh -D 1080 user@jumpbox
# Then: proxychains nmap -sV internal-target

# SSH over HTTP proxy
ssh -o ProxyCommand="nc -X connect -x proxy:8080 %h %p" user@target
```

### Netcat Relays

```bash
# Simple relay
mkfifo /tmp/relay
nc -l -p 8080 < /tmp/relay | nc target 80 > /tmp/relay

# File transfer
# Receiver:
nc -l -p 9999 > received_file
# Sender:
nc target 9999 < file_to_send

# Reverse shell listener
nc -lvnp 4444
```

---

## 4. DNS Operations

```bash
# Bulk DNS resolution
while read domain; do
    ip=$(dig +short "$domain" A | head -1)
    echo "$domain → $ip"
done < domains.txt

# Reverse DNS sweep
for i in $(seq 1 254); do
    result=$(dig +short -x "192.168.1.$i" 2>/dev/null)
    [ -n "$result" ] && echo "192.168.1.$i → $result"
done

# DNS zone transfer attempt
dig axfr @ns1.target.com target.com

# DNS tunneling detection
tcpdump -i any 'udp port 53' -nn | awk '{print length, $0}' | sort -rn | head -20
```

---

## 5. Bandwidth and Performance

```bash
# Measure bandwidth between hosts
iperf3 -s  # Server
iperf3 -c target -t 10  # Client

# Monitor bandwidth per process
nethogs eth0

# Rate-limited operations
while read target; do
    curl -s "$target" > /dev/null
    sleep 0.5  # Rate limit: 2 req/sec
done < urls.txt
```
