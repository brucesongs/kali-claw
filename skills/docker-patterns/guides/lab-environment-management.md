# Lab Environment Management Guide

Comprehensive guide for managing Docker-based penetration testing labs through their full lifecycle: creation, configuration, orchestration, evidence extraction, persistence, and cleanup.

---

## 1. Lab Lifecycle Management

Every lab environment follows a strict lifecycle. Skipping stages leads to resource leaks, stale containers, or lost evidence.

### Lifecycle Stages

```
CREATE → CONFIGURE → SNAPSHOT → OPERATE → EXTRACT → DESTROY
  │         │           │          │          │          │
  │         │           │          │          │          └─ Remove containers, volumes, networks
  │         │           │          │          └─ Copy artifacts, logs, captures to host
  │         │           │          └─ Run pentest exercises against targets
  │         │           └─ Save known-good state for rapid reset
  │         └─ Adjust services, credentials, network topology
  └─ Pull images, build custom Dockerfiles, stand up compose stack
```

### Stage 1: Create

Pull or build all required images before starting the lab. This avoids mid-exercise interruptions from slow image downloads.

```bash
# Pre-pull all images for a lab
docker compose -f docker-compose.lab.yml pull

# Build any custom images
docker compose -f docker-compose.lab.yml build --no-cache

# Start the lab in detached mode
docker compose -f docker-compose.lab.yml up -d
```

Verify all containers are running:

```bash
docker compose -f docker-compose.lab.yml ps
# All services should show "Up" status
```

### Stage 2: Configure

After creation, configure the lab to match the exercise requirements.

```bash
# Set DVWA security level to low (for beginners)
docker exec dvwa-container bash -c \
  "sed -i 's/impossible/low/' /var/www/html/config/config.inc.php"

# Initialize database schema
docker exec dvwa-container bash -c \
  "mysql -u root -p'p@ssw0rd' -e 'source /var/www/html/setup.sql'"

# Verify service is responding
curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8080/
# Expected: 200 or 302
```

### Stage 3: Snapshot

Save the configured state so you can reset quickly after destructive testing.

```bash
# Commit a configured container as a new image
docker commit dvwa-container dvwa-configured:v1

# Tag with date for tracking
docker commit dvwa-container dvwa-configured:$(date +%Y%m%d)

# Export as a portable archive
docker save dvwa-configured:v1 | gzip > dvwa-configured-v1.tar.gz
```

For volume-backed data, snapshot the volume:

```bash
# Create a backup of a named volume
docker run --rm \
  -v lab-data:/source:ro \
  -v $(pwd)/backups:/backup \
  alpine tar czf /backup/lab-data-snapshot.tar.gz -C /source .
```

### Stage 4: Operate

Run pentest exercises. This is where attack skills take over. The lab management concern during this stage is monitoring resource usage and keeping the environment stable.

```bash
# Monitor container resource usage during testing
docker stats --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}"

# Check container logs for crash indicators
docker compose -f docker-compose.lab.yml logs --tail=50 --follow
```

### Stage 5: Extract

Copy evidence out before destroying the lab. See Section 4 for detailed extraction techniques.

### Stage 6: Destroy

Complete cleanup with verification.

```bash
# Stop and remove containers, networks, and volumes
docker compose -f docker-compose.lab.yml down -v --remove-orphans

# Remove custom images built for this lab
docker rmi $(docker images -q --filter "reference=lab-*")

# Verify cleanup
docker ps -a --filter "name=lab-"
# Should return empty
```

---

## 2. Network Topology Design

Different pentest scenarios require different network configurations. Docker provides three main network drivers relevant to security labs.

### Bridge Networks (Default)

Use bridge networks for most lab scenarios. They provide isolation between lab services and the host while allowing inter-container communication.

```yaml
networks:
  pentest-lab:
    driver: bridge
    ipam:
      config:
        - subnet: 172.28.0.0/16
          gateway: 172.28.0.1
```

**Best for**: Web application testing, service enumeration, multi-tier attack chains.

### Host Network

Use host networking when the tool under test needs raw socket access or must see actual host interfaces. This trades isolation for full network visibility.

```yaml
services:
  attacker:
    image: kalilinux/kali-rolling:latest
    network_mode: "host"
    cap_add:
      - NET_ADMIN
      - NET_RAW
```

**Best for**: Network sniffing exercises, ARP spoofing practice, raw packet crafting.

**Warning**: Host networking removes network isolation. Only use for the attacker container, never for vulnerable targets.

### Macvlan Networks

Use macvlan when containers need to appear as physical devices on the LAN. Each container gets its own MAC address and IP on the physical network.

```yaml
networks:
  physical-lab:
    driver: macvlan
    driver_opts:
      parent: eth0
    ipam:
      config:
        - subnet: 192.168.1.0/24
          gateway: 192.168.1.1
          ip_range: 192.168.1.128/25
```

**Best for**: Network discovery exercises, VLAN hopping practice, scenarios requiring ARP visibility.

**Warning**: Macvlan containers cannot communicate with the host by default. This is a known Docker limitation.

### Multi-Network Topology (DMZ Pattern)

Simulate a realistic corporate network with DMZ and internal segments:

```yaml
services:
  # Public-facing web server (DMZ only)
  web-server:
    image: nginx:latest
    networks:
      dmz:
        ipv4_address: 172.29.0.10
    ports:
      - "127.0.0.1:8080:80"

  # Application server (DMZ + Internal)
  app-server:
    image: python:3.11-slim
    networks:
      dmz:
        ipv4_address: 172.29.0.20
      internal:
        ipv4_address: 172.30.0.20

  # Database (Internal only, no external access)
  database:
    image: postgres:15
    networks:
      internal:
        ipv4_address: 172.30.0.30

networks:
  dmz:
    driver: bridge
    ipam:
      config:
        - subnet: 172.29.0.0/24
  internal:
    driver: bridge
    internal: true  # No outbound internet access
    ipam:
      config:
        - subnet: 172.30.0.0/24
```

This topology forces lateral movement through the app server to reach the database -- the web server cannot directly access the internal network.

### Network Debugging

When network connectivity between containers is not working as expected:

```bash
# Inspect network configuration
docker network inspect pentest-lab

# Check which networks a container is connected to
docker inspect --format='{{json .NetworkSettings.Networks}}' <container> | jq

# Test connectivity between containers
docker exec attacker ping -c 3 172.28.0.10
docker exec attacker nmap -sn 172.28.0.0/24

# Trace routing between containers
docker exec attacker traceroute 172.30.0.30
```

---

## 3. Multi-Container Lab Orchestration

Docker Compose is the primary orchestration tool for lab environments. These patterns handle common multi-container lab scenarios.

### Dependency Ordering

Some services need others to be ready before they start. Use `depends_on` with health checks:

```yaml
services:
  database:
    image: mysql:8.0
    environment:
      MYSQL_ROOT_PASSWORD: labpassword
      MYSQL_DATABASE: vulnerable_app
    healthcheck:
      test: ["CMD", "mysqladmin", "ping", "-h", "localhost"]
      interval: 5s
      timeout: 3s
      retries: 10

  web-app:
    image: vulnerables/web-dvwa:latest
    depends_on:
      database:
        condition: service_healthy
    ports:
      - "127.0.0.1:8080:80"
```

### Multi-Compose Lab Stacking

Run multiple vulnerable apps simultaneously by using project names to avoid conflicts:

```bash
# Start web lab on one port range
docker compose -p web-lab -f docker-compose.dvwa.yml up -d

# Start network lab on another range
docker compose -p net-lab -f docker-compose.network-lab.yml up -d

# List all running labs
docker compose ls

# Stop a specific lab
docker compose -p web-lab down -v
```

### Resource Limits

Prevent runaway containers from consuming all host resources:

```yaml
services:
  target:
    image: vulnerables/web-dvwa:latest
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 512M
        reservations:
          cpus: '0.25'
          memory: 128M
```

### Scaling Targets

When practicing enumeration or brute-force techniques, spin up multiple identical targets:

```bash
# Scale a target service to 5 instances
docker compose -f docker-compose.lab.yml up -d --scale target-web=5

# Each instance gets a unique IP on the lab network
docker compose -f docker-compose.lab.yml ps
```

---

## 4. Evidence Extraction from Labs

Every pentest exercise should produce evidence. Extract artifacts before destroying the lab.

### Copy Files from Containers

```bash
# Copy a specific file
docker cp target-container:/var/log/auth.log ./evidence/auth.log

# Copy an entire directory
docker cp target-container:/var/www/html/uploads/ ./evidence/uploads/

# Copy with metadata preservation
docker cp target-container:/etc/shadow ./evidence/shadow
stat ./evidence/shadow  # Verify timestamp
```

### Extract Logs

```bash
# Save all container logs to files
for container in $(docker compose -f docker-compose.lab.yml ps -q); do
  name=$(docker inspect --format='{{.Name}}' $container | sed 's|/||')
  docker logs $container > "./evidence/logs/${name}.log" 2>&1
done

# Save logs with timestamps
docker logs --timestamps target-container > ./evidence/target-timestamps.log 2>&1
```

### Capture Network Traffic

Run a sniffer inside the lab network to capture traffic for later analysis:

```yaml
services:
  # Add to any lab compose file
  packet-capture:
    image: kalilinux/kali-rolling:latest
    command: >
      bash -c "apt-get update && apt-get install -y tcpdump &&
      tcpdump -i any -w /captures/lab-traffic.pcap -Z root"
    volumes:
      - ./evidence/captures:/captures
    networks:
      - lab-net
    cap_add:
      - NET_RAW
      - NET_ADMIN
```

Extract the pcap after the exercise:

```bash
# Stop the capture container gracefully (flushes buffer)
docker stop packet-capture

# Verify the pcap is readable
tcpdump -r ./evidence/captures/lab-traffic.pcap | head -20

# Analyze with tshark
tshark -r ./evidence/captures/lab-traffic.pcap -Y "http" -T fields \
  -e ip.src -e ip.dst -e http.request.uri | head -20
```

### Export Container State

When the container state itself is evidence (e.g., after a successful compromise):

```bash
# Export the full filesystem of a compromised container
docker export target-container > ./evidence/target-filesystem.tar

# Examine without extracting
tar tf ./evidence/target-filesystem.tar | grep -E "(passwd|shadow|\.ssh)"

# Diff against the original image
docker diff target-container
# A = added, C = changed, D = deleted
```

---

## 5. Persistence Strategies

Persist tool configurations, wordlists, and exercise state across lab restarts.

### Named Volumes for Tool Configurations

```yaml
services:
  attacker:
    image: kalilinux/kali-rolling:latest
    volumes:
      - kali-tools:/root/.local        # Tool configs
      - kali-history:/root/.bash_history_vol  # Command history
      - wordlists:/usr/share/wordlists  # Wordlists

volumes:
  kali-tools:
  kali-history:
  wordlists:
```

### Bind Mounts for Shared Resources

Use bind mounts when you need to share files between the host and containers, and you want changes to be immediately visible on both sides.

```yaml
services:
  attacker:
    volumes:
      # Custom scripts accessible in container
      - ./scripts:/opt/scripts:ro
      # Wordlists shared across labs
      - /usr/share/wordlists:/wordlists:ro
      # Evidence output directory
      - ./evidence:/evidence
      # Metasploit resource files
      - ./msf-resources:/root/.msf4/resources:ro
```

### Persistent Metasploit Database

Metasploit session data is valuable. Persist it across lab restarts:

```yaml
services:
  msf-db:
    image: postgres:15-alpine
    environment:
      POSTGRES_USER: msf
      POSTGRES_PASSWORD: msf_password
      POSTGRES_DB: msf_database
    volumes:
      - msf-pgdata:/var/lib/postgresql/data
    networks:
      - lab-net

  attacker:
    image: kalilinux/kali-rolling:latest
    environment:
      MSF_DATABASE_CONFIG: /root/.msf4/database.yml
    volumes:
      - msf-data:/root/.msf4
    depends_on:
      - msf-db
    networks:
      - lab-net

volumes:
  msf-pgdata:
  msf-data:
```

### Volume Backup and Restore

```bash
# Backup a named volume
docker run --rm \
  -v kali-tools:/source:ro \
  -v $(pwd)/backups:/backup \
  alpine tar czf /backup/kali-tools-$(date +%Y%m%d).tar.gz -C /source .

# Restore a named volume
docker run --rm \
  -v kali-tools:/target \
  -v $(pwd)/backups:/backup:ro \
  alpine sh -c "cd /target && tar xzf /backup/kali-tools-20260522.tar.gz"
```

---

## 6. Pre-Built Vulnerable Labs

Recipes for standing up commonly used vulnerable environments.

### DVWA (Damn Vulnerable Web Application)

```bash
# Quick start
docker run --rm -d \
  --name dvwa \
  -p 127.0.0.1:8080:80 \
  vulnerables/web-dvwa:latest

# Access: http://127.0.0.1:8080
# Login: admin / password
# First visit: click "Create / Reset Database"
```

**Covers**: SQL Injection, XSS (Reflected/Stored/DOM), CSRF, Command Injection, File Inclusion, File Upload, Brute Force, Weak Session IDs, Insecure CAPTCHA.

### OWASP Juice Shop

```bash
docker run --rm -d \
  --name juice-shop \
  -p 127.0.0.1:3000:3000 \
  bkimminich/juice-shop:latest

# Access: http://127.0.0.1:3000
# Score board: http://127.0.0.1:3000/#/score-board
```

**Covers**: Full OWASP Top 10, API security, JWT attacks, NoSQL injection, XXE, SSRF, broken access control. Over 100 challenges with difficulty ratings.

### OWASP WebGoat

```bash
docker run --rm -d \
  --name webgoat \
  -p 127.0.0.1:8080:8080 \
  -p 127.0.0.1:9090:9090 \
  -e TZ=UTC \
  webgoat/webgoat

# WebGoat: http://127.0.0.1:8080/WebGoat
# WebWolf: http://127.0.0.1:9090/WebWolf
# Register a new account on first visit
```

**Covers**: Injection flaws, authentication flaws, access control, XXE, deserialization, vulnerable components, request forgery, client-side issues. Includes guided lessons.

### VulnHub-Style Images

Many VulnHub machines have been containerized. Search Docker Hub for them:

```bash
# Search for vulnerable practice images
docker search vulnerable --limit 25
docker search ctf --limit 25

# Popular options
docker run --rm -d -p 127.0.0.1:8081:80 citizenstig/nowasp       # Mutillidae
docker run --rm -d -p 127.0.0.1:8082:80 hmlio/vaas-cve-2014-6271 # Shellshock
docker run --rm -d -p 127.0.0.1:8083:80 opendns/security-ninjas  # Security Ninjas
```

### Full Lab Stack (All-In-One)

Run multiple vulnerable apps behind a single compose file:

```yaml
# docker-compose.full-lab.yml
version: '3.8'
services:
  dvwa:
    image: vulnerables/web-dvwa:latest
    ports:
      - "127.0.0.1:8080:80"
    restart: unless-stopped

  juice-shop:
    image: bkimminich/juice-shop:latest
    ports:
      - "127.0.0.1:3000:3000"
    restart: unless-stopped

  webgoat:
    image: webgoat/webgoat
    ports:
      - "127.0.0.1:8081:8080"
      - "127.0.0.1:9090:9090"
    environment:
      - TZ=UTC
    restart: unless-stopped

  mutillidae:
    image: citizenstig/nowasp
    ports:
      - "127.0.0.1:8082:80"
    restart: unless-stopped
```

```bash
# Start everything
docker compose -f docker-compose.full-lab.yml up -d

# Check all services
docker compose -f docker-compose.full-lab.yml ps

# Stop everything and clean up
docker compose -f docker-compose.full-lab.yml down -v
```

---

## 7. Lab Cleanup and Resource Management

### Routine Cleanup

Run after every lab session:

```bash
# Stop and remove lab containers and volumes
docker compose -f docker-compose.lab.yml down -v --remove-orphans

# Remove dangling images (untagged build artifacts)
docker image prune -f

# Remove unused networks
docker network prune -f
```

### Deep Cleanup

Run periodically or when disk space is low:

```bash
# Remove ALL stopped containers, unused networks, dangling images, and build cache
docker system prune -f

# Include unused volumes (WARNING: destroys persistent data)
docker system prune -f --volumes

# Check disk usage before and after
docker system df
```

### Resource Monitoring

```bash
# Real-time resource usage
docker stats --no-stream

# Disk usage breakdown
docker system df -v

# Find the largest images
docker images --format "{{.Repository}}:{{.Tag}}\t{{.Size}}" | sort -k2 -h -r | head -10

# Find the largest volumes
docker volume ls -q | xargs -I{} docker volume inspect {} --format '{{.Name}}: {{.Mountpoint}}' | \
  while read line; do
    name=$(echo $line | cut -d: -f1)
    path=$(echo $line | cut -d: -f2 | xargs)
    size=$(du -sh "$path" 2>/dev/null | cut -f1)
    echo "$name: $size"
  done
```

### Automated Lab Timeout

Prevent forgotten labs from consuming resources indefinitely:

```bash
#!/bin/bash
# lab-timeout.sh - Kill labs running longer than MAX_HOURS
MAX_HOURS=4

docker ps --format '{{.Names}}\t{{.RunningFor}}' | while read name runtime; do
  hours=$(echo "$runtime" | grep -oP '\d+(?= hours?)' || echo 0)
  if [ "$hours" -ge "$MAX_HOURS" ]; then
    echo "Stopping stale lab container: $name (running $hours hours)"
    docker stop "$name"
  fi
done
```

---

## 8. Troubleshooting Common Issues

### Port Conflicts

```bash
# Symptom: "Bind for 0.0.0.0:8080 failed: port is already allocated"

# Find what is using the port
lsof -i :8080
# or
ss -tlnp | grep 8080

# Resolution: stop the conflicting process or use a different port
docker compose -f docker-compose.lab.yml down
# Edit compose file to use a different port, then restart
```

### Container Fails to Start

```bash
# Check container logs for the crash reason
docker logs <container-name> 2>&1 | tail -30

# Check if the image exists locally
docker images | grep <image-name>

# Re-pull a potentially corrupted image
docker pull <image-name>

# Run interactively to debug
docker run --rm -it <image-name> /bin/bash
```

### Network Connectivity Between Containers

```bash
# Verify containers are on the same network
docker network inspect lab-net --format '{{range .Containers}}{{.Name}} {{.IPv4Address}}{{"\n"}}{{end}}'

# Test DNS resolution between containers
docker exec attacker nslookup target-web

# Test raw connectivity
docker exec attacker ping -c 3 target-web
docker exec attacker nc -zv target-web 80
```

### Volume Permission Issues

```bash
# Symptom: "Permission denied" when writing to mounted volume

# Check the UID inside the container
docker exec <container> id

# Fix: set the volume ownership
docker exec <container> chown -R $(id -u):$(id -g) /mounted/path

# Alternative: run the container with matching UID
docker run --user $(id -u):$(id -g) ...
```

### Out of Disk Space

```bash
# Symptom: "no space left on device"

# Check Docker disk usage
docker system df

# Quick fix: prune unused resources
docker system prune -f

# Nuclear option: prune everything including volumes
docker system prune -f --volumes

# Check host disk space
df -h /var/lib/docker
```

### Containers Cannot Reach the Internet

```bash
# Symptom: apt update fails inside container

# Check if the network is marked as internal
docker network inspect lab-net | jq '.[0].Internal'
# If true, containers on this network cannot reach the internet

# Resolution: use a non-internal network for the container that needs internet
# or temporarily connect it to the bridge network
docker network connect bridge <container-name>

# After installing packages, disconnect
docker network disconnect bridge <container-name>
```

### Lab State Corruption

When a lab enters an inconsistent state after a crash or forced shutdown:

```bash
# Full teardown and rebuild
docker compose -f docker-compose.lab.yml down -v --remove-orphans
docker compose -f docker-compose.lab.yml up -d --force-recreate

# If a snapshot exists, restore from it
docker load < dvwa-configured-v1.tar.gz
docker tag dvwa-configured:v1 vulnerables/web-dvwa:latest
docker compose -f docker-compose.lab.yml up -d --force-recreate
```

---

## Integration Notes

This guide supports the lab lifecycle described in `skills/docker-patterns/SKILL.md`. The create-configure-snapshot-operate-extract-destroy lifecycle integrates with:

- **terminal-ops**: Evidence extraction commands produce artifacts compatible with the evidence capture protocol
- **verification-loop**: Labs provide controlled targets for tool verification
- **autonomous-loops**: Disposable labs (Pattern 4) enable rapid test-destroy cycles
- **safety-guard**: All port bindings use `127.0.0.1` to enforce localhost-only access
