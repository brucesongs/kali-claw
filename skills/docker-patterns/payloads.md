# Docker Patterns — Payloads & Commands

> Companion to `SKILL.md`. Contains Docker lab startup commands, additional lab configurations, evidence extraction patterns, and cleanup commands for security testing environments.

---

## Quick Start Checklist

```
1. Create lab network → 2. Start targets → 3. Start attacker → 4. Test → 5. Extract evidence → 6. Cleanup
```

---

## Quick Launch Commands

### One-Liner Lab Startup

```bash
# DVWA (SQLi, XSS, CSRF, LFI, Command Injection)
docker run --rm -d --name dvwa -p 127.0.0.1:8080:80 vulnerables/web-dvwa:latest

# SQLi Labs (Error-based, Blind, UNION, Time-based SQLi)
docker run --rm -d --name sqli-labs -p 127.0.0.1:8081:80 acgpiano/sqli-labs:latest

# OWASP Juice Shop (Full OWASP Top 10)
docker run --rm -d --name juice-shop -p 127.0.0.1:8082:3000 bkimminich/juice-shop:latest

# Vulnerable SSH
docker run --rm -d --name ssh-target -p 127.0.0.1:2222:22 rastasheep/ubuntu-sshd:18.04

# Vulnerable FTP
docker run --rm -d --name ftp-target -p 127.0.0.1:2121:21 stilliard/pure-ftpd:latest
```

### Batch Lab Startup

```bash
# Start all web labs at once
docker run --rm -d --name dvwa -p 127.0.0.1:8080:80 vulnerables/web-dvwa:latest && \
docker run --rm -d --name sqli-labs -p 127.0.0.1:8081:80 acgpiano/sqli-labs:latest && \
docker run --rm -d --name juice-shop -p 127.0.0.1:8082:3000 bkimminich/juice-shop:latest && \
echo "Labs running: DVWA(:8080) SQLi-Labs(:8081) JuiceShop(:8082)"
```

---

## Additional Lab Configurations

### WordPress Pentest Lab

```yaml
# docker-compose.wordpress.yml
version: '3.8'
services:
  wordpress:
    image: wordpress:6.0
    ports:
      - "127.0.0.1:8090:80"
    environment:
      - WORDPRESS_DB_HOST=db
      - WORDPRESS_DB_USER=wp_user
      - WORDPRESS_DB_PASSWORD=weakpass123
      - WORDPRESS_DB_NAME=wordpress
    networks:
      - wp-net
    depends_on:
      - db

  db:
    image: mysql:5.7
    environment:
      - MYSQL_DATABASE=wordpress
      - MYSQL_USER=wp_user
      - MYSQL_PASSWORD=weakpass123
      - MYSQL_ROOT_PASSWORD=rootpass123
    networks:
      - wp-net

  attacker:
    image: kalilinux/kali-rolling:latest
    networks:
      - wp-net
    command: tail -f /dev/null

networks:
  wp-net:
    driver: bridge
```

**Practice targets:** WP plugin exploitation, XML-RPC attacks, REST API enumeration, wp-admin brute force

### API Security Lab

```yaml
# docker-compose.api-lab.yml
version: '3.8'
services:
  vulnerable-api:
    image: mcybertop/vulnerable-rest-api:latest
    ports:
      - "127.0.0.1:8091:8080"
    networks:
      - api-net

  crapi:
    image: crapi/crapi-community:latest
    ports:
      - "127.0.0.1:8092:8888"
      - "127.0.0.1:8093:8025"
    networks:
      - api-net

networks:
  api-net:
    driver: bridge
```

**Practice targets:** IDOR, JWT attacks, GraphQL injection, API rate limiting bypass, mass assignment

### Active Directory Lab

```yaml
# docker-compose.ad-lab.yml
version: '3.8'
services:
  # Lightweight alternative: Samba-based AD
  samba-dc:
    image: instantlinux/samba-dc:latest
    hostname: dc1
    ports:
      - "127.0.0.1:53:53"
      - "127.0.0.1:88:88"
      - "127.0.0.1:389:389"
      - "127.0.0.1:445:445"
    environment:
      - DOMAIN=lab.local
      - ADMINPASS=P@ssw0rd
    networks:
      - ad-net

  attacker:
    image: kalilinux/kali-rolling:latest
    networks:
      - ad-net
    command: tail -f /dev/null
    cap_add:
      - NET_ADMIN

networks:
  ad-net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.31.0.0/16
```

**Practice targets:** Kerberos attacks, LDAP enumeration, SMB relay, BloodHound collection

---

## Evidence Extraction Commands

### Container State Capture

```bash
# Capture running container info
docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}" | tee evidence/containers.txt

# Inspect container configuration
docker inspect <container_name> | jq '.' > evidence/<container_name>-inspect.json

# Capture container logs
docker logs <container_name> 2>&1 | tee evidence/<container_name>-logs.txt

# Capture container resource usage
docker stats --no-stream | tee evidence/container-stats.txt
```

### Network Traffic Capture

```bash
# Capture traffic on lab network bridge
sudo tcpdump -i br-<network_id> -w evidence/lab-traffic.pcap

# Capture HTTP traffic to file
sudo tcpdump -i br-<network_id> -A -s 0 'tcp port 80' | tee evidence/http-traffic.txt

# Extract container IPs
docker network inspect <network_name> | jq '.[].Containers[] | {Name: .Name, IP: .IPv4Address}'
```

### Volume/File Extraction

```bash
# Copy evidence from container
docker cp <container_name>:/var/log/auth.log evidence/auth.log
docker cp <container_name>:/var/log/apache2/access.log evidence/access.log

# Export container filesystem (for offline analysis)
docker export <container_name> | gzip > evidence/<container_name>-filesystem.tar.gz

# Diff container filesystem from base image
docker diff <container_name>
```

---

## Attacker Container Setup

### Kali Attacker with Tools

```bash
# Build attacker container with common tools
docker run --rm -it --name attacker \
  --network=host \
  -v $(pwd)/evidence:/evidence \
  kalilinux/kali-rolling:latest \
  bash -c "apt update && apt install -y \
    nmap \
    sqlmap \
    nikto \
    gobuster \
    dirb \
    ffuf \
    hydra \
    burpsuite \
    metasploit-framework \
    bloodhound \
    crackmapexec \
    impacket-scripts \
    responder \
    seclists \
    wordlists \
    && bash"
```

### Lightweight Attacker (Fast Setup)

```bash
# Minimal attacker with essential tools
docker run --rm -it --name attacker \
  --network=host \
  -v $(pwd)/evidence:/evidence \
  kalilinux/kali-rolling:latest \
  bash -c "apt update && apt install -y nmap curl jq python3-pip netcat-openbsd && bash"
```

---

## Cleanup Commands

### Single Lab Cleanup

```bash
# Stop and remove specific lab containers
docker stop dvwa sqli-labs juice-shop 2>/dev/null
docker rm dvwa sqli-labs juice-shop 2>/dev/null
echo "Lab containers removed"
```

### Full Lab Cleanup

```bash
# Stop all lab containers (named with common lab ports)
docker ps --filter "publish=8080" --filter "publish=8081" --filter "publish=8082" \
  --filter "publish=8090" --filter "publish=8091" --filter "publish=8092" \
  -q | xargs -r docker stop

# Remove all stopped containers
docker container prune -f

# Remove lab networks
docker network prune -f

# Remove dangling images
docker image prune -f

echo "Full cleanup complete"
```

### Docker Compose Cleanup

```bash
# Stop and remove compose stack with volumes
docker compose -f docker-compose.lab.yml down -v --rmi local

# Nuclear cleanup (everything non-running)
docker system prune -af --volumes
```

---

## Safety Verification Commands

```bash
# Verify no lab services bound to public interfaces
docker ps --format "{{.Ports}}" | grep -v "127.0.0.1" && echo "WARNING: Public bindings detected!" || echo "OK: All services on localhost"

# Check for exposed ports
ss -tlnp | grep -E ":(8080|8081|8082|8090|8091|8092|2222|2121) "

# Verify lab network isolation
docker network ls --filter "name=lab" --format "{{.Name}}"
```
