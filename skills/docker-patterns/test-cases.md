# Docker Patterns — Test Cases

> Structured test scenarios for Docker lab setup, operation, evidence extraction, and cleanup.

---

## TC-DP-001: Vulnerable Web App Lab Deployment

### Scenario
Deploy a complete web application security testing lab with DVWA, SQLi-Labs, and Juice Shop for practicing OWASP Top 10 vulnerabilities.

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
