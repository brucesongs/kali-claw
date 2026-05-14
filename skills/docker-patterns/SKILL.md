# Docker Patterns for Security Testing

> **Supplementary Files**:
> - `payloads.md` — Quick launch commands, additional lab configurations, evidence extraction patterns, and cleanup commands
> - `test-cases.md` — Structured test cases for lab deployment, attack chain setup, evidence extraction, and safety verification

Pre-built Docker Compose configurations for safe, isolated security testing labs. Provides standardized environments for practicing and verifying attack techniques without affecting production systems.

## Activation

- Setting up a practice lab for penetration testing techniques
- Creating isolated environments for exploit development and testing
- Building vulnerable application targets for training
- Testing tools against known-vulnerable configurations
- User says "lab", "docker lab", "test environment", "practice target"

## Core Principle

**Never test attack techniques against systems you don't own or have explicit authorization to test.** Docker labs provide safe, legal environments for security practice and tool validation.

All lab environments bind to `127.0.0.1` only — never expose on public interfaces.

## Pattern 1: Vulnerable Web App Lab

### DVWA (Damn Vulnerable Web Application)

```yaml
# docker-compose.dvwa.yml
version: '3.8'
services:
  dvwa:
    image: vulnerables/web-dvwa:latest
    ports:
      - "127.0.0.1:8080:80"
    environment:
      - DB_PASSWORD=p@ssw0rd
    restart: unless-stopped
```

**Practice targets:** SQL injection, XSS, CSRF, Command Injection, File Upload, LFI/RFI

### SQLi-Labs

```yaml
# docker-compose.sqli-labs.yml
version: '3.8'
services:
  sqli-labs:
    image: acgpiano/sqli-labs:latest
    ports:
      - "127.0.0.1:8081:80"
    restart: unless-stopped
```

**Practice targets:** Error-based SQLi, Blind SQLi, UNION-based SQLi, Time-based SQLi

### OWASP Juice Shop

```yaml
# docker-compose.juice-shop.yml
version: '3.8'
services:
  juice-shop:
    image: bkimminich/juice-shop:latest
    ports:
      - "127.0.0.1:8082:3000"
    restart: unless-stopped
```

**Practice targets:** Full OWASP Top 10 coverage, API security, XSS, JWT attacks, access control

## Pattern 2: Network Pentest Lab

### Multi-Service Network Lab

```yaml
# docker-compose.network-lab.yml
version: '3.8'
services:
  # Target: Vulnerable SSH server
  target-ssh:
    image: rastasheep/ubuntu-sshd:18.04
    ports:
      - "127.0.0.1:2222:22"
    networks:
      - lab-net

  # Target: Vulnerable FTP server
  target-ftp:
    image: stilliard/pure-ftpd:latest
    ports:
      - "127.0.0.1:2121:21"
      - "127.0.0.1:30000-30009:30000-30009"
    environment:
      - PUBLICHOST=localhost
    networks:
      - lab-net

  # Target: Web server with vulnerabilities
  target-web:
    image: php:8.1-apache
    ports:
      - "127.0.0.1:8083:80"
    volumes:
      - ./vulnerable-app:/var/www/html
    networks:
      - lab-net

  # Attacker machine (Kali tools)
  attacker:
    image: kalilinux/kali-rolling:latest
    networks:
      - lab-net
    command: tail -f /dev/null  # Keep alive
    cap_add:
      - NET_ADMIN

networks:
  lab-net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.28.0.0/16
```

**Practice targets:** Network enumeration, service identification, SSH brute force, FTP attacks, web app attacks

## Pattern 3: Multi-Stage Attack Chain Lab

Simulates a realistic attack chain across multiple vulnerable services:

```yaml
# docker-compose.attack-chain.yml
version: '3.8'
services:
  # Stage 1: External-facing web app (initial access)
  web-frontend:
    build: ./scenarios/web-frontend
    ports:
      - "127.0.0.1:9000:80"
    networks:
      - dmz
    depends_on:
      - web-api

  # Stage 2: Internal API (lateral movement target)
  web-api:
    build: ./scenarios/web-api
    ports:
      - "127.0.0.1:9001:8080"
    networks:
      - dmz
      - internal
    environment:
      - DB_HOST=database
      - DB_PASS=weakpassword123

  # Stage 3: Database (data target)
  database:
    image: mysql:5.7
    networks:
      - internal
    environment:
      - MYSQL_ROOT_PASSWORD=weakpassword123
      - MYSQL_DATABASE=secrets
    volumes:
      - ./scenarios/db-init:/docker-entrypoint-initdb.d

  # Stage 4: Internal admin panel (privilege escalation)
  admin-panel:
    build: ./scenarios/admin-panel
    networks:
      - internal
    environment:
      - ADMIN_USER=admin
      - ADMIN_PASS=admin123

networks:
  dmz:
    driver: bridge
    ipam:
      config:
        - subnet: 172.29.0.0/16
  internal:
    driver: bridge
    ipam:
      config:
        - subnet: 172.30.0.0/16
    internal: true  # No external access
```

**Practice targets:** Multi-stage exploitation, lateral movement, privilege escalation, data exfiltration

## Pattern 4: Disposable Testing

Quick spin-up for single-tool testing:

```bash
# One-liner for testing a specific tool against a specific image
docker run --rm -it --network=host kalilinux/kali-rolling:latest \
  bash -c "apt update && apt install -y nmap && nmap -sV 127.0.0.1"

# Temporary vulnerable target
docker run --rm -d -p 127.0.0.1:9999:80 vulnerables/web-dvwa:latest

# Test and destroy
docker stop $(docker ps -q --filter publish=9999)
```

**Rules:**
- Always use `--rm` for auto-cleanup
- Always bind to `127.0.0.1`
- Never persist sensitive data from test containers

## Pattern 5: Tool Testing Environment

Validate tool behavior against known-vulnerable targets:

```yaml
# docker-compose.tool-test.yml
version: '3.8'
services:
  # Known-vulnerable target for tool calibration
  target:
    image: vulnerables/web-dvwa:latest
    ports:
      - "127.0.0.1:9090:80"

  # Tool under test
  tool-test:
    image: kalilinux/kali-rolling:latest
    network_mode: "host"
    command: tail -f /dev/null
    volumes:
      - ./test-results:/results
```

## Safety Rules

1. **Bind to localhost only** — All port mappings use `127.0.0.1:port:container_port`
2. **No persistent sensitive data** — Use `--rm` or anonymous volumes
3. **Isolated networks** — Lab networks should not overlap with production
4. **Resource limits** — Set memory and CPU limits to prevent runaway containers
5. **Cleanup after use** — `docker compose down -v` to remove containers and volumes

```bash
# Full cleanup
docker compose -f docker-compose.lab.yml down -v --rmi local
docker system prune -f
```

## Integration with Other Skills

| Skill | Docker Pattern | Application |
|-------|---------------|-------------|
| `web-sqli` | Pattern 1 (DVWA/SQLi-Labs) | Practice SQL injection techniques safely |
| `web-xss` | Pattern 1 (DVWA/Juice Shop) | Practice XSS payload crafting |
| `web-auth-bypass` | Pattern 1 (Juice Shop) | Practice authentication attack techniques |
| `network-pentest` | Pattern 2 (Network Lab) | Practice network enumeration and service exploitation |
| `post-exploitation` | Pattern 3 (Attack Chain) | Practice lateral movement and privilege escalation |
| `verification-loop` | Pattern 5 (Tool Test) | Verify tool accuracy against known vulnerabilities |
| `autonomous-loops` | Pattern 4 (Disposable) | Quick test loops against disposable targets |
| `terminal-ops` | All patterns | Evidence protocol for all lab activities |

## Quick Start

```bash
# Start DVWA lab
cd ~/.openclaw/workspace-kali-claw/skills/docker-patterns/
docker compose -f configs/docker-compose.dvwa.yml up -d

# Access DVWA
# http://127.0.0.1:8080 (admin/password)

# Stop and clean up
docker compose -f configs/docker-compose.dvwa.yml down -v
```

## Anti-Patterns

- **Binding to 0.0.0.0** — Never expose lab services on all interfaces
- **Using default passwords in production** — Lab passwords stay in the lab
- **Running without resource limits** — Containers can consume all host resources
- **Mixing lab and production networks** — Keep lab traffic isolated
- **Skipping cleanup** — Always remove containers and volumes after testing

## Orchestration

### ECC Loop Pattern
- **Pattern**: Sequential Pipeline (create lab → deploy → test → extract evidence → cleanup)
- **Rationale**: Lab environments follow a strict lifecycle — each phase must complete before the next begins, and cleanup is mandatory
- **Integration**: All security skills that need practice environments (web-sqli, web-xss, network-pentest, post-exploitation), terminal-ops (evidence capture), safety-guard (localhost-only enforcement)

### Cross-Skill Pipeline
```
docker-patterns → [any attack skill] → verification-loop → terminal-ops (evidence)
       ↓                                                          ↑
  safety-guard (verify isolation)                autonomous-loops (disposable targets)
```

### Quality Gate
- Pre-condition: Docker available, ports free, no public interface bindings
- Post-condition: All containers removed, all volumes cleaned, no ports listening
- Verification: `docker ps` returns empty, no lab ports in `ss -tlnp`
