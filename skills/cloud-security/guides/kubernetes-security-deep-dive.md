# Kubernetes Security Deep Dive

## Learning Objectives

Master the Kubernetes attack surface from control plane to workloads, perform comprehensive RBAC audits, enforce pod security standards, test network policies, and assess secrets management and admission controller configurations.

---

## 1. K8s Attack Surface Overview

### 1.1 Control Plane Components

The Kubernetes control plane exposes several high-value targets:

- **API Server** (port 6443) -- The central management hub. All operations flow through the API server, making it the primary attack target. Exposed to authenticated and unauthenticated requests depending on configuration.
- **etcd** (port 2379) -- The cluster's persistent state store. Contains all cluster data including secrets. Direct access to etcd is equivalent to root access to the entire cluster.
- **Scheduler** -- Determines pod placement. Less directly exploitable but can be targeted to influence workload distribution.
- **Controller Manager** -- Runs control loops. Compromised controller manager can modify any cluster resource.

```bash
# Enumerate API server information
kubectl version --output yaml
kubectl cluster-info
kubectl get --raw /healthz
kubectl get --raw /livez
kubectl get --raw /readyz

# Check API server flags for security misconfigurations
# Look for: --anonymous-auth=true, --insecure-port, --insecure-bind-address
ps aux | grep kube-apiserver

# Check etcd access (should be restricted)
# From a control plane node:
ETCDCTL_API=3 etcdctl --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key \
  get / --prefix --keys-only
```

### 1.2 Worker Node Components

- **kubelet** (port 10250) -- The node agent. Each node runs a kubelet that manages pods. If the kubelet API is exposed without authentication, an attacker can execute commands in any pod on that node.
- **kube-proxy** -- Manages network rules on nodes. Compromise allows traffic manipulation.
- **Container Runtime** (containerd, CRI-O) -- The runtime executes containers. Runtime vulnerabilities can lead to container escape.

```bash
# Check kubelet exposure (from within cluster network)
curl -k https://<node-ip>:10250/pods
curl -k https://<node-ip>:10250/runningpods

# Check kubelet anonymous access
curl -k https://<node-ip>:10250/exec/<namespace>/<pod>/<container>?command=/bin/sh&command=-c&command=cat+/etc/shadow&stdout=1&stderr=1

# Enumerate kubelet config
curl -k https://<node-ip>:10250/configz

# Check for readonly port (10255 - deprecated but still found)
curl http://<node-ip>:10255/pods
```

### 1.3 Network Model

- **CNI Plugins** -- Calico, Flannel, Cilium, Weave. Each has different security capabilities (network policy support, eBPF filtering).
- **Service Types** -- ClusterIP, NodePort, LoadBalancer, ExternalName. NodePort and LoadBalancer expose services externally.
- **Ingress** -- HTTP/HTTPS routing. Misconfigured ingress controllers can expose internal services or allow path traversal.

```bash
# Enumerate services looking for external exposure
kubectl get svc --all-namespaces -o wide
kubectl get svc --all-namespaces -o json | jq '.items[] | select(.spec.type=="NodePort" or .spec.type=="LoadBalancer")'

# Check ingress resources
kubectl get ingress --all-namespaces
kubectl get ingress --all-namespaces -o yaml | grep -A5 "tls:"

# Check CNI configuration
ls /etc/cni/net.d/
cat /etc/cni/net.d/*.conflist
```

---

## 2. RBAC Audit Deep Dive

### 2.1 Enumerating Roles and ClusterRoles

```bash
# List all Roles across namespaces
kubectl get roles --all-namespaces -o wide

# List all ClusterRoles
kubectl get clusterroles -o wide

# Get detailed Role definitions
kubectl get role -n kube-system -o yaml

# Find roles with wildcard permissions
kubectl get clusterroles -o json | jq '.items[] | select(.rules[]? | (.resources // [] | contains(["*"])) or (.verbs // [] | contains(["*"]))) | .metadata.name'

# Check bindings for each role
kubectl get rolebindings --all-namespaces -o wide
kubectl get clusterrolebindings -o wide

# Map service accounts to permissions
kubectl get serviceaccounts --all-namespaces
kubectl get serviceaccounts -n kube-system -o json | jq '.items[] | .metadata.name + " -> " + (.automountServiceAccountToken | tostring)'
```

### 2.2 Identifying Overprivileged Service Accounts

```bash
# Find service accounts with cluster-admin binding
kubectl get clusterrolebindings -o json | jq '.items[] | select(.subjects[]? | .kind=="ServiceAccount") | select(.roleRef.name=="cluster-admin") | .subjects[].name'

# List all permissions for a specific service account
kubectl auth can-i --list --as=system:serviceaccount:<namespace>:<sa-name>

# Check what a service account can do with secrets
kubectl auth can-i --list --as=system:serviceaccount:default:default | grep secret

# Enumerate all service account tokens
kubectl get secrets --all-namespaces -o json | jq '.items[] | select(.type=="kubernetes.io/service-account-token") | .metadata.name + " (ns: " + .metadata.namespace + ")"'
```

### 2.3 Checking for Wildcard Permissions

```bash
# Find roles granting all verbs on all resources
kubectl get clusterroles -o json | jq '.items[] | select(.rules[]? | .verbs == ["*"] and .resources == ["*"]) | .metadata.name'

# Find roles with dangerous verb-resource combinations
kubectl get clusterroles -o json | jq '.items[] | select(.rules[]? | (.verbs // [] | contains(["create", "delete"])) and (.resources // [] | contains(["pods", "secrets", "nodes"]))) | .metadata.name'

# Check for impersonation permissions (critical escalation path)
kubectl get clusterrolebindings -o json | jq '.items[] | select(.roleRef.name | test("impersonat")) | .subjects[].name'
```

### 2.4 Privilege Escalation Paths Through RBAC

Common escalation paths:

1. **create pods** -- Can mount secrets, use privileged containers, access host resources
2. **create pods/exec** -- Can execute commands in any pod, access mounted secrets
3. **get/list secrets** -- Direct secret theft including service account tokens
4. **escalate/bind** -- Can bind higher-privileged roles to themselves
5. **impersonate** -- Can become any user including cluster-admin

```bash
# Check if current user can escalate privileges
kubectl auth can-i create clusterrolebindings
kubectl auth can-i escalate roles
kubectl auth can-i bind roles
kubectl auth can-i impersonate users

# Using kubectl-who-can (install: kubectl krew install who-can)
kubectl who-can create pods
kubectl who-can get secrets
kubectl who-can create pods/exec

# Using rakkess (install: kubectl krew install rakkess)
kubectl rakkess --as=system:serviceaccount:default:default
kubectl rakkess -n kube-system
```

---

## 3. Pod Security

### 3.1 Pod Security Standards

Three privilege levels defined by Kubernetes:

- **Privileged** -- Unrestricted. Used for system pods that need host access.
- **Baseline** -- Minimally restrictive. Prevents known privilege escalations.
- **Restricted** -- Heavily restricted. Follows security hardening best practices.

```bash
# Check current pod security admission labels on namespaces
kubectl get namespaces -o json | jq '.items[] | {name: .metadata.name, labels: .metadata.labels} | select(.labels["pod-security.kubernetes.io/enforce"] != null)'

# Audit pods against pod security standards using kubeaudit
kubeaudit all -n default
kubeaudit autoattach -n kube-system

# Check for privileged containers
kubectl get pods --all-namespaces -o json | jq '.items[] | select(.spec.containers[]?.securityContext?.privileged == true) | .metadata.name + " (ns: " + .metadata.namespace + ")"'

# Find pods running as root
kubectl get pods --all-namespaces -o json | jq '.items[] | select(.spec.containers[]?.securityContext?.runAsUser == 0 or (.spec.securityContext?.runAsUser == 0)) | .metadata.name'
```

### 3.2 Pod Security Admission vs PSP

Pod Security Policies (PSP) were removed in K8s 1.25. Pod Security Admission (PSA) replaces them:

```bash
# Check PSA configuration on namespaces
kubectl get namespaces -o json | jq '.items[] | {name: .metadata.name, enforce: .metadata.labels["pod-security.kubernetes.io/enforce"], audit: .metadata.labels["pod-security.kubernetes.io/audit"], warn: .metadata.labels["pod-security.kubernetes.io/warn"]}'

# Set PSA labels on a namespace
kubectl label namespace default pod-security.kubernetes.io/enforce=restricted
kubectl label namespace default pod-security.kubernetes.io/audit=restricted
kubectl label namespace default pod-security.kubernetes.io/warn=restricted

# Check if any namespace lacks PSA labels
kubectl get namespaces -o json | jq '.items[] | select(.metadata.labels["pod-security.kubernetes.io/enforce"] == null) | .metadata.name'
```

### 3.3 Container Escape Vectors

```bash
# Find privileged containers (direct escape path)
kubectl get pods --all-namespaces -o json | jq '.items[] | select(.spec.containers[]?.securityContext?.privileged == true) | .metadata.name'

# Find pods with hostPath mounts (file system escape)
kubectl get pods --all-namespaces -o json | jq '.items[] | select(.spec.volumes[]?.hostPath != null) | {name: .metadata.name, hostPaths: [.spec.volumes[]?.hostPath.path]}'

# Find pods with hostPID (process namespace escape)
kubectl get pods --all-namespaces -o json | jq '.items[] | select(.spec.hostPID == true) | .metadata.name'

# Find pods with hostNetwork (network namespace escape)
kubectl get pods --all-namespaces -o json | jq '.items[] | select(.spec.hostNetwork == true) | .metadata.name'

# Find pods with hostIPC
kubectl get pods --all-namespaces -o json | jq '.items[] | select(.spec.hostIPC == true) | .metadata.name'

# Comprehensive escape vector scan
kubectl get pods --all-namespaces -o json | jq '.items[] | select(
  (.spec.containers[]?.securityContext?.privileged == true) or
  (.spec.hostPID == true) or
  (.spec.hostNetwork == true) or
  (.spec.volumes[]?.hostPath != null) or
  (.spec.containers[]?.securityContext?.capabilities?.add | test("SYS_ADMIN|SYS_PTRACE|NET_ADMIN|DAC_OVERRIDE"))
) | .metadata.name + " (ns: " + .metadata.namespace + ")"'
```

### 3.4 Security Context Analysis

```bash
# Find containers NOT running as non-root
kubectl get pods --all-namespaces -o json | jq '.items[] | select(
  (.spec.containers[]?.securityContext?.runAsNonRoot != true) and
  (.spec.securityContext?.runAsNonRoot != true)
) | .metadata.name' | head -20

# Find containers with writable root filesystem
kubectl get pods --all-namespaces -o json | jq '.items[] | select(.spec.containers[]?.securityContext?.readOnlyRootFilesystem != true) | .metadata.name' | head -20

# Enumerate all capabilities in use
kubectl get pods --all-namespaces -o json | jq '.items[].spec.containers[]?.securityContext?.capabilities?.add[]?' | sort -u

# Find containers with dangerous capabilities
kubectl get pods --all-namespaces -o json | jq '.items[] | select(.spec.containers[]?.securityContext?.capabilities?.add | test("SYS_ADMIN|SYS_PTRACE|SYS_CHROOT|NET_ADMIN|DAC_OVERRIDE|DAC_READ_SEARCH|FOWNER|SETUID|SETGID")) | .metadata.name'
```

---

## 4. Network Policy Testing

### 4.1 Default Deny Enforcement Check

```bash
# Check if any network policies exist
kubectl get networkpolicies --all-namespaces

# Find namespaces without default-deny policies
kubectl get namespaces -o json | jq '.items[] | .metadata.name' | while read ns; do
  count=$(kubectl get networkpolicy -n "$ns" 2>/dev/null | grep -c "default-deny" || echo "0")
  if [ "$count" -eq "0" ]; then
    echo "[!] Namespace $ns has NO default-deny network policy"
  fi
done

# Test connectivity between pods (from inside a pod)
kubectl run test-net --image=alpine --rm -it --restart=Never -- sh -c "apk add curl && curl -s -o /dev/null -w '%{http_code}' http://<target-service>:<port>/"
```

### 4.2 Network Policy Bypass Techniques

```bash
# Check for DNS egress -- often overlooked in network policies
# Network policies typically allow DNS (UDP 53) but may not restrict it
kubectl run dns-test --image=alpine --rm -it --restart=Never -- nslookup exfil.attacker.com

# Test if policies cover both ingress and egress
kubectl get networkpolicies --all-namespaces -o json | jq '.items[] | {name: .metadata.name, namespace: .metadata.namespace, ingress: (.spec.ingress != null), egress: (.spec.egress != null)}'

# Check for policies that allow all traffic to certain pods
kubectl get networkpolicies --all-namespaces -o json | jq '.items[] | select(.spec.ingress[]?.from == null or .spec.ingress[]?.ports == null) | .metadata.name'

# Test using a pod in a different namespace
kubectl run cross-ns-test --image=alpine -n <other-namespace> --rm -it --restart=Never -- wget -qO- http://<target-service>.<target-namespace>.svc.cluster.local
```

### 4.3 East-West Traffic Analysis

```bash
# List all services and their exposure
kubectl get svc --all-namespaces -o json | jq '.items[] | {name: .metadata.name, namespace: .metadata.namespace, type: .spec.type, clusterIP: .spec.clusterIP, ports: [.spec.ports[]?.port]}'

# Enumerate all endpoints (actual pod IPs behind services)
kubectl get endpoints --all-namespaces

# Check for services without corresponding network policies
for ns in $(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}'); do
  svc_count=$(kubectl get svc -n "$ns" --no-headers 2>/dev/null | wc -l)
  np_count=$(kubectl get networkpolicy -n "$ns" --no-headers 2>/dev/null | wc -l)
  if [ "$svc_count" -gt 0 ] && [ "$np_count" -eq 0 ]; then
    echo "[!] $ns: $svc_count services, 0 network policies"
  fi
done
```

### 4.4 Service Mesh Security

```bash
# Check for Istio installation
kubectl get namespace istio-system
kubectl get pods -n istio-system
kubectl get proxyconfig --all-namespaces

# Check Istio mutual TLS enforcement
istioctl analyze
istioctl proxy-status

# Check for permissive mTLS mode (allows plaintext)
kubectl get peerauthentication --all-namespaces -o json | jq '.items[] | select(.spec.mtls.mode == "PERMISSIVE") | .metadata.name'

# Check for authorization policies
kubectl get authorizationpolicies --all-namespaces

# Check for Linkerd installation
kubectl get namespace linkerd
linkerd check
```

---

## 5. Secrets Management

### 5.1 etcd Encryption at Rest Verification

```bash
# Check encryption configuration (requires API server access)
kubectl get --raw /apis/config.openshift.io/v1/encryptions 2>/dev/null || echo "Not OpenShift"

# For standard Kubernetes, check the encryption configuration file
# On control plane node:
cat /etc/kubernetes/encryption-config.yaml

# Check API server flags for encryption
ps aux | grep kube-apiserver | grep encryption

# Verify encryption is active by reading raw etcd data
ETCDCTL_API=3 etcdctl get /registry/secrets/default/test-secret --print-value-only | xxd | head -20
# If the output is plaintext JSON, encryption is NOT enabled
```

### 5.2 Secrets Mounting Exposure

```bash
# List all secrets in all namespaces
kubectl get secrets --all-namespaces -o wide

# Find pods mounting secrets
kubectl get pods --all-namespaces -o json | jq '.items[] | {name: .metadata.name, namespace: .metadata.namespace, secretMounts: [.spec.volumes[]?.secret.secretName]}'

# Find service account token mounts
kubectl get pods --all-namespaces -o json | jq '.items[] | select(.spec.automountServiceAccountToken != false) | .metadata.name' | wc -l

# Check if default service account tokens are auto-mounted
kubectl get serviceaccounts default -o json | jq '.automountServiceAccountToken'

# Access a mounted secret from inside a pod
# (simulated -- run in a target pod)
ls /var/run/secrets/kubernetes.io/serviceaccount/
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace
```

### 5.3 External Secrets Operator Security

```bash
# Check for External Secrets Operator installation
kubectl get namespace external-secrets
kubectl get clustersecretstore --all-namespaces
kubectl get secretstore --all-namespaces

# Check for overly permissive secret stores
kubectl get clustersecretstore -o json | jq '.items[] | {name: .metadata.name, provider: .spec.provider}'

# Enumerate external secrets
kubectl get externalsecrets --all-namespaces -o wide

# Check for secrets stored in ConfigMaps (anti-pattern)
kubectl get configmaps --all-namespaces -o json | jq '.items[] | select(.data | tostring | test("password|secret|token|key|credential"; "i")) | .metadata.name'
```

### 5.4 Vault Integration Security Assessment

```bash
# Check for Vault installation
kubectl get namespace vault
kubectl get pods -n vault

# Check Vault Kubernetes authentication configuration
# From Vault pod:
vault auth list
vault read auth/kubernetes/config

# Check Vault policy bindings
vault list sys/policies/acl
vault policy read <policy-name>

# Check for Vault sidecar injector
kubectl get pods --all-namespaces -o json | jq '.items[] | select(.spec.containers[]?.name | test("vault-agent")) | .metadata.name'

# Verify Vault secrets are not leaking into environment variables
kubectl get pods --all-namespaces -o json | jq '.items[] | select(.spec.containers[]?.env[]?.valueFrom?.vaultKey != null) | .metadata.name'
```

---

## 6. Admission Controller Security

### 6.1 Validating/Mutating Webhook Analysis

```bash
# List all webhook configurations
kubectl get validatingwebhookconfigurations
kubectl get mutatingwebhookconfigurations

# Check webhook failure policies (fail-open is dangerous)
kubectl get validatingwebhookconfigurations -o json | jq '.items[] | {name: .metadata.name, failurePolicy: .webhooks[]?.failurePolicy, sideEffects: .webhooks[]?.sideEffects}'

# Check if webhooks bypass certain namespaces
kubectl get validatingwebhookconfigurations -o json | jq '.items[] | {name: .metadata.name, namespaceSelector: .webhooks[]?.namespaceSelector}'

# Check webhook TLS configuration
kubectl get validatingwebhookconfigurations -o json | jq '.items[] | .webhooks[]?.clientConfig.caBundle' | head -5

# Find webhooks with wildcard operations
kubectl get validatingwebhookconfigurations -o json | jq '.items[] | select(.webhooks[]?.rules[]?.operations | contains(["*"])) | .metadata.name'
```

### 6.2 OPA/Gatekeeper Policy Bypass

```bash
# Check Gatekeeper installation
kubectl get namespace gatekeeper-system
kubectl get constrainttemplates

# List all constraints
kubectl get constraints --all-namespaces

# Check for constraints with enforcement action set to "dryrun"
kubectl get constraints -o json | jq '.items[] | select(.spec.enforcementAction == "dryrun") | .metadata.name'

# Find excluded namespaces (bypass opportunities)
kubectl get constraints -o json | jq '.items[] | {name: .metadata.name, excludedNamespaces: .spec.match.excludedNamespaces}'

# Check Gatekeeper audit logs
kubectl logs -n gatekeeper-system -l gatekeeper.sh/audit
```

### 6.3 Custom Admission Controller Vulnerabilities

```bash
# Check for custom admission webhooks
kubectl get validatingwebhookconfigurations -o json | jq '.items[] | select(.metadata.name | test("gatekeeper|cert-manager|ingress") | not) | .metadata.name'
kubectl get mutatingwebhookconfigurations -o json | jq '.items[] | select(.metadata.name | test("gatekeeper|cert-manager|ingress") | not) | .metadata.name'

# Check webhook service endpoints
kubectl get validatingwebhookconfigurations -o json | jq '.items[] | .webhooks[]?.clientConfig.service'

# Verify webhook service is running and reachable
kubectl get svc -n <webhook-namespace> <webhook-service>
kubectl run curl-test --image=curlimages/curl --rm -it --restart=Never -- curl -k https://<webhook-service>.<namespace>.svc:443/validate
```

---

## 7. Practical kubectl Commands Reference

### Quick Assessment Commands

```bash
# Cluster overview
kubectl cluster-info
kubectl get nodes -o wide
kubectl get namespaces
kubectl api-resources

# Security-focused enumeration
kubectl get pods --all-namespaces -o wide
kubectl get svc --all-namespaces -o wide
kubectl get networkpolicies --all-namespaces
kubectl get secrets --all-namespaces --no-headers | wc -l
kubectl get serviceaccounts --all-namespaces

# RBAC quick audit
kubectl auth can-i --list
kubectl get clusterrolebindings -o wide
kubectl get rolebindings --all-namespaces -o wide

# Pod security audit
kubectl get pods --all-namespaces -o json | jq '.items[] | select(.spec.containers[]?.securityContext?.privileged == true) | .metadata.name'
kubectl get pods --all-namespaces -o json | jq '.items[] | select(.spec.hostPID == true or .spec.hostNetwork == true) | .metadata.name'
kubectl get pods --all-namespaces -o json | jq '.items[] | select(.spec.volumes[]?.hostPath != null) | .metadata.name'
```

### Automated Scanning

```bash
# Run kubeaudit for comprehensive checks
kubeaudit all -n <namespace> -f json > kubeaudit-report.json

# Run trivy scanner on deployed images
kubectl get pods --all-namespaces -o json | jq -r '.items[].spec.containers[].image' | sort -u | while read img; do
  trivy image --severity HIGH,CRITICAL "$img"
done

# Run kubectl with krew plugins
kubectl who-can create pods --all-namespaces
kubectl rakkess --all-namespaces
kubectl access-matrix --all-namespaces

# Check for known vulnerabilities in K8s components
kubectl version --short
# Compare against: https://github.com/kubernetes/kubernetes/blob/master/CHANGELOG/
```

---

## Learning Checklist

### Theory Mastery
- [ ] Understand K8s control plane and worker node architecture
- [ ] Master RBAC evaluation logic and escalation paths
- [ ] Know Pod Security Standards (Privileged/Baseline/Restricted)
- [ ] Understand network policy enforcement and limitations
- [ ] Know secrets management architecture (etcd encryption, external secrets)

### Practical Skills
- [ ] Enumerate and audit all Roles and ClusterRoles
- [ ] Identify overprivileged service accounts
- [ ] Detect container escape vectors (privileged, hostPath, hostPID)
- [ ] Test network policy enforcement and bypass techniques
- [ ] Assess admission controller configurations

### Defense Capabilities
- [ ] Implement Pod Security Admission at the Restricted level
- [ ] Configure default-deny network policies for all namespaces
- [ ] Enable etcd encryption at rest
- [ ] Deploy and configure OPA/Gatekeeper constraints
- [ ] Implement service mesh mTLS for east-west traffic

---

**Document Version**: 1.0
**Created**: 2026-05-14
**Estimated Study Time**: 6-8 hours
**Prerequisites**: Basic Kubernetes knowledge, kubectl proficiency, access to a test cluster
