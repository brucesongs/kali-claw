# Container Security Test Cases

>Structured test cases covering image security, container runtime, Kubernetes, networking, and advanced scenarios.

---

## Statistics

| Category | TestCases |
|------|-----------|
| A. Image Security | 2 |
| B. Container Runtime | 2 |
| C. Kubernetes Security | 3 |
| D. Network Security | 2 |
| E. Advanced Scenarios | 2 |
| **Total** | **11** |

---

## A. Image Security

### TC-CS-001: Image Vulnerability Scanning & Rating

| Field | Value |
|------|-----|
| **Test ID** | TC-CS-001 |
| **Name** | Image Vulnerability Scanning & Rating |
| **Category** | A. imagesecurity |
| **Severity** | HIGH |
| **Prerequisites** | already install trivy; Objectiveimagecan access |
| **Test Steps** | 1. Execute `trivy image --severity HIGH,CRITICAL --format json <image>:<tag>`<br>2. Analyzeoutputin CVE listand CVSS scoring<br>3. Compare NVD databaseConfirmvulnerabilityreality<br>4. Verifyiswhetherexistsalready fixcomplexversion |
| **Expected Results** | Generatecomplete HIGH/CRITICAL vulnerabilitychecklist；all Discover CVE can in NVD infindtoforshoulditemtarget；outputcontainscan fixcomplexversionrecommend |
| **Remediation** | upgradelevelbasic imagetolatestpatchversion；replaceexistsalready knowvulnerability dependencypackage；Use distroless basic imagereduceattack surface |

### TC-CS-002: Image Secret & Sensitive Information Leak Detection

| Field | Value |
|------|-----|
| **Test ID** | TC-CS-002 |
| **Name** | Image Secret & Sensitive Information Leak Detection |
| **Category** | A. imagesecurity |
| **Severity** | CRITICAL |
| **Prerequisites** | already install trivy or truffleHog; Objectiveimagecan access |
| **Test Steps** | 1. Execute `trivy image --scanners secret <image>:<tag>`<br>2. exportimagelayer `docker save <image> -o image.tar` anddecompression<br>3. ineachlayerinSearch `.env`、`.pem`、`.key`、`password`、`token` etc.sensitivefile<br>4. Check `docker history --no-trunc` iniswhetherleakagebuildparameter |
| **Expected Results** | nohardencoding API Key、password、certificateprivate keyordatabaseconnectstring；Dockerfile buildhistoryinnotcontainssensitiveparameter |
| **Remediation** | Usemultiplephasebuildavoidsensitiveinformationentermost终image；Use BuildKit --secret mount；in CI inintegrationkeyScan |

---

## B. Container Runtime

### TC-CS-003: Privileged Container & Dangerous Capability Detection

| Field | Value |
|------|-----|
| **Test ID** | TC-CS-003 |
| **Name** | Privileged Container & Dangerous Capability Detection |
| **Category** | B. containerRunwhen |
| **Severity** | CRITICAL |
| **Prerequisites** | already DeployObjectivecontainer; havehas docker or kubectl accesspermission |
| **Test Steps** | 1. Execute `docker inspect --format '{{.HostConfig.Privileged}}' <container>`<br>2. Execute `docker inspect --format '{{json .HostConfig.CapAdd}}' <container>`<br>3. Verifycontaineriswhetherwith root userRun<br>4. Checkiswhethermount /var/run/docker.sock or /proc/sys |
| **Expected Results** | Privileged shouldas false; CapAdd notshouldcontains SYS_ADMIN、SYS_PTRACE、NET_ADMIN; containernotshouldwith UID 0 Run |
| **Remediation** | remove privileged flag; Use --cap-drop ALL --cap-add <onlyrequires >; Dockerfile inadd USER specifynon root user |

### TC-CS-004: Container Escape Path Verification

| Field | Value |
|------|-----|
| **Test ID** | TC-CS-004 |
| **Name** | Container Escape Path Verification |
| **Category** | B. containerRunwhen |
| **Severity** | CRITICAL |
| **Prerequisites** | inObjectivecontainerinnerobtain shell; already install capsh orcan read /proc/self/status |
| **Test Steps** | 1. Execute `cat /proc/1/cgroup` Confirmcontainerenvironment<br>2. Execute `capsh --print` Checkcanpowerset<br>3. Check `mount` outputin sensitivemountpoint<br>4. Test docker.sock iswhethercan access: `ls -la /var/run/docker.sock`<br>5. Check seccomp status: `cat /proc/self/status \| grep Seccomp` |
| **Expected Results** | containercanpowersetshouldstrictly restricted; docker.sock notshouldexists; seccomp should处atfiltermode (2); notshouldmount宿hostcriticalpath |
| **Remediation** | enable seccomp AppArmor Configurefile; prohibitmount docker.sock and /proc/sys; Use Pod Security Standards Restricted policy |

---

## C. Kubernetes Security

### TC-CS-005: RBAC Over-Privilege Audit

| Field | Value |
|------|-----|
| **Test ID** | TC-CS-005 |
| **Name** | RBAC Over-Privilege Audit |
| **Category** | C. Kubernetes security |
| **Severity** | HIGH |
| **Prerequisites** | havehas kubectl accesspermission; can read ClusterRoleBinding and RoleBinding |
| **Test Steps** | 1. Execute `kubectl get clusterrolebindings -o wide` listall clusterrolebinding<br>2. Checkiswhetherexistsbindingto cluster-admin ServiceAccount<br>3. Execute `kubectl auth can-i --list --as=system:serviceaccount:default:default`<br>4. Verify default ServiceAccount iswhethertoolhassuperoutputread permission<br>5. Checkiswhetherexists wildcard (*) permission ClusterRole |
| **Expected Results** | onlyhasadministratorrolebindingto cluster-admin; default ServiceAccount nosensitiveoperationpermission; notexistsUse wildcard * roleDefinition |
| **Remediation** | followleast privilegeoriginalthen收紧 RBAC; aseachapplicationcreatespecializeduse ServiceAccount; deletenotnecessary cluster-admin binding |

### TC-CS-006: Secret Storage Security Verification

| Field | Value |
|------|-----|
| **Test ID** | TC-CS-006 |
| **Name** | Secret Storage Security Verification |
| **Category** | C. Kubernetes security |
| **Severity** | HIGH |
| **Prerequisites** | havehas kubectl accesspermission; can listandread Secret |
| **Test Steps** | 1. Execute `kubectl get secrets --all-namespaces` listall Secret<br>2. Execute `kubectl get secret <name> -o yaml` Check Secret Content<br>3. Verify Secret iswhetherUse etcd encryption<br>4. Check Pod iswhethermount nonnecessary Secret<br>5. Verifyiswhetherenable EncryptionConfiguration |
| **Expected Results** | etcd in Secret dataalready encryption; Pod onlymountits所need Secret; nohardencoding Secret in Pod spec in |
| **Remediation** | enable etcd encryption at rest; Useexternalkeymanagementtool (Vault、AWS Secrets Manager); Configure automountServiceAccountToken: false |

### TC-CS-007: Pod Security Standards Compliance Check

| Field | Value |
|------|-----|
| **Test ID** | TC-CS-007 |
| **Name** | Pod Security Standards Compliance Check |
| **Category** | C. Kubernetes security |
| **Severity** | MEDIUM |
| **Prerequisites** | already install kubeaudit; Kubernetes version >= 1.23 |
| **Test Steps** | 1. Execute `kubeaudit all -n default` audit命name空intervalConfigure<br>2. CheckiswhetherConfigure Pod Security Admission tag<br>3. Execute `kubeaudit privileged --all-namespaces` Checkprivilege Pod<br>4. Execute `kubeaudit runasnonroot --all-namespaces` Check root Run<br>5. Verify namespace iswhetherExecute enforce、audit、warn 三levelpolicy |
| **Expected Results** | all namespace allConfigure Pod Security Standards; noprivilege Pod inproduction namespace Run; all Pod withnon root userRun |
| **Remediation** | in namespace onadd pod-security.kubernetes.io/enforce: restricted tag; willapplication迁movetonon root Run; Use Security Context Constraint |

---

## D. Network Security

### TC-CS-008: Network Policy Micro-segmentation Verification

| Field | Value |
|------|-----|
| **Test ID** | TC-CS-008 |
| **Name** | Network Policy Micro-segmentation Verification |
| **Category** | D. networksecurity |
| **Severity** | HIGH |
| **Prerequisites** | CNI pluginsupports Network Policy (such as Calico、Cilium); kubectl accesspermission |
| **Test Steps** | 1. Execute `kubectl get networkpolicies --all-namespaces` listalready haspolicy<br>2. Deploydefaultdenyall inputsitepolicy<br>3. fromfrontend Pod Testtobackend Pod connectpassity: `kubectl exec -it <frontend> -- curl <backend>:8080`<br>4. Deployallowsfrontendtobackend policyand重newTest<br>5. fromnonauthorization Pod Testconnectpassityshouldbydeny |
| **Expected Results** | defaultdenypolicy生effectafterall cross Pod communicationby阻断; allowpolicyonlyallowsspecifytag Pod communication; not authorization Pod nomethodaccessbackendservice |
| **Remediation** | inall namespace Deploydefaultdenypolicy; Usetagselecttoolprecisecontrol Pod intervalcommunication; regularlyaudit Network Policy coveringscope |

### TC-CS-009: CIS Docker Benchmark Compliance Assessment

| Field | Value |
|------|-----|
| **Test ID** | TC-CS-009 |
| **Name** | CIS Docker Benchmark Compliance Assessment |
| **Category** | D. networksecurity |
| **Severity** | MEDIUM |
| **Prerequisites** | already install docker-bench-security; Docker daemon Runin |
| **Test Steps** | 1. Execute `docker-bench-security` Runcomplete CIS Benchmark<br>2. Analyze host_configuration Checkitem (1.x) iswhetherthrough<br>3. Analyze docker_daemon_configuration Checkitem (2.x) iswhetherthrough<br>4. Analyze container_runtime Checkitem (5.x) iswhetherthrough<br>5. Statistics WARN and FAIL itemCount |
| **Expected Results** | all criticalConfigureitemthroughCheck; no FAIL Level problem; Docker daemon Configurecharactercombine CIS Benchmark baseline |
| **Remediation** | by照 CIS Benchmark fixcomplexguide逐itemtuneentire; enable live-restore; Configure TLS authenticationremote API; setlog驱dynamicandlog轮转 |

---

## E. Advanced Scenarios

### TC-CS-010: Full Container Escape Chain Verification

| Field | Value |
|------|-----|
| **Test ID** | TC-CS-010 |
| **Name** | Full Container Escape Chain Verification |
| **Category** | E. advanced scenario |
| **Severity** | CRITICAL |
| **Prerequisites** | Objectiveclusteralready Deploy; already Obtaincontainerinner shell; existsalready knowvulnerability kernelversion |
| **Test Steps** | 1. containerinnerExecuteenvironmentfingerprintcollect (kernelversion、canpower、mountpoint)<br>2. Detect cgroup/release_agent escapecan rowity<br>3. Attemptthrough docker.sock createprivilegecontainer<br>4. Verifyiswhethercan throughkernelvulnerability (such as CVE-2022-0185) privilege escalation<br>5. successescapeafterVerify宿hostfilesystemaccesspermission<br>6. Checkiswhethercan lateral movementtoitsothercontainerorsectionpoint |
| **Expected Results** | all already knowescapepathby阻断; escapeAttemptTrigger Falco alert; nomethodObtain宿hostfilesystemaccesspermission |
| **Remediation** | Use seccomp profile limitationsystemtuneuse; enable Pod Security Standards Restricted; Deploy Falco Monitorescapebehavior; regularlyfix补kernelvulnerability |

### TC-CS-011: CI/CD Security Integration Verification

| Field | Value |
|------|-----|
| **Test ID** | TC-CS-011 |
| **Name** | CI/CD Security Integration Verification |
| **Category** | E. advanced scenario |
| **Severity** | MEDIUM |
| **Prerequisites** | CI/CD flow水linecan access; already integrationorpendingintegrationsecurity scanningTools |
| **Test Steps** | 1. Verifyimagebuildphaseiswhetherintegration trivy/grype vulnerability scanning<br>2. Check Dockerfile iswhetherthrough hadolint or dockle bestpracticeCheck<br>3. Verifyiswhetherenableimagesignature (cosign/Notary)<br>4. Testcontainsalready knowvulnerability imageiswhetherbyflow水lineblockDeploy<br>5. Verify SBOM Generateandstorageprocess<br>6. Check Registry iswhetherConfigure imagepullsignatureVerify |
| **Expected Results** | vulnerabilityimagebyblockDeploy; all releaseimagealready signature; SBOM automated Generateandarchive; Dockerfile bestpracticeCheckthrough |
| **Remediation** | in CI pipeline inadd trivy image --exit-code 1 ScanStep; integration cosign signaturetoreleaseprocess; Configure Admission Controller Verifyimagesignature; automated SBOM Generate |
