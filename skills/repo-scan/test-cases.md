# Repository Scan — Test Cases

> Structured test scenarios for cross-stack source code audit methodology.

---

## TC-RS-001: Full Surface Classification

### Scenario
A Python/JavaScript web application repository with vendored dependencies, build artifacts, and mixed project/third-party code needs complete surface classification before security review.

### Pre-conditions
- Repository cloned locally or mounted as volume
- `cloc`, `trivy`, `grype` installed on Kali system
- Write access for output files

### Test Steps

1. **Run file inventory**
   ```bash
   find . -type f | sed 's/.*\.//' | sort | uniq -c | sort -rn | head -30
   cloc --by-file . --json --quiet > surface-classification.json
   ```

2. **Detect third-party directories**
   ```bash
   find . -type d \( -name "vendor" -o -name "node_modules" -o -name "third_party" \) -prune -print
   ```

3. **Classify files into categories**
   - Project code (custom business logic)
   - Third-party code (vendored libraries)
   - Build artifacts (compiled/generated)
   - Configuration (settings, deployment)
   - Test code (fixtures, mocks)

4. **Generate classification summary**
   - Total files per category
   - Lines of code per category
   - Third-party ratio (percentage)

### Expected Outcomes

| Metric | Expected |
|--------|----------|
| File categories identified | 5 (project, third-party, build, config, test) |
| Third-party ratio calculated | Yes (percentage of total LOC) |
| Large files flagged | Files >1MB listed |
| Vendored directories found | node_modules/, vendor/, etc. |

---

## TC-RS-002: Dependency Vulnerability Detection

### Scenario
A web application has both managed dependencies (package.json, requirements.txt) and vendored libraries. Identify all known CVEs in dependencies and flag outdated libraries.

### Pre-conditions
- Target repository with dependency manifests present
- `trivy`, `grype`, `pip-audit`, `npm audit` available

### Test Steps

1. **Scan managed dependencies**
   ```bash
   trivy fs --scanners vuln --format json . > trivy-results.json
   grype dir:. --output json > grype-results.json
   ```

2. **Run ecosystem-specific audits**
   ```bash
   npm audit --json 2>/dev/null
   pip-audit -r requirements.txt --format json
   ```

3. **Identify vendored libraries**
   ```bash
   grep -rn "version.*[0-9]\+\.[0-9]\+\.[0-9]\+" --include="*.js" --include="*.py" --include="*.h" . \
     | grep -i "jquery\|angular\|react\|lodash\|openssl\|sqlite" | head -20
   ```

4. **Correlate findings**
   - Cross-reference trivy and grype results
   - Deduplicate findings between tools
   - Prioritize by severity (Critical > High > Medium > Low)

### Expected Outcomes

| Metric | Expected |
|--------|----------|
| All managed dependencies scanned | Yes |
| Vendored libraries identified | Version strings found |
| CVE count per library | Listed with severity |
| False positive rate | <10% (cross-tool correlation) |

---

## TC-RS-003: Security Hotspot Mapping

### Scenario
Identify all security-sensitive code locations in a multi-language repository for targeted manual review.

### Pre-conditions
- Repository with mixed Python, JavaScript, Java, PHP code
- grep, ripgrep available

### Test Steps

1. **Authentication hotspot grep**
   ```bash
   grep -rn "password\|auth\|token\|session\|login" \
     --include="*.py" --include="*.js" --include="*.java" --include="*.php" . \
     | grep -v "node_modules\|vendor\|test" > hotspots-auth.txt
   ```

2. **Database interaction grep**
   ```bash
   grep -rn "query\|execute\|cursor\|select.*from" \
     --include="*.py" --include="*.php" --include="*.java" . \
     | grep -v "vendor\|test\|migration" > hotspots-db.txt
   ```

3. **File operation grep**
   ```bash
   grep -rn "open(\|readfile\|upload\|include\(" \
     --include="*.py" --include="*.php" --include="*.java" . \
     | grep -v "vendor\|test" > hotspots-fileops.txt
   ```

4. **Command execution grep**
   ```bash
   grep -rn "system(\|exec(\|subprocess\.\|Runtime\.exec" \
     --include="*.py" --include="*.php" --include="*.java" --include="*.js" . \
     | grep -v "vendor\|test" > hotspots-exec.txt
   ```

5. **Generate hotspot map**
   - Consolidate all hotspots into ranked list
   - Group by file/module for efficient review
   - Assign priority (auth > exec > db > fileops)

### Expected Outcomes

| Metric | Expected |
|--------|----------|
| Hotspot categories covered | 4+ (auth, db, fileops, exec) |
| Results exclude third-party | Yes (vendor/node_modules filtered) |
| Hotspots ranked by priority | Yes |
| Module-level grouping | Yes (for review efficiency) |

---

## TC-RS-004: Complete Audit with Verdicts

### Scenario
Full repository audit combining all phases: classification, library detection, hotspot analysis, secret scanning, and module verdicts.

### Pre-conditions
- All Phase 1-4 tools installed
- Repository accessible
- Output directory created

### Test Steps

1. **Execute full scan pipeline**
   ```bash
   # Phase 1: Classification
   cloc --by-file . --json > reports/classification.json

   # Phase 2: Dependencies
   trivy fs --scanners vuln . > reports/dependencies.txt
   grype dir:. > reports/grype.txt

   # Phase 3: Hotspots
   # Run all hotspot greps from TC-RS-003

   # Phase 4: Secrets
   trufflehog git file://. --json > reports/secrets.json
   gitleaks detect --source . --report-format json --report-path reports/gitleaks.json
   ```

2. **Assign verdicts per module**
   - Core Asset: custom business logic with security hotspots
   - Extract & Update: vendored libraries with known CVEs
   - Rebuild: duplicated code across modules
   - Deprecate: unreferenced dead code

3. **Generate final report** using SKILL.md report template

### Expected Outcomes

| Metric | Expected |
|--------|----------|
| All phases completed | 4/4 (classify, detect, hotspot, secrets) |
| Module verdicts assigned | Every module classified |
| Report generated | Complete with findings, verdicts, recommendations |
| Third-party ratio documented | Yes |
| Secret findings reported | Any secrets found documented with severity |

---

## TC-RS-005: CI/CD Pipeline Security Assessment

### Objective
Evaluate the security posture of a repository's CI/CD pipeline configuration, identifying injection risks, secret exposure, and supply chain vulnerabilities in workflow definitions.

### Severity
HIGH — CI/CD misconfigurations can lead to arbitrary code execution, secret exfiltration, and supply chain compromise.

### Pre-conditions
- Repository with CI/CD configuration files (.github/workflows/, .gitlab-ci.yml, Jenkinsfile)
- grep, yq, or jq available for YAML/JSON parsing
- Understanding of CI/CD injection patterns

### Test Steps

1. **Enumerate pipeline configurations**
   ```bash
   find . -name "*.yml" -path "*/.github/workflows/*" -o -name ".gitlab-ci.yml" -o -name "Jenkinsfile" | sort
   ```

2. **Check for injection vulnerabilities**
   ```bash
   grep -rn "github.event\.\|inputs\.\|pull_request\.title\|pull_request\.body" .github/workflows/ \
     | grep -v "#" | head -20
   ```

3. **Audit action pinning**
   ```bash
   grep -rn "uses:" .github/workflows/ | grep -v "@[a-f0-9]\{40\}" | grep -v "^#"
   ```

4. **Check secret exposure risks**
   ```bash
   grep -rn "secrets\.\|GITHUB_TOKEN\|env:" .github/workflows/ | grep -v "^#" | head -20
   ```

5. **Assess permission scope**
   ```bash
   grep -rn "permissions:" .github/workflows/ -A 5
   ```

### Expected Outcomes

| Metric | Expected |
|--------|----------|
| All workflow files enumerated | Yes |
| Injection vectors identified | Expression injection patterns flagged |
| Unpinned actions listed | Actions without SHA pinning |
| Secret handling reviewed | Exposure risks documented |
| Permission scope assessed | Overly permissive scopes flagged |

### Remediation
- Pin all third-party actions to full SHA hashes
- Use intermediate environment variables instead of direct expression interpolation
- Apply least-privilege permissions model to all workflows
- Enable branch protection rules requiring status checks
- Use OIDC for cloud authentication instead of long-lived secrets

### Pass Criteria
- [ ] All CI/CD configuration files discovered and analyzed
- [ ] No unmitigated injection vulnerabilities in workflow expressions
- [ ] All third-party actions pinned to SHA or documented exception
- [ ] Secret exposure risks identified and remediation plan created
- [ ] Permission scopes follow least-privilege principle

---

## TC-RS-006: Supply Chain Dependency Confusion Attack Detection

### Objective
Detect dependency confusion vulnerabilities in package manifests by identifying private package names that could be hijacked on public registries, misconfigured registry scopes, and missing namespace protections.

### Severity
CRITICAL — Dependency confusion allows attackers to execute arbitrary code during package installation by publishing malicious packages to public registries that shadow internal package names.

### Pre-conditions
- Repository with package manifests (package.json, requirements.txt, setup.py, pyproject.toml, .npmrc, pip.conf)
- Access to public registry APIs (npmjs.com, pypi.org)
- `npm`, `pip`, `curl`, `jq` available on Kali system
- Network access to query public registries

### Test Steps

1. **Extract internal package names and check registry scope configuration**
   ```bash
   # Extract scoped and unscoped packages from package.json
   jq -r '.dependencies // {} | keys[]' package.json 2>/dev/null | grep -v "^@" > internal-unscoped.txt
   jq -r '.devDependencies // {} | keys[]' package.json 2>/dev/null | grep -v "^@" >> internal-unscoped.txt

   # Check for .npmrc registry configuration
   cat .npmrc 2>/dev/null || echo "NO .npmrc FOUND — default registry in use"

   # Check pip configuration for extra index URLs
   grep -rn "extra-index-url\|index-url" pip.conf setup.cfg pyproject.toml 2>/dev/null
   ```

2. **Probe public registries for namespace collisions**
   ```bash
   # Check if internal package names exist on public npm
   while read pkg; do
     status=$(curl -s -o /dev/null -w "%{http_code}" "https://registry.npmjs.org/${pkg}")
     if [ "$status" = "404" ]; then
       echo "VULNERABLE: ${pkg} — not claimed on public npm (hijackable)"
     else
       echo "EXISTS: ${pkg} — verify ownership matches your org"
     fi
   done < internal-unscoped.txt

   # Check Python packages on PyPI
   grep -E "^[a-zA-Z]" requirements.txt 2>/dev/null | cut -d'=' -f1 | cut -d'>' -f1 | cut -d'<' -f1 | while read pkg; do
     status=$(curl -s -o /dev/null -w "%{http_code}" "https://pypi.org/pypi/${pkg}/json")
     [ "$status" = "404" ] && echo "VULNERABLE: ${pkg} — not on PyPI (confusion risk)"
   done
   ```

3. **Analyze install hooks and post-install scripts**
   ```bash
   # Check for preinstall/postinstall scripts that could be exploited
   jq '.scripts | to_entries[] | select(.key | test("pre|post|install"))' package.json 2>/dev/null

   # Check setup.py for cmdclass overrides (Python install hooks)
   grep -n "cmdclass\|setup(\|install_requires" setup.py 2>/dev/null

   # Look for .pip-extra-index patterns in CI configs
   grep -rn "extra-index-url\|--index-url\|PIP_INDEX_URL" .github/ .gitlab-ci.yml Dockerfile 2>/dev/null
   ```

### Expected Outcomes

| Metric | Expected |
|--------|----------|
| All package manifests discovered | Yes (npm, pip, and any monorepo workspaces) |
| Unscoped internal packages identified | Listed with public registry status |
| Namespace collision risks flagged | Packages not claimed on public registries |
| Registry scope configuration assessed | .npmrc / pip.conf reviewed for misconfig |
| Install hook abuse vectors documented | Pre/post-install scripts analyzed |

### Remediation
- Claim all internal package names on public registries as placeholders
- Use scoped packages (@org/package-name) for all internal npm packages
- Configure .npmrc with explicit registry scopes for internal packages
- Set `--extra-index-url` only with `--index-url` pointing to public registry first
- Enable package provenance verification where supported (npm `--expect-provenance`)
- Remove unnecessary install hooks from package.json scripts

### Pass Criteria
- [ ] All package manifests in the repository identified and analyzed
- [ ] Internal packages without public registry claims flagged as CRITICAL
- [ ] Registry scope configuration validated (no default fallback to public for private packages)
- [ ] Install hook scripts reviewed for malicious potential
- [ ] Remediation plan created for all identified confusion vectors

---

## TC-RS-007: Infrastructure-as-Code Security Audit

### Objective
Scan Infrastructure-as-Code (IaC) manifests including Terraform, CloudFormation, and Kubernetes configurations for security misconfigurations, overly permissive policies, and compliance violations.

### Severity
HIGH — IaC misconfigurations can expose cloud resources to the internet, grant excessive permissions, or disable security controls, leading to data breaches and unauthorized access.

### Pre-conditions
- Repository containing IaC files (.tf, .yaml/.yml CloudFormation templates, Kubernetes manifests)
- `trivy`, `tfsec`, `checkov`, or `kube-score` installed on Kali system
- Understanding of cloud security benchmarks (CIS, AWS Well-Architected)

### Test Steps

1. **Enumerate and classify IaC files**
   ```bash
   # Find Terraform files
   find . -name "*.tf" -not -path "*/\.terraform/*" | sort > iac-terraform.txt

   # Find CloudFormation templates
   find . -name "*.yml" -o -name "*.yaml" -o -name "*.json" | xargs grep -l "AWSTemplateFormatVersion\|Resources:" 2>/dev/null > iac-cloudformation.txt

   # Find Kubernetes manifests
   find . -name "*.yml" -o -name "*.yaml" | xargs grep -l "apiVersion:\|kind:" 2>/dev/null | grep -v "node_modules\|\.github" > iac-kubernetes.txt

   echo "Terraform: $(wc -l < iac-terraform.txt) files"
   echo "CloudFormation: $(wc -l < iac-cloudformation.txt) files"
   echo "Kubernetes: $(wc -l < iac-kubernetes.txt) files"
   ```

2. **Run automated IaC security scanners**
   ```bash
   # Trivy IaC scan (covers Terraform, CloudFormation, Kubernetes, Dockerfile)
   trivy config --severity HIGH,CRITICAL --format json . > reports/iac-trivy.json

   # tfsec for Terraform-specific checks
   tfsec . --format json > reports/iac-tfsec.json 2>/dev/null

   # Checkov for multi-framework scanning
   checkov -d . --output json --quiet > reports/iac-checkov.json 2>/dev/null

   # Kubernetes-specific scoring
   cat iac-kubernetes.txt | xargs -I{} kube-score score {} 2>/dev/null > reports/iac-kubescore.txt
   ```

3. **Manual checks for critical misconfigurations**
   ```bash
   # Terraform: check for overly permissive IAM and public exposure
   grep -rn 'actions.*=.*\["\*"\]\|principal.*=.*"\*"\|cidr_blocks.*0\.0\.0\.0/0' --include="*.tf" . \
     | grep -v "#" > iac-critical-findings.txt

   # Kubernetes: check for privileged containers and missing security context
   grep -rn "privileged: true\|runAsRoot\|hostNetwork: true\|hostPID: true" --include="*.yml" --include="*.yaml" . \
     | grep -v "#" >> iac-critical-findings.txt

   # CloudFormation: check for public S3 buckets and open security groups
   grep -rn "PublicRead\|PublicReadWrite\|0\.0\.0\.0/0\|::/0" --include="*.yml" --include="*.yaml" --include="*.json" . \
     | grep -v "node_modules" >> iac-critical-findings.txt

   echo "Critical findings: $(wc -l < iac-critical-findings.txt)"
   ```

### Expected Outcomes

| Metric | Expected |
|--------|----------|
| All IaC files enumerated by type | Yes (Terraform, CloudFormation, K8s) |
| Automated scanner results collected | At least 2 scanners executed |
| Critical misconfigurations flagged | Wildcard IAM, public exposure, privileged containers |
| Findings deduplicated across tools | Cross-referenced and prioritized |
| Compliance benchmark violations noted | CIS/AWS benchmarks referenced |

### Remediation
- Replace wildcard IAM actions with least-privilege policies
- Restrict security group ingress to specific CIDR ranges and ports
- Set `privileged: false` and define explicit security contexts for all Kubernetes pods
- Enable encryption at rest for all storage resources (S3, EBS, RDS)
- Use private subnets for databases and internal services
- Enable logging and monitoring on all cloud resources (CloudTrail, VPC Flow Logs)
- Implement resource tagging for ownership and cost tracking

### Pass Criteria
- [ ] All IaC files in the repository discovered and categorized
- [ ] At least two automated scanners executed with results collected
- [ ] No unmitigated wildcard IAM policies or public resource exposure
- [ ] Kubernetes manifests enforce non-root, non-privileged execution
- [ ] Remediation plan addresses all HIGH and CRITICAL findings

---

## TC-RS-008: Container Image Layer Analysis

### Objective
Analyze Docker image layers to detect leaked secrets, known vulnerabilities in base images and installed packages, unnecessary packages that expand the attack surface, and insecure build practices.

### Severity
HIGH — Container images often contain hardcoded credentials, vulnerable system libraries, and excessive packages that provide attackers with tools for lateral movement after initial compromise.

### Pre-conditions
- Repository with Dockerfile(s) or access to built container images
- `docker`, `trivy`, `dive`, `syft`, `grype` installed on Kali system
- Sufficient disk space for image layer extraction
- Docker daemon running or images exported as tar archives

### Test Steps

1. **Enumerate Dockerfiles and analyze build instructions**
   ```bash
   # Find all Dockerfiles in the repository
   find . -name "Dockerfile*" -not -path "*/node_modules/*" | sort

   # Check for insecure patterns in Dockerfiles
   for df in $(find . -name "Dockerfile*" -not -path "*/node_modules/*"); do
     echo "=== ${df} ==="
     # Detect secrets passed as build args
     grep -n "ARG.*PASSWORD\|ARG.*SECRET\|ARG.*TOKEN\|ARG.*KEY" "$df"
     # Detect running as root (no USER directive)
     grep -n "^USER" "$df" || echo "WARNING: No USER directive — runs as root"
     # Detect use of latest tag
     grep -n "^FROM.*:latest\|^FROM.*[^:]$" "$df"
     # Detect COPY of sensitive files
     grep -n "COPY.*\.env\|COPY.*\.key\|COPY.*\.pem\|ADD.*\.ssh" "$df"
   done
   ```

2. **Scan built image layers for secrets and vulnerabilities**
   ```bash
   # Build image (or use existing tag)
   IMAGE_TAG="scan-target:latest"
   docker build -t "$IMAGE_TAG" . 2>/dev/null

   # Trivy image vulnerability scan
   trivy image --severity HIGH,CRITICAL --format json "$IMAGE_TAG" > reports/image-vulns.json

   # Generate SBOM with syft
   syft "$IMAGE_TAG" -o json > reports/image-sbom.json

   # Scan SBOM for vulnerabilities with grype
   grype sbom:reports/image-sbom.json --output json > reports/image-grype.json

   # Analyze layer efficiency and wasted space with dive
   dive "$IMAGE_TAG" --json reports/image-dive.json --ci 2>/dev/null
   ```

3. **Extract and inspect individual layers for secrets**
   ```bash
   # Save image and extract layers
   docker save "$IMAGE_TAG" -o image.tar
   mkdir -p image-layers && tar -xf image.tar -C image-layers/

   # Search all layers for secrets and credentials
   find image-layers/ -name "layer.tar" -exec tar -tf {} \; 2>/dev/null | \
     grep -iE "\.env$|\.pem$|\.key$|id_rsa|credentials|\.aws/|\.docker/config" > layer-secrets.txt

   # Check for package managers and unnecessary tools
   docker run --rm --entrypoint="" "$IMAGE_TAG" sh -c \
     "which curl wget nc ncat gcc make python perl 2>/dev/null" > unnecessary-tools.txt

   # Count total packages installed
   docker run --rm --entrypoint="" "$IMAGE_TAG" sh -c \
     "dpkg -l 2>/dev/null | wc -l || rpm -qa 2>/dev/null | wc -l || apk list --installed 2>/dev/null | wc -l"

   # Cleanup
   rm -rf image-layers/ image.tar
   ```

### Expected Outcomes

| Metric | Expected |
|--------|----------|
| All Dockerfiles analyzed for insecure patterns | Yes |
| Image vulnerability scan completed | HIGH/CRITICAL CVEs listed |
| SBOM generated for full package inventory | Yes (syft output) |
| Layer-level secret scan performed | Sensitive files in any layer flagged |
| Unnecessary packages/tools identified | Attack surface expansion documented |
| Image efficiency score calculated | Wasted space percentage reported |

### Remediation
- Use multi-stage builds to exclude build tools and source code from final image
- Switch to minimal base images (distroless, alpine, scratch) where possible
- Never pass secrets via ARG or ENV — use BuildKit secret mounts (`--mount=type=secret`)
- Add explicit `USER nonroot` directive to run as non-root
- Pin base image tags to specific digests instead of mutable tags
- Remove package managers and shells from production images when feasible
- Use `.dockerignore` to prevent copying `.env`, `.git`, and credential files into build context
- Regularly rebuild images to incorporate upstream security patches

### Pass Criteria
- [ ] All Dockerfiles in the repository analyzed for insecure build patterns
- [ ] No secrets or credentials detected in any image layer
- [ ] All HIGH and CRITICAL vulnerabilities documented with remediation timeline
- [ ] Images run as non-root user with minimal capabilities
- [ ] Unnecessary packages and tools identified for removal
- [ ] Base images pinned to specific versions or digests
