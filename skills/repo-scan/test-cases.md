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
