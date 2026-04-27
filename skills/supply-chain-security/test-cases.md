# Supply Chain Security Test Cases

> This file is a companion to `SKILL.md`, containing structured supply chain security test cases organized by category with severity ratings.

---

## TestTest Case Statistics

| Category | Count | IDs |
|------|------|------|
| A. Dependency Scanning | 3 | TC-SS-01 ~ TC-SS-03 |
| B. Package Integrity | 2 | TC-SS-04 ~ TC-SS-05 |
| C. CI/CD Security | 3 | TC-SS-06 ~ TC-SS-08 |
| D. Attack Simulation | 2 | TC-SS-09 ~ TC-SS-10 |
| E. Hardening Verification | 2 | TC-SS-11 ~ TC-SS-12 |
| **Total** | **12** | |

---

## A. Dependency Scanning

### TC-SS-01: Trivy Multi-target Vulnerability Scanning

| Field | Value |
|------|-----|
| **TestName** | Trivy Dependency Vulnerability Scanning Coverage Verification |
| **Severity** | HIGH |
| **Prerequisites** | already install Trivy；ObjectiveItemwith lock file (package-lock.json or Pipfile.lock) |
| **Test Steps** | 1. Execute `trivy fs --severity HIGH,CRITICAL ./project` Scanfilesystem<br>2. Execute `trivy fs --format json --output trivy-report.json ./project` Generate JSON report<br>3. Execute `trivy fs ./project/package-lock.json` targetingfor lock fileScan<br>4. Execute `trivy repo https://github.com/target/repo` Scanremoterepositorylibrary |
| **Expected Results** | all already know HIGH/CRITICAL vulnerabilitybyIdentify；JSON reportcontainscomplete CVE IDs、CVSS scoringandfixcomplexversionrecommend |
| **Fail Criteria** | vulnerabilityCountand NVD databasenotconsistent；Scannot coveringtransmitdependency；JSON reportformatnotcomplete |
| **Remediation** | update Trivy vulnerabilitydatabase (`trivy image --download-db-only`)；Confirm lock fileexistsatItemrootdirectory |

### TC-SS-02: npm audit Dependency Audit

| Field | Value |
|------|-----|
| **TestName** | Node.js Project Dependency Vulnerability Audit |
| **Severity** | HIGH |
| **Prerequisites** | Node.js Itemwith package.json and package-lock.json |
| **Test Steps** | 1. Execute `npm audit` Obtaincomplete vulnerabilitylist<br>2. Execute `npm audit --audit-level=high --json > audit.json` Generate JSON report<br>3. Execute `npm audit fix` automated fixcomplexcan fixcomplexvulnerability<br>4. Execute `npm outdated` Checkoverwhen dependency<br>5. 重newExecute `npm audit` Verifyfixcomplexeffectresult |
| **Expected Results** | all already knowvulnerabilitybyreport；`npm audit fix` successfixcomplexnondestroyityvulnerability；fixcomplexafter HIGH/CRITICAL vulnerabilityCountreduce |
| **Fail Criteria** | audit commandbecause lock file损坏andfailure；fixcomplexintroduceinputdestroyitychangecausebuildfailure |
| **Remediation** | Use `npm ci` rebuild node_modules；Check package-lock.json integrity；manual upgradelevelnomethodautomated fixcomplex dependency |

### TC-SS-03: Python Dependency Vulnerability Scanning (pip-audit + Safety)

| Field | Value |
|------|-----|
| **TestName** | Python Itemdependencyvulnerability scanning |
| **Severity** | MEDIUM |
| **Prerequisites** | Python Itemwith requirements.txt or Pipfile.lock |
| **Test Steps** | 1. Execute `pip-audit -r requirements.txt` Scandependencyvulnerability<br>2. Execute `pip-audit -r requirements.txt --format json > pip-audit.json` Generate JSON report<br>3. Execute `safety check -r requirements.txt --full-report` Obtaincomplete report<br>4. Compare两Tools Scanresultdifference |
| **Expected Results** | 两Toolsallreportalready knowvulnerability；resultcontains CVE IDsandfixcomplexversionrecommend；differencein预periodscopeinner (databaseupdatewhen interval差) |
| **Fail Criteria** | 任aToolsreport 0 vulnerabilitybutItem确realwith overwhen dependency；CVE IDsnomethodforshould |
| **Remediation** | updatevulnerabilitydatabase；manual Verify CVE suitableuseity；upgradeleveltofixcomplexversion |

---

## B. Package Integrity

### TC-SS-04: Lock File Integrity Verification

| Field | Value |
|------|-----|
| **TestName** | Lock File Integrity Verification |
| **Severity** | HIGH |
| **Prerequisites** | Itemwith package-lock.json or yarn.lock or Pipfile.lock |
| **Test Steps** | 1. backupraw lock file<br>2. modify lock fileinsomepackage integrity hash<br>3. Execute `npm ci` Verifyiswhetherdenyinstall<br>4. recovercomplexraw lock fileandExecute `npm ci` Verifynormalinstall<br>5. Execute `npm ls --package-lock-only` Check manifest and lock filesynchronousity |
| **Expected Results** | modify integrity hash after `npm ci` denyinstallandreportintegrityerror；rawfilerecovercomplexnormalinstall；manifest and lock filesynchronous |
| **Fail Criteria** | modify integrity hash after仍caninstall (integrityCheckbybypass)；lock fileand manifest notsynchronousbutnot alert |
| **Remediation** | ensure npm version >= 7 (increasestrong integrity Check)；in CI inforceUse `npm ci` andnon `npm install` |

### TC-SS-05: Package Signature Verification

| Field | Value |
|------|-----|
| **TestName** | npm Package Signature & Sigstore Verification |
| **Severity** | MEDIUM |
| **Prerequisites** | npm >= v6；already Configure Sigstore/cosign (such as Verifycontainerimage) |
| **Test Steps** | 1. Execute `npm audit signatures` Checkalready installpackage signaturestatus<br>2. Execute `npm install --verify-signatures` Verifyinstallwhen signature<br>3. manual Comparelocalpackageand registry integrity hash<br>4. Use `cosign verify` Verifycontainerimagesignature |
| **Expected Results** | all already signaturepackagethroughVerify；not signaturepackagebymarkaswarning；integrity hash consistent；containerimagesignatureeffective |
| **Fail Criteria** | signatureVerifyby静默jumpover；integrity hash notmatchbutnot alert |
| **Remediation** | upgradelevel npm version；Configure .npmrc forcesignatureVerify；Use Sigstore signatureprocess |

---

## C. CI/CD Security

### TC-SS-06: GitHub Actions Third-party Action Source Verification

| Field | Value |
|------|-----|
| **TestName** | CI Pipeline Third-party Action SHA Pinning Verification |
| **Severity** | HIGH |
| **Prerequisites** | ItemUse GitHub Actions workworkflow |
| **Test Steps** | 1. Scan `.github/workflows/` inall `uses:` introduceuse<br>2. CheckiswhetherUse tag introduceuse (such as `@v3`) andnon commit SHA<br>3. foreach tag introduceuse，Obtainforshould commit SHA: `git ls-remote https://github.com/owner/repo.git refs/tags/v3`<br>4. Verifyall No.third-party Action OpenSSF Scorecard scoring |
| **Expected Results** | all Action introduceuseUsecomplete commit SHA；No.third-party Action Scorecard scoring >= 7；nofrom notcan informationsource Action |
| **Fail Criteria** | exists tag introduceuse (can byhijack)；Usenotcan informationsource Action；Action repositorylibraryalready archiveordelete |
| **Remediation** | willall tag introduceusereplaceas commit SHA；Assessreplacelow质amount Action as官方orhighscoringalternative品 |

### TC-SS-07: GITHUB_TOKEN Permission Minimization Verification

| Field | Value |
|------|-----|
| **TestName** | CI Workflow Permission Scope Review |
| **Severity** | MEDIUM |
| **Prerequisites** | ItemUse GitHub Actions |
| **Test Steps** | 1. Checkrepositorylibrarylevel `permissions` set<br>2. Checkeachworkworkflow `permissions` Field<br>3. Verifyiswhetherfollowleast privilegeoriginalthen (default read-only)<br>4. Checkiswhetherexists `permissions: write-all` orno permissions Field workworkflow |
| **Expected Results** | repositorylibraryleveldefaultpermissionas `contents: read`；eachworkworkflowonlystatement所need least privilege；no `write-all` permission；sensitiveoperationUse OIDC alternativelengthperiodkey |
| **Fail Criteria** | workworkflowmissing `permissions` Field (continue承defaultwritepermission)；Use `write-all`；Uselengthperiodkeyandnon OIDC |
| **Remediation** | inrepositorylibrary Settings > Actions > General insetdefaultpermissionas read-only；aseachworkworkflowadd显style `permissions` Field |

### TC-SS-08: CI/CD Credential Leak Scanning

| Field | Value |
|------|-----|
| **TestName** | Pipeline Configuration & Git History Credential Leak Detection |
| **Severity** | CRITICAL |
| **Prerequisites** | already install gitleaks or trufflehog |
| **Test Steps** | 1. Execute `gitleaks detect --source . --verbose` Scancurrentcode<br>2. Execute `trufflehog git https://github.com/target/repo` Scan Git history<br>3. Check `.github/workflows/` inall environmentvariableand secret Use<br>4. Verifyall secret allthrough `${{ secrets.* }}` introduceuse，nohardencodingValue |
| **Expected Results** | 零credentialsleakage；all secret through GitHub Secrets management；workworkflowlognotprintsensitiveinformation；`.env` filealready in .gitignore in |
| **Fail Criteria** | Discoverhardencoding API key、passwordor token；secret Valueoutputnowinworkworkflowlogin；`.env` filebycommittoversioncontrol |
| **Remediation** | 立i.e.rotationleakage credentials；Use GitHub Secrets storagesensitiveValue；add `.env` to .gitignore；Configurelog屏蔽 |

---

## D. Attack Simulation

### TC-SS-09: Dependency Confusion Attack Simulation

| Field | Value |
|------|-----|
| **TestName** | Dependency Confusion Attack Defense Verification |
| **Severity** | CRITICAL |
| **Prerequisites** | organizationUseprivate npm/PyPI repositorylibrary；already Identifyinternalpackagename |
| **Test Steps** | 1. fromObjectiveapplicationcodeinExtractall internalpackagename<br>2. Checkpublic repositorylibraryiniswhetherexistssamenamepackage: `npm view internal-pkg-name`<br>3. such as notexists，inpublic repositorylibraryregistersamenameTestpackage (onlyprintenvironmentvariable no害 payload)<br>4. innot ConfigureprivaterepositorylibraryPriority environmentinExecute `npm install internal-pkg-name`<br>5. Verifypackagemanagementtoolsolveanalysistopublic repositorylibraryalsoisprivaterepositorylibrary |
| **Expected Results** | Configurecorrectwhen ，privaterepositorylibraryprioritysolveanalysis；not Configurewhen ，public repositorylibrary maliciouspackagebyinstall；defensepolicyblock公共maliciouspackageinstall |
| **Fail Criteria** | Configure privaterepositorylibraryPrioritybut仍solveanalysistopublic repositorylibrary；privaterepositorylibraryreturn退topublic repositorylibrarywhen noalert |
| **Remediation** | Configure `.npmrc` Use scoped registry (`@company:registry`)；pip Configure `index-url` priorityat `extra-index-url`；inprivaterepositorylibraryin预registerall internalpackagename |

### TC-SS-10: Typosquatting Detection & Response

| Field | Value |
|------|-----|
| **TestName** | Typosquatting Package Detection Capability Verification |
| **Severity** | HIGH |
| **Prerequisites** | Itemwith package.json or requirements.txt |
| **Test Steps** | 1. Extractall directdependencyname<br>2. inpublic repositorylibrarySearch拼writesimilar packagename<br>3. Checksimilarpackage metadata: maintenanceerCount、downloadamount、createwhen interval<br>4. Checksimilarpackageiswhethercontainscan suspicious post-install script<br>5. VerifyIteminiswhether误install counterfeitpackage |
| **Expected Results** | all counterfeitpackagebyIdentify；Itemnocounterfeitpackageinstall；Detectprocesscoveringtransmitdependency |
| **Fail Criteria** | existscounterfeitpackagebutnot byDetectto；false positiverateoverhighcauseToolsnotcan use |
| **Remediation** | Use Typosquatting DetectToolsautomated Scan；in CI inintegrationpackagenameVerify；maintenanceorganizationcan informationpackagewhitelist |

---

## E. Hardening Verification

### TC-SS-11: SBOM Generation & Vulnerability Correlation Verification

| Field | Value |
|------|-----|
| **TestName** | SBOM Integrity & Vulnerability Correlation Accuracy |
| **Severity** | MEDIUM |
| **Prerequisites** | already install Syft or Trivy；Itemwith lock file |
| **Test Steps** | 1. Execute `syft ./project -o cyclonedx-json > sbom.json` Generate SBOM<br>2. Statistics SBOM componentCount: `jq '.components \| length' sbom.json`<br>3. andactualdependencyCountCompare (`npm ls --all --json \| jq length`)<br>4. Use Grype Scan SBOM: `grype sbom:./sbom.json --fail-on high`<br>5. Verify Grype report vulnerabilityand Trivy directScanresultconsistent |
| **Expected Results** | SBOM componentCountandactualdependencyconsistent (误差 < 5%)；vulnerability scanningresultanddirectScanhighdegreeconsistent；SBOM containscomplete versionand purl information |
| **Fail Criteria** | SBOM componentCount偏差 > 10%；vulnerability scanningresultanddirectScandifferencesignificant；missingtransmitdependency |
| **Remediation** | ensureGenerate SBOM beforeExecutecomplete dependencyinstall；Check Syft Configureiswhetherexcludespecific生态system |

### TC-SS-12: Build System Security Hardening Verification

| Field | Value |
|------|-----|
| **TestName** | Build Environment Security Baseline Compliance Check |
| **Severity** | MEDIUM |
| **Prerequisites** | buildenvironmentcan access；with CI/CD Configurefile |
| **Test Steps** | 1. Verify `npm ci --ignore-scripts` disableall 生命周periodscript<br>2. Check `.npmrc` Configure: `ignore-scripts=true`, `audit=true`, `audit-level=high`<br>3. Verifyversionlockoutpolicy: `npm config get save-exact` shouldas true<br>4. Check Dockerfile iswhetherUsemultiplephasebuildand distroless basic image<br>5. Verifyall dependencyUsepreciseversionnumber (no `^` or `~` before缀)<br>6. Executecomplete buildprocess，Confirmnoscriptautomated Execute |
| **Expected Results** | all security Configureitemcompliance；buildoverprocessnoscriptautomated Execute；Docker imageminimumize；dependencyversionpreciselockout |
| **Fail Criteria** | security Configuremissingornot 生effect；post-install scriptinbuildinExecute；dependencyversionUsescopesyntax |
| **Remediation** | update `.npmrc` Configurefile；modify Dockerfile Usemultiplephasebuild；Configure `save-exact=true` and重newGenerate lock file |
