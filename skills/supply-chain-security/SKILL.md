# Skill: Software Supply Chain Security

> **Supplementary Files**:
> - `payloads.md` — Supply chain security testing commands and payloads categorized by dependency scanning, package integrity, typosquatting detection, CI/CD auditing, SBOM analysis, dependency confusion attacks, etc.
> - `test-cases.md` — Structured test case list with severity classification and statistics

## Description

Software Supply Chain Security covers security issues across the entire lifecycle from code development to deployment — including dependency vulnerabilities (known-vulnerable third-party dependencies), malicious packages (malicious package injection and typosquatting), CI/CD pipeline attacks (build pipeline hijacking and backdoor injection), and code injection via dependencies (code injection propagated through dependency chains). Due to their "one breach, widespread impact" nature, software supply chain attacks have become one of the most destructive attack vectors.

**Core Attack Types**:

- **Dependency Confusion**: Attackers publish malicious packages with the same name as internal private packages on public registries, exploiting package manager resolution priority to trick targets into installing malicious code. Notable case: In 2021, Alex Birsan used this technique to breach Apple, Microsoft, PayPal, and other enterprises.
- **Typosquatting**: Registering malicious packages with names highly similar to popular packages (e.g., `lodash` vs `lodassh`), exploiting developer typos to plant backdoors.
- **CI/CD Pipeline Compromise**: By poisoning build tools, hijacking update scripts, or stealing CI/CD credentials, backdoors are planted during the software build phase. Notable cases: SolarWinds (2020) affected 18,000+ organizations; Codecov (2021) tampered with a bash upload script to steal environment variables.
- **Maintainer Account Takeover**: Gaining control of legitimate package maintainer accounts to inject malicious code into existing packages. Notable case: `ua-parser-js` (2021) was hijacked to install cryptocurrency mining and credential-stealing trojans.

---

## Use Cases

1. **Project Dependency Security Audit**: Systematically scan all direct and transitive dependencies of a project, identify known vulnerabilities (CVEs), license risks, and abandoned packages, and generate a remediation priority report.
2. **Malicious Package Detection and Response**: Detect typosquatting, post-install script injection, suspicious network requests, and other malicious behavior patterns within organizational npm/PyPI private registries.
3. **CI/CD Pipeline Security Hardening**: Review GitHub Actions / GitLab CI / Jenkins Pipeline configurations to identify insecure `fetch-depth`, unverified third-party Actions, secret leakage, and deployment workflows lacking signature verification.
4. **SBOM Generation and Management**: Generate Software Bills of Materials for software artifacts, achieving complete visibility into the dependency chain and meeting compliance requirements (e.g., US Executive Order 14028).
5. **Red Team Supply Chain Attack Simulation**: Test organizational supply chain defenses through dependency confusion, malicious package injection, and other techniques, validating the effectiveness of SCA tools and private registry policies.

---

## Core Tools

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **Trivy** | Comprehensive container/filesystem/Git repository vulnerability scanning with SBOM generation | `trivy fs --severity HIGH,CRITICAL ./project` |
| **Snyk** | SaaS dependency vulnerability scanning with remediation advice, supporting multiple languages and CI integration | `snyk test --all-projects --severity-threshold=high` |
| **Dependabot** | GitHub-native automated dependency updates and vulnerability alerts | `.github/dependabot.yml` configuration for automated PR updates |
| **OWASP Dependency-Check** | Open-source SCA tool using NVD database for known vulnerability detection | `dependency-check --scan ./project --out report.html` |
| **npm audit** | Built-in Node.js dependency vulnerability detection | `npm audit --audit-level=high --json` |
| **Safety / pip-audit** | Python dependency vulnerability scanning based on known vulnerability databases | `safety check -r requirements.txt --json` |

Supporting tools: **Syft** (SBOM generation), **Grype** (SBOM vulnerability scanning), **Sigstore** (package signature verification), **in-toto** (supply chain integrity verification), **OSV Scanner** (Google open-source vulnerability scanner).

---

## Methodology

### Attack Chain

```
[1] Dependency Analysis   [2] Vulnerability Mapping  [3] Malicious Package Detection
  - Direct/transitive       - CVE database matching     - Typosquatting identification
    dependency enumeration  - CVSS score assessment     - post-install script auditing
  - Version range           - Exploit feasibility       - Anomalous network request
    identification            analysis                    detection
  - Lock file integrity    - Patch version locating    - Maintainer trustworthiness
  - Abandoned/zombie                                    assessment
    dependencies                   |                        |
       |                           v                        v
       v                       [4] CI/CD Pipeline Review  [5] Build Integrity Verification
                                - Third-party Action        - Build reproducibility
                                  provenance                - Signature verification
                                - Secret management         (Sigstore)
                                - Permission model          - SBOM consistency
                                  (GITHUB_TOKEN)              verification
                                - Supply chain policy       - in-toto layout
                                  configuration               verification
```

### Defense Perspective

| Defense Layer | Measure | Key Points |
|---------------|---------|------------|
| **Lock Files** | `package-lock.json`, `yarn.lock`, `Pipfile.lock` | Lock exact versions and integrity hashes to prevent dependency resolution tampering; must be committed to version control |
| **Signature Verification** | npm `--verify-signatures`, Sigstore/cosign | Verify cryptographic signatures of packages to confirm trusted provenance and untampered content |
| **SBOM (Software Bill of Materials)** | SPDX / CycloneDX format | Complete record of all dependency components, versions, and suppliers for rapid vulnerability identification |
| **SCA Tools** | Trivy, Snyk, OWASP Dependency-Check | Automated continuous dependency vulnerability scanning integrated into CI/CD pipelines |
| **Version Pinning** | Exact version numbers instead of ranges (`1.2.3` not `^1.2.3`) | Prevent automatic resolution to hijacked new versions; use in conjunction with lock files |
| **Private Registry** | Private npm/PyPI repositories with priority resolution for internal packages | Defense against Dependency Confusion attacks; private packages take priority over public ones |
| **CI/CD Hardening** | Least privilege, Action provenance verification, secret scanning | Restrict GITHUB_TOKEN permissions, verify third-party Action SHAs, use OIDC instead of long-lived secrets |

---

## Practical Steps

### 1. Dependency Vulnerability Scanning

Use Trivy, npm audit, pip-audit, and other tools to scan project dependencies, identify HIGH/CRITICAL level vulnerabilities, and generate JSON/HTML format reports. Supports multiple scan targets including filesystems, lock files, and Git repositories.

### 2. Malicious Package Detection

Check post-install script injection points, audit anomalous packages in transitive dependency trees, evaluate package maintainer information and download counts, use Syft + Grype to generate SBOMs and scan for known malicious packages.

### 3. CI/CD Pipeline Security Review

Verify third-party Actions use commit SHA instead of tags, restrict GITHUB_TOKEN to minimum permissions, integrate dependency auditing into CI pipelines, disable automatic post-install script execution.

### 4. SBOM Generation and Vulnerability Correlation

Use npm sbom or Trivy to generate CycloneDX format SBOMs, scan SBOMs for correlated vulnerabilities, analyze component counts and risk distribution.

### 5. Dependency Confusion Attack Simulation

Register malicious packages with the same name as internal packages on public registries, test private registry resolution priority, verify the effectiveness of dependency confusion defense strategies.

> **Detailed payloads in `payloads.md`, complete test checklist in `test-cases.md`.**

---

## Hacker Laws

- **Trust but Verify**: Supply chain attacks exploit trust relationships — developers trust packages on npm/PyPI, CI/CD trusts third-party Actions, and build systems trust upstream dependencies. Security policies must independently verify at every layer: package signature verification, lock file integrity checks, and Action commit SHA pinning. Trust is the starting point of the attack surface.
- **Defense in Depth**: A single defense is insufficient to cover the supply chain attack surface. You must combine lock files + private registries + SCA scanning + CI/CD permission controls + SBOM management + signature verification to form a multi-layered defense. When each layer fails independently, the next layer still provides protection.
- **Murphy's Security Law**: If a dependency has a vulnerability, attackers will exploit it. Software projects contain hundreds of transitive dependencies on average, and among them there will inevitably be known vulnerabilities or abandoned components. Proactive scanning and continuous monitoring are not optional — they are necessities.

---

## Learning Resources

- **OWASP Supply Chain Security**: https://owasp.org/www-project-software-supply-chain-security/ (Supply chain security maturity model and best practices)
- **SLSA Framework**: https://slsa.dev/ (Supply-chain Levels for Software Artifacts, Google-led supply chain integrity framework)
- **Sigstore**: https://www.sigstore.dev/ (Free and open-source software signing and verification infrastructure)
- **OpenSSF Scorecard**: https://securityscorecards.dev/ (Open-source project security health scoring tool)
- **PortSwigger - Supply Chain Attacks**: https://portswigger.net/web-security/learning-paths (Includes CI/CD attack labs)
- **CNCF Software Supply Chain Best Practices**: https://project.linuxfoundation.org/hubfs/CNCF_SSCBP.pdf (Cloud-native supply chain security whitepaper)

**This skill's supplementary files**: `payloads.md`, `test-cases.md`
**Related skills**: `skills/container-security/SKILL.md`, `skills/binary-reverse/SKILL.md`
**External resources**: https://owasp.org/www-project-software-supply-chain-security/, https://slsa.dev/, https://www.sigstore.dev/, https://securityscorecards.dev/

## Common Pitfalls

Many organizations adopt SCA tools but fail to configure them properly, resulting in false-positive fatigue that leads teams to ignore genuine critical alerts. A frequent mistake is pinning dependency versions without also verifying lock file integrity hashes, which leaves the door open for registry-level tampering. Another common oversight is configuring private registries for internal packages but forgetting to block the public registry fallback path, negating the defense against dependency confusion attacks entirely.

## Detection Methods

Effective supply chain compromise detection combines multiple signals: monitoring npm/PyPI for newly published packages with names similar to your internal packages, alerting on post-install scripts that invoke `child_process` or `os.system`, and tracking maintainer ownership changes on critical dependencies. Continuous SBOM diffing between releases surfaces unexpected dependency additions or version regressions. Integrating Sigstore-based signature verification into CI pipelines provides build-time assurance that artifacts have not been tampered with between stages.

## Automation and Scripting

Supply chain security at scale requires automation across every stage of the development lifecycle. Pre-commit hooks can run `gitleaks` and `npm audit` before code enters the repository. CI pipelines should generate SBOMs with Syft, scan them with Grype, and fail builds on critical findings. Scheduled cron jobs can poll public registries for typosquat candidates matching internal package names and alert the security team within minutes. Automated PR generation via Renovate or Dependabot keeps dependencies current without developer toil, reducing the window of exposure to known vulnerabilities.

---

**Workspace related documents**:
- `guides/software_supply_chain_complete_guide.md` -- OWASP A03 supply chain security complete learning guide
