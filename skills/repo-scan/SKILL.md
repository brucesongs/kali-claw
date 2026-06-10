---
name: repo-scan
description: "Cross-stack source code asset audit that classifies every file, detects embedded third-party libraries, and delivers actionable verdicts per module."
origin: openclaw
version: "0.1.18"
compatibility:
  - openclaw
  - claude-code
  - cursor
  - windsurf
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
  - WebSearch
  - WebFetch
  - Agent
metadata:
  domain: assessment
  tool_count: 0
  guide_count: 5
---




# Skill: Repository Scan — Cross-Stack Source Code Audit

> **Supplementary Files**:
> - `payloads.md` — Repository scanning commands, classification scripts, and analysis payloads organized by scan phase
> - `test-cases.md` — Structured test cases for surface classification, dependency detection, hotspot mapping, and complete audit workflows

## Summary

Repo Scan skill domain covering assessment operations.

**Domain**: assessment

## Description

Cross-stack source code asset audit that classifies every file, detects embedded third-party libraries, and delivers actionable verdicts per module. This skill is used during white-box penetration testing and security code reviews to understand what code is present, what's third-party, and where security risks may hide.

Difference from `security-review`: security-review provides a checklist for auditing security patterns. This skill focuses on mapping and classifying the codebase itself — understanding what code exists, what's custom vs third-party, and where to focus security analysis.

## Use Cases

- White-box penetration test preparation: understand the target codebase structure before deep analysis
- Open-source security audit: map the attack surface of a project before hunting vulnerabilities
- Third-party library inventory: identify embedded dependencies with known vulnerabilities
- M&A security due diligence: assess code quality and security of an acquired codebase
- Supply chain audit: verify what third-party code is actually running in the target

## Core Tools

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| semgrep | Pattern-based static analysis | `semgrep --config=auto --json .` |
| trivy | Dependency and container scanning | `trivy fs .` |
| grype | Vulnerability matching for packages | `grype dir:.` |
| trufflehog | Secret scanning in git history | `trufflehog git file://. --since-commit HEAD~100` |
| gitleaks | Git secret detection | `gitleaks detect --source .` |
| cloc | Line counting by language | `cloc --by-file .` |
| gh | GitHub code search and analysis | `gh search code "<pattern>" --language python` |

## Methodology

### Repo Scan Four-Phase Process

**Phase 1: Surface Classification**

Enumerate and tag every file:

```bash
# Count lines of code by language
cloc --by-file . --json

# Identify file types and structure
find . -type f | sed 's/.*\.//' | sort | uniq -c | sort -rn

# Detect third-party directories
find . -type d \( -name "vendor" -o -name "node_modules" -o -name "third_party" -o -name "external" -o -name "libs" -o -name "deps" \)
```

Classify each file as:
- **Project code** — written by the project authors
- **Third-party code** — embedded libraries, vendored dependencies
- **Build artifacts** — compiled output, generated files
- **Configuration** — settings, deployment files
- **Test code** — test fixtures, mock data

**Phase 2: Library Detection**

Identify embedded third-party libraries:

```bash
# Scan for known libraries and CVEs
trivy fs --scanners vuln .
grype dir:. --output json

# Check specific library versions
grep -r "version" vendor/*/package.json
grep -r "VERSION" libs/*/*.h
```

**Phase 3: Security Hotspot Analysis**

Focus review on high-value targets:

```bash
# Find authentication-related code
grep -rn "password\|auth\|token\|session\|login" --include="*.py" --include="*.js" --include="*.java" .

# Find database interaction
grep -rn "query\|execute\|cursor\|select\|insert\|update" --include="*.py" .

# Find file operations
grep -rn "open(\|readfile\|upload\|download\|include\(" --include="*.php" .

# Secret scanning
trufflehog filesystem . --json
gitleaks detect --source . --report-format json
```

**Phase 4: Verdict and Report**

Assign verdicts per module:

| Verdict | Meaning | Action |
|---------|---------|--------|
| **Core Asset** | Custom business logic, high security value | Deep security review required |
| **Extract & Update** | Vendored library, should be managed dependency | Replace with package manager; check CVEs |
| **Rebuild** | Duplicated or outdated wrapper code | Refactor; apply current security patterns |
| **Deprecate** | Dead code, unused modules | Remove to reduce attack surface |

### Cross-Stack Coverage

| Stack | Key Files | Security Focus |
|-------|-----------|----------------|
| C/C++ | Makefile, CMakeLists.txt, *.c, *.h | Buffer overflows, memory management |
| Java/Android | build.gradle, pom.xml, *.java | Deserialization, SQL injection |
| iOS | Podfile, *.swift, *.m | Keychain usage, certificate pinning |
| Web (JS/TS) | package.json, *.js, *.ts | XSS, prototype pollution, supply chain |
| Python | requirements.txt, *.py | Pickle deserialization, command injection |
| Go | go.mod, *.go | Race conditions, unsafe operations |
| PHP | composer.json, *.php | SQL injection, file inclusion |
| Rust | Cargo.toml, *.rs | Unsafe blocks, dependency auditing |

### Defense Perspective

- **Inventory everything**: You can't secure what you don't know exists
- **Pin dependencies**: Lock exact versions to prevent supply chain attacks
- **Remove dead code**: Every line of code is a potential attack surface
- **Separate concerns**: Third-party code should be isolated from business logic
- **Automate scanning**: Integrate repo scanning into CI/CD pipelines

## Report Template

```markdown
# Repository Scan Report
*Target: [repo/project] | Date: [date] | Depth: [fast/standard/deep]*

## Executive Summary
[Total files, languages, third-party ratio, key findings]

## Classification Summary
| Category | Files | Lines of Code | Percentage |
|----------|-------|---------------|------------|
| Project Code | N | N | N% |
| Third-Party | N | N | N% |
| Build Artifacts | N | N | N% |

## Detected Libraries
| Library | Version | Known CVEs | Status |
|---------|---------|------------|--------|
| [Name] | [X.Y.Z] | [N CVEs] | [Outdated/Current] |

## Module Verdicts
| Module | Verdict | Rationale | Security Priority |
|--------|---------|-----------|-------------------|
| [Name] | Core Asset / Extract / Rebuild / Deprecate | [Why] | [High/Med/Low] |

## Security Hotspots
[High-priority files/directories for deep security review]

## Recommendations
[Prioritized action items based on verdicts and findings]
```

## Orchestration

### ECC Loop Pattern
- **Pattern**: Batch Processing (classify → detect → map → scan → verdict across multiple files/modules)
- **Rationale**: Repository scanning processes many files in batch — classification, dependency detection, and hotspot analysis all operate across the entire codebase simultaneously
- **Integration**: security-review (consumes repo-scan output for targeted review), terminal-ops (evidence capture), continuous-learning (pattern extraction from scan results)

### Cross-Skill Pipeline
```
repo-scan → security-review → verification-loop → chronicle
    ↓                                                          ↑
search-first (find tools)                continuous-learning (persist patterns)
```

### Quality Gate
- Pre-condition: Repository accessible, scanning tools installed
- Post-condition: All files classified, dependencies inventoried, hotspots mapped, verdicts assigned
- Verification: Third-party ratio calculated, secret scan completed, report generated
