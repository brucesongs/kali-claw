# OWASP Top 10 2025 - A03: Software Supply Chain completeguide

## Learning Objectives
Mastercore principles, attack techniques, and defense methods of software supply chain security

---

## 1. Software Supply Chain Failures Overview

### 1.1 whatissoftwarepiece供shouldchain？
softwarepiece供shouldchain（Software Supply Chain）ispointfromdevelopment、Test、deploymenttomaintenance entiresoftwarepiece生命周periodin涉and all component、processandpractice。

**critical要素**:
- **供should商**: No.third-partylibraryandcomponentProvides商
- **dependency**: open-source/闭sourcesoftwarepiecepackage
- **Toolchain**: CI/CD、buildTool
- **process**: development、Test、deploymentprocess

### 1.2 aswhatis Supply Chain Failures？
softwarepiece供shouldchainfailureispoint：
- Usebandhasalready knowVulnerability No.third-partycomponent
- dependencyobfuscationAttack
- maliciouspackageinjection
- CI/CD pipelineSecuritynotenough
- notSecurity image
- not throughVerification code

---

## 2. Supply Chain Failures Type

### 2.1 dependencyobfuscationAttack
**definition**: Attackercreatemaliciouspackage，induceSystemInstallationerror package

**Attack Steps**:
```
1. Attack者在公共包仓库发布恶意包（如 malicious-package）
2. 包名模仿合法包（如 legitimate-package）
3. TargetSystemInstallation恶意包
4. 恶意包执行恶意代码
```

**realcase**:
- **event-stream (2021)**: Python packagemanagementtoolby攻
 - maliciouspackage: `event-streamer`
 - Through `event-streamer` packagerelease，RequestInstallationamountIncrease

### 2.2 maliciouspackageinjection
**definition**: inpackagerepositorylibraryininjectionmaliciouscode

**common method**:
```
1. 直接提交恶意代码
2. 替持合法包（typosquatting）
3. Through CI/CD pipeline 注入
4. Through post-install 脚本注入
```

**realcase**:
- **colors-js (2021)**: Through colors.js library maliciousTool
 - maliciouscodestealEnvironmentvariable
 - remotecode execution

- **left-pad (2021)**: Through CI/CD pipeline injection
 - Through `preinstall` scriptexecutemaliciouscode

- **ua-parser (2022)**: Through typosquatting injection（`@playform/iframe`） 植inputmaliciouscode

### 2.3 CI/CD pipelineSecuritynotenough
**definition**: CI/CD pipelinelack ofSecuritycontrol

**common problem**:
```
1. 未Verification的第三方组件
2. 不Security的构建脚本
3. 皲气凭未Check
4. 缺少Access控制
5. Sensitive Information泄露
6. 依赖锁定机制缺失
```

**realcase**:
- **Codecov (2021)**: Through CI/CD pipelineexecutemaliciouscode
 - impactnumber千repositorylibrary

- **SolarWinds (2020)**: Through CI/CD pipeline植inputafter门
 - remoteAccesscustomerNetwork

- **Dependency-Confusion (2023)**: multiple npm packagebyhijack
 - impactnumber百万User

### 2.4 not encryption dependency
**definition**: Use HTTP transmissionnot encryption dependencypackage

**Attack Method**:
```
1. 中间人Attack（MITM）
2. 依赖劫持（DNS 劫持）
3. 会话劫持
```

---

## 3. Supply Chain Failures DetectionTechniques

### 3.1 dependencyVulnerabilityDetection
**Tool**: `npm audit`, `yarn audit`, `pip check`, `safety check`

```bash
# Check npm dependency
npm audit --json

# Check yarn dependency
yarn audit --json

# Check Python dependency
pip check safety
safety check -r requirements.txt
```

### 3.2 SBOM Analysis
**Software Bill of Materials (SBOM)**: softwarepiece物料checklist

**Generation SBOM**:
```bash
# npm SBOM
npm sbom

# orUseTool
trivy --sbom --json . > sbom.json

# Analysis SBOM
jq sbom.json | python3 -c "
import sys, json
sbom = json.load(sys.stdin)
print(f\"Components: {len(sbom['components'])}\")
for comp in sbom['components']:
    print(f\"  - {comp['name']}: {comp['version']}\")
"
```

---

## 4. Supply Chain Failures Defense

### 4.1 dependencylockout
```json
// package-lock.json
{
  "name": "my-app",
  "version": "1.0.0",
  "lockfileVersion": 1,
  "requires": true,
  "dependencies": {
    "lodash": {
      "version": "4.17.21",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
      "integrity": "sha512-...",
      "integrityAlgorithm": "sha512"
    }
  }
}
```

### 4.2 Useprivaterepositorylibrary
```bash
# Configuration npm privaterepositorylibrary
npm config set registry https://npm.yourcompany.com/

# Configuration yarn source
echo "registry \"https://npm.yourcompany.com\"" > .yarnrc
```

### 4.3 CI/CD Security Configuration
```yaml
# GitHub Actions Example
name: Secure Build

on:
  push:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v2
      
      - name: Install dependencies securely
        run: |
          npm ci --prefer-offline --no-audit
      
      - name: Audit dependencies
        run: |
          npm audit --audit-level=high
```

---

## 5. Learning Checklist

### Theory Mastery
- [x] understandsoftwarepiece供shouldchainconcept
- [x] MasterdependencyobfuscationAttack
- [x] Master CI/CD Securitynotenough

### Practical Skills
- [x] dependencyVulnerabilityDetection
- [x] SBOM Analysis
- [x] Security Configuration

### Defense Capabilities
- [x] dependencylockout
- [x] privaterepositorylibraryConfiguration
- [x] CI/CD Security Configuration

---

**Document Version**: 1.0
**Created**: 2026-03-26 19:00
**Learningwhen length**: estimated 4-5.0 Hours
**Learning Status**: 🟢 Complete
