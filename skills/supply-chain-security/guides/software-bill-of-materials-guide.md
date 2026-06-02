# Software Bill of Materials (SBOM) Guide

> Practical reference for generating, analyzing, and leveraging SBOMs using CycloneDX and SPDX formats for vulnerability correlation and supply chain visibility.

---

## 1. SBOM Generation with CycloneDX

CycloneDX is a lightweight SBOM standard designed for security use cases including vulnerability identification and license compliance.

```bash
# Generate CycloneDX SBOM for Node.js project
npm install -g @cyclonedx/cyclonedx-npm
cyclonedx-npm --output-file sbom.json --output-format json
cyclonedx-npm --output-file sbom.xml --output-format xml

# Generate for Python project
pip install cyclonedx-bom
cyclonedx-py requirements --input-file requirements.txt --output-file sbom.json --format json

# Generate from pip environment
cyclonedx-py environment --output-file sbom.json --format json

# Generate for Go project
go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@latest
cyclonedx-gomod mod -json -output sbom.json

# Generate for container images
syft alpine:latest -o cyclonedx-json > container-sbom.json
```

```bash
# Validate generated SBOM against CycloneDX schema
npm install -g @cyclonedx/cyclonedx-cli
cyclonedx validate --input-file sbom.json --input-format json --fail-on-errors

# Enrich SBOM with additional metadata
cyclonedx merge --input-files sbom.json additional-components.json --output-file enriched-sbom.json
```

---

## 2. SPDX Format Generation

```bash
# Generate SPDX SBOM using syft (supports multiple ecosystems)
syft . -o spdx-json > sbom-spdx.json
syft . -o spdx-tag-value > sbom.spdx

# Generate SPDX for container image
syft docker:myapp:latest -o spdx-json > container-sbom-spdx.json

# Generate SPDX from package-lock.json specifically
syft file:package-lock.json -o spdx-json > lockfile-sbom.json

# Convert between SBOM formats
# CycloneDX to SPDX (using cdx2spdx or sbom-tool)
pip install sbom-convert
sbom-convert --input sbom-cyclonedx.json --output sbom-spdx.json --format spdx
```

```json
{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "myapp-sbom",
  "documentNamespace": "https://company.com/sbom/myapp-1.0.0",
  "packages": [
    {
      "SPDXID": "SPDXRef-Package-express-4.18.2",
      "name": "express",
      "versionInfo": "4.18.2",
      "supplier": "Organization: OpenJS Foundation",
      "downloadLocation": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
      "checksums": [
        {
          "algorithm": "SHA256",
          "checksumValue": "abc123..."
        }
      ],
      "licenseConcluded": "MIT",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:npm/express@4.18.2"
        }
      ]
    }
  ]
}
```

---

## 3. Vulnerability Correlation

```python
# Correlate SBOM components with known vulnerabilities using OSV
import requests
import json

def load_sbom(filepath):
    with open(filepath) as f:
        return json.load(f)

def query_osv(package_name, version, ecosystem):
    """Query OSV.dev for known vulnerabilities."""
    resp = requests.post("https://api.osv.dev/v1/query", json={
        "package": {"name": package_name, "ecosystem": ecosystem},
        "version": version,
    })
    if resp.status_code == 200:
        return resp.json().get("vulns", [])
    return []

def scan_cyclonedx_sbom(sbom_path):
    sbom = load_sbom(sbom_path)
    components = sbom.get("components", [])
    findings = []
    
    for comp in components:
        name = comp.get("name", "")
        version = comp.get("version", "")
        purl = comp.get("purl", "")
        
        # Determine ecosystem from purl
        ecosystem = "npm"  # Default; parse from purl in production
        if "pkg:pypi" in purl:
            ecosystem = "PyPI"
        elif "pkg:golang" in purl:
            ecosystem = "Go"
        
        vulns = query_osv(name, version, ecosystem)
        if vulns:
            findings.append({
                "component": f"{name}@{version}",
                "vulnerabilities": len(vulns),
                "critical": [v for v in vulns if any(
                    s.get("severity", [{}])[0].get("score", 0) >= 9.0 
                    for s in v.get("affected", [{}])
                )],
                "ids": [v.get("id") for v in vulns],
            })
    
    return findings

results = scan_cyclonedx_sbom("sbom.json")
for r in results:
    severity = "CRITICAL" if r["critical"] else "HIGH" if r["vulnerabilities"] > 2 else "MEDIUM"
    print(f"[{severity}] {r['component']}: {r['vulnerabilities']} vulns ({', '.join(r['ids'][:3])})")
```

---

## 4. SBOM Diff and Drift Detection

```bash
# Compare SBOMs between releases to detect unexpected changes
# Using cyclonedx-cli diff
cyclonedx diff --from sbom-v1.0.json --to sbom-v1.1.json --output-format json > sbom-diff.json

# Manual diff using jq
# Extract component list from each SBOM
jq '[.components[] | {name, version}] | sort_by(.name)' sbom-v1.0.json > components-v1.json
jq '[.components[] | {name, version}] | sort_by(.name)' sbom-v1.1.json > components-v2.json

# Find added dependencies
diff <(jq -r '.[].name' components-v1.json) <(jq -r '.[].name' components-v2.json) | grep "^>"

# Find version changes
diff components-v1.json components-v2.json
```

```python
# Automated SBOM drift monitoring in CI/CD
import json
import sys

def compare_sboms(baseline_path, current_path):
    with open(baseline_path) as f:
        baseline = json.load(f)
    with open(current_path) as f:
        current = json.load(f)
    
    baseline_deps = {c["purl"]: c for c in baseline.get("components", []) if c.get("purl")}
    current_deps = {c["purl"]: c for c in current.get("components", []) if c.get("purl")}
    
    added = set(current_deps.keys()) - set(baseline_deps.keys())
    removed = set(baseline_deps.keys()) - set(current_deps.keys())
    
    report = {"added": [], "removed": [], "changed": []}
    
    for purl in added:
        comp = current_deps[purl]
        report["added"].append(f"{comp['name']}@{comp.get('version', '?')}")
    
    for purl in removed:
        comp = baseline_deps[purl]
        report["removed"].append(f"{comp['name']}@{comp.get('version', '?')}")
    
    if report["added"]:
        print(f"NEW DEPENDENCIES ({len(report['added'])}):")
        for dep in report["added"]:
            print(f"  + {dep}")
    
    if report["removed"]:
        print(f"REMOVED DEPENDENCIES ({len(report['removed'])}):")
        for dep in report["removed"]:
            print(f"  - {dep}")
    
    # Fail CI if unexpected additions
    if report["added"] and "--strict" in sys.argv:
        sys.exit(1)

compare_sboms("sbom-baseline.json", "sbom-current.json")
```

---

## 5. CI/CD Integration

```yaml
# GitHub Actions workflow for SBOM generation and scanning
name: SBOM Generation and Vulnerability Scan
on:
  push:
    branches: [main]
  pull_request:

jobs:
  sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Generate SBOM
        uses: anchore/sbom-action@v0
        with:
          format: cyclonedx-json
          output-file: sbom.json
          
      - name: Scan for vulnerabilities
        uses: anchore/scan-action@v4
        with:
          sbom: sbom.json
          fail-build: true
          severity-cutoff: high
          
      - name: Compare with baseline
        run: |
          if [ -f sbom-baseline.json ]; then
            python scripts/sbom-diff.py sbom-baseline.json sbom.json --strict
          fi
          
      - name: Upload SBOM artifact
        uses: actions/upload-artifact@v4
        with:
          name: sbom-${{ github.sha }}
          path: sbom.json
          
      - name: Publish to dependency track
        run: |
          curl -X POST "https://deptrack.company.com/api/v1/bom" \
            -H "X-Api-Key: ${{ secrets.DEPTRACK_API_KEY }}" \
            -H "Content-Type: multipart/form-data" \
            -F "project=${{ github.repository }}" \
            -F "bom=@sbom.json"
```

---

## 6. License Compliance Analysis

```bash
# Extract license information from SBOM
jq '[.components[] | {name, version, license: (.licenses // [] | map(.license.id // .license.name // "UNKNOWN") | join(", "))}] | sort_by(.name)' sbom.json

# Flag copyleft licenses that may conflict with proprietary code
jq '.components[] | select(.licenses[]?.license.id | test("GPL|AGPL|LGPL|SSPL|EUPL")) | {name, version, license: .licenses[].license.id}' sbom.json

# Generate license summary report
jq '[.components[].licenses[]?.license.id // "UNKNOWN"] | group_by(.) | map({license: .[0], count: length}) | sort_by(-.count)' sbom.json
```

SBOMs provide critical visibility into software composition. Generate them automatically in CI/CD pipelines, store them as build artifacts, and continuously correlate against vulnerability databases for proactive risk management.

## References

- [CycloneDX Specification](https://cyclonedx.org/specification/overview/)
- [SPDX Specification](https://spdx.dev/specifications/)
- [SLSA Framework](https://slsa.dev/spec/v1.0/)
- [OWASP Supply Chain Integrity](https://owasp.org/www-project-supply-chain-integrity/)
- [Sigstore - Software Supply Chain Security](https://www.sigstore.dev/)
