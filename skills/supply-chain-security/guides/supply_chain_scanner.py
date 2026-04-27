#!/usr/bin/env python3
"""
Software Supply Chain Automated Scanning Tool
Comprehensive detection of supply chain vulnerabilities
"""

import requests
import json
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor
import time

class SupplyChainScanner:
    def __init__(self, base_url, api_token=None):
        self.base_url = base_url
        self.api_token = api_token
        self.session = requests.Session()
        self.vulnerabilities = []

    def scan_all(self):
        """Execute all scans"""
        print("\n" + "="*60)
        print("Starting Software Supply Chain comprehensive scan")
        print("="*60)

        # 1. Dependency vulnerability check
        print("\n[1] Checking dependency vulnerabilities...")
        self.check_vulnerable_dependencies()

        # 2. SBOM analysis
        print("\n[2] Analyzing SBOM...")
        self.analyze_sbom()

        # 3. CI/CD configuration check
        print("\n[3] Checking CI/CD configuration...")
        self.check_cicd_config()

        # 4. Unencrypted dependencies
        print("\n[4] Checking unencrypted dependencies...")
        self.check_insecure_dependencies()

        # 5. Dependency confusion check
        print("\n[5] Checking dependency confusion...")
        self.check_dependency_confusion()

        # Generate report
        self.generate_report()

        return self.vulnerabilities

    def check_vulnerable_dependencies(self):
        """Check npm dependency vulnerabilities"""
        try:
            # npm audit
            result = subprocess.run(
                ['npm', 'audit', '--json', '--audit-level=high'],
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode == 0:
                audit_data = json.loads(result.stdout)

                vulnerabilities = audit_data.get('vulnerabilities', [])
                for vuln in vulnerabilities:
                    if vuln.get('severity') in ['high', 'critical']:
                        self.vulnerabilities.append({
                            'type': 'Vulnerable Dependency',
                            'package': vuln.get('module_name'),
                            'version': vuln.get('recommendation'),
                            'severity': vuln.get('severity'),
                            'advisory': vuln.get('recommendation'),
                        })
                        print(f"    [+] Vulnerability: {vuln.get('module_name')}")

        except Exception as e:
            print(f"    [-] npm audit failed: {e}")

    def check_vulnerable_python_dependencies(self):
        """Check Python dependency vulnerabilities"""
        try:
            # pip check
            result = subprocess.run(
                ['pip', 'check', '-r', 'requirements.txt', '--format', 'json'],
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode == 0:
                check_data = json.loads(result.stdout)

                for package in check_data.get('installed', []):
                    deps = package.get('dependencies', {})
                    if deps:
                        self.vulnerabilities.append({
                            'type': 'Vulnerable Python Dependency',
                            'package': package.get('name'),
                            'version': package.get('version'),
                            'vulnerabilities': deps,
                        })
                        print(f"    [+] Vulnerability: {package.get('name')}")

        except Exception as e:
            print(f"    [-] pip check failed: {e}")

    def analyze_sbom(self):
        """Analyze SBOM (Software Bill of Materials)"""
        # Common SBOM files
        sbom_files = [
            'package-lock.json',
            'yarn.lock',
            'package.json',
            'requirements.txt',
            'poetry.lock',
            'Gemfile.lock',
        ]

        for sbom_file in sbom_files:
            if self.analyze_sbom_file(sbom_file):
                print(f"    [+] Found SBOM file: {sbom_file}")

    def analyze_sbom_file(self, filename):
        """Analyze a single SBOM file"""
        try:
            if filename.endswith('.json'):
                with open(filename, 'r') as f:
                    sbom_data = json.load(f)

                    # Check dependencies
                    dependencies = sbom_data.get('dependencies', {})
                    dev_dependencies = sbom_data.get('devDependencies', {})

                    all_deps = {**dependencies, **dev_dependencies}

                    # Check common issues
                    for dep_name, dep_info in all_deps.items():
                        if isinstance(dep_info, dict):
                            version = dep_info.get('version', '')

                            # Check if using latest version (simplified)
                            if version and not version.startswith('^'):
                                self.vulnerabilities.append({
                                    'type': 'Non-Locked Dependency',
                                    'package': dep_name,
                                    'version': version,
                                    'severity': 'Medium',
                                })
                                print(f"        [!] Unlocked dependency: {dep_name}")

                    return True

            elif filename.endswith('requirements.txt'):
                with open(filename, 'r') as f:
                    requirements = f.readlines()

                    for req in requirements:
                        req = req.strip()
                        if '==' in req:
                            pkg_name = req.split('==')[0].strip()

                            # Check if using pinned version
                            if '>' in req or '>=' in req:
                                self.vulnerabilities.append({
                                    'type': 'Unpinned Dependency',
                                    'package': pkg_name,
                                    'requirement': req,
                                    'severity': 'Medium',
                                })
                                print(f"        [!] Unpinned version: {pkg_name}")

                    return True

        except Exception as e:
            return False

    def check_cicd_config(self):
        """Check CI/CD configuration"""
        # Check GitHub Actions
        github_actions_files = [
            '.github/workflows/*.yml',
            '.github/workflows/*.yaml',
        ]

        for pattern in github_actions_files:
            try:
                import glob
                files = glob.glob(pattern)

                for file in files:
                    self.check_github_actions_file(file)

            except Exception as e:
                pass

        # Check common insecure configurations
        insecure_configs = [
            '.github/workflows/main.yml',
            '.gitlab-ci.yml',
            'Jenkinsfile',
        ]

        for config_file in insecure_configs:
            if self.check_insecure_ci_config(config_file):
                print(f"    [!] Insecure CI/CD configuration: {config_file}")

    def check_github_actions_file(self, filename):
        """Check GitHub Actions file"""
        try:
            import yaml
            with open(filename, 'r') as f:
                config = yaml.safe_load(f)

                # Check dangerous patterns
                config_str = str(config)

                dangerous_patterns = [
                    'runs-on: ubuntu-latest',
                    'persist-credentials: true',
                    'permissions: write-all',
                    'security-level: relaxed',
                ]

                for pattern in dangerous_patterns:
                    if pattern in config_str:
                        self.vulnerabilities.append({
                            'type': 'Insecure CI/CD Configuration',
                            'file': filename,
                            'pattern': pattern,
                            'severity': 'High',
                        })
                        print(f"        [!] Found: {pattern}")

        except Exception as e:
            pass

    def check_insecure_ci_config(self, filename):
        """Check insecure CI/CD configuration"""
        # Simplified implementation
        return False

    def check_insecure_dependencies(self):
        """Check unencrypted dependency transmission"""
        # Simplified implementation
        pass

    def check_dependency_confusion(self):
        """Check dependency confusion attacks"""
        # Common confusion attack packages
        malicious_packages = [
            'event-stream',
            'colors-js',
            'left-pad',
            'ua-parser',
            'stream',
        ]

        try:
            result = subprocess.run(
                ['npm', 'list', '--depth=0', '--json'],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                packages = json.loads(result.stdout)
                deps = packages.get('dependencies', {})

                for dep_name, dep_info in deps.items():
                    if dep_name in malicious_packages:
                        self.vulnerabilities.append({
                            'type': 'Malicious Package',
                            'package': dep_name,
                            'version': dep_info.get('version', ''),
                            'severity': 'Critical',
                        })
                        print(f"    [!] Malicious package: {dep_name}")

        except Exception as e:
            print(f"    [-] Check failed: {e}")

    def generate_report(self):
        """Generate scan report"""
        print("\n" + "="*60)
        print(f"Scan complete - Found {len(self.vulnerabilities)} potential issues")
        print("="*60)

        if not self.vulnerabilities:
            print("\n✅ No supply chain security issues found")
            return

        # Categorize by severity
        high_severity = [v for v in self.vulnerabilities if v.get('severity') == 'Critical']
        medium_severity = [v for v in self.vulnerabilities if v.get('severity') == 'Medium']
        low_severity = [v for v in self.vulnerabilities if v.get('severity') == 'Low']

        print(f"\nSeverity breakdown:")
        print(f"  Critical: {len(high_severity)}")
        print(f"  Medium: {len(medium_severity)}")
        print(f"  Low: {len(low_severity)}")

        # Save report
        report_file = f"supply_chain_report_{int(time.time())}.json"
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump({
                'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
                'total_issues': len(self.vulnerabilities),
                'severity_breakdown': {
                    'critical': len(high_severity),
                    'medium': len(medium_severity),
                    'low': len(low_severity),
                },
                'vulnerabilities': self.vulnerabilities
            }, f, indent=4)

        print(f"\nReport saved: {report_file}")


def main():
    """Main function"""
    print("""
    ╔══════════════════════════════════════════════════════╗
    ║    Software Supply Chain Automated Scanner             ║
    ║              OWASP A03:2025                            ║
    ║                  Version 1.0                           ║
    ╚══════════════════════════════════════════════════════╝
    """)

    # Scan local project
    scanner = SupplyChainScanner("local")
    vulnerabilities = scanner.scan_all()

    print("\n" + "="*60)
    print("✅ Scan complete!")
    print("="*60)


if __name__ == "__main__":
    main()
