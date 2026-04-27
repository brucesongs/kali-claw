#!/usr/bin/env python3
"""
Cryptographic Failure Automated Detection Tool
Detects various cryptographic security issues
"""

import requests
import json
import jwt
import hashlib
import re
from concurrent.futures import ThreadPoolExecutor
import time

class CryptographicFailureScanner:
    """Cryptographic Failure Scanner"""

    def __init__(self, base_url, jwt_token=None):
        self.base_url = base_url
        self.jwt_token = jwt_token
        self.session = requests.Session()
        self.vulnerabilities = []

    def scan_all(self):
        """Execute all scans"""
        print("\n" + "="*60)
        print("Starting Cryptographic Failures comprehensive scan")
        print("="*60)

        # 1. JWT security check
        print("\n[1] JWT security check...")
        self.scan_jwt_security()

        # 2. Crypto mode check
        print("\n[2] Crypto mode check...")
        self.scan_crypto_modes()

        # 3. Key management check
        print("\n[3] Key management check...")
        self.scan_key_management()

        # Generate report
        self.generate_report()

        return self.vulnerabilities

    def scan_jwt_security(self):
        """Scan JWT security issues"""
        if not self.jwt_token:
            print("    [-] No JWT token provided")
            return

        try:
            # Decode JWT
            decoded = jwt.decode(self.jwt_token, options={"verify_signature": False})

            # Check algorithm
            if 'alg' in decoded:
                alg = decoded['alg']

                if alg == 'none':
                    self.vulnerabilities.append({
                        'type': 'JWT Algorithm None',
                        'algorithm': alg,
                        'severity': 'Critical'
                    })
                    print(f"    [+] JWT uses none algorithm")

                elif alg.startswith('HS'):
                    hash_alg = alg.split('(')[0] if '(' in alg else alg

                    weak_algorithms = ['HS256', 'HS384', 'HS512']
                    if hash_alg in weak_algorithms:
                        self.vulnerabilities.append({
                            'type': 'Weak JWT Algorithm',
                            'algorithm': alg,
                            'severity': 'Medium'
                        })
                        print(f"    [+] JWT uses weak algorithm: {alg}")

            # Check expiration time
            if 'exp' not in decoded:
                self.vulnerabilities.append({
                    'type': 'JWT No Expiration',
                    'severity': 'High'
                })
                print(f"    [+] JWT missing expiration time")

            # Check sensitive claims
            sensitive_claims = ['admin', 'root', 'superuser', 'is_admin']
            for claim in sensitive_claims:
                if claim in decoded:
                    self.vulnerabilities.append({
                        'type': 'Sensitive JWT Claim',
                        'claim': claim,
                        'value': str(decoded[claim]),
                        'severity': 'High'
                    })
                    print(f"    [+] JWT sensitive claim: {claim}")

        except Exception as e:
            print(f"    [-] JWT parsing failed: {e}")

    def scan_crypto_modes(self):
        """Scan crypto mode issues"""
        # Check ECB mode
        # Check fixed IV
        # Check no padding
        print("    [+] Crypto mode check (requires more context)")

    def scan_key_management(self):
        """Scan key management issues"""
        # Check if key is hardcoded
        # Check if key is transmitted unencrypted
        # Check key rotation
        print("    [+] Key management check (requires more context)")

    def generate_report(self):
        """Generate scan report"""
        print("\n" + "="*60)
        print(f"Scan complete - Found {len(self.vulnerabilities)} issues")
        print("="*60)

        # Save report
        report_file = f"crypto_failures_report_{int(time.time())}.json"
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump({
                'target': self.base_url,
                'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
                'jwt_token': self.jwt_token,
                'total_vulnerabilities': len(self.vulnerabilities),
                'vulnerabilities': self.vulnerabilities
            }, f, indent=4, ensure_ascii=False)

        print(f"\nReport saved: {report_file}")

        # Generate Markdown report
        md_content = f"""# Cryptographic Failures Scan Report

## Target
- **URL**: {self.base_url}
- **Scan Time**: {time.strftime('%Y-%m-%d %H:%M:%S')}
- **Total Issues**: {len(self.vulnerabilities)}

## Issues List

"""

        for idx, vuln in enumerate(self.vulnerabilities, 1):
            md_content += f"""### {idx}. {vuln['type']}

- **Severity**: {vuln.get('severity', 'Unknown')}
"""

            if 'algorithm' in vuln:
                md_content += f"- **Algorithm**: {vuln['algorithm']}\n"

            if 'claim' in vuln:
                md_content += f"- **Claim**: {vuln['claim']} = {vuln['value']}\n"

            md_content += "\n"

        # Save Markdown report
        md_file = report_file.replace('.json', '.md')
        with open(md_file, 'w', encoding='utf-8') as f:
            f.write(md_content)

        print(f"Markdown report saved: {md_file}")


def main():
    """Main function"""
    print("""
    ╔══════════════════════════════════════════════════════╗
    ║     Cryptographic Failure Automated Detection Tool    ║
    ║           OWASP A04:2025                             ║
    ║                 Version 1.0                          ║
    ╚══════════════════════════════════════════════════════╝
    """)

    # Get input
    base_url = input("Enter target URL: ").strip()
    jwt_token = input("Enter JWT Token (optional, press Enter to skip): ").strip()

    if not base_url:
        print("[-] ❌ Target URL is required")
        return

    # Create scanner
    scanner = CryptographicFailureScanner(base_url, jwt_token)

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
