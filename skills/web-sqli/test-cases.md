# SQL Injection Test Cases

> This file is a companion to `SKILL.md`, providing structured SQL injection test case templates.
> Purpose: Check each item during penetration testing to ensure no critical injection types are missed. Each case includes prerequisites, steps, expected results, and severity level.
> All tests are intended solely for authorized security assessments.

---

## Test Case Format

```
TC-SXXX | [Category] Test Name
Severity: CRITICAL / HIGH / MEDIUM / LOW
Prerequisites: Conditions that must be met before testing
Test Steps: Specific operations
Expected Results: Observable behavior when the vulnerability exists
Reference Payload: Corresponding section in payloads.md
```

---

## Index

- [A. Injection Point Detection](#a-injection-point-detection)
- [B. UNION Injection](#b-union-injection)
- [C. Error-based Injection](#c-error-based-injection)
- [D. Blind Injection](#d-blind-injection)
- [E. Advanced Exploitation](#e-advanced-exploitation)

---

## A. Injection Point Detection

### TC-S001 | GET Parameter Injection Point Detection

- **Severity**: CRITICAL
- **Prerequisites**: Known URL with parameters (e.g., `?id=1`)
- **Test Steps**:
  1. Add single quote `?id=1'`, check if SQL error is triggered
  2. Test `?id=1' AND '1'='1` and `?id=1' AND '1'='2`
  3. Test numeric type `?id=1 AND 1=1` and `?id=1 AND 1=2`
  4. Try different closure methods: `'` / `"` / `')` / `"))`
- **Expected Results**: Page behaves abnormally or returns SQL error after adding quote -> Injection point exists
- **Reference**: payloads.md §1 Injection Point Detection

### TC-S002 | POST / Cookie / Header Injection Detection

- **Severity**: CRITICAL
- **Prerequisites**: Login form or other POST endpoint
- **Test Steps**:
  1. Inject single quote into each POST body parameter
  2. Inject single quote into Cookie values
  3. Inject into HTTP Headers (X-Forwarded-For, User-Agent, Referer)
  4. Use sqlmap for automated testing of all injection points
- **Expected Results**: Any location triggers SQL error -> Non-standard injection point
- **Reference**: payloads.md §1 Injection Confirmation

---

## B. UNION Injection

### TC-S003 | UNION Injection Column Count and Echo Position Determination

- **Severity**: HIGH
- **Prerequisites**: Injection point confirmed, page has content echo
- **Test Steps**:
  1. `ORDER BY 1` increment until error, determine column count
  2. `UNION SELECT 1,2,...,N` determine echo positions
  3. Replace echo positions with `database()`, `version()`
- **Expected Results**: Echo positions display database information -> UNION injection usable
- **Reference**: payloads.md §2 UNION Injection

### TC-S004 | UNION Injection Complete Data Extraction

- **Severity**: CRITICAL
- **Prerequisites**: UNION injection confirmed usable, echo positions known
- **Test Steps**:
  1. Extract all database names
  2. Extract table names from target database
  3. Extract column names from sensitive tables (users/accounts)
  4. Extract username and password data
- **Expected Results**: Successfully extract complete user credentials -> Total data breach
- **Reference**: payloads.md §2 Information Extraction

---

## C. Error-based Injection

### TC-S005 | extractvalue/updatexml Error-based Injection

- **Severity**: HIGH
- **Prerequisites**: Injection point exists, page returns MySQL error messages
- **Test Steps**:
  1. Test `extractvalue(1,concat(0x7e,(SELECT database()),0x7e))`
  2. Check if error message contains database name
  3. Extract table names, column names, data
  4. Use SUBSTRING for values exceeding 32 characters
- **Expected Results**: Error message contains query results -> Error-based injection confirmed
- **Reference**: payloads.md §3 Error-based Injection

### TC-S006 | Double Query Injection (floor method)

- **Severity**: HIGH
- **Prerequisites**: Page returns MySQL error messages, extractvalue/updatexml not available
- **Test Steps**:
  1. Test `floor()+rand()+group by` classic payload
  2. Check if Duplicate entry error contains data
  3. Extract step by step: database -> tables -> columns -> data
- **Expected Results**: Duplicate entry error contains query results -> Double Query confirmed
- **Reference**: payloads.md §6 Double Query Injection

---

## D. Blind Injection

### TC-S007 | Boolean Blind Injection

- **Severity**: HIGH
- **Prerequisites**: Injection point exists but no echo/error messages, content differences exist
- **Test Steps**:
  1. `' AND 1=1-- -` (normal) vs `' AND 1=2-- -` (abnormal)
  2. Confirm boolean difference
  3. `LENGTH()` binary search to determine database name length
  4. `SUBSTRING()` + binary search to extract character by character
- **Expected Results**: Can extract data character by character through boolean differences -> Boolean Blind confirmed
- **Reference**: payloads.md §4 Boolean Blind Injection

### TC-S008 | Time Blind Injection

- **Severity**: HIGH
- **Prerequisites**: Injection point exists, no echo/error/boolean differences
- **Test Steps**:
  1. `' AND IF(1=1,SLEEP(5),0)-- -` check if response is delayed by 5 seconds
  2. `' AND IF(1=2,SLEEP(5),0)-- -` check if no delay
  3. After confirming time difference, extract data character by character
- **Expected Results**: Response delays when condition is true -> Time Blind confirmed
- **Reference**: payloads.md §5 Time Blind Injection

---

## E. Advanced Exploitation

### TC-S009 | WAF Bypass Testing

- **Severity**: HIGH
- **Prerequisites**: Basic injection payloads are blocked (returns 403 or filter notification)
- **Test Steps**:
  1. Mixed case: `UnIoN SeLeCt`
  2. Comment bypass: `/**/UNION/**/SELECT/**/`
  3. Inline comments: `/*!50000UNION*/`
  4. Equivalent function substitution (see payloads.md §8)
  5. Use sqlmap tamper scripts for automation
- **Expected Results**: Any bypass method successfully executes SQL -> WAF bypass confirmed
- **Reference**: payloads.md §8 WAF Bypass Techniques

### TC-S010 | File Read/Write Testing

- **Severity**: CRITICAL
- **Prerequisites**: MySQL FILE privilege available, known web root path
- **Test Steps**:
  1. `LOAD_FILE('/etc/passwd')` test file reading
  2. `INTO OUTFILE` test file writing
  3. Write web shell and verify accessibility
  4. Or use `sqlmap --os-shell` for automation
- **Expected Results**: Successfully read server files or write web shell -> RCE prerequisite
- **Reference**: payloads.md §10 File Read/Write and Privilege Escalation

### TC-S011 | Cross-Database Injection

- **Severity**: HIGH
- **Prerequisites**: Target uses non-MySQL database
- **Test Steps**:
  1. Identify database type via `@@version` / `version()` / `@@servername`
  2. Use error-reporting functions for the corresponding database
  3. Use corresponding system tables/functions to extract data
- **Expected Results**: Successfully extract data from non-MySQL databases -> Cross-database injection capability
- **Reference**: payloads.md §9 Cross-Database Injection

### TC-S012 | sqlmap Automated Full Workflow

- **Severity**: CRITICAL
- **Prerequisites**: Confirmed injection point URL
- **Test Steps**:
  1. `sqlmap -u "URL" --batch --dbs` enumerate databases
  2. `sqlmap -u "URL" --batch -D target_db --tables` enumerate tables
  3. `sqlmap -u "URL" --batch -D target_db -T users --dump` extract data
  4. `sqlmap -u "URL" --os-shell` attempt to get OS Shell
- **Expected Results**: sqlmap automatically completes the full workflow from detection to data extraction

---

## Test Case Statistics

| Category | Cases | CRITICAL | HIGH | MEDIUM | LOW |
|----------|-------|----------|------|--------|-----|
| A. Injection Point Detection | 2 | 2 | 0 | 0 | 0 |
| B. UNION Injection | 2 | 1 | 1 | 0 | 0 |
| C. Error-based Injection | 2 | 0 | 2 | 0 | 0 |
| D. Blind Injection | 2 | 0 | 2 | 0 | 0 |
| E. Advanced Exploitation | 4 | 2 | 2 | 0 | 0 |
| **Total** | **12** | **5** | **7** | **0** | **0** |
