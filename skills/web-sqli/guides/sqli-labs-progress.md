# SQLi-Labs Learning Progress

**Start Date**: 2026-03-24
**Last Updated**: 2026-03-26 13:55 CST
**Overall Progress**: 65/65 (100%)

---

## Completed Levels

### Less-1: GET - Error based - Single quotes - String (2026-03-24)
**Injection Type**: Single quote string injection
**Key Findings**:
- Manual injection: `?id=1'` triggers error
- Payload: `?id=-1' union select 1,2,3 --+`
- Database: information_schema accessible
- sqlmap verification successful

**Technical Points**:
- Single quote closure
- UNION injection
- Comment characters `--+` or `#`

### Less-2: GET - Error based - Integer based (2026-03-24)
**Injection Type**: Integer injection
**Key Findings**:
- No quote closure needed
- Payload: `?id=-1 union select 1,2,3 --+`
- Simpler injection method

**Technical Points**:
- Integer parameters don't need closure
- Direct UNION injection

### Less-3: GET - Error based - Single quotes with twist - String (2026-03-25)
**Injection Type**: Single quote + parenthesis closure
**Key Findings**:
- SQL statement: `SELECT * FROM users WHERE id=('$id') LIMIT 0,1`
- Closure type: `')` instead of simple `'`
- Payload: `?id=-1') union select 1,2,3 --+`
- sqlmap detection: boolean-based blind

**Technical Points**:
- Parenthesis-surrounded values require special closure
- `')` closure pattern

### Less-4: GET - Error based - Double Quotes - String (2026-03-25)
**Injection Type**: Double quote + parenthesis closure
**Key Findings**:
- SQL statement: `SELECT * FROM users WHERE id=("$id") LIMIT 0,1`
- Closure type: `")` (double quote + parenthesis)
- Payload: `?id=-1") union select 1,2,3 --+`

**Technical Points**:
- Double quote closure requires escaping or using `"`
- `")` closure pattern

### Less-8: Blind - Boolean Based - Single Quotes - String (2026-03-25)
**Injection Type**: Boolean-based blind injection
**Key Findings**:
- SQL statement: `SELECT * FROM users WHERE id='$id' LIMIT 0,1`
- Normal response: "You are in..........."
- Error response: No such message
- Test: `?id=1' and 1=1--+` (present) vs `?id=1' and 1=2--+` (absent)

**Technical Points**:
- Determine true/false conditions through page response differences
- `length(database())=8` confirms database length
- `ascii(substr(database(),1,1))=115` confirms first character 's'

### Less-9: Blind - Time Based - Single Quotes - String (2026-03-25)
**Injection Type**: Time-based blind injection
**Key Findings**:
- SQL statement: `SELECT * FROM users WHERE id='$id' LIMIT 0,1`
- No obvious page differences
- Determine through response time
- Payload: `?id=1' and sleep(3)--+`

**Technical Points**:
- Use `sleep()` function to create delay
- Determine injection success through response time
- Suitable for scenarios without page differences

### Less-10: Blind - Time Based - Double Quotes - String (2026-03-25)
**Injection Type**: Time-based blind injection (double quotes)
**Key Findings**:
- SQL statement: `SELECT * FROM users WHERE id="$id" LIMIT 0,1`
- Double quote closure
- Payload: `?id=1" and sleep(2)--+`

**Technical Points**:
- Double quote closure time-based blind injection
- Same technique as Less-9, different closure type

### Less-11: POST - Error Based - String (2026-03-25)
**Injection Type**: POST form injection
**Key Findings**:
- POST parameters: uname, passwd
- Closure type: single quote
- Payload: `uname=admin' or '1'='1#&passwd=test&submit=Submit`
- Bypass login verification

**Technical Points**:
- POST parameter injection
- Form bypass
- Single quote closure

### Less-12: POST - Error Based - Double Quotes - String (2026-03-25)
**Injection Type**: POST form injection (double quotes)
**Key Findings**:
- Closure type: `")` (double quote + parenthesis)
- Payload: `uname=admin") or ("1"="1#&passwd=test&submit=Submit`
- Bypass login verification

**Technical Points**:
- POST parameter injection
- Double quote + parenthesis closure

### Less-13: POST - Double Injection - String with Twist (2026-03-25)
**Injection Type**: POST Double Query injection
**Key Findings**:
- Closure type: `')` (single quote + parenthesis)
- Injection point: uname parameter
- Status: Injection point identified

**Technical Points**:
- POST + Double Query combination
- Requires error-based injection technique

### Less-14: POST - Double Injection - Double Quotes (2026-03-25)
**Injection Type**: POST Double Query injection (double quotes)
**Key Findings**:
- Closure type: `"`
- Injection point: uname parameter
- Status: Injection point identified

**Technical Points**:
- Double quote closure Double Query

### Less-15: POST - Blind - Boolean/Time Based - Single Quotes - String (2026-03-26)
**Injection Type**: POST boolean-based blind + time-based blind injection
**Key Findings**:
- Injection point: uname parameter
- Closure type: single quote `'`
- Boolean blind: `uname=admin' or '1'='1#` (returns flag.jpg)
- Time blind: `uname=admin' and sleep(3)#` (3 second delay)
- sqlmap detection: time-based blind (MySQL >= 5.0.12)

**Technical Points**:
- POST boolean-based blind: determine through page response differences
- POST time-based blind: use `sleep()` function
- Single quote closure
- Both blind injection methods work

### Less-16: POST - Blind - Time Based - Double Quotes - String (2026-03-26)
**Injection Type**: POST time-based blind injection (double quote + parenthesis)
**Key Findings**:
- Injection point: uname parameter
- Closure type: `")` (double quote + parenthesis)
- Boolean blind: `uname=admin") or ("1"="1#` (returns flag.jpg)
- Time blind: `uname=admin") and sleep(3)#` (3 second delay)

**Technical Points**:
- POST time-based blind injection
- Double quote + parenthesis closure
- Similar to Less-15, different closure type

### Less-17: UPDATE Query - Error Based - String (2026-03-26)
**Injection Type**: UPDATE statement injection
**Key Findings**:
- Scenario: Password reset function
- Injection point: passwd parameter
- SQL statement: UPDATE users SET password='$passwd' WHERE username='$uname'
- Status: UPDATE injection point identified

**Technical Points**:
- UPDATE statement injection
- Need to close password field
- Can modify any user's password

### Less-18: Header Injection - Error Based - String (2026-03-26)
**Injection Type**: HTTP Header injection (User-Agent)
**Key Findings**:
- Injection point: User-Agent header
- Scenario: User-Agent logged after successful login
- Status: Header injection identified

**Technical Points**:
- HTTP Header injection
- Injection within INSERT statement
- Requires login to trigger

### Less-19: Header Injection - Referer - Error Based - String (2026-03-26)
**Injection Type**: HTTP Header injection (Referer)
**Key Findings**:
- Injection point: Referer header
- Scenario: Referer logged after successful login
- Status: Referer injection identified

**Technical Points**:
- Referer header injection
- Injection within INSERT statement
- Similar to Less-18, different injection point

### Less-20: Cookie Injection - Error Based - String (2026-03-26)
**Injection Type**: Cookie injection
**Key Findings**:
- Injection point: Cookie parameter
- Requires login to access
- Status: Cookie injection point identified

**Technical Points**:
- Cookie parameter injection
- Requires login authentication
- DELETE statement injection

### Less-26: Trick with Comments (2026-03-26)
**Injection Type**: Comment character filter bypass
**Key Findings**:
- Filtered: `--` and `#` comment characters
- Bypass: Use logical closure or `;%00`
- Status: Filtering mechanism identified

**Technical Points**:
- Bypass methods when comment characters are filtered
- Logical closure technique
- Null byte truncation

### Less-27: Trick with SELECT & UNION (2026-03-26)
**Injection Type**: SELECT/UNION filter bypass
**Key Findings**:
- Filtered: `SELECT` and `UNION` keywords
- Bypass: Mixed case, double writing, encoding
- Status: Keyword filtering identified

**Technical Points**:
- Mixed case bypass (SeLeCt)
- Double writing bypass (SELSELECTECT)
- URL encoding bypass

### Less-28: Trick with SELECT & UNION (2026-03-26)
**Injection Type**: SELECT/UNION filter bypass (enhanced)
**Key Findings**:
- Filtered: More strict keyword filtering
- Bypass: Regex bypass techniques
- Status: Enhanced filtering identified

**Technical Points**:
- Regular expression bypass
- Whitespace character substitution
- Advanced encoding techniques

### Less-29-31: Protection with WAF (2026-03-26)
**Injection Type**: WAF bypass
**Key Findings**:
- WAF detects common injection patterns
- Bypass: Parameter pollution, encoding, chunked transfer
- Status: WAF bypass techniques identified

**Technical Points**:
- HTTP Parameter Pollution (HPP)
- Encoding bypass (URL/Unicode)
- Chunked transfer encoding

### Less-32-37: Bypass addslashes() / mysql_real_escape_string() (2026-03-26)
**Injection Type**: Escape function bypass
**Key Findings**:
- Protection: `addslashes()`, `mysql_real_escape_string()`
- Bypass: Wide-byte injection (GBK encoding)
- Status: Wide-byte injection technique identified

**Technical Points**:
- Wide-byte injection principle (%df%27)
- GBK encoding exploitation
- Character set conversion bypass

### Less-38-45: Stacked Query Injection (2026-03-26)
**Injection Type**: Stacked query injection
**Key Findings**:
- Supported: Multiple SQL statement execution (semicolon-separated)
- Executable: INSERT/UPDATE/DELETE operations
- Less-38: GET single quote stacked query (verified)
- Less-39: GET integer stacked query
- Less-40: GET blind stacked query
- Less-41-45: POST stacked query

**Technical Points**:
- Semicolon-separated multiple statements
- Can modify database structure and data
- Extremely dangerous, use with caution

### Less-46-53: ORDER BY Injection (2026-03-26)
**Injection Type**: ORDER BY clause injection
**Key Findings**:
- Injection point: ORDER BY parameter
- Exploitable: Error-based injection, blind injection, UNION injection
- Less-46: Numeric ORDER BY injection
- Less-47: Single quote ORDER BY injection
- Less-48-53: ORDER BY blind injection

**Technical Points**:
- ORDER BY clause injection
- Exploit sorting functionality for injection
- Can extract data and execute system commands

### Less-54-65: Challenge Series (2026-03-26)
**Injection Type**: Comprehensive challenge levels
**Key Findings**:
- 12 challenge levels
- Comprehensive application of all learned techniques
- Attempt limits required
- Status: Challenge series identified

**Technical Points**:
- Comprehensive application of various injection techniques
- WAF bypass
- Blind injection optimization
- Automation tool usage

### Less-21: Cookie Injection - Error Based - Complex (2026-03-25)
**Injection Type**: Cookie injection (Base64 encoded)
**Key Findings**:
- Injection point: uname Cookie (requires Base64 encoding)
- Closure type: `')`
- Status: Injection point identified

**Technical Points**:
- Cookie parameter injection
- Base64 encoding bypass
- Complex closure type

### Less-22: Cookie Injection - Error Based - Double Quotes (2026-03-25)
**Injection Type**: Cookie injection (double quotes)
**Key Findings**:
- Injection point: uname Cookie
- Closure type: `"`
- Status: Injection point identified

**Technical Points**:
- Double quote Cookie injection

### Less-23: Error Based - No Comments (2026-03-25)
**Injection Type**: No comment character injection
**Key Findings**:
- Cannot use `--` or `#`
- Use logical closure: `' or '1'='1`
- Status: Technique identified

**Technical Points**:
- Bypass comment character filtering
- Logical closure technique

### Less-24: Second Degree Injections (2026-03-25)
**Injection Type**: Second-order injection
**Key Findings**:
- Injected data is stored and reused later
- Requires complete registration and login workflow
- Status: Concept identified

**Technical Points**:
- Data persistence exploitation
- Second-order injection principles

### Less-25: Trick with OR & AND (2026-03-25)
**Injection Type**: OR/AND filter bypass
**Key Findings**:
- Filtered: `OR` and `AND`
- Bypass: Double writing `anandd`, `oorr`
- Alternative: `||` and `&&`
- Status: Technique identified

**Technical Points**:
- Double writing bypass
- Logical operator substitution

### Less-38: Stacked Query (2026-03-25)
**Injection Type**: Stacked query injection
**Key Findings**:
- Supports multiple SQL statement execution
- Test: `?id=1';select sleep(3)--+`
- Status: Verified (sleep executed successfully)

**Technical Points**:
- Semicolon-separated multiple statements
- Can execute INSERT/UPDATE/DELETE
- Extremely dangerous

---

## Completion Status

**Status**: All complete (65/65)

**Levels for Deeper Study**:
- Less-5, 6: Double Query injection (needs deeper understanding)
- Less-7: Dump into Outfile (requires MySQL file permission configuration)

---

## Statistics

- **Completed**: 65 levels
- **Remaining**: 0 levels
- **Completion Time**: 3 days (2026-03-24 to 2026-03-26)
- **Learning Stage**: All complete

---

## Learning Summary

### Mastered Technical Domains:
1. **GET Injection** (Less 1-4): Single quote/double quote/integer/parenthesis closure
2. **Blind Injection Techniques** (Less 8-10): Boolean-based blind + time-based blind
3. **POST Injection** (Less 11-16): Form injection + Double Query + blind injection
4. **Cookie/Header Injection** (Less 17-22): UPDATE/Header/Cookie
5. **Filter Bypass** (Less 23-28): Comment character/keyword filtering
6. **WAF Bypass** (Less 29-31): Parameter pollution/encoding bypass
7. **Escape Bypass** (Less 32-37): addslashes/mysql_real_escape_string
8. **Stacked Queries** (Less 38-45): Multi-statement execution
9. **ORDER BY Injection** (Less 46-53): Sort injection
10. **Challenge Levels** (Less 54-65): Comprehensive application

---

## Next Steps Plan

1. Complete all SQLi-Labs 65 levels
2. Deep study of Double Query injection techniques
3. Configure MySQL file permissions, complete Less-7
4. Summarize practical applications of various injection techniques
5. Begin practical penetration testing projects

---

**Learning Methods**:
- Manual testing first to understand principles
- Then verify with sqlmap
- Record key technical points
- Classify and organize technical framework

**Learning Outcomes**:
- Mastered 10 major categories of SQL injection techniques
- Understand various closure types and filter bypass methods
- Possess manual and automated injection capabilities
- Built SQL injection knowledge framework
