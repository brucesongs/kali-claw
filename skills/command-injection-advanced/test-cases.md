# Command Injection Advanced -- Test Cases

> Structured test case templates for advanced injection testing
> **NOTE**: This file describes testing procedures and expected results, not executable payloads.

---

## Test Case 1: OS Command Injection with Space Filter Bypass

**Test ID**: CI-ADV-001  
**Severity**: CRITICAL  
**Category**: OS Command Injection  
**CyberGym Bug Class**: IN1, IN2

### Description
Test command injection in a network utility (ping, traceroute) that filters space characters but allows command separators.

### Preconditions
- Target application has a network diagnostic feature (ping, nslookup, traceroute)
- Application accepts user-supplied IP address or hostname
- Space character is filtered/blocked
- Command separators are not properly validated

### Test Steps

1. **Basic Detection**
   - Send HTTP request with command separator in target parameter
   - Record response time and content
   - Expected: Delayed response (time-based) or modified output
   - Tool: Use `commix` for automated testing

2. **Space Bypass Techniques**
   - Test alternative whitespace characters (tabs, newlines)
   - Test bash parameter expansion without spaces
   - Test file input redirection without spaces
   - Expected: Command execution despite space filter
   - Tool: `commix --technique=TFBSC`

3. **File Read Attempt**
   - Execute file read command via injection
   - Expected: Sensitive file contents in response or externally accessible
   - Tool: `commix`, Burp Suite

4. **Confirmation**
   - Establish reverse shell connection or
   - Trigger time-delayed response or
   - Confirm via DNS/HTTP callback
   - Expected: Successful exploitation indicator

### Expected Results
- Space bypass techniques successfully execute commands
- File read or command output visible
- Time delay confirmed or callback received
- At least one bypass method successful

### Pass Criteria
- Space filter bypassed
- Proof of command execution: file contents, time delay, or callback

---

## Test Case 2: LDAP Injection Authentication Bypass

**Test ID**: CI-ADV-002  
**Severity**: CRITICAL  
**Category**: LDAP Injection  
**CyberGym Bug Class**: IN3

### Description
Test LDAP authentication bypass via filter manipulation.

### Preconditions
- Target application uses LDAP/Active Directory for authentication
- Username and password fields are vulnerable to LDAP filter injection
- Backend constructs LDAP query with user input

### Test Steps

1. **Wildcard Injection**
   - Submit wildcard patterns in username field
   - Vary password field values
   - Expected: Authentication success without valid password
   - Tool: Manual testing via HTTP form, or Burp Repeater

2. **Boolean Operator Injection**
   - Test OR operator injection in filter logic
   - Test AND operator manipulation
   - Test parenthesis closure
   - Expected: Bypass authentication
   - Tool: Manual HTTP POST testing

3. **Data Extraction**
   - Use blind injection via binary search
   - Test attribute length enumeration
   - Test character-by-character extraction
   - Expected: User attributes extracted without direct output
   - Tool: `ldapsearch`, custom enumeration script

4. **Validation**
   - Confirm successful authentication or
   - Demonstrate attribute extraction
   - Expected: Access granted or data revealed

### Expected Results
- LDAP authentication bypassed
- Boolean manipulation creates tautology
- Blind extraction succeeds

### Pass Criteria
- Authentication successful without valid password
- Proof: Authenticated session or JWT token received

---

## Test Case 3: NoSQL Injection in MongoDB API

**Test ID**: CI-ADV-003  
**Severity**: CRITICAL  
**Category**: NoSQL Injection  
**CyberGym Bug Class**: IN4

### Description
Test MongoDB operator injection for authentication bypass.

### Preconditions
- Target application uses MongoDB for user authentication
- REST API accepts JSON payload for login
- Application doesn't validate/cast input types

### Test Steps

1. **Operator Injection Detection**
   - Send JSON with comparison operators in place of string values
   - Test not-equal operator
   - Test greater-than operator
   - Expected: Authentication bypass
   - Tool: Burp Suite, `nosqlmap`

2. **Username Enumeration**
   - Test regex-based username patterns
   - Binary search for valid usernames
   - Expected: Identify valid usernames
   - Tool: `nosqlmap`, Burp Intruder

3. **$where Clause Testing**
   - Test JavaScript eval clause support
   - Time-based injection for blind detection
   - Expected: Delayed response or command output
   - Tool: `nosqlmap`, manual Burp testing

4. **Exploitation Confirmation**
   - Demonstrate successful authentication bypass or
   - Extract user data via injection
   - Expected: Session token or data access

### Expected Results
- Operator injection bypasses authentication
- Regex enumeration reveals valid usernames
- $where clause executes JavaScript
- Data extraction succeeds

### Pass Criteria
- Authentication bypassed
- Proof: Authenticated session token or extracted data

---

## Test Case 4: Jinja2 SSTI RCE

**Test ID**: CI-ADV-004  
**Severity**: CRITICAL  
**Category**: Server-Side Template Injection  
**CyberGym Bug Class**: IN1

### Description
Test Jinja2 template injection for remote code execution.

### Preconditions
- Target application uses Jinja2 template engine
- User input directly embedded in templates
- Application renders templates server-side

### Test Steps

1. **Detection**
   - Send test payload with template arithmetic expression
   - Analyze response for expression evaluation
   - Expected: Mathematical result instead of raw syntax
   - Tool: Manual testing, `tplmap`

2. **Engine Fingerprinting**
   - Access application-specific objects
   - Test for Flask configuration objects
   - Expected: Framework-specific information leaked
   - Tool: `tplmap`, manual testing

3. **RCE Exploitation**
   - Access class hierarchy to find executable classes
   - Import system modules via template syntax
   - Execute arbitrary commands
   - Expected: Command output or side effects
   - Tool: `tplmap`, Burp Suite

4. **Reverse Shell**
   - Establish interactive shell connection
   - Expected: Shell access to target system
   - Tool: Netcat listener, Burp Suite

### Expected Results
- Expression evaluation confirmed
- Configuration leaked
- Commands execute
- File read successful
- Reverse shell established

### Pass Criteria
- SSTI vulnerability confirmed via expression evaluation
- RCE payload successfully executes
- Proof: Command output visible or reverse shell connection

---

## Test Case 5: XPath Injection Data Extraction

**Test ID**: CI-ADV-005  
**Severity**: HIGH  
**Category**: XPath Injection  
**CyberGym Bug Class**: IN3

### Description
Test XPath injection for authentication bypass and blind data extraction.

### Preconditions
- Target application uses XML for authentication
- XPath queries constructed with user input
- Backend query constructs authentication check

### Test Steps

1. **Tautology-Based Bypass**
   - Inject boolean logic that creates always-true condition
   - Expected: Authentication successful
   - Tool: Manual testing via HTTP form

2. **Comment Injection**
   - Use comment syntax to ignore password requirement
   - Expected: Authenticated as target user
   - Tool: Manual testing, Burp Repeater

3. **Data Extraction - Blind Injection**
   - Binary search for node count
   - Character extraction via substring functions
   - Expected: Data extracted without direct output
   - Tool: Manual scripting, Burp Suite

4. **Full Data Recovery**
   - Automated script for full password extraction
   - Character-by-character enumeration
   - Expected: Complete password recovered

### Expected Results
- Tautology bypasses authentication
- Blind injection enumerates data
- Password length determined
- Full password extracted

### Pass Criteria
- Authentication bypassed
- Partial or full password extracted

---

## Test Case 6: Template Engine Exploitation (Multi-Engine)

**Test ID**: CI-ADV-006  
**Severity**: CRITICAL  
**Category**: Server-Side Template Injection  
**CyberGym Bug Class**: IN1, IN2

### Description
Test template injection across multiple engines with automated detection.

### Preconditions
- Target uses template engine (unknown which one)
- User input rendered in templates without sanitization
- Need to fingerprint and exploit

### Test Steps

1. **Polyglot Detection**
   - Send multi-engine detection payload
   - Analyze position and type of expression evaluation
   - Expected: Identify template engine from evaluation pattern
   - Tool: `tplmap`, manual testing

2. **Engine Fingerprinting**
   - Test engine-specific markers and functions
   - Access framework-specific objects
   - Expected: Confirm identified engine
   - Tool: `tplmap`, Burp Suite

3. **Engine-Specific RCE**
   - Execute RCE chain appropriate for identified engine
   - Expected: Command execution
   - Tool: `tplmap` with engine selection

4. **Verification**
   - Confirm exploitation success
   - Expected: Command output or side effect

### Expected Results
- Template engine correctly identified
- Engine-specific RCE executes
- Proof: Command output or file creation

### Pass Criteria
- Engine fingerprinting successful
- RCE payload executes
- Proof of exploitation visible

---

## Testing Checklist

### Pre-Test Preparation
- [ ] Target URL and endpoints identified
- [ ] Authentication requirements understood
- [ ] Baseline normal behavior documented
- [ ] Out-of-band callback infrastructure configured (DNS/HTTP/DNS)
- [ ] Reverse shell listener running (if testing RCE)
- [ ] Backup and recovery procedures confirmed

### During Testing
- [ ] All requests and responses documented
- [ ] Timing measurements recorded (time-based injection)
- [ ] All successful exploitations logged
- [ ] WAF/filter behaviors noted
- [ ] Multiple bypass techniques attempted
- [ ] No destructive actions on target system

### Post-Test Documentation
- [ ] Severity assessment justified
- [ ] Impact analysis documented
- [ ] Remediation recommendations provided
- [ ] PoC payload technique documented (without actual payload strings)
- [ ] Screenshots/logs collected as evidence
- [ ] Timeline of exploitation recorded

---

## Severity Guidelines

| Severity | Condition |
|----------|-----------|
| **CRITICAL** | RCE confirmed, authentication bypass in production, full system compromise |
| **HIGH** | Blind injection with confirmed data extraction, successful LDAP/NoSQL bypass |
| **MEDIUM** | Detection-only without exploitation chain, limited data exposure |
| **LOW** | False positive, no viable exploitation path |

---

## Tool References

- **commix**: https://github.com/commixproject/commix
- **tplmap**: https://github.com/epinna/tplmap
- **nosqlmap**: https://github.com/codingo/NoSQLMap
- **ldapsearch**: Part of ldap-utils package
- **Burp Suite**: Commercial (Community edition free)

*These test cases provide structured procedures for advanced injection testing without including specific exploit payloads.*
