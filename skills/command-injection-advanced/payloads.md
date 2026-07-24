# Command Injection Advanced Payloads -- Payload Technology Reference

> This file documents payload techniques and tool usage for advanced injection testing
> **NOTE**: Specific payload strings have been removed. Use the referenced tools to generate payloads.

---

## 1. OS Command Injection Basics

### Command Separators - Concepts

Command separators are shell metacharacters that control execution flow:
- Sequential execution separator
- Pipe operator for output chaining
- Conditional AND operator
- Conditional OR operator  
- Background execution operator

**Tools**: Use `commix` to automatically test all separator variations.

### Command Substitution - Techniques

Two syntaxes for command substitution exist in bash. Both can be used for nesting.

**Tools**: `commix --technique=TFBSC` tests all variations.

### Input Redirection - Methods

Read file contents via redirection without command names. Redirect output to accessible locations.

**Tools**: `commix` tests redirection variations.

---

## 2. Filter Bypass - Space Replacement

### IFS (Internal Field Separator)

Bash IFS variable holds whitespace characters. Reference it to replace spaces.

**Techniques**:
- Basic IFS variable expansion
- IFS with positional parameters  
- IFS substring extraction

**Limitation**: Bash/sh only. Test with `commix`.

### Alternative Whitespace Characters

Use URL-encoded or escaped whitespace alternatives:
- Tab character (hex 09)
- Newline (hex 0a)
- Carriage return (hex 0d)
- Vertical tab (hex 0b)
- Form feed (hex 0c)

**Tool**: `commix` tests alternative whitespace.

### Brace Expansion (Bash)

Bash feature for command/argument grouping without spaces.

**Limitation**: Bash only. **Tool**: `commix`.

### Input Redirection as Space

Use input redirection and command chaining without spaces.

**Tool**: `commix`.

---

## 3. Filter Bypass - Keyword Evasion

### Quote Insertion

Insert empty quotes within command names to bypass keyword filters.

**Techniques**:
- Single quote insertion
- Double quote insertion
- Mixed quote patterns

**Tool**: Test with `commix --level=3`.

### Backslash Escaping

Escape individual characters to break up filtered keywords.

**Tool**: `commix`.

### Variable Expansion

Reference variables or extract substrings to reconstruct commands.

**Technique**: Empty variable expansion, PATH extraction.

### Wildcards and Globbing

Use glob patterns to match filesystem paths.

**Patterns**: Question mark (single char), asterisk (multiple chars), character classes, ranges.

**Tool**: `commix`.

### Case Manipulation

Some systems allow case-insensitive command execution.

**Tool**: Manual testing or `commix`.

### String Concatenation

Reconstruct commands via variable assignment and concatenation.

**Tool**: `commix`.

---

## 4. Filter Bypass - Encoding and Obfuscation

### URL Encoding

Single or double URL encoding of metacharacters.

**Tools**: 
- `commix` (auto-encodes payloads)
- Burp Suite Intruder (test encoding)
- CyberChef (multi-stage encoding)

### Hex Encoding

Represent characters as hex escape sequences.

**Tool**: Burp Suite, CyberChef, custom scripts.

### Octal Encoding

Represent characters as octal escape sequences.

**Tool**: Burp Suite, CyberChef.

### Base64 Encoding

Encode payload, decode in subshell or eval.

**Tool**: `echo <payload> | base64` + Burp.

### Unicode Encoding

Limited support for Unicode normalization bypasses.

**Tool**: Context-dependent; test with target.

### Null Byte Injection

Null bytes can truncate filtered strings in some contexts.

**Tool**: Burp Suite, manual testing.

---

## 5. LDAP Injection

### Authentication Bypass - Wildcard

Wildcard character matches any substring.

**Concept**: Inject wildcard to bypass password verification.

**Tool**: Manual testing via login forms or `ldapsearch`.

### Authentication Bypass - Boolean Operators

Manipulate LDAP filter logic using boolean operators.

**Concept**: Inject parentheses and operators to restructure filter conditions.

**Technique categories**:
- OR operator to create tautologies
- AND operator manipulation
- Closing parenthesis bypass
- NOT operator usage

**Tool**: Manual testing or `wfuzz` with LDAP wordlists.

### LDAP Filter Injection - Data Extraction

Inject filter logic to extract user attributes or enumerate structure.

**Concept**: Match multiple objects, extract specific attributes.

**Tool**: `ldapsearch` with crafted filters, `ldapdomaindump`.

### Blind LDAP Injection

Extract data via boolean-based inference without direct output.

**Techniques**:
- Length enumeration
- Character-by-character extraction via binary search

**Tool**: Manual scripting with `ldapsearch`, timing analysis.

---

## 6. NoSQL Injection

### MongoDB - Operator Injection

MongoDB operators manipulate query logic.

**Operators**:
- Not-equal operator
- Greater-than operator
- Regex operator
- Array membership
- Field existence check

**Tool**: `nosqlmap`, manual Burp testing.

### MongoDB - $where Clause Exploitation

JavaScript eval context for complex queries.

**Concepts**:
- Time-based blind injection
- Boolean-based extraction
- JavaScript RCE primitives

**Tool**: `nosqlmap`, manual testing.

### Redis - Command Injection via EVAL

Redis Lua scripting for system command execution.

**Concept**: Chain Lua execution with system calls.

**Tool**: `redis-cli` direct access or SSRF + gopher protocol.

### CouchDB - View Function Injection

JavaScript injection in map/reduce functions.

**Tool**: Manual testing via HTTP API.

---

## 7. Template Injection (SSTI)

### Detection Payloads

Multiple template syntaxes to identify engine.

**Technique**: Test mathematical expressions in different template formats.

**Detection methods**:
- Polyglot probes across engines
- String repetition tests
- Engine-specific markers

**Tool**: `tplmap` (automated detection).

### Engine-Specific Exploitation

Each template engine has different object access paths.

**Jinja2 (Python)**:
- Flask configuration objects
- Class hierarchy traversal
- Module imports and system calls

**Thymeleaf (Java)**:
- T() operator for Java class access
- Runtime.exec() for commands
- SpEL injection

**FreeMarker (Java)**:
- Execute class instantiation
- ObjectConstructor for arbitrary object creation
- File operations

**Twig (PHP)**:
- Environment object access
- Filter function manipulation
- System function chaining

**Smarty (PHP)**:
- PHP code execution tags
- File inclusion
- System function execution

**Pug (Node.js)**:
- Process module access
- File system operations
- Child process execution

**Tool**: `tplmap` for automated exploitation.

---

## 8. XPath Injection

### Authentication Bypass

XPath boolean logic for filter manipulation.

**Techniques**:
- Tautology creation
- Comment injection
- Quote manipulation

**Tool**: Manual testing via login forms.

### Boolean-Based Blind Injection

Extract data via binary search.

**Functions**:
- String length measurement
- Substring extraction
- Pattern matching (starts-with, contains)
- Node counting

**Tool**: Manual scripting, timing analysis.

### Data Extraction

Navigate XML structure and extract values.

**Techniques**:
- Node name extraction
- Parent axis traversal  
- Union-based extraction (if output visible)

**Tool**: Manual testing, automated fuzzing.

---

## 9. Context-Specific Techniques

### Bash-Specific

Bash-exclusive features:
- Brace expansion
- Process substitution
- Here-string syntax
- Arithmetic expansion
- Parameter expansion

**Tool**: `commix`, manual testing.

### PowerShell-Specific

Windows PowerShell features and encoding:
- PowerShell -Command execution
- Base64 encoded payloads
- Environment variable paths

**Tool**: Manual testing on Windows targets.

### Python-Specific

Python eval/exec contexts and module imports.

**Techniques**:
- __import__ tricks
- eval/exec abuse
- subprocess module calls

**Tool**: Manual testing, `tplmap` for Python template injection.

---

## 10. Blind Injection Techniques

### Time-Based Detection

Introduce delays and measure response timing.

**Methods**:
- Sleep commands (Linux)
- Ping-based delays (cross-platform)
- Database-specific sleep functions
- Timeout commands (Windows)

**Tool**: `commix` (automated), Burp timing analysis.

### DNS Exfiltration

Query attacker's DNS server to confirm execution.

**Concept**: Command output encoded in DNS query subdomain.

**Tools**: 
- Burp Collaborator (built-in)
- interact.sh (public callback service)
- Custom DNS server

### HTTP Callback

Use HTTP requests to exfiltrate data.

**Concept**: Command output sent to attacker-controlled webhook.

**Tools**:
- webhook.site (free public service)
- Burp Collaborator
- Custom HTTP listener

### Error-Based Blind Injection

Infer conditions from application errors vs. success responses.

**Technique**: Structured injection to trigger errors based on boolean conditions.

**Tool**: Manual testing with error analysis.

---

## 11. Tool Usage Reference

### commix (OS Command Injection)

Automated detection and exploitation of command injection:
- Automatic separator testing
- Space bypass techniques
- Blind detection (time-based, DNS)

**Command**: `commix -u "URL?param=INJECT_HERE" --batch`

### Burp Suite

HTTP interception and payload manipulation:
- Repeater for manual testing
- Intruder for payload iteration
- Encoder for multi-stage encoding
- Collaborator for out-of-band detection

### ldapsearch / ldapdomaindump

LDAP query testing and enumeration:
- Manual filter injection
- Directory structure discovery
- Attribute extraction

### nosqlmap

NoSQL injection scanner:
- MongoDB operator detection
- Blind injection extraction
- Automated exploitation

### tplmap

Template injection detection and exploitation:
- Multi-engine fingerprinting
- Automated RCE chain
- OS shell interaction

### sqlmap

Multi-purpose injection (supports --os-cmd for command execution):
- Database-agnostic injection testing
- OS command chains

### CyberChef

Multi-stage encoding pipeline:
- Combine encoding techniques
- Test encoding bypass chains
- Visual payload construction

### Callback Services

Out-of-band data exfiltration:
- **Burp Collaborator**: Built-in to Burp Suite
- **interact.sh**: Free public service
- **webhook.site**: Simple HTTP webhook testing

---

## 12. CyberGym Challenge Templates

### Template 1: Space-Filtered Command Injection

**Scenario**: Application filters space characters.

**Testing approach**:
- Try alternative whitespace (tabs, newlines)
- Test IFS variable expansion
- Try brace expansion
- Test input redirection
- Attempt URL encoding of spaces

**Tool**: `commix --technique=TFBSC`

### Template 2: Keyword-Filtered Command Injection

**Scenario**: Application blocks specific keywords.

**Testing approach**:
- Quote insertion variations
- Case manipulation
- Wildcard patterns
- Variable expansion
- Encoding chains (base64, hex, URL)

**Tool**: `commix --level=3`

### Template 3: LDAP Authentication Bypass

**Scenario**: LDAP-based login with unsafe filter construction.

**Testing approach**:
- Wildcard injection
- Boolean operator manipulation
- Parenthesis closure testing
- Attribute enumeration

**Tool**: Manual testing, `ldapsearch`

### Template 4: NoSQL Authentication Bypass

**Scenario**: MongoDB REST API without input validation.

**Testing approach**:
- Operator injection ($ne, $gt, $regex)
- Database fingerprinting
- $where clause testing (if enabled)

**Tool**: `nosqlmap`, Burp Suite

### Template 5: SSTI in Template Renderer

**Scenario**: User input in email/report templates.

**Testing approach**:
- Polyglot detection
- Engine fingerprinting
- Engine-specific RCE chain

**Tool**: `tplmap`

### Template 6: Blind Command Injection

**Scenario**: No output in response.

**Testing approach**:
- Time-based delays
- DNS callback setup
- HTTP webhook testing
- Error-based inference

**Tool**: `commix`, Burp Collaborator

### Template 7: Redis RCE via SSRF

**Scenario**: SSRF to internal Redis server.

**Testing approach**:
- Gopher protocol URL crafting
- Redis command sequencing
- File write for persistence

**Tool**: Manual testing, `redis-cli`, Burp Suite

---

*This reference documents payload techniques and tool usage for advanced injection testing. Actual payload generation is performed by the referenced security tools.*
