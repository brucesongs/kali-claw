# LDAP and NoSQL Injection Guide

> Reference guide for LDAP and NoSQL injection testing approaches

---

## Part 1: LDAP Injection Fundamentals

### 1.1 LDAP Basics

**LDAP (Lightweight Directory Access Protocol)** - used for directory services (Active Directory, OpenLDAP).

**Common deployment contexts**:
- Enterprise authentication systems
- Directory search features
- Single Sign-On (SSO) backends
- Email/contact verification

**LDAP Query Structure**:
- Conditions enclosed in parentheses: `(attribute=value)`
- Boolean operators: `&` (AND), `|` (OR), `!` (NOT)
- Example: `(&(uid=admin)(password=secret))` requires both conditions true

### 1.2 Injection Attack Categories

#### Category 1: Wildcard Matching

**Concept**: Wildcard character `*` matches any value.

**Attack approach**: Inject wildcard to bypass exact value matching.

**Example logic**: `(&(uid=admin*)(password=...))` matches any user starting with "admin".

#### Category 2: Boolean Operator Manipulation

**Concept**: Inject parentheses and operators to restructure filter logic.

**Attack approach**: Create tautology (always-true conditions) via OR operators and wildcards.

**Example logic**: Restructure filter so at least one component is always true.

#### Category 3: Filter Restructuring

**Concept**: Close and reopen filters to inject additional conditions.

**Attack approach**: Use parenthesis manipulation to bypass authentication checks.

**Example logic**: Inject `)(&(` to escape current context and create new conditions.

### 1.3 Blind LDAP Injection

**Concept**: Extract data when no direct output, using boolean-based inference.

**Techniques**:
- Length enumeration via wildcard character counts
- Binary search for character-by-character extraction
- Pattern matching via prefix/suffix tests

**Tool**: `ldapsearch` for manual testing, custom scripts for automation.

---

## Part 2: NoSQL Injection

### 2.1 NoSQL Basics

**NoSQL** - document stores (MongoDB), key-value (Redis), use alternative query languages.

**Common deployment contexts**:
- REST API authentication endpoints
- JSON-based search/filter features
- Document query interfaces

**Query Structure**:
- JSON objects as query conditions: `{"username": "admin", "password": "secret"}`
- Operators for conditions: `$ne`, `$gt`, `$regex`, `$where`, etc.
- JavaScript eval contexts in some systems

### 2.2 MongoDB Injection Attack Categories

#### Category 1: Operator Injection

**Concept**: Replace string values with operator objects to change query logic.

**Operators**:
- `$ne` (not equal) - matches any document with field present
- `$gt` (greater than empty string) - matches any value
- `$regex` - pattern matching for enumeration
- `$exists` - field existence check

**Attack approach**: Send operator objects instead of string values.

**Example logic**: `{"username": {"$ne": null}}` matches any document.

#### Category 2: JavaScript Eval Clauses

**Concept**: $where clause executes JavaScript with database context access.

**Capabilities**: Time-based blind injection, JavaScript RCE primitives.

**Limitation**: Often disabled in production due to security.

**Tool**: `nosqlmap` for detection.

#### Category 3: Regex-Based Enumeration

**Concept**: $regex operator for pattern-based username discovery.

**Technique**: Binary search with regex patterns to determine valid usernames.

**Example**: `{"username": {"$regex": "^admin"}, "password": {"$ne": null}}`

### 2.3 Redis Command Injection

**Concept**: Redis EVAL command executes Lua scripts with system access.

**Attack chain**: SSRF → Gopher protocol → Redis EVAL → RCE.

**Technique**: Craft gopher protocol URLs to execute EVAL commands.

**Limitation**: Requires internal access to Redis (unprotected or SSRF vector).

---

## Part 3: Testing Methodology

### Step 1: Identify Injection Point

**For LDAP**:
- Login forms with backend LDAP
- Directory search features
- User lookup endpoints

**For NoSQL**:
- REST API with JSON bodies
- Login endpoints without input validation
- Search/filter APIs

### Step 2: Determine Database Type

**LDAP indicators**:
- "LDAP" explicitly mentioned in application
- Enterprise directory context
- AD/LDAP error messages

**NoSQL indicators**:
- MongoDB, CouchDB, Redis keywords
- JSON request bodies
- "Connection refused" to MongoDB ports

### Step 3: Craft Injection Payloads

**LDAP approach**:
- Start with wildcard injection
- Progress to boolean operator manipulation
- Use blind techniques if no direct feedback

**NoSQL approach**:
- Test operator injection first
- Enumerate valid usernames
- Attempt $where clause if enabled
- Fallback to time-based blind detection

### Step 4: Exploitation Testing

**LDAP objectives**:
- Bypass authentication
- Extract directory information
- Enumerate users

**NoSQL objectives**:
- Bypass authentication
- Enumerate usernames
- Extract user data
- RCE (if $where accessible)

---

## Part 4: Tools Reference

### LDAP Tools

**ldapsearch**:
- Manual LDAP query testing
- Filter syntax validation
- Direct LDAP server access

**ldapdomaindump**:
- Active Directory enumeration
- Complete directory structure discovery

**Custom scripts**:
- Automated blind injection enumeration
- Character-by-character extraction

### NoSQL Tools

**nosqlmap**:
- MongoDB injection detection
- Automated operator testing
- Blind injection extraction
- Database enumeration

**Burp Suite**:
- JSON payload manipulation
- Timing analysis for blind detection
- Repeater for manual testing

**Custom scripts**:
- Regex-based username enumeration
- Binary search for data extraction

---

## Part 5: Common Attack Scenarios

### Scenario 1: LDAP Auth Bypass

**Target**: Login form with LDAP backend.

**Attack chain**:
1. Identify LDAP usage (error messages, application behavior)
2. Test wildcard injection in username
3. Test boolean operator manipulation
4. Confirm authentication bypass

**Success metric**: Login without valid password.

### Scenario 2: MongoDB Operator Injection

**Target**: REST API with JSON login endpoint.

**Attack chain**:
1. Identify NoSQL backend (MongoDB indicators)
2. Test operator injection ($ne, $gt)
3. Enumerate valid usernames via regex
4. Confirm authentication bypass

**Success metric**: Receive session token/JWT.

### Scenario 3: Blind LDAP/NoSQL Extraction

**Target**: Endpoints with no direct data output.

**Attack chain**:
1. Confirm injection (boolean response difference)
2. Enumerate field lengths via binary search
3. Extract data character-by-character
4. Recover sensitive information

**Success metric**: Complete password/data extracted.

---

## Part 6: Detection and Monitoring

**Indicators of attack**:
- LDAP filter syntax errors in logs
- Unusual filter patterns (wildcards, boolean operators)
- Multiple failed authentication attempts
- NoSQL operator keywords in request bodies
- Regex patterns with * wildcards

**Defensive measures**:
- Input validation and escaping
- Parameterized queries
- Type checking for input values
- Rate limiting on auth endpoints
- Security logging and alerting

---

*This guide provides reference material for understanding LDAP and NoSQL injection techniques. Actual testing uses tools like ldapsearch, nosqlmap, and Burp Suite.*
