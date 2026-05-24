# Code Review Security Patterns Guide

> Skill: security-review | Type: methodology
> Created: 2026-05-23 | Estimated Study Time: 40 minutes

## Overview

Learn to perform security-focused code reviews for applications. Covers pattern recognition, vulnerability identification, secure coding assessment, and automated review workflows.

## Prerequisites

- Basic programming knowledge
- Understanding of common vulnerability types
- Familiarity with OWASP Top 10

## 1. Code Review Framework

### Review Process Flow

```
┌─────────────────────────────────────────────────────────────┐
│                    CODE REVIEW PROCESS                       │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │  SCOPE       │───→│  SCAN       │───→│  ANALYZE     │  │
│  │  (Identify   │    │  (Pattern   │    │  (Context    │  │
│  │   Entry)     │    │   Match)    │    │   Validate)  │  │
│  └──────────────┘    └──────────────┘    └──────────────┘  │
│         │                                        │           │
│         │                                        ↓           │
│         │                                ┌──────────────┐   │
│         │                                │   VERIFY    │   │
│         │                                │ (Prove      │   │
│         │                                │  Exploit)    │   │
│         │                                └──────────────┘   │
│         │                                        │           │
│         │                                        ↓           │
│         │                                ┌──────────────┐   │
│         └───────────────────────────────│   REPORT    │   │
│                                          │ (Document +  │   │
│                                          │  Recommend)  │   │
│                                          └──────────────┘   │
│                                                               │
└───────────────────────────────────────────────────────────────┘
```

### Entry Point Identification

```bash
# Identify all entry points in codebase
echo "=== ENTRY POINT ANALYSIS ==="

# HTTP endpoints (web frameworks)
find . -name "*.py" -exec grep -l "@app.route\|@bp.route\|@router.get" {} \;
find . -name "*.js" -exec grep -l "app.get\|app.post\|router.get" {} \;

# API endpoints
find . -name "*.py" -exec grep -l "api_endpoint\|@api.route" {} \;
find . -name "*.ts" -exec grep -l "@Get\|@Post\|@Put\|@Delete" {} \;

# File uploads
grep -r "upload\|multipart\|form-data" --include="*.py" --include="*.js"

# External API calls
grep -r "requests.\|fetch(\|axios\|http.get" --include="*.py" --include="*.js"

# Database queries
grep -r "SELECT\|INSERT\|UPDATE\|DELETE" --include="*.py" --include="*.js" | grep -v "comment\|docstring"
```

## 2. Vulnerability Pattern Recognition

### SQL Injection Patterns

```python
# VULNERABLE: String concatenation
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id  # VULNERABLE
    return db.execute(query)

# VULNERABLE: f-string with user input
def login(username, password):
    query = f"SELECT * FROM users WHERE username = '{username}'"  # VULNERABLE

# VULNERABLE: String formatting
def search(term):
    query = "SELECT * FROM products WHERE name LIKE '%{}%'".format(term)  # VULNERABLE

# SECURE: Parameterized queries
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = %s"
    return db.execute(query, (user_id,))

# SECURE: ORM with parameter binding
def login(username, password):
    return User.query.filter_by(username=username).first()
```

**Detection Commands:**
```bash
# Find SQLi patterns in Python
grep -rn "SELECT.*\+" --include="*.py" | grep -v "comment\|docstring"
grep -rn 'f".*SELECT' --include="*.py"
grep -rn "\.format(.*SELECT" --include="*.py"

# Find SQLi patterns in JavaScript
grep -rn "query.*\+" --include="*.js"
grep -rn '`${.*}.*SELECT' --include="*.js"
```

### XSS Patterns

```python
# VULNERABLE: Direct render of user input
def render_comment(comment):
    return f"<div>{comment}</div>"  # VULNERABLE

# VULNERABLE: Using mark_safe or similar
def render_content(content):
    return mark_safe(content)  # VULNERABLE

# SECURE: HTML escaping
from markupsafe import escape
def render_comment(comment):
    return f"<div>{escape(comment)}</div>"

# SECURE: Auto-escaping template engine
# Jinja2 auto-escapes by default
```

```javascript
// VULNERABLE: innerHTML with user input
function renderComment(comment) {
    document.getElementById('output').innerHTML = comment;  // VULNERABLE
}

// VULNERABLE: dangerouslySetInnerHTML
function renderContent(content) {
    return <div dangerouslySetInnerHTML={{__html: content}} />;  // VULNERABLE
}

// SECURE: textContent
function renderComment(comment) {
    document.getElementById('output').textContent = comment;
}
```

**Detection Commands:**
```bash
# Find XSS patterns in Python
grep -rn "innerHTML\|dangerouslySetInnerHTML" --include="*.py"

# Find XSS patterns in JavaScript/React
grep -rn "innerHTML\|dangerouslySetInnerHTML" --include="*.js" --include="*.tsx"
grep -rn "mark_safe" --include="*.py"
```

### Command Injection Patterns

```python
# VULNERABLE: os.system with user input
import os
def ping(target):
    os.system(f"ping -c 4 {target}")  # VULNERABLE

# VULNERABLE: subprocess with shell=True
def run_command(cmd):
    result = subprocess.run(cmd, shell=True, capture_output=True)  # VULNERABLE

# VULNERABLE: Passing unsanitized input to exec
def compile_code(code_file):
    os.execvp("gcc", ["gcc", code_file])  # VULNERABLE if code_file from user

# SECURE: Using subprocess without shell
import subprocess
def ping(target):
    result = subprocess.run(["ping", "-c", "4", target], capture_output=True)
    return result.stdout.decode()

# SECURE: Input validation
import re
def run_command(cmd):
    if not re.match(r'^[a-z0-9_-]+$', cmd):
        raise ValueError("Invalid command")
    subprocess.run([cmd], check=True)
```

**Detection Commands:**
```bash
# Find command injection patterns
grep -rn "os.system\|os.popen\|subprocess.*shell=True" --include="*.py"
grep -rn "exec(\|eval(\|system(" --include="*.js"
```

### Path Traversal Patterns

```python
# VULNERABLE: Direct use of user input in file path
def read_file(filename):
    with open(f"/uploads/{filename}") as f:  # VULNERABLE
        return f.read()

# VULNERABLE: No path validation
def serve_image(img):
    return send_from_directory('/static', img)  # VULNERABLE if img from user

# SECURE: Path sanitization
import os
def read_file(filename):
    base = "/uploads"
    filepath = os.path.join(base, filename)
    if not os.path.abspath(filepath).startswith(base):
        raise ValueError("Invalid path")
    with open(filepath) as f:
        return f.read()

# SECURE: Safe basename extraction
def serve_image(img):
    safe_img = os.path.basename(img)
    return send_from_directory('/static', safe_img)
```

**Detection Commands:**
```bash
# Find path traversal patterns
grep -rn "open(.*/.*)" --include="*.py" | grep -v "comment\|docstring"
grep -rn "send_from_directory\|send_file" --include="*.py"
```

### SSRF Patterns

```python
# VULNERABLE: User-controlled URL in request
def fetch_url(url):
    response = requests.get(url)  # VULNERABLE
    return response.text

# VULNERABLE: No URL validation
def webhook_callback(url):
    requests.post(url, json={'status': 'completed'})  # VULNERABLE

# SECURE: URL validation and allowlist
import validators
from urllib.parse import urlparse

def fetch_url(url):
    if not validators.url(url):
        raise ValueError("Invalid URL")

    parsed = urlparse(url)
    allowed_hosts = ['api.example.com', 'cdn.example.com']
    if parsed.netloc not in allowed_hosts:
        raise ValueError("URL not in allowlist")

    response = requests.get(url, timeout=5)
    return response.text
```

**Detection Commands:**
```bash
# Find SSRF patterns
grep -rn "requests.get(url)" --include="*.py"
grep -rn "fetch(url)" --include="*.js"
```

## 3. Secrets Management Review

### Hardcoded Secrets Detection

```bash
# Search for API keys
grep -rn "api_key\|apikey\|API_KEY" --include="*.py" --include="*.js"

# Search for passwords
grep -rn "password\s*=" --include="*.py" --include="*.js"

# Search for tokens
grep -rn "token\|bearer\|secret" --include="*.py" --include="*.js"

# Search for database credentials
grep -rn "mysql://\|mongodb://\|postgres://" --include="*.py"

# Search for AWS keys
grep -rn "AWS_ACCESS_KEY\|AWS_SECRET_KEY" --include="*.py"
```

### Environment Variable Usage

```python
# GOOD: Using environment variables
import os
DATABASE_URL = os.getenv('DATABASE_URL')
API_KEY = os.getenv('API_KEY')

# GOOD: With fallback
API_KEY = os.getenv('API_KEY', 'default-dev-key')

# GOOD: Validation
def get_config():
    required = ['DATABASE_URL', 'API_KEY']
    missing = [k for k in required if not os.getenv(k)]
    if missing:
        raise ValueError(f"Missing required env vars: {missing}")
    return {k: os.getenv(k) for k in required}
```

## 4. Authentication & Authorization Review

### Session Management Patterns

```python
# VULNERABLE: Weak session ID generation
import random
def generate_session_id():
    return str(random.randint(0, 1000000))  # VULNERABLE

# VULNERABLE: Session fixation
def login(username, password):
    session_id = request.cookies.get('session_id')  # VULNERABLE
    if not session_id:
        session_id = generate_session_id()
    # Use provided session without regeneration

# SECURE: Secure session generation
import secrets
def generate_session_id():
    return secrets.token_hex(32)

# SECURE: Session regeneration on login
def login(username, password):
    # Authenticate user
    if authenticate(username, password):
        # Regenerate session
        session.regenerate()
        session['user_id'] = user.id
```

### Authorization Patterns

```python
# VULNERABLE: Missing authorization check
def delete_account(account_id):
    # No check if user has permission
    db.delete_account(account_id)  # VULNERABLE

# VULNERABLE: IDOR - direct object reference
def get_document(doc_id):
    doc = db.get_document(doc_id)  # VULNERABLE - no ownership check
    return doc

# SECURE: Role-based authorization
def delete_account(account_id):
    current_user = get_current_user()
    if not current_user.has_permission('admin'):
        raise Forbidden("Insufficient permissions")
    db.delete_account(account_id)

# SECURE: Ownership verification
def get_document(doc_id):
    current_user = get_current_user()
    doc = db.get_document(doc_id)
    if doc.owner_id != current_user.id:
        raise Forbidden("Access denied")
    return doc
```

**Detection Commands:**
```bash
# Find missing authorization patterns
grep -rn "def delete_\|def update_\|def get_" --include="*.py" -A 5 | grep -v "@auth_required\|@login_required"

# Find IDOR patterns
grep -rn "\.get(.*id)\|\.find(.*id)" --include="*.py" -B 2 -A 5 | grep -v "owner_id\|user_id\|permission"
```

## 5. Automated Review Tools

### Using Gitleaks

```bash
# Scan repository for secrets
gitleaks detect --source /path/to/repo --report gitleaks-report.json

# Scan with custom config
gitleaks detect --source /path/to/repo --config gitleaks.toml

# Scan specific file
gitleaks detect --source /path/to/file --no-git
```

### Using Semgrep

```bash
# Install security rules
semgrep --config auto --install

# Run with OWASP rules
semgrep --config owasp-top-10 /path/to/repo

# Run custom rules
semgrep --config rules/ /path/to/repo

# Output JSON for parsing
semgrep --config owasp-top-10 --json /path/to/repo > semgrep-report.json
```

### Using Bandit (Python)

```bash
# Scan Python code
bandit -r /path/to/repo

# Output JSON
bandit -r /path/to/repo -f json > bandit-report.json

# Skip specific tests
bandit -r /path/to/repo -s B201,B301

# Report severity only
bandit -r /path/to/repo -ll
```

### Using ESLint with Security Plugins

```bash
# Install security plugin
npm install eslint-plugin-security --save-dev

# Run with security rules
eslint --plugin security /path/to/js

# Config in .eslintrc.json
{
  "plugins": ["security"],
  "extends": ["plugin:security/recommended"]
}
```

## 6. Code Review Checklist

### Pre-Review Preparation

```markdown
## Code Review Preparation

### Scope Definition
- [ ] Review boundaries defined (files, modules, features)
- [ ] Entry points identified
- [ ] Data flows mapped
- [ ] Authentication boundaries known

### Tools Ready
- [ ] Static analysis tool installed
- [ ] Dependency scanner configured
- [ ] Pattern matching rules loaded
- [ ] Report template prepared
```

### Review Checklist

```markdown
## Security Review Checklist

### Secrets Management
- [ ] No hardcoded credentials
- [ ] Secrets loaded from environment
- [ ] Secrets not in logs
- [ ] Secrets not in error messages
- [ ] Secrets rotated periodically

### Input Validation
- [ ] All user inputs validated
- [ ] Type checking implemented
- [ ] Length limits enforced
- [ ] Character filtering applied
- [ ] Allowlist used over denylist

### Injection Prevention
- [ ] SQL: Parameterized queries
- [ ] NoSQL: Safe operators
- [ ] Command: Shell=False
- [ ] Template: Context-aware escaping
- [ ] LDAP: Proper escaping

### Authentication
- [ ] Strong password policy
- [ ] MFA for sensitive operations
- [ ] Secure session management
- [ ] Session regeneration on login
- [ ] Secure session storage (httpOnly cookies)

### Authorization
- [ ] Role-based access control
- [ ] Least privilege principle
- [ ] IDOR checks on all object access
- [ ] Admin operations protected
- [ ] API rate limiting

### Output Encoding
- [ ] XSS protection enabled
- [ ] HTML context: htmlspecialchars
- [ ] JavaScript context: JSON serialization
- [ ] URL context: URL encoding
- [ ] CSS context: CSS escaping

### Security Headers
- [ ] Strict-Transport-Security
- [ ] Content-Security-Policy
- [ ] X-Frame-Options
- [ ] X-Content-Type-Options
- [ ] X-XSS-Protection

### Error Handling
- [ ] No stack traces to users
- [ ] Generic error messages
- [ ] Errors logged securely
- [ ] No sensitive data in errors
- [ ] Proper HTTP status codes

### Dependencies
- [ ] No known vulnerabilities
- [ ] Dependencies up to date
- [ ] Vulnerability scanning enabled
- [ ] License compliance checked
- [ ] Supply chain verified
```

## Quick Reference

```bash
# SQLi patterns
grep -rn "SELECT.*\+" --include="*.py"
grep -rn 'f".*SELECT' --include="*.py"

# XSS patterns
grep -rn "innerHTML\|dangerouslySetInnerHTML" --include="*.js"
grep -rn "mark_safe" --include="*.py"

# Command injection
grep -rn "os.system\|subprocess.*shell=True" --include="*.py"
grep -rn "exec(\|eval(" --include="*.js"

# Secrets
grep -rn "api_key\|password\s*=" --include="*.py"

# Automated tools
gitleaks detect --source .
semgrep --config owasp-top-10 .
bandit -r .
```

## Integration with Other Skills

- **security-review**: OWASP audit methodology
- **repo-scan**: Codebase analysis and attack surface identification
- **verification-loop**: Proof-of-concept verification of findings
- **web-assessment**: Web application-specific patterns
- **knowledge-ops**: Security findings as knowledge entities