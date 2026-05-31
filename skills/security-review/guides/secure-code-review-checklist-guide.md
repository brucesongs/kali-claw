# Secure Code Review Checklist Guide

> Practical reference for conducting security-focused code reviews using OWASP methodology. Covers language-specific vulnerability patterns, review workflows, and common security anti-patterns.

## 1. OWASP Code Review Methodology

Structure reviews around the OWASP Top 10 categories for systematic coverage.

```yaml
# Review priority order (highest risk first)
review_checklist:
  - category: A01 Broken Access Control
    check: Authorization on every endpoint, IDOR prevention, CORS config
  - category: A02 Cryptographic Failures
    check: Weak algorithms, hardcoded keys, missing encryption at rest/transit
  - category: A03 Injection
    check: SQL, NoSQL, OS command, LDAP, XPath injection vectors
  - category: A04 Insecure Design
    check: Missing rate limits, business logic flaws, trust boundaries
  - category: A05 Security Misconfiguration
    check: Default credentials, verbose errors, unnecessary features enabled
  - category: A06 Vulnerable Components
    check: Outdated dependencies, known CVEs, unmaintained libraries
  - category: A07 Auth Failures
    check: Weak passwords allowed, missing MFA, session fixation
  - category: A08 Data Integrity Failures
    check: Deserialization, unsigned updates, CI/CD pipeline security
  - category: A09 Logging Failures
    check: Missing audit logs, sensitive data in logs, no alerting
  - category: A10 SSRF
    check: Unvalidated URLs, internal network access, cloud metadata
```

## 2. Input Validation Patterns

```python
# VULNERABLE: No input validation
@app.route('/user/<user_id>')
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"  # SQL injection
    return db.execute(query)

# SECURE: Parameterized query + type validation
@app.route('/user/<int:user_id>')
def get_user(user_id: int):
    query = "SELECT * FROM users WHERE id = %s"
    return db.execute(query, (user_id,))

# VULNERABLE: Path traversal
@app.route('/download')
def download():
    filename = request.args.get('file')
    return send_file(f'/uploads/{filename}')  # ../../etc/passwd

# SECURE: Path validation
@app.route('/download')
def download():
    filename = request.args.get('file', '')
    safe_path = os.path.realpath(os.path.join('/uploads', filename))
    if not safe_path.startswith('/uploads/'):
        abort(403)
    return send_file(safe_path)
```

## 3. Authentication and Session Review

```javascript
// VULNERABLE: JWT with no algorithm verification
const decoded = jwt.verify(token, secret); // Accepts 'none' algorithm

// SECURE: Explicit algorithm specification
const decoded = jwt.verify(token, secret, { algorithms: ['HS256'] });

// VULNERABLE: Session fixation — no regeneration after login
app.post('/login', (req, res) => {
  if (authenticate(req.body.user, req.body.pass)) {
    req.session.authenticated = true; // Same session ID
    res.redirect('/dashboard');
  }
});

// SECURE: Regenerate session after authentication
app.post('/login', (req, res) => {
  if (authenticate(req.body.user, req.body.pass)) {
    req.session.regenerate((err) => {
      req.session.authenticated = true;
      req.session.userId = user.id;
      res.redirect('/dashboard');
    });
  }
});

// CHECK: Password storage
// BAD: MD5, SHA1, SHA256 (fast hashes)
// GOOD: bcrypt, scrypt, argon2 (slow, salted)
// Verify cost factor: bcrypt rounds >= 12
```

## 4. Authorization and Access Control

```python
# VULNERABLE: Insecure Direct Object Reference (IDOR)
@app.route('/api/invoice/<invoice_id>')
@login_required
def get_invoice(invoice_id):
    return Invoice.query.get(invoice_id).to_json()  # Any user can access any invoice

# SECURE: Ownership verification
@app.route('/api/invoice/<invoice_id>')
@login_required
def get_invoice(invoice_id):
    invoice = Invoice.query.get_or_404(invoice_id)
    if invoice.owner_id != current_user.id:
        abort(403)
    return invoice.to_json()

# REVIEW CHECKLIST for access control:
# [ ] Every API endpoint has authorization check
# [ ] Horizontal privilege escalation prevented (user A can't access user B's data)
# [ ] Vertical privilege escalation prevented (user can't access admin functions)
# [ ] File uploads restricted by user context
# [ ] Bulk operations respect per-record authorization
# [ ] GraphQL/REST nested resources check parent ownership
```

## 5. Language-Specific Vulnerability Patterns

```python
# Python-specific patterns to flag during review

# Dangerous: pickle deserialization of untrusted data
import pickle
data = pickle.loads(user_supplied_bytes)  # Remote Code Execution

# Dangerous: eval/exec with user input
result = eval(request.args.get('expr'))  # Code injection

# Dangerous: YAML unsafe load
import yaml
config = yaml.load(user_input)  # Use yaml.safe_load()

# Dangerous: subprocess with shell=True
subprocess.run(f"grep {user_input} file.txt", shell=True)  # Command injection

# Dangerous: XML parsing without disabling entities
from xml.etree.ElementTree import parse  # XXE vulnerable
# Use defusedxml instead
```

```javascript
// JavaScript/Node.js patterns to flag

// Dangerous: prototype pollution
function merge(target, source) {
  for (let key in source) {
    target[key] = source[key]; // __proto__ pollution
  }
}

// Dangerous: RegExp DoS (ReDoS)
const emailRegex = /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z]{2,4})+$/;
// Catastrophic backtracking with crafted input

// Dangerous: innerHTML with user data
element.innerHTML = userInput; // XSS

// Dangerous: child_process with user input
exec(`ls ${userInput}`); // Command injection
// Use execFile with array args instead
```

## 6. Cryptography Review Points

```bash
# Grep for weak cryptographic patterns
grep -rn "MD5\|SHA1\|DES\|RC4\|ECB" src/
grep -rn "random()\|Math.random\|rand()" src/  # Insecure randomness
grep -rn "verify=False\|InsecureRequestWarning\|CERT_NONE" src/  # TLS bypass
grep -rn "hardcoded.*key\|secret.*=.*['\"]" src/  # Hardcoded secrets
```

```python
# REVIEW: Cryptographic implementation checklist
# [ ] Using AES-GCM or ChaCha20-Poly1305 (authenticated encryption)
# [ ] Key length >= 256 bits for symmetric encryption
# [ ] RSA key >= 2048 bits (prefer 4096)
# [ ] Using cryptographically secure random (secrets module, not random)
# [ ] No ECB mode (use CBC with HMAC or GCM)
# [ ] IVs/nonces are unique and never reused
# [ ] Password hashing uses bcrypt/argon2/scrypt with appropriate cost
# [ ] TLS 1.2+ enforced, no fallback to older versions

import secrets  # CORRECT: cryptographically secure
token = secrets.token_hex(32)

import random  # WRONG: predictable PRNG
token = ''.join(random.choices('abcdef0123456789', k=32))
```

## 7. Data Exposure and Logging

```python
# VULNERABLE: Sensitive data in logs
logger.info(f"User login: {username}, password: {password}")
logger.debug(f"API response: {response.json()}")  # May contain PII

# SECURE: Redact sensitive fields
logger.info(f"User login: {username}, password: [REDACTED]")
logger.debug(f"API response status: {response.status_code}")

# VULNERABLE: Verbose error messages in production
@app.errorhandler(500)
def error_handler(e):
    return jsonify({"error": str(e), "traceback": traceback.format_exc()}), 500

# SECURE: Generic error message, detailed logging server-side
@app.errorhandler(500)
def error_handler(e):
    logger.exception("Internal server error")  # Full details in logs only
    return jsonify({"error": "An internal error occurred"}), 500

# CHECK: API responses don't leak internal data
# [ ] No stack traces in production responses
# [ ] No database column names in error messages
# [ ] No internal IP addresses or paths exposed
# [ ] User enumeration prevented (same response for valid/invalid users)
# [ ] Rate limiting on authentication endpoints
```

## 8. Review Workflow Automation

```bash
# Pre-review automated checks
#!/bin/bash
echo "=== Security Code Review Automation ==="

# Check for secrets
echo "[1/5] Scanning for hardcoded secrets..."
trufflehog filesystem --directory=. --only-verified 2>/dev/null || \
  grep -rn "API_KEY\|SECRET\|PASSWORD\|TOKEN" src/ --include="*.py" --include="*.js"

# Check for dangerous functions
echo "[2/5] Checking dangerous function usage..."
grep -rn "eval\|exec\|system\|popen\|pickle.loads\|yaml.load\b" src/

# Check for SQL injection patterns
echo "[3/5] Checking SQL injection vectors..."
grep -rn "f\".*SELECT\|f\".*INSERT\|f\".*UPDATE\|f\".*DELETE" src/
grep -rn "format.*SELECT\|format.*INSERT" src/

# Check for missing auth decorators
echo "[4/5] Checking authorization coverage..."
grep -rn "@app.route\|@router" src/ | grep -v "@login_required\|@requires_auth"

# Check dependency vulnerabilities
echo "[5/5] Checking dependencies..."
pip-audit 2>/dev/null || safety check 2>/dev/null || echo "Install pip-audit or safety"

echo "=== Review complete. Manual review required for business logic. ==="
```
