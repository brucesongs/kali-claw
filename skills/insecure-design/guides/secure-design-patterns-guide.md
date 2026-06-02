# Secure Design Patterns Guide for Developers

> Catalog of security-focused design patterns that developers can apply directly: secure-by-default configuration, input validation layers, authorization patterns, session management, and fail-safe defaults. Includes code examples in multiple languages.

---

## Introduction

Secure design is not a feature you add at the end — it is a set of patterns woven into every layer of the architecture. The patterns in this guide address the most common vulnerability classes (injection, broken access control, authentication failures) at the design level, making them impossible or impractical to exploit regardless of implementation details. Each pattern includes a rationale, a structural description, and concrete code examples.

---

## Hands-on Exercise

### Pattern 1: Secure-by-Default Configuration

Every setting should default to the most restrictive option. Features start locked down and must be explicitly opened.

```python
# WRONG: Defaults allow access
@app.route("/admin/users")
def list_users():
    return jsonify(db.get_all_users())

# CORRECT: Defaults deny, require explicit opt-in
@app.route("/admin/users")
@require_role("admin")          # Explicit authorization
@require_mfa                    # Require second factor
@rate_limit(max_requests=50)    # Throttle access
def list_users():
    return jsonify(db.get_all_users())
```

```yaml
# Default configuration (most restrictive)
server:
  tls: true
  tls_min_version: "1.3"
  cors:
    allowed_origins: []           # None by default
    allow_credentials: false
  headers:
    x_frame_options: "DENY"
    content_security_policy: "default-src 'none'"
    strict_transport_security: "max-age=63072000; includeSubDomains"
```

### Pattern 2: Layered Input Validation

Validate at every boundary: network edge, application entry point, and data access layer.

```python
from pydantic import BaseModel, constr, EmailStr, validator

class CreateUserRequest(BaseModel):
    """Schema validation at the application boundary."""
    username: constr(min_length=3, max_length=32, regex=r'^[a-zA-Z0-9_-]+$')
    email: EmailStr
    role: constr(regex=r'^(user|editor)$')  # Whitelist, never free-form

    @validator('role')
    def validate_role_not_admin(cls, v):
        # Business rule: admin role cannot be set via this endpoint
        if v == 'admin':
            raise ValueError('Cannot set admin role via user creation')
        return v

# At the data access layer
def create_user(request: CreateUserRequest) -> User:
    """Parameterized query prevents injection."""
    query = "INSERT INTO users (username, email, role) VALUES (:username, :email, :role)"
    db.execute(query, {
        'username': request.username,
        'email': request.email,
        'role': request.role
    })
```

```javascript
// Node.js — layered validation
const { body, validationResult } = require('express-validator');

app.post('/api/users',
  body('username').isAlphanumeric().isLength({ min: 3, max: 32 }).escape(),
  body('email').isEmail().normalizeEmail(),
  body('role').isIn(['user', 'editor']),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    // Proceed with validated, sanitized input
  }
);
```

### Pattern 3: Authorization Gate Pattern

Centralize authorization logic behind a single gate that every request must pass through.

```python
from functools import wraps
from flask import abort

class AuthorizationGate:
    """Single point of authorization enforcement."""

    @staticmethod
    def require_permission(permission: str):
        def decorator(f):
            @wraps(f)
            def wrapper(*args, **kwargs):
                user = get_current_user()
                resource_id = kwargs.get('resource_id')

                # Check ownership OR role-based access
                if not (user.owns(resource_id) or user.has_permission(permission)):
                    log_access_denied(user, permission, resource_id)
                    abort(403)

                return f(*args, **kwargs)
            return wrapper
        return decorator

# Usage — every sensitive endpoint goes through the gate
@app.route("/api/documents/<resource_id>")
@AuthorizationGate.require_permission("document:read")
def get_document(resource_id):
    return jsonify(db.get_document(resource_id))
```

### Pattern 4: Secure Session Management

```python
import secrets
from datetime import datetime, timedelta

def create_session(user_id: str) -> dict:
    """Create a session with secure defaults."""
    session = {
        'session_id': secrets.token_urlsafe(32),   # Cryptographically random
        'user_id': user_id,
        'created_at': datetime.utcnow(),
        'expires_at': datetime.utcnow() + timedelta(minutes=30),
        'ip_address': request.remote_addr,          # Bind to IP
        'user_agent': request.headers.get('User-Agent'),  # Bind to client
        'is_mfa_verified': False,                   # MFA not yet completed
    }
    store_session(session)
    return session

def validate_session(session_id: str) -> bool:
    """Validate all session properties, not just existence."""
    session = get_session(session_id)
    if not session:
        return False
    if datetime.utcnow() > session['expires_at']:
        destroy_session(session_id)
        return False
    if session['ip_address'] != request.remote_addr:
        destroy_session(session_id)
        return False
    if not session['is_mfa_verified']:
        return False
    return True
```

### Pattern 5: Fail-Safe Defaults

When something goes wrong, the system defaults to a secure state.

```python
# WRONG: Error reveals data
@app.route("/api/users/<user_id>")
def get_user(user_id):
    user = db.get_user(user_id)
    return jsonify(user)  # If user is None, returns "null" — leaks existence

# CORRECT: Error defaults to deny
@app.route("/api/users/<user_id>")
def get_user(user_id):
    try:
        user = db.get_user(user_id)
        if not user or not current_user_can_see(user):
            # Same response whether user doesn't exist or access denied
            abort(404)
        return jsonify(user.public_profile())  # Explicit safe view
    except DatabaseError:
        log_error(f"Database error fetching user {user_id}")
        abort(500)  # Fail closed, don't expose stack traces
```

---

## References

- OWASP Secure Coding Practices: [https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)
- CWE-732: Incorrect Permission Assignment: [https://cwe.mitre.org/data/definitions/732.html](https://cwe.mitre.org/data/definitions/732.html)
- Saltzer and Schroeder: "The Protection of Information in Computer Systems" (1975) — original fail-safe defaults principle
- OWASP Proactive Controls: [https://owasp.org/www-project-proactive-controls/](https://owasp.org/www-project-proactive-controls/)
- NIST SP 800-53: Security and Privacy Controls — AC, AU, IA families
