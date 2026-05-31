# Input Sanitization Patterns Guide

> Practical patterns for preventing XSS, SQL injection, and command injection attacks. Covers server-side validation, output encoding, parameterized queries, and safe command execution across common frameworks and languages.

---

## 1. XSS Prevention: Output Encoding

The primary defense against XSS is context-aware output encoding. Raw user input must never be inserted directly into HTML, JavaScript, or CSS contexts.

```python
# Python — context-aware encoding with MarkupSafe
from markupsafe import escape

def render_user_comment(comment: str) -> str:
    """Encode user input for safe HTML rendering."""
    return f"<div class='comment'>{escape(comment)}</div>"

# Input:  <script>alert('xss')</script>
# Output: <div class='comment'>&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;</div>
```

```javascript
// Node.js — DOMPurify for sanitizing rich HTML input
const DOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');

const window = new JSDOM('').window;
const purify = DOMPurify(window);

function sanitizeRichContent(html) {
  return purify.sanitize(html, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p'],
    ALLOWED_ATTR: ['href', 'title'],
    ALLOW_DATA_ATTR: false
  });
}
```

## 2. SQL Injection Prevention: Parameterized Queries

Never concatenate user input into SQL strings. Use parameterized queries or prepared statements exclusively.

```python
# Python — parameterized queries with psycopg2
import psycopg2

def find_user_by_email(conn, email: str):
    """Safe parameterized query — input is never part of SQL syntax."""
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, username, email FROM users WHERE email = %s AND active = %s",
        (email, True)
    )
    return cursor.fetchone()

# WRONG — vulnerable to SQL injection:
# cursor.execute(f"SELECT * FROM users WHERE email = '{email}'")
```

```bash
# Testing for SQL injection with sqlmap
sqlmap -u "http://target.com/api/users?id=1" \
  --batch \
  --level=3 \
  --risk=2 \
  --technique=BEUSTQ \
  --tamper=space2comment,between \
  --output-dir=/tmp/sqlmap-results
```

## 3. Command Injection Prevention

Never pass user input directly to shell commands. Use array-based execution or strict allowlists.

```python
# Python — safe subprocess execution (no shell=True)
import subprocess
import shlex
from pathlib import Path

ALLOWED_EXTENSIONS = {'.txt', '.log', '.csv'}

def safe_file_read(filename: str) -> str:
    """Read a file without shell injection risk."""
    path = Path(filename).resolve()

    # Validate: no path traversal, allowed extension only
    if '..' in str(path) or path.suffix not in ALLOWED_EXTENSIONS:
        raise ValueError(f"Invalid filename: {filename}")

    # Array-based execution — no shell interpretation
    result = subprocess.run(
        ['cat', str(path)],
        capture_output=True,
        text=True,
        timeout=5
    )
    return result.stdout
```

```bash
# Testing for command injection patterns
# Common injection payloads to test against your validation:
echo "test; id"
echo "test | whoami"
echo 'test $(cat /etc/passwd)'
echo "test \`uname -a\`"
echo "test%0aid"        # null byte / newline injection
```

## 4. Input Validation at System Boundaries

Schema-based validation catches malformed input before it reaches business logic.

```python
# Python — Pydantic schema validation
from pydantic import BaseModel, validator, constr
import re

class UserRegistration(BaseModel):
    username: constr(min_length=3, max_length=30, pattern=r'^[a-zA-Z0-9_]+$')
    email: constr(max_length=254)
    password: constr(min_length=12, max_length=128)

    @validator('email')
    def validate_email(cls, v):
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(pattern, v):
            raise ValueError('Invalid email format')
        return v.lower()

    @validator('password')
    def validate_password_strength(cls, v):
        if not re.search(r'[A-Z]', v) or not re.search(r'[0-9]', v):
            raise ValueError('Password must contain uppercase and digit')
        return v
```

## 5. Content-Type Validation and File Upload Safety

```python
# Python — safe file upload validation
import magic

ALLOWED_MIME_TYPES = {'image/jpeg', 'image/png', 'application/pdf'}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB

def validate_upload(file_bytes: bytes, claimed_filename: str) -> bool:
    """Validate file by magic bytes, not extension or Content-Type header."""
    if len(file_bytes) > MAX_FILE_SIZE:
        raise ValueError("File exceeds maximum size")

    # Detect actual MIME type from file content
    detected_type = magic.from_buffer(file_bytes, mime=True)

    if detected_type not in ALLOWED_MIME_TYPES:
        raise ValueError(f"File type {detected_type} not allowed")

    # Strip path components to prevent directory traversal
    safe_name = os.path.basename(claimed_filename)
    if safe_name != claimed_filename:
        raise ValueError("Filename contains path separators")

    return True
```

## 6. Defense-in-Depth Checklist

| Layer | Control | Implementation |
|-------|---------|----------------|
| Input | Schema validation | Pydantic, Joi, Zod |
| Processing | Parameterized queries | Prepared statements |
| Output | Context-aware encoding | MarkupSafe, DOMPurify |
| Transport | Content-Security-Policy | HTTP headers |
| Storage | Encrypted at rest | AES-256-GCM |

Always apply multiple layers. No single sanitization technique is sufficient on its own — combine input validation, parameterized queries, output encoding, and security headers for robust protection.
