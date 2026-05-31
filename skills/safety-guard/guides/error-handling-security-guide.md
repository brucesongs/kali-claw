# Error Handling Security Guide

> Secure error handling patterns that prevent information leakage while maintaining debuggability. Covers safe error messages, stack trace suppression, structured logging without sensitive data exposure, and environment-aware error responses.

---

## 1. Safe Error Responses: User-Facing vs Internal

Never expose internal details (stack traces, database errors, file paths) to end users. Map internal errors to generic, safe messages.

```python
# Python — Error classification and safe response mapping
from enum import Enum
from dataclasses import dataclass
import logging
import uuid

logger = logging.getLogger(__name__)

class ErrorCategory(Enum):
    VALIDATION = "validation_error"
    AUTHENTICATION = "auth_error"
    AUTHORIZATION = "forbidden"
    NOT_FOUND = "not_found"
    INTERNAL = "internal_error"
    RATE_LIMITED = "rate_limited"

SAFE_MESSAGES = {
    ErrorCategory.VALIDATION: "The request contains invalid parameters.",
    ErrorCategory.AUTHENTICATION: "Authentication required.",
    ErrorCategory.AUTHORIZATION: "You do not have permission for this action.",
    ErrorCategory.NOT_FOUND: "The requested resource was not found.",
    ErrorCategory.INTERNAL: "An internal error occurred. Reference: {error_id}",
    ErrorCategory.RATE_LIMITED: "Too many requests. Please retry later.",
}

@dataclass(frozen=True)
class SafeErrorResponse:
    error_id: str
    category: ErrorCategory
    message: str
    status_code: int

def create_safe_error(category: ErrorCategory, internal_error: Exception) -> SafeErrorResponse:
    """Create a user-safe error response while logging full details internally."""
    error_id = str(uuid.uuid4())[:8]

    # Log full details internally — never sent to client
    logger.error(
        "Error %s [%s]: %s",
        error_id, category.value, str(internal_error),
        exc_info=True,
        extra={'error_id': error_id, 'category': category.value}
    )

    safe_message = SAFE_MESSAGES[category].format(error_id=error_id)
    status_map = {
        ErrorCategory.VALIDATION: 400,
        ErrorCategory.AUTHENTICATION: 401,
        ErrorCategory.AUTHORIZATION: 403,
        ErrorCategory.NOT_FOUND: 404,
        ErrorCategory.INTERNAL: 500,
        ErrorCategory.RATE_LIMITED: 429,
    }

    return SafeErrorResponse(
        error_id=error_id,
        category=category,
        message=safe_message,
        status_code=status_map[category]
    )
```

## 2. Stack Trace Suppression

```python
# Python Flask — Environment-aware error handler
import os
from flask import Flask, jsonify

app = Flask(__name__)
IS_PRODUCTION = os.getenv('FLASK_ENV') == 'production'

@app.errorhandler(Exception)
def handle_all_errors(error):
    """Suppress stack traces in production, show in development."""
    error_id = str(uuid.uuid4())[:8]

    if IS_PRODUCTION:
        # Production: generic message + correlation ID
        response = {
            'error': 'An unexpected error occurred.',
            'reference': error_id
        }
        # Log full trace server-side only
        app.logger.exception(f"Unhandled error [{error_id}]")
    else:
        # Development: include details for debugging
        response = {
            'error': str(error),
            'type': type(error).__name__,
            'reference': error_id
        }

    return jsonify(response), 500

@app.errorhandler(404)
def handle_not_found(error):
    """Don't reveal URL patterns or internal routing."""
    return jsonify({'error': 'Resource not found.'}), 404
```

```nginx
# nginx — Custom error pages that hide server internals
server {
    # Hide server version
    server_tokens off;

    # Custom error pages — no default nginx error pages
    error_page 400 /errors/400.json;
    error_page 403 /errors/403.json;
    error_page 404 /errors/404.json;
    error_page 500 502 503 504 /errors/500.json;

    location /errors/ {
        internal;
        root /var/www/static;
        default_type application/json;
    }

    # Strip server identification headers
    proxy_hide_header X-Powered-By;
    proxy_hide_header Server;
    add_header Server "webserver" always;
}
```

## 3. Logging Without Leaking Sensitive Data

```python
# Python — Structured logging with automatic PII redaction
import re
import json
import logging

REDACTION_PATTERNS = [
    (re.compile(r'password["\s:=]+["\']?[\w!@#$%^&*]+', re.I), 'password=***REDACTED***'),
    (re.compile(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'), '***CARD-REDACTED***'),
    (re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'), '***EMAIL-REDACTED***'),
    (re.compile(r'Bearer\s+[A-Za-z0-9\-._~+/]+=*', re.I), 'Bearer ***TOKEN-REDACTED***'),
    (re.compile(r'(api[_-]?key|secret|token)["\s:=]+["\']?[\w\-]+', re.I), r'\1=***REDACTED***'),
]

class RedactingFormatter(logging.Formatter):
    """Log formatter that strips sensitive data before writing."""

    def format(self, record):
        message = super().format(record)
        for pattern, replacement in REDACTION_PATTERNS:
            message = pattern.sub(replacement, message)
        return message

# Usage
handler = logging.StreamHandler()
handler.setFormatter(RedactingFormatter(
    '%(asctime)s %(levelname)s [%(name)s] %(message)s'
))
logger = logging.getLogger()
logger.addHandler(handler)
```

## 4. Database Error Sanitization

```python
# Python — Catch database errors and return safe messages
from sqlalchemy.exc import (
    IntegrityError, OperationalError, ProgrammingError, DataError
)

def handle_db_error(error: Exception, error_id: str) -> tuple[str, int]:
    """Map database exceptions to safe user messages."""
    if isinstance(error, IntegrityError):
        # Could be duplicate key — don't reveal column names
        logger.warning(f"[{error_id}] Integrity error: {error}")
        return "The request conflicts with existing data.", 409

    if isinstance(error, DataError):
        # Invalid data format — don't reveal schema
        logger.warning(f"[{error_id}] Data error: {error}")
        return "Invalid data format in request.", 400

    if isinstance(error, OperationalError):
        # Connection issues — don't reveal infrastructure
        logger.error(f"[{error_id}] Operational error: {error}")
        return "Service temporarily unavailable.", 503

    # Catch-all for unexpected database errors
    logger.critical(f"[{error_id}] Unexpected DB error: {error}", exc_info=True)
    return "An internal error occurred.", 500
```

## 5. Error Response Testing

```bash
# Test that production errors don't leak information
# Check for stack traces in error responses
curl -s https://target.com/nonexistent-path | \
  grep -iE "(traceback|at line|exception|stack trace|debug)" && \
  echo "WARNING: Stack trace leakage detected"

# Check for server version disclosure
curl -sI https://target.com | grep -iE "(server:|x-powered-by:|x-aspnet)"

# Trigger validation errors and check response format
curl -s -X POST https://target.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"email": "not-an-email", "password": "x"}' | \
  python3 -c "
import sys, json
resp = json.load(sys.stdin)
# Should NOT contain: field names, SQL errors, file paths
dangerous = ['column', 'table', 'SELECT', '/var/', '/home/', 'Traceback']
for term in dangerous:
    if term.lower() in json.dumps(resp).lower():
        print(f'LEAK DETECTED: {term}')
        sys.exit(1)
print('OK: No information leakage detected')
"
```

## 6. Security Error Handling Checklist

| Concern | Production Behavior | Development Behavior |
|---------|-------------------|---------------------|
| Stack traces | Never exposed | Shown in response |
| Error details | Generic message + ID | Full exception info |
| Server headers | Stripped/generic | Default |
| Database errors | Mapped to safe messages | Raw error shown |
| File paths | Never in responses | Allowed |
| Logging | Full details, PII redacted | Full details, verbose |

The error reference ID bridges the gap between user-facing safety and internal debuggability. Users report the ID; engineers use it to find the full trace in logs.
