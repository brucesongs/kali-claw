# MCP Tool Security Patterns Guide

> Practical reference for securing MCP (Model Context Protocol) server tools through input validation, sandboxing, permission models, and defense-in-depth strategies. Covers common attack vectors and mitigation patterns.

## 1. Input Validation for MCP Tools

Every tool parameter is an attack surface. Validate before processing.

```python
# Secure MCP tool with comprehensive input validation
from dataclasses import dataclass
from typing import Any
import re
import os

@dataclass(frozen=True)
class ValidationError:
    field: str
    message: str

def validate_tool_input(params: dict, schema: dict) -> list:
    """Validate MCP tool parameters against schema."""
    errors = []
    
    for field, rules in schema.items():
        value = params.get(field)
        
        # Required check
        if rules.get("required") and value is None:
            errors.append(ValidationError(field, "Required field missing"))
            continue
        
        if value is None:
            continue
        
        # Type check
        expected_type = rules.get("type")
        if expected_type and not isinstance(value, expected_type):
            errors.append(ValidationError(field, f"Expected {expected_type.__name__}"))
            continue
        
        # String constraints
        if isinstance(value, str):
            if "max_length" in rules and len(value) > rules["max_length"]:
                errors.append(ValidationError(field, f"Exceeds max length {rules['max_length']}"))
            if "pattern" in rules and not re.match(rules["pattern"], value):
                errors.append(ValidationError(field, f"Does not match pattern"))
            if "disallow" in rules:
                for forbidden in rules["disallow"]:
                    if forbidden in value:
                        errors.append(ValidationError(field, f"Contains forbidden: {forbidden}"))
    
    return errors

# Usage in MCP tool handler
TOOL_SCHEMA = {
    "file_path": {
        "required": True,
        "type": str,
        "max_length": 255,
        "pattern": r"^[a-zA-Z0-9_\-./]+$",
        "disallow": ["..", "~", "$", "`", ";", "|", "&"]
    },
    "command": {
        "required": True,
        "type": str,
        "max_length": 1000,
        "disallow": [";", "&&", "||", "`", "$(", "${"]
    }
}
```

## 2. Path Traversal Prevention

```python
# Secure file access within MCP tools
import os
from pathlib import Path

ALLOWED_BASE_DIRS = [
    Path("/workspace"),
    Path("/tmp/mcp-sandbox"),
]

def safe_resolve_path(user_path: str, base_dir: Path) -> Path:
    """Resolve path safely, preventing traversal attacks."""
    # Normalize and resolve
    resolved = (base_dir / user_path).resolve()
    
    # Verify it's within allowed base
    if not any(str(resolved).startswith(str(allowed.resolve())) for allowed in ALLOWED_BASE_DIRS):
        raise PermissionError(f"Access denied: path outside allowed directories")
    
    # Block symlinks pointing outside sandbox
    if resolved.is_symlink():
        link_target = resolved.readlink().resolve()
        if not any(str(link_target).startswith(str(allowed.resolve())) for allowed in ALLOWED_BASE_DIRS):
            raise PermissionError(f"Access denied: symlink points outside sandbox")
    
    return resolved

def mcp_read_file(params: dict) -> dict:
    """MCP tool: Read file with security controls."""
    file_path = params.get("path", "")
    base = Path("/workspace")
    
    try:
        safe_path = safe_resolve_path(file_path, base)
    except PermissionError as e:
        return {"error": str(e), "status": "denied"}
    
    # Additional checks
    if safe_path.stat().st_size > 10 * 1024 * 1024:  # 10MB limit
        return {"error": "File too large", "status": "denied"}
    
    return {"content": safe_path.read_text(), "status": "ok"}
```

## 3. Command Execution Sandboxing

```python
import subprocess
import shlex
from typing import Optional

# Allowlist of permitted commands
ALLOWED_COMMANDS = {
    "ls", "cat", "grep", "find", "wc", "head", "tail",
    "git", "npm", "python3", "pip"
}

# Blocked patterns in arguments
BLOCKED_PATTERNS = [
    r";\s*", r"\|\|", r"&&", r"\$\(", r"`",
    r">\s*/", r"<\s*/", r"\.\./\.\."
]

def execute_sandboxed(command: str, timeout: int = 30) -> dict:
    """Execute command with sandboxing controls."""
    import re
    
    # Parse command safely
    try:
        parts = shlex.split(command)
    except ValueError as e:
        return {"error": f"Invalid command syntax: {e}", "status": "denied"}
    
    if not parts:
        return {"error": "Empty command", "status": "denied"}
    
    # Check command allowlist
    base_cmd = os.path.basename(parts[0])
    if base_cmd not in ALLOWED_COMMANDS:
        return {"error": f"Command not allowed: {base_cmd}", "status": "denied"}
    
    # Check for injection patterns
    for pattern in BLOCKED_PATTERNS:
        if re.search(pattern, command):
            return {"error": "Blocked pattern detected", "status": "denied"}
    
    # Execute with constraints
    try:
        result = subprocess.run(
            parts,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd="/workspace",
            env={"PATH": "/usr/bin:/usr/local/bin", "HOME": "/tmp"},
            # Resource limits
            preexec_fn=lambda: __import__('resource').setrlimit(
                __import__('resource').RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024)
            )
        )
        return {
            "stdout": result.stdout[:10000],  # Truncate output
            "stderr": result.stderr[:5000],
            "exit_code": result.returncode,
            "status": "ok"
        }
    except subprocess.TimeoutExpired:
        return {"error": f"Command timed out after {timeout}s", "status": "timeout"}
```

## 4. Permission Model Implementation

```python
from dataclasses import dataclass, field
from typing import FrozenSet
from enum import Enum

class Permission(Enum):
    READ_FILE = "read_file"
    WRITE_FILE = "write_file"
    EXECUTE_CMD = "execute_cmd"
    NETWORK_ACCESS = "network_access"
    INSTALL_PACKAGE = "install_package"
    GIT_WRITE = "git_write"

@dataclass(frozen=True)
class ToolPermissions:
    tool_name: str
    allowed: FrozenSet[Permission]
    denied_paths: FrozenSet[str] = frozenset()
    max_file_size_bytes: int = 10_000_000
    network_allowlist: FrozenSet[str] = frozenset()

# Define permission profiles
TOOL_PERMISSIONS = {
    "read_file": ToolPermissions(
        tool_name="read_file",
        allowed=frozenset({Permission.READ_FILE}),
        denied_paths=frozenset({"/etc/shadow", "/root/.ssh", "**/.env"})
    ),
    "write_file": ToolPermissions(
        tool_name="write_file",
        allowed=frozenset({Permission.READ_FILE, Permission.WRITE_FILE}),
        denied_paths=frozenset({"/etc/", "/usr/", "/bin/"})
    ),
    "run_command": ToolPermissions(
        tool_name="run_command",
        allowed=frozenset({Permission.EXECUTE_CMD}),
        denied_paths=frozenset()
    ),
}

def check_permission(tool: str, action: Permission, context: dict) -> bool:
    """Check if tool has permission for the requested action."""
    perms = TOOL_PERMISSIONS.get(tool)
    if not perms:
        return False  # Deny by default
    
    if action not in perms.allowed:
        return False
    
    # Check path restrictions
    target_path = context.get("path", "")
    for denied in perms.denied_paths:
        if denied.startswith("**"):
            if target_path.endswith(denied[2:]):
                return False
        elif target_path.startswith(denied):
            return False
    
    return True
```

## 5. Rate Limiting and Abuse Prevention

```python
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Tuple

@dataclass
class RateLimiter:
    """Token bucket rate limiter for MCP tool calls."""
    max_tokens: int = 100
    refill_rate: float = 10.0  # tokens per second
    _buckets: Dict[str, Tuple[float, float]] = field(default_factory=dict)
    
    def allow(self, key: str) -> bool:
        now = time.time()
        tokens, last_refill = self._buckets.get(key, (self.max_tokens, now))
        
        # Refill tokens
        elapsed = now - last_refill
        tokens = min(self.max_tokens, tokens + elapsed * self.refill_rate)
        
        if tokens >= 1:
            self._buckets[key] = (tokens - 1, now)
            return True
        
        self._buckets[key] = (tokens, now)
        return False

# Per-tool rate limits
RATE_LIMITS = {
    "read_file": RateLimiter(max_tokens=50, refill_rate=5.0),
    "write_file": RateLimiter(max_tokens=20, refill_rate=2.0),
    "run_command": RateLimiter(max_tokens=10, refill_rate=1.0),
    "network_request": RateLimiter(max_tokens=5, refill_rate=0.5),
}

def rate_limited_tool_call(tool_name: str, session_id: str) -> bool:
    """Check rate limit before allowing tool execution."""
    limiter = RATE_LIMITS.get(tool_name)
    if not limiter:
        return True  # No limit configured
    
    key = f"{session_id}:{tool_name}"
    return limiter.allow(key)
```

## 6. Audit Logging

```python
import json
import logging
from datetime import datetime, timezone
from dataclasses import dataclass, asdict

# Configure structured logging
logging.basicConfig(
    filename="/var/log/mcp/audit.jsonl",
    level=logging.INFO,
    format="%(message)s"
)
audit_logger = logging.getLogger("mcp.audit")

@dataclass(frozen=True)
class AuditEvent:
    timestamp: str
    session_id: str
    tool_name: str
    action: str
    parameters_hash: str  # Don't log sensitive params directly
    result_status: str
    client_ip: str
    duration_ms: float

def log_tool_call(session_id: str, tool: str, params: dict, result: dict, duration: float):
    """Log every tool invocation for security audit."""
    import hashlib
    
    event = AuditEvent(
        timestamp=datetime.now(timezone.utc).isoformat(),
        session_id=session_id,
        tool_name=tool,
        action="tool_call",
        parameters_hash=hashlib.sha256(json.dumps(params, sort_keys=True).encode()).hexdigest()[:16],
        result_status=result.get("status", "unknown"),
        client_ip="127.0.0.1",
        duration_ms=duration * 1000
    )
    
    audit_logger.info(json.dumps(asdict(event)))
```

## 7. Network Access Controls

```python
import ipaddress
import urllib.parse
from typing import FrozenSet

# Block internal network ranges
BLOCKED_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.169.254/32"),  # Cloud metadata
)

ALLOWED_DOMAINS: FrozenSet[str] = frozenset({
    "api.github.com",
    "registry.npmjs.org",
    "pypi.org",
})

def validate_url(url: str) -> tuple:
    """Validate URL is safe for MCP tool to access."""
    parsed = urllib.parse.urlparse(url)
    
    # Scheme check
    if parsed.scheme not in ("http", "https"):
        return False, "Only HTTP/HTTPS allowed"
    
    # Domain allowlist (if configured)
    if ALLOWED_DOMAINS and parsed.hostname not in ALLOWED_DOMAINS:
        return False, f"Domain not in allowlist: {parsed.hostname}"
    
    # Resolve and check IP
    import socket
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
        for network in BLOCKED_NETWORKS:
            if ip in network:
                return False, f"Access to internal network blocked: {ip}"
    except (socket.gaierror, ValueError):
        return False, "Could not resolve hostname"
    
    return True, "ok"
```

## 8. Defense-in-Depth Configuration

```yaml
# mcp-security-config.yaml — Layered security configuration
security:
  # Layer 1: Input validation
  input_validation:
    max_param_length: 10000
    max_params_count: 20
    blocked_characters: ["\x00", "\x1b"]
    
  # Layer 2: Authentication
  authentication:
    required: true
    method: bearer_token
    token_rotation_hours: 24
    
  # Layer 3: Authorization
  authorization:
    default_policy: deny
    role_definitions:
      reader:
        tools: [read_file, search, list_files]
      writer:
        tools: [read_file, write_file, search, list_files]
      admin:
        tools: ["*"]
    
  # Layer 4: Sandboxing
  sandbox:
    filesystem:
      root: /workspace
      writable_dirs: [/workspace, /tmp/mcp]
      max_file_size_mb: 50
    process:
      max_memory_mb: 512
      max_cpu_seconds: 60
      max_processes: 10
    network:
      allow_outbound: false
      allowed_hosts: []
      
  # Layer 5: Monitoring
  monitoring:
    audit_log: /var/log/mcp/audit.jsonl
    alert_on:
      - permission_denied_count > 10/minute
      - rate_limit_exceeded_count > 50/minute
      - blocked_path_access
```
