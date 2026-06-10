# Finding Documentation and Evidence Collection Guide

## Introduction

Proper documentation of security findings is as important as the findings themselves. Without clear, reproducible evidence, even critical vulnerabilities may be dismissed or deprioritized. This guide covers evidence collection standards, documentation best practices, and chain of custody procedures that ensure findings withstand scrutiny from technical and non-technical audiences.

Documentation quality directly impacts remediation velocity. Well-documented findings with clear reproduction steps enable development teams to fix issues faster, while poorly documented findings create back-and-forth that delays remediation and increases organizational risk exposure.

Evidence serves multiple audiences: developers who need to reproduce and fix the issue, management who need to understand business impact, compliance teams who need audit trails, and future testers who reference prior findings. A single piece of evidence must be clear enough for all of these audiences without requiring verbal explanation from the original tester.

## Practical Steps

### 1. Evidence Collection Standards

Every finding must include these evidence types:

| Evidence Type | Format | Required |
|--------------|--------|----------|
| Screenshot | PNG with annotations | Yes |
| HTTP Request/Response | Raw text or HAR file | Yes for web |
| Tool Output | Raw with context | Yes |
| Console Output | Copy of terminal output | If applicable |
| Packet Capture | PCAP with filter | If network-level |
| Video Recording | MP4/GIF for multi-step | For complex exploits |
| Code Snippet | Relevant source code | If code review finding |
| Configuration File | Sanitized copy | If misconfiguration |
| Database Query Result | Anonymized output | If data exposure |

### 2. Evidence Naming Convention

Consistent naming makes evidence traceable across engagements:

```
<finding-id>-<evidence-type>-<sequence-number>.<extension>

Examples:
  F-001-screenshot-001.png
  F-001-http-request-001.txt
  F-001-http-response-001.txt
  F-001-tool-output-sqlmap.txt
  F-001-pcap-filtered.pcap
  F-002-screenshot-001.png
  F-002-video-exploit-demo.mp4
```

### 3. Automated Evidence Collection Framework

```python
#!/usr/bin/env python3
"""Automated evidence collection and management framework."""

import json
import hashlib
import os
import shutil
import subprocess
from datetime import datetime
from typing import Dict, List, Optional


class EvidenceCollector:
    """Manage evidence collection for a penetration testing engagement."""

    def __init__(self, engagement_id: str, output_dir: str = "./evidence"):
        self.engagement_id = engagement_id
        self.output_dir = os.path.join(output_dir, engagement_id)
        self.manifest_path = os.path.join(self.output_dir, "manifest.json")
        self.manifest: List[Dict] = []
        self._init_directory()

    def _init_directory(self) -> None:
        """Create evidence directory structure."""
        subdirs = ["screenshots", "http", "tool-output", "pcap", "video", "misc"]
        for subdir in subdirs:
            os.makedirs(os.path.join(self.output_dir, subdir), exist_ok=True)
        if os.path.exists(self.manifest_path):
            with open(self.manifest_path) as fh:
                self.manifest = json.load(fh)

    def _compute_hash(self, filepath: str) -> str:
        """Compute SHA-256 hash of evidence file for integrity verification."""
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as fh:
            for block in iter(lambda: fh.read(8192), b""):
                sha256.update(block)
        return sha256.hexdigest()

    def record_screenshot(
        self,
        finding_id: str,
        filepath: str,
        description: str,
        annotations: Optional[List[str]] = None,
    ) -> Dict:
        """Register a screenshot as evidence."""
        dest_dir = os.path.join(self.output_dir, "screenshots")
        dest_name = f"{finding_id}-screenshot-{len(self.manifest)+1:03d}.png"
        dest_path = os.path.join(dest_dir, dest_name)
        shutil.copy2(filepath, dest_path)

        entry = {
            "finding_id": finding_id,
            "evidence_type": "screenshot",
            "file_path": dest_path,
            "file_hash": self._compute_hash(dest_path),
            "description": description,
            "annotations": annotations or [],
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "engagement_id": self.engagement_id,
        }
        self.manifest.append(entry)
        self._save_manifest()
        return entry

    def record_http_exchange(
        self,
        finding_id: str,
        request_text: str,
        response_text: str,
        description: str,
    ) -> Dict:
        """Capture an HTTP request/response pair as evidence."""
        dest_dir = os.path.join(self.output_dir, "http")
        seq = len([e for e in self.manifest if e["evidence_type"] == "http"]) + 1
        req_path = os.path.join(dest_dir, f"{finding_id}-http-request-{seq:03d}.txt")
        resp_path = os.path.join(dest_dir, f"{finding_id}-http-response-{seq:03d}.txt")

        with open(req_path, "w") as fh:
            fh.write(request_text)
        with open(resp_path, "w") as fh:
            fh.write(response_text)

        entry = {
            "finding_id": finding_id,
            "evidence_type": "http",
            "request_file": req_path,
            "response_file": resp_path,
            "request_hash": self._compute_hash(req_path),
            "response_hash": self._compute_hash(resp_path),
            "description": description,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "engagement_id": self.engagement_id,
        }
        self.manifest.append(entry)
        self._save_manifest()
        return entry

    def record_tool_output(
        self,
        finding_id: str,
        tool_name: str,
        output_text: str,
        command_used: str,
    ) -> Dict:
        """Record raw tool output as evidence."""
        dest_dir = os.path.join(self.output_dir, "tool-output")
        dest_name = f"{finding_id}-tool-output-{tool_name}-{len(self.manifest)+1:03d}.txt"
        dest_path = os.path.join(dest_dir, dest_name)

        with open(dest_path, "w") as fh:
            fh.write(f"# Command: {command_used}\n")
            fh.write(f"# Timestamp: {datetime.utcnow().isoformat()}Z\n")
            fh.write(f"# Tool: {tool_name}\n")
            fh.write("#" + "=" * 60 + "\n\n")
            fh.write(output_text)

        entry = {
            "finding_id": finding_id,
            "evidence_type": "tool_output",
            "tool_name": tool_name,
            "file_path": dest_path,
            "file_hash": self._compute_hash(dest_path),
            "command_used": command_used,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "engagement_id": self.engagement_id,
        }
        self.manifest.append(entry)
        self._save_manifest()
        return entry

    def _save_manifest(self) -> None:
        """Persist manifest to disk."""
        with open(self.manifest_path, "w") as fh:
            json.dump(self.manifest, fh, indent=2)

    def get_findings_summary(self) -> Dict:
        """Generate summary of all evidence collected."""
        findings: Dict[str, List] = {}
        for entry in self.manifest:
            fid = entry["finding_id"]
            if fid not in findings:
                findings[fid] = []
            findings[fid].append(entry)

        return {
            "engagement_id": self.engagement_id,
            "total_evidence_items": len(self.manifest),
            "findings_count": len(findings),
            "evidence_by_type": {
                etype: sum(1 for e in self.manifest if e["evidence_type"] == etype)
                for etype in set(e["evidence_type"] for e in self.manifest)
            },
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }


# Example usage
if __name__ == "__main__":
    collector = EvidenceCollector("ENG-2026-001")

    collector.record_screenshot(
        finding_id="F-001",
        filepath="/tmp/sqli-proof.png",
        description="SQL injection error on login page",
        annotations=["Highlighted injection point", "Error confirms SQL parsing"],
    )

    collector.record_http_exchange(
        finding_id="F-001",
        request_text="GET /api/users?id=1'+OR+1=1-- HTTP/1.1\nHost: target.com",
        response_text="HTTP/1.1 200 OK\n\n[Full user table dumped]",
        description="SQL injection returns all user records",
    )

    print(json.dumps(collector.get_findings_summary(), indent=2))
```

### 4. Screenshot Best Practices

```bash
# Capture screenshot with metadata
python3 -c "
import json, datetime

evidence = {
    'timestamp': datetime.datetime.utcnow().isoformat() + 'Z',
    'tool': 'manual',
    'finding_id': 'F-001',
    'description': 'SQL injection on login page',
    'url': 'https://target.com/login',
    'evidence_file': 'F-001-sqli-login.png',
    'annotations': [
        'Highlighted injection point in username field',
        'Server error confirming SQL syntax interpretation',
    ],
}
with open('evidence-manifest.json', 'a') as f:
    json.dump(evidence, f, indent=2)
    f.write('\n')
print('Evidence recorded')
"
```

### 5. Screenshot Quality Requirements

Screenshots are the most commonly reviewed evidence type. Follow these standards:

| Requirement | Standard | Reason |
|------------|----------|--------|
| Resolution | Full browser window (not cropped to small area) | Shows full context including URL bar |
| URL bar visible | Always include browser URL bar | Proves which page is being shown |
| Annotations | Use red rectangles/arrows for key areas | Draws attention to the vulnerability indicator |
| Timestamp | Include system clock or browser extension showing time | Correlates with engagement timeline |
| Before/After | Show normal response and malicious response side-by-side | Demonstrates difference from baseline |
| Sensitive data | Redact credentials, PII with black bars | Compliance and client confidentiality |
| Format | PNG (not JPEG) | Lossless compression preserves text clarity |

### 6. HTTP Request Documentation

```bash
# Capture full HTTP exchange with curl
curl -v -s -o response_body.txt -w "\nHTTP_CODE: %{http_code}\nTIME: %{time_total}s\n" \
  "https://target.com/api/users?id=1'+OR+1=1--" \
  -H "Cookie: session=abc123" \
  -H "User-Agent: Mozilla/5.0" \
  > http_exchange.log 2>&1

# Parse and format for report
python3 -c "
with open('http_exchange.log') as f:
    content = f.read()
print('Request captured, include in finding documentation')
"
```

### 7. Advanced HTTP Evidence Capture

For more complex scenarios, capture the full HTTP exchange with all headers and timing information:

```bash
#!/bin/bash
# http-evidence.sh — Capture comprehensive HTTP evidence
# Usage: ./http-evidence.sh <url> <finding_id> <output_dir>

URL="${1:?Usage: $0 <url> <finding_id> <output_dir>}"
FINDING_ID="${2:-F-UNKNOWN}"
OUTDIR="${3:-./http-evidence}"
mkdir -p "$OUTDIR"

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
SAFE_NAME=$(echo "$URL" | md5sum | cut -c1-8)
BASENAME="${FINDING_ID}-http-${SAFE_NAME}"

echo "[$TIMESTAMP] Capturing HTTP evidence for: $URL"

# Capture full request and response with headers
curl -sv -o "$OUTDIR/${BASENAME}-body.bin" \
  -D "$OUTDIR/${BASENAME}-response-headers.txt" \
  -w "\nhttp_code:%{http_code}\ntime_total:%{time_total}\nsize_download:%{size_download}\nredirect_url:%{redirect_url}\nssl_verify:%{ssl_verify_result}\n" \
  "$URL" \
  > "$OUTDIR/${BASENAME}-curl-verbose.log" 2>&1

# Generate a combined, readable evidence file
{
  echo "# HTTP Evidence for Finding: $FINDING_ID"
  echo "# URL: $URL"
  echo "# Timestamp: $TIMESTAMP"
  echo "#"
  echo "## Request"
  echo "GET ${URL}"
  echo ""
  echo "## Response Headers"
  cat "$OUTDIR/${BASENAME}-response-headers.txt"
  echo ""
  echo "## Response Body (first 200 lines)"
  head -200 "$OUTDIR/${BASENAME}-body.bin"
  echo ""
  echo "## Curl Verbose Log"
  cat "$OUTDIR/${BASENAME}-curl-verbose.log"
} > "$OUTDIR/${BASENAME}-complete.txt"

# Compute integrity hash
sha256sum "$OUTDIR/${BASENAME}-complete.txt" > "$OUTDIR/${BASENAME}-complete.sha256"

echo "Evidence captured: $OUTDIR/${BASENAME}-complete.txt"
echo "Integrity hash:   $OUTDIR/${BASENAME}-complete.sha256"
```

### 8. HAR File Collection for Complex Flows

When a vulnerability requires multiple requests (e.g., multi-step XSS, CSRF chains), capture a HAR file:

```bash
# Using a headless browser to capture HAR
python3 -c "
import json, subprocess

# If using playwright or similar, export HAR directly
# This example shows the HAR structure for manual creation
har_template = {
    'log': {
        'version': '1.2',
        'creator': {'name': 'pentest-evidence-collector', 'version': '1.0'},
        'entries': []
    }
}

# Add entries for each request in the exploit chain
example_entry = {
    'startedDateTime': '2026-06-10T12:00:00Z',
    'request': {
        'method': 'POST',
        'url': 'https://target.com/api/comment',
        'headers': [
            {'name': 'Content-Type', 'value': 'application/json'},
            {'name': 'Cookie', 'value': '[REDACTED]'},
        ],
        'postData': {
            'mimeType': 'application/json',
            'text': json.dumps({'comment': '<script>alert(document.domain)</script>'}),
        },
    },
    'response': {
        'status': 201,
        'statusText': 'Created',
        'headers': [],
        'content': {'text': 'Comment created successfully', 'mimeType': 'text/plain'},
    },
}

har_template['log']['entries'].append(example_entry)

with open('evidence-har.json', 'w') as f:
    json.dump(har_template, f, indent=2)

print('HAR template created with exploit chain evidence')
"
```

### 9. Chain of Custody

```python
# Evidence chain of custody tracking
class EvidenceChain:
    def __init__(self, finding_id):
        self.finding_id = finding_id
        self.chain = []

    def add_entry(self, action, performed_by, details=""):
        import datetime
        self.chain.append({
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "action": action,
            "performed_by": performed_by,
            "details": details,
        })

    def verify_integrity(self):
        return len(self.chain) > 0 and all(
            entry.get("timestamp") for entry in self.chain
        )

chain = EvidenceChain("F-001")
chain.add_entry("evidence_collected", "pentester", "Initial SQLi proof captured")
chain.add_entry("evidence_verified", "lead_reviewer", "Confirmed reproducible")
```

### 10. Enhanced Chain of Custody with Integrity Verification

For engagements requiring legal-grade evidence handling, add cryptographic integrity to the chain of custody:

```python
#!/usr/bin/env python3
"""Enhanced chain of custody with cryptographic integrity."""

import hashlib
import hmac
import json
import os
from datetime import datetime
from typing import Dict, List, Optional


class SecureEvidenceChain:
    """Chain of custody with tamper detection via hash chaining."""

    def __init__(self, finding_id: str, secret_key: Optional[str] = None):
        self.finding_id = finding_id
        self.chain: List[Dict] = []
        self.key = (secret_key or os.urandom(32).hex()).encode()

    def add_entry(
        self,
        action: str,
        performed_by: str,
        file_path: Optional[str] = None,
        details: str = "",
    ) -> Dict:
        """Add a custody entry with integrity hash."""
        timestamp = datetime.utcnow().isoformat() + "Z"
        prev_hash = self.chain[-1]["entry_hash"] if self.chain else "GENESIS"

        file_hash = None
        if file_path and os.path.exists(file_path):
            sha256 = hashlib.sha256()
            with open(file_path, "rb") as fh:
                for block in iter(lambda: fh.read(8192), b""):
                    sha256.update(block)
            file_hash = sha256.hexdigest()

        entry_data = json.dumps({
            "finding_id": self.finding_id,
            "action": action,
            "performed_by": performed_by,
            "file_path": file_path,
            "file_hash": file_hash,
            "details": details,
            "timestamp": timestamp,
            "prev_hash": prev_hash,
        }, sort_keys=True)

        entry_hash = hmac.new(self.key, entry_data.encode(), hashlib.sha256).hexdigest()

        entry = {
            "timestamp": timestamp,
            "action": action,
            "performed_by": performed_by,
            "file_path": file_path,
            "file_hash": file_hash,
            "details": details,
            "prev_hash": prev_hash,
            "entry_hash": entry_hash,
        }
        self.chain.append(entry)
        return entry

    def verify_chain(self) -> Dict:
        """Verify the entire chain has not been tampered with."""
        issues: List[str] = []

        for i, entry in enumerate(self.chain):
            prev_hash = self.chain[i - 1]["entry_hash"] if i > 0 else "GENESIS"
            if entry.get("prev_hash") != prev_hash:
                issues.append(f"Chain broken at entry {i}: prev_hash mismatch")

            # Recompute entry hash
            entry_data = json.dumps({
                "finding_id": self.finding_id,
                "action": entry["action"],
                "performed_by": entry["performed_by"],
                "file_path": entry.get("file_path"),
                "file_hash": entry.get("file_hash"),
                "details": entry.get("details", ""),
                "timestamp": entry["timestamp"],
                "prev_hash": entry["prev_hash"],
            }, sort_keys=True)

            expected_hash = hmac.new(
                self.key, entry_data.encode(), hashlib.sha256
            ).hexdigest()

            if entry["entry_hash"] != expected_hash:
                issues.append(f"Entry {i} has been modified (hash mismatch)")

            # Verify file still matches recorded hash
            if entry.get("file_path") and entry.get("file_hash"):
                if os.path.exists(entry["file_path"]):
                    sha256 = hashlib.sha256()
                    with open(entry["file_path"], "rb") as fh:
                        for block in iter(lambda: fh.read(8192), b""):
                            sha256.update(block)
                    if sha256.hexdigest() != entry["file_hash"]:
                        issues.append(f"Entry {i}: file has been modified since collection")

        return {
            "valid": len(issues) == 0,
            "total_entries": len(self.chain),
            "issues": issues,
        }

    def export_chain(self) -> str:
        """Export the full chain as JSON for long-term storage."""
        return json.dumps({
            "finding_id": self.finding_id,
            "entries": self.chain,
            "export_timestamp": datetime.utcnow().isoformat() + "Z",
        }, indent=2)


# Example usage
chain = SecureEvidenceChain("F-001", secret_key="engagement-secret-key")
chain.add_entry(
    "evidence_collected",
    "pentester",
    file_path="./evidence/F-001-screenshot-001.png",
    details="SQL injection proof captured from login page",
)
chain.add_entry(
    "evidence_verified",
    "lead_reviewer",
    details="Reproduced independently, finding confirmed",
)
chain.add_entry(
    "report_included",
    "report_writer",
    details="Evidence included in final report section 3.1",
)

print(chain.export_chain())
print("\nVerification:", json.dumps(chain.verify_chain(), indent=2))
```

### 11. Finding Documentation Template

```markdown
## Finding [ID]: [Title]

**Severity**: [Critical/High/Medium/Low]
**CVSS**: [Score] ([Vector String])
**Status**: [Confirmed/Potential/False Positive]
**Host**: [IP/hostname]
**Port/URL**: [specific endpoint]

### Description
[2-3 sentences describing the vulnerability]

### Steps to Reproduce
1. [Step 1 with exact commands/URLs]
2. [Step 2]
3. [Step 3]

### Evidence
- Screenshot: [reference to file]
- Request: [HTTP request block]
- Response: [relevant response excerpt]

### Impact
[What an attacker could achieve]

### Remediation
[Specific fix recommendation with code examples if possible]
```

### 12. Severity Classification Reference

Use this table to consistently classify finding severity based on impact and exploitability:

| Severity | CVSS Range | Exploitability | Impact | Example |
|----------|-----------|----------------|--------|---------|
| Critical | 9.0-10.0 | Trivial, no auth required | Complete system compromise, data exfiltration | Unauthenticated RCE on public-facing server |
| High | 7.0-8.9 | Moderate effort or limited access needed | Significant data exposure, privilege escalation | Authenticated SQL injection dumping user table |
| Medium | 4.0-6.9 | Requires specific conditions or user interaction | Limited data exposure, session hijacking | Reflected XSS requiring user to click crafted link |
| Low | 0.1-3.9 | Difficult to exploit, minimal impact | Information leakage, minor policy violation | Server version disclosure in HTTP headers |
| Informational | 0.0 | Not a vulnerability | Best practice recommendation | Missing HSTS header on internal-only service |

### 13. Remediation Documentation Standards

Each finding should include actionable remediation guidance. The level of detail determines whether the development team can fix it without follow-up questions:

```markdown
### Remediation

**Immediate mitigation**: [What to do right now to reduce risk]

**Long-term fix**: [The proper architectural or code-level fix]

**Code example (vulnerable)**:
```python
# BAD: String concatenation in SQL query
query = f"SELECT * FROM users WHERE id = {user_input}"
cursor.execute(query)
```

**Code example (fixed)**:
```python
# GOOD: Parameterized query
query = "SELECT * FROM users WHERE id = %s"
cursor.execute(query, (user_input,))
```

**Verification steps**: [How to verify the fix is effective]
1. Re-run the original reproduction steps
2. Confirm the application no longer processes the malicious input
3. Verify normal functionality is not affected
```

### 14. Report Writing Tips for Multiple Audiences

A single finding report serves three audiences. Structure the documentation to serve all of them:

| Section | Developer Audience | Management Audience | Compliance Audience |
|---------|-------------------|--------------------|--------------------|
| Description | Technical detail on root cause | Business impact summary | Risk classification mapping |
| Steps to Reproduce | Exact commands and parameters | Skip or summarize | Sufficient for independent verification |
| Evidence | Full raw output, code snippets | Annotated screenshots only | Hash-verified artifacts |
| Impact | Specific data/systems at risk | Financial/reputation estimate | Regulatory exposure (GDPR, PCI-DSS) |
| Remediation | Code-level fix with examples | Timeline and resource estimate | Compensating control documentation |

### 15. Evidence Sanitization Checklist

Before including evidence in any report, ensure the following sanitization steps are completed:

- [ ] Remove session tokens, cookies, and authentication credentials from HTTP logs
- [ ] Redact personally identifiable information (PII) from screenshots and response bodies
- [ ] Replace internal IP addresses with placeholders unless essential to the finding
- [ ] Remove paths that reveal internal infrastructure details not relevant to the finding
- [ ] Ensure no evidence from out-of-scope systems is included
- [ ] Verify that all timestamps are in UTC and consistently formatted
- [ ] Confirm all file hashes match the chain of custody records

```bash
# Automated evidence sanitization
python3 -c "
import re

def sanitize_http_log(content):
    # Redact cookies and auth headers
    content = re.sub(
        r'(Cookie:|Authorization:|Set-Cookie:)\s*\S+',
        r'\1 [REDACTED]',
        content
    )
    # Redact internal IPs (keep target IP)
    content = re.sub(
        r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
        r'[\1]',  # Bracket all IPs for manual review
        content
    )
    # Redact email addresses
    content = re.sub(
        r'[\w.-]+@[\w.-]+\.\w+',
        '[EMAIL REDACTED]',
        content
    )
    # Redact potential API keys (long hex/base64 strings after key=)
    content = re.sub(
        r'(api[_-]?key|token|secret)=\S+',
        r'\1=[REDACTED]',
        content,
        flags=re.IGNORECASE
    )
    return content

# Example usage
sample = '''GET /api/data?api_key=sk-abc123def456 HTTP/1.1
Cookie: session=eyJhbGciOiJIUzI1NiJ9.abc.123
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9

Response: user email is john.doe@company.com from 10.0.1.50'''

print(sanitize_http_log(sample))
"
```

## Hands-on Exercises

### Exercise 1: Document a SQL Injection Finding

Using the template above, document a SQL injection finding with complete evidence including screenshots, HTTP requests, and remediation code.

**Steps:**

1. Use the EvidenceCollector class to create a new engagement directory.
2. Capture the HTTP request that triggers the SQL injection using the `http-evidence.sh` script.
3. Record a screenshot showing the vulnerable response (with annotations).
4. Record the sqlmap tool output confirming the vulnerability.
5. Write the finding documentation using the template from Section 11.
6. Include both the vulnerable and fixed code examples in the remediation section.
7. Add the finding to the chain of custody using the SecureEvidenceChain class.
8. Verify the chain integrity with `verify_chain()`.

**Expected outcome**: A complete finding package including manifest.json, screenshot, HTTP logs, tool output, and documented finding ready for report inclusion.

### Exercise 2: Build an Evidence Manifest

Create an automated evidence manifest that tracks all collected artifacts for an engagement.

**Steps:**

1. Initialize an EvidenceCollector for a new engagement.
2. Simulate collecting evidence for 5 findings across different types (screenshot, HTTP, tool output).
3. Generate the findings summary report.
4. Verify all file hashes match the manifest entries.
5. Export the manifest as a standalone JSON file for the report appendix.

### Exercise 3: Chain of Custody Verification

Using the SecureEvidenceChain class, build a complete chain for 3 findings with at least 5 chain entries each. Then simulate a tampering attempt by modifying one file and verify that the chain detects the modification.

**Steps:**

1. Create a SecureEvidenceChain with a known key.
2. Add entries for evidence collection, verification, and reporting.
3. Export the chain and save it.
4. Modify one evidence file on disk.
5. Run `verify_chain()` and confirm it detects the tampered file.
6. Document the verification result as evidence of integrity controls.

### Exercise 4: Evidence Sanitization Practice

Take a raw HTTP log file and apply the sanitization function from Section 15. Manually review the output to identify any remaining sensitive information that the automated tool missed.

## References

- OWASP Testing Guide — https://owasp.org/www-project-web-security-testing-guide/
- PTES Reporting Standards — http://www.pentest-standard.org/
- NIST SP 800-115 — Technical Guide to Information Security Testing
- ISO 27037 — Digital Evidence Guidelines
- CVSS Calculator — https://www.first.org/cvss/calculator/3.1
- HAR 1.2 Specification — http://www.softwareishard.com/blog/har-12-spec/
