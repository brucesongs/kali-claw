# Abuse Case Development Guide

> Methodology for developing abuse cases, attack trees, and misuse scenarios during security design reviews. Covers STRIDE per element analysis, attack tree construction, and practical templates for documenting abuse cases.

---

## Introduction

Abuse cases describe how an attacker could misuse a system. Unlike functional test cases that verify intended behavior, abuse cases explore unintended paths — privilege escalation, data exfiltration, denial of service, and trust boundary violations. Developing abuse cases early in the design phase catches flaws that would cost orders of magnitude more to fix after deployment. This guide provides a structured methodology for creating abuse cases using STRIDE classification, attack trees, and misuse case diagrams.

---

## Hands-on Exercise

### 1. STRIDE Per Element Analysis

Start by identifying every trust boundary component and applying the STRIDE threat model to each one.

| Element Type | S | T | R | I | D | E |
|---|---|---|---|---|---|---|
| External Entity | Spoofing | Tampering | Repudiation | Info Disclosure | DoS | Elevation of Privilege |
| Data Store | | Tampering | Repudiation | Info Disclosure | DoS | |
| Data Flow | | Tampering | | Info Disclosure | DoS | |
| Process | Spoofing | Tampering | Repudiation | Info Disclosure | DoS | Elevation of Privilege |

Example — analyzing an API endpoint that accepts file uploads:

```
Component: File Upload API (Process)
- Spoofing: Can an unauthenticated user submit files?
- Tampering: Can uploaded content be modified in transit?
- Repudiation: Are uploads logged with user identity?
- Information Disclosure: Can metadata (EXIF) leak user data?
- Denial of Service: Can oversized files exhaust storage?
- Elevation of Privilege: Can file content execute as code?

Component: Uploaded File Store (Data Store)
- Tampering: Can files be overwritten by other users?
- Information Disclosure: Are files accessible without authorization?
- Denial of Service: Is there a storage quota per user?

Component: Upload Request (Data Flow)
- Tampering: Can the request be modified mid-transfer?
- Information Disclosure: Is the upload channel encrypted?
```

### 2. Attack Tree Development

Convert STRIDE findings into attack trees that model attacker goals and paths.

```
GOAL: Access another user's uploaded files

OR
├── [1] Exploit IDOR in file download API
│   ├── [1.1] Enumerate file IDs sequentially
│   │   └── AND
│   │       ├── Guess valid file ID range (p=0.8)
│   │       └── Download without auth check (p=0.6)
│   └── [1.2] Predict file IDs from timestamp
│       └── AND
│           ├── Know upload time (p=0.5)
│           └── Derive ID from time-based UUID (p=0.4)
├── [2] Exploit path traversal in filename
│   └── AND
│       ├── Upload file with path traversal name (p=0.9)
│       └── Server does not sanitize filenames (p=0.3)
└── [3] Direct storage access
    └── AND
        ├── Storage bucket is public (p=0.2)
        └── Know bucket naming convention (p=0.4)
```

Notation: `AND` means all children must succeed. `OR` means any child suffices. `(p=X)` is estimated probability.

### 3. Abuse Case Template

Use this template for each documented abuse case:

```markdown
## Abuse Case: AC-[NNN]

**Name**: [Descriptive name]
**STRIDE Category**: [Spoofing/Tampering/Repudiation/Info Disclosure/DoS/EoP]
**Affected Component**: [Component name from architecture diagram]
**Trust Boundary Crossed**: [Which boundary is violated]
**Attacker Profile**: [Unauthenticated user / Authenticated user / Admin / Insider]
**Preconditions**: [What must be true for the attack to work]
**Attack Steps**:
  1. [Step 1]
  2. [Step 2]
  3. [Step 3]
**Expected Impact**: [Confidentiality/Integrity/Availability impact]
**Likelihood**: [High/Medium/Low with justification]
**Mitigation**: [Design change that prevents this abuse]
**Verification**: [How to test that the mitigation works]
```

### 4. Example Abuse Case

```markdown
## Abuse Case: AC-001

**Name**: Sequential File ID Enumeration (IDOR)
**STRIDE Category**: Information Disclosure
**Affected Component**: File Download API (GET /api/files/{id})
**Trust Boundary Crossed**: User-to-File-Store boundary
**Attacker Profile**: Authenticated user (any role)
**Preconditions**: User has a valid session token; file IDs are sequential integers
**Attack Steps**:
  1. Upload a file and note the assigned ID (e.g., 1042)
  2. Request GET /api/files/1041 with the same token
  3. Observe that another user's file is returned without ownership check
  4. Script enumeration of IDs 1-1000 to harvest all files
**Expected Impact**: Complete exposure of all user-uploaded files (Confidentiality: High)
**Likelihood**: High — requires only a valid account and sequential ID guessing
**Mitigation**: Use UUIDs for file identifiers; enforce ownership checks in the download handler; implement rate limiting
**Verification**: Send download request for a file owned by a different user; confirm 403 response
```

### 5. Misuse Case Diagram (Text Format)

```
+-------------------+       +-------------------+
|     ATTACKER      |       |     SYSTEM        |
+-------------------+       +-------------------+
        |                           |
        |--- Upload Malicious --->  |
        |    File                   |
        |                           |--- Sanitize? ---> [GUARD]
        |                           |                     |
        |                           |            No sanitization
        |                           |                     |
        |                           |<-- Stored as-is ----+
        |                           |
        |--- Trigger Execution ---> |
        |                           |--- Execute ---> [IMPACT: RCE]
```

---

## References

- OWASP Abuse Case Development: [https://owasp.org/www-community/Application_Threat_Modeling](https://owasp.org/www-community/Application_Threat_Modeling)
- STRIDE Threat Modeling: [https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)
- Attack Trees by Bruce Schneier: [https://schneier.com/academic/archives/1999/12/attack_trees.html](https://schneier.com/academic/archives/1999/12/attack_trees.html)
- NIST SP 800-154: Guide to Data-Centric System Threat Modeling
- SANS: Threat Modeling and Abuse Case Development
