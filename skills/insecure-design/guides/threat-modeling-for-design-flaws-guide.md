# Threat Modeling for Design Flaws Guide

## Overview

Threat modeling identifies architectural weaknesses before they become exploitable vulnerabilities. This guide applies STRIDE and DREAD frameworks to detect insecure design patterns at the system level.

---

## STRIDE Framework

| Threat | Description | Design Impact |
|--------|-------------|---------------|
| **S**poofing | Impersonating another entity | Authentication design |
| **T**ampering | Modifying data in transit/at rest | Integrity controls |
| **R**epudiation | Denying actions performed | Audit logging design |
| **I**nformation Disclosure | Exposing data to unauthorized parties | Data flow boundaries |
| **D**enial of Service | Making system unavailable | Resource management |
| **E**levation of Privilege | Gaining unauthorized access | Authorization architecture |

---

## Data Flow Diagram (DFD) Analysis

### Step 1: Identify Components

```
[User Browser] → [Load Balancer] → [Web App] → [API Gateway] → [Microservice]
                                        ↓                            ↓
                                   [Session Store]              [Database]
                                        ↓
                                   [Cache Layer]
```

### Step 2: Mark Trust Boundaries

```
┌─────────────────────────────────────────────────────────┐
│ EXTERNAL (Untrusted)                                     │
│   [User Browser]                                         │
└─────────────────────────┬───────────────────────────────┘
                          │ Trust Boundary 1 (Internet → DMZ)
┌─────────────────────────┴───────────────────────────────┐
│ DMZ                                                      │
│   [Load Balancer] → [Web App]                           │
└─────────────────────────┬───────────────────────────────┘
                          │ Trust Boundary 2 (DMZ → Internal)
┌─────────────────────────┴───────────────────────────────┐
│ INTERNAL (Trusted)                                       │
│   [API Gateway] → [Microservice] → [Database]           │
└─────────────────────────────────────────────────────────┘
```

### Step 3: Apply STRIDE to Each Boundary Crossing

```yaml
Boundary: Internet → DMZ
  Spoofing:
    - Can attacker impersonate legitimate user?
    - Is session token predictable?
  Tampering:
    - Can request body be modified in transit?
    - Is TLS enforced end-to-end?
  Information Disclosure:
    - Are error messages leaking internal details?
    - Is sensitive data in URL parameters?

Boundary: DMZ → Internal
  Spoofing:
    - Can DMZ component impersonate another service?
    - Is service-to-service auth enforced?
  Elevation of Privilege:
    - Can web app directly access database?
    - Are API permissions checked at gateway?
```

---

## DREAD Risk Scoring

| Factor | Score 1-10 | Question |
|--------|-----------|----------|
| **D**amage | How bad if exploited? | Data loss, financial, reputation |
| **R**eproducibility | How easy to reproduce? | Always vs race condition |
| **E**xploitability | How easy to exploit? | Script kiddie vs nation-state |
| **A**ffected Users | How many impacted? | Single user vs all users |
| **D**iscoverability | How easy to find? | Obvious vs requires insider knowledge |

### Scoring Example: Insecure Direct Object Reference

```yaml
Threat: User can access other users' data by changing ID parameter
  Damage: 8 (full account data exposure)
  Reproducibility: 10 (trivial, change URL parameter)
  Exploitability: 10 (no special tools needed)
  Affected Users: 10 (all users potentially affected)
  Discoverability: 8 (visible in URL, easy to guess)
  DREAD Score: (8+10+10+10+8)/5 = 9.2 (CRITICAL)
```

---

## Common Insecure Design Patterns

### Pattern 1: Client-Side Trust

```yaml
Vulnerability: Business logic enforced only in frontend
Example: Price validation only in JavaScript
Attack: Modify request to bypass client-side checks

Detection Questions:
  - What happens if the client sends unexpected values?
  - Is every business rule re-validated server-side?
  - Can the API be called directly without the UI?
```

### Pattern 2: Implicit Trust Between Services

```yaml
Vulnerability: Internal services trust each other without authentication
Example: Microservice A calls B without credentials
Attack: Compromised service impersonates another

Detection Questions:
  - Is there mutual TLS between services?
  - Are service identities verified on each call?
  - Can a compromised service access all other services?
```

### Pattern 3: Race Condition by Design

```yaml
Vulnerability: TOCTOU (Time of Check to Time of Use) gap
Example: Check balance → deduct → transfer (not atomic)
Attack: Concurrent requests exploit the gap

Detection Questions:
  - Are multi-step operations atomic?
  - What happens with concurrent identical requests?
  - Are there distributed locks on critical operations?
```

### Pattern 4: Insufficient Separation of Duties

```yaml
Vulnerability: Single role can perform conflicting actions
Example: Same user can create and approve transactions
Attack: Insider creates fraudulent transactions

Detection Questions:
  - Can one person complete a sensitive workflow alone?
  - Are there approval gates for high-risk actions?
  - Is there audit trail for who did what?
```

---

## Threat Modeling Workshop Template

### Pre-Workshop

```markdown
1. Identify system scope and boundaries
2. Gather architecture diagrams
3. List all data flows and storage
4. Identify existing security controls
5. Invite: dev lead, security, architect, product owner
```

### During Workshop

```markdown
1. Walk through DFD (15 min)
2. Identify trust boundaries (10 min)
3. Apply STRIDE to each boundary (30 min)
4. Score threats with DREAD (15 min)
5. Prioritize and assign mitigations (20 min)
```

### Post-Workshop Deliverable

```markdown
| ID | Threat | STRIDE | DREAD | Mitigation | Owner | Status |
|----|--------|--------|-------|------------|-------|--------|
| T1 | Session fixation | Spoofing | 7.2 | Regenerate session on auth | Dev | Open |
| T2 | SQL injection | Tampering | 8.4 | Parameterized queries | Dev | Done |
| T3 | Missing audit log | Repudiation | 6.0 | Add audit middleware | Ops | Open |
```

---

## Automated Threat Modeling Tools

```bash
# Microsoft Threat Modeling Tool (Windows)
# Generates threats from DFD diagrams

# OWASP Threat Dragon
docker run -p 3000:3000 owasp/threat-dragon

# pytm (Python Threat Modeling)
pip install pytm
python threat_model.py --dfd --report threat_report.html
```

---

## Testing Checklist

- [ ] DFD created with all trust boundaries marked
- [ ] STRIDE applied to every boundary crossing
- [ ] DREAD scores calculated for top threats
- [ ] Client-side trust assumptions identified
- [ ] Service-to-service authentication verified
- [ ] Race conditions in critical paths analyzed
- [ ] Separation of duties enforced for sensitive operations
- [ ] Threat model reviewed and updated quarterly
