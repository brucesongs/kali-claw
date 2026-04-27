# Skill: Insecure Design

> **Supplementary Files**:
> - `payloads.md` — Attack payloads for business logic testing, race condition exploitation, rate limiting bypass, IDOR, mass assignment, and threat modeling
> - `test-cases.md` — Structured test cases with severity levels covering business logic, race conditions, asset management, and design flaws

## Description

Insecure Design (OWASP A06:2025) focuses on security flaws in system architecture and design phases, rather than code implementation-level bugs. Unlike specific technical vulnerabilities such as broken access control or injection, the root cause of insecure design is the failure to perform threat modeling, define abuse cases, or delineate trust boundaries during design. Such flaws cannot be fixed with patches — they require redesign. This skill covers business logic vulnerability exploitation, threat modeling, trust boundary analysis, and security architecture review.

**Core Concepts**:
- **Design Flaw vs Implementation Bug**: A design flaw is "doing the wrong thing," an implementation bug is "doing the thing wrong" — the former requires architectural changes
- **Threat Modeling**: Examining the system from an attacker's perspective, identifying the six STRIDE threat categories
- **Abuse Case**: In addition to normal use cases, abuse cases must be defined — "How would an attacker use this feature?"
- **Trust Boundary**: Boundaries between different trust levels (user input vs internal data, authenticated vs unauthenticated), each requiring validation and authorization

## Use Cases

1. **Business Logic Security Testing** - Review business processes in e-commerce, finance, SaaS, and other systems to discover workflow bypasses, state machine vulnerabilities, and race conditions
2. **Threat Modeling** - Perform structured threat analysis for new or existing systems (STRIDE/PASTA/LINDDUN)
3. **Security Architecture Review** - Evaluate trust boundary delineation, missing security controls, and single points of failure in system architecture
4. **CTF Competitions** - Solving challenges involving business logic vulnerabilities, race conditions, and design flaws
5. **API Security Assessment** - Detect design-level issues such as missing rate limiting, input validation, and access controls

## Core Tools

| Tool | Purpose | Description |
|------|---------|-------------|
| **OWASP Threat Dragon** | Threat modeling diagrams | Open-source cross-platform, supports STRIDE-categorized visual threat models |
| **STRIDE Methodology** | Structured threat classification | Microsoft's 6-category threat framework (Spoofing/Tampering/Repudiation/Information Disclosure/Denial of Service/Elevation of Privilege) |
| **Burp Suite** | Business logic testing | Repeater for manual debugging, Intruder for concurrency testing, Turbo Intruder for precise race conditions |
| **draw.io / diagrams.net** | Architecture diagram drawing | Draw data flow diagrams (DFD), trust boundaries, and component interaction diagrams |
| **Python threading / asyncio** | Race condition exploitation | Write concurrent scripts to test race condition vulnerabilities |

## Methodology

### Attack Chain

```
Trust Boundary Analysis -> Abuse Case Development -> Business Logic Exploitation -> Design Pattern Attack
```

**1. Trust Boundary Analysis**
- Identify all trust boundaries: user input boundary, authentication boundary, authorization boundary, network boundary
- Check each boundary: Is there validation? Is there authorization? Is there logging?
- Look for missing trust boundaries — "Is user input being directly trusted?"

**2. Abuse Case Development**
- Generate corresponding abuse cases for each use case
- Thinking framework: How to bypass? How to abuse? How to break consistency?
- Focus on unconventional inputs: negative amounts, future dates, illegal states, extremely large values

**3. Business Logic Exploitation**
- Race conditions: Concurrent operations bypass check-use logic (TOCTOU)
- Workflow bypass: Skip required steps and directly call subsequent interfaces
- State machine attacks: Illegal state transitions, repeated state transitions, rollback attacks
- Value tampering: Negative amounts, overflow, precision loss

**4. Design Pattern Attack**
- Singleton abuse: Shared state causing concurrency issues
- Observer pattern: Event ordering dependencies causing logic vulnerabilities
- Factory pattern: Missing permission checks during object creation
- Identify design patterns used by the system and find their security weaknesses

### Defense Perspective

| Defense Measure | Description | Priority |
|-----------------|-------------|----------|
| Secure Development Lifecycle | Introduce threat modeling during requirements, define security requirements during design | CRITICAL |
| Threat Modeling | Use STRIDE and similar methods to systematically identify threats, update each iteration cycle | CRITICAL |
| Abuse Case Testing | Include abuse case test cases in security testing, verify system defense against unintended use | HIGH |
| Secure Design Patterns | Use proven secure design patterns (e.g., state machine validation, idempotent operations) | HIGH |
| Architecture Review | Regularly conduct security architecture reviews, checking trust boundaries, security controls, and failure modes | HIGH |
| Rate Limiting & Input Validation | Enforce rate limiting and input validation at trust boundaries | HIGH |

## Practical Steps

### Step 1: STRIDE Threat Modeling

```
1. Draw system architecture diagram / Data Flow Diagram (DFD)
2. Mark all trust boundaries (external->internal, low-privilege->high-privilege)
3. Apply STRIDE to each component and boundary:

   S - Spoofing:    Can users be impersonated? Is the authentication mechanism reliable?
   T - Tampering:   Can data be tampered with during transmission/storage? Integrity checks?
   R - Repudiation: Can operations be repudiated? Are audit logs complete?
   I - Info Disclosure: Is sensitive data exposed? Is encryption adequate?
   D - Denial of Service: Is there a risk of resource exhaustion? Rate limiting?
   E - Elevation of Privilege: Can privileges be escalated? Are permission checks consistent?

4. Assess risk level for each threat (impact x likelihood)
5. Design corresponding security controls
```

### Step 2: Trust Boundary Mapping

```
1. Draw the system's trust boundary map:

   [Untrusted Zone]          [Trust Boundary]         [Trusted Zone]
   +--------------+         +--------------+         +-------------+
   |  User Input  | ------> |  Validation  | ------> |  Internal   |
   |  HTTP Req    |         |  Auth Check  |         |  Processing |
   |  API Calls   |         |  Rate Limit  |         |  Database   |
   +--------------+         +--------------+         +-------------+

2. Check each boundary:
   - Does validation exist? Is it complete?
   - Can it be bypassed?
   - Does it fail safely (fail-safe)?

3. Common trust boundary deficiencies:
   - Internal APIs without authentication (assume internal = trusted)
   - No authentication between microservice calls
   - Admin interfaces protected only by network isolation
   - WebSocket connections missing origin checks
```

### Step 3: Design Pattern Anti-Pattern Identification

```
Common security anti-patterns:

1. Client-Side Security Control
   - Frontend hides buttons but doesn't check backend permissions
   - JavaScript validation replaces server-side validation
   - Hidden fields store price/discount information

2. Implicit Trust
   - Internal APIs require no authentication
   - Admin interfaces protected only by unreachable ports
   - Unconditional trust between microservice calls

3. Missing State Machine
   - Order states have no valid transition definitions
   - User account states have no constraint checks
   - Workflow steps have no precondition validation

4. No Fail-Safe Default
   - Returns success instead of failure on exceptions
   - Allows read-only access when permission checks fail
   - Defaults to allowing on timeout
```

> **Detailed payloads in `payloads.md`, complete test checklist in `test-cases.md`.**

## Hacker Laws

1. **First Principles** - The essence of insecure design is "the attacker was not considered during design." Return to the fundamental question: Does the system validate at every trust boundary? Does every operation have corresponding abuse case protection? Understanding this first principle enables finding design flaws in any system.

2. **Divergent Thinking** - Discovering business logic vulnerabilities requires stepping outside the "normal user" mindset. What if the amount is negative? What if two requests arrive simultaneously? What if the third interface is called directly, skipping the first two steps? Attackers don't follow preset usage paths; divergent thinking is the core capability for discovering design flaws.

3. **Defense in Depth** - A single security control is never enough. Rate limiting + input validation + state machine validation + audit logging = defense in depth. Each layer is a backup for the next; the failure of any one layer does not cause total system collapse. Security design must assume every layer can fail.

## Learning Resources

  **This skill's supplementary files**: payloads.md, test-cases.md
  **Related skills**: skills/web-access-control/SKILL.md, skills/web-auth-bypass/SKILL.md
  **External resources**:
  - [OWASP Top 10 - A04:2021 Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)
  - [OWASP Threat Modeling](https://owasp.org/www-community/Threat_Modeling)
  - [OWASP Threat Dragon](https://threatdragon.github.io/)
  - [Microsoft STRIDE Threat Model](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)
  - [PortSwigger - Business Logic Vulnerabilities](https://portswigger.net/web-security/logic-flaws)
  - [HackTricks - Business Logic Vulnerabilities](https://book.hacktricks.xyz/pentesting-web/business-logic-vulnerabilities)
