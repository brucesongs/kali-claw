# Knowledge Operations Test Cases

## Test Case Summary

| ID | Name | Scenario | Status |
|----|------|----------|--------|
| TC-KO-001 | Cross-Session Codebase Context | Onboarding multi-session with knowledge persistence | Active |
| TC-KO-002 | Exploit Finding Evolution | Track confidence from hypothesis → verified | Active |
| TC-KO-003 | Pattern Recognition Across Targets | Detect recurring vulnerability pattern | Active |
| TC-KO-004 | Intelligence Handoff | Transfer complete context to new session | Active |
| TC-KO-005 | Knowledge Expiration Management | Archive and remove stale intelligence | Active |

Total: 5 test cases

---

## TC-KO-001: Cross-Session Codebase Context

**Objective**: Validate knowledge persistence across multiple codebase-onboarding sessions

**Scenario**:
Session 1: Onboard target-app-api (auth service, Targeted mode)
Session 2: Onboard target-app-frontend (React SPA, Exploratory mode)
Session 3: Full security surface synthesis using knowledge from Sessions 1+2

**Phase 1 — Session 1: API Onboarding**

```
GIVEN: target-app-api (Go Gin + JWT)
WHEN: codebase-onboarding completes Targeted mode
THEN: create knowledge units:
  - KU-001: Entity (target-app-api, Go service, Gin)
  - KU-002: Finding (JWT middleware location)
  - KU-003: Finding (HS256 with env-based secret)
  - KU-004: Hypothesis (Secret may be weak if env not set)
Store in: memory/2026-05-11-target-app-api-onboarding.md
```

Expected output:
```json
{
  "knowledge_units": 4,
  "entity_count": 1,
  "finding_count": 2,
  "hypothesis_count": 1,
  "avg_confidence": 72
}
```

**Phase 2 — Session 2: Frontend Onboarding**

```
GIVEN: target-app-frontend (React + localStorage for JWT)
WHEN: codebase-onboarding completes Exploratory mode
THEN: create knowledge units:
  - KU-005: Entity (target-app-frontend, React SPA)
  - KU-006: Finding (JWT stored in localStorage, not httpOnly cookie)
  - KU-007: Relationship (Frontend calls API at api.target.com, links KU-001)
Store in: memory/2026-05-11-target-app-frontend-onboarding.md
Link KU-007 to KU-001 (cross-session link)
```

**Phase 3 — Session 3: Synthesis**

```
GIVEN: Sessions 1+2 complete
WHEN: starting security surface synthesis
THEN: knowledge-ops loads:
  - All KU-001 to KU-007
  - Identifies linked units (KU-007 → KU-001)
  - Surfaces hypothesis KU-004 for validation
  
WHEN: hypothesis KU-004 is tested (check .env for JWT_SECRET)
THEN: update confidence:
  - If weak: KU-004 confidence 45 → 85, type: hypothesis → finding
  - If strong: KU-004 confidence 45 → 0, type: archived
```

**Pass Criteria**:
- [ ] All 3 sessions create knowledge units
- [ ] Cross-session links (KU-007 → KU-001) preserved
- [ ] Hypothesis KU-004 was surfaced and validated
- [ ] Confidence updated based on test result
- [ ] Final synthesis report includes all findings from both sessions

---

## TC-KO-002: Exploit Finding Evolution

**Objective**: Track a security finding from hypothesis → confirmed → verified

**Scenario**: SQL injection discovery and exploitation workflow

**Stage 1 — Initial Discovery (Confidence: 40)**

```
GIVEN: codebase-onboarding identifies string concatenation in SQL query
WHEN: creating initial knowledge unit
THEN: create KU-008:
  type: hypothesis
  confidence: 40
  tags: [sql-injection, search, unconfirmed]
  content: "search.php:34 may be vulnerable to SQL injection via GET q param"
  source: codebase-onboarding:static-analysis
```

**Stage 2 — Static Confirmation (Confidence: 40 → 70)**

```
GIVEN: KU-008 exists
WHEN: manual code review confirms no parameterization
THEN: update KU-008:
  type: hypothesis → finding
  confidence: 40 → 70
  Add history: | 2026-05-11 | 70 | Manual review confirms string concat, no escaping |
```

**Stage 3 — Active Testing (Confidence: 70 → 88)**

```
GIVEN: KU-008 at confidence 70
WHEN: testing with payload: ?q=' OR '1'='1
THEN: If successful:
  - Update confidence: 70 → 88
  - Add detail: "Confirmed via error message: MySQL syntax error"
  - Add history: | 2026-05-11 | 88 | Active test confirms SQLi, error-based |
```

**Stage 4 — Exploitation (Confidence: 88 → 98)**

```
GIVEN: KU-008 at confidence 88
WHEN: sqlmap successfully extracts database names
THEN: Update KU-008:
  confidence: 88 → 98
  Add detail: "Exploited via sqlmap, dumped users table (12 records)"
  Add history: | 2026-05-11 | 98 | Full exploitation, data exfiltration confirmed |
  Create linked KU-009:
    type: intelligence
    content: "target-org database contains users table with plaintext passwords"
```

**Pass Criteria**:
- [ ] Confidence evolves 40 → 70 → 88 → 98
- [ ] Type changes: hypothesis → finding
- [ ] Confidence history table has 4+ entries
- [ ] Each update includes reason for score change
- [ ] Final exploitation spawns new intelligence unit (KU-009)

---

## TC-KO-003: Pattern Recognition Across Targets

**Objective**: Detect and catalog recurring patterns across multiple targets

**Scenario**: Recognize JWT HS256 pattern across 3 targets

**Target 1 — Initial Observation**

```
GIVEN: target-a uses HS256 JWT with default fallback
WHEN: creating knowledge unit
THEN: create KU-010:
  type: finding
  target: target-a
  tags: [jwt, hs256, weak-secret]
  confidence: 82
  content: "JWT signed with HS256, secret falls back to 'secret' if env not set"
```

**Target 2 — Pattern Detection Trigger**

```
GIVEN: KU-010 exists from target-a
WHEN: target-b also uses HS256 with fallback
THEN: create KU-011 (finding for target-b)
AND: create KU-012 (pattern):
  type: pattern
  target: [multi-target]
  tags: [jwt, hs256, pattern]
  confidence: 75
  linked: [KU-010, KU-011]
  content: "Express.js codebases often use HS256 with weak fallback secret"
```

**Target 3 — Pattern Confirmation**

```
GIVEN: Pattern KU-012 exists
WHEN: target-c also matches this pattern
THEN: Update KU-012:
  confidence: 75 → 85
  linked: [KU-010, KU-011, KU-013]  # Add KU-013 for target-c
  content: "Confirmed across 3 targets: Express.js + HS256 weak secret pattern"
```

**Query Test**:
```bash
# Can we retrieve all targets with this pattern?
grep -rn "linked:" memory/ | grep "KU-012" | awk -F: '{print $1}'
# Should return: target-a, target-b, target-c knowledge files
```

**Pass Criteria**:
- [ ] Pattern unit created after second observation
- [ ] Pattern unit links all related findings
- [ ] Confidence increases as pattern recurs
- [ ] Query successfully retrieves all affected targets

---

## TC-KO-004: Intelligence Handoff

**Objective**: Simulate session handoff with complete context transfer

**Scenario**: Session A performs recon, Session B performs exploitation using Session A's context

**Session A — Recon & Onboarding**

```
GIVEN: Starting with no prior knowledge
WHEN: Session A completes:
  - OSINT (domain, IP, admin contact found)
  - Codebase onboarding (auth vuln identified)
THEN: create knowledge units:
  - KU-014: Entity (target.com, 203.0.113.42)
  - KU-015: Entity (John Smith, admin@target.com)
  - KU-016: Finding (SQL injection in search.php)
  - KU-017: Hypothesis (Admin credentials may be weak)

Session A ends with summary:
{
  "knowledge_units_created": 4,
  "next_session_priority": "Test KU-016 SQL injection + credential bruteforce"
}
```

**Session B — Context Load & Exploitation**

```
GIVEN: Session A knowledge units exist
WHEN: Session B starts
THEN: knowledge-ops loads:
  - All entities (KU-014, KU-015)
  - All findings (KU-016)
  - Open hypotheses (KU-017)
  
Session B proceeds with:
  1. Test SQL injection (KU-016)
  2. If successful: update KU-016 confidence, extract credentials
  3. Test hypothesis KU-017 (bruteforce admin@target.com)
  4. Create new KU-018: Result of credential test
```

**Handoff Quality Metrics**:
```
Session B should achieve:
- 0 duplicated reconnaissance (all entities already known)
- 100% context from Session A available
- 50%+ time savings vs. starting from scratch
```

**Pass Criteria**:
- [ ] Session B loads all Session A knowledge units at startup
- [ ] Session B does not re-run discovery already done in Session A
- [ ] Session B updates confidence on Session A findings
- [ ] Final report synthesizes work from both sessions

---

## TC-KO-005: Knowledge Expiration Management

**Objective**: Identify and archive stale or expired intelligence

**Scenario**: Manage time-sensitive intelligence like exposed credentials

**Phase 1 — Create Time-Sensitive Intelligence**

```
GIVEN: Exposed API key found on GitHub
WHEN: creating knowledge unit
THEN: create KU-019:
  type: finding
  confidence: 95
  tags: [credential-exposure, github, api-key]
  content: "AWS API key exposed in commit abc123 on github.com/target/repo"
  expires: 2026-06-11  # 30 days from creation (time to rotate keys)
```

**Phase 2 — Expiration Detection (30 days later)**

```
GIVEN: KU-019 with expires: 2026-06-11
WHEN: Current date = 2026-06-12
THEN: knowledge-ops detects expired:
  - Run expiration check script
  - KU-019 appears in expired list
```

**Phase 3 — Validation**

```
GIVEN: KU-019 is expired
WHEN: Checking if still valid
THEN: Test if API key still works
  IF still valid:
    - Update expires: 2026-07-11 (extend 30 days)
    - Add note: "Validated 2026-06-12, key still active (not rotated)"
  IF invalid (rotated):
    - type: finding → archived
    - confidence: 95 → 0
    - Add note: "Archived 2026-06-12, API key no longer valid"
```

**Expiration Query**:
```bash
# Find all expired intelligence
TODAY=$(date +%Y-%m-%d)
grep -rn "expires:" memory/ | grep -v "null" | while read line; do
  expires=$(echo $line | grep -oP '\d{4}-\d{2}-\d{2}')
  if [[ "$expires" < "$TODAY" ]]; then
    echo "$line"
  fi
done
```

**Pass Criteria**:
- [ ] Expired knowledge units detected automatically
- [ ] Validation process confirms whether still relevant
- [ ] Stale intelligence archived with reason
- [ ] Still-valid intelligence has expiration extended
- [ ] Query returns 0 expired units after cleanup
