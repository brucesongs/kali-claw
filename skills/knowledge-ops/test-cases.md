# Knowledge Operations Test Cases

## Test Case Summary

| ID | Name | Scenario | Status |
|----|------|----------|--------|
| TC-KO-001 | Cross-Session Codebase Context | Onboarding multi-session with knowledge persistence | Active |
| TC-KO-002 | Exploit Finding Evolution | Track confidence from hypothesis → verified | Active |
| TC-KO-003 | Pattern Recognition Across Targets | Detect recurring vulnerability pattern | Active |
| TC-KO-004 | Intelligence Handoff | Transfer complete context to new session | Active |
| TC-KO-005 | Knowledge Expiration Management | Archive and remove stale intelligence | Active |
| TC-KO-006 | Knowledge Conflict Resolution | Handle contradictory findings across sessions | Active |
| TC-KO-007 | Automated Knowledge Indexing | Bulk entity extraction and tagging pipeline | Active |
| TC-KO-008 | Knowledge Decay Detection | Identify stale intelligence and trigger refresh | Active |

Total: 8 test cases

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

---

## TC-KO-006: Knowledge Conflict Resolution

**Objective**: Handle contradictory findings from different sessions or sources

**Severity**: HIGH

**Prerequisites**: Multiple sessions producing findings about the same target

**Scenario**: Two sessions produce conflicting assessments of the same component

**Phase 1 — Conflicting Findings Created**

```
Session A finds:
  KU-020: Finding (target auth uses bcrypt, confidence 85)
  Source: codebase-onboarding static analysis

Session B finds:
  KU-021: Finding (target auth uses MD5, confidence 78)
  Source: runtime observation of password hashes in database
```

**Phase 2 — Conflict Detection**

```
GIVEN: KU-020 and KU-021 both describe target auth hashing
WHEN: knowledge-ops runs consistency check
THEN: detect conflict:
  - Same target, same component (auth/password-hashing)
  - Contradictory claims (bcrypt vs MD5)
  - Flag for resolution
```

**Phase 3 — Resolution Strategy**

```
Resolution approaches (in priority order):
1. Source reliability: runtime observation > static analysis
2. Recency: newer finding takes precedence
3. Confidence: higher confidence wins
4. Manual: escalate to operator if unresolvable

THEN: Resolve:
  - KU-021 wins (runtime observation, direct evidence)
  - KU-020 confidence: 85 → 30 (demoted, add note: "contradicted by runtime evidence")
  - Create KU-022: Resolution record linking KU-020 and KU-021
```

**Steps**:
1. Create two conflicting knowledge units about same target
2. Run conflict detection scan
3. Verify conflict is flagged
4. Apply resolution strategy
5. Verify losing unit is demoted with explanation

**Expected Output**:
- Conflict detected and flagged automatically
- Resolution record created with reasoning
- Losing unit demoted (not deleted) with cross-reference

**Pass Criteria**:
- [ ] Conflict detected between KU-020 and KU-021
- [ ] Resolution strategy applied correctly
- [ ] Losing unit retains history (not deleted)
- [ ] Resolution record links both units
- [ ] No orphaned or contradictory active findings remain

**Remediation**: Implement conflict detection as part of knowledge ingestion pipeline

---

## TC-KO-007: Automated Knowledge Indexing

**Objective**: Bulk extract entities and relationships from unstructured session logs

**Severity**: MEDIUM

**Prerequisites**: 5+ session memory files with unstructured findings

**Scenario**: Process raw session logs into structured knowledge units

**Phase 1 — Input Preparation**

```
GIVEN: 5 raw session memory files:
  - memory/2026-05-01.md (recon session, 3 targets mentioned)
  - memory/2026-05-02.md (exploitation session, 2 vulns found)
  - memory/2026-05-03.md (post-exploitation, credentials harvested)
  - memory/2026-05-04.md (lateral movement, 4 hosts accessed)
  - memory/2026-05-05.md (reporting session, findings summarized)
```

**Phase 2 — Entity Extraction**

```
WHEN: Running automated indexing pipeline
THEN: Extract entities:
  - Targets: IP addresses, domains, hostnames
  - Findings: vulnerability mentions with severity indicators
  - Credentials: username/password pairs (redacted in index)
  - Tools: tool names and their usage context
  - Relationships: which tool found which vuln on which target
```

**Phase 3 — Tagging and Linking**

```
THEN: For each extracted entity:
  1. Assign type tag (target/finding/credential/tool)
  2. Assign confidence based on context (mentioned=50, tested=75, exploited=90)
  3. Link related entities (finding → target, tool → finding)
  4. Deduplicate across sessions (same IP mentioned in 3 files = 1 entity)
```

**Steps**:
1. Prepare 5 session memory files with known entities
2. Run indexing pipeline
3. Verify entity extraction completeness
4. Verify deduplication across sessions
5. Verify relationship links are correct

**Expected Output**:
- Structured index with all entities tagged and linked
- Deduplication report (N raw mentions → M unique entities)
- Relationship graph (entity → entity connections)

**Pass Criteria**:
- [ ] All entities extracted from all 5 files
- [ ] Correct type tags assigned (>90% accuracy)
- [ ] Duplicates merged (same entity across files = 1 record)
- [ ] Relationships correctly linked
- [ ] Confidence scores assigned based on evidence level

**Verification**: Compare extracted entities against manually counted ground truth

---

## TC-KO-008: Knowledge Decay Detection

**Objective**: Identify intelligence that has become stale and trigger refresh workflows

**Severity**: MEDIUM

**Prerequisites**: Knowledge base with entries of varying ages

**Scenario**: Detect and handle knowledge units that may no longer be accurate

**Phase 1 — Define Decay Rules**

```
Decay rules by knowledge type:
  - Credentials: decay after 7 days (high rotation risk)
  - Network topology: decay after 30 days (infrastructure changes)
  - Vulnerability findings: decay after 90 days (may be patched)
  - Patterns/techniques: decay after 365 days (slow evolution)
  - Entity metadata: decay after 180 days (organizational changes)
```

**Phase 2 — Decay Scan**

```
GIVEN: Knowledge base with 20 units of varying ages
WHEN: Running decay detection scan
THEN: Identify decayed units:
  - KU-030: Credential (created 14 days ago) → DECAYED
  - KU-031: Network map (created 45 days ago) → DECAYED
  - KU-032: SQLi finding (created 60 days ago) → OK (within 90-day window)
  - KU-033: Pattern (created 200 days ago) → OK (within 365-day window)
```

**Phase 3 — Refresh Workflow**

```
FOR each decayed unit:
  1. Check if refresh is possible (target still accessible?)
  2. If yes: queue for re-validation
     - Credential: test if still valid
     - Network: re-scan topology
  3. If no: mark as "unverifiable" with last-known-good date
  4. After refresh:
     - If still valid: reset decay timer, update confidence
     - If invalid: archive with reason
```

**Steps**:
1. Create knowledge units with various creation dates
2. Run decay detection scan
3. Verify correct units flagged as decayed
4. Execute refresh workflow on flagged units
5. Verify outcomes (refreshed or archived)

**Expected Output**:
- Decay report listing all stale units with age and type
- Refresh queue with prioritized actions
- Post-refresh summary (N refreshed, M archived, K unverifiable)

**Pass Criteria**:
- [ ] Decay rules correctly applied per knowledge type
- [ ] All units exceeding their type's threshold flagged
- [ ] Refresh workflow produces actionable queue
- [ ] Refreshed units have updated timestamps
- [ ] Archived units retain history with decay reason

**Verification**: Manual review of decay report against known creation dates
