# Knowledge Extraction Workflow

Step-by-step operational guide for extracting, scoring, storing, and maintaining structured knowledge from penetration testing engagements. Covers the complete learning cycle from raw observation to reusable knowledge entry.

---

## 1. The Learning Cycle

The continuous learning skill follows a six-phase cycle. Each phase builds on the previous one. Skipping phases produces low-quality knowledge entries that degrade the knowledge base over time.

```text
Phase 1: Observe     → Notice something worth learning from
Phase 2: Extract     → Transform the observation into structured knowledge
Phase 3: Score       → Assign confidence based on evidence strength
Phase 4: Store       → Place the entry in the correct memory layer
Phase 5: Cross-Ref   → Link to existing knowledge and detect contradictions
Phase 6: Maintain    → Review, refresh, prune, and evolve over time
```

### Phase Dependencies

```text
Observe → Extract → Score → Store → Cross-Ref → Maintain
   │         │        │       │         │
   FAIL      FAIL     FAIL    FAIL      FAIL
   ↓         ↓        ↓       ↓         ↓
   No        Cannot   Cannot  Wrong     Isolated
   learnable structure assign  layer     entry, no
   pattern   the data conf.   chosen    connections
```

### Timing Expectations

```text
Phase 1: Observe      →  0 minutes (happens during normal work)
Phase 2: Extract      →  5-15 minutes (structured write-up)
Phase 3: Score        →  2-5 minutes (apply rubric)
Phase 4: Store        →  2-5 minutes (file placement and formatting)
Phase 5: Cross-Ref    →  5-15 minutes (search and link)
Phase 6: Maintain     →  Ongoing (triggered by staleness detection)

Total per entry: 15-40 minutes
```

---

## 2. Pattern Detection Techniques

Pattern detection is Phase 1 of the cycle. It answers the question: "Is there something worth learning from what just happened?"

### 2.1 What to Look For

Not every engagement output contains a learnable pattern. Focus detection on these six trigger categories:

```text
Trigger 1: Unexpected Success
  An exploit worked when it should not have, or worked faster than expected.
  Ask: Why did this work? What was different about this target?

  Example: SQLMap found a blind SQL injection in a parameter that the
  automated scanner marked as "clean." The scanner used time-based
  detection with a 5-second threshold; the actual response delay was 7
  seconds, which the scanner interpreted as network latency.

Trigger 2: Unexpected Failure
  A reliable technique failed on a target where it should have worked.
  Ask: Has the target been patched? Is there a new defense? Did we
  misconfigure the tool?

  Example: Hydra failed to brute-force SSH despite correct credentials
  in the wordlist. Root cause: the target used fail2ban with a 2-attempt
  lockout, and Hydra's default of 16 parallel tasks triggered it instantly.

Trigger 3: Unusual Tool Output
  A tool produced results that do not match expectations.
  Ask: Is this a false positive? A real finding? A tool bug?

  Example: Nmap reported port 443 as "filtered" on a target that
  responded to HTTPS requests in the browser. Root cause: the target
  used a CDN that responded to browser requests but dropped raw SYN
  packets from non-whitelisted IPs.

Trigger 4: Recurring Configuration
  The same misconfiguration or architecture appears across multiple targets.
  Ask: Is this a pattern specific to an industry, technology, or deployment?

  Example: Three consecutive web application assessments found the same
  misconfigured CORS policy allowing wildcard origins with credentials.
  Pattern: this was specific to a popular Node.js CORS middleware default.

Trigger 5: Time Waste
  Significant time was spent on an approach that yielded nothing.
  Ask: What signal was missed that could have prevented this dead end?

  Example: Spent 2 hours enumerating subdomains for a target that turned
  out to use a single-domain architecture. The initial DNS lookup showed
  only A and AAAA records with no NS delegation — a signal that subdomain
  enumeration was unlikely to be productive.

Trigger 6: Defense Behavior
  A defensive mechanism was observed in action.
  Ask: How does this defense work? Can it be bypassed? How can it be
  detected earlier in future engagements?

  Example: A WAF blocked all SQL injection payloads containing the word
  "UNION" but allowed equivalent queries using "union" (case-sensitive
  rule). This bypass worked because the WAF regex was not case-insensitive,
  but the database parser was.
```

### 2.2 Detection During Active Work

During an engagement, keep a lightweight observation log:

```markdown
## Observations — YYYY-MM-DD

- [HH:MM] [TRIGGER-TYPE] Brief description of what was noticed
- [14:30] [UNEXPECTED-SUCCESS] SQLi in search parameter bypassed WAF with case variation
- [15:45] [TOOL-ANOMALY] Nmap SYN scan showed port 80 filtered but HTTP responded
- [16:20] [TIME-WASTE] 90 minutes on subdomain enum with zero results, single-domain target
```

These raw observations are the input to Phase 2 (extraction).

### 2.3 Detection During Review

Some patterns only become visible when reviewing multiple daily logs in aggregate. During weekly or monthly reviews, scan for:

```text
Recurring keywords across logs:
  - Same tool name appearing with "failed" or "false positive"
  - Same technique described with "worked" or "confirmed"
  - Same target technology mentioned repeatedly

Use the pattern detection scripts from payloads.md:
  - attack-patterns scan: finds exploitation success indicators
  - defense-patterns scan: finds defensive measure observations
  - tool-anomalies scan: finds unexpected tool behavior
  - recurring-patterns scan: counts cross-engagement pattern frequency
```

---

## 3. Knowledge Entry Creation

Phase 2 transforms a raw observation into a structured knowledge entry. The structure makes knowledge searchable, comparable, and maintainable.

### 3.1 Choosing the Right Template

Select the template based on what was observed:

| Observation Type | Template | ID Prefix |
|-----------------|----------|-----------|
| Successful attack technique | Attack Pattern Entry | KE-ATK |
| Defensive mechanism observed | Defense Pattern Entry | KE-DEF |
| Tool behavior or configuration tip | Tool Mastery Note | KE-TOOL |
| Infrastructure or architecture pattern | Environment Pattern Entry | KE-ENV |
| Process or methodology lesson | Engagement Lesson Entry | KE-ENG |

### 3.2 Worked Example: Attack Pattern

Raw observation from daily log:

```text
[14:30] SQLi in search parameter bypassed WAF with lowercase "union select"
while uppercase "UNION SELECT" was blocked. Target: WordPress 6.4 with
ModSecurity 3.x CRS 4.0.
```

Structured knowledge entry:

```markdown
## Knowledge Entry: KE-ATK-042

- **Category**: Attack
- **Technique**: T1190 (Exploit Public-Facing Application)
- **Context**: Web application assessment, WordPress 6.4 with ModSecurity
  3.x running OWASP CRS 4.0 in detection-only mode
- **Pattern**: ModSecurity CRS 4.0 default rules for SQL injection use
  case-sensitive regex matching. The keyword "UNION" is blocked but "union"
  and "Union" pass through. The MySQL parser treats all three identically.
- **Root Cause**: CRS 4.0 rule 942100 uses a case-sensitive pattern for
  UNION-based injection. This is a known gap when CRS is deployed without
  the paranoia level 2+ rules that add case-insensitive matching.
- **Prerequisites**: Target uses ModSecurity with CRS 4.0, paranoia level 1,
  and a backend database that is case-insensitive for SQL keywords (MySQL,
  PostgreSQL, MSSQL all qualify).
- **Steps**:
  1. Identify injection point with standard boolean-based test
  2. Confirm WAF presence (blocked request returns 403 with ModSecurity header)
  3. Test case variation: replace "UNION SELECT" with "union select"
  4. If bypass succeeds, enumerate columns and extract data
- **Indicators of Success**: HTTP 200 response with data from injected query
  instead of HTTP 403
- **Variations Observed**: Mixed case ("uNiOn SeLeCt") also bypasses
- **Counter-Indications**: Does not work at paranoia level 2+, or when the
  WAF is configured for case-insensitive matching via SecRuleEngine
- **Applicability**: Any ModSecurity CRS 4.0 deployment at paranoia level 1
- **Source**: Web application assessment, engagement ENG-alpha-2026-05-22
- **Date**: 2026-05-22
- **Confidence**: Medium (single observation, consistent with CRS documentation)
```

### 3.3 Worked Example: Tool Mastery Note

Raw observation:

```text
[15:45] Nmap SYN scan shows port 80 filtered but HTTP responds in browser.
Target behind Cloudflare CDN.
```

Structured knowledge entry:

```markdown
## Knowledge Entry: KE-TOOL-017

- **Category**: Tool
- **Tool**: Nmap 7.95
- **Use Case**: Port scanning targets behind CDN/reverse proxy
- **Command**: `nmap -sS -Pn -p 80,443 target.com`
- **Context**: When the target is behind a CDN (Cloudflare, Akamai, etc.),
  the CDN edge server may not respond to raw SYN packets from non-whitelisted
  IPs, causing Nmap to report ports as "filtered" even though the web
  application is accessible via normal HTTP requests.
- **Output Interpretation**: "filtered" on port 80/443 for a CDN-fronted
  target does NOT mean the service is down. It means the CDN is dropping
  the probe. Always verify with an HTTP-level check.
- **Gotchas**: Do not conclude "port closed/filtered" without an HTTP-level
  verification when a CDN is suspected. Check HTTP headers for CDN indicators
  (cf-ray, x-amz-cf-id, akamai-x-cache) before interpreting scan results.
- **Alternatives**: Use `curl -I` for HTTP-level checks. Use `nmap --script
  http-headers` to detect CDN presence before interpreting port scan results.
- **Performance Notes**: CDN-fronted targets may rate-limit or blacklist
  scanning IPs after sustained SYN probes.
- **Source**: External penetration test, engagement ENG-beta-2026-05-22
- **Date**: 2026-05-22
- **Confidence**: High (observed across 5+ CDN-fronted targets)
```

### 3.4 Writing Quality Checklist

Before storing a knowledge entry:

```text
  [ ] Pattern field describes WHAT happened, not just that something happened
  [ ] Root Cause field explains WHY (or honestly says "unknown")
  [ ] Context includes specific technologies, versions, and configurations
  [ ] Counter-Indications explain when this does NOT apply
  [ ] Source traces back to a specific engagement or research session
  [ ] Date is present
  [ ] Confidence level is assigned with justification
  [ ] Entry is specific enough to be actionable ("SQL injection exists" is not enough)
```

---

## 4. Confidence Scoring in Practice

Phase 3 assigns a confidence score based on evidence strength. Scores drive storage decisions, review frequency, and trust level when applying knowledge.

### 4.1 Initial Score Assignment

Use the scoring worksheet from payloads.md:

```text
Factor 1: Observation Count     (weight 3x)
  - 1 observation      → 2/10
  - 2 observations     → 5/10
  - 3+ observations    → 10/10

Factor 2: Independent Verification (weight 2x)
  - No verification    → 0/10
  - Partial (same tool, different config) → 5/10
  - Full (different tool confirms) → 10/10

Factor 3: Root Cause Clarity    (weight 2x)
  - Unknown            → 0/10
  - Hypothesis only    → 5/10
  - Confirmed          → 10/10

Factor 4: Reproduction Success  (weight 2x)
  - Failed             → 0/10
  - Partial            → 5/10
  - Reliable           → 10/10

Factor 5: Consistency with Prior Knowledge (weight 1x)
  - Contradicts        → 0/10
  - Neutral            → 5/10
  - Reinforces         → 10/10

Total = (F1 * 3 + F2 * 2 + F3 * 2 + F4 * 2 + F5 * 1) = max 100
```

**Score ranges:**

```text
75-100  → High confidence    (established pattern, store permanently)
40-74   → Medium confidence  (provisional pattern, review quarterly)
10-39   → Low confidence     (observation only, review monthly)
0-9     → Negative           (contradicted belief, flag for correction)
```

### 4.2 Worked Scoring Example

For KE-ATK-042 (ModSecurity CRS case-sensitivity bypass):

```text
Factor 1: Observation count = 1           → 2/10  * 3 = 6
Factor 2: Verified with different payload → 5/10  * 2 = 10
Factor 3: Root cause confirmed in CRS docs → 10/10 * 2 = 20
Factor 4: Reproduced reliably on target   → 10/10 * 2 = 20
Factor 5: Consistent with known WAF bypass → 10/10 * 1 = 10

Total: 66/100 → Medium confidence
```

This makes sense — the technique is well-understood and reproducible, but has only been observed on one target. A second independent observation would push it to High.

### 4.3 When to Upgrade Confidence

```text
Low → Medium:
  Trigger: Second independent observation confirms the pattern
  Action: Update score, add new source attribution, change review frequency

Medium → High:
  Trigger: Third observation OR independent tool verification on different target
  Action: Update score, promote to established pattern, change review to annual

Example progression:
  Day 1:  KE-ATK-042 created at Medium (66/100) — single engagement
  Day 15: Same bypass observed on different client's ModSecurity → High (82/100)
  Day 30: Published research confirms the gap in CRS 4.0 → High (95/100)
```

### 4.4 When to Downgrade Confidence

```text
High → Medium:
  Trigger: Contradicting observation from a reliable source
  Action: Add contradicting evidence, lower score, flag for detailed review

Medium → Low:
  Trigger: Failed reproduction attempt OR source tool identified as unreliable
  Action: Add failure evidence, lower score, mark entry as "needs verification"

Any → Negative:
  Trigger: Definitive evidence contradicts the pattern
  Action: Flag original entry with [CONTRADICTED] label, create a correction
          entry that explains what was wrong, notify all entries that
          cross-reference the contradicted entry
```

---

## 5. Knowledge Maintenance Procedures

Phase 6 keeps the knowledge base accurate over time. Without maintenance, the knowledge base becomes a liability — stale entries lead to wrong decisions.

### 5.1 Staleness Detection

Run the staleness detection script from payloads.md on a regular schedule:

```text
Review frequency by confidence level:
  - Low confidence entries:    Monthly review
  - Medium confidence entries: Quarterly review
  - High confidence entries:   Annual review
  - Negative entries:          Immediate review of related entries
```

An entry is stale when:

```text
  - The entry's age exceeds its review threshold (see above)
  - The target technology has released a major version since the entry date
  - A related entry has been contradicted or updated
  - The tool referenced in the entry has been deprecated or replaced
```

### 5.2 Pruning Decisions

For each stale entry, choose one of five actions:

```text
Action 1: RETAIN
  The knowledge is still accurate. Update the review date, confirm the
  confidence level, and leave the entry unchanged.
  When: Entry verified against current technology version or re-observed.

Action 2: UPDATE
  The knowledge is partially accurate but needs modification.
  When: Technology has changed but the core pattern still holds with
  modifications (e.g., new version changed the default setting but the
  technique works with a flag adjustment).

Action 3: DOWNGRADE
  The confidence has decreased due to age, contradicting evidence, or
  inability to reproduce.
  When: Entry has not been re-observed within its review period and no
  independent confirmation exists.

Action 4: ARCHIVE
  The knowledge is no longer applicable but has historical value.
  When: Technology is end-of-life, technique patched in all supported
  versions, or tool discontinued.
  Implementation: Move to an "[ARCHIVED]" section, add note explaining why.

Action 5: DELETE
  The knowledge was incorrect from the start.
  When: Entry identified as false positive, tool bug, or misinterpretation.
  Implementation: Remove entry, create a correction entry if the mistake
  is itself instructive, update cross-references.
```

### 5.3 Contradiction Resolution

When a new observation contradicts an existing entry:

```text
Step 1: Verify the contradiction is real
  - Is the new observation from a reliable source?
  - Could the difference be explained by context (different technology
    version, different configuration)?
  - Could both observations be correct under different conditions?

Step 2: Determine scope of contradiction
  - Does it invalidate the entire entry, or just a specific claim?
  - How many other entries depend on the contradicted knowledge?

Step 3: Resolve
  - If full contradiction: Flag original as [CONTRADICTED], create
    correction entry, update all cross-references
  - If partial contradiction: Update the original entry to narrow its
    applicability, add the new observation as a counter-indication
  - If context-dependent: Both entries are correct. Add cross-references
    that clarify when each applies.
```

### 5.4 Knowledge Health Metrics

Run the health report script from payloads.md quarterly. Track these metrics:

```text
Distribution balance:
  - Are entries spread across all five categories (ATK, DEF, TOOL, ENV, ENG)?
  - A healthy knowledge base has representation in every category.
  - Overweight in one category suggests tunnel vision.

Confidence distribution:
  - Healthy: pyramid shape (many Low, fewer Medium, fewest High)
  - Unhealthy: inverted pyramid (few Low, many High — confidence inflation)
  - Unhealthy: all Low (nothing being verified and promoted)

Staleness rate:
  - Target: <10% of entries are stale at any given time
  - Warning: >20% stale entries indicates maintenance neglect

Cross-reference density:
  - Target: average of 2+ cross-references per entry
  - Warning: many entries with zero cross-references (isolated knowledge)
```

---

## 6. Integration with Chronicle and Knowledge-Ops

Continuous learning does not operate in isolation. It feeds and consumes data from the chronicle system and knowledge-ops infrastructure.

### 6.1 Integration with Chronicle

```text
Inbound (chronicle → continuous-learning):
  - Chronicle events are a primary source of raw observations
  - Monthly chronicle reviews surface patterns that trigger learning
  - Chronicle cross-references help identify recurring themes

Outbound (continuous-learning → chronicle):
  - Significant learning events become chronicle entries (usually P1)
  - Knowledge base milestones (e.g., "100th entry created") are P1 events
  - Knowledge contradictions that overturn established patterns are P0 events

Shared workflows:
  - Distillation: chronicle events distill to MEMORY.md through the same
    process that continuous-learning uses to store knowledge entries
  - Monthly review: chronicle monthly review and knowledge maintenance
    should be done in the same session to catch cross-system patterns
```

### 6.2 Integration with Knowledge-Ops

```text
Inbound (knowledge-ops → continuous-learning):
  - Knowledge-ops provides search infrastructure for cross-referencing
  - Knowledge-ops indexes make duplicate detection possible
  - Knowledge-ops retrieval feeds context for new observations

Outbound (continuous-learning → knowledge-ops):
  - New knowledge entries must be indexed by knowledge-ops
  - Entry updates and deletions must propagate to the index
  - Staleness detection results inform knowledge-ops maintenance priorities
```

### 6.3 Integration with Verification Loop

```text
Direction: bidirectional

  - verification-loop validates findings before they become knowledge entries
  - continuous-learning tracks which verification methods are most reliable
    per finding type (this is itself a knowledge entry: KE-TOOL category)
  - False positive patterns detected by verification-loop feed directly
    into KE-DEF and KE-TOOL entries
```

### 6.4 Integration with All Skills

Every skill is a potential source of learnable observations:

```text
  web-sqli, web-xss     → Attack patterns, WAF bypass knowledge
  network-pentest        → Network architecture patterns, tool behaviors
  post-exploitation      → Privilege escalation techniques, persistence patterns
  cloud-security         → Cloud misconfiguration patterns
  osint                  → Reconnaissance technique effectiveness
  password-attack        → Credential attack success rates, lockout behaviors
  vulnerability-assessment → Scanner false positive patterns, coverage gaps
```

---

## 7. Common Pitfalls

### 7.1 Over-Documenting

```text
Problem: Creating a knowledge entry for every minor observation
Symptoms:
  - Hundreds of Low-confidence entries with no follow-up
  - Time spent documenting exceeds time spent testing
  - Knowledge base becomes unsearchable noise

Fix: Apply the learning triggers from Section 2 strictly. Not every tool
output is a pattern. If the observation would not change how you approach
a future engagement, it does not need a knowledge entry. Keep it in the
daily memory log and let it age out naturally.

Rule of thumb: If you cannot write a non-trivial "Applicability" field
(beyond "always" or "sometimes"), the observation is too vague to store.
```

### 7.2 Stale Knowledge

```text
Problem: Knowledge entries that have not been reviewed within their cycle
Symptoms:
  - Entries reference deprecated tools or patched vulnerabilities
  - Confidence levels do not reflect current reality
  - Applying stale knowledge wastes time or produces incorrect results

Fix: Run staleness detection monthly. Treat maintenance as a mandatory
task, not an optional cleanup. Set calendar reminders for quarterly deep
reviews. When encountering an entry during active work that seems wrong,
stop and investigate immediately rather than ignoring it.
```

### 7.3 Missing Cross-References

```text
Problem: Knowledge entries exist in isolation with no links to related entries
Symptoms:
  - Duplicate entries created because the existing one was not found
  - Contradictions persist because conflicting entries are not connected
  - Related knowledge is not surfaced when it would be useful

Fix: Phase 5 (Cross-Reference) is not optional. After storing every entry,
run at least three searches:
  1. Search by primary keyword (tool name, technique name, CVE)
  2. Search by category (same KE-xxx prefix)
  3. Search by target technology

Link everything that is related. Two minutes of cross-referencing prevents
hours of duplicate work later.
```

### 7.4 Confidence Inflation

```text
Problem: Assigning High confidence based on gut feeling instead of evidence
Symptoms:
  - Most entries are High confidence despite limited observations
  - Knowledge base gives false sense of certainty
  - Actual reproduction rate is lower than confidence levels suggest

Fix: Use the scoring worksheet mechanically. Do not adjust scores
intuitively. If the math says Medium, it is Medium — even if you "feel
sure." High confidence requires three independent observations or
equivalent verification. No exceptions.
```

### 7.5 Knowledge Hoarding

```text
Problem: Storing raw data dumps instead of structured, distilled knowledge
Symptoms:
  - Entries contain pages of tool output with no interpretation
  - Pattern and Root Cause fields are empty or say "see output"
  - Entries cannot be understood without re-analyzing the raw data

Fix: The knowledge entry is the interpretation, not the data. Raw data
belongs in evidence files linked from the Outputs section. The entry
itself must contain the synthesized lesson in its Pattern, Root Cause,
and Applicability fields. If you cannot summarize it, you have not
learned from it yet.
```

### 7.6 Ignoring Negative Results

```text
Problem: Only recording what worked, never recording what failed
Symptoms:
  - Knowledge base has a survivorship bias toward successful techniques
  - Same dead-end approaches are tried repeatedly across engagements
  - No record of tool limitations or technique boundaries

Fix: Negative results are as valuable as positive ones. "Nmap misses
port 443 behind Cloudflare CDN" is a critical KE-TOOL entry. "SQLMap
cannot detect second-order injection" prevents future time waste. Create
entries for failures with the same rigor as successes.
```
