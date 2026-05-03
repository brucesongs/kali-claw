# Verification Loop

Multi-phase verification protocol for penetration testing findings, exploits, and remediations. Ensures every claim is independently confirmed before reporting.

## Activation

- After discovering a potential vulnerability or exploit
- Before submitting any finding to a report or bounty platform
- When verifying that a remediation or patch is effective
- When cross-checking automated scanner results
- User says "verify", "confirm", "validate", "double-check"

## Six-Phase Verification Process

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  1. Pre-    │───→│  2. Execute │───→│  3. Post-   │
│  Condition  │    │  & Observe  │    │  Condition  │
└─────────────┘    └─────────────┘    └─────────────┘
                                            │
┌─────────────┐    ┌─────────────┐    ┌─────┴───────┐
│  6. Evidence │←──│  5. False   │←──│  4. Independ│
│  Document   │    │  Positive   │    │  Confirm    │
│             │    │  Eliminate  │    │             │
└─────────────┘    └─────────────┘    └─────────────┘
```

### Phase 1: Pre-Condition Check

Before executing any verification:

1. **Define success criteria** — What specific outcome confirms the finding?
2. **Record baseline state** — Document the current system state before testing
3. **Identify dependencies** — Network access, credentials, tools required
4. **Set revert plan** — How to restore the system if the test causes changes

```markdown
## Verification Target: [Finding ID]
- **Type:** [Vulnerability / Exploit / Remediation / Scanner Result]
- **Claim:** [What needs to be verified]
- **Success Criteria:** [Measurable outcome]
- **Baseline State:** [Current conditions]
- **Dependencies:** [Required access/tools]
- **Revert Plan:** [How to undo changes]
```

### Phase 2: Execute & Observe

Run the test or exploit under controlled conditions:

1. **Use terminal-ops evidence protocol** — timestamp every command
2. **Capture full output** — stdout, stderr, exit codes
3. **Monitor side effects** — Watch for unintended changes
4. **Record exact commands** — Including all flags and parameters

Rules:
- Execute the EXACT same steps claimed in the original finding
- Do NOT modify parameters to force a result
- If the first attempt fails, document the failure before retrying

### Phase 3: Post-Condition Check

After execution, verify the expected outcome:

1. **Check success criteria** — Does the observed result match the claim?
2. **Measure impact** — What actually changed vs. what was expected?
3. **Capture evidence** — Screenshots, command output, log entries
4. **Assess scope** — Did anything outside the target change?

### Phase 4: Independent Confirmation

Reproduce the finding using a DIFFERENT method:

| Original Method | Independent Confirmation Method |
|----------------|-------------------------------|
| Automated scanner | Manual curl/python script |
| Manual browser test | Command-line tool (nmap, nikto, sqlmap) |
| One exploit tool | Different tool or manual technique |
| Single payload | Different payload targeting same flaw |

**Requirement:** The finding MUST be reproducible via at least one independent method.

### Phase 5: False Positive Elimination

Systematically rule out common false positive causes:

1. **Environment-specific** — Does this only work in this specific setup?
2. **Timing-dependent** — Does it require specific race conditions?
3. **Privilege-dependent** — Does it only work with elevated access?
4. **Configuration-dependent** — Does it rely on non-default settings?
5. **Tool artifact** — Is the tool itself generating misleading output?

```markdown
## False Positive Analysis
- [ ] Environment-specific? [Y/N] — Evidence:
- [ ] Timing-dependent? [Y/N] — Evidence:
- [ ] Privilege-dependent? [Y/N] — Evidence:
- [ ] Configuration-dependent? [Y/N] — Evidence:
- [ ] Tool artifact? [Y/N] — Evidence:
```

### Phase 6: Evidence Documentation

Compile verified evidence into a structured report:

```markdown
## Verification Report: [Finding ID]

### Summary
- **Finding:** [Description]
- **Verdict:** [CONFIRMED / NOT CONFIRMED / PARTIALLY CONFIRMED]
- **Confidence:** [High / Medium / Low]
- **Severity:** [Critical / High / Medium / Low / Info]

### Evidence Chain
1. Pre-condition baseline: [timestamp] — [state]
2. Execution: [timestamp] — [exact command] → [output]
3. Post-condition: [timestamp] — [observed change]
4. Independent confirmation: [method] → [result]
5. False positive analysis: [results]

### Impact Assessment
- [What an attacker could actually achieve]
- [Prerequisites for exploitation]
- [Scope of affected systems]

### Reproduction Steps
1. [Step 1 with exact command]
2. [Step 2]
3. [Expected vs actual result]
```

## Verification by Finding Type

### SQL Injection

```
Phase 2: Execute original payload (e.g., ' OR 1=1--)
Phase 4: Confirm with DIFFERENT payload (e.g., ' UNION SELECT NULL--)
Phase 5: Check — is error-based or blind? Is WAF interfering?
```

### XSS

```
Phase 2: Execute original payload (e.g., <script>alert(1)</script>)
Phase 4: Confirm with different vector (e.g., <img src=x onerror=alert(1)>)
Phase 5: Check — does it only fire in specific browser/context?
```

### Authentication Bypass

```
Phase 2: Execute bypass technique
Phase 4: Confirm with different session/account
Phase 5: Check — is this a configuration issue vs a code flaw?
```

### Network Vulnerability

```
Phase 2: Run original nmap/nessus finding
Phase 4: Manual netcat/telnet confirmation
Phase 5: Check — is the service actually vulnerable or just version-matched?
```

### Remediation Verification

```
Phase 2: Attempt the ORIGINAL exploit after patch
Phase 4: Try variant attacks on the same vector
Phase 5: Check — is the fix complete or partial?
Phase 6: Document: PATCHED / PARTIALLY PATCHED / NOT PATCHED
```

## Integration with Other Skills

| Skill | How Verification Loop Applies |
|-------|------------------------------|
| `security-bounty-hunter` | Every bounty submission requires Phase 6 report |
| `vulnerability-assessment` | Scanner results pass through Phase 5 false positive elimination |
| `terminal-ops` | Verification uses terminal-ops evidence protocol |
| `web-sqli` / `web-xss` | Every injection finding requires independent confirmation |
| `network-pentest` | Network findings verified with secondary tool |
| `deep-research` | CVE claims verified before acting on them |

## Decision Matrix

| Verification Result | Action |
|-------------------|--------|
| CONFIRMED (High confidence) | Include in report, proceed to exploitation or remediation |
| CONFIRMED (Medium confidence) | Include with caveats, recommend manual verification |
| PARTIALLY CONFIRMED | Document what works and what doesn't, adjust severity |
| NOT CONFIRMED | Do NOT include in report, investigate why the original finding appeared |
| INCONCLUSIVE | Flag for manual review, document all evidence collected |

## Anti-Patterns

- **Confirmation bias** — Do not adjust tests to force a positive result
- **Single-method verification** — Always use at least two different methods
- **Skipping Phase 5** — False positive elimination is never optional
- **Over-reporting** — If it's not confirmed, it doesn't go in the report
- **Under-evidence** — "It worked on my machine" is not evidence
