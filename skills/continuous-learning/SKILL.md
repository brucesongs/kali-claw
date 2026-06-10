---
name: continuous-learning
description: "After completing a penetration test engagement - When encountering a novel attack technique or defense - After a tool produces unexpected results - When identifying recurring patterns across targets - User says \"learn\", \"remember this\", \"pattern."
origin: openclaw
version: "0.1.18"
compatibility:
  - openclaw
  - claude-code
  - cursor
  - windsurf
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
  - WebSearch
  - WebFetch
  - Agent
metadata:
  domain: knowledge
  tool_count: 9
  guide_count: 5
---




# Continuous Learning

## Summary

Continuous Learning skill domain covering knowledge operations.

**Tools**: High, Medium, Low, Negative, Attack Patterns, Defense Patterns, Tool Behaviors, Environment Patterns (+1 more)

**Domain**: knowledge

## Use Cases

1. **Post-Engagement Learning** — After a penetration test, extract reusable patterns from observations and tool outputs
2. **Cross-Session Knowledge Building** — Accumulate tool behavior knowledge across multiple engagements into structured entries
3. **Pattern Recognition** — Identify recurring vulnerabilities, tool limitations, and effective technique combinations
4. **Knowledge Confidence Tracking** — Assign and update confidence scores for learned facts based on corroboration frequency
5. **Memory Layering** — Distill raw observations into layered knowledge: immediate notes → verified patterns → core principles

## Activation

- After completing a penetration test engagement
- When encountering a novel attack technique or defense
- After a tool produces unexpected results
- When identifying recurring patterns across targets
- User says "learn", "remember this", "pattern", "lesson learned"

## Learning Cycle

```
┌──────────┐    ┌───────────┐    ┌───────────┐
│ Pattern  │───→│ Extract & │───→│ Confidence │
│ Detection│    │ Structure │    │  Scoring  │
└──────────┘    └───────────┘    └───────────┘
                                        │
┌──────────┐    ┌───────────┐    ┌───────┴───┐
│ Cross-   │←──│  Memory   │←──│  Storage  │
│ Reference│    │ Retrieval │    │           │
└──────────┘    └───────────┘    └───────────┘
```

### Step 1: Pattern Detection

Identify learnable patterns from observations:

| Pattern Category | What to Look For |
|-----------------|-----------------|
| **Attack Patterns** | Successful exploitation techniques, unexpected bypasses |
| **Defense Patterns** | WAF rules detected, IDS triggers, rate limiting behaviors |
| **Tool Behaviors** | Tools that produced false positives, missed findings, gave unusual output |
| **Environment Patterns** | Common misconfigurations, typical network architectures |
| **Engagement Patterns** | Time allocation, methodology gaps, scope surprises |

### Step 2: Extract & Structure

Transform raw observation into structured knowledge:

```markdown
## Knowledge Entry: [ID]
- **Category:** [Attack / Defense / Tool / Environment / Engagement]
- **Context:** [When/where this was observed]
- **Pattern:** [What happened]
- **Root Cause:** [Why it happened, if known]
- **Applicability:** [When this knowledge is relevant]
- **Source:** [Engagement type, tool, or research]
- **Date:** [When observed]
```

### Step 3: Confidence Scoring

Rate confidence based on supporting evidence:

| Confidence Level | Criteria | Storage Action |
|-----------------|----------|---------------|
| **High** | Observed 3+ times across different engagements, independently verified | Store as established pattern |
| **Medium** | Observed 1-2 times, consistent with known theory | Store as provisional pattern |
| **Low** | Single observation, unclear root cause | Store as observation only |
| **Negative** | Previously held belief contradicted by evidence | Flag old entry for review, store correction |

### Step 4: Storage

Save structured knowledge to the appropriate memory layer:

**Short-term (Engagement):** Tactical observations for current engagement
- Specific tool configurations that worked
- Target-specific quirks discovered
- Time-critical findings to revisit

**Medium-term (Technique):** Technique-level knowledge reusable across engagements
- Effective payload patterns for specific technologies
- Bypass techniques for specific WAF/IDS products
- Tool-specific tips and gotchas

**Long-term (Strategic):** Strategic patterns about security landscapes
- Emerging attack technique trends
- Common architectural weaknesses by industry
- Tool capability boundaries and gaps

### Step 5: Cross-Reference

Link new knowledge to existing entries:

- Does this contradict a previous observation?
- Does this reinforce a previous observation?
- Does this fill a gap in existing knowledge?
- Is this a variant of a known pattern?

## Knowledge Categories

### Attack Pattern Library

```markdown
### [Pattern Name]
- **Technique:** [ATT&CK technique ID if applicable]
- **Prerequisites:** [What must be true for this to work]
- **Steps:** [How to execute]
- **Indicators of success:** [How to know it worked]
- **Variations observed:** [Different contexts where it applied]
- **Counter-indications:** [When NOT to attempt this]
```

### Tool Mastery Notes

```markdown
### [Tool Name] - [Specific Use Case]
- **Command:** [Exact command with flags]
- **Context:** [When this configuration is optimal]
- **Output interpretation:** [How to read the results]
- **Gotchas:** [Common mistakes or misleading output]
- **Alternatives:** [Other tools for the same job]
- **Performance notes:** [Speed/resource considerations]
```

### Engagement Lessons

```markdown
### Lesson: [Title]
- **Engagement type:** [Black box / White box / Red team / Bug bounty]
- **What happened:** [Description]
- **What we learned:** [Key takeaway]
- **What we'd do differently:** [Process improvement]
- **Applicable scenarios:** [When this lesson is relevant]
```

## Learning Triggers

Automatic pattern extraction should occur when:

1. **An exploit succeeds unexpectedly** — Why did it work? What was different?
2. **A tool gives unexpected output** — Is this a false positive, a real finding, or a tool bug?
3. **A target behaves unusually** — Custom defense? Misconfiguration? Honeypot?
4. **An attack chain works particularly well** — What made the chain effective?
5. **A previously reliable technique fails** — Has the target been patched? Is there a new defense?
6. **Time is wasted on a dead end** — What signal was missed that could have prevented this?

## Integration with Other Skills

| Skill | Learning Opportunity |
|-------|---------------------|
| `verification-loop` | Learn which verification methods are most reliable per finding type |
| `terminal-ops` | Learn optimal evidence capture formats per engagement type |
| `deep-research` | Learn which sources are most authoritative per topic |
| `search-first` | Learn which repositories have the best exploits per technology |
| `vulnerability-assessment` | Learn scanner false positive patterns per target technology |
| `web-sqli` / `web-xss` | Learn payload patterns effective against specific WAFs |
| `network-pentest` | Learn network architecture patterns and their common weaknesses |
| `security-bounty-hunter` | Learn which vulnerability types are most rewarded per platform |

## Knowledge Quality Rules

1. **Never store assumptions as facts** — Label speculation clearly
2. **Always include context** — Where, when, and under what conditions
3. **Prefer specific over general** — "SQL injection in parameter X of WordPress plugin Y v3.2" beats "SQL injection exists"
4. **Include negative results** — "Tool X missed finding Y" is as valuable as "Tool X found Y"
5. **Date everything** — Knowledge has a shelf life; dated entries can be refreshed
6. **Source attribution** — Every entry must trace back to a specific observation or research

## Anti-Patterns

- **Storing unverified findings** — Verify before storing (use verification-loop)
- **Over-generalizing** — One observation does not make a universal rule
- **Ignoring context** — A technique that worked in one context may fail in another
- **Knowledge hoarding** — Store structured patterns, not raw data dumps
- **Never pruning** — Review and update stored knowledge periodically
- **Confidence inflation** — Be honest about confidence levels

## Orchestration

### ECC Loop Pattern
- **Pattern**: Learning Cycle (detect pattern → extract & structure → score confidence → store → cross-reference)
- **Rationale**: Learning is inherently iterative — each observation refines understanding, confidence scores evolve with more evidence, and cross-referencing with existing knowledge prevents contradictions
- **Integration**: All skills (consumes observations from every engagement), verification-loop (learns which verification methods are most reliable), search-first (learns which sources have best results per topic), terminal-ops (learns optimal evidence formats)

### Cross-Skill Pipeline
```
[all skills] → continuous-learning → MEMORY.md / chronicle
                       ↓                         ↑
              verification-loop (FP patterns)   deep-research (context enrichment)
```

### Quality Gate
- Pre-condition: Observation from real engagement or verified research
- Post-condition: Structured knowledge entry with confidence level and source attribution
- Verification: Entry cross-referenced against existing knowledge, no contradictions
