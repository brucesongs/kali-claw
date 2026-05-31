# Cross-Session Knowledge Aggregation Guide

> Skill: continuous-learning | Type: methodology
> Created: 2026-05-29 | Estimated Study Time: 20 minutes

## Overview

Methodology for aggregating knowledge across multiple penetration testing sessions — deduplication, confidence scoring, conflict resolution, and progressive refinement of knowledge entries.

## Prerequisites

- Familiarity with knowledge-ops skill (KU format)
- Access to memory/ and MEMORY.md files
- Understanding of the daily→distilled→chronicle memory hierarchy

## 1. Aggregation Pipeline

```
Session N observations
        ↓
  Extract patterns
        ↓
  Match against existing KUs
        ↓
  ┌─────────────────┐
  │ New? → Create   │
  │ Exists? → Merge │
  │ Conflict? → Flag│
  └─────────────────┘
        ↓
  Update confidence scores
        ↓
  Distill to MEMORY.md
```

## 2. Pattern Detection

### Identifying Reusable Knowledge

```markdown
## Criteria for Knowledge Extraction

A finding becomes a knowledge unit when:
1. It applies beyond the current target (generalizable)
2. It contradicts or refines existing knowledge (novel)
3. It was non-obvious before discovery (surprising)
4. It will save time in future engagements (actionable)

## Anti-Patterns (Do NOT extract)
- Target-specific configurations
- One-time credentials or tokens
- Ephemeral network states
- Tool output without interpretation
```

### Classification Matrix

| Observation Type | Extract? | Format |
|-----------------|----------|--------|
| New attack technique | Yes | Technique KU |
| Tool behavior quirk | Yes | Tool KU |
| Target-specific config | No | Session log only |
| Confirmed false positive | Yes | Anti-pattern KU |
| Failed approach | Maybe | Only if failure reason is generalizable |

## 3. Confidence Scoring

```markdown
## Confidence Levels

| Level | Score | Criteria |
|-------|-------|----------|
| Hypothesis | 0.3 | Observed once, not verified |
| Probable | 0.5 | Observed 2-3 times OR verified once |
| Confirmed | 0.7 | Verified across multiple targets |
| Established | 0.9 | Consistently reliable, no contradictions |

## Score Update Rules
- Each successful reuse: +0.1 (cap at 0.95)
- Each failure/contradiction: -0.2 (floor at 0.1)
- No use in 30 days: -0.05 (decay)
- Contradicted by newer finding: set to 0.3 and flag for review
```

## 4. Conflict Resolution

### When Two KUs Contradict

```markdown
## Resolution Protocol

1. Identify the conflict
   - KU-A says: "Tool X always requires flag --foo"
   - KU-B says: "Tool X works without --foo on version 3.x"

2. Determine scope
   - Is one more specific? (version-specific vs general)
   - Is one more recent? (tool may have changed)

3. Resolution options
   a) Merge with conditions: "Tool X requires --foo (except v3.x+)"
   b) Supersede: Mark older KU as deprecated, keep newer
   c) Split: Create version-specific KUs

4. Update confidence
   - Winning KU: confidence unchanged
   - Losing KU: confidence → 0.3 or archived
```

## 5. Progressive Refinement

### Session-Over-Session Improvement

```markdown
## Refinement Triggers

After each session, check:
1. Did any KU get used? → Update last_used, bump confidence
2. Did any KU fail? → Flag for review, reduce confidence
3. Did we discover something new? → Create or merge KU
4. Did we find a better approach? → Update existing KU

## Example Refinement Chain

Session 1: "nmap -sV is slow on large ranges"
  → KU: "Use --min-rate 1000 for large scans" (confidence: 0.3)

Session 2: "min-rate 1000 missed some services"
  → Update: "Use --min-rate 500 for accuracy" (confidence: 0.5)

Session 3: "Confirmed: 500 is sweet spot for /24 networks"
  → Update: "min-rate 500 optimal for /24" (confidence: 0.7)
```

## 6. Distillation to Long-Term Memory

### When to Distill

```markdown
## Distillation Criteria

Move from daily logs to MEMORY.md when:
- Confidence ≥ 0.7
- Used successfully ≥ 3 times
- Applies across ≥ 2 different target types
- Not already captured in MEMORY.md

## Distillation Format

Daily log entry (verbose):
  "Discovered that running sqlmap with --level=5 --risk=3 on
   target X found 3 additional injection points that level=1
   missed. Took 4x longer but worth it for thorough assessment."

Distilled MEMORY.md entry (concise):
  "sqlmap: --level=5 --risk=3 finds significantly more injection
   points at 4x time cost. Use for thorough assessments, skip
   for quick checks."
```

## Quick Reference

| Action | Trigger | Output |
|--------|---------|--------|
| Create KU | New generalizable finding | New entry, confidence 0.3 |
| Merge KU | Confirms existing knowledge | Updated entry, confidence +0.1 |
| Flag conflict | Contradicts existing KU | Both flagged for review |
| Distill | Confidence ≥ 0.7, used ≥ 3x | MEMORY.md entry |
| Archive | Confidence < 0.2, unused 60d | Moved to archive |

## Integration with Other Skills

- **knowledge-ops**: Formal KU creation and graph management
- **chronicle**: Monthly aggregation of major knowledge milestones
- **deep-research**: Validate KUs against external sources
