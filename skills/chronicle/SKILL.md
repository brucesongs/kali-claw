---
name: chronicle
description: "A system for recording, indexing, and distilling knowledge from agent lifecycle events. Through a three-layer document system (overview -> detailed records -> knowledge distillation), raw conversation events are transformed into reusable experience."
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
  tool_count: 4
  guide_count: 5
---




# Skill: Chronicle System

> **Supplementary Files**:
> - `chronicle-template.py` — Chronicle detailed record template generator (Python script that automatically generates event record files and creates directory structures)

## Summary

Through a three-layer document system (overview -> detailed records -> knowledge distillation), raw conversation events are transformed into reusable experience.

**Tools**: MEMORY.md, HEARTBEAT.md, TOOLS.md, skills/

**Domain**: knowledge

## Description

A system for recording, indexing, and distilling knowledge from agent lifecycle events. Through a three-layer document system (overview -> detailed records -> knowledge distillation), raw conversation events are transformed into reusable experience.

Distinction from MEMORY.md: Chronicle records "what happened," while MEMORY.md records "what was learned."

---

## Use Cases

- Completing a major security discovery (high-severity vulnerability, data breach)
- Achieving a key milestone (learning plan completion, tool mastery)
- Important environment or configuration changes
- Need to quickly review historical events and handling approaches
- Periodic archiving of expired logs from memory/

---

## Three-Layer Architecture

```
+------------------------------------------+
|  Layer 1: CHRONICLE.md (Overview Index)  |
|  Timeline + one-line summary + nav links |
+------------------+-----------------------+
                   |
                   v
+------------------------------------------+
|  Layer 2: chronicle/YYYY-MM/             |
|  YYYY-MM-DD-event-name.md (Detail)       |
|  Background, process, results, outputs,  |
|  impact                                   |
+------------------+-----------------------+
                   |
                   v
+------------------------------------------+
|  Layer 3: MEMORY.md (Knowledge Distill)  |
|  Experience, lessons, capability growth   |
+------------------------------------------+
```

---

## Event Classification

| Type | Icon | Priority | Trigger Condition |
|------|------|----------|-------------------|
| Security Discovery | red_circle | P0 Record immediately | High-severity vulnerability, data breach, credential exposure |
| Milestone Achieved | party_popper | P0 Record immediately | Learning plan completed, full tool mastery |
| Project Launch | rocket | P1 Record same day | New phase, new goal, new environment |
| Learning Completed | books | P1 Record same day | Tool learning, skill mastery, certification passed |
| Environment Config | wrench | P1 Record same day | Toolchain, system configuration, network changes |
| Report Delivered | page | P1 Record same day | Penetration test report, security assessment |
| System Optimization | gear | P2 Record this week | Workflow improvement, directory cleanup |
| Goal Setting | dart | P2 Record this week | New plans, new directions |

---

## Event Template

File path: `chronicle/YYYY-MM/YYYY-MM-DD-event-name.md`

```markdown
# YYYY-MM-DD - Event Name

> **Type**: [icon] [type name]
> **Priority**: P[0/1/2]
> **Recorded**: YYYY-MM-DD HH:MM

---

## Background

[Why this was done]

---

## Process

### Phase 1: [Name]
- **Action**: [What was done]
- **Result**: [What happened]

### Phase 2: [Name]
- **Action**: [What was done]
- **Result**: [What happened]

---

## Outputs

- `path/to/file` — [description]

---

## Impact

[Significance for future work]

---

## Related

- Daily notes: `memory/YYYY-MM-DD.md`
- Knowledge distillation: `MEMORY.md#[section]`
- Related skill: `skills/[skill-name]/SKILL.md`
```

---

## Index Format

File path: `CHRONICLE.md` (root directory)

```markdown
# Chronicle

## YYYY-MM

### YYYY-MM-DD (Weekday) — Event Name
**Type**: [icon] [type name] | **Priority**: P[0/1/2]

[One-line summary]

**Outcomes**: [key outcomes]
**Details**: -> chronicle/YYYY-MM/YYYY-MM-DD-event-name.md

---
```

---

## Workflow

### Recording Events

```
1. Determine event type and priority (refer to classification table)
2. Create detailed record file (use template)
3. Update CHRONICLE.md overview index
4. If lessons learned -> distill to MEMORY.md
```

### Periodic Maintenance (Heartbeat Task Integration)

| Frequency | Operation |
|-----------|-----------|
| Every heartbeat | Check if P0 events need recording |
| Weekly | Review CHRONICLE.md completeness, fill gaps |
| Monthly | Generate monthly summary, archive expired memory files to chronicle |
| Quarterly | Review classification system, optimize templates |

### Memory Archiving Rules

When logs in memory/ exceed 30 days:
1. Extract important content to corresponding chronicle detailed records
2. Distill lessons learned to MEMORY.md
3. Retain original memory files but mark as archived

---

## Hacker Laws

| Law | Application |
|-----|-------------|
| First Principles | Return to the essence of events when recording, don't pile on details |
| Trust but Verify | Periodically verify chronicle records match reality |
| Free Information Flow | Share experiences and lessons in MEMORY.md, don't hoard |

---

## System Integration

| System | Relationship |
|--------|-------------|
| **MEMORY.md** | Chronicle records events, MEMORY distills knowledge |
| **HEARTBEAT.md** | Heartbeat triggers periodic maintenance and P0 event checks |
| **TOOLS.md** | Tool mastery milestones recorded to chronicle |
| **skills/** | Skill learning completions recorded to chronicle |

---

_Based on CHRONICLE_SYSTEM.md, condensed and rewritten_

## Orchestration

### ECC Loop Pattern
- **Pattern**: Sequential Pipeline (record event → index in chronicle → distill to MEMORY.md)
- **Rationale**: Chronicle follows a strict three-layer progression — raw events are recorded first, then indexed for navigation, then selectively distilled into long-term knowledge
- **Integration**: continuous-learning (feeds knowledge extraction), safety-guard (incident events), HEARTBEAT.md (periodic maintenance triggers), TOOLS.md (tool mastery milestones)

### Cross-Skill Pipeline
```
[any skill event] → chronicle (record) → CHRONICLE.md (index) → MEMORY.md (distill)
                          ↓                                      ↑
                   safety-guard (incidents)          continuous-learning (patterns)
```

### Quality Gate
- Pre-condition: Event meets recording threshold (P0-P2 priority classification)
- Post-condition: Event recorded in chronicle/YYYY-MM/, indexed in CHRONICLE.md, lessons distilled to MEMORY.md if applicable
- Verification: CHRONICLE.md index matches detail files, MEMORY.md reflects distilled knowledge
