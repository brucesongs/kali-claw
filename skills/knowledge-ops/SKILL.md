# Knowledge Operations (knowledge-ops)

## Skill Identity

| Attribute | Value |
|-----------|-------|
| Domain | Knowledge Operations |
| Skill ID | knowledge-ops |
| Version | 1.0.0 |
| Hacker Laws | Law 3 (Intelligence Over Force), Law 8 (Learn from Every Operation), Law 9 (Systematic Over Random) |
| Related Skills | codebase-onboarding, deep-research, social-intelligence |

## Purpose

Build and maintain structured, persistent knowledge graphs across sessions. Knowledge-ops transforms ephemeral session findings into reusable intelligence — connecting entities, tracking confidence over time, and enabling recall across engagements.

Without knowledge-ops, every session starts from zero. With it, each session builds on the last.

## Core Concepts

### Knowledge Unit

The atomic element of the knowledge graph. Each unit contains:

```json
{
  "id": "KU-2026-05-001",
  "type": "finding | entity | relationship | pattern | hypothesis",
  "created": "2026-05-11",
  "updated": "2026-05-11",
  "confidence": 78,
  "tags": ["auth", "JWT", "CVE"],
  "content": "The auth service uses HS256 with a static secret in config.go:45",
  "source": "codebase-onboarding:auth-service",
  "linked_to": ["KU-2026-04-012", "KU-2026-05-003"],
  "expires": null
}
```

### Knowledge Graph

A network of linked knowledge units. Relationships between units reveal:
- Attack chains (A → B → C = full exploit path)
- Pattern recurrence (same vuln type across multiple targets)
- Confidence evolution (a finding confirmed 3 times = higher confidence)

### Knowledge Base

A collection of knowledge graphs organized by domain (target, technology, vulnerability type). Stored in the `memory/` directory as markdown files with structured frontmatter.

## Knowledge Types

| Type | Description | Example |
|------|-------------|---------|
| `entity` | A person, system, domain, IP, org | `target.com`, `admin@target.com`, `192.168.1.1` |
| `finding` | A discovered fact about a target | SQL injection in search endpoint |
| `relationship` | Link between two entities | User X administers System Y |
| `pattern` | Recurring vulnerability or behavior | This org consistently uses outdated JWT libs |
| `hypothesis` | Unconfirmed, needs validation | Admin portal may be accessible via VPN bypass |
| `intelligence` | Aggregated, analyzed insight | Target org has poor patch management practices |

## Methodology

### Phase 1: Capture

Extract knowledge units from session outputs:

- After codebase-onboarding: capture architecture map, security surfaces, confidence scores
- After deep-research: capture key findings, IOCs, CVEs, linked entities
- After social-intelligence: capture sentiment, key actors, timeline events
- After an exploitation attempt: capture what worked, what failed, and why

### Phase 2: Structure

Assign type, tags, confidence, and links to each unit. Establish relationships between related units.

### Phase 3: Store

Write structured units to the appropriate memory file. Follow the naming convention: `memory/YYYY-MM-DD-[topic].md`.

### Phase 4: Retrieve

At session start, query the knowledge base for relevant units. Use tags, entity names, and linked IDs to surface prior context.

### Phase 5: Maintain

Update confidence scores as findings are confirmed or refuted. Mark expired intelligence. Remove stale hypotheses that were disproven.

## Confidence Model

Confidence scores represent certainty about a knowledge unit:

| Score | Meaning | Action |
|-------|---------|--------|
| 0–25 | Speculation — no evidence | Label as hypothesis |
| 26–50 | Unconfirmed — single source | Needs validation |
| 51–75 | Probable — multiple consistent signals | Use with caution |
| 76–90 | High confidence — independently confirmed | Act on it |
| 91–100 | Verified — demonstrated/exploited | Treat as fact |

Confidence is **not static**. Update it when:
- A second source confirms a finding (+15 to +25)
- An attempt fails that should have worked (-10 to -30)
- A CVE is confirmed to affect the target (+20)
- A hypothesis is proven false (set to 0, mark archived)

## Storage Format

### Knowledge File Template

```markdown
---
id: KU-[YYYY]-[MM]-[NNN]
type: [finding|entity|relationship|pattern|hypothesis|intelligence]
target: [target name or scope]
confidence: [0-100]
created: [YYYY-MM-DD]
updated: [YYYY-MM-DD]
tags: [tag1, tag2, tag3]
linked: [KU-ID-1, KU-ID-2]
source: [skill that produced this]
expires: [YYYY-MM-DD or null]
---

## Summary

[One-sentence summary of this knowledge unit]

## Detail

[Full context, evidence, commands used, observed behavior]

## Connections

- **Confirms**: [what this validates]
- **Contradicts**: [what this disproves]
- **Leads to**: [next investigation or action]

## Confidence History

| Date | Score | Reason |
|------|-------|--------|
| [date] | [score] | [why this score] |
```

## Use Cases

1. **Target Intelligence Accumulation**: Track everything learned about a target across multiple sessions
2. **Vulnerability Pattern Tracking**: Recognize when the same weakness appears in different systems
3. **Cross-Engagement Intelligence**: Identify recurring patterns across different targets (org-level behavior)
4. **Pentest Report Preparation**: Aggregate structured findings for final report generation
5. **Knowledge Handoff**: Pass complete context to another session or team member

## Integration

- **Input from**: codebase-onboarding, deep-research, social-intelligence, any skill that produces findings
- **Output to**: article-writing (for reports), MEMORY.md (for distilled summaries)
- **Session startup**: load relevant knowledge units before beginning any task
- **Session end**: capture all new findings into knowledge base before closing

## Hacker Laws Alignment

- **Law 3 (Intelligence Over Force)**: Accumulated knowledge makes every subsequent session more effective
- **Law 8 (Learn from Every Operation)**: Systematically capturing what worked and what failed
- **Law 9 (Systematic Over Random)**: Structured knowledge graph beats random memory
