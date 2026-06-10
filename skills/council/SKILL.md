---
name: council
description: "Council provides a structured framework for analyzing security questions from multiple adversarial and defensive perspectives simultaneously."
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
  domain: analysis
  tool_count: 5
  guide_count: 5
---




# Council (council)

## Summary

Multi-perspective security analysis providing Attack, Defense, and Audit viewpoints for complex security decisions.

**Tools**: Impact 5 (Critical), Impact 4 (Major), Impact 3 (Moderate), Impact 2 (Minor), Impact 1 (Negligible)

**Domain**: analysis

## Skill Identity

| Attribute | Value |
|-----------|-------|
| Domain | Council — Multi-Perspective Security Analysis |
| Skill ID | council |
| Version | 1.0.0 |
| Hacker Laws | Law 2 (Divergent Thinking), Law 8 (Trust but Verify), Law 1 (First Principles), Law 6 (Assume Breach) |
| Related Skills | deep-research, verification-loop, knowledge-ops, article-writing |

## Purpose

Multi-perspective security analysis providing Attack, Defense, and Audit viewpoints for complex security decisions. Council is a structured debate framework with dissent encouragement, bias mitigation, and consensus building — ensuring that no single perspective dominates critical security judgments.

Without council, analysis suffers from tunnel vision. With it, every decision is stress-tested from three fundamentally different mindsets before action is taken.

## Description

Council provides a structured framework for analyzing security questions from multiple adversarial and defensive perspectives simultaneously. Rather than approaching a problem with a single mindset, council forces explicit generation of attacker, defender, and auditor viewpoints — then cross-validates them to produce balanced, evidence-based decisions.

The skill actively encourages dissent, surfaces hidden biases, and prevents groupthink by requiring each perspective to independently argue its position before synthesis occurs.

## Use Cases

1. **Architecture Security Review** — Evaluate system design decisions (microservices decomposition, authentication flows, data partitioning) from attack, defense, and compliance angles simultaneously
2. **Attack Planning (Red Team)** — Stress-test attack strategies by having each path analyzed for feasibility, detection likelihood, and defensive countermeasures before execution
3. **Defense Strategy Design** — Build layered defenses by understanding attacker motivation and technique, then validating coverage against compliance requirements
4. **Incident Response Decision** — Make rapid, balanced decisions during active incidents by considering containment (defender), evidence preservation (auditor), and adversary behavior (attacker)
5. **Vulnerability Risk Assessment** — Rank and prioritize vulnerabilities using a three-dimensional risk framework instead of single-score severity ratings

## Core Analysis Perspectives

### Attacker Perspective (Exploit-First)

Think like the adversary. Approach every system with adversarial intent:

- What is the fastest path to compromise?
- Which controls can be bypassed, and how?
- What assumptions does the system make that can be exploited?
- How would chaining multiple low-severity findings create high-severity impact?
- What is the blast radius of a successful exploit?

**Mindset**: "If I wanted to break this, where would I start? What would I chain together?"

### Defender Perspective (Hardening-First)

Think like the security engineer. Approach every system with risk reduction in mind:

- What is the minimum attack surface achievable?
- Which controls provide the highest return on investment?
- How can detection and response capabilities be improved?
- What is the blast radius if a control fails?
- How does defense in depth apply to this specific scenario?

**Mindset**: "If I had to defend this against a determined adversary, where would I invest first?"

### Auditor Perspective (Compliance-First)

Think like the assessor. Approach every system with evidence and standards in mind:

- What regulatory and framework requirements apply?
- Is there sufficient evidence to demonstrate compliance?
- Where are the gaps between policy and implementation?
- What would an assessor flag as a finding?
- Are risk acceptance decisions documented and justified?

**Mindset**: "If I were auditing this tomorrow, what would I need to see, and what would I flag?"

## Methodology

### Phase 1: Scope Definition

Define the security question, boundaries, and constraints:

- What specific decision needs to be made?
- What systems, data, and processes are in scope?
- What are the time and resource constraints?
- What compliance or regulatory requirements apply?

### Phase 2: Perspective Generation

Generate independent analyses from each of the three perspectives. Each perspective must:

- State its assumptions explicitly
- Identify the top risks and opportunities from its viewpoint
- Provide evidence-based reasoning, not opinion
- Highlight areas of uncertainty

### Phase 3: Cross-Validation

Test each perspective against the others:

- Does the attacker analysis reveal blind spots in the defense?
- Does the defense adequately address the attacker's identified paths?
- Does the audit perspective uncover gaps in both attack and defense reasoning?
- Are there areas of agreement that indicate strong confidence?

### Phase 4: Consensus Building

Synthesize findings into a unified recommendation:

- Document agreement points across perspectives
- Document disagreement points with reasoning from each side
- Identify open questions requiring further investigation
- Assign confidence levels to each recommendation

### Phase 5: Decision Output

Produce a structured decision document with clear attribution:

- Recommended action with supporting evidence
- Dissenting views and their reasoning
- Risk acceptance decisions with justification
- Follow-up actions and verification criteria

### Flow Diagram

```
+-------------------+
| Scope Definition  |
| (question, bounds)|
+--------+----------+
         |
         v
+--------+----------+     +--------+----------+     +--------+----------+
|   Attacker View   |     |   Defender View   |     |   Auditor View    |
| (exploit-first)   |     | (hardening-first) |     | (compliance-first)|
+--------+----------+     +--------+----------+     +--------+----------+
         |                         |                         |
         v                         v                         v
    Attack paths             Control gaps              Compliance gaps
    Exploit chains           Detection holes           Evidence gaps
    Impact assessment        Hardening priorities      Remediation tracking
         |                         |                         |
         +------------+------------+------------+------------+
                      |
                      v
            +---------+----------+
            | Cross-Validation   |
            | (stress-test each  |
            |  view against      |
            |  the others)       |
            +---------+----------+
                      |
                      v
            +---------+----------+
            | Consensus Building |
            | (agree/disagree/   |
            |  open questions)   |
            +---------+----------+
                      |
                      v
            +---------+----------+
            | Decision Output    |
            | (recommendation,   |
            |  dissent, actions) |
            +--------------------+
```

## Decision Matrix

### Impact x Likelihood Framework

| | Likelihood 1 (Rare) | Likelihood 2 (Unlikely) | Likelihood 3 (Possible) | Likelihood 4 (Likely) | Likelihood 5 (Certain) |
|---|---|---|---|---|---|
| **Impact 5 (Critical)** | Medium (5) | High (10) | Critical (15) | Critical (20) | Critical (25) |
| **Impact 4 (Major)** | Low (4) | Medium (8) | High (12) | Critical (16) | Critical (20) |
| **Impact 3 (Moderate)** | Low (3) | Medium (6) | Medium (9) | High (12) | High (15) |
| **Impact 2 (Minor)** | Info (2) | Low (4) | Low (6) | Medium (8) | Medium (10) |
| **Impact 1 (Negligible)** | Info (1) | Info (2) | Low (3) | Low (4) | Low (5) |

### Severity Classification

| Severity | Score Range | Action Required |
|----------|-------------|-----------------|
| Critical | 15-25 | Immediate action, escalate to leadership |
| High | 10-14 | Priority fix within current sprint |
| Medium | 5-9 | Schedule fix in upcoming sprint |
| Low | 3-4 | Add to backlog, fix when convenient |
| Info | 1-2 | Document, no action required |

## Defense Perspective

Council helps defenders think like attackers and attackers think like defenders:

- **Defender to Attacker**: Forces defenders to consider "how would I actually break this?" instead of only checking control boxes. Reveals which controls look good on paper but fail in practice.
- **Attacker to Defender**: Forces attackers to consider "what would actually stop me?" instead of only finding paths in. Reveals which mitigations are genuinely effective versus theater.
- **Both to Auditor**: Ensures that analysis is not just technically sound but also defensible, documented, and compliant with relevant standards.

## Practical Steps

### 1. Web Application Security Review

Scope: e-commerce platform with payment flow, user authentication, and admin panel.

- **Attacker**: Map attack surface (login, payment API, admin, upload), identify injection points, construct exploit chains (XSS to CSRF to account takeover)
- **Defender**: Review WAF rules, session management, input validation coverage, logging completeness, incident response readiness
- **Auditor**: Map PCI-DSS requirements to controls, verify evidence for each requirement, identify gaps in compliance documentation

### 2. Cloud Architecture Assessment

Scope: multi-cloud deployment with Kubernetes clusters, managed databases, and serverless functions.

- **Attacker**: Enumerate cloud resources, test IAM permission boundaries, identify cross-service trust relationships, assess metadata service exposure
- **Defender**: Review network segmentation, IAM least privilege, encryption at rest and in transit, logging and monitoring coverage, backup and recovery procedures
- **Auditor**: Map controls to CIS benchmarks, verify security group rules, review access logs for anomalies, check certificate rotation policies

### 3. Mobile Application Evaluation

Scope: fintech mobile app with biometric authentication, API communication, and local data storage.

- **Attacker**: Reverse-engineer APK/IPA, analyze certificate pinning, test biometric bypass via Frida, assess API authentication flows
- **Defender**: Verify secure storage (Keychain/Keystore), review certificate pinning implementation, test jailbreak/root detection, assess data leakage in logs
- **Auditor**: Map to OWASP Mobile Top 10, verify PCI compliance for payment features, review privacy policy alignment with actual data handling

### 4. Incident Response Decision

Scope: active breach with lateral movement detected on internal network.

- **Attacker**: Analyze attacker behavior to predict next moves, identify likely objectives and remaining targets
- **Defender**: Recommend containment actions, prioritize evidence preservation, assess detection gaps
- **Auditor**: Ensure chain of custody for evidence, document timeline, verify regulatory notification requirements

## Hacker Laws Alignment

- **Law 2 (Divergent Thinking First)**: Council generates multiple perspectives before converging — ensuring no single viewpoint dominates
- **Law 8 (Trust but Verify)**: Cross-validation phase stress-tests every perspective against the others
- **Law 1 (First Principles)**: Each perspective reasons from fundamentals rather than relying on assumptions from a single angle
- **Law 6 (Assume Breach)**: The attacker perspective explicitly models the system under the assumption that compromise has occurred or will occur

## Orchestration

### Pattern: Sequential Pipeline

Each perspective is analyzed sequentially, then synthesized into a unified recommendation.

```
FOR EACH perspective IN [attacker, defender, auditor]:
    analysis = generate_perspective(scope, perspective)
    evidence = gather_evidence(analysis.claims)
    log_findings(perspective, analysis, evidence)

synthesis = cross_validate([attacker_analysis, defender_analysis, auditor_analysis])
consensus = build_consensus(synthesis)
decision = produce_decision(consensus)
persist_decision(decision)  # via knowledge-ops
```

### Rationale

Multi-perspective analysis requires independent viewpoints before synthesis. Generating perspectives sequentially ensures each is formed without contamination from the others. Cross-validation and consensus building happen only after all three perspectives are complete.

### Integration

| Skill | Role | Trigger |
|-------|------|---------|
| deep-research | Evidence gathering for perspective claims | During Phase 2 (Perspective Generation) |
| verification-loop | Finding validation across perspectives | During Phase 3 (Cross-Validation) |
| knowledge-ops | Decision persistence and retrieval | During Phase 5 (Decision Output) |
| article-writing | Decision document generation | After Phase 5, for formal reporting |

### Cross-Skill Pipeline

```
deep-research → council → verification-loop → article-writing
(gather          (analyze     (validate          (produce
 context)        from 3       findings)          decision
                 views)                           document)
```

### Quality Gate

**Pre-condition**: Sufficient context has been gathered (via deep-research or direct input). The scope definition is clear with explicit boundaries.

**Post-condition**: All three perspectives (Attacker, Defender, Auditor) have been addressed with evidence-based reasoning. Agreement and disagreement points are documented. A recommendation with confidence level is produced.

**Verification**: No single perspective dominates the final recommendation. Dissenting views are explicitly documented. Open questions are identified for follow-up.

## Learning Resources

- **NIST Risk Management Framework (SP 800-37)** — Structured approach to risk assessment and authorization
- **OWASP Threat Modeling Guide** — Systematic threat identification methodology
- **SANS Reading Room** — Research papers on security decision-making and incident response
- **FAIR (Factor Analysis of Information Risk)** — Quantitative risk analysis framework
- **STRIDE/DREAD** — Microsoft threat classification and risk ranking methodologies
- **MITRE ATT&CK Framework** — Adversary behavior modeling for attacker perspective analysis

> Detailed analysis templates in `payloads.md`, test scenarios in `test-cases.md`, deep-dive guides in `guides/`.
