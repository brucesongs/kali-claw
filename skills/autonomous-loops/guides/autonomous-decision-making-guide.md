# Autonomous Decision-Making Guide

> Practical patterns for autonomous agent decision-making: decision trees, confidence thresholds, human-in-the-loop triggers, and risk-aware action selection for AI-driven security operations.

## 1. Decision Tree Framework

Structure autonomous decisions as explicit trees with clear criteria at each node.

```python
#!/usr/bin/env python3
"""Decision tree framework for autonomous security operations."""

from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable

class ActionType(Enum):
    EXECUTE = "execute"       # Proceed autonomously
    CONFIRM = "confirm"       # Ask human before proceeding
    ESCALATE = "escalate"     # Hand off to human entirely
    SKIP = "skip"             # Skip this action
    DEFER = "defer"           # Postpone for later

@dataclass(frozen=True)
class Decision:
    action_type: ActionType
    action: str
    confidence: float
    reasoning: str
    risk_level: int  # 1-5, where 5 is highest risk
    reversible: bool

@dataclass(frozen=True)
class Context:
    target_scope: str
    rules_of_engagement: tuple[str, ...]
    time_remaining_seconds: int
    findings_so_far: tuple
    current_phase: str

def decide_action(context: Context, candidate_action: str,
                  confidence: float, risk: int, reversible: bool) -> Decision:
    """Core decision function applying rules of engagement."""

    # Rule 1: Never exceed scope regardless of confidence
    if not is_in_scope(candidate_action, context.target_scope):
        return Decision(
            action_type=ActionType.SKIP,
            action=candidate_action,
            confidence=confidence,
            reasoning="Action outside defined scope",
            risk_level=risk,
            reversible=reversible
        )

    # Rule 2: High-risk irreversible actions always need confirmation
    if risk >= 4 and not reversible:
        return Decision(
            action_type=ActionType.CONFIRM,
            action=candidate_action,
            confidence=confidence,
            reasoning=f"High risk ({risk}/5) and irreversible",
            risk_level=risk,
            reversible=reversible
        )

    # Rule 3: Low confidence triggers escalation
    if confidence < 0.3:
        return Decision(
            action_type=ActionType.ESCALATE,
            action=candidate_action,
            confidence=confidence,
            reasoning=f"Confidence too low ({confidence:.0%})",
            risk_level=risk,
            reversible=reversible
        )

    # Rule 4: Medium confidence + medium risk = confirm
    if confidence < 0.7 and risk >= 3:
        return Decision(
            action_type=ActionType.CONFIRM,
            action=candidate_action,
            confidence=confidence,
            reasoning=f"Moderate confidence ({confidence:.0%}) with elevated risk",
            risk_level=risk,
            reversible=reversible
        )

    # Rule 5: High confidence + low risk = execute
    return Decision(
        action_type=ActionType.EXECUTE,
        action=candidate_action,
        confidence=confidence,
        reasoning=f"High confidence ({confidence:.0%}), acceptable risk ({risk}/5)",
        risk_level=risk,
        reversible=reversible
    )

def is_in_scope(action: str, scope: str) -> bool:
    """Verify action falls within authorized scope."""
    # Implementation depends on scope definition format
    return True  # Placeholder
```

## 2. Confidence Threshold System

```python
from dataclasses import dataclass

@dataclass(frozen=True)
class ConfidenceThresholds:
    """Thresholds that determine autonomous vs. human-assisted decisions."""
    auto_execute: float = 0.85    # Execute without asking
    suggest_and_confirm: float = 0.60  # Suggest, wait for approval
    present_options: float = 0.40  # Show multiple options to human
    escalate: float = 0.20        # Hand off entirely

@dataclass(frozen=True)
class ConfidenceScore:
    value: float
    factors: tuple[tuple[str, float], ...]  # (factor_name, weight)
    evidence: tuple[str, ...]

def calculate_confidence(
    evidence_strength: float,   # 0-1: how strong is the evidence
    prior_success_rate: float,  # 0-1: historical success with similar actions
    tool_reliability: float,    # 0-1: how reliable is the tool being used
    context_clarity: float      # 0-1: how clear is the current situation
) -> ConfidenceScore:
    """Calculate composite confidence from multiple factors."""
    factors = (
        ("evidence_strength", evidence_strength),
        ("prior_success_rate", prior_success_rate),
        ("tool_reliability", tool_reliability),
        ("context_clarity", context_clarity),
    )

    # Weighted combination (evidence and context weighted higher)
    weights = (0.35, 0.20, 0.20, 0.25)
    values = (evidence_strength, prior_success_rate, tool_reliability, context_clarity)
    composite = sum(w * v for w, v in zip(weights, values))

    # Apply penalty for any very low factor (weakest link)
    min_factor = min(values)
    if min_factor < 0.3:
        composite *= 0.7  # 30% penalty for weak link

    return ConfidenceScore(
        value=min(composite, 1.0),
        factors=factors,
        evidence=()
    )
```

## 3. Human-in-the-Loop Triggers

```python
from dataclasses import dataclass
from enum import Enum

class EscalationUrgency(Enum):
    IMMEDIATE = "immediate"   # Stop everything, ask now
    NEXT_PHASE = "next_phase" # Ask before starting next phase
    BATCH = "batch"           # Collect questions, ask in batch
    INFORMATIONAL = "info"    # Notify human, don't block

@dataclass(frozen=True)
class EscalationTrigger:
    condition: str
    urgency: EscalationUrgency
    message: str
    context_data: dict

# Define trigger conditions
ESCALATION_RULES = (
    # Security-critical triggers (IMMEDIATE)
    {
        "condition": "credentials_found",
        "urgency": EscalationUrgency.IMMEDIATE,
        "template": "Found credentials for {service}. Proceed with access attempt?"
    },
    {
        "condition": "production_system_detected",
        "urgency": EscalationUrgency.IMMEDIATE,
        "template": "Target appears to be production ({indicator}). Confirm scope."
    },
    {
        "condition": "destructive_action_needed",
        "urgency": EscalationUrgency.IMMEDIATE,
        "template": "Next step ({action}) may cause service disruption. Approve?"
    },
    # Phase transition triggers (NEXT_PHASE)
    {
        "condition": "recon_complete",
        "urgency": EscalationUrgency.NEXT_PHASE,
        "template": "Recon complete. {n_targets} targets found. Proceed to exploitation?"
    },
    {
        "condition": "new_network_segment",
        "urgency": EscalationUrgency.NEXT_PHASE,
        "template": "Discovered new segment {subnet}. Expand scope?"
    },
    # Informational triggers
    {
        "condition": "vulnerability_confirmed",
        "urgency": EscalationUrgency.INFORMATIONAL,
        "template": "Confirmed {vuln_type} on {target}. Continuing assessment."
    },
)

def check_escalation_triggers(state, action_result) -> list[EscalationTrigger]:
    """Evaluate all triggers against current state."""
    triggered = []
    for rule in ESCALATION_RULES:
        if evaluate_condition(rule["condition"], state, action_result):
            triggered.append(EscalationTrigger(
                condition=rule["condition"],
                urgency=rule["urgency"],
                message=rule["template"],
                context_data={"state": state, "result": action_result}
            ))
    return triggered

def evaluate_condition(condition: str, state, result) -> bool:
    """Check if a specific escalation condition is met."""
    # Implementation maps condition strings to actual checks
    return False  # Placeholder
```

## 4. Risk-Aware Action Selection

```python
from dataclasses import dataclass

@dataclass(frozen=True)
class ActionCandidate:
    name: str
    expected_value: float    # Expected information gain or progress
    risk_score: float        # 0-1, probability of negative outcome
    impact_if_failed: float  # 0-1, severity if something goes wrong
    time_cost_seconds: int
    token_cost: int
    reversible: bool

def risk_adjusted_score(action: ActionCandidate, risk_tolerance: float = 0.5) -> float:
    """Calculate risk-adjusted value for action ranking."""
    # Expected value minus risk penalty
    risk_penalty = action.risk_score * action.impact_if_failed * (1 - risk_tolerance)
    reversibility_bonus = 0.1 if action.reversible else 0.0
    return action.expected_value - risk_penalty + reversibility_bonus

def select_best_action(
    candidates: tuple[ActionCandidate, ...],
    risk_tolerance: float = 0.5,
    max_acceptable_risk: float = 0.8
) -> ActionCandidate | None:
    """Select the best action considering risk constraints."""
    # Filter out actions exceeding risk threshold
    acceptable = tuple(
        a for a in candidates
        if a.risk_score * a.impact_if_failed <= max_acceptable_risk
    )

    if not acceptable:
        return None  # No safe actions available

    # Rank by risk-adjusted score
    return max(acceptable, key=lambda a: risk_adjusted_score(a, risk_tolerance))
```

## 5. Multi-Criteria Decision Matrix

```python
from dataclasses import dataclass

@dataclass(frozen=True)
class ScoredOption:
    name: str
    scores: dict[str, float]  # criterion -> score (0-1)
    weighted_total: float

def weighted_decision_matrix(
    options: tuple[dict, ...],
    criteria_weights: dict[str, float]
) -> tuple[ScoredOption, ...]:
    """Rank options using weighted multi-criteria scoring."""
    scored = []
    for option in options:
        total = sum(
            option["scores"].get(criterion, 0) * weight
            for criterion, weight in criteria_weights.items()
        )
        scored.append(ScoredOption(
            name=option["name"],
            scores=option["scores"],
            weighted_total=total
        ))

    return tuple(sorted(scored, key=lambda s: s.weighted_total, reverse=True))

# Example: choosing between exploitation approaches
criteria = {
    "success_probability": 0.30,
    "stealth": 0.25,
    "information_gain": 0.20,
    "time_efficiency": 0.15,
    "reversibility": 0.10,
}

options = (
    {"name": "sql_injection_union", "scores": {
        "success_probability": 0.9, "stealth": 0.3,
        "information_gain": 0.8, "time_efficiency": 0.7, "reversibility": 1.0}},
    {"name": "blind_sqli_time", "scores": {
        "success_probability": 0.7, "stealth": 0.8,
        "information_gain": 0.5, "time_efficiency": 0.2, "reversibility": 1.0}},
    {"name": "os_command_injection", "scores": {
        "success_probability": 0.5, "stealth": 0.2,
        "information_gain": 0.9, "time_efficiency": 0.6, "reversibility": 0.3}},
)

ranked = weighted_decision_matrix(options, criteria)
for r in ranked:
    print(f"  {r.name}: {r.weighted_total:.3f}")
```

## 6. Autonomous Operation Boundaries

```bash
#!/bin/bash
# Boundary enforcement for autonomous pentest operations

# Define hard boundaries (NEVER cross autonomously)
FORBIDDEN_ACTIONS=(
    "rm -rf"
    "DROP TABLE"
    "DROP DATABASE"
    "format"
    "mkfs"
    "dd if=/dev/zero"
    "shutdown"
    "reboot"
)

# Define scope boundaries
ALLOWED_TARGETS="192.168.1.0/24"
FORBIDDEN_TARGETS="192.168.1.1 192.168.1.2"  # Gateway, DNS
MAX_CONCURRENT_CONNECTIONS=50
MAX_BANDWIDTH_MBPS=10

validate_command() {
    local cmd="$1"

    # Check against forbidden patterns
    for pattern in "${FORBIDDEN_ACTIONS[@]}"; do
        if echo "$cmd" | grep -qi "$pattern"; then
            echo "[BLOCKED] Command matches forbidden pattern: $pattern"
            return 1
        fi
    done

    # Check target scope
    local target_ip=$(echo "$cmd" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    if [ -n "$target_ip" ]; then
        for forbidden in $FORBIDDEN_TARGETS; do
            if [ "$target_ip" = "$forbidden" ]; then
                echo "[BLOCKED] Target $target_ip is out of scope"
                return 1
            fi
        done
    fi

    echo "[ALLOWED] Command passed boundary checks"
    return 0
}

# Usage
validate_command "nmap -sS 192.168.1.50"
validate_command "nmap -sS 192.168.1.1"
validate_command "rm -rf /important/data"
```

## 7. Decision Audit Trail

```python
import json
import time
from dataclasses import dataclass, asdict

@dataclass(frozen=True)
class AuditEntry:
    timestamp: float
    decision_id: str
    action: str
    action_type: str
    confidence: float
    risk_level: int
    reasoning: str
    outcome: str  # "pending", "success", "failure", "skipped"
    context_snapshot: dict

class DecisionAuditLog:
    """Immutable append-only audit log for all autonomous decisions."""

    def __init__(self, log_path: str):
        self._log_path = log_path
        self._entries: tuple[AuditEntry, ...] = ()

    def record(self, decision: 'Decision', context: dict) -> 'DecisionAuditLog':
        """Record a decision (returns new log instance conceptually)."""
        entry = AuditEntry(
            timestamp=time.time(),
            decision_id=f"d-{int(time.time()*1000)}",
            action=decision.action,
            action_type=decision.action_type.value,
            confidence=decision.confidence,
            risk_level=decision.risk_level,
            reasoning=decision.reasoning,
            outcome="pending",
            context_snapshot=context
        )

        # Append to file (append-only, never modify existing entries)
        with open(self._log_path, 'a') as f:
            f.write(json.dumps(asdict(entry)) + '\n')

        self._entries = self._entries + (entry,)
        return self

    def get_decision_stats(self) -> dict:
        """Summarize decision patterns for review."""
        if not self._entries:
            return {}
        total = len(self._entries)
        auto_executed = sum(1 for e in self._entries if e.action_type == "execute")
        escalated = sum(1 for e in self._entries if e.action_type == "escalate")
        avg_confidence = sum(e.confidence for e in self._entries) / total

        return {
            "total_decisions": total,
            "auto_executed_pct": auto_executed / total,
            "escalated_pct": escalated / total,
            "avg_confidence": avg_confidence,
        }
```
