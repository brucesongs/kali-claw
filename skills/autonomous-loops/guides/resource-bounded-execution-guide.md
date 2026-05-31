# Resource-Bounded Execution Guide

> Practical patterns for managing token budgets, execution timeouts, graceful degradation, and cost control in autonomous AI-driven security operations.

## 1. Token Budget Management

Control LLM token consumption to prevent runaway costs while maintaining operation quality.

```python
#!/usr/bin/env python3
"""Token budget tracker with allocation and enforcement."""

from dataclasses import dataclass, field
from typing import Any

@dataclass(frozen=True)
class TokenBudget:
    total_limit: int
    consumed: int = 0
    reserved: int = 0  # Tokens reserved for final summary/reporting
    phase_allocations: tuple[tuple[str, int], ...] = field(default_factory=tuple)

    @property
    def remaining(self) -> int:
        return self.total_limit - self.consumed - self.reserved

    @property
    def utilization(self) -> float:
        return self.consumed / max(self.total_limit, 1)

    def can_afford(self, estimated_cost: int) -> bool:
        return estimated_cost <= self.remaining

    def spend(self, amount: int, phase: str = "default") -> 'TokenBudget':
        """Return new budget with tokens spent (immutable)."""
        new_consumed = self.consumed + amount
        new_allocations = self.phase_allocations + ((phase, amount),)
        return TokenBudget(
            total_limit=self.total_limit,
            consumed=new_consumed,
            reserved=self.reserved,
            phase_allocations=new_allocations
        )

def create_phased_budget(total: int, phases: dict[str, float]) -> dict[str, int]:
    """Allocate budget across phases by percentage."""
    # Example: {"recon": 0.3, "exploit": 0.4, "report": 0.2, "reserve": 0.1}
    allocations = {}
    for phase, pct in phases.items():
        allocations[phase] = int(total * pct)
    return allocations

# Usage
budget = TokenBudget(total_limit=100000, reserved=5000)
phases = create_phased_budget(100000, {
    "reconnaissance": 0.30,
    "exploitation": 0.40,
    "reporting": 0.20,
    "emergency_reserve": 0.10
})
print(f"Recon budget: {phases['reconnaissance']} tokens")
print(f"Remaining: {budget.remaining} tokens")
```

## 2. Timeout Management with Cascading Deadlines

```python
import signal
import time
from dataclasses import dataclass
from contextlib import contextmanager

@dataclass(frozen=True)
class TimeoutConfig:
    total_operation_seconds: int = 300
    phase_timeout_seconds: int = 60
    tool_call_timeout_seconds: int = 30
    grace_period_seconds: int = 10

class TimeoutError(Exception):
    pass

@contextmanager
def cascading_timeout(config: TimeoutConfig):
    """Manage nested timeouts with graceful shutdown."""
    start = time.time()

    def check_budget():
        elapsed = time.time() - start
        remaining = config.total_operation_seconds - elapsed
        if remaining <= 0:
            raise TimeoutError(f"Total operation timeout ({config.total_operation_seconds}s)")
        if remaining <= config.grace_period_seconds:
            raise TimeoutError(f"Entering grace period ({remaining:.1f}s left)")
        return remaining

    yield check_budget

@contextmanager
def tool_timeout(seconds: int):
    """Timeout wrapper for individual tool calls."""
    def handler(signum, frame):
        raise TimeoutError(f"Tool call exceeded {seconds}s timeout")

    old_handler = signal.signal(signal.SIGALRM, handler)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)

# Usage pattern
config = TimeoutConfig(total_operation_seconds=300, tool_call_timeout_seconds=30)

with cascading_timeout(config) as check:
    remaining = check()
    print(f"Time remaining: {remaining:.1f}s")

    with tool_timeout(config.tool_call_timeout_seconds):
        # Execute tool call with individual timeout
        time.sleep(1)  # Simulated work
```

## 3. Graceful Degradation Strategies

```python
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Any

class QualityLevel(Enum):
    FULL = "full"           # Complete analysis, all checks
    STANDARD = "standard"   # Normal operation, skip optional steps
    REDUCED = "reduced"     # Core functionality only
    MINIMAL = "minimal"     # Bare minimum, emergency mode

@dataclass(frozen=True)
class DegradationState:
    quality_level: QualityLevel
    reason: str
    skipped_steps: tuple[str, ...]
    budget_remaining_pct: float

def determine_quality_level(budget_remaining_pct: float,
                           time_remaining_pct: float,
                           error_rate: float) -> QualityLevel:
    """Select quality level based on resource pressure."""
    # Worst constraint determines level
    min_resource = min(budget_remaining_pct, time_remaining_pct)

    if error_rate > 0.5:
        return QualityLevel.MINIMAL
    elif min_resource > 0.6:
        return QualityLevel.FULL
    elif min_resource > 0.3:
        return QualityLevel.STANDARD
    elif min_resource > 0.1:
        return QualityLevel.REDUCED
    else:
        return QualityLevel.MINIMAL

def execute_with_degradation(
    steps: dict[QualityLevel, list[Callable]],
    quality: QualityLevel
) -> list[Any]:
    """Execute only the steps appropriate for current quality level."""
    # Quality levels are cumulative: FULL includes all lower levels
    level_order = [QualityLevel.MINIMAL, QualityLevel.REDUCED,
                   QualityLevel.STANDARD, QualityLevel.FULL]
    active_levels = level_order[:level_order.index(quality) + 1]

    results = []
    for level in active_levels:
        for step in steps.get(level, []):
            results.append(step())
    return results
```

## 4. Cost Control and Rate Limiting

```python
import time
from dataclasses import dataclass

@dataclass(frozen=True)
class CostTracker:
    total_spent_usd: float = 0.0
    budget_limit_usd: float = 10.0
    api_calls_made: int = 0
    api_calls_limit: int = 1000
    last_call_timestamp: float = 0.0
    min_interval_seconds: float = 0.1  # Rate limit

    @property
    def budget_remaining_usd(self) -> float:
        return self.budget_limit_usd - self.total_spent_usd

    @property
    def calls_remaining(self) -> int:
        return self.api_calls_limit - self.api_calls_made

    def can_proceed(self) -> bool:
        return (self.budget_remaining_usd > 0 and
                self.calls_remaining > 0)

    def record_call(self, cost_usd: float) -> 'CostTracker':
        """Return new tracker with call recorded (immutable)."""
        return CostTracker(
            total_spent_usd=self.total_spent_usd + cost_usd,
            budget_limit_usd=self.budget_limit_usd,
            api_calls_made=self.api_calls_made + 1,
            api_calls_limit=self.api_calls_limit,
            last_call_timestamp=time.time(),
            min_interval_seconds=self.min_interval_seconds
        )

    def wait_for_rate_limit(self):
        """Block until rate limit allows next call."""
        elapsed = time.time() - self.last_call_timestamp
        if elapsed < self.min_interval_seconds:
            time.sleep(self.min_interval_seconds - elapsed)

# Model cost estimation
TOKEN_COSTS = {
    "claude-sonnet-4-6": {"input": 3.0 / 1_000_000, "output": 15.0 / 1_000_000},
    "claude-haiku-4-5": {"input": 0.80 / 1_000_000, "output": 4.0 / 1_000_000},
    "claude-opus-4-5": {"input": 15.0 / 1_000_000, "output": 75.0 / 1_000_000},
}

def estimate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    """Estimate API call cost before making it."""
    costs = TOKEN_COSTS.get(model, TOKEN_COSTS["claude-sonnet-4-6"])
    return (input_tokens * costs["input"]) + (output_tokens * costs["output"])
```

## 5. Resource-Aware Task Scheduling

```python
from dataclasses import dataclass
from typing import Callable

@dataclass(frozen=True)
class Task:
    name: str
    priority: int  # 1=critical, 5=optional
    estimated_tokens: int
    estimated_seconds: int
    min_quality: str  # Minimum quality level needed

@dataclass(frozen=True)
class ResourceState:
    tokens_remaining: int
    seconds_remaining: int
    quality_level: str

def schedule_tasks(tasks: tuple[Task, ...], resources: ResourceState) -> tuple[Task, ...]:
    """Schedule tasks that fit within remaining resources, by priority."""
    # Sort by priority (lower number = higher priority)
    sorted_tasks = sorted(tasks, key=lambda t: t.priority)

    scheduled = []
    tokens_left = resources.tokens_remaining
    time_left = resources.seconds_remaining

    quality_order = ["minimal", "reduced", "standard", "full"]
    current_quality_idx = quality_order.index(resources.quality_level)

    for task in sorted_tasks:
        task_quality_idx = quality_order.index(task.min_quality)

        # Skip tasks that require higher quality than available
        if task_quality_idx > current_quality_idx:
            continue

        # Check resource fit
        if (task.estimated_tokens <= tokens_left and
            task.estimated_seconds <= time_left):
            scheduled.append(task)
            tokens_left -= task.estimated_tokens
            time_left -= task.estimated_seconds

    return tuple(scheduled)
```

## 6. Bounded Execution Wrapper

```bash
#!/bin/bash
# Resource-bounded execution wrapper for pentest tools

MAX_TIME="${1:-300}"      # Max seconds (default 5 min)
MAX_MEMORY="${2:-512}"    # Max memory MB
MAX_OUTPUT="${3:-10000}"  # Max output lines
TOOL_CMD="${@:4}"

OUTPUT_FILE="/tmp/bounded_exec_$$"
LINES_CAPTURED=0

echo "[BOUNDED] Running: $TOOL_CMD"
echo "[BOUNDED] Limits: time=${MAX_TIME}s, mem=${MAX_MEMORY}MB, output=${MAX_OUTPUT} lines"

# Set resource limits and execute
timeout --signal=TERM --kill-after=10 "$MAX_TIME" \
  bash -c "ulimit -v $((MAX_MEMORY * 1024)); $TOOL_CMD" \
  2>&1 | head -n "$MAX_OUTPUT" > "$OUTPUT_FILE"

EXIT_CODE=$?
LINES_CAPTURED=$(wc -l < "$OUTPUT_FILE")

# Report execution status
if [ $EXIT_CODE -eq 124 ]; then
    echo "[BOUNDED] TIMEOUT: Command exceeded ${MAX_TIME}s limit"
elif [ $EXIT_CODE -ne 0 ]; then
    echo "[BOUNDED] ERROR: Exit code $EXIT_CODE"
else
    echo "[BOUNDED] SUCCESS: Completed within limits"
fi

echo "[BOUNDED] Output: $LINES_CAPTURED lines captured"
cat "$OUTPUT_FILE"
rm -f "$OUTPUT_FILE"
exit $EXIT_CODE
```

## 7. Progressive Depth Control

```python
from dataclasses import dataclass

@dataclass(frozen=True)
class DepthConfig:
    max_depth: int = 5
    tokens_per_depth: tuple[int, ...] = (5000, 10000, 15000, 20000, 25000)
    time_per_depth: tuple[int, ...] = (30, 60, 90, 120, 180)

@dataclass(frozen=True)
class DepthState:
    current_depth: int
    findings_at_depth: int
    total_findings: int
    tokens_spent: int
    time_spent: int

def should_go_deeper(state: DepthState, config: DepthConfig,
                     budget_remaining: int) -> bool:
    """Decide whether to increase analysis depth based on ROI."""
    if state.current_depth >= config.max_depth:
        return False

    next_depth = state.current_depth + 1
    if next_depth >= len(config.tokens_per_depth):
        return False

    # Check if we can afford the next depth
    next_cost = config.tokens_per_depth[next_depth]
    if next_cost > budget_remaining:
        return False

    # ROI check: are we still finding things?
    if state.current_depth > 0 and state.findings_at_depth == 0:
        return False  # Last depth found nothing, stop

    # Diminishing returns: findings per token spent
    if state.tokens_spent > 0:
        roi = state.total_findings / state.tokens_spent
        projected_roi = roi * 0.5  # Assume 50% decay per depth
        if projected_roi < 0.001:  # Less than 1 finding per 1000 tokens
            return False

    return True
```

## 8. Emergency Shutdown Protocol

```python
import sys
import signal
from dataclasses import dataclass

@dataclass(frozen=True)
class ShutdownState:
    reason: str
    partial_results: tuple
    resources_consumed: dict
    cleanup_performed: bool

def emergency_shutdown(reason: str, state, results_so_far: list) -> ShutdownState:
    """Perform graceful emergency shutdown preserving partial results."""
    print(f"[EMERGENCY SHUTDOWN] Reason: {reason}", file=sys.stderr)

    # Save partial results
    partial = tuple(results_so_far)

    # Calculate resource consumption
    resources = {
        "tokens_used": state.consumed if hasattr(state, 'consumed') else 0,
        "iterations_completed": state.iteration if hasattr(state, 'iteration') else 0,
        "errors_encountered": state.error_count if hasattr(state, 'error_count') else 0,
    }

    return ShutdownState(
        reason=reason,
        partial_results=partial,
        resources_consumed=resources,
        cleanup_performed=True
    )

def register_shutdown_handlers(state_ref: list, results_ref: list):
    """Register signal handlers for graceful shutdown."""
    def handler(signum, frame):
        state = state_ref[0] if state_ref else None
        shutdown = emergency_shutdown(
            reason=f"Signal {signum} received",
            state=state,
            results_so_far=results_ref
        )
        print(f"Shutdown complete: {len(shutdown.partial_results)} partial results saved")
        sys.exit(128 + signum)

    signal.signal(signal.SIGTERM, handler)
    signal.signal(signal.SIGINT, handler)
```
