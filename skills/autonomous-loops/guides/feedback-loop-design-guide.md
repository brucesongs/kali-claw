# Feedback Loop Design Guide

> Practical patterns for building self-correcting autonomous loops: error recovery strategies, convergence detection, exit conditions, and adaptive retry mechanisms for AI-driven security operations.

## 1. Core Feedback Loop Architecture

A well-designed feedback loop observes results, compares against expectations, and adjusts behavior accordingly. The key is knowing when to retry, when to adapt, and when to stop.

```python
#!/usr/bin/env python3
"""Core feedback loop pattern with convergence detection."""

from dataclasses import dataclass, field
from typing import Callable, Any

@dataclass(frozen=True)
class LoopState:
    iteration: int
    last_result: Any
    error_count: int
    consecutive_successes: int
    history: tuple = field(default_factory=tuple)

@dataclass(frozen=True)
class LoopConfig:
    max_iterations: int = 50
    max_consecutive_errors: int = 3
    convergence_threshold: float = 0.95
    convergence_window: int = 5
    cooldown_base_seconds: float = 1.0
    cooldown_max_seconds: float = 60.0

def run_feedback_loop(
    action: Callable,
    evaluate: Callable,
    adapt: Callable,
    config: LoopConfig = LoopConfig()
) -> LoopState:
    """Execute a self-correcting feedback loop."""
    state = LoopState(iteration=0, last_result=None, error_count=0,
                      consecutive_successes=0)

    while state.iteration < config.max_iterations:
        try:
            result = action(state)
            score = evaluate(result, state)
            new_history = state.history + (score,)

            if is_converged(new_history, config):
                return LoopState(
                    iteration=state.iteration + 1,
                    last_result=result,
                    error_count=state.error_count,
                    consecutive_successes=state.consecutive_successes + 1,
                    history=new_history
                )

            # Adapt strategy based on feedback
            action = adapt(action, result, score, state)
            state = LoopState(
                iteration=state.iteration + 1,
                last_result=result,
                error_count=state.error_count,
                consecutive_successes=state.consecutive_successes + 1,
                history=new_history
            )

        except Exception as e:
            new_error_count = state.error_count + 1
            if new_error_count >= config.max_consecutive_errors:
                raise RuntimeError(
                    f"Loop failed after {new_error_count} consecutive errors: {e}"
                )
            state = LoopState(
                iteration=state.iteration + 1,
                last_result=None,
                error_count=new_error_count,
                consecutive_successes=0,
                history=state.history
            )

    return state

def is_converged(history: tuple, config: LoopConfig) -> bool:
    """Check if recent scores indicate convergence."""
    if len(history) < config.convergence_window:
        return False
    window = history[-config.convergence_window:]
    return all(s >= config.convergence_threshold for s in window)
```

## 2. Error Recovery with Exponential Backoff

```python
import time
import random
from dataclasses import dataclass

@dataclass(frozen=True)
class RetryState:
    attempt: int
    last_error: str
    strategy: str  # "retry", "fallback", "escalate"
    cooldown: float

def calculate_backoff(attempt: int, base: float = 1.0, max_delay: float = 60.0) -> float:
    """Exponential backoff with jitter to prevent thundering herd."""
    delay = min(base * (2 ** attempt), max_delay)
    jitter = random.uniform(0, delay * 0.3)
    return delay + jitter

def error_recovery_loop(task_fn, max_retries=5, fallback_fn=None):
    """Execute with progressive error recovery strategies."""
    state = RetryState(attempt=0, last_error="", strategy="retry", cooldown=0)

    while state.attempt < max_retries:
        try:
            if state.strategy == "fallback" and fallback_fn:
                return fallback_fn()
            return task_fn()

        except ConnectionError as e:
            # Network errors: retry with backoff
            cooldown = calculate_backoff(state.attempt)
            state = RetryState(
                attempt=state.attempt + 1,
                last_error=str(e),
                strategy="retry",
                cooldown=cooldown
            )
            time.sleep(cooldown)

        except PermissionError as e:
            # Auth errors: escalate immediately, no retry
            state = RetryState(
                attempt=state.attempt + 1,
                last_error=str(e),
                strategy="escalate",
                cooldown=0
            )
            raise

        except TimeoutError as e:
            # Timeout: try fallback after 2 failures
            new_strategy = "fallback" if state.attempt >= 2 else "retry"
            cooldown = calculate_backoff(state.attempt, base=2.0)
            state = RetryState(
                attempt=state.attempt + 1,
                last_error=str(e),
                strategy=new_strategy,
                cooldown=cooldown
            )
            time.sleep(cooldown)

    raise RuntimeError(f"All recovery strategies exhausted: {state.last_error}")
```

## 3. Convergence Detection Patterns

```python
import statistics
from dataclasses import dataclass

@dataclass(frozen=True)
class ConvergenceMetrics:
    is_converged: bool
    trend: str  # "improving", "stable", "degrading", "oscillating"
    rate_of_change: float
    confidence: float

def detect_convergence(scores: list[float], window: int = 5) -> ConvergenceMetrics:
    """Analyze score history to determine if the loop has converged."""
    if len(scores) < window:
        return ConvergenceMetrics(False, "insufficient_data", 0.0, 0.0)

    recent = scores[-window:]
    older = scores[-2*window:-window] if len(scores) >= 2*window else scores[:window]

    recent_mean = statistics.mean(recent)
    recent_stdev = statistics.stdev(recent) if len(recent) > 1 else 0
    older_mean = statistics.mean(older) if older else 0

    # Rate of change between windows
    rate = (recent_mean - older_mean) / max(older_mean, 0.001)

    # Determine trend
    if recent_stdev < 0.02 and recent_mean > 0.9:
        trend = "stable"
        is_converged = True
    elif rate > 0.05:
        trend = "improving"
        is_converged = False
    elif rate < -0.05:
        trend = "degrading"
        is_converged = False
    elif recent_stdev > 0.15:
        trend = "oscillating"
        is_converged = False
    else:
        trend = "stable"
        is_converged = recent_mean > 0.8

    confidence = max(0, 1.0 - recent_stdev) * min(len(scores) / 20, 1.0)

    return ConvergenceMetrics(
        is_converged=is_converged,
        trend=trend,
        rate_of_change=rate,
        confidence=confidence
    )
```

## 4. Exit Condition Framework

```python
from dataclasses import dataclass
from enum import Enum
from typing import Any

class ExitReason(Enum):
    CONVERGED = "converged"
    MAX_ITERATIONS = "max_iterations"
    BUDGET_EXHAUSTED = "budget_exhausted"
    ERROR_THRESHOLD = "error_threshold"
    HUMAN_INTERRUPT = "human_interrupt"
    DIMINISHING_RETURNS = "diminishing_returns"
    OBJECTIVE_MET = "objective_met"

@dataclass(frozen=True)
class ExitDecision:
    should_exit: bool
    reason: ExitReason | None
    message: str
    final_state: Any

def evaluate_exit_conditions(state, config) -> ExitDecision:
    """Evaluate all exit conditions and return decision."""

    # Hard limits (always exit)
    if state.iteration >= config.max_iterations:
        return ExitDecision(True, ExitReason.MAX_ITERATIONS,
            f"Reached max iterations ({config.max_iterations})", state)

    if state.error_count >= config.max_consecutive_errors:
        return ExitDecision(True, ExitReason.ERROR_THRESHOLD,
            f"Too many errors ({state.error_count})", state)

    # Objective met
    if state.last_result and state.last_result.score >= config.target_score:
        return ExitDecision(True, ExitReason.OBJECTIVE_MET,
            f"Target score reached ({state.last_result.score:.2f})", state)

    # Diminishing returns (improvement rate below threshold)
    if len(state.history) >= 10:
        recent_improvement = state.history[-1] - state.history[-10]
        if abs(recent_improvement) < config.min_improvement_rate:
            return ExitDecision(True, ExitReason.DIMINISHING_RETURNS,
                f"Improvement stalled (delta={recent_improvement:.4f})", state)

    return ExitDecision(False, None, "Continue", state)
```

## 5. Adaptive Strategy Selection

```python
from dataclasses import dataclass

@dataclass(frozen=True)
class Strategy:
    name: str
    success_rate: float
    avg_score: float
    times_used: int

def select_strategy(strategies: tuple[Strategy, ...], state) -> Strategy:
    """Select best strategy using Upper Confidence Bound (UCB1)."""
    import math

    total_uses = sum(s.times_used for s in strategies)
    if total_uses == 0:
        return strategies[0]

    def ucb_score(strategy: Strategy) -> float:
        if strategy.times_used == 0:
            return float('inf')  # Explore unused strategies
        exploitation = strategy.avg_score
        exploration = math.sqrt(2 * math.log(total_uses) / strategy.times_used)
        return exploitation + exploration

    return max(strategies, key=ucb_score)
```

## 6. Practical Pentest Feedback Loop

```bash
#!/bin/bash
# Self-correcting port scan with adaptive timing

TARGET="$1"
MAX_RETRIES=3
SCAN_RATE=1000
RESULTS_FILE="/tmp/scan_results_$$"

scan_with_feedback() {
    local rate="$1"
    local retry=0

    while [ $retry -lt $MAX_RETRIES ]; do
        echo "[Attempt $((retry+1))] Scanning at rate $rate packets/sec..."

        nmap -sS -T4 --min-rate "$rate" --max-retries 2 \
            -oG "$RESULTS_FILE" "$TARGET" 2>/tmp/scan_errors

        # Evaluate results
        OPEN_PORTS=$(grep -c "open" "$RESULTS_FILE" 2>/dev/null || echo 0)
        FILTERED=$(grep -c "filtered" "$RESULTS_FILE" 2>/dev/null || echo 0)
        ERRORS=$(wc -l < /tmp/scan_errors 2>/dev/null || echo 0)

        # Feedback: adjust based on results
        if [ "$ERRORS" -gt 5 ]; then
            # Too aggressive, reduce rate
            rate=$((rate / 2))
            echo "[ADAPT] Reducing rate to $rate (errors detected)"
            retry=$((retry + 1))
        elif [ "$FILTERED" -gt "$OPEN_PORTS" ] && [ "$OPEN_PORTS" -lt 3 ]; then
            # Firewall detected, switch to stealth
            echo "[ADAPT] Firewall detected, switching to stealth scan"
            nmap -sS -T2 --scan-delay 500ms -f "$TARGET" -oG "$RESULTS_FILE"
            break
        else
            echo "[CONVERGED] Found $OPEN_PORTS open ports"
            break
        fi
    done

    cat "$RESULTS_FILE"
    rm -f "$RESULTS_FILE" /tmp/scan_errors
}

scan_with_feedback "$SCAN_RATE"
```

## 7. Loop Health Monitoring

```python
from dataclasses import dataclass
import time

@dataclass(frozen=True)
class HealthMetrics:
    iterations_per_second: float
    error_rate: float
    memory_usage_mb: float
    is_healthy: bool
    warnings: tuple[str, ...]

def monitor_loop_health(state, start_time: float) -> HealthMetrics:
    """Monitor loop performance and resource usage."""
    import resource

    elapsed = time.time() - start_time
    iterations_per_sec = state.iteration / max(elapsed, 0.001)
    error_rate = state.error_count / max(state.iteration, 1)
    memory_mb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024

    warnings = []
    if iterations_per_sec < 0.1:
        warnings.append("Loop running very slowly (<0.1 iter/s)")
    if error_rate > 0.5:
        warnings.append(f"High error rate: {error_rate:.0%}")
    if memory_mb > 500:
        warnings.append(f"High memory usage: {memory_mb:.0f}MB")
    if elapsed > 300:
        warnings.append(f"Long running loop: {elapsed:.0f}s")

    return HealthMetrics(
        iterations_per_second=iterations_per_sec,
        error_rate=error_rate,
        memory_usage_mb=memory_mb,
        is_healthy=len(warnings) == 0,
        warnings=tuple(warnings)
    )
```
