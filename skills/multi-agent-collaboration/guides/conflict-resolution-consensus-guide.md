# Conflict Resolution and Consensus Guide

> Practical reference for resolving disagreements between agents, achieving consensus on findings, and preventing deadlocks in multi-agent security operations. Covers voting mechanisms, priority systems, and deadlock detection.

## 1. Conflict Types in Multi-Agent Systems

Agents can disagree on findings, resource allocation, and action priorities.

```python
from dataclasses import dataclass, field
from typing import List, Dict, FrozenSet
from enum import Enum

class ConflictType(Enum):
    FINDING_DISAGREEMENT = "finding_disagreement"  # Agents disagree on severity/validity
    RESOURCE_CONTENTION = "resource_contention"    # Multiple agents need same resource
    ACTION_CONFLICT = "action_conflict"            # Contradictory recommended actions
    PRIORITY_DISPUTE = "priority_dispute"          # Disagreement on task ordering
    STATE_INCONSISTENCY = "state_inconsistency"    # Shared state divergence

@dataclass(frozen=True)
class Conflict:
    id: str
    type: ConflictType
    agents_involved: FrozenSet[str]
    subject: str  # What the conflict is about
    positions: dict  # agent_id → their position/vote
    timestamp: str
    resolved: bool = False
    resolution: str = ""

@dataclass(frozen=True)
class AgentPosition:
    agent_id: str
    value: str  # The agent's assessment
    confidence: float  # 0.0 to 1.0
    evidence: tuple = ()  # Supporting evidence

# Example: Two scanners disagree on vulnerability severity
conflict = Conflict(
    id="conflict_001",
    type=ConflictType.FINDING_DISAGREEMENT,
    agents_involved=frozenset({"scanner_1", "scanner_2"}),
    subject="SQLi on /api/users — severity classification",
    positions={
        "scanner_1": AgentPosition("scanner_1", "critical", 0.9, ("time-based blind confirmed",)),
        "scanner_2": AgentPosition("scanner_2", "medium", 0.6, ("only error-based, no data extraction",))
    },
    timestamp="2025-03-15T10:30:00Z"
)
```

## 2. Voting Mechanisms

```python
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from collections import Counter

@dataclass(frozen=True)
class Vote:
    agent_id: str
    choice: str
    weight: float = 1.0  # Weighted voting based on expertise
    confidence: float = 1.0

@dataclass
class VotingSystem:
    """Consensus through weighted voting."""
    
    def majority_vote(self, votes: List[Vote]) -> str:
        """Simple majority — most common choice wins."""
        choices = [v.choice for v in votes]
        counter = Counter(choices)
        winner, count = counter.most_common(1)[0]
        
        total = len(votes)
        if count > total / 2:
            return winner
        return "no_consensus"
    
    def weighted_vote(self, votes: List[Vote]) -> str:
        """Weighted voting — expertise and confidence matter."""
        scores: Dict[str, float] = {}
        
        for vote in votes:
            weight = vote.weight * vote.confidence
            scores[vote.choice] = scores.get(vote.choice, 0) + weight
        
        if not scores:
            return "no_consensus"
        
        total_weight = sum(scores.values())
        winner = max(scores, key=scores.get)
        
        # Require >60% of weighted votes for consensus
        if scores[winner] / total_weight > 0.6:
            return winner
        return "no_consensus"
    
    def supermajority_vote(self, votes: List[Vote], threshold: float = 0.67) -> str:
        """Require supermajority (2/3) for critical decisions."""
        choices = [v.choice for v in votes]
        counter = Counter(choices)
        total = len(votes)
        
        for choice, count in counter.most_common():
            if count / total >= threshold:
                return choice
        
        return "no_consensus"

# Usage: Resolve severity disagreement
voting = VotingSystem()
votes = [
    Vote("scanner_1", "critical", weight=1.2, confidence=0.9),  # Specialized scanner
    Vote("scanner_2", "medium", weight=1.0, confidence=0.6),
    Vote("exploiter_1", "critical", weight=1.5, confidence=0.95),  # Confirmed exploitation
]
result = voting.weighted_vote(votes)
print(f"Consensus severity: {result}")  # "critical"
```

## 3. Priority Systems

```python
from dataclasses import dataclass, field
from typing import List, Tuple
import time

@dataclass(frozen=True)
class PriorityRule:
    name: str
    condition: str  # Description of when this rule applies
    priority_boost: int
    
PRIORITY_RULES = (
    PriorityRule("critical_finding", "Finding severity is critical", priority_boost=100),
    PriorityRule("active_exploitation", "Exploit is actively running", priority_boost=80),
    PriorityRule("time_sensitive", "Target has maintenance window", priority_boost=60),
    PriorityRule("dependency_chain", "Many tasks depend on this", priority_boost=40),
    PriorityRule("resource_efficient", "Uses minimal shared resources", priority_boost=20),
)

@dataclass
class PriorityArbiter:
    """Resolve priority disputes between competing tasks."""
    _resource_locks: Dict[str, str] = field(default_factory=dict)  # resource → task_id
    
    def resolve_contention(self, tasks: List[Tuple[str, dict]]) -> List[str]:
        """Order tasks by computed priority when they compete for resources."""
        scored = []
        
        for task_id, task_meta in tasks:
            score = task_meta.get("base_priority", 0)
            
            # Apply priority rules
            if task_meta.get("severity") == "critical":
                score += 100
            if task_meta.get("has_dependents", 0) > 3:
                score += 40
            if task_meta.get("time_constraint"):
                score += 60
            
            # Penalize tasks that have been waiting (fairness)
            wait_time = time.time() - task_meta.get("submitted_at", time.time())
            score += min(wait_time / 60, 30)  # Up to 30 points for waiting
            
            scored.append((task_id, score))
        
        scored.sort(key=lambda x: -x[1])
        return [task_id for task_id, _ in scored]
    
    def acquire_resource(self, resource: str, task_id: str) -> bool:
        """Try to acquire exclusive resource access."""
        if resource in self._resource_locks:
            return False
        self._resource_locks[resource] = task_id
        return True
    
    def release_resource(self, resource: str, task_id: str) -> bool:
        """Release resource lock."""
        if self._resource_locks.get(resource) == task_id:
            del self._resource_locks[resource]
            return True
        return False
```

## 4. Deadlock Prevention

```python
import asyncio
from dataclasses import dataclass, field
from typing import Dict, Set, List, Optional

@dataclass
class DeadlockDetector:
    """Detect and resolve deadlocks in agent resource acquisition."""
    _wait_for_graph: Dict[str, Set[str]] = field(default_factory=lambda: defaultdict(set))
    _resource_holders: Dict[str, str] = field(default_factory=dict)
    _resource_waiters: Dict[str, List[str]] = field(default_factory=lambda: defaultdict(list))
    
    def request_resource(self, agent_id: str, resource: str) -> Optional[str]:
        """Register resource request. Returns deadlock cycle if detected."""
        holder = self._resource_holders.get(resource)
        
        if holder is None:
            # Resource is free
            self._resource_holders[resource] = agent_id
            return None
        
        if holder == agent_id:
            return None  # Already holds it
        
        # Agent must wait — check for deadlock
        self._wait_for_graph[agent_id].add(holder)
        self._resource_waiters[resource].append(agent_id)
        
        cycle = self._detect_cycle(agent_id)
        if cycle:
            # Remove the wait edge to prevent deadlock
            self._wait_for_graph[agent_id].discard(holder)
            self._resource_waiters[resource].remove(agent_id)
            return f"Deadlock detected: {' -> '.join(cycle)}"
        
        return None
    
    def _detect_cycle(self, start: str) -> Optional[List[str]]:
        """DFS cycle detection in wait-for graph."""
        visited = set()
        path = []
        
        def dfs(node: str) -> bool:
            if node in visited:
                cycle_start = path.index(node)
                return True
            visited.add(node)
            path.append(node)
            
            for neighbor in self._wait_for_graph.get(node, set()):
                if neighbor == start and len(path) > 1:
                    path.append(neighbor)
                    return True
                if neighbor not in visited:
                    if dfs(neighbor):
                        return True
            
            path.pop()
            return False
        
        if dfs(start):
            return path
        return None
    
    def resolve_deadlock(self, cycle: List[str]) -> str:
        """Break deadlock by preempting lowest-priority agent."""
        # Find agent with lowest priority in cycle
        victim = min(cycle[:-1], key=lambda a: self._get_priority(a))
        
        # Release all resources held by victim
        resources_released = []
        for resource, holder in list(self._resource_holders.items()):
            if holder == victim:
                del self._resource_holders[resource]
                resources_released.append(resource)
                # Grant to first waiter
                waiters = self._resource_waiters.get(resource, [])
                if waiters:
                    new_holder = waiters.pop(0)
                    self._resource_holders[resource] = new_holder
        
        return f"Preempted {victim}, released: {resources_released}"
    
    def _get_priority(self, agent_id: str) -> int:
        """Get agent priority for victim selection."""
        priorities = {"orchestrator": 100, "exploiter": 80, "scanner": 60, "recon": 40}
        for prefix, priority in priorities.items():
            if agent_id.startswith(prefix):
                return priority
        return 50
```

## 5. Consensus Protocols for Findings

```python
from dataclasses import dataclass, field
from typing import List

@dataclass
class FindingConsensus:
    """Achieve consensus on security findings across multiple agents."""
    required_confirmations: int = 2
    
    def evaluate_finding(self, assessments: List[dict]) -> dict:
        """Determine finding validity from multiple agent assessments."""
        if not assessments:
            return {"status": "insufficient_data", "confidence": 0}
        
        # Count confirmations and rejections
        confirmed = [a for a in assessments if a["verdict"] == "confirmed"]
        rejected = [a for a in assessments if a["verdict"] == "false_positive"]
        uncertain = [a for a in assessments if a["verdict"] == "uncertain"]
        
        total = len(assessments)
        
        if len(confirmed) >= self.required_confirmations:
            # Calculate consensus severity (weighted by confidence)
            severities = {"critical": 4, "high": 3, "medium": 2, "low": 1}
            weighted_severity = sum(
                severities.get(a["severity"], 0) * a["confidence"]
                for a in confirmed
            ) / sum(a["confidence"] for a in confirmed)
            
            # Map back to severity label
            severity_label = "low"
            for label, value in severities.items():
                if weighted_severity >= value - 0.5:
                    severity_label = label
            
            return {
                "status": "confirmed",
                "severity": severity_label,
                "confidence": sum(a["confidence"] for a in confirmed) / len(confirmed),
                "confirmed_by": [a["agent_id"] for a in confirmed]
            }
        
        elif len(rejected) > total / 2:
            return {
                "status": "false_positive",
                "confidence": sum(a["confidence"] for a in rejected) / len(rejected),
                "rejected_by": [a["agent_id"] for a in rejected]
            }
        
        return {
            "status": "needs_review",
            "confidence": 0.5,
            "assessments": assessments
        }

# Usage
consensus = FindingConsensus(required_confirmations=2)
result = consensus.evaluate_finding([
    {"agent_id": "scanner_1", "verdict": "confirmed", "severity": "high", "confidence": 0.85},
    {"agent_id": "exploiter_1", "verdict": "confirmed", "severity": "critical", "confidence": 0.95},
    {"agent_id": "scanner_2", "verdict": "uncertain", "severity": "medium", "confidence": 0.4},
])
print(f"Finding status: {result['status']}, severity: {result.get('severity')}")
```

## 6. Resource Contention Resolution

```python
import asyncio
from dataclasses import dataclass, field
from typing import Dict, List

@dataclass
class ResourceManager:
    """Manage shared resources with fair scheduling."""
    _resources: Dict[str, int] = field(default_factory=dict)  # resource → capacity
    _allocated: Dict[str, Dict[str, int]] = field(default_factory=lambda: defaultdict(lambda: defaultdict(int)))
    _queue: Dict[str, asyncio.Queue] = field(default_factory=lambda: defaultdict(asyncio.Queue))
    
    def register_resource(self, name: str, capacity: int) -> None:
        """Register a shared resource with capacity limit."""
        self._resources[name] = capacity
    
    async def acquire(self, resource: str, agent_id: str, amount: int = 1) -> bool:
        """Acquire resource units. Blocks if unavailable."""
        available = self._resources.get(resource, 0) - sum(self._allocated[resource].values())
        
        if available >= amount:
            self._allocated[resource][agent_id] += amount
            return True
        
        # Queue the request
        future = asyncio.get_event_loop().create_future()
        await self._queue[resource].put((agent_id, amount, future))
        return await future
    
    def release(self, resource: str, agent_id: str, amount: int = 1) -> None:
        """Release resource units and notify waiters."""
        self._allocated[resource][agent_id] -= amount
        if self._allocated[resource][agent_id] <= 0:
            del self._allocated[resource][agent_id]
        
        # Check if queued requests can be satisfied
        asyncio.get_event_loop().create_task(self._process_queue(resource))
    
    async def _process_queue(self, resource: str) -> None:
        """Process waiting requests for a resource."""
        while not self._queue[resource].empty():
            agent_id, amount, future = await self._queue[resource].get()
            available = self._resources[resource] - sum(self._allocated[resource].values())
            if available >= amount:
                self._allocated[resource][agent_id] += amount
                future.set_result(True)
            else:
                await self._queue[resource].put((agent_id, amount, future))
                break

# Setup shared resources
resources = ResourceManager()
resources.register_resource("target_connections", capacity=10)
resources.register_resource("gpu_compute", capacity=2)
resources.register_resource("network_bandwidth_mbps", capacity=100)
```

## 7. Escalation and Override Mechanisms

```yaml
# escalation-policy.yaml
escalation:
  levels:
    - name: automatic
      description: Resolved by voting/priority rules
      timeout: 30s
      
    - name: orchestrator
      description: Orchestrator agent makes final decision
      timeout: 60s
      trigger: automatic_resolution_failed
      
    - name: human
      description: Human operator decides
      timeout: 300s
      trigger: orchestrator_confidence_below_70_percent

  override_rules:
    # Critical findings always escalate
    - condition: "finding.severity == 'critical'"
      action: "require_human_confirmation_before_exploit"
    
    # Resource deadlocks auto-resolve after timeout
    - condition: "deadlock_duration > 60s"
      action: "preempt_lowest_priority_agent"
    
    # Conflicting scan results require re-scan
    - condition: "scanner_disagreement AND confidence_delta > 0.3"
      action: "trigger_rescan_with_different_tool"
```

```python
@dataclass
class EscalationManager:
    """Handle unresolved conflicts through escalation."""
    
    async def escalate(self, conflict: Conflict, level: str) -> dict:
        """Escalate conflict to next resolution level."""
        if level == "orchestrator":
            return await self._orchestrator_decision(conflict)
        elif level == "human":
            return await self._request_human_input(conflict)
        return {"status": "unresolved"}
    
    async def _orchestrator_decision(self, conflict: Conflict) -> dict:
        """Orchestrator makes authoritative decision based on evidence."""
        positions = conflict.positions
        # Prefer position with highest confidence and most evidence
        best = max(
            positions.values(),
            key=lambda p: p.confidence * (1 + len(p.evidence) * 0.1)
        )
        return {"resolution": best.value, "decided_by": "orchestrator", "basis": "highest_confidence"}
    
    async def _request_human_input(self, conflict: Conflict) -> dict:
        """Queue conflict for human review."""
        return {"resolution": "pending_human_review", "conflict_id": conflict.id}
```

## 8. Monitoring Consensus Health

```python
from dataclasses import dataclass, field
from collections import defaultdict
import time

@dataclass
class ConsensusMetrics:
    """Track consensus and conflict resolution health."""
    conflicts_total: int = 0
    conflicts_resolved: int = 0
    conflicts_escalated: int = 0
    avg_resolution_time: float = 0.0
    _resolution_times: list = field(default_factory=list)
    _disagreement_pairs: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    
    def record_conflict(self, conflict: Conflict, resolution_time: float) -> None:
        self.conflicts_total += 1
        self._resolution_times.append(resolution_time)
        self.avg_resolution_time = sum(self._resolution_times) / len(self._resolution_times)
        
        # Track which agent pairs disagree most
        agents = sorted(conflict.agents_involved)
        if len(agents) >= 2:
            pair = f"{agents[0]}:{agents[1]}"
            self._disagreement_pairs[pair] += 1
    
    def health_report(self) -> dict:
        """Generate consensus health report."""
        resolution_rate = self.conflicts_resolved / max(self.conflicts_total, 1)
        return {
            "total_conflicts": self.conflicts_total,
            "resolution_rate": f"{resolution_rate:.1%}",
            "avg_resolution_time_seconds": f"{self.avg_resolution_time:.1f}",
            "escalation_rate": f"{self.conflicts_escalated / max(self.conflicts_total, 1):.1%}",
            "frequent_disagreements": dict(
                sorted(self._disagreement_pairs.items(), key=lambda x: -x[1])[:5]
            )
        }

metrics = ConsensusMetrics()
```
