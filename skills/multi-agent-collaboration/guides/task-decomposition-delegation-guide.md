# Task Decomposition and Delegation Guide

> Practical reference for splitting complex security tasks into parallelizable subtasks, building dependency graphs, and delegating work across multiple agents. Covers work breakdown strategies, execution scheduling, and result aggregation.

## 1. Task Decomposition Principles

Break complex penetration testing tasks into independent, parallelizable units.

```python
from dataclasses import dataclass, field
from typing import List, FrozenSet, Optional
from enum import Enum
import uuid

class TaskStatus(Enum):
    PENDING = "pending"
    READY = "ready"      # All dependencies met
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"  # Dependency failed

@dataclass(frozen=True)
class Task:
    id: str
    name: str
    agent: str  # Assigned agent
    action: dict  # Task payload
    dependencies: FrozenSet[str] = frozenset()  # Task IDs that must complete first
    priority: int = 0
    timeout_seconds: int = 300
    retries: int = 1

def decompose_pentest(target: str, scope: list) -> List[Task]:
    """Decompose a penetration test into parallelizable tasks."""
    tasks = []
    
    # Phase 1: Reconnaissance (parallel)
    recon_dns = Task(
        id="recon_dns", name="DNS Enumeration",
        agent="recon", action={"tool": "subfinder", "target": target},
        priority=1
    )
    recon_ports = Task(
        id="recon_ports", name="Port Scanning",
        agent="scanner", action={"tool": "nmap", "target": target, "flags": "-sV -sC"},
        priority=1
    )
    recon_web = Task(
        id="recon_web", name="Web Technology Detection",
        agent="recon", action={"tool": "whatweb", "target": target},
        priority=1
    )
    tasks.extend([recon_dns, recon_ports, recon_web])
    
    # Phase 2: Vulnerability scanning (depends on recon)
    vuln_scan = Task(
        id="vuln_scan", name="Vulnerability Scan",
        agent="scanner", action={"tool": "nuclei", "target": target},
        dependencies=frozenset({"recon_ports", "recon_web"}),
        priority=2, timeout_seconds=600
    )
    tasks.append(vuln_scan)
    
    # Phase 3: Exploitation (depends on vuln scan)
    exploit = Task(
        id="exploit", name="Exploit Verification",
        agent="exploiter", action={"findings": "from_vuln_scan"},
        dependencies=frozenset({"vuln_scan"}),
        priority=3
    )
    tasks.append(exploit)
    
    return tasks
```

## 2. Dependency Graph Construction

```python
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import List, Set, Dict

@dataclass
class DependencyGraph:
    """DAG for task execution ordering."""
    _adjacency: Dict[str, Set[str]] = field(default_factory=lambda: defaultdict(set))
    _in_degree: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    _tasks: Dict[str, Task] = field(default_factory=dict)
    
    def add_task(self, task: Task) -> None:
        """Add task and its dependency edges to the graph."""
        self._tasks[task.id] = task
        if task.id not in self._in_degree:
            self._in_degree[task.id] = 0
        
        for dep_id in task.dependencies:
            self._adjacency[dep_id].add(task.id)
            self._in_degree[task.id] += 1
    
    def get_ready_tasks(self, completed: Set[str]) -> List[Task]:
        """Get tasks whose dependencies are all satisfied."""
        ready = []
        for task_id, task in self._tasks.items():
            if task_id in completed:
                continue
            if task.dependencies.issubset(completed):
                ready.append(task)
        return sorted(ready, key=lambda t: -t.priority)
    
    def topological_sort(self) -> List[List[str]]:
        """Return execution layers (tasks in same layer can run in parallel)."""
        in_degree = dict(self._in_degree)
        layers = []
        
        while True:
            layer = [node for node, degree in in_degree.items() if degree == 0]
            if not layer:
                break
            layers.append(layer)
            for node in layer:
                del in_degree[node]
                for neighbor in self._adjacency[node]:
                    if neighbor in in_degree:
                        in_degree[neighbor] -= 1
        
        return layers
    
    def detect_cycles(self) -> List[str]:
        """Detect circular dependencies."""
        visited = set()
        rec_stack = set()
        cycles = []
        
        def dfs(node):
            visited.add(node)
            rec_stack.add(node)
            for neighbor in self._adjacency[node]:
                if neighbor not in visited:
                    if dfs(neighbor):
                        return True
                elif neighbor in rec_stack:
                    cycles.append(f"{node} -> {neighbor}")
                    return True
            rec_stack.discard(node)
            return False
        
        for node in self._tasks:
            if node not in visited:
                dfs(node)
        return cycles

# Build and validate graph
graph = DependencyGraph()
tasks = decompose_pentest("target.com", ["web", "network"])
for task in tasks:
    graph.add_task(task)

layers = graph.topological_sort()
print("Execution plan:")
for i, layer in enumerate(layers):
    print(f"  Layer {i}: {layer} (parallel)")
```

## 3. Parallel Execution Engine

```python
import asyncio
from dataclasses import dataclass, field
from typing import Dict, Set, Callable

@dataclass
class ExecutionEngine:
    """Execute tasks respecting dependencies with max parallelism."""
    max_concurrent: int = 5
    _results: Dict[str, dict] = field(default_factory=dict)
    _completed: Set[str] = field(default_factory=set)
    _failed: Set[str] = field(default_factory=set)
    _semaphore: asyncio.Semaphore = field(default=None)
    
    def __post_init__(self):
        self._semaphore = asyncio.Semaphore(self.max_concurrent)
    
    async def execute_plan(self, graph: DependencyGraph, executor: Callable) -> Dict[str, dict]:
        """Execute all tasks in dependency order with parallelism."""
        pending = set(graph._tasks.keys())
        
        while pending:
            ready = [
                graph._tasks[tid] for tid in pending
                if graph._tasks[tid].dependencies.issubset(self._completed)
                and not graph._tasks[tid].dependencies.intersection(self._failed)
            ]
            
            if not ready:
                blocked = [
                    tid for tid in pending
                    if graph._tasks[tid].dependencies.intersection(self._failed)
                ]
                for tid in blocked:
                    self._failed.add(tid)
                    pending.discard(tid)
                    self._results[tid] = {"status": "blocked", "reason": "dependency_failed"}
                if not ready and pending:
                    break
                continue
            
            results = await asyncio.gather(
                *[self._run_task(task, executor) for task in ready],
                return_exceptions=True
            )
            
            for task, result in zip(ready, results):
                pending.discard(task.id)
                if isinstance(result, Exception):
                    self._failed.add(task.id)
                    self._results[task.id] = {"status": "failed", "error": str(result)}
                else:
                    self._completed.add(task.id)
                    self._results[task.id] = result
        
        return self._results
    
    async def _run_task(self, task: Task, executor: Callable) -> dict:
        """Run single task with semaphore and timeout."""
        async with self._semaphore:
            return await asyncio.wait_for(
                executor(task), timeout=task.timeout_seconds
            )
```

## 4. Work Distribution Strategies

```python
from dataclasses import dataclass, field
from typing import List

@dataclass(frozen=True)
class AgentCapability:
    agent_id: str
    skills: FrozenSet[str]
    max_concurrent: int
    current_load: int = 0

@dataclass
class WorkDistributor:
    """Assign tasks to agents based on capability and load."""
    agents: List[AgentCapability] = field(default_factory=list)
    
    def assign(self, task: Task) -> str:
        """Find best agent for a task using capability matching + load balancing."""
        candidates = []
        
        for agent in self.agents:
            required_skills = frozenset(task.action.get("required_skills", []))
            if required_skills and not required_skills.issubset(agent.skills):
                continue
            if agent.current_load >= agent.max_concurrent:
                continue
            
            skill_match = len(required_skills.intersection(agent.skills))
            load_score = 1.0 - (agent.current_load / agent.max_concurrent)
            score = skill_match * 0.6 + load_score * 0.4
            candidates.append((agent.agent_id, score))
        
        if not candidates:
            raise RuntimeError(f"No available agent for task: {task.name}")
        
        candidates.sort(key=lambda x: -x[1])
        return candidates[0][0]

# Define agent pool
distributor = WorkDistributor(agents=[
    AgentCapability("scanner_1", frozenset({"nmap", "nuclei", "nikto"}), max_concurrent=3),
    AgentCapability("scanner_2", frozenset({"nmap", "nuclei", "masscan"}), max_concurrent=3),
    AgentCapability("exploiter_1", frozenset({"sqlmap", "metasploit"}), max_concurrent=2),
    AgentCapability("recon_1", frozenset({"subfinder", "whatweb", "cewl"}), max_concurrent=5),
])
```

## 5. Result Aggregation

```python
from dataclasses import dataclass, field
from typing import List, Dict

@dataclass(frozen=True)
class TaskResult:
    task_id: str
    agent_id: str
    status: str
    output: dict
    duration_seconds: float

@dataclass
class ResultAggregator:
    """Collect and merge results from parallel task execution."""
    _results: List[TaskResult] = field(default_factory=list)
    
    def add(self, result: TaskResult) -> None:
        self._results.append(result)
    
    def merge_findings(self) -> dict:
        """Merge security findings from all tasks, deduplicating."""
        all_findings = []
        seen_signatures = set()
        
        for result in self._results:
            findings = result.output.get("findings", [])
            for finding in findings:
                sig = f"{finding.get('url')}:{finding.get('type')}:{finding.get('parameter')}"
                if sig not in seen_signatures:
                    seen_signatures.add(sig)
                    all_findings.append({**finding, "discovered_by": result.agent_id})
        
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        all_findings.sort(key=lambda f: severity_order.get(f.get("severity", "info"), 5))
        
        return {
            "total_findings": len(all_findings),
            "by_severity": {
                sev: len([f for f in all_findings if f.get("severity") == sev])
                for sev in severity_order
            },
            "findings": all_findings
        }
```

## 6. Dynamic Task Generation

```python
async def dynamic_decomposition(initial_results: dict, graph: DependencyGraph) -> List[Task]:
    """Generate follow-up tasks based on initial results."""
    new_tasks = []
    findings = initial_results.get("findings", [])
    
    for finding in findings:
        vuln_type = finding.get("type")
        severity = finding.get("severity")
        
        if severity not in ("critical", "high"):
            continue
        
        if vuln_type == "sqli":
            task = Task(
                id=f"exploit_sqli_{uuid.uuid4().hex[:8]}",
                name=f"SQLi Exploitation: {finding['url']}",
                agent="exploiter",
                action={"tool": "sqlmap", "url": finding["url"], "parameter": finding["parameter"]},
                dependencies=frozenset({"vuln_scan"}),
                priority=3
            )
            new_tasks.append(task)
        elif vuln_type == "rce":
            task = Task(
                id=f"exploit_rce_{uuid.uuid4().hex[:8]}",
                name=f"RCE Verification: {finding['url']}",
                agent="exploiter",
                action={"tool": "manual_verify", "url": finding["url"]},
                dependencies=frozenset({"vuln_scan"}),
                priority=4
            )
            new_tasks.append(task)
    
    for task in new_tasks:
        graph.add_task(task)
    return new_tasks
```

## 7. Timeout and Cancellation

```yaml
# Task timeout configuration by type
task_timeouts:
  recon_dns: 120s
  recon_ports: 300s
  vuln_scan: 600s
  exploit_sqli: 180s
  exploit_rce: 60s
  report_gen: 120s

cancellation_policy:
  on_critical_failure: cancel_dependent_tasks
  on_timeout: retry_once_then_skip
  on_agent_disconnect: reassign_to_available_agent
  max_total_duration: 3600s
```

```python
import asyncio
from typing import Set

class TaskCancellation:
    """Handle task cancellation and cleanup."""
    _running_tasks: Dict[str, asyncio.Task] = {}
    
    async def cancel_task(self, task_id: str, reason: str) -> None:
        """Cancel a running task."""
        if task_id in self._running_tasks:
            self._running_tasks[task_id].cancel()
            del self._running_tasks[task_id]
    
    async def cancel_dependents(self, failed_task_id: str, graph: DependencyGraph) -> Set[str]:
        """Cancel all tasks that depend on a failed task."""
        cancelled = set()
        to_cancel = set(graph._adjacency[failed_task_id])
        
        while to_cancel:
            task_id = to_cancel.pop()
            await self.cancel_task(task_id, f"dependency {failed_task_id} failed")
            cancelled.add(task_id)
            to_cancel.update(graph._adjacency[task_id])
        
        return cancelled
```

## 8. Execution Monitoring

```python
import time
from dataclasses import dataclass, field

@dataclass
class ExecutionMonitor:
    """Real-time monitoring of task execution progress."""
    _start_time: float = field(default_factory=time.time)
    _task_states: Dict[str, dict] = field(default_factory=dict)
    
    def update_task(self, task_id: str, status: str, details: str = "") -> None:
        self._task_states[task_id] = {
            "status": status, "details": details, "updated_at": time.time()
        }
    
    def render_progress(self) -> str:
        """Render execution progress as text dashboard."""
        elapsed = time.time() - self._start_time
        total = len(self._task_states)
        completed = sum(1 for t in self._task_states.values() if t["status"] == "completed")
        running = sum(1 for t in self._task_states.values() if t["status"] == "running")
        failed = sum(1 for t in self._task_states.values() if t["status"] == "failed")
        
        lines = [
            f"=== Execution Progress ({elapsed:.0f}s elapsed) ===",
            f"Total: {total} | Done: {completed} | Running: {running} | Failed: {failed}",
            f"Progress: [{'#' * completed}{'.' * (total - completed)}] {completed}/{total}",
        ]
        for task_id, state in self._task_states.items():
            icon = {"completed": "+", "running": "*", "failed": "!", "pending": " "}
            lines.append(f"  [{icon.get(state['status'], '?')}] {task_id}: {state['status']}")
        
        return "\n".join(lines)
```
