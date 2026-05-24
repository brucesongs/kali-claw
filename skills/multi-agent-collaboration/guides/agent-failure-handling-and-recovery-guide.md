# Agent Failure Handling and Recovery Guide

> Skill: multi-agent-collaboration | Type: methodology
> Created: 2026-05-23 | Estimated Study Time: 35 minutes

## Overview

Learn to handle agent failures in coordinated penetration testing engagements. Covers failure detection, retry strategies, task redistribution, graceful degradation, and rollback procedures.

## Prerequisites

- Multi-agent collaboration patterns
- Autonomous loops understanding
- Task decomposition methodology

## 1. Failure Classification

### Failure Types

```
┌─────────────────────────────────────────────────────────────┐
│                    FAILURE CLASSIFICATION                    │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │ TRANSIENT    │    │  PERMANENT   │    │   SYSTEMIC   │  │
│  │ (Recoverable)│    │ (Fatal)      │    │ (Cascading)  │  │
│  └──────────────┘    └──────────────┘    └──────────────┘  │
│         │                                        │           │
│         │                                        │           │
│         │                ┌──────────────┐       │           │
│         │                │   SCOPE      │       │           │
│         │                │   VIOLATION  │◄──────┘           │
│         │                └──────────────┘                   │
│         │                                                    │
│         │                ┌──────────────┐                   │
│         │                │  DEADLOCK    │                   │
│         │                └──────────────┘                   │
│                                                               │
└───────────────────────────────────────────────────────────────┘
```

### Failure Detection Matrix

| Failure Type | Detection Signal | Recovery Strategy |
|--------------|------------------|-------------------|
| **Transient** | Timeout, network error | Retry with backoff |
| **Permanent** | Agent crash, tool not found | Redistribute task |
| **Systemic** | Multiple agents failing | Pause engagement |
| **Scope Violation** | Out-of-scope access detected | Immediate rollback |
| **Deadlock** | No progress for N minutes | Break and redistribute |

## 2. Failure Detection

### Health Check Protocol

```python
class AgentHealthMonitor:
    def __init__(self, agents):
        self.agents = agents
        self.health_status = {}
        self.last_heartbeat = {}

    async def monitor(self, interval=30):
        """Continuous health monitoring"""
        while True:
            for agent_id in self.agents:
                health = await self.check_agent_health(agent_id)
                self.health_status[agent_id] = health
                self.last_heartbeat[agent_id] = datetime.utcnow()

                if not health['alive']:
                    await self.handle_failure(agent_id, health)

            await asyncio.sleep(interval)

    async def check_agent_health(self, agent_id):
        """Check if agent is responsive"""
        try:
            response = await asyncio.wait_for(
                self.ping_agent(agent_id),
                timeout=5
            )

            return {
                'alive': True,
                'last_activity': response.get('last_activity'),
                'current_task': response.get('current_task'),
                'error_count': response.get('error_count', 0),
            }
        except asyncio.TimeoutError:
            return {
                'alive': False,
                'reason': 'timeout',
                'last_seen': self.last_heartbeat.get(agent_id),
            }
        except Exception as e:
            return {
                'alive': False,
                'reason': str(e),
                'last_seen': self.last_heartbeat.get(agent_id),
            }
```

### Progress Monitoring

```python
class ProgressTracker:
    def __init__(self):
        self.tasks = {}
        self.agent_progress = {}

    def assign_task(self, task_id, agent_id):
        """Assign task and start tracking"""
        self.tasks[task_id] = {
            'assigned_to': agent_id,
            'status': 'in_progress',
            'assigned_at': datetime.utcnow(),
            'checkpoints': [],
        }

        if agent_id not in self.agent_progress:
            self.agent_progress[agent_id] = []

        self.agent_progress[agent_id].append(task_id)

    def update_checkpoint(self, task_id, checkpoint):
        """Record progress checkpoint"""
        if task_id in self.tasks:
            self.tasks[task_id]['checkpoints'].append({
                'timestamp': datetime.utcnow(),
                'checkpoint': checkpoint,
            })

    def check_stalled_tasks(self, timeout_minutes=30):
        """Find tasks with no progress"""
        stalled = []
        cutoff = datetime.utcnow() - timedelta(minutes=timeout_minutes)

        for task_id, task in self.tasks.items():
            if task['status'] == 'in_progress':
                last_checkpoint = task['checkpoints'][-1]['timestamp'] if task['checkpoints'] else task['assigned_at']
                if last_checkpoint < cutoff:
                    stalled.append({
                        'task_id': task_id,
                        'agent_id': task['assigned_to'],
                        'stalled_since': last_checkpoint,
                    })

        return stalled
```

## 3. Retry Strategies

### Exponential Backoff

```python
class RetryPolicy:
    def __init__(self, max_retries=3, base_delay=1, max_delay=60):
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay

    async def execute_with_retry(self, func, *args, **kwargs):
        """Execute function with exponential backoff"""
        last_error = None

        for attempt in range(self.max_retries):
            try:
                result = await func(*args, **kwargs)
                return {
                    'success': True,
                    'result': result,
                    'attempts': attempt + 1,
                }

            except Exception as e:
                last_error = e

                # Check if retry is appropriate
                if not self.is_retryable(e):
                    break

                # Calculate delay
                delay = min(
                    self.base_delay * (2 ** attempt),
                    self.max_delay
                )

                await asyncio.sleep(delay)

        return {
            'success': False,
            'error': last_error,
            'attempts': self.max_retries,
        }

    def is_retryable(self, error):
        """Determine if error is retryable"""
        retryable_errors = [
            'timeout',
            'connection refused',
            'rate limit',
            'temporary failure',
        ]

        error_str = str(error).lower()
        return any(r in error_str for r in retryable_errors)
```

### Circuit Breaker Pattern

```python
class CircuitBreaker:
    def __init__(self, failure_threshold=5, recovery_timeout=60):
        self.failure_count = 0
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.state = 'closed'  # closed, open, half-open
        self.last_failure_time = None

    async def execute(self, func, *args, **kwargs):
        """Execute with circuit breaker protection"""
        if self.state == 'open':
            if self.should_attempt_reset():
                self.state = 'half-open'
            else:
                raise Exception('Circuit breaker is OPEN')

        try:
            result = await func(*args, **kwargs)

            # Success - reset circuit breaker
            if self.state == 'half-open':
                self.state = 'closed'
            self.failure_count = 0

            return result

        except Exception as e:
            self.failure_count += 1
            self.last_failure_time = datetime.utcnow()

            if self.failure_count >= self.failure_threshold:
                self.state = 'open'

            raise

    def should_attempt_reset(self):
        """Check if recovery timeout has passed"""
        if self.last_failure_time is None:
            return True

        elapsed = (datetime.utcnow() - self.last_failure_time).total_seconds()
        return elapsed >= self.recovery_timeout
```

## 4. Task Redistribution

### Redistributor Implementation

```python
class TaskRedistributor:
    def __init__(self, coordinator, available_agents):
        self.coordinator = coordinator
        self.available_agents = available_agents
        self.redistribution_log = []

    async def redistribute_task(self, task_id, failed_agent_id):
        """Redistribute failed task to another agent"""
        task = self.coordinator.get_task(task_id)

        # Find available agent with matching capabilities
        new_agent = self.find_compatible_agent(task, failed_agent_id)

        if new_agent is None:
            return {
                'success': False,
                'reason': 'No compatible agent available',
            }

        # Reassign task
        self.coordinator.reassign_task(task_id, new_agent['id'])

        # Log redistribution
        self.redistribution_log.append({
            'timestamp': datetime.utcnow().isoformat(),
            'task_id': task_id,
            'from_agent': failed_agent_id,
            'to_agent': new_agent['id'],
            'reason': 'Agent failure',
        })

        return {
            'success': True,
            'new_agent': new_agent['id'],
        }

    def find_compatible_agent(self, task, exclude_agent_id):
        """Find agent capable of handling the task"""
        required_capabilities = task.get('required_capabilities', [])

        for agent in self.available_agents:
            if agent['id'] == exclude_agent_id:
                continue

            if not agent['available']:
                continue

            # Check capabilities
            if all(cap in agent['capabilities'] for cap in required_capabilities):
                return agent

        return None
```

### Bulk Redistribution

```python
async def handle_agent_failure(self, agent_id, reason):
    """Handle complete agent failure - redistribute all its tasks"""
    failed_tasks = self.get_agent_tasks(agent_id)

    self.log(f"Agent {agent_id} failed: {reason}")
    self.log(f"Redistributing {len(failed_tasks)} tasks...")

    redistribution_results = []
    for task in failed_tasks:
        task_id = task['id']
        result = await self.redistributor.redistribute_task(task_id, agent_id)
        redistribution_results.append({
            'task_id': task_id,
            'result': result,
        })

    # Report results
    successful = sum(1 for r in redistribution_results if r['result']['success'])
    failed = len(redistribution_results) - successful

    self.log(f"Redistribution complete: {successful} succeeded, {failed} failed")

    # Handle permanently failed tasks
    for result in redistribution_results:
        if not result['result']['success']:
            task = self.coordinator.get_task(result['task_id'])
            task['status'] = 'failed'
            task['failure_reason'] = result['result']['reason']
```

## 5. Graceful Degradation

### Degradation Strategy

```python
class DegradationManager:
    def __init__(self):
        self.degradation_levels = ['full', 'partial', 'minimal', 'stopped']
        self.current_level = 'full'
        self.capabilities_by_level = {
            'full': ['recon', 'scan', 'exploit', 'post-exploit', 'report'],
            'partial': ['recon', 'scan', 'exploit'],
            'minimal': ['recon', 'scan'],
            'stopped': [],
        }

    def assess_degradation_level(self, agent_health):
        """Assess current operational level"""
        alive_count = sum(1 for a in agent_health.values() if a['alive'])
        total_count = len(agent_health)

        availability = alive_count / total_count

        if availability >= 0.75:
            return 'full'
        elif availability >= 0.5:
            return 'partial'
        elif availability >= 0.25:
            return 'minimal'
        else:
            return 'stopped'

    async def adjust_scope(self, new_level):
        """Reduce scope based on degradation level"""
        old_level = self.current_level
        self.current_level = new_level

        # Remove tasks that are no longer possible
        removed_capabilities = set(
            self.capabilities_by_level[old_level]
        ) - set(self.capabilities_by_level[new_level])

        for capability in removed_capabilities:
            await self.pause_capability_tasks(capability)

        self.log(f"Degradation: {old_level} → {new_level}")
        self.log(f"Removed capabilities: {removed_capabilities}")
```

### Capability-Based Task Filtering

```python
async def filter_tasks_by_capability(self, tasks, available_capabilities):
    """Filter tasks to only those supported by available capabilities"""

    capability_to_tasks = {
        'recon': ['host_discovery', 'port_scan', 'service_enum'],
        'scan': ['vuln_scan', 'config_audit'],
        'exploit': ['exploit', 'privilege_escalation'],
        'post-exploit': ['data_exfiltration', 'persistence'],
        'report': ['generate_report', 'evidence_collection'],
    }

    # Map capabilities to task types
    supported_task_types = set()
    for cap in available_capabilities:
        supported_task_types.update(capability_to_tasks.get(cap, []))

    # Filter tasks
    filtered_tasks = [
        t for t in tasks
        if t['type'] in supported_task_types
    ]

    removed_count = len(tasks) - len(filtered_tasks)

    if removed_count > 0:
        self.log(f"Filtered {removed_count} tasks due to capability loss")

    return filtered_tasks
```

## 6. Rollback Procedures

### Scope Violation Rollback

```python
class ScopeViolationHandler:
    def __init__(self, scope_config):
        self.scope_config = scope_config
        self.violations = []

    async def handle_violation(self, agent_id, violation):
        """Handle scope violation by agent"""
        self.violations.append({
            'timestamp': datetime.utcnow().isoformat(),
            'agent_id': agent_id,
            'violation': violation,
        })

        # Immediate actions
        await self.immediate_actions(agent_id, violation)

        # Determine rollback scope
        rollback_plan = self.create_rollback_plan(violation)

        # Execute rollback
        rollback_result = await self.execute_rollback(rollback_plan)

        return {
            'violation_handled': True,
            'rollback_result': rollback_result,
        }

    async def immediate_actions(self, agent_id, violation):
        """Immediate actions to stop further damage"""
        # Stop the agent
        await self.stop_agent(agent_id)

        # Document what was accessed
        accessed_resources = violation.get('accessed_resources', [])
        for resource in accessed_resources:
            self.log(f"Resource accessed: {resource}")

    def create_rollback_plan(self, violation):
        """Create rollback plan based on violation type"""
        rollback_type = violation.get('type')

        if rollback_type == 'out_of_scope_target':
            return {
                'type': 'revert_changes',
                'actions': [
                    {'action': 'disconnect_from_target', 'target': violation['target']},
                    {'action': 'remove_evidence_of_access', 'target': violation['target']},
                ],
            }

        elif rollback_type == 'unauthorized_modification':
            return {
                'type': 'restore_original_state',
                'actions': [
                    {'action': 'restore_backup', 'target': violation['target']},
                    {'action': 'verify_integrity', 'target': violation['target']},
                ],
            }

        elif rollback_type == 'data_exfiltration':
            return {
                'type': 'contain_exposure',
                'actions': [
                    {'action': 'document_exfiltrated_data', 'data': violation['data']},
                    {'action': 'notify_responsible_party', 'data': violation['data']},
                ],
            }

    async def execute_rollback(self, plan):
        """Execute rollback plan"""
        results = []

        for action in plan['actions']:
            action_type = action['action']
            result = await self.execute_rollback_action(action_type, action)
            results.append(result)

        return {
            'plan_type': plan['type'],
            'actions_executed': len(results),
            'successful_actions': sum(1 for r in results if r['success']),
        }
```

### System-Wide Rollback

```python
class EngagementRollbackManager:
    def __init__(self):
        self.snapshots = {}
        self.rollback_log = []

    async def create_engagement_snapshot(self):
        """Create snapshot of current engagement state"""
        snapshot = {
            'timestamp': datetime.utcnow().isoformat(),
            'agents': self.get_agent_states(),
            'tasks': self.get_all_tasks(),
            'findings': self.get_all_findings(),
            'scope': self.get_current_scope(),
        }

        snapshot_id = generate_id()
        self.snapshots[snapshot_id] = snapshot

        return snapshot_id

    async def rollback_to_snapshot(self, snapshot_id):
        """Rollback engagement to snapshot state"""
        if snapshot_id not in self.snapshots:
            return {'success': False, 'reason': 'Snapshot not found'}

        snapshot = self.snapshots[snapshot_id]

        # Restore task states
        for task in snapshot['tasks']:
            self.restore_task_state(task)

        # Clear findings after snapshot
        self.clear_recent_findings(snapshot['timestamp'])

        # Restore scope
        self.set_scope(snapshot['scope'])

        self.rollback_log.append({
            'timestamp': datetime.utcnow().isoformat(),
            'snapshot_id': snapshot_id,
            'action': 'rollback',
        })

        return {'success': True, 'restored_to': snapshot['timestamp']}
```

## 7. Failure Reporting

### Failure Report Template

```markdown
## Agent Failure Report

**Engagement ID:** [engagement-id]
**Report Time:** [timestamp]
**Failed Agent ID:** [agent-id]

### Failure Details
- **Type:** [transient/permanent/systemic/scope-violation]
- **Detected At:** [timestamp]
- **Detection Method:** [health-check/timeout/manual]
- **Root Cause:** [detailed explanation]

### Impact Assessment
- **Tasks Affected:** [count]
- **Findings at Risk:** [count and description]
- **Scope Impact:** [if applicable]

### Recovery Actions Taken
1. [Action 1]
2. [Action 2]
3. [Action 3]

### Redistribution Results
- **Tasks Redistributed:** [count]
- **Successful:** [count]
- **Failed:** [count]
- **Permanently Failed Tasks:** [list]

### Current State
- **Degradation Level:** [full/partial/minimal/stopped]
- **Remaining Agents:** [count]
- **Expected Completion:** [estimate]
```

## Quick Reference

```python
# Health check
health = await check_agent_health(agent_id)

# Retry with backoff
result = await execute_with_retry(func, *args)

# Circuit breaker
result = await circuit_breaker.execute(func, *args)

# Redistribute task
result = await redistribute_task(task_id, failed_agent_id)

# Assess degradation
level = assess_degradation_level(agent_health)

# Handle scope violation
await handle_violation(agent_id, violation)

# Rollback to snapshot
await rollback_to_snapshot(snapshot_id)
```

## Integration with Other Skills

- **multi-agent-collaboration**: Coordinated pentest playbook
- **autonomous-loops**: Loop failure handling patterns
- **verification-loop**: Verify redistribution didn't create gaps
- **safety-guard**: Scope violation enforcement
- **chronicle**: Failure event logging