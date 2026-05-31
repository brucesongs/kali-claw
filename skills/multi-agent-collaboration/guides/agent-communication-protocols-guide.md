# Agent Communication Protocols Guide

> Practical reference for implementing inter-agent communication in multi-agent systems. Covers message passing patterns, shared state management, event-driven coordination, and protocol design for security-focused agent workflows.

## 1. Message Passing Fundamentals

Agents communicate through structured messages with clear contracts.

```python
from dataclasses import dataclass, field
from typing import Any, FrozenSet
from enum import Enum
from datetime import datetime, timezone
import json
import uuid

class MessageType(Enum):
    REQUEST = "request"
    RESPONSE = "response"
    EVENT = "event"
    COMMAND = "command"
    HEARTBEAT = "heartbeat"

class Priority(Enum):
    LOW = 0
    NORMAL = 1
    HIGH = 2
    CRITICAL = 3

@dataclass(frozen=True)
class AgentMessage:
    id: str
    type: MessageType
    sender: str
    recipient: str  # Agent ID or "*" for broadcast
    payload: dict
    priority: Priority = Priority.NORMAL
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    correlation_id: str = ""  # Links request/response pairs
    ttl_seconds: int = 300  # Message expiry

    def to_json(self) -> str:
        return json.dumps({
            "id": self.id,
            "type": self.type.value,
            "sender": self.sender,
            "recipient": self.recipient,
            "payload": self.payload,
            "priority": self.priority.value,
            "timestamp": self.timestamp,
            "correlation_id": self.correlation_id,
            "ttl_seconds": self.ttl_seconds
        })

def create_task_request(sender: str, recipient: str, task: dict) -> AgentMessage:
    msg_id = str(uuid.uuid4())
    return AgentMessage(
        id=msg_id,
        type=MessageType.REQUEST,
        sender=sender,
        recipient=recipient,
        payload=task,
        priority=Priority.NORMAL,
        correlation_id=msg_id
    )
```

## 2. Message Queue Implementation

```python
import asyncio
from collections import defaultdict
from typing import Callable
from dataclasses import dataclass, field

@dataclass
class MessageBroker:
    """Central message broker for agent communication."""
    _queues: dict = field(default_factory=lambda: defaultdict(asyncio.Queue))
    _handlers: dict = field(default_factory=dict)
    
    async def publish(self, message: AgentMessage) -> None:
        """Publish message to recipient's queue."""
        if message.recipient == "*":
            for agent_id in self._handlers:
                if agent_id != message.sender:
                    await self._queues[agent_id].put(message)
        else:
            await self._queues[message.recipient].put(message)
    
    async def subscribe(self, agent_id: str, handler: Callable) -> None:
        """Register message handler for an agent."""
        self._handlers[agent_id] = handler
        asyncio.create_task(self._process_queue(agent_id))
    
    async def _process_queue(self, agent_id: str) -> None:
        """Process messages from agent's queue."""
        queue = self._queues[agent_id]
        handler = self._handlers[agent_id]
        
        while True:
            message = await queue.get()
            try:
                response = await handler(message)
                if response and message.type == MessageType.REQUEST:
                    await self.publish(response)
            except Exception as e:
                error_msg = AgentMessage(
                    id=str(uuid.uuid4()),
                    type=MessageType.RESPONSE,
                    sender=agent_id,
                    recipient=message.sender,
                    payload={"error": str(e)},
                    correlation_id=message.correlation_id
                )
                await self.publish(error_msg)

# Usage
broker = MessageBroker()

async def scanner_handler(msg: AgentMessage) -> AgentMessage:
    """Handle messages for the scanner agent."""
    if msg.payload.get("action") == "scan":
        result = {"findings": ["SQLi on /login", "XSS on /search"]}
        return AgentMessage(
            id=str(uuid.uuid4()),
            type=MessageType.RESPONSE,
            sender="scanner",
            recipient=msg.sender,
            payload=result,
            correlation_id=msg.correlation_id
        )
    return None
```

## 3. Shared State Management

```python
import asyncio
from dataclasses import dataclass, field
from typing import Any, Optional
import copy
import time
from collections import defaultdict

@dataclass
class SharedState:
    """Thread-safe shared state with versioning and conflict detection."""
    _state: dict = field(default_factory=dict)
    _versions: dict = field(default_factory=lambda: defaultdict(int))
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    _history: list = field(default_factory=list)
    
    async def get(self, key: str) -> Optional[Any]:
        """Read value from shared state."""
        async with self._lock:
            return copy.deepcopy(self._state.get(key))
    
    async def set(self, key: str, value: Any, agent_id: str, expected_version: int = None) -> bool:
        """Write value with optimistic concurrency control."""
        async with self._lock:
            current_version = self._versions[key]
            
            if expected_version is not None and current_version != expected_version:
                return False  # Conflict detected
            
            self._history.append({
                "key": key,
                "old_value": self._state.get(key),
                "new_value": copy.deepcopy(value),
                "agent": agent_id,
                "version": current_version + 1,
                "timestamp": time.time()
            })
            
            self._state[key] = copy.deepcopy(value)
            self._versions[key] = current_version + 1
            return True
    
    async def get_version(self, key: str) -> int:
        """Get current version for optimistic locking."""
        async with self._lock:
            return self._versions[key]

# Usage in multi-agent pentest
state = SharedState()
await state.set("findings", [
    {"type": "sqli", "url": "/login", "severity": "high"}
], agent_id="scanner")

findings = await state.get("findings")
```

## 4. Event-Driven Coordination

```python
from dataclasses import dataclass, field
from typing import Callable, List
import asyncio
from collections import defaultdict

@dataclass
class EventBus:
    """Pub/sub event system for agent coordination."""
    _listeners: dict = field(default_factory=lambda: defaultdict(list))
    
    def on(self, event_type: str, handler: Callable) -> None:
        """Register event listener."""
        self._listeners[event_type].append(handler)
    
    async def emit(self, event_type: str, data: dict) -> None:
        """Emit event to all registered listeners."""
        handlers = self._listeners.get(event_type, [])
        await asyncio.gather(
            *[handler(data) for handler in handlers],
            return_exceptions=True
        )

# Define security workflow events
EVENTS = {
    "scan.started": "Scanner began scanning target",
    "scan.completed": "Scanner finished, findings available",
    "finding.new": "New vulnerability discovered",
    "exploit.started": "Exploitation attempt initiated",
    "exploit.success": "Exploitation successful",
    "exploit.failed": "Exploitation failed",
    "report.ready": "Final report generated",
}

# Wire up event-driven workflow
bus = EventBus()

async def on_scan_complete(data: dict):
    """When scan completes, trigger exploitation of findings."""
    findings = data.get("findings", [])
    for finding in findings:
        if finding["severity"] in ("critical", "high"):
            await bus.emit("exploit.started", {"finding": finding, "agent": "exploiter"})

async def on_exploit_success(data: dict):
    """When exploit succeeds, capture evidence and notify."""
    await bus.emit("evidence.capture", {"finding": data["finding"], "proof": data["proof"]})

bus.on("scan.completed", on_scan_complete)
bus.on("exploit.success", on_exploit_success)
```

## 5. Request-Response with Timeout

```python
import asyncio
from typing import Optional

class AgentClient:
    """Client for making request-response calls to other agents."""
    
    def __init__(self, agent_id: str, broker: MessageBroker):
        self.agent_id = agent_id
        self.broker = broker
        self._pending: dict = {}
    
    async def request(self, recipient: str, payload: dict, timeout: float = 30.0) -> dict:
        """Send request and wait for response with timeout."""
        msg = create_task_request(self.agent_id, recipient, payload)
        
        future = asyncio.get_event_loop().create_future()
        self._pending[msg.correlation_id] = future
        
        await self.broker.publish(msg)
        
        try:
            response = await asyncio.wait_for(future, timeout=timeout)
            return response.payload
        except asyncio.TimeoutError:
            del self._pending[msg.correlation_id]
            return {"error": f"Timeout waiting for response from {recipient}"}
    
    async def handle_response(self, message: AgentMessage) -> None:
        """Process incoming response messages."""
        future = self._pending.pop(message.correlation_id, None)
        if future and not future.done():
            future.set_result(message)

# Usage
client = AgentClient("orchestrator", broker)
result = await client.request("scanner", {
    "action": "scan",
    "target": "http://target.com",
    "scope": ["sqli", "xss", "ssrf"]
}, timeout=120.0)
```

## 6. Protocol Versioning and Compatibility

```python
from dataclasses import dataclass
from typing import Tuple

@dataclass(frozen=True)
class ProtocolVersion:
    major: int
    minor: int
    patch: int
    
    def is_compatible(self, other: 'ProtocolVersion') -> bool:
        """Check backward compatibility (same major version)."""
        return self.major == other.major
    
    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"

CURRENT_VERSION = ProtocolVersion(2, 1, 0)

def negotiate_protocol(client_version: str, server_version: str) -> Tuple[bool, str]:
    """Negotiate protocol version between agents."""
    client = ProtocolVersion(*map(int, client_version.split(".")))
    server = ProtocolVersion(*map(int, server_version.split(".")))
    
    if client.is_compatible(server):
        negotiated = min(client.minor, server.minor)
        return True, f"{client.major}.{negotiated}.0"
    
    return False, f"Incompatible: client={client}, server={server}"

# Handshake message
handshake = AgentMessage(
    id=str(uuid.uuid4()),
    type=MessageType.REQUEST,
    sender="agent_a",
    recipient="agent_b",
    payload={
        "action": "handshake",
        "protocol_version": str(CURRENT_VERSION),
        "capabilities": ["scan", "exploit", "report"],
        "supported_formats": ["json", "sarif"]
    }
)
```

## 7. Error Handling and Recovery

```python
import asyncio
from dataclasses import dataclass

@dataclass(frozen=True)
class RetryPolicy:
    max_retries: int = 3
    base_delay: float = 1.0
    max_delay: float = 30.0
    exponential_base: float = 2.0

async def send_with_retry(
    client: AgentClient,
    recipient: str,
    payload: dict,
    policy: RetryPolicy = RetryPolicy()
) -> dict:
    """Send message with exponential backoff retry."""
    last_error = None
    
    for attempt in range(policy.max_retries + 1):
        try:
            result = await client.request(recipient, payload, timeout=30.0)
            if "error" not in result:
                return result
            last_error = result["error"]
        except Exception as e:
            last_error = str(e)
        
        if attempt < policy.max_retries:
            delay = min(
                policy.base_delay * (policy.exponential_base ** attempt),
                policy.max_delay
            )
            await asyncio.sleep(delay)
    
    return {"error": f"Failed after {policy.max_retries} retries: {last_error}"}

# Dead letter queue for undeliverable messages
@dataclass
class DeadLetterQueue:
    _messages: list = field(default_factory=list)
    max_size: int = 1000
    
    def add(self, message: AgentMessage, reason: str) -> None:
        if len(self._messages) >= self.max_size:
            self._messages.pop(0)
        self._messages.append({"message": message, "reason": reason, "timestamp": time.time()})
    
    def get_failed(self, since_seconds: int = 3600) -> list:
        cutoff = time.time() - since_seconds
        return [m for m in self._messages if m["timestamp"] > cutoff]
```

## 8. Monitoring Agent Communication

```python
from dataclasses import dataclass, field
from collections import defaultdict
import time

@dataclass
class CommunicationMetrics:
    """Track inter-agent communication health."""
    messages_sent: dict = field(default_factory=lambda: defaultdict(int))
    messages_received: dict = field(default_factory=lambda: defaultdict(int))
    errors: dict = field(default_factory=lambda: defaultdict(int))
    latencies: dict = field(default_factory=lambda: defaultdict(list))
    
    def record_send(self, sender: str, recipient: str) -> None:
        self.messages_sent[f"{sender}->{recipient}"] += 1
    
    def record_receive(self, sender: str, recipient: str, latency_ms: float) -> None:
        key = f"{sender}->{recipient}"
        self.messages_received[key] += 1
        self.latencies[key].append(latency_ms)
    
    def record_error(self, sender: str, recipient: str, error_type: str) -> None:
        self.errors[f"{sender}->{recipient}:{error_type}"] += 1
    
    def summary(self) -> dict:
        """Generate communication health summary."""
        total_sent = sum(self.messages_sent.values())
        total_errors = sum(self.errors.values())
        return {
            "total_sent": total_sent,
            "total_received": sum(self.messages_received.values()),
            "total_errors": total_errors,
            "error_rate": total_errors / max(total_sent, 1),
            "avg_latency_ms": {
                k: sum(v) / len(v) if v else 0
                for k, v in self.latencies.items()
            },
            "busiest_channels": sorted(
                self.messages_sent.items(), key=lambda x: -x[1]
            )[:5]
        }

metrics = CommunicationMetrics()
```
