# MCP Server Deployment Guide

> Practical reference for deploying MCP servers in production using Docker, with scaling strategies, monitoring, and health check configurations. Covers containerization, orchestration, and operational best practices.

## 1. Docker Container Setup

Package MCP servers as lightweight, reproducible containers.

```dockerfile
# Dockerfile for MCP server
FROM python:3.12-slim AS base

# Security: non-root user
RUN groupadd -r mcp && useradd -r -g mcp -d /app -s /sbin/nologin mcp

WORKDIR /app

# Install dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY --chown=mcp:mcp src/ ./src/
COPY --chown=mcp:mcp config/ ./config/

# Security hardening
RUN chmod -R 550 /app/src && \
    chmod -R 550 /app/config && \
    mkdir -p /app/workspace && chmod 770 /app/workspace

USER mcp

# Health check endpoint
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')"

EXPOSE 8080

ENTRYPOINT ["python", "-m", "src.server"]
CMD ["--host", "0.0.0.0", "--port", "8080"]
```

```bash
# Build and run
docker build -t mcp-server:latest .
docker run -d \
  --name mcp-server \
  --memory=512m \
  --cpus=1.0 \
  --read-only \
  --tmpfs /tmp:size=100m \
  -p 8080:8080 \
  -v /workspace:/app/workspace:rw \
  -e MCP_LOG_LEVEL=info \
  -e MCP_MAX_CONNECTIONS=50 \
  mcp-server:latest
```

## 2. Docker Compose for Multi-Service Setup

```yaml
# docker-compose.yml
version: '3.8'

services:
  mcp-server:
    build: .
    ports:
      - "8080:8080"
    environment:
      - MCP_LOG_LEVEL=info
      - MCP_REDIS_URL=redis://redis:6379
      - MCP_MAX_WORKERS=4
    volumes:
      - workspace:/app/workspace
      - ./config:/app/config:ro
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: '1.0'
        reservations:
          memory: 256M
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 10s
    restart: unless-stopped
    networks:
      - mcp-internal

  redis:
    image: redis:7-alpine
    volumes:
      - redis-data:/data
    networks:
      - mcp-internal
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s

  nginx:
    image: nginx:alpine
    ports:
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./certs:/etc/nginx/certs:ro
    depends_on:
      mcp-server:
        condition: service_healthy
    networks:
      - mcp-internal
      - mcp-external

volumes:
  workspace:
  redis-data:

networks:
  mcp-internal:
    internal: true
  mcp-external:
```

## 3. Health Check Implementation

```python
"""MCP server health check endpoints."""
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import asyncio
import psutil

@dataclass(frozen=True)
class HealthStatus:
    status: str  # "healthy", "degraded", "unhealthy"
    timestamp: str
    uptime_seconds: float
    version: str
    checks: dict

START_TIME = datetime.now(timezone.utc)

async def check_health() -> HealthStatus:
    """Comprehensive health check for MCP server."""
    checks = {}
    overall = "healthy"
    
    # Check 1: Memory usage
    memory = psutil.virtual_memory()
    checks["memory"] = {
        "status": "ok" if memory.percent < 85 else "warning",
        "used_percent": memory.percent
    }
    if memory.percent > 90:
        overall = "degraded"
    
    # Check 2: Disk space
    disk = psutil.disk_usage("/app/workspace")
    checks["disk"] = {
        "status": "ok" if disk.percent < 80 else "warning",
        "used_percent": disk.percent
    }
    
    # Check 3: Active connections
    connections = len(psutil.net_connections(kind='tcp'))
    checks["connections"] = {
        "status": "ok" if connections < 100 else "warning",
        "active": connections
    }
    
    # Check 4: Redis connectivity (if used)
    try:
        import redis
        r = redis.Redis.from_url("redis://redis:6379", socket_timeout=2)
        r.ping()
        checks["redis"] = {"status": "ok"}
    except Exception as e:
        checks["redis"] = {"status": "error", "message": str(e)}
        overall = "degraded"
    
    now = datetime.now(timezone.utc)
    return HealthStatus(
        status=overall,
        timestamp=now.isoformat(),
        uptime_seconds=(now - START_TIME).total_seconds(),
        version="1.0.0",
        checks=checks
    )

# HTTP handler (using aiohttp or similar)
async def health_handler(request):
    health = await check_health()
    status_code = 200 if health.status == "healthy" else 503
    return web.json_response(asdict(health), status=status_code)
```

## 4. Scaling Strategies

```yaml
# Kubernetes deployment for horizontal scaling
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mcp-server
spec:
  replicas: 3
  selector:
    matchLabels:
      app: mcp-server
  template:
    metadata:
      labels:
        app: mcp-server
    spec:
      containers:
        - name: mcp-server
          image: mcp-server:latest
          ports:
            - containerPort: 8080
          resources:
            requests:
              memory: "256Mi"
              cpu: "250m"
            limits:
              memory: "512Mi"
              cpu: "1000m"
          livenessProbe:
            httpGet:
              path: /health
              port: 8080
            initialDelaySeconds: 10
            periodSeconds: 30
          readinessProbe:
            httpGet:
              path: /health
              port: 8080
            initialDelaySeconds: 5
            periodSeconds: 10
          env:
            - name: MCP_WORKER_COUNT
              value: "4"
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: mcp-server-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: mcp-server
  minReplicas: 2
  maxReplicas: 10
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
    - type: Resource
      resource:
        name: memory
        target:
          type: Utilization
          averageUtilization: 80
```

## 5. Monitoring and Metrics

```python
"""Prometheus metrics for MCP server monitoring."""
from prometheus_client import Counter, Histogram, Gauge, start_http_server
import time
from functools import wraps

# Define metrics
TOOL_CALLS_TOTAL = Counter(
    'mcp_tool_calls_total',
    'Total MCP tool invocations',
    ['tool_name', 'status']
)

TOOL_DURATION = Histogram(
    'mcp_tool_duration_seconds',
    'Tool execution duration',
    ['tool_name'],
    buckets=[0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 30.0, 60.0]
)

ACTIVE_SESSIONS = Gauge(
    'mcp_active_sessions',
    'Number of active MCP sessions'
)

ERRORS_TOTAL = Counter(
    'mcp_errors_total',
    'Total errors by type',
    ['error_type']
)

def instrument_tool(tool_name: str):
    """Decorator to instrument MCP tool calls."""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            start = time.time()
            try:
                result = await func(*args, **kwargs)
                TOOL_CALLS_TOTAL.labels(tool_name=tool_name, status="success").inc()
                return result
            except Exception as e:
                TOOL_CALLS_TOTAL.labels(tool_name=tool_name, status="error").inc()
                ERRORS_TOTAL.labels(error_type=type(e).__name__).inc()
                raise
            finally:
                TOOL_DURATION.labels(tool_name=tool_name).observe(time.time() - start)
        return wrapper
    return decorator

# Start metrics server on separate port
start_http_server(9090)
```

## 6. Nginx Reverse Proxy Configuration

```nginx
# nginx.conf — TLS termination and rate limiting for MCP server
upstream mcp_backend {
    least_conn;
    server mcp-server-1:8080;
    server mcp-server-2:8080;
    server mcp-server-3:8080;
}

limit_req_zone $binary_remote_addr zone=mcp_limit:10m rate=30r/s;
limit_conn_zone $binary_remote_addr zone=mcp_conn:10m;

server {
    listen 443 ssl http2;
    server_name mcp.example.com;

    ssl_certificate /etc/nginx/certs/fullchain.pem;
    ssl_certificate_key /etc/nginx/certs/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    # Rate limiting
    limit_req zone=mcp_limit burst=50 nodelay;
    limit_conn mcp_conn 20;

    # Request size limits
    client_max_body_size 10m;
    client_body_timeout 30s;

    location / {
        proxy_pass http://mcp_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 120s;
        proxy_send_timeout 60s;
        
        # WebSocket support (for streaming)
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    location /health {
        proxy_pass http://mcp_backend/health;
        access_log off;
    }

    location /metrics {
        deny all;  # Only internal access
    }
}
```

## 7. Logging and Observability

```python
"""Structured logging configuration for MCP server."""
import logging
import json
from datetime import datetime, timezone

class JSONFormatter(logging.Formatter):
    """JSON log formatter for structured logging."""
    
    def format(self, record):
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
        }
        
        # Add extra fields
        if hasattr(record, "session_id"):
            log_entry["session_id"] = record.session_id
        if hasattr(record, "tool_name"):
            log_entry["tool_name"] = record.tool_name
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        
        return json.dumps(log_entry)

# Configure logging
def setup_logging(level: str = "INFO"):
    handler = logging.StreamHandler()
    handler.setFormatter(JSONFormatter())
    
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level))
    root_logger.addHandler(handler)
    
    # Reduce noise from libraries
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("asyncio").setLevel(logging.WARNING)
```

```bash
# Log aggregation with Docker
docker logs mcp-server --since 1h | jq 'select(.level == "ERROR")'

# Monitor in real-time
docker logs -f mcp-server | jq --unbuffered 'select(.tool_name != null)'
```

## 8. Graceful Shutdown and Updates

```python
"""Graceful shutdown handling for MCP server."""
import signal
import asyncio
import logging

logger = logging.getLogger(__name__)

class GracefulShutdown:
    """Handle graceful shutdown of MCP server."""
    
    def __init__(self, server):
        self.server = server
        self.shutting_down = False
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)
    
    def _handle_signal(self, signum, frame):
        logger.info(f"Received signal {signum}, initiating graceful shutdown")
        self.shutting_down = True
        asyncio.get_event_loop().create_task(self._shutdown())
    
    async def _shutdown(self):
        """Drain connections and shut down cleanly."""
        # Stop accepting new connections
        self.server.stop_accepting()
        logger.info("Stopped accepting new connections")
        
        # Wait for active requests to complete (max 30s)
        timeout = 30
        while self.server.active_connections > 0 and timeout > 0:
            logger.info(f"Waiting for {self.server.active_connections} active connections...")
            await asyncio.sleep(1)
            timeout -= 1
        
        if self.server.active_connections > 0:
            logger.warning(f"Force closing {self.server.active_connections} connections")
        
        # Cleanup resources
        await self.server.cleanup()
        logger.info("Shutdown complete")
```

```bash
# Zero-downtime deployment with Docker Compose
docker compose up -d --no-deps --build mcp-server
# Docker handles draining old container via healthcheck + depends_on

# Rolling update with Kubernetes
kubectl rollout restart deployment/mcp-server
kubectl rollout status deployment/mcp-server
```
