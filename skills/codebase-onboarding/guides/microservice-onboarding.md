# Microservice Onboarding Guide

Onboarding multi-service architectures: service discovery, API contracts, inter-service trust, and distributed security surfaces.

---

## Microservice Mental Model

A microservice system is not one codebase — it's a cluster of smaller codebases with contracts between them. Onboarding strategy shifts from "read one codebase deeply" to "map the system, then dive into target services."

```
Monolith onboarding:  Root → Modules → Functions
Microservice onboarding: System Map → Service Inventory → Target Service(s)
```

## Step 1: System Map Discovery

Before reading any service code:

```bash
# Find all service directories
ls -la services/ apps/ microservices/ 2>/dev/null
find . -name "Dockerfile" | grep -v node_modules | grep -v ".git" | sort

# Docker Compose reveals the full system
cat docker-compose.yml docker-compose.yaml docker-compose.dev.yml 2>/dev/null

# Kubernetes manifests
find . -name "*.yaml" -path "*/k8s/*" -o -name "*.yaml" -path "*/kubernetes/*" \
  | head -20
find . -name "deployment.yaml" -o -name "service.yaml" -o -name "ingress.yaml" \
  | grep -v node_modules | head -20

# Helm charts
find . -name "Chart.yaml" | grep -v node_modules | head -10
find . -name "values.yaml" | grep -v node_modules | head -10

# Terraform / Pulumi (infrastructure as code)
find . -name "*.tf" -o -name "Pulumi.yaml" | grep -v node_modules | head -10
```

## Step 2: Service Inventory

Create a service inventory before diving into any code:

```bash
# Count services
find . -name "Dockerfile" | grep -v node_modules | wc -l

# Service names and purposes (from docker-compose)
grep "^  [a-z]" docker-compose.yml 2>/dev/null | sed 's/://'

# Port assignments (reveals service roles)
grep -A2 "ports:" docker-compose.yml 2>/dev/null | grep -v "^--$"

# Environment variables per service (reveals dependencies)
grep -A20 "environment:" docker-compose.yml 2>/dev/null | head -60
```

Service inventory template:
```
| Service | Tech | Port | Role | Depends On |
|---------|------|------|------|------------|
| api-gateway | Node.js | 8080 | Entry point | auth, users, products |
| auth-service | Go | 3001 | JWT issuance | postgres, redis |
| user-service | Python | 3002 | User CRUD | postgres |
| product-service | Java | 3003 | Product catalog | postgres, elasticsearch |
| notification-worker | Node.js | - | Async emails | rabbitmq, smtp |
```

## Step 3: API Contract Discovery

```bash
# OpenAPI/Swagger specs
find . -name "openapi.yaml" -o -name "swagger.yaml" -o -name "openapi.json" \
  -o -name "swagger.json" | grep -v node_modules | head -10

# AsyncAPI (event-driven contracts)
find . -name "asyncapi.yaml" -o -name "asyncapi.json" | grep -v node_modules

# Protobuf definitions (gRPC)
find . -name "*.proto" | grep -v node_modules | head -20
grep -rn "service\s" --include="*.proto" . | head -20

# GraphQL schema
find . -name "*.graphql" -o -name "schema.gql" -o -name "*.gql" \
  | grep -v node_modules | head -10

# API documentation
find . -name "API.md" -o -name "api.md" -iname "api-reference*" | head -5
```

## Step 4: Inter-Service Communication Patterns

### Synchronous (HTTP/gRPC)

```bash
# HTTP client calls between services
grep -rn "http://\|https://" --include="*.go" --include="*.py" --include="*.js" . \
  | grep -v node_modules | grep -v test | grep "localhost\|svc\|service\|:3" | head -20

# Service discovery patterns
grep -rn "SERVICE_URL\|_SERVICE_HOST\|getenv.*_URL\|os\.Getenv.*SERVICE" \
  --include="*.go" --include="*.py" --include="*.js" . \
  | grep -v node_modules | grep -v test | head -15

# gRPC client connections
grep -rn "grpc\.Dial\|grpc\.NewClient\|grpc\.DialContext" --include="*.go" . \
  | grep -v test | head -10
grep -rn "grpc\.insecure_channel\|grpc\.channel\|stub(" --include="*.py" . \
  | grep -v test | head -10
```

### Asynchronous (Message Queues)

```bash
# RabbitMQ
grep -rn "amqp\.\|rabbitmq\|pika\.\|amqplib" \
  --include="*.go" --include="*.py" --include="*.js" . -il | head -5

# Kafka
grep -rn "kafka\.\|confluent_kafka\|sarama\." \
  --include="*.go" --include="*.py" --include="*.js" . -il | head -5

# Redis pub/sub or queues
grep -rn "redis\.Subscribe\|redis\.Publish\|BullQueue\|Bull(" \
  --include="*.go" --include="*.py" --include="*.js" . | head -10

# Event topics/queues (security: what sensitive events flow through queues?)
grep -rn "queue_name\|topic_name\|QUEUE\|TOPIC\|exchange_name" \
  --include="*.go" --include="*.py" --include="*.js" . \
  | grep -v node_modules | head -15
```

## Step 5: Inter-Service Authentication

This is the critical security surface for microservices:

```bash
# Service-to-service tokens
grep -rn "service_token\|SERVICE_TOKEN\|INTERNAL_API_KEY\|X-Internal-Key\|X-Service-Token" \
  --include="*.go" --include="*.py" --include="*.js" --include="*.ts" . \
  | grep -v node_modules | grep -v test | head -10

# Mutual TLS (mTLS)
grep -rn "tls\.Config\|mtls\|client_cert\|client_key\|ClientCA" \
  --include="*.go" . | grep -v test | head -10

# Service mesh (Istio, Linkerd)
find . -name "*.yaml" | xargs grep -l "istio\|linkerd\|envoy" 2>/dev/null | head -5

# JWT service identity claims
grep -rn "service_id\|iss.*service\|sub.*service" \
  --include="*.go" --include="*.py" --include="*.js" . \
  | grep -v node_modules | grep -v test | head -10

# WARNING: Missing auth between services
grep -rn "skip.*auth\|bypass.*auth\|internal.*no.*auth\|SKIP_AUTH" \
  --include="*.go" --include="*.py" --include="*.js" . \
  | grep -v test | head -5
```

## Step 6: API Gateway Analysis

The API gateway is the highest-value target in microservice security:

```bash
# Gateway config (Kong, AWS API Gateway, Nginx, Traefik)
find . -name "kong.yml" -o -name "kong.yaml" | head -3
find . -name "nginx.conf" -o -path "*/nginx/*.conf" | head -5
find . -name "traefik.yml" -o -name "traefik.toml" | head -3

# Rate limiting at gateway level
grep -rn "rate_limit\|rateLimit\|rate-limit" \
  --include="*.yaml" --include="*.yml" --include="*.toml" . \
  | grep -v node_modules | head -10

# Auth enforcement at gateway
grep -rn "jwt\|oauth\|api_key\|plugin.*auth\|middleware.*auth" \
  --include="*.yaml" --include="*.yml" . | grep -v node_modules | head -10

# Route definitions (reveals all public endpoints)
grep -rn "path:\|route:\|upstream:\|service:" \
  --include="*.yaml" --include="*.yml" . | grep -v node_modules | head -30
```

## Microservice Security Checklist

```bash
# 1. Missing auth on internal endpoints
grep -rn "NoAuth\|skip_auth\|public_route\|unauthenticated" \
  --include="*.go" --include="*.py" --include="*.js" . \
  | grep -v node_modules | grep -v test | head -10

# 2. Direct database access from multiple services (shared DB anti-pattern)
grep -rn "DB_HOST\|DATABASE_URL\|POSTGRES_" \
  --include="*.env*" --include="docker-compose*" . | head -20

# 3. Secret sharing between services
grep -rn "SHARED_SECRET\|JWT_SECRET\|API_SECRET" \
  --include="*.env*" --include="docker-compose*" . | head -10

# 4. Network policy gaps (Kubernetes)
find . -name "networkpolicy.yaml" -o -name "network-policy.yaml" | head -5

# 5. Container security context
grep -rn "privileged: true\|runAsRoot\|allowPrivilegeEscalation: true" \
  --include="*.yaml" . | grep -v node_modules | head -5

# 6. Health check endpoints (often unauthenticated, may leak info)
grep -rn "healthcheck\|health_check\|/health\|/ready\|/live" \
  --include="*.go" --include="*.py" --include="*.js" . \
  | grep -v node_modules | grep -v test | head -10
```

## Distributed Tracing for Attack Surface Mapping

If distributed tracing is enabled (Jaeger, Zipkin, OpenTelemetry), it can accelerate architecture mapping:

```bash
# Find tracing setup
grep -rn "opentelemetry\|jaeger\|zipkin\|tracer\.\|Span(" \
  --include="*.go" --include="*.py" --include="*.js" . -il | head -10

# Trace IDs in logs can reveal request flows across services
grep -rn "trace_id\|span_id\|X-Trace-Id\|X-B3-TraceId" \
  --include="*.go" --include="*.py" --include="*.js" . \
  | grep -v node_modules | head -10
```

## Output Template for Microservice Systems

```markdown
## System Architecture

Services: [count]
Entry: [API Gateway / Load Balancer]
Inter-service: [HTTP / gRPC / Message Queue]
Auth model: [JWT / mTLS / Service Mesh / API Keys]

## Service Map

[Mermaid diagram of service dependencies]

## Security Surface Summary

| Risk | Location | Severity |
|------|----------|----------|
| No mTLS between services | docker-compose.yml | HIGH |
| Shared DB credentials | auth-service + user-service | MEDIUM |
| Unauthenticated health endpoint | /health leaks version | LOW |

## Per-Service Confidence

| Service | Confidence | Notes |
|---------|-----------|-------|
| api-gateway | 80 | Fully mapped |
| auth-service | 85 | JWT logic traced |
| user-service | 60 | DB layer not reviewed |
| product-service | 40 | Not started |
```
