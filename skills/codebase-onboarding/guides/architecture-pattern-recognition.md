# Architecture Pattern Recognition Guide

Recognize common architecture patterns from code signals — before reading the full codebase.

---

## Why Pattern Recognition Matters

The first 10 minutes of codebase onboarding should answer: "What kind of system is this?" The answer shapes everything — where to look, what security patterns to expect, and how to prioritize reading.

---

## Pattern Detection Signals

### Signal 1: Entry Point Shape

```bash
# Single main → monolith
find . -name "main.go" -o -name "main.py" -o -name "server.js" | grep -v test | wc -l
# Count = 1: likely monolith
# Count = 3-10: likely microservices (one per service)
# Count = 0: likely serverless or library

# Multiple cmd/ directories → microservices (Go pattern)
ls cmd/ 2>/dev/null

# Functions as entry points → serverless
find . -name "handler.py" -o -name "handler.js" -o -name "lambda.py" | head -5
grep -rn "exports.handler\|lambda_handler\|def handler" \
  --include="*.py" --include="*.js" . | head -5
```

### Signal 2: Dependency File Shape

```bash
# Single package.json at root → single service or monolith
# Multiple package.json → monorepo or microservices
find . -name "package.json" | grep -v node_modules | wc -l

# workspace field in root package.json → monorepo
grep -rn '"workspaces"' package.json 2>/dev/null

# go.work → Go workspace (multi-module monorepo)
cat go.work 2>/dev/null

# Multiple go.mod files → separate Go services
find . -name "go.mod" | grep -v vendor | wc -l
```

### Signal 3: Infrastructure Files

```bash
# Terraform → cloud infrastructure
find . -name "*.tf" | wc -l

# Kubernetes YAML → containerized deployment
find . -name "*.yaml" -path "*/k8s/*" | wc -l

# Docker Compose → local multi-service dev
cat docker-compose.yml 2>/dev/null | grep "^  [a-z]" | wc -l  # count services

# Serverless framework
cat serverless.yml 2>/dev/null | head -20
cat serverless.yaml 2>/dev/null | head -20
find . -name "template.yaml" -o -name "template.yml" | xargs grep -l "AWS::Serverless" 2>/dev/null
```

---

## Common Architecture Patterns

### Pattern 1: MVC Monolith

**Signals**:
- Single entry point
- `controllers/`, `models/`, `views/` or `templates/` directories
- Single database config
- Framework: Django, Rails, Laravel, Spring MVC

**Security Focus**:
- All attack surface in one place
- Database is the crown jewel
- Check: IDOR (insecure direct object references), mass assignment, CSRF
- Audit: controller parameter handling, model validation

```bash
# MVC detection
ls -la app/ src/ | grep -E "controller|model|view|template"
grep -rn "render\|redirect_to\|response\|template" \
  --include="*.py" --include="*.rb" --include="*.php" . | head -10
```

### Pattern 2: REST API + Frontend SPA

**Signals**:
- Backend API (JSON responses only, no templates)
- Separate frontend directory (`frontend/`, `client/`, `web/`)
- CORS configuration present
- JWT or session tokens for auth

**Security Focus**:
- API authorization on every endpoint
- JWT implementation quality
- CORS misconfiguration
- Input validation at API boundary (frontend validation is not enough)

```bash
# API detection
grep -rn "application/json\|json.Marshal\|json.dumps\|JSONResponse\|jsonify(" \
  --include="*.go" --include="*.py" --include="*.js" . | grep -v test | head -10

# Frontend directory
ls -la frontend/ client/ web/ dist/ build/ 2>/dev/null

# CORS config
grep -rn "AllowOrigins\|allow_origins\|Access-Control-Allow-Origin" \
  --include="*.go" --include="*.py" --include="*.js" --include="*.ts" . | head -5
```

### Pattern 3: Microservices

**Signals**:
- Multiple Dockerfiles
- docker-compose with 4+ services
- Service-specific config files
- Service discovery or DNS-based service addressing

**Security Focus**:
- Service-to-service authentication
- API gateway security
- Overly permissive network policies
- Shared secrets between services
- Sidechannel: which services can reach the database directly?

```bash
# Microservice detection
find . -name "Dockerfile" | grep -v node_modules | wc -l  # > 3 = microservices
cat docker-compose.yml | grep "^  [a-z]" | sed 's/://'

# Inter-service HTTP calls
grep -rn "http://.*:3[0-9][0-9][0-9]\|http://.*-service\|http://.*-svc" \
  --include="*.go" --include="*.py" --include="*.js" . \
  | grep -v node_modules | head -10
```

### Pattern 4: Event-Driven / CQRS

**Signals**:
- Message queue dependencies (Kafka, RabbitMQ, SQS)
- `events/`, `handlers/`, `consumers/`, `producers/` directories
- Command and Query separation
- Event sourcing patterns

**Security Focus**:
- Message authentication (can attackers inject messages?)
- Consumer idempotency (replay attacks)
- Event schema validation
- Poison message handling

```bash
# Event-driven detection
find . -name "*.go" -o -name "*.py" -o -name "*.js" | \
  xargs grep -l "Consumer\|Producer\|EventHandler\|MessageHandler" 2>/dev/null | head -5

grep -rn "kafka\|rabbitmq\|sqs\|sns\|pubsub\|eventbus\|event_bus" \
  --include="*.go" --include="*.py" --include="*.js" . -il | head -5

# CQRS pattern
find . -name "*Command.go" -o -name "*Query.go" -o -name "*command.py" \
  -o -name "*query.py" | grep -v test | head -10
```

### Pattern 5: Serverless Functions

**Signals**:
- `serverless.yml` or AWS SAM `template.yaml`
- Lambda handler functions
- No long-running processes
- Infrastructure defined in YAML

**Security Focus**:
- IAM role permissions (often over-privileged)
- Cold start timing attacks
- Environment variable exposure
- Layer vulnerabilities (shared Lambda layers)
- API Gateway authorization

```bash
# Serverless detection
cat serverless.yml 2>/dev/null | grep "handler\:" | head -20
find . -name "handler.py" -o -name "handler.js" -o -name "handler.go" | head -10

# IAM roles (critical for privilege escalation research)
grep -rn "Effect.*Allow\|Action.*\*\|Resource.*\*" \
  --include="*.yaml" --include="*.yml" --include="*.json" . \
  | grep -v node_modules | head -10
```

### Pattern 6: GraphQL API

**Signals**:
- `schema.graphql` or `.gql` files
- GraphQL libraries (Apollo, Strawberry, gqlgen, graphene)
- `/graphql` endpoint
- Resolver functions

**Security Focus**:
- Schema introspection (should be disabled in production)
- Batch query depth attacks
- Authorization in resolvers (missing field-level auth)
- N+1 query attacks (DataLoader usage check)
- Subscription security

```bash
# GraphQL detection
find . -name "*.graphql" -o -name "*.gql" | grep -v node_modules | head -10
grep -rn "graphql\|ApolloServer\|strawberry\|graphene\|gqlgen" \
  --include="*.go" --include="*.py" --include="*.js" --include="*.ts" . \
  -il | grep -v node_modules | head -5

# Introspection enabled check
grep -rn "introspection.*false\|disableIntrospection\|IntrospectionQuery" \
  --include="*.go" --include="*.py" --include="*.js" --include="*.ts" . \
  | grep -v node_modules | head -5

# Resolver auth checks
grep -rn "def resolve_\|resolve(" --include="*.py" . | grep -v test | head -10
```

---

## Data Layer Patterns

### ORM vs Raw SQL

```bash
# ORM usage (safer by default)
grep -rn "\.filter(\|\.where(\|\.find_by\|\.query\." \
  --include="*.py" --include="*.rb" --include="*.js" . | grep -v test | head -10

# Raw SQL (manual review required)
grep -rn "cursor\.execute\|db\.Exec\|\.Raw(\|connection\.query\|QueryBuilder" \
  --include="*.py" --include="*.go" --include="*.js" . | grep -v test | head -10

# Query builders (risk depends on parameterization)
grep -rn "qb\.\|QueryBuilder\|Knex\|\$wpdb->" \
  --include="*.js" --include="*.ts" --include="*.php" . \
  | grep -v node_modules | head -10
```

### Caching Patterns

```bash
# Redis caching
grep -rn "redis\.\|\.get(\|\.set(\|cache\." \
  --include="*.go" --include="*.py" --include="*.js" . \
  | grep -i "cache\|redis" | grep -v test | head -10

# Security interest: what is cached? Is sensitive data cached?
grep -rn "cache.*user\|cache.*token\|cache.*session\|cache.*password" \
  --include="*.go" --include="*.py" --include="*.js" . \
  | grep -v test | head -5
```

---

## Anti-Pattern Detection

Flags that indicate security risks regardless of architecture:

```bash
# 1. Business logic in the database (stored procedures)
grep -rn "CALL\|EXECUTE\|sp_\|CREATE PROCEDURE" \
  --include="*.py" --include="*.go" --include="*.js" --include="*.sql" . | head -5

# 2. Flat files used as database
find . -name "*.json" -o -name "*.csv" | xargs grep -l "password\|token\|secret" \
  2>/dev/null | grep -v node_modules | head -5

# 3. Client-side authorization (never trust the client)
grep -rn "localStorage.*role\|sessionStorage.*admin\|client.*isAdmin" \
  --include="*.js" --include="*.ts" . | grep -v node_modules | head -5

# 4. Debug/dev endpoints in production code
grep -rn "debug.*true\|DEBUG.*=.*True\|dev.*mode\|development.*mode" \
  --include="*.py" --include="*.go" --include="*.js" . \
  | grep -v node_modules | grep -v test | head -10

# 5. Admin functionality mixed with regular user code
grep -rn "is_admin\|isAdmin\|role.*admin\|admin.*role" \
  --include="*.py" --include="*.go" --include="*.js" . \
  | grep -v node_modules | grep -v test | head -10
```

---

## Architecture Summary Template

Fill this in after pattern recognition phase (should take < 15 minutes):

```
Architecture Type: [MVC Monolith / REST+SPA / Microservices / Serverless / Event-Driven / GraphQL]
Primary Language: [language]
Framework: [framework]
Scale: [~LOC, # services]
Deployment: [Docker / Kubernetes / Serverless / Bare metal]
Database: [type + ORM or raw SQL]
Auth Model: [JWT / Sessions / OAuth2 / API Keys]
Message Queue: [yes/no, type]
Caching: [yes/no, Redis/Memcached]

Primary Security Concern for this Architecture:
[One sentence identifying the highest-risk attack vector for this pattern]

Recommended Onboarding Mode: [Targeted / Exploratory / Comprehensive]
Recommended First Focus: [subsystem or component to start with]
```
