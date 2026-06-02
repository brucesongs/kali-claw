# Codebase Onboarding Payloads

Command reference organized by discovery phase. Run in order for systematic onboarding.

---

## Quick Start Checklist

Copy-paste sequence for any new codebase:

```bash
# 1. Get the lay of the land
find . -maxdepth 2 -type f | head -60
ls -la

# 2. Language and size
find . -name "*.py" -o -name "*.js" -o -name "*.ts" -o -name "*.go" \
  -o -name "*.java" -o -name "*.rb" -o -name "*.php" -o -name "*.rs" \
  | xargs wc -l 2>/dev/null | sort -rn | head -30

# 3. Find entry points
find . -name "main.*" -o -name "index.*" -o -name "app.*" \
  -o -name "server.*" -o -name "manage.py" -o -name "artisan" \
  | grep -v node_modules | grep -v ".git"

# 4. Dependency files
find . -maxdepth 3 \( -name "package.json" -o -name "go.mod" \
  -o -name "requirements.txt" -o -name "Cargo.toml" \
  -o -name "pom.xml" -o -name "build.gradle" -o -name "Gemfile" \
  -o -name "composer.json" \) | grep -v node_modules

# 5. Documentation
find . -maxdepth 3 -iname "readme*" -o -iname "architecture*" \
  -o -iname "contributing*" -o -iname "changelog*" | grep -v ".git"

# 6. Config files (may reveal secrets)
find . -name ".env*" -o -name "config.yml" -o -name "config.yaml" \
  -o -name "settings.py" -o -name "application.properties" \
  | grep -v ".git" | grep -v node_modules
```

---

## Phase 0: Pre-Read Discovery

### Documentation Hunt

```bash
# Find all markdown docs
find . -name "*.md" | grep -v node_modules | grep -v ".git" | sort

# Find OpenAPI specs
find . -name "*.yaml" -o -name "*.yml" | xargs grep -l "openapi\|swagger" 2>/dev/null

# Find Protobuf definitions
find . -name "*.proto" | grep -v ".git"

# Find architecture docs
find . -iname "arch*" -o -iname "design*" -o -iname "overview*" \
  | grep -v ".git" | grep -v node_modules

# CI/CD configuration
find . -name ".github" -o -name ".gitlab-ci.yml" -o -name "Jenkinsfile" \
  -o -name "Makefile" -o -name "Taskfile*" | grep -v node_modules
```

### Static Indexing (for large codebases)

```bash
# Generate ctags index
ctags -R --exclude=.git --exclude=node_modules --exclude=vendor .

# Cscope index (C/C++)
find . -name "*.c" -o -name "*.h" -o -name "*.cpp" > cscope.files
cscope -b -q -k

# Count symbols by type (Go example)
grep -r "^func " --include="*.go" . | wc -l
grep -r "^type " --include="*.go" . | wc -l

# Find all exported functions (Python)
grep -r "^def " --include="*.py" . | grep -v "def _" | wc -l
```

---

## Phase 1: Orientation Payloads

### File Distribution Analysis

```bash
# Count files by extension
find . -type f | grep -v ".git" | grep -v node_modules \
  | sed 's/.*\.//' | sort | uniq -c | sort -rn | head -20

# Largest files (likely most important)
find . -type f -name "*.py" | xargs wc -l 2>/dev/null | sort -rn | head -20
find . -type f -name "*.go" | xargs wc -l 2>/dev/null | sort -rn | head -20
find . -type f -name "*.ts" | xargs wc -l 2>/dev/null | sort -rn | head -20

# Most recently modified files (active development areas)
find . -type f -newer ./README.md | grep -v ".git" | grep -v node_modules \
  | head -30

# Git hotspots (files changed most often)
git log --name-only --pretty=format: | sort | uniq -c | sort -rn | head -20
```

### Framework Detection

```bash
# Python frameworks
grep -r "from django\|import django" --include="*.py" . -l 2>/dev/null | head -3
grep -r "from flask\|import flask\|Flask(" --include="*.py" . -l 2>/dev/null | head -3
grep -r "from fastapi\|import fastapi\|FastAPI(" --include="*.py" . -l 2>/dev/null | head -3

# JavaScript/TypeScript frameworks
cat package.json 2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin); print(list(d.get('dependencies',{}).keys())[:20])"
grep -r "express()\|require('express')\|from 'express'" --include="*.js" --include="*.ts" . -l | head -3
grep -r "NestFactory\|@Module\|@Controller" --include="*.ts" . -l | head -3

# Go frameworks
grep -r "gin.Default\|gin.New\|echo.New\|chi.NewRouter" --include="*.go" . -l | head -3
cat go.mod 2>/dev/null | head -30

# Java frameworks
grep -r "SpringApplication\|@SpringBootApplication" --include="*.java" . -l | head -3
cat pom.xml 2>/dev/null | grep -A1 "<artifactId>" | grep -v "artifactId" | head -20

# PHP frameworks
cat composer.json 2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin); print(list(d.get('require',{}).keys()))"
```

---

## Phase 2: Architecture Mapping Payloads

### Entry Point Tracing

```bash
# Python: Trace import chain from entry
python3 -c "import ast, sys
with open('app.py') as f:
    tree = ast.parse(f.read())
for node in ast.walk(tree):
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        print(ast.dump(node))" 2>/dev/null | head -30

# Go: Find all HTTP handler registrations
grep -rn "\.GET\|\.POST\|\.PUT\|\.DELETE\|\.HandleFunc\|\.Handle(" \
  --include="*.go" . | grep -v "_test.go" | head -30

# Express.js: Find all routes
grep -rn "app\.\(get\|post\|put\|delete\|patch\)\|router\.\(get\|post\|put\|delete\)" \
  --include="*.js" --include="*.ts" . | grep -v node_modules | head -30

# Django: URL patterns
find . -name "urls.py" | grep -v ".git"
grep -rn "path\|re_path\|url(" --include="urls.py" . | head -30

# Spring Boot: Controller mappings
grep -rn "@RequestMapping\|@GetMapping\|@PostMapping\|@PutMapping\|@DeleteMapping" \
  --include="*.java" . | head -30

# Laravel: Routes
cat routes/web.php routes/api.php 2>/dev/null | head -50
```

### Database Layer Discovery

```bash
# ORM model definitions
# Django
find . -name "models.py" | grep -v ".git"
grep -rn "class.*models.Model" --include="*.py" . | head -20

# SQLAlchemy
grep -rn "Base.metadata\|Column(\|declarative_base" --include="*.py" . -l | head -5

# Sequelize (Node.js)
find . -name "*.model.js" -o -name "*.model.ts" | grep -v node_modules

# GORM (Go)
grep -rn "gorm.Model\|AutoMigrate\|db.Create\|db.Find" --include="*.go" . | head -20

# Hibernate (Java)
grep -rn "@Entity\|@Table\|@Column" --include="*.java" . | head -20

# Raw SQL queries (security interest)
grep -rn "SELECT\|INSERT\|UPDATE\|DELETE" --include="*.py" --include="*.go" \
  --include="*.js" --include="*.ts" --include="*.php" . \
  | grep -v "_test\|test_\|// \|#" | grep -v node_modules | head -20
```

### Inter-Service Communication

```bash
# HTTP client calls (external APIs)
grep -rn "requests.get\|requests.post\|axios\.\|fetch(" \
  --include="*.py" --include="*.js" --include="*.ts" . \
  | grep -v node_modules | grep -v "_test" | head -20

# gRPC service definitions
find . -name "*.proto" | xargs grep -l "service " 2>/dev/null

# Message queue usage
grep -rn "kafka\|rabbitmq\|sqs\|pubsub\|celery\|sidekiq" \
  --include="*.py" --include="*.go" --include="*.js" --include="*.ts" \
  -il . | grep -v node_modules | head -10

# Environment variable usage (infrastructure dependencies)
grep -rn "os\.getenv\|os\.Getenv\|process\.env\.\|getenv(" \
  --include="*.py" --include="*.go" --include="*.js" . \
  | grep -v node_modules | head -30
```

---

## Phase 3: Security Surface Payloads

### Authentication Code Location

```bash
# JWT handling
grep -rn "jwt\|JWT\|jsonwebtoken\|decode_token\|verify_token" \
  --include="*.py" --include="*.go" --include="*.js" --include="*.ts" \
  --include="*.php" --include="*.java" . \
  | grep -v node_modules | grep -v "_test" | head -20

# Session management
grep -rn "session\['\|session\.get\|request\.session\|ctx\.Session" \
  --include="*.py" --include="*.go" --include="*.js" --include="*.ts" . \
  | grep -v node_modules | head -15

# Password hashing
grep -rn "bcrypt\|argon2\|pbkdf2\|hashpw\|check_password\|PasswordHasher" \
  --include="*.py" --include="*.go" --include="*.js" --include="*.ts" . \
  | grep -v node_modules | head -15

# OAuth/SSO
grep -rn "oauth\|OAuth\|openid\|SAML\|passport\.\|social_auth" \
  --include="*.py" --include="*.go" --include="*.js" --include="*.ts" . \
  -il | grep -v node_modules | head -10
```

### Dangerous Pattern Detection

```bash
# SQL injection candidates (string concatenation in queries)
grep -rn "SELECT.*%s\|SELECT.*+.*\|SELECT.*format(" \
  --include="*.py" --include="*.php" . | grep -v node_modules | head -10

grep -rn 'db\.Raw\|db\.Exec.*\+\|fmt\.Sprintf.*SELECT' \
  --include="*.go" . | head -10

# Command injection candidates
grep -rn "os\.system\|subprocess\.call\|exec\.\|eval(\|shell=True" \
  --include="*.py" . | grep -v "_test\|test_" | head -10

grep -rn "exec\.Command\|os/exec" --include="*.go" . | head -10

# Path traversal candidates
grep -rn "open(\|os\.path\.join\|filepath\.Join" \
  --include="*.py" --include="*.go" . \
  | grep -v node_modules | grep -v "_test" | head -15

# Hardcoded secrets
grep -rn "password\s*=\s*['\"][^'\"]*['\"]" \
  --include="*.py" --include="*.go" --include="*.js" . \
  | grep -v test | grep -v node_modules | head -10

grep -rn "api_key\s*=\s*['\"][^'\"]*['\"]" \
  --include="*.py" --include="*.go" --include="*.js" . \
  | grep -v test | grep -v node_modules | head -10

# XSS candidates (unescaped template output)
grep -rn "mark_safe\|autoescape\|Markup(\|innerHTML\s*=" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.html" . \
  | grep -v node_modules | head -10
```

### Dependency Vulnerability Surface

```bash
# Show all direct dependencies with versions
cat requirements.txt 2>/dev/null
cat package.json 2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin); [print(k,v) for k,v in d.get('dependencies',{}).items()]"
cat go.mod 2>/dev/null | grep "require" -A 100 | head -50
cat Cargo.toml 2>/dev/null | grep -A 100 "\[dependencies\]" | head -30

# Check for known vulnerable packages (requires safety/npm audit)
# pip install safety && safety check
# npm audit
# cargo audit
# govulncheck ./...
```

---

## Phase 4: Large Codebase Tactics

### Smart Sampling for 100M+ LOC

```bash
# Top 50 most-changed files in last 6 months
git log --since="6 months ago" --name-only --pretty=format: \
  | sort | uniq -c | sort -rn | head -50

# Files with highest cyclomatic complexity (Python)
# pip install radon
radon cc -s -a -n C . 2>/dev/null | head -30

# Find all public API surface (Go)
grep -rn "^func [A-Z]" --include="*.go" . \
  | grep -v "_test.go" | wc -l

# Module boundary analysis
cat go.mod | grep "^module"
ls -la cmd/ internal/ pkg/ api/ 2>/dev/null

# Critical path tracing: follow a single request
# 1. Find the router
# 2. Pick one endpoint
# 3. Trace handler → service → repository → query
# Document each hop with file:line
```

### Divide & Conquer Session Plan

```
For a 100M LOC monorepo, structure as:
Session 1: Top-level architecture + entry points (Targeted mode)
Session 2: Authentication subsystem (Targeted mode)
Session 3: Core business logic module A (Exploratory mode)
Session 4: Core business logic module B (Exploratory mode)
Session 5: Data layer + database schema (Targeted mode)
Session 6: External integrations + API surface (Targeted mode)
Session 7: Security surface synthesis (Comprehensive mode)

Each session: output structured JSON → store in knowledge-ops
```

---

## Mode-Specific Command Sequences

### Targeted Mode (15–30 min)

```bash
# Goal: understand specific subsystem
# 1. Find all files in target area
find . -path "*/auth/*" -o -path "*/payment/*" | grep -v node_modules

# 2. Map the entry point
grep -rn "def login\|func Login\|loginHandler\|auth.go" --include="*.py" \
  --include="*.go" --include="*.js" .

# 3. Trace call chain (3–5 hops)
# Read each file, follow function calls

# 4. Document findings
# Output: security surfaces + confidence score for subsystem
```

### Exploratory Mode (1–3 hours)

```bash
# Run full Phase 0 + Phase 1 + Phase 2
# For each major module:
for module in $(ls -d */); do
  echo "=== $module ==="
  find "$module" -type f | wc -l
  find "$module" -name "*.go" -o -name "*.py" -o -name "*.js" | \
    xargs wc -l 2>/dev/null | tail -1
done
```

### Comprehensive Mode (full session)

```bash
# Run all phases in sequence
# Generate complete intelligence package
# Minimum output:
# - Architecture diagram (Mermaid)
# - Confidence scores per subsystem
# - Security surface map
# - Identified risks with file:line references
# - Gaps list for follow-up sessions
```

---

## Phase 5: CI/CD and Build System Analysis

### Build Configuration Discovery

```bash
# Makefile targets
cat Makefile 2>/dev/null | grep -E "^[a-zA-Z_-]+:" | sed 's/:.*//g'

# Package.json scripts
cat package.json 2>/dev/null | jq '.scripts | keys[]'

# Docker build files
find . -name "Dockerfile*" -o -name "docker-compose*" | grep -v node_modules

# GitHub Actions workflows
ls .github/workflows/*.yml 2>/dev/null
grep -l "runs-on" .github/workflows/*.yml 2>/dev/null

# Terraform / IaC
find . -name "*.tf" -o -name "*.tfvars" | grep -v ".terraform" | head -20
```

### Pipeline Security Analysis

```bash
# Find secrets in CI configs
grep -rn "secret\|password\|token\|key" .github/workflows/ .gitlab-ci.yml Jenkinsfile 2>/dev/null \
  | grep -v "secrets\.\|Secret(" | head -10

# Check for dangerous CI patterns
grep -rn "curl.*|.*sh\|wget.*|.*bash" .github/workflows/ 2>/dev/null
grep -rn "npm install.*--ignore-scripts" .github/workflows/ 2>/dev/null

# Privileged container builds
grep -rn "privileged\|--privileged\|docker.sock" .github/workflows/ docker-compose* 2>/dev/null
```

### Deployment Configuration

```bash
# Kubernetes manifests
find . -name "*.yaml" -o -name "*.yml" | xargs grep -l "apiVersion.*apps\|kind.*Deployment" 2>/dev/null

# Exposed ports and services
grep -rn "containerPort\|hostPort\|nodePort" --include="*.yaml" --include="*.yml" . 2>/dev/null | head -15

# Service accounts and RBAC
grep -rn "serviceAccountName\|ClusterRole\|RoleBinding" --include="*.yaml" . 2>/dev/null | head -10

# Secrets in manifests (bad practice)
grep -rn "kind: Secret" --include="*.yaml" --include="*.yml" . 2>/dev/null
```

---

## Phase 6: Test Infrastructure Mapping

### Test Coverage Assessment

```bash
# Find test directories
find . -type d -name "test*" -o -type d -name "__tests__" -o -type d -name "spec" | grep -v node_modules

# Count test files vs source files
echo "Source files: $(find . -name '*.py' -o -name '*.go' -o -name '*.ts' | grep -v test | grep -v node_modules | wc -l)"
echo "Test files: $(find . -name '*_test.*' -o -name '*.test.*' -o -name '*_spec.*' | grep -v node_modules | wc -l)"

# Test framework detection
grep -rl "pytest\|unittest" --include="*.py" --include="*.cfg" --include="*.toml" . 2>/dev/null | head -3
grep -rl "jest\|mocha\|vitest" --include="*.json" --include="*.js" --include="*.ts" . 2>/dev/null | head -3
grep -rl "testing.T\|testify" --include="*.go" . 2>/dev/null | head -3
```

### Security Test Detection

```bash
# Find existing security tests
grep -rn "injection\|xss\|csrf\|auth.*bypass\|sanitize\|escape" \
  --include="*test*" --include="*spec*" . | grep -v node_modules | head -20

# Find fuzzing infrastructure
find . -name "*fuzz*" -o -name "*fuzzing*" | grep -v node_modules
grep -rn "Fuzz\|fuzz_target\|AFL\|libfuzzer" --include="*.go" --include="*.py" --include="*.c" . 2>/dev/null | head -10

# Integration test infrastructure
find . -name "docker-compose*test*" -o -name "docker-compose*integration*" 2>/dev/null
grep -rn "testcontainers\|test.*database\|test.*redis" --include="*.go" --include="*.py" --include="*.ts" . 2>/dev/null | head -10
```

---

## Phase 7: Code Ownership and Change Patterns

### Git History Analysis

```bash
# Most active files (hotspots = likely security-relevant)
git log --since="3 months ago" --name-only --pretty=format: | sort | uniq -c | sort -rn | head -20

# Files changed together (coupling detection)
git log --since="6 months ago" --name-only --pretty=format:"---" | awk '/^---$/{if(NR>1)for(i in f)for(j in f)if(i<j)print f[i]" <-> "f[j]; delete f; next}{f[$0]=$0}' | sort | uniq -c | sort -rn | head -15

# Contributors per module
for dir in $(ls -d */); do
    authors=$(git log --since="6 months ago" -- "$dir" --pretty=format:"%ae" | sort -u | wc -l)
    echo "$dir: $authors contributors"
done | sort -t: -k2 -rn | head -10

# Recent security-related commits
git log --since="6 months ago" --grep="security\|CVE\|vuln\|fix.*auth\|patch" --oneline | head -20
```

### Code Age Analysis

```bash
# Oldest files (potentially unmaintained, security debt)
git log --diff-filter=A --name-only --pretty=format:"%ai %H" -- "*.py" "*.go" "*.js" "*.ts" 2>/dev/null \
  | sort | head -20

# Files never modified since creation
git log --follow --oneline -- <file> | wc -l

# Dead code candidates (files not imported anywhere)
for f in $(find . -name "*.py" | grep -v test | grep -v __pycache__); do
    module=$(basename "$f" .py)
    refs=$(grep -r "import.*$module\|from.*$module" --include="*.py" . 2>/dev/null | grep -v "$f" | wc -l)
    [ "$refs" -eq 0 ] && echo "UNUSED: $f"
done 2>/dev/null | head -10
```

---

## Phase 8: API Surface Mapping

### OpenAPI/Swagger Discovery

```bash
# Find API documentation files
find . -name "swagger*" -o -name "openapi*" -o -name "api-spec*" | grep -v node_modules

# Extract endpoints from OpenAPI spec
cat openapi.yaml 2>/dev/null | grep -E "^\s+/[a-z]" | sort -u

# Auto-generate from code (Python/FastAPI)
python3 -c "
from importlib import import_module
import json
app = import_module('main').app
print(json.dumps(app.openapi(), indent=2))
" 2>/dev/null | jq '.paths | keys[]'
```

### GraphQL Schema Discovery

```bash
# Find GraphQL schema files
find . -name "*.graphql" -o -name "*.gql" | grep -v node_modules

# Extract types and queries
grep -rn "type Query\|type Mutation\|type Subscription" --include="*.graphql" --include="*.gql" --include="*.ts" --include="*.py" . 2>/dev/null

# Introspection query (if server running)
curl -s http://localhost:4000/graphql -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name fields{name}}}}"}' | jq '.data.__schema.types[] | select(.fields != null) | .name'
```

### REST Endpoint Extraction

```bash
# FastAPI/Flask route extraction
grep -rn "@app\.\(get\|post\|put\|delete\|patch\)\|@router\." --include="*.py" . | grep -v test | sort

# Express route extraction
grep -rn "router\.\|app\.\(get\|post\|put\|delete\)" --include="*.ts" --include="*.js" . \
  | grep -v node_modules | grep -v test | sort

# Spring Boot endpoint extraction
grep -rn "@\(Get\|Post\|Put\|Delete\|Patch\)Mapping\|@RequestMapping" --include="*.java" . | sort

# Go Chi/Gin route extraction
grep -rn "\.GET\|\.POST\|\.PUT\|\.DELETE\|\.Group\|\.Route" --include="*.go" . | grep -v test | sort
```

---

## Architecture Discovery

### Dependency Graphs

```bash
# Python — generate import dependency graph
python3 << 'EOF'
import ast, os, json
from pathlib import Path

deps = {}
for py_file in Path(".").rglob("*.py"):
    if "node_modules" in str(py_file) or ".git" in str(py_file):
        continue
    try:
        tree = ast.parse(py_file.read_text())
        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.append(node.module)
        deps[str(py_file)] = imports
    except (SyntaxError, UnicodeDecodeError):
        pass

# Output as adjacency list
for file, imports in sorted(deps.items()):
    local_imports = [i for i in imports if not i.startswith(("os", "sys", "json", "re", "typing"))]
    if local_imports:
        print(f"{file} -> {', '.join(local_imports[:10])}")
EOF

# Go — module dependency graph
go mod graph | head -50
go mod graph | awk '{print $1}' | sort -u | wc -l  # Count direct deps

# Node.js — dependency tree (depth-limited)
npm ls --depth=2 --json 2>/dev/null | jq '.dependencies | keys[]'
npx depcheck --json 2>/dev/null | jq '{unused: .dependencies, missing: .missing}'

# Visualize with Graphviz (Python)
pipdeptree --graph-output png > evidence/dependency_graph.png 2>/dev/null
pipdeptree --json | jq '.[].dependencies[].package_name' | sort -u
```

### Module Boundaries

```bash
# Identify module boundaries by package/directory structure
find . -name "__init__.py" -o -name "go.mod" -o -name "package.json" \
  | grep -v node_modules | grep -v ".git" | sort

# Go — list all packages and their sizes
find . -name "*.go" -not -path "./.git/*" -not -name "*_test.go" \
  | xargs -I{} dirname {} | sort -u | while read -r pkg; do
    files=$(find "$pkg" -maxdepth 1 -name "*.go" -not -name "*_test.go" | wc -l)
    lines=$(find "$pkg" -maxdepth 1 -name "*.go" -not -name "*_test.go" | xargs wc -l 2>/dev/null | tail -1 | awk '{print $1}')
    echo "$lines lines | $files files | $pkg"
done | sort -rn | head -20

# TypeScript — find barrel exports (module boundaries)
find . -name "index.ts" -o -name "index.js" | grep -v node_modules | while read -r f; do
  exports=$(grep -c "^export" "$f" 2>/dev/null)
  echo "$exports exports | $f"
done | sort -rn | head -20

# Detect circular dependencies (Python)
python3 -c "
import importlib, sys
from pathlib import Path
# Simple cycle detection via import tracing
seen = set()
for f in Path('.').rglob('*.py'):
    if 'test' in str(f) or '.git' in str(f): continue
    print(f'Checking: {f}')
" 2>/dev/null

# Find cross-module imports (potential coupling issues)
grep -rn "from \.\." --include="*.py" . | grep -v test | grep -v ".git" | head -20
grep -rn "import.*internal" --include="*.go" . | grep -v test | head -20
```

### API Surface Mapping

```bash
# Extract all public API endpoints with HTTP methods
echo "=== REST API Surface ===" > evidence/api_surface.txt

# FastAPI/Flask
grep -rn "@app\.\|@router\." --include="*.py" . | grep -v test \
  | sed 's/.*@//' | sort >> evidence/api_surface.txt

# Express/NestJS
grep -rn "\.get\|\.post\|\.put\|\.delete\|\.patch\|@Get\|@Post\|@Put\|@Delete" \
  --include="*.ts" --include="*.js" . | grep -v node_modules | grep -v test \
  | sort >> evidence/api_surface.txt

# Go (Chi/Gin/Echo)
grep -rn "\.GET\|\.POST\|\.PUT\|\.DELETE\|HandleFunc\|Handle(" \
  --include="*.go" . | grep -v test | sort >> evidence/api_surface.txt

# Count total endpoints
echo "Total endpoints: $(wc -l < evidence/api_surface.txt)"

# Find undocumented endpoints (no swagger/openapi annotation)
grep -rn "app\.\(get\|post\)" --include="*.py" . | grep -v "swagger\|openapi\|doc" | head -10
```

### Internal Communication Patterns

```bash
# Map service-to-service communication
echo "=== Service Communication Map ===" > evidence/service_map.txt

# HTTP clients (outbound calls)
grep -rn "httpx\.\|requests\.\|axios\.\|fetch(\|http\.Get\|http\.Post" \
  --include="*.py" --include="*.go" --include="*.ts" --include="*.js" . \
  | grep -v node_modules | grep -v test >> evidence/service_map.txt

# gRPC connections
grep -rn "grpc\.Dial\|grpc\.NewClient\|createChannel\|GrpcClient" \
  --include="*.go" --include="*.ts" --include="*.py" . \
  | grep -v test >> evidence/service_map.txt

# Message queue producers/consumers
grep -rn "publish\|subscribe\|send_message\|receive_message\|enqueue\|dequeue" \
  --include="*.py" --include="*.go" --include="*.ts" . \
  | grep -v node_modules | grep -v test | head -20 >> evidence/service_map.txt

# Database connections
grep -rn "connect\|createPool\|NewClient\|dial\|DSN\|connection_string" \
  --include="*.py" --include="*.go" --include="*.ts" . \
  | grep -iE "postgres|mysql|mongo|redis|elastic" \
  | grep -v node_modules | grep -v test >> evidence/service_map.txt
```

### Mermaid Architecture Diagram Generation

```bash
# Auto-generate Mermaid diagram from discovered architecture
python3 << 'EOF'
import os, re
from pathlib import Path

services = set()
connections = []

# Scan for service definitions
for f in Path(".").rglob("*.py"):
    if ".git" in str(f) or "test" in str(f):
        continue
    content = f.read_text(errors="ignore")
    # Find HTTP client calls
    for match in re.finditer(r'(requests|httpx)\.(get|post)\(["\']https?://([^/\'"]+)', content):
        services.add(str(f.parent.name))
        connections.append((str(f.parent.name), match.group(3).split(":")[0]))

print("graph LR")
for src, dst in set(connections):
    print(f"    {src} --> {dst}")
EOF
```

---

## Security-Focused Code Navigation

### Auth Flow Tracing

```bash
# Trace authentication flow from entry to token validation
echo "=== Authentication Flow ===" > evidence/auth_flow.txt

# Find login/auth endpoints
grep -rn "login\|authenticate\|sign_in\|signin" \
  --include="*.py" --include="*.go" --include="*.ts" --include="*.js" . \
  | grep -v node_modules | grep -v test | grep -v ".git" \
  | sort >> evidence/auth_flow.txt

# Find token generation
grep -rn "generate_token\|sign(\|jwt\.encode\|jwt\.sign\|create_access_token" \
  --include="*.py" --include="*.go" --include="*.ts" . \
  | grep -v test >> evidence/auth_flow.txt

# Find middleware/guards
grep -rn "middleware\|guard\|interceptor\|before_request\|authenticate" \
  --include="*.py" --include="*.go" --include="*.ts" . \
  | grep -v test | grep -v node_modules >> evidence/auth_flow.txt

# Find authorization checks
grep -rn "has_permission\|is_admin\|role.*check\|authorize\|can(\|ability" \
  --include="*.py" --include="*.go" --include="*.ts" . \
  | grep -v test | grep -v node_modules >> evidence/auth_flow.txt

# Find session management
grep -rn "session\.\|cookie\.\|set_cookie\|clear_session\|destroy_session" \
  --include="*.py" --include="*.go" --include="*.ts" . \
  | grep -v test | grep -v node_modules >> evidence/auth_flow.txt
```

### Data Path Analysis

```bash
# Trace sensitive data from input to storage
echo "=== Sensitive Data Paths ===" > evidence/data_paths.txt

# User input entry points
grep -rn "request\.body\|request\.form\|request\.json\|req\.body\|r\.Body\|FormValue\|QueryParam" \
  --include="*.py" --include="*.go" --include="*.ts" --include="*.js" . \
  | grep -v test | grep -v node_modules | head -30 >> evidence/data_paths.txt

# Data transformation/validation
grep -rn "validate\|sanitize\|escape\|clean\|filter\|marshal\|serialize" \
  --include="*.py" --include="*.go" --include="*.ts" . \
  | grep -v test | grep -v node_modules | head -20 >> evidence/data_paths.txt

# Data storage operations
grep -rn "\.save\|\.create\|\.insert\|\.update\|db\.Exec\|\.execute(" \
  --include="*.py" --include="*.go" --include="*.ts" . \
  | grep -v test | grep -v node_modules | head -20 >> evidence/data_paths.txt

# PII handling
grep -rn "email\|phone\|address\|ssn\|credit_card\|password" \
  --include="*.py" --include="*.go" --include="*.ts" . \
  | grep -iE "encrypt\|hash\|mask\|redact" | grep -v test | head -10 >> evidence/data_paths.txt

# Data output/response
grep -rn "response\.\|render\|jsonify\|json\.Marshal\|res\.json\|res\.send" \
  --include="*.py" --include="*.go" --include="*.ts" . \
  | grep -v test | grep -v node_modules | head -20 >> evidence/data_paths.txt
```

### Trust Boundary Identification

```bash
# Map trust boundaries in the application
echo "=== Trust Boundaries ===" > evidence/trust_boundaries.txt

# External API calls (crossing trust boundary)
grep -rn "https\?://\|grpc\.Dial\|net\.Dial" \
  --include="*.py" --include="*.go" --include="*.ts" . \
  | grep -v test | grep -v node_modules \
  | awk -F: '{print $1":"$2}' | sort -u >> evidence/trust_boundaries.txt

# File system access (trust boundary with OS)
grep -rn "open(\|os\.Open\|fs\.readFile\|writeFile\|os\.Create" \
  --include="*.py" --include="*.go" --include="*.ts" . \
  | grep -v test | grep -v node_modules | head -20 >> evidence/trust_boundaries.txt

# Process execution (trust boundary — command injection risk)
grep -rn "subprocess\|os\.system\|exec\.Command\|child_process\|spawn\|execSync" \
  --include="*.py" --include="*.go" --include="*.ts" --include="*.js" . \
  | grep -v test | grep -v node_modules >> evidence/trust_boundaries.txt

# Deserialization points (trust boundary — RCE risk)
grep -rn "pickle\.load\|yaml\.load\|json\.loads\|unmarshal\|deserialize\|JSON\.parse" \
  --include="*.py" --include="*.go" --include="*.ts" . \
  | grep -v test | grep -v node_modules >> evidence/trust_boundaries.txt

# Network listeners (trust boundary — external input)
grep -rn "listen\|bind\|serve\|ListenAndServe\|createServer" \
  --include="*.py" --include="*.go" --include="*.ts" . \
  | grep -v test | grep -v node_modules >> evidence/trust_boundaries.txt
```

### Privilege Escalation Paths in Code

```bash
# Find code paths that change privilege levels
echo "=== Privilege Transitions ===" > evidence/privilege_paths.txt

# Role/permission changes
grep -rn "set_role\|grant\|elevate\|promote\|add_permission\|setAdmin\|makeAdmin" \
  --include="*.py" --include="*.go" --include="*.ts" . \
  | grep -v test | grep -v node_modules >> evidence/privilege_paths.txt

# Sudo/root operations
grep -rn "sudo\|setuid\|setgid\|os\.setuid\|syscall\.Setuid\|RunAsUser" \
  --include="*.py" --include="*.go" --include="*.ts" . \
  | grep -v test >> evidence/privilege_paths.txt

# Service account usage
grep -rn "service_account\|impersonate\|assume_role\|sts\.AssumeRole" \
  --include="*.py" --include="*.go" --include="*.ts" . \
  | grep -v test >> evidence/privilege_paths.txt

# Debug/admin endpoints (often unprotected)
grep -rn "debug\|admin\|internal\|backdoor\|bypass" \
  --include="*.py" --include="*.go" --include="*.ts" . \
  | grep -iE "route\|endpoint\|handler\|path" \
  | grep -v test | grep -v node_modules >> evidence/privilege_paths.txt
```

---

## Automated Documentation Generation

### API Documentation Extraction

```bash
# Generate API documentation from code annotations
python3 << 'EOF'
import ast, json
from pathlib import Path

endpoints = []
for f in Path(".").rglob("*.py"):
    if "test" in str(f) or ".git" in str(f) or "node_modules" in str(f):
        continue
    try:
        tree = ast.parse(f.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                for decorator in node.decorator_list:
                    dec_str = ast.dump(decorator)
                    if any(m in dec_str for m in ["get", "post", "put", "delete", "route"]):
                        endpoints.append({
                            "file": str(f),
                            "line": node.lineno,
                            "function": node.name,
                            "docstring": ast.get_docstring(node) or "No documentation",
                        })
    except (SyntaxError, UnicodeDecodeError):
        pass

for ep in sorted(endpoints, key=lambda x: x["file"]):
    print(f"  {ep['file']}:{ep['line']} — {ep['function']}")
    if ep['docstring'] != "No documentation":
        print(f"    {ep['docstring'][:100]}")
EOF

# Go — extract godoc comments for exported functions
grep -rn -B2 "^func [A-Z]" --include="*.go" . | grep -v test | head -40

# TypeScript — extract JSDoc comments
grep -rn -B3 "export.*function\|export.*class\|export.*const" \
  --include="*.ts" . | grep -v node_modules | grep -E "\/\*\*|export" | head -40
```

### Architecture Diagram Generation

```bash
# Generate PlantUML component diagram from imports
python3 << 'EOF'
import ast, re
from pathlib import Path
from collections import defaultdict

modules = defaultdict(set)
for f in Path(".").rglob("*.py"):
    if any(x in str(f) for x in [".git", "test", "node_modules", "__pycache__"]):
        continue
    try:
        tree = ast.parse(f.read_text())
        module_name = str(f.parent).replace("/", ".").lstrip(".")
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                if not node.module.startswith(("os", "sys", "json", "typing", "re")):
                    modules[module_name].add(node.module.split(".")[0])
    except (SyntaxError, UnicodeDecodeError):
        pass

print("@startuml")
print("' Auto-generated component diagram")
for mod, deps in sorted(modules.items()):
    for dep in sorted(deps):
        if dep in modules:  # Only internal dependencies
            print(f"[{mod}] --> [{dep}]")
print("@enduml")
EOF

# Generate Mermaid flowchart from Go call graph
go-callvis -group pkg -focus main ./... 2>/dev/null | head -50

# TypeScript — generate dependency graph with madge
npx madge --image evidence/dependency_graph.svg src/ 2>/dev/null
npx madge --circular src/ 2>/dev/null | tee evidence/circular_deps.txt
```

### Dependency Tree Documentation

```bash
# Full dependency tree with license info
pip-licenses --format=json 2>/dev/null | jq '.[] | {Name, Version, License}' | head -50

# npm — full dependency tree with sizes
npm ls --all --json 2>/dev/null | jq '{
  direct: (.dependencies | keys | length),
  total: [.. | .dependencies? // empty | keys[]] | length
}'

# Go — dependency tree with why analysis
go mod why -m <module_name> 2>/dev/null
go mod graph | grep -c "^" | xargs echo "Total dependency edges:"

# Security-relevant dependency info
pip-audit --format=json 2>/dev/null | jq '.[] | select(.vulns | length > 0) | {name, version, vulns: [.vulns[].id]}'
npm audit --json 2>/dev/null | jq '.vulnerabilities | to_entries[] | {pkg: .key, severity: .value.severity, via: .value.via[0]}'

# Generate SBOM (Software Bill of Materials)
syft . -o spdx-json > evidence/sbom.spdx.json 2>/dev/null
cyclonedx-py --format json -o evidence/sbom.cdx.json 2>/dev/null
```

### README and Onboarding Doc Generation

```bash
# Auto-generate project summary from code analysis
generate_project_summary() {
  echo "# Project Summary (Auto-Generated)"
  echo ""
  echo "## Language Distribution"
  find . -type f -name "*.py" -o -name "*.go" -o -name "*.ts" -o -name "*.js" \
    | grep -v node_modules | grep -v ".git" \
    | sed 's/.*\.//' | sort | uniq -c | sort -rn
  echo ""
  echo "## Entry Points"
  find . -name "main.*" -o -name "index.*" -o -name "app.*" \
    | grep -v node_modules | grep -v ".git"
  echo ""
  echo "## Key Directories"
  find . -maxdepth 2 -type d | grep -v ".git" | grep -v node_modules | sort
  echo ""
  echo "## External Dependencies Count"
  echo "  Python: $(cat requirements*.txt 2>/dev/null | grep -v "^#" | wc -l)"
  echo "  Node: $(cat package.json 2>/dev/null | jq '.dependencies | length' 2>/dev/null)"
  echo "  Go: $(cat go.mod 2>/dev/null | grep -c '\t')"
}
generate_project_summary | tee evidence/project_summary.txt
```

---

## Code Complexity Analysis

### Cyclomatic Complexity

```bash
# Python — radon complexity analysis
radon cc -s -a -n C . 2>/dev/null | tee evidence/complexity.txt
radon cc -s -j . 2>/dev/null | jq '[.[] | .[] | select(.complexity > 10)] | sort_by(-.complexity) | .[:20]'

# Python — maintainability index
radon mi -s . 2>/dev/null | grep -E "^[A-F]" | sort | head -20

# Go — gocyclo complexity
gocyclo -over 10 . 2>/dev/null | sort -rn | head -20
gocyclo -avg . 2>/dev/null

# TypeScript/JavaScript — eslint complexity rule
npx eslint --rule '{"complexity": ["error", 10]}' --format json src/ 2>/dev/null \
  | jq '[.[].messages[] | {file: .ruleId, line: .line, message: .message}]' | head -30

# Generic — count decision points per function
grep -rn "if \|else \|for \|while \|case \|catch \|&&\|||" \
  --include="*.py" --include="*.go" --include="*.ts" . \
  | grep -v test | grep -v node_modules \
  | awk -F: '{print $1}' | sort | uniq -c | sort -rn | head -20
```

### Coupling Metrics

```bash
# Afferent coupling (Ca) — who depends on this module?
# Efferent coupling (Ce) — what does this module depend on?
python3 << 'EOF'
import ast
from pathlib import Path
from collections import defaultdict

imports_from = defaultdict(set)  # module -> set of modules it imports
imported_by = defaultdict(set)   # module -> set of modules that import it

for f in Path(".").rglob("*.py"):
    if any(x in str(f) for x in [".git", "test", "node_modules", "__pycache__"]):
        continue
    module = str(f).replace("/", ".").rstrip(".py")
    try:
        tree = ast.parse(f.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                target = node.module.split(".")[0]
                imports_from[module].add(target)
                imported_by[target].add(module)
    except (SyntaxError, UnicodeDecodeError):
        pass

print("=== Highest Afferent Coupling (most depended upon) ===")
for mod, dependents in sorted(imported_by.items(), key=lambda x: len(x[1]), reverse=True)[:10]:
    print(f"  {mod}: {len(dependents)} dependents")

print("\n=== Highest Efferent Coupling (most dependencies) ===")
for mod, deps in sorted(imports_from.items(), key=lambda x: len(x[1]), reverse=True)[:10]:
    print(f"  {mod}: {len(deps)} dependencies")
EOF

# Go — package coupling via import analysis
for pkg in $(find . -name "*.go" -not -path "./.git/*" | xargs dirname | sort -u); do
  imports=$(grep -h "^import\|\"" "$pkg"/*.go 2>/dev/null | grep -c "\"")
  echo "$imports imports | $pkg"
done | sort -rn | head -15
```

### Hotspot Detection

```bash
# Git churn + complexity = hotspots (high-risk files)
# Files that change often AND are complex are the riskiest

# Step 1: Get change frequency (last 6 months)
git log --since="6 months ago" --name-only --pretty=format: \
  | sort | uniq -c | sort -rn | head -30 > /tmp/churn.txt

# Step 2: Get complexity scores
radon cc -s -j . 2>/dev/null | jq -r '.[] | .[] | "\(.complexity) \(.filename)"' \
  | sort -rn > /tmp/complexity.txt 2>/dev/null

# Step 3: Correlate (files appearing in both lists are hotspots)
echo "=== HOTSPOTS (High Churn + High Complexity) ==="
while read -r count file; do
  complexity=$(grep "$file" /tmp/complexity.txt 2>/dev/null | awk '{print $1}' | head -1)
  if [ -n "$complexity" ] && [ "$complexity" -gt 5 ]; then
    risk_score=$((count * complexity))
    echo "RISK=$risk_score | changes=$count complexity=$complexity | $file"
  fi
done < /tmp/churn.txt | sort -t= -k2 -rn | head -15

# Alternative: use git-of-theseus for code age analysis
# pip install git-of-theseus
# git-of-theseus-analyze . --outdir evidence/theseus/
```

### Code Duplication Detection

```bash
# Python — find duplicate code blocks
# pip install pylint
pylint --disable=all --enable=duplicate-code --min-similarity-lines=6 \
  $(find . -name "*.py" -not -path "./.git/*" -not -path "*/test*") 2>/dev/null \
  | grep -A5 "Similar lines" | head -40

# Generic — find similar files by content hash
find . -name "*.py" -o -name "*.go" -o -name "*.ts" | grep -v node_modules | grep -v ".git" \
  | while read -r f; do
    hash=$(md5sum "$f" | awk '{print $1}')
    echo "$hash $f"
done | sort | uniq -D -w32 | tee evidence/duplicate_files.txt

# Find copy-paste patterns (repeated code blocks)
grep -rn "TODO\|FIXME\|HACK\|XXX\|WORKAROUND" \
  --include="*.py" --include="*.go" --include="*.ts" . \
  | grep -v node_modules | grep -v ".git" | tee evidence/tech_debt.txt

# jscpd — copy-paste detector for multiple languages
npx jscpd --min-lines 5 --reporters json --output evidence/ . 2>/dev/null
```

### Function Size and File Size Analysis

```bash
# Find oversized functions (>50 lines)
python3 << 'EOF'
import ast
from pathlib import Path

oversized = []
for f in Path(".").rglob("*.py"):
    if any(x in str(f) for x in [".git", "test", "node_modules"]):
        continue
    try:
        tree = ast.parse(f.read_text())
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                size = node.end_lineno - node.lineno + 1
                if size > 50:
                    oversized.append((size, str(f), node.lineno, node.name))
    except (SyntaxError, UnicodeDecodeError):
        pass

print("=== Oversized Functions (>50 lines) ===")
for size, file, line, name in sorted(oversized, reverse=True)[:20]:
    print(f"  {size:4d} lines | {file}:{line} | {name}")
EOF

# Find oversized files (>800 lines)
find . -name "*.py" -o -name "*.go" -o -name "*.ts" -o -name "*.js" \
  | grep -v node_modules | grep -v ".git" \
  | xargs wc -l 2>/dev/null | sort -rn | awk '$1 > 800 {print "[OVERSIZED] "$0}' | head -15

# Nesting depth analysis
grep -rn "^\s*" --include="*.py" . | awk -F: '{
  gsub(/[^ \t].*/, "", $3)
  depth = gsub(/    /, "", $3)
  if(depth > 4) print depth" levels | "$1":"$2
}' | sort -rn | head -10
```

---

## Dependency Graph Generation

### Visual Dependency Graph with Graphviz

```bash
# Generate a visual dependency graph from Python imports using Graphviz
python3 << 'EOF'
import ast
from pathlib import Path
from collections import defaultdict

edges = defaultdict(int)
for f in Path(".").rglob("*.py"):
    if any(x in str(f) for x in [".git", "test", "node_modules", "__pycache__", "venv"]):
        continue
    src = str(f.parent.name) or "root"
    try:
        tree = ast.parse(f.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                pkg = node.module.split(".")[0]
                if not pkg.startswith(("os", "sys", "json", "re", "typing", "collections")):
                    edges[(src, pkg)] += 1
    except (SyntaxError, UnicodeDecodeError):
        pass

print("digraph deps {")
print("  rankdir=LR; node [shape=box];")
for (src, dst), weight in sorted(edges.items(), key=lambda x: -x[1])[:30]:
    print(f'  "{src}" -> "{dst}" [weight={weight}];')
print("}")
EOF

# Go — visualize module dependency graph
go mod graph | awk -F' ' '{print "\""$1"\" -> \""$2"\""}' | \
  head -50 | awk 'BEGIN{print "digraph godeps {rankdir=LR;"} {print "  "$0} END{print "}"}'

# Node.js — dependency graph via dependency-cruiser
npx dependency-cruiser --include-only-reaches "src/" --output-type dot src/ | dot -Tpng -o dep-graph.png
```

### Architecture Documentation Generator

```bash
# Generate a structured architecture document from codebase analysis
python3 << 'EOF'
import os
import re
from pathlib import Path
from collections import defaultdict

layers = defaultdict(lambda: {"files": 0, "lines": 0, "languages": set()})
layer_patterns = {
    "Controllers": r"(controller|handler|route|endpoint)",
    "Services": r"(service|usecase|interactor|manager)",
    "Repositories": r"(repository|dao|store|model|entity)",
    "Configuration": r"(config|setting|constant|env)",
    "Utilities": r"(util|helper|common|shared|lib)",
    "Tests": r"(test|spec|mock|fixture)",
}

for f in Path(".").rglob("*"):
    if any(x in str(f) for x in [".git", "node_modules", "__pycache__", ".venv"]):
        continue
    if f.is_file() and f.suffix in (".py", ".ts", ".go", ".js", ".java"):
        matched = False
        for layer, pattern in layer_patterns.items():
            if re.search(pattern, str(f).lower()):
                try:
                    lines = len(f.read_text().splitlines())
                    layers[layer]["files"] += 1
                    layers[layer]["lines"] += lines
                    layers[layer]["languages"].add(f.suffix)
                except: pass
                matched = True
                break
        if not matched:
            try:
                lines = len(f.read_text().splitlines())
                layers["Other"]["files"] += 1
                layers["Other"]["lines"] += lines
                layers["Other"]["languages"].add(f.suffix)
            except: pass

print("| Layer | Files | Lines | Languages |")
print("|-------|-------|-------|-----------|")
for layer, info in sorted(layers.items(), key=lambda x: -x[1]["lines"]):
    langs = ", ".join(sorted(info["languages"]))
    print(f"| {layer} | {info['files']} | {info['lines']} | {langs} |")
EOF
```

### Call Graph Tracing

```bash
# Python — trace function call graph with static analysis
python3 << 'EOF'
import ast
from pathlib import Path
from collections import defaultdict

call_graph = defaultdict(set)
for f in Path(".").rglob("*.py"):
    if any(x in str(f) for x in [".git", "test", "node_modules", "__pycache__"]):
        continue
    try:
        tree = ast.parse(f.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                caller = node.name
                for child in ast.walk(node):
                    if isinstance(child, ast.Call):
                        if isinstance(child.func, ast.Name):
                            call_graph[caller].add(child.func.id)
                        elif isinstance(child.func, ast.Attribute):
                            call_graph[caller].add(child.func.attr)
    except (SyntaxError, UnicodeDecodeError):
        pass

for caller, callees in sorted(call_graph.items()):
    for callee in sorted(callees):
        if callee in call_graph:
            print(f"  {caller} -> {callee}")
EOF

# Go — static call graph visualization
go callgraph -format digraph ./... 2>/dev/null | head -50

# Generate Mermaid sequence diagram from discovered endpoints
echo "sequenceDiagram"
echo "  participant Client"
echo "  participant Router"
echo "  participant Handler"
echo "  participant Service"
echo "  participant Repository"
echo "  Client->>Router: HTTP Request"
echo "  Router->>Handler: Dispatch"
echo "  Handler->>Service: Business Logic"
echo "  Service->>Repository: Data Access"
echo "  Repository-->>Service: Result"
echo "  Service-->>Handler: Response"
echo "  Handler-->>Client: HTTP Response"
```

### API Surface Documentation Generator

```python
#!/usr/bin/env python3
"""Auto-generate API documentation from discovered route handlers."""
import ast
import json
from pathlib import Path

endpoints = []
for f in Path(".").rglob("*.py"):
    if any(x in str(f) for x in [".git", "test", "node_modules", "__pycache__"]):
        continue
    try:
        tree = ast.parse(f.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                for dec in node.decorator_list:
                    dec_str = ast.dump(dec)
                    for method in ["get", "post", "put", "delete", "patch"]:
                        if f'"{method}"' in dec_str or f"'{method}'" in dec_str:
                            path = "/"
                            if isinstance(dec, ast.Call) and len(dec.args) > 0:
                                if isinstance(dec.args[0], ast.Constant):
                                    path = dec.args[0.value]
                            endpoints.append({
                                "file": str(f),
                                "line": node.lineno,
                                "method": method.upper(),
                                "path": path,
                                "handler": node.name,
                                "docstring": ast.get_docstring(node) or "",
                            })
    except (SyntaxError, UnicodeDecodeError):
        pass

print(f"Total endpoints discovered: {len(endpoints)}")
print("\n| Method | Path | Handler | File | Docstring |")
print("|--------|------|---------|------|-----------|")
for ep in sorted(endpoints, key=lambda x: (x["method"], x["path"])):
    doc = ep["docstring"][:40] + "..." if len(ep["docstring"]) > 40 else ep["docstring"]
    print(f"| {ep['method']} | {ep['path']} | {ep['handler']} | {ep['file']}:{ep['line']} | {doc or 'N/A'} |")
```

### Tech Stack Identification Report

```bash
# Auto-detect technology stack and generate a summary report
python3 << 'EOF'
import os
import json
from pathlib import Path

STACK_SIGNATURES = {
    "Python": ["requirements.txt", "setup.py", "pyproject.toml", "Pipfile"],
    "Node.js": ["package.json", "yarn.lock", "pnpm-lock.yaml"],
    "Go": ["go.mod", "go.sum"],
    "Rust": ["Cargo.toml", "Cargo.lock"],
    "Java": ["pom.xml", "build.gradle", "build.gradle.kts"],
    "PHP": ["composer.json", "artisan"],
    "Ruby": ["Gemfile", "Gemfile.lock"],
    "Docker": ["Dockerfile", "docker-compose.yml"],
    "Kubernetes": ["k8s/", "helm/", "charts/"],
    "Terraform": ["main.tf", "variables.tf"],
}

FRAMEWORK_MAP = {
    "django": ("Python", "Django"), "flask": ("Python", "Flask"),
    "fastapi": ("Python", "FastAPI"), "express": ("Node.js", "Express"),
    "nestjs": ("Node.js", "NestJS"), "react": ("Node.js", "React"),
    "gin-gonic": ("Go", "Gin"), "spring-boot": ("Java", "Spring Boot"),
    "laravel": ("PHP", "Laravel"), "rails": ("Ruby", "Ruby on Rails"),
}

detected = []
for tech, sigs in STACK_SIGNATURES.items():
    for sig in sigs:
        matches = list(Path(".").rglob(sig))
        if matches:
            detected.append({"technology": tech, "evidence": [str(m) for m in matches[:3]]})

print("# Technology Stack Report\n")
print("| Technology | Evidence |")
print("|------------|----------|")
for item in detected:
    print(f"| {item['technology']} | {', '.join(item['evidence'][:2])} |")
print(f"\nTotal technologies detected: {len(detected)}")
EOF
```

### Documentation Coverage Scanner

```bash
# Check which functions and classes are missing docstrings or comments
python3 << 'EOF'
import ast
from pathlib import Path

undocumented = []
for f in Path(".").rglob("*.py"):
    if any(x in str(f) for x in [".git", "test", "node_modules", "__pycache__", "venv"]):
        continue
    try:
        tree = ast.parse(f.read_text())
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                doc = ast.get_docstring(node)
                if not doc:
                    kind = "class" if isinstance(node, ast.ClassDef) else "function"
                    undocumented.append((str(f), node.lineno, kind, node.name))
    except (SyntaxError, UnicodeDecodeError):
        pass

total = len(undocumented)
print(f"### Documentation Coverage\n")
print(f"Found **{total}** undocumented symbols:\n")
print("| File | Line | Type | Name |")
print("|------|------|------|------|")
for file, line, kind, name in sorted(undocumented)[:30]:
    print(f"| {file} | {line} | {kind} | `{name}` |")
if total > 30:
    print(f"\n... and {total - 30} more")
EOF
```
