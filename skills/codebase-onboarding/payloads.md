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
