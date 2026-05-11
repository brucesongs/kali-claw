# Codebase Onboarding Test Cases

## Test Case Summary

| ID | Name | Mode | Language | Status |
|----|------|------|----------|--------|
| TC-CO-001 | Django Web App Onboarding | Exploratory | Python | Active |
| TC-CO-002 | Go Microservice Security Audit Prep | Targeted | Go | Active |
| TC-CO-003 | Node.js Monorepo Architecture Map | Comprehensive | TypeScript | Active |
| TC-CO-004 | Legacy PHP Application | Exploratory | PHP | Active |
| TC-CO-005 | Large-Scale Java Monolith (100M+ LOC) | Comprehensive | Java | Active |

Total: 5 test cases

---

## TC-CO-001: Django Web App Onboarding

**Objective**: Map a Django web application for security audit preparation

**Mode**: Exploratory

**Target Profile**:
- Language: Python (Django 4.x)
- Scale: ~50,000 LOC, 20–30 modules
- Context: Black-box code review, no prior knowledge

**Phase 0 — Search-First**:
```
GIVEN: access to Django project root
WHEN: running discovery commands
THEN:
  - manage.py is found and identified as entry point
  - settings.py (or settings/) reveals database, installed apps, middleware
  - urls.py hierarchy is traced to find all URL patterns
  - requirements.txt reveals Django version and key packages
  - docs/ or README reveals deployment context
```

**Phase 1 — Orientation**:
```
GIVEN: Django project identified
WHEN: running orientation payloads
THEN:
  - Framework detected as Django from manage.py + INSTALLED_APPS
  - App directories identified (each app = functional module)
  - Custom middleware listed (often contains auth/logging)
  - Celery config found if async tasks present
```

**Phase 2 — Architecture Mapping**:
```
GIVEN: apps and URL patterns mapped
WHEN: tracing request flow
THEN:
  - URL → View → Template or URL → View → Serializer → Response
  - Model definitions found in models.py per app
  - Database relationships documented
  - Custom managers or querysets noted
```

**Phase 3 — Security Surface**:
```
GIVEN: views and models mapped
WHEN: running security surface payloads
THEN:
  - @login_required, @permission_required decorators located
  - CSRF exemptions (@csrf_exempt) flagged
  - Raw SQL queries found and marked as review candidates
  - File upload handlers identified
  - Admin interface customizations noted
```

**Expected Output**:
```json
{
  "framework": "Django 4.2",
  "apps": ["users", "products", "orders", "admin", "api"],
  "confidence": {"overall": 68, "auth": 80, "data_layer": 72, "api_surface": 75},
  "security_surfaces": {
    "csrf_exemptions": ["api/views.py:34", "webhook/views.py:12"],
    "raw_sql": ["reports/views.py:89"],
    "file_uploads": ["products/views.py:156"]
  }
}
```

**Pass Criteria**:
- [ ] All Django apps identified
- [ ] URL hierarchy mapped completely
- [ ] At least one security risk located with file:line reference
- [ ] Confidence score ≥ 60/100

---

## TC-CO-002: Go Microservice Security Audit Prep

**Objective**: Targeted onboarding of authentication microservice

**Mode**: Targeted

**Target Profile**:
- Language: Go (Gin framework)
- Scale: ~8,000 LOC, single service
- Context: Focused security audit of auth subsystem

**Phase 0 — Search-First**:
```
GIVEN: Go project with go.mod
WHEN: running discovery
THEN:
  - go.mod reveals module path and Go version
  - cmd/ directory shows entry points
  - internal/ vs pkg/ separation noted
  - JWT library (golang-jwt or similar) identified in go.mod
```

**Targeted Trace — Auth Flow**:
```
GIVEN: entry point found (cmd/server/main.go)
WHEN: tracing auth middleware
THEN:
  - middleware/ directory contains auth middleware
  - JWT validation function located with file:line
  - Token expiry and claim validation code reviewed
  - Refresh token mechanism found or absence noted
```

**Security Pattern Detection**:
```
GIVEN: auth code located
WHEN: running dangerous pattern detection
THEN:
  - Timing-safe comparison used for token comparison (constant time)
  - Token secrets loaded from environment (not hardcoded)
  - Authorization checks present on protected routes
  - Error messages don't leak user existence (user enumeration check)
```

**Expected Output**:
```
Auth subsystem confidence: 88/100

Entry: cmd/server/main.go:42 → router setup
Auth middleware: middleware/auth.go:18 → JWTMiddleware()
Token validation: internal/auth/jwt.go:34 → ValidateToken()
Protected routes: 14 routes under /api/v1/
RISK: middleware/auth.go:67 — error returns username in message (user enumeration)
RISK: internal/auth/jwt.go:89 — HS256 used (consider RS256 for public clients)
```

**Pass Criteria**:
- [ ] Auth middleware located within 5 commands
- [ ] Token validation function found with file:line
- [ ] At least one security observation made
- [ ] Total time: Targeted mode should complete in <30 minutes

---

## TC-CO-003: Node.js Monorepo Architecture Map

**Objective**: Comprehensive onboarding of a TypeScript monorepo

**Mode**: Comprehensive

**Target Profile**:
- Language: TypeScript (NestJS + React)
- Scale: ~200,000 LOC, monorepo (apps/ + packages/)
- Context: Full architecture map for pentest engagement scoping

**Phase 0 — Search-First**:
```
GIVEN: monorepo with package.json at root and workspaces
WHEN: running discovery
THEN:
  - package.json workspace configuration found
  - apps/ directory contains 2–5 deployable services
  - packages/ contains shared libraries
  - Each app has its own package.json with dependencies
  - CI/CD (GitHub Actions) reveals build and deploy pipeline
```

**Architecture Mapping**:
```
GIVEN: monorepo structure understood
WHEN: mapping all services
THEN:
  - Each app identified: api-server, web-frontend, admin-portal, worker
  - NestJS modules mapped: AuthModule, UserModule, PaymentModule, etc.
  - Shared packages identified: @company/auth, @company/db, @company/types
  - Inter-service communication: HTTP APIs + message queue (Bull/BullMQ)
  - Database: TypeORM entities found in packages/db/
```

**Security Surface**:
```
GIVEN: all services and shared packages mapped
WHEN: running security surface analysis
THEN:
  - Auth guards (@UseGuards) located per controller
  - Input validation (class-validator + class-transformer) usage mapped
  - File upload endpoints found
  - Admin panel access control reviewed
  - Rate limiting configuration found
```

**Expected Output**:
```
Architecture diagram generated (Mermaid)
Services: api-server (NestJS), web-frontend (Next.js), admin-portal (React), worker (Bull)
Shared: @company/auth, @company/db (TypeORM), @company/types
Confidence: overall=74, auth=82, data_layer=69, api_surface=80, frontend=65
Security surfaces: 3 unguarded admin routes, 1 missing rate limit, file upload in api-server
```

**Pass Criteria**:
- [ ] All services in monorepo identified
- [ ] Shared package dependency graph documented
- [ ] Mermaid diagram generated
- [ ] Security surface report covers all services
- [ ] Overall confidence ≥ 70/100

---

## TC-CO-004: Legacy PHP Application

**Objective**: Exploratory onboarding of legacy PHP codebase

**Mode**: Exploratory

**Target Profile**:
- Language: PHP 5.6–7.x (no framework, procedural)
- Scale: ~30,000 LOC, single app
- Context: Security review of legacy e-commerce site

**Challenges**:
- No framework structure (Tier 2 automation)
- Mixed procedural and OOP code
- Likely SQL injection and XSS vulnerabilities
- Possible hardcoded credentials

**Discovery Strategy**:
```
GIVEN: legacy PHP project
WHEN: no framework detected
THEN:
  - index.php is entry point
  - include/require chains traced manually
  - URL routing via GET parameters (e.g., ?page=home)
  - Database connection in config.php or db.php
  - Session management using PHP native sessions
```

**Security Surface Focus**:
```
GIVEN: PHP legacy codebase
WHEN: running legacy-focused security payloads
THEN:
  - mysql_query() or mysqli calls with string concatenation flagged
  - echo/print with $_GET/$_POST without sanitization flagged
  - include/require with variables flagged (LFI candidates)
  - file_get_contents/file_put_contents reviewed
  - eval() usage flagged immediately
  - Hardcoded DB credentials found in connection file
```

**Expected Output**:
```
Confidence: overall=55 (Tier 2/3 language limitations noted)
High-confidence findings:
  - CRITICAL: SQL injection in search.php:34 (string concat in query)
  - HIGH: XSS in product.php:89 (unescaped $_GET['name'])
  - HIGH: Hardcoded MySQL password in includes/db.php:5
  - MEDIUM: LFI candidate in admin/page.php:12 (include($_GET['page']))
Gaps: Payment processing module not reviewed
```

**Pass Criteria**:
- [ ] Legacy structure understood without framework docs
- [ ] At least 2 CRITICAL/HIGH security findings with file:line
- [ ] Hardcoded credentials or SQL injection identified
- [ ] Confidence score reported with Tier 2 caveat

---

## TC-CO-005: Large-Scale Java Monolith (100M+ LOC Strategy)

**Objective**: Demonstrate 100M+ LOC strategy on large Java monolith

**Mode**: Comprehensive (multi-session)

**Target Profile**:
- Language: Java (Spring Boot)
- Scale: ~2,000,000 LOC (simulated large enterprise app)
- Context: Pre-pentest engagement scoping

**Session 1 — Index and Baseline**:
```
GIVEN: large Java project with Maven multi-module structure
WHEN: running Index First strategy
THEN:
  - pom.xml hierarchy reveals module structure
  - ctags index generated before reading any source
  - Top-level modules listed: core, api, admin, reporting, batch, integration
  - Entry points: each module's Application.java
  - Git hotspots: top 20 most-changed files in 6 months
```

**Session 2 — Smart Sampling**:
```
GIVEN: module boundaries known
WHEN: applying Smart Sampling
THEN:
  - Focus on: api module (attack surface), core module (business logic)
  - Security-critical paths: authentication, authorization, payment processing
  - Sample 10% of files by: highest churn + security-relevant filenames
  - auth/, security/, payment/, admin/ directories prioritized
```

**Session 3 — Targeted Subsystem Analysis**:
```
GIVEN: high-priority modules identified
WHEN: running Targeted mode per subsystem
THEN:
  - Auth subsystem: Spring Security configuration found
  - WebSecurityConfigurerAdapter or SecurityFilterChain mapped
  - JWT filter chain traced
  - Method-level security (@PreAuthorize) usage surveyed
  - Admin endpoints identified and access control verified
```

**Expected Output (multi-session)**:
```json
{
  "sessions_completed": 3,
  "total_files_reviewed": 450,
  "pct_codebase_covered": "~5% (strategic sampling)",
  "confidence": {
    "overall": 61,
    "auth": 78,
    "api_surface": 70,
    "data_layer": 45,
    "internal_logic": 40,
    "batch_jobs": 20
  },
  "gaps": ["reporting module", "batch processing", "legacy SOAP services"],
  "high_risk_findings": [
    "admin/AdminController.java:234 — missing @PreAuthorize",
    "integration/ThirdPartyClient.java:89 — API key in application.properties"
  ]
}
```

**Pass Criteria**:
- [ ] Multi-session plan documented before starting
- [ ] Index-first approach used (ctags or Maven structure)
- [ ] Each session produces structured JSON output for knowledge-ops
- [ ] Overall confidence score reported with explicit gap list
- [ ] At least one security finding per session
