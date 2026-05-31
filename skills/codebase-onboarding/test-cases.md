# Codebase Onboarding Test Cases

## Test Case Summary

| ID | Name | Mode | Language | Status |
|----|------|------|----------|--------|
| TC-CO-001 | Django Web App Onboarding | Exploratory | Python | Active |
| TC-CO-002 | Go Microservice Security Audit Prep | Targeted | Go | Active |
| TC-CO-003 | Node.js Monorepo Architecture Map | Comprehensive | TypeScript | Active |
| TC-CO-004 | Legacy PHP Application | Exploratory | PHP | Active |
| TC-CO-005 | Large-Scale Java Monolith (100M+ LOC) | Comprehensive | Java | Active |
| TC-CO-006 | Ruby on Rails API Onboarding | Exploratory | Ruby | Active |
| TC-CO-007 | Rust Binary Security Audit Prep | Targeted | Rust | Active |
| TC-CO-008 | C/C++ Legacy Binary Reverse Engineering Prep | Exploratory | C/C++ | Active |
| TC-CO-009 | Flutter/Dart Mobile App Onboarding | Comprehensive | Dart | Active |
| TC-CO-010 | GraphQL API Security Audit Prep | Targeted | TypeScript | Active |

Total: 10 test cases

---

## TC-CO-001: Django Web App Onboarding

**Objective**: Map a Django web application for security audit preparation

**Severity**: HIGH

**Mode**: Exploratory

**Prerequisites**:
- Django project source code accessible on local filesystem
- Python 3.8+ environment with project dependencies resolvable
- Basic familiarity with Django project structure (manage.py, settings, urls, apps)
- Code reading tool or IDE available for file navigation
- No prior knowledge of the application (black-box approach)

**Remediation**: If onboarding reveals security gaps (e.g., missing auth decorators, raw SQL), create a prioritized remediation list ordered by severity. Common fixes include adding `@login_required` to unprotected views, replacing raw SQL with ORM calls, and enabling CSRF protection on all state-changing endpoints.

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

**Severity**: HIGH

**Mode**: Targeted

**Prerequisites**:
- Go project source code accessible with go.mod present
- Go toolchain installed for `go list` and `go vet` commands
- Targeted scope defined: authentication subsystem only
- JWT library usage expected (golang-jwt or similar)
- Service architecture follows standard Go layout (cmd/, internal/, pkg/)

**Remediation**: Address user enumeration by returning generic error messages for both invalid username and invalid password cases. Migrate from HS256 to RS256 when the JWT consumer is a public client. Ensure token secrets are loaded from environment variables or a secrets manager, never hardcoded.

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

**Severity**: MEDIUM

**Mode**: Comprehensive

**Prerequisites**:
- Node.js monorepo with workspace configuration in root package.json
- TypeScript and NestJS framework expected in backend services
- Access to CI/CD configuration files (GitHub Actions, GitLab CI, etc.)
- At least 2 deployable services under apps/ directory
- Package manager (npm, yarn, or pnpm) installed

**Remediation**: Add `@UseGuards(AuthGuard)` to all unprotected admin routes. Enable rate limiting via `@nestjs/throttler` on authentication and password-reset endpoints. Validate all file upload payloads with strict MIME type and size checks. Review shared package boundaries for privilege escalation paths.

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

**Severity**: CRITICAL

**Mode**: Exploratory

**Prerequisites**:
- Legacy PHP 5.6-7.x source code accessible (no framework, procedural style)
- No autoloader or PSR-4 structure expected
- Understanding of common legacy PHP vulnerability patterns
- grep, find, and file search tools available
- Ability to trace include/require chains manually

**Remediation**: Replace all `mysql_query()` calls with PDO prepared statements. Escape all user input echoed in HTML using `htmlspecialchars()` or a templating engine. Move hardcoded database credentials to environment variables or a secrets file outside the web root. Replace dynamic include paths with an allowlist of valid page names.

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

**Severity**: HIGH

**Mode**: Comprehensive (multi-session)

**Prerequisites**:
- Large Java/Spring Boot project with Maven multi-module structure
- Maven or Gradle build tool installed for dependency analysis
- ctags or equivalent code indexing tool available
- Sufficient time budget for multi-session approach (3+ sessions planned)
- Git history available for hotspot analysis

**Remediation**: Add `@PreAuthorize` annotations to all admin controller methods. Move API keys from `application.properties` to a secrets manager (HashiCorp Vault, AWS Secrets Manager). Review and restrict Spring Security filter chain to enforce consistent authorization across all endpoints. Schedule follow-up sessions for uncovered gap areas.

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

---

## TC-CO-006: Ruby on Rails API Onboarding

**Objective**: Exploratory onboarding of a Ruby on Rails API-only application for security review

**Severity**: HIGH

**Mode**: Exploratory

**Prerequisites**:
- Rails application source code accessible (Rails 6+ expected)
- Ruby environment with bundler available
- PostgreSQL or MySQL database schema accessible
- Understanding of Rails conventions (MVC, routes, strong parameters)
- No prior knowledge of the application

**Remediation**: If strong parameters are missing on controllers, add `params.require(:model).permit(:field1, :field2)` to all create/update actions. Replace any `eval` or `send` calls with safe alternatives. Ensure all API endpoints require authentication via `before_action`.

**Target Profile**:
- Language: Ruby (Rails 7.x, API-only mode)
- Scale: ~40,000 LOC, 15 controllers
- Context: Security audit of payment processing API

**Phase 0 — Search-First**:
```
GIVEN: Rails project root with Gemfile
WHEN: running discovery commands
THEN:
  - config/routes.rb reveals all API endpoints
  - Gemfile.lock reveals Rails version and key gems (devise, pundit, etc.)
  - db/schema.rb reveals database structure and relationships
  - app/controllers/ lists all controller files
  - config/initializers/ reveals authentication and session configuration
```

**Architecture Mapping**:
```
GIVEN: routes and controllers identified
WHEN: tracing request flow
THEN:
  - Route → Controller → Service Object or Model → Response
  - Authentication via Devise or custom JWT
  - Authorization via Pundit policies or cancancan
  - Background jobs via Sidekiq (job/ directory)
  - API versioning in routes (namespace :v1, :v2)
```

**Security Surface**:
```
GIVEN: controllers and models mapped
WHEN: running security surface analysis
THEN:
  - Strong parameters verified on all POST/PUT/PATCH endpoints
  - Mass assignment vulnerabilities flagged
  - SQL injection via raw SQL (Model.find_by_sql) flagged
  - Unsafe deserialization (YAML.load) flagged
  - File upload handling reviewed
  - API rate limiting configuration found or absence noted
```

**Expected Output**:
```
Framework: Rails 7.0 (API-only)
Controllers: 15 (Users, Sessions, Payments, Orders, Admin, ...)
Auth: Devise-JWT (token-based)
Authorization: Pundit (missing on 3 admin controllers)
Confidence: overall=72, auth=80, api_surface=75, data_layer=68
Security surfaces:
  - HIGH: Admin::DashboardController missing Pundit authorization
  - HIGH: PaymentsController#webhook skips authentication (no before_action)
  - MEDIUM: OrdersController uses raw SQL in search method
  - LOW: No rate limiting on authentication endpoints
```

**Pass Criteria**:
- [ ] All API routes mapped from config/routes.rb
- [ ] Authentication mechanism identified (JWT, session, API key)
- [ ] At least 2 security observations with file:line references
- [ ] Confidence score >= 65/100

---

## TC-CO-007: Rust Binary Security Audit Prep

**Objective**: Targeted onboarding of a Rust binary for security audit preparation

**Severity**: MEDIUM

**Mode**: Targeted

**Prerequisites**:
- Rust project source code accessible with Cargo.toml
- Rust toolchain installed (rustc, cargo)
- Understanding of Rust safety model (unsafe blocks, FFI)
- `cargo audit` and `cargo geiger` available
- Target: cryptographic library within the project

**Remediation**: If unsafe blocks are found, review each one for memory safety violations (buffer overflow, use-after-free, null pointer dereference). Update dependencies with known CVEs using `cargo update`. Replace custom cryptographic implementations with audited crates (ring, rustls).

**Target Profile**:
- Language: Rust (edition 2021)
- Scale: ~15,000 LOC, single crate with 3 modules
- Context: Security audit of custom crypto implementation

**Discovery Strategy**:
```
GIVEN: Rust project with Cargo.toml
WHEN: running discovery
THEN:
  - Cargo.toml reveals dependencies and feature flags
  - src/ directory structure mapped (lib.rs, modules)
  - unsafe usage located via cargo geiger
  - FFI (extern "C") calls identified
  - Test coverage assessed via cargo tarpaulin
```

**Security Pattern Detection**:
```
GIVEN: crypto module identified
WHEN: running security-focused analysis
THEN:
  - All unsafe blocks listed with file:line
  - Panic paths in crypto functions (should not panic)
  - Timing-safe comparisons used for secret comparison
  - Proper zeroization of sensitive memory
  - No unwraps on secret-dependent operations
```

**Expected Output**:
```
Rust edition: 2021
Crate type: lib
Dependencies: 12 (3 with known advisories)
Unsafe blocks: 8 (4 in crypto module, 4 in FFI bridge)
Confidence: overall=78, crypto_module=85, ffi_bridge=60, safe_rust=90
Security surfaces:
  - CRITICAL: custom AES implementation in src/crypto/aes.rs (use ring crate instead)
  - HIGH: unsafe block at src/ffi/bridge.rs:45 — raw pointer dereference without null check
  - MEDIUM: dependency `sha2 v0.9.0` has known advisory (upgrade to 0.10.x)
  - LOW: 3 unwrap() calls in src/crypto/mod.rs on secret-dependent paths
```

**Pass Criteria**:
- [ ] All unsafe blocks located with file:line references
- [ ] Dependencies audited via `cargo audit`
- [ ] At least one security finding in crypto module
- [ ] FFI boundary documented with risk assessment
- [ ] Confidence score >= 70/100

---

## TC-CO-008: C/C++ Legacy Binary Reverse Engineering Prep

**Objective**: Exploratory onboarding of a legacy C/C++ binary for reverse engineering preparation

**Severity**: CRITICAL

**Mode**: Exploratory

**Prerequisites**:
- Compiled binary available (ELF or PE format)
- Source code available (mixed C and C++)
- Ghidra or IDA Pro available for disassembly reference
- Understanding of memory corruption vulnerability patterns
- Build system available (Make, CMake, or Autotools)

**Remediation**: Replace all `strcpy`, `strcat`, `sprintf` with length-checked alternatives (`strncpy`, `strncat`, `snprintf`). Enable compiler hardening flags (`-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`, `-pie`). Implement ASLR and DEP/NX-compatible code patterns.

**Target Profile**:
- Language: C/C++ (C99/C++11)
- Scale: ~80,000 LOC, monolithic binary
- Context: Vulnerability research on network daemon

**Discovery Strategy**:
```
GIVEN: C/C++ source with Makefile
WHEN: running discovery
THEN:
  - Makefile/CMakeLists.txt reveals build configuration
  - Source tree mapped: src/, include/, lib/
  - Entry point identified (main() or WinMain)
  - Network-facing functions located (socket, bind, accept, recv)
  - Signal handlers and daemonization code found
```

**Security Pattern Detection**:
```
GIVEN: source tree mapped
WHEN: running dangerous pattern detection
THEN:
  - Buffer overflow candidates: strcpy, strcat, sprintf, gets
  - Format string vulnerabilities: printf(user_input), syslog(user_input)
  - Integer overflow: unchecked arithmetic on lengths/sizes
  - Use-after-free: free() followed by access without NULL set
  - Command injection: system(), popen() with user input
  - Hardcoded credentials in source
```

**Expected Output**:
```
Binary: network_daemon (ELF x86_64)
Build system: Autotools (configure.ac, Makefile.am)
Network surfaces: 3 (TCP listener on 8080, UDP on 514, Unix socket)
Confidence: overall=65, network_surface=80, memory_safety=55, crypto=40
Security surfaces:
  - CRITICAL: gets() in src/client_handler.c:234 — buffer overflow
  - CRITICAL: system() in src/admin.c:89 — command injection
  - HIGH: sprintf() in src/logging.c:156 — buffer overflow
  - HIGH: printf(user_input) in src/debug.c:67 — format string
  - MEDIUM: Hardcoded password in src/auth.c:12
```

**Pass Criteria**:
- [ ] Build system and entry points identified
- [ ] All network-facing functions located
- [ ] At least 3 dangerous function calls flagged with file:line
- [ ] Hardcoded credentials search completed
- [ ] Confidence score reported with memory safety caveat

---

## TC-CO-009: Flutter/Dart Mobile App Onboarding

**Objective**: Comprehensive onboarding of a Flutter mobile application for security testing

**Severity**: MEDIUM

**Mode**: Comprehensive

**Prerequisites**:
- Flutter project source code accessible with pubspec.yaml
- Flutter SDK and Dart SDK installed
- Understanding of Flutter widget tree and state management
- Mobile security testing experience (Android/iOS)
- APK/IPA build tools available

**Remediation**: If API keys are hardcoded in Dart source, move them to secure storage (flutter_secure_storage). If SSL pinning is absent, implement it using the `http` package with custom `SecurityContext`. If local storage contains sensitive data unencrypted, enable encryption with `flutter_secure_storage` or Hive with encryption.

**Target Profile**:
- Language: Dart (Flutter 3.x)
- Scale: ~60,000 LOC, cross-platform mobile app
- Context: Pre-pentest scoping of banking mobile application

**Phase 0 — Search-First**:
```
GIVEN: Flutter project with pubspec.yaml
WHEN: running discovery
THEN:
  - pubspec.yaml reveals dependencies (http, dio, flutter_secure_storage, etc.)
  - lib/ directory contains main.dart and feature modules
  - AndroidManifest.xml and Info.plist reveal permissions
  - API endpoints found in lib/services/ or lib/api/
  - State management pattern identified (Provider, Bloc, Riverpod)
```

**Architecture Mapping**:
```
GIVEN: Flutter project structure understood
WHEN: mapping all components
THEN:
  - UI layer: lib/screens/ or lib/pages/
  - Business logic: lib/bloc/ or lib/providers/ or lib/controllers/
  - Data layer: lib/services/ or lib/repositories/
  - Models: lib/models/
  - Navigation: named routes or GoRouter configuration
  - Platform channels: MethodChannel usage for native code
```

**Security Surface**:
```
GIVEN: architecture mapped
WHEN: running mobile security analysis
THEN:
  - API keys/tokens in source code (hardcoded)
  - SSL/TLS configuration (certificate pinning present/absent)
  - Local storage usage (SharedPreferences, SQLite, Hive)
  - Platform channel security (input validation on native calls)
  - Deep link handling and URL scheme registration
  - Obfuscation status (build configuration)
```

**Expected Output**:
```
Framework: Flutter 3.19 (Dart 3.3)
Platforms: Android + iOS
State management: Bloc (flutter_bloc)
Dependencies: 28 (3 with known vulnerabilities)
Confidence: overall=71, auth=78, api_surface=75, local_storage=65, platform_channels=55
Security surfaces:
  - CRITICAL: API key hardcoded in lib/services/api_client.dart:15
  - HIGH: No SSL certificate pinning in HTTP client
  - HIGH: Sensitive data in SharedPreferences (lib/services/auth_service.dart:45)
  - MEDIUM: Deep link handler lacks input validation (lib/main.dart:67)
  - LOW: Code obfuscation not enabled in build configuration
```

**Pass Criteria**:
- [ ] All feature modules identified in lib/
- [ ] State management pattern documented
- [ ] API endpoints extracted from service layer
- [ ] At least one hardcoded secret found or all confirmed absent
- [ ] SSL pinning status verified (present/absent)
- [ ] Confidence score >= 65/100

---

## TC-CO-010: GraphQL API Security Audit Prep

**Objective**: Targeted onboarding of a GraphQL API for security testing

**Severity**: HIGH

**Mode**: Targeted

**Prerequisites**:
- GraphQL API endpoint accessible
- Introspection enabled or schema document available
- GraphQL client tools available (graphql-cli, inql, graphw00f)
- Understanding of GraphQL security patterns (injection, DoS, authorization)
- Backend language/framework identified

**Remediation**: If introspection is enabled in production, disable it. If query depth is unbounded, implement depth limiting and query complexity analysis. If authorization is missing at the field level, implement directive-based authorization. If batch queries allow brute force, add rate limiting per query.

**Target Profile**:
- Language: TypeScript (Apollo Server) or Python (Graphene)
- Scale: ~100 types, 50 mutations, 200 queries
- Context: Security audit of public-facing GraphQL API

**Discovery Strategy**:
```
GIVEN: GraphQL endpoint URL
WHEN: running discovery
THEN:
  - Introspection query returns full schema
  - graphw00f identifies GraphQL engine
  - SDL (Schema Definition Language) exported
  - Playground/GraphiQL interface accessible (or not)
  - Batch query support tested
```

**Security Pattern Detection**:
```
GIVEN: full schema available
WHEN: running GraphQL security analysis
THEN:
  - Unauthenticated queries/mutations identified
  - Sensitive types (User, Payment, Admin) enumerated
  - Nested query depth analyzed (DoS potential)
  - Custom scalar validation present or absent
  - Subscription endpoints checked for authentication
  - File upload mutations identified
```

**Expected Output**:
```
GraphQL Engine: Apollo Server 4.x (TypeScript)
Schema: 120 types, 55 mutations, 210 queries, 15 subscriptions
Introspection: ENABLED (should be disabled in production)
Confidence: overall=76, auth=72, dos_surface=85, injection=70
Security surfaces:
  - CRITICAL: Introspection enabled in production
  - HIGH: Query depth unbounded (max depth = unlimited)
  - HIGH: Batch queries accepted (up to 10 per request — brute force risk)
  - MEDIUM: 12 mutations lack authentication directives
  - LOW: Custom scalars for email/URL lack server-side validation
```

**Pass Criteria**:
- [ ] Full schema obtained via introspection or documentation
- [ ] GraphQL engine and version identified
- [ ] All mutations checked for authentication requirements
- [ ] Query depth/complexity limits tested
- [ ] At least 2 security observations documented
- [ ] Confidence score >= 70/100
