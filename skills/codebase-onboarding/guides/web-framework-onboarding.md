# Web Framework Onboarding Guide

Fast-path onboarding for the most common web frameworks. Each section covers: directory structure, entry points, routing, auth pattern, and security surface.

---

## Django (Python)

### Directory Structure

```
project/
├── manage.py              ← CLI entry point
├── project/
│   ├── settings.py        ← All config (or settings/ directory)
│   ├── urls.py            ← Root URL configuration
│   ├── wsgi.py            ← WSGI entry point
│   └── asgi.py            ← ASGI entry point
├── app1/
│   ├── models.py          ← Database models
│   ├── views.py           ← Request handlers
│   ├── urls.py            ← App URL patterns
│   ├── serializers.py     ← DRF serializers (if REST API)
│   ├── admin.py           ← Admin panel customizations
│   └── tests.py           ← Tests
└── requirements.txt
```

### Entry Points

```bash
# Main entry point
cat manage.py | head -20

# URL hierarchy
grep -rn "include(" project/urls.py  # finds app URL includes
find . -name "urls.py" | xargs grep -l "urlpatterns"

# WSGI/ASGI servers
cat project/wsgi.py
grep -rn "application" project/wsgi.py
```

### Auth Pattern Detection

```bash
# Django built-in auth
grep -rn "from django.contrib.auth" --include="*.py" . | head -10
grep -rn "@login_required\|LoginRequiredMixin" --include="*.py" . | head -10

# Django REST Framework auth
grep -rn "authentication_classes\|permission_classes\|IsAuthenticated" \
  --include="*.py" . | head -10

# Custom auth backends
grep -rn "AUTHENTICATION_BACKENDS" project/settings.py

# Session config
grep -rn "SESSION_ENGINE\|SESSION_COOKIE" project/settings.py
```

### Security Surface

```bash
# CSRF exemptions (dangerous)
grep -rn "@csrf_exempt" --include="*.py" . | head -10

# Debug mode (must be False in production)
grep -rn "^DEBUG" project/settings.py

# Allowed hosts
grep -rn "ALLOWED_HOSTS" project/settings.py

# Secret key (should not be hardcoded)
grep -rn "^SECRET_KEY" project/settings.py

# SECURE_ settings
grep -rn "^SECURE_\|^SESSION_COOKIE_SECURE\|^CSRF_COOKIE_SECURE" project/settings.py

# Raw SQL
grep -rn "\.raw(\|cursor\.execute(" --include="*.py" . | grep -v test | head -10

# File uploads
grep -rn "FileField\|ImageField\|request\.FILES" --include="*.py" . | head -10
```

---

## Express.js / Node.js (TypeScript/JavaScript)

### Directory Structure

```
project/
├── src/
│   ├── index.ts           ← Entry point
│   ├── app.ts             ← Express app setup
│   ├── routes/            ← Route definitions
│   ├── controllers/       ← Request handlers
│   ├── middleware/        ← Auth, logging, error handling
│   ├── models/            ← Data models
│   └── services/          ← Business logic
├── package.json
├── tsconfig.json
└── .env.example
```

### Entry Points

```bash
# Main entry
cat package.json | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('main',''), d.get('scripts',{}))"

# Express app setup
grep -rn "express()\|new express" --include="*.ts" --include="*.js" src/ | head -5

# Route registration
grep -rn "app\.use\|router\.use" --include="*.ts" --include="*.js" src/ | head -20
```

### Auth Pattern Detection

```bash
# JWT
grep -rn "jwt\.\|jsonwebtoken\|verify\|sign(" \
  --include="*.ts" --include="*.js" src/ | grep -v test | head -10

# Passport.js
grep -rn "passport\.\|passport-" --include="*.ts" --include="*.js" src/ | head -10

# Auth middleware
find src/middleware -type f | xargs grep -l "auth\|token\|jwt" 2>/dev/null

# Protected routes
grep -rn "authenticate\|requireAuth\|isAuthenticated" \
  --include="*.ts" --include="*.js" src/ | head -15
```

### Security Surface

```bash
# Helmet (security headers)
grep -rn "helmet()\|helmet(" --include="*.ts" --include="*.js" src/ | head -3

# CORS configuration
grep -rn "cors(\|CORS" --include="*.ts" --include="*.js" src/ | head -5

# Rate limiting
grep -rn "rateLimit\|rate-limit\|express-rate-limit" \
  --include="*.ts" --include="*.js" src/ | head -5

# Input validation
grep -rn "joi\.\|yup\.\|zod\.\|express-validator\|validate(" \
  --include="*.ts" --include="*.js" src/ | head -10

# File uploads
grep -rn "multer\|busboy\|formidable" --include="*.ts" --include="*.js" src/ | head -5

# SQL queries (if not using ORM)
grep -rn "db\.query\|pool\.query\|connection\.query" \
  --include="*.ts" --include="*.js" src/ | grep -v test | head -10
```

---

## Spring Boot (Java)

### Directory Structure

```
project/
├── src/main/java/com/company/app/
│   ├── Application.java           ← Entry point (@SpringBootApplication)
│   ├── config/
│   │   ├── SecurityConfig.java    ← Spring Security config
│   │   └── DatabaseConfig.java
│   ├── controller/                ← REST controllers (@RestController)
│   ├── service/                   ← Business logic (@Service)
│   ├── repository/                ← Data access (@Repository)
│   ├── model/                     ← JPA entities (@Entity)
│   └── security/                  ← Custom security components
├── src/main/resources/
│   ├── application.yml            ← Configuration
│   └── application-prod.yml       ← Production overrides
└── pom.xml
```

### Entry Points

```bash
# Main application class
find . -name "Application.java" | grep -v test

# Security configuration (critical)
find . -name "SecurityConfig.java" -o -name "WebSecurityConfig.java" | grep -v test

# REST controllers
find . -name "*Controller.java" | grep -v test | head -20
grep -rn "@RestController\|@Controller" --include="*.java" src/ | head -20

# API routes
grep -rn "@RequestMapping\|@GetMapping\|@PostMapping\|@PutMapping\|@DeleteMapping" \
  --include="*.java" src/ | grep -v test | head -30
```

### Auth Pattern Detection

```bash
# Spring Security configuration
grep -rn "SecurityFilterChain\|WebSecurityConfigurerAdapter\|HttpSecurity" \
  --include="*.java" src/ | head -10

# JWT filter
find . -name "*JwtFilter*" -o -name "*JwtAuthentication*" -o -name "*TokenFilter*" \
  | grep -v test

# Method-level security
grep -rn "@PreAuthorize\|@PostAuthorize\|@Secured\|@RolesAllowed" \
  --include="*.java" src/ | head -20

# OAuth2 / SSO
grep -rn "oauth2\|@EnableOAuth2\|OAuth2UserService\|OidcUser" \
  --include="*.java" src/ -l | head -5
```

### Security Surface

```bash
# CSRF configuration
grep -rn "csrf()\|\.csrf()" --include="*.java" src/ | head -5

# CORS configuration
grep -rn "CorsConfiguration\|@CrossOrigin\|corsConfigurer" \
  --include="*.java" src/ | head -5

# Actuator endpoints (often exposed accidentally)
grep -rn "management.endpoints\|actuator" src/main/resources/application.yml | head -5

# SQL injection (native queries)
grep -rn "@Query.*nativeQuery\|entityManager\.createNativeQuery\|jdbcTemplate\.query" \
  --include="*.java" src/ | grep -v test | head -10

# Sensitive config
grep -rn "password\|secret\|key" src/main/resources/application.yml \
  | grep -v "#" | grep -v "placeholder" | head -10
```

---

## FastAPI (Python)

### Directory Structure

```
project/
├── main.py                ← App entry point
├── app/
│   ├── __init__.py
│   ├── main.py            ← FastAPI app instance
│   ├── routers/           ← APIRouter definitions
│   ├── models/            ← Pydantic + SQLAlchemy models
│   ├── schemas/           ← Pydantic schemas
│   ├── dependencies/      ← Dependency injection (auth, db)
│   ├── services/          ← Business logic
│   └── core/
│       ├── config.py      ← Settings (pydantic-settings)
│       └── security.py    ← Auth utilities
└── requirements.txt
```

### Entry Points

```bash
# App instance
grep -rn "FastAPI()\|app = FastAPI" --include="*.py" . | head -5

# Router registration
grep -rn "include_router\|app\.include_router" --include="*.py" . | head -10

# Dependency injection (auth)
grep -rn "Depends(\|Security(" --include="*.py" . | grep -v test | head -15

# Background tasks
grep -rn "BackgroundTasks\|celery\|@app.on_event" --include="*.py" . | head -5
```

### Auth Pattern Detection

```bash
# OAuth2 / JWT
grep -rn "OAuth2PasswordBearer\|HTTPBearer\|decode.*jwt\|create_access_token" \
  --include="*.py" . | head -10

# Dependency-based auth
grep -rn "get_current_user\|current_user\|oauth2_scheme" \
  --include="*.py" . | head -10

# API key auth
grep -rn "APIKeyHeader\|APIKeyQuery\|api_key" --include="*.py" . | head -5
```

### Security Surface

```bash
# CORS
grep -rn "CORSMiddleware\|allow_origins\|allow_credentials" --include="*.py" . | head -5

# Request body validation (Pydantic handles this automatically)
grep -rn "class.*BaseModel" --include="*.py" . | grep -v test | head -10

# File uploads
grep -rn "UploadFile\|File(" --include="*.py" . | head -5

# Direct database queries
grep -rn "db\.execute\|text(" --include="*.py" . | grep -v test | head -10
```

---

## Gin (Go)

### Directory Structure

```
project/
├── cmd/
│   └── server/
│       └── main.go        ← Entry point
├── internal/
│   ├── api/
│   │   ├── router.go      ← Route setup
│   │   └── handlers/      ← HTTP handlers
│   ├── middleware/        ← Auth, logging, rate limit
│   ├── service/           ← Business logic
│   ├── repository/        ← Database layer
│   └── model/             ← Domain models
├── pkg/                   ← Shared/exportable packages
└── go.mod
```

### Entry Points

```bash
# Main and router setup
cat cmd/server/main.go
grep -rn "gin.Default\|gin.New\|r.Run\|srv.ListenAndServe" --include="*.go" . | head -5

# Route registration
grep -rn "\.GET(\|\.POST(\|\.PUT(\|\.DELETE(\|\.Group(" \
  --include="*.go" . | grep -v "_test" | head -30

# Middleware registration
grep -rn "\.Use(" --include="*.go" . | grep -v "_test" | head -10
```

### Auth Pattern Detection

```bash
# JWT middleware
find . -name "*.go" | xargs grep -l "jwt\|JWT" | grep -v _test | head -5

# Auth middleware location
find . -path "*/middleware/*" -name "*.go" | xargs grep -l "auth\|token" 2>/dev/null

# Claims extraction
grep -rn "c\.Get(\"claims\"\|c\.MustGet\|claims\." --include="*.go" . \
  | grep -v _test | head -10
```

### Security Surface

```bash
# CORS
grep -rn "cors\.\|CORS\|CORSMiddleware" --include="*.go" . -l | head -3

# Rate limiting
grep -rn "rateLimit\|rate_limit\|limiter\." --include="*.go" . | head -5

# Input binding (Gin auto-validation)
grep -rn "ShouldBind\|ShouldBindJSON\|BindJSON" --include="*.go" . | head -10

# SQL via GORM
grep -rn "Raw(\|Exec(\|Where(\"" --include="*.go" . | grep -v _test | head -10

# File operations
grep -rn "os\.Open\|os\.Create\|ioutil\.ReadFile\|os\.ReadFile" \
  --include="*.go" . | grep -v _test | head -10
```

---

## Framework-Agnostic Security Checklist

After completing framework-specific onboarding, always run:

```bash
# 1. Secrets scan
grep -rEin "(password|passwd|secret|api_key|apikey|token|auth_token)\s*[=:]\s*['\"][^'\"]{8,}" \
  --include="*.py" --include="*.go" --include="*.js" --include="*.ts" \
  --include="*.java" --include="*.php" --include="*.rb" . \
  | grep -v test | grep -v node_modules | grep -v ".git" | head -20

# 2. Find all TODO/FIXME security comments
grep -rn "TODO.*auth\|FIXME.*auth\|TODO.*security\|FIXME.*security\|HACK.*" \
  --include="*.py" --include="*.go" --include="*.js" --include="*.ts" . \
  | grep -v node_modules | head -15

# 3. Dependency versions for CVE cross-reference
cat requirements.txt go.mod package.json Cargo.toml 2>/dev/null | \
  grep -E "[a-z].*[0-9]+\.[0-9]" | head -40
```
