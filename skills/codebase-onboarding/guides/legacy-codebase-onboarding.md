# Legacy Codebase Onboarding Guide

Tactics for codebases with no framework, outdated languages, missing documentation, and technical debt. Legacy code is high-value for security research — it often contains the oldest, most unreviewed vulnerabilities.

---

## Defining "Legacy"

A codebase is legacy when:
- Framework version is end-of-life (PHP 5.x, Python 2.7, Java 6/7, Rails 3.x)
- No framework at all (raw PHP, Perl CGI, ASP Classic)
- Original developers are gone, documentation is missing
- Test coverage is near zero
- Dependencies are years out of date
- Mix of programming styles across the codebase

**Security implication**: Legacy code is most likely to contain unpatched CVEs, SQL injection, XSS, hardcoded credentials, and outdated cryptography.

---

## Phase 0: Legacy-Specific Discovery

```bash
# Detect language versions
python3 --version 2>/dev/null || python --version 2>/dev/null
php --version 2>/dev/null
ruby --version 2>/dev/null
java -version 2>/dev/null
node --version 2>/dev/null

# Find language version pins
cat runtime.txt 2>/dev/null        # Python Heroku
cat .python-version 2>/dev/null    # pyenv
cat .ruby-version 2>/dev/null      # rbenv
cat .nvmrc 2>/dev/null             # nvm
grep "java.version" pom.xml 2>/dev/null | head -3
grep "php" composer.json 2>/dev/null | grep "require"

# Check for EOL versions
# Python 2: print "hello" or print("hello") without parens
grep -rn "^print [^(]" --include="*.py" . | head -5

# Ancient PHP patterns
grep -rn "mysql_connect\|mysql_query\|ereg(" --include="*.php" . | head -5

# Old Java patterns
grep -rn "new Vector\|Hashtable\|StringBuffer" --include="*.java" . | head -5
```

## Phase 1: No-Framework Navigation

When there's no MVC framework, mapping the codebase requires different signals:

```bash
# PHP legacy: entry points via web server config
cat .htaccess 2>/dev/null | grep "RewriteRule\|DirectoryIndex" | head -20
cat nginx.conf 2>/dev/null | grep "location\|index\|try_files" | head -20

# PHP: All files that handle HTTP requests directly
grep -rn "\$_GET\|\$_POST\|\$_REQUEST\|\$_COOKIE\|\$_SERVER" \
  --include="*.php" . | grep -v node_modules | awk -F: '{print $1}' \
  | sort -u | head -20

# CGI scripts
find . -name "*.cgi" -o -name "*.pl" | head -10
find . -path "*/cgi-bin/*" | head -10

# Classic ASP
find . -name "*.asp" -o -name "*.aspx" | head -10

# Perl
find . -name "*.pl" -o -name "*.pm" | head -10
grep -rn "use CGI\|use strict\|sub handler" --include="*.pl" . | head -10
```

## Phase 2: Legacy Auth Patterns

Legacy auth is often custom-built and fragile:

```bash
# PHP session auth
grep -rn "session_start\|session_register\|\$_SESSION" \
  --include="*.php" . | grep -v node_modules | head -15

# Homegrown auth checks (the dangerous kind)
grep -rn "if.*password\|if.*pass\|if.*auth" \
  --include="*.php" . | grep -v node_modules | grep -v test | head -10

# Plaintext or MD5 passwords (critical finding)
grep -rn "md5(\|sha1(\|crypt(" --include="*.php" . | head -10
grep -rn "MD5\|SHA1\b" --include="*.java" . | head -5
grep -rn "hashlib\.md5\|hashlib\.sha1" --include="*.py" . | head -5

# Cookie-based auth (check for signed/encrypted)
grep -rn "setcookie\|\$_COOKIE\[" --include="*.php" . | head -10
grep -rn "response\.set_cookie\|request\.cookies" --include="*.py" . | head -5
```

## Phase 3: Legacy Security Anti-Patterns

These patterns are overwhelmingly common in legacy code:

### SQL Injection (Most Common Legacy Risk)

```bash
# PHP legacy SQL injection patterns
grep -rn "mysql_query.*\\\$\|mysqli_query.*\\\$\|\".*SELECT.*\\\$\|'.*SELECT.*\\\$" \
  --include="*.php" . | grep -v node_modules | head -20

grep -rn "\.query(.*\+\|\.execute(.*%\|\.execute(.*\+" \
  --include="*.py" . | grep -v test | head -10

# Java JDBC without PreparedStatement
grep -rn "Statement.*execute\|createStatement\b" --include="*.java" . | head -10
grep -rn "\"SELECT.*\+\|\"INSERT.*\+\|\"UPDATE.*\+\|\"DELETE.*\+" \
  --include="*.java" . | grep -v test | head -10

# Classic Perl DBI
grep -rn "do\s*\"SELECT\|prepare.*\\\$\|quote.*\\\$" --include="*.pl" . | head -5
```

### XSS (Second Most Common)

```bash
# PHP: Unescaped output
grep -rn "echo.*\$_GET\|echo.*\$_POST\|print.*\$_REQUEST\|print.*\$_GET" \
  --include="*.php" . | grep -v "htmlspecialchars\|htmlentities" | head -15

# PHP: Template output without escaping
grep -rn "<?=\s*\$_\|<?php.*echo.*\$_" --include="*.php" . \
  | grep -v "htmlspecialchars\|htmlentities\|strip_tags" | head -10

# Python legacy: Template injection
grep -rn "render_template_string\|Markup(\|mark_safe(" \
  --include="*.py" . | grep -v test | head -5
```

### Command Injection

```bash
# PHP
grep -rn "exec(\|system(\|passthru(\|shell_exec(\|popen(\|proc_open(" \
  --include="*.php" . | grep -v node_modules | head -10

# Check if user input flows into these
grep -rn "exec.*\$_GET\|system.*\$_POST\|shell_exec.*\$_REQUEST" \
  --include="*.php" . | head -5

# Python
grep -rn "os\.system\|subprocess\.call.*shell=True\|os\.popen" \
  --include="*.py" . | grep -v test | head -10

# Perl
grep -rn "system(\|`.*\\\$" --include="*.pl" . | head -5
```

### File Inclusion / Path Traversal

```bash
# PHP Local File Inclusion (LFI)
grep -rn "include.*\$_GET\|include.*\$_POST\|require.*\$_GET\|require.*\$_POST" \
  --include="*.php" . | head -10

# File reads with user input
grep -rn "file_get_contents.*\$_\|fopen.*\$_\|readfile.*\$_" \
  --include="*.php" . | head -5

# Path traversal candidates
grep -rn "\.\.\/\|\.\.\\\\" --include="*.php" --include="*.py" . | grep -v test | head -5
```

### Hardcoded Credentials

```bash
# Database passwords
grep -rn "mysql_connect.*\".*\".*\"" --include="*.php" . | head -5
grep -rn "new PDO.*password\|mysqli.*password" --include="*.php" . | head -5
grep -rn "password\s*=\s*['\"][^'\"]\+['\"]" \
  --include="*.php" --include="*.py" --include="*.java" . \
  | grep -v test | grep -v "#" | head -10

# Email credentials
grep -rn "smtp.*password\|mail.*password\|SMTP_PASS" \
  --include="*.php" --include="*.py" --include="*.java" . | head -5
```

## Phase 4: Dependency Archaeology

```bash
# PHP: Composer (if exists)
cat composer.json 2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin); [print(k,v) for k,v in d.get('require',{}).items()]"
cat composer.lock 2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin); [print(p['name'], p['version']) for p in d.get('packages',[])]" | head -30

# Python: Old-style requirements
cat requirements.txt 2>/dev/null | head -30
cat setup.py 2>/dev/null | grep "install_requires" -A 20 | head -20

# Java: JAR files in project (often copied directly)
find . -name "*.jar" | grep -v target | grep -v ".git" | head -20

# Check for CVE-prone old versions
# Focus on: struts (Java), log4j (Java), phpmailer (PHP), jquery < 3 (JS)
grep -rn "log4j\|struts\|phpmailer" \
  --include="*.xml" --include="*.json" --include="*.txt" . | head -10
find . -name "jquery*.js" | grep -v node_modules | grep -v min | head -5
```

## Legacy-Specific Interview Questions

When documentation is sparse, look for answers in the code:

```bash
# Q: Where is session data stored?
grep -rn "session_save_path\|SessionStore\|store.*session" \
  --include="*.php" --include="*.py" --include="*.rb" . | head -5

# Q: Is there any CSRF protection?
grep -rn "csrf_token\|_token\|X-CSRF-TOKEN\|nonce" \
  --include="*.php" --include="*.html" . | head -5

# Q: Are passwords hashed at all?
grep -rn "password_hash\|bcrypt\|argon2\|pbkdf2" \
  --include="*.php" --include="*.py" . | head -5

# Q: Is there any logging?
grep -rn "error_log\|file_put_contents.*log\|logging\.\|Logger\." \
  --include="*.php" --include="*.py" --include="*.java" . | head -10

# Q: What does the admin section do?
find . -path "*/admin/*" -type f | head -20
find . -name "admin.php" -o -name "administrator.php" | head -5
```

## Legacy Onboarding Confidence Calibration

Legacy codebases should receive adjusted confidence scores due to:
- Lower automation support (Tier 2/3 languages)
- No test suite to indicate behavior
- Hidden logic in stored procedures or config files
- Copy-paste code that may differ from "main" implementation

**Adjustment**: Subtract 10–15 points from confidence scores vs. modern codebases. Explicitly note "Legacy Caveat" in the output.

Example output note:
```
Confidence: 52/100 (Legacy Caveat: -12 pts — PHP 5.6, no framework, no tests, stored procedures in DB not reviewed)
```

## Priority Order for Legacy Security Review

1. **Hardcoded credentials** — immediate data breach risk
2. **SQL injection in input-handling files** — highest exploitation probability
3. **File inclusion with user input** — RCE potential
4. **Command injection** — RCE potential
5. **XSS in output** — user impact, often widespread
6. **Authentication logic** — often rolling their own, often broken
7. **Dependency CVEs** — old dependencies = known exploits
8. **Insecure cryptography** — MD5/SHA1 passwords, broken cipher usage

## Hands-on Exercise

Practice onboarding a legacy codebase by following these steps:

1. **Select a target**: Clone a 10,000+ LOC open-source project you're unfamiliar with
2. **Architecture scan**: Run `ctags -R` and identify the top-level module structure
3. **Entry point mapping**: Find the `main()` or equivalent entry points — trace the first 3 call chains
4. **Dependency graph**: Run `pipdeptree` / `npm ls` / equivalent to map external dependencies
5. **Hotspot analysis**: Use `git log --oneline | awk '{print $1}' | xargs -I{} git diff-tree --no-commit-id --name-only -r {} | sort | uniq -c | sort -rn | head -20` to find the most-changed files
6. **Document findings**: Write a 1-page summary of the architecture, key modules, and risk areas
