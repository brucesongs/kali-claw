# Secret Detection and Pattern Scanning Guide

> Skill: repo-scan | Type: practical
> Created: 2026-05-23 | Estimated Study Time: 35 minutes

## Overview

Learn to detect secrets, credentials, and sensitive data in code repositories. Covers pattern recognition, custom regex rules, false positive reduction, and integration with scanning tools.

## Prerequisites

- Basic regex knowledge
- grep/ripgrep familiarity
- Understanding of common secret patterns

## 1. Common Secret Patterns

### API Keys

```bash
# Generic API key patterns (20-50 chars, alphanumeric + special chars)
rg -E "(api[-_]?key|apikey)[-:=\s]+['\"]?[a-zA-Z0-9_\-]{20,50}['\"]?" --type py

# Service-specific API keys
rg -E "(AWS|AWS_ACCESS|AWS_SECRET)[-_]KEY[-:]?\s*['\"]?[A-Z0-9]{20,}['\"]?" --type py

# Google API key (starts with AIza)
rg -E "AIza[a-zA-Z0-9_\-]{35}" --type py

# GitHub personal access token (starts with ghp_)
rg -E "ghp_[a-zA-Z0-9]{36}" --type py

# Slack tokens
rg -E "xox[baprs]-[a-zA-Z0-9\-]{10,48}" --type py
```

### Database Credentials

```bash
# Database connection strings
rg -E "(mongodb|mysql|postgres|redis)[:+][^'\"]+[:@][^'\"]+" --type py

# Password patterns in connection strings
rg -E "password[=:][^'\"]+" --type py

# AWS RDS connection string
rg -E "jdbc:[^:]+://[^:]+:[^@]+@" --type py

# MongoDB connection URI
rg -E "mongodb://[^:]+:[^@]+@" --type py
```

### Private Keys

```bash
# RSA private key header
rg -E "-----BEGIN (RSA )?PRIVATE KEY-----" --type-add 'key:*.pem *.key' --type key

# EC private key
rg -E "-----BEGIN EC PRIVATE KEY-----" --type-add 'key:*.pem *.key' --type key

# PGP private key
rg -E "-----BEGIN PGP PRIVATE KEY BLOCK-----" --type-add 'key:*.pem *.key' --type key

# SSH private key
rg -E "ssh-(rsa|ed25519|ecdsa|dss) [A-Za-z0-9+/=]{100,}" --type py
```

### Tokens and Sessions

```bash
# JWT tokens (3 parts, dot separated, base64-like)
rg -E "ey[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}" --type py

# Session cookies
rg -E "(session|sess)[_-]id[=:]['\"]?[a-zA-Z0-9]{20,}['\"]?" --type py

# OAuth bearer tokens
rg -E "(Bearer|Token):?\s*[A-Za-z0-9_\-\.]{20,}" --type py

# Reset tokens
rg -E "(reset[-_]?token|password[-_]?reset)[-:=\s]+['\"]?[a-zA-Z0-9]{20,}['\"]?" --type py
```

### Webhook URLs

```bash
# Webhook URLs with embedded tokens
rg -E "https://(hooks\.slack\.com|discord\.com/api/webhooks|api\.telegram\.org)/[^'\"]+/" --type py

# Stripe webhook secret
rg -E "whsec_[a-zA-Z0-9]{32,}" --type py

# GitHub webhook secret
rg -E "(webhook[-_]?secret|gh[-_]?webhook)[-:=\s]+['\"]?[a-zA-Z0-9]{20,}['\"]?" --type py
```

## 2. High-Fidelity Pattern Rules

### Variable Assignment Detection

```bash
# Direct assignment with string literals
rg -E "(password|secret|key|token|credential)\s*=\s*['\"]" --type py

# Environment variable assignment
rg -E "(os\.environ|os\.getenv)\(['\"](password|secret|key|token)" --type py

# Configuration file patterns (JSON)
rg -E '"(password|secret|api[_-]?key|token)"\s*:\s*"' --type json

# Configuration file patterns (YAML)
rg -E "(password|secret|api[_-]?key|token):\s*['\"]?" --type-add 'yaml:*.yaml *.yml' --type yaml
```

### Context-Aware Detection

```bash
# With common import context (Python)
rg -B 5 "(import os|from os import).*password.*=" --type py

# With AWS context
rg -B 2 "aws_access_key_id.*aws_secret_access_key" --type py

# With database context
rg -B 2 "(connect|connection|create_engine).*password" --type py
```

### URL-Embedded Secrets

```bash
# Database URLs with credentials
rg -E "[a-z]+://[a-zA-Z0-9_-]+:[a-zA-Z0-9_-]+@" --type py

# API URLs with key parameters
rg -E "https://[^'\"]+(api[-_]?key|token)=[^'\"]+" --type py

# S3 URLs with embedded credentials
rg -E "s3://[^:@]+:[^@]+@" --type py
```

## 3. False Positive Reduction

### Exclude Test Files

```bash
# Skip test directories
rg "password" --type py --glob "!test_*" --glob "!*/test/*" --glob "!*/tests/*"

# Skip mock/fake data
rg -E "password.*=\s*['\"]?(test|fake|mock|example|sample|placeholder)" --type py --ignore-case

# Skip documentation comments
rg "password" --type py -v "#"
```

### Exclude Safe Patterns

```bash
# Exclude parameter references
rg -E "password[{}$\[]"?" --type py --glob "!**/config/*"

# Exclude environment variable references (no literal values)
rg -E "(password|secret)[^=]*$" --type py -v "=[\"']"

# Exclude default/placeholder mentions
rg -iE "(password|secret).*(your|enter|replace|change|default|placeholder)" --type py
```

### Context-Based Filtering

```bash
# Only report actual assignments, not comments or string literals in text
rg -E "^\s*(password|secret|key|token)\s*=\s*['\"]" --type py

# Only report outside documentation strings
rg -E "(password|secret)" --type py -v '"""' -v "'''"

# Only report in actual code (not examples in comments)
rg -E "password" --type py --passthru | grep -v "^\s*#" | rg "password"
```

## 4. Custom Regex Rules File

### Pattern Registry Format

```bash
# Create patterns file for reuse
cat > secret-patterns.txt << 'EOF'
# API Keys
(AWS|AWS_ACCESS|AWS_SECRET)[-_]KEY[-:]?\s*['\"]?[A-Z0-9]{20,}['\"]?
AIza[a-zA-Z0-9_\-]{35}
ghp_[a-zA-Z0-9]{36}
xox[baprs]-[a-zA-Z0-9\-]{10,48}

# Database
password[=:][^'\"]+
mongodb://[^:]+:[^@]+@
jdbc:[^:]+://[^:]+:[^@]+@

# Keys
-----BEGIN (RSA )?PRIVATE KEY-----
-----BEGIN EC PRIVATE KEY-----
ssh-(rsa|ed25519|ecdsa|dss) [A-Za-z0-9+/=]{100,}

# Tokens
ey[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}
Bearer:\s*[A-Za-z0-9_\-\.]{20,}

# Webhooks
https://hooks\.slack\.com/services/[A-Z0-9]{9,11}/[A-Z0-9]{9,11}/[A-Za-z0-9_\-]{24}
EOF

# Use patterns file
rg -f secret-patterns.txt --type py
```

## 5. Multi-Language Scanning

```bash
# Python
rg -E "(password|secret|key|token)\s*=\s*['\"]" --type py

# JavaScript/TypeScript
rg -E "(password|secret|key|token)\s*[=:]?\s*['\"`]" --type ts --type js

# Go
rg -E "(Password|Secret|Key|Token)\s*[:=]\s*['\"]" --type go

# Java
rg -E "(password|secret|key|token)\s*[=:]\s*['\"]" --type java

# PHP
rg -E "['\"]?(password|secret|api[_-]?key)['\"]?\s*=>" --type php

# Ruby
rg -E "(password|secret|key)\s*[=:].*['\"]" --type rb

# Shell scripts
rg -E "(password|secret|key|token)=['\"]?" --type-add 'shell:*.sh' --type shell

# Terraform
rg -E "(password|secret|api_key)\s*=\s*['\"]" --type-add 'tf:*.tf' --type tf
```

## 6. Git History Scanning

```bash
# Search current branch
git grep -E "(password|secret|api[-_]?key)" -- '*.py' '*.js' '*.go'

# Search all branches
git grep -E "(password|secret|api[-_]?key)" $(git rev-parse --all) -- '*.py'

# Find commits that added secrets
git log -S "password" --oneline --all

# Find commits that removed secrets (to check if exposed)
git log -G "password" --oneline --all

# Search specific commit
git show <commit-hash> | grep -E "password|secret|key"

# Binary search for secret introduction
git bisect start HEAD <old-commit>
git bisect run sh -c 'git grep -q "password" && exit 1 || exit 0'
```

## 7. Comprehensive Scan Script

```bash
#!/bin/bash
# comprehensive-secret-scan.sh

echo "=== SECRET SCAN REPORT: $(date) ==="
echo ""

# Define patterns
patterns=(
    "password|secret|api[-_]?key|token"
    "-----BEGIN.*PRIVATE KEY-----"
    "ghp_[a-zA-Z0-9]{36}"
    "AIza[a-zA-Z0-9_\-]{35}"
    "xox[baprs]-[a-zA-Z0-9\-]{10,48}"
    "ey[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"
)

# Scan each pattern
for pattern in "${patterns[@]}"; do
    echo "--- Pattern: $pattern ---"
    rg -E "$pattern" --type py --type js --type go --type ts -l 2>/dev/null || echo "No matches"
    echo ""
done

# Check git history
echo "--- Git History Scan ---"
for pattern in "${patterns[@]}"; do
    commits=$(git log -S "$pattern" --oneline --all | wc -l)
    if [ "$commits" -gt 0 ]; then
        echo "Pattern '$pattern' found in $commits commits"
    fi
done

echo "=== SCAN COMPLETE ==="
```

## Quick Reference

```bash
# API keys
rg -E "(api[-_]?key|apikey)[-:=\s]+['\"]?[a-zA-Z0-9_\-]{20,50}['\"]?"

# Database credentials
rg -E "password[=:][^'\"]+"

# Private keys
rg -E "-----BEGIN (RSA )?PRIVATE KEY-----"

# JWT tokens
rg -E "ey[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"

# Skip tests
rg "password" --type py --glob "!*/test/*"

# Git history scan
git log -S "password" --oneline --all

# Multi-language
rg -E "(password|secret|key|token)" --type py --type js --type go
```

## Integration with Other Skills

- **repo-scan**: Core scanning capability
- **security-review**: Secret findings as part of review
- **knowledge-ops**: Secret patterns as security entities
- **article-writing**: Secret scan reports for security documentation