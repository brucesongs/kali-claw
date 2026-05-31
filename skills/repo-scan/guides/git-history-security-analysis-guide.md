# Git History Security Analysis Guide

> Techniques for mining git history to discover leaked secrets, sensitive file changes, and security-relevant commit patterns.

---

## 1. Secret Detection in Git History

```bash
# Scan full git history with trufflehog
trufflehog git file://. --since-commit HEAD~100 --only-verified

# Scan with gitleaks
gitleaks detect --source . --verbose --report-path gitleaks_report.json

# Manual regex search through history
git log -p --all -S 'AKIA[0-9A-Z]{16}' -- . | head -50
git log -p --all -S 'password' --diff-filter=A -- '*.env' '*.yml' '*.json'
```

---

## 2. Sensitive File Tracking

```bash
# Find when sensitive files were added
git log --all --diff-filter=A -- '*.pem' '*.key' '*.env' '*.p12' '*.pfx'

# Check if secrets were removed but still in history
git log --all --full-history -- '.env' 'credentials*' '*.key'

# Find large binary files (potential data dumps)
git rev-list --objects --all | git cat-file --batch-check='%(objecttype) %(objectname) %(objectsize) %(rest)' | awk '/^blob/ && $3 > 1048576 {print $3, $4}' | sort -rn | head -10
```

---

## 3. Author and Commit Pattern Analysis

```bash
# List all contributors with commit counts
git shortlog -sne --all

# Find commits with security-related messages
git log --all --oneline --grep="fix.*vuln\|security\|CVE\|patch.*auth\|credential" | head -20

# Detect force pushes (potential history rewriting)
git reflog --all | grep "forced-update"

# Find commits that modified auth/security files
git log --all --oneline -- '*auth*' '*security*' '*permission*' '*rbac*' | head -20
```

---

## 4. Deleted Content Recovery

```bash
# Find deleted files
git log --all --diff-filter=D --name-only --pretty=format:"%H %s" | head -30

# Recover deleted file content
git show <commit_hash>^:<path/to/deleted/file>

# Search for content in deleted files
git log --all -p --diff-filter=D -- '*.sql' '*.env' | grep -iE "password|secret|key" | head -20
```

---

## 5. Automated History Audit

```bash
#!/bin/bash
# git-history-audit.sh — Security audit of git history
echo "=== Git History Security Audit ==="

echo "[1] Checking for secrets in history..."
git log -p --all | grep -cE "AKIA|password\s*=\s*['\"]|BEGIN (RSA|DSA|EC) PRIVATE KEY" | xargs -I{} echo "  Potential secrets: {} matches"

echo "[2] Sensitive files ever committed..."
git log --all --diff-filter=A --name-only --pretty=format: | grep -iE "\.(env|pem|key|p12|pfx|jks)$" | sort -u

echo "[3] Security-related commits..."
git log --all --oneline --grep="security\|CVE\|vuln" | wc -l | xargs -I{} echo "  Security commits: {}"

echo "[4] Contributors..."
git shortlog -sne --all | wc -l | xargs -I{} echo "  Total contributors: {}"

echo "[+] Audit complete"
```
