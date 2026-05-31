# Terminal Automation and Scripting Guide

> Patterns for automating repetitive terminal operations, building reusable command pipelines, and managing complex multi-step workflows.

---

## 1. Command Pipeline Construction

### Chaining Commands Safely

```bash
# Sequential with error handling
command1 && command2 && command3 || echo "Pipeline failed at step $?"

# Parallel execution with wait
cmd1 & cmd2 & cmd3 &
wait
echo "All background jobs complete"

# Pipeline with intermediate error checking
set -o pipefail
find . -name "*.log" | grep -l "ERROR" | xargs -I{} tail -5 {}
```

### Named Pipes for Inter-Process Communication

```bash
# Create named pipe for streaming data between processes
mkfifo /tmp/scan_pipe

# Producer: feed targets
cat targets.txt > /tmp/scan_pipe &

# Consumer: process targets
while read target; do
    nmap -sV "$target" >> results.txt
done < /tmp/scan_pipe

rm /tmp/scan_pipe
```

---

## 2. Session Persistence Patterns

### tmux Automation

```bash
# Create scripted tmux session for pentest workflow
tmux new-session -d -s pentest

# Split into panes
tmux split-window -h -t pentest
tmux split-window -v -t pentest:0.1

# Send commands to specific panes
tmux send-keys -t pentest:0.0 "tail -f /var/log/proxy.log" C-m
tmux send-keys -t pentest:0.1 "msfconsole" C-m
tmux send-keys -t pentest:0.2 "sudo tcpdump -i eth0 -w capture.pcap" C-m

# Attach
tmux attach -t pentest
```

### Screen Session Management

```bash
# Create detached session with logging
screen -dmS recon -L -Logfile recon_$(date +%Y%m%d).log

# Send command to running session
screen -S recon -X stuff "subfinder -d target.com -o subs.txt\n"

# List all sessions
screen -ls
```

---

## 3. Output Processing Patterns

### Structured Output Parsing

```bash
# Parse nmap XML output
xmlstarlet sel -t -m "//host[status/@state='up']" \
  -v "address/@addr" -o ":" -v "ports/port/service/@name" -n \
  nmap_results.xml

# Parse JSON tool output
cat nuclei_results.json | jq -r '[.info.severity, .host, .info.name] | @tsv' | sort

# Convert CSV to actionable commands
awk -F',' '{print "curl -s -o /dev/null -w \"%{http_code}\" " $2}' targets.csv | bash
```

### Real-Time Filtering

```bash
# Monitor and filter live output
stdbuf -oL nmap -sV 192.168.1.0/24 | grep --line-buffered "open"

# Tee to file while filtering display
masscan 10.0.0.0/8 -p80,443 --rate 10000 | tee full_scan.txt | grep "open"

# Colorized real-time alerts
tail -f /var/log/auth.log | grep --color=always "Failed\|Accepted"
```

---

## 4. Batch Operations

### Parallel Target Processing

```bash
# GNU parallel for concurrent scanning
cat targets.txt | parallel -j 10 "nmap -sV -p- {} > results/{}.txt"

# xargs with concurrency control
cat urls.txt | xargs -P 5 -I{} curl -s -o /dev/null -w "%{http_code} {}\n" {}

# Custom parallel with job control
MAX_JOBS=10
job_count=0
while read target; do
    scan_target "$target" &
    ((job_count++))
    if [ "$job_count" -ge "$MAX_JOBS" ]; then
        wait -n
        ((job_count--))
    fi
done < targets.txt
wait
```

### Progress Tracking

```bash
# Progress bar for batch operations
total=$(wc -l < targets.txt)
current=0
while read target; do
    ((current++))
    printf "\r[%d/%d] Scanning: %s" "$current" "$total" "$target"
    nmap -sV "$target" >> results.txt 2>/dev/null
done < targets.txt
echo ""
```

---

## 5. Error Recovery and Resilience

### Checkpoint-Based Execution

```bash
#!/bin/bash
CHECKPOINT_FILE="/tmp/scan_checkpoint"
TARGETS_FILE="targets.txt"

# Resume from last checkpoint
start_line=1
if [ -f "$CHECKPOINT_FILE" ]; then
    start_line=$(cat "$CHECKPOINT_FILE")
    echo "[*] Resuming from line $start_line"
fi

tail -n +"$start_line" "$TARGETS_FILE" | while read -r target; do
    ((start_line++))
    echo "$start_line" > "$CHECKPOINT_FILE"
    
    # Retry logic
    for attempt in 1 2 3; do
        if nmap -sV "$target" >> results.txt 2>/dev/null; then
            break
        fi
        sleep $((attempt * 2))
    done
done

rm -f "$CHECKPOINT_FILE"
echo "[+] Scan complete"
```

### Timeout Wrapper

```bash
# Wrap commands with timeout to prevent hangs
timeout_exec() {
    local seconds="$1"
    shift
    timeout "$seconds" "$@"
    local exit_code=$?
    if [ $exit_code -eq 124 ]; then
        echo "[TIMEOUT] Command exceeded ${seconds}s: $*"
    fi
    return $exit_code
}

# Usage
timeout_exec 30 curl -s "http://slow-target.com"
timeout_exec 60 nmap -sV "$target"
```

---

## 6. Environment Management

### Tool Version Switching

```bash
# Python version management for exploit compatibility
pyenv install 2.7.18
pyenv local 2.7.18  # For legacy exploits

# Ruby version for Metasploit
rbenv install 3.1.0
rbenv local 3.1.0

# Node version for JS-based tools
nvm use 18
```

### Isolated Execution Environments

```bash
# Python virtual environment per engagement
python3 -m venv /opt/engagements/client_a/venv
source /opt/engagements/client_a/venv/bin/activate
pip install -r requirements.txt

# Temporary PATH modification
PATH="/opt/custom-tools:$PATH" ./run_scan.sh
```
