# Terminal Forensics and Evidence Collection Guide

> Techniques for capturing, preserving, and documenting terminal session activity for forensic analysis and engagement reporting.

---

## 1. Session Recording

### script Command

```bash
# Record entire terminal session with timestamps
script -t 2>timing.log session_$(date +%Y%m%d_%H%M%S).log

# Replay session at original speed
scriptreplay timing.log session.log

# Record with automatic naming
script -q "/opt/evidence/$(hostname)_$(date +%Y%m%d_%H%M%S).log"
```

### asciinema Recording

```bash
# Record session
asciinema rec engagement_$(date +%Y%m%d).cast

# Record with idle time limit
asciinema rec --idle-time-limit 5 session.cast

# Replay locally
asciinema play session.cast
```

---

## 2. Command History Forensics

### History Analysis

```bash
# Extract commands with timestamps
HISTTIMEFORMAT="%F %T " history | tail -100

# Find security-relevant commands
history | grep -iE "ssh|sudo|passwd|chmod|chown|curl|wget|nc |ncat"

# Export full history with context
fc -l -1000 > command_history_export.txt
```

### Evidence Preservation

```bash
# Hash evidence files for integrity
sha256sum evidence/*.log > evidence/checksums.sha256

# Create tamper-evident archive
tar czf "evidence_$(date +%Y%m%d).tar.gz" evidence/
sha256sum "evidence_$(date +%Y%m%d).tar.gz" > "evidence_$(date +%Y%m%d).tar.gz.sha256"

# Verify integrity
sha256sum -c evidence/checksums.sha256
```

---

## 3. Output Capture Patterns

### Structured Evidence Collection

```bash
# Capture command + output + exit code
capture_evidence() {
    local cmd="$*"
    local timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    local output_file="evidence/$(date +%H%M%S)_$(echo "$cmd" | tr ' /' '_-' | head -c 50).txt"
    
    {
        echo "=== EVIDENCE ==="
        echo "Timestamp: $timestamp"
        echo "Command: $cmd"
        echo "Operator: $(whoami)@$(hostname)"
        echo "=== OUTPUT ==="
        eval "$cmd" 2>&1
        echo ""
        echo "=== EXIT CODE: $? ==="
    } | tee "$output_file"
}
```

### Screenshot Automation

```bash
# Capture terminal screenshot (text-based)
capture_terminal() {
    local output="evidence/screenshot_$(date +%Y%m%d_%H%M%S).txt"
    {
        echo "Terminal: $(tty)"
        echo "Size: $(stty size)"
        echo "Date: $(date -u)"
        echo "---"
        cat /dev/stdin
    } > "$output"
}
```
