# Log Tampering Detection Guide

## Overview

Attackers routinely tamper with logs to cover their tracks. This guide covers techniques for detecting log manipulation, verifying log integrity, and maintaining forensic chain-of-custody.

---

## Common Log Tampering Techniques

### Log Deletion

```bash
# Full log wipe
> /var/log/auth.log
cat /dev/null > /var/log/syslog
rm -f /var/log/secure

# Selective line removal
sed -i '/attacker_ip/d' /var/log/auth.log
grep -v "10.0.1.50" /var/log/access.log > /tmp/clean && mv /tmp/clean /var/log/access.log
```

### Log Modification

```bash
# Timestamp manipulation
touch -t 202501010000 /var/log/auth.log

# In-place editing to change IPs
sed -i 's/10.0.1.50/10.0.1.1/g' /var/log/access.log
```

### Log Rotation Abuse

```bash
# Force rotation to push evidence into compressed archives
logrotate -f /etc/logrotate.conf

# Delete rotated files
rm -f /var/log/auth.log.1.gz
```

---

## Detection Techniques

### Gap Analysis

```bash
# Detect time gaps in syslog (missing entries)
awk '{print $1, $2, $3}' /var/log/syslog | while read month day time; do
    current=$(date -d "$month $day $time" +%s 2>/dev/null)
    if [ -n "$prev" ] && [ -n "$current" ]; then
        gap=$((current - prev))
        if [ $gap -gt 300 ]; then
            echo "GAP DETECTED: $gap seconds at $month $day $time"
        fi
    fi
    prev=$current
done
```

### File Integrity Monitoring

```bash
# AIDE (Advanced Intrusion Detection Environment)
aide --init
aide --check

# Tripwire
tripwire --init
tripwire --check

# Simple hash-based monitoring
find /var/log -type f -exec sha256sum {} \; > /secure/log_hashes_$(date +%Y%m%d).txt
# Compare with previous
diff <(sort /secure/log_hashes_yesterday.txt) <(sort /secure/log_hashes_today.txt)
```

### Inode and Metadata Analysis

```bash
# Check if log file was recreated (inode changed)
stat /var/log/auth.log
# Compare inode number with expected value

# Check modification time vs last log entry
ls -la /var/log/auth.log
tail -1 /var/log/auth.log
# If mtime is newer than last entry → suspicious

# Check file size progression
du -b /var/log/auth.log
# Sudden size decrease indicates deletion
```

### Audit Log Cross-Reference

```bash
# Linux auditd rules for log file access
# /etc/audit/rules.d/log-protection.rules
-w /var/log/auth.log -p wa -k log_tampering
-w /var/log/syslog -p wa -k log_tampering
-w /var/log/secure -p wa -k log_tampering
-w /var/log/ -p wa -k log_dir_change

# Search audit log for tampering
ausearch -k log_tampering -ts recent
aureport -f -ts today | grep -E "(auth|syslog|secure)"
```

### Journal Integrity (systemd)

```bash
# Verify journal integrity
journalctl --verify

# Check for sealed journals (FSS - Forward Secure Sealing)
journalctl --setup-keys
journalctl --verify-key=<verification-key>
```

---

## Centralized Logging for Tamper Resistance

### Write-Once Remote Logging

```bash
# rsyslog with TLS to remote immutable store
# /etc/rsyslog.d/60-remote.conf
$DefaultNetstreamDriverCAFile /etc/ssl/ca.pem
$DefaultNetstreamDriverCertFile /etc/ssl/client-cert.pem
$DefaultNetstreamDriverKeyFile /etc/ssl/client-key.pem

$ActionSendStreamDriver gtls
$ActionSendStreamDriverMode 1
$ActionSendStreamDriverAuthMode x509/name
*.* @@logserver.internal:6514
```

### Append-Only Storage

```bash
# Set immutable attribute on log files
chattr +a /var/log/auth.log
chattr +a /var/log/syslog

# Verify attribute
lsattr /var/log/auth.log
# Output: -----a--------e--- /var/log/auth.log
```

### Blockchain-Anchored Logging

```python
import hashlib
import json

class TamperEvidentLog:
    def __init__(self):
        self.chain = []
        self.prev_hash = "0" * 64

    def append(self, entry):
        block = {
            "entry": entry,
            "prev_hash": self.prev_hash,
            "index": len(self.chain)
        }
        block["hash"] = hashlib.sha256(
            json.dumps(block, sort_keys=True).encode()
        ).hexdigest()
        self.chain.append(block)
        self.prev_hash = block["hash"]

    def verify(self):
        for i in range(1, len(self.chain)):
            if self.chain[i]["prev_hash"] != self.chain[i-1]["hash"]:
                return False, f"Tampering detected at block {i}"
        return True, "Chain intact"
```

---

## Forensic Evidence Preservation

### Chain of Custody Protocol

```bash
# 1. Create forensic copy
dd if=/var/log/auth.log of=/evidence/auth.log.forensic bs=4096
sha256sum /evidence/auth.log.forensic > /evidence/auth.log.forensic.sha256

# 2. Document collection
cat > /evidence/collection_notes.txt << EOF
Collected: $(date -u)
Source: /var/log/auth.log on host $(hostname)
Collector: $(whoami)
Hash: $(cat /evidence/auth.log.forensic.sha256)
Purpose: Incident IR-2025-001 investigation
EOF

# 3. Sign evidence
gpg --detach-sign /evidence/auth.log.forensic
```

### Volatile Evidence Collection Order

```bash
# Collect in order of volatility (RFC 3227)
# 1. Memory
dd if=/dev/mem of=/evidence/memory.dump bs=1M

# 2. Network state
ss -tulnp > /evidence/network_state.txt
ip route > /evidence/routes.txt
arp -a > /evidence/arp_cache.txt

# 3. Running processes
ps auxf > /evidence/processes.txt
ls -la /proc/*/exe 2>/dev/null > /evidence/proc_exe.txt

# 4. Disk (logs)
tar czf /evidence/var_log.tar.gz /var/log/
```

---

## Monitoring Configuration

### Real-Time Tampering Alerts

```yaml
# Splunk alert for log source going silent
| tstats count where index=* by sourcetype, _time span=5m
| streamstats current=f last(count) as prev_count by sourcetype
| where count=0 AND prev_count>0
| table sourcetype, _time

# Alert on log file size decrease
index=_internal source=*metrics.log group=per_sourcetype_thruput
| timechart span=1h sum(kb) by series
| foreach * [eval alert_<<FIELD>>=if('<<FIELD>>' < 0.5 * prev('<<FIELD>>'), 1, 0)]
```

### Auditd Real-Time Monitoring

```bash
# Watch for log tampering in real-time
tail -f /var/log/audit/audit.log | grep -E "log_tampering|log_dir_change" | while read line; do
    echo "ALERT: Log tampering detected - $line" | mail -s "Log Tampering Alert" security@company.com
done
```

---

## Testing Checklist

- [ ] Verify centralized logging is configured and receiving events
- [ ] Test gap detection on known-good and tampered logs
- [ ] Verify file integrity monitoring covers all critical log files
- [ ] Test auditd rules fire on log file modification
- [ ] Verify append-only attributes are set on critical logs
- [ ] Test journal verification (systemd --verify)
- [ ] Confirm forensic collection procedures produce valid evidence
- [ ] Verify alerting fires when log sources go silent
