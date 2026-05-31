# Forensic Logging Requirements Guide

> Companion to `skills/logging-monitoring/SKILL.md`. This guide covers evidence-grade logging standards, chain of custody requirements, tamper detection mechanisms, and retention policies that ensure logs are admissible and reliable for incident response and legal proceedings.

---

## 1. Evidence-Grade Log Requirements

Forensic-quality logs must meet specific criteria to be useful in investigations and admissible in legal proceedings:

```yaml
# Forensic logging standard — minimum fields per log entry
required_fields:
  timestamp:
    format: "ISO 8601 with timezone (2026-05-30T14:23:45.123456+00:00)"
    precision: "microsecond minimum"
    source: "NTP-synchronized system clock"
    requirement: "MUST use UTC for storage, convert for display only"

  identity:
    user_id: "Authenticated user identifier"
    session_id: "Unique session token"
    source_ip: "Client IP (after proxy resolution via X-Forwarded-For)"
    user_agent: "Full User-Agent string"

  action:
    event_type: "Categorized action (auth.login, data.export, admin.config_change)"
    resource: "Target resource identifier (URI, database table, file path)"
    outcome: "success | failure | error"
    detail: "Human-readable description of what occurred"

  context:
    request_id: "Correlation ID for distributed tracing"
    service_name: "Originating service identifier"
    environment: "production | staging | development"
    hostname: "Server hostname or container ID"
```

---

## 2. Implementing Structured Forensic Logging

Configure applications to produce forensic-quality structured logs:

```python
#!/usr/bin/env python3
"""Forensic-grade structured logging configuration."""

import json
import hashlib
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone

@dataclass(frozen=True)
class ForensicLogEntry:
    timestamp: str
    event_type: str
    user_id: str
    session_id: str
    source_ip: str
    resource: str
    outcome: str
    detail: str
    request_id: str
    service_name: str
    hostname: str
    integrity_hash: str = ""

    def with_integrity(self) -> "ForensicLogEntry":
        """Create new entry with computed integrity hash."""
        entry_data = json.dumps(asdict(self), sort_keys=True, default=str)
        hash_value = hashlib.sha256(entry_data.encode()).hexdigest()
        return ForensicLogEntry(
            timestamp=self.timestamp,
            event_type=self.event_type,
            user_id=self.user_id,
            session_id=self.session_id,
            source_ip=self.source_ip,
            resource=self.resource,
            outcome=self.outcome,
            detail=self.detail,
            request_id=self.request_id,
            service_name=self.service_name,
            hostname=self.hostname,
            integrity_hash=hash_value
        )

def create_forensic_entry(
    event_type: str, user_id: str, session_id: str,
    source_ip: str, resource: str, outcome: str,
    detail: str, request_id: str
) -> ForensicLogEntry:
    """Create a forensic log entry with all required fields."""
    import socket
    entry = ForensicLogEntry(
        timestamp=datetime.now(timezone.utc).isoformat(),
        event_type=event_type,
        user_id=user_id,
        session_id=session_id,
        source_ip=source_ip,
        resource=resource,
        outcome=outcome,
        detail=detail,
        request_id=request_id,
        service_name="auth-service",
        hostname=socket.gethostname()
    )
    return entry.with_integrity()
```

---

## 3. Chain of Custody Implementation

Maintain provable chain of custody for log data from creation to analysis:

```bash
# Step 1: Secure log collection with integrity verification
# Configure rsyslog to sign log entries with RFC 5848 (signed syslog)
cat > /etc/rsyslog.d/50-forensic.conf << 'EOF'
# Enable log signing
module(load="lmsig_gt")

# Sign all security-relevant logs
action(
  type="omfile"
  file="/var/log/forensic/security.log"
  sig.provider="gt"
  sig.hashFunction="SHA-256"
  sig.block.sizeLimit="100"
)

# Forward to immutable storage with TLS
action(
  type="omfwd"
  target="logserver.internal"
  port="6514"
  protocol="tcp"
  StreamDriver="gtls"
  StreamDriverMode="1"
  StreamDriverAuthMode="x509/name"
)
EOF

# Step 2: Generate hash chain for log files
# Each log file gets a SHA-256 hash, chained to previous
generate_hash_chain() {
  local log_dir="/var/log/forensic"
  local chain_file="$log_dir/hash_chain.json"
  local prev_hash="GENESIS"

  for logfile in $(ls -t "$log_dir"/security.log.*); do
    current_hash=$(sha256sum "$logfile" | cut -d' ' -f1)
    timestamp=$(stat -c %Y "$logfile")
    echo "{\"file\":\"$logfile\",\"hash\":\"$current_hash\",\"prev\":\"$prev_hash\",\"ts\":$timestamp}" >> "$chain_file"
    prev_hash="$current_hash"
  done
}

# Step 3: Verify chain integrity
verify_hash_chain() {
  local chain_file="/var/log/forensic/hash_chain.json"
  local prev_hash="GENESIS"

  while IFS= read -r entry; do
    expected_prev=$(echo "$entry" | jq -r '.prev')
    if [ "$expected_prev" != "$prev_hash" ]; then
      echo "CHAIN BROKEN at: $(echo "$entry" | jq -r '.file')"
      return 1
    fi
    file=$(echo "$entry" | jq -r '.file')
    actual_hash=$(sha256sum "$file" | cut -d' ' -f1)
    recorded_hash=$(echo "$entry" | jq -r '.hash')
    if [ "$actual_hash" != "$recorded_hash" ]; then
      echo "FILE TAMPERED: $file"
      return 1
    fi
    prev_hash="$recorded_hash"
  done < "$chain_file"
  echo "Chain integrity verified"
}
```

---

## 4. Tamper Detection Mechanisms

Implement multiple layers of tamper detection for log integrity:

```bash
# Method 1: Append-only filesystem with immutable flag
# Create dedicated log partition with append-only attribute
chattr +a /var/log/forensic/security.log
# Now only append operations succeed; no deletion or modification

# Method 2: Remote log shipping to write-once storage
# Ship logs to S3 with Object Lock (WORM compliance)
aws s3api put-object-lock-configuration \
  --bucket forensic-logs-prod \
  --object-lock-configuration '{
    "ObjectLockEnabled": "Enabled",
    "Rule": {
      "DefaultRetention": {
        "Mode": "COMPLIANCE",
        "Days": 2555
      }
    }
  }'

# Upload log with retention lock
aws s3 cp /var/log/forensic/security.log.1 \
  "s3://forensic-logs-prod/$(date +%Y/%m/%d)/security.log.gz" \
  --object-lock-mode COMPLIANCE \
  --object-lock-retain-until-date "2033-05-30T00:00:00Z"

# Method 3: Blockchain-anchored log hashes
# Periodically anchor log hashes to a timestamping service
LOG_HASH=$(sha256sum /var/log/forensic/security.log | cut -d' ' -f1)
curl -X POST "https://timestamp.service/api/v1/stamp" \
  -H "Content-Type: application/json" \
  -d "{\"hash\": \"$LOG_HASH\", \"algorithm\": \"sha256\"}"
```

---

## 5. Retention Policy Configuration

Define and enforce retention policies that meet legal and compliance requirements:

```yaml
# log-retention-policy.yaml
retention_policies:
  security_events:
    description: "Authentication, authorization, access control events"
    retention_period: 7_years
    compliance: ["SOX", "PCI-DSS", "HIPAA"]
    storage_tier:
      hot: 90_days      # Elasticsearch, instant query
      warm: 365_days    # S3 Standard, minutes to access
      cold: 2555_days   # S3 Glacier, hours to access
    deletion: "Automated after retention + 30-day grace period"
    legal_hold: "Suspend deletion when litigation hold active"

  network_traffic:
    description: "Firewall logs, DNS queries, flow data"
    retention_period: 1_year
    compliance: ["PCI-DSS"]
    storage_tier:
      hot: 30_days
      warm: 180_days
      cold: 365_days

  application_logs:
    description: "Application debug and info level logs"
    retention_period: 90_days
    compliance: ["internal"]
    storage_tier:
      hot: 30_days
      warm: 60_days
      cold: 0  # Delete after warm

  audit_trail:
    description: "Administrative actions, configuration changes"
    retention_period: 10_years
    compliance: ["SOX", "GDPR"]
    storage_tier:
      hot: 180_days
      warm: 730_days
      cold: 3650_days
    immutable: true  # Cannot be deleted even by admins
```

---

## 6. Log Integrity Monitoring

Continuously monitor for signs of log tampering or gaps:

```bash
# Detect log gaps (missing time periods indicate tampering or failure)
#!/bin/bash
# gap-detector.sh — finds time gaps in log streams

LOG_FILE="/var/log/forensic/security.log"
MAX_GAP_SECONDS=300  # Alert if > 5 minutes between entries

prev_ts=0
while IFS= read -r line; do
  current_ts=$(echo "$line" | jq -r '.timestamp' | date -d - +%s 2>/dev/null)
  if [ "$prev_ts" -ne 0 ] && [ -n "$current_ts" ]; then
    gap=$((current_ts - prev_ts))
    if [ "$gap" -gt "$MAX_GAP_SECONDS" ]; then
      echo "GAP DETECTED: ${gap}s gap at $(date -d @$prev_ts -Iseconds)"
    fi
  fi
  prev_ts="$current_ts"
done < "$LOG_FILE"

# Detect log truncation (file size decreased)
# Run via cron every minute
CURRENT_SIZE=$(stat -c %s /var/log/forensic/security.log)
PREVIOUS_SIZE=$(cat /var/run/log_size_prev 2>/dev/null || echo 0)
if [ "$CURRENT_SIZE" -lt "$PREVIOUS_SIZE" ]; then
  echo "ALERT: Log file truncated! Was $PREVIOUS_SIZE, now $CURRENT_SIZE" | \
    mail -s "LOG TAMPERING ALERT" security@company.com
fi
echo "$CURRENT_SIZE" > /var/run/log_size_prev

# Verify log shipping completeness
# Compare local log count with remote storage count
LOCAL_COUNT=$(wc -l < /var/log/forensic/security.log)
REMOTE_COUNT=$(aws s3 cp "s3://forensic-logs/today/security.log" - | wc -l)
DELTA=$((LOCAL_COUNT - REMOTE_COUNT))
if [ "$DELTA" -gt 100 ]; then
  echo "WARNING: $DELTA log entries missing from remote storage"
fi
```

---

## 7. Compliance-Specific Logging Requirements

Map logging requirements to specific compliance frameworks:

```yaml
# compliance-logging-matrix.yaml
frameworks:
  PCI_DSS:
    requirement: "10.x — Track and monitor all access"
    mandatory_events:
      - "All access to cardholder data"
      - "All actions by any individual with root/admin privileges"
      - "Access to all audit trails"
      - "Invalid logical access attempts"
      - "Use of identification and authentication mechanisms"
      - "Initialization, stopping, or pausing of audit logs"
      - "Creation and deletion of system-level objects"
    retention: "1 year minimum, 3 months immediately available"
    review: "Daily review of security events"

  HIPAA:
    requirement: "164.312(b) — Audit controls"
    mandatory_events:
      - "Access to electronic protected health information (ePHI)"
      - "Authentication events for ePHI systems"
      - "Changes to ePHI records"
      - "Administrative actions on ePHI systems"
    retention: "6 years from creation or last effective date"
    review: "Regular review of audit logs"

  SOX:
    requirement: "Section 302/404 — Internal controls"
    mandatory_events:
      - "Financial system access and modifications"
      - "Database changes to financial records"
      - "Administrative privilege usage"
      - "Configuration changes to financial systems"
    retention: "7 years"
    review: "Quarterly review with annual audit"
```

---

## 8. Forensic Log Analysis Queries

Pre-built queries for common forensic investigation scenarios:

```bash
# Timeline reconstruction for incident response
# Find all actions by a compromised user account
curl -s "http://siem:9200/forensic-*/_search" \
  -H "Content-Type: application/json" \
  -d '{
    "query": {
      "bool": {
        "must": [
          {"term": {"user_id": "compromised_user@company.com"}},
          {"range": {"@timestamp": {"gte": "2026-05-28T00:00:00Z", "lte": "2026-05-30T23:59:59Z"}}}
        ]
      }
    },
    "sort": [{"@timestamp": "asc"}],
    "size": 10000
  }' | jq '.hits.hits[]._source | {time: .timestamp, action: .event_type, resource: .resource, outcome: .outcome}'

# Detect privilege escalation patterns
# User accessing resources beyond their normal pattern
curl -s "http://siem:9200/forensic-*/_search" \
  -H "Content-Type: application/json" \
  -d '{
    "query": {
      "bool": {
        "must": [
          {"term": {"outcome": "success"}},
          {"terms": {"event_type": ["admin.config_change", "data.export", "auth.privilege_grant"]}},
          {"range": {"@timestamp": {"gte": "now-24h"}}}
        ],
        "must_not": [
          {"terms": {"user_id": ["admin@company.com", "sre-bot@company.com"]}}
        ]
      }
    },
    "sort": [{"@timestamp": "desc"}]
  }' | jq '.hits.hits[]._source'

# Evidence preservation — export with integrity verification
EXPORT_FILE="incident_2026_05_30_evidence.jsonl"
curl -s "http://siem:9200/forensic-*/_search?scroll=5m" \
  -H "Content-Type: application/json" \
  -d '{"query":{"term":{"incident_id":"INC-2026-0530"}},"size":1000}' > "$EXPORT_FILE"
sha256sum "$EXPORT_FILE" > "${EXPORT_FILE}.sha256"
echo "Evidence exported: $(wc -l < $EXPORT_FILE) entries"
echo "Integrity hash: $(cat ${EXPORT_FILE}.sha256)"
```

Forensic-quality logging is not optional for organizations handling sensitive data. The difference between logs that support an investigation and logs that are useless in court comes down to completeness, integrity, and provable chain of custody — all of which must be designed in from the start, not bolted on after an incident.
