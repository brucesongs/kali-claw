# SIEM Log Analysis Guide

## Overview

Security Information and Event Management (SIEM) systems aggregate logs from multiple sources for correlation, alerting, and forensic analysis. This guide covers log analysis techniques for detecting attacks, building correlation rules, and tuning alert thresholds.

---

## Log Source Integration

### Common Log Sources

| Source | Format | Key Fields |
|--------|--------|------------|
| Web servers (Apache/Nginx) | Combined Log Format | IP, timestamp, method, URI, status, user-agent |
| Firewalls (iptables/pf) | Syslog | src_ip, dst_ip, port, action, protocol |
| Authentication (PAM/AD) | Syslog/EVTX | user, source, result, timestamp |
| Application logs | JSON/structured | varies by application |
| DNS servers | Query log | query, type, source_ip, response |
| Proxy servers | Access log | user, url, category, action |

### Syslog Forwarding Configuration

```bash
# rsyslog - forward to SIEM
# /etc/rsyslog.d/50-siem.conf
*.* @@siem.internal:514    # TCP
*.* @siem.internal:514     # UDP

# Filebeat configuration for JSON logs
# /etc/filebeat/filebeat.yml
filebeat.inputs:
- type: log
  paths:
    - /var/log/auth.log
    - /var/log/syslog
  fields:
    log_type: system
output.elasticsearch:
  hosts: ["siem.internal:9200"]
```

### Windows Event Log Collection

```powershell
# Forward security events via WEF
wecutil qc /q:true
wecutil cs subscription.xml

# Key Event IDs
# 4624 - Successful logon
# 4625 - Failed logon
# 4648 - Explicit credential logon
# 4672 - Special privileges assigned
# 4720 - User account created
# 4732 - Member added to security group
```

---

## Correlation Rules

### Brute Force Detection

```yaml
# Splunk SPL
index=auth sourcetype=linux_secure "Failed password"
| stats count by src_ip, user
| where count > 5
| sort -count

# Elasticsearch query
{
  "query": {
    "bool": {
      "must": [
        {"match": {"event.action": "authentication_failure"}},
        {"range": {"@timestamp": {"gte": "now-5m"}}}
      ]
    }
  },
  "aggs": {
    "by_source": {
      "terms": {"field": "source.ip", "min_doc_count": 5}
    }
  }
}
```

### Lateral Movement Detection

```yaml
# Detect multiple hosts accessed from single source in short window
index=auth action=success
| stats dc(dest_host) as unique_hosts values(dest_host) as hosts by src_ip
| where unique_hosts > 3
| sort -unique_hosts
```

### Privilege Escalation Detection

```yaml
# Linux: detect sudo to root from unusual users
index=auth sourcetype=linux_secure "session opened for user root"
| stats count by user, src_ip
| where user!="admin" AND user!="deploy"

# Windows: detect new admin group membership
index=wineventlog EventCode=4732 TargetGroupName="Administrators"
| table _time, SubjectUserName, MemberName, TargetGroupName
```

### Data Exfiltration Indicators

```yaml
# Large outbound transfers
index=firewall direction=outbound
| stats sum(bytes_out) as total_bytes by src_ip, dst_ip
| where total_bytes > 100000000
| sort -total_bytes

# DNS tunneling detection (high query volume)
index=dns
| stats count dc(query) as unique_queries avg(len(query)) as avg_length by src_ip
| where count > 1000 AND avg_length > 50
```

---

## Alert Tuning

### Reducing False Positives

```yaml
# Baseline normal behavior first
index=auth action=success
| stats count by user, hour=strftime(_time, "%H")
| eventstats avg(count) as avg_count stdev(count) as std_count by user
| eval threshold = avg_count + (3 * std_count)

# Alert only on anomalies exceeding 3 standard deviations
| where count > threshold
```

### Alert Severity Classification

| Pattern | Severity | Response |
|---------|----------|----------|
| Single failed login | INFO | Log only |
| 5+ failed logins from same IP | MEDIUM | Auto-block after 10 |
| Successful login after failures | HIGH | Investigate immediately |
| Admin account login from new IP | CRITICAL | Page on-call |

### Suppression Rules

```yaml
# Suppress known scanner IPs
| where NOT cidrmatch("10.0.0.0/8", src_ip)
| where NOT src_ip IN ("vulnerability-scanner.internal")

# Suppress during maintenance windows
| where NOT (_time >= relative_time(now(), "@d+2h") AND _time <= relative_time(now(), "@d+4h") AND strftime(_time, "%w")="6")
```

---

## Log Enrichment

### GeoIP Enrichment

```yaml
# Splunk
| iplocation src_ip
| where Country!="United States" AND action=success

# Elasticsearch (ingest pipeline)
{
  "geoip": {
    "field": "source.ip",
    "target_field": "source.geo"
  }
}
```

### Threat Intelligence Correlation

```yaml
# Match against IOC feed
| lookup threat_intel_ip ip AS src_ip OUTPUT threat_category, confidence
| where isnotnull(threat_category) AND confidence > 70
| table _time, src_ip, threat_category, confidence, action
```

### User Context Enrichment

```yaml
# Join with HR/identity data
| lookup user_directory user AS username OUTPUT department, role, manager
| eval risk_score = case(
    role="admin", 80,
    department="finance", 60,
    1=1, 40
)
```

---

## Forensic Analysis Patterns

### Timeline Reconstruction

```yaml
# Build attack timeline from multiple sources
index=* (src_ip="10.0.1.50" OR dst_ip="10.0.1.50")
| sort _time
| table _time, index, sourcetype, action, src_ip, dst_ip, user, details
| head 1000
```

### Session Tracking

```yaml
# Track full session from login to logout
index=auth user="compromised_user"
| transaction user startswith="session opened" endswith="session closed"
| table _time, duration, eventcount, src_ip
```

### Evidence Preservation

```bash
# Export raw logs for forensic chain of custody
splunk search 'index=* src_ip="attacker_ip" earliest=-7d' -output rawdata > evidence_export.log
sha256sum evidence_export.log > evidence_export.log.sha256
```

---

## Testing SIEM Detection

### Atomic Red Team Integration

```bash
# Execute test and verify SIEM detection
# T1110.001 - Brute Force: Password Guessing
for i in $(seq 1 20); do
    sshpass -p "wrong" ssh -o StrictHostKeyChecking=no user@target 2>/dev/null
done

# Verify alert fired within SLA
sleep 60
curl -s "http://siem:9200/alerts/_search?q=rule_name:brute_force" | jq '.hits.total'
```

### Detection Coverage Matrix

| MITRE ATT&CK | Technique | Detection Rule | Status |
|--------------|-----------|----------------|--------|
| T1110 | Brute Force | auth_brute_force | Active |
| T1021 | Remote Services | lateral_movement | Active |
| T1078 | Valid Accounts | anomalous_login | Active |
| T1048 | Exfiltration | large_transfer | Active |
| T1071 | Application Layer Protocol | dns_tunnel | Active |
