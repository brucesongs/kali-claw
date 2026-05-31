# Continuous Security Validation Guide

> Practical reference for implementing scheduled security scans, configuration drift detection, and compliance monitoring. Covers automated scanning pipelines, alerting on security regressions, and maintaining security posture over time.

## 1. Scheduled Scanning Architecture

Continuous validation runs security checks on a recurring basis, catching regressions and new exposures.

```yaml
# scanning-schedule.yaml — Define scan cadence by type
schedules:
  vulnerability_scan:
    tool: nuclei
    frequency: daily
    targets: production_assets.txt
    severity_threshold: medium
    
  configuration_audit:
    tool: scout-suite
    frequency: weekly
    targets: aws,gcp
    compliance: cis-benchmark
    
  dependency_check:
    tool: grype
    frequency: on_deploy + daily
    targets: container_images
    
  secret_scan:
    tool: trufflehog
    frequency: on_commit + daily
    targets: git_repositories
    
  ssl_monitoring:
    tool: testssl
    frequency: weekly
    targets: external_domains.txt
```

## 2. Automated Vulnerability Scanning Pipeline

```bash
#!/bin/bash
# continuous_scan.sh — Daily automated security scan
SCAN_DATE=$(date +%Y%m%d)
RESULTS_DIR="/opt/security/scans/$SCAN_DATE"
BASELINE_DIR="/opt/security/baseline"
ALERT_WEBHOOK="${SECURITY_WEBHOOK_URL}"
mkdir -p "$RESULTS_DIR"

echo "[$(date)] Starting continuous security scan"

# Scan external assets with nuclei
nuclei -l /opt/security/targets/external.txt \
  -t /opt/nuclei-templates/ \
  -severity critical,high,medium \
  -json -o "$RESULTS_DIR/nuclei_external.json" \
  -rl 50 -c 10 -timeout 15 \
  -silent

# Scan internal assets
nuclei -l /opt/security/targets/internal.txt \
  -t /opt/nuclei-templates/ \
  -severity critical,high \
  -json -o "$RESULTS_DIR/nuclei_internal.json" \
  -silent

# Compare against baseline — find NEW findings
python3 /opt/security/scripts/diff_findings.py \
  "$BASELINE_DIR/latest.json" \
  "$RESULTS_DIR/nuclei_external.json" \
  > "$RESULTS_DIR/new_findings.json"

# Alert on new critical/high findings
NEW_COUNT=$(jq 'length' "$RESULTS_DIR/new_findings.json")
if [ "$NEW_COUNT" -gt 0 ]; then
    curl -s -X POST "$ALERT_WEBHOOK" \
      -H "Content-Type: application/json" \
      -d "{\"text\": \"Security Alert: $NEW_COUNT new findings detected. Review: $RESULTS_DIR\"}"
fi

echo "[$(date)] Scan complete. New findings: $NEW_COUNT"
```

## 3. Configuration Drift Detection

```python
#!/usr/bin/env python3
"""Detect security configuration drift from approved baseline."""
import json
import subprocess
from dataclasses import dataclass
from typing import List, Tuple
from pathlib import Path

@dataclass(frozen=True)
class DriftItem:
    resource: str
    setting: str
    expected: str
    actual: str
    severity: str

def check_aws_drift() -> List[DriftItem]:
    """Check AWS security configuration against baseline."""
    drifts = []
    
    # Check S3 bucket public access
    result = subprocess.run(
        ["aws", "s3api", "list-buckets", "--query", "Buckets[].Name", "--output", "json"],
        capture_output=True, text=True
    )
    buckets = json.loads(result.stdout)
    
    for bucket in buckets:
        pub_result = subprocess.run(
            ["aws", "s3api", "get-public-access-block", "--bucket", bucket],
            capture_output=True, text=True
        )
        if pub_result.returncode != 0:
            drifts.append(DriftItem(
                resource=f"s3://{bucket}",
                setting="PublicAccessBlock",
                expected="enabled",
                actual="not configured",
                severity="HIGH"
            ))
    
    # Check security groups for 0.0.0.0/0 ingress
    sg_result = subprocess.run(
        ["aws", "ec2", "describe-security-groups", "--output", "json"],
        capture_output=True, text=True
    )
    sgs = json.loads(sg_result.stdout).get("SecurityGroups", [])
    
    for sg in sgs:
        for rule in sg.get("IpPermissions", []):
            for ip_range in rule.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0":
                    port = rule.get("FromPort", "all")
                    if port not in (80, 443):
                        drifts.append(DriftItem(
                            resource=f"sg:{sg['GroupId']}",
                            setting=f"ingress_port_{port}",
                            expected="restricted",
                            actual="0.0.0.0/0",
                            severity="CRITICAL"
                        ))
    
    return drifts

if __name__ == "__main__":
    drifts = check_aws_drift()
    for d in drifts:
        print(f"[{d.severity}] {d.resource}: {d.setting} = {d.actual} (expected: {d.expected})")
```

## 4. SSL/TLS Certificate Monitoring

```bash
#!/bin/bash
# monitor_ssl.sh — Check certificate expiry and configuration
DOMAINS_FILE="/opt/security/targets/domains.txt"
ALERT_DAYS=30

while IFS= read -r domain; do
    [ -z "$domain" ] && continue
    
    # Check certificate expiry
    expiry=$(echo | openssl s_client -servername "$domain" -connect "$domain:443" 2>/dev/null | \
             openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
    
    if [ -n "$expiry" ]; then
        expiry_epoch=$(date -d "$expiry" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$expiry" +%s 2>/dev/null)
        now_epoch=$(date +%s)
        days_left=$(( (expiry_epoch - now_epoch) / 86400 ))
        
        if [ "$days_left" -lt "$ALERT_DAYS" ]; then
            echo "[WARN] $domain: Certificate expires in $days_left days ($expiry)"
        fi
    else
        echo "[ERROR] $domain: Could not retrieve certificate"
    fi
done < "$DOMAINS_FILE"

# Full TLS audit with testssl
testssl --json-pretty --severity HIGH \
  --file "$DOMAINS_FILE" \
  --outfile /opt/security/scans/ssl_audit.json
```

## 5. Container Image Scanning

```bash
# Scan container images on build and on schedule
#!/bin/bash
REGISTRY="registry.company.com"
RESULTS_DIR="/opt/security/scans/containers/$(date +%Y%m%d)"
mkdir -p "$RESULTS_DIR"

# Get list of production images
IMAGES=$(kubectl get pods -A -o jsonpath='{.items[*].spec.containers[*].image}' | tr ' ' '\n' | sort -u)

for image in $IMAGES; do
    safe_name=$(echo "$image" | tr '/:' '_')
    echo "[*] Scanning: $image"
    
    # Scan with grype
    grype "$image" -o json > "$RESULTS_DIR/${safe_name}_grype.json" 2>/dev/null
    
    # Count by severity
    critical=$(jq '[.matches[] | select(.vulnerability.severity=="Critical")] | length' "$RESULTS_DIR/${safe_name}_grype.json")
    high=$(jq '[.matches[] | select(.vulnerability.severity=="High")] | length' "$RESULTS_DIR/${safe_name}_grype.json")
    
    if [ "$critical" -gt 0 ] || [ "$high" -gt 5 ]; then
        echo "  [!] $image: $critical critical, $high high vulnerabilities"
    fi
done

# Generate summary report
echo "=== Container Scan Summary ===" > "$RESULTS_DIR/summary.txt"
for f in "$RESULTS_DIR"/*_grype.json; do
    image=$(basename "$f" _grype.json | tr '_' '/')
    total=$(jq '.matches | length' "$f")
    echo "$image: $total vulnerabilities" >> "$RESULTS_DIR/summary.txt"
done
```

## 6. Compliance Monitoring

```yaml
# compliance-checks.yaml — CIS Benchmark automated checks
checks:
  - id: CIS-1.1
    name: "Ensure MFA is enabled for root account"
    command: "aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled'"
    expected: "1"
    severity: critical

  - id: CIS-2.1
    name: "Ensure CloudTrail is enabled in all regions"
    command: "aws cloudtrail describe-trails --query 'trailList[?IsMultiRegionTrail==`true`].Name'"
    expected_not_empty: true
    severity: high

  - id: CIS-3.1
    name: "Ensure VPC flow logging is enabled"
    command: "aws ec2 describe-flow-logs --query 'FlowLogs[].FlowLogId'"
    expected_not_empty: true
    severity: medium
```

```bash
# Run compliance checks
#!/bin/bash
echo "=== CIS Compliance Check ==="
PASS=0; FAIL=0; TOTAL=0

check_compliance() {
    local id="$1" name="$2" cmd="$3" expected="$4"
    TOTAL=$((TOTAL + 1))
    
    result=$(eval "$cmd" 2>/dev/null)
    if echo "$result" | grep -q "$expected"; then
        echo "[PASS] $id: $name"
        PASS=$((PASS + 1))
    else
        echo "[FAIL] $id: $name (got: $result)"
        FAIL=$((FAIL + 1))
    fi
}

check_compliance "CIS-1.1" "Root MFA enabled" \
    "aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled' --output text" "1"

check_compliance "CIS-2.3" "S3 bucket logging" \
    "aws s3api get-bucket-logging --bucket main-bucket --output text" "LoggingEnabled"

echo "=== Results: $PASS passed, $FAIL failed, $TOTAL total ==="
echo "Compliance: $(( PASS * 100 / TOTAL ))%"
```

## 7. Alerting and Notification

```python
#!/usr/bin/env python3
"""Security alerting based on scan results and thresholds."""
import json
import requests
from pathlib import Path
from dataclasses import dataclass
from typing import List

@dataclass(frozen=True)
class Alert:
    severity: str
    title: str
    details: str
    source: str

def evaluate_scan_results(results_file: str) -> List[Alert]:
    """Evaluate scan results against alerting thresholds."""
    alerts = []
    results = json.loads(Path(results_file).read_text())
    
    for finding in results:
        severity = finding.get("info", {}).get("severity", "unknown")
        if severity in ("critical", "high"):
            alerts.append(Alert(
                severity=severity.upper(),
                title=finding["info"]["name"],
                details=f"Found at: {finding.get('matched-at', 'unknown')}",
                source=results_file
            ))
    
    return alerts

def send_slack_alert(alerts: List[Alert], webhook_url: str) -> None:
    """Send security alerts to Slack."""
    if not alerts:
        return
    
    blocks = [{"type": "header", "text": {"type": "plain_text", "text": f"Security Alert: {len(alerts)} new findings"}}]
    
    for alert in alerts[:10]:  # Limit to 10 in notification
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*[{alert.severity}]* {alert.title}\n{alert.details}"}
        })
    
    requests.post(webhook_url, json={"blocks": blocks})

if __name__ == "__main__":
    import sys
    alerts = evaluate_scan_results(sys.argv[1])
    if alerts:
        send_slack_alert(alerts, "https://hooks.slack.com/services/XXX/YYY/ZZZ")
        print(f"Sent {len(alerts)} alerts")
```

## 8. Dashboard and Trend Tracking

```bash
# Generate metrics for security dashboard
#!/bin/bash
METRICS_FILE="/opt/security/metrics/$(date +%Y%m%d).json"

# Collect daily metrics
cat > "$METRICS_FILE" <<EOF
{
  "date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "vulnerabilities": {
    "critical": $(find /opt/security/scans/$(date +%Y%m%d) -name "*.json" -exec jq '[.[] | select(.severity=="critical")] | length' {} + 2>/dev/null | paste -sd+ | bc || echo 0),
    "high": $(find /opt/security/scans/$(date +%Y%m%d) -name "*.json" -exec jq '[.[] | select(.severity=="high")] | length' {} + 2>/dev/null | paste -sd+ | bc || echo 0),
    "new_today": $(jq 'length' /opt/security/scans/$(date +%Y%m%d)/new_findings.json 2>/dev/null || echo 0),
    "fixed_today": $(jq 'length' /opt/security/scans/$(date +%Y%m%d)/resolved.json 2>/dev/null || echo 0)
  },
  "compliance_score": 85,
  "mean_time_to_remediate_days": 4.2,
  "scan_coverage_percent": 94
}
EOF

# Append to time-series for trending
jq -s '.' /opt/security/metrics/2025*.json > /opt/security/metrics/trend.json

echo "Metrics written to $METRICS_FILE"
```
