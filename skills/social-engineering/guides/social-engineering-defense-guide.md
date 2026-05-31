# Social Engineering Defense Guide

> Comprehensive reference for building organizational resilience against social engineering attacks through awareness training, verification protocols, and incident response procedures.

---

## 1. Security Awareness Training Program

```yaml
# Training program structure
awareness_program:
  frequency: "quarterly"
  components:
    - module: "Phishing Recognition"
      duration: "30 minutes"
      format: "interactive_simulation"
      topics:
        - Identifying suspicious sender addresses
        - Hovering over links before clicking
        - Recognizing urgency manipulation
        - Reporting procedures
        
    - module: "Vishing Defense"
      duration: "20 minutes"
      format: "recorded_scenarios"
      topics:
        - Caller verification procedures
        - Information disclosure boundaries
        - Callback verification protocol
        
    - module: "Physical Security"
      duration: "15 minutes"
      format: "video_walkthrough"
      topics:
        - Tailgating prevention
        - Badge verification
        - Clean desk policy
        - USB device policy

  metrics:
    phish_click_rate_target: "<5%"
    report_rate_target: ">60%"
    training_completion: ">95%"
```

---

## 2. Verification Protocol Implementation

```python
# Automated caller verification system
import hashlib
import time
import secrets

class VerificationSystem:
    def __init__(self):
        self.pending_verifications = {}
    
    def generate_challenge(self, claimed_identity, contact_method):
        """Generate a verification challenge for claimed identity."""
        challenge_code = secrets.token_hex(3).upper()  # e.g., "A3F2B1"
        verification_id = hashlib.sha256(
            f"{claimed_identity}{time.time()}".encode()
        ).hexdigest()[:12]
        
        self.pending_verifications[verification_id] = {
            "identity": claimed_identity,
            "code": challenge_code,
            "created": time.time(),
            "expires": time.time() + 300,  # 5 minute expiry
            "verified": False,
        }
        
        # Send challenge via KNOWN contact method (not caller-provided)
        self.send_via_trusted_channel(claimed_identity, challenge_code)
        return verification_id
    
    def verify_response(self, verification_id, provided_code):
        """Verify the challenge response."""
        record = self.pending_verifications.get(verification_id)
        if not record:
            return {"status": "FAILED", "reason": "Unknown verification ID"}
        if time.time() > record["expires"]:
            return {"status": "FAILED", "reason": "Challenge expired"}
        if provided_code != record["code"]:
            return {"status": "FAILED", "reason": "Incorrect code"}
        
        record["verified"] = True
        return {"status": "VERIFIED", "identity": record["identity"]}
    
    def send_via_trusted_channel(self, identity, code):
        """Send code via pre-registered contact method from directory."""
        # Look up in corporate directory, NOT from caller-provided info
        print(f"Sending code {code} to {identity} via trusted channel")
```

---

## 3. Email Security Controls

```bash
# DMARC, SPF, DKIM configuration for inbound protection
# Check current DMARC policy
dig TXT _dmarc.company.com +short

# Recommended DMARC policy (reject spoofed emails)
# _dmarc.company.com TXT "v=DMARC1; p=reject; rua=mailto:dmarc-reports@company.com; pct=100"

# Verify SPF record
dig TXT company.com +short | grep spf

# Test email header analysis for spoofing indicators
cat suspicious_email.eml | grep -E "^(From|Return-Path|Received|Authentication-Results|X-Originating-IP):"

# Check if sender domain passes authentication
python3 -c "
import dns.resolver
domain = 'suspicious-sender.com'
try:
    spf = dns.resolver.resolve(domain, 'TXT')
    print(f'SPF: {[r for r in spf if \"spf\" in str(r)]}')
except: print('No SPF record')
try:
    dmarc = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
    print(f'DMARC: {list(dmarc)}')
except: print('No DMARC record')
"
```

```yaml
# Email gateway rules for social engineering indicators
email_gateway_rules:
  block:
    - condition: "sender_domain_age < 30_days"
      action: "quarantine"
    - condition: "display_name_matches_internal AND sender_external"
      action: "add_warning_banner"
    - condition: "contains_urgency_keywords AND has_link AND sender_new"
      action: "quarantine_and_alert"
      
  warning_banners:
    external_sender: "[EXTERNAL] This email originated outside the organization."
    new_sender: "[NEW SENDER] You have not received email from this sender before."
    link_mismatch: "[CAUTION] Links in this email may not go where expected."
    
  urgency_keywords:
    - "immediate action required"
    - "account will be suspended"
    - "verify within 24 hours"
    - "unauthorized access detected"
    - "wire transfer"
```

---

## 4. Phishing Simulation and Metrics

```python
# Phishing simulation metrics tracking and trending
import json
from datetime import datetime
from collections import defaultdict

class PhishingMetrics:
    def __init__(self):
        self.campaigns = []
    
    def record_campaign(self, campaign_data):
        """Record results from a phishing simulation campaign."""
        metrics = {
            "date": datetime.now().isoformat(),
            "total_targets": campaign_data["total"],
            "emails_delivered": campaign_data["delivered"],
            "emails_opened": campaign_data["opened"],
            "links_clicked": campaign_data["clicked"],
            "credentials_submitted": campaign_data["submitted"],
            "reported_to_security": campaign_data["reported"],
        }
        
        metrics["click_rate"] = metrics["links_clicked"] / metrics["total_targets"]
        metrics["submit_rate"] = metrics["credentials_submitted"] / metrics["total_targets"]
        metrics["report_rate"] = metrics["reported_to_security"] / metrics["total_targets"]
        metrics["resilience_score"] = (
            (1 - metrics["click_rate"]) * 0.4 +
            metrics["report_rate"] * 0.4 +
            (1 - metrics["submit_rate"]) * 0.2
        )
        
        self.campaigns.append(metrics)
        return metrics
    
    def generate_trend_report(self):
        """Show improvement over time."""
        if len(self.campaigns) < 2:
            return "Insufficient data for trending"
        
        latest = self.campaigns[-1]
        previous = self.campaigns[-2]
        
        return {
            "click_rate_change": latest["click_rate"] - previous["click_rate"],
            "report_rate_change": latest["report_rate"] - previous["report_rate"],
            "resilience_trend": latest["resilience_score"] - previous["resilience_score"],
            "target_met": latest["click_rate"] < 0.05 and latest["report_rate"] > 0.60,
        }
```

---

## 5. Incident Response for Social Engineering

```bash
# Immediate response playbook when SE attack is confirmed
#!/bin/bash
# social-engineering-response.sh

INCIDENT_ID="SE-$(date +%Y%m%d-%H%M%S)"
LOG_FILE="/var/log/security/se-incidents/${INCIDENT_ID}.log"

echo "[$INCIDENT_ID] Social Engineering Incident Response Initiated" | tee "$LOG_FILE"

# Step 1: Contain - Disable compromised credentials
echo "Step 1: Credential containment" | tee -a "$LOG_FILE"
# Disable affected user accounts
# az ad user update --id victim@company.com --account-enabled false
# aws iam update-login-profile --user-name victim --no-password-reset-required

# Step 2: Identify scope - Check for lateral movement
echo "Step 2: Scope identification" | tee -a "$LOG_FILE"
# Check authentication logs for compromised account
# grep "victim@company.com" /var/log/auth.log | tail -50

# Step 3: Alert - Notify potentially affected parties
echo "Step 3: Alerting affected parties" | tee -a "$LOG_FILE"
# Send targeted alert to department members

# Step 4: Preserve evidence
echo "Step 4: Evidence preservation" | tee -a "$LOG_FILE"
# Save original phishing email with full headers
# Screenshot any malicious pages still active
# Export relevant log entries
```

---

## 6. Reporting Channel Setup

```yaml
# Multi-channel reporting system for suspected social engineering
reporting_channels:
  email:
    address: "phishing@company.com"
    auto_response: true
    sla: "acknowledge within 15 minutes"
    
  button:
    type: "Outlook/Gmail phishing report button"
    action: "forward to SOC with full headers"
    user_feedback: "Thank you for reporting. Our team is reviewing."
    
  phone:
    hotline: "ext. 9-SECURITY (9-732)"
    hours: "24/7"
    script: "Security hotline, what is the nature of the suspicious activity?"
    
  chat:
    channel: "#security-reports"
    bot_triage: true
    escalation: "page on-call analyst if keywords match"
    
  metrics_tracked:
    - time_to_report (from receipt to report)
    - time_to_acknowledge (from report to SOC response)
    - time_to_contain (from acknowledge to threat neutralized)
    - false_positive_rate
```

Building a security-aware culture requires consistent training, easy reporting mechanisms, and positive reinforcement. Never punish employees for reporting suspected attacks, even if they initially fell for the pretext.
