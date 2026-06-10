# Scope Management Guide

## Introduction

Scope management defines what is in-bounds and out-of-bounds for a penetration test. Poor scope management leads to legal liability, production outages, incomplete assessments, and damaged client relationships. Effective scope management is a discipline that requires clear documentation, continuous verification, and disciplined enforcement throughout the engagement.

Scope is not just a list of IP addresses — it encompasses target systems, testing techniques, time windows, depth of testing, and communication protocols. Every aspect of what the engagement will and will not do must be explicitly defined and agreed upon before testing begins. Ambiguity in scope is the root cause of most engagement disputes.

## Scope Definition

### Required Elements

Every penetration test engagement must have a scope document that addresses all of the following elements:

1. **Target inventory**: Complete list of all IP ranges, domains, applications, APIs, and cloud resources to be tested. Each target should have an assigned type (web, network, cloud, mobile, API) for skill composition.

2. **Exclusions**: Explicit list of systems that must not be tested. Exclusions are as important as inclusions — missing an exclusion can cause production outages or legal issues.

3. **Testing windows**: Specific dates and times when testing is permitted. Some clients require after-hours testing only, others permit business-hours testing with advance notice.

4. **Technique restrictions**: Clear definition of what testing techniques are allowed and prohibited. Common restrictions include no denial-of-service testing, no social engineering, no data exfiltration, and no physical access testing.

5. **Emergency procedures**: Documented process for immediately stopping testing if a critical issue is discovered or a production problem occurs. Must include 24/7 emergency contacts.

6. **Communication plan**: Frequency and format of status updates, escalation procedures, and stakeholder notification requirements.

7. **Depth of testing**: Whether testing should be comprehensive (all vulnerabilities) or focused (specific attack surfaces or vulnerability classes).

### Scope Document Template

The scope document should use a machine-readable format for automated enforcement:

```json
{
    "engagement_id": "ENG-20260610",
    "client": "Client Name",
    "type": "web",
    "scope": {
        "targets": [
            {"type": "web", "value": "example.com", "description": "Main web application"},
            {"type": "network", "value": "192.168.1.0/24", "description": "Internal network"}
        ],
        "domains": ["example.com", "app.example.com"],
        "ip_ranges": ["192.168.1.0/24"],
        "applications": ["Web Portal v3.2", "REST API v2"]
    },
    "exclusions": {
        "targets": [
            {"value": "admin.example.com", "reason": "Production admin panel"},
            {"value": "192.168.1.1", "reason": "Core router"}
        ],
        "techniques": ["denial_of_service", "social_engineering", "physical_access"],
        "data_handling": ["no_exfiltration", "no_modification"]
    },
    "rules_of_engagement": {
        "testing_window": {"start": "2026-06-10T09:00:00Z", "end": "2026-06-14T17:00:00Z"},
        "denial_of_service": false,
        "data_exfiltration": false,
        "social_engineering": false,
        "physical_access": false,
        "notification_threshold": "critical",
        "notification_window_hours": 4
    },
    "contacts": {
        "primary": {"name": "Client Contact", "email": "contact@example.com", "phone": "+1-555-0100"},
        "emergency": {"name": "Emergency Contact", "phone": "+1-555-0199"}
    }
}
```

## Scope Boundary Rules

### Hard Boundaries (Never Cross)

Hard boundaries represent absolute limits that must never be violated under any circumstances. Crossing a hard boundary constitutes a scope violation that must be reported immediately:

- Targets not listed in the approved scope document
- Production databases containing real user data (unless explicitly authorized)
- Third-party systems not owned by the client (CDNs, SaaS platforms, shared hosting)
- Systems explicitly listed in the exclusions section of the scope document
- Techniques explicitly prohibited in the rules of engagement
- Testing outside the approved testing window

### Soft Boundaries (Confirm Before Crossing)

Soft boundaries represent gray areas that require explicit client approval before proceeding. Document the request and approval:

- Subdomains discovered during reconnaissance not in original scope
- Cloud resources not initially identified during scoping
- APIs discovered during testing that were not in the original scope
- Internal networks reached via pivoting through compromised hosts
- Staging or development environments that may share infrastructure with production
- Partner or vendor systems that interact with in-scope targets

## Scope Change Management

Scope changes during an engagement are common and must be handled through a formal process:

### Change Process

1. **Document the proposed change**: Clearly describe what is being added, removed, or modified, and why
2. **Assess impact**: Determine how the change affects timeline, risk, and resource requirements
3. **Obtain written client approval**: No verbal approvals — all scope changes must be documented in writing
4. **Update scope document**: Modify the scope document with the change and timestamp
5. **Notify all team members**: Ensure everyone on the engagement team is aware of the change
6. **Resume testing**: Only after written approval is received and documented

### Common Scope Change Scenarios

- Client requests additional target systems after testing has begun
- Discovered subdomains or cloud resources expand the attack surface
- Critical finding requires deeper testing than originally scoped
- Timeline extension needed due to complexity or findings volume
- Client requests technique changes (e.g., allowing DoS testing on non-production systems)

## Scope Verification Checklist

Run this verification checklist before each phase begins to ensure ongoing scope compliance:

### Pre-Phase Verification

- [ ] Current targets are within approved scope (check against scope document)
- [ ] No excluded targets are being tested (verify against exclusion list)
- [ ] Testing techniques are within approved methods (check rules of engagement)
- [ ] Testing is occurring within approved time windows (check current time against window)
- [ ] Emergency contacts are current and reachable (test contact method)
- [ ] Scope document is the latest approved version (check document timestamp)

### Automated Scope Verification

Use scripts to automate scope verification before critical actions:

```bash
# Verify target is in scope before scanning
TARGET="192.168.1.50"
if grep -q "$TARGET" engagement/scope/targets.txt; then
    echo "IN SCOPE: $TARGET"
else
    echo "OUT OF SCOPE: $TARGET — SKIPPING"
fi

# Check if current time is within testing window
python3 -c "
import datetime, json
with open('engagement/scope/scope-rules.json') as f:
    scope = json.load(f)
now = datetime.datetime.utcnow()
start = datetime.datetime.fromisoformat(scope['rules_of_engagement']['testing_window']['start'].replace('Z','+00:00'))
end = datetime.datetime.fromisoformat(scope['rules_of_engagement']['testing_window']['end'].replace('Z','+00:00'))
if start <= now <= end:
    print('WITHIN TESTING WINDOW')
else:
    print('OUTSIDE TESTING WINDOW — STOP')
"
```

## Scope Violation Response

If a scope violation occurs, follow this response protocol immediately:

1. **Stop all testing** — Immediately cease all testing activity
2. **Document the violation** — Record what happened, when, and what was affected
3. **Assess impact** — Determine if any out-of-scope systems were affected
4. **Notify client** — Contact the primary client contact within 1 hour
5. **Notify team** — Alert all engagement team members to pause work
6. **Root cause analysis** — Determine why the violation occurred
7. **Prevent recurrence** — Implement controls to prevent similar violations
8. **Resume only after approval** — Get written approval before resuming testing

## Hands-on Exercise

Practice scope management in a controlled environment:

1. Create a scope document for a mock web application engagement with 3 in-scope targets and 2 exclusions
2. Set up automated scope verification scripts
3. Simulate a scope violation by attempting to scan an excluded target
4. Practice the scope change management process by requesting and documenting a scope expansion
5. Create a scope verification checklist and run it against a mock engagement

## References

- Rules of Engagement Template: validation/engagement-template/scope-rules.json.example
- PTES Pre-engagement: http://www.pentest-standard.org/index.php/Preengagement
- CREST Penetration Testing Guide: https://www.crest-approved.org/
- NIST SP 800-115: Technical Guide to Information Security Testing and Assessment
- OSSTMM Scope Definition: https://www.isecom.org/OSSTMM.3.pdf
