# Target Profiling Guide for Security Assessments

## Introduction

Target profiling is the systematic process of mapping a subject's digital footprint, behavioral patterns, technology preferences, and professional network to build a comprehensive intelligence picture. In authorized security assessments, target profiling supports social engineering simulations, insider threat evaluations, and red team operations. This guide covers the methodology for digital footprint mapping, behavioral pattern analysis, technology stack identification, and professional network analysis using open-source intelligence tools.

Ethical note: Target profiling must only be performed within the scope of an authorized engagement. Always verify that the assessment scope explicitly covers the individuals being profiled.

## Practical Steps

### 1. Digital Footprint Mapping

Map the target's presence across digital platforms:

```bash
# Email address discovery and validation
theHarvester -d targetcompany.com -b all -l 500

# Phone number and email correlation
h8mail -t target@company.com

# Social media profile discovery
# Search for username variations across platforms
sherlock target_username --output sherlock_results.txt

# Domain and IP correlation
amass enum -passive -d targetcompany.com -o domains.txt

# Email breach database check (haveibeenpwned API)
curl -s -H "hibp-api-key: YOUR_KEY" \
  "https://haveibeenpwned.com/api/v3/breachedaccount/target@company.com" | jq
```

Build a comprehensive profile inventory:

```python
#!/usr/bin/env python3
"""Digital footprint inventory builder"""
import json

profile = {
    "target": "John Smith",
    "role": "Senior Developer",
    "company": "TargetCorp",
    "emails": [],
    "social_media": {},
    "domains": [],
    "tech_stack": [],
    "behavioral_patterns": {},
    "professional_network": [],
    "data_sources_checked": []
}

# Document each discovered asset
profile["emails"] = [
    {"address": "jsmith@targetcorp.com", "source": "LinkedIn", "valid": True},
    {"address": "john.smith@gmail.com", "source": "GitHub", "valid": True}
]

profile["social_media"] = {
    "github": {"username": "jsmith-dev", "repos": 23, "followers": 150},
    "linkedin": {"url": "linkedin.com/in/jsmith", "connections": "500+"},
    "twitter": {"handle": "@jsmith_dev", "tweets": 1200, "followers": 340}
}

with open("target_profile.json", "w") as f:
    json.dump(profile, f, indent=2)
```

### 2. Behavioral Pattern Analysis

Identify patterns in the target's online activity:

```bash
# Analyze GitHub commit patterns for working hours and tech preferences
curl -s "https://api.github.com/users/jsmith-dev/events/public" | \
  jq -r '.[] | select(.type=="PushEvent") | .created_at' | \
  cut -dT -f2 | cut -d: -f1 | sort | uniq -c | sort -rn

# Extract programming languages from repositories
curl -s "https://api.github.com/users/jsmith-dev/repos?per_page=100" | \
  jq -r '.[].language' | sort | uniq -c | sort -rn

# Analyze commit message patterns for project names and internal references
curl -s "https://api.github.com/users/jsmith-dev/events/public" | \
  jq -r '.[] | select(.type=="PushEvent") | .payload.commits[].message' | \
  head -50
```

```python
#!/usr/bin/env python3
"""Behavioral pattern analyzer"""
import requests
from collections import Counter
from datetime import datetime

def analyze_github_patterns(username):
    """Analyze GitHub activity for behavioral patterns"""
    events = requests.get(
        f"https://api.github.com/users/{username}/events/public"
    ).json()

    commit_hours = []
    languages = []
    repos = []

    for event in events:
        if event["type"] == "PushEvent":
            hour = datetime.strptime(
                event["created_at"], "%Y-%m-%dT%H:%M:%SZ"
            ).hour
            commit_hours.append(hour)
            repos.append(event["repo"]["name"])

        if event["type"] == "CreateEvent":
            if event.get("payload", {}).get("description"):
                languages.append(event["payload"].get("language", "unknown"))

    patterns = {
        "active_hours": dict(Counter(commit_hours)),
        "most_active_hour": Counter(commit_hours).most_common(1)[0][0] if commit_hours else None,
        "repos_touched": list(set(repos))[:10],
        "estimated_timezone": "UTC" if not commit_hours else None
    }

    print(f"Behavioral Profile for {username}:")
    print(f"  Most active hour (UTC): {patterns['most_active_hour']}")
    print(f"  Repositories: {len(set(repos))}")
    print(f"  Active hours distribution: {patterns['active_hours']}")

    return patterns

analyze_github_patterns("jsmith-dev")
```

### 3. Technology Preferences

Identify tools and technologies the target uses:

```bash
# Extract technology signals from GitHub profile
# Check starred repos for tool preferences
curl -s "https://api.github.com/users/jsmith-dev/starred" | \
  jq -r '.[].full_name' | grep -iE "docker|k8s|terraform|ansible|react|vue|django"

# Check package manager activity
# NPM: recently published packages
curl -s "https://registry.npmjs.org/-/v1/search?text=maintainer:jsmith" | jq

# PyPI: published packages
curl -s "https://pypi.org/user/jsmith/" | grep -oE 'pypi.org/project/[^/]+'

# Analyze technology stack from personal website or blog
whatweb -v https://jsmith.dev

# Check Stack Overflow profile for technology tags
# Scrape profile for tag scores and activity
```

### 4. Professional Network Analysis

Map the target's professional relationships:

```bash
# Discover colleagues via LinkedIn public data
# Use theHarvester with LinkedIn source
theHarvester -d targetcorp.com -b linkedin -l 200

# Cross-reference with GitHub organization members
curl -s "https://api.github.com/orgs/targetcorp/members" | jq -r '.[].login'

# Find email patterns from discovered contacts
# Generate potential email addresses
python3 -c "
names = ['john.smith', 'jsmith', 'john_smith', 'johns']
domain = 'targetcorp.com'
for name in names:
    print(f'{name}@{domain}')
"

# Correlate conference talks and publications
curl -s "https://api.github.com/search/code?q=author:jsmith-dev+extension:md" | \
  jq -r '.items[].repository.full_name'
```

```python
#!/usr/bin/env python3
"""Professional network mapper"""
import json

def build_network_map(target_profile):
    """Build a network map from collected intelligence"""
    network = {
        "primary_contacts": [],
        "organizational_position": {},
        "external_connections": []
    }

    # Map organizational hierarchy
    network["organizational_position"] = {
        "target": target_profile["target"],
        "title": "Senior Developer",
        "department": "Engineering",
        "reports_to": "Engineering Manager",
        "peers": ["dev-team@targetcorp.com"],
        "likely_access": [
            "source_code repositories",
            "CI/CD pipeline",
            "internal documentation",
            "staging environments"
        ]
    }

    # Map external connections (conference co-authors, open-source collaborators)
    network["external_connections"] = [
        {"name": "Jane Doe", "connection": "OSS collaborator", "platform": "GitHub"},
        {"name": "Bob Wilson", "connection": "Conference co-speaker", "event": "DEF CON 31"}
    ]

    with open("network_map.json", "w") as f:
        json.dump(network, f, indent=2)

    return network
```

## References

- theHarvester: https://github.com/laramies/theHarvester
- Sherlock: https://github.com/sherlock-project/sherlock
- h8mail: https://github.com/khast3x/h8mail
- MITRE PRE-ATT&CK: https://attack.mitre.org/tactics/TA0093/
- OSINT Framework: https://osintframework.com/
