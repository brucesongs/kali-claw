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

### 5. Digital Footprint Mapping

Comprehensive digital footprint mapping goes beyond surface-level account discovery to catalog every traceable online presence, establish cross-references between accounts, and identify abandoned or forgotten profiles that may expose additional attack surface.

```python
#!/usr/bin/env python3
"""Comprehensive digital footprint mapper."""
import json
import requests
from datetime import datetime
from pathlib import Path

class DigitalFootprintMapper:
    """Map and correlate all known digital footprints for a target."""

    def __init__(self, target_name):
        self.target = target_name
        self.footprints = {
            "target": target_name,
            "scan_date": datetime.utcnow().isoformat(),
            "email_addresses": [],
            "usernames": [],
            "social_profiles": [],
            "domains": [],
            "ip_addresses": [],
            "documents": [],
            "code_repositories": [],
            "forum_posts": [],
            "breach_appearances": []
        }

    def add_username_variants(self, base_username):
        """Generate common username variations to search across platforms."""
        variants = set()
        name_parts = self.target.lower().split()

        if len(name_parts) >= 2:
            first, last = name_parts[0], name_parts[-1]
            variants.update([
                first, last, f"{first}{last}", f"{first}.{last}",
                f"{first}_{last}", f"{first[0]}{last}", f"{first}{last[0]}",
                f"{first}.{last[0]}", f"{first[0]}.{last}",
                f"{last}{first}", f"{last}.{first}", f"{last}_{first}"
            ])
        variants.add(base_username.lower())
        self.footprints["usernames"] = sorted(variants)
        return variants

    def check_username_availability(self, username):
        """Check if a username exists on multiple platforms."""
        platform_checks = {
            "github": f"https://api.github.com/users/{username}",
            "gitlab": f"https://gitlab.com/api/v4/users?username={username}",
            "keybase": f"https://keybase.io/_/api/1.0/user/lookup.json?username={username}",
            "reddit": f"https://www.reddit.com/user/{username}/about.json",
            "pinterest": f"https://www.pinterest.com/{username}/",
            "medium": f"https://medium.com/@{username}",
        }

        found = []
        for platform, url in platform_checks.items():
            try:
                resp = requests.get(url, timeout=5,
                                    headers={"User-Agent": "kali-claw/1.0"})
                if resp.status_code == 200:
                    found.append({"platform": platform, "username": username, "url": url})
            except requests.RequestException:
                pass

        self.footprints["social_profiles"].extend(found)
        return found

    def correlate_email_breaches(self, email, hibp_api_key):
        """Check email against breach databases."""
        headers = {"hibp-api-key": hibp_api_key, "user-agent": "kali-claw"}
        try:
            resp = requests.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                headers=headers, params={"truncateResponse": "false"}
            )
            if resp.status_code == 200:
                breaches = resp.json()
                for breach in breaches:
                    self.footprints["breach_appearances"].append({
                        "email": email,
                        "breach": breach.get("Name", ""),
                        "domain": breach.get("Domain", ""),
                        "breach_date": breach.get("BreachDate", ""),
                        "data_classes": breach.get("DataClasses", []),
                        "verified": breach.get("IsVerified", False)
                    })
        except requests.RequestException:
            pass

    def export_report(self, output_dir="target_profiles"):
        """Export the complete footprint map."""
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)
        filename = f"{self.target.replace(' ', '_')}_footprint.json"
        with open(out_path / filename, "w") as f:
            json.dump(self.footprints, f, indent=2)
        return str(out_path / filename)
```

### 6. Cross-Referencing Multiple Data Sources

Correlate intelligence from disparate sources to validate findings, fill gaps, and discover non-obvious connections. Single-source intelligence is unreliable; cross-referencing builds confidence.

```python
#!/usr/bin/env python3
"""Multi-source data cross-referencing engine."""
import json
from collections import defaultdict
from pathlib import Path

class CrossReferenceEngine:
    """Cross-reference intelligence from multiple sources."""

    def __init__(self):
        self.sources = {}
        self.correlations = []
        self.conflicts = []

    def load_source(self, source_name, data_file):
        """Load intelligence data from a specific source."""
        with open(data_file) as f:
            self.sources[source_name] = json.load(f)

    def correlate_by_email(self):
        """Find entities linked by the same email across sources."""
        email_map = defaultdict(list)
        for source_name, data in self.sources.items():
            for email in data.get("emails", []):
                email_map[email.get("address", email if isinstance(email, str) else "")].append({
                    "source": source_name,
                    "context": email
                })

        correlations = []
        for email, appearances in email_map.items():
            if len(set(a["source"] for a in appearances)) > 1:
                correlations.append({
                    "type": "email_cross_reference",
                    "value": email,
                    "found_in": appearances,
                    "confidence": "HIGH" if len(appearances) >= 3 else "MEDIUM"
                })
        self.correlations.extend(correlations)
        return correlations

    def correlate_by_username(self):
        """Find the same username across multiple platforms."""
        username_map = defaultdict(list)
        for source_name, data in self.sources.items():
            for profile in data.get("social_profiles", []):
                username = profile.get("username", "")
                if username:
                    username_map[username.lower()].append({
                        "source": source_name,
                        "platform": profile.get("platform", source_name),
                        "url": profile.get("url", "")
                    })

        correlations = []
        for username, appearances in username_map.items():
            platforms = set(a["platform"] for a in appearances)
            if len(platforms) > 1:
                correlations.append({
                    "type": "username_cross_platform",
                    "username": username,
                    "platforms": list(platforms),
                    "appearances": appearances,
                    "confidence": "HIGH"
                })
        self.correlations.extend(correlations)
        return correlations

    def detect_conflicts(self):
        """Find contradictory information across sources."""
        # Check for conflicting location data
        locations = defaultdict(list)
        for source_name, data in self.sources.items():
            for loc in data.get("locations", []):
                locations[source_name].append(loc)

        source_locations = {src: set(locs) for src, locs in locations.items()}
        sources = list(source_locations.keys())
        for i in range(len(sources)):
            for j in range(i + 1, len(sources)):
                overlap = source_locations[sources[i]] & source_locations[sources[j]]
                if not overlap:
                    self.conflicts.append({
                        "type": "location_conflict",
                        "source_a": {"name": sources[i], "values": list(source_locations[sources[i]])},
                        "source_b": {"name": sources[j], "values": list(source_locations[sources[j]])},
                        "note": "No overlapping locations - one source may be outdated"
                    })
        return self.conflicts

    def generate_correlation_report(self, output_file="correlation_report.json"):
        """Generate a complete correlation analysis report."""
        report = {
            "generated_at": datetime.utcnow().isoformat(),
            "sources_analyzed": list(self.sources.keys()),
            "total_correlations": len(self.correlations),
            "total_conflicts": len(self.conflicts),
            "correlations": self.correlations,
            "conflicts": self.conflicts,
            "confidence_summary": defaultdict(int)
        }
        for corr in self.correlations:
            report["confidence_summary"][corr.get("confidence", "UNKNOWN")] += 1

        with open(output_file, "w") as f:
            json.dump(report, f, indent=2, default=str)
        return report
```

### 7. Building Comprehensive Target Profiles

Synthesize all collected intelligence into a structured target profile suitable for engagement planning, social engineering scenario development, and red team operations.

```python
#!/usr/bin/env python3
"""Comprehensive target profile builder."""
import json
from datetime import datetime
from pathlib import Path

class TargetProfileBuilder:
    """Build a complete target profile from collected intelligence."""

    def __init__(self, target_name):
        self.profile = {
            "meta": {
                "target_name": target_name,
                "created_at": datetime.utcnow().isoformat(),
                "last_updated": datetime.utcnow().isoformat(),
                "confidence_level": "LOW",
                "data_sources": []
            },
            "identity": {
                "full_name": "",
                "known_aliases": [],
                "email_addresses": [],
                "phone_numbers": [],
                "physical_locations": []
            },
            "professional": {
                "current_employer": "",
                "job_title": "",
                "department": "",
                "reports_to": "",
                "direct_reports": [],
                "skills": [],
                "certifications": [],
                "employment_history": []
            },
            "digital_presence": {
                "social_media": {},
                "code_repositories": [],
                "personal_websites": [],
                "forum_memberships": []
            },
            "behavioral": {
                "active_hours_utc": [],
                "inferred_timezone": "",
                "primary_platforms": [],
                "communication_style": "",
                "interests": []
            },
            "technical": {
                "programming_languages": [],
                "frameworks": [],
                "tools": [],
                "infrastructure": [],
                "security_tools": []
            },
            "network": {
                "close_collaborators": [],
                "professional_connections": [],
                "community_memberships": []
            },
            "risk_assessment": {
                "security_awareness": "UNKNOWN",
                "likely_access_levels": [],
                "social_engineering_vectors": [],
                "phishing_suitability": "UNKNOWN"
            }
        }

    def ingest_footprint_data(self, footprint_file):
        """Ingest digital footprint scan results."""
        with open(footprint_file) as f:
            data = json.load(f)

        self.profile["meta"]["data_sources"].append("digital_footprint_scan")
        for email in data.get("emails", []):
            addr = email.get("address", email) if isinstance(email, dict) else email
            if addr not in self.profile["identity"]["email_addresses"]:
                self.profile["identity"]["email_addresses"].append(addr)

        for profile in data.get("social_profiles", []):
            platform = profile.get("platform", "unknown")
            self.profile["digital_presence"]["social_media"][platform] = {
                "username": profile.get("username", ""),
                "url": profile.get("url", "")
            }

    def ingest_behavioral_data(self, behavioral_file):
        """Ingest behavioral analysis results."""
        with open(behavioral_file) as f:
            data = json.load(f)

        self.profile["meta"]["data_sources"].append("behavioral_analysis")
        self.profile["behavioral"]["active_hours_utc"] = data.get("active_hours", [])
        self.profile["behavioral"]["inferred_timezone"] = data.get("inferred_timezone", "Unknown")

    def assess_confidence(self):
        """Calculate overall confidence level based on data completeness."""
        fields_filled = 0
        fields_total = 0

        for section in ["identity", "professional", "digital_presence", "behavioral", "technical"]:
            section_data = self.profile.get(section, {})
            for key, value in section_data.items():
                fields_total += 1
                if value and value != [] and value != {} and value != "":
                    fields_filled += 1

        completeness = fields_filled / max(fields_total, 1)
        if completeness >= 0.7:
            self.profile["meta"]["confidence_level"] = "HIGH"
        elif completeness >= 0.4:
            self.profile["meta"]["confidence_level"] = "MEDIUM"
        else:
            self.profile["meta"]["confidence_level"] = "LOW"

        self.profile["meta"]["last_updated"] = datetime.utcnow().isoformat()
        return self.profile["meta"]["confidence_level"]

    def export_profile(self, output_dir="target_profiles"):
        """Export the complete target profile."""
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        filename = f"{self.profile['meta']['target_name'].replace(' ', '_')}_profile.json"
        with open(out / filename, "w") as f:
            json.dump(self.profile, f, indent=2)
        return str(out / filename)
```

### 8. Temporal Activity Analysis

Analyze when and how frequently a target engages online to infer timezone, work schedule, daily routine, and optimal contact windows for social engineering.

```python
#!/usr/bin/env python3
"""Temporal activity analysis for target profiling."""
import json
import requests
from collections import Counter
from datetime import datetime, timedelta
import statistics

class TemporalActivityAnalyzer:
    """Analyze temporal patterns across platforms."""

    def __init__(self):
        self.activity_timeline = []
        self.headers = {"User-Agent": "kali-claw/1.0"}

    def collect_github_temporal(self, username):
        """Collect GitHub activity timestamps."""
        events = requests.get(
            f"https://api.github.com/users/{username}/events/public?per_page=100",
            headers=self.headers
        ).json()

        timestamps = []
        for event in events:
            if event.get("type") in ("PushEvent", "IssuesEvent", "IssueCommentEvent"):
                ts = datetime.strptime(event["created_at"], "%Y-%m-%dT%H:%M:%SZ")
                timestamps.append({
                    "source": "github",
                    "timestamp": ts.isoformat(),
                    "hour_utc": ts.hour,
                    "day_of_week": ts.weekday(),
                    "event_type": event["type"]
                })
        self.activity_timeline.extend(timestamps)
        return timestamps

    def collect_reddit_temporal(self, username):
        """Collect Reddit activity timestamps."""
        comments = requests.get(
            f"https://www.reddit.com/user/{username}/comments.json?limit=100&sort=new",
            headers=self.headers
        ).json().get("data", {}).get("children", [])

        timestamps = []
        for child in comments:
            created_utc = child["data"].get("created_utc", 0)
            ts = datetime.utcfromtimestamp(created_utc)
            timestamps.append({
                "source": "reddit",
                "timestamp": ts.isoformat(),
                "hour_utc": ts.hour,
                "day_of_week": ts.weekday(),
                "subreddit": child["data"].get("subreddit", "")
            })
        self.activity_timeline.extend(timestamps)
        return timestamps

    def infer_timezone(self):
        """Infer likely timezone from multi-platform activity peaks."""
        if not self.activity_timeline:
            return {"error": "No activity data collected"}

        hours = [entry["hour_utc"] for entry in self.activity_timeline]
        hour_counts = Counter(hours)

        # Typical work hours are 9-17 local time
        # Find the offset where activity peaks during work hours
        best_offset = 0
        best_score = 0

        for offset in range(-12, 13):
            score = sum(hour_counts.get((h + offset) % 24, 0) for h in range(9, 18))
            if score > best_score:
                best_score = score
                best_offset = offset

        peak_hour = hour_counts.most_common(1)[0][0]
        inferred_utc = (10 - peak_hour) % 24
        if inferred_utc > 12:
            inferred_utc -= 24

        return {
            "total_data_points": len(hours),
            "peak_activity_hour_utc": peak_hour,
            "inferred_timezone_offset": f"UTC{'+' if inferred_utc >= 0 else ''}{inferred_utc}",
            "confidence": "HIGH" if len(hours) > 50 else "MEDIUM" if len(hours) > 20 else "LOW",
            "hourly_distribution": dict(sorted(hour_counts.items())),
            "weekday_distribution": dict(Counter(
                entry["day_of_week"] for entry in self.activity_timeline
            )),
            "optimal_contact_window": {
                "start_utc": (9 - best_offset) % 24,
                "end_utc": (17 - best_offset) % 24,
                "rationale": "During inferred local work hours when target is active"
            }
        }

    def detect_activity_anomalies(self):
        """Detect unusual activity patterns (all-night sessions, weekend surges)."""
        anomalies = []
        hours = [entry["hour_utc"] for entry in self.activity_timeline]
        weekdays = [entry["day_of_week"] for entry in self.activity_timeline]

        # Late night activity (potential burnout, deadline, or different timezone)
        night_hours = sum(1 for h in hours if h < 5 or h > 23)
        night_ratio = night_hours / max(len(hours), 1)
        if night_ratio > 0.3:
            anomalies.append({
                "type": "high_night_activity",
                "ratio": round(night_ratio, 2),
                "interpretation": "Significant late-night activity may indicate different timezone, deadline pressure, or personal issues"
            })

        # Weekend activity surge
        weekend_count = sum(1 for d in weekdays if d >= 5)
        weekend_ratio = weekend_count / max(len(weekdays), 1)
        if weekend_ratio > 0.4:
            anomalies.append({
                "type": "high_weekend_activity",
                "ratio": round(weekend_ratio, 2),
                "interpretation": "High weekend activity may indicate passion projects, work pressure, or freelancer schedule"
            })

        return anomalies
```

### 9. Geolocation Inference

Infer a target's physical location from metadata, timezone hints, language patterns, photo backgrounds, and check-in data across platforms.

```python
#!/usr/bin/env python3
"""Geolocation inference from OSINT data."""
import json
import re
from collections import Counter

class GeolocationInferrer:
    """Infer physical location from multiple data signals."""

    def __init__(self):
        self.location_signals = []

    def analyze_profile_text(self, text):
        """Extract location hints from profile descriptions and posts."""
        patterns = {
            "timezone_mentions": re.compile(
                r'\b(EST|CST|MST|PST|EDT|CDT|MDT|PDT|CET|EET|GMT|UTC[+-]\d{1,2}|'
                r'Europe/\w+|America/\w+|Asia/\w+)\b', re.I
            ),
            "city_country": re.compile(
                r'\b(San Francisco|New York|London|Berlin|Tokyo|Singapore|'
                r'Sydney|Toronto|Austin|Seattle|Portland|Denver|Chicago|'
                r'Atlanta|Boston|Miami|Los Angeles|Amsterdam|Dublin)\b', re.I
            ),
            "area_codes": re.compile(r'\b\((\d{3})\)\s*\d{3}-\d{4}\b'),
            "airport_codes": re.compile(r'\b([A-Z]{3})\s*(?:airport|intl|international)\b', re.I)
        }

        results = {}
        for signal_type, pattern in patterns.items():
            matches = pattern.findall(text)
            if matches:
                results[signal_type] = matches
                self.location_signals.append({
                    "type": signal_type,
                    "values": matches,
                    "source": "profile_text"
                })
        return results

    def analyze_photo_metadata(self, image_paths):
        """Extract GPS data from image EXIF metadata."""
        try:
            from PIL import Image
            from PIL.ExifTags import GPSTAGS, TAGS
        except ImportError:
            return {"error": "Pillow library required: pip install Pillow"}

        locations = []
        for img_path in image_paths:
            try:
                img = Image.open(img_path)
                exif_data = img._getexif()
                if not exif_data:
                    continue

                gps_info = {}
                for tag_id, value in exif_data.items():
                    tag = TAGS.get(tag_id, tag_id)
                    if tag == "GPSInfo":
                        for gps_tag_id in value:
                            gps_tag = GPSTAGS.get(gps_tag_id, gps_tag_id)
                            gps_info[gps_tag] = value[gps_tag_id]

                if gps_info.get("GPSLatitude") and gps_info.get("GPSLongitude"):
                    lat = self._convert_to_degrees(gps_info["GPSLatitude"])
                    lon = self._convert_to_degrees(gps_info["GPSLongitude"])
                    if gps_info.get("GPSLatitudeRef", "N") == "S":
                        lat = -lat
                    if gps_info.get("GPSLongitudeRef", "E") == "W":
                        lon = -lon

                    locations.append({
                        "image": img_path,
                        "latitude": lat,
                        "longitude": lon,
                        "altitude": gps_info.get("GPSAltitude"),
                        "source": "exif_gps"
                    })
                    self.location_signals.append(locations[-1])
            except Exception:
                pass

        return locations

    @staticmethod
    def _convert_to_degrees(gps_coordinate):
        """Convert GPS coordinate tuple to decimal degrees."""
        d, m, s = gps_coordinate
        return float(d) + float(m) / 60.0 + float(s) / 3600.0

    def synthesize_location(self):
        """Combine all location signals into a best estimate."""
        if not self.location_signals:
            return {"error": "No location signals collected"}

        signals_by_type = Counter()
        for signal in self.location_signals:
            for value in signal.get("values", [signal.get("latitude", "unknown")]):
                signals_by_type[str(value)] += 1

        return {
            "total_signals": len(self.location_signals),
            "signal_types": list(set(s["type"] for s in self.location_signals)),
            "most_frequent_signals": signals_by_type.most_common(5),
            "confidence": "HIGH" if len(self.location_signals) >= 5 else
                         "MEDIUM" if len(self.location_signals) >= 3 else "LOW"
        }
```

### 10. Professional Network Mapping

Map and visualize the target's professional relationships, organizational position, and access paths to key assets or decision-makers.

```python
#!/usr/bin/env python3
"""Professional network mapping and analysis."""
import json
import requests
from collections import defaultdict, Counter

class ProfessionalNetworkMapper:
    """Map a target's professional network and access paths."""

    def __init__(self):
        self.network = {
            "nodes": {},
            "edges": [],
            "organizations": defaultdict(list)
        }

    def add_person(self, person_id, attributes):
        """Add a person to the network map."""
        self.network["nodes"][person_id] = {
            "type": "person",
            "attributes": attributes
        }
        org = attributes.get("company", attributes.get("organization", ""))
        if org:
            self.network["organizations"][org].append(person_id)

    def add_relationship(self, source, target, relation, weight=1, source_platform=""):
        """Add a relationship between two entities."""
        self.network["edges"].append({
            "source": source,
            "target": target,
            "relation": relation,
            "weight": weight,
            "discovered_via": source_platform
        })

    def discover_from_github_org(self, org_name):
        """Discover organizational structure from GitHub."""
        headers = {"User-Agent": "kali-claw/1.0"}

        # Get org members
        members = requests.get(
            f"https://api.github.com/orgs/{org_name}/members?per_page=100",
            headers=headers
        ).json()

        for member in members:
            username = member.get("login", "")
            self.add_person(username, {
                "github_user": username,
                "avatar": member.get("avatar_url", ""),
                "company": org_name,
                "discovered_via": "github_org_members"
            })

            # Get individual profile for more details
            profile = requests.get(
                f"https://api.github.com/users/{username}",
                headers=headers
            ).json()
            if profile.get("company"):
                self.add_person(username, {
                    "company_displayed": profile["company"],
                    "location": profile.get("location", ""),
                    "public_repos": profile.get("public_repos", 0),
                    "followers": profile.get("followers", 0)
                })

            # Check for collaborators via repo contributions
            repos = requests.get(
                f"https://api.github.com/users/{username}/repos?per_page=30&sort=updated",
                headers=headers
            ).json()
            for repo in repos:
                contributors = requests.get(
                    f"https://api.github.com/repos/{repo['full_name']}/contributors",
                    headers=headers
                ).json()
                if isinstance(contributors, list):
                    for contrib in contributors[:10]:
                        if contrib["login"] != username:
                            self.add_relationship(
                                username, contrib["login"],
                                "code_collaborator",
                                weight=contrib.get("contributions", 1),
                                source_platform="github"
                            )

    def analyze_access_paths(self, target_person, high_value_assets):
        """Find paths from any person to high-value assets."""
        # Build adjacency list
        adj = defaultdict(list)
        for edge in self.network["edges"]:
            adj[edge["source"]].append(edge["target"])
            adj[edge["target"]].append(edge["source"])

        # BFS from target to find who can reach them
        reachable_from = defaultdict(int)
        visited = {target_person}
        queue = [target_person]
        depth = 0

        while queue and depth < 4:
            next_queue = []
            for node in queue:
                for neighbor in adj[node]:
                    if neighbor not in visited:
                        visited.add(neighbor)
                        reachable_from[neighbor] = depth + 1
                        next_queue.append(neighbor)
            queue = next_queue
            depth += 1

        return {
            "target": target_person,
            "reachable_by": [
                {"person": person, "degrees": degrees}
                for person, degrees in sorted(reachable_from.items(), key=lambda x: x[1])
            ],
            "total_reachable": len(reachable_from)
        }

    def export_network(self, output_file="professional_network.json"):
        """Export the network map."""
        with open(output_file, "w") as f:
            json.dump(self.network, f, indent=2)
        return self.network
```

## References

- theHarvester: https://github.com/laramies/theHarvester
- Sherlock: https://github.com/sherlock-project/sherlock
- h8mail: https://github.com/khast3x/h8mail
- MITRE PRE-ATT&CK: https://attack.mitre.org/tactics/TA0093/
- OSINT Framework: https://osintframework.com/
- MITRE ATT&CK Social Engineering: https://attack.mitre.org/techniques/enterprise/
- Have I Been Pwned API: https://haveibeenpwned.com/API/v3
- GitHub REST API: https://docs.github.com/en/rest
- Pillow EXIF Documentation: https://pillow.readthedocs.io/en/stable/reference/Image.html

## Hands-on Exercises

Practice these techniques against public data sources and authorized targets. Always respect privacy laws and terms of service.
