# Social Intelligence Payloads / Search Query Templates

> This file is a companion to `SKILL.md`, containing platform-specific search queries organized by intelligence gathering scenario.

---

## 1. Reddit OSINT

### Subreddit Search

```bash
# Search specific subreddits for target mentions
site:reddit.com/r/sysadmin "<target-company>"
site:reddit.com/r/netsec "<target-technology>"
site:reddit.com/r/networking "<target-company>" VPN OR firewall OR network
site:reddit.com/r/devops "<target-company>" kubernetes OR docker OR CI
site:reddit.com/r/cybersecurity "<target-company>" breach OR incident
site:reddit.com/r/AskNetsec "<target-technology>" vulnerability

# Reddit API search (OAuth required)
curl -s "https://oauth.reddit.com/r/sysadmin/search?q=<target>&sort=new&t=month&limit=25" \
  -H "Authorization: Bearer $REDDIT_TOKEN" \
  -H "User-Agent: kali-claw/1.0" | jq '.data.children[].data | {title, selftext: .selftext[:200], author, score, created_utc, permalink}'
```

### User History Mining

```bash
# Get user's recent posts and comments (public API)
curl -s "https://www.reddit.com/user/<username>/comments.json?limit=100&sort=new" \
  | jq '.data.children[].data | {body: .body[:300], subreddit, score, created_utc}'

# Search user's posts for security-relevant keywords
curl -s "https://www.reddit.com/user/<username>/comments.json?limit=100" \
  | jq '.data.children[].data | select(.body | test("password|VPN|firewall|security|admin|server"; "i")) | {body: .body[:300], subreddit}'
```

### Security Subreddit Monitoring

```
# Key security subreddits to monitor
/r/netsec — Security research and news
/r/AskNetsec — Security Q&A
/r/cybersecurity — General cybersecurity
/r/sysadmin — System administration (rich in tech stack leaks)
/r/networking — Network infrastructure
/r/devops — DevOps and infrastructure
/r/blueteamsec — Defensive security
/r/redteamsec — Offensive security
/r/hacking — General hacking community
/r/ReverseEngineering — Binary analysis community
```

---

## 2. HackerNews OSINT

### Algolia API Queries

```bash
# Search stories mentioning target (last 30 days)
curl -s "https://hn.algolia.com/api/v1/search?query=<target>&tags=story&numericFilters=created_at_i>$(date -d '30 days ago' +%s)&hitsPerPage=50" \
  | jq '.hits[] | {title, url, points, num_comments, created_at, objectID}'

# Search comments (often more revealing than stories)
curl -s "https://hn.algolia.com/api/v1/search?query=<target>&tags=comment&numericFilters=created_at_i>$(date -d '30 days ago' +%s)&hitsPerPage=50" \
  | jq '.hits[] | {text: .comment_text[:300], author, created_at, story_title}'

# Search by specific author
curl -s "https://hn.algolia.com/api/v1/search?tags=comment,author_<username>&hitsPerPage=50" \
  | jq '.hits[] | {text: .comment_text[:300], created_at, story_title}'

# Search for security-related discussions about a technology
curl -s "https://hn.algolia.com/api/v1/search?query=<technology>+vulnerability+OR+CVE+OR+exploit&tags=story&hitsPerPage=20" \
  | jq '.hits[] | {title, url, points, created_at}'
```

### HN User Profile Analysis

```bash
# Get user profile
curl -s "https://hacker-news.firebaseio.com/v0/user/<username>.json" \
  | jq '{id, created, karma, about}'

# Get user's recent submissions
curl -s "https://hacker-news.firebaseio.com/v0/user/<username>.json" \
  | jq '.submitted[:20][]' | while read id; do
    curl -s "https://hacker-news.firebaseio.com/v0/item/${id}.json" \
      | jq '{type, title, text: .text[:200], time}'
  done
```

---

## 3. Twitter/X OSINT

### Advanced Search Operators

```
# Target company mentions with security context
"<target-company>" (security OR breach OR vulnerability OR hack) since:2026-04-01
from:<employee-handle> (server OR infrastructure OR deploy OR production)
"<target-company>" (fired OR layoff OR "looking for") — organizational changes

# Technology stack discovery
from:<employee-handle> (kubernetes OR docker OR AWS OR terraform OR ansible)
"<target-company>" (migrating OR upgrading OR deploying) (to OR from)

# Security incident signals
"<target-company>" (down OR outage OR incident OR "can't login" OR "not working")
"<target-company>" (phishing OR spam OR "suspicious email")

# Conference talks and presentations
"<target-company>" (presented OR "gave a talk" OR "at defcon" OR "at blackhat" OR slides)
```

### X API Search (v2)

```bash
# Search recent tweets (requires Bearer Token)
curl -s "https://api.twitter.com/2/tweets/search/recent?query=<target-company>%20security&max_results=100&tweet.fields=created_at,public_metrics,author_id" \
  -H "Authorization: Bearer $TWITTER_BEARER_TOKEN" | jq '.data[] | {text, created_at, metrics: .public_metrics}'

# Get user timeline
curl -s "https://api.twitter.com/2/users/<user-id>/tweets?max_results=100&tweet.fields=created_at,public_metrics" \
  -H "Authorization: Bearer $TWITTER_BEARER_TOKEN"
```

---

## 4. YouTube OSINT

### Video Search & Transcript Extraction

```bash
# Search for target-related security videos
yt-dlp --flat-playlist "ytsearch20:<target-technology> security vulnerability" \
  --print "%(title)s | %(upload_date)s | %(view_count)s views | %(url)s"

# Search for conference talks
yt-dlp --flat-playlist "ytsearch10:<target-company> defcon OR blackhat OR bsides" \
  --print "%(title)s | %(url)s"

# Download auto-generated subtitles (no video download)
yt-dlp --write-auto-sub --sub-lang en --skip-download -o "%(title)s" "<video-url>"

# Extract security keywords from subtitles
grep -iE "vulnerability|exploit|bypass|CVE|patch|credential|password|injection|XSS|SSRF" *.vtt \
  | head -30

# Batch download subtitles from search results
yt-dlp --flat-playlist "ytsearch5:<target> security" --print url | while read url; do
  yt-dlp --write-auto-sub --sub-lang en --skip-download -o "transcript_%(id)s" "$url" 2>/dev/null
done
```

---

## 5. Forum & Paste Site OSINT

### Security Forums

```bash
# Google Dorking for forum posts
site:forum.hackthebox.com "<target-technology>"
site:0x00sec.org "<target-technology>" exploit
site:exploit.in "<target-company>" — (use via Tor)
site:breachforums.* "<target-company>" OR "<target-domain>" — (use via Tor)

# Stack Overflow — often reveals internal architecture
site:stackoverflow.com "<target-company>" OR "<internal-tool-name>"
site:serverfault.com "<target-company>" configuration OR deploy
```

### Paste Site Monitoring

```bash
# Pastebin search (via psbdmp)
curl -s "https://psbdmp.ws/api/search/<target-keyword>" | jq '.data[:10]'

# Google Dorking for paste sites
site:pastebin.com "<target-company>" OR "<target-domain>"
site:ghostbin.com "<target-keyword>"
site:paste.ee "<target-keyword>"
site:dpaste.org "<target-keyword>"
site:justpaste.it "<target-keyword>"

# GitHub Gists (often overlooked)
site:gist.github.com "<target-company>" OR "<target-domain>"
```

### Dark Web Monitoring (via Clearnet Gateways)

```bash
# Ahmia search engine (Tor clearnet gateway)
curl -s "https://ahmia.fi/search/?q=<target-keyword>" | grep -oP 'href="/search/redirect\?search_url=[^"]*"' | head -10

# IntelX (Intelligence X) — historical and dark web search
curl -s "https://2.intelx.io/intelligent/search" \
  -H "x-key: $INTELX_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"term":"<target-keyword>","maxresults":10,"media":0,"sort":2,"terminate":[]}'
```

---

## 6. Sentiment & Context Queries

### Employee Sentiment Discovery

```
# Glassdoor reviews (via Google)
site:glassdoor.com "<target-company>" "security" OR "IT" review
site:glassdoor.com "<target-company>" "cons" "security"

# Reddit employee sentiment
site:reddit.com "<target-company>" (work OR job OR "working at" OR employer) (security OR IT)
site:reddit.com/r/cscareerquestions "<target-company>"

# Blind (anonymous employee reviews)
site:teamblind.com "<target-company>" security OR engineering
```

### Technology Adoption Signals

```bash
# Detect what the target is adopting/migrating
"<target-company>" (migrating OR "moving to" OR adopting OR deploying) 2026
"<target-company>" (hiring OR "looking for") (security OR DevSecOps OR "cloud security")
"<target-company>" job posting (AWS OR Azure OR GCP OR kubernetes)

# LinkedIn job postings analysis (via Google)
site:linkedin.com/jobs "<target-company>" (security OR cybersecurity OR "information security")
```

### Incident & Breach Signals

```bash
# Recent incident mentions
"<target-company>" (breach OR leaked OR hacked OR compromised OR ransomware) after:2026-01-01
"<target-company>" (incident OR outage OR "data loss" OR "unauthorized access")

# Check HaveIBeenPwned for domain
curl -s "https://haveibeenpwned.com/api/v3/breaches" | jq '.[] | select(.Domain == "<target-domain>") | {Name, BreachDate, DataClasses}'
```

---

## 7. Cross-Platform Correlation

### Username Discovery & Tracking

```bash
# Find usernames across platforms
sherlock <username1> <username2> --json -o cross_platform.json

# Extract confirmed profiles
cat cross_platform.json | jq 'to_entries[] | select(.value == "Claimed") | .key'

# Check email registrations
holehe <target-email>

# Connect username → email → platform
# username on GitHub → email in commits → email on HN/Reddit
git log --format='%ae' | sort -u  # Extract emails from repos they contribute to
```

### Multi-Platform Timeline Construction

```markdown
# Correlation template
| Date | Platform | Author | Content Summary | Relevance |
|------|----------|--------|-----------------|-----------|
| 2026-04-15 | Reddit | u/devops_user | Discussed migrating to Cloudflare | Tech stack |
| 2026-04-18 | HN | same_username | Commented on CDN security post | Confirms interest |
| 2026-04-20 | GitHub | same_handle | Pushed Terraform config for CF | Confirms adoption |
→ CORRELATION: Target is migrating CDN to Cloudflare (HIGH confidence)
```

---

## 8. Social Network Graph Analysis

### Relationship Extraction

```python
import requests
import json
from collections import defaultdict

def build_org_graph(company, github_org):
    """Build organizational relationship graph from GitHub contributions"""
    graph = defaultdict(set)
    headers = {"Authorization": f"token {GITHUB_TOKEN}"}

    repos = requests.get(
        f"https://api.github.com/orgs/{github_org}/repos?per_page=100",
        headers=headers
    ).json()

    for repo in repos:
        contributors = requests.get(
            f"https://api.github.com/repos/{github_org}/{repo['name']}/contributors",
            headers=headers
        ).json()
        usernames = [c["login"] for c in contributors if isinstance(c, dict)]
        for i, u1 in enumerate(usernames):
            for u2 in usernames[i+1:]:
                graph[u1].add(u2)
                graph[u2].add(u1)

    return dict(graph)
```

### Influence Scoring

```python
def calculate_influence_scores(graph):
    """PageRank-style influence scoring for social network"""
    scores = {node: 1.0 for node in graph}
    damping = 0.85
    iterations = 20

    for _ in range(iterations):
        new_scores = {}
        for node in graph:
            incoming = sum(
                scores[neighbor] / len(graph[neighbor])
                for neighbor in graph
                if node in graph[neighbor]
            )
            new_scores[node] = (1 - damping) + damping * incoming
        scores = new_scores

    total = sum(scores.values())
    return {k: v / total for k, v in sorted(scores.items(), key=lambda x: -x[1])}
```

### Community Detection

```python
def detect_communities(graph, threshold=3):
    """Simple community detection via shared connections"""
    communities = []
    visited = set()

    for node in graph:
        if node in visited:
            continue
        community = set()
        queue = [node]
        while queue:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)
            community.add(current)
            for neighbor in graph.get(current, []):
                shared = len(graph.get(current, set()) & graph.get(neighbor, set()))
                if shared >= threshold and neighbor not in visited:
                    queue.append(neighbor)
        if len(community) > 1:
            communities.append(community)

    return communities
```

---

## 9. Automated Monitoring Pipelines

### Reddit Monitoring Bot

```python
import time
import requests

def monitor_subreddit(subreddit, keywords, interval=300):
    """Monitor subreddit for keyword mentions"""
    seen_ids = set()
    url = f"https://www.reddit.com/r/{subreddit}/new.json?limit=25"
    headers = {"User-Agent": "security-monitor/1.0"}

    while True:
        resp = requests.get(url, headers=headers)
        if resp.status_code != 200:
            time.sleep(interval)
            continue

        posts = resp.json()["data"]["children"]
        for post in posts:
            data = post["data"]
            if data["id"] in seen_ids:
                continue
            seen_ids.add(data["id"])
            text = f"{data['title']} {data.get('selftext', '')}".lower()
            matched = [kw for kw in keywords if kw.lower() in text]
            if matched:
                yield {
                    "platform": "reddit",
                    "subreddit": subreddit,
                    "title": data["title"],
                    "url": f"https://reddit.com{data['permalink']}",
                    "keywords": matched,
                    "author": data["author"],
                    "timestamp": data["created_utc"]
                }
        time.sleep(interval)
```

### HackerNews Real-Time Monitor

```python
import requests
import time

def monitor_hn_keywords(keywords, check_interval=60):
    """Monitor HackerNews for keyword mentions in new stories"""
    last_max_id = requests.get(
        "https://hacker-news.firebaseio.com/v0/maxitem.json"
    ).json()

    while True:
        current_max = requests.get(
            "https://hacker-news.firebaseio.com/v0/maxitem.json"
        ).json()

        for item_id in range(last_max_id + 1, current_max + 1):
            item = requests.get(
                f"https://hacker-news.firebaseio.com/v0/item/{item_id}.json"
            ).json()
            if not item:
                continue
            text = f"{item.get('title', '')} {item.get('text', '')}".lower()
            matched = [kw for kw in keywords if kw.lower() in text]
            if matched:
                yield {
                    "platform": "hackernews",
                    "type": item.get("type"),
                    "title": item.get("title", ""),
                    "url": item.get("url", f"https://news.ycombinator.com/item?id={item_id}"),
                    "keywords": matched,
                    "author": item.get("by"),
                    "timestamp": item.get("time")
                }

        last_max_id = current_max
        time.sleep(check_interval)
```

### Multi-Platform Alert Aggregator

```python
import json
from datetime import datetime

class AlertAggregator:
    def __init__(self, output_file="alerts.jsonl"):
        self.output_file = output_file
        self.alert_count = 0

    def process_alert(self, alert):
        alert["alert_id"] = f"SI-{self.alert_count:04d}"
        alert["processed_at"] = datetime.utcnow().isoformat()
        alert["severity"] = self._classify_severity(alert)

        with open(self.output_file, "a") as f:
            f.write(json.dumps(alert) + "\n")
        self.alert_count += 1
        return alert

    def _classify_severity(self, alert):
        high_keywords = ["breach", "leaked", "compromised", "credential", "exploit"]
        medium_keywords = ["vulnerability", "security", "incident", "CVE"]
        matched = alert.get("keywords", [])
        if any(kw in high_keywords for kw in matched):
            return "HIGH"
        if any(kw in medium_keywords for kw in matched):
            return "MEDIUM"
        return "LOW"
```

---

## 10. Data Enrichment & Correlation

### Email-to-Identity Resolution

```bash
# Resolve email to social profiles
holehe target@company.com 2>/dev/null | grep -E "^\[" | grep -v "not used"

# GitHub email search
curl -s "https://api.github.com/search/users?q=target@company.com+in:email" \
  -H "Authorization: token $GITHUB_TOKEN" | jq '.items[].login'

# Gravatar hash lookup
echo -n "target@company.com" | md5sum | cut -d' ' -f1
# Check: https://gravatar.com/<hash>.json
```

### Organization Mapping from Job Postings

```python
import requests
from bs4 import BeautifulSoup

def extract_tech_stack_from_jobs(company_name):
    """Extract technology stack from job postings"""
    technologies = {
        "languages": set(),
        "frameworks": set(),
        "infrastructure": set(),
        "security_tools": set()
    }

    tech_keywords = {
        "languages": ["python", "go", "java", "rust", "typescript", "c++"],
        "frameworks": ["react", "django", "spring", "fastapi", "express"],
        "infrastructure": ["aws", "gcp", "azure", "kubernetes", "terraform", "docker"],
        "security_tools": ["splunk", "crowdstrike", "sentinel", "wiz", "snyk"]
    }

    # Parse job descriptions (simplified)
    # In practice, use LinkedIn API or job board scrapers
    for category, keywords in tech_keywords.items():
        for kw in keywords:
            # Search for keyword in job postings
            technologies[category].add(kw)  # Placeholder

    return {k: list(v) for k, v in technologies.items()}
```

### Temporal Pattern Analysis

```python
from collections import Counter
from datetime import datetime

def analyze_activity_patterns(posts):
    """Detect posting patterns (timezone, work hours, frequency)"""
    hours = Counter()
    weekdays = Counter()
    platforms = Counter()

    for post in posts:
        ts = datetime.fromtimestamp(post["timestamp"])
        hours[ts.hour] += 1
        weekdays[ts.strftime("%A")] += 1
        platforms[post["platform"]] += 1

    peak_hours = hours.most_common(3)
    peak_days = weekdays.most_common(3)

    # Estimate timezone from peak activity
    if peak_hours[0][0] in range(9, 18):
        estimated_tz = "UTC (or close)"
    elif peak_hours[0][0] in range(14, 23):
        estimated_tz = "US Pacific (UTC-8)"
    else:
        estimated_tz = "Unknown"

    return {
        "peak_hours": peak_hours,
        "peak_days": peak_days,
        "platforms": dict(platforms),
        "estimated_timezone": estimated_tz,
        "total_posts": len(posts)
    }
```

---

## 11. Reporting & Visualization

### Intelligence Summary Generator

```python
def generate_intel_summary(findings, target):
    """Generate structured intelligence summary"""
    summary = {
        "target": target,
        "generated_at": datetime.utcnow().isoformat(),
        "total_findings": len(findings),
        "by_platform": Counter(f["platform"] for f in findings),
        "by_severity": Counter(f.get("severity", "UNKNOWN") for f in findings),
        "key_insights": [],
        "recommended_actions": []
    }

    high_findings = [f for f in findings if f.get("severity") == "HIGH"]
    for f in high_findings[:5]:
        summary["key_insights"].append(
            f"[{f['platform']}] {f.get('title', f.get('keywords', ['unknown'])[0])}"
        )

    if any(f.get("keywords") and "breach" in f["keywords"] for f in findings):
        summary["recommended_actions"].append("Investigate potential data breach mentions")
    if any(f.get("keywords") and "credential" in f["keywords"] for f in findings):
        summary["recommended_actions"].append("Check for exposed credentials on paste sites")

    return summary
```

### Network Graph Export (Gephi/D3)

```python
import json

def export_graph_for_visualization(graph, output="network.json"):
    """Export social network graph for D3.js or Gephi visualization"""
    nodes = [{"id": node, "group": 1} for node in graph]
    links = []
    seen = set()
    for node, neighbors in graph.items():
        for neighbor in neighbors:
            edge = tuple(sorted([node, neighbor]))
            if edge not in seen:
                seen.add(edge)
                links.append({"source": node, "target": neighbor, "value": 1})

    d3_data = {"nodes": nodes, "links": links}
    with open(output, "w") as f:
        json.dump(d3_data, f, indent=2)
    return f"Exported {len(nodes)} nodes, {len(links)} edges to {output}"
```

---

## 12. Automated Profile Correlation

### Cross-Platform Identity Linking

```bash
# Use sherlock for bulk username enumeration across 300+ platforms
sherlock <target-username> --timeout 10 --print-found --output /tmp/sherlock-results.txt

# WhatsMyName — alternative with broader coverage
git clone https://github.com/WebBreacher/WhatsMyName.git
python3 WhatsMyName/whats_my_name.py -u <target-username> -o /tmp/wmn-results.json

# maigret — advanced username OSINT with profile parsing
maigret <target-username> --all-sites --reports-dir /tmp/maigret-output/ --json ndjson

# Correlate usernames found across platforms
cat /tmp/sherlock-results.txt | grep -E "^\[" | awk -F'[][]' '{print $2}' | sort > /tmp/confirmed-platforms.txt
echo "[CORRELATION] Confirmed presence on $(wc -l < /tmp/confirmed-platforms.txt) platforms"
```

### Username Enumeration and Variation Discovery

```bash
# Generate username variations from known handle
USERNAME="johndoe"
cat <<EOF > /tmp/username-variants.txt
${USERNAME}
${USERNAME}123
${USERNAME}_dev
${USERNAME}-sec
${USERNAME}2026
j.doe
jdoe
john.doe
john_doe
johnd
EOF

# Test each variation across platforms
while read variant; do
  sherlock "$variant" --timeout 5 --print-found 2>/dev/null | grep -c "\[" | \
    xargs -I{} echo "$variant: {} platforms found"
done < /tmp/username-variants.txt
```

### Email-Based Cross-Platform Discovery

```python
import subprocess
import json

def correlate_identity(email, username):
    """Cross-reference email and username to build identity profile"""
    identity = {
        "email": email,
        "username": username,
        "platforms": [],
        "linked_accounts": []
    }

    # holehe: check email registration across services
    result = subprocess.run(
        ["holehe", email, "--only-used", "--no-color"],
        capture_output=True, text=True
    )
    for line in result.stdout.splitlines():
        if "[+]" in line:
            platform = line.split("[+]")[1].strip().split()[0]
            identity["platforms"].append({"source": "email", "platform": platform})

    # sherlock: check username across platforms
    result = subprocess.run(
        ["sherlock", username, "--print-found", "--timeout", "8"],
        capture_output=True, text=True
    )
    for line in result.stdout.splitlines():
        if "http" in line:
            identity["linked_accounts"].append(line.strip())

    return identity
```

### GitHub Commit Email Harvesting

```bash
# Extract all unique emails from a user's public repos
TARGET_USER="target-github-user"
GITHUB_TOKEN="${GITHUB_TOKEN}"

curl -s "https://api.github.com/users/${TARGET_USER}/repos?per_page=100" \
  -H "Authorization: token $GITHUB_TOKEN" | jq -r '.[].name' | while read repo; do
  curl -s "https://api.github.com/repos/${TARGET_USER}/${repo}/commits?per_page=100" \
    -H "Authorization: token $GITHUB_TOKEN" | \
    jq -r '.[].commit | .author.email, .committer.email' 2>/dev/null
done | sort -u | grep -v "noreply" > /tmp/${TARGET_USER}-emails.txt

echo "[HARVEST] Found $(wc -l < /tmp/${TARGET_USER}-emails.txt) unique emails for $TARGET_USER"
cat /tmp/${TARGET_USER}-emails.txt
```

### Profile Photo Reverse Image Search

```bash
# Download profile photos for reverse image search
TARGET_USER="target-username"

# GitHub avatar
curl -s "https://api.github.com/users/${TARGET_USER}" | jq -r '.avatar_url' | \
  xargs -I{} wget -q -O /tmp/avatar-github.jpg "{}"

# Use facial recognition API to find matches (example with face++ or similar)
# Upload to reverse image search engines
echo "[PHOTO] Downloaded avatar for reverse image search"
echo "[PHOTO] Manual steps: upload to Google Images, Yandex, TinEye, PimEyes"

# Extract EXIF data from any photos found on social media
exiftool /tmp/avatar-github.jpg 2>/dev/null | grep -iE "GPS|Location|Date|Camera|Software"
```

### Automated Profile Merge Scoring

```python
def calculate_match_score(profile_a, profile_b):
    """Score likelihood that two profiles belong to the same person"""
    score = 0
    reasons = []

    # Username similarity
    if profile_a["username"].lower() == profile_b["username"].lower():
        score += 30
        reasons.append("exact username match")
    elif profile_a["username"].lower() in profile_b["username"].lower():
        score += 15
        reasons.append("partial username match")

    # Email overlap
    emails_a = set(profile_a.get("emails", []))
    emails_b = set(profile_b.get("emails", []))
    if emails_a & emails_b:
        score += 40
        reasons.append(f"shared email: {emails_a & emails_b}")

    # Bio keyword overlap
    bio_a = set(profile_a.get("bio", "").lower().split())
    bio_b = set(profile_b.get("bio", "").lower().split())
    overlap = len(bio_a & bio_b) / max(len(bio_a | bio_b), 1)
    if overlap > 0.3:
        score += 20
        reasons.append(f"bio similarity: {overlap:.0%}")

    # Activity time correlation
    if profile_a.get("timezone") == profile_b.get("timezone"):
        score += 10
        reasons.append("same timezone")

    return {"score": score, "confidence": "HIGH" if score >= 70 else "MEDIUM" if score >= 40 else "LOW", "reasons": reasons}
```

---

## 13. Geolocation Intelligence

### Photo Metadata Extraction

```bash
# Extract GPS coordinates from images
exiftool -GPS* -DateTimeOriginal -Make -Model /tmp/target-photos/*.jpg 2>/dev/null

# Batch extract and format as CSV
exiftool -csv -GPS* -DateTimeOriginal -FileName /tmp/target-photos/ > /tmp/geo-data.csv

# Convert GPS DMS to decimal degrees
exiftool -n -p '$FileName, $GPSLatitude, $GPSLongitude' /tmp/target-photos/*.jpg 2>/dev/null | \
  grep -v "^$" > /tmp/coordinates.csv

# Generate Google Maps links from coordinates
while IFS=', ' read -r file lat lon; do
  [ -n "$lat" ] && [ -n "$lon" ] && \
    echo "$file: https://www.google.com/maps?q=${lat},${lon}"
done < /tmp/coordinates.csv
```

### Social Media Check-In Analysis

```python
import json
from collections import Counter
from datetime import datetime

def analyze_checkins(checkin_data):
    """Analyze check-in patterns to determine home/work locations and travel"""
    locations = Counter()
    time_location = []

    for checkin in checkin_data:
        loc = checkin.get("location", {})
        place = f"{loc.get('city', 'Unknown')}, {loc.get('country', 'Unknown')}"
        locations[place] += 1
        time_location.append({
            "timestamp": checkin["timestamp"],
            "place": place,
            "lat": loc.get("lat"),
            "lon": loc.get("lon"),
            "day_of_week": datetime.fromtimestamp(checkin["timestamp"]).strftime("%A"),
            "hour": datetime.fromtimestamp(checkin["timestamp"]).hour
        })

    # Determine home location (most frequent evening/weekend location)
    home_candidates = [t for t in time_location if t["hour"] >= 18 or t["day_of_week"] in ("Saturday", "Sunday")]
    home_location = Counter(t["place"] for t in home_candidates).most_common(1)

    # Determine work location (most frequent weekday daytime location)
    work_candidates = [t for t in time_location if 8 <= t["hour"] <= 17 and t["day_of_week"] not in ("Saturday", "Sunday")]
    work_location = Counter(t["place"] for t in work_candidates).most_common(1)

    return {
        "total_checkins": len(checkin_data),
        "unique_locations": len(locations),
        "top_locations": locations.most_common(10),
        "probable_home": home_location[0] if home_location else None,
        "probable_work": work_location[0] if work_location else None
    }
```

### Travel Pattern Reconstruction

```bash
# Extract location data from Instagram posts (via instaloader)
instaloader --no-pictures --no-videos --no-captions --geotags \
  --login=$INSTA_USER --password=$INSTA_PASS \
  profile <target-username>

# Parse geotag data from downloaded metadata
find . -name "*.json" -exec jq -r '.location | select(. != null) | "\(.name) | \(.lat),\(.lng)"' {} \; 2>/dev/null | \
  sort -u > /tmp/instagram-locations.txt

# Timeline reconstruction from multiple sources
echo "[GEO] Building travel timeline..."
cat /tmp/instagram-locations.txt /tmp/twitter-locations.txt /tmp/foursquare-checkins.txt 2>/dev/null | \
  sort -t'|' -k3 | uniq > /tmp/travel-timeline.txt
```

### WiFi BSSID Geolocation

```bash
# Look up WiFi BSSID locations from Wigle.net
# (Requires Wigle API key)
BSSID="AA:BB:CC:DD:EE:FF"
curl -s "https://api.wigle.net/api/v2/network/search?netid=${BSSID}" \
  -u "${WIGLE_API_NAME}:${WIGLE_API_TOKEN}" | \
  jq '.results[] | {ssid, trilat, trilong, city, region, country, lastupdt}'

# Batch lookup from captured probe requests
cat /tmp/captured-bssids.txt | while read bssid; do
  result=$(curl -s "https://api.wigle.net/api/v2/network/search?netid=${bssid}" \
    -u "${WIGLE_API_NAME}:${WIGLE_API_TOKEN}" | jq -r '.results[0] | "\(.trilat),\(.trilong),\(.ssid)"')
  echo "$bssid -> $result"
  sleep 2  # Rate limiting
done > /tmp/bssid-geolocations.txt
```

### IP Geolocation Correlation

```bash
# Resolve IP addresses to geographic locations
TARGET_IP="203.0.113.42"

# MaxMind GeoIP lookup
mmdblookup --file /usr/share/GeoIP/GeoLite2-City.mmdb --ip "$TARGET_IP" \
  city names en country names en location latitude location longitude

# ipinfo.io API
curl -s "https://ipinfo.io/${TARGET_IP}/json" | jq '{ip, city, region, country, loc, org, timezone}'

# Batch IP geolocation from access logs
awk '{print $1}' /tmp/access.log | sort -u | while read ip; do
  geo=$(curl -s "https://ipinfo.io/${ip}/json" | jq -r '"\(.city),\(.country),\(.org)"')
  echo "$ip -> $geo"
done > /tmp/ip-geo-mapping.txt
```

### Location Pattern Visualization

```python
import json
from collections import defaultdict

def generate_location_heatmap_data(location_records):
    """Generate heatmap data from location records for visualization"""
    grid = defaultdict(int)

    for record in location_records:
        lat = round(record["lat"], 2)
        lon = round(record["lon"], 2)
        grid[(lat, lon)] += 1

    heatmap_data = [
        {"lat": lat, "lon": lon, "weight": count}
        for (lat, lon), count in grid.items()
    ]

    # Identify clusters (locations with 3+ visits)
    clusters = [p for p in heatmap_data if p["weight"] >= 3]

    output = {
        "heatmap_points": sorted(heatmap_data, key=lambda x: -x["weight"]),
        "clusters": clusters,
        "total_points": len(location_records),
        "unique_cells": len(grid)
    }

    with open("/tmp/location-heatmap.json", "w") as f:
        json.dump(output, f, indent=2)

    return output
```

---

## 14. Organizational Mapping

### LinkedIn Employee Enumeration

```bash
# Google dorking for LinkedIn profiles at target company
COMPANY="target-company"

# Find employees by department
site:linkedin.com/in "$COMPANY" "security" OR "cybersecurity" OR "information security"
site:linkedin.com/in "$COMPANY" "DevOps" OR "SRE" OR "infrastructure"
site:linkedin.com/in "$COMPANY" "CTO" OR "CISO" OR "VP Engineering"

# Use linkedin2username for email format discovery
git clone https://github.com/initstring/linkedin2username.git
python3 linkedin2username/linkedin2username.py -u $LI_USER -p $LI_PASS -c "$COMPANY" -o /tmp/li-users.txt

# CrossLinked — scrape without authentication
crosslinked -f '{first}.{last}@company.com' -t 100 "$COMPANY"
crosslinked -f '{f}{last}@company.com' -t 100 "$COMPANY"
```

### Org Chart Reconstruction

```python
import json
from collections import defaultdict

def build_org_chart(employee_data):
    """Reconstruct organizational hierarchy from LinkedIn/public data"""
    org = {
        "company": employee_data[0].get("company", "Unknown"),
        "departments": defaultdict(list),
        "hierarchy": defaultdict(list),
        "key_personnel": []
    }

    executive_titles = ["ceo", "cto", "ciso", "cfo", "vp", "director", "head of"]
    manager_titles = ["manager", "lead", "principal", "senior director"]

    for emp in employee_data:
        title = emp.get("title", "").lower()
        dept = emp.get("department", "Unknown")
        org["departments"][dept].append(emp)

        # Identify key personnel
        if any(t in title for t in executive_titles):
            emp["level"] = "executive"
            org["key_personnel"].append(emp)
            org["hierarchy"]["executives"].append(emp)
        elif any(t in title for t in manager_titles):
            emp["level"] = "manager"
            org["hierarchy"]["managers"].append(emp)
        else:
            emp["level"] = "individual_contributor"
            org["hierarchy"]["ic"].append(emp)

    return org
```

### Key Personnel Identification

```bash
# Identify security team members via multiple sources
COMPANY="target-company"

# GitHub organization members
curl -s "https://api.github.com/orgs/${COMPANY}/members?per_page=100" \
  -H "Authorization: token $GITHUB_TOKEN" | jq -r '.[].login' > /tmp/github-members.txt

# Cross-reference with security conference speakers
for conf in "defcon" "blackhat" "bsides" "rsaconference"; do
  curl -s "https://hn.algolia.com/api/v1/search?query=${COMPANY}+${conf}&tags=story" | \
    jq -r '.hits[].title' 2>/dev/null
done > /tmp/conf-mentions.txt

# Find security team blog posts
curl -s "https://api.github.com/search/repositories?q=org:${COMPANY}+security" \
  -H "Authorization: token $GITHUB_TOKEN" | jq -r '.items[] | "\(.name): \(.description)"'

echo "[ORG] Key personnel identification complete"
echo "[ORG] GitHub members: $(wc -l < /tmp/github-members.txt)"
```

### Department Technology Stack Mapping

```bash
# Map technologies to departments via job postings and GitHub repos
COMPANY="target-company"

# Analyze GitHub repos by language
curl -s "https://api.github.com/orgs/${COMPANY}/repos?per_page=100&sort=updated" \
  -H "Authorization: token $GITHUB_TOKEN" | \
  jq -r '.[] | "\(.name)|\(.language)|\(.description // "no description")"' | \
  sort -t'|' -k2 > /tmp/org-tech-stack.txt

# Count languages
cut -d'|' -f2 /tmp/org-tech-stack.txt | sort | uniq -c | sort -rn

# Find infrastructure repos (likely DevOps/SRE team)
curl -s "https://api.github.com/search/repositories?q=org:${COMPANY}+terraform+OR+ansible+OR+kubernetes+OR+docker" \
  -H "Authorization: token $GITHUB_TOKEN" | jq -r '.items[] | "\(.name) [\(.language)]"'
```

### Supply Chain Vendor Identification

```python
import requests
import json

def identify_vendors(company_domain, github_org):
    """Identify third-party vendors and suppliers from public data"""
    vendors = {
        "saas_tools": [],
        "infrastructure": [],
        "security_vendors": [],
        "development_tools": []
    }

    # Check DNS records for SaaS indicators
    import subprocess
    dns_result = subprocess.run(
        ["dig", "+short", "TXT", company_domain],
        capture_output=True, text=True
    )
    txt_records = dns_result.stdout

    # SPF/DKIM records reveal email providers
    if "google" in txt_records.lower():
        vendors["saas_tools"].append("Google Workspace")
    if "microsoft" in txt_records.lower():
        vendors["saas_tools"].append("Microsoft 365")
    if "spf.protection.outlook" in txt_records:
        vendors["saas_tools"].append("Microsoft Exchange Online")

    # Check for common SaaS subdomains
    saas_indicators = {
        "slack": "Slack", "okta": "Okta", "zendesk": "Zendesk",
        "atlassian": "Atlassian", "salesforce": "Salesforce"
    }
    for indicator, vendor in saas_indicators.items():
        try:
            result = subprocess.run(
                ["dig", "+short", f"{indicator}.{company_domain}"],
                capture_output=True, text=True, timeout=5
            )
            if result.stdout.strip():
                vendors["saas_tools"].append(vendor)
        except subprocess.TimeoutExpired:
            pass

    return vendors
```

---

## 15. Dark Web Monitoring

### Paste Site Scanning

```bash
# Monitor multiple paste sites for target mentions
TARGET="target-company.com"

# Pastebin search via psbdmp API
curl -s "https://psbdmp.ws/api/search/${TARGET}" | jq '.data[:20] | .[] | {id, tags, time}'

# Download and analyze matching pastes
curl -s "https://psbdmp.ws/api/search/${TARGET}" | jq -r '.data[].id' | head -10 | while read paste_id; do
  echo "=== Paste: $paste_id ==="
  curl -s "https://psbdmp.ws/api/dump/get/${paste_id}" | jq -r '.data' | head -50
  echo ""
done > /tmp/paste-findings.txt

# Search across multiple paste engines
for site in "pastebin.com" "paste.ee" "ghostbin.com" "dpaste.org"; do
  echo "[PASTE] Searching $site for $TARGET"
  curl -s "https://www.google.com/search?q=site:${site}+%22${TARGET}%22&num=10" \
    -H "User-Agent: Mozilla/5.0" | grep -oP "https?://${site}/[a-zA-Z0-9]+" | sort -u
done
```

### Breach Data Correlation

```python
import hashlib
import requests

def check_breach_exposure(email, domain):
    """Check if email/domain appears in known breaches"""
    results = {
        "email": email,
        "domain": domain,
        "breaches": [],
        "pastes": [],
        "credential_exposure": False
    }

    # HaveIBeenPwned API v3
    headers = {"hibp-api-key": HIBP_API_KEY, "user-agent": "kali-claw-osint"}

    # Check email breaches
    resp = requests.get(
        f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
        headers=headers
    )
    if resp.status_code == 200:
        results["breaches"] = [
            {"name": b["Name"], "date": b["BreachDate"], "data_classes": b["DataClasses"]}
            for b in resp.json()
        ]
        if any("Passwords" in b["data_classes"] for b in results["breaches"]):
            results["credential_exposure"] = True

    # Check domain breaches
    resp = requests.get(
        f"https://haveibeenpwned.com/api/v3/breaches",
        headers=headers
    )
    if resp.status_code == 200:
        domain_breaches = [b for b in resp.json() if domain.lower() in b.get("Domain", "").lower()]
        results["domain_breaches"] = domain_breaches

    # Check password via k-anonymity (safe)
    # sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
    # prefix, suffix = sha1_hash[:5], sha1_hash[5:]

    return results
```

### Dark Web Forum Monitoring

```bash
# Ahmia.fi (Tor search engine with clearnet access)
TARGET="target-company"
curl -s "https://ahmia.fi/search/?q=${TARGET}" | \
  grep -oP 'href="[^"]*"' | grep "redirect" | head -20

# IntelX historical search
curl -s -X POST "https://2.intelx.io/intelligent/search" \
  -H "x-key: $INTELX_API_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"term\":\"${TARGET}\",\"maxresults\":25,\"media\":0,\"sort\":2,\"terminate\":[]}" | \
  jq '.records[] | {name, date, bucket, mediah, size}'

# Fetch results from IntelX search
SEARCH_ID=$(curl -s -X POST "https://2.intelx.io/intelligent/search" \
  -H "x-key: $INTELX_API_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"term\":\"${TARGET}\",\"maxresults\":10}" | jq -r '.id')

sleep 5
curl -s "https://2.intelx.io/intelligent/search/result?id=${SEARCH_ID}" \
  -H "x-key: $INTELX_API_KEY" | jq '.records[:10]'
```

### Credential Leak Monitoring Pipeline

```python
import time
import json
import hashlib
from datetime import datetime

class CredentialLeakMonitor:
    def __init__(self, target_domain, alert_callback=None):
        self.target_domain = target_domain
        self.alert_callback = alert_callback
        self.seen_hashes = set()

    def check_paste_sites(self):
        """Poll paste sites for new mentions of target domain"""
        import requests
        findings = []

        # psbdmp check
        resp = requests.get(f"https://psbdmp.ws/api/search/{self.target_domain}")
        if resp.status_code == 200:
            for paste in resp.json().get("data", []):
                paste_hash = hashlib.md5(paste["id"].encode()).hexdigest()
                if paste_hash not in self.seen_hashes:
                    self.seen_hashes.add(paste_hash)
                    findings.append({
                        "source": "psbdmp",
                        "paste_id": paste["id"],
                        "timestamp": paste.get("time"),
                        "tags": paste.get("tags", [])
                    })

        return findings

    def run_monitoring_cycle(self):
        """Single monitoring cycle — call on schedule"""
        findings = self.check_paste_sites()
        for finding in findings:
            finding["detected_at"] = datetime.utcnow().isoformat()
            finding["target"] = self.target_domain
            if self.alert_callback:
                self.alert_callback(finding)
        return findings
```

### Threat Actor Attribution

```bash
# Search for threat actor mentions related to target industry
TARGET_INDUSTRY="financial"

# Search threat intelligence feeds
curl -s "https://otx.alienvault.com/api/v1/search/pulses?q=${TARGET_INDUSTRY}+breach&limit=20" \
  -H "X-OTX-API-KEY: $OTX_API_KEY" | \
  jq '.results[] | {name, description: .description[:200], created, tags, adversary}'

# Check Ransomware group leak sites (via clearnet mirrors/trackers)
echo "[DARKWEB] Checking ransomware leak site trackers..."
curl -s "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json" | \
  jq --arg target "$TARGET" '.[] | select(.post_title | ascii_downcase | contains($target | ascii_downcase)) | {group_name, post_title, discovered}'

# Monitor for new mentions
echo "[DARKWEB] Setting up monitoring for: $TARGET_INDUSTRY"
echo "Sources: Ahmia, IntelX, OTX, RansomWatch, HIBP"
echo "Frequency: Every 6 hours"
```

### Stealer Log Analysis

```python
def analyze_stealer_logs(log_entries, target_domain):
    """Analyze infostealer logs for credentials matching target domain"""
    matches = []

    for entry in log_entries:
        url = entry.get("url", "").lower()
        username = entry.get("username", "")
        # Check if the stolen credential is for our target
        if target_domain.lower() in url:
            matches.append({
                "url": url,
                "username": username,
                "has_password": bool(entry.get("password")),
                "source_malware": entry.get("malware_family", "unknown"),
                "infection_date": entry.get("date"),
                "victim_machine": entry.get("machine_id", "unknown"),
                "browser": entry.get("browser", "unknown")
            })

    # Deduplicate by username
    unique_users = {}
    for match in matches:
        user = match["username"]
        if user not in unique_users or match["infection_date"] > unique_users[user]["infection_date"]:
            unique_users[user] = match

    return {
        "total_matches": len(matches),
        "unique_accounts": len(unique_users),
        "accounts": list(unique_users.values()),
        "earliest_exposure": min((m["infection_date"] for m in matches), default=None),
        "latest_exposure": max((m["infection_date"] for m in matches), default=None)
    }
```

---

## 16. TikTok Intelligence Gathering

### Profile Discovery & Metadata Extraction

```bash
# Search TikTok for target mentions via Google dorking
site:tiktok.com "@<target-company>" OR "<target-technology>"
site:tiktok.com "@<target-username>"

# TikTok public API — search users (unauthenticated)
curl -s "https://www.tiktok.com/api/user/search/?keyword=<target-company>&count=20" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
  | jq '.user_list[].user_info | {unique_id, nickname, signature, follower_count, video_count}'

# TikTok video search by hashtag
curl -s "https://www.tiktok.com/api/search/item/full/?keyword=<target-technology>+security&count=20" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
  | jq '.item_list[] | {desc, author: .author.unique_id, stats: .stats, created_time: .create_time}'
```

### Video Content Analysis

```bash
# Download TikTok video metadata without watermark
yt-dlp --dump-json "https://www.tiktok.com/@<username>/video/<video-id>" \
  | jq '{title: .description, upload_date, view_count, like_count, comment_count, repost_count, uploader, uploader_id}'

# Batch download videos from a target user for offline analysis
yt-dlp -o "/tmp/tiktok/%(uploader)s/%(id)s.%(ext)s" \
  "https://www.tiktok.com/@<username>" --max-downloads 50 --write-description

# Extract video descriptions containing security keywords
find /tmp/tiktok -name "*.description" -exec grep -liE "password|VPN|firewall|server|breach|hack|exploit|credential" {} \; \
  | while read f; do echo "=== $f ==="; cat "$f"; echo; done
```

### Employee TikTok Activity Monitoring

```python
import requests
import json
from datetime import datetime

def search_tiktok_users(keyword):
    """Search TikTok for users matching a keyword (company name, etc.)"""
    url = "https://www.tiktok.com/api/user/search/"
    params = {"keyword": keyword, "count": 20}
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

    resp = requests.get(url, params=params, headers=headers)
    if resp.status_code != 200:
        return []

    data = resp.json()
    results = []
    for user_entry in data.get("user_list", []):
        user = user_entry.get("user_info", {})
        results.append({
            "username": user.get("unique_id"),
            "display_name": user.get("nickname"),
            "bio": user.get("signature"),
            "followers": user.get("follower_count"),
            "videos": user.get("video_count"),
            "verified": user.get("verified"),
            "bio_keywords": extract_security_keywords(user.get("signature", ""))
        })
    return results

def extract_security_keywords(text):
    """Extract security-relevant keywords from bio or video descriptions"""
    sec_keywords = [
        "security", "cybersecurity", "hacker", "pentest", "redteam",
        "blueteam", "CTF", "OSCP", "defcon", "blackhat", "infosec",
        "CVE", "exploit", "vulnerability", "firewall", "VPN",
        "SOC", "SIEM", "cloud security", "DevSecOps"
    ]
    text_lower = text.lower()
    return [kw for kw in sec_keywords if kw.lower() in text_lower]
```

### TikTok Hashtag Intelligence

```bash
# Discover trending hashtags related to target industry
curl -s "https://www.tiktok.com/api/search/item/full/?keyword=<target-industry>+breach+OR+security+OR+hacked&count=30" \
  -H "User-Agent: Mozilla/5.0" | \
  jq '[.item_list[].desc | scan("#[^\\s]+")] | flatten | .[]' | sort | uniq -c | sort -rn | head -20

# Monitor TikTok for company name mentions via RSS-like polling
while true; do
  COUNT=$(curl -s "https://www.tiktok.com/api/search/item/full/?keyword=%22<target-company>%22&count=10" \
    -H "User-Agent: Mozilla/5.0" | jq '.item_list | length')
  echo "$(date +%Y-%m-%dT%H:%M:%S) — <target-company> mentions: $COUNT"
  sleep 3600
done
```

---

## 17. Instagram OSINT Techniques

### Profile Enumeration & Public Data

```bash
# Instagram public profile via Google dorking
site:instagram.com "<target-company>" OR "<target-username>"
site:instagram.com/p/ "<target-company>" (office OR workplace OR datacenter)

# instaloader — public profile scraping without login
instaloader --no-pictures --no-videos --no-captions \
  --metadata-json <target-username>

# Extract profile metadata from downloaded JSON
find . -name "*.json.xz" -exec jq '{username: .node.username, full_name: .node.full_name, biography: .node.biography, followers: .node.edge_followed_by.count, following: .node.edge_follow.count, is_private: .node.is_private, is_verified: .node.is_verified, external_url: .node.external_url}' {} \;
```

### Geolocation Extraction from Posts

```bash
# Download location-tagged posts (requires login for private data)
instaloader --login=$INSTA_USER --password=$INSTA_PASS \
  --no-pictures --no-videos --geotags <target-username>

# Extract all geotag data from metadata files
find . -name "*.json.xz" | while read f; do
  jq -r '.node.location | select(. != null) | "\(.name) | \(.lat), \(.lng) | \(.id)"' "$f" 2>/dev/null
done | sort -u > /tmp/instagram-geotags.txt

# Generate Google Maps links from extracted locations
while IFS=' | ' read -r name lat lng id; do
  [ -n "$lat" ] && echo "$name: https://www.google.com/maps?q=${lat},${lng}"
done < /tmp/instagram-geotags.txt
```

### Instagram Network Analysis

```python
import json
from collections import Counter

def analyze_instagram_network(followers_data, following_data):
    """Analyze Instagram follower/following relationships for intel"""
    followers = {u["id"]: u for u in followers_data}
    following = {u["id"]: u for u in following_data}

    # Identify mutual connections (likely real-world relationships)
    mutual_ids = set(followers.keys()) & set(following.keys())
    mutual_profiles = [followers[uid] for uid in mutual_ids]

    # Categorize mutuals by bio keywords
    categorized = {"coworkers": [], "industry": [], "security": [], "other": []}
    for profile in mutual_profiles:
        bio = profile.get("biography", "").lower()
        if any(kw in bio for kw in ["@target-company", "target-company"]):
            categorized["coworkers"].append(profile)
        elif any(kw in bio for kw in ["security", "infosec", "cyber", "pentest", "hack"]):
            categorized["security"].append(profile)
        elif any(kw in bio for kw in ["engineer", "developer", "devops", "cloud"]):
            categorized["industry"].append(profile)
        else:
            categorized["other"].append(profile)

    return {
        "total_followers": len(followers),
        "total_following": len(following),
        "mutual_connections": len(mutual_ids),
        "mutual_profiles": mutual_profiles[:50],
        "categorized": {k: len(v) for k, v in categorized.items()},
        "coworker_profiles": categorized["coworkers"]
    }
```

### Instagram Story & Highlight Monitoring

```bash
# Download stories and highlights (requires login)
instaloader --login=$INSTA_USER --password=$INSTA_PASS \
  --stories --highlights <target-username>

# Extract text from story images using OCR
for img in /tmp/target-stories/*.jpg; do
  TEXT=$(tesseract "$img" stdout 2>/dev/null | grep -iE "password|login|server|VPN|office|badge|key|token")
  [ -n "$TEXT" ] && echo "FILE: $img — TEXT: $TEXT"
done

# Monitor for new stories on schedule (check every 30 minutes)
while true; do
  instaloader --login=$INSTA_USER --password=$INSTA_PASS \
    --stories --no-pictures --no-videos --metadata-json \
    --dirname-pattern /tmp/insta-monitor/{target} <target-username> 2>/dev/null
  sleep 1800
done
```

### Instagram Hashtag & Location Intelligence

```bash
# Search posts by hashtag related to target company
instaloader --login=$INSTA_USER --password=$INSTA_PASS \
  "#<target-company>" --max-count=100 \
  --no-pictures --no-videos --metadata-json \
  --dirname-pattern /tmp/insta-hashtags/{target}

# Search posts by location (requires location ID from Instagram)
# Find location IDs: https://www.instagram.com/explore/locations/?query=<city>
instaloader --login=$INSTA_USER --password=$INSTA_PASS \
  "%<location-id>" --max-count=50 \
  --metadata-json --dirname-pattern /tmp/insta-locations/{target}

# Extract captions for keyword analysis
find /tmp/insta-hashtags -name "*.json.xz" | while read f; do
  jq -r '.node.edge_media_to_caption.edges[0].node.text // empty' "$f" 2>/dev/null
done | grep -iE "<target-company>|security|office|server|datacenter|badge" > /tmp/insta-caption-matches.txt
```

---

## 18. Discord Server Enumeration

### Server Discovery & Invite Link Hunting

```bash
# Google dorking for Discord invite links related to target
site:discord.com/invite "<target-company>" OR "<target-technology>"
site:discord.gg "<target-company>"
"<target-company>" "discord.gg/" OR "discord.com/invite/"

# Search GitHub for embedded Discord invite links
curl -s "https://api.github.com/search/code?q=discord.gg+<target-company>" \
  -H "Authorization: token $GITHUB_TOKEN" | \
  jq '.items[] | {repository: .repository.full_name, path: .path, html_url: .html_url}'

# Search Reddit for Discord server invites
curl -s "https://oauth.reddit.com/search?q=discord.gg+<target-company>&sort=new&limit=25" \
  -H "Authorization: Bearer $REDDIT_TOKEN" \
  -H "User-Agent: kali-claw/1.0" | \
  jq '.data.children[].data | {title, selftext: .selftext[:300], url, permalink}'
```

### Discord Server Enumeration via API

```python
import requests
import json
from datetime import datetime

def enumerate_discord_server(invite_code, discord_token=None):
    """Enumerate Discord server via invite link metadata"""
    headers = {"User-Agent": "Mozilla/5.0"}
    if discord_token:
        headers["Authorization"] = discord_token

    # Get invite metadata (works without authentication)
    resp = requests.get(
        f"https://discord.com/api/v10/invites/{invite_code}?with_counts=true&with_expiration=true",
        headers=headers
    )

    if resp.status_code != 200:
        return {"error": f"HTTP {resp.status_code}", "body": resp.text}

    data = resp.json()
    guild = data.get("guild", {})
    channel = data.get("channel", {})
    inviter = data.get("inviter", {})

    return {
        "server_name": guild.get("name"),
        "server_id": guild.get("id"),
        "member_count": data.get("approximate_member_count"),
        "active_count": data.get("approximate_presence_count"),
        "description": guild.get("description"),
        "is_nsfw": guild.get("nsfw"),
        "verification_level": guild.get("verification_level"),
        "vanity_url": guild.get("vanity_url_code"),
        "channel_name": channel.get("name"),
        "channel_type": channel.get("type"),
        "inviter": inviter.get("username"),
        "features": guild.get("features", []),
        "icon_hash": guild.get("icon"),
        "banner_hash": guild.get("banner"),
        "boost_level": guild.get("premium_tier"),
        "boost_count": guild.get("premium_subscription_count")
    }
```

### Discord User Activity Analysis

```python
def analyze_discord_user(user_id, messages, guild_id=None):
    """Analyze Discord user activity patterns from collected messages"""
    activity = {
        "user_id": user_id,
        "message_count": len(messages),
        "channels_active": set(),
        "mentioned_users": Counter(),
        "mentioned_roles": Counter(),
        "shared_links": [],
        "shared_files": [],
        "keywords_found": [],
        "activity_hours": Counter(),
        "first_seen": None,
        "last_seen": None
    }

    security_keywords = [
        "password", "token", "api_key", "secret", "credential",
        "exploit", "CVE", "vulnerability", "breach", "hack",
        "payload", "reverse_shell", "backdoor", "phishing"
    ]

    for msg in messages:
        ts = datetime.fromisoformat(msg["timestamp"])
        activity["channels_active"].add(msg.get("channel_id"))
        activity["activity_hours"][ts.hour] += 1

        if activity["first_seen"] is None or ts < activity["first_seen"]:
            activity["first_seen"] = ts
        if activity["last_seen"] is None or ts > activity["last_seen"]:
            activity["last_seen"] = ts

        content = msg.get("content", "").lower()
        for kw in security_keywords:
            if kw in content and kw not in activity["keywords_found"]:
                activity["keywords_found"].append(kw)

        for mention in msg.get("mentions", []):
            activity["mentioned_users"][mention.get("id")] += 1

        for attachment in msg.get("attachments", []):
            activity["shared_files"].append({
                "filename": attachment.get("filename"),
                "size": attachment.get("size"),
                "url": attachment.get("url")
            })

        for embed in msg.get("embeds", []):
            if embed.get("url"):
                activity["shared_links"].append(embed["url"])

    activity["channels_active"] = len(activity["channels_active"])
    return activity
```

### Discord Webhook & Integration Discovery

```bash
# Search for exposed Discord webhooks related to target
curl -s "https://api.github.com/search/code?q=discord.com+api+webhooks+<target-company>" \
  -H "Authorization: token $GITHUB_TOKEN" | \
  jq '.items[] | {repository: .repository.full_name, path: .path, html_url: .html_url}'

# Google dorking for exposed webhook URLs
"discord.com/api/webhooks/" "<target-company>" OR "<target-technology>"

# Search for Discord bot tokens in public repositories
curl -s "https://api.github.com/search/code?q=DISCORD_TOKEN+OR+DISCORD_BOT_TOKEN+<target-company>" \
  -H "Authorization: token $GITHUB_TOKEN" | \
  jq '.items[] | {repository: .repository.full_name, path: .path}'

# Enumerate Discord bots present in a server (requires server access)
# Check bot presence via gateway events or member list
curl -s "https://discord.com/api/v10/guilds/<guild-id>/members?limit=100" \
  -H "Authorization: Bot $DISCORD_BOT_TOKEN" | \
  jq '[.[] | select(.user.bot == true) | {id: .user.id, username: .user.username, roles: .roles}]'
```

---

## 19. Mastodon/Fediverse Monitoring

### Instance Discovery & User Search

```bash
# Search for target across multiple Mastodon instances via Google dorking
site:mastodon.social "@<target-username>"
site:mastodon.online "<target-company>"
site:infosec.exchange "<target-technology>" security

# Federated search across known Mastodon instances
INSTANCES=("mastodon.social" "mastodon.online" "infosec.exchange" "fosstodon.org" "hachyderm.io" "securitymastod.one")

for instance in "${INSTANCES[@]}"; do
  echo "[MASTODON] Searching $instance for <target-username>"
  curl -s "https://${instance}/api/v2/search?q=<target-username>&type=accounts&limit=20" \
    -H "Authorization: Bearer $MASTODON_TOKEN" | \
    jq ".accounts[] | {id, username, display_name, acct, followers_count, following_count, statuses_count, note: .note[:200], bot, verified_at: (.fields // [] | map(select(.verified_at != null)) | length)}"
done
```

### Mastodon Account Profiling

```python
import requests
import json
from datetime import datetime

def profile_mastodon_account(instance, username, access_token=None):
    """Profile a Mastodon account and extract intelligence"""
    headers = {}
    if access_token:
        headers["Authorization"] = f"Bearer {access_token}"

    # Get account info
    resp = requests.get(
        f"https://{instance}/api/v1/accounts/lookup?acct={username}",
        headers=headers
    )
    if resp.status_code != 200:
        return {"error": f"Account not found on {instance}"}

    account = resp.json()

    profile = {
        "instance": instance,
        "username": account["username"],
        "display_name": account["display_name"],
        "bio": account.get("note", ""),
        "followers": account["followers_count"],
        "following": account["following_count"],
        "statuses": account["statuses_count"],
        "created_at": account["created_at"],
        "is_bot": account.get("bot", False),
        "is_locked": account.get("locked", False),
        "profile_fields": [],
        "avatar_url": account.get("avatar"),
        "header_url": account.get("header"),
        "recent_posts": []
    }

    # Extract verified profile fields
    for field in account.get("fields", []):
        profile["profile_fields"].append({
            "name": field["name"],
            "value": field["value"],
            "verified": field.get("verified_at") is not None
        })

    # Get recent posts
    account_id = account["id"]
    resp = requests.get(
        f"https://{instance}/api/v1/accounts/{account_id}/statuses?limit=40",
        headers=headers
    )
    if resp.status_code == 200:
        for status in resp.json():
            profile["recent_posts"].append({
                "content": status.get("content", "")[:500],
                "created_at": status["created_at"],
                "reblogs": status.get("reblogs_count", 0),
                "favourites": status.get("favourites_count", 0),
                "tags": [t["name"] for t in status.get("tags", [])],
                "media_attachments": len(status.get("media_attachments", [])),
                "in_reply_to": status.get("in_reply_to_id"),
                "visibility": status.get("visibility")
            })

    return profile
```

### Fediverse Instance Monitoring

```python
import requests
from collections import Counter
from datetime import datetime, timedelta

class FediverseMonitor:
    """Monitor multiple Fediverse instances for target mentions"""

    def __init__(self, instances, access_tokens=None):
        self.instances = instances
        self.tokens = access_tokens or {}
        self.seen_status_ids = set()

    def search_public_timeline(self, query, instance):
        """Search public timeline on a specific instance"""
        headers = {}
        if instance in self.tokens:
            headers["Authorization"] = f"Bearer {self.tokens[instance]}"

        resp = requests.get(
            f"https://{instance}/api/v2/search",
            params={"q": query, "type": "statuses", "limit": 40},
            headers=headers
        )
        if resp.status_code != 200:
            return []

        results = []
        for status in resp.json().get("statuses", []):
            if status["id"] not in self.seen_status_ids:
                self.seen_status_ids.add(status["id"])
                results.append({
                    "instance": instance,
                    "id": status["id"],
                    "content": self._strip_html(status.get("content", "")),
                    "author": status["account"]["acct"],
                    "author_followers": status["account"]["followers_count"],
                    "created_at": status["created_at"],
                    "reblogs": status.get("reblogs_count", 0),
                    "favourites": status.get("favourites_count", 0),
                    "tags": [t["name"] for t in status.get("tags", [])],
                    "url": status.get("url")
                })
        return results

    def monitor_all_instances(self, query):
        """Search across all configured instances"""
        all_results = []
        for instance in self.instances:
            try:
                results = self.search_public_timeline(query, instance)
                all_results.extend(results)
            except requests.RequestException:
                continue
        return all_results

    @staticmethod
    def _strip_html(text):
        """Remove HTML tags from Mastodon content"""
        import re
        return re.sub(r"<[^>]+>", "", text).strip()
```

### Fediverse Tag & Trend Analysis

```bash
# Monitor trending tags on security-focused Mastodon instances
curl -s "https://infosec.exchange/api/v1/trends/tags?limit=20" | \
  jq '.[] | {name, url, history: .history[-7:] | map({day: .day, uses: .uses, accounts: .accounts})}'

# Get statuses for a specific hashtag
curl -s "https://mastodon.social/api/v1/timelines/tag/cybersecurity?limit=40" | \
  jq '.[] | {content: .content[:200], account: .account.acct, created_at, reblogs_count, tags: [.tags[].name]}'

# Monitor Fediverse for target company mentions across instances
QUERY="<target-company>"
for instance in mastodon.social infosec.exchange fosstodon.org hachyderm.io; do
  echo "[FEDI] $instance: searching for '$QUERY'"
  curl -s "https://${instance}/api/v2/search?q=${QUERY}&type=statuses&limit=20" | \
    jq --arg inst "$instance" '[.statuses[] | {instance: $inst, content: (.content | gsub("<[^>]+>"; "") | .[0:200]), author: .account.acct, created_at}]'
  sleep 1
done
```
