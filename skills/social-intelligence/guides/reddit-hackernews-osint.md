# Reddit & HackerNews OSINT Guide

> Guide for the social-intelligence skill — covers Reddit and HackerNews intelligence gathering techniques.

## Reddit Intelligence

### API Setup

Reddit requires OAuth2 for API access. Create an app at [reddit.com/prefs/apps](https://www.reddit.com/prefs/apps/).

```bash
# Obtain OAuth token
TOKEN=$(curl -s -X POST -d "grant_type=password&username=$REDDIT_USER&password=$REDDIT_PASS" \
  --user "$CLIENT_ID:$CLIENT_SECRET" \
  "https://www.reddit.com/api/v1/access_token" | jq -r '.access_token')

# Authenticated search
curl -s "https://oauth.reddit.com/search?q=<query>&sort=new&t=month&limit=100" \
  -H "Authorization: Bearer $TOKEN" \
  -H "User-Agent: kali-claw/1.0"
```

### High-Value Subreddits for Security OSINT

| Subreddit | Intelligence Value |
|-----------|-------------------|
| /r/sysadmin | Tech stack leaks, infrastructure complaints, vendor evaluations |
| /r/netsec | Vulnerability discussions, exploit announcements, research sharing |
| /r/devops | CI/CD tools, cloud providers, deployment practices |
| /r/networking | Network equipment, firewall rules, VPN discussions |
| /r/cybersecurity | Security incidents, tool reviews, career discussions |
| /r/AskNetsec | Security questions revealing organizational challenges |
| /r/blueteamsec | Defensive tools, detection rules, SOC practices |
| /r/redteamsec | Offensive techniques, tool releases, engagement stories |
| /r/homelab | Often used by employees testing work-related tech at home |

### Search Techniques

#### Company-Specific Intelligence

```bash
# Direct company mentions
"<company-name>" subreddit:sysadmin OR subreddit:devops
"<company-domain>" subreddit:netsec OR subreddit:cybersecurity

# Employee identification (people asking about company-specific issues)
"at <company-name>" OR "work at <company>" subreddit:sysadmin
"our company uses" "<technology>" subreddit:sysadmin
```

#### Technology Stack Discovery

```bash
# Infrastructure discussions
"<company>" (AWS OR Azure OR GCP OR "on-prem") subreddit:devops
"<company>" (Kubernetes OR Docker OR Terraform) subreddit:devops
"migrating from" OR "migrating to" "<company>" subreddit:sysadmin

# Security tool discussions
"<company>" (CrowdStrike OR SentinelOne OR "Carbon Black" OR Splunk) subreddit:sysadmin
"<company>" (Okta OR "Azure AD" OR "Active Directory") subreddit:sysadmin
```

#### Complaint Mining (Social Engineering Gold)

```bash
# Security policy frustrations
"<company>" "password policy" OR "MFA" OR "VPN issues" subreddit:sysadmin
"<company>" "security team" OR "security training" OR "phishing test" subreddit:sysadmin
"<company>" "can't access" OR "locked out" OR "too many restrictions" subreddit:sysadmin
```

### User Analysis

```bash
# Analyze a user's posting history for intelligence
# 1. Get recent comments
curl -s "https://www.reddit.com/user/<username>/comments.json?limit=100&sort=new" \
  | jq '.data.children[].data | {subreddit, body: .body[:200], created_utc, score}'

# 2. Identify subreddit distribution (reveals interests)
curl -s "https://www.reddit.com/user/<username>/comments.json?limit=100" \
  | jq '.data.children[].data.subreddit' | sort | uniq -c | sort -rn

# 3. Extract technical keywords
curl -s "https://www.reddit.com/user/<username>/comments.json?limit=100" \
  | jq -r '.data.children[].data.body' \
  | grep -ioE 'AWS|Azure|GCP|kubernetes|docker|terraform|ansible|jenkins|gitlab|nginx|apache|postgresql|mysql|redis|elasticsearch|splunk|crowdstrike|okta' \
  | sort | uniq -c | sort -rn
```

---

## HackerNews Intelligence

### Algolia API (No Auth Required)

HN provides a free, unauthenticated search API via Algolia — the most accessible social intelligence source.

```bash
BASE="https://hn.algolia.com/api/v1"
```

### Search Types

#### Story Search (Articles, Show HN, Ask HN)

```bash
# Recent stories about target
curl -s "$BASE/search?query=<target>&tags=story&numericFilters=created_at_i>$(date -d '30 days ago' +%s)&hitsPerPage=50" \
  | jq '.hits[] | {title, url, points, num_comments, created_at}'

# High-engagement stories (likely important)
curl -s "$BASE/search?query=<target>&tags=story&numericFilters=points>50&hitsPerPage=20" \
  | jq '.hits[] | {title, url, points, num_comments}'

# Show HN (companies sharing their products)
curl -s "$BASE/search?query=<target>&tags=show_hn&hitsPerPage=20" \
  | jq '.hits[] | {title, url, points}'
```

#### Comment Search (Often More Revealing)

```bash
# Comments mentioning target (employees often comment)
curl -s "$BASE/search?query=<target>&tags=comment&numericFilters=created_at_i>$(date -d '30 days ago' +%s)&hitsPerPage=50" \
  | jq '.hits[] | {text: .comment_text[:300], author, story_title, created_at}'

# Comments with security context
curl -s "$BASE/search?query=<target>+vulnerability+OR+breach+OR+security&tags=comment&hitsPerPage=20" \
  | jq '.hits[] | {text: .comment_text[:300], author, story_title}'

# Comments about specific technology
curl -s "$BASE/search?query=<technology>+exploit+OR+CVE+OR+bypass&tags=comment&hitsPerPage=20" \
  | jq '.hits[] | {text: .comment_text[:300], author, story_title}'
```

### User Profile Intelligence

```bash
# Get user profile (karma reveals credibility)
curl -s "https://hacker-news.firebaseio.com/v0/user/<username>.json" \
  | jq '{id, created, karma, about}'

# Get recent submissions
SUBMISSIONS=$(curl -s "https://hacker-news.firebaseio.com/v0/user/<username>.json" | jq '.submitted[:30][]')
for id in $SUBMISSIONS; do
  curl -s "https://hacker-news.firebaseio.com/v0/item/${id}.json" \
    | jq 'select(.type == "comment") | {text: .text[:200], time}' 2>/dev/null
done
```

### Intelligence Patterns on HN

| Signal | What It Reveals |
|--------|----------------|
| Employee comments on company stories | Insider perspective, confirms employment |
| "I work at X and..." | Direct tech stack / culture revelation |
| Show HN posts | Company product launches, technical architecture |
| Hiring threads ("Who's Hiring") | Technology requirements, team structure |
| Complaints about a technology | Pain points that may indicate vulnerabilities |
| Security incident discussions | Community assessment of severity and impact |

---

## Combined Reddit + HN Workflow

### Pre-Engagement Intelligence Pipeline

```bash
# Step 1: Broad search across both platforms
echo "=== Reddit ===" 
for sub in sysadmin netsec devops networking cybersecurity; do
  echo "--- /r/$sub ---"
  curl -s "https://www.reddit.com/r/$sub/search.json?q=<target>&sort=new&t=month&limit=10" \
    | jq '.data.children[].data | {title, selftext: .selftext[:100], score, subreddit}'
done

echo "=== HackerNews ==="
curl -s "$BASE/search?query=<target>&numericFilters=created_at_i>$(date -d '30 days ago' +%s)&hitsPerPage=30" \
  | jq '.hits[] | {title, text: (.comment_text // .title)[:200], author, points, created_at}'

# Step 2: Identify key users and deep-dive
# Extract unique authors from both platforms
# Cross-reference with Sherlock for other platforms

# Step 3: Categorize findings
# - Technology stack mentions
# - Security-related discussions
# - Employee sentiment
# - Vulnerability/incident mentions
```

### Advanced Search Operators

Reddit and HackerNews support powerful query syntax that enables precise intelligence extraction beyond basic keyword searches.

```bash
# Reddit advanced search operators
# Boolean combinations
"(AWS OR Azure) AND (security OR breach)" subreddit:netsec
"company-name" AND (password OR credential OR leaked) subreddit:all

# Negation to remove noise
"company-name" -"job posting" -"hiring" -"career" subreddit:all
"vulnerability" -"CVE-" -subreddit:cve subreddit:netsec

# Time-bounded searches (Reddit URL parameters)
# t=hour, t=day, t=week, t=month, t=year, t=all
curl -s "https://www.reddit.com/search.json?q=<target>&t=week&sort=top&limit=100" \
  -H "User-Agent: kali-claw/1.0" | jq '.data.children[].data | {title, score, url}'

# Reddit flair filtering (some subreddits tag posts with flairs)
curl -s "https://www.reddit.com/r/netsec/search.json?q=<target>&flair=Exploit&limit=50"

# HackerNews advanced Algolia queries
# Boolean AND/OR
curl -s "$BASE/search?query=<company>+AND+(breach+OR+vulnerability)&tags=story"

# Date range with points threshold
curl -s "$BASE/search?query=<target>&tags=story&numericFilters=created_at_i>$(date -d '7 days ago' +%s),points>10"

# Search by specific author
curl -s "$BASE/search?query=&tags=story&by=<username>"

# Combine author and topic
curl -s "$BASE/search?query=<technology>+exploit&tags=comment&by=<username>"
```

### Subreddit Analysis Methodology

Systematic subreddit analysis goes beyond keyword search to understand community dynamics, identify key contributors, and map topic distribution.

```python
#!/usr/bin/env python3
"""Subreddit analysis methodology for intelligence gathering."""
import requests
import json
from collections import Counter, defaultdict
from datetime import datetime

def analyze_subreddit(subreddit_name, limit=500):
    """Perform comprehensive analysis of a subreddit."""
    headers = {"User-Agent": "kali-claw-analyzer/1.0"}

    # Collect recent posts
    url = f"https://www.reddit.com/r/{subreddit_name}/new.json?limit={limit}"
    response = requests.get(url, headers=headers)
    posts = response.json().get("data", {}).get("children", [])

    analysis = {
        "subreddit": subreddit_name,
        "analyzed_at": datetime.utcnow().isoformat(),
        "total_posts": len(posts),
        "top_authors": Counter(),
        "domain_distribution": Counter(),
        "title_keywords": Counter(),
        "posting_times": Counter(),
        "score_distribution": {"min": 0, "max": 0, "avg": 0},
        "flair_distribution": Counter(),
        "crossposted_to": Counter()
    }

    scores = []
    for child in posts:
        post = child["data"]
        scores.append(post.get("score", 0))

        # Author frequency
        analysis["top_authors"][post.get("author", "[deleted]")] += 1

        # Domain analysis (reveals preferred sources)
        url_str = post.get("url", "")
        if url_str and not url_str.startswith("/r/"):
            domain = url_str.split("/")[2] if "/" in url_str else url_str
            analysis["domain_distribution"][domain] += 1

        # Flair/tag distribution
        flair = post.get("link_flair_text")
        if flair:
            analysis["flair_distribution"][flair] += 1

        # Posting time distribution (UTC hours)
        created = post.get("created_utc", 0)
        hour = datetime.utcfromtimestamp(created).hour
        analysis["posting_times"][hour] += 1

    if scores:
        analysis["score_distribution"] = {
            "min": min(scores),
            "max": max(scores),
            "avg": round(sum(scores) / len(scores), 1)
        }

    return analysis

def compare_subreddits(subreddits, target_keyword):
    """Compare how different subreddits discuss a target keyword."""
    headers = {"User-Agent": "kali-claw/1.0"}
    comparison = {}

    for sub in subreddits:
        url = f"https://www.reddit.com/r/{sub}/search.json?q={target_keyword}&restrict_sr=on&sort=relevance&t=year&limit=100"
        response = requests.get(url, headers=headers)
        results = response.json().get("data", {}).get("children", [])

        comparison[sub] = {
            "total_mentions": len(results),
            "avg_score": sum(r["data"].get("score", 0) for r in results) / max(len(results), 1),
            "top_post_title": results[0]["data"]["title"] if results else None,
            "unique_authors": len(set(r["data"].get("author", "") for r in results))
        }

    return comparison
```

### User Profiling Across Platforms

Correlate a single user's identity across Reddit, HackerNews, and other platforms to build a comprehensive activity profile.

```python
#!/usr/bin/env python3
"""Cross-platform user profiling and correlation."""
import json
import requests
from collections import Counter
from datetime import datetime

class CrossPlatformProfiler:
    """Build a unified profile from multiple platforms."""

    def __init__(self):
        self.profile = {
            "username": None,
            "platforms": {},
            "correlated_accounts": [],
            "interests": Counter(),
            "activity_timeline": [],
            "technical_skills": set(),
            "geographic_hints": set()
        }

    def profile_reddit_user(self, username, limit=200):
        """Deep-dive into a Reddit user's activity."""
        headers = {"User-Agent": "kali-claw-profiler/1.0"}
        url = f"https://www.reddit.com/user/{username}/comments.json?limit={limit}&sort=new"
        response = requests.get(url, headers=headers)
        comments = response.json().get("data", {}).get("children", [])

        subreddits = Counter()
        tech_mentions = Counter()
        for child in comments:
            comment = child["data"]
            subreddits[comment.get("subreddit", "")] += 1
            body = comment.get("body", "").lower()

            # Extract technical keywords
            import re
            tech_terms = re.findall(
                r'\b(python|java|golang|rust|docker|kubernetes|terraform|aws|azure|gcp|'
                r'linux|windows|macos|nginx|apache|postgresql|mysql|redis|mongodb|'
                r'react|vue|angular|node|django|flask|fastapi)\b', body
            )
            tech_mentions.update(tech_terms)

            # Geographic hints from language/timezone references
            geo_hints = re.findall(
                r'\b(EST|PST|CET|GMT|UTC[+-]\d|London|NYC|Berlin|Tokyo|Singapore)\b', body
            )
            self.profile["geographic_hints"].update(geo_hints)

        self.profile["platforms"]["reddit"] = {
            "username": username,
            "total_comments_analyzed": len(comments),
            "subreddit_distribution": dict(subreddits.most_common(20)),
            "technical_skills": dict(tech_mentions.most_common(20)),
            "primary_subreddits": list(subreddits.keys())[:5]
        }
        self.profile["interests"].update(subreddits)
        self.profile["technical_skills"].update(tech_mentions.elements())
        return self.profile

    def profile_hn_user(self, username):
        """Profile a HackerNews user and their submission history."""
        url = f"https://hacker-news.firebaseio.com/v0/user/{username}.json"
        response = requests.get(url)
        data = response.json()

        if not data:
            return None

        submission_ids = data.get("submitted", [])[:50]
        stories = []
        comments = []

        for sid in submission_ids:
            item_resp = requests.get(f"https://hacker-news.firebaseio.com/v0/item/{sid}.json")
            item = item_resp.json()
            if not item:
                continue
            if item.get("type") == "story":
                stories.append(item.get("title", ""))
            elif item.get("type") == "comment":
                comments.append(item.get("text", "")[:500])

        self.profile["platforms"]["hackernews"] = {
            "username": username,
            "karma": data.get("karma", 0),
            "account_created": datetime.utcfromtimestamp(data.get("created", 0)).isoformat(),
            "about": data.get("about", ""),
            "stories_submitted": len(stories),
            "comments_submitted": len(comments),
            "recent_stories": stories[:10]
        }
        return self.profile

    def correlate_usernames(self, candidate_usernames):
        """Try multiple username variations across platforms to find aliases."""
        found = []
        for uname in candidate_usernames:
            checks = {
                "reddit": f"https://www.reddit.com/user/{uname}/about.json",
                "github": f"https://api.github.com/users/{uname}",
                "twitter": f"https://nitter.net/{uname}",
            }
            for platform, url in checks.items():
                try:
                    resp = requests.get(url, timeout=5)
                    if resp.status_code == 200:
                        found.append({"username": uname, "platform": platform, "url": url})
                except requests.RequestException:
                    pass
        self.profile["correlated_accounts"] = found
        return found
```

### Comment Network Analysis

Analyze reply chains and comment interactions to map social relationships and identify information flows within communities.

```python
#!/usr/bin/env python3
"""Comment network analysis for social relationship mapping."""
import json
import requests
from collections import defaultdict, Counter
from datetime import datetime

class CommentNetworkAnalyzer:
    """Analyze comment reply networks to map social connections."""

    def __init__(self):
        self.interactions = defaultdict(lambda: defaultdict(int))
        self.reply_chains = []

    def analyze_reddit_thread(self, submission_id, headers=None):
        """Map the reply network within a Reddit submission."""
        if headers is None:
            headers = {"User-Agent": "kali-claw/1.0"}

        url = f"https://www.reddit.com/comments/{submission_id}.json?limit=500"
        response = requests.get(url, headers=headers)
        data = response.json()

        if len(data) < 2:
            return {}

        # Parse comment tree recursively
        def parse_comment_tree(comments, parent_author="OP"):
            for child in comments:
                comment = child.get("data", {})
                author = comment.get("author", "[deleted]")
                self.interactions[parent_author][author] += 1

                replies = comment.get("replies", {})
                if isinstance(replies, dict) and replies.get("data", {}).get("children"):
                    parse_comment_tree(
                        replies["data"]["children"],
                        parent_author=author
                    )

        comment_list = data[1].get("data", {}).get("children", [])
        op_author = data[0]["data"]["children"][0]["data"].get("author", "OP")
        parse_comment_tree(comment_list, parent_author=op_author)

        # Calculate interaction metrics
        interaction_graph = {}
        for source, targets in self.interactions.items():
            interaction_graph[source] = {
                "replied_to": dict(targets),
                "total_replies": sum(targets.values()),
                "unique_targets": len(targets)
            }

        return interaction_graph

    def identify_information_brokers(self):
        """Find users who bridge different conversation clusters."""
        brokers = []
        for user, targets in self.interactions.items():
            if len(targets) >= 3:
                broker_score = len(targets) * sum(targets.values())
                brokers.append({
                    "user": user,
                    "unique_connections": len(targets),
                    "total_interactions": sum(targets.values()),
                    "broker_score": broker_score
                })
        brokers.sort(key=lambda b: -b["broker_score"])
        return brokers
```

### Temporal Posting Pattern Analysis

Analyze when users post to infer timezone, work schedule, and behavioral patterns useful for social engineering timing.

```python
#!/usr/bin/env python3
"""Temporal posting pattern analysis for behavioral inference."""
import json
import requests
from collections import Counter
from datetime import datetime
import statistics

class TemporalAnalyzer:
    """Analyze temporal patterns in user activity."""

    def analyze_reddit_temporal(self, username, headers=None):
        """Analyze posting time patterns for timezone inference."""
        if headers is None:
            headers = {"User-Agent": "kali-claw/1.0"}

        url = f"https://www.reddit.com/user/{username}/comments.json?limit=100&sort=new"
        response = requests.get(url, headers=headers)
        comments = response.json().get("data", {}).get("children", [])

        hours = []
        weekdays = []
        for child in comments:
            created = child["data"].get("created_utc", 0)
            dt = datetime.utcfromtimestamp(created)
            hours.append(dt.hour)
            weekdays.append(dt.weekday())

        if not hours:
            return {"error": "No comments found"}

        hour_counts = Counter(hours)
        peak_hour = hour_counts.most_common(1)[0][0]

        # Infer likely timezone (UTC offset where activity peaks 9-11 AM local)
        # If peak is at UTC 14:00, likely offset is -5 (EST)
        inferred_offset = (10 - peak_hour) % 24
        if inferred_offset > 12:
            inferred_offset -= 24

        return {
            "username": username,
            "total_comments": len(hours),
            "hourly_distribution": dict(sorted(hour_counts.items())),
            "peak_hour_utc": peak_hour,
            "inferred_utc_offset": inferred_offset,
            "weekday_distribution": dict(Counter(weekdays)),
            "activity_window": {
                "earliest_hour": min(hours),
                "latest_hour": max(hours)
            },
            "likely_work_hours": self._infer_work_hours(hour_counts),
            "activity_consistency": round(statistics.stdev(hours), 2) if len(hours) > 1 else 0
        }

    def _infer_work_hours(self, hour_counts):
        """Infer likely work hours from posting patterns."""
        total = sum(hour_counts.values())
        if total == 0:
            return None

        # Find contiguous block of highest activity
        weighted_hours = sorted(hour_counts.items(), key=lambda x: -x[1])
        top_hours = [h for h, _ in weighted_hours[:8]]
        top_hours.sort()

        return {
            "likely_work_start_utc": min(top_hours),
            "likely_work_end_utc": max(top_hours),
            "lunch_break_utc": statistics.median(top_hours) if top_hours else None
        }

    def analyze_hn_temporal(self, username):
        """Analyze HackerNews posting temporal patterns."""
        url = f"https://hacker-news.firebaseio.com/v0/user/{username}.json"
        data = requests.get(url).json()
        if not data:
            return {"error": "User not found"}

        submission_ids = data.get("submitted", [])[:100]
        timestamps = []
        for sid in submission_ids:
            item = requests.get(f"https://hacker-news.firebaseio.com/v0/item/{sid}.json").json()
            if item and "time" in item:
                timestamps.append(item["time"])

        hours = [datetime.utcfromtimestamp(ts).hour for ts in timestamps]
        return {
            "username": username,
            "total_items_analyzed": len(hours),
            "hourly_distribution": dict(Counter(hours)),
            "peak_hour_utc": Counter(hours).most_common(1)[0][0] if hours else None,
            "account_age_days": (datetime.utcnow() - datetime.utcfromtimestamp(data.get("created", 0))).days
        }
```

### Data Extraction with API

Automated bulk data extraction pipelines for systematic intelligence collection from both Reddit and HackerNews.

```python
#!/usr/bin/env python3
"""Bulk data extraction pipeline for Reddit and HN."""
import json
import time
import requests
from datetime import datetime
from pathlib import Path

class BulkExtractor:
    """Extract and archive data from Reddit and HackerNews."""

    def __init__(self, output_dir="extracted_data"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.headers = {"User-Agent": "kali-claw-extractor/1.0"}

    def extract_subreddit_history(self, subreddit, pages=10):
        """Extract historical posts from a subreddit with pagination."""
        all_posts = []
        after = None

        for page in range(pages):
            url = f"https://www.reddit.com/r/{subreddit}/new.json?limit=100"
            if after:
                url += f"&after={after}"

            response = requests.get(url, headers=self.headers)
            data = response.json().get("data", {})
            children = data.get("children", [])

            if not children:
                break

            for child in children:
                post = child["data"]
                all_posts.append({
                    "id": post["id"],
                    "title": post["title"],
                    "author": post.get("author", ""),
                    "score": post.get("score", 0),
                    "created_utc": post.get("created_utc", 0),
                    "url": post.get("url", ""),
                    "selftext": post.get("selftext", ""),
                    "num_comments": post.get("num_comments", 0),
                    "link_flair_text": post.get("link_flair_text"),
                    "extracted_at": datetime.utcnow().isoformat()
                })

            after = data.get("after")
            if not after:
                break
            time.sleep(2)  # Rate limit respect

        output_file = self.output_dir / f"reddit_{subreddit}_{datetime.utcnow().strftime('%Y%m%d')}.json"
        with open(output_file, "w") as f:
            json.dump(all_posts, f, indent=2)
        print(f"Extracted {len(all_posts)} posts to {output_file}")
        return all_posts

    def extract_hn_search_bulk(self, query, max_pages=10):
        """Extract all matching HackerNews stories/comments with pagination."""
        all_hits = []
        page = 0

        while page < max_pages:
            url = f"https://hn.algolia.com/api/v1/search?query={query}&page={page}&hitsPerPage=50"
            response = requests.get(url)
            data = response.json()
            hits = data.get("hits", [])

            if not hits:
                break

            for hit in hits:
                all_hits.append({
                    "id": hit["objectID"],
                    "title": hit.get("title", ""),
                    "author": hit.get("author", ""),
                    "points": hit.get("points", 0),
                    "num_comments": hit.get("num_comments", 0),
                    "url": hit.get("url", ""),
                    "created_at": hit.get("created_at", ""),
                    "comment_text": hit.get("comment_text", "")[:1000] if hit.get("comment_text") else "",
                    "type": hit.get("type", ""),
                    "extracted_at": datetime.utcnow().isoformat()
                })

            nb_pages = data.get("nbPages", 1)
            page += 1
            if page >= nb_pages:
                break
            time.sleep(0.5)

        output_file = self.output_dir / f"hn_{query.replace(' ', '_')}_{datetime.utcnow().strftime('%Y%m%d')}.json"
        with open(output_file, "w") as f:
            json.dump(all_hits, f, indent=2)
        print(f"Extracted {len(all_hits)} hits to {output_file}")
        return all_hits
```

### Identifying Key Influencers

Pinpoint the most impactful voices in security communities by combining quantitative metrics with qualitative signals.

```python
#!/usr/bin/env python3
"""Key influencer identification from community data."""
import json
from collections import defaultdict

class InfluencerIdentifier:
    """Identify key influencers across Reddit and HackerNews."""

    def __init__(self):
        self.user_metrics = defaultdict(lambda: {
            "posts": 0, "comments": 0, "total_score": 0,
            "domains_shared": set(), "topics": set(),
            "response_rate": 0, "avg_score": 0,
            "platforms": set()
        })

    def process_reddit_data(self, posts):
        """Process Reddit post data into influencer metrics."""
        for post in posts:
            author = post.get("author", "")
            if author in ("[deleted]", "AutoModerator"):
                continue
            metrics = self.user_metrics[author]
            metrics["posts"] += 1
            metrics["total_score"] += post.get("score", 0)
            metrics["platforms"].add("reddit")
            if post.get("url"):
                try:
                    domain = post["url"].split("/")[2]
                    metrics["domains_shared"].add(domain)
                except IndexError:
                    pass

    def process_hn_data(self, hits):
        """Process HackerNews data into influencer metrics."""
        for hit in hits:
            author = hit.get("author", "")
            if not author:
                continue
            metrics = self.user_metrics[author]
            if hit.get("type") == "story":
                metrics["posts"] += 1
            else:
                metrics["comments"] += 1
            metrics["total_score"] += hit.get("points", 0)
            metrics["platforms"].add("hackernews")

    def rank_influencers(self, top_n=20):
        """Rank users by composite influence score."""
        rankings = []
        for user, metrics in self.user_metrics.items():
            total_activity = metrics["posts"] + metrics["comments"]
            if total_activity == 0:
                continue

            avg_score = metrics["total_score"] / total_activity
            cross_platform_bonus = len(metrics["platforms"]) * 15
            source_diversity = min(len(metrics["domains_shared"]), 10) * 3

            influence_score = round(
                (min(total_activity, 100) * 0.3) +
                (min(avg_score, 100) * 0.4) +
                cross_platform_bonus +
                source_diversity,
                2
            )

            rankings.append({
                "username": user,
                "influence_score": influence_score,
                "platforms": list(metrics["platforms"]),
                "total_activity": total_activity,
                "avg_score_per_item": round(avg_score, 1),
                "sources_shared": len(metrics["domains_shared"])
            })

        rankings.sort(key=lambda r: -r["influence_score"])
        return rankings[:top_n]

    def export_rankings(self, rankings, output_file="influencer_rankings.json"):
        """Export ranked influencer data."""
        with open(output_file, "w") as f:
            json.dump(rankings, f, indent=2)
        return rankings
```

## OPSEC Notes

- **Rate limiting**: Reddit limits to 60 requests/minute; HN Algolia has no documented limit but be respectful
- **User-Agent**: Always send a descriptive User-Agent header on Reddit
- **Account linkage**: Be careful not to reveal your research interest through your own search/view patterns
- **Data freshness**: Reddit posts can be edited or deleted; capture evidence when found
- **API rotation**: Use multiple API keys or fall back to scraping if rate-limited
- **Fingerprint resistance**: Vary request timing and patterns to avoid bot detection
- **Data retention**: Store extracted data securely and comply with retention policies

## Introduction

This guide covers social intelligence gathering techniques for authorized security research and OSINT operations.

## References

- OWASP Testing Guide — https://owasp.org/www-project-web-security-testing-guide/
- OSINT Framework — https://osintframework.com/

## Hands-on Exercises

Practice these techniques against public data sources and authorized targets. Always respect privacy laws and terms of service.
