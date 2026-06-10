# Online Community Monitoring Guide

## Introduction

Online community monitoring enables security professionals to detect emerging threats, track targeted keywords across platforms, identify trend shifts, and perform sentiment analysis on discussions relevant to a target organization or topic. This guide covers setting up automated monitoring for Reddit, Hacker News, and X (formerly Twitter), building keyword alerting pipelines, detecting trending topics, and performing basic sentiment analysis.

Effective community monitoring transforms the noise of social media into actionable intelligence. Security teams use it to detect data breach disclosures, track discussions about their organization, identify insider threats, and monitor adversarial communities for emerging attack techniques.

## Practical Steps

### 1. Reddit Monitoring Setup

Monitor Reddit for keywords and track targeted subreddits:

```python
#!/usr/bin/env python3
"""Reddit community monitoring script"""
import praw
import json
import time
from datetime import datetime

reddit = praw.Reddit(
    client_id="YOUR_CLIENT_ID",
    client_secret="YOUR_CLIENT_SECRET",
    user_agent="security-monitor/1.0"
)

KEYWORDS = ["data breach", "vulnerability", "exploit", "leaked", "0day"]
SUBREDDITS = ["netsec", "cybersecurity", "security", "hacking", "bugbounty"]

def monitor_reddit():
    """Monitor subreddits for keyword matches"""
    subreddit = reddit.subreddit("+".join(SUBREDDITS))

    for submission in subreddit.stream.submissions(skip_existing=True):
        text = f"{submission.title} {submission.selftext}".lower()
        matches = [kw for kw in KEYWORDS if kw in text]

        if matches:
            alert = {
                "timestamp": datetime.utcnow().isoformat(),
                "platform": "reddit",
                "title": submission.title,
                "url": f"https://reddit.com{submission.permalink}",
                "subreddit": submission.subreddit.display_name,
                "author": str(submission.author),
                "score": submission.score,
                "matched_keywords": matches,
                "created_utc": submission.created_utc
            }
            print(json.dumps(alert, indent=2))

            # Save to file
            with open("reddit_alerts.jsonl", "a") as f:
                f.write(json.dumps(alert) + "\n")

if __name__ == "__main__":
    print("[*] Starting Reddit monitor...")
    monitor_reddit()
```

### 2. Hacker News Monitoring

```python
#!/usr/bin/env python3
"""Hacker News monitoring via Algolia API"""
import requests
import json
import time
from datetime import datetime

HN_SEARCH_URL = "https://hn.algolia.com/api/v1/search"

KEYWORDS = ["security", "breach", "vulnerability", "CVE"]

def search_hn(query, tags="story"):
    """Search Hacker News for matching stories"""
    params = {
        "query": query,
        "tags": tags,
        "numericFilters": "created_at_i>{}"
            .format(int(time.time()) - 86400)  # Last 24 hours
    }
    response = requests.get(HN_SEARCH_URL, params=params)
    return response.json().get("hits", [])

def monitor_hn():
    """Monitor HN for security-related posts"""
    seen_ids = set()

    for keyword in KEYWORDS:
        results = search_hn(keyword)
        for hit in results:
            if hit["objectID"] not in seen_ids:
                seen_ids.add(hit["objectID"])
                alert = {
                    "timestamp": datetime.utcnow().isoformat(),
                    "platform": "hackernews",
                    "title": hit.get("title", ""),
                    "url": hit.get("url", ""),
                    "hn_link": f"https://news.ycombinator.com/item?id={hit['objectID']}",
                    "points": hit.get("points", 0),
                    "author": hit.get("author", ""),
                    "matched_keyword": keyword
                }
                print(json.dumps(alert, indent=2))

                with open("hn_alerts.jsonl", "a") as f:
                    f.write(json.dumps(alert) + "\n")

if __name__ == "__main__":
    print("[*] Monitoring Hacker News...")
    monitor_hn()
```

### 3. X (Twitter) Monitoring

```python
#!/usr/bin/env python3
"""X/Twitter monitoring using twscrape or snscrape"""
import subprocess
import json
from datetime import datetime

KEYWORDS = ["#bugbounty", "#infosec", "data breach"]
ACCOUNTS = ["@SwiftOnSecurity", "@thegrugq", "@malabororman"]

def monitor_x():
    """Monitor X for keywords using snscrape"""
    for keyword in KEYWORDS:
        cmd = [
            "snscrape", "--json", "--max-results", "50",
            "twitter-search", keyword
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            for line in result.stdout.strip().split("\n"):
                if line:
                    tweet = json.loads(line)
                    alert = {
                        "timestamp": datetime.utcnow().isoformat(),
                        "platform": "twitter",
                        "user": tweet.get("user", {}).get("username", ""),
                        "content": tweet.get("content", "")[:500],
                        "url": tweet.get("url", ""),
                        "likes": tweet.get("likeCount", 0),
                        "retweets": tweet.get("retweetCount", 0),
                        "keyword": keyword
                    }
                    with open("x_alerts.jsonl", "a") as f:
                        f.write(json.dumps(alert) + "\n")
        except Exception as e:
            print(f"Error monitoring {keyword}: {e}")

if __name__ == "__main__":
    print("[*] Monitoring X/Twitter...")
    monitor_x()
```

### 4. Keyword Alerting Pipeline

Combine all sources into a unified alerting system:

```python
#!/usr/bin/env python3
"""Unified alerting pipeline"""
import json
import smtplib
from email.mime.text import MIMEText

ALERT_THRESHOLD = 3  # Minimum keyword matches for high-priority alert
HIGH_PRIORITY_KEYWORDS = ["0day", "active exploit", "data breach", "ransomware"]

def process_alerts(alert_file="combined_alerts.jsonl"):
    """Process and prioritize alerts from all sources"""
    high_priority = []
    normal_priority = []

    with open(alert_file) as f:
        for line in f:
            alert = json.loads(line)
            is_high = any(kw in str(alert).lower()
                         for kw in HIGH_PRIORITY_KEYWORDS)

            if is_high:
                high_priority.append(alert)
            else:
                normal_priority.append(alert)

    print(f"High priority: {len(high_priority)} alerts")
    print(f"Normal priority: {len(normal_priority)} alerts")

    return high_priority, normal_priority

def send_alert_email(alerts, recipient="team@corp.com"):
    """Send high-priority alerts via email"""
    body = "\n\n".join(
        f"[{a.get('platform','?').upper()}] {a.get('title','')}\n{a.get('url','')}"
        for a in alerts
    )
    msg = MIMEText(body)
    msg["Subject"] = f"[Security Alert] {len(alerts)} high-priority items"
    msg["From"] = "monitor@corp.com"
    msg["To"] = recipient

    with smtplib.SMTP("smtp.corp.com", 587) as server:
        server.send_message(msg)
```

### 5. Sentiment Analysis

```python
#!/usr/bin/env python3
"""Basic sentiment analysis on collected alerts"""
from collections import Counter
import json
import re

NEGATIVE_WORDS = ["breach", "hack", "vulnerable", "exploit", "leak",
                  "compromised", "attack", "malware", "ransomware"]
POSITIVE_WORDS = ["patch", "secure", "fixed", "defense", "protect",
                  "mitigation", "update", "hardened"]

def analyze_sentiment(text):
    """Simple keyword-based sentiment scoring"""
    text_lower = text.lower()
    neg_count = sum(1 for w in NEGATIVE_WORDS if w in text_lower)
    pos_count = sum(1 for w in POSITIVE_WORDS if w in text_lower)

    if neg_count > pos_count:
        return "negative", neg_count - pos_count
    elif pos_count > neg_count:
        return "positive", pos_count - neg_count
    return "neutral", 0

def trend_detection(alert_file):
    """Detect trending topics across alerts"""
    word_freq = Counter()
    with open(alert_file) as f:
        for line in f:
            alert = json.loads(line)
            words = re.findall(r'\b[a-z]{4,}\b', str(alert).lower())
            word_freq.update(words)

    print("Trending terms (top 20):")
    for word, count in word_freq.most_common(20):
        print(f"  {word}: {count}")
```

### 6. Automated Community Monitoring Scripts

Deploy long-running monitoring agents that collect, filter, and archive community data on a schedule. This enables continuous intelligence collection without manual intervention.

```python
#!/usr/bin/env python3
"""Automated community monitoring daemon with scheduling and rotation."""
import json
import time
import signal
import logging
import os
from datetime import datetime, timedelta
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("monitor.log"),
        logging.StreamHandler()
    ]
)

class CommunityMonitor:
    """Base class for platform-specific monitors."""

    def __init__(self, output_dir="monitor_output"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.running = True
        self.seen_ids = set()
        self._load_state()

    def _load_state(self):
        state_file = self.output_dir / "state.json"
        if state_file.exists():
            with open(state_file) as f:
                state = json.load(f)
                self.seen_ids = set(state.get("seen_ids", []))
                logging.info("Loaded %d seen IDs from state", len(self.seen_ids))

    def _save_state(self):
        state_file = self.output_dir / "state.json"
        with open(state_file, "w") as f:
            json.dump({"seen_ids": list(self.seen_ids)[-10000:]}, f)

    def _write_alert(self, alert, platform):
        date_str = datetime.utcnow().strftime("%Y-%m-%d")
        alert_file = self.output_dir / f"{platform}_{date_str}.jsonl"
        with open(alert_file, "a") as f:
            f.write(json.dumps(alert) + "\n")

    def stop(self):
        self.running = False
        self._save_state()
        logging.info("Monitor stopped, state saved")

def run_scheduled_monitor(monitor_cls, interval_minutes=15):
    """Run a monitor on a fixed interval with graceful shutdown."""
    monitor = monitor_cls()

    def handle_signal(signum, frame):
        logging.info("Received signal %d, shutting down...", signum)
        monitor.stop()

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    logging.info("Starting monitor with %d minute interval", interval_minutes)
    while monitor.running:
        try:
            monitor.collect()
        except Exception as e:
            logging.error("Collection error: %s", e)
        time.sleep(interval_minutes * 60)
```

Configure monitoring intervals based on platform velocity:

| Platform | Recommended Interval | Rationale |
|----------|---------------------|-----------|
| Reddit (large subreddits) | 5-10 minutes | High post volume, fast-moving discussions |
| Hacker News | 15-30 minutes | Moderate volume, stories stay visible longer |
| X/Twitter | 5-15 minutes | Very high velocity, breaking news appears here first |
| Discord/Telegram | 1-5 minutes | Real-time chat, messages scroll off quickly |
| Forums (Slow) | 1-4 hours | Lower volume, slower response times |

### 7. Keyword Tracking and Alerting

Build a hierarchical keyword system with severity classification and deduplication to reduce noise and surface high-value intelligence.

```python
#!/usr/bin/env python3
"""Advanced keyword tracking with fuzzy matching and severity classification."""
import json
import re
from difflib import SequenceMatcher
from datetime import datetime

class KeywordTracker:
    """Multi-tier keyword tracking with alert prioritization."""

    CRITICAL_KEYWORDS = {
        "active_exploit": r"\bactive\s+exploit\b",
        "zero_day": r"\b0[\\-]?day\b|zero[\\s-]?day",
        "data_breach": r"\bdata\s+breach\b|\bbreach\s+of\b",
        "ransomware_attack": r"\bransomware\b",
        "credential_dump": r"\bcredential\s+(dump|leak|theft)\b",
    }

    HIGH_KEYWORDS = {
        "vulnerability": r"\bvulnerability\b|\bvuln\b",
        "cve_mention": r"\bCVE[- ]?\d{4}[- ]?\d{4,}\b",
        "exploit_poc": r"\b(exploit|poc|proof.of.concept)\b",
        "auth_bypass": r"\b(auth.*bypass|bypass.*auth)\b",
        "privilege_escalation": r"\bpriv(ilege)?\s?esc(alation)?\b",
    }

    MEDIUM_KEYWORDS = {
        "security_patch": r"\b(patch|security\s+update|hotfix)\b",
        "misconfiguration": r"\bmisconfig(ur(e|uration)?)?\b",
        "security_tool": r"\b(burp|nmap|metasploit|cobalt\s+strike)\b",
        "compliance": r"\b(PCI|HIPAA|SOC\s*2|GDPR|compliance)\b",
    }

    def __init__(self, custom_keywords=None):
        self.all_patterns = {}
        self.all_patterns.update({k: (re.compile(v, re.I), "CRITICAL")
                                  for k, v in self.CRITICAL_KEYWORDS.items()})
        self.all_patterns.update({k: (re.compile(v, re.I), "HIGH")
                                  for k, v in self.HIGH_KEYWORDS.items()})
        self.all_patterns.update({k: (re.compile(v, re.I), "MEDIUM")
                                  for k, v in self.MEDIUM_KEYWORDS.items()})
        if custom_keywords:
            for kw in custom_keywords:
                pattern = re.compile(r"\b" + re.escape(kw) + r"\b", re.I)
                self.all_patterns[f"custom_{kw}"] = (pattern, "CUSTOM")

    def analyze(self, text):
        """Analyze text against all keyword patterns and return matches."""
        matches = []
        for name, (pattern, severity) in self.all_patterns.items():
            found = pattern.findall(text)
            if found:
                matches.append({
                    "keyword": name,
                    "severity": severity,
                    "matched_text": found,
                    "count": len(found)
                })
        matches.sort(key=lambda m: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "CUSTOM": 3}.get(m["severity"], 4))
        return matches

    def should_alert(self, matches):
        """Determine if matches warrant an alert notification."""
        if any(m["severity"] == "CRITICAL" for m in matches):
            return "CRITICAL", True
        if sum(1 for m in matches if m["severity"] == "HIGH") >= 2:
            return "HIGH", True
        if len(matches) >= 3:
            return "MEDIUM", True
        return "LOW", False

# Webhook-based alerting (Slack, Teams, Discord, custom)
def send_webhook_alert(alert_data, webhook_url):
    """Send alert to a webhook endpoint."""
    import requests
    payload = {
        "text": f"[{alert_data['severity']}] {alert_data['title']}",
        "blocks": [
            {"type": "section", "text": {"type": "mrkdwn",
             "text": f"*Severity:* {alert_data['severity']}\n*Platform:* {alert_data['platform']}\n*URL:* {alert_data['url']}"}},
            {"type": "section", "text": {"type": "mrkdwn",
             "text": f"*Matches:* {', '.join(m['keyword'] for m in alert_data['matches'])}"}}
        ]
    }
    try:
        requests.post(webhook_url, json=payload, timeout=10)
    except requests.RequestException as e:
        print(f"Webhook delivery failed: {e}")
```

### 8. Influence Mapping

Identify key influencers, amplifiers, and information brokers within monitored communities. Influence mapping reveals who drives narratives and whose posts correlate with topic trends.

```python
#!/usr/bin/env python3
"""Influence mapping from community activity data."""
import json
from collections import defaultdict
from datetime import datetime

class InfluenceMapper:
    """Map influence patterns from collected community data."""

    def __init__(self):
        self.user_stats = defaultdict(lambda: {
            "posts": 0, "comments": 0, "upvotes_received": 0,
            "downvotes_received": 0, "replies_received": 0,
            "cross_references": 0, "first_seen": None, "last_seen": None,
            "subreddits": set(), "topics": set()
        })

    def ingest_alert(self, alert):
        """Process an alert into user statistics."""
        author = alert.get("author") or alert.get("user", "unknown")
        stats = self.user_stats[author]

        if alert.get("platform") == "reddit":
            if alert.get("type") == "submission":
                stats["posts"] += 1
            else:
                stats["comments"] += 1
            stats["upvotes_received"] += alert.get("score", 0)
            if "subreddit" in alert:
                stats["subreddits"].add(alert["subreddit"])

        if stats["first_seen"] is None:
            stats["first_seen"] = alert.get("timestamp")
        stats["last_seen"] = alert.get("timestamp")

    def calculate_influence_score(self, author):
        """Calculate a composite influence score for a user."""
        stats = self.user_stats[author]
        total_activity = stats["posts"] + stats["comments"]
        if total_activity == 0:
            return 0.0

        # Weighted scoring: engagement quality matters more than volume
        activity_score = min(total_activity / 50.0, 1.0) * 25
        engagement_score = min(stats["upvotes_received"] / 500.0, 1.0) * 35
        breadth_score = min(len(stats["subreddits"]) / 10.0, 1.0) * 20
        consistency_score = 20  # Based on first_seen to last_seen span

        return round(activity_score + engagement_score + breadth_score + consistency_score, 2)

    def rank_influencers(self, top_n=20):
        """Return the top N most influential users."""
        scores = [(author, self.calculate_influence_score(author))
                  for author in self.user_stats]
        scores.sort(key=lambda x: -x[1])
        return scores[:top_n]

    def export_influence_report(self, output_file="influence_report.json"):
        """Export ranked influence data for visualization."""
        ranked = self.rank_influencers()
        report = []
        for author, score in ranked:
            stats = self.user_stats[author]
            report.append({
                "author": author,
                "influence_score": score,
                "total_posts": stats["posts"],
                "total_comments": stats["comments"],
                "total_upvotes": stats["upvotes_received"],
                "communities": list(stats["subreddits"]),
                "activity_period": {
                    "first": stats["first_seen"],
                    "last": stats["last_seen"]
                }
            })
        with open(output_file, "w") as f:
            json.dump(report, f, indent=2)
        return report
```

### 9. Community Health Metrics

Track the overall health and activity patterns of monitored communities to establish baselines and detect anomalies.

```python
#!/usr/bin/env python3
"""Community health metrics and anomaly detection."""
import json
import statistics
from collections import Counter, defaultdict
from datetime import datetime, timedelta

class CommunityHealthMetrics:
    """Track and measure community health indicators."""

    def __init__(self):
        self.hourly_activity = defaultdict(int)
        self.daily_activity = defaultdict(int)
        self.user_activity = defaultdict(int)
        self.sentiment_scores = []
        self.topic_distribution = Counter()

    def record_activity(self, alert):
        """Record an alert for health metric calculation."""
        ts = alert.get("timestamp", "")
        if ts:
            hour_key = ts[:13]  # YYYY-MM-DDTHH
            day_key = ts[:10]   # YYYY-MM-DD
            self.hourly_activity[hour_key] += 1
            self.daily_activity[day_key] += 1

        author = alert.get("author") or alert.get("user", "unknown")
        self.user_activity[author] += 1

        for kw in alert.get("matched_keywords", []):
            self.topic_distribution[kw] += 1

    def get_activity_summary(self):
        """Calculate community activity statistics."""
        daily_counts = list(self.daily_activity.values())
        if not daily_counts:
            return {}

        return {
            "total_days_tracked": len(daily_counts),
            "avg_daily_posts": round(statistics.mean(daily_counts), 1),
            "median_daily_posts": statistics.median(daily_counts),
            "std_dev": round(statistics.stdev(daily_counts), 1) if len(daily_counts) > 1 else 0,
            "peak_day": max(self.daily_activity.items(), key=lambda x: x[1]),
            "total_unique_users": len(self.user_activity),
            "top_contributors": Counter(self.user_activity).most_common(10),
            "top_topics": self.topic_distribution.most_common(10)
        }

    def detect_anomalies(self, threshold_sigma=2.0):
        """Detect days with anomalous activity levels."""
        daily_counts = list(self.daily_activity.values())
        if len(daily_counts) < 7:
            return []

        mean = statistics.mean(daily_counts)
        stdev = statistics.stdev(daily_counts) if len(daily_counts) > 1 else 1

        anomalies = []
        for day, count in self.daily_activity.items():
            z_score = (count - mean) / stdev if stdev > 0 else 0
            if abs(z_score) >= threshold_sigma:
                anomalies.append({
                    "date": day,
                    "count": count,
                    "z_score": round(z_score, 2),
                    "direction": "spike" if z_score > 0 else "drop"
                })
        return sorted(anomalies, key=lambda a: -abs(a["z_score"]))

    def generate_report(self):
        """Generate a complete health metrics report."""
        summary = self.get_activity_summary()
        anomalies = self.detect_anomalies()
        return {
            "generated_at": datetime.utcnow().isoformat(),
            "summary": summary,
            "anomalies": anomalies,
            "health_score": self._calculate_health_score(summary)
        }

    def _calculate_health_score(self, summary):
        """Compute a 0-100 community health score."""
        if not summary:
            return 0
        active_users = summary.get("total_unique_users", 0)
        consistency = max(0, 100 - (summary.get("std_dev", 0) * 10))
        diversity = min(len(summary.get("top_topics", [])) * 10, 30)
        participation = min(active_users, 30)
        return min(int(consistency * 0.4 + diversity + participation), 100)
```

### 10. Detecting Coordinated Campaigns

Identify coordinated inauthentic behavior (CIB) patterns such as synchronized posting, shared narratives, bot networks, and astroturfing campaigns across monitored communities.

```python
#!/usr/bin/env python3
"""Coordinated campaign detection from community data."""
import json
from collections import defaultdict
from datetime import datetime, timedelta

class CoordinatedCampaignDetector:
    """Detect signs of coordinated inauthentic behavior."""

    def __init__(self, time_window_minutes=30, min_cluster_size=3):
        self.time_window = timedelta(minutes=time_window_minutes)
        self.min_cluster = min_cluster_size
        self.posts_by_topic = defaultdict(list)

    def ingest(self, alert):
        """Group posts by extracted topic keywords."""
        keywords = alert.get("matched_keywords", [])
        for kw in keywords:
            self.posts_by_topic[kw].append({
                "author": alert.get("author") or alert.get("user", ""),
                "timestamp": alert.get("timestamp", ""),
                "platform": alert.get("platform", ""),
                "text": alert.get("title", "") + " " + alert.get("content", ""),
                "url": alert.get("url", "")
            })

    def detect_temporal_clusters(self):
        """Find groups of posts on the same topic within a short time window."""
        campaigns = []
        for topic, posts in self.posts_by_topic.items():
            if len(posts) < self.min_cluster:
                continue

            # Sort by timestamp
            sorted_posts = sorted(posts, key=lambda p: p["timestamp"])
            for i, base_post in enumerate(sorted_posts):
                cluster = [base_post]
                base_time = datetime.fromisoformat(base_post["timestamp"].replace("Z", "+00:00"))
                for other in sorted_posts[i+1:]:
                    other_time = datetime.fromisoformat(other["timestamp"].replace("Z", "+00:00"))
                    if (other_time - base_time) <= self.time_window:
                        cluster.append(other)
                    else:
                        break

                if len(cluster) >= self.min_cluster:
                    unique_authors = len(set(p["author"] for p in cluster))
                    unique_platforms = len(set(p["platform"] for p in cluster))
                    campaigns.append({
                        "topic": topic,
                        "cluster_size": len(cluster),
                        "unique_authors": unique_authors,
                        "unique_platforms": unique_platforms,
                        "time_span": cluster[-1]["timestamp"],
                        "posts": cluster,
                        "coordination_score": round(
                            (len(cluster) / max(unique_authors, 1)) *
                            unique_platforms, 2
                        )
                    })

        campaigns.sort(key=lambda c: -c["coordination_score"])
        return campaigns

    def detect_account_similarity(self, min_overlap=0.6):
        """Find accounts with suspiciously similar posting patterns."""
        user_topics = defaultdict(set)
        for topic, posts in self.posts_by_topic.items():
            for post in posts:
                user_topics[post["author"]].add(topic)

        authors = list(user_topics.keys())
        similar_pairs = []
        for i in range(len(authors)):
            for j in range(i + 1, len(authors)):
                set_a = user_topics[authors[i]]
                set_b = user_topics[authors[j]]
                if not set_a or not set_b:
                    continue
                overlap = len(set_a & set_b) / len(set_a | set_b)
                if overlap >= min_overlap:
                    similar_pairs.append({
                        "account_a": authors[i],
                        "account_b": authors[j],
                        "topic_overlap": round(overlap, 3),
                        "shared_topics": list(set_a & set_b)
                    })

        similar_pairs.sort(key=lambda p: -p["topic_overlap"])
        return similar_pairs
```

### 11. Cross-Platform Monitoring Integration

Unify data from multiple platforms into a single normalized schema for cross-referencing and correlation analysis.

```python
#!/usr/bin/env python3
"""Cross-platform monitoring normalization and correlation."""
import json
from datetime import datetime
from pathlib import Path

class CrossPlatformNormalizer:
    """Normalize alerts from different platforms into a common schema."""

    def normalize_reddit(self, raw_alert):
        return {
            "platform": "reddit",
            "id": raw_alert.get("url", ""),
            "author": raw_alert.get("author", ""),
            "timestamp": raw_alert.get("timestamp", ""),
            "title": raw_alert.get("title", ""),
            "content": raw_alert.get("selftext", ""),
            "url": raw_alert.get("url", ""),
            "engagement": {
                "score": raw_alert.get("score", 0),
                "comments": raw_alert.get("num_comments", 0)
            },
            "tags": ["reddit", raw_alert.get("subreddit", "")]
        }

    def normalize_hackernews(self, raw_alert):
        return {
            "platform": "hackernews",
            "id": raw_alert.get("hn_link", ""),
            "author": raw_alert.get("author", ""),
            "timestamp": raw_alert.get("timestamp", ""),
            "title": raw_alert.get("title", ""),
            "content": raw_alert.get("text", ""),
            "url": raw_alert.get("url", raw_alert.get("hn_link", "")),
            "engagement": {
                "score": raw_alert.get("points", 0),
                "comments": raw_alert.get("num_comments", 0)
            },
            "tags": ["hackernews"]
        }

    def normalize_twitter(self, raw_alert):
        return {
            "platform": "twitter",
            "id": raw_alert.get("url", ""),
            "author": raw_alert.get("user", ""),
            "timestamp": raw_alert.get("timestamp", ""),
            "title": "",
            "content": raw_alert.get("content", ""),
            "url": raw_alert.get("url", ""),
            "engagement": {
                "score": raw_alert.get("likes", 0),
                "comments": raw_alert.get("retweets", 0)
            },
            "tags": ["twitter"]
        }

    def correlate_cross_platform(self, alerts, time_window_hours=24):
        """Find the same topic discussed across multiple platforms."""
        from collections import defaultdict
        topic_clusters = defaultdict(list)

        for alert in alerts:
            content = f"{alert.get('title', '')} {alert.get('content', '')}".lower()
            # Simple keyword-based clustering
            for keyword in ["breach", "vulnerability", "exploit", "ransomware"]:
                if keyword in content:
                    topic_clusters[keyword].append(alert)

        cross_platform_topics = []
        for topic, items in topic_clusters.items():
            platforms = set(item["platform"] for item in items)
            if len(platforms) >= 2:
                cross_platform_topics.append({
                    "topic": topic,
                    "platform_count": len(platforms),
                    "platforms": list(platforms),
                    "total_mentions": len(items),
                    "items": items
                })

        cross_platform_topics.sort(key=lambda t: -t["platform_count"])
        return cross_platform_topics

    def merge_alert_files(self, input_dir="monitor_output", output_file="merged_alerts.jsonl"):
        """Merge all platform-specific alert files into one normalized file."""
        input_path = Path(input_dir)
        normalized = []
        for alert_file in sorted(input_path.glob("*.jsonl")):
            with open(alert_file) as f:
                for line in f:
                    raw = json.loads(line)
                    platform = raw.get("platform", "")
                    normalizer = getattr(self, f"normalize_{platform}", None)
                    if normalizer:
                        normalized.append(normalizer(raw))
                    else:
                        normalized.append(raw)

        with open(output_file, "w") as f:
            for item in normalized:
                f.write(json.dumps(item) + "\n")
        return len(normalized)
```

## References

- PRAW (Python Reddit API Wrapper): https://praw.readthedocs.io/
- Hacker News Algolia API: https://hn.algolia.com/api
- snscrape: https://github.com/JustAnotherArchivist/snscrape
- NLTK Sentiment Analysis: https://www.nltk.org/
- SANS OSINT Framework: https://osintframework.com/
- Coordinated Inauthentic Behavior Detection: https://about.fb.com/news/2018/12/inside-feed-coordinated-inauthentic-behavior/
- Graphite Metrics: https://graphiteapp.org/
- Elasticsearch Alerting: https://www.elastic.co/guide/en/kibana/current/alerting.html

## Hands-on Exercises

Practice these techniques against public data sources and authorized targets. Always respect privacy laws and terms of service.
