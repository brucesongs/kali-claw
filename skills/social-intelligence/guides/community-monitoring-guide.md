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

## References

- PRAW (Python Reddit API Wrapper): https://praw.readthedocs.io/
- Hacker News Algolia API: https://hn.algolia.com/api
- snscrape: https://github.com/JustAnotherArchivist/snscrape
- NLTK Sentiment Analysis: https://www.nltk.org/
- SANS OSINT Framework: https://osintframework.com/
