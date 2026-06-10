# Twitter/X & YouTube OSINT Guide

> Guide for the social-intelligence skill — covers X (Twitter) and YouTube intelligence gathering techniques.

## Twitter/X Intelligence

### Search Without API (Google Dorking)

X's native search has become restricted. Google Dorking remains the most reliable free method.

```
# Basic target search
site:twitter.com "<target-company>" security OR breach OR vulnerability
site:x.com "<target-company>" security OR hack

# Employee discovery
site:twitter.com "works at <target>" OR "engineer at <target>"
site:x.com "<target-company>" bio:security OR bio:engineer OR bio:devops

# Technology stack leaks
site:twitter.com from:<employee-handle> kubernetes OR docker OR AWS OR terraform
site:x.com "<target-company>" "we use" OR "migrating to" OR "deployed"

# Incident signals
site:twitter.com "<target-company>" down OR outage OR incident since:2026-04-01
```

### Advanced X Search Operators

```
# Recency filters
"<target>" since:2026-04-01 until:2026-05-06

# Engagement filters (high-impact posts)
"<target>" security min_retweets:10
"<target>" vulnerability min_faves:20

# Exclude noise
"<target>" security -is:retweet -filter:replies
"<target>" -"customer service" -"support" security

# Media and links
"<target>" security filter:links    — posts with URLs
"<target>" security filter:media    — posts with images/video

# From specific security researchers
from:SwiftOnSecurity "<target-technology>"
from:taviso "<target-technology>"
from:thegrugq "<target-company>"
```

### X API v2 (Requires Developer Account)

```bash
# Recent tweet search (Basic tier: 10,000 tweets/month)
curl -s "https://api.twitter.com/2/tweets/search/recent" \
  -G -d "query=<target-company>%20security%20-is:retweet" \
  -d "max_results=100" \
  -d "tweet.fields=created_at,public_metrics,author_id,entities" \
  -H "Authorization: Bearer $TWITTER_BEARER_TOKEN" \
  | jq '.data[] | {text: .text[:200], created_at, metrics: .public_metrics}'

# Get user details from author_id
curl -s "https://api.twitter.com/2/users/<author_id>" \
  -d "user.fields=name,username,description,location,public_metrics" \
  -H "Authorization: Bearer $TWITTER_BEARER_TOKEN"

# User timeline (get employee's recent posts)
curl -s "https://api.twitter.com/2/users/<user_id>/tweets" \
  -G -d "max_results=100" \
  -d "tweet.fields=created_at,public_metrics" \
  -H "Authorization: Bearer $TWITTER_BEARER_TOKEN"
```

### Alternative Tools (No API Required)

```bash
# snscrape — scrapes X without API
snscrape --jsonl twitter-search "<target-company> security since:2026-04-01" | head -50 \
  | jq '{date: .date, content: .rawContent[:200], username: .user.username, likes: .likeCount}'

# Twint (if still functional)
twint -s "<target-company> security" --since 2026-04-01 -o target_tweets.json --json
```

### Security Researcher Accounts to Monitor

```
# High-value security researchers on X
@SwiftOnSecurity — Security awareness, enterprise security
@taviso — Google Project Zero vulnerability research
@thegrugq — OPSEC, APT analysis
@malaborodog — Malware analysis
@hasaborobot — Bug bounty and web security
@_JohnHammond — Security education, CTF
@GossiTheDog — Threat intel, enterprise security
@campuscodi — Security news aggregation
```

---

## YouTube Intelligence

### Video Search Strategies

```bash
# Search for security talks about target technology
yt-dlp --flat-playlist "ytsearch20:<technology> vulnerability exploit" \
  --print "%(title)s | %(upload_date)s | %(view_count)s | %(url)s"

# Search for company-related conference talks
yt-dlp --flat-playlist "ytsearch10:<company-name> security defcon blackhat" \
  --print "%(title)s | %(channel)s | %(url)s"

# Search specific channels
yt-dlp --flat-playlist "ytsearch10:site:youtube.com/@ippsec <technology>" \
  --print "%(title)s | %(url)s"
```

### Transcript Extraction & Analysis

```bash
# Download auto-generated subtitles (English)
yt-dlp --write-auto-sub --sub-lang en --skip-download \
  -o "%(title)s.%(ext)s" "<video-url>"

# Download manual subtitles (higher quality, if available)
yt-dlp --write-sub --sub-lang en --skip-download \
  -o "%(title)s.%(ext)s" "<video-url>"

# Convert VTT to plain text
sed -e '/^$/d' -e '/^[0-9]/d' -e 's/<[^>]*>//g' transcript.en.vtt \
  | sort -u > transcript_clean.txt

# Extract security keywords from transcript
grep -iE 'vulnerability|exploit|bypass|CVE|patch|credential|password|injection|XSS|SSRF|RCE|privilege.escalation|misconfiguration' \
  transcript_clean.txt | sort -u
```

### Batch Transcript Intelligence

```bash
# Search, download transcripts, and extract intelligence in one pipeline
search_and_extract() {
  local query="$1"
  local output_dir="transcripts_$(echo $query | tr ' ' '_')"
  mkdir -p "$output_dir"

  # Get video URLs
  yt-dlp --flat-playlist "ytsearch10:$query" --print url > "$output_dir/urls.txt"

  # Download transcripts
  while read url; do
    yt-dlp --write-auto-sub --sub-lang en --skip-download \
      -o "$output_dir/%(id)s" "$url" 2>/dev/null
  done < "$output_dir/urls.txt"

  # Extract security-relevant lines from all transcripts
  grep -ihE 'vulnerability|exploit|bypass|CVE|attack|compromise|credential' \
    "$output_dir"/*.vtt 2>/dev/null | sort -u > "$output_dir/security_mentions.txt"

  echo "Results in $output_dir/security_mentions.txt"
}

search_and_extract "<target-technology> security"
```

### High-Value YouTube Channels for Security OSINT

| Channel | Content Type |
|---------|-------------|
| **IppSec** | HTB walkthroughs, penetration testing techniques |
| **John Hammond** | CTF solutions, security tools, malware analysis |
| **LiveOverflow** | Binary exploitation, web hacking, security research |
| **STÖK** | Bug bounty, web security, recon techniques |
| **NetworkChuck** | Networking, security fundamentals |
| **Black Hat** | Conference talks (official) |
| **DEF CON** | Conference talks (official) |
| **BSides** | Regional security conference talks |
| **The Cyber Mentor** | Ethical hacking courses and techniques |

### YouTube Intelligence Patterns

| Signal | What It Reveals |
|--------|----------------|
| Employee presenting at a conference | Architecture details, technology choices, security challenges |
| Tutorial using company's product | Attack surface knowledge, common misconfigurations |
| PoC demonstration video | Exploit details not yet in written advisories |
| "How I hacked..." videos | Attack methodology, tool chains, bypass techniques |
| Product review by security channel | Independent security assessment |

---

## Combined X + YouTube Workflow

### Vulnerability Intelligence Pipeline

```bash
# Step 1: Search X for initial signal
# "new CVE in <technology>" OR "<technology> vulnerability" since:2026-04-01

# Step 2: Find related YouTube content
yt-dlp --flat-playlist "ytsearch5:<CVE-ID> OR <technology> exploit" \
  --print "%(title)s | %(url)s"

# Step 3: Extract transcripts from relevant videos
# Transcripts often contain more technical detail than X posts

# Step 4: Cross-reference with HN/Reddit discussions
# Build a comprehensive picture from all social sources

# Step 5: Feed into deep-research for authoritative confirmation
```

### Twitter API Advanced Queries

The X API v2 supports complex boolean queries that enable precise intelligence extraction far beyond simple keyword search.

```bash
# Boolean operators for precision targeting
# AND, OR, NOT (represented as space, OR, -)
curl -s "https://api.twitter.com/2/tweets/search/recent" \
  -G -d "query=<company> (password OR credential OR \"data breach\") -is:retweet" \
  -d "tweet.fields=created_at,public_metrics,author_id,geo,entities" \
  -d "user.fields=location,verified,public_metrics,description" \
  -d "expansions=author_id,referenced_tweets.id" \
  -d "max_results=100" \
  -H "Authorization: Bearer $TWITTER_BEARER_TOKEN" \
  | jq '.data[] | {text: .text[:300], metrics: .public_metrics, created_at}'

# Conversation threading analysis (trace full discussion)
curl -s "https://api.twitter.com/2/tweets/search/recent" \
  -G -d "query=conversation_id:<thread_id>" \
  -d "tweet.fields=created_at,public_metrics,author_id,in_reply_to_user_id,referenced_tweets" \
  -d "max_results=100" \
  -H "Authorization: Bearer $TWITTER_BEARER_TOKEN"

# Geo-tagged tweet search (discover employees near offices)
curl -s "https://api.twitter.com/2/tweets/search/recent" \
  -G -d "query=<company> has:geo" \
  -d "tweet.fields=geo,created_at,author_id" \
  -d "max_results=100" \
  -H "Authorization: Bearer $TWITTER_BEARER_TOKEN"

# Retweet network extraction (find amplification patterns)
curl -s "https://api.twitter.com/2/tweets/<tweet_id>/retweets" \
  -d "user.fields=username,public_metrics,description,location" \
  -d "max_results=100" \
  -H "Authorization: Bearer $TWITTER_BEARER_TOKEN" \
  | jq '.data[].username'
```

### YouTube Metadata Analysis

Extract and analyze rich metadata from YouTube videos and channels to identify employees, technology stacks, and organizational patterns.

```python
#!/usr/bin/env python3
"""YouTube metadata analysis for OSINT intelligence."""
import json
import requests
from datetime import datetime
from collections import Counter, defaultdict

class YouTubeMetadataAnalyzer:
    """Analyze YouTube video and channel metadata."""

    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://www.googleapis.com/youtube/v3"

    def search_videos(self, query, max_results=50):
        """Search YouTube videos with full metadata."""
        params = {
            "part": "snippet,contentDetails,statistics",
            "q": query,
            "type": "video",
            "maxResults": min(max_results, 50),
            "key": self.api_key
        }
        response = requests.get(f"{self.base_url}/search", params=params)
        items = response.json().get("items", [])

        videos = []
        for item in items:
            video_id = item["id"].get("videoId", "")
            if not video_id:
                continue

            # Get detailed statistics
            stats_params = {
                "part": "statistics,contentDetails",
                "id": video_id,
                "key": self.api_key
            }
            stats_resp = requests.get(f"{self.base_url}/videos", params=stats_params)
            stats_items = stats_resp.json().get("items", [])
            stats = stats_items[0] if stats_items else {}

            video = {
                "video_id": video_id,
                "title": item["snippet"]["title"],
                "description": item["snippet"]["description"][:2000],
                "channel": item["snippet"]["channelTitle"],
                "channel_id": item["snippet"]["channelId"],
                "published_at": item["snippet"]["publishedAt"],
                "tags": item["snippet"].get("tags", []),
                "url": f"https://youtube.com/watch?v={video_id}",
                "statistics": stats.get("statistics", {}),
                "duration": stats.get("contentDetails", {}).get("duration", ""),
                "thumbnail": item["snippet"]["thumbnails"].get("high", {}).get("url", "")
            }
            videos.append(video)

        return videos

    def analyze_channel(self, channel_id):
        """Perform deep analysis of a YouTube channel."""
        params = {
            "part": "snippet,statistics,brandingSettings",
            "id": channel_id,
            "key": self.api_key
        }
        response = requests.get(f"{self.base_url}/channels", params=params)
        channel = response.json().get("items", [{}])[0]

        # Get recent uploads
        uploads_id = channel.get("contentDetails", {}).get("relatedPlaylists", {}).get("uploads", "")
        recent_videos = []
        if uploads_id:
            playlist_params = {
                "part": "snippet,contentDetails",
                "playlistId": uploads_id,
                "maxResults": 50,
                "key": self.api_key
            }
            pl_resp = requests.get(f"{self.base_url}/playlistItems", params=playlist_params)
            recent_videos = pl_resp.json().get("items", [])

        return {
            "channel_name": channel.get("snippet", {}).get("title", ""),
            "description": channel.get("snippet", {}).get("description", ""),
            "published_at": channel.get("snippet", {}).get("publishedAt", ""),
            "country": channel.get("snippet", {}).get("country", ""),
            "subscriber_count": channel.get("statistics", {}).get("subscriberCount", "0"),
            "video_count": channel.get("statistics", {}).get("videoCount", "0"),
            "view_count": channel.get("statistics", {}).get("viewCount", "0"),
            "keywords": channel.get("brandingSettings", {}).get("channel", {}).get("keywords", ""),
            "recent_upload_count": len(recent_videos),
            "custom_url": channel.get("snippet", {}).get("customUrl", "")
        }

    def extract_description_intelligence(self, videos):
        """Extract intelligence signals from video descriptions."""
        findings = {
            "urls": Counter(),
            "emails": [],
            "social_handles": defaultdict(list),
            "technology_mentions": Counter(),
            "employee_names": []
        }

        import re
        for video in videos:
            desc = video.get("description", "")

            # URLs
            urls = re.findall(r'https?://[^\s<>"]+', desc)
            findings["urls"].update(urls)

            # Email addresses
            emails = re.findall(r'[\w.+-]+@[\w-]+\.[\w.]+', desc)
            findings["emails"].extend(emails)

            # Social media handles
            twitter = re.findall(r'@(\w{3,15})', desc)
            for handle in twitter:
                findings["social_handles"]["twitter"].append(handle)

            github = re.findall(r'github\.com/([\w-]+)', desc)
            for user in github:
                findings["social_handles"]["github"].append(user)

        return findings
```

### Video Content Analysis Techniques

Go beyond metadata to analyze the actual content of YouTube videos for visual intelligence such as screen contents, whiteboards, badge photos, and building interiors.

```python
#!/usr/bin/env python3
"""Video content analysis techniques for OSINT."""
import json
import subprocess
from pathlib import Path
from datetime import datetime

class VideoContentAnalyzer:
    """Analyze video content for visual intelligence."""

    def extract_keyframes(self, video_url, interval_seconds=30, output_dir="keyframes"):
        """Extract keyframes from a video at regular intervals."""
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        cmd = [
            "yt-dlp", "--skip-download",
            "--write-thumbnail", "-o", f"{out_path}/thumb_%(id)s",
            video_url
        ]
        subprocess.run(cmd, capture_output=True)

        # Download video for frame extraction
        video_file = out_path / "temp_video.mp4"
        subprocess.run([
            "yt-dlp", "-f", "worst[ext=mp4]",
            "-o", str(video_file), video_url
        ], capture_output=True)

        if not video_file.exists():
            return {"error": "Failed to download video"}

        # Extract frames at interval
        subprocess.run([
            "ffmpeg", "-i", str(video_file),
            "-vf", f"fps=1/{interval_seconds}",
            "-q:v", "2",
            str(out_path / "frame_%04d.jpg")
        ], capture_output=True)

        frames = sorted(out_path.glob("frame_*.jpg"))
        return {
            "video_url": video_url,
            "frames_extracted": len(frames),
            "frame_paths": [str(f) for f in frames],
            "interval_seconds": interval_seconds
        }

    def analyze_screenshots_in_video(self, keyframe_dir):
        """Identify frames that contain computer screens or displays.
        Requires OCR tool (tesseract) for text extraction."""
        keyframe_path = Path(keyframe_dir)
        results = []

        for frame_file in sorted(keyframe_path.glob("frame_*.jpg")):
            # Use tesseract for OCR on each frame
            try:
                ocr_result = subprocess.run(
                    ["tesseract", str(frame_file), "stdout", "-l", "eng"],
                    capture_output=True, text=True, timeout=30
                )
                text = ocr_result.stdout.strip()
                if text:
                    # Look for security-relevant content
                    security_terms = [
                        "password", "admin", "login", "token", "key",
                        "secret", "credential", "api_key", "vpn", "ssh",
                        "firewall", "internal", "staging", "production"
                    ]
                    found_terms = [t for t in security_terms if t.lower() in text.lower()]
                    if found_terms:
                        results.append({
                            "frame": str(frame_file),
                            "text_length": len(text),
                            "security_terms_found": found_terms,
                            "ocr_text_preview": text[:500]
                        })
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

        return results

    def batch_video_analysis(self, video_urls, output_dir="video_analysis"):
        """Analyze multiple videos and aggregate findings."""
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        all_results = []
        for url in video_urls:
            keyframes = self.extract_keyframes(url, output_dir=str(out_path / "keyframes"))
            if "error" not in keyframes:
                screenshot_analysis = self.analyze_screenshots_in_video(
                    str(out_path / "keyframes")
                )
                all_results.append({
                    "url": url,
                    "keyframes": keyframes["frames_extracted"],
                    "screenshots_with_content": len(screenshot_analysis),
                    "findings": screenshot_analysis
                })

        report = {
            "analyzed_at": datetime.utcnow().isoformat(),
            "total_videos": len(video_urls),
            "total_findings": sum(r["screenshots_with_content"] for r in all_results),
            "results": all_results
        }

        with open(out_path / "analysis_report.json", "w") as f:
            json.dump(report, f, indent=2)
        return report
```

### Account Age and Authenticity Verification

Assess whether social media accounts are genuine, established, and trustworthy intelligence sources rather than recently created burner accounts or impersonators.

```python
#!/usr/bin/env python3
"""Account age and authenticity verification."""
import json
import requests
from datetime import datetime
from collections import Counter

class AccountAuthenticityVerifier:
    """Verify social media account authenticity and age."""

    def verify_twitter_account(self, username, bearer_token):
        """Assess Twitter/X account authenticity."""
        headers = {"Authorization": f"Bearer {bearer_token}"}

        # Get user details
        user_resp = requests.get(
            f"https://api.twitter.com/2/users/by/username/{username}",
            params={"user.fields": "created_at,public_metrics,verified,description,location,url,entities"},
            headers=headers
        )
        user = user_resp.json().get("data", {})

        if not user:
            return {"error": "Account not found"}

        created_at = datetime.strptime(user.get("created_at", ""), "%Y-%m-%dT%H:%M:%S.%fZ")
        age_days = (datetime.utcnow() - created_at).days
        metrics = user.get("public_metrics", {})

        # Authenticity scoring heuristics
        score = 0
        signals = []

        # Account age
        if age_days > 365 * 3:
            score += 30
            signals.append(f"Account is {age_days // 365} years old (established)")
        elif age_days > 365:
            score += 15
            signals.append(f"Account is {age_days // 30} months old (moderate)")
        else:
            signals.append(f"Account is only {age_days} days old (suspicious)")

        # Follower/following ratio
        followers = metrics.get("followers_count", 0)
        following = metrics.get("following_count", 1)
        ratio = followers / max(following, 1)
        if ratio > 2:
            score += 20
            signals.append(f"Good follower ratio: {ratio:.1f}")
        elif ratio < 0.1 and following > 500:
            signals.append(f"Low follower ratio: {ratio:.2f} (follows many, few followers)")

        # Tweet count
        tweets = metrics.get("tweet_count", 0)
        if tweets > 1000:
            score += 15
            signals.append(f"High tweet count: {tweets} (active history)")
        elif tweets < 10:
            signals.append(f"Very few tweets: {tweets} (potentially inactive or new)")

        # Bio completeness
        if user.get("description"):
            score += 10
            signals.append("Has profile description")
        if user.get("location"):
            score += 5
            signals.append(f"Location: {user['location']}")
        if user.get("verified"):
            score += 20
            signals.append("Account is verified")

        authenticity = "HIGH" if score >= 70 else "MEDIUM" if score >= 40 else "LOW"

        return {
            "username": username,
            "created_at": user.get("created_at"),
            "age_days": age_days,
            "metrics": metrics,
            "authenticity_score": score,
            "authenticity_level": authenticity,
            "signals": signals,
            "recommendation": (
                "Trusted source" if authenticity == "HIGH" else
                "Verify with additional sources" if authenticity == "MEDIUM" else
                "Do not rely on this account alone"
            )
        }

    def verify_youtube_channel(self, channel_url, api_key):
        """Assess YouTube channel authenticity."""
        # Extract channel identifier from URL
        import re
        handle_match = re.search(r'@([\w-]+)', channel_url)
        if not handle_match:
            return {"error": "Could not parse channel handle"}

        base_url = "https://www.googleapis.com/youtube/v3"

        # Search for channel
        search_resp = requests.get(f"{base_url}/search", params={
            "part": "snippet", "q": handle_match.group(1),
            "type": "channel", "maxResults": 5, "key": api_key
        })
        channels = search_resp.json().get("items", [])
        if not channels:
            return {"error": "Channel not found"}

        channel_id = channels[0]["snippet"]["channelId"]

        # Get channel details
        channel_resp = requests.get(f"{base_url}/channels", params={
            "part": "snippet,statistics", "id": channel_id, "key": api_key
        })
        channel = channel_resp.json().get("items", [{}])[0]

        stats = channel.get("statistics", {})
        snippet = channel.get("snippet", {})

        created = snippet.get("publishedAt", "")
        subscribers = int(stats.get("subscriberCount", 0))
        videos = int(stats.get("videoCount", 0))
        views = int(stats.get("viewCount", 0))

        signals = []
        score = 0

        if created:
            created_dt = datetime.strptime(created, "%Y-%m-%dT%H:%M:%SZ")
            age_days = (datetime.utcnow() - created_dt).days
            if age_days > 365 * 2:
                score += 25
                signals.append(f"Channel is {age_days // 365} years old")
            else:
                signals.append(f"Channel is only {age_days // 30} months old")

        if subscribers > 10000:
            score += 25
            signals.append(f"Large subscriber base: {subscribers}")
        elif subscribers > 1000:
            score += 15
            signals.append(f"Moderate subscriber base: {subscribers}")

        if videos > 50:
            score += 20
            signals.append(f"Extensive content library: {videos} videos")
        elif videos < 5:
            signals.append(f"Very few videos: {videos}")

        avg_views = views / max(videos, 1)
        if avg_views > 1000:
            score += 15
            signals.append(f"Good average views: {int(avg_views)}")

        authenticity = "HIGH" if score >= 60 else "MEDIUM" if score >= 30 else "LOW"

        return {
            "channel_name": snippet.get("title", ""),
            "channel_id": channel_id,
            "created_at": created,
            "subscribers": subscribers,
            "videos": videos,
            "total_views": views,
            "authenticity_score": score,
            "authenticity_level": authenticity,
            "signals": signals
        }
```

### Bot Detection Methodology

Identify automated or coordinated inauthentic accounts that may distort intelligence or disseminate disinformation.

```python
#!/usr/bin/env python3
"""Bot detection methodology for social media accounts."""
import json
import requests
from datetime import datetime
from collections import Counter

class BotDetector:
    """Detect bot-like behavior patterns in social media accounts."""

    def __init__(self):
        self.indicators = {
            "temporal": [],    # Posting frequency patterns
            "content": [],    # Content repetition or automation signals
            "network": [],    # Follower/following anomalies
            "profile": []     # Profile completeness signals
        }

    def analyze_temporal_patterns(self, tweets):
        """Detect temporal patterns consistent with automation."""
        if not tweets:
            return {"error": "No tweets provided"}

        timestamps = []
        for tweet in tweets:
            ts_str = tweet.get("created_at", "")
            if ts_str:
                try:
                    ts = datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%S.%fZ")
                except ValueError:
                    ts = datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%SZ")
                timestamps.append(ts)

        if len(timestamps) < 5:
            return {"error": "Insufficient data for temporal analysis"}

        # Calculate inter-post intervals in seconds
        timestamps.sort()
        intervals = []
        for i in range(1, len(timestamps)):
            delta = (timestamps[i] - timestamps[i-1]).total_seconds()
            intervals.append(delta)

        bot_signals = []
        bot_score = 0

        # Check for suspiciously regular posting intervals
        if intervals:
            import statistics
            avg_interval = statistics.mean(intervals)
            stdev_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0

            # Coefficient of variation (low = too regular for a human)
            cv = stdev_interval / max(avg_interval, 1)
            if cv < 0.1 and len(intervals) > 10:
                bot_signals.append(f"Very regular posting intervals (CV: {cv:.3f})")
                bot_score += 30
            elif cv < 0.3 and len(intervals) > 10:
                bot_signals.append(f"Somewhat regular posting intervals (CV: {cv:.3f})")
                bot_score += 15

        # Check for posting at identical times across days
        hour_counts = Counter(ts.hour for ts in timestamps)
        minute_counts = Counter((ts.hour, ts.minute) for ts in timestamps)
        repeated_times = sum(1 for count in minute_counts.values() if count > 2)
        if repeated_times > 5:
            bot_signals.append(f"Posts at {repeated_times} identical hour:minute combinations")
            bot_score += 20

        # Check for 24/7 activity (humans sleep)
        active_hours = len(hour_counts)
        if active_hours >= 23 and len(timestamps) > 50:
            bot_signals.append(f"Active in {active_hours}/24 hours (no sleep pattern)")
            bot_score += 25

        return {
            "total_tweets_analyzed": len(tweets),
            "bot_score": bot_score,
            "bot_probability": "HIGH" if bot_score >= 50 else "MEDIUM" if bot_score >= 25 else "LOW",
            "signals": bot_signals,
            "posting_hours_distribution": dict(sorted(hour_counts.items()))
        }

    def analyze_content_patterns(self, tweets):
        """Detect content patterns consistent with bots."""
        bot_signals = []
        bot_score = 0

        # Check for identical or near-identical posts
        text_list = [t.get("text", t.get("content", "")) for t in tweets]
        text_counter = Counter(text_list)
        duplicates = {text: count for text, count in text_counter.items() if count > 1}
        if len(duplicates) > 3:
            bot_signals.append(f"{len(duplicates)} duplicated posts found")
            bot_score += 20

        # Check for excessive URL sharing
        url_count = sum(1 for text in text_list if "http" in text)
        url_ratio = url_count / max(len(text_list), 1)
        if url_ratio > 0.9:
            bot_signals.append(f"URL in {url_ratio:.0%} of posts (very high)")
            bot_score += 15

        # Check for hashtag flooding
        import re
        hashtag_counts = [len(re.findall(r'#\w+', text)) for text in text_list]
        avg_hashtags = sum(hashtag_counts) / max(len(hashtag_counts), 1)
        if avg_hashtags > 5:
            bot_signals.append(f"Average {avg_hashtags:.1f} hashtags per post")
            bot_score += 15

        # Check for link shortener usage
        shorteners = sum(1 for text in text_list
                        if any(s in text for s in ["bit.ly", "t.co", "goo.gl", "ow.ly"]))
        if shorteners > len(text_list) * 0.5:
            bot_signals.append(f"Heavy use of URL shorteners: {shorteners} posts")
            bot_score += 10

        return {
            "bot_score": bot_score,
            "bot_probability": "HIGH" if bot_score >= 40 else "MEDIUM" if bot_score >= 20 else "LOW",
            "signals": bot_signals,
            "duplicate_post_count": len(duplicates),
            "url_ratio": round(url_ratio, 2),
            "avg_hashtags": round(avg_hashtags, 1)
        }
```

### Engagement Metrics Analysis

Analyze engagement patterns to distinguish genuine influence from artificial inflation and identify high-impact content.

```python
#!/usr/bin/env python3
"""Engagement metrics analysis for social media intelligence."""
import json
import statistics
from collections import Counter, defaultdict

class EngagementAnalyzer:
    """Analyze engagement patterns for authenticity and influence assessment."""

    def analyze_twitter_engagement(self, tweets):
        """Analyze engagement metrics across a collection of tweets."""
        metrics_list = []
        for tweet in tweets:
            m = tweet.get("public_metrics", {})
            metrics_list.append({
                "likes": m.get("like_count", 0),
                "retweets": m.get("retweet_count", 0),
                "replies": m.get("reply_count", 0),
                "quotes": m.get("quote_count", 0),
                "impressions": m.get("impression_count", 0)
            })

        if not metrics_list:
            return {"error": "No metrics available"}

        likes = [m["likes"] for m in metrics_list]
        retweets = [m["retweets"] for m in metrics_list]
        replies = [m["replies"] for m in metrics_list]

        analysis = {
            "total_tweets": len(metrics_list),
            "likes": {
                "total": sum(likes),
                "average": round(statistics.mean(likes), 1),
                "median": statistics.median(likes),
                "max": max(likes),
                "std_dev": round(statistics.stdev(likes), 1) if len(likes) > 1 else 0
            },
            "retweets": {
                "total": sum(retweets),
                "average": round(statistics.mean(retweets), 1),
                "median": statistics.median(retweets),
                "max": max(retweets)
            },
            "engagement_ratios": {
                "retweet_to_like": round(sum(retweets) / max(sum(likes), 1), 3),
                "reply_to_like": round(sum(replies) / max(sum(likes), 1), 3)
            }
        }

        # Anomaly detection: posts with abnormally high engagement
        if len(likes) > 5:
            avg = statistics.mean(likes)
            stdev = statistics.stdev(likes) if len(likes) > 1 else 1
            outliers = []
            for i, like_count in enumerate(likes):
                z_score = (like_count - avg) / max(stdev, 1)
                if z_score > 3:
                    outliers.append({
                        "index": i,
                        "likes": like_count,
                        "z_score": round(z_score, 2),
                        "note": "Abnormally high engagement - possible viral content or artificial inflation"
                    })
            analysis["engagement_outliers"] = outliers

        # Engagement authenticity assessment
        rtl_ratio = analysis["engagement_ratios"]["retweet_to_like"]
        if rtl_ratio > 0.8:
            analysis["authenticity_note"] = "Very high retweet-to-like ratio may indicate bot amplification"
        elif rtl_ratio < 0.05:
            analysis["authenticity_note"] = "Very low retweet-to-like ratio may indicate purchased likes"
        else:
            analysis["authenticity_note"] = "Engagement ratios within normal range"

        return analysis
```

### Media Forensics on User-Generated Content

Analyze images and videos posted by users for metadata, manipulation indicators, geolocation clues, and device fingerprinting.

```python
#!/usr/bin/env python3
"""Media forensics analysis for user-generated content."""
import json
import subprocess
from pathlib import Path
from datetime import datetime

class MediaForensicsAnalyzer:
    """Analyze images and videos for forensic intelligence."""

    def extract_exif_data(self, image_path):
        """Extract comprehensive EXIF metadata from images."""
        try:
            result = subprocess.run(
                ["exiftool", "-json", str(image_path)],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                exif_data = json.loads(result.stdout)[0]
                intelligence = {
                    "camera_make": exif_data.get("Make", ""),
                    "camera_model": exif_data.get("Model", ""),
                    "software": exif_data.get("Software", ""),
                    "create_date": exif_data.get("CreateDate", ""),
                    "gps_latitude": exif_data.get("GPSLatitude", ""),
                    "gps_longitude": exif_data.get("GPSLongitude", ""),
                    "gps_altitude": exif_data.get("GPSAltitude", ""),
                    "image_width": exif_data.get("ImageWidth", ""),
                    "image_height": exif_data.get("ImageHeight", ""),
                    "file_size": exif_data.get("FileSize", ""),
                    "mime_type": exif_data.get("MIMEType", ""),
                    "device_serial": exif_data.get("SerialNumber", "")
                }
                # Remove empty values
                return {k: v for k, v in intelligence.items() if v}
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
            pass
        return {"error": "exiftool not available or no EXIF data"}

    def detect_image_manipulation(self, image_path):
        """Detect signs of image manipulation or editing."""
        indicators = []

        try:
            # Check for editing software signatures in EXIF
            result = subprocess.run(
                ["exiftool", "-Software", "-CreatorTool", "-History",
                 "-LastModified", "-ModifyDate", "-json", str(image_path)],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)[0]
                software = data.get("Software", "")
                creator_tool = data.get("CreatorTool", "")

                editing_tools = ["Photoshop", "GIMP", "Paint.NET", "Affinity",
                                 "Lightroom", "Capture One", "Snapseed"]
                for tool in editing_tools:
                    if tool.lower() in (software + " " + creator_tool).lower():
                        indicators.append({
                            "type": "editing_software_detected",
                            "tool": tool,
                            "detail": f"Software: {software}, Creator: {creator_tool}"
                        })

                # Check for date mismatches (creation vs modification)
                create_date = data.get("CreateDate", "")
                modify_date = data.get("ModifyDate", "")
                if create_date and modify_date and create_date != modify_date:
                    indicators.append({
                        "type": "date_mismatch",
                        "create_date": create_date,
                        "modify_date": modify_date,
                        "note": "Image was modified after initial creation"
                    })

            # Error Level Analysis (ELA) using ImageMagick
            ela_path = Path(image_path).stem + "_ela.jpg"
            subprocess.run([
                "convert", str(image_path),
                "-quality", "90", "/tmp/ela_recompressed.jpg"
            ], capture_output=True)
            subprocess.run([
                "convert", str(image_path), "/tmp/ela_recompressed.jpg",
                "-compose", "difference", "-composite",
                "-normalize", ela_path
            ], capture_output=True)

            if Path(ela_path).exists():
                indicators.append({
                    "type": "ela_generated",
                    "path": ela_path,
                    "note": "Error Level Analysis image generated for visual inspection"
                })

        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
            pass

        return {
            "image": str(image_path),
            "manipulation_indicators": indicators,
            "suspicious": len(indicators) > 0
        }

    def analyze_video_metadata(self, video_path):
        """Extract and analyze video file metadata."""
        try:
            result = subprocess.run(
                ["ffprobe", "-v", "quiet", "-print_format", "json",
                 "-show_format", "-show_streams", str(video_path)],
                capture_output=True, text=True, timeout=30
            )
            data = json.loads(result.stdout)

            video_stream = next(
                (s for s in data.get("streams", []) if s.get("codec_type") == "video"),
                {}
            )
            audio_stream = next(
                (s for s in data.get("streams", []) if s.get("codec_type") == "audio"),
                {}
            )

            return {
                "duration_seconds": float(data.get("format", {}).get("duration", 0)),
                "format": data.get("format", {}).get("format_name", ""),
                "file_size": int(data.get("format", {}).get("size", 0)),
                "video_codec": video_stream.get("codec_name", ""),
                "resolution": f"{video_stream.get('width', '?')}x{video_stream.get('height', '?')}",
                "frame_rate": video_stream.get("r_frame_rate", ""),
                "audio_codec": audio_stream.get("codec_name", ""),
                "creation_time": video_stream.get("tags", {}).get("creation_time", ""),
                "encoder": video_stream.get("tags", {}).get("encoder", ""),
                "device_model": data.get("format", {}).get("tags", {}).get("model", ""),
                "location_gps": data.get("format", {}).get("tags", {}).get("location", "")
            }
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError, ValueError):
            return {"error": "ffprobe not available or could not parse video"}
```

## OPSEC Notes

- **X rate limiting**: API is heavily rate-limited; snscrape/Google Dorking may be more practical
- **YouTube view tracking**: Watching specific videos may signal research interest to creators with analytics
- **Account fingerprinting**: Use a dedicated research browser profile with VPN
- **Evidence preservation**: X posts and YouTube videos can be deleted; save evidence when found
- **Legal compliance**: Respect platform ToS; use official APIs where possible
- **API key management**: Store API keys in environment variables, never in source code
- **Download OPSEC**: Use yt-dlp with --no-cache to avoid local caching of viewed content
- **Thumbnail analysis**: YouTube thumbnails are tracked in analytics; use yt-dlp to download without viewing

## Introduction

This guide covers social intelligence gathering techniques for authorized security research and OSINT operations.

## References

- OWASP Testing Guide — https://owasp.org/www-project-web-security-testing-guide/
- OSINT Framework — https://osintframework.com/

## Hands-on Exercises

Practice these techniques against public data sources and authorized targets. Always respect privacy laws and terms of service.
