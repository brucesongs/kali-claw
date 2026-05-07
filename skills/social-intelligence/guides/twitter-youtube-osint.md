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

## OPSEC Notes

- **X rate limiting**: API is heavily rate-limited; snscrape/Google Dorking may be more practical
- **YouTube view tracking**: Watching specific videos may signal research interest to creators with analytics
- **Account fingerprinting**: Use a dedicated research browser profile with VPN
- **Evidence preservation**: X posts and YouTube videos can be deleted; save evidence when found
- **Legal compliance**: Respect platform ToS; use official APIs where possible
