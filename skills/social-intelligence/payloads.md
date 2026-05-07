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
