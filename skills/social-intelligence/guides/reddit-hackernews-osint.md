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

## OPSEC Notes

- **Rate limiting**: Reddit limits to 60 requests/minute; HN Algolia has no documented limit but be respectful
- **User-Agent**: Always send a descriptive User-Agent header on Reddit
- **Account linkage**: Be careful not to reveal your research interest through your own search/view patterns
- **Data freshness**: Reddit posts can be edited or deleted; capture evidence when found
