# Skill: Social Intelligence

> **Supplementary Files**:
> - `payloads.md` — Platform-specific search queries for Reddit, HackerNews, Twitter/X, YouTube, forums, and paste sites organized by intelligence gathering scenario
> - `test-cases.md` — Structured test cases covering target profiling, technology leak discovery, vulnerability discussion tracking, sentiment analysis, and dark web monitoring

## Description

Real-time intelligence gathering from social platforms and community discussions — capturing what people are saying, sharing, and leaking right now. This skill transforms ephemeral social media activity, forum discussions, and community chatter into actionable security intelligence.

**Difference from `osint`**: OSINT focuses on structured passive data collection using specialized tools (Sherlock, SpiderFoot, theHarvester) against specific targets. Social intelligence focuses on unstructured community discourse — what real people are discussing, complaining about, and accidentally revealing on social platforms.

**Difference from `deep-research`**: Deep research synthesizes authoritative, published sources (NVD, vendor advisories, research papers) into depth-first reports. Social intelligence captures breadth-first social signals — trends, sentiment, leaked information, and community knowledge that hasn't been formally published.

**Combined value**: Social intelligence discovers signals ("employees are complaining about a new VPN on Reddit") that deep research then validates and enriches ("the VPN product has 3 unpatched CVEs").

## Use Cases

- **Pre-engagement target profiling**: Discover what target employees discuss on Reddit, HackerNews, and X — revealing tech stacks, security concerns, and organizational culture
- **Technology stack leak discovery**: Find developers mentioning internal tools, frameworks, and infrastructure in public forums and code discussions
- **Vulnerability discussion tracking**: Monitor security communities for discussions about new exploits, bypasses, and attack techniques before formal advisories
- **Pre-attack sentiment analysis**: Assess target organization's security posture through employee sentiment — complaints about security tools, password policies, or IT restrictions signal weak points
- **Dark web mention monitoring**: Track when target organizations, domains, or credentials appear in dark web forums and paste sites
- **Threat actor community tracking**: Monitor hacker forums and communities for discussions about specific targets or attack techniques
- **Security tool evaluation**: Gather real-world user feedback on security products from community discussions rather than vendor marketing

## Core Tools

### Search & Discovery

| Tool | Purpose | Command/Usage Example |
|------|---------|----------------------|
| **Brave Search API** | Privacy-respecting web search with API access | `curl "https://api.search.brave.com/res/v1/web/search?q=<query>" -H "X-Subscription-Token: $BRAVE_API_KEY"` |
| **Serper API** | Google Search API for programmatic access | `curl "https://google.serper.dev/search" -H "X-API-KEY: $SERPER_API_KEY" -d '{"q":"<query>"}'` |
| **Reddit API** | Subreddit search, user history, comment mining | `curl "https://oauth.reddit.com/r/<sub>/search?q=<query>&sort=new" -H "Authorization: Bearer $TOKEN"` |
| **HackerNews (Algolia)** | HN story and comment search | `curl "https://hn.algolia.com/api/v1/search?query=<keyword>&tags=story"` |

### Social Media OSINT

| Tool | Purpose | Command/Usage Example |
|------|---------|----------------------|
| **Sherlock** | Cross-platform username search | `sherlock <username> --json` |
| **yt-dlp** | YouTube video/transcript download | `yt-dlp --write-auto-sub --skip-download "<url>"` |
| **snscrape** | Social media scraping (X, Reddit, etc.) | `snscrape twitter-search "<query> since:2026-04-01"` |
| **Twint** | Twitter OSINT (no API needed) | `twint -s "<keyword>" --since 2026-04-01` |

### Content Processing

| Tool | Purpose | Command/Usage Example |
|------|---------|----------------------|
| **jq** | JSON processing for API responses | `curl <api> \| jq '.data[].title'` |
| **html2markdown** | HTML to readable text conversion | `curl -sL <url> \| html2markdown` |
| **yt-dlp** | YouTube subtitle extraction | `yt-dlp --write-auto-sub --sub-lang en --skip-download <url>` |

## Methodology

### Social Intelligence Five-Phase Process

```
Phase 1           Phase 2           Phase 3           Phase 4           Phase 5
Define Target  →  Select Platforms  →  Parallel Search  →  Normalize &    →  Cluster &
& Keywords        & Configure          & Collect           Deduplicate       Report
    │                 │                    │                   │                │
    ▼                 ▼                    ▼                   ▼                ▼
Target name,     Reddit, HN,          API calls per       Remove dupes,    Group by theme,
keywords,        X, YouTube,          (keyword, platform)  extract key      rank by relevance,
time window      forums, paste        combination          snippets         generate report
```

**Phase 1: Define Target & Keywords**

Identify what to search for and the time window.

```
Target: "Acme Corp" security posture
Keywords:
  - Primary: "Acme Corp", "acme.com", "AcmeTech"
  - Technical: "acme VPN", "acme security", "acme IT"
  - Personnel: known employee names, handles
  - Products: identified product/service names
Time window: last 30 days
```

**Phase 2: Select Platforms & Configure**

Choose platforms based on target characteristics.

| Target Type | Priority Platforms |
|-------------|-------------------|
| Tech company | HackerNews, Reddit (/r/programming, /r/sysadmin), GitHub, X |
| Enterprise | Reddit (/r/sysadmin, /r/networking), Glassdoor, LinkedIn |
| Security vendor | Reddit (/r/netsec), HN, X, security conference channels |
| Government | Reddit, X, specialized forums, FOIA databases |
| Financial | Reddit (/r/finance), X, Bloomberg Terminal (if available) |

**Phase 3: Parallel Search & Collect**

Execute searches across all selected platforms simultaneously.

```bash
# Parallel collection (conceptual)
# Agent 1: Reddit search across target subreddits
# Agent 2: HackerNews story + comment search
# Agent 3: X/Twitter keyword search
# Agent 4: YouTube video + transcript search
# Agent 5: General web search (Brave/Serper)
```

**Phase 4: Normalize & Deduplicate**

```
For each result:
  1. Extract: title, body/snippet, author, platform, date, URL, engagement metrics
  2. Normalize dates to UTC
  3. Deduplicate: same content cross-posted to multiple platforms
  4. Score relevance: keyword density + engagement + recency
  5. Extract key snippets: the most informative 2-3 sentences
```

**Phase 5: Cluster & Report**

Group findings by theme and generate a structured report.

```
Clusters:
  - "Technology stack mentions" (what tools/frameworks they use)
  - "Security complaints" (employee frustrations with security)
  - "Personnel information" (role, expertise, interests)
  - "Vulnerability discussions" (known issues being discussed)
  - "Organizational culture" (work environment signals)
```

### Defense Perspective

| Defense Measure | Description |
|-----------------|-------------|
| **Employee OPSEC training** | Train employees not to reveal internal details on social media |
| **Social media monitoring** | Monitor what employees post about the organization |
| **Username hygiene** | Discourage use of work-related usernames on personal platforms |
| **Information classification** | Clear policies on what can be discussed publicly |
| **Glassdoor/Reddit monitoring** | Track negative reviews and complaints for insider threat indicators |

## Practical Steps

> **Detailed payloads in `payloads.md`, complete test checklist in `test-cases.md`.**

### Exercise 1: Reddit Intelligence Gathering

```bash
# Search for target mentions in security subreddits
curl -s "https://hn.algolia.com/api/v1/search?query=<target>&tags=story" | jq '.hits[] | {title, url, points, created_at}'

# Reddit search (via web)
# site:reddit.com "<target-company>" "security" OR "IT" OR "VPN" OR "firewall"
# site:reddit.com/r/sysadmin "<target-company>"
# site:reddit.com/r/netsec "<target-technology>"
```

### Exercise 2: HackerNews Discussion Mining

```bash
# Search HN stories
curl -s "https://hn.algolia.com/api/v1/search?query=<target>&tags=story&numericFilters=created_at_i>$(date -d '30 days ago' +%s)" | jq '.hits[] | {title, url, points, num_comments, objectID}'

# Search HN comments (often more revealing than stories)
curl -s "https://hn.algolia.com/api/v1/search?query=<target>&tags=comment&numericFilters=created_at_i>$(date -d '30 days ago' +%s)" | jq '.hits[] | {comment_text: .comment_text[:200], author, created_at, story_title}'
```

### Exercise 3: YouTube Transcript Intelligence

```bash
# Search for conference talks or tutorials about target technology
yt-dlp --flat-playlist "ytsearch20:<target-technology> security" --print "%(title)s | %(url)s"

# Download transcript from a relevant video
yt-dlp --write-auto-sub --sub-lang en --skip-download -o "transcript" "<video-url>"

# Extract security-relevant keywords from transcript
grep -iE "vulnerability|exploit|bypass|CVE|patch|misconfiguration|credential|password" transcript.en.vtt
```

### Exercise 4: Cross-Platform Target Profile

```bash
# Step 1: Find employee usernames
sherlock <suspected-username> --json -o profiles.json

# Step 2: Search each discovered platform for security-relevant posts
# Parse profiles.json for confirmed accounts
cat profiles.json | jq 'to_entries[] | select(.value == "Claimed") | .key'

# Step 3: Aggregate findings into target profile
# - Technical interests (from GitHub repos, HN comments)
# - Security opinions (from Reddit, X posts)
# - Professional role (from LinkedIn, company blog)
# - Technology preferences (from code, forum posts)
```

## Social Intelligence Report Template

```markdown
# Social Intelligence Report: [Target]
*Period: [start-date] to [end-date] | Platforms: [N] | Sources: [N]*

## Executive Summary
[3-5 sentences: what the social landscape reveals about this target]

## 1. Technology Stack Signals
[What technologies are mentioned by employees/community]
- Evidence: "[quote]" — @user on Reddit /r/sysadmin (date)

## 2. Security Posture Indicators
[Complaints, concerns, and discussions about security]
- Evidence: "[quote]" — HN comment (date)

## 3. Personnel Intelligence
[Key individuals identified, roles, technical interests]

## 4. Organizational Culture
[Work environment signals, morale indicators]

## 5. Vulnerability & Risk Signals
[Any discussions about vulnerabilities, breaches, or incidents]

## Key Takeaways
- [Actionable insight for engagement planning]

## Recommended Follow-Up
- [Deep research topics identified]
- [OSINT targets identified]
- [Social engineering angles identified]

## Sources
| Platform | Query | Results | Key Findings |
|----------|-------|---------|-------------|
```

## Hacker Laws

1. **The Weakest Link Is Human** — Social intelligence exploits the human tendency to share. Employees complain about security tools on Reddit, developers push credentials to GitHub, executives discuss strategy on X. The social attack surface is always open.

2. **Divergent Thinking First** — Don't search just the obvious platforms. A target's employees might be active on niche subreddits, Mastodon instances, or Stack Overflow. Cast a wide net across unexpected platforms.

3. **Information Wants to Be Free** — People share more than they realize. A Glassdoor review reveals the security stack. A conference talk reveals the architecture. A GitHub contribution reveals the codebase. Aggregate these fragments into a complete picture.

## Learning Resources

  **This skill's supplementary files**: payloads.md, test-cases.md

  **Guides**: guides/reddit-hackernews-osint.md, guides/twitter-youtube-osint.md, guides/sentiment-analysis.md

  **Related skills**: skills/osint/SKILL.md, skills/deep-research/SKILL.md, skills/social-engineering/SKILL.md, skills/recon-osint/SKILL.md

  **External resources**:
  - **OSINT Framework**: [osintframework.com](https://osintframework.com/)
  - **Sherlock Project**: [github.com/sherlock-project/sherlock](https://github.com/sherlock-project/sherlock)
  - **HN Algolia API**: [hn.algolia.com/api](https://hn.algolia.com/api)
  - **Brave Search API**: [api.search.brave.com](https://api.search.brave.com/)
  - **yt-dlp**: [github.com/yt-dlp/yt-dlp](https://github.com/yt-dlp/yt-dlp)
