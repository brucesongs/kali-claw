# Social Intelligence Test Cases

> This file is a companion to `SKILL.md`, containing structured test cases organized by category with severity ratings.

---

## Statistics

| Category | Count | Severity Range |
|------|------|-----------|
| A. Target Profiling | 2 | MEDIUM - HIGH |
| B. Technology & Vulnerability Discovery | 2 | MEDIUM - HIGH |
| C. Monitoring & Sentiment | 1 | HIGH |
| **Total** | **5** | **MEDIUM - HIGH** |

---

## A. Target Profiling

### TC-SI-001: Target Employee Social Profile

| Field | Value |
|------|-----|
| **ID** | TC-SI-001 |
| **Name** | Target Employee Social Profile Construction |
| **Severity** | MEDIUM |
| **Category** | Target Profiling |
| **Objective** | Build a comprehensive social profile of target organization employees using publicly available social platform data |
| **Prerequisites** | Target organization name, at least one known employee name or email domain, internet access |
| **Test Steps** | 1. Use theHarvester to collect employee emails from the target domain<br>2. Extract potential usernames from email addresses<br>3. Run Sherlock against extracted usernames across platforms<br>4. Search Reddit for posts from confirmed accounts<br>5. Search HackerNews for submissions and comments from confirmed accounts<br>6. Search GitHub for repositories and contributions<br>7. Cross-correlate findings: same person across platforms<br>8. Build profile: role, technical interests, security opinions, active platforms |
| **Expected Results** | Employee social profile with: confirmed platform accounts, technical interests and expertise areas, security-relevant discussions, organizational role indicators, and cross-platform correlation evidence |
| **False Positive Risk** | MEDIUM - Common usernames may belong to different individuals; verify with contextual clues (location, company mention, technical domain) |
| **Remediation** | Require at least 2 corroborating data points before attributing an account to a specific individual; flag uncertain attributions |
| **Related Tools** | Sherlock, theHarvester, Reddit API, HN Algolia API, GitHub |

### TC-SI-002: Technology Stack Leak Discovery

| Field | Value |
|------|-----|
| **ID** | TC-SI-002 |
| **Name** | Technology Stack Leak Discovery via Social Platforms |
| **Severity** | HIGH |
| **Category** | Target Profiling |
| **Objective** | Discover target organization's internal technology stack through employee social media activity, forum posts, and code contributions |
| **Prerequisites** | Target organization name, identified employee accounts (from TC-SI-001), internet access |
| **Test Steps** | 1. Search Reddit /r/sysadmin, /r/devops, /r/networking for target company mentions<br>2. Search HN comments for employees discussing their infrastructure<br>3. Search GitHub for employee contributions revealing internal tools<br>4. Search job postings for required technology skills<br>5. Search conference talks and slides for architecture discussions<br>6. Extract technology mentions: frameworks, cloud providers, security tools, databases<br>7. Cross-reference with Shodan/Censys for external confirmation |
| **Expected Results** | Technology stack report with: confirmed technologies (with source evidence), probable technologies (single source), technology versions where available, and security implications of each identified technology |
| **False Positive Risk** | MEDIUM - Employees may discuss technologies they use personally, not at work; job postings may list aspirational rather than current technologies |
| **Remediation** | Prioritize evidence from multiple independent sources; weight company-context mentions higher than general discussions; verify externally visible technologies with Shodan |
| **Related Tools** | Reddit API, HN Algolia API, GitHub search, Shodan, Google Dorking |

---

## B. Technology & Vulnerability Discovery

### TC-SI-003: Vulnerability Discussion Tracking

| Field | Value |
|------|-----|
| **ID** | TC-SI-003 |
| **Name** | Vulnerability Discussion Tracking in Security Communities |
| **Severity** | HIGH |
| **Category** | Technology & Vulnerability Discovery |
| **Objective** | Track and analyze community discussions about new vulnerabilities, exploits, and attack techniques relevant to a target technology stack |
| **Prerequisites** | Target technology list (from TC-SI-002), security community accounts, internet access |
| **Test Steps** | 1. Search Reddit /r/netsec for target technology vulnerability discussions<br>2. Search HN for vulnerability disclosure stories and comments<br>3. Search X/Twitter for security researcher discussions<br>4. Search YouTube for PoC demonstrations and technique walkthroughs<br>5. Extract key findings: CVE references, exploit details, mitigation discussion<br>6. Compare community timeline with official advisory timeline<br>7. Identify information available in community before formal disclosure |
| **Expected Results** | Vulnerability discussion report with: community-discussed vulnerabilities mapped to CVEs, exploit availability timeline (community vs. official), community-shared mitigation techniques, and early warning signals for upcoming disclosures |
| **False Positive Risk** | MEDIUM - Community discussions may exaggerate severity; unverified claims require validation against official sources |
| **Remediation** | Cross-reference all community-sourced vulnerability claims with NVD/vendor advisories; flag unverified claims; note when community discussion precedes official disclosure |
| **Related Tools** | Reddit API, HN Algolia API, X search, YouTube (yt-dlp), NVD API |

### TC-SI-004: Pre-Engagement Sentiment Analysis

| Field | Value |
|------|-----|
| **ID** | TC-SI-004 |
| **Name** | Pre-Engagement Security Sentiment Analysis |
| **Severity** | MEDIUM |
| **Category** | Technology & Vulnerability Discovery |
| **Objective** | Assess target organization's security posture through employee sentiment analysis on social platforms — identifying weak points in security culture |
| **Prerequisites** | Target organization name, internet access, Glassdoor access |
| **Test Steps** | 1. Search Glassdoor reviews for security-related complaints<br>2. Search Reddit for employee discussions about company security policies<br>3. Search TeamBlind for anonymous employee complaints<br>4. Analyze sentiment: positive vs. negative mentions of security tools, training, policies<br>5. Identify patterns: common complaints, recurring frustrations, workaround behaviors<br>6. Map sentiment to social engineering opportunities |
| **Expected Results** | Sentiment analysis report with: security culture score (positive/neutral/negative distribution), common security complaints, identified workaround behaviors (potential bypass paths), and recommended social engineering vectors based on sentiment |
| **False Positive Risk** | MEDIUM - Disgruntled employees may exaggerate negatives; reviews may be outdated or from former employees |
| **Remediation** | Weight recent reviews higher; look for patterns across multiple platforms rather than individual outliers; note review dates and employment status |
| **Related Tools** | Google Dorking (Glassdoor, Reddit, TeamBlind), sentiment keyword analysis |

---

## C. Monitoring & Sentiment

### TC-SI-005: Dark Web Mention Monitoring

| Field | Value |
|------|-----|
| **ID** | TC-SI-005 |
| **Name** | Dark Web and Underground Forum Mention Monitoring |
| **Severity** | HIGH |
| **Category** | Monitoring & Sentiment |
| **Objective** | Monitor dark web forums, paste sites, and underground markets for mentions of target organization, domains, or credentials |
| **Prerequisites** | Target domain and organization name, IntelX API key (optional), Tor access (optional), paste site monitoring tools |
| **Test Steps** | 1. Search Ahmia (Tor clearnet gateway) for target mentions<br>2. Search IntelX for historical dark web mentions<br>3. Search paste sites (Pastebin, Ghostbin, dpaste) for target domain/email leaks<br>4. Search GitHub Gists for accidentally exposed target data<br>5. Check HaveIBeenPwned for target domain breaches<br>6. Categorize findings: credential leaks, data dumps, access sales, vulnerability discussions<br>7. Assess threat level based on recency and specificity of mentions |
| **Expected Results** | Dark web monitoring report with: categorized mentions (credentials, data, access, discussions), threat assessment per finding, timeline of mentions, and recommended incident response actions |
| **False Positive Risk** | HIGH - Dark web data may be fabricated, recycled from old breaches, or belong to different organizations with similar names |
| **Remediation** | Verify credential validity where possible (ethically); cross-reference with known breach databases; check data freshness indicators; never access or use leaked credentials beyond verification |
| **Related Tools** | Ahmia, IntelX, psbdmp API, HaveIBeenPwned, GitHub Gist search |

---

## Summary

| ID | Name | Severity | Category |
|----|------|----------|----------|
| TC-SI-001 | Target Employee Social Profile | MEDIUM | Target Profiling |
| TC-SI-002 | Technology Stack Leak Discovery | HIGH | Target Profiling |
| TC-SI-003 | Vulnerability Discussion Tracking | HIGH | Technology & Vulnerability Discovery |
| TC-SI-004 | Pre-Engagement Sentiment Analysis | MEDIUM | Technology & Vulnerability Discovery |
| TC-SI-005 | Dark Web Mention Monitoring | HIGH | Monitoring & Sentiment |

---

## D. Anomaly Detection & Analysis

### TC-SI-006: Social Graph Anomaly Detection

| Field | Value |
|------|-----|
| **ID** | TC-SI-006 |
| **Name** | Social Graph Anomaly Detection |
| **Severity** | HIGH |
| **Category** | Anomaly Detection & Analysis |
| **Objective** | Detect anomalous patterns in organizational social graphs that may indicate insider threats, compromised accounts, social engineering preparation, or coordinated influence operations targeting the organization |
| **Prerequisites** | Target organization employee social data collected (from TC-SI-001), social graph visualization tools (Maltego, custom Python scripts), at least 3 months of historical social interaction data, understanding of normal organizational communication patterns |
| **Test Steps** | 1. Build social graph from collected employee data: nodes = employees + external contacts, edges = interactions (messages, mentions, follows)<br>2. Calculate baseline metrics: average connections per employee, clustering coefficient, centrality measures (betweenness, closeness, degree)<br>3. Identify anomalous nodes: employees with sudden spike in external connections (>2 standard deviations from baseline)<br>4. Detect bridge nodes: individuals connecting otherwise disconnected clusters (high betweenness centrality) — these are high-value targets<br>5. Flag dormant accounts that suddenly become active (potential compromised accounts)<br>6. Identify employees connecting to known threat actor-adjacent accounts (cross-reference with threat intelligence feeds)<br>7. Analyze temporal patterns: sudden formation of new clusters, rapid follow/unfollow cycles, unusual posting times outside business hours<br>8. Map anomalies to risk categories: insider threat (new connections to competitors), compromised account (dormant → active), social engineering target (bridge node with recent external contact spikes) |
| **Expected Results** | Social graph anomaly report with: detected anomalous nodes and edges with risk categorization, baseline metrics for organizational social graph, identified bridge nodes (high-value targets for social engineering), temporal anomaly timeline showing pattern changes, and recommended investigation priorities ranked by risk score |
| **False Positive Risk** | MEDIUM — New hires naturally have connection spikes; role changes create new cluster formations; conferences generate temporary external connection bursts |
| **Remediation** | Filter out known benign patterns (onboarding, conferences, role changes); require temporal correlation across multiple anomaly types before flagging; weight anomalies by employee access level and data sensitivity |
| **Related Tools** | Maltego, NetworkX (Python), Gephi, Neo4j, theHarvester |

### TC-SI-007: Cross-Platform Identity Correlation

| Field | Value |
|------|-----|
| **ID** | TC-SI-007 |
| **Name** | Cross-Platform Identity Correlation |
| **Severity** | HIGH |
| **Category** | Anomaly Detection & Analysis |
| **Objective** | Correlate identities across multiple social platforms to determine if target organization employees maintain accounts that could be leveraged for social engineering, or if threat actors are impersonating employees across platforms |
| **Prerequisites** | Known employee names and email domains from TC-SI-001, Sherlock or WhatsMyName installed, access to LinkedIn, GitHub, Twitter/X, Reddit, and other platforms, OSINT correlation tools (Maltego, SpiderFoot) |
| **Test Steps** | 1. Extract unique identifiers from known employee profiles: username patterns, email formats, profile photos, bio text<br>2. Run Sherlock against employee usernames across 300+ platforms<br>3. Perform reverse image search on employee profile photos (Google Images, TinEye) to find matching accounts on other platforms<br>4. Cross-reference bio text and employment history across LinkedIn, GitHub, and Twitter/X<br>5. Identify impersonation accounts: same name and photo but different email domain or inconsistent employment history<br>6. Detect credential reuse: check if corporate email pattern (first.last@target.com) maps to same username on external platforms<br>7. Build correlation matrix: for each employee, list all confirmed accounts with confidence scores<br>8. Flag high-risk correlations: employees with accounts on platforms that conflict with security policy (e.g., developer with active account on hacking forums), or impersonation accounts with large follower counts |
| **Expected Results** | Cross-platform identity correlation report with: per-employee account inventory across platforms, confidence scores for each correlation (High/Medium/Low based on corroborating evidence), identified impersonation accounts with evidence, credential reuse findings, and risk-ranked employee profiles based on exposed account surface |
| **False Positive Risk** | HIGH — Common names produce false matches; similar usernames may belong to different individuals; profile photos may be stock images or publicly shared |
| **Remediation** | Require minimum 2 corroborating data points for High confidence correlation (e.g., username + profile photo + bio match); manually verify Medium and Low confidence matches before acting; cross-reference with email verification where possible |
| **Related Tools** | Sherlock, WhatsMyName, Maltego, SpiderFoot, TinEye, Google Images, GitHub search, LinkedIn |

### TC-SI-008: Influence Campaign Analysis

| Field | Value |
|------|-----|
| **ID** | TC-SI-008 |
| **Name** | Influence Campaign Analysis |
| **Severity** | HIGH |
| **Category** | Anomaly Detection & Analysis |
| **Objective** | Detect and analyze coordinated influence campaigns targeting or affecting the target organization, including disinformation, reputation attacks, stock manipulation narratives, or coordinated negative review campaigns |
| **Prerequisites** | Target organization name and key brands/products identified, access to Twitter/X API or Nitter, Reddit API access, access to news aggregation services, sentiment analysis tools, at least 30 days of historical mention data |
| **Test Steps** | 1. Collect all mentions of target organization across platforms (Twitter/X, Reddit, HN, news sites) for past 30 days<br>2. Perform sentiment analysis on collected mentions: categorize as positive, neutral, or negative<br>3. Identify sentiment anomalies: sudden spike in negative mentions (>3 standard deviations from daily baseline)<br>4. Analyze account characteristics of negative-mention accounts: account age, follower count, posting frequency, bot indicators (posting patterns, lack of profile photo, generic bio)<br>5. Detect coordination signals: multiple accounts posting similar content within short timeframes (<1 hour), shared URL shorteners, identical hashtags, coordinated reply chains<br>6. Map amplification network: trace retweets, shares, and cross-posting patterns to identify amplification nodes<br>7. Classify campaign type: reputation attack (negative news + social amplification), stock manipulation (timed negative sentiment before trading hours), competitive attack (narrative originating from competitor-adjacent accounts)<br>8. Produce timeline: first mention, amplification triggers, peak activity, and current status |
| **Expected Results** | Influence campaign analysis report with: detected campaign or confirmed absence with evidence, sentiment anomaly timeline, identified coordinated accounts with bot probability scores, amplification network visualization, campaign classification and probable motive, and recommended response actions (monitor, counter-narrative, report to platform) |
| **False Positive Risk** | MEDIUM — Genuine customer complaints can cluster after service outages; negative news coverage can trigger organic negative sentiment; competitor mentions may be coincidental timing |
| **Remediation** | Correlate sentiment spikes with real-world events (outages, news, earnings reports) before attributing to campaigns; require multiple coordination signals (timing + content similarity + account characteristics) before confirming campaign; differentiate between organic negative sentiment and coordinated amplification |
| **Related Tools** | Twitter/X API, Reddit API, HN Algolia API, sentiment analysis (VADER, TextBlob), Botometer, Gephi, NetworkX |
