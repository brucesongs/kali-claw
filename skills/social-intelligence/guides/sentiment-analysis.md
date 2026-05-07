# Sentiment Analysis for Security Intelligence

> Guide for the social-intelligence skill — covers using sentiment analysis to assess security posture and identify social engineering opportunities.

## Overview

Sentiment analysis in a security context extracts actionable intelligence from how people feel about an organization's security practices. Employee complaints about MFA, frustrated posts about VPN issues, or angry reviews about security training all reveal exploitable weaknesses in security culture.

## Security Sentiment Framework

### Sentiment Categories

| Category | Positive Signal | Negative Signal (Exploitable) |
|----------|----------------|-------------------------------|
| **Security Tools** | "Love our new SSO setup" | "This VPN is garbage, always disconnects" |
| **Policies** | "Reasonable password policy" | "Have to change passwords every 30 days, insane" |
| **Training** | "Phishing tests are actually useful" | "Another useless security awareness training" |
| **IT Support** | "IT resolved my access in minutes" | "Took IT 3 days to reset my account" |
| **Incident Response** | "Team handled the outage well" | "Nobody told us about the breach for weeks" |
| **Culture** | "Security is everyone's job here" | "Security team blocks everything, we just use personal devices" |

### What Negative Sentiment Reveals

| Complaint Pattern | Security Implication |
|-------------------|---------------------|
| "VPN is too slow/unreliable" | Employees may bypass VPN, expose traffic |
| "MFA is annoying" | Users may share MFA codes, approve push blindly |
| "Password policy is too strict" | Users reuse passwords, write them down |
| "Security training is a waste of time" | Low awareness = high phishing success rate |
| "IT takes too long" | Shadow IT adoption, unauthorized tools |
| "Can't access what I need" | Users find workarounds, bypass access controls |
| "Security blocks my tools" | Personal device usage, unauthorized cloud storage |

## Collection Methodology

### Step 1: Source Identification

```
Priority sources for sentiment analysis:

1. Glassdoor reviews (search "security" OR "IT" in cons)
2. Reddit /r/sysadmin (employees venting about policies)
3. TeamBlind (anonymous, high candor)
4. HackerNews (tech employees discussing frustrations)
5. Twitter/X (real-time complaints during outages)
6. LinkedIn (professional but revealing in comments)
```

### Step 2: Keyword-Based Sentiment Extraction

```bash
# Glassdoor sentiment mining (via Google)
site:glassdoor.com "<company>" review "security" OR "IT"
site:glassdoor.com "<company>" "cons" "password" OR "VPN" OR "MFA"

# Reddit complaint mining
site:reddit.com "<company>" "hate" OR "annoying" OR "broken" OR "useless" security OR IT OR VPN
site:reddit.com/r/sysadmin "<company>" "frustrating" OR "nightmare" OR "terrible"

# TeamBlind
site:teamblind.com "<company>" security OR IT OR engineering "worst" OR "bad" OR "terrible"

# Twitter outage/incident sentiment
site:twitter.com "<company>" "down" OR "outage" OR "can't login" OR "broken"
```

### Step 3: Sentiment Categorization

Classify each finding into one of these buckets:

```markdown
## Sentiment Analysis: [Target]

### Category A: Tool Frustrations
[What security tools do employees complain about?]
→ Implication: Which tools might be misconfigured or have bypass potential

### Category B: Policy Resistance
[What policies generate the most pushback?]
→ Implication: Where employees are most likely to circumvent controls

### Category C: IT Friction
[What IT processes cause delays or frustration?]
→ Implication: Where shadow IT and workarounds are likely

### Category D: Culture Indicators
[Does the organization treat security as important or a checkbox?]
→ Implication: Overall security awareness level and phishing susceptibility

### Category E: Incident Transparency
[How does the org communicate about security incidents?]
→ Implication: Internal trust level and incident detection capabilities
```

## Analysis Techniques

### Frequency Analysis

Count how often specific keywords appear in negative contexts.

```bash
# Extract negative sentiment keywords
NEGATIVE_WORDS="hate|terrible|broken|worst|annoying|frustrating|useless|impossible|nightmare|garbage|awful|ridiculous"
SECURITY_WORDS="VPN|MFA|password|firewall|security|IT|access|login|authentication|SSO|endpoint"

# Score: high negative + high security keyword overlap = exploitable frustration
grep -iE "$NEGATIVE_WORDS" collected_posts.txt | grep -icE "$SECURITY_WORDS"
```

### Temporal Analysis

Correlate sentiment spikes with organizational events.

```markdown
| Date Range | Sentiment Shift | Possible Cause |
|------------|-----------------|----------------|
| 2026-03-01 to 2026-03-15 | Sharp negative spike | New MFA rollout |
| 2026-04-01 to 2026-04-10 | Negative spike | Annual security training |
| 2026-04-20 to 2026-04-25 | Mixed | System migration/outage |
```

### Comparative Analysis

Compare target's sentiment against industry baseline.

```markdown
| Metric | Target | Industry Average | Assessment |
|--------|--------|-----------------|------------|
| MFA satisfaction | 2.1/5 | 3.2/5 | Below average — bypass risk |
| VPN reliability | 1.8/5 | 3.0/5 | Poor — shadow IT likely |
| Security training value | 2.5/5 | 2.8/5 | Average |
| IT response time | 3.5/5 | 3.0/5 | Above average |
```

## Mapping Sentiment to Social Engineering Vectors

### Decision Matrix

| Sentiment Finding | SE Vector | Attack Approach |
|-------------------|-----------|-----------------|
| "MFA is annoying" | MFA fatigue attack | Flood push notifications, victim approves to stop |
| "VPN always disconnects" | Fake VPN update phishing | "Install this VPN fix" email with malicious installer |
| "Password policy too strict" | Credential harvesting | "Simplified login portal" phishing page |
| "IT is too slow" | Impersonate IT support | "We noticed your issue, let us help remotely" |
| "Security training is useless" | Standard phishing | Low awareness = generic phishing may work |
| "Using personal devices for work" | Rogue device attack | Target personal devices with weaker security |
| "Switched to new SSO" | Migration-themed phishing | "Complete your SSO migration" email |

## Sentiment Report Template

```markdown
# Security Sentiment Report: [Target]
*Period: [date range] | Sources: [N platforms] | Posts analyzed: [N]*

## Overall Sentiment Score
[1-5 scale: 1=very negative, 5=very positive]
- Security tools: X/5
- Policies: X/5
- IT support: X/5
- Security culture: X/5
- **Overall: X/5**

## Top Frustration Areas
1. [Most complained about] — [N mentions] — Exploitation potential: HIGH/MEDIUM/LOW
2. [Second most] — [N mentions] — Exploitation potential: HIGH/MEDIUM/LOW
3. [Third most] — [N mentions] — Exploitation potential: HIGH/MEDIUM/LOW

## Key Evidence
[Anonymized quotes with source attribution]

## Social Engineering Recommendations
Based on sentiment analysis, the following SE vectors are most likely to succeed:
1. [Vector] — rationale: [sentiment evidence]
2. [Vector] — rationale: [sentiment evidence]

## Confidence Assessment
- Data volume: HIGH/MEDIUM/LOW (based on number of sources)
- Data recency: HIGH/MEDIUM/LOW (based on date range)
- Source diversity: HIGH/MEDIUM/LOW (number of platforms)
```

## Ethical Considerations

- Sentiment analysis is for **authorized security assessments only**
- Never harass or contact individuals identified in social media analysis
- Anonymize specific individuals in reports (use roles, not names)
- Focus on organizational patterns, not individual complaints
- Respect platform terms of service when collecting data
