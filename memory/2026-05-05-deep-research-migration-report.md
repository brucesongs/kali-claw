# Deep Research Capability Migration Report

*Generated: 2026-05-05 | Research Duration: 30 min | Sources: 15+*

## Executive Summary

Investigated the "deep research" AI capability landscape (last 30 days) and the open-source `last30days` skill, evaluating migration feasibility to kali-claw. Key finding: these are **complementary, not competing** capabilities. Both should be integrated into kali-claw for maximum intelligence-gathering effectiveness.

---

## 1. Industry State: Deep Research (April-May 2026)

### Platform Comparison

| Platform | Product | API | Key Feature | Latency |
|----------|---------|-----|-------------|---------|
| Google Gemini | Deep Research Max (Apr 21) | Interactions API | MCP, native charts, multimodal input | 2-15 min |
| OpenAI | o3-deep-research | Responses API | MCP, vector stores, code interpreter | 10-30+ min |
| Perplexity | Deep Research + Computer (Apr) | Enterprise API | 19-model orchestration, Claude as orchestrator | 2-4 min |
| Claude | No standalone product | Standard API + MCP | 1M token window, Extended Thinking, best synthesis | Real-time |

### Common Architecture (All Platforms)

```
Query Understanding → Iterative Search (100+ sources) → Source Evaluation → Synthesis → Cited Report
                         ↑________________↓ (refine queries based on findings)
```

Key innovations in last 30 days:
- **MCP for private data** (Google + OpenAI both support)
- **Extended test-time compute** (more reasoning tokens = better reports)
- **Native visualization** (Google: inline charts/infographics)
- **Collaborative planning** (user reviews/modifies research plan before execution)

---

## 2. `last30days` Skill Analysis

### What It Is

Open-source Claude Code skill by Matt Van Horn ([GitHub](https://github.com/mvanhorn/last30days-skill)). Searches **social platforms** for the most recent 30 days of discussion on any topic.

### Pipeline (v3)

```
Plan Query → Retrieve (per source) → Normalize/Dedup → Extract Snippets
    → Reciprocal Rank Fusion → Rerank → Cluster Evidence → Render Output
```

### Sources

- Reddit, X (Twitter), YouTube (transcripts via yt-dlp)
- TikTok, Instagram, Hacker News
- Polymarket (prediction markets)
- General web (Brave Search / Serper)

### Requirements

- Python 3.12+
- API keys: `BRAVE_API_KEY` or `SERPER_API_KEY`, `SCRAPECREATORS_API_KEY`
- Optional: Google/OpenAI/xAI for reasoning, Twitter auth tokens, yt-dlp

---

## 3. Core Distinction: last30days vs deep-research

| Dimension | **last30days** | **deep-research (kali-claw)** |
|-----------|---------------|-------------------------------|
| **Core question** | "What are people SAYING about X right now?" | "What is KNOWN about X in depth?" |
| **Signal type** | Community sentiment, viral posts, engagement metrics | Published sources, advisories, research papers |
| **Time window** | Strictly last 30 days | Any timeframe (historical analysis possible) |
| **Sources** | Social platforms (Reddit, X, YouTube, TikTok, HN) | Web, NVD, Exploit-DB, MITRE, GitHub, security blogs |
| **Output** | Cluster-based synthesis with @handles, subreddits | Structured report with executive summary, citations |
| **Retrieval** | Automated pipeline with RRF reranking | Agent-guided iterative search |
| **Best for** | Trend detection, pulse check, pre-engagement context | Due diligence, CVE analysis, adversary profiling |

### One-Sentence Summary

- **last30days** = Real-time social intelligence ("What's the buzz?")
- **deep-research** = Systematic knowledge synthesis ("What's the truth?")

---

## 4. Security Application Mapping

### For Hackers: Why Both Matter

| Security Task | last30days Contribution | deep-research Contribution |
|---------------|------------------------|---------------------------|
| **Reconnaissance** | Discover target discussions, employee complaints, leaked info on social | Map full attack surface, technology stack, historical vulnerabilities |
| **Social Engineering** | Find target's interests, recent posts, social graph, communication style | Build organizational chart, identify key personnel, map reporting structure |
| **Vulnerability Exploitation** | Find PoC discussions, bypass techniques shared in communities | CVE deep-dive, exploit status, affected versions, patch analysis |
| **Threat Intelligence** | Track APT group discussions, new tool releases, community chatter | Build comprehensive adversary profiles, map TTPs to MITRE ATT&CK |
| **OPSEC Awareness** | Monitor if your operation is being discussed | Research detection methods, defensive tools, blue team capabilities |
| **Supply Chain** | Track developer discussions about package security | Map dependency trees, audit CVE exposure, analyze maintainer trust |

### Combined Workflow Example: Pre-Engagement Target Research

```
Phase 1 (last30days): "What are employees of $TARGET saying on Reddit/X/HN?"
  → Discover: tech stack discussions, complaints about security policies,
     hiring posts revealing infrastructure, conference talks

Phase 2 (deep-research): "Deep-dive into $TARGET's identified tech stack"
  → Produce: CVE list, known misconfigurations, attack surface map,
     historical breaches, detection capabilities

Phase 3 (Synthesis): Combine social intelligence + technical research
  → Attack plan with social engineering vectors informed by real sentiment
```

---

## 5. Gap Analysis: Current kali-claw vs Target State

| Capability | Current State | Target State | Gap |
|------------|---------------|--------------|-----|
| Depth-first research | SKILL.md complete | Add iterative automation | Medium |
| Recency-first social intel | Not present | Integrate last30days | **High** |
| Continuous monitoring | Not present | Scheduled research jobs | **High** |
| Change detection | Not present | Diff between research snapshots | Medium |
| Private data integration | Not present | MCP tool chain | Medium |
| Knowledge graph | Not present | Structured IOC/entity correlation | Low (future) |

---

## 6. Migration Plan: Integrate last30days into kali-claw

### Architecture

```
skills/
├── deep-research/          ← Existing (enhance)
│   ├── SKILL.md            ← Add Phase 7-9 (continuous + correlation)
│   ├── payloads.md         ← Add monitoring query templates
│   ├── test-cases.md       ← Add continuous monitoring test cases
│   └── guides/
│       ├── iterative-search-patterns.md
│       ├── continuous-monitoring.md
│       ├── intelligence-correlation.md
│       └── mcp-integration.md
│
├── social-intelligence/    ← NEW (migrated from last30days concept)
│   ├── SKILL.md            ← Social platform OSINT methodology
│   ├── payloads.md         ← Platform-specific search queries
│   ├── test-cases.md       ← Social intel gathering test cases
│   └── guides/
│       ├── reddit-osint.md
│       ├── twitter-osint.md
│       ├── youtube-osint.md
│       ├── hackernews-osint.md
│       └── sentiment-analysis.md
```

### Implementation Phases

**Phase 1: Enhance deep-research (2-3 days)**
- Fill `guides/` directory with iterative patterns, continuous monitoring, correlation
- Add Phases 7-9 to methodology
- Expand payloads.md with monitoring templates

**Phase 2: Create social-intelligence skill (2-3 days)**
- New skill domain following kali-claw pattern (SKILL.md + payloads.md + test-cases.md + guides/)
- Adapt last30days methodology to security context
- Platform-specific OSINT techniques
- Sentiment analysis for pre-engagement profiling

**Phase 3: Integration (1-2 days)**
- Cross-reference between deep-research and social-intelligence
- Combined workflow templates
- Update IDENTITY.md and TOOLS.md

**Phase 4: Automation layer (2-3 days)**
- Integrate with autonomous-loops skill
- Scheduled research patterns
- Change detection templates
- Alert trigger definitions

### Total Effort: ~8-10 days

---

## 7. Key Decisions Required

1. **last30days tool integration**: Install the Python package as a tool, or adapt the methodology into kali-claw's native format?
   - Recommendation: **Adapt methodology** (avoid external Python dependency on Kali ARM64, maintain kali-claw's tool-agnostic philosophy)

2. **Social platform API access**: Which APIs to prioritize?
   - Recommendation: Brave Search (free tier) + Reddit API + HackerNews (no auth needed) first; X/TikTok/Instagram as optional

3. **Continuous monitoring trigger**: Manual or automated?
   - Recommendation: Define templates in payloads.md; use autonomous-loops skill for execution patterns

---

## Sources

1. [Google Deep Research Max Announcement (Apr 2026)](https://blog.google/innovation-and-ai/models-and-research/gemini-models/next-generation-gemini-deep-research/)
2. [OpenAI Deep Research API Guide](https://developers.openai.com/api/docs/guides/deep-research)
3. [OpenAI Introducing Deep Research](https://openai.com/index/introducing-deep-research/)
4. [Perplexity Changelog Feb 2026](https://www.perplexity.ai/changelog/what-we-shipped---february-6th-2026)
5. [Perplexity March 2026 Features](https://www.datastudios.org/post/perplexity-new-features-and-use-cases-in-march-2026)
6. [mvanhorn/last30days-skill GitHub](https://github.com/mvanhorn/last30days-skill)
7. [How Last 30 Days Turns Claude Code Into a Research Superpower (Medium)](https://medium.com/@francofuji/how-last-30-days-turns-claude-code-into-a-research-superpower-de2b8806170f)
8. [JMIR: Deep Research Agents Definition](https://www.jmir.org/2026/1/e88195)
9. [AI Agent Platform Updates May 2026](https://turion.ai/blog/ai-agent-platform-updates-may-2026)
10. [AI Deep Research Tools Compared 2026](https://rephrase-it.com/blog/ai-deep-research-tools-compared-for-2026)
