# Exa Search

## Skill Identity

| Attribute | Value |
|-----------|-------|
| Domain | Intelligence Gathering |
| Skill ID | exa-search |
| Version | 1.0.0 |
| Hacker Laws | Law 3 (Intelligence Over Force), Law 9 (Systematic Over Random) |
| Related Skills | deep-research, osint, social-intelligence |

## Purpose

Semantic search using Exa API for security research queries. Unlike keyword-based search, Exa understands context and retrieves high-quality, relevant results for technical research.

## Core Capabilities

1. **Semantic Search**: Context-aware query understanding
2. **Date Filtering**: Recent content prioritization
3. **Domain Filtering**: Target specific sources
4. **Content Extraction**: Full-text retrieval

## Use Cases

- **CVE Research**: "Recent CVEs affecting Spring Boot applications"
- **Exploit Techniques**: "SSRF bypass techniques in AWS metadata service"
- **Tool Research**: "Best tools for JWT security testing"
- **Threat Intelligence**: "APT campaigns targeting healthcare 2024"

## Exa API Reference

- **Endpoint**: https://api.exa.ai/search
- **Auth**: API key via X-API-Key header
- **Docs**: https://docs.exa.ai/

## Integration

- Use after **deep-research** when primary sources are insufficient
- Feed results to **knowledge-ops**
- Complement **social-intelligence** for broader coverage
