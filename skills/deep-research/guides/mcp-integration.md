# MCP Integration Guide

> Guide for the deep-research skill — covers connecting external data sources via MCP (Model Context Protocol) for private and real-time intelligence.

## Overview

MCP enables deep research to access data beyond public web search: private threat intelligence feeds, internal vulnerability databases, and real-time security APIs. This guide covers configuring MCP servers for security research.

## Architecture

```
Claude Code / kali-claw Agent
      │
      ├── MCP Server: Shodan
      │     └── Real-time device/exposure search
      │
      ├── MCP Server: VirusTotal
      │     └── Hash/URL/domain analysis
      │
      ├── MCP Server: GreyNoise
      │     └── Internet noise vs. targeted activity
      │
      ├── MCP Server: Web Reader / Firecrawl
      │     └── Full-page content extraction
      │
      └── MCP Server: Custom (Internal)
            └── Private threat intel, asset inventory
```

## Available Security MCP Servers

### Tier 1: Core Intelligence

| MCP Server | Purpose | API Key Required |
|------------|---------|------------------|
| **Shodan** | Internet-facing device search, exposure monitoring | `SHODAN_API_KEY` |
| **VirusTotal** | Malware analysis, URL scanning, hash lookup | `VT_API_KEY` |
| **GreyNoise** | Distinguish targeted attacks from internet noise | `GREYNOISE_API_KEY` |
| **AbuseIPDB** | IP reputation and abuse reporting | `ABUSEIPDB_API_KEY` |

### Tier 2: Content Extraction

| MCP Server | Purpose | API Key Required |
|------------|---------|------------------|
| **Firecrawl** | Web scraping with structured extraction | `FIRECRAWL_API_KEY` |
| **Web Reader** | URL to markdown conversion | Varies |
| **Exa** | Semantic web search | `EXA_API_KEY` |
| **Brave Search** | Web search with privacy | `BRAVE_API_KEY` |

### Tier 3: Specialized

| MCP Server | Purpose | API Key Required |
|------------|---------|------------------|
| **GitHub** | Code search, advisory lookup | `GITHUB_TOKEN` |
| **NVD** | CVE database queries | Free (rate-limited) |
| **MITRE ATT&CK** | Technique/group lookup | Free |

## Configuration

### Claude Code MCP Settings

MCP servers are configured in `~/.claude/settings.json` or project-level `.claude/settings.json`:

```json
{
  "mcpServers": {
    "shodan": {
      "command": "npx",
      "args": ["-y", "shodan-mcp-server"],
      "env": {
        "SHODAN_API_KEY": "${SHODAN_API_KEY}"
      }
    },
    "virustotal": {
      "command": "npx",
      "args": ["-y", "virustotal-mcp-server"],
      "env": {
        "VT_API_KEY": "${VT_API_KEY}"
      }
    },
    "firecrawl": {
      "command": "npx",
      "args": ["-y", "firecrawl-mcp-server"],
      "env": {
        "FIRECRAWL_API_KEY": "${FIRECRAWL_API_KEY}"
      }
    }
  }
}
```

### Environment Variables

Store API keys securely — never in source code.

```bash
# Add to ~/.zshrc or ~/.bashrc (or use a secret manager)
export SHODAN_API_KEY="your-key-here"
export VT_API_KEY="your-key-here"
export GREYNOISE_API_KEY="your-key-here"
export ABUSEIPDB_API_KEY="your-key-here"
export BRAVE_API_KEY="your-key-here"
export FIRECRAWL_API_KEY="your-key-here"
export EXA_API_KEY="your-key-here"
```

## Usage Patterns

### Pattern 1: IOC Enrichment Pipeline

```
Input: raw IOC list (IPs, hashes, domains)
  │
  ├── Shodan MCP: enrich IPs with services, location, org
  ├── VirusTotal MCP: enrich hashes with detection results
  ├── AbuseIPDB MCP: enrich IPs with reputation scores
  └── GreyNoise MCP: classify IPs as noise vs. targeted
  │
  ▼
Output: enriched IOC report with context
```

### Pattern 2: Vulnerability Research Augmentation

```
Input: CVE ID or technology name
  │
  ├── NVD API: CVE details, CVSS, affected CPEs
  ├── GitHub MCP: search for PoC code and tools
  ├── Firecrawl MCP: extract full content from security blogs
  └── Exa MCP: semantic search for related research
  │
  ▼
Output: comprehensive vulnerability assessment
```

### Pattern 3: Attack Surface Discovery

```
Input: target organization name or domain
  │
  ├── Shodan MCP: discover internet-facing assets
  ├── GitHub MCP: search for code leaks and exposed credentials
  ├── Brave Search MCP: discover related domains and services
  └── Web Reader MCP: extract content from discovered endpoints
  │
  ▼
Output: attack surface inventory with risk assessment
```

## Rate Limiting and Cost Management

| Service | Free Tier | Rate Limit | Cost (Paid) |
|---------|-----------|------------|-------------|
| Shodan | 100 queries/month | 1 req/sec | $69/month (Small Business) |
| VirusTotal | 500 lookups/day | 4 req/min | $2,400/year (Premium) |
| GreyNoise | 50 queries/day (Community) | 1 req/sec | $359/year (Research) |
| AbuseIPDB | 1,000 checks/day | 5 req/sec | Free for most use cases |
| NVD | Unlimited | 5 req/30sec (no key), 50 req/30sec (with key) | Free |

### Best Practices

1. **Cache aggressively**: store API results locally to avoid redundant queries
2. **Batch queries**: combine multiple lookups into batch requests where supported
3. **Tier your sources**: use free sources first, paid sources for enrichment
4. **Set daily budgets**: limit API calls per day to control costs
5. **Store API keys securely**: use environment variables or a secret manager, never in code

## OPSEC Considerations

- **API query logging**: most services log your queries — use a VPN if researching sensitive targets
- **Rate limit fingerprinting**: aggressive querying patterns may reveal your research interest
- **API key exposure**: a compromised key reveals your research history
- **Target awareness**: some services (Shodan, Censys) notify organizations when they are scanned
