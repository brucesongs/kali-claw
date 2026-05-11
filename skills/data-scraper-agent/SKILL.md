# Data Scraper Agent

## Skill Identity

| Attribute | Value |
|-----------|-------|
| Domain | Intelligence Gathering |
| Skill ID | data-scraper-agent |
| Version | 1.0.0 |
| Hacker Laws | Law 3 (Intelligence Over Force), Law 9 (Systematic Over Random) |
| Related Skills | deep-research, osint, knowledge-ops |

## Purpose

Automated data collection from structured sources: CVE databases, threat intelligence feeds, exploit databases, and security advisories. Transform unstructured web data into structured knowledge units.

## Core Capabilities

1. **CVE Database Scraping**: NVD, MITRE, vendor-specific databases
2. **Exploit Database Collection**: Exploit-DB, GitHub security advisories
3. **Threat Intel Feeds**: Parse and filter IOC feeds
4. **Structured Data Extraction**: JSON/XML APIs, HTML scraping

## Use Cases

- **Vulnerability Research**: Collect CVEs for specific products
- **Exploit Availability**: Check if public exploits exist for CVEs
- **Threat Intelligence**: Aggregate IOCs for a campaign
- **Vendor Advisories**: Monitor vendor security bulletins

## Tools

- **BeautifulSoup**: HTML parsing
- **Scrapy**: Web scraping framework
- **requests**: HTTP client
- **jq**: JSON filtering

## Integration

- Feed scraped data to **knowledge-ops** for storage
- Use **deep-research** to contextualize findings
- Export to **article-writing** for reporting
