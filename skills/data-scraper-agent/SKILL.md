---
name: data-scraper-agent
description: "Automated data collection from structured sources: CVE databases, threat intelligence feeds, exploit databases, and security advisories. Transform unstructured web data into structured knowledge units."
origin: openclaw
version: "0.1.18"
compatibility:
  - openclaw
  - claude-code
  - cursor
  - windsurf
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
  - WebSearch
  - WebFetch
  - Agent
metadata:
  domain: research
  tool_count: 0
  guide_count: 5
---




# Data Scraper Agent

## Summary

Transform unstructured web data into structured knowledge units.

**Domain**: research

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

## Scraping Strategy

- **API-first**: Prefer JSON APIs (NVD 2.0, GitHub Advisory) over HTML scraping — schemas are stable, rate limits documented, content validated.
- **Pagination discipline**: Always honor `Link: rel="next"` headers or cursor-based tokens; never scrape past published page limits.
- **Selective extraction**: Pull only the fields you need (`cve.id`, `descriptions[*].value`, `metrics.cvssMetricV31`) instead of dumping full records.
- **Incremental sync**: Track `lastModifiedDate` watermarks per source to avoid re-fetching unchanged records.

## Ethical Scraping

1. Respect `robots.txt` even when the legal status is unclear — courts treat ignored robots files as a hostile signal.
2. Add a descriptive `User-Agent` (`kali-claw-research/1.0 contact@org`) so site operators can reach you.
3. Throttle to ≤1 req/sec by default; back off exponentially on `429`/`503`.
4. Cache aggressively — `If-Modified-Since` and `ETag` cut load on both sides.
5. Avoid scraping content behind authentication unless explicitly authorized.

## Data Normalization

- Coerce all timestamps to UTC ISO 8601 before persisting.
- Map CVE severity to a canonical scale (CVSS v3.1 base score); store vendor-specific scores separately.
- Deduplicate by `(source, primary_id)` tuples — the same CVE appears in NVD, MITRE, and vendor feeds with slight schema drift.
- Preserve raw source payloads alongside normalized records for audit and reprocessing.

## Common Pitfalls

- **Brittle CSS selectors** — HTML structures change without notice; prefer semantic anchors (microdata, JSON-LD) when available.
- **Silent rate-limit bans** — some APIs degrade quietly instead of `429`; monitor response sizes and freshness.
- **Encoding bugs** — non-UTF-8 sources (older vendor advisories) corrupt downstream pipelines without explicit decoding.
- **Schema drift** — NVD 1.x vs 2.0 schemas differ subtly; pin client versions and run schema validation per ingest.

## Pipeline Architecture

- **Extractor stage**: Fetch raw content from source (HTTP GET, API call, RSS feed). Validate HTTP status and content-type before proceeding.
- **Parser stage**: Convert raw bytes to structured records using schema-specific parsers (JSON, XML, HTML table). Reject malformed records to quarantine.
- **Transformer stage**: Normalize fields (dates, severity, identifiers), deduplicate, and enrich with cross-references (link CVEs to advisories).
- **Loader stage**: Persist normalized records to knowledge store. Use upsert semantics to handle re-ingestion without duplication.

## Error Handling and Retry

- Classify errors as retryable (network timeout, HTTP 429/503) vs non-retryable (HTTP 404, invalid API key, schema mismatch).
- Implement exponential backoff with jitter for retryable errors: `sleep(base * 2^attempt + random(0, jitter))`.
- Set per-source circuit breakers: after N consecutive failures, pause that source for a cooling period and alert.
- Log all retry attempts with timestamps and error details for post-mortem analysis.

## Source-Specific Patterns

- **NVD 2.0 API**: Use `startIndex` + `resultsPerPage` pagination; filter by `cpeName` for product-specific queries; handle 503 during peak hours.
- **GitHub Advisory**: Query by ecosystem (`ecosystem=PIP`), severity, and date range; paginate with `cursor` tokens.
- **Exploit-DB**: Scrape search results with rate limiting; cross-reference CVEs via the `files_cves.csv` mapping file.
- **Vendor Advisories**: Each vendor has unique HTML structure; write dedicated parsers per vendor, share common extraction utilities.

## Performance Optimization

- Use async I/O (`aiohttp`, `asyncio`) for parallel requests across independent sources — 10x throughput over sequential fetching.
- Cache raw HTTP responses with `requests-cache` or similar; set TTL per source (NVD: 1h, vendor advisories: 24h).
- Stream large responses instead of buffering into memory — parse JSON incrementally with `ijson` for large datasets.
- Batch database writes (insert 100 records per transaction) instead of individual inserts.

## Monitoring and Alerting

- Track scrape success rate per source (target >95%); alert on sustained drops indicating source changes or IP blocks.
- Monitor ingestion lag: time between source publication and local availability. Flag sources where lag exceeds threshold.
- Log schema validation failures per source — rising failure rates signal upstream format changes.
- Emit structured metrics (source, records_fetched, records_parsed, records_loaded, errors) for dashboard visualization.

## Integration

- Feed scraped data to **knowledge-ops** for storage
- Use **deep-research** to contextualize findings
- Export to **article-writing** for reporting
