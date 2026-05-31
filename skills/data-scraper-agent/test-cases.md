# Data Scraper Agent Test Cases

## TC-DSA-001: CVE Collection for Product
**Objective**: Collect all CVEs for a specific product
**Severity**: HIGH
**Prerequisites**: Python 3.8+, requests library, NVD API key (optional for higher rate limits)

**Remediation**: Maintain a regularly updated CVE inventory for all products in your technology stack; automate CVE collection with scheduled pipelines; cross-reference collected CVEs with internal asset inventory to prioritize remediation based on actual exposure

**Steps**:
1. Query NVD API with product keyword
2. Handle pagination (resultsPerPage=2000)
3. Parse JSON response
4. Extract CVE IDs, CVSS scores, descriptions
5. Store in structured format (CSV/JSON)

**Expected Output**: List of CVEs with metadata

**Pass Criteria**:
- [ ] All CVEs returned from API (pagination complete)
- [ ] CVSS scores extracted correctly
- [ ] Data stored in structured format
- [ ] Rate limiting respected

## TC-DSA-002: Exploit Availability Check
**Objective**: Check if public exploits exist for CVE list
**Severity**: HIGH
**Prerequisites**: Python 3.8+, searchsploit installed, GitHub API token (optional for higher rate limits), internet access

**Remediation**: Monitor exploit availability proactively for all known CVEs in your stack; prioritize patching when public exploits appear; subscribe to exploit-db RSS feeds; implement virtual patching via WAF rules when immediate patching is not possible

**Steps**:
1. For each CVE, search Exploit-DB via searchsploit
2. Check GitHub for PoC repositories
3. Query GitHub Advisory Database
4. Record exploit availability + link

**Expected Output**: Table of CVEs with exploit status

**Pass Criteria**:
- [ ] All CVEs checked across multiple sources
- [ ] Exploit links recorded
- [ ] No false positives

## TC-DSA-003: GitHub Advisory Scraping
**Objective**: Collect recent security advisories from GitHub
**Severity**: MEDIUM
**Prerequisites**: GitHub API token with public_repo scope, Python requests library, rate limiting middleware configured

**Remediation**: Subscribe to GitHub Dependabot alerts for automated notification; enable automatic security updates where possible; monitor GitHub Advisory Database for newly disclosed vulnerabilities affecting your dependencies

**Steps**:
1. Query GitHub Advisory API with ecosystem filter (npm/pip/go)
2. Filter by severity (critical/high)
3. Extract GHSA ID, summary, affected packages, patched versions
4. Deduplicate against previously collected advisories

**Expected Output**: Structured list of advisories with remediation info

**Pass Criteria**:
- [ ] API authentication works
- [ ] Results filtered by severity
- [ ] Affected packages and versions extracted
- [ ] Output format consistent

## TC-DSA-004: Rate-Limited API Scraping
**Objective**: Scrape data from rate-limited API without triggering blocks
**Severity**: MEDIUM
**Prerequisites**: Python 3.8+, requests library with retry adapter, API key for target service (NVD, GitHub, etc.)

**Remediation**: Respect API rate limits and Terms of Service; implement proper backoff strategies; cache responses to minimize redundant requests; use API keys where available for higher rate limits; consider API subscription tiers for production workloads

**Steps**:
1. Configure rate limiter (5 requests/30 seconds for NVD)
2. Implement exponential backoff on 429 responses
3. Run scraping job for 50+ pages
4. Verify all pages collected without errors

**Expected Output**: Complete dataset with no gaps

**Pass Criteria**:
- [ ] No 429 errors in final run
- [ ] All pages retrieved successfully
- [ ] Backoff triggered correctly on rate limit
- [ ] Total time within expected bounds

## TC-DSA-005: Multi-Source Data Correlation
**Objective**: Correlate vulnerability data across NVD, GitHub, and Exploit-DB
**Severity**: HIGH
**Prerequisites**: Python 3.8+, requests library, API keys for NVD and GitHub, searchsploit installed

**Remediation**: Implement automated cross-referencing pipelines to detect discrepancies between vulnerability databases; establish a single source of truth with manual review for conflicting severity ratings; use structured data formats (CVE JSON 5.0) for consistent parsing

**Steps**:
1. Collect CVEs from NVD for target product
2. Cross-reference each CVE with GitHub advisories
3. Check Exploit-DB for available exploits
4. Merge data into unified report with all sources

**Expected Output**: Unified vulnerability report with cross-references

**Pass Criteria**:
- [ ] Data merged correctly by CVE ID
- [ ] Source attribution maintained
- [ ] Conflicts flagged (e.g., different CVSS scores)
- [ ] Output includes exploitability status

## TC-DSA-006: NVD API Pagination Handler
**Objective**: Implement robust pagination handling for the NVD 2.0 API to collect all CVEs matching a query without missing records or exceeding rate limits, supporting both offset-based and date-range pagination
**Severity**: HIGH
**Prerequisites**: Python 3.8+, requests library, NVD API key (optional, provides 50 req/30s vs 5 req/30s without key)

**Remediation**: Implement API key provisioning for production scraping pipelines; cache NVD responses with 24-hour TTL to reduce redundant queries; use date-range segmentation for large dataset queries instead of fetching all results at once

**Steps**:
1. Define the search query and initial parameters (keyword, resultsPerPage=2000)
2. Send initial request to NVD API and parse `totalResults` from response
3. Calculate required page count: `pages = ceil(totalResults / resultsPerPage)`
4. Implement pagination loop with configurable delay:
   ```python
   import time, math, requests
   def scrape_nvd_paginated(keyword, api_key=None, per_page=2000, delay=6):
       url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
       headers = {"apiKey": api_key} if api_key else {}
       all_cves = []
       params = {"keywordSearch": keyword, "resultsPerPage": per_page, "startIndex": 0}
       resp = requests.get(url, params=params, headers=headers, timeout=30)
       data = resp.json()
       total = data["totalResults"]
       all_cves.extend(data.get("vulnerabilities", []))
       pages = math.ceil(total / per_page)
       for page in range(1, pages):
           params["startIndex"] = page * per_page
           time.sleep(delay)
           resp = requests.get(url, params=params, headers=headers, timeout=30)
           all_cves.extend(resp.json().get("vulnerabilities", []))
       return all_cves
   ```
5. Verify collected count matches `totalResults` from initial response
6. Handle 429 responses with exponential backoff
7. Store results with deduplication by CVE ID

**Expected Output**: Complete set of all CVEs matching the query with no gaps or duplicates

**Pass Criteria**:
- [ ] Total CVE count from pagination matches NVD totalResults
- [ ] No duplicate CVE IDs in collected dataset
- [ ] 429 responses handled with backoff (no data loss)
- [ ] Pagination completes within expected time bounds based on rate limits
- [ ] Results stored in structured format with metadata

## TC-DSA-007: Exploit-DB Automated Scraping
**Objective**: Automate Exploit-DB data collection by parsing searchsploit JSON output, downloading exploit source files, and categorizing exploits by platform, type, and port for integration into vulnerability assessment workflows
**Severity**: HIGH
**Prerequisites**: searchsploit installed and database updated, Python 3.8+, internet access for Exploit-DB mirror downloads

**Remediation**: Use Exploit-DB data only for authorized defensive security assessments; verify exploit compatibility with target versions before execution; maintain a local mirror of Exploit-DB for air-gapped environments

**Steps**:
1. Update searchsploit database: `searchsploit --update`
2. Search for exploits matching target product:
   ```bash
   searchsploit apache 2.4 --json > /tmp/apache_exploits.json
   ```
3. Parse JSON output and extract structured fields:
   ```python
   import json, subprocess
   def parse_exploitdb(query):
       result = subprocess.run(
           ["searchsploit", query, "--json"],
           capture_output=True, text=True
       )
       data = json.loads(result.stdout)
       exploits = []
       for item in data.get("RESULTS_EXPLOIT", []):
           exploits.append({
               "id": item.get("Code", "").split("/")[-1],
               "title": item.get("Title", ""),
               "type": item.get("Type", ""),
               "platform": item.get("Platform", ""),
               "date": item.get("Date", ""),
               "path": item.get("Path", "")
           })
       return exploits
   ```
4. Download exploit files for offline analysis: `searchsploit -m <exploit_id>`
5. Categorize by type: remote, local, webapps, dos, shellcode
6. Cross-reference with CVE database using `searchsploit --cve`
7. Generate summary report with counts by platform and type

**Expected Output**: Structured exploit inventory with IDs, types, platforms, and local file paths

**Pass Criteria**:
- [ ] searchsploit JSON output parsed without errors
- [ ] All exploit entries contain valid ID, title, type, and platform
- [ ] Exploit source files downloaded and readable
- [ ] CVE cross-references extracted where available
- [ ] Summary report generated with category breakdown

## TC-DSA-008: GitHub Advisory Deep Parsing
**Objective**: Parse GitHub Security Advisory (GHSA) data beyond basic metadata, extracting affected version ranges, patched versions, dependency chains, and CVE cross-references to build a complete vulnerability impact matrix
**Severity**: MEDIUM
**Prerequisites**: GitHub API token, Python requests library, familiarity with GitHub Advisory GraphQL schema

**Remediation**: Enable GitHub Dependabot alerts and security updates for automated advisory processing; use GHSA data to drive automated patch management pipelines; implement dependency pinning and lockfile validation to reduce advisory surface area

**Steps**:
1. Query GitHub Advisory API for a specific ecosystem:
   ```python
   import requests
   def fetch_advisories(ecosystem, severity="critical", per_page=100):
       url = f"https://api.github.com/advisories"
       params = {
           "ecosystem": ecosystem,
           "severity": severity,
           "per_page": per_page
       }
       headers = {"Accept": "application/vnd.github+json",
                  "Authorization": f"Bearer {GITHUB_TOKEN}"}
       all_advisories = []
       page = 1
       while True:
           params["page"] = page
           resp = requests.get(url, params=params, headers=headers, timeout=15)
           data = resp.json()
           if not data:
               break
           all_advisories.extend(data)
           page += 1
           time.sleep(1)
       return all_advisories
   ```
2. For each advisory, extract nested fields:
   - `vulnerabilities[].package.ecosystem` and `.name`
   - `vulnerabilities[].vulnerable_version_range`
   - `vulnerabilities[].patched_versions` and `.first_patched_version`
3. Build an impact matrix: package -> affected versions -> advisory -> severity
4. Cross-reference with CVE IDs and NVD data
5. Identify packages with no patched version available
6. Export as JSON and CSV for integration with dependency management tools

**Expected Output**: Structured advisory database with version impact ranges, patched versions, and zero-patch package list

**Pass Criteria**:
- [ ] All advisories for target ecosystem fetched with pagination
- [ ] Affected version ranges parsed and validated
- [ ] Patched versions extracted with version identifiers
- [ ] Packages with no available patch identified and flagged
- [ ] CVE cross-references matched against NVD records

## TC-DSA-009: RSS Feed Vulnerability Monitoring
**Objective**: Set up continuous monitoring of security advisory RSS feeds from multiple sources (NVD, vendor bulletins, security blogs) to detect newly disclosed vulnerabilities within minutes of publication
**Severity**: MEDIUM
**Prerequisites**: Python 3.8+, feedparser library, scheduling mechanism (cron or asyncio), persistent storage for seen entries

**Remediation**: Implement automated RSS monitoring with alert thresholds based on CVSS severity; integrate with incident response workflows for critical disclosures; maintain feed redundancy across multiple sources to avoid single-point-of-failure in monitoring

**Steps**:
1. Configure RSS feed sources:
   ```python
   FEED_SOURCES = {
       "nvd_recent": "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml",
       "exploitdb": "https://www.exploit-db.com/rss.xml",
       "us_cert": "https://www.us-cert.gov/ncas/alerts.xml",
       "vendor_adobe": "https://helpx.adobe.com/security.html",
   }
   ```
2. Implement feed parser with deduplication:
   ```python
   import feedparser, hashlib, json
   from pathlib import Path

   class FeedMonitor:
       def __init__(self, state_file="seen_entries.json"):
           self.state_file = Path(state_file)
           self.seen = self._load_state()

       def _load_state(self):
           if self.state_file.exists():
               return set(json.loads(self.state_file.read_text()))
           return set()

       def check_feed(self, name, url):
           feed = feedparser.parse(url)
           new_entries = []
           for entry in feed.entries:
               entry_id = hashlib.md5(entry.get("id", entry.get("link", "")).encode()).hexdigest()
               if entry_id not in self.seen:
                   new_entries.append({
                       "source": name,
                       "title": entry.get("title", ""),
                       "link": entry.get("link", ""),
                       "date": entry.get("published", ""),
                       "summary": entry.get("summary", "")[:500]
                   })
                   self.seen.add(entry_id)
           self.state_file.write_text(json.dumps(list(self.seen)))
           return new_entries
   ```
3. Run monitoring loop at configurable intervals (5, 15, 60 minutes)
4. Filter new entries by severity keywords (critical, RCE, zero-day)
5. Generate alerts for high-priority findings
6. Store all new entries in timestamped log files

**Expected Output**: Stream of newly detected vulnerability disclosures with source attribution and severity classification

**Pass Criteria**:
- [ ] All configured RSS feeds parsed without errors
- [ ] Deduplication prevents duplicate alerts for same entry
- [ ] New entries detected within one monitoring interval
- [ ] Severity-based filtering correctly classifies critical findings
- [ ] State persistence survives monitoring restarts

## TC-DSA-010: CAPTCHA Handling and Rate Limit Bypass
**Objective**: Implement strategies for handling CAPTCHA challenges and rate-limiting mechanisms during web scraping, including detection of challenge pages, CAPTCHA type identification, service integration, and adaptive request throttling
**Severity**: MEDIUM
**Prerequisites**: Python 3.8+, Playwright or Selenium installed, optional CAPTCHA solving service API key (2captcha/anti-captcha), proxy infrastructure for IP rotation

**Remediation**: Respect website rate limits and robots.txt directives; implement server-side caching to reduce scraping frequency; use official APIs instead of web scraping when available; obtain explicit authorization before scraping authenticated or protected endpoints

**Steps**:
1. Detect CAPTCHA challenge pages automatically:
   ```python
   CAPTCHA_INDICATORS = [
       "recaptcha", "g-recaptcha", "hcaptcha", "h-captcha",
       "cf-challenge", "cf-turnstile", "captcha",
       "please verify you are human", "are you a robot"
   ]

   def detect_captcha(page):
       content = page.content().lower()
       for indicator in CAPTCHA_INDICATORS:
           if indicator in content:
               return {"detected": True, "type": indicator}
       return {"detected": False}
   ```
2. Identify CAPTCHA type (reCAPTCHA v2/v3, hCaptcha, Cloudflare Turnstile)
3. Extract site key for solving service integration:
   ```python
   site_key = page.evaluate("""
       document.querySelector('.g-recaptcha')?.getAttribute('data-sitekey') ||
       document.querySelector('[data-sitekey]')?.getAttribute('data-sitekey') ||
       document.querySelector('iframe[src*="recaptcha"]')?.src.match(/k=([^&]+)/)?.[1]
   """)
   ```
4. Implement adaptive rate limiting:
   ```python
   import time, random
   class AdaptiveThrottle:
       def __init__(self, base_delay=2.0, max_delay=30.0):
           self.base_delay = base_delay
           self.max_delay = max_delay
           self.consecutive_blocks = 0

       def wait(self):
           if self.consecutive_blocks > 0:
               delay = min(self.base_delay * (2 ** self.consecutive_blocks), self.max_delay)
               jitter = random.uniform(0, delay * 0.3)
               time.sleep(delay + jitter)
           else:
               time.sleep(self.base_delay + random.uniform(0, 1))

       def on_success(self):
           self.consecutive_blocks = max(0, self.consecutive_blocks - 1)

       def on_block(self):
           self.consecutive_blocks += 1
   ```
5. Test with proxy rotation when rate-limited
6. Document which anti-bot mechanisms were encountered and how they were handled

**Expected Output**: Scraping completion report with CAPTCHA encounters, solving results, and rate limit status

**Pass Criteria**:
- [ ] CAPTCHA challenge pages detected with type identification
- [ ] Site key extracted for solving service integration
- [ ] Adaptive throttle increases delay on 429/block responses
- [ ] Proxy rotation triggered when IP-based blocking detected
- [ ] All target pages scraped within acceptable time bounds
