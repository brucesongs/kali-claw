# Exa Search Test Cases

## TC-ES-001: CVE Research
**Objective**: Find recent CVEs for a product
**Prerequisites**: Exa API key configured, Python requests library or curl available
**Severity**: HIGH

**Remediation**: Cross-reference findings with NVD and vendor advisories; validate exploitability before reporting

**Query**: "CVE-2024 affecting nginx"

**Steps**:
1. Submit query to Exa API
2. Filter by date (last 90 days)
3. Extract CVE IDs and descriptions
4. Verify results are relevant

**Expected Output**: 5-10 relevant CVE articles/advisories

**Pass Criteria**:
- [ ] Results mention nginx
- [ ] Results from last 90 days
- [ ] CVE IDs extracted

## TC-ES-002: Exploit Technique Research
**Objective**: Research bypass techniques for a specific protection
**Severity**: HIGH
**Prerequisites**: Exa API key configured, Python requests library or curl available

**Remediation**: Cross-reference findings with vendor documentation and security best practices; validate bypass techniques in isolated lab environments before incorporating into assessments; maintain ethical use boundaries when researching exploit methodologies

**Query**: "SSRF bypass techniques cloud metadata"

**Steps**:
1. Submit query with domain filter (github.com, portswigger.net)
2. Get full text content
3. Extract techniques mentioned
4. Store in knowledge-ops

**Expected Output**: Technical articles with PoC code

**Pass Criteria**:
- [ ] Results contain PoC or techniques
- [ ] Content from trusted domains
- [ ] Actionable information for testing

## TC-EX-003: Vulnerability Disclosure Monitoring Workflow
**Objective**: Continuously monitor for new vulnerability disclosures affecting a target technology stack and track CVEs from advisory to public exploit
**Severity**: HIGH
**Prerequisites**: Exa API key configured, Python with exa_py SDK, list of target technology products to monitor

**Remediation**: Implement automated vulnerability monitoring with alerting for critical disclosures; maintain an asset inventory mapping technology stack to CVE exposure; establish SLA for triaging newly disclosed vulnerabilities (24 hours for critical)

**Query**: "critical vulnerability disclosed Apache Struts remote code execution 2024"

**Steps**:
1. Configure target products list (e.g., Apache Struts, nginx, Kubernetes)
2. Submit neural search query with date filter (last 14 days)
3. Filter results to advisory sources (nvd.nist.gov, github.com/advisories, vendor blogs)
4. Extract CVE IDs from result text using regex pattern
5. For each CVE found, run follow-up search for proof-of-concept code
6. Cross-reference with exploit databases (exploit-db.com, packetstormsecurity.com)
7. Classify findings by severity (Critical/High/Medium/Low)
8. Generate timeline from disclosure to exploit availability

**Expected Output**: Structured report containing 3-10 new CVEs with severity ratings, affected versions, exploit availability status, and links to advisories and PoCs

**Pass Criteria**:
- [ ] CVE IDs correctly extracted and validated (format CVE-YYYY-NNNNN)
- [ ] Results are within the specified date window
- [ ] Advisory sources are authoritative (NVD, vendor, CERT)
- [ ] Exploit availability status accurately determined
- [ ] Severity classification matches CVSS score where available
- [ ] No false positives (unrelated CVEs filtered out)

## TC-EX-004: Attack Surface Discovery via Search
**Objective**: Map an organization's external attack surface by discovering subdomains, shadow IT services, exposed infrastructure, and technology stack through search intelligence
**Severity**: HIGH
**Prerequisites**: Exa API key configured, Python with exa_py SDK, target organization domain name and legal authorization for passive reconnaissance

**Remediation**: Maintain comprehensive asset inventory with regular external attack surface assessments; implement subdomain monitoring with alerting for new discoveries; decommission or secure forgotten staging/dev environments; enforce cloud resource tagging and governance policies

**Query**: "target.com staging dev internal portal admin dashboard"

**Steps**:
1. Define target organization (domain and name)
2. Run keyword search for subdomains using site:*.target.com pattern
3. Run neural search for shadow IT (staging environments, dev servers, admin panels)
4. Search for technology stack indicators via job postings and engineering blogs
5. Search for exposed configuration files and cloud storage references
6. Run find_similar against the main corporate site to discover related domains
7. Search for acquisition and subsidiary information to expand scope
8. Deduplicate results by domain and categorize by service type
9. Validate discovered assets are actually associated with the target

**Expected Output**: Asset inventory containing discovered subdomains, shadow services, technology stack components, related domains, and potential exposure points with confidence ratings

**Pass Criteria**:
- [ ] Discovered at least 5 unique subdomains or related services
- [ ] Shadow IT services identified with URLs and descriptions
- [ ] Technology stack components extracted from job postings or docs
- [ ] Results deduplicated (no duplicate domains in output)
- [ ] Each finding categorized (subdomain/shadow-IT/cloud/acquisition)
- [ ] False positives below 20% (validated association with target)
- [ ] No active scanning performed (passive search only)

## TC-EX-005: Threat Intelligence Aggregation
**Objective**: Aggregate threat intelligence on a specific APT group or malware family, extracting IOCs, TTPs, and campaign timelines from multiple sources
**Severity**: HIGH
**Prerequisites**: Exa API key configured, Python with exa_py SDK and regex libraries, familiarity with MITRE ATT&CK framework and IOC formats

**Remediation**: Integrate threat intelligence feeds into SIEM and SOAR platforms for automated detection; map TTPs to MITRE ATT&CK for standardized reporting; validate IOCs against internal telemetry before creating blocking rules; maintain threat actor profiles with regular updates

**Query**: "APT29 Cozy Bear campaign 2024 indicators compromise techniques"

**Steps**:
1. Define threat actor or malware family to research
2. Submit neural search targeting threat intel vendors (Mandiant, CrowdStrike, Securelist)
3. Extract full text content from top 15 results
4. Parse IOCs from text using regex (IPs, domains, SHA256 hashes, URLs)
5. Extract MITRE ATT&CK technique IDs (T####.###) from reports
6. Search for related campaigns and aliases of the same actor
7. Build timeline of campaign activity from publication dates
8. Cross-reference IOCs across multiple reports for confidence scoring
9. Compile final intelligence package with deduplicated IOCs and TTP mapping

**Expected Output**: Threat intelligence package containing validated IOCs (IPs, domains, hashes), mapped MITRE ATT&CK techniques, campaign timeline, and source attribution with confidence levels

**Pass Criteria**:
- [ ] IOCs extracted in correct format (valid IPs, proper hash lengths)
- [ ] At least 3 distinct IOC types found (IP, domain, hash minimum)
- [ ] MITRE ATT&CK technique IDs valid and relevant to actor
- [ ] Campaign timeline has at least 3 dated data points
- [ ] Sources are from reputable threat intel providers
- [ ] IOCs appearing in multiple reports flagged as high-confidence
- [ ] No IOCs from unrelated threat actors included (precision check)

## TC-ES-006: Vendor Advisory Search and Patch Intelligence
**Objective**: Systematically search for and collect vendor security advisories for a specific technology stack, extract patch availability and version information, and generate a prioritized patching schedule based on CVSS severity and exploit availability
**Severity**: HIGH
**Prerequisites**: Exa API key configured, list of target vendor domains, Python with exa_py SDK

**Remediation**: Subscribe to vendor security notification services (RSS, email); implement automated patch management for non-breaking updates; maintain an asset inventory that maps vendor advisories to deployed software versions; establish SLA targets for critical patch deployment (48 hours for actively exploited CVEs)

**Steps**:
1. Define target vendor domains and product list:
   ```python
   vendors = {
       "microsoft": ["msrc.microsoft.com"],
       "adobe": ["helpx.adobe.com"],
       "oracle": ["oracle.com/security"],
       "redhat": ["access.redhat.com"],
       "apache": ["lists.apache.org", "httpd.apache.org"],
   }
   ```
2. For each vendor, submit a neural search for recent security bulletins:
   ```python
   from exa_py import Exa
   exa = Exa(api_key="your_api_key")
   for vendor, domains in vendors.items():
       results = exa.search_and_contents(
           f"{vendor} security advisory critical vulnerability patch",
           type="neural",
           num_results=15,
           include_domains=domains,
           start_published_date="2024-01-01",
           text=True,
           highlights={"num_sentences": 3}
       )
   ```
3. Extract CVE IDs, affected versions, and patch versions from each result
4. Cross-reference each CVE with NVD for CVSS scores
5. Check exploit availability via Exploit-DB and GitHub
6. Generate prioritized patching schedule sorted by: CVSS > 9.0 with exploit available first
7. Export as CSV with columns: Vendor, CVE, CVSS, Affected Version, Patch Version, Exploit Status, Priority

**Expected Output**: Vendor advisory inventory with 10-30 advisories, patch availability status, and a prioritized remediation schedule

**Pass Criteria**:
- [ ] At least 5 vendor advisory sources queried successfully
- [ ] CVE IDs extracted in valid format (CVE-YYYY-NNNNN)
- [ ] Affected and patched version numbers documented for each advisory
- [ ] CVSS scores verified against NVD data
- [ ] Exploit availability status determined for each CVE
- [ ] Patching schedule sorted by risk priority (CVSS + exploit availability)

## TC-ES-007: Competitive Intelligence via Public Disclosure Analysis
**Objective**: Analyze publicly disclosed vulnerability reports and breach disclosures for competitor products to understand their security posture, common weakness patterns, and incident response timelines without any unauthorized access
**Severity**: MEDIUM
**Prerequisites**: Exa API key configured, list of competitor product names and vendor domains, Python with exa_py SDK

**Remediation**: Use competitive intelligence findings to improve your own security posture; benchmark your vulnerability disclosure timelines against industry peers; implement security measures that address common weaknesses found across the industry segment

**Steps**:
1. Define competitor products and their vendor domains
2. Search for vulnerability disclosures and security bulletins:
   ```python
   competitors = ["ProductA", "ProductB", "ProductC"]
   for product in competitors:
       results = exa.search_and_contents(
           f"{product} vulnerability disclosure security advisory CVE",
           type="neural",
           num_results=20,
           start_published_date="2024-01-01",
           text=True,
           highlights={"num_sentences": 3}
       )
   ```
3. For each product, extract: total CVE count, severity distribution, time-to-patch metrics
4. Identify common CWE categories across competitors
5. Build a comparative security posture matrix
6. Analyze breach disclosure timelines: detection to disclosure, disclosure to patch
7. Generate summary report with anonymized competitive benchmarks

**Expected Output**: Competitive security posture analysis with CVE counts, severity distributions, CWE patterns, and patch timeline benchmarks for 3+ competitor products

**Pass Criteria**:
- [ ] Vulnerability disclosures found for all specified competitors
- [ ] CVE count and severity distribution calculated per competitor
- [ ] Top 5 CWE categories identified across the competitive set
- [ ] Time-to-patch metrics extracted from disclosure-to-advisory dates
- [ ] All data sourced exclusively from public disclosures (no unauthorized access)

## TC-ES-008: API Cost Optimization Strategy
**Objective**: Optimize Exa API usage by implementing caching, query deduplication, batch processing, and result relevance scoring to minimize API calls while maximizing intelligence value per request
**Severity**: LOW
**Prerequisites**: Exa API key configured, Python with exa_py SDK, Redis or file-based cache, understanding of Exa pricing model

**Remediation**: Implement query result caching with configurable TTL; batch related queries to reduce total API calls; use keyword search for precise queries and neural search for exploratory research only; monitor API usage against budget thresholds

**Steps**:
1. Implement a caching layer for Exa search results:
   ```python
   import hashlib
   import json
   from datetime import datetime, timedelta
   from pathlib import Path

   class ExaCache:
       def __init__(self, cache_dir="exa_cache", default_ttl_hours=24):
           self.cache_dir = Path(cache_dir)
           self.cache_dir.mkdir(exist_ok=True)
           self.default_ttl = default_ttl_hours

       def _cache_key(self, query, **kwargs):
           params = json.dumps({"query": query, **kwargs}, sort_keys=True)
           return hashlib.sha256(params.encode()).hexdigest()

       def get(self, query, **kwargs):
           key = self._cache_key(query, **kwargs)
           cache_file = self.cache_dir / f"{key}.json"
           if cache_file.exists():
               age_hours = (datetime.now().timestamp() - cache_file.stat().st_mtime) / 3600
               if age_hours < self.default_ttl:
                   return json.loads(cache_file.read_text())
           return None

       def set(self, query, results, **kwargs):
           key = self._cache_key(query, **kwargs)
           cache_file = self.cache_dir / f"{key}.json"
           cache_file.write_text(json.dumps(results))

       def cached_search(self, exa_client, query, **kwargs):
           cached = self.get(query, **kwargs)
           if cached:
               return cached
           results = exa_client.search_and_contents(query, **kwargs)
           self.set(query, [r.__dict__ for r in results.results], **kwargs)
           return results
   ```
2. Deduplicate similar queries by normalizing query text
3. Use batch processing for related queries in a single search where possible
4. Track API call count and estimate costs per research session
5. Implement budget alerts when approaching usage thresholds

**Expected Output**: Cost-optimized search pipeline that reduces API calls by 30-50% through caching and deduplication

**Pass Criteria**:
- [ ] Cache layer stores and retrieves results correctly
- [ ] Cache hit rate >50% for repeated research topics
- [ ] Similar queries normalized to avoid redundant API calls
- [ ] API call count tracked and reported per research session
- [ ] Budget threshold alerts implemented and tested

## TC-ES-009: CVE-to-Exploit Rapid Assessment
**Objective**: For a given list of CVEs, rapidly determine exploit availability, proof-of-concept code existence, detection rule availability, and patch status by searching across multiple intelligence sources in a single automated pipeline
**Severity**: HIGH
**Prerequisites**: Exa API key configured, list of CVE IDs to assess, Python with exa_py SDK

**Remediation**: Automate CVE triage with risk scoring that factors in exploit availability; prioritize patching based on combined CVSS + exploit maturity + asset exposure; implement virtual patching via WAF/IPS rules for CVEs with public exploits where immediate patching is not possible

**Steps**:
1. Define the CVE list to assess (from scanner output or advisory feed)
2. For each CVE, execute parallel searches across intelligence sources:
   ```python
   def rapid_cve_assessment(cve_id):
       stages = {
           "advisory": {
               "query": f"{cve_id} official advisory affected versions",
               "domains": ["nvd.nist.gov", "cve.org", "github.com/advisories"],
               "type": "keyword"
           },
           "exploit": {
               "query": f"{cve_id} proof of concept exploit PoC code",
               "domains": ["github.com", "exploit-db.com", "packetstormsecurity.com"],
               "type": "neural"
           },
           "detection": {
               "query": f"{cve_id} detection YARA Sigma Snort Suricata rule",
               "domains": ["github.com", "rules.emergingthreats.net", "snort.org"],
               "type": "neural"
           },
           "discussion": {
               "query": f"{cve_id} analysis writeup technical details root cause",
               "domains": ["portswigger.net", "projectzero.org", "blog.cloudflare.com"],
               "type": "neural"
           }
       }

       results = {}
       for stage, config in stages.items():
           search_result = exa.search_and_contents(
               config["query"],
               type=config["type"],
               num_results=5,
               include_domains=config["domains"],
               text=True
           )
           results[stage] = [
               {"title": r.title, "url": r.url, "snippet": (r.text or "")[:300]}
               for r in search_result.results
           ]
       return results
   ```
3. Score each CVE: +3 for public exploit, +2 for PoC, +1 for detection rules, +2 for CVSS >9.0
4. Categorize: IMMEDIATE (score >= 7), SCHEDULED (4-6), MONITOR (0-3)
5. Generate executive summary with risk distribution

**Expected Output**: Structured CVE assessment report with exploit maturity scoring, detection coverage, and priority classification for each CVE

**Pass Criteria**:
- [ ] All CVEs assessed across all 4 intelligence stages
- [ ] Exploit availability accurately determined (PoC exists vs. theoretical)
- [ ] Detection rule coverage documented (YARA/Sigma/Snort availability)
- [ ] Risk scoring applied consistently across all CVEs
- [ ] Priority categories (IMMEDIATE/SCHEDULED/MONITOR) assigned with justification

## TC-ES-010: Dark Web Threat Intelligence Correlation
**Objective**: Search surface-web reporting and analysis of dark web activity to identify threats targeting a specific industry or organization, including data breach sales, initial access broker listings, and ransomware targeting patterns, without accessing dark web infrastructure directly
**Severity**: HIGH
**Prerequisites**: Exa API key configured, target industry or organization name, Python with exa_py SDK

**Remediation**: Monitor dark web threat intelligence reporting services proactively; implement data breach notification procedures aligned with regulatory requirements; deploy deception technology (honeypots, honeytokens) to detect unauthorized access; maintain incident response playbooks for dark web-related threats

**Steps**:
1. Define target industry (healthcare, finance, energy) or organization name
2. Search for breach reporting and data sale mentions:
   ```python
   def dark_web_threat_intel(target, days_back=30):
       from datetime import datetime, timedelta
       date_threshold = (datetime.now() - timedelta(days=days_back)).strftime("%Y-%m-%d")

       queries = {
           "data_breaches": {
               "query": f"{target} data breach stolen database sale leak",
               "domains": ["krebsonsecurity.com", "therecord.media",
                           "bleepingcomputer.com", "haveibeenpwned.com"],
           },
           "initial_access": {
               "query": f"{target} network access sale VPN credentials broker",
               "domains": ["flashpoint.io", "recordedfuture.com",
                           "kela.io", "intel471.com"],
           },
           "ransomware": {
               "query": f"{target} ransomware attack victim leak site",
               "domains": ["therecord.media", "bleepingcomputer.com",
                           "techcrunch.com", "databreaches.net"],
           },
           "phishing_kits": {
               "query": f"{target} phishing kit template credential harvesting",
               "domains": ["proofpoint.com", "campusguard.com",
                           "group-ib.com", "ironnet.com"],
           }
       }

       findings = {}
       for category, config in queries.items():
           results = exa.search_and_contents(
               config["query"],
               type="neural",
               num_results=10,
               start_published_date=date_threshold,
               include_domains=config["domains"],
               text=True,
               highlights={"num_sentences": 3}
           )
           findings[category] = [
               {"title": r.title, "url": r.url, "date": r.published_date,
                "summary": (r.text or "")[:500]}
               for r in results.results
           ]
       return findings
   ```
3. Extract IOCs from findings (domains, IPs, hashes mentioned in reports)
4. Cross-reference IOCs with internal logs and SIEM data
5. Generate threat brief with risk assessment and recommended actions

**Expected Output**: Dark web threat intelligence brief covering data breaches, initial access threats, ransomware targeting, and phishing kit activity for the target, with actionable IOCs

**Pass Criteria**:
- [ ] All 4 threat categories searched across reputable intelligence sources
- [ ] At least 5 relevant findings per category for active threats
- [ ] IOCs extracted and formatted for SIEM ingestion
- [ ] Findings sourced exclusively from surface-web reporting (no dark web access required)
- [ ] Risk assessment includes recommended defensive actions
