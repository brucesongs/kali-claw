# Data Scraper Agent Test Cases

## TC-DSA-001: CVE Collection for Product
**Objective**: Collect all CVEs for a specific product
**Severity**: HIGH

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
