# Data Scraper Agent Test Cases

## TC-DSA-001: CVE Collection for Product
**Objective**: Collect all CVEs for a specific product

**Input**: Product name (e.g., "nginx")

**Steps**:
1. Query NVD API with product keyword
2. Parse JSON response
3. Extract CVE IDs, CVSS scores, descriptions
4. Store in structured format

**Expected Output**: List of CVEs with metadata

**Pass Criteria**:
- [ ] All CVEs returned from API
- [ ] CVSS scores extracted
- [ ] Data stored in knowledge-ops format

## TC-DSA-002: Exploit Availability Check
**Objective**: Check if public exploits exist for CVE list

**Input**: List of CVE IDs

**Steps**:
1. For each CVE, search Exploit-DB
2. Check GitHub for PoC repositories
3. Record exploit availability + link

**Expected Output**: Table of CVEs with exploit status

**Pass Criteria**:
- [ ] All CVEs checked
- [ ] Exploit links recorded
- [ ] No false positives
