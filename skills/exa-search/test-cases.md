# Exa Search Test Cases

## TC-ES-001: CVE Research
**Objective**: Find recent CVEs for a product

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
