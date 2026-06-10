# Corporate Reconnaissance Techniques Guide

## Introduction

Corporate reconnaissance maps an organization's digital footprint: domains, subdomains, IP ranges, employee profiles, technology stack, and business relationships. This guide covers passive and semi-passive techniques for building comprehensive target profiles suitable for penetration testing engagements, red team operations, and security assessments.

The techniques presented here operate on a spectrum from fully passive (no direct interaction with target systems) to semi-passive (interactions that mimic normal user traffic). Understanding this distinction is critical for engagement planning and rules of engagement compliance.

### Reconnaissance Phase Overview

| Phase | Technique | Noise Level | Data Yield |
|-------|-----------|-------------|-----------|
| Passive DNS | Certificate transparency, WHOIS | None | Domains, subdomains, IP history |
| Passive Web | Search engines, cached pages | None | Technologies, content, relationships |
| Semi-passive DNS | Direct queries, resolution | Very low | Full DNS records, zone data |
| Semi-passive Web | HTTP probing, fingerprinting | Low | Live services, software versions |
| Active scanning | Port scanning, vulnerability probing | High | Open ports, vulnerabilities |

## Practical Steps

### 1. Domain and Subdomain Enumeration

```bash
# Passive subdomain enumeration via certificate transparency
curl -s "https://crt.sh/?q=%25.target.com&output=json" | \
  jq -r '.[].name_value' | sort -u > subdomains.txt

# DNS brute force with resolved IPs
subfinder -d target.com -silent | \
  httpx -silent -status-code -title -tech-detect | \
  column -t -s' '

# Reverse DNS on known IP ranges
for ip in $(seq 1 254); do
  host 10.0.1.$ip 2>/dev/null | grep "domain name pointer"
done
```

### 2. Technology Fingerprinting

```bash
# Web technology detection
whatweb -v https://target.com

# Wappali CLI for bulk detection
wappalyzer https://target.com | jq '.technologies[].name'

# Header analysis for security posture
curl -sI https://target.com | grep -iE \
  "server:|x-powered-by:|x-frame|x-content|strict-transport|content-security"
```

### 3. Employee and Role Mapping

```python
# LinkedIn-derived org chart (OSINT, no scraping)
ROLE_KEYWORDS = [
    "IT Administrator", "DevOps Engineer", "Security Analyst",
    "System Administrator", "Network Engineer", "CTO", "CISO",
]

def build_org_profile(employees):
    """Map key personnel and their technology exposure."""
    profiles = []
    for emp in employees:
        role_tech_map = infer_tech_stack(emp.get("role", ""))
        profiles.append({
            "name": emp["name"],
            "role": emp["role"],
            "likely_access": role_tech_map,
            "social_accounts": find_social_handles(emp["name"]),
        })
    return profiles
```

### 4. Business Relationship Mapping

```bash
# Third-party and vendor discovery
# Check DNS MX records for email providers
dig +short target.com MX

# SPF records reveal authorized senders (often third-party)
dig +short target.com TXT | grep spf

# Analyze TLS certificates for related domains
openssl s_client -connect target.com:443 </dev/null 2>/dev/null | \
  openssl x509 -noout -text | grep -A1 "Subject Alternative Name"
```

### 5. Data Aggregation Template

```python
RECON_TEMPLATE = {
    "organization": "target.com",
    "domains": [],
    "subdomains": {"count": 0, "live": [], "technologies": {}},
    "ip_ranges": [],
    "email_patterns": "{first}.{last}@target.com",
    "key_personnel": [],
    "tech_stack": {"frontend": [], "backend": [], "infrastructure": []},
    "third_parties": [],
    "security_posture": {
        "spf": False, "dmarc": False, "dkim": False,
        "security_headers": {}, "csp_domains": [],
    },
}
```

### 6. Code Repository Discovery

```bash
# Find organization's public repositories
github-dorks -u targetorg -o results.txt

# Search for leaked secrets in repos
trufflehog github --org=targetorg --only-verified

# Find related repositories by email domain
curl -s "https://api.github.com/search/users?q=target.com+in:email" | \
  jq '.items[].login'
```

### 7. Cloud Asset Discovery

```bash
# Discover cloud storage buckets (AWS S3, Azure Blob, GCP)
# AWS S3 bucket enumeration
for word in $(cat /usr/share/seclists/Discovery/WebContent/common.txt); do
    if curl -s "https://$word.s3.amazonaws.com" | grep -q "ListBucketResult"; then
        echo "[FOUND] $word.s3.amazonaws.com"
    fi
done

# Azure blob storage discovery
for word in $(cat /usr/share/seclists/Discovery/WebContent/common.txt); do
    status=$(curl -s -o /dev/null -w "%{http_code}" "https://$word.blob.core.windows.net")
    if [ "$status" != "404" ]; then
        echo "[CHECK] $word.blob.core.windows.net -> $status"
    fi
done

# Google Cloud Storage
curl -s "https://storage.googleapis.com/storage/v1/b?project=target-project" | jq '.items[].name'
```

### 8. Document Metadata Extraction

```bash
# Discover and analyze publicly available documents for metadata
# Find document links on the target website
curl -s https://target.com | grep -oP 'href="[^"]*\.(pdf|docx|xlsx|pptx)"' | \
    sed 's/href="//;s/"//' > document_links.txt

# Extract metadata from PDFs
while IFS= read -r url; do
    wget -q "$url" -O /tmp/doc.pdf 2>/dev/null
    exiftool /tmp/doc.pdf | grep -iE "author|creator|producer|modifydate|createdate"
done < document_links.txt

# Check for tracked changes in Office documents
python3 -c "
import olefile
ole = olefile.OleFileIO('/tmp/doc.docx')
meta = ole.get_metadata()
print(f'Author: {meta.author}')
print(f'Last Modified: {meta.last_modified_by}')
print(f'Created: {meta.create_time}')
print(f'Modified: {meta.last_saved_time}')
"
```

## Corporate Structure Analysis

Understanding an organization's legal structure reveals subsidiaries, joint ventures, and brand names that expand the attack surface far beyond the primary domain.

### Subsidiary and Brand Discovery

```bash
# Query OpenCorporates for corporate relationships
curl -s "https://api.opencorporates.com/v0.4/companies/search?q=Target+Corp&jurisdiction_code=us_de" | \
  jq '.results.companies[] | {name: .company.name, number: .company.company_number, status: .company.current_status}'

# Cross-reference with trademark databases
curl -s "https://developer.uspto.gov/ trademark/v1/trademarkSearch?query=target+corp&start=0&rows=50" | \
  jq '.results[] | {mark: .markName, owner: .currentOwner, status: .status}'
```

### Organizational Hierarchy Mapping

```python
def map_corporate_structure(entity_name, depth=2):
    """Recursively discover corporate relationships."""
    structure = {
        "parent": None,
        "subsidiaries": [],
        "brands": [],
        "domains": [],
    }

    # Check Crunchbase-style data for acquisitions
    acquisitions = query_acquisitions(entity_name)
    for acq in acquisitions:
        structure["subsidiaries"].append({
            "name": acq["company"],
            "date": acq["date"],
            "domains": discover_domains(acq["company"]),
        })

    # Map brand names to domain portfolios
    for sub in structure["subsidiaries"]:
        for domain in sub["domains"]:
            structure["domains"].append({
                "domain": domain,
                "entity": sub["name"],
                "relationship": "subsidiary",
            })

    return structure
```

### Key Data Sources for Corporate Mapping

- **SEC EDGAR**: Public company filings, 10-K annual reports, 10-Q quarterly reports
- **OpenCorporates**: Global corporate registry data with parent-subsidiary links
- **Crunchbase**: Startup and acquisition data, funding rounds
- **LinkedIn Company Pages**: Employee counts, locations, acquisitions
- **Trademark Databases (USPTO, EUIPO)**: Brand names and owning entities
- **Wikipedia**: Often lists major subsidiaries and brands for large corporations

## Financial OSINT

Public financial documents are a goldmine for understanding organizational structure, risk factors, technology investments, and vendor relationships.

### SEC Filing Analysis

```python
def analyze_sec_filings(ticker, filing_type="10-K"):
    """Extract intelligence from SEC filings."""
    import re

    # Fetch latest filing from SEC EDGAR
    filing_url = get_latest_filing_url(ticker, filing_type)
    filing_text = fetch_filing(filing_url)

    intel = {
        "subsidiaries": extract_section(filing_text, "Exhibit 21"),
        "risk_factors": extract_section(filing_text, "Risk Factors"),
        "cyber_incidents": find_keywords(filing_text, [
            "cyber", "data breach", "ransomware", "incident",
            "vulnerability", "security", "encryption",
        ]),
        "technology_investments": find_keywords(filing_text, [
            "cloud", "migration", "digital transformation",
            "infrastructure", "platform", "SaaS",
        ]),
        "vendors": extract_vendor_mentions(filing_text),
    }
    return intel
```

### Annual Report Intelligence Extraction

Focus areas when reading annual reports and investor presentations:

- **Risk Factors**: Mention of past breaches, regulatory compliance concerns, technology debt
- **IT Budget Allocation**: References to cloud migration, security spending, digital transformation
- **Geographic Operations**: Countries and regions with offices, data centers, or legal entities
- **Key Partnerships**: Technology vendors, cloud providers, managed service providers
- **Acquisition Strategy**: Recently acquired companies and their technology stacks
- **Regulatory Environment**: Compliance frameworks (SOC 2, HIPAA, PCI-DSS) that suggest technology requirements

### Financial Statement Red Flags for Security Assessors

- Rapid growth without corresponding IT budget increases (potential technical debt)
- Recent acquisitions with integration costs (potential network merging issues)
- Regulatory fines or settlements (indicates compliance gaps)
- Significant outsourcing (expanded third-party attack surface)

## Supply Chain Reconnaissance

Mapping the supply chain reveals third-party vendors, service providers, and dependencies that often provide alternative paths into the target organization.

### Vendor Discovery Techniques

```bash
# SPF record parsing reveals email service providers
dig +short target.com TXT | grep spf | parse_spf_includes

# DMARC reporting domain (rua/ruf) reveals email security vendor
dig +short _dmarc.target.com TXT

# DNS delegation reveals hosting and DNS providers
dig +short target.com NS
whois target.com | grep -i "registrar\|name server"

# Check for CDN/WAF providers
curl -sI https://target.com | grep -i "cf-ray\|x-amz\|x-akamai\|x-fastly\|x-sucuri"
```

### Supply Chain Mapping Template

```python
SUPPLY_CHAIN_TEMPLATE = {
    "dns_provider": None,
    "hosting_provider": None,
    "cdn_provider": None,
    "waf_provider": None,
    "email_provider": None,
    "email_security_vendor": None,
    "certificate_authority": None,
    "registrars": [],
    "saas_tools": [],       # Discovered via DNS records, headers, JS includes
    "monitoring_tools": [],  # Statuspage, PagerDuty, etc.
    "payment_processor": None,
    "analytics_providers": [],
    "support_platform": None,
    "crm_platform": None,
}
```

### Technology Dependency Discovery

```bash
# Discover third-party JavaScript dependencies
curl -s https://target.com | grep -oP 'src="https?://[^"]*\.js[^"]*"' | \
  sed 's/src="//;s/"//' | awk -F/ '{print $3}' | sort -u

# Identify SaaS platforms from DNS records
# Many SaaS tools create CNAME records
dig +short target.com CNAME
dig +short crm.target.com CNAME
dig +short support.target.com CNAME
dig +short status.target.com CNAME
dig +short mail.target.com CNAME
```

## Technology Stack Fingerprinting

Going beyond basic tool detection to build a complete picture of the target's technology ecosystem.

### Comprehensive Stack Detection

```bash
# Wappalyzer deep scan with version detection
wappalyzer https://target.com --all --pretty | jq '.'

# Whatweb with aggressive plugins
whatweb -a 3 -v https://target.com

# BuiltWith API integration for detailed stack data
curl -s "https://api.builtwith.com/v21/api.json?KEY=$BW_KEY&LOOKUP=target.com" | \
  jq '.domains[0].technologies[] | {name: .name, category: .category, version: .version}'
```

### Infrastructure Stack Correlation

```python
def correlate_tech_stack(subdomains_data):
    """Correlate technology stacks across subdomains to identify patterns."""
    stack_map = {}

    for subdomain, tech_list in subdomains_data.items():
        for tech in tech_list:
            stack_map.setdefault(tech["name"], []).append({
                "subdomain": subdomain,
                "version": tech.get("version"),
                "category": tech.get("category"),
            })

    # Identify common infrastructure patterns
    common_techs = {
        tech: locs for tech, locs in stack_map.items()
        if len(locs) > 3
    }

    return {
        "technology_distribution": stack_map,
        "common_infrastructure": common_techs,
        "version_diversity": analyze_version_spread(stack_map),
        "outdated_count": count_outdated_versions(stack_map),
    }
```

## Employee Enumeration Techniques

### Email Pattern Discovery

Determining the email naming convention is critical for phishing assessments and credential checking:

```python
def discover_email_pattern(known_emails):
    """Analyze known email addresses to determine naming convention."""
    patterns = {}

    for email in known_emails:
        local_part = email.split("@")[0]

        if "." in local_part:
            parts = local_part.split(".")
            if len(parts) == 2:
                patterns.setdefault("first.last", []).append(email)
        elif "_" in local_part:
            patterns.setdefault("first_last", []).append(email)
        else:
            patterns.setdefault("other", []).append(email)

    dominant_pattern = max(patterns, key=lambda k: len(patterns[k]))
    return {
        "pattern": dominant_pattern,
        "confidence": len(patterns.get(dominant_pattern, [])) / len(known_emails),
        "examples": patterns.get(dominant_pattern, [])[:5],
    }
```

### Email Generation for Credential Checking

```python
def generate_email_list(employees, domain, pattern="first.last"):
    """Generate email list based on naming convention and employee names."""
    emails = []
    for emp in employees:
        first = emp.get("first_name", "").lower().replace(" ", "")
        last = emp.get("last_name", "").lower().replace(" ", "")
        fi = first[0] if first else ""
        li = last[0] if last else ""

        if pattern == "first.last":
            emails.append(f"{first}.{last}@{domain}")
        elif pattern == "f.last":
            emails.append(f"{fi}.{last}@{domain}")
        elif pattern == "firstl":
            emails.append(f"{first}{li}@{domain}")
        elif pattern == "flast":
            emails.append(f"{fi}{last}@{domain}")
        elif pattern == "first_last":
            emails.append(f"{first}_{last}@{domain}")
        elif pattern == "firstlast":
            emails.append(f"{first}{last}@{domain}")

    return emails
```

### Social Media Cross-Reference

```python
def enumerate_social_presence(employee_name):
    """Check multiple platforms for employee social accounts."""
    platforms = {
        "twitter": f"https://twitter.com/search?q={employee_name}",
        "github": f"https://api.github.com/search/users?q={employee_name}+in:fullname",
        "keybase": f"https://keybase.io/_/api/1.0/user/lookup.json?query={employee_name}",
    }

    results = {}
    for platform, url in platforms.items():
        response = safe_request(url)
        if response and has_match(response, employee_name):
            results[platform] = extract_profile(response)

    return results
```

## Domain and IP Correlation

### ASN-Based Asset Discovery

```bash
# Discover all IP ranges belonging to an ASN
whois -h whois.radb.net -- "-i origin AS12345" | grep route

# Find all ASNs associated with the organization
amass intel -org "Target Corporation" -whois

# Map IP ranges to cloud providers
for cidr in $(cat ip_ranges.txt); do
  provider=$(identify_provider "$cidr")
  echo "$cidr -> $provider"
done
```

### IP Geolocation and Infrastructure Mapping

```python
def map_ip_infrastructure(ip_ranges):
    """Map IP ranges to geographic locations and cloud providers."""
    infrastructure_map = {
        "cloud_providers": {},
        "data_centers": [],
        "cdn_edges": [],
        "office_locations": [],
    }

    for cidr in ip_ranges:
        metadata = query_ip_metadata(cidr)
        provider = metadata.get("org_name", "unknown")

        infrastructure_map["cloud_providers"].setdefault(provider, []).append({
            "cidr": cidr,
            "country": metadata.get("country"),
            "city": metadata.get("city"),
            "asn": metadata.get("asn"),
        })

    return infrastructure_map
```

### Historical DNS Analysis

```bash
# Query PassiveTotal for historical DNS records
curl -s -u "$PT_USER:$PT_KEY" \
  "https://api.passivetotal.org/v2/dns/passive?query=target.com" | \
  jq '.results[] | {name: .resolve, type: .recordType, value: .resolve, first: .firstSeen, last: .lastSeen}'

# Check SecurityTrails for historical records
curl -s -H "APIKey: $ST_KEY" \
  "https://api.securitytrails.com/v1/history/target.com/dns/a" | \
  jq '.records[] | {ip: .values[0].ip, seen: .first_seen}'
```

## Comprehensive Recon Report Template

### Report Generation Script

```python
"""Generate a comprehensive corporate reconnaissance report."""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
import json

@dataclass(frozen=True)
class ReconReport:
    target_organization: str
    assessment_date: str
    assessor: str
    scope: list[str]
    executive_summary: str
    domain_findings: list[dict] = field(default_factory=list)
    subdomain_findings: list[dict] = field(default_factory=list)
    technology_findings: list[dict] = field(default_factory=list)
    personnel_findings: list[dict] = field(default_factory=list)
    supply_chain_findings: list[dict] = field(default_factory=list)
    security_posture: dict = field(default_factory=dict)
    recommendations: list[str] = field(default_factory=list)

def generate_recon_report(data: dict) -> ReconReport:
    """Compile all findings into a structured report."""
    return ReconReport(
        target_organization=data["organization"],
        assessment_date=datetime.utcnow().strftime("%Y-%m-%d"),
        assessor=data.get("assessor", "OSINT Team"),
        scope=data.get("scope", []),
        executive_summary=build_executive_summary(data),
        domain_findings=data.get("domains", []),
        subdomain_findings=data.get("subdomains", []),
        technology_findings=data.get("technologies", []),
        personnel_findings=data.get("personnel", []),
        supply_chain_findings=data.get("supply_chain", []),
        security_posture=assess_posture(data),
        recommendations=prioritize_recommendations(data),
    )

def assess_posture(data: dict) -> dict:
    """Assess overall security posture based on findings."""
    posture = {
        "spf_configured": False,
        "dmarc_configured": False,
        "dkim_configured": False,
        "security_headers_score": 0,
        "exposed_services_count": 0,
        "dev_environment_exposed": False,
        "admin_panels_public": False,
    }

    # Evaluate email security
    for sub in data.get("subdomains", []):
        if sub.get("is_admin"):
            posture["admin_panels_public"] = True
        if "dev" in sub.get("name", "").lower():
            posture["dev_environment_exposed"] = True

    return posture

def prioritize_recommendations(data: dict) -> list[str]:
    """Generate prioritized recommendations based on findings."""
    recs = []

    posture = assess_posture(data)

    if posture["dev_environment_exposed"]:
        recs.append("CRITICAL: Restrict access to development environments via VPN or IP whitelist")
    if posture["admin_panels_public"]:
        recs.append("HIGH: Move admin interfaces behind authentication or VPN")
    if not posture["spf_configured"]:
        recs.append("HIGH: Configure SPF records to prevent email spoofing")
    if not posture["dmarc_configured"]:
        recs.append("MEDIUM: Implement DMARC policy with p=reject")

    return recs

def report_to_markdown(report: ReconReport) -> str:
    """Convert report to markdown format."""
    lines = [
        f"# Corporate Reconnaissance Report: {report.target_organization}",
        f"**Date**: {report.assessment_date}",
        f"**Assessor**: {report.assessor}",
        "",
        "## Executive Summary",
        report.executive_summary,
        "",
        "## Security Posture Assessment",
        f"- SPF Configured: {'Yes' if report.security_posture.get('spf_configured') else 'No'}",
        f"- DMARC Configured: {'Yes' if report.security_posture.get('dmarc_configured') else 'No'}",
        f"- Dev Environment Exposed: {'Yes' if report.security_posture.get('dev_environment_exposed') else 'No'}",
        f"- Admin Panels Public: {'Yes' if report.security_posture.get('admin_panels_public') else 'No'}",
        "",
        "## Recommendations",
    ]
    for rec in report.recommendations:
        lines.append(f"- {rec}")

    lines.extend([
        "",
        "## Findings Detail",
        f"- Domains: {len(report.domain_findings)}",
        f"- Subdomains: {len(report.subdomain_findings)}",
        f"- Technologies: {len(report.technology_findings)}",
        f"- Personnel: {len(report.personnel_findings)}",
        f"- Supply Chain: {len(report.supply_chain_findings)}",
    ])

    return "\n".join(lines)
```

## Advanced Correlation Techniques

### Cross-Platform Identity Resolution

```python
"""Correlate employee identities across multiple platforms."""

@dataclass(frozen=True)
class Identity:
    name: str
    email: str | None
    platforms: dict  # platform -> profile_url
    confidence: float
    aliases: list[str]

def resolve_identity(name: str, employer: str) -> Identity:
    """Attempt to resolve a single person across multiple platforms."""
    platforms = {}
    aliases = [name]

    # GitHub search
    gh_results = search_github_users(name, employer)
    if gh_results:
        primary = gh_results[0]
        platforms["github"] = primary["html_url"]
        if primary.get("email"):
            aliases.append(primary["email"])

    # Gravatar / email hash
    if platforms.get("github"):
        email = extract_github_email(primary["login"])
        if email:
            gravatar_url = compute_gravatar_url(email)
            if verify_gravatar_exists(gravatar_url):
                platforms["gravatar"] = gravatar_url

    # Keybase
    kb_results = search_keybase(name)
    if kb_results:
        platforms["keybase"] = f"https://keybase.io/{kb_results[0]['basics']['username']}"

    return Identity(
        name=name,
        email=extract_github_email(primary.get("login", "")) if gh_results else None,
        platforms=platforms,
        confidence=calculate_identity_confidence(platforms),
        aliases=aliases,
    )

def calculate_identity_confidence(platforms: dict) -> float:
    """Score identity confidence based on number of correlated platforms."""
    base = 0.3
    per_platform = 0.15
    return min(base + len(platforms) * per_platform, 1.0)
```

## Hands-on Exercises

Practice the techniques described in this guide against authorized targets or lab environments. Document your findings and methodology for each exercise.
## References

- [OWASP -- Information Gathering](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/)
- [MITRE -- Reconnaissance Tactics](https://attack.mitre.org/tactics/TA0043/)
- [Subfinder Documentation](https://github.com/projectdiscovery/subfinder)
- [crt.sh -- Certificate Transparency](https://crt.sh/)
- [SEC EDGAR Filing Search](https://www.sec.gov/cgi-bin/browse-edgar)
- [OpenCorporates API](https://api.opencorporates.com/)
- [BuiltWith Technology Tracker](https://builtwith.com/)
