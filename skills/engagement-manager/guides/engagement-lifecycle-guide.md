# Engagement Lifecycle Guide

## Introduction

This guide covers the full lifecycle of a penetration testing engagement, from initial scoping through final report delivery. Each phase produces structured evidence that feeds into subsequent phases. Understanding the complete lifecycle is essential for managing engagements effectively, ensuring no phase is skipped, and maintaining the quality and integrity of the final deliverable.

A penetration testing engagement is not simply a series of technical tests — it is a structured project with defined inputs, outputs, quality gates, and stakeholder communication requirements. The engagement lifecycle provides the framework that connects technical testing activities with project management disciplines.

## Phase 1: Scoping and Planning

Define the engagement boundaries before any testing begins. Scoping is the most critical phase because mistakes here cascade through the entire engagement, potentially causing legal liability, production outages, or incomplete testing.

### Scope Definition Elements

- **Target inventory**: All IP ranges, domains, applications, and cloud resources to be tested
- **Exclusions**: Systems that must not be tested (production databases, third-party services, medical devices)
- **Testing windows**: When testing is permitted (business hours vs. after-hours vs. weekends)
- **Technique restrictions**: What is and is not allowed (no DoS, no social engineering, no data exfiltration)
- **Emergency procedures**: How to stop testing immediately if a critical issue is discovered
- **Communication plan**: Status update frequency, emergency contacts, and escalation paths
- **Authorization documentation**: Signed rules of engagement, statement of work, and NDA

### Planning Activities

1. Review scope document and identify target types (web, network, cloud, mobile, API)
2. Determine skill composition based on target types using the Skill Composition table
3. Estimate time requirements per phase based on target complexity
4. Prepare tool chain and verify all tools are available and configured
5. Create engagement workspace directory structure
6. Initialize checkpoint system for progress tracking

## Phase 2: Reconnaissance

Passive and active information gathering. Reconnaissance builds the target knowledge base that drives all subsequent phases. Thorough reconnaissance directly correlates with better testing outcomes.

### Passive Reconnaissance

- Subdomain enumeration using third-party data sources (subfinder, amass)
- Technology fingerprinting via HTTP headers and response analysis (whatweb, wappalyzer)
- Email harvesting from public sources (theHarvester)
- Document metadata extraction from publicly available files (metagoofil)
- Historical URL discovery from web archives (waybackurls, gau)

### Active Reconnaissance

- HTTP probing to identify live hosts and response codes (httpx)
- DNS enumeration to discover additional records and subdomains (dnsrecon)
- Certificate transparency log analysis for subdomain discovery

### Output and Handoff

Reconnaissance produces: subdomain lists, live host inventory, technology stack identification, email address lists, and historical URL collections. These feed directly into the scanning phase as target inputs.

## Phase 3: Scanning

Active service discovery and vulnerability scanning. Scanning converts the target inventory from reconnaissance into a detailed map of running services, open ports, and potential attack surfaces.

### Activities

- Full port scan to identify all listening services (nmap -sS -sV -p-)
- Service version detection to map software versions to known vulnerabilities
- Vulnerability scanning with template-based tools (nuclei, nikto)
- SSL/TLS security assessment for encrypted services (testssl)
- UDP scanning for services that only respond to UDP probes

### Output and Handoff

Scanning produces: port scan results in XML/text formats, service version lists, vulnerability scan reports, and SSL assessment results. These feed into enumeration for deep-dive analysis of discovered services.

## Phase 4: Enumeration

Deep analysis of discovered services. Enumeration extracts detailed information from each service, including configuration details, user accounts, file shares, and API endpoints.

### Activities

- Directory and file brute-forcing to discover hidden content (ffuf, gobuster, feroxbuster)
- User enumeration from web applications, SMB, and LDAP
- API endpoint discovery and parameter identification (kiterunner, arjun)
- SMB/LDAP/SNMP enumeration for internal services (enum4linux, ldapsearch, snmpwalk)
- Database enumeration to identify tables, columns, and data types

### Output and Handoff

Enumeration produces: discovered directories and files, user lists, API endpoint maps, SMB share inventories, and parameter lists. These feed into vulnerability discovery for targeted testing.

## Phase 5: Vulnerability Discovery

Systematic identification of security weaknesses. This phase uses the enumeration data to focus testing on specific attack surfaces rather than broad scanning.

### Activities

- SQL injection testing against all identified input points (sqlmap)
- Cross-site scripting verification on reflected and stored input (dalfox, xsstrike)
- Authentication bypass testing against login mechanisms
- Authorization testing for privilege escalation and IDOR vulnerabilities
- Server-side request forgery testing where URL fetching is identified
- Business logic vulnerability identification through manual testing

### Output and Handoff

Vulnerability discovery produces: confirmed vulnerabilities with proof of concept, potential vulnerabilities requiring manual verification, and false positive analysis. These feed into exploitation for impact validation.

## Phase 6: Exploitation

Verified exploitation of discovered vulnerabilities. Exploitation confirms the real-world impact of findings and demonstrates attack paths to stakeholders.

### Activities

- SQL injection exploitation for data extraction (sqlmap --dump, --os-shell)
- XSS proof-of-concept development with cookie stealing or key logging demonstrations
- Authentication bypass to gain unauthorized access
- Credential brute-forcing against discovered login forms and services
- Remote code execution where vulnerabilities permit

### Output and Handoff

Exploitation produces: confirmed access levels, extracted data samples, and proof-of-concept evidence. These feed into post-exploitation for impact assessment.

## Phase 7: Post-Exploitation

Assessing impact of successful exploitation. Post-exploitation determines the full extent of access that an attacker could achieve.

### Activities

- Privilege escalation on compromised systems (linpeas, winpeas)
- Lateral movement assessment across the network (crackmapexec)
- Persistence mechanism documentation (what an attacker could install)
- Data exfiltration simulation within approved scope
- Active Directory enumeration if domain environment discovered

## Phase 8: Reporting

Compiling findings into actionable deliverables. Reporting is the primary client-facing output and must be professional, accurate, and actionable.

### Required Report Sections

1. **Executive Summary**: High-level risk overview for non-technical stakeholders
2. **Scope and Methodology**: What was tested and how
3. **Findings Summary**: Table of all findings with severity ratings
4. **Detailed Findings**: Per-finding analysis with PoC, impact, and remediation
5. **Remediation Priorities**: Organized by urgency (immediate, 7-day, 30-day, quarterly)
6. **Appendices**: Tool inventory, raw evidence index, scope document

## Best Practices

- Document every action with timestamps throughout all phases
- Maintain evidence integrity — never modify raw evidence files after creation
- Report critical findings within 4 hours of discovery per notification protocol
- Validate all findings before including in final report to eliminate false positives
- Follow scope boundaries strictly and document any scope-related decisions
- Use consistent evidence naming conventions across all phases
- Run quality assurance checks before delivering the final report

## Hands-on Exercise

Practice the full engagement lifecycle in a lab:

1. Set up a lab with DVWA and a vulnerable network (Metasploitable)
2. Walk through all 8 phases with proper evidence collection
3. Practice the checkpoint resume feature by interrupting mid-engagement
4. Generate a complete report and perform quality assurance review
5. Review the report for completeness, accuracy, and professional quality

## References

- PTES (Penetration Testing Execution Standard): http://www.pentest-standard.org/
- OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- NIST SP 800-115: Technical Guide to Information Security Testing and Assessment
- CREST Penetration Testing Guide: https://www.crest-approved.org/
- OSSTMM: Open Source Security Testing Methodology Manual
