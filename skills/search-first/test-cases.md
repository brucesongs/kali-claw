# Search First — Test Cases

> Structured test scenarios for exploit/tool/technique search methodology.

---

## TC-SF-001: CVE Exploit Discovery

### Scenario
During a penetration test, Apache 2.4.49 is identified on the target. Search for known exploits before attempting manual exploitation.

### Pre-conditions
- Target service and version identified (Apache 2.4.49)
- `searchsploit` database updated
- `gh` CLI authenticated
- Internet access available

### Test Steps

1. **Define the need**
   - Target: Apache HTTP Server 2.4.49
   - Need: Remote exploitation path (path traversal or RCE)

2. **Parallel search across sources**
   ```bash
   # ExploitDB
   searchsploit apache 2.4.49

   # GitHub PoCs
   gh search repos "CVE-2021-41773" --sort stars --limit 10

   # Metasploit modules
   msfconsole -q -x "search apache 2.4 path; exit"

   # Nuclei templates
   nuclei -tl -tags cve | grep "2021-41773"
   ```

3. **Evaluate results**
   - Score each result using evaluation matrix from payloads.md
   - Check reliability: verified PoC with multiple reports
   - Check compatibility: exact version match (2.4.49)

4. **Decide and execute**
   - Select highest-scoring result
   - Test against Docker lab target first

### Expected Outcomes

| Source | Finding | Score | Decision |
|--------|---------|-------|----------|
| ExploitDB | CVE-2021-41773 (path traversal) | High | Use as-is |
| GitHub | Multiple curl-based PoCs | High | Use simplest PoC |
| MSF | auxiliary/scanner/http/apache_normalize_path | Medium | Use for verification |
| Nuclei | CVE-2021-41773 template | High | Use for scanning |

---

## TC-SF-002: Security Tool Discovery

### Scenario
Need an automated subdomain enumeration tool for a bug bounty engagement. Search for the best available tool before writing custom scripts.

### Pre-conditions
- Need clearly defined: fast subdomain enumeration
- Kali Linux environment with package manager
- GitHub CLI available

### Test Steps

1. **Search existing tools**
   ```bash
   # Kali packages
   apt search subdomain 2>/dev/null | grep -i enum

   # GitHub repos
   gh search repos "subdomain enumeration" --sort stars --limit 20
   gh search repos "subdomain finder" --sort stars --limit 20
   ```

2. **Evaluate top candidates**
   - subfinder (ProjectDiscovery)
   - amass (OWASP)
   - sublist3r
   - OneForAll
   - Score each on: speed, accuracy, extensibility, maintenance

3. **Check Kali availability**
   ```bash
   apt list --installed 2>/dev/null | grep subfinder
   apt list --installed 2>/dev/null | grep amass
   ```

4. **Select and install**
   ```bash
   apt install -y subfinder
   ```

### Expected Outcomes

| Metric | Expected |
|--------|----------|
| Tools found | 4+ candidates |
| Evaluation | Scored on 5 factors |
| Selection | Best-fit tool chosen |
| Installation | Tool installed and verified |

---

## TC-SF-003: Attack Technique Research

### Scenario
During an Active Directory engagement, need to research Kerberoasting technique and find available tools for execution.

### Pre-conditions
- Target: Active Directory environment with SPNs
- Need: Kerberoasting attack capability
- Internet access for research

### Test Steps

1. **Search for technique information**
   ```bash
   searchsploit kerberoast
   gh search repos "kerberoast" --sort stars --limit 20
   gh search code "kerberoast" --language python --limit 20
   msfconsole -q -x "search kerberoast; exit"
   ```

2. **Evaluate tool options**
   - Rubeus (C# — Windows)
   - Impacket-GetUserSPNs (Python — cross-platform)
   - Invoke-Kerberoast (PowerShell)
   - CrackMapExec SPN module

3. **Select best-fit for environment**
   - Consider target access level
   - Consider OPSEC requirements
   - Consider available credentials

4. **Verify with lab testing**
   - Test selected tool against Docker AD lab
   - Verify TGS hash extraction
   - Verify hashcat cracking compatibility

### Expected Outcomes

| Metric | Expected |
|--------|----------|
| Tools found | 4+ (Rubeus, Impacket, PowerShell, CME) |
| Technique documented | MITRE ATT&CK T1208 mapped |
| Tool selected | Best-fit for engagement context |
| Lab verified | TGS hash extracted and crackable |

---

## TC-SF-004: No Results — Build Custom

### Scenario
A custom web application uses a proprietary authentication protocol. No existing tools or exploits are found after comprehensive search.

### Pre-conditions
- Exhaustive search completed (all sources checked)
- No suitable existing tools found
- Custom solution needed

### Test Steps

1. **Document search failure**
   ```markdown
   ## Search Results: None Found
   - **Need**: [custom auth protocol fuzzer]
   - **ExploitDB**: 0 results
   - **GitHub**: 2 results, both abandoned/unrelated
   - **MSF**: 0 modules
   - **Nuclei**: 0 templates
   - **Kali**: No matching packages
   ```

2. **Identify closest partial solutions**
   ```bash
   gh search repos "protocol fuzzer" --sort stars --limit 10
   searchsploit "fuzzer"
   ```

3. **Plan custom build**
   - Identify base framework (e.g., BooFuzz for protocol fuzzing)
   - Define protocol specification needed
   - Estimate development effort
   - Plan testing against lab target

4. **Build minimal viable tool**
   - Start with framework scaffold
   - Add protocol-specific messages
   - Test incrementally

### Expected Outcomes

| Metric | Expected |
|--------|----------|
| Search completeness | All 4+ sources checked |
| Partial solutions | Closest tools identified |
| Build plan | Framework selected, effort estimated |
| Result | Minimal viable custom tool created |
