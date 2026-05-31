# Search First — Test Cases

> Structured test scenarios for exploit/tool/technique search methodology.

---

## TC-SF-001: CVE Exploit Discovery

### Scenario
During a penetration test, Apache 2.4.49 is identified on the target. Search for known exploits before attempting manual exploitation.

**Severity**: CRITICAL

**Objective**: Validate the search-first methodology for CVE exploit discovery by searching multiple sources (ExploitDB, GitHub, Metasploit, Nuclei) in parallel, scoring results, and selecting the highest-value exploit.

**Remediation**: If no exploits are found for the exact version, broaden the search to the major/minor version range. If search sources return inconsistent results, verify searchsploit database is updated (`searchsploit -u`). Always validate exploits in a lab environment before using against production targets.

**Pass Criteria**:
- [ ] All 4 search sources queried (ExploitDB, GitHub, MSF, Nuclei)
- [ ] Each result scored using evaluation matrix
- [ ] Highest-scoring result selected with documented rationale
- [ ] Selected exploit tested against Docker lab target

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

**Severity**: MEDIUM

**Objective**: Validate the tool discovery workflow by searching Kali packages and GitHub for subdomain enumeration tools, evaluating candidates on multiple criteria, and selecting the best-fit tool for the engagement.

**Remediation**: If the selected tool fails during engagement, fall back to the second-ranked candidate from the evaluation. If no Kali package exists, install from GitHub releases or use Go install. Keep evaluation notes for future engagements to avoid re-searching.

**Pass Criteria**:
- [ ] At least 4 candidate tools identified across Kali packages and GitHub
- [ ] Each candidate scored on speed, accuracy, extensibility, and maintenance
- [ ] Best-fit tool selected with documented rationale
- [ ] Tool installed and verified operational

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

**Severity**: HIGH

**Objective**: Validate the attack technique research workflow by searching for Kerberoasting tools across multiple sources, mapping the technique to MITRE ATT&CK, and verifying tool capabilities in a lab environment before engagement use.

**Remediation**: If the preferred tool fails due to OPSEC detection, switch to an alternative from the evaluation list. If no cross-platform tool works, use a combination (e.g., Impacket for extraction, hashcat for cracking). Document tool selection rationale for the engagement report.

**Pass Criteria**:
- [ ] 4+ tools found across search sources (Rubeus, Impacket, PowerShell, CME)
- [ ] Technique mapped to MITRE ATT&CK T1208
- [ ] Best-fit tool selected for the engagement context
- [ ] Lab verified: TGS hash extracted and crackable with hashcat

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

**Severity**: HIGH

**Objective**: Validate the fallback workflow when search-first yields no results: document the search failure comprehensively, identify closest partial solutions, plan and build a minimal custom tool.

**Remediation**: If the custom tool takes longer than estimated, reassess whether a partial existing solution can be adapted. Keep the custom tool modular so it can be extended for future engagements. Contribute the tool back to the community if it has general applicability.

**Pass Criteria**:
- [ ] All 4+ search sources checked and documented as empty
- [ ] Closest partial solutions identified with gap analysis
- [ ] Framework selected with development effort estimated
- [ ] Minimal viable custom tool created and tested against lab target

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

---

## TC-SF-005: WordPress Plugin Vulnerability Search

### Scenario
During a black-box engagement, a WordPress 6.2 site is identified with multiple plugins. Search for known vulnerabilities in the detected plugins before attempting brute force or custom exploitation.

**Severity**: HIGH

**Objective**: Validate plugin-level vulnerability discovery by combining automated scanner results with manual exploit database searches to find known CVEs in specific WordPress plugin versions.

**Remediation**: If no CVEs match the exact plugin version, check for vulnerabilities in nearby versions that may still apply. Keep a local mirror of WPScan vulnerability database for offline engagements. Report all findings with CVE references and CVSS scores.

**Pass Criteria**:
- [ ] WPScan identifies installed plugins and versions
- [ ] Each plugin version checked against exploit databases
- [ ] At least one known vulnerability found or all plugins confirmed patched
- [ ] Findings documented with CVE IDs and exploit references

### Pre-conditions
- WordPress target identified with version 6.2
- WPScan installed and API token available
- Target URL accessible
- Plugin detection possible (not heavily obfuscated)

### Test Steps

1. **Enumerate plugins with WPScan**
   ```bash
   wpscan --url https://target.com --enumerate ap --api-token <TOKEN>
   ```

2. **Search for plugin-specific CVEs**
   ```bash
   searchsploit "woocommerce" --exclude-dos
   gh search repos "woocommerce exploit" --sort stars --limit 10
   ```

3. **Cross-reference with NVD**
   ```bash
   # Check specific CVEs found
   curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=woocommerce" | jq '.vulnerabilities[].cve.id'
   ```

4. **Validate in lab environment**
   - Deploy matching WordPress + plugin version in Docker
   - Test exploit against lab before engagement use

### Expected Outcomes

| Metric | Expected |
|--------|----------|
| Plugins detected | 5+ plugins with versions |
| CVE matches | At least 1 known vulnerability or all confirmed patched |
| Validation | Lab reproduction successful for confirmed CVEs |
| Documentation | Full report with CVE, CVSS, and exploit paths |

---

## TC-SF-006: Cloud Service Misconfiguration Search

### Scenario
During a cloud security assessment, need to research known misconfiguration patterns for AWS S3 buckets before attempting manual enumeration of the target's cloud infrastructure.

**Severity**: HIGH

**Objective**: Validate the search methodology for cloud-specific misconfiguration research by querying exploit databases, GitHub tools, and vendor security advisories to identify known cloud misconfiguration patterns and tools.

**Remediation**: If specific misconfiguration patterns are not documented, test for the OWASP Top 10 Cloud risks. Report all open buckets or misconfigured policies with specific remediation steps (e.g., enable bucket encryption, restrict IAM policies).

**Pass Criteria**:
- [ ] 3+ cloud security tools identified and evaluated
- [ ] Known AWS S3 misconfiguration patterns documented
- [ ] Best-fit tool selected for the engagement context
- [ ] Misconfiguration check validated against lab AWS account

### Pre-conditions
- Cloud service provider identified (AWS)
- S3 buckets detected during reconnaissance
- AWS CLI configured with read-only test credentials
- Pacu, CloudSploit, or ScoutSuite considered

### Test Steps

1. **Search for cloud security tools**
   ```bash
   gh search repos "aws security audit" --sort stars --limit 20
   gh search repos "s3 bucket scanner" --sort stars --limit 10
   searchsploit "aws s3"
   ```

2. **Evaluate top candidates**
   - Pacu (AWS exploitation framework)
   - ScoutSuite (multi-cloud security auditing)
   - CloudSploit (config audit)
   - S3Scanner (bucket enumeration)

3. **Research known S3 misconfigurations**
   - Public read/write access
   - Missing server-side encryption
   - Overly permissive IAM policies
   - Missing bucket logging

4. **Test selected tool against lab AWS account**

### Expected Outcomes

| Metric | Expected |
|--------|----------|
| Tools evaluated | 4+ candidates with scoring |
| Misconfiguration patterns | 10+ known patterns documented |
| Tool selection | Best-fit tool installed and verified |
| Lab validation | At least 1 misconfiguration detected in lab |

---

## TC-SF-007: Wireless Attack Technique Research

### Scenario
During a wireless assessment, need to research the latest WPA3 attack techniques and available tools before engaging the target wireless network.

**Severity**: MEDIUM

**Objective**: Validate the search methodology for wireless-specific attack research by finding current WPA3 attack techniques, tools, and research papers across multiple intelligence sources.

**Remediation**: If WPA3 attacks are limited for the target configuration, document the finding as a security strength and recommend WPA3 adoption for legacy networks. Keep research notes for future assessments targeting different wireless configurations.

**Pass Criteria**:
- [ ] 3+ WPA3 attack techniques researched
- [ ] At least 2 wireless assessment tools evaluated
- [ ] Attack feasibility assessed for target configuration
- [ ] Research documented with references to papers/tools

### Pre-conditions
- Wireless network detected (WPA3-SAE or WPA3-Enterprise)
- WiFi adapter capable of monitor mode available
- Aircrack-ng suite installed
- Internet access for research

### Test Steps

1. **Search for WPA3 attack research**
   ```bash
   searchsploit "wpa3" "sae"
   gh search repos "wpa3 attack" --sort stars --limit 10
   gh search repos "dragonblood" --sort stars --limit 10
   ```

2. **Research specific attacks**
   - Dragonblood (CVE-2019-9494) — downgrade attacks
   - Side-channel leaks in SAE handshake
   - PMF (Protected Management Frames) bypass

3. **Evaluate wireless tools**
   - hcxdumptool + hcxtools (WPA3 capture)
   - Bully (WPS attacks)
   - Bettercap (WiFi MITM)

4. **Test against lab wireless setup**

### Expected Outcomes

| Metric | Expected |
|--------|----------|
| Attack techniques | 3+ documented (Dragonblood, SAE leaks, downgrade) |
| Tools found | 3+ candidates evaluated |
| Feasibility | Clear go/no-go decision for target network |
| Lab validation | Attack tested against lab WPA3 AP |

---

## TC-SF-008: API Authentication Bypass Research

### Scenario
During an API penetration test, JWT-based authentication is detected. Research known JWT attack techniques and available tools before attempting custom exploitation.

**Severity**: CRITICAL

**Objective**: Validate the search methodology for API authentication bypass research by finding JWT-specific vulnerabilities, tools, and testing techniques across exploit databases and security research sources.

**Remediation**: If JWT implementation is secure (RS256, proper validation), document it as a positive finding. If vulnerabilities are found, recommend migrating to RS256 with proper key management, implementing token revocation, and adding rate limiting on authentication endpoints.

**Pass Criteria**:
- [ ] 4+ JWT attack techniques researched (none algorithm, key confusion, weak secret, jku header)
- [ ] At least 2 JWT testing tools evaluated
- [ ] Attack feasibility assessed for target JWT implementation
- [ ] Findings documented with CVE references where applicable

### Pre-conditions
- JWT authentication detected on target API
- jwt-tool or similar available
- Burp Suite with JWT extension installed
- Target API endpoints documented

### Test Steps

1. **Search for JWT attack techniques**
   ```bash
   searchsploit "jwt" "json web token"
   gh search repos "jwt hack" --sort stars --limit 10
   gh search repos "jwt tool" --sort stars --limit 10
   ```

2. **Research known JWT vulnerabilities**
   - Algorithm none attack
   - RS/HS256 key confusion
   - Weak secret brute force
   - jku/x5u header injection
   - kid parameter injection

3. **Evaluate JWT testing tools**
   - jwt-tool (ticarpi)
   - jwt_forgery.py
   - Burp JWT Editor extension

4. **Test against lab API with JWT auth**

### Expected Outcomes

| Metric | Expected |
|--------|----------|
| Attack techniques | 5+ documented JWT attacks |
| Tools evaluated | 3+ candidates with pros/cons |
| Feasibility | Specific attacks applicable to target identified |
| Lab validation | At least 1 JWT bypass demonstrated in lab |

---

## TC-SF-009: Container Escape Technique Discovery

### Scenario
During a container security assessment, need to research known Docker and Kubernetes container escape techniques and find available tools for testing.

**Severity**: CRITICAL

**Objective**: Validate the search methodology for container escape research by finding known CVEs and techniques for breaking out of container isolation, evaluating exploitation tools, and testing against lab environments.

**Remediation**: If container escape is achievable, recommend running containers as non-root, using seccomp/AppArmor profiles, enabling user namespaces, and keeping the container runtime patched. Report with CVSS scores and specific CVE references.

**Pass Criteria**:
- [ ] 5+ container escape techniques/CVEs researched
- [ ] At least 2 container security tools evaluated
- [ ] Escape feasibility assessed for target container configuration
- [ ] Lab validation with matching container runtime version

### Pre-conditions
- Container runtime identified (Docker version, containerd, or CRI-O)
- Kubernetes cluster version identified (if applicable)
- Lab environment with matching container runtime
- Internet access for CVE research

### Test Steps

1. **Search for container escape CVEs**
   ```bash
   searchsploit "docker" "escape" "container"
   gh search repos "container escape" --sort stars --limit 20
   gh search repos "cve container" --sort stars --limit 10
   ```

2. **Research specific escape techniques**
   - CVE-2022-0492 (cgroup v1 escape)
   - CVE-2022-0847 (Dirty Pipe)
   - runc exploits (CVE-2019-5736)
   - Kernel exploit paths from containers
   - Kubernetes RBAC misconfigurations

3. **Evaluate container security tools**
   - CDK (Container Development Kit for penetration testing)
   - DeepCe
   - kube-bench (CIS benchmark)

4. **Test against lab container environment**

### Expected Outcomes

| Metric | Expected |
|--------|----------|
| Escape techniques | 5+ documented with CVEs |
| Tools evaluated | 3+ candidates |
| Feasibility | Clear assessment for target configuration |
| Lab validation | At least 1 escape technique verified in lab |

---

## TC-SF-010: Cryptographic Weakness Research

### Scenario
During a security assessment, the target application uses custom encryption. Research known cryptographic attacks applicable to the identified algorithms and find tools for testing weak implementations.

**Severity**: HIGH

**Objective**: Validate the search methodology for cryptographic attack research by identifying applicable attacks for the target's encryption implementation and finding tools capable of exploiting cryptographic weaknesses.

**Remediation**: If weak cryptography is identified, recommend migrating to AES-256-GCM for symmetric encryption, RSA-2048+ or Ed25519 for asymmetric operations, and using established libraries (libsodium, OpenSSL) rather than custom implementations.

**Pass Criteria**:
- [ ] Target cryptographic algorithms identified
- [ ] Applicable attacks researched for each algorithm
- [ ] At least 2 crypto analysis tools evaluated
- [ ] Attack feasibility documented with complexity analysis

### Pre-conditions
- Target encryption implementation identified (algorithm, key size, mode)
- Crypto analysis tools available (hashcat, CyberChef, RsaCtfTool)
- Understanding of common crypto attack vectors
- Lab environment for safe testing

### Test Steps

1. **Identify crypto implementation details**
   ```bash
   # From intercepted data/traffic
   # Document: algorithm, key size, IV/nonce handling, padding mode
   ```

2. **Search for applicable attacks**
   ```bash
   searchsploit "cbc" "padding oracle" "ecb"
   gh search repos "padding oracle attack" --sort stars --limit 10
   gh search repos "rsa attack tool" --sort stars --limit 10
   ```

3. **Research specific attack vectors**
   - Padding oracle (CBC mode)
   - ECB pattern analysis
   - RSA small exponent attack
   - Key reuse / IV reuse
   - Rainbow table / dictionary attacks on hashes

4. **Evaluate crypto tools**
   - hashcat (hash cracking)
   - RsaCtfTool (RSA attacks)
   - padding-oracle-tool (CBC oracle)
   - CyberChef (encoding/decoding)

### Expected Outcomes

| Metric | Expected |
|--------|----------|
| Algorithms identified | Full crypto stack documented |
| Attack vectors | 5+ applicable attacks researched |
| Tools evaluated | 4+ candidates with capability matrix |
| Feasibility | Complexity and success probability estimated |
