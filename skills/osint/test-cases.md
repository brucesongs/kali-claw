# OSINT Test Cases

> This file is a companion to `SKILL.md`, containing structured test cases organized by category with severity ratings.

---

## Statistics

| Category | Count | Severity Range |
|------|------|-----------|
| A. Passive Reconnaissance | 3 | LOW - MEDIUM |
| B. Active Scanning | 2 | MEDIUM - HIGH |
| C. OSINT Collection | 3 | LOW - HIGH |
| D. Fingerprinting | 2 | LOW - MEDIUM |
| **Total** | **10** | **LOW - HIGH** |

---

## A. Passive Reconnaissance

### TC-OSINT-001: WHOIS & DNS Passive Information Gathering

| Field | Value |
|------|-----|
| **ID** | TC-OSINT-001 |
| **Name** | WHOIS & DNS Passive Information Gathering |
| **Severity** | LOW |
| **Category** | bydynamicreconnaissance |
| **Objective** | notandObjectivedirectexchange互 situationbelowcollectdomain nameregisterinformationand DNS Record |
| **Prerequisites** | authorizationscopeinner Objectivedomain name、interconnectnetworkconnect |
| **Test Steps** | 1. Execute `whois example.com` Obtainregisterperson、register商、NS Record<br>2. Execute `dig any example.com @8.8.8.8` Obtainall DNS Record<br>3. Execute `dig mx example.com` Obtainmailpieceserver<br>4. Attempt DNS zone transfer `dig axfr example.com @ns1.example.com` |
| **Expected Results** | successcollectdomain nameregisterpersoninformation（orprivacyprotectstatus）、DNS Recordtype（A/MX/NS/TXT/SOA）、mailpieceserveraddress |
| **False Positive Risk** | LOW - WHOIS privacyprotectcan canhideregisterpersoninformation；DNS Recordcan cancontains CNAME othernameandnonactual IP |
| **Remediation** | enable WHOIS privacyprotect；minimumize DNS Recordexposure；disable DNS zone transfer；regularlyreview DNS Configure |
| **Related Tools** | whois, dig |

### TC-OSINT-002: Certificate Transparency & Passive Subdomain Discovery

| Field | Value |
|------|-----|
| **ID** | TC-OSINT-002 |
| **Name** | Certificate Transparency & Passive Subdomain Discovery |
| **Severity** | MEDIUM |
| **Category** | bydynamicreconnaissance |
| **Objective** | throughcertificatetransparentdegreelogandbydynamicdatasourceDiscoverObjectivesubdomain name |
| **Prerequisites** | authorizationscopeinner Objectivedomain name、subfinder/amass already install |
| **Test Steps** | 1. Execute `curl -s "https://crt.sh/?q=%25.example.com&output=json"` querycertificatelog<br>2. Execute `subfinder -d example.com -o subs.txt` bydynamicEnumerate<br>3. Execute `amass enum -passive -d example.com -o amass_subs.txt`<br>4. mergededuplicate：`sort -u subs.txt amass_subs.txt` |
| **Expected Results** | DiscoverObjective subdomain namelist，can cancontainsnot public internalsubdomain name、Testenvironment、managementpaneletc. |
| **False Positive Risk** | MEDIUM - certificatelogincan cancontainsoverperiodoralready 弃use subdomain name；partialresultcan can属atNo.third-partyservice |
| **Remediation** | regularlyreviewcertificatetransparentdegreelogin Record；Cleanupoverperiod DNS Record；forinternalsubdomain nameUseinternal CA |
| **Related Tools** | subfinder, amass, crt.sh |

### TC-OSINT-003: Search Engine Passive Information Gathering (Google Dorking)

| Field | Value |
|------|-----|
| **ID** | TC-OSINT-003 |
| **Name** | Search Engine Passive Information Gathering (Google Dorking) |
| **Severity** | MEDIUM |
| **Category** | bydynamicreconnaissance |
| **Objective** | exploitSearchengineadvanced 运calculatecharacterDiscoverObjectiveexposure sensitiveinformation |
| **Prerequisites** | authorizationscopeinner Objectivedomain name、browsetool |
| **Test Steps** | 1. Search `site:example.com intitle:"index of"` findexposuredirectory<br>2. Search `site:example.com filetype:env OR filetype:yml "password"` findConfigurefile<br>3. Search `site:example.com filetype:pdf OR filetype:xlsx` findpublicdocumentation<br>4. Search `site:example.com inurl:admin OR inurl:login` findmanagemententry point |
| **Expected Results** | Discoverexposure directorylist、Configurefile、sensitivedocumentation、admin backendentry pointetc. |
| **False Positive Risk** | LOW - Searchengineresultdirectanti映Objectivewebsite publicContent |
| **Remediation** | Configure robots.txt blocksensitivepath索introduce；removeSearchenginecachein sensitivepage；Use Google Search Console deletealready 索introduce sensitive URL |
| **Related Tools** | Google, theHarvester |

---

## B. Active Scanning

### TC-OSINT-004: Subdomain Brute Force & Verification

| Field | Value |
|------|-----|
| **ID** | TC-OSINT-004 |
| **Name** | Subdomain Brute Force & Verification |
| **Severity** | MEDIUM |
| **Category** | maindynamicScan |
| **Objective** | throughmaindynamic DNS queryDiscoverbydynamicmethodomit subdomain name |
| **Prerequisites** | authorizationscopeinner Objectivedomain name、gobuster/amass already install、subdomain namedictionary |
| **Test Steps** | 1. Execute `gobuster dns -d example.com -w /usr/share/wordlists/subdomains-top1mil-20000.txt -t 50`<br>2. Execute `amass enum -active -d example.com -o active_subs.txt`<br>3. Verifyalive：`cat active_subs.txt \| httpx -silent -status-code -title`<br>4. ComparebydynamicEnumerateresult，markdifference |
| **Expected Results** | DiscoverbydynamicEnumerateomit subdomain name，Verifyalivestatusand HTTP serviceinformation |
| **False Positive Risk** | MEDIUM - DNS wildcardcan cancauselargeamountfalse positive；requiresVerifyeachDiscoveriswhetherrealeffective |
| **Remediation** | Detectandmark DNS wildcard；minimumize面tointerconnectnetwork subdomain nameCount；fornonnecessarysubdomain namedisable DNS solveanalysis |
| **Related Tools** | gobuster, amass, httpx, dnsx |

### TC-OSINT-005: Shodan/Censys Exposed Asset Search

| Field | Value |
|------|-----|
| **ID** | TC-OSINT-005 |
| **Name** | Shodan/Censys Exposed Asset Search |
| **Severity** | HIGH |
| **Category** | maindynamicScan |
| **Objective** | throughinterconnectnetworkSearchengineDiscoverObjectiveorganization exposuredeviceandservice |
| **Prerequisites** | ObjectiveorganizationNameor IP scope、Shodan/Censys API Key |
| **Test Steps** | 1. Execute `shodan search "org:Example Corp"` Searchorganizationasset<br>2. Execute `shodan search "net:<CIDR>"` Search IP scope<br>3. Searchhigh危port：`shodan search "port:3306,5432,27017,6379 org:Example Corp"`<br>4. Searchalready knowvulnerability：`shodan search "vuln:CVE-* org:Example Corp"`<br>5. in Censys incrossVerify |
| **Expected Results** | Discoverexposure databaseservice、managementpanel、IoT device、existsalready knowvulnerability systemetc. |
| **False Positive Risk** | LOW - Shodan/Censys datafrom actualScan，butcan canexistsdelay |
| **Remediation** | disablenonnecessaryport interconnectnetworkexposure；willdatabaseandmanagementpanellimitationasinternal networkaccess；andwhen fix补already knowvulnerability；Configurefirewallrule |
| **Related Tools** | shodan, censys |

---

## C. OSINT Collection

### TC-OSINT-006: Email Address Collection & Leak Check

| Field | Value |
|------|-----|
| **ID** | TC-OSINT-006 |
| **Name** | Email Address Collection & Leak Check |
| **Severity** | HIGH |
| **Category** | OSINT collect |
| **Objective** | collectObjectiveorganization email addressaddressandCheckiswhetheroutputnowindataleakagein |
| **Prerequisites** | Objectivedomain name、theHarvester/h8mail already install |
| **Test Steps** | 1. Execute `theHarvester -d example.com -b all` allsourceemail addresscollect<br>2. Execute `theHarvester -d example.com -b hunter` Obtainemail addressformat<br>3. Execute `h8mail -t @example.com -l local -o leaks.json` leakageCheck<br>4. Execute `holehe user@example.com` Checkserviceregister<br>5. Execute `gpg --search-keys user@example.com` Search PGP key |
| **Expected Results** | ObtainObjectiveorganizationemail addresslist、email addressformatrule律、leakagecredentialsinformation、email addressrelated serviceaccount |
| **False Positive Risk** | MEDIUM - leakagedatacan cancontains虚fakeinformation；email addressformatpush测can cannotaccurate |
| **Remediation** | employeeUseenterpriseemail addressregisterNo.third-partyservicewhen noteprivacy；regularlyCheck HaveIBeenPwned leakagepassknow；realimplement MFA protectall account |
| **Related Tools** | theHarvester, h8mail, holehe |

### TC-OSINT-007: Username Cross-platform Tracking

| Field | Value |
|------|-----|
| **ID** | TC-OSINT-007 |
| **Name** | Username Cross-platform Tracking |
| **Severity** | MEDIUM |
| **Category** | OSINT collect |
| **Objective** | traceObjectiveusernameinmultiplesocialexchangeplatform existssituation |
| **Prerequisites** | Objectiveusernamelist、Sherlock already install |
| **Test Steps** | 1. Execute `sherlock username --json -o results.json` Search 300+ platform<br>2. Execute `theHarvester -d example.com -b linkedin` collect LinkedIn username<br>3. forDiscover socialexchangeaccountperformpersonworkVerify<br>4. Checkaccount publicinformation（personal简介、bitconfiguration、relatedperson） |
| **Expected Results** | ObtainObjectiveusernameineachlargesocialexchangeplatform registersituationandpersonalinformation |
| **False Positive Risk** | LOW - Sherlock through HTTP statuscodejudge，can canexists少amountfalse positive |
| **Remediation** | Useunified privacyset；minimumizesocial mediaon personalinformationexposure；regularlyreviewpublicinformation |
| **Related Tools** | sherlock, theHarvester |

### TC-OSINT-008: GitHub Code Leak Audit

| Field | Value |
|------|-----|
| **ID** | TC-OSINT-008 |
| **Name** | GitHub Code Leak Audit |
| **Severity** | HIGH |
| **Category** | OSINT collect |
| **Objective** | SearchObjectiveorganizationin GitHub onleakage sensitiveinformation（API Key、password、Configurefile） |
| **Prerequisites** | Objectiveorganization GitHub username/organizationname、curl/jq already install |
| **Test Steps** | 1. Search `.env` file：`curl -s "https://api.github.com/search/code?q=org:target+filename:.env" \| jq '.items[].html_url'`<br>2. batchamountSearchcritical词：password, secret, api_key, token, private_key, aws_access_key<br>3. downloadcan suspiciousrepositorylibrary：`git-dumper https://github.com/target/repo /tmp/audit`<br>4. deep Analyze：`grep -rn "password\|api_key\|secret\|token" /tmp/audit/ --include="*.yml" --include="*.env" --include="*.json"` |
| **Expected Results** | Discoverleakage API Key、databasepassword、AWS credentials、private Token etc.sensitiveinformation |
| **False Positive Risk** | MEDIUM - can canDiscover isTestuseexamplein exampleValueandnonrealcredentials |
| **Remediation** | 立i.e.rotationalready leakage credentials；Use git-secrets or pre-commit hooks preventcommitsensitiveinformation；realimplement GitHub Secret Scanning；Cleanuphistorycommitin sensitivedata |
| **Related Tools** | GitHub API, git-dumper, grep |

---

## D. Fingerprinting

### TC-OSINT-009: Web Technology Stack Fingerprint Identification

| Field | Value |
|------|-----|
| **ID** | TC-OSINT-009 |
| **Name** | Web Technology Stack Fingerprint Identification |
| **Severity** | LOW |
| **Category** | fingerprintIdentify |
| **Objective** | IdentifyObjectivewebsiteUse Web technique、framework、serversoftwarepiece |
| **Prerequisites** | Objective URL list、whatweb/httpx already install |
| **Test Steps** | 1. Execute `whatweb -a 3 example.com` detailed Identify<br>2. Execute `httpx -l urls.txt -silent -tech-detect -status-code -title -server`<br>3. Execute `curl -sI https://example.com` Analyze HTTP responsehead<br>4. Compare whatweb and httpx result，crossVerify |
| **Expected Results** | IdentifyoutputObjectiveUse CMS、编processlanguage、Web server、JavaScript framework、CDN etc.technique |
| **False Positive Risk** | LOW - fingerprintIdentifybaseat HTTP responsecharacteristic，typicallyaccuratebutcan canomitfromDefinitionmodify |
| **Remediation** | remove HTTP responseheadin versioninformation（Server、X-Powered-By）；Usesecurity defaultConfigure；regularlyupdatetech stackversion |
| **Related Tools** | whatweb, httpx, curl, Wappalyzer |

### TC-OSINT-010: Document Metadata Extraction & Sensitive Information Analysis

| Field | Value |
|------|-----|
| **ID** | TC-OSINT-010 |
| **Name** | Document Metadata Extraction & Sensitive Information Analysis |
| **Severity** | MEDIUM |
| **Category** | fingerprintIdentify |
| **Objective** | fromObjectivewebsitepublic documentationinExtractmetadata，Discoverusername、internalpath、softwarepieceversionetc.information |
| **Prerequisites** | Objectivedomain name、exiftool already install、already downloadObjectivedocumentation |
| **Test Steps** | 1. through Google Dork downloadObjectivewebsite publicdocumentation（PDF/DOCX/XLSX）<br>2. Execute `exiftool -r /path/to/documents/` batchamountExtractmetadata<br>3. Execute `exiftool -Creator -Author -Producer -LastModifiedBy document.pdf` Extractusername<br>4. Execute `exiftool -gps:all image.jpg` Extract GPS information<br>5. summaryall Discover sensitiveinformation |
| **Expected Results** | Discoverinternalusername（email addressformat）、softwarepieceversion、internalnetworkpath、printmachineName、GPS coordinatesetc. |
| **False Positive Risk** | LOW - metadatadirectfrom fileAttribute，butcan cancontainsgeneral systemaccountname |
| **Remediation** | releasebeforecleardocumentationmetadata（`exiftool -all= file` or `mat2 file`）；制定documentationreleaseprocessspecification；Use DLP Toolsautomated Detect |
| **Related Tools** | exiftool, mat2, FOCA |

---

## Appendix：Severity Definitions

| Level | Definition |
|------|------|
| **LOW** | informationexposurebutnot directconstruct成threat（such as tech stackinformation、publicdocumentation） |
| **MEDIUM** | indegreerisk，can canasfollow-upattackprovideshaspriceValueinformation（such as subdomain name、email addressformat） |
| **HIGH** | highdegreerisk，can directused forattack（such as leakagecredentials、exposuredatabase） |
| **CRITICAL** | extremelyhighrisk，can 立i.e.byexploit（such as plaintextcredentials、remoteaccessexposure） |
