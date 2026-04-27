# Recon & OSINT Test Cases

This file contains 11 structured test cases covering passive reconnaissance, active scanning, OSINT collection, and technology fingerprinting.

---

## Statistics

| Category | Count | Severity Range |
|------|------|-------------|
| A. Passive Recon / bydynamicreconnaissance | 3 | HIGH - CRITICAL |
| B. Active Scanning / maindynamicScan | 3 | MEDIUM - HIGH |
| C. OSINT Collection | 3 | MEDIUM - CRITICAL |
| D. Fingerprinting | 2 | MEDIUM - HIGH |
| **Total** | **11** | **MEDIUM - CRITICAL** |

---

## A. Passive Recon / bydynamicreconnaissance

### TC-RECON-001: WHOIS Domain Registration Information Complete Extraction

| Attribute | Value |
|------|-----|
| **ID** | TC-RECON-001 |
| **Category** | A. Passive Recon |
| **Severity** | HIGH |
| **Tools** | whois, dig |
| **Prerequisites** | Objectivedomain namealready know，whois servicecan use |
| **Description** | through WHOIS queryExtractdomain nameregisterperson、registeremail address、DNS server、registerwhen intervalandoverperiodwhen intervaletc.criticalinformation。 |

**Test Steps**:

```bash
# 1. Execute WHOIS query
whois example.com > whois_raw.txt

# 2. ExtractcriticalField
whois example.com | grep -iE "Registrant|Admin|Name Server|Email|Created|Expiry"

# 3. DNS Recordsupplement
dig any example.com @8.8.8.8
```

**Expected Results**:

- successExtractregisterperson姓nameandorganization
- Obtainregisteremail addressand联systemelectric话
- Identifyall DNS authorityserver
- Obtaindomain nameregisterandoverperiodwhen interval

**Verification Criteria**:

- [ ] WHOIS datainat leastcontainsregisterpersonand DNS serverinformation
- [ ] DNS queryreturn NS and MX Record
- [ ] Identifydomain nameregister商

---

### TC-RECON-002: DNS Zone Transfer Vulnerability Detection

| Attribute | Value |
|------|-----|
| **ID** | TC-RECON-002 |
| **Category** | A. Passive Recon |
| **Severity** | CRITICAL |
| **Tools** | dig |
| **Prerequisites** | already IdentifyObjective DNS authorityserver |
| **Description** | AttemptforObjective DNS serverExecutezone transfer（AXFR），ifsuccessthencan Obtainalldepartment DNS Record，includinginternalhostnameand IP 映射。 |

**Test Steps**:

```bash
# 1. Obtain NS Record
dig NS example.com +short

# 2. foreach NS Attempt AXFR
for ns in $(dig NS example.com +short); do
  echo "=== Trying $ns ==="
  dig axfr example.com @$ns
done
```

**Expected Results**:

- if DNS not correctConfigure，AXFR successandreturnalldepartmentzonedomainRecord
- exposureinternalhostname、IP address、CNAME othernameetc.sensitiveinformation
- ifConfigurecorrect，serverdeny AXFR request（REFUSED/SERVFAIL）

**Verification Criteria**:

- [ ] foreachauthority NS allAttempt AXFR
- [ ] Record AXFR success/failurestatus
- [ ] ifsuccess，Extractall A/CNAME/MX/TXT Record

---

### TC-RECON-003: Google Dork Sensitive Information Disclosure Detection

| Attribute | Value |
|------|-----|
| **ID** | TC-RECON-003 |
| **Category** | A. Passive Recon |
| **Severity** | CRITICAL |
| **Tools** | Google Search, Browser |
| **Prerequisites** | Objectivedomain namealready know |
| **Description** | Use Google Dork advanced Searchsyntax，DetectObjectivedomain name sensitivefileleakage、directorylistexposure、errorinformationleakageetc.information。 |

**Test Steps**:

```
# 1. Detectdirectorylist
intitle:"index of" site:example.com

# 2. Detectsensitivefile
site:example.com filetype:env OR filetype:conf OR filetype:sql OR filetype:bak

# 3. DetectError Page Information Disclosure
site:example.com "sql syntax" OR "stack trace" OR "Fatal error"

# 4. Detectexposure admin backend
site:example.com inurl:admin OR inurl:login OR inurl:dashboard

# 5. Detectpublicdocumentationin internalinformation
site:example.com filetype:pdf intext:"confidential" OR intext:"internal"
```

**Expected Results**:

- Discoverexposure directorylistpage
- Identifyleakage Configurefile、databasefileorbackupfile
- Detecttocontainsinternalinformation publicdocumentation

**Verification Criteria**:

- [ ] foreach Dork CategoryallExecute Search
- [ ] Recordall Discover sensitive URL
- [ ] forDiscover leakageperformscreenshotandpartclass

---

## B. Active Scanning / maindynamicScan

### TC-RECON-004: Full Port Service Scan & Version Identification

| Attribute | Value |
|------|-----|
| **ID** | TC-RECON-004 |
| **Category** | B. Active Scanning |
| **Severity** | HIGH |
| **Tools** | nmap |
| **Prerequisites** | Objective IP already know，networkcan reach |
| **Description** | forObjectiveExecuteallport SYN Scan，coordinateserviceversionDetectandscriptScan，establishcomplete servicechecklist。 |

**Test Steps**:

```bash
# 1. quick hostDiscover
nmap -sn 192.168.1.0/24 -oG hosts.txt

# 2. allport SYN Scan + serviceversion + OS Detect
nmap -sS -sV -sC -O -p- -oA full_scan target

# 3. UDP criticalportsupplementScan
nmap -sU --top-ports 50 target
```

**Expected Results**:

- Identifyall open TCP port（1-65535）
- Obtaineachport serviceNameandversionnumber
- operationsystemfingerprintIdentifyresult
- NSE scriptDiscover additionalinformation

**Verification Criteria**:

- [ ] Scancoveringalldepartment 65535 TCP port
- [ ] eachopenportallhasserviceversioninformation
- [ ] OS Detectresulthasconfigurationinformationdegree标注
- [ ] resultsaveasmultiplekindformat（-oA）

---

### TC-RECON-005: Subdomain Enumeration Multi-tool Cross-verification

| Attribute | Value |
|------|-----|
| **ID** | TC-RECON-005 |
| **Category** | B. Active Scanning |
| **Severity** | MEDIUM |
| **Tools** | sublist3r, assetfinder, dnsenum, fierce, httpx |
| **Prerequisites** | Objectivedomain namealready know |
| **Description** | Useat least 3 kindToolsperformsubdomain nameEnumerate，mergededuplicateafterVerifyalivestatus，mostlargeizesubdomain namecoveringrate。 |

**Test Steps**:

```bash
# 1. multipleToolsEnumerate
sublist3r -d example.com -t 50 -o subs_sublist3r.txt
assetfinder --subs-only example.com > subs_assetfinder.txt
dnsenum -f /usr/share/wordlists/subdomains-top1mil-20000.txt example.com 2>/dev/null | grep -oE '[a-z0-9.-]+\.example\.com' > subs_dnsenum.txt

# 2. mergededuplicate
sort -u subs_*.txt > all_subdomains.txt

# 3. aliveVerify
cat all_subdomains.txt | httpx -silent -status-code -title -o live_subs.txt

# 4. Statisticscoveringrate
echo "Total found: $(wc -l < all_subdomains.txt)"
echo "Alive: $(wc -l < live_subs.txt)"
```

**Expected Results**:

- 三ToolseachfromDiscovernotsame subdomain namecollection
- mergeafterdeduplicate得tomostlargesubdomain namecollection
- aliveVerifyfilteralready belowline subdomain name

**Verification Criteria**:

- [ ] at leastUse 3 kindToolsperformEnumerate
- [ ] resultmergededuplicatehandlingcorrect
- [ ] alivesubdomain namealready through HTTP/HTTPS Verify
- [ ] RecordeachTools DiscoverCountCompare

---

### TC-RECON-006: Web Directory & File Brute Force

| Attribute | Value |
|------|-----|
| **ID** | TC-RECON-006 |
| **Category** | B. Active Scanning |
| **Severity** | HIGH |
| **Tools** | gobuster, dirb, ffuf |
| **Prerequisites** | Objective Web application URL already know |
| **Description** | UsemultipleToolsforObjective Web applicationperformdirectoryandfilebrute force，Discoverhide admin backend、API endpoint、backupfileandConfigurefile。 |

**Test Steps**:

```bash
# 1. gobuster basic Scan
gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt -x .php,.html,.txt,.bak -o gobuster_results.txt

# 2. dirb VerifyScan
dirb http://target /usr/share/dirb/wordlists/common.txt -o dirb_results.txt

# 3. ffuf advanced Scan（filterfalse positive）
ffuf -u http://target/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -fc 404 -fs 0 -o ffuf_results.json
```

**Expected Results**:

- Discoverhidedirectory（such as /admin、/backup、/api）
- Identifysensitivefile（such as .env、config.php、database.sql）
- Detecttobackupfileandtemporarywhen file

**Verification Criteria**:

- [ ] at leastUse 2 kindToolscrossVerify
- [ ] Scancontainscommon fileextensionname
- [ ] filter false positiveresult（such as fromDefinition 404 page）
- [ ] forDiscover pathperform manual Verify

---

## C. OSINT Collection

### TC-RECON-007: Email Address Collection & Format Analysis

| Attribute | Value |
|------|-----|
| **ID** | TC-RECON-007 |
| **Category** | C. OSINT Collection |
| **Severity** | HIGH |
| **Tools** | theHarvester, curl |
| **Prerequisites** | Objectivedomain namealready know |
| **Description** | throughSearchengine、PGP keyserver、social mediaetc.multiplesourcecollectObjectiveorganization email addressaddress，Analyzeemail address命nameformatwithsupportsfollow-upphishing attackSimulate。 |

**Test Steps**:

```bash
# 1. theHarvester allsourcecollect
theHarvester -d example.com -b all -f harvest_results.html

# 2. specifysourcecollect
theHarvester -d example.com -b google,bing,linkedin -f harvest_targeted.html

# 3. Extractemail addressandAnalyzeformat
grep -oE '[a-zA-Z0-9._%+-]+@example\.com' harvest_results.html | sort -u > emails.txt

# 4. Analyzeemail addressformatrule律
# Identifyis firstname.lastname、flastname alsoisitsotherformat
```

**Expected Results**:

- frommultipleSearchenginecollecttoObjectiveorganization email addressaddress
- Identifyemail address命nameformat（used forfollow-upphishingTest）
- Discoverandemail addressrelated employee姓nameand职bit

**Verification Criteria**:

- [ ] Use multipleSearchenginesource
- [ ] email addressdeduplicatehandlingcorrect
- [ ] AnalyzeandRecord email address命nameformatrule律
- [ ] resultsaveascan readformat

---

### TC-RECON-008: Social Media & GitHub Code Leak Detection

| Attribute | Value |
|------|-----|
| **ID** | TC-RECON-008 |
| **Category** | C. OSINT Collection |
| **Severity** | CRITICAL |
| **Tools** | Google Search, Browser, recon-ng |
| **Prerequisites** | ObjectiveorganizationNameanddomain namealready know |
| **Description** | insocial mediaandcode托管platformSearchObjectiveorganizationrelated informationleakage，includingemployeeinformation、codein hardencodingkey、Configurefileleakageetc.。 |

**Test Steps**:

```
# 1. LinkedIn employeeEnumerate
site:linkedin.com/company "Example Corp"
site:linkedin.com/in "example.com"

# 2. GitHub codeleakageSearch
site:github.com "example.com" password OR secret OR api_key
site:github.com "example.com" filename:.env
site:github.com "example.com" filename:config.py OR filename:settings.py

# 3. Pastebin leakageDetect
site:pastebin.com "example.com"
site:paste.ee "example.com"

# 4. recon-ng automated collect
recon-ng
> use recon/profiles-profiles/profiler
> set source example.com
> run
```

**Expected Results**:

- EnumeratetoObjectiveorganization criticalemployeeand职bitinformation
- Discover GitHub oncontainssensitiveinformation coderepositorylibrary
- Detecttoin Pastebin etc.platform code/dataleakage

**Verification Criteria**:

- [ ] at leastSearch 3 socialexchangeplatform
- [ ] GitHub Searchcovering common sensitivefilenameandcritical词
- [ ] forDiscover leakageperform screenshotandpartclass
- [ ] Identify can used forsocialwillengineeringattack employeeinformation

---

### TC-RECON-009: Document Metadata Extraction & Sensitive Information Analysis

| Attribute | Value |
|------|-----|
| **ID** | TC-RECON-009 |
| **Category** | C. OSINT Collection |
| **Severity** | MEDIUM |
| **Tools** | metagoofil, exiftool |
| **Prerequisites** | Objectivedomain namealready know |
| **Description** | fromObjectivewebsitedownloadpublicdocumentation（PDF、Word、Excel、PPT），Extractmetadatain workerinformation、internalpath、softwarepieceversionetc.sensitivedata。 |

**Test Steps**:

```bash
# 1. downloadObjectivedomain namerelated documentation
metagoofil -d example.com -t pdf,doc,xls,pptx -l 50 -n 20 -o /tmp/metadata/

# 2. batchamountExtractmetadata
exiftool /tmp/metadata/* > metadata_analysis.txt

# 3. ExtractspecificsensitiveField
exiftool -Creator -Author -Producer -LastModifiedBy -Company /tmp/metadata/* | grep -v "^$"

# 4. Searchinternalpathleakage
exiftool /tmp/metadata/* | grep -iE "C:\\Users\\|/home/|/var/www/|\\\\server\\"
```

**Expected Results**:

- fromdocumentationmetadatainExtracttoworker real姓name
- Discoverinternalusernameformat（such as domainusername DOMAIN\username）
- Identifydocumentationinleakage internalfileserverpath
- Obtainsoftwarepieceversioninformation（Office version、PDF Generatetooletc.）

**Verification Criteria**:

- [ ] successdownload at least 10 Objectivedocumentation
- [ ] metadataExtractcontainsworker、createer、modifyerField
- [ ] Identify internalusernameandfilepathformat
- [ ] resultbyinformationtypepartclassentirereason

---

## D. Fingerprinting

### TC-RECON-010: Web Technology Stack Comprehensive Fingerprint Identification

| Attribute | Value |
|------|-----|
| **ID** | TC-RECON-010 |
| **Category** | D. Fingerprinting |
| **Severity** | HIGH |
| **Tools** | whatweb, wpscan, curl |
| **Prerequisites** | Objective Web application URL already know |
| **Description** | forObjective Web applicationperformcomprehensivetech stackIdentify，including Web server、编processlanguage、CMS、JavaScript framework、CDN etc.。 |

**Test Steps**:

```bash
# 1. whatweb comprehensiveIdentify
whatweb -v http://target

# 2. HTTP responseheadAnalyze
curl -sI http://target

# 3. security headdepartmentDetect
curl -sI http://target | grep -iE "X-Frame-Options|X-Content-Type-Options|Strict-Transport-Security|Content-Security-Policy|X-XSS-Protection"

# 4. CMS specializeditemScan（such as Detectto WordPress）
wpscan --url http://target --enumerate u,p,t

# 5. favicon hash Identify
curl -s http://target/favicon.ico | md5sum

# 6. robots.txt and sitemap.xml Analyze
curl -s http://target/robots.txt
curl -s http://target/sitemap.xml
```

**Expected Results**:

- Identify Web servertypeandversion（Apache、Nginx、IIS）
- Detect编processlanguage（PHP、ASP.NET、Java）
- Discover CMS systemanditsversion
- Identifyfrontendframework（jQuery、React、Vue）
- Detectmissing security HTTP headdepartment

**Verification Criteria**:

- [ ] tech stackIdentifyat leastcoveringserver、language、CMS 三dimensiondegree
- [ ] security headdepartmentmissingsituationalready Record
- [ ] CMS versionnumberalready preciseIdentify
- [ ] resultandmanual Verifyconsistent

---

### TC-RECON-011: Attack Surface & Error Page Information Disclosure Detection

| Attribute | Value |
|------|-----|
| **ID** | TC-RECON-011 |
| **Category** | D. Fingerprinting |
| **Severity** | MEDIUM |
| **Tools** | curl, whatweb |
| **Prerequisites** | Objective Web application URL already know |
| **Description** | throughrequestcommon path、Triggererrorpage、Testspecialrequest，DetectObjectiveapplication informationleakagesituation，includingversioninformation、stacktracking、internal IP etc.。 |

**Test Steps**:

```bash
# 1. Detectcommon sensitivepath
for path in /.git/HEAD /.svn/entries /.env /wp-config.php /config.php /server-status /server-info /.DS_Store /crossdomain.xml; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://target$path")
  echo "$path: $code"
done

# 2. Triggererrorpage
curl -s http://target/nonexistent_path_12345
curl -s http://target/'<script>test</script>'
curl -s -X OPTIONS http://target

# 3. Detectdefaultpage
curl -s http://target/ | head -n 50

# 4. Detect TRACE method（XST vulnerability）
curl -s -X TRACE http://target
```

**Expected Results**:

- Discoverexposure sensitivepath（.git、.env、server-status）
- errorpageleakagestacktrackingorinternalpath
- defaultpageexposureserverversioninformation
- TRACE methodenable（潜in XST risk）

**Verification Criteria**:

- [ ] at leastTest 10 common sensitivepath
- [ ] errorTriggerreturn informationalready Record
- [ ] HTTP methodEnumeratecomplete
- [ ] foreachDiscover标注 riskLevel
