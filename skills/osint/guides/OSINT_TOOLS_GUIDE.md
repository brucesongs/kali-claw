# OSINT ToolLearningguide

> 日period: 2026-03-28
> Target: Master OSINT ToolandperformPracticeAnalysis

---

## 📚 OSINT Framework Overview

### 1. Information Gatheringpartclass (OSINT Framework)

| Category | Description | 典typeTool |
|------|------|----------|
| Training | trainingresource | TRY Hack Me, HTB, PentesterLab |
| Documentation/Evidence | documentationandevidencecollect | Archive.org, Google Cache |
| OpSec | work战Security | personalinformationprotectCheck |
| Threat Intelligence | Threat Intelligence | Shodan, VirusTotal, AlienVault |
| Exploits & Advisories | Vulnerabilityand公告 | CVE, NVD, Exploit-DB |
| Malicious File Analysis | maliciousFileAnalysis | VirusTotal, Hybrid Analysis |
| AI Tools | AI Tool | largetypelanguagemodetypesearch |
| Encoding/Decoding | encoding/decode | CyberChef, Base64 Decoder |
| Classifieds | partclassinformation | Craiglist, 58same城 |
| Blockchain & Cryptocurrency | zoneblockchain | Blockchain Explorer, Etherscan |
| Dark Web | 暗network | Tor, Ahmia, Torch |
| Mobile OSINT | movedynamicendintelligence | Android ID, iOS ID |
| Search Engines | Search Engines | Google, Bing, DuckDuckGo |
| Geolocation | 地reasonlocate | Google Maps, Bing Maps |
| Business Records | 商业record | Days眼查, 企查查 |
| Public Records | 公共record | 政府Dataopenplatform |
| Telephone Numbers | phone number | Truecaller, NumLookup |
| People Search | person物search | Spokeo, Pipl, 脉脉 |
| Social Networks | socialexchangeNetwork | Facebook, LinkedIn, 微information |
| Images/Video | image/viewfrequency | Google Images, TinEye, Yandex |
| IP & MAC Address | IP address | IPinfo, ARIN, RIPE |
| Cloud Infrastructure | cloudbasic facility | Shodan, Censys, AWS Bucket Finder |
| Domain Name | domain name | WHOIS, Subdomain Enum |
| Email Address | Email | Have I Been Pwned, Hunter |
| Username | Username | Sherlock, Namechk |

---

## 🛠️ Core OSINT Tools

### 1. SpiderFoot (comprehensive OSINT Framework)

**Introduction**: automated OSINT collectTool，Supports 200+ module

**Installation**:
```bash
# Kali already 预install
spiderfoot --help
```

**Common Commands**:
```bash
# basic Scanning
spiderfoot -s <Target> -t <事件Type> -o <Output格式>

# bydynamicScanning
spiderfoot -s example.com -t INTERNET_NAME,DNS_ANY,SUBDOMAIN_HTTPS -u passive

# Output JSON
spiderfoot -s example.com -t ALL -o json > results.json
```

**Common Event Types**:
- `INTERNET_NAME`: domain name
- `DNS_ANY`: DNS record
- `SUBDOMAIN_HTTPS`: HTTPS Subdomains
- `EMAILADDR`: Emailaddress
- `PORT`: openPorts
- `IP_ADDRESS`: IP address

### 2. theHarvester (EmailandSubdomainscollect)

**Introduction**: EmailandSubdomainscollectTool

**Installation**:
```bash
pip install theHarvester
```

**Common Commands**:
```bash
# basic Email Collection
theHarvester -d example.com -b all

# specifydata sources
theHarvester -d example.com -b linkedin
theHarvester -d example.com -b crtsh
theHarvester -d example.com -b hunter

# OutputtoFile
theHarvester -d example.com -b all -f output.html
```

**Available Data Sources**:
- `google` - Google search (need API)
- `bing` - Bing search (need API)
- `linkedin` - LinkedIn employeesearch
- `crtsh` - Certificate Transparency
- `dnsdumpster` - DNS Enumerate
- `hunter` - Hunter.io
- `rapiddns` - RapidDNS

### 3. Sherlock (Username Search)

**Introduction**: in 300+ Social MediaplatformsearchUsername

**Installation**:
```bash
pip install sherlock
```

**Common Commands**:
```bash
# searchUsername
sherlock username1 username2

# Output JSON
sherlock username1 --json

# limitationlineprocess
sherlock username1 --timeout 60
```

### 4. h8mail (Email OSINT)

**Introduction**: Emailintelligencecollect，Supports 20+ data sources

**Installation**:
```bash
pip install h8mail
```

**Common Commands**:
```bash
# singleEmail Lookup
h8mail -t target@email.com

# batchamountquery
h8mail -t @targetdomain.com -l local

# ExportResult
h8mail -t target@email.com -o results.json
```

**data sources**:
- Hunter.io
- EmailMarker
- HaveIBeenPwned
- LeakCheck
- Skymem

### 5. sn0int (Semi-automatic OSINT Framework)

**Introduction**: structureize OSINT collectandThreat Intelligence

**Installation**:
```bash
# fromsourcecodeInstallation
cargo install sn0int

# orUse Docker
docker run -it kn33h7/sn0int
```

**Common Commands**:
```bash
# initializeworkworkzone
sn0int init

# runreconnaissance
sn0int -t target.com

# searchUsername
sn0int > search domain target.com
```

### 6. Recon-ng (Web reconnaissanceFramework)

**Introduction**: moduleize Web reconnaissanceTool

**Installation**:
```bash
# Kali already 预install
recon-ng
```

**Common Commands**:
```bash
# start
recon-ng

# adddomain name
[recon-ng] > add domains example.com

# Usemodule
[recon-ng] > modules search
[recon-ng] > use recon/domains-hosts/brute_hosts

# run
[recon-ng] > run

# Export
[recon-ng] > show contacts
[recon-ng] > export csv contacts.csv
```

### 7. Maltego (linkAnalysis)

**Introduction**: can viewizelinkAnalysisTool

**Installation**:
```bash
# Kali already 预install
maltego
```

**oftenuseFunction**:
- entitytransform (Transform)
- graphicalizedisplay
- Automated Analysis

### 8. Shodan (Network空intervalSearch Engines)

**Introduction**: 物联networkandServerSearch Engines

**Installation**:
```bash
pip install shodan
```

**Common Commands**:
```bash
# basic search
shodan search "apache"

# hostinformation
shodan host <IP>

# query API information
shodan info
```

### 9. theHarvester vs Sherlock vs h8mail

| Tool | Purpose | Enter | Output |
|------|------|------|------|
| theHarvester | Email+Subdomains | domain name | Email、personname、host |
| Sherlock | Username Search | Username | Social Mediaaccount |
| h8mail | Emailleakage | Email | leakagerecord |

---

## 🎯 OSINT Practical Workflow

### 1. bydynamicInformation Gathering

```bash
# 1. WHOIS query
whois example.com

# 2. DNS collect
subfinder -d example.com -o subdomains.txt
dnsx -d example.com -a -silent

# 3. certificatetransparentdegree
theHarvester -d example.com -b crtsh

# 4. Search Engines
theHarvester -d example.com -b google

# 5. SpiderFoot automated
spiderfoot -s example.com -t ALL -u passive
```

### 2. Email Intelligence

```bash
# Email Collection
theHarvester -d example.com -b all

# EmailleakageCheck
h8mail -t user@example.com

# searchEmailformat
theHarvester -d example.com -b hunter

# PGP keysearch
gpg --search-keys user@example.com
```

### 3. UsernameandSocial Media

```bash
# Username Search
sherlock username1 username2

# specificplatformsearch
theHarvester -d "Company Name" -b linkedin

# Social Media档案
theHarvester -d example.com -b twitter
```

### 4. Domains and Subdomains

```bash
# Subdomain Enumeration
subfinder -d example.com -o subdomains.txt
amass enum -passive -d example.com

# maindynamicScanning
nmap -p 80,443 --script dns-brute example.com

# brute force
gobuster dns -d example.com -w wordlist.txt
```

### 5. Leaked Credential Search

```bash
# GitHub search (Requires Token)
curl -H "Authorization: token <TOKEN>" \
  "https://api.github.com/search/code?q=example+password"

# Have I Been Pwned
curl "https://haveibeenpwned.com/api/v3/breachcheck?email=<EMAIL>"

# DeHashed (Requires API)
curl -H "API-Key: <KEY>" \
  "https://api.dehashed.com/search?query=example.com"
```

---

## 📊 Online OSINT Resources

### Search Engines

| Tool | URL | Description |
|------|-----|------|
| Google | https://www.google.com | advanced search运calculatecharacter |
| Bing | https://www.bing.com | 微softwaresearch |
| DuckDuckGo | https://duckduckgo.com | privacysearch |
| Yandex | https://yandex.com | 俄罗斯search，imagepowerful |
| Shodan | https://shodan.io | deviceSearch Engines |
| Censys | https://censys.io | certificateandhostData |

### Domains and DNS

| Tool | URL | Description |
|------|-----|------|
| WHOIS | https://whois.domaintools.com | domain nameinformation |
| DNSdumpster | https://dnsdumpster.com | DNS Enumerate |
| crt.sh | https://crt.sh | certificatetransparentdegree |
| VirusTotal | https://virustotal.com | URL/Domain Analysis |
| ThreatMiner | https://threatminer.org | Threat Intelligence |

### Email Lookup

| Tool | URL | Description |
|------|-----|------|
| Hunter.io | https://hunter.io | Emailfind |
| Email Finder | https://email-finder.io | EmailVerification |
| Have I Been Pwned | https://haveibeenpwned.com | leakageCheck |
| DeHashed | https://dehashed.com | Leaked Datalibrary |

### Social Media

| Tool | URL | Description |
|------|-----|------|
| Sherlock | https://sherlock.project | Username Search |
| Namechk | https://namechk.com | UsernameCheck |
| Social Searcher | https://social-searcher.com | socialexchangesearch |
| IntelTechniques | https://inteltechniques.com | OSINT Toolcollection |

### Leaked Data

| Tool | URL | Description |
|------|-----|------|
| LeakCheck | https://leakcheck.io | leakageCheck |
| Snusbase | https://snusbase.com | Leaked Datalibrary |
| weleakinfo | https://weleakinfo.com | leakagesearch |
| BreachChecker | https://breachchecker.com | Emailleakage |

### Business Information (in国)

| Tool | URL | Description |
|------|-----|------|
| Days眼查 | https://tianyancha.com | enterpriseinformation |
| 企查查 | https://qichacha.com | enterprisework商information |
| 启information宝 | https://qixin.com | enterpriseinformationuse |
| 爱企查 | https://aiqicha.baidu.com | 百degreeenterprise |

### Images and Geography

| Tool | URL | Description |
|------|-----|------|
| Google Images | https://images.google.com | imagesearch |
| TinEye | https://tineye.com | reverseimage |
| Yandex Images | https://yandex.com/images | imagesearch |
| Google Maps | https://maps.google.com | 地reasonlocate |
| Bing Maps | https://maps.bing.com | 微software地diagram |

### Archives and Data

| Tool | URL | Description |
|------|-----|------|
| Archive.org | https://archive.org | network页archive |
| Wayback Machine | https://web.archive.org | historyversion |
| Google Cache | cache:example.com | Google cache |

### Threat Intelligence

| Tool | URL | Description |
|------|-----|------|
| AlienVault OTX | https://otx.alienvault.com | Threat Intelligence |
| VirusTotal | https://virustotal.com | File/URL Analysis |
| AbuseIPDB | https://abuseipdb.com | IP 举report |
| IPinfo | https://ipinfo.io | IP details |
| GreyNoise | https://greynoise.io | interconnectnetworknoise |

---

## 🛡️ Privacy and Security Notes

### 1. Avoiding Detection

- Use VPN or Tor
- setcombinereason Requestinterval隔
- Useno害ize User-Agent
- avoiddirectAccessTargetSystem

### 2. Data Protection

- encryptionstoragesensitiveData
- regularly清reasonScanninglog
- Securitydeletetemporarywhen File

### 3. Compliance

- onlyScanningauthorizationTarget
- complywhen地method律methodrule
- protectcollectto personalinformation

---

## 📝 Tool Selection Guide

| Scenario | recommendTool |
|------|----------|
| quick reconnaissance | SpiderFoot |
| Email Collection | theHarvester + Hunter |
| Username Search | Sherlock |
| Emailleakage | h8mail |
| Subdomain Enumeration | subfinder + amass |
| Threat Intelligence | Shodan + AlienVault |
| Social Media | theHarvester (LinkedIn) |
| comprehensiveAnalysis | Maltego |
| automated | Recon-ng |

---

## 🔧 Troubleshooting

### pip Installationfailure (PEP 668)

```bash
# resolvesolution 1: UseSystempackage
sudo apt install python3-sherlock

# resolvesolution 2: forceInstallation
pip install --break-system-packages <package>

# resolvesolution 3: virtualEnvironment
python3 -m venv osint_env
source osint_env/bin/activate
pip install <package>
```

### API Key missing

```bash
# Configuration theHarvester API keys
cat /etc/theHarvester/api-keys.yaml
# add你 API keys
hunter: YOUR_API_KEY
```

### Toolsuperwhen

```bash
# Increasesuperwhen when interval
spiderfoot -s example.com -t ALL --max-threads 5

# Useafter台run
spiderfoot -s example.com -t ALL -o json > output.json &
```

---

## 📚 Further Learning Resources

- OSINT Framework: https://osintframework.com
- OSINT Framework (GitHub): https://github.com/lockfale/osint-framework
- TRACE Labs: https://tracelabs.org
- OSINT Techniques: https://inteltechniques.com
- Metactf: https://metactf.com

---

**update日period**: 2026-03-28
**version**: 1.0

---

## 🆕 newincreaseTool (2026-03-28)

### 9. Holehe (Email-servicerelated)

**Introduction**: CheckEmailin 120+ serviceon registersituation

**Installation**:
```bash
pip install holehe
```

**Common Commands**:
```bash
# CheckEmailrelated
holehe target@email.com

# OutputtoFile
holehe target@email.com -o results.txt
```

### 10. PhoneInfoga (phone number OSINT)

**Introduction**: phone numberintelligencecollect

**Installation**:
```bash
pip install phoneinfoga
```

**Common Commands**:
```bash
# basic Scanning
phoneinfoga -n +1234567890

# Detailed Scan
phoneinfoga -n +1234567890 -s all
```

### 11. GitHub Dorking (GitHub search)

**Introduction**: exploit GitHub API searchSensitive Information

**Common Searches**:
```bash
# searchspecificrepositorylibrary Password
curl -s "https://api.github.com/search/code?q=repo:owner/repo+password+in:file" 

# searchUser codeleakage
curl -s "https://api.github.com/search/code?q=user:username+password+in:file"

# searchOrganizationsensitiveFile
curl -s "https://api.github.com/search/code?q=org:company+application.yml+in:path"
```

**sensitivecritical词**:
```
password, secret, api_key, token, private_key,
aws_access_key, aws_secret_key, database.yml
```

### 12. Git-Dumper (Git repositorylibrarydownload)

**Introduction**: download GitHub repositorylibraryused forofflineAnalysis

**Installation**:
```bash
pip install git-dumper
```

**Common Commands**:
```bash
# downloadrepositorylibrary
git-dumper https://github.com/user/repo /output/dir
```

### 13. SN0int (structureize OSINT)

**Introduction**: Semi-automatic OSINT Framework，SupportsstructureizeDatacollect

**Installation**:
```bash
sudo apt-get install sn0int
```

**Common Commands**:
```bash
# createworkworkzone
sn0int workspace create osint_test

# runmodule
sn0int run <module>

# viewhelp
sn0int --help
```

