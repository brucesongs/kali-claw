# OSINT Payloads / attackpayloadlargeall

> thisfileis `SKILL.md` Supplementary Files，containsall OSINT commandandattackpayload，byclassotherorganization。

---

## 1. domain name / WHOIS reconnaissance / Domain & WHOIS Reconnaissance

```bash
# basic WHOIS query
whois example.com

# queryregister商information
whois -H example.com | grep -i "registrar\|name server\|creation\|expir"

# reverse WHOIS（throughregisterpersonfinditsotherdomain name）
# useonlineTool：whois.domaintools.com or viewdns.info

# WHOIS historyrecord
# DomainTools WHOIS History or whoisrequest.com
```

```bash
# domain name年龄andstatuscheck
whois example.com | grep -E "Creation Date|Expiry Date|Domain Status"
```

---

## 2. DNS Enumerate / DNS Enumeration

```bash
# queryall DNS record
dig any example.com @8.8.8.8

# queryspecificrecordtype
dig a example.com +short
dig mx example.com +short
dig ns example.com +short
dig txt example.com +short
dig soa example.com +short

# DNS zone transferattempt（oftenbydisablebutValue得attempt）
dig axfr example.com @ns1.example.com

# use dnsx batchamountsolveanalysis
dnsx -d example.com -a -silent
dnsx -d example.com -a -aaaa -cname -mx -ns -txt -silent

# reverse DNS query
dig -x <IP> @8.8.8.8
```

```bash
# DNS cachedetect
dig example.com +trace

# DNSSEC check
dig example.com DNSKEY +short
dig example.com DS +short
```

---

## 3. subdomain enumeration / Subdomain Enumeration

### subfinder

```bash
# basic bydynamicEnumerate
subfinder -d example.com -o subs_subfinder.txt

# enableall datasource
subfinder -d example.com -all -o subs_all.txt

# recursiveEnumerate
subfinder -d example.com -recursive -o subs_recursive.txt

# bandpart辨rateverify
subfinder -d example.com -o subs.txt && dnsx -l subs.txt -a -silent
```

### amass

```bash
# bydynamicEnumeratemode
amass enum -passive -d example.com -o subs_amass.txt

# maindynamicEnumerate（with DNS solveanalysis）
amass enum -active -d example.com -o subs_amass_active.txt

# brute forcemode
amass enum -brute -d example.com -o subs_amass_brute.txt

# usefromdefinitiondictionary
amass enum -brute -d example.com -w /path/to/wordlist.txt -o subs_custom.txt

# onlydisplaysolveanalysis subdomain name
amass enum -passive -d example.com -o subs.txt && amass track -d example.com
```

### gobuster dns

```bash
# DNS brute force
gobuster dns -d example.com -w /usr/share/wordlists/subdomains-top1mil-20000.txt

# bandsolveanalysisandspeedratecontrol
gobuster dns -d example.com -w /usr/share/wordlists/subdomains-top1mil-20000.txt -t 50 --delay 100ms

# usefromdefinition resolver
gobuster dns -d example.com -w wordlist.txt -r 8.8.8.8,1.1.1.1
```

### multipleToolcrossEnumerate

```bash
# mergededuplicateandverify
subfinder -d example.com -o subs_subfinder.txt
amass enum -passive -d example.com -o subs_amass.txt
sort -u subs_*.txt | httpx -silent -status-code -title

# complete flow水line
subfinder -d example.com -silent | dnsx -silent | httpx -silent -status-code -title -tech-detect
```

---

## 4. Google Dorking 运calculatecharacter / Google Dorking Operators

### basic 运calculatecharacter

```
site:example.com                    # 限定目标域名
inurl:admin                         # URL 中包含关键词
intitle:"index of"                  # 页面标题包含关键词
filetype:pdf                        # 搜索特定文件类型
intext:"password"                   # 页面正文包含关键词
cache:example.com                   # 查看缓存页面
link:example.com                    # 链接到目标的页面
related:example.com                 # 相似网站
```

### informationleakage Dork

```
# exposure directorylist
site:example.com intitle:"index of" "parent directory"

# exposure configurationfile
site:example.com filetype:env OR filetype:yml OR filetype:ini "password"

# exposure databasefile
site:example.com filetype:sql OR filetype:db OR filetype:mdb

# exposure logfile
site:example.com filetype:log inurl:"log"

# exposure backupfile
site:example.com filetype:bak OR filetype:backup OR filetype:old

# loginpage
site:example.com inurl:login OR inurl:admin OR inurl:dashboard
```

### credentialssearch Dork

```
# publicdocumentationin sensitiveinformation
site:example.com filetype:xlsx OR filetype:csv "password" OR "username"

# GitHub on leakage
"example.com" password OR secret OR api_key site:github.com

# Paste sitepointleakage
site:pastebin.com "example.com"
site:paste.ee "example.com"
```

---

## 5. email addresscollect / Email Harvesting

### theHarvester

```bash
# alldatasourceemail addresscollect
theHarvester -d example.com -b all

# specificdatasource
theHarvester -d example.com -b google
theHarvester -d example.com -b bing
theHarvester -d example.com -b linkedin
theHarvester -d example.com -b twitter
theHarvester -d example.com -b hunter
theHarvester -d example.com -b crtsh

# export HTML report
theHarvester -d example.com -b all -f recon_report.html

# use DNS solveanalysis
theHarvester -d example.com -b all -n
```

### h8mail

```bash
# singleemail addressleakagecheck
h8mail -t target@email.com

# entiredomain nameleakagecheck
h8mail -t @targetdomain.com -l local

# fromfilebatchamountcheck
h8mail -t @targetdomain.com -l local -o leaks.json

# specifydatasource
h8mail -t user@example.com -c config.ini
```

### Holehe

```bash
# checkemail addressin 120+ service registersituation
holehe user@example.com

# batchamountcheck
for email in user1@example.com user2@example.com; do
  holehe "$email"
done
```

### PGP keysearch

```bash
# through PGP keyserversearchemail address
gpg --search-keys user@example.com

# useonline PGP search
# https://keys.openpgp.org/
# https://keyserver.ubuntu.com/
```

---

## 6. social mediaintelligence / Social Media Intelligence

### Sherlock - crossplatformusernamesearch

```bash
# singleusernamesearch
sherlock username

# multipleusernamesearch
sherlock user1 user2 user3

# JSON output
sherlock username --json

# outputtofile
sherlock user1 user2 user3 --json -o social_accounts.json

# specifysitepoint
sherlock username --site twitter --site github
```

### theHarvester socialexchangesearch

```bash
# LinkedIn employeesearch
theHarvester -d "Company Name" -b linkedin

# Twitter related
theHarvester -d example.com -b twitter
```

### PhoneInfoga - phone numberintelligence

```bash
# singlenumbercodeScan
phoneinfoga -n +1234567890 -s all

# batchamountScan
phoneinfoga -i numbers.txt -s all -o results.json

# Web interfacemode
phoneinfoga serve -p 8080
```

---

## 7. metadata extraction / Metadata Extraction

### exiftool

```bash
# Extractfilemetadata
exiftool document.pdf
exiftool image.jpg

# batchamountExtractdirectoryinall file metadata
exiftool -r /path/to/files/

# ExtractspecificField
exiftool -Creator -Author -Producer -LastModifiedBy document.pdf

# GPS coordinatesExtract
exiftool -gps:all image.jpg

# deletemetadata（defensePurpose）
exiftool -all= document.pdf
exiftool -all= image.jpg

# Extract Word documentationfix订history
exiftool -LastModifiedBy -Creator -ModifyDate document.docx
```

### FOCA（Windows GUI Tool）

```
# throughsearchenginebatchamountExtractdocumentationmetadata
# searchtargetdomain name .pdf, .docx, .xlsx file
# Extractusername、printmachinename、path、softwarepieceversionetc.information
```

### mat2（metadata匿nameize）

```bash
# viewmetadata
mat2 -s document.pdf

# clearmetadata
mat2 document.pdf
```

---

## 8. Shodan / Censys query / Shodan & Censys Queries

### Shodan

```bash
# initialize API Key
shodan init <API_KEY>

# searchorganizationasset
shodan search "org:Example Corp"

# view IP details
shodan host <IP>

# searchspecificportandservice
shodan search "port:3389 org:Example Corp"
shodan search "port:22 org:Example Corp"
shodan search "port:443 ssl.cert.subject.cn:example.com"

# searchspecificdevice
shodan search "product:Apache httpd"
shodan search "product:nginx version:1.18"

# searchexposure service
shodan search "port:3306 mysql"
shodan search "port:5432 postgresql"
shodan search "port:27017 mongodb"
shodan search "port:6379 redis"

# searchvulnerabilitydevice
shodan search "vuln:CVE-2021-44228"
shodan search "vuln:CVE-2023-44487"

# statisticssearchresult
shodan count "org:Example Corp"
shodan stats "org:Example Corp"

# facilitysearch
shodan search "net:<CIDR>"

# exportsearchresult
shodan download results "org:Example Corp" --limit 100
shodan parse --fields ip_str,port,org,hostnames results.json.gz
```

### Censys

```bash
# searchcertificate（Web UI）
# https://search.censys.io/certificates?q=parsed.names:example.com

# searchhost
# https://search.censys.io/hosts?q=services.tls.certificates.leaf.names:example.com

# oftenuse Censys querysyntax
# services.port:443 AND services.tls.certificates.leaf.names:example.com
# services.software.product:nginx AND location.country_code:CN
# services.port:3389 AND autonomous_system.name:EXAMPLE-CORP
```

---

## 9. techniquefingerprinting / Technology Fingerprinting

### whatweb

```bash
# singletargetIdentify
whatweb example.com

# 聚combinelevelotherScan
whatweb -a 3 example.com

# batchamountScan
whatweb -i urls.txt -o results.txt

# detailed output
whatweb -v example.com

# JSON output
whatweb example.com --output json -o results.json

# searchspecifictechnique
whatweb -s "WordPress,PHP,nginx" example.com
```

### Wappalyzer（browsetoolextension + CLI）

```bash
# CLI use（wappalyzer-cli）
wappalyzer https://example.com

# browsetoolextension：directaccesstargetwebsiteviewDetectresult
```

### httpx techniqueDetect

```bash
# batchamounttechniqueDetect
httpx -l subdomains.txt -silent -tech-detect -status-code -title

# complete fingerprint
httpx -l subdomains.txt -silent -tech-detect -status-code -title -server -content-length -web-server
```

### HTTP responseheadanalysis

```bash
# HTTP responseheadanalysis
curl -sI https://example.com | grep -i "server\|x-powered-by\|x-aspnet"

# Cookie characteristicanalysis
curl -sI https://example.com | grep -i "set-cookie"
```

---

## 10. GitHub codeleakagesearch / GitHub Code Leak Search

```bash
# searchorganizationsensitivefile
curl -s "https://api.github.com/search/code?q=org:target+filename:.env" | jq '.items[].html_url'
curl -s "https://api.github.com/search/code?q=org:target+password+in:file" | jq '.items[].html_url'

# batchamountsearchcriticalcredentialscritical词
for keyword in password secret api_key token private_key aws_access_key; do
  curl -s "https://api.github.com/search/code?q=org:target+${keyword}+in:file" | jq '.items[].html_url'
done

# searchspecificrepositorylibraryin sensitiveinformation
curl -s "https://api.github.com/search/code?q=repo:owner/repo+secret+in:path" | jq '.items[].html_url'

# downloadcan suspiciousrepositorylibrarydeep analysis
git-dumper https://github.com/target/suspicious-repo /tmp/audit
grep -rn "password\|api_key\|secret\|token\|aws_" /tmp/audit/ --include="*.yml" --include="*.env" --include="*.json"

# leakagedatabasequery
curl -s "https://haveibeenpwned.com/api/v3/breachedaccount/<EMAIL>" -H "hibp-api-key: <KEY>"
```

---

## 11. SpiderFoot allautomated Scan / SpiderFoot Automated Scanning

```bash
# bydynamicmodeScan（not接触target）
spiderfoot -s example.com -t INTERNET_NAME,DNS_ANY,SUBDOMAIN_HTTPS -u passive

# allmoduleScan
spiderfoot -s example.com -t ALL -u passive -o json > full_osint.json

# Web UI mode
spiderfoot -l 127.0.0.1:5001
```

---

## 12. Recon-ng automated flow水line / Recon-ng Automated Pipeline

```bash
# startandcreateworkworkzone
recon-ng
[recon-ng] > workspaces create target_recon

# addtargetdomain name
[recon-ng] > add domains example.com

# subdomain enumerationmodulechain
[recon-ng] > use recon/domains-hosts/brute_hosts
[recon-ng] > run
[recon-ng] > use recon/hosts-hosts/resolve
[recon-ng] > run

# email addresscollect
[recon-ng] > use recon/domains-contacts/email-harvester
[recon-ng] > set source example.com
[recon-ng] > run

# exportresult
[recon-ng] > show hosts
[recon-ng] > show contacts
[recon-ng] > export csv /tmp/recon_results.csv
```

---

## 13. certificatetransparentdegreequery / Certificate Transparency

```bash
# crt.sh query
curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq '.[].name_value' | sort -u

# through theHarvester query
theHarvester -d example.com -b crtsh

# use certspotter
curl -s "https://api.certspotter.com/v1/issuances?domain=example.com&include_subdomains=true" | jq '.[].dns_names[]'
```
