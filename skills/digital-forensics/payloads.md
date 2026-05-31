# Payloads: digital forensics / Digital Forensics

> thisfileas `SKILL.md` Supplementary Files，containsdigital forensicsallprocess commandquick referencemanual。

---

## 1. diskimageandobtain / Disk Imaging and Acquisition

### dd / dcfldd 逐bitimage

```bash
# use dcfldd create逐bitimageandchecksumhash
dcfldd if=/dev/sdb of=evidence.dd hash=sha256 hashlog=hash.txt

# usestandard dd createimage
dd if=/dev/sdb of=evidence.dd bs=4K conv=noerror,sync status=progress

# calculateimagehashchecksumValue
sha256sum evidence.dd > evidence.sha256
md5sum evidence.dd > evidence.md5

# verifyimageintegrity（forthanrawmediaandimage）
dcfldd if=/dev/sdb hash=sha256 hashlog=original.txt verifylog=verify.txt
```

### FTK Imager（GUI Tool）

```bash
# commandrowmodecreateimage
ftk imager.exe evidence.dd --verify

# FTK Imager supports: E01/Ex01 format、compression、inner嵌hash
```

---

## 2. filesystemanalysis / File System Analysis

### SleuthKit commandrowToolset

```bash
# viewpartition tableoffset
mmls evidence.dd

# filesysteminformation
fsstat -o 2048 evidence.dd

# recursivelistfileanddirectory
fls -r -o 2048 evidence.dd

# by inode Extractfilecontent
icat -o 2048 evidence.dd 12345

# listalready delete inode
ils -o 2048 evidence.dd

# findspecifyfilenameforshould inode
ifind -o 2048 -n "secret.doc" evidence.dd

# byblockaddressfindmetadatastructure
blkcat -o 2048 evidence.dd 1024
```

### Autopsy platform

```bash
# start Autopsy Web platform
autopsy -p 8080 -d /case/evidence
# browsetoolaccess http://localhost:8080
# create Case -> add Data Source -> selectimagefile -> selectwhen zone
```

**Autopsy criticalanalysissuccesscan**:
- Data Source -> searchalready knowmaliciousfilehash
- Deleted Files -> recovercomplexalready deletecontent
- File Metadata -> view MAC when timestamp
- Keyword Search -> searchsensitivecritical词
- Extract -> Extract EXIF metadataand地reasoncoordinates

---

## 3. memory forensics / Memory Forensics

### Volatility framework

```bash
# Identifyoperationsystem profile
vol.py -f memory.dmp imageinfo

# processanalysis
vol.py -f memory.dmp --profile=Win10x64_19041 pslist       # 进程列表
vol.py -f memory.dmp --profile=Win10x64_19041 pstree       # 进程树
vol.py -f memory.dmp --profile=Win10x64_19041 psxview      # 检测隐藏进程
vol.py -f memory.dmp --profile=Win10x64_19041 psscan       # 进程扫描（Pool tag）

# maliciouscodeDetect
vol.py -f memory.dmp --profile=Win10x64_19041 malfind      # 检测代码注入
vol.py -f memory.dmp --profile=Win10x64_19041 apihooks     # 检测 API hook
vol.py -f memory.dmp --profile=Win10x64_19041 ssdt         # 检查 SSDT hook

# networkconnectExtract
vol.py -f memory.dmp --profile=Win10x64_19041 netscan      # 网络连接扫描
vol.py -f memory.dmp --profile=Win10x64_19041 connscan     # TCP 连接扫描
vol.py -f memory.dmp --profile=Win10x64_19041 sockets      # Socket 扫描

# Extractcan suspiciousprocess DLL andmemory
vol.py -f memory.dmp --profile=Win10x64_19041 dlllist -p 1234     # DLL 列表
vol.py -f memory.dmp --profile=Win10x64_19041 procdump -p 1234 -D /output  # 进程转储
vol.py -f memory.dmp --profile=Win10x64_19041 dlldump -p 1234 -D /output    # DLL 转储

# registertableanalysis
vol.py -f memory.dmp --profile=Win10x64_19041 hivelist            # 注册表 hive 列表
vol.py -f memory.dmp --profile=Win10x64_19041 printkey -o 0xfffff80  # 打印注册表键值

# credentialsExtract
vol.py -f memory.dmp --profile=Win10x64_19041 hashdump    # SAM 哈希
vol.py -f memory.dmp --profile=Win10x64_19041 cachedump   # 缓存凭据
vol.py -f memory.dmp --profile=Win10x64_19041 mimikatz    # Mimikatz 提取
```

---

## 4. network forensics / Network Forensics

### Wireshark / tshark filtertool

```bash
# basic statisticsand概览
tshark -r capture.pcap -q -z io,stat,1           # 流量统计
tshark -r capture.pcap -q -z conv,ip              # IP 对话统计
tshark -r capture.pcap -q -z endpoints,ip         # 端点统计

# HTTP requestalsooriginal
tshark -r capture.pcap -Y "http.request" -T fields \
  -e frame.time -e ip.src -e http.host -e http.request.uri

# DNS queryanalysis（Identifymaliciousdomain name）
tshark -r capture.pcap -Y "dns.qr==0" -T fields \
  -e frame.time -e ip.src -e dns.qry.name | sort | uniq -c | sort -rn

# Extracttransmissionfile
tshark -r capture.pcap --export-objects http,/output/http_files
tshark -r capture.pcap --export-objects smb,/output/smb_files

# TLS metadata extraction（Identify C2 communication）
tshark -r capture.pcap -Y "tls.handshake.type==1" -T fields \
  -e ip.dst -e tls.handshake.extensions_server_name

# dataexfiltrationDetect（DNS tunnelDetect）
tshark -r capture.pcap -Y "dns" -T fields -e dns.qry.name \
  | awk '{print length, $0}' | sort -rn | head -20

# Extractspecific IP alldepartmentflowamount
tshark -r capture.pcap -Y "ip.addr==192.168.1.100" -w filtered.pcap

# HTTP POST requestbodyExtract
tshark -r capture.pcap -Y "http.request.method==POST" -T fields \
  -e frame.time -e ip.src -e ip.dst -e http.request.uri -e http.file_data

# SMTP mailpieceExtract
tshark -r capture.pcap -Y "smtp" -T fields \
  -e frame.time -e smtp.from -e smtp.to -e smtp.data
```

---

## 5. loganalysiscommand / Log Analysis

```bash
# SSH brute forceDetect
grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head

# Apache access loganalysis - statistics HTTP statuscode
awk '{print $9}' /var/log/apache2/access.log | sort | uniq -c | sort -rn

# Nginx log - Extractspecificwhen intervalsegment request
awk '$4 ~ /26\/Apr\/2026:1[0-2]:/' /var/log/nginx/access.log

# system log - Extract sudo operation
grep "sudo:" /var/log/auth.log

# dmesg kernelloganalysis
dmesg -T | grep -i "error\|warn\|fail"

# lastlog userloginrecord
lastlog | grep -v "Never"

# last commandviewloginhistory
last -n 50 -a
```

---

## 6. when timelineanalysis / Timeline Analysis

```bash
# SleuthKit generate MAC when timeline
fls -m "/" -o 2048 evidence.dd > timeline_body.txt
mactime -b timeline_body.txt > timeline.csv

# log2timeline (Plaso) generatesuperlevelwhen timeline
log2timeline.py --storage-file case.plaso /case/evidence
psort.py -o dynamic -w timeline.csv case.plaso

# relatedanalysis（comprehensivedisk + network + memory）
# willwithbelowsource when timestampunifiedimportanalysisTool:
# - disk: fls -m output MAC when interval
# - network: tshark Extract frame.time
# - memory: volatility pslist processcreatewhen interval
# - log: /var/log/auth.log, Windows Event Log

# criticaleventsorting（close注abnormalwhen intervalpoint）
# - filecreate/modify（maliciouspayload落地）
# - processstart（vulnerability exploitationexecute）
# - networkconnect（C2 returnconnect、dataexfiltration）
# - userlogin（lateral movement）
```

---

## 7. filecarving / File Carving

### foremost

```bash
# byspecifyfilesignaturerecovercomplex
foremost -t jpg,png,pdf,doc,zip -i evidence.dd -o /recovery

# recovercomplexall already knowtype
foremost -t all -i damaged_disk.img -o /recovery_all
```

### binwalk

```bash
# Scanfilesignature
binwalk evidence.dd

# recursiveExtractall embedfile
binwalk -Me evidence.dd

# Extractspecifictypefile
binwalk --dd='png:image' firmware.bin
```

### scalpel

```bash
# 精细controlfilecarving
scalpel -c /etc/scalpel/scalpel.conf -o /output evidence.dd
```

### bulk_extractor

```bash
# highitycancharacteristicExtract
bulk_extractor -o /output evidence.dd
# output: email.txt, url.txt, credit_card.txt, phone.txt etc.
```

### exiftool（metadataanalysis）

```bash
# recursiveviewmetadata
exiftool -r /recovery/

# JSON formatoutput
exiftool -json /recovery/*.jpg

# close注: GPS coordinates、createwhen interval、deviceinformation、modifyhistory
```

---

## 8. anti-forensicsDetect / Anti-Forensics Detection

```bash
# Detectwhen timestamptamper（Timestomping）
# forthanfilesystem MAC when intervalandfilecontentmetadata notconsistent
fls -m "/" -o 2048 evidence.dd | sort -k 3,3 > mac_times.txt

# Detectdisk擦除trace
# viewdisk末尾andnot partmatch空intervaliswhetherby清零
dd if=evidence.dd bs=1M skip=XXXX count=1 | xxd | head -20

# Detectencryptioncontainer
binwalk evidence.dd | grep -i "truecrypt\|veracrypt\|luks"

# Detect Steganography（隐write）
steghide extract -sf suspicious.jpg -p ""
stegseek --crack suspicious.jpg /usr/share/wordlists/rockyou.txt

# Detectlogclear
# forthanlogfile continuousityandwhen intervalinterval隔abnormal
awk 'NR>1 {print prev, $0, $0-prev} {prev=$0}' /var/log/syslog

# Detect ADS（Alternate Data Streams）- NTFS
# in Windows imageincheck
streams -s suspicious_file.exe
```

---

## 9. Windows forensics / Windows Forensics

### registertableanalysis

```bash
# use Volatility Extractregistertable hive
vol.py -f memory.dmp --profile=Win10x64_19041 hivelist
vol.py -f memory.dmp --profile=Win10x64_19041 printkey -o 0xfffff80 -K "Software\Microsoft\Windows\CurrentVersion\Run"

# common registertableforensicsbitconfiguration
# HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run - fromstartitem
# HKLM\SYSTEM\CurrentControlSet\Services - serviceitem
# HKLM\SAM - useraccountandpasswordhash
# HKLM\SYSTEM\MountedDevices - mountdevicerecord
# NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer - useractivity
```

### Windows event log

```bash
# use Volatility Extractevent log
vol.py -f memory.dmp --profile=Win10x64_19041 evtlogs -D /output

# criticalevent ID
# 4624 - successlogin / 4625 - loginfailure
# 4688 - processcreate / 4689 - processterminate
# 4720 - useraccountcreate / 4728/4732 - useraddtoadministratorgroup
# 7045 - serviceinstall / 7036 - servicestatuschange
# 1102 - audit logclear
# 4697 - serviceinstall（maliciousserviceDetect）

# use LogParser analysis .evtx
LogParser.exe -i:EVT "SELECT TimeGenerated, SourceName, EventID, Message FROM security.evtx WHERE EventID=4624"
```

---

## 10. Linux forensics / Linux Forensics

### /var/log system log

```bash
# auth.log - authenticationlog
cat /var/log/auth.log | grep -i "accepted\|failed\|invalid"

# syslog - systemmessage
cat /var/log/syslog | grep -i "error\|fail\|critical"

# kern.log - kernellog
cat /var/log/kern.log

# usercommandhistory
cat ~/.bash_history
cat ~/.zsh_history

# userloginrecord
last -f /var/log/wtmp
lastb -f /var/log/btmp  # 失败登录

# cron log
cat /var/log/cron.log
grep -i "cron" /var/log/syslog
```

### journalctl (systemd)

```bash
# viewalldepartmentlog
journalctl --no-pager

# bywhen intervalscopefilter
journalctl --since "2026-04-25 00:00:00" --until "2026-04-26 00:00:00"

# byservicefilter
journalctl -u sshd
journalctl -u apache2

# byPriorityfilter
journalctl -p err -b    # 当前启动的错误级别日志

# byprocess PID filter
journalctl _PID=1234

# viewstartlog
journalctl -b -1   # 上一次启动
journalctl -b 0    # 当前启动

# outputas JSON（thenatfollow-upanalysis）
journalctl -o json-pretty --since "2026-04-25"
```

### /proc and /etc forensics

```bash
# currentrunprocess
ps auxf
ls -la /proc/[0-9]*/exe    # 进程可执行文件链接
ls -la /proc/[0-9]*/fd     # 进程文件描述符

# already mountfilesystem
cat /proc/mounts
findmnt

# networkconnect
ss -tulpn
cat /proc/net/tcp

# 定when task
crontab -l
cat /etc/crontab
ls -la /etc/cron.*
ls -la /var/spool/cron/

# userandgroup
cat /etc/passwd | grep -v "nologin\|false"
cat /etc/shadow
cat /etc/group
```

---

## 11. Memory Acquisition

### LiME (Linux Memory Extractor)

```bash
# Build LiME kernel module for target system
cd LiME/src
make
# Load module and dump memory to file
insmod lime-$(uname -r).ko "path=/tmp/memory.lime format=lime"

# Dump memory over network (avoid writing to target disk)
insmod lime-$(uname -r).ko "path=tcp:4444 format=lime"
# On forensic workstation:
nc target_ip 4444 > memory.lime

# Dump memory in raw format (compatible with more tools)
insmod lime-$(uname -r).ko "path=/tmp/memory.raw format=raw"

# Dump memory with timeout (for large RAM systems)
insmod lime-$(uname -r).ko "path=/tmp/memory.lime format=lime timeout=0"

# Verify dump integrity
sha256sum /tmp/memory.lime > /tmp/memory.lime.sha256
```

### WinPmem (Windows Memory Acquisition)

```bash
# Dump physical memory to raw file
winpmem_mini_x64.exe memory.raw

# Dump to AFF4 format (compressed, with metadata)
winpmem_mini_x64.exe -o memory.aff4

# Dump specific address range
winpmem_mini_x64.exe --mode physical -o memory.raw

# Dump with page file included
winpmem_mini_x64.exe -p pagefile.sys -o memory_with_pagefile.raw

# Verify acquisition
certutil -hashfile memory.raw SHA256
```

### Remote Memory Capture

```bash
# Remote memory acquisition via SSH (Linux target)
ssh root@target "insmod /tmp/lime.ko 'path=tcp:4444 format=lime'" &
nc target 4444 > remote_memory.lime

# Remote memory acquisition via WinRM (Windows target)
# Upload winpmem and execute remotely
Invoke-Command -ComputerName target -ScriptBlock { C:\temp\winpmem.exe C:\temp\mem.raw }
Copy-Item -Path \\target\C$\temp\mem.raw -Destination .\evidence\

# AVML (Acquire Volatile Memory for Linux) - no kernel module needed
./avml memory.lime
./avml --compress memory.lime.zst

# Capture memory from VMware virtual machine
vmss2core -W virtual_machine.vmss virtual_machine.vmem
# Or directly copy .vmem file while VM is running

# Capture memory from VirtualBox
VBoxManage debugvm "VM_Name" dumpvmcore --filename=memory.elf
```

---

## 12. Volatility3 Analysis

### Process Analysis

```bash
# List running processes
vol3 -f memory.raw windows.pslist.PsList
vol3 -f memory.raw windows.pstree.PsTree

# Detect hidden processes (compare multiple sources)
vol3 -f memory.raw windows.psscan.PsScan

# Process command line arguments
vol3 -f memory.raw windows.cmdline.CmdLine

# Process environment variables
vol3 -f memory.raw windows.envars.Envars --pid 1234

# DLL listing for specific process
vol3 -f memory.raw windows.dlllist.DllList --pid 1234

# Process memory map
vol3 -f memory.raw windows.memmap.Memmap --pid 1234 --dump
```

### Network Connection Analysis

```bash
# Active network connections
vol3 -f memory.raw windows.netscan.NetScan

# Filter for established connections
vol3 -f memory.raw windows.netscan.NetScan | grep ESTABLISHED

# Filter for listening ports
vol3 -f memory.raw windows.netscan.NetScan | grep LISTENING

# Linux network connections
vol3 -f memory.lime linux.sockstat.Sockstat

# Identify suspicious outbound connections (non-standard ports)
vol3 -f memory.raw windows.netscan.NetScan | awk '$4 !~ /:80$|:443$|:53$/ && $6 == "ESTABLISHED"'
```

### Malware Detection

```bash
# Detect injected code (RWX memory regions)
vol3 -f memory.raw windows.malfind.Malfind

# Dump suspicious process memory for analysis
vol3 -f memory.raw windows.malfind.Malfind --dump --pid 1234

# Check for API hooks
vol3 -f memory.raw windows.ssdt.SSDT

# Scan for known malware signatures with YARA
vol3 -f memory.raw windows.vadyarascan.VadYaraScan --yara-file malware_rules.yar

# Registry analysis (persistence mechanisms)
vol3 -f memory.raw windows.registry.printkey.PrintKey --key "Software\Microsoft\Windows\CurrentVersion\Run"

# Extract handles (files, registry keys, mutexes)
vol3 -f memory.raw windows.handles.Handles --pid 1234
```

### Volatility3 Linux Analysis

```bash
# Linux process listing
vol3 -f memory.lime linux.pslist.PsList
vol3 -f memory.lime linux.pstree.PsTree

# Linux bash history from memory
vol3 -f memory.lime linux.bash.Bash

# Linux loaded kernel modules (detect rootkits)
vol3 -f memory.lime linux.lsmod.Lsmod

# Linux mount points
vol3 -f memory.lime linux.mountinfo.MountInfo

# Linux network connections
vol3 -f memory.lime linux.sockstat.Sockstat

# Check for LD_PRELOAD rootkits
vol3 -f memory.lime linux.envars.Envars | grep LD_PRELOAD
```

---

## 13. Disk Forensics

### DD Imaging with Verification

```bash
# Create forensic image with dcfldd (enhanced dd)
dcfldd if=/dev/sdb of=evidence.dd bs=4K hash=sha256 hashlog=hash.log hashwindow=1G

# Create split image (for large disks)
dcfldd if=/dev/sdb of=evidence.dd.split bs=4K split=2G hash=sha256

# Create E01 (Expert Witness) format image with ewfacquire
ewfacquire /dev/sdb -t evidence -f encase6 -c deflate:best -S 2G

# Mount E01 image for analysis
ewfmount evidence.E01 /mnt/ewf/
mount -o ro,loop /mnt/ewf/ewf1 /mnt/evidence/

# Verify image integrity
dcfldd if=evidence.dd hash=sha256 hashlog=verify.log
diff hash.log verify.log

# Create image over network (avoid writing to evidence disk)
ssh root@target "dd if=/dev/sda bs=4K" | dd of=remote_evidence.dd bs=4K
```

### File Carving and Recovery

```bash
# Foremost - recover files by header/footer signatures
foremost -t jpg,png,pdf,doc,xls,zip -i evidence.dd -o /recovery/

# PhotoRec - advanced file recovery
photorec /d /recovery/ evidence.dd

# Scalpel - configurable file carving
scalpel -c /etc/scalpel/scalpel.conf -o /recovery/ evidence.dd

# Bulk Extractor - extract artifacts (emails, URLs, credit cards)
bulk_extractor -o /output/ evidence.dd
# Review: email.txt, url.txt, ccn.txt, telephone.txt

# Recover deleted files from ext4 filesystem
extundelete evidence.dd --restore-all --output-dir /recovery/

# Recover deleted files from NTFS
ntfsundelete /dev/sdb1 -u -m '*.docx' -d /recovery/
```

### Deleted File Recovery and Slack Space

```bash
# List deleted files in filesystem
fls -rd -o 2048 evidence.dd

# Recover specific deleted file by inode
icat -o 2048 evidence.dd 12345 > recovered_file.doc

# Extract file slack space (data between EOF and end of cluster)
blkls -s evidence.dd > slack_space.raw
strings slack_space.raw | grep -iE "password|secret|key"

# Search unallocated space for keywords
blkls evidence.dd > unallocated.raw
grep -boa "password" unallocated.raw

# Recover deleted partitions
testdisk evidence.dd
# Interactive: Analyze -> Quick Search -> Write partition table
```

### Filesystem Timeline Generation

```bash
# Generate body file from filesystem
fls -r -m "/" -o 2048 evidence.dd > body.txt

# Create timeline from body file
mactime -b body.txt -d > timeline.csv

# Filter timeline by date range
mactime -b body.txt -d "2026-01-01..2026-01-31" > january_timeline.csv

# Generate NTFS-specific timeline (includes $MFT metadata)
analyzeMFT.py -f \$MFT -o mft_timeline.csv -e

# Combine multiple timeline sources
cat body_disk1.txt body_disk2.txt > combined_body.txt
mactime -b combined_body.txt -d > combined_timeline.csv
```

---

## 14. Log Analysis

### Windows Event Log Analysis

```bash
# Parse Windows Event Logs with evtx_dump
evtx_dump.py Security.evtx > security_events.xml

# Search for logon events (Event ID 4624)
evtx_dump.py Security.evtx | grep -A 20 "EventID.*4624"

# Search for failed logons (Event ID 4625)
evtx_dump.py Security.evtx | grep -A 20 "EventID.*4625" | grep -E "TargetUserName|IpAddress"

# Search for new service installations (Event ID 7045)
evtx_dump.py System.evtx | grep -A 15 "EventID.*7045"

# Search for PowerShell execution (Event ID 4104)
evtx_dump.py Microsoft-Windows-PowerShell%4Operational.evtx | grep -A 30 "EventID.*4104"

# Detect log clearing (Event ID 1102)
evtx_dump.py Security.evtx | grep -A 10 "EventID.*1102"
```

### Syslog Parsing and Analysis

```bash
# Parse auth.log for SSH brute force
grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head -20

# Detect successful SSH logins after failed attempts
grep "Accepted" /var/log/auth.log | awk '{print $1,$2,$3,$9,$11}'

# Parse Apache/Nginx logs for suspicious requests
awk '$9 >= 400' /var/log/apache2/access.log | awk '{print $7}' | sort | uniq -c | sort -rn | head -20

# Detect SQL injection attempts in web logs
grep -iE "union.*select|or.*1=1|drop.*table|insert.*into" /var/log/apache2/access.log

# Detect command injection attempts
grep -iE ";\s*(ls|cat|id|whoami|wget|curl)" /var/log/apache2/access.log

# Parse syslog for privilege escalation indicators
grep -iE "sudo|su\[|pkexec|polkit" /var/log/auth.log | grep -v "session opened"
```

### Timeline Construction from Multiple Sources

```bash
# Combine filesystem, log, and network timelines
# Step 1: Generate filesystem timeline
fls -r -m "/" evidence.dd > body.txt
mactime -b body.txt -d > fs_timeline.csv

# Step 2: Parse logs into timeline format
awk '{print $1" "$2" "$3",LOG,"$0}' /var/log/auth.log > log_timeline.csv

# Step 3: Parse network capture timestamps
tshark -r capture.pcap -T fields -e frame.time -e ip.src -e ip.dst -e tcp.dstport \
  | awk -F'\t' '{print $1",NETWORK,"$2" -> "$3":"$4}' > net_timeline.csv

# Step 4: Merge and sort all timelines
cat fs_timeline.csv log_timeline.csv net_timeline.csv | sort -t',' -k1 > master_timeline.csv

# Step 5: Use Plaso for automated super-timeline
log2timeline.py --storage-file case.plaso /evidence/
psort.py -o l2tcsv -w super_timeline.csv case.plaso "date > '2026-01-01' AND date < '2026-02-01'"
```

### Log Correlation and Anomaly Detection

```bash
# Correlate login events with file access
# Find files modified within 5 minutes of SSH login
login_time=$(grep "Accepted publickey" /var/log/auth.log | tail -1 | awk '{print $1" "$2" "$3}')
find / -newer /tmp/login_marker -mmin -5 2>/dev/null

# Detect unusual process execution times (off-hours activity)
journalctl --since "22:00" --until "06:00" | grep -iE "exec|spawn|fork"

# Detect data exfiltration patterns (large outbound transfers)
tshark -r capture.pcap -q -z conv,ip | sort -k 6 -rn | head -10

# Correlate DNS queries with process execution
paste <(tshark -r capture.pcap -Y "dns.qr==0" -T fields -e frame.time -e dns.qry.name) \
      <(vol3 -f memory.raw windows.cmdline.CmdLine) 2>/dev/null
```

---

## 15. Network Forensics

### PCAP Deep Analysis

```bash
# Protocol hierarchy statistics
tshark -r capture.pcap -q -z io,phs

# Extract all HTTP objects (files transferred)
tshark -r capture.pcap --export-objects http,/output/http_objects/

# Extract all SMB objects
tshark -r capture.pcap --export-objects smb,/output/smb_objects/

# Reconstruct TCP streams
tshark -r capture.pcap -q -z follow,tcp,ascii,0

# Extract credentials from unencrypted protocols
tshark -r capture.pcap -Y "ftp.request.command == USER || ftp.request.command == PASS" -T fields -e ftp.request.arg

# Extract HTTP POST data (potential credential submission)
tshark -r capture.pcap -Y "http.request.method == POST" -T fields \
  -e frame.time -e ip.src -e http.host -e http.request.uri -e http.file_data
```

### DNS Exfiltration Detection

```bash
# Detect unusually long DNS queries (potential data exfiltration)
tshark -r capture.pcap -Y "dns.qr==0" -T fields -e dns.qry.name \
  | awk '{if(length($0) > 50) print length($0), $0}' | sort -rn

# Detect high-frequency DNS queries to single domain
tshark -r capture.pcap -Y "dns.qr==0" -T fields -e dns.qry.name \
  | awk -F'.' '{print $(NF-1)"."$NF}' | sort | uniq -c | sort -rn | head -20

# Detect TXT record queries (common exfil channel)
tshark -r capture.pcap -Y "dns.qry.type == 16" -T fields -e frame.time -e ip.src -e dns.qry.name

# Detect DNS tunneling tools (iodine, dnscat2)
tshark -r capture.pcap -Y "dns" -T fields -e dns.qry.name \
  | grep -E "^[a-f0-9]{32,}\." | head -20

# Calculate DNS query entropy (high entropy = encoded data)
tshark -r capture.pcap -Y "dns.qr==0" -T fields -e dns.qry.name \
  | python3 -c "
import sys, math
for line in sys.stdin:
    name = line.strip().split('.')[0]
    if len(name) > 10:
        freq = [name.count(c)/len(name) for c in set(name)]
        entropy = -sum(f * math.log2(f) for f in freq)
        if entropy > 3.5:
            print(f'HIGH ENTROPY ({entropy:.2f}): {line.strip()}')
"
```

### C2 Communication Identification

```bash
# Detect beaconing behavior (regular interval connections)
tshark -r capture.pcap -Y "tcp.flags.syn==1 && tcp.flags.ack==0" -T fields \
  -e frame.time_epoch -e ip.dst -e tcp.dstport \
  | python3 -c "
import sys
from collections import defaultdict
connections = defaultdict(list)
for line in sys.stdin:
    parts = line.strip().split('\t')
    if len(parts) == 3:
        connections[f'{parts[1]}:{parts[2]}'].append(float(parts[0]))
for dest, times in connections.items():
    if len(times) > 5:
        intervals = [times[i+1]-times[i] for i in range(len(times)-1)]
        avg = sum(intervals)/len(intervals)
        if all(abs(i-avg) < avg*0.1 for i in intervals):
            print(f'BEACON DETECTED: {dest} interval={avg:.1f}s count={len(times)}')
"

# Detect JA3/JA3S TLS fingerprints (identify known C2 frameworks)
tshark -r capture.pcap -Y "tls.handshake.type==1" -T fields \
  -e ip.src -e ip.dst -e tls.handshake.ja3

# Detect unusual User-Agent strings
tshark -r capture.pcap -Y "http.user_agent" -T fields -e ip.src -e http.user_agent \
  | sort -u | grep -ivE "mozilla|chrome|safari|edge"

# Detect encrypted traffic to non-standard ports
tshark -r capture.pcap -Y "tls && tcp.dstport != 443 && tcp.dstport != 8443" -T fields \
  -e ip.src -e ip.dst -e tcp.dstport | sort -u
```

---

## 16. Anti-Forensics Detection

### Timestomping Detection

```bash
# Compare $MFT timestamps with $STDINFO timestamps (NTFS)
# $STDINFO is easily modified, $FILENAME is harder to tamper
analyzeMFT.py -f \$MFT -o mft_analysis.csv
# Look for entries where STDINFO created < FILENAME created (impossible normally)

# Detect timestamp anomalies with Volatility
vol3 -f memory.raw windows.mftscan.MFTScan | awk '{if($4 > $6) print "SUSPICIOUS:", $0}'

# Linux: compare file mtime with filesystem journal
debugfs -R "stat <inode>" /dev/sda1
# Compare crtime vs mtime - if mtime < crtime, timestomping detected

# Detect files with timestamps outside system installation range
find / -newermt "2030-01-01" -o ! -newermt "2000-01-01" 2>/dev/null

# Check for $MFT entry number vs creation time inconsistency
# Higher MFT entry numbers should have later creation times
python3 -c "
import csv
with open('mft_analysis.csv') as f:
    reader = csv.DictReader(f)
    prev_entry = 0
    for row in reader:
        if int(row.get('Entry',0)) > prev_entry and row.get('Created','') < '2020':
            print(f'ANOMALY: Entry {row[\"Entry\"]} created {row[\"Created\"]}')
"
```

### Log Wiping Detection

```bash
# Detect gaps in sequential log entries
awk 'NR>1 {
  split(prev,a," "); split($0,b," ");
  # Compare timestamps for gaps > 1 hour
  if (b[3] - a[3] > 3600) print "GAP at line " NR ": " prev " -> " $0
} {prev=$0}' /var/log/syslog

# Check for truncated log files (size vs expected)
ls -la /var/log/auth.log
stat /var/log/auth.log | grep "Birth"
# If file birth time is recent but should contain old entries -> wiped

# Detect Event Log clearing (Windows - Event ID 1102)
evtx_dump.py Security.evtx | grep -B5 -A10 "EventID.*1102"

# Check for missing log rotation files
ls -la /var/log/auth.log*
# If auth.log.1, auth.log.2 etc. are missing but auth.log is small -> wiped

# Detect journal gaps in systemd
journalctl --verify
journalctl --list-boots | awk '{print NR, $0}'
# Missing boot entries indicate journal tampering
```

### Data Hiding Detection

```bash
# Detect Alternate Data Streams (NTFS)
# Using streams.exe (Sysinternals)
streams -s C:\Users\

# Detect steganography in images
stegdetect suspicious_image.jpg
zsteg suspicious_image.png

# Detect hidden partitions
fdisk -l evidence.dd | grep -v "^$"
# Compare total disk size vs sum of partition sizes

# Detect TrueCrypt/VeraCrypt hidden volumes
# Look for high-entropy regions in unallocated space
dd if=evidence.dd bs=1M skip=100 count=10 | ent
# Entropy > 7.99 suggests encrypted/hidden volume

# Detect slack space data hiding
blkls -s evidence.dd | strings | grep -iE "password|secret|hidden"

# Detect process hollowing artifacts in memory
vol3 -f memory.raw windows.malfind.Malfind | grep -E "Protection.*PAGE_EXECUTE_READWRITE"
```

### Rootkit and Anti-Forensics Tool Detection

```bash
# Detect hidden processes (compare multiple enumeration methods)
vol3 -f memory.raw windows.pslist.PsList > pslist.txt
vol3 -f memory.raw windows.psscan.PsScan > psscan.txt
diff <(awk '{print $1}' pslist.txt | sort) <(awk '{print $1}' psscan.txt | sort)

# Detect DKOM (Direct Kernel Object Manipulation)
vol3 -f memory.raw windows.psscan.PsScan | grep -v "$(vol3 -f memory.raw windows.pslist.PsList | awk '{print $1}')"

# Linux rootkit detection
chkrootkit
rkhunter --check --skip-keypress

# Detect LD_PRELOAD hooking
cat /etc/ld.so.preload
env | grep LD_PRELOAD
find / -name "*.so" -newer /etc/passwd 2>/dev/null

# Detect kernel module rootkits
lsmod | grep -v "^Module"
# Compare with known-good module list
cat /proc/modules | awk '{print $1}' | sort > current_modules.txt
diff known_good_modules.txt current_modules.txt
```

---

## 17. Evidence Preservation and Chain of Custody

### Write Blocker Verification

```bash
# Verify write blocker is active (Linux software write block)
blockdev --getro /dev/sdb
# Should return 1 (read-only)

# Set device to read-only before acquisition
blockdev --setro /dev/sdb

# Verify no writes occurred during acquisition
hdparm -r /dev/sdb
# Should show "readonly = 1 (on)"

# Mount evidence read-only with additional protections
mount -o ro,noexec,nosuid,nodev /dev/sdb1 /mnt/evidence/
```

### Hash Verification and Documentation

```bash
# Generate multiple hash algorithms for evidence
sha256sum evidence.dd > evidence.sha256
md5sum evidence.dd > evidence.md5
sha1sum evidence.dd > evidence.sha1

# Verify evidence integrity at each analysis step
sha256sum -c evidence.sha256

# Generate hash of individual files extracted
find /recovery/ -type f -exec sha256sum {} \; > recovered_files_hashes.txt

# Create acquisition log with timestamps
echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') - Acquisition started" >> chain_of_custody.log
echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') - Source: /dev/sdb ($(blockdev --getsize64 /dev/sdb) bytes)" >> chain_of_custody.log
echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') - SHA256: $(sha256sum evidence.dd | awk '{print $1}')" >> chain_of_custody.log
```

### Remote Evidence Collection

```bash
# Collect volatile data before shutdown (order of volatility)
# 1. Memory
./avml /tmp/memory.lime

# 2. Network connections
ss -tulpn > /tmp/netstat.txt
ip addr > /tmp/ifconfig.txt
ip route > /tmp/routes.txt
arp -a > /tmp/arp.txt

# 3. Running processes
ps auxf > /tmp/processes.txt
ls -la /proc/*/exe 2>/dev/null > /tmp/proc_exe.txt

# 4. Open files
lsof > /tmp/open_files.txt

# 5. Logged-in users
w > /tmp/users.txt
last -a > /tmp/last_logins.txt

# 6. System time (for timeline correlation)
date -u > /tmp/system_time.txt
ntpq -p > /tmp/ntp_status.txt 2>/dev/null
```

---

## 18. Mobile and Cloud Forensics

### Android Evidence Acquisition

```bash
# ADB backup (unencrypted)
adb backup -apk -shared -all -f android_backup.ab

# Extract APK files
adb shell pm list packages | while read pkg; do
  adb pull "$(adb shell pm path ${pkg#package:} | sed 's/package://')" ./apks/
done

# Dump logcat (application logs)
adb logcat -d > logcat_dump.txt

# Extract databases (requires root)
adb shell su -c "cp /data/data/com.app.name/databases/*.db /sdcard/"
adb pull /sdcard/*.db ./evidence/

# Extract WhatsApp messages database
adb shell su -c "cp /data/data/com.whatsapp/databases/msgstore.db /sdcard/"
adb pull /sdcard/msgstore.db ./evidence/
```

### Cloud Service Log Acquisition

```bash
# AWS CloudTrail logs
aws cloudtrail lookup-events --start-time "2026-01-01" --end-time "2026-01-31" --output json > cloudtrail.json

# AWS S3 access logs
aws s3 sync s3://target-bucket-logs/ ./s3_logs/

# Azure Activity Log
az monitor activity-log list --start-time "2026-01-01" --end-time "2026-01-31" -o json > azure_activity.json

# GCP Audit Logs
gcloud logging read "logName:cloudaudit.googleapis.com" --project=PROJECT_ID --format=json > gcp_audit.json

# Office 365 Unified Audit Log
# Search-UnifiedAuditLog -StartDate "01/01/2026" -EndDate "01/31/2026" -ResultSize 5000
```
