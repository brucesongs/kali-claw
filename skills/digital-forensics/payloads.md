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
