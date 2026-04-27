# Digital Forensics Test Cases

> This file is a companion to `SKILL.md`, containing structureizeTestuseexamplechecklist。

---

## TestTest Case Statistics

| Category | Count | Severity Coverage |
|------|------|-------------|
| A. evidenceObtain | 2 | CRITICAL, HIGH |
| B. filesystemAnalyze | 2 | CRITICAL, HIGH |
| C. memory forensics | 2 | CRITICAL, HIGH |
| D. network forensics | 2 | HIGH, MEDIUM |
| E. anti-forensicsDetect | 2 | HIGH, MEDIUM |
| **Total** | **10** | **CRITICAL: 3, HIGH: 5, MEDIUM: 2** |

---

## A. Evidence Acquisition

### TC-EA-001: Disk Image Integrity & Hash Verification

| Field | Value |
|------|-----|
| **ID** | TC-EA-001 |
| **Category** | A. evidenceObtain |
| **Severity** | CRITICAL |
| **Title** | Disk Image Integrity & Hash Verification |
| **Description** | VerifyUse dcfldd/dd create diskimageandrawmediacompleteconsistent，SHA256 hashchecksumthrough，ensureevidencechainintegrity。 |
| **Prerequisites** | Testuse USB deviceordiskimagefile（with already knowfilesystemstructure） |
| **Test Steps** | 1. Use `dcfldd if=/dev/sdb of=evidence.dd hash=sha256 hashlog=hash.txt` createimage |
| | 2. Use `sha256sum evidence.dd` calculateimagehash |
| | 3. Compare hashlog in rawhashandimagehash |
| | 4. Use `dd if=evidence.dd bs=1M count=1 | xxd | head -5` Verify首扇zoneContent |
| **Expected Results** | rawmediahashandimagehashcompletematch；image首扇zonecontainseffective introduceguideRecordorpartition tablesignature。 |
| **Related File** | `payloads.md` -> diskimageandObtain |

### TC-EA-002: Chain of Custody Documentation & Timestamp Recording

| Field | Value |
|------|-----|
| **ID** | TC-EA-002 |
| **Category** | A. evidenceObtain |
| **Severity** | HIGH |
| **Title** | Chain of Custody Documentation & Timestamp Recording |
| **Description** | Verifyevidencecollectoverprocessin Chain of Custody documentationcomplete ，includingcollectwhen interval、operationpersonnel、media序columnnumber、hashValueetc.critical要素。 |
| **Prerequisites** | forensicsworkworksite、evidencestoragemedia、Chain of Custody formtemplate |
| **Test Steps** | 1. Recordmedia物reasoncharacteristic（品牌、typenumber、序columnnumber） |
| | 2. connecthardpiecewriteprotecttoolafteraccessforensicsworkworksite |
| | 3. createimagebeforeRecord `date` commandoutput |
| | 4. imagecompleteafterRecordhashValueandcompletewhen interval |
| | 5. 填write Chain of Custody formandsignature |
| **Expected Results** | Chain of Custody formcomplete containsall 必填Field；when timestampcontinuousandno空隙；hashValuebeforeafterconsistent。 |
| **Related File** | `payloads.md` -> diskimageandObtain |

---

## B. File System Analysis

### TC-FS-001: SleuthKit Partition Table & File System Parsing

| Field | Value |
|------|-----|
| **ID** | TC-FS-001 |
| **Category** | B. filesystemAnalyze |
| **Severity** | CRITICAL |
| **Title** | SleuthKit Partition Table & File System Parsing |
| **Description** | Verify SleuthKit ToolschaincancorrectIdentifypartition tablestructure、solveanalysisfilesystemmetadata、listactiveandalready deletefile，andby inode ExtractfileContent。 |
| **Prerequisites** | containsmultiplepartzone（NTFS + ext4） Testdiskimagefile |
| **Test Steps** | 1. Use `mmls evidence.dd` Identifypartzoneoffset |
| | 2. Use `fsstat -o <offset> evidence.dd` Checkfilesystemtypeandstatus |
| | 3. Use `fls -r -o <offset> evidence.dd` recursivelistall file |
| | 4. Use `ils -o <offset> evidence.dd` listalready delete inode |
| | 5. Use `icat -o <offset> evidence.dd <inode>` ExtractObjectivefileContent |
| | 6. CompareExtractfile hashandalready knowrawfilehash |
| **Expected Results** | mmls correctdisplayall partzone；fsstat outputandactualfilesystemtypematch；fls list fileCountand预periodconsistent；already deletefilecan through ils Discover；icat Extract filehashandrawfileconsistent。 |
| **Related File** | `payloads.md` -> filesystemAnalyze |

### TC-FS-002: Deleted File Recovery Verification

| Field | Value |
|------|-----|
| **ID** | TC-FS-002 |
| **Category** | B. filesystemAnalyze |
| **Severity** | HIGH |
| **Title** | Deleted File Recovery Verification |
| **Description** | Verifyfromdiskimageinrecovercomplexalready deletefile integrity，Confirmrecovercomplexfile hashanddeletebeforerawfileconsistent。 |
| **Prerequisites** | containsalready knowalready deletefile Testdiskimage（deletebeforealready Recordfilehash） |
| **Test Steps** | 1. Use `foremost -t jpg,png,pdf,doc -i evidence.dd -o /recovery` Executefilecarving |
| | 2. Check `/recovery` directoryin recovercomplexfileCount |
| | 3. foreachrecovercomplexfilecalculate `sha256sum` andandalready knowhashCompare |
| | 4. Use `exiftool /recovery/*.jpg` Checkmetadataintegrity |
| | 5. Attemptuse `scalpel` repeatrecovercomplex，crossVerifyresult |
| **Expected Results** | foremost successrecovercomplexlargepartialalready deletefile；recovercomplexfile hashandrawfileconsistent；filemetadata（EXIF、when timestamp）maintaincomplete ；scalpel resultand foremost basic consistent。 |
| **Related File** | `payloads.md` -> filecarving |

---

## C. Memory Forensics

### TC-MF-001: Volatility Process Analysis & Hidden Process Detection

| Field | Value |
|------|-----|
| **ID** | TC-MF-001 |
| **Category** | C. memory forensics |
| **Severity** | CRITICAL |
| **Title** | Volatility Process Analysis & Hidden Process Detection |
| **Description** | Verify Volatility cancorrectIdentifyoperationsystem profile、listactiveprocess、Detectthrough DKOM（Direct Kernel Object Manipulation）hide maliciousprocess。 |
| **Prerequisites** | containsalready knowmaliciousprocess（such as Meterpreter anti弹 shell） Windows memory Dump file |
| **Test Steps** | 1. Use `vol.py -f memory.dmp imageinfo` Identifyoperationsystem profile |
| | 2. Use `vol.py -f memory.dmp --profile=<profile> pslist` listprocess |
| | 3. Use `vol.py -f memory.dmp --profile=<profile> pstree` viewprocess树closesystem |
| | 4. Use `vol.py -f memory.dmp --profile=<profile> psxview` Detecthideprocess |
| | 5. Compare pslist and psxview output，Identifydifferenceitem |
| **Expected Results** | imageinfo correctIdentifyoperationsystemversion；pslist displayall oftenruleprocess；psxview Discover pslist innot display hideprocess；pstree revealmaliciousprocess 父processclosesystem。 |
| **Related File** | `payloads.md` -> memory forensics |

### TC-MF-002: Code Injection & API Hook Detection

| Field | Value |
|------|-----|
| **ID** | TC-MF-002 |
| **Category** | C. memory forensics |
| **Severity** | HIGH |
| **Title** | Code Injection & API Hook Detection |
| **Description** | Verify Volatility malfind and apihooks plugincanDetecttoprocessininjection maliciouscodeandby hook system API。 |
| **Prerequisites** | contains DLL injectionorprocess hollowing attacktrace memory Dump file |
| **Test Steps** | 1. Use `vol.py -f memory.dmp --profile=<profile> malfind` Scancodeinjection |
| | 2. Use `vol.py -f memory.dmp --profile=<profile> apihooks` Detect API hook |
| | 3. Use `vol.py -f memory.dmp --profile=<profile> ssdt` Check SSDT integrity |
| | 4. for malfind Discover can suspiciousprocessExecute `procdump -p <PID> -D /output` |
| | 5. forexport can ExecutefileperformmalwareAnalyze（strings/yara） |
| **Expected Results** | malfind reportcontainscan suspiciousmemoryzonedomain（hasExecutepermissionbutnoforshoulddiskfile）；apihooks Discovernot know API hook；ssdt Detecttonon-standard systemtuneusetablemodify；export can suspiciousfilethroughAnalyzeConfirmasmalware。 |
| **Related File** | `payloads.md` -> memory forensics |

---

## D. Network Forensics

### TC-NF-001: PCAP Traffic Analysis & Attack Behavior Reconstruction

| Field | Value |
|------|-----|
| **ID** | TC-NF-001 |
| **Category** | D. network forensics |
| **Severity** | HIGH |
| **Title** | PCAP Traffic Analysis & Attack Behavior Reconstruction |
| **Description** | Verify tshark canfrom PCAP fileinalsooriginalcomplete networkAttack Chain，includinginitial access、C2 communicationanddataexfiltrationbehavior。 |
| **Prerequisites** | containsalready knowattackflowamount PCAP file（such as contains Nmap Scan + vulnerability exploitation + anti弹 shell flowamount） |
| **Test Steps** | 1. Use `tshark -r capture.pcap -q -z conv,ip` Statistics IP for话 |
| | 2. Use `tshark -r capture.pcap -q -z endpoints,ip` Identifycriticalendpoint |
| | 3. Use `tshark -r capture.pcap -Y "http.request"` alsooriginal HTTP request |
| | 4. Use `tshark -r capture.pcap -Y "dns.qr==0" -T fields -e dns.qry.name` Analyze DNS query |
| | 5. Use `tshark -r capture.pcap --export-objects http,/output` Extracttransmissionfile |
| **Expected Results** | IP for话Statisticsrevealattacker IP andObjective IP highfrequencycommunication；HTTP requestalsooriginalattackpayloaddeliverpath；DNS queryinDiscovermaliciousdomain name；Extract transmissionfileand预periodattackToolsconsistent。 |
| **Related File** | `payloads.md` -> network forensics |

### TC-NF-002: DNS Tunnel & Data Exfiltration Detection

| Field | Value |
|------|-----|
| **ID** | TC-NF-002 |
| **Category** | D. network forensics |
| **Severity** | MEDIUM |
| **Title** | DNS Tunnel & Data Exfiltration Detection |
| **Description** | Verifythrough tshark filterandStatisticsAnalyze，caneffectiveIdentify DNS tunnelcommunicationandabnormaldataexfiltrationbehavior。 |
| **Prerequisites** | contains DNS tunnel（such as dnscat2 or iodine）flowamount PCAP file |
| **Test Steps** | 1. Use `tshark -r capture.pcap -Y "dns" -T fields -e dns.qry.name | awk '{print length, $0}' | sort -rn | head -20` Detectsuperlength DNS query |
| | 2. Statisticseachdomain name queryfrequencyrate：`tshark -r capture.pcap -Y "dns.qr==0" -T fields -e dns.qry.name | sort | uniq -c | sort -rn` |
| | 3. Use `tshark -r capture.pcap -Y "dns.qry.name contains <tunnel_domain>"` Extracttunnelflowamount |
| | 4. Analyze TXT Recordresponsein encodingdata |
| **Expected Results** | superlength DNS query（>50 characters）bysuccessIdentify；specificdomain name呈nowabnormalhighfrequencyquerymode；TXT Recordincontains Base64/Base32 encoding dataexfiltrationContent。 |
| **Related File** | `payloads.md` -> network forensics |

---

## E. Anti-Forensics Detection

### TC-AF-001: Timestamp Tampering (Timestomping) Detection

| Field | Value |
|------|-----|
| **ID** | TC-AF-001 |
| **Category** | E. anti-forensicsDetect |
| **Severity** | HIGH |
| **Title** | Timestamp Tampering (Timestomping) Detection |
| **Description** | VerifycanthroughComparefilesystem MAC when timestampandfileContentmetadata notconsistentity，Detectattackertamperwhen timestampwith掩盖attackwhen timeline behavior。 |
| **Prerequisites** | containsalready know Timestomping operationtrace diskimage（attackerUse PowerShell Set-ItemProperty or touch commandmodifywhen timestamp） |
| **Test Steps** | 1. Use `fls -m "/" -o <offset> evidence.dd > mac_times.txt` Extract MAC when interval |
| | 2. ExtractfileContentandAnalyzeinternalwhen timestamp（such as PDF /CreationDate、DOCX core.xml） |
| | 3. Use `mactime -b mac_times.txt` Generatewhen timeline CSV |
| | 4. Comparefilesystem M when intervalandContentmetadatain createwhen interval |
| | 5. Checkiswhetherexists M when interval早atfile所indirectorycreatewhen interval abnormal |
| **Expected Results** | Discoverfilesystemmodifywhen interval（M）andfileinternalmetadatawhen intervalnotconsistent；partialfile M when intervalbysetasoverremovesomewhen intervalpoint；when timelineinoutputnowwhen intervallogic矛盾（such as filemodifywhen interval早atcreatewhen interval）。 |
| **Related File** | `payloads.md` -> anti-forensicsDetect, when timelineAnalyze |

### TC-AF-002: Log Clearing & Evidence Destruction Detection

| Field | Value |
|------|-----|
| **ID** | TC-AF-002 |
| **Category** | E. anti-forensicsDetect |
| **Severity** | MEDIUM |
| **Title** | Log Clearing & Evidence Destruction Detection |
| **Description** | VerifycanDetectattackerclearsystem log、security eventlogorUseanti-forensicsTools擦除trace behavior。 |
| **Prerequisites** | Simulateattackerclearbehavior Testenvironment（already Execute `rm /var/log/auth.log`、`auditctl -D`、or Windows event ID 1102） |
| **Test Steps** | 1. Checklogfileiswhetherexists空隙：`awk 'NR>1 {print prev, $0, $0-prev} {prev=$0}' /var/log/syslog` |
| | 2. Check Windows event ID 1102（audit logclear）：`vol.py -f memory.dmp --profile=<profile> evtlogs -D /output` afterSearch 1102 event |
| | 3. Check /var/log directoryinfile mostaftermodifywhen intervaliswhethersetininawhen intervalsegment |
| | 4. Use `journalctl --list-boots` CheckStartRecord continuousity |
| | 5. Searchalready knowanti-forensicsTools residual：`strings evidence.dd | grep -i "ccleaner\|bleachbit\|eraser\|sdelete"` |
| **Expected Results** | Discoverlogfile when intervalinterval隔abnormal（largesegmentmissing）；Windows event loginoutputnow 1102 event；/var/log filemodifywhen intervalsetininattackwhen time window；Discoveranti-forensicsTools filenameorstringresidual。 |
| **Related File** | `payloads.md` -> anti-forensicsDetect, logAnalyze, Windows forensics, Linux forensics |
