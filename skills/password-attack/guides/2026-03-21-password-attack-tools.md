# 2026-03-21 Password Attack CLI Tools Learning

## Mastered Tools

### 1. Hashcat - worldmostfast PasswordrecovercomplexTool
- **Function**: Supports300+kindhashType，multiplekindAttackmode
- **CoreAttackmode**: WordlistAttack(0)、groupcombineAttack(1)、brute force(3)、混combineAttack(6,7)
- **Practical Key Points**:
 - SupportsCPUandGPUaddspeed
 - powerful ruleengineandmaskAttack
 - sessionrecovercomplexandStatussave
 - built-inrich hashTypeSupports

### 2. John the Ripper - maindynamicPasswordcrackTool
- **Function**: quick Passwordcrack，specialother擅lengthhandlingeachkindencryptionPasswordhash
- **CoreAttackmode**: singletimecrack(--single)、WordlistAttack(--wordlist)、increaseamountmode(--incremental)
- **Practical Key Points**:
 - automated hashTypeDetection
 - powerful singletimecrackmode（exploitUsernameinformation）
 - SupportsmultiplekindFileformat（ZIP、PDF、Officeetc.）
 - sessionmanagementandrecovercomplex

### 3. Hydra - quick Networklogincracktool
- **Function**: Supports50+kindprotocol Networkloginbrute force
- **Coreprotocol**: SSH、FTP、HTTP、Database、Email、remoteAccessetc.
- **Practical Key Points**:
 - extremelyfast Networkbrute forcespeeddegree
 - flexible Webformbrute forcesyntax
 - proxyandSSLSupports
 - concurrentcontrolandsessionrecovercomplex

### 4. Medusa - parallelloginbrute forceTool
- **Function**: Modular Design parallelloginbrute forceTool
- **Coremodule**: ssh、ftp、http、mssql、mysql、pop3、vncetc.
- **Practical Key Points**:
 - moduleizearchitecture，易atextension
 - parallelhandlingCapabilities
 - flexible moduleparameterConfiguration
 - detailed logOutput

### 5. Crunch - fromdefinitionWordlistGenerationtool
- **Function**: based onspecifycharacterssetandlengthdegreeGenerationPasswordgroupcombine
- **Core Functions**: characterssetdefinition、modeGeneration、memorymanagement
- **Practical Key Points**:
 - precisecontrolWordlistsize
 - SupportscomplexmodeGeneration（such as pass@%%%）
 - memoryanddiskUseoptimize
 - anditsotherToolno缝integration

### 6. Cewl - customizeWordlistGenerationtool
- **Function**: fromTargetWebsitecrawlsingle词GenerationcustomizePasswordWordlist
- **Core Functions**: Websitecrawl、deepdegreecontrol、metaData Extraction
- **Practical Key Points**:
 - GenerationTargetrelated Wordlist
 - Supportsauthenticationandproxy
 - ExtractmetaDataandHTML注释
 - can anditsotherWordlistToolcombineUse

### 7. itsotherAssistantTool
- **JohntransformTool**: 1password2john、keepass2john、office2johnetc.
- **HashcatToolset**: hashcat-utils、rulegen、statsgenetc.
- **WordlisthandlingTool**: rsmangler、maskprocessor、princeprocessoretc.

## Tool Combination Strategies

### offlinehashcrackWorkflow
1. **hashExtract**: secretsdump.py → hashes.txt
2. **hashIdentify**: hashcat --identify
3. **WordlistAttack**: hashcat -a 0 -m 1000 hashes.txt wordlist.txt
4. **ruleAttack**: hashcat -a 0 -m 1000 hashes.txt wordlist.txt -r rules/dive.rule
5. **brute force**: hashcat -a 3 -m 1000 hashes.txt ?a?a?a?a?a?a

### onlineservicebrute forceWorkflow
1. **Target Reconnaissance**: nmap -sV target.com
2. **WordlistPreparation**: cewl https://target.com -d 2 -m 4 -w custom_dict.txt
3. **SSHbrute force**: hydra -L users.txt -P custom_dict.txt ssh://target.com
4. **Webformbrute force**: hydra -l admin -P custom_dict.txt http-post-form "/login:user=^USER^&pass=^PASS^:F=error"
5. **Databasebrute force**: medusa -h target.com -u sa -P custom_dict.txt -M mssql

### customizeWordlistGenerationWorkflow
1. **Websitecrawl**: cewl https://target.com -d 3 -m 4 -w website_words.txt
2. **Wordlisttransformation**: rsmangler --file website_words.txt --output mangled_dict.txt
3. **modeGeneration**: crunch 6 8 -t company@%%% -o pattern_dict.txt
4. **mergeWordlist**: cat website_words.txt mangled_dict.txt pattern_dict.txt rockyou.txt > final_dict.txt
5. **deduplicatesorting**: sort -u final_dict.txt > unique_dict.txt

## Practical Notes

### Legal and Ethical
- **绝forauthorization**: PasswordAttackmustobtain explicit writtenauthorization
- **scopelimitation**: strictly complyTestscope，notsuperoutputauthorizationboundary
- **minimumimpact**: controlAttackfrequencyrateavoidDoS
- **Data Protection**: properlyhandlingcrackoutput Sensitive Information

### Technical Best Practices
- **Wordlistselect**: based onTargetcustomWordlist，extracthighsuccessrate
- **Attack顺序**: 先WordlistAttack，再ruleAttack，mostafterbrute force
- **Performance Optimization**: combinereasonpartmatchSystemresource，monitoringhardpiece温degree
- **ResultVerification**: VerificationcrackResult realityandeffectiveity

## File Locations
- Detailed Command Reference: `/home/parallels/.openclaw/workspace/security-tools-67/password-attack-cli-reference.md`
- This learning record: Current file
- Tool classification statistics: `/home/parallels/.openclaw/workspace/kali-517-analysis/`

## Follow-up Learning Plan
- deep LearningnolineSecurityTool（kismet, aircrack-ng, reaveretc.）
- LearningcontainerSecurityTool（trivy, grype, docker-benchetc.）
- Organizecomplete Kali 517tool learning summary report