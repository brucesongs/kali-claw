# 2026-03-21 Information Gathering CLI Tools Learning

## Mastered Tools

### 1. theHarvester (v4.10.1)
- **Function**: OSINTInformation Gathering，Supports50+data sources
- **Core Commands**: `-d domain -b source -r -c -n -f file`
- **Practical Key Points**:
 - bydynamiccollectasmain，RequiresAPIkeyobtaincomplete Function
 - SupportsDNSsolveanalysis、brute force、Shodanintegration
 - Outputformatrich（XML/JSON）

### 2. Sublist3r
- **Function**: Subdomain EnumerationTool
- **Core Commands**: `-d domain -b -e engines -p ports -o output`
- **Practical Key Points**:
 - combinemultipleSearch EnginesextracthighCoverage
 - built-inbrute forcemodule（subbrute）
 - can directScanningDiscoverySubdomains Ports

### 3. DNSRecon
- **Function**: comprehensive DNSEnumerateandreconnaissanceTool
- **Core Commands**: `-d domain -t type -D wordlist -j json_output`
- **Practical Key Points**:
 - Supports9kindEnumerateType（std, axfr, brt, rvl, crtetc.）
 - zone transferTest、reverseDNS、brute force
 - multipleformatOutput（JSON/XML/CSV/SQLite）

### 4. Masscan
- **Function**: superhighspeedPort Scanningtool（10M pps）
- **Core Commands**: `targets -p ports --rate speed --banners -oJ json`
- **Practical Key Points**:
 - Requiresrootpermissionrun
 - extremelyhigh Scanningspeeddegree，suitablelargescopeScanning
 - Supportsservice横幅obtain

### 5. Amass
- **Function**: Attacksurface mappingandassetDiscovery
- **Core Commands**: `enum -d domain -passive/-active -config file -o output`
- **Practical Key Points**:
 - bydynamicandmaindynamicmodecombine
 - RequiresConfigurationAPIkeyobtainbesteffectresult
 - enterpriselevelAttack面managementTool

## Tool Combination Strategies

### Information GatheringWorkflow
1. **initialreconnaissance**: theHarvester + Sublist3r（bydynamicDiscovery）
2. **deepdegreeDNS**: DNSRecon（maindynamicVerificationandextension）
3. **IPDiscovery**: fromdomain nameResultExtractIP
4. **Port Scanning**: Masscan（quick PortsDiscovery）
5. **Attacksurface mapping**: Amass（comprehensiveAnalysis）

### Dataentirecombine
- all ToolSupportsJSONOutput，thenatautomated handling
- establishunified DatastorageandAnalysispipeline
- crossVerificationnotsameTool Resultextracthighaccurateity

## Practical Notes

### Legal Compliance
- alwaysobtainauthorizationafter再performScanning
- complyTargetSystem Useitemclause
- controlScanningspeedrateavoidcauseimpact

### Technical Optimization
- Uselatest SecListsWordlistFile
- ConfigurationAPIkeyextracthighdata sourcescovering
- based onNetworkEnvironmenttuneentireScanningparameter
- VerificationanddeduplicateDiscovery Result

## File Locations
- Detailed Command Reference: `/home/parallels/.openclaw/workspace/security-tools-67/information-gathering-cli-reference.md`
- This learning record: Current file
- Tool classification statistics: `/home/parallels/.openclaw/workspace/kali-517-analysis/`

## Follow-up Learning Plan
- deep LearningWebApplicationSecurityTool（Burp Suite CLI, ZAP CLIetc.）
- MasterPasswordAttackTool（hashcat, johnetc.）
- LearningafterpenetrationTool（crackmapexec, mimikatzetc.）