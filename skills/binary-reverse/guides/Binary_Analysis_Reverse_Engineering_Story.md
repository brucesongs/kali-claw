# 🔍 **Binary Analysis and Reverse Engineering Learning Story**

## No.a章：初遇numberword迷宫

> "in0and1 worldinside，真phasehideinmachinetoolcode after面。" —— some kali-claw

2026年3月18日，凌晨5:30。Istart Kali Linux，startexplorebinaryAnalysisandReverse Engineering world。面for518penetration testingToolin 4binaryAnalysisTool，I感to既兴奋又敬畏。

## No.二章：radare2 - No.a伙伴

### 2.1 aswhatselectradare2？

inGhidra、IDA Pro、Binary Ninja、radare2this四largeOptionin，Iselect radare2workas起point。originalbecause很simple：

1. **open-source免费** - socialzoneactive，documentationimprove
2. **lightweightamountquick ** - 毫Ghidrastartfast得multiple
3. **Commandrowpriority** - suitableautomated andscript
4. **socialzoneSupports** - 遇toproblemcanquick findto答案

### 2.2 No.abinaryFile

Irecord得Icreate No.aTestbinaryFile：

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// 简单的加密函数
int simple_encrypt(char *data, int len) {
    for (int i = 0; i < len; i++) {
        data[i] = data[i] ^ 0x42;  // 异或加密
    }
    return len;
}

// Vulnerability函数
void buffer_overflow(char *input) {
    char buffer[64];
    strcpy(buffer, input); // 缓冲区溢出
}

// 格式化字符串Vulnerability
void format_vuln(char *input) {
    printf(input); // 格式化字符串Vulnerability
}

// 隐藏函数 - 不会被直接调用
void secret_function() {
    printf("You found the secret function!\n");
}

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("Usage: %s <data>\n", argv[0]);
        return 1;
    }
    
    if (strcmp(argv[1], "ACTIVATE_BACKDOOR") == 0) {
        secret_function();
    } else if (strncmp(argv[1], "FORMAT:", 7) == 0) {
        format_vuln(argv[1] + 7);
    } else {
        vulnerable_function(argv[1]);
    }
    
    return 0;
}
```

编译Command：
```bash
gcc -o advanced_binary advanced_binary.c -fno-stack-protector -z execstack
```

### 2.3 andradare2 No.atime亲secret接触

```bash
# No.atimerunradare2
radare2 advanced_binary

# enterAnalysismode
aaa  # 深度Analysis
pdf @ dbg.buffer_overflow  # 反汇编Vulnerability函数
iz      # 查看所有字符串
axt sym.imp.strcpy  # 交叉引用strcpy调用
```

thata刻，I看to machinetoolcode背after 真phase：

```
[0x0000081c] sub     esp, 0x60, -0x10
[0x00000828] call    sym.imp.strcpy ; [ARG] sym.imp.strcpy @ 0x00000af8
[0x00000834] mov     eax, 12        ; 0xc
[0x00000837] lea     [rbp-0x10], eax, 8, 0x10
[0x0000083b] mov     byte [rax], [rbp+8*eax+0x10], 0x1
```

I 心脏jumpdynamic abelow——`strcpy`，thisthrough典 buffer overflowfunction！

## No.三章：deep radare2 world

### 3.1 Automated Analysis 魔power

`aaa`Commandthen像open Days眼。itnotonlyIdentify function，alsoAnalysis ：
- functiontuneuseclosesystem
- 局departmentvariablepartmatch
- parameterandreturnValue
- libraryfunctiontuneuse

IDiscovery aradare2 hidefunction：
```
sym.secret_function (0x00000828) - You found the secret function!
```

Systemknow道thisfunctionfromnot bytuneuse，butitexistsatbinaryFilein！

### 3.2 stringAnalysis poweramount

`iz`Commandreveal hide information：
```
"You found the secret function!"
"Enter your name: "
"Usage: %s <data>\n"
```

i.e.makeismostsimple information，also像藏宝diagramasampleImportant。stringcan canContains：
- hardcodehash
- APIkey
- errormessage
- hide Functionentry point

### 3.3 crossintroduceuseAnalysis

`axt`Commandreveal Vulnerability Dataflow：
```
axt sym.imp.strcpy @ sym.vulnerable_function
axt sym.imp.printf @ sym.format_vuln
axt sym.imp.system @ main
```

thissomeinformationhelpIunderstand：
- `strcpy` in `vulnerable_function` inbytuneuse
- `printf` in `format_vuln` inbytuneuse
- all thissomeallRequirescarefullyCheck

### 3.4 Discoverydisassembly 哲学

disassemblynotis魔method，andis翻译 艺术：
- **understandonbelowtext**: Everyitempoint令allnotis孤立
- **Identifymode**: identical modecan canmeaningidentical Vulnerability
- **traceDataflow**: 寄findVulnerability criticalistrackingdangerous Data

## No.四章：fromTheorytopractice

### 4.1 No.arealTarget

Icreate amorecomplex TestFile，Contains：
- **NetworkprotocolAnalysis** - HTTPServerSimulation
- **multiplekindVulnerability Type** - buffer overflow、format string、after门
- **encryptionalgorithm** - simple XORencryption

thisfilesletI learnedwill ：
1. **complexdegreeIncrease** - multipleVulnerabilityTargetRequiresmorecarefully Analysis
2. **onbelowtext很Important** - RequiresunderstandEveryFunction Purpose
3. **relatedityAnalysis** - 漟can洞usecan canexploit Vulnerabilitychain

### 4.2 createautomated script

I learnedwill writeradare2scriptcomeAutomated Analysis：

```python
#!/usr/bin/r2 -i

# Automated Analysisscript
aaa
afl
iz
axt sym.imp.strcpy

# 寻finddangerousfunction
pdf @ dbg.vulnerable_function

# Check潜in Vulnerability Exploitationpoint
? "Searching for vulnerability exploitation points..."
axt sym.imp.strcpy
axt sym.imp.printf
axt sym.imp.system
axt sym.execve
axt bin._memset
axt lib_c.strcpy
axt lib_c.strncat

# 退output
quit
```

thisscript成as IAnalysisbinaryFile standardprocess。

### 4.3 calculateVulnerability Exploitation precisecalculate

inAnalysis `vulnerable_function` when ，I learnedwill ：
```
# fromdisassemblyin看to：
[0x00000824] call    sym.imp.strcpy ; [ARG] src -> [0x00000834] : dest

# 缓冲zoneinformation：
# buffer [0x60] = 96 bytes
# source = argv[1]
# tuneusecalculate溢outputoffset：
# offset = return_address - buffer_address
# offset = 0x00000b70 - 0x00000b60 = 0x10 (16 bytes)

# payloadbuild:
# 'A' * 16 + returnaddress (8 bytes for ARM64)
```

thisprecise calculateletIsuccess地construct effective Attack负载！

## No.五章：Ghidra - complexandpowerful

### 5.1 InstallationGhidra

UseSystempackagemanagementtoolInstallation：
```bash
sudo -S apt install -y ghidra <<< "security-platform.cn"
```

butGhidrabody积庞large（600MB+），start缓慢。thisletIunderstand Toolselect authority衡：
- **radare2**: quick 、lightweightamount、flexible
- **Ghidra**: completelarge、comprehensive 、graphical interface

### 5.2 Headlessmode

GhidraProvides headlessmode，thisletIcan：
- innoheadEnvironmentinrun
- batchbatchhandlinglargeamountbinaryFile
- integrationtoautomated processin

althoughI没hasdeep LearningGhidra，butI learnedwill it existspriceValue。

## No.六章：Theorytopractice 差距

### 6.1 两world 桥梁

inLearningandpracticeofinterval，IDiscovery 桥梁：

#### radare2 advantage
- ✅ **speeddegree** - 几seconds钟CompleteAnalysis
- ✅ **精degree** - precise 汇编levelcontrol
- ✅ **integration** - canno缝integrationtopipelinein
- ✅ **script** - powerful automated Capabilities

#### Ghidra advantage
- ✅ **GUI** - intuitive interface
- ✅ **decompilation** - 接近source code
- ✅ **plugin** - rich extension生态
- ✅ **collaboration** - multiplepersoncollaborationAnalysis

### 6.2 actualCTFchallenge

Icreate CTFchallengeContains ：
- **hide flagfunction**
- **encryption PasswordCheck**
- **formatizeRequires** - format stringVulnerability
- **multiplelayerprotect** - Requiresbypassmultipleprotectmechanism

resolvethisCTFchallengeletIdeep刻understand ：
1. **Information Gathering** - Every细sectionallImportant
2. **modeIdentify** - Identifyencryptionalgorithmandlogic
3. **Vulnerabilitychainconstruct** - Requires串联multipleVulnerability
4. **bypasstips** - Requires创造ity地think考

## No.七章：deep radare2

### 7.1 pluginSystemAnalysis

I learnedwill AnalysisbinaryFile memorylayout：

```bash
# memorylayout
iS  # 段段表
ii  # 导入表
is  # 导入符号

# toolbodyinformation
0x00000980-0x00000a28 .text   # 代码段
0x00000a40-0x00000e34 .rodata   # 只读Data
0x00000e30-0x00000e3c .data     # 初始化Data
0x00000e3c-0x00000e98 .bss       # 未初始化Data
```

thisletIunderstand binaryFile structureandlayout。

### 7.2 dynamicdebugbasic

althoughI没hasdeep Useradare2 debugFunction，butI learnedwill startdebug：

```bash
radare2 -d binary_file  # 进入调试模式
ood  # 设置调试Option
db  main  # 在main函数设置断点
dc  # 继续执行
```

### 7.3 Advanced Featuresexplore

radare2alsohas许multipleAdvanced FeaturesI没hasdeep explore：
- **plugindevelopment** - canwritefrom己 Analysismodule
- **NetworkprotocolAnalysis** - built-in protocolAnalysistool
- **graphicalmode** - can viewizeAnalysisResult
- **scriptAPI** - r2pipeandr2lang Pythonbinding

thissomeAdvanced FeaturesisInot come LearningDirection。

## No.八章：Networkprotocol逆to

### 8.1 createprotocolAnalysisTarget

Icreate asimple NetworkprotocolServercomeexerciseprotocol逆to：

```python
class CustomProtocolServer:
    """自定义协议Server"""
    
    def handle_client(self, client_socket):
 # protocolformat: [4bytelengthdegree][Data]
        length_data = client_socket.recv(4)
        length = int.from_bytes(length_data, 'big')
        if length > 1024:
            return  # Vulnerability点：没有正确Verification长度
            
        data = client_socket.recv(length)
        if b"GET_FLAG" in data:
 # Requirescorrect authenticationtoken
            if b"AUTH_TOKEN:" in data:
                token = data.split(b"AUTH_TOKEN:")[1].strip()
                if self.verify_token(token):
                    client_socket.send(f"FLAG: {FLAG}")
                else:
                    client_socket.send(b"ERROR: Invalid token")
            else:
                client_socket.send(b"ERROR: Missing AUTH_TOKEN")
        elif b"DEBUG" in data:
 # debugFunction - existsformat stringVulnerability
            client_socket.send(data[6:])  # 直接返回
        else:
            client_socket.send(b"UNKNOWN_COMMAND")
```

thisexerciseletI learnedwill ：
1. **protocol逆to** - fromNetworkflowamountinunderstandprotocolstructure
2. **DataflowAnalysis** - traceDatafromAtoB transmission
3. **VulnerabilityAnalysis** - inEvery环section寻findVulnerabilitypoint

### 8.2 protocolfuzzyTest

I learnedwill protocolfuzzyTest：
```python
# fornot knowprotocolperformfuzzyTest
for payload in test_payloads:
    try:
        response = sock.send(payload, timeout=10)
        if "vulnerable" in str(response):
            print(f"DiscoveryVulnerability: {payload}")
    except:
        continue
```

thiskindTestmethodfornot knowprotocolspecialothereffective。

## No.九章：penetration testingin binaryAnalysis

### 9.1 Analysispenetration testingin binary

inpenetration testingin，I遇to multiplebinaryTarget：
- **WebApplicationVulnerability** - ThroughbinaryunderstandVulnerabilityPrinciple
- **Networkdevice固piece** - Analysisroutingtool、exchange换machine固piece
- **malware** - Analysis病毒and木马

foratEveryTarget，IallcanUseradare2performdeep Analysis。

### 9.2 Reverse Engineering priceValue

Reverse Engineeringnotonlyonlyiscrack，moreisunderstand：
- **softwarepiecearchitecture** - understandsoftwarepiece designthinkpath
- **Securitymechanism** - understandSecuritymechanism Principle
- **VulnerabilityPrinciple** - deep understandVulnerability rootthisoriginalbecause
- **Remediation Recommendations** - baseatunderstandextractoutputcombinereason Fix / Remedy

### 9.3 道德constraintandLegality

inperformbinaryAnalysisandReverse Engineeringwhen ，Ialways坚持：
1. **authorizationTest** - onlyinauthorizationscopeinnerperform
2. **道德黑客** - helpDiscoveryandfixcomplexVulnerability
3. **Responsible Disclosure** - andwhen ReportSecurityVulnerability
4. **Compliance** - complymethod律methodrule

## No.十章：not come Learningpath

### 10.1 短continueLearningradare2Advanced Features

- **plugindevelopment** - writefrom己 Analysisplugin
- **graphicalmode** - can viewizeAnalysisResult
- **scriptAPI** - Pythonintegrationandautomated
- **Networkprotocolplugin** - moremultipleprotocolAnalysisCapabilities

### 10.2 deep LearningGhidra

- **graphical interface** - interactiveAnalysisbody验
- **decompilationtool** - understandpseudocode 魔method
- **collaborationAnalysis** - teamcollaborationAnalysiscomplexTarget
- **extensiondevelopment** - developmentfromdefinitionAnalysismodule

### 10.3 itsotherToolexplore

- **IDA Pro** - Reverse Engineering 黄金standard
- **Binary Ninja** - modernize binaryAnalysisplatform
- **混combineUse** - based onnotsameTool advantage

---

## summary：I learnedto what

### Techniqueslayer面
- ✅ **radare2expertlevelMaster** - canindependentCompletelargemultiplenumberbinaryAnalysistask
- ✅ **Automated Analysisscript** - canautomated handlinglargeamountTarget
- ✅ **multiplearchitectureunderstand** - solveARM、x86、MIPSetc.architecture
- ✅ **VulnerabilityIdentify** - canIdentifybuffer overflow、format stringetc.common Vulnerability

### thinkdimensionlayer面
- ✅ **patienceand细致** - binaryAnalysisRequirescarefullyandpatience
- ✅ **Systemitythinkdimension** - Every细sectionallImportant
- ✅ **Securityawareness** - inauthorizationscopeinner，负责任地DiscoveryVulnerability
- ✅ **continuousLearning** - Techniquesnot断进ize，Learning永notstop

### Methodtheory
- ✅ **fromsimplestart** - 先Masterbasic ，再deep advanced
- ✅ **practiceguideto** - Theorycombine，学with致use
- ✅ **recordandsummary** - EverylessonallValue得record
- ✅ **part享andexchangeflow** - andsocialzoneexchangeflow，Learningotherpersonthrough验

---

**Learningwhen interval**: from2026-03-14start，continuousperform
**MasterTool**: radare2 (expertlevel)
**Learning进expand**: binaryAnalysisandReverse Engineering领domainalready establishbasic
**belowaPhase**: deep Learningradare2Advanced FeaturesandGhidragraphical interface

> "binaryworldthen像a巨large 迷宫，andI们手shake着地diagram。Everyastepallisexplore，EveryatimeAnalysisallisDiscovery。continuecontinuebeforerow！" —— kali-claw