# Reverse Engineering Command Line Tools Detailed Reference

## 1. Radare2 - open-sourcereverse engineeringframework

### Basic Usage
```bash
# basic analysis
r2 binary_file

# automated analysisall introduceusecode
r2 -A binary_file

# Debugmode
r2 -d binary_file

# specifyArchitectureandbitnumber
r2 -a x86 -b 32 binary_file

# executecommandafter退output
r2 -c 'aaa; pdf @ main' -q binary_file

# fromStandardinputread
r2 malloc://512
```

### Core Commands (in r2 interactive mode)
```bash
# Analysis Commands
aaa        # Auto analysisAll functions
afl        # List all functions
pdf @ main # DisassemblemainFunction
s main     # Jump tomainFunction
i          # Show file information
ii         # Show import table
ie         # ShowExport表

# Search Commands
/ pattern  # Search byte patterns
/ string   # Search strings
izz        # List all strings

# Debug Commands
doo        # RestartStartProgram
dc         # ContinueExecute
db address # SetBreakpoint
dr         # Show registers
```

### Practical Examples
```bash
# quick analysisbinaryfile
r2 -A -c 'afl; i' -q malware.bin

# Extractstringandanalysis
r2 -c 'izz; afl' -q suspicious.exe

# Debuganalysis
r2 -d -c 'db main; dc; dr' vulnerable_program
```

## 2. Binwalk - 固pieceanalysisTool

### Basic Usage
```bash
# basic signatureScan
binwalk firmware.bin

# onlydisplayfilesignature
binwalk -B firmware.bin

# ExtractEmbedded file
binwalk -e firmware.bin

# deepdegreeanalysis（includingcompressionflow）
binwalk -Me firmware.bin

# Hex dump
binwalk -W file1 file2
```

### Advanced Options
```bash
# ArchitectureIdentify
binwalk -Y firmware.bin

# fromdefinitionMagicfile
binwalk -m custom.magic firmware.bin

# Excludespecificresult
binwalk -x "ELF" firmware.bin

# logoutput
binwalk -f analysis.log firmware.bin

# CSVformatoutput
binwalk -c firmware.bin
```

### Firmware Analysis Workflow
```bash
# Step 1: InitialScan
binwalk firmware.bin

# Step 2: Extractfilesystem
binwalk -e firmware.bin

# Step 3: deepdegreeanalysisExtract content
binwalk -Me _firmware.bin.extracted/*

# Step 4: ArchitectureIdentify
binwalk -Y firmware.bin
```

## 3. Ghidra - NSAopen-sourcereverse engineeringplatform（commandrowmode）

### Headless Mode Usage
```bash
# createnewproject
ghidraRun -import binary_file -project /path/to/project

# analysisandgeneratereport
ghidraRun -process binary_file -postScript GenerateReport.java

# batchamountanalysis
ghidraRun -importDir /path/to/binaries -project /path/to/project
```

### Actual Command Line Invocation (need to find correct script path)
```bash
# typicallybitat Ghidra installdirectory support/ directorybelow
# analyzeHeadless /path/to/project project_name -import binary_file -postScript script.py
```

### Common Analysis Scripts
- **FunctionGraphScript**: generatefunctiontuneusediagram
- **GenerateReport**: generateanalysisreport
- **FindCrypt**: Identifyencryptionoftenamount
- **AutoAnalysis**: automated analysisscript

## 4. Xxd - Hex dumpTool

### Basic Usage
```bash
# StandardHex dump
xxd binary_file

# CLanguage styleoutput
xxd -i binary_file

# limitationoutputlengthdegree
xxd -l 100 binary_file

# fromspecifyoffsetstart
xxd -s 0x100 binary_file

# Reverseoperation（hexadecimal转binary）
xxd -r hexdump.txt output.bin
```

### Advanced Options
```bash
# Binary bit dump
xxd -b binary_file

# smallend序output
xxd -e binary_file

# fromdefinitioncolumnnumber
xxd -c 8 binary_file

# largewritehexadecimal
xxd -u binary_file
```

### Practical Examples
```bash
# Extractfilehead
xxd -l 16 executable | head -1

# than较两file difference
xxd file1 > file1.hex
xxd file2 > file2.hex
diff file1.hex file2.hex

# fromhexadecimalcreatebinaryfile
echo "48656c6c6f20576f726c64" | xxd -r -p > hello.txt
```

## 5. Objdump - for象fileDumpTool

### Basic Usage
```bash
# displayfileheadinformation
objdump -f binary_file

# disassemblycan executesegment
objdump -d binary_file

# disassemblyall segment
objdump -D binary_file

# displaysectionheadinformation
objdump -h binary_file

# displaycharacternumbertable
objdump -t binary_file
```

### Advanced Options
```bash
# 混combinesource codeanddisassembly
objdump -S binary_file

# displaycomplete content
objdump -s binary_file

# specifyArchitecture
objdump -m i386 binary_file

# displaydynamiccharacternumber
objdump -T binary_file
```

### Practical Examples
```bash
# quick viewProgramentry pointpoint
objdump -f program | grep start

# analysiscan suspiciousfunction
objdump -d malware | grep -A 20 "suspicious_function"

# checkdynamiclink
objdump -T shared_library.so
```

## 6. Readelf - ELFfileanalysisTool

### Basic Usage
```bash
# displayall information
readelf -a binary_file

# displayfilehead
readelf -h binary_file

# displayProgramhead
readelf -l binary_file

# displaysectionhead
readelf -S binary_file

# displaycharacternumbertable
readelf -s binary_file
```

### Advanced Options
```bash
# displaydynamicsegment
readelf -d binary_file

# display重locateinformation
readelf -r binary_file

# displaysectiongroupinformation
readelf -g binary_file

# displaysectiondetailed information
readelf -t binary_file
```

### Practical Examples
```bash
# checkELFfiletype
readelf -h program | grep "Type:"

# analysisdynamicdependency
readelf -d program | grep NEEDED

# findcharacternumberaddress
readelf -s library.so | grep "function_name"
```

## 7. itsotherimportantTool

### Strings - Extractcan Printablestring
```bash
# basic stringExtract
strings binary_file

# MinimumlengthdegreeControl
strings -n 8 binary_file

# displayoffsetaddress
strings -t d binary_file

# handlingspecificencoding
strings -e l binary_file  # little-endian
```

### Hexdump - Hex dump
```bash
# Standardhexadecimaloutput
hexdump -C binary_file

# onlydisplayoffsetanddata
hexdump -v binary_file

# fromdefinitionformat
hexdump -e '16/1 "%02x " "\n"' binary_file
```

## Tool Combination Usage Strategy

### 1. Binary File Initial Analysis
```bash
# Step 1: fileinformation
file suspicious_binary
readelf -h suspicious_binary  # ELFFile
objdump -f suspicious_binary  # OtherFormat

# Step 2: stringanalysis
strings -n 8 suspicious_binary | sort | uniq

# Step 3: structureanalysis
r2 -A -c 'i; afl' -q suspicious_binary

# Step 4: deepdegreedisassembly
objdump -d suspicious_binary > disassembly.asm
```

### 2. Firmware Analysis Workflow
```bash
# Step 1: signatureIdentify
binwalk firmware.bin

# Step 2: fileExtract
binwalk -e firmware.bin

# Step 3: ArchitectureIdentify
binwalk -Y firmware.bin

# Step 4: binary analysis
# forExtract eachbinaryfilerepeatStep 1-3
```

### 3. Malware Analysis
```bash
# Step 1: staticanalysis
xxd -l 64 malware_sample        # File header
strings -n 6 malware_sample     # Suspicious strings
readelf -d malware_sample       # Dynamic dependencies

# Step 2: dynamicanalysispreparation
r2 -d malware_sample            # DebugMode
objdump -T malware_sample       # Import functions

# Step 3: behavioranalysis
# useDebugtoolStep-by-stepexecute，monitoringAPItuneuse
```

## Best Practices and Considerations

### 1. Security Considerations
- Analyze Suspicious Files in Isolated Environment
- Do Not Directly Execute Unknown Binaries
- Use Read-only Mount for Firmware Analysis
- Back Up Original Files

### 2. Analysis Tips
- Combine Results from Multiple Tools for Cross-validation
- Start with Simple Tools, Gradually Deepen Complex Analysis
- Document Analysis Process and Findings
- Use Scripts to Automate Repetitive Tasks

### 3. Performance Optimization
- Use Offset and Length Limits for Large Files
- Process Multiple Files in Parallel
- Use Appropriate Buffer Size
- Monitor Memory Usage

### 4. Result Validation
- Manually Verify Key Findings
- Compare with Known Samples
- Use Multiple Tools to Confirm Results
- Document Analysis Hypotheses and Conclusions