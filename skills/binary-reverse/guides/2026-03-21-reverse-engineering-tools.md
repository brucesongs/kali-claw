# 2026-03-21 Reverse Engineering Command Line Tools Learning

## Mastered Tools

### 1. Radare2 - Open Source Reverse Engineering Framework
- **Functionality**: Complete reverse engineering platform supporting multiple architectures and file formats
- **Core Commands**: `r2 -A -c 'commands' -q file`
- **Practical Points**:
  - Auto analysis (aaa) quickly identifies functions
  - Interactive debugging and disassembly
  - Scriptable analysis capabilities
  - Supports multiple file formats (ELF, PE, Mach-O, etc.)

### 2. Binwalk - Firmware Analysis Tool
- **Functionality**: Firmware and binary file analysis, signature identification and extraction
- **Core Commands**: `binwalk -Me firmware.bin`
- **Practical Points**:
  - Automatic file signature identification
  - Embedded filesystem extraction
  - Architecture auto-detection (-Y)
  - Supports custom magic files

### 3. Ghidra - NSA Open Source Reverse Engineering Platform
- **Functionality**: Enterprise-grade reverse engineering platform supporting complex analysis
- **Core Commands**: Headless mode batch analysis
- **Practical Points**:
  - Requires proper Java environment configuration
  - Supports scripted extensions
  - Powerful decompilation capabilities
  - Team collaboration features

### 4. Xxd - Hex Dump Tool
- **Functionality**: File hexadecimal representation and conversion
- **Core Commands**: `xxd -i file` or `xxd -r hexdump`
- **Practical Points**:
  - C-style output for embedding in code
  - Reverse operation can reconstruct binary from hex
  - Supports various format options

### 5. Objdump - Object File Dump Tool
- **Functionality**: Binary file structure and disassembly
- **Core Commands**: `objdump -d binary_file`
- **Practical Points**:
  - Multi-architecture support
  - Detailed disassembly output
  - Symbol table and dynamic information display

### 6. Readelf - ELF File Analysis Tool
- **Functionality**: Detailed analysis specifically for ELF format
- **Core Commands**: `readelf -a elf_file`
- **Practical Points**:
  - Detailed ELF file header, program header, section header information
  - Dynamic linking and relocation information
  - Symbol table and debug information

### 7. Other Tools
- **Strings**: Extract printable strings
- **Hexdump**: Hex dump
- **File**: File type identification

## Tool Combination Strategy

### Binary Analysis Workflow
1. **Initial Identification**: file + strings + xxd
2. **Structure Analysis**: readelf/objdump + r2
3. **Deep Disassembly**: objdump -d + r2 interactive
4. **Firmware Analysis**: binwalk + extraction + repeat

### Malware Analysis
1. **Static Analysis**: strings + binwalk + readelf
2. **Dynamic Preparation**: r2 -d + objdump -T
3. **Behavior Monitoring**: Debugger step-by-step execution

## Practical Considerations

### Security Best Practices
- Analyze suspicious files in isolated environments
- Do not directly execute unknown binaries
- Handle original files in read-only mode
- Back up important samples

### Technical Optimization
- Cross-validate results from multiple tools
- Start with simple tools, gradually go deeper
- Use scripts to automate repetitive tasks
- Document the complete analysis process

## File Locations
- Detailed command reference: `/home/parallels/.openclaw/workspace/security-tools-67/reverse-engineering-cli-reference.md`
- This learning record: current file
- Tool classification statistics: `/home/parallels/.openclaw/workspace/kali-517-analysis/`

## Follow-up Learning Plan
- Deep study of digital forensics tools (autopsy, scalpel, foremost, etc.)
- Master wireless security tools (kismet, aircrack-ng, reaver, etc.)
- Learn post-exploitation tools (mimikatz, crackmapexec, bloodhound, etc.)
