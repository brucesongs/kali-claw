# Command Injection Filter Bypass Guide

> Reference guide for understanding filter bypass techniques and tool usage

---

## Overview

Modern web applications implement input validation mechanisms to prevent command injection. This guide documents the categories of bypass techniques and recommended tools for testing.

---

## 1. Space Bypass Techniques

Space characters separate command names from arguments. Multiple bypass categories exist.

### 1.1 Alternative Whitespace Characters

**Concept**: Replace spaces with other whitespace that shell parsers accept.

**Methods**:
- Tab characters (hex 09)
- Newline (hex 0a)
- Carriage return (hex 0d)
- Vertical tab (hex 0b)
- Form feed (hex 0c)

**Limitation**: Bash/sh only. Test with `commix`.

### 1.2 Bash Parameter Expansion

**Concept**: Reference shell variables to create spaces without literal space character.

**Methods**:
- IFS (Internal Field Separator) variable
- Positional parameters
- Substring extraction from environment variables

**Limitation**: Bash/sh only. Test with `commix`.

### 1.3 Bash Brace Expansion

**Concept**: Bash feature for command/argument grouping without separators.

**Syntax**: Comma-separated arguments within braces, no spaces required.

**Tool**: `commix --technique=TFBSC`.

### 1.4 Input Redirection

**Concept**: Use shell redirection operators to read/write without spaces.

**Operators**: `<`, `>`, `>>`, `<<` (here-doc), `<()` (process substitution).

**Tool**: `commix`.

### 1.5 Variable Expansion Tricks

**Methods**:
- Empty variable expansion
- Substring extraction from PATH or other env variables
- Command substitution for spacing

**Tool**: `commix --level=3`.

---

## 2. Keyword Bypass Techniques

### 2.1 Quote Insertion

**Concept**: Insert empty quotes within command names to break up filtered keywords.

**Methods**:
- Single quotes between characters
- Double quotes between characters
- Mixed quote patterns

**Example pattern**: `c''at` (single quotes), `c""at` (double quotes).

### 2.2 Backslash Escaping

**Concept**: Escape individual characters to bypass keyword filters.

**Method**: Backslash prefix on characters.

### 2.3 Variable Expansion

**Concept**: Reconstruct commands via variable assignment and expansion.

**Methods**:
- Assign portions of command to variables
- Expand variables in sequence
- Use substring extraction

### 2.4 Wildcards and Globbing

**Concept**: Use glob patterns to match filesystem paths, breaking up command names.

**Patterns**:
- `?` (single character match)
- `*` (multiple characters)
- `[...]` (character class)
- `[a-z]` (range)

**Example patterns**: `/???/c?t`, `/*/bin/w*ami`.

### 2.5 Case Manipulation

**Concept**: Mixed case execution for case-insensitive systems.

**Method**: Alternate uppercase/lowercase.

### 2.6 String Concatenation

**Concept**: Reconstruct commands via variable assignment.

**Method**: Assign portions to variables, concatenate via expansion.

---

## 3. Encoding and Obfuscation

### 3.1 URL Encoding

**Method**: Single or double URL encoding of metacharacters.

**Limitation**: Only effective if application decodes before parsing.

**Tool**: `commix` (auto-encodes), Burp Suite Intruder.

### 3.2 Hex Encoding

**Method**: Represent characters as hex escape sequences.

**Tool**: Burp Suite, CyberChef.

### 3.3 Octal Encoding

**Method**: Represent characters as octal escape sequences.

**Tool**: Burp Suite, CyberChef, `printf`.

### 3.4 Base64 Encoding

**Concept**: Encode payload, decode in subshell via base64.

**Method**: Pipe through `base64 -d` or decode in eval context.

**Tool**: Standard utilities + Burp.

### 3.5 Unicode Encoding

**Limitation**: Limited support; context-dependent.

**Tool**: Test with target.

### 3.6 Null Byte Injection

**Concept**: Null bytes can truncate strings in some contexts.

**Limitation**: Modern systems handle safely; limited applicability.

---

## 4. Context-Specific Bypass

### 4.1 Bash-Specific Features

**Available features**:
- Brace expansion
- Process substitution
- Here-string syntax
- Arithmetic expansion
- Parameter expansion

**Tool**: `commix`.

### 4.2 PowerShell-Specific

**Features**:
- PowerShell -Command execution
- Base64 encoded command blocks
- Environment variable paths

**Tool**: Manual testing on Windows.

### 4.3 Python/Eval Context

**Features**:
- __import__ for module loading
- eval/exec for code execution
- subprocess module calls

**Tool**: Manual testing, `tplmap` for template injection.

---

## 5. Automated Testing

### Tool: commix

**Purpose**: Automated command injection detection and exploitation.

**Capabilities**:
- Tests all separator types (`;`, `|`, `&&`, `||`, etc.)
- Space bypass via IFS, tabs, brace expansion
- Blind injection via time-based or DNS detection
- Multiple technique levels (TFBSC)

**Usage**: `commix -u "URL?param=INJECT_HERE" --batch --level=3`

### Tool: Burp Suite

**Features**:
- Repeater for manual payload crafting
- Intruder for payload variation
- Encoder for multi-stage encoding
- Timing analysis for blind injection

### Tool: CyberChef

**Features**:
- Multi-stage encoding chains
- Visualization of encoding pipeline
- Recipe sharing for complex transforms

---

## 6. Detection and Bypass Workflow

1. **Identify filter type**: Determine what characters/keywords are blocked
2. **Classify bypass**: Whitespace, keyword, encoding, or context-specific
3. **Apply tool**: Use `commix` for automated testing or manual Burp for specific payloads
4. **Test progressively**: Level 1 (basic) → Level 2 (space bypass) → Level 3 (keyword bypass) → Level 4 (encoding)
5. **Verify exploitation**: Time-based, DNS callback, or output-based confirmation

---

## 7. WAF Considerations

**Common WAF bypass challenges**:
- Multi-layer encoding detection
- Keyword pattern matching with wildcards
- Sequence-based attack detection
- Rate limiting on repeated attempts

**Approach**:
- Start with basic techniques
- Progress to complex encoding chains
- Use randomization in payloads (CyberChef)
- Distribute requests over time
- Test with `commix --level=3` or custom scripts

---

*This guide documents bypass technique categories and tools. Specific payload generation is performed by security tools like commix and Burp Suite.*
