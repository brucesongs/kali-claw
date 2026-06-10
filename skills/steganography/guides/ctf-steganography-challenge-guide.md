# CTF Steganography Challenge Guide

## Introduction

Steganography challenges are a staple of Capture The Flag (CTF) competitions, testing participants' ability to identify carrier formats, apply the correct detection tools, and decode hidden payloads through multiple layers of obfuscation. Unlike real-world steganography where the goal is to evade detection, CTF challenges are designed to be solvable within the competition timeframe, often using well-known tools with specific twists.

This guide provides a systematic approach to solving CTF steganography challenges, organized by carrier format and embedding technique. Each section identifies the tool to use, the specific flags and options that matter, and the common tricks that challenge authors use to add difficulty.

---

## 1. Initial Triage: The First 60 Seconds

When you encounter a steganography challenge, the first minute should establish the basic facts:

```bash
# Step 1: Determine the true file type
file challenge_file.jpg

# Step 2: Inspect magic bytes
xxd challenge_file.jpg | head -3

# Step 3: Quick strings check (catches 20% of easy challenges)
strings -n 8 challenge_file.jpg | grep -iE 'flag|ctf|key|password'
strings -n 8 challenge_file.jpg | tail -20

# Step 4: Check file size vs. expected
ls -la challenge_file.jpg
```

**Common easy wins**: Many beginner challenges hide the flag in plaintext in a comment field, appended after the EOF marker, or as a base64-encoded string visible in `strings` output. These three checks take under 30 seconds and solve a surprising number of challenges.

### File Type Mismatch Detection

Challenge authors frequently change file extensions to mislead participants. A PNG file renamed to .jpg will fail steghide analysis but succeed with zsteg. Always trust the `file` command output over the extension.

```bash
# Common mismatch patterns:
# PNG renamed to .jpg -> use zsteg, not steghide
# JPEG renamed to .png -> use steghide, not zsteg
# ZIP renamed to .jpg -> use unzip after locating the ZIP header
# PDF with appended data -> check after %%EOF marker
```

---

## 2. JPEG Challenges: Steghide and Beyond

### Standard Steghide Challenges

Most JPEG steganography challenges use steghide. The systematic approach:

```bash
# 1. Try empty passphrase first (most common in CTF)
steghide extract -sf challenge.jpg -p ""

# 2. Try common CTF passphrases
for pass in "password" "secret" "hidden" "stego" "flag"; do
  echo "Trying: $pass"
  steghide extract -sf challenge.jpg -p "$pass" -f /tmp/out.tmp 2>/dev/null && \
    echo "SUCCESS: $pass" && cat /tmp/out.tmp && break
done

# 3. Check if passphrase is provided in challenge description or metadata
exiftool -Comment -UserComment challenge.jpg
steghide info challenge.jpg
```

### Advanced JPEG Tricks

**JSteg embedding**: If steghide finds nothing, the challenge may use jsteg, which embeds data differently in DCT coefficients:

```bash
# jsteg uses a different embedding algorithm
# Install: go get github.com/lukechampine/jsteg
jsteg reveal challenge.jpg > revealed_data.txt
```

**Outguess**: Another JPEG steganography tool with statistical correction that preserves the JPEG's statistical properties:

```bash
# Outguess uses statistical correction to avoid detection
outguess -r challenge.jpg revealed.txt
outguess -r -k "password" challenge.jpg revealed.txt
```

### JPEG Structure Analysis

```bash
# Check for data after JPEG EOF marker (FF D9)
python3 -c "
with open('challenge.jpg', 'rb') as f:
    data = f.read()
    eoi = data.rfind(b'\xff\xd9')
    if eoi + 2 < len(data):
        extra = data[eoi + 2:]
        print(f'Data after JPEG EOF: {len(extra)} bytes')
        print(extra[:200])
    else:
        print('No data after EOF marker')
"
```

---

## 3. PNG Challenges: zsteg and LSB Analysis

PNG is the second most common carrier format in CTF challenges. Since steghide does not support PNG, zsteg is the primary tool.

### Standard zsteg Workflow

```bash
# 1. Full scan of all channels and bit planes
zsteg -a challenge.png

# 2. If zsteg reports findings, extract them
zsteg -a challenge.png -o extracted.bin

# 3. Try zlib decompression on all channels
zsteg -a --try-zlib challenge.png

# 4. Target specific channels if full scan is noisy
zsteg -b 1,rgb,lsb,xy challenge.png
zsteg -b 2,rgb,lsb,xy challenge.png
```

### Interpreting zsteg Output

zsteg reports findings with metadata about where data was found. Key fields:

- **Channel**: `b1,r,lsb,xy` means bit 1, red channel, LSB first, row-major order
- **Offset**: Where in the decoded stream the pattern was recognized
- **Pattern**: What zsteg thinks it found (text, zlib stream, etc.)

```bash
# Common zsteg findings and their meaning:
# "text" at offset 0 = plaintext hidden in LSB
# "zlib compressed" = compressed data in LSB (extract and decompress)
# "OpenEXR" or "bpg" = another image format embedded in LSB
```

### Manual LSB Extraction

When zsteg does not automatically find data, manual extraction may be necessary:

```python
#!/usr/bin/env python3
"""Manual LSB extraction from PNG image."""
from PIL import Image
import sys

def extract_lsb(image_path, num_bits=None):
    """Extract LSB data from all RGB channels."""
    img = Image.open(image_path).convert('RGB')
    pixels = list(img.getdata())

    bits = []
    for pixel in pixels:
        for channel in pixel:  # R, G, B
            bits.append(str(channel & 1))

    # Convert bits to bytes
    byte_data = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = int(''.join(bits[i:i+8]), 2)
        byte_data.append(byte)
        if num_bits and i >= num_bits:
            break

    return bytes(byte_data)

data = extract_lsb('challenge.png')
# Check what the extracted data looks like
print(data[:100])

# Try to identify the format
with open('lsb_extracted.bin', 'wb') as f:
    f.write(data[:10000])  # Write first 10KB for analysis

# Then run file on it
# file lsb_extracted.bin
```

---

## 4. Firmware and Binary Challenges: Binwalk

Challenges that provide firmware images, ROM dumps, or mysterious binary files often require binwalk for extraction.

### Standard Binwalk Workflow

```bash
# 1. Scan for embedded signatures
binwalk challenge.bin

# 2. Extract everything recursively
binwalk -Me challenge.bin

# 3. Check the extraction directory
ls -la _challenge.bin.extracted/

# 4. Examine each extracted file
file _challenge.bin.extracted/*

# 5. If binwalk finds a ZIP, try extracting with password
cd _challenge.bin.extracted/
unzip hidden.zip
# If password-protected, try common passwords
```

### Entropy Analysis

When binwalk does not find known signatures, entropy analysis can reveal hidden data regions:

```bash
# Generate entropy plot
binwalk -E challenge.bin

# High entropy region in the middle of a file may indicate:
# - Encrypted payload
# - Compressed archive without header
# - Random data padding
```

---

## 5. Common Encoding Tricks

CTF challenges rarely stop at simple embedding. The extracted data often requires additional decoding:

### Base64 and Hex Encoding

```bash
# Check if extracted data is base64
cat extracted.txt | base64 -d 2>/dev/null && echo "Base64 confirmed"
cat extracted.txt | base64 -d > decoded.bin 2>/dev/null
file decoded.bin

# Check if extracted data is hex-encoded
cat extracted.txt | xxd -r -p > decoded.bin
file decoded.bin

# Sometimes data is double-encoded (hex of base64, etc.)
cat extracted.txt | xxd -r -p | base64 -d > double_decoded.bin
```

### Binary and Octal Encoding

```bash
# Binary string to text
python3 -c "
binary = '01000110 01001100 01000001 01000011'
text = ''.join(chr(int(b, 2)) for b in binary.split())
print(text)
"

# Octal string to text
python3 -c "
octal = '106 114 101 103'
text = ''.join(chr(int(o, 8)) for o in octal.split())
print(text)
"
```

### Palette and Color Manipulation

Some PNG challenges hide data in the color palette rather than pixel values:

```bash
# Extract PNG palette and check for unusual patterns
python3 -c "
from PIL import Image
img = Image.open('challenge.png')
if img.mode == 'P':
    palette = img.getpalette()
    # Check for duplicate colors (possible data encoding)
    colors = [(palette[i], palette[i+1], palette[i+2])
              for i in range(0, len(palette), 3)]
    unique = len(set(colors))
    total = len(colors)
    print(f'Palette entries: {total}, Unique: {unique}')
    if unique < total:
        print(f'DUPLICATE COLORS DETECTED: {total - unique} duplicates')
        print('This may indicate palette-based steganography')
"
```

### Appended Data and Composite Files

```bash
# Check for ZIP appended after image data
# This works for any image format
python3 -c "
import zipfile
try:
    z = zipfile.ZipFile('challenge.jpg')
    print('ZIP FOUND in JPEG file!')
    print(z.namelist())
    z.extractall('/tmp/zip_contents/')
except:
    print('No ZIP structure found')
"

# Alternative: binwalk handles this automatically
binwalk -e challenge.jpg
```

---

## 6. Systematic Challenge-Solving Checklist

Follow this checklist in order for every steganography challenge:

1. [ ] Run `file` to verify true file type
2. [ ] Run `strings -n 8` to check for plaintext flags
3. [ ] Run `exiftool` to check metadata for hidden data or hints
4. [ ] If JPEG: run `steghide info` then try extraction (empty pass, common passwords)
5. [ ] If JPEG + steghide fails: try jsteg, outguess
6. [ ] If PNG: run `zsteg -a` to scan all LSB channels
7. [ ] Run `binwalk` to scan for embedded file signatures
8. [ ] Check for appended data after EOF marker
9. [ ] Check for ZIP archive embedded in the file
10. [ ] Decode extracted data: try base64, hex, ROT13, zlib
11. [ ] If passphrase-protected: run stegcracker with targeted wordlists
12. [ ] Check the challenge description for hints (theme words as passwords)

---

## References

- **CTF Steganography Walkthrough Collection**: https://github.com/Dvd848/CTFs -- Extensive collection of CTF challenge solutions with steganography examples
- **Steganography Tutorial by 0xRick**: https://0xrick.github.io/lists/stego/ -- Tool-by-tool steganography guide oriented toward CTF solving
- **zsteg Repository**: https://github.com/zed-0xff/zsteg -- PNG/BMP LSB detection and extraction tool
- **Steghide Documentation**: https://steghide.sourceforge.net/ -- Official steghide reference for JPEG/BMP/WAV embedding
- **CyberChef**: https://gchq.github.io/CyberChef/ -- Online tool for decoding chains (base64, hex, zlib, etc.) often needed for multi-layer CTF payloads
- **APT42 Steganography Research**: https://attack.mitre.org/techniques/T1001/001/ -- MITRE ATT&CK reference for steganography in real-world attacks (T1001.001)
