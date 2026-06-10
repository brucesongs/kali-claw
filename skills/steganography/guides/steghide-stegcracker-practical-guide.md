# Steghide and Stegcracker Practical Guide

## Introduction

Steghide is the most widely used steganography tool in both CTF competitions and real-world scenarios, supporting JPEG, BMP, WAV, and AU carrier formats with optional passphrase protection. Stegcracker is a dedicated brute-force tool that automates passphrase recovery against steghide-protected files using wordlist attacks. This guide provides practical, step-by-step instructions for embedding data, extracting hidden payloads, and recovering lost or unknown passphrases.

The guide is structured for both offensive use (testing whether hidden data channels can be established within a target environment) and defensive use (extracting hidden data during forensic investigations and incident response).

---

## 1. Steghide Fundamentals

### Supported Carrier Formats

Steghide operates on specific carrier formats by modifying their internal data structures:

| Carrier Format | Extension | Embedding Method | Capacity Notes |
|----------------|-----------|-----------------|----------------|
| JPEG | .jpg, .jpeg | DCT coefficient modification | High capacity; visually identical output |
| BMP | .bmp | Pixel value modification | Very high capacity; lossless carrier |
| WAV | .wav | Audio sample modification | High capacity; inaudible modifications |
| AU | .au | Audio sample modification | Less common; same approach as WAV |

Key constraint: steghide cannot embed into PNG, GIF, or TIFF files. If you encounter these formats, use alternative tools (zsteg for PNG, custom scripts for GIF).

### Embedding Data

```bash
# Basic embedding (prompts for passphrase interactively)
steghide embed -cf carrier.jpg -ef secret.txt

# Embed with passphrase specified on command line
steghide embed -cf carrier.jpg -ef secret.txt -p "MySecretPass"

# Embed without passphrase (empty passphrase)
steghide embed -cf carrier.jpg -ef secret.txt -p ""

# Embed with compression level (0=none, 9=max, default=none for JPEG)
steghide embed -cf carrier.jpg -ef secret.txt -z 9

# Embed into BMP carrier (often preferred for higher capacity)
steghide embed -cf carrier.bmp -ef secret.txt -p "password"

# Embed into WAV audio carrier
steghide embed -cf audio.wav -ef secret.txt -p "password"

# Specify output filename (preserves original carrier)
steghide embed -cf original.jpg -ef secret.txt -sf stego_output.jpg -p "pass"
```

### Checking Embedding Capacity

Before embedding large payloads, verify the carrier file has sufficient capacity:

```bash
# Display embedding info including capacity
steghide info carrier.jpg

# Output example:
# "carrier.jpg": format is jpeg
#   capacity: 3.2 KB
# Try to get information about embedded data? (y/n)

# For JPEG: capacity depends on image complexity (more complex = more capacity)
# For BMP: capacity is approximately (width * height * 3) / 8 bytes
```

### Verifying Embedding Quality

After embedding, verify that the steganographic carrier passes casual inspection:

```bash
# File size comparison (JPEG: sizes should be very similar)
ls -la original.jpg stego_output.jpg

# Visual comparison using ImageMagick
compare original.jpg stego_output.jpg diff.png
# diff.png should be nearly all black (minimal differences)

# Check that the file still opens normally
xdg-open stego_output.jpg  # or any image viewer

# Verify file type is unchanged
file original.jpg stego_output.jpg
```

---

## 2. Steghide Extraction

### Basic Extraction

```bash
# Extract with known passphrase
steghide extract -sf stego_carrier.jpg -p "MySecretPass"

# Extract with empty passphrase (very common in CTF)
steghide extract -sf stego_carrier.jpg -p ""

# Extract and specify output filename
steghide extract -sf stego_carrier.jpg -p "password" -f recovered_secret.txt

# Force extraction even if integrity check fails
steghide extract -sf stego_carrier.jpg -p "password" --force

# Extract from WAV carrier
steghide extract -sf audio_stego.wav -p "password"
```

### Information Gathering Before Extraction

```bash
# Check if file contains steghide embedding
steghide info stego_carrier.jpg

# This reveals:
# - Whether embedded data exists
# - The embedded file's original name
# - The embedded file's size
# - The compression used

# If steghide asks "Try to get information about embedded data? (y/n)"
# Answer 'y' to see embedding details (requires passphrase)
# Answer 'n' if you don't have the passphrase yet
```

### Common Extraction Issues

**Problem: "The file format is not supported"**
- The file is likely PNG, GIF, or another unsupported format. Use zsteg (PNG/BMP) or binwalk instead.

**Problem: "The passphrase is wrong"**
- The file is passphrase-protected. Try common passwords first, then use stegcracker for brute-force recovery.

**Problem: "No data could be extracted"**
- Either the file does not contain steghide embedding, or it uses a different tool. Try binwalk, zsteg, or other detection methods.

---

## 3. Stegcracker Password Recovery

### How Stegcracker Works

Stegcracker automates the process of trying each word in a wordlist as a steghide passphrase. It reads the wordlist line by line, attempts extraction with each word, and stops when extraction succeeds. Under the hood, it calls `steghide extract` for each candidate passphrase.

### Basic Usage

```bash
# Standard wordlist attack with rockyou.txt
stegcracker stego_carrier.jpg /usr/share/wordlists/rockyou.txt

# Specify expected file extension (optimization hint)
stegcracker stego_carrier.jpg /usr/share/wordlists/rockyou.txt -x txt

# Use custom wordlist
stegcracker stego_carrier.jpg custom_wordlist.txt

# Use SecLists specialized wordlists
stegcracker stego_carrier.jpg /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100000.txt
```

### Optimizing Password Recovery

Recovery speed is limited by steghide's extraction speed (typically 50-200 attempts per second on modern hardware). Optimization strategies focus on wordlist selection rather than raw speed:

```bash
# Strategy 1: Start with small, targeted wordlists
stegcracker stego_carrier.txt /usr/share/seclists/Passwords/Common-Credentials/best1050.txt

# Strategy 2: CTF-specific wordlists
# Generate a custom wordlist based on the challenge theme
cat > ctf_wordlist.txt << 'EOF'
password
secret
hidden
flag
stego
steganography
admin
letmein
welcome
EOF

# Strategy 3: If the challenge has a theme, add related words
# For a space-themed CTF:
cat >> ctf_wordlist.txt << 'EOF'
nasa
rocket
apollo
orbit
satellite
EOF

stegcracker stego_carrier.jpg ctf_wordlist.txt
```

### Manual Brute Force (Fallback)

If stegcracker is not available, a manual brute-force loop achieves the same result:

```bash
# Manual brute force with steghide
while IFS= read -r password; do
  if steghide extract -sf stego_carrier.jpg -p "$password" -f /tmp/extract.tmp 2>/dev/null; then
    echo "PASSWORD FOUND: $password"
    echo "Extracted data:"
    cat /tmp/extract.tmp
    break
  fi
done < /usr/share/wordlists/rockyou.txt

# Parallelized manual brute force (faster on multi-core systems)
grep -v '^#' /usr/share/wordlists/rockyou.txt | \
  xargs -P 4 -I {} sh -c 'steghide extract -sf stego_carrier.jpg -p "{}" -f /tmp/extract.tmp 2>/dev/null && echo "FOUND: {}"'
```

### Handling Large Wordlists

For very large wordlists, consider splitting the work:

```bash
# Split rockyou.txt into chunks
split -l 100000 /usr/share/wordlists/rockyou.txt chunk_

# Process chunks sequentially or in parallel
for chunk in chunk_*; do
  echo "Processing $chunk..."
  stegcracker stego_carrier.jpg "$chunk" && break
done

# Clean up chunks
rm -f chunk_*
```

---

## 4. Practical Workflow for Investigations

### Step-by-Step Investigation Process

When you encounter a suspected steganographic file during an investigation or CTF:

**1. Verify the file type**: Run `file suspect.jpg` and check magic bytes. If the extension does not match the actual format, rename it and proceed with the correct tool.

**2. Extract metadata**: Run `exiftool -a suspect.jpg` to check for hidden data in comment fields, unusual software tags, or GPS coordinates that provide context.

**3. Check for steghide embedding**: Run `steghide info suspect.jpg`. If it reports embedded data, attempt extraction with common passphrases first (empty string, "password", challenge theme words).

**4. Escalate to stegcracker**: If common passphrases fail, run stegcracker with progressively larger wordlists, starting with targeted lists and escalating to rockyou.txt.

**5. Validate extracted data**: Run `file` on the extracted output, attempt to decode base64 or hex, check for compressed archives, and verify data integrity against any known indicators.

### Common CTF Patterns

CTF challenges involving steghide commonly use one of these patterns:

- **Empty passphrase**: Always try `-p ""` first; it is the most common CTF default
- **Challenge name as password**: The CTF challenge title or category name is often the passphrase
- **Flag-in-flag**: The extracted data may itself be encoded (base64, hex, ROT13) and require further decoding
- **Multi-layer**: Extracted data may be another carrier file that requires different steganography tools

---

## 5. Batch Processing for Forensic Investigations

When analyzing multiple suspected carrier files during an investigation:

```bash
#!/bin/bash
# Batch steghide extraction script
# Processes all JPEG files in a directory

DIR="$1"
PASS="$2"  # Optional passphrase

for file in "$DIR"/*.jpg "$DIR"/*.jpeg "$DIR"/*.bmp "$DIR"/*.wav; do
  [ -f "$file" ] || continue
  echo "Analyzing: $file"

  # Check for embedding
  if steghide info "$file" -p "${PASS:-}" 2>/dev/null | grep -q "embedded"; then
    echo "  [+] Embedding detected: $file"
    # Attempt extraction
    outfile="$(basename "$file" | sed 's/\.[^.]*$//')_extracted"
    if steghide extract -sf "$file" -p "${PASS:-}" -f "/tmp/$outfile" 2>/dev/null; then
      echo "  [+] Extracted: /tmp/$outfile"
      file "/tmp/$outfile"
    else
      echo "  [-] Extraction failed (wrong passphrase?)"
    fi
  else
    echo "  [-] No steghide embedding found"
  fi
  echo
done
```

---

## References

- **Steghide Manual Page**: `man steghide` or https://steghide.sourceforge.net/documentation.php -- Complete steghide documentation covering all options and carrier formats
- **Stegcracker GitHub**: https://github.com/StefanoDeCarli/stegcracker -- Stegcracker tool repository with installation instructions and usage examples
- **SecLists Passwords**: https://github.com/danielmiessler/SecLists/tree/master/Passwords -- Comprehensive password wordlists for brute-force attacks
- **Kali Steganography Tools**: https://www.kali.org/tools/ -- Kali Linux steganography tool catalog with package names
- **Steganography Tutorial**: https://0xrick.github.io/lists/stego/ -- Practical steganography tools and techniques reference
