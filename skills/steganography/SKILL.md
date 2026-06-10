---
name: steganography
description: "Steganography is the practice of concealing data within non-secret carrier files such as images, audio, video, and documents. Unlike encryption, which makes data unreadable but visibly present, steganography hides the very existence of the hidden data."
origin: openclaw
version: "0.1.18"
compatibility:
  - openclaw
  - claude-code
  - cursor
  - windsurf
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
  - WebSearch
  - WebFetch
metadata:
  domain: forensics
  tool_count: 6
  guide_count: 5
---




# Skill: Steganography

> **Supplementary Files**:
> - `payloads.md` — Steganography command reference covering format identification, embedding and extraction with steghide, PNG analysis with zsteg, firmware extraction with binwalk, file carving with foremost, metadata analysis with exiftool, and password recovery with stegcracker
> - `test-cases.md` — Structured test case list covering format identification, steghide embedding/extraction, zsteg PNG analysis, binwalk firmware extraction, stegcracker password recovery, and metadata analysis with exiftool

## Summary

Unlike encryption, which makes data unreadable but visibly present, steganography hides the very existence of the hidden data.

**Tools**: steghide, stegcracker, zsteg, binwalk, foremost, exiftool

**Domain**: forensics

## Description

Steganography is the practice of concealing data within non-secret carrier files such as images, audio, video, and documents. Unlike encryption, which makes data unreadable but visibly present, steganography hides the very existence of the hidden data. This skill covers both offensive techniques (embedding covert data for exfiltration or C2 communication) and defensive techniques (detecting and extracting hidden data during forensics investigations and CTF challenges).

**Core Insight**: Steganography exploits the gap between what humans perceive and what digital files actually contain. A JPEG image that looks identical before and after embedding may carry megabytes of hidden data in its least-significant bits, quantization tables, or appended file segments. Detection requires statistical analysis, not visual inspection.

**Key Attack Surfaces**:

- **LSB Embedding**: Least-significant-bit manipulation in BMP/PNG/WAV files where altering the lowest bit of each color channel is imperceptible to the human eye
- **JPEG Coefficient Manipulation**: Modifying DCT coefficients in JPEG files using tools like steghide, which hides data in the frequency domain
- **Metadata Abuse**: Hiding data in EXIF fields, IPTC tags, XMP metadata, or comment sections where it is overlooked during casual inspection
- **Appended Data**: Concatenating archives, scripts, or binaries after the carrier file's EOF marker, invisible to standard viewers
- **Palette Manipulation**: Reordering or duplicating color palette entries in GIF/PNG to encode information

---

## Use Cases

1. **CTF Steganography Challenges** - Systematically identify carrier format, apply format-specific detection tools, extract hidden flags from images, audio files, and documents
2. **Data Exfiltration Detection** - Analyze suspected carrier files on compromised systems to detect hidden data channels used for intellectual property theft or C2 communication
3. **Anti-Forensics Analysis** - Detect steganographic tools and embedded payloads on seized devices during digital forensic investigations
4. **Covert Channel Assessment** - Test organizational defenses against data hiding techniques by embedding test data in common file types and measuring detection rates
5. **Malware Payload Analysis** - Extract steganographically-hidden payloads from images delivered via phishing emails or hosted on compromised websites

---

## Core Tools

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **steghide** | Embed and extract data in JPEG, BMP, WAV, and AU files with passphrase support | `steghide extract -sf carrier.jpg -p password` |
| **stegcracker** | Brute-force steghide passphrases using wordlists | `stegcracker carrier.jpg /usr/share/wordlists/rockyou.txt` |
| **zsteg** | Detect and extract LSB-encoded data in PNG and BMP files | `zsteg -a suspicious.png` |
| **binwalk** | Identify and extract embedded files, firmware components, and appended data | `binwalk -Me firmware.bin` |
| **foremost** | Carve files from disk images and carrier files based on header/footer signatures | `foremost -t jpg,png,pdf -i carrier.bin -o /output` |
| **exiftool** | Read and analyze file metadata including EXIF, IPTC, XMP, and custom tags | `exiftool -a -G1 suspicious.jpg` |

Auxiliary tools: **stegsolve** (visual analysis with bit-plane filters), **g stag** (generic steganography framework), **outguess** (JPEG steganography with statistical correction), **jsteg** (JPEG LSB embedding), **strings** (quick text extraction from any binary file).

---

## Methodology

### Analysis Chain

```
[1] Identify              [2] Analyze             [3] Detect
  - Carrier format          - File metadata          - Format-specific stego
    (JPEG/PNG/BMP/          - Size anomalies          detection
     WAV/PDF)               - Entropy analysis      - steghide info / zsteg /
  - True file type          - Comment fields           binwalk signatures
    vs extension          - Appended data            - Statistical tests
       |                        |                        |
       v                        v                        v
[4] Extract              [5] Crack               [6] Verify
  - Tool-specific           - stegcracker with        - Validate extracted
    extraction                wordlists                data integrity
  - LSB data recovery       - Custom dictionary       - Check file signatures
  - Carve embedded files    - Rule-based              - Confirm completeness
                              mutations
```

**Phase Details**:

1. **Identify** - Determine the true file format regardless of extension using magic bytes (`file` command, `xxd | head`). JPEG files start with `FF D8 FF`, PNG with `89 50 4E 47`, BMP with `42 4D`, and WAV with `52 49 46 46`. Mismatched extensions are a common anti-analysis trick
2. **Analyze** - Extract comprehensive metadata with exiftool, compare file size against expected size for the format and resolution, check for unusually high entropy in regions that should be structured, and examine comment/annotation fields
3. **Detect** - Run format-appropriate detection: steghide info for JPEG/BMP, zsteg for PNG/BMP, binwalk for any binary with embedded signatures. Statistical analysis tools can reveal LSB manipulation through chi-square tests and sample-pair analysis
4. **Extract** - Use the appropriate tool based on format and embedding method: steghide for JPEG/BMP/WAV, zsteg for PNG LSB, binwalk for appended/embedded files, foremost for file carving from composite images
5. **Crack** - If the embedded data is passphrase-protected, use stegcracker with standard wordlists (rockyou.txt, SecLists). Custom dictionaries based on context (CTF theme, target organization) improve success rates
6. **Verify** - Validate the extracted data by checking file signatures, attempting to decompress archives, decoding base64 or hex payloads, and confirming data completeness against any embedded length indicators

### Defense Perspective

| Defense Measure | Description | Attack Types Countered |
|-----------------|-------------|----------------------|
| Statistical Steganalysis | Chi-square tests, RS analysis, and sample-pair analysis to detect LSB modifications | LSB embedding in BMP/PNG |
| File Integrity Monitoring | Baseline hashing and size monitoring for files on web servers and shared directories | Appended data, metadata abuse |
| Entropy Analysis | Scan for unusually high entropy regions in image files that may indicate encrypted hidden data | Any steganographic embedding |
| Network DLP | Deep packet inspection for large image/audio uploads that exceed normal size expectations | Data exfiltration via carrier files |
| Metadata Stripping | Automatically strip EXIF/XMP metadata from uploaded files | Metadata-based data hiding |

---

## Practical Steps

### 1. Format Identification Phase

```bash
# Determine true file type regardless of extension
file suspicious_image.jpg
xxd suspicious_image.jpg | head -5

# Check for mismatched extensions (common CTF trick)
# PNG with .jpg extension or vice versa
python3 -c "
import magic
print(magic.from_file('suspicious_image.jpg'))
"
```

### 2. Metadata Analysis Phase

```bash
# Comprehensive metadata extraction
exiftool -a -G1 suspicious.jpg

# Check for unusual comment fields
exiftool -Comment -UserComment -ImageDescription suspicious.jpg

# Compare file size to expected size for resolution
identify suspicious.jpg  # ImageMagick for dimensions
```

### 3. Detection and Extraction Phase

```bash
# JPEG/BMP: check for steghide embedding
steghide info carrier.jpg

# PNG: run zsteg with all channels
zsteg -a suspicious.png

# Any binary: scan for embedded signatures
binwalk suspicious.png
```

> **For detailed payloads see `payloads.md`, and for the complete test checklist see `test-cases.md`.**

---

## Common Pitfalls

- **Relying on visual inspection**: Most steganographic embedding is invisible to the human eye. A JPEG image can carry hundreds of kilobytes of hidden data without any perceptible visual difference. Always use statistical and tool-based detection methods.
- **Ignoring file type mismatches**: Many CTF challenges and real-world payloads use intentionally wrong file extensions (e.g., a PNG file with a .jpg extension). Always verify the actual file type using magic bytes before selecting detection tools.
- **Giving up after one tool fails**: Different embedding methods require different tools. If steghide finds nothing on a JPEG, try outguess or jsteg. If zsteg finds nothing on a PNG, check for appended data with binwalk. Method coverage matters.

## Automation and Scripting

Automate initial triage by running file type identification, exiftool metadata extraction, and format-appropriate detection in sequence. For batch analysis of many suspected carrier files, script a pipeline that runs `file` to determine format, then dispatches to steghide info (JPEG/BMP), zsteg (PNG/BMP), or binwalk (any binary). Use stegcracker in batch mode with multiple wordlists, chained from common passwords to context-specific dictionaries. For CTF automation, combine zsteg output parsing with automatic base64/hex decoding attempts on extracted strings.

## Reporting and Documentation

Steganography findings should document the carrier file (type, size, hash), the detection method used (tool name and version, specific flags), the extraction parameters (passphrase if cracked, embedding method identified), and the extracted payload (type, size, content hash). Include statistical evidence of embedding such as chi-square test results or entropy measurements. For forensic reports, maintain chain of custody for the carrier file and preserve the original unmodified file alongside the extracted evidence.

## Legal and Ethical Considerations

Steganography detection and extraction on systems you own or are authorized to test is permissible. Analyzing files obtained from compromised systems during incident response is standard forensic practice. However, using steganographic techniques to conceal data exfiltration from systems you do not own is illegal. When testing organizational defenses, ensure that embedding test data does not violate data handling policies or trigger false positive security incidents.

## Integration with Other Tools

Steganographic analysis connects to several adjacent skills. Extracted payloads that contain encrypted archives feed into the crypto-attacks skill for password cracking and analysis. Hidden executables or scripts found in carrier images connect to binary-reverse for malware analysis and digital-forensics for incident investigation. Metadata findings from exiftool complement OSINT analysis when carrier images contain GPS coordinates or device fingerprints. Use container-security techniques to analyze steganographic tools found in Docker images or CI/CD pipelines.

## Case Studies and Examples

- **Malware delivery via image steganography**: The Stegoloader malware family used PNG images hosted on compromised websites to carry encrypted configuration data. The malware downloaded the image, extracted the LSB-encoded payload, and decrypted it to obtain C2 server addresses. Detection required statistical steganalysis of network-cached images.
- **CTF challenge - PNG LSB flag**: A CTF challenge provided a PNG file that appeared normal. Running `zsteg -a` revealed a base64-encoded string in the LSB of the blue color channel. Decoding the base64 produced the flag, which was split across the first 1024 pixels.
- **Data exfiltration via EXIF metadata**: An insider threat investigation revealed that an employee was embedding proprietary data in the EXIF comment fields of product photos uploaded to a public-facing CMS. The data was invisible to web visitors but readable by anyone who downloaded the images and ran exiftool.

## Detection and Evasion

Defenders detect steganography through statistical anomaly detection (chi-square tests on LSB distributions), file size monitoring (carrier files with hidden data are often larger than expected for their resolution), entropy analysis (regions of unusually high entropy in image data), and network traffic analysis (unusually large image uploads or frequent image transfers to unexpected destinations). Attackers evade detection by using JPEG-domain embedding (steghide) which preserves file size, adding noise to reduce statistical signatures, and distributing hidden data across multiple carrier files. For testing, use steghide with its built-in statistical correction to produce carriers that resist basic chi-square detection.

## Advanced Techniques

Beyond core LSB and DCT embedding, advanced steganography includes: adaptive embedding that avoids smooth image regions where modifications are more detectable, matrix embedding using Hamming codes to minimize the number of modified bits, palette-based hiding in indexed-color images (GIF/PNG-8) by reordering or duplicating palette entries, and spread-spectrum embedding that distributes hidden data across the frequency domain for robustness against compression and resizing. For audio carriers, echo hiding encodes data in the parameters of artificially introduced echoes. In video, motion vector steganography modifies inter-frame motion vectors to carry hidden data.

## Tool Comparison Matrix

| Tool | Best For | Speed | Coverage | Skill Level |
|------|----------|-------|----------|-------------|
| **steghide** | JPEG/BMP/WAV embedding and extraction | Fast | JPEG/BMP/WAV | Beginner |
| **zsteg** | PNG/BMP LSB detection and extraction | Fast | PNG/BMP | Beginner |
| **binwalk** | Embedded file signatures in any binary | Moderate | Universal | Beginner |
| **foremost** | File carving from disk images | Fast | Universal | Beginner |
| **exiftool** | Metadata analysis for all file types | Fast | Universal | Beginner |
| **stegcracker** | Steghide passphrase recovery | Slow | Steghide-protected | Intermediate |

## Performance and Remediation

Stegcracker performance depends on wordlist size and the complexity of the passphrase. Using targeted wordlists (SecLists steganography-specific lists) rather than rockyou.txt dramatically improves crack time. For PNG LSB analysis, zsteg processes most images in under a second, but scanning all bit planes and channels with `-a` takes longer on large files. Binwalk signature scanning scales linearly with file size. For defensive remediation: implement file upload validation that strips metadata, enforce maximum file size limits for image uploads, deploy statistical steganalysis tools on file sharing servers, and monitor for steganographic tool installations on endpoints.

## Hacker Laws

1. **What You See Is Not What There Is** -- The human visual system discards enormous amounts of data. A 1920x1080 PNG image contains over 6 million bytes of pixel data; modifying 0.4% of it (the LSB) carries 750 KB of hidden data with zero perceptible difference. Trust tools, not eyes.

2. **Know Your Format** -- Every file format has corners where data can hide: JPEG has DCT coefficients and comment segments, PNG has ancillary chunks and filter bytes, BMP has palette padding, WAV has unused channel bits. Understanding the format specification is prerequisite to finding hidden data.

3. **Layers of Concealment** -- Sophisticated steganography stacks multiple layers: data is encrypted, then encoded (base64/hex), then embedded (LSB/DCT), then the carrier file is renamed. Each layer must be peeled in reverse order. Never assume extraction reveals the final answer.

---

## Learning Resources

  **Supplementary files for this skill**: payloads.md, test-cases.md
  **Related skills**: skills/digital-forensics/SKILL.md, skills/binary-reverse/SKILL.md, skills/crypto-attacks/SKILL.md
  **External resources**:
  - **Workspace internal materials**: `guides/steganography-techniques-detection-guide.md` -- Detection methodology and extraction workflow for image steganography
  - **Workspace internal materials**: `guides/steghide-stegcracker-practical-guide.md` -- Practical embedding, extraction, and password recovery with steghide and stegcracker
  - **Workspace internal materials**: `guides/ctf-steganography-challenge-guide.md` -- Systematic approach to solving CTF steganography challenges
  - **Steghide Manual**: https://steghide.sourceforge.net/documentation.php -- Official steghide documentation
  - **zsteg GitHub**: https://github.com/zed-0xff/zsteg -- PNG/BMP steganography detection tool
  - **HackTricks - Steganography**: https://book.hacktricks.xyz/crypto-and-stego/steganography -- Steganography quick reference
  - **Steganography Analysis and Research Center**: https://www.sarc-wv.com/ -- Academic steganography research and tools
