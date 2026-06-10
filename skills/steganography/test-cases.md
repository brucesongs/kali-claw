# Steganography Test Cases

> This file is a companion to `SKILL.md`, containing structured test cases grouped by technique with severity ratings and verification criteria.

---

## Statistics

| Category | Count | Severity Range |
|------|------|-----------|
| A. Format Identification | 1 | MEDIUM |
| B. Steghide Operations | 1 | HIGH |
| C. PNG LSB Analysis | 1 | HIGH |
| D. Binwalk Extraction | 1 | HIGH |
| E. Password Recovery | 1 | HIGH |
| F. Metadata Analysis | 1 | MEDIUM |
| **Total** | **6** | **MEDIUM - HIGH** |

---

## A. Format Identification

### TC-STEG-001: Carrier Format Identification and Anti-Analysis Detection

| Field | Value |
|------|-----|
| **ID** | TC-STEG-001 |
| **Name** | Carrier Format Identification and Anti-Analysis Detection |
| **Severity** | MEDIUM |
| **Prerequisites** | Sample carrier files in multiple formats (JPEG, PNG, BMP, WAV, PDF); file command, xxd, python3 with python-magic installed |
| **Test Steps** | 1. Run `file suspicious.jpg` to determine true file type<br>2. Inspect magic bytes with `xxd suspicious.jpg \| head -5`<br>3. Verify extension matches actual format (flag mismatches as anti-analysis technique)<br>4. For PNG files: verify `89 50 4E 47` magic bytes<br>5. For JPEG files: verify `FF D8 FF` magic bytes and locate `FF D9` EOI marker<br>6. Check file size against expected size for the format and resolution<br>7. Run `identify suspicious.jpg` (ImageMagick) for dimension metadata<br>8. Calculate entropy: high entropy (>7.9 bits/byte) may indicate encrypted hidden data |
| **Expected Results (vulnerability)** | File extension does not match actual format; file size significantly exceeds expected size for dimensions; entropy analysis reveals suspiciously high values in structured regions; data found after declared EOF marker |
| **Expected Results (secure)** | File extension matches actual format; file size is within normal range for the format and resolution; entropy is consistent with expected image data distribution; no data after declared EOF marker |
| **Remediation** | Implement file upload validation that checks magic bytes rather than extensions; enforce maximum file size limits relative to image dimensions; strip metadata and verify file structure on upload |

---

## B. Steghide Operations

### TC-STEG-002: Steghide Embedding and Extraction in JPEG/BMP

| Field | Value |
|------|-----|
| **ID** | TC-STEG-002 |
| **Name** | Steghide Embedding and Extraction in JPEG/BMP |
| **Severity** | HIGH |
| **Prerequisites** | steghide installed; original JPEG/BMP carrier file; payload file to embed; test passphrase |
| **Test Steps** | 1. Verify carrier file integrity: `steghide info carrier.jpg` (should report no embedding)<br>2. Embed test payload: `steghide embed -cf carrier.jpg -ef payload.txt -p "testpass"`<br>3. Verify carrier still opens normally in image viewer<br>4. Check embedding info: `steghide info carrier_stego.jpg` (should report embedded file)<br>5. Extract with correct passphrase: `steghide extract -sf carrier_stego.jpg -p "testpass"`<br>6. Compare extracted file with original payload: `diff payload.txt extracted_payload.txt`<br>7. Verify extraction fails with wrong passphrase: `steghide extract -sf carrier_stego.jpg -p "wrongpass"`<br>8. Test empty passphrase: `steghide embed -cf carrier2.jpg -ef payload.txt -p ""` then extract with `-p ""`<br>9. Test WAV carrier: `steghide embed -cf carrier.wav -ef payload.txt -p "testpass"` and extract |
| **Expected Results (vulnerability)** | Steghide embedding is undetectable by visual inspection; extraction with correct passphrase recovers identical payload; wrong passphrase produces error or corrupted data; empty passphrase extraction succeeds when no passphrase was set |
| **Expected Results (secure)** | Steganographic tools are not installed on production systems; file integrity monitoring detects modified carrier files; upload validation strips steganographic markers |
| **Remediation** | Install and configure file integrity monitoring (AIDE, Tripwire) to detect modified image files; restrict steganographic tool installation on production endpoints; implement statistical steganalysis on file sharing servers |

---

## C. PNG LSB Analysis

### TC-STEG-003: PNG LSB Steganography Detection with zsteg

| Field | Value |
|------|-----|
| **ID** | TC-STEG-003 |
| **Name** | PNG LSB Steganography Detection with zsteg |
| **Severity** | HIGH |
| **Prerequisites** | zsteg installed; PNG files with known LSB-embedded data; clean PNG files for comparison; Python3 with PIL/Pillow for test image generation |
| **Test Steps** | 1. Generate test image with LSB-embedded data (Python script below)<br>2. Run `zsteg -a suspicious.png` to scan all channels and bit planes<br>3. Verify zsteg identifies the embedded data location and channel<br>4. Extract specific channel data: `zsteg -b 1,rgb,lsb,xy suspicious.png`<br>5. Try zlib decompression: `zsteg -a --try-zlib suspicious.png`<br>6. Run `zsteg -a clean.png` on a clean reference image and compare output<br>7. Extract and decode found data: `zsteg -o extracted.bin suspicious.png`<br>8. Validate extracted data matches the original embedded payload |
| **Expected Results (vulnerability)** | zsteg identifies hidden data in LSB planes; extracted data matches embedded payload; clean images show no false positives; zlib-compressed payloads are detected and decompressed |
| **Expected Results (secure)** | No hidden data detected in LSB planes; statistical analysis shows expected bit distribution; all extracted data is consistent with normal image content |
| **Remediation** | Implement LSB randomization during image processing (re-save images); deploy statistical steganalysis tools to scan uploaded PNG files; use JPEG format instead of PNG for user uploads (JPEG's lossy compression disrupts LSB encoding) |

---

## D. Binwalk Extraction

### TC-STEG-004: Embedded File Extraction with binwalk

| Field | Value |
|------|-----|
| **ID** | TC-STEG-004 |
| **Name** | Embedded File Extraction with binwalk |
| **Severity** | HIGH |
| **Prerequisites** | binwalk installed; composite file with embedded archives (ZIP, PNG, etc.); firmware image or multi-part carrier file |
| **Test Steps** | 1. Create test composite file: `cat carrier.png secret.zip > composite.bin`<br>2. Run signature scan: `binwalk composite.bin`<br>3. Verify binwalk identifies both the PNG header and ZIP signature with correct offsets<br>4. Extract all embedded files: `binwalk -Me composite.bin`<br>5. Verify extracted files: check that the PNG and ZIP were recovered intact<br>6. Run entropy analysis: `binwalk -E composite.bin` to visualize data regions<br>7. Test manual extraction at known offset: `dd if=composite.bin bs=1 skip=OFFSET of=extracted.zip`<br>8. Test against real firmware: `binwalk -Me firmware.bin` and verify component extraction<br>9. Verify recursive extraction works on nested archives |
| **Expected Results (vulnerability)** | binwalk identifies all embedded file signatures at correct offsets; extracted files are complete and valid; entropy analysis shows distinct regions for different embedded components; nested archives are recursively extracted |
| **Expected Results (secure)** | No unexpected file signatures found in carrier files; file upload validation rejects composite files; endpoint monitoring detects binwalk execution on production systems |
| **Remediation** | Implement file upload validation that scans for embedded signatures; reject files that contain multiple format headers; strip data after declared EOF markers during file processing |

---

## E. Password Recovery

### TC-STEG-005: Steghide Password Recovery with stegcracker

| Field | Value |
|------|-----|
| **ID** | TC-STEG-005 |
| **Name** | Steghide Password Recovery with stegcracker |
| **Severity** | HIGH |
| **Prerequisites** | stegcracker and steghide installed; JPEG file with steghide-embedded data protected by a known-weak passphrase; wordlist files (rockyou.txt, SecLists) |
| **Test Steps** | 1. Create test file: `steghide embed -cf carrier.jpg -ef secret.txt -p "password123"`<br>2. Verify embedding: `steghide info carrier_stego.jpg`<br>3. Run stegcracker: `stegcracker carrier_stego.jpg /usr/share/wordlists/rockyou.txt`<br>4. Verify stegcracker recovers the passphrase "password123"<br>5. Verify extracted data matches original secret.txt<br>6. Test with uncommon passphrase to measure failure time<br>7. Test with custom wordlist containing the passphrase to measure success time<br>8. Compare stegcracker performance against manual steghide brute-force loop |
| **Expected Results (vulnerability)** | stegcracker recovers weak passphrases from standard wordlists; extracted data is complete and matches original; weak passwords (dictionary words, common patterns) are recovered within minutes; custom wordlists improve recovery time for context-specific passphrases |
| **Expected Results (secure)** | Steghide-protected files use strong, non-dictionary passphrases; passphrase length exceeds 16 characters with mixed character types; stegcracker fails to recover passphrase within reasonable time |
| **Remediation** | Use strong passphrases for steganographic protection (16+ characters, mixed case, digits, symbols); avoid dictionary words and common patterns; consider additional encryption of payload before embedding |

---

## F. Metadata Analysis

### TC-STEG-006: Metadata Analysis and Hidden Data Detection with exiftool

| Field | Value |
|------|-----|
| **ID** | TC-STEG-006 |
| **Name** | Metadata Analysis and Hidden Data Detection with exiftool |
| **Severity** | MEDIUM |
| **Prerequisites** | exiftool installed; sample JPEG/PNG/TIFF files with metadata; files with hidden data in EXIF comment fields; GPS-tagged images |
| **Test Steps** | 1. Run comprehensive metadata extraction: `exiftool -a -G1 test.jpg`<br>2. Identify all metadata groups present: EXIF, IPTC, XMP, GPS, MakerNotes<br>3. Check comment fields for hidden data: `exiftool -Comment -UserComment test.jpg`<br>4. Search for encoded payloads: pipe comment output through base64 decode and hex decode<br>5. Extract GPS coordinates: `exiftool -GPS:All test.jpg` and verify against expected location<br>6. Check software and tool tags for steganography tool signatures: `exiftool -Software -CreatorTool test.jpg`<br>7. Compare metadata between clean reference and suspect file: `diff <(exiftool clean.jpg) <(exiftool suspect.jpg)`<br>8. Test metadata stripping: `exiftool -all= test.jpg -o stripped.jpg` and verify all tags removed<br>9. Verify stripped file still renders correctly |
| **Expected Results (vulnerability)** | Comment fields contain hidden data (base64, hex, or plaintext); GPS coordinates reveal unexpected location; software tags indicate use of steganography tools; metadata comparison reveals fields present only in suspect file |
| **Expected Results (secure)** | Comment fields contain no hidden data; metadata is stripped during upload processing; GPS data is removed before public distribution; no steganography tool signatures in software tags |
| **Remediation** | Automatically strip all metadata from uploaded files using `exiftool -all=`; implement metadata stripping in image processing pipelines; remove GPS data before publishing images online; configure web servers to strip metadata on upload |

---

## G. Audio Steganography

### TC-STEG-007: Audio Steganography Detection and Extraction with Steghide

| Field | Value |
|------|-----|
| **ID** | TC-STEG-007 |
| **Name** | Audio Steganography Detection and Extraction with Steghide |
| **Category** | G. Audio Steganography |
| **Severity** | HIGH |
| **Prerequisites** | steghide installed; WAV carrier audio files; payload data to embed; audio playback tools for quality verification |
| **Objective** | Verify that steganographic data can be embedded into WAV audio files and extracted without detection, and assess audio quality impact |
| **Test Steps** | 1. Embed payload into WAV carrier: `steghide embed -cf carrier.wav -ef secret.txt -p "audiopass"`<br>2. Verify the WAV file still plays correctly in an audio player<br>3. Check file size difference: `ls -la carrier.wav carrier_stego.wav`<br>4. Extract with correct passphrase: `steghide extract -sf carrier_stego.wav -p "audiopass"`<br>5. Verify extracted data matches original: `diff secret.txt extracted_secret.txt`<br>6. Attempt extraction with wrong passphrase and verify failure<br>7. Compare spectrogram of original vs stego file using audacity or sox for visual artifacts |
| **Expected Results** | Embedded audio file plays without audible artifacts; file size difference is minimal; extraction with correct passphrase recovers identical payload; wrong passphrase produces error; spectrogram comparison shows no obvious anomalies in stego file |
| **Remediation** | Implement audio file integrity checks on file sharing platforms; deploy statistical steganalysis tools for audio files; restrict audio file uploads in sensitive environments |

### TC-STEG-008: Spectrogram-Based Hidden Message Detection

| Field | Value |
|------|-----|
| **ID** | TC-STEG-008 |
| **Name** | Spectrogram-Based Hidden Message Detection |
| **Category** | G. Audio Steganography |
| **Severity** | MEDIUM |
| **Prerequisites** | sox installed; sample audio files with spectrogram-encoded messages; ImageMagick for spectrogram image analysis |
| **Objective** | Verify the ability to detect and extract messages hidden within audio spectrograms, a technique that encodes visual data into the frequency spectrum of audio files |
| **Test Steps** | 1. Generate spectrogram of suspect audio: `sox suspicious.wav -n spectrogram -o spectrogram.png`<br>2. View the spectrogram image: visually inspect for text, URLs, or patterns embedded in the frequency domain<br>3. Generate spectrogram of clean reference audio for comparison<br>4. Compare spectrograms for anomalies: unusual horizontal bands or text patterns at specific frequencies<br>5. If hidden content is visual, use OCR tools to extract: `tesseract spectrogram.png output`<br>6. Test batch spectrogram generation for multiple files |
| **Expected Results** | Spectrogram reveals hidden visual content (text, URLs, images) embedded in the audio frequency spectrum; hidden content is not audible when playing the audio; spectrogram comparison between clean and suspect files shows clear anomalies |
| **Remediation** | Implement automated spectrogram analysis on audio file sharing platforms; restrict audio file uploads in environments handling sensitive data; use frequency analysis tools to detect anomalous audio patterns |
| **Pass Criteria** | Hidden visual content is clearly visible in the spectrogram; extracted content matches the known hidden message; clean audio files show no false positives in spectrogram analysis |
