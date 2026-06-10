# Steganography Techniques and Detection Guide

## Introduction

Steganography encompasses a wide range of data hiding techniques that exploit the structure of digital media files to conceal information. This guide covers the primary embedding methods used in modern steganography, the statistical detection techniques that expose them, and the extraction workflow for recovering hidden data. Understanding both the embedding and detection sides is essential for offensive testing (validating that covert channels bypass detection) and defensive forensics (identifying hidden data in seized files).

The guide focuses on image-based steganography (JPEG, PNG, BMP) as the most common carrier format, with coverage of audio and document carriers where techniques differ significantly.

---

## 1. Embedding Techniques by Carrier Format

### JPEG Steganography (DCT Domain)

JPEG files use lossy compression based on the Discrete Cosine Transform (DCT). Steganographic tools like steghide operate in the frequency domain by modifying DCT coefficients rather than pixel values directly. This approach preserves file size and produces images that are visually identical to the original.

**How steghide embeds data**: Steghide uses a graph-theoretic approach to select DCT coefficients for modification. It identifies coefficients that can be changed with minimal impact on image quality and embeds data by slightly adjusting their values. The embedding process includes error correction coding to ensure data integrity.

```bash
# Embed data with steghide using JPEG carrier
steghide embed -cf photo.jpg -ef secret.txt -p "passphrase"

# The resulting file is the same size and visually identical
# Data is hidden in DCT coefficients, not pixel values
```

**Detection challenges**: JPEG steganography is harder to detect than spatial-domain methods because the modifications are distributed across frequency coefficients. Statistical detection requires comparing the coefficient histogram against expected distributions for natural images.

### PNG/BMP LSB Steganography (Spatial Domain)

PNG and BMP files use lossless compression (PNG) or no compression (BMP), making them ideal for Least Significant Bit (LSB) embedding. The LSB of each pixel's color channel is modified to carry hidden data without perceptible visual change.

**LSB encoding pattern**: For a 24-bit RGB image, each pixel has three color channels (red, green, blue), each with 8 bits. Modifying only the least significant bit of each channel changes the pixel value by at most 1 out of 256, which is invisible to the human eye.

```python
# LSB embedding demonstration
def embed_lsb(pixel_value, data_bit):
    """Replace the LSB of a pixel value with a data bit."""
    return (pixel_value & 0xFE) | data_bit

def extract_lsb(pixel_value):
    """Extract the LSB from a pixel value."""
    return pixel_value & 0x01

# For a 1000x1000 RGB image:
# Total pixels: 1,000,000
# Available LSBs: 1,000,000 * 3 = 3,000,000 bits = 375 KB
# This is enough to hide a short document or small image
```

**Detection advantage**: LSB embedding in spatial domain is more easily detected through statistical analysis. The distribution of even and odd pixel values in a natural image follows a specific pattern that is disrupted by LSB embedding.

### Audio Steganography (WAV)

WAV audio files are uncompressed PCM data, making them suitable for LSB embedding similar to BMP images. Each audio sample's least significant bit can carry hidden data. Steghide supports WAV carriers using the same interface as image files.

### Document Steganography (PDF)

PDF files support multiple hiding mechanisms: invisible text layers, metadata fields with hidden content, JavaScript-based triggers, and appended data after the PDF EOF marker. Detection requires parsing the PDF structure and examining each object.

---

## 2. Statistical Detection Methodology

### Chi-Square Test for LSB Detection

The chi-square test compares the observed distribution of even and odd pixel values against the expected distribution for a natural image. In an unmodified image, even and odd values are roughly balanced. After LSB embedding, the distribution shifts depending on the embedded data.

```python
from PIL import Image
import math

def chi_square_detect(image_path):
    """Run chi-square steganalysis on an image."""
    img = Image.open(image_path).convert('RGB')
    pixels = list(img.getdata())

    even = odd = 0
    for pixel in pixels:
        for channel in pixel:
            if channel % 2 == 0:
                even += 1
            else:
                odd += 1

    total = even + odd
    expected = total / 2
    chi_sq = ((even - expected) ** 2 / expected +
              (odd - expected) ** 2 / expected)

    # High chi-square value indicates possible embedding
    return {
        'chi_square': chi_sq,
        'even_pct': even / total * 100,
        'odd_pct': odd / total * 100,
        'suspicious': chi_sq < 3.84  # Below threshold = too uniform = suspicious
    }
```

A natural image typically has a chi-square value well above 3.84 (the 95% confidence threshold for 1 degree of freedom). Values significantly below this threshold suggest the LSB distribution has been artificially smoothed by embedding.

### Sample Pair Analysis

Sample pair analysis examines the relationship between adjacent pixel values. In natural images, pairs of adjacent pixels tend to have similar values. LSB embedding disrupts this relationship by creating more pairs where the values differ by exactly 1.

### Visual Bit Plane Inspection

Extracting individual bit planes (especially the LSB plane) and examining them visually can reveal patterns. Natural images produce structured patterns in higher bit planes but should show random noise in the LSB plane. However, if the LSB plane shows unexpected structure (like text or repeated patterns), it may indicate non-standard embedding.

```bash
# Use zsteg to quickly check all bit planes of a PNG
zsteg -a suspicious.png
# zsteg reports data found in each channel/bit combination
```

---

## 3. Extraction Workflow

The extraction workflow follows a systematic approach that avoids missing hidden data by trying all applicable techniques:

**Step 1: Identify the true carrier format** using `file` and magic byte inspection. Do not trust file extensions.

**Step 2: Extract metadata** with exiftool to check comment fields, GPS data, and software tags that may contain hidden data or indicate the steganography tool used.

**Step 3: Run format-appropriate detection**:
- JPEG/BMP/WAV: `steghide info` to check for steghide embedding
- PNG/BMP: `zsteg -a` to scan all LSB channels
- Any binary: `binwalk` to scan for embedded file signatures

**Step 4: Check for appended data** after the carrier file's EOF marker. Use manual inspection with `xxd` or Python scripts to locate the declared end of the carrier and examine anything beyond it.

**Step 5: If passphrase-protected**, attempt common passphrases first (empty string, "password", theme-related words), then escalate to stegcracker with standard wordlists.

**Step 6: Decode the extracted payload**. Common encodings include base64, hex, ROT13, and compressed archives. Always run `file` on extracted data to identify its type before attempting to decode.

---

## 4. Anti-Detection Techniques

For offensive testing, understanding how to evade steganalysis is as important as understanding the embedding methods:

- **JPEG domain embedding** (steghide) is inherently harder to detect than spatial LSB because it operates on frequency coefficients rather than pixels
- **Embedding rate reduction**: Embedding less data per pixel reduces statistical anomalies. A 10% embedding rate in a 1-megapixel image still provides 37 KB of capacity
- **Edge-adaptive embedding**: Embedding data only in high-frequency regions (edges, textures) of an image where modifications are less statistically detectable
- **Encryption before embedding**: Encrypting the payload before embedding ensures that extracted data appears random, making it harder to confirm successful extraction without the key

---

## References

- **Steghide Documentation**: https://steghide.sourceforge.net/documentation.php -- Official steghide manual covering embedding, extraction, and file format support
- **zsteg Repository**: https://github.com/zed-0xff/zsteg -- PNG/BMP steganography detection tool with multi-channel LSB scanning
- **Westfeld, A. & Pfitzmann, A. (2000)**: "Attacks on Steganographic Systems" -- Foundational paper on chi-square steganalysis for LSB detection
- **Fridrich, J. (2009)**: "Steganography in Digital Media: Principles, Algorithms, and Applications" -- Comprehensive academic reference on steganography theory
- **HackTricks Steganography**: https://book.hacktricks.xyz/crypto-and-stego/steganography -- Practical steganography techniques and tool reference
