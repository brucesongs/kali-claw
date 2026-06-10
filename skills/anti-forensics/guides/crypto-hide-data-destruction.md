# Cryptographic Hiding and Data Destruction Guide

## Introduction

Cryptographic hiding and steganographic techniques represent the most sophisticated layer of anti-forensic operations. While secure deletion (shred, wipe) removes data after the fact and log tampering covers operational traces, cryptographic hiding prevents data from being recognizable in the first place. Encrypted volumes make stored data unreadable without the key, and steganography makes data invisible by embedding it within innocent-looking carrier files.

This guide covers encrypted volume management with tcplay (TrueCrypt/VeraCrypt compatible), steganographic data hiding with steghide, the concept of deniable encryption through hidden volumes, and using bulk_extractor as a validation tool to test whether anti-forensic measures are effective against real forensic examination.

---

## 1. Encrypted Volumes with tcplay

### What is tcplay

tcplay is a free, open-source implementation of the TrueCrypt and VeraCrypt disk encryption specification. It creates and manages encrypted container files that appear as random data to anyone examining the disk. Without the correct passphrase or keyfile, the contents are cryptographically inaccessible. tcplay supports AES, Serpent, and Twofish ciphers in XTS mode, as well as cascaded cipher combinations for maximum security.

### Creating Encrypted Volumes

```bash
# Step 1: Create a container file (100MB in this example)
dd if=/dev/zero of=encrypted.vol bs=1M count=100

# Step 2: Attach to a loop device
losetup /dev/loop0 encrypted.vol

# Step 3: Initialize encrypted volume with tcplay
tcplay -c -d /dev/loop0
# Follow prompts: enter and confirm passphrase

# Step 4: Map the encrypted volume for access
tcplay -m secure_vol -d /dev/loop0
# Enter passphrase when prompted

# Step 5: Create a filesystem (first time only)
mkfs.ext4 /dev/mapper/secure_vol

# Step 6: Mount and use
mount /dev/mapper/secure_vol /mnt/secure/
cp sensitive_data.txt /mnt/secure/
```

### Detaching Encrypted Volumes

Proper teardown is critical for anti-forensic hygiene. Leaving an encrypted volume mapped exposes the decrypted contents to forensic tools that can access the device mapper.

```bash
# Step 1: Unmount the filesystem
umount /mnt/secure/

# Step 2: Unmap the encrypted volume (locks the container)
tcplay -u secure_vol

# Step 3: Detach the loop device
losetup -d /dev/loop0

# Step 4: Verify no mapped devices remain
dmsetup ls | grep secure
losetup -a | grep encrypted.vol
```

### Keyfile-Based Authentication

Instead of a memorized passphrase, tcplay supports keyfile-based authentication where the encryption key is derived from a file. This allows storing the keyfile on a separate device (USB token, smartphone) that can be physically separated from the encrypted container.

```bash
# Generate a random keyfile
dd if=/dev/urandom of=keyfile.bin bs=512 count=4

# Create volume with keyfile
tcplay -c -d /dev/loop0 -k keyfile.bin

# Map volume with keyfile
tcplay -m secure_vol -d /dev/loop0 -k keyfile.bin

# Destroy the keyfile after unmounting (renders volume unrecoverable)
shred -vfz -n 3 keyfile.bin
rm -f keyfile.bin
```

### Forensic Detection of Encrypted Volumes

Forensic examiners look for several indicators of encrypted volume activity:

1. **High-entropy regions**: Encrypted data has near-maximum entropy (~7.99 out of 8.0 bits per byte). Tools like `ent` or `binwalk` can identify high-entropy regions in unallocated space that suggest encrypted containers.

2. **TrueCrypt/VeraCrypt headers**: The volume header contains a magic string ("TRUE") that identifies it as a TrueCrypt-type volume. tcplay creates headers compatible with this format, which binwalk and bulk_extractor can detect.

3. **Loop device history**: Linux systems log loop device associations. Even after detaching, `/dev` entries and dmesg output may reference the encrypted container file path.

4. **Device mapper remnants**: The mapped device name persists in udev rules and device mapper metadata until explicitly cleared.

```bash
# Test detection resistance: scan for TrueCrypt headers
binwalk encrypted.vol | grep -i "truecrypt\|encrypt"

# Test entropy
dd if=encrypted.vol bs=1M count=5 | ent
# Output: entropy should be ~7.999999 (indistinguishable from random data)

# Check for header signatures
strings encrypted.vol | head -20
# TrueCrypt header magic is located at byte offset 65536
dd if=encrypted.vol bs=1 skip=65536 count=4 2>/dev/null | xxd
```

---

## 2. Steganographic Data Hiding with steghide

### How Steganography Complements Encryption

While encryption makes data unreadable, it does not hide the fact that data exists. An encrypted volume file is obviously encrypted -- its presence is suspicious. Steganography solves this by hiding data within ordinary-looking media files. A vacation photo with embedded data looks like a normal vacation photo to anyone examining the filesystem.

### Embedding Data with steghide

```bash
# Check carrier file capacity before embedding
steghide info vacation_photo.jpg
# Output shows available capacity (e.g., "capacity: 4.8 KB")

# Embed with passphrase protection
steghide embed -cf vacation_photo.jpg -ef exfiltration_data.txt -p "engagement_key"

# Embed without passphrase (useful for automated extraction pipelines)
steghide embed -cf vacation_photo.jpg -ef small_payload.txt -p ""

# Embed into BMP for higher capacity (lossless carrier)
steghide embed -cf image.bmp -ef large_payload.bin -p "key123"

# Embed into WAV audio carrier
steghide embed -cf song.wav -ef data.txt -p "key123"

# Specify output file (preserves original carrier)
steghide embed -cf original.jpg -ef secret.txt -sf stego_output.jpg -p "key"
```

### Steganographic Capacity and Carrier Selection

| Carrier Format | Typical Capacity | Detection Risk | Notes |
|---------------|-----------------|---------------|-------|
| JPEG | 5-15% of file size | Medium | DCT modification; statistical tests can detect anomalies |
| BMP | ~12.5% of file size | Low-Medium | Pixel value modification; lossless carrier |
| WAV | ~12.5% of file size | Low | Audio sample modification; inaudible changes |

For anti-forensic operations, choose carrier files that are contextually appropriate for the target environment. A vacation photo on a personal workstation is unremarkable. A BMP file on a server that has no business storing images is suspicious regardless of steganographic quality.

### Extracting Hidden Data

```bash
# Extract with known passphrase
steghide extract -sf stego_image.jpg -p "engagement_key"

# Extract with empty passphrase
steghide extract -sf stego_image.jpg -p ""

# Extract to specific output file
steghide extract -sf stego_image.jpg -p "key" -f /tmp/recovered_data.bin
```

### Steganographic Detection Testing

Before relying on steganographic hiding in an engagement, test whether the target's forensic capabilities can detect the embedding:

```bash
# Statistical analysis with stegdetect
stegdetect stego_image.jpg

# Entropy analysis of LSB (least significant bits)
# High LSB entropy indicates potential steganographic embedding
python3 -c "
from PIL import Image
import math, collections
img = Image.open('stego_image.jpg')
pixels = list(img.getdata())
lsbs = [p & 1 for row in pixels for p in (row[:3] if isinstance(row, tuple) else (row,))]
freq = collections.Counter(lsbs)
total = len(lsbs)
entropy = -sum((c/total) * math.log2(c/total) for c in freq.values())
print(f'LSB entropy: {entropy:.4f} (random = 1.0, clean image < 0.95)')
"

# Visual attack: extract LSB plane for visual inspection
python3 -c "
from PIL import Image
img = Image.open('stego_image.jpg')
pixels = list(img.getdata())
w, h = img.size
lsb_img = Image.new('1', (w, h))
lsb_data = []
for p in pixels:
    if isinstance(p, tuple):
        lsb_data.append((p[0] & 1) * 255)
    else:
        lsb_data.append((p & 1) * 255)
lsb_img.putdata([0 if b > 127 else 255 for b in lsb_data])
lsb_img.save('lsb_visual.png')
print('LSB visual analysis saved to lsb_visual.png')
# Structured patterns in the LSB plane indicate steganographic embedding
"
```

---

## 3. Deniable Encryption (Hidden Volumes)

### Concept

Deniable encryption provides plausible deniability by allowing the existence of a hidden volume within an outer encrypted volume. The user can reveal the outer volume passphrase (containing innocuous data) while keeping the hidden volume passphrase secret. There is no cryptographic way to prove the hidden volume exists.

### Implementation with tcplay

```bash
# Step 1: Create outer volume
dd if=/dev/zero of=deniable.vol bs=1M count=200
losetup /dev/loop0 deniable.vol
tcplay -c -d /dev/loop0
tcplay -m outer -d /dev/loop0
mkfs.ext4 /dev/mapper/outer
mount /dev/mapper/outer /mnt/outer/

# Step 2: Fill outer volume with decoy data (important for realism)
cp -r /usr/share/doc/* /mnt/outer/
dd if=/dev/urandom of=/mnt/outer/random_padding.bin bs=1M count=80
# Leave ~30% free space for the hidden volume

umount /mnt/outer/
tcplay -u outer

# Step 3: Create hidden volume within the free space
tcplay -c -d /dev/loop0 --hidden --hidden-from-rc-pt 4096
# Set a DIFFERENT passphrase for the hidden volume

# Step 4: Map hidden volume for use
tcplay -m hidden -d /dev/loop0
# Enter the hidden volume passphrase
mkfs.ext4 /dev/mapper/hidden
mount /dev/mapper/hidden /mnt/hidden/

# Store sensitive data in hidden volume
cp truly_sensitive_data /mnt/hidden/
```

### Operational Security for Hidden Volumes

The outer volume must contain plausible, regularly-accessed data to be convincing. If the outer volume contains no meaningful files or has obviously fabricated content, an examiner may suspect the presence of a hidden volume. Best practice is to use the outer volume for actual non-sensitive encrypted storage (personal documents, backups) that you would genuinely have a reason to protect.

---

## 4. bulk_extractor for Anti-Forensic Validation

### Using bulk_extractor as a Testing Tool

bulk_extractor is primarily a forensic feature extraction tool, but in anti-forensic operations it serves as a validation tool. By running bulk_extractor against a post-cleanup disk image, you can verify whether your anti-forensic measures are effective. If bulk_extractor still extracts engagement-related artifacts (email addresses, URLs, IP addresses, tool strings), the cleanup was insufficient.

```bash
# Pre-cleanup baseline extraction
bulk_extractor -o /tmp/be_before target_image.dd

# Perform anti-forensic cleanup operations

# Post-cleanup extraction
bulk_extractor -o /tmp/be_after cleaned_image.dd

# Compare results
echo "=== Email addresses ==="
diff /tmp/be_before/email.txt /tmp/be_after/email.txt

echo "=== URLs ==="
diff /tmp/be_before/url.txt /tmp/be_after/url.txt

echo "=== TCP connections ==="
diff /tmp/be_before/tcp.txt /tmp/be_after/tcp.txt

echo "=== New features found after cleanup (should be minimal) ==="
diff /tmp/be_before/ /tmp/be_after/ | grep "^>" | head -20
```

### Interpreting Results

| Finding | Implication | Action Required |
|---------|-------------|-----------------|
| No features extracted | Cleanup effective | Document result |
| Features in unallocated space | Secure deletion incomplete | Re-wipe with shred, fill unallocated space |
| Features in slack space | Slack space not wiped | Use blkls to wipe slack, re-test |
| Features in swap/pagefile | Volatile data not cleaned | Wipe swap partition, disable pagefile |
| Encrypted container headers | Volume not properly detached | Verify loop/dm cleanup, consider headerless encryption |
| Steganographic tool strings | steghide binary artifacts remain | Clean tool binaries, check temp files |

---

## References

- **tcplay GitHub**: https://github.com/bwalex/tc-play -- tcplay source code and documentation for TrueCrypt/VeraCrypt compatible volume management
- **VeraCrypt Documentation**: https://www.veracrypt.fr/en/Documentation.html -- Comprehensive documentation on hidden volumes, plausible deniability, and cipher modes
- **steghide Manual**: `man steghide` or https://steghide.sourceforge.net/ -- Complete steghide documentation covering embedding, extraction, and supported carrier formats
- **bulk_extractor**: https://github.com/simsong/bulk_extractor -- Forensic feature extraction tool used for anti-forensic effectiveness validation
- **NIST SP 800-111**: https://csrc.nist.gov/publications/detail/sp/800-111/final -- Guide to storage encryption technologies for end-user devices
