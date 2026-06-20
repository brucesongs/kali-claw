# Physical Security Testing Playbook — End-to-End On-Site Engagement Workflow

> Deep-dive companion to `skills/physical-security-testing/SKILL.md`.
>
> Audience: operators who already know what a Proxmark3 and a lock pick do, and want a battle-tested playbook for taking a target facility from "we heard they have weak physical security" to "engagement closed with a defensible report and zero legal exposure" — without leaving an implant behind, getting arrested at the door, or shipping a half-destroyed facility to a client.

---

## 1. Why a Playbook, Not Just Commands

A defensible physical pentest requires more than tooling. The five failure modes are predictable:

1. **Legal exposure** — operator arrested because the engagement scope was misread or the authorization letter wasn't carried.
2. **Detection** — operator caught on camera, by a guard, or by an employee challenge; engagement aborts; client loses trust.
3. **Irreversible change** — broken glass, picked lock left open, dropped device discovered by facilities staff — any of these creates a forensic trail and operational exposure.
4. **Forgotten reversal** — drop box or hidden camera left behind after the engagement; on a client's network six months later; legally classified as an unauthorized device.
5. **Scope creep** — operator enters an area explicitly out of scope (HR office, third-party colocation cage, executive residence); engagement becomes a felony.

This playbook addresses all five. Follow it in order; do not skip the pre-flight.

---

## 2. Pre-Flight: Scope, Authorization, Hardware

Before any operational activity, answer these — in writing:

### 2.1 Legal scope

- **Who authorized this?** A pentest engagement authorizes the target organization's *physical facility*, not its employees' personal lives, not third-party colocation tenants, not executive residences. Confirm scope with the client and with internal legal.
- **What's the lawful basis?** In most jurisdictions, physical pentest is lawful only with explicit written authorization. The contract must identify the target addresses, dates, and prohibited areas.
- **What's the jurisdictional exposure?** Lock pick possession is criminal in California (Penal Code 466), Nevada, Japan, and parts of the UK without a locksmith credential. Audio recording has one-party vs two-party consent state law. Verify before traveling.
- **What's the deliverable?** Internal threat intel? Client report? Insurance compliance? Different deliverables need different verification depth.

### 2.2 Operator commitment

Document the operational rules and have every operator sign:

- Every operator carries the authorization letter on their person at all times.
- Every operator has the client's 24/7 contact saved in their phone.
- Every operator knows the abort criteria (guard draws → stop, produce authorization, call client).
- Every operator's photo ID matches the authorization letter.
- All evidence encrypted at rest (`gpg --symmetric --cipher-algo AES256`).
- All evidence destroyed at the contracted retention period.
- No operator works alone; minimum team of two.
- No operator works under the influence; no alcohol 12 hours before engagement.

### 2.3 Hardware provisioning

| Tier | Setup | Use When |
|------|-------|----------|
| **Tier 1 (highest OPSEC)** | Dedicated burner laptop + dedicated tools + cash-purchased equipment; no personal devices on engagement | High-stakes engagement; client is sophisticated; risk of equipment seizure |
| **Tier 2** | Consultancy-owned engagement kit; tools inventoried before and after each engagement | Standard client engagement |
| **Tier 3 (lowest OPSEC)** | Personal laptop + personal tools | AVOID — cross-contamination of personal data and engagement data; risk if equipment seized |

> Tier 3 is unacceptable for any paid engagement. Use Tier 2 for standard clients; Tier 1 for high-stakes (financial, defense, healthcare) work.

### 2.4 Tool inventory (before and after engagement)

```
Before engagement — log every tool's serial number:
[ ] Proxmark3 (serial #X)
[ ] ESP-RFID-Tool (serial #X)
[ ] USB Rubber Ducky (serial #X)
[ ] Bash Bunny (serial #X)
[ ] LAN Turtle (serial #X)
[ ] Packet Squirrel (serial #X)
[ ] Pi Zero W implants (count: N)
[ ] Lock pick set (count: N)
[ ] Bump keys (count: N)
[ ] Hidden cameras (count: N)
[ ] Cloned badges (count: 0 at start)

After engagement — verify every tool's serial number is back in inventory:
[ ] Same serial numbers returned
[ ] No "extra" devices (indicates a forgotten device on the engagement site)
[ ] No tools missing (indicates a forgotten device on the engagement site)
```

> If the after-engagement inventory doesn't match the before-engagement inventory, you have a forgotten device on the client site. This is a CRITICAL engagement failure — contact the client immediately and retrieve the device.

---

## 3. Phase 1 — Pre-Engagement Recon

Recon is the difference between a successful engagement and an aborted one. Walk the building (on public property) before any active operation.

### 3.1 Passive OSINT

```bash
# Satellite and Street View imagery
# - Google Maps satellite view: entrances, loading dock, parking
# - Street View historical imagery: track changes over time
# - Save screenshots with timestamps

# LinkedIn badge vendor OSINT
# Search for "<client>" employees; look at profile photos
# Many badges are partially visible in conference photos

# Job postings OSINT
# Search "<client>" + "security" + "experience with"
# Common patterns:
#   "Lenel OnGuard" → Lenel S2 (blue reader LED)
#   "HID Origo / iCLASS SE" → HID (white reader body)
#   "AMAG Symmetry" → AMAG (grey reader body)
#   "Software House C-CURE 9000" → Tyco/Johnson Controls
#   "Gallagher" → Gallagher (T-Series readers)

# County / city building permits
# Search "<client>" + "security install" or "camera install"
# Recent upgrades? New access control vendor?

# Conference videos / employee blogs
# Internal office tours sometimes leak reader vendors
```

### 3.2 Active walk-by recon

```
ALWAYS on public property — never enter without authorization.

Visit at multiple times of day:
- 7:30-9:00am: morning arrival
- 11:30-13:30: lunch
- 16:30-18:30: evening departure
- 22:00-24:00: after-hours (cleaning crew, HVAC, IT late shifts)

Log at each visit:
- Reader vendor (visual: HID blue/white, Symmetry grey, Lenel black)
- Badge design (color, vendor logo, employee photo visible?)
- Camera coverage (count, placement, vendor)
- Guard rotation (shift change times, patrol frequency)
- Employee tailgating behavior (count per 10-minute window)
- Smoking area (location, popular times)
- Loading dock (deliveries observed, vendor vans)

DO NOT:
- Photograph employee faces
- Photograph badge designs in detail
- Approach the building beyond public property
- Engage employees in conversation (you're a passive observer)
```

### 3.3 Recon pack output

Produce a recon pack (markdown) with:

1. Building layout sketch
2. Inferred badge vendor (with at least 2 evidence sources)
3. Camera coverage map
4. Guard cadence log
5. Recommended entry vector

See `payloads.md` §11.1 for the template.

---

## 4. Phase 2 — Entry Vector Selection

Score each entry vector against probability of success, time-to-entry, detectability, and reversibility. Pick the lowest-risk path.

### 4.1 Entry vector decision matrix

| Entry Vector | Probability (typical) | Time to Entry | Detectability | Reversibility | Use When |
|--------------|----------------------|---------------|---------------|---------------|----------|
| Tailgating (social) | HIGH (most orgs) | <1 min | LOW (if guard absent) | N/A — no artifact | Reception or loading dock traffic observed; guard cadence has gaps |
| Badge clone (HID Prox LF) | HIGH | <30 s | LOW (reader log shows valid tap) | Badge returns to owner | HID Prox deployed; source badge available |
| Badge clone (Mifare Classic HF) | HIGH | <5 min | LOW | Same as above | Mifare Classic deployed; source card available |
| Badge clone (HID iCLASS) | MEDIUM | 5-30 min | MEDIUM (cloning requires sniffing) | Reader log may show duplicate tap | iCLASS deployed; standard keys in use |
| Lock pick (commercial pin-tumbler) | HIGH | 10-60 s | LOW (no marks) | No artifact | Pin-tumbler locks; operator trained |
| Lock pick (high-security Medeco/Assa) | LOW | minutes-hours | MEDIUM (tool marks) | May leave forensic evidence | AVOID unless explicitly in scope |
| USB weapon (unattended workstation) | HIGH (if observed) | <10 s | HIGH (USB device log) | Exfil artifacts may persist | Unattended workstation; endpoint protection permissive |
| Drop-box deploy (LAN Turtle) | MEDIUM | 30 s | MEDIUM (network admins may notice) | Implant retrievable if undetected | Live network jack available; 802.1X not enforced |
| Crash bar / shove knife | MEDIUM (hardware-specific) | <10 s | LOW | No artifact | Specific hardware recon confirmed |

### 4.2 Selection rule

> Try the lowest-detectability, lowest-reversibility-risk vector first.

A successful badge clone leaves the badge holder unaware. A successful lock pick leaves no evidence. A successful tailgate leaves no artifact at all.

USB weapons and drop boxes are highest-impact but highest-detectability. Reserve them for after entry is already achieved — they're force multipliers, not entry vectors.

### 4.3 Fallback chain

Plan a fallback chain in advance:

```
Primary entry:    tailgating at loading dock (HVAC contractor pretext)
Fallback 1:       HID Prox clone (if source badge borrowed)
Fallback 2:       lock pick on side entrance (commercial pin-tumbler)
Abort criterion:  guard challenge beyond pretext script
```

If the primary entry fails, transition smoothly to fallback 1. If fallback 1 fails, transition to fallback 2. If all fail, abort gracefully via the nearest exit.

---

## 5. Phase 3 — Execution & Access

Document everything: timestamps, before/after photos, any deviation from the plan. Wear body cameras (with client consent) for after-action review.

### 5.1 Tailgating execution

```
1. Stage at a smoking area or loading dock
2. Wait for an employee with a badge
3. Follow at conversational distance (not too close)
4. At the door, deploy the pretext script (15-second greeting)
5. Employee holds the door
6. Enter; thank them; move with purpose
7. If challenged: stay in character; repeat the pretext; gracefully exit if pressed
8. If challenged by a guard: STOP, produce authorization letter, call client contact
```

### 5.2 Badge clone execution

```
1. Capture the credential:
   - Borrow the original badge (insider cooperation)
   - Sniff the badge at the reader (Proxmark3 sniff mode)
   - Read an unattended badge from a desk

2. Clone to a writable card or simulate from Proxmark3:
   - Proxmark3: lf hid clone / hf mf cload
   - ESP-RFID-Tool: READ then WRITE
   - Walrus: READ then WRITE (HF only)

3. Walk to the door
4. Tap confidently (don't fumble)
5. Reader LED turns green; door unlocks
6. Enter; document the time
7. Note: reader logs show a valid badge tap; original holder unaware

Anti-detection:
- Tap at a location consistent with the original's pattern
- Don't tap at the same time as the original
- Avoid anti-passback alarms (tap "in" only after original tapped "out")
- Avoid DFO alarms (always tap the badge — don't just pull the door)
```

### 5.3 Lock pick execution

```
1. Approach the door outside camera coverage (if possible)
2. Verify lock type (pin-tumbler, dimple, tubular)
3. Apply light tension
4. Pick (single-pin or rake)
5. When the core rotates, the lock opens
6. Enter; re-lock from the inside if possible
7. If no inside lock, pick closed behind you
8. Document: time-to-pick, technique, any tool marks

Anti-detection:
- Pick at a time consistent with normal traffic (lunch hour, shift change)
- Don't pick locks with anti-pick pins (Medeco, Assa) — too slow, leaves marks
- Don't pick emergency exit locks (function keys) — likely out of scope
```

### 5.4 USB weapon execution

```
1. Locate an unattended workstation (after-hours is best)
2. Verify endpoint posture in recon (USB whitelisting? EDR? Lock screen?)
3. Plug in the USB weapon (Ducky / Bash Bunny)
4. Wait for LED to indicate payload completion (~5-10 seconds)
5. Remove the USB weapon
6. Verify C2 (Netcat listener, beacon check-in)
7. Document: time-of-insertion, payload-completion, shell-establishment, USB-removal
8. Note workstation asset tag and location

Anti-detection:
- After-hours reduces the chance of an employee walking by
- Avoid leaving USB weapons unattended
- Clear PowerShell event logs only with client authorization
```

---

## 6. Phase 4 — On-Site Ops & Persistence

Once inside, the goal shifts to situational awareness, lateral movement, and persistent access.

### 6.1 Situational awareness

```
Deploy a hidden camera at a choke point (break room, elevator lobby) to
track guard rounds for the duration of the engagement.

Pi Zero W + Pi Camera V2 + battery:
- Capture a JPEG every 60 seconds
- Off-site upload (cellular or WiFi)
- Operator reviews feed every 30 minutes

Document placement for retrieval.
```

### 6.2 Drop-box deployment

```
LAN Turtle (USB):
- Find an unused USB port on an always-on workstation
- Plug in; verify Cloud C2 check-in (30 seconds)
- From Cloud C2: SSH in; tcpdump on the internal network; pivot

Packet Squirrel (Ethernet):
- Find an Ethernet drop where a device plugs in
- Unplug device's cable from wall jack; plug Squirrel into wall jack
- Plug device's cable into Squirrel
- Verify Cloud C2 check-in

Pi Zero W (DIY):
- Connect to target WiFi; reverse SSH tunnel to consultancy C2
- SSH in; pivot to internal targets
```

### 6.3 Lateral movement

From the drop box:

```bash
# Internal network scan (light touch — don't trigger IDS)
nmap -sn 10.0.0.0/24         # ping sweep
nmap -sV -O 10.0.0.5         # service detection on a target

# Credential harvesting (with client authorization)
#Responder: poison LLMNR/NBT-NS to capture NetNTLM hashes
python /opt/Responder/Responder.py -I eth0 -wrf

# Mimikatz on a compromised Windows host (if beacon deployed)
# See ad-ldap-attack and post-exploitation skills

# Active Directory enumeration
# See ad-ldap-attack skill: BloodHound, PowerView, SharpHound
```

### 6.4 Anti-forensics

Minimize footprint. Document what was changed for the report.

```bash
# Clear command history on a compromised Linux host (with authorization)
history -c && rm ~/.bash_history

# Clear PowerShell event logs on Windows (with authorization)
wevtutil cl PowerShell
wevtutil cl "Windows PowerShell"

# Document the clearing in the engagement timeline
# Note: clearing logs is itself an indicator; defenders will see the gap
```

---

## 7. Phase 5 — Exit & Evidence

The exit is as operationally sensitive as the entry. A botched exit burns the engagement.

### 7.1 Exit checklist

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

### 7.2 Evidence pack

Produce an evidence pack with:

1. **Engagement timeline** — minute-by-minute log of every action
2. **Cloned badge photos** — before/after for each clone
3. **Drop box logs** — Cloud C2 export, tcpdump captures
4. **USB payload evidence** — Bash Bunny LED photo, C2 session capture
5. **Hidden camera footage** — with employee faces blurred
6. **Body camera footage** — operator POV (with client consent)
7. **Chain-of-custody form** — every artifact, every transfer

### 7.3 Chain-of-custody

Every artifact gets an entry in the chain-of-custody form:

| Item | Description | Collected | Operator | Storage | Retention | Destroyed |
|------|-------------|-----------|----------|---------|-----------|-----------|
| 001 | Cloned HID Prox T5577 | 2026-06-17 09:50 | A | encrypted volume | 30 days | 2026-07-17 |
| 002 | LAN Turtle (retrieved) | 2026-06-17 14:15 | A | evidence safe | 30 days | n/a (returned to inventory) |
| 003 | Hidden camera SD card | 2026-06-17 14:15 | B | evidence safe | 30 days | 2026-07-17 |

### 7.4 Encrypt and deliver

```bash
tar -czf evidence_pack.tar.gz evidence_pack/
gpg --symmetric --cipher-algo AES256 evidence_pack.tar.gz
# Passphrase shared with client out-of-band
shred -uvz evidence_pack.tar.gz
# Deliver evidence_pack.tar.gz.gpg via agreed secure channel
```

---

## 8. Defense Perspective

For defenders reading this playbook: the controls that defeat each phase.

### 8.1 Defeating Phase 1 (recon)

| Recon activity | Defensive control |
|----------------|-------------------|
| Walk-by recon | Trained reception; signage noting authorized-access-only; CCTV with retention |
| LinkedIn badge vendor OSINT | Standardize badge design (no vendor logos visible); restrict conference photos |
| Job posting OSINT | Generic job descriptions ("access control system"); avoid naming vendors |
| Building permits | Coordinate with installers to minimize permit disclosure |

### 8.2 Defeating Phase 2 (entry vector)

| Entry vector | Defensive control |
|--------------|-------------------|
| Tailgating | Anti-passback; turnstiles; trained reception; people-counting cameras |
| Badge clone (LF) | Migrate to HF with mutual authentication (DESFire EV3, iCLASS SEOS) |
| Badge clone (Mifare Classic) | Migrate to Mifare DESFire EV3 (CRYPTO1 is broken) |
| Lock pick | High-security locks (Medeco, Assa); restricted keyway control |
| USB weapon | Endpoint protection (USB whitelisting); Group Policy HID blocking; auto-lock on USB insertion |
| Drop box | 802.1X port authentication; MAC OUI monitoring; periodic jack sweeps |
| Crash bar tape | Anti-tape shields on exit hardware; door-position alarms |

### 8.3 Defeating Phase 3 (execution)

| Execution activity | Defensive control |
|--------------------|-------------------|
| Tailgating | Employee training (annual tailgating awareness); clear policy on challenging strangers |
| Badge clone | Duplicate-tap alerting; anti-passback at all doors |
| Lock pick | Door-forced-open alarms; guard response SLA |
| USB weapon | EDR with USB device analysis; PowerShell Constrained Language Mode |

### 8.4 Defeating Phase 4 (persistence)

| Persistence activity | Defensive control |
|----------------------|-------------------|
| Drop box | Network anomaly detection; 802.1X; switch-port security |
| Network implant | Network baselining; MAC OUI monitoring; periodic sweeps |
| Hidden camera | RF sweeps; thermal sweeps; physical inspection (TSCM) |
| Lateral movement | Network segmentation; EDR; honeytokens |

### 8.5 Defeating Phase 5 (exit) — for the operator

This is the operator's perspective, not the defender's. The exit is what makes or breaks the engagement's legal posture.

- Reverse every change.
- A missed drop-box becomes a criminal device on a client's network.
- A missed USB weapon becomes evidence of an unauthorized device.
- A missed lock-pick becomes a tool left at the crime scene.
- Reversal is part of the engagement scope, not optional.

---

## 9. Common Mistakes

### 9.1 Operator mistakes

- **Forgetting the authorization letter** → arrested, engagement burned
- **Operating outside the contracted hours** → engagement scope violated
- **Entering a prohibited area** (HR, executive residence, third-party colocation) → felony risk
- **Leaving a device behind** → unauthorized device on client network
- **Recording audio in a two-party consent state without consent** → wiretapping charge
- **Lock picking an emergency exit (function)** → likely out of scope; safety violation
- **Engaging with an employee who challenges** → pretext burned; gracefully exit
- **Running from a guard** → escalation; engagement burned; possible arrest

### 9.2 Engagement lead mistakes

- **Scope ambiguity** → operator enters an out-of-scope area
- **No fallback chain** → primary entry fails; engagement aborts
- **No inventory check after engagement** → forgotten device on client site
- **Inadequate evidence encryption** → data breach of engagement artifacts
- **No retention policy** → evidence kept indefinitely; legal exposure grows
- **Single-operator engagement** → no second pair of eyes; safety risk

### 9.3 Client-side mistakes (counsel the client)

- **Vague authorization letter** → does not cover the engagement as executed
- **Unreachable 24/7 contact** → operator arrested; client can't confirm authorization
- **Scope drift during engagement** → client requests additional areas verbally; not in writing
- **No insurance coordination** → consultancy's E&O doesn't cover the engagement

---

## 10. Integration with Adjacent Skills

This skill is part of a broader red-team / pentest toolkit. The integrations:

### 10.1 Pre-engagement (before this skill)

- `osint` — passive OSINT on the client (LinkedIn, public records) → input to recon
- `social-intelligence` — discourse monitoring (Reddit, HN, X) on the client → input to recon
- `engagement-manager` — contract, scope, deliverable framing

### 10.2 During engagement (parallel with this skill)

- `bluetooth-rfid-nfc` — protocol-level analysis of cloned credentials (CRYPTO1 internals, Mifare nested attack theory)
- `sdr-rf-attack` — RF replay at 313/433 MHz for gates and keyfobs (this skill covers badge replay, not broad RF)
- `hardware-security` — JTAG/UART/firmware extraction on captured devices after drop-box deployment
- `social-engineering` — phishing/vishing pretexts that complement physical tailgating

### 10.3 Post-engagement (after this skill)

- `post-exploitation` — internal pivoting after drop-box deployment
- `ad-ldap-attack` — Active Directory attacks after physical-to-network pivot
- `anti-forensics` — minimizing footprint; reversing engagement artifacts
- `pentest-reporting` — engagement report writing

### 10.4 Hand-off pattern

```
engagement-manager → osint (pre) → physical-security-testing →
post-exploitation → ad-ldap-attack → anti-forensics → pentest-reporting
```

The hand-off at each stage is a structured artifact (recon pack, engagement timeline, evidence pack, internal network map) that the next skill consumes.

---

## 11. References

- **TrustedSec physical-docs** (legal templates): [github.com/trustedsec/physical-docs](https://github.com/trustedsec/physical-docs)
- **awesome-lockpicking**: [github.com/meitar/awesome-lockpicking](https://github.com/meitar/awesome-lockpicking)
- **RedTeam-Physical-Tools**: [github.com/topics/redteam-physical](https://github.com/topics/redteam-physical)
- **ESP-RFID-Tool**: [github.com/topics/esp-rfid-tool](https://github.com/topics/esp-rfid-tool)
- **TeamWalrus/Walrus**: [github.com/TeamWalrus/Walrus](https://github.com/TeamWalrus/Walrus)
- **Proxmark3**: [github.com/RfidResearchGroup/proxmark3](https://github.com/RfidResearchGroup/proxmark3)
- **Hak5** (LAN Turtle, Packet Squirrel, Rubber Ducky, Bash Bunny): [hak5.org](https://hak5.org)
- **Schuyler Towne** (locksport educator): [youtube.com/@SchuylerTowne](https://www.youtube.com/@SchuylerTowne)
- **DEF CON Physical Security Village**: [defcon.org](https://defcon.org)
- **TOOOL** (The Open Organisation Of Lockpickers): [toool.us](https://toool.us)
- **CPTED** (Crime Prevention Through Environmental Design): [cpted.net](https://www.cpted.net)
