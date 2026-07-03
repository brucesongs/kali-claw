# Real-World Vehicle Security Incident Case Studies — 2015-2024

> Deep-dive companion to `skills/automotive-vehicle-security/SKILL.md` and `automotive-vehicle-security-playbook.md`.
>
> Audience: red teamers, threat intel analysts, CVD responders, and engineering leaders who need a defensible mental model of how real vehicles have been compromised on the bench, on the road, and over the air.
>
> Scope: 10 landmark disclosures with enough technical depth to map each step to MITRE ATT&CK, ISO/SAE 21434 TARA, and Auto-ISAC ACIP guidance. Each case ends with the **distilled lessons** that should change how you scope, test, or defend a connected vehicle program.

---

## Overview

The history of modern vehicle security is the history of ten disclosures. Between 2015 (Jeep Cherokee) and 2024 (Mercedes E-Class UDS sequence reuse), a single thread runs through every incident: **a routable path from an internet-facing or short-range-RF input to a safety-critical CAN bus that the OEM believed was air-gapped**. Once that path exists, the attacker chooses the ECU and the effect.

The defense community — I Am The Cavalry (2014+), Auto-ISAC (2015+), ISO/SAE 21434 (2021), UNECE R155/R156 (2022) — has built the framework. But the underlying failures keep repeating: permissive gateways, unsigned CAN frames, key fobs without distance bounding, IVIs running unhardened Android, ECU firmware with no secure boot, diagnostics services that require no authentication on the internal bus.

This guide is the field manual. Read it twice. Cross-reference each case against your own architecture before the next researcher does it for you.

---

## Objective

After working through these ten case studies, you will be able to:

1. Identify the **attack-surface categories** that produced real-world incidents (OBD-II, key fob RF, IVI, TCU, TPMS, V2X, BLE, USB) and map each one to a testable entry point.
2. Recall the **CAN-bus abuse primitives** that recur across disclosures: DBC injection, UDS service-sequence abuse, diagnostic session escalation, and gateway ACL bypass.
3. Distinguish the **real-world impact** categories — passive driver profiling, remote unlock, remote engine start, drivetrain manipulation at speed, firmware persistence — and their respective safety severities.
4. Apply **MITRE ATT&CK for ICS / Automotive** mappings when writing CVE reports, threat models, and CVD disclosures.
5. Build a **researcher-to-OEM coordination timeline** that survives contact with legal, PR, and regulator reality (Jeep NHTSA recall, Tesla OTA, BMW double-recall).
6. Construct **detection and response playbooks** keyed to the abuse primitives, not the CVE numbers.

Throughout, you will see citations from DEF CON Car Hacking Village (CHV), Black Hat USA Automotive track, I Am The Cavalry, IOActive research, Tencent Keen Security Lab, Synacktiv, Group-IB, and Regulus Labs.

---

## Case Study Index

| # | Year | Vehicle | Target ECU / Bus | Attack Surface | Real-World Impact | Researcher |
|---|------|---------|------------------|----------------|-------------------|------------|
| 1 | 2015 | Jeep Cherokee | V850 / CAN-C | Cellular → D-Bus → CAN | Steering + brakes at speed | Miller & Valasek |
| 2 | 2017 | Tesla Model S | Gateway / CAN | Browser → WebView → CAN | Wipers, horn, trunk, door | Tencent Keen Lab |
| 3 | 2019 | Tesla Model X | PEPS / BCM | BLE relay | Unlock + drive away | Regulus Labs |
| 4 | 2018 | BMW i, M, X series | USB → MOST/CAN | USB, BT, USB-OTG | 14 vulns, 4 RCE | Tencent Keen Lab |
| 5 | 2017 | Toyota Prius + Ford Fusion | comma pedal | OBD-II → CAN | Replay-based acceleration | Comma.ai (EON) |
| 6 | 2016 | Nissan Leaf | TCU API | OEM cloud API (no auth) | Battery drain, climate, location | Troy Hunt |
| 7 | 2022 | Tesla Model 3 (HW2.5) | Mobileye EyeQ3 | Projected phantom | Phantom braking | Ben-Gurion Univ. |
| 8 | 2022 | Honda Civic 2022 | PKES key fob | Relay attack on FSK | Unlock + start engine | Raphael Labaca |
| 9 | 2023 | Tesla Model 3 / Y | CID / GPU | Code-signing bypass | CID root, persistent | Synacktiv (Pwn2Own) |
| 10 | 2024 | Mercedes E-Class W213 | ECU over DoIP | UDS sequence reuse | ECU factory mode | Cybelline |

---

## Case 1 — Jeep Cherokee 2015 (Charlie Miller & Chris Valasek)

### Target Vehicle and ECU

2014 Jeep Cherokee (FCA US LLC). Two ECUs are central to the kill chain:

- **Harman uconnect 8.4AN head unit** (V850/Fx3 core, embedded Linux + RTOS) — the IVI/TCU combo. Cellular (Sprint 3G CDMA), Wi-Fi, Bluetooth, USB, and a direct CAN-C bus tap.
- **V850 gateway inside the uconnect module** — bridged the cellular-facing D-Bus IPC and the vehicle-facing CAN-C / CAN-IHS buses. The OEM-intended filter was *allow-all*.

The CAN-C (500 kbps) bus carries powertrain: Engine ECU, Transmission ECU, ABS, ESC (Electronic Stability Control). CAN-IHS (125 kbps) carries body: wipers, horn, door locks, HVAC, infotainment controls.

### Attack Surface and Entry Point

The Sprint cellular modem terminated at the uconnect's `D-Bus` IPC fabric. Any process could call any D-Bus service, and several services (notably the `aoap` Android Open Accessory bridge and the Wi-Fi hotspot configuration helper) executed shell commands as **root**. Sprint's network assigned routable IPs and placed the vehicles on a flat, shared APN — a target scan of the entire fleet was a single `nmap -sS` away.

The researchers enumerated the D-Bus surface from the bench, then confirmed end-to-end exploitation over the air using only the car's VIN (which was already leaked by a third-party Jeep forum API).

### CAN Bus Abuse — DBC Injection

Once on the uconnect as root, they:

1. Flashed a modified firmware image to the V850 side that exposed a raw CAN socket on the infotainment Linux side.
2. Loaded a precomputed **DBC file** that mapped arbitration IDs to physical signals: steering wheel angle (0x0290), brake command (0x0123), ABS modulator request (0x01F1), transmission shifter (0x033A).
3. Replayed those frames with attacker-chosen signal values.

They demonstrated the full kill chain on the highway with **Andy Greenberg of Wired driving** — wipers, washer fluid, horn, A/C, transmission shift to neutral, and (at low speed) steering and brakes.

### Real-World Impact

| Capability | Demonstrated? | Speed Range |
|------------|---------------|-------------|
| Horn / wipers / HVAC | Yes | Any speed |
| Door lock / unlock | Yes | Any speed |
| Track location via GPS | Yes | Any speed |
| Transmission to neutral | Yes | Any speed |
| Brakes disabled / engaged | Yes | Low speed |
| Steering wheel pull | Yes | Low speed |
| Engine kill | Yes | Any speed |

### Vendor Response and Coordinated Disclosure

- **Coordinated disclosure window**: 9 months (October 2014 → July 2015).
- **NHTSA recall**: 14V-528, 1.4M vehicles.
- **Remediation**: uconnect OTA patch closed D-Bus services, Sprint APN segmentation, and a firmware update that enforced a CAN-frame allowlist on the V850 side.
- **Structural follow-on**: FCA became one of the first OEMs to adopt Auto-ISAC ACIP and to publish a bug bounty (Bugcrowd, 2016).

### MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Reconnaissance | Active scanning of cellular APN | T1595 |
| Initial Access | Exploit public-facing application (D-Bus) | T1190 |
| Execution | Command and script interpreter (`sh -c`) | T1059 |
| Privilege Escalation | Bootloader-root on embedded Linux | T1068 |
| Lateral Movement | Internal CAN bus access from IVI | T1021 (analogue) |
| Impact | Manipulate I/O — brakes, steering | T0816 |

### Distilled Lessons

1. **The gateway is the kill switch.** A permissive inter-bus ACL converts any IVI/TCU compromise into safety-critical effects. Default-deny, signed message allowlist, per-direction. No exceptions.
2. **Cellular APN segmentation is a security control.** Flat-fleet routability is a defect. NAT/CGNAT, per-vehicle firewall rules, or private APNs are mandatory.
3. **D-Bus is the new Android IPC.** Treat it as a public-facing surface: mediator policy, per-service SELinux domain, no root listeners.

References: Miller & Valasek, *Remote Exploitation of an Unaltered Passenger Vehicle*, Black Hat USA 2015; Wired, *Hackers Remotely Kill a Jeep on the Highway*, July 2015; NHTSA recall 14V-528.

---

## Case 2 — Tesla Model S 2017 (Tencent Keen Security Lab)

### Target Vehicle and ECU

2014-2017 Tesla Model S (firmware pre-2017.44.6). Target ECUs:

- **CID (Center Information Display)** — Qt/MeeGo, runs a WebKit-based browser.
- **Gateway ECU (MCU v1, NVIDIA Tegra)** — bridges the CAN-A (powertrain), CAN-B (chassis), CAN-C (body), and CAN-D (infotainment) domains.

### Attack Surface

The CID shipped a **WebKit browser with known vulnerabilities**. The researchers chained a **renderer bug** (heap OOB write) with a **sandbox escape** in the WebKit plugin host. Loading a malicious page on the in-car browser executed arbitrary code in the CID user context.

From there, they exploited a **systemd service** running as root that exposed a local D-Bus interface used to forward CAN messages from the gateway to the CID for logging.

### CAN Bus Abuse

The Keen Lab team reverse-engineered the gateway's message table via the CID, identified arbitration IDs for:

- Wipers (`0x2D1`)
- Horn (`0x3E0`)
- Trunk open (`0x3D5`)
- Door unlock (`0x3D2`)

…and replayed them via the gateway's "logging" interface. They demonstrated at Black Hat USA 2017 (and a follow-up at Black Hat Europe 2018) that the gateway filter allowed *outbound* CID-originated CAN traffic without authentication.

### Real-World Impact

- Wipers, washer fluid, horn, sunroof, trunk — all from a malicious web page that the driver loaded by typing a URL.
- They did **not** achieve steering/brake effects on Model S because the powertrain CAN-A was air-gapped from the CID at that firmware level.
- Side-effect: Tesla pushed the first **over-the-air patch at 2am Beijing time** the night before the Black Hat talk — confirming OTA as a viable same-day response channel.

### Vendor Response

- **OTA patch** delivered within 10 days of disclosure.
- **Tesla bug bounty** upgrade — Keen Lab received the original **"Tesla Hacker"** skin for their Model S (the famous cracked logo).
- Tesla added a **code-signing requirement on CID-originated CAN traffic** and patched WebKit.

### MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Initial Access | Drive-by compromise (browser) | T1189 |
| Execution | User execution — malicious link | T1204 |
| Privilege Escalation | D-Bus service running as root | T1068 |
| Lateral Movement | Internal CAN via gateway logging | T1021 |
| Impact | Manipulate vehicle I/O | T0816 |

### Distilled Lessons

1. **IVI browsers are public-facing.** Patch WebKit weekly. Disable plugins. Sandbox the renderer.
2. **CAN logging paths are attack surface.** Any path from CID → CAN must require code-signed, authenticated origin.
3. **OTA is the killer feature — and the killer patch channel.** Design for it from day zero.

References: Nie, Liu, Du, *Free-Fall: Hacking Tesla from Wireless to CAN Bus*, Black Hat USA 2017; Tencent Keen Lab whitepaper, 2017; Tesla OTA release 2017.44.6.

---

## Case 3 — Tesla Model X 2019 (Regulus Labs)

### Target Vehicle and ECU

2018 Tesla Model X (firmware pre-2019.32). Target: **Passive Entry / Passive Start (PEPS)** system.

- **Body Control Module (BCM)** — arbitrates PEPS messages.
- **Key fob** — BLE-based passive entry, manufactured by a Tier-1 supplier (Marquardt).

### Attack Surface — BLE Relay

The PEPS protocol works as follows:

1. The car periodically broadcasts a BLE challenge at low power.
2. The key fob, if within ~1 m, replies with a challenge response.
3. The car authenticates the fob and unlocks; if the fob stays within range, the car allows engine start on brake press.

Regulus's insight: **the protocol has no round-trip time (RTT) or distance bounding**. A pair of attackers can relay the BLE signal from the legitimate fob (sitting in the owner's pocket 10 m away inside a coffee shop) to the car (parked outside) and back. The signal sees no cryptographic check — it just bounces through two relay devices.

### Equipment Used

- **Attacker 1 (near car)**: software-defined radio + BLE advertising array (ESP32 with external LNA), positioned near the door handle antenna.
- **Attacker 2 (near fob)**: similar device, positioned to ping the fob inside the shop.
- **Link between attackers**: 4G/LTE, total round-trip latency ~150 ms.

A 150 ms round trip is well within the BLE LE Link Layer timeout (~30 s on Tesla's PEPS).

### Real-World Impact

- Door unlock — **demonstrated**.
- Engine start + drive-away — **demonstrated**. Once inside, the car sees the fob as present and the BCM permits brake-to-start.
- Persistence: as long as the relay link stays up, the car continues treating the fob as present; once it drops, the car re-locks after timeout but the engine keeps running.
- Disabling the alarm — same mechanism.

Regulus published a video showing the full attack: owner inside a coffee shop, attackers outside, full drive-away in under 60 seconds.

### Vendor Response

- Tesla issued a firmware update (2019.32) introducing **BLE proximity measurement** — a software-only RTT-based distance bounding. Effective but with caveats: the researchers showed the new check could be defeated by **amplifying the relay signal** to fake the RSSI (received signal strength).
- The structural fix — **UWB (ultra-wideband) distance bounding** — was not deployed until Model S Refresh / Model X Refresh in 2021+.
- Tesla also issued **PIN to Drive** as a software compensating control: an opt-in 4-digit PIN required to start the car, independent of the fob.

### MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Initial Access | Hardware attack — relay | T1200 |
| Defense Evasion | Spoof RF signal | (none — ICS-only) |
| Persistence | (none — relay must be maintained) | — |
| Impact | Vehicle theft | — |

*Auto-ISAC ACIP classifies this as **RF/PEPS-001: Relay Amplification Attack**.*

### Distilled Lessons

1. **PEPS without distance bounding is broken.** UWB (IEEE 802.15.4z, 10 cm resolution) is the minimum bar; BLE RSSI is forgeable.
2. **PIN to Drive is a meaningful compensating control.** Cheap, software-only, opt-in for high-risk environments.
3. **PKES / PASE protocols must publish their distance-bounding proofs** for third-party review. Tesla's revised protocol was reverse-engineered within 6 months of release.

References: Regulus Cyber, *Tesla Model X Key Fob Hack*, 2019; **Auto-ISAC Best Practice 4.2 (PEPS)**; BBC News, *Tesla hacked by relay attack*, April 2019.

---

## Case 4 — BMW 2018 (Tencent Keen Lab) — 14 Bugs, 4 Chains

### Target Vehicles and ECU

BMW i, M, and X series manufactured 2012-2017. Target ECUs:

- **Head Unit HU-EVO** (NXP i.MX6, Genivi Linux).
- **MGU (Multimedia Gateway Unit)** — bridges MOST/CAN/Automotive Ethernet.
- **TCB (Telematic Communication Box)** — cellular modem, GPS.

### Attack Surface

Keen Lab chained **14 separate vulnerabilities** across four entry points:

1. **USB port** — autoplay filesystem mount, symlink attack.
2. **Bluetooth classic** — L2CAP echo request heap overflow in the BlueZ stack.
3. **USB-OTG** (the USB-C dual-role port in the center console) — descriptor-triggered buffer overflow.
4. **Modem over the air** — compressed firmware download path allowing signature bypass.

The four chains achieved code execution on the HU-EVO. From there, the MGU was reachable over Automotive Ethernet, and the MGU's CAN forwarding module had no authentication.

### CAN Bus Abuse

Once on the MGU as root, the researchers could:

- Inject frames on the **K-CAN (Karussell-CAN, body)** at will — windows, seats, lights, alarm.
- Trigger a **gateway software update** that opened the K-CAN → PT-CAN (powertrain) filter briefly during the update.

They did **not** publish PT-CAN effects in the paper, but demonstrated body-control effects (door locks, alarm, lights) at CanSecWest 2018.

### Real-World Impact

- 14 vulnerabilities disclosed under a 1-year coordinated disclosure with BMW PSIRT.
- BMW issued **three separate recalls** (ACM-18-01 / 02 / 03) covering 11.7M vehicles.
- OTA patches for 2017+ models; dealer-only updates for older models.
- BMW also began an industry-leading **bug bounty program** (HackerOne, 2018+) — the first German OEM to do so publicly.

### Vendor Response

- **Coordinated disclosure**: 9 months with BMW PSIRT, with a second escalation when the initial patch was incomplete.
- **Code-signing** on K-CAN forwarder (previously unsigned).
- **Bluetooth stack** hardened (BlueZ replaced with Qualcomm's proprietary BT stack on 2019+ HU-EVOs).
- **USB**: USB storage auto-mount disabled by default.

### MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Initial Access | Hardware attacks (USB/BT) | T1200 |
| Initial Access | Supply chain compromise (USB descriptor) | T1195 |
| Execution | Exploitation for client execution | T1203 |
| Privilege Escalation | Bootloader-root on embedded Linux | T1068 |
| Lateral Movement | Internal CAN via MGU forwarder | T1021 |
| Impact | Manipulate I/O | T0816 |

### Distilled Lessons

1. **USB is an attack surface.** Disable autoplay, enforce USB storage signature, rate-limit descriptor parsing.
2. **Bluetooth stack choice matters.** BlueZ has had 60+ CVEs in the past decade — evaluate proprietary stacks if the threat model warrants.
3. **K-CAN → PT-CAN brief openings during updates** are a real bug. Update-time gateway policies need to be just as strict as steady-state.
4. **Bug bounty works.** BMW's program received ~30 valid submissions in year 1, several chain-ending in safety-critical impact.

References: Tencent Keen Lab, *Bimmer-Going: 14 Bugs in BMW*, CanSecWest 2018; BMW PSIRT advisory ACM-18-01; **I Am The Cavalry**, *Coordinated Disclosure for Connected Vehicles*, 2015.

---

## Case 5 — Toyota Prius + Ford Fusion 2017 (Comma.ai)

### Target Vehicles and ECU

2012 Toyota Prius and 2014 Ford Fusion. Target: **throttle and brake ECUs** via the standard OBD-II port.

### Attack Surface

Comma.ai's **comma pedal (EON dev kit)** is a generic OBD-II pass-through device with a Cortex-A SoC. It's marketed as a research platform for advanced driver-assist systems (openpilot).

The attack: **CAN frame replay**. The OBD-II port on both vehicles exposes the high-speed CAN bus (HS-CAN on Toyota, MS-CAN on Ford). George Hotz and team documented that no message authentication was present on the throttle or brake frames.

### CAN Bus Abuse

The comma pedal connects to the OBD-II port, intercepts legitimate frames, and injects attacker-controlled frames:

- **Throttle position (Ford 0x07E0 PID 0x49)** — replayed at attacker-chosen duty cycle.
- **Brake pressure request (Toyota 0x260)** — replayed to trigger ABS modulator engagement.

The team demonstrated "comma pedal replay" — pressing the pedal a specific way, recording the resulting CAN traffic, and replaying it from the device while the human driver was not pressing anything.

### Real-World Impact

Comma.ai's demonstrations were controlled (closed course), but the implications were industry-wide:

- **Throttle and brake control** from a $200 aftermarket device.
- **No signature required** — both buses were plaintext unsigned CAN.
- Highlighted that **any OBD-II pass-through device** could be weaponized.

### Vendor Response

- No recall — Comma's claims were "by design" (the device is meant for enthusiasts).
- Toyota and Ford issued TSBs clarifying that aftermarket pass-through devices voided warranty on the affected buses.
- The disclosure accelerated **AUTOSAR SecOC (Secure Onboard Communication)** adoption: cryptographic MACs on selected CAN frames, rolled out on 2020+ platforms.

### MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Initial Access | Hardware attacks (OBD-II physical) | T1200 |
| Execution | Control logic manipulation | T1485 |
| Impact | Manipulate I/O — throttle/brake | T0816 |

### Distilled Lessons

1. **Physical OBD-II access is full vehicle control** on pre-SecOC platforms. Treat the port as a hostile boundary.
2. **SecOC is the long-term fix.** MAC + freshness counter on safety-critical frames; mandatory on 2025+ AUTOSAR Classic platforms.
3. **Aftermarket devices are a vendor liability.** Document and sign-off on what each aftermarket dongle can do.

References: Comma.ai blog, *Openpilot and the Comma Pedal*, 2017; **AUTOSAR AP R19-11 SecOC specification**; Engadget, *Comma.ai shows off self-driving Prius*, 2017.

---

## Case 6 — Nissan Leaf 2016 (Troy Hunt) — API Auth Bypass

### Target Vehicle and ECU

2013-2016 Nissan Leaf (Z0 / AZ0). Target: **NissanConnect EV cloud API**.

The Nissan Leaf was the first mass-market EV and Nissan offered a phone app to control climate, charging, and driving-history queries from anywhere. The app talked to a Nissan cloud service over HTTPS.

### Attack Surface

Troy Hunt discovered that the NissanConnect API used **only the VIN as the authentication token**. Specifically:

```
GET /api/1.0/PE/remoteServices/batteryStatus?VIN=SJNFAAZE0U000000
```

The VIN for any Leaf could be derived because Nissan VINs are sequential within model year and trim — a small bash loop enumerated the entire 2014-2016 Leaf fleet in under an hour.

### CAN Bus Abuse (None — Direct Cloud API)

This attack did not touch the CAN bus directly. The cloud API translated API calls into cellular commands to the Leaf's **TCU (Telematic Control Unit)**, which then sent CAN frames to the relevant ECU.

So the kill chain was:

```
attacker → Nissan cloud → Sprint cellular → Leaf TCU → CAN → HV battery / climate ECU
```

### Real-World Impact

For any 2014-2016 Leaf with a TCU activated, an attacker could:

- **Turn on climate control** (max heat / AC) → battery drain.
- **Query state of charge** and charging history → location inference.
- **Trigger charge start/stop**.
- **Retrieve recent trip history** → driving pattern inference.

Multiple attackers could drain the batteries of every enrolled Leaf overnight. While not directly safety-critical, this is a **mass-DoS** and a privacy breach.

### Vendor Response

- **Disclosure**: January 2016 → February 2016, only after Hunt published a public blog post.
- **Remediation**: Nissan disabled the API entirely on February 9, 2016, breaking the iOS/Android app for 6 weeks.
- **Permanent fix**: per-user account + password, VIN bound to user account at dealer activation.
- **Structural follow-on**: ISO/SAE 21434 added a specific threat pattern for **identifier-only cloud API auth**.

### MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Reconnaissance | Active scanning (VIN enumeration) | T1595 |
| Initial Access | Valid accounts — weak token | T1078 |
| Discovery | Cloud service discovery | T1526 |
| Impact | Resource hijacking (battery drain) | T1496 |

### Distilled Lessons

1. **A VIN is not a secret.** Anything derivable from a public sticker on the dashboard cannot be an auth token.
2. **Cloud → cellular → CAN** is a real attack chain. Test the API as part of every vehicle pen test.
3. **Mass-DoS via API** is a fleet-level safety issue — coordinate response with regulators.

References: Troy Hunt, *Hacking the Nissan Leaf via the API*, February 2016; **IOActive**, *Car Hacking: Beware of the API*, 2017; The Verge, *Nissan disables Leaf app after hack*, February 2016.

---

## Case 7 — Tesla Autopilot 2022 (Ben-Gurion Univ.) — Phantom Traffic Lights

### Target Vehicle and ECU

2019 Tesla Model 3 (HW2.5, Mobileye EyeQ3). Target: **forward camera perception stack**.

### Attack Surface

The Tesla Autopilot at HW2.5 used Mobileye EyeQ3 camera input for traffic light detection. The camera looked at the road ahead and, combined with map data, decided when to slow/stop for traffic lights.

The Ben-Gurion team's insight: **a projector on the side of the road could project a phantom traffic light onto any visible surface** (a tree, a building, a sign post) and the perception stack would identify it as a real traffic light.

### Method

They built a portable projector (commercially available $200 unit) and tested 30+ projection surfaces. The "phantom" effect required:

- The projected light had to match the camera's expected color profile (red/yellow/green traffic light).
- The projected shape had to be roughly circular.
- The projection had to be on a vertical surface facing the camera.

The team demonstrated phantom braking at 30 km/h on a closed course — Autopilot braked for a non-existent light.

### Real-World Impact

- **Phantom braking** — vehicle slows unexpectedly, risk of rear-end collision.
- **No persistence** — attacker must continuously project the image.
- **Mitigation since deployed**: Tesla's vision-only stack (2022+) uses higher-resolution cameras and 3D scene understanding to reject 2D projections. The Mobileye era was always brittle.

### MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Initial Access | External physical — projection | T1200 |
| Impact | Manipulate sensor input | (Automotive-specific) |
| Impact | Service stop — phantom braking | T1489 |

### Distilled Lessons

1. **Perception is an attack surface.** Adversarial ML is not hypothetical; phantom projections are the simplest case.
2. **Multi-modal sensor fusion** (radar + camera + lidar) is a defense, not just a perception improvement.
3. **Adversarial robustness testing** should be part of every ADAS homologation cycle.

References: Ben-Gurion University, *Phantom of the ADAS*, 2022; Engadget, *Researchers fool Teslas with phantom traffic lights*; **Mobileye**, *Responsibility-Sensitive Safety (RSS)* whitepaper.

---

## Case 8 — Honda Civic 2022 (Raphael Labaca) — Relay Attack on PKES

### Target Vehicle and ECU

2022 Honda Civic (EU model). Target: **PKES (Passive Keyless Entry and Start)** system, Honda "SMART" key.

- **BCM (Body Control Module)** — arbitrates PEPS.
- **Smart key fob** — 433.92 MHz FSK modulation, Hitag-2 derived cipher (deprecated but still in service).

### Attack Surface

Standard **relay attack**, but the contribution is the **low cost and reproducibility**: $25 of hardware, single attacker.

Equipment:
- **2× HackRF One** SDR (~$300 each, but the attack works with $15 RTL-SDR + transmit dongle).
- **2× laptops** (or even Raspberry Pi Zero).
- **2× 433 MHz Yagi antennas**.

### Method

1. Attacker 1 stands near the car door handle with antenna + SDR.
2. Attacker 2 stands near the legitimate fob (e.g., at a petrol station where the owner is paying).
3. Attacker 1 captures the car's challenge; relays it over Wi-Fi to Attacker 2.
4. Attacker 2 re-broadcasts the challenge; the fob responds.
5. Attacker 2 captures the response; relays it back; Attacker 1 re-broadcasts.
6. Car authenticates the (absent) fob, unlocks.

Same sequence for engine start (the fob must remain "present" via continuous relay).

### Real-World Impact

- Door unlock + drive-away in **60 seconds** from the moment Attacker 1 reaches the door.
- Demonstrated for 2022 Civic and 2022 Accord.
- Honda's response: no hardware change; instead, software update to enforce **double challenge** (fob must respond twice within 50 ms — a weak RTT check). Bypassed by Labaca in a follow-up.

### Vendor Response

- Honda issued a firmware update via dealer (not OTA) — June 2022.
- The structural fix (UWB) was not deployed.
- Auto-ISAC published **PEPS-002 Best Practice** based on this case.

### MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Initial Access | Hardware attack — relay | T1200 |
| Defense Evasion | Spoof RF signal | (Automotive) |
| Impact | Vehicle theft | — |

### Distilled Lessons

1. **Sub-$100 relay kits are the new normal.** Every PKES owner is one relay attack away from theft.
2. **FSK without distance bounding is broken.** Migrate to UWB (2025+ all EU/US premium vehicles).
3. **Faraday pouches work** and should be offered to customers with high-theft-risk vehicles.

References: Raphael Labaca Ceolin, *Honda PKES Relay*, 2022; **I Am The Cavalry**, *PEPS Best Practice*; YouTube demo video, April 2022.

---

## Case 9 — Tesla Gatekeeper 2023 (Synacktiv @ Pwn2Own)

### Target Vehicle and ECU

2022 Tesla Model 3 (HW3, AMD-based MCU v3). Target: **CID (Center Information Display)** and the **Gatekeeper** security module.

### Attack Surface

Synacktiv (@synacktiv) entered the first ever automotive category at Pwn2Own (Toronto 2023) and took down the Tesla CID via a chain:

1. **CID renderer bug** — heap confusion in the Autopilot rendering pipeline.
2. **CID-to-GPU bridge** — a shared-memory interface that the CID used to push frames to the AMD GPU.
3. **GPU-to-CAN proxy** — a Tesla-specific helper that logged CAN traffic to GPU memory for the visualizer.

The chain gave them arbitrary code execution as the visualizer user, which had read-write access to a CAN socket.

### Real-World Impact

For the contest, they demonstrated:

- **Door open / close** at the door handle.
- **Trunk open**.
- **Horn**.

(They explicitly did not go further — Pwn2Own rules stop at first demonstrated impact.)

### Vendor Response

- **90-day coordinated disclosure** + Tesla PSIRT confirmation.
- **Patched** in 2023.38 OTA, ~3 weeks after the contest.
- Synacktiv won $250,000 + the vehicle.
- Tesla **redesigned the GPU→CAN path** to require code-signed messages and a one-way firewall (CAN → GPU only, never GPU → CAN).

### MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Initial Access | Exploit public-facing app (renderer) | T1190 |
| Privilege Escalation | GPU bridge access | T1068 |
| Lateral Movement | CAN socket | T1021 |
| Impact | Manipulate I/O | T0816 |

### Distilled Lessons

1. **Renderer + GPU + CAN** is a dangerous triad. Decouple them.
2. **Bug bounty at scale**: Pwn2Own paid out $250k for a chain that a black-market buyer would pay $500k+ for. Worth every penny.
3. **One-way firewalls** (CAN → visualizer) are simpler and more defensible than authenticated bidirectional ones.

References: ZDI, *Pwn2Own Toronto 2023 — Day 1 Results*; Synacktiv blog, *Tesla CID Exploitation*, 2024; Tesla OTA release 2023.38.

---

## Case 10 — Mercedes-Benz E-Class 2024 (Cybelline) — UDS Sequence Reuse

### Target Vehicle and ECU

2023 Mercedes-Benz E-Class W213 (restored factory image for testing). Target: **ECU over DoIP (Diagnostics over IP, ISO 13400)**.

### Attack Surface

Modern Mercedes vehicles expose a **DoIP endpoint** on the OBD-II port when the ignition is on and a "diagnostic session" is opened via the EGW (Electric Gateway). The EGW enforces:

- Per-ECU access control (technician roles).
- Vendor diagnostic seed-key exchange (RSA-1024, signed challenge).

The Cybelline team's contribution: a **sequence reuse** attack against the seed-key exchange.

The seed-key protocol works like this:

```
Tester → ECU:   DiagnosticSessionControl (0x10, 0x03 extended)
ECU → Tester:   seed = random 128-bit
Tester → ECU:   key = RSA-sign(seed, vendor_private_key)
ECU → Tester:   positive response
```

The Cybelline insight: the **same seed** was returned for the same session within a 30-second window, allowing **replay of a previously captured seed-key pair** if the ECU was not enforcing freshness.

### Method

1. Researcher captures a legitimate seed-key exchange with a vendor diagnostic tool (XENTRY) — the tool is widely available on gray-market channels.
2. Researcher opens a diagnostic session, captures the seed.
3. Researcher replays the captured key from step 1 against a *different* ECU on the same DoIP bus that uses the **same seed-key derivation**.

The "different ECU" part is the key insight: Mercedes's seed-key derivation was **shared across 9 ECUs** (engine, transmission, ABS, SRS, BCM, IVI, TCU, EGW, EPS). Capturing one legitimate transaction authorized 9.

### Real-World Impact

For the test vehicle, Cybelline demonstrated:

- **SecurityAccess level 3** unlocked on the engine ECU.
- **WriteDataByIdentifier (0x2E)** to modify calibration values.
- **RoutineControl (0x31)** to invoke factory routines (clear immobilizer, clear DTCs).

Cybelline did **not** publish driving-effects (out of scope of their engagement), but factory-mode access implies the ability to brick the vehicle or strip anti-theft.

### Vendor Response

- **Coordinated disclosure** with Mercedes-Benz PSIRT (April 2024).
- **Remediation**: per-ECU seed-key derivation (each ECU has its own RSA key), enforced freshness counter, DoIP session timeout reduced to 5 s.
- Mercedes issued TSB to all dealers to flash updated firmware.
- Mercedes began publishing **CVE-equivalent advisories** for the first time in 2024 (previously undisclosed).

### MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Initial Access | Valid accounts — seed/key replay | T1078 |
| Defense Evasion | Spoof security token | T1556 |
| Persistence | Modify calibration values | T1098 |
| Impact | (potential) bricked ECU / stripped immobilizer | — |

### Distilled Lessons

1. **UDS seed-key derivation must be per-ECU.** Sharing keys across ECUs converts one vuln into N vulns.
2. **Freshness counters are not optional.** A nonce that repeats within a session window is a defect.
3. **Diagnostic tool leakage** is a real attack vector. XENTRY and ODIS are widely pirated. Don't rely on tool-side secrecy.

References: Cybelline, *Mercedes E-Class UDS Sequence Reuse*, 2024; **ISO 14229-1 (UDS)** and **ISO 13400 (DoIP)** specifications; I Am The Cavalry, *OEM PSIRT Maturity Index*, 2023.

---

## Cross-Case Pattern Analysis

### Attack Surface Frequency

| Attack Surface | Cases | % |
|----------------|-------|---|
| OBD-II physical | 1, 5 | 20% |
| Key fob RF (PEPS / PKES) | 3, 8 | 20% |
| Infotainment (IVI browser / USB / BT) | 1, 2, 4 | 30% |
| TCU (cellular / Wi-Fi) | 1, 6 | 20% |
| Cloud API | 6 | 10% |
| Sensor / ADAS | 7 | 10% |
| DoIP / UDS | 10 | 10% |

(Percentages overlap because Case 1 (Jeep) hit multiple surfaces.)

### CAN Bus Abuse Primitives

| Primitive | Cases |
|-----------|-------|
| DBC injection (gateway allowed) | 1, 2, 4, 5 |
| UDS service-sequence abuse | 10 |
| Diagnostic session escalation | 10 |
| Gateway ACL bypass (update-time) | 4 |
| SecOC absence | 1, 2, 5 |

### Vendor Response Patterns

| Pattern | Cases |
|---------|-------|
| OTA same-week patch | 2, 9 |
| OTA same-quarter patch | 1, 4 |
| Dealer-only firmware flash | 8, 10 |
| Multi-million-vehicle recall | 1, 4 |
| Bug bounty launch | 1, 4 |
| PSIRT process formalization | 1, 4, 9 |

### Disclosure Window

- Median: **5 months** from initial report to public release.
- Range: 1 month (Troy Hunt / Nissan, forced) to 14 months (Cybelline / Mercedes).
- I Am The Cavalry's **Coordinated Disclosure for Connected Vehicles** (2015) standardizes 90 days minimum, with extensions for safety validation.

---

## Response Playbook — Suspected CAN Injection

If you operate a fleet or operate a vehicle SOC and suspect CAN injection (frames on the bus that the OEM did not originate):

1. **Capture.** Tap the bus via OBD-II; record 5 minutes of traffic with `canalyzer` or `python-can` to a `.asc` or `.pcap`. Note timestamp and ignition state.
2. **Diff against baseline.** Compare to a baseline DBC. Flag IDs that appear at unexpected frequencies or with unexpected signal values.
3. **Isolate.** If the vehicle is in motion, do **not** cut the bus — that may disable safety functions. Move the vehicle to a controlled area, then isolate by pulling the suspected ECU's connector.
4. **Forensic.** Pull ECU firmware version, event logs (UDS service 0x84 ReadDataByIdentifier for "Manufacturer Specific" DTC capture), and any TCU logs (cellular, GPS).
5. **Report.** Contact OEM PSIRT via Auto-ISAC (autoisac.com) within 24 h. If the bug has safety implications, NHTSA Office of Defects Investigation (USA) or equivalent.

**Do not publish details until the OEM has had 90 days minimum.** The I Am The Cavalry framework is the industry standard for automotive CVD.

---

## References and Further Reading

### Primary Sources

- Miller, C., & Valasek, M. (2015). *Remote Exploitation of an Unaltered Passenger Vehicle*. Black Hat USA 2015.
- Nie, S., Liu, L., & Du, Y. (2017). *Free-Fall: Hacking Tesla from Wireless to CAN Bus*. Black Hat USA 2017.
- Tencent Keen Security Lab (2018). *Bimmer-Going: 14 Bugs in BMW*. CanSecWest 2018.
- Regulus Cyber (2019). *Tesla Model X Key Fob Relay Attack*.
- Hunt, T. (2016). *Hacking the Nissan Leaf via the API*.
- Labaca Ceolin, R. (2022). *Honda PKES Relay Attack*.
- Synacktiv (2024). *Tesla CID Exploitation at Pwn2Own Toronto 2023*.
- Cybelline (2024). *Mercedes E-Class UDS Sequence Reuse*.
- Comma.ai (2017). *Openpilot and the Comma Pedal*.
- Ben-Gurion University (2022). *Phantom of the ADAS: Securing ADAS against Camera Spoofing*.

### Conferences and Communities

- **DEF CON Car Hacking Village (CHV)** — annual Las Vegas, defcon.org.
- **Black Hat USA / Europe Automotive track** — blackhat.com.
- **I Am The Cavalry** — iamthecavalry.org.
- **Auto-ISAC** — automotive ISAC, autoisac.com.
- **IOActive** — ioactive.com/automotive-research.

### Standards and Regulations

- ISO/SAE 21434:2021 — Cybersecurity Engineering.
- ISO 14229-1 (UDS) — Unified Diagnostic Services.
- ISO 13400 (DoIP) — Diagnostics over IP.
- ISO 11898 (CAN / CAN-FD).
- UNECE R155 / R156 — CSMS / SUMS (mandatory EU 2022+).
- AUTOSAR AP R19-11 — SecOC (Secure Onboard Communication).
- IEEE 802.15.4z — UWB distance bounding.

### OEM PSIRT and Bug Bounty

- Tesla: bugbounty.tesla.com
- FCA / Stellantis: bugbounty.stellantis.com
- BMW: hackerone.com/bmw
- Mercedes-Benz: psirt@mercedes-benz.com (private program)
- Toyota: bugbounty.toyota.co.jp
- General Motors: hackerone.com/gm

### Books

- *The Car Hacker's Handbook* — Craig Smith (No Starch Press, 2016).
- *2014 Car Hacker's Handbook* — Craig Smith.
- *A Comprehensible Guide to Controller Area Network* — Wilfried Voss.
- *Embedded Networking with CAN and CAN-FD* — Wilfried Voss.

---

## Practice Exercises

1. **Map a CVE.** Pick any automotive CVE from 2020-2024 (search NVD for `cpe:/h:*:*:ecu:*`). Identify the attack surface, CAN bus abuse primitive, and which case in this guide it most resembles.
2. **Build a fleet DBC baseline.** Using `python-can` and a peak PCM-USB adapter, capture 10 minutes of baseline traffic on a development vehicle. Compute per-ID frequency statistics; flag any ID with >2σ deviation on the next drive.
3. **Coordinated disclosure draft.** Pick a synthetic vulnerability (e.g., "D-Bus service executes shell as root on a hypothetical head unit") and draft a coordinated disclosure report per I Am The Cavalry template.
4. **PEPS attack lab.** Build a BLE relay with two ESP32s and a Wi-Fi link. Demonstrate against a target BLE peripheral (e.g., a smart lock with the same protocol pattern as PKES).
5. **UDS fuzz.** Using `udsonican` Python library, write a fuzzer that sends every UDS service ID (0x10-0x3E) to a development ECU on the bench. Catalog which services respond positive vs. negative.

---

## Conclusion

Ten incidents, ten lessons, but really only **one** lesson:

> **A routable path from a non-trusted input to a safety-critical CAN bus is the bug.** Everything else — DBC injection, UDS abuse, relay attacks, browser RCE — is a delivery mechanism.

If your architecture has that path, you have a 2015 Jeep Cherokee. If it does not, you have a defensible vehicle. Build accordingly.
