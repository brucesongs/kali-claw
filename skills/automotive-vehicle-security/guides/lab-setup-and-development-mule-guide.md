# Automotive Security Lab Setup — Building a Development Mule

> Companion to `automotive-vehicle-security-playbook.md`. The bench setup that lets you take a vehicle from "in scope" to "fully characterized" without buying an OEM dev kit.

---

## Overview

You cannot do real vehicle security work without a lab. The lab has three tiers:

1. **Bench tier** — ECUs on a desk, jumpered together. Cheap, safe.
2. **Mule tier** — A real vehicle, owned by your team, with safety-disabling mods.
3. **Live tier** — Customer vehicles, with NDA and insurance.

This guide covers tier 1 and tier 2 setup.

---

## Objective

Stand up a lab that lets you do CAN injection, UDS fuzzing, firmware extraction, and key fob replay — without endangering people or property.

---

## Bench Tier — Parts List

| Item | Cost | Purpose |
|------|------|---------|
| 2-3 used ECUs from eBay (engine, BCM, ABS) | $50-$200 each | Target ECUs |
| 12V bench power supply (5A minimum) | $80 | Power |
| OBD-II breakout cable with banana jacks | $40 | CAN tap |
| PCAN-USB or Kvaser adapter | $300-$400 | CAN interface |
| Bosch CAN termination resistor (×2, 120Ω) | $5 | Bus termination |
| Breadboard + jumper wires | $20 | Hookup |
| ESP32 dev board (×2) | $15 | BLE relay practice |
| RTL-SDR | $25 | Key fob receive |
| Linux laptop | (existing) | Tools host |

**Total bench tier: ~$700** for a complete setup.

---

## Bench Tier — Wiring Diagram

```
   ┌─────────────┐    +12V    ┌─────────────────┐
   │ 12V PS      │───────────│  ECU 1 (Engine)  │──┐
   │ 5A          │           └──────────────────┘  │ CAN-H
   │             │                                   │ CAN-L
   │             │           ┌─────────────────┐    │
   │             │─── +12V ──│  ECU 2 (BCM)    │────┤
   │             │─── GND ───│                 │    │
   └─────────────┘           └──────────────────┘    │
                                                     │
                              ┌─────────────────┐    │
                              │   PCAN-USB      │────┘
                              │   (laptop)      │ 120Ω
                              └─────────────────┘ terminators
```

Each ECU gets +12V, GND, and connects CAN-H / CAN-L to the shared bus. Two 120Ω resistors terminate the bus ends.

---

## Bench Tier — Power-Up Sequence

1. Set the bench power supply to 13.8V (vehicle charging voltage), current limit 3A.
2. Power off. Connect PS ground to ECU ground. Connect PS +12V to ECU B+ pins (consult ECU datasheet).
3. Connect CAN-H / CAN-L between ECUs.
4. Install terminators.
5. Plug PCAN-USB into laptop; connect to bench bus.
6. Power on PS. ECUs should boot (LED activity, normal current draw ~0.5-2A each).
7. Run `candump -L can0` on laptop. Expect to see periodic frames within 5s.

If you see nothing, the ECUs may need an **ignition signal** (typically +12V on a specific pin). Consult the datasheet.

---

## Mule Tier — Vehicle Acquisition

A mule is a real vehicle your team owns outright. Buy used:

- 2010-2015 era is ideal — modern enough to have CAN, old enough to lack SecOC.
- Salvage title acceptable — you're not driving it on the road.
- Budget: $3-10k depending on vehicle.

**Recommended mules by research area:**

| Research Area | Recommended Mule |
|---------------|------------------|
| CAN bus reversing | 2012-2015 Toyota Prius (openpilot support) |
| Key fob relay | 2018-2022 Honda Civic (documented PKES bug) |
| IVI / Android Auto | 2015-2018 Hyundai Sonata (AAOS in head unit) |
| EV charging | 2012-2016 Nissan Leaf (Z0 generation) |
| ADAS / Mobileye | 2016-2019 Tesla Model S HW2.5 |
| Heavy-duty | 2010+ Freightliner Cascadia (J1939) |

---

## Mule Tier — Safety Modifications

Before any active testing:

1. **Disable propulsion.** Pull the starter fuse (gas) or HV contactor fuse (EV). Vehicle can boot but cannot move under its own power.
2. **Chock wheels.** Even with propulsion disabled, brake testing can roll the vehicle.
3. **Vent garage.** If running engine, CO hazard. Best: only run EVs indoors.
4. **Fire extinguisher** nearby (Class ABC).
5. **Second person** present during active testing (for emergency response).
6. **Kill switch** on bench PS. Easy to cut power.
7. **Lockout/tagout** for any test where you're under the vehicle.

---

## Mule Tier — Permanent Instrumentation

Install permanently:

- **OBD-II breakout box** wired to the vehicle, with banana jack taps for each pin. Cost: $80 or DIY.
- **Raspberry Pi 4** with `can0` interface, mounted in the trunk. Continuous traffic capture.
- **GPS module** on the Pi. Tag captures with location.
- **4G/LTE modem** on the Pi. Push captures to S3.
- **Fuse bypass kit** for ignition circuits. Lets you wake ECUs without the key.

---

## Mule Tier — Engagement Workflow

For each engagement:

1. Document the engagement scope and safety boundaries in writing.
2. Confirm all safety modifications are in place (propulsion disable, wheel chocks).
3. Notify team of test times. No visitors during active CAN injection.
4. Capture baseline (30 minutes idle, no injection).
5. Perform engagement (fuzz, inject, etc.).
6. Capture results.
7. Restore vehicle to baseline state.
8. Document any anomalies (ECU DTCs cleared, etc.).

---

## Cloud / Fleet Lab Tier

For testing cloud APIs (Nissan Leaf-style):

1. **Test account** with the OEM cloud service.
2. **Burp Suite** intercepting phone-app traffic.
3. **Test VIN** registered to your test account.
4. **Rate limiter** on your test scripts to avoid fleet-wide impact.

---

## Software Configuration

On the Linux laptop:

```bash
# CAN tools
sudo apt install can-utils iproute2

# Python ecosystem
pip install python-can cantools udsoncan

# Capture analysis
pip install pandas matplotlib jupyter

# Firmware analysis
sudo apt install binwalk gdb-multiarch qemu-user-static
# Ghidra: download from https://ghidra-sre.org/

# SDR
sudo apt install gqrx hackrf
pip install urh
```

On macOS (Apple Silicon):

```bash
brew install python-can
brew install --cask gqrx
brew install urh
# CAN adapters: use the vendor's driver
```

---

## Common Lab Pitfalls

- **CAN bus termination missing.** Symptom: intermittent frames, corrupted CRCs. Fix: add 120Ω at each end.
- **Ground loop between PS and ECU.** Symptom: noise on CAN-L. Fix: tie PS ground to bench ground.
- **Wrong power supply.** Symptom: ECU resets when inject frames. Fix: 13.8V regulated, 5A minimum.
- **Laptop CAN adapter not isolated.** Symptom: laptop reboots when ECU shorts. Fix: use galvanic-isolated adapter (most PCAN-USB are).
- **No ignition wake.** Symptom: ECUs dark on power-up. Fix: tie ignition pin to +12V.

---

## Hands-on Practice

Set up the bench tier:

1. Source 2 ECUs from eBay (any 2010-2015 vehicle).
2. Wire them per the diagram above.
3. Confirm power-up.
4. Capture 5 minutes of CAN traffic.
5. Decode using SavvyCAN.
6. Write a one-page lab report.

Time budget: 1 weekend, including eBay waiting.

---

## References

- OpenGarages: `opengarages.org` — bench tutorials.
- /r/CarHacking: subreddit for lab setup advice.
- DEF CON CHV Slack: real-time help.
- Hacker Hotel (UK) and Car Hacking Village (US) annual training events.

---

## See Also

- `can-bus-reverse-engineering-guide.md` — DBC reverse engineering workflow
- `quick-reference-card.md` — pinouts and protocol reference
- `automotive-security-testing-tools-guide.md` — software tools
