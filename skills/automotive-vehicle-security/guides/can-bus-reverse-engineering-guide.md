# CAN Bus Reverse Engineering — Practical Guide

> Companion to `automotive-vehicle-security-playbook.md`. This guide walks the **DBC reverse-engineering workflow** from a blank slate through a usable DBC file.

---

## Overview

Modern vehicles ship without a published CAN database. To do meaningful work — find injected frames, decode actuator signals, write a fleet detector — you need to build one. This guide is the workflow the DEF CON Car Hacking Village teaches in its beginner track.

---

## Objective

Take a development vehicle from "I have no idea what's on the bus" to "I have a DBC with 30+ named signals and a confidence ranking" in 8 hours.

---

## Hardware Required

- CAN adapter: PCAN-USB ($300) or Kvaser Leaf v2 ($400). Cheap: CANalyst-II ($15).
- OBD-II breakout cable with flying leads.
- Laptop with Linux. Mac: use a VM. Windows: Vector CANalyzer if you have a license.
- Vehicle: any 2008+ US-market vehicle is OBD-II-mandated to expose CAN on pins 6/14.

---

## Step-by-Step Methodology

### Step 1 — Physical Tap

1. Locate the OBD-II port (under the dashboard, driver's side).
2. Connect the breakout cable. Power off the CAN adapter.
3. With the vehicle ignition off, plug the CAN adapter into pins 6 (CAN-H), 14 (CAN-L), and 4 (chassis ground).
4. **Verify resistance**: with vehicle off and adapter disconnected, measure between pins 6 and 14 with a multimeter. Should read 60Ω (two 120Ω terminators in parallel).
5. Power up the CAN adapter; verify Linux sees it (`ip link`).

### Step 2 — Bring Up the Interface

```bash
# Load kernel modules
sudo modprobe can can_raw vcan
# Set bitrate (500 kbps for HS-CAN)
sudo ip link set can0 type can bitrate 500000
sudo ip link set can0 up
# Verify
ip -details link show can0
```

### Step 3 — Capture Baseline

```bash
# Capture to file
candump -L can0 > baseline-ignition-off.log &
# Turn on ignition (don't start engine). Wait 30s.
# Start engine. Wait 60s. Let idle 30s.
# Stop capture
killall candump
```

### Step 4 — Replay and Identify

```bash
# Use SavvyCAN (graphical) or cantools (CLI)
# Load baseline log into SavvyCAN, click "Auto-detect signals"
# OR
python3 -c "
import cantools
# Parse the captured log
# cantools doesn't auto-discover, use savvy-can or a custom analyzer
"
```

### Step 5 — Frequency Clustering

Signals cluster by update rate:

| Frequency | Likely Meaning |
|-----------|----------------|
| 100 Hz | Engine RPM, throttle position |
| 50 Hz | Vehicle speed, brake pressure |
| 10 Hz | Steering angle, gear position |
| 1 Hz | Coolant temperature, oil pressure |
| 0.1 Hz | odometer, VIN |

Use this to identify candidates:

```python
from collections import Counter
import can
bus = can.interface.Bus(channel='can0', interface='socketcan')
counts = Counter()
for _ in range(1000):
    msg = bus.recv(timeout=0.1)
    if msg:
        counts[msg.arbitration_id] += 1
for aid, count in counts.most_common():
    freq = count / 60.0  # assuming 60s capture
    print(f"0x{aid:04X}: {freq:.1f} Hz")
```

### Step 6 — Signal Validation

Pick a candidate ID. Drive the vehicle while a passenger watches the data:

- Engine RPM: rev engine. Find signal that scales with tachometer.
- Vehicle speed: drive. Find signal that scales with speedometer.
- Brake: brake pedal. Find signal that goes high on press.
- Steering: turn wheel. Find signal that scales linearly with angle.

### Step 7 — Build the DBC

Use SavvyCAN's "DBC Editor" or hand-write a `.dbc` file (see `quick-reference-card.md`).

### Step 8 — Validate via Injection

```python
# After building DBC, validate by replaying captured values
import can, cantools
db = cantools.database.load_file('my-vehicle.dbc')
bus = can.interface.Bus(channel='can0', interface='socketcan')
msg = db.get_message_by_name('EngineStatus')
# Send a "valid" frame
bus.send(msg.encode({'EngineRPM': 1500.0}))
```

---

## Hands-on Practice

Reproduce this workflow on any vehicle you have legal access to (your own car, a fleet vehicle, a development mule). Submit your DBC + 30s capture to the Auto-ISAC DBC repository (members only) or the OpenGarages forum.

---

## Common Pitfalls

- **Forgetting the second terminator.** Modern vehicles have 2× 120Ω; older vehicles sometimes have only 1. If you see 120Ω, add an external terminator.
- **Wrong bitrate.** Most passenger vehicles: 500 kbps. Heavy-duty (J1939): 250 kbps. GMLAN single-wire: 33.3 kbps.
- **CAN-FD confusion.** CAN-FD frames look like classic CAN but with longer DLC. If you see >8 bytes, you're on CAN-FD.
- **Ground loops.** Always connect pin 4 (chassis ground). Skipping causes intermittent decode errors.

---

## References

- SavvyCAN: `github.com/collin80/SavvyCAN`
- python-can docs: `python-can.readthedocs.io`
- cantools docs: `cantools.readthedocs.io`
- can-utils: `github.com/linux-can/can-utils`
- DEF CON Car Hacking Village training materials (annual, free).

---

## See Also

- `quick-reference-card.md` — pinouts, UDS services, DBC syntax
- `automotive-vehicle-security-playbook.md` — full engagement methodology
- `automotive-ecu-firmware-and-uds-deep-dive.md` — UDS deep dive
