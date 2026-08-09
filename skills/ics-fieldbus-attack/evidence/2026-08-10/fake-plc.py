#!/usr/bin/env python3
"""
Vulnerable PLC simulator for ics-fieldbus-attack SKILL validation.

Simulates a water-pump PLC with intentional vulnerabilities matching
typical real PLCs (no auth, no encryption, permissive register range,
no OOB check).

Usage on Kali VM (parallels@10.211.55.5):
    pip3 install --break-system-packages pyModbusTCP
    python3 fake-plc.py

Then attack from the same VM (127.0.0.1:502) using SKILL payloads.
"""
from pyModbusTCP.server import ModbusServer, DataBank
import time, random, threading

# Initialize data
db = DataBank()
db.set_holding_registers(0, [0])      # 40001: pump status (0=off, 1=on)
db.set_input_registers(0, [50])       # 30001: tank level (0-100%)
db.set_coils(0, [False])              # 00001: remote start/stop control

# Background thread: simulate tank level based on pump status
def simulate():
    while True:
        try:
            pump_status = db.get_holding_registers(0, 1)[0]
            level = db.get_input_registers(0, 1)[0]
            if pump_status == 1:  # pump on → tank drains
                level = max(0, level - random.randint(1, 3))
            else:                  # pump off → tank fills
                level = min(100, level + random.randint(1, 2))
            db.set_input_registers(0, [level])
        except Exception:
            pass
        time.sleep(2)

threading.Thread(target=simulate, daemon=True).start()

server = ModbusServer(host='0.0.0.0', port=502, no_block=True, data_bank=db)
server.start()
print("[+] Vulnerable PLC simulator listening on 0.0.0.0:502")
print("[+] Holding register 40001 = pump status (0=off, 1=on)")
print("[+] Input register   30001 = tank level (0-100%)")
print("[+] Coil             00001 = remote start/stop")
print("[+] NO AUTH (matches typical real PLCs)")
print("[+] Press Ctrl+C to stop")

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    server.stop()
    print("[+] Server stopped")
